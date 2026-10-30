//! The module loader (§10): discovers `use` dependencies, loads and resolves
//! every involved module, and exposes them for the multi-file build.
//!
//! Binding decisions (see docs/NOTES-modules.md):
//! - `use seg(::seg)*;` — the LAST segment names the item; the preceding
//!   segments are a file path relative to the importing file's directory
//!   (`use math::divmod` → `math.yana`; `use lib::math::divmod` →
//!   `lib/math.yana`). Both `.yana` and `.yn` extensions are accepted
//!   (SPEC §15, решение 30.10).
//! - Only `#[global]` items are importable; anything else gives
//!   `unresolved-import` with the "not exported: add #[global]" help.
//! - Circular `use` (a module transitively using itself) is an error.
//! - The same name imported twice from different origins is
//!   `duplicate-import`; the same import twice is allowed (idempotent).
//! - No name mangling: symbol = item name verbatim.
//!
//! Loading order is DFS post-order: dependencies end up *before* their
//! importers in `Loader::mods`, which is also the argument order handed to
//! `ld`.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use yana_ast::{DiagCode, Diagnostic, File, Span};
use yana_codegen::{resolve_module, ImportedDecl, Module, ResolveOptions, TargetInfo};
use yana_codegen::modules as cgmod;

/// One loaded module: the resolved IR plus everything needed for
/// diagnostics and extraction.
pub struct LoadedModule {
    /// Canonical path (for messages).
    pub path: PathBuf,
    pub source: String,
    pub ast: File,
    pub comments: Vec<(u32, String)>,
    /// Resolved IR (after `yana_analysis::analyze`).
    pub module: Module,
}

/// Diagnostics gathered while loading; rendered against the per-module source
/// text. Every entry keeps the module's display name so the renderer can map
/// spans to the right file.
pub struct ModuleDiag {
    pub module: String,
    pub diag: Diagnostic,
}

/// The result of loading a module graph.
pub struct Loader {
    /// All loaded modules, DFS post-order (dependencies before importers).
    pub mods: Vec<LoadedModule>,
    /// Diagnostics per module (name + Diagnostic), in discovery order.
    pub diags: Vec<ModuleDiag>,
    /// path → index into `mods`
    by_path: HashMap<PathBuf, usize>,
    /// chain of modules currently being loaded (cycle detection)
    chain: Vec<PathBuf>,
}

const EXTENSIONS: [&str; 2] = ["yana", "yn"];

impl Loader {
    pub fn new() -> Self {
        Loader { mods: Vec::new(), diags: Vec::new(), by_path: HashMap::new(), chain: Vec::new() }
    }

    /// Load `path` and (transitively) every module it uses.
    ///
    /// Fatal problems (unreadable root, module not found, cycles, unresolved
    /// imports, resolve/analysis errors) are reported as diagnostics against
    /// the offending module's source; `has_fatal(strict)` decides the exit.
    pub fn load(&mut self, path: &Path, strict: bool) -> Result<(), String> {
        let path = resolve_file(path).ok_or_else(|| {
            format!("cannot read {}: no such file (.yana/.yn)", path.display())
        })?;
        self.load_module(&path, strict);
        Ok(())
    }

    /// All accumulated diagnostics fatal under `strict`?
    pub fn has_fatal(&self, strict: bool) -> bool {
        self.diags.iter().any(|d| d.diag.is_fatal(strict))
    }

    /// Render every diagnostic with ariadne (one report per module).
    /// Returns the fatal count.
    pub fn render(&self, strict: bool) -> usize {
        let mut fatal = 0;
        let names: Vec<String> = self.diags.iter().map(|d| d.module.clone()).collect();
        let mut seen: Vec<String> = Vec::new();
        for m in names {
            if seen.contains(&m) {
                continue;
            }
            seen.push(m.clone());
            let diags: Vec<Diagnostic> = self
                .diags
                .iter()
                .filter(|d| d.module == m)
                .map(|d| d.diag.clone())
                .collect();
            fatal += crate::report::render(&m, &self.module_source(&m), &diags, strict);
        }
        fatal
    }

    fn module_source(&self, name: &str) -> String {
        self.mods
            .iter()
            .find(|m| display(&m.path) == name)
            .map(|m| m.source.clone())
            .unwrap_or_default()
    }

    fn push_diag(&mut self, path: &Path, diag: Diagnostic) {
        self.diags.push(ModuleDiag { module: display(path), diag });
    }

    /// Load + resolve one module, recursing into its `use` deps first.
    fn load_module(&mut self, path: &Path, strict: bool) -> Option<usize> {
        let key = canonical(path);
        if let Some(&i) = self.by_path.get(&key) {
            // already loaded (or currently loading → cycle)
            if self.chain.contains(&key) {
                // cycle: report at the importer below
                return None;
            }
            return Some(i);
        }

        let source = match std::fs::read_to_string(path) {
            Ok(s) => s,
            Err(e) => {
                self.push_diag(
                    path,
                    Diagnostic::error(
                        DiagCode::Semantic,
                        "module-not-found",
                        format!("cannot read module file {}: {e}", path.display()),
                        Span::DUMMY,
                    ),
                );
                return None;
            }
        };

        let parsed = yana_parser::parse(&source);
        for d in &parsed.diagnostics {
            self.push_diag(path, d.clone());
        }
        let ast = match parsed.file {
            Some(f) => f,
            None => return None, // parse errors already reported
        };

        // cycle detection: mark this module as in-progress
        self.chain.push(key.clone());

        // collect + load dependencies, extracting imported declarations
        let mut imports: Vec<ImportedDecl> = Vec::new();
        let mut import_names: Vec<(String, PathBuf)> = Vec::new();
        for uref in cgmod::use_refs(&ast) {
            let (file_seg, item) = match cgmod::split_use_path(&uref.segments) {
                Ok(x) => x,
                Err(span) => {
                    self.push_diag(
                        path,
                        Diagnostic::error(
                            DiagCode::Semantic,
                            "use-path",
                            "`use` needs at least `module::item` — a bare name has no module part",
                            span,
                        ),
                    );
                    continue;
                }
            };
            let dep_path = match resolve_file(&path.parent().unwrap_or(Path::new(".")).join(&file_seg)) {
                Some(p) => p,
                None => {
                    self.push_diag(
                        path,
                        Diagnostic::error(
                            DiagCode::Semantic,
                            "module-not-found",
                            format!(
                                "module `{file_seg}` not found (looked next to {})",
                                path.display()
                            ),
                            uref.span,
                        )
                        .with_help(format!("expected `{file_seg}.yana` (or `.yn`) in the importing file's directory")),
                    );
                    continue;
                }
            };
            // circular use?
            let dep_key = canonical(&dep_path);
            if dep_key == key || self.chain.contains(&dep_key) {
                self.push_diag(
                    path,
                    Diagnostic::error(
                        DiagCode::Semantic,
                        "circular-use",
                        format!(
                            "module `{}` is (transitively) using itself",
                            display(&dep_path)
                        ),
                        uref.span,
                    ),
                );
                continue;
            }

            let dep_idx = self.load_module(&dep_path, strict);
            let Some(dep_idx) = dep_idx else {
                continue; // errors already reported
            };

            // duplicate-import: same name, different origin
            let dep = &self.mods[dep_idx];
            if let Some((_, prev)) = import_names.iter().find(|(n, _)| *n == item) {
                if *prev != dep.path {
                    self.push_diag(
                        path,
                        Diagnostic::error(
                            DiagCode::Semantic,
                            "duplicate-import",
                            format!("`{item}` is imported twice from different modules ({} and {})", display(prev), display(&dep.path)),
                            uref.span,
                        ),
                    );
                    continue;
                }
            }
            import_names.push((item.clone(), dep.path.clone()));

            match cgmod::extract_decl(&dep.ast, &dep.module, &item) {
                Ok(decl) => imports.push(decl),
                Err(cgmod::ExtractError::Unresolved) => {
                    self.push_diag(
                        path,
                        Diagnostic::error(
                            DiagCode::Semantic,
                            "unresolved-import",
                            format!("module `{}` has no item named `{item}`", display(&dep.path)),
                            uref.span,
                        ),
                    );
                }
                Err(cgmod::ExtractError::NotExported) => {
                    self.push_diag(
                        path,
                        Diagnostic::error(
                            DiagCode::Semantic,
                            "unresolved-import",
                            format!("`{item}` in module `{}` is not exported", display(&dep.path)),
                            uref.span,
                        )
                        .with_help("not exported: add #[global]"),
                    );
                }
            }
        }

        self.chain.pop();

        // resolve this module with its imports (§10: imports of fn/extern fn
        // signatures, const values, statics; macro imports are out of scope)
        let target = TargetInfo::linux_x86_64();
        let opts = ResolveOptions { strict, imports, ..Default::default() };
        let mut out = resolve_module(&ast, &target, &opts);
        if !out.has_errors() {
            // §14 pass 3 (same pipeline as the single-file path): lowers
            // `align N;` into StackPad and derives clobbers.
            yana_analysis::analyze(&mut out.module);
        }
        for d in out.diagnostics {
            self.push_diag(path, d);
        }

        let idx = self.mods.len();
        self.mods.push(LoadedModule {
            path: path.to_path_buf(),
            source,
            comments: parsed.comments,
            ast,
            module: out.module,
        });
        self.by_path.insert(key, idx);
        Some(idx)
    }
}

impl Default for Loader {
    fn default() -> Self {
        Self::new()
    }
}

/// Resolve `p` (with or without extension) to an existing `.yana`/`.yn` file.
fn resolve_file(p: &Path) -> Option<PathBuf> {
    let try_ext = |p: &Path| -> Option<PathBuf> {
        for ext in EXTENSIONS {
            let q = p.with_extension(ext);
            if q.is_file() {
                return Some(q);
            }
        }
        // also accept the exact path when it already carries an extension
        if p.is_file() {
            return Some(p.to_path_buf());
        }
        None
    };
    try_ext(p)
}

fn canonical(p: &Path) -> PathBuf {
    std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf())
}

fn display(p: &Path) -> String {
    p.display().to_string()
}
