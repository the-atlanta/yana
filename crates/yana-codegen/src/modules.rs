//! Module (§10) helpers: pure AST/IR-level utilities shared by the CLI module
//! loader and tests. The loader itself lives in `yana-cli` because it needs to
//! read files and run the parser; everything here is side-effect free.
//!
//! Binding decisions (see docs/NOTES-modules.md):
//! - `use seg(::seg)*;` — the LAST segment is the item name, preceding
//!   segments are a file path relative to the importing file's directory.
//! - Exports are `#[global]` only (`pub` was removed, §15).
//! - No name mangling: the object symbol is the item name verbatim.

use yana_ast::{File, Item, Span};
use yana_ast::reg::Reg;

use crate::ir::{Module, SymbolKind};
use crate::target::ImportedDecl;

/// A parsed `use path::name;` reference.
#[derive(Debug, Clone)]
pub struct UseRef {
    /// Path segments as written, each with its span.
    pub segments: Vec<(String, Span)>,
    pub span: Span,
}

/// Collect the `use` items of a file (§10).
pub fn use_refs(file: &File) -> Vec<UseRef> {
    file.items
        .iter()
        .filter_map(|item| match item {
            Item::Use { path, span } => Some(UseRef { segments: path.clone(), span: *span }),
            _ => None,
        })
        .collect()
}

/// Split a `use` path into (module file path, item name).
///
/// `use math::divmod` → file `math` (the loader adds the extension), item
/// `divmod`. `use lib::math::divmod` → file `lib/math`, item `divmod`.
/// A single-segment path has no module part; the error span lets the loader
/// report it precisely.
pub fn split_use_path(segments: &[(String, Span)]) -> Result<(String, String), Span> {
    if segments.len() < 2 {
        return Err(segments.first().map(|s| s.1).unwrap_or(Span::DUMMY));
    }
    let (item, _) = segments.last().unwrap();
    let file = segments[..segments.len() - 1]
        .iter()
        .map(|(s, _)| s.as_str())
        .collect::<Vec<_>>()
        .join("/");
    Ok((file, item.clone()))
}

/// Why an import could not be extracted from a used module.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtractError {
    /// The name does not exist in the module.
    Unresolved,
    /// The name exists but is not `#[global]` (§10: export is #[global] only).
    NotExported,
}

fn is_global(attrs: &[yana_ast::Attr]) -> bool {
    attrs.iter().any(|a| a.has_name("global"))
}

/// Clobbers for an imported `fn` (§5.4): the resolved IR symbol's list
/// (declared block, or what the analysis pass derived and stored).
fn ir_clobbers(module: &Module, name: &str) -> Vec<Reg> {
    module
        .symbols
        .iter()
        .find(|s| s.name == name)
        .map(|s| s.clobbers.clone())
        .unwrap_or_default()
}

/// Extract the declaration `name` from a used module's AST + resolved IR.
///
/// Only `#[global]` items are importable (§10). `fn`/`extern fn` contribute
/// their signature (clobbers from the resolved IR symbol — declared blocks,
/// or the derivation the analysis pass stored); `const` contributes its
/// evaluated value; static binds contribute their size (for `name.len` at the
/// importer) and become undefined symbol references.
pub fn extract_decl(
    file: &File,
    module: &Module,
    name: &str,
) -> Result<ImportedDecl, ExtractError> {
    for item in &file.items {
        match item {
            Item::Fn(f) if f.sig.name == name => {
                if !f.exported {
                    return Err(ExtractError::NotExported);
                }
                return Ok(ImportedDecl::Fn { sig: f.sig.clone(), clobbers: ir_clobbers(module, name) });
            }
            Item::ExternFn(e) if e.sig.name == name => {
                if !is_global(&e.attrs) {
                    return Err(ExtractError::NotExported);
                }
                let clobbers = match &e.clobbers {
                    Some(c) => c.regs.clone(),
                    None => ir_clobbers(module, name),
                };
                return Ok(ImportedDecl::Fn { sig: e.sig.clone(), clobbers });
            }
            Item::Const(c) if c.name == name => {
                if !is_global(&c.attrs) {
                    return Err(ExtractError::NotExported);
                }
                let value = module
                    .symbols
                    .iter()
                    .find(|s| s.name == name)
                    .and_then(|s| match &s.kind {
                        SymbolKind::Const { value } => Some(*value),
                        _ => None,
                    })
                    .unwrap_or(0);
                return Ok(ImportedDecl::Const { name: name.to_string(), value });
            }
            Item::Static(s) if s.name == name => {
                if !is_global(&s.attrs) {
                    return Err(ExtractError::NotExported);
                }
                let size = module
                    .symbols
                    .iter()
                    .find(|sym| sym.name == name)
                    .and_then(|sym| match &sym.kind {
                        SymbolKind::Static { size, .. } => Some(*size),
                        _ => None,
                    })
                    .unwrap_or(0);
                return Ok(ImportedDecl::Static { name: name.to_string(), size });
            }
            _ => {}
        }
    }
    Err(ExtractError::Unresolved)
}

/// Default clobber list when a signature provides none (§5.4): the syscall
/// ABI rcx/r11 — the conservative x86-64 caller-saved set.
pub fn default_clobbers() -> Vec<Reg> {
    vec![
        Reg::parse("rcx").expect("rcx"),
        Reg::parse("r11").expect("r11"),
    ]
}
