//! World state: all open documents, their parses, a unified symbol index
//! across the workspace (open + scanned files), compiled IR, and const values.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tower_lsp::lsp_types::Url;
use tokio::sync::RwLock;

use yana_parser::ParseOutput;
use yana_codegen::{resolve_module, ResolveOptions, TargetInfo};
use yana_ast::File;

use crate::symbols::{collect_symbols, SymbolEntry, SymbolKind};
use yana_ast::ConstExpr;

/// One parsed document.
#[derive(Debug, Default)]
pub struct Document {
    pub source: String,
    pub parse: Option<ParseOutput>,
    pub symbols: Vec<SymbolEntry>,
    /// Const name → evaluated i128 value (from this document).
    pub const_values: HashMap<String, i128>,
}

impl Document {
    pub fn source_map(&self) -> yana_ast::diag::SourceMap {
        yana_ast::diag::SourceMap::new(&self.source)
    }
}

/// The in-memory world: every open + scanned file and a cross-file symbol index.
pub struct World {
    pub docs: RwLock<HashMap<Url, Arc<Document>>>,
    /// Workspace root directory (for scanning), set at `initialize`.
    pub root: RwLock<Option<PathBuf>>,
}

impl World {
    pub fn new() -> Self {
        Self {
            docs: RwLock::new(HashMap::new()),
            root: RwLock::new(None),
        }
    }

    pub async fn set_root(&self, root: PathBuf) {
        *self.root.write().await = Some(root);
    }

    /// Store (or replace) a document's source, re-parse and re-index symbols.
    pub async fn upsert(&self, uri: Url, source: String) {
        let parsed = yana_parser::parse(&source);
        let symbols = parsed
            .file
            .as_ref()
            .map(|f| collect_symbols(f, &uri))
            .unwrap_or_default();
        let const_values = parsed
            .file
            .as_ref()
            .map(extract_const_values_from_file)
            .unwrap_or_default();
        let doc = Arc::new(Document {
            source,
            parse: Some(parsed),
            symbols,
            const_values,
        });
        self.docs.write().await.insert(uri, doc);
    }

    pub async fn get(&self, uri: &Url) -> Option<Arc<Document>> {
        self.docs.read().await.get(uri).cloned()
    }

    pub async fn remove(&self, uri: &Url) {
        self.docs.write().await.remove(uri);
    }

    /// Every symbol in every document (open + scanned).
    pub async fn all_symbols(&self) -> Vec<SymbolEntry> {
        let docs = self.docs.read().await;
        docs.values()
            .flat_map(|d| d.symbols.clone())
            .collect()
    }

    /// All documents currently in the world.
    pub async fn all_docs(&self) -> Vec<(Url, Arc<Document>)> {
        let docs = self.docs.read().await;
        docs.iter().map(|(u, d)| (u.clone(), d.clone())).collect()
    }

    /// Symbol definitions matching `name` across all documents.
    pub async fn find_definitions(&self, name: &str) -> Vec<SymbolEntry> {
        let docs = self.docs.read().await;
        docs.values()
            .flat_map(|d| d.symbols.iter())
            .filter(|s| s.name == name)
            .filter(|s| {
                matches!(
                    s.kind,
                    SymbolKind::Bind
                        | SymbolKind::Static
                        | SymbolKind::Function
                        | SymbolKind::ExternFunction
                        | SymbolKind::Const
                        | SymbolKind::ConstFunction
                        | SymbolKind::Label
                        | SymbolKind::Parameter
                )
            })
            .cloned()
            .collect()
    }

    /// Scan all `.yana` files under the workspace root and index their symbols.
    /// Files already open are skipped (they have live sources).
    pub async fn scan_workspace(&self) {
        let root = match self.root.read().await.as_ref() {
            Some(r) => r.clone(),
            None => return,
        };

        let mut files: Vec<PathBuf> = Vec::new();
        collect_yana_files(&root, &mut files);

        let open_uris: Vec<Url> = {
            let docs = self.docs.read().await;
            docs.keys().cloned().collect()
        };

        for path in files {
            let uri = match Url::from_file_path(path.clone()) {
                Ok(u) => u,
                Err(_) => continue,
            };
            if open_uris.contains(&uri) {
                continue;
            }
            let source = match std::fs::read_to_string(&path) {
                Ok(s) => s,
                Err(_) => continue,
            };
            let parsed = yana_parser::parse(&source);
            let symbols = parsed
                .file
                .as_ref()
                .map(|f| collect_symbols(f, &uri))
                .unwrap_or_default();
            let const_values = parsed
                .file
                .as_ref()
                .map(extract_const_values_from_file)
                .unwrap_or_default();
            let doc = Arc::new(Document {
                source,
                parse: Some(parsed),
                symbols,
                const_values,
            });
            self.docs.write().await.insert(uri, doc);
        }
    }

    /// Compile a document's IR on demand (no caching — Module is not Clone).
    pub async fn module_for(&self, uri: &Url) -> Option<yana_codegen::ir::Module> {
        let doc = self.get(uri).await?;
        let parsed = match &doc.parse {
            Some(p) => p,
            None => return None,
        };
        let file = match &parsed.file {
            Some(f) => f,
            None => return None,
        };
        let out = resolve_module(file, &TargetInfo::linux_x86_64(), &ResolveOptions::default());
        if out.diagnostics.iter().any(|d| d.level == yana_ast::diag::DiagLevel::Error) {
            return None;
        }
        Some(out.module)
    }

    /// Const value for a name in a document.
    pub async fn const_value(&self, uri: &Url, name: &str) -> Option<i128> {
        let doc = self.get(uri).await?;
        doc.const_values.get(name).copied()
    }
}

/// Collect all `.yana` files under `dir` recursively.
fn collect_yana_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if path.file_name().and_then(|n| n.to_str()) == Some(".git") {
                continue;
            }
            collect_yana_files(&path, out);
        } else if path.extension().and_then(|e| e.to_str()) == Some("yana") {
            out.push(path);
        }
    }
}

/// Extract const name → evaluated i128 value from a parsed file (best-effort).
pub(crate) fn extract_const_values_from_file(file: &File) -> HashMap<String, i128> {
    use yana_ast::{Item, ConstExpr};
    let mut out = HashMap::new();
    for item in &file.items {
        match item {
            Item::Const(c) => {
                if let Some(v) = yana_codegen::consteval::try_eval(&c.value) {
                    out.insert(c.name.clone(), v);
                }
            }
            _ => {}
        }
    }
    out
}

