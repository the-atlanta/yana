//! `yana-lsp` — Language Server for YANA (tower-lsp, stdio transport).
//!
//! Features:
//! - live diagnostics on open/change (full pipeline: lex → parse → resolve)
//! - completion: keywords, registers, instruction-level snippets per context
//!   (bind/alt statements, branch conditions, types, sections)
//! - hover: register width/aliases, keyword docs from the spec, symbol info
//!
//! The completion/hover content comes from [`knowledge`], one table shared
//! with any future tooling.

pub mod backend;
pub mod knowledge;

use tower_lsp::{LspService, Server};

#[tokio::main]
async fn main() {
    let stdin = tokio::io::stdin();
    let stdout = tokio::io::stdout();
    let (service, socket) = LspService::new(backend::Backend::new);
    Server::new(stdin, stdout, socket).serve(service).await;
}
