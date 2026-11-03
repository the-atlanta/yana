//! `yana-lsp` — Language Server *and* Debug Adapter for YANA.
//!
//! Two modes, chosen by argv:
//! - default: LSP over stdio (tower-lsp)
//! - `--dap`: Debug Adapter Protocol over stdio (see [`dap`])
//!
//! LSP features:
//! - live diagnostics on open/change (full pipeline: lex → parse → resolve)
//! - completion: keywords, registers, instruction-level snippets per context
//! - hover: register width/aliases, keyword docs from the spec, symbol info
//! - go-to-definition, references, signature help, document symbols
//! - code actions, rename, inlay hints, code lens, folding, selection ranges
//! - semantic tokens, execute commands (build / run / expand / debug / ir)
//! - workspace scanning, const folding preview, source→IR mapping
//!
//! DAP features:
//! - launch a `.yana` file, line breakpoints, step in/over/out, continue
//! - stack traces, registers / stack / flags views, `setVariable`, `evaluate`
//!
//! The completion/hover content comes from [`knowledge`], one table shared
//! with any future tooling.

pub mod backend;
pub mod dap;
pub mod knowledge;
pub mod range;
pub mod symbols;
pub mod syscalls;
pub mod vm;
pub mod world;

use tower_lsp::{LspService, Server};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();

    if args.iter().any(|a| a == "--dap") {
        dap::serve_stdio();
        return;
    }
    if args.iter().any(|a| a == "--version" || a == "-V") {
        println!("yana-lsp {}", env!("CARGO_PKG_VERSION"));
        return;
    }
    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!(
            "yana-lsp {} — YANA language server + debug adapter\n\n\
             Usage:\n  yana-lsp          LSP over stdio (default)\n  yana-lsp --dap    Debug Adapter Protocol over stdio\n  yana-lsp --version\n\n\
             Helix: see crates/yana-lsp/README.md",
            env!("CARGO_PKG_VERSION")
        );
        return;
    }

    lsp_main();
}

#[tokio::main]
async fn lsp_main() {
    let stdin = tokio::io::stdin();
    let stdout = tokio::io::stdout();
    let (service, socket) = LspService::new(backend::Backend::new);
    Server::new(stdin, stdout, socket).serve(service).await;
}
