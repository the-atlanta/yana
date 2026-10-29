use zed_extension_api::{self as zed, process::Command, Result};

struct YanaExtension;

impl zed::Extension for YanaExtension {
    fn new() -> Self {
        YanaExtension
    }

    fn language_server_command(
        &mut self,
        _language_server_id: &zed::LanguageServerId,
        _worktree: &zed::Worktree,
    ) -> Result<zed::Command> {
        // The LSP is a native binary: tokio + tower-lsp don't fit the
        // extension wasm sandbox, so Zed launches it as a subprocess.
        // Lookup order:
        //   1. a build inside the worktree (target/release, target/debug)
        //   2. `yana-lsp` on PATH
        for candidate in ["target/release/yana-lsp", "target/debug/yana-lsp"] {
            let mut check = Command::new("test").arg("-x").arg(candidate);
            if let Ok(out) = check.output() {
                if out.status == Some(0) {
                    return Ok(zed::Command {
                        command: candidate.to_string(),
                        args: vec![],
                        env: vec![],
                    });
                }
            }
        }

        // PATH lookup via `which`
        let mut which = Command::new("which").arg("yana-lsp");
        if let Ok(out) = which.output() {
            if out.status == Some(0) {
                let path = String::from_utf8_lossy(&out.stdout).trim().to_string();
                if !path.is_empty() {
                    return Ok(zed::Command { command: path, args: vec![], env: vec![] });
                }
            }
        }

        Err(
            "yana-lsp not found: run `cargo install --path crates/yana-lsp`, \
             or build the YANA workspace in this worktree (target/release/yana-lsp)"
                .to_string(),
        )
    }
}

zed::register_extension!(YanaExtension);
