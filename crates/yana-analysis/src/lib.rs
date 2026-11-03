//! YANA analysis layer (§14 pass 3, `--strict`): flow analysis over the IR.
//!
//! Input is a resolved [`Module`]; output is diagnostics (spec classes) plus
//! derived facts the later passes reuse:
//! - [`cfg`]: basic-block CFG per function (§14.2 "IR по функциям (базовые блоки)")
//! - [`liveness`]: register liveness → dead-store notes and clobber derivation
//! - [`stack`]: stack-depth tracking → balance errors, max depth (feeds the
//!   Xtensa `entry a1, framesize` requirement and `align 16` sugar)
//! - [`flags`]: Jcc reading flags that no reaching instruction wrote
//! - [`result`]: return-reachability + result-definedness for `-> T`
//! - [`scope`]: §6 check — jumping into a nested block is an error
//!
//! Everything consults `yana_codegen::insn::insn_info` — never re-derives
//! register effects (§14: one source of truth).

pub mod cfg;
pub mod flags;
pub mod liveness;
pub mod scope;
pub mod stack;
pub mod result;
pub mod verify;

use yana_ast::Diagnostic;
use yana_codegen::Module;

/// Run the full analysis suite over a module (pass 3).
///
/// Takes the module mutably: the stack pass lowers `align N;` into concrete
/// padding (§4.3) before the other checks and the backends ever see it.
pub fn analyze(module: &mut Module) -> Vec<Diagnostic> {
    // stack first: lowers aligns, so every later pass sees StackPad
    let mut diags = stack::lower_and_check(module);
    for body in &module.bodies {
        let graph = cfg::build(module, body);
        diags.extend(scope::check(module, body, &graph));
        diags.extend(flags::check(module, body, &graph));
        diags.extend(result::check(module, body, &graph));
        diags.extend(liveness::check(module, body, &graph));
    }
    diags.extend(preserves::check(module));
    diags
}

/// §5.4 `preserves`: a function that promises not to destroy a register must
/// not write it (directly or through a call's clobber contract).
pub mod preserves {
    use crate::flags::norm64;
    use yana_ast::{DiagCode, Diagnostic};
    use yana_codegen::Module;

    pub fn check(module: &Module) -> Vec<Diagnostic> {
        let mut diags = Vec::new();
        for body in &module.bodies {
            let Some(sym) = module.symbols.get(body.symbol) else { continue };
            if sym.preserves.is_empty() {
                continue;
            }
            let derived = crate::liveness::derive_clobbers(module, body);
            for p in &sym.preserves {
                let p64 = norm64(*p);
                if derived.iter().any(|d| norm64(*d) == p64) {
                    diags.push(
                        Diagnostic::error(
                            DiagCode::Contract,
                            "preserves-violated",
                            format!("`{}` is declared `preserves`, but the body writes it", p64.name()),
                            sym.span,
                        )
                        .with_help("remove the register from `preserves`, or stop writing it (§5.4)"),
                    );
                }
            }
        }
        diags
    }
}
