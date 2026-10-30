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
    diags
}
