//! Result-definedness and return-reachability (§14.3 "определённость результата").
//!
//! Checks, per function:
//! (a) control must not fall off the end without `return`/a noreturn call;
//! (b) a `-> !` function must not have a `return` reachable without a
//!     preceding noreturn call;
//! (c) for a function with declared result registers, every reachable `ret`
//!     must have those registers *definitely written* on all paths (a forward
//!     must-defined dataflow, calls kill caller-saved regs).

use std::collections::{HashMap, HashSet};

use yana_ast::reg::Reg;
use yana_ast::{DiagCode, Diagnostic};
use yana_codegen::insn::insn_info;
use yana_codegen::{FnBody, Insn, Module};

use crate::cfg::Cfg;
use crate::flags::norm64;

/// Check a function body for result/return problems.
pub fn check(module: &Module, body: &FnBody, cfg: &Cfg) -> Vec<Diagnostic> {
    let mut diags = Vec::new();
    let sym = &module.symbols[body.symbol];
    let n = body.insns.len();
    if n == 0 {
        return diags;
    }

    // (a) control falling off the end — unless the function is `-> !`, where
    // falling off IS the contract (it ends in a noreturn call/syscall).
    let last_block = cfg.blocks.len().saturating_sub(1);
    if !body.returns_never {
    if let Some(bb) = cfg.blocks.get(last_block) {
        let (s, e) = bb.insns;
        let last_i = e.min(n).saturating_sub(1);
        let last = &body.insns[last_i].insn;
        let info = insn_info(last);
        if bb.succs.is_empty() && !info.is_terminator && !info.is_noreturn {
            diags.push(
                Diagnostic::error(
                    DiagCode::Contract,
                    "fallthrough",
                    format!("control falls off the end of `{}` without `return`/noreturn", sym.name),
                    body.insns[last_i].span,
                )
                .with_help("end the function with `return;`, `return <place>;`, or a `-> !` call"),
            );
        }
    }
    }

    // (b) noreturn function with a reachable plain ret
    if body.returns_never {
        for (i, si) in body.insns.iter().enumerate() {
            if matches!(si.insn, Insn::Ret) && reachable_without_noreturn(body, cfg, i) {
                diags.push(
                    Diagnostic::warn(
                        DiagCode::Contract,
                        "noreturn-has-ret",
                        format!("`{}` is declared `-> !` but has a reachable `return`", sym.name),
                        si.span,
                    )
                    .with_help("a `-> !` function must end in a noreturn call/syscall on every path"),
                );
            }
        }
    }

    // (c) result-register definedness — from the `-> ...` signature (§5.1),
    // which the resolver stored on the body (no call site needed).
    let result_regs = body.result_regs.clone();
    if !result_regs.is_empty() {
        let mustdef = must_defined(body, cfg);
        for (i, si) in body.insns.iter().enumerate() {
            if !matches!(si.insn, Insn::Ret) {
                continue;
            }
            let defined_here = must_defined_at(&mustdef, cfg, body, i);
            for r in &result_regs {
                if !defined_here.contains(&norm64(*r)) {
                    diags.push(
                        Diagnostic::warn(
                            DiagCode::Contract,
                            "result-undefined",
                            format!(
                                "`{}` returns with result register {} possibly undefined on some path",
                                sym.name,
                                r.name()
                            ),
                            si.span,
                        )
                        .with_help("write the result place on every path before `return`"),
                    );
                }
            }
        }
    }

    diags
}

/// Result registers, recovered from any call site's contract targeting this
/// symbol (the resolver attached the callee's result regs there). Empty if the
/// function is never called in this module.
pub fn result_regs_of(module: &Module, body: &FnBody) -> Vec<Reg> {
    // Prefer the body's own signature-derived result regs.
    if !body.result_regs.is_empty() {
        return body.result_regs.iter().map(|r| norm64(*r)).collect();
    }
    for b in &module.bodies {
        for si in &b.insns {
            if let Insn::Call { sym, contract } = &si.insn {
                if *sym == body.symbol && !contract.results.is_empty() {
                    return contract.results.iter().map(|r| norm64(*r)).collect();
                }
            }
        }
    }
    Vec::new()
}

/// Forward must-defined analysis: block id → registers definitely written at
/// block *entry*. Entry block starts empty; calls kill caller-saved regs.
fn must_defined(body: &FnBody, cfg: &Cfg) -> HashMap<usize, HashSet<Reg>> {
    let n = body.insns.len();
    // gen/kill per instruction index
    let mut entry: HashMap<usize, HashSet<Reg>> = HashMap::new();
    entry.insert(0, HashSet::new());
    let mut worklist: Vec<usize> = vec![0];
    let mut guard = 0;

    while let Some(bi) = worklist.pop() {
        guard += 1;
        if guard > 10_000 {
            break;
        }
        let bb = &cfg.blocks[bi];
        let mut set = entry.get(&bi).cloned().unwrap_or_default();
        let (s, e) = bb.insns;
        for i in s..e.min(n) {
            let info = insn_info(&body.insns[i].insn);
            if info.is_call {
                set.retain(|r| yana_codegen::insn::is_callee_saved(*r));
            }
            for w in &info.writes {
                let w = norm64(*w);
                if w != norm64(Reg::Rip) {
                    set.insert(w);
                }
            }
        }
        // exit set `set` → intersect into each successor's entry
        for &succ in &bb.succs {
            let e = entry.entry(succ).or_insert_with(|| set.clone());
            let before = e.clone();
            *e = before.intersection(&set).cloned().collect();
            if *e != before {
                worklist.push(succ);
            }
        }
    }
    entry
}

/// Must-defined set at a specific instruction index (walk from its block entry).
fn must_defined_at(
    entry: &HashMap<usize, HashSet<Reg>>,
    cfg: &Cfg,
    body: &FnBody,
    idx: usize,
) -> HashSet<Reg> {
    let Some(bb) = cfg.blocks.iter().find(|bb| idx >= bb.insns.0 && idx < bb.insns.1) else {
        return HashSet::new();
    };
    let mut set = entry.get(&bb.id).cloned().unwrap_or_default();
    for i in bb.insns.0..idx {
        let info = insn_info(&body.insns[i].insn);
        if info.is_call {
            set.retain(|r| yana_codegen::insn::is_callee_saved(*r));
        }
        for w in &info.writes {
            set.insert(norm64(*w));
        }
    }
    set
}

/// Is a plain Ret at `ret_idx` reachable without passing a noreturn call in
/// its own block? (A coarse §5.2 check; precise path-sensitivity isn't needed
/// to catch the common `-> !` mistake.)
fn reachable_without_noreturn(body: &FnBody, cfg: &Cfg, ret_idx: usize) -> bool {
    let Some(bb) = cfg.blocks.iter().find(|bb| ret_idx >= bb.insns.0 && ret_idx < bb.insns.1) else {
        return false;
    };
    for i in bb.insns.0..ret_idx {
        if insn_info(&body.insns[i].insn).is_noreturn {
            return false;
        }
    }
    true
}
