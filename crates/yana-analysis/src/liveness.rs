//! Register liveness (§14.3 "живость") + clobber derivation (§5.4).
//!
//! Classic backward liveness over the CFG using the instruction table's
//! read/write sets. Two outputs:
//! - diagnostics: dead stores (a register written and never read before being
//!   rewritten or the function returning) — `redundant` class, since removing
//!   them is semantics-preserving;
//! - [`derive_clobbers`]: registers the body destroys (for call contracts).

use std::collections::{HashMap, HashSet};

use yana_ast::reg::Reg;
use yana_ast::{DiagCode, Diagnostic};
use yana_codegen::insn::insn_info;
use yana_codegen::{FnBody, Insn, Module};

use crate::cfg::Cfg;
use crate::flags::norm64;

/// block id → registers live at block *entry*.
pub fn liveness(body: &FnBody, cfg: &Cfg) -> HashMap<usize, HashSet<Reg>> {
    let n = body.insns.len();
    // per-instruction use/def (normalized to 64-bit families)
    let mut live_in: HashMap<usize, HashSet<Reg>> = cfg.blocks.iter().map(|b| (b.id, HashSet::new())).collect();
    let mut changed = true;
    let mut guard = 0;
    while changed && guard < 10_000 {
        changed = false;
        guard += 1;
        for bi in (0..cfg.blocks.len()).rev() {
            let bb = &cfg.blocks[bi];
            // live_out[b] = ∪ live_in[succ]
            let mut live_out: HashSet<Reg> = HashSet::new();
            for &s in &bb.succs {
                if let Some(set) = live_in.get(&s) {
                    live_out.extend(set.iter().copied());
                }
            }
            // walk block backward
            let (s, e) = bb.insns;
            let mut live = live_out;
            for i in (s..e.min(n)).rev() {
                let info = insn_info(&body.insns[i].insn);
                if info.is_call {
                    // a call may read any argument reg; contract writes are
                    // defs. Reads: everything the contract says it clobbers is
                    // NOT live across unless used after; conservatively treat
                    // callee-clobbered regs as killed, callee-saved as live.
                    live.retain(|r| yana_codegen::insn::is_callee_saved(*r));
                }
                // use before def: reads make regs live
                for r in &info.reads {
                    live.insert(norm64(*r));
                }
                // defs kill (unless also read, handled above)
                for w in &info.writes {
                    let w = norm64(*w);
                    if !info.reads.iter().any(|r| norm64(*r) == w) {
                        live.remove(&w);
                    }
                }
            }
            let prev = live_in.get(&bi).cloned().unwrap_or_default();
            if prev != live {
                live_in.insert(bi, live);
                changed = true;
            }
        }
    }
    live_in
}

/// Dead-store detection: an instruction writes a register that is not live
/// immediately afterwards AND is not read by the instruction itself.
/// Volatile-marked instructions are exempt (§12).
pub fn check(module: &Module, body: &FnBody, cfg: &Cfg) -> Vec<Diagnostic> {
    let mut diags = Vec::new();
    let live_in = liveness(body, cfg);
    let n = body.insns.len();

    for bb in &cfg.blocks {
        let (s, e) = bb.insns;
        // compute live-after for each insn by walking backward from block exit
        let mut live_out: HashSet<Reg> = HashSet::new();
        for &succ in &bb.succs {
            if let Some(set) = live_in.get(&succ) {
                live_out.extend(set.iter().copied());
            }
        }
        let mut live_after: Vec<HashSet<Reg>> = vec![HashSet::new(); n];
        for i in (s..e.min(n)).rev() {
            live_after[i] = live_out.clone();
            let info = insn_info(&body.insns[i].insn);
            if info.is_call {
                live_out.retain(|r| yana_codegen::insn::is_callee_saved(*r));
            }
            for r in &info.reads {
                live_out.insert(norm64(*r));
            }
            for w in &info.writes {
                let w = norm64(*w);
                if !info.reads.iter().any(|r| norm64(*r) == w) {
                    live_out.remove(&w);
                }
            }
        }

        for i in s..e.min(n) {
            let si = &body.insns[i];
            let info = insn_info(&si.insn);
            if info.is_volatile || info.is_call || info.writes_mem {
                continue;
            }
            // result registers of the current function are never "dead"
            let is_result_write = is_result_reg(module, body, &info.writes);
            if is_result_write {
                continue;
            }
            for w in &info.writes {
                let w64 = norm64(*w);
                if w64 == norm64(Reg::Rip) {
                    continue;
                }
                let read_by_self = info.reads.iter().any(|r| norm64(*r) == w64);
                if !read_by_self && !live_after[i].contains(&w64) {
                    // rsp writes are structural, not dead stores
                    if w64.name() == "rsp" {
                        continue;
                    }
                    diags.push(
                        Diagnostic::warn(
                            DiagCode::Redundant,
                            "dead-store",
                            format!(
                                "write to {} is never read before being overwritten or returning",
                                w.name()
                            ),
                            si.span,
                        )
                        .with_help("remove the write, or mark the binding volatile if the store is observable (§12)"),
                    );
                }
            }
        }
    }

    diags
}

fn is_result_reg(module: &Module, body: &FnBody, writes: &[Reg]) -> bool {
    // Prefer the signature-derived result regs on the body (§5.1).
    if !body.result_regs.is_empty() {
        return writes.iter().any(|w| body.result_regs.iter().any(|r| norm64(*r) == norm64(*w)));
    }
    for b in &module.bodies {
        for si in &b.insns {
            if let Insn::Call { sym, contract } = &si.insn {
                if *sym == body.symbol {
                    return writes.iter().any(|w| {
                        contract.results.iter().any(|r| norm64(*r) == norm64(*w))
                    });
                }
            }
        }
    }
    false
}

/// Derive the clobber list for a function body (§5.4 ✅ 29.10): every
/// register the body writes, transitively through calls (contract clobbers),
/// minus result registers. Callee-saved registers ARE included when actually
/// written — the contract documents observable destruction.
pub fn derive_clobbers(module: &Module, body: &FnBody) -> Vec<Reg> {
    let mut out: Vec<Reg> = Vec::new();
    // Signature-derived result regs (§5.1) are excluded from the clobber list:
    // writing your own return value isn't "clobbering".
    let result_regs: Vec<Reg> = if body.result_regs.is_empty() {
        crate::result::result_regs_of(module, body)
    } else {
        body.result_regs.iter().map(|r| norm64(*r)).collect()
    };
    for si in &body.insns {
        let info = insn_info(&si.insn);
        let mut writes: Vec<Reg> = info.writes.clone();
        if let Insn::Call { contract, .. } = &si.insn {
            writes.extend(contract.clobbers.iter().copied());
            writes.extend(contract.results.iter().copied());
        }
        for w in writes {
            let w64 = norm64(w);
            if w64.name() == "rsp" || w64 == Reg::Rip {
                continue;
            }
            if result_regs.contains(&w64) {
                continue;
            }
            if !out.contains(&w64) {
                out.push(w64);
            }
        }
    }
    // stable, ABI-ish ordering: by enc id
    out.sort_by_key(|r| match r {
        Reg::Gpr { base, .. } => base.enc_id(),
        _ => 99,
    });
    out
}
