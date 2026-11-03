//! Stack-depth analysis (§14.3 "глубина стека").
//!
//! Forward dataflow tracking rsp displacement from the entry value. Detects:
//! - unbalanced stack at `ret` (pushes not matched by pops)
//! - underflow (popping below the entry depth)
//! - a block reached with two different depths (control-flow joins a mismatch)
//!
//! Also computes the maximum depth, which the Xtensa backend needs for
//! `entry a1, framesize` (§15 ✅ 29.10), and lowers the `align N;` sugar
//! (§4.3): each [`Insn::StackAlign`] is rewritten in place to a concrete
//! [`Insn::StackPad`] once the static depth at that point is known.

use std::collections::HashMap;

use yana_ast::{DiagCode, Diagnostic, Span};
use yana_codegen::insn::insn_info;
use yana_codegen::{FnBody, Insn, Module};

use crate::cfg::Cfg;

/// Per-block entry stack depth (bytes below the entry rsp; positive = deeper).
#[derive(Debug, Clone, Default)]
pub struct StackFacts {
    /// block id → entry depth in bytes (i32 so underflow shows as negative).
    pub block_entry: HashMap<usize, i32>,
    /// instruction index → depth in bytes *before* that instruction executes.
    pub depth_before: HashMap<usize, i32>,
    /// deepest point reached, in bytes (for frame sizing).
    pub max_depth: i32,
}

/// Lower every `align N;` and report stack-imbalance diagnostics for the whole
/// module. Runs before the other analyses and before codegen, so the backends
/// only ever see concrete [`Insn::StackPad`] (never [`Insn::StackAlign`]).
///
/// `pad = (entry_offset − depth) mod N`, making `rsp ≡ 0 (mod N)` after the
/// pad. On SysV x86-64 `entry_offset` is 8 (the `call` pushed the return
/// address), so `align 16;` in a fresh function pads by 8.
pub fn lower_and_check(module: &mut Module) -> Vec<Diagnostic> {
    let call_offset = module.target.stack_entry_offset();
    // First infer every function's net rsp change and copy it into call
    // contracts, so cross-function `push`/`pop` balances in the walk below.
    infer_deltas(module, call_offset);
    let mut diags = Vec::new();
    // CFGs borrow the module immutably; build them all first, then walk mutably.
    let cfgs: Vec<Cfg> = module.bodies.iter().map(|b| crate::cfg::build(module, b)).collect();
    let naked: Vec<bool> = module
        .bodies
        .iter()
        .map(|b| module.symbols.get(b.symbol).map(|s| s.naked).unwrap_or(false))
        .collect();
    for ((body, cfg), is_naked) in module.bodies.iter_mut().zip(cfgs).zip(naked) {
        // §5.6: `#[naked]` bodies manage rsp by hand; no balance check.
        if is_naked {
            continue;
        }
        // The process-entry function starts with the kernel's 16-aligned rsp
        // (no caller pushed a return address) → offset 0; every other function
        // is entered via `call` → the ABI offset (8 on SysV x86-64).
        let is_entry = module.entry == Some(body.symbol);
        let entry_offset = if is_entry { 0 } else { call_offset };
        walk(body, &cfg, entry_offset, &mut diags);
    }
    diags
}

/// Infer each function's net `rsp` change and patch every `call` contract.
///
/// A function's delta can depend on the deltas of functions it calls, so this
/// is a fixed point. Recursion that never settles is left at the last value
/// (the diagnostic walk will still report any real imbalance).
fn infer_deltas(module: &mut Module, call_offset: i32) {
    for _round in 0..8 {
        let cfgs: Vec<Cfg> = module.bodies.iter().map(|b| crate::cfg::build(module, b)).collect();
        let mut deltas = vec![0i32; module.symbols.len()];
        let mut changed = false;

        for (body, cfg) in module.bodies.iter().zip(cfgs.iter()) {
            if module.symbols.get(body.symbol).map(|s| s.naked).unwrap_or(false) {
                continue; // §5.6: the body owns rsp; assume balanced
            }
            let is_entry = module.entry == Some(body.symbol);
            let entry_offset = if is_entry { 0 } else { call_offset };
            let delta = infer_body_delta(body, cfg, entry_offset);
            deltas[body.symbol] = delta;
            if body.stack_delta != delta {
                changed = true;
            }
        }

        for body in &mut module.bodies {
            body.stack_delta = deltas[body.symbol];
            for si in &mut body.insns {
                if let Insn::Call { sym, contract } = &mut si.insn {
                    if let Some(&d) = deltas.get(*sym) {
                        if contract.stack_delta != d {
                            contract.stack_delta = d;
                            changed = true;
                        }
                    }
                }
            }
        }

        if !changed {
            break;
        }
    }
}

/// One body's net rsp change: `-depth` at the return, or 0 when the returns
/// disagree (the diagnostic walk reports that) or there is no `ret`.
fn infer_body_delta(body: &FnBody, cfg: &Cfg, entry_offset: i32) -> i32 {
    let mut block_entry: HashMap<usize, i32> = HashMap::new();
    block_entry.insert(0, 0);
    let mut worklist: Vec<usize> = vec![0];
    let mut ret_depths: Vec<i32> = Vec::new();

    while let Some(bi) = worklist.pop() {
        let Some(bb) = cfg.blocks.get(bi) else { continue };
        let start_depth = *block_entry.get(&bi).unwrap_or(&0);
        let (s, e) = bb.insns;
        let mut depth = start_depth;
        for i in s..e.min(body.insns.len()) {
            let insn = &body.insns[i].insn;
            if matches!(insn, Insn::Ret) {
                ret_depths.push(depth);
                continue;
            }
            if let Insn::StackAlign { align } = insn {
                let a = *align as i32;
                let pad = if a <= 0 { 0 } else { ((entry_offset - depth) % a + a) % a };
                depth += pad;
                continue;
            }
            depth -= insn_info(insn).stack_delta;
            if depth < 0 {
                depth = 0;
            }
        }
        for &succ in &bb.succs {
            if !block_entry.contains_key(&succ) {
                block_entry.insert(succ, depth);
                worklist.push(succ);
            }
        }
    }

    match ret_depths.first() {
        Some(&d) if ret_depths.iter().all(|&x| x == d) => -d,
        _ => 0,
    }
}

/// Max frame depth in bytes for a function (used by the Xtensa backend).
/// Lowers any remaining `align` on a throwaway clone first, then measures.
pub fn max_frame_bytes(body: &FnBody, cfg: &Cfg, entry_offset: i32) -> i32 {
    let mut clone = body.clone();
    let mut diags = Vec::new();
    walk(&mut clone, cfg, entry_offset, &mut diags).max_depth
}

/// The forward dataflow walk. Mutates `body` to lower `align`; pushes
/// imbalance diagnostics; returns the computed facts.
fn walk(
    body: &mut FnBody,
    cfg: &Cfg,
    entry_offset: i32,
    diags: &mut Vec<Diagnostic>,
) -> StackFacts {
    let mut block_entry: HashMap<usize, i32> = HashMap::new();
    let mut depth_before: HashMap<usize, i32> = HashMap::new();
    block_entry.insert(0, 0);
    let mut worklist: Vec<usize> = vec![0];
    let mut max_depth = 0i32;

    while let Some(bi) = worklist.pop() {
        let Some(bb) = cfg.blocks.get(bi) else { continue };
        let start_depth = *block_entry.get(&bi).unwrap_or(&0);
        let (s, e) = bb.insns;
        let mut depth = start_depth;
        for i in s..e.min(body.insns.len()) {
            depth_before.insert(i, depth);

            // Lower `align N;` inline: pad so rsp ≡ 0 (mod N) after this point.
            let align = if let Insn::StackAlign { align } = &body.insns[i].insn {
                Some(*align)
            } else {
                None
            };
            if let Some(align) = align {
                let a = align as i32;
                let pad = if a <= 0 { 0 } else { ((entry_offset - depth) % a + a) % a };
                body.insns[i].insn = Insn::StackPad { pad: pad as u32 };
                depth += pad;
                if depth > max_depth {
                    max_depth = depth;
                }
                continue;
            }

            let info = insn_info(&body.insns[i].insn);
            // depth is measured as bytes pushed (positive = deeper)
            if matches!(body.insns[i].insn, Insn::Ret) {
                if depth != 0 {
                    diags.push(
                        Diagnostic::error(
                            DiagCode::Contract,
                            "stack-unbalanced",
                            format!("stack is {depth} byte(s) off at `return` — pushes not balanced by pops"),
                            body.insns[i].span,
                        )
                        .with_help("pop what you pushed before returning (§4.3); a caller's `pop` cannot recover it because `ret` needs the return address on top"),
                    );
                }
                // `ret` itself pops the return address (stack_delta +8), which
                // is balanced by the caller's `call`, not by this function's
                // push/pop. Don't fold it into the intra-function depth.
                continue;
            }
            depth -= info.stack_delta; // stack_delta is negative for push
            if depth > max_depth {
                max_depth = depth;
            }
            if depth < 0 {
                let under = -depth;
                diags.push(
                    Diagnostic::error(
                        DiagCode::Semantic,
                        "stack-underflow",
                        format!("stack underflow: popped {under} byte(s) below the entry depth"),
                        body.insns[i].span,
                    )
                    .with_help("every `pop`/`_`-slot must be matched by an earlier `push` on this path (§4.3)"),
                );
                depth = 0; // resync to keep the walk useful
            }
        }
        // propagate to successors
        for &succ in &bb.succs {
            let prev = block_entry.get(&succ).copied();
            match prev {
                None => {
                    block_entry.insert(succ, depth);
                    worklist.push(succ);
                }
                Some(p) if p != depth => {
                    // join with mismatched depth — report once at the block head
                    let span = block_head_span(body, cfg, succ);
                    diags.push(
                        Diagnostic::warn(
                            DiagCode::Contract,
                            "stack-join-mismatch",
                            format!("control flow joins with stack depths {p} and {depth} — the stack is not consistent here"),
                            span,
                        )
                        .with_help("balance push/pop on every path reaching this point"),
                    );
                    // keep the first-seen depth to stay monotone and terminate
                }
                Some(_) => {}
            }
        }
    }

    StackFacts { block_entry, depth_before, max_depth }
}

fn block_head_span(body: &FnBody, cfg: &Cfg, bi: usize) -> Span {
    cfg.blocks
        .get(bi)
        .and_then(|bb| body.insns.get(bb.insns.0.min(body.insns.len().saturating_sub(1))))
        .map(|si| si.span)
        .unwrap_or(Span::DUMMY)
}
