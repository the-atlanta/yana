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
    let mut diags = Vec::new();
    // CFGs borrow the module immutably; build them all first, then walk mutably.
    let cfgs: Vec<Cfg> = module.bodies.iter().map(|b| crate::cfg::build(module, b)).collect();
    for (body, cfg) in module.bodies.iter_mut().zip(cfgs) {
        // The process-entry function starts with the kernel's 16-aligned rsp
        // (no caller pushed a return address) → offset 0; every other function
        // is entered via `call` → the ABI offset (8 on SysV x86-64).
        let is_entry = module.entry == Some(body.symbol);
        let entry_offset = if is_entry { 0 } else { call_offset };
        walk(body, &cfg, entry_offset, &mut diags);
    }
    diags
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
                        .with_help("pop what you pushed before returning (§4.3)"),
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
