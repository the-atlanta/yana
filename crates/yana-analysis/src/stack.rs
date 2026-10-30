//! Stack-depth analysis (§14.3 "глубина стека").
//!
//! Forward dataflow tracking rsp displacement from the entry value. Detects:
//! - unbalanced stack at `ret` (pushes not matched by pops)
//! - underflow (popping below the entry depth)
//! - a block reached with two different depths (control-flow joins a mismatch)
//!
//! Also computes the maximum depth, which the Xtensa backend needs for
//! `entry a1, framesize` (§15 ✅ 29.10) and the `align 16` sugar (§4.3).

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
    /// deepest point reached, in bytes (for frame sizing).
    pub max_depth: i32,
}

/// Compute stack facts and report imbalance diagnostics.
pub fn check(module: &Module, body: &FnBody, cfg: &Cfg) -> Vec<Diagnostic> {
    let mut diags = Vec::new();
    let facts = analyze(body, cfg, &mut diags);
    let _ = facts;
    let _ = module;
    diags
}

/// Run the dataflow; push diagnostics into `diags`; return the facts.
pub fn analyze(body: &FnBody, cfg: &Cfg, diags: &mut Vec<Diagnostic>) -> StackFacts {
    let mut block_entry: HashMap<usize, i32> = HashMap::new();
    block_entry.insert(0, 0);
    let mut worklist: Vec<usize> = vec![0];
    let mut max_depth = 0i32;

    while let Some(bi) = worklist.pop() {
        let Some(bb) = cfg.blocks.get(bi) else { continue };
        let start_depth = *block_entry.get(&bi).unwrap_or(&0);
        let (s, e) = bb.insns;
        let mut depth = start_depth;
        for i in s..e.min(body.insns.len()) {
            let si = &body.insns[i];
            let info = insn_info(&si.insn);
            // depth is measured as bytes pushed (positive = deeper)
            if let Insn::Ret = si.insn {
                if depth != 0 {
                    diags.push(
                        Diagnostic::error(
                            DiagCode::Contract,
                            "stack-unbalanced",
                            format!("stack is {depth} byte(s) off at `return` — pushes not balanced by pops"),
                            si.span,
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
                        si.span,
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

    StackFacts { block_entry, max_depth }
}

fn block_head_span(body: &FnBody, cfg: &Cfg, bi: usize) -> Span {
    cfg.blocks
        .get(bi)
        .and_then(|bb| body.insns.get(bb.insns.0.min(body.insns.len().saturating_sub(1))))
        .map(|si| si.span)
        .unwrap_or(Span::DUMMY)
}

/// Max frame depth in bytes for a function (used by the Xtensa backend).
pub fn max_frame_bytes(body: &FnBody, cfg: &Cfg) -> i32 {
    let mut diags = Vec::new();
    analyze(body, cfg, &mut diags).max_depth
}
