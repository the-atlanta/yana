//! Basic-block CFG construction (§14.2).
//!
//! A basic block ends at any terminator (Jmp/Ret/Int3/noreturn-Call) or a Jcc
//! (which has two successors). Labels are block *starts*; a branch to a label
//! targets the block containing that label.

use std::collections::{HashMap, HashSet};

use yana_codegen::insn::insn_info;
use yana_codegen::{FnBody, Insn, Module};

/// A basic block.
#[derive(Debug, Clone)]
pub struct BasicBlock {
    /// Index in [`Cfg::blocks`].
    pub id: usize,
    /// Range of instruction indices in `body.insns` — `[start, end)`.
    pub insns: (usize, usize),
    /// Successor block ids, in order: fallthrough first, then branch target.
    /// A terminator has only its target(s); Ret/Int3 have none.
    pub succs: Vec<usize>,
    /// Predecessor block ids.
    pub preds: Vec<usize>,
}

/// The CFG of one function.
#[derive(Debug, Default)]
pub struct Cfg {
    pub blocks: Vec<BasicBlock>,
    /// instruction index → block id
    pub insn_block: Vec<usize>,
    /// label index → block id where the label sits
    pub label_block: HashMap<usize, usize>,
}

impl Cfg {
    /// Blocks in reverse postorder (a good iteration order for dataflow).
    pub fn rpo(&self) -> Vec<usize> {
        let mut visited = HashSet::new();
        let mut post = Vec::new();
        fn dfs(cfg: &Cfg, b: usize, visited: &mut HashSet<usize>, post: &mut Vec<usize>) {
            if !visited.insert(b) {
                return;
            }
            for &s in &cfg.blocks[b].succs {
                dfs(cfg, s, visited, post);
            }
            post.push(b);
        }
        if !self.blocks.is_empty() {
            dfs(self, 0, &mut visited, &mut post);
        }
        post.reverse();
        post
    }
}

/// Build the CFG for one function body.
pub fn build(module: &Module, body: &FnBody) -> Cfg {
    let n = body.insns.len();
    let mut leaders: HashSet<usize> = HashSet::new();
    leaders.insert(0);

    // label targets are leaders
    let mut label_to_insn: HashMap<usize, usize> = HashMap::new();
    for (li, def) in body.label_defs.iter().enumerate() {
        let at = def.at_insn.min(n);
        label_to_insn.insert(li, at);
        leaders.insert(at);
    }
    // instruction after any branch/jmp/ret is a leader (fallthrough)
    for (i, si) in body.insns.iter().enumerate() {
        let info = insn_info(&si.insn);
        let is_cf = matches!(si.insn, Insn::Jmp { .. } | Insn::Jcc { .. }) || info.is_terminator;
        if is_cf && i + 1 < n {
            leaders.insert(i + 1);
        }
        if let Insn::Jmp { label } | Insn::Jcc { label, .. } = &si.insn {
            if let Some(&t) = label_to_insn.get(label) {
                leaders.insert(t.min(n));
            }
        }
    }

    let mut leader_list: Vec<usize> = leaders.into_iter().collect();
    leader_list.sort_unstable();
    if leader_list.is_empty() {
        leader_list.push(0);
    }

    // map instruction index → block id
    let mut insn_block = vec![usize::MAX; n.max(1)];
    let mut blocks: Vec<BasicBlock> = Vec::new();
    let mut insn_to_block_start: HashMap<usize, usize> = HashMap::new();
    for (bi, &start) in leader_list.iter().enumerate() {
        let end = if bi + 1 < leader_list.len() { leader_list[bi + 1] } else { n };
        for i in start..end.max(start) {
            if i < n {
                insn_block[i] = bi;
            }
        }
        insn_to_block_start.insert(start, bi);
        blocks.push(BasicBlock { id: bi, insns: (start, end.max(start)), succs: vec![], preds: vec![] });
    }
    // a label pointing at n (end of body) maps to the last block
    let last_block = blocks.len().saturating_sub(1);

    // label index → block
    let mut label_block = HashMap::new();
    for (li, def) in body.label_defs.iter().enumerate() {
        let at = def.at_insn.min(n);
        let b = insn_to_block_start.get(&at).copied().unwrap_or(last_block);
        label_block.insert(li, b);
    }

    // edges
    for bi in 0..blocks.len() {
        let (start, end) = blocks[bi].insns;
        if start >= n {
            continue;
        }
        let last = end.min(n).saturating_sub(1);
        let last_insn = &body.insns[last].insn;
        let info = insn_info(last_insn);
        match last_insn {
            Insn::Jmp { label } => {
                if let Some(&t) = label_block.get(label) {
                    blocks[bi].succs.push(t);
                }
            }
            Insn::Jcc { label, .. } => {
                // fallthrough then target
                if bi + 1 < blocks.len() {
                    blocks[bi].succs.push(bi + 1);
                }
                if let Some(&t) = label_block.get(label) {
                    blocks[bi].succs.push(t);
                }
            }
            _ if info.is_terminator || info.is_noreturn => {
                // Ret/Int3/noreturn call: no successors
            }
            _ => {
                // check if a mid-block noreturn call ends it
                let noret = (start..end.min(n)).any(|i| {
                    let inf = insn_info(&body.insns[i].insn);
                    inf.is_noreturn
                });
                if !noret && bi + 1 < blocks.len() {
                    blocks[bi].succs.push(bi + 1);
                }
            }
        }
    }
    // predecessors
    let edges: Vec<(usize, usize)> = blocks
        .iter()
        .flat_map(|b| b.succs.iter().map(move |&s| (b.id, s)))
        .collect();
    for (from, to) in edges {
        if to < blocks.len() && !blocks[to].preds.contains(&from) {
            blocks[to].preds.push(from);
        }
    }

    let _ = module;
    Cfg { blocks, insn_block, label_block }
}

/// The single instruction a block ends with, if any.
pub fn block_terminator<'a>(body: &'a FnBody, bb: &BasicBlock) -> Option<&'a Insn> {
    let (s, e) = bb.insns;
    if s == e || s >= body.insns.len() {
        return None;
    }
    Some(&body.insns[e.min(body.insns.len()) - 1].insn)
}

#[cfg(test)]
mod tests {
    use super::*;
    use yana_codegen::{resolve_module, ResolveOptions, TargetInfo};

    fn module_of(src: &str) -> Module {
        let parsed = yana_parser::parse(src);
        assert!(!parsed.has_errors(), "{:?}", parsed.diagnostics.iter().map(|d| &d.message).collect::<Vec<_>>());
        resolve_module(parsed.file.as_ref().unwrap(), &TargetInfo::linux_x86_64(), &ResolveOptions::default()).module
    }

    #[test]
    fn loop_has_back_edge() {
        let m = module_of(
            r#"
#[entry]
fn main() -> ! {
    bind mut n @ rbx: u64 = 3;
    label (loop) {
        branch (n == 0) => 'done;
        alt n -= 1;
        branch => 'loop;
    }
    label (done) { syscall; }
}
"#,
        );
        let body = &m.bodies[0];
        let cfg = build(&m, body);
        // there is a back edge: some block's successor has a lower id
        let back = cfg.blocks.iter().any(|b| b.succs.iter().any(|&s| s < b.id));
        assert!(back, "no back edge in a loop: {:?}", cfg.blocks.iter().map(|b| (b.id, b.succs.clone())).collect::<Vec<_>>());
    }

    #[test]
    fn rpo_visits_all_reachable() {
        let m = module_of("fn f() -> rax: u64 { alt rax = 1; return; }");
        let cfg = build(&m, &m.bodies[0]);
        let rpo = cfg.rpo();
        assert!(!rpo.is_empty());
        assert_eq!(rpo[0], 0);
    }
}
