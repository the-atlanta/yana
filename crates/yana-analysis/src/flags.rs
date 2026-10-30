//! Flag-definite analysis (§14.3 "флаги").
//!
//! Forward dataflow of *available* EFLAGS bits: a bit is available at a point
//! if some instruction on every path to that point wrote it and nothing since
//! cleared it. A `Jcc` reading an unavailable flag is a `contract` violation —
//! the classic bug of branching on flags a call or an unrelated arithmetic op
//! silently destroyed.
//!
//! Calls and syscalls destroy all flags (§5.4, §5.5), modelled as killing the
//! whole set; `lea`/`mov`/`push`/`pop` preserve flags (they write none).

use std::collections::HashMap;

use yana_ast::{DiagCode, Diagnostic};
use yana_codegen::insn::{insn_info, jcc_reads, FlagWrite};
use yana_codegen::{FnBody, Insn, Module};

use crate::cfg::Cfg;

/// The six EFLAGS bits, as a bitmask.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct FlagSet(pub u8);

pub const CF: u8 = 1 << 0;
pub const PF: u8 = 1 << 1;
pub const AF: u8 = 1 << 2;
pub const ZF: u8 = 1 << 3;
pub const SF: u8 = 1 << 4;
pub const OF: u8 = 1 << 5;
pub const ALL: u8 = CF | PF | AF | ZF | SF | OF;

impl FlagSet {
    pub const NONE: FlagSet = FlagSet(0);

    #[inline]
    pub fn union(self, o: FlagSet) -> FlagSet {
        FlagSet(self.0 | o.0)
    }
    #[inline]
    pub fn intersect(self, o: FlagSet) -> FlagSet {
        FlagSet(self.0 & o.0)
    }
    #[inline]
    pub fn diff(self, o: FlagSet) -> FlagSet {
        FlagSet(self.0 & !o.0 & ALL)
    }

    pub fn from_write(w: FlagWrite) -> FlagSet {
        let mut f = 0u8;
        if w.cf { f |= CF; }
        if w.pf { f |= PF; }
        if w.af { f |= AF; }
        if w.zf { f |= ZF; }
        if w.sf { f |= SF; }
        if w.of { f |= OF; }
        FlagSet(f)
    }

    pub fn names(self) -> Vec<&'static str> {
        let mut v = Vec::new();
        if self.0 & CF != 0 { v.push("carry"); }
        if self.0 & PF != 0 { v.push("even"); }
        if self.0 & AF != 0 { v.push("aux"); }
        if self.0 & ZF != 0 { v.push("zero"); }
        if self.0 & SF != 0 { v.push("negative"); }
        if self.0 & OF != 0 { v.push("overflow"); }
        v
    }
}

/// Flags an instruction makes available (kills the rest it writes).
///
/// `transfer(avail, insn)` = the available set after executing `insn`.
fn transfer(avail: FlagSet, insn: &Insn) -> FlagSet {
    let info = insn_info(insn);
    // A call/syscall clobbers every flag (conservative but ABI-true).
    if info.is_call || matches!(insn, Insn::Syscall) {
        return FlagSet::NONE;
    }
    let w = FlagSet::from_write(info.writes_flags);
    if w.0 == 0 {
        // flags untouched (mov/lea/push/pop/not/…): pass through
        avail
    } else {
        // written bits become available; the rest are killed (x86 writes the
        // full group — e.g. add sets cf/pf/af/zf/sf/of together)
        avail.diff(w).union(w)
    }
}

/// Flags an instruction reads (Jcc condition + explicit flag reads).
fn reads(insn: &Insn) -> FlagSet {
    let info = insn_info(insn);
    let mut r = FlagSet::from_write(info.reads_flags);
    if let Insn::Jcc { cc, .. } = insn {
        r = r.union(FlagSet::from_write(jcc_reads(*cc)));
    }
    r
}

/// Registers normalized to 64-bit for set membership (a write to `eax`
/// defines `rax` for liveness/definedness purposes).
pub(crate) fn norm64(r: yana_ast::reg::Reg) -> yana_ast::reg::Reg {
    use yana_ast::reg::RegSize;
    r.resize(RegSize::R64).unwrap_or(r)
}

/// Report every Jcc that reads a flag not available at that point.
pub fn check(module: &Module, body: &FnBody, cfg: &Cfg) -> Vec<Diagnostic> {
    let mut diags = Vec::new();
    let fn_name = module.symbols.get(body.symbol).map(|s| s.name.as_str()).unwrap_or("?");
    let n = body.insns.len();

    // Forward available-flags dataflow over blocks, iterate to a fixpoint.
    // block_entry[bi] = flags available at the first instruction of bi.
    let mut block_entry: HashMap<usize, FlagSet> = HashMap::new();
    block_entry.insert(0, FlagSet::NONE); // function entry: flags undefined

    let mut worklist: Vec<usize> = (0..cfg.blocks.len()).collect();
    let mut guard = 0;
    while let Some(bi) = worklist.pop() {
        guard += 1;
        if guard > 10_000 {
            break;
        }
        let bb = &cfg.blocks[bi];
        let (s, e) = bb.insns;
        let mut avail = *block_entry.get(&bi).unwrap_or(&FlagSet::NONE);
        for i in s..e.min(n) {
            avail = transfer(avail, &body.insns[i].insn);
        }
        // propagate the block-exit set to successors' entries (intersection)
        for &succ in &bb.succs {
            let entry = block_entry.entry(succ).or_insert(FlagSet(ALL));
            let merged = entry.intersect(avail);
            if merged != *entry {
                *entry = merged;
                worklist.push(succ);
            }
        }
    }

    // Second walk: with converged entry sets, check each Jcc precisely.
    for bi in 0..cfg.blocks.len() {
        let bb = &cfg.blocks[bi];
        let (s, e) = bb.insns;
        let mut avail = *block_entry.get(&bi).unwrap_or(&FlagSet::NONE);
        for i in s..e.min(n) {
            let si = &body.insns[i];
            let rd = reads(&si.insn);
            if rd.0 != 0 {
                let missing = rd.diff(avail);
                if missing.0 != 0 {
                    diags.push(
                        Diagnostic::warn(
                            DiagCode::Contract,
                            "undefined-flags",
                            format!(
                                "branch in `{fn_name}` reads flag(s) {} that no reaching instruction set",
                                missing.names().join(", ")
                            ),
                            si.span,
                        )
                        .with_help(
                            "put a `cmp` (or other flag-setting instruction) before the branch; \
                             calls and syscalls destroy all flags (§5.4)",
                        ),
                    );
                }
            }
            avail = transfer(avail, &si.insn);
        }
    }

    diags
}
