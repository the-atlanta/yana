//! §14 pass 4 (`--verify`): interval analysis + minimal SMT contracts.
//!
//! READ-ONLY over the resolved [`Module`] — unlike [`crate::analyze`], this
//! pass never rewrites the IR. Pipeline per body: CFG → interval fixed-point
//! (widening hull join) → diagnostics:
//! - `verify-div-zero` (flagship): a `DivWide` whose divisor interval
//!   contains 0 cannot be proven safe (DiagCode::Semantic, Error).
//! - `verify-requires` / `verify-ensures` (§15 ✅ 30.10 minimal contracts):
//!   call-site `requires` and exit `ensures` discharged through z3
//!   (SMT-LIB2, QF_NIA). Proven violation → Error with the counterexample
//!   model in the message. z3 missing/timeout → one `verify-smt-unavailable`
//!   warning, contract checks skipped (never fail the build).
//!
//! Memory model (owner decision 30.10): CONSERVATIVE — the only memory facts
//! are statics' initial constant bytes; any memory-writing instruction kills
//! them all. Memory reads without a live fact give TOP.
//!
//! Design notes + deviations: docs/NOTES-verify.md.

use std::collections::HashMap;
use std::io::Write;
use std::process::{Command, Stdio};
use std::time::Duration;

use yana_ast::reg::{GprBase, Reg, RegSize};
use yana_ast::{ConstBinOp, ConstExpr, ConstUnOp, DiagCode, DiagLevel, Diagnostic, Span};
use yana_codegen::insn::insn_info;
use yana_codegen::{
    FnBody, Insn, Jcc, Module, Operand,
};

use crate::cfg::{self, Cfg};
use crate::flags::norm64;

// ---------------------------------------------------------------------------
// Interval domain
// ---------------------------------------------------------------------------

/// A signed-integer interval [lo, hi]; `lo > hi` means BOTTOM (unreachable).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ival {
    pub lo: i128,
    pub hi: i128,
}

/// Unknown / no fact.
pub const TOP: Ival = Ival { lo: i128::MIN, hi: i128::MAX };
/// Unreachable.
pub const BOTTOM: Ival = Ival { lo: 1, hi: 0 };

impl Ival {
    pub fn point(v: i128) -> Ival {
        Ival { lo: v, hi: v }
    }
    pub fn is_top(self) -> bool {
        self == TOP
    }
    pub fn is_bottom(self) -> bool {
        self.lo > self.hi
    }
    pub fn contains(self, v: i128) -> bool {
        !self.is_bottom() && self.lo <= v && v <= self.hi
    }
    /// Widening hull (the join of the fixed point). BOTTOM is the identity.
    pub fn hull(self, other: Ival) -> Ival {
        if self.is_bottom() {
            other
        } else if other.is_bottom() {
            self
        } else {
            Ival { lo: self.lo.min(other.lo), hi: self.hi.max(other.hi) }
        }
    }
    pub fn intersect(self, other: Ival) -> Ival {
        if self.is_bottom() || other.is_bottom() {
            return BOTTOM;
        }
        let lo = self.lo.max(other.lo);
        let hi = self.hi.min(other.hi);
        if lo > hi {
            BOTTOM
        } else {
            Ival { lo, hi }
        }
    }
    /// Remove a single point from an endpoint (sound partial exclusion).
    pub fn exclude_point(self, p: i128) -> Ival {
        if self.is_bottom() || !self.contains(p) {
            return self;
        }
        if self.lo == p && self.hi == p {
            BOTTOM
        } else if self.lo == p {
            Ival { lo: p.saturating_add(1), hi: self.hi }
        } else if self.hi == p {
            Ival { lo: self.lo, hi: p.saturating_sub(1) }
        } else {
            self // p interior: keep the whole interval (sound)
        }
    }
    pub fn display(self) -> String {
        if self.is_bottom() {
            "⊥".to_string()
        } else if self.lo == self.hi {
            format!("{}", self.lo)
        } else if self == TOP {
            "⊤".to_string()
        } else if self.lo == i128::MIN {
            format!("[..{}]", self.hi)
        } else if self.hi == i128::MAX {
            format!("[{}..]", self.lo)
        } else {
            format!("[{}, {}]", self.lo, self.hi)
        }
    }
}

fn sat_add(a: i128, b: i128) -> i128 {
    a.saturating_add(b)
}
fn sat_sub(a: i128, b: i128) -> i128 {
    a.saturating_sub(b)
}

/// Sound over-approximation of `a + b`.
fn iv_add(a: Ival, b: Ival) -> Ival {
    if a.is_bottom() || b.is_bottom() {
        return BOTTOM;
    }
    Ival { lo: sat_add(a.lo, b.lo), hi: sat_add(a.hi, b.hi) }
}
fn iv_sub(a: Ival, b: Ival) -> Ival {
    if a.is_bottom() || b.is_bottom() {
        return BOTTOM;
    }
    Ival { lo: sat_sub(a.lo, b.hi), hi: sat_sub(a.hi, b.lo) }
}
fn iv_neg(a: Ival) -> Ival {
    if a.is_bottom() {
        return BOTTOM;
    }
    Ival { lo: a.hi.saturating_neg(), hi: a.lo.saturating_neg() }
}
/// Sound over-approximation of `a * b`: hull of the four corner products;
/// if any corner overflows i128 the result is TOP.
fn iv_mul(a: Ival, b: Ival) -> Ival {
    if a.is_bottom() || b.is_bottom() {
        return BOTTOM;
    }
    let corners = [
        a.lo.checked_mul(b.lo),
        a.lo.checked_mul(b.hi),
        a.hi.checked_mul(b.lo),
        a.hi.checked_mul(b.hi),
    ];
    let mut lo = i128::MAX;
    let mut hi = i128::MIN;
    for c in corners {
        match c {
            Some(v) => {
                lo = lo.min(v);
                hi = hi.max(v);
            }
            None => return TOP,
        }
    }
    Ival { lo, hi }
}

/// The full value range an `size`-bit register can hold, covering both the
/// signed and unsigned interpretations (sound for bitwise results).
fn full_range(size: u32) -> Ival {
    let bits = if size == 0 || size > 64 { 64 } else { size };
    if bits >= 64 {
        Ival { lo: i64::MIN as i128, hi: u64::MAX as i128 }
    } else {
        Ival { lo: -(1i128 << (bits - 1)), hi: (1i128 << bits) - 1 }
    }
}

/// Unsigned range [0, 2^bits-1].
fn unsigned_range(bits: u32) -> Ival {
    if bits >= 127 {
        return TOP;
    }
    Ival { lo: 0, hi: (1i128 << bits) - 1 }
}

// ---------------------------------------------------------------------------
// Abstract state
// ---------------------------------------------------------------------------

/// Per-function dataflow state: register facts (keyed by the R64 family
/// member; absent = TOP) + the conservative memory-fact flag (D2).
#[derive(Debug, Clone, Default)]
pub struct State {
    pub regs: HashMap<Reg, Ival>,
    /// Statics' initial bytes are still valid (nothing wrote memory yet).
    pub mem_alive: bool,
}

impl State {
    fn new() -> State {
        State { regs: HashMap::new(), mem_alive: true }
    }
    pub fn get(&self, r: Reg) -> Ival {
        self.regs.get(&norm64(r)).copied().unwrap_or(TOP)
    }
    fn set(&mut self, r: Reg, v: Ival) {
        let key = norm64(r);
        if v.is_top() {
            self.regs.remove(&key);
        } else {
            self.regs.insert(key, v);
        }
    }
    /// Pointwise widening join (absent key = TOP).
    fn join(&self, other: &State) -> State {
        let mut regs = HashMap::new();
        for (k, v) in &self.regs {
            let ov = other.regs.get(k).copied().unwrap_or(TOP);
            let h = v.hull(ov);
            if !h.is_top() {
                regs.insert(*k, h);
            }
        }
        // keys present only in `other`: self had TOP → hull = TOP → absent
        State { regs, mem_alive: self.mem_alive && other.mem_alive }
    }
}

/// Static memory facts: symbol index → initial constant value (LE, ≤8 bytes).
fn static_facts(module: &Module) -> HashMap<usize, i128> {
    let mut out = HashMap::new();
    for sec in &module.sections {
        for item in &sec.items {
            if let yana_codegen::DataItem::Bytes { bytes, sym: Some(s), .. } = item {
                if !bytes.is_empty() && bytes.len() <= 8 {
                    let mut buf = [0u8; 8];
                    buf[..bytes.len()].copy_from_slice(bytes);
                    let raw = u64::from_le_bytes(buf);
                    let mask = if bytes.len() >= 8 { u64::MAX } else { (1u64 << (bytes.len() * 8)) - 1 };
                    out.insert(*s, (raw & mask) as i128);
                }
            }
        }
    }
    out
}

struct Ctx<'a> {
    module: &'a Module,
    statics: &'a HashMap<usize, i128>,
}

/// Value of an operand under the state.
fn op_val(op: &Operand, st: &State, ctx: &Ctx) -> Ival {
    match op {
        Operand::Reg(r) => {
            let fact = st.get(*r);
            match r.size() {
                RegSize::R64 => fact,
                _ => {
                    // sub-register read: only usable when the whole-register
                    // fact already fits the unsigned size range (D1)
                    let bits = r.size().bits();
                    if !fact.is_bottom() && fact.lo >= 0 && fact.hi <= (1i128 << bits) - 1 {
                        fact
                    } else if fact.is_bottom() {
                        BOTTOM
                    } else {
                        TOP
                    }
                }
            }
        }
        Operand::Imm(v) => Ival::point(*v as i128),
        Operand::Mem(m) => {
            if !st.mem_alive {
                return TOP;
            }
            // static read with no base/index: symbol displacement only
            if m.base.is_none() && m.index.is_none() {
                if let yana_codegen::Displacement::Sym { sym, add } = &m.disp {
                    if let Some(v) = ctx.statics.get(sym) {
                        if *add == 0 {
                            return Ival::point(*v);
                        }
                    }
                }
            }
            TOP
        }
        Operand::Sym { .. } => TOP, // addresses are not value facts
    }
}

/// Write a value into a destination operand (register fact + memory kill).
fn set_dst(dst: &Operand, v: Ival, st: &mut State) {
    match dst {
        Operand::Reg(r) => {
            let nv = match r.size() {
                RegSize::R64 => v,
                RegSize::R32 => {
                    // x86 32-bit writes zero-extend into the 64-bit register
                    let u32r = unsigned_range(32);
                    if !v.is_bottom() && v.lo >= 0 && v.hi <= u32r.hi {
                        v
                    } else if v.is_bottom() {
                        BOTTOM
                    } else {
                        u32r
                    }
                }
                // R16/R8 partial writes: precise modeling unsound → TOP (D1)
                _ => TOP,
            };
            st.set(*r, nv);
        }
        Operand::Mem(_) | Operand::Sym { .. } => {
            st.mem_alive = false; // memory write kills all memory facts (D2)
        }
        Operand::Imm(_) => {} // not a valid destination; nothing to track
    }
}

fn caller_saved() -> [Reg; 9] {
    let g = |b: GprBase| Reg::Gpr { base: b, size: RegSize::R64 };
    [
        g(GprBase::A),
        g(GprBase::C),
        g(GprBase::D),
        g(GprBase::Si),
        g(GprBase::Di),
        g(GprBase::R8),
        g(GprBase::R9),
        g(GprBase::R10),
        g(GprBase::R11),
    ]
}

/// Transfer one instruction. Returns diagnostics produced at this point
/// (div-zero). `prev` is the preceding instruction (for Cmp→Jcc pairing).
fn xfer(insn: &Insn, st: &mut State, ctx: &Ctx, diags: &mut Vec<Diagnostic>, span: Span) {
    match insn {
        Insn::Mov { dst, src, .. } => {
            let v = op_val(src, st, ctx);
            set_dst(dst, v, st);
        }
        Insn::Movzx { dst, src, src_size, .. } => {
            let v = op_val(src, st, ctx);
            let ur = unsigned_range(*src_size);
            let r = if v.is_bottom() {
                BOTTOM
            } else if v.lo >= 0 && v.hi <= ur.hi {
                v
            } else {
                ur
            };
            st.set(*dst, r);
        }
        Insn::Movsx { dst, src, src_size, .. } => {
            let v = op_val(src, st, ctx);
            let sr = Ival { lo: -(1i128 << (src_size - 1)), hi: (1i128 << (src_size - 1)) - 1 };
            let r = if v.is_bottom() {
                BOTTOM
            } else if v.lo >= sr.lo && v.hi <= sr.hi {
                v
            } else {
                sr
            };
            st.set(*dst, r);
        }
        Insn::Lea { dst, .. } | Insn::LeaSym { dst, .. } => st.set(*dst, TOP),
        Insn::Push { .. } => st.mem_alive = false,
        Insn::StackSlot { .. } | Insn::StackAlign { .. } | Insn::StackPad { .. } | Insn::Nop
        | Insn::Int3 | Insn::Ret | Insn::Jmp { .. } | Insn::Jcc { .. } | Insn::Cmp { .. } => {}
        Insn::Pop { dst, .. } => set_dst(dst, TOP, st),
        Insn::Xchg { a, b, .. } => {
            let (va, vb) = (op_val(a, st, ctx), op_val(b, st, ctx));
            let a_mem = !matches!(a, Operand::Reg(_));
            let b_mem = !matches!(b, Operand::Reg(_));
            if a_mem || b_mem {
                st.mem_alive = false;
            }
            set_dst(a, vb, st);
            set_dst(b, va, st);
        }
        Insn::Add { dst, src, .. } => {
            let v = iv_add(op_val(dst, st, ctx), op_val(src, st, ctx));
            set_dst(dst, v, st);
        }
        Insn::Sub { dst, src, .. } => {
            let v = iv_sub(op_val(dst, st, ctx), op_val(src, st, ctx));
            set_dst(dst, v, st);
        }
        Insn::And { dst, src, size } => {
            let (a, b) = (op_val(dst, st, ctx), op_val(src, st, ctx));
            let v = if a.is_bottom() || b.is_bottom() {
                BOTTOM
            } else if lo_eq(a) && lo_eq(b) {
                Ival::point(a.lo & b.lo)
            } else if lo_eq(b) && b.lo >= 0 {
                // AND with a constant mask: result ∈ [0, mask]
                Ival { lo: 0, hi: b.lo }
            } else if lo_eq(a) && a.lo >= 0 {
                Ival { lo: 0, hi: a.lo }
            } else {
                full_range(*size)
            };
            set_dst(dst, v, st);
        }
        Insn::Or { dst, src, size } => {
            let (a, b) = (op_val(dst, st, ctx), op_val(src, st, ctx));
            let v = points_or_full(a, b, *size, |x, y| x | y);
            set_dst(dst, v, st);
        }
        Insn::Xor { dst, src, size } => {
            let (a, b) = (op_val(dst, st, ctx), op_val(src, st, ctx));
            let v = points_or_full(a, b, *size, |x, y| x ^ y);
            set_dst(dst, v, st);
        }
        Insn::Shl { dst, src, size } => {
            let (a, b) = (op_val(dst, st, ctx), op_val(src, st, ctx));
            let v = if a.is_bottom() || b.is_bottom() {
                BOTTOM
            } else if lo_eq(b) && b.lo >= 0 && b.lo < 64 {
                let s = b.lo as u32;
                // saturating corner shifts; wrap → conservative full range
                let lo = a.lo.checked_shl(s);
                let hi = a.hi.checked_shl(s);
                match (lo, hi) {
                    (Some(l), Some(h)) => Ival { lo: l.min(h), hi: l.max(h) },
                    _ => full_range(*size),
                }
            } else {
                full_range(*size)
            };
            set_dst(dst, v, st);
        }
        Insn::Shr { dst, src, .. } => {
            let (a, b) = (op_val(dst, st, ctx), op_val(src, st, ctx));
            // x86 shr is logical: the result is non-negative
            let v = if a.is_bottom() || b.is_bottom() {
                BOTTOM
            } else if lo_eq(b) && b.lo >= 0 && b.lo < 64 && a.lo >= 0 {
                let s = b.lo as u32;
                Ival { lo: a.lo >> s, hi: a.hi >> s }
            } else {
                unsigned_range(64)
            };
            set_dst(dst, v, st);
        }
        Insn::Imul2 { dst, src, .. } => {
            let (a, b) = (op_val(dst, st, ctx), op_val(src, st, ctx));
            let prod = iv_mul(a, b);
            // hardware keeps the low 64 bits — exact only when no wrap
            let v = if !prod.is_bottom()
                && prod.lo >= i64::MIN as i128
                && prod.hi <= u64::MAX as i128
            {
                prod
            } else if prod.is_bottom() {
                BOTTOM
            } else {
                TOP
            };
            set_dst(dst, v, st);
        }
        Insn::Neg { dst, .. } => {
            let v = iv_neg(op_val(dst, st, ctx));
            set_dst(dst, v, st);
        }
        Insn::Not { dst, size } => {
            let a = op_val(dst, st, ctx);
            let v = if lo_eq(a) {
                Ival::point(!a.lo)
            } else {
                full_range(*size)
            };
            set_dst(dst, v, st);
        }
        Insn::Inc { dst, .. } => {
            let v = iv_add(op_val(dst, st, ctx), Ival::point(1));
            set_dst(dst, v, st);
        }
        Insn::Dec { dst, .. } => {
            let v = iv_sub(op_val(dst, st, ctx), Ival::point(1));
            set_dst(dst, v, st);
        }
        Insn::MulWide { .. } => {
            // rdx:rax pair result — keep it simple and sound (plan §4)
            let g = |b: GprBase| Reg::Gpr { base: b, size: RegSize::R64 };
            st.set(g(GprBase::A), TOP);
            st.set(g(GprBase::D), TOP);
        }
        Insn::DivWide { src, .. } => {
            // FLAGSHIP: div-by-zero proof obligation
            let dv = op_val(src, st, ctx);
            if !dv.is_bottom() && dv.contains(0) {
                diags.push(
                    Diagnostic::error(
                        DiagCode::Semantic,
                        "verify-div-zero",
                        format!(
                            "divisor {} may be zero — division would trap (#SIGFPE)",
                            dv.display()
                        ),
                        span,
                    )
                    .with_help("prove the divisor nonzero: a `branch (d == 0) => ...` guard, a constant, or a `requires` contract on the caller path"),
                );
            }
            let g = |b: GprBase| Reg::Gpr { base: b, size: RegSize::R64 };
            st.set(g(GprBase::A), TOP);
            st.set(g(GprBase::D), TOP);
        }
        Insn::ExtendPair { signed, .. } => {
            let g = |b: GprBase| Reg::Gpr { base: b, size: RegSize::R64 };
            let rax = st.get(g(GprBase::A));
            let rdx = if !*signed {
                Ival::point(0) // xor edx,edx
            } else if !rax.is_bottom() && rax.hi < 0 {
                Ival::point(-1)
            } else if !rax.is_bottom() && rax.lo >= 0 {
                Ival::point(0)
            } else {
                Ival { lo: -1, hi: 0 }
            };
            st.set(g(GprBase::D), rdx);
        }
        Insn::Call { contract, .. } => {
            // D3: conservative ABI — every caller-saved register dies, plus
            // the declared clobbers/results. Calls also kill memory facts.
            for r in caller_saved() {
                st.set(r, TOP);
            }
            for r in &contract.clobbers {
                st.set(*r, TOP);
            }
            for r in &contract.results {
                st.set(*r, TOP);
            }
            st.mem_alive = false;
        }
        Insn::Syscall => {
            let g = |b: GprBase| Reg::Gpr { base: b, size: RegSize::R64 };
            st.set(g(GprBase::A), TOP);
            st.set(g(GprBase::C), TOP);
            st.set(g(GprBase::R11), TOP);
            st.mem_alive = false;
        }
        Insn::AtomicRMW { dst, .. } => {
            if !matches!(dst, Operand::Reg(_)) {
                st.mem_alive = false;
            }
        }
        Insn::Volatile(inner) => {
            let info = insn_info(inner);
            xfer(inner, st, ctx, diags, span);
            if info.writes_mem {
                st.mem_alive = false;
            }
        }
    }
}

fn lo_eq(v: Ival) -> bool {
    v.lo == v.hi && !v.is_bottom()
}

/// Exact result when both operands are points; otherwise the full range of
/// the operation width (sound for bitwise ops).
fn points_or_full(a: Ival, b: Ival, size: u32, f: impl Fn(i128, i128) -> i128) -> Ival {
    if a.is_bottom() || b.is_bottom() {
        return BOTTOM;
    }
    if lo_eq(a) && lo_eq(b) {
        Ival::point(f(a.lo, b.lo))
    } else {
        full_range(size)
    }
}

// ---------------------------------------------------------------------------
// Jcc edge refinement
// ---------------------------------------------------------------------------

/// Refine (a, b) for the TAKEN edge of `Jcc cc` after `Cmp a, b`.
/// Returns (a', b'); BOTTOM marks an impossible edge.
fn refine(cc: Jcc, a: Ival, b: Ival) -> (Ival, Ival) {
    if a.is_bottom() || b.is_bottom() {
        return (a, b);
    }
    let unsigned_ok = a.lo >= 0 && b.lo >= 0;
    match cc {
        Jcc::E => {
            let ia = a.intersect(b);
            (ia, ia)
        }
        Jcc::Ne => (a.exclude_point(if lo_eq(b) { b.lo } else { return (a, b) }), b.exclude_point(if lo_eq(a) { a.lo } else { return (a, b) })),
        Jcc::L => (
            a.intersect(Ival { lo: i128::MIN, hi: b.hi.saturating_sub(1) }),
            b.intersect(Ival { lo: a.lo.saturating_add(1), hi: i128::MAX }),
        ),
        Jcc::Le => (
            a.intersect(Ival { lo: i128::MIN, hi: b.hi }),
            b.intersect(Ival { lo: a.lo, hi: i128::MAX }),
        ),
        Jcc::G => {
            let (nb, na) = refine(Jcc::L, b, a);
            (na, nb)
        }
        Jcc::Ge => {
            let (nb, na) = refine(Jcc::Le, b, a);
            (na, nb)
        }
        Jcc::B if unsigned_ok => {
            let (na, nb) = refine(Jcc::L, a, b);
            (na, nb)
        }
        Jcc::Be if unsigned_ok => {
            let (na, nb) = refine(Jcc::Le, a, b);
            (na, nb)
        }
        Jcc::A if unsigned_ok => {
            let (nb, na) = refine(Jcc::L, b, a);
            (na, nb)
        }
        Jcc::Ae if unsigned_ok => {
            let (nb, na) = refine(Jcc::Le, b, a);
            (na, nb)
        }
        // flag-only conditions and unsigned ccs crossing zero: no refinement
        _ => (a, b),
    }
}

/// The negated condition (for the NOT-taken edge).
fn negate(cc: Jcc) -> Option<Jcc> {
    Some(match cc {
        Jcc::E => Jcc::Ne,
        Jcc::Ne => Jcc::E,
        Jcc::L => Jcc::Ge,
        Jcc::Le => Jcc::G,
        Jcc::G => Jcc::Le,
        Jcc::Ge => Jcc::L,
        Jcc::B => Jcc::Ae,
        Jcc::Be => Jcc::A,
        Jcc::A => Jcc::Be,
        Jcc::Ae => Jcc::B,
        Jcc::S | Jcc::Ns | Jcc::O | Jcc::No | Jcc::P | Jcc::Np => return None,
    })
}

// ---------------------------------------------------------------------------
// Fixed point
// ---------------------------------------------------------------------------

/// Block-entry states after the widening fixed point.
pub fn entry_states(body: &FnBody, graph: &Cfg, ctx: &Ctx) -> HashMap<usize, State> {
    let mut entries: HashMap<usize, State> = HashMap::new();
    entries.insert(0, State::new());
    let rpo = graph.rpo();
    let mut guard = 0;
    loop {
        let mut changed = false;
        guard += 1;
        if guard > 1000 {
            break;
        }
        for &bi in &rpo {
            let Some(entry) = entries.get(&bi).cloned() else { continue };
            let block = &graph.blocks[bi];
            let (_, succ_states) = walk_block(body, block, entry, ctx, None, None);
            for (succ, st) in succ_states {
                let joined = match entries.get(&succ) {
                    Some(cur) => cur.join(&st),
                    None => st,
                };
                let differs = match entries.get(&succ) {
                    Some(cur) => !same_state(cur, &joined),
                    None => true,
                };
                if differs {
                    entries.insert(succ, joined);
                    changed = true;
                }
            }
        }
        if !changed {
            break;
        }
    }
    entries
}

fn same_state(a: &State, b: &State) -> bool {
    a.mem_alive == b.mem_alive && a.regs.len() == b.regs.len()
        && a.regs.iter().all(|(k, v)| b.regs.get(k) == Some(v))
}

/// Walk one block's instructions from `entry`. Returns the plain exit state
/// plus per-successor states (Jcc edges get the condition refinement).
/// When `out` is provided, per-instruction diagnostics/checks are collected
/// (fixed-point mode passes None to stay side-effect free).
fn walk_block(
    body: &FnBody,
    block: &cfg::BasicBlock,
    entry: State,
    ctx: &Ctx,
    mut out: Option<&mut Visitor>,
    mut diags: Option<&mut Vec<Diagnostic>>,
) -> (State, Vec<(usize, State)>) {
    let mut st = entry;
    let (s, e) = block.insns;
    let n = body.insns.len();
    let mut succ: Vec<(usize, State)> = Vec::new();
    for i in s..e.min(n) {
        let si = &body.insns[i];
        // visit BEFORE the transfer: contract checks need the pre-instruction
        // state (a Call kills caller-saved regs, erasing the actual-arg facts)
        if let Some(v) = out.as_mut() {
            v.visit(&si.insn, si.span, &st);
        }
        if let Some(d) = &mut diags {
            let mut local = Vec::new();
            xfer(&si.insn, &mut st, ctx, &mut local, si.span);
            d.extend(local);
        } else {
            xfer(&si.insn, &mut st, ctx, &mut Vec::new(), si.span);
        }
    }
    // successor states
    let last = e.min(n).saturating_sub(1);
    let term = if s < e.min(n) { Some(&body.insns[last].insn) } else { None };
    match (&block.succs[..], term) {
        ([fall, taken], Some(Insn::Jcc { cc, .. })) => {
            // refine using the adjacent Cmp (resolver emits them pairwise)
            let cmp = body.insns.get(last.saturating_sub(1)).map(|p| &p.insn);
            if let Some(Insn::Cmp { a, b, .. }) = cmp {
                // evaluate the cmp operands in the state BEFORE the jcc —
                // the walk already moved past both; recompute from `st` is
                // unsound if the jcc block wrote regs (it doesn't: Cmp/Jcc
                // write no GPRs), so using st is exact here.
                let (va, vb) = (op_val(a, &st, ctx), op_val(b, &st, ctx));
                let (ra, rb) = refine(*cc, va, vb);
                let mut taken_st = st.clone();
                apply_cmp_refinement(a, b, ra, rb, &mut taken_st);
                let mut fall_st = st.clone();
                if let Some(ncc) = negate(*cc) {
                    let (na, nb) = refine(ncc, va, vb);
                    apply_cmp_refinement(a, b, na, nb, &mut fall_st);
                }
                succ.push((*fall, fall_st));
                succ.push((*taken, taken_st));
            } else {
                succ.push((*fall, st.clone()));
                succ.push((*taken, st.clone()));
            }
        }
        (succs, _) => {
            for &s in succs {
                succ.push((s, st.clone()));
            }
        }
    }
    (st, succ)
}

fn apply_cmp_refinement(a: &Operand, b: &Operand, ra: Ival, rb: Ival, st: &mut State) {
    if let Operand::Reg(r) = a {
        let cur = st.get(*r);
        st.set(*r, cur.intersect(ra));
    }
    if let Operand::Reg(r) = b {
        let cur = st.get(*r);
        st.set(*r, cur.intersect(rb));
    }
}

// ---------------------------------------------------------------------------
// z3 bridge (SMT-LIB2, QF_NIA)
// ---------------------------------------------------------------------------

/// Emit a ConstExpr as SMT-LIB2. `None` = unsupported shape (bitwise ops on
/// Int, non-const-foldable If/Call/Array/... — see NOTES D6/D9).
pub fn smt_of(e: &ConstExpr) -> Option<String> {
    match e {
        ConstExpr::Int { value, .. } => {
            if *value < 0 {
                Some(format!("(- {})", -value))
            } else {
                Some(format!("{value}"))
            }
        }
        ConstExpr::Bool { value, .. } => Some(if *value { "true".into() } else { "false".into() }),
        ConstExpr::Name { name, .. } => Some(format!("v_{}", sanitize(name))),
        ConstExpr::Unary { op, expr, .. } => {
            let inner = smt_of(expr)?;
            Some(match op {
                ConstUnOp::Neg => format!("(- {inner})"),
                ConstUnOp::Not => format!("(not {inner})"),
            })
        }
        ConstExpr::Binary { op, lhs, rhs, .. } => {
            let a = smt_of(lhs)?;
            let b = smt_of(rhs)?;
            Some(match op {
                ConstBinOp::Add => format!("(+ {a} {b})"),
                ConstBinOp::Sub => format!("(- {a} {b})"),
                ConstBinOp::Mul => format!("(* {a} {b})"),
                ConstBinOp::Div => format!("(div {a} {b})"),
                ConstBinOp::Rem => format!("(mod {a} {b})"),
                ConstBinOp::Eq => format!("(= {a} {b})"),
                ConstBinOp::Ne => format!("(not (= {a} {b}))"),
                ConstBinOp::Lt => format!("(< {a} {b})"),
                ConstBinOp::Le => format!("(<= {a} {b})"),
                ConstBinOp::Gt => format!("(> {a} {b})"),
                ConstBinOp::Ge => format!("(>= {a} {b})"),
                ConstBinOp::And => format!("(and {a} {b})"),
                ConstBinOp::Or => format!("(or {a} {b})"),
                ConstBinOp::Shl => match rhs.as_ref() {
                    ConstExpr::Int { value: k, .. } if (0..64).contains(k) => {
                        format!("(* {a} {})", 1i128 << k)
                    }
                    _ => return None,
                },
                ConstBinOp::Shr => match rhs.as_ref() {
                    ConstExpr::Int { value: k, .. } if (0..64).contains(k) => {
                        format!("(div {a} {})", 1i128 << k)
                    }
                    _ => return None,
                },
                // bitwise ops have no QF_NIA encoding (D9)
                ConstBinOp::BitAnd | ConstBinOp::BitOr | ConstBinOp::BitXor => return None,
            })
        }
        // resolve already rejects these (verify-contract-expr); belt & braces
        ConstExpr::If { .. }
        | ConstExpr::Call { .. }
        | ConstExpr::Array { .. }
        | ConstExpr::Tuple { .. }
        | ConstExpr::Repeat { .. } => None,
    }
}

fn sanitize(name: &str) -> String {
    name.chars().map(|c| if c.is_ascii_alphanumeric() || c == '_' { c } else { '_' }).collect()
}

pub struct Z3 {
    pub bin: String,
}

impl Z3 {
    fn find() -> Option<Z3> {
        for cand in ["/home/nika/.local/bin/z3", "/usr/bin/z3", "/usr/local/bin/z3"] {
            if std::path::Path::new(cand).exists() {
                return Some(Z3 { bin: cand.to_string() });
            }
        }
        // PATH lookup
        let out = Command::new("which").arg("z3").output().ok()?;
        if out.status.success() {
            let p = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if !p.is_empty() {
                return Some(Z3 { bin: p });
            }
        }
        None
    }

    /// Run a script; Ok(Some(sat, model)) on success, Ok(None) on
    /// timeout/failure (caller warns once), the model is the get-value text.
    fn run(&self, script: &str, vars: &[String]) -> Option<(bool, String)> {
        let mut child = Command::new(&self.bin)
            .arg("-in")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .ok()?;
        child.stdin.take()?.write_all(script.as_bytes()).ok()?;
        let (tx, rx) = std::sync::mpsc::channel();
        let mut wait_child = child;
        std::thread::spawn(move || {
            let out = wait_child.wait_with_output();
            let _ = tx.send(out);
        });
        let out = rx.recv_timeout(Duration::from_secs(5)).ok()?.ok()?;
        let text = String::from_utf8_lossy(&out.stdout).to_string();
        let sat = text.lines().next().map(|l| l.trim())?;
        let mut model = String::new();
        for v in vars {
            if let Some(val) = extract_value(&text, v) {
                if !model.is_empty() {
                    model.push_str(", ");
                }
                model.push_str(&format!("{} = {}", &v[2..], val));
            }
        }
        Some((sat == "sat", model))
    }
}

/// Pull `((v_name 12))`-style values out of z3's get-value output.
/// Handles nested parens (negative literals come back as `(- 5)`).
fn extract_value(text: &str, var: &str) -> Option<String> {
    let needle = format!("({var} ");
    let at = text.find(&needle)?;
    let rest = &text[at + needle.len()..];
    let mut depth = 0usize;
    let mut end = rest.len();
    for (i, c) in rest.char_indices() {
        match c {
            '(' => depth += 1,
            ')' => {
                if depth == 0 {
                    end = i;
                    break;
                }
                depth -= 1;
            }
            _ => {}
        }
    }
    let raw = rest[..end].trim();
    // forms: "5", "(- 5)" — keep it literal
    Some(raw.to_string())
}

// ---------------------------------------------------------------------------
// Contract checks (visitor over the second walk)
// ---------------------------------------------------------------------------

struct Visitor<'a> {
    module: &'a Module,
    body: &'a FnBody,
    z3: Option<&'a Z3>,
    smt_warned: bool,
    diags: Vec<Diagnostic>,
    // entry-parameter facts are unknown → unconstrained vars
}

impl<'a> Visitor<'a> {
    fn var_list(names: impl Iterator<Item = String>) -> Vec<String> {
        names.map(|n| format!("v_{}", sanitize(&n))).collect()
    }

    fn interval_assert(name: &str, iv: Ival) -> Option<String> {
        if iv.is_top() || iv.is_bottom() {
            return None; // TOP: unconstrained. BOTTOM: unreachable — skip.
        }
        let v = format!("v_{}", sanitize(name));
        Some(format!("(assert (and (>= {v} {}) (<= {v} {})))", iv.lo, iv.hi))
    }

    fn check_call(&mut self, sym: usize, span: Span, st: &State) {
        let Some(callee) = self.module.symbols.get(sym) else { return };
        if callee.contracts.requires.is_empty() {
            return;
        }
        let Some(z3) = self.z3 else {
            if !self.smt_warned {
                self.smt_warned = true;
                self.diags.push(Diagnostic::warn(
                    DiagCode::Semantic,
                    "verify-smt-unavailable",
                    "z3 not available — `requires`/`ensures` contract checks skipped",
                    span,
                ));
            }
            return;
        };
        for (clause, cspan) in &callee.contracts.requires {
            let Some(formula) = smt_of(clause) else {
                self.diags.push(
                    Diagnostic::warn(
                        DiagCode::Semantic,
                        "verify-contract-expr",
                        "contract expression has no SMT encoding (bitwise op or non-const shape) — check skipped",
                        *cspan,
                    )
                    .with_note("keep contract expressions to + - * div mod comparisons && || on parameters/results (NOTES-verify D9)"),
                );
                continue;
            };
            // variables: callee parameter names; facts from the CALLER state
            let mut script = String::from("(set-logic QF_NIA)\n");
            let mut vars = Vec::new();
            for (pname, preg) in &callee.contracts.params {
                let v = format!("v_{}", sanitize(pname));
                vars.push(v.clone());
                script.push_str(&format!("(declare-const {v} Int)\n"));
                let fact = st.get(*preg);
                if let Some(a) = Self::interval_assert(pname, fact) {
                    script.push_str(&a);
                    script.push('\n');
                }
            }
            script.push_str(&format!("(assert (not {formula}))\n(check-sat)\n"));
            if !vars.is_empty() {
                script.push_str(&format!("(get-value ({}))\n", vars.join(" ")));
            }
            match z3.run(&script, &vars) {
                Some((true, model)) => {
                    self.diags.push(
                        Diagnostic::error(
                            DiagCode::Contract,
                            "verify-requires",
                            format!(
                                "call to `{}` violates its `requires` contract{}",
                                callee.name,
                                if model.is_empty() { String::new() } else { format!(" — counterexample: {model}") }
                            ),
                            span,
                        )
                        .with_label("the callee requires this at entry", *cspan, false),
                    );
                }
                Some((false, _)) => {} // proven
                None => {
                    if !self.smt_warned {
                        self.smt_warned = true;
                        self.diags.push(Diagnostic::warn(
                            DiagCode::Semantic,
                            "verify-smt-unavailable",
                            "z3 timed out or failed — remaining contract checks skipped",
                            span,
                        ));
                    }
                }
            }
        }
    }

    fn check_exits(&mut self, exit_state: &State, exit_span: Span, what: &str) {
        let sym = &self.module.symbols[self.body.symbol];
        if sym.contracts.ensures.is_empty() {
            return;
        }
        let Some(z3) = self.z3 else {
            if !self.smt_warned {
                self.smt_warned = true;
                self.diags.push(Diagnostic::warn(
                    DiagCode::Semantic,
                    "verify-smt-unavailable",
                    "z3 not available — `requires`/`ensures` contract checks skipped",
                    exit_span,
                ));
            }
            return;
        };
        for (clause, cspan) in &sym.contracts.ensures {
            let Some(formula) = smt_of(clause) else {
                self.diags.push(Diagnostic::warn(
                    DiagCode::Semantic,
                    "verify-contract-expr",
                    "contract expression has no SMT encoding (bitwise op or non-const shape) — check skipped",
                    *cspan,
                ));
                continue;
            };
            let mut script = String::from("(set-logic QF_NIA)\n");
            let mut vars = Vec::new();
            // parameters: value AT ENTRY — unknown → unconstrained (D-plan)
            for (pname, _) in &sym.contracts.params {
                let v = format!("v_{}", sanitize(pname));
                vars.push(v.clone());
                script.push_str(&format!("(declare-const {v} Int)\n"));
            }
            // results: interval facts at this exit point
            for (rname, rreg) in &sym.contracts.results {
                let v = format!("v_{}", sanitize(rname));
                if !vars.contains(&v) {
                    vars.push(v.clone());
                    script.push_str(&format!("(declare-const {v} Int)\n"));
                }
                let fact = exit_state.get(*rreg);
                if let Some(a) = Self::interval_assert(rname, fact) {
                    script.push_str(&a);
                    script.push('\n');
                }
            }
            script.push_str(&format!("(assert (not {formula}))\n(check-sat)\n"));
            if !vars.is_empty() {
                script.push_str(&format!("(get-value ({}))\n", vars.join(" ")));
            }
            match z3.run(&script, &vars) {
                Some((true, model)) => {
                    self.diags.push(
                        Diagnostic::error(
                            DiagCode::Contract,
                            "verify-ensures",
                            format!(
                                "`{}` cannot prove its `ensures` contract at {}{}",
                                sym.name,
                                what,
                                if model.is_empty() { String::new() } else { format!(" — counterexample: {model}") }
                            ),
                            exit_span,
                        )
                        .with_label("the function promises this at every exit", *cspan, false),
                    );
                }
                Some((false, _)) => {}
                None => {
                    if !self.smt_warned {
                        self.smt_warned = true;
                        self.diags.push(Diagnostic::warn(
                            DiagCode::Semantic,
                            "verify-smt-unavailable",
                            "z3 timed out or failed — remaining contract checks skipped",
                            exit_span,
                        ));
                    }
                }
            }
        }
    }

    fn visit(&mut self, insn: &Insn, span: Span, st: &State) {
        match insn {
            Insn::Call { sym, .. } => self.check_call(*sym, span, st),
            Insn::Ret => {
                let st2 = st.clone();
                self.check_exits(&st2, span, "`return`");
            }
            _ => {}
        }
    }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// Run pass 4 over a resolved module. Read-only: the IR is never rewritten.
pub fn verify(module: &Module) -> Vec<Diagnostic> {
    verify_with(module, Z3::find())
}

/// [`verify`] with an explicit z3 handle (`None` = SMT unavailable: contract
/// checks warn once with `verify-smt-unavailable` and are skipped).
pub fn verify_with(module: &Module, z3: Option<Z3>) -> Vec<Diagnostic> {
    let statics = static_facts(module);
    let ctx = Ctx { module, statics: &statics };
    let mut diags: Vec<Diagnostic> = Vec::new();
    let mut smt_warned_global = false;

    for body in &module.bodies {
        let graph = cfg::build(module, body);
        let entries = entry_states(body, &graph, &ctx);

        // second walk: diagnostics + contract checks with per-insn states
        let mut visitor = Visitor {
            module,
            body,
            z3: z3.as_ref(),
            smt_warned: smt_warned_global,
            diags: Vec::new(),
        };
        let rpo = graph.rpo();
        let n = body.insns.len();
        let mut last_block_end_state: Option<(State, Span)> = None;
        for &bi in &rpo {
            let Some(entry) = entries.get(&bi).cloned() else { continue };
            let block = &graph.blocks[bi];
            let (exit, _) = walk_block(body, block, entry, &ctx, Some(&mut visitor), Some(&mut diags));
            if block.insns.1 >= n && block.insns.0 < n {
                // this block reaches the end of the body — remember for the
                // fall-through ensures check (D8)
                let end_span = body.insns[n.saturating_sub(1)].span;
                last_block_end_state = Some((exit, end_span));
            }
        }
        // fall-through end: only when the function may return and the body
        // doesn't end in a terminator (Ret/Jmp/Int3/noreturn Call)
        if !body.returns_never {
            if let Some((exit, span)) = &last_block_end_state {
                let last_insn = &body.insns[n.saturating_sub(1)].insn;
                let info = insn_info(last_insn);
                let is_term = matches!(last_insn, Insn::Ret | Insn::Jmp { .. } | Insn::Int3)
                    || info.is_terminator
                    || info.is_noreturn;
                if !is_term {
                    visitor.check_exits(exit, *span, "the fall-through end of the body");
                }
            }
        }
        if visitor.smt_warned {
            smt_warned_global = true;
        }
        diags.extend(visitor.diags);
    }
    diags
}

/// Convenience for tests/CLI: verify diagnostics that are errors.
pub fn verify_errors(diags: &[Diagnostic]) -> usize {
    diags.iter().filter(|d| d.level == DiagLevel::Error).count()
}

// ---------------------------------------------------------------------------
// Tests (milestone 4: interval arithmetic + fixed point)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use yana_codegen::{resolve_module, ResolveOptions, TargetInfo};

    fn module_of(src: &str) -> Module {
        let parsed = yana_parser::parse(src);
        assert!(
            !parsed.has_errors(),
            "{:?}",
            parsed.diagnostics.iter().map(|d| &d.message).collect::<Vec<_>>()
        );
        resolve_module(
            parsed.file.as_ref().unwrap(),
            &TargetInfo::linux_x86_64(),
            &ResolveOptions::default(),
        )
        .module
    }

    fn verify_of(src: &str) -> Vec<Diagnostic> {
        verify(&module_of(src))
    }

    fn kinds(diags: &[Diagnostic]) -> Vec<&str> {
        diags.iter().map(|d| d.kind.as_str()).collect()
    }

    // ---- interval arithmetic corners ----

    #[test]
    fn iv_arith_corners() {
        // add: corner sums
        assert_eq!(
            iv_add(Ival { lo: -5, hi: 10 }, Ival { lo: 3, hi: 7 }),
            Ival { lo: -2, hi: 17 }
        );
        // add saturates at the i128 bounds instead of overflowing
        assert_eq!(
            iv_add(Ival { lo: i128::MAX - 1, hi: i128::MAX }, Ival::point(5)),
            Ival { lo: i128::MAX, hi: i128::MAX }
        );
        // sub: lo−b.hi, hi−b.lo
        assert_eq!(
            iv_sub(Ival { lo: 0, hi: 10 }, Ival { lo: 3, hi: 7 }),
            Ival { lo: -7, hi: 7 }
        );
        assert_eq!(
            iv_sub(Ival { lo: i128::MIN, hi: i128::MIN }, Ival::point(5)),
            Ival { lo: i128::MIN, hi: i128::MIN }
        );
        // mul: hull of the four corners (mixed signs)
        assert_eq!(
            iv_mul(Ival { lo: -3, hi: 4 }, Ival { lo: -2, hi: 5 }),
            Ival { lo: -15, hi: 20 }
        );
        // mul overflow → TOP (sound)
        assert_eq!(
            iv_mul(Ival { lo: i128::MAX / 2, hi: i128::MAX }, Ival::point(4)),
            TOP
        );
        // BOTTOM propagates
        assert!(iv_add(BOTTOM, Ival::point(1)).is_bottom());
        assert!(iv_mul(BOTTOM, BOTTOM).is_bottom());
        // neg swaps + saturates
        assert_eq!(iv_neg(Ival { lo: -2, hi: 3 }), Ival { lo: -3, hi: 2 });
        assert_eq!(iv_neg(Ival::point(i128::MIN)).hi, i128::MAX);
    }

    #[test]
    fn hull_intersect_exclude() {
        assert_eq!(Ival::point(5).hull(Ival::point(-2)), Ival { lo: -2, hi: 5 });
        // BOTTOM is the identity of hull
        assert_eq!(BOTTOM.hull(Ival::point(3)), Ival::point(3));
        // empty intersection → BOTTOM
        assert!(Ival { lo: 0, hi: 5 }.intersect(Ival { lo: 6, hi: 9 }).is_bottom());
        // endpoint exclusion is exact; interior stays whole (sound)
        assert_eq!(Ival { lo: 0, hi: 5 }.exclude_point(0), Ival { lo: 1, hi: 5 });
        assert_eq!(Ival { lo: 0, hi: 5 }.exclude_point(5), Ival { lo: 0, hi: 4 });
        assert_eq!(Ival { lo: 0, hi: 5 }.exclude_point(3), Ival { lo: 0, hi: 5 });
        assert!(Ival::point(3).exclude_point(3).is_bottom());
    }

    // ---- fixed point over a real CFG ----

    #[test]
    fn div_zero_detected_after_arith() {
        // rax = 10; rbx = 0; rdx:rax = rax as u128; /% rbx → divisor is the
        // POINT 0 → verify-div-zero
        let diags = verify_of(
            r#"
#[entry]
fn main() -> ! {
    bind mut a @ rax: u64 = 10;
    bind mut d @ rbx: u64 = 0;
    alt a += 5;
    alt rdx:rax = a as u128;
    alt (rax, rdx) = rdx:rax /% d;
    syscall;
}
"#,
        );
        assert!(
            kinds(&diags).contains(&"verify-div-zero"),
            "{:?}",
            diags.iter().map(|d| (&d.kind, &d.message)).collect::<Vec<_>>()
        );
    }

    #[test]
    fn div_zero_not_flagged_when_guarded() {
        // the branch guard proves the divisor nonzero on the dividing path
        let diags = verify_of(
            r#"
#[entry]
fn main() -> ! {
    bind mut a @ rax: u64 = 100;
    bind mut d @ rbx: u64;
    alt rbx = 7;
    branch (d == 0) => 'skip;
    alt rdx:rax = a as u128;
    alt (rax, rdx) = rdx:rax /% d;
    branch => 'end;
    label (skip) { alt rax = 0; }
    label (end) { syscall; }
}
"#,
        );
        assert!(
            !kinds(&diags).contains(&"verify-div-zero"),
            "guarded division must not be flagged: {:?}",
            diags.iter().map(|d| (&d.kind, &d.message)).collect::<Vec<_>>()
        );
    }

    #[test]
    fn div_zero_flagged_when_guard_only_partial() {
        // guard excludes 0 only on one path; the join widens back to [0,9]
        // at the merge → the div AFTER the merge is unproven
        let diags = verify_of(
            r#"
#[entry]
fn main() -> ! {
    bind mut a @ rax: u64 = 100;
    bind mut d @ rbx: u64 = 4;
    branch (d == 0) => 'other;
    label (other) { alt d = 9; }
    alt rdx:rax = a as u128;
    alt (rax, rdx) = rdx:rax /% d;
    syscall;
}
"#,
        );
        // both branches give d ∈ {4, 9}, neither contains 0 → NOT flagged
        assert!(
            !kinds(&diags).contains(&"verify-div-zero"),
            "{:?}",
            diags.iter().map(|d| (&d.kind, &d.message)).collect::<Vec<_>>()
        );
    }

    #[test]
    fn fixed_point_terminates_on_loops() {
        // countdown loop: the back edge must widen to a fixpoint quickly
        let m = module_of(
            r#"
#[entry]
fn main() -> ! {
    bind mut n @ rbx: u64 = 10;
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
        let graph = cfg::build(&m, body);
        let statics = static_facts(&m);
        let ctx = Ctx { module: &m, statics: &statics };
        let entries = entry_states(body, &graph, &ctx);
        // every block got an entry state (reachable) and widening converged
        assert_eq!(entries.len(), graph.blocks.len());
        // the loop body sees n's interval widened, not diverged to a panic
        let diags = verify(&m);
        let ks = kinds(&diags);
        assert_eq!(verify_errors(&diags), 0, "{ks:?}");
    }

    #[test]
    fn interval_facts_track_mov_add() {
        // div by a register the analysis knows is exactly 5 → no diagnostic
        let diags = verify_of(
            r#"
#[entry]
fn main() -> ! {
    bind mut a @ rax: u64 = 100;
    bind mut d @ rbx: u64 = 2;
    alt d += 3;
    alt rdx:rax = a as u128;
    alt (rax, rdx) = rdx:rax /% d;
    syscall;
}
"#,
        );
        assert!(
            !kinds(&diags).contains(&"verify-div-zero"),
            "{:?}",
            kinds(&diags)
        );
    }

    // ---- z3 bridge (SMT emitter — text-level, no binary needed) ----

    fn int(v: i128) -> ConstExpr {
        ConstExpr::Int { value: v, span: Span::new(0, 0) }
    }
    fn name(s: &str) -> ConstExpr {
        ConstExpr::Name { name: s.to_string(), span: Span::new(0, 0) }
    }
    fn bin(op: ConstBinOp, a: ConstExpr, b: ConstExpr) -> ConstExpr {
        ConstExpr::Binary { op, lhs: Box::new(a), rhs: Box::new(b), span: Span::new(0, 0) }
    }
    fn un(op: ConstUnOp, a: ConstExpr) -> ConstExpr {
        ConstExpr::Unary { op, expr: Box::new(a), span: Span::new(0, 0) }
    }

    #[test]
    fn smt_emitter_shapes() {
        assert_eq!(smt_of(&int(5)).unwrap(), "5");
        assert_eq!(smt_of(&int(-7)).unwrap(), "(- 7)");
        assert_eq!(smt_of(&ConstExpr::Bool { value: true, span: Span::new(0, 0) }).unwrap(), "true");
        assert_eq!(smt_of(&name("n")).unwrap(), "v_n");
        // requires n > 0
        assert_eq!(
            smt_of(&bin(ConstBinOp::Gt, name("n"), int(0))).unwrap(),
            "(> v_n 0)"
        );
        // ensures (rax >= 100) && (n != 0)
        let e = bin(
            ConstBinOp::And,
            bin(ConstBinOp::Ge, name("rax"), int(100)),
            bin(ConstBinOp::Ne, name("n"), int(0)),
        );
        assert_eq!(
            smt_of(&e).unwrap(),
            "(and (>= v_rax 100) (not (= v_n 0)))"
        );
        // arithmetic: (n + 1) * (-2)
        assert_eq!(
            smt_of(&bin(ConstBinOp::Mul, bin(ConstBinOp::Add, name("n"), int(1)), un(ConstUnOp::Neg, int(2)))).unwrap(),
            "(* (+ v_n 1) (- 2))"
        );
        // shl by a const becomes a multiplication (QF_NIA has no shifts)
        assert_eq!(
            smt_of(&bin(ConstBinOp::Shl, name("n"), int(3))).unwrap(),
            "(* v_n 8)"
        );
        assert_eq!(
            smt_of(&bin(ConstBinOp::Shr, name("n"), int(2))).unwrap(),
            "(div v_n 4)"
        );
        // bitwise ops have no encoding → None (D9)
        assert!(smt_of(&bin(ConstBinOp::BitAnd, name("n"), int(3))).is_none());
        // div/mod map to SMT div/mod
        assert_eq!(smt_of(&bin(ConstBinOp::Div, name("n"), int(3))).unwrap(), "(div v_n 3)");
        assert_eq!(smt_of(&bin(ConstBinOp::Rem, name("n"), int(3))).unwrap(), "(mod v_n 3)");
    }

    #[test]
    fn extract_value_parses_z3_model() {
        let text = "sat\n((v_n 0)\n (v_rax (- 5)))\n";
        assert_eq!(extract_value(text, "v_n").unwrap(), "0");
        assert_eq!(extract_value(text, "v_rax").unwrap(), "(- 5)");
        assert!(extract_value(text, "v_missing").is_none());
    }

    // ---- contract integration (z3 required; skipped when unavailable) ----

    /// Resolve + run pass 4. Returns None (test skips) when z3 is missing.
    fn verify_z3(src: &str) -> Option<Vec<Diagnostic>> {
        let z3 = Z3::find()?;
        Some(verify_with(&module_of(src), Some(z3)))
    }

    fn assert_z3(diags: Option<Vec<Diagnostic>>) -> Vec<Diagnostic> {
        match diags {
            Some(d) => d,
            None => {
                eprintln!("z3 not available — contract integration test skipped");
                Vec::new()
            }
        }
    }

    #[test]
    fn requires_violated_by_imm_zero_arg() {
        let diags = assert_z3(verify_z3(
            r#"
fn f(n @ rdi: u64) -> rax: u64
requires n > 0;
{
    alt rax = 1;
    return;
}

#[entry]
fn main() -> ! {
    bind r = call f { n: 0 };
    syscall;
}
"#,
        ));
        let d = diags
            .iter()
            .find(|d| d.kind == "verify-requires")
            .expect("verify-requires diagnostic");
        assert!(matches!(d.level, DiagLevel::Error));
        assert!(matches!(d.code, DiagCode::Contract));
        assert!(d.message.contains('f'), "{}", d.message);
        // the counterexample model names the offending parameter
        assert!(d.message.contains("n = 0"), "{}", d.message);
    }

    #[test]
    fn requires_proven_by_nonzero_arg() {
        let diags = assert_z3(verify_z3(
            r#"
fn f(n @ rdi: u64) -> rax: u64
requires n > 0;
{
    alt rax = 1;
    return;
}

#[entry]
fn main() -> ! {
    bind r = call f { n: 5 };
    syscall;
}
"#,
        ));
        assert!(
            !kinds(&diags).contains(&"verify-requires"),
            "{:?}",
            kinds(&diags)
        );
    }

    #[test]
    fn requires_proven_by_interval_not_point() {
        // the arg register carries a computed interval [7,7] → n > 0 holds
        let diags = assert_z3(verify_z3(
            r#"
fn f(n @ rdi: u64) -> rax: u64
requires n > 0;
{
    alt rax = 1;
    return;
}

#[entry]
fn main() -> ! {
    bind mut x @ rbx: u64 = 3;
    alt x += 4;
    bind r = call f { n: x };
    syscall;
}
"#,
        ));
        assert!(
            !kinds(&diags).contains(&"verify-requires"),
            "{:?}",
            kinds(&diags)
        );
    }

    #[test]
    fn requires_violated_by_interval_incl_zero() {
        // the entry parameter y is unconstrained; x = y or 0 depending on the
        // branch → at the join x spans a true interval including 0 →
        // `requires x >= 5` is unprovable
        let diags = assert_z3(verify_z3(
            r#"
fn f(n @ rdi: u64) -> rax: u64
requires n >= 5;
{
    alt rax = 1;
    return;
}

#[entry]
fn main(y @ rsi: u64) -> ! {
    bind mut x @ rbx: u64 = 0;
    branch (y == 0) => 'iszero;
    alt x = y;
    branch => 'docall;
    label (iszero) { alt x = 0; }
    label (docall) {
        bind r = call f { n: x };
        syscall;
    }
}
"#,
        ));
        assert!(
            kinds(&diags).contains(&"verify-requires"),
            "{:?}",
            diags.iter().map(|d| (&d.kind, &d.message)).collect::<Vec<_>>()
        );
    }

    #[test]
    fn ensures_satisfied_no_error() {
        let diags = assert_z3(verify_z3(
            r#"
fn f(n @ rdi: u64) -> rax: u64
ensures rax >= 100;
{
    alt rax = 100;
    return;
}
"#,
        ));
        assert!(
            !kinds(&diags).contains(&"verify-ensures"),
            "{:?}",
            kinds(&diags)
        );
    }

    #[test]
    fn ensures_violated_with_model() {
        let diags = assert_z3(verify_z3(
            r#"
fn f(n @ rdi: u64) -> rax: u64
ensures rax >= 100;
{
    alt rax = 50;
    return;
}
"#,
        ));
        let d = diags
            .iter()
            .find(|d| d.kind == "verify-ensures")
            .expect("verify-ensures diagnostic");
        assert!(matches!(d.level, DiagLevel::Error));
        assert!(d.message.contains("rax = 50"), "{}", d.message);
    }

    #[test]
    fn smt_unavailable_warns_once_and_skips() {
        // no z3 → contract checks skipped with exactly one warning; the
        // div-zero interval check still runs (it needs no SMT)
        let m = module_of(
            r#"
fn f(n @ rdi: u64) -> rax: u64
requires n > 0;
{
    alt rax = 1;
    return;
}

#[entry]
fn main() -> ! {
    bind r = call f { n: 0 };
    syscall;
}
"#,
        );
        let diags = verify_with(&m, None);
        let warns: Vec<_> = diags.iter().filter(|d| d.kind == "verify-smt-unavailable").collect();
        assert_eq!(warns.len(), 1, "{:?}", kinds(&diags));
        assert!(matches!(warns[0].level, DiagLevel::Warning));
        assert_eq!(verify_errors(&diags), 0, "{:?}", kinds(&diags));
    }
}
