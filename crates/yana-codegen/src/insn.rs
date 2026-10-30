//! The instruction table (§14: "таблица инструкций (читает, пишет, флаги,
//! неявные операнды): один источник правды для кодировщика и анализов").
//!
//! [`insn_info`] answers, for any [`Insn`]: which architectural registers it
//! reads and writes (including implicit ones — `mul rdx:rax`, `syscall`
//! rcx/r11, …), which EFLAGS bits it writes/reads, stack effects, terminator
//! and call status. Every analysis in pass 3 (liveness, definedness, stack
//! depth, flags, clobbers) and every backend consumes this table only.

use crate::ir::{AtomicOp, CallContract, Insn, Jcc, Operand, WideOp};
use yana_ast::reg::{GprBase, Reg};

/// Which EFLAGS bits an instruction writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FlagWrite {
    pub cf: bool,
    pub pf: bool,
    pub af: bool,
    pub zf: bool,
    pub sf: bool,
    pub of: bool,
}

impl FlagWrite {
    pub const NONE: FlagWrite = FlagWrite { cf: false, pf: false, af: false, zf: false, sf: false, of: false };
    /// add/sub/cmp-style: all six.
    pub const ARITH: FlagWrite = FlagWrite { cf: true, pf: true, af: true, zf: true, sf: true, of: true };
    /// and/or/xor: cf=of=0 cleared, pf/zf/sf written, af undefined.
    pub const LOGIC: FlagWrite = FlagWrite { cf: true, pf: true, af: true, zf: true, sf: true, of: true };
    /// shl/shr: cf/of/pf/zf/sf written (cf only for 1-bit shifts, modelled
    /// conservatively as written), af undefined.
    pub const SHIFT: FlagWrite = FlagWrite { cf: true, pf: true, af: true, zf: true, sf: true, of: true };
    /// inc/dec: of/sf/zf/af/pf written, cf unchanged.
    pub const INCDEC: FlagWrite = FlagWrite { cf: false, pf: true, af: true, zf: true, sf: true, of: true };
    /// mul/imul/div/idiv: cf/of defined, rest undefined → modelled written.
    pub const MULDIV: FlagWrite = FlagWrite { cf: true, pf: true, af: true, zf: true, sf: true, of: true };

    pub fn any(self) -> bool {
        self.cf || self.pf || self.af || self.zf || self.sf || self.of
    }
}

/// The EFLAGS bit a [`Jcc`] condition code reads.
pub fn jcc_reads(cc: Jcc) -> FlagWrite {
    let mut f = FlagWrite::NONE;
    match cc {
        Jcc::E | Jcc::Ne => f.zf = true,
        Jcc::B | Jcc::Ae => f.cf = true,
        Jcc::Be | Jcc::A => {
            f.cf = true;
            f.zf = true;
        }
        Jcc::S | Jcc::Ns => f.sf = true,
        Jcc::O | Jcc::No => f.of = true,
        Jcc::P | Jcc::Np => f.pf = true,
        Jcc::L | Jcc::Ge => {
            f.sf = true;
            f.of = true;
        }
        Jcc::Le | Jcc::G => {
            f.sf = true;
            f.of = true;
            f.zf = true;
        }
    }
    f
}

/// Static properties of one instruction instance.
#[derive(Debug, Clone, PartialEq)]
pub struct InsnInfo {
    /// Architectural GPRs read (explicit operands + implicit sources).
    pub reads: Vec<Reg>,
    /// Architectural GPRs written (explicit dst + implicit destinations).
    pub writes: Vec<Reg>,
    /// Reads memory (address registers go into `reads` as well).
    pub reads_mem: bool,
    /// Writes memory.
    pub writes_mem: bool,
    /// EFLAGS bits written.
    pub writes_flags: FlagWrite,
    /// EFLAGS bits read.
    pub reads_flags: FlagWrite,
    /// rsp change in bytes (push −8, pop +8, StackSlot ∓8, call −8).
    pub stack_delta: i32,
    /// Control-flow transfer that does not fall through.
    pub is_terminator: bool,
    pub is_call: bool,
    /// `-> !` call or exit syscall: control never returns at all.
    pub is_noreturn: bool,
    /// §12 volatile/atomic marker: analysis may not remove or reorder it.
    pub is_volatile: bool,
}

impl InsnInfo {
    /// Convenience: registers this instruction reads but never writes.
    pub fn reads_only(&self) -> impl Iterator<Item = &Reg> {
        self.reads.iter().filter(move |r| !self.writes.contains(r))
    }
}

/// Registers touched by an operand (memory address regs included).
fn operand_reads(o: &Operand) -> Vec<Reg> {
    match o {
        Operand::Reg(r) => vec![*r],
        Operand::Imm(_) | Operand::Sym { .. } => vec![],
        Operand::Mem(m) => {
            let mut v = Vec::new();
            if let Some(b) = m.base {
                if b != Reg::Rip {
                    v.push(b);
                }
            }
            if let Some(i) = m.index {
                v.push(i);
            }
            v
        }
    }
}

fn operand_writes(o: &Operand) -> Vec<Reg> {
    match o {
        Operand::Reg(r) => vec![*r],
        Operand::Mem { .. } | Operand::Imm(_) | Operand::Sym { .. } => vec![],
    }
}

fn operand_writes_mem(o: &Operand) -> bool {
    matches!(o, Operand::Mem(_))
}

/// The wide-op implicit pair for a given operand size: `(hi, lo)`.
pub fn wide_pair(size: u32) -> (Reg, Reg) {
    match size {
        32 => (r32(GprBase::D), r32(GprBase::A)),
        16 => (r16(GprBase::D), r16(GprBase::A)),
        _ => (r64(GprBase::D), r64(GprBase::A)),
    }
}

const fn r64(b: GprBase) -> Reg {
    Reg::Gpr { base: b, size: yana_ast::reg::RegSize::R64 }
}
const fn r32(b: GprBase) -> Reg {
    Reg::Gpr { base: b, size: yana_ast::reg::RegSize::R32 }
}
const fn r16(b: GprBase) -> Reg {
    Reg::Gpr { base: b, size: yana_ast::reg::RegSize::R16 }
}

/// The Linux x86-64 syscall ABI (§5.5): number in rax, args rdi/rsi/rdx/r10/
/// r8/r9, result in rax, rcx and r11 destroyed.
pub const SYSCALL_ABI: [Reg; 6] = [
    r64(GprBase::Di),
    r64(GprBase::Si),
    r64(GprBase::D),
    r64(GprBase::R10),
    r64(GprBase::R8),
    r64(GprBase::R9),
];

/// Classify an instruction — the single source of truth for analyses.
pub fn insn_info(i: &Insn) -> InsnInfo {
    let base = InsnInfo {
        reads: Vec::new(),
        writes: Vec::new(),
        reads_mem: false,
        writes_mem: false,
        writes_flags: FlagWrite::NONE,
        reads_flags: FlagWrite::NONE,
        stack_delta: 0,
        is_terminator: false,
        is_call: false,
        is_noreturn: false,
        is_volatile: false,
    };
    match i {
        Insn::Mov { dst, src, .. } => InsnInfo {
            reads: operand_reads(src),
            writes: operand_writes(dst),
            reads_mem: matches!(src, Operand::Mem(_)),
            writes_mem: operand_writes_mem(dst),
            ..base
        },
        Insn::Movzx { dst, src, .. } | Insn::Movsx { dst, src, .. } => InsnInfo {
            reads: operand_reads(src),
            writes: vec![*dst],
            reads_mem: matches!(src, Operand::Mem(_)),
            ..base
        },
        Insn::Lea { dst, addr } => InsnInfo {
            reads: operand_reads(&Operand::Mem(addr.clone())),
            writes: vec![*dst],
            ..base
        },
        Insn::LeaSym { dst, .. } => InsnInfo { writes: vec![*dst], ..base },
        Insn::Push { src, .. } => InsnInfo {
            reads: operand_reads(src),
            reads_mem: false,
            writes_mem: true, // pushes write [rsp-8]
            stack_delta: -8,
            ..base
        },
        Insn::Pop { dst, .. } => InsnInfo {
            writes: operand_writes(dst),
            writes_mem: operand_writes_mem(dst),
            reads_mem: true, // pops read [rsp]
            stack_delta: 8,
            ..base
        },
        Insn::StackSlot { grow } => InsnInfo {
            reads: vec![r64(GprBase::Sp)],
            writes: vec![r64(GprBase::Sp)],
            stack_delta: if *grow { -8 } else { 8 },
            ..base
        },
        // Unlowered `align N;`: the concrete pad isn't known until the stack
        // analysis rewrites it into StackPad (§4.3 + §14.3). Delta 0 here —
        // the analysis handles StackAlign specially.
        Insn::StackAlign { .. } => InsnInfo {
            reads: vec![r64(GprBase::Sp)],
            writes: vec![r64(GprBase::Sp)],
            ..base
        },
        Insn::StackPad { pad } => InsnInfo {
            reads: vec![r64(GprBase::Sp)],
            writes: vec![r64(GprBase::Sp)],
            stack_delta: -(*pad as i32),
            ..base
        },
        Insn::Xchg { a, b, .. } => {
            let mut reads = operand_reads(a);
            reads.extend(operand_reads(b));
            let mut writes = operand_writes(a);
            writes.extend(operand_writes(b));
            InsnInfo {
                reads,
                writes,
                reads_mem: matches!(a, Operand::Mem(_)) || matches!(b, Operand::Mem(_)),
                writes_mem: matches!(a, Operand::Mem(_)) || matches!(b, Operand::Mem(_)),
                ..base
            }
        }
        Insn::Add { dst, src, .. } | Insn::Sub { dst, src, .. } => InsnInfo {
            reads: {
                let mut r = operand_reads(src);
                // dst is read too (read-modify-write)
                r.extend(operand_reads(dst));
                r
            },
            writes: operand_writes(dst),
            reads_mem: matches!(src, Operand::Mem(_)) || matches!(dst, Operand::Mem(_)),
            writes_mem: operand_writes_mem(dst),
            writes_flags: FlagWrite::ARITH,
            ..base
        },
        Insn::And { dst, src, .. } | Insn::Or { dst, src, .. } | Insn::Xor { dst, src, .. } => InsnInfo {
            reads: {
                let mut r = operand_reads(src);
                r.extend(operand_reads(dst));
                r
            },
            writes: operand_writes(dst),
            reads_mem: matches!(src, Operand::Mem(_)) || matches!(dst, Operand::Mem(_)),
            writes_mem: operand_writes_mem(dst),
            writes_flags: FlagWrite::LOGIC,
            ..base
        },
        Insn::Shl { dst, src, .. } | Insn::Shr { dst, src, .. } => InsnInfo {
            reads: {
                let mut r = operand_reads(src);
                r.extend(operand_reads(dst));
                r
            },
            writes: operand_writes(dst),
            reads_mem: matches!(src, Operand::Mem(_)) || matches!(dst, Operand::Mem(_)),
            writes_mem: operand_writes_mem(dst),
            writes_flags: FlagWrite::SHIFT,
            ..base
        },
        Insn::Imul2 { dst, src, .. } => InsnInfo {
            reads: {
                let mut r = operand_reads(src);
                r.extend(operand_reads(dst));
                r
            },
            writes: operand_writes(dst),
            reads_mem: matches!(src, Operand::Mem(_)) || matches!(dst, Operand::Mem(_)),
            writes_mem: operand_writes_mem(dst),
            writes_flags: FlagWrite::MULDIV,
            ..base
        },
        Insn::Neg { dst, .. } => InsnInfo {
            reads: operand_reads(dst),
            writes: operand_writes(dst),
            writes_mem: operand_writes_mem(dst),
            writes_flags: FlagWrite::ARITH,
            ..base
        },
        Insn::Not { dst, .. } => InsnInfo {
            reads: operand_reads(dst),
            writes: operand_writes(dst),
            writes_mem: operand_writes_mem(dst),
            ..base // not: flags unchanged
        },
        Insn::Inc { dst, .. } | Insn::Dec { dst, .. } => InsnInfo {
            reads: operand_reads(dst),
            writes: operand_writes(dst),
            writes_mem: operand_writes_mem(dst),
            writes_flags: FlagWrite::INCDEC,
            ..base
        },
        Insn::Cmp { a, b, .. } => InsnInfo {
            reads: {
                let mut r = operand_reads(a);
                r.extend(operand_reads(b));
                r
            },
            reads_mem: matches!(a, Operand::Mem(_)) || matches!(b, Operand::Mem(_)),
            writes_flags: FlagWrite::ARITH,
            ..base
        },
        Insn::MulWide { src, size, .. } => {
            let (hi, lo) = wide_pair(*size);
            let mut reads = operand_reads(src);
            reads.push(lo); // implicit: rax multiplicand
            InsnInfo {
                reads,
                writes: vec![hi, lo],
                reads_mem: matches!(src, Operand::Mem(_)),
                writes_flags: FlagWrite::MULDIV,
                ..base
            }
        }
        Insn::DivWide { src, size, .. } => {
            let (hi, lo) = wide_pair(*size);
            let mut reads = operand_reads(src);
            reads.push(hi);
            reads.push(lo);
            InsnInfo {
                reads,
                writes: vec![hi, lo],
                reads_mem: matches!(src, Operand::Mem(_)),
                writes_flags: FlagWrite::MULDIV,
                ..base
            }
        }
        Insn::ExtendPair { signed, size } => {
            let (hi, lo) = wide_pair(*size);
            InsnInfo {
                reads: vec![lo],
                writes: vec![hi],
                // cqo doesn't touch flags; xor edx,edx does (LOGIC)
                writes_flags: if *signed { FlagWrite::NONE } else { FlagWrite::LOGIC },
                ..base
            }
        }
        Insn::Jmp { .. } => InsnInfo { is_terminator: true, ..base },
        Insn::Jcc { cc, .. } => InsnInfo { reads_flags: jcc_reads(*cc), ..base },
        Insn::Call { contract, .. } => {
            // implicit: rsp written (return address), rip jumps; the contract
            // lists everything else the analysis must assume destroyed.
            InsnInfo {
                reads: vec![r64(GprBase::Sp)],
                writes: {
                    let mut w = vec![r64(GprBase::Sp)];
                    w.extend(contract.clobbers.iter().copied());
                    w.extend(contract.results.iter().copied());
                    w
                },
                reads_mem: true,
                writes_mem: true,
                stack_delta: 0, // call+ret balance
                is_call: true,
                is_terminator: contract.noreturn,
                is_noreturn: contract.noreturn,
                ..base
            }
        }
        Insn::Syscall => {
            // Linux x86-64: reads rax (number) + up to 6 arg regs; writes rax
            // (result); destroys rcx and r11 unconditionally; flags undefined.
            let mut reads: Vec<Reg> = vec![r64(GprBase::A)];
            reads.extend_from_slice(&SYSCALL_ABI);
            InsnInfo {
                reads,
                writes: vec![
                    r64(GprBase::A),
                    r64(GprBase::C),
                    r64(GprBase::R11),
                ],
                reads_mem: true,
                writes_mem: true, // syscalls may write through pointer args
                writes_flags: FlagWrite::ARITH,
                ..base
            }
        }
        Insn::Ret => InsnInfo {
            reads: vec![r64(GprBase::Sp)],
            writes_mem: false,
            reads_mem: true,
            stack_delta: 8,
            is_terminator: true,
            ..base
        },
        Insn::Int3 => InsnInfo { is_terminator: true, is_noreturn: true, ..base },
        Insn::Nop => base.clone(),
        // §12: locked RMW. Register-wise it writes nothing (the memory cell
        // is the destination); xchg-with-memory is implicitly locked and
        // leaves flags untouched, the rest carry their non-atomic flag sets.
        Insn::AtomicRMW { op, dst, src, .. } => {
            let mut reads = operand_reads(src);
            reads.extend(operand_reads(dst));
            InsnInfo {
                reads,
                reads_mem: true,
                writes_mem: true,
                writes_flags: match op {
                    AtomicOp::Exchange => FlagWrite::NONE,
                    AtomicOp::Add | AtomicOp::Sub => FlagWrite::ARITH,
                    AtomicOp::And | AtomicOp::Or | AtomicOp::Xor => FlagWrite::LOGIC,
                },
                is_volatile: true,
                ..base
            }
        }
        // §12 volatile wrapper: same facts as the inner instruction, but the
        // analysis may never elide it.
        Insn::Volatile(inner) => InsnInfo { is_volatile: true, ..insn_info(inner) },
    }
}

/// Is `reg` callee-saved under the SysV AMD64 ABI? (spec §15 ✅ 29.10:
/// rbx, rbp, r12–r15 default to NOT clobbered).
pub fn is_callee_saved(r: Reg) -> bool {
    matches!(
        r,
        Reg::Gpr { base: GprBase::B | GprBase::Bp | GprBase::R12 | GprBase::R13 | GprBase::R14 | GprBase::R15, .. }
    )
}

/// The full SysV callee-saved set (used by the clobber derivation).
pub fn callee_saved_set() -> Vec<Reg> {
    vec![
        r64(GprBase::B),
        r64(GprBase::Bp),
        r64(GprBase::R12),
        r64(GprBase::R13),
        r64(GprBase::R14),
        r64(GprBase::R15),
    ]
}

/// Derive the clobber list for a function body without an explicit block
/// (§5.4 ✅ 29.10): every register the body writes (transitively through
/// calls) minus nothing — results are added by the caller. Callee-saved
/// registers ARE included if actually written: declaring clobbers documents
/// observable destruction regardless of ABI conventions.
pub fn derive_clobbers(body_insns: impl Iterator<Item = Insn>, fn_results: &[Reg]) -> Vec<Reg> {
    let mut clobbers: Vec<Reg> = Vec::new();
    for ins in body_insns {
        let info = insn_info(&ins);
        for w in info.writes {
            // rsp/rip are ABI structure, not clobbers
            if w == r64(GprBase::Sp) {
                continue;
            }
            // normalize to the 64-bit family member for the contract list
            let w64 = w.resize(yana_ast::reg::RegSize::R64).unwrap_or(w);
            if !clobbers.contains(&w64) && !fn_results.contains(&w64) {
                clobbers.push(w64);
            }
        }
    }
    clobbers
}

/// The contract for a `#[syscall(N)]` extern: clobbers rcx/r11 (+rax result),
/// per §5.5.
pub fn syscall_contract(noreturn: bool) -> CallContract {
    CallContract {
        clobbers: vec![r64(GprBase::C), r64(GprBase::R11)],
        results: if noreturn { vec![] } else { vec![r64(GprBase::A)] },
        noreturn,
        syscall: None, // filled by the resolver with the actual number
    }
}

/// x86-64 condition codes.

/// Comparison + signedness → condition code (for the *taken* branch).
pub fn cmp_cc(op: yana_ast::CmpOp, signed: bool) -> crate::ir::Jcc {
    use crate::ir::Jcc;
    use yana_ast::CmpOp;
    match (op, signed) {
        (CmpOp::Eq, _) => Jcc::E,
        (CmpOp::Ne, _) => Jcc::Ne,
        (CmpOp::Lt, true) => Jcc::L,
        (CmpOp::Lt, false) => Jcc::B,
        (CmpOp::Le, true) => Jcc::Le,
        (CmpOp::Le, false) => Jcc::Be,
        (CmpOp::Gt, true) => Jcc::G,
        (CmpOp::Gt, false) => Jcc::A,
        (CmpOp::Ge, true) => Jcc::Ge,
        (CmpOp::Ge, false) => Jcc::Ae,
    }
}

/// Flag name + negation → condition code (spec §4.4: flags, no cmp).
pub fn flag_cc(flag: yana_ast::Flag, negated: bool) -> crate::ir::Jcc {
    use crate::ir::Jcc;
    use yana_ast::Flag;
    match (flag, negated) {
        (Flag::Zero, false) => Jcc::E,
        (Flag::Zero, true) => Jcc::Ne,
        (Flag::Carry, false) => Jcc::B,
        (Flag::Carry, true) => Jcc::Ae,
        (Flag::Negative, false) => Jcc::S,
        (Flag::Negative, true) => Jcc::Ns,
        (Flag::Overflow, false) => Jcc::O,
        (Flag::Overflow, true) => Jcc::No,
        (Flag::Even, false) => Jcc::P,
        (Flag::Even, true) => Jcc::Np,
    }
}

/// Jcc → x86 mnemonic (used by the NASM backend and diagnostics).
pub fn jcc_mnemonic(cc: crate::ir::Jcc) -> &'static str {
    use crate::ir::Jcc;
    match cc {
        Jcc::E => "je",
        Jcc::Ne => "jne",
        Jcc::L => "jl",
        Jcc::Le => "jle",
        Jcc::G => "jg",
        Jcc::Ge => "jge",
        Jcc::B => "jb",
        Jcc::Be => "jbe",
        Jcc::A => "ja",
        Jcc::Ae => "jae",
        Jcc::S => "js",
        Jcc::Ns => "jns",
        Jcc::O => "jo",
        Jcc::No => "jno",
        Jcc::P => "jp",
        Jcc::Np => "jnp",
    }
}

/// Jcc → AArch64 condition suffix (`b.eq`, `b.lt`, …) for the aarch64 backend.
pub fn jcc_aarch64(cc: Jcc) -> &'static str {
    match cc {
        Jcc::E => "eq",
        Jcc::Ne => "ne",
        Jcc::L => "lt",
        Jcc::Le => "le",
        Jcc::G => "gt",
        Jcc::Ge => "ge",
        Jcc::B => "lo",
        Jcc::Be => "ls",
        Jcc::A => "hi",
        Jcc::Ae => "hs",
        Jcc::S => "mi",
        Jcc::Ns => "pl",
        Jcc::O => "vs",
        Jcc::No => "vc",
        Jcc::P => "mi", // parity has no direct AArch64 cond — backend handles via tbz/tbnz
        Jcc::Np => "pl",
    }
}

/// The [`WideOp`] signedness selector used by wide mul/div lowering.
pub fn wide_signed(op: WideOp) -> bool {
    matches!(op, WideOp::Signed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{Displacement, MemOp};

    #[test]
    fn syscall_abi_regs() {
        let i = insn_info(&Insn::Syscall);
        assert!(i.writes.contains(&r64(GprBase::A)));
        assert!(i.writes.contains(&r64(GprBase::C)));
        assert!(i.writes.contains(&r64(GprBase::R11)));
        assert!(i.reads.contains(&r64(GprBase::Di)));
    }

    #[test]
    fn mulwide_implicit_pair() {
        let i = insn_info(&Insn::MulWide { src: Operand::Reg(r64(GprBase::B)), signed: false, size: 64 });
        assert!(i.reads.contains(&r64(GprBase::A)), "rax read implicitly");
        assert!(i.writes.contains(&r64(GprBase::D)) && i.writes.contains(&r64(GprBase::A)));
    }

    #[test]
    fn call_contract_writes() {
        let i = insn_info(&Insn::Call {
            sym: 0,
            contract: CallContract {
                clobbers: vec![r64(GprBase::C)],
                results: vec![r64(GprBase::A)],
                noreturn: false,
                syscall: None,
            },
        });
        assert!(i.is_call && !i.is_terminator);
        assert!(i.writes.contains(&r64(GprBase::C)));
        let nr = insn_info(&Insn::Call {
            sym: 0,
            contract: CallContract { clobbers: vec![], results: vec![], noreturn: true, syscall: None },
        });
        assert!(nr.is_terminator && nr.is_noreturn);
    }

    #[test]
    fn stack_deltas() {
        assert_eq!(insn_info(&Insn::Push { src: Operand::Reg(r64(GprBase::B)), size: 64 }).stack_delta, -8);
        assert_eq!(insn_info(&Insn::Pop { dst: Operand::Reg(r64(GprBase::B)), size: 64 }).stack_delta, 8);
        assert_eq!(insn_info(&Insn::StackSlot { grow: true }).stack_delta, -8);
        assert_eq!(insn_info(&Insn::StackSlot { grow: false }).stack_delta, 8);
        assert_eq!(insn_info(&Insn::Ret).stack_delta, 8);
    }

    #[test]
    fn mem_address_regs_are_reads() {
        let m = MemOp {
            base: Some(r64(GprBase::B)),
            index: Some(r64(GprBase::C)),
            scale: 8,
            disp: Displacement::Const(16),
            size: 64,
            rip_relative: false,
        };
        let i = insn_info(&Insn::Mov { dst: Operand::Reg(r64(GprBase::A)), src: Operand::Mem(m), size: 64 });
        assert!(i.reads.contains(&r64(GprBase::B)));
        assert!(i.reads.contains(&r64(GprBase::C)));
        assert!(i.reads_mem && !i.writes_mem);
    }

    #[test]
    fn cqo_vs_xor_flags() {
        let signed = insn_info(&Insn::ExtendPair { signed: true, size: 64 });
        assert!(!signed.writes_flags.any(), "cqo does not touch flags");
        let unsigned = insn_info(&Insn::ExtendPair { signed: false, size: 64 });
        assert!(unsigned.writes_flags.any(), "xor edx,edx writes flags");
    }

    #[test]
    fn callee_saved_set_is_sysv() {
        let s = callee_saved_set();
        assert!(s.contains(&r64(GprBase::B)));
        assert!(s.contains(&r64(GprBase::Bp)));
        assert!(s.contains(&r64(GprBase::R12)));
        assert!(!s.contains(&r64(GprBase::A)));
    }

    // ------------------------------------------------------------------
    // §12: atomics / volatile
    // ------------------------------------------------------------------

    fn mem_op(base: GprBase) -> MemOp {
        MemOp {
            base: Some(r64(base)),
            index: None,
            scale: 1,
            disp: Displacement::Const(0),
            size: 64,
            rip_relative: false,
        }
    }

    #[test]
    fn atomic_exchange_touches_no_flags() {
        let i = insn_info(&Insn::AtomicRMW {
            op: crate::ir::AtomicOp::Exchange,
            dst: Operand::Mem(mem_op(GprBase::A)),
            src: Operand::Reg(r64(GprBase::B)),
            size: 64,
            order: crate::ir::MemOrder::SeqCst,
        });
        assert!(!i.writes_flags.any(), "xchg does not touch flags");
        assert!(i.is_volatile, "atomics are volatile to the analysis");
        assert!(i.reads_mem && i.writes_mem, "locked RMW touches memory");
        assert!(i.reads.contains(&r64(GprBase::A)), "address reg read");
        assert!(i.reads.contains(&r64(GprBase::B)), "source reg read");
        assert!(!i.writes.contains(&r64(GprBase::B)), "no register destination");
        assert_eq!(i.stack_delta, 0);
        assert!(!i.is_terminator && !i.is_call);
    }

    #[test]
    fn atomic_add_writes_arith_flags() {
        let i = insn_info(&Insn::AtomicRMW {
            op: crate::ir::AtomicOp::Add,
            dst: Operand::Mem(mem_op(GprBase::A)),
            src: Operand::Imm(1),
            size: 64,
            order: crate::ir::MemOrder::Relaxed,
        });
        assert!(i.writes_flags.any(), "lock add writes flags like add");
        assert!(i.writes_flags.zf && i.writes_flags.cf, "full ARITH group");
        assert!(i.is_volatile);
        // same flag set as the plain Add
        let plain = insn_info(&Insn::Add {
            dst: Operand::Mem(mem_op(GprBase::A)),
            src: Operand::Imm(1),
            size: 64,
        });
        assert_eq!(i.writes_flags, plain.writes_flags);
    }

    #[test]
    fn volatile_delegates_to_inner() {
        let inner = Insn::Mov { dst: Operand::Reg(r64(GprBase::A)), src: Operand::Imm(7), size: 64 };
        let plain = insn_info(&inner);
        let vol = insn_info(&Insn::Volatile(Box::new(inner.clone())));
        assert!(!plain.is_volatile);
        assert!(vol.is_volatile, "Volatile wrapper marks the access");
        assert_eq!(vol.reads, plain.reads);
        assert_eq!(vol.writes, plain.writes);
        assert_eq!(vol.reads_mem, plain.reads_mem);
        assert_eq!(vol.writes_mem, plain.writes_mem);
        assert_eq!(vol.writes_flags, plain.writes_flags);
        assert_eq!(vol.stack_delta, plain.stack_delta);
    }
}
