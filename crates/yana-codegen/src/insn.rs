//! The instruction table (§14: "один источник правды для кодировщика и
//! анализов"): per-opcode flags — what the instruction reads, writes, and does
//! to EFLAGS. Backends consult it; future analyses (liveness, flag tracking,
//! clobber derivation) consult the same table.

use crate::ir::Insn;

/// Static properties of one instruction instance.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct InsnInfo {
    /// Writes EFLAGS (cmp, add, sub, ...).
    pub writes_flags: bool,
    /// Reads EFLAGS (jcc, and friends).
    pub reads_flags: bool,
    /// Is a control-flow transfer that doesn't fall through (jmp, ret, syscall-exit).
    pub is_terminator: bool,
    /// Is a call (affects clobber reasoning).
    pub is_call: bool,
    /// Number of explicit operands the instruction has (for encoders).
    pub operands: u8,
}

/// Classify an instruction.
///
/// Kept deliberately simple for the MVP slice; the analysis layer will extend
/// it with per-operand read/write sets.
pub fn insn_info(i: &Insn) -> InsnInfo {
    match i {
        Insn::Mov { .. } | Insn::Movzx { .. } | Insn::Movsx { .. } | Insn::Lea { .. } | Insn::LeaSym { .. } => {
            InsnInfo { writes_flags: false, reads_flags: false, is_terminator: false, is_call: false, operands: 2 }
        }
        Insn::Push { .. } | Insn::Pop { .. } | Insn::StackSlot { .. } => {
            InsnInfo { writes_flags: false, reads_flags: false, is_terminator: false, is_call: false, operands: 1 }
        }
        Insn::Xchg { .. } => {
            InsnInfo { writes_flags: false, reads_flags: false, is_terminator: false, is_call: false, operands: 2 }
        }
        Insn::Add { .. } | Insn::Sub { .. } | Insn::And { .. } | Insn::Or { .. } | Insn::Xor { .. }
        | Insn::Shl { .. } | Insn::Shr { .. } | Insn::Imul2 { .. } | Insn::Neg { .. }
        | Insn::Not { .. } | Insn::Inc { .. } | Insn::Dec { .. } | Insn::Cmp { .. }
        | Insn::MulWide { .. } | Insn::DivWide { .. } => {
            InsnInfo { writes_flags: true, reads_flags: false, is_terminator: false, is_call: false, operands: 2 }
        }
        Insn::ExtendPair { .. } => {
            // cqo writes rdx but no flags; xor edx,edx writes flags — the
            // resolver records which form; conservatively: writes flags.
            InsnInfo { writes_flags: true, reads_flags: false, is_terminator: false, is_call: false, operands: 0 }
        }
        Insn::Jcc { .. } => {
            InsnInfo { writes_flags: false, reads_flags: true, is_terminator: false, is_call: false, operands: 1 }
        }
        Insn::Jmp { .. } => {
            InsnInfo { writes_flags: false, reads_flags: false, is_terminator: true, is_call: false, operands: 1 }
        }
        Insn::Call { .. } => {
            InsnInfo { writes_flags: false, reads_flags: false, is_terminator: false, is_call: true, operands: 1 }
        }
        Insn::Syscall => {
            InsnInfo { writes_flags: true, reads_flags: false, is_terminator: false, is_call: false, operands: 0 }
        }
        Insn::Ret => {
            InsnInfo { writes_flags: false, reads_flags: false, is_terminator: true, is_call: false, operands: 0 }
        }
        Insn::Int3 | Insn::Nop => {
            InsnInfo { writes_flags: false, reads_flags: false, is_terminator: false, is_call: false, operands: 0 }
        }
    }
}

/// x86-64 condition codes → Jcc mapping tables used by both backends and the
/// branch lowering. Signedness matters (spec §4.4: знаковость из типа).

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
