//! x86-64 register model.
//!
//! A [`Reg`] is a concrete named register (`rax`, `eax`, `dl`, `xmm0`, ...).
//! The base GPR family ([`GprBase`]) plus a [`RegSize`] determines which concrete
//! name you get, which is exactly what the spec's `as` casting rule (§4.2) needs:
//! `d as u8` where `d @ rdx` yields `dl`.

/// General-purpose register base families (the 16 architectural GPRs).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GprBase {
    A, B, C, D,
    Si, Di, Bp, Sp,
    R8, R9, R10, R11, R12, R13, R14, R15,
}

impl GprBase {
    /// The 3 low registers have special 8-bit high halves (ah/bh/ch/dh).
    #[inline]
    pub fn has_high8(self) -> bool {
        matches!(self, GprBase::A | GprBase::B | GprBase::C | GprBase::D)
    }

    /// Numeric id used in ModRM/SIB encoding (rax=0 ... r15=15).
    #[inline]
    pub fn enc_id(self) -> u8 {
        use GprBase::*;
        match self {
            A => 0, C => 1, D => 2, B => 3,
            Sp => 4, Bp => 5, Si => 6, Di => 7,
            R8 => 8, R9 => 9, R10 => 10, R11 => 11,
            R12 => 12, R13 => 13, R14 => 14, R15 => 15,
        }
    }
}

/// Operand width.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RegSize {
    R8,
    R16,
    R32,
    R64,
}

impl RegSize {
    #[inline]
    pub fn bits(self) -> u32 {
        match self {
            RegSize::R8 => 8,
            RegSize::R16 => 16,
            RegSize::R32 => 32,
            RegSize::R64 => 64,
        }
    }

    #[inline]
    pub fn bytes(self) -> u32 {
        self.bits() / 8
    }
}

/// A concrete x86-64 register.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Reg {
    /// A GPR at some width: `(rax, R64)`, `(eax, R32)`, `(dl, R8)`.
    Gpr { base: GprBase, size: RegSize },
    /// The legacy high-byte registers ah/bh/ch/dh (8-bit only, encode ids 4..7).
    GprHigh8(GprBase),
    /// Instruction pointer (rip), only valid as a memory base.
    Rip,
    /// x87/SSE control-ish registers we may need later.
    Xmm(u8),
}

impl Reg {
    /// Size of this register in bits (rip counts as 64).
    pub fn size(self) -> RegSize {
        match self {
            Reg::Gpr { size, .. } => size,
            Reg::GprHigh8(_) => RegSize::R8,
            Reg::Rip => RegSize::R64,
            Reg::Xmm(_) => RegSize::R64, // not precise, but unused for GPR paths
        }
    }

    /// Reinterpret the same GPR family at a different width (`rdx -> dl`).
    ///
    /// Returns `None` for non-GPR registers or when R8 is requested on a base
    /// without a low-byte form (all GPRs have one, so only non-GPR fails).
    pub fn resize(self, size: RegSize) -> Option<Reg> {
        match self {
            Reg::Gpr { base, .. } => Some(Reg::Gpr { base, size }),
            Reg::GprHigh8(base) => Some(Reg::Gpr { base, size }),
            _ => None,
        }
    }

    /// Canonical lowercase name (`rax`, `eax`, `dl`, `r8b`, `rip`).
    pub fn name(self) -> &'static str {
        match self {
            Reg::Rip => "rip",
            Reg::GprHigh8(b) => high8_name(b),
            Reg::Xmm(n) => XMM_NAMES[n as usize],
            Reg::Gpr { base, size } => gpr_name(base, size),
        }
    }

    /// Parse a register name. Accepts the full x86-64 GPR set plus `rip`.
    pub fn parse(s: &str) -> Option<Reg> {
        if s.eq_ignore_ascii_case("rip") {
            return Some(Reg::Rip);
        }
        if let Some(r) = parse_gpr(s) {
            return Some(r);
        }
        if let Some(i) = XMM_NAMES.iter().position(|n| n.eq_ignore_ascii_case(s)) {
            return Some(Reg::Xmm(i as u8));
        }
        None
    }
}

const fn high8_name(b: GprBase) -> &'static str {
    match b {
        GprBase::A => "ah",
        GprBase::B => "bh",
        GprBase::C => "ch",
        GprBase::D => "dh",
        _ => "",
    }
}

fn gpr_name(base: GprBase, size: RegSize) -> &'static str {
    use GprBase::*;
    let idx = match base {
        A => 0, C => 1, D => 2, B => 3, Sp => 4, Bp => 5, Si => 6, Di => 7,
        R8 => 8, R9 => 9, R10 => 10, R11 => 11, R12 => 12, R13 => 13, R14 => 14, R15 => 15,
    };
    match size {
        RegSize::R64 => R64_NAMES[idx],
        RegSize::R32 => R32_NAMES[idx],
        RegSize::R16 => R16_NAMES[idx],
        RegSize::R8 => R8_NAMES[idx],
    }
}

const R64_NAMES: [&str; 16] = [
    "rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi",
    "r8","r9","r10","r11","r12","r13","r14","r15",
];
const R32_NAMES: [&str; 16] = [
    "eax","ecx","edx","ebx","esp","ebp","esi","edi",
    "r8d","r9d","r10d","r11d","r12d","r13d","r14d","r15d",
];
const R16_NAMES: [&str; 16] = [
    "ax","cx","dx","bx","sp","bp","si","di",
    "r8w","r9w","r10w","r11w","r12w","r13w","r14w","r15w",
];
const R8_NAMES: [&str; 16] = [
    "al","cl","dl","bl","spl","bpl","sil","dil",
    "r8b","r9b","r10b","r11b","r12b","r13b","r14b","r15b",
];
const XMM_NAMES: [&str; 16] = [
    "xmm0","xmm1","xmm2","xmm3","xmm4","xmm5","xmm6","xmm7",
    "xmm8","xmm9","xmm10","xmm11","xmm12","xmm13","xmm14","xmm15",
];

fn parse_gpr(s: &str) -> Option<Reg> {
    let s = s.to_ascii_lowercase();
    for (idx, n) in R64_NAMES.iter().enumerate() {
        if s == *n {
            return Some(Reg::Gpr { base: idx_to_base(idx), size: RegSize::R64 });
        }
    }
    for (idx, n) in R32_NAMES.iter().enumerate() {
        if s == *n {
            return Some(Reg::Gpr { base: idx_to_base(idx), size: RegSize::R32 });
        }
    }
    for (idx, n) in R16_NAMES.iter().enumerate() {
        if s == *n {
            return Some(Reg::Gpr { base: idx_to_base(idx), size: RegSize::R16 });
        }
    }
    for (idx, n) in R8_NAMES.iter().enumerate() {
        if s == *n {
            return Some(Reg::Gpr { base: idx_to_base(idx), size: RegSize::R8 });
        }
    }
    // high-byte forms
    for b in [GprBase::A, GprBase::B, GprBase::C, GprBase::D] {
        if s == high8_name(b) {
            return Some(Reg::GprHigh8(b));
        }
    }
    None
}

const fn idx_to_base(idx: usize) -> GprBase {
    match idx {
        0 => GprBase::A,
        1 => GprBase::C,
        2 => GprBase::D,
        3 => GprBase::B,
        4 => GprBase::Sp,
        5 => GprBase::Bp,
        6 => GprBase::Si,
        7 => GprBase::Di,
        8 => GprBase::R8,
        9 => GprBase::R9,
        10 => GprBase::R10,
        11 => GprBase::R11,
        12 => GprBase::R12,
        13 => GprBase::R13,
        14 => GprBase::R14,
        _ => GprBase::R15,
    }
}
