//! Places (§3 of the spec): a register, a memory address, or a data section.
//!
//! A binding is `имя @ место: тип`; the `место` is one of these three.

use crate::reg::Reg;
use crate::ty::Ty;
use crate::Span;

/// Abstract data section (§7). The backend maps these onto ELF/Mach-O.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SectionKind {
    Text,
    RoData,
    Data,
    Bss,
}

impl SectionKind {
    /// Canonical section name used by both backends before mapping.
    pub fn name(self) -> &'static str {
        match self {
            SectionKind::Text => ".text",
            SectionKind::RoData => ".rodata",
            SectionKind::Data => ".data",
            SectionKind::Bss => ".bss",
        }
    }

    pub fn parse(s: &str) -> Option<SectionKind> {
        match s {
            ".text" => Some(SectionKind::Text),
            ".rodata" => Some(SectionKind::RoData),
            ".data" => Some(SectionKind::Data),
            ".bss" => Some(SectionKind::Bss),
            _ => None,
        }
    }

    /// Is this section writable at runtime? (`.data`/`.bss` yes, `.rodata`/`.text` no)
    pub fn writable(self) -> bool {
        matches!(self, SectionKind::Data | SectionKind::Bss)
    }
}

/// One additive term of a memory address: `[rax + rcx*8 + sym + 16]`.
///
/// The parser keeps terms in source order; the semantic pass assigns
/// base/index/scale/disp roles (at most one unscaled register → base, at most
/// one scaled register → index, at most one name, ints fold into disp).
#[derive(Debug, Clone, PartialEq)]
pub enum MemTerm {
    /// An unscaled register operand (base or index candidate).
    Reg(Reg),
    /// A register times a scale (2/4/8) — always the index.
    RegScaled { reg: Reg, scale: u8 },
    /// A bare name: a symbol or a binding name — the semantic pass decides.
    Name(String),
    /// A name times a scale — resolves to an index register at semantic time.
    NameScaled { name: String, scale: u8 },
    /// A constant displacement contribution (signed).
    Const(i64),
}

/// A parsed memory address `[terms]` before semantic role assignment.
#[derive(Debug, Clone, PartialEq)]
pub struct RawAddr {
    pub terms: Vec<MemTerm>,
    pub span: Span,
}

/// A place: the target of a binding or an operand (§3).
///
/// The optional `ty` is the inline annotation from the source (`[buf]: u64`,
/// `rax: u64`). For registers it is redundant with the register width; for
/// memory it is the operand size. The semantic pass validates consistency.
#[derive(Debug, Clone, PartialEq)]
pub enum Place {
    /// A named register: `rax`, `dl` (optionally `rax: u64`).
    Reg { reg: Reg, ty: Option<Ty>, span: Span },
    /// The `rdx:rax` 128-bit pair (§4.5). `ty` is `u128`/`i128` if written.
    RegPair { hi: Reg, lo: Reg, ty: Option<Ty>, span: Span },
    /// A memory location: `[rbx + rcx*8 + 16]: u64`.
    Mem { addr: RawAddr, ty: Option<Ty>, span: Span },
    /// A reference to a `bind` name or `const` — resolved by the semantic pass
    /// into its underlying place/value (§4.2: `alt n -= 1;`).
    Named { name: String, ty: Option<Ty>, span: Span },
    /// A data-section binding: `.rodata`, `.bss` (optionally `: [u8; 16]`).
    Section { kind: SectionKind, ty: Option<Ty>, span: Span },
    /// Discard `_`.
    Discard { span: Span },
}

impl Place {
    pub fn span(&self) -> Span {
        match self {
            Place::Reg { span, .. }
            | Place::RegPair { span, .. }
            | Place::Mem { span, .. }
            | Place::Named { span, .. }
            | Place::Section { span, .. }
            | Place::Discard { span } => *span,
        }
    }

    /// The declared type annotation, if the source carried one.
    pub fn ty(&self) -> Option<&Ty> {
        match self {
            Place::Reg { ty, .. }
            | Place::RegPair { ty, .. }
            | Place::Mem { ty, .. }
            | Place::Named { ty, .. }
            | Place::Section { ty, .. } => ty.as_ref(),
            Place::Discard { .. } => None,
        }
    }

    /// Attach a type annotation (from `: T` after the place).
    pub fn with_ty(self, ty: Option<Ty>) -> Place {
        match self {
            Place::Reg { reg, span, .. } => Place::Reg { reg, ty, span },
            Place::RegPair { hi, lo, span, .. } => Place::RegPair { hi, lo, ty, span },
            Place::Mem { addr, span, .. } => Place::Mem { addr, ty, span },
            Place::Named { name, span, .. } => Place::Named { name, ty, span },
            Place::Section { kind, span, .. } => Place::Section { kind, ty, span },
            other => other,
        }
    }

    /// Register width in bits, if this is a register place.
    pub fn reg_bits(&self) -> Option<u32> {
        match self {
            Place::Reg { reg, .. } => Some(reg.size().bits()),
            Place::RegPair { .. } => Some(128),
            _ => None,
        }
    }
}

/// A resolved memory address: `[base + index*scale + disp]`.
///
/// Produced by the semantic pass from [`RawAddr`]; backends consume this.
#[derive(Debug, Clone, PartialEq)]
pub struct MemAddr {
    pub base: Option<Reg>,
    pub index: Option<Reg>,
    pub scale: u8, // 1, 2, 4 or 8
    pub disp: Disp,
    pub span: Span,
}

/// A displacement term in a resolved memory address.
#[derive(Debug, Clone, PartialEq)]
pub enum Disp {
    /// A constant displacement (may be negative).
    Const(i64),
    /// `symbol + const` — resolved to an absolute or rip-relative relocation.
    Symbol { name: String, add: i64, span: Span },
}

impl MemAddr {
    /// Is this a rip-relative address (`[rip + disp]`)?
    pub fn is_rip_relative(&self) -> bool {
        self.base == Some(Reg::Rip) && self.index.is_none()
    }
}
