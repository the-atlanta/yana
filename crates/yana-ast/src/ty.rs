//! YANA type system (§2 of the spec).
//!
//! Types determine operand width. `usize`/`isize` are target-defined and resolved
//! by the backend to 64 bits on x86-64. `u128`/`i128` exist only as the
//! `rdx:rax` register-pair pseudo-type (§4.5), so they are modelled separately.

use crate::Span;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Ty {
    U8,
    U16,
    U32,
    U64,
    Usize,
    I8,
    I16,
    I32,
    I64,
    Isize,
    /// Pointer to `T`.
    Ptr(Box<Ty>),
    /// Sized array `[T; N]`.
    Array(Box<Ty>, u64),
    /// Slice `[T]` — length known only from the binding, no in-type size.
    Slice(Box<Ty>),
    /// Tuple `(A, B, ...)`.
    Tuple(Vec<Ty>),
    /// The 128-bit register pair `rdx:rax` (§4.5). Only valid for that pair.
    U128,
    I128,
    /// Never type `!` — a function that does not return.
    Never,
}

impl Ty {
    /// Is this an integer type (including the 128-bit pair types)?
    pub fn is_int(&self) -> bool {
        matches!(
            self,
            Ty::U8 | Ty::U16 | Ty::U32 | Ty::U64 | Ty::Usize
                | Ty::I8 | Ty::I16 | Ty::I32 | Ty::I64 | Ty::Isize
                | Ty::U128 | Ty::I128
        )
    }

    /// Is this a signed integer type?
    pub fn is_signed(&self) -> bool {
        matches!(
            self,
            Ty::I8 | Ty::I16 | Ty::I32 | Ty::I64 | Ty::Isize | Ty::I128
        )
    }

    /// Size in bits, resolving `usize`/`isize` against a target pointer width.
    /// Returns `None` for unsized types (slices, tuples of mixed size, never).
    pub fn size_bits(&self, usize_bits: u32) -> Option<u32> {
        match self {
            Ty::U8 | Ty::I8 => Some(8),
            Ty::U16 | Ty::I16 => Some(16),
            Ty::U32 | Ty::I32 => Some(32),
            Ty::U64 | Ty::I64 => Some(64),
            Ty::Usize | Ty::Isize => Some(usize_bits),
            Ty::U128 | Ty::I128 => Some(128),
            Ty::Ptr(_) => Some(usize_bits),
            Ty::Array(inner, n) => inner.size_bits(usize_bits).map(|b| b * *n as u32),
            Ty::Slice(_) => None,
            Ty::Tuple(_) => None,
            Ty::Never => None,
        }
    }

    /// The register width implied by this type (used to pick register forms).
    pub fn reg_size(&self, usize_bits: u32) -> Option<crate::RegSize> {
        use crate::RegSize;
        match self.size_bits(usize_bits)? {
            8 => Some(RegSize::R8),
            16 => Some(RegSize::R16),
            32 => Some(RegSize::R32),
            64 => Some(RegSize::R64),
            _ => None,
        }
    }

    /// A span-annotated type as it appears in source.
    pub fn spanned(self, span: Span) -> Spanned<Ty> {
        Spanned { node: self, span }
    }
}

/// A node with an attached source span. Used where the parser wants to keep
/// provenance without threading spans through every type signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Spanned<T> {
    pub node: T,
    pub span: Span,
}

impl<T> Spanned<T> {
    pub fn map<U>(self, f: impl FnOnce(T) -> U) -> Spanned<U> {
        Spanned { node: f(self.node), span: self.span }
    }
}
