/// A byte-offset span into the source file. `lo` is inclusive, `hi` exclusive.
///
/// Kept as plain `u32` offsets (not line/col) so the lexer can produce them for
/// free; the diagnostic layer converts to line/col via a [`crate::diag::SourceMap`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Span {
    pub lo: u32,
    pub hi: u32,
}

impl Span {
    pub const DUMMY: Span = Span { lo: 0, hi: 0 };

    #[inline]
    pub fn new(lo: u32, hi: u32) -> Self {
        Span { lo, hi }
    }

    /// Smallest span covering both `self` and `other`.
    #[inline]
    pub fn merge(self, other: Span) -> Span {
        Span {
            lo: self.lo.min(other.lo),
            hi: self.hi.max(other.hi),
        }
    }

    #[inline]
    pub fn is_dummy(self) -> bool {
        self.lo == 0 && self.hi == 0
    }

    #[inline]
    pub fn len(self) -> u32 {
        self.hi.saturating_sub(self.lo)
    }

    #[inline]
    pub fn is_empty(self) -> bool {
        self.len() == 0
    }
}
