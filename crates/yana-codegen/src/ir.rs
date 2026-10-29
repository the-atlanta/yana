//! The YANA IR: a flat, symbolic instruction stream per module.
//!
//! The IR is deliberately *close to the wire*: every [`Insn`] maps 1:1 to one
//! machine instruction (spec §0 principle: constructions expand into a visible,
//! known instruction set). Symbolic operands ([`Operand::Sym`]) and label
//! references ([`Operand::Label`]) are resolved by the backend with
//! backpatching; the IR itself never contains byte offsets.

use yana_ast::place::SectionKind;
use yana_ast::reg::Reg;
use yana_ast::Span;

/// A resolved module: symbols + per-function instruction streams + section data.
#[derive(Debug, Default)]
pub struct Module {
    /// All symbols in declaration order.
    pub symbols: Vec<Symbol>,
    /// Static data per section (`.rodata`, `.data`, `.bss`).
    pub sections: Vec<SectionData>,
    /// Function bodies, one per [`SymbolKind::Function`].
    pub bodies: Vec<FnBody>,
    /// The `#[entry]` symbol index, if any.
    pub entry: Option<usize>,
}

impl Module {
    /// Look up a symbol by name.
    pub fn find(&self, name: &str) -> Option<usize> {
        self.symbols.iter().position(|s| s.name == name)
    }

    pub fn section_mut(&mut self, kind: SectionKind) -> &mut SectionData {
        if let Some(i) = self.sections.iter().position(|s| s.kind == kind) {
            return &mut self.sections[i];
        }
        self.sections.push(SectionData { kind, items: Vec::new() });
        self.sections.last_mut().unwrap()
    }
}

#[derive(Debug, Clone)]
pub struct Symbol {
    pub name: String,
    pub kind: SymbolKind,
    /// Exported (`pub` / `#[global]`).
    pub exported: bool,
    /// `#[syscall(N)]` externs carry their number.
    pub syscall: Option<i64>,
    /// Declared clobbers for externs (spec §5.4); functions without a block get
    /// derived clobbers (empty for MVP — analysis layer comes later).
    pub clobbers: Vec<Reg>,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq)]
pub enum SymbolKind {
    /// Has a body in [`Module::bodies`] (index stored alongside).
    Function { body_index: usize },
    /// `extern fn` — no body; calls resolve to an undefined ELF symbol,
    /// or to `mov rax,N; syscall` when `syscall` is set.
    ExternFn,
    /// Static data: `section` + `offset` within it + `size`.
    Static { section: SectionKind, offset: u64, size: u64 },
    /// Build-time constant — no runtime presence, usable as an immediate.
    Const { value: i128 },
}

#[derive(Debug, Clone)]
pub struct SectionData {
    pub kind: SectionKind,
    pub items: Vec<DataItem>,
}

#[derive(Debug, Clone)]
pub enum DataItem {
    Bytes { offset: u64, bytes: Vec<u8>, align: u64, sym: Option<usize> },
    /// `.bss` reservation (no bytes).
    Zero { offset: u64, size: u64, align: u64, sym: Option<usize> },
}

/// One function's instruction stream.
#[derive(Debug, Default)]
pub struct FnBody {
    pub symbol: usize,
    pub insns: Vec<Insn>,
    pub label_defs: Vec<LabelDef>,
}

#[derive(Debug, Clone)]
pub struct LabelDef {
    /// Label name as written (`'loop` → "loop").
    pub name: String,
    /// Index into [`FnBody::insns`] of the instruction that follows the label.
    pub at_insn: usize,
}

/// An instruction operand.
#[derive(Debug, Clone, PartialEq)]
pub enum Operand {
    Reg(Reg),
    /// Immediate value; width is implied by the destination/source type.
    Imm(i64),
    /// A memory location.
    Mem(MemOp),
    /// Address of a symbol — resolved by the backend to a relocation.
    Sym { sym: usize, add: i64 },
}

/// A resolved memory operand `[base + index*scale + disp]`.
#[derive(Debug, Clone, PartialEq)]
pub struct MemOp {
    pub base: Option<Reg>,
    pub index: Option<Reg>,
    pub scale: u8,
    pub disp: Displacement,
    /// Operand width in bits (8/16/32/64) — from the type annotation.
    pub size: u32,
    /// Force rip-relative encoding (symbol displacements default to rip).
    pub rip_relative: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Displacement {
    Const(i64),
    /// `symbol + add` — becomes a relocation at encode time.
    Sym { sym: usize, add: i64 },
}

/// Relocation hint for the backend (recorded when lowering a symbolic operand).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelocHint {
    /// `R_X86_64_PC32`, addend −4 (rip-relative field).
    Pc32,
    /// `R_X86_64_PLT32` for `call sym`.
    Plt32,
    /// `R_X86_64_32S` for a 32-bit absolute immediate.
    Abs32,
}

/// Conditional jump kinds (x86 mnemonics map 1:1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Jcc {
    E,
    Ne,
    L,
    Le,
    G,
    Ge,
    B,
    Be,
    A,
    Ae,
    S,
    Ns,
    O,
    No,
    P,
    Np,
}

/// Wide (implicit-operand) mul/div forms (§4.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WideOp {
    /// unsigned: `mul` / `div`
    Unsigned,
    /// signed: `imul` / `idiv`
    Signed,
}

/// One machine instruction. Every variant maps to exactly one x86-64 insn
/// (spec §0: visible expansion).
#[derive(Debug, Clone)]
pub enum Insn {
    // ---- data movement ----
    Mov { dst: Operand, src: Operand, size: u32 },
    /// movzx dst, src (src narrower).
    Movzx { dst: Reg, src: Operand, src_size: u32, dst_size: u32 },
    /// movsx dst, src (src narrower).
    Movsx { dst: Reg, src: Operand, src_size: u32, dst_size: u32 },
    Lea { dst: Reg, addr: MemOp },
    /// Load address of a symbol into a register: `lea dst, [rel sym+add]`.
    LeaSym { dst: Reg, sym: usize, add: i64 },
    Push { src: Operand, size: u32 },
    /// `_` slot in push/pop: `lea rsp, [rsp-8]` (flags untouched, §4.3).
    StackSlot { grow: bool },
    Pop { dst: Operand, size: u32 },
    Xchg { a: Operand, b: Operand, size: u32 },

    // ---- arithmetic / logic ----
    Add { dst: Operand, src: Operand, size: u32 },
    Sub { dst: Operand, src: Operand, size: u32 },
    And { dst: Operand, src: Operand, size: u32 },
    Or { dst: Operand, src: Operand, size: u32 },
    Xor { dst: Operand, src: Operand, size: u32 },
    Shl { dst: Operand, src: Operand, size: u32 },
    Shr { dst: Operand, src: Operand, size: u32 },
    /// two-operand imul (dst *= src)
    Imul2 { dst: Operand, src: Operand, size: u32 },
    Neg { dst: Operand, size: u32 },
    Not { dst: Operand, size: u32 },
    Inc { dst: Operand, size: u32 },
    Dec { dst: Operand, size: u32 },

    // ---- compare / test ----
    Cmp { a: Operand, b: Operand, size: u32 },

    // ---- wide mul/div (§4.5) — pair implied by size ----
    /// `rdx:rax = rax * src` (mul/imul single-operand).
    MulWide { src: Operand, signed: bool, size: u32 },
    /// `(quot, rem) = pair / src` — pair implied (rdx:rax).
    DivWide { src: Operand, op: WideOp, size: u32 },
    /// sign/zero-extend rax → rdx:rax before a wide op (`cqo`/`xor edx,edx`).
    ExtendPair { signed: bool, size: u32 },

    // ---- control flow ----
    Jmp { label: usize },
    Jcc { cc: Jcc, label: usize },
    /// `call` to a symbol; the syscall lowering happens in the backend.
    Call { sym: usize },
    /// Raw `syscall;` instruction (§5.5).
    Syscall,
    Ret,
    /// x86 `int3` — emitted for `-> !` fallthrough guards (later) and tests.
    Int3,
    Nop,
}

/// Hint attached to an instruction for diagnostics (source span).
#[derive(Debug, Clone)]
pub struct Spanned<T> {
    pub node: T,
    pub span: Span,
}
