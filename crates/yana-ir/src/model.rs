//! The SSA-IR data model.
//!
//! YANA is an assembly-first language: source registers are observable, and
//! `bind name @ rax` really means "this value lives in rax". The IR therefore
//! keeps **both** kinds of values in one graph:
//!
//! - [`Home::Pinned`] — the language pinned the value to a register
//!   (`bind`, `alt`, `pop`, a `-> rax` result). The register is an invariant,
//!   not a hint: `clobbers`/`preserves`/`alt` talk about it.
//! - [`Home::Fixed`] — the ABI or an instruction pinned it (syscall args in
//!   `rdi`/`rsi`/`rdx`, `mul` on `rdx:rax`, `rsp` for push/pop). Compiler
//!   imposed, still not movable.
//! - [`Home::Virtual`] — an ordinary SSA value with no register yet. These
//!   are the values a future resolver emits for expression temporaries; the
//!   register allocator gives them a home when lowering to machine IR.
//!
//! A register write creates a new version (`%rax.0`, `%rax.1`, …), so the
//! def-use graph covers the whole machine state. At a CFG join a physical
//! register gets a physical `phi`; virtual values get an ordinary `phi`.

use std::collections::HashMap;

use yana_ast::reg::{GprBase, Reg, RegSize};
use yana_ast::ty::Ty;
use yana_ast::Span;
use yana_codegen::ir::{CallContract, Displacement, Insn, Jcc};

pub type ValueId = u32;
pub type BlockId = u32;

/// A whole module in SSA form.
#[derive(Debug, Clone)]
pub struct Module {
    pub source: String,
    pub target: String,
    pub functions: Vec<Function>,
    pub externs: Vec<Extern>,
    /// Index into [`Module::functions`] of the `#[entry]` function.
    pub entry: Option<usize>,
    pub stats: Stats,
}

#[derive(Debug, Clone, Default)]
pub struct Stats {
    pub symbols: usize,
    pub functions: usize,
    pub externs: usize,
    pub blocks: usize,
    pub insts: usize,
    pub values: usize,
    pub phis: usize,
}

/// An `extern fn` declaration (no body).
#[derive(Debug, Clone)]
pub struct Extern {
    pub symbol: usize,
    pub name: String,
    pub params: Vec<ParamDecl>,
    pub ret: RetTy,
    pub syscall: Option<i64>,
    pub clobbers: Vec<Reg>,
    pub preserves: Vec<Reg>,
    pub span: Span,
}

/// A declared parameter, before SSA values exist.
#[derive(Debug, Clone)]
pub struct ParamDecl {
    pub name: String,
    pub ty: Ty,
    pub reg: Option<Reg>,
    pub stack: Option<u32>,
    pub span: Span,
}

/// A function parameter with its entry SSA value.
#[derive(Debug, Clone)]
pub struct Param {
    pub name: String,
    pub ty: Ty,
    pub reg: Reg,
    pub value: ValueId,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq)]
pub enum RetTy {
    None,
    Single(Ty),
    Tuple(Vec<Ty>),
    Never,
}

impl RetTy {
    pub fn is_never(&self) -> bool {
        matches!(self, RetTy::Never)
    }
}

/// One function in SSA form.
#[derive(Debug, Clone)]
pub struct Function {
    pub symbol: usize,
    pub name: String,
    /// Source-level name (`main` even when the symbol is `_start`).
    pub source_name: String,
    pub params: Vec<Param>,
    pub ret: RetTy,
    pub blocks: Vec<Block>,
    pub values: Vec<Value>,
    pub bindings: Vec<Binding>,
    pub clobbers: Vec<Reg>,
    pub preserves: Vec<Reg>,
    pub stack: StackInfo,
    pub span: Span,
    pub is_entry: bool,
    pub returns_never: bool,
}

#[derive(Debug, Clone, Default)]
pub struct StackInfo {
    /// Bytes reserved in the prologue (`stack` places).
    pub frame: u32,
    /// Deepest transient `push` depth seen in the body, in bytes.
    pub max_depth: i32,
    /// Stack alignment the ABI promises at entry.
    pub alignment: u32,
}

/// A basic block.
#[derive(Debug, Clone)]
pub struct Block {
    pub id: BlockId,
    pub label: Option<String>,
    pub insts: Vec<Inst>,
    pub preds: Vec<BlockId>,
    pub succs: Vec<BlockId>,
    pub span: Span,
    pub reachable: bool,
}

/// One SSA instruction.
#[derive(Debug, Clone)]
pub struct Inst {
    pub op: Op,
    pub span: Span,
    /// Pre-rendered LLVM-style text (`%rax.1 = mov i64 1`).
    pub text: String,
    pub defs: Vec<ValueId>,
    pub uses: Vec<ValueId>,
    pub effects: Effects,
    /// Original machine instruction, for the lowering back to `yana-codegen`.
    /// `None` for synthetic nodes (`phi`, `unreachable`).
    pub machine: Option<Insn>,
    pub comment: Option<String>,
}

/// Semantic shape of an instruction. [`Op::Raw`] is the escape hatch for
/// machine instructions the SSA layer does not model yet; its `text` and
/// `defs`/`uses` are still exact.
#[derive(Debug, Clone)]
pub enum Op {
    Phi {
        incoming: Vec<(ValueId, BlockId)>,
    },
    Mov {
        dst: Place,
        src: Operand,
        size: u32,
    },
    Alu {
        op: AluOp,
        dst: Place,
        /// Old value of `dst` for read-modify-write forms (`add rax, 1`).
        lhs: Option<ValueId>,
        rhs: Operand,
        size: u32,
    },
    Cmp {
        a: Operand,
        b: Operand,
        size: u32,
    },
    Lea {
        dst: ValueId,
        addr: Mem,
    },
    Push {
        value: Operand,
        sp_in: ValueId,
        sp_out: ValueId,
        slot: ValueId,
    },
    Pop {
        sp_in: ValueId,
        sp_out: ValueId,
        dst: Option<Place>,
    },
    StackSlot {
        sp_in: ValueId,
        sp_out: ValueId,
        grow: bool,
    },
    StackPad {
        sp_in: ValueId,
        sp_out: ValueId,
        pad: u32,
    },
    /// Synthetic entry node: `%rsp.0 = stack.entry`. Not machine code; it
    /// makes the incoming stack pointer explicit so the first `push` has a
    /// real predecessor value instead of an `undef`.
    StackEntry {
        sp: ValueId,
    },
    Call {
        callee: usize,
        args: Vec<Operand>,
        results: Vec<ValueId>,
        clobbers: Vec<ValueId>,
        noreturn: bool,
        syscall: Option<i64>,
        contract: CallContract,
    },
    Syscall {
        args: Vec<Operand>,
        results: Vec<ValueId>,
        clobbers: Vec<ValueId>,
        noreturn: bool,
    },
    Ret {
        value: Option<ValueId>,
    },
    Jmp {
        target: BlockId,
    },
    Jcc {
        cc: Jcc,
        flags: ValueId,
        target: BlockId,
        fallthrough: Option<BlockId>,
    },
    /// `virt unbind <name>` — a binding-table instruction, not machine code.
    /// It retires the source name; the SSA value it named stays valid until
    /// its last use. The lowering emits zero bytes for this node.
    VirtUnbind {
        name: String,
    },
    Int3,
    Ud2,
    Nop,
    Unreachable,
    Raw,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AluOp {
    Add,
    Sub,
    And,
    Or,
    Xor,
    Shl,
    Shr,
    Imul,
    Neg,
    Not,
    Inc,
    Dec,
}

/// An SSA operand. `Mem` is a place, not a value: its address registers are
/// SSA values, but the memory itself is not SSA-renamed (yet).
#[derive(Debug, Clone, PartialEq)]
pub enum Operand {
    Value(ValueId),
    Imm(i64),
    Sym { sym: usize, add: i64 },
    Mem(Mem),
}

/// A place: an SSA value or a memory location.
pub type Place = Operand;

#[derive(Debug, Clone, PartialEq)]
pub struct Mem {
    pub base: Option<ValueId>,
    pub index: Option<ValueId>,
    pub scale: u8,
    pub disp: Displacement,
    pub size: u32,
    pub rip_relative: bool,
}

/// One SSA value.
#[derive(Debug, Clone)]
pub struct Value {
    pub id: ValueId,
    /// Rendered name: `%rax.0`, `%v12`, `%flags.3`, `%slot1`, `%undef2`.
    pub name: String,
    pub ty: Ty,
    pub home: Home,
    pub kind: ValueKind,
    pub def: Option<DefSite>,
    pub span: Span,
    /// Index into [`Function::bindings`] when this value is a source binding.
    pub bind: Option<usize>,
    /// 8/16-bit writes preserve the rest of the register; the value is a
    /// partial definition and must not be treated as a full overwrite.
    pub partial: bool,
    /// Width of the write that produced this value (8/16/32/64).
    pub width: u32,
    /// Known constant value, when the defining instruction is a `mov imm`.
    pub const_value: Option<i64>,
    /// Placeholder created for a read before any definition (unreachable or
    /// malformed input). The verifier should flag real uses.
    pub undef: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Home {
    /// No physical register yet; the register allocator decides.
    Virtual,
    /// The source language pinned the value (`bind n @ rax`, `alt rax`).
    Pinned(Reg),
    /// The ABI/instruction pinned the value (syscall args, `mul` pair, rsp).
    Fixed(Reg, FixedKind),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FixedKind {
    AbiArg,
    AbiRet,
    Implicit,
    Stack,
    Syscall,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValueKind {
    Reg,
    Flags,
    StackPtr,
    Slot,
    Temp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DefSite {
    pub block: BlockId,
    /// Index into [`Block::insts`].
    pub inst: usize,
}

/// A source-level binding (`fd`, `n`, `n1`, `_`) attached to an SSA value.
#[derive(Debug, Clone)]
pub struct Binding {
    pub name: String,
    pub reg: Option<Reg>,
    pub ty: Ty,
    pub span: Span,
    pub kind: BindKind,
    pub value: Option<ValueId>,
    /// Flat instruction index where the name becomes visible.
    pub active_from: usize,
    /// Flat instruction index of `unbind name;`, if any.
    pub retired_at: Option<usize>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindKind {
    Param,
    Local,
    Discard,
    ReturnPlace,
}

#[derive(Debug, Clone, Default)]
pub struct Effects {
    pub reads_mem: bool,
    pub writes_mem: bool,
    /// EFLAGS bitmask written (cf=1, pf=2, af=4, zf=8, sf=16, of=32).
    pub writes_flags: u8,
    pub reads_flags: u8,
    pub stack_delta: i32,
    pub is_call: bool,
    pub is_noreturn: bool,
    pub is_volatile: bool,
}

impl Effects {
    pub fn writes_any_flags(&self) -> bool {
        self.writes_flags != 0
    }
    pub fn reads_any_flags(&self) -> bool {
        self.reads_flags != 0
    }
}

/// Canonical location of a physical register or the flags word.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Loc {
    Reg(GprBase),
    Flags,
}

impl Loc {
    pub fn reg(self) -> Option<Reg> {
        match self {
            Loc::Reg(base) => Some(Reg::Gpr { base, size: RegSize::R64 }),
            Loc::Flags => None,
        }
    }

    pub fn name(self) -> String {
        match self {
            Loc::Reg(base) => Reg::Gpr { base, size: RegSize::R64 }.name().to_string(),
            Loc::Flags => "flags".to_string(),
        }
    }

    pub fn base(self) -> Option<GprBase> {
        match self {
            Loc::Reg(base) => Some(base),
            Loc::Flags => None,
        }
    }
}

/// The canonical 64-bit register family of any GPR spelling.
pub fn loc_of(reg: &Reg) -> Option<Loc> {
    match reg {
        Reg::Gpr { base, .. } | Reg::GprHigh8(base) => Some(Loc::Reg(*base)),
        Reg::Rip | Reg::Xmm(_) => None,
    }
}

/// All canonical locations in a stable order: 16 GPRs (encoding order) then
/// flags. Used by analyses that need deterministic iteration.
pub fn all_locs() -> Vec<Loc> {
    const BASES: [GprBase; 16] = [
        GprBase::A,
        GprBase::C,
        GprBase::D,
        GprBase::B,
        GprBase::Sp,
        GprBase::Bp,
        GprBase::Si,
        GprBase::Di,
        GprBase::R8,
        GprBase::R9,
        GprBase::R10,
        GprBase::R11,
        GprBase::R12,
        GprBase::R13,
        GprBase::R14,
        GprBase::R15,
    ];
    BASES
        .iter()
        .copied()
        .map(Loc::Reg)
        .chain(std::iter::once(Loc::Flags))
        .collect()
}

/// Human/LLVM-style type rendering.
pub fn ty_str(ty: &Ty) -> String {
    match ty {
        Ty::U8 | Ty::I8 => "i8".into(),
        Ty::U16 | Ty::I16 => "i16".into(),
        Ty::U32 | Ty::I32 => "i32".into(),
        Ty::U64 | Ty::I64 | Ty::Usize | Ty::Isize => "i64".into(),
        Ty::U128 | Ty::I128 => "i128".into(),
        Ty::Never => "void".into(),
        Ty::Ptr(_) => "ptr".into(),
        Ty::Array(t, n) => format!("[{n} x {}]", ty_str(t)),
        Ty::Slice(t) => format!("[]{}", ty_str(t)),
        Ty::Tuple(ts) => format!(
            "{{ {} }}",
            ts.iter().map(ty_str).collect::<Vec<_>>().join(", ")
        ),
        Ty::Struct(name) => format!("%struct.{name}"),
    }
}

/// Look up the type of a register parameter in the module symbol table.
pub fn symbol_param_types(
    symbols: &[yana_codegen::ir::Symbol],
) -> HashMap<usize, Vec<(String, Ty)>> {
    symbols
        .iter()
        .enumerate()
        .map(|(i, s)| {
            (
                i,
                s.params
                    .iter()
                    .map(|p| (p.name.clone(), p.ty.clone()))
                    .collect(),
            )
        })
        .collect()
}
