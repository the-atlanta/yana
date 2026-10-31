//! The YANA AST (§1–§9 of the spec).
//!
//! One source file = one module = one object file (§10). The parser produces a
//! [`File`] of [`Item`]s. Statements mirror the spec 1:1: one statement is one
//! instruction (§4.1), so `a = b + c;` is not expressible.

use crate::place::Place;
use crate::reg::Reg;
use crate::span::{Span, Sp};
use crate::ty::Ty;

/// A parsed source file.
#[derive(Debug, Clone, Default)]
pub struct File {
    pub items: Vec<Item>,
}

/// Top-level item.
#[derive(Debug, Clone)]
pub enum Item {
    Fn(FnItem),
    ExternFn(ExternFnItem),
    Const(ConstItem),
    ConstFn(ConstFnItem),
    /// `bind` at top level — a data-section binding (§7).
    Static(StaticBind),
    /// `use path::name;` — a module import (§10).
    ///
    /// `path` is the colon-separated path as written. The last segment is the
    /// item name; preceding segments form a file path relative to the importer's
    /// directory. `use math::divmod` → file `math.yana`, item `divmod`;
    /// `use lib::math::divmod` → `lib/math.yana`.
    Use { path: Vec<(String, Span)>, span: Span },
}

/// An attribute: `#[name]` or `#[name(args)]` (§1).
#[derive(Debug, Clone)]
pub struct Attr {
    pub name: String,
    pub args: Vec<AttrArg>,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub enum AttrArg {
    Ident(String),
    Int(i64),
    Str(String),
    /// `name = value` form used by `#[cfg(arch = "x86-64")]`.
    Assign { name: String, value: Box<AttrArg> },
}

impl Attr {
    pub fn has_name(&self, name: &str) -> bool {
        self.name == name
    }

    pub fn int_arg(&self) -> Option<i64> {
        self.args.iter().find_map(|a| match a {
            AttrArg::Int(i) => Some(*i),
            _ => None,
        })
    }

    pub fn str_arg(&self) -> Option<&str> {
        self.args.iter().find_map(|a| match a {
            AttrArg::Str(s) => Some(s.as_str()),
            AttrArg::Assign { value: box_, .. } => match box_.as_ref() {
                AttrArg::Str(s) => Some(s.as_str()),
                _ => None,
            },
            _ => None,
        })
    }

    /// `#[cfg(k = "v")]` pairs.
    pub fn cfg_pairs(&self) -> Vec<(String, String)> {
        self.args
            .iter()
            .filter_map(|a| match a {
                AttrArg::Assign { name, value } => match value.as_ref() {
                    AttrArg::Str(s) | AttrArg::Ident(s) => Some((name.clone(), s.clone())),
                    _ => None,
                },
                _ => None,
            })
            .collect()
    }
}

/// Function signature, shared by `fn` and `extern fn`.
#[derive(Debug, Clone)]
pub struct FnSig {
    pub name: String,
    pub name_span: Span,
    pub params: Vec<Param>,
    pub ret: RetSig,
    pub span: Span,
}

/// `[mut] name @ place[: ty]` — the type lives in the place annotation.
#[derive(Debug, Clone)]
pub struct Param {
    pub mutable: bool,
    pub name: String,
    pub place: Place,
    pub span: Span,
}

impl Param {
    /// The declared type, taken from the place annotation if present.
    pub fn ty(&self) -> Option<&Ty> {
        self.place.ty()
    }
}

/// Return signature (§5.1): `-> rax: u64`, `-> (lo @ rax: u64, hi @ rdx: u64)`,
/// `-> !`, or nothing.
#[derive(Debug, Clone)]
pub enum RetSig {
    None,
    /// `-> !` — never returns.
    Never { span: Span },
    /// `-> rax: u64` — the place (with its type annotation).
    Single { place: Place, span: Span },
    /// `-> (lo @ rax: u64, hi @ rdx: u64)`.
    Tuple { parts: Vec<Param>, span: Span },
}

/// A function with a body (§5).
#[derive(Debug, Clone)]
pub struct FnItem {
    pub attrs: Vec<Attr>,
    /// `pub` / `#[global]` — export the symbol (§5.1).
    pub exported: bool,
    pub sig: FnSig,
    /// Clobber list (§5.4). `None` = derive by analysis (later pass).
    pub clobbers: Option<Clobbers>,
    /// §14.4 minimal contracts (`requires`/`ensures`, SPEC §15 ✅ 30.10).
    pub contracts: Contracts,
    pub body: Block,
    pub span: Span,
}

impl FnItem {
    pub fn is_entry(&self) -> bool {
        self.attrs.iter().any(|a| a.has_name("entry"))
    }
}

#[derive(Debug, Clone)]
pub struct Clobbers {
    pub regs: Vec<Reg>,
    pub span: Span,
}

/// §14.4 minimal contracts (SPEC §15 ✅ 30.10): `requires <expr>;` /
/// `ensures <expr>;` clauses after the optional `clobbers:` block, before the
/// body. Expressions reuse the [`ConstExpr`] shape; identifiers name
/// parameters (and, in `ensures`, result registers) — validated at resolve
/// time (`verify-contract-name`).
#[derive(Debug, Clone, Default)]
pub struct Contracts {
    pub requires: Vec<Sp<ConstExpr>>,
    pub ensures: Vec<Sp<ConstExpr>>,
}

impl Contracts {
    pub fn is_empty(&self) -> bool {
        self.requires.is_empty() && self.ensures.is_empty()
    }
}

/// `extern fn` declaration (§5.5), e.g. `#[syscall(1)] extern fn write(...)`.
#[derive(Debug, Clone)]
pub struct ExternFnItem {
    pub attrs: Vec<Attr>,
    /// `extern "C"` → Some("C"); plain `extern` → None (syscall ABI).
    pub abi: Option<String>,
    pub sig: FnSig,
    pub clobbers: Option<Clobbers>,
    /// §14.4 minimal contracts — accepted on externs for symmetry; pass 4
    /// only checks call sites against them (no body to verify ensures on).
    pub contracts: Contracts,
    pub span: Span,
}

impl ExternFnItem {
    /// `#[syscall(N)]` number, if present.
    pub fn syscall_number(&self) -> Option<i64> {
        self.attrs.iter().find(|a| a.has_name("syscall")).and_then(|a| a.int_arg())
    }
}

/// `const NAME: T = expr;` (§7).
#[derive(Debug, Clone)]
pub struct ConstItem {
    pub attrs: Vec<Attr>,
    pub name: String,
    pub name_span: Span,
    pub ty: Ty,
    pub value: ConstExpr,
    pub span: Span,
}

/// `const fn` (§8): evaluated at build time; body is `return <const expr>;`.
#[derive(Debug, Clone)]
pub struct ConstFnItem {
    pub attrs: Vec<Attr>,
    pub name: String,
    pub name_span: Span,
    pub params: Vec<(String, Ty)>,
    pub ret: Option<Ty>,
    pub body: ConstExpr,
    pub span: Span,
}

/// Top-level data binding (§7): `bind hello @ .rodata: [u8] = "Hello\n";`
///
/// The place must be a section (checked semantically); the type comes from the
/// place annotation.
#[derive(Debug, Clone)]
pub struct StaticBind {
    pub name: String,
    pub name_span: Span,
    pub place: Place,
    pub init: Option<Value>,
    pub attrs: Vec<Attr>,
    pub span: Span,
}

/// Compile-time expression (§8). Values only — never instructions.
#[derive(Debug, Clone)]
pub enum ConstExpr {
    Int { value: i128, span: Span },
    Bool { value: bool, span: Span },
    Name { name: String, span: Span },
    Unary { op: ConstUnOp, expr: Box<ConstExpr>, span: Span },
    Binary { op: ConstBinOp, lhs: Box<ConstExpr>, rhs: Box<ConstExpr>, span: Span },
    If { cond: Box<ConstExpr>, then_b: Box<ConstExpr>, else_b: Box<ConstExpr>, span: Span },
    /// `const fn` call.
    Call { name: String, args: Vec<ConstExpr>, span: Span },
    Array { items: Vec<ConstExpr>, span: Span },
    Tuple { items: Vec<ConstExpr>, span: Span },
    /// Array repeat `[v; n]`.
    Repeat { value: Box<ConstExpr>, count: Box<ConstExpr>, span: Span },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConstUnOp {
    Neg,
    Not,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConstBinOp {
    Add,
    Sub,
    Mul,
    Div,
    Rem,
    BitAnd,
    BitOr,
    BitXor,
    Shl,
    Shr,
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    And,
    Or,
}

/// A block `{ ... }` of statements.
#[derive(Debug, Clone, Default)]
pub struct Block {
    pub stmts: Vec<Stmt>,
    pub span: Span,
}

/// A statement (§3–§6). One statement = one machine instruction after lowering.
#[derive(Debug, Clone)]
pub enum Stmt {
    /// `bind [mut] name @ place[: ty] [= init];` (§3). Initial write needs no `alt`.
    Bind {
        mutable: bool,
        name: Option<String>,
        name_span: Span,
        place: Place,
        init: Option<Value>,
        /// Destructuring form: `bind (q @ rax, r @ rdx) = ...;`
        pattern: Option<Vec<Param>>,
        span: Span,
    },
    /// `alt [modifier] dst <op>= src;` (§4.1, §4.2; §12 for the modifiers).
    Alt {
        dst: Place,
        op: AssignOp,
        src: Value,
        /// §12 modifier on the whole statement (atomic/volatile); the order
        /// of an atomic RMW is carried here, kept for future targets (on
        /// x86-64 every order encodes identically — lock RMW is a full
        /// barrier).
        modifier: AltModifier,
        span: Span,
    },
    /// `alt (rax, rdx) = pair /% d;` — divide with explicit hardware operands
    /// (§4.5): `div`/`idiv`; results land in the given places (validated
    /// against the hardware pair by analysis).
    DivMod {
        results: Vec<Place>,
        dividend: Place,
        divisor: Value,
        span: Span,
    },
    /// `push { a, b };` (§4.3) — expands in written order.
    Push { items: Vec<Place>, span: Span },
    /// `pop { b, a };` (§4.3) — expands in written order.
    Pop { items: Vec<Place>, span: Span },
    /// `align N;` (§4.3 🟡) — pad the stack so rsp ≡ 0 (mod N) at this point.
    /// The static depth from the stack analysis decides the padding.
    Align { align: u64, span: Span },
    /// `branch (cond)? => 'label;` (§4.4).
    Branch {
        cond: Option<BranchCond>,
        target: String,
        target_span: Span,
        span: Span,
    },
    /// `call name { p: v };` or `bind r = call f { ... };` (§5.3).
    Call {
        results: Option<CallResults>,
        name: String,
        name_span: Span,
        args: Vec<CallArg>,
        span: Span,
    },
    /// `return [value];` (§5.2). Value is a const or a place assertion.
    Return { value: Option<Value>, span: Span },
    /// Raw `syscall;` (§5.5).
    Syscall { span: Span },
    /// `label (name) { ... }` (§6) — block-scoped fallthrough label.
    Label {
        name: String,
        name_span: Span,
        body: Block,
        span: Span,
    },
    /// A bare block (scoping for binds).
    Nested(Block),
}

/// Where the results of a call land (§5.3).
#[derive(Debug, Clone)]
pub enum CallResults {
    /// `bind r = call f` — `None` name means discard (`bind _ = ...`).
    Single { name: Option<String>, span: Span },
    /// `bind (a, b) = call f` — places come from the callee signature.
    Tuple { names: Vec<Option<String>>, span: Span },
}

#[derive(Debug, Clone)]
pub struct CallArg {
    /// Parameter name when given: `call f { n: 5 };`
    pub param: Option<String>,
    pub value: Value,
    /// Explicit place override: `{ n: v @ rdi }` (§5.3) — asserts where the
    /// value already lives; matching the signature silences the mov.
    pub at: Option<Place>,
    pub span: Span,
}

/// §12 modifier on an `alt` statement: plain, atomic RMW, or volatile access.
///
/// - `alt atomic(order) ...` — locked read-modify-write. x86-64: one `lock`
///   instruction (order recorded in the IR for future targets).
/// - `alt volatile ...` — the analysis must not elide the access.
#[derive(Debug, Clone, PartialEq)]
pub enum AltModifier {
    /// Plain `alt` — no §12 modifier.
    None,
    /// `alt atomic(<order>) ...`.
    Atomic(AtomicOrder),
    /// `alt volatile ...`.
    Volatile,
}

/// Memory order for `alt atomic(order)` (§12). Not keywords — parsed as
/// identifiers with exact text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AtomicOrder {
    Relaxed,
    Acquire,
    Release,
    AcqRel,
    SeqCst,
}

impl AtomicOrder {
    /// Parse an order name as written in source. `None` = bad name.
    pub fn parse(s: &str) -> Option<AtomicOrder> {
        match s {
            "relaxed" => Some(AtomicOrder::Relaxed),
            "acquire" => Some(AtomicOrder::Acquire),
            "release" => Some(AtomicOrder::Release),
            "acqrel" => Some(AtomicOrder::AcqRel),
            "seqcst" => Some(AtomicOrder::SeqCst),
            _ => None,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            AtomicOrder::Relaxed => "relaxed",
            AtomicOrder::Acquire => "acquire",
            AtomicOrder::Release => "release",
            AtomicOrder::AcqRel => "acqrel",
            AtomicOrder::SeqCst => "seqcst",
        }
    }
}

/// Assignment operators (§4.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssignOp {
    /// `=` → mov (or lea when src is `&place`).
    Assign,
    /// `+=` → add
    Add,
    /// `-=` → sub
    Sub,
    /// `^=` → xor
    Xor,
    /// `&=` → and
    And,
    /// `|=` → or
    Or,
    /// `<<=` → shl
    Shl,
    /// `>>=` → shr
    Shr,
    /// `*=` → imul (two-operand)
    Mul,
    // `/=` and `%=` are handled via the explicit div forms (§4.5), not here.
}

/// Branch condition (§4.4): comparison or flag test.
#[derive(Debug, Clone)]
pub enum BranchCond {
    /// `a < b` — emits `cmp`, signedness from the type.
    Cmp { lhs: Value, op: CmpOp, rhs: Value, span: Span },
    /// `zero`, `!carry`, ... — no `cmp` emitted.
    Flag { flag: Flag, negated: bool, span: Span },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CmpOp {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flag {
    Zero,
    Carry,
    Negative,
    Overflow,
    /// Parity (even).
    Even,
}

/// An operand value: a place, an immediate, or a build-time constant.
#[derive(Debug, Clone)]
pub enum Value {
    Place(Place),
    Imm { value: i128, span: Span },
    Str { bytes: Vec<u8>, span: Span },
    /// `&name` / `&@[...]` — lea source (§3).
    AddrOf { place: Box<Place>, span: Span },
    /// `expr as T` — cast (§4.2).
    Cast { value: Box<Value>, ty: Ty, span: Span },
    /// `a * b` in a wide-multiply destination context (§4.5):
    /// `alt rdx:rax = rax * x;`. A single `mul`/`imul` instruction — legal
    /// only when the destination is the register pair matching the hardware.
    Mul { lhs: Box<Value>, rhs: Box<Value>, span: Span },
    /// `name.len` (§7 🟡) — currently the only field; resolved to the binding's
    /// byte length at semantic time.
    Field { base: Box<Value>, name: String, span: Span },
    /// `const { ... }` inline build-time value (§8).
    Const { expr: ConstExpr, span: Span },
}

impl Value {
    pub fn span(&self) -> Span {
        match self {
            Value::Place(p) => p.span(),
            Value::Imm { span, .. }
            | Value::Str { span, .. }
            | Value::AddrOf { span, .. }
            | Value::Cast { span, .. }
            | Value::Mul { span, .. }
            | Value::Field { span, .. }
            | Value::Const { span, .. } => *span,
        }
    }
}

/// Label reference `'имя` (§1) as used by `branch`.
#[derive(Debug, Clone)]
pub struct LabelRef {
    pub name: String,
    pub span: Span,
}
