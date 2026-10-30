//! Grammar helpers shared with the LALRPOP-generated parser.
//!
//! Fallible actions in the grammar (`=>?`) fail with synthetic
//! [`Token::BadNum`]/[`Token::BadEscape`] variants that carry spans; the driver
//! turns them into precise diagnostics.

use yana_ast::place::{MemTerm, RawAddr};
use yana_ast::reg::Reg;
use yana_ast::{
    AssignOp, Attr, AttrArg, Block, BranchCond, CallArg, CallResults, CmpOp, ConstBinOp,
    ConstExpr, ConstFnItem, ConstItem, ConstUnOp, ExternFnItem, Flag, FnItem, FnSig, Item, Param,
    Place, RetSig, Span, StaticBind, Stmt, Ty, Value,
};
use yana_ast::place::SectionKind;
use yana_lexer::Token;
use lalrpop_util::ParseError;

/// Error type LALRPOP fallible actions must return.
pub type PErr = ParseError<usize, Token, Token>;

fn user_err(t: Token) -> PErr {
    ParseError::User { error: t }
}

/// The token type the grammar fails with.
pub type Err = Token;

/// Anything that can produce a span (payload tokens + synthetic error tokens).
pub trait WithSpan {
    fn span(&self) -> Span;
}

impl WithSpan for Token {
    fn span(&self) -> Span {
        match self {
            Token::BadNum(b) | Token::BadEscape(b) | Token::BadReg(b) => b.span(),
            _ => Span::DUMMY,
        }
    }
}

/// A parsed payload token plus its source span.
#[derive(Debug, Clone)]
pub struct Sp<T> {
    pub v: T,
    pub span: Span,
}

impl Sp<String> {
    pub fn len_from(&self) -> Span {
        self.span
    }
}

/// Parse an integer literal (dec/hex/bin, `_` separators allowed).
pub fn parse_int(s: &str, span: Span) -> Result<i128, PErr> {
    let clean: String = s.chars().filter(|c| *c != '_').collect();
    let r = if let Some(h) = clean.strip_prefix("0x").or_else(|| clean.strip_prefix("0X")) {
        i128::from_str_radix(h, 16)
    } else if let Some(b) = clean.strip_prefix("0b").or_else(|| clean.strip_prefix("0B")) {
        i128::from_str_radix(b, 2)
    } else {
        clean.parse()
    };
    r.map_err(|_| user_err(Token::BadNum(yana_lexer::token::BadLit::new(s, span.lo, span.hi))))
}

/// Unescape a string literal (source text including quotes) into bytes.
pub fn parse_str(raw: &str, span: Span) -> Result<Vec<u8>, PErr> {
    let body = &raw[1..raw.len() - 1];
    yana_lexer::unescape_string(body).map_err(|(off, _)| {
        user_err(Token::BadEscape(yana_lexer::token::BadLit::new(raw, span.lo + off as u32, span.hi)))
    })
}

/// Resolve an identifier token into a [`Place`] (discard / register / section /
/// named).
pub fn ident_place(s: &str, span: Span) -> Place {
    if s == "_" {
        return Place::Discard { span };
    }
    if let Some(kind) = SectionKind::parse(s) {
        return Place::Section { kind, ty: None, span };
    }
    if let Some(reg) = Reg::parse(s) {
        return Place::Reg { reg, ty: None, span };
    }
    Place::Named { name: s.to_string(), ty: None, span }
}

/// Resolve a section name token; fails with a parse error if it isn't one.
pub fn section_place(s: &str, span: Span) -> Result<Place, PErr> {
    SectionKind::parse(s)
        .map(|kind| Place::Section { kind, ty: None, span })
        .ok_or_else(|| user_err(Token::Ident(s.to_string())))
}

/// An identifier that must be a register (RegPair halves).
pub fn reg_of(s: &str, span: Span) -> Result<Reg, PErr> {
    Reg::parse(s).ok_or_else(|| user_err(Token::BadReg(yana_lexer::token::BadLit::new(s, span.lo, span.hi))))
}

/// A "not a register" parse error (used inside memory-term fallible actions).
pub fn bad_reg_err(s: String, span: Span) -> PErr {
    user_err(Token::BadReg(yana_lexer::token::BadLit::new(s, span.lo, span.hi)))
}

/// Primitive type keywords.
pub fn prim_ty(t: &Token) -> Option<Ty> {
    Some(match t {
        Token::Tu8 => Ty::U8,
        Token::Tu16 => Ty::U16,
        Token::Tu32 => Ty::U32,
        Token::Tu64 => Ty::U64,
        Token::Tu128 => Ty::U128,
        Token::Tusize => Ty::Usize,
        Token::Ti8 => Ty::I8,
        Token::Ti16 => Ty::I16,
        Token::Ti32 => Ty::I32,
        Token::Ti64 => Ty::I64,
        Token::Ti128 => Ty::I128,
        Token::Tisize => Ty::Isize,
        _ => return None,
    })
}

/// A memory term with its sign (`-` → true).
pub struct SignedTerm {
    pub neg: bool,
    pub term: MemTerm,
}

/// Fold parsed memory terms into a [`RawAddr`].
pub fn build_addr(first: MemTerm, rest: Vec<SignedTerm>, span: Span) -> RawAddr {
    let mut terms = vec![first];
    for t in rest {
        let term = match (t.neg, t.term) {
            (false, term) => term,
            (true, MemTerm::Const(c)) => MemTerm::Const(-c),
            // `-name` / `-reg` inside addresses: keep positive, the semantic
            // pass rejects negative register/symbol terms with a clear error.
            (true, other) => other,
        };
        terms.push(term);
    }
    RawAddr { terms, span }
}

/// `#[global]` also exports (§5.1).
/// Export is `#[global]` only — the `pub` keyword was removed from the
/// language (SPEC §15, решение Ники 29.10).
pub fn fn_exported(attrs: &[Attr]) -> bool {
    attrs.iter().any(|a| a.has_name("global"))
}

/// Fallible action for the removed `pub` keyword: produces the synthetic
/// [`Token::RemovedPub`] the driver turns into a precise diagnostic.
pub fn removed_pub(lo: usize, hi: usize) -> PErr {
    user_err(Token::RemovedPub(yana_lexer::token::BadLit::new("pub", lo as u32, hi as u32)))
}

/// Dummy param for single-value return signatures.
pub fn ret_single(place: Place) -> RetSig {
    let span = place.span();
    RetSig::Single { place, span }
}

/// Build the never-return signature.
pub fn ret_never(span: Span) -> RetSig {
    RetSig::Never { span }
}

/// Build an attribute.
pub fn attr(name: Sp<String>, args: Vec<AttrArg>) -> Attr {
    Attr { name: name.v, args, span: name.span }
}

/// Build a call statement.
pub fn call_stmt(
    res: Option<CallResults>,
    name: Sp<String>,
    args: Vec<CallArg>,
    lo: usize,
    hi: usize,
) -> Stmt {
    Stmt::Call {
        results: res,
        name: name.v,
        name_span: name.span,
        args,
        span: Span::new(lo as u32, hi as u32),
    }
}

/// Build a function item.
pub fn fn_item(
    attrs: Vec<Attr>,
    name: Sp<String>,
    params: Vec<Param>,
    ret: RetSig,
    clobbers: Option<yana_ast::Clobbers>,
    body: Block,
    lo: usize,
    hi: usize,
) -> FnItem {
    FnItem {
        exported: fn_exported(&attrs),
        attrs,
        sig: FnSig {
            name: name.v,
            name_span: name.span,
            params,
            ret,
            span: Span::new(lo as u32, hi as u32),
        },
        clobbers,
        body,
        span: Span::new(lo as u32, hi as u32),
    }
}

/// Build an extern fn item.
pub fn extern_fn_item(
    attrs: Vec<Attr>,
    abi: Option<String>,
    name: Sp<String>,
    params: Vec<Param>,
    ret: RetSig,
    clobbers: Option<yana_ast::Clobbers>,
    lo: usize,
    hi: usize,
) -> ExternFnItem {
    ExternFnItem {
        attrs,
        abi,
        sig: FnSig {
            name: name.v,
            name_span: name.span,
            params,
            ret,
            span: Span::new(lo as u32, hi as u32),
        },
        clobbers,
        span: Span::new(lo as u32, hi as u32),
    }
}

/// Build a static bind item.
pub fn static_bind(
    attrs: Vec<Attr>,
    name: Sp<String>,
    place: Place,
    init: Option<Value>,
    lo: usize,
    hi: usize,
) -> StaticBind {
    StaticBind {
        name: name.v,
        name_span: name.span,
        place,
        init,
        attrs,
        span: Span::new(lo as u32, hi as u32),
    }
}

/// Build a const item.
pub fn const_item(name: Sp<String>, ty: Ty, value: ConstExpr, lo: usize, hi: usize) -> ConstItem {
    ConstItem {
        name: name.v,
        name_span: name.span,
        ty,
        value,
        span: Span::new(lo as u32, hi as u32),
    }
}

/// Build a const fn item. Body must be exactly `return <const expr>;` (§8).
pub fn const_fn_item(
    name: Sp<String>,
    params: Vec<(String, Ty)>,
    ret: Option<Ty>,
    body: ConstExpr,
    span: Span,
) -> ConstFnItem {
    ConstFnItem {
        name: name.v,
        name_span: name.span,
        params,
        ret,
        body,
        span,
    }
}

/// Binary op constructors for the precedence chain.
pub fn bin(op: ConstBinOp, l: ConstExpr, r: ConstExpr, lo: usize, hi: usize) -> ConstExpr {
    ConstExpr::Binary {
        op,
        lhs: Box::new(l),
        rhs: Box::new(r),
        span: Span::new(lo as u32, hi as u32),
    }
}

pub fn un(op: ConstUnOp, e: ConstExpr, lo: usize, hi: usize) -> ConstExpr {
    ConstExpr::Unary { op, expr: Box::new(e), span: Span::new(lo as u32, hi as u32) }
}

/// A call argument with an optional param name and place override.
pub fn call_arg(param: Option<Sp<String>>, value: Value, at: Option<Place>, lo: usize, hi: usize) -> CallArg {
    CallArg { param: param.map(|p| p.v), value, at, span: Span::new(lo as u32, hi as u32) }
}

/// Assign-op table for `alt` statements.
pub fn assign_op(t: &Token) -> AssignOp {
    match t {
        Token::Eq => AssignOp::Assign,
        Token::PlusEq => AssignOp::Add,
        Token::MinusEq => AssignOp::Sub,
        Token::StarEq => AssignOp::Mul,
        Token::CaretEq => AssignOp::Xor,
        Token::AmpEq => AssignOp::And,
        Token::PipeEq => AssignOp::Or,
        Token::ShlEq => AssignOp::Shl,
        Token::ShrEq => AssignOp::Shr,
        _ => unreachable!("assign_op on non-assign token {t:?}"),
    }
}

/// Comparison-op table for branch conditions.
pub fn cmp_op(t: &Token) -> CmpOp {
    match t {
        Token::EqEq => CmpOp::Eq,
        Token::Ne => CmpOp::Ne,
        Token::Lt => CmpOp::Lt,
        Token::Le => CmpOp::Le,
        Token::Gt => CmpOp::Gt,
        Token::Ge => CmpOp::Ge,
        _ => unreachable!("cmp_op on non-cmp token {t:?}"),
    }
}

/// Flag table for branch conditions.
pub fn flag_of(t: &Token) -> Flag {
    match t {
        Token::FlagZero => Flag::Zero,
        Token::FlagCarry => Flag::Carry,
        Token::FlagNegative => Flag::Negative,
        Token::FlagOverflow => Flag::Overflow,
        Token::FlagEven => Flag::Even,
        _ => unreachable!("flag_of on non-flag token {t:?}"),
    }
}

/// Item constructors, so grammar actions stay one-liners.
pub fn item_fn(f: FnItem) -> Item { Item::Fn(f) }
pub fn item_extern(e: ExternFnItem) -> Item { Item::ExternFn(e) }
pub fn item_const(c: ConstItem) -> Item { Item::Const(c) }
pub fn item_constfn(c: ConstFnItem) -> Item { Item::ConstFn(c) }
pub fn item_static(s: StaticBind) -> Item { Item::Static(s) }
