//! The resolver: AST → IR (passes 1–2 of §14).
//!
//! Pass 1 collects declarations: statics (with layout), consts, const fns,
//! functions and externs become symbols. Pass 2 lowers each function body,
//! one statement → one instruction, resolving names, casts and the wide
//! mul/div forms, and validating the spec's contracts as it goes (§4.2, §4.5,
//! §5.2, §6). Diagnostics use the spec's classes (`redundant`, `contract`).

use std::collections::HashMap;

use yana_ast::place::{MemTerm, RawAddr, SectionKind};
use yana_ast::reg::Reg;
use yana_ast::{
    AltModifier, AssignOp, Block, BranchCond, CallArg, CallResults, DiagCode, Diagnostic, File,
    FnSig, Item, Param, Place, RetSig, Span, Stmt, Ty, Value,
};

use crate::consteval::{self, ConstEnv, Value as CValue};
use crate::insn;
use crate::ir::{
    AtomicOp, BranchUse, CallContract, DataItem, Displacement, FnBody, Insn, Jcc, LabelDef, MemOp,
    MemOrder, Module, Operand, SectionData, SpannedInsn, Symbol, SymbolKind, WideOp,
};
use crate::target::{Arch, ResolveOptions, TargetInfo};

/// Result of resolving one module.
pub struct ResolveOutput {
    pub module: Module,
    pub diagnostics: Vec<Diagnostic>,
}

impl ResolveOutput {
    pub fn has_errors(&self) -> bool {
        self.diagnostics.iter().any(|d| matches!(d.level, yana_ast::DiagLevel::Error))
    }
}

/// A name binding visible in a scope.
#[derive(Debug, Clone)]
struct Binding {
    operand: Operand,
    ty: Ty,
    mutable: bool,
    span: Span,
}

impl Binding {
    fn size_bits(&self, target: &TargetInfo) -> u32 {
        ty_bits(&self.ty, target)
    }
}

/// Resolve a parsed [`File`] into an IR [`Module`].
pub fn resolve_module(file: &File, target: &TargetInfo, opts: &ResolveOptions) -> ResolveOutput {
    let mut r = Resolver::new(target.clone(), opts.clone());
    r.run(file);
    ResolveOutput { module: r.module, diagnostics: r.diagnostics }
}

struct Resolver {
    target: TargetInfo,
    opts: ResolveOptions,
    module: Module,
    diagnostics: Vec<Diagnostic>,

    // const-eval state
    env: ConstEnvOwned,
    const_fns: HashMap<String, yana_ast::ConstFnItem>,

    // symbol tables
    statics: HashMap<String, StaticInfo>,
    consts: HashMap<String, i128>,
    fns: HashMap<String, FnInfo>,

    // current function state
    scopes: Vec<HashMap<String, Binding>>,
    body: FnBody,
    /// label name → index into body.label_defs
    labels: HashMap<String, usize>,
    /// jumps awaiting label resolution: (insn index, label name, span, scope depth)
    pending_jumps: Vec<(usize, String, Span, u32)>,
    cur_ret: RetSig,
    cur_fn_span: Span,
    /// Span of the statement currently being lowered — every emitted
    /// instruction is tagged with it (§14: spans in the IR).
    cur_span: Span,
}

/// Owned const env (ConstEnv borrows fns; we clone them in).
struct ConstEnvOwned {
    consts: HashMap<String, CValue>,
}

#[derive(Debug, Clone)]
struct StaticInfo {
    sym: usize,
    section: SectionKind,
    offset: u64,
    size: u64,
}

#[derive(Debug, Clone)]
struct FnInfo {
    sym: usize,
    params: Vec<ParamInfo>,
    ret: RetInfo,
    /// `#[syscall(N)]` — calls lower inline to `mov rax,N; syscall`.
    syscall: Option<i64>,
    /// True for `extern "C"` (real linker symbol call).
    real_call: bool,
}

#[derive(Debug, Clone)]
struct ParamInfo {
    operand: Operand,
    ty: Ty,
    name: String,
}

#[derive(Debug, Clone)]
enum RetInfo {
    None,
    Never,
    Single { operand: Operand, ty: Ty },
    Tuple { parts: Vec<ParamInfo> },
}

fn ty_bits(ty: &Ty, target: &TargetInfo) -> u32 {
    ty.size_bits(target.usize_bits()).unwrap_or(target.usize_bits())
}

impl Resolver {
    fn new(target: TargetInfo, opts: ResolveOptions) -> Self {
        let mut r = Resolver {
            env: ConstEnvOwned { consts: HashMap::new() },
            const_fns: HashMap::new(),
            statics: HashMap::new(),
            consts: HashMap::new(),
            fns: HashMap::new(),
            scopes: Vec::new(),
            body: FnBody::default(),
            labels: HashMap::new(),
            pending_jumps: Vec::new(),
            cur_ret: RetSig::None,
            cur_fn_span: Span::DUMMY,
            cur_span: Span::DUMMY,
            target,
            opts,
            module: Module::default(),
            diagnostics: Vec::new(),
        };
        r.env_consts_setup();
        r.module.target = r.target.clone();
        r
    }

    fn env_consts_setup(&mut self) {
        // nothing yet; consts filled during pass 1
    }

    fn err(&mut self, kind: &str, msg: impl Into<String>, span: Span) {
        self.diagnostics
            .push(Diagnostic::error(DiagCode::Semantic, kind, msg, span));
    }

    fn err_help(&mut self, kind: &str, msg: impl Into<String>, help: impl Into<String>, span: Span) {
        self.diagnostics.push(
            Diagnostic::error(DiagCode::Semantic, kind, msg, span).with_help(help),
        );
    }

    fn warn(&mut self, code: DiagCode, kind: &str, msg: impl Into<String>, span: Span) {
        self.diagnostics.push(Diagnostic::warn(code, kind, msg, span));
    }

    // =====================================================================
    // Pass 1: declarations
    // =====================================================================

    fn run(&mut self, file: &File) {
        self.collect_decls(file);
        if self.diagnostics.iter().any(|d| matches!(d.level, yana_ast::DiagLevel::Error)) {
            return; // don't lower on a broken decl set
        }
        self.lower_bodies(file);
    }

    fn collect_decls(&mut self, file: &File) {
        // statics + consts + const fns first (bodies may reference them)
        for item in &file.items {
            match item {
                Item::Static(s) => self.collect_static(s),
                Item::Const(c) => self.collect_const(c),
                Item::ConstFn(f) => {
                    self.const_fns.insert(f.name.clone(), f.clone());
                }
                _ => {}
            }
        }
        // evaluate consts (may reference other consts — single pass in decl order;
        // forward refs error for MVP)
        for item in &file.items {
            if let Item::Const(c) = item {
                self.eval_const(c);
            }
        }
        // functions and externs → symbols
        for item in &file.items {
            match item {
                Item::Fn(f) => self.collect_fn(&f.sig, f.exported, f.is_entry(), None, false, f.span),
                Item::ExternFn(e) => {
                    let syscall = e.syscall_number();
                    let real_call = e.abi.as_deref() == Some("C");
                    self.collect_fn(&e.sig, true, false, syscall, true, e.span);
                    if let Some(sym) = self.module.find(&e.sig.name) {
                        let info = self.fns.get_mut(&e.sig.name).unwrap();
                        info.real_call = real_call;
                        let _ = sym;
                    }
                }
                _ => {}
            }
        }
    }

    fn collect_static(&mut self, s: &yana_ast::StaticBind) {
        let section = match &s.place {
            Place::Section { kind, .. } => *kind,
            _ => {
                self.err(
                    "static-place",
                    "top-level bind must target a section (.rodata/.data/.bss)",
                    s.place.span(),
                );
                return;
            }
        };
        let ty = s.place.ty().cloned().unwrap_or(Ty::U8);

        // compute initializer bytes and size
        let (bytes, size): (Option<Vec<u8>>, u64) = match (&s.init, &ty) {
            (Some(init), _) => match self.init_bytes(init, &ty, s.span) {
                Ok(b) => {
                    let n = b.len() as u64;
                    (Some(b), n)
                }
                Err(()) => return,
            },
            (None, Ty::Array(inner, n)) => {
                if section != SectionKind::Bss {
                    // allowed but zero-filled; keep in .bss semantics
                }
                (None, ty_bits(inner, &self.target) as u64 / 8 * n)
            }
            (None, _) => {
                self.err(
                    "static-init",
                    "static data without initializer needs an array type (or use .bss)",
                    s.span,
                );
                return;
            }
        };

        let align = (ty_bits(&ty, &self.target) / 8).max(1) as u64;
        let sec = self.module.section_mut(section);
        let offset = next_offset(sec, align);

        // symbol first, so the data item can reference it (NASM emits the label)
        let sym = self.module.symbols.len();
        self.module.symbols.push(Symbol {
            name: s.name.clone(),
            kind: SymbolKind::Static { section, offset, size },
            exported: s.attrs.iter().any(|a| a.has_name("global")),
            syscall: None,
            clobbers: vec![],
            span: s.span,
        });
        let sec = self.module.section_mut(section);
        match bytes {
            Some(b) => sec.items.push(DataItem::Bytes { offset, bytes: b, align, sym: Some(sym) }),
            None => sec.items.push(DataItem::Zero { offset, size, align, sym: Some(sym) }),
        }
        self.statics.insert(
            s.name.clone(),
            StaticInfo { sym, section, offset, size },
        );
    }

    /// Compute initializer bytes; Err(()) after emitting a diagnostic.
    fn init_bytes(&mut self, init: &Value, ty: &Ty, span: Span) -> Result<Vec<u8>, ()> {
        match init {
            Value::Str { bytes, .. } => Ok(bytes.clone()),
            Value::Imm { value, .. } => Ok(imm_to_bytes(*value, ty, &self.target)),
            Value::Const { expr, .. } => match self.eval_const_expr(expr) {
                Ok(v) => Ok(self.const_to_bytes(&v, ty)),
                Err(d) => {
                    self.diagnostics.push(d);
                    Err(())
                }
            },
            other => {
                self.err(
                    "static-init",
                    format!("unsupported static initializer ({:?})", init_kind_name(other)),
                    span,
                );
                Err(())
            }
        }
    }

    fn const_to_bytes(&self, v: &CValue, ty: &Ty) -> Vec<u8> {
        match (v, ty) {
            (CValue::Array(items), Ty::Array(inner, _)) | (CValue::Array(items), Ty::Slice(inner)) => {
                let elem = (ty_bits(inner, &self.target) / 8).max(1) as usize;
                items.iter().flat_map(|i| i.to_bytes(elem)).collect()
            }
            (CValue::Tuple(items), Ty::Tuple(tys)) => {
                let mut out = Vec::new();
                for (i, t) in items.iter().zip(tys) {
                    let w = (ty_bits(t, &self.target) / 8).max(1) as usize;
                    out.extend(i.to_bytes(w));
                }
                out
            }
            _ => {
                let w = (ty_bits(ty, &self.target) / 8).max(1) as usize;
                v.to_bytes(w)
            }
        }
    }

    fn collect_const(&mut self, c: &yana_ast::ConstItem) {
        // value computed in eval_const (needs env); placeholder registered here
        let sym = self.module.symbols.len();
        self.module.symbols.push(Symbol {
            name: c.name.clone(),
            kind: SymbolKind::Const { value: 0 },
            exported: false,
            syscall: None,
            clobbers: vec![],
            span: c.span,
        });
        self.consts.insert(c.name.clone(), 0); // patched by eval_const
        let _ = sym;
    }

    fn eval_const(&mut self, c: &yana_ast::ConstItem) {
        match self.eval_const_expr(&c.value) {
            Ok(v) => {
                let i = v.as_int().unwrap_or(0);
                // fits in declared type?
                let bits = ty_bits(&c.ty, &self.target);
                if !imm_fits(i, bits, c.ty.is_signed()) {
                    self.err(
                        "const-range",
                        format!("const `{}` = {i} does not fit in {:?}", c.name, c.ty),
                        c.span,
                    );
                    return;
                }
                if let Some(sym) = self.module.find(&c.name) {
                    self.module.symbols[sym].kind = SymbolKind::Const { value: i };
                }
                self.consts.insert(c.name.clone(), i);
                self.env.consts.insert(c.name.clone(), CValue::Int(i));
            }
            Err(d) => self.diagnostics.push(d),
        }
    }

    fn eval_const_expr(&self, expr: &yana_ast::ConstExpr) -> Result<CValue, Diagnostic> {
        // Build a borrowed env each call (fns cloned refs live in self.const_fns)
        let mut fns_ref: HashMap<String, &yana_ast::ConstFnItem> = HashMap::new();
        for (k, v) in &self.const_fns {
            fns_ref.insert(k.clone(), v);
        }
        let mut env = ConstEnv::with(
            self.env.consts.clone(),
            fns_ref,
            self.opts.const_steps,
        );
        consteval::eval(&mut env, expr, &HashMap::new()).map_err(|e| e.into_diag())
    }

    fn collect_fn(
        &mut self,
        sig: &FnSig,
        exported: bool,
        is_entry: bool,
        syscall: Option<i64>,
        is_extern: bool,
        span: Span,
    ) {
        if self.fns.contains_key(&sig.name) || self.statics.contains_key(&sig.name) {
            self.err("dup-symbol", format!("symbol `{}` declared twice", sig.name), span);
            return;
        }
        let name = if is_entry {
            self.target.entry_symbol().to_string()
        } else {
            format!("{}{}", self.target.symbol_prefix(), sig.name)
        };

        let params: Vec<ParamInfo> = sig
            .params
            .iter()
            .map(|p| ParamInfo {
                operand: self.param_operand(p),
                ty: p.ty().cloned().unwrap_or(Ty::U64),
                name: p.name.clone(),
            })
            .collect();

        let ret: RetInfo = match &sig.ret {
            RetSig::None => RetInfo::None,
            RetSig::Never { .. } => RetInfo::Never,
            RetSig::Single { place, .. } => RetInfo::Single {
                operand: self.place_to_operand_simple(place),
                ty: place.ty().cloned().unwrap_or(Ty::U64),
            },
            RetSig::Tuple { parts, .. } => RetInfo::Tuple {
                parts: parts
                    .iter()
                    .map(|p| ParamInfo {
                        operand: self.param_operand(p),
                        ty: p.ty().cloned().unwrap_or(Ty::U64),
                        name: p.name.clone(),
                    })
                    .collect(),
            },
        };

        let sym_idx = self.module.symbols.len();
        // externs have no body: ExternFn; real fns get a body index in pass 2.
        // (We mark externs when the caller said so via `real_call`/syscall or
        // when the symbol has no Fn item — pass 2 only walks Fn items.)
        let kind = if is_extern {
            SymbolKind::ExternFn
        } else {
            SymbolKind::Function { body_index: usize::MAX }
        };

        self.module.symbols.push(Symbol {
            name,
            kind,
            exported: exported || is_entry || syscall.is_some(),
            syscall,
            clobbers: if syscall.is_some() { vec![Reg::parse("rcx").unwrap(), Reg::parse("r11").unwrap()] } else { vec![] },
            span,
        });

        if is_entry {
            self.module.entry = Some(sym_idx);
        }
        self.fns.insert(
            sig.name.clone(),
            FnInfo { sym: sym_idx, params, ret, syscall, real_call: false },
        );
    }

    fn param_operand(&self, p: &Param) -> Operand {
        self.place_to_operand_simple(&p.place)
    }

    /// Simplified place → operand for signatures (registers only, really).
    fn place_to_operand_simple(&self, p: &Place) -> Operand {
        match p {
            Place::Reg { reg, .. } => Operand::Reg(*reg),
            Place::Named { name, .. } => {
                // signature places are registers; named would be a bug — Imm 0
                let _ = name;
                Operand::Imm(0)
            }
            Place::Mem { addr, .. } => Operand::Mem(self.raw_addr_to_memop(addr, 64, None)),
            _ => Operand::Imm(0),
        }
    }

    // =====================================================================
    // Pass 2: bodies
    // =====================================================================

    fn lower_bodies(&mut self, file: &File) {
        for item in &file.items {
            if let Item::Fn(f) = item {
                self.lower_fn(f);
            }
        }
    }

    fn lower_fn(&mut self, f: &yana_ast::FnItem) {
        let info = match self.fns.get(&f.sig.name) {
            Some(i) => i.clone(),
            None => return, // dup-symbol already reported
        };
        // fresh per-function state
        let result_regs = ret_result_regs(&f.sig.ret);
        let returns_never = matches!(f.sig.ret, RetSig::Never { .. });
        self.body = FnBody {
            symbol: info.sym,
            insns: Vec::new(),
            label_defs: Vec::new(),
            branches: Vec::new(),
            result_regs,
            returns_never,
        };
        self.labels.clear();
        self.pending_jumps.clear();
        self.scopes.clear();
        self.cur_ret = f.sig.ret.clone();
        self.cur_fn_span = f.span;
        self.push_scope();

        // params become bindings
        for p in &f.sig.params {
            let ty = p.ty().cloned().unwrap_or(Ty::U64);
            let operand = self.param_operand(p);
            self.define(p.name.clone(), Binding { operand, ty, mutable: p.mutable, span: p.span });
        }

        self.lower_block(&f.body);

        // backpatch jumps and record branch uses with scope depths (§6 check
        // lives in the analysis pass: jumping into a nested block is illegal)
        for (idx, name, span, depth) in std::mem::take(&mut self.pending_jumps) {
            match self.labels.get(&name) {
                Some(&def) => {
                    match &mut self.body.insns[idx].insn {
                        Insn::Jmp { label } | Insn::Jcc { label, .. } => *label = def,
                        _ => unreachable!(),
                    }
                    self.body.branches.push(BranchUse { insn: idx, label: def, scope_depth: depth, span });
                }
                None => self.err(
                    "unknown-label",
                    format!("label '{name} is not defined in this function"),
                    span,
                ),
            }
        }

        self.pop_scope();
        if !self.has_errors() {
            let body_index = self.module.bodies.len();
            self.module.bodies.push(std::mem::take(&mut self.body));
            if let SymbolKind::Function { body_index: slot } = &mut self.module.symbols[info.sym].kind {
                *slot = body_index;
            }
        }
    }

    /// Build the brief contract summary for a call site (§14).
    fn call_contract(&self, info: &FnInfo) -> CallContract {
        let results = match &info.ret {
            RetInfo::Single { operand, .. } => match operand {
                Operand::Reg(r) => vec![r.resize(yana_ast::reg::RegSize::R64).unwrap_or(*r)],
                _ => vec![],
            },
            RetInfo::Tuple { parts } => parts
                .iter()
                .filter_map(|p| match &p.operand {
                    Operand::Reg(r) => Some(r.resize(yana_ast::reg::RegSize::R64).unwrap_or(*r)),
                    _ => None,
                })
                .collect(),
            _ => vec![],
        };
        let noreturn = matches!(info.ret, RetInfo::Never);
        // clobbers: externs must declare them (§5.4); we stored declared ones
        // on the Symbol; local fns get derived clobbers after analysis (pass 3)
        // — until then, conservatively: everything the callee's symbol lists.
        let clobbers = self
            .module
            .symbols
            .get(info.sym)
            .map(|s| s.clobbers.clone())
            .unwrap_or_default();
        CallContract { clobbers, results, noreturn, syscall: info.syscall }
    }

    fn has_errors(&self) -> bool {
        self.diagnostics.iter().any(|d| matches!(d.level, yana_ast::DiagLevel::Error))
    }

    fn push_scope(&mut self) {
        self.scopes.push(HashMap::new());
    }
    fn pop_scope(&mut self) {
        self.scopes.pop();
    }
    fn define(&mut self, name: String, b: Binding) {
        if let Some(top) = self.scopes.last_mut() {
            top.insert(name, b);
        }
    }
    fn lookup(&self, name: &str) -> Option<&Binding> {
        self.scopes.iter().rev().find_map(|s| s.get(name))
    }

    fn emit(&mut self, i: Insn) -> usize {
        self.body.insns.push(SpannedInsn::new(i, self.cur_span));
        self.body.insns.len() - 1
    }

    fn lower_block(&mut self, b: &Block) {
        for s in &b.stmts {
            self.lower_stmt(s);
        }
    }

    fn lower_stmt(&mut self, s: &Stmt) {
        self.cur_span = stmt_span(s);
        match s {
            Stmt::Bind { mutable, name, name_span, place, init, pattern, span } => {
                if let Some(pat) = pattern {
                    self.lower_bind_pattern(pat, init.as_ref(), *span);
                    return;
                }
                let name = match name {
                    Some(n) => n.clone(),
                    None => return,
                };
                let ty = place.ty().cloned().unwrap_or(Ty::U64);
                let operand = match self.resolve_place(place) {
                    Some(o) => o,
                    None => return,
                };
                if let Place::Section { .. } = place {
                    self.err("bind-place", "function-local bind cannot target a section", *span);
                    return;
                }
                // duplicate name in same scope?
                if self.scopes.last().map(|s| s.contains_key(&name)).unwrap_or(false) {
                    self.err("dup-bind", format!("`{name}` is already bound in this scope"), *name_span);
                }
                // §3 🟡 two names on one register at once is an error
                if let Operand::Reg(r) = &operand {
                    let conflict = self.scopes.iter().rev().find_map(|scope| {
                        scope.iter().find_map(|(other, b)| {
                            (other != &name && b.operand == Operand::Reg(*r)).then(|| other.clone())
                        })
                    });
                    if let Some(other) = conflict {
                        self.err(
                            "reg-conflict",
                            format!("`{name}` and `{other}` are bound to {} at the same time (§3)", r.name()),
                            *span,
                        );
                    }
                }
                let ty_for_init = ty.clone();
                self.define(name, Binding { operand: operand.clone(), ty, mutable: *mutable, span: *span });
                if let Some(v) = init {
                    // initial write: no `alt` needed (§4.2)
                    self.lower_write(&operand, &ty_for_init, v, *span);
                }
            }
            Stmt::Alt { dst, op, src, modifier, span } => {
                self.lower_alt(dst, *op, src, modifier, *span)
            }
            Stmt::DivMod { results, dividend, divisor, span } => {
                self.lower_divmod(results, dividend, divisor, *span)
            }
            Stmt::Push { items, span } => {
                for it in items {
                    match it {
                        Place::Discard { .. } => {
                            self.emit(Insn::StackSlot { grow: true });
                        }
                        p => {
                            let size = self.place_size(p);
                            if let Some(o) = self.resolve_place(p) {
                                self.emit(Insn::Push { src: o, size });
                            } else {
                                self.err("push-place", "cannot push this place", *span);
                            }
                        }
                    }
                }
            }
            Stmt::Pop { items, span } => {
                for it in items {
                    match it {
                        Place::Discard { .. } => {
                            self.emit(Insn::StackSlot { grow: false });
                        }
                        p => {
                            let size = self.place_size(p);
                            if let Some(o) = self.resolve_place(p) {
                                // pop writes — command instruction, no alt needed (§4.2)
                                self.emit(Insn::Pop { dst: o, size });
                            } else {
                                self.err("pop-place", "cannot pop into this place", *span);
                            }
                        }
                    }
                }
            }
            Stmt::Branch { cond, target, target_span, span } => {
                let idx = match cond {
                    None => self.emit(Insn::Jmp { label: usize::MAX }),
                    Some(BranchCond::Cmp { lhs, op, rhs, .. }) => {
                        let signed = self.cmp_signedness(lhs, rhs);
                        let (a, sa) = match self.resolve_value(lhs) {
                            Some(v) => v,
                            None => return,
                        };
                        let (b, _sb) = match self.resolve_value(rhs) {
                            Some(v) => v,
                            None => return,
                        };
                        let size = sa.max(8);
                        self.emit(Insn::Cmp { a, b, size });
                        let cc = insn::cmp_cc(*op, signed);
                        self.emit(Insn::Jcc { cc, label: usize::MAX })
                    }
                    Some(BranchCond::Flag { flag, negated, .. }) => {
                        let cc = insn::flag_cc(*flag, *negated);
                        self.emit(Insn::Jcc { cc, label: usize::MAX })
                    }
                };
                self.pending_jumps.push((idx, target.clone(), target_span.merge(*span), self.scopes.len() as u32));
            }
            Stmt::Call { results, name, name_span, args, span } => {
                self.lower_call(results, name, *name_span, args, *span);
            }
            Stmt::Return { value, span } => self.lower_return(value, *span),
            Stmt::Syscall { span } => {
                let _ = span;
                self.emit(Insn::Syscall);
            }
            Stmt::Align { align, span } => {
                // §4.3 🟡: `align N;` pads rsp to a multiple of N. The pad
                // depends on the static stack depth, so resolve only records
                // the intent; the stack analysis (§14.3) lowers it.
                if *align == 0 || !align.is_power_of_two() {
                    self.err(
                        "align-power-of-two",
                        format!("`align {align}` — alignment must be a power of two ≥ 1"),
                        *span,
                    );
                    return;
                }
                self.emit(Insn::StackAlign { align: *align as u32 });
            }
            Stmt::Label { name, name_span, body, span } => {
                // §6: label = start of block, fallthrough; visible in enclosing
                // block including its own body → define BEFORE walking body.
                if self.labels.contains_key(name) {
                    self.err("dup-label", format!("label '{name} declared twice in this function"), *name_span);
                } else {
                    let def = self.body.label_defs.len();
                    self.body.label_defs.push(LabelDef {
                        name: name.clone(),
                        at_insn: self.body.insns.len(),
                        scope_depth: self.scopes.len() as u32,
                    });
                    self.labels.insert(name.clone(), def);
                }
                let _ = span;
                self.lower_block(body);
            }
            Stmt::Nested(b) => {
                self.push_scope();
                self.lower_block(b);
                self.pop_scope();
            }
        }
    }

    // ------------------------------------------------------------------
    // alt / writes
    // ------------------------------------------------------------------

    fn lower_alt(&mut self, dst: &Place, op: AssignOp, src: &Value, modifier: &AltModifier, span: Span) {
        // §12 modifiers take their own lowering path (the atomic path applies
        // the mut/alt contract itself, and additionally admits static-bound
        // names — those are anonymous memory, not bindings).
        match modifier {
            AltModifier::None => {}
            AltModifier::Atomic(order) => {
                return self.lower_atomic(dst, op, src, *order, span);
            }
            AltModifier::Volatile => {
                return self.lower_volatile(dst, op, src, span);
            }
        }
        // `alt` targets: named bindings (must be mut), registers, memory.
        if let Place::Named { name, .. } = dst {
            match self.lookup(name) {
                Some(b) if !b.mutable => {
                    self.err(
                        "immutable-write",
                        format!("cannot write to `{name}`: binding is not `mut` (§4.2)"),
                        span,
                    );
                    return;
                }
                None => {
                    self.err("unknown-name", format!("`{name}` is not bound here"), span);
                    return;
                }
                _ => {}
            }
        }
        let operand = match self.resolve_place(dst) {
            Some(o) => o,
            None => return,
        };
        let ty = self.place_ty(dst);

        // §4.5 special form: `alt rdx:rax = <lo> as u128;` is the pair-extend
        // idiom — zero/sign-extend the low half into the high half. It is NOT
        // a movzx into a single register.
        if let Place::RegPair { hi, lo, ty: pty, .. } = dst {
            if let Value::Cast { value, ty: cast_ty, span: cspan } = src {
                if matches!(cast_ty, Ty::U128 | Ty::I128) {
                    if !(hi.name() == "rdx" && lo.name() == "rax")
                        && !(hi.name() == "edx" && lo.name() == "eax")
                    {
                        self.err(
                            "pair-order",
                            "128-bit pair extension requires the hardware order `rdx:rax`/`edx:eax` (§4.5)",
                            *cspan,
                        );
                        return;
                    }
                    if !matches!(value.as_ref(), Value::Place(Place::Reg { reg, .. }) if reg.name() == lo.name()) {
                        self.warn(
                            DiagCode::Contract,
                            "extend-src",
                            format!("pair extension source should be `{}` (the low half, §4.5)", lo.name()),
                            *cspan,
                        );
                    }
                    let signed = matches!(cast_ty, Ty::I128) || pty.as_ref().map(|t| t.is_signed()).unwrap_or(false);
                    let size = if lo.name() == "eax" { 32 } else { 64 };
                    self.emit(Insn::ExtendPair { signed, size });
                    return;
                }
            }
        }

        let size = ty_bits(&ty, &self.target) as u32;

        // Assign handles mov / lea / wide-mul / casts; compound ops are the
        // read-modify-write family (§4.1) — one instruction each.
        if op == AssignOp::Assign {
            self.lower_write(&operand, &ty, src, span);
            return;
        }
        let (sop, _ssize) = match self.resolve_value(src) {
            Some(v) => v,
            None => return,
        };
        let insn = match op {
            AssignOp::Add => Insn::Add { dst: operand, src: sop, size },
            AssignOp::Sub => Insn::Sub { dst: operand, src: sop, size },
            AssignOp::Xor => Insn::Xor { dst: operand, src: sop, size },
            AssignOp::And => Insn::And { dst: operand, src: sop, size },
            AssignOp::Or => Insn::Or { dst: operand, src: sop, size },
            AssignOp::Shl => Insn::Shl { dst: operand, src: sop, size },
            AssignOp::Shr => Insn::Shr { dst: operand, src: sop, size },
            AssignOp::Mul => Insn::Imul2 { dst: operand, src: sop, size },
            AssignOp::Assign => unreachable!(),
        };
        self.emit(insn);
    }

    // ------------------------------------------------------------------
    // §12: atomic / volatile
    // ------------------------------------------------------------------

    /// `alt atomic(order) dst <op>= src;` → one locked x86 instruction.
    ///
    /// Contracts (§12, binding decisions):
    /// - dst MUST be memory: `@[...]` or a name bound to a static (anonymous
    ///   memory). A register/pair destination is `atomic-register`.
    /// - src MUST be a register or immediate; a memory source is
    ///   `atomic-src-memory` (no hidden temporaries, §0).
    /// - `=` (Exchange) needs a register source: `xchg` has no imm form →
    ///   `atomic-assign-imm`.
    /// - Non-x86-64 target: `unsupported-atomic-target` (owner 30.10).
    fn lower_atomic(&mut self, dst: &Place, op: AssignOp, src: &Value, order: yana_ast::AtomicOrder, span: Span) {
        use crate::target::Arch;
        if self.target.arch != Arch::X86_64 {
            self.err(
                "unsupported-atomic-target",
                "atomic(...) is not supported on this target (§15, решение 30.10)",
                span,
            );
            return;
        }
        // mut/alt contract (§4.2): a bound name must be a mut binding; a
        // static-bound name is anonymous memory and always writable.
        if let Place::Named { name, .. } = dst {
            if let Some(b) = self.lookup(name) {
                if !b.mutable {
                    self.err(
                        "immutable-write",
                        format!("cannot write to `{name}`: binding is not `mut` (§4.2)"),
                        span,
                    );
                    return;
                }
            }
        }
        let aop = match op {
            AssignOp::Assign => AtomicOp::Exchange,
            AssignOp::Add => AtomicOp::Add,
            AssignOp::Sub => AtomicOp::Sub,
            AssignOp::And => AtomicOp::And,
            AssignOp::Or => AtomicOp::Or,
            AssignOp::Xor => AtomicOp::Xor,
            _ => {
                self.err(
                    "atomic-op",
                    format!("`{op:?}` has no one-instruction atomic form (§12: = + - & | ^ only)"),
                    span,
                );
                return;
            }
        };
        // dst must be memory: `@[...]`, or a name bound to a static (anonymous
        // memory). Registers/pairs → atomic-register.
        let dst_op = match self.resolve_place(dst) {
            Some(o) => o,
            None => return,
        };
        let dst_op = match dst_op {
            Operand::Mem(m) => Operand::Mem(m),
            // static-bound name: symbolic address → [sym] memory operand
            Operand::Sym { sym, add } => Operand::Mem(MemOp {
                base: None,
                index: None,
                scale: 1,
                disp: Displacement::Sym { sym, add },
                size: ty_bits(&self.place_ty(dst), &self.target) as u32,
                rip_relative: true,
            }),
            _ => {
                self.err(
                    "atomic-register",
                    "atomic target must be memory — x86 lock needs a memory operand (§12)",
                    span,
                );
                return;
            }
        };
        // src: register or immediate
        let (src_op, _) = match self.resolve_value(src) {
            Some(v) => v,
            None => return,
        };
        match &src_op {
            Operand::Mem(_) | Operand::Sym { .. } => {
                self.err_help(
                    "atomic-src-memory",
                    "atomic source must be a register or immediate, not memory (§12)",
                    "load it into a register first",
                    span,
                );
                return;
            }
            Operand::Imm(_) if aop == AtomicOp::Exchange => {
                self.err_help(
                    "atomic-assign-imm",
                    "atomic `=` lowers to `xchg` which needs a register source (§12)",
                    "xchg needs a register source: bind the value first",
                    span,
                );
                return;
            }
            _ => {}
        }
        let size = ty_bits(&self.place_ty(dst), &self.target) as u32;
        let mo = match order {
            yana_ast::AtomicOrder::Relaxed => MemOrder::Relaxed,
            yana_ast::AtomicOrder::Acquire => MemOrder::Acquire,
            yana_ast::AtomicOrder::Release => MemOrder::Release,
            yana_ast::AtomicOrder::AcqRel => MemOrder::AcqRel,
            yana_ast::AtomicOrder::SeqCst => MemOrder::SeqCst,
        };
        self.emit(Insn::AtomicRMW { op: aop, dst: dst_op, src: src_op, size, order: mo });
    }

    /// `alt volatile dst <op>= src;` → the normal one-instruction lowering,
    /// wrapped in [`Insn::Volatile`] so no analysis may elide it.
    fn lower_volatile(&mut self, dst: &Place, op: AssignOp, src: &Value, span: Span) {
        // plain alt contract first: mut / known name
        if let Place::Named { name, .. } = dst {
            match self.lookup(name) {
                Some(b) if !b.mutable => {
                    self.err(
                        "immutable-write",
                        format!("cannot write to `{name}`: binding is not `mut` (§4.2)"),
                        span,
                    );
                    return;
                }
                None => {
                    self.err("unknown-name", format!("`{name}` is not bound here"), span);
                    return;
                }
                _ => {}
            }
        }
        // lower as a plain alt, then wrap whatever instruction it emitted
        let before = self.body.insns.len();
        self.lower_alt(dst, op, src, &AltModifier::None, span);
        for si in &mut self.body.insns[before..] {
            if !matches!(si.insn, Insn::Volatile(_)) {
                si.insn = Insn::Volatile(Box::new(std::mem::replace(&mut si.insn, Insn::Nop)));
            }
        }
    }

    /// Emit the instruction(s) writing `src` into `dst` with `op`.
    fn lower_write(&mut self, dst: &Operand, ty: &Ty, src: &Value, span: Span) {
        let size = ty_bits(ty, &self.target);
        match src {
            Value::Mul { lhs, rhs, span: mspan } => {
                // wide multiply (§4.5): dst must be the hardware pair low half
                let want_lo = if size == 32 { "eax" } else { "rax" };
                let ok = matches!(dst, Operand::Reg(r) if r.name() == want_lo);
                if !ok {
                    self.err(
                        "wide-mul",
                        format!("wide multiply requires the pair destination `{}` (§4.5); got a different place", want_lo.replace("eax", "edx:eax").replace("rax", "rdx:rax")),
                        *mspan,
                    );
                    return;
                }
                // lhs should be the low half (spec: `rdx:rax = rax * x`)
                if let Value::Place(Place::Reg { reg, .. }) = lhs.as_ref() {
                    if reg.name() != want_lo {
                        self.warn(
                            DiagCode::Contract,
                            "wide-mul-src",
                            format!("wide multiply source should be `{want_lo}` (the implicit hardware operand, §4.5)"),
                            *mspan,
                        );
                    }
                }
                let signed = ty.is_signed();
                let (rop, _rs) = match self.resolve_value(rhs) {
                    Some(v) => v,
                    None => return,
                };
                self.emit(Insn::MulWide { src: rop, signed, size });
                return;
            }
            _ => {}
        }
        let (sop, ssize) = match self.resolve_value(src) {
            Some(v) => v,
            None => return,
        };
        // mov family
        match src {
            Value::Cast { value, ty: cast_ty, span: cspan } => {
                let cast_bits = ty_bits(cast_ty, &self.target);
                let inner_is_signed = self.value_signedness(value);
                if cast_bits > size {
                    // widening: needs movzx/movsx into a register dst
                    match dst {
                        Operand::Reg(r) => {
                            let (iop, _) = match self.resolve_value(value) {
                                Some(v) => v,
                                None => return,
                            };
                            let ext = if inner_is_signed {
                                Insn::Movsx { dst: *r, src: iop, src_size: size, dst_size: cast_bits }
                            } else {
                                Insn::Movzx { dst: *r, src: iop, src_size: size, dst_size: cast_bits }
                            };
                            self.emit(ext);
                            let _ = cspan;
                            return;
                        }
                        _ => {
                            self.err(
                                "cast-dst",
                                "widening cast needs a register destination",
                                span,
                            );
                            return;
                        }
                    }
                }
                // narrowing/equal: operand already resized by resolve_value
            }
            Value::AddrOf { place, span: aspan } => {
                // lea
                if let Operand::Reg(r) = dst {
                    let r = *r;
                    match self.lea_source(place) {
                        Some(LeaSrc::Mem(m)) => { self.emit(Insn::Lea { dst: r, addr: m }); }
                        Some(LeaSrc::Sym { sym, add }) => { self.emit(Insn::LeaSym { dst: r, sym, add }); }
                        None => {
                            self.err("lea-src", "cannot take the address of this place", *aspan);
                            return;
                        }
                    }
                } else {
                    self.err("lea-dst", "`&` requires a register destination", span);
                    return;
                }
                return;
            }
            _ => {}
        }
        // skip trivial self-mov? keep it — visible expansion (§0)
        if matches!((&sop, dst), (Operand::Reg(a), Operand::Reg(b)) if a == b) {
            // mov rax, rax — legal, keep (assembler oracle compares equally)
        }
        self.emit(Insn::Mov { dst: dst.clone(), src: sop, size: size as u32 });
    }

    // ------------------------------------------------------------------
    // div/mod (§4.5)
    // ------------------------------------------------------------------

    fn lower_divmod(&mut self, results: &[Place], dividend: &Place, divisor: &Value, span: Span) {
        if results.len() != 2 {
            self.err("divmod", "`/%` destructures into exactly two places (quotient, remainder)", span);
            return;
        }
        // dividend must be the hw pair rdx:rax (or edx:eax)
        let (pair_ok, signed, size) = match dividend {
            Place::RegPair { hi, lo, ty, .. } => {
                let s = ty.as_ref().map(|t| t.is_signed()).unwrap_or(false);
                let bits = ty.as_ref().map(|t| ty_bits(t, &self.target)).unwrap_or(128);
                let half = bits / 2;
                let ok = (hi.name() == "rdx" && lo.name() == "rax" && half == 64)
                    || (hi.name() == "edx" && lo.name() == "eax" && half == 32);
                (ok, s, half)
            }
            _ => (false, false, 64),
        };
        if !pair_ok {
            self.err(
                "divmod-pair",
                "`/%` dividend must be the explicit hardware pair `rdx:rax` (or `edx:eax`) (§4.5)",
                span,
            );
            return;
        }
        // constant zero divisor → error (§4.5)
        if let Value::Imm { value: 0, span: vspan } = divisor {
            self.err("div-zero", "division by constant zero (§4.5: compile error)", *vspan);
            return;
        }
        let (dop, _ds) = match self.resolve_value(divisor) {
            Some(v) => v,
            None => return,
        };
        self.emit(Insn::DivWide {
            src: dop,
            op: if signed { WideOp::Signed } else { WideOp::Unsigned },
            size,
        });
        // results: (quot, rem) — spec form `alt (rax, rdx) = ...` means rax=quot, rdx=rem,
        // which is exactly where the hardware already leaves them; verify the
        // places match and emit redundant/contract diagnostics (§5.2 style).
        let quot = self.resolve_place(&results[0]);
        let rem = self.resolve_place(&results[1]);
        let rax = Reg::parse("rax").unwrap();
        let rdx = Reg::parse("rdx").unwrap();
        if let (Some(Operand::Reg(q)), Some(Operand::Reg(r))) = (&quot, &rem) {
            if *q != rax || *r != rdx {
                self.warn(
                    DiagCode::Contract,
                    "divmod-order",
                    format!(
                        "results ({}, {}) are not the hardware order (rax=quotient, rdx=remainder); values will be swapped",
                        q.name(),
                        r.name()
                    ),
                    span,
                );
                // emit xchgs to honor written order
                self.emit(Insn::Xchg { a: Operand::Reg(*q), b: Operand::Reg(rax), size: 64 });
                self.emit(Insn::Xchg { a: Operand::Reg(*r), b: Operand::Reg(rdx), size: 64 });
            }
        }
    }

    // ------------------------------------------------------------------
    // calls (§5.3, §5.5)
    // ------------------------------------------------------------------

    fn lower_call(
        &mut self,
        results: &Option<CallResults>,
        name: &str,
        name_span: Span,
        args: &[CallArg],
        span: Span,
    ) {
        let info = match self.fns.get(name) {
            Some(i) => i.clone(),
            None => {
                self.err("unknown-call", format!("no function or extern named `{name}`"), name_span);
                return;
            }
        };

        // map args to params (named or positional)
        let mut slots: Vec<Option<&CallArg>> = vec![None; info.params.len()];
        let mut positional = 0usize;
        for a in args {
            match &a.param {
                Some(pname) => match info.params.iter().position(|p| p.name == *pname) {
                    Some(i) => slots[i] = Some(a),
                    None => self.err(
                        "unknown-param",
                        format!("`{name}` has no parameter `{pname}`"),
                        a.span,
                    ),
                },
                None => {
                    if positional < slots.len() {
                        slots[positional] = Some(a);
                    } else {
                        self.err("extra-arg", format!("too many arguments for `{name}`"), a.span);
                    }
                    positional += 1;
                }
            }
        }

        // emit argument movs
        for (p, slot) in info.params.iter().zip(slots.iter()) {
            let Some(a) = slot else { continue };
            // explicit place assertion: `{ n: v @ rdi }`
            if let Some(at) = &a.at {
                let at_op = self.resolve_place(at);
                if at_op == Some(p.operand.clone()) {
                    // value already where the ABI wants it: no mov (§5.3)
                    continue;
                }
                if let Some((vo, _)) = self.resolve_value(&a.value) {
                    let size = ty_bits(&p.ty, &self.target) as u32;
                    self.emit(Insn::Mov { dst: p.operand.clone(), src: vo, size });
                }
                continue;
            }
            match &a.value {
                Value::AddrOf { place, .. } => {
                    if let Operand::Reg(r) = p.operand {
                        match self.lea_source(place) {
                            Some(LeaSrc::Sym { sym, add }) => {
                                self.emit(Insn::LeaSym { dst: r, sym, add });
                            }
                            Some(LeaSrc::Mem(m)) => {
                                self.emit(Insn::Lea { dst: r, addr: m });
                            }
                            None => self.err("lea-src", "cannot take this address", a.span),
                        }
                    } else {
                        self.err("abi-place", "address arguments need a register parameter", a.span);
                    }
                }
                v => {
                    let (op, _) = match self.resolve_value(v) {
                        Some(x) => x,
                        None => continue,
                    };
                    let size = ty_bits(&p.ty, &self.target) as u32;
                    self.emit(Insn::Mov { dst: p.operand.clone(), src: op, size });
                }
            }
        }

        // the call itself
        if let Some(num) = info.syscall {
            // Linux x86-64 syscall ABI (§5.5): number in rax
            self.emit(Insn::Mov {
                dst: Operand::Reg(Reg::parse("rax").unwrap()),
                src: Operand::Imm(num),
                size: 64,
            });
            self.emit(Insn::Syscall);
        } else {
            let contract = self.call_contract(&info);
            self.emit(Insn::Call { sym: info.sym, contract });
        }

        // results (§5.3)
        if let Some(res) = results {
            self.bind_results(res, &info, span);
        }
    }

    fn bind_results(&mut self, res: &CallResults, info: &FnInfo, span: Span) {
        match (res, &info.ret) {
            (CallResults::Single { name: Some(n), .. }, RetInfo::Single { operand, ty }) => {
                self.define(
                    n.clone(),
                    Binding { operand: operand.clone(), ty: ty.clone(), mutable: false, span },
                );
            }
            (CallResults::Single { name: Some(n), .. }, RetInfo::None) => {
                self.warn(
                    DiagCode::Contract,
                    "no-result",
                    format!("callee returns nothing; binding `{n}` will be unresolvable"),
                    span,
                );
            }
            (CallResults::Single { name: None, .. }, _) => {} // discard
            (CallResults::Tuple { names, .. }, RetInfo::Tuple { parts }) => {
                for (name, part) in names.iter().zip(parts) {
                    if let Some(n) = name {
                        self.define(
                            n.clone(),
                            Binding {
                                operand: part.operand.clone(),
                                ty: part.ty.clone(),
                                mutable: false,
                                span,
                            },
                        );
                    }
                }
            }
            _ => {}
        }
    }

    // ------------------------------------------------------------------
    // return (§5.2)
    // ------------------------------------------------------------------

    fn lower_return(&mut self, value: &Option<Value>, span: Span) {
        match (&self.cur_ret.clone(), value) {
            (RetSig::Never { .. }, _) | (RetSig::None, None) => {
                // fall through to Ret
            }
            (RetSig::None, Some(_)) => {
                self.err("return-value", "function returns nothing but `return` has a value", span);
                return;
            }
            (RetSig::Single { place, .. }, Some(v)) => {
                // `return <place>;` asserts where the result is (§5.2)
                if let Value::Place(p) = v {
                    if same_place(place, p) {
                        self.warn(
                            DiagCode::Redundant,
                            "redundant",
                            "return place matches the signature (redundant); plain `return;` says the same",
                            span,
                        );
                    } else {
                        self.warn(
                            DiagCode::Contract,
                            "contract",
                            "return place does not match the signature",
                            span,
                        );
                        if self.opts.strict {
                            // escalated by is_fatal; also mark error level here
                            let last = self.diagnostics.last_mut().unwrap();
                            last.level = yana_ast::DiagLevel::Error;
                        }
                    }
                } else {
                    // `return <const>;` → write into the result place (§5.2 🟡)
                    let op = self.place_to_operand_simple(place);
                    let ty = place.ty().cloned().unwrap_or(Ty::U64);
                    self.lower_write(&op, &ty, v, span);
                }
            }
            (RetSig::Single { .. }, None) => {}
            (RetSig::Tuple { .. }, Some(_)) => {
                self.err("return-tuple", "tuple results are already in their places; use plain `return;`", span);
                return;
            }
            (RetSig::Tuple { .. }, None) => {}
        }
        if !matches!(self.cur_ret, RetSig::Never { .. }) {
            self.emit(Insn::Ret);
        } else {
            // `-> !` — exit path; emit nothing after (e.g. exit syscall did it)
            self.emit(Insn::Ret);
        }
    }

    // ------------------------------------------------------------------
    // places & values
    // ------------------------------------------------------------------

    fn place_size(&self, p: &Place) -> u32 {
        match p {
            Place::Reg { reg, .. } => reg.size().bits(),
            Place::RegPair { .. } => 128,
            Place::Mem { ty: Some(t), .. } => ty_bits(t, &self.target),
            Place::Mem { ty: None, .. } => 64,
            Place::Named { name, .. } => self
                .lookup(name)
                .map(|b| b.size_bits(&self.target))
                .unwrap_or(64),
            Place::Section { .. } | Place::Discard { .. } => 64,
        }
    }

    fn place_ty(&self, p: &Place) -> Ty {
        match p {
            Place::Named { name, .. } => self
                .lookup(name)
                .map(|b| b.ty.clone())
                .unwrap_or(Ty::U64),
            other => other.ty().cloned().unwrap_or_else(|| match other {
                Place::Reg { reg, .. } => reg_size_ty(reg),
                _ => Ty::U64,
            }),
        }
    }

    /// Resolve a place to an operand (register / memory / static symbol).
    fn resolve_place(&mut self, p: &Place) -> Option<Operand> {
        match p {
            Place::Reg { reg, .. } => Some(Operand::Reg(*reg)),
            Place::RegPair { hi, lo, .. } => {
                // pairs appear only in wide-op positions; represent as the low
                // register and let the consumer (MulWide/DivWide) check
                self.pair_operand(hi, lo, p.span())
            }
            Place::Mem { addr, ty, .. } => {
                let size = ty.as_ref().map(|t| ty_bits(t, &self.target)).unwrap_or(64);
                Some(Operand::Mem(self.resolve_addr(addr, size)))
            }
            Place::Named { name, span, .. } => {
                if let Some(b) = self.lookup(name) {
                    return Some(b.operand.clone());
                }
                if let Some(s) = self.statics.get(name) {
                    return Some(Operand::Sym { sym: s.sym, add: 0 });
                }
                if let Some(v) = self.consts.get(name) {
                    return Some(Operand::Imm(*v as i64));
                }
                self.err("unknown-name", format!("`{name}` is not bound here"), *span);
                None
            }
            Place::Section { span, .. } => {
                self.err("section-place", "a section is not an operand", *span);
                None
            }
            Place::Discard { span } => {
                self.err("discard-place", "`_` cannot be read", *span);
                None
            }
        }
    }

    fn pair_operand(&mut self, hi: &Reg, lo: &Reg, span: Span) -> Option<Operand> {
        let ok64 = hi.name() == "rdx" && lo.name() == "rax";
        let ok32 = hi.name() == "edx" && lo.name() == "eax";
        if !(ok64 || ok32) {
            self.err(
                "pair-order",
                format!("register pair must be hardware order `rdx:rax` or `edx:eax`, got `{}:{}`", hi.name(), lo.name()),
                span,
            );
            return None;
        }
        Some(Operand::Reg(*lo))
    }

    fn resolve_addr(&mut self, raw: &RawAddr, size: u32) -> MemOp {
        let mut base: Option<Reg> = None;
        let mut index: Option<Reg> = None;
        let mut scale: u8 = 1;
        let mut disp_const: i64 = 0;
        let mut disp_sym: Option<(usize, i64)> = None;

        for term in &raw.terms {
            match term {
                MemTerm::Reg(r) => {
                    if base.is_none() && index.is_none() {
                        base = Some(*r);
                    } else if base.is_some() && index.is_none() {
                        index = Some(*r);
                    } else {
                        self.err("mem-form", "too many register terms in address (x86 allows base+index)", raw.span);
                    }
                }
                MemTerm::RegScaled { reg, scale: s } => {
                    if index.is_some() {
                        self.err("mem-form", "address has two scaled terms", raw.span);
                    }
                    index = Some(*reg);
                    scale = *s;
                }
                MemTerm::NameScaled { name, scale: s } => {
                    match self.lookup(name).map(|b| b.operand.clone()) {
                        Some(Operand::Reg(r)) => {
                            index = Some(r);
                            scale = *s;
                        }
                        _ => self.err(
                            "mem-name",
                            format!("`{name}` in a scaled address term must be bound to a register"),
                            raw.span,
                        ),
                    }
                }
                MemTerm::Name(name) => {
                    // binding → base register, or static → symbol displacement
                    if let Some(b) = self.lookup(name) {
                        match &b.operand {
                            Operand::Reg(r) => {
                                if base.is_none() {
                                    base = Some(*r);
                                } else if index.is_none() {
                                    index = Some(*r);
                                } else {
                                    self.err("mem-form", "too many register terms", raw.span);
                                }
                            }
                            other => {
                                self.err(
                                    "mem-name",
                                    format!("`{name}` does not resolve to a register base ({other:?})"),
                                    raw.span,
                                );
                            }
                        }
                    } else if self.statics.contains_key(name) {
                        if disp_sym.is_some() {
                            self.err("mem-form", "two symbols in one address", raw.span);
                        }
                        let s = self.statics[name].clone();
                        disp_sym = Some((s.sym, s.offset as i64));
                    } else if let Some(v) = self.consts.get(name) {
                        disp_const += *v as i64;
                    } else {
                        self.err("unknown-name", format!("`{name}` is not bound here"), raw.span);
                    }
                }
                MemTerm::Const(c) => disp_const += *c,
            }
        }

        let disp = match disp_sym {
            Some((sym, add)) => Displacement::Sym { sym, add: add + disp_const },
            None => Displacement::Const(disp_const),
        };
        let rip_relative = base == Some(Reg::Rip)
            || (matches!(disp, Displacement::Sym { .. }) && base.is_none() && index.is_none());
        MemOp { base, index, scale, disp, size, rip_relative }
    }

    /// `[addr]` without semantic resolution, for signatures.
    fn raw_addr_to_memop(&self, raw: &RawAddr, size: u32, _ty: Option<&Ty>) -> MemOp {
        let mut base = None;
        let mut index = None;
        let mut scale = 1;
        let mut disp_const = 0i64;
        for term in &raw.terms {
            match term {
                MemTerm::Reg(r) => {
                    if base.is_none() {
                        base = Some(*r);
                    } else {
                        index = Some(*r);
                    }
                }
                MemTerm::RegScaled { reg, scale: s } => {
                    index = Some(*reg);
                    scale = *s;
                }
                MemTerm::Const(c) => disp_const += *c,
                _ => {}
            }
        }
        MemOp {
            base,
            index,
            scale,
            disp: Displacement::Const(disp_const),
            size,
            rip_relative: base == Some(Reg::Rip),
        }
    }

    /// Resolve a value to (operand, size_bits).
    fn resolve_value(&mut self, v: &Value) -> Option<(Operand, u32)> {
        match v {
            Value::Place(p) => {
                let size = self.place_size(p);
                self.resolve_place(p).map(|o| (o, size))
            }
            Value::Imm { value, .. } => Some((Operand::Imm(*value as i64), 64)),
            Value::Str { span, .. } => {
                self.err(
                    "str-value",
                    "string literals live in static data; bind it to .rodata first (§7)",
                    *span,
                );
                None
            }
            Value::AddrOf { .. } => {
                // handled by lower_write/lea paths; as a plain value it's an
                // address-sized immediate only for statics — resolve here too
                None
            }
            Value::Cast { value, ty, span } => {
                let target_bits = ty_bits(ty, &self.target);
                match value.as_ref() {
                    Value::Place(Place::Reg { reg, .. }) => {
                        match reg.resize(reg_size_from_bits(target_bits)) {
                            Some(r) => Some((Operand::Reg(r), target_bits)),
                            None => {
                                self.err("cast", format!("cannot resize {} to {target_bits} bits", reg.name()), *span);
                                None
                            }
                        }
                    }
                    Value::Imm { value: i, .. } => Some((Operand::Imm(trunc_imm(*i, target_bits)), target_bits)),
                    Value::Place(p) => {
                        let op = self.resolve_place(p)?;
                        Some((op, target_bits))
                    }
                    other => {
                        let (op, _) = self.resolve_value(other)?;
                        Some((op, target_bits))
                    }
                }
            }
            Value::Mul { span, .. } => {
                self.err("wide-mul", "`a * b` is only valid as `alt rdx:rax = lo * x;` (§4.5)", *span);
                None
            }
            Value::Field { base, name, span } => {
                if name != "len" {
                    self.err("field", format!("unknown field `.{name}` (§7: only .len for now)"), *span);
                    return None;
                }
                match base.as_ref() {
                    Value::Place(Place::Named { name: bname, .. }) => {
                        match self.statics.get(bname.as_str()) {
                            Some(s) => Some((Operand::Imm(s.size as i64), 64)),
                            None => {
                                self.err("field", format!("`{bname}` is not static data; .len needs a static binding"), *span);
                                None
                            }
                        }
                    }
                    _ => {
                        self.err("field", ".len needs a static data binding", *span);
                        None
                    }
                }
            }
            Value::Const { expr, .. } => match self.eval_const_expr(expr) {
                Ok(v) => match v {
                    CValue::Int(i) => Some((Operand::Imm(i as i64), 64)),
                    CValue::Bool(b) => Some((Operand::Imm(b as i64), 64)),
                    other => {
                        self.err("const-value", format!("const value {other:?} is not a scalar operand"), expr_span(expr));
                        None
                    }
                },
                Err(d) => {
                    self.diagnostics.push(d);
                    None
                }
            },
        }
    }

    fn lea_source(&mut self, place: &Box<Place>) -> Option<LeaSrc> {
        match place.as_ref() {
            Place::Named { name, span, .. } => {
                if let Some(s) = self.statics.get(name.as_str()) {
                    return Some(LeaSrc::Sym { sym: s.sym, add: 0 });
                }
                if let Some(b) = self.lookup(name) {
                    match &b.operand {
                        Operand::Mem(m) => return Some(LeaSrc::Mem(m.clone())),
                        _ => {}
                    }
                }
                self.err("unknown-name", format!("`{name}` is not bound here"), *span);
                None
            }
            Place::Mem { addr, .. } => Some(LeaSrc::Mem(self.resolve_addr(addr, 64))),
            Place::Section { span, .. } => {
                self.err("lea-section", "cannot take the address of a section", *span);
                None
            }
            _ => None,
        }
    }

    fn cmp_signedness(&self, lhs: &Value, rhs: &Value) -> bool {
        // §4.4: signedness from the type. Use the left operand's binding type.
        if let Value::Place(p) = lhs {
            if let Place::Named { name, .. } = p {
                if let Some(b) = self.lookup(name) {
                    return b.ty.is_signed();
                }
            }
            if let Some(t) = p.ty() {
                return t.is_signed();
            }
        }
        if let Value::Place(p) = rhs {
            if let Place::Named { name, .. } = p {
                if let Some(b) = self.lookup(name) {
                    return b.ty.is_signed();
                }
            }
        }
        false
    }

    fn value_signedness(&self, v: &Value) -> bool {
        match v {
            Value::Place(p) => self.place_ty(p).is_signed(),
            Value::Cast { ty, .. } => ty.is_signed(),
            _ => false,
        }
    }

    fn lower_bind_pattern(&mut self, pat: &[Param], init: Option<&Value>, span: Span) {
        let Some(init) = init else {
            self.err("bind-init", "destructuring bind needs an initializer", span);
            return;
        };
        // MVP: `bind (q @ rax, r @ rdx) = const { ... }` — tuple const results
        match init {
            Value::Const { expr, .. } => match self.eval_const_expr(expr) {
                Ok(CValue::Tuple(items)) => {
                    if items.len() != pat.len() {
                        self.err(
                            "bind-pattern",
                            format!("pattern has {} places but the tuple has {}", pat.len(), items.len()),
                            span,
                        );
                        return;
                    }
                    for (p, v) in pat.iter().zip(items) {
                        let op = self.param_operand(p);
                        let ty = p.ty().cloned().unwrap_or(Ty::U64);
                        let imm = Operand::Imm(v.as_int().unwrap_or(0) as i64);
                        let size = ty_bits(&ty, &self.target) as u32;
                        self.emit(Insn::Mov { dst: op, src: imm, size });
                        self.define(
                            p.name.clone(),
                            Binding {
                                operand: self.param_operand(p),
                                ty,
                                mutable: p.mutable,
                                span: p.span,
                            },
                        );
                    }
                }
                Ok(_) => self.err("bind-pattern", "destructuring bind needs a tuple value", span),
                Err(d) => self.diagnostics.push(d),
            },
            other => self.err(
                "bind-pattern",
                format!("unsupported destructuring source ({:?})", init_kind_name(other)),
                span,
            ),
        }
    }
}

enum LeaSrc {
    Mem(MemOp),
    Sym { sym: usize, add: i64 },
}

fn stmt_span(s: &Stmt) -> Span {
    match s {
        Stmt::Bind { span, .. }
        | Stmt::Alt { span, .. }
        | Stmt::DivMod { span, .. }
        | Stmt::Push { span, .. }
        | Stmt::Pop { span, .. }
        | Stmt::Align { span, .. }
        | Stmt::Branch { span, .. }
        | Stmt::Call { span, .. }
        | Stmt::Return { span, .. }
        | Stmt::Syscall { span, .. }
        | Stmt::Label { span, .. } => *span,
        Stmt::Nested(b) => b.span,
    }
}

/// Result registers (normalized to 64-bit) declared by a return signature
/// (§5.1). `-> ()` and `-> !` yield none.
fn ret_result_regs(ret: &RetSig) -> Vec<Reg> {
    use yana_ast::reg::RegSize;
    fn norm(r: &Reg) -> Reg {
        r.resize(RegSize::R64).unwrap_or(*r)
    }
    match ret {
        RetSig::None | RetSig::Never { .. } => Vec::new(),
        RetSig::Single { place, .. } => match place {
            Place::Reg { reg, .. } => vec![norm(reg)],
            Place::RegPair { hi, lo, .. } => vec![norm(hi), norm(lo)],
            _ => Vec::new(),
        },
        RetSig::Tuple { parts, .. } => parts
            .iter()
            .filter_map(|p| match &p.place {
                Place::Reg { reg, .. } => Some(norm(reg)),
                _ => None,
            })
            .collect(),
    }
}

/// Compare two places ignoring type annotations (a signature place carries
/// `: u64`; a bare `return rax;` does not — but they are the same place, §5.2).
fn same_place(a: &Place, b: &Place) -> bool {
    match (a, b) {
        (Place::Reg { reg: r1, .. }, Place::Reg { reg: r2, .. }) => r1 == r2,
        (Place::RegPair { hi: h1, lo: l1, .. }, Place::RegPair { hi: h2, lo: l2, .. }) => h1 == h2 && l1 == l2,
        (Place::Named { name: n1, .. }, Place::Named { name: n2, .. }) => n1 == n2,
        (Place::Section { kind: k1, .. }, Place::Section { kind: k2, .. }) => k1 == k2,
        (Place::Discard { .. }, Place::Discard { .. }) => true,
        (Place::Mem { addr: a1, .. }, Place::Mem { addr: a2, .. }) => a1 == a2,
        _ => false,
    }
}

fn reg_size_ty(r: &Reg) -> Ty {
    use yana_ast::reg::RegSize;
    match r.size() {
        RegSize::R8 => Ty::U8,
        RegSize::R16 => Ty::U16,
        RegSize::R32 => Ty::U32,
        RegSize::R64 => Ty::U64,
    }
}

fn reg_size_from_bits(bits: u32) -> yana_ast::reg::RegSize {
    use yana_ast::reg::RegSize;
    match bits {
        8 => RegSize::R8,
        16 => RegSize::R16,
        32 => RegSize::R32,
        _ => RegSize::R64,
    }
}

fn trunc_imm(v: i128, bits: u32) -> i64 {
    if bits >= 64 {
        v as i64
    } else {
        let mask = (1i128 << bits) - 1;
        (v & mask) as i64
    }
}

fn imm_fits(v: i128, bits: u32, signed: bool) -> bool {
    if bits >= 128 {
        return true;
    }
    if signed {
        let min = -(1i128 << (bits - 1));
        let max = (1i128 << (bits - 1)) - 1;
        v >= min && v <= max
    } else {
        v >= 0 && v < (1i128 << bits)
    }
}

fn imm_to_bytes(v: i128, ty: &Ty, target: &TargetInfo) -> Vec<u8> {
    let w = (ty_bits(ty, target) / 8).max(1) as usize;
    (v.to_le_bytes()[..w.min(16)]).to_vec()
}

fn init_kind_name(v: &Value) -> &'static str {
    match v {
        Value::Place(_) => "place",
        Value::Imm { .. } => "immediate",
        Value::Str { .. } => "string",
        Value::AddrOf { .. } => "address-of",
        Value::Cast { .. } => "cast",
        Value::Mul { .. } => "wide multiply",
        Value::Field { .. } => "field access",
        Value::Const { .. } => "const block",
    }
}

fn expr_span(e: &yana_ast::ConstExpr) -> Span {
    match e {
        yana_ast::ConstExpr::Int { span, .. }
        | yana_ast::ConstExpr::Bool { span, .. }
        | yana_ast::ConstExpr::Name { span, .. }
        | yana_ast::ConstExpr::Unary { span, .. }
        | yana_ast::ConstExpr::Binary { span, .. }
        | yana_ast::ConstExpr::If { span, .. }
        | yana_ast::ConstExpr::Call { span, .. }
        | yana_ast::ConstExpr::Array { span, .. }
        | yana_ast::ConstExpr::Tuple { span, .. }
        | yana_ast::ConstExpr::Repeat { span, .. } => *span,
    }
}

fn next_offset(sec: &SectionData, align: u64) -> u64 {
    let cur = sec
        .items
        .iter()
        .map(|i| match i {
            DataItem::Bytes { offset, bytes, .. } => *offset + bytes.len() as u64,
            DataItem::Zero { offset, size, .. } => *offset + *size,
        })
        .max()
        .unwrap_or(0);
    cur.div_ceil(align) * align
}
