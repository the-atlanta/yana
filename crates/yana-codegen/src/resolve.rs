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
    AtomicOp, BranchUse, CallContract, DataItem, Displacement, FnBody, FnContracts, Insn, Jcc,
    LabelDef, MemOp, MemOrder, Module, Operand, SectionData, SpannedInsn, Symbol, SymbolKind,
    WideOp,
};
use crate::target::{Arch, ImportedDecl, ResolveOptions, TargetInfo};

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
    /// `bind volatile` (§12): writes through this binding are wrapped in
    /// [`Insn::Volatile`] so no analysis may elide them.
    volatile: bool,
    /// Parameters live for the whole function and cannot be `unbind`-ed.
    is_param: bool,
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
    /// `struct` declarations before layout, and their laid-out forms (§8).
    structs_raw: HashMap<String, RawStruct>,
    structs: HashMap<String, StructDef>,
    /// `const P: Point = ...;` values, keyed by const name (raw bytes).
    struct_consts: HashMap<String, Vec<u8>>,
    fns: HashMap<String, FnInfo>,
    /// Names seeded by `use` imports (§10) — local declarations may not clash.
    imported_names: Vec<String>,

    // current function state
    scopes: Vec<HashMap<String, Binding>>,
    /// Snapshot of [`FnBody::reg_names`] per scope, restored on `pop_scope` so
    /// a shadowed binding in a nested block does not leak its register name.
    reg_names_stack: Vec<HashMap<Reg, String>>,
    /// Group aliases visible at each scope level (§3). Separate namespace from
    /// `scopes`: a group is a compile-time list of places, not a value.
    group_scopes: Vec<HashMap<String, GroupDef>>,
    /// Top-level `group` declarations — visible in every function.
    global_groups: HashMap<String, GroupDef>,
    /// Frame slots allocated for `stack`/`stack(N)` places, keyed by source
    /// span so that re-resolving the same place reuses its slot.
    stack_slots: HashMap<(u32, u32), i64>,
    /// Bytes allocated in the current function frame (0 → no prologue).
    frame_used: u32,
    /// The function has `stack` parameters → it needs `rbp` as a frame base
    /// even when it allocates no local slots (§5.3).
    needs_frame: bool,
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

/// A named group of places (§3) — a compile-time alias, never a value.
#[derive(Debug, Clone)]
struct GroupDef {
    places: Vec<Place>,
    span: Span,
}

#[derive(Debug, Clone)]
struct StaticInfo {
    sym: usize,
    section: SectionKind,
    offset: u64,
    size: u64,
}

/// A `struct` declaration before layout is computed.
#[derive(Debug, Clone)]
struct RawStruct {
    fields: Vec<(String, Ty, Span)>,
    span: Span,
}

#[derive(Debug, Clone)]
struct StructFieldDef {
    name: String,
    ty: Ty,
    offset: u64,
}

/// Laid-out const-only struct (§8): C-like alignment/padding.
#[derive(Debug, Clone)]
struct StructDef {
    fields: Vec<StructFieldDef>,
    size: u64,
    align: u64,
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
    /// `Some(rbp_offset)` for a stack parameter (§5.3): the caller pushes it,
    /// the callee reads it at `[rbp + offset]`. Register params are `None`.
    stack: Option<u32>,
}

#[derive(Debug, Clone)]
enum RetInfo {
    None,
    Never,
    Single { operand: Operand, ty: Ty },
    Tuple { parts: Vec<ParamInfo> },
}

fn align_up(value: u64, align: u64) -> u64 {
    if align <= 1 {
        value
    } else {
        (value + align - 1) & !(align - 1)
    }
}

/// Layout one type. Structs recurse into [`RawStruct`]; cycles and unknown
/// names are reported as `(diagnostic kind, message, span)`.
fn layout_ty(
    ty: &Ty,
    raws: &HashMap<String, RawStruct>,
    usize_bits: u32,
    stack: &mut Vec<String>,
) -> Result<(u64, u64), (String, String, Span)> {
    match ty {
        Ty::Struct(name) => {
            if stack.contains(name) {
                let span = raws.get(name).map(|r| r.span).unwrap_or(Span::DUMMY);
                return Err((
                    "struct-cycle".into(),
                    format!("struct `{name}` contains itself"),
                    span,
                ));
            }
            let Some(raw) = raws.get(name) else {
                return Err((
                    "unknown-struct".into(),
                    format!("struct `{name}` is not declared"),
                    Span::DUMMY,
                ));
            };
            stack.push(name.clone());
            let def = layout_struct_fields(&raw.fields, raws, usize_bits, stack)?;
            stack.pop();
            Ok((def.size, def.align))
        }
        Ty::Array(inner, n) => {
            let (size, align) = layout_ty(inner, raws, usize_bits, stack)?;
            Ok((size * n, align))
        }
        Ty::Tuple(items) => {
            let fields: Vec<(String, Ty, Span)> = items
                .iter()
                .enumerate()
                .map(|(i, t)| (format!("{i}"), t.clone(), Span::DUMMY))
                .collect();
            let def = layout_struct_fields(&fields, raws, usize_bits, stack)?;
            Ok((def.size, def.align))
        }
        _ => match ty.size_bits(usize_bits) {
            Some(bits) => {
                let size = (bits as u64 / 8).max(1);
                Ok((size, size))
            }
            None => Err((
                "struct-layout".into(),
                format!("type {ty:?} has no fixed size"),
                Span::DUMMY,
            )),
        },
    }
}

fn layout_struct_fields(
    fields: &[(String, Ty, Span)],
    raws: &HashMap<String, RawStruct>,
    usize_bits: u32,
    stack: &mut Vec<String>,
) -> Result<StructDef, (String, String, Span)> {
    let mut offset = 0u64;
    let mut align = 1u64;
    let mut out = Vec::new();
    for (name, ty, span) in fields {
        let (size, a) = layout_ty(ty, raws, usize_bits, stack).map_err(|(k, m, s)| {
            let s = if s.is_dummy() { *span } else { s };
            (k, m, s)
        })?;
        offset = align_up(offset, a);
        out.push(StructFieldDef { name: name.clone(), ty: ty.clone(), offset });
        offset += size;
        align = align.max(a);
    }
    Ok(StructDef { fields: out, size: align_up(offset, align), align })
}

fn layout_struct_named(
    name: &str,
    raws: &HashMap<String, RawStruct>,
    usize_bits: u32,
    stack: &mut Vec<String>,
) -> Result<StructDef, (String, String, Span)> {
    let Some(raw) = raws.get(name) else {
        return Err((
            "unknown-struct".into(),
            format!("struct `{name}` is not declared"),
            Span::DUMMY,
        ));
    };
    stack.push(name.to_string());
    let def = layout_struct_fields(&raw.fields, raws, usize_bits, stack)?;
    stack.pop();
    Ok(def)
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
            structs_raw: HashMap::new(),
            structs: HashMap::new(),
            struct_consts: HashMap::new(),
            fns: HashMap::new(),
            scopes: Vec::new(),
            reg_names_stack: Vec::new(),
            group_scopes: Vec::new(),
            global_groups: HashMap::new(),
            stack_slots: HashMap::new(),
            frame_used: 0,
            needs_frame: false,
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
            imported_names: Vec::new(),
        };
        r.env_consts_setup();
        r.module.target = r.target.clone();
        r
    }

    fn env_consts_setup(&mut self) {
        // nothing yet; consts filled during pass 1
    }

    /// Seed imported declarations (§10) into the symbol tables before the
    /// file's own items are collected.
    ///
    /// Imported functions become extern-like symbols: undefined (resolved by
    /// the linker at `ld` time), with ABI/clobbers taken from the imported
    /// signature so call-site lowering and contracts behave exactly as for a
    /// local `extern fn`. Imported consts fold to their value; imported
    /// statics become undefined symbol references (Pc32 relocations). No
    /// mangling (§10): the symbol name is the item name verbatim.
    fn seed_imports(&mut self) {
        let mut names: Vec<String> = Vec::new();
        for decl in self.opts.imports.clone() {
            let name = match &decl {
                ImportedDecl::Fn { sig, .. } => sig.name.clone(),
                ImportedDecl::Const { name, .. } => name.clone(),
                ImportedDecl::Static { name, .. } => name.clone(),
            };
            names.push(name);
            match decl {
                ImportedDecl::Fn { sig, clobbers } => {
                    self.collect_fn(&sig, true, false, None, true, clobbers, sig.span);
                    if let Some(info) = self.fns.get_mut(&sig.name) {
                        info.real_call = true;
                    }
                }
                ImportedDecl::Const { name, value } => {
                    let sym = self.module.symbols.len();
                    self.module.symbols.push(Symbol {
                        name: name.clone(),
                        kind: SymbolKind::Const { value },
                        exported: false,
                        syscall: None,
                        clobbers: vec![],
                        preserves: vec![],
                        naked: false,
                        contracts: FnContracts::default(),
                        span: Span::DUMMY,
                    });
                    self.consts.insert(name.clone(), value);
                    self.env.consts.insert(name, CValue::Int(value));
                    let _ = sym;
                }
                ImportedDecl::Static { name, size } => {
                    // undefined symbol: SHN_UNDEF, STB_GLOBAL at write_object time
                    let sym = self.module.symbols.len();
                    self.module.symbols.push(Symbol {
                        name: name.clone(),
                        kind: SymbolKind::ExternStatic { size },
                        exported: true,
                        syscall: None,
                        clobbers: vec![],
                        preserves: vec![],
                        naked: false,
                        contracts: FnContracts::default(),
                        span: Span::DUMMY,
                    });
                    self.statics.insert(
                        name,
                        StaticInfo { sym, section: SectionKind::Data, offset: 0, size },
                    );
                }
            }
        }
        // only now that seeding is done: local declarations may not clash
        // with imported names (checked in the collect_* functions)
        self.imported_names = names;
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
        self.seed_imports();
        self.collect_decls(file);
        if self.diagnostics.iter().any(|d| matches!(d.level, yana_ast::DiagLevel::Error)) {
            return; // don't lower on a broken decl set
        }
        self.lower_bodies(file);
    }

    fn collect_decls(&mut self, file: &File) {
        // struct declarations first: static/const layout needs them (§8).
        for item in &file.items {
            if let Item::Struct(s) = item {
                self.collect_struct(s);
            }
        }
        self.compute_struct_layouts();

        // Struct constants must be evaluated before statics: a static can be
        // initialised from a struct constant (`bind p @ .rodata: Point = P;`).
        for item in &file.items {
            if let Item::Const(c) = item {
                if matches!(c.ty, Ty::Struct(_)) {
                    self.eval_const(c);
                }
            }
        }

        // statics + consts + const fns first (bodies may reference them)
        for item in &file.items {
            match item {
                Item::Static(s) => self.collect_static(s),
                Item::Const(c) => self.collect_const(c),
                Item::ConstFn(f) => {
                    self.const_fns.insert(f.name.clone(), f.clone());
                }
                Item::Group(g) => self.declare_group(g, true),
                _ => {}
            }
        }
        // evaluate consts (may reference other consts — single pass in decl order;
        // forward refs error for MVP). Struct consts were evaluated above,
        // before statics.
        for item in &file.items {
            if let Item::Const(c) = item {
                if !matches!(c.ty, Ty::Struct(_)) {
                    self.eval_const(c);
                }
            }
        }
        // functions and externs → symbols
        for item in &file.items {
            match item {
                Item::Fn(f) => self.collect_fn_with_contracts(
                    &f.sig,
                    f.exported,
                    f.is_entry(),
                    None,
                    false,
                    f.clobbers.as_ref().map(|c| c.regs.clone()).unwrap_or_default(),
                    f.preserves.as_ref().map(|c| c.regs.clone()).unwrap_or_default(),
                    f.is_naked(),
                    f.contracts.clone(),
                    f.span,
                ),
                Item::ExternFn(e) => {
                    let syscall = e.syscall_number();
                    let real_call = e.abi.as_deref() == Some("C");
                    self.collect_fn_with_contracts(
                        &e.sig,
                        true,
                        false,
                        syscall,
                        true,
                        e.clobbers.as_ref().map(|c| c.regs.clone()).unwrap_or_default(),
                        e.preserves.as_ref().map(|c| c.regs.clone()).unwrap_or_default(),
                        false,
                        e.contracts.clone(),
                        e.span,
                    );
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

    /// Collect a `struct` declaration; layout is computed after all structs
    /// are known (fields may refer to structs declared later).
    fn collect_struct(&mut self, s: &yana_ast::StructDecl) {
        if self.structs_raw.contains_key(&s.name) {
            self.err(
                "struct-duplicate",
                format!("struct `{}` is declared twice", s.name),
                s.name_span,
            );
            return;
        }
        let mut seen: Vec<&str> = Vec::new();
        let mut fields = Vec::new();
        for f in &s.fields {
            if seen.contains(&f.name.as_str()) {
                self.err(
                    "struct-field",
                    format!("struct `{}` has duplicate field `{}`", s.name, f.name),
                    f.name_span,
                );
                continue;
            }
            seen.push(&f.name);
            fields.push((f.name.clone(), f.ty.clone(), f.span));
        }
        self.structs_raw.insert(
            s.name.clone(),
            RawStruct { fields, span: s.span },
        );
    }

    fn compute_struct_layouts(&mut self) {
        let names: Vec<String> = self.structs_raw.keys().cloned().collect();
        for name in names {
            let mut stack = Vec::new();
            match layout_struct_named(
                &name,
                &self.structs_raw,
                self.target.usize_bits(),
                &mut stack,
            ) {
                Ok(def) => {
                    self.structs.insert(name, def);
                }
                Err((kind, msg, span)) => self.err(&kind, msg, span),
            }
        }
    }

    /// Size and alignment of a type, resolving struct/array/tuple layouts.
    fn ty_size_align(&self, ty: &Ty) -> Option<(u64, u64)> {
        match ty {
            Ty::Struct(name) => self.structs.get(name).map(|d| (d.size, d.align)),
            Ty::Array(inner, n) => {
                let (size, align) = self.ty_size_align(inner)?;
                Some((size.checked_mul(*n)?, align))
            }
            Ty::Tuple(items) => {
                let mut off = 0u64;
                let mut align = 1u64;
                for t in items {
                    let (size, a) = self.ty_size_align(t)?;
                    off = align_up(off, a);
                    off += size;
                    align = align.max(a);
                }
                Some((align_up(off, align), align))
            }
            _ => {
                let bits = ty.size_bits(self.target.usize_bits())?;
                let size = (bits as u64 / 8).max(1);
                Some((size, size))
            }
        }
    }

    /// Encode a const-only struct literal. Structs use positional
    /// construction: `Point(1, 2)` in field declaration order (§8).
    fn struct_value_bytes(
        &mut self,
        expr: &yana_ast::ConstExpr,
        ty: &Ty,
        span: Span,
    ) -> Result<Vec<u8>, ()> {
        let Ty::Struct(name) = ty else {
            self.err("struct-init", "expected a struct type", span);
            return Err(());
        };
        let Some(def) = self.structs.get(name).cloned() else {
            self.err(
                "unknown-struct",
                format!("struct `{name}` is not declared"),
                span,
            );
            return Err(());
        };
        match expr {
            yana_ast::ConstExpr::Name { name: other, span: nspan } => {
                if let Some(bytes) = self.struct_consts.get(other) {
                    Ok(bytes.clone())
                } else {
                    self.err(
                        "struct-init",
                        format!("`{other}` is not a struct constant of type `{name}`"),
                        *nspan,
                    );
                    Err(())
                }
            }
            yana_ast::ConstExpr::Call { name: ctor, args, span: espan } => {
                if ctor != name {
                    self.err(
                        "struct-init",
                        format!("expected `{name}(...)`, got `{ctor}(...)`"),
                        *espan,
                    );
                    return Err(());
                }
                if args.len() != def.fields.len() {
                    self.err(
                        "struct-init-arity",
                        format!(
                            "struct `{name}` has {} field(s), got {} initializer(s)",
                            def.fields.len(),
                            args.len()
                        ),
                        *espan,
                    );
                    return Err(());
                }
                let mut bytes = vec![0u8; def.size as usize];
                for (field, arg) in def.fields.iter().zip(args.iter()) {
                    let fb = self.field_value_bytes(arg, &field.ty, span)?;
                    let off = field.offset as usize;
                    if off + fb.len() > bytes.len() {
                        self.err(
                            "struct-init",
                            format!("field `{}` does not fit in struct `{name}`", field.name),
                            span,
                        );
                        return Err(());
                    }
                    bytes[off..off + fb.len()].copy_from_slice(&fb);
                }
                Ok(bytes)
            }
            _ => {
                self.err(
                    "struct-init",
                    format!("struct `{name}` needs a constructor `{name}(...)`"),
                    span,
                );
                Err(())
            }
        }
    }

    fn field_value_bytes(
        &mut self,
        expr: &yana_ast::ConstExpr,
        ty: &Ty,
        span: Span,
    ) -> Result<Vec<u8>, ()> {
        if matches!(ty, Ty::Struct(_)) {
            return self.struct_value_bytes(expr, ty, span);
        }
        match self.eval_const_expr(expr) {
            Ok(v) => {
                if let (CValue::Int(i), Some(bits)) =
                    (&v, ty.size_bits(self.target.usize_bits()))
                {
                    if !imm_fits(*i, bits, ty.is_signed()) {
                        self.err(
                            "struct-init-type",
                            format!("value {i} does not fit in field type {ty:?}"),
                            expr_span(expr),
                        );
                        return Err(());
                    }
                }
                Ok(self.const_to_bytes(&v, ty))
            }
            Err(d) => {
                self.diagnostics.push(d);
                Err(())
            }
        }
    }

    fn collect_static(&mut self, s: &yana_ast::StaticBind) {
        if self.imported_names.contains(&s.name) {
            self.err(
                "duplicate-import",
                format!("`{}` is both imported and declared here", s.name),
                s.name_span,
            );
            return;
        }
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
                let elem = self
                    .ty_size_align(inner)
                    .map(|(size, _)| size)
                    .unwrap_or_else(|| ty_bits(inner, &self.target) as u64 / 8);
                (None, elem * n)
            }
            (None, Ty::Struct(_)) => match self.ty_size_align(&ty) {
                Some((size, _)) => (None, size),
                None => {
                    self.err(
                        "unknown-struct",
                        format!("cannot lay out struct type {ty:?}"),
                        s.span,
                    );
                    return;
                }
            },
            (None, _) => {
                self.err(
                    "static-init",
                    "static data without initializer needs an array type (or use .bss)",
                    s.span,
                );
                return;
            }
        };

        let align = self
            .ty_size_align(&ty)
            .map(|(_, a)| a)
            .unwrap_or_else(|| (ty_bits(&ty, &self.target) / 8).max(1) as u64);
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
            preserves: vec![],
            naked: false,
            contracts: FnContracts::default(),
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
            Value::Str { bytes, .. } | Value::Bytes { bytes, .. } => Ok(bytes.clone()),
            Value::Imm { value, .. } => Ok(imm_to_bytes(*value, ty, &self.target)),
            Value::Const { expr, .. } => {
                if matches!(ty, Ty::Struct(_)) {
                    return self.struct_value_bytes(expr, ty, span);
                }
                match self.eval_const_expr(expr) {
                    Ok(v) => Ok(self.const_to_bytes(&v, ty)),
                    Err(d) => {
                        self.diagnostics.push(d);
                        Err(())
                    }
                }
            }
            Value::Place(Place::Named { name, .. }) if matches!(ty, Ty::Struct(_)) => {
                match self.struct_consts.get(name) {
                    Some(bytes) => Ok(bytes.clone()),
                    None => {
                        self.err(
                            "struct-init",
                            format!("`{name}` is not a struct constant"),
                            span,
                        );
                        Err(())
                    }
                }
            }
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
        if self.imported_names.contains(&c.name) {
            self.err(
                "duplicate-import",
                format!("const `{}` is both imported and declared here", c.name),
                c.name_span,
            );
            return;
        }
        // value computed in eval_const (needs env); placeholder registered here
        let sym = self.module.symbols.len();
        self.module.symbols.push(Symbol {
            name: c.name.clone(),
            kind: SymbolKind::Const { value: 0 },
            exported: false,
            syscall: None,
            clobbers: vec![],
            preserves: vec![],
            naked: false,
            contracts: FnContracts::default(),
            span: c.span,
        });
        self.consts.insert(c.name.clone(), 0); // patched by eval_const
        let _ = sym;
    }

    fn eval_const(&mut self, c: &yana_ast::ConstItem) {
        if matches!(c.ty, Ty::Struct(_)) {
            if self.struct_consts.contains_key(&c.name) {
                return;
            }
            // Const-only struct value: store its bytes for static initializers.
            // The symbol itself was registered by `collect_const`.
            match self.struct_value_bytes(&c.value, &c.ty, c.span) {
                Ok(bytes) => {
                    self.struct_consts.insert(c.name.clone(), bytes);
                }
                Err(()) => {}
            }
            return;
        }
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
        clobbers: Vec<Reg>,
        span: Span,
    ) {
        self.collect_fn_with_contracts(sig, exported, is_entry, syscall, is_extern, clobbers, vec![], false, yana_ast::Contracts::default(), span)
    }

    fn collect_fn_with_contracts(
        &mut self,
        sig: &FnSig,
        exported: bool,
        is_entry: bool,
        syscall: Option<i64>,
        is_extern: bool,
        clobbers: Vec<Reg>,
        preserves: Vec<Reg>,
        naked: bool,
        ast_contracts: yana_ast::Contracts,
        span: Span,
    ) {
        if self.fns.contains_key(&sig.name) || self.statics.contains_key(&sig.name) {
            self.err("dup-symbol", format!("symbol `{}` declared twice", sig.name), span);
            return;
        }
        if self.imported_names.contains(&sig.name) {
            self.err(
                "duplicate-import",
                format!("`{}` is both imported and declared here", sig.name),
                sig.name_span,
            );
            return;
        }
        let name = if is_entry {
            self.target.entry_symbol().to_string()
        } else {
            format!("{}{}", self.target.symbol_prefix(), sig.name)
        };

        // §5.3: register params first, then stack params in declaration
        // order at [rbp+16], [rbp+24], ... (the SysV layout).
        let mut stack_off = 16u32;
        let mut has_stack_param = false;
        let params: Vec<ParamInfo> = sig
            .params
            .iter()
            .map(|p| {
                let ty = p.ty().cloned().unwrap_or(Ty::U64);
                let mut stack = None;
                let operand = if let Place::Stack { size, .. } = &p.place {
                    has_stack_param = true;
                    let bits = p
                        .place
                        .ty()
                        .map(|t| ty_bits(t, &self.target))
                        .or_else(|| size.map(|n| n * 8))
                        .unwrap_or(64);
                    let slot = ((bits / 8).max(1) + 7) & !7;
                    let off = stack_off;
                    stack_off += slot;
                    stack = Some(off);
                    Operand::Mem(MemOp {
                        base: Some(Reg::Gpr {
                            base: yana_ast::reg::GprBase::Bp,
                            size: yana_ast::reg::RegSize::R64,
                        }),
                        index: None,
                        scale: 1,
                        disp: Displacement::Const(off as i64),
                        size: bits,
                        rip_relative: false,
                    })
                } else {
                    self.param_operand(p)
                };
                ParamInfo { operand, ty, name: p.name.clone(), stack }
            })
            .collect();
        if is_extern && has_stack_param {
            self.err(
                "stack-param-extern",
                "`extern fn` cannot take `stack` parameters — the ABI is not ours to define",
                sig.span,
            );
        }

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
                        stack: None,
                    })
                    .collect(),
            },
        };

        // §14.4 contracts: build the IR-level form and validate every ident
        // against the signature (`verify-contract-name`).
        let contracts = self.lower_contracts(sig, &ret, &ast_contracts);

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
            clobbers: if syscall.is_some() { vec![Reg::parse("rcx").unwrap(), Reg::parse("r11").unwrap()] } else { clobbers },
            preserves,
            naked,
            contracts,
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

    /// "Did you mean" suffix for an unknown name (§11): the closest visible
    /// binding, function, static, const, group, or label.
    fn suggest(&self, needle: &str) -> String {
        let mut cands: Vec<&str> = Vec::new();
        for scope in &self.scopes {
            cands.extend(scope.keys().map(String::as_str));
        }
        cands.extend(self.fns.keys().map(String::as_str));
        cands.extend(self.statics.keys().map(String::as_str));
        cands.extend(self.consts.keys().map(String::as_str));
        cands.extend(self.global_groups.keys().map(String::as_str));
        for scope in &self.group_scopes {
            cands.extend(scope.keys().map(String::as_str));
        }
        cands.extend(self.labels.keys().map(String::as_str));
        match yana_ast::text::closest(needle, cands) {
            Some(s) => format!("; did you mean `{s}`?"),
            None => String::new(),
        }
    }

    fn param_operand(&self, p: &Param) -> Operand {
        self.place_to_operand_simple(&p.place)
    }

    /// §14.4: build the IR contract form and validate clause idents against
    /// the signature. In `requires`/`ensures` an ident names a parameter; in
    /// `ensures` idents may ALSO name result registers (ret-sig binding name,
    /// or the bare register name for `-> rax: u64`). Unknown ident →
    /// `verify-contract-name`; unsupported expression shapes → 
    /// `verify-contract-expr` (docs/NOTES-verify.md D6).
    fn lower_contracts(
        &mut self,
        sig: &FnSig,
        ret: &RetInfo,
        c: &yana_ast::Contracts,
    ) -> FnContracts {
        use yana_ast::reg::RegSize;
        let norm = |r: Reg| r.resize(RegSize::R64).unwrap_or(r);
        let params: Vec<(String, Reg)> = sig
            .params
            .iter()
            .filter_map(|p| match self.param_operand(p) {
                Operand::Reg(r) => Some((p.name.clone(), norm(r))),
                _ => None,
            })
            .collect();
        let results: Vec<(String, Reg)> = match ret {
            RetInfo::Single { operand: Operand::Reg(r), .. } => vec![(norm(*r).name().to_string(), norm(*r))],
            RetInfo::Tuple { parts } => parts
                .iter()
                .filter_map(|p| match &p.operand {
                    Operand::Reg(r) => Some((p.name.clone(), norm(*r))),
                    _ => None,
                })
                .collect(),
            _ => vec![],
        };
        let mut out = FnContracts {
            requires: Vec::new(),
            ensures: Vec::new(),
            invariants: Vec::new(),
            params: params.clone(),
            results: results.clone(),
        };
        for sp in &c.requires {
            if self.check_contract_expr(&sp.v, &params, &[]) {
                out.requires.push((sp.v.clone(), sp.span));
            }
        }
        for sp in &c.ensures {
            // ensures may also name result regs; allow reg names as idents too
            let mut allowed: Vec<(String, Reg)> = params.clone();
            allowed.extend(results.iter().cloned());
            if self.check_contract_expr(&sp.v, &allowed, &results) {
                out.ensures.push((sp.v.clone(), sp.span));
            }
        }
        for sp in &c.invariants {
            // Invariants may mention parameters and results: entry checks see
            // parameters, exit checks see results.
            let mut allowed: Vec<(String, Reg)> = params.clone();
            allowed.extend(results.iter().cloned());
            if self.check_contract_expr(&sp.v, &allowed, &results) {
                out.invariants.push((sp.v.clone(), sp.span));
            }
        }
        out
    }

    /// Validate one contract expression. `allowed` are the ident names in
    /// scope; `results` additionally allows bare result-register names
    /// (`rax`) in ensures clauses. Returns false when a diagnostic was
    /// emitted (the clause is dropped).
    fn check_contract_expr(
        &mut self,
        e: &yana_ast::ConstExpr,
        allowed: &[(String, Reg)],
        results: &[(String, Reg)],
    ) -> bool {
        let mut ok = true;
        match e {
            yana_ast::ConstExpr::Name { name, span } => {
                let known = allowed.iter().any(|(n, _)| n == name)
                    || results.iter().any(|(_, r)| r.name() == name);
                if !known {
                    let mut valid: Vec<&str> = allowed.iter().map(|(n, _)| n.as_str()).collect();
                    for (_, r) in results {
                        if !valid.contains(&r.name()) {
                            valid.push(r.name());
                        }
                    }
                    self.err_help(
                        "verify-contract-name",
                        format!("`{name}` is not a parameter or result of this function (§14.4)"),
                        if valid.is_empty() {
                            "this function has no names available in contract clauses".to_string()
                        } else {
                            format!("valid names: {}", valid.join(", "))
                        },
                        *span,
                    );
                    ok = false;
                }
            }
            yana_ast::ConstExpr::Int { .. } | yana_ast::ConstExpr::Bool { .. } => {}
            yana_ast::ConstExpr::Unary { expr, .. } => {
                ok &= self.check_contract_expr(expr, allowed, results);
            }
            yana_ast::ConstExpr::Binary { lhs, rhs, .. } => {
                ok &= self.check_contract_expr(lhs, allowed, results);
                ok &= self.check_contract_expr(rhs, allowed, results);
            }
            other => {
                self.err_help(
                    "verify-contract-expr",
                    format!("unsupported expression shape in a contract clause ({})", contract_shape_name(other)),
                    "contracts are minimal (§15 30.10): integers, comparisons, &&/||, arithmetic, unary -/!",
                    expr_span(other),
                );
                ok = false;
            }
        }
        ok
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
            reg_names: std::collections::HashMap::new(),
            stack_delta: 0,
        };
        self.labels.clear();
        self.pending_jumps.clear();
        self.scopes.clear();
        self.group_scopes.clear();
        self.stack_slots.clear();
        self.frame_used = 0;
        self.needs_frame = false;
        self.cur_ret = f.sig.ret.clone();
        self.cur_fn_span = f.span;
        self.push_scope();

        // params become bindings; stack params carry their [rbp+N] operand
        self.needs_frame = info.params.iter().any(|p| p.stack.is_some());
        for (p, pinfo) in f.sig.params.iter().zip(info.params.iter()) {
            let ty = p.ty().cloned().unwrap_or(Ty::U64);
            let operand = pinfo.operand.clone();
            self.define(p.name.clone(), Binding { operand, ty, mutable: p.mutable, volatile: false, is_param: true, span: p.span });
        }

        self.lower_block(&f.body);
        if f.is_naked() {
            // §5.6: no compiler-generated prologue/epilogue.
            if self.frame_used > 0 {
                self.err_help(
                    "naked-frame",
                    "`#[naked]` function uses a `stack` slot, but the frame is not emitted",
                    "allocate the frame by hand (`push`/`sub rsp`) or drop `stack` places",
                    f.span,
                );
            }
        } else {
            self.apply_frame();
        }

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
                    format!("label '{name} is not defined in this function{}", self.suggest(&name)),
                    span,
                ),
            }
        }

        // The function scope itself is not a nested block: keep its
        // `reg_names` map (nested scopes already restored their snapshots).
        let reg_names = self.body.reg_names.clone();
        self.pop_scope();
        self.body.reg_names = reg_names;
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
        // Argument registers: liveness needs them as reads of the call, or a
        // `mov rdi, ...` that only feeds a call looks like a dead store.
        let args: Vec<Reg> = info
            .params
            .iter()
            .filter_map(|p| match &p.operand {
                Operand::Reg(r) => Some(r.resize(yana_ast::reg::RegSize::R64).unwrap_or(*r)),
                _ => None,
            })
            .collect();
        // clobbers: externs must declare them (§5.4); we stored declared ones
        // on the Symbol; local fns get derived clobbers after analysis (pass 3)
        // — until then, conservatively: everything the callee's symbol lists.
        let clobbers = self
            .module
            .symbols
            .get(info.sym)
            .map(|s| s.clobbers.clone())
            .unwrap_or_default();
        CallContract {
            clobbers,
            args,
            results,
            noreturn,
            syscall: info.syscall,
            stack_delta: 0, // inferred by the stack analysis pass
        }
    }

    fn has_errors(&self) -> bool {
        self.diagnostics.iter().any(|d| matches!(d.level, yana_ast::DiagLevel::Error))
    }

    fn push_scope(&mut self) {
        self.reg_names_stack.push(self.body.reg_names.clone());
        self.scopes.push(HashMap::new());
        self.group_scopes.push(HashMap::new());
    }
    fn pop_scope(&mut self) {
        self.scopes.pop();
        self.group_scopes.pop();
        if let Some(saved) = self.reg_names_stack.pop() {
            self.body.reg_names = saved;
        }
    }
    fn define(&mut self, name: String, b: Binding) {
        if let Some(top) = self.scopes.last_mut() {
            top.insert(name, b);
        }
    }
    fn define_group(&mut self, name: String, g: GroupDef) {
        if let Some(top) = self.group_scopes.last_mut() {
            top.insert(name, g);
        }
    }
    fn lookup_group(&self, name: &str) -> Option<&GroupDef> {
        self.group_scopes
            .iter()
            .rev()
            .find_map(|s| s.get(name))
            .or_else(|| self.global_groups.get(name))
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
            Stmt::Group(g) => self.declare_group(g, false),
            Stmt::Breakpoint { .. } => {
                self.emit(Insn::Int3);
            }
            Stmt::Trap { .. } => {
                self.emit(Insn::Ud2);
            }
            Stmt::Assert { cond, .. } => self.lower_assert(cond),
            Stmt::Debug(b) => {
                if self.opts.debug {
                    self.push_scope();
                    self.lower_block(b);
                    self.pop_scope();
                }
            }
            Stmt::Bind { mutable, volatile, name, name_span, place, init, pattern, span } => {
                if let Some(pat) = pattern {
                    self.lower_bind_pattern(pat, init.as_ref(), *span);
                    return;
                }
                // `bind name @ group(g) = b"...";` — a group alias, not a value.
                if let Place::Group { name: gname, span: gspan } = place {
                    let Some(def) = self.lookup_group(gname).cloned() else {
                        self.err("unknown-group", format!("group `{gname}` is not declared{}", self.suggest(gname)), *gspan);
                        return;
                    };
                    if let Some(n) = name {
                        self.define_group(n.clone(), def.clone());
                    }
                    let Some(v) = init else { return };
                    self.lower_group_write(&def, v, *span);
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
                // `_` is the discard (Rust convention, SPEC §11 ✅): rebindable,
                // holds no name and no register; its writes are intentional sinks.
                let is_wildcard = name == "_";
                // Shadowing (§3): a later `bind name` replaces the earlier one,
                // even in the same scope (Rust `let`-style). Retire the old
                // binding's register name so liveness does not keep a stale
                // mapping; the old value becomes inaccessible.
                if !is_wildcard {
                    if let Some(old) = self.scopes.last().and_then(|s| s.get(&name)).cloned() {
                        if let Operand::Reg(r) = &old.operand {
                            let r64 = r.resize(yana_ast::reg::RegSize::R64).unwrap_or(*r);
                            if self.body.reg_names.get(&r64) == Some(&name) {
                                self.body.reg_names.remove(&r64);
                            }
                        }
                    }
                }
                // §3 🟡 two names on one register at once is an error
                if !is_wildcard {
                    if let Operand::Reg(r) = &operand {
                        let conflict = self.scopes.iter().rev().find_map(|scope| {
                            scope.iter().find_map(|(other, b)| {
                                (other != &name && b.operand == Operand::Reg(*r))
                                    .then(|| (other.clone(), b.span))
                            })
                        });
                        if let Some((other, other_span)) = conflict {
                            self.diagnostics.push(
                                Diagnostic::error(
                                    DiagCode::Semantic,
                                    "reg-conflict",
                                    format!(
                                        "`{name}` and `{other}` are bound to {} at the same time (§3)",
                                        r.name()
                                    ),
                                    *name_span,
                                )
                                .with_primary_label(format!("`{name}` wants {} here", r.name()))
                                .with_label(
                                    format!("`{other}` is bound to {} here", r.name()),
                                    other_span,
                                    false,
                                )
                                .with_help(
                                    "a binding holds its register until the end of the block even \
                                     after its last use: shadow the earlier name with a new \
                                     `bind`, close it in a nested `{ ... }` block, or bind the \
                                     value to `_`",
                                ),
                            );
                        }
                    }
                }
                let ty_for_init = ty.clone();
                if let Operand::Reg(r) = &operand {
                    // liveness: remember which name holds this register, so
                    // `_`-prefixed sinks never produce dead-store warnings.
                    let r64 = r.resize(yana_ast::reg::RegSize::R64).unwrap_or(*r);
                    self.body.reg_names.insert(r64, name.clone());
                }
                if !is_wildcard {
                    self.define(
                        name,
                        Binding {
                            operand: operand.clone(),
                            ty,
                            mutable: *mutable,
                            volatile: *volatile,
                            is_param: false,
                            span: *span,
                        },
                    );
                }
                if let Some(v) = init {
                    // initial write: no `alt` needed (§4.2)
                    let before = self.body.insns.len();
                    self.lower_write(&operand, &ty_for_init, v, *span);
                    if *volatile {
                        self.wrap_volatile(before);
                    }
                }
            }
            Stmt::Unbind { name, name_span, span } => {
                self.lower_unbind(name, *name_span, *span);
            }
            Stmt::Alt { dst, op, src, modifier, span } => {
                let vol = *modifier == AltModifier::None
                    && matches!(dst, Place::Named { name, .. }
                        if self.lookup(name).map(|b| b.volatile).unwrap_or(false));
                let before = self.body.insns.len();
                self.lower_alt(dst, *op, src, modifier, *span);
                if vol {
                    self.wrap_volatile(before);
                }
            }
            Stmt::DivMod { results, dividend, divisor, span } => {
                self.lower_divmod(results, dividend, divisor, *span)
            }
            Stmt::Push { items, span } => {
                let items = self.expand_group_items(items, true, *span);
                for it in &items {
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
                let items = self.expand_group_items(items, false, *span);
                for it in &items {
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
                // §3: the label body is a block — `bind` inside is scoped to it,
                // so the same register may be re-bound in a sibling label.
                self.push_scope();
                self.lower_block(body);
                self.pop_scope();
                let _ = span;
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

    /// Wrap every instruction emitted since `before` in [`Insn::Volatile`]
    /// (§12) — used by `bind volatile` and by volatile bindings' writes.
    fn wrap_volatile(&mut self, before: usize) {
        for si in &mut self.body.insns[before..] {
            if !matches!(si.insn, Insn::Volatile(_)) {
                si.insn = Insn::Volatile(Box::new(std::mem::replace(&mut si.insn, Insn::Nop)));
            }
        }
    }

    /// `assert (cond);` (§4.6) — `ud2` when the condition does not hold:
    /// `cmp; j<inverted> over; ud2; over:`.
    fn lower_assert(&mut self, cond: &BranchCond) {
        let cc = match cond {
            BranchCond::Cmp { lhs, op, rhs, .. } => {
                let signed = self.cmp_signedness(lhs, rhs);
                let (mut a, sa) = match self.resolve_value(lhs) {
                    Some(v) => v,
                    None => return,
                };
                let (mut b, _) = match self.resolve_value(rhs) {
                    Some(v) => v,
                    None => return,
                };
                let mut op = *op;
                // `cmp` has no imm,imm form: constant-fold or swap.
                match (&a, &b) {
                    (Operand::Imm(x), Operand::Imm(y)) => {
                        let ok = match op {
                            yana_ast::CmpOp::Eq => x == y,
                            yana_ast::CmpOp::Ne => x != y,
                            yana_ast::CmpOp::Lt => x < y,
                            yana_ast::CmpOp::Le => x <= y,
                            yana_ast::CmpOp::Gt => x > y,
                            yana_ast::CmpOp::Ge => x >= y,
                        };
                        if !ok {
                            self.emit(Insn::Ud2);
                        }
                        return;
                    }
                    (Operand::Imm(_), _) => {
                        std::mem::swap(&mut a, &mut b);
                        op = match op {
                            yana_ast::CmpOp::Eq => yana_ast::CmpOp::Eq,
                            yana_ast::CmpOp::Ne => yana_ast::CmpOp::Ne,
                            yana_ast::CmpOp::Lt => yana_ast::CmpOp::Gt,
                            yana_ast::CmpOp::Le => yana_ast::CmpOp::Ge,
                            yana_ast::CmpOp::Gt => yana_ast::CmpOp::Lt,
                            yana_ast::CmpOp::Ge => yana_ast::CmpOp::Le,
                        };
                    }
                    _ => {}
                }
                let size = sa.max(8);
                self.emit(Insn::Cmp { a, b, size });
                let inverted = match op {
                    yana_ast::CmpOp::Eq => yana_ast::CmpOp::Ne,
                    yana_ast::CmpOp::Ne => yana_ast::CmpOp::Eq,
                    yana_ast::CmpOp::Lt => yana_ast::CmpOp::Ge,
                    yana_ast::CmpOp::Le => yana_ast::CmpOp::Gt,
                    yana_ast::CmpOp::Gt => yana_ast::CmpOp::Le,
                    yana_ast::CmpOp::Ge => yana_ast::CmpOp::Lt,
                };
                insn::cmp_cc(inverted, signed)
            }
            BranchCond::Flag { flag, negated, .. } => insn::flag_cc(*flag, !negated),
        };
        let def = self.body.label_defs.len();
        self.body.label_defs.push(LabelDef {
            name: format!("$assert{def}"),
            at_insn: self.body.insns.len() + 2,
            scope_depth: self.scopes.len() as u32,
        });
        self.emit(Insn::Jcc { cc, label: def });
        self.emit(Insn::Ud2);
    }

    /// `unbind name;` (§3): release the binding so its register is free for a
    /// different name. Only bindings of the current block can be released;
    /// parameters live for the whole function and are rejected.
    fn lower_unbind(&mut self, name: &str, name_span: Span, span: Span) {
        if name == "_" {
            self.err(
                "unbind-discard",
                "`_` is not a binding and cannot be unbound",
                name_span,
            );
            return;
        }
        let mut found: Option<(usize, Binding)> = None;
        for (idx, scope) in self.scopes.iter().enumerate().rev() {
            if let Some(b) = scope.get(name) {
                found = Some((idx, b.clone()));
                break;
            }
        }
        let Some((idx, binding)) = found else {
            self.err(
                "unknown-name",
                format!("`{name}` is not bound here{}", self.suggest(name)),
                name_span,
            );
            return;
        };
        if idx + 1 != self.scopes.len() {
            self.err_help(
                "unbind-scope",
                format!("`{name}` is bound in an outer block; `unbind` only releases bindings of the current block"),
                "move `unbind` into the block where the binding was declared, or shadow the name with a new `bind`",
                name_span,
            );
            return;
        }
        if binding.is_param {
            self.err_help(
                "unbind-param",
                format!("`{name}` is a parameter and lives for the whole function"),
                "bind the parameter value to a new name and `unbind` that name instead",
                name_span,
            );
            return;
        }
        if let Some(scope) = self.scopes.last_mut() {
            scope.remove(name);
        }
        if let Operand::Reg(r) = &binding.operand {
            let r64 = r.resize(yana_ast::reg::RegSize::R64).unwrap_or(*r);
            if self.body.reg_names.get(&r64) == Some(&name.to_string()) {
                self.body.reg_names.remove(&r64);
            }
        }
        let _ = span;
    }

    /// Is `r` already declared/used by this function? Parameters and result
    /// registers count, as does any earlier `bind` (including `bind _`).
    fn register_bound(&self, r: &Reg) -> bool {
        let r64 = r.resize(yana_ast::reg::RegSize::R64).unwrap_or(*r);
        if self.body.result_regs.contains(&r64) || self.body.reg_names.contains_key(&r64) {
            return true;
        }
        self.scopes.iter().rev().any(|s| {
            s.values().any(|b| match &b.operand {
                Operand::Reg(br) => {
                    br.resize(yana_ast::reg::RegSize::R64).unwrap_or(*br) == r64
                }
                _ => false,
            })
        })
    }

    fn lower_alt(&mut self, dst: &Place, op: AssignOp, src: &Value, modifier: &AltModifier, span: Span) {
        // A group destination is an alias for several places: `alt g = b"...";`
        // (also via a name bound with `bind n @ group(g)`).
        let group = match dst {
            Place::Group { name, span: gspan } => match self.lookup_group(name).cloned() {
                Some(g) => Some(g),
                None => {
                    self.err("unknown-group", format!("group `{name}` is not declared{}", self.suggest(name)), *gspan);
                    None
                }
            },
            Place::Named { name, .. } if self.lookup(name).is_none() => {
                self.lookup_group(name).cloned()
            }
            _ => None,
        };
        if let Some(g) = group {
            if op != AssignOp::Assign {
                self.err("group-op", "a group can only be assigned with `=`", span);
                return;
            }
            if *modifier != AltModifier::None {
                self.err("group-modifier", "§12 modifiers are not supported on a group yet", span);
                return;
            }
            self.lower_group_write(&g, src, span);
            return;
        }
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
                    self.err("unknown-name", format!("`{name}` is not bound here{}", self.suggest(name)), span);
                    return;
                }
                _ => {}
            }
        }
        // §4.2: `alt` mutates a place that already exists. A raw register is
        // only writable after it has been declared with `bind` (or is part of
        // the function's parameters/results) — no implicit register writes.
        if let Place::Reg { reg, span: rspan, .. } = dst {
            if !self.register_bound(reg) {
                self.err_help(
                    "alt-unbound-reg",
                    format!("`{}` is not bound here; `alt` mutates existing places (§4.2)", reg.name()),
                    format!("declare it first: `bind mut name @ {}: u64 = <initial>;`", reg.name()),
                    *rspan,
                );
                return;
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
                    self.err("unknown-name", format!("`{name}` is not bound here{}", self.suggest(name)), span);
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
                self.err("unknown-call", format!("no function or extern named `{name}`{}", self.suggest(name)), name_span);
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

        // §5.3 stack arguments: pushed right-to-left before the register
        // args, so the callee sees them at [rbp+16], [rbp+24], ... The caller
        // cleans them up after the call.
        let mut stack_slots = 0u32;
        for (p, slot) in info.params.iter().zip(slots.iter()).rev() {
            if p.stack.is_none() {
                continue;
            }
            let Some(a) = slot else { continue };
            if ty_bits(&p.ty, &self.target) > 64 {
                self.err_help(
                    "stack-arg-too-big",
                    format!("stack argument `{}` is wider than 8 bytes", p.name),
                    "pass a pointer to the value instead",
                    a.span,
                );
                continue;
            }
            let src = match &a.value {
                Value::AddrOf { .. } => {
                    self.err(
                        "stack-arg-addr",
                        "address arguments need a register parameter",
                        a.span,
                    );
                    continue;
                }
                v => match self.resolve_value(v) {
                    Some((op, _)) => op,
                    None => continue,
                },
            };
            match &src {
                Operand::Imm(v) if *v < i32::MIN as i64 || *v > i32::MAX as i64 => {
                    self.err_help(
                        "stack-arg-imm",
                        "this immediate does not fit the `push imm32` form",
                        "bind it to a register first",
                        a.span,
                    );
                    continue;
                }
                _ => {}
            }
            self.emit(Insn::Push { src, size: 64 });
            stack_slots += 1;
        }

        // emit argument movs
        for (p, slot) in info.params.iter().zip(slots.iter()) {
            if p.stack.is_some() {
                continue;
            }
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

        // §5.3 caller cleanup: drop the stack arguments.
        for _ in 0..stack_slots {
            self.emit(Insn::StackSlot { grow: false });
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
                    Binding { operand: operand.clone(), ty: ty.clone(), mutable: false, volatile: false, is_param: false, span },
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
                                volatile: false,
                                is_param: false,
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
            Place::Stack { size, ty, .. } => ty
                .as_ref()
                .map(|t| ty_bits(t, &self.target))
                .unwrap_or_else(|| size.map(|s| s * 8).unwrap_or(64)),
            Place::Group { .. } => 64,
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
                self.err("unknown-name", format!("`{name}` is not bound here{}", self.suggest(name)), *span);
                None
            }
            Place::Section { span, .. } => {
                self.err("section-place", "a section is not an operand", *span);
                None
            }
            Place::Stack { size, ty, span } => {
                let bits = ty
                    .as_ref()
                    .map(|t| ty_bits(t, &self.target))
                    .unwrap_or_else(|| size.map(|s| s * 8).unwrap_or(64));
                let bytes = (bits / 8).max(1);
                Some(Operand::Mem(self.stack_slot(bytes, bits, *span)))
            }
            Place::Group { name, span } => {
                self.err_help(
                    "group-place",
                    format!("`group({name})` is not a single place"),
                    "use it with `bind`/`alt`/`push`/`pop`, where it expands to its members",
                    *span,
                );
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
                        self.err("unknown-name", format!("`{name}` is not bound here{}", self.suggest(name)), raw.span);
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
            Value::Bytes { bytes, span } => {
                if bytes.len() > 8 {
                    self.err_help(
                        "byte-string-too-long",
                        format!(
                            "byte string is {} bytes; an immediate is at most 8",
                            bytes.len()
                        ),
                        "bind the bytes in .rodata and pass their address instead",
                        *span,
                    );
                    return None;
                }
                let mut buf = [0u8; 8];
                buf[..bytes.len()].copy_from_slice(bytes);
                Some((Operand::Imm(i64::from_le_bytes(buf)), 64))
            }
            Value::Str { span, .. } => {
                self.err_help(
                    "str-value",
                    "string literals live in static data; bind it to .rodata first (§7)",
                    "use `b\"...\"` for a ≤8-byte immediate",
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
                self.err("unknown-name", format!("`{name}` is not bound here{}", self.suggest(name)), *span);
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

    // =====================================================================
    // Groups and frame slots (§3)
    // =====================================================================

    /// Validate and register a `group (name) | places |;` declaration.
    fn declare_group(&mut self, g: &yana_ast::GroupDecl, global: bool) {
        let mut places: Vec<Place> = Vec::new();
        let mut seen: Vec<String> = Vec::new();
        let mut ok = true;
        for p in &g.places {
            match p {
                Place::Reg { reg, span, .. } => {
                    if seen.iter().any(|r| r == reg.name()) {
                        self.err(
                            "group-dup-reg",
                            format!("register `{}` appears twice in group `{}`", reg.name(), g.name),
                            *span,
                        );
                        ok = false;
                    }
                    seen.push(reg.name().to_string());
                    places.push(p.clone());
                }
                Place::Stack { .. } => places.push(p.clone()),
                other => {
                    self.err_help(
                        "group-member",
                        "a group member must be a register or `stack`/`stack(N)`",
                        "e.g. `group (buf) | rax, stack(16), rbx |;`",
                        other.span(),
                    );
                    ok = false;
                }
            }
        }
        if places.is_empty() {
            self.err("group-empty", format!("group `{}` has no places", g.name), g.span);
            ok = false;
        }
        if !ok {
            return;
        }
        let def = GroupDef { places, span: g.span };
        if global {
            if self.global_groups.insert(g.name.clone(), def).is_some() {
                self.err(
                    "dup-group",
                    format!("group `{}` is already declared", g.name),
                    g.name_span,
                );
            }
        } else if let Some(top) = self.group_scopes.last_mut() {
            if top.insert(g.name.clone(), def).is_some() {
                self.err(
                    "dup-group",
                    format!("group `{}` is already declared in this scope", g.name),
                    g.name_span,
                );
            }
        }
    }

    /// Size of one group chunk in bytes (a register's width or a slot's size).
    fn place_bytes(&self, p: &Place) -> Option<u32> {
        match p {
            Place::Reg { reg, .. } => Some(reg.size().bits() / 8),
            Place::Stack { size, ty, .. } => Some(
                ty.as_ref()
                    .map(|t| ty_bits(t, &self.target) / 8)
                    .unwrap_or_else(|| size.unwrap_or(8)),
            ),
            _ => None,
        }
    }

    /// Expand `group(name)` items into their member places. `reverse` is used
    /// by `push` so that the bytes end up in memory in declaration order.
    fn expand_group_items(&mut self, items: &[Place], reverse: bool, span: Span) -> Vec<Place> {
        let mut out = Vec::new();
        for it in items {
            let def = match it {
                Place::Group { name, span: gspan } => match self.lookup_group(name).cloned() {
                    Some(g) => Some(g),
                    None => {
                        self.err("unknown-group", format!("group `{name}` is not declared{}", self.suggest(name)), *gspan);
                        None
                    }
                },
                _ => None,
            };
            let Some(def) = def else {
                out.push(it.clone());
                continue;
            };
            if def.places.iter().any(|p| matches!(p, Place::Stack { .. })) {
                self.err_help(
                    "group-stack-push",
                    "a group with `stack` slots cannot be pushed or popped",
                    "the slots already live in the frame; push/pop only register members",
                    span,
                );
                continue;
            }
            let mut members = def.places.clone();
            if reverse {
                members.reverse();
            }
            out.extend(members);
        }
        out
    }

    /// Extract the bytes an initializer provides, plus whether `.aligned` was
    /// requested (zero-fill the remaining group places).
    fn bytes_of_value(&mut self, v: &Value) -> Option<(Vec<u8>, bool)> {
        match v {
            Value::Bytes { bytes, .. } => Some((bytes.clone(), false)),
            Value::Field { base, name, span } if name == "aligned" => match base.as_ref() {
                Value::Bytes { bytes, .. } => Some((bytes.clone(), true)),
                _ => {
                    self.err("aligned-base", "`.aligned` needs a `b\"...\"` byte string", *span);
                    None
                }
            },
            Value::Const { expr, .. } => match self.eval_const_expr(expr) {
                Ok(CValue::Int(i)) => Some((i.to_le_bytes().to_vec(), false)),
                Ok(CValue::Array(items)) => Some((
                    items.iter().map(|b| b.as_int().unwrap_or(0) as u8).collect(),
                    false,
                )),
                Ok(_) => {
                    self.err("group-init", "a group needs a byte-string initializer", v.span());
                    None
                }
                Err(d) => {
                    self.diagnostics.push(d);
                    None
                }
            },
            other => {
                self.err_help(
                    "group-init",
                    format!(
                        "a group needs a byte-string initializer, got {}",
                        init_kind_name(other)
                    ),
                    "e.g. `bind g @ group(buf) = b\"text\";`",
                    other.span(),
                );
                None
            }
        }
    }

    /// Distribute the bytes of a `b"..."` value over a group's places.
    ///
    /// Chunk order follows the declaration order; each chunk is little-endian
    /// and zero-padded to the member width. Members that receive no bytes are
    /// left untouched unless `.aligned` asks for a full zero-fill.
    fn lower_group_write(&mut self, g: &GroupDef, v: &Value, span: Span) {
        let Some((bytes, aligned)) = self.bytes_of_value(v) else { return };
        let mut cap = 0u32;
        for p in &g.places {
            cap += self.place_bytes(p).unwrap_or(0);
        }
        if bytes.len() as u32 > cap {
            self.err_help(
                "byte-string-too-long",
                format!("byte string is {} bytes but the group holds only {cap}", bytes.len()),
                "use a bigger group, `.aligned`, or bind the bytes in .rodata",
                span,
            );
            return;
        }
        let mut pos = 0usize;
        for p in &g.places {
            let n = self.place_bytes(p).unwrap_or(0) as usize;
            if pos >= bytes.len() && !aligned {
                break;
            }
            let start = pos.min(bytes.len());
            let end = (pos + n).min(bytes.len());
            let chunk = &bytes[start..end];
            pos += n;
            let Some(dst) = self.resolve_place(p) else { continue };
            let bits = (n * 8) as u32;
            match dst {
                Operand::Reg(_) => {
                    let mut buf = [0u8; 8];
                    let take = chunk.len().min(8);
                    buf[..take].copy_from_slice(&chunk[..take]);
                    self.emit(Insn::Mov {
                        dst,
                        src: Operand::Imm(i64::from_le_bytes(buf)),
                        size: bits,
                    });
                }
                Operand::Mem(m) => {
                    // `mov [mem], imm64` does not exist (the imm32 form is
                    // sign-extended), so store exact 4-byte pieces instead of
                    // burning a scratch register.
                    let mut off = 0usize;
                    while off < n {
                        let piece = (n - off).min(4);
                        let mut buf = [0u8; 4];
                        let avail = chunk.len().saturating_sub(off).min(piece);
                        if avail > 0 {
                            buf[..avail].copy_from_slice(&chunk[off..off + avail]);
                        }
                        let mut m2 = m.clone();
                        if let Displacement::Const(d) = m2.disp {
                            m2.disp = Displacement::Const(d + off as i64);
                        }
                        self.emit(Insn::Mov {
                            dst: Operand::Mem(m2),
                            src: Operand::Imm(u32::from_le_bytes(buf) as i64),
                            size: (piece * 8) as u32,
                        });
                        off += piece;
                    }
                }
                _ => self.err("group-dst", "this group member is not writable", p.span()),
            }
        }
    }

    /// Allocate (or reuse) a frame slot and return its `[rbp - off]` operand.
    fn stack_slot(&mut self, bytes: u32, bits: u32, span: Span) -> MemOp {
        let key = (span.lo, span.hi);
        let off = match self.stack_slots.get(&key) {
            Some(o) => *o,
            None => {
                self.frame_used = (self.frame_used + 7) & !7;
                self.frame_used += bytes.max(1);
                let off = self.frame_used as i64;
                self.stack_slots.insert(key, off);
                off
            }
        };
        MemOp {
            base: Some(Reg::Gpr {
                base: yana_ast::reg::GprBase::Bp,
                size: yana_ast::reg::RegSize::R64,
            }),
            index: None,
            scale: 1,
            disp: Displacement::Const(-off),
            size: bits,
            rip_relative: false,
        }
    }

    /// Wrap the lowered body in a frame when it uses `stack` slots:
    /// `push rbp; mov rbp, rsp; sub rsp, N` … `mov rsp, rbp; pop rbp` before
    /// every `ret`. Functions without slots stay zero-overhead.
    fn apply_frame(&mut self) {
        if self.frame_used == 0 && !self.needs_frame {
            return;
        }
        let size = (self.frame_used + 15) & !15;
        let rsp = Reg::Gpr {
            base: yana_ast::reg::GprBase::Sp,
            size: yana_ast::reg::RegSize::R64,
        };
        let rbp = Reg::Gpr {
            base: yana_ast::reg::GprBase::Bp,
            size: yana_ast::reg::RegSize::R64,
        };
        let span = self.cur_fn_span;

        let old = std::mem::take(&mut self.body.insns);
        let mut map = vec![0usize; old.len()];
        let mut out: Vec<SpannedInsn> = Vec::with_capacity(old.len() + 8);
        out.push(SpannedInsn::new(Insn::Push { src: Operand::Reg(rbp), size: 64 }, span));
        // mov rbp, rsp — the frame base
        out.push(SpannedInsn::new(
            Insn::Mov { dst: Operand::Reg(rbp), src: Operand::Reg(rsp), size: 64 },
            span,
        ));
        if size > 0 {
            out.push(SpannedInsn::new(
                Insn::Sub { dst: Operand::Reg(rsp), src: Operand::Imm(size as i64), size: 64 },
                span,
            ));
        }
        for (i, si) in old.into_iter().enumerate() {
            if matches!(si.insn, Insn::Ret) {
                out.push(SpannedInsn::new(
                    Insn::Mov { dst: Operand::Reg(rsp), src: Operand::Reg(rbp), size: 64 },
                    si.span,
                ));
                out.push(SpannedInsn::new(Insn::Pop { dst: Operand::Reg(rbp), size: 64 }, si.span));
            }
            map[i] = out.len();
            out.push(si);
        }
        self.body.insns = out;

        for (idx, ..) in self.pending_jumps.iter_mut() {
            if let Some(&m) = map.get(*idx) {
                *idx = m;
            }
        }
        for def in &mut self.body.label_defs {
            if let Some(&m) = map.get(def.at_insn) {
                def.at_insn = m;
            }
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
                                volatile: false,
                                is_param: false,
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
        Stmt::Unbind { span, .. }
        | Stmt::Bind { span, .. }
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
        Stmt::Group(g) => g.span,
        Stmt::Breakpoint { span } | Stmt::Trap { span } | Stmt::Assert { span, .. } => *span,
        Stmt::Debug(b) => b.span,
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
        Value::Bytes { .. } => "byte string",
        Value::AddrOf { .. } => "address-of",
        Value::Cast { .. } => "cast",
        Value::Mul { .. } => "wide multiply",
        Value::Field { .. } => "field access",
        Value::Const { .. } => "const block",
    }
}

/// Human name for an unsupported contract expression shape (§14.4).
fn contract_shape_name(e: &yana_ast::ConstExpr) -> &'static str {
    match e {
        yana_ast::ConstExpr::If { .. } => "if-expression",
        yana_ast::ConstExpr::Call { .. } => "function call",
        yana_ast::ConstExpr::Array { .. } => "array literal",
        yana_ast::ConstExpr::Tuple { .. } => "tuple literal",
        yana_ast::ConstExpr::Repeat { .. } => "repeat literal",
        yana_ast::ConstExpr::Bytes { .. } => "byte string",
        _ => "expression",
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
        | yana_ast::ConstExpr::Repeat { span, .. }
        | yana_ast::ConstExpr::Bytes { span, .. } => *span,
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
