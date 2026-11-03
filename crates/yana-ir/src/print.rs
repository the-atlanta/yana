//! LLVM-style textual dump of the SSA-IR.
//!
//! The printer is deliberately annotation-heavy: every instruction can carry
//! `[resolve]`, `[ssa]`, `[abi]`, `[opt]`, `[verify]` and `[bind]` notes, and
//! every value/instruction gets `!span` / `!bind` metadata. That is the whole
//! point of the format — a human and a tool can both see *why* the IR looks
//! the way it does without re-parsing the source.

use std::collections::HashMap;
use std::fmt::Write as _;

use yana_ast::reg::Reg;
use yana_ast::ty::Ty;
use yana_ast::Span;
use yana_codegen::ir::SymbolKind;

use crate::model::*;

/// Knobs for [`print_module`].
pub struct PrintOptions<'a> {
    /// Emit `; [tag] ...` annotations above instructions.
    pub comments: bool,
    /// Emit the module statistics header.
    pub stats: bool,
    /// Emit `!span` / `!bind` / `!fn` metadata and the metadata section.
    pub metadata: bool,
    /// Source text, used to turn byte spans into line/column pairs.
    pub source_text: Option<&'a str>,
    /// Name used in `source_filename` and `!span` metadata.
    pub module_name: Option<&'a str>,
}

impl<'a> Default for PrintOptions<'a> {
    fn default() -> Self {
        PrintOptions {
            comments: true,
            stats: true,
            metadata: true,
            source_text: None,
            module_name: None,
        }
    }
}

/// Render a whole module.
pub fn print_module(module: &Module, opts: &PrintOptions<'_>) -> String {
    let mut p = Printer::new(opts, module);
    p.render(module)
}

/// Render one function (without the module header / metadata section).
pub fn print_function(module: &Module, function: &Function, opts: &PrintOptions<'_>) -> String {
    let mut p = Printer::new(opts, module);
    let mut out = String::new();
    p.function(&mut out, function);
    out
}

// ---------------------------------------------------------------------------
// metadata arena
// ---------------------------------------------------------------------------

#[derive(Default)]
struct Meta {
    nodes: Vec<String>,
    map: HashMap<String, usize>,
}

impl Meta {
    fn add(&mut self, text: String) -> usize {
        if let Some(&id) = self.map.get(&text) {
            return id;
        }
        let id = self.nodes.len();
        self.nodes.push(text);
        self.map.insert(self.nodes[id].clone(), id);
        id
    }

    fn reference(&mut self, text: String) -> String {
        format!("!{}", self.add(text))
    }

    fn emit(&self, out: &mut String) {
        for (id, node) in self.nodes.iter().enumerate() {
            let _ = writeln!(out, "!{id} = {node}");
        }
    }
}

// ---------------------------------------------------------------------------
// printer
// ---------------------------------------------------------------------------

struct Printer<'a> {
    opts: &'a PrintOptions<'a>,
    meta: Meta,
    file: String,
}

impl<'a> Printer<'a> {
    fn new(opts: &'a PrintOptions<'a>, module: &Module) -> Self {
        let file = opts
            .module_name
            .map(|s| s.to_string())
            .unwrap_or_else(|| module.source.clone());
        Printer { opts, meta: Meta::default(), file }
    }

    // -- module -------------------------------------------------------------

    fn render(&mut self, m: &Module) -> String {
        let mut out = String::new();

        let module_meta = self.meta.add(format!(
            "!{{!\"YANA\", !\"{}\", !\"ssa-ir\", !\"physical-register-ssa\"}}",
            env!("CARGO_PKG_VERSION")
        ));
        let passes_meta = self.meta.add(
            "!{!\"lex\", !\"parse\", !\"resolve\", !\"ssa-construct\", !\"verify\", !\"dump\"}"
                .to_string(),
        );

        self.header(&mut out, m);
        let _ = writeln!(out, "source_filename = \"{}\"", self.file);
        let _ = writeln!(out, "target triple = \"{}\"", m.target);
        let _ = writeln!(
            out,
            "target datalayout = \"e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-f80:128-n8:16:32:64-S128\""
        );
        let _ = writeln!(out, "target cpu = \"generic\"");
        let _ = writeln!(out, "target features = \"+cx16,+sse2\"");
        let _ = writeln!(out);
        let _ = writeln!(out, "!yana.module = !{{!{module_meta}}}");
        let _ = writeln!(out, "!yana.passes = !{{!{passes_meta}}}");
        let _ = writeln!(out);

        for ext in &m.externs {
            self.extern_decl(&mut out, m, ext);
        }

        for f in &m.functions {
            self.function(&mut out, f);
        }

        if self.opts.metadata {
            let _ = writeln!(out, "; ===========================================================================");
            let _ = writeln!(out, "; metadata");
            let _ = writeln!(out, "; ===========================================================================");
            let _ = writeln!(out);
            self.meta.emit(&mut out);
        }

        out
    }

    fn header(&self, out: &mut String, m: &Module) {
        let _ = writeln!(out, "; ============================================================================");
        let _ = writeln!(out, ";  YANA SSA-IR  ·  module dump");
        let _ = writeln!(out, ";  --------------------------------------------------------------------------");
        let _ = writeln!(out, ";  source        {}", self.file);
        let _ = writeln!(out, ";  compiler      yana {} · ssa-construct", env!("CARGO_PKG_VERSION"));
        let _ = writeln!(out, ";  pipeline      lex -> parse -> resolve -> ssa-construct -> dump");
        let _ = writeln!(out, ";  target        {}", m.target);
        if m.target.contains("linux") {
            let _ = writeln!(out, ";  abi           SysV AMD64 + Linux syscall ABI (no libc)");
        }
        if self.opts.stats {
            let _ = writeln!(out, ";  --------------------------------------------------------------------------");
            let _ = writeln!(
                out,
                ";  stats         symbols {} · functions {} · externs {} · blocks {}",
                m.stats.symbols, m.stats.functions, m.stats.externs, m.stats.blocks
            );
            let _ = writeln!(
                out,
                ";                instructions {} · ssa values {} · phi {}",
                m.stats.insts, m.stats.values, m.stats.phis
            );
        }
        let _ = writeln!(out, ";  --------------------------------------------------------------------------");
        let _ = writeln!(out, ";  model         physical-register SSA. Every write to an architectural");
        let _ = writeln!(out, ";                register creates a new version (%rax.0, %rax.1, …).");
        let _ = writeln!(out, ";                Memory, flags and rsp are explicit state values, so the");
        let _ = writeln!(out, ";                def-use graph covers the whole machine state.");
        let _ = writeln!(out, "; ============================================================================");
        let _ = writeln!(out);
    }

    // -- externs ------------------------------------------------------------

    fn extern_decl(&mut self, out: &mut String, m: &Module, ext: &Extern) {
        let ret = ret_str(&ext.ret);
        let ret_comment = ret_comment_str(&ext.ret);
        let sig_params = ext
            .params
            .iter()
            .map(|p| {
                let home = p
                    .reg
                    .map(|r| r.name().to_string())
                    .or_else(|| p.stack.map(|s| format!("[rbp+{s}]")))
                    .unwrap_or_else(|| "?".into());
                format!("{} @ {}: {}", p.name, home, ty_str(&p.ty))
            })
            .collect::<Vec<_>>()
            .join(", ");
        let params = ext
            .params
            .iter()
            .map(|p| format!("{} %{}", ty_str(&p.ty), p.name))
            .collect::<Vec<_>>()
            .join(", ");
        let _ = writeln!(out, "; ===========================================================================");
        let _ = writeln!(out, "; extern fn {}({}) -> {}{}", ext.name, sig_params, ret_comment, match ext.syscall {
            Some(n) => format!("  #[syscall({n})]"),
            None => String::new(),
        });
        let _ = writeln!(out, "; ===========================================================================");
        let _ = writeln!(out, ";");
        if let Some(n) = ext.syscall {
            let _ = writeln!(out, "; [resolve] номер syscall'а — факт контракта (`syscall {n}`), а не аргумент.");
            let _ = writeln!(out, ";           Символ не линкуется ни с каким libc, вызов идёт через `syscall`.");
        } else {
            let _ = writeln!(out, "; [resolve] `extern \"C\"` — реальный символ линкера, не syscall.");
        }
        let _ = writeln!(out, "; [abi]     {}.", abi_map(ext));
        let _ = writeln!(out, "; [effects] {}.", extern_effects(ext));
        let _ = writeln!(out, "; [clobber] {}.", regs_list(&ext.clobbers));
        let _ = writeln!(out);

        let _ = writeln!(out, "declare {ret} @{}({params})", ext.name);
        if let Some(n) = ext.syscall {
            let _ = writeln!(out, "    syscall {n}");
        }
        let _ = writeln!(out, "    abi = {}", abi_map(ext));
        let _ = writeln!(out, "    effects = {{ {} }}", extern_effects(ext));
        let _ = writeln!(out, "    clobbers = [{}]", regs_list(&ext.clobbers));
        if !ext.preserves.is_empty() {
            let _ = writeln!(out, "    preserves = [{}]", regs_list(&ext.preserves));
        }
        let contract = self.meta.reference(contract_meta(ext));
        let span = self.span_ref(ext.span);
        if self.opts.metadata {
            let _ = writeln!(out, "    !contract {contract}");
            if let Some(span) = span {
                let _ = writeln!(out, "    !span {span}");
            }
        }
        let _ = writeln!(out);
    }

    // -- functions ----------------------------------------------------------

    fn function(&mut self, out: &mut String, f: &Function) {
        let params = f
            .params
            .iter()
            .map(|p| format!("{} %{}", ty_str(&p.ty), p.name))
            .collect::<Vec<_>>()
            .join(", ");
        let sig_params = f
            .params
            .iter()
            .map(|p| format!("{} @ {}: {}", p.name, p.reg.name(), ty_str(&p.ty)))
            .collect::<Vec<_>>()
            .join(", ");
        let ret = ret_str(&f.ret);
        let ret_comment = ret_sig_str(f);
        let _ = writeln!(out, "; ===========================================================================");
        let _ = writeln!(out, "; fn {}({}) -> {}", f.source_name, sig_params, ret_comment);
        if !f.clobbers.is_empty() {
            let _ = writeln!(out, ";     clobbers: {}", regs_list(&f.clobbers));
        }
        if !f.preserves.is_empty() {
            let _ = writeln!(out, ";     preserves: {}", regs_list(&f.preserves));
        }
        let _ = writeln!(out, "; ===========================================================================");
        let _ = writeln!(out, ";");
        if f.is_entry {
            let _ = writeln!(out, "; [resolve] `#[entry]` делает символ global; исходное имя `{}` остаётся в !fn.", f.source_name);
            let _ = writeln!(out, "; [abi]     вход из ядра, а не из call: rsp выровнен, возвратного адреса нет.");
        } else {
            let _ = writeln!(out, "; [resolve] обычная функция; аргументы и результат — по ABI-контракту.");
        }
        if !f.params.is_empty() {
            let _ = writeln!(
                out,
                "; [abi]     entry state: {}",
                f.params
                    .iter()
                    .map(|p| format!("{} -> {} ({})", p.name, p.value_name(f), ty_str(&p.ty)))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        let _ = writeln!(out);

        let symbol_line = if f.name != f.source_name {
            format!("\n    symbol = \"{}\"", f.name)
        } else {
            String::new()
        };
        let _ = writeln!(out, "define {ret} @{}({params}){symbol_line}", f.source_name);
        let _ = writeln!(out, "    abi = {{ {} }}", fn_abi(f));
        let _ = writeln!(out, "    clobbers = [{}]", regs_list(&f.clobbers));
        let _ = writeln!(out, "    preserves = [{}]", regs_list(&f.preserves));
        let _ = writeln!(
            out,
            "    stack = {{ frame: {}, max_depth: {}, alignment: {} }}",
            f.stack.frame, f.stack.max_depth, f.stack.alignment
        );
        if self.opts.metadata {
            let fm = self.meta.reference(fn_meta(f));
            let _ = writeln!(out, "    !fn {fm}");
            if let Some(span) = self.span_ref(f.span) {
                let _ = writeln!(out, "    !span {span}");
            }
        }
        let _ = writeln!(out, "{{");

        let use_count = use_counts(f);
        let def_binds = def_bindings(f);

        for block in &f.blocks {
            self.block(out, f, block, &use_count, &def_binds);
        }

        self.binding_table(out, f);

        let _ = writeln!(out, "}}");
        let _ = writeln!(out);
    }

    fn block(
        &mut self,
        out: &mut String,
        f: &Function,
        block: &Block,
        use_count: &[usize],
        def_binds: &HashMap<ValueId, Vec<usize>>,
    ) {
        let label = block_label(f, block.id);
        if !block.reachable {
            let _ = writeln!(out, "; [ssa] unreachable block: no path from entry");
        }
        let _ = writeln!(out, "{label}:");
        if self.opts.comments && !block.preds.is_empty() {
            let preds = block
                .preds
                .iter()
                .map(|p| block_label(f, *p))
                .collect::<Vec<_>>()
                .join(", ");
            let succs = block
                .succs
                .iter()
                .map(|p| block_label(f, *p))
                .collect::<Vec<_>>()
                .join(", ");
            let _ = writeln!(out, "    ; [cfg] preds: {preds} | succs: {}", if succs.is_empty() { "-".into() } else { succs });
        }

        for (idx, inst) in block.insts.iter().enumerate() {
            if self.opts.comments {
                self.annotations(out, f, block, idx, inst, use_count, def_binds);
            }
            let mut line = format!("    {}", inst.text);
            if self.opts.metadata {
                let mut refs: Vec<String> = Vec::new();
                for v in &inst.defs {
                    if let Some(binds) = def_binds.get(v) {
                        for b in binds {
                            let bind = &f.bindings[*b];
                            let m = self.bind_ref(bind);
                            refs.push(format!("!bind {m}"));
                        }
                    }
                }
                if let Some(span) = self.span_ref(inst.span) {
                    refs.push(format!("!span {span}"));
                }
                if !refs.is_empty() {
                    let _ = write!(line, ", {}", refs.join(", "));
                }
            }
            let _ = writeln!(out, "{line}");
        }
        let _ = writeln!(out);
    }

    fn annotations(
        &mut self,
        out: &mut String,
        f: &Function,
        _block: &Block,
        _idx: usize,
        inst: &Inst,
        use_count: &[usize],
        def_binds: &HashMap<ValueId, Vec<usize>>,
    ) {
        if let Some(c) = &inst.comment {
            let _ = writeln!(out, "    ; {c}");
        }

        for v in &inst.defs {
            if let Some(binds) = def_binds.get(v) {
                for b in binds {
                    let bind = &f.bindings[*b];
                    let _ = writeln!(
                        out,
                        "    ; [bind] {} -> {} ({}){}",
                        bind.name,
                        f.value_name(bind.value.unwrap_or(*v)),
                        bind_kind_str(bind.kind),
                        match bind.retired_at {
                            Some(at) => format!(", retired at insn {at}"),
                            None => String::new(),
                        }
                    );
                }
            }
            let value = &f.values[*v as usize];
            if value.partial {
                let _ = writeln!(out, "    ; [ssa] partial {}-bit write; upper bits preserved", value.width);
            }
        }

        match &inst.op {
            Op::Push { slot, .. } if use_count.get(*slot as usize).copied().unwrap_or(0) == 0 => {
                let _ = writeln!(
                    out,
                    "    ; [opt] dead stack slot {}; DSE candidate at -O1",
                    f.value_name(*slot)
                );
            }
            Op::Call { results, .. } => {
                for v in results {
                    if use_count.get(*v as usize).copied().unwrap_or(0) == 0 {
                        let name = f.value_name(*v);
                        let _ = writeln!(
                            out,
                            "    ; [opt] dead result {name}; call kept for its effects"
                        );
                    }
                }
            }
            Op::Mov { src: Operand::Imm(i), .. } => {
                let _ = writeln!(out, "    ; [opt] constant materialization: {i}");
            }
            Op::Ret { value: Some(v) } => {
                let value = &f.values[*v as usize];
                if value.undef {
                    let _ = writeln!(out, "    ; [verify] ERROR: return value is undefined");
                } else {
                    let _ = writeln!(out, "    ; [verify] return value is defined on this path");
                }
            }
            Op::Jcc { .. } => {
                let _ = writeln!(out, "    ; [verify] branch reads the flags value defined above");
            }
            Op::VirtUnbind { name } => {
                let _ = writeln!(
                    out,
                    "    ; [bind] name `{name}` retired; the SSA value stays valid until its last use"
                );
            }
            _ => {}
        }
    }

    fn binding_table(&mut self, out: &mut String, f: &Function) {
        if !self.opts.comments || f.bindings.is_empty() {
            return;
        }
        let _ = writeln!(out, "    ; ---- bindings -------------------------------------------------------");
        for b in &f.bindings {
            let value = b
                .value
                .map(|v| f.value_name(v))
                .unwrap_or_else(|| "<none>".into());
            let range = match b.retired_at {
                Some(end) => format!("insn {}..{}", b.active_from, end),
                None => format!("insn {}..end", b.active_from),
            };
            let _ = writeln!(
                out,
                "    ; [bindings] {} -> {} ({}, {})",
                b.name,
                value,
                bind_kind_str(b.kind),
                range
            );
        }
        let _ = writeln!(out);
    }

    // -- metadata helpers ---------------------------------------------------

    fn span_ref(&mut self, span: Span) -> Option<String> {
        if !self.opts.metadata || span.is_dummy() {
            return None;
        }
        let node = match self.opts.source_text {
            Some(src) => {
                let (l1, c1) = line_col(src, span.lo);
                let (l2, c2) = line_col(src, span.hi);
                format!(
                    "!{{!\"{}\", i32 {l1}, i32 {c1}, i32 {l2}, i32 {c2}}}",
                    self.file
                )
            }
            None => format!("!{{!\"{}\", i32 {}, i32 {}}}", self.file, span.lo, span.hi),
        };
        Some(self.meta.reference(node))
    }

    fn bind_ref(&mut self, b: &Binding) -> String {
        let reg = b
            .reg
            .map(|r| r.name().to_string())
            .unwrap_or_else(|| "stack".into());
        self.meta.reference(format!(
            "!{{!\"bind\", !\"{}\", !\"{}\", !\"{}\", !\"{}\"}}",
            b.name,
            bind_kind_str(b.kind),
            reg,
            ty_str(&b.ty)
        ))
    }
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

impl Param {
    fn value_name(&self, f: &Function) -> String {
        f.value_name(self.value)
    }
}

impl Function {
    fn value_name(&self, v: ValueId) -> String {
        self.values
            .get(v as usize)
            .map(|v| v.name.clone())
            .unwrap_or_else(|| format!("%v{v}"))
    }
}

fn block_label(f: &Function, id: BlockId) -> String {
    f.blocks
        .get(id as usize)
        .and_then(|b| b.label.clone())
        .unwrap_or_else(|| format!("bb{id}"))
}

fn use_counts(f: &Function) -> Vec<usize> {
    let mut counts = vec![0usize; f.values.len()];
    for b in &f.blocks {
        for i in &b.insts {
            for u in &i.uses {
                if let Some(c) = counts.get_mut(*u as usize) {
                    *c += 1;
                }
            }
        }
    }
    counts
}

fn def_bindings(f: &Function) -> HashMap<ValueId, Vec<usize>> {
    let mut map: HashMap<ValueId, Vec<usize>> = HashMap::new();
    for (i, b) in f.bindings.iter().enumerate() {
        if let Some(v) = b.value {
            map.entry(v).or_default().push(i);
        }
    }
    map
}

fn ret_comment_str(r: &RetTy) -> String {
    match r {
        RetTy::Never => "!".into(),
        other => ret_str(other),
    }
}

fn ret_sig_str(f: &Function) -> String {
    match &f.ret {
        RetTy::Never => "!".into(),
        RetTy::None => "()".into(),
        RetTy::Single(t) => {
            let reg = f
                .bindings
                .iter()
                .find(|b| b.kind == BindKind::ReturnPlace)
                .and_then(|b| b.reg)
                .map(|r| format!("{}: ", r.name()))
                .unwrap_or_default();
            format!("{reg}{}", ty_str(t))
        }
        RetTy::Tuple(ts) => format!(
            "({})",
            ts.iter().map(ty_str).collect::<Vec<_>>().join(", ")
        ),
    }
}

fn ret_str(r: &RetTy) -> String {
    match r {
        RetTy::None => "void".into(),
        RetTy::Never => "noreturn void".into(),
        RetTy::Single(t) => ty_str(t),
        RetTy::Tuple(ts) => format!(
            "{{ {} }}",
            ts.iter().map(ty_str).collect::<Vec<_>>().join(", ")
        ),
    }
}

fn regs_list(regs: &[Reg]) -> String {
    regs.iter().map(|r| r.name()).collect::<Vec<_>>().join(", ")
}

fn bind_kind_str(k: BindKind) -> &'static str {
    match k {
        BindKind::Param => "param",
        BindKind::Local => "local",
        BindKind::Discard => "discard",
        BindKind::ReturnPlace => "return-place",
    }
}

fn fn_abi(f: &Function) -> String {
    let mut parts: Vec<String> = Vec::new();
    for (i, p) in f.params.iter().enumerate() {
        parts.push(format!("{}: {}", if p.name.is_empty() { format!("arg{i}") } else { p.name.clone() }, p.reg.name()));
    }
    match &f.ret {
        RetTy::None | RetTy::Never => parts.push("ret: none".into()),
        RetTy::Single(_) => {
            let reg = f
                .bindings
                .iter()
                .find(|b| b.kind == BindKind::ReturnPlace)
                .and_then(|b| b.reg)
                .map(|r| r.name().to_string())
                .unwrap_or_else(|| "none".into());
            parts.push(format!("ret: {reg}"));
        }
        RetTy::Tuple(_) => parts.push("ret: tuple".into()),
    }
    if f.is_entry {
        parts.push("entry: true".into());
        parts.push(format!("stack_alignment: {}", f.stack.alignment));
    }
    parts.join(", ")
}

fn abi_map(ext: &Extern) -> String {
    let mut parts: Vec<String> = ext
        .params
        .iter()
        .map(|p| {
            let home = p
                .reg
                .map(|r| r.name().to_string())
                .or_else(|| p.stack.map(|s| format!("[rbp+{s}]")))
                .unwrap_or_else(|| "?".into());
            format!("{}: {home}", p.name)
        })
        .collect();
    match &ext.ret {
        RetTy::None => parts.push("ret: none".into()),
        RetTy::Never => parts.push("ret: never".into()),
        RetTy::Single(_) => parts.push("ret: rax".into()),
        RetTy::Tuple(_) => parts.push("ret: tuple".into()),
    }
    format!("{{ {} }}", parts.join(", "))
}

fn extern_effects(ext: &Extern) -> String {
    match ext.syscall {
        Some(0) => "memory: read(argmem), convergent, nounwind".into(),
        Some(1) => "memory: write(argmem), convergent, nounwind".into(),
        Some(60) | Some(231) => "noreturn, sideeffect, nounwind".into(),
        Some(_) => "unknown, convergent".into(),
        None => "memory: readwrite, sideeffect, nounwind".into(),
    }
}

fn contract_meta(ext: &Extern) -> String {
    let mut parts: Vec<String> = vec![
        "!\"contract\"".into(),
        format!("!\"{}\"", ext.name),
    ];
    if let Some(n) = ext.syscall {
        parts.push("!\"syscall\"".into());
        parts.push(format!("i64 {n}"));
    }
    for p in &ext.params {
        parts.push(format!("!\"{}\"", p.name));
        parts.push(format!(
            "!\"{}\"",
            p.reg.map(|r| r.name().to_string()).unwrap_or_else(|| "stack".into())
        ));
        parts.push(format!("!\"{}\"", ty_str(&p.ty)));
    }
    match &ext.ret {
        RetTy::None => {
            parts.push("!\"ret\"".into());
            parts.push("!\"none\"".into());
        }
        RetTy::Never => {
            parts.push("!\"ret\"".into());
            parts.push("!\"never\"".into());
            parts.push("!\"noreturn\"".into());
        }
        RetTy::Single(t) => {
            parts.push("!\"ret\"".into());
            parts.push(format!("!\"{}\"", ty_str(t)));
        }
        RetTy::Tuple(ts) => {
            parts.push("!\"ret\"".into());
            parts.push(format!(
                "!\"{}\"",
                ts.iter().map(ty_str).collect::<Vec<_>>().join(",")
            ));
        }
    }
    format!("!{{{}}}", parts.join(", "))
}

fn fn_meta(f: &Function) -> String {
    let linkage = if f.is_entry { "global" } else { "local" };
    let mut parts: Vec<String> = vec![
        "!\"fn\"".into(),
        format!("!\"{}\"", f.source_name),
        format!("!\"sym#{}\"", f.symbol),
        format!("!\"{linkage}\""),
    ];
    if f.name != f.source_name {
        parts.push(format!("!\"symbol\""));
        parts.push(format!("!\"{}\"", f.name));
    }
    if f.is_entry {
        parts.push("!\"entry\"".into());
        parts.push("i1 true".into());
    }
    if !f.clobbers.is_empty() {
        parts.push("!\"clobbers\"".into());
        parts.push(format!("!\"{}\"", regs_list(&f.clobbers)));
    }
    parts.push("!\"stack\"".into());
    parts.push(format!("i32 {}", f.stack.max_depth));
    parts.push("!\"align\"".into());
    parts.push(format!("i32 {}", f.stack.alignment));
    format!("!{{{}}}", parts.join(", "))
}

fn line_col(src: &str, off: u32) -> (u32, u32) {
    let off = (off as usize).min(src.len());
    let mut line = 1u32;
    let mut col = 1u32;
    for (i, ch) in src.char_indices() {
        if i >= off {
            break;
        }
        if ch == '\n' {
            line += 1;
            col = 1;
        } else {
            col += 1;
        }
    }
    (line, col)
}

#[allow(dead_code)]
fn ty_width(ty: &Ty) -> u32 {
    match ty {
        Ty::U8 | Ty::I8 => 8,
        Ty::U16 | Ty::I16 => 16,
        Ty::U32 | Ty::I32 => 32,
        Ty::U64 | Ty::I64 | Ty::Usize | Ty::Isize | Ty::Ptr(_) => 64,
        _ => 0,
    }
}

#[allow(dead_code)]
fn is_extern(sym: &yana_codegen::ir::Symbol) -> bool {
    matches!(sym.kind, SymbolKind::ExternFn)
}
