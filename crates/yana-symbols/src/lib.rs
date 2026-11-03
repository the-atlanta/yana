//! Symbol extraction from a YANA [`File`] for LSP navigation, hover,
//! go-to-definition, references, rename and document symbols.

use url::Url;
use yana_ast::{File, Item, Stmt, Block, RetSig, Span};

/// Kind of a symbol — maps roughly to LSP `SymbolKind`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SymbolKind {
    /// `bind [mut] name @ ...` (top-level or function-local).
    Bind,
    /// Top-level `bind` into a data section (`.rodata` / `.data` / `.bss`).
    Static,
    /// `fn name(...)`.
    Function,
    /// `extern fn name(...)`.
    ExternFunction,
    /// `const NAME: T = ...`.
    Const,
    /// `const fn NAME(...) -> ...`.
    ConstFunction,
    /// `label ('name) { ... }` — block label (§6).
    Label,
    /// Function parameter `name @ place: ty`.
    Parameter,
    /// A data section (`.text`, `.rodata`, …) appearing in a place.
    Section,
    /// A `use path::name;` import (§10).
    Import,
    /// `group (name) | places |;` — a place-group alias (§3).
    Group,
    /// `struct Name { ... }` — a const-only data layout (§8).
    Struct,
}

/// One symbol with its source span and owning document URI.
#[derive(Debug, Clone)]
pub struct SymbolEntry {
    pub name: String,
    pub kind: SymbolKind,
    pub span: Span,
    pub uri: Url,
    /// Human-readable detail shown in completion / hover.
    pub detail: String,
    /// Enclosing container for document symbols (e.g. function name).
    pub container: Option<String>,
}

/// Collect all top-level and nested symbols from one parsed file.
pub fn collect_symbols(file: &File, uri: &Url) -> Vec<SymbolEntry> {
    let mut out = Vec::new();
    for item in &file.items {
        collect_item(item, uri, None, &mut out);
    }
    out
}

fn collect_item(item: &Item, uri: &Url, container: Option<&str>, out: &mut Vec<SymbolEntry>) {
    match item {
        Item::Fn(f) => {
            out.push(SymbolEntry {
                name: f.sig.name.clone(),
                kind: SymbolKind::Function,
                span: f.sig.name_span,
                uri: uri.clone(),
                detail: format!("fn {} → {}", f.sig.name, ret_summary(&f.sig.ret)),
                container: container.map(|s| s.to_string()),
            });
            collect_block(&f.body, uri, Some(&f.sig.name), out);
        }
        Item::ExternFn(e) => {
            let detail = match e.syscall_number() {
                Some(nr) => match yana_knowledge::syscalls::name_of(nr) {
                    Some(name) => format!("extern fn {} — syscall {nr} ({name})", e.sig.name),
                    None => format!("extern fn {} — syscall {nr}", e.sig.name),
                },
                None => format!("extern fn {}", e.sig.name),
            };
            out.push(SymbolEntry {
                name: e.sig.name.clone(),
                kind: SymbolKind::ExternFunction,
                span: e.sig.name_span,
                uri: uri.clone(),
                detail,
                container: None,
            });
        }
        Item::Const(c) => {
            out.push(SymbolEntry {
                name: c.name.clone(),
                kind: SymbolKind::Const,
                span: c.name_span,
                uri: uri.clone(),
                detail: format!("const {}: {:?}", c.name, c.ty),
                container: None,
            });
        }
        Item::ConstFn(cf) => {
            out.push(SymbolEntry {
                name: cf.name.clone(),
                kind: SymbolKind::ConstFunction,
                span: cf.name_span,
                uri: uri.clone(),
                detail: "const fn".to_string(),
                container: None,
            });
        }
        Item::Static(s) => {
            let ty = s
                .place
                .ty()
                .map(|t| format!("{:?}", t))
                .unwrap_or_else(|| "?".to_string());
            out.push(SymbolEntry {
                name: s.name.clone(),
                kind: SymbolKind::Static,
                span: s.name_span,
                uri: uri.clone(),
                detail: format!("static bind @ {}: {}", section_name(&s.place), ty),
                container: None,
            });
        }
        Item::Group(g) => {
            out.push(SymbolEntry {
                name: g.name.clone(),
                kind: SymbolKind::Group,
                span: g.name_span,
                uri: uri.clone(),
                detail: format!("group of {} place(s)", g.places.len()),
                container: None,
            });
        }
        Item::Struct(s) => {
            out.push(SymbolEntry {
                name: s.name.clone(),
                kind: SymbolKind::Struct,
                span: s.name_span,
                uri: uri.clone(),
                detail: format!("struct {} {{ {} field(s) }}", s.name, s.fields.len()),
                container: None,
            });
        }
        Item::Use { path, span } => {
            if let Some((name, _)) = path.last() {
                out.push(SymbolEntry {
                    name: name.clone(),
                    kind: SymbolKind::Import,
                    span: *span,
                    uri: uri.clone(),
                    detail: format!(
                        "use {}",
                        path.iter().map(|(s, _)| s.as_str()).collect::<Vec<_>>().join("::")
                    ),
                    container: None,
                });
            }
        }
    }
}

fn collect_block(block: &Block, uri: &Url, container: Option<&str>, out: &mut Vec<SymbolEntry>) {
    for stmt in &block.stmts {
        collect_stmt(stmt, uri, container, out);
    }
}

fn collect_stmt(stmt: &Stmt, uri: &Url, container: Option<&str>, out: &mut Vec<SymbolEntry>) {
    match stmt {
        Stmt::Bind {
            name,
            name_span,
            mutable,
            place,
            span: _,
            pattern,
            ..
        } => {
            // destructuring bind: `bind (a @ rax, b @ rdx) = ...`
            if let Some(pat) = pattern {
                for p in pat {
                    out.push(SymbolEntry {
                        name: p.name.clone(),
                        kind: SymbolKind::Parameter,
                        span: p.span,
                        uri: uri.clone(),
                        detail: format!("destructured bind {}", p.name),
                        container: container.map(|s| s.to_string()),
                    });
                }
                return;
            }
            if let Some(n) = name {
                let kind = if container.is_some() {
                    SymbolKind::Bind
                } else {
                    SymbolKind::Static
                };
                out.push(SymbolEntry {
                    name: n.clone(),
                    kind,
                    span: *name_span,
                    uri: uri.clone(),
                    detail: format!(
                        "bind{} @ {}",
                        if *mutable { " mut" } else { "" },
                        place_ty_summary(place)
                    ),
                    container: container.map(|s| s.to_string()),
                });
            }
        }
        Stmt::Label {
            name,
            name_span,
            body,
            span: _,
        } => {
            out.push(SymbolEntry {
                name: name.clone(),
                kind: SymbolKind::Label,
                span: *name_span,
                uri: uri.clone(),
                detail: format!("label '{}", name),
                container: container.map(|s| s.to_string()),
            });
            collect_block(body, uri, Some(name), out);
        }
        Stmt::Nested(b) => collect_block(b, uri, container, out),
        _ => {}
    }
}

fn ret_summary(ret: &RetSig) -> String {
    match ret {
        RetSig::None => "()".to_string(),
        RetSig::Never { .. } => "!".to_string(),
        RetSig::Single { place, .. } => place
            .reg_bits()
            .map(|b| format!("{} bits", b))
            .unwrap_or_else(|| "?".to_string()),
        RetSig::Tuple { parts, .. } => format!("({} results)", parts.len()),
    }
}

fn place_ty_summary(place: &yana_ast::Place) -> String {
    match place {
        yana_ast::Place::Reg { reg, .. } => format!("reg {}", reg.name()),
        yana_ast::Place::RegPair { hi, lo, .. } => format!("regpair {}:{}", hi.name(), lo.name()),
        yana_ast::Place::Mem { .. } => "mem".to_string(),
        yana_ast::Place::Named { name, .. } => format!("named {}", name),
        yana_ast::Place::Section { kind, .. } => section_kind_name(*kind).to_string(),
        yana_ast::Place::Discard { .. } => "_".to_string(),
        yana_ast::Place::Stack { size, .. } => match size {
            Some(n) => format!("stack({n})"),
            None => "stack".to_string(),
        },
        yana_ast::Place::Group { name, .. } => format!("group({name})"),
    }
}

fn section_name(place: &yana_ast::Place) -> String {
    match place {
        yana_ast::Place::Section { kind, .. } => section_kind_name(*kind).to_string(),
        _ => place_ty_summary(place),
    }
}

fn section_kind_name(k: yana_ast::place::SectionKind) -> &'static str {
    match k {
        yana_ast::place::SectionKind::Text => ".text",
        yana_ast::place::SectionKind::RoData => ".rodata",
        yana_ast::place::SectionKind::Data => ".data",
        yana_ast::place::SectionKind::Bss => ".bss",
    }
}
