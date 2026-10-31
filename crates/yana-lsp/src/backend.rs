//! The LSP server implementation: diagnostics on change, context-aware
//! completion, hover.

use std::collections::HashMap;

use tower_lsp::jsonrpc::Result;
use tower_lsp::lsp_types::*;
use tower_lsp::{Client, LanguageServer};

use yana_ast::diag::SourceMap;
use yana_codegen::{resolve_module, ResolveOptions, TargetInfo};

use crate::knowledge;

pub struct Backend {
    client: Client,
    /// uri → latest source text
    docs: tokio::sync::RwLock<HashMap<Url, String>>,
}

impl Backend {
    pub fn new(client: Client) -> Self {
        Backend { client, docs: tokio::sync::RwLock::new(HashMap::new()) }
    }

    /// Run the full pipeline (lex → parse → resolve) and publish diagnostics.
    async fn check(&self, uri: Url, source: &str) {
        let map = SourceMap::new(source);
        let mut diags: Vec<Diagnostic> = Vec::new();

        // lex errors
        let lexed = yana_lexer::lex(source);
        for span in &lexed.errors {
            diags.push(make_diag(
                DiagnosticSeverity::ERROR,
                "lex-error",
                "unrecognized byte in source",
                None,
                &map,
                *span,
            ));
        }

        let parsed = yana_parser::parse(source);
        for d in &parsed.diagnostics {
            diags.push(convert(d, &map, false, &uri));
        }

        if let Some(file) = &parsed.file {
            let out = resolve_module(file, &TargetInfo::linux_x86_64(), &ResolveOptions::default());
            for d in &out.diagnostics {
                diags.push(convert(d, &map, false, &uri));
            }
        }

        self.client.publish_diagnostics(uri, diags, None).await;
    }
}

fn convert(d: &yana_ast::Diagnostic, map: &SourceMap, strict: bool, uri: &Url) -> Diagnostic {
    let level = d.adjusted_level(strict);
    let severity = match level {
        yana_ast::DiagLevel::Error => DiagnosticSeverity::ERROR,
        yana_ast::DiagLevel::Warning => DiagnosticSeverity::WARNING,
        yana_ast::DiagLevel::Note => DiagnosticSeverity::INFORMATION,
    };
    let span = d.primary_span().unwrap_or(yana_ast::Span::DUMMY);
    let mut diag = make_diag(severity, d.kind.clone(), d.message.clone(), d.help.clone(), map, span);
    // secondary labels → relatedInformation (e.g. "first bound here")
    let related: Vec<DiagnosticRelatedInformation> = d
        .labels
        .iter()
        .filter(|l| !l.primary)
        .map(|l| {
            let ((sl, sc), (el, ec)) = map.span_to_range(l.span);
            DiagnosticRelatedInformation {
                location: Location {
                    uri: uri.clone(),
                    range: Range {
                        start: Position { line: sl, character: sc },
                        end: Position { line: el, character: ec },
                    },
                },
                message: l.message.clone(),
            }
        })
        .collect();
    if !related.is_empty() {
        diag.related_information = Some(related);
    }
    diag
}

fn make_diag(
    severity: DiagnosticSeverity,
    code: impl Into<String>,
    message: impl Into<String>,
    help: Option<String>,
    map: &SourceMap,
    span: yana_ast::Span,
) -> Diagnostic {
    let ((sl, sc), (el, ec)) = map.span_to_range(span);
    Diagnostic {
        range: Range {
            start: Position { line: sl, character: sc },
            end: Position { line: el, character: ec },
        },
        severity: Some(severity),
        code: Some(NumberOrString::String(code.into())),
        source: Some("yana".into()),
        message: message.into(),
        related_information: None,
        tags: None,
        code_description: None,
        data: None,
    }
    .pipe_help(help)
}

trait PipeHelp {
    fn pipe_help(self, help: Option<String>) -> Diagnostic;
}
impl PipeHelp for Diagnostic {
    fn pipe_help(mut self, help: Option<String>) -> Diagnostic {
        if let Some(h) = help {
            self.message = format!("{}\nhelp: {h}", self.message);
        }
        self
    }
}

#[tower_lsp::async_trait]
impl LanguageServer for Backend {
    async fn initialize(&self, _: InitializeParams) -> Result<InitializeResult> {
        Ok(InitializeResult {
            capabilities: ServerCapabilities {
                text_document_sync: Some(TextDocumentSyncCapability::Kind(
                    TextDocumentSyncKind::FULL,
                )),
                completion_provider: Some(CompletionOptions {
                    trigger_characters: Some(vec![
                        ".".into(), "@".into(), "#".into(), ":".into(), "'".into(),
                    ]),
                    ..Default::default()
                }),
                hover_provider: Some(HoverProviderCapability::Simple(true)),
                ..Default::default()
            },
            server_info: Some(ServerInfo {
                name: "yana-lsp".into(),
                version: Some(env!("CARGO_PKG_VERSION").into()),
            }),
        })
    }

    async fn initialized(&self, _: InitializedParams) {
        self.client
            .log_message(MessageType::INFO, "yana-lsp ready")
            .await;
    }

    async fn shutdown(&self) -> Result<()> {
        Ok(())
    }

    async fn did_open(&self, params: DidOpenTextDocumentParams) {
        let uri = params.text_document.uri;
        let text = params.text_document.text;
        self.docs.write().await.insert(uri.clone(), text.clone());
        self.check(uri, &text).await;
    }

    async fn did_change(&self, params: DidChangeTextDocumentParams) {
        let uri = params.text_document.uri;
        // FULL sync: the last change carries the whole document
        if let Some(change) = params.content_changes.into_iter().last() {
            let text = change.text;
            self.docs.write().await.insert(uri.clone(), text.clone());
            self.check(uri, &text).await;
        }
    }

    async fn did_close(&self, params: DidCloseTextDocumentParams) {
        self.docs.write().await.remove(&params.text_document.uri);
        self.client.publish_diagnostics(params.text_document.uri, vec![], None).await;
    }

    async fn completion(&self, params: CompletionParams) -> Result<Option<CompletionResponse>> {
        let uri = &params.text_document_position.text_document.uri;
        let pos = params.text_document_position.position;
        let docs = self.docs.read().await;
        let source = docs.get(uri).cloned().unwrap_or_default();
        let ctx = completion_context(&source, pos);

        let mut items: Vec<CompletionItem> = Vec::new();

        match ctx {
            Ctx::Register | Ctx::Place => {
                for (name, detail) in knowledge::registers() {
                    items.push(ci(&name, Some(detail), None, CompletionItemKind::VARIABLE, None));
                }
                if matches!(ctx, Ctx::Place) {
                    // also offer local bindings and statics from the doc
                    for name in binding_names(&source) {
                        items.push(ci(&name, Some("binding".into()), None, CompletionItemKind::VALUE, None));
                    }
                    for s in knowledge::sections() {
                        items.push(ci(s.label, Some(s.detail.into()), None, CompletionItemKind::CONSTANT, None));
                    }
                }
            }
            Ctx::Type => {
                for t in knowledge::types() {
                    items.push(ci(t.label, Some(t.detail.into()), Some(t.docs.into()), CompletionItemKind::TYPE_PARAMETER, None));
                }
            }
            Ctx::Section => {
                for s in knowledge::sections() {
                    items.push(ci(s.label, Some(s.detail.into()), None, CompletionItemKind::MODULE, None));
                }
            }
            Ctx::Flag => {
                for f in knowledge::flags() {
                    items.push(ci(f.label, Some(f.detail.into()), Some(f.docs.into()), CompletionItemKind::ENUM_MEMBER, None));
                }
            }
            Ctx::Attribute => {
                for a in knowledge::attributes() {
                    items.push(ci(a.label, Some(a.detail.into()), Some(a.docs.into()), CompletionItemKind::KEYWORD, a.insert.map(|s| s.to_string())));
                }
            }
            Ctx::Label => {
                for name in label_names(&source) {
                    items.push(ci(&format!("'{name}"), Some("label (§6)".into()), None, CompletionItemKind::REFERENCE, Some(name)));
                }
            }
            Ctx::General => {
                for k in knowledge::keywords() {
                    items.push(ci(k.label, Some(k.detail.into()), Some(k.docs.into()), CompletionItemKind::KEYWORD, k.insert.map(|s| s.to_string())));
                }
                for t in knowledge::types() {
                    items.push(ci(t.label, Some(t.detail.into()), None, CompletionItemKind::TYPE_PARAMETER, None));
                }
                for s in knowledge::sections() {
                    items.push(ci(s.label, Some(s.detail.into()), None, CompletionItemKind::MODULE, None));
                }
                for (name, detail) in knowledge::registers().into_iter().take(32) {
                    // common GPRs first: 64/32-bit of the first 8 families
                    items.push(ci(&name, Some(detail), None, CompletionItemKind::VARIABLE, None));
                }
                for name in binding_names(&source) {
                    items.push(ci(&name, Some("binding".into()), None, CompletionItemKind::VALUE, None));
                }
            }
        }

        Ok(Some(CompletionResponse::Array(items)))
    }

    async fn hover(&self, params: HoverParams) -> Result<Option<Hover>> {
        let uri = &params.text_document_position_params.text_document.uri;
        let pos = params.text_document_position_params.position;
        let docs = self.docs.read().await;
        let source = docs.get(uri).cloned().unwrap_or_default();
        let Some(word) = word_at(&source, pos) else {
            return Ok(None);
        };

        let md = if word.starts_with('.') {
            knowledge::sections()
                .into_iter()
                .find(|s| s.label == word)
                .map(|s| format!("**{}** — {}", s.label, s.detail))
        } else if let Some(h) = knowledge::register_hover(&word) {
            Some(h)
        } else if let Some(h) = knowledge::keyword_hover(&word) {
            Some(h)
        } else if binding_names(&source).contains(&word) {
            Some(format!("**{word}** — binding (see its `bind` for the place and type)"))
        } else {
            None
        };

        Ok(md.map(|md| Hover {
            contents: HoverContents::Markup(MarkupContent { kind: MarkupKind::Markdown, value: md }),
            range: None,
        }))
    }
}

fn ci(
    label: &str,
    detail: Option<String>,
    docs: Option<String>,
    kind: CompletionItemKind,
    insert: Option<String>,
) -> CompletionItem {
    CompletionItem {
        label: label.to_string(),
        detail,
        documentation: docs.filter(|d| !d.is_empty()).map(Documentation::String),
        kind: Some(kind),
        insert_text: insert.clone(),
        insert_text_format: insert.map(|_| InsertTextFormat::SNIPPET),
        ..Default::default()
    }
}

// ---------------------------------------------------------------------------
// context detection — deliberately simple and text-based (no semantic pass)
// ---------------------------------------------------------------------------

#[derive(PartialEq, Clone, Copy)]
enum Ctx {
    General,
    Register,
    Place,
    Type,
    Section,
    Flag,
    Attribute,
    Label,
}

fn completion_context(source: &str, pos: Position) -> Ctx {
    let Some(line) = source.lines().nth(pos.line as usize) else {
        return Ctx::General;
    };
    let upto: String = line.chars().take(pos.character as usize).collect();
    let t = upto.trim_end();

    // inside #[ ... ]
    if let Some(h) = t.rfind("#[") {
        if !t[h..].contains(']') {
            return Ctx::Attribute;
        }
    }
    // after ' (label reference)
    if t.ends_with('\'') || t.chars().last().map(|c| c.is_ascii_alphanumeric()).unwrap_or(false) && t.contains('\'') {
        if let Some(q) = t.rfind('\'') {
            if !t[..q].contains(' ') || t.ends_with('\'') || is_label_site(t) {
                return Ctx::Label;
            }
        }
    }
    // `@ ` → place (register / memory / section)
    if t.ends_with('@') || t.ends_with("@ ") {
        return Ctx::Place;
    }
    if t.ends_with('.') || after_dot(t) {
        // `.text` etc or field access — sections complete after '.'
        if t.ends_with('.') {
            return Ctx::Section;
        }
    }
    // `: ` → type
    if t.ends_with(':') || t.ends_with(": ") {
        return Ctx::Type;
    }
    // `branch ( ... ` → flags & compares; offer flags
    if let Some(p) = t.rfind("branch") {
        let tail = &t[p..];
        if tail.contains('(') && !tail.contains("=>") {
            return Ctx::Flag;
        }
    }
    // inside [ ... ] → registers/names
    if let Some(b) = t.rfind('[') {
        if !t[b..].contains(']') {
            return Ctx::Register;
        }
    }
    // `bind x @ ` handled above; `push {` / `pop {` → registers
    for kw in ["push {", "pop {"] {
        if let Some(b) = t.rfind(kw) {
            if !t[b..].contains('}') {
                return Ctx::Register;
            }
        }
    }
    Ctx::General
}

fn is_label_site(t: &str) -> bool {
    // after `=>` in a branch statement
    t.rfind("=>").map(|i| !t[i..].contains(';')).unwrap_or(false)
}

fn after_dot(t: &str) -> bool {
    t.chars().last() == Some('.')
}

/// Names bound via `bind name @` and fn params — cheap regex-free scan.
fn binding_names(source: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in source.lines() {
        let l = line.trim();
        if let Some(rest) = l.strip_prefix("bind ") {
            let rest = rest.strip_prefix("mut ").unwrap_or(rest);
            if let Some(name) = rest.split_whitespace().next() {
                let name = name.trim_end_matches(|c: char| !c.is_ascii_alphanumeric() && c != '_');
                if !name.is_empty() && name != "(" {
                    out.push(name.to_string());
                }
            }
        }
        // fn params: `name @`
        if l.starts_with("fn ") || l.starts_with("extern fn ") {
            if let Some(open) = l.find('(') {
                if let Some(close) = l[open..].find(')') {
                    let params = &l[open + 1..open + close];
                    for p in params.split(',') {
                        let p = p.trim();
                        if let Some(at) = p.find('@') {
                            let mut name = p[..at].trim().to_string();
                            if let Some(n) = name.strip_prefix("mut ") {
                                name = n.to_string();
                            }
                            if !name.is_empty() {
                                out.push(name);
                            }
                        }
                    }
                }
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

/// `label (name)` declarations.
fn label_names(source: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in source.lines() {
        let l = line.trim();
        if let Some(rest) = l.strip_prefix("label (") {
            if let Some(name) = rest.split(')').next() {
                out.push(name.trim().to_string());
            }
        }
    }
    out
}

/// The identifier under a position (for hover).
fn word_at(source: &str, pos: Position) -> Option<String> {
    let line = source.lines().nth(pos.line as usize)?;
    let chars: Vec<char> = line.chars().collect();
    let c = pos.character as usize;
    if c >= chars.len() && !(c > 0) {
        return None;
    }
    let is_word = |ch: char| ch.is_ascii_alphanumeric() || ch == '_' || ch == '.';
    let mut start = c.min(chars.len());
    while start > 0 && is_word(chars[start - 1]) {
        start -= 1;
    }
    let mut end = c.min(chars.len());
    while end < chars.len() && is_word(chars[end]) {
        end += 1;
    }
    if end > start {
        Some(chars[start..end].iter().collect())
    } else {
        None
    }
}
