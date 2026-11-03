//! The LSP server implementation: diagnostics, context-aware completion,
//! hover, go-to-definition, references, signature help, document symbols,
//! code actions, rename, inlay hints, code lens, folding ranges.

use std::collections::HashMap;
use std::sync::Arc;

use tower_lsp::jsonrpc::Result;
use tower_lsp::lsp_types::*;
use tower_lsp::lsp_types::ExecuteCommandParams;
use serde_json::Value;
use tower_lsp::{Client, LanguageServer};

use yana_knowledge as knowledge;
use crate::range::{offset_to_position, position_to_offset, span_to_range, word_at};
use crate::symbols::{collect_symbols, SymbolEntry};
use crate::symbols::SymbolKind as SymKind;
use yana_knowledge::syscalls;
use crate::world::{Document, World};

use yana_ast::diag::SourceMap;
use yana_ast::{File, Item};
use yana_codegen::{resolve_module, ResolveOptions, TargetInfo};
use yana_ast::Span;

pub struct Backend {
    client: Client,
    /// uri → latest document (source + parse + symbols)
    world: Arc<World>,
}

impl Backend {
    pub fn new(client: Client) -> Self {
        Backend {
            client,
            world: Arc::new(World::new()),
        }
    }

    /// Set workspace root from `initialize` and scan all `.yana` files on disk.
    async fn set_workspace_root(&self, root_uri: &Url) {
        let root_path = root_uri
            .to_file_path()
            .unwrap_or_else(|_| std::path::PathBuf::from(""));
        if !root_path.as_os_str().is_empty() {
            self.world.set_root(root_path.clone()).await;
            self.world.scan_workspace().await;
            self.client
                .log_message(
                    MessageType::INFO,
                    format!("yana-lsp: workspace root = {}, scanned .yana files", root_uri.path()),
                )
                .await;
        }
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

        self.client
            .publish_diagnostics(uri, diags, None)
            .await;
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
    span: Span,
) -> Diagnostic {
    let ((sl, sc), (el, ec)) = map.span_to_range(span);
    Diagnostic {
        range: Range {
            start: Position { line: sl as u32, character: sc as u32 },
            end: Position { line: el as u32, character: ec as u32 },
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

// ===========================================================================
// LanguageServer
// ===========================================================================

#[tower_lsp::async_trait]
impl LanguageServer for Backend {
    async fn initialize(&self, params: InitializeParams) -> Result<InitializeResult> {
        // Set workspace root from client's rootUri and scan .yana files.
        if let Some(root_uri) = &params.root_uri {
            self.set_workspace_root(root_uri).await;
        }
        Ok(InitializeResult {
            capabilities: ServerCapabilities {
                text_document_sync: Some(TextDocumentSyncCapability::Kind(
                    TextDocumentSyncKind::FULL,
                )),
                completion_provider: Some(CompletionOptions {
                    trigger_characters: Some(vec![
                        ".".into(), "@".into(), "#".into(), ":".into(), "'".into(),
                        "(".into(), ",".into(), "{".into(), "}".into(),
                    ]),
                    ..Default::default()
                }),
                hover_provider: Some(HoverProviderCapability::Simple(true)),
                definition_provider: Some(OneOf::Left(true)),
                references_provider: Some(OneOf::Left(true)),
                signature_help_provider: Some(SignatureHelpOptions {
                    trigger_characters: Some(vec!["(".into(), ",".into(), "{".into()]),
                    retrigger_characters: Some(vec![".".into(), ",".into()]),
                    ..Default::default()
                }),
                document_symbol_provider: Some(OneOf::Left(true)),
                code_action_provider: Some(CodeActionProviderCapability::Options(
                    CodeActionOptions {
                        resolve_provider: Some(false),
                        ..Default::default()
                    },
                )),
                rename_provider: Some(OneOf::Left(true)),
                inlay_hint_provider: Some(OneOf::Left(true)),
                code_lens_provider: Some(CodeLensOptions {
                    resolve_provider: Some(false),
                }),
                folding_range_provider: Some(
                    tower_lsp::lsp_types::FoldingRangeProviderCapability::Simple(true),
                ),
                selection_range_provider: Some(
                    tower_lsp::lsp_types::SelectionRangeProviderCapability::Simple(true),
                ),
                execute_command_provider: Some(ExecuteCommandOptions {
                    commands: vec![
                        "yana.build".into(),
                        "yana.run".into(),
                        "yana.expand".into(),
                        "yana.debug".into(),
                        "yana.ir".into(),
                    ],
                    work_done_progress_options: WorkDoneProgressOptions::default(),
                }),
                semantic_tokens_provider: Some(
                    SemanticTokensServerCapabilities::SemanticTokensOptions(
                        SemanticTokensOptions {
                            work_done_progress_options: WorkDoneProgressOptions::default(),
                            legend: SemanticTokensLegend {
                                token_types: vec![
                                    SemanticTokenType::NAMESPACE,
                                    SemanticTokenType::TYPE,
                                    SemanticTokenType::CLASS,
                                    SemanticTokenType::ENUM,
                                    SemanticTokenType::INTERFACE,
                                    SemanticTokenType::STRUCT,
                                    SemanticTokenType::PARAMETER,
                                    SemanticTokenType::VARIABLE,
                                    SemanticTokenType::ENUM_MEMBER,
                                    SemanticTokenType::EVENT,
                                    SemanticTokenType::FUNCTION,
                                    SemanticTokenType::METHOD,
                                    SemanticTokenType::MACRO,
                                    SemanticTokenType::KEYWORD,
                                    SemanticTokenType::COMMENT,
                                    SemanticTokenType::STRING,
                                    SemanticTokenType::NUMBER,
                                    SemanticTokenType::REGEXP,
                                    SemanticTokenType::OPERATOR,
                                ],
                                token_modifiers: vec![
                                    SemanticTokenModifier::DECLARATION,
                                    SemanticTokenModifier::DOCUMENTATION,
                                    SemanticTokenModifier::READONLY,
                                ],
                            },
                            full: Some(SemanticTokensFullOptions::Bool(true)),
                            range: Some(true),
                        },
                    ),
                ),
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
            .log_message(MessageType::INFO, "yana-lsp ready — super smart mode")
            .await;
    }

    async fn shutdown(&self) -> Result<()> {
        Ok(())
    }

    async fn did_open(&self, params: DidOpenTextDocumentParams) {
        let uri = params.text_document.uri;
        let text = params.text_document.text.clone();
        self.world.upsert(uri.clone(), text.clone()).await;
        self.check(uri, &text).await;
    }

    async fn did_change(&self, params: DidChangeTextDocumentParams) {
        let uri = params.text_document.uri;
        if let Some(change) = params.content_changes.into_iter().last() {
            let text = change.text;
            self.world.upsert(uri.clone(), text.clone()).await;
            self.check(uri, &text).await;
        }
    }

    async fn did_close(&self, params: DidCloseTextDocumentParams) {
        let uri = params.text_document.uri;
        self.world.remove(&uri).await;
        self.client
            .publish_diagnostics(uri, vec![], None)
            .await;
    }

    // -----------------------------------------------------------------------
    // Completion
    // -----------------------------------------------------------------------

    async fn completion(&self, params: CompletionParams) -> Result<Option<CompletionResponse>> {
        let uri = &params.text_document_position.text_document.uri;
        let pos = params.text_document_position.position;
        let doc = match self.world.get(uri).await {
            Some(d) => d,
            None => return Ok(None),
        };
        let source = &doc.source;
        let ctx = completion_context(source, pos);

        let mut items: Vec<CompletionItem> = Vec::new();

        match ctx {
            Ctx::Register | Ctx::Place => {
                for (name, detail) in knowledge::registers() {
                    items.push(ci(&name, Some(detail), None, CompletionItemKind::VARIABLE, None));
                }
                if matches!(ctx, Ctx::Place) {
                    for sym in &doc.symbols {
                        if matches!(
                            sym.kind,
                            SymKind::Bind | SymKind::Static | SymKind::Parameter
                        ) {
                            items.push(ci(
                                &sym.name,
                                Some(sym.detail.clone()),
                                None,
                                CompletionItemKind::VARIABLE,
                                None,
                            ));
                        }
                    }
                    for s in knowledge::sections() {
                        items.push(ci(
                            s.label,
                            Some(s.detail.into()),
                            None,
                            CompletionItemKind::CONSTANT,
                            None,
                        ));
                    }
                }
            }
            Ctx::Type => {
                for t in knowledge::types() {
                    items.push(ci(
                        t.label,
                        Some(t.detail.into()),
                        Some(t.docs.into()),
                        CompletionItemKind::TYPE_PARAMETER,
                        None,
                    ));
                }
            }
            Ctx::Section => {
                for s in knowledge::sections() {
                    items.push(ci(
                        s.label,
                        Some(s.detail.into()),
                        None,
                        CompletionItemKind::MODULE,
                        None,
                    ));
                }
            }
            Ctx::Flag => {
                for f in knowledge::flags() {
                    items.push(ci(
                        f.label,
                        Some(f.detail.into()),
                        Some(f.docs.into()),
                        CompletionItemKind::ENUM_MEMBER,
                        None,
                    ));
                }
            }
            Ctx::Attribute => {
                for a in knowledge::attributes() {
                    items.push(ci(
                        a.label,
                        Some(a.detail.into()),
                        Some(a.docs.into()),
                        CompletionItemKind::KEYWORD,
                        a.insert.map(|s| s.to_string()),
                    ));
                }
            }
            Ctx::Label => {
                for sym in &doc.symbols {
                    if sym.kind == SymKind::Label {
                        items.push(ci(
                            &format!("'{}", sym.name),
                            Some(sym.detail.clone()),
                            None,
                            CompletionItemKind::REFERENCE,
                            Some(sym.name.clone()),
                        ));
                    }
                }
                for name in label_names(source) {
                    items.push(ci(
                        &format!("'{name}"),
                        Some("label (§6)".into()),
                        None,
                        CompletionItemKind::REFERENCE,
                        Some(name),
                    ));
                }
            }
            Ctx::General => {
                for k in knowledge::keywords() {
                    items.push(ci(
                        k.label,
                        Some(k.detail.into()),
                        Some(k.docs.into()),
                        CompletionItemKind::KEYWORD,
                        k.insert.map(|s| s.to_string()),
                    ));
                }
                for t in knowledge::types() {
                    items.push(ci(
                        t.label,
                        Some(t.detail.into()),
                        None,
                        CompletionItemKind::TYPE_PARAMETER,
                        None,
                    ));
                }
                for s in knowledge::sections() {
                    items.push(ci(
                        s.label,
                        Some(s.detail.into()),
                        None,
                        CompletionItemKind::MODULE,
                        None,
                    ));
                }
                for (name, detail) in knowledge::registers().into_iter().take(32) {
                    items.push(ci(&name, Some(detail), None, CompletionItemKind::VARIABLE, None));
                }
                for sym in &doc.symbols {
                    if matches!(
                        sym.kind,
                        SymKind::Bind | SymKind::Static | SymKind::Function
                            | SymKind::ExternFunction | SymKind::Const
                            | SymKind::ConstFunction
                    ) {
                        items.push(ci(
                            &sym.name,
                            Some(sym.detail.clone()),
                            None,
                            CompletionItemKind::VARIABLE,
                            None,
                        ));
                    }
                }
                for name in binding_names(source) {
                    items.push(ci(&name, Some("binding".into()), None, CompletionItemKind::VALUE, None));
                }
            }
        }

        Ok(Some(CompletionResponse::Array(items)))
    }

    // -----------------------------------------------------------------------
    // Hover
    // -----------------------------------------------------------------------

    async fn hover(&self, params: HoverParams) -> Result<Option<Hover>> {
        let uri = &params.text_document_position_params.text_document.uri;
        let pos = params.text_document_position_params.position;
        let doc = match self.world.get(uri).await {
            Some(d) => d,
            None => return Ok(None),
        };
        let source = &doc.source;
        let map = doc.source_map();

        // 0. `#[syscall(N)]` — explain the syscall itself: name, signature,
        //    per-register arguments, return value and the man page (§5.5).
        if let Some((nr, range)) = syscall_attr_at(source, pos) {
            let md = match syscalls::by_number(nr) {
                Some(sc) => syscall_markdown(sc, Some(nr)),
                None => format!(
                    "**syscall {nr}** — нет в таблице\n\nНомер не описан в `knowledge`: \
                     Linux x86-64 кладёт номер в `rax`, аргументы — в `rdi, rsi, rdx, r10, r8, r9`, \
                     результат возвращается в `rax`.\n\nСмотри `man 2 syscall` (§5.5)."
                ),
            };
            return Ok(Some(Hover {
                contents: HoverContents::Markup(MarkupContent {
                    kind: MarkupKind::Markdown,
                    value: md,
                }),
                range,
            }));
        }

        let Some(word) = word_at(source, pos) else {
            return Ok(None);
        };

        // 1. Symbol from this document's index — full explanation
        if let Some(sym) = doc.symbols.iter().find(|s| s.name == word) {
            let range = span_to_range(&map, sym.span);

            // An `extern fn` with `#[syscall(N)]` gets the syscall's docs,
            // not the generic "extern function" blurb.
            if sym.kind == SymKind::ExternFunction {
                if let Some(nr) = extern_syscall_number(doc.parse.as_ref().and_then(|p| p.file.as_ref()), &sym.name) {
                    if let Some(sc) = syscalls::by_number(nr) {
                        return Ok(Some(Hover {
                            contents: HoverContents::Markup(MarkupContent {
                                kind: MarkupKind::Markdown,
                                value: format!(
                                    "`extern fn {}` — привязка к syscall {nr} (§5.5)\n\n{}",
                                    sym.name,
                                    syscall_markdown(sc, Some(nr))
                                ),
                            }),
                            range: Some(range),
                        }));
                    }
                }
            }

            let md = format!(
                "**{}** — {}\n\n{}",
                sym.name,
                sym.detail,
                symbol_explanation(sym)
            );
            return Ok(Some(Hover {
                contents: HoverContents::Markup(MarkupContent {
                    kind: MarkupKind::Markdown,
                    value: md,
                }),
                range: Some(range),
            }));
        }

        // 2. Sections
        if word.starts_with('.') {
            if let Some(s) = knowledge::sections().into_iter().find(|s| s.label == word) {
                let md = format!(
                    "**{}** — {}\n\n{}",
                    s.label,
                    s.detail,
                    section_explanation(s.label)
                );
                return Ok(Some(Hover {
                    contents: HoverContents::Markup(MarkupContent {
                        kind: MarkupKind::Markdown,
                        value: md,
                    }),
                    range: None,
                }));
            }
        }

        // 3. Registers — full register explanation
        if let Some(h) = knowledge::register_hover(&word) {
            let md = format!("{h}\n\n{}", register_explanation(&word));
            return Ok(Some(Hover {
                contents: HoverContents::Markup(MarkupContent {
                    kind: MarkupKind::Markdown,
                    value: md,
                }),
                range: None,
            }));
        }

        // 4. Keywords — full keyword explanation
        if let Some(h) = knowledge::keyword_hover(&word) {
            let md = format!("{h}\n\n{}", keyword_explanation(&word));
            return Ok(Some(Hover {
                contents: HoverContents::Markup(MarkupContent {
                    kind: MarkupKind::Markdown,
                    value: md,
                }),
                range: None,
            }));
        }

        // 5. Fallback: binding mentioned in source
        if binding_names(source).contains(&word) {
            return Ok(Some(Hover {
                contents: HoverContents::Markup(MarkupContent {
                    kind: MarkupKind::Markdown,
                    value: format!("**{word}** — binding (see its `bind` for the place and type)"),
                }),
                range: None,
            }));
        }

        Ok(None)
    }

    // -----------------------------------------------------------------------
    // Go-to-definition
    // -----------------------------------------------------------------------

    async fn goto_definition(
        &self,
        params: GotoDefinitionParams,
    ) -> Result<Option<GotoDefinitionResponse>> {
        let uri = &params.text_document_position_params.text_document.uri;
        let pos = params.text_document_position_params.position;
        let doc = match self.world.get(uri).await {
            Some(d) => d,
            None => return Ok(None),
        };
        let source = &doc.source;
        let map = doc.source_map();

        let Some(word) = word_at(source, pos) else {
            return Ok(None);
        };

        for sym in &doc.symbols {
            let range = span_to_range(&map, sym.span);
            if range.start <= pos && pos < range.end {
                return Ok(Some(GotoDefinitionResponse::Scalar(Location {
                    uri: uri.clone(),
                    range,
                })));
            }
        }

        let defs = self.world.find_definitions(&word).await;
        if defs.is_empty() {
            return Ok(None);
        }
        let mut locations = Vec::new();
        for def in &defs {
            let target_doc = self.world.get(&def.uri).await;
            let map = target_doc
                .map(|d| d.source_map())
                .unwrap_or_else(|| SourceMap::new(""));
            let range = span_to_range(&map, def.span);
            locations.push(Location {
                uri: def.uri.clone(),
                range,
            });
        }

        if locations.len() == 1 {
            Ok(Some(GotoDefinitionResponse::Scalar(locations.remove(0))))
        } else {
            Ok(Some(GotoDefinitionResponse::Array(locations)))
        }
    }

    // -----------------------------------------------------------------------
    // References
    // -----------------------------------------------------------------------

    async fn references(
        &self,
        params: ReferenceParams,
    ) -> Result<Option<Vec<Location>>> {
        let uri = &params.text_document_position.text_document.uri;
        let pos = params.text_document_position.position;
        let context = params.context;
        let doc = match self.world.get(uri).await {
            Some(d) => d,
            None => return Ok(None),
        };
        let source = &doc.source;

        let Some(word) = word_at(source, pos) else {
            return Ok(None);
        };

        let defs = self.world.find_definitions(&word).await;
        if defs.is_empty() {
            return Ok(None);
        }

        let mut locations = Vec::new();
        for (doc_uri, doc) in self.world.all_docs().await {
            let map = doc.source_map();
            for rng in find_word_occurrences(&doc.source, &word) {
                if doc_uri == *uri && !context.include_declaration {
                    let is_def = doc.symbols.iter().any(|s| s.name == word && {
                        let sr = span_to_range(&map, s.span);
                        sr.start <= rng.start && rng.start < sr.end
                    });
                    if is_def {
                        continue;
                    }
                }
                locations.push(Location {
                    uri: doc_uri.clone(),
                    range: rng,
                });
            }
        }

        if locations.is_empty() {
            Ok(None)
        } else {
            Ok(Some(locations))
        }
    }

    // -----------------------------------------------------------------------
    // Signature help
    // -----------------------------------------------------------------------

    async fn signature_help(
        &self,
        params: SignatureHelpParams,
    ) -> Result<Option<SignatureHelp>> {
        let uri = &params.text_document_position_params.text_document.uri;
        let pos = params.text_document_position_params.position;
        let doc = match self.world.get(uri).await {
            Some(d) => d,
            None => return Ok(None),
        };
        let source = &doc.source;

        let line = source.lines().nth(pos.line as usize).unwrap_or("");
        let upto: String = line.chars().take(pos.character as usize).collect();
        let t = upto.trim_end();

        if let Some(p) = t.rfind("call ") {
            let after = &t[p + 5..];
            let name = after.split_whitespace().next().unwrap_or("");
            if !name.is_empty() {
                return signature_for(&self.world, name).await;
            }
        }

        Ok(None)
    }

    // -----------------------------------------------------------------------
    // Document symbols
    // -----------------------------------------------------------------------

    async fn document_symbol(
        &self,
        params: DocumentSymbolParams,
    ) -> Result<Option<DocumentSymbolResponse>> {
        let uri = &params.text_document.uri;
        let doc = match self.world.get(uri).await {
            Some(d) => d,
            None => return Ok(None),
        };
        let map = doc.source_map();

        let mut out = Vec::new();
        for sym in &doc.symbols {
            let range = span_to_range(&map, sym.span);
            let sel = range.clone();
            #[allow(deprecated)]
            out.push(DocumentSymbol {
                name: sym.name.clone(),
                detail: Some(sym.detail.clone()),
                kind: lsp_kind(sym.kind),
                tags: None,
                deprecated: None,
                range,
                selection_range: sel,
                children: Some(vec![]),
            });
        }

        Ok(Some(DocumentSymbolResponse::Nested(out)))
    }

    // -----------------------------------------------------------------------
    // Code actions
    // -----------------------------------------------------------------------

    async fn code_action(
        &self,
        params: CodeActionParams,
    ) -> Result<Option<CodeActionResponse>> {
        let uri = &params.text_document.uri;
        let range = params.range;
        let context = params.context;
        let doc = match self.world.get(uri).await {
            Some(d) => d,
            None => return Ok(None),
        };
        let source = &doc.source;
        let map = doc.source_map();

        let mut actions: Vec<CodeActionOrCommand> = Vec::new();

        for diag in &context.diagnostics {
            let code = diag.code.as_ref().and_then(|c| match c {
                NumberOrString::String(s) => Some(s.as_str()),
                NumberOrString::Number(_) => None,
            }).unwrap_or("");
            match code {
                "immutable-write" => {
                    if let Some(name) = extract_bind_name(&diag.message) {
                        actions.push(CodeActionOrCommand::CodeAction(make_code_action(
                            format!("Add `mut` to `{name}` and use `alt`"),
                            CodeActionKind::QUICKFIX,
                            uri.clone(),
                            range,
                            format!("alt {name} = ...;"),
                        )));
                    }
                }
                "unknown-name" => {
                    if let Some(name) = extract_bind_name(&diag.message) {
                        actions.push(CodeActionOrCommand::CodeAction(make_code_action(
                            format!("Add `bind {name} @ <place>: <type>;`"),
                            CodeActionKind::QUICKFIX,
                            uri.clone(),
                            range,
                            format!("bind {name} @ rax: u64 = 0;"),
                        )));
                    }
                }
                "dup-bind" => {
                    actions.push(CodeActionOrCommand::CodeAction(CodeAction {
                        title: "Rename one of the conflicting bindings".into(),
                        kind: Some(CodeActionKind::REFACTOR),
                        diagnostics: Some(vec![diag.clone()]),
                        edit: None,
                        command: None,
                        is_preferred: Some(false),
                        disabled: None,
                        data: None,
                    }));
                }
                "type-mismatch" => {
                    if let Some((name, expected, found)) = extract_type_mismatch(&diag.message) {
                        actions.push(CodeActionOrCommand::CodeAction(make_code_action(
                            format!("Change `{name}` type to `{expected}`"),
                            CodeActionKind::QUICKFIX,
                            uri.clone(),
                            range,
                            format!("{name}: {expected}"),
                        )));
                    }
                }
                "unknown-label" => {
                    if let Some(label) = extract_unknown_label(&diag.message) {
                        actions.push(CodeActionOrCommand::CodeAction(make_code_action(
                            format!("Add `label ('{label}) {{ ... }}`"),
                            CodeActionKind::QUICKFIX,
                            uri.clone(),
                            range,
                            format!("label ('{label}) {{\n    \n}}"),
                        )));
                    }
                }
                _ => {}
            }
        }

        Ok(Some(actions))
    }

    // -----------------------------------------------------------------------
    // Rename
    // -----------------------------------------------------------------------

    async fn rename(&self, params: RenameParams) -> Result<Option<WorkspaceEdit>> {
        let uri = &params.text_document_position.text_document.uri;
        let pos = params.text_document_position.position;
        let new_name = &params.new_name;
        let doc = match self.world.get(uri).await {
            Some(d) => d,
            None => return Ok(None),
        };
        let source = &doc.source;

        let Some(word) = word_at(source, pos) else {
            return Ok(None);
        };

        let mut changes: HashMap<Url, Vec<TextEdit>> = HashMap::new();
        for (doc_uri, doc) in self.world.all_docs().await {
            let mut edits = Vec::new();
            for rng in find_word_occurrences(&doc.source, &word) {
                edits.push(TextEdit {
                    range: rng,
                    new_text: new_name.clone(),
                });
            }
            if !edits.is_empty() {
                changes.insert(doc_uri.clone(), edits);
            }
        }

        if changes.is_empty() {
            return Ok(None);
        }

        Ok(Some(WorkspaceEdit {
            changes: Some(changes),
            document_changes: None,
            change_annotations: None,
        }))
    }

    // -----------------------------------------------------------------------
    // Execute command (build / run / expand from the editor)
    // -----------------------------------------------------------------------

    async fn execute_command(
        &self,
        params: ExecuteCommandParams,
    ) -> Result<Option<serde_json::Value>> {
        let command = params.command.as_str();
        let uri = params
            .arguments
            .first()
            .and_then(|a| a.as_str())
            .unwrap_or("")
            .to_string();

        let uri = match Url::parse(&uri) {
            Ok(u) => u,
            Err(_) => {
                self.client
                    .log_message(MessageType::ERROR, format!("yana-lsp: bad URI `{uri}`"))
                    .await;
                return Ok(None);
            }
        };

        let doc = match self.world.get(&uri).await {
            Some(d) => d,
            None => {
                self.client
                    .log_message(MessageType::ERROR, "yana-lsp: document not open")
                    .await;
                return Ok(None);
            }
        };

        // Write the source to a temp file so the CLI can build/run it.
        let source = &doc.source;
        let tmp_dir = std::env::temp_dir().join("yana-lsp");
        let _ = std::fs::create_dir_all(&tmp_dir);
        let file_name = uri
            .path_segments()
            .and_then(|mut s| s.next_back())
            .unwrap_or("program");
        let tmp_file = tmp_dir.join(format!("{file_name}.yana"));
        if let Err(e) = std::fs::write(&tmp_file, source) {
            self.client
                .log_message(MessageType::ERROR, format!("yana-lsp: cannot write temp file: {e}"))
                .await;
            return Ok(None);
        }

        // Find the `yana` CLI binary (sibling of this LSP binary, or on PATH).
        let exe_path = std::env::current_exe().ok();
        let yana_cli = exe_path
            .as_ref()
            .and_then(|p| p.parent())
            .and_then(|parent| {
                let y = parent.join("yana");
                if y.exists() {
                    Some(y)
                } else {
                    let yc = parent.join("yana-cli");
                    if yc.exists() {
                        Some(yc)
                    } else {
                        None
                    }
                }
            })
            .unwrap_or_else(|| std::path::PathBuf::from("yana"));

        // ------------------------------------------------------------------
        // Shared: write source to temp file, find CLI binary
        // ------------------------------------------------------------------
        let source = &doc.source;
        let tmp_dir = std::env::temp_dir().join("yana-lsp");
        let _ = std::fs::create_dir_all(&tmp_dir);
        let file_name = uri
            .path_segments()
            .and_then(|mut s| s.next_back())
            .unwrap_or("program");
        let tmp_file = tmp_dir.join(format!("{file_name}.yana"));
        if let Err(e) = std::fs::write(&tmp_file, source) {
            self.client
                .log_message(MessageType::ERROR, format!("yana-lsp: cannot write temp file: {e}"))
                .await;
            return Ok(None);
        }

        let exe_path = std::env::current_exe().ok();
        let yana_cli = exe_path
            .as_ref()
            .and_then(|p| p.parent())
            .and_then(|parent| {
                let y = parent.join("yana");
                if y.exists() {
                    Some(y)
                } else {
                    let yc = parent.join("yana-cli");
                    if yc.exists() {
                        Some(yc)
                    } else {
                        None
                    }
                }
            })
            .unwrap_or_else(|| std::path::PathBuf::from("yana"));

        // ------------------------------------------------------------------
        // Command dispatch
        // ------------------------------------------------------------------
        match command {
            "yana.build" | "yana.run" | "yana.expand" => {
                let (cmd, args): (&std::ffi::OsStr, Vec<&std::ffi::OsStr>) = match command {
                    "yana.build" => (
                        yana_cli.as_os_str(),
                        vec!["build".as_ref(), tmp_file.as_os_str()],
                    ),
                    "yana.run" => (
                        yana_cli.as_os_str(),
                        vec!["run".as_ref(), tmp_file.as_os_str()],
                    ),
                    "yana.expand" => (
                        yana_cli.as_os_str(),
                        vec!["expand".as_ref(), tmp_file.as_os_str()],
                    ),
                    _ => unreachable!(),
                };

                self.client
                    .log_message(MessageType::INFO, format!("yana-lsp: running `{cmd:?} {:?}`", args))
                    .await;

                match std::process::Command::new(cmd).args(&args).output() {
                    Ok(output) => {
                        let stdout = String::from_utf8_lossy(&output.stdout);
                        let stderr = String::from_utf8_lossy(&output.stderr);
                        if !stdout.is_empty() {
                            self.client
                                .log_message(MessageType::INFO, format!("yana {command}: {stdout}"))
                                .await;
                        }
                        if !stderr.is_empty() {
                            self.client
                                .log_message(MessageType::ERROR, format!("yana {command}: {stderr}"))
                                .await;
                        }
                        if output.status.success() {
                            self.client
                                .log_message(MessageType::INFO, format!("yana {command}: OK"))
                                .await;
                        } else {
                            self.client
                                .log_message(
                                    MessageType::ERROR,
                                    format!("yana {command}: failed (exit {})", output.status),
                                )
                                .await;
                        }
                    }
                    Err(e) => {
                        self.client
                            .log_message(
                                MessageType::ERROR,
                                format!("yana-lsp: cannot spawn `{cmd:?}`: {e}"),
                            )
                            .await;
                    }
                }
            }

            "yana.debug" => {
                // Run the program and capture output; report as "debug session".
                let (cmd, args) = (
                    yana_cli.as_os_str(),
                    vec!["run".as_ref(), tmp_file.as_os_str()],
                );
                self.client
                    .log_message(MessageType::INFO, format!("yana-lsp: debug run `{cmd:?} {:?}`", args))
                    .await;
                match std::process::Command::new(cmd).args(&args).output() {
                    Ok(output) => {
                        let stdout = String::from_utf8_lossy(&output.stdout);
                        let stderr = String::from_utf8_lossy(&output.stderr);
                        let status = output.status;
                        let mut report = format!(
                            "🐛 Debug session for `{}`\nexit code: {}\n",
                            file_name,
                            status.code().unwrap_or(-1)
                        );
                        if !stdout.is_empty() {
                            report.push_str(&format!("\nstdout:\n{stdout}"));
                        }
                        if !stderr.is_empty() {
                            report.push_str(&format!("\nstderr:\n{stderr}"));
                        }
                        self.client
                            .log_message(MessageType::INFO, report.clone())
                            .await;
                        // Also show in a window message so the user sees it.
                        self.client
                            .show_message(MessageType::INFO, report)
                            .await;
                    }
                    Err(e) => {
                        self.client
                            .log_message(
                                MessageType::ERROR,
                                format!("yana-lsp: cannot spawn `{cmd:?}`: {e}"),
                            )
                            .await;
                    }
                }
            }

            "yana.ir" => {
                // Compile IR and send it back as a log message with source→IR mapping.
                let module = match self.world.module_for(&uri).await {
                    Some(m) => m,
                    None => {
                        self.client
                            .log_message(MessageType::ERROR, "yana-lsp: cannot compile IR")
                            .await;
                        return Ok(None);
                    }
                };

                let source_lines: Vec<&str> = source.lines().collect();
                let mut report = String::new();
                report.push_str(&format!("📦 IR for `{}`\n", file_name));
                report.push_str("========================================\n");

                // Map each instruction to its source line.
                for body in &module.bodies {
                    report.push_str(&format!("\nfunction symbol index {}\n", body.symbol));
                    for spanned_insn in &body.insns {
                        let span = spanned_insn.span;
                        let map = doc.source_map();
                        let ((sl, sc), (el, ec)) = map.span_to_range(span);
                        let src_line = source_lines.get(sl as usize).unwrap_or(&"");
                        report.push_str(&format!(
                            "  L{}:{}-{}:{} | {}\n",
                            sl + 1, sc + 1, el + 1, ec + 1,
                            format_insn_brief(spanned_insn)
                        ));
                        report.push_str(&format!(
                            "      source: {}\n",
                            src_line.trim_end()
                        ));
                    }
                }
                report.push_str("========================================\n");

                self.client
                    .log_message(MessageType::INFO, report)
                    .await;
                self.client
                    .show_message(MessageType::INFO, format!("IR for `{}` compiled ({} instructions)", file_name, module.bodies.iter().map(|b| b.insns.len()).sum::<usize>()))
                    .await;
            }

            _ => {
                self.client
                    .log_message(MessageType::ERROR, format!("yana-lsp: unknown command `{command}`"))
                    .await;
                return Ok(None);
            }
        }

        Ok(None)
    }

    // -----------------------------------------------------------------------
    // Inlay hints
    // -----------------------------------------------------------------------

    async fn inlay_hint(
        &self,
        params: InlayHintParams,
    ) -> Result<Option<Vec<InlayHint>>> {
        let uri = &params.text_document.uri;
        let doc = match self.world.get(uri).await {
            Some(d) => d,
            None => return Ok(None),
        };
        let source = &doc.source;
        let map = doc.source_map();
        let mut hints: Vec<InlayHint> = Vec::new();

        // Hint 1: After `bind name @ place[: ty]` show type and mutability
        for sym in &doc.symbols {
            if matches!(sym.kind, SymKind::Bind | SymKind::Static) {
                let range = span_to_range(&map, sym.span);
                let end_col = range.end.character;
                let hint_text = if sym.kind == SymKind::Bind {
                    format!(" // {name} → {detail}", name = sym.name, detail = sym.detail)
                } else {
                    format!(" // static {name}: {detail}", name = sym.name, detail = sym.detail)
                };
                hints.push(InlayHint {
                    position: Position {
                        line: range.start.line,
                        character: end_col,
                    },
                    label: InlayHintLabel::String(hint_text),
                    kind: Some(InlayHintKind::TYPE),
                    text_edits: None,
                    tooltip: Some(format!("Type info for `{}`", sym.name).into()),
                    padding_left: Some(true),
                    padding_right: Some(false),
                    data: None,
                });
            }
        }

        // Hint 2: After register usage show bit width
        for line in source.lines().enumerate() {
            let line_idx = line.0 as u32;
            let line_text = line.1;
            for (name, _) in knowledge::registers() {
                if let Some(pos) = find_word_pos(line_text, &name) {
                    let reg = yana_ast::reg::Reg::parse(&name);
                    if let Some(r) = reg {
                        let bits = r.size().bits();
                        hints.push(InlayHint {
                            position: Position {
                                line: line_idx,
                                character: pos as u32 + name.len() as u32,
                            },
                            label: InlayHintLabel::String(format!(" {bits}b")),
                            kind: Some(InlayHintKind::TYPE),
                            text_edits: None,
                            tooltip: Some(
                                format!("Register `{name}` is {bits}-bit", name = name).into(),
                            ),
                            padding_left: Some(true),
                            padding_right: Some(false),
                            data: None,
                        });
                    }
                }
            }
        }

        // Hint 3: Const folding preview — show evaluated value next to `const NAME = ...`
        for sym in &doc.symbols {
            if sym.kind == SymKind::Const {
                let range = span_to_range(&map, sym.span);
                let end_col = range.end.character;
                if let Some(val) = self.world.const_value(uri, &sym.name).await {
                    let hint_text = format!(" = {val}");
                    hints.push(InlayHint {
                        position: Position {
                            line: range.start.line,
                            character: end_col,
                        },
                        label: InlayHintLabel::String(hint_text),
                        kind: Some(InlayHintKind::TYPE),
                        text_edits: None,
                        tooltip: Some(format!("Const `{}` folds to {val}", sym.name).into()),
                        padding_left: Some(true),
                        padding_right: Some(false),
                        data: None,
                    });
                }
            }
        }

        // Hint 4: `#[syscall(N)]` → the syscall's name, so the number is readable
        for (_start, end, nr) in syscall_attrs(source) {
            if let Some(name) = syscalls::name_of(nr) {
                hints.push(InlayHint {
                    position: offset_to_position(source, end),
                    label: InlayHintLabel::String(format!(" {name}")),
                    kind: Some(InlayHintKind::TYPE),
                    text_edits: None,
                    tooltip: syscalls::by_number(nr).map(|sc| {
                        InlayHintTooltip::MarkupContent(MarkupContent {
                            kind: MarkupKind::Markdown,
                            value: format!("{} · `{}`", sc.summary, sc.man),
                        })
                    }),
                    padding_left: Some(true),
                    padding_right: Some(false),
                    data: None,
                });
            }
        }

        Ok(Some(hints))
    }

    // -----------------------------------------------------------------------
    // Code lens
    // -----------------------------------------------------------------------

    async fn code_lens(
        &self,
        params: CodeLensParams,
    ) -> Result<Option<Vec<CodeLens>>> {
        let uri = &params.text_document.uri;
        let doc = match self.world.get(uri).await {
            Some(d) => d,
            None => return Ok(None),
        };
        let source = &doc.source;
        let map = doc.source_map();
        let mut lenses: Vec<CodeLens> = Vec::new();

        let uri_str = uri.to_string();

        for sym in &doc.symbols {
            let range = span_to_range(&map, sym.span);
            match sym.kind {
                SymKind::Function | SymKind::ExternFunction => {
                    // Run button
                    lenses.push(CodeLens {
                        range,
                        command: Some(Command {
                            title: format!("▶ Run `{}`", sym.name),
                            command: "yana.run".into(),
                            arguments: Some(vec![serde_json::Value::String(uri_str.clone())]),
                        }),
                        data: None,
                    });
                    // Build button
                    lenses.push(CodeLens {
                        range,
                        command: Some(Command {
                            title: format!("🔨 Build `{}`", sym.name),
                            command: "yana.build".into(),
                            arguments: Some(vec![serde_json::Value::String(uri_str.clone())]),
                        }),
                        data: None,
                    });
                }
                SymKind::Bind | SymKind::Static | SymKind::Const | SymKind::ConstFunction
                | SymKind::Label | SymKind::Struct => {
                    lenses.push(CodeLens {
                        range,
                        command: Some(Command {
                            title: format!("Find references to '{}'", sym.name),
                            command: "editor.action.referenceSearch.trigger".into(),
                            arguments: None,
                        }),
                        data: None,
                    });
                }
                SymKind::Parameter | SymKind::Section | SymKind::Import | SymKind::Group => {}
            }
        }

        Ok(Some(lenses))
    }

    // -----------------------------------------------------------------------
    // Folding ranges
    // -----------------------------------------------------------------------

    async fn folding_range(
        &self,
        params: FoldingRangeParams,
    ) -> Result<Option<Vec<FoldingRange>>> {
        let uri = &params.text_document.uri;
        let doc = match self.world.get(uri).await {
            Some(d) => d,
            None => return Ok(None),
        };
        let source = &doc.source;
        let map = doc.source_map();
        let mut ranges: Vec<FoldingRange> = Vec::new();

        for sym in &doc.symbols {
            let range = span_to_range(&map, sym.span);
            match sym.kind {
                SymKind::Function | SymKind::ExternFunction | SymKind::ConstFunction => {
                    // Fold from fn decl to end of its body — approximate: fold the declaration line
                    ranges.push(FoldingRange {
                        start_line: range.start.line,
                        start_character: Some(range.start.character),
                        end_line: range.start.line,
                        end_character: Some(range.end.character),
                        kind: Some(FoldingRangeKind::Region),
                        collapsed_text: None,
                    });
                }
                SymKind::Label => {
                    ranges.push(FoldingRange {
                        start_line: range.start.line,
                        start_character: Some(range.start.character),
                        end_line: range.start.line,
                        end_character: Some(range.end.character),
                        kind: Some(FoldingRangeKind::Region),
                        collapsed_text: None,
                    });
                }
                _ => {}
            }
        }

        // Also fold blocks `{ ... }` by scanning braces
        let mut brace_stack: Vec<(u32, u32)> = Vec::new();
        for (line_idx, line) in source.lines().enumerate() {
            let line_idx = line_idx as u32;
            for (col, ch) in line.char_indices() {
                if ch == '{' {
                    brace_stack.push((line_idx, col as u32));
                } else if ch == '}' {
                    if let Some((start_line, start_col)) = brace_stack.pop() {
                        if start_line != line_idx || start_col != col as u32 {
                            ranges.push(FoldingRange {
                                start_line,
                                start_character: Some(start_col),
                                end_line: line_idx,
                                end_character: Some(col as u32 + 1),
                                kind: Some(FoldingRangeKind::Region),
                                collapsed_text: None,
                            });
                        }
                    }
                }
            }
        }

        Ok(Some(ranges))
    }

    // -----------------------------------------------------------------------
    // Selection ranges
    // -----------------------------------------------------------------------

    async fn selection_range(
        &self,
        params: SelectionRangeParams,
    ) -> Result<Option<Vec<SelectionRange>>> {
        let uri = &params.text_document.uri;
        let doc = match self.world.get(uri).await {
            Some(d) => d,
            None => return Ok(None),
        };
        let source = &doc.source;
        let map = doc.source_map();
        let mut ranges: Vec<SelectionRange> = Vec::new();

        for pos in &params.positions {
            let word = word_at(source, *pos);
            if let Some(w) = word {
                // Find the smallest range containing this position
                let mut best: Option<Range> = None;
                for sym in &doc.symbols {
                    let r = span_to_range(&map, sym.span);
                    if r.start <= *pos && *pos < r.end {
                        if best.is_none() || range_size(r) < range_size(best.unwrap()) {
                            best = Some(r);
                        }
                    }
                }
                if let Some(r) = best {
                    ranges.push(SelectionRange {
                        range: r,
                        parent: None,
                    });
                } else {
                    // Fall back to word range
                    if let Some(wr) = crate::range::word_range_at(source, *pos) {
                        ranges.push(SelectionRange {
                            range: wr,
                            parent: None,
                        });
                    }
                }
            }
        }

        Ok(Some(ranges))
    }

    // -----------------------------------------------------------------------
    // Semantic tokens
    // -----------------------------------------------------------------------

    async fn semantic_tokens_full(
        &self,
        params: SemanticTokensParams,
    ) -> Result<Option<SemanticTokensResult>> {
        let uri = &params.text_document.uri;
        let doc = match self.world.get(uri).await {
            Some(d) => d,
            None => return Ok(None),
        };
        Ok(Some(SemanticTokensResult::Tokens(build_semantic_tokens(&doc))))
    }

    async fn semantic_tokens_range(
        &self,
        params: SemanticTokensRangeParams,
    ) -> Result<Option<SemanticTokensRangeResult>> {
        let uri = &params.text_document.uri;
        let doc = match self.world.get(uri).await {
            Some(d) => d,
            None => return Ok(None),
        };
        Ok(Some(SemanticTokensRangeResult::Tokens(build_semantic_tokens(&doc))))
    }
}

// ===========================================================================
// Helpers
// ===========================================================================

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

fn make_code_action(
    title: impl Into<String>,
    kind: CodeActionKind,
    uri: Url,
    range: Range,
    insert_text: impl Into<String>,
) -> CodeAction {
    let title = title.into();
    CodeAction {
        title,
        kind: Some(kind),
        diagnostics: None,
        edit: Some(WorkspaceEdit {
            changes: Some(HashMap::from([(uri, vec![TextEdit {
                range,
                new_text: insert_text.into(),
            }])])),
            document_changes: None,
            change_annotations: None,
        }),
        command: None,
        is_preferred: Some(false),
        disabled: None,
        data: None,
    }
}

async fn signature_for(world: &Arc<World>, name: &str) -> Result<Option<SignatureHelp>> {
    for sym in world.all_symbols().await {
        if sym.name == name && matches!(sym.kind, SymKind::Function | SymKind::ExternFunction) {
            if let Some(doc) = world.get(&sym.uri).await {
                for s2 in &doc.symbols {
                    if s2.name == name {
                        return Ok(Some(SignatureHelp {
                            signatures: vec![SignatureInformation {
                                label: format!("{name} {}", s2.detail),
                                documentation: None,
                                active_parameter: Some(0),
                                parameters: None,
                            }],
                            active_signature: Some(0),
                            active_parameter: Some(0),
                        }));
                    }
                }
            }
        }
    }
    Ok(None)
}

/// Find all whole-word occurrences of `word` in `source` as ranges.
fn find_word_occurrences(source: &str, word: &str) -> Vec<Range> {
    let mut out = Vec::new();
    let mut search_from = 0usize;
    let wlen = word.len();

    while let Some(pos) = source[search_from..].find(word) {
        let abs = search_from + pos;
        let end = abs + wlen;
        let before_ok = abs == 0 || !is_word_char(source.as_bytes()[abs - 1]);
        let after_ok = end >= source.len() || !is_word_char(source.as_bytes()[end]);
        if before_ok && after_ok {
            let (sl, sc) = byte_to_line_col(source, abs);
            let (el, ec) = byte_to_line_col(source, end);
            out.push(Range {
                start: Position { line: sl as u32, character: sc as u32 },
                end: Position { line: el as u32, character: ec as u32 },
            });
        }
        search_from = end;
    }
    out
}

fn is_word_char(b: u8) -> bool {
    (b as char).is_ascii_alphanumeric() || b == b'_' || b == b'.' || b == b'\''
}

fn byte_to_line_col(source: &str, byte_offset: usize) -> (u32, u32) {
    let mut line = 0u32;
    let mut col = 0u32;
    for (i, c) in source.char_indices() {
        if i == byte_offset {
            return (line, col);
        }
        if c == '\n' {
            line += 1;
            col = 0;
        } else {
            col += 1;
        }
    }
    (line, col)
}

/// Text-based context detection.
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

    if let Some(h) = t.rfind("#[") {
        if !t[h..].contains(']') {
            return Ctx::Attribute;
        }
    }
    if t.ends_with('\'')
        || (t.chars().last().map(|c| c.is_ascii_alphanumeric()).unwrap_or(false) && t.contains('\''))
    {
        if let Some(q) = t.rfind('\'') {
            if !t[..q].contains(' ') || t.ends_with('\'') || is_label_site(t) {
                return Ctx::Label;
            }
        }
    }
    if t.ends_with('@') || t.ends_with("@ ") {
        return Ctx::Place;
    }
    if t.ends_with(':') || t.ends_with(": ") {
        return Ctx::Type;
    }
    if t.ends_with('.') {
        return Ctx::Section;
    }
    if let Some(p) = t.rfind("branch") {
        let tail = &t[p..];
        if tail.contains('(') && !tail.contains("=>") {
            return Ctx::Flag;
        }
    }
    if let Some(b) = t.rfind('[') {
        if !t[b..].contains(']') {
            return Ctx::Register;
        }
    }
    for kw in ["push {", "pop {"] {
        if let Some(b) = t.rfind(kw) {
            if !t[b..].contains('}') {
                return Ctx::Register;
            }
        }
    }
    Ctx::General
}

/// Names bound via `bind name @` and fn params — cheap scan.
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

/// Extract a bind name from messages like `cannot write to `x`: ...`.
fn extract_bind_name(msg: &str) -> Option<String> {
    let start = msg.find('`')?;
    let end = msg[start + 1..].find('`')?;
    Some(msg[start + 1..start + 1 + end].to_string())
}

/// Extract type mismatch info: (name, expected, found)
fn extract_type_mismatch(msg: &str) -> Option<(String, String, String)> {
    // Look for patterns like "expected `u64`, found `u32`"
    let expected_start = msg.find("expected `")?;
    let expected_end = msg[expected_start + 10..].find('`')?;
    let expected = msg[expected_start + 10..expected_start + 10 + expected_end].to_string();
    let found_start = msg.find("found `")?;
    let found_end = msg[found_start + 7..].find('`')?;
    let found = msg[found_start + 7..found_start + 7 + found_end].to_string();
    let name = extract_bind_name(msg).unwrap_or_else(|| "value".to_string());
    Some((name, expected, found))
}

/// Extract unknown label name
fn extract_unknown_label(msg: &str) -> Option<String> {
    // Pattern: "label ''loop' is not defined"
    let start = msg.find("'")?;
    let end = msg[start + 1..].find('\'')?;
    Some(msg[start + 1..start + 1 + end].to_string())
}

fn is_label_site(t: &str) -> bool {
    t.rfind("=>").map(|i| !t[i..].contains(';')).unwrap_or(false)
}

// Indices into the semantic token legend declared in `initialize`.
const TOKEN_NAMESPACE: u32 = 0;
const TOKEN_TYPE: u32 = 1;
const TOKEN_CLASS: u32 = 2;
const TOKEN_ENUM: u32 = 3;
const TOKEN_INTERFACE: u32 = 4;
const TOKEN_STRUCT: u32 = 5;
const TOKEN_PARAMETER: u32 = 6;
const TOKEN_VARIABLE: u32 = 7;
const TOKEN_ENUM_MEMBER: u32 = 8;
const TOKEN_EVENT: u32 = 9;
const TOKEN_FUNCTION: u32 = 10;
const TOKEN_METHOD: u32 = 11;
const TOKEN_MACRO: u32 = 12;
const TOKEN_KEYWORD: u32 = 13;
const TOKEN_COMMENT: u32 = 14;
const TOKEN_STRING: u32 = 15;
const TOKEN_NUMBER: u32 = 16;
const TOKEN_REGEXP: u32 = 17;
const TOKEN_OPERATOR: u32 = 18;

// Bit indices into the semantic token modifier legend.
const MOD_DECLARATION: u32 = 1 << 0;
const MOD_DOCUMENTATION: u32 = 1 << 1;
const MOD_READONLY: u32 = 1 << 2;

/// Build semantic tokens for a whole document (manual delta encoding).
fn build_semantic_tokens(doc: &Document) -> SemanticTokens {
    let source = &doc.source;
    let symbols = &doc.symbols;
    let symbol_names: Vec<&str> = symbols.iter().map(|s| s.name.as_str()).collect();

    let mut tokens: Vec<(u32, u32, u32, u32, u32)> = Vec::new();

    for (line_idx, line) in source.lines().enumerate() {
        let mut col = 0;
        let chars: Vec<char> = line.chars().collect();
        while col < chars.len() {
            let ch = chars[col];
            if ch.is_ascii_alphanumeric() || ch == '_' || ch == '.' || ch == '\'' {
                let mut end = col;
                while end < chars.len()
                    && (chars[end].is_ascii_alphanumeric()
                        || chars[end] == '_'
                        || chars[end] == '.'
                        || chars[end] == '\'')
                {
                    end += 1;
                }
                let word: String = chars[col..end].iter().collect();
                let start_col = col as u32;
                let length = (end - col) as u32;

                let token_type = classify_token(&word, &symbol_names);
                let token_modifiers = classify_modifiers(&word, symbols, start_col);

                tokens.push((line_idx as u32, start_col, length, token_type, token_modifiers));
                col = end;
            } else {
                col += 1;
            }
        }
    }

    let mut data: Vec<SemanticToken> = Vec::with_capacity(tokens.len());
    let mut prev_line = 0u32;
    let mut prev_col = 0u32;
    for (line, start, length, ty, mod_) in tokens {
        let delta_start = if line == prev_line {
            start.saturating_sub(prev_col)
        } else {
            start
        };
        data.push(SemanticToken {
            delta_line: line - prev_line,
            delta_start,
            length,
            token_type: ty,
            token_modifiers_bitset: mod_,
        });
        prev_line = line;
        prev_col = start;
    }

    SemanticTokens { result_id: None, data }
}

fn classify_token(word: &str, symbol_names: &[&str]) -> u32 {
    if knowledge::keywords().iter().any(|k| k.label == word) {
        return TOKEN_KEYWORD;
    }
    if knowledge::types().iter().any(|t| t.label == word) {
        return TOKEN_TYPE;
    }
    if knowledge::sections().iter().any(|s| s.label == word) {
        return TOKEN_NAMESPACE;
    }
    if knowledge::flags().iter().any(|f| f.label == word) {
        return TOKEN_ENUM_MEMBER;
    }
    if knowledge::registers().iter().any(|(n, _)| n == word) {
        return TOKEN_VARIABLE;
    }
    if symbol_names.contains(&word) {
        return TOKEN_FUNCTION;
    }
    if binding_names_crude(word) {
        return TOKEN_VARIABLE;
    }
    TOKEN_VARIABLE
}

fn classify_modifiers(word: &str, symbols: &[SymbolEntry], _start_col: u32) -> u32 {
    let mut mask = 0u32;
    if symbols.iter().any(|s| s.name == word) {
        mask |= MOD_DECLARATION;
    }
    if knowledge::registers().iter().any(|(n, _)| n == word) {
        mask |= MOD_READONLY;
    }
    mask
}

fn binding_names_crude(word: &str) -> bool {
    let mut chars = word.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_alphabetic() || c == '_')
}

fn find_word_pos(line: &str, word: &str) -> Option<usize> {
    line.find(word)
}

fn range_size(r: Range) -> u32 {
    (r.end.line - r.start.line) * 1000 + (r.end.character - r.start.character)
}

// ---------------------------------------------------------------------------
// Syscall docs (§5.5) — `#[syscall(N)]` hover + inlay hints
// ---------------------------------------------------------------------------

/// Every `#[syscall(N)]` in `source` as `(start, end, nr)` byte offsets,
/// where `[start, end)` covers the whole attribute.
fn syscall_attrs(source: &str) -> Vec<(usize, usize, i64)> {
    let mut out = Vec::new();
    let mut from = 0usize;
    while let Some(rel) = source[from..].find("#[syscall") {
        let start = from + rel;
        let Some(close) = source[start..].find(']').map(|e| start + e + 1) else {
            break;
        };
        let attr = &source[start..close];
        if let (Some(open), Some(close_paren)) = (attr.find('('), attr.rfind(')')) {
            if open < close_paren {
                let digits = attr[open + 1..close_paren].trim();
                if let Ok(nr) = digits.parse::<i64>() {
                    out.push((start, close, nr));
                }
            }
        }
        from = close;
    }
    out
}

/// The `#[syscall(N)]` attribute containing `pos`, with the range of `N`.
fn syscall_attr_at(source: &str, pos: Position) -> Option<(i64, Option<Range>)> {
    let offset = position_to_offset(source, pos)?;
    for (start, end, nr) in syscall_attrs(source) {
        if offset >= start && offset <= end {
            // Range of the number itself, so the hover highlights `N`.
            let digits = source[start..end]
                .find('(')
                .map(|p| start + p + 1)
                .unwrap_or(start);
            let digits_end = source[start..end]
                .rfind(')')
                .map(|p| start + p)
                .unwrap_or(end);
            let range = Range {
                start: offset_to_position(source, digits),
                end: offset_to_position(source, digits_end),
            };
            return Some((nr, Some(range)));
        }
    }
    None
}

/// The `#[syscall(N)]` number attached to `extern fn name` in `file`.
fn extern_syscall_number(file: Option<&File>, name: &str) -> Option<i64> {
    file?.items.iter().find_map(|item| match item {
        Item::ExternFn(e) if e.sig.name == name => e.syscall_number(),
        _ => None,
    })
}

/// Markdown hover for one syscall: signature, arguments, return, man page.
fn syscall_markdown(sc: &syscalls::Syscall, nr: Option<i64>) -> String {
    let mut md = String::new();
    let nr = nr.unwrap_or(sc.nr);
    md.push_str(&format!("**`{}`** — syscall {nr}", sc.name));
    if sc.nr != nr {
        md.push_str(&format!(" (номер {} в таблице)", sc.nr));
    }
    md.push_str(&format!(" · `{}`\n\n", sc.man));
    md.push_str(&format!("```c\n{}\n```\n\n", sc.signature));
    md.push_str(&format!("{}\n\n", sc.summary));

    if !sc.args.is_empty() {
        md.push_str("| регистр | имя | тип | смысл |\n|---|---|---|---|\n");
        for a in sc.args {
            md.push_str(&format!(
                "| `{}` | `{}` | `{}` | {} |\n",
                a.reg, a.name, a.ty, a.doc
            ));
        }
        md.push('\n');
    } else {
        md.push_str("Аргументов нет.\n\n");
    }

    md.push_str(&format!("**Возврат**: {}\n\n", sc.returns));
    md.push_str(
        "§5.5 — номер syscall в `rax`, аргументы в `rdi, rsi, rdx, r10, r8, r9`, \
         результат в `rax`; инструкция `syscall` портит `rcx` и `r11`.",
    );
    md
}

// ---------------------------------------------------------------------------
// Explanation helpers — full docs from SPEC.md
// ---------------------------------------------------------------------------

/// Map a shared [`SymKind`] to the LSP symbol kind.
fn lsp_kind(kind: SymKind) -> tower_lsp::lsp_types::SymbolKind {
    use tower_lsp::lsp_types::SymbolKind as LspKind;
    match kind {
        SymKind::Bind | SymKind::Static => LspKind::VARIABLE,
        SymKind::Function | SymKind::ExternFunction | SymKind::ConstFunction => LspKind::FUNCTION,
        SymKind::Const => LspKind::CONSTANT,
        SymKind::Label => LspKind::STRING,
        SymKind::Parameter => LspKind::TYPE_PARAMETER,
        SymKind::Struct => LspKind::STRUCT,
        SymKind::Section | SymKind::Import | SymKind::Group => LspKind::NAMESPACE,
    }
}

fn symbol_explanation(sym: &SymbolEntry) -> String {
    match sym.kind {
        SymKind::Bind => format!(
            "§3 Binding\n\n`{}` is a named place in memory or a register. Use `mut` + `alt` to write to it after initialisation.\n\nSee SPEC §3 (places and bindings).",
            sym.name
        ),
        SymKind::Static => format!(
            "§7 Static binding\n\n`{}` lives in a data section (`.rodata`/`.data`/`.bss`). Its address can be taken with `&{name}`.\n\nSee SPEC §7 (data sections).",
            sym.name,
            name = sym.name
        ),
        SymKind::Function => format!(
            "§5.1 Function\n\n`{}` is a callable code block. Parameters are passed in registers per the SysV ABI.\n\nSee SPEC §5.1 (functions).",
            sym.name
        ),
        SymKind::ExternFunction => format!(
            "§5.5 Extern function\n\n`{}` is declared externally (e.g. a syscall). Calls lower to `mov rax, N; syscall` when `#[syscall(N)]` is set.\n\nSee SPEC §5.5 (syscalls).",
            sym.name
        ),
        SymKind::Const => format!(
            "§7 Constant\n\n`{}` is a compile-time constant value.\n\nSee SPEC §7 (constants).",
            sym.name
        ),
        SymKind::ConstFunction => format!(
            "§8 Const fn\n\n`{}` is evaluated at build time. No memory or register access allowed.\n\nSee SPEC §8 (const evaluation).",
            sym.name
        ),
        SymKind::Label => format!(
            "§6 Label\n\n`' {}` is a jump target inside a function. `branch (...) => ' {name};` transfers control there.\n\nSee SPEC §6 (labels and branches).",
            sym.name,
            name = sym.name
        ),
        SymKind::Parameter => format!(
            "§5.1 Parameter\n\n`{}` is a function parameter bound to a register place.\n\nSee SPEC §5.1 (function signatures).",
            sym.name
        ),
        SymKind::Section => format!(
            "§7 Section\n\n`{}` is a data-section placeholder.\n\nSee SPEC §7 (data sections).",
            sym.name
        ),
        SymKind::Import => format!(
            "§10 Import\n\n`{}` is imported from another module via `use`.\n\nSee SPEC §10 (modules).",
            sym.name
        ),
        SymKind::Group => format!(
            "§3 Group\n\n`{}` is a named alias for a list of places. It emits no code and expands in `bind`/`alt`/`push`/`pop`.\n\nSee SPEC §3 (places and bindings).",
            sym.name
        ),
        SymKind::Struct => format!(
            "§8 Struct\n\n`{}` is a const-only data layout. Construct values with `Name(...)` in field declaration order; static layout is C-like (align + padding).\n\nSee SPEC §8 (const evaluation).",
            sym.name
        ),
    }
}

fn section_explanation(section: &str) -> String {
    match section {
        ".text" => "§7 — Executable code section. Read-only at runtime.",
        ".rodata" => "§7 — Read-only data section. Use for strings and constants.",
        ".data" => "§7 — Initialised writable data section.",
        ".bss" => "§7 — Uninitialised writable data section (zero-filled).",
        _ => "§7 — Data section.",
    }
    .to_string()
}

fn register_explanation(reg: &str) -> String {
    format!(
        "§3 Register places\n\n`{}` is an x86-64 general-purpose register. It can be used as a place in `bind`, `alt`, `push`, `pop`, etc.\n\nRegister families share aliases: e.g. `rax` (64-bit) → `eax` (32) → `ax` (16) → `al` (8).\n\nSee SPEC §3 (places).",
        reg
    )
}

fn keyword_explanation(keyword: &str) -> String {
    match keyword {
        "bind" => "§3 — Create a named binding to a place. Syntax: `bind [mut] name @ place[: type] [= init];`",
        "alt" => "§4.1 — Write to a place. Syntax: `alt dst op= src;`. Requires `mut` for bound names.",
        "push" => "§4.3 — Push values onto the stack in written order.",
        "pop" => "§4.3 — Pop values from the stack in written order.",
        "branch" => "§4.4 — Conditional jump. Syntax: `branch (cond) => 'label;` or `branch => 'label;`.",
        "call" => "§5.3 — Call a function. Arguments passed by name: `call fn { param: value };`",
        "return" => "§5.2 — Return from a function.",
        "syscall" => "§5.5 — инструкция `syscall`:\n\n\
            - `rax` — номер системного вызова;\n\
            - `rdi`, `rsi`, `rdx`, `r10`, `r8`, `r9` — аргументы;\n\
            - результат приходит в `rax` (отрицательное значение — `-errno`);\n\
            - `rcx` и `r11` портятся.\n\n\
            Обычно писать её вручную не нужно: `#[syscall(N)] extern fn write(...)` \
            даёт именованную обёртку, вызов которой раскрывается в `mov rax, N; syscall`. \
            Наведите на номер в `#[syscall(N)]`, чтобы увидеть имя syscall, аргументы и man-страницу.",
        "label" => "§6 — Define a local jump target block.",
        "fn" => "§5.1 — Define a function.",
        "extern" => "§5.5 — Declare an external function.",
        "const" => "§7 — Define a compile-time constant.",
        "const fn" => "§8 — Define a compile-time function.",
        "macro" => "§9 — Define a macro.",
        "macro_rules" => "§9 — Define a macro with pattern rules.",
        "align" => "§4.3 — Align stack pointer.",
        "atomic" => "§12 — Atomic read-modify-write.",
        "volatile" => "§12 — Volatile memory access.",
        _ => "See SPEC for details.",
    }
    .to_string()
}

/// Brief textual representation of an IR instruction (used by `yana.ir` command).
fn format_insn_brief(insn: &yana_codegen::ir::SpannedInsn) -> String {
    use yana_codegen::ir::Insn;
    match &insn.insn {
        Insn::Mov { dst, src, size } => format!("mov {:?} <- {:?} ({size})", dst, src),
        Insn::Add { dst, src, size } => format!("add {:?} += {:?} ({size})", dst, src),
        Insn::Sub { dst, src, size } => format!("sub {:?} -= {:?} ({size})", dst, src),
        Insn::Jmp { label } => format!("jmp label[{label}]"),
        Insn::Jcc { cc, label } => format!("jcc {:?} label[{label}]", cc),
        Insn::Syscall => "syscall".to_string(),
        Insn::Ret => "ret".to_string(),
        Insn::Push { src, size } => format!("push {:?} ({size})", src),
        Insn::Pop { dst, size } => format!("pop {:?} ({size})", dst),
        Insn::Call { .. } => "call".to_string(),
        Insn::Cmp { a, b, .. } => format!("cmp {:?}, {:?}", a, b),
        _ => format!("{:?}", insn.insn),
    }
}