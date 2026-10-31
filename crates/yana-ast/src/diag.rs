//! Diagnostics (§11): two classes — `redundant` (silenceable) and `contract`
//! (error under `--strict`). Modelled independently of any renderer so the CLI,
//! LSP and tests all consume the same structured form.
//!
//! Rendering to the terminal uses ariadne (see `yana-cli`/`yana-lsp`); rendering
//! to LSP uses [`Diagnostic::to_lsp_range`]-style helpers in the LSP crate.

use crate::span::Span;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiagLevel {
    /// Recoverable note, not surfaced as error.
    Note,
    /// A warning that can be silenced with an attribute (`redundant`).
    Warning,
    /// Under `--strict`, `contract` warnings become errors; lex/parse are always errors.
    Error,
}

/// Diagnostic class (§11).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiagCode {
    /// Redundant annotation — `warning(redundant)`, silenceable.
    Redundant,
    /// Contract mismatch — `warning(contract)`, error under `--strict`.
    Contract,
    /// Lexical/parse error — always fatal.
    Syntax,
    /// Semantic/typing error — always fatal.
    Semantic,
    /// Codegen/backend error — always fatal.
    Codegen,
}

impl DiagCode {
    /// Default level for this code (before `--strict` adjustment).
    pub fn default_level(self) -> DiagLevel {
        match self {
            DiagCode::Redundant | DiagCode::Contract => DiagLevel::Warning,
            DiagCode::Syntax | DiagCode::Semantic | DiagCode::Codegen => DiagLevel::Error,
        }
    }
}

/// A secondary annotation attached to a diagnostic (label + span).
#[derive(Debug, Clone)]
pub struct DiagLabel {
    pub message: String,
    pub span: Span,
    /// True for the primary span (drawn with a solid underline).
    pub primary: bool,
}

/// A single diagnostic produced by any pipeline stage.
#[derive(Debug, Clone)]
pub struct Diagnostic {
    pub code: DiagCode,
    pub level: DiagLevel,
    /// Short machine-readable kind, e.g. `"redundant"`, `"contract"`, `"type-mismatch"`.
    pub kind: String,
    pub message: String,
    pub labels: Vec<DiagLabel>,
    /// Optional help text.
    pub help: Option<String>,
    /// Optional note text.
    pub note: Option<String>,
}

impl Diagnostic {
    /// Build an error diagnostic with a single primary label.
    pub fn error(code: DiagCode, kind: impl Into<String>, message: impl Into<String>, span: Span) -> Self {
        Diagnostic {
            code,
            level: DiagLevel::Error,
            kind: kind.into(),
            message: message.into(),
            labels: vec![DiagLabel { message: String::new(), span, primary: true }],
            help: None,
            note: None,
        }
    }

    /// Build a warning with a single primary label.
    pub fn warn(code: DiagCode, kind: impl Into<String>, message: impl Into<String>, span: Span) -> Self {
        Diagnostic {
            code,
            level: DiagLevel::Warning,
            kind: kind.into(),
            message: message.into(),
            labels: vec![DiagLabel { message: String::new(), span, primary: true }],
            help: None,
            note: None,
        }
    }

    pub fn with_help(mut self, help: impl Into<String>) -> Self {
        self.help = Some(help.into());
        self
    }

    pub fn with_note(mut self, note: impl Into<String>) -> Self {
        self.note = Some(note.into());
        self
    }

    pub fn with_label(mut self, message: impl Into<String>, span: Span, primary: bool) -> Self {
        self.labels.push(DiagLabel { message: message.into(), span, primary });
        self
    }

    /// Set the message drawn under the primary underline (ariadne renders an
    /// empty `╰──` when the primary label has no text).
    pub fn with_primary_label(mut self, message: impl Into<String>) -> Self {
        if let Some(l) = self.labels.iter_mut().find(|l| l.primary) {
            l.message = message.into();
        }
        self
    }

    /// The primary span, if any.
    pub fn primary_span(&self) -> Option<Span> {
        self.labels.iter().find(|l| l.primary).map(|l| l.span).or_else(|| self.labels.first().map(|l| l.span))
    }

    /// Under `--strict`, `contract` warnings escalate to errors. Returns whether
    /// this diagnostic is fatal given the strict flag.
    pub fn is_fatal(&self, strict: bool) -> bool {
        match self.code {
            DiagCode::Contract => strict,
            _ => matches!(self.level, DiagLevel::Error),
        }
    }

    /// Apply `--strict`: escalate `contract` warnings to errors.
    pub fn adjusted_level(&self, strict: bool) -> DiagLevel {
        if strict && matches!(self.code, DiagCode::Contract) {
            DiagLevel::Error
        } else {
            self.level
        }
    }
}

/// Maps byte offsets to `(line, col)` for rendering, given the source text.
///
/// Built once per file; both ariadne rendering and LSP ranges use it.
pub struct SourceMap {
    /// Byte offset where each line starts.
    line_starts: Vec<u32>,
    source_len: u32,
}

impl SourceMap {
    pub fn new(source: &str) -> Self {
        let mut line_starts = vec![0u32];
        for (i, b) in source.bytes().enumerate() {
            if b == b'\n' {
                line_starts.push((i + 1) as u32);
            }
        }
        SourceMap { line_starts, source_len: source.len() as u32 }
    }

    /// Convert a byte offset to `(line, col)`, both 0-based (LSP convention).
    pub fn offset_to_line_col(&self, offset: u32) -> (u32, u32) {
        let offset = offset.min(self.source_len);
        // binary search for the last line_start <= offset
        let idx = match self.line_starts.binary_search(&offset) {
            Ok(i) => i,
            Err(i) => i.saturating_sub(1),
        };
        let line = idx as u32;
        let col = offset - self.line_starts[idx];
        (line, col)
    }

    /// Convert a span to an LSP-style range `((sl, sc), (el, ec))`, 0-based.
    pub fn span_to_range(&self, span: Span) -> ((u32, u32), (u32, u32)) {
        let start = self.offset_to_line_col(span.lo);
        let end = self.offset_to_line_col(span.hi);
        (start, end)
    }
}
