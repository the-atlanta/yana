//! YANA parser: source text → [`File`], with structured diagnostics.
//!
//! Pipeline: `yana_lexer::lex` → token triples → LALRPOP `FileParser`. Any
//! failure (lex error, parse error, fallible action) becomes a
//! [`Diagnostic`] the driver/CLI renders.

use lalrpop_util::lalrpop_mod;
use lalrpop_util::ParseError;
use yana_ast::{Diagnostic, DiagCode, File, Span};
use yana_lexer::Token;

pub mod gram;
pub mod macros;
pub use macros::ExpandResult;

lalrpop_mod!(
    #[allow(clippy::all)]
    #[rustfmt::skip]
    pub yana
);

/// The full result of parsing one source file.
#[derive(Debug)]
pub struct ParseOutput {
    /// The parsed file (present unless a hard parse error occurred).
    pub file: Option<File>,
    /// All diagnostics from lexing and parsing, in source order.
    pub diagnostics: Vec<Diagnostic>,
    /// Comments captured as trivia, `(byte_offset, text)`.
    pub comments: Vec<(u32, String)>,
}

impl ParseOutput {
    /// Did parsing produce any error-level diagnostic?
    pub fn has_errors(&self) -> bool {
        self.diagnostics.iter().any(|d| matches!(d.level, yana_ast::DiagLevel::Error))
    }
}

/// Parse `source` into a [`File`], collecting diagnostics.
pub fn parse(source: &str) -> ParseOutput {
    let lexed = yana_lexer::lex(source);
    let mut diagnostics = Vec::new();

    // Lex errors → syntax diagnostics.
    for span in &lexed.errors {
        diagnostics.push(
            Diagnostic::error(
                DiagCode::Syntax,
                "lex-error",
                "unrecognized byte in source",
                *span,
            )
            .with_help("YANA tokens are ASCII; check for stray characters."),
        );
    }

    let triples = yana_lexer::token_triples(&lexed);

    // §14 pass 0.5: macro expansion (§9). Token-level pre-pass, after lexing
    // (and after the PairReg collapse), before the LALRPOP parser — by parse
    // time all macro declarations and invocations are gone from the stream,
    // so the grammar stays macro-free (see docs/NOTES-macros.md).
    let macro_out = macros::expand(triples);
    diagnostics.extend(macro_out.diagnostics);

    // Merge the expansion comments (§9.7: every expansion is signed) into the
    // trivia channel, keeping byte-offset order.
    let mut comments = lexed.comments;
    comments.extend(macro_out.comments);
    comments.sort_by_key(|(off, _)| *off);

    let parser = yana::FileParser::new();

    match parser.parse(macro_out.triples) {
        Ok(file) => ParseOutput {
            file: Some(file),
            diagnostics,
            comments,
        },
        Err(err) => {
            diagnostics.push(parse_error_to_diag(err));
            ParseOutput {
                file: None,
                diagnostics,
                comments,
            }
        }
    }
}

/// Convert a LALRPOP [`ParseError`] into a [`Diagnostic`].
fn parse_error_to_diag(err: ParseError<usize, Token, Token>) -> Diagnostic {
    match err {
        ParseError::InvalidToken { location } => Diagnostic::error(
            DiagCode::Syntax,
            "invalid-token",
            "invalid token here",
            Span::new(location as u32, location as u32),
        ),
        ParseError::UnrecognizedEof { location, expected } => {
            let mut d = Diagnostic::error(
                DiagCode::Syntax,
                "unexpected-eof",
                "unexpected end of file",
                Span::new(location as u32, location as u32),
            );
            if !expected.is_empty() {
                d = d.with_help(format!("expected one of: {}", join_expected(&expected)));
            }
            d
        }
        ParseError::UnrecognizedToken { token: (lo, tok, hi), expected } => {
            let span = Span::new(lo as u32, hi as u32);
            let mut d = Diagnostic::error(
                DiagCode::Syntax,
                "unexpected-token",
                format!("unexpected token `{tok}`"),
                span,
            );
            if !expected.is_empty() {
                d = d.with_help(format!("expected one of: {}", join_expected(&expected)));
            }
            d
        }
        ParseError::ExtraToken { token: (lo, tok, hi) } => Diagnostic::error(
            DiagCode::Syntax,
            "extra-token",
            format!("extra token `{tok}`"),
            Span::new(lo as u32, hi as u32),
        ),
        ParseError::User { error } => user_error_to_diag(error),
    }
}

/// Fallible grammar actions fail with span-carrying synthetic tokens.
fn user_error_to_diag(tok: Token) -> Diagnostic {
    match tok {
        Token::BadNum(b) => Diagnostic::error(
            DiagCode::Syntax,
            "bad-number",
            format!("`{}` is not a valid integer literal", b.text),
            b.span(),
        )
        .with_help("Use decimal, 0x… hex, or 0b… binary; value must fit in 128 bits."),
        Token::BadEscape(b) => Diagnostic::error(
            DiagCode::Syntax,
            "bad-escape",
            format!("invalid escape sequence in `{}`", b.text),
            b.span(),
        )
        .with_help(r#"Valid escapes: \n \r \t \0 \\ \' \" \xNN."#),
        Token::BadReg(b) => Diagnostic::error(
            DiagCode::Syntax,
            "bad-register",
            format!("`{}` is not a register", b.text),
            b.span(),
        )
        .with_help("Expected an x86-64 register name like rax, eax, dl, r8, r15b."),
        Token::RemovedPub(b) => Diagnostic::error(
            DiagCode::Syntax,
            "pub-removed",
            "`pub` was removed from the language",
            b.span(),
        )
        .with_help("Export symbols with the `#[global]` attribute (SPEC §15, решение 29.10)."),
        Token::BadAtomicOrder(b) => Diagnostic::error(
            DiagCode::Syntax,
            "atomic-order",
            format!("`{}` is not a memory order (§12)", b.text),
            b.span(),
        )
        .with_help("Valid orders: relaxed, acquire, release, acqrel, seqcst."),
        other => Diagnostic::error(
            DiagCode::Syntax,
            "parse-error",
            format!("parse error near `{other}`"),
            Span::DUMMY,
        ),
    }
}

fn join_expected(expected: &[String]) -> String {
    let mut seen: Vec<&str> = Vec::new();
    for e in expected {
        if !seen.contains(&e.as_str()) {
            seen.push(e.as_str());
        }
    }
    seen.join(", ")
}

/// Convenience for tests that expect success.
#[track_caller]
pub fn parse_ok(source: &str) -> File {
    let out = parse(source);
    assert!(
        !out.has_errors() && out.file.is_some(),
        "expected successful parse, got diagnostics: {:?}",
        out.diagnostics.iter().map(|d| (&d.kind, &d.message)).collect::<Vec<_>>()
    );
    out.file.unwrap()
}
