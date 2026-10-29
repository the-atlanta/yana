//! YANA lexer: source text → token stream (logos).
//!
//! Comments are trivia (§1): they are captured into a side channel
//! ([`token::begin_comment_capture`]) so the NASM backend can echo them, and
//! never reach the grammar.

use logos::Logos;
use yana_ast::Span;

pub mod token;
pub use token::{begin_comment_capture, take_comments, unescape_string, Token};

/// A lexed token with its span.
#[derive(Debug, Clone, PartialEq)]
pub struct LexedToken {
    pub kind: Token,
    pub span: Span,
}

/// Result of lexing.
#[derive(Debug, Clone)]
pub struct LexOutput {
    pub tokens: Vec<LexedToken>,
    /// Comments as `(byte_offset, text_without_slashes)`, in source order.
    pub comments: Vec<(u32, String)>,
    /// Spans of unrecognized bytes — always reported as syntax errors.
    pub errors: Vec<Span>,
}

/// Lex `source`.
///
/// Unrecognized bytes are recorded in [`LexOutput::errors`] and skipped; the
/// parser still runs on the remaining stream so the LSP can show partial
/// results after a bad byte.
pub fn lex(source: &str) -> LexOutput {
    token::begin_comment_capture();

    let mut lexer = Token::lexer(source);
    let mut tokens = Vec::new();
    let mut errors = Vec::new();

    while let Some(result) = lexer.next() {
        let s = lexer.span();
        let span = Span::new(s.start as u32, s.end as u32);
        match result {
            // Comment is trivia: not part of the grammar stream.
            Ok(Token::Comment) => {}
            Ok(tok) => tokens.push(LexedToken { kind: tok, span }),
            Err(()) => errors.push(span),
        }
    }

    LexOutput { tokens, comments: token::take_comments(), errors }
}

/// The `(offset, Token, offset)` triples that the LALRPOP parser consumes.
///
/// Runs the §0.5 pre-pass first: collapses `Ident ":" Ident` into a synthetic
/// [`Token::PairReg`] when both idents are register names (spec §4.5). Register
/// names and type keywords are disjoint token classes, so `rax: u64` (annotated
/// register) and `rdx:rax` (register pair) never collide.
pub fn token_triples(out: &LexOutput) -> Vec<(usize, Token, usize)> {
    let mut triples: Vec<(usize, Token, usize)> = out
        .tokens
        .iter()
        .map(|t| (t.span.lo as usize, t.kind.clone(), t.span.hi as usize))
        .collect();

    // Collapse `reg ":" reg` → PairReg, scanning left to right.
    let mut i = 0;
    while i + 2 < triples.len() {
        let collapsed = match (&triples[i].1, &triples[i + 1].1, &triples[i + 2].1) {
            (Token::Ident(a), Token::Colon, Token::Ident(b)) => {
                match (yana_ast::reg::Reg::parse(a), yana_ast::reg::Reg::parse(b)) {
                    (Some(hi), Some(lo)) => Some(Token::PairReg((
                        hi,
                        lo,
                        triples[i].0 as u32,
                        triples[i + 2].2 as u32,
                    ))),
                    _ => None,
                }
            }
            _ => None,
        };
        if let Some(tok) = collapsed {
            let lo = triples[i].0;
            let hi = triples[i + 2].2;
            triples.splice(i..i + 3, std::iter::once((lo, tok, hi)));
            // don't advance: overlapping pairs like a:b:c are pathological, but
            // staying put keeps the scan consistent
        }
        i += 1;
    }

    triples
}
