//! `yana fmt` — a conservative source formatter.
//!
//! The formatter is deliberately line-based and token-aware rather than a
//! full pretty-printer: it fixes under-indentation from brace depth, strips
//! trailing whitespace and collapses runs of blank lines. It never reduces
//! existing indentation (so continuation lines and hand-aligned parameter
//! lists keep their shape), and everything inside a line is preserved
//! verbatim — formatting can never change program semantics.
//!
//! Brace depth comes from lexed tokens, not raw characters, so `{`/`}` in
//! string literals and comments do not affect indentation. Comments are
//! trivia in the lexer but still live on their original lines.

use yana_lexer::{lex, Token};

/// Indentation width in spaces.
pub const INDENT: usize = 4;

/// Format `source` and return the result.
///
/// The output always ends with exactly one newline (unless the input is
/// empty).
pub fn format_source(source: &str) -> String {
    if source.is_empty() {
        return String::new();
    }

    // Byte offset → line index lookup table.
    let mut line_starts = vec![0usize];
    for (i, b) in source.bytes().enumerate() {
        if b == b'\n' {
            line_starts.push(i + 1);
        }
    }
    let line_of = |off: usize| -> usize {
        match line_starts.binary_search(&off) {
            Ok(i) => i,
            Err(i) => i.saturating_sub(1),
        }
    };

    let lexed = lex(source);
    let nlines = line_starts.len();
    let mut starts_with_rbrace = vec![false; nlines];
    let mut first_token_seen = vec![false; nlines];
    let mut delta = vec![0i32; nlines];

    for tok in &lexed.tokens {
        let line = line_of(tok.span.lo as usize);
        if line >= nlines {
            continue;
        }
        if !first_token_seen[line] {
            first_token_seen[line] = true;
            starts_with_rbrace[line] = matches!(tok.kind, Token::RBrace);
        }
        match tok.kind {
            Token::LBrace => delta[line] += 1,
            Token::RBrace => delta[line] -= 1,
            _ => {}
        }
    }

    let mut out = String::with_capacity(source.len());
    let mut depth: i32 = 0;
    let mut last_blank = false;

    for (idx, raw) in source.split('\n').enumerate() {
        // `split` yields a final empty slice when the source ends in `\n`.
        if idx + 1 == nlines && raw.is_empty() {
            break;
        }
        let without_trailing = raw.trim_end();
        let trimmed = without_trailing.trim_start();
        let original_indent: usize = without_trailing
            .chars()
            .take_while(|c| *c == ' ' || *c == '\t')
            .map(|c| if c == '\t' { INDENT } else { 1 })
            .sum();

        if trimmed.is_empty() {
            if !last_blank && !out.is_empty() {
                out.push('\n');
                last_blank = true;
            }
            continue;
        }
        last_blank = false;

        let computed = if starts_with_rbrace.get(idx).copied().unwrap_or(false) {
            (depth - 1).max(0) as usize * INDENT
        } else {
            depth.max(0) as usize * INDENT
        };
        if computed <= original_indent && !starts_with_rbrace.get(idx).copied().unwrap_or(false) {
            // Keep hand-aligned continuations exactly as written.
            out.push_str(&without_trailing[..without_trailing.len() - trimmed.len()]);
        } else {
            for _ in 0..computed {
                out.push(' ');
            }
        }
        out.push_str(trimmed);
        out.push('\n');

        depth += delta.get(idx).copied().unwrap_or(0);
        if depth < 0 {
            depth = 0;
        }
    }

    // Exactly one trailing newline, no trailing blank lines.
    while out.ends_with("\n\n") {
        out.pop();
    }
    out
}

/// Is `source` already formatted?
pub fn is_formatted(source: &str) -> bool {
    format_source(source) == source
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn indents_braced_blocks() {
        let src = "fn main() -> ! {\nalt rax = 60;\nif rax {\nalt rdi = 1;\n}\n}\n";
        let want = "fn main() -> ! {\n    alt rax = 60;\n    if rax {\n        alt rdi = 1;\n    }\n}\n";
        assert_eq!(format_source(src), want);
    }

    #[test]
    fn closes_dedent_before_the_line() {
        let src = "fn f() {\n    label (x) {\n        alt rax = 1;\n    }\n}\n";
        assert_eq!(format_source(src), src);
    }

    #[test]
    fn ignores_braces_in_strings_and_comments() {
        let src = "bind s @ .rodata: [u8; 2] = \"{}\";\n// } not a brace\nfn f() {\n    alt rax = 1;\n}\n";
        let out = format_source(src);
        assert!(out.contains("    alt rax = 1;"), "{out}");
        assert!(out.contains("// } not a brace\nfn f()"), "{out}");
    }

    #[test]
    fn strips_trailing_whitespace_and_extra_blank_lines() {
        let src = "fn f() {   \n\n\n    alt rax = 1;   \n}\n";
        let want = "fn f() {\n\n    alt rax = 1;\n}\n";
        assert_eq!(format_source(src), want);
    }

    #[test]
    fn one_liners_stay_one_line() {
        let src = "fn f() { alt rax = 1; }\n";
        assert_eq!(format_source(src), src);
    }

    #[test]
    fn empty_input_stays_empty() {
        assert_eq!(format_source(""), "");
    }
}
