//! Convert YANA byte spans to LSP ranges and locate the word under a cursor.
//!
//! The text logic itself lives in `yana_ast::text`; this module only adapts
//! it to `tower_lsp` types so the CLI/DAP can share the same implementation.

use tower_lsp::lsp_types::{Position, Range};
use yana_ast::diag::SourceMap;
use yana_ast::Span;

/// Convert a byte span into an LSP range (0-based line/col).
pub fn span_to_range(map: &SourceMap, span: Span) -> Range {
    let ((sl, sc), (el, ec)) = map.span_to_range(span);
    Range {
        start: Position { line: sl as u32, character: sc as u32 },
        end: Position { line: el as u32, character: ec as u32 },
    }
}

/// The range of the identifier/word under `pos`, or `None` if there is none.
pub fn word_range_at(source: &str, pos: Position) -> Option<Range> {
    let (start, end) = yana_ast::text::word_range_at(source, pos.line as usize, pos.character as usize)?;
    Some(Range {
        start: Position { line: pos.line, character: start as u32 },
        end: Position { line: pos.line, character: end as u32 },
    })
}

/// Convert an LSP position (UTF-16 columns, as the protocol specifies) into a
/// byte offset into `source`.
pub fn position_to_offset(source: &str, pos: Position) -> Option<usize> {
    yana_ast::text::position_to_offset(source, pos.line, pos.character)
}

/// Convert a byte offset into an LSP position (UTF-16 columns).
pub fn offset_to_position(source: &str, offset: usize) -> Position {
    let (line, character) = yana_ast::text::offset_to_position(source, offset);
    Position { line, character }
}

/// The text of the word under `pos`.
pub fn word_at(source: &str, pos: Position) -> Option<String> {
    yana_ast::text::word_at(source, pos.line as usize, pos.character as usize)
}
