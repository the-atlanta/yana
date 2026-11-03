//! Text helpers shared by the LSP, DAP and CLI: word extraction and
//! line/column ↔ byte-offset conversion.
//!
//! Columns are UTF-16 code units, matching the LSP wire format. The module
//! deliberately has no editor-specific types so every frontend can use it.

/// Word characters used by hover/go-to-definition: identifiers, dotted
/// fields, and `'label` references.
fn is_word(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || ch == '_' || ch == '.' || ch == '\''
}

/// The range of the word under `(line, character)` in character columns.
pub fn word_range_at(source: &str, line: usize, character: usize) -> Option<(usize, usize)> {
    let line = source.lines().nth(line)?;
    let chars: Vec<char> = line.chars().collect();
    let c = character.min(chars.len());
    let mut start = c;
    while start > 0 && is_word(chars[start - 1]) {
        start -= 1;
    }
    let mut end = c;
    while end < chars.len() && is_word(chars[end]) {
        end += 1;
    }
    (end > start).then_some((start, end))
}

/// The text of the word under `(line, character)`.
pub fn word_at(source: &str, line: usize, character: usize) -> Option<String> {
    let line_text = source.lines().nth(line)?;
    let (start, end) = word_range_at(source, line, character)?;
    Some(line_text.chars().skip(start).take(end - start).collect())
}

/// Convert `(line, character)` (UTF-16 columns) into a byte offset.
pub fn position_to_offset(source: &str, line: u32, character: u32) -> Option<usize> {
    let mut offset = 0usize;
    for (i, text) in source.split('\n').enumerate() {
        if i as u32 == line {
            let mut units = 0u32;
            for (b, ch) in text.char_indices() {
                if units >= character {
                    return Some(offset + b);
                }
                units += ch.len_utf16() as u32;
            }
            return Some(offset + text.len());
        }
        offset += text.len() + 1; // the '\n' itself
    }
    None
}

/// Convert a byte offset into `(line, character)` (UTF-16 columns).
pub fn offset_to_position(source: &str, offset: usize) -> (u32, u32) {
    let offset = offset.min(source.len());
    let mut line = 0u32;
    let mut line_start = 0usize;
    for (i, ch) in source.char_indices() {
        if i >= offset {
            break;
        }
        if ch == '\n' {
            line += 1;
            line_start = i + 1;
        }
    }
    let character = source[line_start..offset]
        .chars()
        .map(|c| c.len_utf16() as u32)
        .sum();
    (line, character)
}

/// Levenshtein edit distance (insert/delete/substitute).
pub fn levenshtein(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    if a.is_empty() {
        return b.len();
    }
    if b.is_empty() {
        return a.len();
    }
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    let mut cur = vec![0usize; b.len() + 1];
    for (i, ca) in a.iter().enumerate() {
        cur[0] = i + 1;
        for (j, cb) in b.iter().enumerate() {
            let cost = usize::from(ca != cb);
            cur[j + 1] = (prev[j + 1] + 1).min(cur[j] + 1).min(prev[j] + cost);
        }
        std::mem::swap(&mut prev, &mut cur);
    }
    prev[b.len()]
}

/// The closest candidate to `needle`, if it is close enough to be a typo.
/// Threshold: distance ≤ max(2, len/3).
pub fn closest<'a>(needle: &str, candidates: impl IntoIterator<Item = &'a str>) -> Option<&'a str> {
    let limit = (needle.chars().count() / 3).max(2);
    let mut best: Option<(&str, usize)> = None;
    for c in candidates {
        let d = levenshtein(needle, c);
        if d <= limit && best.map(|(_, bd)| d < bd).unwrap_or(true) {
            best = Some((c, d));
        }
    }
    best.map(|(c, _)| c)
}
