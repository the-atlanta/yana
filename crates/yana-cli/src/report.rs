//! Diagnostic rendering with ariadne: one place where [`Diagnostic`]s become
//! terminal output. Used by the CLI; the LSP converts the same structs into
//! LSP diagnostics instead.

use ariadne::{Color, Label, Report, ReportKind, Source};
use yana_ast::diag::SourceMap;
use yana_ast::{DiagLevel, Diagnostic, Span};

type ASpan = (&'static str, std::ops::Range<usize>);

fn to_aspan(filename: &'static str, s: Span) -> ASpan {
    (filename, s.lo as usize..s.hi.max(s.lo + 1) as usize)
}

/// Render diagnostics for one file as ariadne reports to stderr.
///
/// Returns the number of *fatal* diagnostics (errors, plus `contract`
/// warnings when `strict`), so the caller can set the exit code.
pub fn render(filename: &str, source: &str, diagnostics: &[Diagnostic], strict: bool) -> usize {
    // leak the filename once so ariadne spans can be 'static tuples; CLI runs
    // one file per invocation, this is fine.
    let fname: &'static str = Box::leak(filename.to_string().into_boxed_str());
    let map = SourceMap::new(source);
    let mut fatal = 0;

    for d in diagnostics {
        let level = d.adjusted_level(strict);
        if matches!(level, DiagLevel::Error) {
            fatal += 1;
        }
        let kind = match level {
            DiagLevel::Error => ReportKind::Error,
            DiagLevel::Warning => ReportKind::Warning,
            DiagLevel::Note => ReportKind::Advice,
        };
        let color = match level {
            DiagLevel::Error => Color::Red,
            DiagLevel::Warning => Color::Yellow,
            DiagLevel::Note => Color::Blue,
        };

        let primary = d.primary_span().unwrap_or(Span::DUMMY);
        let (line, _col) = map.offset_to_line_col(primary.lo);

        let mut builder = Report::build(kind, to_aspan(fname, primary))
            .with_code(&d.kind)
            .with_message(&d.message);

        let primary_msg = d
            .labels
            .iter()
            .find(|l| l.primary)
            .map(|l| l.message.clone())
            .unwrap_or_default();
        builder = builder.with_label(
            Label::new(to_aspan(fname, primary))
                .with_message(primary_msg)
                .with_color(color),
        );
        for l in d.labels.iter().filter(|l| !l.primary) {
            builder = builder.with_label(
                Label::new(to_aspan(fname, l.span))
                    .with_message(l.message.clone())
                    .with_color(Color::Cyan),
            );
        }
        if let Some(h) = &d.help {
            builder = builder.with_note(format!("help: {h}"));
        }
        if let Some(n) = &d.note {
            builder = builder.with_note(format!("note: {n}"));
        }
        let report = builder.finish();
        // ariadne wants (id, source) pairs matching the span ids
        let cache = (fname, Source::from(source));
        if report.eprint(cache).is_err() {
            eprintln!(
                "yana: {}[{}]: {} (line {})",
                fname, d.kind, d.message, line + 1
            );
        }
    }
    fatal
}
