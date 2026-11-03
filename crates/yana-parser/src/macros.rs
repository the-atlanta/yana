//! Token-level macro expansion pre-pass (spec §9, §14 pass 0.5).
//!
//! Runs *after* lexing but *before* LALRPOP. Scans the token triple stream
//! for top-level `macro` and `macro_rules!` declarations, removes them,
//! captures their bodies, then repeatedly finds invocation sites
//! (`name!(...)` / `name!{...}`), matches + substitutes + splices until
//! no invocations remain. Hygiene renames declared `bind`/`label` names
//! inside the body template on every expansion.
//!
//! Design notes and edge cases live in `docs/NOTES-macros.md`.

use std::collections::HashMap;

use yana_ast::{Diagnostic, DiagCode, Span};
use yana_lexer::Token;

/// A token triple: `(byte_lo, Token, byte_hi)`.
type Triple = (usize, Token, usize);

/// One declarative macro parameter. A variadic parameter (`name: kind..`)
/// captures zero or more remaining invocation arguments (§9).
#[derive(Debug, Clone)]
struct MacroParam {
    name: String,
    kind: String,
    variadic: bool,
}

/// What a macro is.
#[derive(Debug, Clone)]
enum MacroDef {
    /// `macro name(a: kind, ...) { body }` — positional/named.
    Declarative {
        /// Parameters in declaration order; at most the last is variadic.
        params: Vec<MacroParam>,
        /// Body token triples (between `{` and `}`).
        body: Vec<Triple>,
        /// Hygiene set: names declared via `bind`/`label` inside the body
        /// template (renamed on every expansion).
        hyg: Vec<String>,
        /// Visible to `use` from another module (`#[global]`, §10).
        exported: bool,
        /// Body spans belong to another file; remap them to the invocation.
        foreign: bool,
    },
    /// `macro_rules! name { (pat) => { body }; ... }`.
    Rules {
        /// One arm: (pattern token triples, body token triples, hygiene set).
        arms: Vec<RulesArm>,
        /// Visible to `use` from another module (`#[global]`, §10).
        exported: bool,
        /// Body spans belong to another file; remap them to the invocation.
        foreign: bool,
    },
}

impl MacroDef {
    fn is_exported(&self) -> bool {
        match self {
            MacroDef::Declarative { exported, .. } | MacroDef::Rules { exported, .. } => *exported,
        }
    }

    fn is_foreign(&self) -> bool {
        match self {
            MacroDef::Declarative { foreign, .. } | MacroDef::Rules { foreign, .. } => *foreign,
        }
    }
}

/// A macro declaration captured from another module for `use` import (§10).
#[derive(Debug, Clone)]
pub struct MacroExport {
    name: String,
    def: MacroDef,
}

impl MacroExport {
    pub fn name(&self) -> &str {
        &self.name
    }
}

#[derive(Debug, Clone)]
struct RulesArm {
    pat: Vec<Triple>,
    body: Vec<Triple>,
    hyg: Vec<String>,
}

/// A captured macro_rules metavariable: `$name:kind`.
#[derive(Debug, Clone)]
struct MetaVar {
    name: String,
    kind: String,
}

/// Result of the pre-pass.
pub struct ExpandResult {
    /// Token stream with declarations removed and invocations expanded.
    pub triples: Vec<Triple>,
    /// Diagnostics produced during expansion.
    pub diagnostics: Vec<Diagnostic>,
    /// Comments added by expansion (spliced into the comments channel).
    /// Each is `(byte_offset, text)` where text already includes a leading space.
    pub comments: Vec<(u32, String)>,
}

/// Run the macro pre-pass on a token triple stream.
pub fn expand(triples: Vec<Triple>) -> ExpandResult {
    expand_with_prelude(triples, &[])
}

/// Run the pre-pass with macros imported from other modules already in scope
/// (§10). Prelude definitions are inserted first, so a local macro of the same
/// name overrides the import (matching the loader's duplicate-import rule).
pub fn expand_with_prelude(triples: Vec<Triple>, prelude: &[MacroExport]) -> ExpandResult {
    let mut ctx = Ctx {
        defs: HashMap::new(),
        def_order: Vec::new(),
        diags: Vec::new(),
        comments: Vec::new(),
        exp_counter: 0u64,
        defined_names: Vec::new(),
    };

    for exp in prelude {
        let mut def = exp.def.clone();
        match &mut def {
            MacroDef::Declarative { foreign, .. } | MacroDef::Rules { foreign, .. } => {
                *foreign = true;
            }
        }
        ctx.defs.insert(exp.name.clone(), def);
        ctx.def_order.push(exp.name.clone());
        ctx.defined_names.push(exp.name.clone());
    }

    // 1. Extract declarations.
    let after_decls = extract_declarations(triples, &mut ctx);

    // 2. Repeatedly expand invocations.
    let after_expansion = expand_invocations(after_decls, &mut ctx);

    ExpandResult {
        triples: after_expansion,
        diagnostics: ctx.diags,
        comments: ctx.comments,
    }
}

struct Ctx {
    defs: HashMap<String, MacroDef>,
    def_order: Vec<String>,
    diags: Vec<Diagnostic>,
    comments: Vec<(u32, String)>,
    exp_counter: u64,
    /// Names of defined macros (for unknown-macro suggestions).
    defined_names: Vec<String>,
}

impl Ctx {
    fn next_expansion_id(&mut self) -> u64 {
        self.exp_counter += 1;
        self.exp_counter
    }

    fn err(&mut self, kind: &str, msg: impl Into<String>, span: Span) {
        self.diags.push(
            Diagnostic::error(DiagCode::Syntax, kind, msg, span),
        );
    }

    fn err_with_help(&mut self, kind: &str, msg: impl Into<String>, span: Span, help: impl Into<String>) {
        self.diags.push(
            Diagnostic::error(DiagCode::Syntax, kind, msg, span).with_help(help),
        );
    }
}

// =========================================================================
// §9.1 — declaration extraction
// =========================================================================

/// Scan for top-level `macro name(params) { body }` and
/// `macro_rules ! name { arms }` declarations; remove them from the stream.
fn extract_declarations(triples: Vec<Triple>, ctx: &mut Ctx) -> Vec<Triple> {
    let mut out: Vec<Triple> = Vec::with_capacity(triples.len());
    let mut i = 0;
    while i < triples.len() {
        // `#[global] macro ...` — attributes are part of the declaration, not
        // items the grammar should see.
        let (decl_at, exported) = match attr_prefix(&triples, i) {
            Some((at, global)) => (at, global),
            None => (i, false),
        };

        let is_macro = matches!(triples.get(decl_at).map(|t| &t.1), Some(Token::KwMacro));
        let is_macro_rules =
            matches!(triples.get(decl_at).map(|t| &t.1), Some(Token::KwMacroRules))
            && matches!(triples.get(decl_at + 1).map(|t| &t.1), Some(Token::Bang));

        if is_macro {
            // `macro Ident ( params ) { body }`
            match try_parse_declarative(&triples, decl_at, ctx, exported) {
                Some((consumed, name, def)) => {
                    ctx.defs.insert(name.clone(), def);
                    ctx.def_order.push(name.clone());
                    ctx.defined_names.push(name);
                    i = decl_at + consumed;
                    continue;
                }
                None => {
                    // If we saw `macro` but couldn't parse, emit a syntax
                    // error and skip the `macro` token so the parser doesn't
                    // choke on it (KwMacro is not in the grammar).
                    let span = span_of(&triples[decl_at]);
                    ctx.err("macro-syntax", "malformed `macro` declaration", span);
                    i = decl_at + 1;
                    continue;
                }
            }
        }

        if is_macro_rules {
            match try_parse_rules(&triples, decl_at, ctx, exported) {
                Some((consumed, name, def)) => {
                    ctx.defs.insert(name.clone(), def);
                    ctx.def_order.push(name.clone());
                    ctx.defined_names.push(name);
                    i = decl_at + consumed;
                    continue;
                }
                None => {
                    let span = span_of(&triples[decl_at]);
                    ctx.err("macro-syntax", "malformed `macro_rules!` declaration", span);
                    // skip KwMacroRules + Bang
                    i = decl_at + 2;
                    continue;
                }
            }
        }

        out.push(triples[i].clone());
        i += 1;
    }
    out
}

/// If an attribute run starts at `start`, return `(index of the first token
/// after the attributes, has_#[global])`. `#[global]` before a macro makes it
/// importable (§10).
fn attr_prefix(triples: &[Triple], start: usize) -> Option<(usize, bool)> {
    if !matches!(triples.get(start).map(|t| &t.1), Some(Token::HashLBracket)) {
        return None;
    }
    let mut i = start;
    let mut global = false;
    while matches!(triples.get(i).map(|t| &t.1), Some(Token::HashLBracket)) {
        let end = find_matching(triples, i + 1, &Token::LBracket, &Token::RBracket)?;
        // `#[global]` or `#[global(...)]`; the first Ident is the attr name.
        if let Some((_, Token::Ident(name), _)) = triples.get(i + 1) {
            if name == "global" {
                global = true;
            }
        }
        i = end + 1;
    }
    Some((i, global))
}

/// Collect the macros a module exports with `#[global]` (§10). Used by the
/// loader before parsing the importer, so imported invocations expand in pass
/// 0.5 exactly like local ones.
pub fn collect_exports(source: &str) -> Vec<MacroExport> {
    collect_defs(source, true)
}

/// Does this module define a macro with `name` at all (exported or not)?
/// Lets the loader distinguish "missing" from "not exported".
pub fn defines_macro(source: &str, name: &str) -> bool {
    collect_defs(source, false).iter().any(|e| e.name == name)
}

fn collect_defs(source: &str, only_exported: bool) -> Vec<MacroExport> {
    let lexed = yana_lexer::lex(source);
    let triples = yana_lexer::token_triples(&lexed);
    let mut ctx = Ctx {
        defs: HashMap::new(),
        def_order: Vec::new(),
        diags: Vec::new(),
        comments: Vec::new(),
        exp_counter: 0,
        defined_names: Vec::new(),
    };
    let mut out = Vec::new();
    let mut i = 0;
    while i < triples.len() {
        let (decl_at, exported) = match attr_prefix(&triples, i) {
            Some((at, global)) => (at, global),
            None => (i, false),
        };
        let is_macro = matches!(triples.get(decl_at).map(|t| &t.1), Some(Token::KwMacro));
        let is_macro_rules = matches!(
            triples.get(decl_at).map(|t| &t.1),
            Some(Token::KwMacroRules)
        ) && matches!(triples.get(decl_at + 1).map(|t| &t.1), Some(Token::Bang));
        if is_macro {
            if let Some((consumed, name, def)) =
                try_parse_declarative(&triples, decl_at, &mut ctx, exported)
            {
                if !only_exported || def.is_exported() {
                    out.push(MacroExport { name, def });
                }
                i = decl_at + consumed;
                continue;
            }
        } else if is_macro_rules {
            if let Some((consumed, name, def)) =
                try_parse_rules(&triples, decl_at, &mut ctx, exported)
            {
                if !only_exported || def.is_exported() {
                    out.push(MacroExport { name, def });
                }
                i = decl_at + consumed;
                continue;
            }
        }
        i += 1;
    }
    out
}

/// Try to parse `macro Ident ( params ) { body }` starting at `start`.
/// Returns `(tokens_consumed, name, def)` on success.
fn try_parse_declarative(
    triples: &[Triple],
    start: usize,
    ctx: &mut Ctx,
    exported: bool,
) -> Option<(usize, String, MacroDef)> {
    // macro Ident
    let mut i = start + 1;
    let name = match triples.get(i) {
        Some((_, Token::Ident(s), _)) => s.clone(),
        _ => return None,
    };
    i += 1;

    // ( params )
    let params = match triples.get(i) {
        Some((_, Token::LParen, _)) => {
            i += 1;
            let (p, end) = parse_param_list(&triples, i, ctx)?;
            i = end + 1; // skip RParen
            p
        }
        _ => return None,
    };

    // { body }
    let body = match triples.get(i) {
        Some((_, Token::LBrace, _)) => {
            i += 1;
            let (b, end) = match collect_balanced(&triples, i, &Token::LBrace, &Token::RBrace) {
                Ok(v) => v,
                Err(span) => {
                    ctx.err("macro-syntax", "unbalanced braces in macro body", span);
                    return None;
                }
            };
            i = end + 1; // skip RBrace
            b
        }
        _ => return None,
    };

    let hyg = collect_hygiene_names(&body);
    let consumed = i - start;
    Some((
        consumed,
        name,
        MacroDef::Declarative { params, body, hyg, exported, foreign: false },
    ))
}

/// Parse `(a: kind, b: kind, rest: kind..)` — returns
/// `(params, rparen_index)`. `..` (or `...`) marks the last parameter
/// variadic: it captures zero or more comma-separated invocation arguments.
fn parse_param_list(
    triples: &[Triple],
    start: usize,
    ctx: &mut Ctx,
) -> Option<(Vec<MacroParam>, usize)> {
    let mut params: Vec<MacroParam> = Vec::new();
    let mut i = start;
    loop {
        // Either RParen (end) or Ident : kind
        match triples.get(i) {
            Some((_, Token::RParen, _)) => {
                if let Some(pos) = params.iter().position(|p| p.variadic) {
                    if pos + 1 != params.len() {
                        let span = triples
                            .get(start.saturating_sub(1))
                            .map(|t| Span::new(t.0 as u32, t.2 as u32))
                            .unwrap_or(Span::DUMMY);
                        ctx.err(
                            "macro-syntax",
                            "a variadic parameter must be the last one",
                            span,
                        );
                        return None;
                    }
                }
                return Some((params, i));
            }
            Some((lo, Token::Ident(name), hi)) => {
                let pname = name.clone();
                i += 1;
                // expect Colon
                match triples.get(i) {
                    Some((_, Token::Colon, _)) => i += 1,
                    _ => {
                        ctx.err(
                            "macro-syntax",
                            "expected `:` after macro parameter name",
                            Span::new(*lo as u32, *hi as u32),
                        );
                        return None;
                    }
                }
                // expect Ident (kind)
                let kind = match triples.get(i) {
                    Some((_, Token::Ident(k), _)) => k.clone(),
                    _ => {
                        ctx.err(
                            "macro-syntax",
                            "expected a fragment kind (place/value/label/type/ident/block)",
                            Span::new(*lo as u32, *hi as u32),
                        );
                        return None;
                    }
                };
                if !is_valid_kind(&kind) {
                    ctx.err(
                        "macro-syntax",
                        format!("unknown fragment kind `{kind}`"),
                        Span::new(*lo as u32, *hi as u32),
                    );
                    return None;
                }
                i += 1;
                // `kind..` / `kind...` / `kind*` marks a variadic tail.
                let mut variadic = false;
                if let Some((_, Token::DotDot, _)) = triples.get(i) {
                    variadic = true;
                    i += 1;
                    // `...`: DotDot + Dot (lexer's longest match).
                    if let Some((_, Token::Dot, _)) = triples.get(i) {
                        i += 1;
                    }
                } else if let Some((_, Token::Star, _)) = triples.get(i) {
                    variadic = true;
                    i += 1;
                }
                if variadic && !params.is_empty() {
                    // Only the last parameter may be variadic; if another
                    // parameter follows, the check below reports it.
                }
                params.push(MacroParam { name: pname, kind, variadic });
                // optional comma
                if let Some((_, Token::Comma, _)) = triples.get(i) {
                    i += 1;
                }
            }
            _ => {
                ctx.err(
                    "macro-syntax",
                    "expected parameter name or `)` in macro declaration",
                    Span::DUMMY,
                );
                return None;
            }
        }
    }
}

/// Try to parse `macro_rules ! Ident { arms }` starting at `start` (the
/// `macro_rules` token).
fn try_parse_rules(
    triples: &[Triple],
    start: usize,
    ctx: &mut Ctx,
    exported: bool,
) -> Option<(usize, String, MacroDef)> {
    // start is KwMacroRules; [start+1] is Bang
    let mut i = start + 2;
    let name = match triples.get(i) {
        Some((_, Token::Ident(s), _)) => s.clone(),
        _ => return None,
    };
    i += 1;

    // { arms }
    match triples.get(i) {
        Some((_, Token::LBrace, _)) => {}
        _ => return None,
    }
    i += 1;

    let mut arms = Vec::new();
    // Arms: ( pattern ) => { body } ;
    loop {
        // end of macro_rules body
        if let Some((_, Token::RBrace, _)) = triples.get(i) {
            i += 1;
            break;
        }
        // ( pattern )
        let pat = match triples.get(i) {
            Some((_, Token::LParen, _)) => {
                i += 1;
                let (p, end) = match collect_balanced(triples, i, &Token::LParen, &Token::RParen) {
                    Ok(v) => v,
                    Err(span) => {
                        ctx.err("macro-syntax", "unbalanced parens in macro_rules pattern", span);
                        return None;
                    }
                };
                i = end + 1; // skip RParen
                p
            }
            _ => {
                ctx.err(
                    "macro-syntax",
                    "expected `(` to start a macro_rules arm pattern",
                    Span::DUMMY,
                );
                return None;
            }
        };

        // => (FatArrow)
        match triples.get(i) {
            Some((_, Token::FatArrow, _)) => i += 1,
            _ => {
                ctx.err("macro-syntax", "expected `=>` in macro_rules arm", Span::DUMMY);
                return None;
            }
        }

        // { body }
        let body = match triples.get(i) {
            Some((_, Token::LBrace, _)) => {
                i += 1;
                let (b, end) = match collect_balanced(triples, i, &Token::LBrace, &Token::RBrace) {
                    Ok(v) => v,
                    Err(span) => {
                        ctx.err("macro-syntax", "unbalanced braces in macro_rules body", span);
                        return None;
                    }
                };
                i = end + 1;
                b
            }
            _ => {
                ctx.err("macro-syntax", "expected `{` for macro_rules arm body", Span::DUMMY);
                return None;
            }
        };

        let hyg = collect_hygiene_names(&body);
        arms.push(RulesArm { pat, body, hyg });

        // optional ;
        if let Some((_, Token::Semi, _)) = triples.get(i) {
            i += 1;
        }
    }

    let consumed = i - start;
    Some((consumed, name, MacroDef::Rules { arms, exported, foreign: false }))
}

// =========================================================================
// §9.2 — invocation expansion
// =========================================================================

/// Repeatedly find `Ident ! ( ... )` / `Ident ! { ... }` invocation sites and
/// expand them, until a fixpoint (or depth limit 64).
fn expand_invocations(triples: Vec<Triple>, ctx: &mut Ctx) -> Vec<Triple> {
    let mut stream = triples;
    for depth in 0..64 {
        let (next, changed, had_error) = expand_one_pass(&stream, ctx, depth);
        stream = next;
        if had_error || !changed {
            break;
        }
        if depth == 63 {
            // One more pass would still find work → recursion too deep.
            ctx.err(
                "macro-recursion-limit",
                "macro expansion exceeded depth limit of 64",
                Span::DUMMY,
            );
        }
    }
    stream
}

/// One left-to-right pass: find the first (well, every) invocation site and
/// expand it in-place. Returns `(new_stream, changed, had_error)`.
fn expand_one_pass(
    triples: &[Triple],
    ctx: &mut Ctx,
    depth: usize,
) -> (Vec<Triple>, bool, bool) {
    let mut out: Vec<Triple> = Vec::with_capacity(triples.len());
    let mut changed = false;
    let mut had_error = false;
    let mut i = 0;
    while i < triples.len() {
        // Look for `Ident ! LParen/LBrace` where Ident names a known macro.
        if let Some((_, Token::Ident(name), _)) = triples.get(i) {
            if let Some((_, Token::Bang, _)) = triples.get(i + 1) {
                if ctx.defs.contains_key(name) {

                    if depth >= 64 {
                        let span = span_invocation(triples, i);
                        ctx.err(
                            "macro-recursion-limit",
                            format!("macro `{name}` exceeded recursion depth limit (64)"),
                            span,
                        );
                        had_error = true;
                        // Skip and stop.
                        let skip = skip_invocation(triples, i);
                        i += skip;
                        changed = true;
                        continue;
                    }

                    match expand_one_invocation(triples, i, name, ctx, depth) {
                        Ok((expanded, consumed)) => {
                            // Add expansion comment at the invocation site's offset.
                            let exp_id = ctx.exp_counter;
                            let lo = triples[i].0 as u32;
                            ctx.comments.push((
                                lo,
                                format!(" macro `{name}` → #{}", exp_id),
                            ));
                            out.extend(expanded);
                            i += consumed;
                            changed = true;
                            continue;
                        }
                        Err(()) => {
                            had_error = true;
                            let skip = skip_invocation(triples, i);
                            i += skip;
                            changed = true;
                            continue;
                        }
                    }
                } else {
                    // `Ident !` but not a known macro — could be a legitimate
                    // token sequence or an unknown-macro error. We check: is
                    // this followed by `(` or `{`? If so, it looks like a macro
                    // invocation → unknown-macro error.
                    if let Some((_, tok, _)) = triples.get(i + 2) {
                        if matches!(tok, Token::LParen | Token::LBrace) {
                            let span = span_invocation(triples, i);
                            let suggestions = ctx.defined_names.join(", ");
                            let hint = match yana_ast::text::closest(name, ctx.defined_names.iter().map(String::as_str)) {
                                Some(s) => format!("did you mean `{s}`?"),
                                None if suggestions.is_empty() => "no macros are defined in this file.".to_string(),
                                None => format!("defined macros: {suggestions}"),
                            };
                            ctx.err_with_help(
                                "unknown-macro",
                                format!("unknown macro `{name}`"),
                                span,
                                hint,
                            );
                            had_error = true;
                            let skip = skip_invocation(triples, i);
                            i += skip;
                            changed = true;
                            continue;
                        }
                    }
                    // Not a macro invocation shape — pass through normally.
                }
            }
        }
        out.push(triples[i].clone());
        i += 1;
    }
    (out, changed, had_error)
}

/// Expand a single invocation at index `inv_start`. Returns the expanded
/// token list and the number of triples consumed from the input.
/// `_depth` is the current pass depth (recursion limit checked by the caller).
fn expand_one_invocation(
    triples: &[Triple],
    inv_start: usize,
    name: &str,
    ctx: &mut Ctx,
    _depth: usize,
) -> Result<(Vec<Triple>, usize), ()> {
    // Clone the arms we need (avoids borrowing ctx while expanding) — bodies
    // are cloned per-invocation; macro bodies are small.
    let arms: Vec<RulesArm> = match ctx.defs.get(name).unwrap() {
        MacroDef::Rules { arms, .. } => arms.to_vec(),
        _ => Vec::new(),
    };
    let foreign = ctx.defs.get(name).unwrap().is_foreign();
    let params_body = match ctx.defs.get(name).unwrap() {
        MacroDef::Declarative { params, body, hyg, .. } => {
            Some((params.clone(), body.clone(), hyg.clone()))
        }
        _ => None,
    };
    // inv_start = Ident, +1 = Bang, +2 = LParen or LBrace
    let open = &triples[inv_start + 2].1;
    let is_brace = matches!(open, Token::LBrace);

    // Collect args (balanced group after `!`).
    let args_start = inv_start + 3;
    let (raw_args, end_idx) = match collect_balanced(triples, args_start, open, closing(open)) {
        Ok(v) => v,
        Err(span) => {
            ctx.err("macro-syntax", "unbalanced delimiters in macro invocation", span);
            return Err(());
        }
    };
    // The invocation statement includes its trailing `;` (like Rust:
    // `name!(args);`) — the body supplies the statements, the site supplies
    // the terminator. Consume it when present.
    let mut consumed = (end_idx + 1) - inv_start; // through the closing delimiter
    if let Some((_, Token::Semi, _)) = triples.get(end_idx + 1) {
        consumed += 1;
    }

    let exp_id = ctx.next_expansion_id();

    let expanded: Vec<Triple> = if let Some((params, body, hyg)) = params_body {
        let args = if is_brace {
            // named: { a: x, b: y }
            parse_named_args(&raw_args, &params, triples, inv_start, ctx)?
        } else {
            // positional: (a, b)
            parse_positional_args(&raw_args, &params, triples, inv_start, ctx)?
        };
        // Substitute: replace param-name Ident tokens in the body with the
        // captured arg slice, then apply hygiene renaming.
        let mut result = match substitute_declarative(&body, &params, &args) {
            Ok(r) => r,
            Err(msg) => {
                let span = span_invocation(triples, inv_start);
                ctx.err("macro-arity", msg, span);
                return Err(());
            }
        };
        apply_hygiene(&mut result, &hyg, exp_id);
        result
    } else {
        // macro_rules: try each arm; first match wins.
        let mut matched = false;
        let mut result = Vec::new();
        for arm in &arms {
            let mut captures: HashMap<String, Captures> = HashMap::new();
            if match_pattern(&arm.pat, &raw_args, &mut captures) {
                // Check repetition lockstep: all metavariables in a
                // repetition group must have the same count.
                if let Err(mv) = check_repetition_lockstep(&captures) {
                    let span = span_invocation(triples, inv_start);
                    ctx.err(
                        "macro-repeat-mismatch",
                        format!("repetition metavariable `{mv}` has a different count than its group"),
                        span,
                    );
                    return Err(());
                }
                result = substitute_rules(&arm.body, &captures);
                // Apply hygiene to the result.
                apply_hygiene(&mut result, &arm.hyg, exp_id);
                matched = true;
                break;
            }
        }
        if !matched {
            let span = span_invocation(triples, inv_start);
            ctx.err_with_help(
                "macro-match",
                format!("no macro_rules arm matched the invocation of `{name}`"),
                span,
                format!("tried {} arm(s)", arms.len()),
            );
            return Err(());
        }
        result
    };

    let expanded = if foreign {
        // Body tokens carry byte offsets from the defining module; this
        // module's source map would misrender them. Point diagnostics inside
        // an imported expansion at the invocation instead.
        let (lo, hi) = (triples[inv_start].0, triples[inv_start].2);
        expanded
            .into_iter()
            .map(|(_, tok, _)| (lo, tok, hi))
            .collect()
    } else {
        expanded
    };

    Ok((expanded, consumed))
}

// ---- declarative arg parsing ----

/// Parsed declarative-macro arguments: fixed parameters plus an optional
/// variadic tail (one token slice per extra argument).
struct DeclarativeArgs {
    fixed: Vec<Vec<Triple>>,
    rest: Option<Vec<Vec<Triple>>>,
}

/// Split `raw_args` at top-level commas → positional arg slices.
fn parse_positional_args(
    raw_args: &[Triple],
    params: &[MacroParam],
    triples: &[Triple],
    inv_start: usize,
    ctx: &mut Ctx,
) -> Result<DeclarativeArgs, ()> {
    let mut slices = split_top_level_commas(raw_args);
    // A trailing comma produces an empty final slice; it is not an argument.
    if matches!(raw_args.last().map(|t| &t.1), Some(Token::Comma)) {
        slices.pop();
    }

    let variadic_at = params.iter().position(|p| p.variadic);
    match variadic_at {
        None => {
            if slices.len() != params.len() {
                let span = span_invocation(triples, inv_start);
                ctx.err(
                    "macro-arity",
                    format!(
                        "macro expects {} argument(s), got {}",
                        params.len(),
                        slices.len()
                    ),
                    span,
                );
                return Err(());
            }
            for (i, (slice, param)) in slices.iter().zip(params.iter()).enumerate() {
                if let Err(msg) = validate_kind(&param.kind, slice) {
                    let span = slice
                        .first()
                        .map(|t| Span::new(t.0 as u32, t.2 as u32))
                        .unwrap_or(Span::DUMMY);
                    ctx.err("macro-arity", format!("argument {i}: {msg}"), span);
                    return Err(());
                }
            }
            Ok(DeclarativeArgs { fixed: slices, rest: None })
        }
        Some(vi) => {
            if slices.len() < vi {
                let span = span_invocation(triples, inv_start);
                ctx.err(
                    "macro-arity",
                    format!(
                        "macro expects at least {} argument(s), got {}",
                        vi,
                        slices.len()
                    ),
                    span,
                );
                return Err(());
            }
            let rest = slices.split_off(vi);
            for (i, (slice, param)) in slices.iter().zip(params.iter()).enumerate() {
                if let Err(msg) = validate_kind(&param.kind, slice) {
                    let span = slice
                        .first()
                        .map(|t| Span::new(t.0 as u32, t.2 as u32))
                        .unwrap_or(Span::DUMMY);
                    ctx.err("macro-arity", format!("argument {i}: {msg}"), span);
                    return Err(());
                }
            }
            let kind = &params[vi].kind;
            for (i, slice) in rest.iter().enumerate() {
                if let Err(msg) = validate_kind(kind, slice) {
                    let span = slice
                        .first()
                        .map(|t| Span::new(t.0 as u32, t.2 as u32))
                        .unwrap_or(Span::DUMMY);
                    ctx.err(
                        "macro-arity",
                        format!("variadic argument {i}: {msg}"),
                        span,
                    );
                    return Err(());
                }
            }
            Ok(DeclarativeArgs { fixed: slices, rest: Some(rest) })
        }
    }
}

/// Parse `{ a: x, b: y }` → map param_name → arg slice, in param order.
fn parse_named_args(
    raw_args: &[Triple],
    params: &[MacroParam],
    triples: &[Triple],
    inv_start: usize,
    ctx: &mut Ctx,
) -> Result<DeclarativeArgs, ()> {
    if params.iter().any(|p| p.variadic) {
        let span = span_invocation(triples, inv_start);
        ctx.err_with_help(
            "macro-arity",
            "a variadic macro takes positional arguments only",
            span,
            "write `name!(a, b, c)` instead of `name! { a: ..., }`",
        );
        return Err(());
    }
    let slices = split_top_level_commas(raw_args);
    let mut by_name: HashMap<String, Vec<Triple>> = HashMap::new();
    let mut seen: Vec<String> = Vec::new();
    for slice in &slices {
        // Each slice should be `Ident Colon <value>`
        let (pname, value) = match (slice.first(), slice.get(1)) {
            (Some((_, Token::Ident(n), _)), Some((_, Token::Colon, _))) => {
                (n.clone(), &slice[2..])
            }
            _ => {
                let span = slice
                    .first()
                    .map(|t| Span::new(t.0 as u32, t.2 as u32))
                    .unwrap_or(Span::DUMMY);
                ctx.err(
                    "macro-arity",
                    "named arguments must be `name: value`",
                    span,
                );
                return Err(());
            }
        };
        if seen.contains(&pname) {
            let span = slice
                .first()
                .map(|t| Span::new(t.0 as u32, t.2 as u32))
                .unwrap_or(Span::DUMMY);
            ctx.err("macro-arity", format!("duplicate argument `{pname}`"), span);
            return Err(());
        }
        seen.push(pname.clone());
        by_name.insert(pname, value.to_vec());
    }
    // Build in param order, checking all params are present and no unknowns.
    let mut result = Vec::new();
    for param in params {
        match by_name.get(&param.name) {
            Some(val) => {
                if let Err(msg) = validate_kind(&param.kind, val) {
                    let span = val
                        .first()
                        .map(|t| Span::new(t.0 as u32, t.2 as u32))
                        .unwrap_or(Span::DUMMY);
                    ctx.err(
                        "macro-arity",
                        format!("argument `{}`: {msg}", param.name),
                        span,
                    );
                    return Err(());
                }
                result.push(val.clone());
            }
            None => {
                let span = span_invocation(triples, inv_start);
                ctx.err(
                    "macro-arity",
                    format!("missing argument `{}`", param.name),
                    span,
                );
                return Err(());
            }
        }
    }
    // Check for unknown args.
    for s in &seen {
        if !params.iter().any(|p| &p.name == s) {
            let span = span_invocation(triples, inv_start);
            ctx.err("macro-arity", format!("unknown argument `{s}`"), span);
            return Err(());
        }
    }
    Ok(DeclarativeArgs { fixed: result, rest: None })
}

// ---- declarative substitution ----

/// Substitute parameter names in the body with captured argument slices.
///
/// Variadic parameters splice all captured arguments comma-separated; inside
/// `$( ... )*` / `$( ... ),*` / `$( ... )+` they splice one argument per
/// repetition, so a declarative macro can repeat a statement per argument
/// (the same shape as `macro_rules!` repetition).
fn substitute_declarative(
    body: &[Triple],
    params: &[MacroParam],
    args: &DeclarativeArgs,
) -> Result<Vec<Triple>, String> {
    substitute_declarative_rep(body, params, args, None)
}

fn substitute_declarative_rep(
    body: &[Triple],
    params: &[MacroParam],
    args: &DeclarativeArgs,
    rep: Option<usize>,
) -> Result<Vec<Triple>, String> {
    let mut out = Vec::with_capacity(body.len());
    let mut i = 0;
    while i < body.len() {
        let tok = &body[i];

        // Repetition: `$( ... ) sep? *|+`
        if matches!(tok.1, Token::Dollar)
            && matches!(body.get(i + 1).map(|t| &t.1), Some(Token::LParen))
        {
            let sub_start = i + 2;
            let sub_end = find_matching(body, sub_start, &Token::LParen, &Token::RParen)
                .ok_or_else(|| "unbalanced `$(` in macro body".to_string())?;
            let subtemplate = &body[sub_start..sub_end];
            let after = sub_end + 1;
            let sep = body.get(after).filter(|t| matches!(t.1, Token::Comma));
            let op = body.get(after + if sep.is_some() { 1 } else { 0 });
            let min = match op.map(|t| &t.1) {
                Some(Token::Star) => 0,
                Some(Token::Plus) => 1,
                _ => {
                    return Err(
                        "expected `*` or `+` after `$( ... )` in macro body".to_string()
                    )
                }
            };
            let count = args.rest.as_ref().map(|r| r.len()).unwrap_or(0);
            if count < min {
                return Err(
                    "`$( ... )+` needs at least one variadic argument".to_string()
                );
            }
            for r in 0..count {
                if r > 0 {
                    if let Some(sep) = sep {
                        out.push(sep.clone());
                    }
                }
                out.extend(substitute_declarative_rep(subtemplate, params, args, Some(r))?);
            }
            i = after + if sep.is_some() { 2 } else { 1 };
            continue;
        }

        if let Token::Ident(text) = &tok.1 {
            if let Some(pos) = params.iter().position(|p| &p.name == text) {
                let param = &params[pos];
                if param.variadic {
                    let rest = args
                        .rest
                        .as_ref()
                        .ok_or_else(|| "internal: missing variadic capture".to_string())?;
                    match rep {
                        Some(r) => out.extend(rest[r].iter().cloned()),
                        None => {
                            for (k, arg) in rest.iter().enumerate() {
                                if k > 0 {
                                    out.push((tok.0, Token::Comma, tok.2));
                                }
                                out.extend(arg.iter().cloned());
                            }
                        }
                    }
                } else {
                    out.extend(args.fixed[pos].iter().cloned());
                }
                i += 1;
                continue;
            }
        }

        out.push(tok.clone());
        i += 1;
    }
    Ok(out)
}

// ---- macro_rules pattern matching ----
//
// Captures use a dual representation:
//   - `Captures::Single` for non-repetition metavars: one token slice.
//   - `Captures::Repetition` for repetition metavars: a list of per-rep slices.
// This lets the template expander splice the r-th capture in lockstep.

#[derive(Debug, Clone)]
enum Captures {
    /// `$x:kind` outside a repetition — captures one balanced slice.
    Single(Vec<Triple>),
    /// `$x:kind` inside a `$(...),*` / `$(...),+` — one slice per repetition.
    Repetition(Vec<Vec<Triple>>),
}

/// Match a pattern against input. On success, fills `captures`.
fn match_pattern(
    pat: &[Triple],
    input: &[Triple],
    captures: &mut HashMap<String, Captures>,
) -> bool {
    let mut pi = 0;
    let mut ii = 0;
    while pi < pat.len() {
        let ptok = &pat[pi];

        // Repetition: `$ ( subpattern ) , * | +`
        if matches!(ptok.1, Token::Dollar)
            && matches!(pat.get(pi + 1).map(|t| &t.1), Some(Token::LParen))
        {
            let sub_start = pi + 2;
            let sub_end = match find_matching(pat, sub_start, &Token::LParen, &Token::RParen) {
                Some(e) => e,
                None => return false,
            };
            let subpattern = &pat[sub_start..sub_end];
            let after_rparen = sub_end + 1;
            // After RParen: optional separator (Comma) + repeat op (Star/Plus)
            let _sep = pat.get(after_rparen).map(|t| &t.1);
            let rep_op = pat.get(after_rparen + 1).map(|t| &t.1);
            let min_reps = match rep_op {
                Some(Token::Star) => 0,
                Some(Token::Plus) => 1,
                _ => return false,
            };
            let after_rep = after_rparen + 2;

            // After-repetition bound: the next pattern token after the rep
            // group (if any), used to bound the last repetition's greedy
            // capture. If the separator is a comma, the last metavar of each
            // rep is bounded by Comma; otherwise by the after-rep literal.
            let after_bound = pat.get(after_rep).map(|t| &t.1);
            let has_sep = matches!(pat.get(after_rparen).map(|t| &t.1), Some(Token::Comma));
            let last_bound = if has_sep { Some(&Token::Comma) } else { after_bound };

            // Collect per-repetition captures.
            let mut rep_count = 0;
            let mut rep_caps: HashMap<String, Vec<Vec<Triple>>> = HashMap::new();
            loop {
                match match_one_repetition(subpattern, &input[ii..], last_bound) {
                    Some((consumed, sub_captures)) => {
                        for (name, slice) in sub_captures {
                            rep_caps.entry(name).or_default().push(slice);
                        }
                        ii += consumed;
                        rep_count += 1;
                        // Consume separator comma if present.
                        if let Some((_, Token::Comma, _)) = input.get(ii) {
                            ii += 1;
                        } else {
                            break;
                        }
                    }
                    None => break,
                }
            }

            if rep_count < min_reps {
                return false;
            }
            for (name, slices) in rep_caps {
                captures.insert(name, Captures::Repetition(slices));
            }
            pi = after_rep;
            continue;
        }

        // Metavariable: `$ name : kind`
        if matches!(ptok.1, Token::Dollar) {
            if let Some((_, Token::Ident(mv_name), _)) = pat.get(pi + 1) {
                if let Some((_, Token::Colon, _)) = pat.get(pi + 2) {
                    if let Some((_, Token::Ident(kind), _)) = pat.get(pi + 3) {
                        let mv = MetaVar { name: mv_name.clone(), kind: kind.clone() };
                        let bound = pat.get(pi + 4).map(|t| &t.1);
                        match capture_metavar(&mv, &input[ii..], bound) {
                            Some((slice, consumed)) => {
                                captures.insert(mv.name.clone(), Captures::Single(slice));
                                ii += consumed;
                                pi += 4;
                                continue;
                            }
                            None => return false,
                        }
                    }
                }
            }
            return false;
        }

        // Literal token.
        if ii >= input.len() {
            return false;
        }
        if !tokens_match(&ptok.1, &input[ii].1) {
            return false;
        }
        pi += 1;
        ii += 1;
    }
    ii == input.len()
}

/// Match one repetition of a subpattern against `input`. Returns
/// `(tokens_consumed, captures_for_this_rep)`.
///
/// `last_bound` bounds the final metavar in the subpattern (the separator
/// comma or the after-repetition literal).
fn match_one_repetition(
    subpattern: &[Triple],
    input: &[Triple],
    last_bound: Option<&Token>,
) -> Option<(usize, Vec<(String, Vec<Triple>)>)> {
    let mut captures: Vec<(String, Vec<Triple>)> = Vec::new();
    let mut si = 0;
    let mut ii = 0;
    while si < subpattern.len() {
        let stok = &subpattern[si];

        // Metavariable: $ name : kind
        if matches!(stok.1, Token::Dollar) {
            if let Some((_, Token::Ident(mv_name), _)) = subpattern.get(si + 1) {
                if let Some((_, Token::Colon, _)) = subpattern.get(si + 2) {
                    if let Some((_, Token::Ident(kind), _)) = subpattern.get(si + 3) {
                        let mv = MetaVar { name: mv_name.clone(), kind: kind.clone() };
                        // Bound: next literal in subpattern, or last_bound if
                        // this is the last element.
                        let next_idx = si + 4;
                        let bound = if next_idx < subpattern.len() {
                            Some(&subpattern[next_idx].1)
                        } else {
                            last_bound
                        };
                        match capture_metavar(&mv, &input[ii..], bound) {
                            Some((slice, consumed)) => {
                                captures.push((mv.name.clone(), slice));
                                ii += consumed;
                                si += 4;
                                continue;
                            }
                            None => return None,
                        }
                    }
                }
            }
            return None;
        }

        // Literal match.
        if ii >= input.len() {
            return None;
        }
        if !tokens_match(&stok.1, &input[ii].1) {
            return None;
        }
        si += 1;
        ii += 1;
    }
    Some((ii, captures))
}

/// Capture a metavar `$name:kind` from `input`, bounded by an optional
/// next-literal token (at bracket depth 0).
fn capture_metavar(
    mv: &MetaVar,
    input: &[Triple],
    bound: Option<&Token>,
) -> Option<(Vec<Triple>, usize)> {
    match mv.kind.as_str() {
        "ident" => match input.first() {
            Some((_, Token::Ident(_), _)) => Some((vec![input[0].clone()], 1)),
            _ => None,
        },
        "label" => match input.first() {
            Some((_, Token::LabelRef(_), _)) => Some((vec![input[0].clone()], 1)),
            _ => None,
        },
        "block" => match input.first() {
            Some((_, Token::LBrace, _)) => {
                let (tree, end) = collect_balanced(input, 1, &Token::LBrace, &Token::RBrace).ok()?;
                let mut slice = vec![input[0].clone()];
                slice.extend(tree);
                Some((slice, end + 1))
            }
            _ => None,
        },
        // place / value / type: any balanced token slice up to the bound.
        "place" | "value" | "type" => capture_balanced_slice(input, bound),
        _ => None,
    }
}

/// Capture a balanced token slice up to (but not including) the next occurrence
/// of `bound` at bracket depth 0. Greedy.
fn capture_balanced_slice(
    input: &[Triple],
    bound: Option<&Token>,
) -> Option<(Vec<Triple>, usize)> {
    let mut slice = Vec::new();
    let mut i = 0;
    let mut depth = 0i32;
    while i < input.len() {
        let tok = &input[i].1;
        // Check bound at depth 0.
        if depth == 0 {
            if let Some(b) = bound {
                if tokens_match(tok, b) {
                    if slice.is_empty() {
                        return None;
                    }
                    return Some((slice, i));
                }
            }
        }
        match tok {
            Token::LParen | Token::LBrace | Token::LBracket => depth += 1,
            Token::RParen | Token::RBrace | Token::RBracket => {
                depth -= 1;
                if depth < 0 {
                    if slice.is_empty() {
                        return None;
                    }
                    return Some((slice, i));
                }
            }
            _ => {}
        }
        slice.push(input[i].clone());
        i += 1;
    }
    if slice.is_empty() {
        None
    } else {
        Some((slice, i))
    }
}

/// Check that all repetition-group metavariables have equal counts.
fn check_repetition_lockstep(captures: &HashMap<String, Captures>) -> Result<(), String> {
    let max_rep = captures
        .values()
        .filter_map(|c| match c {
            Captures::Repetition(v) => Some(v.len()),
            _ => None,
        })
        .max()
        .unwrap_or(0);
    for (name, cap) in captures {
        if let Captures::Repetition(v) = cap {
            if v.len() != max_rep {
                return Err(name.clone());
            }
        }
    }
    Ok(())
}

// ---- macro_rules substitution ----

/// Substitute captured metavariables into a macro_rules body template.
/// Handles `$( ... ),*` / `$( ... ),+` repetition expansion in lockstep.
fn substitute_rules(
    body: &[Triple],
    captures: &HashMap<String, Captures>,
) -> Vec<Triple> {
    let mut out = Vec::with_capacity(body.len());
    let mut bi = 0;
    while bi < body.len() {
        let btok = &body[bi];

        // Repetition in template: `$ ( ... ) , * | +`
        if matches!(btok.1, Token::Dollar) {
            if let Some((_, Token::LParen, _)) = body.get(bi + 1) {
                let sub_start = bi + 2;
                let sub_end = match find_matching(body, sub_start, &Token::LParen, &Token::RParen) {
                    Some(e) => e,
                    None => {
                        // Malformed template; emit as-is.
                        out.push(btok.clone());
                        bi += 1;
                        continue;
                    }
                };
                let subtemplate = &body[sub_start..sub_end];
                let after_rparen = sub_end + 1;
                let sep_idx = after_rparen;
                let _op_idx = after_rparen + 1;

                // Determine repetition count from the first Repetition
                // capture referenced in the subtemplate.
                let reps = count_repetitions(subtemplate, captures);
                for r in 0..reps {
                    if r > 0 {
                        // Emit separator (Comma) if present.
                        if let Some((_, Token::Comma, _)) = body.get(sep_idx) {
                            out.push(body[sep_idx].clone());
                        }
                    }
                    expand_one_rep(subtemplate, captures, r, &mut out);
                }
                bi = after_rparen + 2; // past sep + op
                continue;
            }

            // Metavariable reference: `$ name`
            if let Some((_, Token::Ident(mv_name), _)) = body.get(bi + 1) {
                if let Some(cap) = captures.get(mv_name) {
                    match cap {
                        Captures::Single(slice) => out.extend(slice.iter().cloned()),
                        Captures::Repetition(slices) => {
                            // Outside a repetition template — splice all
                            // concatenated (shouldn't normally happen, but
                            // handle gracefully).
                            for s in slices {
                                out.extend(s.iter().cloned());
                            }
                        }
                    }
                }
                bi += 2;
                continue;
            }
        }

        out.push(btok.clone());
        bi += 1;
    }
    out
}

/// Determine the number of repetitions by finding the first Repetition capture
/// referenced in the subtemplate.
fn count_repetitions(subtemplate: &[Triple], captures: &HashMap<String, Captures>) -> usize {
    let mut si = 0;
    while si < subtemplate.len() {
        if matches!(subtemplate[si].1, Token::Dollar) {
            if let Some((_, Token::Ident(mv_name), _)) = subtemplate.get(si + 1) {
                if let Some(Captures::Repetition(slices)) = captures.get(mv_name) {
                    return slices.len();
                }
            }
        }
        si += 1;
    }
    0
}

/// Expand one repetition (index `r`) of a subtemplate, splicing the r-th
/// capture of each metavariable.
fn expand_one_rep(
    subtemplate: &[Triple],
    captures: &HashMap<String, Captures>,
    r: usize,
    out: &mut Vec<Triple>,
) {
    let mut si = 0;
    while si < subtemplate.len() {
        let stok = &subtemplate[si];

        if matches!(stok.1, Token::Dollar) {
            // The template normally uses `$name` (without `:kind`), but be
            // robust to both forms.
            if let Some((_, Token::Ident(mv_name), _)) = subtemplate.get(si + 1) {
                if let Some(cap) = captures.get(mv_name) {
                    match cap {
                        Captures::Single(slice) => out.extend(slice.iter().cloned()),
                        Captures::Repetition(slices) => {
                            if let Some(slice) = slices.get(r) {
                                out.extend(slice.iter().cloned());
                            }
                        }
                    }
                }
                // Advance past `$name` (and `:kind` if present in template).
                si += 2;
                if let Some((_, Token::Colon, _)) = subtemplate.get(si) {
                    si += 1; // Colon
                    if subtemplate.get(si).is_some() {
                        si += 1; // kind Ident
                    }
                }
                continue;
            }
        }

        out.push(stok.clone());
        si += 1;
    }
}


// §9.6 — hygiene
// =========================================================================

/// Scan a body token tree for declared names that need hygiene:
/// - `bind [mut] <Ident>` (the Ident is the binding name)
/// - `bind ( <Ident> @ ... , <Ident> @ ... )` (destructuring: Ident before @)
/// - `label ( <Ident> )` (the label name)
fn collect_hygiene_names(body: &[Triple]) -> Vec<String> {
    let mut names = Vec::new();
    let mut i = 0;
    while i < body.len() {
        match &body[i].1 {
            Token::KwBind => {
                // bind [mut] Ident ...
                let mut j = i + 1;
                if let Some((_, Token::KwMut, _)) = body.get(j) {
                    j += 1;
                }
                // Form 1: bind Ident @ place ...
                if let Some((_, Token::Ident(name), _)) = body.get(j) {
                    if name != "_" {
                        names.push(name.clone());
                    }
                    // j is at the Ident; advance past it.
                } else if let Some((_, Token::LParen, _)) = body.get(j) {
                    // Form 2: bind ( Ident @ , Ident @ ) ...
                    // Scan inside the parens for `Ident @`.
                    j += 1;
                    while j < body.len() {
                        match &body[j].1 {
                            Token::RParen => break,
                            Token::Ident(name) => {
                                if name != "_" {
                                    // Check if followed by @
                                    if let Some((_, Token::At, _)) = body.get(j + 1) {
                                        names.push(name.clone());
                                    }
                                }
                                j += 1;
                            }
                            _ => j += 1,
                        }
                    }
                }
            }
            Token::KwLabel => {
                // label ( Ident )
                if let Some((_, Token::LParen, _)) = body.get(i + 1) {
                    if let Some((_, Token::Ident(name), _)) = body.get(i + 2) {
                        names.push(name.clone());
                    }
                }
            }
            _ => {}
        }
        i += 1;
    }
    names
}

/// Apply hygiene renaming: rename every occurrence (declaration AND reference)
/// of the collected names inside `tokens` to `<name>__h<exp_id>`.
/// Both Ident and LabelRef token texts are rewritten.
fn apply_hygiene(tokens: &mut [Triple], names: &[String], exp_id: u64) {
    if names.is_empty() {
        return;
    }
    let suffix = format!("__h{exp_id}");
    let rename = |text: &str| -> Option<String> {
        // Exact match against a hygiene name.
        if names.iter().any(|n| n == text) {
            Some(format!("{text}{suffix}"))
        } else {
            None
        }
    };
    for (_lo, tok, _hi) in tokens.iter_mut() {
        match tok {
            Token::Ident(s) => {
                if let Some(new) = rename(s) {
                    *s = new;
                }
            }
            Token::LabelRef(s) => {
                if let Some(new) = rename(s) {
                    *s = new;
                }
            }
            _ => {}
        }
    }
}

// =========================================================================
// Helpers
// =========================================================================

fn is_valid_kind(k: &str) -> bool {
    matches!(k, "place" | "value" | "label" | "type" | "ident" | "block")
}

/// Validate that a captured arg slice satisfies a fragment kind.
fn validate_kind(kind: &str, slice: &[Triple]) -> Result<(), String> {
    match kind {
        "ident" => {
            if slice.len() != 1 || !matches!(slice[0].1, Token::Ident(_)) {
                return Err("expected a single identifier".to_string());
            }
        }
        "label" => {
            if slice.len() != 1 || !matches!(slice[0].1, Token::LabelRef(_)) {
                return Err("expected a single label reference".to_string());
            }
        }
        "block" => {
            if slice.is_empty() || !matches!(slice[0].1, Token::LBrace) {
                return Err("expected a `{ ... }` block".to_string());
            }
            // Check balance.
            let mut depth = 0i32;
            for t in slice {
                match &t.1 {
                    Token::LBrace => depth += 1,
                    Token::RBrace => {
                        depth -= 1;
                        if depth < 0 {
                            return Err("unbalanced braces in block argument".to_string());
                        }
                    }
                    _ => {}
                }
            }
            if depth != 0 {
                return Err("unbalanced braces in block argument".to_string());
            }
        }
        "place" | "value" | "type" => {
            // Any balanced token slice — validated when the expansion re-parses.
            let mut depth = 0i32;
            for t in slice {
                match &t.1 {
                    Token::LParen | Token::LBrace | Token::LBracket => depth += 1,
                    Token::RParen | Token::RBrace | Token::RBracket => {
                        depth -= 1;
                        if depth < 0 {
                            return Err("unbalanced delimiters in argument".to_string());
                        }
                    }
                    _ => {}
                }
            }
            if depth != 0 {
                return Err("unbalanced delimiters in argument".to_string());
            }
        }
        _ => {}
    }
    Ok(())
}

/// Split a token slice at top-level commas (depth 0). Empty slices between
/// commas are included as empty vecs (e.g. trailing comma).
fn split_top_level_commas(slice: &[Triple]) -> Vec<Vec<Triple>> {
    let mut result = Vec::new();
    let mut current = Vec::new();
    let mut depth = 0i32;
    for t in slice {
        match &t.1 {
            Token::LParen | Token::LBrace | Token::LBracket => depth += 1,
            Token::RParen | Token::RBrace | Token::RBracket => depth -= 1,
            Token::Comma if depth == 0 => {
                result.push(std::mem::take(&mut current));
                continue;
            }
            _ => {}
        }
        current.push(t.clone());
    }
    // Handle the last segment (or empty input).
    if !current.is_empty() || !result.is_empty() {
        result.push(current);
    }
    // If the input was completely empty, return an empty vec (zero args).
    if slice.is_empty() {
        result.clear();
    }
    result
}

/// Collect a balanced token tree starting at `start` (the first token INSIDE
/// the delimiters). Returns `(inner_tokens, closing_delimiter_index)`.
fn collect_balanced(
    triples: &[Triple],
    start: usize,
    open: &Token,
    close: &Token,
) -> Result<(Vec<Triple>, usize), Span> {
    let mut inner = Vec::new();
    let mut depth = 1i32;
    let mut i = start;
    while i < triples.len() {
        let tok = &triples[i].1;
        if tokens_match(tok, open) {
            depth += 1;
        } else if tokens_match(tok, close) {
            depth -= 1;
            if depth == 0 {
                return Ok((inner, i));
            }
        }
        inner.push(triples[i].clone());
        i += 1;
    }
    // Unbalanced.
    Err(Span::new(
        triples.get(start.saturating_sub(1)).map(|t| t.0).unwrap_or(0) as u32,
        triples.last().map(|t| t.2).unwrap_or(0) as u32,
    ))
}

/// Find the index of the matching closing delimiter, given `start` is the
/// index AFTER the opening delimiter. Returns the index of the closing delim.
fn find_matching(
    triples: &[Triple],
    start: usize,
    open: &Token,
    close: &Token,
) -> Option<usize> {
    let mut depth = 1i32;
    let mut i = start;
    while i < triples.len() {
        let tok = &triples[i].1;
        if tokens_match(tok, open) {
            depth += 1;
        } else if tokens_match(tok, close) {
            depth -= 1;
            if depth == 0 {
                return Some(i);
            }
        }
        i += 1;
    }
    None
}

/// Get the closing delimiter for an opening one.
fn closing(open: &Token) -> &'static Token {
    match open {
        Token::LParen => &Token::RParen,
        Token::LBrace => &Token::RBrace,
        Token::LBracket => &Token::RBracket,
        _ => unreachable!("closing() on non-bracket"),
    }
}

/// Compare two tokens for matching purposes. For Ident/Num/Str/LabelRef,
/// compare by text; for everything else, compare by discriminant.
fn tokens_match(a: &Token, b: &Token) -> bool {
    match (a, b) {
        (Token::Ident(x), Token::Ident(y)) => x == y,
        (Token::Num(x), Token::Num(y)) => x == y,
        (Token::Str(x), Token::Str(y)) => x == y,
        (Token::LabelRef(x), Token::LabelRef(y)) => x == y,
        (Token::Char(x), Token::Char(y)) => x == y,
        _ => std::mem::discriminant(a) == std::mem::discriminant(b),
    }
}

/// Get the span of a triple.
fn span_of(t: &Triple) -> Span {
    Span::new(t.0 as u32, t.2 as u32)
}

/// Get the span of an invocation starting at `inv_start` (the Ident).
fn span_invocation(triples: &[Triple], inv_start: usize) -> Span {
    // We don't know the full extent without scanning, but the Ident + Bang
    // is a reasonable approximation.
    let lo = triples[inv_start].0 as u32;
    // Try to find the closing delimiter.
    if triples.len() > inv_start + 2 {
        let open = &triples[inv_start + 2].1;
        let close = closing(open);
        if let Some(end) = find_matching(triples, inv_start + 3, open, close) {
            return Span::new(lo, triples[end].2 as u32);
        }
    }
    Span::new(lo, triples[inv_start].2 as u32)
}

/// Count how many triples an invocation at `inv_start` spans (for skipping).
fn skip_invocation(triples: &[Triple], inv_start: usize) -> usize {
    // Ident + Bang + ( ... ) or { ... }
    if triples.len() <= inv_start + 2 {
        return triples.len() - inv_start;
    }
    let open = &triples[inv_start + 2].1;
    let close = closing(open);
    if let Some(end) = find_matching(triples, inv_start + 3, open, close) {
        // Consume the statement terminator too, so a failed expansion does
        // not cascade into a second "unexpected `;`" parse error. This also
        // keeps `use` detection working on the first parse of a file whose
        // macros are imported from another module (§10).
        let mut skip = (end + 1) - inv_start;
        if let Some((_, Token::Semi, _)) = triples.get(end + 1) {
            skip += 1;
        }
        skip
    } else {
        // Unbalanced — skip everything remaining.
        triples.len() - inv_start
    }
}

