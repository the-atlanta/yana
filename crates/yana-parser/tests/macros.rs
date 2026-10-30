use yana_parser::parse;

fn parse_ok(src: &str) -> yana_ast::File {
    let out = parse(src);
    let errs: Vec<String> = out
        .diagnostics
        .iter()
        .filter(|d| d.level == yana_ast::DiagLevel::Error)
        .map(|d| format!("{}: {}", d.kind, d.message))
        .collect();
    assert!(errs.is_empty(), "expected clean parse, got: {errs:?}");
    out.file.expect("file")
}

fn diags(src: &str) -> Vec<String> {
    parse(src)
        .diagnostics
        .iter()
        .filter(|d| d.level == yana_ast::DiagLevel::Error)
        .map(|d| d.kind.as_str().to_string())
        .collect()
}

fn fns(file: &yana_ast::File) -> Vec<&yana_ast::Item> {
    file.items
        .iter()
        .filter(|i| matches!(i, yana_ast::Item::Fn(_)))
        .collect()
}

fn stmt_count(file: &yana_ast::File, fn_idx: usize) -> usize {
    match fns(file).get(fn_idx) {
        Some(yana_ast::Item::Fn(f)) => f.body.stmts.len(),
        _ => panic!("no fn #{fn_idx}"),
    }
}

// --- declarative `macro` form ---------------------------------------------

#[test]
fn declarative_positional_expansion() {
    let file = parse_ok(
        r#"
macro set(dst: place, src: value) { alt dst = src; }
fn f() {
    bind mut x @ rax: u64 = 0;
    set!(x, 42);
}
"#,
    );
    // bind + expanded alt = 2 statements
    assert_eq!(stmt_count(&file, 0), 2);
}

#[test]
fn declarative_named_expansion() {
    let file = parse_ok(
        r#"
macro set(dst: place, v: value) { alt dst = v; }
fn f() {
    bind mut x @ rax: u64 = 0;
    set! { dst: x, v: 42 };
}
"#,
    );
    assert_eq!(stmt_count(&file, 0), 2);
}

// --- macro_rules -----------------------------------------------------------

#[test]
fn rules_fragments_place_value() {
    let file = parse_ok(
        r#"
macro_rules! set2 { ($d:place, $v:value) => { alt $d = $v; } }
fn f() {
    bind mut x @ rax: u64 = 0;
    set2!(x, 42);
}
"#,
    );
    assert_eq!(stmt_count(&file, 0), 2);
}

#[test]
fn rules_repetition_star_lockstep() {
    // $(...),* — zero or more, expansion iterates metavariables in lockstep
    let file = parse_ok(
        r#"
macro_rules! incs { ($($r:ident),*) => { $(alt $r += 1;)* } }
fn f() {
    bind mut a @ rax: u64 = 0;
    bind mut b @ rcx: u64 = 0;
    bind mut c @ rdx: u64 = 0;
    incs!(a, b, c);
}
"#,
    );
    assert_eq!(stmt_count(&file, 0), 3 + 3);
}

#[test]
fn rules_repetition_plus_lockstep() {
    // $(...),+ — one or more
    let file = parse_ok(
        r#"
macro_rules! pairs { ($($x:ident, $y:ident),+) => { $(alt $x = $y;)* } }
fn f() {
    bind mut a @ rax: u64 = 0;
    bind mut b @ rcx: u64 = 0;
    pairs!(a, b);
}
"#,
    );
    assert_eq!(stmt_count(&file, 0), 2 + 1);
}

#[test]
fn rules_repetition_zero_is_allowed_for_star() {
    // empty repetition with ,* expands to nothing
    let file = parse_ok(
        r#"
macro_rules! incs { ($($r:ident),*) => { $(alt $r += 1;)* } }
fn f() {
    incs!();
}
"#,
    );
    assert_eq!(stmt_count(&file, 0), 0);
}

#[test]
fn two_metavars_in_one_repetition_iterate_lockstep() {
    let file = parse_ok(
        r#"
macro_rules! swaps { ($($a:ident, $b:ident),*) => { $(alt $a ^= $b;)* } }
fn f() {
    bind mut p @ rax: u64 = 1;
    bind mut q @ rcx: u64 = 2;
    bind mut s @ rdx: u64 = 3;
    bind mut t @ rsi: u64 = 4;
    swaps!(p, q, s, t);
}
"#,
    );
    // 4 binds + 2 xor expansions (lockstep over pairs)
    assert_eq!(stmt_count(&file, 0), 4 + 2);
}

// --- hygiene ----------------------------------------------------------------

#[test]
fn hygiene_two_expansions_distinct_symbols() {
    let src = r#"
macro cnt(r: value) {
    label (top) {
        bind mut i @ rcx: u64 = r;
        branch (i == 0) => 'done;
        alt i -= 1;
        branch => 'top;
    }
}
fn f() {
    cnt!(5);
    cnt!(7);
}
"#;
    let out = parse(src);
    let errk: Vec<String> = out
        .diagnostics
        .iter()
        .filter(|d| d.level == yana_ast::DiagLevel::Error)
        .map(|d| d.kind.to_string())
        .collect();
    assert!(errk.is_empty(), "{errk:?}");
    // The body has label `top` + bind `i` — one label block stmt per expansion
    let file = out.file.unwrap();
    assert_eq!(stmt_count(&file, 0), 2);

    // walk the AST: each label block must contain a distinct bind name
    fn label_names(f: &yana_ast::File, out: &mut Vec<String>) {
        for item in &f.items {
            if let yana_ast::Item::Fn(fndef) = item {
                for s in &fndef.body.stmts {
                    if let yana_ast::Stmt::Label { name, .. } = s {
                        out.push(name.clone());
                    }
                }
            }
        }
    }
    let mut labels = Vec::new();
    label_names(&file, &mut labels);
    assert_eq!(labels.len(), 2, "{labels:?}");
    assert!(
        labels[0] != labels[1],
        "hygiene must rename labels per expansion: {labels:?}"
    );
}

#[test]
fn hygiene_free_labels_not_renamed() {
    // 'done is referenced but not declared inside the macro — never renamed
    let file = parse_ok(
        r#"
macro m() { branch => 'outside; }
fn f() { m!(); }
"#,
    );
    let yana_ast::Item::Fn(f) = fns(&file)[0] else {
        panic!()
    };
    let yana_ast::Stmt::Branch { target, .. } = &f.body.stmts[0] else {
        panic!("expected branch, got {:?}", f.body.stmts[0]);
    };
    assert_eq!(format!("{target:?}"), format!("{:?}", target.clone()));
    // the raw check: target name contains no hygiene suffix
    let s = format!("{target:?}");
    assert!(!s.contains("__h"), "free label renamed: {s}");
}

// --- errors -----------------------------------------------------------------

#[test]
fn unknown_macro_reports_with_suggestion() {
    let kinds = diags(
        r#"
macro m(a: value) { alt rax = a; }
fn f() { nosuch!(1); }
"#,
    );
    assert!(kinds.iter().any(|k| k.contains("unknown-macro")), "{kinds:?}");
}

#[test]
fn arity_error_positional() {
    let kinds = diags(
        r#"
macro m(a: value) { alt rax = a; }
fn f() { m!(1, 2); }
"#,
    );
    assert!(kinds.iter().any(|k| k.contains("macro-arity")), "{kinds:?}");
}

#[test]
fn macro_match_error_when_no_arm_fits() {
    let kinds = diags(
        r#"
macro_rules! two { ($a:ident, $b:ident) => { alt $a = $b; } }
fn f() { two!(1, 2); }
"#,
    );
    assert!(kinds.iter().any(|k| k.contains("macro-match")), "{kinds:?}");
}

#[test]
fn recursion_limit_fires() {
    let kinds = diags(
        r#"
macro_rules! forever { () => { forever!(); } }
fn f() { forever!(); }
"#,
    );
    assert!(
        kinds.iter().any(|k| k.contains("recursion")),
        "{kinds:?}"
    );
}

#[test]
fn item_position_error() {
    let kinds = diags(
        r#"
macro m(a: value) { alt rax = a; }
m!(1);
fn f() { }
"#,
    );
    assert!(
        kinds.iter().any(|k| k.contains("item-position")),
        "{kinds:?}"
    );
}

// --- expansion comments -------------------------------------------------------

#[test]
fn expansion_comment_lands_in_comments_channel() {
    let out = parse(
        r#"
macro set(dst: place, src: value) { alt dst = src; }
fn f() {
    bind mut x @ rax: u64 = 0;
    set!(x, 42);
}
"#,
    );
    let found = out
        .comments
        .iter()
        .any(|(off, c)| c.contains("macro `set`") && *off > 0);
    assert!(found, "no expansion comment: {:?}", out.comments);
}

// --- declaration removal / stream hygiene -------------------------------------

#[test]
fn macro_declaration_removed_from_stream() {
    // after expansion no `macro` keyword should survive in the parsed items
    let file = parse_ok(
        r#"
macro set(dst: place, src: value) { alt dst = src; }
fn f() {
    bind mut x @ rax: u64 = 0;
    set!(x, 42);
}
"#,
    );
    // no stray items: exactly one fn
    assert_eq!(file.items.len(), 1);
}
