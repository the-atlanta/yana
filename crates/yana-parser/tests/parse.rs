use yana_ast::*;
use yana_parser::{parse, parse_ok};

const HELLO: &str = include_str!("../../../examples/hello.yana");

#[test]
fn parses_hello_example() {
    let file = parse_ok(HELLO);
    // bind hello @ .rodata + 2 extern fns + #[entry] fn main
    assert_eq!(file.items.len(), 4, "{:#?}", file.items);

    match &file.items[0] {
        Item::Static(s) => {
            assert_eq!(s.name, "hello");
            assert!(matches!(s.place, Place::Section { kind: place::SectionKind::RoData, .. }));
            match &s.init {
                Some(Value::Str { bytes, .. }) => assert_eq!(bytes, b"Hello, YANA!\n"),
                other => panic!("expected str init, got {other:?}"),
            }
        }
        other => panic!("expected static, got {other:?}"),
    }

    match &file.items[1] {
        Item::ExternFn(e) => {
            assert_eq!(e.sig.name, "write");
            assert_eq!(e.syscall_number(), Some(1));
            assert_eq!(e.sig.params.len(), 3);
            assert_eq!(e.sig.params[0].name, "fd");
        }
        other => panic!("expected extern fn, got {other:?}"),
    }

    match &file.items[3] {
        Item::Fn(f) => {
            assert_eq!(f.sig.name, "main");
            assert!(f.is_entry());
            assert!(matches!(f.sig.ret, RetSig::Never { .. }));
            assert_eq!(f.body.stmts.len(), 2);
            match &f.body.stmts[0] {
                Stmt::Call { name, args, .. } => {
                    assert_eq!(name, "write");
                    assert_eq!(args.len(), 3);
                    assert_eq!(args[0].param.as_deref(), Some("fd"));
                    assert!(matches!(&args[1].value, Value::AddrOf { .. }));
                }
                other => panic!("expected call, got {other:?}"),
            }
        }
        other => panic!("expected fn, got {other:?}"),
    }
}

#[test]
fn parses_factorial() {
    let src = r#"
#[entry]
fn main() -> ! {
    bind mut n @ rcx: u64 = 5;
    bind mut acc @ rax: u64 = 1;
    label (loop) {
        branch (n == 0) => 'done;
        alt rdx:rax = acc * n;
        alt acc = rax;
        alt n -= 1;
        branch => 'loop;
    }
    label (done) {
        syscall;
    }
}
"#;
    let file = parse_ok(src);
    assert_eq!(file.items.len(), 1);
    match &file.items[0] {
        Item::Fn(f) => {
            assert!(f.is_entry());
            assert_eq!(f.body.stmts.len(), 4); // bind, bind, label, label
            // check the wide multiply parsed
            let lbl = match &f.body.stmts[2] {
                Stmt::Label { name, body, .. } => {
                    assert_eq!(name, "loop");
                    body
                }
                other => panic!("expected label, got {other:?}"),
            };
            assert!(matches!(&lbl.stmts[1], Stmt::Alt { src: Value::Mul { .. }, op: AssignOp::Assign, .. }));
            // branch with cmp
            assert!(matches!(&lbl.stmts[0], Stmt::Branch { cond: Some(BranchCond::Cmp { op: CmpOp::Eq, .. }), .. }));
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn parses_wide_div_forms() {
    let src = r#"
fn f() {
    alt rdx:rax = rax as u128;
    alt (rax, rdx) = rdx:rax /% d;
}
"#;
    let file = parse_ok(src);
    match &file.items[0] {
        Item::Fn(f) => {
            assert_eq!(f.body.stmts.len(), 2);
            assert!(matches!(&f.body.stmts[0], Stmt::Alt { src: Value::Cast { .. }, .. }));
            assert!(matches!(&f.body.stmts[1], Stmt::DivMod { .. }));
        }
        _ => panic!(),
    }
}

#[test]
fn parses_memory_places_and_casts() {
    let src = r#"
fn f(i @ rbx: u64) {
    bind x @ [arr + i * 8]: u64;
    alt x = 3;
    alt [rbx + rcx * 4 + 16]: u64 += x;
    alt dl = d as u8;
    bind (q @ rax, r @ rdx) = const { divmod(100, 7) };
}
"#;
    let file = parse_ok(src);
    match &file.items[0] {
        Item::Fn(f) => {
            assert_eq!(f.body.stmts.len(), 5);
            match &f.body.stmts[0] {
                Stmt::Bind { place, init, .. } => {
                    assert!(matches!(place, Place::Mem { .. }));
                    assert!(init.is_none());
                }
                other => panic!("{other:?}"),
            }
            assert!(matches!(&f.body.stmts[3], Stmt::Alt { src: Value::Cast { .. }, .. }));
            assert!(matches!(&f.body.stmts[4], Stmt::Bind { pattern: Some(_), .. }));
        }
        _ => panic!(),
    }
}

#[test]
fn parses_const_fn_and_consts() {
    let src = r#"
const fn divmod(a: u64, b: u64) -> (u64, u64) { return (a / b, a % b); }
const LIMIT: u64 = 0xFF + 1_000;
bind buf @ .bss: [u8; 16];
"#;
    let file = parse_ok(src);
    assert_eq!(file.items.len(), 3);
    assert!(matches!(&file.items[0], Item::ConstFn(c) if c.name == "divmod" && c.params.len() == 2));
    assert!(matches!(&file.items[1], Item::Const(c) if c.name == "LIMIT" && c.attrs.is_empty()));
    match &file.items[2] {
        Item::Static(s) => {
            assert_eq!(s.name, "buf");
            assert!(s.init.is_none());
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn parses_push_pop_flags_and_syscall() {
    let src = r#"
fn f() {
    push { rbx, r12 };
    pop { r12, rbx };
    branch (!carry) => 'next;
    syscall;
}
"#;
    let file = parse_ok(src);
    match &file.items[0] {
        Item::Fn(f) => {
            assert_eq!(f.body.stmts.len(), 4);
            assert!(matches!(&f.body.stmts[0], Stmt::Push { items, .. } if items.len() == 2));
            assert!(matches!(&f.body.stmts[2], Stmt::Branch { cond: Some(BranchCond::Flag { negated: true, .. }), .. }));
        }
        _ => panic!(),
    }
}

#[test]
fn parse_error_has_span_and_help() {
    // a number too large for i128 → bad-number diagnostic with a real span
    let out = parse("bind x @ rax: u64 = 99999999999999999999999999999999999999999999;");
    assert!(out.has_errors(), "{:#?}", out.diagnostics);
    let d = out.diagnostics.iter().find(|d| d.kind == "bad-number").expect("bad-number");
    assert!(d.primary_span().unwrap().lo > 0);
}

#[test]
fn unterminated_fn_error() {
    let out = parse("fn f() {");
    assert!(out.has_errors());
    assert_eq!(out.diagnostics[0].kind, "unexpected-eof");
}

#[test]
fn comments_captured_as_trivia() {
    let out = parse("// leading comment\nfn f() {} // trailing");
    assert!(!out.has_errors());
    assert!(out.comments.iter().any(|(_, c)| c.contains("leading")));
    assert!(out.comments.iter().any(|(_, c)| c.contains("trailing")));
}

// ---------------------------------------------------------------------------
// `pub` removal (§15 ✅ 29.10) — precise diagnostic, not a generic parse error
// ---------------------------------------------------------------------------

#[test]
fn pub_keyword_is_a_precise_error() {
    let src = "pub fn f() -> ! { syscall; }\n";
    let out = parse(src);
    assert!(out.file.is_none(), "pub fn must not parse");
    let d = out
        .diagnostics
        .iter()
        .find(|d| d.kind == "pub-removed")
        .unwrap_or_else(|| panic!("expected pub-removed diag, got {:?}", out.diagnostics.iter().map(|d| &d.kind).collect::<Vec<_>>()));
    assert!(d.message.contains("removed"), "{}", d.message);
}

#[test]
fn global_attribute_exports() {
    // #[global] is the surviving export mechanism.
    let src = "#[global]\nfn f() -> ! { syscall; }\n";
    let file = parse_ok(src);
    match &file.items[0] {
        Item::Fn(f) => assert!(f.exported, "#[global] must set exported"),
        other => panic!("expected fn, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// `use path::name;` (§10 modules)
// ---------------------------------------------------------------------------

#[test]
fn parses_use_item_single_segment_path() {
    let src = "use math::divmod;\n";
    let file = parse_ok(src);
    assert_eq!(file.items.len(), 1);
    match &file.items[0] {
        Item::Use { path, .. } => {
            let segs: Vec<&str> = path.iter().map(|(s, _)| s.as_str()).collect();
            assert_eq!(segs, vec!["math", "divmod"], "{path:?}");
        }
        other => panic!("expected use, got {other:?}"),
    }
}

#[test]
fn parses_use_item_nested_path() {
    let src = "use lib::math::divmod;\nuse single::thing;\n";
    let file = parse_ok(src);
    assert_eq!(file.items.len(), 2);
    match &file.items[0] {
        Item::Use { path, .. } => {
            let segs: Vec<&str> = path.iter().map(|(s, _)| s.as_str()).collect();
            assert_eq!(segs, vec!["lib", "math", "divmod"]);
        }
        other => panic!("expected use, got {other:?}"),
    }
    match &file.items[1] {
        Item::Use { path, .. } => {
            let segs: Vec<&str> = path.iter().map(|(s, _)| s.as_str()).collect();
            assert_eq!(segs, vec!["single", "thing"]);
        }
        other => panic!("expected use, got {other:?}"),
    }
}

#[test]
fn use_span_covers_the_statement() {
    let src = "use math::divmod;\n";
    let file = parse_ok(src);
    match &file.items[0] {
        Item::Use { span, .. } => {
            // "use math::divmod;" is 17 bytes: 0..17
            assert_eq!((span.lo, span.hi), (0, 17), "{span:?}");
        }
        other => panic!("expected use, got {other:?}"),
    }
}

#[test]
fn use_may_mix_with_other_items() {
    let src = "use math::divmod;\n#[global]\nfn f() -> ! { syscall; }\n";
    let file = parse_ok(src);
    assert_eq!(file.items.len(), 2);
    assert!(matches!(&file.items[0], Item::Use { .. }));
    assert!(matches!(&file.items[1], Item::Fn(_)));
}

// ---------------------------------------------------------------------------
// §14.4 minimal contracts: requires/ensures clauses (SPEC §15 ✅ 30.10)
// ---------------------------------------------------------------------------

#[test]
fn contracts_parse_on_fn() {
    let src = r#"
fn div(n @ rdi: u64, d @ rsi: u64) -> rax: u64
requires d != 0;
ensures rax >= 0;
{
    return;
}
"#;
    let file = parse_ok(src);
    match &file.items[0] {
        Item::Fn(f) => {
            assert_eq!(f.contracts.requires.len(), 1);
            assert_eq!(f.contracts.ensures.len(), 1);
            // `d != 0` is a Binary Ne over Name(d) and Int(0)
            match &f.contracts.requires[0].v {
                yana_ast::ConstExpr::Binary { op: yana_ast::ConstBinOp::Ne, lhs, rhs, .. } => {
                    assert!(matches!(lhs.as_ref(), yana_ast::ConstExpr::Name { name, .. } if name == "d"));
                    assert!(matches!(rhs.as_ref(), yana_ast::ConstExpr::Int { value: 0, .. }));
                }
                other => panic!("expected `d != 0`, got {other:?}"),
            }
            // clause spans are real (not dummy)
            assert!(!f.contracts.requires[0].span.is_dummy());
        }
        other => panic!("expected fn, got {other:?}"),
    }
}

#[test]
fn contracts_parse_after_clobbers_before_body() {
    let src = r#"
fn f(n @ rdi: u64) -> rax: u64
clobbers:
    rcx,
requires n > 0;
requires n < 100;
ensures rax > 0;
ensures rax <= 100;
{
    return;
}
"#;
    let file = parse_ok(src);
    match &file.items[0] {
        Item::Fn(f) => {
            assert!(f.clobbers.is_some());
            assert_eq!(f.contracts.requires.len(), 2);
            assert_eq!(f.contracts.ensures.len(), 2);
        }
        other => panic!("expected fn, got {other:?}"),
    }
}

#[test]
fn contracts_parse_on_extern_fn() {
    // spec order: clobbers block first, then contract clauses, then `;`
    let src = r#"
#[syscall(1)]
extern fn write(fd @ rdi: u64, buf @ rsi: *u8, len @ rdx: u64) -> rax: i64
clobbers:
    rcx,
    r11,
requires len > 0;
;
"#;
    let file = parse_ok(src);
    match &file.items[0] {
        Item::ExternFn(e) => {
            assert_eq!(e.contracts.requires.len(), 1);
            assert!(e.contracts.ensures.is_empty());
        }
        other => panic!("expected extern fn, got {other:?}"),
    }
}

#[test]
fn fn_without_contracts_keeps_empty_default() {
    let file = parse_ok("fn f() -> rax: u64 { return; }");
    match &file.items[0] {
        Item::Fn(f) => assert!(f.contracts.is_empty()),
        other => panic!("expected fn, got {other:?}"),
    }
}

#[test]
fn contract_expr_uses_const_precedence() {
    // `n > 0 && n < 10` parses as And(Gt, Lt), not Gt(n, And(...))
    let src = "fn f(n @ rdi: u64)\nrequires n > 0 && n < 10;\n{ }\n";
    let file = parse_ok(src);
    match &file.items[0] {
        Item::Fn(f) => match &f.contracts.requires[0].v {
            yana_ast::ConstExpr::Binary { op: yana_ast::ConstBinOp::And, .. } => {}
            other => panic!("expected && at top, got {other:?}"),
        },
        other => panic!("expected fn, got {other:?}"),
    }
}
