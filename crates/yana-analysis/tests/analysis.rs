//! Analysis tests: each check must fire on a crafted bad program and stay
//! silent on the good one.

use yana_analysis::{analyze, cfg};
use yana_codegen::{resolve_module, ResolveOptions, TargetInfo};

fn module_of(src: &str) -> yana_codegen::Module {
    let parsed = yana_parser::parse(src);
    assert!(
        !parsed.has_errors(),
        "parse failed: {:?}",
        parsed.diagnostics.iter().map(|d| &d.message).collect::<Vec<_>>()
    );
    let out = resolve_module(
        parsed.file.as_ref().unwrap(),
        &TargetInfo::linux_x86_64(),
        &ResolveOptions::default(),
    );
    let errs: Vec<_> = out
        .diagnostics
        .iter()
        .filter(|d| matches!(d.level, yana_ast::DiagLevel::Error))
        .collect();
    assert!(errs.is_empty(), "resolve errors: {:?}", errs.iter().map(|d| &d.message).collect::<Vec<_>>());
    out.module
}

fn kinds(src: &str) -> Vec<String> {
    let mut m = module_of(src);
    analyze(&mut m).into_iter().map(|d| d.kind).collect()
}

// ---- stack ----

#[test]
fn unbalanced_push_at_return_is_flagged() {
    let k = kinds(
        r#"
fn f() -> rax: u64 {
    push { rbx };
    alt rax = 1;
    return;
}
"#,
    );
    assert!(k.iter().any(|s| s == "stack-unbalanced"), "{k:?}");
}

#[test]
fn balanced_push_pop_is_clean() {
    let k = kinds(
        r#"
fn f() -> rax: u64 {
    push { rbx };
    alt rbx = 5;
    alt rax = rbx;
    pop { rbx };
    return;
}
"#,
    );
    assert!(!k.iter().any(|s| s == "stack-unbalanced"), "{k:?}");
}

#[test]
fn pop_without_push_underflows() {
    let k = kinds(
        r#"
fn f() -> rax: u64 {
    pop { rbx };
    alt rax = rbx;
    return;
}
"#,
    );
    assert!(k.iter().any(|s| s == "stack-underflow"), "{k:?}");
}

// ---- flags ----

#[test]
fn branch_without_cmp_reads_undefined_flags() {
    let k = kinds(
        r#"
fn f() -> rax: u64 {
    alt rax = 1;
    branch (zero) => 'end;
    label (end) {
        return;
    }
}
"#,
    );
    assert!(k.iter().any(|s| s == "undefined-flags"), "{k:?}");
}

#[test]
fn branch_after_cmp_is_clean() {
    let k = kinds(
        r#"
fn f(n @ rbx: u64) -> rax: u64 {
    alt rax = 0;
    branch (n == 0) => 'end;
    label (end) {
        return;
    }
}
"#,
    );
    assert!(!k.iter().any(|s| s == "undefined-flags"), "{k:?}");
}

// ---- scope (§6) ----

#[test]
fn branch_into_nested_block_is_error() {
    let k = kinds(
        r#"
fn f() -> rax: u64 {
    alt rax = 0;
    branch => 'inner;
    {
        label (inner) {
            alt rax = 1;
        }
    }
    return;
}
"#,
    );
    assert!(k.iter().any(|s| s == "label-into-block"), "{k:?}");
}

#[test]
fn branch_to_outer_label_is_fine() {
    let k = kinds(
        r#"
fn f() -> rax: u64 {
    label (outer) {
        alt rax = 0;
        branch => 'outer;
    }
}
"#,
    );
    assert!(!k.iter().any(|s| s == "label-into-block"), "{k:?}");
}

// ---- result / fallthrough ----

#[test]
fn fallthrough_off_the_end_is_error() {
    let k = kinds(
        r#"
fn f() -> rax: u64 {
    alt rax = 1;
}
"#,
    );
    assert!(k.iter().any(|s| s == "fallthrough"), "{k:?}");
}

// ---- cfg ----

#[test]
fn cfg_has_back_edge_for_loop() {
    let m = module_of(
        r#"
fn f(n @ rbx: u64) -> rax: u64 {
    alt rax = 0;
    label (loop) {
        branch (n == 0) => 'done;
        alt rax += n;
        branch => 'loop;
    }
    label (done) {
        return;
    }
}
"#,
    );
    let g = cfg::build(&m, &m.bodies[0]);
    assert!(g.blocks.len() >= 3, "expected multiple blocks, got {}", g.blocks.len());
    let rpo = g.rpo();
    assert_eq!(rpo[0], 0);
}

// ---- clobber derivation ----

#[test]
fn derive_clobbers_lists_written_regs() {
    let m = module_of(
        r#"
fn f() -> rax: u64 {
    alt rcx = 1;
    alt rax = rcx;
    return;
}
"#,
    );
    let clob = yana_analysis::liveness::derive_clobbers(&m, &m.bodies[0]);
    let names: Vec<_> = clob.iter().map(|r| r.name()).collect();
    // rcx written and not a result → clobbered; rax is the result → excluded
    assert!(names.contains(&"rcx"), "{names:?}");
    assert!(!names.contains(&"rax"), "result reg should not be a clobber: {names:?}");
}
