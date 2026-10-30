//! E2e for §9 macros: source → expand → resolve → iced backend → bytes.

use yana_codegen::{resolve_module, ResolveOptions, TargetInfo};

fn resolve_clean(src: &str) -> yana_codegen::Module {
    let parsed = yana_parser::parse(src);
    assert!(
        !parsed.has_errors(),
        "parse failed: {:?}",
        parsed
            .diagnostics
            .iter()
            .map(|d| &d.message)
            .collect::<Vec<_>>()
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
    assert!(
        errs.is_empty(),
        "resolve errors: {:?}",
        errs.iter().map(|d| &d.message).collect::<Vec<_>>()
    );
    out.module
}

fn assemble(src: &str) -> Vec<u8> {
    let module = resolve_clean(src);
    let enc = yana_back_iced::assemble_text(&module, Some(yana_back_iced::Layout::default_x86_64()))
        .expect("assembly failed");
    enc.text
}

#[test]
fn macro_expansion_resolves_and_assembles() {
    // a macro that expands to register ops: bind + expanded alt (mov)
    let text = assemble(
        r#"
macro set(dst: place, src: value) { alt dst = src; }
#[entry]
fn main() -> ! {
    bind mut x @ rax: u64 = 0;
    set!(x, 42);
}
"#,
    );
    let dis = yana_back_iced::disassemble(&text, 0).join("\n");
    assert!(dis.contains("mov"), "no mov in disassembly:\n{dis}");
}

#[test]
fn macro_rules_repetition_assembles() {
    // $(...),+ repetition: each ident gets one `add`
    let text = assemble(
        r#"
macro_rules! incs { ($($r:ident),+) => { $(alt $r += 1;)* } }
#[entry]
fn main() -> ! {
    bind mut a @ rax: u64 = 0;
    bind mut b @ rcx: u64 = 0;
    incs!(a, b);
}
"#,
    );
    let dis = yana_back_iced::disassemble(&text, 0).join("\n");
    assert!(
        dis.matches("add").count() >= 2,
        "expected >=2 adds from repetition, got:\n{dis}"
    );
}

#[test]
fn nasm_emit_contains_expansion_comment() {
    let parsed = yana_parser::parse(
        r#"
macro set(dst: place, src: value) { alt dst = src; }
#[entry]
fn main() -> ! {
    bind mut x @ rax: u64 = 0;
    set!(x, 42);
}
"#,
    );
    assert!(!parsed.has_errors(), "parse failed");
    let out = resolve_module(
        parsed.file.as_ref().unwrap(),
        &TargetInfo::linux_x86_64(),
        &ResolveOptions::default(),
    );
    assert!(
        !out.diagnostics.iter().any(|d| matches!(d.level, yana_ast::DiagLevel::Error)),
        "resolve failed: {:?}",
        out.diagnostics.iter().map(|d| &d.message).collect::<Vec<_>>()
    );
    let asm = yana_back_nasm::emit(&out.module, &parsed.comments);
    assert!(
        asm.contains("macro `set`"),
        "no expansion comment in NASM output:\n{asm}"
    );
}

#[test]
fn hygiene_two_expansions_still_resolve() {
    // two expansions of the same macro: binds/labels renamed, program resolves
    let module = resolve_clean(
        r#"
macro cnt(r: value) {
    label (top) {
        bind mut i @ rcx: u64 = r;
        branch (i == 0) => 'done;
        alt i -= 1;
        branch => 'top;
    }
}
#[entry]
fn main() -> ! {
    label (done) {
        cnt!(5);
        cnt!(7);
        alt rax = 60;
        syscall;
    }
}
"#,
    );
    // both expansions must have survived lowering: distinct label definitions
    // (top__h1, top__h2 renamed; done declared once)
    let label_names: Vec<String> = module
        .bodies
        .iter()
        .flat_map(|b| b.label_defs.iter().map(|l| l.name.clone()))
        .collect();
    assert!(label_names.contains(&"top__h1".to_string()), "{label_names:?}");
    assert!(label_names.contains(&"top__h2".to_string()), "{label_names:?}");
}
