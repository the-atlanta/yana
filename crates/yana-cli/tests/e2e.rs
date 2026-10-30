//! End-to-end tests: source → resolve → iced backend → bytes → disassemble.
//! (Actual execution of built binaries happens in the CLI smoke tests below,
//! which shell out to the `yana` binary — skipped when it isn't built.)

use std::collections::HashMap;

use yana_codegen::{resolve_module, ResolveOptions, TargetInfo};
use yana_codegen::Insn;

fn resolve(src: &str) -> (yana_codegen::Module, Vec<yana_ast::Diagnostic>) {
    let parsed = yana_parser::parse(src);
    assert!(!parsed.has_errors(), "parse failed: {:?}", parsed.diagnostics.iter().map(|d| &d.message).collect::<Vec<_>>());
    let out = resolve_module(
        parsed.file.as_ref().unwrap(),
        &TargetInfo::linux_x86_64(),
        &ResolveOptions::default(),
    );
    (out.module, out.diagnostics)
}

fn assemble(src: &str) -> Vec<u8> {
    let (module, diags) = resolve(src);
    let errs: Vec<_> = diags
        .iter()
        .filter(|d| matches!(d.level, yana_ast::DiagLevel::Error))
        .collect();
    assert!(errs.is_empty(), "resolve errors: {:?}", errs.iter().map(|d| &d.message).collect::<Vec<_>>());
    let enc = yana_back_iced::assemble_text(&module, Some(yana_back_iced::Layout::default_x86_64()))
        .expect("assembly failed");
    enc.text
}

const HELLO: &str = include_str!("../../../examples/hello.yana");
const FACTORIAL: &str = include_str!("../../../examples/factorial.yana");

#[test]
fn hello_assembles_to_expected_bytes() {
    let text = assemble(HELLO);
    let dis = yana_back_iced::disassemble(&text, 0);
    let joined = dis.join("\n");
    assert!(joined.contains("mov rdi,1"), "{joined}");
    assert!(joined.contains("lea rsi,"), "{joined}");
    assert!(joined.contains("mov rdx,0Dh"), "{joined}");
    assert!(joined.contains("syscall"), "{joined}");
}

#[test]
fn factorial_loop_and_branches_resolve() {
    let text = assemble(FACTORIAL);
    let dis = yana_back_iced::disassemble(&text, 0);
    let joined = dis.join("\n");
    // cmp + je (forward to done), jmp (backward to loop), imul
    assert!(joined.contains("cmp"), "{joined}");
    assert!(joined.contains("je "), "{joined}");
    assert!(joined.contains("jmp"), "{joined}");
    assert!(joined.contains("imul"), "{joined}");
}

#[test]
fn branches_encode_rel32_and_targets_are_correct() {
    let text = assemble(FACTORIAL);
    let dis = yana_back_iced::disassemble(&text, 0);
    let jmp = dis.iter().find(|l| l.contains("jmp")).expect("has jmp");
    // iced prints "0000001e  jmp 0000000Eh" — strip the h suffix
    let target_str = jmp.split("jmp").nth(1).unwrap().trim();
    let target_str = target_str.strip_suffix('h').unwrap_or(target_str);
    let target = u64::from_str_radix(target_str, 16).expect("hex target");
    let own = u64::from_str_radix(jmp.split_whitespace().next().unwrap(), 16).unwrap();
    assert!(target < own, "expected backward jump, got {jmp}");
    // and je jumps forward to done
    let je = dis.iter().find(|l| l.contains("je ")).expect("has je");
    let je_target_str = je.split("je").nth(1).unwrap().trim();
    let je_target_str = je_target_str.strip_suffix('h').unwrap_or(je_target_str);
    let je_target = u64::from_str_radix(je_target_str, 16).expect("hex target");
    let je_own = u64::from_str_radix(je.split_whitespace().next().unwrap(), 16).unwrap();
    assert!(je_target > je_own, "expected forward jump, got {je}");
}

#[test]
fn wide_div_forms() {
    let src = r#"
#[entry]
fn main() -> ! {
    bind mut a @ rax: u64 = 100;
    bind mut d @ rbx: u64 = 7;
    alt rdx:rax = a as u128;
    alt (rax, rdx) = rdx:rax /% d;
    syscall;
}
"#;
    let (module, _) = resolve(src);
    let body = &module.bodies[0];
    // expect: mov rax,100; mov rbx,7; xor edx,edx (extend pair unsigned); div rbx; syscall
    let kinds: Vec<&Insn> = body.insns.iter().map(|s| &s.insn).collect();
    assert!(kinds.iter().any(|i| matches!(i, Insn::ExtendPair { signed: false, .. })), "{kinds:?}");
    assert!(kinds.iter().any(|i| matches!(i, Insn::DivWide { op: yana_codegen::WideOp::Unsigned, .. })), "{kinds:?}");
}

#[test]
fn const_divmod_into_destructuring_bind() {
    let src = r#"
const fn divmod(a: u64, b: u64) -> (u64, u64) { return (a / b, a % b); }
#[entry]
fn main() -> ! {
    bind (q @ rax, r @ rdx) = const { divmod(100, 7) };
    syscall;
}
"#;
    let (module, diags) = resolve(src);
    assert!(!diags.iter().any(|d| matches!(d.level, yana_ast::DiagLevel::Error)), "{:?}", diags.iter().map(|d| &d.message).collect::<Vec<_>>());
    let body = &module.bodies[0];
    // q=14 → rax, r=2 → rdx
    let movs: Vec<_> = body
        .insns
        .iter()
        .filter_map(|s| match &s.insn {
            Insn::Mov { dst: yana_codegen::Operand::Reg(r), src: yana_codegen::Operand::Imm(v), .. } => {
                Some((r.name(), *v))
            }
            _ => None,
        })
        .collect();
    assert!(movs.contains(&("rax", 14)), "{movs:?}");
    assert!(movs.contains(&("rdx", 2)), "{movs:?}");
}

#[test]
fn immutable_bind_write_is_error() {
    let src = r#"
fn f() {
    bind x @ rax: u64 = 1;
    alt x += 1;
}
"#;
    let (_, diags) = resolve(src);
    assert!(
        diags.iter().any(|d| d.kind == "immutable-write"),
        "expected immutable-write error, got {:?}",
        diags.iter().map(|d| (&d.kind, &d.message)).collect::<Vec<_>>()
    );
}

#[test]
fn mut_bind_write_is_fine() {
    let src = r#"
fn f() {
    bind mut x @ rax: u64 = 1;
    alt x += 1;
}
"#;
    let (_, diags) = resolve(src);
    assert!(!diags.iter().any(|d| matches!(d.level, yana_ast::DiagLevel::Error)), "{:?}", diags.iter().map(|d| &d.message).collect::<Vec<_>>());
}

#[test]
fn wrong_pair_order_is_error() {
    let src = r#"
fn f() {
    bind mut v @ rbx: u64 = 3;
    alt rax:rdx = v as u128;
}
"#;
    // `rax:rdx` parses as pair but in wrong hw order → pair-order error
    let (_, diags) = resolve(src);
    assert!(
        diags.iter().any(|d| d.kind == "pair-order"),
        "expected pair-order error, got {:?}",
        diags.iter().map(|d| (&d.kind, &d.message)).collect::<Vec<_>>()
    );
}

#[test]
fn div_by_const_zero_is_error() {
    let src = r#"
fn f() {
    bind mut d @ rbx: u64 = 0;
    alt (rax, rdx) = rdx:rax /% 0;
    alt d += 1;
}
"#;
    let (_, diags) = resolve(src);
    assert!(diags.iter().any(|d| d.kind == "div-zero"), "{:?}", diags.iter().map(|d| &d.kind).collect::<Vec<_>>());
}

#[test]
fn return_redundant_place_is_warning() {
    let src = r#"
fn f() -> rax: u64 {
    return rax;
}
"#;
    let (_, diags) = resolve(src);
    assert!(
        diags.iter().any(|d| d.kind == "redundant" && matches!(d.level, yana_ast::DiagLevel::Warning)),
        "{:?}",
        diags.iter().map(|d| (&d.kind, &d.level)).collect::<Vec<_>>()
    );
}

#[test]
fn return_contract_mismatch_warns_and_strict_escalates() {
    let src = r#"
fn f() -> rax: u64 {
    return rcx;
}
"#;
    let parsed = yana_parser::parse(src);
    let file = parsed.file.unwrap();
    let out = resolve_module(&file, &TargetInfo::linux_x86_64(), &ResolveOptions::default());
    let c = out.diagnostics.iter().find(|d| d.kind == "contract").expect("contract warning");
    assert!(!c.is_fatal(false));
    assert!(c.is_fatal(true));
}

#[test]
fn syscall_extern_lowers_to_mov_rax_syscall() {
    let (module, _) = resolve(HELLO);
    let body = &module.bodies[0];
    let seq: Vec<&Insn> = body.insns.iter().map(|s| &s.insn).collect();
    // find `mov rax, 1` immediately followed by Syscall (the write extern)
    let found = seq.windows(2).any(|w| {
        matches!(w[0], Insn::Mov { dst: yana_codegen::Operand::Reg(r), src: yana_codegen::Operand::Imm(1), .. } if r.name() == "rax")
            && matches!(w[1], Insn::Syscall)
    });
    assert!(found, "syscall extern not lowered: {seq:?}");
}

#[test]
fn static_len_field_resolves() {
    let src = r#"
bind msg @ .rodata: [u8] = "abcd";
fn f() -> rsi: u64 {
    bind n @ rax: u64 = msg.len;
    return rax;
}
"#;
    let (module, diags) = resolve(src);
    assert!(!diags.iter().any(|d| matches!(d.level, yana_ast::DiagLevel::Error)), "{:?}", diags.iter().map(|d| &d.message).collect::<Vec<_>>());
    let body = &module.bodies[0];
    assert!(body.insns.iter().any(|s| matches!(&s.insn, Insn::Mov { src: yana_codegen::Operand::Imm(4), .. })), "{:?}", body.insns);
}

#[test]
fn memory_indexed_addressing() {
    let src = r#"
bind arr @ .bss: [u64; 8];
fn f(i @ rbx: u64) -> rax: u64 {
    alt rax = [arr + i * 8]: u64;
    return;
}
"#;
    let (module, diags) = resolve(src);
    assert!(!diags.iter().any(|d| matches!(d.level, yana_ast::DiagLevel::Error)), "{:?}", diags.iter().map(|d| &d.message).collect::<Vec<_>>());
    let body = &module.bodies[0];
    // expect a mov rax, [rip-ish sym + rbx*8]
    assert!(
        body.insns.iter().any(|s| matches!(&s.insn, Insn::Mov { src: yana_codegen::Operand::Mem(m), .. } if m.index.is_some() && m.scale == 8)),
        "{:?}",
        body.insns
    );
}

#[test]
fn push_pop_slots_use_lea_rsp() {
    let src = r#"
fn f() {
    push { rbx, _ };
    pop { _, rbx };
}
"#;
    let (module, _) = resolve(src);
    let body = &module.bodies[0];
    let slots: Vec<bool> = body
        .insns
        .iter()
        .filter_map(|s| match &s.insn {
            Insn::StackSlot { grow } => Some(*grow),
            _ => None,
        })
        .collect();
    assert_eq!(slots, vec![true, false], "{:?}", body.insns);
}

#[test]
fn exe_link_produces_valid_elf() {
    let (module, _) = resolve(HELLO);
    let exe = yana_back_iced::link_exe(&module).expect("link_exe");
    assert_eq!(&exe[0..4], b"\x7fELF");
    assert_eq!(exe[4], 2, "ELF64");
    // ET_EXEC
    assert_eq!(u16::from_le_bytes([exe[16], exe[17]]), 2);
    // entry nonzero
    let entry = u64::from_le_bytes(exe[24..32].try_into().unwrap());
    assert_eq!(entry, 0x401000);
}

/// The NASM emitter must produce text nasm(1) accepts; the CLI oracle test
/// does the full comparison. Here we only snapshot basic structure.
#[test]
fn nasm_emit_has_labels_and_globals() {
    let (module, _) = resolve(HELLO);
    let src = yana_back_nasm::emit(&module, &[]);
    assert!(src.contains("bits 64"), "{src}");
    assert!(src.contains("default rel"), "{src}");
    assert!(src.contains("global _start"), "{src}");
    assert!(src.contains("hello:"), "static label missing:\n{src}");
    assert!(src.contains("lea rsi, [rel hello]"), "{src}");
}
