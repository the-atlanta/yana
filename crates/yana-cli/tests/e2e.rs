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
fn sibling_labels_scope_their_binds() {
    // §3/§6: a label body is a block — the same register may be re-bound in
    // a sibling label (the old behavior leaked binds across label bodies).
    let src = r#"
fn f() {
    label (a) { bind mut i @ rdi: u64 = 5; }
    label (b) { bind mut j @ rdi: u64 = 7; }
}
"#;
    let (_, diags) = resolve(src);
    assert!(
        !diags.iter().any(|d| d.kind == "reg-conflict"),
        "sibling label binds must not conflict: {:?}",
        diags.iter().map(|d| &d.message).collect::<Vec<_>>()
    );
}

#[test]
fn bind_leaves_scope_after_label_body() {
    // a name bound inside a label body is NOT visible after it
    let src = r#"
fn f() {
    label (a) { bind mut i @ rdi: u64 = 5; }
    alt i = 1;
}
"#;
    let (_, diags) = resolve(src);
    assert!(
        diags.iter().any(|d| matches!(d.level, yana_ast::DiagLevel::Error)),
        "expected error using out-of-scope bind, got {:?}",
        diags.iter().map(|d| (&d.kind, &d.message)).collect::<Vec<_>>()
    );
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

// ---------------------------------------------------------------------------
// `align N;` (§4.3 sugar, lowered by the §14.3 stack analysis)
// ---------------------------------------------------------------------------

/// Resolve + run the analysis pass (which lowers StackAlign → StackPad).
fn resolve_analyzed(src: &str) -> yana_codegen::Module {
    let (mut module, diags) = resolve(src);
    let errs: Vec<_> = diags
        .iter()
        .filter(|d| matches!(d.level, yana_ast::DiagLevel::Error))
        .map(|d| d.message.clone())
        .collect();
    assert!(errs.is_empty(), "resolve errors: {errs:?}");
    yana_analysis::analyze(&mut module);
    module
}

const ALIGN_CALLED: &str = r#"
#[entry]
fn main() -> ! {
    call worker {};
    syscall;
}

fn worker() -> ! {
    align 16;
    syscall;
}
"#;

#[test]
fn align_in_called_function_pads_by_8() {
    // A function entered via `call` has rsp ≡ 8 (mod 16) → align 16 pads by 8.
    let module = resolve_analyzed(ALIGN_CALLED);
    let worker = module
        .bodies
        .iter()
        .find(|b| module.symbols[b.symbol].name == "worker")
        .expect("worker body");
    let pads: Vec<u32> = worker
        .insns
        .iter()
        .filter_map(|si| match si.insn {
            Insn::StackPad { pad } => Some(pad),
            _ => None,
        })
        .collect();
    assert_eq!(pads, vec![8], "called fn align 16 must pad by 8");
    // no unlowered StackAlign may survive the analysis pass
    assert!(
        !worker.insns.iter().any(|si| matches!(si.insn, Insn::StackAlign { .. })),
        "StackAlign survived lowering"
    );
}

#[test]
fn align_encodes_to_lea_rsp_matching_nasm() {
    // The pad becomes `lea rsp,[rsp-8]` (flags untouched) in BOTH backends.
    let module = resolve_analyzed(ALIGN_CALLED);
    let enc = yana_back_iced::assemble_text(&module, Some(yana_back_iced::Layout::default_x86_64()))
        .expect("assemble");
    let dis = yana_back_iced::disassemble(&enc.text, 0).join("\n");
    assert!(dis.contains("lea rsp,[rsp-8h]"), "missing lea rsp,[rsp-8h]:\n{dis}");

    let nasm = yana_back_nasm::emit(&module, &[]);
    assert!(nasm.contains("lea rsp, [rsp-8]"), "nasm missing pad:\n{nasm}");
}

#[test]
fn align_at_depth_zero_in_entry_pads_by_zero() {
    // The process-entry function starts 16-aligned → align 16 pads by 0 →
    // StackPad{0} encodes to ZERO bytes in both backends.
    let src = r#"
#[entry]
fn main() -> ! {
    align 16;
    syscall;
}
"#;
    let module = resolve_analyzed(src);
    let pads: Vec<u32> = module.bodies[0]
        .insns
        .iter()
        .filter_map(|si| match si.insn {
            Insn::StackPad { pad } => Some(pad),
            _ => None,
        })
        .collect();
    assert_eq!(pads, vec![0], "entry fn at depth 0 must pad by 0");

    let enc = yana_back_iced::assemble_text(&module, Some(yana_back_iced::Layout::default_x86_64()))
        .expect("assemble");
    let dis = yana_back_iced::disassemble(&enc.text, 0).join("\n");
    assert!(!dis.contains("lea rsp"), "pad 0 must emit nothing:\n{dis}");
}

#[test]
fn align_after_push_realigns() {
    // push (depth 8) then align 16 in the entry fn → pad 8 → depth 16.
    let src = r#"
#[entry]
fn main() -> ! {
    push { rbx };
    align 16;
    pop { rbx };
    syscall;
}
"#;
    let module = resolve_analyzed(src);
    let pads: Vec<u32> = module.bodies[0]
        .insns
        .iter()
        .filter_map(|si| match si.insn {
            Insn::StackPad { pad } => Some(pad),
            _ => None,
        })
        .collect();
    assert_eq!(pads, vec![8], "push then align 16 in entry must pad by 8");
}

#[test]
fn align_non_power_of_two_is_error() {
    let src = r#"
#[entry]
fn main() -> ! {
    align 12;
    syscall;
}
"#;
    let (_, diags) = resolve(src);
    assert!(
        diags.iter().any(|d| d.kind == "align-power-of-two"
            && matches!(d.level, yana_ast::DiagLevel::Error)),
        "align 12 must be a semantic error: {:?}",
        diags.iter().map(|d| (&d.kind, &d.level)).collect::<Vec<_>>()
    );
}

// ---------------------------------------------------------------------------
// §12: atomics + volatile
// ---------------------------------------------------------------------------

const ATOMICS: &str = include_str!("../../../examples/atomics.yana");

#[test]
fn atomic_rmw_lowers_to_atomicrmw_insns() {
    let (module, diags) = resolve(ATOMICS);
    assert!(
        !diags.iter().any(|d| matches!(d.level, yana_ast::DiagLevel::Error)),
        "{:?}",
        diags.iter().map(|d| &d.message).collect::<Vec<_>>()
    );
    let body = &module.bodies[0];
    let atomics: Vec<&Insn> = body
        .insns
        .iter()
        .filter(|s| matches!(&s.insn, Insn::AtomicRMW { .. }))
        .map(|s| &s.insn)
        .collect();
    assert_eq!(atomics.len(), 3, "three atomic RMWs: {:?}", body.insns);
    for a in atomics {
        match a {
            Insn::AtomicRMW { op, order, src, dst, size } => {
                assert_eq!(*op, yana_codegen::AtomicOp::Add);
                assert_eq!(*order, yana_codegen::MemOrder::Relaxed);
                assert_eq!(*size, 64);
                assert!(matches!(src, yana_codegen::Operand::Imm(_)));
                assert!(matches!(dst, yana_codegen::Operand::Mem(_)));
            }
            _ => unreachable!(),
        }
    }
}

#[test]
fn atomic_encodes_lock_add_and_fixup_offsets_survive() {
    // The rip-relative disp32 of `lock add [rel counter], N` sits BEFORE the
    // trailing imm — the fixup must not clobber the immediate (§12 note).
    let (module, _) = resolve(ATOMICS);
    let enc = yana_back_iced::assemble_text(&module, Some(yana_back_iced::Layout::default_x86_64()))
        .expect("assemble");
    let dis = yana_back_iced::disassemble(&enc.text, 0).join("\n");
    // layout resolves the symbol: `lock add qword ptr [2000h],3` — the disp
    // is a concrete address, not [rip+…]; what matters is the immediate
    // survived the fixup (the disp32 sits BEFORE the imm8).
    assert!(dis.contains("lock add qword ptr ["), "{dis}");
    assert!(dis.contains(",3h"), "{dis}");
    assert!(dis.contains(",3"), "{dis}");
    assert!(dis.contains(",4"), "{dis}");
    assert!(dis.contains(",5"), "{dis}");
}

/// Full run: .data static counter, three atomic RMWs, exit with the sum (12).
#[test]
fn atomic_program_runs_and_exits_with_sum() {
    // `run` builds a static ELF and executes it; the test binary shells out.
    // NOTE: the bin is named `yana` (modules refactor moved main.rs → lib.rs).
    let exe = std::env::var("CARGO_BIN_EXE_yana").ok();
    let yana = exe.unwrap_or_else(|| "target/debug/yana".to_string());
    let out = std::process::Command::new(&yana)
        .arg("run")
        .arg(concat!(env!("CARGO_MANIFEST_DIR"), "/../../examples/atomics.yana"))
        .status()
        .expect("run yana-cli run examples/atomics.yana");
    let code = out.code().unwrap_or(-1);
    assert_eq!(code, 12, "3+4+5 must exit as 12, got {code}");
}

#[test]
fn atomic_all_orders_and_ops_resolve() {
    let src = r#"
bind cell @ .data: u64 = 0;
fn f() {
    bind mut r @ rax: u64 = 1;
    alt atomic(relaxed) [cell]: u64 += 1;
    alt atomic(acquire) [cell]: u64 -= 1;
    alt atomic(release) [cell]: u64 &= r;
    alt atomic(acqrel) [cell]: u64 |= 2;
    alt atomic(seqcst) [cell]: u64 ^= 4;
    alt atomic(seqcst) [cell]: u64 = r;
    return;
}
"#;
    let (module, diags) = resolve(src);
    assert!(
        !diags.iter().any(|d| matches!(d.level, yana_ast::DiagLevel::Error)),
        "{:?}",
        diags.iter().map(|d| &d.message).collect::<Vec<_>>()
    );
    let body = &module.bodies[0];
    let ops: Vec<yana_codegen::AtomicOp> = body
        .insns
        .iter()
        .filter_map(|s| match &s.insn {
            Insn::AtomicRMW { op, .. } => Some(*op),
            _ => None,
        })
        .collect();
    assert_eq!(
        ops,
        vec![
            yana_codegen::AtomicOp::Add,
            yana_codegen::AtomicOp::Sub,
            yana_codegen::AtomicOp::And,
            yana_codegen::AtomicOp::Or,
            yana_codegen::AtomicOp::Xor,
            yana_codegen::AtomicOp::Exchange,
        ],
        "{:?}",
        body.insns
    );
}

#[test]
fn atomic_register_target_is_error() {
    let src = r#"
fn f() {
    bind mut x @ rax: u64 = 0;
    alt atomic(relaxed) x += 1;
    return;
}
"#;
    let (_, diags) = resolve(src);
    assert!(
        diags.iter().any(|d| d.kind == "atomic-register"
            && matches!(d.level, yana_ast::DiagLevel::Error)),
        "expected atomic-register: {:?}",
        diags.iter().map(|d| (&d.kind, &d.level)).collect::<Vec<_>>()
    );
}

#[test]
fn atomic_memory_source_is_error_with_help() {
    let src = r#"
bind a @ .data: u64 = 0;
bind b @ .data: u64 = 1;
fn f() {
    alt atomic(relaxed) [a]: u64 += [b]: u64;
    return;
}
"#;
    let (_, diags) = resolve(src);
    let d = diags
        .iter()
        .find(|d| d.kind == "atomic-src-memory")
        .expect("atomic-src-memory diagnostic");
    assert!(matches!(d.level, yana_ast::DiagLevel::Error));
    assert_eq!(d.help.as_deref(), Some("load it into a register first"));
}

#[test]
fn atomic_bad_order_is_syntax_error() {
    let src = r#"
fn f() {
    alt atomic(sequentially) [rax]: u64 += 1;
    return;
}
"#;
    let parsed = yana_parser::parse(src);
    assert!(
        parsed.diagnostics.iter().any(|d| d.kind == "atomic-order"
            && matches!(d.level, yana_ast::DiagLevel::Error)),
        "expected atomic-order: {:?}",
        parsed.diagnostics.iter().map(|d| &d.message).collect::<Vec<_>>()
    );
}

#[test]
fn atomic_assign_imm_is_error_with_help() {
    let src = r#"
bind cell @ .data: u64 = 0;
fn f() {
    alt atomic(seqcst) [cell]: u64 = 42;
    return;
}
"#;
    let (_, diags) = resolve(src);
    let d = diags
        .iter()
        .find(|d| d.kind == "atomic-assign-imm")
        .expect("atomic-assign-imm diagnostic");
    assert!(matches!(d.level, yana_ast::DiagLevel::Error));
    assert_eq!(d.help.as_deref(), Some("xchg needs a register source: bind the value first"));
}

#[test]
fn atomic_on_non_x86_64_target_is_error() {
    // Owner decision 30.10: atomics on AArch64/Xtensa → unsupported on target.
    let src = r#"
fn f() {
    alt atomic(relaxed) [rax]: u64 += 1;
    return;
}
"#;
    let parsed = yana_parser::parse(src);
    let out = resolve_module(
        parsed.file.as_ref().unwrap(),
        &TargetInfo::aarch64_linux(),
        &ResolveOptions::default(),
    );
    assert!(
        out.diagnostics.iter().any(|d| d.kind == "unsupported-atomic-target"
            && matches!(d.level, yana_ast::DiagLevel::Error)),
        "expected unsupported-atomic-target: {:?}",
        out.diagnostics.iter().map(|d| (&d.kind, &d.message)).collect::<Vec<_>>()
    );
}

#[test]
fn volatile_wraps_inner_insn() {
    let src = r#"
fn f() {
    bind mut x @ rbx: u64 = 5;
    alt volatile x += 1;
    return;
}
"#;
    let (module, diags) = resolve(src);
    assert!(
        !diags.iter().any(|d| matches!(d.level, yana_ast::DiagLevel::Error)),
        "{:?}",
        diags.iter().map(|d| &d.message).collect::<Vec<_>>()
    );
    let body = &module.bodies[0];
    // the store to memory via volatile is a Volatile(Add) — and the liveness
    // analysis must not flag it dead even when its result is unused
    assert!(
        body.insns.iter().any(|s| matches!(&s.insn, Insn::Volatile(inner) if matches!(inner.as_ref(), Insn::Add { .. }))),
        "expected Volatile(Add): {:?}",
        body.insns
    );
}

#[test]
fn volatile_store_is_not_dead() {
    // liveness: a volatile memory store must never be flagged dead (§12)
    let src = r#"
fn f() {
    bind mut p @ rbx: *u64;
    alt volatile [p]: u64 = 0;
    return;
}
"#;
    let (mut module, diags) = resolve(src);
    assert!(
        !diags.iter().any(|d| matches!(d.level, yana_ast::DiagLevel::Error)),
        "{:?}",
        diags.iter().map(|d| &d.message).collect::<Vec<_>>()
    );
    let analysis = yana_analysis::analyze(&mut module);
    let dead: Vec<_> = analysis
        .iter()
        .filter(|d| d.kind == "dead-store" && d.message.contains("[p]") || d.message.contains("volatile"))
        .collect();
    assert!(
        dead.is_empty(),
        "volatile access must not be flagged dead: {:?}",
        dead.iter().map(|d| &d.message).collect::<Vec<_>>()
    );
}

// ---------------------------------------------------------------------------
// §14.4 contracts: resolve plumbing (names validated at resolve time)
// ---------------------------------------------------------------------------

#[test]
fn contracts_resolve_into_symbol() {
    let src = r#"
fn f(n @ rdi: u64) -> rax: u64
requires n != 0;
ensures rax >= 0;
{
    return;
}
"#;
    let (module, diags) = resolve(src);
    assert!(
        !diags.iter().any(|d| matches!(d.level, yana_ast::DiagLevel::Error)),
        "{:?}",
        diags.iter().map(|d| (&d.kind, &d.message)).collect::<Vec<_>>()
    );
    let sym = module.find("f").expect("symbol f");
    let c = &module.symbols[sym].contracts;
    assert_eq!(c.requires.len(), 1);
    assert_eq!(c.ensures.len(), 1);
    assert_eq!(c.params, vec![("n".to_string(), yana_ast::Reg::parse("rdi").unwrap())]);
    assert_eq!(c.results, vec![("rax".to_string(), yana_ast::Reg::parse("rax").unwrap())]);
}

#[test]
fn contract_unknown_ident_is_error() {
    let src = r#"
fn f(n @ rdi: u64) -> rax: u64
requires m != 0;
{
    return;
}
"#;
    let (_, diags) = resolve(src);
    let d = diags
        .iter()
        .find(|d| d.kind == "verify-contract-name")
        .expect("verify-contract-name diagnostic");
    assert!(matches!(d.level, yana_ast::DiagLevel::Error));
    assert!(d.message.contains('m'), "{}", d.message);
    assert!(d.help.as_deref().unwrap().contains('n'), "{:?}", d.help);
}

#[test]
fn contract_ensures_result_binding_name_allowed() {
    // tuple ret-sig: ensures may name the binding (`lo`) or the reg (`rax`)
    let src = r#"
fn f(n @ rdi: u64) -> (lo @ rax: u64, hi @ rdx: u64)
ensures lo >= 0;
ensures rdx >= hi;
{
    return;
}
"#;
    let (_, diags) = resolve(src);
    assert!(
        !diags.iter().any(|d| matches!(d.level, yana_ast::DiagLevel::Error)),
        "{:?}",
        diags.iter().map(|d| (&d.kind, &d.message)).collect::<Vec<_>>()
    );
}

#[test]
fn contract_ensures_result_name_rejected_in_requires() {
    // result regs are NOT in scope for requires (value at entry, not exit)
    let src = r#"
fn f(n @ rdi: u64) -> rax: u64
requires rax != 0;
{
    return;
}
"#;
    let (_, diags) = resolve(src);
    assert!(
        diags.iter().any(|d| d.kind == "verify-contract-name"),
        "{:?}",
        diags.iter().map(|d| (&d.kind, &d.message)).collect::<Vec<_>>()
    );
}

#[test]
fn contract_unsupported_shape_is_error() {
    let src = r#"
fn f(n @ rdi: u64) -> rax: u64
requires [n, n] != 0;
{
    return;
}
"#;
    let (_, diags) = resolve(src);
    assert!(
        diags.iter().any(|d| d.kind == "verify-contract-expr"),
        "{:?}",
        diags.iter().map(|d| (&d.kind, &d.message)).collect::<Vec<_>>()
    );
}
