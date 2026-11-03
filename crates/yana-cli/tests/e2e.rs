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
// §11 diagnostics UX (review 31.10): `_` discard, label texts, second spans
// ---------------------------------------------------------------------------

#[test]
fn wildcard_bind_is_repeatable_and_holds_no_name() {
    // `_` is the discard: two `bind _` in one scope are fine, and `_` never
    // conflicts with a named binding on the same register.
    let src = r#"
fn f() {
    bind a @ rax: u64 = 1;
    bind _ @ rax: u64 = 0x0000000A21646C72;
    bind _ @ rax: u64 = 0x6F77206F6C6C6548;
    return;
}
"#;
    let (_, diags) = resolve(src);
    assert!(
        !diags.iter().any(|d| matches!(d.level, yana_ast::DiagLevel::Error)),
        "`_` must be freely rebindable: {:?}",
        diags.iter().map(|d| (&d.kind, &d.message)).collect::<Vec<_>>()
    );
}

#[test]
fn dup_bind_labels_point_at_both_sites() {
    let src = r#"
fn f() {
    bind a @ rax: u64 = 1;
    bind a @ rcx: u64 = 2;
    return;
}
"#;
    let (_, diags) = resolve(src);
    let d = diags.iter().find(|d| d.kind == "dup-bind").expect("dup-bind expected");
    // primary label has text (no empty `╰──`) and a secondary points at the first bind
    let primary = d.labels.iter().find(|l| l.primary).unwrap();
    assert!(!primary.message.is_empty(), "primary label must carry text");
    let secondary = d.labels.iter().find(|l| !l.primary).expect("secondary label expected");
    assert!(
        secondary.message.contains("first bound here") && secondary.message.contains("`a`"),
        "secondary label: {:?}",
        secondary.message
    );
    // secondary span is the FIRST bind statement (earlier in the source)
    assert!(secondary.span.lo < primary.span.lo, "secondary must point backwards");
    let help = d.help.as_deref().unwrap();
    assert!(help.contains("{ ... }") && help.contains("`_`"), "help must offer block/`_`: {help}");
}

#[test]
fn reg_conflict_underlines_name_and_offers_fixes() {
    let src = "fn f() {\n    bind a @ rax: u64 = 1;\n    bind aa @ rax: u64 = 2;\n    return;\n}\n";
    let (_, diags) = resolve(src);
    let d = diags.iter().find(|d| d.kind == "reg-conflict").expect("reg-conflict expected");
    // primary span = the NAME `aa`, not the whole statement
    let p = d.primary_span().unwrap();
    assert_eq!(p.hi - p.lo, 2, "must underline just `aa`, got span {:?}", p);
    assert_eq!(&src[p.lo as usize..p.hi as usize], "aa");
    // secondary label shows who holds the register
    let secondary = d.labels.iter().find(|l| !l.primary).expect("secondary label expected");
    assert!(
        secondary.message.contains("`a` is bound to rax here"),
        "secondary label: {:?}",
        secondary.message
    );
    let primary = d.labels.iter().find(|l| l.primary).unwrap();
    assert!(!primary.message.is_empty(), "primary label must carry text");
    let help = d.help.as_deref().unwrap();
    assert!(help.contains("{ ... }") && help.contains("`_`"), "help must offer block/`_`: {help}");
}

#[test]
fn underscore_prefix_suppresses_dead_store() {
    // `_sink` is an intentional sink: no dead-store note…
    let src = "fn f() {\n    bind _sink @ rcx: u64 = 42;\n    return;\n}\n";
    let (mut module, diags) = resolve(src);
    assert!(!diags.iter().any(|d| matches!(d.level, yana_ast::DiagLevel::Error)), "{:?}", diags);
    let analysis = yana_analysis::analyze(&mut module);
    assert!(
        !analysis.iter().any(|d| d.kind == "dead-store"),
        "`_`-prefixed binding must not warn: {:?}",
        analysis.iter().map(|d| &d.message).collect::<Vec<_>>()
    );
    // …while the same code without the prefix does warn, and the help
    // mentions the `_` convention.
    let src2 = "fn f() {\n    bind sink @ rcx: u64 = 42;\n    return;\n}\n";
    let (mut module2, _) = resolve(src2);
    let analysis2 = yana_analysis::analyze(&mut module2);
    let dead = analysis2.iter().find(|d| d.kind == "dead-store").expect("dead-store expected");
    let help = dead.help.as_deref().unwrap();
    assert!(help.contains("volatile") && help.contains("`_`"), "help must offer both options: {help}");
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
    assert!(c.invariants.is_empty());
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

// ---------------------------------------------------------------------------
// §5.3 stack arguments, §4.6 debug/assert, §5.6 #[naked]
// ---------------------------------------------------------------------------

#[test]
fn stack_args_push_in_reverse_and_caller_cleans_up() {
    let src = r#"
fn add3(a @ rdi: u64, b @ stack: u64, c @ stack: u64) -> rax: u64 {
    alt rax = a;
    alt rax += b;
    alt rax += c;
    return;
}
#[entry]
fn main() -> ! {
    bind r = call add3 { a: 1, b: 2, c: 3 };
    syscall;
}
"#;
    let text = assemble(src);
    let dis = yana_back_iced::disassemble(&text, 0);
    let joined = dis.join("\n");
    // last stack arg first
    let push3 = joined.find("push 3").expect("push 3");
    let push2 = joined.find("push 2").expect("push 2");
    assert!(push3 < push2, "stack args must be pushed right-to-left:\n{joined}");
    assert!(joined.contains("call"), "{joined}");
    assert_eq!(joined.matches("lea rsp,[rsp+8h]").count(), 2, "{joined}");
}

#[test]
fn assert_lowers_to_cmp_jcc_ud2() {
    let src = r#"
#[entry]
fn main() -> ! {
    bind mut x @ rdi = 5;
    alt x = 6;
    assert (x == 5);
    syscall;
}
"#;
    let text = assemble(src);
    let joined = yana_back_iced::disassemble(&text, 0).join("\n");
    assert!(joined.contains("cmp"), "{joined}");
    assert!(joined.contains("jne"), "{joined}");
    assert!(joined.contains("ud2"), "{joined}");
}

#[test]
fn debug_block_is_skipped_in_release() {
    let src = r#"
#[entry]
fn main() -> ! {
    debug { alt rdi = 7; }
    syscall;
}
"#;
    let parsed = yana_parser::parse(src);
    let target = TargetInfo::linux_x86_64();

    let mut debug_opts = ResolveOptions::default();
    debug_opts.debug = true;
    let dbg = resolve_module(parsed.file.as_ref().unwrap(), &target, &debug_opts).module;
    let dbg_text = yana_back_iced::assemble_text(&dbg, Some(yana_back_iced::Layout::default_x86_64()))
        .expect("assemble debug")
        .text;
    assert!(yana_back_iced::disassemble(&dbg_text, 0).join("\n").contains("mov rdi,7"));

    let mut rel_opts = ResolveOptions::default();
    rel_opts.debug = false;
    let rel = resolve_module(parsed.file.as_ref().unwrap(), &target, &rel_opts).module;
    let rel_text = yana_back_iced::assemble_text(&rel, Some(yana_back_iced::Layout::default_x86_64()))
        .expect("assemble release")
        .text;
    assert!(!yana_back_iced::disassemble(&rel_text, 0).join("\n").contains("mov rdi,7"));
}

#[test]
fn naked_function_has_no_prologue_or_epilogue() {
    let src = r#"
#[naked]
fn hand() -> rax: u64 {
    alt rax = 42;
    return;
}
#[entry]
fn main() -> ! {
    syscall;
}
"#;
    let text = assemble(src);
    let joined = yana_back_iced::disassemble(&text, 0).join("\n");
    assert!(!joined.contains("push rbp"), "{joined}");
    assert!(!joined.contains("mov rbp,rsp"), "{joined}");
    assert!(joined.contains("mov rax,2Ah") || joined.contains("mov rax,42"), "{joined}");
}


#[test]
fn invariant_resolves_into_symbol() {
    let src = r#"
fn f(n @ rdi: u64) -> rax: u64
invariant n < 100;
invariant rax <= 100;
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
    assert_eq!(module.symbols[sym].contracts.invariants.len(), 2);
}

// ---------------------------------------------------------------------------
// §8 const-only structs
// ---------------------------------------------------------------------------

#[test]
fn struct_const_and_static_resolve() {
    let src = r#"
struct Point { x: u32, y: u32 }
const P: Point = Point(1, 2);
bind p @ .rodata: Point = P;
bind q @ .data: Point = Point(3, 4);
#[entry]
fn main() -> ! { alt rax = 60; alt rdi = 0; syscall; }
"#;
    let (module, diags) = resolve(src);
    assert!(
        !diags.iter().any(|d| matches!(d.level, yana_ast::DiagLevel::Error)),
        "{:?}",
        diags.iter().map(|d| (&d.kind, &d.message)).collect::<Vec<_>>()
    );
    assert!(module.find("P").is_some(), "const symbol");
    let rodata = module.sections.iter().find(|s| s.kind == yana_ast::place::SectionKind::RoData).unwrap();
    let bytes: Vec<u8> = rodata
        .items
        .iter()
        .flat_map(|i| match i {
            yana_codegen::DataItem::Bytes { bytes, .. } => bytes.clone(),
            _ => vec![],
        })
        .collect();
    assert!(bytes.windows(8).any(|w| w == [1, 0, 0, 0, 2, 0, 0, 0]), "{bytes:?}");
}

#[test]
fn struct_layout_pads_and_aligns() {
    let src = r#"
struct Inner { a: u8, b: u32 }
struct Outer { x: u8, inner: Inner, y: u16 }
const O: Outer = Outer(0x11, Inner(0x22, 0x33333333), 0x4444);
bind o @ .rodata: Outer = O;
#[entry]
fn main() -> ! { alt rax = 60; alt rdi = 0; syscall; }
"#;
    let (module, diags) = resolve(src);
    assert!(
        !diags.iter().any(|d| matches!(d.level, yana_ast::DiagLevel::Error)),
        "{:?}",
        diags.iter().map(|d| (&d.kind, &d.message)).collect::<Vec<_>>()
    );
    let rodata = module.sections.iter().find(|s| s.kind == yana_ast::place::SectionKind::RoData).unwrap();
    let bytes: Vec<u8> = rodata
        .items
        .iter()
        .flat_map(|i| match i {
            yana_codegen::DataItem::Bytes { bytes, .. } => bytes.clone(),
            _ => vec![],
        })
        .collect();
    let expected = [0x11, 0, 0, 0, 0x22, 0, 0, 0, 0x33, 0x33, 0x33, 0x33, 0x44, 0x44, 0, 0];
    assert!(bytes.windows(expected.len()).any(|w| w == expected), "{bytes:?}");
}

#[test]
fn struct_init_arity_is_error() {
    let src = r#"
struct Point { x: u32, y: u32 }
const P: Point = Point(1, 2, 3);
#[entry]
fn main() -> ! { alt rax = 60; alt rdi = 0; syscall; }
"#;
    let (_module, diags) = resolve(src);
    assert!(diags.iter().any(|d| d.kind == "struct-init-arity"), "{:?}", diags.iter().map(|d| &d.kind).collect::<Vec<_>>());
}

#[test]
fn struct_cycle_is_error() {
    let src = r#"
struct A { b: B }
struct B { a: A }
#[entry]
fn main() -> ! { alt rax = 60; alt rdi = 0; syscall; }
"#;
    let (_module, diags) = resolve(src);
    assert!(diags.iter().any(|d| d.kind == "struct-cycle"), "{:?}", diags.iter().map(|d| &d.kind).collect::<Vec<_>>());
}

// ---------------------------------------------------------------------------
// F8: Mach-O object output (x86-64 macOS)
// ---------------------------------------------------------------------------

#[test]
fn macos_target_emits_macho_object() {
    let src = r#"
extern "C" fn ext();
bind msg @ .rodata: [u8; 4] = b"abcd";
#[entry]
fn main() -> ! { call ext; alt rax = 60; alt rdi = 0; syscall; }
"#;
    let dir = std::env::temp_dir().join(format!("yana-macho-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let input = dir.join("m.yana");
    let output = dir.join("m.o");
    std::fs::write(&input, src).unwrap();
    let code = yana_cli::run([
        "yana",
        "build",
        input.to_str().unwrap(),
        "--target",
        "x86_64-macos",
        "--object",
        "-o",
        output.to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "macho build failed");
    let bytes = std::fs::read(&output).unwrap();
    assert_eq!(&bytes[0..4], &0xfeed_facfu32.to_le_bytes(), "MH_MAGIC_64");
    assert_eq!(
        u32::from_le_bytes(bytes[12..16].try_into().unwrap()),
        1,
        "MH_OBJECT"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn unsupported_target_is_a_clean_error() {
    let src = "#[entry]\nfn main() -> ! { alt rax = 60; alt rdi = 0; syscall; }\n";
    let dir = std::env::temp_dir().join(format!("yana-target-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let input = dir.join("m.yana");
    std::fs::write(&input, src).unwrap();
    let code = yana_cli::run([
        "yana",
        "build",
        input.to_str().unwrap(),
        "--target",
        "aarch64-linux",
    ]);
    assert_eq!(code, 1, "unsupported target must fail");
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// F16: `yana fmt`
// ---------------------------------------------------------------------------

#[test]
fn fmt_write_normalizes_indentation_and_check_detects_it() {
    let dir = std::env::temp_dir().join(format!("yana-fmt-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("f.yana");
    std::fs::write(&path, "fn f() {\nalt rax = 1;\n}\n").unwrap();

    // --check fails before formatting
    assert_eq!(
        yana_cli::run(["yana", "fmt", path.to_str().unwrap(), "--check"]),
        1
    );
    // --write fixes it
    assert_eq!(
        yana_cli::run(["yana", "fmt", path.to_str().unwrap(), "--write"]),
        0
    );
    let formatted = std::fs::read_to_string(&path).unwrap();
    assert_eq!(formatted, "fn f() {\n    alt rax = 1;\n}\n");
    // now --check passes
    assert_eq!(
        yana_cli::run(["yana", "fmt", path.to_str().unwrap(), "--check"]),
        0
    );
    let _ = std::fs::remove_dir_all(&dir);
}
