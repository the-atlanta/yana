//! SSA-IR construction tests: bindings, `virt unbind`, phis and metadata.

use yana_codegen::{resolve_module, ResolveOptions, TargetInfo};
use yana_ir::{lift_module, BindKind, Home, Module, Op, PrintOptions, ValueKind};

fn resolve(src: &str) -> Module {
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
    lift_module(&out.module, "test.yana")
}

fn find_fn<'a>(m: &'a Module, name: &str) -> &'a yana_ir::Function {
    m.functions
        .iter()
        .find(|f| f.source_name == name)
        .unwrap_or_else(|| panic!("no function {name}"))
}

#[test]
fn bind_and_unbind_are_metadata_not_machine_code() {
    let m = resolve(
        r#"
#[syscall(60)]
extern fn sys_exit(code @ rdi: u64) -> !;

#[entry]
fn main() -> ! {
    bind n @ rax: u64 = 1;
    unbind n;
    bind n1 @ rax: u64 = 2;
    call sys_exit { code: 0 };
}
"#,
    );
    let f = find_fn(&m, "main");

    let n = f.bindings.iter().find(|b| b.name == "n").expect("n binding");
    let n1 = f.bindings.iter().find(|b| b.name == "n1").expect("n1 binding");
    assert_eq!(n.kind, BindKind::Local);
    assert!(n.retired_at.is_some(), "unbind must retire n");
    assert!(n1.retired_at.is_none());
    assert_ne!(n.value, n1.value, "n1 must be a new SSA definition");

    let unbind = f
        .blocks
        .iter()
        .flat_map(|b| &b.insts)
        .find(|i| matches!(&i.op, Op::VirtUnbind { name } if name == "n"))
        .expect("virt unbind n");
    assert_eq!(unbind.text, "virt unbind n");
    assert!(unbind.defs.is_empty(), "virt unbind defines nothing");
    assert!(unbind.machine.is_none(), "virt unbind emits no machine insn");
}

#[test]
fn bindings_shadow_and_keep_the_new_value() {
    let m = resolve(
        r#"
#[syscall(60)]
extern fn sys_exit(code @ rdi: u64) -> !;

#[entry]
fn main() -> ! {
    bind n @ rax: u64 = 1;
    bind n @ rax: u64 = 2;
    call sys_exit { code: 0 };
}
"#,
    );
    let f = find_fn(&m, "main");
    let ns: Vec<_> = f.bindings.iter().filter(|b| b.name == "n").collect();
    assert_eq!(ns.len(), 2, "both bindings are recorded");
    assert_ne!(ns[0].value, ns[1].value, "the shadowing bind is a new value");
    assert_eq!(ns[1].active_from, 1);
}

#[test]
fn loop_gets_physical_phis_and_done_reads_the_phi() {
    let src = include_str!("../../../examples/factorial.yana");
    let m = resolve(src);
    let f = find_fn(&m, "main");

    let loop_block = f
        .blocks
        .iter()
        .find(|b| b.label.as_deref() == Some("loop"))
        .expect("loop block");
    let phis: Vec<_> = loop_block
        .insts
        .iter()
        .filter_map(|i| match &i.op {
            Op::Phi { incoming } => Some((i, incoming)),
            _ => None,
        })
        .collect();
    assert!(
        phis.iter().any(|(i, incoming)| i.text.contains("%rax") && incoming.len() == 2),
        "rax needs a two-input phi at the loop header: {:?}",
        phis.iter().map(|(i, _)| &i.text).collect::<Vec<_>>()
    );
    assert!(
        phis.iter().any(|(i, incoming)| i.text.contains("%rbx") && incoming.len() == 2),
        "rbx needs a two-input phi at the loop header"
    );

    let done = f
        .blocks
        .iter()
        .find(|b| b.label.as_deref() == Some("done"))
        .expect("done block");
    let reads_phi = done.insts.iter().any(|i| {
        i.uses.iter().any(|v| {
            f.values[*v as usize].name == "%rax.0"
        })
    });
    assert!(
        reads_phi,
        "done must read the loop-header phi, not a value defined in bb2"
    );
}

#[test]
fn syscall_carries_abi_metadata_and_clobbers() {
    let src = include_str!("../../../examples/hello.yana");
    let m = resolve(src);
    let f = find_fn(&m, "main");
    let sys = f
        .blocks
        .iter()
        .flat_map(|b| &b.insts)
        .find(|i| matches!(i.op, Op::Syscall { .. }))
        .expect("syscall");
    assert!(
        sys.text.contains("syscall @write("),
        "syscall should name the contract: {}",
        sys.text
    );
    assert!(
        sys.comment.as_deref().unwrap_or("").contains("syscall nr 1"),
        "missing ABI comment: {:?}",
        sys.comment
    );
    let reg_defs: Vec<_> = sys
        .defs
        .iter()
        .filter(|v| f.values[**v as usize].kind != ValueKind::Flags)
        .collect();
    assert_eq!(reg_defs.len(), 3, "rax result + rcx/r11 clobbers");
}

#[test]
fn printer_emits_llvm_syntax_and_metadata() {
    let src = include_str!("../../../examples/factorial.yana");
    let m = resolve(src);
    let opts = PrintOptions {
        source_text: Some(src),
        module_name: Some("factorial.yana"),
        ..PrintOptions::default()
    };
    let text = yana_ir::print_module(&m, &opts);
    assert!(text.contains("source_filename = \"factorial.yana\""));
    assert!(text.contains("target triple = \"x86_64-unknown-linux-gnu\""));
    assert!(text.contains("!yana.module = !{!0}"));
    assert!(text.contains(" = phi i64 ["));
    assert!(text.contains("!bind !"));
    assert!(text.contains("!span !"));
    assert!(text.contains("[ssa] physical phi"));
    assert!(text.contains("br i1 "));
}

#[test]
fn physical_homes_are_pinned_and_stack_is_fixed() {
    let m = resolve(
        r#"
fn f() {
    bind n @ rax: u64 = 1;
    push { rax };
    pop { _ };
    return;
}
"#,
    );
    let f = find_fn(&m, "f");
    let rax = f.values.iter().find(|v| v.name == "%rax.0").unwrap();
    assert_eq!(rax.home, Home::Pinned(yana_ast::reg::Reg::parse("rax").unwrap()));
    let rsp = f.values.iter().find(|v| v.name == "%rsp.0").unwrap();
    assert!(matches!(rsp.home, Home::Fixed(_, _)));
}
