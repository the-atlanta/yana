//! E2E tests for §14 pass 4 through the CLI: `yana verify <file>` and
//! `yana build --verify <file>`. Contract checks need z3; tests that require
//! it skip (print + pass) when the binary is missing, mirroring the CLI's
//! `verify-smt-unavailable` degrade path.

use std::io::Write;
use std::path::PathBuf;
use std::process::Command;

fn yana_bin() -> String {
    std::env::var("CARGO_BIN_EXE_yana").unwrap_or_else(|_| "target/debug/yana".to_string())
}

fn z3_present() -> bool {
    for cand in ["/home/nika/.local/bin/z3", "/usr/bin/z3", "/usr/local/bin/z3"] {
        if std::path::Path::new(cand).exists() {
            return true;
        }
    }
    Command::new("which").arg("z3").status().map(|s| s.success()).unwrap_or(false)
}

/// Write `src` to a fresh file under CARGO_TARGET_TMPDIR and return its path.
fn fixture(name: &str, src: &str) -> PathBuf {
    let mut dir = PathBuf::from(std::env::var("CARGO_TARGET_TMPDIR").unwrap_or_else(|_| ".".into()));
    dir.push("verify-e2e");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(name);
    let mut f = std::fs::File::create(&path).unwrap();
    f.write_all(src.as_bytes()).unwrap();
    drop(f);
    path
}

fn run(args: &[&str]) -> (i32, String) {
    let out = Command::new(yana_bin())
        .args(args)
        .output()
        .expect("run yana");
    let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&out.stderr));
    (out.status.code().unwrap_or(-1), text)
}

// ---------------------------------------------------------------------------
// `yana verify`
// ---------------------------------------------------------------------------

#[test]
fn verify_div_by_zero_program_fails() {
    // flow-dependent zero divisor (a constant 0 divisor is already a resolve
    // error; here the divisor becomes 0 through arithmetic)
    let src = r#"
#[entry]
fn main() -> ! {
    bind mut a @ rax: u64 = 100;
    bind mut d @ rbx: u64 = 3;
    alt d -= 3;
    alt rdx:rax = a as u128;
    alt (rax, rdx) = rdx:rax /% d;
    syscall;
}
"#;
    let path = fixture("divzero.yana", src);
    let (code, text) = run(&["verify", path.to_str().unwrap()]);
    assert!(code > 0, "verify must fail on a provable div-by-zero: {text}");
    assert!(text.contains("verify-div-zero"), "{text}");
}

#[test]
fn verify_safe_program_passes() {
    // the divisor is provably nonzero on every path reaching the division
    let src = r#"
#[syscall(60)]
extern fn exit(code @ rdi: u64) -> !;

#[entry]
fn main() -> ! {
    bind mut a @ rax: u64 = 100;
    bind mut d @ rbx: u64 = 7;
    branch (d == 0) => 'bye;
    alt rdx:rax = a as u128;
    alt (rax, rdx) = rdx:rax /% d;
    branch => 'bye;
    label (bye) { call exit { code: 0 }; }
}
"#;
    let path = fixture("divsafe.yana", src);
    let (code, text) = run(&["verify", path.to_str().unwrap()]);
    assert_eq!(code, 0, "provably-safe program must pass verify: {text}");
}

#[test]
fn verify_examples_clean() {
    // the shipped examples must stay verify-clean (no new gate breakage)
    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../../examples");
    for ex in ["hello.yana", "factorial.yana", "atomics.yana"] {
        let path = format!("{root}/{ex}");
        let (code, text) = run(&["verify", &path]);
        assert_eq!(code, 0, "{ex} must pass verify: {text}");
    }
}

#[test]
fn verify_contract_violation_caught() {
    if !z3_present() {
        eprintln!("z3 missing — contract e2e skipped");
        return;
    }
    let src = r#"
fn f(n @ rdi: u64) -> rax: u64
requires n > 0;
ensures rax >= 100;
{
    alt rax = 50;
    return;
}

#[entry]
fn main() -> ! {
    bind r = call f { n: 0 };
    syscall;
}
"#;
    let path = fixture("contract.yana", src);
    let (code, text) = run(&["verify", path.to_str().unwrap()]);
    assert!(code > 0, "contract violations must fail verify: {text}");
    assert!(text.contains("verify-requires"), "{text}");
    assert!(text.contains("verify-ensures"), "{text}");
    // z3 counterexample model in the messages
    assert!(text.contains("n = 0"), "{text}");
}

#[test]
fn verify_contract_ok_program_passes() {
    if !z3_present() {
        eprintln!("z3 missing — contract e2e skipped");
        return;
    }
    let src = r#"
fn f(n @ rdi: u64) -> rax: u64
requires n > 0;
ensures rax >= 100;
{
    alt rax = 100;
    return;
}

#[entry]
fn main() -> ! {
    bind r = call f { n: 7 };
    syscall;
}
"#;
    let path = fixture("contract_ok.yana", src);
    let (code, text) = run(&["verify", path.to_str().unwrap()]);
    assert_eq!(code, 0, "proven contracts must pass: {text}");
}

// ---------------------------------------------------------------------------
// `yana build --verify`
// ---------------------------------------------------------------------------

#[test]
fn build_verify_flag_fails_on_div_zero() {
    let src = r#"
#[entry]
fn main() -> ! {
    bind mut a @ rax: u64 = 100;
    bind mut d @ rbx: u64 = 3;
    alt d -= 3;
    alt rdx:rax = a as u128;
    alt (rax, rdx) = rdx:rax /% d;
    syscall;
}
"#;
    let path = fixture("build_divzero.yana", src);
    let out = std::env::temp_dir().join(format!("yana-verify-e2e-{}.exe", std::process::id()));
    let (code, text) = run(&[
        "build",
        "--verify",
        "-o",
        out.to_str().unwrap(),
        path.to_str().unwrap(),
    ]);
    assert!(code != 0, "build --verify must fail on div-by-zero: {text}");
    assert!(text.contains("verify-div-zero"), "{text}");
    assert!(!out.exists(), "no executable may be written when verify fails");
}

#[test]
fn build_verify_flag_passes_and_still_builds() {
    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../../examples");
    let out = std::env::temp_dir().join(format!("yana-verify-e2e-ok-{}.exe", std::process::id()));
    let (code, text) = run(&[
        "build",
        "--verify",
        "-o",
        out.to_str().unwrap(),
        &format!("{root}/factorial.yana"),
    ]);
    assert_eq!(code, 0, "build --verify on factorial must succeed: {text}");
    assert!(out.exists(), "executable must be written");
    // and it still runs correctly
    let status = Command::new(&out).status().expect("run built exe");
    assert_eq!(status.code().unwrap_or(-1), 120);
    let _ = std::fs::remove_file(&out);
}
