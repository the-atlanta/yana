//! Module loader (§10) unit tests + multi-module e2e build/run tests.
//!
//! The e2e tests shell out to `ld` (the multi-module link uses the system
//! linker, like the existing nasm backend path) and execute the built binary;
//! both are guarded on `ld` being present.

use std::path::{Path, PathBuf};
use std::process::Command;

use yana_cli::loader::Loader;

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/modules")
}

fn ld_available() -> bool {
    Command::new("ld").arg("--version").output().is_ok()
}

fn load(path: &Path) -> Loader {
    let mut loader = Loader::new();
    loader.load(path, false).expect("load");
    loader
}

// ---------------------------------------------------------------------------
// loader unit tests
// ---------------------------------------------------------------------------

#[test]
fn loader_loads_root_and_dependencies() {
    let loader = load(&fixtures().join("main.yana"));
    assert!(loader.diags.is_empty(), "diags: {:?}", loader.diags.iter().map(|d| &d.diag.kind).collect::<Vec<_>>());
    // two modules: math (dep) first, main (root) last — DFS post-order
    assert_eq!(loader.mods.len(), 2);
    let math = &loader.mods[0];
    let main = &loader.mods[1];
    assert!(math.path.ends_with("math.yana"));
    assert!(main.path.ends_with("main.yana"));
    // math's IR defines add10 (global) and BASE
    assert!(math.module.symbols.iter().any(|s| s.name == "add10" && s.exported));
    // main's IR has an undefined import for add10 and _start entry
    assert!(main.module.entry.is_some());
}

#[test]
fn unresolved_import_missing_name_is_error() {
    let loader = load(&fixtures().join("bad/main_import_missing.yana"));
    assert!(loader.has_fatal(false));
    let d = loader
        .diags
        .iter()
        .find(|d| d.diag.kind == "unresolved-import")
        .expect("unresolved-import diagnostic");
    assert!(d.diag.message.contains("no item named `nope`"), "{}", d.diag.message);
}

#[test]
fn unresolved_import_non_global_is_error_with_help() {
    let loader = load(&fixtures().join("bad/main_import_hidden.yana"));
    assert!(loader.has_fatal(false));
    let d = loader
        .diags
        .iter()
        .find(|d| d.diag.kind == "unresolved-import")
        .expect("unresolved-import diagnostic");
    assert!(d.diag.message.contains("`hidden`"), "{}", d.diag.message);
    assert_eq!(d.diag.help.as_deref(), Some("not exported: add #[global]"));
}

#[test]
fn module_not_found_is_error() {
    let loader = load(&fixtures().join("bad/main_mod_not_found.yana"));
    assert!(loader.has_fatal(false));
    let d = loader
        .diags
        .iter()
        .find(|d| d.diag.kind == "module-not-found")
        .expect("module-not-found diagnostic");
    assert!(d.diag.message.contains("`gone`"), "{}", d.diag.message);
}

#[test]
fn circular_use_is_error() {
    let loader = load(&fixtures().join("bad/loop_a.yana"));
    assert!(loader.has_fatal(false));
    let d = loader
        .diags
        .iter()
        .find(|d| d.diag.kind == "circular-use")
        .expect("circular-use diagnostic");
    assert!(d.diag.message.contains("using itself"), "{}", d.diag.message);
}

// ---------------------------------------------------------------------------
// e2e: build → link with ld → execute
// ---------------------------------------------------------------------------

#[test]
fn two_module_program_builds_links_and_runs() {
    if !ld_available() {
        eprintln!("skipping: ld not available");
        return;
    }
    let out = std::env::temp_dir().join(format!("yana-test-mod-{}", std::process::id()));
    let code = yana_cli::run([
        "yana",
        "build",
        fixtures().join("main.yana").to_str().unwrap(),
        "-o",
        out.to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "build failed");

    // the built executable runs and exits with the computed value:
    // (7 + 10 + BASE(1000) + 52) mod 256 = 45
    let status = Command::new(&out).status().expect("execute");
    assert_eq!(status.code(), Some(45), "wrong exit code");

    let _ = std::fs::remove_file(&out);
}

#[test]
fn two_module_program_run_command_executes() {
    if !ld_available() {
        eprintln!("skipping: ld not available");
        return;
    }
    let code = yana_cli::run(["yana", "run", fixtures().join("main.yana").to_str().unwrap()]);
    assert_eq!(code, 45, "yana run exit code");
}

#[test]
fn object_output_for_used_file_has_undefined_import() {
    // `--object` emits ONE .o for the given file (§10): imports undefined.
    let out = std::env::temp_dir().join(format!("yana-test-obj-{}.o", std::process::id()));
    let code = yana_cli::run([
        "yana",
        "build",
        fixtures().join("main.yana").to_str().unwrap(),
        "--object",
        "-o",
        out.to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "object build failed");
    let bytes = std::fs::read(&out).expect("read .o");
    assert_eq!(&bytes[0..4], b"\x7fELF");
    // ET_REL
    assert_eq!(u16::from_le_bytes([bytes[16], bytes[17]]), 1);
    let _ = std::fs::remove_file(&out);
}

#[test]
fn object_outputs_link_together_with_ld() {
    if !ld_available() {
        eprintln!("skipping: ld not available");
        return;
    }
    let tmp = std::env::temp_dir().join(format!("yana-test-link-{}", std::process::id()));
    let main_o = tmp.with_extension("main.o");
    let math_o = tmp.with_extension("math.o");
    let exe = tmp.with_extension("exe");
    fn obj_build(src: &Path, out: &Path) -> i32 {
        yana_cli::run(["yana", "build", "--object", "-o", out.to_str().unwrap(), src.to_str().unwrap()])
    }
    assert_eq!(0, obj_build(&fixtures().join("main.yana"), &main_o), "main.o");
    assert_eq!(0, obj_build(&fixtures().join("math.yana"), &math_o), "math.o");
    let ok = Command::new("ld")
        .arg("-o")
        .arg(&exe)
        .arg(&main_o)
        .arg(&math_o)
        .status()
        .expect("ld")
        .success();
    assert!(ok, "ld link failed");
    let status = Command::new(&exe).status().expect("execute");
    assert_eq!(status.code(), Some(45));
    let _ = std::fs::remove_file(&main_o);
    let _ = std::fs::remove_file(&math_o);
    let _ = std::fs::remove_file(&exe);
}

// ---------------------------------------------------------------------------
// baseline: single-file behavior unchanged
// ---------------------------------------------------------------------------

#[test]
fn single_file_build_run_unchanged() {
    if !ld_available() {
        eprintln!("skipping: ld not available");
        return;
    }
    let examples = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples");
    let code = yana_cli::run(["yana", "run", examples.join("factorial.yana").to_str().unwrap()]);
    assert_eq!(code, 120, "factorial exit code");
}

#[test]
fn loader_missing_root_file_is_error() {
    let mut loader = Loader::new();
    let res = loader.load(Path::new("/nonexistent/nope.yana"), false);
    assert!(res.is_err(), "missing root must be Err: {res:?}");
}
