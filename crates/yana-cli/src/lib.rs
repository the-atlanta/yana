//! `yana` — the CLI (spec §13/§14 driver).
//!
//! Subcommands:
//! - `build`   → object or executable via a chosen backend
//! - `run`     → build a static exe (iced) + execute
//! - `expand`  → print resolved IR (one line per instruction)
//! - `nasm`    → emit NASM source (comments preserved as trivia)
//! - `oracle`  → build with BOTH backends, compare disassembly (§13)
//!
//! Diagnostics render through ariadne; exit code = fatal diagnostic count
//! (errors + `contract` warnings under `--strict`).
//!
//! §10 modules: `build`/`run` auto-discover `use` dependencies, resolve each
//! module, emit one object file per source file and link them with the
//! system `ld` (entry = the root module's `#[entry]` symbol). Files without
//! `use` keep the single-file pipeline (link_exe static path) unchanged.

pub mod loader;
pub mod report;

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use clap::{Parser, Subcommand, ValueEnum};

use yana_codegen::{resolve_module, Module, ResolveOptions, TargetInfo};

use loader::Loader;

#[derive(Parser)]
#[command(name = "yana", version, about = "Yet Another New Assembly")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Compile a .yana file
    Build {
        file: PathBuf,
        #[arg(short, long)]
        out: Option<PathBuf>,
        #[arg(long, value_enum, default_value_t = BackendArg::Iced)]
        backend: BackendArg,
        /// Emit a relocatable .o instead of an executable (iced backend)
        #[arg(long)]
        object: bool,
        /// `contract` warnings become errors (§11)
        #[arg(long)]
        strict: bool,
        /// §14 pass 4: interval analysis + contracts before building;
        /// verify errors fail the build
        #[arg(long)]
        verify: bool,
    },
    /// Compile and run (iced backend, static executable)
    Run {
        file: PathBuf,
        #[arg(long)]
        strict: bool,
    },
    /// Print the resolved IR, one instruction per line (§14 pass 2)
    Expand {
        file: PathBuf,
        /// Print the post-expansion token stream instead of the IR (§9):
        /// one token per line, comments included.
        #[arg(long)]
        macros: bool,
    },
    /// Emit NASM assembly text (§13: comments preserved)
    Nasm {
        file: PathBuf,
        #[arg(short, long)]
        out: Option<PathBuf>,
        /// Also assemble with nasm(1) when available
        #[arg(long)]
        assemble: bool,
    },
    /// Build with both backends and compare the disassembly (test oracle)
    Oracle { file: PathBuf },
    /// §14 pass 4: verify (interval analysis + `requires`/`ensures` via z3);
    /// exit code = number of verify errors
    Verify { file: PathBuf },
}

#[derive(ValueEnum, Clone, Copy, PartialEq, Eq)]
enum BackendArg {
    Iced,
    Nasm,
}

/// Run the CLI from raw `args`. Integration tests call this instead of
/// shelling out to the binary.
pub fn run<I, S>(args: I) -> i32
where
    I: IntoIterator<Item = S>,
    S: Into<std::ffi::OsString> + Clone,
{
    let cli = Cli::parse_from(args);
    match cli.cmd {
        Cmd::Build { file, out, backend, object, strict, verify } => cmd_build(&file, out, backend, object, strict, verify),
        Cmd::Run { file, strict } => cmd_run(&file, strict),
        Cmd::Expand { file, macros } => cmd_expand(&file, macros),
        Cmd::Nasm { file, out, assemble } => cmd_nasm(&file, out, assemble),
        Cmd::Oracle { file } => cmd_oracle(&file),
        Cmd::Verify { file } => cmd_verify(&file),
    }
}

fn main() {
    let code = run(std::env::args());
    std::process::exit(code);
}

// ---------------------------------------------------------------------------
// pipeline helpers
// ---------------------------------------------------------------------------

struct Loaded {
    name: String,
    source: String,
    comments: Vec<(u32, String)>,
}

fn load(path: &Path) -> Option<Loaded> {
    match std::fs::read_to_string(path) {
        Ok(source) => {
            let parsed = yana_parser::parse(&source);
            Some(Loaded {
                name: path
                    .file_name()
                    .map(|s| s.to_string_lossy().into_owned())
                    .unwrap_or_else(|| path.display().to_string()),
                comments: parsed.comments,
                source,
            })
        }
        Err(e) => {
            eprintln!("yana: cannot read {}: {e}", path.display());
            None
        }
    }
}

/// Parse + resolve, rendering diagnostics. Returns None on any fatal error.
/// `verify` additionally runs §14 pass 4 after pass 3 (`build --verify`).
fn resolve_ex(loaded: &Loaded, strict: bool, verify: bool) -> Option<Module> {
    let parsed = yana_parser::parse(&loaded.source);
    let mut diags = parsed.diagnostics.clone();
    let file = match parsed.file {
        Some(f) => f,
        None => {
            report::render(&loaded.name, &loaded.source, &diags, strict);
            return None;
        }
    };
    let target = TargetInfo::linux_x86_64();
    let opts = ResolveOptions { strict, ..Default::default() };
    let mut out = resolve_module(&file, &target, &opts);
    let had_errors = out.has_errors();
    diags.extend(out.diagnostics.clone());
    if !had_errors {
        // §14 pass 3: flow analysis. Runs always (contract-class diagnostics
        // are warnings by default, errors under --strict per §11). Also
        // lowers `align N;` into concrete StackPad before the backends run.
        diags.extend(yana_analysis::analyze(&mut out.module));
        if verify {
            // §14 pass 4: read-only interval + contract verification. Errors
            // fail the build (the caller counts fatals below).
            diags.extend(yana_analysis::verify::verify(&out.module));
        }
    }
    let fatal = report::render(&loaded.name, &loaded.source, &diags, strict);
    if fatal > 0 || had_errors {
        return None;
    }
    Some(out.module)
}

/// Parse + resolve, rendering diagnostics. Returns None on any fatal error.
fn resolve(loaded: &Loaded, strict: bool) -> Option<Module> {
    resolve_ex(loaded, strict, false)
}

/// Resolve WITHOUT pass 3 (`yana verify`, NOTES-verify D3: pass 4 stays
/// read-only, so no `analyze()` — Call clobbers are handled conservatively
/// inside the verifier itself). Returns None on any fatal resolve error.
fn resolve_for_verify(loaded: &Loaded) -> Option<Module> {
    let parsed = yana_parser::parse(&loaded.source);
    let mut diags = parsed.diagnostics.clone();
    let file = match parsed.file {
        Some(f) => f,
        None => {
            report::render(&loaded.name, &loaded.source, &diags, false);
            return None;
        }
    };
    let target = TargetInfo::linux_x86_64();
    let opts = ResolveOptions { strict: false, ..Default::default() };
    let out = resolve_module(&file, &target, &opts);
    let had_errors = out.has_errors();
    diags.extend(out.diagnostics.clone());
    let fatal = report::render(&loaded.name, &loaded.source, &diags, false);
    if fatal > 0 || had_errors {
        return None;
    }
    Some(out.module)
}

// ---------------------------------------------------------------------------
// §10 multi-module pipeline
// ---------------------------------------------------------------------------

/// Run §14 pass 4 over every loaded module, render its diagnostics against
/// each module's own source, and return the fatal (error) count.
fn loader_verify(loader: &mut Loader, strict: bool) -> usize {
    let mut fatal = 0;
    for m in &loader.mods {
        let diags = yana_analysis::verify::verify(&m.module);
        let name = m.path.display().to_string();
        fatal += report::render(&name, &m.source, &diags, strict);
    }
    fatal
}

/// `--object` for a file with `use` items: resolve the module graph (imports
/// come from the used modules) but emit only ONE .o for the given file —
/// §10 "one source file = one object file". The imports remain undefined
/// (SHN_UNDEF) for the user's own link step.
fn build_single_object(path: &Path, strict: bool, out: &Path, verify: bool) -> Result<Option<usize>, String> {
    let mut loader = Loader::new();
    loader.load(path, strict)?;
    if loader.render(strict) > 0 || loader.has_fatal(strict) {
        return Ok(None);
    }
    if verify && loader_verify(&mut loader, strict) != 0 {
        return Ok(None);
    }
    let Some(root) = loader.mods.last() else { return Ok(None) };
    let enc = yana_back_iced::assemble_text(&root.module, None).map_err(|e| e.to_string())?;
    let bytes = yana_back_iced::write_object(&root.module, &enc).map_err(|e| e.to_string())?;
    std::fs::write(out, &bytes).map_err(|e| format!("cannot write {}: {e}", out.display()))?;
    Ok(Some(bytes.len()))
}

/// Build a multi-module program (§10): resolve every involved module →
/// one object file per source file → link all .o with the system `ld`.
/// The entry point is the root module's `#[entry]` symbol.
///
/// Returns Ok(Some(exe)) on success; Ok(None) when diagnostics were rendered
/// and the build should stop; Err(msg) for environment problems (missing ld).
fn build_multi(path: &Path, strict: bool, exe: &Path, verify: bool) -> Result<Option<Vec<u8>>, String> {
    let mut loader = Loader::new();
    loader.load(path, strict)?;

    if loader.render(strict) > 0 || loader.has_fatal(strict) {
        return Ok(None);
    }
    if verify && loader_verify(&mut loader, strict) != 0 {
        return Ok(None);
    }
    let mods = &loader.mods;
    if mods.is_empty() {
        return Ok(None);
    }
    // root must be the last one (deps come first in post-order) — entry lives there
    let root = mods.last().expect("at least the root module");
    if root.module.entry.is_none() {
        eprintln!("yana: root module {} has no #[entry] function", root.path.display());
        return Ok(None);
    }

    // one object file per source file, temp files next to the output
    let tmpdir = std::env::temp_dir().join(format!(
        "yana-build-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&tmpdir).map_err(|e| format!("cannot create {}: {e}", tmpdir.display()))?;
    let mut objects: Vec<PathBuf> = Vec::new();
    for (i, m) in mods.iter().enumerate() {
        let enc = yana_back_iced::assemble_text(&m.module, None)
            .map_err(|e| e.to_string())?;
        let bytes = yana_back_iced::write_object(&m.module, &enc).map_err(|e| e.to_string())?;
        let o = tmpdir.join(format!("mod{i}.o"));
        std::fs::write(&o, bytes).map_err(|e| format!("cannot write {}: {e}", o.display()))?;
        objects.push(o);
    }

    // link with the system ld (like the nasm backend path)
    let mut cmd = Command::new("ld");
    cmd.arg("-o").arg(exe);
    for o in &objects {
        cmd.arg(o);
    }
    match cmd.status() {
        Ok(s) if s.success() => {}
        Ok(s) => return Err(format!("ld exited with {s}")),
        Err(e) => return Err(format!("cannot run ld: {e}")),
    }

    let out = std::fs::read(exe).map_err(|e| format!("cannot read {}: {e}", exe.display()))?;
    let _ = std::fs::remove_dir_all(&tmpdir);
    eprintln!(
        "yana: wrote {} ({} modules, via ld)",
        exe.display(),
        mods.len()
    );
    Ok(Some(out))
}

// ---------------------------------------------------------------------------
// subcommands
// ---------------------------------------------------------------------------

fn cmd_build(path: &Path, out: Option<PathBuf>, backend: BackendArg, object: bool, strict: bool, verify: bool) -> i32 {
    // §10: auto-discover `use` dependencies; single-file behavior is
    // unchanged when the file has no `use` items.
    let has_uses = std::fs::read_to_string(path)
        .map(|src| {
            yana_parser::parse(&src)
                .file
                .map(|f| !yana_codegen::modules::use_refs(&f).is_empty())
                .unwrap_or(false)
        })
        .unwrap_or(false);

    if has_uses && backend == BackendArg::Iced {
        let out = out.unwrap_or_else(|| default_out(path, backend, object));
        if object {
            // §10: one object file per source file — emit only the given
            // file's .o (imports stay undefined; the user links them).
            return match build_single_object(path, strict, &out, verify) {
                Ok(Some(n)) => {
                    eprintln!("yana: wrote {} ({} bytes)", out.display(), n);
                    0
                }
                Ok(None) => 1,
                Err(e) => fail(&e),
            };
        }
        return match build_multi(path, strict, &out, verify) {
            Ok(Some(_)) => {
                if let Err(e) = set_executable(&out) {
                    return fail(&e);
                }
                0
            }
            Ok(None) => 1,
            Err(e) => fail(&e),
        };
    }

    let Some(loaded) = load(path) else { return 2 };
    let Some(module) = resolve_ex(&loaded, strict, verify) else { return 1 };
    let out = out.unwrap_or_else(|| default_out(path, backend, object));

    match backend {
        BackendArg::Iced => {
            let bytes = if object {
                let enc = match yana_back_iced::assemble_text(&module, None) {
                    Ok(e) => e,
                    Err(e) => return fail(&e.to_string()),
                };
                match yana_back_iced::write_object(&module, &enc) {
                    Ok(b) => b,
                    Err(e) => return fail(&e.to_string()),
                }
            } else {
                match yana_back_iced::link_exe(&module) {
                    Ok(b) => b,
                    Err(e) => return fail(&e.to_string()),
                }
            };
            if let Err(e) = std::fs::write(&out, &bytes) {
                return fail(&format!("cannot write {}: {e}", out.display()));
            }
            if !object {
                if let Err(e) = set_executable(&out) {
                    return fail(&e);
                }
            }
            eprintln!("yana: wrote {} ({} bytes)", out.display(), bytes.len());
            0
        }
        BackendArg::Nasm => {
            let src = yana_back_nasm::emit(&module, &loaded.comments);
            let asm_path = out.with_extension("asm");
            if let Err(e) = std::fs::write(&asm_path, &src) {
                return fail(&format!("cannot write {}: {e}", asm_path.display()));
            }
            let o_path = out.with_extension("o");
            match Command::new("nasm").args(["-f", "elf64", "-o"]).arg(&o_path).arg(&asm_path).status() {
                Ok(s) if s.success() => {}
                Ok(s) => return fail(&format!("nasm exited with {s}")),
                Err(e) => return fail(&format!("cannot run nasm: {e}")),
            }
            match Command::new("ld").arg("-o").arg(&out).arg(&o_path).status() {
                Ok(s) if s.success() => {}
                Ok(s) => return fail(&format!("ld exited with {s}")),
                Err(e) => return fail(&format!("cannot run ld: {e}")),
            }
            if let Err(e) = set_executable(&out) {
                return fail(&e);
            }
            eprintln!("yana: wrote {} (via nasm+ld)", out.display());
            0
        }
    }
}

fn cmd_run(path: &Path, strict: bool) -> i32 {
    // §10: multi-module run goes through the ld path
    let has_uses = std::fs::read_to_string(path)
        .map(|src| {
            yana_parser::parse(&src)
                .file
                .map(|f| !yana_codegen::modules::use_refs(&f).is_empty())
                .unwrap_or(false)
        })
        .unwrap_or(false);

    let tmp = std::env::temp_dir().join(format!(
        "yana-run-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0)
    ));
    let exe_bytes: Vec<u8> = if has_uses {
        match build_multi(path, strict, &tmp, false) {
            Ok(Some(b)) => b,
            Ok(None) => return 1,
            Err(e) => return fail(&e),
        }
    } else {
        let Some(loaded) = load(path) else { return 2 };
        let Some(module) = resolve(&loaded, strict) else { return 1 };
        match yana_back_iced::link_exe(&module) {
            Ok(b) => b,
            Err(e) => return fail(&e.to_string()),
        }
    };
    if let Err(e) = std::fs::write(&tmp, &exe_bytes) {
        return fail(&format!("cannot write {}: {e}", tmp.display()));
    }
    if let Err(e) = set_executable(&tmp) {
        let _ = std::fs::remove_file(&tmp);
        return fail(&e);
    }
    let status = Command::new(&tmp)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status();
    let code = match status {
        Ok(s) => s.code().unwrap_or(-1),
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            return fail(&format!("cannot execute: {e}"));
        }
    };
    let _ = std::fs::remove_file(&tmp);
    code
}

/// §14 pass 4: `yana verify <file>` — resolve (without pass 3, D3) →
/// interval analysis + contract checks → render → exit = error count.
fn cmd_verify(path: &Path) -> i32 {
    let Some(loaded) = load(path) else { return 2 };
    let Some(module) = resolve_for_verify(&loaded) else { return 1 };
    let diags = yana_analysis::verify::verify(&module);
    let fatal = report::render(&loaded.name, &loaded.source, &diags, false);
    if fatal == 0 {
        let warns = diags.len();
        if warns == 0 {
            eprintln!("yana verify: {} — no issues", loaded.name);
        } else {
            eprintln!("yana verify: {} — {warns} warning(s), no errors", loaded.name);
        }
    }
    fatal as i32
}

fn cmd_expand(path: &Path, macros: bool) -> i32 {
    if macros {
        // §9: dump the post-expansion token stream (pass 0.5 output),
        // one token per line: `lo..hi\tTokenKind\ttext`, comments included.
        let Ok(source) = std::fs::read_to_string(path) else {
            return fail(&format!("cannot read {}", path.display()));
        };
        let parsed = yana_parser::parse(&source);
        let lexed = yana_lexer::lex(&source);
        let triples = yana_lexer::token_triples(&lexed);
        let expanded = yana_parser::macros::expand(triples);
        let mut comments = parsed.comments.clone();
        comments.sort_by_key(|(off, _)| *off);
        // Interleave tokens and comments by byte offset.
        let mut rows: Vec<(u32, bool, String)> = Vec::new();
        for (lo, tok, hi) in &expanded.triples {
            let (kind, text) = token_display(tok);
            rows.push((*lo as u32, false, format!("{}\t{}\t{}", kind, text, hi)));
        }
        for (off, c) in &comments {
            rows.push((*off, true, format!("comment\t{c}")));
        }
        rows.sort_by_key(|(off, is_comment, _)| (*off, !*is_comment));
        for (_, _, line) in rows {
            println!("{line}");
        }
        if parsed.has_errors() {
            report::render(
                &path.display().to_string(),
                &source,
                &parsed.diagnostics,
                false,
            );
            return 1;
        }
        return 0;
    }
    let Some(loaded) = load(path) else { return 2 };
    let Some(module) = resolve(&loaded, false) else { return 1 };
    print!("{}", yana_back_nasm::expand_ir(&module));
    0
}

/// Render a token for the `--macros` dump: (kind, text).
fn token_display(tok: &yana_lexer::Token) -> (String, String) {
    use yana_lexer::Token;
    match tok {
        Token::Ident(s) => ("ident".into(), s.clone()),
        Token::Num(s) => ("num".into(), s.clone()),
        Token::Str(s) => ("str".into(), s.clone()),
        Token::LabelRef(s) => ("lbl".into(), format!("'{s}")),
        Token::Char(c) => ("char".into(), format!("'{}'", *c as char)),
        Token::PairReg((hi, lo, ..)) => ("pair".into(), format!("{}:{}", hi.name(), lo.name())),
        other => (format!("{other:?}"), String::new()),
    }
}

fn cmd_nasm(path: &Path, out: Option<PathBuf>, assemble: bool) -> i32 {
    let Some(loaded) = load(path) else { return 2 };
    let Some(module) = resolve(&loaded, false) else { return 1 };
    let src = yana_back_nasm::emit(&module, &loaded.comments);
    match out {
        Some(o) => {
            if let Err(e) = std::fs::write(&o, &src) {
                return fail(&format!("cannot write {}: {e}", o.display()));
            }
            eprintln!("yana: wrote {}", o.display());
        }
        None => print!("{src}"),
    }
    if assemble {
        let asm = std::env::temp_dir().join(format!("yana-nasm-{}.asm", std::process::id()));
        let o = std::env::temp_dir().join(format!("yana-nasm-{}.o", std::process::id()));
        if let Err(e) = std::fs::write(&asm, &src) {
            return fail(&e.to_string());
        }
        match Command::new("nasm").args(["-f", "elf64", "-o"]).arg(&o).arg(&asm).status() {
            Ok(s) if s.success() => eprintln!("yana: nasm assembled ok → {}", o.display()),
            Ok(s) => return fail(&format!("nasm exited with {s}")),
            Err(e) => return fail(&format!("cannot run nasm: {e}")),
        }
    }
    0
}

/// Build the same module with both backends and compare disassembly (§13: the
/// NASM output doubles as a test oracle).
///
/// Displacement *values* legitimately differ (the two linkers place sections
/// at different addresses), so [`normalize`] strips numeric fields and compares
/// the instruction shapes.
fn cmd_oracle(path: &Path) -> i32 {
    let Some(loaded) = load(path) else { return 2 };
    let Some(module) = resolve(&loaded, false) else { return 1 };

    let enc = match yana_back_iced::assemble_text(&module, Some(yana_back_iced::Layout::default_x86_64())) {
        Ok(e) => e,
        Err(e) => return fail(&e.to_string()),
    };
    let iced_dis = yana_back_iced::disassemble(&enc.text, 0);

    let src = yana_back_nasm::emit(&module, &loaded.comments);
    let tmpdir = std::env::temp_dir().join(format!("yana-oracle-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&tmpdir);
    let asm = tmpdir.join("out.asm");
    let o = tmpdir.join("out.o");
    let bin = tmpdir.join("out.text");
    if let Err(e) = std::fs::write(&asm, &src) {
        return fail(&e.to_string());
    }
    for (prog, args) in [
        ("nasm", vec!["-f", "elf64", "-o", o.to_str().unwrap(), asm.to_str().unwrap()]),
        (
            "objcopy",
            vec!["-O", "binary", "--only-section=.text", o.to_str().unwrap(), bin.to_str().unwrap()],
        ),
    ] {
        match Command::new(prog).args(&args).status() {
            Ok(s) if s.success() => {}
            Ok(s) => return fail(&format!("{prog} exited with {s}")),
            Err(e) => return fail(&format!("cannot run {prog}: {e}")),
        }
    }
    let nasm_bytes = match std::fs::read(&bin) {
        Ok(b) => b,
        Err(e) => return fail(&format!("cannot read nasm .text: {e}")),
    };
    let nasm_dis = yana_back_iced::disassemble(&nasm_bytes, 0);

    let mut diffs = 0;
    let max = iced_dis.len().max(nasm_dis.len());
    for i in 0..max {
        let a = iced_dis.get(i).map(|s| normalize(s)).unwrap_or_else(|| "<none>".into());
        let b = nasm_dis.get(i).map(|s| normalize(s)).unwrap_or_else(|| "<none>".into());
        if a != b {
            diffs += 1;
            eprintln!("insn {i}:\n  iced: {a}\n  nasm: {b}");
        }
    }
    let _ = std::fs::remove_dir_all(&tmpdir);
    if diffs == 0 {
        println!("oracle: MATCH ({} instructions)", iced_dis.len());
        0
    } else {
        eprintln!("oracle: {diffs} differences");
        1
    }
}

/// Normalize a disassembly line for oracle comparison.
///
/// Differences that are legitimate and must NOT count as diffs:
/// - leading addresses;
/// - immediate/displacement numeric values (the two linkers place sections at
///   different addresses, and iced prints `1h` while NASM prints `0x1`);
/// - register *width* for the 64/32-bit GPR pair: NASM shortens `mov rbx,5`
///   to the 32-bit `mov ebx,5` (zero-extends — semantically identical), while
///   iced keeps the explicit 64-bit form the IR asked for. 8/16-bit registers
///   are NOT folded (movzx al,dl vs movzx eax,edx are different instructions).
/// - mnemonic suffixes NASM adds for disambiguation (`imul rax,rbx,rbx`).
fn normalize(line: &str) -> String {
    // 1. drop the leading address column
    let body = line.split_whitespace().skip(1).collect::<Vec<_>>().join(" ");

    // 2. blank out numeric fields: optional 0x prefix, then hex/digit run
    let mut out = String::new();
    let bytes: Vec<char> = body.chars().collect();
    let mut i = 0usize;
    while i < bytes.len() {
        let starts_num = bytes[i].is_ascii_digit()
            || (bytes[i] == '-' && i + 1 < bytes.len() && bytes[i + 1].is_ascii_digit());
        if starts_num {
            // consume optional sign
            if bytes[i] == '-' {
                i += 1;
            }
            // optional 0x
            if i + 1 < bytes.len() && bytes[i] == '0' && (bytes[i + 1] == 'x' || bytes[i + 1] == 'X') {
                i += 2;
            }
            while i < bytes.len() && (bytes[i].is_ascii_hexdigit() || bytes[i] == '_') {
                i += 1;
            }
            // trailing h suffix (iced style)
            if i < bytes.len() && bytes[i] == 'h' {
                i += 1;
            }
            out.push('#');
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    let s = out.to_ascii_lowercase();

    // 3. fold 64/32-bit GPR names to a width-neutral token
    let s = fold_gpr_widths(&s);

    // 4. tidy: split mnemonic/operands, drop a redundant 3rd imul operand
    let s = s.replace("\t", " ");
    let mut parts = s.split_whitespace().collect::<Vec<_>>();
    if let Some(mn) = parts.first() {
        if mn.starts_with("imul") && parts.len() >= 4 {
            // `imul dst, src, src` → `imul dst, src`
            parts.truncate(3);
        }
    }
    parts.join(" ")
}

/// Replace each 64/32-bit GPR name with `w64`/`w32`-neutral `<gprN>` so a
/// width difference between backends does not show as a diff. Leaves 8/16-bit
/// names (al/ah/ax/dl/...) and rip untouched.
fn fold_gpr_widths(s: &str) -> String {
    const FAMILIES: [(&str, &str, &str); 16] = [
        ("rax", "eax", "ax"), ("rcx", "ecx", "cx"), ("rdx", "edx", "dx"), ("rbx", "ebx", "bx"),
        ("rsp", "esp", "sp"), ("rbp", "ebp", "bp"), ("rsi", "esi", "si"), ("rdi", "edi", "di"),
        ("r8", "r8d", "r8w"), ("r9", "r9d", "r9w"), ("r10", "r10d", "r10w"), ("r11", "r11d", "r11w"),
        ("r12", "r12d", "r12w"), ("r13", "r13d", "r13w"), ("r14", "r14d", "r14w"), ("r15", "r15d", "r15w"),
    ];
    // longest-first so `r10d` is matched before `r10`
    let mut pats: Vec<(String, String)> = Vec::new();
    for (idx, (r64, r32, _r16)) in FAMILIES.iter().enumerate() {
        pats.push((r64.to_string(), format!("<g{idx}>")));
        pats.push((r32.to_string(), format!("<g{idx}>")));
    }
    pats.sort_by(|a, b| b.0.len().cmp(&a.0.len()));

    let mut out = String::with_capacity(s.len());
    let chars: Vec<char> = s.chars().collect();
    let mut i = 0usize;
    'outer: while i < chars.len() {
        // don't start a match in the middle of an identifier
        let prev_ok = i == 0 || !(chars[i - 1].is_ascii_alphanumeric() || chars[i - 1] == '_' || chars[i - 1] == '.');
        if prev_ok {
            for (pat, rep) in &pats {
                let pc: Vec<char> = pat.chars().collect();
                if i + pc.len() <= chars.len() && chars[i..i + pc.len()] == pc[..] {
                    let after = i + pc.len();
                    let next_ok = after >= chars.len()
                        || !(chars[after].is_ascii_alphanumeric() || chars[after] == '_');
                    if next_ok {
                        out.push_str(rep);
                        i = after;
                        continue 'outer;
                    }
                }
            }
        }
        out.push(chars[i]);
        i += 1;
    }
    out
}

fn default_out(path: &Path, backend: BackendArg, object: bool) -> PathBuf {
    let stem = path.file_stem().unwrap_or_default();
    let ext = match (backend, object) {
        (BackendArg::Iced, true) => "o",
        (BackendArg::Nasm, _) => "nasm-exe",
        _ => "exe",
    };
    path.with_file_name(stem).with_extension(ext)
}

fn set_executable(p: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(p).map_err(|e| e.to_string())?.permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(p, perms).map_err(|e| e.to_string())
}

fn fail(msg: &str) -> i32 {
    eprintln!("yana: {msg}");
    1
}
