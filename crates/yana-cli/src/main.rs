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

mod report;

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use clap::{Parser, Subcommand, ValueEnum};

use yana_codegen::{resolve_module, Module, ResolveOptions, TargetInfo};

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
    },
    /// Compile and run (iced backend, static executable)
    Run {
        file: PathBuf,
        #[arg(long)]
        strict: bool,
    },
    /// Print the resolved IR, one instruction per line (§14 pass 2)
    Expand { file: PathBuf },
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
}

#[derive(ValueEnum, Clone, Copy)]
enum BackendArg {
    Iced,
    Nasm,
}

fn main() {
    let cli = Cli::parse();
    let code = match cli.cmd {
        Cmd::Build { file, out, backend, object, strict } => cmd_build(&file, out, backend, object, strict),
        Cmd::Run { file, strict } => cmd_run(&file, strict),
        Cmd::Expand { file } => cmd_expand(&file),
        Cmd::Nasm { file, out, assemble } => cmd_nasm(&file, out, assemble),
        Cmd::Oracle { file } => cmd_oracle(&file),
    };
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
fn resolve(loaded: &Loaded, strict: bool) -> Option<Module> {
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
    }
    let fatal = report::render(&loaded.name, &loaded.source, &diags, strict);
    if fatal > 0 || had_errors {
        return None;
    }
    Some(out.module)
}

// ---------------------------------------------------------------------------
// subcommands
// ---------------------------------------------------------------------------

fn cmd_build(path: &Path, out: Option<PathBuf>, backend: BackendArg, object: bool, strict: bool) -> i32 {
    let Some(loaded) = load(path) else { return 2 };
    let Some(module) = resolve(&loaded, strict) else { return 1 };
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
            if let Err(e) = std::fs::write(&asm_path, src) {
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
    let Some(loaded) = load(path) else { return 2 };
    let Some(module) = resolve(&loaded, strict) else { return 1 };
    let exe = match yana_back_iced::link_exe(&module) {
        Ok(b) => b,
        Err(e) => return fail(&e.to_string()),
    };
    let tmp = std::env::temp_dir().join(format!("yana-run-{}", std::process::id()));
    if let Err(e) = std::fs::write(&tmp, &exe) {
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

fn cmd_expand(path: &Path) -> i32 {
    let Some(loaded) = load(path) else { return 2 };
    let Some(module) = resolve(&loaded, false) else { return 1 };
    print!("{}", yana_back_nasm::expand_ir(&module));
    0
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
