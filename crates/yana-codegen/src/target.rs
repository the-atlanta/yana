//! Target description: what `usize` is, which syscalls exist, and how `#[entry]`
//! maps to an OS symbol name (§13).

use yana_ast::reg::Reg;
use yana_ast::{FnSig};
use yana_ast::place::SectionKind;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arch {
    X86_64,
    // AArch64 / Xtensa come later (§13 🟡)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Os {
    Linux,
    Macos,
}

#[derive(Debug, Clone)]
pub struct TargetInfo {
    pub arch: Arch,
    pub os: Os,
}

impl Default for TargetInfo {
    fn default() -> Self {
        TargetInfo::linux_x86_64()
    }
}

impl TargetInfo {
    pub fn linux_x86_64() -> Self {
        TargetInfo { arch: Arch::X86_64, os: Os::Linux }
    }

    /// rsp modulo the natural stack alignment at function entry, BEFORE any
    /// of the function's own pushes. SysV x86-64: the `call` pushed the
    /// return address, so rsp ≡ 8 (mod 16) at entry. AArch64 keeps sp
    /// 16-aligned at all times and `bl` doesn't touch the stack → 0.
    pub fn stack_entry_offset(&self) -> i32 {
        match self.arch {
            Arch::X86_64 => 8,
        }
    }

    /// `usize`/`isize` width in bits for this target.
    pub fn usize_bits(&self) -> u32 {
        match self.arch {
            Arch::X86_64 => 64,
        }
    }

    /// The symbol name the `#[entry]` function exports.
    pub fn entry_symbol(&self) -> &'static str {
        match (self.arch, self.os) {
            (Arch::X86_64, Os::Linux) => "_start",
            (Arch::X86_64, Os::Macos) => "_main",
        }
    }

    /// Do exported symbols get a leading underscore? (macOS yes, Linux no)
    pub fn symbol_prefix(&self) -> &'static str {
        match self.os {
            Os::Linux => "",
            Os::Macos => "_",
        }
    }

    /// Linker default: static ELF for Linux x86-64.
    pub fn object_format(&self) -> &'static str {
        match (self.arch, self.os) {
            (Arch::X86_64, Os::Linux) => "elf64",
            (Arch::X86_64, Os::Macos) => "macho64",
        }
    }

    /// Sections present in an object file for this target, in link order.
    pub fn sections(&self) -> &'static [SectionKind] {
        match (self.arch, self.os) {
            (Arch::X86_64, Os::Linux) => &[
                SectionKind::Text,
                SectionKind::RoData,
                SectionKind::Data,
                SectionKind::Bss,
            ],
            (Arch::X86_64, Os::Macos) => &[
                SectionKind::Text,
                SectionKind::RoData,
                SectionKind::Data,
                SectionKind::Bss,
            ],
        }
    }
}

/// Resolver options (flags the CLI passes through).
#[derive(Debug, Clone)]
pub struct ResolveOptions {
    /// `--strict`: `contract` warnings become errors (§11).
    pub strict: bool,
    /// Step budget for const evaluation (§8).
    pub const_steps: u64,
    /// Declarations imported via `use path::name;` (§10) — seeded into the
    /// symbol tables before the file's own items are collected. The module
    /// loader (CLI) extracts these from the referenced module files.
    pub imports: Vec<ImportedDecl>,
}

impl Default for ResolveOptions {
    fn default() -> Self {
        ResolveOptions { strict: false, const_steps: 1_000_000, imports: Vec::new() }
    }
}

/// One declaration extracted from a used module (§10).
///
/// Export visibility (`#[global]`) was already checked by the loader, so every
/// entry here is importable. No name mangling anywhere (§10): the symbol name
/// is the item name verbatim.
#[derive(Debug, Clone)]
pub enum ImportedDecl {
    /// A function (or extern fn) — imported as an undefined, linkable symbol.
    /// The full signature is kept so call-site lowering (movs into ABI places,
    /// results, contract) works exactly as for a local extern.
    Fn { sig: FnSig, clobbers: Vec<Reg> },
    /// A build-time constant — its value, usable in const expressions.
    Const { name: String, value: i128 },
    /// Static data — an undefined symbol reference usable in places/`lea`
    /// (Pc32 relocation); `size` feeds `name.len`.
    Static { name: String, size: u64 },
}
