//! Target description: what `usize` is, which syscalls exist, and how `#[entry]`
//! maps to an OS symbol name (§13).

use yana_ast::reg::Reg;
use yana_ast::{FnSig};
use yana_ast::place::SectionKind;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arch {
    X86_64,
    /// AArch64 target facts (§13 🟡). No backend exists yet; the description
    /// drives diagnostics such as `unsupported-atomic-target` (§15, 30.10).
    Aarch64,
    /// Xtensa LX7 (ESP32-S3) target facts (§13 🟡). No backend exists yet;
    /// `usize` is 32-bit and the windowed ABI uses `entry`/`retw` (§15).
    Xtensa,
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

    /// AArch64/Linux target facts (§13 🟡). No backend exists yet — used by
    /// the `unsupported-atomic-target` diagnostic test (§15, 30.10).
    pub fn aarch64_linux() -> Self {
        TargetInfo { arch: Arch::Aarch64, os: Os::Linux }
    }

    /// Xtensa LX7 / ESP32-S3 target facts (§13 🟡, §15): 32-bit `usize`,
    /// windowed ABI (`entry`/`retw`, args in `a2`–`a7`). No backend yet.
    pub fn xtensa_esp32s3() -> Self {
        TargetInfo { arch: Arch::Xtensa, os: Os::Linux }
    }

    /// The canonical LLVM-style triple for this target.
    pub fn triple(&self) -> &'static str {
        match (self.arch, self.os) {
            (Arch::X86_64, Os::Linux) => "x86_64-unknown-linux-gnu",
            (Arch::X86_64, Os::Macos) => "x86_64-apple-darwin",
            (Arch::Aarch64, Os::Linux) => "aarch64-unknown-linux-gnu",
            (Arch::Xtensa, Os::Linux) => "xtensa-esp32s3-elf",
            // macOS is only wired for x86-64 today; keep the triple stable
            // for the other architectures until their backends exist.
            (Arch::Aarch64, Os::Macos) => "aarch64-apple-darwin",
            (Arch::Xtensa, Os::Macos) => "xtensa-esp32s3-elf",
        }
    }

    /// rsp modulo the natural stack alignment at function entry, BEFORE any
    /// of the function's own pushes. SysV x86-64: the `call` pushed the
    /// return address, so rsp ≡ 8 (mod 16) at entry. AArch64 keeps sp
    /// 16-aligned at all times and `bl` doesn't touch the stack → 0.
    pub fn stack_entry_offset(&self) -> i32 {
        match self.arch {
            Arch::X86_64 => 8,
            Arch::Aarch64 | Arch::Xtensa => 0,
        }
    }

    /// `usize`/`isize` width in bits for this target.
    pub fn usize_bits(&self) -> u32 {
        match self.arch {
            Arch::X86_64 => 64,
            Arch::Aarch64 => 64,
            Arch::Xtensa => 32,
        }
    }

    /// The symbol name the `#[entry]` function exports.
    pub fn entry_symbol(&self) -> &'static str {
        match (self.arch, self.os) {
            (Arch::X86_64, Os::Linux) => "_start",
            (Arch::X86_64, Os::Macos) => "_main",
            (Arch::Aarch64, Os::Linux) => "_start",
            (Arch::Aarch64, Os::Macos) => "_main",
            (Arch::Xtensa, _) => "_start",
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
            (Arch::Aarch64, Os::Linux) => "elf64",
            (Arch::Aarch64, Os::Macos) => "macho64",
            (Arch::Xtensa, _) => "elf32",
        }
    }

    /// Sections present in an object file for this target, in link order.
    pub fn sections(&self) -> &'static [SectionKind] {
        match (self.arch, self.os) {
            (Arch::X86_64, Os::Linux)
            | (Arch::X86_64, Os::Macos)
            | (Arch::Aarch64, _)
            | (Arch::Xtensa, _) => &[
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
    /// `debug { ... }` blocks are lowered only when this is true (§4.6).
    /// `yana build --release` clears it.
    pub debug: bool,
    /// Declarations imported via `use path::name;` (§10) — seeded into the
    /// symbol tables before the file's own items are collected. The module
    /// loader (CLI) extracts these from the referenced module files.
    pub imports: Vec<ImportedDecl>,
}

impl Default for ResolveOptions {
    fn default() -> Self {
        ResolveOptions { strict: false, const_steps: 1_000_000, debug: true, imports: Vec::new() }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xtensa_facts_are_32_bit_and_windowed() {
        let t = TargetInfo::xtensa_esp32s3();
        assert_eq!(t.arch, Arch::Xtensa);
        assert_eq!(t.usize_bits(), 32);
        assert_eq!(t.stack_entry_offset(), 0);
        assert_eq!(t.object_format(), "elf32");
        assert_eq!(t.entry_symbol(), "_start");
    }

    #[test]
    fn macos_prefixes_symbols_and_uses_main() {
        let t = TargetInfo { arch: Arch::X86_64, os: Os::Macos };
        assert_eq!(t.symbol_prefix(), "_");
        assert_eq!(t.entry_symbol(), "_main");
        assert_eq!(t.object_format(), "macho64");
    }
}
