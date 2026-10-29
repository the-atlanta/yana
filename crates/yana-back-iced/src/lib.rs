//! iced-x86 backend: IR → machine bytes → ELF.
//!
//! Two output modes (spec §13: native encoder first):
//! - [`encode::assemble_text`]: IR → encoded `.text` bytes with resolved
//!   labels/symbols (or recorded [`encode::PatchSite`]s in object mode).
//! - [`elf::link_exe`]: a static ET_EXEC ELF64 with program headers — runs
//!   without an external linker (the spike proved the format).
//! - [`elf::write_object`]: ET_REL `.o` for `ld`/oracle comparisons.
//!
//! The encoder never guesses: every [`yana_codegen::Insn`] maps to exactly one
//! `iced_x86::Instruction` (spec §0 — visible expansion).

pub mod encode;
pub mod elf;

pub use encode::{assemble_text, disassemble, section_bytes, AsmError, EncodedText, Layout, PatchSite, RelocKind};
pub use elf::{link_exe, write_object};
