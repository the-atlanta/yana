//! AArch64 backend (F7) — scaffold.
//!
//! The crate exists so the workspace and the target/feature table stay stable
//! while SSA-IR work lands first. Instruction selection, the ELF64 `EM_AARCH64`
//! writer and the `qemu-aarch64` test path will live here.

/// Target triple this backend will emit for.
pub const TRIPLE: &str = "aarch64-unknown-linux-gnu";
