//! YANA codegen: AST → IR, the single source of truth both backends consume.
//!
//! Design (spec §14):
//! - Pass 1 collects declarations (statics, consts, fns, externs).
//! - Pass 2 lowers each function body to [`Insn`]s — one statement, one
//!   instruction, explicit symbolic operands (no relocations yet).
//! - The instruction table ([`insn`]) declares reads/writes/flags per opcode:
//!   one source of truth for the encoder and future analyses.
//! - Backends lower [`Insn`] to bytes (iced + ELF writer) or text (NASM).

pub mod ir;
pub mod insn;
pub mod consteval;
pub mod modules;
pub mod target;
pub mod resolve;

pub use ir::{
    AtomicOp, DataItem, Displacement, FnBody, Insn, Jcc, LabelDef, MemOp, MemOrder, Module,
    Operand, SectionData, Symbol, SymbolKind, WideOp,
};
pub use target::{Arch, ImportedDecl, Os, ResolveOptions, TargetInfo};
pub use resolve::resolve_module;
