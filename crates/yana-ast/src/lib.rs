//! YANA — core AST types, spans, and the instruction/place model.
//!
//! This crate is dependency-free: it defines the shape of the language that the
//! lexer, parser, codegen and both backends all speak. Every node carries a
//! [`Span`] so diagnostics can point at source precisely (see §11 of the spec).

pub mod span;
pub mod reg;
pub mod ty;
pub mod place;
pub mod ast;
pub mod diag;

pub use span::{Span, Sp};
pub use reg::{Reg, GprBase, RegSize};
pub use ty::Ty;
pub use place::{Place, MemAddr, SectionKind};
pub use ast::*;
pub use diag::{Diagnostic, DiagLevel, DiagCode};
