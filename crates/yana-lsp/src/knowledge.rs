//! Thin re-export of [`yana_knowledge`] for LSP-internal paths.
//!
//! The single source of completion/hover knowledge lives in the shared
//! `yana-knowledge` crate (M5 D1), so CLI tooling (`yana doc`), the LSP and
//! any future editor integration read the same tables.

pub use yana_knowledge::*;
