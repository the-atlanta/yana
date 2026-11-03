//! Shared symbol extraction (§14: one source of truth).
//!
//! The implementation lives in the `yana-symbols` crate so the CLI, DAP and
//! editor tooling all see the same symbols. This module is a thin re-export.

pub use yana_symbols::*;
