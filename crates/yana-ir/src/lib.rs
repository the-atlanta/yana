//! YANA SSA-IR.
//!
//! The IR keeps the machine honest: YANA is assembly-first, so every value
//! either has a physical home already ([`Home::Pinned`], [`Home::Fixed`]) or
//! is a [`Home::Virtual`] value the register allocator will place later.
//! The module is produced from the resolved machine IR by [`lift_module`];
//! the textual dump lives in [`print`].

pub mod lift;
pub mod model;
pub mod print;

pub use lift::{lift_function, lift_module};
pub use model::*;
pub use print::{print_function, print_module, PrintOptions};
