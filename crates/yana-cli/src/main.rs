//! `yana` — the CLI binary (§13/§14 driver).
//!
//! The real implementation lives in the `yana_cli` library crate so
//! integration tests can drive it in-process.

fn main() {
    let code = yana_cli::run(std::env::args());
    std::process::exit(code);
}
