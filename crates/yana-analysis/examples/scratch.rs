// scratch: exercise contract checks
use yana_analysis::verify::verify;
use yana_codegen::{resolve_module, ResolveOptions, TargetInfo};

fn main() {
    let src = std::env::args().nth(1).unwrap();
    let source = std::fs::read_to_string(&src).unwrap();
    let parsed = yana_parser::parse(&source);
    if parsed.has_errors() {
        for d in &parsed.diagnostics {
            println!("PARSE {}: {}", d.kind, d.message);
        }
        return;
    }
    let out = resolve_module(
        parsed.file.as_ref().unwrap(),
        &TargetInfo::linux_x86_64(),
        &ResolveOptions::default(),
    );
    for d in &out.diagnostics {
        println!("RESOLVE {:?} {}: {}", d.level, d.kind, d.message);
    }
    let diags = verify(&out.module);
    for d in &diags {
        println!("VERIFY {:?} {}: {}", d.level, d.kind, d.message);
    }
    println!("errors: {}", yana_analysis::verify::verify_errors(&diags));
}
