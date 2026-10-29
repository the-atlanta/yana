fn main() {
    println!("cargo:rerun-if-changed=src/yana.lalrpop");
    lalrpop::process_root().unwrap();
}
