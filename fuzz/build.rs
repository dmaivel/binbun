//! With feature `xed` (the differential target), links
//! `tools/xed-oracle/oracle.c` (as a library) and Intel XED from `XED_DIR`,
//! a built XED checkout (one where `python3 mfile.py` has run, leaving the
//! kit in `obj/wkit`). The C API target needs neither.

fn main() {
    #[cfg(feature = "xed")]
    xed();
}

#[cfg(feature = "xed")]
fn xed() {
    use std::path::PathBuf;

    println!("cargo::rerun-if-env-changed=XED_DIR");
    println!("cargo::rerun-if-changed=../tools/xed-oracle/oracle.c");
    let xed = std::env::var_os("XED_DIR").expect("XED_DIR names a built XED checkout");
    let kit = PathBuf::from(xed).join("obj/wkit");
    cc::Build::new()
        .file("../tools/xed-oracle/oracle.c")
        .define("ORACLE_LIBRARY", None)
        .include(kit.join("include"))
        .opt_level(2)
        .compile("binbun_xed_oracle");
    println!(
        "cargo::rustc-link-search=native={}",
        kit.join("lib").display()
    );
    println!("cargo::rustc-link-lib=static=xed");
}
