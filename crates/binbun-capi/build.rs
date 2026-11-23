//! Exports the header directory to crates that depend on this one (and so
//! link `libbinbun`): their build scripts read it as `DEP_BINBUN_INCLUDE`
//! and compile C or C++ against the headers that match the library.

fn main() {
    println!("cargo::rerun-if-changed=build.rs");
    let manifest = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_default();
    println!("cargo::metadata=include={manifest}/include");
}
