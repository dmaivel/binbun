//! Links the C contenders that are not Rust crates, when available:
//!
//! - Intel XED when `XED_DIR` names a built XED checkout (one where
//!   `python3 mfile.py` has run, leaving the kit in `obj/wkit`);
//! - LLVM's MC disassembler, for x86-64 and AArch64, when `llvm-config` (or
//!   `$LLVM_CONFIG`) runs;
//! - Capstone 6.0.0-Alpha11, for AArch64, when `CAPSTONE6_DIR` names its
//!   source tree with `libcapstone.a` built in `build/` (for example
//!   `cmake -B build -DCMAKE_BUILD_TYPE=Release
//!   -DCAPSTONE_ARCHITECTURE_DEFAULT=OFF -DCAPSTONE_AARCH64_SUPPORT=ON
//!   -DCMAKE_POSITION_INDEPENDENT_CODE=ON && cmake --build build --target
//!   capstone_static`). It needs GNU `ld`, `objcopy` and `ar`.
//!
//! Each missing one is left out of the comparison with a build warning.

use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    println!("cargo::rustc-check-cfg=cfg(xed)");
    println!("cargo::rustc-check-cfg=cfg(llvm)");
    println!("cargo::rustc-check-cfg=cfg(capstone6)");
    xed();
    llvm();
    capstone6();
}

fn xed() {
    println!("cargo::rerun-if-env-changed=XED_DIR");
    println!("cargo::rerun-if-changed=src/xed.c");
    let Some(xed) = std::env::var_os("XED_DIR") else {
        println!("cargo::warning=XED_DIR is unset; XED is not benchmarked");
        return;
    };
    let kit = PathBuf::from(xed).join("obj/wkit");
    cc::Build::new()
        .file("src/xed.c")
        .include(kit.join("include"))
        .opt_level(3)
        .compile("binbun_bench_xed");
    println!(
        "cargo::rustc-link-search=native={}",
        kit.join("lib").display()
    );
    println!("cargo::rustc-link-lib=static=xed");
    println!("cargo::rustc-cfg=xed");
}

fn llvm() {
    println!("cargo::rerun-if-env-changed=LLVM_CONFIG");
    println!("cargo::rerun-if-changed=src/llvm.c");
    println!("cargo::rerun-if-changed=src/llvm_a64.c");
    let config = std::env::var("LLVM_CONFIG").unwrap_or_else(|_| "llvm-config".to_owned());
    let query = |arg: &str| -> Option<String> {
        let output = Command::new(&config).arg(arg).output().ok()?;
        output
            .status
            .success()
            .then(|| String::from_utf8_lossy(&output.stdout).trim().to_owned())
    };
    let (Some(version), Some(include), Some(lib), Some(libs)) = (
        query("--version"),
        query("--includedir"),
        query("--libdir"),
        query("--libs"),
    ) else {
        println!("cargo::warning=llvm-config not found; LLVM is not benchmarked");
        return;
    };
    cc::Build::new()
        .file("src/llvm.c")
        .file("src/llvm_a64.c")
        .include(include)
        .opt_level(3)
        .compile("binbun_bench_llvm");
    println!("cargo::rustc-link-search=native={lib}");
    for name in libs
        .split_whitespace()
        .filter_map(|flag| flag.strip_prefix("-l"))
    {
        println!("cargo::rustc-link-lib=dylib={name}");
    }
    println!("cargo::rustc-env=BINBUN_BENCH_LLVM_NAME=LLVM MC {version}");
    println!("cargo::rustc-cfg=llvm");
}

fn capstone6() {
    println!("cargo::rerun-if-env-changed=CAPSTONE6_DIR");
    println!("cargo::rerun-if-changed=src/capstone6.c");
    let Some(dir) = std::env::var_os("CAPSTONE6_DIR") else {
        println!("cargo::warning=CAPSTONE6_DIR is unset; Capstone 6 is not benchmarked");
        return;
    };
    let dir = PathBuf::from(dir);
    let library = dir.join("build/libcapstone.a");
    println!("cargo::rerun-if-changed={}", library.display());
    let out = PathBuf::from(std::env::var_os("OUT_DIR").expect("set by cargo"));
    let objects = cc::Build::new()
        .file("src/capstone6.c")
        .include(dir.join("include"))
        .opt_level(3)
        .compile_intermediates();
    // The `capstone` crate links Capstone 5, whose functions have the same
    // names. So link the sweep and the parts of Capstone 6 it uses into one
    // object, and make every symbol in it but the sweep's local.
    let linked = out.join("capstone6.o");
    run(Command::new("ld")
        .arg("-r")
        .arg("-o")
        .arg(&linked)
        .args(&objects)
        .arg(&library));
    run(Command::new("objcopy")
        .arg("--keep-global-symbol=binbun_bench_cs6_init")
        .arg("--keep-global-symbol=binbun_bench_cs6_sweep")
        .arg(&linked));
    let archive = out.join("libbinbun_bench_cs6.a");
    // `ar` adds to an existing archive; start afresh.
    if archive.exists() {
        std::fs::remove_file(&archive).expect("removes the old archive");
    }
    run(Command::new("ar").arg("crs").arg(&archive).arg(&linked));
    println!("cargo::rustc-link-search=native={}", out.display());
    println!("cargo::rustc-link-lib=static=binbun_bench_cs6");
    println!("cargo::rustc-cfg=capstone6");
}

/// Runs `command`, panicking (failing the build) if it does not succeed.
fn run(command: &mut Command) {
    let status = command
        .status()
        .unwrap_or_else(|error| panic!("{}: {error}", Path::new(command.get_program()).display()));
    assert!(status.success(), "{command:?} failed: {status}");
}
