#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers fail loudly"
)]

//! AVX2 code (`tests/fixtures/simd.c`, GCC -O3 -mavx2: 256-bit loads and
//! stores, lane-wise arithmetic, comparisons, blends, broadcasts,
//! reductions): every vectorised function decompiles to C holding 256-bit
//! vectors, agrees with its L1 from the differential's states, compiles
//! with GCC and Clang, and, compiled with -mavx2 and run beside its source
//! on the same inputs, gives what the source gives. No interface takes a
//! vector register an all-ones or zeroing idiom only seems to read
//! (`vpcmpeqd ymm3, ymm3, ymm3`): every function is called by the
//! source's prototype.

use std::fmt::Write as _;
use std::path::PathBuf;
use std::process::Command;
use std::{env, fs};

use binbun::Database;
use binbun::analysis::Seeds;
use binbun::decompile::Options;
use binbun::queries::verify::{self, Verdict};
use binbun_loader::Image;
use binbun_print::c::HEADER;

/// The vectorised functions of `simd.c`, with their prototypes there.
const FUNCTIONS: [(&str, &str); 10] = [
    ("sum_bytes", "uint32_t NAME(const uint8_t *, size_t)"),
    (
        "add_arrays",
        "void NAME(int32_t *, const int32_t *, const int32_t *, size_t)",
    ),
    (
        "count_byte",
        "size_t NAME(const uint8_t *, size_t, uint8_t)",
    ),
    (
        "max_bytes",
        "void NAME(uint8_t *, const uint8_t *, const uint8_t *, size_t)",
    ),
    (
        "xor_bytes",
        "void NAME(uint8_t *, const uint8_t *, size_t, uint8_t)",
    ),
    (
        "mix_words",
        "void NAME(uint32_t *, const uint32_t *, size_t)",
    ),
    ("max_int", "int32_t NAME(const int32_t *, size_t)"),
    ("ramp_words", "void NAME(uint64_t *, size_t, uint64_t)"),
    (
        "clamp_shorts",
        "void NAME(int16_t *, const int16_t *, size_t, int16_t)",
    ),
    (
        "widen_bytes",
        "void NAME(uint16_t *, const uint8_t *, size_t)",
    ),
];

/// `binbun_defs.h`'s 256-bit vector types.
const WIDE: [&str; 10] = [
    "u8x32", "i8x32", "u16x16", "i16x16", "u32x8", "i32x8", "u64x4", "i64x4", "u128x2", "f32x8",
];

fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures")
}

/// Calls every function, decompiled and from its source, on buffers of
/// many lengths and alignments, comparing results and every byte written
/// (and around it); prints the number of differences.
const HARNESS: &str = r#"
static uint8_t a8[1280], b8[1280], d8[1280], e8[1280];

static uint32_t next(uint32_t *state) {
    *state ^= *state << 13;
    *state ^= *state >> 17;
    *state ^= *state << 5;
    return *state;
}

static int check(const char *name, size_t n, int same) {
    if (!same)
        printf("%s differs at length %zu\n", name, n);
    return !same;
}

int main(void) {
    uint32_t state = 0x2545f491;
    int bad = 0;
    for (size_t n = 0; n < 150; n += n < 70 ? 1 : 7) {
        for (size_t at = 0; at < 3; at++) {
            for (size_t i = 0; i < sizeof a8; i++) {
                a8[i] = (uint8_t)next(&state);
                b8[i] = i % 5 == 0 ? a8[i] : (uint8_t)next(&state);
            }
            uint8_t key = a8[at];
            bad += check("sum_bytes", n, sum_bytes(a8 + at, n) == ref_sum_bytes(a8 + at, n));
            bad += check("count_byte", n,
                         count_byte(a8 + at, n, key) == ref_count_byte(a8 + at, n, key));
            bad += check("max_int", n,
                         max_int((const int32_t *)(a8 + 4 * at), n) ==
                             ref_max_int((const int32_t *)(a8 + 4 * at), n));
#define WRITES(name, call, ref_call)                                          \
    memset(d8, 0x5a, sizeof d8);                                              \
    memset(e8, 0x5a, sizeof e8);                                              \
    call;                                                                     \
    ref_call;                                                                 \
    bad += check(name, n, memcmp(d8, e8, sizeof d8) == 0);
            WRITES("add_arrays",
                   add_arrays((int32_t *)(d8 + 4 * at), (const int32_t *)a8,
                              (const int32_t *)b8, n),
                   ref_add_arrays((int32_t *)(e8 + 4 * at), (const int32_t *)a8,
                                  (const int32_t *)b8, n))
            WRITES("max_bytes", max_bytes(d8 + at, a8, b8 + at, n),
                   ref_max_bytes(e8 + at, a8, b8 + at, n))
            WRITES("xor_bytes", xor_bytes(d8 + at, a8, n, key),
                   ref_xor_bytes(e8 + at, a8, n, key))
            WRITES("mix_words", mix_words((uint32_t *)d8, (const uint32_t *)(a8 + at), n),
                   ref_mix_words((uint32_t *)e8, (const uint32_t *)(a8 + at), n))
            WRITES("ramp_words", ramp_words((uint64_t *)(d8 + at), n, key * 0x123456789ull),
                   ref_ramp_words((uint64_t *)(e8 + at), n, key * 0x123456789ull))
            WRITES("clamp_shorts",
                   clamp_shorts((int16_t *)d8, (const int16_t *)(a8 + 2 * at), n,
                                (int16_t)(key * 100)),
                   ref_clamp_shorts((int16_t *)e8, (const int16_t *)(a8 + 2 * at), n,
                                    (int16_t)(key * 100)))
            WRITES("widen_bytes", widen_bytes((uint16_t *)d8, a8 + at, n),
                   ref_widen_bytes((uint16_t *)e8, a8 + at, n))
        }
    }
    printf("%d differences\n", bad);
    return bad != 0;
}
"#;

#[test]
fn avx2_loops_decompile_verify_compile_and_run_as_their_source() {
    let path = fixtures().join("simd-avx2-x86_64.elf");
    let data = fs::read(&path).unwrap();
    let image = Image::parse(&data).unwrap();
    let database = Database::new(&image, Seeds::ALL).unwrap();
    let options = Options {
        style: Some("kr".to_owned()),
        ..Options::default()
    };
    let mut sources = Vec::new();
    for (name, _) in FUNCTIONS {
        let id = database.find_function(name).unwrap();
        let decompiled = database.decompile(id, &options).result;
        let c = decompiled
            .unwrap_or_else(|e| panic!("{name}: {e:?}"))
            .c
            .unwrap_or_else(|| panic!("{name}: no C"));
        let text = c.text;
        assert!(
            WIDE.iter().any(|ty| text.contains(ty)),
            "{name}: no 256-bit vector in\n{text}"
        );
        let verification = verify::verify(&database, id, &verify::Options::default());
        assert!(
            matches!(verification.verdict, Verdict::Agreed(_)),
            "{name}: {:?}",
            verification.verdict
        );
        assert!(
            !vector_parameter(&text, name),
            "{name}: a vector parameter in\n{text}"
        );
        sources.push((name, text));
    }
    run_against_source(&sources);
}

/// Whether the definition of `name` in `text` has a vector parameter (a
/// type of `binbun_defs.h`'s, `u64x4`).
fn vector_parameter(text: &str, name: &str) -> bool {
    let Some(start) = text.find(&format!("{name}(")) else {
        return false;
    };
    let parameters = &text[start..];
    let parameters = &parameters[..parameters.find(')').unwrap_or(parameters.len())];
    parameters
        .split(|c: char| !c.is_ascii_alphanumeric())
        .any(|word| {
            let mut parts = word.splitn(2, 'x');
            let (kind, lanes) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));
            kind.len() > 1
                && kind.starts_with(['u', 'i', 'f'])
                && kind[1..].bytes().all(|b| b.is_ascii_digit())
                && !lanes.is_empty()
                && lanes.bytes().all(|b| b.is_ascii_digit())
        })
}

/// Whether this processor runs AVX2 code.
#[cfg(target_arch = "x86_64")]
fn has_avx2() -> bool {
    std::arch::is_x86_feature_detected!("avx2")
}

/// Whether this processor runs AVX2 code: not an x86 one.
#[cfg(not(target_arch = "x86_64"))]
const fn has_avx2() -> bool {
    false
}

/// Each function's C compiled with GCC and Clang (`-mavx2`), linked with
/// `simd.c` (its functions renamed `ref_…`) and the harness, and run where
/// the processor has AVX2; on an x86-64 host only (`-mavx2` is x86's).
fn run_against_source(sources: &[(&str, String)]) {
    if !cfg!(target_arch = "x86_64") {
        eprintln!("skipped: compiling -mavx2 code needs an x86-64 host");
        return;
    }
    let dir = env::home_dir()
        .unwrap()
        .join(".cache/binbun-print-check")
        .join(format!("simd-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("binbun_defs.h"), HEADER).unwrap();
    let mut objects = Vec::new();
    for (name, text) in sources {
        let file = format!("{name}.c");
        fs::write(dir.join(&file), text).unwrap();
        objects.push(file);
    }
    let mut harness = String::from(
        "#include <stddef.h>\n#include <stdint.h>\n#include <stdio.h>\n#include <string.h>\n",
    );
    for (name, prototype) in FUNCTIONS {
        for prefix in ["", "ref_"] {
            let declared = prototype.replace("NAME", &format!("{prefix}{name}"));
            writeln!(harness, "{declared};").unwrap();
        }
    }
    harness.push_str(HARNESS);
    fs::write(dir.join("harness.c"), harness).unwrap();
    let renames: Vec<String> = FUNCTIONS
        .iter()
        .map(|(name, _)| format!("-D{name}=ref_{name}"))
        .chain(["-Dmain=ref_main".to_owned()])
        .collect();
    let source = fixtures().join("simd.c");
    let avx2 = has_avx2();
    let mut compiled = 0;
    for compiler in ["gcc", "clang"] {
        if Command::new(compiler).arg("--version").output().is_err() {
            continue;
        }
        let run = |args: &[&str]| {
            let output = Command::new(compiler)
                .current_dir(&dir)
                .args(args)
                .output()
                .unwrap();
            let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
            assert!(
                output.status.success() && !stderr.contains(" error"),
                "{compiler} {args:?}:\n{stderr}"
            );
        };
        let flags = [
            "-std=c11",
            "-O2",
            "-mavx2",
            "-fwrapv",
            "-fno-strict-aliasing",
            "-Wall",
        ];
        let mut link: Vec<String> = Vec::new();
        for file in &objects {
            let object = format!("{compiler}-{file}.o");
            let mut args: Vec<&str> = flags.to_vec();
            args.extend(["-c", file, "-o", &object]);
            run(&args);
            link.push(object);
        }
        let reference = format!("{compiler}-ref.o");
        let mut args: Vec<&str> = flags.to_vec();
        args.extend(renames.iter().map(String::as_str));
        let source = source.to_str().unwrap();
        args.extend(["-c", source, "-o", &reference]);
        run(&args);
        let program = format!("{compiler}-run");
        let mut args: Vec<&str> = flags.to_vec();
        args.push("harness.c");
        args.push(&reference);
        args.extend(link.iter().map(String::as_str));
        args.extend(["-o", &program]);
        run(&args);
        compiled += 1;
        if avx2 {
            let output = Command::new(dir.join(&program)).output().unwrap();
            let stdout = String::from_utf8_lossy(&output.stdout);
            assert!(output.status.success(), "{compiler}:\n{stdout}");
            assert!(stdout.ends_with("0 differences\n"), "{compiler}:\n{stdout}");
        }
    }
    if compiled == 0 {
        eprintln!("neither gcc nor clang is installed: not compiled");
    }
    if env::var_os("BINBUN_C_KEEP").is_none() {
        let _ = fs::remove_dir_all(&dir);
    }
}
