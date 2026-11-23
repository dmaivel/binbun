#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers fail loudly"
)]

//! `binbun_defs.h` compiles cleanly (`-Werror`) with GCC and Clang, and for
//! AArch64, and each helper gives L0's values, edges included; the thread
//! pointer's spellings read and write what they name.

mod common;

use common::{Scratch, compilers};

/// Each helper against the value L0 gives.
const CHECKS: &str = r#"
#include "binbun_defs.h"
#include <stdio.h>

static int failures;

#define CHECK(expr, want)                                                     \
    do {                                                                      \
        unsigned long long got_ = (unsigned long long)(expr);                 \
        unsigned long long want_ = (unsigned long long)(want);                \
        if (got_ != want_) {                                                  \
            printf("FAIL %s: %llx, not %llx\n", #expr, got_, want_);          \
            failures++;                                                       \
        }                                                                     \
    } while (0)

int main(void) {
    CHECK(popcount((uint8_t)0xff), 8);
    CHECK(popcount((binbun_u128)-1), 128);
    CHECK(clz((uint32_t)0), 32);
    CHECK(clz((uint32_t)1), 31);
    CHECK(clz((uint8_t)0x10), 3);
    CHECK(clz((binbun_u128)1), 127);
    CHECK(ctz((uint16_t)0), 16);
    CHECK(ctz((uint64_t)8), 3);
    CHECK(ctz((binbun_u128)1 << 100), 100);
    CHECK(clz_n((uint64_t)1, 24), 23);
    CHECK(clz_n((uint64_t)0, 24), 24);
    CHECK(ctz_n((uint64_t)0, 24), 24);
    CHECK(ctz_n((uint64_t)4, 24), 2);
    CHECK(even_parity8(3), 1);
    CHECK(even_parity8(1), 0);
    CHECK(even_parity8(0x100), 1);
    CHECK(bswap((uint16_t)0x1122), 0x2211);
    CHECK(bswap((uint32_t)0x11223344), 0x44332211);
    CHECK(bswap((uint64_t)0x1122334455667788), 0x8877665544332211);
    CHECK((uint64_t)(bswap((binbun_u128)1) >> 64), 0x0100000000000000);

    CHECK(shl((uint32_t)1, (uint32_t)31), 0x80000000);
    CHECK(shl((uint32_t)1, (uint32_t)32), 0);
    CHECK(shl((uint8_t)1, (uint8_t)200), 0);
    CHECK(lshr((uint64_t)-1, (uint64_t)63), 1);
    CHECK(lshr((uint64_t)-1, (uint64_t)64), 0);
    CHECK(ashr((int32_t)-8, 1u), -4);
    CHECK(ashr((int32_t)-8, 40u), -1);
    CHECK(ashr((int16_t)8, (uint16_t)16), 0);
    CHECK(rotl((uint8_t)0x81, (uint8_t)1), 0x03);
    CHECK(rotl((uint8_t)0x81, (uint8_t)9), 0x03);
    CHECK(rotr((uint32_t)1, (uint32_t)33), 0x80000000);
    CHECK(rotr((uint64_t)1, (uint64_t)0), 1);
    CHECK(rotl_n((uint64_t)0x10, 1, 5), 0x01);
    CHECK(rotr_n((uint64_t)1, 1, 5), 0x10);
    CHECK(rotr_n((uint64_t)1, 5, 5), 1);
    CHECK(sext_n((uint64_t)0x10, 5), -16);
    CHECK(sext_n((uint64_t)0x0f, 5), 15);
    CHECK(sext_n((uint64_t)0x30, 5), -16);
    CHECK(sext_n((uint64_t)1, 1), -1);

    CHECK(low8(0x123456789a), 0x9a);
    CHECK(low16(0x123456789a), 0x789a);
    CHECK(low32(0x123456789a), 0x3456789a);
    CHECK(high8(0x1234), 0x12);

    CHECK(add_carry((uint8_t)0xff, 1, 0), 1);
    CHECK(add_carry((uint8_t)0xfe, 1, 1), 1);
    CHECK(add_carry((uint8_t)0xfe, 1, 0), 0);
    CHECK(add_carry((uint64_t)-1, 0, 1), 1);
    CHECK(add_overflow((uint8_t)0x7f, 1, 0), 1);
    CHECK(add_overflow((uint8_t)0x7f, 0, 1), 1);
    CHECK(add_overflow((uint8_t)0x80, 0xff, 0), 1);
    CHECK(add_overflow((uint8_t)0x10, 0x10, 0), 0);
    CHECK(sub_borrow((uint32_t)0, 0, 1), 1);
    CHECK(sub_borrow((uint32_t)1, 0, 1), 0);
    CHECK(sub_borrow((uint32_t)0, (uint32_t)-1, 1), 1);
    CHECK(sub_overflow((uint8_t)0x80, 1, 0), 1);
    CHECK(sub_overflow((uint8_t)0x7f, 0xff, 0), 1);
    CHECK(sub_overflow((uint8_t)5, 3, 1), 0);
    CHECK(nibble_carry((uint8_t)0x0f, 1, 0x10), 1);
    CHECK(nibble_carry((uint8_t)0x01, 1, 0x02), 0);

    CHECK(umulh((uint64_t)-1, (uint64_t)-1), 0xfffffffffffffffe);
    CHECK(umulh((uint8_t)0xff, (uint8_t)0xff), 0xfe);
    CHECK(smulh((int32_t)-1, 1), -1);
    CHECK(smulh((int64_t)INT64_MIN, (int64_t)INT64_MIN), 0x4000000000000000);
    CHECK(smulh((int8_t)-128, (int8_t)-128), 0x40);

    CHECK(udiv((uint32_t)7, 0), 0xffffffff);
    CHECK(udiv((uint32_t)7, 2), 3);
    CHECK(urem((uint32_t)7, 0), 7);
    CHECK(urem((uint8_t)7, (uint8_t)4), 3);
    CHECK(sdiv((int32_t)INT32_MIN, -1), INT32_MIN);
    CHECK(sdiv((int16_t)5, 0), -1);
    CHECK(sdiv((int8_t)-7, 2), -3);
    CHECK(srem((int32_t)INT32_MIN, -1), 0);
    CHECK(srem((int8_t)-7, 2), -1);
    CHECK(srem((int64_t)9, 0), 9);

    CHECK(f32_bits(as_f32(0x3f800000)), 0x3f800000);
    CHECK(f64_bits(as_f64(0x3ff0000000000000)), 0x3ff0000000000000);
    CHECK(fcmp(1.0, 2.0), 1);
    CHECK(fcmp(2.0f, 2.0f), 2);
    CHECK(fcmp(3.0, 2.0), 4);
    CHECK(fcmp(__builtin_nan(""), 1.0), 8);
    CHECK(f64_bits(binbun_round(2.5, 0)), f64_bits(2.0));
    CHECK(f64_bits(binbun_round(-2.5, 1)), f64_bits(-3.0));
    CHECK(f64_bits(binbun_round(2.1, 2)), f64_bits(3.0));
    CHECK(f32_bits(binbun_roundf(-1.5f, 3)), f32_bits(-1.0f));
    CHECK(float_to_sint(-2.5, 32, 0), -2);
    CHECK(float_to_sint(-2.5, 32, 1), -3);
    CHECK(float_to_sint(2.5, 32, 2), 3);
    CHECK(float_to_sint(2.7, 32, 3), 2);
    CHECK(float_to_sint(3e9, 32, 0), 0);
    CHECK(float_to_sint(__builtin_nan(""), 64, 0), 0);
    CHECK(float_to_uint(3e9, 32, 0), 3000000000u);
    CHECK(float_to_uint(-1.0, 32, 0), 0);
    CHECK(float_to_uint(5e9, 32, 0), 0);

    uint32_t cell = 5;
    binbun_atomic_store32(&cell, 9);
    CHECK(binbun_atomic_load32(&cell), 9);
    uint8_t byte = 1;
    binbun_atomic_store8(&byte, 0xff);
    CHECK(binbun_atomic_load8(&byte), 0xff);
    /* Each update gives what it read and leaves what it made. */
    CHECK(binbun_atomic_exchange32(&cell, 5), 9);
    CHECK(binbun_atomic_fetch_add32(&cell, 0xfffffffe), 5);
    CHECK(binbun_atomic_fetch_sub32(&cell, 4), 3);
    CHECK(binbun_atomic_fetch_or32(&cell, 0xf0), 0xffffffff);
    CHECK(binbun_atomic_fetch_and32(&cell, 0x3c), 0xffffffff);
    CHECK(binbun_atomic_fetch_xor32(&cell, 0xc), 0x3c);
    CHECK(binbun_atomic_compare_exchange32(&cell, 0x31, 7), 0x30);
    CHECK(cell, 0x30);
    CHECK(binbun_atomic_compare_exchange32(&cell, 0x30, 7), 0x30);
    CHECK(cell, 7);
    uint64_t wide = 1;
    CHECK(binbun_atomic_fetch_add64(&wide, 0xffffffffffffffff), 1);
    CHECK(binbun_atomic_exchange64(&wide, 2), 0);
    CHECK(binbun_atomic_fetch_or8(&byte, 0), 0xff);
#if defined(__x86_64__) && defined(__linux__)
    /* getpid, twice: the same process. */
    CHECK(binbun_syscall(39), binbun_syscall(39));
#endif
    printf("%s\n", failures ? "failed" : "ok");
    return failures != 0;
}
"#;

/// The escape and trap hooks.
const HOOKS: &str = r#"
#define BINBUN_HOOKS
#include "binbun_defs.h"
#include <stdio.h>
#include <stdlib.h>

uint64_t binbun_hook_escape(int kind, size_t count, const uint64_t *operands) {
    uint64_t sum = 0;
    for (size_t i = 0; i < count; i++)
        sum += operands[i];
    binbun_results[1] = sum;
    return (uint64_t)kind * 1000 + count * 100 + sum;
}

_Noreturn void binbun_hook_trap(int kind) {
    printf("trap %d\n", kind);
    exit(0);
}

int main(void) {
    printf("%llu\n", (unsigned long long)binbun_syscall(1, 2, 3));
    printf("%llu\n", (unsigned long long)binbun_result(1));
    printf("%llu\n", (unsigned long long)binbun_stack_trick());
    printf("%llu\n", (unsigned long long)binbun_non_standard_call(7));
    binbun_trap(BINBUN_TRAP_DIVIDE);
}
"#;

#[test]
fn header_compiles_cleanly_and_its_helpers_give_l0s_values() {
    let compilers = compilers();
    if compilers.is_empty() {
        eprintln!("skipped: neither gcc nor clang found");
        return;
    }
    let scratch = Scratch::new("header");
    scratch.write("checks.c", CHECKS);
    scratch.write("hooks.c", HOOKS);
    for &compiler in &compilers {
        for opt in ["-O0", "-O2"] {
            scratch
                .compile(
                    compiler,
                    &["-Werror", opt, "-o", "checks"],
                    &["checks.c", "-lm"],
                )
                .unwrap_or_else(|e| panic!("{compiler} {opt}: {e}"));
            assert_eq!(scratch.run("checks"), "ok\n", "{compiler} {opt}");
            scratch
                .compile(
                    compiler,
                    &["-Werror", opt, "-o", "hooks"],
                    &["hooks.c", "-lm"],
                )
                .unwrap_or_else(|e| panic!("{compiler} {opt}: {e}"));
            assert_eq!(
                scratch.run("hooks"),
                "5306\n6\n4000\n3107\ntrap 0\n",
                "{compiler} {opt}"
            );
        }
    }
    if compilers.contains(&"clang") {
        // The header alone, for AArch64 (the system call's other branch,
        // and the thread pointers: `tpidr_el0`, Windows' `x18`),
        // assembled.
        scratch.write(
            "alone.c",
            "#include \"binbun_defs.h\"\nint binbun_used(void) { return (int)binbun_syscall(172) + \\
             (__builtin_thread_pointer() != 0) + (NtCurrentTeb() != 0) + (KeGetPcr() != 0); }\n",
        );
        match scratch.compile(
            "clang",
            &[
                "--target=aarch64-linux-gnu",
                "-Werror",
                "-c",
                "-o",
                "alone.o",
            ],
            &["alone.c"],
        ) {
            Ok(_) => {}
            Err(e) if e.contains("file not found") => {
                eprintln!("skipped AArch64: no headers ({e})");
            }
            Err(e) => panic!("clang for AArch64: {e}"),
        }
    }
}

/// The vector types and helpers: sizes and layout (alignment 1, any
/// offset in a struct), the lane-wise shifts at and past the lane width
/// (0, or the sign: L0's), masks packed and spread again, blends, splats,
/// comparisons of the compilers' own result types passed to the helpers,
/// halves as 128-bit lanes; the wide undefined and unlifted helpers
/// compile.
const VECTORS: &str = r#"
#include "binbun_defs.h"
#include <stdio.h>

struct packed_in { uint8_t tag; u64x4 value; uint8_t after; };
_Static_assert(sizeof(u8x4) == 4 && sizeof(u16x4) == 8 && sizeof(f64x2) == 16, "sizes");
_Static_assert(sizeof(u128x2) == 32 && sizeof(u64x8) == 64 && sizeof(f32x16) == 64, "sizes");
_Static_assert(_Alignof(u64x4) == 1 && _Alignof(i32x16) == 1, "alignment");
_Static_assert(__builtin_offsetof(struct packed_in, after) == 33, "layout");

static int failed;

static void expect(const char *what, uint64_t got, uint64_t want) {
    if (got != want) {
        printf("%s: %llx, not %llx\n", what, (unsigned long long)got,
               (unsigned long long)want);
        failed = 1;
    }
}

int main(void) {
    volatile uint8_t bytes[40];
    for (int i = 0; i < 40; i++)
        bytes[i] = (uint8_t)(i * 37 + 5);
    /* An unaligned load and store. */
    u64x4 loaded = *(u64x4 *)(bytes + 3);
    expect("load", loaded[0] & 0xff, (uint8_t)(3 * 37 + 5));
    *(u64x4 *)(bytes + 5) = loaded;
    expect("store", bytes[5], (uint8_t)(3 * 37 + 5));

    u32x8 v = {1, 0x80000000u, 7, 0xffffffffu, 2, 3, 4, 5};
    u32x8 n = {0, 31, 32, 33, 1, 0xffffffffu, 0x80000000u, 4};
    u32x8 left = shl_lanes(v, n), right = lshr_lanes(v, n);
    i32x8 arith = ashr_lanes((i32x8)v, n);
    expect("shl 0", left[0], 1);
    expect("shl 31", left[1], 0);
    expect("shl 32", left[2], 0);
    expect("shl huge", left[5], 0);
    expect("shl 4", left[7], 0x50);
    expect("lshr 31", right[1], 1);
    expect("lshr 33", right[3], 0);
    expect("ashr 31", (uint32_t)arith[1], 0xffffffffu);
    expect("ashr 33", (uint32_t)arith[3], 0xffffffffu);
    expect("ashr 2^31", (uint32_t)arith[6], 0);
    expect("ashr 1", (uint32_t)arith[4], 1);
    i8x16 bytes_shift = ashr_lanes((i8x16)splat(u8x16, 0x80), splat(u8x16, 200));
    expect("ashr 8-bit", (uint8_t)bytes_shift[9], 0xff);

    u8x16 a = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    u8x16 b = {1, 0, 3, 0, 5, 0, 7, 0, 200, 0, 0, 0, 0, 0, 0, 16};
    expect("mask_bits ==", mask_bits(a == b), 0x8055);
    expect("mask_bits <", mask_bits((i8x16)b < 0), 0x100);
    expect("mask_bits 0/1", mask_bits((a == b) & 1), 0x8055);
    /* A vector literal's commas in parentheses, as the printer puts them. */
    expect("mask_bits floats", mask_bits(((f32x4){1, 2, 3, 4} < (f32x4){2, 2, 2, 5})), 0x9);
    expect("mask_bits 64", mask_bits(splat(u8x64, 1) == splat(u8x64, 1)), ~0ull);
    i16x8 spread = lanes_from_bits(i16x8, 0x81);
    expect("lanes_from_bits", (uint16_t)spread[0], 0xffff);
    expect("lanes_from_bits 0", (uint16_t)spread[1], 0);
    expect("lanes_from_bits 7", (uint16_t)spread[7], 0xffff);
    expect("round trip", mask_bits(lanes_from_bits(i8x32, 0xdeadbeef)), 0xdeadbeef);
    u8x16 picked = blend(a < b, a, b);
    expect("blend", picked[8], 9);
    expect("blend other", picked[1], 0);
    u64x4 everywhere = splat(u64x4, 0x0123456789abcdefull);
    expect("splat", everywhere[3], 0x0123456789abcdefull);

    binbun_u128 low = ((binbun_u128)5 << 64) | 6, high = 7;
    u128x2 halves = {low, high};
    u64x4 whole = (u64x4)halves;
    expect("halves", whole[0] + whole[1] * 10 + whole[2] * 100 + whole[3], 756);
    expect("half", (uint64_t)((u128x2)whole)[1], 7);
    u16x16 widened = __builtin_convertvector((i8x16)b, u16x16);
    expect("widen", widened[8], 0xffc8);

    /* Compiled, as the printer calls them. */
    u64x8 undefined = binbun_undefined_u512();
    u64x4 unlifted = unlifted_u256("vpermq ymm0, ymm1, 0x1b");
    (void)undefined;
    (void)unlifted;
    puts(failed ? "failed" : "ok");
    return failed;
}
"#;

#[test]
fn vector_types_and_helpers_compile_cleanly_and_give_l0s_values() {
    let compilers = compilers();
    if compilers.is_empty() {
        eprintln!("skipped: neither gcc nor clang found");
        return;
    }
    let scratch = Scratch::new("vectors");
    scratch.write("vectors.c", VECTORS);
    for &compiler in &compilers {
        for opt in ["-O0", "-O2"] {
            scratch
                .compile(compiler, &["-Werror", opt, "-o", "vectors"], &["vectors.c"])
                .unwrap_or_else(|e| panic!("{compiler} {opt}: {e}"));
            assert_eq!(scratch.run("vectors"), "ok\n", "{compiler} {opt}");
        }
    }
}

/// Every exception macro as the printer uses them: nested, in a loop,
/// handlers leaving by `continue`, `break` and `goto`, reading the
/// exception values.
const EXCEPTIONS: &str = r#"
#include "binbun_defs.h"
#include <stdio.h>

static int calls;

static int step(int x) {
    calls++;
    return x + 1;
}

static void consume(void *object, intptr_t selector) {
    printf("handler %p %ld\n", object, (long)selector);
}

static int run(int n) {
    int total = 0;
    for (int i = 0; i < n; i++) {
        BINBUN_TRY {
            total += step(i);
            BINBUN_TRY {
                total += step(total);
            } BINBUN_CATCH(std::exception) {
                consume(binbun_exception(), binbun_selector());
                continue;
            } BINBUN_CATCH_ALL {
                break;
            }
        } BINBUN_CATCH(Error) {
            consume(binbun_exception(), 0);
            goto done;
        } BINBUN_CATCH(_ZTI5Other) {
            total = -1;
        } BINBUN_CLEANUP {
            consume(binbun_exception(), binbun_selector());
        }
        BINBUN_TRY {
            total++;
        } BINBUN_UNEXPECTED(std::bad_alloc, Error) {
            total = 0;
        }
        BINBUN_TRY {
            total++;
        } BINBUN_LANDING {
            if (binbun_selector() == 1)
                goto done;
            consume(binbun_exception(), binbun_selector());
        }
    }
done:
    return total;
}

int main(void) {
    int total = run(3);
    printf("%d %d\n", total, calls);
    return 0;
}
"#;

#[test]
fn exception_macros_compile_cleanly_and_run_only_the_body() {
    let compilers = compilers();
    if compilers.is_empty() {
        eprintln!("skipped: neither gcc nor clang found");
        return;
    }
    let scratch = Scratch::new("exceptions");
    scratch.write("exceptions.c", EXCEPTIONS);
    for &compiler in &compilers {
        for opt in ["-O0", "-O2"] {
            scratch
                .compile(
                    compiler,
                    &["-Werror", opt, "-o", "exceptions"],
                    &["exceptions.c"],
                )
                .unwrap_or_else(|e| panic!("{compiler} {opt}: {e}"));
            // No handler runs: 1+2, +1+1, then 7+8, +2, then 20+21, +2.
            assert_eq!(scratch.run("exceptions"), "43 6\n", "{compiler} {opt}");
        }
    }
}

/// The thread pointer's spellings on x86-64 Linux: the builtin is the
/// `fs` base (`arch_prctl`'s) and the TCB there points to itself (what
/// makes `__builtin_thread_pointer() + k` the `%fs:k` the binary reads);
/// with a fake TEB (and KPCR: its `Self` at 0x18) as the `gs` base,
/// `NtCurrentTeb()`, `KeGetPcr()` and every `__readgs…`/`__writegs…`
/// width at constant and computed offsets.
const THREAD: &str = r#"
#define _DEFAULT_SOURCE
#include "binbun_defs.h"
#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>

static uint64_t teb[8];

int main(void) {
    unsigned long fs = 0;
    syscall(SYS_arch_prctl, 0x1003 /* ARCH_GET_FS */, &fs);
    void *tp = __builtin_thread_pointer();
    printf("%d %d\n", tp == (void *)fs, *(void **)tp == tp);
    teb[6] = (uint64_t)(uintptr_t)teb;
    teb[3] = (uint64_t)(uintptr_t)teb;
    teb[2] = 0x1122334455667788;
    if (syscall(SYS_arch_prctl, 0x1001 /* ARCH_SET_GS */, teb) != 0)
        return 1;
    unsigned long k = 16;
    printf("%d %d %llx %x %x %x\n", NtCurrentTeb() == (void *)teb, KeGetPcr() == (void *)teb,
           (unsigned long long)__readgsqword(k), __readgsdword(0x14), __readgsword(0x12),
           __readgsbyte(k + 1));
    __writegsqword(0x20, 0xa1a2a3a4a5a6a7a8);
    __writegsdword(0x28, 0xb1b2b3b4);
    __writegsword(0x2c, 0xc1c2);
    __writegsbyte(k + 0x1f, 0xd1);
    printf("%llx %llx\n", (unsigned long long)teb[4], (unsigned long long)teb[5]);
    return 0;
}
"#;

#[test]
fn thread_pointer_spellings_read_and_write_what_they_name() {
    let compilers = compilers();
    if compilers.is_empty() || !cfg!(all(target_arch = "x86_64", target_os = "linux")) {
        eprintln!("skipped: needs gcc or clang on x86-64 Linux");
        return;
    }
    let scratch = Scratch::new("thread");
    scratch.write("thread.c", THREAD);
    for &compiler in &compilers {
        for opt in ["-O0", "-O2"] {
            scratch
                .compile(compiler, &["-Werror", opt, "-o", "thread"], &["thread.c"])
                .unwrap_or_else(|e| panic!("{compiler} {opt}: {e}"));
            assert_eq!(
                scratch.run("thread"),
                "1 1\n1 1 1122334455667788 11223344 5566 77\na1a2a3a4a5a6a7a8 d100c1c2b1b2b3b4\n",
                "{compiler} {opt}"
            );
        }
    }
}

/// x86-64's floating-point control registers set (rounding toward zero,
/// flush-to-zero, an exception flag raised; x87 rounding up, 53-bit
/// precision), then read by `binbun_read_mxcsr` and `binbun_read_fcw`.
const FLOAT_CONTROL: &str = r#"
#include "binbun_defs.h"
#include <stdio.h>

int main(void) {
    uint32_t mxcsr = 0x7fa1;
    uint16_t fcw = 0x0a7f;
    __asm__ volatile("ldmxcsr %0" : : "m"(mxcsr));
    __asm__ volatile("fldcw %0" : : "m"(fcw));
    printf("%x %x\n", (unsigned)binbun_read_mxcsr(), (unsigned)binbun_read_fcw());
    return 0;
}
"#;

#[test]
fn float_control_readers_read_their_registers() {
    let compilers = compilers();
    if compilers.is_empty() || !cfg!(target_arch = "x86_64") {
        eprintln!("skipped: needs gcc or clang on x86-64");
        return;
    }
    let scratch = Scratch::new("float_control");
    scratch.write("control.c", FLOAT_CONTROL);
    for &compiler in &compilers {
        for opt in ["-O0", "-O2"] {
            scratch
                .compile(compiler, &["-Werror", opt, "-o", "control"], &["control.c"])
                .unwrap_or_else(|e| panic!("{compiler} {opt}: {e}"));
            assert_eq!(scratch.run("control"), "7fa1 a7f\n", "{compiler} {opt}");
        }
    }
}

/// The driver of [`float_operations_under_a_rounding_give_l0s_values_and_exceptions`]:
/// `cases.inc` is rows of operation, format, three operands' bits,
/// rounding, whether the value is checked, L0's value and L0's flags.
const FLOAT_OPERATIONS: &str = r#"
#include "binbun_defs.h"
#include <stdio.h>

struct row { int op, wide; uint64_t a, b, c; int rounding, valued; uint64_t value; unsigned flags; };
static const struct row rows[] = {
#include "cases.inc"
};

#define BOTH(wide, call32, call64) ((wide) ? (call64) : (call32))
#define F(x) as_f32((uint32_t)(x))
#define D(x) as_f64(x)

int main(void) {
    int failures = 0;
    uint32_t before = binbun_read_mxcsr();
    for (unsigned i = 0; i < sizeof rows / sizeof *rows; i++) {
        const struct row *r = &rows[i];
        uint64_t value = 0;
        unsigned flags = 0;
        int n = r->rounding;
        switch (r->op) {
#define BINARY(code, name)                                                    \
        case code:                                                            \
            value = BOTH(r->wide, f32_bits(name(F(r->a), F(r->b), n)),        \
                         f64_bits(name(D(r->a), D(r->b), n)));                \
            flags = BOTH(r->wide, name##_status(F(r->a), F(r->b), n),         \
                         name##_status(D(r->a), D(r->b), n));                 \
            break;
        BINARY(0, float_add) BINARY(1, float_sub) BINARY(2, float_mul) BINARY(3, float_div)
        case 4:
            value = BOTH(r->wide, f32_bits(float_sqrt(F(r->a), n)), f64_bits(float_sqrt(D(r->a), n)));
            flags = BOTH(r->wide, float_sqrt_status(F(r->a), n), float_sqrt_status(D(r->a), n));
            break;
        case 5:
            value = BOTH(r->wide, f32_bits(float_fma(F(r->a), F(r->b), F(r->c), n)),
                         f64_bits(float_fma(D(r->a), D(r->b), D(r->c), n)));
            flags = BOTH(r->wide, float_fma_status(F(r->a), F(r->b), F(r->c), n),
                         float_fma_status(D(r->a), D(r->b), D(r->c), n));
            break;
        case 6:
            flags = BOTH(r->wide, float_round_status(F(r->a), n), float_round_status(D(r->a), n));
            break;
        case 7:
            value = BOTH(r->wide, f64_bits(float_convert(F(r->a), n)), f32_bits(float_convert(D(r->a), n)));
            flags = BOTH(r->wide, float_convert_status(F(r->a), n), float_convert_status(D(r->a), n));
            break;
        case 8:
            value = BOTH(r->wide, f32_bits(f32_from_sint((int32_t)r->a, n)), f64_bits(f64_from_sint((int32_t)r->a, n)));
            flags = BOTH(r->wide, f32_from_sint_status((int32_t)r->a, n), f64_from_sint_status((int32_t)r->a, n));
            break;
        case 9:
            value = BOTH(r->wide, f32_bits(f32_from_sint((int64_t)r->a, n)), f64_bits(f64_from_sint((int64_t)r->a, n)));
            flags = BOTH(r->wide, f32_from_sint_status((int64_t)r->a, n), f64_from_sint_status((int64_t)r->a, n));
            break;
        case 10:
            flags = BOTH(r->wide, float_to_sint32_status(F(r->a), n), float_to_sint32_status(D(r->a), n));
            break;
        case 11:
            flags = BOTH(r->wide, float_to_sint64_status(F(r->a), n), float_to_sint64_status(D(r->a), n));
            break;
        case 12:
            flags = BOTH(r->wide, float_compare_status(F(r->a), F(r->b)), float_compare_status(D(r->a), D(r->b)));
            break;
        case 13:
            flags = BOTH(r->wide, float_compare_signaling_status(F(r->a), F(r->b)),
                         float_compare_signaling_status(D(r->a), D(r->b)));
            break;
        }
        if ((r->valued && value != r->value) || flags != r->flags) {
            if (failures++ < 20)
                printf("FAIL op %d wide %d a %llx b %llx c %llx rounding %d: %llx flags %x, not %llx flags %x\n",
                       r->op, r->wide, (unsigned long long)r->a, (unsigned long long)r->b,
                       (unsigned long long)r->c, n, (unsigned long long)value, flags,
                       (unsigned long long)r->value, r->flags);
        }
    }
    /* The caller's controls are as they were, and every flag raised on the
     * way is set, as the instructions would have left them. */
    if (binbun_read_mxcsr() != (before | 0x3f))
        failures++, printf("FAIL mxcsr %x, not %x\n", binbun_read_mxcsr(), before | 0x3f);
    printf(failures ? "%d failed\n" : "ok\n", failures);
    return 0;
}
"#;

/// Doubles at the edges: the zeros, small numbers, the largest, the
/// smallest normal, denormals, the infinities, a quiet and a signalling
/// NaN, a number no `float` or 32-bit integer holds.
const DOUBLES: [u64; 16] = [
    0,
    0x8000_0000_0000_0000,
    0x3ff0_0000_0000_0000,
    0x3ff8_0000_0000_0000,
    0x4008_0000_0000_0000,
    0x3fb9_9999_9999_999a,
    0xc004_0000_0000_0000,
    0x7fef_ffff_ffff_ffff,
    0x0010_0000_0000_0000,
    0x0000_0000_0000_0001,
    0x000f_ffff_ffff_ffff,
    0x7ff0_0000_0000_0000,
    0xfff0_0000_0000_0000,
    0x7ff8_0000_0000_0000,
    0x7ff0_0000_0000_0001,
    0x41e0_0000_0020_0000,
];

/// The same for floats.
const SINGLES: [u64; 16] = [
    0,
    0x8000_0000,
    0x3f80_0000,
    0x3fc0_0000,
    0x4040_0000,
    0x3dcc_cccd,
    0xc020_0000,
    0x7f7f_ffff,
    0x0080_0000,
    0x0000_0001,
    0x007f_ffff,
    0x7f80_0000,
    0xff80_0000,
    0x7fc0_0000,
    0x7f80_0001,
    0x4f00_0001,
];

/// Integers to convert: exact ones, and ones a float or a double rounds.
const INTEGERS: [u64; 8] = [
    0,
    1,
    u64::MAX,
    0x7fff_ffff,
    0x8000_0000,
    0x0020_0000_0000_0001,
    0x7fff_ffff_ffff_ffff,
    0x0000_0000_0100_0001,
];

/// One row of [`FLOAT_OPERATIONS`]: operation `code` (`op` on `format`)
/// on `operands` (width and bits) under `rounding`, with what L0's
/// interpreter gives.
fn float_row(
    out: &mut String,
    code: u8,
    op: binbun_semantics::ir::FloatOp,
    format: binbun_semantics::ir::Format,
    operands: &[(u16, u64)],
    rounding: u64,
) {
    use binbun_semantics::Bits;
    use binbun_semantics::interpret::{self, Value};
    use binbun_semantics::ir::{FloatOp, FloatOutput, Format};
    use std::fmt::Write as _;

    let inputs: Vec<Value> = operands
        .iter()
        .map(|&(width, bits)| Value::defined(Bits::from_u64(width, bits)))
        .collect();
    let run = |output| {
        let rounding = Value::defined(Bits::from_u64(2, rounding));
        interpret::float(op, format, 1, output, rounding, &inputs)
            .known()
            .unwrap()
            .low_u64()
    };
    // The helpers for these give flags alone.
    let checked = !matches!(
        op,
        FloatOp::RoundToIntegral | FloatOp::ToInt { .. } | FloatOp::Compare { .. }
    );
    let operand = |index: usize| operands.get(index).map_or(0, |&(_, bits)| bits);
    writeln!(
        out,
        "{{{code}, {}, {:#x}u, {:#x}u, {:#x}u, {rounding}, {}, {:#x}u, {:#x}}},",
        u8::from(format == Format::Double),
        operand(0),
        operand(1),
        operand(2),
        u8::from(checked),
        if checked { run(FloatOutput::Value) } else { 0 },
        run(FloatOutput::Status),
    )
    .unwrap();
}

/// The rows of [`FLOAT_OPERATIONS`]: every operation the helpers run, on
/// both formats, under the four roundings, over operands that reach each
/// exception and its edges.
fn float_cases() -> String {
    use binbun_semantics::ir::{FloatOp, Format};

    let mut out = String::new();
    let mut row = |code, op, format, operands: &[(u16, u64)], rounding| {
        float_row(&mut out, code, op, format, operands, rounding);
    };
    for (format, width, values) in [
        (Format::Single, 32, &SINGLES),
        (Format::Double, 64, &DOUBLES),
    ] {
        let other = if format == Format::Single {
            Format::Double
        } else {
            Format::Single
        };
        for rounding in 0..4 {
            for &a in values {
                for &b in values {
                    for (code, op) in [
                        (0, FloatOp::Add),
                        (1, FloatOp::Sub),
                        (2, FloatOp::Mul),
                        (3, FloatOp::Div),
                    ] {
                        row(code, op, format, &[(width, a), (width, b)], rounding);
                    }
                    // The product's low bits and a small addend: one rounding.
                    let c = values[(a.count_ones() + b.count_ones()) as usize % values.len()];
                    let three = [(width, a), (width, b), (width, c)];
                    row(5, FloatOp::MulAdd, format, &three, rounding);
                    if rounding == 0 {
                        for (code, signaling) in [(12, false), (13, true)] {
                            let op = FloatOp::Compare { signaling };
                            row(code, op, format, &[(width, a), (width, b)], 0);
                        }
                    }
                }
                row(4, FloatOp::Sqrt, format, &[(width, a)], rounding);
                row(6, FloatOp::RoundToIntegral, format, &[(width, a)], rounding);
                row(7, FloatOp::Convert(other), format, &[(width, a)], rounding);
                for (code, bits) in [(10, 32), (11, 64)] {
                    let op = FloatOp::ToInt {
                        signed: true,
                        width: bits,
                    };
                    row(code, op, format, &[(width, a)], rounding);
                }
            }
            for &integer in &INTEGERS {
                let signed = FloatOp::FromInt { signed: true };
                row(8, signed, format, &[(32, integer & 0xffff_ffff)], rounding);
                row(9, signed, format, &[(64, integer)], rounding);
            }
        }
    }
    out
}

/// `binbun_defs.h`'s floating-point operations under a rounding
/// (`float_mul(a, b, rounding)`) and their exceptions
/// (`float_mul_status`) run the machine's instruction, so they are
/// checked against L0's interpreter, which the lifted code means: each
/// operation, both formats, the four roundings, operands at every edge
/// (zeros, denormals, the largest, infinities, both NaNs); afterwards
/// the caller's MXCSR has its controls as they were and the flags raised.
#[test]
fn float_operations_under_a_rounding_give_l0s_values_and_exceptions() {
    let compilers = compilers();
    let features = cfg!(target_arch = "x86_64")
        && std::arch::is_x86_feature_detected!("fma")
        && std::arch::is_x86_feature_detected!("sse4.1");
    if compilers.is_empty() || !features {
        eprintln!("skipped: needs gcc or clang on x86-64 with FMA and SSE4.1");
        return;
    }
    let scratch = Scratch::new("float_operations");
    scratch.write("operations.c", FLOAT_OPERATIONS);
    scratch.write("cases.inc", &float_cases());
    for &compiler in &compilers {
        for opt in ["-O0", "-O2"] {
            scratch
                .compile(
                    compiler,
                    &["-Werror", opt, "-o", "operations"],
                    &["operations.c"],
                )
                .unwrap_or_else(|e| panic!("{compiler} {opt}: {e}"));
            assert_eq!(scratch.run("operations"), "ok\n", "{compiler} {opt}");
        }
    }
}

/// Every helper for instructions without semantics as the printer calls
/// them (exact view): none, one or several outputs, each width; a value
/// stored before one is reloaded after it (memory may change), the
/// output of one is used in a condition.
const UNLIFTED: &str = r#"
#include "binbun_defs.h"
#include <stdio.h>

uint32_t g;

static uint64_t f(uint32_t *p) {
    uint8_t t0;
    uint64_t t1;
    binbun_u128 wide;
    *p = 1;
    unlifted("vmovdqu64 ymm17, ymmword ptr [rsi]");
    unlifted("vcomisd xmm16, xmm17", &t0, &t1);
    uint32_t _EAX = unlifted_u32("kmovd eax, k1");
    if (_EAX != 0 && unlifted_bool("kortestw k1, k2"))
        g++;
    wide = unlifted_u128("vmovq xmm0, xmm16");
    return *p + t0 + t1 + unlifted_u8("kmovb al, k1") + unlifted_u16("kmovw ax, k1") +
           unlifted_u64("kmovq rax, k1") + (uint64_t)wide;
}

int main(void) {
    uint32_t cell = 0;
    (void)f(&cell);
    printf("%u\n", cell);
    return 0;
}
"#;

#[test]
fn unlifted_helpers_compile_cleanly() {
    let compilers = compilers();
    if compilers.is_empty() {
        eprintln!("skipped: neither gcc nor clang found");
        return;
    }
    let scratch = Scratch::new("unlifted");
    scratch.write("unlifted.c", UNLIFTED);
    for &compiler in &compilers {
        for opt in ["-O0", "-O2"] {
            let stderr = scratch
                .compile(
                    compiler,
                    &["-Werror", opt, "-o", "unlifted"],
                    &["unlifted.c"],
                )
                .unwrap_or_else(|e| panic!("{compiler} {opt}: {e}"));
            assert!(stderr.is_empty(), "{compiler} {opt}: {stderr}");
            assert_eq!(scratch.run("unlifted"), "1\n", "{compiler} {opt}");
        }
    }
}

/// Values the architecture leaves undefined as the printer calls their
/// helpers: compared with each other and with a constant, every width.
const UNDEFINED: &str = r#"
#include "binbun_defs.h"

int same(void) { return binbun_undefined_bool() == binbun_undefined_bool(); }
int branch(void) { return binbun_undefined_u32() == 7 ? 1 : 2; }
binbun_u128 wide(void) {
    return binbun_undefined_u128() ^ binbun_undefined_u8() ^ binbun_undefined_u16() ^
           binbun_undefined_u64();
}
"#;

/// The helpers compile cleanly, and at -O2 no compiler folds them: two
/// calls are still compared (not taken as one value), and a comparison
/// with a constant is still made (not decided).
#[test]
fn undefined_helpers_compile_and_are_not_folded() {
    let compilers = compilers();
    if compilers.is_empty() || !cfg!(target_arch = "x86_64") {
        eprintln!("skipped: needs gcc or clang on x86-64");
        return;
    }
    let scratch = Scratch::new("undefined");
    scratch.write("undefined.c", UNDEFINED);
    for &compiler in &compilers {
        let stderr = scratch
            .compile(
                compiler,
                &["-Werror", "-O2", "-S", "-o", "undefined.s"],
                &["undefined.c"],
            )
            .unwrap_or_else(|e| panic!("{compiler}: {e}"));
        assert!(stderr.is_empty(), "{compiler}: {stderr}");
        let assembly = std::fs::read_to_string(scratch.dir.join("undefined.s")).unwrap();
        let body = |name: &str| {
            let start = assembly
                .find(&format!("\n{name}:"))
                .unwrap_or_else(|| panic!("{compiler}: no {name}: {assembly}"));
            let rest = &assembly[start..];
            rest[..rest.find("ret").unwrap_or(rest.len())].to_owned()
        };
        assert!(body("same").contains("sete"), "{compiler}: {assembly}");
        assert!(body("branch").contains("$7,"), "{compiler}: {assembly}");
    }
}
