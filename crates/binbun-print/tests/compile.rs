#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers fail loudly"
)]

//! Hand-built functions printed and compiled with GCC and Clang
//! (`-std=c11 -fwrapv -fno-strict-aliasing -Wall -Wextra`): structured
//! control flow and the gotos it needs, memory through typed pointers,
//! calls, intrinsics, every escape, and names from the binary that are not
//! C identifiers or collide.

mod common;

use binbun_ast::ir::{Call, Callee, Expr, Place, Stmt, VarId, VarKind};
use binbun_ast::types::{Aggregate, Field, Type, TypeId};
use binbun_print::style::{IntSpelling, Style};
use binbun_semantics::ir::{Binary, Format, Trap};
use common::samples::{branches, calls, escapes, loops, memory, symbols, wide_literals};
use common::{Builder, LLP64, LP64, Platform, Scratch, compilers, print_with, warnings};

#[test]
fn hand_built_functions_compile_without_warnings() {
    let compilers = compilers();
    if compilers.is_empty() {
        eprintln!("skipped: no C compiler to check with");
        return;
    }
    let scratch = Scratch::new("compile");
    let mut total = 0;
    let functions = [loops(), memory(), calls(), escapes(), branches()];
    let styles = [
        (Style::kr(), LP64),
        // C's own names, as on Linux and as on 64-bit Windows.
        (Style::kr().with_int_spelling(IntSpelling::Plain), LP64),
        (Style::kr().with_int_spelling(IntSpelling::Plain), LLP64),
        (Style::llvm(), LP64),
        (Style::linux(), LP64),
        (Style::allman(), LP64),
    ];
    for f in &functions {
        for (style, long) in &styles {
            let (text, _) = print_with(f, style, &Platform(*long));
            scratch.write("out.c", &text);
            for &compiler in &compilers {
                let stderr = scratch
                    .compile(compiler, &["-c", "-o", "out.o", "-O2"], &["out.c"])
                    .unwrap_or_else(|e| panic!("{compiler} failed on\n{text}\n{e}"));
                if warnings(&stderr) > 0 {
                    eprintln!("{compiler}:\n{text}\n{stderr}");
                }
                total += warnings(&stderr);
            }
        }
    }
    eprintln!(
        "compile: {} functions x {} styles x {} compilers: {total} warnings",
        functions.len(),
        styles.len(),
        compilers.len()
    );
    assert_eq!(total, 0);
}

#[test]
fn wide_literals_stay_64_bits_on_64_bit_windows() {
    // Must: under LLP64 (`long` 32 bits) a 64-bit literal is still 64
    // bits: `0xdeadUL << 40` would shift a 32-bit `unsigned long` past
    // its width (a warning, and no constant). Clang for 64-bit Windows
    // (the GNU flavour: binbun_defs.h needs GCC or Clang), syntax only, the
    // shift's value checked where the compiler computes it.
    if !compilers().contains(&"clang") {
        eprintln!("skipped: clang not found");
        return;
    }
    let mut b = Builder::new(0x5900, "shifted");
    let word = b.uint(64);
    b.f.returns = Some(word);
    let (dead, forty) = (b.c(64, 0xdead), b.c(64, 40));
    let shifted = b.bin(Binary::Shl, dead, forty);
    let ret = b.ret(shifted);
    let shifted = b.done(vec![ret]);
    let scratch = Scratch::new("llp64");
    let windows = ["--target=x86_64-pc-windows-gnu", "-Werror", "-fsyntax-only"];
    for style in [
        Style::kr(),
        Style::kr().with_int_spelling(IntSpelling::Plain),
    ] {
        let (text, _) = print_with(&shifted, &style, &Platform(LLP64));
        let value = text
            .lines()
            .find_map(|line| line.trim().strip_prefix("return ")?.strip_suffix(';'))
            .unwrap_or_else(|| panic!("no return:\n{text}"));
        let checked =
            format!("{text}\n_Static_assert(({value}) == 0xdead0000000000, \"64 bits\");\n");
        let (wide, _) = print_with(&wide_literals(), &style, &Platform(LLP64));
        for source in [checked, wide] {
            scratch.write("out.c", &source);
            let stderr = scratch
                .compile("clang", &windows, &["out.c"])
                .unwrap_or_else(|e| panic!("clang for Windows failed on\n{source}\n{e}"));
            assert_eq!(warnings(&stderr), 0, "{source}\n{stderr}");
        }
    }
}

#[test]
fn breaks_and_continues_of_outer_loops_become_gotos() {
    let (text, counts) = print_with(&loops(), &Style::kr(), &symbols);
    // The continue and the break of the outer loop from the inner one,
    // and the goto to the label after the loop.
    assert_eq!(counts.gotos, 3, "{text}");
    assert!(text.contains("goto continue_"), "{text}");
    assert!(text.contains("goto break_"), "{text}");
    assert!(text.contains("__attribute__((fallthrough));"), "{text}");
    // The switch's own breaks stay `break`.
    assert!(text.contains("break;"), "{text}");
}

#[test]
fn names_from_the_binary_are_made_c_identifiers_and_kept_in_comments() {
    let (text, _) = print_with(&calls(), &Style::kr(), &symbols);
    // Callees keep their names; a name that is not an identifier links to
    // its symbol; a second signature of one callee gets a second name.
    assert!(
        text.contains("void *memcpy(void *, void *, uint64_t);"),
        "{text}"
    );
    assert!(
        text.contains(
            "int32_t foo_cold(int32_t) BINBUN_SYMBOL(\"foo.cold\"); /* 0x6000 foo.cold */"
        ),
        "{text}"
    );
    assert!(
        text.contains("foo_cold_2(uint64_t, uint64_t) BINBUN_SYMBOL(\"foo.cold\")"),
        "{text}"
    );
    assert!(
        text.contains("int32_t printf(void *, ...); /* 0x8000 printf@plt */"),
        "{text}"
    );
    assert!(
        text.contains("/* calls (calls@@GLIBC_2.2) at 0x3000"),
        "{text}"
    );
    // Locals named like a callee, a keyword and a helper are renamed.
    for local in ["void *memcpy_2;", "int32_t int_2;", "uint64_t rotl_2;"] {
        assert!(text.contains(local), "{local}:\n{text}");
    }
    let (text, _) = print_with(&memory(), &Style::kr(), &symbols);
    assert!(
        text.contains("extern int32_t switch_2; /* 0x404010 switch */"),
        "{text}"
    );
    assert!(text.contains("int16_t int_;"), "{text}");
    assert!(text.contains("a1->next->value + a1->value"), "{text}");
    assert!(text.contains("a1->data[2]"), "{text}");
    assert!(text.contains("frame_m20[1] = a1->value;"), "{text}");
}

#[test]
fn accesses_at_a_constant_address_are_volatile() {
    // GCC's cold paths store to address 0 to fault, then `ud2`: C lets a
    // compiler drop a store it proves undefined, so it must be volatile.
    // Loads of a data pointer and of a function pointer from fixed
    // addresses (a GOT slot, a table): the loaded pointer is what is
    // volatile. It is named by its typedef of alignment 1 (nothing says
    // an address is a multiple of 8), which the qualifier in front
    // qualifies; in front of `void *` or of a function's return type it
    // would qualify the pointee, which neither compiler accepts as the
    // value's type.
    let mut b = Builder::new(0x9000, "cold");
    let byte = b.uint(8);
    let void_ptr = b.ty(Type::Pointer(None));
    let int32 = b.int(32);
    let callback = b.code(vec![int32], Some(int32), false);
    let (data, code) = (b.local(void_ptr), b.local(callback));
    let (slot1, slot2) = (b.c(64, 0x40_4000), b.c(64, 0x40_4008));
    let (load1, load2) = (b.load_at(slot1, 0, void_ptr), b.load_at(slot2, 0, callback));
    let first = b.assign(data, load1);
    let second = b.assign(code, load2);
    let (zero, value) = (b.c(64, 0), b.c(8, 0));
    let store = b.s(Stmt::Assign {
        place: Place::Memory {
            address: zero,
            ty: byte,
        },
        value,
    });
    let trap = b.s(Stmt::Trap(Trap::InvalidInstruction));
    let f = b.done(vec![first, second, store, trap]);
    let (text, _) = print_with(&f, &Style::kr(), &symbols);
    assert!(text.contains("*(volatile uint8_t *)0"), "{text}");
    for expected in [
        "typedef void *void_p_u __attribute__((aligned(1)));",
        "typedef int32_t (*int32_t_p_int32_t_u)(int32_t) __attribute__((aligned(1)));",
        "*(volatile void_p_u *)0x404000",
        "*(volatile int32_t_p_int32_t_u *)0x404008",
    ] {
        assert!(text.contains(expected), "no {expected:?} in\n{text}");
    }
    let scratch = Scratch::new("volatile");
    scratch.write("out.c", &text);
    // Compiled: the loaded values' types must be what they are assigned to
    // (the misplaced qualifier was an error in both compilers).
    for compiler in compilers() {
        scratch
            .compile(compiler, &["-c", "-o", "out.o"], &["out.c"])
            .unwrap_or_else(|e| panic!("{compiler} failed on\n{text}\n{e}"));
    }
}

#[test]
fn a_pointer_used_as_an_index_is_subscripted_as_an_integer() {
    // A variable the types made a pointer (a register holding `strlen`'s
    // result and later `strcpy`'s) indexing a byte array: C's subscript
    // must be an integer.
    let mut b = Builder::new(0x9100, "index");
    let byte = b.uint(8);
    b.f.returns = Some(byte);
    let bytes = b.ty(Type::Pointer(Some(byte)));
    let (array, length) = (b.param(bytes), b.param(bytes));
    let (array, length) = (b.read(array), b.read(length));
    let address = b.bin(Binary::Add, array, length);
    let last = b.load_at(address, u64::MAX, byte);
    let ret = b.ret(last);
    let f = b.done(vec![ret]);
    let (text, _) = print_with(&f, &Style::kr(), &symbols);
    assert!(text.contains('['), "{text}");
    let scratch = Scratch::new("index");
    scratch.write("out.c", &text);
    for compiler in compilers() {
        scratch
            .compile(compiler, &["-c", "-o", "out.o"], &["out.c"])
            .unwrap_or_else(|e| panic!("{compiler} failed on\n{text}\n{e}"));
    }
}

#[test]
fn a_call_on_the_right_of_a_one_bit_or_stays_evaluated() {
    // `a < 0 | g(b) == 0`: L2 evaluates both operands, so the call is made
    // whatever `a`; C's `||` would skip it when `a < 0`.
    let mut b = Builder::new(0x9180, "either");
    let int32 = b.int(32);
    b.f.returns = Some(int32);
    let (first, second) = (b.param(int32), b.param(int32));
    let signature = b.code(vec![int32], Some(int32), false);
    let argument = b.read(second);
    let call = b.f.add_call(Call {
        callee: Callee::Address(0x2000),
        arguments: vec![argument],
        signature,
        variadic: Vec::new(),
    });
    let called = b.e(Expr::Call(call));
    let zero = b.c(32, 0);
    let failed = b.bin(Binary::Eq, called, zero);
    let a = b.read(first);
    let negative = b.bin(Binary::SLt, a, zero);
    let either = b.bin(Binary::Or, negative, failed);
    let one = b.c(32, 1);
    let early = b.ret(one);
    let decision = b.when(either, vec![early]);
    let late = b.ret(zero);
    let f = b.done(vec![decision, late]);
    let (text, _) = print_with(&f, &Style::kr(), &symbols);
    assert!(!text.contains("||"), "{text}");
    assert!(text.contains(" | "), "{text}");
}

#[test]
fn pointer_sums_differences_and_null_tests_need_no_casts() {
    // `p + i * 4` of an `int32_t *` is `p + i`; `a - c` of two byte
    // pointers is their distance; `q != 0` is C's null pointer test; and
    // `q < a` of pointers of different types still compares their bits.
    let mut b = Builder::new(0x9200, "pointers");
    let (int32, int64, byte, word) = (b.int(32), b.int(64), b.uint(8), b.uint(64));
    let ints = b.ty(Type::Pointer(Some(int32)));
    let bytes = b.ty(Type::Pointer(Some(byte)));
    b.f.returns = Some(int64);
    let (base, index) = (b.param(ints), b.param(word));
    let (end, start) = (b.param(bytes), b.param(bytes));
    let (element, length) = (b.local(ints), b.local(int64));
    let (base, index, four) = (b.read(base), b.read(index), b.c(64, 4));
    let scaled = b.bin(Binary::Mul, index, four);
    let sum = b.bin(Binary::Add, base, scaled);
    let first = b.assign(element, sum);
    let zero = b.c(64, 0);
    let cleared = b.assign(length, zero);
    let (high, low) = (b.read(end), b.read(start));
    let distance = b.bin(Binary::Sub, high, low);
    let set = b.assign(length, distance);
    let (pointer, zero) = (b.read(element), b.c(64, 0));
    let null = b.bin(Binary::Ne, pointer, zero);
    let nonnull = b.when(null, vec![set]);
    let (pointer, other, one) = (b.read(element), b.read(end), b.c(64, 1));
    let below = b.bin(Binary::ULt, pointer, other);
    let count = b.read(length);
    let bump = b.bin(Binary::Add, count, one);
    let bumped = b.assign(length, bump);
    let order = b.when(below, vec![bumped]);
    let count = b.read(length);
    let ret = b.ret(count);
    let f = b.done(vec![first, cleared, nonnull, order, ret]);
    let (text, printed) = print_with(&f, &Style::kr(), &symbols);
    assert!(text.contains("v4 = a1 + a2;"), "{text}");
    assert!(text.contains("v5 = a3 - a4;"), "{text}");
    assert!(text.contains("if (v4 != 0)"), "{text}");
    assert!(text.contains("if ((uint64_t)v4 < (uint64_t)a3)"), "{text}");
    assert_eq!(printed.casts, 2, "{text}");
    let scratch = Scratch::new("pointers");
    scratch.write("out.c", &text);
    for compiler in compilers() {
        let stderr = scratch
            .compile(compiler, &["-c", "-o", "out.o"], &["out.c"])
            .unwrap_or_else(|e| panic!("{compiler} failed on\n{text}\n{e}"));
        assert_eq!(warnings(&stderr), 0, "{compiler}:\n{text}\n{stderr}");
    }
}

#[test]
fn byte_offsets_are_byte_pointer_sums_and_accesses_cast_the_pointer_itself() {
    // `p - 16 + n` (an index not scaled to what `p` points to) is a sum in
    // bytes, not on `p`'s integer value: on the `void *` `p` itself (GNU
    // C's arithmetic), on a byte pointer for the `int32_t *` `q`; `n + q`
    // puts the pointer first; a load at `p` itself casts `p` to the type
    // read, with no byte pointer between.
    let mut b = Builder::new(0x9280, "bytes");
    let (word, int32) = (b.uint(64), b.int(32));
    let void = b.ty(Type::Pointer(None));
    let ints = b.ty(Type::Pointer(Some(int32)));
    b.f.returns = Some(word);
    let (bytes, length, words) = (b.param(void), b.param(word), b.param(ints));
    let (end, at) = (b.local(void), b.local(ints));
    let (base, sixteen, count) = (b.read(bytes), b.c(64, 16), b.read(length));
    let back = b.bin(Binary::Sub, base, sixteen);
    let sum = b.bin(Binary::Add, back, count);
    let first = b.assign(end, sum);
    let (count, ints_base) = (b.read(length), b.read(words));
    let swapped = b.bin(Binary::Add, count, ints_base);
    let second = b.assign(at, swapped);
    let (pointer, zero) = (b.read(at), b.c(64, 0));
    let null = b.bin(Binary::Ne, pointer, zero);
    let base = b.read(bytes);
    let head = b.load_at(base, 0, word);
    let early = b.ret(head);
    let nonnull = b.when(null, vec![early]);
    let tail = b.read(end);
    let last = b.load_at(tail, 0, word);
    let ret = b.ret(last);
    let f = b.done(vec![first, second, nonnull, ret]);
    let (text, printed) = print_with(&f, &Style::kr(), &symbols);
    assert!(text.contains("v3 = a1 - 16 + a2;"), "{text}");
    assert!(
        text.contains("v4 = (binbun_i32_u *)((uint8_t *)a3 + a2);"),
        "{text}"
    );
    assert!(text.contains("return *(binbun_u64_u *)a1;"), "{text}");
    assert!(text.contains("return *(binbun_u64_u *)v3;"), "{text}");
    assert_eq!(printed.casts, 4, "{text}");
    let scratch = Scratch::new("bytes");
    scratch.write("out.c", &text);
    for compiler in compilers() {
        let stderr = scratch
            .compile(compiler, &["-c", "-o", "out.o"], &["out.c"])
            .unwrap_or_else(|e| panic!("{compiler} failed on\n{text}\n{e}"));
        assert_eq!(warnings(&stderr), 0, "{compiler}:\n{text}\n{stderr}");
    }
}

#[test]
fn arithmetic_on_a_void_pointer_counts_bytes_without_a_byte_pointer() {
    // `p + 152`, `p + n`, a load at `p - 32` and the distance `r - q` of
    // two `void *`s: GCC's and Clang's arithmetic on `void *` (in bytes),
    // no `(uint8_t *)` cast; the load still casts to the type read.
    let mut b = Builder::new(0x92a0, "voids");
    let (word, int32) = (b.uint(64), b.int(32));
    let void = b.ty(Type::Pointer(None));
    b.f.returns = Some(word);
    let (bytes, length) = (b.param(void), b.param(word));
    let (near, far) = (b.local(void), b.local(void));
    let (base, offset) = (b.read(bytes), b.c(64, 152));
    let sum = b.bin(Binary::Add, base, offset);
    let first = b.assign(near, sum);
    let (base, count) = (b.read(bytes), b.read(length));
    let moved = b.bin(Binary::Add, base, count);
    let second = b.assign(far, moved);
    let (base, back) = (b.read(bytes), b.c(64, 32u64.wrapping_neg()));
    let at = b.bin(Binary::Add, base, back);
    let loaded = b.load_at(at, 0, int32);
    let loaded = b.ext(true, loaded, 64);
    let (end, start) = (b.read(far), b.read(near));
    let distance = b.bin(Binary::Sub, end, start);
    let total = b.bin(Binary::Add, loaded, distance);
    let ret = b.ret(total);
    let f = b.done(vec![first, second, ret]);
    let (text, printed) = print_with(&f, &Style::kr(), &symbols);
    assert!(text.contains("v2 = a1 + 152;"), "{text}");
    assert!(text.contains("v3 = a1 + a2;"), "{text}");
    assert!(text.contains("*)(a1 - 32)"), "{text}");
    assert!(text.contains("v3 - v2"), "{text}");
    assert!(!text.contains("uint8_t *"), "{text}");
    assert_eq!(printed.casts, 1, "{text}");
    let scratch = Scratch::new("voids");
    scratch.write("out.c", &text);
    for compiler in compilers() {
        let stderr = scratch
            .compile(compiler, &["-c", "-o", "out.o"], &["out.c"])
            .unwrap_or_else(|e| panic!("{compiler} failed on\n{text}\n{e}"));
        assert_eq!(warnings(&stderr), 0, "{compiler}:\n{text}\n{stderr}");
    }
}

#[test]
fn an_index_into_a_global_array_is_scaled_to_its_element() {
    // `&table + (i & 63) * 4` of an `int32_t table[64]`, held in a
    // variable: `table + (i & 0x3f)`, scaled to the element, not a sum on
    // a byte pointer cast back.
    let mut b = Builder::new(0x92b0, "element");
    let int32 = b.int(32);
    let word = b.uint(64);
    let elements = b.ty(Type::Array {
        element: int32,
        length: Some(64),
    });
    let ints = b.ty(Type::Pointer(Some(int32)));
    b.f.returns = Some(int32);
    let table = b.var(VarKind::Global(0x5f00), elements, None);
    let index = b.param(word);
    let at = b.local(ints);
    let (read, mask) = (b.read(index), b.c(64, 63));
    let masked = b.bin(Binary::And, read, mask);
    let four = b.c(64, 4);
    let scaled = b.bin(Binary::Mul, masked, four);
    let base = b.e(Expr::AddressOf(table));
    let sum = b.bin(Binary::Add, base, scaled);
    let held = b.assign(at, sum);
    let pointer = b.read(at);
    let loaded = b.load_at(pointer, 0, int32);
    let ret = b.ret(loaded);
    let f = b.done(vec![held, ret]);
    let (text, printed) = print_with(&f, &Style::kr(), &symbols);
    assert!(text.contains("v2 = g_5f00 + (a1 & 0x3f);"), "{text}");
    assert_eq!(printed.casts, 0, "{text}");
    let scratch = Scratch::new("element");
    scratch.write("out.c", &text);
    for compiler in compilers() {
        let stderr = scratch
            .compile(compiler, &["-c", "-o", "out.o"], &["out.c"])
            .unwrap_or_else(|e| panic!("{compiler} failed on\n{text}\n{e}"));
        assert_eq!(warnings(&stderr), 0, "{compiler}:\n{text}\n{stderr}");
    }
}

#[test]
fn a_literal_printed_unsigned_gives_a_sum_its_unsigned_value() {
    // `x - 14` compared unsigned, `y - 1` shifted right logically and
    // `1 - x` zero-extended need their unsigned values: at 32 and 64 bits
    // the literal printed unsigned makes C compute them in the unsigned
    // type (`a1 - 14U`), with no cast; at 16 bits C computes in `int`,
    // and the cast stays.
    let mut b = Builder::new(0x92c0, "unsigned");
    let (int16, int32, int64, word) = (b.int(16), b.int(32), b.int(64), b.uint(64));
    b.f.returns = Some(word);
    let (int, long, short) = (b.param(int32), b.param(int64), b.param(int16));
    let (read, fourteen, one) = (b.read(int), b.c(32, 14), b.c(32, 1));
    let less = b.bin(Binary::Sub, read, fourteen);
    let below = b.bin(Binary::ULe, less, one);
    let two = b.c(64, 2);
    let early = b.ret(two);
    let first = b.when(below, vec![early]);
    let (read, fourteen, one) = (b.read(short), b.c(16, 14), b.c(16, 1));
    let less = b.bin(Binary::Sub, read, fourteen);
    let below = b.bin(Binary::ULe, less, one);
    let three = b.c(64, 3);
    let early = b.ret(three);
    let second = b.when(below, vec![early]);
    let (read, one, three) = (b.read(long), b.c(64, 1), b.c(64, 3));
    let less = b.bin(Binary::Sub, read, one);
    let shifted = b.bin(Binary::LShr, less, three);
    let (one, read) = (b.c(32, 1), b.read(int));
    let from = b.bin(Binary::Sub, one, read);
    let wide = b.ext(false, from, 64);
    let total = b.bin(Binary::Add, shifted, wide);
    let ret = b.ret(total);
    let f = b.done(vec![first, second, ret]);
    let (text, printed) = print_with(&f, &Style::kr(), &symbols);
    assert!(text.contains("if (a1 - 14U <= 1)"), "{text}");
    assert!(text.contains("if ((uint16_t)(a3 - 14) <= 1)"), "{text}");
    assert!(text.contains("(a2 - 1UL) >> 3"), "{text}");
    assert!(text.contains("1U - a1"), "{text}");
    assert_eq!(printed.casts, 1, "{text}");
    let scratch = Scratch::new("unsigned");
    scratch.write("out.c", &text);
    for compiler in compilers() {
        let stderr = scratch
            .compile(compiler, &["-c", "-o", "out.o"], &["out.c"])
            .unwrap_or_else(|e| panic!("{compiler} failed on\n{text}\n{e}"));
        assert_eq!(warnings(&stderr), 0, "{compiler}:\n{text}\n{stderr}");
    }
}

#[test]
fn a_pointer_selected_against_zero_keeps_its_type() {
    // `c ? p : 0` and `c ? 0 : p`, of a data pointer and of a function
    // pointer: C's null pointer constant needs no cast, and the select is
    // the pointer's type (not `(T *)(c ? (uint64_t)p : 0)`).
    let mut b = Builder::new(0x9300, "select");
    let (int32, word) = (b.int(32), b.uint(64));
    let ints = b.ty(Type::Pointer(Some(int32)));
    let code = b.code(vec![], None, false);
    b.f.returns = Some(code);
    let (data, function, flag) = (b.param(ints), b.param(code), b.param(word));
    let (first, second) = (b.local(ints), b.local(ints));
    let select = |b: &mut Builder, value: VarId, pointer_first: bool| {
        let (test, zero) = (b.read(flag), b.c(64, 0));
        let condition = b.bin(Binary::Eq, test, zero);
        let (pointer, null) = (b.read(value), b.c(64, 0));
        let (then, otherwise) = if pointer_first {
            (pointer, null)
        } else {
            (null, pointer)
        };
        b.e(Expr::Select {
            condition,
            then,
            otherwise,
        })
    };
    let value = select(&mut b, data, true);
    let one = b.assign(first, value);
    let value = select(&mut b, data, false);
    let two = b.assign(second, value);
    let (pointer, zero) = (b.read(first), b.c(64, 0));
    let set = b.bin(Binary::Ne, pointer, zero);
    let value = select(&mut b, function, true);
    let early = b.ret(value);
    let three = b.when(set, vec![early]);
    let (pointer, zero) = (b.read(second), b.c(64, 0));
    let set = b.bin(Binary::Ne, pointer, zero);
    let value = select(&mut b, function, false);
    let late = b.ret(value);
    let four = b.when(set, vec![late]);
    let whole = b.read(function);
    let ret = b.ret(whole);
    let f = b.done(vec![one, two, three, four, ret]);
    let (text, printed) = print_with(&f, &Style::kr(), &symbols);
    assert!(text.contains("v3 = a3 == 0 ? a1 : 0;"), "{text}");
    assert!(text.contains("v4 = a3 == 0 ? 0 : a1;"), "{text}");
    assert!(text.contains("return a3 == 0 ? a2 : 0;"), "{text}");
    assert!(text.contains("return a3 == 0 ? 0 : a2;"), "{text}");
    assert_eq!(printed.casts, 0, "{text}");
    let scratch = Scratch::new("select");
    scratch.write("out.c", &text);
    for compiler in compilers() {
        let stderr = scratch
            .compile(compiler, &["-c", "-o", "out.o"], &["out.c"])
            .unwrap_or_else(|e| panic!("{compiler} failed on\n{text}\n{e}"));
        assert_eq!(warnings(&stderr), 0, "{compiler}:\n{text}\n{stderr}");
    }
}

/// A struct of `fields` (offset, type) named `name`, `size` bytes.
fn aggregate(b: &mut Builder, name: &str, size: u64, fields: &[(u64, TypeId)]) -> TypeId {
    b.ty(Type::Struct(Aggregate {
        name: Some(name.into()),
        size,
        fields: fields
            .iter()
            .map(|&(offset, ty)| Field {
                offset,
                ty,
                name: Some(format!("field_{offset:x}")),
            })
            .collect(),
    }))
}

#[test]
fn structs_reached_through_pointers_are_packed_and_their_fields_addressed() {
    // Nothing says where a struct the program reaches through a pointer
    // lies, so each is packed, its trailing bytes spelled out (`pad_c`
    // in the 16-byte struct whose last field ends at 12), and a field's
    // address is `&p->field_8` in either, the struct of natural offsets
    // and the one with a field where its type could not lie: it becomes
    // a pointer to a type of alignment 1, on which neither compiler
    // warns (-Waddress-of-packed-member).
    let mut b = Builder::new(0x9380, "fields");
    let (int32, int64) = (b.int(32), b.int(64));
    let natural = aggregate(&mut b, "natural", 16, &[(0, int64), (8, int32)]);
    let packed = aggregate(&mut b, "packed", 12, &[(0, int32), (4, int64)]);
    let (to_natural, to_packed) = (
        b.ty(Type::Pointer(Some(natural))),
        b.ty(Type::Pointer(Some(packed))),
    );
    let (ints, longs) = (
        b.ty(Type::Pointer(Some(int32))),
        b.ty(Type::Pointer(Some(int64))),
    );
    b.f.returns = Some(int64);
    let (p, q) = (b.param(to_natural), b.param(to_packed));
    let (at_p, at_q) = (b.local(ints), b.local(longs));
    let (base, eight) = (b.read(p), b.c(64, 8));
    let sum = b.bin(Binary::Add, base, eight);
    let first = b.assign(at_p, sum);
    let (base, four) = (b.read(q), b.c(64, 4));
    let sum = b.bin(Binary::Add, base, four);
    let second = b.assign(at_q, sum);
    let (address, zero) = (b.read(at_p), b.c(32, 0));
    let clear = b.s(Stmt::Assign {
        place: Place::Memory { address, ty: int32 },
        value: zero,
    });
    let other = b.read(at_q);
    let other = b.load_at(other, 0, int64);
    let ret = b.ret(other);
    let f = b.done(vec![first, second, clear, ret]);
    let (text, _) = print_with(&f, &Style::kr(), &symbols);
    assert!(text.contains("v2 = &a1->field_8;"), "{text}");
    assert!(text.contains("v3 = &a2->field_4;"), "{text}");
    assert!(text.contains("binbun_i32_u *v2;"), "{text}");
    assert!(text.contains("uint8_t pad_c[4];"), "{text}");
    assert_eq!(text.matches("__attribute__((packed))").count(), 2, "{text}");
    let scratch = Scratch::new("fields");
    scratch.write("out.c", &text);
    for compiler in compilers() {
        let stderr = scratch
            .compile(compiler, &["-c", "-o", "out.o"], &["out.c"])
            .unwrap_or_else(|e| panic!("{compiler} failed on\n{text}\n{e}"));
        assert_eq!(warnings(&stderr), 0, "{compiler}:\n{text}\n{stderr}");
    }
}

#[test]
fn a_field_accessed_as_another_scalar_of_its_width_is_the_field() {
    // struct node { char *field_0; int32_t field_8; }: an `int64_t` load
    // of field_0 into a `void *` is the field itself (C converts
    // `char *` to `void *`), a `uint32_t` store to field_8 and a `uint32_t`
    // load of it returned as one are the field too (the same bits as C
    // converts them), none through `*(T *)&p->f`. A load of field_0 as a
    // pointer to another known type stays a conversion of the field; an
    // `int64_t` store of a `void *` to field_0 converts it to the field's
    // `char *` as C does.
    let mut b = Builder::new(0x9390, "node");
    let (int32, int64) = (b.int(32), b.int(64));
    let uint32 = b.ty(Type::UInt(32));
    let char_ty = b.ty(Type::Char { signed: true });
    let chars = b.ty(Type::Pointer(Some(char_ty)));
    let node = aggregate(&mut b, "node", 16, &[(0, chars), (8, int32)]);
    let (to_node, void, longs) = (
        b.ty(Type::Pointer(Some(node))),
        b.ty(Type::Pointer(None)),
        b.ty(Type::Pointer(Some(int64))),
    );
    b.f.returns = Some(uint32);
    let p = b.param(to_node);
    let (untyped, typed) = (b.local(void), b.local(longs));
    let base = b.read(p);
    let word = b.load_at(base, 0, int64);
    let first = b.assign(untyped, word);
    let base = b.read(p);
    let word = b.load_at(base, 0, longs);
    let second = b.assign(typed, word);
    let (base, eight, seven) = (b.read(p), b.c(64, 8), b.c(32, 7));
    let address = b.bin(Binary::Add, base, eight);
    let set = b.s(Stmt::Assign {
        place: Place::Memory {
            address,
            ty: uint32,
        },
        value: seven,
    });
    let base = b.read(p);
    let field = b.load_at(base, 8, uint32);
    let ret = b.ret(field);
    let (address, value) = (b.read(p), b.read(untyped));
    let back = b.s(Stmt::Assign {
        place: Place::Memory { address, ty: int64 },
        value,
    });
    let (address, zero) = (b.read(typed), b.c(64, 0));
    let clear = b.s(Stmt::Assign {
        place: Place::Memory { address, ty: int64 },
        value: zero,
    });
    let f = b.done(vec![first, second, set, back, clear, ret]);
    let (text, printed) = print_with(&f, &Style::kr(), &symbols);
    assert!(text.contains("v1 = a1->field_0;"), "{text}");
    assert!(text.contains("v2 = (binbun_i64_u *)a1->field_0;"), "{text}");
    assert!(text.contains("a1->field_8 = 7;"), "{text}");
    assert!(text.contains("a1->field_0 = v1;"), "{text}");
    assert!(text.contains("*v2 = 0;"), "{text}");
    assert!(text.contains("return a1->field_8;"), "{text}");
    assert_eq!(printed.casts, 1, "{text}");
    let scratch = Scratch::new("node");
    scratch.write("out.c", &text);
    for compiler in compilers() {
        let stderr = scratch
            .compile(compiler, &["-c", "-o", "out.o"], &["out.c"])
            .unwrap_or_else(|e| panic!("{compiler} failed on\n{text}\n{e}"));
        assert_eq!(warnings(&stderr), 0, "{compiler}:\n{text}\n{stderr}");
    }
}

/// A frame struct (`Function::frames`) of `fields` (entry offset, type)
/// from entry offset `start`, `size` bytes, named as lowering names them.
fn frame_struct(b: &mut Builder, start: i64, size: u64, fields: &[(i64, TypeId)]) -> TypeId {
    b.ty(Type::Struct(Aggregate {
        name: None,
        size,
        fields: fields
            .iter()
            .map(|&(at, ty)| Field {
                offset: at.abs_diff(start),
                ty,
                name: Some(format!("at_m{:x}", at.unsigned_abs())),
            })
            .collect(),
    }))
}

#[test]
fn a_union_field_is_accessed_through_the_member_of_each_width() {
    // A frame struct whose field at entry−0x18 is a union of an `int32_t`
    // `w32` and an `int64_t` `w64` (one slot written in two widths): a
    // 4-byte store and an 8-byte load there are `frame.at_m18.w32` and
    // `frame.at_m18.w64`, no cast of the field's address.
    let mut b = Builder::new(0x9400, "views");
    let (int32, int64) = (b.int(32), b.int(64));
    let views = b.ty(Type::Union(Aggregate {
        name: None,
        size: 8,
        fields: [(int32, "w32"), (int64, "w64")]
            .into_iter()
            .map(|(ty, name)| Field {
                offset: 0,
                ty,
                name: Some(name.to_owned()),
            })
            .collect(),
    }));
    let layout = frame_struct(&mut b, -0x18, 16, &[(-0x18, views), (-0x10, int64)]);
    b.f.returns = Some(int64);
    let frame = b.var(VarKind::Frame(-0x18), layout, None);
    b.f.frames.push(frame);
    let (address, seven) = (b.e(Expr::AddressOf(frame)), b.c(32, 7));
    let set = b.s(Stmt::Assign {
        place: Place::Memory { address, ty: int32 },
        value: seven,
    });
    let base = b.e(Expr::AddressOf(frame));
    let whole = b.load_at(base, 0, int64);
    let ret = b.ret(whole);
    let f = b.done(vec![set, ret]);
    let (text, printed) = print_with(&f, &Style::kr(), &symbols);
    assert!(text.contains("frame.at_m18.w32 = 7;"), "{text}");
    assert!(text.contains("return frame.at_m18.w64;"), "{text}");
    assert_eq!(printed.casts, 0, "{text}");
    let scratch = Scratch::new("views");
    scratch.write("out.c", &text);
    for compiler in compilers() {
        let stderr = scratch
            .compile(compiler, &["-c", "-o", "out.o"], &["out.c"])
            .unwrap_or_else(|e| panic!("{compiler} failed on\n{text}\n{e}"));
        assert_eq!(warnings(&stderr), 0, "{compiler}:\n{text}\n{stderr}");
    }
}

#[test]
fn the_frame_struct_and_promoted_objects_are_spelled_as_objects() {
    // A frame struct of 12 bytes (an `int64_t` at entry−0x18, an
    // `int32_t` at entry−0x10): `struct frame_<function> frame`, not packed
    // though 12 is no multiple of 8 (C's tail padding is no frame byte);
    // its fields `frame.at_m10`, their addresses `&frame.at_m10`. A
    // promoted `struct natural` at entry−0x30: a local's name, its frame
    // offset in a comment, its field `v1.field_8`.
    let mut b = Builder::new(0x9400, "frames");
    let (int32, int64) = (b.int(32), b.int(64));
    let ints = b.ty(Type::Pointer(Some(int32)));
    let layout = frame_struct(&mut b, -0x18, 12, &[(-0x18, int64), (-0x10, int32)]);
    let natural = aggregate(&mut b, "natural", 16, &[(0, int64), (8, int32)]);
    b.f.returns = Some(int32);
    let frame = b.var(VarKind::Frame(-0x18), layout, None);
    let object = b.var(VarKind::Frame(-0x30), natural, None);
    b.f.frames.push(frame);
    b.f.promoted.push(object);
    let at = b.local(ints);
    let (base, eight) = (b.e(Expr::AddressOf(frame)), b.c(64, 8));
    let address = b.bin(Binary::Add, base, eight);
    let take = b.assign(at, address);
    let (address, zero) = (b.read(at), b.c(32, 0));
    let clear = b.s(Stmt::Assign {
        place: Place::Memory { address, ty: int32 },
        value: zero,
    });
    let (base, eight) = (b.e(Expr::AddressOf(object)), b.c(64, 8));
    let address = b.bin(Binary::Add, base, eight);
    let value = b.read(at);
    let value = b.load_at(value, 0, int32);
    let set = b.s(Stmt::Assign {
        place: Place::Memory { address, ty: int32 },
        value,
    });
    let base = b.e(Expr::AddressOf(object));
    let field = b.load_at(base, 8, int32);
    let ret = b.ret(field);
    let f = b.done(vec![take, clear, set, ret]);
    let (text, _) = print_with(&f, &Style::kr(), &symbols);
    assert!(text.contains("struct frame_frames frame;"), "{text}");
    assert!(text.contains("= &frame.at_m10;"), "{text}");
    assert!(
        text.contains("struct natural v1; /* [entry-0x30] */"),
        "{text}"
    );
    assert!(text.contains("v1.field_8 = *v2;"), "{text}");
    assert!(text.contains("return v1.field_8;"), "{text}");
    // The frame's struct is the function's own object, laid out as C
    // lays it out; the other is a type pointers may reach.
    assert!(text.contains("    int32_t at_m10;\n};"), "{text}");
    assert_eq!(text.matches("__attribute__((packed))").count(), 1, "{text}");
    let scratch = Scratch::new("frames");
    scratch.write("out.c", &text);
    for compiler in compilers() {
        let stderr = scratch
            .compile(compiler, &["-c", "-o", "out.o"], &["out.c"])
            .unwrap_or_else(|e| panic!("{compiler} failed on\n{text}\n{e}"));
        assert_eq!(warnings(&stderr), 0, "{compiler}:\n{text}\n{stderr}");
    }
}

#[test]
fn indices_scaled_by_an_element_subscript_arrays_of_scalars_and_of_structs() {
    // `p + i·16 + 8` through a pointer to a 16-byte struct is
    // `p[i].field_8` (its address `&p[i].field_8`), `p + i·16` read as
    // the first field `p[i].field_0`; `q + i·8` through a pointer to a
    // 64-bit integer is `q[i]`. An index scaled by anything else than the
    // element's size is no subscript.
    let mut b = Builder::new(0x9400, "elements");
    let (int32, int64) = (b.int(32), b.int(64));
    let pair = aggregate(&mut b, "pair", 16, &[(0, int64), (8, int32)]);
    let (to_pair, longs, ints) = (
        b.ty(Type::Pointer(Some(pair))),
        b.ty(Type::Pointer(Some(int64))),
        b.ty(Type::Pointer(Some(int32))),
    );
    b.f.returns = Some(int64);
    let (p, scalars, counter) = (b.param(to_pair), b.param(longs), b.param(int64));
    let (at, sum) = (b.local(ints), b.local(int64));
    let element = |b: &mut Builder, scale: u64| {
        let (base, index, size) = (b.read(p), b.read(counter), b.c(64, scale));
        let scaled = b.bin(Binary::Mul, index, size);
        b.bin(Binary::Add, base, scaled)
    };
    let address = element(&mut b, 16);
    let eight = b.c(64, 8);
    let address = b.bin(Binary::Add, address, eight);
    let first = b.assign(at, address);
    let (address, zero) = (b.read(at), b.c(32, 0));
    let clear = b.s(Stmt::Assign {
        place: Place::Memory { address, ty: int32 },
        value: zero,
    });
    let address = element(&mut b, 16);
    let field = b.load_at(address, 8, int32);
    let field = b.ext(true, field, 64);
    let address = element(&mut b, 16);
    let whole = b.load_at(address, 0, int64);
    let total = b.bin(Binary::Add, field, whole);
    let second = b.assign(sum, total);
    let (base, index, size) = (b.read(scalars), b.read(counter), b.c(64, 8));
    let scaled = b.bin(Binary::Mul, index, size);
    let address = b.bin(Binary::Add, base, scaled);
    let scalar = b.load_at(address, 0, int64);
    let address = element(&mut b, 8);
    let odd = b.load_at(address, 8, int32);
    let odd = b.ext(true, odd, 64);
    let (total, partial) = (b.read(sum), b.bin(Binary::Add, scalar, odd));
    let total = b.bin(Binary::Add, total, partial);
    let ret = b.ret(total);
    let f = b.done(vec![first, clear, second, ret]);
    let (text, _) = print_with(&f, &Style::kr(), &symbols);
    assert!(text.contains("v3 = &a1[a3].field_8;"), "{text}");
    assert!(text.contains("a1[a3].field_8"), "{text}");
    assert!(text.contains("a1[a3].field_0"), "{text}");
    assert!(text.contains("a2[a3]"), "{text}");
    assert_eq!(text.matches("a1[").count(), 3, "{text}");
    let scratch = Scratch::new("elements");
    scratch.write("out.c", &text);
    for compiler in compilers() {
        let stderr = scratch
            .compile(compiler, &["-c", "-o", "out.o"], &["out.c"])
            .unwrap_or_else(|e| panic!("{compiler} failed on\n{text}\n{e}"));
        assert_eq!(warnings(&stderr), 0, "{compiler}:\n{text}\n{stderr}");
    }
}

#[test]
fn two_indices_scaled_by_whole_elements_are_one_subscript() {
    // `p + i·4 + j·16` through a `float *` is `p[i + j * 4]` (a column of
    // rows of four), `+ 8` after it `p[i + j * 4 + 2]`, read and written;
    // a scale that is no whole number of elements (`j·6`) is no subscript.
    let mut b = Builder::new(0x9480, "rows");
    let (int32, int64, uint64) = (b.int(32), b.int(64), b.uint(64));
    let float = b.ty(Type::Float(Format::Single));
    let floats = b.ty(Type::Pointer(Some(float)));
    b.f.returns = Some(int64);
    let (pointer, row, column) = (b.param(floats), b.param(int32), b.param(uint64));
    let at = |b: &mut Builder, by: u64, offset: u64| {
        let (base, rows, columns) = (b.read(pointer), b.read(row), b.read(column));
        let rows = b.ext(true, rows, 64);
        let (four, by) = (b.c(64, 4), b.c(64, by));
        let rows = b.bin(Binary::Mul, rows, four);
        let columns = b.bin(Binary::Mul, columns, by);
        let sum = b.bin(Binary::Add, base, rows);
        let sum = b.bin(Binary::Add, sum, columns);
        if offset == 0 {
            sum
        } else {
            let offset = b.c(64, offset);
            b.bin(Binary::Add, sum, offset)
        }
    };
    let address = at(&mut b, 16, 8);
    let zero = b.c(32, 0);
    let store = b.s(Stmt::Assign {
        place: Place::Memory { address, ty: float },
        value: zero,
    });
    let address = at(&mut b, 16, 0);
    let element = b.load_at(address, 0, float);
    let address = at(&mut b, 6, 0);
    let odd = b.load_at(address, 0, float);
    let element = b.e(Expr::Cast {
        value: element,
        ty: int32,
    });
    let odd = b.e(Expr::Cast {
        value: odd,
        ty: int32,
    });
    let total = b.bin(Binary::Add, element, odd);
    let total = b.ext(true, total, 64);
    let ret = b.ret(total);
    let function = b.done(vec![store, ret]);
    let (text, _) = print_with(&function, &Style::kr(), &symbols);
    assert!(text.contains("a1[a2 + a3 * 4 + 2] = "), "{text}");
    assert!(text.contains("a1[a2 + a3 * 4]"), "{text}");
    assert_eq!(text.matches("a1[").count(), 2, "{text}");
    let scratch = Scratch::new("rows");
    scratch.write("out.c", &text);
    for compiler in compilers() {
        let stderr = scratch
            .compile(compiler, &["-c", "-o", "out.o"], &["out.c"])
            .unwrap_or_else(|e| panic!("{compiler} failed on\n{text}\n{e}"));
        assert_eq!(warnings(&stderr), 0, "{compiler}:\n{text}\n{stderr}");
    }
}

#[test]
fn reserved_prefixes_are_prefixed_and_double_underscores_kept() {
    // `__stack_chk_fail` is what every hardened binary calls: kept. A name
    // starting like binbun_defs.h's helpers or the compilers' builtins cannot
    // be fixed by a suffix (`binbun_trap_2` still starts with `binbun_`);
    // it gets an `x` in front and links to its symbol.
    let names = |address: u64| match address {
        0x5000 => Some("__stack_chk_fail".to_owned()),
        0x6000 => Some("binbun_trap".to_owned()),
        0x7000 => Some("__builtin_trap".to_owned()),
        other => symbols(other),
    };
    let (text, _) = print_with(&calls(), &Style::kr(), &names);
    assert!(text.contains("*__stack_chk_fail(void *"), "{text}");
    assert!(
        text.contains("xbinbun_trap(int32_t) BINBUN_SYMBOL(\"binbun_trap\")"),
        "{text}"
    );
    assert!(
        text.contains("x__builtin_trap(uint64_t) BINBUN_SYMBOL(\"__builtin_trap\")"),
        "{text}"
    );
}

#[test]
fn a_load_after_stores_through_pointers_that_overlap_in_part_reads_memory() {
    // `*a = 1; *b = 1; return *a;` on 32-bit words: with `b` one byte on
    // from `a` the machine returns 257, the second store having written
    // into the first word. Through two `int32_t *` GCC at -O2 returns 1
    // without reading (aligned words are the same or apart); what the
    // pointers point to is of alignment 1, and both compilers read.
    let mut b = Builder::new(0x9500, "twice");
    let int32 = b.int(32);
    let ints = b.ty(Type::Pointer(Some(int32)));
    b.f.returns = Some(int32);
    let (first, second) = (b.param(ints), b.param(ints));
    let mut body = Vec::new();
    for pointer in [first, second] {
        let (address, value) = (b.read(pointer), b.c(32, 1));
        body.push(b.s(Stmt::Assign {
            place: Place::Memory { address, ty: int32 },
            value,
        }));
    }
    let address = b.read(first);
    let value = b.load_at(address, 0, int32);
    body.push(b.ret(value));
    let f = b.done(body);
    let (text, _) = print_with(&f, &Style::kr(), &symbols);
    assert!(
        text.contains("int32_t twice(binbun_i32_u *a1, binbun_i32_u *a2)"),
        "{text}"
    );
    let scratch = Scratch::new("overlap");
    scratch.write("out.c", &text);
    scratch.write(
        "main.c",
        "#include <stdio.h>\n#include <string.h>\nint twice(void *, void *);\n\
         int main(void) {\n    static unsigned char bytes[16];\n\
         \x20   for (int offset = 0; offset <= 4; offset++) {\n\
         \x20       memset(bytes, 0, sizeof bytes);\n\
         \x20       printf(\"%d \", twice(bytes + 4, bytes + 4 + offset));\n    }\n\
         \x20   return 0;\n}\n",
    );
    for compiler in compilers() {
        for opt in ["-O0", "-O2"] {
            scratch
                .compile(compiler, &[opt, "-o", "overlap"], &["out.c", "main.c"])
                .unwrap_or_else(|e| panic!("{compiler} {opt} failed on\n{text}\n{e}"));
            assert_eq!(
                scratch.run("overlap"),
                "1 257 65537 16777217 1 ",
                "{compiler} {opt}"
            );
        }
    }
}

#[test]
fn every_escape_is_counted_and_spelled_with_its_helper() {
    let (text, counts) = print_with(&escapes(), &Style::kr(), &symbols);
    assert_eq!(counts.escapes, 8, "{text}");
    for helper in [
        "binbun_unresolved_jump(",
        "binbun_foreign_jump(",
        "binbun_overlapping_code(",
        "binbun_non_standard_call(",
        "binbun_stack_trick(",
        "binbun_syscall(",
        "binbun_atomic_load32(",
        "binbun_atomic_store32(",
        "binbun_result(1)",
        "binbun_unreachable()",
    ] {
        assert!(text.contains(helper), "{helper} missing:\n{text}");
    }
}
