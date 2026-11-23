#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers fail loudly"
)]

//! Enumerations' constants by name: an argument of a set of flags as the
//! flags it holds (bits no flag names in hexadecimal), a comparison with
//! and a case of a switch on a value of a plain enumeration as the
//! constant equal to it, the number where none is or the name is another
//! name; each enumeration defined with only the constants used and its
//! underlying type; values of one declared with its tag (its integer
//! where the tag is another name); compiled in both views with GCC and
//! Clang without warnings.

mod common;

use binbun_ast::ir::{Callee, Function, Stmt};
use binbun_ast::types::{Enumeration, Type};
use binbun_print::c::{self, Opaque};
use binbun_print::layout;
use binbun_print::style::Style;
use binbun_semantics::ir::Binary;
use common::{Builder, DECLARATIONS, Scratch, arm, compilers, warnings};

/// `ACCESS_MASK`, flags of 32 bits.
fn access() -> Enumeration {
    Enumeration {
        name: Some("ACCESS_MASK".to_owned()),
        width: 32,
        signed: false,
        flags: true,
        macros: false,
        constants: vec![
            ("GENERIC_READ".to_owned(), 0x8000_0000),
            ("GENERIC_WRITE".to_owned(), 0x4000_0000),
            ("GENERIC_ALL".to_owned(), 0x1000_0000),
        ],
    }
}

/// `FILE_TYPE`, a plain signed enumeration of 32 bits; `FILE_TYPE_REMOTE`
/// is also the function's name.
fn file_type() -> Enumeration {
    Enumeration {
        name: Some("FILE_TYPE".to_owned()),
        width: 32,
        signed: true,
        flags: false,
        macros: false,
        constants: vec![
            ("FILE_TYPE_UNKNOWN".to_owned(), 0),
            ("FILE_TYPE_DISK".to_owned(), 1),
            ("FILE_TYPE_CHAR".to_owned(), 2),
            ("FILE_TYPE_REMOTE".to_owned(), 0x8000),
            ("FILE_TYPE_ERROR".to_owned(), 0xffff_ffff),
        ],
    }
}

/// `open_flags`: flags whose constants are macros in C's headers, with
/// the values of glibc's `<fcntl.h>` on x86-64 and AArch64.
fn open_flags() -> Enumeration {
    Enumeration {
        name: Some("open_flags".to_owned()),
        width: 32,
        signed: true,
        flags: true,
        macros: true,
        constants: vec![
            ("O_WRONLY".to_owned(), 1),
            ("O_RDWR".to_owned(), 2),
            ("O_CREAT".to_owned(), 0x40),
            ("O_NONBLOCK".to_owned(), 0x800),
        ],
    }
}

/// `void opens(open_flags a1)`: `sub_3000(O_RDWR | O_NONBLOCK)`,
/// `sub_3000(O_WRONLY | O_CREAT)`, `sub_3000(a1)` (a callee of no name:
/// `open` would be `<fcntl.h>`'s, of another type).
fn opens() -> Function {
    let mut b = Builder::new(0x1000, "opens");
    let flags = b.ty(Type::Enum(open_flags()));
    let a1 = b.param(flags);
    let open = b.code(vec![flags], None, false);
    let mut body = Vec::new();
    for value in [0x802, 0x41] {
        let argument = b.c(32, value);
        body.push(b.call(Callee::Address(0x3000), vec![argument], open, Vec::new()));
    }
    let argument = b.read(a1);
    body.push(b.call(Callee::Address(0x3000), vec![argument], open, Vec::new()));
    b.done(body)
}

/// Constants that are macros in C's headers are defined as the macros
/// they are where no header has (`#ifndef O_RDWR`), and a value of their
/// set has its integer type, no tag: the C compiles alone and after the
/// headers (an `enum` of `O_RDWR` there was `{ 2 = 2 }`).
#[test]
fn macro_constants_are_defined_as_macros_where_no_header_has() {
    let text = printed(&opens(), Opaque::Calls);
    let lines: Vec<&str> = text.lines().map(str::trim).collect();
    for line in [
        "#ifndef O_RDWR",
        "#define O_RDWR 2",
        "#ifndef O_NONBLOCK",
        "#define O_NONBLOCK 0x800",
        "#define O_CREAT 64",
        "#endif",
        "void opens(int32_t a1)",
        "sub_3000(O_RDWR | O_NONBLOCK);",
        "sub_3000(O_WRONLY | O_CREAT);",
        "sub_3000(a1);",
    ] {
        assert!(lines.contains(&line), "{line} in\n{text}");
    }
    assert!(!text.contains("enum"), "{text}");
    let compilers = compilers();
    if compilers.is_empty() {
        eprintln!("no C compiler found; skipping the compile");
        return;
    }
    let scratch = Scratch::new("macro-constants");
    scratch.write("out.c", &text);
    let headers: &[&[&str]] = if cfg!(unix) {
        &[&[], &["-include", "fcntl.h"]]
    } else {
        &[&[]]
    };
    for &compiler in &compilers {
        for &extra in headers {
            let mut flags = vec!["-std=c11", "-Wall", "-c", "-o", "out.o"];
            flags.extend(extra);
            let stderr = scratch
                .compile(compiler, &flags, &["out.c"])
                .unwrap_or_else(|e| panic!("{compiler} {extra:?} failed on\n{text}\n{e}"));
            assert_eq!(
                warnings(&stderr),
                0,
                "{compiler} {extra:?}:\n{text}\n{stderr}"
            );
        }
    }
}

/// `int32_t FILE_TYPE_REMOTE(FILE_TYPE a1)`: `open(GENERIC_READ |
/// GENERIC_WRITE)`, `open(GENERIC_READ | 1)`, `open(0x20000000)`; then a
/// switch on `a1` with cases 1, 2 and 7; then `a1 == 2`, `a1 == 3`,
/// `a1 == 0x8000`, `a1 == -1` as a sum returned.
fn function() -> Function {
    let mut b = Builder::new(0x1000, "FILE_TYPE_REMOTE");
    let int32 = b.int(32);
    b.f.returns = Some(int32);
    let mask = b.ty(Type::Enum(access()));
    let kind = b.ty(Type::Enum(file_type()));
    let a1 = b.param(kind);
    let open = b.code(vec![mask], None, false);
    let mut body = Vec::new();
    for value in [0xc000_0000, 0x8000_0001, 0x2000_0000] {
        let argument = b.c(32, value);
        body.push(b.call(Callee::Address(0x2000), vec![argument], open, Vec::new()));
    }
    let result = b.local(int32);
    let zero = b.c(32, 0);
    body.push(b.assign(result, zero));
    let arms = [1, 2, 7]
        .into_iter()
        .map(|case| {
            let x = b.read(result);
            let one = b.c(32, case);
            let sum = b.bin(Binary::Add, x, one);
            let set = b.assign(result, sum);
            arm(&[case], 32, false, vec![set], false)
        })
        .collect();
    let scrutinee = b.read(a1);
    body.push(b.s(Stmt::Switch { scrutinee, arms }));
    let mut sum = b.read(result);
    for value in [2, 3, 0x8000, 0xffff_ffff] {
        let x = b.read(a1);
        let constant = b.c(32, value);
        let equal = b.bin(Binary::Eq, x, constant);
        let wide = b.ext(false, equal, 32);
        sum = b.bin(Binary::Add, sum, wide);
    }
    body.push(b.ret(sum));
    b.done(body)
}

/// `f` printed in the view `opaque` stands for, `open` the callee's name.
fn printed(f: &Function, opaque: Opaque) -> String {
    let image = |address: u64| (address == 0x2000).then(|| "open".to_owned());
    let printed = c::function(f, &DECLARATIONS, &Style::kr(), &image, opaque).unwrap();
    layout::render(&printed.document, &Style::kr())
}

#[test]
fn constants_print_by_name_where_c_gives_the_name_the_same_value() {
    for opaque in [Opaque::Calls, Opaque::Asm] {
        let text = printed(&function(), opaque);
        let lines: Vec<&str> = text.lines().map(str::trim).collect();
        for line in [
            "open(GENERIC_READ | GENERIC_WRITE);",
            "open(GENERIC_READ | 0x1);",
            // No flag names it.
            "open(0x20000000);",
            "case FILE_TYPE_DISK:",
            "case FILE_TYPE_CHAR:",
            "case 7:",
            "enum ACCESS_MASK : uint32_t {",
            "GENERIC_READ = 0x80000000,",
            "GENERIC_WRITE = 0x40000000,",
            "enum FILE_TYPE : int32_t {",
            "FILE_TYPE_DISK = 1,",
            "FILE_TYPE_CHAR = 2,",
            "FILE_TYPE_ERROR = -1,",
        ] {
            assert!(lines.contains(&line), "{line} in\n{text}");
        }
        assert!(text.contains("a1 == FILE_TYPE_CHAR"), "{text}");
        assert!(text.contains("a1 == 3"), "{text}");
        assert!(text.contains("a1 == FILE_TYPE_ERROR"), "{text}");
        // The function's own name: the number.
        assert!(text.contains("a1 == 0x8000"), "{text}");
        // The parameter has the enumeration's type; the switch on it is on
        // its integer type (`case 7` is no constant of it).
        assert!(
            lines.contains(&"int32_t FILE_TYPE_REMOTE(enum FILE_TYPE a1)"),
            "{text}"
        );
        assert!(lines.contains(&"switch ((int32_t)a1) {"), "{text}");
        // Defined only where used.
        for unused in ["GENERIC_ALL", "FILE_TYPE_UNKNOWN", "FILE_TYPE_REMOTE ="] {
            assert!(!text.contains(unused), "{unused} in\n{text}");
        }
    }
}

#[test]
fn named_constants_compile_without_warnings() {
    let compilers = compilers();
    if compilers.is_empty() {
        eprintln!("no C compiler found; skipping");
        return;
    }
    let scratch = Scratch::new("enums");
    for (f, opaque) in [function(), typed_only("adjust")]
        .iter()
        .flat_map(|f| [(f, Opaque::Calls), (f, Opaque::Asm)])
    {
        let text = printed(f, opaque);
        scratch.write("out.c", &text);
        for &compiler in &compilers {
            let stderr = scratch
                .compile(
                    compiler,
                    &["-std=c11", "-Wall", "-c", "-o", "out.o", "-O2"],
                    &["out.c"],
                )
                .unwrap_or_else(|e| panic!("{compiler} failed on\n{text}\n{e}"));
            assert_eq!(warnings(&stderr), 0, "{compiler}:\n{text}\n{stderr}");
        }
    }
}

#[test]
fn flags_decompose_only_into_whole_flags_widest_first() {
    let mut flags = access();
    flags.constants.push(("GENERIC_RW".to_owned(), 0xc000_0000));
    let named = flags.named(0xc000_0001).unwrap();
    assert_eq!(named.names, ["GENERIC_RW"]);
    assert_eq!(named.rest, 1);
    // No flag in it: no name.
    assert_eq!(flags.named(0x2000_0000), None);
    // A plain enumeration: only a constant equal to it.
    let plain = file_type();
    assert_eq!(plain.named(3), None);
    assert_eq!(plain.named(0xffff_ffff).unwrap().names, ["FILE_TYPE_ERROR"]);
    assert_eq!(plain.number(0xffff_ffff), -1);
}

/// `ACCESS_MASK name(ACCESS_MASK a1)`: a local of `ACCESS_MASK` set to
/// `a1 + 1` and returned; no constant of it named.
fn typed_only(name: &str) -> Function {
    let mut b = Builder::new(0x1000, name);
    let mask = b.ty(Type::Enum(access()));
    b.f.returns = Some(mask);
    let a1 = b.param(mask);
    let local = b.local(mask);
    let x = b.read(a1);
    let one = b.c(32, 1);
    let sum = b.bin(Binary::Add, x, one);
    let set = b.assign(local, sum);
    let back = b.read(local);
    let ret = b.ret(back);
    b.done(vec![set, ret])
}

#[test]
fn values_of_an_enumeration_are_declared_with_its_tag() {
    for opaque in [Opaque::Calls, Opaque::Asm] {
        let text = printed(&typed_only("adjust"), opaque);
        let lines: Vec<&str> = text.lines().map(str::trim).collect();
        // No constant named: declared with its underlying type alone.
        assert!(lines.contains(&"enum ACCESS_MASK : uint32_t;"), "{text}");
        assert!(
            lines.contains(&"enum ACCESS_MASK adjust(enum ACCESS_MASK a1)"),
            "{text}"
        );
        let locals = lines
            .iter()
            .filter(|line| line.starts_with("enum ACCESS_MASK ") && !line.contains(['(', ':']))
            .count();
        assert_eq!(locals, 1, "{text}");
        // A tag another name has: declared as its integer, no enumeration.
        let text = printed(&typed_only("ACCESS_MASK"), opaque);
        assert!(!text.contains("enum "), "{text}");
        assert!(text.contains("uint32_t ACCESS_MASK(uint32_t a1)"), "{text}");
    }
}
