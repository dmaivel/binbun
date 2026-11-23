#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers fail loudly"
)]

//! The image's data in the output: globals in read-only memory declared
//! `const` (after the `*` of a pointer) unless the function writes them, a
//! `char` array in read-only
//! memory holding a string printed as its literal (escaped), one that is
//! not (writable, or no NUL at its end) named and declared, a function's
//! address as `&f` with its prototype, plain `char` as `char`; compiled
//! with GCC and Clang without warnings.

mod common;

use std::collections::BTreeMap;

use binbun_ast::ir::{Callee, Expr, Function, Place, Stmt, VarKind};
use binbun_ast::types::Type;
use binbun_print::c::Image;
use binbun_print::style::Style;
use binbun_semantics::ir::Binary;
use common::{Builder, Scratch, compilers, print_with, warnings};

/// An image: names, and read-only ranges with their bytes (`buffer`, at
/// 0x7000, is writable).
struct Data {
    names: BTreeMap<u64, &'static str>,
    read_only: Vec<(u64, &'static [u8])>,
}

impl Image for Data {
    fn symbol(&self, address: u64) -> Option<String> {
        self.names.get(&address).map(|&name| name.to_owned())
    }

    fn read_only(&self, address: u64, bytes: u64) -> bool {
        self.read_only
            .iter()
            .any(|&(start, data)| address >= start && address + bytes <= start + data.len() as u64)
    }

    fn constant(&self, address: u64, bytes: u64) -> Option<Vec<u8>> {
        self.read_only.iter().find_map(|&(start, data)| {
            let from = usize::try_from(address.checked_sub(start)?).ok()?;
            data.get(from..from + usize::try_from(bytes).ok()?)
                .map(<[u8]>::to_vec)
        })
    }

    fn string(&self, address: u64) -> Option<Vec<u8>> {
        self.read_only.iter().find_map(|&(start, data)| {
            let rest = data.get(usize::try_from(address.checked_sub(start)?).ok()?..)?;
            let end = rest.iter().position(|&byte| byte == 0)?;
            rest.get(..end).map(<[u8]>::to_vec)
        })
    }
}

fn image() -> Data {
    Data {
        names: BTreeMap::from([
            (0x5000, "table"),
            (0x5100, "hook"),
            (0x7000, "buffer"),
            (0x8000, "puts"),
            (0x8100, "atexit"),
            (0x9000, "cleanup"),
        ]),
        read_only: vec![
            (0x5000, &[1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 4, 0, 0, 0]),
            (0x5100, &[0; 8]),
            (0x6000, b"q\"\\\n\x01??=\0"),
            (0x6100, b"abc"),
        ],
    }
}

/// `puts(<string>); puts(<buffer>); puts(<no NUL>); atexit(&cleanup);
/// v = table[2] + *hook; table[0] = v; return v;`
fn data() -> Function {
    let mut b = Builder::new(0x4000, "data");
    let (int32, character) = (b.int(32), b.ty(Type::Char { signed: true }));
    b.f.returns = Some(int32);
    let string = |b: &mut Builder, length| {
        b.ty(Type::Array {
            element: character,
            length: Some(length),
        })
    };
    let quoted = string(&mut b, 9);
    let quoted = b.var(VarKind::Global(0x6000), quoted, None);
    let buffer = string(&mut b, 3);
    let buffer = b.var(VarKind::Global(0x7000), buffer, None);
    let unterminated = string(&mut b, 3);
    let unterminated = b.var(VarKind::Global(0x6100), unterminated, None);
    let elements = b.ty(Type::Array {
        element: int32,
        length: Some(4),
    });
    let table = b.var(VarKind::Global(0x5000), elements, None);
    let int_ptr = b.ty(Type::Pointer(Some(int32)));
    let hook = b.var(VarKind::Global(0x5100), int_ptr, None);
    let char_ptr = b.ty(Type::Pointer(Some(character)));
    let puts = b.code(vec![char_ptr], Some(int32), false);
    let handler = b.code(Vec::new(), None, false);
    let atexit = b.code(vec![handler], Some(int32), false);
    let mut body = Vec::new();
    for var in [quoted, buffer, unterminated] {
        let address = b.e(Expr::AddressOf(var));
        body.push(b.call(Callee::Address(0x8000), vec![address], puts, Vec::new()));
    }
    let entry = b.c(64, 0x9000);
    let cleanup = b.cast(entry, handler);
    body.push(b.call(Callee::Address(0x8100), vec![cleanup], atexit, Vec::new()));
    let base = b.e(Expr::AddressOf(table));
    let element = b.load_at(base, 8, int32);
    let hooked = b.read(hook);
    let target = b.load_at(hooked, 0, int32);
    let sum = b.bin(Binary::Add, element, target);
    let local = b.local(int32);
    body.push(b.assign(local, sum));
    let stored = b.read(local);
    body.push(b.s(Stmt::Assign {
        place: Place::Memory {
            address: base,
            ty: int32,
        },
        value: stored,
    }));
    let result = b.read(local);
    body.push(b.ret(result));
    b.done(body)
}

#[test]
fn read_only_data_reads_as_constants_strings_and_functions() {
    let image = image();
    let (text, _) = print_with(&data(), &Style::kr(), &image);
    for expected in [
        // In read-only memory, but written: not `const` (C would refuse
        // the write the binary makes, and faults on).
        "extern int32_t table[4];",
        "extern binbun_i32_u *const hook;",
        "extern char buffer[3];",
        "int32_t puts(char *);",
        "puts(\"q\\\"\\\\\\n\\001?\\?=\");",
        "puts(buffer);",
        "atexit(&cleanup);",
        "void cleanup(void);",
        "table[2] + *hook",
    ] {
        assert!(text.contains(expected), "no {expected:?} in\n{text}");
    }
    // Bytes without a NUL at the end are no string: the array, named.
    assert!(text.contains("extern const char g_6100[3];"), "{text}");
    assert!(text.contains("puts(g_6100);"), "{text}");
    // Nothing here is at a constant address: no `volatile`.
    assert!(!text.contains("volatile"), "{text}");
}

#[test]
fn read_only_data_compiles_without_warnings() {
    let compilers = compilers();
    if compilers.is_empty() {
        eprintln!("skipped: neither gcc nor clang found");
        return;
    }
    let scratch = Scratch::new("data");
    let (text, _) = print_with(&data(), &Style::kr(), &image());
    scratch.write("out.c", &text);
    for compiler in compilers {
        let stderr = scratch
            .compile(compiler, &["-c", "-o", "out.o"], &["out.c"])
            .unwrap_or_else(|e| panic!("{compiler} failed on\n{text}\n{e}"));
        assert_eq!(warnings(&stderr), 0, "{compiler}:\n{text}\n{stderr}");
    }
}
