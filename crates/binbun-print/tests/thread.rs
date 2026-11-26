#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers fail loudly"
)]

//! The thread pointer (an environment variable) as each platform spells
//! it: on Windows x64 Microsoft's `__readgs…`/`__writegs…` intrinsics for
//! accesses at an offset from it and `NtCurrentTeb()` for its value; on
//! ELF platforms `__builtin_thread_pointer()` and accesses through it.
//! Both compile with GCC and Clang without warnings.

mod common;

use binbun_ast::ir::{Function, Place, Stmt, VarKind};
use binbun_ast::types::Type;
use binbun_print::c::{Image, ThreadPointer};
use binbun_print::style::Style;
use binbun_semantics::ir::{Binary, Format, RegisterId};
use binbun_semantics::{Declarations, RegisterInfo};
use common::{Builder, Scratch, compilers, print_with, warnings};

/// Names nothing; the thread pointer is Windows' TEB (user mode) or KPCR
/// (kernel mode), in x64's `gs` or ARM64's `x18`.
struct Windows(ThreadPointer);

/// Names nothing; register 0 is no thread pointer (a floating-point
/// control register).
struct FloatControl;

impl Image for FloatControl {
    fn symbol(&self, _: u64) -> Option<String> {
        None
    }

    fn read_only(&self, _: u64, _: u64) -> bool {
        false
    }

    fn constant(&self, _: u64, _: u64) -> Option<Vec<u8>> {
        None
    }

    fn is_thread_pointer(&self, register: RegisterId) -> bool {
        register != RegisterId(0)
    }

    fn string(&self, _: u64) -> Option<Vec<u8>> {
        None
    }
}

/// Register 0 named `mxcsr`.
const MXCSR: Declarations = Declarations {
    registers: &[RegisterInfo {
        name: "mxcsr",
        width: 64,
    }],
    intrinsics: &[],
    sites: &[],
};

/// `return (int64_t)extract(env, 13, 2);`: the rounding mode of the
/// environment register 0.
fn rounding_mode() -> Function {
    let mut b = Builder::new(0x5000, "rounding_mode");
    let int64 = b.int(64);
    b.f.returns = Some(int64);
    let bits = b.bits(64);
    let environment = b.var(VarKind::Environment(RegisterId(0)), bits, None);
    let read = b.read(environment);
    let mode = b.bits_of(read, 13, 2);
    let wide = b.ext(false, mode, 64);
    let body = vec![b.ret(wide)];
    b.done(body)
}

#[test]
fn a_float_control_register_is_read_once_at_entry() {
    // Not the thread pointer's spelling: its value at entry, read into a
    // local before anything else runs.
    let printed = binbun_print::c::function(
        &rounding_mode(),
        &MXCSR,
        &Style::kr(),
        &FloatControl,
        binbun_print::c::Opaque::Calls,
    )
    .unwrap();
    let text = binbun_print::layout::render(&printed.document, &Style::kr());
    let declared = text.find(" mxcsr_entry = binbun_read_mxcsr();").unwrap();
    let used = text.find("return (mxcsr_entry >> 13)").unwrap();
    assert!(declared < used, "{text}");
    assert!(
        !text.contains("thread_pointer") && !text.contains("NtCurrentTeb"),
        "{text}"
    );
    if !cfg!(target_arch = "x86_64") {
        return;
    }
    let scratch = Scratch::new("float_control");
    scratch.write("mode.c", &text);
    for compiler in compilers() {
        let stderr = scratch
            .compile(compiler, &["-c", "-o", "out.o"], &["mode.c"])
            .unwrap_or_else(|e| panic!("{compiler} failed on\n{text}\n{e}"));
        assert_eq!(warnings(&stderr), 0, "{compiler}:\n{text}\n{stderr}");
    }
}

impl Image for Windows {
    fn symbol(&self, _: u64) -> Option<String> {
        None
    }

    fn read_only(&self, _: u64, _: u64) -> bool {
        false
    }

    fn constant(&self, _: u64, _: u64) -> Option<Vec<u8>> {
        None
    }

    fn thread_pointer(&self) -> ThreadPointer {
        self.0
    }

    fn string(&self, _: u64) -> Option<Vec<u8>> {
        None
    }
}

/// `p = *(int64_t **)(tp + 0x30); n = *(int32_t *)(tp + i * 8 + 0x10);
/// *(uint16_t *)(tp + 0x2c) = n; (void)*(uint8_t *)(tp + 8);
/// q = *(double *)(tp + 0x18); return tp + *p + n + (int64_t)q bits;`
fn thread() -> Function {
    let mut b = Builder::new(0x4000, "thread");
    let (int64, int32, uint16, uint8) = (b.int(64), b.int(32), b.uint(16), b.uint(8));
    let double = b.ty(Type::Float(Format::Double));
    let pointer = b.ty(Type::Pointer(Some(int64)));
    b.f.returns = Some(int64);
    let i = b.param(int64);
    let bits = b.bits(64);
    let tp = b.var(VarKind::Environment(RegisterId(0)), bits, None);
    let mut body = Vec::new();
    let base = b.read(tp);
    let self_pointer = b.load_at(base, 0x30, pointer);
    let own_address = b.local(pointer);
    body.push(b.assign(own_address, self_pointer));
    let index = b.read(i);
    let eight = b.c(64, 8);
    let scaled = b.bin(Binary::Mul, index, eight);
    let base = b.read(tp);
    let indexed = b.bin(Binary::Add, base, scaled);
    let element = b.load_at(indexed, 0x10, int32);
    let n = b.local(int32);
    body.push(b.assign(n, element));
    let base = b.read(tp);
    let offset = b.c(64, 0x2c);
    let address = b.bin(Binary::Add, base, offset);
    let read = b.read(n);
    let low = b.bits_of(read, 0, 16);
    body.push(b.s(Stmt::Assign {
        place: Place::Memory {
            address,
            ty: uint16,
        },
        value: low,
    }));
    let base = b.read(tp);
    let dropped = b.load_at(base, 8, uint8);
    body.push(b.s(Stmt::Expr(dropped)));
    let base = b.read(tp);
    let float = b.load_at(base, 0x18, double);
    let ratio = b.local(double);
    body.push(b.assign(ratio, float));
    let own = b.read(tp);
    let through = b.read(own_address);
    let target = b.load_at(through, 0, int64);
    let sum = b.bin(Binary::Add, own, target);
    let read = b.read(n);
    let wide = b.ext(true, read, 64);
    let sum = b.bin(Binary::Add, sum, wide);
    let read = b.read(ratio);
    let as_bits = b.cast(read, int64);
    let sum = b.bin(Binary::Add, sum, as_bits);
    body.push(b.ret(sum));
    b.done(body)
}

#[test]
fn windows_reads_and_writes_the_teb_with_microsofts_intrinsics() {
    let (text, _) = print_with(&thread(), &Style::kr(), &Windows(ThreadPointer::Teb));
    for expected in [
        "thread(int64_t a1)",
        "(binbun_i64_u *)__readgsqword(48)",
        "__readgsdword(a1 * 8 + 16)",
        "__writegsword(44, ",
        "(void)__readgsbyte(8);",
        "as_f64(__readgsqword(24))",
        "NtCurrentTeb()",
    ] {
        assert!(text.contains(expected), "no {expected:?} in\n{text}");
    }
    // The thread pointer is no parameter, no variable.
    assert!(!text.contains("a2"), "{text}");
    assert!(!text.contains("__builtin_thread_pointer"), "{text}");
}

#[test]
fn kernel_mode_reads_and_writes_the_kpcr_with_the_same_intrinsics() {
    let teb = print_with(&thread(), &Style::kr(), &Windows(ThreadPointer::Teb)).0;
    let (text, _) = print_with(&thread(), &Style::kr(), &Windows(ThreadPointer::Kpcr));
    // The same single gs-relative accesses; the value is the KPCR's.
    assert_eq!(text, teb.replace("NtCurrentTeb()", "KeGetPcr()"));
    assert!(text.contains("KeGetPcr()"), "{text}");
}

#[test]
fn elf_reaches_memory_through_the_builtin_thread_pointer() {
    let (text, _) = print_with(&thread(), &Style::kr(), &|_: u64| None);
    for expected in [
        "thread(int64_t a1)",
        "typedef binbun_i64_u *int64_t_p_u __attribute__((aligned(1)));",
        "*(int64_t_p_u *)(__builtin_thread_pointer() + 48)",
        "*(binbun_u16_u *)(__builtin_thread_pointer() + 44) = ",
    ] {
        assert!(text.contains(expected), "no {expected:?} in\n{text}");
    }
    assert!(!text.contains("__readgs"), "{text}");
    assert!(!text.contains("NtCurrentTeb"), "{text}");
}

/// Windows ARM64's TEB and KPCR are in `x18`, an ordinary register: no
/// segment intrinsic, memory reached through `NtCurrentTeb()` or
/// `KeGetPcr()` as ELF's through the builtin, as a `void *` as the
/// builtin is (a `struct _TEB *` would count structures; compared without
/// white space: the longer name breaks lines elsewhere).
#[test]
fn windows_arm64_reaches_memory_through_x18s_pointer() {
    let bare = |text: &str| -> String { text.split_whitespace().collect() };
    let elf = bare(&print_with(&thread(), &Style::kr(), &|_: u64| None).0);
    for (pointer, value) in [
        (ThreadPointer::TebX18, "NtCurrentTeb()"),
        (ThreadPointer::KpcrX18, "KeGetPcr()"),
    ] {
        let (text, _) = print_with(&thread(), &Style::kr(), &Windows(pointer));
        assert_eq!(
            bare(&text),
            elf.replace("__builtin_thread_pointer()", &format!("(void*){value}")),
            "{text}"
        );
    }
}

#[test]
fn both_spellings_compile_without_warnings() {
    let compilers = compilers();
    if compilers.is_empty() {
        eprintln!("skipped: no C compiler to check with");
        return;
    }
    let scratch = Scratch::new("thread");
    let windows = print_with(&thread(), &Style::kr(), &Windows(ThreadPointer::Teb)).0;
    let kernel = print_with(&thread(), &Style::kr(), &Windows(ThreadPointer::Kpcr)).0;
    let arm64 = print_with(&thread(), &Style::kr(), &Windows(ThreadPointer::TebX18)).0;
    let elf = print_with(&thread(), &Style::kr(), &|_: u64| None).0;
    scratch.write("windows.c", &windows);
    scratch.write("kernel.c", &kernel);
    scratch.write("arm64.c", &arm64);
    scratch.write("elf.c", &elf);
    for compiler in compilers {
        for (file, text) in [
            ("windows.c", &windows),
            ("kernel.c", &kernel),
            ("arm64.c", &arm64),
            ("elf.c", &elf),
        ] {
            // binbun_defs.h defines the Windows x64 intrinsics for x86-64 only
            // (NtCurrentTeb() on AArch64 too).
            let anywhere = matches!(file, "elf.c" | "arm64.c");
            if !anywhere && !cfg!(target_arch = "x86_64") {
                continue;
            }
            let stderr = scratch
                .compile(compiler, &["-c", "-o", "out.o"], &[file])
                .unwrap_or_else(|e| panic!("{compiler} failed on\n{text}\n{e}"));
            assert_eq!(warnings(&stderr), 0, "{compiler}:\n{text}\n{stderr}");
        }
    }
}
