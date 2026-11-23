//! The C API from C and C++: `tests/c/disasm_test.c` and
//! `tests/cpp/disasm_test.cpp`, compiled with the system's `cc` and `c++`
//! (MSVC's `cl` on Windows, `support/compile.rs`) against the library
//! cargo built for this test, sweep the code of the checked-in fixtures;
//! what they print must be what the Rust API says (the decoders', and
//! `binbun-disasm`'s for the decoder of either architecture), printed here
//! in the same notation, instruction by instruction.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers fail loudly"
)]

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::LazyLock;

use binbun_aarch64::operand::{
    ElementSize, Extend, ExtendKind, LabelBase, ListStyle, Memory, Modifier, NameKind, Offset,
    Operand as A64Operand, Predication, Radix, Register as A64Register, RegisterClass, ShiftKind,
    SliceDirection, Writeback, Za, ZaList,
};
use binbun_aarch64::{
    Access, CompareOperand, Condition as A64Condition, Decoder as A64Decoder, Error, LabelStyle,
    MemoryKind,
};
use binbun_disasm::Arch as DisasmArch;
use binbun_isa::{Flow, Instruction as _, Target};
use binbun_x86::{
    Action, Condition, DecodeError, Decoder, Encoding, Instruction, Mode, Operand, Register, Value,
    Visibility,
};
use object::{Architecture, Object, ObjectSection, SectionKind};

#[path = "support/compile.rs"]
mod compile;

use compile::{Language, Library};

/// The crate's directory.
fn manifest() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

/// This process's scratch directory: a runner that gives each test its own
/// process (nextest) runs several of these tests at once, and a program one
/// rewrites while another runs it fails.
fn scratch() -> &'static Path {
    static SCRATCH: LazyLock<PathBuf> = LazyLock::new(|| {
        let dir =
            Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("capi-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("scratch directory");
        dir
    });
    &SCRATCH
}

/// Compiles a test program; panics with the compiler's output if it fails.
fn compile(language: Language, source: &str, output: &str, library: Library) -> PathBuf {
    compile::compile(
        language,
        &manifest().join(source),
        &manifest().join("include"),
        &scratch().join(output),
        library,
    )
}

/// The C program, linked with the shared library.
static C_PROGRAM: LazyLock<PathBuf> = LazyLock::new(|| {
    compile(
        Language::C,
        "tests/c/disasm_test.c",
        "disasm_test_c",
        Library::Shared,
    )
});

/// The C++ program, linked with the static library.
static CPP_PROGRAM: LazyLock<PathBuf> = LazyLock::new(|| {
    compile(
        Language::Cpp,
        "tests/cpp/disasm_test.cpp",
        "disasm_test_cpp",
        Library::Static,
    )
});

/// Runs `program` with `args`; its standard output, which must be UTF-8.
/// The library is found by the program's rpath, not cargo's
/// `LD_LIBRARY_PATH`, which may name an older copy. Lines end in `\n`
/// (Windows' C runtime writes `\r\n`, its text mode).
fn run(program: &Path, args: &[&str]) -> String {
    let result = Command::new(program)
        .args(args)
        .env_remove("LD_LIBRARY_PATH")
        .output()
        .unwrap_or_else(|error| panic!("{}: {error}", program.display()));
    assert!(
        result.status.success(),
        "{} {args:?} failed:\n{}",
        program.display(),
        String::from_utf8_lossy(&result.stderr)
    );
    let out = String::from_utf8(result.stdout).expect("UTF-8 output");
    if cfg!(windows) {
        out.replace("\r\n", "\n")
    } else {
        out
    }
}

/// Asserts that `actual` (from C or C++) is `expected` (from Rust), naming
/// the first line that differs.
fn assert_same(what: &str, actual: &str, expected: &str) {
    for (number, (a, e)) in actual.lines().zip(expected.lines()).enumerate() {
        assert_eq!(a, e, "{what}: line {} differs", number + 1);
    }
    assert_eq!(
        actual.lines().count(),
        expected.lines().count(),
        "{what}: line count"
    );
}

/// The architecture of a fixture's code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Arch {
    X86_64,
    X86_32,
    Aarch64,
}

impl Arch {
    const fn name(self) -> &'static str {
        match self {
            Self::X86_64 => "x86-64",
            Self::X86_32 => "x86-32",
            Self::Aarch64 => "aarch64",
        }
    }
}

/// A code section of a fixture, written to a file for the programs.
struct Code {
    arch: Arch,
    address: u64,
    bytes: Vec<u8>,
    file: PathBuf,
}

/// The code sections of the fixtures.
static FIXTURES: LazyLock<Vec<Code>> = LazyLock::new(|| {
    let names = [
        "program-x86_64.elf",
        "program-x86_64.exe",
        "program-i686.exe",
        "resolve-aarch64.elf",
        "dozen-aarch64.elf",
        "mangled-aarch64.elf",
        "opaque-aarch64.elf",
    ];
    let mut code = Vec::new();
    for name in names {
        code.extend(code_of(&manifest().join("../../tests/fixtures").join(name)));
    }
    assert!(code.iter().any(|c| c.arch == Arch::X86_32));
    assert!(code.iter().any(|c| c.arch == Arch::Aarch64));
    code
});

/// The code sections of the ELF or PE file at `path`, each written to a
/// file of its own for the programs.
fn code_of(path: &Path) -> Vec<Code> {
    let name = path.file_name().expect("file name").to_string_lossy();
    let data = std::fs::read(path).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
    let file = object::File::parse(&*data).expect("object file");
    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "every other architecture is refused"
    )]
    let arch = match file.architecture() {
        Architecture::X86_64 => Arch::X86_64,
        Architecture::I386 => Arch::X86_32,
        Architecture::Aarch64 => Arch::Aarch64,
        other => panic!("{name}: {other:?}"),
    };
    let mut code = Vec::new();
    for (index, section) in file
        .sections()
        .filter(|s| s.kind() == SectionKind::Text)
        .enumerate()
    {
        let bytes = section.data().expect("section data").to_vec();
        let out = scratch().join(format!("{name}.{index}.text"));
        std::fs::write(&out, &bytes).expect("write code");
        code.push(Code {
            arch,
            address: section.address(),
            bytes,
            file: out,
        });
    }
    code
}

#[test]
fn c_api_keeps_its_contract() {
    assert_eq!(run(&C_PROGRAM, &["check"]), "ok\n");
}

#[test]
fn c_program_prints_what_the_rust_api_decodes() {
    for code in FIXTURES.iter() {
        let address = format!("{:x}", code.address);
        let printed = run(
            &C_PROGRAM,
            &[
                "dump",
                code.arch.name(),
                &address,
                code.file.to_str().expect("path"),
            ],
        );
        let expected = match code.arch {
            Arch::X86_64 => x86_dump(Mode::Bits64, code.address, &code.bytes),
            Arch::X86_32 => x86_dump(Mode::Bits32, code.address, &code.bytes),
            Arch::Aarch64 => aarch64_dump(code.address, &code.bytes),
        };
        assert_same(&format!("C, {}", code.file.display()), &printed, &expected);
    }
}

/// The C program on more code: the ELF and PE files named by
/// `BINBUN_CAPI_CORPUS` (separated as in `PATH`: by `:`, on Windows `;`),
/// x86-64, i386 or AArch64.
#[test]
#[ignore = "needs BINBUN_CAPI_CORPUS"]
fn c_program_prints_what_the_rust_api_decodes_on_a_corpus() {
    let corpus = std::env::var("BINBUN_CAPI_CORPUS").expect("BINBUN_CAPI_CORPUS");
    for path in std::env::split_paths(&corpus) {
        for code in code_of(&path) {
            let address = format!("{:x}", code.address);
            let printed = run(
                &C_PROGRAM,
                &[
                    "dump",
                    code.arch.name(),
                    &address,
                    code.file.to_str().expect("path"),
                ],
            );
            let expected = match code.arch {
                Arch::X86_64 => x86_dump(Mode::Bits64, code.address, &code.bytes),
                Arch::X86_32 => x86_dump(Mode::Bits32, code.address, &code.bytes),
                Arch::Aarch64 => aarch64_dump(code.address, &code.bytes),
            };
            assert_same(&format!("C, {}", path.display()), &printed, &expected);
            eprintln!(
                "{}: {} lines agree",
                path.display(),
                printed.lines().count()
            );
        }
    }
}

/// Every A64 word's text and tokens fit the header's
/// `BINBUN_AARCH64_MAX_TEXT` and `BINBUN_AARCH64_MAX_TOKENS`, with labels
/// of 16 hex digits: all 2^32 words, swept by the C program in 16
/// processes.
#[test]
#[ignore = "decodes every word; minutes"]
fn aarch64_every_word_fits_the_bounds() {
    let children: Vec<_> = (0..16u64)
        .map(|part| {
            let first = part << 28;
            let last = first + (1 << 28) - 1;
            Command::new(&*C_PROGRAM)
                .args([
                    "bounds-aarch64",
                    &format!("{first:x}"),
                    &format!("{last:x}"),
                ])
                .env_remove("LD_LIBRARY_PATH")
                .stdout(std::process::Stdio::piped())
                .spawn()
                .expect("spawn")
        })
        .collect();
    let (mut text, mut tokens) = ((0, String::new()), (0, String::new()));
    for child in children {
        let output = child.wait_with_output().expect("wait");
        assert!(output.status.success());
        let line = String::from_utf8(output.stdout).expect("UTF-8");
        let fields: Vec<&str> = line.split_whitespace().collect();
        let length: usize = fields[0].parse().unwrap();
        let count: usize = fields[2].parse().unwrap();
        if length > text.0 {
            text = (length, fields[1].to_owned());
        }
        if count > tokens.0 {
            tokens = (count, fields[3].to_owned());
        }
    }
    eprintln!(
        "longest text {} (word {}), most tokens {} (word {})",
        text.0, text.1, tokens.0, tokens.1
    );
    assert!(text.0 <= binbun_capi::aarch64::MAX_TEXT, "word {}", text.1);
    assert!(
        tokens.0 <= binbun_capi::aarch64::MAX_TOKENS,
        "word {}",
        tokens.1
    );
}

#[test]
fn cpp_program_prints_what_the_rust_api_decodes() {
    for code in FIXTURES.iter() {
        let address = format!("{:x}", code.address);
        let printed = run(
            &CPP_PROGRAM,
            &[
                code.arch.name(),
                &address,
                code.file.to_str().expect("path"),
            ],
        );
        let expected = match code.arch {
            Arch::X86_64 => x86_summary(Mode::Bits64, code.address, &code.bytes),
            Arch::X86_32 => x86_summary(Mode::Bits32, code.address, &code.bytes),
            Arch::Aarch64 => aarch64_summary(code.address, &code.bytes),
        };
        assert_same(
            &format!("C++, {}", code.file.display()),
            &printed,
            &expected,
        );
    }
}

#[test]
fn c_program_decodes_either_architecture_as_binbun_disasm() {
    for code in FIXTURES.iter() {
        let address = format!("{:x}", code.address);
        let printed = run(
            &C_PROGRAM,
            &[
                "any",
                code.arch.name(),
                &address,
                code.file.to_str().expect("path"),
            ],
        );
        let arch = match code.arch {
            Arch::X86_64 => DisasmArch::X86(Mode::Bits64),
            Arch::X86_32 => DisasmArch::X86(Mode::Bits32),
            Arch::Aarch64 => DisasmArch::AArch64,
        };
        assert_same(
            &format!("C, either architecture, {}", code.file.display()),
            &printed,
            &any_dump(arch, code.address, &code.bytes),
        );
    }
}

/// The C program's `any` notation, from `binbun-disasm`: per instruction
/// its address, bytes, mnemonic, text, the registers it reads and writes
/// by name, and its branch.
fn any_dump(arch: DisasmArch, address: u64, bytes: &[u8]) -> String {
    let names = |out: &mut String, label: &str, registers: &binbun_disasm::Registers| {
        write!(out, " {label}").unwrap();
        if registers.is_empty() {
            out.push_str(" -");
        }
        for register in registers {
            write!(out, " {register}").unwrap();
        }
    };
    let mut out = String::new();
    for (at, result) in binbun_disasm::Decoder::new(arch, bytes, address) {
        match result {
            Ok(insn) => {
                write!(out, "@{at:x} ").unwrap();
                for byte in insn.bytes() {
                    write!(out, "{byte:02x}").unwrap();
                }
                write!(out, " mnem={} text={insn}", insn.mnemonic()).unwrap();
                names(&mut out, "reads", &insn.registers_read());
                names(&mut out, "; writes", &insn.registers_written());
                print_branch(&mut out, insn.flow());
            }
            Err(error) => {
                let status = match error {
                    binbun_disasm::DecodeError::X86(error) => x86_status(error).0,
                    binbun_disasm::DecodeError::AArch64(error) => aarch64_status(error).0,
                };
                writeln!(out, "@{at:x} {status}").unwrap();
            }
        }
    }
    out
}

// ----------------------------------------------------------------- notation

/// The header's status for an x86 decode error, by name and number.
const fn x86_status(error: DecodeError) -> (&'static str, i32) {
    match error {
        DecodeError::TooShort => ("TRUNCATED", 2),
        DecodeError::TooLong => ("X86_TOO_LONG", 17),
        DecodeError::Invalid => ("INVALID", 16),
        DecodeError::InvalidMode => ("X86_INVALID_MODE", 18),
        DecodeError::BadRegister => ("X86_BAD_REGISTER", 19),
        DecodeError::BadLockPrefix => ("X86_BAD_LOCK_PREFIX", 20),
        DecodeError::BadLegacyPrefix => ("X86_BAD_LEGACY_PREFIX", 21),
        DecodeError::BadRexPrefix => ("X86_BAD_REX_PREFIX", 22),
        DecodeError::BadMap => ("X86_BAD_MAP", 23),
        DecodeError::BadEvexVPrime => ("X86_BAD_EVEX_V_PRIME", 24),
        DecodeError::BadEvexZeroingWithoutMask => ("X86_BAD_EVEX_ZEROING", 25),
        DecodeError::BadEvexLength => ("X86_BAD_EVEX_LENGTH", 26),
        DecodeError::GatherRegisters => ("X86_GATHER_REGISTERS", 27),
        DecodeError::BadRegisterMatch => ("X86_BAD_REGISTER_MATCH", 28),
    }
}

/// The header's status for an AArch64 decode error.
const fn aarch64_status(error: Error) -> (&'static str, i32) {
    match error {
        Error::TooShort => ("TRUNCATED", 2),
        Error::Unallocated => ("AARCH64_UNALLOCATED", 32),
        Error::Undefined => ("AARCH64_UNDEFINED", 33),
        Error::Unpredictable => ("AARCH64_UNPREDICTABLE", 34),
    }
}

/// The header's branch kind, conditionality and target of `flow`.
fn branch(flow: Flow) -> (u8, &'static str, bool, Option<Target>) {
    match flow {
        Flow::Next => (0, "none", false, None),
        Flow::Jump(target) => (1, "jump", false, Some(target)),
        Flow::Branch(target) => (1, "jump", true, Some(target)),
        Flow::Call(target) => (2, "call", false, Some(target)),
        Flow::Return => (3, "return", false, None),
        Flow::Trap { conditional } => (4, "trap", conditional, None),
        Flow::SystemCall => (5, "syscall", false, None),
        Flow::ExceptionReturn => (6, "eret", false, None),
        Flow::Halt => (7, "halt", false, None),
    }
}

fn print_branch(out: &mut String, flow: Flow) {
    let (_, kind, conditional, target) = branch(flow);
    let target = match target {
        None => "none".to_owned(),
        Some(Target::Address(address)) => format!("address:{address:x}"),
        Some(Target::Pointer { address, size }) => format!("pointer:{address:x}/{size}"),
        Some(Target::Indirect) => "indirect".to_owned(),
        Some(Target::Far { selector, offset }) => format!("far:{selector:x}:{offset:x}"),
    };
    let question = if conditional { "?" } else { "" };
    let fall = u8::from(flow.falls_through());
    writeln!(out, " branch={kind}{question} fall={fall} target={target}").unwrap();
}

/// The C++ program's short form of a branch.
fn branch_summary(flow: Flow) -> String {
    let (kind, _, conditional, target) = branch(flow);
    let (target_kind, address) = match target {
        None => (0, 0),
        Some(Target::Address(address)) => (1, address),
        Some(Target::Pointer { address, .. }) => (2, address),
        Some(Target::Indirect) => (3, 0),
        Some(Target::Far { offset, .. }) => (4, offset),
    };
    let question = if conditional { "?" } else { "" };
    format!(" branch={kind}{question}/{target_kind}/{address:x}")
}

fn x86_dump(mode: Mode, address: u64, bytes: &[u8]) -> String {
    let mut out = String::new();
    for (at, result) in Decoder::new(bytes, mode, address) {
        match result {
            Ok(instruction) => x86_instruction(&mut out, &instruction, at),
            Err(error) => writeln!(out, "@{at:x} {}", x86_status(error).0).unwrap(),
        }
    }
    out
}

const fn x86_condition(condition: Option<Condition>) -> &'static str {
    match condition {
        None => "-",
        Some(Condition::Overflow) => "o",
        Some(Condition::NotOverflow) => "no",
        Some(Condition::Below) => "b",
        Some(Condition::NotBelow) => "nb",
        Some(Condition::Zero) => "z",
        Some(Condition::NotZero) => "nz",
        Some(Condition::BelowOrEqual) => "be",
        Some(Condition::Above) => "nbe",
        Some(Condition::Sign) => "s",
        Some(Condition::NotSign) => "ns",
        Some(Condition::Parity) => "p",
        Some(Condition::NotParity) => "np",
        Some(Condition::Less) => "l",
        Some(Condition::NotLess) => "nl",
        Some(Condition::LessOrEqual) => "le",
        Some(Condition::Greater) => "nle",
        Some(Condition::False) => "false",
        Some(Condition::True) => "true",
        Some(Condition::CountZero) => "count_zero",
        Some(Condition::Loop) => "loop",
        Some(Condition::LoopZero) => "loop_zero",
        Some(Condition::LoopNotZero) => "loop_not_zero",
        Some(Condition::TransactionAbort) => "transaction_abort",
    }
}

fn x86_instruction(out: &mut String, i: &Instruction, at: u64) {
    let encoding = match i.encoding() {
        Encoding::Legacy => "legacy",
        Encoding::Vex => "vex",
        Encoding::Evex => "evex",
        Encoding::Xop => "xop",
    };
    writeln!(
        out,
        "@{at:x} len={} mnem={} form={} cat={} ext={} isa={} enc={encoding} cond={} w={},{},{}",
        i.len(),
        i.mnemonic(),
        i.form(),
        i.category(),
        i.extension(),
        i.isa_set(),
        x86_condition(i.condition()),
        i.operand_width(),
        i.address_width(),
        i.stack_address_width(),
    )
    .unwrap();
    writeln!(out, " text={}", i.intel(at)).unwrap();
    print_branch(out, i.flow(at));
    if let Some(computed) = i.computed_address(at) {
        writeln!(out, " computed={computed:x}").unwrap();
    }
    let flags = i.flags().map_or((0, 0, 0, false, false), |f| {
        (
            f.read.0,
            f.written.0,
            f.undefined.0,
            f.may_write,
            f.must_write,
        )
    });
    writeln!(
        out,
        " flags={:x},{:x},{:x},{},{}",
        flags.0,
        flags.1,
        flags.2,
        u8::from(flags.3),
        u8::from(flags.4)
    )
    .unwrap();
    for (position, operand) in i.operands().enumerate() {
        x86_operand(out, i, position, &operand);
    }
}

fn register_name(register: Option<Register>) -> &'static str {
    register.map_or("-", Register::name)
}

fn x86_operand(out: &mut String, i: &Instruction, position: usize, operand: &Operand) {
    let kind = match operand.value {
        Value::Register(_) => "register",
        Value::Memory(_) => "memory",
        Value::Immediate { .. } => "immediate",
        Value::SecondImmediate(_) => "second",
        Value::Relative(_) => "relative",
        Value::Field(_) => "field",
    };
    let visibility = match operand.visibility {
        Visibility::Explicit => "explicit",
        Visibility::Implicit => "implicit",
        Visibility::Suppressed => "suppressed",
    };
    let action = match operand.action {
        Action::Read => "r",
        Action::Write => "w",
        Action::ReadWrite => "rw",
        Action::ConditionalRead => "cr",
        Action::ConditionalWrite => "cw",
        Action::ConditionalReadWrite => "crw",
        Action::ReadConditionalWrite => "rcw",
    };
    let access = match (operand.action.reads(), operand.action.writes()) {
        (false, false) => "-",
        (true, false) => "r",
        (false, true) => "w",
        (true, true) => "rw",
    };
    write!(
        out,
        " op={kind} field={} vis={visibility} act={action} acc={access} bits={}",
        operand.name.as_str(),
        i.operand_bits(position)
    )
    .unwrap();
    match operand.value {
        Value::Register(register) => write!(out, " reg={}", register_name(register)),
        Value::Memory(m) => write!(
            out,
            " seg={} base={} index={} scale={} disp={} size={}",
            register_name(m.segment),
            register_name(m.base),
            register_name(m.index),
            m.scale,
            m.displacement,
            m.size
        ),
        Value::Immediate { value, signed } => {
            write!(out, " value={value:x} signed={}", u8::from(signed))
        }
        Value::SecondImmediate(value) => write!(out, " value={value:x}"),
        Value::Field(value) => write!(out, " value={value:x}"),
        Value::Relative(displacement) => write!(out, " disp={displacement}"),
    }
    .unwrap();
    out.push('\n');
}

fn x86_summary(mode: Mode, address: u64, bytes: &[u8]) -> String {
    let mut out = String::new();
    for (at, result) in Decoder::new(bytes, mode, address) {
        match result {
            Ok(i) => writeln!(
                out,
                "@{at:x} len={} mnem={} ops={} text={}{}",
                i.len(),
                i.mnemonic(),
                i.operands().len(),
                i.intel(at),
                branch_summary(i.flow(at))
            ),
            Err(error) => writeln!(out, "@{at:x} {}", x86_status(error).1),
        }
        .unwrap();
    }
    out
}

const COND_NAMES: [&str; 16] = [
    "eq", "ne", "hs", "lo", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt", "le", "al", "nv",
];

const fn element(element: Option<ElementSize>) -> &'static str {
    match element {
        None => "-",
        Some(ElementSize::B) => "b",
        Some(ElementSize::H) => "h",
        Some(ElementSize::S) => "s",
        Some(ElementSize::D) => "d",
        Some(ElementSize::Q) => "q",
    }
}

const fn radix(radix: Radix) -> &'static str {
    match radix {
        Radix::Hex => "hex",
        Radix::Decimal => "dec",
        Radix::PaddedHex => "padded",
    }
}

fn a64_register(out: &mut String, label: &str, register: A64Register) {
    let class = match register.class {
        RegisterClass::W => "w",
        RegisterClass::X => "x",
        RegisterClass::Wsp => "wsp",
        RegisterClass::Xsp => "xsp",
        RegisterClass::B => "b",
        RegisterClass::H => "h",
        RegisterClass::S => "s",
        RegisterClass::D => "d",
        RegisterClass::Q => "q",
        RegisterClass::V => "v",
        RegisterClass::Z => "z",
        RegisterClass::P => "p",
        RegisterClass::Pn => "pn",
        RegisterClass::Zt => "zt",
        RegisterClass::C => "c",
        RegisterClass::Ffr => "ffr",
    };
    let lanes = register.arrangement.map_or(0, |a| a.count);
    let elem = element(register.arrangement.map(|a| a.element));
    let index = register.index.map_or("-".to_owned(), |i| i.to_string());
    let predication = match register.predication {
        None => "-",
        Some(Predication::Zeroing) => "z",
        Some(Predication::Merging) => "m",
    };
    write!(
        out,
        " {label}={class}{}/{lanes}{elem}/{index}/{predication}",
        register.number
    )
    .unwrap();
}

const fn shift_name(kind: ShiftKind) -> &'static str {
    match kind {
        ShiftKind::Lsl => "lsl",
        ShiftKind::Lsr => "lsr",
        ShiftKind::Asr => "asr",
        ShiftKind::Ror => "ror",
        ShiftKind::Msl => "msl",
        ShiftKind::Mul => "mul",
    }
}

const fn extend_name(kind: ExtendKind) -> &'static str {
    match kind {
        ExtendKind::Uxtb => "uxtb",
        ExtendKind::Uxth => "uxth",
        ExtendKind::Uxtw => "uxtw",
        ExtendKind::Uxtx => "uxtx",
        ExtendKind::Sxtb => "sxtb",
        ExtendKind::Sxth => "sxth",
        ExtendKind::Sxtw => "sxtw",
        ExtendKind::Sxtx => "sxtx",
    }
}

fn a64_extend(out: &mut String, extend: Extend) {
    write!(out, " {}", extend_name(extend.kind)).unwrap();
    if let Some(amount) = extend.amount {
        write!(out, "={amount}").unwrap();
    }
}

fn a64_za(out: &mut String, za: Za) {
    let tile = za.tile.map_or("-".to_owned(), |t| t.to_string());
    let direction = match za.direction {
        None => "-",
        Some(SliceDirection::Horizontal) => "h",
        Some(SliceDirection::Vertical) => "v",
    };
    write!(out, " za={tile}/{}/{direction}", element(za.element)).unwrap();
    if let Some(slice) = za.slice {
        write!(out, "/w{}+{}", slice.index, slice.offset).unwrap();
        if let Some(last) = slice.last {
            write!(out, ":{last}").unwrap();
        }
        write!(out, "x{}", slice.group.unwrap_or(0)).unwrap();
    }
}

const fn a64_kind(operand: &A64Operand) -> &'static str {
    match operand {
        A64Operand::Register(_) => "register",
        A64Operand::List(_) => "list",
        A64Operand::Immediate(_) => "immediate",
        A64Operand::Float(_) => "float",
        A64Operand::Shift(_) => "shift",
        A64Operand::Extend(_) => "extend",
        A64Operand::Memory(_) => "memory",
        A64Operand::Writeback(_) => "writeback",
        A64Operand::Label(_) => "label",
        A64Operand::Condition(_) => "condition",
        A64Operand::SystemRegister(_) => "sysreg",
        A64Operand::Named(_) => "named",
        A64Operand::Za(_) => "za",
        A64Operand::ZaList(_) => "za_list",
        A64Operand::TableSlice(_) => "table_slice",
        A64Operand::IndexedRegister(_) => "indexed",
    }
}

fn a64_memory(out: &mut String, memory: Memory) {
    a64_register(out, "base", memory.base);
    match memory.offset {
        Offset::None => out.push_str(" offset=none"),
        Offset::Immediate(immediate) => write!(
            out,
            " offset={} signed={} radix={}",
            immediate.as_i64(),
            u8::from(immediate.signed),
            radix(immediate.radix)
        )
        .unwrap(),
        Offset::Register { index, modifier } => {
            a64_register(out, "index", index);
            match modifier {
                Modifier::None => {}
                Modifier::Shift(shift) => {
                    write!(out, " {}={}", shift_name(shift.kind), shift.amount).unwrap();
                }
                Modifier::Extend(extend) => a64_extend(out, extend),
            }
        }
        Offset::VectorLength(multiple) => write!(out, " offset={multiple}vl").unwrap(),
    }
    let writeback = match memory.writeback {
        Writeback::None => "none",
        Writeback::Pre => "pre",
        Writeback::Post => "post",
    };
    write!(out, " wb={writeback}").unwrap();
}

fn a64_operand(out: &mut String, operand: &A64Operand, access: Access) {
    let access = match access {
        Access::Read => "r",
        Access::Write => "w",
        Access::ReadWrite => "rw",
    };
    write!(out, " op={} acc={access}", a64_kind(operand)).unwrap();
    match *operand {
        A64Operand::Register(register) | A64Operand::Writeback(register) => {
            a64_register(out, "reg", register);
        }
        A64Operand::List(list) => {
            a64_register(out, "first", list.first);
            let style = match list.style {
                ListStyle::Commas => "commas",
                ListStyle::Range => "range",
            };
            let (count, stride) = (list.count, list.stride);
            write!(out, " count={count} stride={stride} style={style}").unwrap();
        }
        A64Operand::Immediate(immediate) => write!(
            out,
            " value={:x} signed={} radix={}",
            immediate.value,
            u8::from(immediate.signed),
            radix(immediate.radix)
        )
        .unwrap(),
        A64Operand::Float(float) => {
            let (bits, exact) = (float.value.to_bits(), u8::from(float.exact));
            write!(out, " bits={bits:016x} exact={exact}").unwrap();
        }
        A64Operand::Shift(shift) => {
            write!(out, " {}={}", shift_name(shift.kind), shift.amount).unwrap();
        }
        A64Operand::Extend(extend) => a64_extend(out, extend),
        A64Operand::Memory(memory) => a64_memory(out, memory),
        A64Operand::Label(label) => {
            let base = match label.base {
                LabelBase::Instruction => "pc",
                LabelBase::Page => "page",
            };
            write!(
                out,
                " offset={} base={base} radix={}",
                label.offset,
                radix(label.radix)
            )
            .unwrap();
        }
        A64Operand::Condition(condition) => write!(out, " cond={}", condition.name()).unwrap(),
        A64Operand::SystemRegister(register) => {
            write!(
                out,
                " sysreg={:x}/{}",
                register.encoding,
                register.name.unwrap_or("")
            )
            .unwrap();
        }
        A64Operand::Named(named) => {
            let kind = match named.kind {
                NameKind::Prefetch => "prefetch",
                NameKind::Barrier => "barrier",
                NameKind::BranchTarget => "bti",
                NameKind::PstateField => "pstate",
                NameKind::Pattern => "pattern",
                NameKind::SystemOperation => "sysop",
                NameKind::Keyword => "keyword",
            };
            write!(out, " {kind}={}", named.name).unwrap();
        }
        A64Operand::Za(za) | A64Operand::ZaList(ZaList::Slice(za)) => a64_za(out, za),
        A64Operand::ZaList(ZaList::Tiles(tiles)) => write!(out, " tiles={tiles:x}").unwrap(),
        A64Operand::TableSlice(offset) => write!(out, " slice={offset}").unwrap(),
        A64Operand::IndexedRegister(indexed) => {
            a64_register(out, "reg", indexed.register);
            a64_register(out, "index", indexed.index);
            write!(out, " offset={}", indexed.offset).unwrap();
        }
    }
    out.push('\n');
}

fn a64_condition(out: &mut String, condition: A64Condition) {
    match condition {
        A64Condition::Flags(cond) => {
            write!(out, " cond=flags:{}", COND_NAMES[cond as usize]).unwrap();
        }
        A64Condition::Zero { register, zero } => {
            write!(out, " cond=zero:{}", u8::from(zero)).unwrap();
            a64_register(out, "reg", register);
        }
        A64Condition::Bit { register, bit, set } => {
            write!(out, " cond=bit:{bit}:{}", u8::from(set)).unwrap();
            a64_register(out, "reg", register);
        }
        A64Condition::Compare { cond, left, right } => {
            write!(out, " cond=compare:{}", COND_NAMES[cond as usize]).unwrap();
            a64_register(out, "reg", left);
            match right {
                CompareOperand::Register(register) => a64_register(out, "right", register),
                CompareOperand::Immediate(value) => write!(out, " right={value}").unwrap(),
            }
        }
    }
    out.push('\n');
}

fn aarch64_dump(address: u64, bytes: &[u8]) -> String {
    let mut out = String::new();
    for (at, result) in A64Decoder::new(bytes, address) {
        let i = match result {
            Ok(i) => i,
            Err(error) => {
                writeln!(out, "@{at:x} {}", aarch64_status(error).0).unwrap();
                continue;
            }
        };
        writeln!(
            out,
            "@{at:x} word={:08x} enc={} base={} mnem={}",
            i.word(),
            i.encoding().name(),
            i.encoding().mnemonic(),
            i.mnemonic()
        )
        .unwrap();
        writeln!(out, " text={}", i.display(at)).unwrap();
        writeln!(
            out,
            " relative={}",
            i.display_with(at, LabelStyle::Relative)
        )
        .unwrap();
        print_branch(&mut out, i.flow(at));
        if let Some(computed) = i.computed_address(at) {
            writeln!(out, " computed={computed:x}").unwrap();
        }
        if let Some(condition) = i.condition() {
            a64_condition(&mut out, condition);
        }
        let flags = i.flags();
        writeln!(
            out,
            " flags={:x},{:x}",
            flags.read.bits(),
            flags.written.bits()
        )
        .unwrap();
        if let Some(memory) = i.memory() {
            let kind = match memory.kind {
                MemoryKind::Load => "load",
                MemoryKind::Store => "store",
                MemoryKind::Atomic => "atomic",
                MemoryKind::LoadExclusive => "load_exclusive",
                MemoryKind::StoreExclusive => "store_exclusive",
                MemoryKind::Prefetch => "prefetch",
                MemoryKind::Copy => "copy",
                MemoryKind::LoadTag => "load_tag",
                MemoryKind::StoreTag => "store_tag",
            };
            writeln!(out, " memory={kind}/{}", memory.size).unwrap();
        }
        let implicit = i.implicit();
        for (label, registers) in [("reads", implicit.reads), ("writes", implicit.writes)] {
            if !registers.is_empty() {
                write!(out, " {label}:").unwrap();
                for &register in registers {
                    a64_register(&mut out, "r", register);
                }
                out.push('\n');
            }
        }
        for (operand, access) in i.operands().iter().zip(i.access().iter()) {
            a64_operand(&mut out, operand, *access);
        }
    }
    out
}

fn aarch64_summary(address: u64, bytes: &[u8]) -> String {
    let mut out = String::new();
    for (at, result) in A64Decoder::new(bytes, address) {
        match result {
            Ok(i) => writeln!(
                out,
                "@{at:x} word={:08x} mnem={} enc={} ops={} text={}{}",
                i.word(),
                i.mnemonic(),
                i.encoding().name(),
                i.operands().len(),
                i.display(at),
                branch_summary(i.flow(at))
            ),
            Err(error) => writeln!(out, "@{at:x} {}", aarch64_status(error).1),
        }
        .unwrap();
    }
    out
}
