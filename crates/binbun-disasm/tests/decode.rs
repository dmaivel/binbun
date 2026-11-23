//! The façade against the native decoders: every instruction of the
//! checked-in fixtures' code decodes as the native decoder decodes it
//! (address, bytes, text, flow, the native instruction), sweeps step as the
//! native sweeps do, and the register facts of chosen instructions.

#![cfg(all(feature = "x86", feature = "aarch64"))]

use std::path::Path;

use binbun_disasm::{
    AArch64Register, Arch, DecodeError, Decoder, Insn, Register, aarch64, decode, x86,
};
use object::{Architecture, Object, ObjectSection, SectionKind};

/// The fixtures with code for both architectures (as the C API's test
/// sweeps them).
const FIXTURES: [&str; 7] = [
    "program-x86_64.elf",
    "program-x86_64.exe",
    "program-i686.exe",
    "resolve-aarch64.elf",
    "dozen-aarch64.elf",
    "mangled-aarch64.elf",
    "opaque-aarch64.elf",
];

/// The architecture, address and bytes of each code section of the
/// fixtures.
fn code() -> Vec<(Arch, u64, Vec<u8>)> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures");
    let mut code = Vec::new();
    for name in FIXTURES {
        let data = std::fs::read(root.join(name)).expect("fixture");
        let file = object::File::parse(&*data).expect("object file");
        #[expect(
            clippy::wildcard_enum_match_arm,
            reason = "every other architecture is refused"
        )]
        let arch = match file.architecture() {
            Architecture::X86_64 => Arch::X86(x86::Mode::Bits64),
            Architecture::I386 => Arch::X86(x86::Mode::Bits32),
            Architecture::Aarch64 => Arch::AArch64,
            other => panic!("{name}: {other:?}"),
        };
        for section in file.sections().filter(|s| s.kind() == SectionKind::Text) {
            let bytes = section.data().expect("section data").to_vec();
            code.push((arch, section.address(), bytes));
        }
    }
    assert!(code.iter().any(|c| c.0 == Arch::X86(x86::Mode::Bits32)));
    assert!(code.iter().any(|c| c.0 == Arch::AArch64));
    code
}

/// The names of the registers `insn` reads and writes.
fn registers(insn: &Insn<'_>) -> (Vec<String>, Vec<String>) {
    let names = |registers: &binbun_disasm::Registers| {
        registers
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
    };
    (
        names(&insn.registers_read()),
        names(&insn.registers_written()),
    )
}

#[test]
fn fixture_code_decodes_as_the_native_decoders_decode_it() {
    let mut counts = [0usize; 2];
    for (arch, address, bytes) in code() {
        let mut generic = Decoder::new(arch, &bytes, address);
        match arch {
            Arch::X86(mode) => {
                for (at, native) in x86::Decoder::new(&bytes, mode, address) {
                    let (got_at, got) = generic.next().expect("as many items");
                    assert_eq!(got_at, at);
                    match (got, native) {
                        (Ok(insn), Ok(native)) => {
                            let offset = usize::try_from(at - address).expect("offset");
                            assert_eq!(insn.bytes(), &bytes[offset..offset + native.len()]);
                            assert_eq!(insn.len(), native.len());
                            assert_eq!(insn.to_string(), native.intel(at).to_string());
                            assert_eq!(insn.flow(), native.flow(at));
                            assert_eq!(insn.as_x86(), Some(&native));
                            assert_eq!(insn.as_aarch64(), None);
                            assert_eq!(insn.arch(), arch);
                            assert_eq!(insn.mnemonic(), native.intel_mnemonic());
                            // The mnemonic is the text's after its prefix words.
                            let text = insn.to_string();
                            assert!(
                                text.split(' ').any(|word| word == insn.mnemonic())
                                    || text.starts_with(insn.mnemonic()),
                                "{text}"
                            );
                            counts[0] += 1;
                        }
                        (Err(got), Err(native)) => assert_eq!(got, DecodeError::X86(native)),
                        (got, native) => panic!("{at:#x}: {got:?} but {native:?}"),
                    }
                }
            }
            Arch::AArch64 => {
                for (at, native) in aarch64::Decoder::new(&bytes, address) {
                    let (got_at, got) = generic.next().expect("as many items");
                    assert_eq!(got_at, at);
                    match (got, native) {
                        (Ok(insn), Ok(native)) => {
                            assert_eq!(insn.bytes(), native.word().to_le_bytes());
                            assert_eq!(insn.to_string(), native.display(at).to_string());
                            assert_eq!(insn.flow(), native.flow(at));
                            assert_eq!(insn.as_aarch64(), Some(&native));
                            assert_eq!(insn.as_x86(), None);
                            assert_eq!(insn.mnemonic(), native.mnemonic());
                            let text = insn.to_string();
                            assert_eq!(text.split('\t').next(), Some(insn.mnemonic()));
                            counts[1] += 1;
                        }
                        (Err(got), Err(native)) => {
                            assert_eq!(got, DecodeError::AArch64(native));
                        }
                        (got, native) => panic!("{at:#x}: {got:?} but {native:?}"),
                    }
                }
            }
        }
        assert!(generic.next().is_none());
    }
    assert!(counts.iter().all(|&count| count > 100), "{counts:?}");
}

#[test]
fn fixture_register_facts_hold_their_promises() {
    for (arch, address, bytes) in code() {
        for (_, insn) in Decoder::new(arch, &bytes, address) {
            let Ok(insn) = insn else { continue };
            for registers in [insn.registers_read(), insn.registers_written()] {
                let names: Vec<String> = registers.iter().map(ToString::to_string).collect();
                // Each register once, under one name.
                let mut unique = names.clone();
                unique.sort();
                unique.dedup();
                assert_eq!(unique.len(), names.len(), "{insn}: {names:?}");
                for register in &registers {
                    match (register, arch) {
                        (Register::X86(r), Arch::X86(_)) => {
                            assert_ne!(r.class(), x86::RegisterClass::Flags, "{insn}");
                        }
                        (Register::AArch64(_), Arch::AArch64) => {}
                        (register, arch) => panic!("{insn}: {register:?} for {arch:?}"),
                    }
                }
            }
            // On x86 every register an explicit operand names is listed.
            if let Some(native) = insn.as_x86() {
                for operand in native.operands() {
                    if let x86::Value::Register(Some(r)) = operand.value
                        && operand.visibility == x86::Visibility::Explicit
                        && r.class() != x86::RegisterClass::Flags
                    {
                        let listed = insn.registers_read().contains(Register::X86(r))
                            || insn.registers_written().contains(Register::X86(r));
                        assert!(listed, "{insn}: {}", r.name());
                    }
                }
            }
            // On AArch64 the implicit registers are listed.
            if let Some(native) = insn.as_aarch64() {
                let implicit = native.implicit();
                for &r in implicit.reads {
                    let r = Register::AArch64(AArch64Register::of(r));
                    assert!(insn.registers_read().contains(r), "{insn}");
                }
                for &r in implicit.writes {
                    let r = Register::AArch64(AArch64Register::of(r));
                    assert!(insn.registers_written().contains(r), "{insn}");
                }
            }
        }
    }
}

/// The registers `hex` reads and writes at 0x1000.
fn facts(arch: Arch, hex: &str) -> (String, String, String, String) {
    let bytes: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex"))
        .collect();
    let insn = decode(arch, &bytes, 0x1000).expect("an instruction");
    let (read, written) = registers(&insn);
    (
        insn.to_string(),
        insn.mnemonic().to_owned(),
        read.join(" "),
        written.join(" "),
    )
}

#[test]
fn x86_register_facts() {
    let x64 = Arch::X86(x86::Mode::Bits64);
    let x32 = Arch::X86(x86::Mode::Bits32);
    let cases: [(Arch, &str, [&str; 4]); 13] = [
        (x64, "55", ["push rbp", "push", "rbp rsp", "rsp"]),
        // The text is XED's, unnormalised (its `ret ` ends in a space).
        (x64, "c3", ["ret ", "ret", "rsp", "rip rsp"]),
        (x64, "31c0", ["xor eax, eax", "xor", "eax", "eax"]),
        (x64, "b001", ["mov al, 0x1", "mov", "", "al"]),
        // The memory operand's base is read; the flags are left out.
        (
            x64,
            "48014310",
            ["add qword ptr [rbx+0x10], rax", "add", "rbx rax", ""],
        ),
        (
            x64,
            "f0014310",
            ["lock add dword ptr [rbx+0x10], eax", "add", "rbx eax", ""],
        ),
        (
            x64,
            "488d0510000000",
            ["lea rax, ptr [rip+0x10]", "lea", "rip", "rax"],
        ),
        (
            x64,
            "f3a4",
            [
                "rep movsb byte ptr [rdi], byte ptr [rsi]",
                "movsb",
                "rdi rsi rcx",
                "rdi rsi rcx",
            ],
        ),
        // Outside 64-bit mode the segments used are reported.
        (
            x32,
            "f3a4",
            [
                "rep movsb byte ptr [edi], byte ptr [esi]",
                "movsb",
                "es edi ds esi ecx",
                "edi esi ecx",
            ],
        ),
        (
            x64,
            "0fa2",
            ["cpuid ", "cpuid", "eax ecx", "eax ebx ecx edx"],
        ),
        // A write mask is read, k0 (no mask) is not.
        (
            x64,
            "62f17c4958c1",
            [
                "vaddps zmm0{k1}, zmm0, zmm1",
                "vaddps",
                "k1 zmm0 zmm1",
                "zmm0",
            ],
        ),
        (
            x64,
            "62f17c4858c1",
            ["vaddps zmm0, zmm0, zmm1", "vaddps", "zmm0 zmm1", "zmm0"],
        ),
        // No x87push: the status word is written.
        (x64, "d9e8", ["fld1 ", "fld1", "", "st(0) x87status"]),
    ];
    for (arch, hex, [text, mnemonic, read, written]) in cases {
        assert_eq!(
            facts(arch, hex),
            (text.into(), mnemonic.into(), read.into(), written.into()),
            "{hex}"
        );
    }
    assert_eq!(facts(x64, "ff18").1, "call far");
    assert_eq!(facts(Arch::X86(x86::Mode::Bits16), "6690").1, "nop");
}

#[test]
fn aarch64_register_facts() {
    let a64 = Arch::AArch64;
    let cases: [(&str, [&str; 4]); 15] = [
        (
            "fd7bbfa9",
            ["stp\tx29, x30, [sp, #-0x10]!", "stp", "x29 x30 sp", "sp"],
        ),
        (
            "fd7bc1a8",
            ["ldp\tx29, x30, [sp], #0x10", "ldp", "sp", "x29 x30 sp"],
        ),
        (
            "417863f8",
            ["ldr\tx1, [x2, x3, lsl #3]", "ldr", "x2 x3", "x1"],
        ),
        ("2000020b", ["add\tw0, w1, w2", "add", "w1 w2", "w0"]),
        // The zero register as a destination is listed.
        ("ff0300aa", ["mov\txzr, x0", "mov", "x0", "xzr"]),
        // NZCV is left out.
        ("1f1000f1", ["cmp\tx0, #0x4", "cmp", "x0", ""]),
        ("00000054", ["b.eq\t0x1000", "b.eq", "", ""]),
        ("00000094", ["bl\t0x1000", "bl", "", "x30"]),
        ("c0035fd6", ["ret", "ret", "x30", ""]),
        ("9f2103d5", ["autia1716", "autia1716", "x17 x16", "x17"]),
        // Lists are expanded.
        (
            "0000404c",
            [
                "ld4\t{ v0.16b, v1.16b, v2.16b, v3.16b }, [x0]",
                "ld4",
                "x0",
                "v0 v1 v2 v3",
            ],
        ),
        // System registers by name, then by encoding.
        ("40d03bd5", ["mrs\tx0, TPIDR_EL0", "mrs", "TPIDR_EL0", "x0"]),
        ("40d01bd5", ["msr\tTPIDR_EL0, x0", "msr", "x0", "TPIDR_EL0"]),
        // A ZA tile slice: the tile, its index register.
        (
            "0000c0e0",
            [
                "ld1d\t{za0h.d[w12, 0]}, p0/z, [x0, x0, lsl #3]",
                "ld1d",
                "w12 p0 x0",
                "za0.d",
            ],
        ),
        ("ff0008c0", ["zero\t{za}", "zero", "", "za"]),
    ];
    for (hex, [text, mnemonic, read, written]) in cases {
        assert_eq!(
            facts(a64, hex),
            (text.into(), mnemonic.into(), read.into(), written.into()),
            "{hex}"
        );
    }
}

#[test]
fn sweeps_step_as_the_native_sweeps() {
    // x86: one byte past what is no instruction; a truncated tail byte by byte.
    let x86 = [0x55, 0x06, 0xc3, 0x48, 0x89];
    let items: Vec<(u64, Result<usize, DecodeError>)> =
        Decoder::new(Arch::X86(x86::Mode::Bits64), &x86, 0x10)
            .map(|(at, insn)| (at, insn.map(|insn| insn.len())))
            .collect();
    let too_short = Err(DecodeError::X86(x86::DecodeError::TooShort));
    assert_eq!(
        items,
        [
            (0x10, Ok(1)),
            (0x11, Err(DecodeError::X86(x86::DecodeError::Invalid))),
            (0x12, Ok(1)),
            (0x13, too_short),
            (0x14, too_short),
        ]
    );
    // AArch64: four bytes, a short tail once.
    let a64 = [
        0x1f, 0x20, 0x03, 0xd5, 0xff, 0xff, 0xff, 0xff, 0xc0, 0x03, 0x5f,
    ];
    let mut decoder = Decoder::new(Arch::AArch64, &a64, 0x100);
    assert_eq!(decoder.size_hint(), (3, Some(3)));
    let items: Vec<(u64, Result<String, DecodeError>)> = decoder
        .by_ref()
        .map(|(at, insn)| (at, insn.map(|insn| insn.to_string())))
        .collect();
    assert_eq!(
        items,
        [
            (0x100, Ok("nop".into())),
            (
                0x104,
                Err(DecodeError::AArch64(aarch64::Error::Unallocated))
            ),
            (0x108, Err(DecodeError::AArch64(aarch64::Error::TooShort))),
        ]
    );
    assert!(decoder.next().is_none());
    // Continuing elsewhere.
    let mut decoder = Decoder::new(Arch::X86(x86::Mode::Bits64), &x86, 0x10);
    decoder.set_offset(2);
    assert_eq!((decoder.offset(), decoder.address()), (2, 0x12));
    assert_eq!(decoder.remaining(), [0xc3, 0x48, 0x89]);
}

#[test]
fn errors_and_lengths() {
    let truncated = decode(Arch::X86(x86::Mode::Bits64), &[0x48], 0).expect_err("truncated");
    assert!(truncated.is_truncated());
    let undefined = decode(Arch::AArch64, &[0x20, 0x00, 0xc2, 0x0b], 0).expect_err("undefined");
    assert_eq!(undefined, DecodeError::AArch64(aarch64::Error::Undefined));
    assert!(!undefined.is_truncated());
    // The bytes are the instruction's, borrowed from the buffer.
    let code = [0x90, 0xc3];
    let nop = decode(Arch::X86(x86::Mode::Bits64), &code, 7).expect("nop");
    assert_eq!((nop.bytes(), nop.address(), nop.len()), (&code[..1], 7, 1));
    assert!(std::ptr::eq(nop.bytes().as_ptr(), code.as_ptr()));
}
