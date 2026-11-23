//! Control-flow classification and branch targets. (Flags and CPUID come
//! from XED's tables and are checked against XED itself in `oracle.rs`.)

#![allow(clippy::unwrap_used, reason = "test helpers fail loudly")]

use binbun_isa::{Architecture, Flow, Target};
use binbun_x86::{Condition, Mnemonic, Mode, X86, decode};

/// The flow of `bytes` at `address` in `mode`.
fn flow_at(mode: Mode, bytes: &[u8], address: u64) -> Flow {
    decode(bytes, mode).unwrap().flow(address)
}

fn flow(bytes: &[u8]) -> Flow {
    flow_at(Mode::Bits64, bytes, 0x1000)
}

#[test]
fn classifies_transfers() {
    let cases: &[(&[u8], Flow)] = &[
        (&[0x48, 0x89, 0xc7], Flow::Next),
        // jz +2; ja -4 (rel32); jrcxz +16; loop -2; xbegin +0
        (&[0x74, 0x02], Flow::Branch(Target::Address(0x1004))),
        (
            &[0x0f, 0x87, 0xfc, 0xff, 0xff, 0xff],
            Flow::Branch(Target::Address(0x1002)),
        ),
        (&[0xe3, 0x10], Flow::Branch(Target::Address(0x1012))),
        (&[0xe2, 0xfe], Flow::Branch(Target::Address(0x1000))),
        (
            &[0xc7, 0xf8, 0, 0, 0, 0],
            Flow::Branch(Target::Address(0x1006)),
        ),
        (&[0xeb, 0x00], Flow::Jump(Target::Address(0x1002))),
        (&[0xff, 0xe0], Flow::Jump(Target::Indirect)),
        (&[0xe8, 0x10, 0, 0, 0], Flow::Call(Target::Address(0x1015))),
        (&[0xff, 0xd0], Flow::Call(Target::Indirect)),
        (&[0xc3], Flow::Return),
        (&[0xc2, 0x08, 0x00], Flow::Return),
        (&[0x48, 0xcf], Flow::ExceptionReturn),
        (&[0x0f, 0x07], Flow::ExceptionReturn),
        (&[0x0f, 0x05], Flow::SystemCall),
        (&[0x0f, 0x01, 0xc1], Flow::SystemCall),
        (&[0xcc], Flow::Trap { conditional: false }),
        (&[0xcd, 0x80], Flow::Trap { conditional: false }),
        (&[0x0f, 0x0b], Flow::Trap { conditional: false }),
        (&[0xf4], Flow::Halt),
        // XEND and XABORT do not branch themselves.
        (&[0x0f, 0x01, 0xd5], Flow::Next),
        (&[0xc6, 0xf8, 0x01], Flow::Next),
    ];
    for &(bytes, expected) in cases {
        assert_eq!(flow(bytes), expected, "{bytes:02x?}");
    }
}

#[test]
fn jumps_and_calls_through_fixed_pointers() {
    // jmp [rip+0x10]: the pointer is after the 6-byte instruction.
    assert_eq!(
        flow(&[0xff, 0x25, 0x10, 0, 0, 0]),
        Flow::Jump(Target::Pointer {
            address: 0x1016,
            size: 8
        })
    );
    // call [rip-6]: the GOT/IAT slot may lie before the instruction.
    assert_eq!(
        flow(&[0xff, 0x15, 0xfa, 0xff, 0xff, 0xff]),
        Flow::Call(Target::Pointer {
            address: 0x1000,
            size: 8
        })
    );
    // 32-bit call [0x404000]: an absolute pointer of 4 bytes.
    assert_eq!(
        flow_at(Mode::Bits32, &[0xff, 0x15, 0x00, 0x40, 0x40, 0x00], 0),
        Flow::Call(Target::Pointer {
            address: 0x40_4000,
            size: 4
        })
    );
    // Through a register, an index, or a segment with a base: unknown.
    for bytes in [
        &[0xff, 0x20][..],
        &[0xff, 0x24, 0xc5, 0, 0x10, 0, 0],
        &[0x64, 0xff, 0x24, 0x25, 0x10, 0, 0, 0],
    ] {
        assert_eq!(flow(bytes), Flow::Jump(Target::Indirect), "{bytes:02x?}");
    }
    // A far jump through memory reads a far pointer, not an address.
    assert_eq!(
        flow(&[0xff, 0x2d, 0, 0, 0, 0]),
        Flow::Jump(Target::Indirect)
    );
}

#[test]
fn far_and_absolute_targets() {
    // jmp far 0x6655:0x44332211, call far 0xbbaa:0x44332211 (32-bit)
    assert_eq!(
        flow_at(Mode::Bits32, &[0xea, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66], 0),
        Flow::Jump(Target::Far {
            selector: 0x6655,
            offset: 0x4433_2211
        })
    );
    assert_eq!(
        flow_at(Mode::Bits32, &[0x9a, 0x11, 0x22, 0x33, 0x44, 0xaa, 0xbb], 0),
        Flow::Call(Target::Far {
            selector: 0xbbaa,
            offset: 0x4433_2211
        })
    );
    assert_eq!(
        flow_at(Mode::Bits32, &[0xce], 0),
        Flow::Trap { conditional: true }
    );
    // APX jmpabs 0x1122334455667788
    let jmpabs = [
        0xd5, 0x00, 0xa1, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
    ];
    assert_eq!(
        flow(&jmpabs),
        Flow::Jump(Target::Address(0x1122_3344_5566_7788))
    );
}

#[test]
fn relative_targets_wrap_like_the_instruction_pointer() {
    let address = |mode, bytes: &[u8], at| {
        let (Flow::Jump(target) | Flow::Call(target) | Flow::Branch(target)) =
            flow_at(mode, bytes, at)
        else {
            panic!("{bytes:02x?} is not a jump");
        };
        target.address().unwrap()
    };
    // 64-bit: plain addition.
    assert_eq!(address(Mode::Bits64, &[0xeb, 0xfe], 0x1000), 0x1000);
    assert_eq!(
        address(Mode::Bits64, &[0xeb, 0x80], 0x10),
        0xffff_ffff_ffff_ff92
    );
    // 32-bit: wraps at 4 GiB.
    assert_eq!(address(Mode::Bits32, &[0xeb, 0x10], 0xffff_fff0), 2);
    // 16-bit operand size: wraps at 64 KiB.
    assert_eq!(address(Mode::Bits16, &[0xeb, 0x10], 0xfff0), 2);
    // 0x1f000 + 4 + 0x1000, truncated to 16 bits.
    assert_eq!(
        address(Mode::Bits32, &[0x66, 0xe8, 0x00, 0x10], 0x0001_f000),
        0x0004
    );
}

#[test]
fn condition_codes_agree_across_families() {
    let families = [
        (
            Mnemonic::Jnbe,
            Mnemonic::Setnbe,
            Mnemonic::Cmovnbe,
            Condition::Above,
        ),
        (
            Mnemonic::Jnl,
            Mnemonic::Setnl,
            Mnemonic::Cmovnl,
            Condition::NotLess,
        ),
        (
            Mnemonic::Jz,
            Mnemonic::Setz,
            Mnemonic::Cmovz,
            Condition::Zero,
        ),
        (
            Mnemonic::Jp,
            Mnemonic::Setp,
            Mnemonic::Cmovp,
            Condition::Parity,
        ),
    ];
    for (jump, set, mov, condition) in families {
        for mnemonic in [jump, set, mov] {
            assert_eq!(mnemonic.condition(), Some(condition), "{mnemonic:?}");
        }
    }
    assert_eq!(Mnemonic::Cmpnbexadd.condition(), Some(Condition::Above));
    assert_eq!(Mnemonic::Ccmpt.condition(), Some(Condition::True));
    assert_eq!(Mnemonic::Fcmovnu.condition(), Some(Condition::NotParity));
    assert_eq!(Mnemonic::Fcmove.condition(), Some(Condition::Zero));
    for mnemonic in [
        Mnemonic::Jmp,
        Mnemonic::Setssbsy,
        Mnemonic::Cmpsb,
        Mnemonic::Mov,
    ] {
        assert_eq!(mnemonic.condition(), None, "{mnemonic:?}");
    }
    // The instruction's condition is its mnemonic's.
    assert_eq!(
        decode(&[0x0f, 0x4f, 0xc1], Mode::Bits64)
            .unwrap()
            .condition(),
        Some(Condition::Greater)
    );
}

#[test]
fn analyses_see_the_same_instruction_through_the_trait() {
    let call = [0xe8, 0x10, 0, 0, 0];
    let instruction = X86.decode(&call, Mode::Bits64).unwrap();
    assert_eq!(binbun_isa::Instruction::len(&instruction), 5);
    assert_eq!(
        binbun_isa::Instruction::flow(&instruction, 0x1000),
        Flow::Call(Target::Address(0x1015))
    );
    assert!(X86.decode(&call[..3], Mode::Bits64).is_err());
    assert_eq!(<X86 as Architecture>::MAX_LENGTH, 15);
}
