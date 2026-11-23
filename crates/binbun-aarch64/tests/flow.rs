//! Control flow, conditions, the streaming decoder and the `binbun_isa`
//! implementation. (Flow is checked against exarmo on every encoding in
//! `oracle.rs`, `flow_matches_exarmo`.)

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers fail loudly"
)]

use binbun_aarch64::operand::{Condition as Cond, Register, RegisterClass};
use binbun_aarch64::{
    AArch64, CompareOperand, Condition, Decoder, Error, Instruction, Mode, decode, decode_bytes,
};
use binbun_isa::{Architecture as _, Flow, Instruction as _, Target};

fn flow(word: u32) -> Flow {
    decode(word).unwrap().flow(0x1000)
}

fn condition(word: u32) -> Option<Condition> {
    decode(word).unwrap().condition()
}

const fn x(number: u8) -> Register {
    Register::new(RegisterClass::X, number)
}

const fn w(number: u8) -> Register {
    Register::new(RegisterClass::W, number)
}

#[test]
fn classifies_transfers() {
    let at = |address| Target::Address(address);
    let cases = [
        // add x0, x1, x2
        (0x8b02_0020, Flow::Next),
        // b +0x40, bl -4 (targets from the instruction's address)
        (0x1400_0010, Flow::Jump(at(0x1040))),
        (0x97ff_ffff, Flow::Call(at(0xffc))),
        // b.eq -8; b.al and b.nv always branch; bc.ne +0x10
        (0x54ff_ffc0, Flow::Branch(at(0xff8))),
        (0x5400_008e, Flow::Jump(at(0x1010))),
        (0x5400_008f, Flow::Jump(at(0x1010))),
        (0x5400_0091, Flow::Branch(at(0x1010))),
        // cbz x1, cbnz w1, tbz w3 #5, tbnz x3 #63, cbgt x1 #3, cbbeq w1 w2
        (0xb400_0201, Flow::Branch(at(0x1040))),
        (0x3500_0201, Flow::Branch(at(0x1040))),
        (0x3628_0203, Flow::Branch(at(0x1040))),
        (0xb7f8_0203, Flow::Branch(at(0x1040))),
        (0xf501_8201, Flow::Branch(at(0x1040))),
        (0x74c2_be01, Flow::Branch(at(0xfc0))),
        // br x1, br x30, braa x1 x2, braaz x1: jumps, whatever the register
        (0xd61f_0020, Flow::Jump(Target::Indirect)),
        (0xd61f_03c0, Flow::Jump(Target::Indirect)),
        (0xd71f_0822, Flow::Jump(Target::Indirect)),
        (0xd61f_083f, Flow::Jump(Target::Indirect)),
        // blr x30, blraa x1 x2, blrabz x1
        (0xd63f_03c0, Flow::Call(Target::Indirect)),
        (0xd73f_0822, Flow::Call(Target::Indirect)),
        (0xd63f_0c3f, Flow::Call(Target::Indirect)),
        // ret, ret x1, retaa, retab, retaasppc (its label is no target),
        // retaasppcr x16
        (0xd65f_03c0, Flow::Return),
        (0xd65f_0020, Flow::Return),
        (0xd65f_0bff, Flow::Return),
        (0xd65f_0fff, Flow::Return),
        (0x5500_009f, Flow::Return),
        (0xd65f_0bf0, Flow::Return),
        // eret, eretaa, drps
        (0xd69f_03e0, Flow::ExceptionReturn),
        (0xd69f_0bff, Flow::ExceptionReturn),
        (0xd6bf_03e0, Flow::ExceptionReturn),
        // svc #0, hvc #0, smc #0
        (0xd400_0001, Flow::SystemCall),
        (0xd400_0002, Flow::SystemCall),
        (0xd400_0003, Flow::SystemCall),
        // brk #0, hlt #0, udf #0: no fall-through
        (0xd420_0000, Flow::Trap { conditional: false }),
        (0xd440_0000, Flow::Trap { conditional: false }),
        (0x0000_0000, Flow::Trap { conditional: false }),
        // dcps1, wfi, wfe, wfet x0, wfit x0, nop: execution continues
        (0xd4a0_0001, Flow::Next),
        (0xd503_207f, Flow::Next),
        (0xd503_205f, Flow::Next),
        (0xd503_1000, Flow::Next),
        (0xd503_1020, Flow::Next),
        (0xd503_201f, Flow::Next),
    ];
    for (word, expected) in cases {
        assert_eq!(flow(word), expected, "{word:08x}");
    }
}

#[test]
fn branch_targets_wrap() {
    // b.eq -8 at 0: the address space wraps.
    assert_eq!(
        decode(0x54ff_ffc0).unwrap().flow(0),
        Flow::Branch(Target::Address(0xffff_ffff_ffff_fff8))
    );
    // b with the largest negative offset, -128 MiB.
    assert_eq!(
        decode(0x1600_0000).unwrap().flow(0x1000_0000),
        Flow::Jump(Target::Address(0x0800_0000))
    );
}

#[test]
fn conditions() {
    let cases = [
        // b.hi, csel x0, x1, x2, lt, ccmp x1, #3, #0, ne
        (0x5400_0088, Some(Condition::Flags(Cond::Hi))),
        (0x9a82_b020, Some(Condition::Flags(Cond::Lt))),
        (0xfa43_1820, Some(Condition::Flags(Cond::Ne))),
        // cbz x1, cbnz w1
        (
            0xb400_0201,
            Some(Condition::Zero {
                register: x(1),
                zero: true,
            }),
        ),
        (
            0x3500_0201,
            Some(Condition::Zero {
                register: w(1),
                zero: false,
            }),
        ),
        // tbz w3, #5; tbnz x3, #63 (b5 makes the register 64-bit)
        (
            0x3628_0203,
            Some(Condition::Bit {
                register: w(3),
                bit: 5,
                set: false,
            }),
        ),
        (
            0xb7f8_0203,
            Some(Condition::Bit {
                register: x(3),
                bit: 63,
                set: true,
            }),
        ),
        // cbgt x1, #3; cbbeq w1, w2
        (
            0xf501_8201,
            Some(Condition::Compare {
                cond: Cond::Gt,
                left: x(1),
                right: CompareOperand::Immediate(3),
            }),
        ),
        (
            0x74c2_be01,
            Some(Condition::Compare {
                cond: Cond::Eq,
                left: w(1),
                right: CompareOperand::Register(w(2)),
            }),
        ),
        // b, ret, add: none
        (0x1400_0010, None),
        (0xd65f_03c0, None),
        (0x8b02_0020, None),
    ];
    for (word, expected) in cases {
        assert_eq!(condition(word), expected, "{word:08x}");
    }
}

#[test]
fn conditions_are_the_encodings_not_the_aliases() {
    // cset w0, eq is csinc w0, wzr, wzr, ne: the selection tests ne.
    let cset = decode(0x1a9f_17e0).unwrap();
    assert_eq!(cset.display(0).to_string(), "cset\tw0, eq");
    assert_eq!(cset.condition(), Some(Condition::Flags(Cond::Ne)));
}

#[test]
fn decoder_steps_four_bytes() {
    // mov x0, x1; an unallocated word; ret; two bytes left
    let code = [
        0xe0, 0x03, 0x01, 0xaa, 0xff, 0xff, 0xff, 0xff, 0xc0, 0x03, 0x5f, 0xd6, 0x1f, 0x20,
    ];
    let decoder = Decoder::new(&code, 0x1000);
    assert_eq!(decoder.len(), 4);
    let items: Vec<(u64, Result<&str, Error>)> = decoder
        .map(|(address, result)| (address, result.map(Instruction::mnemonic)))
        .collect();
    assert_eq!(
        items,
        [
            (0x1000, Ok("mov")),
            (0x1004, Err(Error::Unallocated)),
            (0x1008, Ok("ret")),
            (0x100c, Err(Error::TooShort)),
        ]
    );
}

#[test]
fn implements_binbun_isa() {
    let bytes = 0x1000_0080u32.to_le_bytes(); // adr x0, +16
    let adr = AArch64.decode(&bytes, Mode::A64).unwrap();
    assert_eq!(adr, decode_bytes(&bytes).unwrap());
    assert_eq!(adr.len(), 4);
    assert_eq!(adr.computed_address(0x1010), Some(0x1020));
    // adrp computes a page, not a pointer.
    assert_eq!(decode(0xb000_0020).unwrap().computed_address(0x1014), None);
    assert_eq!(
        binbun_isa::Instruction::flow(&decode(0x1400_0010).unwrap(), 0x1000),
        Flow::Jump(Target::Address(0x1040))
    );
    assert_eq!(AArch64.decode(&bytes[..3], Mode::A64), Err(Error::TooShort));
}
