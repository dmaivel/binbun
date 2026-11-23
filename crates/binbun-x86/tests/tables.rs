//! The generated enums against XED's own (`xed-iclass-enum.h`,
//! `xed-reg-enum.h` built from the same datafiles).

use binbun_x86::{Mnemonic, Register, RegisterClass, UnknownName};

#[test]
fn mnemonics_are_xeds_decodable_iclasses() {
    // XED has 1995 iclasses; NOP2..NOP9 exist only for its encoder.
    assert_eq!(Mnemonic::COUNT, 1995 - 8);
    for mnemonic in Mnemonic::ALL {
        assert_eq!(mnemonic.as_str().parse(), Ok(mnemonic));
    }
    assert_eq!("REP_MOVSB".parse(), Ok(Mnemonic::RepMovsb));
    assert_eq!("rep_movsb".parse::<Mnemonic>(), Err(UnknownName));
    assert_eq!("NOP2".parse::<Mnemonic>(), Err(UnknownName));
}

#[test]
fn registers_follow_xed_order_and_metadata() {
    // xed_reg_enum_t has 365 members besides INVALID; ERROR is a lookup
    // failure marker rather than a register.
    assert_eq!(Register::COUNT, 365 - 1);

    // Classes are contiguous and in encoding order, so decoders can index.
    let offset = |base: Register, register: Register| register as usize - base as usize;
    assert_eq!(offset(Register::XMM0, Register::XMM31), 31);
    assert_eq!(offset(Register::RAX, Register::R31), 31);
    assert_eq!(offset(Register::AL, Register::R31B), 31);
    assert_eq!(offset(Register::AH, Register::BH), 3);
    assert_eq!(Register::RSP as usize - Register::RAX as usize, 4);

    assert_eq!(Register::AH.full(), Register::RAX);
    assert_eq!(Register::AH.full32(), Register::EAX);
    assert_eq!(Register::R9W.full(), Register::R9);
    assert_eq!(Register::XMM7.full(), Register::ZMM7);
    assert_eq!(Register::ZMM7.full(), Register::ZMM7);
    assert_eq!(Register::RFLAGS.class(), RegisterClass::Flags);
    assert_eq!(Register::AH.class(), RegisterClass::Gpr);
    assert_eq!(Register::MMX0.name(), "mm0");
    assert_eq!(Register::ST3.name(), "st(3)");
    assert_eq!(Register::R31B.to_string(), "r31b");
}
