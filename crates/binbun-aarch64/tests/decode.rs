//! Decoding without an oracle: encodings of each top-level group, the
//! precedence of specific hints over `HINT`, field conditions, should-be bits
//! and the decode-time checks.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers fail loudly"
)]

use binbun_aarch64::operand::{
    Immediate, Label, LabelBase, Memory, Offset, Radix, Register, RegisterClass, Shift, ShiftKind,
    Writeback,
};
use binbun_aarch64::{
    Access, Encoding, Error, Feature, Instruction, LabelStyle, Operand, Sink, TokenKind, decode,
    decode_bytes,
};

fn encoding(word: u32) -> Result<Encoding, Error> {
    decode(word).map(Instruction::encoding)
}

fn text(word: u32) -> String {
    decode(word).unwrap().display(0x1000).to_string()
}

#[test]
fn writes_text_as_llvm_does() {
    // Texts LLVM 22 writes for these words (C API, every feature, hex
    // immediates).
    let cases = [
        (0x9140_3020, "add\tx0, x1, #0xc, lsl #12"),
        // An extended register with SP as source: `lsl #0` is left out.
        (0x8b21_63e0, "add\tx0, sp, x1"),
        (0xab22_03ff, "cmn\tsp, w2, uxtb"),
        // UBFM: LSL wins over UBFIZ where both apply.
        (0xd37e_f420, "lsl\tx0, x1, #2"),
        // BFM: LLVM writes BFI, not BFC, for the zero register.
        (0x3311_0ff9, "bfi\tw25, wzr, #15, #4"),
        // ORR from XZR stays ORR when MOVN could write the value.
        (0xb269_e3f9, "orr\tx25, xzr, #0xffffffffff80ffff"),
        (0xaa01_03e0, "mov\tx0, x1"),
        (0x5400_0080, "b.eq\t0x1010"),
        (0x9000_0001, "adrp\tx1, 0x1000"),
        (0xd65f_03c0, "ret"),
        (0xd420_0000, "brk\t#0"),
        // Optional offsets of 0 are left out; pre- and post-index offsets
        // are written, the fixed ones in decimal.
        (0xf940_0020, "ldr\tx0, [x1]"),
        (0xa8c0_0820, "ldp\tx0, x2, [x1], #0x0"),
        (0xf8f6_cde4, "ldrab\tx4, [x15, #-0x4a0]!"),
        (0xd980_0bea, "stlr\tx10, [sp, #-8]!"),
        (0x0cdf_a290, "ld1\t{ v16.8b, v17.8b }, [x20], #16"),
        (0x0dff_0134, "ld2\t{ v20.b, v21.b }[0], [x9], #2"),
        // Byte accesses write a zero shift when S is set.
        (0x3862_7820, "ldrb\tw0, [x1, x2, lsl #0]"),
        (0xb871_d836, "ldr\tw22, [x1, w17, sxtw #2]"),
        // LDEORB to the zero register is STEORB.
        (0x3823_205f, "steorb\tw3, [x2]"),
        (0x1901_0440, "cpyfp\t[x0]!, [x1]!, x2!"),
    ];
    for (word, expected) in cases {
        assert_eq!(text(word), expected, "{word:08x}");
    }
}

/// Labels as llvm-objdump 22 writes them (without its `<symbol>` suffix)
/// for these words at 0x1000 + 4 × index, and as LLVM's C API does.
#[test]
fn writes_labels_as_addresses_or_offsets() {
    let cases = [
        (0x1400_0010, "b\t0x1040", "b\t#0x40"),
        (0x54ff_ffc0, "b.eq\t0xffc", "b.eq\t#-0x8"),
        (0xb400_0201, "cbz\tx1, 0x1048", "cbz\tx1, #0x40"),
        (0x3628_0203, "tbz\tw3, #0x5, 0x104c", "tbz\tw3, #0x5, #0x40"),
        (0x1000_0080, "adr\tx0, 0x1020", "adr\tx0, #16"),
        (0xb000_0020, "adrp\tx0, 0x6000", "adrp\tx0, #20480"),
        (0x5800_0040, "ldr\tx0, 0x1020", "ldr\tx0, #0x8"),
        (
            0xd800_0040,
            "prfm\tpldl1keep, 0x1024",
            "prfm\tpldl1keep, #0x8",
        ),
        (
            0xf501_8201,
            "cbgt\tx1, #0x3, 0x1060",
            "cbgt\tx1, #0x3, #0x40",
        ),
        (0x74c2_be01, "cbbeq\tw1, w2, 0xfe4", "cbbeq\tw1, w2, #-0x40"),
        (0x5500_009f, "retaasppc\t0x1018", "retaasppc\t#-0x10"),
        (0xf380_009f, "autiasppc\t0x101c", "autiasppc\t#-0x10"),
        (0x9c00_0800, "ldr\tq0, 0x1130", "ldr\tq0, #0x100"),
        (0x9800_0021, "ldrsw\tx1, 0x1038", "ldrsw\tx1, #0x4"),
        (0x97ff_ffff, "bl\t0x1034", "bl\t#-0x4"),
    ];
    for (index, (word, absolute, relative)) in (0u64..).zip(cases) {
        let instruction = decode(word).unwrap();
        let address = 0x1000 + 4 * index;
        assert_eq!(
            instruction.display(address).to_string(),
            absolute,
            "{word:08x}"
        );
        assert_eq!(
            instruction
                .display_with(address, LabelStyle::Relative)
                .to_string(),
            relative,
            "{word:08x}"
        );
    }
    // Targets wrap around the address space.
    assert_eq!(
        decode(0x54ff_ffc0).unwrap().display(0).to_string(),
        "b.eq\t0xfffffffffffffff8"
    );
}

#[test]
fn operands_are_typed() {
    // add x0, x1, x2, lsl #3
    let add = decode(0x8b02_0c20).unwrap();
    let x = |number| Operand::Register(Register::new(RegisterClass::X, number));
    assert_eq!(
        add.operands().as_slice(),
        [
            x(0),
            x(1),
            x(2),
            Operand::Shift(Shift {
                kind: ShiftKind::Lsl,
                amount: 3
            })
        ]
    );
    // adrp x1, page + 0x3000: the label is relative to the page.
    let operands = decode(0xf000_0001).unwrap().operands();
    let [_, Operand::Label(label)] = operands.as_slice() else {
        panic!("{operands:?}");
    };
    assert_eq!(
        *label,
        Label {
            offset: 0x3000,
            base: LabelBase::Page,
            radix: Radix::Decimal
        }
    );
    assert_eq!(label.target(0x1234_5678), 0x1234_8000);
    // ldp x0, x2, [x1], #0x0: one memory operand, written back after.
    let operands = decode(0xa8c0_0820).unwrap().operands();
    assert_eq!(
        operands.as_slice()[2],
        Operand::Memory(Memory {
            base: Register::new(RegisterClass::Xsp, 1),
            offset: Offset::Immediate(Immediate::signed(0)),
            writeback: Writeback::Post,
        })
    );
}

#[test]
fn encoding_operands_ignore_aliases() {
    let x = |number| Operand::Register(Register::new(RegisterClass::X, number));
    // cmp x1, #0x5 is subs xzr, x1, #0x5: the destination is an operand of
    // the encoding, written.
    let cmp = decode(0xf100_143f).unwrap();
    assert_eq!(cmp.mnemonic(), "cmp");
    assert_eq!(cmp.operands().len(), 2);
    assert_eq!(
        cmp.encoding_operands().as_slice(),
        [
            x(31),
            Operand::Register(Register::new(RegisterClass::Xsp, 1)),
            Operand::Immediate(Immediate::unsigned(5)),
        ]
    );
    assert_eq!(
        cmp.encoding_access().as_slice(),
        [Access::Write, Access::Read, Access::Read]
    );
    assert_eq!(cmp.access().as_slice(), [Access::Read, Access::Read]);
    // mov x0, x1 is orr x0, xzr, x1.
    let mov = decode(0xaa01_03e0).unwrap();
    assert_eq!(mov.operands().as_slice(), [x(0), x(1)]);
    assert_eq!(mov.encoding_operands().as_slice(), [x(0), x(31), x(1)]);
    assert_eq!(
        mov.encoding_access().as_slice(),
        [Access::Write, Access::Read, Access::Read]
    );
}

#[test]
fn sinks_receive_typed_tokens() {
    struct Tokens(Vec<(TokenKind, String)>);
    impl Sink for Tokens {
        fn token(&mut self, kind: TokenKind, text: &str) -> std::fmt::Result {
            self.0.push((kind, text.to_owned()));
            Ok(())
        }
    }
    let mut tokens = Tokens(Vec::new());
    // add x0, x1, x2, lsl #3
    decode(0x8b02_0c20).unwrap().format(0, &mut tokens).unwrap();
    let expected = [
        (TokenKind::Mnemonic, "add"),
        (TokenKind::Whitespace, "\t"),
        (TokenKind::Register, "x0"),
        (TokenKind::Punctuation, ", "),
        (TokenKind::Register, "x1"),
        (TokenKind::Punctuation, ", "),
        (TokenKind::Register, "x2"),
        (TokenKind::Punctuation, ", "),
        (TokenKind::Text, "lsl"),
        (TokenKind::Whitespace, " "),
        (TokenKind::Immediate, "#3"),
    ];
    let expected: Vec<(TokenKind, String)> = expected
        .iter()
        .map(|(kind, text)| (*kind, (*text).to_owned()))
        .collect();
    assert_eq!(tokens.0, expected);
    // A label is one Address token, absolute or relative.
    let mut tokens = Tokens(Vec::new());
    decode(0xb400_0201)
        .unwrap()
        .format(0x1008, &mut tokens)
        .unwrap();
    assert_eq!(tokens.0[4], (TokenKind::Address, "0x1048".to_owned()));
    let mut tokens = Tokens(Vec::new());
    decode(0xb400_0201)
        .unwrap()
        .format_with(0x1008, LabelStyle::Relative, &mut tokens)
        .unwrap();
    assert_eq!(tokens.0[4], (TokenKind::Address, "#0x40".to_owned()));
}

#[test]
fn decodes_each_group() {
    let cases = [
        (0x9100_0420, Encoding::ADD_64_addsub_imm), // add x0, x1, #1
        (0x8b02_0020, Encoding::ADD_64_addsub_shift), // add x0, x1, x2
        (0xf940_0020, Encoding::LDR_64_ldst_pos),   // ldr x0, [x1]
        (0x1400_0000, Encoding::B_only_branch_imm), // b .
        (0xd65f_03c0, Encoding::RET_64R_branch_reg), // ret
        (0x4e22_8420, Encoding::ADD_asimdsame_only), // add v0.16b, v1.16b, v2.16b
        (0x04a0_0000, Encoding::add_z_zz_),         // add z0.s, z0.s, z0.s
        (0xc008_00ff, Encoding::zero_za_i_),        // zero {za}
        (0x0000_0000, Encoding::UDF_only_perm_undef), // udf #0
    ];
    for (word, expected) in cases {
        assert_eq!(encoding(word), Ok(expected), "{word:08x}");
    }
    let add = decode(0x8b02_0020).unwrap();
    assert_eq!(add.word(), 0x8b02_0020);
    assert_eq!(add.encoding().mnemonic(), "ADD");
    assert_eq!(add.encoding().groups(), ["dpreg", "addsub_shift"]);
    assert_eq!(add.features(), []);
    assert_eq!(
        decode(0x04a0_0000).unwrap().features(),
        [Feature::SVE, Feature::SME]
    );
}

#[test]
fn specific_hints_win_over_the_catch_all() {
    assert_eq!(encoding(0xd503_201f), Ok(Encoding::NOP_HI_hints));
    assert_eq!(encoding(0xd503_233f), Ok(Encoding::PACIASP_HI_hints));
    // hint #0x7f has no instruction of its own.
    assert_eq!(encoding(0xd503_2fff), Ok(Encoding::HINT_HM_hints));
}

#[test]
fn field_conditions_select_the_encoding() {
    // PRFM (register) excludes Rt = 11xxx, which is RPRFM.
    assert_eq!(encoding(0xf8a1_6800), Ok(Encoding::PRFM_P_ldst_regoff));
    assert_eq!(encoding(0xf8a1_6818), Ok(Encoding::RPRFM_R_ldst_regoff));
}

#[test]
fn should_be_bits_are_not_required_where_llvm_accepts_them() {
    // fcmp s0, #0.0 with Rm (should be 00000) set to 1.
    assert_eq!(encoding(0x1e20_2008), Ok(Encoding::FCMP_SZ_floatcmp));
    assert_eq!(encoding(0x1e21_2008), Ok(Encoding::FCMP_SZ_floatcmp));
    // stxr w0, x0, [x1] with Rt2 (should be 11111) set to 0.
    assert_eq!(encoding(0xc800_7c20), Ok(Encoding::STXR_SR64_ldstexclr));
    assert_eq!(encoding(0xc800_0020), Ok(Encoding::STXR_SR64_ldstexclr));
    // ldar x0, [x1] with Rs (should be 11111) set to 0: LLVM rejects it.
    assert_eq!(encoding(0xc8df_fc20), Ok(Encoding::LDAR_LR64_ldstord));
    assert_eq!(encoding(0xc8c0_fc20), Err(Error::Unpredictable));
}

#[test]
fn decode_time_checks_reject_reserved_values() {
    // add x0, x1, x2 with shift == '11'.
    assert_eq!(encoding(0x8bc2_0020), Err(Error::Undefined));
    // and x0, x0, #imm: N:imms = 1:000000 is a bitmask, 1:111111 is all ones.
    assert_eq!(encoding(0x9240_0000), Ok(Encoding::AND_64_log_imm));
    assert_eq!(encoding(0x9240_fc00), Err(Error::Undefined));
    // sxtb z0.h, p0/m, z0.h; size == '00' (a byte source into bytes) has no
    // syntax.
    assert_eq!(encoding(0x0450_a000), Ok(Encoding::sxtb_z_p_z_m));
    assert_eq!(encoding(0x0410_a000), Err(Error::Undefined));
    // ldp x0, x0, [x1]: one register loaded twice.
    assert_eq!(encoding(0xa940_0020), Err(Error::Unpredictable));
    assert_eq!(encoding(0xa940_0420), Ok(Encoding::LDP_64_ldstpair_off));
    // No encoding has this word.
    assert_eq!(encoding(0xffff_ffff), Err(Error::Unallocated));
}

#[test]
fn pair_writeback_overlap_reads_each_register_field() {
    // ldp <Rt>, <Rt2>, [<Rn>], #16: base written back into a loaded
    // register is rejected (as LLVM rejects it) unless the base is SP.
    let ldp = |rt: u32, rt2: u32, rn: u32| encoding(0xa8c1_0000 | rt2 << 10 | rn << 5 | rt);
    assert_eq!(ldp(1, 2, 1), Err(Error::Unpredictable));
    assert_eq!(ldp(2, 1, 1), Err(Error::Unpredictable));
    assert_eq!(ldp(2, 3, 1), Ok(Encoding::LDP_64_ldstpair_post));
    // Register 31 is SP as the base and XZR as a loaded register, so these
    // do not overlap; with any two of the fields swapped they would.
    assert_eq!(ldp(31, 2, 31), Ok(Encoding::LDP_64_ldstpair_post));
    assert_eq!(ldp(2, 31, 31), Ok(Encoding::LDP_64_ldstpair_post));
}

#[test]
fn mops_overlap_reads_each_register_field() {
    // cpyfp [<Xd>]!, [<Xs>]!, <Xn>!: overlapping registers are rejected,
    // and so is XZR as an address, but not as the count.
    let cpyfp = |d: u32, s: u32, n: u32| encoding(0x1900_0400 | s << 16 | n << 5 | d);
    assert_eq!(cpyfp(0, 1, 0), Err(Error::Unpredictable));
    assert_eq!(cpyfp(0, 1, 2), Ok(Encoding::CPYFP_CPY_memcms));
    assert_eq!(cpyfp(0, 1, 31), Ok(Encoding::CPYFP_CPY_memcms));
    assert_eq!(cpyfp(31, 1, 2), Err(Error::Unpredictable));
    assert_eq!(cpyfp(0, 31, 2), Err(Error::Unpredictable));
}

#[test]
fn bytes_are_little_endian_and_four_long() {
    assert_eq!(
        decode_bytes(&[0x1f, 0x20, 0x03, 0xd5, 0xff]).map(Instruction::word),
        Ok(0xd503_201f)
    );
    assert_eq!(decode_bytes(&[0x1f, 0x20, 0x03]), Err(Error::TooShort));
    assert_eq!(size_of::<Instruction>(), 8);
}

#[test]
fn names_round_trip() {
    assert_eq!(Encoding::COUNT, 4429);
    for encoding in Encoding::ALL {
        assert_eq!(encoding.name().parse(), Ok(encoding));
    }
    for feature in Feature::ALL {
        assert_eq!(feature.name().parse(), Ok(feature));
    }
    assert!("ADD_32_addsub_im".parse::<Encoding>().is_err());
}

#[test]
fn fat_encodings_need_a_fat_feature() {
    for encoding in Encoding::ALL.into_iter().filter(|e| e.fat()) {
        assert!(
            encoding.features().iter().any(|f| f.fat()),
            "{encoding}: {:?}",
            encoding.features()
        );
    }
    // FEAT_FPv2 alone, and FEAT_FPv2 with SVE2p3 or SME2p3.
    assert!(Encoding::FMAXMG_D_floatdp2.fat());
    assert!(Encoding::fmaxmg_z_p_zz_.fat());
    // FEAT_MOPS_GO.
    assert!(Encoding::SETGOP_memset_go.fat());
    // FEAT_CFLT is announced (Armv9.7), though newer than LLVM 22.
    assert!(!Encoding::CFLTEQ_32_imm.fat());
    assert!(!Encoding::ADD_64_addsub_imm.fat());
}
