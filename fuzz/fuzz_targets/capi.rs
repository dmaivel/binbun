//! The C API on arbitrary bytes, through its C entry points: every decode,
//! accessor, text and token function, with buffers of every size the input
//! picks, checking the API's promises (bounds, NUL-termination, cut text a
//! prefix of the whole, tokens covering the text and naming real operands,
//! the sweep covering the buffer). A panic is a crash: libFuzzer's panic
//! hook aborts before the library could catch it.

#![no_main]
#![allow(unsafe_code, reason = "the target calls the C API's entry points")]

use std::ffi::c_char;
use std::ptr;

use binbun_capi::aarch64::{
    self as a64, A64Decoder, A64Instruction, A64Operand, A64Register, binbun_aarch64_decode_bytes,
    binbun_aarch64_decode_word, binbun_aarch64_decoder_init, binbun_aarch64_decoder_next,
    binbun_aarch64_encoding_from_name, binbun_aarch64_encoding_name,
    binbun_aarch64_instruction_branch, binbun_aarch64_instruction_condition,
    binbun_aarch64_instruction_encoding, binbun_aarch64_instruction_flags,
    binbun_aarch64_instruction_implicit_reads, binbun_aarch64_instruction_memory,
    binbun_aarch64_instruction_mnemonic, binbun_aarch64_instruction_operands,
    binbun_aarch64_instruction_text, binbun_aarch64_instruction_tokens,
};
use binbun_capi::x86::{
    self, X86Decoder, X86Instruction, X86Operand, binbun_x86_decode_bytes,
    binbun_x86_decode_length, binbun_x86_decoder_init, binbun_x86_decoder_next,
    binbun_x86_form_from_name, binbun_x86_instruction_branch,
    binbun_x86_instruction_computed_address, binbun_x86_instruction_condition,
    binbun_x86_instruction_flags, binbun_x86_instruction_form, binbun_x86_instruction_length,
    binbun_x86_instruction_mnemonic, binbun_x86_instruction_operands, binbun_x86_instruction_text,
    binbun_x86_instruction_tokens, binbun_x86_mnemonic_from_name, binbun_x86_mnemonic_name,
    binbun_x86_register_describe, binbun_x86_register_name,
};
use binbun_capi::{Status, TextSize, Token, binbun_status_name};
use libfuzzer_sys::fuzz_target;

/// What a token's operand is when it is part of none.
const NO_OPERAND: u8 = 0xff;
/// `BINBUN_TOKEN_REGISTER`, `BINBUN_TOKEN_SEPARATOR`.
const REGISTER: u8 = 2;
const SEPARATOR: u8 = 10;

fuzz_target!(|data: &[u8]| {
    let Some((&selector, rest)) = data.split_first() else {
        return;
    };
    // Capacities and an address from the input's first bytes.
    let cut = usize::from(selector >> 3);
    let address = rest
        .first_chunk::<8>()
        .map_or(0x1000, |bytes| u64::from_le_bytes(*bytes));
    names(rest);
    match selector & 7 {
        mode @ 1..=5 => {
            x86_one(u32::from(mode), rest, address, cut);
            x86_sweep(u32::from(mode), rest, address);
        }
        6 => {
            a64_one(rest, address, cut);
            a64_sweep(rest, address);
        }
        _ => {
            // Unknown modes, null pointers.
            let mut storage = X86Instruction { opaque: [0; 24] };
            // SAFETY: valid buffer and storage.
            let status =
                unsafe { binbun_x86_decode_bytes(0, rest.as_ptr(), rest.len(), &raw mut storage) };
            assert!(status == Status::BadArgument || status == Status::NullPointer);
            // SAFETY: null pointers are allowed.
            assert_eq!(
                unsafe { binbun_x86_decode_bytes(5, rest.as_ptr(), rest.len(), ptr::null_mut()) },
                Status::NullPointer
            );
            // SAFETY: zeroed storage holds no instruction.
            assert_eq!(
                unsafe { binbun_x86_instruction_length(&raw const storage) },
                0
            );
        }
    }
});

/// Name lookups with ids and names from the input.
fn names(bytes: &[u8]) {
    let id = bytes
        .first_chunk::<2>()
        .map_or(0, |b| u16::from_le_bytes(*b));
    let _ = binbun_x86_mnemonic_name(id);
    let _ = binbun_x86_register_name(id);
    let _ = binbun_aarch64_encoding_name(id);
    let _ = binbun_status_name(i32::from(id));
    let mut info = std::mem::MaybeUninit::uninit();
    // SAFETY: `info` is writable.
    let _ = unsafe { binbun_x86_register_describe(id, info.as_mut_ptr()) };
    let name = bytes.as_ptr().cast::<c_char>();
    // SAFETY: `bytes` is readable for its length.
    unsafe {
        let _ = binbun_x86_mnemonic_from_name(name, bytes.len());
        let _ = binbun_x86_form_from_name(name, bytes.len());
        let _ = binbun_aarch64_encoding_from_name(name, bytes.len());
    }
}

/// Text and tokens of an instruction, through `text` and `tokens` (the
/// architecture's functions), checked against each other and the bounds.
fn check_text(
    text: impl Fn(*mut c_char, usize) -> usize,
    tokens: impl Fn(*mut c_char, usize, *mut Token, usize) -> TextSize,
    max_text: usize,
    max_tokens: usize,
    operands: usize,
    cut: usize,
    separators_are_operands: bool,
) {
    let mut whole = [0u8; 256];
    let length = text(whole.as_mut_ptr().cast(), whole.len());
    assert!(length > 0 && length <= max_text, "text of {length} bytes");
    assert_eq!(whole[length], 0);
    assert!(whole[..length].iter().all(|&b| b != 0 && b.is_ascii()));
    // Cut short: the same length, a NUL-terminated prefix.
    let mut short = [0xffu8; 256];
    assert_eq!(text(short.as_mut_ptr().cast(), cut), length);
    if cut > 0 {
        let kept = length.min(cut - 1);
        assert_eq!(short[..kept], whole[..kept]);
        assert_eq!(short[kept], 0);
    }
    assert!(short[cut..].iter().all(|&b| b == 0xff));
    assert_eq!(text(ptr::null_mut(), 0), length);

    let mut buffer = [0u8; 256];
    let mut list = [Token {
        kind: 0,
        operand: 0,
        reserved0: 0,
        offset: 0,
        length: 0,
        reserved1: 0,
        value: 0,
    }; 128];
    let size = tokens(
        buffer.as_mut_ptr().cast(),
        buffer.len(),
        list.as_mut_ptr(),
        list.len(),
    );
    assert_eq!(size.length, length);
    assert!(
        size.tokens > 0 && size.tokens <= max_tokens,
        "{} tokens",
        size.tokens
    );
    assert_eq!(buffer[..=length], whole[..=length]);
    let mut offset = 0;
    let mut separators = 0;
    for token in &list[..size.tokens] {
        assert_eq!(token.offset as usize, offset);
        assert!(token.length > 0);
        offset += token.length as usize;
        assert!(token.operand == NO_OPERAND || usize::from(token.operand) < operands);
        if token.kind == SEPARATOR {
            separators += 1;
        }
        if token.kind == REGISTER {
            assert_ne!(
                token.operand, NO_OPERAND,
                "register token outside the operands"
            );
        }
    }
    assert_eq!(offset, length);
    if separators_are_operands {
        assert_eq!(separators, operands.saturating_sub(1));
    }
    let partial = tokens(ptr::null_mut(), 0, list.as_mut_ptr(), cut.min(list.len()));
    assert_eq!(partial, size);
}

fn x86_one(mode: u32, bytes: &[u8], address: u64, cut: usize) {
    let mut inst = X86Instruction { opaque: [0; 24] };
    // SAFETY: `bytes` is readable, `inst` writable.
    let status =
        unsafe { binbun_x86_decode_bytes(mode, bytes.as_ptr(), bytes.len(), &raw mut inst) };
    let mut length = 0;
    // SAFETY: as above.
    let length_status =
        unsafe { binbun_x86_decode_length(mode, bytes.as_ptr(), bytes.len(), &raw mut length) };
    if status != Status::Ok {
        assert!(
            status != Status::Failed
                && status != Status::NullPointer
                && status != Status::BadArgument
        );
        // SAFETY: storage is still zeroed: no instruction.
        assert_eq!(unsafe { binbun_x86_instruction_length(&raw const inst) }, 0);
        return;
    }
    let inst = &raw const inst;
    // SAFETY: `inst` holds an instruction; out-pointers are valid.
    unsafe {
        let len = usize::from(binbun_x86_instruction_length(inst));
        assert!((1..=x86::MAX_LENGTH).contains(&len) && len <= bytes.len());
        assert_eq!((length_status, length), (Status::Ok, len));
        let name = binbun_x86_mnemonic_name(binbun_x86_instruction_mnemonic(inst));
        assert!(name.length > 0);
        assert!(binbun_x86_instruction_form(inst) > 0);
        assert!(binbun_x86_instruction_condition(inst) <= 23);
        let _ = binbun_x86_instruction_branch(inst, address);
        let mut computed = 0;
        let _ = binbun_x86_instruction_computed_address(inst, address, &raw mut computed);
        let _ = binbun_x86_instruction_flags(inst);
        let mut operands = [X86Operand::default(); x86::MAX_OPERANDS];
        let count = binbun_x86_instruction_operands(inst, operands.as_mut_ptr(), operands.len());
        assert!(count <= x86::MAX_OPERANDS);
        assert_eq!(
            binbun_x86_instruction_operands(inst, operands.as_mut_ptr(), cut.min(count)),
            count
        );
        check_text(
            |text, capacity| binbun_x86_instruction_text(inst, address, 0, text, capacity),
            |text, capacity, tokens, token_capacity| {
                binbun_x86_instruction_tokens(
                    inst,
                    address,
                    0,
                    text,
                    capacity,
                    tokens,
                    token_capacity,
                )
            },
            x86::MAX_TEXT,
            x86::MAX_TOKENS,
            count,
            cut,
            false,
        );
    }
}

fn x86_sweep(mode: u32, bytes: &[u8], address: u64) {
    let mut decoder = std::mem::MaybeUninit::<X86Decoder>::uninit();
    // SAFETY: `decoder` is writable; `bytes` outlives the sweep.
    let status = unsafe {
        binbun_x86_decoder_init(
            decoder.as_mut_ptr(),
            mode,
            bytes.as_ptr(),
            bytes.len(),
            address,
        )
    };
    assert_eq!(status, Status::Ok);
    // SAFETY: initialised by the call above.
    let mut decoder = unsafe { decoder.assume_init() };
    let mut inst = X86Instruction { opaque: [0; 24] };
    let mut expected = 0usize;
    loop {
        let mut at = 0;
        // SAFETY: valid decoder, storage and out-pointer.
        let status =
            unsafe { binbun_x86_decoder_next(&raw mut decoder, &raw mut inst, &raw mut at) };
        if status == Status::End {
            break;
        }
        assert_eq!(at, address.wrapping_add(expected as u64));
        expected += if status == Status::Ok {
            // SAFETY: the decode succeeded.
            usize::from(unsafe { binbun_x86_instruction_length(&raw const inst) })
        } else {
            1
        };
        assert_eq!(decoder.offset, expected);
    }
    assert!(expected >= bytes.len());
}

fn a64_one(bytes: &[u8], address: u64, cut: usize) {
    let mut inst = A64Instruction { opaque: [0; 4] };
    // SAFETY: `bytes` is readable, `inst` writable.
    let status = unsafe { binbun_aarch64_decode_bytes(bytes.as_ptr(), bytes.len(), &raw mut inst) };
    if bytes.len() < 4 {
        assert_eq!(status, Status::Truncated);
    }
    if let Some(word) = bytes.first_chunk::<4>() {
        let mut again = A64Instruction { opaque: [0; 4] };
        // SAFETY: `again` is writable.
        let word_status =
            unsafe { binbun_aarch64_decode_word(u32::from_le_bytes(*word), &raw mut again) };
        assert_eq!(word_status, status);
    }
    if status != Status::Ok {
        return;
    }
    let inst = &raw const inst;
    // SAFETY: `inst` holds an instruction; out-pointers are valid.
    unsafe {
        assert!(binbun_aarch64_instruction_encoding(inst) > 0);
        assert!(binbun_aarch64_instruction_mnemonic(inst).length > 0);
        let _ = binbun_aarch64_instruction_branch(inst, address);
        let mut condition = std::mem::MaybeUninit::uninit();
        let _ = binbun_aarch64_instruction_condition(inst, condition.as_mut_ptr());
        let _ = binbun_aarch64_instruction_flags(inst);
        let mut memory = std::mem::MaybeUninit::uninit();
        let _ = binbun_aarch64_instruction_memory(inst, memory.as_mut_ptr());
        let mut registers = [A64Register::default(); 8];
        assert!(
            binbun_aarch64_instruction_implicit_reads(inst, registers.as_mut_ptr(), cut.min(8))
                <= 8
        );
        let mut operands = [std::mem::MaybeUninit::<A64Operand>::uninit(); a64::MAX_OPERANDS];
        let count =
            binbun_aarch64_instruction_operands(inst, operands.as_mut_ptr().cast(), operands.len());
        assert!(count <= a64::MAX_OPERANDS);
        for options in [0, 1] {
            check_text(
                |text, capacity| {
                    binbun_aarch64_instruction_text(inst, address, options, text, capacity)
                },
                |text, capacity, tokens, token_capacity| {
                    binbun_aarch64_instruction_tokens(
                        inst,
                        address,
                        options,
                        text,
                        capacity,
                        tokens,
                        token_capacity,
                    )
                },
                a64::MAX_TEXT,
                a64::MAX_TOKENS,
                count,
                cut,
                true,
            );
        }
    }
}

fn a64_sweep(bytes: &[u8], address: u64) {
    let mut decoder = std::mem::MaybeUninit::<A64Decoder>::uninit();
    // SAFETY: `decoder` is writable; `bytes` outlives the sweep.
    let status = unsafe {
        binbun_aarch64_decoder_init(decoder.as_mut_ptr(), bytes.as_ptr(), bytes.len(), address)
    };
    assert_eq!(status, Status::Ok);
    // SAFETY: initialised by the call above.
    let mut decoder = unsafe { decoder.assume_init() };
    let mut inst = A64Instruction { opaque: [0; 4] };
    let mut steps = 0usize;
    loop {
        let mut at = 0;
        // SAFETY: valid decoder, storage and out-pointer.
        let status =
            unsafe { binbun_aarch64_decoder_next(&raw mut decoder, &raw mut inst, &raw mut at) };
        if status == Status::End {
            break;
        }
        assert_eq!(at, address.wrapping_add(4 * steps as u64));
        steps += 1;
    }
    assert_eq!(steps, bytes.len().div_ceil(4));
}
