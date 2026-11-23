//! x86 (16, 32 and 64-bit): the `binbun_x86_*` functions over
//! [`binbun_x86`].

mod operand;
mod tokens;

use std::ffi::c_char;
use std::fmt::Write as _;

use binbun_isa::Instruction as _;
use binbun_x86::{
    Category, Condition, DecodeError, Encoding, Extension, Form, Instruction, IsaSet,
    MAX_LENGTH as DECODER_MAX_LENGTH, MAX_OPERANDS as DECODER_MAX_OPERANDS, Mnemonic, Mode,
    Register, RegisterClass, decode, decode_length,
};

pub use operand::{X86Operand, binbun_x86_instruction_operands};
pub use tokens::write as write_tokens;

use crate::ffi::{self, Stored};
use crate::text::{TextOut, TextSize, Token, TokenOut};
use crate::{
    Branch, Status, Str, TEXT_DEFAULT, guard, name as utf8_name, read as read_storage, status,
};

/// The longest instruction, in bytes (`BINBUN_X86_MAX_LENGTH`).
pub const MAX_LENGTH: usize = 15;
/// Most operands an instruction has (`BINBUN_X86_MAX_OPERANDS`).
pub const MAX_OPERANDS: usize = 16;
/// The longest text, without its NUL (`BINBUN_X86_MAX_TEXT`): x86 cannot be
/// swept whole, so a bound well above what is seen (57 at any offset of
/// libc, libcrypto, libstdc++ and bash) that the fuzz target checks.
pub const MAX_TEXT: usize = 160;
/// Most tokens an instruction's text has (`BINBUN_X86_MAX_TOKENS`): 21 seen,
/// as [`MAX_TEXT`].
pub const MAX_TOKENS: usize = 64;

const _: () = assert!(DECODER_MAX_LENGTH == MAX_LENGTH);
const _: () = assert!(DECODER_MAX_OPERANDS <= MAX_OPERANDS);

/// Tags storage that holds an x86 instruction.
pub(crate) const TAG: u64 = u64::from_le_bytes(*b"bbnx86\x00\x01");

/// Storage for one decoded instruction, owned by the caller
/// (`binbun_x86_instruction`).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct X86Instruction {
    /// Contents only the library reads.
    pub opaque: [u64; 24],
}

// The layouts the header describes, on 64-bit targets.
#[cfg(target_pointer_width = "64")]
const _: () = assert!(size_of::<X86Instruction>() == 192 && align_of::<X86Instruction>() == 8);

/// A linear sweep over a buffer, owned by the caller
/// (`binbun_x86_decoder`).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct X86Decoder {
    /// The buffer.
    pub bytes: *const u8,
    /// Its length.
    pub length: usize,
    /// Offset of the next instruction in the buffer.
    pub offset: usize,
    /// Address of the buffer's first byte.
    pub address: u64,
    /// The mode, a `binbun_x86_mode`.
    pub mode: u32,
    /// Zero.
    pub reserved: u32,
}

#[cfg(target_pointer_width = "64")]
const _: () = assert!(size_of::<X86Decoder>() == 40 && align_of::<X86Decoder>() == 8);

/// What an instruction does to the flags (`binbun_x86_flag_effect`).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct X86FlagEffect {
    /// Flags read, `BINBUN_X86_FLAG_` bits (`RFLAGS` positions, the x87
    /// condition codes in bits 28–31).
    pub read: u32,
    /// Flags written (modified, set, cleared or undefined).
    pub written: u32,
    /// Flags left undefined.
    pub undefined: u32,
    /// Whether the instruction may write flags.
    pub may_write: bool,
    /// Whether it always writes them.
    pub must_write: bool,
    /// Zero.
    pub reserved: u16,
}

const _: () = assert!(size_of::<X86FlagEffect>() == 16);

impl X86FlagEffect {
    /// What `instruction` does to the flags; all zero for none.
    pub fn of(instruction: &Instruction) -> Self {
        instruction
            .flags()
            .map_or_else(Self::default, |flags| Self {
                read: flags.read.0,
                written: flags.written.0,
                undefined: flags.undefined.0,
                may_write: flags.may_write,
                must_write: flags.must_write,
                reserved: 0,
            })
    }
}

/// What a register is (`binbun_x86_register_info`).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct X86RegisterInfo {
    /// Its class, a `binbun_x86_register_class`.
    pub class: u8,
    /// Zero.
    pub reserved: u8,
    /// Its width in bits in 64-bit mode; 0 for pseudo registers.
    pub width: u16,
    /// The largest register containing it in 64-bit mode (`rax` for `al`).
    pub full: u16,
    /// The largest register containing it outside 64-bit mode.
    pub full32: u16,
    /// The bit at which it starts within `full` (8 for `ah`).
    pub offset: u32,
}

const _: () = assert!(size_of::<X86RegisterInfo>() == 12);

/// The mode numbered `mode` (`binbun_x86_mode`).
///
/// # Errors
///
/// [`Status::BadArgument`] for a number that is no mode.
pub const fn decode_mode(mode: u32) -> Result<Mode, Status> {
    Ok(match mode {
        1 => Mode::Real16,
        2 => Mode::Real32,
        3 => Mode::Bits16,
        4 => Mode::Bits32,
        5 => Mode::Bits64,
        _ => return Err(Status::BadArgument),
    })
}

/// The status of a decode that failed with `error`.
pub const fn failure(error: DecodeError) -> Status {
    match error {
        DecodeError::TooShort => Status::Truncated,
        DecodeError::TooLong => Status::X86TooLong,
        DecodeError::Invalid => Status::Invalid,
        DecodeError::InvalidMode => Status::X86InvalidMode,
        DecodeError::BadRegister => Status::X86BadRegister,
        DecodeError::BadLockPrefix => Status::X86BadLockPrefix,
        DecodeError::BadLegacyPrefix => Status::X86BadLegacyPrefix,
        DecodeError::BadRexPrefix => Status::X86BadRexPrefix,
        DecodeError::BadMap => Status::X86BadMap,
        DecodeError::BadEvexVPrime => Status::X86BadEvexVPrime,
        DecodeError::BadEvexZeroingWithoutMask => Status::X86BadEvexZeroing,
        DecodeError::BadEvexLength => Status::X86BadEvexLength,
        DecodeError::GatherRegisters => Status::X86GatherRegisters,
        DecodeError::BadRegisterMatch => Status::X86BadRegisterMatch,
    }
}

/// How many bytes of storage a decode writes, as the library was built:
/// no more than `sizeof(binbun_x86_instruction)`.
#[unsafe(no_mangle)]
pub extern "C" fn binbun_x86_instruction_size() -> usize {
    size_of::<Stored<Instruction>>()
}

/// Decodes the instruction at the start of the `len` bytes at `bytes` in
/// `mode` into `out`, which is written only on [`Status::Ok`].
///
/// # Safety
///
/// `bytes` is null or readable for `len` bytes; `out` is null or writable
/// storage.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn binbun_x86_decode_bytes(
    mode: u32,
    bytes: *const u8,
    len: usize,
    out: *mut X86Instruction,
) -> Status {
    status(|| {
        // SAFETY: `bytes` is null or readable for `len` bytes (contract).
        let bytes = unsafe { ffi::bytes(bytes, len) }?;
        ffi::storage(out)?;
        let instruction = decode(bytes, decode_mode(mode)?).map_err(failure)?;
        // SAFETY: `out` passed `storage` and is writable storage (contract).
        unsafe { ffi::store(out, TAG, instruction) };
        Ok(())
    })
}

/// The length of the instruction at the start of the `len` bytes at
/// `bytes`, into `*length` (only on [`Status::Ok`]): XED's length decoder,
/// which decodes prefixes and opcode maps but does not check which
/// instructions exist, so it succeeds on some bytes a full decode rejects.
///
/// # Safety
///
/// `bytes` is null or readable for `len` bytes; `length` is null or
/// writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn binbun_x86_decode_length(
    mode: u32,
    bytes: *const u8,
    len: usize,
    length: *mut usize,
) -> Status {
    status(|| {
        // SAFETY: `bytes` is null or readable for `len` bytes (contract).
        let bytes = unsafe { ffi::bytes(bytes, len) }?;
        if length.is_null() {
            return Err(Status::NullPointer);
        }
        let n = decode_length(bytes, decode_mode(mode)?).map_err(failure)?;
        // SAFETY: `length` is writable (contract).
        unsafe { ffi::write(length, n) };
        Ok(())
    })
}

/// Starts a sweep of the `length` bytes at `bytes`, which are at
/// `address`, in `mode`.
///
/// # Safety
///
/// `decoder` is null or writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn binbun_x86_decoder_init(
    decoder: *mut X86Decoder,
    mode: u32,
    bytes: *const u8,
    length: usize,
    address: u64,
) -> Status {
    status(|| {
        if decoder.is_null() || (bytes.is_null() && length != 0) {
            return Err(Status::NullPointer);
        }
        decode_mode(mode)?;
        let value = X86Decoder {
            bytes,
            length,
            offset: 0,
            address,
            mode,
            reserved: 0,
        };
        // SAFETY: `decoder` is writable (contract).
        unsafe { ffi::write(decoder, value) };
        Ok(())
    })
}

/// Decodes the next instruction of the sweep into `out` (written only on
/// [`Status::Ok`]) and its address into `*address` (if not null, whatever
/// the status but [`Status::End`]), then moves past it, or one byte on after
/// bytes that are no instruction.
///
/// # Safety
///
/// `decoder` is null or a decoder whose bytes are readable; `out` is null
/// or writable storage; `address` is null or writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn binbun_x86_decoder_next(
    decoder: *mut X86Decoder,
    out: *mut X86Instruction,
    address: *mut u64,
) -> Status {
    status(|| {
        // SAFETY: `decoder` is null or the caller's decoder (contract).
        let decoder = unsafe { ffi::borrow_mut(decoder) }.ok_or(Status::NullPointer)?;
        ffi::storage(out)?;
        let mode = decode_mode(decoder.mode)?;
        // SAFETY: the decoder's bytes are readable (contract).
        let bytes = unsafe { ffi::bytes(decoder.bytes, decoder.length) }?;
        // As `binbun_x86::Decoder` sweeps, without its item to copy.
        let offset = decoder.offset;
        let rest = bytes
            .get(offset..)
            .filter(|rest| !rest.is_empty())
            .ok_or(Status::End)?;
        // SAFETY: `address` is null or writable (contract).
        unsafe { ffi::write(address, decoder.address.wrapping_add(offset as u64)) };
        match decode(rest, mode) {
            Ok(instruction) => {
                decoder.offset = offset + instruction.len();
                // SAFETY: `out` passed `storage` and is writable storage
                // (contract).
                unsafe { ffi::store(out, TAG, instruction) };
                Ok(())
            }
            Err(error) => {
                decoder.offset = offset + 1;
                Err(failure(error))
            }
        }
    })
}

/// `body` of the instruction in `inst`, or `failed` if `inst` holds none or
/// `body` panics.
///
/// # Safety
///
/// `inst` is null or storage a successful decode wrote, unchanged since.
unsafe fn read<T: Copy>(
    inst: *const X86Instruction,
    failed: T,
    body: impl FnOnce(&Instruction) -> T,
) -> T {
    // SAFETY: passed on from the caller.
    unsafe { read_storage(inst, TAG, failed, body) }
}

/// The id of a 0-based enumeration value: its number plus one, so that 0
/// is none.
fn id(index: usize) -> u16 {
    u16::try_from(index + 1).unwrap_or(0)
}

/// The value of 1-based id `id` among `all`.
fn from_id<T: Copy>(all: &[T], id: u16) -> Option<T> {
    all.get(usize::from(id).checked_sub(1)?).copied()
}

/// The instruction's length in bytes, 1 to 15; 0 if `inst` holds none.
///
/// # Safety
///
/// `inst` is null or storage a successful decode wrote, unchanged since.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn binbun_x86_instruction_length(inst: *const X86Instruction) -> u8 {
    // SAFETY: the contract of `inst`.
    unsafe { read(inst, 0, |i| u8::try_from(i.len()).unwrap_or(0)) }
}

/// The instruction's mnemonic (XED's iclass), a `binbun_x86_mnemonic`; 0
/// if `inst` holds none.
///
/// # Safety
///
/// `inst` is null or storage a successful decode wrote, unchanged since.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn binbun_x86_instruction_mnemonic(inst: *const X86Instruction) -> u16 {
    // SAFETY: the contract of `inst`.
    unsafe { read(inst, 0, |i| id(i.mnemonic() as usize)) }
}

/// The instruction's form (XED's iform), a `binbun_x86_form`; 0 if `inst`
/// holds none.
///
/// # Safety
///
/// `inst` is null or storage a successful decode wrote, unchanged since.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn binbun_x86_instruction_form(inst: *const X86Instruction) -> u16 {
    // SAFETY: the contract of `inst`.
    unsafe { read(inst, 0, |i| id(i.form() as usize)) }
}

/// The instruction's category, a `binbun_x86_category`; 0 if `inst` holds
/// none.
///
/// # Safety
///
/// `inst` is null or storage a successful decode wrote, unchanged since.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn binbun_x86_instruction_category(inst: *const X86Instruction) -> u16 {
    // SAFETY: the contract of `inst`.
    unsafe { read(inst, 0, |i| id(i.category() as usize)) }
}

/// The ISA extension of the instruction, a `binbun_x86_extension`; 0 if
/// `inst` holds none.
///
/// # Safety
///
/// `inst` is null or storage a successful decode wrote, unchanged since.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn binbun_x86_instruction_extension(inst: *const X86Instruction) -> u16 {
    // SAFETY: the contract of `inst`.
    unsafe { read(inst, 0, |i| id(i.extension() as usize)) }
}

/// The feature set the instruction needs, a `binbun_x86_isa_set`; 0 if
/// `inst` holds none.
///
/// # Safety
///
/// `inst` is null or storage a successful decode wrote, unchanged since.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn binbun_x86_instruction_isa_set(inst: *const X86Instruction) -> u16 {
    // SAFETY: the contract of `inst`.
    unsafe { read(inst, 0, |i| id(i.isa_set() as usize)) }
}

/// How the instruction is encoded, a `binbun_x86_encoding`; 0 if `inst`
/// holds none.
///
/// # Safety
///
/// `inst` is null or storage a successful decode wrote, unchanged since.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn binbun_x86_instruction_encoding(inst: *const X86Instruction) -> u8 {
    // SAFETY: the contract of `inst`.
    unsafe { read(inst, 0, |i| encoding(i.encoding())) }
}

/// `encoding` as a `binbun_x86_encoding`.
pub const fn encoding(encoding: Encoding) -> u8 {
    match encoding {
        Encoding::Legacy => 1,
        Encoding::Vex => 2,
        Encoding::Evex => 3,
        Encoding::Xop => 4,
    }
}

/// The condition the instruction tests (a conditional jump, `SETcc`,
/// `CMOVcc`…), a `binbun_x86_condition`; 0 for none.
///
/// # Safety
///
/// `inst` is null or storage a successful decode wrote, unchanged since.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn binbun_x86_instruction_condition(inst: *const X86Instruction) -> u8 {
    // SAFETY: the contract of `inst`.
    unsafe { read(inst, 0, |i| i.condition().map_or(0, condition)) }
}

/// `condition` as a `binbun_x86_condition`.
pub const fn condition(condition: Condition) -> u8 {
    match condition {
        Condition::Overflow => 1,
        Condition::NotOverflow => 2,
        Condition::Below => 3,
        Condition::NotBelow => 4,
        Condition::Zero => 5,
        Condition::NotZero => 6,
        Condition::BelowOrEqual => 7,
        Condition::Above => 8,
        Condition::Sign => 9,
        Condition::NotSign => 10,
        Condition::Parity => 11,
        Condition::NotParity => 12,
        Condition::Less => 13,
        Condition::NotLess => 14,
        Condition::LessOrEqual => 15,
        Condition::Greater => 16,
        Condition::False => 17,
        Condition::True => 18,
        Condition::CountZero => 19,
        Condition::Loop => 20,
        Condition::LoopZero => 21,
        Condition::LoopNotZero => 22,
        Condition::TransactionAbort => 23,
    }
}

/// The effective operand width in bits (8, 16, 32 or 64); 0 if `inst`
/// holds none.
///
/// # Safety
///
/// `inst` is null or storage a successful decode wrote, unchanged since.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn binbun_x86_instruction_operand_width(inst: *const X86Instruction) -> u32 {
    // SAFETY: the contract of `inst`.
    unsafe { read(inst, 0, Instruction::operand_width) }
}

/// The effective address width in bits (16, 32 or 64), 0 if the
/// instruction has none or `inst` holds none.
///
/// # Safety
///
/// `inst` is null or storage a successful decode wrote, unchanged since.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn binbun_x86_instruction_address_width(inst: *const X86Instruction) -> u32 {
    // SAFETY: the contract of `inst`.
    unsafe { read(inst, 0, Instruction::address_width) }
}

/// The stack address width in bits (16, 32 or 64); 0 if `inst` holds none.
///
/// # Safety
///
/// `inst` is null or storage a successful decode wrote, unchanged since.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn binbun_x86_instruction_stack_address_width(
    inst: *const X86Instruction,
) -> u32 {
    // SAFETY: the contract of `inst`.
    unsafe { read(inst, 0, Instruction::stack_address_width) }
}

/// What the instruction at `address` does to the flow of control.
///
/// # Safety
///
/// `inst` is null or storage a successful decode wrote, unchanged since.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn binbun_x86_instruction_branch(
    inst: *const X86Instruction,
    address: u64,
) -> Branch {
    // SAFETY: the contract of `inst`.
    unsafe { read(inst, Branch::NONE, |i| Branch::new(i.flow(address))) }
}

/// The address a RIP-relative `lea` at `address` computes, into `*out`;
/// whether it computes one.
///
/// # Safety
///
/// `inst` is null or storage a successful decode wrote, unchanged since;
/// `out` is null or writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn binbun_x86_instruction_computed_address(
    inst: *const X86Instruction,
    address: u64,
    out: *mut u64,
) -> bool {
    // SAFETY: the contract of `inst`.
    let computed = unsafe { read(inst, None, |i| i.computed_address(address)) };
    let Some(computed) = computed else {
        return false;
    };
    // SAFETY: `out` is null or writable (contract).
    unsafe { ffi::write(out, computed) };
    !out.is_null()
}

/// What the instruction does to the flags; all zero if it touches none or
/// `inst` holds none.
///
/// # Safety
///
/// `inst` is null or storage a successful decode wrote, unchanged since.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn binbun_x86_instruction_flags(
    inst: *const X86Instruction,
) -> X86FlagEffect {
    // SAFETY: the contract of `inst`.
    unsafe { read(inst, X86FlagEffect::default(), X86FlagEffect::of) }
}

/// Writes the instruction at `address` as Intel-syntax text (as XED prints
/// it) into `text`, NUL-terminated when `capacity` allows. Returns the
/// length of the whole text without the NUL (more than `capacity - 1` when
/// it was cut short), or 0 if `inst` holds no instruction or `options` is
/// not `BINBUN_TEXT_DEFAULT`.
///
/// # Safety
///
/// `inst` is null or storage a successful decode wrote, unchanged since;
/// `text` is null or writable for `capacity` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn binbun_x86_instruction_text(
    inst: *const X86Instruction,
    address: u64,
    options: u32,
    text: *mut c_char,
    capacity: usize,
) -> usize {
    // SAFETY: `text` is null or writable for `capacity` bytes (contract).
    let buffer = unsafe { ffi::out_slice(text.cast::<u8>(), capacity) };
    // SAFETY: the contract of `inst`.
    unsafe {
        read(inst, 0, |i| {
            if options != TEXT_DEFAULT {
                return 0;
            }
            let mut out = TextOut::new(buffer);
            match write!(out, "{}", i.intel(address)) {
                Ok(()) => out.finish(),
                Err(_) => 0,
            }
        })
    }
}

/// Writes the instruction at `address` as tokens: the text, as
/// [`binbun_x86_instruction_text`] writes it, into `text`, and each token
/// into `tokens`, as far as the capacities go. Returns how many tokens and
/// how much text there are; both 0 if `inst` holds no instruction or
/// `options` is not `BINBUN_TEXT_DEFAULT`.
///
/// # Safety
///
/// `inst` is null or storage a successful decode wrote, unchanged since;
/// `text` is null or writable for `text_capacity` bytes; `tokens` is null
/// or writable for `token_capacity` tokens.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn binbun_x86_instruction_tokens(
    inst: *const X86Instruction,
    address: u64,
    options: u32,
    text: *mut c_char,
    text_capacity: usize,
    tokens: *mut Token,
    token_capacity: usize,
) -> TextSize {
    // SAFETY: `text` is null or writable for `text_capacity` bytes
    // (contract).
    let text = unsafe { ffi::out_slice(text.cast::<u8>(), text_capacity) };
    // SAFETY: `tokens` is null or writable for `token_capacity` tokens
    // (contract).
    let tokens = unsafe { ffi::out_slice(tokens, token_capacity) };
    // SAFETY: the contract of `inst`.
    unsafe {
        read(inst, TextSize::default(), |i| {
            if options != TEXT_DEFAULT {
                return TextSize::default();
            }
            let mut out = TokenOut::new(TextOut::new(text), tokens);
            if tokens::write(i, address, &mut out).is_err() {
                return TextSize::default();
            }
            out.finish()
        })
    }
}

/// XED's name for a mnemonic (`REP_MOVSB`); empty for a value that is no
/// mnemonic.
#[unsafe(no_mangle)]
pub extern "C" fn binbun_x86_mnemonic_name(mnemonic: u16) -> Str {
    guard(Str::EMPTY, || {
        from_id(&Mnemonic::ALL, mnemonic).map_or(Str::EMPTY, |m| Str::new(m.as_str()))
    })
}

/// The mnemonic XED names `name` (exact, upper case), or 0.
///
/// # Safety
///
/// `name` is null or readable for `length` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn binbun_x86_mnemonic_from_name(name: *const c_char, length: usize) -> u16 {
    // SAFETY: passed on from the caller.
    let name = unsafe { utf8_name(name, length) };
    guard(0, || {
        name.and_then(|name| name.parse::<Mnemonic>().ok())
            .map_or(0, |m| id(m as usize))
    })
}

/// XED's name for a form (`ADD_GPRv_GPRv_01`); empty for a value that is
/// no form.
#[unsafe(no_mangle)]
pub extern "C" fn binbun_x86_form_name(form: u16) -> Str {
    guard(Str::EMPTY, || {
        from_id(&Form::ALL, form).map_or(Str::EMPTY, |f| Str::new(f.as_str()))
    })
}

/// The form XED names `name` (exact), or 0.
///
/// # Safety
///
/// `name` is null or readable for `length` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn binbun_x86_form_from_name(name: *const c_char, length: usize) -> u16 {
    // SAFETY: passed on from the caller.
    let name = unsafe { utf8_name(name, length) };
    guard(0, || {
        name.and_then(|name| name.parse::<Form>().ok())
            .map_or(0, |f| id(f as usize))
    })
}

/// A category's name (`BINARY`); empty for a value that is none.
#[unsafe(no_mangle)]
pub extern "C" fn binbun_x86_category_name(category: u16) -> Str {
    guard(Str::EMPTY, || {
        from_id(&Category::ALL, category).map_or(Str::EMPTY, |c| Str::new(c.as_str()))
    })
}

/// An extension's name (`BASE`, `AVX512EVEX`); empty for a value that is
/// none.
#[unsafe(no_mangle)]
pub extern "C" fn binbun_x86_extension_name(extension: u16) -> Str {
    guard(Str::EMPTY, || {
        from_id(&Extension::ALL, extension).map_or(Str::EMPTY, |e| Str::new(e.as_str()))
    })
}

/// A feature set's name (`I86`, `AVX2`); empty for a value that is none.
#[unsafe(no_mangle)]
pub extern "C" fn binbun_x86_isa_set_name(isa_set: u16) -> Str {
    guard(Str::EMPTY, || {
        from_id(&IsaSet::ALL, isa_set).map_or(Str::EMPTY, |s| Str::new(s.as_str()))
    })
}

/// A register's name as the text writes it (`rax`, `st(0)`); empty for a
/// value that is no register.
#[unsafe(no_mangle)]
pub extern "C" fn binbun_x86_register_name(register: u16) -> Str {
    guard(Str::EMPTY, || {
        Register::from_raw(register).map_or(Str::EMPTY, |r| Str::new(r.name()))
    })
}

/// The register the text writes as `name` (lower case), or 0.
///
/// # Safety
///
/// `name` is null or readable for `length` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn binbun_x86_register_from_name(name: *const c_char, length: usize) -> u16 {
    // SAFETY: passed on from the caller.
    let name = unsafe { utf8_name(name, length) };
    guard(0, || name.and_then(register_named).map_or(0, |r| r as u16))
}

/// The register written `name`.
fn register_named(name: &str) -> Option<Register> {
    Register::ALL.into_iter().find(|r| r.name() == name)
}

/// What `register` is, into `*out`; whether it is a register.
///
/// # Safety
///
/// `out` is null or writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn binbun_x86_register_describe(
    register: u16,
    out: *mut X86RegisterInfo,
) -> bool {
    let info = guard(None, || {
        Register::from_raw(register).map(|r| X86RegisterInfo {
            class: register_class(r.class()),
            reserved: 0,
            width: u16::try_from(r.width()).unwrap_or(0),
            full: r.full() as u16,
            full32: r.full32() as u16,
            offset: r.offset(),
        })
    });
    let Some(info) = info else {
        return false;
    };
    // SAFETY: `out` is null or writable (contract).
    unsafe { ffi::write(out, info) };
    !out.is_null()
}

/// `class` as a `binbun_x86_register_class`.
const fn register_class(class: RegisterClass) -> u8 {
    match class {
        RegisterClass::Bndcfg => 1,
        RegisterClass::Bndstat => 2,
        RegisterClass::Bound => 3,
        RegisterClass::Cr => 4,
        RegisterClass::Dr => 5,
        RegisterClass::Flags => 6,
        RegisterClass::Gpr => 7,
        RegisterClass::Ip => 8,
        RegisterClass::Mask => 9,
        RegisterClass::Mmx => 10,
        RegisterClass::Msr => 11,
        RegisterClass::Mxcsr => 12,
        RegisterClass::Pseudo => 13,
        RegisterClass::Pseudox87 => 14,
        RegisterClass::Sr => 15,
        RegisterClass::Tmp => 16,
        RegisterClass::Treg => 17,
        RegisterClass::Uif => 18,
        RegisterClass::X87 => 19,
        RegisterClass::Xcr => 20,
        RegisterClass::Xmm => 21,
        RegisterClass::Ymm => 22,
        RegisterClass::Zmm => 23,
    }
}
