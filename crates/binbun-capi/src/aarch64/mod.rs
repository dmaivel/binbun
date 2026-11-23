//! AArch64 (A64): the `binbun_aarch64_*` functions over
//! [`binbun_aarch64`].

mod operand;
mod tokens;

use std::ffi::c_char;
use std::fmt::Write as _;

use binbun_aarch64::operand::{MAX_OPERANDS as DECODER_MAX_OPERANDS, Register};
use binbun_aarch64::{
    CompareOperand, Condition, Encoding, Error, Instruction, LabelStyle, MemoryAccess, MemoryKind,
    decode, decode_bytes,
};
use binbun_isa::Instruction as _;

pub use operand::{
    A64Extend, A64Float, A64Immediate, A64IndexedRegister, A64Label, A64Memory, A64Named,
    A64Operand, A64OperandDetail, A64Register, A64RegisterList, A64Shift, A64SystemRegister, A64Za,
    A64ZaList, binbun_aarch64_instruction_operands,
};
pub use tokens::write as write_tokens;

pub(crate) use operand::{class_of, element_of, element_size, register_class};

use crate::ffi::{self, Stored};
use crate::text::{TextOut, TextSize, Token, TokenOut};
use crate::{
    Branch, Status, Str, TEXT_DEFAULT, TEXT_RELATIVE_LABELS, guard, name as utf8_name,
    read as read_storage, status,
};

/// Every instruction's length in bytes.
pub const LENGTH: usize = 4;
/// Most operands an instruction has (`BINBUN_AARCH64_MAX_OPERANDS`).
pub const MAX_OPERANDS: usize = 8;
/// The longest text, without its NUL (`BINBUN_AARCH64_MAX_TEXT`): 71 for
/// every word of this release (`aarch64_every_word_fits_the_bounds`), with
/// room for later ones.
pub const MAX_TEXT: usize = 96;
/// Most tokens an instruction's text has (`BINBUN_AARCH64_MAX_TOKENS`): 26
/// for every word of this release, with room for later ones.
pub const MAX_TOKENS: usize = 40;

const _: () = assert!(DECODER_MAX_OPERANDS == MAX_OPERANDS);

/// Tags storage that holds an AArch64 instruction.
pub(crate) const TAG: u64 = u64::from_le_bytes(*b"bbna64\x00\x01");

/// Storage for one decoded instruction, owned by the caller
/// (`binbun_aarch64_instruction`).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct A64Instruction {
    /// Contents only the library reads.
    pub opaque: [u64; 4],
}

// The layouts the header describes, on 64-bit targets.
#[cfg(target_pointer_width = "64")]
const _: () = assert!(size_of::<A64Instruction>() == 32 && align_of::<A64Instruction>() == 8);

/// A linear sweep over a buffer, owned by the caller
/// (`binbun_aarch64_decoder`).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct A64Decoder {
    /// The buffer.
    pub bytes: *const u8,
    /// Its length.
    pub length: usize,
    /// Offset of the next instruction in the buffer.
    pub offset: usize,
    /// Address of the buffer's first byte.
    pub address: u64,
}

#[cfg(target_pointer_width = "64")]
const _: () = assert!(size_of::<A64Decoder>() == 32 && align_of::<A64Decoder>() == 8);

/// The condition an instruction tests (`binbun_aarch64_condition`).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct A64Condition {
    /// A `binbun_aarch64_condition_kind`.
    pub kind: u8,
    /// Flags and compare: the condition, a `binbun_aarch64_cond`.
    pub cond: u8,
    /// Zero: whether the test passes when the register is zero (`cbz`);
    /// bit: whether it passes when the bit is set (`tbnz`).
    pub sense: bool,
    /// Bit: the bit's number.
    pub bit: u8,
    /// Compare: what `register` is compared with, a
    /// `binbun_aarch64_compare_kind`.
    pub right_kind: u8,
    /// Zero.
    pub reserved: [u8; 3],
    /// Zero, bit: the register tested; compare: the left register.
    pub register: A64Register,
    /// Compare: the right register.
    pub right_register: A64Register,
    /// Compare: the immediate compared with.
    pub right_immediate: i64,
}

const _: () = assert!(size_of::<A64Condition>() == 32);

impl From<Condition> for A64Condition {
    /// `condition` as C sees it.
    fn from(condition: Condition) -> Self {
        let mut out = Self::default();
        match condition {
            Condition::Flags(cond) => {
                out.kind = 1;
                out.cond = cond as u8;
            }
            Condition::Zero { register, zero } => {
                out.kind = 2;
                out.register = A64Register::new(register);
                out.sense = zero;
            }
            Condition::Bit { register, bit, set } => {
                out.kind = 3;
                out.register = A64Register::new(register);
                out.bit = bit;
                out.sense = set;
            }
            Condition::Compare { cond, left, right } => {
                out.kind = 4;
                out.cond = cond as u8;
                out.register = A64Register::new(left);
                match right {
                    CompareOperand::Register(register) => {
                        out.right_kind = 1;
                        out.right_register = A64Register::new(register);
                    }
                    CompareOperand::Immediate(value) => {
                        out.right_kind = 2;
                        out.right_immediate = value;
                    }
                }
            }
        }
        out
    }
}

/// What an instruction does to the condition flags
/// (`binbun_aarch64_flag_effect`).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct A64FlagEffect {
    /// Flags read, `BINBUN_AARCH64_FLAG_` bits (N = 8, Z = 4, C = 2, V = 1).
    pub read: u8,
    /// Flags written.
    pub written: u8,
    /// Zero.
    pub reserved: u16,
}

const _: () = assert!(size_of::<A64FlagEffect>() == 4);

impl A64FlagEffect {
    /// What `instruction` does to the condition flags.
    pub fn of(instruction: Instruction) -> Self {
        let flags = instruction.flags();
        Self {
            read: flags.read.bits(),
            written: flags.written.bits(),
            reserved: 0,
        }
    }
}

/// An instruction's memory access (`binbun_aarch64_memory_access`).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct A64MemoryAccess {
    /// A `binbun_aarch64_memory_kind`.
    pub kind: u8,
    /// Zero.
    pub reserved: [u8; 3],
    /// Bytes accessed in total, 0 where that is not fixed.
    pub size: u32,
}

const _: () = assert!(size_of::<A64MemoryAccess>() == 8);

impl From<MemoryAccess> for A64MemoryAccess {
    /// `access` as C sees it.
    fn from(access: MemoryAccess) -> Self {
        let kind = match access.kind {
            MemoryKind::Load => 1,
            MemoryKind::Store => 2,
            MemoryKind::Atomic => 3,
            MemoryKind::LoadExclusive => 4,
            MemoryKind::StoreExclusive => 5,
            MemoryKind::Prefetch => 6,
            MemoryKind::Copy => 7,
            MemoryKind::LoadTag => 8,
            MemoryKind::StoreTag => 9,
        };
        Self {
            kind,
            reserved: [0; 3],
            size: access.size,
        }
    }
}

/// The status of a decode that failed with `error`.
pub const fn failure(error: Error) -> Status {
    match error {
        Error::TooShort => Status::Truncated,
        Error::Unallocated => Status::Aarch64Unallocated,
        Error::Undefined => Status::Aarch64Undefined,
        Error::Unpredictable => Status::Aarch64Unpredictable,
    }
}

/// How many bytes of storage a decode writes, as the library was built:
/// no more than `sizeof(binbun_aarch64_instruction)`.
#[unsafe(no_mangle)]
pub extern "C" fn binbun_aarch64_instruction_size() -> usize {
    size_of::<Stored<Instruction>>()
}

/// Decodes the instruction word `word` into `out`, which is written only on
/// [`Status::Ok`].
///
/// # Safety
///
/// `out` is null or writable storage.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn binbun_aarch64_decode_word(word: u32, out: *mut A64Instruction) -> Status {
    status(|| {
        ffi::storage(out)?;
        let instruction = decode(word).map_err(failure)?;
        // SAFETY: `out` passed `storage` and is writable storage (contract).
        unsafe { ffi::store(out, TAG, instruction) };
        Ok(())
    })
}

/// Decodes the instruction at the start of the `len` bytes at `bytes`
/// (little-endian) into `out`, which is written only on [`Status::Ok`].
///
/// # Safety
///
/// `bytes` is null or readable for `len` bytes; `out` is null or writable
/// storage.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn binbun_aarch64_decode_bytes(
    bytes: *const u8,
    len: usize,
    out: *mut A64Instruction,
) -> Status {
    status(|| {
        // SAFETY: `bytes` is null or readable for `len` bytes (contract).
        let bytes = unsafe { ffi::bytes(bytes, len) }?;
        ffi::storage(out)?;
        let instruction = decode_bytes(bytes).map_err(failure)?;
        // SAFETY: `out` passed `storage` and is writable storage (contract).
        unsafe { ffi::store(out, TAG, instruction) };
        Ok(())
    })
}

/// Starts a sweep of the `length` bytes at `bytes`, which are at `address`.
///
/// # Safety
///
/// `decoder` is null or writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn binbun_aarch64_decoder_init(
    decoder: *mut A64Decoder,
    bytes: *const u8,
    length: usize,
    address: u64,
) -> Status {
    status(|| {
        if decoder.is_null() || (bytes.is_null() && length != 0) {
            return Err(Status::NullPointer);
        }
        let value = A64Decoder {
            bytes,
            length,
            offset: 0,
            address,
        };
        // SAFETY: `decoder` is writable (contract).
        unsafe { ffi::write(decoder, value) };
        Ok(())
    })
}

/// Decodes the next instruction of the sweep into `out` (written only on
/// [`Status::Ok`]) and its address into `*address` (if not null, whatever
/// the status but [`Status::End`]), then moves 4 bytes on.
///
/// # Safety
///
/// `decoder` is null or a decoder whose bytes are readable; `out` is null
/// or writable storage; `address` is null or writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn binbun_aarch64_decoder_next(
    decoder: *mut A64Decoder,
    out: *mut A64Instruction,
    address: *mut u64,
) -> Status {
    status(|| {
        // SAFETY: `decoder` is null or the caller's decoder (contract).
        let decoder = unsafe { ffi::borrow_mut(decoder) }.ok_or(Status::NullPointer)?;
        ffi::storage(out)?;
        // SAFETY: the decoder's bytes are readable (contract).
        let bytes = unsafe { ffi::bytes(decoder.bytes, decoder.length) }?;
        // As `binbun_aarch64::Decoder` sweeps, without its item to
        // copy.
        let offset = decoder.offset;
        let rest = bytes
            .get(offset..)
            .filter(|rest| !rest.is_empty())
            .ok_or(Status::End)?;
        // SAFETY: `address` is null or writable (contract).
        unsafe { ffi::write(address, decoder.address.wrapping_add(offset as u64)) };
        decoder.offset = offset.saturating_add(LENGTH);
        let instruction = decode_bytes(rest).map_err(failure)?;
        // SAFETY: `out` passed `storage` and is writable storage (contract).
        unsafe { ffi::store(out, TAG, instruction) };
        Ok(())
    })
}

/// `body` of the instruction in `inst`, or `failed` if `inst` holds none or
/// `body` panics.
///
/// # Safety
///
/// `inst` is null or storage a successful decode wrote, unchanged since.
unsafe fn read<T: Copy>(
    inst: *const A64Instruction,
    failed: T,
    body: impl FnOnce(Instruction) -> T,
) -> T {
    // SAFETY: passed on from the caller.
    unsafe { read_storage(inst, TAG, failed, |i: &Instruction| body(*i)) }
}

/// The instruction word; 0 if `inst` holds none.
///
/// # Safety
///
/// `inst` is null or storage a successful decode wrote, unchanged since.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn binbun_aarch64_instruction_word(inst: *const A64Instruction) -> u32 {
    // SAFETY: the contract of `inst`.
    unsafe { read(inst, 0, Instruction::word) }
}

/// The instruction's length in bytes, 4; 0 if `inst` holds none.
///
/// # Safety
///
/// `inst` is null or storage a successful decode wrote, unchanged since.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn binbun_aarch64_instruction_length(inst: *const A64Instruction) -> u8 {
    // SAFETY: the contract of `inst`.
    unsafe { read(inst, 0, |_| 4) }
}

/// The encoding the word is an instance of, a `binbun_aarch64_encoding`; 0
/// if `inst` holds none.
///
/// # Safety
///
/// `inst` is null or storage a successful decode wrote, unchanged since.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn binbun_aarch64_instruction_encoding(inst: *const A64Instruction) -> u16 {
    // SAFETY: the contract of `inst`.
    unsafe { read(inst, 0, |i| encoding_id(i.encoding())) }
}

/// The id of `encoding`: its number plus one.
fn encoding_id(encoding: Encoding) -> u16 {
    u16::try_from(encoding as usize + 1).unwrap_or(0)
}

/// The mnemonic as the text writes it, after alias selection (`mov` for
/// `orr x0, xzr, x1`, `b.eq`); empty if `inst` holds none.
///
/// # Safety
///
/// `inst` is null or storage a successful decode wrote, unchanged since.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn binbun_aarch64_instruction_mnemonic(inst: *const A64Instruction) -> Str {
    // SAFETY: the contract of `inst`.
    unsafe { read(inst, Str::EMPTY, |i| Str::new(i.mnemonic())) }
}

/// What the instruction at `address` does to the flow of control.
///
/// # Safety
///
/// `inst` is null or storage a successful decode wrote, unchanged since.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn binbun_aarch64_instruction_branch(
    inst: *const A64Instruction,
    address: u64,
) -> Branch {
    // SAFETY: the contract of `inst`.
    unsafe { read(inst, Branch::NONE, |i| Branch::new(i.flow(address))) }
}

/// The address an `adr` at `address` computes, into `*out`; whether it
/// computes one.
///
/// # Safety
///
/// `inst` is null or storage a successful decode wrote, unchanged since;
/// `out` is null or writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn binbun_aarch64_instruction_computed_address(
    inst: *const A64Instruction,
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

/// The condition the instruction tests, into `*out`; whether it tests
/// one.
///
/// # Safety
///
/// `inst` is null or storage a successful decode wrote, unchanged since;
/// `out` is null or writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn binbun_aarch64_instruction_condition(
    inst: *const A64Instruction,
    out: *mut A64Condition,
) -> bool {
    // SAFETY: the contract of `inst`.
    let condition = unsafe { read(inst, None, |i| i.condition().map(A64Condition::from)) };
    let Some(condition) = condition else {
        return false;
    };
    // SAFETY: `out` is null or writable (contract).
    unsafe { ffi::write(out, condition) };
    !out.is_null()
}

/// What the instruction does to the condition flags; zero if `inst` holds
/// none.
///
/// # Safety
///
/// `inst` is null or storage a successful decode wrote, unchanged since.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn binbun_aarch64_instruction_flags(
    inst: *const A64Instruction,
) -> A64FlagEffect {
    // SAFETY: the contract of `inst`.
    unsafe { read(inst, A64FlagEffect::default(), A64FlagEffect::of) }
}

/// The instruction's memory access through an operand, into `*out`;
/// whether it makes one.
///
/// # Safety
///
/// `inst` is null or storage a successful decode wrote, unchanged since;
/// `out` is null or writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn binbun_aarch64_instruction_memory(
    inst: *const A64Instruction,
    out: *mut A64MemoryAccess,
) -> bool {
    // SAFETY: the contract of `inst`.
    let access = unsafe { read(inst, None, Instruction::memory) };
    let Some(access) = access else {
        return false;
    };
    // SAFETY: `out` is null or writable (contract).
    unsafe { ffi::write(out, A64MemoryAccess::from(access)) };
    !out.is_null()
}

/// Writes the registers in `registers` into `out`, up to `capacity`;
/// returns how many there are.
///
/// # Safety
///
/// `out` is null or writable for `capacity` registers.
unsafe fn registers(registers: &[Register], out: *mut A64Register, capacity: usize) -> usize {
    // SAFETY: passed on from the caller.
    let out = unsafe { ffi::out_slice(out, capacity) };
    for (slot, &register) in out.iter_mut().zip(registers) {
        slot.write(A64Register::new(register));
    }
    registers.len()
}

/// Writes the registers the instruction reads without naming them (x30 of
/// `ret`, x16 and x17 of `pacia1716`, FFR) into `out`, up to `capacity`;
/// returns how many there are, 0 if `inst` holds none.
///
/// # Safety
///
/// `inst` is null or storage a successful decode wrote, unchanged since;
/// `out` is null or writable for `capacity` registers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn binbun_aarch64_instruction_implicit_reads(
    inst: *const A64Instruction,
    out: *mut A64Register,
    capacity: usize,
) -> usize {
    // SAFETY: the contract of `inst`.
    let implicit = unsafe { read(inst, None, |i| Some(i.implicit())) };
    // SAFETY: the contract of `out`.
    implicit.map_or(0, |implicit| unsafe {
        registers(implicit.reads, out, capacity)
    })
}

/// Writes the registers the instruction writes without naming them (x30 of
/// `bl`, FFR) into `out`, up to `capacity`; returns how many there are, 0
/// if `inst` holds none.
///
/// # Safety
///
/// `inst` is null or storage a successful decode wrote, unchanged since;
/// `out` is null or writable for `capacity` registers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn binbun_aarch64_instruction_implicit_writes(
    inst: *const A64Instruction,
    out: *mut A64Register,
    capacity: usize,
) -> usize {
    // SAFETY: the contract of `inst`.
    let implicit = unsafe { read(inst, None, |i| Some(i.implicit())) };
    // SAFETY: the contract of `out`.
    implicit.map_or(0, |implicit| unsafe {
        registers(implicit.writes, out, capacity)
    })
}

/// The label style `options` asks for, `None` for unknown options.
pub const fn style(options: u32) -> Option<LabelStyle> {
    match options {
        TEXT_DEFAULT => Some(LabelStyle::Absolute),
        TEXT_RELATIVE_LABELS => Some(LabelStyle::Relative),
        _ => None,
    }
}

/// Writes the instruction at `address` as text (as LLVM writes it: the
/// mnemonic, a tab, the operands; labels as the addresses they name, or as
/// offsets with `BINBUN_TEXT_RELATIVE_LABELS`) into `text`, NUL-terminated
/// when `capacity` allows. Returns the length of the whole text without
/// the NUL (more than `capacity - 1` when it was cut short), or 0 if `inst`
/// holds no instruction or `options` has an unknown bit.
///
/// # Safety
///
/// `inst` is null or storage a successful decode wrote, unchanged since;
/// `text` is null or writable for `capacity` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn binbun_aarch64_instruction_text(
    inst: *const A64Instruction,
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
            let Some(style) = style(options) else {
                return 0;
            };
            let mut out = TextOut::new(buffer);
            match write!(out, "{}", i.display_with(address, style)) {
                Ok(()) => out.finish(),
                Err(_) => 0,
            }
        })
    }
}

/// Writes the instruction at `address` as tokens: the text, as
/// [`binbun_aarch64_instruction_text`] writes it, into `text`, and each
/// token into `tokens`, as far as the capacities go. Returns how many
/// tokens and how much text there are; both 0 if `inst` holds no
/// instruction or `options` has an unknown bit.
///
/// # Safety
///
/// `inst` is null or storage a successful decode wrote, unchanged since;
/// `text` is null or writable for `text_capacity` bytes; `tokens` is null
/// or writable for `token_capacity` tokens.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn binbun_aarch64_instruction_tokens(
    inst: *const A64Instruction,
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
            let Some(style) = style(options) else {
                return TextSize::default();
            };
            let mut out = TokenOut::new(TextOut::new(text), tokens);
            if tokens::write(i, address, style, &mut out).is_err() {
                return TextSize::default();
            }
            out.finish()
        })
    }
}

/// An encoding's name, as Arm's specification and `disasm_generated.h`
/// spell it (`ADD_64_addsub_shift`); empty for a value that is no encoding.
#[unsafe(no_mangle)]
pub extern "C" fn binbun_aarch64_encoding_name(encoding: u16) -> Str {
    guard(Str::EMPTY, || {
        encoding_of(encoding).map_or(Str::EMPTY, |e| Str::new(e.name()))
    })
}

/// The mnemonic of an encoding's own syntax, upper case (`ADD`); empty for
/// a value that is no encoding.
#[unsafe(no_mangle)]
pub extern "C" fn binbun_aarch64_encoding_mnemonic(encoding: u16) -> Str {
    guard(Str::EMPTY, || {
        encoding_of(encoding).map_or(Str::EMPTY, |e| Str::new(e.mnemonic()))
    })
}

/// The encoding with id `id`.
fn encoding_of(id: u16) -> Option<Encoding> {
    Encoding::ALL.get(usize::from(id).checked_sub(1)?).copied()
}

/// The encoding named `name` (exact), or 0.
///
/// # Safety
///
/// `name` is null or readable for `length` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn binbun_aarch64_encoding_from_name(
    name: *const c_char,
    length: usize,
) -> u16 {
    // SAFETY: passed on from the caller.
    let name = unsafe { utf8_name(name, length) };
    guard(0, || {
        name.and_then(|name| name.parse::<Encoding>().ok())
            .map_or(0, encoding_id)
    })
}
