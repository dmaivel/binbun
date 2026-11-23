//! One decoder for both architectures: `binbun_decode`, `binbun_decoder_*`,
//! `binbun_instruction_*` and `binbun_register_name`, over
//! [`binbun_disasm`], the architecture chosen by the caller.
//!
//! An instruction's storage (`binbun_instruction`) holds its address, its
//! bytes and the native instruction, itself in the storage of its own
//! architecture: `binbun_instruction_as_x86` and
//! `binbun_instruction_as_aarch64` point at it, so that every `binbun_x86_*`
//! or `binbun_aarch64_*` function reads it as it is. What both
//! architectures share is what [`binbun_disasm::Insn`] says of it.

use std::ffi::c_char;
use std::fmt::Write as _;

#[cfg(feature = "aarch64")]
use binbun_aarch64::operand::SystemRegister;
#[cfg(feature = "aarch64")]
use binbun_disasm::AArch64Register;
use binbun_disasm::{Arch, Insn, Registers};

#[cfg(feature = "aarch64")]
use crate::aarch64::{self, A64Instruction};
use crate::ffi::{self, Stored};
use crate::text::TextOut;
#[cfg(feature = "x86")]
use crate::x86::{self, X86Instruction};
use crate::{Branch, Status, Str, TEXT_DEFAULT, guard, status};

/// The longest instruction, in bytes (`BINBUN_MAX_LENGTH`): x86's.
pub const MAX_LENGTH: usize = 15;
/// The longest text, without its NUL (`BINBUN_MAX_TEXT`): x86's, the
/// longer.
pub const MAX_TEXT: usize = 160;
/// Most registers an instruction reads, or writes
/// (`BINBUN_MAX_REGISTERS`).
pub const MAX_REGISTERS: usize = 72;
/// The longest register name, without its NUL
/// (`BINBUN_MAX_REGISTER_NAME`): 23 in this release
/// (`ICH_PPI_PRIORITYR15_EL2`), with room for later ones.
pub const MAX_REGISTER_NAME: usize = 32;

const _: () = assert!(Registers::CAPACITY <= MAX_REGISTERS);
#[cfg(feature = "x86")]
const _: () = assert!(x86::MAX_LENGTH <= MAX_LENGTH && x86::MAX_TEXT <= MAX_TEXT);
#[cfg(feature = "aarch64")]
const _: () = assert!(aarch64::LENGTH <= MAX_LENGTH && aarch64::MAX_TEXT <= MAX_TEXT);

/// x86, in a mode (`BINBUN_ARCH_X86`).
pub const ARCH_X86: u32 = 1;
/// AArch64 (`BINBUN_ARCH_AARCH64`).
pub const ARCH_AARCH64: u32 = 2;

/// Tags storage that holds an x86 instruction, decoded through
/// `binbun_decode`.
#[cfg(feature = "x86")]
const X86_TAG: u64 = u64::from_le_bytes(*b"bbnax86\x01");
/// Tags storage that holds an AArch64 instruction, decoded through
/// `binbun_decode`.
#[cfg(feature = "aarch64")]
const AARCH64_TAG: u64 = u64::from_le_bytes(*b"bbnaa64\x01");

/// Storage for one decoded instruction of either architecture, owned by
/// the caller (`binbun_instruction`).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Instruction {
    /// Contents only the library reads.
    pub opaque: [u64; 32],
}

// The layouts the header describes, on 64-bit targets.
#[cfg(target_pointer_width = "64")]
const _: () = assert!(size_of::<Instruction>() == 256 && align_of::<Instruction>() == 8);

/// A linear sweep over a buffer, owned by the caller (`binbun_decoder`).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Decoder {
    /// The buffer.
    pub bytes: *const u8,
    /// Its length.
    pub length: usize,
    /// Offset in `bytes` of the next instruction.
    pub offset: usize,
    /// Address of `bytes[0]`.
    pub address: u64,
    /// A `binbun_arch`.
    pub arch: u32,
    /// x86: a `binbun_x86_mode`; AArch64: 0.
    pub mode: u32,
}

#[cfg(target_pointer_width = "64")]
const _: () = assert!(size_of::<Decoder>() == 40 && align_of::<Decoder>() == 8);

/// `binbun_register_kind`: an x86 register, `value`.
pub const REGISTER_X86: u8 = 1;
/// `binbun_register_kind`: an AArch64 register by `class` and `number`.
pub const REGISTER_AARCH64: u8 = 2;
/// `binbun_register_kind`: the SME array, or tile `number` where
/// `has_tile`, of `element`.
pub const REGISTER_AARCH64_ZA: u8 = 3;
/// `binbun_register_kind`: an AArch64 system register, encoding `value`,
/// named `name` where `has_name`.
pub const REGISTER_AARCH64_SYSTEM: u8 = 4;

/// A register an instruction reads or writes (`binbun_register`), as
/// [`binbun_disasm::Register`]: its fields are those its kind names, the
/// others 0. C's `bool` fields are `u8` here, so that a struct the caller
/// wrote is read soundly whatever they hold.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Register {
    /// A `binbun_register_kind`.
    pub kind: u8,
    /// AArch64: the class, a `binbun_aarch64_register_class`.
    pub class: u8,
    /// AArch64: the number; ZA: the tile, where `has_tile`.
    pub number: u8,
    /// ZA: the tile's element size, a `binbun_aarch64_element`, 0 for none.
    pub element: u8,
    /// ZA: whether a tile, not the whole array (a C `bool`).
    pub has_tile: u8,
    /// System: whether it has a name for the access (a C `bool`).
    pub has_name: u8,
    /// x86: the register, a `binbun_x86_register`; system:
    /// `op0:op1:CRn:CRm:op2`, `op0` in bits 15:14.
    pub value: u16,
    /// System: its name for the access as LLVM writes it (`TPIDR_EL0`),
    /// empty where it has none.
    pub name: Str,
}

#[cfg(target_pointer_width = "64")]
const _: () = assert!(size_of::<Register>() == 24 && align_of::<Register>() == 8);

impl Register {
    /// No register, every field 0.
    const NONE: Self = Self {
        kind: 0,
        class: 0,
        number: 0,
        element: 0,
        has_tile: 0,
        has_name: 0,
        value: 0,
        name: Str::EMPTY,
    };

    /// `register` as C sees it.
    pub fn new(register: binbun_disasm::Register) -> Self {
        match register {
            #[cfg(feature = "x86")]
            binbun_disasm::Register::X86(register) => Self {
                kind: REGISTER_X86,
                value: register as u16,
                ..Self::NONE
            },
            #[cfg(feature = "aarch64")]
            binbun_disasm::Register::AArch64(register) => Self::aarch64(register),
        }
    }

    /// The AArch64 `register` as C sees it.
    #[cfg(feature = "aarch64")]
    fn aarch64(register: AArch64Register) -> Self {
        match register {
            AArch64Register::Register { class, number } => Self {
                kind: REGISTER_AARCH64,
                class: aarch64::register_class(class),
                number,
                ..Self::NONE
            },
            AArch64Register::Za { tile, element } => Self {
                kind: REGISTER_AARCH64_ZA,
                number: tile.unwrap_or(0),
                has_tile: u8::from(tile.is_some()),
                element: element.map_or(0, aarch64::element_size),
                ..Self::NONE
            },
            AArch64Register::System(system) => Self {
                kind: REGISTER_AARCH64_SYSTEM,
                value: system.encoding,
                has_name: u8::from(system.name.is_some()),
                name: system.name.map_or(Str::EMPTY, Str::new),
                ..Self::NONE
            },
        }
    }

    /// The register the fields name, but a system register's name (which
    /// C holds as a string of its own); `None` if they name none.
    fn native(&self) -> Option<binbun_disasm::Register> {
        match self.kind {
            #[cfg(feature = "x86")]
            REGISTER_X86 => {
                binbun_x86::Register::from_raw(self.value).map(binbun_disasm::Register::X86)
            }
            #[cfg(feature = "aarch64")]
            REGISTER_AARCH64 | REGISTER_AARCH64_ZA | REGISTER_AARCH64_SYSTEM => {
                self.aarch64_native().map(binbun_disasm::Register::AArch64)
            }
            _ => None,
        }
    }

    /// [`Register::native`] of an AArch64 kind.
    #[cfg(feature = "aarch64")]
    fn aarch64_native(&self) -> Option<AArch64Register> {
        Some(match self.kind {
            REGISTER_AARCH64 => AArch64Register::Register {
                class: aarch64::class_of(self.class)?,
                number: self.number,
            },
            REGISTER_AARCH64_ZA => AArch64Register::Za {
                tile: (self.has_tile != 0).then_some(self.number),
                element: match self.element {
                    0 => None,
                    element => Some(aarch64::element_of(element)?),
                },
            },
            REGISTER_AARCH64_SYSTEM => AArch64Register::System(SystemRegister {
                encoding: self.value,
                name: None,
            }),
            _ => return None,
        })
    }
}

/// What a decode through `binbun_decode` writes, after the tag (which says
/// the architecture): the instruction's address, x86 mode (a
/// `binbun_x86_mode`, 0 on AArch64) and bytes, and the native instruction
/// in `native`, storage of its architecture.
#[repr(C)]
#[derive(Debug)]
struct Held<S> {
    address: u64,
    mode: u32,
    length: u8,
    bytes: [u8; MAX_LENGTH],
    native: S,
}

impl<S> Held<S> {
    /// The instruction's bytes.
    fn bytes(&self) -> &[u8] {
        self.bytes
            .get(..usize::from(self.length))
            .unwrap_or_default()
    }
}

/// An instruction in storage, as read.
enum View<'a> {
    #[cfg(feature = "x86")]
    X86(&'a Held<X86Instruction>, &'a binbun_x86::Instruction),
    #[cfg(feature = "aarch64")]
    AArch64(&'a Held<A64Instruction>, &'a binbun_aarch64::Instruction),
}

impl View<'_> {
    const fn address(&self) -> u64 {
        match self {
            #[cfg(feature = "x86")]
            Self::X86(held, _) => held.address,
            #[cfg(feature = "aarch64")]
            Self::AArch64(held, _) => held.address,
        }
    }

    /// The architecture and x86 mode, as C numbers them.
    const fn numbers(&self) -> (u32, u32) {
        match self {
            #[cfg(feature = "x86")]
            Self::X86(held, _) => (ARCH_X86, held.mode),
            #[cfg(feature = "aarch64")]
            Self::AArch64(..) => (ARCH_AARCH64, 0),
        }
    }

    fn bytes(&self) -> &[u8] {
        match self {
            #[cfg(feature = "x86")]
            Self::X86(held, _) => held.bytes(),
            #[cfg(feature = "aarch64")]
            Self::AArch64(held, _) => held.bytes(),
        }
    }

    /// The instruction as [`binbun_disasm`] has it.
    fn insn(&self) -> Insn<'_> {
        match *self {
            #[cfg(feature = "x86")]
            Self::X86(held, native) => {
                // A decode checked the mode.
                let mode = x86::decode_mode(held.mode).unwrap_or(binbun_x86::Mode::Bits64);
                Insn::from_x86(native.clone(), mode, held.bytes(), held.address)
            }
            #[cfg(feature = "aarch64")]
            Self::AArch64(held, &native) => Insn::from_aarch64(native, held.bytes(), held.address),
        }
    }
}

/// The instruction in the storage at `inst`; `None` if it holds none.
///
/// # Safety
///
/// `inst` is null or storage a successful decode wrote, unchanged since.
unsafe fn view<'a>(inst: *const Instruction) -> Option<View<'a>> {
    #[cfg(feature = "x86")]
    // SAFETY: passed on from the caller.
    if let Some(held) = unsafe { ffi::load::<_, Held<X86Instruction>>(inst, X86_TAG) } {
        // SAFETY: the decode wrote an x86 instruction into `native`.
        let native = unsafe { ffi::load(&raw const held.native, x86::TAG) }?;
        return Some(View::X86(held, native));
    }
    #[cfg(feature = "aarch64")]
    // SAFETY: passed on from the caller.
    if let Some(held) = unsafe { ffi::load::<_, Held<A64Instruction>>(inst, AARCH64_TAG) } {
        // SAFETY: the decode wrote an AArch64 instruction into `native`.
        let native = unsafe { ffi::load(&raw const held.native, aarch64::TAG) }?;
        return Some(View::AArch64(held, native));
    }
    None
}

/// `body` of the instruction in `inst`, or `failed` if it holds none or
/// `body` panics.
///
/// # Safety
///
/// `inst` is null or storage a successful decode wrote, unchanged since.
unsafe fn read<'a, T>(inst: *const Instruction, failed: T, body: impl FnOnce(&View<'a>) -> T) -> T {
    // SAFETY: passed on from the caller.
    match unsafe { view(inst) } {
        Some(view) => guard(failed, || body(&view)),
        None => failed,
    }
}

/// The architecture `arch` and `mode` name.
///
/// # Errors
///
/// [`Status::BadArgument`] for an unknown architecture or x86 mode, a mode
/// other than 0 for AArch64, or an architecture the library was built
/// without.
const fn arch_of(arch: u32, mode: u32) -> Result<Arch, Status> {
    match (arch, mode) {
        #[cfg(feature = "x86")]
        (ARCH_X86, mode) => match x86::decode_mode(mode) {
            Ok(mode) => Ok(Arch::X86(mode)),
            Err(status) => Err(status),
        },
        #[cfg(feature = "aarch64")]
        (ARCH_AARCH64, 0) => Ok(Arch::AArch64),
        _ => Err(Status::BadArgument),
    }
}

/// `bytes` (no more than [`MAX_LENGTH`]) as [`Held`] keeps them.
fn kept(bytes: &[u8]) -> ([u8; MAX_LENGTH], u8) {
    let mut kept = [0; MAX_LENGTH];
    let length = bytes.len().min(MAX_LENGTH);
    if let (Some(to), Some(from)) = (kept.get_mut(..length), bytes.get(..length)) {
        to.copy_from_slice(from);
    }
    (kept, u8::try_from(length).unwrap_or(0))
}

/// Decodes the instruction at the start of `bytes`, which is at `address`,
/// for `arch` (x86 in C's `mode`) into `out`, as [`binbun_disasm::decode`]
/// does (the native decoder, its instruction stored once); its length.
///
/// # Safety
///
/// `out` passed [`ffi::storage`] and is writable storage.
unsafe fn decode_into(
    arch: Arch,
    mode: u32,
    bytes: &[u8],
    address: u64,
    out: *mut Instruction,
) -> Result<usize, Status> {
    match arch {
        #[cfg(feature = "x86")]
        Arch::X86(x86_mode) => {
            let instruction = binbun_x86::decode(bytes, x86_mode).map_err(x86::failure)?;
            let length = instruction.len();
            let (bytes, kept_length) = kept(bytes.get(..length).unwrap_or(bytes));
            let mut native = X86Instruction { opaque: [0; 24] };
            // SAFETY: `native` is aligned, writable x86 storage.
            unsafe { ffi::store(&raw mut native, x86::TAG, instruction) };
            let held = Held {
                address,
                mode,
                length: kept_length,
                bytes,
                native,
            };
            // SAFETY: `out` is writable storage (caller).
            unsafe { ffi::store(out, X86_TAG, held) };
            Ok(length)
        }
        #[cfg(feature = "aarch64")]
        Arch::AArch64 => {
            let instruction = binbun_aarch64::decode_bytes(bytes).map_err(aarch64::failure)?;
            let (bytes, length) = kept(bytes.get(..aarch64::LENGTH).unwrap_or(bytes));
            let mut native = A64Instruction { opaque: [0; 4] };
            // SAFETY: `native` is aligned, writable AArch64 storage.
            unsafe { ffi::store(&raw mut native, aarch64::TAG, instruction) };
            // `mode` is 0, as `arch_of` checked.
            let held = Held {
                address,
                mode,
                length,
                bytes,
                native,
            };
            // SAFETY: `out` is writable storage (caller).
            unsafe { ffi::store(out, AARCH64_TAG, held) };
            Ok(aarch64::LENGTH)
        }
    }
}

/// How many bytes of storage a decode writes, as the library was built:
/// no more than `sizeof(binbun_instruction)`.
#[unsafe(no_mangle)]
pub extern "C" fn binbun_instruction_size() -> usize {
    let size = 0;
    #[cfg(feature = "x86")]
    let size = size.max(size_of::<Stored<Held<X86Instruction>>>());
    #[cfg(feature = "aarch64")]
    let size = size.max(size_of::<Stored<Held<A64Instruction>>>());
    size
}

/// Decodes the instruction at the start of the `len` bytes at `bytes`,
/// which is at `address`, for architecture `arch` (x86 in `mode`, AArch64
/// with mode 0) into `out`, which is written only on [`Status::Ok`].
///
/// # Safety
///
/// `bytes` is null or readable for `len` bytes; `out` is null or writable
/// storage.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn binbun_decode(
    arch: u32,
    mode: u32,
    bytes: *const u8,
    len: usize,
    address: u64,
    out: *mut Instruction,
) -> Status {
    status(|| {
        // SAFETY: `bytes` is null or readable for `len` bytes (contract).
        let bytes = unsafe { ffi::bytes(bytes, len) }?;
        ffi::storage(out)?;
        let arch = arch_of(arch, mode)?;
        // SAFETY: `out` passed `storage` and is writable storage (contract).
        unsafe { decode_into(arch, mode, bytes, address, out) }.map(|_| ())
    })
}

/// Starts a sweep of the `length` bytes at `bytes`, which are at
/// `address`, for `arch` (x86 in `mode`, AArch64 with mode 0).
///
/// # Safety
///
/// `decoder` is null or writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn binbun_decoder_init(
    decoder: *mut Decoder,
    arch: u32,
    mode: u32,
    bytes: *const u8,
    length: usize,
    address: u64,
) -> Status {
    status(|| {
        if decoder.is_null() || (bytes.is_null() && length != 0) {
            return Err(Status::NullPointer);
        }
        arch_of(arch, mode)?;
        let value = Decoder {
            bytes,
            length,
            offset: 0,
            address,
            arch,
            mode,
        };
        // SAFETY: `decoder` is writable (contract).
        unsafe { ffi::write(decoder, value) };
        Ok(())
    })
}

/// Decodes the next instruction of the sweep into `out` (written only on
/// [`Status::Ok`]) and its address into `*address` (if not null, whatever
/// the status but [`Status::End`]), then moves past it, or after bytes that
/// are no instruction as [`binbun_disasm::Decoder`] does: one byte on x86,
/// four on AArch64.
///
/// # Safety
///
/// `decoder` is null or a decoder whose bytes are readable; `out` is null
/// or writable storage; `address` is null or writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn binbun_decoder_next(
    decoder: *mut Decoder,
    out: *mut Instruction,
    address: *mut u64,
) -> Status {
    status(|| {
        // SAFETY: `decoder` is null or the caller's decoder (contract).
        let decoder = unsafe { ffi::borrow_mut(decoder) }.ok_or(Status::NullPointer)?;
        ffi::storage(out)?;
        let arch = arch_of(decoder.arch, decoder.mode)?;
        // SAFETY: the decoder's bytes are readable (contract).
        let bytes = unsafe { ffi::bytes(decoder.bytes, decoder.length) }?;
        let offset = decoder.offset;
        let rest = bytes
            .get(offset..)
            .filter(|rest| !rest.is_empty())
            .ok_or(Status::End)?;
        let at = decoder.address.wrapping_add(offset as u64);
        // SAFETY: `address` is null or writable (contract).
        unsafe { ffi::write(address, at) };
        // SAFETY: `out` passed `storage` and is writable storage (contract).
        let result = unsafe { decode_into(arch, decoder.mode, rest, at, out) };
        let step = *result.as_ref().unwrap_or(&arch.invalid_step());
        decoder.offset = offset.saturating_add(step);
        result.map(|_| ())
    })
}

/// The instruction's architecture, a `binbun_arch`; 0 if `inst` holds
/// none.
///
/// # Safety
///
/// `inst` is null or storage a successful decode wrote, unchanged since.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn binbun_instruction_arch(inst: *const Instruction) -> u32 {
    // SAFETY: the contract of `inst`.
    unsafe { read(inst, 0, |view| view.numbers().0) }
}

/// The x86 mode it was decoded in, a `binbun_x86_mode`; 0 on AArch64 or if
/// `inst` holds none.
///
/// # Safety
///
/// `inst` is null or storage a successful decode wrote, unchanged since.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn binbun_instruction_mode(inst: *const Instruction) -> u32 {
    // SAFETY: the contract of `inst`.
    unsafe { read(inst, 0, |view| view.numbers().1) }
}

/// The instruction's address; 0 if `inst` holds none.
///
/// # Safety
///
/// `inst` is null or storage a successful decode wrote, unchanged since.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn binbun_instruction_address(inst: *const Instruction) -> u64 {
    // SAFETY: the contract of `inst`.
    unsafe { read(inst, 0, View::address) }
}

/// The instruction's length in bytes; 0 if `inst` holds none.
///
/// # Safety
///
/// `inst` is null or storage a successful decode wrote, unchanged since.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn binbun_instruction_length(inst: *const Instruction) -> u8 {
    // SAFETY: the contract of `inst`.
    unsafe {
        read(inst, 0, |view| {
            u8::try_from(view.bytes().len()).unwrap_or(0)
        })
    }
}

/// The instruction's bytes, in its storage (`binbun_instruction_length` of
/// them); null if `inst` holds none.
///
/// # Safety
///
/// `inst` is null or storage a successful decode wrote, unchanged since.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn binbun_instruction_bytes(inst: *const Instruction) -> *const u8 {
    // SAFETY: the contract of `inst`.
    unsafe { read(inst, std::ptr::null(), |view| view.bytes().as_ptr()) }
}

/// The mnemonic the text writes, lower case ([`Insn::mnemonic`]); empty if
/// `inst` holds none.
///
/// # Safety
///
/// `inst` is null or storage a successful decode wrote, unchanged since.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn binbun_instruction_mnemonic(inst: *const Instruction) -> Str {
    // SAFETY: the contract of `inst`.
    unsafe { read(inst, Str::EMPTY, |view| Str::new(view.insn().mnemonic())) }
}

/// What the instruction does to the flow of control at its address.
///
/// # Safety
///
/// `inst` is null or storage a successful decode wrote, unchanged since.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn binbun_instruction_branch(inst: *const Instruction) -> Branch {
    // SAFETY: the contract of `inst`.
    unsafe { read(inst, Branch::NONE, |view| Branch::new(view.insn().flow())) }
}

/// Writes the instruction as text at its address, as the native decoder
/// writes it, into `text`, NUL-terminated when `capacity` allows. Returns
/// the length of the whole text without the NUL, or 0 if `inst` holds none
/// or the options are unknown to its architecture (x86 has none).
///
/// # Safety
///
/// `inst` is null or storage a successful decode wrote, unchanged since;
/// `text` is null or writable for `capacity` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn binbun_instruction_text(
    inst: *const Instruction,
    options: u32,
    text: *mut c_char,
    capacity: usize,
) -> usize {
    // SAFETY: `text` is null or writable for `capacity` bytes (contract).
    let buffer = unsafe { ffi::out_slice(text.cast::<u8>(), capacity) };
    // SAFETY: the contract of `inst`.
    unsafe {
        read(inst, 0, |view| {
            let mut out = TextOut::new(buffer);
            let written = if options == TEXT_DEFAULT {
                write!(out, "{}", view.insn())
            } else {
                match *view {
                    #[cfg(feature = "x86")]
                    View::X86(..) => return 0,
                    #[cfg(feature = "aarch64")]
                    View::AArch64(held, native) => match aarch64::style(options) {
                        Some(style) => write!(out, "{}", native.display_with(held.address, style)),
                        None => return 0,
                    },
                }
            };
            written.map_or(0, |()| out.finish())
        })
    }
}

/// Writes `registers` into `out`, up to `capacity`; how many there are.
///
/// # Safety
///
/// `out` is null or writable for `capacity` registers.
unsafe fn write_registers(registers: &Registers, out: *mut Register, capacity: usize) -> usize {
    // SAFETY: passed on from the caller.
    let out = unsafe { ffi::out_slice(out, capacity) };
    for (slot, &register) in out.iter_mut().zip(registers) {
        slot.write(Register::new(register));
    }
    registers.len()
}

/// Writes the registers the instruction may read
/// ([`Insn::registers_read`]) into `out`, up to `capacity`; returns how
/// many there are, 0 if `inst` holds none.
///
/// # Safety
///
/// `inst` is null or storage a successful decode wrote, unchanged since;
/// `out` is null or writable for `capacity` registers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn binbun_instruction_registers_read(
    inst: *const Instruction,
    out: *mut Register,
    capacity: usize,
) -> usize {
    // SAFETY: the contract of `inst`.
    let registers = unsafe { read(inst, None, |view| Some(view.insn().registers_read())) };
    // SAFETY: the contract of `out`.
    registers.map_or(0, |registers| unsafe {
        write_registers(&registers, out, capacity)
    })
}

/// Writes the registers the instruction may write
/// ([`Insn::registers_written`]) into `out`, up to `capacity`; returns how
/// many there are, 0 if `inst` holds none.
///
/// # Safety
///
/// `inst` is null or storage a successful decode wrote, unchanged since;
/// `out` is null or writable for `capacity` registers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn binbun_instruction_registers_written(
    inst: *const Instruction,
    out: *mut Register,
    capacity: usize,
) -> usize {
    // SAFETY: the contract of `inst`.
    let registers = unsafe { read(inst, None, |view| Some(view.insn().registers_written())) };
    // SAFETY: the contract of `out`.
    registers.map_or(0, |registers| unsafe {
        write_registers(&registers, out, capacity)
    })
}

/// The x86 instruction in the storage (`binbun_x86_instruction`, which the
/// `binbun_x86_*` functions read); null if it holds an AArch64 one or none.
///
/// # Safety
///
/// `inst` is null or storage a successful decode wrote, unchanged since.
#[cfg(feature = "x86")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn binbun_instruction_as_x86(
    inst: *const Instruction,
) -> *const X86Instruction {
    // SAFETY: the contract of `inst`.
    unsafe {
        read(inst, std::ptr::null(), |view| match *view {
            View::X86(held, _) => &raw const held.native,
            #[cfg(feature = "aarch64")]
            View::AArch64(..) => std::ptr::null(),
        })
    }
}

/// The AArch64 instruction in the storage (`binbun_aarch64_instruction`,
/// which the `binbun_aarch64_*` functions read); null if it holds an x86
/// one or none.
///
/// # Safety
///
/// `inst` is null or storage a successful decode wrote, unchanged since.
#[cfg(feature = "aarch64")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn binbun_instruction_as_aarch64(
    inst: *const Instruction,
) -> *const A64Instruction {
    // SAFETY: the contract of `inst`.
    unsafe {
        read(inst, std::ptr::null(), |view| match *view {
            #[cfg(feature = "x86")]
            View::X86(..) => std::ptr::null(),
            View::AArch64(held, _) => &raw const held.native,
        })
    }
}

/// Writes the register's name, as its architecture writes it (`rax`, `x0`,
/// `za1.d`, `TPIDR_EL0`), into `text`, NUL-terminated when `capacity`
/// allows. Returns the length of the whole name without the NUL, or 0 if
/// `reg` is null or names no register.
///
/// # Safety
///
/// `reg` is null or a register the library wrote (or a copy of one), whose
/// `name` is the library's; `text` is null or writable for `capacity`
/// bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn binbun_register_name(
    reg: *const Register,
    text: *mut c_char,
    capacity: usize,
) -> usize {
    // SAFETY: `text` is null or writable for `capacity` bytes (contract).
    let buffer = unsafe { ffi::out_slice(text.cast::<u8>(), capacity) };
    // SAFETY: `reg` is null or a register (contract).
    let Some(register) = (unsafe { ffi::borrow(reg) }) else {
        return 0;
    };
    guard(0, || {
        let mut out = TextOut::new(buffer);
        if register.kind == REGISTER_AARCH64_SYSTEM && register.has_name != 0 {
            // SAFETY: the name is a string of the library (contract).
            let Ok(name) = (unsafe { ffi::bytes(register.name.data.cast(), register.name.length) })
            else {
                return 0;
            };
            out.push(name);
            return out.finish();
        }
        match register.native() {
            Some(native) if write!(out, "{native}").is_ok() => out.finish(),
            Some(_) | None => 0,
        }
    })
}
