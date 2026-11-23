//! Text: instructions written as LLVM's disassembler writes them, as a
//! stream of tokens, with labels as absolute addresses (as llvm-objdump
//! writes them) or as offsets (as LLVM's C API does).
//!
//! The printer writes tokens, fixed or composed from pieces, into an
//! [`Out`]: for a [`Sink`], a composed token is collected in a small buffer
//! and handed over whole; for [`Display`], the whole line is collected and
//! written once. Numbers are written by hand rather than through
//! `core::fmt`, which cost more than the rest of the printer together.

use core::fmt;

use crate::Instruction;
use crate::generated::syntax;
use crate::operand::{
    Arrangement, ElementSize, Extend, ExtendKind, Float, Immediate, IndexedRegister, Label,
    ListStyle, Memory, Modifier, Offset, Operand, Operands, Predication, Radix, Register,
    RegisterClass, RegisterList, Shift, ShiftKind, SliceDirection, SystemRegister, Writeback, Za,
    ZaList,
};

/// What a piece of text is, for colouring.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TokenKind {
    /// The mnemonic, with any suffix (`b.eq`).
    Mnemonic,
    /// A register, including its arrangement and qualifier (`v0.16b`, `p0/z`).
    Register,
    /// An immediate, with its `#` (`#0x10`).
    Immediate,
    /// A PC-relative address: the address it names (`0x1040`), or the
    /// offset with [`LabelStyle::Relative`] (`#0x40`).
    Address,
    /// Brackets, braces, commas and the like.
    Punctuation,
    /// Spaces and tabs.
    Whitespace,
    /// Anything else: shift and extend kinds, names, conditions.
    Text,
}

/// How labels (the PC-relative addresses of branches, `adr`, `adrp` and
/// literal loads) are written.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum LabelStyle {
    /// The address the label names, in hexadecimal without `#`: `b
    /// 0x1040`, `adrp x0, 0x6000` (llvm-objdump without its `<symbol>`
    /// suffix, and other disassemblers).
    #[default]
    Absolute,
    /// The offset from the instruction (or its 4 KiB page for `adrp`), as
    /// LLVM's C API writes it: `b #0x40`, `adrp x0, #20480`, `adr x0,
    /// #16`. The text does not depend on the address.
    Relative,
}

/// Receives an instruction's text as tokens.
pub trait Sink {
    /// Writes one token.
    ///
    /// # Errors
    ///
    /// If the sink fails; formatting stops.
    fn token(&mut self, kind: TokenKind, text: &str) -> fmt::Result;
}

/// Every text writer is a sink that ignores token kinds.
impl<W: fmt::Write + ?Sized> Sink for W {
    fn token(&mut self, _kind: TokenKind, text: &str) -> fmt::Result {
        self.write_str(text)
    }
}

/// A stack buffer of ASCII text.
struct Buffer<const N: usize> {
    bytes: [u8; N],
    len: usize,
}

impl<const N: usize> Buffer<N> {
    const fn new() -> Self {
        Self {
            bytes: [0; N],
            len: 0,
        }
    }

    /// The next `n` bytes, appended, for the caller to fill with ASCII.
    fn reserve(&mut self, n: usize) -> Result<&mut [u8], fmt::Error> {
        let start = self.len;
        let bytes = self.bytes.get_mut(start..start + n).ok_or(fmt::Error)?;
        self.len = start + n;
        Ok(bytes)
    }

    fn as_str(&self) -> &str {
        // Validated in whole 16-byte blocks, which `from_utf8` checks for
        // ASCII a word at a time; the bytes after `len` are zeros, valid
        // ASCII.
        let validated = self.len.next_multiple_of(16).min(N);
        self.bytes
            .get(..validated)
            .and_then(|bytes| core::str::from_utf8(bytes).ok())
            .and_then(|text| text.get(..self.len))
            .unwrap_or_default()
    }

    /// Forgets the text, zeroing the bytes [`Buffer::as_str`] validates.
    fn clear(&mut self) {
        let used = self.len.next_multiple_of(16).min(N);
        if let Some(bytes) = self.bytes.get_mut(..used) {
            bytes.fill(0);
        }
        self.len = 0;
    }
}

/// Where the printer writes: tokens, each whole or built from pieces of
/// ASCII text and ended with its kind. `write_str` appends a piece.
trait Out: fmt::Write {
    /// The next `n` bytes of the token being built, for the caller to fill
    /// with ASCII.
    fn reserve(&mut self, n: usize) -> Result<&mut [u8], fmt::Error>;

    /// Appends ASCII `bytes` to the token being built.
    fn push(&mut self, bytes: &[u8]) -> fmt::Result {
        copy(self.reserve(bytes.len())?, bytes);
        Ok(())
    }

    /// Appends one ASCII byte to the token being built.
    fn push_byte(&mut self, byte: u8) -> fmt::Result {
        *self.reserve(1)?.first_mut().ok_or(fmt::Error)? = byte;
        Ok(())
    }

    /// Ends the token being built, as `kind`.
    fn end(&mut self, kind: TokenKind) -> fmt::Result;

    /// Writes `text` as one token; no token is being built.
    fn token(&mut self, kind: TokenKind, text: &str) -> fmt::Result;
}

/// Copies `source` to `target`, of the same length: pieces of text are
/// short, and two overlapping fixed-size copies cost less than a call of
/// `memcpy`.
fn copy(target: &mut [u8], source: &[u8]) {
    fn halves<const N: usize>(target: &mut [u8], source: &[u8]) {
        if let (Some(target), Some(source)) = (target.first_chunk_mut::<N>(), source.first_chunk())
        {
            *target = *source;
        }
        if let (Some(target), Some(source)) = (target.last_chunk_mut::<N>(), source.last_chunk()) {
            *target = *source;
        }
    }
    match source.len() {
        0 => {}
        1 => halves::<1>(target, source),
        2..4 => halves::<2>(target, source),
        4..8 => halves::<4>(target, source),
        8..=16 => halves::<8>(target, source),
        _ => target.copy_from_slice(source),
    }
}

/// Tokens for a [`Sink`], each collected whole before it is handed over.
struct Tokens<'a, S: Sink + ?Sized> {
    sink: &'a mut S,
    buffer: Buffer<40>,
}

impl<S: Sink + ?Sized> fmt::Write for Tokens<'_, S> {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        self.push(text.as_bytes())
    }
}

impl<S: Sink + ?Sized> Out for Tokens<'_, S> {
    fn reserve(&mut self, n: usize) -> Result<&mut [u8], fmt::Error> {
        self.buffer.reserve(n)
    }

    fn end(&mut self, kind: TokenKind) -> fmt::Result {
        self.sink.token(kind, self.buffer.as_str())?;
        self.buffer.clear();
        Ok(())
    }

    fn token(&mut self, kind: TokenKind, text: &str) -> fmt::Result {
        self.sink.token(kind, text)
    }
}

/// A whole line of text, token kinds dropped; longer lines than any
/// instruction's fail.
struct Line(Buffer<128>);

impl fmt::Write for Line {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        self.push(text.as_bytes())
    }
}

impl Out for Line {
    fn reserve(&mut self, n: usize) -> Result<&mut [u8], fmt::Error> {
        self.0.reserve(n)
    }

    fn end(&mut self, _kind: TokenKind) -> fmt::Result {
        Ok(())
    }

    fn token(&mut self, _kind: TokenKind, text: &str) -> fmt::Result {
        self.push(text.as_bytes())
    }
}

const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

/// Appends `value` in decimal.
fn decimal(out: &mut impl Out, value: u64) -> fmt::Result {
    if let Ok(digit @ 0..10) = u8::try_from(value) {
        return out.push_byte(b'0' + digit);
    }
    let digits = value.ilog10() as usize + 1;
    let mut rest = value;
    for digit in out.reserve(digits)?.iter_mut().rev() {
        *digit = b'0' + u8::try_from(rest % 10).unwrap_or_default();
        rest /= 10;
    }
    Ok(())
}

/// Appends `value` in lower-case hex, without `0x`, zero-padded to at least
/// `width` (1 to 16) digits.
fn hex(out: &mut impl Out, value: u64, width: u32) -> fmt::Result {
    let digits = (64 - value.leading_zeros()).div_ceil(4).max(width) as usize;
    let mut rest = value;
    for digit in out.reserve(digits)?.iter_mut().rev() {
        let nibble = usize::from(u8::try_from(rest & 15).unwrap_or_default());
        *digit = HEX_DIGITS.get(nibble).copied().unwrap_or_default();
        rest >>= 4;
    }
    Ok(())
}

/// Appends `0x` and `value` in hex, as `{:#x}`.
fn prefixed_hex(out: &mut impl Out, value: u64) -> fmt::Result {
    out.push(b"0x")?;
    hex(out, value, 1)
}

/// `#0x1f`, `#-0x1f` or `#31`.
fn number(
    out: &mut impl Out,
    kind: TokenKind,
    value: i64,
    signed: bool,
    radix: Radix,
) -> fmt::Result {
    let negative = signed && value < 0;
    let magnitude = if negative {
        value.unsigned_abs()
    } else {
        value.cast_unsigned()
    };
    out.push_byte(b'#')?;
    if negative {
        out.push_byte(b'-')?;
    }
    match radix {
        Radix::Hex => prefixed_hex(out, magnitude)?,
        Radix::Decimal => decimal(out, magnitude)?,
        Radix::PaddedHex if magnitude == 0 => hex(out, 0, 16)?,
        Radix::PaddedHex => {
            out.push(b"0x")?;
            hex(out, magnitude, 14)?;
        }
    }
    out.end(kind)
}

fn immediate(out: &mut impl Out, immediate: Immediate) -> fmt::Result {
    number(
        out,
        TokenKind::Immediate,
        immediate.as_i64(),
        immediate.signed,
        immediate.radix,
    )
}

fn label(out: &mut impl Out, label: Label, address: u64, style: LabelStyle) -> fmt::Result {
    match style {
        LabelStyle::Absolute => {
            prefixed_hex(out, label.target(address))?;
            out.end(TokenKind::Address)
        }
        LabelStyle::Relative => number(out, TokenKind::Address, label.offset, true, label.radix),
    }
}

const fn class_prefix(class: RegisterClass) -> &'static str {
    match class {
        RegisterClass::W | RegisterClass::Wsp => "w",
        RegisterClass::X | RegisterClass::Xsp => "x",
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
    }
}

const fn element_name(element: ElementSize) -> u8 {
    match element {
        ElementSize::B => b'b',
        ElementSize::H => b'h',
        ElementSize::S => b's',
        ElementSize::D => b'd',
        ElementSize::Q => b'q',
    }
}

/// Appends the register's name with its arrangement, index and qualifier.
fn register_text(out: &mut impl Out, register: Register) -> fmt::Result {
    match (register.class, register.number) {
        (RegisterClass::W, 31) => out.push(b"wzr")?,
        (RegisterClass::X, 31) => out.push(b"xzr")?,
        (RegisterClass::Wsp, 31) => out.push(b"wsp")?,
        (RegisterClass::Xsp, 31) => out.push(b"sp")?,
        (RegisterClass::Ffr, _) => out.push(b"ffr")?,
        (class, number) => {
            out.push(class_prefix(class).as_bytes())?;
            decimal(out, u64::from(number))?;
        }
    }
    if let Some(Arrangement { count, element }) = register.arrangement {
        out.push_byte(b'.')?;
        if count != 0 {
            decimal(out, u64::from(count))?;
        }
        out.push_byte(element_name(element))?;
    }
    if let Some(index) = register.index {
        out.push_byte(b'[')?;
        decimal(out, u64::from(index))?;
        out.push_byte(b']')?;
    }
    match register.predication {
        Some(Predication::Zeroing) => out.push(b"/z"),
        Some(Predication::Merging) => out.push(b"/m"),
        None => Ok(()),
    }
}

fn register(out: &mut impl Out, register: Register) -> fmt::Result {
    register_text(out, register)?;
    out.end(TokenKind::Register)
}

/// A register list; the lane index the registers share is written once,
/// after the closing brace (`{ v0.b, v1.b }[3]`).
fn list(out: &mut impl Out, mut list: RegisterList) -> fmt::Result {
    let index = list.first.index.take();
    out.token(TokenKind::Punctuation, "{ ")?;
    match list.style {
        // LLVM writes a range only for more than two registers that do not
        // wrap past the last register (31, 15 for predicates): `{ z0.s, z1.s }`,
        // `{ z30.s, z31.s, z0.s, z1.s }`.
        ListStyle::Range
            if list.count > 2
                && u32::from(list.first.number)
                    + u32::from(list.count - 1) * u32::from(list.stride)
                    < u32::from(list.registers()) =>
        {
            register(out, list.first)?;
            out.token(TokenKind::Punctuation, " - ")?;
            register(out, list.get(list.count - 1))?;
        }
        ListStyle::Range | ListStyle::Commas => {
            for i in 0..list.count {
                if i > 0 {
                    out.token(TokenKind::Punctuation, ", ")?;
                }
                register(out, list.get(i))?;
            }
        }
    }
    out.token(TokenKind::Punctuation, " }")?;
    if let Some(index) = index {
        out.token(TokenKind::Punctuation, "[")?;
        decimal(out, u64::from(index))?;
        out.end(TokenKind::Immediate)?;
        out.token(TokenKind::Punctuation, "]")?;
    }
    Ok(())
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

/// `lsl #8`; the SVE multiplier in hex (`mul #0x2`), as LLVM writes it.
fn shift(out: &mut impl Out, shift: Shift) -> fmt::Result {
    out.token(TokenKind::Text, shift_name(shift.kind))?;
    out.token(TokenKind::Whitespace, " ")?;
    let radix = if shift.kind == ShiftKind::Mul {
        Radix::Hex
    } else {
        Radix::Decimal
    };
    number(
        out,
        TokenKind::Immediate,
        i64::from(shift.amount),
        false,
        radix,
    )
}

/// `p2.b[w12, 15]`.
fn indexed_register(out: &mut impl Out, value: IndexedRegister) -> fmt::Result {
    register(out, value.register)?;
    out.token(TokenKind::Punctuation, "[")?;
    register(out, value.index)?;
    out.token(TokenKind::Punctuation, ", ")?;
    decimal(out, u64::from(value.offset))?;
    out.end(TokenKind::Immediate)?;
    out.token(TokenKind::Punctuation, "]")
}

fn extend(out: &mut impl Out, extend: Extend) -> fmt::Result {
    out.token(TokenKind::Text, extend_name(extend.kind))?;
    if let Some(amount) = extend.amount {
        out.token(TokenKind::Whitespace, " ")?;
        number(
            out,
            TokenKind::Immediate,
            i64::from(amount),
            false,
            Radix::Decimal,
        )?;
    }
    Ok(())
}

fn offset(out: &mut impl Out, offset: Offset) -> fmt::Result {
    match offset {
        Offset::None => Ok(()),
        Offset::Immediate(value) => immediate(out, value),
        Offset::Register { index, modifier } => {
            register(out, index)?;
            match modifier {
                Modifier::None => Ok(()),
                Modifier::Shift(value) => {
                    out.token(TokenKind::Punctuation, ", ")?;
                    shift(out, value)
                }
                Modifier::Extend(value) => {
                    out.token(TokenKind::Punctuation, ", ")?;
                    extend(out, value)
                }
            }
        }
        Offset::VectorLength(multiple) => {
            number(out, TokenKind::Immediate, multiple, true, Radix::Hex)?;
            out.token(TokenKind::Punctuation, ", ")?;
            out.token(TokenKind::Text, "mul vl")
        }
    }
}

fn memory(out: &mut impl Out, memory: Memory) -> fmt::Result {
    out.token(TokenKind::Punctuation, "[")?;
    register(out, memory.base)?;
    let has_offset = !matches!(memory.offset, Offset::None);
    if memory.writeback == Writeback::Post {
        out.token(TokenKind::Punctuation, "]")?;
        if has_offset {
            out.token(TokenKind::Punctuation, ", ")?;
            offset(out, memory.offset)?;
        }
        return Ok(());
    }
    if has_offset {
        out.token(TokenKind::Punctuation, ", ")?;
        offset(out, memory.offset)?;
    }
    out.token(TokenKind::Punctuation, "]")?;
    if memory.writeback == Writeback::Pre {
        out.token(TokenKind::Punctuation, "!")?;
    }
    Ok(())
}

fn za(out: &mut impl Out, za: Za) -> fmt::Result {
    out.push(b"za")?;
    if let Some(tile) = za.tile {
        decimal(out, u64::from(tile))?;
    }
    match za.direction {
        Some(SliceDirection::Horizontal) => out.push_byte(b'h')?,
        Some(SliceDirection::Vertical) => out.push_byte(b'v')?,
        None => {}
    }
    if let Some(element) = za.element {
        out.push_byte(b'.')?;
        out.push_byte(element_name(element))?;
    }
    out.end(TokenKind::Register)?;
    let Some(slice) = za.slice else {
        return Ok(());
    };
    out.token(TokenKind::Punctuation, "[")?;
    out.push_byte(b'w')?;
    decimal(out, u64::from(slice.index))?;
    out.end(TokenKind::Register)?;
    out.token(TokenKind::Punctuation, ", ")?;
    // LLVM writes offset ranges in hex (`0x4:0x7`), single offsets in
    // decimal (`7`).
    match slice.last {
        Some(last) => {
            prefixed_hex(out, u64::from(slice.offset))?;
            out.push_byte(b':')?;
            prefixed_hex(out, u64::from(last))?;
        }
        None => decimal(out, u64::from(slice.offset))?,
    }
    out.end(TokenKind::Immediate)?;
    if let Some(group) = slice.group {
        out.token(TokenKind::Punctuation, ", ")?;
        out.push(b"vgx")?;
        decimal(out, u64::from(group))?;
        out.end(TokenKind::Text)?;
    }
    out.token(TokenKind::Punctuation, "]")
}

/// The tiles of `mask` (bit i = tile i) as `za<i>.<element>`, joined by
/// `separator`.
fn tiles(out: &mut impl Out, mask: u8, element: u8, separator: &str) -> fmt::Result {
    let mut first = true;
    for tile in 0..8u8 {
        if mask & (1 << tile) == 0 {
            continue;
        }
        if !first {
            out.token(TokenKind::Punctuation, separator)?;
        }
        first = false;
        out.push(b"za")?;
        out.push_byte(b'0' + tile)?;
        out.push_byte(b'.')?;
        out.push_byte(element)?;
        out.end(TokenKind::Register)?;
    }
    Ok(())
}

fn za_list(out: &mut impl Out, list: ZaList) -> fmt::Result {
    out.token(TokenKind::Punctuation, "{")?;
    match list {
        ZaList::Slice(value) => za(out, value)?,
        ZaList::Tiles(0xff) => out.token(TokenKind::Register, "za")?,
        ZaList::Tiles(0x55) => out.token(TokenKind::Register, "za0.h")?,
        ZaList::Tiles(0xaa) => out.token(TokenKind::Register, "za1.h")?,
        ZaList::Tiles(mask) if mask & 0xf == mask >> 4 => tiles(out, mask & 0xf, b's', ",")?,
        ZaList::Tiles(mask) => tiles(out, mask, b'd', ", ")?,
    }
    out.token(TokenKind::Punctuation, "}")
}

/// `S<op0>_<op1>_C<n>_C<m>_<op2>`.
fn system_register_encoding(out: &mut impl Out, encoding: u16) -> fmt::Result {
    out.push_byte(b'S')?;
    decimal(out, u64::from(encoding >> 14))?;
    out.push_byte(b'_')?;
    decimal(out, u64::from((encoding >> 11) & 7))?;
    out.push(b"_C")?;
    decimal(out, u64::from((encoding >> 7) & 15))?;
    out.push(b"_C")?;
    decimal(out, u64::from((encoding >> 3) & 15))?;
    out.push_byte(b'_')?;
    decimal(out, u64::from(encoding & 7))?;
    out.end(TokenKind::Register)
}

/// Writes one operand of the instruction at `address`.
fn operand(out: &mut impl Out, value: &Operand, address: u64, style: LabelStyle) -> fmt::Result {
    match *value {
        Operand::Register(value) => register(out, value),
        Operand::List(value) => list(out, value),
        Operand::Immediate(value) => immediate(out, value),
        Operand::Float(Float { value, exact: true }) => {
            write!(out, "#{value:?}")?;
            out.end(TokenKind::Immediate)
        }
        Operand::Float(Float {
            value,
            exact: false,
        }) => {
            write!(out, "#{value:.8}")?;
            out.end(TokenKind::Immediate)
        }
        Operand::Shift(value) => shift(out, value),
        Operand::Extend(value) => extend(out, value),
        Operand::Memory(value) => memory(out, value),
        Operand::Writeback(value) => {
            register(out, value)?;
            out.token(TokenKind::Punctuation, "!")
        }
        Operand::Label(value) => label(out, value, address, style),
        Operand::Condition(value) => out.token(TokenKind::Text, value.name()),
        Operand::SystemRegister(SystemRegister {
            name: Some(name), ..
        }) => out.token(TokenKind::Register, name),
        Operand::SystemRegister(SystemRegister {
            encoding,
            name: None,
        }) => system_register_encoding(out, encoding),
        Operand::Named(value) => out.token(TokenKind::Text, value.name),
        Operand::Za(value) => za(out, value),
        Operand::ZaList(value) => za_list(out, value),
        Operand::TableSlice(offset) => {
            out.token(TokenKind::Register, "zt0")?;
            out.token(TokenKind::Punctuation, "[")?;
            decimal(out, u64::from(offset))?;
            out.end(TokenKind::Immediate)?;
            out.token(TokenKind::Punctuation, ", ")?;
            out.token(TokenKind::Text, "mul vl")?;
            out.token(TokenKind::Punctuation, "]")
        }
        Operand::IndexedRegister(value) => indexed_register(out, value),
    }
}

impl Instruction {
    /// Writes the instruction, at `address`, to `sink` as LLVM's
    /// disassembler (every feature, hexadecimal immediates) does: the
    /// mnemonic, a tab, and the operands separated by `, `; labels as the
    /// addresses they name (`b 0x1040`), as llvm-objdump writes them.
    ///
    /// # Errors
    ///
    /// If the sink fails.
    pub fn format(self, address: u64, sink: &mut impl Sink) -> fmt::Result {
        self.format_with(address, LabelStyle::Absolute, sink)
    }

    /// Writes the instruction as [`Instruction::format`] does, with labels
    /// written in `style`; [`LabelStyle::Relative`] gives the text of LLVM's
    /// C API exactly.
    ///
    /// # Errors
    ///
    /// If the sink fails.
    pub fn format_with(self, address: u64, style: LabelStyle, sink: &mut impl Sink) -> fmt::Result {
        self.write(
            address,
            style,
            &mut Tokens {
                sink,
                buffer: Buffer::new(),
            },
        )
    }

    /// Writes the instruction's tokens to `out`.
    fn write(self, address: u64, style: LabelStyle, out: &mut impl Out) -> fmt::Result {
        let alias = syntax::select(self.encoding(), self.word());
        out.token(
            TokenKind::Mnemonic,
            syntax::mnemonic(self.encoding(), alias, self.word()),
        )?;
        let mut operands = Operands::new();
        syntax::operands(self.encoding(), alias, self.word(), &mut operands);
        for (i, value) in operands.iter().enumerate() {
            if i == 0 {
                out.token(TokenKind::Whitespace, "\t")?;
            } else {
                out.token(TokenKind::Punctuation, ", ")?;
            }
            operand(out, value, address, style)?;
        }
        Ok(())
    }

    /// The instruction's text at `address`, as [`Instruction::format`]
    /// writes it (labels as addresses).
    pub const fn display(self, address: u64) -> Display {
        self.display_with(address, LabelStyle::Absolute)
    }

    /// The instruction's text at `address` with labels written in `style`,
    /// as [`Instruction::format_with`] writes it.
    pub const fn display_with(self, address: u64, style: LabelStyle) -> Display {
        Display {
            instruction: self,
            address,
            style,
        }
    }
}

/// An instruction's text, from [`Instruction::display`] or
/// [`Instruction::display_with`].
#[derive(Clone, Copy, Debug)]
pub struct Display {
    instruction: Instruction,
    address: u64,
    style: LabelStyle,
}

impl fmt::Display for Display {
    /// Collects the line on the stack and writes it with one call.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut line = Line(Buffer::new());
        match self.instruction.write(self.address, self.style, &mut line) {
            Ok(()) => f.write_str(line.0.as_str()),
            // Longer than the line buffer: token by token.
            Err(fmt::Error) => self.instruction.format_with(self.address, self.style, f),
        }
    }
}
