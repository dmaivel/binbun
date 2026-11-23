//! Named example states ([`ExampleState`]) as a TOML file, in the style of
//! the session's project file, and the entry state a run starts from.
//!
//! ```toml
//! format = 1
//! name = "three"
//! function = "strvec_len"
//! arguments = ["0x10000"]          # by the prototype, in order
//!
//! [[region]]                       # mapped; bytes not set are undefined
//! address = "0x10000"
//! values = ["ptr:0x20000", "ptr:0x20008", "ptr:0x20010", "ptr:0"]
//!
//! [[stub]]
//! target = "strlen"
//! returns = "3"                    # a value, "argK", or "unknown"
//! ```
//!
//! A value is a number (decimal, `-` signed, or `0x` hexadecimal, where
//! `?` is an undefined digit) or `undefined`; a typed value is `TYPE:VALUE`
//! with `TYPE` one of `u8`–`u64`, `i8`–`i64`, `ptr`, `f32`, `f64`.

use binbun_decompile::lower::Convention;
use binbun_decompile::mapping::{Mapping, Source};
use binbun_decompile::validate::{Link, RETURN_ADDRESS, Setup, random_states};
use binbun_loader::{Format, Image, Machine};
use binbun_semantics::bits::Bits;
use binbun_semantics::interpret::Value;
use serde::{Deserialize, Serialize};

use super::memory::{Fill, Memory};

/// The version of the state file's format.
pub const FORMAT: u32 = 1;

/// The entry stack pointer a state without one starts at (16-byte
/// aligned before the call pushes a return address).
pub const STACK: u64 = 0x7ffe_0000_0000;

/// The thread pointer a state without one has.
pub const THREAD_POINTER: u64 = 0x7ff0_0000_0000;

/// The stack guard System V x86-64's thread control block holds
/// (`fs:0x28`) in every state: its low byte 0, as glibc's.
pub const STACK_GUARD: u64 = 0x5eed_c0de_1234_5600;

/// How much of the stack is mapped below the entry stack pointer.
const STACK_BELOW: u64 = 1 << 20;

/// How much of the stack is mapped above it (the caller's frame: stack
/// arguments).
const STACK_ABOVE: u64 = 1 << 16;

/// A named example state: what a function is run from.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExampleState {
    /// The file format's version ([`FORMAT`]).
    pub format: u32,
    /// Its name.
    pub name: String,
    /// The function it is for, by name or address, if one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub function: Option<String>,
    /// What memory nothing else sets reads as.
    #[serde(default)]
    pub fill: Fill,
    /// The arguments, by the function's prototype, in order: values
    /// (missing ones undefined).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub arguments: Vec<String>,
    /// The entry stack pointer ([`STACK`] if not given).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stack: Option<String>,
    /// The thread pointer ([`THREAD_POINTER`] if not given).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thread_pointer: Option<String>,
    /// Registers set by name (after the ABI's and before the arguments).
    #[serde(default, rename = "register", skip_serializing_if = "Vec::is_empty")]
    pub registers: Vec<RegisterValue>,
    /// Memory regions.
    #[serde(default, rename = "region", skip_serializing_if = "Vec::is_empty")]
    pub regions: Vec<Region>,
    /// Globals overridden.
    #[serde(default, rename = "global", skip_serializing_if = "Vec::is_empty")]
    pub globals: Vec<Global>,
    /// What calls that are not stepped into do.
    #[serde(default, rename = "stub", skip_serializing_if = "Vec::is_empty")]
    pub stubs: Vec<Stub>,
}

/// A register's value.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisterValue {
    /// The register's name.
    pub name: String,
    /// Its value (the register's width).
    pub value: String,
}

/// A memory region: mapped, its contents laid out from its address (raw
/// bytes, then a string, then typed values, then records), the bytes
/// nothing sets undefined.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Region {
    /// Its first address.
    pub address: String,
    /// Its size; at least what its contents take.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    /// Raw bytes, in hexadecimal pairs (spaces allowed, `??` undefined).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes: Option<String>,
    /// A string, NUL-terminated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub string: Option<String>,
    /// Typed values, each at its natural alignment (untyped: `u64`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub values: Vec<String>,
    /// An array of structs: each record's typed fields at their natural
    /// alignment, records `stride` bytes apart (the largest record's
    /// size, aligned, if not given).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub records: Vec<Vec<String>>,
    /// The distance between records.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stride: Option<u64>,
}

/// A global's value.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Global {
    /// The global, by name or address.
    pub at: String,
    /// Its typed value.
    pub value: String,
}

/// What a call does instead of running ([`ExampleState::stubs`]).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stub {
    /// The callee, by name (a function's or an import's) or address.
    pub target: String,
    /// Its result: a value, `argK` (argument `K`, from 0), or `unknown`
    /// (undefined; the default).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub returns: Option<String>,
    /// Bytes it copies, first.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub copy: Option<Copy>,
}

/// A copy a stub makes: each operand a number or `argK`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Copy {
    /// The source address.
    pub from: String,
    /// The destination address.
    pub to: String,
    /// How many bytes.
    pub bytes: String,
}

/// A stub's operand.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Operand {
    /// A value.
    Value(Value),
    /// Argument `k` of the call.
    Argument(usize),
    /// Undefined.
    Unknown,
}

impl Operand {
    /// The operand `text` names, `width` bits wide where it is a value.
    ///
    /// # Errors
    ///
    /// It is none.
    pub fn parse(text: &str, width: u16) -> Result<Self, String> {
        if text == "unknown" {
            return Ok(Self::Unknown);
        }
        if let Some(index) = text.strip_prefix("arg") {
            return index
                .parse()
                .map(Self::Argument)
                .map_err(|_| format!("not an argument: {text:?}"));
        }
        parse_value(text, width).map(Self::Value)
    }

    /// Its value with the call's `arguments`, `width` bits wide (an
    /// argument of another width zero-extended or cut).
    pub fn value(self, arguments: &[Value], width: u16) -> Value {
        match self {
            Self::Value(value) => fit(value, width),
            Self::Argument(k) => arguments
                .get(k)
                .map_or_else(|| Value::unknown(width), |&value| fit(value, width)),
            Self::Unknown => Value::unknown(width),
        }
    }
}

/// `value` at `width` bits: its low bits, or zero-extended.
pub fn fit(value: Value, width: u16) -> Value {
    use core::cmp::Ordering;
    match value.width().cmp(&width) {
        Ordering::Equal => value,
        Ordering::Greater => binbun_semantics::interpret::extract(value, 0, width),
        Ordering::Less => binbun_semantics::interpret::extend(false, value, width),
    }
}

/// The value `text` says, `width` bits wide.
///
/// # Errors
///
/// It is not a value.
pub fn parse_value(text: &str, width: u16) -> Result<Value, String> {
    let text = text.trim();
    if text == "undefined" {
        return Ok(Value::unknown(width));
    }
    let bad = || format!("not a value: {text:?}");
    if let Some(digits) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        let digits: Vec<char> = digits.chars().filter(|&c| c != '_').collect();
        let mut bytes = vec![0u8; usize::from(width.div_ceil(8))];
        let mut undefined = vec![0u8; bytes.len()];
        for (index, digit) in digits.iter().rev().enumerate() {
            let (byte, shift) = (index / 2, (index % 2) * 4);
            let (Some(value), Some(mask)) = (bytes.get_mut(byte), undefined.get_mut(byte)) else {
                return Err(format!("{text:?} is wider than {width} bits"));
            };
            match digit {
                '?' => *mask |= 0xf << shift,
                _ => {
                    *value |= u8::try_from(digit.to_digit(16).ok_or_else(bad)?)
                        .map_err(|_| bad())?
                        << shift;
                }
            }
        }
        return Ok(Value {
            bits: Bits::from_le_bytes(width, &bytes),
            undefined: Bits::from_le_bytes(width, &undefined),
        });
    }
    let number = match text.strip_prefix('-') {
        Some(magnitude) => magnitude.parse::<u64>().map_err(|_| bad())?.wrapping_neg(),
        None => text.parse::<u64>().map_err(|_| bad())?,
    };
    let value = Bits::from_u64(64, number);
    Ok(fit(Value::defined(value), width))
}

/// `value` as a state file writes it: hexadecimal, `?` for undefined
/// digits, `undefined` if no bit is defined.
pub fn format_value(value: &Value) -> String {
    if value.bits.is_zero() && value.undefined == Bits::ones(value.width()) {
        return "undefined".to_owned();
    }
    let bits: Vec<u8> = value.bits.to_le_bytes().collect();
    let undefined: Vec<u8> = value.undefined.to_le_bytes().collect();
    let digits = usize::from(value.width().div_ceil(4));
    let mut text = String::with_capacity(digits + 2);
    for index in (0..digits).rev() {
        let (byte, shift) = (index / 2, (index % 2) * 4);
        let mask = undefined.get(byte).copied().unwrap_or(0) >> shift & 0xf;
        let digit = bits.get(byte).copied().unwrap_or(0) >> shift & 0xf;
        text.push(if mask == 0 {
            char::from_digit(u32::from(digit), 16).unwrap_or('0')
        } else {
            '?'
        });
    }
    let trimmed = text.trim_start_matches('0');
    format!("0x{}", if trimmed.is_empty() { "0" } else { trimmed })
}

/// A typed value's bytes (value, undefined bits) and alignment.
///
/// # Errors
///
/// It is not a typed value.
fn typed(text: &str) -> Result<(Vec<(u8, u8)>, u64), String> {
    let (ty, value) = text.split_once(':').unwrap_or(("u64", text));
    let bytes: u16 = match ty {
        "u8" | "i8" => 1,
        "u16" | "i16" => 2,
        "u32" | "i32" | "f32" => 4,
        "u64" | "i64" | "ptr" | "f64" => 8,
        _ => return Err(format!("no type {ty:?} (in {text:?})")),
    };
    let width = bytes * 8;
    let value = match ty {
        "f32" => value
            .parse::<f32>()
            .map(|f| Value::defined(Bits::from_u64(32, u64::from(f.to_bits()))))
            .map_err(|_| format!("not a float: {value:?}"))?,
        "f64" => value
            .parse::<f64>()
            .map(|f| Value::defined(Bits::from_u64(64, f.to_bits())))
            .map_err(|_| format!("not a float: {value:?}"))?,
        _ => parse_value(value, width)?,
    };
    let pairs = value.bits.to_le_bytes().zip(value.undefined.to_le_bytes());
    Ok((pairs.collect(), u64::from(bytes)))
}

/// `address` (a name of `names`, or a number).
///
/// # Errors
///
/// It is neither.
pub fn address(text: &str, names: &dyn Fn(&str) -> Option<u64>) -> Result<u64, String> {
    if let Some(address) = names(text) {
        return Ok(address);
    }
    let value = parse_value(text, 64)?;
    value
        .known()
        .map(|bits| bits.low_u64())
        .ok_or_else(|| format!("not an address: {text:?}"))
}

/// A byte of a region: its offset, value and undefined bits.
type Placed = (u64, (u8, u8));

/// A region's contents: each byte (value, undefined bits) at its offset.
///
/// # Errors
///
/// A value is malformed.
fn contents(region: &Region) -> Result<Vec<Placed>, String> {
    let mut out = Vec::new();
    let mut at = 0u64;
    if let Some(bytes) = &region.bytes {
        let digits: Vec<char> = bytes.chars().filter(|c| !c.is_whitespace()).collect();
        for pair in digits.chunks(2) {
            let text: String = pair.iter().collect();
            let byte = if text == "??" {
                (0, 0xff)
            } else {
                let value =
                    u8::from_str_radix(&text, 16).map_err(|_| format!("not a byte: {text:?}"))?;
                (value, 0)
            };
            out.push((at, byte));
            at += 1;
        }
    }
    if let Some(string) = &region.string {
        for byte in string.bytes().chain([0]) {
            out.push((at, (byte, 0)));
            at += 1;
        }
    }
    for value in &region.values {
        let (bytes, align) = typed(value)?;
        at = at.next_multiple_of(align);
        for byte in bytes {
            out.push((at, byte));
            at += 1;
        }
    }
    let mut records = Vec::new();
    let mut largest = 1u64;
    for record in &region.records {
        let mut fields = Vec::new();
        let mut offset = 0u64;
        for field in record {
            let (bytes, align) = typed(field)?;
            largest = largest.max(align);
            offset = offset.next_multiple_of(align);
            for byte in bytes {
                fields.push((offset, byte));
                offset += 1;
            }
        }
        records.push((fields, offset));
    }
    if !records.is_empty() {
        let size = records.iter().map(|&(_, size)| size).max().unwrap_or(0);
        let stride = region.stride.unwrap_or(size.next_multiple_of(largest));
        at = at.next_multiple_of(largest);
        for (index, (fields, _)) in (0u64..).zip(records) {
            let base = at + index * stride;
            out.extend(
                fields
                    .into_iter()
                    .map(|(offset, byte)| (base + offset, byte)),
            );
        }
    }
    Ok(out)
}

/// The machine state a run starts from.
#[derive(Clone, Debug)]
pub struct Entry<'a> {
    /// Every register, in register order.
    pub registers: Vec<Value>,
    /// The memory.
    pub memory: Memory<'a>,
    /// The entry stack pointer.
    pub stack: u64,
    /// Where the function returns to.
    pub return_address: u64,
}

impl ExampleState {
    /// A state with nothing set (every argument undefined), named `name`.
    pub fn scratch(name: &str) -> Self {
        Self {
            format: FORMAT,
            name: name.to_owned(),
            ..Self::default()
        }
    }

    /// The `seed`th random state of the differential check under `setup`
    /// ([`random_states`]): every register set, on hashed memory
    /// ([`Fill::Hashed`]).
    pub fn random(setup: &Setup<'_>, seed: u64, name: &str) -> Self {
        let state = random_states(setup, 1, seed).pop();
        let registers = state
            .map(|state| {
                setup
                    .declarations
                    .registers
                    .iter()
                    .zip(&state.registers)
                    .map(|(info, value)| RegisterValue {
                        name: info.name.to_owned(),
                        value: format_value(value),
                    })
                    .collect()
            })
            .unwrap_or_default();
        Self {
            fill: Fill::Hashed,
            registers,
            ..Self::scratch(name)
        }
    }

    /// The state's TOML.
    ///
    /// # Errors
    ///
    /// TOML cannot hold it (it can).
    pub fn to_toml(&self) -> Result<String, String> {
        toml::to_string(self).map_err(|error| error.to_string())
    }

    /// The state a TOML `text` says.
    ///
    /// # Errors
    ///
    /// It is not TOML, not this format, or a later version.
    pub fn parse(text: &str) -> Result<Self, String> {
        let state: Self = toml::from_str(text).map_err(|error| error.to_string())?;
        if state.format > FORMAT {
            return Err(format!(
                "format {} is newer than this binbun's ({FORMAT})",
                state.format
            ));
        }
        Ok(state)
    }

    /// The machine state of a run of the function at `entry` of `image`
    /// under `setup` and `convention`, its parameters where `mapping` says,
    /// names resolved by `names`.
    ///
    /// The ABI's part first: every register undefined but the fixed ones
    /// (the program counter, a clear direction flag), the stack pointer
    /// (the return address pushed, or in the link register), the thread
    /// pointer (with System V x86-64's thread control block: its self
    /// pointers and [`STACK_GUARD`]), the floating-point controls at their
    /// initial values; the stack and the thread's block mapped; then the
    /// state's registers, arguments, regions and globals.
    ///
    /// # Errors
    ///
    /// A value, register or address of the state is malformed.
    pub fn entry<'a>(
        &self,
        image: &'a Image<'a>,
        setup: &Setup<'_>,
        convention: &Convention,
        mapping: &Mapping,
        names: &dyn Fn(&str) -> Option<u64>,
    ) -> Result<Entry<'a>, String> {
        let declarations = setup.declarations;
        let mut registers: Vec<Value> = declarations
            .registers
            .iter()
            .map(|info| Value::unknown(info.width))
            .collect();
        let set = |registers: &mut Vec<Value>, id: binbun_semantics::RegisterId, value: u64| {
            if let Some(slot) = registers.get_mut(usize::from(id.0)) {
                *slot = Value::defined(Bits::from_u64(slot.width(), value));
            }
        };
        let stack = match &self.stack {
            Some(text) => address(text, names)?,
            None => match setup.link {
                Link::Stack { bytes } => STACK - u64::from(bytes),
                Link::Register(_) => STACK,
            },
        };
        let tp = match &self.thread_pointer {
            Some(text) => address(text, names)?,
            None => THREAD_POINTER,
        };
        for &(id, value) in &setup.fixed {
            set(&mut registers, id, value);
        }
        set(&mut registers, setup.stack_pointer, stack);
        if let Link::Register(link) = setup.link {
            set(&mut registers, link, RETURN_ADDRESS);
        }
        if let Some(thread) = convention.thread_pointer {
            set(&mut registers, thread, tp);
        }
        for (name, value) in [("mxcsr", 0x1f80), ("fcw", 0x37f), ("fpcr", 0)] {
            if let Some(id) = declarations.find(name) {
                set(&mut registers, id, value);
            }
        }
        for register in &self.registers {
            let id = declarations
                .find(&register.name)
                .ok_or_else(|| format!("no register {:?}", register.name))?;
            let slot = registers
                .get_mut(usize::from(id.0))
                .ok_or_else(|| format!("no register {:?}", register.name))?;
            *slot = parse_value(&register.value, slot.width())?;
        }
        let stack = registers
            .get(usize::from(setup.stack_pointer.0))
            .and_then(Value::known)
            .map_or(stack, |bits| bits.low_u64());
        let mut memory = Memory::new(image, self.fill);
        memory.map(stack.saturating_sub(STACK_BELOW)..stack.saturating_add(STACK_ABOVE));
        if let Link::Stack { bytes } = setup.link
            && bytes > 0
        {
            let pushed = Bits::from_u64(bytes * 8, RETURN_ADDRESS);
            memory.set_value(stack, &Value::defined(pushed));
        }
        if image.machine == Machine::X86_64 && image.format == Format::Elf {
            memory.map(tp.saturating_sub(1 << 16)..tp.saturating_add(1 << 12));
            for (offset, value) in [(0, tp), (0x10, tp), (0x28, STACK_GUARD), (0x30, 0)] {
                memory.set_value(tp + offset, &Value::defined(Bits::from_u64(64, value)));
            }
        }
        self.place_arguments(mapping, stack, &mut registers, &mut memory)?;
        for region in &self.regions {
            let start = address(&region.address, names)?;
            let bytes = contents(region)?;
            let end = bytes
                .iter()
                .map(|&(offset, _)| offset + 1)
                .max()
                .unwrap_or(0);
            let size = region.size.unwrap_or(0).max(end);
            memory.map(start..start.saturating_add(size));
            for (offset, byte) in bytes {
                memory.set(start.wrapping_add(offset), byte);
            }
        }
        for global in &self.globals {
            let start = address(&global.at, names)?;
            let (bytes, _) = typed(&global.value)?;
            for (byte, at) in bytes.into_iter().zip(start..) {
                memory.set(at, byte);
            }
        }
        memory.set_registers(registers.clone());
        Ok(Entry {
            registers,
            memory,
            stack,
            return_address: RETURN_ADDRESS,
        })
    }

    /// Puts the arguments where `mapping`'s parameters are.
    fn place_arguments(
        &self,
        mapping: &Mapping,
        stack: u64,
        registers: &mut [Value],
        memory: &mut Memory<'_>,
    ) -> Result<(), String> {
        for (text, source) in self.arguments.iter().zip(&mapping.parameters) {
            match *source {
                Source::Register(piece) => {
                    let slot = registers
                        .get_mut(usize::from(piece.register.0))
                        .ok_or("an argument's register is not declared")?;
                    let value = parse_value(text, piece.width)?;
                    *slot = insert(*slot, value, piece.offset);
                }
                Source::Stack { offset, bytes } => {
                    let value = parse_value(text, bytes * 8)?;
                    memory.set_value(stack.wrapping_add_signed(offset), &value);
                }
            }
        }
        if self.arguments.len() > mapping.parameters.len() {
            return Err(format!(
                "{} arguments given, the function takes {}",
                self.arguments.len(),
                mapping.parameters.len()
            ));
        }
        Ok(())
    }
}

/// `whole` with `part` at bit `offset`.
fn insert(whole: Value, part: Value, offset: u16) -> Value {
    let width = whole.width();
    let place = |bits: Bits| {
        let bytes: Vec<u8> = bits.to_le_bytes().collect();
        Bits::from_le_bytes(width, &bytes).shift_left(u32::from(offset))
    };
    let mask = place(Bits::ones(part.width())).invert();
    Value {
        bits: whole.bits.and(&mask).or(&place(part.bits)),
        undefined: whole.undefined.and(&mask).or(&place(part.undefined)),
    }
}
