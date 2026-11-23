//! Behaviour checking: packs carry recordings of a library function's
//! behaviour, never its code.
//!
//! When a pack is made, each library function runs through the L1
//! interpreter on chosen states ([`record`]): random ones, ones shaped
//! by its prototype ([`Shape`]), ones that reach blocks the others did
//! not, and separators (states on which it and a look-alike differ). Its
//! behaviour on each is recorded ([`Recorded`]): the calls and system
//! calls it makes in order (callee, the argument registers the callee
//! reads, the result it was given), how it ended (the result at the ABI
//! by the prototype, a fault, a trap) and the memory it wrote outside its
//! frame. States are not stored: they are generated again from their
//! number and the shape ([`spec`], of generator version [`STATES`]).
//!
//! When a binary is matched, only the unknown function runs, on the
//! recorded states, its calls answered with the recorded results
//! ([`replay`]), and it agrees with the recording if every call, end and
//! write is the same. Addresses in the library's image are recorded by
//! symbol (`@__ctype_b+16`) and bound to the binary's addresses at first
//! use, consistently over every state of one check; a frame address is
//! any of the unknown's own frame; undefined bits match anything.

use core::fmt;
use core::str::FromStr;
use std::collections::{BTreeMap, BTreeSet, HashMap};

use binbun_semantics::bits::Bits;
use binbun_semantics::interpret::{Fault, Machine, Value as Bitvalue};
use binbun_semantics::ir::{IntrinsicId, RegisterId};
use binbun_ssa::interpret::{Calls, Outcome, run_calling};
use binbun_ssa::ir::{BlockId, Function, Op};
use serde::{Deserialize, Serialize};

use crate::canon::Abi;

/// The state generator version: bumped by every change to [`spec`].
pub const STATES: u32 = 2;

/// The fewest states that must run for a check to count.
pub const MINIMUM: usize = 16;

/// The most states a recording holds before separators.
pub const STATES_BEFORE_SEPARATORS: usize = 64;

/// Where functions return to.
pub const RETURN_ADDRESS: u64 = 0x7fff_0000_1000;

/// Where shaped states place their objects.
const HEAP: u64 = 0x6000_0000_0000;

/// Where allocators' fresh objects are placed.
const FRESH: u64 = 0x5000_0000_0000;

/// The bytes below the entry stack pointer that are the function's own.
const FRAME: u64 = 1 << 24;

/// The defined bytes after every object a state places.
const PADDING: usize = 64;

/// The first state number of the separator search.
pub const SEARCH: u32 = 1000;

/// How many states the separator search tries.
pub const SEARCH_STATES: u32 = 64;

/// The first state number of the coverage pool.
pub const POOL: u32 = 2000;

/// How many states the coverage pool holds.
pub const POOL_STATES: u32 = 192;

/// Names of allocators, whose result is a fresh object.
const ALLOCATORS: [&str; 8] = [
    "malloc",
    "calloc",
    "realloc",
    "aligned_alloc",
    "__libc_malloc",
    "__libc_calloc",
    "__libc_realloc",
    "__simple_malloc",
];

/// One parameter of a [`Shape`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Param {
    /// An integer of this many bytes (`i4`; unsigned `u4`).
    Int {
        /// Its size.
        bytes: u8,
        /// Whether signed.
        signed: bool,
    },
    /// A size of the object a pointer parameter before it points to (`n`).
    Count,
    /// A pointer to a string (`s`).
    Str,
    /// A pointer to a buffer (`b`).
    Buf,
    /// A floating-point number of this many bytes (`f8`).
    Float(u8),
    /// Not known (`?`).
    Unknown,
}

/// The result of a [`Shape`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Ret {
    /// None (`v`).
    Void,
    /// An integer of this many bytes (`i4`).
    Int(u8),
    /// A pointer (`p`).
    Ptr,
    /// A floating-point number of this many bytes (`f8`).
    Float(u8),
    /// Not known: compared in the low 32 bits of the first result
    /// register (`?`).
    Unknown,
}

/// What a function's states are shaped by: its parameters and result, by
/// the pack's prototype (or, without one, by the argument registers it
/// reads). Written `s,b,n>p`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Shape {
    /// The parameters, in order.
    pub params: Vec<Param>,
    /// The result.
    pub ret: Ret,
}

impl fmt::Display for Param {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Int { bytes, signed } => write!(f, "{}{bytes}", if *signed { 'i' } else { 'u' }),
            Self::Count => f.write_str("n"),
            Self::Str => f.write_str("s"),
            Self::Buf => f.write_str("b"),
            Self::Float(bytes) => write!(f, "f{bytes}"),
            Self::Unknown => f.write_str("?"),
        }
    }
}

impl FromStr for Param {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let bytes = |digits: &str| digits.parse::<u8>().map_err(|e| format!("{text}: {e}"));
        Ok(match text {
            "n" => Self::Count,
            "s" => Self::Str,
            "b" => Self::Buf,
            "?" => Self::Unknown,
            _ => match text.split_at_checked(1) {
                Some(("i", digits)) => Self::Int {
                    bytes: bytes(digits)?,
                    signed: true,
                },
                Some(("u", digits)) => Self::Int {
                    bytes: bytes(digits)?,
                    signed: false,
                },
                Some(("f", digits)) => Self::Float(bytes(digits)?),
                _ => return Err(format!("{text}: no parameter shape")),
            },
        })
    }
}

impl fmt::Display for Ret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Void => f.write_str("v"),
            Self::Int(bytes) => write!(f, "i{bytes}"),
            Self::Ptr => f.write_str("p"),
            Self::Float(bytes) => write!(f, "f{bytes}"),
            Self::Unknown => f.write_str("?"),
        }
    }
}

impl FromStr for Ret {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let bytes = |digits: &str| digits.parse::<u8>().map_err(|e| format!("{text}: {e}"));
        Ok(match text {
            "v" => Self::Void,
            "p" => Self::Ptr,
            "?" => Self::Unknown,
            _ => match text.split_at_checked(1) {
                Some(("i", digits)) => Self::Int(bytes(digits)?),
                Some(("f", digits)) => Self::Float(bytes(digits)?),
                _ => return Err(format!("{text}: no result shape")),
            },
        })
    }
}

impl fmt::Display for Shape {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, param) in self.params.iter().enumerate() {
            if index != 0 {
                f.write_str(",")?;
            }
            write!(f, "{param}")?;
        }
        write!(f, ">{}", self.ret)
    }
}

impl FromStr for Shape {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let (params, ret) = text
            .split_once('>')
            .ok_or_else(|| format!("{text}: no shape (parameters>result)"))?;
        let params = if params.is_empty() {
            Vec::new()
        } else {
            params
                .split(',')
                .map(str::parse)
                .collect::<Result<_, _>>()?
        };
        Ok(Self {
            params,
            ret: ret.parse()?,
        })
    }
}

/// Serde through `Display` and `FromStr`.
macro_rules! textual {
    ($type:ty) => {
        impl Serialize for $type {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.collect_str(self)
            }
        }

        impl<'de> Deserialize<'de> for $type {
            fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let text = String::deserialize(deserializer)?;
                text.parse().map_err(serde::de::Error::custom)
            }
        }
    };
}

textual!(Shape);
textual!(Val);
textual!(End);

/// A value in a recording.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Val {
    /// These bits (`x1f`).
    Int(u64),
    /// An address in the library's image: a symbol and an offset
    /// (`@name+16`, `@name-8`, `@name`).
    Sym(String, i64),
    /// An address in the function's own frame (`frame`).
    Frame,
    /// Bits not all defined (`?`).
    Any,
    /// A pointer to a NUL-terminated string in read-only memory of the
    /// image, by the hash of its bytes (`$` and 32 hexadecimal digits).
    Text(u128),
}

impl fmt::Display for Val {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Int(bits) => write!(f, "x{bits:x}"),
            Self::Sym(name, 0) => write!(f, "@{name}"),
            Self::Sym(name, offset) if *offset > 0 => write!(f, "@{name}+{offset}"),
            Self::Sym(name, offset) => write!(f, "@{name}{offset}"),
            Self::Frame => f.write_str("frame"),
            Self::Any => f.write_str("?"),
            Self::Text(hash) => write!(f, "${hash:032x}"),
        }
    }
}

impl FromStr for Val {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Ok(match text {
            "frame" => Self::Frame,
            "?" => Self::Any,
            _ => {
                if let Some(hex) = text.strip_prefix('$') {
                    Self::Text(u128::from_str_radix(hex, 16).map_err(|e| format!("{text}: {e}"))?)
                } else if let Some(hex) = text.strip_prefix('x') {
                    Self::Int(u64::from_str_radix(hex, 16).map_err(|e| format!("{text}: {e}"))?)
                } else if let Some(symbol) = text.strip_prefix('@') {
                    // The offset is the last `+n` or `-n`.
                    match symbol.rfind(['+', '-']) {
                        Some(at)
                            if at > 0
                                && symbol.get(at + 1..).is_some_and(|d| {
                                    !d.is_empty() && d.bytes().all(|b| b.is_ascii_digit())
                                }) =>
                        {
                            let (name, offset) = symbol.split_at(at);
                            Self::Sym(
                                name.to_owned(),
                                offset.parse().map_err(|e| format!("{text}: {e}"))?,
                            )
                        }
                        _ => Self::Sym(symbol.to_owned(), 0),
                    }
                } else {
                    return Err(format!("{text}: no value"));
                }
            }
        })
    }
}

/// How a run ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum End {
    /// It returned (`ret`), with its result where the shape has one
    /// (`ret:x0`).
    Return(Option<Val>),
    /// A memory access faulted at this address (`fault:…`; a write
    /// `wfault:…`).
    Fault {
        /// The address.
        at: Val,
        /// Whether a write.
        write: bool,
    },
    /// It trapped (`trap:Divide`).
    Trap(String),
    /// A call that does not return (`stop`).
    Stop,
}

impl fmt::Display for End {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Return(None) => f.write_str("ret"),
            Self::Return(Some(value)) => write!(f, "ret:{value}"),
            Self::Fault { at, write: false } => write!(f, "fault:{at}"),
            Self::Fault { at, write: true } => write!(f, "wfault:{at}"),
            Self::Trap(trap) => write!(f, "trap:{trap}"),
            Self::Stop => f.write_str("stop"),
        }
    }
}

impl FromStr for End {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Ok(match text.split_once(':') {
            None if text == "ret" => Self::Return(None),
            None if text == "stop" => Self::Stop,
            Some(("ret", value)) => Self::Return(Some(value.parse()?)),
            Some(("fault", value)) => Self::Fault {
                at: value.parse()?,
                write: false,
            },
            Some(("wfault", value)) => Self::Fault {
                at: value.parse()?,
                write: true,
            },
            Some(("trap", trap)) => Self::Trap(trap.to_owned()),
            _ => return Err(format!("{text}: no end")),
        })
    }
}

/// A call or system call a recorded run made.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    /// The callee (a system call: its number).
    pub to: Val,
    /// Whether a system call.
    #[serde(default, skip_serializing_if = "core::ops::Not::not")]
    pub sys: bool,
    /// The argument registers compared (a mask over the convention's
    /// argument registers; a system call: over its argument registers).
    #[serde(rename = "m")]
    pub mask: u32,
    /// Their values.
    #[serde(rename = "a", default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<Val>,
    /// The result it was given.
    #[serde(rename = "r")]
    pub result: u64,
}

/// Which state a recorded run ran from: its number, and the shape it was
/// generated by if not the recording's (a separator found with a
/// look-alike's shape). Written as the number, or `[number, shape]`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum StateId {
    /// Of the recording's shape.
    Own(u32),
    /// Of another shape.
    Shaped(u32, Shape),
}

impl StateId {
    /// The number.
    pub fn number(&self) -> u32 {
        match self {
            Self::Own(number) | Self::Shaped(number, _) => *number,
        }
    }
}

/// One recorded run.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Recorded {
    /// The state.
    #[serde(rename = "s")]
    pub state: StateId,
    /// The calls and system calls, in order.
    #[serde(rename = "c", default, skip_serializing_if = "Vec::is_empty")]
    pub calls: Vec<Event>,
    /// How it ended.
    #[serde(rename = "e")]
    pub end: End,
    /// What it wrote outside its frame: runs of bytes, each its first
    /// address and its bytes in hexadecimal (`??`: undefined).
    #[serde(rename = "w", default, skip_serializing_if = "Vec::is_empty")]
    pub writes: Vec<(Val, String)>,
}

/// A library function's recorded behaviour.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Recording {
    /// The state generator version ([`STATES`]).
    pub generator: u32,
    /// The shape its states are generated by.
    pub shape: Shape,
    /// The runs.
    pub states: Vec<Recorded>,
}

/// What checking asks of the image a function is in.
pub trait World {
    /// The byte the image holds at `address` when loaded, if it maps it.
    fn byte(&self, address: u64) -> Option<u8>;
    /// The symbol `address` lies in, and its offset there (the library's
    /// image, when recording). An imported function, where its import's
    /// slot points, is `__imp_NAME`, when recording and when replaying: a
    /// recorded import is only that import, and a recorded function of
    /// the library never an import.
    fn symbol(&self, address: u64) -> Option<(String, i64)>;
    /// The argument registers (a mask) the function at `callee` reads, if
    /// known.
    fn reads(&self, callee: u64) -> Option<u32>;
    /// The hash of the NUL-terminated string at `address`, if it is one
    /// in read-only memory of the image.
    fn text(&self, address: u64) -> Option<u128>;
}

/// The machine checks run on: its convention and fixed registers.
#[derive(Clone, Debug)]
pub struct Platform<'a> {
    /// The convention.
    pub abi: Abi<'a>,
    /// The program counter, set to the function's entry.
    pub program_counter: Option<RegisterId>,
    /// Registers with a fixed value on entry (a flag the convention keeps
    /// clear, the thread pointer).
    pub fixed: Vec<(RegisterId, u64)>,
    /// The thread pointer, if the platform has one: the 4 KiB on each
    /// side of it read as zeros but for [`Platform::thread_words`], so
    /// code reading its thread's block runs on rather than following
    /// garbage.
    pub thread: Option<u64>,
    /// The words of the thread's block that are not zero, by their offset
    /// from the thread pointer: the thread's self pointers (musl's and
    /// glibc's at 0 and 16; the TEB's at `0x30`) and Windows' pointer to
    /// the thread's array of thread-local blocks (`0x58`).
    pub thread_words: Vec<(u64, u64)>,
    /// The bytes of the return address pushed at the entry stack pointer.
    pub link_bytes: u16,
    /// The blocks a run may enter.
    pub fuel: u64,
}

/// A state's values ([`spec`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Spec {
    /// The integer argument registers' values.
    pub arguments: Vec<u64>,
    /// The vector argument registers' low 64 bits.
    pub floats: Vec<u64>,
    /// The stack pointer at entry (the return address pushed).
    pub stack: u64,
    /// Memory it sets: each region's first address and bytes.
    pub regions: Vec<(u64, Vec<u8>)>,
}

/// A 64-bit mix (the finalizer of `SplitMix64`).
fn mix(mut x: u64) -> u64 {
    x = (x ^ (x >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    x ^ (x >> 31)
}

/// A deterministic generator.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        mix(self.0)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }

    fn byte(&mut self) -> u8 {
        self.next().to_le_bytes()[0]
    }

    /// A register value: often an edge value, a small number or a
    /// pointer-like one.
    fn value(&mut self) -> u64 {
        match self.below(12) {
            0 => 0,
            1 => u64::MAX,
            2 => 1,
            3 => 1 << self.below(64),
            4 => (1 << self.below(64)) - 1,
            5 => self.below(64),
            6 => 0x8000_0000 | (self.next() & !0xffff_ffff),
            7 => self.below(0x1_0000),
            8 | 9 => 0x5555_0000_0000 + self.below(0x1_0000_0000) * 8,
            _ => self.next(),
        }
    }

    /// A string character: often an edge one.
    fn character(&mut self) -> u8 {
        const EDGE: &[u8] = b" \t\n0123456789+-xX.aAzZ%";
        match self.below(4) {
            0 => EDGE
                .get(usize::try_from(self.below(EDGE.len() as u64)).unwrap_or(0))
                .copied()
                .unwrap_or(b'a'),
            1 => 0x80 | self.byte(),
            _ => 0x20 + u8::try_from(self.below(95)).unwrap_or(0),
        }
    }
}

/// An integer parameter's value: a character, a small number or an edge.
fn integer(rng: &mut Rng, bytes: u8, signed: bool) -> u64 {
    let bits = u32::from(bytes.clamp(1, 8)) * 8;
    let value: i64 = match rng.below(8) {
        0 | 1 => i64::try_from(rng.below(257)).unwrap_or(0) - 1,
        2 | 3 => i64::try_from(rng.below(17)).unwrap_or(0),
        4 => -1,
        5 => i64::from(rng.character()),
        6 => {
            if signed {
                i64::MIN >> (64 - bits)
            } else {
                0
            }
        }
        _ => rng.next().cast_signed(),
    };
    truncate(value.cast_unsigned(), bits, signed)
}

/// `value` cut to `bits`, then sign- or zero-extended.
fn truncate(value: u64, bits: u32, signed: bool) -> u64 {
    if bits >= 64 {
        return value;
    }
    let low = value & ((1 << bits) - 1);
    if signed && low >> (bits - 1) & 1 == 1 {
        low | !((1 << bits) - 1)
    } else {
        low
    }
}

/// A floating-point parameter's bits.
fn float(rng: &mut Rng, bytes: u8) -> u64 {
    const DOUBLES: [f64; 8] = [0.0, -0.0, 1.5, -2.25, 1e300, f64::INFINITY, 3.0e-310, 42.0];
    let value = match rng.below(3) {
        0 => DOUBLES
            .get(usize::try_from(rng.below(8)).unwrap_or(0))
            .copied()
            .unwrap_or(0.0),
        1 => f64::NAN,
        _ => f64::from(u32::try_from(rng.next() >> 32).unwrap_or(0)) / 1e3 - 2e6,
    };
    if bytes == 4 {
        #[expect(
            clippy::cast_possible_truncation,
            reason = "a float argument: the double rounded"
        )]
        let single = value as f32;
        u64::from(single.to_bits())
    } else {
        value.to_bits()
    }
}

/// How the separator search varies a shaped state.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Variation {
    None,
    OverlapForward,
    OverlapBackward,
    ZeroCounts,
    FullCounts,
    Edges,
    Absent,
    Empty,
    Long,
}

/// The values of state `number` for a function of `shape`, under a
/// convention of `integers` and `floats` argument registers ([the
/// module](self)): 0–15 random, 16–47 shaped by the parameters, from
/// [`SEARCH`] the separator search's variations, from [`POOL`] more
/// shaped and random ones for coverage. A parameter of unknown type is
/// shaped as a pointer to an object (half the time) whose words are
/// pointers to further objects, small numbers, zeros or random bits, so
/// that code following pointers runs past its first load; else as a
/// small number or a register value.
#[expect(clippy::too_many_lines, reason = "one family of states after another")]
#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "each variation changes what it is about; the others keep the default"
)]
pub fn spec(shape: &Shape, integers: usize, floats: usize, number: u32) -> Spec {
    let mut rng = Rng(mix(u64::from(number).wrapping_add(0x5157_a7e5)));
    let stack = 0x7ffe_0000_0000 + rng.below(0x10_0000) * 16 - 8;
    let random = number < 16 || (number >= POOL && number.is_multiple_of(4));
    let variation = if (SEARCH..SEARCH + SEARCH_STATES).contains(&number) {
        match (number - SEARCH) % 8 {
            0 => Variation::OverlapForward,
            1 => Variation::OverlapBackward,
            2 => Variation::ZeroCounts,
            3 => Variation::FullCounts,
            4 => Variation::Edges,
            5 => Variation::Absent,
            6 => Variation::Empty,
            _ => Variation::Long,
        }
    } else {
        Variation::None
    };
    let mut spec = Spec {
        arguments: Vec::new(),
        floats: Vec::new(),
        stack,
        regions: Vec::new(),
    };
    let mut next = HEAP;
    // Each object's start and size.
    let mut objects: Vec<(u64, u64)> = Vec::new();
    let mut place = |bytes: Vec<u8>, rng: &mut Rng, objects: &mut Vec<(u64, u64)>| {
        let start = next;
        let size = bytes.len() as u64;
        let mut region = bytes;
        region.extend((0..PADDING).map(|_| rng.byte()));
        next += (region.len() as u64).next_multiple_of(0x1000) + 0x1000;
        spec.regions.push((start, region));
        objects.push((start, size));
        start
    };
    let params: Vec<Param> = if shape.params.is_empty() && random {
        vec![Param::Unknown; integers]
    } else {
        shape.params.clone()
    };
    let mut integer_values = Vec::new();
    let mut float_values = Vec::new();
    for param in &params {
        if random {
            match param {
                Param::Float(bytes) => float_values.push(float(&mut rng, *bytes)),
                Param::Int { .. } | Param::Count | Param::Str | Param::Buf | Param::Unknown => {
                    integer_values.push(rng.value());
                }
            }
            continue;
        }
        let value = match *param {
            Param::Int { bytes, signed } => {
                if variation == Variation::Edges {
                    truncate(
                        1 << (u32::from(bytes.clamp(1, 8)) * 8 - 1),
                        u32::from(bytes) * 8,
                        signed,
                    )
                } else if variation == Variation::Absent {
                    0x7f
                } else {
                    integer(&mut rng, bytes, signed)
                }
            }
            Param::Count => {
                let bound = objects.iter().map(|&(_, size)| size).min().unwrap_or(16);
                match variation {
                    Variation::ZeroCounts => 0,
                    Variation::FullCounts => bound,
                    _ => rng.below(bound + 1),
                }
            }
            Param::Str => {
                let length = match variation {
                    Variation::Empty => 0,
                    Variation::Long => 64,
                    _ => rng.below(17),
                };
                let mut text: Vec<u8> = (0..length)
                    .map(|_| {
                        let c = rng.character();
                        if variation == Variation::Absent && c == 0x7f {
                            b'a'
                        } else {
                            c
                        }
                    })
                    .collect();
                text.push(0);
                place(text, &mut rng, &mut objects)
            }
            Param::Buf => {
                const SIZES: [u64; 7] = [0, 1, 7, 8, 16, 31, 64];
                let size = match variation {
                    Variation::Long => 64,
                    Variation::Empty => 0,
                    _ => SIZES
                        .get(usize::try_from(rng.below(7)).unwrap_or(0))
                        .copied()
                        .unwrap_or(16),
                };
                let bytes = (0..size).map(|_| rng.byte()).collect();
                place(bytes, &mut rng, &mut objects)
            }
            Param::Float(bytes) => {
                float_values.push(float(&mut rng, bytes));
                continue;
            }
            Param::Unknown => match rng.below(4) {
                0 | 1 => {
                    let mut bytes = Vec::with_capacity(64);
                    for _ in 0..8 {
                        let word = match rng.below(4) {
                            0 => {
                                let inner = (0..64).map(|_| rng.byte()).collect();
                                place(inner, &mut rng, &mut objects)
                            }
                            1 => rng.below(64),
                            2 => 0,
                            _ => rng.next(),
                        };
                        bytes.extend(word.to_le_bytes());
                    }
                    place(bytes, &mut rng, &mut objects)
                }
                2 => integer(&mut rng, 8, true),
                _ => rng.value(),
            },
        };
        integer_values.push(value);
    }
    // Overlapping pointers: the second pointer one byte after (or
    // before) the first.
    let pointers: Vec<usize> = params
        .iter()
        .filter(|p| !matches!(p, Param::Float(_)))
        .enumerate()
        .filter(|(_, p)| matches!(p, Param::Str | Param::Buf))
        .map(|(index, _)| index)
        .collect();
    if let [first, second, ..] = pointers.as_slice()
        && let (Some(&a), Some(&b)) = (integer_values.get(*first), integer_values.get(*second))
    {
        let _ = b;
        match variation {
            Variation::OverlapForward => {
                if let Some(value) = integer_values.get_mut(*second) {
                    *value = a + 1;
                }
            }
            Variation::OverlapBackward => {
                if let Some(value) = integer_values.get_mut(*first) {
                    *value = b + 1;
                }
            }
            _ => {}
        }
    }
    integer_values.resize(integers.max(integer_values.len()), 0);
    for value in integer_values.iter_mut().skip(params.len()) {
        *value = rng.value();
    }
    float_values.resize(floats.max(float_values.len()), 0);
    integer_values.truncate(integers);
    float_values.truncate(floats);
    spec.arguments = integer_values;
    spec.floats = float_values;
    spec
}

/// The memory of one run: the state's regions, the image, and hashed
/// bytes elsewhere (bytes below 0x1000 fault), and the thread's block
/// ([`Platform::thread`]); the run's writes.
struct Memory<'w> {
    world: &'w dyn World,
    thread: Option<u64>,
    thread_words: &'w [(u64, u64)],
    set: BTreeMap<u64, (u8, u8)>,
    writes: BTreeSet<u64>,
}

impl Memory<'_> {
    fn byte(&self, address: u64) -> Option<(u8, u8)> {
        if let Some(&byte) = self.set.get(&address) {
            return Some(byte);
        }
        if let Some(thread) = self.thread
            && address.wrapping_sub(thread.wrapping_sub(0x1000)) < 0x2000
        {
            let offset = address.wrapping_sub(thread);
            let byte = self
                .thread_words
                .iter()
                .find(|&&(at, _)| offset.wrapping_sub(at) < 8)
                .and_then(|&(at, word)| {
                    word.to_le_bytes()
                        .get(usize::try_from(offset.wrapping_sub(at)).ok()?)
                        .copied()
                });
            return Some((byte.unwrap_or(0), 0));
        }
        if let Some(byte) = self.world.byte(address) {
            return Some((byte, 0));
        }
        (address >= 0x1000).then(|| (mix(address).to_le_bytes()[0], 0))
    }
}

impl Machine for Memory<'_> {
    fn read(&mut self, _register: RegisterId) -> Bitvalue {
        Bitvalue::unknown(1)
    }

    fn write(&mut self, _register: RegisterId, _value: Bitvalue) {}

    fn load(&mut self, address: u64, bytes: u16) -> Result<Bitvalue, Fault> {
        let fault = Fault {
            address,
            write: false,
        };
        let mut values = Vec::with_capacity(usize::from(bytes));
        let mut undefined = Vec::with_capacity(usize::from(bytes));
        for offset in 0..u64::from(bytes) {
            let (value, mask) = self.byte(address.wrapping_add(offset)).ok_or(fault)?;
            values.push(value);
            undefined.push(mask);
        }
        let width = bytes * 8;
        Ok(Bitvalue {
            bits: Bits::from_le_bytes(width, &values),
            undefined: Bits::from_le_bytes(width, &undefined),
        })
    }

    fn store(&mut self, address: u64, value: Bitvalue) -> Result<(), Fault> {
        let bytes = u64::from(value.width() / 8);
        for offset in 0..bytes {
            if self.byte(address.wrapping_add(offset)).is_none() {
                return Err(Fault {
                    address,
                    write: true,
                });
            }
        }
        let pairs = value.bits.to_le_bytes().zip(value.undefined.to_le_bytes());
        for (offset, (bits, undefined)) in (0..bytes).zip(pairs) {
            let at = address.wrapping_add(offset);
            self.set.insert(at, (bits & !undefined, undefined));
            self.writes.insert(at);
        }
        Ok(())
    }

    fn intrinsic(
        &mut self,
        intrinsic: IntrinsicId,
        inputs: &[Bitvalue],
        outputs: &[u16],
    ) -> Vec<Bitvalue> {
        let mut state = mix(u64::from(intrinsic.0) + 1);
        for input in inputs {
            let known = input.bits.and(&input.undefined.invert());
            for byte in known.to_le_bytes() {
                state = mix(state ^ u64::from(byte));
            }
        }
        outputs
            .iter()
            .map(|&width| {
                let bytes: Vec<u8> = (0..width.div_ceil(8))
                    .map(|_| {
                        state = mix(state);
                        state.to_le_bytes()[0]
                    })
                    .collect();
                Bitvalue::defined(Bits::from_le_bytes(width, &bytes))
            })
            .collect()
    }
}

/// Addresses bound to the library's symbols over one check.
#[derive(Clone, Debug, Default)]
pub struct Bindings {
    names: HashMap<String, u64>,
    addresses: HashMap<u64, String>,
}

impl Bindings {
    /// The address each symbol was bound to.
    pub fn bound(&self) -> impl Iterator<Item = (&str, u64)> {
        self.names
            .iter()
            .map(|(name, &address)| (name.as_str(), address))
    }

    /// Binds `name` to `address` if neither is bound to another; whether
    /// they are bound to each other.
    fn bind(&mut self, name: &str, address: u64) -> bool {
        match (self.names.get(name), self.addresses.get(&address)) {
            (Some(&known), _) => known == address,
            (None, Some(_)) => false,
            (None, None) => {
                self.names.insert(name.to_owned(), address);
                self.addresses.insert(address, name.to_owned());
                true
            }
        }
    }
}

/// One run's context: its stack and the world.
struct Context<'w> {
    world: &'w dyn World,
    stack: u64,
}

impl Context<'_> {
    /// Whether `address` is in the run's own frame (or the pushed return
    /// address).
    fn frame(&self, address: u64) -> bool {
        (self.stack.wrapping_sub(FRAME)..self.stack.wrapping_add(8)).contains(&address)
    }

    /// `value` as recorded: symbolic where the image maps it.
    fn classify(&self, value: Bitvalue) -> Val {
        let Some(bits) = value.known() else {
            return Val::Any;
        };
        let bits = bits.low_u64();
        if self.frame(bits) {
            return Val::Frame;
        }
        if let Some(hash) = self.world.text(bits) {
            return Val::Text(hash);
        }
        match self.world.symbol(bits) {
            Some((name, offset)) => Val::Sym(name, offset),
            None => Val::Int(bits),
        }
    }

    /// Whether `actual` (its low `bits` bits) is what `expected` says,
    /// binding symbols on the way.
    fn matches(
        &self,
        expected: &Val,
        actual: Bitvalue,
        bits: u32,
        bindings: &mut Bindings,
    ) -> bool {
        match expected {
            Val::Any => true,
            Val::Int(value) => actual.known().is_some_and(|known| {
                let mask = if bits >= 64 {
                    u64::MAX
                } else {
                    (1 << bits) - 1
                };
                known.low_u64() & mask == value & mask
            }),
            Val::Frame => actual
                .known()
                .is_some_and(|known| self.frame(known.low_u64())),
            Val::Text(hash) => actual
                .known()
                .is_some_and(|known| self.world.text(known.low_u64()) == Some(*hash)),
            Val::Sym(name, offset) => actual.known().is_some_and(|known| {
                let address = known.low_u64();
                // An import is itself by name, on both sides: never bound
                // to another function.
                match self.world.symbol(address).filter(|(n, _)| is_import(n)) {
                    Some((import, at)) => import == *name && at == *offset,
                    None => {
                        !is_import(name)
                            && self.world.byte(address).is_some()
                            && bindings.bind(name, address.wrapping_sub(offset.cast_unsigned()))
                    }
                }
            }),
        }
    }

    /// Why call `index` of a run (a system call if `sys`, to `target`,
    /// its argument registers' values `arguments` in order) is not the
    /// recorded `event`, if it is not: another callee, or another value
    /// in an argument register the callee reads.
    fn call_differs(
        &self,
        event: &Event,
        index: usize,
        (sys, target): (bool, Bitvalue),
        arguments: impl IntoIterator<Item = Bitvalue>,
        bindings: &mut Bindings,
    ) -> Option<String> {
        if !(event.sys == sys && self.matches(&event.to, target, 64, bindings)) {
            return Some(format!(
                "call {} is to another callee ({})",
                index + 1,
                event.to
            ));
        }
        let mut values = event.args.iter();
        for (bit, actual) in arguments.into_iter().enumerate() {
            if event.mask & (1 << bit) == 0 {
                continue;
            }
            let Some(expected) = values.next() else { break };
            if !self.matches(expected, actual, 32, bindings) {
                return Some(format!(
                    "call {} ({}) has another argument {} ({expected} expected)",
                    index + 1,
                    event.to,
                    bit + 1
                ));
            }
        }
        None
    }
}

/// Whether a [`World::symbol`] name is an import's (`__imp_NAME`).
fn is_import(name: &str) -> bool {
    name.starts_with("__imp_")
}

/// What the run's calls do: record them, or answer them from a recording.
enum Mode<'r> {
    Record {
        masks: &'r BTreeMap<u64, u32>,
        seed: u64,
    },
    Replay {
        expected: &'r [Event],
        bindings: &'r mut Bindings,
    },
    /// Stop at the first call, keeping it ([`opening`]).
    Open { first: Option<FirstCall> },
}

/// A run's first call (or system call), as made: what a replay compares
/// with a recording's first call.
#[derive(Clone, Debug)]
struct FirstCall {
    sys: bool,
    /// The callee's address (a system call: its number).
    target: Bitvalue,
    /// The argument registers' values, in order.
    arguments: Vec<Bitvalue>,
}

/// The calls handler of one run.
struct Handler<'c, 'r> {
    context: &'c Context<'c>,
    platform: &'c Platform<'c>,
    mode: Mode<'r>,
    events: Vec<Event>,
    /// Why the run disagrees, if it does.
    differs: Option<String>,
    fresh: u64,
}

impl Handler<'_, '_> {
    /// The result of the next call to `to` with `values` (every register),
    /// comparing `mask`'s argument registers; `None` if it disagrees.
    #[expect(
        clippy::too_many_lines,
        reason = "recording and replaying a call, side by side"
    )]
    fn event(
        &mut self,
        address: u64,
        target: Bitvalue,
        registers: &[Bitvalue],
        sys: bool,
    ) -> Option<u64> {
        let argument_registers = if sys {
            self.platform
                .abi
                .system_call
                .iter()
                .skip(1)
                .copied()
                .collect()
        } else {
            self.platform.abi.argument_registers()
        };
        let value_of = |register: RegisterId| {
            registers
                .get(usize::from(register.0))
                .copied()
                .unwrap_or_else(|| Bitvalue::unknown(64))
        };
        let index = self.events.len();
        match &mut self.mode {
            Mode::Record { masks, seed } => {
                let to = if sys {
                    Val::Int(target.known()?.low_u64())
                } else {
                    self.context.classify(target)
                };
                if to == Val::Any {
                    return None;
                }
                let target_bits = target.known().map(|b| b.low_u64());
                let mask = if sys {
                    (1 << argument_registers.len()) - 1
                } else {
                    target_bits
                        .and_then(|t| self.context.world.reads(t))
                        .or_else(|| masks.get(&address).copied())
                        .unwrap_or(0)
                };
                let args = argument_registers
                    .iter()
                    .enumerate()
                    .filter(|(bit, _)| mask & (1 << bit) != 0)
                    .map(|(_, &register)| self.context.classify(value_of(register)))
                    .collect();
                let allocator =
                    matches!(&to, Val::Sym(name, 0) if ALLOCATORS.contains(&name.as_str()));
                let mut rng = Rng(mix(*seed ^ (index as u64 + 1).wrapping_mul(0x9e37)));
                let result = if allocator {
                    self.fresh += 1;
                    FRESH + self.fresh * 0x1_0000
                } else if sys {
                    match rng.below(4) {
                        0 => 0,
                        1 => (-1i64 - rng.below(40).cast_signed()).cast_unsigned(),
                        _ => rng.below(64),
                    }
                } else {
                    match rng.below(5) {
                        0 => 0,
                        1 => 1,
                        2 => u64::MAX,
                        3 => rng.below(64),
                        _ => rng.next(),
                    }
                };
                self.events.push(Event {
                    to,
                    sys,
                    mask,
                    args,
                    result,
                });
                Some(result)
            }
            Mode::Replay { expected, bindings } => {
                let Some(event) = expected.get(index) else {
                    self.differs = Some(format!("an extra call (call {})", index + 1));
                    return None;
                };
                let arguments = argument_registers
                    .iter()
                    .map(|&register| value_of(register));
                if let Some(what) =
                    self.context
                        .call_differs(event, index, (sys, target), arguments, bindings)
                {
                    self.differs = Some(what);
                    return None;
                }
                self.events.push(event.clone());
                Some(event.result)
            }
            Mode::Open { first } => {
                *first = Some(FirstCall {
                    sys,
                    target,
                    arguments: argument_registers
                        .iter()
                        .map(|&register| value_of(register))
                        .collect(),
                });
                None
            }
        }
    }

    /// The registers `changes` after a call that returned `result`: the
    /// result registers hold it, the others are undefined.
    fn results(&self, changes: &[RegisterId], result: u64) -> Vec<Bitvalue> {
        let first = self.platform.abi.results.first().copied();
        let float = self.platform.abi.float_results.first().copied();
        changes
            .iter()
            .map(|&register| {
                let width = self
                    .platform
                    .abi
                    .declarations
                    .info(register)
                    .map_or(64, |info| info.width);
                if Some(register) == first || Some(register) == float {
                    Bitvalue::defined(
                        Bits::from_u64(64, result)
                            .zext(width.max(64))
                            .extract(0, width),
                    )
                } else {
                    Bitvalue::unknown(width)
                }
            })
            .collect()
    }
}

impl Calls for Handler<'_, '_> {
    fn call(
        &mut self,
        address: u64,
        target: Bitvalue,
        registers: &[Bitvalue],
        changes: &[RegisterId],
    ) -> Option<Vec<Bitvalue>> {
        let result = self.event(address, target, registers, false)?;
        Some(self.results(changes, result))
    }

    fn system_call(
        &mut self,
        address: u64,
        registers: &[Bitvalue],
        changes: &[RegisterId],
    ) -> Option<Vec<Bitvalue>> {
        let number = self
            .platform
            .abi
            .system_call
            .first()
            .and_then(|r| registers.get(usize::from(r.0)))
            .copied()
            .unwrap_or_else(|| Bitvalue::unknown(64));
        let result = self.event(address, number, registers, true)?;
        Some(self.results(changes, result))
    }
}

/// How one state's run ended, before it is compared or recorded.
#[derive(Debug)]
enum Ended {
    /// It returned, with every register's final value.
    Returned(Vec<Bitvalue>),
    /// Otherwise.
    Other(End),
}

/// One state's run.
struct Run {
    /// How it ended, or why the state is skipped.
    end: Result<Ended, Skip>,
    /// What it wrote outside its frame.
    writes: Vec<Written>,
    /// The blocks it entered.
    blocks: BTreeSet<BlockId>,
}

/// A run of bytes a run wrote outside its frame: its first address and
/// the bytes (value, undefined bits).
type Written = (u64, Vec<(u8, u8)>);

/// Why a state did not count.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Skip {
    /// A branch, address or call target depended on undefined bits.
    Undetermined,
    /// More blocks than the fuel.
    Fuel,
    /// Anything else the run could not go through (a landing pad, an
    /// unresolved jump, malformed L1, a return elsewhere).
    Other,
}

/// The registers at entry of the function at `entry` on `spec`.
fn registers(platform: &Platform<'_>, spec: &Spec, entry: u64) -> Vec<Bitvalue> {
    let declarations = platform.abi.declarations;
    let mut registers: Vec<Bitvalue> = declarations
        .registers
        .iter()
        .map(|info| Bitvalue::defined(Bits::from_u64(info.width, 0)))
        .collect();
    let mut set = |register: RegisterId, value: u64| {
        if let Some(slot) = registers.get_mut(usize::from(register.0)) {
            *slot = widened(value, slot.width());
        }
    };
    for (&register, &value) in platform.abi.arguments.iter().zip(&spec.arguments) {
        set(register, value);
    }
    for (&register, &value) in platform.abi.float_arguments.iter().zip(&spec.floats) {
        set(register, value);
    }
    set(platform.abi.stack_pointer, spec.stack);
    if let Some(pc) = platform.program_counter {
        set(pc, entry);
    }
    for &(register, value) in &platform.fixed {
        set(register, value);
    }
    registers
}

/// `value` as a defined value of `width` bits (zero-extended or cut).
fn widened(value: u64, width: u16) -> Bitvalue {
    Bitvalue::defined(
        Bits::from_u64(64, value)
            .zext(width.max(64))
            .extract(0, width),
    )
}

/// Runs `function` (at `entry`) on `spec` with `handler` answering its
/// calls.
fn execute(
    function: &Function,
    world: &dyn World,
    spec: &Spec,
    entry: u64,
    handler: &mut Handler<'_, '_>,
) -> Run {
    let platform = handler.platform;
    let mut memory = Memory {
        world,
        thread: platform.thread,
        thread_words: &platform.thread_words,
        set: BTreeMap::new(),
        writes: BTreeSet::new(),
    };
    for (start, bytes) in &spec.regions {
        for (offset, &byte) in (0u64..).zip(bytes) {
            memory.set.insert(start + offset, (byte, 0));
        }
    }
    for (offset, byte) in (0u64..)
        .zip(RETURN_ADDRESS.to_le_bytes())
        .take(usize::from(platform.link_bytes))
    {
        memory.set.insert(spec.stack + offset, (byte, 0));
    }
    let registers = registers(platform, spec, entry);
    let (outcome, trace) = run_calling(
        function,
        platform.abi.declarations,
        &registers,
        &mut memory,
        platform.fuel,
        handler,
    );
    let context = handler.context;
    let end = match outcome {
        Outcome::Exit {
            returned: true,
            address,
            registers,
        } => {
            if address == RETURN_ADDRESS {
                Ok(Ended::Returned(registers))
            } else {
                Err(Skip::Other)
            }
        }
        Outcome::Exit {
            returned: false,
            address,
            mut registers,
        } => {
            // A tail call: a call whose result is returned.
            let target = Bitvalue::defined(Bits::from_u64(64, address));
            let at = trace
                .blocks
                .last()
                .and_then(|&b| function.block(b))
                .map_or(0, |b| b.end);
            match handler.event(at, target, &registers, false) {
                Some(result) => {
                    for register in platform
                        .abi
                        .results
                        .iter()
                        .chain(&platform.abi.float_results)
                    {
                        if let Some(slot) = registers.get_mut(usize::from(register.0)) {
                            *slot = widened(result, slot.width());
                        }
                    }
                    Ok(Ended::Returned(registers))
                }
                None if handler.differs.is_some() => Ok(Ended::Other(End::Stop)),
                None => Err(Skip::Undetermined),
            }
        }
        Outcome::Trap(trap) => Ok(Ended::Other(End::Trap(format!("{trap:?}")))),
        Outcome::Fault(fault) => Ok(Ended::Other(End::Fault {
            at: context.classify(Bitvalue::defined(Bits::from_u64(64, fault.address))),
            write: fault.write,
        })),
        Outcome::Stop => Ok(Ended::Other(End::Stop)),
        Outcome::Call(_) if handler.differs.is_some() => Ok(Ended::Other(End::Stop)),
        Outcome::Undetermined => Err(Skip::Undetermined),
        Outcome::OutOfFuel => Err(Skip::Fuel),
        Outcome::Call(_) | Outcome::Unresolved(_) | Outcome::Malformed => Err(Skip::Other),
    };
    let mut writes: Vec<Written> = Vec::new();
    for &address in &memory.writes {
        if context.frame(address) {
            continue;
        }
        let byte = memory.set.get(&address).copied().unwrap_or((0, 0xff));
        match writes.last_mut() {
            Some((start, bytes)) if *start + bytes.len() as u64 == address => bytes.push(byte),
            Some(_) | None => writes.push((address, vec![byte])),
        }
    }
    Run {
        end,
        writes,
        blocks: trace.blocks.into_iter().collect(),
    }
}

/// The result value of `registers` by `ret`, and how many low bits of it
/// compare.
fn result(platform: &Platform<'_>, ret: Ret, registers: &[Bitvalue]) -> Option<(Bitvalue, u32)> {
    let integer = platform.abi.results.first();
    let float = platform.abi.float_results.first();
    let (register, bits) = match ret {
        Ret::Void => return None,
        Ret::Int(bytes) => (integer, u32::from(bytes) * 8),
        Ret::Ptr => (integer, 64),
        Ret::Float(bytes) => (float, u32::from(bytes) * 8),
        Ret::Unknown => (integer, 32),
    };
    let value = registers.get(usize::from(register?.0))?;
    Some((value.extract_low(bits), bits))
}

/// The low bits of a value, as a 64-bit value.
trait Low {
    fn extract_low(&self, bits: u32) -> Bitvalue;
}

impl Low for Bitvalue {
    fn extract_low(&self, bits: u32) -> Bitvalue {
        let width = self.width();
        let take = u16::try_from(bits).unwrap_or(64).min(width).min(64);
        let cut = |b: &Bits| b.extract(0, take).zext(64);
        Bitvalue {
            bits: cut(&self.bits),
            undefined: cut(&self.undefined),
        }
    }
}

/// A run of written bytes in hexadecimal, `??` for undefined ones.
fn hex(bytes: &[(u8, u8)]) -> String {
    use std::fmt::Write as _;
    let mut text = String::with_capacity(bytes.len() * 2);
    for &(value, undefined) in bytes {
        if undefined == 0 {
            let _ = write!(text, "{value:02x}");
        } else {
            text.push_str("??");
        }
    }
    text
}

/// What recording a function asks for.
#[derive(Clone, Copy, Debug)]
pub struct Subject<'a> {
    /// Its L1, as decompilation prepares it.
    pub function: &'a Function,
    /// Its entry.
    pub entry: u64,
    /// The argument registers each of its calls compares
    /// ([`Canonical::masks`](crate::Canonical::masks)), by the call's
    /// address.
    pub masks: &'a BTreeMap<u64, u32>,
}

/// The intrinsics whose results decide control in code that dispatches
/// by processor: a function using one is not checked.
const DISPATCH: [&str; 3] = ["cpuid", "xgetbv", "rdtsc"];

/// Whether `function` asks the processor what it is ([`DISPATCH`]).
pub fn dispatches(function: &Function, platform: &Platform<'_>) -> bool {
    function.insts.iter().any(|inst| {
        matches!(&inst.op, Op::Intrinsic { intrinsic, .. }
            if platform
                .abi
                .declarations
                .intrinsic(*intrinsic)
                .is_some_and(|info| DISPATCH.iter().any(|name| info.name.starts_with(name))))
    })
}

/// The recorded run of `subject` on `state` (of `shape`, or the state's
/// own), or why it is skipped; and the blocks it entered.
pub fn record_one(
    subject: Subject<'_>,
    platform: &Platform<'_>,
    world: &dyn World,
    shape: &Shape,
    state: &StateId,
) -> (Result<Recorded, Skip>, BTreeSet<BlockId>) {
    let shape_of = match state {
        StateId::Own(_) => shape,
        StateId::Shaped(_, other) => other,
    };
    let spec = spec(
        shape_of,
        platform.abi.arguments.len(),
        platform.abi.float_arguments.len(),
        state.number(),
    );
    let context = Context {
        world,
        stack: spec.stack,
    };
    let mut handler = Handler {
        context: &context,
        platform,
        mode: Mode::Record {
            masks: subject.masks,
            seed: mix(u64::from(state.number()) ^ 0xca11),
        },
        events: Vec::new(),
        differs: None,
        fresh: 0,
    };
    let run = execute(subject.function, world, &spec, subject.entry, &mut handler);
    let end = match run.end {
        Ok(Ended::Returned(registers)) => match result(platform, shape.ret, &registers) {
            Some((value, _)) => End::Return(Some(context.classify(value))),
            None => End::Return(None),
        },
        Ok(Ended::Other(end)) => end,
        Err(skip) => return (Err(skip), run.blocks),
    };
    let writes = run
        .writes
        .iter()
        .map(|(start, bytes)| {
            (
                context.classify(Bitvalue::defined(Bits::from_u64(64, *start))),
                hex(bytes),
            )
        })
        .collect();
    (
        Ok(Recorded {
            state: state.clone(),
            calls: handler.events,
            end,
            writes,
        }),
        run.blocks,
    )
}

/// `subject`'s recording ([the module](self)): the runs of states 0–47
/// that ran, then states of the coverage pool that enter a block none
/// before did, up to [`STATES_BEFORE_SEPARATORS`]; `None` if fewer than
/// [`MINIMUM`] ran or it dispatches by processor ([`dispatches`]).
pub fn record(
    subject: Subject<'_>,
    platform: &Platform<'_>,
    world: &dyn World,
    shape: &Shape,
) -> Option<Recording> {
    if dispatches(subject.function, platform) {
        return None;
    }
    let mut states = Vec::new();
    let mut covered = BTreeSet::new();
    for number in (0..48).chain(POOL..POOL + POOL_STATES) {
        if states.len() >= STATES_BEFORE_SEPARATORS {
            break;
        }
        let (recorded, blocks) = record_one(subject, platform, world, shape, &StateId::Own(number));
        let new = blocks.iter().any(|block| !covered.contains(block));
        covered.extend(blocks);
        if let Ok(recorded) = recorded
            && (number < 48 || new)
        {
            states.push(recorded);
        }
    }
    (states.len() >= MINIMUM).then(|| Recording {
        generator: STATES,
        shape: shape.clone(),
        states,
    })
}

/// How one recorded state compared.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Compared {
    /// The same calls, end and writes.
    Agrees,
    /// Something differs: what.
    Differs(String),
    /// The unknown's run did not count.
    Skipped(Skip),
}

/// The result of checking an unknown function against a recording.
#[derive(Clone, Debug, Default)]
pub struct Verdict {
    /// How many states agreed.
    pub agreed: usize,
    /// How many were skipped.
    pub skipped: usize,
    /// The first state that differed and how, if one did.
    pub differs: Option<(u32, String)>,
    /// The unknown's blocks the runs entered.
    pub covered: BTreeSet<BlockId>,
    /// The symbols bound to the unknown's addresses.
    pub bindings: Bindings,
    /// Whether the states that agreed were recorded doing different
    /// things (calls and their arguments, end, writes), the results the
    /// calls were given aside: a recording on which the function does
    /// one thing whatever the input (faults at one address, returns one
    /// value, passes one value on and returns what it gets back) says
    /// little of which function it is.
    pub varied: bool,
    /// How many of the states that agreed were recorded faulting (or
    /// trapping on a non-canonical address) before any call or write: a
    /// function reading through its argument first fits those alike,
    /// whatever it does next (a program's function jumping through a
    /// table its argument indexes fits `_isleadbyte_fast_internal`, whose
    /// every state faults reading `**locale`).
    pub faulted: usize,
}

impl Verdict {
    /// Whether the unknown agrees: no state differed and at least
    /// [`MINIMUM`] ran.
    pub fn agrees(&self) -> bool {
        self.differs.is_none() && self.agreed >= MINIMUM
    }
}

/// `unknown` (at `entry`, in `world`) run on `recording`'s states, its
/// calls answered as recorded, compared with the recording; stops at the
/// first state that differs.
pub fn replay(
    unknown: &Function,
    entry: u64,
    platform: &Platform<'_>,
    world: &dyn World,
    recording: &Recording,
) -> Verdict {
    replay_knowing(unknown, entry, platform, world, recording, |_| false)
}

/// [`replay`], not running the states whose index `skipped` holds: those
/// the unknown's [`Opening`] skipped ([`Opening::skipped`]), which its
/// replay skips alike.
pub fn replay_knowing(
    unknown: &Function,
    entry: u64,
    platform: &Platform<'_>,
    world: &dyn World,
    recording: &Recording,
    skipped: impl Fn(usize) -> bool,
) -> Verdict {
    let mut verdict = Verdict::default();
    if recording.generator != STATES {
        verdict.differs = Some((0, format!("states of generator {}", recording.generator)));
        return verdict;
    }
    let mut first: Option<String> = None;
    for (index, recorded) in recording.states.iter().enumerate() {
        if skipped(index) {
            verdict.skipped += 1;
            continue;
        }
        let compared = compare(
            unknown,
            entry,
            platform,
            world,
            &recording.shape,
            recorded,
            &mut verdict,
        );
        match compared {
            Compared::Agrees => {
                verdict.agreed += 1;
                if recorded.calls.is_empty()
                    && recorded.writes.is_empty()
                    && matches!(recorded.end, End::Fault { .. } | End::Trap(_))
                {
                    verdict.faulted += 1;
                }
                let key = informative(recorded);
                match &first {
                    None => first = Some(key),
                    Some(first) => verdict.varied |= *first != key,
                }
            }
            Compared::Skipped(_) => verdict.skipped += 1,
            Compared::Differs(what) => {
                verdict.differs = Some((recorded.state.number(), what));
                break;
            }
        }
    }
    verdict
}

/// What a run did up to its first call ([`Opening`]).
#[derive(Debug)]
enum Opened {
    /// The state is skipped (undetermined, out of fuel, …).
    Skipped,
    /// It called.
    Call(FirstCall),
    /// It ended without calling, having written these runs of memory.
    Ended(Ended, Vec<Written>),
}

/// What a function does on one state up to its first call (or system
/// call), or to its end if it calls nothing ([`opening`]). A replay
/// runs the function alike up to there whatever the recording: calls
/// are answered from the recording only from the first on. So one
/// opening tells, for every recording with that state, whether the
/// function's replay could agree with it there ([`Opening::may_agree`]).
#[derive(Debug)]
pub struct Opening {
    /// The shape of the recordings it is for.
    shape: Shape,
    /// The state.
    state: StateId,
    /// The state's stack pointer (what is the function's own frame).
    stack: u64,
    opened: Opened,
}

/// `unknown` (at `entry`, in `world`) run on `state` of recordings of
/// `shape` up to its first call ([`Opening`]).
pub fn opening(
    unknown: &Function,
    entry: u64,
    platform: &Platform<'_>,
    world: &dyn World,
    shape: &Shape,
    state: &StateId,
) -> Opening {
    let shape_of = match state {
        StateId::Own(_) => shape,
        StateId::Shaped(_, other) => other,
    };
    let spec = spec(
        shape_of,
        platform.abi.arguments.len(),
        platform.abi.float_arguments.len(),
        state.number(),
    );
    let context = Context {
        world,
        stack: spec.stack,
    };
    let mut handler = Handler {
        context: &context,
        platform,
        mode: Mode::Open { first: None },
        events: Vec::new(),
        differs: None,
        fresh: 0,
    };
    let run = execute(unknown, world, &spec, entry, &mut handler);
    let first = match handler.mode {
        Mode::Open { first } => first,
        Mode::Record { .. } | Mode::Replay { .. } => None,
    };
    let opened = match (first, run.end) {
        (Some(call), _) => Opened::Call(call),
        (None, Ok(end)) => Opened::Ended(end, run.writes),
        (None, Err(_)) => Opened::Skipped,
    };
    Opening {
        shape: shape.clone(),
        state: state.clone(),
        stack: spec.stack,
        opened,
    }
}

impl Opening {
    /// Whether the state is skipped: the run neither called nor ended (it
    /// was undetermined, ran out of fuel, …), as its replay does whatever
    /// the recording, since nothing a recording answers was asked.
    pub fn skipped(&self) -> bool {
        matches!(self.opened, Opened::Skipped)
    }

    /// Whether the function's run on `recorded` (a state of a recording of
    /// `own`) could agree with it in a [`replay`]: `false` only when the
    /// replay would find that state differing (another first call, a call
    /// where none was recorded or none where one was, another end or other
    /// writes) whatever the recording's earlier states bound, since
    /// nothing bound accepts what nothing bound refuses. Another state
    /// than this opening's could agree.
    pub fn may_agree(
        &self,
        own: &Shape,
        recorded: &Recorded,
        platform: &Platform<'_>,
        world: &dyn World,
    ) -> bool {
        if recorded.state != self.state || *own != self.shape {
            return true;
        }
        let context = Context {
            world,
            stack: self.stack,
        };
        let mut bindings = Bindings::default();
        match &self.opened {
            Opened::Skipped => true,
            Opened::Call(call) => recorded.calls.first().is_some_and(|event| {
                context
                    .call_differs(
                        event,
                        0,
                        (call.sys, call.target),
                        call.arguments.iter().copied(),
                        &mut bindings,
                    )
                    .is_none()
            }),
            Opened::Ended(end, writes) => {
                if !recorded.calls.is_empty() {
                    return false;
                }
                ending_differs(
                    &context,
                    platform,
                    own,
                    recorded,
                    (end, writes),
                    &mut bindings,
                )
                .is_none()
            }
        }
    }
}

/// One recorded state (of a recording of `shape`) compared with
/// `unknown`'s run on it.
fn compare(
    unknown: &Function,
    entry: u64,
    platform: &Platform<'_>,
    world: &dyn World,
    own: &Shape,
    recorded: &Recorded,
    verdict: &mut Verdict,
) -> Compared {
    let shape = match &recorded.state {
        StateId::Own(_) => own,
        StateId::Shaped(_, shape) => shape,
    };
    let spec = spec(
        shape,
        platform.abi.arguments.len(),
        platform.abi.float_arguments.len(),
        recorded.state.number(),
    );
    let context = Context {
        world,
        stack: spec.stack,
    };
    let mut handler = Handler {
        context: &context,
        platform,
        mode: Mode::Replay {
            expected: &recorded.calls,
            bindings: &mut verdict.bindings,
        },
        events: Vec::new(),
        differs: None,
        fresh: 0,
    };
    let run = execute(unknown, world, &spec, entry, &mut handler);
    let calls = handler.events.len();
    let differs = handler.differs.take();
    let Mode::Replay { bindings, .. } = handler.mode else {
        return Compared::Skipped(Skip::Other);
    };
    verdict.covered.extend(run.blocks);
    if let Some(what) = differs {
        return Compared::Differs(what);
    }
    let end = match run.end {
        Ok(end) => end,
        Err(skip) => return Compared::Skipped(skip),
    };
    if calls != recorded.calls.len() {
        return Compared::Differs(format!("{calls} calls, {} recorded", recorded.calls.len()));
    }
    match ending_differs(
        &context,
        platform,
        own,
        recorded,
        (&end, &run.writes),
        bindings,
    ) {
        Some(what) => Compared::Differs(what),
        None => Compared::Agrees,
    }
}

/// Why a run that made `recorded`'s calls, ended as `end` and wrote
/// `writes` does not end as `recorded` (of a recording of `own`) did, if
/// it does not: another end, or other memory written.
#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "a fault address other than a number compares as recorded"
)]
fn ending_differs(
    context: &Context<'_>,
    platform: &Platform<'_>,
    own: &Shape,
    recorded: &Recorded,
    (end, writes): (&Ended, &[Written]),
    bindings: &mut Bindings,
) -> Option<String> {
    let same_end = match (&recorded.end, end) {
        (End::Return(expected), Ended::Returned(registers)) => {
            match (expected, result(platform, own.ret, registers)) {
                (None, _) => true,
                (Some(expected), Some((value, bits))) => {
                    context.matches(expected, value, bits, bindings)
                }
                (Some(_), None) => false,
            }
        }
        (
            End::Fault { at, write },
            Ended::Other(End::Fault {
                at: actual,
                write: actual_write,
            }),
        ) => {
            write == actual_write
                && match actual {
                    Val::Int(address) => context.matches(
                        at,
                        Bitvalue::defined(Bits::from_u64(64, *address)),
                        64,
                        bindings,
                    ),
                    other => at == other || matches!(at, Val::Any),
                }
        }
        (expected, Ended::Other(actual)) => expected == actual,
        (End::Fault { .. } | End::Trap(_) | End::Stop, Ended::Returned(_)) => false,
    };
    if !same_end {
        return Some(format!("ends otherwise ({} recorded)", recorded.end));
    }
    if writes.len() != recorded.writes.len() {
        return Some(format!(
            "writes {} runs of memory, {} recorded",
            writes.len(),
            recorded.writes.len()
        ));
    }
    for ((start, bytes), (expected_start, expected_bytes)) in writes.iter().zip(&recorded.writes) {
        let actual = hex(bytes);
        let same_bytes = actual.len() == expected_bytes.len()
            && actual
                .as_bytes()
                .chunks(2)
                .zip(expected_bytes.as_bytes().chunks(2))
                .all(|(a, e)| a == e || e == b"??");
        if !same_bytes
            || !context.matches(
                expected_start,
                Bitvalue::defined(Bits::from_u64(64, *start)),
                64,
                bindings,
            )
        {
            return Some(format!("writes other memory at {expected_start}"));
        }
    }
    None
}

/// What a recorded run says of the function, the results its calls were
/// given aside (a result returned as it came back from the last call is
/// written as such): two runs that differ in it did different things.
fn informative(recorded: &Recorded) -> String {
    use core::fmt::Write as _;
    let mut key = String::new();
    for call in &recorded.calls {
        let _ = write!(
            key,
            "{}{}:{:x}:",
            call.to,
            if call.sys { "!" } else { "" },
            call.mask
        );
        for arg in &call.args {
            let _ = write!(key, "{arg},");
        }
        key.push(';');
    }
    let fed = recorded.calls.last().map(|call| call.result);
    // The result as the shape compares it: its low 8, 16, 32 or 64 bits.
    let returned_fed = |value: u64| {
        fed.is_some_and(|fed| {
            [
                u64::from(u8::MAX),
                u64::from(u16::MAX),
                u64::from(u32::MAX),
                u64::MAX,
            ]
            .into_iter()
            .any(|mask| value == fed & mask)
        })
    };
    let fed_back =
        matches!(&recorded.end, End::Return(Some(Val::Int(value))) if returned_fed(*value));
    if fed_back {
        key.push_str("ret:fed");
    } else {
        let _ = write!(key, "{}", recorded.end);
    }
    for (at, bytes) in &recorded.writes {
        let _ = write!(key, ";{at}={bytes}");
    }
    key
}

/// Whether `b` (run as an unknown function) does not do on `recorded`'s
/// state what a function of `shape` is recorded doing there: whether the
/// state is a separator of that function from `b`. `b` is
/// compared as a binary's function is at match time: its callees and
/// globals bound to the recording's symbols at first use, so a state on
/// which they differ only by which symbol they call separates nothing.
pub fn separates(
    b: Subject<'_>,
    shape: &Shape,
    platform: &Platform<'_>,
    world: &dyn World,
    recorded: &Recorded,
) -> bool {
    let mut verdict = Verdict::default();
    let compared = compare(
        b.function,
        b.entry,
        platform,
        world,
        shape,
        recorded,
        &mut verdict,
    );
    matches!(compared, Compared::Differs(_))
}
