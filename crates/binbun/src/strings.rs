//! String literals: NUL-terminated text in the program's data
//! ([`program_data`]: read-only and writable sections that are not code
//! nor what the loader or unwinder read), from two sources joined
//! ([`strings`]):
//!
//! - **Referred to**: the start of every address a reference takes or a
//!   pointer in data holds ([`Kind::Address`], [`Kind::Pointer`]; a load
//!   or store alone says nothing about text) that starts text and a NUL,
//!   of any length from one character. A reference into the middle of
//!   text (a compiler's suffix sharing, `"bar"` inside `"foobar"`) is a
//!   string of its own there. Inside a data object of known size, only one
//!   starting at the object and ending within it is (an object's leading
//!   bytes that happen to be text are not). In writable data, one needs
//!   as many characters as a scanned one: a variable whose address is
//!   taken is more often a number than text.
//! - **Scanned**: every maximal run of at least `min` characters ending in
//!   a NUL, whether referred to or not. binutils `strings` takes runs of
//!   four by default; that is the default here ([`MIN_SCANNED`]): shorter
//!   NUL-terminated runs are mostly bytes of numbers (a little-endian
//!   `0x00636261` is `"abc"`).
//!
//! Text is UTF-8 (valid only) or UTF-16LE (Windows' wide strings, 2-byte
//! aligned): characters that print, and the whitespace and escape
//! characters text holds (tab, newline, carriage return, vertical tab,
//! form feed, escape), never other control characters. binutils
//! `strings` takes printable ASCII and tab only, so every NUL-terminated
//! run it finds is inside one found here. A UTF-16 string is Latin-1 only
//! (every unit's high byte zero): nearly any two bytes are some printable
//! character, and narrow text read two bytes at a time is a run of CJK
//! ideographs, so wider wide text cannot be told from other data (it is
//! rare outside resources). Where both encodings read text at a
//! referred-to address, the longer reading wins (UTF-8 on a tie): an
//! ASCII wide string is one character of UTF-8. A wide string of one
//! character is not taken (it is as much a small number).
//!
//! Bytes the dynamic loader writes ([`Image::fixups`]: relocated
//! pointers, import slots) are never text, whatever the file holds there
//! (a pointer's low bytes often read as a character or two).
//!
//! Compilers put strings among the code too (MSVC ends a driver's `.text`
//! with its wide strings). Text in code whose address is computed or
//! stored, and that is no function's code ([`crate::cfg::Program::data`],
//! read by [`code_text`]), is program data as well.

use std::collections::BTreeMap;

use binbun_decompile::data::Data as _;
use binbun_loader::Image;
use binbun_semantics::core::Memory as _;

use crate::data::{ImageData, program_data};
use crate::memory::ImageMemory;
use crate::references::{Kind, References};

/// The fewest characters of a string found by scanning, by default: as
/// binutils `strings`.
pub const MIN_SCANNED: usize = 4;

/// The most bytes a referred-to string has before its NUL.
const MAX_REFERRED: usize = 1 << 16;

/// The most bytes text in code ([`code_text`]) has, its NUL included.
pub const MAX_CODE_TEXT: usize = 4096;

/// How a string's characters are stored.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Encoding {
    /// UTF-8, ending in a NUL byte.
    Utf8,
    /// UTF-16 little-endian, ending in a NUL unit.
    Utf16,
}

impl Encoding {
    /// The size of its NUL in bytes.
    pub const fn unit(self) -> u64 {
        match self {
            Self::Utf8 => 1,
            Self::Utf16 => 2,
        }
    }
}

/// A string literal of the image's data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Literal {
    /// Its first byte.
    pub address: u64,
    /// How it is stored.
    pub encoding: Encoding,
    /// Its text, without the NUL.
    pub text: String,
    /// Its bytes before the NUL.
    pub bytes: u64,
    /// How many references there are to its first byte, of any kind.
    pub references: usize,
    /// Whether the program cannot change it (a read-only section, or RELRO).
    pub read_only: bool,
}

/// The string literals of `image`'s program data, by address: those its
/// `references` refer to, and those of at least `min` characters found by
/// scanning; `data` tells the extent of its objects.
pub fn strings(
    image: &Image<'_>,
    references: &References,
    data: &ImageData<'_>,
    min: usize,
) -> Vec<Literal> {
    let memory = ImageMemory::new(image);
    let mut ranges: Vec<(u64, u64)> = program_data(image)
        .into_iter()
        .map(|section| (section.start, section.size))
        .chain(
            data.code_data()
                .iter()
                .map(|(&start, &end)| (start, end - start)),
        )
        .collect();
    ranges.sort_unstable();
    let sections: Vec<(u64, Vec<u8>)> = ranges
        .into_iter()
        .map(|(start, size)| {
            let mut bytes = vec![0; usize::try_from(size).unwrap_or(0)];
            let read = image.read(start, &mut bytes).unwrap_or(0);
            bytes.truncate(read);
            (start, bytes)
        })
        .collect();
    let mut found: BTreeMap<u64, (Encoding, String, u64)> = BTreeMap::new();
    let mut previous = None;
    for reference in references.all() {
        let address = reference.target;
        if previous == Some(address) || !matches!(reference.kind, Kind::Address | Kind::Pointer(_))
        {
            continue;
        }
        previous = Some(address);
        if let Some(string) = referred(&sections, data, address) {
            // A writable variable whose address is taken is more often a
            // number than text: there, a string needs `min` characters.
            let end = address + string.2 + string.0.unit();
            if !memory.unchanging(address, end) && string.1.chars().count() < min {
                continue;
            }
            found.insert(address, string);
        }
    }
    for (start, bytes) in &sections {
        for (offset, end, text) in scan_utf8(bytes, min) {
            let bytes = (end - offset) as u64;
            let string = (Encoding::Utf8, text, bytes);
            found.entry(start + offset as u64).or_insert(string);
        }
        let skip = usize::from(!start.is_multiple_of(2));
        for (offset, end, text) in scan_utf16(bytes.get(skip..).unwrap_or_default(), min) {
            let bytes = (end - offset) as u64;
            let string = (Encoding::Utf16, text, bytes);
            found
                .entry(start + (skip + offset) as u64)
                .or_insert(string);
        }
    }
    found
        .into_iter()
        .filter_map(|(address, (encoding, text, bytes))| {
            let end = address + bytes + encoding.unit();
            (!memory.written(address, end)).then(|| Literal {
                address,
                encoding,
                text,
                bytes,
                references: references.to(address).len(),
                read_only: memory.unchanging(address, end),
            })
        })
        .collect()
}

/// The string at `address`, referred to, in one of `sections` (start,
/// bytes): its encoding, text and bytes before the NUL; inside an object
/// of `data`, only one that starts it and ends within it.
fn referred(
    sections: &[(u64, Vec<u8>)],
    data: &ImageData<'_>,
    address: u64,
) -> Option<(Encoding, String, u64)> {
    let index = sections
        .partition_point(|(start, _)| *start <= address)
        .checked_sub(1)?;
    let (start, bytes) = sections.get(index)?;
    let offset = usize::try_from(address - start).ok()?;
    let bytes = bytes.get(offset..)?;
    let bytes = bytes.get(..MAX_REFERRED.min(bytes.len()))?;
    let (encoding, text, length) = text_at(address, bytes)?;
    if let Some(object) = data.object(address) {
        let end = length + encoding.unit();
        if object.start != address || end > object.size {
            return None;
        }
    }
    Some((encoding, text, length))
}

/// The string `bytes` (at `address`) start with, as a referred-to one is
/// read: its encoding (UTF-16 where that reads more characters, at an even
/// address, and more than one), text and bytes before the NUL; `None` if
/// they start no text ending in a NUL.
pub fn text_at(address: u64, bytes: &[u8]) -> Option<(Encoding, String, u64)> {
    let utf8 = utf8_at(bytes);
    let utf16 = if address.is_multiple_of(2) {
        utf16_at(bytes)
    } else {
        None
    };
    let characters =
        |text: &Option<(String, usize)>| text.as_ref().map_or(0, |(text, _)| text.chars().count());
    let wide = characters(&utf16);
    let (encoding, (text, length)) = if wide > 1 && wide > characters(&utf8) {
        (Encoding::Utf16, utf16?)
    } else {
        (Encoding::Utf8, utf8?)
    };
    Some((encoding, text, length as u64))
}

/// The string `bytes` (at `address`, in code) start with, if they read as
/// text rather than code ([`crate::cfg::Resolver::data`]): its encoding
/// and bytes before the NUL, as [`text_at`] reads it, of at least
/// [`MIN_SCANNED`] characters, all printable ASCII, tab, newline or
/// carriage return. Machine code seldom runs into a NUL after four such
/// bytes (x86's prologues reach a ModRM byte above `0x7f` first, an
/// AArch64 instruction's high byte is rarely ASCII), and in UTF-16 every
/// other byte would have to be zero.
pub fn code_text(address: u64, bytes: &[u8]) -> Option<(Encoding, u64)> {
    let (encoding, text, length) = text_at(address, bytes)?;
    let ascii = text
        .chars()
        .all(|c| matches!(c, ' '..='~' | '\t' | '\n' | '\r'));
    (ascii && text.chars().count() >= MIN_SCANNED).then_some((encoding, length))
}

/// Whether `c` is a character of text: one that prints, or tab, newline,
/// carriage return, vertical tab, form feed or escape.
fn printable(c: char) -> bool {
    matches!(
        c,
        ' '..='~' | '\t' | '\n' | '\r' | '\u{b}' | '\u{c}' | '\u{1b}'
    ) || (!c.is_ascii() && !c.is_control())
}

/// The UTF-8 text at the start of `bytes` up to a NUL, and its length in
/// bytes, if it has at least one character and all are text.
fn utf8_at(bytes: &[u8]) -> Option<(String, usize)> {
    let end = bytes.iter().position(|&byte| byte == 0)?;
    let text = std::str::from_utf8(bytes.get(..end)?).ok()?;
    (end > 0 && text.chars().all(printable)).then(|| (text.to_owned(), end))
}

/// The Latin-1 UTF-16LE text at the start of `bytes` up to a NUL unit,
/// and its length in bytes, if it has at least one character and all are
/// text.
fn utf16_at(bytes: &[u8]) -> Option<(String, usize)> {
    let mut text = String::new();
    for &[low, high] in bytes.as_chunks::<2>().0 {
        match (low, high) {
            (0, 0) => {
                let length = 2 * text.chars().count();
                return (length > 0).then_some((text, length));
            }
            (low, 0) if printable(char::from(low)) => text.push(char::from(low)),
            _ => return None,
        }
    }
    None
}

/// The maximal runs of at least `min` UTF-8 characters of text ending in
/// a NUL in `bytes`: start, end (the NUL) and text.
fn scan_utf8(bytes: &[u8], min: usize) -> Vec<(usize, usize, String)> {
    let mut runs = Vec::new();
    let (mut start, mut characters) = (0, 0);
    let mut at = 0;
    while let Some(&byte) = bytes.get(at) {
        if byte == 0 {
            if characters >= min.max(1)
                && let Some(text) = bytes
                    .get(start..at)
                    .and_then(|b| std::str::from_utf8(b).ok())
            {
                runs.push((start, at, text.to_owned()));
            }
            at += 1;
            (start, characters) = (at, 0);
            continue;
        }
        let width = match byte {
            0x00..=0x7f => 1,
            0xc2..=0xdf => 2,
            0xe0..=0xef => 3,
            0xf0..=0xf4 => 4,
            0x80..=0xc1 | 0xf5..=0xff => 0,
        };
        let character = bytes
            .get(at..at + width)
            .and_then(|b| std::str::from_utf8(b).ok())
            .and_then(|text| text.chars().next())
            .filter(|&c| width > 0 && printable(c));
        if character.is_some() {
            characters += 1;
            at += width;
        } else {
            at += 1;
            (start, characters) = (at, 0);
        }
    }
    runs
}

/// The maximal runs of at least `min` Latin-1 UTF-16LE characters of
/// text ending in a NUL unit in `bytes` (from its start, 2-byte aligned):
/// start, end (the NUL) and text.
fn scan_utf16(bytes: &[u8], min: usize) -> Vec<(usize, usize, String)> {
    let mut runs = Vec::new();
    let mut text = String::new();
    let mut start = 0;
    for (index, &[low, high]) in bytes.as_chunks::<2>().0.iter().enumerate() {
        let at = 2 * index;
        let character = char::from(low);
        if high == 0 && low == 0 {
            if text.chars().count() >= min.max(1) {
                runs.push((start, at, std::mem::take(&mut text)));
            }
            text.clear();
            start = at + 2;
        } else if high == 0 && printable(character) {
            text.push(character);
        } else {
            text.clear();
            start = at + 2;
        }
    }
    runs
}
