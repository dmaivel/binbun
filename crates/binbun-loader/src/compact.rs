//! Mach-O compact unwind tables (`__unwind_info`, version 1, as Apple's
//! `<mach-o/compact_unwind_encoding.h>` lays them out): per function, a
//! 32-bit encoding of how to unwind it (or that its `__eh_frame` entry
//! says), its personality routine and its exception table (LSDA).
//!
//! A first-level index splits the image's code into second-level pages,
//! each a list of function starts with their encodings, regular (an
//! offset and an encoding per entry) or compressed (an offset from the
//! index entry's function in the low 24 bits, and an index into the common
//! encodings or the page's own in the high 8). The index's last entry
//! only marks where the last function ends. Function offsets count from
//! the image's start (its Mach-O header).

/// An entry's encoding: its code is no function's start (code a compiler
/// split off one).
pub const NOT_FUNCTION_START: u32 = 0x8000_0000;
/// The bits of an entry's encoding that number its personality routine
/// (from 1; 0: none).
const PERSONALITY: u32 = 0x3000_0000;
/// A second-level page of `(offset, encoding)` pairs.
const REGULAR: u32 = 2;
/// A second-level page of compressed entries.
const COMPRESSED: u32 = 3;

/// One entry: the code from its start to the next entry's (or the table's
/// end) unwinds as `encoding` says.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entry {
    /// Its first address.
    pub start: u64,
    /// Its encoding (0: no unwind information).
    pub encoding: u32,
}

impl Entry {
    /// The number of its personality routine in [`Table::personalities`]
    /// (from 1), if it has one.
    pub const fn personality(self) -> Option<u32> {
        match (self.encoding & PERSONALITY) >> PERSONALITY.trailing_zeros() {
            0 => None,
            index => Some(index),
        }
    }
}

/// A compact unwind table.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Table {
    /// Its entries, by address.
    pub entries: Vec<Entry>,
    /// Where the last entry's code ends.
    pub end: u64,
    /// The exception tables: a function's start and its table's address.
    pub lsdas: Vec<(u64, u64)>,
    /// The personality routines: each the address of the slot holding
    /// its address (a `__got` entry).
    pub personalities: Vec<u64>,
}

/// The table `bytes` (the section's contents) of an image starting at
/// `base`; what is damaged.
///
/// # Errors
///
/// Its header, index or a page does not fit, or its version is not 1.
pub fn parse(bytes: &[u8], base: u64) -> Result<Table, String> {
    let header = |index: usize| word(bytes, index * 4);
    if header(0)? != 1 {
        return Err(format!("version {} (only 1 is read)", header(0)?));
    }
    let (common_offset, common_count) = (header(1)?, header(2)?);
    let (personality_offset, personality_count) = (header(3)?, header(4)?);
    let (index_offset, index_count) = (header(5)?, header(6)?);
    let common: Vec<u32> = (0..common_count)
        .map(|i| word(bytes, at(common_offset, i, 4)))
        .collect::<Result<_, _>>()?;
    let personalities = (0..personality_count)
        .map(|i| Ok(offset(base, word(bytes, at(personality_offset, i, 4))?)))
        .collect::<Result<_, String>>()?;
    let index = |i: u32, field: u32| word(bytes, at(index_offset, i, 12) + field as usize * 4);
    let mut table = Table {
        personalities,
        ..Table::default()
    };
    let last = index_count.checked_sub(1).ok_or("no index entries")?;
    for i in 0..last {
        let function = index(i, 0)?;
        let page = index(i, 1)?;
        if page != 0 {
            second_level(bytes, page as usize, function, &common, base, &mut table)
                .map_err(|damage| format!("page at {page:#x}: {damage}"))?;
        }
    }
    table.end = offset(base, index(last, 0)?);
    // The exception tables of every index entry, one array.
    let (first, after) = (index(0, 2)?, index(last, 2)?);
    for i in 0..after.saturating_sub(first) / 8 {
        let function = word(bytes, at(first, i, 8))?;
        let lsda = word(bytes, at(first, i, 8) + 4)?;
        table
            .lsdas
            .push((offset(base, function), offset(base, lsda)));
    }
    Ok(table)
}

/// The entries of the second-level page at `page`, whose index entry's
/// function is at offset `function`, into `table`.
fn second_level(
    bytes: &[u8],
    page: usize,
    function: u32,
    common: &[u32],
    base: u64,
    table: &mut Table,
) -> Result<(), String> {
    let kind = word(bytes, page)?;
    let entries = page + usize::from(half(bytes, page + 4)?);
    let count = u32::from(half(bytes, page + 6)?);
    match kind {
        REGULAR => {
            for i in 0..count {
                let record = at_usize(entries, i, 8);
                table.entries.push(Entry {
                    start: offset(base, word(bytes, record)?),
                    encoding: word(bytes, record + 4)?,
                });
            }
        }
        COMPRESSED => {
            let encodings = page + usize::from(half(bytes, page + 8)?);
            for i in 0..count {
                let entry = word(bytes, at_usize(entries, i, 4))?;
                let number = entry >> 24;
                let encoding = if let Some(&encoding) = common.get(number as usize) {
                    encoding
                } else {
                    let own = number as usize - common.len();
                    word(bytes, encodings + own * 4)?
                };
                table.entries.push(Entry {
                    start: offset(base, function).saturating_add(u64::from(entry & 0x00ff_ffff)),
                    encoding,
                });
            }
        }
        other => return Err(format!("kind {other}")),
    }
    Ok(())
}

/// The offset of the `index`th of the `size`-byte records at `start`.
fn at(start: u32, index: u32, size: usize) -> usize {
    at_usize(start as usize, index, size)
}

/// The address `offset` bytes past `base`.
fn offset(base: u64, offset: u32) -> u64 {
    base.saturating_add(u64::from(offset))
}

/// The offset of the `index`th of the `size`-byte records at `start`.
fn at_usize(start: usize, index: u32, size: usize) -> usize {
    start.saturating_add((index as usize).saturating_mul(size))
}

/// The little-endian 32-bit word at `offset`.
fn word(bytes: &[u8], offset: usize) -> Result<u32, String> {
    bytes
        .get(offset..offset.saturating_add(4))
        .and_then(|b| b.try_into().ok())
        .map(u32::from_le_bytes)
        .ok_or_else(|| format!("offset {offset:#x} past its end"))
}

/// The little-endian 16-bit half-word at `offset`.
fn half(bytes: &[u8], offset: usize) -> Result<u16, String> {
    bytes
        .get(offset..offset.saturating_add(2))
        .and_then(|b| b.try_into().ok())
        .map(u16::from_le_bytes)
        .ok_or_else(|| format!("offset {offset:#x} past its end"))
}
