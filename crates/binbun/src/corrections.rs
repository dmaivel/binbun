//! The user's corrections of what recovery found ([`Corrections`]), as
//! the usual disassembler commands make them: code at an address (`C`),
//! bytes undefined (`U`), data of a width or type (`D`, `A`, `*`), a
//! function at an address (`P`), a function's end (Edit Function) and a
//! function deleted.
//!
//! They are inputs to recovery, never edits of its result: a database
//! recovered with them ([`crate::Database::with_corrections`]) takes them
//! as seeds and constraints ([`Corrections::seeds`]: [`Seed::Flow`],
//! [`Seed::NotCode`], [`Seed::Function`] of [`SeedKind::User`],
//! [`Seed::End`], [`Seed::NoFunction`]), and with none it is the database
//! recovered without. The listing reads the data items
//! ([`Corrections::items`]); [`check_item`] and [`check_bounds`] say why one
//! cannot apply to a program as recovered.

use std::collections::{BTreeMap, BTreeSet};

use binbun_aarch64::{AArch64, Mode as AArch64Mode};
use binbun_isa::{Architecture as _, Instruction as _};
use binbun_loader::{Image, Machine};
use binbun_semantics::core::Memory as _;
use binbun_x86::X86;

use crate::analysis::x86_mode;
use crate::cfg::{Program, Seed, SeedKind};
use crate::strings::{Encoding, text_at};

/// What the units of a data item are.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Unit {
    /// One byte (`db`).
    Byte,
    /// Two bytes (`dw`).
    Word,
    /// Four bytes (`dd`).
    Dword,
    /// Eight bytes (`dq`).
    Qword,
    /// A C string's bytes, its NUL the last.
    String,
    /// A UTF-16 string's units, its NUL the last.
    Utf16,
}

impl Unit {
    /// Its size in bytes.
    pub const fn width(self) -> u64 {
        match self {
            Self::Byte | Self::String => 1,
            Self::Word | Self::Utf16 => 2,
            Self::Dword => 4,
            Self::Qword => 8,
        }
    }

    /// Its name in a project file.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Byte => "byte",
            Self::Word => "word",
            Self::Dword => "dword",
            Self::Qword => "qword",
            Self::String => "string",
            Self::Utf16 => "utf16",
        }
    }

    /// The unit `name` names ([`Self::name`]).
    pub fn named(name: &str) -> Option<Self> {
        [
            Self::Byte,
            Self::Word,
            Self::Dword,
            Self::Qword,
            Self::String,
            Self::Utf16,
        ]
        .into_iter()
        .find(|unit| unit.name() == name)
    }

    /// Whether it is a string's.
    pub const fn is_string(self) -> bool {
        matches!(self, Self::String | Self::Utf16)
    }

    /// The width `D` goes to from this one: byte, word, dword, qword,
    /// byte again (a string's goes to byte).
    #[must_use]
    pub const fn cycled(self) -> Self {
        match self {
            Self::Byte => Self::Word,
            Self::Word => Self::Dword,
            Self::Dword => Self::Qword,
            Self::Qword | Self::String | Self::Utf16 => Self::Byte,
        }
    }
}

/// A data item: `count` units (an array if more than one; a string's
/// units, its NUL included).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Data {
    /// Its units.
    pub unit: Unit,
    /// How many.
    pub count: u64,
}

impl Data {
    /// Its size in bytes.
    pub const fn size(self) -> u64 {
        self.unit.width().saturating_mul(self.count)
    }

    /// The string `bytes` (at `address`) start with, C or UTF-16 by what
    /// the bytes are (as a referred-to literal is read), its NUL included;
    /// `None` if they start no text ending in a NUL.
    pub fn string(address: u64, bytes: &[u8]) -> Option<Self> {
        let (encoding, _, length) = text_at(address, bytes)?;
        Some(match encoding {
            Encoding::Utf8 => Self {
                unit: Unit::String,
                count: length + 1,
            },
            Encoding::Utf16 => Self {
                unit: Unit::Utf16,
                count: length / 2 + 1,
            },
        })
    }
}

/// What the user says the bytes at an address are.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Item {
    /// Code, decoded and followed from there (`C`).
    Code,
    /// Bytes nothing types (`U`): no code, no data item.
    Undefined {
        /// How many.
        size: u64,
    },
    /// A data item (`D`, `A`, `*`).
    Data(Data),
}

impl Item {
    /// The bytes it covers (code: its first byte; what follows is what the
    /// code decodes to).
    pub const fn size(self) -> u64 {
        match self {
            Self::Code => 1,
            Self::Undefined { size } => size,
            Self::Data(data) => data.size(),
        }
    }
}

/// What the user says of a function.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Bounds {
    /// A function starts here (`P`), ending at `end` if given (Edit
    /// Function): control leaving its range is a tail call.
    Function {
        /// The address after its last byte.
        end: Option<u64>,
    },
    /// No function starts here (Delete Function); its code stays code.
    Deleted,
}

/// The user's corrections: items by address (their bytes disjoint),
/// functions' bounds by entry, and the functions known not to return
/// (a library function a signature identified, whose declaration says
/// so).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Corrections {
    items: BTreeMap<u64, Item>,
    functions: BTreeMap<u64, Bounds>,
    no_return: BTreeSet<u64>,
}

impl Corrections {
    /// Whether there are none.
    pub fn is_empty(&self) -> bool {
        self.items.is_empty() && self.functions.is_empty() && self.no_return.is_empty()
    }

    /// The items, by address.
    pub fn items(&self) -> &BTreeMap<u64, Item> {
        &self.items
    }

    /// The functions' bounds, by entry.
    pub fn functions(&self) -> &BTreeMap<u64, Bounds> {
        &self.functions
    }

    /// The item starting at `address`.
    pub fn item(&self, address: u64) -> Option<Item> {
        self.items.get(&address).copied()
    }

    /// The item holding `address`, and its start.
    pub fn holding(&self, address: u64) -> Option<(u64, Item)> {
        let (&start, &item) = self.items.range(..=address).next_back()?;
        (address < start.saturating_add(item.size())).then_some((start, item))
    }

    /// The bounds of the function at `entry`.
    pub fn bounds(&self, entry: u64) -> Option<Bounds> {
        self.functions.get(&entry).copied()
    }

    /// The entries of the functions known not to return.
    pub fn no_return(&self) -> &BTreeSet<u64> {
        &self.no_return
    }

    /// Says whether the function at `entry` is known not to return.
    pub fn set_no_return(&mut self, entry: u64, no_return: bool) {
        if no_return {
            self.no_return.insert(entry);
        } else {
            self.no_return.remove(&entry);
        }
    }

    /// Says the bytes at `address` are `item` in place of the items whose
    /// bytes it overlaps (`None`: no longer the one starting there).
    pub fn set_item(&mut self, address: u64, item: Option<Item>) {
        let Some(item) = item else {
            self.items.remove(&address);
            return;
        };
        let end = address.saturating_add(item.size());
        // Disjoint items end in the order they start: those ending after
        // `address`, from the last before `end` back, overlap it.
        let overlapping: Vec<u64> = self
            .items
            .range(..end)
            .rev()
            .take_while(|&(&start, &other)| start.saturating_add(other.size()) > address)
            .map(|(&start, _)| start)
            .collect();
        for start in overlapping {
            self.items.remove(&start);
        }
        self.items.insert(address, item);
    }

    /// Says `bounds` of the function at `entry` (`None`: nothing).
    pub fn set_bounds(&mut self, entry: u64, bounds: Option<Bounds>) {
        match bounds {
            Some(bounds) => self.functions.insert(entry, bounds),
            None => self.functions.remove(&entry),
        };
    }

    /// The bytes no instruction may overlap: the items undefined and the
    /// data items, as `(start, end)` by start.
    pub fn not_code(&self) -> impl Iterator<Item = (u64, u64)> + '_ {
        self.items.iter().filter_map(|(&start, &item)| match item {
            Item::Code => None,
            Item::Undefined { .. } | Item::Data(_) => {
                Some((start, start.saturating_add(item.size())))
            }
        })
    }

    /// Recovery's seeds for them: [`Seed::Flow`] for code,
    /// [`Seed::NotCode`] for bytes undefined or data, [`Seed::Function`]
    /// ([`SeedKind::User`]) and [`Seed::End`] for a function, and
    /// [`Seed::NoFunction`] with [`Seed::Flow`] for one deleted (its code
    /// stays code).
    pub fn seeds(&self) -> Vec<Seed> {
        let mut seeds = Vec::new();
        for (&start, &item) in &self.items {
            seeds.push(match item {
                Item::Code => Seed::Flow(start),
                Item::Undefined { .. } | Item::Data(_) => Seed::NotCode {
                    start,
                    end: start.saturating_add(item.size()),
                },
            });
        }
        for (&entry, &bounds) in &self.functions {
            match bounds {
                Bounds::Function { end } => {
                    seeds.push(Seed::Function(entry, SeedKind::User));
                    if let Some(end) = end {
                        seeds.push(Seed::End {
                            function: entry,
                            end,
                        });
                    }
                }
                Bounds::Deleted => {
                    seeds.push(Seed::NoFunction(entry));
                    seeds.push(Seed::Flow(entry));
                }
            }
        }
        seeds
    }
}

/// The length of the instruction at `address` of `image`'s code, if it is
/// executable and decodes.
pub fn instruction_length(image: &Image<'_>, address: u64) -> Option<u64> {
    let memory = image.code_view();
    if !memory.region(address)?.permissions.execute {
        return None;
    }
    let mut buffer = [0u8; 16];
    let read = memory.read(address, &mut buffer).ok()?;
    let bytes = buffer.get(..read)?;
    let length = match image.machine {
        Machine::Aarch64 => AArch64.decode(bytes, AArch64Mode::A64).ok()?.len(),
        Machine::X86 | Machine::X86_64 | Machine::Arm | Machine::Other => {
            X86.decode(bytes, x86_mode(image.machine).ok()?).ok()?.len()
        }
    };
    Some(length as u64)
}

/// The start of the recovered instruction `address` is inside of (not at
/// its start), if any.
fn inside_instruction(image: &Image<'_>, program: &Program, address: u64) -> Option<u64> {
    let block = program.blocks.get(program.block_containing(address)?)?;
    let mut pc = block.start;
    while pc < address {
        let next = pc.checked_add(instruction_length(image, pc)?)?;
        if next > address {
            return Some(pc);
        }
        pc = next;
    }
    None
}

/// Whether `address` is mapped in `image`.
fn mapped(image: &Image<'_>, address: u64) -> bool {
    image
        .segments
        .iter()
        .any(|segment| segment.start <= address && address < segment.end())
}

/// Why code cannot start at `address` of `program` (recovered from
/// `image`): not executable, inside a recovered instruction, or no
/// instruction decodes there.
fn check_code(image: &Image<'_>, program: &Program, address: u64) -> Result<(), String> {
    if !image.is_code(address) {
        return Err(format!("{address:#x} is not in executable code"));
    }
    if let Some(start) = inside_instruction(image, program, address) {
        return Err(format!(
            "{address:#x} is inside the instruction at {start:#x}"
        ));
    }
    if instruction_length(image, address).is_none() {
        return Err(format!("no instruction decodes at {address:#x}"));
    }
    Ok(())
}

/// Why `item` cannot be what the bytes at `address` of `program`
/// (recovered from `image`) are: code where [`check_code`] says, bytes
/// not all mapped, none, or a string that does not end in its NUL.
///
/// # Errors
///
/// The reason, for the user.
pub fn check_item(
    image: &Image<'_>,
    program: &Program,
    address: u64,
    item: Item,
) -> Result<(), String> {
    match item {
        Item::Code => check_code(image, program, address),
        Item::Undefined { size: 0 } => Err("no bytes to undefine".to_owned()),
        Item::Data(Data { count: 0, .. }) => Err("an array of no elements".to_owned()),
        Item::Undefined { .. } | Item::Data(_) => {
            let last = address.saturating_add(item.size()) - 1;
            if !mapped(image, address) || !mapped(image, last) {
                return Err(format!(
                    "{address:#x}..{:#x} is not all mapped",
                    last.saturating_add(1)
                ));
            }
            Ok(())
        }
    }
}

/// Why `bounds` cannot be the function at `entry`'s in `program`
/// (recovered from `image`): a function where code cannot start
/// ([`check_code`]), an end not after its entry, inside an instruction
/// or past another function's entry; deleting where no function starts.
///
/// # Errors
///
/// The reason, for the user.
pub fn check_bounds(
    image: &Image<'_>,
    program: &Program,
    entry: u64,
    bounds: Bounds,
) -> Result<(), String> {
    match bounds {
        Bounds::Deleted => program
            .function_at(entry)
            .map(|_| ())
            .ok_or_else(|| format!("no function starts at {entry:#x}")),
        Bounds::Function { end } => {
            check_code(image, program, entry)?;
            let Some(end) = end else {
                return Ok(());
            };
            if end <= entry {
                return Err(format!("its end {end:#x} is not after its start"));
            }
            if let Some(other) = program
                .functions
                .values()
                .map(|function| function.entry)
                .find(|&other| entry < other && other < end)
            {
                return Err(format!("it would overlap the function at {other:#x}"));
            }
            if let Some(start) = inside_instruction(image, program, end) {
                return Err(format!(
                    "its end {end:#x} is inside the instruction at {start:#x}"
                ));
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn data(unit: Unit, count: u64) -> Item {
        Item::Data(Data { unit, count })
    }

    #[test]
    fn an_item_replaces_those_it_overlaps_and_no_other() {
        let mut c = Corrections::default();
        c.set_item(0x10, Some(data(Unit::Dword, 1)));
        c.set_item(0x14, Some(data(Unit::Byte, 1)));
        c.set_item(0x20, Some(Item::Code));
        // A qword at 0x12 overlaps the dword (from before) and the byte.
        c.set_item(0x12, Some(data(Unit::Qword, 1)));
        assert_eq!(
            c.items().iter().map(|(&a, &i)| (a, i)).collect::<Vec<_>>(),
            [(0x12, data(Unit::Qword, 1)), (0x20, Item::Code)]
        );
        assert_eq!(c.holding(0x19), Some((0x12, data(Unit::Qword, 1))));
        assert_eq!(c.holding(0x1a), None);
        c.set_item(0x12, None);
        assert_eq!(c.items().len(), 1);
    }

    #[test]
    fn seeds_say_what_recovery_takes() {
        let mut c = Corrections::default();
        c.set_item(0x10, Some(Item::Code));
        c.set_item(0x20, Some(Item::Undefined { size: 3 }));
        c.set_item(0x30, Some(data(Unit::Word, 4)));
        c.set_bounds(0x40, Some(Bounds::Function { end: Some(0x48) }));
        c.set_bounds(0x50, Some(Bounds::Deleted));
        assert_eq!(
            c.seeds(),
            [
                Seed::Flow(0x10),
                Seed::NotCode {
                    start: 0x20,
                    end: 0x23
                },
                Seed::NotCode {
                    start: 0x30,
                    end: 0x38
                },
                Seed::Function(0x40, SeedKind::User),
                Seed::End {
                    function: 0x40,
                    end: 0x48
                },
                Seed::NoFunction(0x50),
                Seed::Flow(0x50),
            ]
        );
        assert_eq!(Corrections::default().seeds(), []);
    }

    #[test]
    fn a_string_is_c_or_utf16_by_its_bytes() {
        assert_eq!(
            Data::string(0x1000, b"hi\0rest"),
            Some(Data {
                unit: Unit::String,
                count: 3
            })
        );
        assert_eq!(
            Data::string(0x1000, b"h\0i\0!\0\0\0"),
            Some(Data {
                unit: Unit::Utf16,
                count: 4
            })
        );
        // At an odd address it can only be C (one character, `h`).
        assert_eq!(
            Data::string(0x1001, b"h\0i\0!\0\0\0").map(|d| d.unit),
            Some(Unit::String)
        );
        assert_eq!(Data::string(0x1000, b"\x01\x02\0"), None);
    }

    #[test]
    fn d_cycles_the_widths() {
        let mut unit = Unit::Byte;
        let mut seen = Vec::new();
        for _ in 0..5 {
            seen.push(unit);
            unit = unit.cycled();
        }
        assert_eq!(
            seen,
            [Unit::Byte, Unit::Word, Unit::Dword, Unit::Qword, Unit::Byte]
        );
        assert_eq!(Unit::String.cycled(), Unit::Byte);
    }
}
