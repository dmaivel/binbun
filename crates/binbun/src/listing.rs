//! The continuous listing of an image: every mapped byte, code and data,
//! as lines, in the usual disassembler layout, from what a
//! [`binbun::Database`] knows.
//!
//! - **Line space.** A line is a number (`u64`) and 16 bytes of layout
//!   (the address of the item it belongs to, what it is); its text is
//!   made only when it is drawn ([`Listing::render`]), so the listing of a
//!   large image costs memory per line, not per character.
//! - **Items.** Instructions (recovered blocks; bytes between them swept
//!   linearly, padding as `align`) and data items (strings, pointers the
//!   relocations store, objects the symbols size, never cut by what
//!   refers inside them, scalars of the largest width code accesses them
//!   at, jump tables, ELF's dynamic entries, `align`, runs of one value as
//!   `dup`, the rest one unexplored byte a line).
//! - **Names.** Symbols, then the usual dummy names: `sub_`, `loc_`,
//!   `locret_`, `jpt_` and `def_` for code, `a…` from a string's text,
//!   `off_`, `byte_`…`xmmword_` (an array by its unit) and `unk_` for
//!   referenced data. A name plus an offset is only written inside the
//!   named item; past its end the address gets a dummy name; code is
//!   never its function plus an offset.
//! - **Lines around items.** Section banners; the function header (banner,
//!   attributes, the prototype the type library declares, `public`,
//!   `proc near`, the frame block of an `rbp`-based frame) and `endp`;
//!   labels on their own line after a blank line; cross-references on the
//!   item's line (as many as [`Options::xrefs`], then `...`); the
//!   separator after an instruction control does not fall through; the
//!   further lines of a user's comment under the item's first content
//!   line, as the front end lays them ([`Listing::set_comments`]).
//! - **Tokens.** Each line is tokens with a [`Role`] (what colours them)
//!   and, for references, the address they go to; a mnemonic's role is its
//!   instruction's class by how it transfers control (jump, call, return,
//!   padding), a name's token says whether binbun made the name.
//!
//! x86 operands are the decoder's Intel text with names put in
//! (`lea rdi, top_level`, `call cs:sleep_ptr`, `[rbp+var_54]`, `jz short
//! loc_1C74A`) and the common `88h` notation (0–9 in decimal); AArch64 keeps
//! its own syntax with names for labels and `@PAGE`/`@PAGEOFF` for the
//! `adrp` pairs that form an address.

mod build;
mod code;
mod data;
mod decl;
mod names;
mod render;
mod text;

use std::collections::{BTreeMap, HashMap};
use std::ops::Range;
use std::sync::{Mutex, PoisonError};

use crate::Database;
use crate::cfg::FunctionId;

/// The listing's settings; [`Default`] is the usual disassembler layout:
/// `88h` numbers, names in operands, no opcode bytes, two
/// cross-references.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Options {
    /// Opcode bytes shown between the prefix and the text (0: none).
    pub opcode_bytes: usize,
    /// How numbers are written.
    pub numbers: Numbers,
    /// Names in operands; otherwise the decoder's operands, with the name
    /// in a comment.
    pub symbolic: bool,
    /// Cross-references shown per item before `...`.
    pub xrefs: usize,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            opcode_bytes: 0,
            numbers: Numbers::Masm,
            symbolic: true,
            xrefs: 2,
        }
    }
}

/// How numbers are written.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Numbers {
    /// The `h`-suffixed assembler notation: `88h`, `0A8h`, 0–9 in decimal.
    Masm,
    /// C's: `0x88`.
    C,
}

/// What the item a line belongs to is (what colours its address prefix).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Item {
    /// An instruction of a function.
    Function,
    /// An instruction no function holds.
    Code,
    /// Typed data.
    Data,
    /// Bytes nothing gives a type.
    Unexplored,
}

/// What a line is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum LineKind {
    /// An empty line.
    Blank,
    /// A section's border line.
    SegmentBorder,
    /// A section's type (code, data, uninitialised).
    SegmentType,
    /// A section's permissions.
    SegmentPermissions,
    /// The `S U B R O U T I N E` banner.
    Banner,
    /// A function's attributes.
    Attributes,
    /// A function's prototype.
    Prototype,
    /// `public name`.
    Public,
    /// `name proc near`.
    Proc,
    /// A frame variable of a function.
    Frame,
    /// A code label.
    Label,
    /// A further cross-reference of the item.
    Xref,
    /// The text a pointer points to.
    Preview,
    /// An instruction.
    Instruction,
    /// Data (one line of an item).
    Data,
    /// The separator after code control does not fall through.
    Separator,
    /// `name endp`.
    End,
    /// A further line of the user's comment on the item, under its first
    /// content line ([`Listing::set_comments`]): rendered as its prefix,
    /// the front end writes the comment's line after it.
    Comment,
}

/// One line of the listing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Line {
    /// The address of the item the line belongs to: every line of one
    /// item (header, label, cross-references, pieces) has it.
    pub address: u64,
    /// What the item is.
    pub item: Item,
    /// What the line is.
    pub kind: LineKind,
}

/// A jump or branch within one function, by line.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Arrow {
    /// The line of the jump.
    pub from: u64,
    /// The line of its target.
    pub to: u64,
    /// Whether it is a conditional branch.
    pub conditional: bool,
    /// Whether code of another function lies between its ends (a jump
    /// between a function's distant parts, such as to its cold part): its
    /// lane is its function's, so a front end shows it as stubs rather
    /// than a line across the other function's arrows.
    pub crosses: bool,
    /// Its lane in the branch gutter, from the code outward: fixed per
    /// function when the listing is built ([`Jump::lane`]), so it never
    /// depends on the lines asked for.
    pub lane: u16,
}

/// A jump or branch within one function, by address, with its lane.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Jump {
    /// The jump's address.
    pub(crate) from: u64,
    /// Its target.
    pub(crate) to: u64,
    /// Whether it is a conditional branch.
    pub(crate) conditional: bool,
    /// Whether a block of another function lies between its ends
    /// ([`Arrow::crosses`]).
    pub(crate) crosses: bool,
    /// Its lane among its function's jumps: the shortest innermost, each
    /// in the first lane free over its whole span (interval colouring;
    /// a front end with fewer lanes shows the rest as stubs).
    pub(crate) lane: u16,
}

/// What a token is, which decides its colour.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Role {
    /// Padding.
    Space,
    /// The `section:address` prefix.
    Prefix,
    /// Opcode bytes.
    OpcodeBytes,
    /// An instruction's mnemonic none of the classes below takes.
    Mnemonic,
    /// A jump's or branch's mnemonic, unconditional or conditional (`jmp`,
    /// `jz`, `loop`, `jrcxz`; `b`, `b.eq`, `cbz`, `tbnz`, `br`).
    JumpMnemonic,
    /// A call's mnemonic (`call`; `bl`, `blr`).
    CallMnemonic,
    /// A return's mnemonic, from a call or an exception (`retn`, `retf`,
    /// `iret`; `ret`, `retaa`, `eret`).
    ReturnMnemonic,
    /// Padding: a `nop` of any length, a trap that fills bytes no
    /// recovered block holds (x86's `int 3`, AArch64's zero word `udf
    /// #0`), the `align` directive.
    PaddingMnemonic,
    /// A register.
    Register,
    /// A number, in code or data.
    Number,
    /// Punctuation: `, [ ] + - : = ( )`.
    Punctuation,
    /// A data directive's word: `db`…`dq`, `dup`, `text`; AArch64's
    /// operand words (`lsl`, `uxtw`).
    Keyword,
    /// What qualifies an x86 operand: `short`, `qword ptr`, `offset`, a
    /// segment (`cs:`, `fs:`).
    OperandKeyword,
    /// An assembler directive: `public`, `proc near`, `endp`.
    Directive,
    /// The name of code: a function, a label.
    CodeName,
    /// The name of data.
    DataName,
    /// The name of an import.
    ImportName,
    /// A stack variable.
    LocalName,
    /// A string's text.
    String,
    /// A regular comment: a prototype.
    Comment,
    /// An automatic comment: banners, attributes, previews, separators.
    AutoComment,
    /// A cross-reference from code.
    CodeXref,
    /// A cross-reference from data, or one taking an address.
    DataXref,
}

/// A token of a line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Token {
    /// Its text.
    pub text: String,
    /// What it is.
    pub role: Role,
    /// The address it names, for following it.
    pub target: Option<u64>,
    /// Whether it is a name binbun made (`sub_`, `loc_`, `off_`, `unk_`,
    /// `byte_`…, `a…` from a string, `var_`/`arg_`), not one a symbol,
    /// debug information, an import or the user gives.
    pub automatic: bool,
}

/// A line as tokens (whitespace included).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Rendered {
    /// The tokens, in order.
    pub tokens: Vec<Token>,
}

impl Rendered {
    /// The line's text.
    pub fn text(&self) -> String {
        self.tokens.iter().map(|t| t.text.as_str()).collect()
    }

    /// Its length in characters.
    fn width(&self) -> usize {
        self.tokens.iter().map(|t| t.text.chars().count()).sum()
    }

    fn push(&mut self, role: Role, text: impl Into<String>) {
        self.tokens.push(Token {
            text: text.into(),
            role,
            target: None,
            automatic: false,
        });
    }

    fn push_target(&mut self, role: Role, text: impl Into<String>, target: u64) {
        self.tokens.push(Token {
            text: text.into(),
            role,
            target: Some(target),
            automatic: false,
        });
    }

    /// A stack variable's name, which binbun makes from its offset.
    fn push_local(&mut self, text: String) {
        self.tokens.push(Token {
            text,
            role: Role::LocalName,
            target: None,
            automatic: true,
        });
    }

    /// Pads with spaces to `column` characters (at least one space if
    /// `space`).
    fn pad_to(&mut self, column: usize, space: bool) {
        let at = self.width();
        let n = column.saturating_sub(at).max(usize::from(space && at > 0));
        if n > 0 {
            self.push(Role::Space, " ".repeat(n));
        }
    }
}

/// What the listing holds.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    /// Lines.
    pub lines: u64,
    /// Instructions.
    pub instructions: u64,
    /// Data items.
    pub data_items: u64,
    /// Dummy names given (`sub_`, `loc_`, `off_`…, strings' excluded).
    pub dummy_names: u64,
    /// Names made from strings' text.
    pub string_names: u64,
}

/// What the bytes of a [`Span`] are.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SpanKind {
    /// An instruction; of a function if `function`.
    Instruction {
        /// Whether a function holds it.
        function: bool,
    },
    /// A string literal and its NUL; UTF-16 if `wide`.
    String {
        /// Whether it is UTF-16.
        wide: bool,
    },
    /// A pointer a relocation stores.
    Pointer {
        /// Where it points.
        target: u64,
    },
    /// An import's pointer slot.
    Import,
    /// One value of this many bytes.
    Scalar {
        /// Its width in bytes.
        width: u8,
    },
    /// An object of values of this many bytes (a sized symbol, an array).
    Values {
        /// The width of each value.
        width: u8,
    },
    /// A run of one byte value.
    Fill {
        /// The value.
        byte: u8,
    },
    /// Bytes the file does not supply.
    Uninitialised,
    /// Padding to an alignment.
    Align,
    /// A jump table.
    Table,
    /// Bytes no analysis typed (a run of them is one span).
    Unexplored,
}

/// An item's bytes: an instruction or a data item ([`Listing::spans`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Span {
    /// Its first address.
    pub start: u64,
    /// Past its last byte.
    pub end: u64,
    /// What it is.
    pub kind: SpanKind,
}

/// What a name names, for its colour.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum NameKind {
    Code,
    Data,
    Import,
}

impl NameKind {
    fn role(self) -> Role {
        match self {
            Self::Code => Role::CodeName,
            Self::Data => Role::DataName,
            Self::Import => Role::ImportName,
        }
    }
}

#[derive(Clone, Debug)]
struct Name {
    text: String,
    kind: NameKind,
    /// Whether binbun made it (a dummy name, a string's name), not a
    /// symbol or debug information.
    automatic: bool,
}

impl Name {
    /// The name of `address` as a token.
    fn token(&self, address: u64) -> Token {
        Token {
            text: self.text.clone(),
            role: self.kind.role(),
            target: Some(address),
            automatic: self.automatic,
        }
    }
}

/// One line's layout.
#[derive(Clone, Copy, Debug)]
struct Row {
    address: u64,
    /// Per kind: a piece or entry index, the `k`th cross-reference line,
    /// a frame slot, a section index, an instruction's length.
    aux: u32,
    kind: LineKind,
    item: Item,
}

#[derive(Clone, Debug)]
struct Section {
    name: String,
    start: u64,
    end: u64,
    /// Where the bytes the file supplies end.
    file_end: u64,
    code: bool,
    /// Its segment's permissions, as the banner writes them (`Read/Execute`).
    permissions: String,
}

/// A stack slot of an `rbp`-based frame: its offset from `rbp` and the
/// size it is first accessed at.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Slot {
    offset: i64,
    size: u32,
}

#[derive(Clone, Debug)]
struct Function {
    id: FunctionId,
    /// Past the last instruction of its body from the entry (before the
    /// next function's entry).
    end: u64,
    /// The next function's entry (or the end of its code): code up to
    /// there that recovery did not reach is laid out as its.
    limit: u64,
    bp_frame: bool,
    /// `rbp`'s offset from the stack pointer on entry, where the prologue
    /// makes it plain.
    base: Option<i64>,
    noreturn: bool,
    public: bool,
    prototype: Option<String>,
    frame: Vec<Slot>,
}

/// What a data item is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DataKind {
    /// A string literal and its NUL; UTF-16 if `wide`.
    String { wide: bool },
    /// A pointer a relocation stores.
    Pointer { target: u64 },
    /// An import's pointer slot (index into the image's imports).
    Import { index: u32 },
    /// One value of this many bytes.
    Scalar { width: u8 },
    /// Values of this many bytes, several a line.
    Values { width: u8 },
    /// A run of one byte value.
    Fill { byte: u8 },
    /// Bytes the file does not supply; one value of `width` if not 0.
    Uninitialised { width: u8 },
    /// Padding to this alignment.
    Align { to: u64 },
    /// A jump table of `width`-byte entries, relative to its start if
    /// `relative`.
    Table { width: u8, relative: bool },
    /// Bytes no analysis typed, one a line.
    Unexplored,
}

#[derive(Clone, Copy, Debug)]
struct DataItem {
    start: u64,
    size: u64,
    kind: DataKind,
}

/// The decoder of the image's code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Decoder {
    X86(binbun_x86::Mode),
    Aarch64,
}

/// Lines found for addresses, kept while the lines stay numbered as they
/// are; a copy starts empty (it is only a cache).
#[derive(Debug, Default)]
struct EndLines(Mutex<HashMap<u64, u64>>);

impl Clone for EndLines {
    fn clone(&self) -> Self {
        Self::default()
    }
}

/// The listing of one image.
#[derive(Clone, Debug)]
pub struct Listing {
    options: Options,
    rows: Vec<Row>,
    sections: Vec<Section>,
    names: BTreeMap<u64, Name>,
    by_name: HashMap<String, u64>,
    functions: BTreeMap<u64, Function>,
    /// Every block of a function, `(start, end, entry)`, by start.
    owners: Vec<(u64, u64, u64)>,
    /// Data items (and `align` in code), by start.
    items: Vec<DataItem>,
    /// Jumps and branches within a function, by `from`.
    jumps: Vec<Jump>,
    /// The line of each jump's end asked for so far, by address
    /// ([`Listing::arrows`]: a long function's jumps span every view of it,
    /// and finding a line searches every line); emptied whenever lines
    /// are numbered anew.
    end_lines: EndLines,
    /// AArch64 `adrp`s and the address their pair forms.
    pages: HashMap<u64, u64>,
    /// String literals' text, by address.
    strings: BTreeMap<u64, String>,
    /// The imports' names, in the image's order.
    imports: Vec<String>,
    /// Hex digits of an address.
    digits: usize,
    decoder: Option<Decoder>,
    /// Whether the image is loaded where the loader chooses (an
    /// immediate is then never an address).
    relocatable: bool,
    pointer_size: u8,
    stats: Stats,
    /// The [`LineKind::Comment`] lines laid, by address: how many.
    comments: BTreeMap<u64, u32>,
}

impl Listing {
    /// The listing of `db`'s image under `options` (builds the database's
    /// cross-references if not built yet).
    pub fn build(db: &Database<'_>, options: &Options) -> Self {
        build::build(db, options.clone())
    }

    /// Its settings.
    pub fn options(&self) -> &Options {
        &self.options
    }

    /// How many lines there are.
    pub fn len(&self) -> u64 {
        self.rows.len() as u64
    }

    /// Whether there are none.
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// Line `n`.
    pub fn line(&self, n: u64) -> Option<Line> {
        let row = self.row(n)?;
        Some(Line {
            address: row.address,
            item: row.item,
            kind: row.kind,
        })
    }

    fn row(&self, n: u64) -> Option<&Row> {
        self.rows.get(usize::try_from(n).ok()?)
    }

    /// Lays the further lines of the user's comments: under the first
    /// content line of the item at each address of `comments` (with how
    /// many lines its comment has), one [`LineKind::Comment`] line for
    /// each line after the first (the `k`th renders its prefix; the front
    /// end writes the comment's line `k` after it); those laid before for
    /// other comments go. An address with no item starting there gets
    /// none. Whether any line changed (lines after a change are numbered
    /// anew).
    pub fn set_comments(&mut self, comments: &BTreeMap<u64, usize>) -> bool {
        let wanted: BTreeMap<u64, u32> = comments
            .iter()
            .filter(|&(&address, &lines)| lines > 1 && self.content_row(address).is_some())
            .map(|(&address, &lines)| (address, u32::try_from(lines - 1).unwrap_or(u32::MAX)))
            .collect();
        if wanted == self.comments {
            return false;
        }
        let more: usize = wanted.values().map(|&k| k as usize).sum();
        let old = std::mem::take(&mut self.rows);
        let mut rows = Vec::with_capacity(old.len() + more);
        let mut content = None;
        for row in old {
            if row.kind == LineKind::Comment {
                continue;
            }
            rows.push(row);
            if matches!(row.kind, LineKind::Instruction | LineKind::Data)
                && content != Some(row.address)
            {
                content = Some(row.address);
                let count = wanted.get(&row.address).copied().unwrap_or(0);
                rows.extend((1..=count).map(|k| Row {
                    aux: k,
                    kind: LineKind::Comment,
                    ..row
                }));
            }
        }
        self.rows = rows;
        self.comments = wanted;
        self.end_lines
            .0
            .get_mut()
            .unwrap_or_else(PoisonError::into_inner)
            .clear();
        true
    }

    /// The first content line (instruction or data) of the item starting
    /// at `address`.
    fn content_row(&self, address: u64) -> Option<usize> {
        let first = self.rows.partition_point(|r| r.address < address);
        (first..self.rows.len())
            .take_while(|&i| self.rows.get(i).is_some_and(|r| r.address == address))
            .find(|&i| {
                self.rows
                    .get(i)
                    .is_some_and(|r| matches!(r.kind, LineKind::Instruction | LineKind::Data))
            })
    }

    /// What it holds.
    pub fn stats(&self) -> &Stats {
        &self.stats
    }

    /// The first line (a header, a label, a cross-reference: the first of
    /// any) of the items at `address` and after.
    pub fn first_line(&self, address: u64) -> u64 {
        self.rows.partition_point(|r| r.address < address) as u64
    }

    /// The content line (instruction or data, not header or label) of the
    /// item holding `address`, else the nearest line after it.
    pub fn line_of(&self, address: u64) -> u64 {
        let after = self.rows.partition_point(|r| r.address <= address);
        let Some(last) = after.checked_sub(1) else {
            return 0;
        };
        let head = self.rows.get(last).map_or(0, |r| r.address);
        let first = self.rows.partition_point(|r| r.address < head);
        let content = (first..after).find(|&i| {
            self.rows
                .get(i)
                .is_some_and(|r| matches!(r.kind, LineKind::Instruction | LineKind::Data))
        });
        let within = self.item_end(head).is_some_and(|end| address < end);
        match content {
            Some(i) if within || head == address => i as u64,
            _ => after.min(self.rows.len().saturating_sub(1)) as u64,
        }
    }

    /// Past the end of the item at `head`, if one starts there.
    fn item_end(&self, head: u64) -> Option<u64> {
        let first = self.rows.partition_point(|r| r.address < head);
        let row = self
            .rows
            .get(first..)?
            .iter()
            .take_while(|r| r.address == head)
            .find(|r| matches!(r.kind, LineKind::Instruction | LineKind::Data))?;
        match row.kind {
            LineKind::Instruction => Some(head + u64::from(row.aux)),
            LineKind::Blank
            | LineKind::SegmentBorder
            | LineKind::SegmentType
            | LineKind::SegmentPermissions
            | LineKind::Banner
            | LineKind::Attributes
            | LineKind::Prototype
            | LineKind::Public
            | LineKind::Proc
            | LineKind::Frame
            | LineKind::Label
            | LineKind::Xref
            | LineKind::Preview
            | LineKind::Data
            | LineKind::Separator
            | LineKind::End
            | LineKind::Comment => self.item(head).map(|item| item.start + item.size),
        }
    }

    /// The data item starting at `address`.
    fn item(&self, address: u64) -> Option<&DataItem> {
        let i = self.items.partition_point(|item| item.start < address);
        self.items.get(i).filter(|item| item.start == address)
    }

    /// The data item holding `address`.
    fn item_holding(&self, address: u64) -> Option<&DataItem> {
        let i = self.items.partition_point(|item| item.start <= address);
        self.items
            .get(i.checked_sub(1)?)
            .filter(|item| address < item.start + item.size)
    }

    /// The first address of the data item holding `address`, if one does
    /// (`record+4` is `record`'s).
    pub fn data_of(&self, address: u64) -> Option<u64> {
        self.item_holding(address).map(|item| item.start)
    }

    /// The name the listing shows for `address`.
    pub fn name(&self, address: u64) -> Option<&str> {
        self.names.get(&address).map(|n| n.text.as_str())
    }

    /// The frame slot a stack variable's name (`var_54`, as the listing
    /// writes it on the line of `address`) names: the entry of the
    /// `rbp`-based function whose frame the line uses, and the slot's
    /// offset from the stack pointer on entry (as decompilation's frame
    /// slots are; `var_54` is `rbp-54h`). `None` for another name, or
    /// where the prologue leaves `rbp`'s place unclear.
    pub fn local(&self, address: u64, name: &str) -> Option<(u64, i64)> {
        let entry = self
            .function_of(address)
            .map(|(_, entry)| entry)
            .or_else(|| self.functions.contains_key(&address).then_some(address))?;
        let function = self.functions.get(&entry)?;
        let offset = render::slot_offset(name)?;
        if !function.frame.iter().any(|slot| slot.offset == offset) {
            return None;
        }
        Some((entry, function.base?.checked_add(offset)?))
    }

    /// The address `wanted` names: a name, else a mapped hexadecimal
    /// address (`0x` optional).
    pub fn find(&self, wanted: &str) -> Option<u64> {
        let wanted = wanted.trim();
        if let Some(&a) = self.by_name.get(wanted) {
            return Some(a);
        }
        let hex = wanted.trim_start_matches("0x").trim_end_matches('h');
        u64::from_str_radix(hex, 16)
            .ok()
            .filter(|&a| self.section_of(a).is_some())
    }

    /// `main+58`, `top_level`, `.rodata:EC000`: where `address` is, as a
    /// cross-reference says it.
    pub fn describe(&self, address: u64) -> String {
        if let Some(name) = self.name(address) {
            return name.to_owned();
        }
        if let Some((_, entry)) = self.function_of(address) {
            let name = self.name(entry).unwrap_or("?");
            return if address >= entry {
                format!("{name}+{:X}", address - entry)
            } else {
                format!("{name}-{:X}", entry - address)
            };
        }
        if let Some(item) = self.item_holding(address)
            && let Some(name) = self.name(item.start)
        {
            return format!("{name}+{:X}", address - item.start);
        }
        let section = self.section_of(address).map_or("?", |s| s.name.as_str());
        format!("{section}:{address:0w$X}", w = self.digits)
    }

    /// The function whose block holds `address`, and its entry.
    pub fn function_of(&self, address: u64) -> Option<(FunctionId, u64)> {
        let i = self
            .owners
            .partition_point(|&(start, _, _)| start <= address);
        let &(_, end, entry) = self.owners.get(i.checked_sub(1)?)?;
        if address >= end {
            return None;
        }
        Some((self.functions.get(&entry)?.id, entry))
    }

    /// The jumps and branches within one function with an end on a line
    /// of `lines`.
    pub fn arrows(&self, lines: Range<u64>) -> Vec<Arrow> {
        let (Some(first), Some(last)) = (
            self.row(lines.start),
            self.row(lines.end.saturating_sub(1).max(lines.start)),
        ) else {
            return Vec::new();
        };
        let (low, high) = (first.address, last.address);
        let inside = |a: u64| (low..=high).contains(&a);
        // A jump reaches at most a function away.
        let from = self
            .jumps
            .partition_point(|j| j.from < low.saturating_sub(1 << 20));
        let mut known = self
            .end_lines
            .0
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let mut line_of = |address: u64| {
            *known
                .entry(address)
                .or_insert_with(|| self.line_of(address))
        };
        self.jumps
            .get(from..)
            .unwrap_or_default()
            .iter()
            .take_while(|j| j.from <= high.saturating_add(1 << 20))
            .filter(|j| {
                let (f, t) = (j.from, j.to);
                inside(f) || inside(t) || (f.min(t) < low && f.max(t) > high)
            })
            .map(|j| Arrow {
                from: line_of(j.from),
                to: line_of(j.to),
                conditional: j.conditional,
                crosses: j.crosses,
                lane: j.lane,
            })
            .collect()
    }

    /// The items with a byte in `addresses`, in address order: each
    /// instruction and each data item, a run of unexplored bytes as one
    /// span. Costs the number of lines over `addresses`, not the image.
    pub fn spans(&self, addresses: Range<u64>) -> Vec<Span> {
        let mut out: Vec<Span> = Vec::new();
        let mut push = |span: Span| match out.last_mut() {
            Some(last)
                if span.kind == SpanKind::Unexplored
                    && last.kind == SpanKind::Unexplored
                    && last.end == span.start =>
            {
                last.end = span.end;
            }
            Some(_) | None => out.push(span),
        };
        // An instruction may start up to 15 bytes before the range.
        let from = self
            .rows
            .partition_point(|r| r.address < addresses.start.saturating_sub(16));
        let mut items = self
            .items
            .partition_point(|item| item.start + item.size <= addresses.start);
        for row in self.rows.get(from..).unwrap_or_default() {
            if row.address >= addresses.end {
                break;
            }
            if row.kind != LineKind::Instruction {
                continue;
            }
            let end = row.address + u64::from(row.aux);
            if end <= addresses.start {
                continue;
            }
            // The data items before it first.
            while let Some(item) = self.items.get(items).filter(|i| i.start < row.address) {
                push(data_span(item));
                items += 1;
            }
            push(Span {
                start: row.address,
                end,
                kind: SpanKind::Instruction {
                    function: row.item == Item::Function,
                },
            });
        }
        while let Some(item) = self.items.get(items).filter(|i| i.start < addresses.end) {
            push(data_span(item));
            items += 1;
        }
        out
    }

    fn section_of(&self, address: u64) -> Option<&Section> {
        let i = self.sections.partition_point(|s| s.start <= address);
        self.sections
            .get(i.checked_sub(1)?)
            .filter(|s| address < s.end)
    }

    /// Line `n` as tokens.
    pub fn render(&self, db: &Database<'_>, n: u64) -> Rendered {
        let mut r = Rendered::default();
        if let Some(&row) = self.row(n) {
            self.render_row(db, row, &mut r);
        }
        r
    }
}

/// A data item as a [`Span`].
fn data_span(item: &DataItem) -> Span {
    let kind = match item.kind {
        DataKind::String { wide } => SpanKind::String { wide },
        DataKind::Pointer { target } => SpanKind::Pointer { target },
        DataKind::Import { .. } => SpanKind::Import,
        DataKind::Scalar { width } => SpanKind::Scalar { width },
        DataKind::Values { width } => SpanKind::Values { width },
        DataKind::Fill { byte } => SpanKind::Fill { byte },
        DataKind::Uninitialised { .. } => SpanKind::Uninitialised,
        DataKind::Align { .. } => SpanKind::Align,
        DataKind::Table { .. } => SpanKind::Table,
        DataKind::Unexplored => SpanKind::Unexplored,
    };
    Span {
        start: item.start,
        end: item.start + item.size,
        kind,
    }
}
