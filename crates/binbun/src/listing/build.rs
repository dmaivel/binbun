//! Building a listing: sections, functions, names, then the lines of each
//! section in address order.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::ops::Range;

use binbun_isa::Flow;
use binbun_loader::{Format, Image, Machine, SymbolKind, SymbolSource};
use binbun_x86::{Mnemonic, Register, Value, decode};

use crate::Database;
use crate::analysis::x86_mode;
use crate::cfg::{BlockId, Destination, Exit};
use crate::corrections::{Data, Item as UserItem, Unit};
use crate::listing::code::{arm_access_width, length};
use crate::listing::names::{dummy, string_name};
use crate::listing::render::{bytes, xref_layout};
use crate::listing::text::data_prefix;
use crate::listing::{
    DataItem, DataKind, Decoder, EndLines, Function, Item, Jump, LineKind, Listing, NameKind,
    Options, Row, Section, Slot, Stats, code, data, decl,
};
use crate::references::{Kind, Reference, References};
use crate::strings::Encoding;

/// The shortest string literal found by scanning that is shown as one
/// (referenced ones are shown whatever their length).
const MIN_STRING: usize = 4;

/// How many instructions at a function's entry are looked at for its
/// frame's prologue.
const PROLOGUE: usize = 8;

/// A jump table: where it is, its entries' width, how many, and whether
/// they are offsets from its start.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Table {
    pub(crate) base: u64,
    pub(crate) width: u8,
    pub(crate) count: u64,
    pub(crate) relative: bool,
}

/// What building needs on the way.
pub(crate) struct Builder<'d, 'a> {
    pub(crate) db: &'d Database<'a>,
    pub(crate) image: &'a Image<'a>,
    pub(crate) refs: &'d References,
    pub(crate) l: Listing,
    /// Jump tables by start.
    pub(crate) tables: BTreeMap<u64, Table>,
    /// String literals: size with the NUL, and whether UTF-16.
    pub(crate) strings: BTreeMap<u64, (u64, bool)>,
    /// The width code reads or writes data at, by address (0: its address
    /// only taken).
    pub(crate) widths: BTreeMap<u64, u8>,
    /// Import slots: index into the image's imports, by slot.
    pub(crate) slots: BTreeMap<u64, u32>,
    /// Data symbols with a size, by address.
    pub(crate) objects: BTreeMap<u64, u64>,
    /// ELF's dynamic section.
    pub(crate) dynamic: Option<Range<u64>>,
    /// The addresses the image exports (ELF dynamic symbols, PE exports).
    pub(crate) exported: HashSet<u64>,
}

pub(crate) fn build(db: &Database<'_>, options: Options) -> Listing {
    let image = db.image();
    let refs = db.references();
    let decoder = match image.machine {
        Machine::Aarch64 => Some(Decoder::Aarch64),
        Machine::X86 | Machine::X86_64 => x86_mode(image.machine).ok().map(Decoder::X86),
        Machine::Arm | Machine::Other => None,
    };
    let top = image
        .segments
        .iter()
        .map(|s| s.start + s.size)
        .max()
        .unwrap_or(0);
    let digits = usize::try_from((64 - top.leading_zeros()).div_ceil(4))
        .unwrap_or(16)
        .max(4);
    let l = Listing {
        options,
        rows: Vec::new(),
        sections: sections(image),
        names: BTreeMap::new(),
        by_name: HashMap::new(),
        functions: BTreeMap::new(),
        owners: Vec::new(),
        items: Vec::new(),
        jumps: Vec::new(),
        end_lines: EndLines::default(),
        pages: HashMap::new(),
        strings: BTreeMap::new(),
        imports: image.imports.iter().map(|i| i.name.clone()).collect(),
        digits,
        decoder,
        relocatable: image.position_independent,
        pointer_size: if image.machine == Machine::X86 { 4 } else { 8 },
        stats: Stats::default(),
        comments: BTreeMap::new(),
    };
    let mut b = Builder {
        db,
        image,
        refs,
        l,
        tables: BTreeMap::new(),
        strings: BTreeMap::new(),
        widths: BTreeMap::new(),
        slots: BTreeMap::new(),
        objects: BTreeMap::new(),
        dynamic: None,
        exported: image
            .symbols
            .iter()
            .filter(|s| matches!(s.source, SymbolSource::Dynamic | SymbolSource::Export))
            .map(|s| s.address)
            .collect(),
    };
    b.dynamic = (image.format == Format::Elf)
        .then(|| b.l.sections.iter().find(|s| s.name == ".dynamic"))
        .flatten()
        .map(|s| s.start..s.end);
    b.functions();
    b.symbol_names();
    b.tables();
    b.code_names();
    b.data_facts();
    b.string_names();
    b.lay_out();
    let mut l = b.l;
    let owners: Vec<Option<u64>> = l
        .jumps
        .iter()
        .map(|j| l.function_of(j.from).map(|(_, entry)| entry))
        .collect();
    mark_crossing(&mut l.jumps, &owners, &l.owners);
    assign_lanes(&mut l.jumps, &owners);
    l.stats.lines = l.rows.len() as u64;
    l.stats.data_items = l
        .items
        .iter()
        .filter(|i| !matches!(i.kind, DataKind::Align { .. }))
        .count() as u64;
    l
}

impl Builder<'_, '_> {
    pub(crate) fn push(&mut self, address: u64, kind: LineKind, aux: u32, item: Item) {
        // One blank line where two would meet (a section's header, then a
        // function's).
        if kind == LineKind::Blank
            && self
                .l
                .rows
                .last()
                .is_some_and(|r| r.kind == LineKind::Blank)
        {
            return;
        }
        self.l.rows.push(Row {
            address,
            aux,
            kind,
            item,
        });
    }

    /// The bytes the file supplies at `address`, at most `len`.
    pub(crate) fn bytes(&self, address: u64, len: u64) -> &[u8] {
        bytes(self.image, address, len)
    }

    /// The user's items that are no code (bytes undefined, data) with a
    /// byte in `start..end`, as `(start, end)` in address order.
    pub(crate) fn user_items(&self, start: u64, end: u64) -> Vec<(u64, u64)> {
        let items = self.db.corrections().items();
        if items.is_empty() {
            return Vec::new();
        }
        // Disjoint items end in the order they start.
        let mut found: Vec<(u64, u64)> = items
            .range(..end)
            .rev()
            .map(|(&at, &item)| (at, at.saturating_add(item.size()), item))
            .take_while(|&(_, item_end, _)| item_end > start)
            .filter(|&(_, _, item)| item != UserItem::Code)
            .map(|(at, item_end, _)| (at, item_end))
            .collect();
        found.reverse();
        found
    }

    /// The user's item that is no code holding `address`: its start, its
    /// end, and its data if typed (else the bytes are undefined).
    pub(crate) fn user_item(&self, address: u64) -> Option<(u64, u64, Option<Data>)> {
        let (start, item) = self.db.corrections().holding(address)?;
        let end = start.saturating_add(item.size());
        match item {
            UserItem::Code => None,
            UserItem::Undefined { .. } => Some((start, end, None)),
            UserItem::Data(data) => Some((start, end, Some(data))),
        }
    }

    /// The functions: their blocks, extent, frame, attributes, prototype.
    fn functions(&mut self) {
        let program = self.db.program();
        let mut entries: Vec<u64> = program.functions.values().map(|f| f.entry).collect();
        entries.sort_unstable();
        let mut owners = Vec::new();
        for (id, f) in program.functions.iter() {
            let next = entries
                .get(entries.partition_point(|&e| e <= f.entry))
                .copied()
                .unwrap_or(u64::MAX);
            let code_end = self
                .image
                .code
                .iter()
                .find(|range| range.contains(&f.entry))
                .map_or(f.entry, |range| range.end);
            let limit = next.min(code_end);
            let mut end = f.entry;
            for block in f.blocks.iter().filter_map(|&b| program.blocks.get(b)) {
                owners.push((block.start, block.end, f.entry));
                if block.start >= f.entry && block.start < next {
                    end = end.max(block.end);
                }
            }
            let (bp_frame, base, frame) = match self.frame(f.entry, &f.blocks, end..limit) {
                Some((base, frame)) => (true, base, frame),
                None => (false, None, Vec::new()),
            };
            let function = Function {
                id,
                end,
                limit,
                bp_frame,
                base,
                noreturn: !f.returns,
                public: self.exported.contains(&f.entry),
                prototype: self.prototype(f.entry),
                frame,
            };
            self.l.functions.insert(f.entry, function);
        }
        owners.sort_unstable();
        owners.dedup_by_key(|o| o.0);
        self.l.owners = owners;
    }

    /// The prototype the type library declares for the function at
    /// `entry`, by its name (a symbol, or an import thunk's import).
    fn prototype(&self, entry: u64) -> Option<String> {
        let name = self
            .db
            .name(entry)
            .map(str::to_owned)
            .or_else(|| self.db.data_name(entry))?;
        let module = self
            .image
            .imports
            .iter()
            .find(|i| i.name == name)
            .and_then(|i| i.library.as_deref());
        let library = self.db.library();
        let declaration = library.function(module, &name)?;
        let signature = &declaration.prototype.as_ref()?.value;
        Some(decl::prototype(library, &name, signature))
    }

    /// If the function at `entry` (of `blocks`, and the code `after` them
    /// before the next function) keeps an `rbp`-based frame (`push
    /// rbp`, then `mov rbp, rsp`, among its first [`PROLOGUE`]
    /// instructions, which compilers may interleave with others) with
    /// `rbp`'s offset from the stack pointer on entry where the prologue
    /// makes it plain (only pushes move the stack pointer before `mov rbp,
    /// rsp`), and the slots its instructions address from `rbp`, by
    /// offset, each at the largest size it is accessed at (x86 only).
    fn frame(
        &self,
        entry: u64,
        blocks: &[BlockId],
        after: Range<u64>,
    ) -> Option<(Option<i64>, Vec<Slot>)> {
        let Some(Decoder::X86(mode)) = self.l.decoder else {
            return None;
        };
        let mut texts = Vec::new();
        let mut pc = entry;
        for _ in 0..PROLOGUE {
            let Ok(i) = decode(self.bytes(pc, 15), mode) else {
                break;
            };
            texts.push(i.intel(pc).to_string());
            pc += i.len() as u64;
        }
        let pushes = texts.iter().position(|t| t == "push rbp");
        let set = pushes.and_then(|p| {
            let after = texts.get(p + 1..)?;
            Some(p + 1 + after.iter().position(|t| t == "mov rbp, rsp")?)
        })?;
        let base = rbp_base(texts.get(..set).unwrap_or_default());
        let program = self.db.program();
        let mut starts: Vec<(u64, u64)> = blocks
            .iter()
            .filter_map(|&b| program.blocks.get(b))
            .map(|b| (b.start, b.end))
            .collect();
        starts.push((after.start, after.end));
        starts.sort_unstable();
        let mut slots: BTreeMap<i64, u32> = BTreeMap::new();
        for (start, end) in starts {
            let mut pc = start;
            while pc < end {
                let Ok(i) = decode(self.bytes(pc, 15), mode) else {
                    break;
                };
                for operand in i.operands() {
                    if let Value::Memory(m) = operand.value
                        && m.base == Some(Register::RBP)
                        && m.index.is_none()
                        && (m.displacement < 0 || m.displacement >= 16)
                    {
                        let size = slots.entry(m.displacement).or_insert(1);
                        *size = (*size).max(m.size);
                    }
                }
                pc += i.len() as u64;
            }
        }
        let frame = slots
            .into_iter()
            .map(|(offset, size)| Slot { offset, size })
            .collect();
        Some((base, frame))
    }

    /// Symbols' names, import slots' and thunks' names.
    fn symbol_names(&mut self) {
        for (&address, name) in self.db.names() {
            let kind = if self.image.is_code(address) {
                NameKind::Code
            } else {
                NameKind::Data
            };
            self.l.give(address, name.clone(), kind, false);
        }
        for (index, import) in self.image.imports.iter().enumerate() {
            if let Some(name) = self.db.data_name(import.slot) {
                self.l.give(import.slot, name, NameKind::Data, false);
            }
            self.slots
                .insert(import.slot, u32::try_from(index).unwrap_or(u32::MAX));
        }
        let entries: Vec<u64> = self.l.functions.keys().copied().collect();
        for entry in entries {
            if let Some(name) = self.db.data_name(entry) {
                // An import thunk takes its import's name.
                self.l.give(entry, name, NameKind::Import, false);
            }
        }
        for symbol in &self.image.symbols {
            if let Some(size) = symbol.size
                && size > 0
                && matches!(symbol.kind, SymbolKind::Data | SymbolKind::Other)
                && !self.image.is_code(symbol.address)
            {
                self.objects.entry(symbol.address).or_insert(size);
            }
        }
    }

    /// `sub_` for functions, `loc_` (`sub_` if called) for other code
    /// something refers to (not data in code: a string there is named
    /// from its text).
    fn code_names(&mut self) {
        let entries: Vec<u64> = self.l.functions.keys().copied().collect();
        let mut dummies = 0;
        for entry in entries {
            dummies += u64::from(
                self.l
                    .give(entry, dummy("sub", entry), NameKind::Code, true),
            );
        }
        let mut targets: Vec<(u64, bool)> = self
            .refs
            .all()
            .iter()
            .filter(|r| {
                self.image.is_code(r.target) && !self.db.program().data().contains_key(&r.target)
            })
            .map(|r| (r.target, r.kind == Kind::Call))
            .collect();
        for section in self.l.sections.iter().filter(|s| s.code) {
            targets.extend(code::swept_targets(self, section));
        }
        // A target both called and jumped to is a `sub_`.
        targets.sort_unstable_by_key(|&(target, call)| (target, !call));
        targets.dedup_by_key(|t| t.0);
        for (target, call) in targets {
            // `locret_` for a label on a return or on x86's `leave`
            // (the frame's teardown), whatever follows it.
            let returns = matches!(
                code::flow(self.l.decoder, self.bytes(target, 15), target),
                Some((_, Flow::Return))
            );
            let leave = match self.l.decoder {
                Some(Decoder::X86(mode)) => decode(self.bytes(target, 15), mode)
                    .is_ok_and(|i| i.mnemonic() == Mnemonic::Leave),
                Some(Decoder::Aarch64) | None => false,
            };
            let returns = returns || leave;
            let prefix = match (call, returns) {
                (true, _) => "sub",
                (false, true) => "locret",
                (false, false) => "loc",
            };
            dummies += u64::from(
                self.l
                    .give(target, dummy(prefix, target), NameKind::Code, true),
            );
        }
        self.l.stats.dummy_names += dummies;
    }

    /// Strings, the widths code accesses data at.
    fn data_facts(&mut self) {
        let mut literals = self.db.strings(MIN_STRING);
        literals.sort_by_key(|l| l.address);
        let mut end = 0;
        for literal in literals {
            // A literal that is another's tail stays part of it
            // (`aBashEnv+5`).
            if literal.address < end {
                continue;
            }
            let wide = matches!(literal.encoding, Encoding::Utf16);
            let nul = if wide { 2 } else { 1 };
            // The user's items win over what analysis found.
            if !self
                .user_items(literal.address, literal.address + literal.bytes + nul)
                .is_empty()
            {
                continue;
            }
            end = literal.address + literal.bytes + nul;
            self.strings
                .insert(literal.address, (literal.bytes + nul, wide));
            self.l.strings.insert(literal.address, literal.text);
        }
        for (&start, &item) in self.db.corrections().items() {
            if let UserItem::Data(data) = item
                && data.unit.is_string()
            {
                let size = data.size();
                let wide = data.unit == Unit::Utf16;
                let text = user_text(self.bytes(start, size), wide);
                self.strings.insert(start, (size, wide));
                self.l.strings.insert(start, text);
            }
        }
        let mut widths: BTreeMap<u64, u8> = BTreeMap::new();
        for r in self.refs.all() {
            if self.image.is_code(r.target) {
                continue;
            }
            let width = match r.kind {
                Kind::Read | Kind::Write => self.access_width(r),
                Kind::Call | Kind::Jump | Kind::Address | Kind::Pointer(_) => 0,
            };
            // The largest access (a `qword` read as two halves too).
            let slot = widths.entry(r.target).or_insert(width);
            *slot = (*slot).max(width);
        }
        self.widths = widths;
    }

    /// The width of the memory access `r` makes, if known.
    fn access_width(&self, r: &Reference) -> u8 {
        match self.l.decoder {
            Some(Decoder::X86(mode)) => decode(self.bytes(r.from, 15), mode)
                .ok()
                .and_then(|i| {
                    i.operands().find_map(|o| match o.value {
                        Value::Memory(m) if m.size > 0 => u8::try_from(m.size).ok(),
                        Value::Register(_)
                        | Value::Memory(_)
                        | Value::Immediate { .. }
                        | Value::SecondImmediate(_)
                        | Value::Relative(_)
                        | Value::Field(_) => None,
                    })
                })
                .unwrap_or(0),
            Some(Decoder::Aarch64) => arm_access_width(self.bytes(r.from, 4)),
            None => 0,
        }
    }

    /// Names from strings' text (`asc_` where it has no word).
    fn string_names(&mut self) {
        let starts: Vec<u64> = self.strings.keys().copied().collect();
        for start in starts {
            let text = self.l.strings.get(&start).map_or("", String::as_str);
            if let Some(name) = string_name(text) {
                let given = self.l.give(start, name, NameKind::Data, true);
                self.l.stats.string_names += u64::from(given);
            } else {
                let given = self
                    .l
                    .give(start, dummy("asc", start), NameKind::Data, true);
                self.l.stats.dummy_names += u64::from(given);
            }
        }
    }

    /// Every section's lines, in address order.
    fn lay_out(&mut self) {
        let sections = self.l.sections.clone();
        for (index, section) in sections.iter().enumerate() {
            let aux = u32::try_from(index).unwrap_or(u32::MAX);
            let item = if section.code { Item::Code } else { Item::Data };
            for kind in [
                LineKind::SegmentBorder,
                LineKind::Blank,
                LineKind::SegmentType,
                LineKind::SegmentPermissions,
                LineKind::Blank,
            ] {
                self.push(section.start, kind, aux, item);
            }
            if section.code {
                code::lay_out(self, section);
            } else {
                data::lay_out(self, section.start, section.end, section.file_end);
            }
        }
    }

    /// A dummy name for the data item `item` if something refers to it
    /// and it has none: by what it is, an array by its unit (`dword_` for
    /// `dd 4 dup(?)` as for `dd ?`).
    pub(crate) fn name_data(&mut self, item: DataItem) {
        if self.l.names.contains_key(&item.start) || self.refs.to(item.start).is_empty() {
            return;
        }
        let prefix = match item.kind {
            DataKind::Pointer { .. } | DataKind::Import { .. } => "off",
            DataKind::Scalar { width } | DataKind::Values { width } => {
                data_prefix(u32::from(width))
            }
            DataKind::Uninitialised { width } => {
                // The user's array there has no width of its own: its
                // unit's.
                let width = if width > 0 {
                    u64::from(width)
                } else {
                    self.user_item(item.start)
                        .and_then(|(at, _, data)| data.filter(|_| at == item.start))
                        .filter(|data| !data.unit.is_string())
                        .map_or(0, |data| data.unit.width())
                };
                data_prefix(u32::try_from(width).unwrap_or(0))
            }
            DataKind::Table { .. } => "jpt",
            DataKind::Fill { .. }
            | DataKind::Unexplored
            | DataKind::String { .. }
            | DataKind::Align { .. } => "unk",
        };
        let given = self
            .l
            .give(item.start, dummy(prefix, item.start), NameKind::Data, true);
        self.l.stats.dummy_names += u64::from(given);
    }

    /// The cross-references of the item `range` (an item's bytes, or an
    /// instruction's first byte), code first, each kind by where it is
    /// made.
    pub(crate) fn xref_count(&self, start: u64, end: u64) -> u32 {
        let refs = self.refs.within(start..end.max(start + 1));
        u32::try_from(xref_layout(refs, self.l.options.xrefs).len()).unwrap_or(u32::MAX)
    }

    /// x86 jump tables: for each computed jump with resolved cases, the
    /// data its function refers to whose entries (offsets from the table
    /// as compilers lay out position-independent switches, or absolute
    /// addresses) are those cases; named `jpt_` after the jump, the case
    /// the guard branches to otherwise `def_`.
    fn tables(&mut self) {
        let Some(Decoder::X86(_)) = self.l.decoder else {
            return;
        };
        let program = self.db.program();
        let mut found = Vec::new();
        for (_, f) in program.functions.iter() {
            let id = program.function_at(f.entry);
            for &block_id in &f.blocks {
                let (Some(table), Some(block)) =
                    (program.table(block_id), program.blocks.get(block_id))
                else {
                    continue;
                };
                if !matches!(
                    block.exit,
                    Exit::Jump(Destination::Indirect | Destination::Pointer(_))
                ) {
                    continue;
                }
                let cases: BTreeSet<u64> = table.targets.iter().copied().collect();
                let Some(id) = id else { continue };
                let candidates: BTreeSet<u64> = self
                    .refs
                    .from_function(id)
                    .filter(|r| !self.image.is_code(r.target) || !cases.contains(&r.target))
                    .map(|r| r.target)
                    .collect();
                let jump = self.last_instruction(block.start, block.end);
                for base in candidates {
                    if let Some(t) = self.table_at(base, &cases) {
                        found.push((jump, t));
                        // The guard's branch around the table.
                        let default = f
                            .blocks
                            .iter()
                            .filter_map(|&b| program.blocks.get(b))
                            .filter(|g| g.end == block.start)
                            .find_map(|g| {
                                if let Exit::Branch(Destination::Address(to)) = g.exit {
                                    Some(to)
                                } else {
                                    None
                                }
                            });
                        if let Some(default) = default {
                            self.l
                                .give(default, dummy("def", jump), NameKind::Code, true);
                        }
                        break;
                    }
                }
            }
        }
        for (jump, t) in found {
            self.l
                .give(t.base, dummy("jpt", jump), NameKind::Data, true);
            self.tables.insert(t.base, t);
        }
    }

    /// The table at `base` whose entries go to `cases`, if one is there.
    fn table_at(&self, base: u64, cases: &BTreeSet<u64>) -> Option<Table> {
        let entry = |width: u8, relative: bool, k: u64| -> Option<u64> {
            let at = base.checked_add(k * u64::from(width))?;
            let bytes = self.bytes(at, u64::from(width));
            if bytes.len() != usize::from(width) {
                return None;
            }
            let mut v = [0u8; 8];
            v.get_mut(..bytes.len())?.copy_from_slice(bytes);
            let value = u64::from_le_bytes(v);
            if relative {
                let offset = i64::from(i32::from_le_bytes([v[0], v[1], v[2], v[3]]));
                Some(base.wrapping_add_signed(offset))
            } else {
                Some(value)
            }
        };
        for (width, relative) in [(4, true), (8, false), (4, false)] {
            if !entry(width, relative, 0).is_some_and(|t| cases.contains(&t)) {
                continue;
            }
            let count = (0..4096)
                .take_while(|&k| entry(width, relative, k).is_some_and(|t| cases.contains(&t)))
                .count() as u64;
            return Some(Table {
                base,
                width,
                count,
                relative,
            });
        }
        None
    }

    /// The address of the last instruction of the block `start..end`.
    pub(crate) fn last_instruction(&self, start: u64, end: u64) -> u64 {
        let mut pc = start;
        let mut last = start;
        while pc < end {
            let Some(len) = length(self.l.decoder, self.bytes(pc, 15)) else {
                break;
            };
            last = pc;
            pc += len;
        }
        last
    }
}

/// The text of the user's string of `bytes` (its NUL the last), UTF-16 if
/// `wide`; what is not text replaced.
fn user_text(bytes: &[u8], wide: bool) -> String {
    if wide {
        let units = bytes
            .as_chunks::<2>()
            .0
            .iter()
            .map(|&pair| u16::from_le_bytes(pair))
            .take_while(|&unit| unit != 0);
        char::decode_utf16(units)
            .map(|c| c.unwrap_or(char::REPLACEMENT_CHARACTER))
            .collect()
    } else {
        let text = bytes.split(|&byte| byte == 0).next().unwrap_or_default();
        String::from_utf8_lossy(text).into_owned()
    }
}

/// The image's mapped sections by address, overlaps clipped, and the
/// mapped bytes no section covers (headers) as `LOAD` sections.
fn sections(image: &Image<'_>) -> Vec<Section> {
    let mut found: Vec<(u64, u64, String)> = image
        .sections
        .iter()
        .filter(|s| s.size > 0 && image.is_mapped(s.start))
        .map(|s| (s.start, s.start + s.size, s.name.clone()))
        .collect();
    found.sort_by_key(|&(start, end, _)| (start, end));
    let mut out: Vec<Section> = Vec::new();
    for segment in &image.segments {
        let (s_start, s_end) = (segment.start, segment.start + segment.size);
        let file_end = segment.start + segment.bytes.len() as u64;
        let p = segment.permissions;
        let permissions: Vec<&str> = [(p.read, "Read"), (p.write, "Write"), (p.execute, "Execute")]
            .into_iter()
            .filter_map(|(on, word)| on.then_some(word))
            .collect();
        let permissions = permissions.join("/");
        let push = |out: &mut Vec<Section>, start: u64, end: u64, name: &str| {
            let end = end.min(s_end);
            if end > start {
                out.push(Section {
                    name: name.to_owned(),
                    start,
                    end,
                    file_end: file_end.clamp(start, end),
                    code: image.code.iter().any(|r| r.start < end && start < r.end),
                    permissions: permissions.clone(),
                });
            }
        };
        let mut at = s_start;
        for (start, end, name) in found
            .iter()
            .filter(|(start, _, _)| *start >= s_start && *start < s_end)
        {
            let start = (*start).max(at);
            if start >= *end {
                continue;
            }
            if start > at {
                push(&mut out, at, start, "LOAD");
            }
            push(&mut out, start, *end, name);
            at = at.max((*end).min(s_end));
        }
        if at < s_end {
            push(&mut out, at, s_end, "LOAD");
        }
    }
    out
}

/// Marks the jumps (of the functions `owners`, one per jump) with a block
/// of another function between their ends ([`Jump::crosses`]): `blocks`
/// are every function's blocks as `(start, end, entry)`, by start.
pub(crate) fn mark_crossing(
    jumps: &mut [Jump],
    owners: &[Option<u64>],
    blocks: &[(u64, u64, u64)],
) {
    // Each block's next block of another function (or the end).
    let mut other = vec![blocks.len(); blocks.len()];
    let mut next = blocks.len();
    for (i, (slot, block)) in other.iter_mut().zip(blocks).enumerate().rev() {
        if blocks.get(i + 1).is_some_and(|after| after.2 != block.2) {
            next = i + 1;
        }
        *slot = next;
    }
    for (jump, owner) in jumps.iter_mut().zip(owners) {
        let Some(entry) = *owner else {
            continue;
        };
        let (lo, hi) = (jump.from.min(jump.to), jump.from.max(jump.to));
        // The first block starting after `lo`, else the first after it of
        // another function.
        let first = blocks.partition_point(|b| b.0 <= lo);
        let foreign = match blocks.get(first) {
            Some(b) if b.2 == entry => other.get(first).copied().unwrap_or(blocks.len()),
            Some(_) | None => first,
        };
        jump.crosses = blocks.get(foreign).is_some_and(|b| b.0 < hi);
    }
}

/// Gives every jump its lane among the jumps of its function (`owners`,
/// one per jump): interval colouring over the whole function, once, so a
/// lane never depends on what part of the function is on screen. The
/// shortest spans go innermost; each takes the first lane free over its
/// whole span (ends included); ties go by address, so the result is the
/// same on every build.
pub(crate) fn assign_lanes(jumps: &mut [Jump], owners: &[Option<u64>]) {
    let span = |j: &Jump| (j.from.min(j.to), j.from.max(j.to));
    let mut order: Vec<usize> = (0..jumps.len()).collect();
    order.sort_by_key(|&i| {
        let owner = owners.get(i).copied().flatten();
        let (lo, hi) = jumps.get(i).map_or((0, 0), span);
        (owner, hi - lo, lo, hi)
    });
    let mut function = None;
    // Each lane's spans, sorted by start, disjoint.
    let mut lanes: Vec<BTreeMap<u64, u64>> = Vec::new();
    for i in order {
        let owner = owners.get(i).copied().flatten();
        if owner != function {
            function = owner;
            lanes.clear();
        }
        let Some(jump) = jumps.get_mut(i) else {
            continue;
        };
        let (lo, hi) = span(jump);
        let free = |spans: &BTreeMap<u64, u64>| {
            spans
                .range(..=hi)
                .next_back()
                .is_none_or(|(_, &end)| end < lo)
        };
        let lane = lanes.iter().position(free).unwrap_or(lanes.len());
        if lane == lanes.len() {
            lanes.push(BTreeMap::new());
        }
        if let Some(spans) = lanes.get_mut(lane) {
            spans.insert(lo, hi);
        }
        jump.lane = u16::try_from(lane).unwrap_or(u16::MAX);
    }
}

/// `rbp`'s offset from the stack pointer on entry when `mov rbp, rsp`
/// follows the instructions `before` (as Intel text): 8 below it per push,
/// if only pushes move the stack pointer.
fn rbp_base(before: &[String]) -> Option<i64> {
    let pushes = before.iter().filter(|t| t.starts_with("push ")).count();
    let moved = before
        .iter()
        .any(|t| t.contains("rsp") && !t.starts_with("push "));
    if moved {
        return None;
    }
    i64::try_from(pushes).ok()?.checked_mul(-8)
}

#[cfg(test)]
mod tests {
    use super::{assign_lanes, mark_crossing, rbp_base};
    use crate::listing::Jump;

    fn jump(from: u64, to: u64) -> Jump {
        Jump {
            from,
            to,
            conditional: true,
            crosses: false,
            lane: 0,
        }
    }

    fn lanes(jumps: &[(u64, u64)], owners: &[Option<u64>]) -> Vec<u16> {
        let mut jumps: Vec<Jump> = jumps.iter().map(|&(f, t)| jump(f, t)).collect();
        assign_lanes(&mut jumps, owners);
        jumps.iter().map(|j| j.lane).collect()
    }

    #[test]
    fn nested_jumps_take_lanes_inside_out_and_disjoint_ones_share() {
        // An outer loop round two inner branches that do not overlap, and
        // a backward jump nested in the second.
        let got = lanes(
            &[(0x10, 0x80), (0x20, 0x30), (0x40, 0x70), (0x60, 0x50)],
            &[Some(0); 4],
        );
        assert_eq!(got, [2, 0, 1, 0]);
        // Spans that share an end are not disjoint.
        assert_eq!(lanes(&[(0x10, 0x20), (0x20, 0x30)], &[Some(0); 2]), [0, 1]);
    }

    #[test]
    fn lanes_restart_per_function_and_do_not_depend_on_the_order_given() {
        let jumps = [(0x10, 0x40), (0x20, 0x30), (0x110, 0x140)];
        let owners = [Some(0), Some(0), Some(0x100)];
        assert_eq!(lanes(&jumps, &owners), [1, 0, 0]);
        let reversed: Vec<(u64, u64)> = jumps.iter().rev().copied().collect();
        let owners_reversed: Vec<Option<u64>> = owners.iter().rev().copied().collect();
        assert_eq!(lanes(&reversed, &owners_reversed), [0, 0, 1]);
    }

    #[test]
    fn a_jump_crosses_when_another_functions_block_lies_between_its_ends() {
        // Function 0x100 in two runs of blocks round function 0x200, then
        // a part of 0x100 past a gap.
        let blocks = [
            (0x100, 0x110, 0x100),
            (0x110, 0x120, 0x100),
            (0x200, 0x210, 0x200),
            (0x300, 0x310, 0x100),
            (0x400, 0x410, 0x100),
        ];
        let crossing = |pairs: &[(u64, u64, u64)]| {
            let mut jumps: Vec<Jump> = pairs.iter().map(|&(f, t, _)| jump(f, t)).collect();
            let owners: Vec<Option<u64>> = pairs.iter().map(|&(_, _, o)| Some(o)).collect();
            mark_crossing(&mut jumps, &owners, &blocks);
            jumps.iter().map(|j| j.crosses).collect::<Vec<_>>()
        };
        assert_eq!(
            crossing(&[
                // Within a run of its blocks.
                (0x105, 0x115, 0x100),
                // Over the other function, both ways.
                (0x105, 0x305, 0x100),
                (0x305, 0x115, 0x100),
                // Over a gap holding no other function.
                (0x305, 0x405, 0x100),
                // The other function's own jump.
                (0x205, 0x20a, 0x200),
            ]),
            [false, true, true, false, false]
        );
    }

    #[test]
    fn rbp_sits_below_the_pushes_before_it_unless_the_stack_moves_otherwise() {
        let texts = |t: &[&str]| t.iter().map(|&t| t.to_owned()).collect::<Vec<_>>();
        assert_eq!(rbp_base(&texts(&["endbr64", "push rbp"])), Some(-8));
        assert_eq!(
            rbp_base(&texts(&["push r15", "xor eax, eax", "push rbp"])),
            Some(-16)
        );
        assert_eq!(rbp_base(&texts(&["push rbp", "sub rsp, 10h"])), None);
    }
}
