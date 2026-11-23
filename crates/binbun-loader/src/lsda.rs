//! Itanium C++ ABI exception tables (language-specific data areas, LSDAs),
//! as GCC's and LLVM's personality routines read them
//! (`libstdc++-v3/libsupc++/eh_personality.cc`, `libcxxabi`'s
//! `cxa_personality.cpp`) and compilers emit them (LLVM's `EHStreamer`):
//!
//! ```text
//! header      landing-pad base encoding (u8) [base: the function start if
//!             omitted], type table encoding (u8) [uleb128 offset of its
//!             end], call-site encoding (u8), uleb128 call-site table length
//! call sites  start, length (from the function start), landing pad (from
//!             the landing-pad base; 0: none), uleb128 action (1 + its
//!             offset in the action table; 0: cleanup only)
//! actions     sleb128 filter (> 0: catch, type table index; 0: cleanup;
//!             < 0: exception specification, -filter - 1 bytes past the type
//!             table's end), sleb128 offset of the next action from this
//!             field (0: the last)
//! types       type_info pointers, indexed from 1 backwards from the end;
//!             after it, exception specifications: uleb128 type indices
//!             ending in 0
//! ```
//!
//! A pointer of value 0 is null whatever its encoding (no base is added),
//! as the personality routines read them.

use core::fmt;
use std::collections::{HashMap, HashSet};

use binbun_semantics::core::Memory;
use gimli::constants::{self, DwEhPe};
use gimli::{EndianSlice, Reader, RunTimeEndian};

use crate::{CallSite, Clause, ExceptionTable, Image, Referent, Symbol, SymbolKind, TypeInfo};

/// The most bytes of one exception table read.
pub const LIMIT: usize = 1 << 16;

/// The most actions one chain is followed for: real chains have one per
/// `catch` of a `try` (and of its enclosing ones).
const CHAIN_LIMIT: usize = 1024;

/// The most bytes of a `type_info` object's name read.
const NAME_LIMIT: usize = 1024;

/// `DW_EH_PE_signed`: a signed address-sized value (gimli lacks it).
const DW_EH_PE_SIGNED: DwEhPe = DwEhPe(0x08);

/// How the image's pointers read: their size and byte order, and what
/// text- and data-relative encodings count from.
#[derive(Clone, Copy, Debug)]
pub struct Layout {
    /// The byte order.
    pub endian: RunTimeEndian,
    /// The size of an address in bytes (4 or 8).
    pub address_size: u8,
    /// Where `.text` is.
    pub text: Option<u64>,
    /// Where data-relative pointers count from (the GOT).
    pub data: Option<u64>,
}

/// What is wrong in an exception table.
#[derive(Clone, Debug)]
enum Damage {
    /// A field does not parse.
    Read(gimli::Error),
    /// A field lies outside the bytes read.
    Outside,
    /// An indirect pointer's slot does not read.
    Unreadable(u64),
    /// An action names a type, but the table has no type table.
    NoTypeTable,
    /// The type table's entries are of variable size (LEB128).
    UnsizedTypes,
    /// An exception specification names no type (a null entry).
    NullSpecification,
    /// An action chain comes back to an action.
    Loop,
    /// An action chain is longer than [`CHAIN_LIMIT`].
    TooLong,
}

impl From<gimli::Error> for Damage {
    fn from(error: gimli::Error) -> Self {
        Self::Read(error)
    }
}

impl fmt::Display for Damage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read(error) => write!(f, "{error}"),
            Self::Outside => f.write_str("a field lies outside the table"),
            Self::Unreadable(slot) => write!(f, "the pointer at {slot:#x} does not read"),
            Self::NoTypeTable => f.write_str("an action names a type, but there is no type table"),
            Self::UnsizedTypes => f.write_str("the type table's entries have no fixed size"),
            Self::NullSpecification => f.write_str("an exception specification names no type"),
            Self::Loop => f.write_str("an action chain loops"),
            Self::TooLong => write!(f, "an action chain is longer than {CHAIN_LIMIT} actions"),
        }
    }
}

/// An exception table's call sites, and what is damaged in it.
#[derive(Clone, Debug, Default)]
pub struct Parsed {
    /// The call sites before the damage, if any, with the clauses of each
    /// up to where its action chain is damaged.
    pub call_sites: Vec<CallSite>,
    /// What is damaged.
    pub damage: Vec<String>,
}

/// One exception table being read.
struct Table<'a> {
    /// Its bytes.
    bytes: &'a [u8],
    /// Its address.
    lsda: u64,
    /// The start of its function.
    function: u64,
    layout: Layout,
    /// Reads an indirect pointer's slot.
    deref: &'a dyn Fn(u64) -> Option<u64>,
    /// The encoding of the call-site table.
    call_site_encoding: DwEhPe,
    /// The type table's encoding and the offset of its end.
    types: Option<(DwEhPe, usize)>,
    /// The offset of the action table.
    actions: usize,
}

/// The call sites of the exception table `bytes` at `lsda`, of the
/// function starting at `function` in an image laid out as `layout`, whose
/// pointer-sized slots `deref` reads.
pub fn parse(
    bytes: &[u8],
    lsda: u64,
    function: u64,
    layout: Layout,
    deref: &dyn Fn(u64) -> Option<u64>,
) -> Parsed {
    let mut parsed = Parsed::default();
    let mut table = Table {
        bytes,
        lsda,
        function,
        layout,
        deref,
        call_site_encoding: constants::DW_EH_PE_omit,
        types: None,
        actions: 0,
    };
    let (mut entries, landing_pad_base) = match table.header() {
        Ok(header) => header,
        Err(damage) => {
            parsed.damage.push(damage.to_string());
            return parsed;
        }
    };
    // Call sites share action chains.
    let mut chains: HashMap<u64, (Vec<Clause>, Vec<i64>)> = HashMap::new();
    while !entries.is_empty() {
        let at = table.address(&entries);
        let (mut call_site, action) = match table.call_site(&mut entries, landing_pad_base) {
            Ok(entry) => entry,
            Err(damage) => {
                parsed
                    .damage
                    .push(format!("call site at {at:#x}: {damage}"));
                break;
            }
        };
        (call_site.clauses, call_site.selectors) = match (call_site.landing_pad, action) {
            (None, _) => (Vec::new(), Vec::new()),
            (Some(_), 0) => (vec![Clause::Cleanup], vec![0]),
            (Some(_), action) => chains
                .entry(action)
                .or_insert_with(|| {
                    let mut chain = (Vec::new(), Vec::new());
                    if let Err(damage) = table.chain(action, &mut chain) {
                        parsed
                            .damage
                            .push(format!("action {action} of call site at {at:#x}: {damage}"));
                    }
                    chain
                })
                .clone(),
        };
        parsed.call_sites.push(call_site);
    }
    parsed
}

impl<'a> Table<'a> {
    /// Reads the header: the call-site table's entries and the landing-pad
    /// base.
    fn header(&mut self) -> Result<(EndianSlice<'a, RunTimeEndian>, u64), Damage> {
        let mut reader = self.at(0)?;
        let base_encoding = DwEhPe(reader.read_u8()?);
        let landing_pad_base = if base_encoding == constants::DW_EH_PE_omit {
            self.function
        } else {
            self.pointer(&mut reader, base_encoding)?
        };
        let type_encoding = DwEhPe(reader.read_u8()?);
        if type_encoding != constants::DW_EH_PE_omit {
            let offset = usize::try_from(reader.read_uleb128()?).map_err(|_| Damage::Outside)?;
            let end = self
                .offset(&reader)
                .checked_add(offset)
                .ok_or(Damage::Outside)?;
            self.types = Some((type_encoding, end));
        }
        self.call_site_encoding = DwEhPe(reader.read_u8()?);
        let length = usize::try_from(reader.read_uleb128()?).map_err(|_| Damage::Outside)?;
        let entries = reader.split(length)?;
        self.actions = self.offset(&reader);
        Ok((entries, landing_pad_base))
    }

    /// Reads a call-site entry: the call site, without its clauses, and its
    /// action.
    fn call_site(
        &self,
        entries: &mut EndianSlice<'a, RunTimeEndian>,
        landing_pad_base: u64,
    ) -> Result<(CallSite, u64), Damage> {
        let start = self.pointer(entries, self.call_site_encoding)?;
        let length = self.pointer(entries, self.call_site_encoding)?;
        let landing_pad = self.pointer(entries, self.call_site_encoding)?;
        let action = entries.read_uleb128()?;
        let start = self.sized(self.function.wrapping_add(start));
        let call_site = CallSite {
            start,
            end: self.sized(start.wrapping_add(length)),
            landing_pad: (landing_pad != 0)
                .then(|| self.sized(landing_pad_base.wrapping_add(landing_pad))),
            clauses: Vec::new(),
            selectors: Vec::new(),
        };
        Ok((call_site, action))
    }

    /// Appends the clauses of the action chain starting at `action` (1 +
    /// its offset in the action table), and their selectors (filters), to
    /// `chain`.
    fn chain(&self, action: u64, chain: &mut (Vec<Clause>, Vec<i64>)) -> Result<(), Damage> {
        let mut at = usize::try_from(action - 1)
            .ok()
            .and_then(|offset| self.actions.checked_add(offset))
            .ok_or(Damage::Outside)?;
        let mut seen = HashSet::new();
        for _ in 0..CHAIN_LIMIT {
            if !seen.insert(at) {
                return Err(Damage::Loop);
            }
            let mut reader = self.at(at)?;
            let filter = reader.read_sleb128()?;
            let next_at = self.offset(&reader);
            let next = reader.read_sleb128()?;
            chain.0.push(self.clause(filter)?);
            chain.1.push(filter);
            if next == 0 {
                return Ok(());
            }
            at = isize::try_from(next)
                .ok()
                .and_then(|next| next_at.checked_add_signed(next))
                .ok_or(Damage::Outside)?;
        }
        Err(Damage::TooLong)
    }

    /// The clause of an action's filter.
    fn clause(&self, filter: i64) -> Result<Clause, Damage> {
        match filter.cmp(&0) {
            core::cmp::Ordering::Equal => Ok(Clause::Cleanup),
            core::cmp::Ordering::Greater => Ok(self
                .type_info(filter.unsigned_abs())?
                .map_or(Clause::CatchAll, Clause::Catch)),
            core::cmp::Ordering::Less => {
                let (_, end) = self.types.ok_or(Damage::NoTypeTable)?;
                let at = usize::try_from(filter.unsigned_abs() - 1)
                    .ok()
                    .and_then(|offset| end.checked_add(offset))
                    .ok_or(Damage::Outside)?;
                let mut reader = self.at(at)?;
                let mut types = Vec::new();
                loop {
                    let index = reader.read_uleb128()?;
                    if index == 0 {
                        return Ok(Clause::Filter(types));
                    }
                    types.push(self.type_info(index)?.ok_or(Damage::NullSpecification)?);
                }
            }
        }
    }

    /// The type of type table entry `index` (from 1), none if null (a
    /// catch-all). Its object is not named yet ([`name`]).
    fn type_info(&self, index: u64) -> Result<Option<TypeInfo>, Damage> {
        let (encoding, end) = self.types.ok_or(Damage::NoTypeTable)?;
        let size = fixed_size(encoding, self.layout.address_size).ok_or(Damage::UnsizedTypes)?;
        let at = usize::try_from(index)
            .ok()
            .and_then(|index| index.checked_mul(size))
            .and_then(|offset| end.checked_sub(offset))
            .ok_or(Damage::Outside)?;
        let value = self.value(&mut self.at(at)?, encoding)?;
        if value == 0 {
            return Ok(None);
        }
        let object = if encoding.is_indirect() {
            Referent {
                slot: Some(value),
                ..Referent::default()
            }
        } else {
            Referent {
                address: Some(value),
                ..Referent::default()
            }
        };
        Ok(Some(TypeInfo { object, name: None }))
    }

    /// The pointer of encoding `encoding` that `reader` starts with, read
    /// through its slot if indirect.
    fn pointer(
        &self,
        reader: &mut EndianSlice<'a, RunTimeEndian>,
        encoding: DwEhPe,
    ) -> Result<u64, Damage> {
        let value = self.value(reader, encoding)?;
        if encoding.is_indirect() && value != 0 {
            (self.deref)(value).ok_or(Damage::Unreadable(value))
        } else {
            Ok(value)
        }
    }

    /// The value of encoding `encoding` that `reader` starts with, its base
    /// added (unless 0), not read through a slot.
    fn value(
        &self,
        reader: &mut EndianSlice<'a, RunTimeEndian>,
        encoding: DwEhPe,
    ) -> Result<u64, Damage> {
        let size = self.layout.address_size;
        let application = encoding.application();
        if application == constants::DW_EH_PE_aligned {
            // An address-sized word at the next multiple of its size.
            let at = self.offset(reader);
            let padding = at.next_multiple_of(usize::from(size)) - at;
            reader.skip(padding)?;
            return Ok(reader.read_address(size)?);
        }
        let at = self.address(reader);
        let raw = match encoding.format() {
            constants::DW_EH_PE_absptr => reader.read_address(size)?,
            DW_EH_PE_SIGNED => match size {
                4 => i64::from(reader.read_i32()?).cast_unsigned(),
                _ => reader.read_i64()?.cast_unsigned(),
            },
            constants::DW_EH_PE_uleb128 => reader.read_uleb128()?,
            constants::DW_EH_PE_udata2 => u64::from(reader.read_u16()?),
            constants::DW_EH_PE_udata4 => u64::from(reader.read_u32()?),
            constants::DW_EH_PE_udata8 => reader.read_u64()?,
            constants::DW_EH_PE_sleb128 => reader.read_sleb128()?.cast_unsigned(),
            constants::DW_EH_PE_sdata2 => i64::from(reader.read_i16()?).cast_unsigned(),
            constants::DW_EH_PE_sdata4 => i64::from(reader.read_i32()?).cast_unsigned(),
            constants::DW_EH_PE_sdata8 => reader.read_i64()?.cast_unsigned(),
            _ => return Err(gimli::Error::UnknownPointerEncoding(encoding).into()),
        };
        if raw == 0 {
            return Ok(0);
        }
        let base = match application {
            constants::DW_EH_PE_absptr => 0,
            constants::DW_EH_PE_pcrel => at,
            constants::DW_EH_PE_funcrel => self.function,
            constants::DW_EH_PE_textrel => self
                .layout
                .text
                .ok_or(gimli::Error::TextRelativePointerButTextBaseIsUndefined)?,
            constants::DW_EH_PE_datarel => self
                .layout
                .data
                .ok_or(gimli::Error::DataRelativePointerButDataBaseIsUndefined)?,
            _ => return Err(gimli::Error::UnknownPointerEncoding(encoding).into()),
        };
        Ok(self.sized(base.wrapping_add(raw)))
    }

    /// `value` as an address: wrapped to the address size.
    fn sized(&self, value: u64) -> u64 {
        if self.layout.address_size == 4 {
            value & u64::from(u32::MAX)
        } else {
            value
        }
    }

    /// A reader of the bytes from `offset` on.
    fn at(&self, offset: usize) -> Result<EndianSlice<'a, RunTimeEndian>, Damage> {
        self.bytes
            .get(offset..)
            .map(|bytes| EndianSlice::new(bytes, self.layout.endian))
            .ok_or(Damage::Outside)
    }

    /// The offset `reader` is at.
    fn offset(&self, reader: &EndianSlice<'a, RunTimeEndian>) -> usize {
        self.bytes.len() - reader.len()
    }

    /// The address `reader` is at.
    fn address(&self, reader: &EndianSlice<'a, RunTimeEndian>) -> u64 {
        self.sized(self.lsda.wrapping_add(self.offset(reader) as u64))
    }
}

/// The size of a value of encoding `encoding`, if fixed.
fn fixed_size(encoding: DwEhPe, address_size: u8) -> Option<usize> {
    match encoding.format() {
        constants::DW_EH_PE_absptr | DW_EH_PE_SIGNED => Some(usize::from(address_size)),
        constants::DW_EH_PE_udata2 | constants::DW_EH_PE_sdata2 => Some(2),
        constants::DW_EH_PE_udata4 | constants::DW_EH_PE_sdata4 => Some(4),
        constants::DW_EH_PE_udata8 | constants::DW_EH_PE_sdata8 => Some(8),
        _ => None,
    }
}

/// Names what `image`'s exception tables refer to: an indirect pointer's
/// slot becomes the import it holds or the address stored there (its
/// relocation's target, else its bytes), an address the symbol there, and
/// each catch type its demangled name (from its `type_info` symbol, else
/// from the mangled name the object stores). `word` and `little` are the
/// size and byte order of the image's pointers.
pub fn name(image: &mut Image<'_>, word: usize, little: bool) {
    let mut tables = core::mem::take(&mut image.exception_tables);
    let imports: HashMap<u64, &str> = image
        .imports
        .iter()
        .map(|import| (import.slot, import.name.as_str()))
        .collect();
    for referent in referents(&mut tables) {
        through_slot(image, &imports, word, little, referent);
    }
    let wanted: HashSet<u64> = referents(&mut tables)
        .filter_map(|referent| referent.address)
        .collect();
    let mut symbols: HashMap<u64, &Symbol> = HashMap::new();
    for symbol in image.symbols.iter().filter(|s| wanted.contains(&s.address)) {
        symbols
            .entry(symbol.address)
            .and_modify(|best| {
                if rank(symbol) < rank(best) {
                    *best = symbol;
                }
            })
            .or_insert(symbol);
    }
    for referent in referents(&mut tables) {
        if referent.symbol.is_none() {
            referent.symbol = referent
                .address
                .and_then(|address| symbols.get(&address))
                .map(|symbol| symbol.name.clone());
        }
    }
    for type_info in type_infos(&mut tables) {
        type_info.name = type_name(image, &type_info.object, word, little);
    }
    image.exception_tables = tables;
}

/// Every referent of `tables`: personality routines and `type_info`
/// objects.
fn referents(tables: &mut [ExceptionTable]) -> impl Iterator<Item = &mut Referent> {
    let mut personalities = Vec::new();
    let mut types = Vec::new();
    for table in tables {
        personalities.extend(table.personality.as_mut());
        types.extend(
            table
                .call_sites
                .iter_mut()
                .flat_map(|call_site| call_site.clauses.iter_mut())
                .flat_map(clause_types)
                .map(|type_info| &mut type_info.object),
        );
    }
    personalities.into_iter().chain(types)
}

/// Every catch type of `tables`.
fn type_infos(tables: &mut [ExceptionTable]) -> impl Iterator<Item = &mut TypeInfo> {
    tables
        .iter_mut()
        .flat_map(|table| table.call_sites.iter_mut())
        .flat_map(|call_site| call_site.clauses.iter_mut())
        .flat_map(clause_types)
}

/// The types `clause` names.
fn clause_types(clause: &mut Clause) -> &mut [TypeInfo] {
    match clause {
        Clause::Catch(type_info) => core::slice::from_mut(type_info),
        Clause::Filter(types) => types,
        Clause::CatchAll | Clause::Cleanup => &mut [],
    }
}

/// Resolves `referent`'s slot, if indirect: to the import it holds, else
/// to the address stored in it.
fn through_slot(
    image: &Image<'_>,
    imports: &HashMap<u64, &str>,
    word: usize,
    little: bool,
    referent: &mut Referent,
) {
    let (None, Some(slot)) = (referent.address, referent.slot) else {
        return;
    };
    if let Some(&name) = imports.get(&slot) {
        referent.symbol = Some(name.to_owned());
    } else {
        referent.address = stored(image, slot, word, little);
    }
}

/// The address stored at `at`: its relocation's target, else its bytes
/// (none if 0).
fn stored(image: &Image<'_>, at: u64, word: usize, little: bool) -> Option<u64> {
    let index = image.pointers.partition_point(|p| p.at < at);
    match image.pointers.get(index) {
        Some(pointer) if pointer.at == at => Some(pointer.target),
        _ => image
            .read_word(at, word, little)
            .filter(|&value| value != 0),
    }
}

/// How well `symbol` names a personality routine or `type_info` object:
/// lower is better.
fn rank(symbol: &Symbol) -> u8 {
    if symbol.name.starts_with("_ZTI") {
        return 0;
    }
    match symbol.kind {
        SymbolKind::Function | SymbolKind::Data => 1,
        SymbolKind::Other => 2,
    }
}

/// The demangled name of the type whose `type_info` object is `object`:
/// from the object's symbol (`_ZTI` and the mangled type, and a version
/// after `@`), else from the mangled name it stores after its virtual table
/// pointer (`*` first for a type local to its unit, as GCC marks them).
fn type_name(image: &Image<'_>, object: &Referent, word: usize, little: bool) -> Option<String> {
    if let Some(name) = object
        .symbol
        .as_deref()
        .and_then(|symbol| symbol.split('@').next()?.strip_prefix("_ZTI"))
        .and_then(demangle_type)
    {
        return Some(name);
    }
    let name_at = stored(
        image,
        object.address?.checked_add(word as u64)?,
        word,
        little,
    )?;
    let mut bytes = vec![0; NAME_LIMIT];
    let read = image.read(name_at, &mut bytes).unwrap_or(0);
    let bytes = bytes.get(..read)?;
    let length = bytes.iter().position(|&byte| byte == 0)?;
    let name = core::str::from_utf8(bytes.get(..length)?).ok()?;
    demangle_type(name.strip_prefix('*').unwrap_or(name))
}

/// The demangled type of mangled type `mangled` (`St9exception`:
/// `std::exception`).
fn demangle_type(mangled: &str) -> Option<String> {
    let symbol = cpp_demangle::Symbol::new(format!("_ZTI{mangled}")).ok()?;
    let demangled = symbol.demangle().ok()?;
    demangled.strip_prefix("typeinfo for ").map(str::to_owned)
}
