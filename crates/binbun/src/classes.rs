//! C++ classes from an image's run-time type information, under the
//! Itanium C++ ABI (§2.5 virtual tables, §2.9.5 `type_info` objects),
//! ELF images of 64-bit machines (x86-64, AArch64): the program's
//! [`Classes`].
//!
//! - **`type_info` objects**: a `_ZTI<type>` symbol, or by shape where
//!   a virtual table points to one: its second word points to its name
//!   string, a mangled class type (`5Shape`, `_ZTS` and the string
//!   parsing as `typeinfo name for` a class). Its layout says its bases:
//!   `__si_class_type_info` (24 bytes: one public non-virtual base at
//!   offset 0, the pointer at +16) and `__vmi_class_type_info` (flags at
//!   +16, the base count at +20, then per base its `type_info` and its
//!   offset and flags: offset `>> 8`, bit 0 virtual), by the symbol's size
//!   where it has one, else by shape (+16 points to a `type_info`: one
//!   base; else a count from 1 to 255 whose first base is one). A base
//!   whose `type_info` the image does not define (an import's) is not
//!   known. The primary base is the first non-virtual base at offset 0.
//! - **Virtual tables**: a `_ZTV<class>` symbol, or by shape a word 0
//!   (the offset to top of a primary table) followed by a pointer to a
//!   class's `type_info` and at least one pointer to code. The address
//!   point is past those two words; the slots are the words from there
//!   that point to code or are unknown (a relocation against another
//!   module's symbol: `__cxa_pure_virtual`) where code follows, up to the
//!   symbol's end and before the next table of the group (a non-zero
//!   offset to top followed by the same `type_info`: a secondary table,
//!   not read). A table whose `type_info` pointer is unknown (a
//!   relocation against an interposable symbol, as in a shared library)
//!   is its symbol's class; a base whose pointer is unknown is not known.
//! - **Methods**: a function whose mangling is a member of a class of the
//!   table (its scope renders as the class's name) and that is a slot of
//!   some primary table (virtual, so never static), or that is a
//!   constructor or destructor of it, takes that class's `this`; a slot
//!   with no such mangling, the join of the classes whose tables hold it
//!   (stripped: an inherited method sits in every derived table).
//! - **Slot names**: the last component of the slot function's mangling
//!   (a destructor `destructor`, a deleting one `deleting_destructor`,
//!   operators none).
//!
//! Words are read from memory the program cannot change once loaded
//! ([`ImageMemory`]: a relocated slot's known value), so tables in
//! writable data are not read.

use std::collections::{BTreeMap, BTreeSet};

use binbun_decompile::typing::{Classes, CxxClass};
use binbun_demangle::itanium::{self, Encoding, NameKind, Special, Type};
use binbun_loader::{Format, Image, Machine, SymbolKind};
use binbun_ssa::constant::ReadOnly as _;

use crate::manglings::scope;
use crate::memory::ImageMemory;

/// The bytes of a word (a pointer) on the machines read.
const WORD: u64 = 8;

/// The longest `type_info` name string read.
const NAME_LIMIT: u64 = 1024;

/// The most bases a `__vmi_class_type_info` is taken to list.
const BASE_LIMIT: u64 = 255;

/// The C++ classes of `image` (see the [module](self)); none for other
/// formats and machines.
pub fn classes(image: &Image<'_>) -> Classes {
    if image.format != Format::Elf || !matches!(image.machine, Machine::X86_64 | Machine::Aarch64) {
        return Classes::empty();
    }
    Reader::new(image).read()
}

/// What reading an image's classes has found so far.
struct Reader<'a> {
    /// The image.
    image: &'a Image<'a>,
    /// Its read-only memory.
    memory: ImageMemory<'a>,
    /// The symbols at each address, as stored.
    symbols: BTreeMap<u64, Vec<&'a str>>,
    /// The size of each `_ZTI`/`_ZTV` symbol, by address.
    sizes: BTreeMap<u64, u64>,
    /// The class of each `type_info` object (by address), `None` where the
    /// address is none.
    infos: BTreeMap<u64, Option<usize>>,
    /// The classes found.
    classes: Vec<CxxClass>,
    /// Each class by name.
    by_name: BTreeMap<String, usize>,
}

impl<'a> Reader<'a> {
    /// A reader of `image`.
    fn new(image: &'a Image<'a>) -> Self {
        let mut symbols: BTreeMap<u64, Vec<&str>> = BTreeMap::new();
        let mut sizes = BTreeMap::new();
        for symbol in &image.symbols {
            symbols
                .entry(symbol.address)
                .or_default()
                .push(symbol.name.as_str());
            if (symbol.name.starts_with("_ZTI") || symbol.name.starts_with("_ZTV"))
                && let Some(size) = symbol.size.filter(|&size| size > 0)
            {
                sizes.insert(symbol.address, size);
            }
        }
        Self {
            image,
            memory: ImageMemory::new(image),
            symbols,
            sizes,
            infos: BTreeMap::new(),
            classes: Vec::new(),
            by_name: BTreeMap::new(),
        }
    }

    /// The word at `address`, if known.
    fn word(&self, address: u64) -> Option<u64> {
        let bytes = u16::try_from(WORD).ok()?;
        self.memory.read(address, bytes).map(|bits| bits.low_u64())
    }

    /// The class a special symbol at `address` names (`_ZTV` where
    /// `vtable`, else `_ZTI`): its type rendered.
    fn special(&self, address: u64, vtable: bool) -> Option<String> {
        self.symbols.get(&address)?.iter().find_map(|name| {
            let symbol = itanium::parse(unversioned(name)).ok()?;
            let Encoding::Special(special) = symbol.encoding else {
                return None;
            };
            let ((Special::TypeInfo(ty), false) | (Special::VirtualTable(ty), true)) =
                (special, vtable)
            else {
                return None;
            };
            class_type(&symbol, ty)
        })
    }

    /// The class of the `type_info` object at `address`, found (with its
    /// bases) the first time it is asked for.
    fn info(&mut self, address: u64) -> Option<usize> {
        if let Some(&known) = self.infos.get(&address) {
            return known;
        }
        // Not a class while its bases are read (a cycle is none).
        self.infos.insert(address, None);
        let name = self
            .special(address, false)
            .or_else(|| self.info_name(address))?;
        let index = self.class(&name);
        self.infos.insert(address, Some(index));
        if let Some(class) = self.classes.get_mut(index) {
            class.type_info = Some(address);
        }
        let base = self.primary_base(address);
        if let Some(class) = self.classes.get_mut(index)
            && class.base.is_none()
        {
            class.base = base.filter(|&base| base != index);
        }
        Some(index)
    }

    /// The class named by the name string `type_info` object `address`
    /// points to, if it is a mangled class type.
    fn info_name(&self, address: u64) -> Option<String> {
        if !self.image.is_mapped(address) || self.image.is_code(address) {
            return None;
        }
        let string = self.word(address.checked_add(WORD)?)?;
        let mut bytes = Vec::new();
        for at in string..string.checked_add(NAME_LIMIT)? {
            let byte = self.memory.read(at, 1)?.low_u64();
            if byte == 0 {
                break;
            }
            bytes.push(u8::try_from(byte).ok()?);
        }
        let text = std::str::from_utf8(&bytes).ok()?;
        let symbol = itanium::parse(&format!("_ZTS{text}")).ok()?;
        let Encoding::Special(Special::TypeInfoName(ty)) = symbol.encoding else {
            return None;
        };
        class_type(&symbol, ty)
    }

    /// The primary base of the class whose `type_info` object is at
    /// `address` (see the [module](self)).
    fn primary_base(&mut self, address: u64) -> Option<usize> {
        let size = self.sizes.get(&address).copied();
        let single = match size {
            Some(size) => size == 3 * WORD,
            None => self
                .word(address + 2 * WORD)
                .is_some_and(|base| self.looks_like_info(base)),
        };
        if single {
            let base = self.word(address + 2 * WORD)?;
            return self.info(base);
        }
        if size.is_some_and(|size| size < 4 * WORD) {
            return None;
        }
        let count = self.memory.read(address + 2 * WORD + 4, 4)?.low_u64();
        if count == 0 || count > BASE_LIMIT {
            return None;
        }
        let first = address + 3 * WORD;
        if size.is_none()
            && !self
                .word(first)
                .is_some_and(|base| self.looks_like_info(base))
        {
            return None;
        }
        for k in 0..count {
            let entry = first + k * 2 * WORD;
            let (Some(base), Some(flags)) = (self.word(entry), self.word(entry + WORD)) else {
                continue;
            };
            let flags = flags.cast_signed();
            if flags & 1 == 0 && flags >> 8 == 0 {
                return self.info(base);
            }
        }
        None
    }

    /// Whether `address` is a `type_info` object's: known as one, by its
    /// symbol, or by its name string.
    fn looks_like_info(&self, address: u64) -> bool {
        matches!(self.infos.get(&address), Some(Some(_)))
            || self.special(address, false).is_some()
            || self.info_name(address).is_some()
    }

    /// The class named `name`, added if new.
    fn class(&mut self, name: &str) -> usize {
        if let Some(&index) = self.by_name.get(name) {
            return index;
        }
        let index = self.classes.len();
        self.classes.push(CxxClass {
            name: name.to_owned(),
            ..CxxClass::default()
        });
        self.by_name.insert(name.to_owned(), index);
        index
    }

    /// The primary virtual table at `start` (its offset to top), if one:
    /// its class and its slots, bounded by `end` where its symbol says.
    /// Its class is its `type_info`'s, else (the pointer's value unknown:
    /// a relocation against an interposable symbol) its symbol's.
    fn table(&mut self, start: u64, end: Option<u64>) -> Option<(usize, Vec<Option<u64>>)> {
        if self.word(start)? != 0 {
            return None;
        }
        let info = self.word(start + WORD);
        if info == Some(0) {
            return None;
        }
        let class = if let Some(info) = info {
            self.info(info)?
        } else {
            let name = self.special(start, true)?;
            self.class(&name)
        };
        let mut slots = Vec::new();
        let mut at = start + 2 * WORD;
        while end.is_none_or(|end| at + WORD <= end) {
            match self.word(at) {
                Some(target) if self.image.is_code(target) => slots.push(Some(target)),
                Some(_) => break,
                None => {
                    // Unknown: another module's function (a pure virtual
                    // one) where the table goes on, else its end.
                    let next = self.word(at + WORD);
                    let goes_on = match end {
                        Some(end) => at + 2 * WORD <= end && (info.is_none() || next != info),
                        None => next.is_some_and(|next| self.image.is_code(next)),
                    };
                    if !goes_on {
                        break;
                    }
                    slots.push(None);
                }
            }
            at += WORD;
        }
        (!slots.is_empty() || end.is_some()).then_some((class, slots))
    }

    /// Records the primary table at `start` (its symbol's end `end`).
    fn add_table(&mut self, start: u64, end: Option<u64>) {
        let Some((class, slots)) = self.table(start, end) else {
            return;
        };
        if slots.is_empty() && end.is_none() {
            return;
        }
        if let Some(class) = self.classes.get_mut(class)
            && class.vtable.is_none()
        {
            class.vtable = Some(start + 2 * WORD);
            class.slots = slots;
        }
    }

    /// Every class and table of the image, and its methods.
    fn read(mut self) -> Classes {
        let image = self.image;
        let specials: Vec<(u64, bool)> = image
            .symbols
            .iter()
            .filter(|symbol| symbol.kind != SymbolKind::Function)
            .filter_map(|symbol| {
                let vtable = symbol.name.starts_with("_ZTV");
                (vtable || symbol.name.starts_with("_ZTI")).then_some((symbol.address, vtable))
            })
            .collect();
        // `type_info` objects first, so a table whose `type_info` pointer
        // is unknown finds its class (with its bases) by name.
        for &(address, _) in specials.iter().filter(|&&(_, vtable)| !vtable) {
            self.info(address);
        }
        for &(address, _) in specials.iter().filter(|&&(_, vtable)| vtable) {
            let end = self.sizes.get(&address).map(|size| address + size);
            self.add_table(address, end);
        }
        // Stripped: tables by shape, in read-only data.
        let ranges: Vec<(u64, u64)> = image
            .segments
            .iter()
            .filter(|segment| !segment.permissions.execute)
            .map(|segment| (segment.start, segment.end()))
            .collect();
        let known: BTreeSet<u64> = self
            .classes
            .iter()
            .filter_map(|class| class.vtable)
            .collect();
        for (start, end) in ranges {
            let mut at = start.next_multiple_of(WORD);
            while at + 3 * WORD <= end {
                if !known.contains(&(at + 2 * WORD))
                    && self.word(at) == Some(0)
                    && self
                        .word(at + WORD)
                        .is_some_and(|info| info != 0 && self.image.is_mapped(info))
                    && self
                        .word(at + 2 * WORD)
                        .is_some_and(|slot| self.image.is_code(slot))
                {
                    self.add_table(at, None);
                }
                at += WORD;
            }
        }
        let methods = self.methods();
        for class in &mut self.classes {
            class.names = class
                .slots
                .iter()
                .map(|slot| slot.and_then(|entry| slot_name(&self.symbols, entry)))
                .collect();
        }
        Classes::new(self.classes, methods)
    }

    /// The class whose `this` each function takes (see the
    /// [module](self)).
    fn methods(&self) -> BTreeMap<u64, usize> {
        let mut holders: BTreeMap<u64, Vec<usize>> = BTreeMap::new();
        for (index, class) in self.classes.iter().enumerate() {
            for &entry in class.slots.iter().flatten() {
                holders.entry(entry).or_default().push(index);
            }
        }
        let mut methods = BTreeMap::new();
        for symbol in &self.image.symbols {
            if symbol.kind != SymbolKind::Function {
                continue;
            }
            let Ok(parsed) = itanium::parse(unversioned(&symbol.name)) else {
                continue;
            };
            if parsed.suffix.is_some() {
                continue;
            }
            let Some(class) = scope(&parsed)
                .and_then(|scope| parsed.prefix_text(scope))
                .and_then(|name| self.by_name.get(&name).copied())
            else {
                continue;
            };
            let special = matches!(
                parsed.last_name().map(|name| &name.kind),
                Some(NameKind::Constructor(_) | NameKind::Destructor(_))
            );
            if special || holders.contains_key(&symbol.address) {
                methods.insert(symbol.address, class);
            }
        }
        let classes = Classes::new(self.classes.clone(), BTreeMap::new());
        for (entry, holders) in holders {
            if methods.contains_key(&entry) || self.symbols.contains_key(&entry) {
                continue;
            }
            let mut holders = holders.into_iter();
            let first = holders.next();
            if let Some(class) = holders
                .try_fold(first, |joined, other| Some(classes.join(joined?, other)))
                .flatten()
            {
                methods.insert(entry, class);
            }
        }
        methods
    }
}

/// `name` without its ELF symbol version (`@VERSION`, `@@VERSION`).
fn unversioned(name: &str) -> &str {
    name.split('@').next().unwrap_or(name)
}

/// Type `ty` of `symbol` rendered, if it is a class (a named type).
fn class_type(symbol: &itanium::Symbol, ty: itanium::TypeId) -> Option<String> {
    matches!(symbol.ty(ty)?, Type::Named { .. })
        .then(|| symbol.type_text(ty))
        .flatten()
}

/// The method name of the function at `entry` (by its symbols, as
/// `symbols` lists them) as a C identifier: its mangling's last
/// component; a destructor `destructor`, a deleting one
/// `deleting_destructor`.
fn slot_name(symbols: &BTreeMap<u64, Vec<&str>>, entry: u64) -> Option<String> {
    symbols.get(&entry)?.iter().find_map(|name| {
        let symbol = itanium::parse(unversioned(name)).ok()?;
        match &symbol.last_name()?.kind {
            NameKind::Source(name) => Some(name.clone()),
            NameKind::Destructor(0) => Some("deleting_destructor".to_owned()),
            NameKind::Destructor(_) => Some("destructor".to_owned()),
            NameKind::Operator(_) | NameKind::Constructor(_) => None,
        }
    })
}
