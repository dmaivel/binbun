//! Microsoft x64 exception handling data: what the language-specific
//! handler that a function's unwind information names reads, from the
//! data after the handler's RVA in `.xdata` ([`FrameHandler`]).
//!
//! - **Structured exception handling** (`__C_specific_handler`,
//!   `__GSHandlerCheck_SEH`): a `SCOPE_TABLE`, a count then `{Begin, End,
//!   Handler, JumpTarget}` RVAs. A `JumpTarget` of 0 makes the scope a
//!   `__finally`, `Handler` its termination handler; else `Handler` is the
//!   filter (an RVA of code, or a constant such as 1,
//!   `EXCEPTION_EXECUTE_HANDLER`) and `JumpTarget` the `__except` block.
//! - **C++** (`__CxxFrameHandler3`, `__GSHandlerCheck_EH`): the RVA of a
//!   `FuncInfo` (a magic number `0x1993052x`, then the unwind map, try
//!   block map with handler arrays, and IP-to-state map, fixed-size records
//!   of RVAs and integers).
//! - **C++, compressed** (`__CxxFrameHandler4`, `__GSHandlerCheck_EH4`,
//!   the default since Visual Studio 2019): the RVA of a `FuncInfo4`, a
//!   header byte saying which fields follow, its maps in variable-length
//!   unsigned integers (the low bits of the first byte give the length:
//!   `0` one byte, `01` two, `011` three, `0111` four, else a whole 32-bit
//!   word follows) and RVAs. An unwind entry's first integer holds its
//!   kind (low two bits: none, destructor of an object, destructor through
//!   a pointer, a funclet) and how far back the entry of the state it
//!   unwinds to starts (0: none); IP-to-state entries are deltas from the
//!   start of the code they map (a separated map has one map per part:
//!   the function, each funclet), states biased by one; a handler's flags byte says
//!   which of its fields (adjectives, type, catch object, continuation
//!   addresses) are present.
//!
//! The handler is named by the import its thunk jumps through (`jmp
//! [rip+slot]`) or the symbol at its address; a statically linked handler
//! without a name is recognised by `FuncInfo`'s magic number only.
//!
//! The funclets the tables name (filters, termination handlers, catch
//! blocks, unwind funclets: code the handler calls with the function's
//! frame) are linked to the function as [`Funclet`]s. An `__except` block
//! is code of the function that the runtime jumps to; it is reached
//! through the calls of its guarded range (as a landing pad is), so it is
//! not listed apart: a range without calls (only faulting instructions)
//! would lead to it from nowhere recovery follows.
//!
//! A handled function's establisher frame, which the runtime hands its
//! funclets, is placed by its `UNWIND_INFO`'s codes ([`establisher`],
//! [`FrameHandler::establisher`]).

use std::collections::{BTreeMap, BTreeSet};

use binbun_semantics::core::memory::Memory;

use crate::{
    Catch, CxxTable, CxxVersion, Destructor, FrameHandler, Funclet, FuncletKind, HandlerTable,
    Image, Part, Referent, Scope, ScopeAction, SehFilter, StateRange, TryBlock, TypeInfo,
    UnwindState,
};

/// A function whose unwind information names an exception handler.
pub struct Handled {
    /// The function's start.
    pub function: u64,
    /// Where its handler's RVA is stored.
    pub at: u64,
    /// The handler's address.
    pub handler: u64,
    /// How far its establisher frame is below its entry stack pointer
    /// ([`establisher`]).
    pub establisher: Option<u64>,
}

/// The kind of language-specific data a handler reads, by its name.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Scopes,
    Cxx3,
    Cxx4,
}

/// `FuncInfo`'s magic numbers (the low 29 bits of its first word).
const MAGIC: [u32; 3] = [0x1993_0520, 0x1993_0521, 0x1993_0522];

/// The 32-bit little-endian word at `at`.
fn word(image: &Image<'_>, at: u64) -> Option<u32> {
    let mut bytes = [0u8; 4];
    (image.read(at, &mut bytes) == Ok(4)).then(|| u32::from_le_bytes(bytes))
}

/// How far the establisher frame of a function is below its stack
/// pointer at entry (where the return address is), from its `UNWIND_INFO`
/// (`info`: the header and the unwind codes): what its prologue pushes and
/// allocates (the codes, listed last-executed first, each a depth: a push
/// 8, an allocation its size, a machine frame 40 or 48, the others none)
/// up to the stack pointer the frame register is set from (`UWOP_SET_FPREG`:
/// the establisher frame is then the frame register minus 16 × its
/// offset, the stack pointer when it was set), or all of it without a
/// frame register (the stack pointer after the prologue).
pub(crate) fn establisher(info: &[u8]) -> Option<u64> {
    let &[version_flags, _, count, _] = info.get(..4)? else {
        return None;
    };
    let version = version_flags & 7;
    let codes = info.get(4..4 + 2 * usize::from(count))?;
    let slot = |index: usize| -> Option<u64> {
        let bytes = codes.get(2 * index..2 * index + 2)?;
        Some(u64::from(u16::from_le_bytes([
            *bytes.first()?,
            *bytes.get(1)?,
        ])))
    };
    let mut depth = 0u64;
    let mut index = 0;
    while index < usize::from(count) {
        let code = slot(index)?;
        let operand = code >> 12;
        let (add, slots) = match (code >> 8) & 0xf {
            0 => (8, 1),
            1 if operand == 0 => (slot(index + 1)? * 8, 2),
            1 => (slot(index + 1)? | (slot(index + 2)? << 16), 3),
            2 => (operand * 8 + 8, 1),
            // The codes after it in the list ran before the frame register
            // was set: the establisher frame is the stack pointer then.
            3 => {
                depth = 0;
                (0, 1)
            }
            // Version 2's `UWOP_EPILOG`.
            6 if version >= 2 => (0, 1),
            4 | 6 | 8 => (0, 2),
            5 | 7 | 9 => (0, 3),
            10 => (if operand == 0 { 40 } else { 48 }, 1),
            _ => return None,
        };
        depth = depth.checked_add(add)?;
        index += slots;
    }
    Some(depth)
}

/// Reads the language-specific data of the handlers of `handled`, into
/// [`Image::frame_handlers`], and the funclets they name, linked to their
/// functions, into [`Image::funclets`].
pub fn read(image: &mut Image<'_>, base: u64, handled: &[Handled]) {
    let mut tables = Vec::new();
    for entry in handled {
        let referent = handler(image, entry.handler);
        let data = entry.at + 4;
        let kind = match referent.symbol.as_deref() {
            Some("__C_specific_handler" | "__GSHandlerCheck_SEH") => Some(Kind::Scopes),
            Some("__CxxFrameHandler3" | "__GSHandlerCheck_EH") => Some(Kind::Cxx3),
            Some("__CxxFrameHandler4" | "__GSHandlerCheck_EH4") => Some(Kind::Cxx4),
            _ => image
                .read_word(data, 4, true)
                .and_then(|rva| word(image, base + rva))
                .filter(|&magic| MAGIC.contains(&(magic & 0x1fff_ffff)))
                .map(|_| Kind::Cxx3),
        };
        let table = match kind {
            Some(Kind::Scopes) => scopes(image, base, data).map(HandlerTable::Scopes),
            Some(Kind::Cxx3) => image
                .read_word(data, 4, true)
                .and_then(|rva| cxx3(image, base, base + rva))
                .map(HandlerTable::Cxx),
            Some(Kind::Cxx4) => image
                .read_word(data, 4, true)
                .and_then(|rva| cxx4(image, base, base + rva, entry.function))
                .map(HandlerTable::Cxx),
            None => continue,
        };
        match table {
            Some(table) => tables.push(FrameHandler {
                function: entry.function,
                handler: referent,
                data,
                establisher: entry.establisher,
                table,
            }),
            None => image.warn(
                Part::Pdata,
                format_args!(
                    "{:#x}: damaged exception handler data at {data:#x}",
                    entry.function
                ),
            ),
        }
    }
    link(image, tables);
}

/// The handler at `address`, named by the symbol there or by the import
/// its thunk (`jmp [rip+slot]`, `ff 25` and a 32-bit displacement) jumps
/// through.
fn handler(image: &Image<'_>, address: u64) -> Referent {
    let mut referent = Referent {
        address: Some(address),
        slot: None,
        symbol: image
            .symbols
            .iter()
            .find(|symbol| symbol.address == address)
            .map(|symbol| symbol.name.clone()),
    };
    let mut bytes = [0u8; 6];
    if referent.symbol.is_none()
        && image.read(address, &mut bytes) == Ok(6)
        && let [0xff, 0x25, d0, d1, d2, d3] = bytes
    {
        let displacement = i64::from(i32::from_le_bytes([d0, d1, d2, d3]));
        let slot = (address + 6).wrapping_add_signed(displacement);
        referent.slot = Some(slot);
        referent.symbol = image
            .imports
            .iter()
            .find(|import| import.slot == slot)
            .map(|import| import.name.clone());
    }
    referent
}

/// The scope table at `at`.
fn scopes(image: &Image<'_>, base: u64, at: u64) -> Option<Vec<Scope>> {
    let count = u64::from(word(image, at)?);
    (0..count.min(0x1_0000))
        .map(|i| {
            let word = |field: u64| word(image, at + 4 + 16 * i + 4 * field).map(u64::from);
            let (begin, end, handler, target) = (word(0)?, word(1)?, word(2)?, word(3)?);
            let action = if target == 0 {
                ScopeAction::Finally(base + handler)
            } else {
                let filter = base + handler;
                ScopeAction::Except {
                    filter: if image.is_code(filter) {
                        SehFilter::Funclet(filter)
                    } else {
                        SehFilter::Constant(u32::try_from(handler).ok()?.cast_signed())
                    },
                    target: base + target,
                }
            };
            Some(Scope {
                start: base + begin,
                end: base + end,
                action,
            })
        })
        .collect()
}

/// The `FuncInfo` (`__CxxFrameHandler3`) at `at`.
fn cxx3(image: &Image<'_>, base: u64, at: u64) -> Option<CxxTable> {
    let word = |at: u64| word(image, at);
    let int = |at: u64| word(at).map(u32::cast_signed);
    let rva = |at: u64| word(at).filter(|&w| w != 0).map(|w| base + u64::from(w));
    if !MAGIC.contains(&(word(at)? & 0x1fff_ffff)) {
        return None;
    }
    let states = word(at + 4)?.min(0x1_0000);
    let unwind = match rva(at + 8) {
        Some(map) => (0..u64::from(states))
            .map(|i| {
                Some(UnwindState {
                    next: int(map + 8 * i)?,
                    action: rva(map + 8 * i + 4),
                    destructor: None,
                })
            })
            .collect::<Option<_>>()?,
        None => Vec::new(),
    };
    let tries = match rva(at + 16) {
        Some(map) => (0..u64::from(word(at + 12)?.min(0x1_0000)))
            .map(|i| {
                let entry = map + 20 * i;
                let handlers = rva(entry + 16);
                let catches = (0..u64::from(word(entry + 12)?.min(0x1_0000)))
                    .map(|j| {
                        let handler = handlers? + 20 * j;
                        let object = int(handler + 8)?;
                        Some(Catch {
                            adjectives: word(handler)?,
                            ty: rva(handler + 4).map(|td| type_descriptor(image, td)),
                            object: (object != 0).then_some(object),
                            funclet: rva(handler + 12)?,
                            continuations: Vec::new(),
                        })
                    })
                    .collect::<Option<_>>()?;
                Some(TryBlock {
                    low: int(entry)?,
                    high: int(entry + 4)?,
                    catch_high: int(entry + 8)?,
                    catches,
                })
            })
            .collect::<Option<_>>()?,
        None => Vec::new(),
    };
    let ranges = match rva(at + 24) {
        Some(map) => (0..u64::from(word(at + 20)?.min(0x10_0000)))
            .map(|i| {
                Some(StateRange {
                    start: rva(map + 8 * i)?,
                    state: int(map + 8 * i + 4)?,
                })
            })
            .collect::<Option<_>>()?,
        None => Vec::new(),
    };
    Some(CxxTable {
        version: CxxVersion::V3,
        info: at,
        unwind,
        tries,
        states: ranges,
    })
}

/// A cursor over `FuncInfo4`'s compressed encoding.
struct Cursor<'a, 'data> {
    image: &'a Image<'data>,
    at: u64,
}

impl Cursor<'_, '_> {
    fn byte(&mut self) -> Option<u8> {
        let mut byte = [0u8];
        if self.image.read(self.at, &mut byte) != Ok(1) {
            return None;
        }
        self.at += 1;
        Some(byte[0])
    }

    /// A variable-length unsigned integer.
    fn uint(&mut self) -> Option<u32> {
        let first = self.byte()?;
        let length = first.trailing_ones() + 1;
        if length > 4 {
            let value = word(self.image, self.at)?;
            self.at += 4;
            return Some(value);
        }
        let mut value = u32::from(first) >> length;
        for i in 1..length {
            value |= u32::from(self.byte()?) << (8 * i - length);
        }
        Some(value)
    }

    /// A 32-bit RVA.
    fn rva(&mut self) -> Option<u32> {
        let value = word(self.image, self.at)?;
        self.at += 4;
        Some(value)
    }
}

/// `FuncInfo4`'s header flags (bit 0, a catch funclet's own table, has its
/// frame offset follow the maps' RVAs; it is not read).
const IS_SEPARATED: u8 = 0x02;
const BBT: u8 = 0x04;
const UNWIND_MAP: u8 = 0x08;
const TRY_BLOCK_MAP: u8 = 0x10;

/// A handler's flags in `FuncInfo4`.
const HANDLER_ADJECTIVES: u8 = 0x01;
const HANDLER_TYPE: u8 = 0x02;
const HANDLER_OBJECT: u8 = 0x04;
const HANDLER_SEPARATED: u8 = 0x08;
const HANDLER_CONTINUATIONS: u8 = 0x30;

/// The `FuncInfo4` (`__CxxFrameHandler4`) at `at` of the function at
/// `function`.
fn cxx4(image: &Image<'_>, base: u64, at: u64, function: u64) -> Option<CxxTable> {
    let mut cursor = Cursor { image, at };
    let header = cursor.byte()?;
    if header & BBT != 0 {
        cursor.uint()?;
    }
    let unwind_map = if header & UNWIND_MAP != 0 {
        Some(cursor.rva()?)
    } else {
        None
    };
    let try_map = if header & TRY_BLOCK_MAP != 0 {
        Some(cursor.rva()?)
    } else {
        None
    };
    let ip_map = cursor.rva()?;
    let function_rva = u32::try_from(function.checked_sub(base)?).ok()?;
    let unwind = match unwind_map {
        Some(map) => unwind4(image, base, base + u64::from(map))?,
        None => Vec::new(),
    };
    let mut tries = Vec::new();
    if let Some(map) = try_map {
        let mut cursor = Cursor {
            image,
            at: base + u64::from(map),
        };
        for _ in 0..cursor.uint()?.min(0x1_0000) {
            let (low, high, catch_high) = (cursor.uint()?, cursor.uint()?, cursor.uint()?);
            let handlers = cursor.rva()?;
            let mut catches = Vec::new();
            if handlers != 0 {
                let mut cursor = Cursor {
                    image,
                    at: base + u64::from(handlers),
                };
                for _ in 0..cursor.uint()?.min(0x1_0000) {
                    catches.push(catch4(&mut cursor, base, function_rva)?);
                }
            }
            tries.push(TryBlock {
                low: low.cast_signed(),
                high: high.cast_signed(),
                catch_high: catch_high.cast_signed(),
                catches,
            });
        }
    }
    // A separated map lists the IP-to-state maps of the function and of
    // its funclets, by their starts: each part's map counts from its start.
    let mut maps = vec![(function_rva, ip_map)];
    if header & IS_SEPARATED != 0 {
        let mut cursor = Cursor {
            image,
            at: base + u64::from(ip_map),
        };
        let count = cursor.uint()?;
        maps.clear();
        for _ in 0..count.min(0x1_0000) {
            maps.push((cursor.rva()?, cursor.rva()?));
        }
        if !maps.iter().any(|&(part, _)| part == function_rva) {
            return None;
        }
    }
    let mut states = Vec::new();
    for (mut ip, map) in maps {
        let mut cursor = Cursor {
            image,
            at: base + u64::from(map),
        };
        for _ in 0..cursor.uint()?.min(0x10_0000) {
            ip = ip.checked_add(cursor.uint()?)?;
            let state = cursor.uint()?.cast_signed().wrapping_sub(1);
            states.push(StateRange {
                start: base + u64::from(ip),
                state,
            });
        }
    }
    states.sort_by_key(|range| range.start);
    Some(CxxTable {
        version: CxxVersion::V4,
        info: at,
        unwind,
        tries,
        states,
    })
}

/// `FuncInfo4`'s unwind map at `at`: per state, the state it unwinds to and
/// its unwind funclet (a destructor of an object, called with its address,
/// is not one). An entry links back to the entry of the state it unwinds
/// to, or to the map's start (its count) for none.
fn unwind4(image: &Image<'_>, base: u64, at: u64) -> Option<Vec<UnwindState>> {
    let mut cursor = Cursor { image, at };
    let count = cursor.uint()?.min(0x1_0000);
    let mut starts = BTreeMap::from([(at, -1)]);
    let mut entries = Vec::new();
    for state in 0..count {
        let start = cursor.at;
        starts.insert(start, state.cast_signed());
        let word = cursor.uint()?;
        let back = u64::from(word >> 2);
        let (action, destructor) = match word & 3 {
            1 | 2 => {
                let function = base + u64::from(cursor.rva()?);
                let object = cursor.uint()?.cast_signed();
                let destructor = Destructor {
                    function,
                    object,
                    indirect: word & 3 == 2,
                };
                (None, Some(destructor))
            }
            3 => (Some(base + u64::from(cursor.rva()?)), None),
            _ => (None, None),
        };
        entries.push((start, back, action, destructor));
    }
    entries
        .into_iter()
        .map(|(start, back, action, destructor)| {
            let next = *starts.get(&start.checked_sub(back)?)?;
            Some(UnwindState {
                next,
                action,
                destructor,
            })
        })
        .collect()
}

/// A handler of `FuncInfo4`'s handler array at `cursor`.
fn catch4(cursor: &mut Cursor<'_, '_>, base: u64, function: u32) -> Option<Catch> {
    let flags = cursor.byte()?;
    let adjectives = if flags & HANDLER_ADJECTIVES != 0 {
        cursor.uint()?
    } else {
        0
    };
    let ty = if flags & HANDLER_TYPE != 0 {
        cursor.rva()?
    } else {
        0
    };
    let object = if flags & HANDLER_OBJECT != 0 {
        Some(cursor.uint()?.cast_signed())
    } else {
        None
    };
    let funclet = base + u64::from(cursor.rva()?);
    let count = match flags & HANDLER_CONTINUATIONS {
        0x10 => 1,
        0x20 => 2,
        0 => 0,
        _ => return None,
    };
    let continuations = (0..count)
        .map(|_| {
            let rva = if flags & HANDLER_SEPARATED != 0 {
                cursor.rva()?
            } else {
                function.checked_add(cursor.uint()?)?
            };
            Some(base + u64::from(rva))
        })
        .collect::<Option<_>>()?;
    Some(Catch {
        adjectives,
        ty: (ty != 0).then(|| type_descriptor(cursor.image, base + u64::from(ty))),
        object,
        funclet,
        continuations,
    })
}

/// The C++ type of the `TypeDescriptor` at `at` (a vtable pointer, a
/// spare pointer, then the type's decorated name, `.?AUError@@`): its
/// symbol (`??_R0?AUError@@@8`) and the type demangled.
fn type_descriptor(image: &Image<'_>, at: u64) -> TypeInfo {
    let mut decorated = Vec::new();
    let mut cursor = Cursor { image, at: at + 16 };
    while decorated.len() < 4096
        && let Some(byte) = cursor.byte()
        && byte != 0
    {
        decorated.push(byte);
    }
    let decorated = String::from_utf8(decorated)
        .ok()
        .and_then(|name| name.strip_prefix('.').map(str::to_owned));
    TypeInfo {
        object: Referent {
            address: Some(at),
            slot: None,
            symbol: decorated.as_ref().map(|name| format!("??_R0{name}@8")),
        },
        name: decorated.as_deref().and_then(type_name),
    }
}

/// The C++ type that the decorated type `name` (a `TypeDescriptor`'s,
/// without its leading `.`: `?AUError@@`, `H`) encodes, demangled as a
/// variable's type (`?x@@3UError@@A`, `struct Error x`).
fn type_name(name: &str) -> Option<String> {
    let ty = name.strip_prefix("?A").unwrap_or(name);
    let flags = msvc_demangler::DemangleFlags::NO_CLASS_TYPE
        | msvc_demangler::DemangleFlags::NO_MS_KEYWORDS
        | msvc_demangler::DemangleFlags::SPACE_AFTER_COMMA;
    let variable = msvc_demangler::demangle(&format!("?x@@3{ty}A"), flags).ok()?;
    let ty = variable.strip_suffix("x")?.trim_end();
    (!ty.is_empty()).then(|| ty.to_owned())
}

/// Links the funclets and landing pads that `tables` name to their
/// functions: a funclet of a function's table is that function's (and a
/// funclet's funclets its root's), and a table read again through a
/// funclet's unwind information (`__CxxFrameHandler3`'s catch blocks name
/// their function's `FuncInfo`) is kept once, at the function.
fn link(image: &mut Image<'_>, mut tables: Vec<FrameHandler>) {
    let mut funclets: BTreeMap<u64, (u64, FuncletKind)> = BTreeMap::new();
    for table in &tables {
        for (address, kind) in table.funclets() {
            if address != table.function {
                funclets.entry(address).or_insert((table.function, kind));
            }
        }
    }
    // A table met again at one of its own funclets.
    let infos: BTreeMap<u64, BTreeSet<u64>> =
        tables.iter().fold(BTreeMap::new(), |mut infos, table| {
            if let HandlerTable::Cxx(cxx) = &table.table {
                infos.entry(cxx.info).or_default().insert(table.function);
            }
            infos
        });
    tables.retain(|table| match &table.table {
        HandlerTable::Cxx(cxx) => {
            let owners = infos.get(&cxx.info);
            !(owners.is_some_and(|owners| owners.len() > 1)
                && funclets.contains_key(&table.function))
        }
        HandlerTable::Scopes(_) => true,
    });
    let root = |mut function: u64| {
        for _ in 0..64 {
            match funclets.get(&function) {
                Some(&(parent, _)) if parent != function => function = parent,
                _ => break,
            }
        }
        function
    };
    image.funclets = funclets
        .iter()
        .map(|(&address, &(_, kind))| Funclet {
            function: root(address),
            address,
            kind,
        })
        .collect();
    image.frame_handlers = tables;
}

impl FrameHandler {
    /// The funclets its table names, with their kinds.
    pub fn funclets(&self) -> impl Iterator<Item = (u64, FuncletKind)> + '_ {
        let (scopes, cxx) = match &self.table {
            HandlerTable::Scopes(scopes) => (scopes.as_slice(), None),
            HandlerTable::Cxx(cxx) => (&[][..], Some(cxx)),
        };
        let scopes = scopes.iter().filter_map(|scope| match scope.action {
            ScopeAction::Except {
                filter: SehFilter::Funclet(filter),
                ..
            } => Some((filter, FuncletKind::Filter)),
            ScopeAction::Finally(handler) => Some((handler, FuncletKind::Finally)),
            ScopeAction::Except {
                filter: SehFilter::Constant(_),
                ..
            } => None,
        });
        let unwinds = cxx
            .into_iter()
            .flat_map(|cxx| &cxx.unwind)
            .filter_map(|state| Some((state.action?, FuncletKind::Unwind)));
        let catches = cxx
            .into_iter()
            .flat_map(|cxx| &cxx.tries)
            .flat_map(|block| &block.catches)
            .map(|catch| (catch.funclet, FuncletKind::Catch));
        scopes.chain(unwinds).chain(catches)
    }
}

#[cfg(test)]
mod tests {
    use super::{establisher, type_name};

    /// The establisher frame is the stack pointer after the prologue, or
    /// where it was when the frame register was set (codes listed
    /// last-executed first: those after `UWOP_SET_FPREG` ran before it).
    #[test]
    fn places_the_establisher_frame() {
        // `sub rsp, 0x38`: UWOP_ALLOC_SMALL (6 × 8 + 8).
        assert_eq!(establisher(&[0x01, 4, 1, 0, 4, 0x62]), Some(0x38));
        // `push rbp; sub rsp, 0x40; lea rbp, [rsp + 0x20]`: rbp, offset 2.
        let framed = [0x01, 10, 3, 0x25, 10, 0x03, 5, 0x72, 1, 0x50];
        assert_eq!(establisher(&framed), Some(0x48));
        // `push rbx; sub rsp, 0x20; ...` without a frame register: all of it,
        // with a UWOP_SAVE_NONVOL (two slots) that moves nothing.
        let saved = [0x01, 10, 4, 0x00, 10, 0x34, 0x06, 0x00, 5, 0x32, 1, 0x30];
        assert_eq!(establisher(&saved), Some(0x28));
        // Codes cut short.
        assert_eq!(establisher(&[0x01, 4, 2, 0, 4, 0x62]), None);
    }

    #[test]
    fn names_decorated_types() {
        assert_eq!(type_name("?AUError@@").as_deref(), Some("Error"));
        assert_eq!(
            type_name("?AVexception@std@@").as_deref(),
            Some("std::exception")
        );
        assert_eq!(type_name("H").as_deref(), Some("int"));
        assert_eq!(
            type_name("?AV?$vector@HV?$allocator@H@std@@@std@@").as_deref(),
            Some("std::vector<int, std::allocator<int> >")
        );
        assert_eq!(type_name(""), None);
    }
}
