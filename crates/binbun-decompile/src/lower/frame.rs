//! The frame: the accesses at known offsets from the entry stack pointer,
//! grouped into slots, and where each slot lives (a local, a stack
//! parameter, or memory in a `Frame` variable), as the module docs of
//! [`lower`](super) say.
//!
//! A `Frame` variable below the entry stack pointer whose address is a
//! call's argument at a declared parameter that states its extent
//! ([`Lowering::declared_target`]) is promoted to an object of that type
//! ([`Region::promoted`]) where nothing else could reach its bytes
//! ([`Lowering::promotions`]).

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

use binbun_ast::types::{Type, TypeId};
use binbun_semantics::ir::{Binary, RegisterId};
use binbun_ssa::ir::{BlockId, Definition, InstId, Op, Terminator, Unknown, Value, ValueInfo};

use super::facts::{Kind, Lowering, Site};
use crate::mapping::Source;
use crate::validate::Link;

/// The most values [`Lowering::saved`] looks at.
const SAVE_STEPS: usize = 4096;

/// The most block visits [`Lowering::reuses`] makes for one slot.
const REUSE_STEPS: usize = 1 << 16;

/// Where a slot lives.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Home {
    /// A local variable.
    Local,
    /// A stack parameter.
    Parameter,
    /// Memory: bytes of a `Frame` variable ([`Region`]).
    Frame,
}

/// Accesses that overlap, transitively, or one reuse of such bytes
/// ([`Lowering::reuses`]).
#[derive(Clone, Debug, PartialEq, Eq)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "independent facts about one slot"
)]
pub(super) struct Slot {
    /// Its first byte, from the entry stack pointer.
    pub(super) offset: i64,
    /// Past its last byte.
    pub(super) end: i64,
    /// Whether every access is the whole slot.
    pub(super) shape: bool,
    /// Whether some access is the whole slot (every access, where
    /// `shape`); the others are inside it.
    pub(super) whole: bool,
    /// Whether an access writes it.
    pub(super) written: bool,
    /// Whether an address used as a value may reach its bytes (or the
    /// stack escapes): it lives in memory but where it only saves a
    /// register ([`Lowering::reach`]).
    pub(super) reached: bool,
    /// Where it lives.
    pub(super) home: Home,
}

impl Slot {
    /// Its size in bytes (of one shape: every access's; else the span of
    /// its accesses).
    pub(super) fn bytes(&self) -> u64 {
        self.end.abs_diff(self.offset)
    }
}

/// The bytes of one `Frame` variable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Region {
    /// Its first byte, from the entry stack pointer.
    pub(super) offset: i64,
    /// Its size in bytes.
    pub(super) bytes: u64,
    /// Whether it is one slot of one shape that fits a value (accessed as
    /// the variable itself, not through its address).
    pub(super) whole: bool,
    /// The declared type of the object it is, if promoted: its bytes are
    /// exactly that type's.
    pub(super) promoted: Option<TypeId>,
    /// Whether it is memory an address used as a value may reach (else
    /// one slot's own variable, as in a frame no address escapes).
    pub(super) memory: bool,
}

impl Region {
    /// Whether it holds byte `offset`.
    pub(super) fn contains(&self, offset: i64) -> bool {
        offset >= self.offset && offset.abs_diff(self.offset) < self.bytes
    }

    /// Past its last byte.
    pub(super) fn end(&self) -> i64 {
        self.offset.saturating_add_unsigned(self.bytes)
    }
}

/// The frame.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "independent facts about one frame"
)]
pub(super) struct Frame {
    /// Whether a stack address is used as a value or the stack escapes:
    /// the slots such an address may reach are memory ([`Slot::reached`]).
    pub(super) memory: bool,
    /// How far each address used as a value may reach, by its offset:
    /// past the last byte (`i64::MAX`: any byte above it).
    pub(super) reach: BTreeMap<i64, i64>,
    /// Whether the stack escapes: every slot is reached.
    pub(super) escaped: bool,
    /// Whether an address below the entry stack pointer that nothing
    /// bounds may step back from where it points (`container_of`) in code
    /// it is passed or stored to, the function's own code steps back from
    /// none ([`Lowering::steps_back_itself`]) and nothing else makes the
    /// stack escape: every slot is reached unless the reading view assumes
    /// no such code steps back
    /// ([`Context::assume_forward_reach`](crate::lower::Context::assume_forward_reach)).
    pub(super) steps_back: bool,
    /// The slots, by offset.
    pub(super) slots: Vec<Slot>,
    /// The slot each load and store at a known offset accesses.
    pub(super) accesses: BTreeMap<InstId, usize>,
    /// The slot each stack argument of a call reads, by site and
    /// argument.
    pub(super) arguments: BTreeMap<(Site, usize), usize>,
    /// The loads that may read what the caller left in a slot of its
    /// argument area: no store of the whole slot comes before the read on
    /// some path from the entry ([`Lowering::unwritten_reads`]).
    pub(super) entry_reads: BTreeSet<InstId>,
    /// The stack arguments of calls that may read it, by site and
    /// argument (a tail call passing on an argument in place).
    pub(super) entry_arguments: BTreeSet<(Site, usize)>,
    /// The stores of a call's return address (pushed by the call): not
    /// lowered.
    pub(super) pushes: BTreeSet<InstId>,
    /// The calls made on a stack other than the function's own frame
    /// (`stack_tricks`): a `StackTrick` escape before each.
    pub(super) tricks: BTreeSet<Site>,
    /// The `Frame` variables.
    pub(super) regions: Vec<Region>,
    /// The region of each slot that lives in memory.
    pub(super) region_of: BTreeMap<usize, usize>,
    /// Whether a store writes the return address's bytes.
    pub(super) return_written: bool,
    /// The objects promoted out of the frame's memory: their bytes (first,
    /// past the last) and declared type.
    pub(super) promoted: Vec<(i64, i64, TypeId)>,
    /// The bytes of the return address (where a call leaves it on the
    /// stack): the canonical frame address, 16-byte aligned by the ABI,
    /// is this far above the entry stack pointer.
    pub(super) link: i64,
    /// The highest stack pointer at a call, from the entry stack pointer
    /// (`i64::MIN` without calls; `None` if one is not at a known offset).
    pub(super) call_top: Option<i64>,
    /// The offsets of the stack addresses used as values
    /// ([`Lowering::taken`]).
    pub(super) taken: Vec<i64>,
}

/// One access at a known offset.
struct Access {
    offset: i64,
    bytes: u16,
    write: bool,
    /// For a store: the value stored.
    value: Option<Value>,
    at: At,
}

/// What makes an access.
#[derive(Clone, Copy)]
enum At {
    Inst(InstId),
    Argument(Site, usize),
}

/// How a value may be computed from the entry stack pointer.
#[derive(Clone, Copy)]
enum Candidate {
    /// A pure operation.
    Pure(InstId),
    /// Parameter `index` of a block.
    Phi(BlockId, usize),
    /// A load of these bytes of the own frame (first, past the last).
    Load(i64, i64),
}

/// A store at a known stack offset: its first byte, past its last, and the
/// value stored.
type StackStore = (i64, i64, Value);

impl Frame {
    /// Records the reads `unwritten` as reading what the caller left.
    fn read_at_entry(&mut self, unwritten: Vec<At>) {
        for at in unwritten {
            match at {
                At::Inst(inst) => {
                    self.entry_reads.insert(inst);
                }
                At::Argument(site, argument) => {
                    self.entry_arguments.insert((site, argument));
                }
            }
        }
    }

    /// The region holding byte `offset`, if one does.
    pub(super) fn region_at(&self, offset: i64) -> Option<usize> {
        self.regions
            .iter()
            .position(|region| region.contains(offset))
    }

    /// Whether region `index` is a frame struct: memory below the entry
    /// stack pointer, not one value, not a promoted object, not the
    /// `va_list` at `list`.
    pub(super) fn is_struct(&self, index: usize, list: Option<i64>) -> bool {
        self.regions.get(index).is_some_and(|region| {
            region.memory
                && region.end() <= 0
                && !region.whole
                && region.promoted.is_none()
                && list != Some(region.offset)
        })
    }

    /// The `Frame` variables without the bytes `hole`, and with the bytes
    /// `own` (if any) one of their own (a variadic definition's save area
    /// and `va_list`, [`Plan`](super::variadic::Plan)). A promoted object
    /// cut is no longer one.
    pub(super) fn cut(&mut self, hole: (i64, i64), own: Option<(i64, i64)>) {
        let mut regions = Vec::new();
        for region in &self.regions {
            let end = region.offset.saturating_add_unsigned(region.bytes);
            let mut bounds: Vec<i64> = [Some(hole), own]
                .into_iter()
                .flatten()
                .flat_map(|(start, end)| [start, end])
                .filter(|&bound| bound > region.offset && bound < end)
                .chain([end])
                .collect();
            bounds.sort_unstable();
            bounds.dedup();
            let inside = region.offset < hole.1 && hole.0 < end;
            if region.promoted.is_some() && bounds.len() == 1 && !inside {
                regions.push(*region);
                continue;
            }
            let mut at = region.offset;
            for bound in bounds {
                if at < hole.0 || bound > hole.1 {
                    regions.push(self.span(at, bound, region.memory));
                }
                at = bound;
            }
        }
        self.regions = regions;
        let kept: Vec<(i64, i64)> = self
            .regions
            .iter()
            .filter(|region| region.promoted.is_some())
            .map(|region| (region.offset, region.end()))
            .collect();
        self.promoted
            .retain(|&(start, end, _)| kept.contains(&(start, end)));
        self.finish(own.map(|(start, _)| start));
    }

    /// Past the last byte the object at the highest address below the
    /// entry stack pointer that may reach any byte above it
    /// ([`Frame::reach`]) may have. Nothing says where
    /// an object known only by its address ends, and what is given the
    /// address may write all of it (`char buf[40]; gets(buf);` accesses no
    /// byte of `buf` itself): a `Frame` variable that ended at the last
    /// byte the function accesses would be an object too small in C. It
    /// ends before the next thing above that is not its bytes: a local
    /// (in a frame that is memory, a saved register) or a promoted
    /// object, else at the entry stack pointer. The objects at the
    /// addresses below are inside the span up to that one. `None` where
    /// the frame is not memory, no address is taken there, or the highest
    /// is a promoted object's (its type states its extent).
    fn taken_end(&self) -> Option<i64> {
        if !self.memory {
            return None;
        }
        let top = self
            .reach
            .iter()
            .filter(|&(&offset, &far)| offset < 0 && far == i64::MAX)
            .map(|(&offset, _)| offset)
            .max()?;
        if self
            .promoted
            .iter()
            .any(|&(start, end, _)| start <= top && top < end)
        {
            return None;
        }
        let above = self
            .slots
            .iter()
            .filter(|slot| slot.home == Home::Local)
            .map(|slot| slot.offset)
            .chain(self.promoted.iter().map(|&(start, ..)| start))
            .filter(|&start| start > top)
            .min();
        Some(above.unwrap_or(0).min(0))
    }

    /// The `Frame` variable of the bytes `start..end`, memory or not: one
    /// value where it is exactly one slot of one shape of at most 64
    /// bytes.
    fn span(&self, start: i64, end: i64, memory: bool) -> Region {
        let bytes = end.abs_diff(start);
        let whole = self.slots.iter().any(|slot| {
            slot.home == Home::Frame
                && slot.shape
                && slot.offset == start
                && slot.end == end
                && bytes <= 64
        });
        Region {
            offset: start,
            bytes,
            whole,
            promoted: None,
            memory,
        }
    }

    /// The regions made final: each that will be a frame struct (but the
    /// one at `list`) starts on the ABI's 16-byte grid (the canonical frame
    /// address's alignment), so its fields sit at their natural alignment
    /// from the struct's start as they do in the stack: it takes the bytes
    /// below it down to the grid where those are no slot's, no other
    /// region's, and every call's stack pointer is at or below them (the
    /// function's own padding: no call's push and no callee writes them);
    /// then the region of each slot in memory.
    fn finish(&mut self, list: Option<i64>) {
        for index in 0..self.regions.len() {
            let Some(&region) = self.regions.get(index) else {
                continue;
            };
            let grid = (region.offset + self.link).rem_euclid(16);
            let start = region.offset - grid;
            let free = !self
                .slots
                .iter()
                .any(|slot| slot.offset < region.offset && start < slot.end)
                && !self
                    .regions
                    .iter()
                    .any(|other| other.offset < region.offset && start < other.end());
            let below = self.call_top.is_some_and(|top| top <= start);
            if grid > 0
                && free
                && below
                && self.is_struct(index, list)
                && let Some(widened) = self.regions.get_mut(index)
            {
                widened.offset = start;
                widened.bytes = widened.bytes.saturating_add(grid.unsigned_abs());
            }
        }
        self.region_of.clear();
        for (index, slot) in self.slots.iter().enumerate() {
            if slot.home == Home::Frame
                && let Some(region) = self.region_at(slot.offset)
            {
                self.region_of.insert(index, region);
            }
        }
    }
}

/// The accesses that overlap, transitively, grouped (as indices into
/// `accesses`), by offset.
fn overlapping(accesses: &[Access]) -> Vec<Vec<usize>> {
    let mut order: Vec<usize> = (0..accesses.len()).collect();
    order.sort_by_key(|&index| accesses.get(index).map(|a| (a.offset, a.bytes)));
    let mut groups: Vec<Vec<usize>> = Vec::new();
    let mut end = i64::MIN;
    for index in order {
        let Some(access) = accesses.get(index) else {
            continue;
        };
        let last = groups.last_mut();
        match last {
            Some(group) if access.offset < end => group.push(index),
            Some(_) | None => groups.push(alloc::vec![index]),
        }
        end = end.max(access.offset + i64::from(access.bytes));
    }
    groups
}

/// A use of an L1 value ([`Lowering::steps_back_itself`]).
#[derive(Clone, Copy)]
enum Use {
    /// An instruction's operand.
    Inst(InstId),
    /// An argument of a block parameter.
    Param(Value),
    /// The address of an indirect jump.
    Jump,
}

/// What a use makes of a value computed from a stack address
/// ([`Lowering::steps_back_itself`]).
enum Through {
    /// Nothing that reaches memory.
    Nothing,
    /// Another such value, maybe below the address if `true`.
    Value(Value, bool),
    /// A reach of memory that may be below the address.
    Reaches,
}

/// How far each stack address used as a value, at `offsets`, may reach,
/// by its offset (see [`Frame::reach`]): one inside a range of `bounded`,
/// to its end; any other, any byte above it. Each range of `bounded` is
/// reached too: an object of its own (the save area, the `va_list`),
/// whatever reads its bytes.
fn reach(offsets: &[i64], bounded: &[(i64, i64)]) -> BTreeMap<i64, i64> {
    let mut reach: BTreeMap<i64, i64> = BTreeMap::new();
    let mut widen = |offset: i64, far: i64| {
        let entry = reach.entry(offset).or_insert(far);
        *entry = (*entry).max(far);
    };
    for &offset in offsets {
        let far = bounded
            .iter()
            .find(|&&(start, end)| start <= offset && offset < end)
            .map_or(i64::MAX, |&(_, end)| end);
        widen(offset, far);
    }
    for &(start, end) in bounded {
        widen(start, end);
    }
    reach
}

/// Whether one of the addresses of `reach` below the entry stack pointer
/// is bounded by nothing: what is given it may step back from it (an
/// enclosing object's `container_of`) to any byte below, so every slot is
/// memory ([`Frame::steps_back`]).
fn steps_back(reach: &BTreeMap<i64, i64>) -> bool {
    reach
        .iter()
        .any(|(&offset, &far)| offset < 0 && far == i64::MAX)
}

/// Whether every access of `members`, the slot `offset..end`, is of the
/// whole slot but reads of its parts as calls' stack arguments (pushed as
/// 8 bytes, passed as 4): a variable's value, the arguments its bits. A
/// spill slot a function also loads in part is often one several values
/// share, and stays memory.
fn passed_in_parts(members: &[&Access], offset: i64, end: i64) -> bool {
    members.iter().all(|access| {
        let whole = access.offset == offset && access.offset + i64::from(access.bytes) == end;
        whole || (!access.write && matches!(access.at, At::Argument(..)))
    })
}

/// The bytes `members` access: the first, past the last.
fn extent(members: &[&Access]) -> (i64, i64) {
    let offset = members.iter().map(|a| a.offset).min().unwrap_or(0);
    let end = members
        .iter()
        .map(|a| a.offset + i64::from(a.bytes))
        .max()
        .unwrap_or(offset);
    (offset, end)
}

/// Whether the accesses `members` of the bytes `offset..end` are those of
/// one value: written, and every access of all of them (or read in parts
/// only as calls' stack arguments, [`passed_in_parts`]).
fn one_value(members: &[&Access], offset: i64, end: i64) -> bool {
    let whole = |a: &&Access| a.offset == offset && a.offset + i64::from(a.bytes) == end;
    members.iter().any(|a| a.write)
        && (members.iter().all(whole) || passed_in_parts(members, offset, end))
}

/// The root of `index` in the forest `parent` (halving the path).
fn root(parent: &mut [usize], mut index: usize) -> usize {
    loop {
        let up = parent.get(index).copied().unwrap_or(index);
        if up == index {
            return index;
        }
        let grand = parent.get(up).copied().unwrap_or(up);
        if let Some(link) = parent.get_mut(index) {
            *link = grand;
        }
        index = grand;
    }
}

impl Lowering<'_, '_> {
    /// The frame: its accesses, slots and regions. `bounded`: addresses
    /// known to reach only as far as a given byte (a recognised
    /// `va_start`'s save area and `va_list`, [`Lowering::find_variadic`]),
    /// by their offset: first, past the last.
    pub(super) fn build_frame(&mut self, bounded: &[(i64, i64)]) {
        let pushes = self.pushes();
        let tricks = self.stack_tricks();
        let accesses = self.accesses(&pushes);
        let (others, passed) = self.uses(&tricks);
        let offsets: Vec<i64> = others
            .iter()
            .copied()
            .chain(passed.iter().map(|&(offset, _)| offset))
            .collect();
        let reach = reach(&offsets, bounded);
        let unseen = self.unseen(&reach);
        // The function's own code stepping back is no assumption's.
        let itself = steps_back(&reach) && self.steps_back_itself(&tricks);
        let steps_back = !unseen && !itself && steps_back(&reach);
        let escaped = unseen || itself || (steps_back && !self.cx.assume_forward_reach);
        let memory = !offsets.is_empty() || escaped;
        let link = i64::from(self.cx.link_bytes());
        let shadow = link + i64::from(self.cx.convention.shadow);
        let mut frame = Frame {
            memory,
            escaped,
            steps_back,
            pushes,
            tricks,
            link,
            call_top: self.call_top(),
            return_written: accesses
                .iter()
                .any(|a| a.write && a.offset < link && a.offset + i64::from(a.bytes) > 0),
            ..Frame::default()
        };
        for group in &overlapping(&accesses) {
            let members: Vec<&Access> = group.iter().filter_map(|&i| accesses.get(i)).collect();
            if members.is_empty() {
                continue;
            }
            let (offset, end) = extent(&members);
            // An address used as a value reaches its bytes: they are
            // memory (a slot no such address reaches lives as it would in
            // a frame where none escapes).
            let reached = escaped || reach.iter().any(|(&at, &far)| at < end && far > offset);
            // The callee's own bytes: below the entry stack pointer, or in
            // the space the caller reserves for it above the return
            // address (Microsoft x64's home space).
            let own = end <= 0 || (offset >= link && end <= shadow);
            let parts = if !reached && own && end - offset <= 64 {
                self.reuses(members)
            } else {
                alloc::vec![members]
            };
            for members in parts {
                self.add_slot(&mut frame, &members, own, reached, shadow);
            }
        }
        if memory {
            frame.promoted = self.promotions(&frame.slots, &others, &passed, bounded);
        }
        frame.reach = reach;
        frame.regions();
        frame.taken = offsets;
        self.frame = frame;
    }

    /// The slot of the accesses `members` (`own`: in the function's own
    /// bytes; `reached`: by an address used as a value) added to `frame`,
    /// with where it lives.
    fn add_slot(
        &self,
        frame: &mut Frame,
        members: &[&Access],
        own: bool,
        reached: bool,
        shadow: i64,
    ) {
        let link = frame.link;
        let (offset, end) = extent(members);
        let is_whole = |a: &&Access| a.offset == offset && a.offset + i64::from(a.bytes) == end;
        let (shape, whole) = (members.iter().all(is_whole), members.iter().any(is_whole));
        let written = members.iter().any(|a| a.write);
        let parts = written && passed_in_parts(members, offset, end);
        let mut register = None;
        let saves = members.iter().filter(|a| a.write).all(|a| {
            a.value
                .and_then(|v| self.saved(v, offset, end))
                .is_some_and(|saved| *register.get_or_insert(saved) == saved)
        });
        let in_link = offset < link && end > 0;
        let unwritten = self.unwritten_reads(members, offset, end, shadow);
        let home = if in_link || end - offset > 64 {
            Home::Frame
        } else if !reached && (shape || parts) && own && written {
            Home::Local
        } else if !reached
            && shape
            && offset >= shadow
            && !written
            && !self.declared_parts(offset, end)
        {
            Home::Parameter
        } else if reached && shape && own && written && saves {
            Home::Local
        } else {
            Home::Frame
        };
        let index = frame.slots.len();
        frame.slots.push(Slot {
            offset,
            end,
            shape,
            whole,
            written,
            reached,
            home,
        });
        frame.read_at_entry(unwritten);
        for access in members {
            match access.at {
                At::Inst(inst) => {
                    frame.accesses.insert(inst, index);
                }
                At::Argument(site, argument) => {
                    frame.arguments.insert((site, argument), index);
                }
            }
        }
    }

    /// The slots the overlapping accesses `members` are, in the function's
    /// own bytes no address used as a value reaches (so that only they
    /// read and write those bytes): one per reuse of the bytes
    /// ([`Self::webs`]) that is one value's ([`one_value`]: a compiler
    /// sharing a spill slot among values, of one type or of several: a
    /// `sqlite3_context *` saved across one call, a `JsonParse *` across
    /// another) where every reuse is; else all of them one slot (in
    /// memory, whose bytes are then that slot's alone).
    fn reuses<'m>(&self, members: Vec<&'m Access>) -> Vec<Vec<&'m Access>> {
        let Some(webs) = self.webs(&members) else {
            return alloc::vec![members];
        };
        let mut slots: Vec<Vec<&Access>> = Vec::new();
        for web in webs {
            let web: Vec<&Access> = web
                .iter()
                .filter_map(|&i| members.get(i).copied())
                .collect();
            let (offset, end) = extent(&web);
            if !one_value(&web, offset, end) {
                return alloc::vec![members];
            }
            slots.push(web);
        }
        slots.sort_by_key(|slot| extent(slot));
        slots
    }

    /// The reuses of the bytes the accesses `members` (one slot's, which
    /// alone read and write them) make, as indices into `members`: each
    /// read (a load, a call's stack argument) with every store that may
    /// have written one of its bytes last on some path from the entry,
    /// joined transitively. `None` where that is one reuse, an access is
    /// in no block lowered, a jump goes where nothing is known, or the walk
    /// passes [`REUSE_STEPS`].
    fn webs(&self, members: &[&Access]) -> Option<Vec<Vec<usize>>> {
        let (offset, end) = extent(members);
        let bytes = usize::try_from(end - offset).ok()?;
        let mut at_inst: BTreeMap<InstId, Vec<usize>> = BTreeMap::new();
        let mut at_end: BTreeMap<BlockId, Vec<usize>> = BTreeMap::new();
        for (index, access) in members.iter().enumerate() {
            match access.at {
                At::Inst(inst) | At::Argument(Site::Call(inst), _) => {
                    at_inst.entry(inst).or_default().push(index);
                }
                At::Argument(Site::Tail(block), _) => at_end.entry(block).or_default().push(index),
            }
        }
        // Each block's accesses, in order.
        let mut order: BTreeMap<BlockId, Vec<usize>> = BTreeMap::new();
        let mut found = 0;
        for (id, block) in self.blocks() {
            if matches!(&block.terminator, Terminator::IndirectJump { targets, .. } if targets.is_empty())
            {
                return None;
            }
            let list = order.entry(id).or_default();
            for inst in &block.insts {
                if let Some(indices) = at_inst.get(inst) {
                    list.extend(indices);
                    found += indices.len();
                }
            }
            if let Some(indices) = at_end.get(&id) {
                list.extend(indices);
                found += indices.len();
            }
        }
        if found != members.len() {
            return None;
        }
        // The stores that may have written each byte last, where each
        // block starts.
        let mut start: BTreeMap<BlockId, Vec<BTreeSet<usize>>> = BTreeMap::new();
        start.insert(BlockId(0), alloc::vec![BTreeSet::new(); bytes]);
        let mut reaching: Vec<BTreeSet<usize>> = alloc::vec![BTreeSet::new(); members.len()];
        let mut work = alloc::vec![BlockId(0)];
        let mut steps = 0;
        while let Some(id) = work.pop() {
            steps += 1;
            if steps > REUSE_STEPS {
                return None;
            }
            let Some(mut state) = start.get(&id).cloned() else {
                continue;
            };
            for &index in order.get(&id).map_or(&[][..], Vec::as_slice) {
                let access = members.get(index)?;
                let from = usize::try_from(access.offset - offset).ok()?;
                let touched = state.get_mut(from..from + usize::from(access.bytes))?;
                if access.write {
                    for byte in touched {
                        *byte = BTreeSet::from([index]);
                    }
                } else {
                    let into = reaching.get_mut(index)?;
                    for byte in touched {
                        into.extend(byte.iter().copied());
                    }
                }
            }
            let Some(block) = self.l1.block(id) else {
                continue;
            };
            for target in block.terminator.targets() {
                let changed = if let Some(known) = start.get_mut(&target.block) {
                    let mut changed = false;
                    for (into, from) in known.iter_mut().zip(&state) {
                        for &store in from {
                            changed |= into.insert(store);
                        }
                    }
                    changed
                } else {
                    start.insert(target.block, state.clone());
                    true
                };
                if changed {
                    work.push(target.block);
                }
            }
        }
        let mut parent: Vec<usize> = (0..members.len()).collect();
        for (read, stores) in reaching.iter().enumerate() {
            for &store in stores {
                let (a, b) = (root(&mut parent, read), root(&mut parent, store));
                if let Some(link) = parent.get_mut(a.max(b)) {
                    *link = a.min(b);
                }
            }
        }
        let mut webs: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
        for index in 0..members.len() {
            webs.entry(root(&mut parent, index))
                .or_default()
                .push(index);
        }
        (webs.len() > 1).then(|| webs.into_values().collect())
    }

    /// Whether a stack address escapes where the frame does not see it
    /// used as a value (no reach of its own in `reach`): every slot is
    /// memory.
    fn unseen(&self, reach: &BTreeMap<i64, i64>) -> bool {
        self.stack
            .escaping()
            .iter()
            .any(|offset| !reach.contains_key(offset))
    }

    /// Whether the function's own code may reach a byte below a stack
    /// address below the entry stack pointer: a value it computes from
    /// one, other than another such address, by anything but adding
    /// constants that are not negative (through block parameters, and
    /// the arm a constant condition chooses: `rep stos`'s step by the
    /// clear direction flag), is accessed, stored, passed or joined in a
    /// block parameter (compared, as an alignment check does, it reaches
    /// nothing); or one is jumped to or given to an instruction without
    /// semantics, or a call is made on another stack (`tricks`). Passing
    /// one to a call, storing or returning it are not its own code: what
    /// is done with it there is the reading view's assumption
    /// ([`Context::assume_forward_reach`](crate::lower::Context::assume_forward_reach)).
    fn steps_back_itself(&self, tricks: &BTreeSet<Site>) -> bool {
        if !tricks.is_empty() {
            return true;
        }
        let users = self.value_uses();
        // Each value computed from a stack address below the entry, and
        // whether it may be below it.
        let mut seen: BTreeMap<Value, bool> = BTreeMap::new();
        let mut work: Vec<(Value, bool)> = (0..self.l1.values.len())
            .filter_map(|index| u32::try_from(index).ok().map(Value))
            .filter(|&v| self.canonical(v) == v && self.address(v).is_some_and(|o| o < 0))
            .map(|v| (v, false))
            .collect();
        while let Some((v, back)) = work.pop() {
            // Again where it may be below now and was not.
            if seen.get(&v).is_some_and(|&was| was || !back) {
                continue;
            }
            seen.insert(v, back);
            for &user in users.get(&v).map_or(&[][..], Vec::as_slice) {
                match user {
                    Use::Jump => return true,
                    Use::Param(parameter) => {
                        if back {
                            return true;
                        }
                        let parameter = self.canonical(parameter);
                        if self.address(parameter).is_none() {
                            work.push((parameter, false));
                        }
                    }
                    Use::Inst(inst) => match self.through(inst, v, back) {
                        Through::Nothing => {}
                        Through::Value(r, below) => work.push((r, below)),
                        Through::Reaches => return true,
                    },
                }
            }
        }
        false
    }

    /// Each canonical value's uses: the instructions with it as an
    /// operand, the block parameters it is an argument of, an indirect
    /// jump to it.
    fn value_uses(&self) -> BTreeMap<Value, Vec<Use>> {
        let mut users: BTreeMap<Value, Vec<Use>> = BTreeMap::new();
        for (_, block) in self.blocks() {
            for &inst in &block.insts {
                let Some(i) = self.l1.inst(inst) else {
                    continue;
                };
                for operand in i.op.operands() {
                    let at = self.canonical(operand);
                    users.entry(at).or_default().push(Use::Inst(inst));
                }
            }
            if let Terminator::IndirectJump { address, .. } = block.terminator {
                let at = self.canonical(address);
                users.entry(at).or_default().push(Use::Jump);
            }
            for target in block.terminator.targets() {
                let parameters = self
                    .l1
                    .block(target.block)
                    .map_or(&[][..], |b| b.parameters.as_slice());
                for (&argument, &parameter) in target.arguments.iter().zip(parameters) {
                    let at = self.canonical(argument);
                    users.entry(at).or_default().push(Use::Param(parameter));
                }
            }
        }
        users
    }

    /// What instruction `inst` makes of `v`, a value computed from a stack
    /// address (`back`: maybe below it) that it uses
    /// ([`Self::steps_back_itself`]).
    fn through(&self, inst: InstId, v: Value, back: bool) -> Through {
        let Some(i) = self.l1.inst(inst) else {
            return Through::Nothing;
        };
        // A result that is a stack address is accessed at its own offset;
        // one narrower than an address is none.
        let derived = i
            .results
            .first()
            .map(|&result| self.canonical(result))
            .filter(|&result| self.address(result).is_none() && self.width(result) >= self.pointer);
        match &i.op {
            Op::Binary(op @ (Binary::Add | Binary::Sub), a, b) => {
                let Some(result) = derived else {
                    return Through::Nothing;
                };
                let (left, right) = (self.canonical(*a), self.canonical(*b));
                let added = if *op == Binary::Add {
                    self.signed_constant(if left == v { right } else { left })
                } else if left == v {
                    self.signed_constant(right).and_then(i64::checked_neg)
                } else {
                    None
                };
                Through::Value(result, back || added.is_none_or(|added| added < 0))
            }
            Op::Select {
                condition,
                then,
                otherwise,
            } => {
                let chosen = match self.signed_constant(*condition) {
                    Some(0) => self.canonical(*otherwise) == v,
                    Some(_) => self.canonical(*then) == v,
                    None => true,
                };
                match derived {
                    Some(result) if chosen => Through::Value(result, back),
                    Some(_) | None => Through::Nothing,
                }
            }
            Op::Load { .. } | Op::Store { .. } | Op::Call { .. } | Op::SystemCall { .. } => {
                if back {
                    Through::Reaches
                } else {
                    Through::Nothing
                }
            }
            Op::Intrinsic { .. } => Through::Reaches,
            // Anywhere (an alignment, a scaled index), which only an
            // access, a call, a store or a jump through it makes a reach.
            Op::Const(_)
            | Op::Undefined(..)
            | Op::Landing { .. }
            | Op::Unary(..)
            | Op::Binary(..)
            | Op::Flag(..)
            | Op::Extract { .. }
            | Op::Concat { .. }
            | Op::Extend { .. }
            | Op::Lanes { .. }
            | Op::Float { .. } => match derived {
                Some(result) => Through::Value(result, true),
                None => Through::Nothing,
            },
        }
    }

    /// `v`'s value read signed, if it is a constant of at most 64 bits.
    fn signed_constant(&self, v: Value) -> Option<i64> {
        let Kind::Const(bits) = self.kind(v) else {
            return None;
        };
        let shift = 64u32.checked_sub(u32::from(bits.width()))?;
        Some(bits.low_u64().cast_signed() << shift >> shift)
    }

    /// Whether the bytes `offset..end` hold bytes of declared stack
    /// parameters without being one of them (an aggregate's, declared 8
    /// bytes at a time and read 16 at once): they are read from memory,
    /// which takes the parameters' values at entry.
    fn declared_parts(&self, offset: i64, end: i64) -> bool {
        self.returns.declared.as_ref().is_some_and(|declared| {
            declared.iter().any(|&(source, ..)| match source {
                Source::Stack { offset: at, bytes } => {
                    let past = at.saturating_add(i64::from(bytes));
                    at < end && offset < past && (at, past) != (offset, end)
                }
                Source::Register(_) => false,
            })
        })
    }

    /// The reads among `members` (the accesses of the slot `offset..end`)
    /// that may read what the caller left there: of a slot in its
    /// argument area (from `area` up), those some path from the entry
    /// reaches before a store of the whole slot (a store of part of it
    /// leaves the rest as it was); all of them where no store writes the
    /// whole slot.
    fn unwritten_reads(&self, members: &[&Access], offset: i64, end: i64, area: i64) -> Vec<At> {
        if offset < area {
            return Vec::new();
        }
        let reads = || members.iter().filter(|a| !a.write).map(|a| a.at);
        let stores: BTreeSet<InstId> = members
            .iter()
            .filter(|a| a.write && a.offset == offset && a.offset + i64::from(a.bytes) == end)
            .filter_map(|a| match a.at {
                At::Inst(inst) => Some(inst),
                At::Argument(..) => None,
            })
            .collect();
        if stores.is_empty() {
            return reads().collect();
        }
        let wanted: BTreeSet<InstId> = reads()
            .filter_map(|at| match at {
                At::Inst(inst) | At::Argument(Site::Call(inst), _) => Some(inst),
                At::Argument(Site::Tail(_), _) => None,
            })
            .collect();
        // Each block's first store of the whole slot, and where the reads
        // are.
        let mut first: BTreeMap<BlockId, usize> = BTreeMap::new();
        let mut position: BTreeMap<InstId, (BlockId, usize)> = BTreeMap::new();
        for (id, block) in self.blocks() {
            for (index, &inst) in block.insts.iter().enumerate() {
                if stores.contains(&inst) {
                    first.entry(id).or_insert(index);
                }
                if wanted.contains(&inst) {
                    position.insert(inst, (id, index));
                }
            }
        }
        // The blocks control may enter with the slot not written.
        let mut unwritten = BTreeSet::new();
        let mut work = alloc::vec![BlockId(0)];
        while let Some(id) = work.pop() {
            if !unwritten.insert(id) || first.contains_key(&id) {
                continue;
            }
            if let Some(block) = self.l1.block(id) {
                work.extend(block.terminator.targets().map(|target| target.block));
            }
        }
        reads()
            .filter(|&at| {
                let (block, index) = match at {
                    At::Inst(inst) | At::Argument(Site::Call(inst), _) => {
                        match position.get(&inst) {
                            Some(&at) => at,
                            None => return true,
                        }
                    }
                    At::Argument(Site::Tail(block), _) => (block, usize::MAX),
                };
                unwritten.contains(&block) && first.get(&block).is_none_or(|&store| index < store)
            })
            .collect()
    }

    /// The objects promoted out of the frame (see the [module](self)): an
    /// offset whose every use is as a call's argument at a declared
    /// parameter pointing to one type `T` (`stat(path, &st)`) is the
    /// address of a `T` there, its bytes `sizeof(T)` from it, where they
    /// are below the entry stack pointer, no other address is taken among
    /// them, every slot they overlap lies inside them and lives in
    /// memory, and no address below them may reach them (an address
    /// used otherwise, or passed where no declaration bounds it, may reach
    /// any byte above it; one passed at declared parameters only, as far
    /// as their largest type; one of `bounded`, as far as it says).
    /// `others`: the offsets of stack addresses
    /// used otherwise than as calls' register arguments; `passed`: those
    /// arguments' offsets, with their parameters' declared targets.
    fn promotions(
        &self,
        slots: &[Slot],
        others: &[i64],
        passed: &[(i64, Option<TypeId>)],
        bounded: &[(i64, i64)],
    ) -> Vec<(i64, i64, TypeId)> {
        // How far each address taken may reach, past its first byte; and
        // the one type it is declared to point to, if any.
        let mut reach: BTreeMap<i64, (i64, Option<TypeId>)> = BTreeMap::new();
        for &offset in others {
            let far = bounded
                .iter()
                .find(|&&(start, end)| start <= offset && offset < end)
                .map_or(i64::MAX, |&(_, end)| end);
            reach.insert(offset, (far, None));
        }
        for &(offset, target) in passed {
            let bytes = target
                .and_then(|target| self.types.width(target))
                .and_then(|width| i64::try_from(width / 8).ok());
            let (far, kept) = reach.entry(offset).or_insert((i64::MIN, target));
            match bytes {
                Some(bytes) if *kept == target => {
                    *far = (*far).max(offset.saturating_add(bytes));
                }
                Some(_) | None => *far = i64::MAX,
            }
        }
        let mut promoted = Vec::new();
        for (&offset, &(end, target)) in &reach {
            let Some(target) = target else {
                continue;
            };
            if end == i64::MAX || end > 0 {
                continue;
            }
            let reached = reach.range(..offset).any(|(_, &(far, _))| far > offset)
                || reach.range(offset + 1..end).next().is_some();
            let slots_inside = slots
                .iter()
                .filter(|slot| slot.offset < end && offset < slot.end)
                .all(|slot| slot.home == Home::Frame && slot.offset >= offset && slot.end <= end);
            if !reached && slots_inside {
                promoted.push((offset, end, target));
            }
        }
        promoted
    }

    /// The type the parameter of argument `index` of the call at `site`
    /// is declared to point to, where that states the extent of what it
    /// points to: a complete type of a known size, not a character type
    /// (a `char *` points to a string or a buffer whose length the type
    /// does not say), nor `void`. From the callee's declared prototype or
    /// the arguments its parsed format string gives (`scanf`'s `%d`: an
    /// `int *`).
    pub(super) fn declared_target(&self, site: Site, index: usize) -> Option<TypeId> {
        let callee = self.callees.get(&site)?;
        if callee.interfaced {
            return None;
        }
        let signature = self.types.signature(callee.signature)?;
        let ty = match signature.parameters.get(index) {
            Some(&ty) => ty,
            None => *callee
                .variadic
                .get(index.checked_sub(signature.parameters.len())?)?,
        };
        let Some(&Type::Pointer(Some(target))) = self.types.get(ty) else {
            return None;
        };
        let character = match self.types.get(target)? {
            Type::Char { .. } => true,
            Type::Array { element, .. } => {
                matches!(self.types.get(*element), Some(Type::Char { .. }))
            }
            Type::Bits(_)
            | Type::Int(_)
            | Type::UInt(_)
            | Type::Bool(_)
            | Type::Float(_)
            | Type::Pointer(_)
            | Type::Code(_)
            | Type::Struct(_)
            | Type::Union(_)
            | Type::Vector { .. }
            | Type::Enum(_) => false,
        };
        let width = self.types.width(target)?;
        (!character && width > 0 && width.is_multiple_of(8)).then_some(target)
    }

    /// The highest stack pointer at a call (not a tail call), from the
    /// entry stack pointer: `i64::MIN` without calls, `None` if one is not
    /// at a known offset.
    fn call_top(&self) -> Option<i64> {
        let sp = usize::from(self.cx.stack_pointer.0);
        let mut top = i64::MIN;
        for &site in self.callees.keys() {
            if !matches!(site, Site::Call(_)) {
                continue;
            }
            let stack = self.site_registers(site).get(sp).copied()?;
            top = top.max(self.address(stack)?);
        }
        Some(top)
    }

    /// The callee-saved register, or the link register (AArch64's `x30`,
    /// which holds the return address: no input of the function but where
    /// to return, which a return through what is loaded back reads as
    /// the caller's: [`Self::caller_return`]), whose entry value `value`,
    /// stored to the stack bytes `offset..end`, saves there: on every path
    /// (through block parameters) that entry value, or what a load of
    /// those bytes read back (saved again after a restore, as separate
    /// shrink-wrapping does); `None` if it is anything else.
    fn saved(&self, value: Value, offset: i64, end: i64) -> Option<RegisterId> {
        let mut register = None;
        let mut seen = BTreeSet::new();
        let mut work = alloc::vec![self.canonical(value)];
        while let Some(value) = work.pop() {
            if !seen.insert(value) {
                continue;
            }
            if seen.len() > SAVE_STEPS {
                return None;
            }
            if let Some(entry) = self.saved_entry(value) {
                if *register.get_or_insert(entry) != entry {
                    return None;
                }
                continue;
            }
            match self.kind(value) {
                Kind::Load(inst) => match self.l1.inst(inst).map(|i| &i.op) {
                    Some(&Op::Load { address, bytes, .. })
                        if self.address(address) == Some(offset)
                            && offset + i64::from(bytes) == end => {}
                    _ => return None,
                },
                Kind::Phi => {
                    let Some(&ValueInfo {
                        definition: Definition::Parameter { block, index },
                        ..
                    }) = self.l1.value(value)
                    else {
                        return None;
                    };
                    for (_, argument) in self.incoming(block, index as usize) {
                        work.push(self.canonical(argument));
                    }
                }
                Kind::Entry(_)
                | Kind::None
                | Kind::Const(_)
                | Kind::Undefined(..)
                | Kind::Address(_)
                | Kind::Pure(_)
                | Kind::Result(_)
                | Kind::CallView { .. } => return None,
            }
        }
        register
    }

    /// The callee-saved or link register whose entry value `value` is, or
    /// the low part of (as a save of `xmm6` stores, the part of `zmm6` the
    /// Microsoft x64 convention keeps). An entry value the reading view
    /// drops (undefined, [`Unknown::Entry`]) is still its register's: its
    /// save stays one.
    pub(super) fn saved_entry(&self, value: Value) -> Option<RegisterId> {
        let whole = if let Kind::Pure(inst) = self.kind(value)
            && let Some(&Op::Extract {
                value, offset: 0, ..
            }) = self.l1.inst(inst).map(|i| &i.op)
        {
            value
        } else {
            value
        };
        let entry = match self.kind(whole) {
            Kind::Entry(entry)
            | Kind::Undefined(
                _,
                Unknown::Entry {
                    register: Some(entry),
                },
            ) => entry,
            Kind::None
            | Kind::Const(_)
            | Kind::Undefined(..)
            | Kind::Address(_)
            | Kind::Phi
            | Kind::Pure(_)
            | Kind::Load(_)
            | Kind::Result(_)
            | Kind::CallView { .. } => return None,
        };
        (self.cx.convention.callee_saved.contains(&entry) || self.cx.link == Link::Register(entry))
            .then_some(entry)
    }

    /// The callee-saved registers the function keeps as its convention
    /// says ([`Found::kept`](super::Found::kept)): each saved in a slot
    /// that holds nothing but its saves, and holding its entry value (as
    /// found, or loaded back from that slot) at every return and every
    /// way out to code that may return to the caller.
    pub(super) fn kept_registers(&self) -> BTreeSet<RegisterId> {
        // Each register's save slots, and the slots anything else writes.
        let mut slots: BTreeMap<RegisterId, BTreeSet<usize>> = BTreeMap::new();
        let mut spoiled: BTreeSet<usize> = BTreeSet::new();
        for (&inst, &slot) in &self.frame.accesses {
            let Some(&Op::Store { value, .. }) = self.l1.inst(inst).map(|i| &i.op) else {
                continue;
            };
            match self.saved_entry(value) {
                Some(register) if self.cx.convention.callee_saved.contains(&register) => {
                    slots.entry(register).or_default().insert(slot);
                }
                Some(_) | None => {
                    spoiled.insert(slot);
                }
            }
        }
        let owners = |slot: usize| slots.values().filter(|s| s.contains(&slot)).count();
        let keep: Vec<(RegisterId, BTreeSet<usize>)> = slots
            .iter()
            .filter(|(_, saved)| {
                saved
                    .iter()
                    .all(|&slot| !spoiled.contains(&slot) && owners(slot) == 1)
            })
            .map(|(&register, saved)| (register, saved.clone()))
            .collect();
        keep.into_iter()
            .filter(|(register, saved)| self.held_at_exits(*register, saved))
            .map(|(register, _)| register)
            .collect()
    }

    /// Whether `register` holds its entry value, as found or loaded back
    /// from one of its save `slots`, at every return and every way out to
    /// code that may return to the caller.
    fn held_at_exits(&self, register: RegisterId, slots: &BTreeSet<usize>) -> bool {
        self.blocks().all(|(_, block)| {
            let state = match &block.terminator {
                Terminator::Return { state, .. }
                | Terminator::Leave {
                    state,
                    returns: true,
                    ..
                } => state,
                Terminator::Leave { returns: false, .. }
                | Terminator::Jump(_)
                | Terminator::Branch { .. }
                | Terminator::IndirectJump { .. }
                | Terminator::Invoke { .. }
                | Terminator::Trap(_)
                | Terminator::Stop
                | Terminator::Open => return true,
            };
            state
                .registers
                .get(usize::from(register.0))
                .is_some_and(|&value| self.holds_entry(value, register, slots))
        })
    }

    /// Whether `value` is `register`'s entry value on every path (through
    /// block parameters): as found, or loaded back whole from one of its
    /// save `slots`, which hold nothing but its saves.
    fn holds_entry(&self, value: Value, register: RegisterId, slots: &BTreeSet<usize>) -> bool {
        let mut seen = BTreeSet::new();
        let mut work = alloc::vec![self.canonical(value)];
        while let Some(value) = work.pop() {
            if !seen.insert(value) {
                continue;
            }
            if seen.len() > SAVE_STEPS {
                return false;
            }
            if self.saved_entry(value) == Some(register) {
                continue;
            }
            match self.kind(value) {
                Kind::Load(inst) => {
                    let Some(&Op::Load { address, bytes, .. }) = self.l1.inst(inst).map(|i| &i.op)
                    else {
                        return false;
                    };
                    // The load's own slot (a slot reused for other values
                    // is several of one offset).
                    let restored = self.address(address).is_some_and(|offset| {
                        self.frame.accesses.get(&inst).is_some_and(|&slot| {
                            slots.contains(&slot)
                                && self.frame.slots.get(slot).is_some_and(|s| {
                                    s.offset == offset && s.end == offset + i64::from(bytes)
                                })
                        })
                    });
                    if !restored {
                        return false;
                    }
                }
                Kind::Phi => {
                    let Some(&ValueInfo {
                        definition: Definition::Parameter { block, index },
                        ..
                    }) = self.l1.value(value)
                    else {
                        return false;
                    };
                    for (_, argument) in self.incoming(block, index as usize) {
                        work.push(self.canonical(argument));
                    }
                }
                Kind::Entry(_)
                | Kind::None
                | Kind::Const(_)
                | Kind::Undefined(..)
                | Kind::Address(_)
                | Kind::Pure(_)
                | Kind::Result(_)
                | Kind::CallView { .. } => return false,
            }
        }
        true
    }

    /// The stores of a call's return address: the store whose memory the
    /// call takes, of the call's return address.
    fn pushes(&self) -> BTreeSet<InstId> {
        let mut pushes = BTreeSet::new();
        for site in self.callees.keys() {
            let Site::Call(inst) = *site else {
                continue;
            };
            let Some(Op::Call {
                return_address,
                memory,
                ..
            }) = self.l1.inst(inst).map(|i| &i.op)
            else {
                continue;
            };
            if let Some((store, Op::Store { value, .. })) = self.defining(*memory)
                && self.canonical(*value) == self.canonical(*return_address)
            {
                pushes.insert(store);
            }
        }
        pushes
    }

    /// The calls made on a stack other than the function's own frame: the
    /// stack pointer at the call (after a push of the return address) is
    /// a stack address whose link (the pushed return address) is not
    /// below the entry stack pointer (in the caller's frame, or over the
    /// return address), or is not computed from the entry stack pointer at
    /// all (loaded, another register's: a stack switched to). C cannot
    /// say either: the callee would run on, and the push would write,
    /// memory that is not the frame. A stack pointer computed from the
    /// entry one at an unknown offset (`alloca`, alignment) is the frame's.
    fn stack_tricks(&self) -> BTreeSet<Site> {
        let sp = usize::from(self.cx.stack_pointer.0);
        let link = i64::from(self.cx.link_bytes());
        let mut derived: Option<Vec<bool>> = None;
        let mut tricks = BTreeSet::new();
        for &site in self.callees.keys() {
            if !matches!(site, Site::Call(_)) {
                continue;
            }
            let Some(&stack) = self.site_registers(site).get(sp) else {
                continue;
            };
            let own = if let Some(offset) = self.address(stack) {
                offset.saturating_add(link) <= 0
            } else {
                let derived = derived.get_or_insert_with(|| self.stack_computed());
                derived.get(stack.0 as usize).copied().unwrap_or(false)
            };
            if !own {
                tricks.insert(site);
            }
        }
        tricks
    }

    /// Which values are computed from the entry stack pointer: a stack
    /// address; a pure operation on one; a block parameter whose every
    /// argument is one; a load of a slot of the function's own frame that
    /// every store to it, of its shape, saves one in (a stack pointer saved
    /// before an `alloca` and restored; callees are taken not to write
    /// it). The greatest such set, so a loop does not make a value one by
    /// itself.
    fn stack_computed(&self) -> Vec<bool> {
        let l1 = self.l1;
        let sp = self.cx.stack_pointer;
        let root =
            |v: Value| matches!(self.kind(v), Kind::Address(_)) || self.kind(v) == Kind::Entry(sp);
        let (candidates, stores) = self.stack_candidates();
        let mut derived = alloc::vec![false; l1.values.len()];
        for &(value, _) in &candidates {
            if let Some(slot) = derived.get_mut(value.0 as usize) {
                *slot = true;
            }
        }
        let is = |derived: &[bool], v: Value| {
            root(v) || derived.get(v.0 as usize).copied().unwrap_or(false)
        };
        let mut changed = true;
        while changed {
            changed = false;
            for &(value, candidate) in &candidates {
                if root(value) || !is(&derived, value) {
                    continue;
                }
                let keep = match candidate {
                    Candidate::Pure(inst) => l1
                        .inst(inst)
                        .is_some_and(|i| i.op.operands().into_iter().any(|o| is(&derived, o))),
                    Candidate::Phi(block, index) => {
                        let incoming = self.incoming(block, index);
                        !incoming.is_empty() && incoming.iter().all(|&(_, a)| is(&derived, a))
                    }
                    Candidate::Load(start, end) => {
                        let mut writers = stores
                            .iter()
                            .filter(|&&(a, b, _)| a < end && start < b)
                            .peekable();
                        writers.peek().is_some()
                            && writers.all(|&(a, b, stored)| {
                                (a, b) == (start, end) && is(&derived, stored)
                            })
                    }
                };
                if !keep && let Some(slot) = derived.get_mut(value.0 as usize) {
                    *slot = false;
                    changed = true;
                }
            }
        }
        for (index, slot) in derived.iter_mut().enumerate() {
            *slot |= root(Value(u32::try_from(index).unwrap_or(u32::MAX)));
        }
        derived
    }

    /// The values [`stack_computed`](Self::stack_computed) may find
    /// computed from the entry stack pointer, with how; and the stores at
    /// known stack offsets.
    fn stack_candidates(&self) -> (Vec<(Value, Candidate)>, Vec<StackStore>) {
        let l1 = self.l1;
        let mut candidates = Vec::new();
        let mut stores = Vec::new();
        for (id, block) in self.blocks() {
            for (index, &parameter) in block.parameters.iter().enumerate() {
                candidates.push((parameter, Candidate::Phi(id, index)));
            }
            for &inst in &block.insts {
                let Some(i) = l1.inst(inst) else {
                    continue;
                };
                match i.op {
                    Op::Unary(..)
                    | Op::Binary(..)
                    | Op::Extract { .. }
                    | Op::Concat { .. }
                    | Op::Extend { .. }
                    | Op::Select { .. } => {
                        candidates.extend(i.results.iter().map(|&r| (r, Candidate::Pure(inst))));
                    }
                    Op::Load { address, bytes, .. } => {
                        let slot = self
                            .address(address)
                            .map(|start| (start, start.saturating_add(i64::from(bytes))));
                        if let Some((start, end)) = slot
                            && end <= 0
                            && let Some(&result) = i.results.first()
                        {
                            candidates.push((result, Candidate::Load(start, end)));
                        }
                    }
                    Op::Store { address, value, .. } => {
                        if let Some(start) = self.address(address) {
                            let bytes = i64::from(self.width(value).div_ceil(8));
                            stores.push((start, start.saturating_add(bytes), value));
                        }
                    }
                    Op::Const(_)
                    | Op::Undefined(..)
                    | Op::Flag(..)
                    | Op::Lanes { .. }
                    | Op::Float { .. }
                    | Op::Intrinsic { .. }
                    | Op::Call { .. }
                    | Op::SystemCall { .. }
                    | Op::Landing { .. } => {}
                }
            }
        }
        (candidates, stores)
    }

    /// The stack offset `value` is, if it is a stack address.
    pub(super) fn address(&self, value: Value) -> Option<i64> {
        match self.kind(value) {
            Kind::Address(offset) => Some(offset),
            Kind::None
            | Kind::Const(_)
            | Kind::Undefined(..)
            | Kind::Entry(_)
            | Kind::Phi
            | Kind::Pure(_)
            | Kind::Load(_)
            | Kind::Result(_)
            | Kind::CallView { .. } => None,
        }
    }

    /// The accesses at known stack offsets (but `pushes`).
    fn accesses(&self, pushes: &BTreeSet<InstId>) -> Vec<Access> {
        let mut accesses = Vec::new();
        for (_, block) in self.blocks() {
            for &inst in &block.insts {
                let Some(i) = self.l1.inst(inst) else {
                    continue;
                };
                let (address, bytes, value) = match i.op {
                    Op::Load {
                        address,
                        bytes,
                        atomic: None,
                        ..
                    } => (address, bytes, None),
                    Op::Store {
                        address,
                        value,
                        atomic: None,
                        ..
                    } if !pushes.contains(&inst) => {
                        (address, self.width(value).div_ceil(8), Some(value))
                    }
                    Op::Load { .. }
                    | Op::Store { .. }
                    | Op::Const(_)
                    | Op::Undefined(..)
                    | Op::Unary(..)
                    | Op::Binary(..)
                    | Op::Flag(..)
                    | Op::Extract { .. }
                    | Op::Concat { .. }
                    | Op::Extend { .. }
                    | Op::Select { .. }
                    | Op::Lanes { .. }
                    | Op::Float { .. }
                    | Op::Intrinsic { .. }
                    | Op::Call { .. }
                    | Op::SystemCall { .. }
                    | Op::Landing { .. } => continue,
                };
                if let Some(offset) = self.address(address) {
                    accesses.push(Access {
                        offset,
                        bytes,
                        write: value.is_some(),
                        value,
                        at: At::Inst(inst),
                    });
                }
            }
        }
        let sp = usize::from(self.cx.stack_pointer.0);
        for (&site, callee) in &self.callees {
            let Some(&stack) = self.site_registers(site).get(sp) else {
                continue;
            };
            let Some(base) = self.address(stack) else {
                continue;
            };
            for (index, source) in callee.arguments.iter().enumerate() {
                if let Source::Stack { offset, bytes } = *source {
                    accesses.push(Access {
                        offset: base + offset,
                        bytes,
                        write: false,
                        value: None,
                        at: At::Argument(site, index),
                    });
                }
            }
        }
        accesses
    }

    /// Whether a stack address is used as a value (other than as the
    /// address of a load or store at a known offset, in offset arithmetic,
    /// or in an operation whose result is narrower than an address; the
    /// stack pointer of a call in `tricks` is, by its escape), and the
    /// offsets so used.
    pub(super) fn taken(&self, tricks: &BTreeSet<Site>) -> (bool, Vec<i64>) {
        let mut values = Vec::new();
        for (id, block) in self.blocks() {
            for &inst in &block.insts {
                self.taken_by(inst, &mut values);
            }
            self.taken_at_end(id, &block.terminator, &mut values);
        }
        let sp = usize::from(self.cx.stack_pointer.0);
        for &site in tricks {
            values.extend(self.site_registers(site).get(sp));
        }
        let offsets: Vec<i64> = values.into_iter().filter_map(|v| self.address(v)).collect();
        (!offsets.is_empty(), offsets)
    }

    /// The offsets [`taken`](Self::taken) finds, in two: those used
    /// otherwise than as a call's register argument, and those passed as
    /// one, each with the type its parameter is declared to point to
    /// ([`declared_target`](Self::declared_target)), if it states one.
    fn uses(&self, tricks: &BTreeSet<Site>) -> (Vec<i64>, Vec<(i64, Option<TypeId>)>) {
        let mut values = Vec::new();
        let mut passed = Vec::new();
        for (id, block) in self.blocks() {
            for &inst in &block.insts {
                if let Some(Op::Call { registers, .. }) = self.l1.inst(inst).map(|i| &i.op) {
                    let site = Site::Call(inst);
                    let Some(callee) = self.callees.get(&site) else {
                        continue;
                    };
                    for (index, source) in callee.arguments.iter().enumerate() {
                        if let Source::Register(piece) = source
                            && piece.register != self.cx.stack_pointer
                            && let Some(&value) = registers.get(usize::from(piece.register.0))
                            && let Some(offset) = self.address(value)
                        {
                            passed.push((offset, self.declared_target(site, index)));
                        }
                    }
                } else {
                    self.taken_by(inst, &mut values);
                }
            }
            self.taken_at_end(id, &block.terminator, &mut values);
        }
        let sp = usize::from(self.cx.stack_pointer.0);
        for &site in tricks {
            values.extend(self.site_registers(site).get(sp));
        }
        let others = values.into_iter().filter_map(|v| self.address(v)).collect();
        (others, passed)
    }

    /// The values `inst` uses as values (some may be stack addresses).
    pub(super) fn taken_by(&self, inst: InstId, values: &mut Vec<Value>) {
        let Some(i) = self.l1.inst(inst) else {
            return;
        };
        match &i.op {
            Op::Load { atomic: None, .. }
            | Op::Const(_)
            | Op::Undefined(..)
            | Op::Landing { .. } => {}
            Op::Load {
                address,
                atomic: Some(_),
                ..
            } => values.push(*address),
            Op::Store {
                address,
                value,
                atomic,
                ..
            } => {
                values.push(*value);
                if atomic.is_some() {
                    values.push(*address);
                }
            }
            Op::Call { registers, .. } => {
                self.register_arguments(Site::Call(inst), registers, values);
            }
            Op::SystemCall { registers, .. } => {
                for register in self.system_call_registers(inst) {
                    values.extend(registers.get(usize::from(register.0)));
                }
            }
            Op::Intrinsic { inputs, .. } => values.extend(inputs),
            op @ (Op::Unary(..)
            | Op::Binary(..)
            | Op::Flag(..)
            | Op::Extract { .. }
            | Op::Concat { .. }
            | Op::Extend { .. }
            | Op::Select { .. }
            | Op::Lanes { .. }
            | Op::Float { .. }) => {
                // Offset arithmetic, a copy, or a narrow result carries
                // no address on.
                if let Some(&result) = i.results.first()
                    && self.address(result).is_none()
                    && self.canonical(result) == result
                    && self.width(result) >= self.pointer
                {
                    values.extend(op.operands());
                }
            }
        }
    }

    /// The values block `id`'s `terminator` uses as values, and those it
    /// passes to block parameters that are no stack addresses.
    pub(super) fn taken_at_end(
        &self,
        id: BlockId,
        terminator: &Terminator,
        values: &mut Vec<Value>,
    ) {
        match terminator {
            Terminator::IndirectJump { address, .. } => values.push(*address),
            Terminator::Return { address, state } => {
                values.push(*address);
                for piece in &self.returns.pieces {
                    values.extend(state.registers.get(usize::from(piece.register.0)));
                }
            }
            Terminator::Leave { address, state, .. } => {
                values.push(*address);
                self.register_arguments(Site::Tail(id), &state.registers, values);
            }
            Terminator::Jump(_)
            | Terminator::Branch { .. }
            | Terminator::Invoke { .. }
            | Terminator::Trap(_)
            | Terminator::Stop
            | Terminator::Open => {}
        }
        for target in terminator.targets() {
            let parameters = self
                .l1
                .block(target.block)
                .map_or(&[][..], |b| b.parameters.as_slice());
            for (&argument, &parameter) in target.arguments.iter().zip(parameters) {
                if self.address(parameter).is_none() {
                    values.push(argument);
                }
            }
        }
    }

    /// The values the call at `site` passes in registers (but the stack
    /// pointer).
    fn register_arguments(&self, site: Site, registers: &[Value], values: &mut Vec<Value>) {
        let Some(callee) = self.callees.get(&site) else {
            return;
        };
        for source in &callee.arguments {
            if let Source::Register(piece) = source
                && piece.register != self.cx.stack_pointer
            {
                values.extend(registers.get(usize::from(piece.register.0)));
            }
        }
    }
}

impl Frame {
    /// The `Frame` variables. Below the entry stack pointer, memory: one
    /// span from the lowest address that may reach any byte above it (or
    /// the lowest slot, where the stack escapes) over every byte above
    /// it of its slots in memory and the addresses taken, up to where the
    /// object at the highest of those may end ([`Self::taken_end`]); one
    /// for each other reach of an address used as a value with the slots
    /// it overlaps; each cut around the slots that are locals and the
    /// promoted objects. Every other slot in a `Frame` variable is one of
    /// its own.
    fn regions(&mut self) {
        let mut spans: Vec<(i64, i64, bool)> = Vec::new();
        let mut pieces: Vec<(i64, i64)> = Vec::new();
        for slot in &self.slots {
            if slot.home != Home::Frame {
                continue;
            }
            if slot.reached && slot.offset < 0 {
                pieces.push((slot.offset, slot.end));
            } else {
                spans.push((slot.offset, slot.end, slot.reached));
            }
        }
        for (&offset, &far) in &self.reach {
            if offset < 0 {
                pieces.push((offset, if far == i64::MAX { offset + 1 } else { far }));
            }
        }
        let low = if self.escaped {
            pieces.iter().map(|&(start, _)| start).min()
        } else {
            self.reach
                .iter()
                .filter(|&(&offset, &far)| offset < 0 && far == i64::MAX)
                .map(|(&offset, _)| offset)
                .min()
        };
        pieces.sort_unstable();
        let mut own: Vec<(i64, i64)> = Vec::new();
        for (start, end) in pieces {
            let joins = |last: &(i64, i64)| start < last.1 || low.is_some_and(|low| last.0 >= low);
            match own.last_mut() {
                Some(last) if joins(last) => last.1 = last.1.max(end),
                Some(_) | None => own.push((start, end)),
            }
        }
        if let Some(top) = self.taken_end()
            && let Some(last) = own.last_mut()
            && low.is_some_and(|low| last.0 >= low)
        {
            last.1 = last.1.max(top);
        }
        // Cut around the locals and promoted objects inside.
        let mut holes: Vec<(i64, i64)> = self
            .slots
            .iter()
            .filter(|slot| slot.home == Home::Local)
            .map(|slot| (slot.offset, slot.end))
            .chain(self.promoted.iter().map(|&(start, end, _)| (start, end)))
            .collect();
        holes.sort_unstable();
        for (start, end) in own {
            let mut at = start;
            for &(hole_start, hole_end) in &holes {
                if hole_end <= at || hole_start >= end {
                    continue;
                }
                if hole_start > at {
                    spans.push((at, hole_start, true));
                }
                at = at.max(hole_end);
            }
            if at < end {
                spans.push((at, end, true));
            }
        }
        spans.sort_unstable();
        for (start, end, memory) in spans {
            let region = self.span(start, end, memory);
            self.regions.push(region);
        }
        for &(start, end, ty) in &self.promoted {
            self.regions.push(Region {
                offset: start,
                bytes: end.abs_diff(start),
                whole: false,
                promoted: Some(ty),
                memory: true,
            });
        }
        self.regions.sort_by_key(|region| region.offset);
        self.finish(None);
    }
}
