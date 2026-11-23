//! Variadic definitions: the prologue's spill of the unnamed argument
//! registers and `va_start`'s initialisation of a `va_list`, by the
//! convention's rule ([`VaList`]), prove a function variadic after its
//! named arguments.
//!
//! - System V x86-64: a `va_list` at stack offset `l` is a store of
//!   `gp_offset` = 8·n at `l` and `fp_offset` = 48 + 16·m at `l + 4` (or one
//!   8-byte store of both), of the address of the caller's stack
//!   arguments after the named ones at `l + 8` (the entry stack pointer
//!   plus the return address plus 8·s), and of the register save area's
//!   address `a` at `l + 16`, below the entry stack pointer. The save
//!   area holds the entry value of each integer argument register k ≥ n
//!   at `a + 8·k`, and either no vector register or the low 128 bits of
//!   the entry value of each vector argument register k ≥ m at
//!   `a + 48 + 16·k`, every such store in code entered only when the low
//!   byte of the count register (`al`) is not 0.
//! - Microsoft x64: the address of the home slot after the n-th (n ≥ 1)
//!   is used as a value (`va_start`'s `char *`), and the home slot of
//!   each integer argument register k ≥ n holds its entry value (at least
//!   one: the n-th register is an argument register).
//!
//! - AAPCS64 ("Variable argument lists"): a `va_list` at stack offset `l`
//!   is a store of the address of the caller's stack arguments after the
//!   named ones (`__stack`, the entry stack pointer plus 8·s) at `l`, of
//!   `__gr_offs` = g at `l + 24` and `__vr_offs` = v at `l + 28` (or one
//!   8-byte store of both), g a multiple of 8 and v of 16, neither
//!   positive; and, where registers of a class are saved, of the address
//!   their area ends at (`__gr_top` at `l + 8`, `__vr_top` at `l + 16`),
//!   at or below the entry stack pointer. The integer area holds the
//!   entry values of i consecutive integer argument registers
//!   `x`*n*..`x`*n+i−1* in 8 bytes each, the last just below `__gr_top`;
//!   the vector area the low 128 bits of j consecutive `q`*m*.. in 16
//!   bytes each below `__vr_top`; no count register guards them. At least
//!   one register is saved, −8·i ≤ g and −16·j ≤ v (GCC saves only
//!   what a `va_arg` may read, and may store an offset already advanced
//!   past a `va_arg` it folded in), and each area holds its saves alone.
//!   The named counts are the saves' first registers, *n* and *m*; for a
//!   class with no save, those up to the last whose entry value an
//!   instruction other than a call reads. Such a definition is recognised
//!   but not yet printed as C's.
//!
//! Every store must be there at the offsets the named count gives: the
//! saves once, no other store writing the save area (System V) or the
//! unnamed arguments' home slots (Microsoft); System V's `va_list` stores
//! the first to each field (a `va_arg` the compiler expands in place
//! stores `gp_offset` and `overflow_arg_area` again). Otherwise the
//! function is not recognised. The named counts are those of the first
//! (lowest) `va_list` that fits.
//!
//! A recognised definition is called as a variadic one whether or not it
//! is printed as one ([`Interface::variadic`](super::Interface)): its
//! callers pass its named arguments, then what they set.
//!
//! A recognised definition is printed as C's ([`Plan`]: `T f(named,
//! ...)`, `va_list ap; va_start(ap, last);`) where its declared prototype,
//! if any, is variadic with the named parameters, its named arguments
//! are in registers, and the code says nothing C's cannot:
//! - the saves and `va_start`'s stores are one [`Stmt::VaStart`]
//!   (`binbun_ast::ir`), in place of the last `va_list` store (System V:
//!   the four in one block, with nothing between them but operations and
//!   stores at known stack offsets) or first in the body (Microsoft: its
//!   `va_list` is a pointer computed from the entry stack pointer);
//! - nothing else accesses the save area, the `va_list` or the unnamed
//!   arguments' home slots at a known offset, and no address in them is
//!   used as a value but the `va_list`'s own (passed on whole) and, for
//!   Microsoft, the first unnamed argument's (the `va_list`'s value);
//! - the code the count register's test guards (System V) only saves
//!   vector registers and checks that the save area is 16-byte aligned,
//!   which it is under the ABI's stack alignment (the stack pointer plus
//!   the return address's bytes is a multiple of 16 at entry), so its
//!   traps are never taken: that branch and those blocks are absorbed
//!   into the `va_start` ([`Origin::Absorbed`](binbun_ast::ir::Origin)),
//!   their join receiving the same values from them as from the branch;
//! - the unnamed argument registers' entry values (and the count
//!   register's) are used only by the saves, the count's test, and calls
//!   that pass an unnamed register on in place (as an argument in its own
//!   register): C reaches them only through the `va_list`, so their entry
//!   values are undefined (an argument passed on in place is undefined:
//!   [`Mapping::unnamed`](crate::mapping::Mapping::unnamed)).
//!
//! The save area and the unnamed arguments' home slots are then no L2
//! variable; System V's `va_list` is its own `Frame` variable.

use alloc::collections::BTreeSet;
use alloc::vec::Vec;

use binbun_ast::ir::{Save, Va, VaList as Layout};
use binbun_semantics::ir::{Binary, RegisterId};
use binbun_ssa::condition::Relation;
use binbun_ssa::ir::{BlockId, InstId, Op, Terminator, Unknown, Value};
use binbun_ssa::stack::entry_value;

use super::facts::{Kind, Lowering, Site};
use super::{Named, VaList, Variadic};
use crate::mapping::Source;
use crate::prototype::Format;

/// System V's register save area: six 8-byte integer registers, then
/// eight 16-byte vector registers.
const SAVE_AREA: i64 = 6 * 8 + 8 * 16;

/// Where System V's vector registers start in the save area.
const VECTORS: i64 = 6 * 8;

/// System V's `va_list`'s bytes.
const TAG: i64 = 24;

/// AAPCS64's `va_list`'s bytes.
const LIST: i64 = 32;

/// The most passes following the unnamed registers' entry values takes.
const PASSES: usize = 64;

/// A store at a known stack offset.
#[derive(Clone, Copy)]
struct Store {
    inst: InstId,
    offset: i64,
    bytes: i64,
    value: Value,
    block: BlockId,
}

impl Store {
    /// Whether it writes a byte of `start..end`.
    fn overlaps(&self, start: i64, end: i64) -> bool {
        self.offset < end && self.offset + self.bytes > start
    }
}

/// System V's `va_start`, recognised.
struct SystemV {
    named: Named,
    /// The `va_list`'s offset.
    list: i64,
    /// `overflow_arg_area`'s and the save area's offsets.
    overflow: i64,
    area: i64,
    /// The save area's bytes: 176, or the integer registers' 48 where no
    /// vector register is saved.
    bytes: i64,
    /// The first `gp_offset` and `fp_offset`, the latter `None` where
    /// it is not stored.
    gp: u32,
    fp: Option<u32>,
    /// The `va_list`'s stores.
    fields: Vec<Store>,
    /// The saves, with their registers.
    saves: Vec<(Store, RegisterId)>,
    /// The block entered where the count is not 0, if a vector register
    /// is saved.
    guarded: Option<BlockId>,
    /// The count register.
    count: RegisterId,
}

/// AAPCS64's `va_start`, recognised (not printed as C's yet: [`Plan`]
/// has no form for it).
struct Aapcs64 {
    named: Named,
    unprinted: Unprinted,
}

/// What a recognised AAPCS64 `va_start` not printed as C's tells of the
/// function's format ([`Lowering::own_format`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Unprinted {
    /// The `va_list`'s offset.
    list: i64,
    /// Its field stores and the saves.
    stores: BTreeSet<InstId>,
    /// The save areas' bytes.
    areas: Vec<(i64, i64)>,
    /// Whether the saves and offsets are the ABI's own: every unnamed
    /// register saved, `__gr_offs` and `__vr_offs` as `va_start` sets
    /// them (not advanced past a `va_arg` folded in).
    whole: bool,
    /// The unnamed argument registers.
    unnamed: Vec<RegisterId>,
}

/// Microsoft x64's `va_start`, recognised.
struct Pointer {
    named: Named,
    /// The first unnamed argument's home slot.
    start: i64,
    /// The saves, with their registers.
    saves: Vec<(Store, RegisterId)>,
}

/// A recognised `va_start`.
enum Found {
    SystemV(SystemV),
    Pointer(Pointer),
    Aapcs64(Aapcs64),
}

impl Found {
    fn named(&self) -> Named {
        match self {
            Self::SystemV(found) => found.named,
            Self::Pointer(found) => found.named,
            Self::Aapcs64(found) => found.named,
        }
    }
}

/// How a recognised variadic definition is printed as C's (the [module]
/// (self) says when).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Plan {
    /// What its `va_start` does.
    pub(super) va: Va,
    /// Its named arguments.
    pub(super) named: Named,
    /// The stores the `va_start` stands for (not lowered).
    pub(super) stores: BTreeSet<InstId>,
    /// The store the `va_start` replaces; `None`: first in the body.
    pub(super) at: Option<InstId>,
    /// System V's `va_list`: its offset (a `Frame` variable of its own).
    pub(super) list: Option<i64>,
    /// Microsoft's: the offset its value points to (an address there is
    /// the `va_list`'s value).
    pub(super) start: Option<i64>,
    /// The branch on the count register (its block) and where it goes on
    /// (the join): the branch is absorbed, its block going to the join.
    pub(super) guard: Option<(BlockId, BlockId)>,
    /// The blocks absorbed: the vector saves and their alignment checks
    /// (not lowered).
    pub(super) blocks: BTreeSet<BlockId>,
    /// The unnamed argument registers.
    pub(super) unnamed: Vec<RegisterId>,
    /// System V's register save area's bytes (176, or the integer
    /// registers' 48 where no vector register is saved); 0 otherwise.
    pub(super) save_bytes: i64,
}

/// Where C finds what a variadic definition reads of its unnamed
/// arguments without `va_arg` (a `va_arg` the compiler expanded in place
/// is arithmetic on these addresses): bytes on from the `va_list`'s
/// `reg_save_area`, or from its `overflow_arg_area` as `va_start` left
/// it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Walked {
    /// In the register save area.
    Save(i64),
    /// Among the caller's stack arguments.
    Stack(i64),
}

impl Plan {
    /// Where stack offset `offset` is for C, if it is in System V's
    /// register save area or among the caller's stack arguments after
    /// the named ones.
    pub(super) fn walked(&self, offset: i64) -> Option<Walked> {
        let Layout::Tag {
            overflow,
            save_area,
            ..
        } = self.va.list
        else {
            return None;
        };
        if (save_area..save_area + self.save_bytes).contains(&offset) {
            Some(Walked::Save(offset - save_area))
        } else if offset >= overflow {
            Some(Walked::Stack(offset - overflow))
        } else {
            None
        }
    }

    /// Where in System V's register save area unnamed integer register
    /// `register`'s entry value is saved, if it is one.
    pub(super) fn saved(&self, register: RegisterId) -> Option<i64> {
        let Layout::Tag { save_area, .. } = self.va.list else {
            return None;
        };
        self.va
            .saves
            .iter()
            .find(|save| save.register == register && save.bytes == 8 && save.guard.is_none())
            .map(|save| save.offset - save_area)
    }
}

impl Lowering<'_, '_> {
    /// Whether the function is a variadic definition, recognised by its
    /// convention's rule and declared ([`Variadic`]); if it is printed as
    /// C's, its [`Plan`], the unnamed registers' entry values undefined
    /// and the frame's variables cut around the save area.
    pub(super) fn find_variadic(&mut self) {
        let cx = self.cx;
        let declared = cx
            .prototypes
            .of(self.l1.entry, &mut self.types)
            .and_then(|prototype| self.types.signature(prototype.signature))
            .map(|signature| signature.variadic);
        let stores = self.stack_stores();
        let found = match cx.convention.va_list {
            VaList::Unknown => None,
            VaList::SystemV { count } => stores
                .iter()
                .find_map(|store| self.system_v(&stores, store.offset, count))
                .map(Found::SystemV),
            VaList::Pointer => self.home_slots(&stores).map(Found::Pointer),
            VaList::Aapcs64 => stores
                .iter()
                .find_map(|store| self.aapcs64(&stores, store.offset))
                .map(Found::Aapcs64),
        };
        let recognised = found.as_ref().map(Found::named);
        let unprinted = match &found {
            Some(Found::Aapcs64(found)) if declared != Some(false) => Some(found.unprinted.clone()),
            Some(Found::Aapcs64(_) | Found::SystemV(_) | Found::Pointer(_)) | None => None,
        };
        let plan = found
            .filter(|_| declared != Some(false))
            .and_then(|found| self.plan(found));
        self.variadic = Variadic {
            recognised,
            declared,
            printed: plan.is_some(),
        };
        let Some(plan) = plan else {
            self.unprinted = unprinted;
            return;
        };
        for &register in &plan.unnamed {
            if let Some(entry) = entry_value(self.l1, register) {
                let width = self.width(entry);
                let unknown = Unknown::Entry {
                    register: Some(register),
                };
                self.set_kind(entry, Kind::Undefined(width, unknown));
            }
        }
        let hole = match plan.va.list {
            Layout::Tag { save_area, .. } => (save_area, save_area + plan.save_bytes),
            Layout::Pointer(start) => (start, i64::MAX),
            // The two save areas, as far as the saves reach.
            Layout::Aapcs64 { .. } => {
                let start = plan
                    .va
                    .saves
                    .iter()
                    .map(|save| save.offset)
                    .min()
                    .unwrap_or(0);
                let end = plan
                    .va
                    .saves
                    .iter()
                    .map(|save| save.offset + i64::from(save.bytes))
                    .max()
                    .unwrap_or(0);
                (start, end)
            }
        };
        let bytes = match plan.va.list {
            Layout::Aapcs64 { .. } => LIST,
            Layout::Tag { .. } | Layout::Pointer(_) => TAG,
        };
        // The save area's address reaches only the save area, the
        // `va_list`'s only the list (the plan's rule: no other address in
        // them is a value): slots no other address reaches are no memory.
        if let (Layout::Tag { save_area, .. }, Some(list)) = (plan.va.list, plan.list) {
            self.build_frame(&[
                (save_area, save_area + plan.save_bytes),
                (list, list + bytes),
            ]);
        }
        self.frame
            .cut(hole, plan.list.map(|list| (list, list + bytes)));
        self.va = Some(plan);
    }

    /// The format string the function's variadic arguments follow, as
    /// GCC's `-Wsuggest-attribute=format` finds it: a variadic definition
    /// printed as C's ([`Plan`]) whose `va_list` is used as a value once,
    /// as the argument after the format of a call of a `v` function
    /// (declared with a format describing its `va_list`: [`Format::list`])
    /// whose format is one of the function's register parameters,
    /// untouched (its entry value). That function reads exactly the
    /// arguments the format's conversions name from the `va_list`, which
    /// nothing else reads or changes (the plan's rule: nothing else
    /// accesses its bytes, and its address is no other value), so they
    /// are what callers pass after the named parameters. `string` counts
    /// in the parameters ([`Interface::format`](super::Interface)).
    pub(super) fn own_format(&self) -> Option<Format> {
        let Some(plan) = self.va.as_ref() else {
            return self.unprinted_format();
        };
        let list = plan.list.or(plan.start)?;
        let taken = self.taken_outside(&plan.stores, &plan.blocks);
        if taken.iter().filter(|&&offset| offset == list).count() != 1 {
            return None;
        }
        self.format_call(list)
    }

    /// [`Self::own_format`] for a recognised AAPCS64 `va_start` not
    /// printed as C's ([`Unprinted`]): its `va_list` passed on by value,
    /// copied whole to a temporary whose address is the `v` function's
    /// `va_list` argument (AAPCS64 passes a composite of more than 16
    /// bytes as a pointer to a copy the caller makes). As for a printed
    /// one, nothing else reads what the callee reads: the saves and
    /// offsets are the ABI's own (no `va_arg` folded in), only the saves
    /// access the save areas and use the unnamed registers' entry values,
    /// only its stores and the copy access the `va_list` and only the
    /// copy the temporary, and no address in either is a value but the
    /// temporary's, once.
    fn unprinted_format(&self) -> Option<Format> {
        let unprinted = self.unprinted.as_ref()?;
        if !unprinted.whole {
            return None;
        }
        let list = unprinted.list;
        let (temp, loads, copies) = self.list_copy(list)?;
        if unprinted
            .areas
            .iter()
            .any(|&(start, end)| !self.accessed_only(start, end, &unprinted.stores))
        {
            return None;
        }
        let mut list_accesses = unprinted.stores.clone();
        list_accesses.extend(&loads);
        if !self.accessed_only(list, list + LIST, &list_accesses)
            || !self.accessed_only(temp, temp + LIST, &copies)
        {
            return None;
        }
        let mut own = list_accesses;
        own.extend(&copies);
        let taken = self.taken_outside(&own, &BTreeSet::new());
        if taken.iter().any(|&offset| {
            (list..list + LIST).contains(&offset) || (temp + 1..temp + LIST).contains(&offset)
        }) || taken.iter().filter(|&&offset| offset == temp).count() != 1
        {
            return None;
        }
        if !self.passed_on_only(
            &unprinted.unnamed,
            &unprinted.unnamed,
            &unprinted.stores,
            &BTreeSet::new(),
            None,
        ) {
            return None;
        }
        self.format_call(temp)
    }

    /// A whole copy of the 32-byte AAPCS64 `va_list` at stack offset
    /// `list`: loads covering its bytes once, each value stored at the
    /// same offset of a temporary. The temporary's offset, the loads and
    /// the stores.
    fn list_copy(&self, list: i64) -> Option<(i64, BTreeSet<InstId>, BTreeSet<InstId>)> {
        let stores = self.stack_stores();
        let mut temp = None;
        let (mut loads, mut copies) = (BTreeSet::new(), BTreeSet::new());
        let mut covered = 0;
        for (_, block) in self.blocks() {
            for &inst in &block.insts {
                let Some(i) = self.l1.inst(inst) else {
                    continue;
                };
                let Op::Load { address, bytes, .. } = i.op else {
                    continue;
                };
                let bytes = i64::from(bytes);
                let Some(offset) = self.address(address) else {
                    continue;
                };
                if offset + bytes <= list || offset >= list + LIST {
                    continue;
                }
                if offset < list || offset + bytes > list + LIST {
                    return None;
                }
                let loaded = self.canonical(*i.results.first()?);
                let store = stores
                    .iter()
                    .find(|store| store.bytes == bytes && self.canonical(store.value) == loaded)?;
                let at = store.offset - (offset - list);
                if *temp.get_or_insert(at) != at {
                    return None;
                }
                loads.insert(inst);
                copies.insert(store.inst);
                covered += bytes;
            }
        }
        (covered == LIST).then_some((temp?, loads, copies))
    }

    /// The format of the function's call of a `v` function whose
    /// `va_list` argument is the stack address `list` ([`Self::own_format`]),
    /// where that format is one of its register parameters, untouched.
    fn format_call(&self, list: i64) -> Option<Format> {
        let mut found = None;
        for (site, callee) in &self.callees {
            let (Site::Call(_), Some(format)) = (site, callee.list_format) else {
                continue;
            };
            let registers = self.site_registers(*site);
            let at = |index: usize| match callee.arguments.get(index) {
                Some(&Source::Register(piece)) if piece.offset == 0 => {
                    registers.get(usize::from(piece.register.0)).copied()
                }
                Some(_) | None => None,
            };
            let (Some(string), Some(arguments)) = (at(format.string), at(format.string + 1)) else {
                continue;
            };
            if self.address(arguments) != Some(list) {
                continue;
            }
            let Kind::Entry(register) = self.kind(string) else {
                return None;
            };
            let parameter = self.needed.parameters.iter().position(|parameter| {
                matches!(parameter.source, Source::Register(piece) if piece.register == register && piece.offset == 0)
            })?;
            found = Some(Format {
                family: format.family,
                string: parameter,
                list: false,
            });
        }
        found
    }

    /// The lowered (not atomic) stores at known stack offsets, but the
    /// pushes of return addresses.
    fn stack_stores(&self) -> Vec<Store> {
        let mut stores = Vec::new();
        for (block, b) in self.blocks() {
            for &inst in &b.insts {
                if self.frame.pushes.contains(&inst) {
                    continue;
                }
                let Some(&Op::Store {
                    address,
                    value,
                    atomic: None,
                    ..
                }) = self.l1.inst(inst).map(|i| &i.op)
                else {
                    continue;
                };
                if let Some(offset) = self.address(address) {
                    stores.push(Store {
                        inst,
                        offset,
                        bytes: i64::from(self.width(value).div_ceil(8)),
                        value,
                        block,
                    });
                }
            }
        }
        stores
    }

    /// The only store of `bytes` bytes at `offset`, if exactly one is.
    fn only(stores: &[Store], offset: i64, bytes: i64) -> Option<Store> {
        let mut found = stores
            .iter()
            .filter(|store| store.offset == offset && store.bytes == bytes);
        let first = found.next().copied();
        if found.next().is_some() {
            return None;
        }
        first
    }

    /// The first store of `bytes` bytes at `offset`: the one before every
    /// other store that writes a byte it writes (earlier in its block, or
    /// in a block that dominates theirs), if there is one. `va_start`'s
    /// stores are the first to the `va_list`'s fields; a `va_arg` the
    /// compiler expanded in place stores to them again (`gp_offset += 8`,
    /// `overflow_arg_area += 8`).
    fn first(&self, stores: &[Store], offset: i64, bytes: i64) -> Option<Store> {
        stores.iter().copied().find(|candidate| {
            candidate.offset == offset
                && candidate.bytes == bytes
                && stores
                    .iter()
                    .filter(|other| {
                        other.inst != candidate.inst && other.overlaps(offset, offset + bytes)
                    })
                    .all(|other| self.before(candidate, other))
        })
    }

    /// Whether store `a` is run before `b` wherever `b` is.
    fn before(&self, a: &Store, b: &Store) -> bool {
        if a.block != b.block {
            return self.dominators.dominates(a.block, b.block);
        }
        let Some(block) = self.l1.block(a.block) else {
            return false;
        };
        let at = |inst: InstId| block.insts.iter().position(|&i| i == inst);
        matches!((at(a.inst), at(b.inst)), (Some(a), Some(b)) if a < b)
    }

    /// The constant `v` is, if it is one (its low 64 bits).
    fn constant(&self, v: Value) -> Option<u64> {
        match self.kind(v) {
            Kind::Const(bits) => Some(bits.low_u64()),
            Kind::None
            | Kind::Undefined(..)
            | Kind::Address(_)
            | Kind::Entry(_)
            | Kind::Phi
            | Kind::Pure(_)
            | Kind::Load(_)
            | Kind::Result(_)
            | Kind::CallView { .. } => None,
        }
    }

    /// The register whose entry value (or the low bits of it) `v` is.
    fn entry_low(&self, v: Value) -> Option<RegisterId> {
        if let Kind::Entry(register) = self.kind(v) {
            return Some(register);
        }
        match self.defining(self.canonical(v)) {
            Some((
                _,
                &Op::Extract {
                    value, offset: 0, ..
                },
            )) => match self.kind(value) {
                Kind::Entry(register) => Some(register),
                Kind::None
                | Kind::Const(_)
                | Kind::Undefined(..)
                | Kind::Address(_)
                | Kind::Phi
                | Kind::Pure(_)
                | Kind::Load(_)
                | Kind::Result(_)
                | Kind::CallView { .. } => None,
            },
            Some(_) | None => None,
        }
    }

    /// Whether `store` saves a vector argument register: its 16 bytes
    /// are the low 128 bits of one's entry value.
    fn saves_vector(&self, store: &Store) -> bool {
        store.bytes == 16
            && self
                .entry_low(store.value)
                .is_some_and(|register| self.cx.convention.float_arguments.contains(&register))
    }

    /// System V's `va_list` at stack offset `list`, if the stores are
    /// those of its rule.
    fn system_v(&self, stores: &[Store], list: i64, count: RegisterId) -> Option<SystemV> {
        let convention = self.cx.convention;
        let mut fields = Vec::new();
        let (gp, set) = if let Some(both) = self.first(stores, list, 8) {
            fields.push(both);
            let both = self.constant(both.value)?;
            (both & 0xffff_ffff, Some(both >> 32))
        } else {
            let gp = self.first(stores, list, 4)?;
            fields.push(gp);
            let set = if let Some(fp) = self.first(stores, list + 4, 4) {
                fields.push(fp);
                Some(self.constant(fp.value)?)
            } else if stores
                .iter()
                .any(|store| store.overlaps(list + 4, list + 8))
                || self.reads_vectors()
            {
                return None;
            } else {
                // GCC leaves `fp_offset` unset where no `va_arg` reads a
                // vector register: then none is named either, the
                // function reading none at all.
                None
            };
            (self.constant(gp.value)?, set)
        };
        let fp = set.unwrap_or(48);
        let overflow = self.first(stores, list + 8, 8)?;
        let area = self.first(stores, list + 16, 8)?;
        fields.extend([overflow, area]);
        let overflow = self.address(overflow.value)?;
        let area = self.address(area.value)?;
        let integer = usize::try_from(gp / 8).ok()?;
        let vector = usize::try_from(fp.checked_sub(48)? / 16).ok()?;
        let link = i64::from(self.cx.link_bytes());
        let stack = overflow.checked_sub(link)?;
        // The save area is as long as what is saved: GCC allocates the
        // integer registers' 48 bytes alone where it saves no vector
        // register (the rest of the area would lie over the return
        // address, or over the callee-saved registers the prologue
        // pushed, which are no vector saves).
        let vectors = stores
            .iter()
            .filter(|store| {
                store.overlaps(area + VECTORS, (area + SAVE_AREA).min(0))
                    && self.saves_vector(store)
            })
            .count();
        let bytes = if vectors > 0 { SAVE_AREA } else { VECTORS };
        if gp % 8 != 0
            || fp % 16 != 0
            || integer > convention.arguments.len()
            || vector > convention.float_arguments.len()
            || stack < 0
            || stack % 8 != 0
            || area + bytes > 0
            || (list < area + bytes && list + TAG > area)
        {
            return None;
        }
        let mut saves = Vec::new();
        for (k, &register) in (0i64..).zip(&convention.arguments).skip(integer) {
            let spill = Self::only(stores, area + 8 * k, 8)?;
            if self.entry_low(spill.value) != Some(register) || self.width(spill.value) != 64 {
                return None;
            }
            saves.push((spill, register));
        }
        let mut guarded = None;
        if vectors > 0 {
            let guard = self.counted(count)?;
            for (k, &register) in (0i64..).zip(&convention.float_arguments).skip(vector) {
                let spill = Self::only(stores, area + VECTORS + 16 * k, 16)?;
                if self.entry_low(spill.value) != Some(register)
                    || !self.dominators.dominates(guard, spill.block)
                {
                    return None;
                }
                saves.push((spill, register));
            }
            guarded = Some(guard);
        }
        let written = stores
            .iter()
            .filter(|store| store.overlaps(area, area + bytes))
            .count();
        (written == saves.len()).then_some(())?;
        Some(SystemV {
            named: Named {
                integer: u8::try_from(integer).ok()?,
                vector: u8::try_from(vector).ok()?,
                stack: u8::try_from(stack / 8).ok()?,
            },
            list,
            overflow,
            area,
            bytes,
            gp: u32::try_from(gp).ok()?,
            fp: match set {
                Some(fp) => Some(u32::try_from(fp).ok()?),
                None => None,
            },
            fields,
            saves,
            guarded,
            count,
        })
    }

    /// AAPCS64's `va_list` at stack offset `list`, if the stores are those
    /// of its rule (the [module](self) states it).
    fn aapcs64(&self, stores: &[Store], list: i64) -> Option<Aapcs64> {
        let convention = self.cx.convention;
        let stack_store = self.first(stores, list, 8)?;
        let stack = self.address(stack_store.value)?;
        let mut fields = BTreeSet::from([stack_store.inst]);
        // A 32-bit field, signed; an impossible positive value where it is
        // not one.
        let offset = |bits: u64| {
            u32::try_from(bits & 0xffff_ffff)
                .map_or(1, |low| i64::from(i32::from_ne_bytes(low.to_ne_bytes())))
        };
        let (gr_offs, vr_offs) = if let Some(both) = self.first(stores, list + 24, 8) {
            fields.insert(both.inst);
            let both = self.constant(both.value)?;
            (offset(both), offset(both >> 32))
        } else {
            let gr = self.first(stores, list + 24, 4)?;
            let vr = self.first(stores, list + 28, 4)?;
            fields.extend([gr.inst, vr.inst]);
            (
                offset(self.constant(gr.value)?),
                offset(self.constant(vr.value)?),
            )
        };
        if gr_offs > 0 || vr_offs > 0 || gr_offs % 8 != 0 || vr_offs % 16 != 0 {
            return None;
        }
        if stack < 0 || stack % 8 != 0 {
            return None;
        }
        let top = |field: i64| {
            let store = self.first(stores, list + field, 8)?;
            let top = self.address(store.value).filter(|&top| top <= 0)?;
            Some((store.inst, top))
        };
        let mut areas = Vec::new();
        let mut run = |field: i64, bytes: i64, registers: &[RegisterId]| {
            let Some((inst, top)) = top(field) else {
                return Some((0, 0));
            };
            fields.insert(inst);
            let (first, count, saves) = self.saved_run(stores, top, bytes, registers)?;
            fields.extend(saves);
            areas.push((top - bytes * i64::from(count), top));
            Some((first, count))
        };
        let (integer, saved_integer) = run(8, 8, &convention.arguments)?;
        let (vector, saved_vector) = run(16, 16, &convention.float_arguments)?;
        if saved_integer + saved_vector == 0
            || -8 * i64::from(saved_integer) > gr_offs
            || -16 * i64::from(saved_vector) > vr_offs
        {
            return None;
        }
        let named = |saved: u8, first: u8, registers: &[RegisterId]| {
            if saved > 0 {
                first
            } else {
                self.read_argument_count(registers)
            }
        };
        let named = Named {
            integer: named(saved_integer, integer, &convention.arguments),
            vector: named(saved_vector, vector, &convention.float_arguments),
            stack: u8::try_from(stack / 8).ok()?,
        };
        // The ABI's own: each class's unnamed registers all saved, its
        // offset what `va_start` sets for them.
        let own = |named: u8, saved: u8, size: i64, offs: i64| {
            usize::from(named) + usize::from(saved) == 8 && offs == -size * i64::from(saved)
        };
        let whole = own(named.integer, saved_integer, 8, gr_offs)
            && own(named.vector, saved_vector, 16, vr_offs);
        let unnamed = convention
            .arguments
            .iter()
            .skip(usize::from(named.integer))
            .chain(
                convention
                    .float_arguments
                    .iter()
                    .skip(usize::from(named.vector)),
            )
            .copied()
            .collect();
        Some(Aapcs64 {
            named,
            unprinted: Unprinted {
                list,
                stores: fields,
                areas,
                whole,
                unnamed,
            },
        })
    }

    /// The run of saves ending at `top` (an AAPCS64 save area's end): the
    /// entry values of consecutive argument registers of `registers`,
    /// `bytes` each (8: `x`; 16: `q`), the last just below `top`; as the
    /// index of the first register saved, how many, and the saves; none
    /// for none. `None` where a save is stored twice, a slot of the run
    /// holds anything else, or another store writes the area.
    fn saved_run(
        &self,
        stores: &[Store],
        top: i64,
        bytes: i64,
        registers: &[RegisterId],
    ) -> Option<(u8, u8, Vec<InstId>)> {
        let saved_at = |at: i64| {
            let store = Self::only(stores, at, bytes)?;
            let register = self.entry_low(store.value)?;
            (self.width(store.value) == u16::try_from(bytes * 8).ok()?)
                .then(|| registers.iter().position(|&r| r == register))
                .flatten()
        };
        let Some(last) = saved_at(top - bytes) else {
            return Some((0, 0, Vec::new()));
        };
        let mut first = last;
        while first > 0
            && saved_at(top - bytes * i64::try_from(last - first + 2).ok()?) == Some(first - 1)
        {
            first -= 1;
        }
        let count = last - first + 1;
        let start = top - bytes * i64::try_from(count).ok()?;
        let written: Vec<InstId> = stores
            .iter()
            .filter(|store| store.overlaps(start, top))
            .map(|store| store.inst)
            .collect();
        (written.len() == count).then_some(())?;
        Some((
            u8::try_from(first).ok()?,
            u8::try_from(count).ok()?,
            written,
        ))
    }

    /// How many of `registers` (argument registers, in order) are named
    /// where none is saved: up to the last whose entry value an
    /// instruction other than a call reads (a call's state holds every
    /// register's value, read or not).
    fn read_argument_count(&self, registers: &[RegisterId]) -> u8 {
        let read = |register: RegisterId| {
            entry_value(self.l1, register).is_some_and(|entry| {
                let entry = self.canonical(entry);
                self.blocks().any(|(_, block)| {
                    block.insts.iter().any(|&inst| {
                        self.l1.inst(inst).is_some_and(|i| {
                            !matches!(i.op, Op::Call { .. } | Op::SystemCall { .. })
                                && i.op
                                    .operands()
                                    .iter()
                                    .any(|&operand| self.canonical(operand) == entry)
                        })
                    })
                })
            })
        };
        registers
            .iter()
            .rposition(|&register| read(register))
            .map_or(0, |last| u8::try_from(last + 1).unwrap_or(u8::MAX))
    }

    /// Whether an instruction other than a call reads the entry value of
    /// a vector argument register (a call's state holds every
    /// register's value, read or not).
    fn reads_vectors(&self) -> bool {
        let entries: Vec<Value> = self
            .cx
            .convention
            .float_arguments
            .iter()
            .filter_map(|&register| entry_value(self.l1, register))
            .map(|entry| self.canonical(entry))
            .collect();
        self.blocks().any(|(_, block)| {
            block.insts.iter().any(|&inst| {
                self.l1.inst(inst).is_some_and(|i| {
                    !matches!(i.op, Op::Call { .. } | Op::SystemCall { .. })
                        && i.op
                            .operands()
                            .iter()
                            .any(|&operand| entries.contains(&self.canonical(operand)))
                })
            })
        })
    }

    /// The block entered only where the low byte of `count`'s entry value
    /// is not 0: the target of the one branch testing it whose only
    /// predecessor that branch is.
    fn counted(&self, count: RegisterId) -> Option<BlockId> {
        let mut found = None;
        for (block, b) in self.blocks() {
            let Terminator::Branch {
                condition,
                then,
                otherwise,
            } = &b.terminator
            else {
                continue;
            };
            let Some(comparison) = self.compare(*condition) else {
                continue;
            };
            let tests = |value: Value, zero: Value| {
                self.entry_low(value) == Some(count)
                    && self.width(value) == 8
                    && self.constant(zero) == Some(0)
            };
            if !tests(comparison.left, comparison.right)
                && !tests(comparison.right, comparison.left)
            {
                continue;
            }
            let target = match comparison.relation {
                Relation::Ne => then.block,
                Relation::Eq => otherwise.block,
                Relation::ULt
                | Relation::ULe
                | Relation::UGt
                | Relation::UGe
                | Relation::SLt
                | Relation::SLe
                | Relation::SGt
                | Relation::SGe => continue,
            };
            let only = self
                .preds
                .get(target.0 as usize)
                .is_some_and(|preds| preds.iter().all(|&(pred, _)| pred == block));
            if !only || found.replace(target).is_some() {
                return None;
            }
        }
        found
    }

    /// Microsoft x64's `va_start`: the first n ≥ 1 whose home slot's
    /// address is used as a value and after which every argument
    /// register's home slot holds its entry value, written by no other
    /// store.
    fn home_slots(&self, stores: &[Store]) -> Option<Pointer> {
        let registers = &self.cx.convention.arguments;
        let link = i64::from(self.cx.link_bytes());
        let end = link + 8 * i64::try_from(registers.len()).ok()?;
        let (_, taken) = self.taken(&self.frame.tricks);
        (1..registers.len()).find_map(|integer| {
            let start = link + 8 * i64::try_from(integer).ok()?;
            if !taken.contains(&start) {
                return None;
            }
            let mut saves = Vec::new();
            for (k, &register) in (0i64..).zip(registers).skip(integer) {
                let spill = Self::only(stores, link + 8 * k, 8)?;
                if self.entry_low(spill.value) != Some(register) || self.width(spill.value) != 64 {
                    return None;
                }
                saves.push((spill, register));
            }
            let written = stores
                .iter()
                .filter(|store| store.overlaps(start, end))
                .count();
            (written == saves.len()).then_some(Pointer {
                named: Named {
                    integer: u8::try_from(integer).ok()?,
                    vector: 0,
                    stack: 0,
                },
                start,
                saves,
            })
        })
    }

    /// How recognised `found` is printed as C's, if it can be.
    fn plan(&self, found: Found) -> Option<Plan> {
        let named = found.named();
        let declared = self.returns.declared.as_ref().map(Vec::len);
        let count = usize::from(named.integer) + usize::from(named.vector);
        if named.stack != 0 || count == 0 || declared.is_some_and(|declared| declared != count) {
            return None;
        }
        match found {
            Found::SystemV(found) => self.plan_system_v(&found),
            Found::Pointer(found) => self.plan_pointer(&found),
            Found::Aapcs64(_) => None,
        }
    }

    /// [`Self::plan`] for System V.
    fn plan_system_v(&self, found: &SystemV) -> Option<Plan> {
        let named = found.named;
        let convention = self.cx.convention;
        let at = self.together(&found.fields)?;
        let stores: BTreeSet<InstId> = found
            .fields
            .iter()
            .chain(found.saves.iter().map(|(store, _)| store))
            .map(|store| store.inst)
            .collect();
        let (blocks, guard) = match found.guarded {
            Some(guarded) => {
                let (branch, join, blocks) = self.vector_saves(guarded, &stores)?;
                (blocks, Some((branch, join)))
            }
            None => (BTreeSet::new(), None),
        };
        let (area, list) = (found.area, found.list);
        // The save area and the caller's stack arguments are read through
        // addresses only ([`Self::walked`]), never at a known offset.
        if !self.accessed_only(area, area + found.bytes, &stores)
            || !self.accessed_only(found.overflow, i64::MAX, &BTreeSet::new())
        {
            return None;
        }
        let taken = self.taken_outside(&stores, &blocks);
        if taken
            .iter()
            .any(|&offset| (list + 1..list + TAG).contains(&offset))
        {
            return None;
        }
        let integers = convention.arguments.iter().skip(usize::from(named.integer));
        let vectors = convention
            .float_arguments
            .iter()
            .skip(usize::from(named.vector));
        let unnamed: Vec<RegisterId> = integers.clone().chain(vectors.clone()).copied().collect();
        // An unnamed integer register read otherwise is read from the
        // save area ([`Self::walked`]); a vector one is saved only where
        // the count says so, so it has no value C can read.
        let mut entries: Vec<RegisterId> = vectors.copied().collect();
        entries.push(found.count);
        let branch = guard.map(|(branch, _)| branch);
        if !self.passed_on_only(&entries, &unnamed, &stores, &blocks, branch) {
            return None;
        }
        let integers: Vec<RegisterId> = integers.copied().collect();
        if !self.walked_after(at, found, &integers, &stores, &blocks) {
            return None;
        }
        let mut saves = Vec::new();
        for &(store, register) in &found.saves {
            saves.push(Save {
                register,
                offset: store.offset,
                bytes: u16::try_from(store.bytes).ok()?,
                guard: (store.offset >= area + VECTORS).then_some(found.count),
            });
        }
        Some(Plan {
            va: Va {
                list: Layout::Tag {
                    gp_offset: found.gp,
                    fp_offset: found.fp,
                    overflow: found.overflow,
                    save_area: area,
                },
                saves,
            },
            named,
            stores,
            at: Some(at),
            list: Some(list),
            start: None,
            guard,
            blocks,
            unnamed,
            save_bytes: found.bytes,
        })
    }

    /// Whether everything that reads what the `va_start` standing for
    /// store `at` sets up comes after it (in a block `at`'s dominates, or
    /// later in its own): an address in the save area or among the
    /// caller's stack arguments used as a value, or the entry value of an
    /// unnamed integer register (`saved`). C reads those through the
    /// `va_list` ([`Plan`]: `reg_save_area`, `overflow_arg_area`), which
    /// holds them only once `va_start` has run.
    fn walked_after(
        &self,
        at: InstId,
        found: &SystemV,
        saved: &[RegisterId],
        stores: &BTreeSet<InstId>,
        blocks: &BTreeSet<BlockId>,
    ) -> bool {
        let entries: Vec<Value> = saved
            .iter()
            .filter_map(|&register| entry_value(self.l1, register))
            .map(|entry| self.canonical(entry))
            .collect();
        let walked = |value: Value| {
            entries.contains(&self.canonical(value))
                || self.address(value).is_some_and(|offset| {
                    (found.area..found.area + found.bytes).contains(&offset)
                        || offset >= found.overflow
                })
        };
        let Some((home, position)) = self.blocks().find_map(|(id, block)| {
            let position = block.insts.iter().position(|&inst| inst == at)?;
            Some((id, position))
        }) else {
            return false;
        };
        for (id, block) in self.blocks() {
            if blocks.contains(&id) {
                continue;
            }
            let later = id != home && self.dominators.dominates(home, id);
            if later {
                continue;
            }
            let mut values = Vec::new();
            for (index, &inst) in block.insts.iter().enumerate() {
                if !(stores.contains(&inst) || id == home && index > position) {
                    self.taken_by(inst, &mut values);
                }
            }
            if id != home {
                self.taken_at_end(id, &block.terminator, &mut values);
            }
            if values.into_iter().any(walked) {
                return false;
            }
        }
        true
    }

    /// [`Self::plan`] for Microsoft x64.
    fn plan_pointer(&self, found: &Pointer) -> Option<Plan> {
        let named = found.named;
        let stores: BTreeSet<InstId> = found.saves.iter().map(|(store, _)| store.inst).collect();
        let none = BTreeSet::new();
        if !self.accessed_only(found.start, i64::MAX, &stores)
            || self
                .taken_outside(&stores, &none)
                .iter()
                .any(|&offset| offset > found.start)
        {
            return None;
        }
        let unnamed: Vec<RegisterId> = self
            .cx
            .convention
            .arguments
            .iter()
            .skip(usize::from(named.integer))
            .copied()
            .collect();
        if !self.passed_on_only(&unnamed, &unnamed, &stores, &none, None) {
            return None;
        }
        let mut saves = Vec::new();
        for &(store, register) in &found.saves {
            saves.push(Save {
                register,
                offset: store.offset,
                bytes: u16::try_from(store.bytes).ok()?,
                guard: None,
            });
        }
        Some(Plan {
            va: Va {
                list: Layout::Pointer(found.start),
                saves,
            },
            named,
            stores,
            at: None,
            list: None,
            start: Some(found.start),
            guard: None,
            blocks: none,
            unnamed,
            save_bytes: 0,
        })
    }

    /// The last of the `va_list`'s stores `fields`, if they are in one
    /// straight line of code (blocks each jumping to the next, its only
    /// predecessor) with nothing between them but operations, and stores
    /// and loads at known stack offsets (which `va_start` does not write,
    /// nor reads: [`Self::accessed_only`]) or at constant addresses (the
    /// image's data, not the stack): none reads what the `va_start` in
    /// the last one's place writes.
    fn together(&self, fields: &[Store]) -> Option<InstId> {
        let insts = fields
            .iter()
            .find_map(|field| self.line(field.block, fields))?;
        let positions = fields
            .iter()
            .map(|field| insts.iter().position(|&inst| inst == field.inst))
            .collect::<Option<Vec<usize>>>()?;
        let (first, last) = (*positions.iter().min()?, *positions.iter().max()?);
        for &inst in insts.get(first..=last)? {
            if fields.iter().any(|field| field.inst == inst) {
                continue;
            }
            let quiet = match self.l1.inst(inst)?.op {
                Op::Const(_)
                | Op::Undefined(..)
                | Op::Unary(..)
                | Op::Binary(..)
                | Op::Flag(..)
                | Op::Extract { .. }
                | Op::Concat { .. }
                | Op::Extend { .. }
                | Op::Select { .. }
                | Op::Lanes { .. }
                | Op::Float { .. } => true,
                Op::Store {
                    address,
                    atomic: None,
                    ..
                } => self.address(address).is_some(),
                Op::Load {
                    address,
                    atomic: None,
                    ..
                } => self.address(address).is_some() || self.constant(address).is_some(),
                Op::Load { .. }
                | Op::Store { .. }
                | Op::Intrinsic { .. }
                | Op::Call { .. }
                | Op::SystemCall { .. }
                | Op::Landing { .. } => false,
            };
            if !quiet {
                return None;
            }
        }
        insts.get(last).copied()
    }

    /// The instructions of the straight line of code from `start` (each
    /// block jumping to the next, its only predecessor) up to the block
    /// holding the last of `fields`, if it holds them all.
    fn line(&self, start: BlockId, fields: &[Store]) -> Option<Vec<InstId>> {
        let mut insts = Vec::new();
        let mut at = start;
        let mut left: BTreeSet<BlockId> = fields.iter().map(|field| field.block).collect();
        for _ in 0..=self.l1.blocks.len() {
            let block = self.l1.block(at)?;
            insts.extend(block.insts.iter().copied());
            left.remove(&at);
            if left.is_empty() {
                return Some(insts);
            }
            let Terminator::Jump(target) = &block.terminator else {
                return None;
            };
            let only = self
                .preds
                .get(target.block.0 as usize)
                .is_some_and(|preds| preds.len() == 1);
            if !only {
                return None;
            }
            at = target.block;
        }
        None
    }

    /// Whether only `stores` access the stack bytes `start..end` at known
    /// offsets (no load, other store or call's stack argument).
    fn accessed_only(&self, start: i64, end: i64, stores: &BTreeSet<InstId>) -> bool {
        let overlaps = |slot: usize| {
            self.frame
                .slots
                .get(slot)
                .is_some_and(|slot| slot.offset < end && slot.end > start)
        };
        self.frame
            .accesses
            .iter()
            .all(|(inst, &slot)| !overlaps(slot) || stores.contains(inst))
            && self.frame.arguments.values().all(|&slot| !overlaps(slot))
    }

    /// The stack offsets used as values ([`Self::taken`]) outside `stores`
    /// and `blocks`.
    fn taken_outside(&self, stores: &BTreeSet<InstId>, blocks: &BTreeSet<BlockId>) -> Vec<i64> {
        let mut values = Vec::new();
        for (id, block) in self.blocks() {
            if blocks.contains(&id) {
                continue;
            }
            for &inst in &block.insts {
                if !stores.contains(&inst) {
                    self.taken_by(inst, &mut values);
                }
            }
            self.taken_at_end(id, &block.terminator, &mut values);
        }
        values.into_iter().filter_map(|v| self.address(v)).collect()
    }

    /// The branch on the count register's block, its join and the blocks
    /// `guarded` dominates, if those only save vector registers (`stores`)
    /// and check the save area's alignment, which the ABI's stack
    /// alignment proves (the module says how).
    fn vector_saves(
        &self,
        guarded: BlockId,
        stores: &BTreeSet<InstId>,
    ) -> Option<(BlockId, BlockId, BTreeSet<BlockId>)> {
        let &(branch, _) = self.preds.get(guarded.0 as usize)?.first()?;
        let Terminator::Branch {
            then, otherwise, ..
        } = &self.l1.block(branch)?.terminator
        else {
            return None;
        };
        let join = if then.block == guarded {
            otherwise.block
        } else {
            then.block
        };
        let region: BTreeSet<BlockId> = self
            .blocks()
            .map(|(id, _)| id)
            .filter(|&id| self.dominators.dominates(guarded, id))
            .collect();
        if join == guarded || region.contains(&join) || region.contains(&branch) {
            return None;
        }
        let mut traps = BTreeSet::new();
        let mut entered = BTreeSet::new();
        for &id in &region {
            let block = self.l1.block(id)?;
            for &inst in &block.insts {
                if !stores.contains(&inst) && !pure(&self.l1.inst(inst)?.op) {
                    return None;
                }
            }
            match &block.terminator {
                Terminator::Jump(target) => {
                    entered.insert(target.block);
                }
                Terminator::Branch {
                    condition,
                    then,
                    otherwise,
                } => {
                    let (bad, good) = if self.misaligned(*condition)? {
                        (then, otherwise)
                    } else {
                        (otherwise, then)
                    };
                    traps.insert(bad.block);
                    entered.insert(good.block);
                }
                Terminator::Trap(_) => {}
                Terminator::Invoke { .. }
                | Terminator::IndirectJump { .. }
                | Terminator::Return { .. }
                | Terminator::Leave { .. }
                | Terminator::Stop
                | Terminator::Open => return None,
            }
        }
        // The one block the region goes on to: the join, or where it
        // only jumps to.
        let mut exits = traps
            .iter()
            .chain(&entered)
            .filter(|target| !region.contains(target));
        let exit = *exits.next()?;
        if exits.any(|&other| other != exit) {
            return None;
        }
        for &id in &region {
            let trap = matches!(self.l1.block(id)?.terminator, Terminator::Trap(_));
            if trap != traps.contains(&id) || entered.contains(&id) && trap {
                return None;
            }
        }
        self.joins(branch, join, exit, &region)?;
        Some((branch, join, region))
    }

    /// Whether `join` reaches `exit` through blocks that only compute and
    /// jump, and `exit` receives from `region` what it does from that
    /// way (but the memory, which only the saves change).
    fn joins(
        &self,
        branch: BlockId,
        join: BlockId,
        exit: BlockId,
        region: &BTreeSet<BlockId>,
    ) -> Option<()> {
        let mut last = branch;
        let mut at = join;
        for _ in 0..=self.l1.blocks.len() {
            if at == exit {
                break;
            }
            let block = self.l1.block(at)?;
            let Terminator::Jump(target) = &block.terminator else {
                return None;
            };
            let quiet = block
                .insts
                .iter()
                .all(|&inst| self.l1.inst(inst).is_some_and(|i| pure(&i.op)));
            if !quiet {
                return None;
            }
            (last, at) = (at, target.block);
        }
        if at != exit {
            return None;
        }
        let parameters = &self.l1.block(exit)?.parameters;
        for (index, &parameter) in parameters.iter().enumerate() {
            if self.width(parameter) == 0 {
                continue;
            }
            let incoming = self.incoming(exit, index);
            let mut values = incoming
                .iter()
                .filter(|&&(pred, _)| pred == last || region.contains(&pred))
                .map(|&(_, argument)| self.canonical(argument));
            let first = values.next();
            if values.any(|value| Some(value) != first) {
                return None;
            }
        }
        Some(())
    }

    /// Whether branch condition `condition` is a 16-byte alignment check
    /// of a stack address the ABI aligns, `(a & 15) != 0` (then
    /// misaligned: `Some(true)`) or `== 0` (`Some(false)`).
    fn misaligned(&self, condition: Value) -> Option<bool> {
        let comparison = self.compare(condition)?;
        let masked = if self.constant(comparison.right) == Some(0) {
            comparison.left
        } else if self.constant(comparison.left) == Some(0) {
            comparison.right
        } else {
            return None;
        };
        let (_, &Op::Binary(Binary::And, a, b)) = self.defining(self.canonical(masked))? else {
            return None;
        };
        let address = if self.constant(b) == Some(15) {
            a
        } else if self.constant(a) == Some(15) {
            b
        } else {
            return None;
        };
        let link = i64::from(self.cx.link_bytes());
        if (self.address(address)? - link).rem_euclid(16) != 0 {
            return None;
        }
        match comparison.relation {
            Relation::Ne => Some(true),
            Relation::Eq => Some(false),
            Relation::ULt
            | Relation::ULe
            | Relation::UGt
            | Relation::UGe
            | Relation::SLt
            | Relation::SLe
            | Relation::SGt
            | Relation::SGe => None,
        }
    }

    /// Whether the entry values of `entries` (and what is computed from
    /// them) are used, outside `stores` and `blocks`, only by `branch`'s
    /// decision and as calls' state, an argument only an `unnamed`
    /// register's own entry value passed on in place.
    fn passed_on_only(
        &self,
        entries: &[RegisterId],
        unnamed: &[RegisterId],
        stores: &BTreeSet<InstId>,
        blocks: &BTreeSet<BlockId>,
        branch: Option<BlockId>,
    ) -> bool {
        let entry = |register: RegisterId| {
            entry_value(self.l1, register).map(|value| self.canonical(value))
        };
        let in_place: BTreeSet<(RegisterId, Value)> = unnamed
            .iter()
            .filter_map(|&register| Some((register, entry(register)?)))
            .collect();
        let mut tainted: BTreeSet<Value> = entries.iter().filter_map(|&r| entry(r)).collect();
        for _ in 0..PASSES {
            let before = tainted.len();
            for (id, block) in self.blocks() {
                if blocks.contains(&id) {
                    continue;
                }
                for &inst in &block.insts {
                    if stores.contains(&inst) {
                        continue;
                    }
                    let Some(i) = self.l1.inst(inst) else {
                        continue;
                    };
                    let hit = |value: &Value| tainted.contains(&self.canonical(*value));
                    match &i.op {
                        op @ (Op::Const(_)
                        | Op::Undefined(..)
                        | Op::Unary(..)
                        | Op::Binary(..)
                        | Op::Flag(..)
                        | Op::Extract { .. }
                        | Op::Concat { .. }
                        | Op::Extend { .. }
                        | Op::Select { .. }
                        | Op::Lanes { .. }
                        | Op::Float { .. }) => {
                            if op.operands().iter().any(hit) {
                                let results: Vec<Value> =
                                    i.results.iter().map(|&r| self.canonical(r)).collect();
                                tainted.extend(results);
                            }
                        }
                        Op::Call {
                            target, registers, ..
                        } => {
                            if hit(target)
                                || !self.in_place(Site::Call(inst), registers, &tainted, &in_place)
                            {
                                return false;
                            }
                        }
                        Op::SystemCall { registers, .. } => {
                            let read = self.system_call_registers(inst);
                            if read
                                .iter()
                                .any(|r| registers.get(usize::from(r.0)).is_some_and(hit))
                            {
                                return false;
                            }
                        }
                        op @ (Op::Load { .. }
                        | Op::Store { .. }
                        | Op::Intrinsic { .. }
                        | Op::Landing { .. }) => {
                            if op.operands().iter().any(hit) {
                                return false;
                            }
                        }
                    }
                }
                if !self.ends_quietly(id, &block.terminator, &tainted, &in_place, branch) {
                    return false;
                }
                for target in block.terminator.targets() {
                    let parameters = self
                        .l1
                        .block(target.block)
                        .map_or(&[][..], |b| b.parameters.as_slice());
                    for (argument, &parameter) in target.arguments.iter().zip(parameters) {
                        if tainted.contains(&self.canonical(*argument)) {
                            tainted.insert(self.canonical(parameter));
                        }
                    }
                }
            }
            if tainted.len() == before {
                return true;
            }
        }
        false
    }

    /// Whether block `id`'s `terminator` uses no `tainted` value but as
    /// [`Self::passed_on_only`] allows.
    fn ends_quietly(
        &self,
        id: BlockId,
        terminator: &Terminator,
        tainted: &BTreeSet<Value>,
        in_place: &BTreeSet<(RegisterId, Value)>,
        branch: Option<BlockId>,
    ) -> bool {
        let hit = |value: &Value| tainted.contains(&self.canonical(*value));
        match terminator {
            Terminator::Branch { condition, .. } => !hit(condition) || branch == Some(id),
            Terminator::IndirectJump { address, .. } => !hit(address),
            Terminator::Return { address, state } => {
                !hit(address)
                    && self.returns.pieces.iter().all(|piece| {
                        !state
                            .registers
                            .get(usize::from(piece.register.0))
                            .is_some_and(hit)
                    })
            }
            Terminator::Leave { address, state, .. } => {
                !hit(address) && self.in_place(Site::Tail(id), &state.registers, tainted, in_place)
            }
            Terminator::Jump(_)
            | Terminator::Invoke { .. }
            | Terminator::Trap(_)
            | Terminator::Stop
            | Terminator::Open => true,
        }
    }

    /// Whether the call at `site` in state `registers` passes no
    /// `tainted` value as an argument but an unnamed register's own entry
    /// value in place.
    fn in_place(
        &self,
        site: Site,
        registers: &[Value],
        tainted: &BTreeSet<Value>,
        in_place: &BTreeSet<(RegisterId, Value)>,
    ) -> bool {
        let Some(callee) = self.callees.get(&site) else {
            return true;
        };
        callee.arguments.iter().all(|source| match *source {
            Source::Register(piece) => {
                registers
                    .get(usize::from(piece.register.0))
                    .is_none_or(|&value| {
                        let value = self.canonical(value);
                        !tainted.contains(&value) || in_place.contains(&(piece.register, value))
                    })
            }
            Source::Stack { .. } => true,
        })
    }
}

/// Whether `op` is an operation on values (no memory, call or effect).
fn pure(op: &Op) -> bool {
    match op {
        Op::Const(_)
        | Op::Undefined(..)
        | Op::Unary(..)
        | Op::Binary(..)
        | Op::Flag(..)
        | Op::Extract { .. }
        | Op::Concat { .. }
        | Op::Extend { .. }
        | Op::Select { .. }
        | Op::Lanes { .. }
        | Op::Float { .. } => true,
        Op::Load { .. }
        | Op::Store { .. }
        | Op::Intrinsic { .. }
        | Op::Call { .. }
        | Op::SystemCall { .. }
        | Op::Landing { .. } => false,
    }
}
