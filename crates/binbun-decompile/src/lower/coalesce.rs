//! Variables out of SSA: each value lowered to a variable starts in a
//! class of its own; block parameters are coalesced with their arguments
//! where their live ranges do not interfere (Budimlić et al. 2002: in
//! strict SSA, two values interfere if one is live where the other, which
//! it dominates, is defined). Liveness counts a folded value's operands at
//! the statement it is folded into, and a block argument at the end of its
//! predecessor. Types ([`crate::typing`], solved before coalescing)
//! inform it: a class holding a pointer is not coalesced with one holding
//! an integer, nor one holding a pointer to a struct with one holding a
//! pointer to another struct or to a scalar ([`Sort`], what the solution
//! rounds each pointer-wide value to alone, an integer computation being
//! an integer whatever it rounds to); the argument stays a copy on its
//! edge. A class takes the first target its members show, so `void *`
//! joins pointers to two structs to neither.
//! An argument proved zero on every edge it arrives by
//! ([`Lowering::nulls`]) is not coalesced with its parameter at all: its
//! copy there is of 0, whatever else it holds.

use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;

use binbun_ssa::ir::{BlockId, Value};

use super::facts::{Def, Kind, Lowering};
use super::needed::{Role, Use};
use crate::typing::{Pointee, Sort};

/// No class.
const NONE: u32 = u32::MAX;

/// What a class holds, of [`Sort`]s: a pointer (to what, if its members
/// say), an integer.
#[derive(Clone, Copy, Debug, Default)]
struct Held {
    pointer: bool,
    integer: bool,
    pointee: Option<Pointee>,
}

impl Held {
    /// What `members` hold, by `sorts` (per value).
    fn of(members: &[Value], sorts: &[Option<Sort>]) -> Self {
        let mut held = Self::default();
        for member in members {
            match sorts.get(member.0 as usize).copied().flatten() {
                Some(Sort::Pointer(pointee)) => {
                    held.pointer = true;
                    held.pointee = held.pointee.or(pointee);
                }
                Some(Sort::Integer) => held.integer = true,
                None => {}
            }
        }
        held
    }

    /// Whether one holds a pointer and the other an integer, or they hold
    /// pointers to what one variable may not ([`Pointee::agrees`]).
    fn conflicts(self, other: Self) -> bool {
        (self.pointer && other.integer)
            || (self.integer && other.pointer)
            || self
                .pointee
                .zip(other.pointee)
                .is_some_and(|(a, b)| !a.agrees(b))
    }

    /// What both hold.
    fn with(self, other: Self) -> Self {
        Self {
            pointer: self.pointer || other.pointer,
            integer: self.integer || other.integer,
            pointee: self.pointee.or(other.pointee),
        }
    }
}

/// A class of values sharing one variable.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct Class {
    /// Its values.
    pub(super) members: Vec<Value>,
    /// The width of its variable.
    pub(super) width: u16,
    /// The parameter it is, if it holds a register's entry value.
    pub(super) parameter: Option<usize>,
}

/// The classes of the values lowered to variables.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct Classes {
    /// Per value: its class, or [`NONE`].
    class: Vec<u32>,
    /// The classes; merged ones are left empty.
    pub(super) sets: Vec<Class>,
    /// Whether the budget stopped coalescing.
    pub(super) over_budget: bool,
}

impl Classes {
    /// How many values have a variable.
    pub(super) fn values(&self) -> usize {
        self.class.iter().filter(|&&class| class != NONE).count()
    }

    /// How many variables they have.
    pub(super) fn count(&self) -> usize {
        self.sets
            .iter()
            .filter(|class| !class.members.is_empty())
            .count()
    }

    /// The class of value `v`, if it has a variable.
    pub(super) fn of(&self, v: Value) -> Option<usize> {
        let class = *self.class.get(v.0 as usize)?;
        (class != NONE).then_some(class as usize)
    }
}

/// Live values per block, as bit sets over the values with variables.
struct Liveness {
    /// Dense index of each value with a variable.
    index: BTreeMap<Value, usize>,
    /// Per block: the values live at its end.
    live_out: Vec<Vec<u64>>,
    /// Per block: each value used in it, with its last use's position.
    last_use: Vec<BTreeMap<usize, u32>>,
    /// Per block: its interval in a depth-first walk of the dominator tree
    /// (a block dominates those whose interval is inside its own).
    intervals: Vec<(u32, u32)>,
}

impl Liveness {
    /// Whether definition point `a` dominates `b`.
    fn dominates(&self, a: Def, b: Def) -> bool {
        if a.block == b.block {
            return a.pos <= b.pos;
        }
        match (
            self.intervals.get(a.block as usize),
            self.intervals.get(b.block as usize),
        ) {
            (Some(&(a_in, a_out)), Some(&(b_in, b_out))) => a_in <= b_in && b_out <= a_out,
            (Some(_) | None, Some(_) | None) => false,
        }
    }

    fn live_out(&self, block: u32, value: usize) -> bool {
        self.live_out
            .get(block as usize)
            .and_then(|set| set.get(value / 64))
            .is_some_and(|word| word >> (value % 64) & 1 == 1)
    }

    fn used_after(&self, block: u32, value: usize, pos: u32) -> bool {
        self.last_use
            .get(block as usize)
            .and_then(|uses| uses.get(&value))
            .is_some_and(|&last| last > pos)
    }
}

impl Lowering<'_, '_> {
    /// The width of the variable of value `v` (canonical, with a
    /// variable).
    pub(super) fn var_width(&self, v: Value) -> u16 {
        match (self.role(v), self.kind(v)) {
            (Role::Parameter(index), _) => self
                .needed
                .parameters
                .get(index)
                .and_then(|p| self.types.value_width(p.ty))
                .unwrap_or(0),
            (_, Kind::CallView { width, .. }) => width,
            (Role::Var, Kind::Phi | Kind::Pure(_)) => self.lane_width(v),
            _ => self.width(v),
        }
    }

    /// The width of the variable of a block parameter or a computed value
    /// that is a whole vector register's state (over 128 bits: SSE's
    /// scalar instructions write the low lane and keep the rest, so a
    /// `double` a loop adds to is 512 bits of `zmm0` in L1): the low bits
    /// anything uses ([`Needed::bits`](super::needed::Needed)), as a lane
    /// of 32, 64, 128 or 256 bits, where that is less than the value. The
    /// variable holds those bits; a read of the value has nothing above
    /// them, as a parameter's.
    fn lane_width(&self, v: Value) -> u16 {
        let width = self.width(v);
        let used = self.needed.bits.get(v.0 as usize).copied().unwrap_or(0);
        if width <= 128 || used == 0 {
            return width;
        }
        [32u16, 64, 128, 256]
            .into_iter()
            .find(|&lane| lane >= used && lane < width)
            .unwrap_or(width)
    }

    /// The values with variables a use of `item` at a statement reads:
    /// itself, or for a folded value, its operands', transitively.
    pub(super) fn leaves(&self, item: Use, out: &mut Vec<Value>) {
        let mut work = vec![item];
        while let Some(item) = work.pop() {
            let Use::Value(value, _) = item else {
                continue;
            };
            let value = self.canonical(value);
            match self.role(value) {
                Role::Var | Role::Parameter(_) => out.push(value),
                Role::Fold(_) => work.extend(self.inputs(value)),
                Role::Inline | Role::Drop | Role::None => {}
            }
        }
    }

    /// The classes: each value with a variable alone, then block
    /// parameters coalesced with their arguments where they do not
    /// interfere and do not hold a pointer and an integer ([`Sort`]),
    /// within the budget.
    pub(super) fn coalesce(&mut self) {
        let mut classes = self.singletons();
        let sorts = self.sorts();
        self.nulls = self.null_arguments(&self.shapes());
        let mut steps = 0u64;
        let merged = self
            .liveness(&classes, &mut steps)
            .and_then(|liveness| self.merge(&mut classes, &liveness, &sorts, &mut steps));
        if merged.is_none() {
            // Past the budget: every value keeps its own variable.
            classes = self.singletons();
            classes.over_budget = true;
        }
        self.classes = classes;
    }

    /// Each value with a variable in a class of its own.
    fn singletons(&self) -> Classes {
        let count = self.l1.values.len();
        let mut classes = Classes {
            class: vec![NONE; count],
            sets: Vec::new(),
            over_budget: false,
        };
        for index in 0..count {
            let v = Value(u32::try_from(index).unwrap_or(u32::MAX));
            if self.canonical(v) != v || self.def(v) == Def::NONE {
                continue;
            }
            let parameter = match self.role(v) {
                Role::Var => None,
                Role::Parameter(index) => Some(index),
                Role::None | Role::Inline | Role::Fold(_) | Role::Drop => continue,
            };
            if let Some(slot) = classes.class.get_mut(index) {
                *slot = u32::try_from(classes.sets.len()).unwrap_or(NONE);
            }
            classes.sets.push(Class {
                members: vec![v],
                width: self.var_width(v),
                parameter,
            });
        }
        classes
    }

    /// Merges block parameters' classes with their arguments' where no
    /// members interfere and one does not hold a pointer the other an
    /// integer (by `sorts`, per value); `None` past the budget.
    fn merge(
        &self,
        classes: &mut Classes,
        liveness: &Liveness,
        sorts: &[Option<Sort>],
        steps: &mut u64,
    ) -> Option<()> {
        let blocks: Vec<_> = self.blocks().collect();
        let mut held: Vec<Held> = classes
            .sets
            .iter()
            .map(|class| Held::of(&class.members, sorts))
            .collect();
        for (id, block) in blocks {
            for (k, &parameter) in block.parameters.iter().enumerate() {
                if id.0 == 0 || self.canonical(parameter) != parameter {
                    continue;
                }
                if classes.of(parameter).is_none() {
                    continue;
                }
                for (_, argument) in self.incoming(id, k) {
                    if self.nulls.contains(&(parameter, argument)) {
                        continue;
                    }
                    let argument = self.canonical(argument);
                    let (Some(a), Some(b)) = (classes.of(argument), classes.of(parameter)) else {
                        continue;
                    };
                    if a == b {
                        continue;
                    }
                    let (Some(x), Some(y)) = (classes.sets.get(a), classes.sets.get(b)) else {
                        continue;
                    };
                    if x.width != y.width || (x.parameter.is_some() && y.parameter.is_some()) {
                        continue;
                    }
                    let (hx, hy) = (
                        held.get(a).copied().unwrap_or_default(),
                        held.get(b).copied().unwrap_or_default(),
                    );
                    if hx.conflicts(hy) {
                        continue;
                    }
                    let pairs = (x.members.len() as u64).saturating_mul(y.members.len() as u64);
                    *steps = steps.saturating_add(pairs);
                    if *steps > self.cx.budget {
                        return None;
                    }
                    let clash = x
                        .members
                        .iter()
                        .any(|&p| y.members.iter().any(|&q| self.interferes(liveness, p, q)));
                    if clash {
                        continue;
                    }
                    // Merge the smaller into the larger.
                    let (keep, gone) = if x.members.len() >= y.members.len() {
                        (a, b)
                    } else {
                        (b, a)
                    };
                    let moved = classes
                        .sets
                        .get_mut(gone)
                        .map(core::mem::take)
                        .unwrap_or_default();
                    for &member in &moved.members {
                        if let Some(slot) = classes.class.get_mut(member.0 as usize) {
                            *slot = u32::try_from(keep).unwrap_or(NONE);
                        }
                    }
                    if let Some(kept) = classes.sets.get_mut(keep) {
                        kept.members.extend(moved.members);
                        kept.parameter = kept.parameter.or(moved.parameter);
                    }
                    if let Some(slot) = held.get_mut(keep) {
                        *slot = hx.with(hy);
                    }
                }
            }
        }
        Some(())
    }

    /// Whether values `a` and `b` (with variables) interfere: the one
    /// defined first is live where the other is defined.
    fn interferes(&self, liveness: &Liveness, a: Value, b: Value) -> bool {
        let (da, db) = (self.def(a), self.def(b));
        let (first, at) = if liveness.dominates(da, db) {
            (a, db)
        } else if liveness.dominates(db, da) {
            (b, da)
        } else {
            return false;
        };
        let Some(&index) = liveness.index.get(&first) else {
            return false;
        };
        liveness.live_out(at.block, index) || liveness.used_after(at.block, index, at.pos)
    }

    /// Each block's interval in a depth-first walk of the dominator tree.
    fn intervals(&self) -> Vec<(u32, u32)> {
        let count = self.l1.blocks.len();
        let mut children: Vec<Vec<u32>> = vec![Vec::new(); count];
        for (id, _) in self.blocks() {
            if let Some(parent) = self.dominators.parent(id)
                && let Some(list) = children.get_mut(parent.0 as usize)
            {
                list.push(id.0);
            }
        }
        let mut intervals = vec![(u32::MAX, 0); count];
        let mut clock = 0u32;
        let mut work = vec![(0u32, false)];
        while let Some((block, done)) = work.pop() {
            let Some(slot) = intervals.get_mut(block as usize) else {
                continue;
            };
            clock += 1;
            if done {
                slot.1 = clock;
                continue;
            }
            slot.0 = clock;
            work.push((block, true));
            for &child in children.get(block as usize).map_or(&[][..], Vec::as_slice) {
                work.push((child, false));
            }
        }
        intervals
    }

    /// The uses, with positions, of the values with variables in each
    /// block lowered.
    fn block_uses(&self) -> BTreeMap<u32, Vec<(Value, u32)>> {
        let mut uses: BTreeMap<u32, Vec<(Value, u32)>> = BTreeMap::new();
        let mut leaves = Vec::new();
        for (id, block) in self.blocks() {
            let list = uses.entry(id.0).or_default();
            for (k, &inst) in block.insts.iter().enumerate() {
                let pos = u32::try_from(k + 1).unwrap_or(u32::MAX);
                let Some(i) = self.l1.inst(inst) else {
                    continue;
                };
                leaves.clear();
                if !matches!(i.op, binbun_ssa::ir::Op::Store { .. }) || self.store_lowered(inst) {
                    for item in self.statement_uses(inst) {
                        self.leaves(item, &mut leaves);
                    }
                }
                for &result in &i.results {
                    if self.canonical(result) != result {
                        continue;
                    }
                    if matches!(self.role(result), Role::Var | Role::Drop) {
                        for item in self.inputs(result) {
                            self.leaves(item, &mut leaves);
                        }
                    }
                }
                list.extend(leaves.iter().map(|&v| (v, pos)));
            }
            leaves.clear();
            for item in self.terminator_uses(id) {
                self.leaves(item, &mut leaves);
            }
            let pos = self.terminator_pos(id);
            list.extend(leaves.iter().map(|&v| (v, pos)));
            leaves.clear();
            for target in block.terminator.targets() {
                let Some(next) = self.l1.block(target.block) else {
                    continue;
                };
                for (&parameter, &argument) in next.parameters.iter().zip(&target.arguments) {
                    if self.canonical(parameter) == parameter
                        && matches!(self.role(parameter), Role::Var)
                    {
                        self.leaves(Use::Value(argument, self.width(argument)), &mut leaves);
                    }
                }
            }
            let pos = self.edge_pos(id);
            list.extend(leaves.iter().map(|&v| (v, pos)));
        }
        uses
    }

    /// Liveness of the values in `classes`, or `None` past the budget.
    fn liveness(&self, classes: &Classes, steps: &mut u64) -> Option<Liveness> {
        let index: BTreeMap<Value, usize> = classes
            .sets
            .iter()
            .flat_map(|class| class.members.iter().copied())
            .enumerate()
            .map(|(i, v)| (v, i))
            .collect();
        let words = index.len().div_ceil(64);
        let blocks = self.l1.blocks.len();
        let uses = self.block_uses();
        let mut last_use: Vec<BTreeMap<usize, u32>> = vec![BTreeMap::new(); blocks];
        // Upward-exposed uses: of values defined in other blocks.
        let mut gen_sets = vec![vec![0u64; words]; blocks];
        let mut defs = vec![vec![0u64; words]; blocks];
        for (&value, &i) in &index {
            let def = self.def(value);
            if let Some(word) = defs
                .get_mut(def.block as usize)
                .and_then(|set| set.get_mut(i / 64))
            {
                *word |= 1 << (i % 64);
            }
        }
        for (&block, list) in &uses {
            for &(value, pos) in list {
                let Some(&i) = index.get(&value) else {
                    continue;
                };
                if let Some(map) = last_use.get_mut(block as usize) {
                    let last = map.entry(i).or_insert(pos);
                    *last = (*last).max(pos);
                }
                if self.def(value).block != block
                    && let Some(word) = gen_sets
                        .get_mut(block as usize)
                        .and_then(|set| set.get_mut(i / 64))
                {
                    *word |= 1 << (i % 64);
                }
            }
        }
        let order: Vec<BlockId> = self.blocks().map(|(id, _)| id).collect();
        let successors: Vec<Vec<usize>> = (0..blocks)
            .map(|b| {
                self.l1
                    .blocks
                    .get(b)
                    .map(|block| {
                        block
                            .terminator
                            .targets()
                            .map(|t| t.block.0 as usize)
                            .collect()
                    })
                    .unwrap_or_default()
            })
            .collect();
        let mut live_in = vec![vec![0u64; words]; blocks];
        let mut live_out = vec![vec![0u64; words]; blocks];
        let mut changed = true;
        while changed {
            changed = false;
            for &id in order.iter().rev() {
                let b = id.0 as usize;
                *steps = steps.saturating_add(words as u64 + 1);
                if *steps > self.cx.budget {
                    return None;
                }
                let mut out = vec![0u64; words];
                for &s in successors.get(b).map_or(&[][..], Vec::as_slice) {
                    if let Some(set) = live_in.get(s) {
                        for (o, i) in out.iter_mut().zip(set) {
                            *o |= i;
                        }
                    }
                }
                let mut inn = gen_sets.get(b).cloned().unwrap_or_default();
                if let Some(def) = defs.get(b) {
                    for ((n, o), d) in inn.iter_mut().zip(&out).zip(def) {
                        *n |= o & !d;
                    }
                }
                if live_in.get(b) != Some(&inn) {
                    changed = true;
                    if let Some(slot) = live_in.get_mut(b) {
                        *slot = inn;
                    }
                }
                if let Some(slot) = live_out.get_mut(b) {
                    *slot = out;
                }
            }
        }
        Some(Liveness {
            index,
            live_out,
            last_use,
            intervals: self.intervals(),
        })
    }
}
