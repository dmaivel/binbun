//! Atomic groups as the one operation each is.
//!
//! L0 states a locked instruction as the accesses it makes, in an
//! `atomic` block; L1 keeps the block's number on each load and store
//! ([`Op::Load`], [`Op::Store`]). Lowered one access at a time
//! ([`Escape::Atomic`](binbun_ast::ir::Escape::Atomic)), the group is two
//! statements another thread can come between: `lock xadd` as a load and a
//! store loses increments. [`Lowering::find_atomics`] finds the groups
//! that are one read-modify-write C has a name for
//! ([`Update`](binbun_ast::ir::Update)):
//!
//! - A load and a store of what was read, changed: one of each, of one
//!   address and width, in one block, the value stored the value read
//!   added to, subtracted from, and-ed, or-ed or exclusive-or-ed with a
//!   value the group does not compute (`lock xadd`, `lock add`, `lock
//!   sub`, `lock or`, `lock bts` by a constant), or a value that is not
//!   the group's at all (`xchg`).
//! - A compare-and-exchange (`lock cmpxchg`): a load, a branch on the
//!   value read being another, a store of a third value on the equal
//!   side, and on the other a second load whose value is stored back.
//!
//! The first load then stands for the group: lowered as the update, with
//! the value read as its result; the other accesses are not lowered, and
//! a second load's value is the first's. An operand is a value available
//! where that load is ([`Lowering::early`]). Any other group stays its
//! accesses.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

use binbun_ast::ir::Update;
use binbun_semantics::ir::Binary;
use binbun_ssa::condition::Relation;
use binbun_ssa::ir::{BlockId, InstId, Op, Terminator, Value};

use super::facts::{Def, Kind, Lowering};

/// The atomic groups lowered as one update each.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct Atomics {
    /// Each update, by the load that stands for its group: what it is and
    /// its operands, in the update's order.
    pub(super) updates: BTreeMap<InstId, (Update, Vec<Value>)>,
    /// The group's other accesses, which are not lowered.
    pub(super) absorbed: BTreeSet<InstId>,
}

/// An access of an atomic group: its block and place there, and the
/// instruction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Access {
    block: BlockId,
    at: Def,
    inst: InstId,
}

/// A group found to be an update: the load that stands for it, the
/// update, the accesses it absorbs and the loads whose value is that
/// load's.
struct Found {
    load: InstId,
    update: Update,
    operands: Vec<Value>,
    absorbed: Vec<InstId>,
    same: Vec<Value>,
}

impl Lowering<'_, '_> {
    /// Finds the atomic groups that are one update ([`Atomics`]).
    pub(super) fn find_atomics(&mut self) {
        let l1 = self.l1;
        let mut groups: BTreeMap<u32, Vec<Access>> = BTreeMap::new();
        for (block, body) in self.blocks() {
            for (index, &inst) in body.insts.iter().enumerate() {
                let Some(
                    Op::Load {
                        atomic: Some(group),
                        ..
                    }
                    | Op::Store {
                        atomic: Some(group),
                        ..
                    },
                ) = l1.inst(inst).map(|i| &i.op)
                else {
                    continue;
                };
                let at = Def {
                    block: block.0,
                    pos: u32::try_from(index + 1).unwrap_or(u32::MAX),
                };
                groups
                    .entry(*group)
                    .or_default()
                    .push(Access { block, at, inst });
            }
        }
        for accesses in groups.values() {
            let Some(found) = self
                .read_modify_write(accesses)
                .or_else(|| self.compare_exchange(accesses))
            else {
                continue;
            };
            let Some(&old) = l1.inst(found.load).and_then(|i| i.results.first()) else {
                continue;
            };
            for value in found.same {
                if let Some(slot) = self.canon.get_mut(value.0 as usize) {
                    *slot = old;
                }
            }
            self.atomics.absorbed.extend(found.absorbed);
            self.atomics
                .updates
                .insert(found.load, (found.update, found.operands));
        }
    }

    /// The update `accesses` are if they are a load and a store of the
    /// value read, changed by a value available at the load, or of such a
    /// value alone.
    fn read_modify_write(&self, accesses: &[Access]) -> Option<Found> {
        let &[load, store] = accesses else {
            return None;
        };
        let (
            &Op::Load {
                memory,
                address,
                bytes,
                ..
            },
            &Op::Store {
                memory: before,
                address: to,
                value,
                ..
            },
        ) = (&self.l1.inst(load.inst)?.op, &self.l1.inst(store.inst)?.op)
        else {
            return None;
        };
        let old = *self.l1.inst(load.inst)?.results.first()?;
        let same = load.block == store.block
            && memory == before
            && self.canonical(address) == self.canonical(to)
            && self.width(value) == bytes.checked_mul(8)?;
        if !same {
            return None;
        }
        let stored = self.canonical(value);
        let is_old = |v: Value| self.canonical(v) == old;
        let (update, operand) = match self.defining(stored).map(|(_, op)| op) {
            Some(&Op::Binary(op, a, b)) if is_old(a) || is_old(b) => {
                let update = match op {
                    Binary::Add => Update::Add,
                    Binary::And => Update::And,
                    Binary::Or => Update::Or,
                    Binary::Xor => Update::Xor,
                    Binary::Sub if is_old(a) => Update::Sub,
                    Binary::Sub
                    | Binary::Mul
                    | Binary::UDiv
                    | Binary::URem
                    | Binary::SDiv
                    | Binary::SRem
                    | Binary::Shl
                    | Binary::LShr
                    | Binary::AShr
                    | Binary::Rol
                    | Binary::Ror
                    | Binary::Eq
                    | Binary::Ne
                    | Binary::ULt
                    | Binary::ULe
                    | Binary::SLt
                    | Binary::SLe => return None,
                };
                (update, if is_old(a) { b } else { a })
            }
            Some(_) | None => (Update::Exchange, stored),
        };
        self.early(operand, load.at)?;
        Some(Found {
            load: load.inst,
            update,
            operands: alloc::vec![operand],
            absorbed: alloc::vec![store.inst],
            same: Vec::new(),
        })
    }

    /// The update `accesses` are if they are a compare-and-exchange: a
    /// load, its block's branch on the value read being equal to a value
    /// available there, a store of another such value where it is, and
    /// where it is not a second load stored back.
    fn compare_exchange(&self, accesses: &[Access]) -> Option<Found> {
        let l1 = self.l1;
        let load = *accesses.first()?;
        let &Op::Load { address, bytes, .. } = &l1.inst(load.inst)?.op else {
            return None;
        };
        let old = *l1.inst(load.inst)?.results.first()?;
        let Terminator::Branch {
            condition,
            then,
            otherwise,
        } = &l1.block(load.block)?.terminator
        else {
            return None;
        };
        let compare = self.compare(*condition)?;
        let (equal, unequal) = match compare.relation {
            Relation::Eq => (then.block, otherwise.block),
            Relation::Ne => (otherwise.block, then.block),
            Relation::ULt
            | Relation::ULe
            | Relation::UGt
            | Relation::UGe
            | Relation::SLt
            | Relation::SLe
            | Relation::SGt
            | Relation::SGe => return None,
        };
        let expected = [(compare.left, compare.right), (compare.right, compare.left)]
            .into_iter()
            .find_map(|(read, other)| (self.canonical(read) == old).then_some(other))?;
        let rest: Vec<Access> = accesses.iter().skip(1).copied().collect();
        let (mut stores, mut reload) = (Vec::new(), None);
        for access in &rest {
            let op = &l1.inst(access.inst)?.op;
            if let &Op::Store {
                address: to, value, ..
            } = op
                && self.canonical(to) == self.canonical(address)
                && self.width(value) == bytes.checked_mul(8)?
            {
                stores.push((access.block, value));
            } else if let &Op::Load {
                address: from,
                bytes: again,
                ..
            } = op
                && access.block == unequal
                && reload.is_none()
                && again == bytes
                && self.canonical(from) == self.canonical(address)
            {
                reload = l1.inst(access.inst)?.results.first().copied();
            } else {
                return None;
            }
        }
        let reload = reload?;
        let &[(first, a), (second, b)] = stores.as_slice() else {
            return None;
        };
        let (desired, back) = if (first, second) == (equal, unequal) {
            (a, b)
        } else if (first, second) == (unequal, equal) {
            (b, a)
        } else {
            return None;
        };
        if self.canonical(back) != self.canonical(reload) {
            return None;
        }
        self.early(expected, load.at)?;
        self.early(desired, load.at)?;
        Some(Found {
            load: load.inst,
            update: Update::CompareExchange,
            operands: alloc::vec![expected, desired],
            absorbed: rest.iter().map(|access| access.inst).collect(),
            same: alloc::vec![reload],
        })
    }

    /// The value `value` is computed from that is available at `at`,
    /// where an update's operand is evaluated, and the bits of it `value`
    /// is (`offset`, from bit 0 if `None`: all of it, zero- or
    /// sign-extended): a constant, a value defined before `at` (earlier
    /// in its block, or in a block that dominates it), or an extraction
    /// from or an extension of one (a register's view the instruction
    /// reads after its load). `None` for a value the group computes.
    pub(super) fn early(&self, value: Value, at: Def) -> Option<Value> {
        let mut value = self.canonical(value);
        for _ in 0..DEPTH {
            let def = self.def(value);
            let before = if def.block == at.block {
                def.pos < at.pos
            } else {
                self.dominators
                    .dominates(BlockId(def.block), BlockId(at.block))
            };
            if before || def == Def::NONE || matches!(self.kind(value), Kind::Const(_)) {
                return Some(value);
            }
            value = match self.defining(value).map(|(_, op)| op) {
                Some(&(Op::Extract { value: from, .. } | Op::Extend { value: from, .. })) => {
                    self.canonical(from)
                }
                Some(_) | None => return None,
            };
        }
        None
    }
}

/// How many extractions and extensions [`Lowering::early`] looks through.
const DEPTH: usize = 4;
