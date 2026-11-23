//! One key's state: a multi-value register.
//! Its **leaves** are the ops on the key that no other op on it names
//! among the ops it saw (`prev`); the value shown is the leaf with the
//! highest stamp (for a bookmark, a name before a removal), and more than
//! one leaf is a conflict. It is a function of the set of ops alone, so
//! every order of arrival gives the same.

use std::collections::{BTreeMap, BTreeSet};

use super::{OpId, Stamp, Value};

/// An op as a register keeps it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Entry {
    /// Its place in the total order.
    pub(crate) stamp: Stamp,
    /// Its value.
    pub(crate) value: Value,
    /// The leaves its author saw.
    pub(crate) prev: Vec<OpId>,
}

/// The ops on one key.
#[derive(Clone, Debug, Default)]
pub(crate) struct Register {
    ops: BTreeMap<OpId, Entry>,
    /// Every op some op here names in `prev`, with how many times.
    named: BTreeMap<OpId, usize>,
    leaves: BTreeSet<OpId>,
}

impl Register {
    /// Takes op `id` (in place of one of that id).
    pub(crate) fn insert(&mut self, id: OpId, entry: Entry) {
        self.remove_op(id);
        for prev in &entry.prev {
            *self.named.entry(*prev).or_default() += 1;
            self.leaves.remove(prev);
        }
        if !self.named.contains_key(&id) {
            self.leaves.insert(id);
        }
        self.ops.insert(id, entry);
    }

    /// Drops op `id`, if held: the ops it alone named are leaves again.
    /// The work is that of its own `prev`, not of the register.
    pub(crate) fn remove_op(&mut self, id: OpId) {
        let Some(entry) = self.ops.remove(&id) else {
            return;
        };
        self.leaves.remove(&id);
        for prev in entry.prev {
            let Some(count) = self.named.get_mut(&prev) else {
                continue;
            };
            *count -= 1;
            if *count == 0 {
                self.named.remove(&prev);
                if self.ops.contains_key(&prev) {
                    self.leaves.insert(prev);
                }
            }
        }
    }

    /// Drops the ops `gone` says, the leaves found again.
    pub(crate) fn remove(&mut self, gone: impl Fn(&OpId) -> bool) {
        let ids: Vec<OpId> = self.ops.keys().filter(|id| gone(id)).copied().collect();
        for id in ids {
            self.remove_op(id);
        }
    }

    /// The leaves, in id order.
    pub(crate) fn leaves(&self) -> impl Iterator<Item = (&OpId, &Entry)> {
        self.leaves
            .iter()
            .filter_map(|id| Some((id, self.ops.get(id)?)))
    }

    /// How many leaves there are.
    pub(crate) fn width(&self) -> usize {
        self.leaves.len()
    }

    /// Every op, in id order.
    pub(crate) fn ops(&self) -> impl Iterator<Item = (&OpId, &Entry)> {
        self.ops.iter()
    }

    /// The op shown among `ids` (those it holds): a bookmark's name before
    /// a removal (`adds`), then the highest stamp.
    pub(crate) fn winner_of<'a>(
        &'a self,
        ids: impl Iterator<Item = &'a OpId>,
        adds: bool,
    ) -> Option<(&'a OpId, &'a Entry)> {
        ids.filter_map(|id| Some((id, self.ops.get(id)?)))
            .max_by_key(|(_, entry)| (adds && entry.value.is_some(), entry.stamp))
    }

    /// The leaf shown.
    pub(crate) fn winner(&self, adds: bool) -> Option<(&OpId, &Entry)> {
        self.winner_of(self.leaves.iter(), adds)
    }
}
