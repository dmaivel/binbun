//! Lists of items by a dense key (a value's or block's number), all in one
//! allocation: what the analyses use for users and arguments, built once
//! and only read afterwards.

use alloc::vec;
use alloc::vec::Vec;

/// Items grouped by key, each group in the order its items came.
#[derive(Clone, Debug)]
pub struct Groups<T> {
    /// Where each key's items start in `items`, and their end last.
    starts: Vec<usize>,
    items: Vec<T>,
}

impl<T: Copy> Groups<T> {
    /// The items of `pairs` grouped by key, for keys `0..keys`; pairs with
    /// a key out of range are left out.
    pub fn new(keys: usize, pairs: impl Iterator<Item = (usize, T)> + Clone) -> Self {
        // Counts per key, then where each key's items start.
        let mut starts = vec![0; keys + 1];
        let mut first = None;
        for (key, item) in pairs.clone() {
            if key < keys
                && let Some(count) = starts.get_mut(key)
            {
                *count += 1;
                first.get_or_insert(item);
            }
        }
        let mut total = 0;
        for start in &mut starts {
            let count = *start;
            *start = total;
            total += count;
        }
        let Some(first) = first else {
            return Self {
                starts,
                items: Vec::new(),
            };
        };
        let mut items = vec![first; total];
        let mut next = starts.clone();
        for (key, item) in pairs {
            if key < keys
                && let Some(position) = next.get_mut(key)
            {
                if let Some(slot) = items.get_mut(*position) {
                    *slot = item;
                }
                *position += 1;
            }
        }
        Self { starts, items }
    }

    /// The items of `key`.
    pub fn get(&self, key: usize) -> &[T] {
        match (self.starts.get(key), self.starts.get(key + 1)) {
            (Some(&start), Some(&end)) => self.items.get(start..end).unwrap_or_default(),
            _ => &[],
        }
    }
}
