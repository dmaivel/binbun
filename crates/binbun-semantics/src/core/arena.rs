use alloc::vec::Vec;
use core::fmt;
use core::marker::PhantomData;
use core::ops::{Index, IndexMut};

use crate::core::Id;

/// Append-only storage that hands out a typed [`Id`] for every element.
///
/// Elements are never removed, so an id stays valid for the arena's lifetime.
/// Indexing with an id from a different arena of the same id type is a logic
/// error; it panics if out of bounds and otherwise returns the wrong element.
pub struct Arena<I: Id, T> {
    items: Vec<T>,
    // `fn() -> I` keeps `Arena` covariant and `Send`/`Sync` regardless of `I`.
    id: PhantomData<fn() -> I>,
}

impl<I: Id, T> Arena<I, T> {
    /// An empty arena.
    pub const fn new() -> Self {
        Self {
            items: Vec::new(),
            id: PhantomData,
        }
    }

    /// An empty arena with room for `capacity` elements.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            items: Vec::with_capacity(capacity),
            id: PhantomData,
        }
    }

    /// Appends `value` and returns its id.
    ///
    /// # Panics
    ///
    /// If the arena already holds `u32::MAX + 1` elements.
    pub fn push(&mut self, value: T) -> I {
        let id = I::from_index(self.items.len());
        self.items.push(value);
        id
    }

    /// The element for `id`, if it is in bounds.
    pub fn get(&self, id: I) -> Option<&T> {
        self.items.get(id.index())
    }

    /// The element for `id`, if it is in bounds.
    pub fn get_mut(&mut self, id: I) -> Option<&mut T> {
        self.items.get_mut(id.index())
    }

    /// Number of elements.
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Whether the arena has no elements.
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// The id the next [`push`](Self::push) will return.
    pub fn next_id(&self) -> I {
        I::from_index(self.items.len())
    }

    /// Ids of all elements, in insertion order.
    pub fn ids(&self) -> impl ExactSizeIterator<Item = I> + DoubleEndedIterator + use<I, T> {
        (0..self.items.len()).map(I::from_index)
    }

    /// Elements with their ids, in insertion order.
    pub fn iter(&self) -> impl ExactSizeIterator<Item = (I, &T)> + DoubleEndedIterator {
        self.items
            .iter()
            .enumerate()
            .map(|(index, value)| (I::from_index(index), value))
    }

    /// Mutable elements with their ids, in insertion order.
    pub fn iter_mut(&mut self) -> impl ExactSizeIterator<Item = (I, &mut T)> + DoubleEndedIterator {
        self.items
            .iter_mut()
            .enumerate()
            .map(|(index, value)| (I::from_index(index), value))
    }

    /// Elements in insertion order.
    pub fn values(&self) -> core::slice::Iter<'_, T> {
        self.items.iter()
    }

    /// Elements as a slice, indexed by [`Id::index`].
    pub fn as_slice(&self) -> &[T] {
        &self.items
    }
}

impl<I: Id, T> Default for Arena<I, T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<I: Id, T: Clone> Clone for Arena<I, T> {
    fn clone(&self) -> Self {
        Self {
            items: self.items.clone(),
            id: PhantomData,
        }
    }
}

impl<I: Id, T: PartialEq> PartialEq for Arena<I, T> {
    fn eq(&self, other: &Self) -> bool {
        self.items == other.items
    }
}

impl<I: Id, T: Eq> Eq for Arena<I, T> {}

impl<I: Id, T: fmt::Debug> fmt::Debug for Arena<I, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_map().entries(self.iter()).finish()
    }
}

impl<I: Id, T> Index<I> for Arena<I, T> {
    type Output = T;

    /// # Panics
    ///
    /// If `id` is out of bounds.
    fn index(&self, id: I) -> &T {
        match self.items.get(id.index()) {
            Some(value) => value,
            None => panic!(
                "{id:?} is out of bounds for an arena of {} elements",
                self.items.len()
            ),
        }
    }
}

impl<I: Id, T> IndexMut<I> for Arena<I, T> {
    /// # Panics
    ///
    /// If `id` is out of bounds.
    fn index_mut(&mut self, id: I) -> &mut T {
        let len = self.items.len();
        match self.items.get_mut(id.index()) {
            Some(value) => value,
            None => panic!("{id:?} is out of bounds for an arena of {len} elements"),
        }
    }
}

impl<I: Id, T> FromIterator<T> for Arena<I, T> {
    fn from_iter<It: IntoIterator<Item = T>>(iter: It) -> Self {
        let items: Vec<T> = iter.into_iter().collect();
        // Validates the length once, so later `from_index` calls cannot fail.
        if let Some(last) = items.len().checked_sub(1) {
            let _ = I::from_index(last);
        }
        Self {
            items,
            id: PhantomData,
        }
    }
}

impl<I: Id, T> Extend<T> for Arena<I, T> {
    fn extend<It: IntoIterator<Item = T>>(&mut self, iter: It) {
        for value in iter {
            self.push(value);
        }
    }
}

impl<'a, I: Id, T> IntoIterator for &'a Arena<I, T> {
    type Item = (I, &'a T);
    type IntoIter = core::iter::Map<
        core::iter::Enumerate<core::slice::Iter<'a, T>>,
        fn((usize, &'a T)) -> (I, &'a T),
    >;

    fn into_iter(self) -> Self::IntoIter {
        self.items
            .iter()
            .enumerate()
            .map(|(index, value)| (I::from_index(index), value))
    }
}

#[cfg(test)]
mod tests {
    use crate::core::{Arena, Id};
    use alloc::vec::Vec;

    #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Id)]
    struct Node(u32);

    #[test]
    fn ids_follow_insertion_order_and_index_back() {
        let mut arena: Arena<Node, &str> = Arena::new();
        let a = arena.push("a");
        let b = arena.push("b");
        assert_eq!((a.raw(), b.raw()), (0, 1));
        assert_eq!(arena.next_id().raw(), 2);
        assert_eq!(arena[b], "b");
        arena[a] = "z";
        let pairs: Vec<_> = arena.iter().collect();
        assert_eq!(pairs, [(a, &"z"), (b, &"b")]);
        assert_eq!(arena.ids().rev().collect::<Vec<_>>(), [b, a]);
    }

    #[test]
    fn out_of_bounds_lookup_is_none_for_get() {
        let arena: Arena<Node, u8> = [1, 2].into_iter().collect();
        assert_eq!(arena.get(Node(2)), None);
        assert_eq!(arena.get(Node(1)), Some(&2));
    }

    #[test]
    #[should_panic(expected = "out of bounds")]
    fn out_of_bounds_index_panics() {
        let arena: Arena<Node, u8> = Arena::new();
        let _ = arena[Node(0)];
    }
}
