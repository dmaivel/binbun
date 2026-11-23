//! Lists and maps of at most `N` items.

use std::collections::BTreeMap;
use std::fmt;
use std::marker::PhantomData;
use std::ops::{Deref, DerefMut};

use serde::de::{self, DeserializeOwned, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{Bounds, Error, Refuse, mark, reserve};

/// A list of at most `N` items: a `Vec` whose decoder refuses item
/// `N + 1` before decoding it. Encoded as the `Vec` is.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Bounded<T, const N: usize>(Vec<T>);

impl<T, const N: usize> Bounded<T, N> {
    /// The most items.
    pub const MAX: usize = N;

    /// An empty one.
    pub const fn new() -> Self {
        Self(Vec::new())
    }

    /// The first `N` of `items`.
    pub fn truncated(mut items: Vec<T>) -> Self {
        items.truncate(N);
        Self(items)
    }

    /// Adds `item` at the end, if fewer than `N` are there; else gives
    /// it back.
    ///
    /// # Errors
    ///
    /// `N` are there.
    pub fn push(&mut self, item: T) -> Result<(), T> {
        if self.0.len() < N {
            self.0.push(item);
            Ok(())
        } else {
            Err(item)
        }
    }

    /// Keeps the first `length` items.
    pub fn truncate(&mut self, length: usize) {
        self.0.truncate(length);
    }

    /// Keeps the items `keep` says to, in order.
    pub fn retain(&mut self, keep: impl FnMut(&T) -> bool) {
        self.0.retain(keep);
    }

    /// Drops every item.
    pub fn clear(&mut self) {
        self.0.clear();
    }

    /// The items.
    pub fn into_vec(self) -> Vec<T> {
        self.0
    }
}

impl<T, const N: usize> Default for Bounded<T, N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: fmt::Debug, const N: usize> fmt::Debug for Bounded<T, N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl<T, const N: usize> Deref for Bounded<T, N> {
    type Target = [T];

    fn deref(&self) -> &[T] {
        &self.0
    }
}

impl<T, const N: usize> DerefMut for Bounded<T, N> {
    fn deref_mut(&mut self) -> &mut [T] {
        &mut self.0
    }
}

impl<T, const N: usize> TryFrom<Vec<T>> for Bounded<T, N> {
    type Error = Error;

    fn try_from(items: Vec<T>) -> Result<Self, Error> {
        if items.len() <= N {
            Ok(Self(items))
        } else {
            Err(Error::Length {
                least: 0,
                most: N,
                length: items.len(),
            })
        }
    }
}

impl<T, const N: usize> From<Bounded<T, N>> for Vec<T> {
    fn from(items: Bounded<T, N>) -> Self {
        items.0
    }
}

impl<T: PartialEq<U>, U, const N: usize, const M: usize> PartialEq<[U; M]> for Bounded<T, N> {
    fn eq(&self, other: &[U; M]) -> bool {
        self.0 == other
    }
}

impl<T: PartialEq<U>, U, const N: usize> PartialEq<Vec<U>> for Bounded<T, N> {
    fn eq(&self, other: &Vec<U>) -> bool {
        self.0 == *other
    }
}

impl<T, const N: usize> IntoIterator for Bounded<T, N> {
    type Item = T;
    type IntoIter = std::vec::IntoIter<T>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'a, T, const N: usize> IntoIterator for &'a Bounded<T, N> {
    type Item = &'a T;
    type IntoIter = std::slice::Iter<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl<T: Serialize, const N: usize> Serialize for Bounded<T, N> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(&self.0)
    }
}

impl<'de, T: Deserialize<'de>, const N: usize> Deserialize<'de> for Bounded<T, N> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_newtype_struct(mark::LIST, ListVisitor::<T, N>(PhantomData))
    }
}

impl<T: DeserializeOwned, const N: usize> Bounds for Bounded<T, N> {}

/// Reads a [`Bounded`].
struct ListVisitor<T, const N: usize>(PhantomData<T>);

impl<'de, T: Deserialize<'de>, const N: usize> Visitor<'de> for ListVisitor<T, N> {
    type Value = Bounded<T, N>;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "a list of at most {N} items")
    }

    fn visit_newtype_struct<D: Deserializer<'de>>(self, inner: D) -> Result<Self::Value, D::Error> {
        inner.deserialize_seq(self)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        let declared = seq.size_hint();
        if let Some(length) = declared.filter(|&length| length > N) {
            return Err(de::Error::invalid_length(length, &self));
        }
        let mut items = Vec::with_capacity(reserve::<T>(declared, N));
        while items.len() < N {
            match seq.next_element()? {
                Some(item) => items.push(item),
                None => return Ok(Bounded(items)),
            }
        }
        // `N` read: one more is refused unread.
        match seq.next_element_seed(Refuse(N))? {
            Some(()) | None => Ok(Bounded(items)),
        }
    }
}

/// A map of at most `N` entries, each key once: a `BTreeMap` whose
/// decoder refuses entry `N + 1` before decoding it, and a key given
/// twice. Encoded as the `BTreeMap` is.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Map<K, V, const N: usize>(BTreeMap<K, V>);

impl<K: Ord, V, const N: usize> Map<K, V, N> {
    /// The most entries.
    pub const MAX: usize = N;

    /// An empty one.
    pub const fn new() -> Self {
        Self(BTreeMap::new())
    }

    /// The entries.
    pub fn into_inner(self) -> BTreeMap<K, V> {
        self.0
    }
}

impl<K: Ord, V, const N: usize> Default for Map<K, V, N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<K: fmt::Debug, V: fmt::Debug, const N: usize> fmt::Debug for Map<K, V, N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl<K, V, const N: usize> Deref for Map<K, V, N> {
    type Target = BTreeMap<K, V>;

    fn deref(&self) -> &BTreeMap<K, V> {
        &self.0
    }
}

impl<K, V, const N: usize> TryFrom<BTreeMap<K, V>> for Map<K, V, N> {
    type Error = Error;

    fn try_from(entries: BTreeMap<K, V>) -> Result<Self, Error> {
        if entries.len() <= N {
            Ok(Self(entries))
        } else {
            Err(Error::Length {
                least: 0,
                most: N,
                length: entries.len(),
            })
        }
    }
}

impl<K, V, const N: usize> From<Map<K, V, N>> for BTreeMap<K, V> {
    fn from(entries: Map<K, V, N>) -> Self {
        entries.0
    }
}

impl<K: Serialize, V: Serialize, const N: usize> Serialize for Map<K, V, N> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_map(&self.0)
    }
}

impl<'de, K: Deserialize<'de> + Ord, V: Deserialize<'de>, const N: usize> Deserialize<'de>
    for Map<K, V, N>
{
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_newtype_struct(mark::MAP, MapVisitor::<K, V, N>(PhantomData))
    }
}

impl<K: DeserializeOwned + Ord, V: DeserializeOwned, const N: usize> Bounds for Map<K, V, N> {}

/// Reads a [`Map`].
struct MapVisitor<K, V, const N: usize>(PhantomData<(K, V)>);

impl<'de, K: Deserialize<'de> + Ord, V: Deserialize<'de>, const N: usize> Visitor<'de>
    for MapVisitor<K, V, N>
{
    type Value = Map<K, V, N>;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "a map of at most {N} entries, each key once")
    }

    fn visit_newtype_struct<D: Deserializer<'de>>(self, inner: D) -> Result<Self::Value, D::Error> {
        inner.deserialize_map(self)
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        if let Some(length) = map.size_hint().filter(|&length| length > N) {
            return Err(de::Error::invalid_length(length, &self));
        }
        let mut entries = BTreeMap::new();
        while entries.len() < N {
            let Some((key, value)) = map.next_entry::<K, V>()? else {
                return Ok(Map(entries));
            };
            if entries.insert(key, value).is_some() {
                return Err(de::Error::custom("a key given twice"));
            }
        }
        match map.next_key_seed(Refuse(N))? {
            Some(()) | None => Ok(Map(entries)),
        }
    }
}
