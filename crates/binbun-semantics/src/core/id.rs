/// A dense, typed index stored as a `u32`.
///
/// Implement it with `#[derive(Id)]` on `struct Name(u32);`. Two id types are
/// never interchangeable, so an index into one arena cannot be used with
/// another by accident.
pub trait Id: Copy + Eq + Ord + core::hash::Hash + core::fmt::Debug {
    /// Wraps a raw index.
    fn from_raw(raw: u32) -> Self;

    /// The raw index.
    fn raw(self) -> u32;

    /// Converts a `usize` position into an id.
    ///
    /// # Panics
    ///
    /// If `index` does not fit in a `u32`. Arenas reach that limit only
    /// after allocating more than four billion elements.
    #[inline]
    fn from_index(index: usize) -> Self {
        let raw = u32::try_from(index).expect("id index exceeds u32::MAX");
        Self::from_raw(raw)
    }

    /// The id as a `usize` position.
    #[inline]
    fn index(self) -> usize {
        // `usize` is at least 32 bits on every target binbun supports.
        self.raw() as usize
    }
}

#[cfg(test)]
mod tests {
    use crate::core::Id;
    use alloc::format;

    #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Id)]
    #[id(prefix = "v")]
    struct Value(u32);

    #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Id)]
    struct Unprefixed(u32);

    #[test]
    fn round_trips_through_usize() {
        let id = Value::from_index(7);
        assert_eq!(id.raw(), 7);
        assert_eq!(id.index(), 7);
    }

    #[test]
    #[should_panic(expected = "exceeds u32::MAX")]
    fn rejects_indices_beyond_u32() {
        let _ = Value::from_index(usize::try_from(u64::from(u32::MAX) + 1).unwrap());
    }

    #[test]
    fn formats_with_prefix() {
        assert_eq!(format!("{:?}", Value(3)), "v3");
        assert_eq!(format!("{}", Unprefixed(3)), "Unprefixed#3");
    }
}
