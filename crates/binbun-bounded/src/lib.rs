//! Decoding bytes another party wrote within declared bounds, and
//! encoding within a limit. The format is postcard; what this crate adds
//! is that no decode allocates more than the type it decodes declares.
//!
//! - **Bounded types**: [`Bounded`] (a list of at most `N` items),
//!   [`Bytes`] (at most `N` bytes, at least `MIN`: the least an item of a
//!   [`Bounded`] list can be, so many tiny items cost their count, not
//!   their allocations), [`Exact`] (exactly `N` bytes), [`Text`] (UTF-8
//!   of at most `N` bytes) and [`Map`] (at most `N` entries, each key
//!   once). Each encodes as the postcard of the `Vec`, `String` or
//!   `BTreeMap` it wraps. Each decoder refuses a declared length past
//!   its bound before reading what it declares, counts items as it
//!   decodes them and refuses item `N + 1` before decoding it, and
//!   reserves room for at most [`PREALLOC`] bytes before items arrive.
//! - **[`decode`]** reads a value from bytes and refuses any left over
//!   ([`take`] gives them back, for formats that put more after a
//!   value). It takes only types marked [`Bounds`]: every list, map,
//!   string and byte string in them is one of the bounded types, which
//!   [`walk`] checks by visiting the type's shape, every variant of every
//!   enum in it.
//! - **[`encode`]** writes a value through a postcard flavour that
//!   fails once its limit is reached, so an oversized value fails before
//!   its buffer grows past the limit; [`size`] counts without
//!   allocating.
//! - **Pages** ([`Page`], [`PageBuilder`]): a reply that can grow is
//!   filled by encoded size, never past the room it is given. The next
//!   page is asked for by a position the asker states (the last key it
//!   was given), never by a handle the responder keeps.

mod page;
mod seq;
mod text;
mod walk;

use std::fmt;

use serde::Serialize;
use serde::de::{self, DeserializeOwned, DeserializeSeed};

pub use page::{Page, PageBuilder};
pub use seq::{Bounded, Map};
pub use text::{Bytes, Exact, Text};
pub use walk::{Unbounded, walk};

/// The most bytes a bounded decoder reserves for its items before they
/// arrive: past it, its buffer grows as they come.
pub const PREALLOC: usize = 4096;

/// A type all of whose lists, maps, strings and byte strings have
/// declared bounds (this crate's types), so that decoding it allocates
/// no more than they declare: what [`decode`] takes. The claim is
/// checked by [`walk`], which every type marked should be tested with.
pub trait Bounds: DeserializeOwned {}

macro_rules! bounds {
    ($($t:ty),*) => { $(impl Bounds for $t {})* };
}
bounds!(
    bool, u8, u16, u32, u64, u128, usize, i8, i16, i32, i64, i128, isize
);

impl<T: Bounds> Bounds for Option<T> {}
impl<T: Bounds> Bounds for Box<T> {}
impl<A: Bounds, B: Bounds> Bounds for (A, B) {}
impl<T: Bounds, const N: usize> Bounds for [T; N] where [T; N]: DeserializeOwned {}

/// Why a value did not decode or encode.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// It does not read as the type (a bound is past, among others).
    Malformed(postcard::Error),
    /// It read with this many bytes left over.
    Trailing(usize),
    /// Its encoding passes the limit of this many bytes.
    TooLarge(usize),
    /// A value of `length` items (or bytes) given to a bounded type of
    /// `least` to `most`.
    Length {
        /// The least allowed.
        least: usize,
        /// The most allowed.
        most: usize,
        /// The items given.
        length: usize,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(error) => write!(f, "does not read: {error}"),
            Self::Trailing(left) => write!(f, "{left} bytes past its end"),
            Self::TooLarge(limit) => write!(f, "larger than its limit of {limit} bytes"),
            Self::Length {
                least,
                most,
                length,
            } => write!(f, "{length} items, where {least} to {most} are allowed"),
        }
    }
}

impl std::error::Error for Error {}

/// The value `bytes` hold, all of them.
///
/// # Errors
///
/// They do not read as a `T` within its bounds, or bytes are left over.
pub fn decode<T: Bounds>(bytes: &[u8]) -> Result<T, Error> {
    let (value, rest) = take::<T>(bytes)?;
    if rest.is_empty() {
        Ok(value)
    } else {
        Err(Error::Trailing(rest.len()))
    }
}

/// The value at the start of `bytes`, and the bytes after it.
///
/// # Errors
///
/// They do not start with a `T` within its bounds.
pub fn take<T: Bounds>(bytes: &[u8]) -> Result<(T, &[u8]), Error> {
    postcard::take_from_bytes(bytes).map_err(Error::Malformed)
}

/// `value`'s postcard, of at most `limit` bytes; its buffer never grows
/// past `limit`.
///
/// # Errors
///
/// It is larger than `limit`, or does not encode.
pub fn encode<T: Serialize + ?Sized>(value: &T, limit: usize) -> Result<Vec<u8>, Error> {
    postcard::serialize_with_flavor(
        value,
        Within {
            bytes: Vec::new(),
            limit,
        },
    )
    .map_err(|error| over(error, limit))
}

/// The bytes of `value`'s postcard, counted without writing them, if at
/// most `limit`.
///
/// # Errors
///
/// It is larger than `limit`, or does not encode.
pub fn size<T: Serialize + ?Sized>(value: &T, limit: usize) -> Result<usize, Error> {
    postcard::serialize_with_flavor(value, Count { count: 0, limit })
        .map_err(|error| over(error, limit))
}

/// `error` as this crate's: a full buffer is a value past `limit`.
fn over(error: postcard::Error, limit: usize) -> Error {
    if error == postcard::Error::SerializeBufferFull {
        Error::TooLarge(limit)
    } else {
        Error::Malformed(error)
    }
}

/// A postcard flavour writing into a buffer that never grows past
/// `limit` bytes.
struct Within {
    /// What is written.
    bytes: Vec<u8>,
    /// The most bytes.
    limit: usize,
}

impl postcard::ser_flavors::Flavor for Within {
    type Output = Vec<u8>;

    fn try_push(&mut self, byte: u8) -> postcard::Result<()> {
        self.try_extend(&[byte])
    }

    fn try_extend(&mut self, data: &[u8]) -> postcard::Result<()> {
        let end = self
            .bytes
            .len()
            .checked_add(data.len())
            .filter(|&end| end <= self.limit)
            .ok_or(postcard::Error::SerializeBufferFull)?;
        if end > self.bytes.capacity() {
            // Doubling, as a `Vec` grows, but never past the limit.
            let capacity = end
                .max(self.bytes.capacity().saturating_mul(2))
                .max(64)
                .min(self.limit);
            self.bytes.reserve_exact(capacity - self.bytes.len());
        }
        self.bytes.extend_from_slice(data);
        Ok(())
    }

    fn finalize(self) -> postcard::Result<Vec<u8>> {
        Ok(self.bytes)
    }
}

/// A postcard flavour counting bytes, up to `limit`.
struct Count {
    /// The bytes so far.
    count: usize,
    /// The most bytes.
    limit: usize,
}

impl postcard::ser_flavors::Flavor for Count {
    type Output = usize;

    fn try_push(&mut self, _: u8) -> postcard::Result<()> {
        self.try_extend(&[0])
    }

    fn try_extend(&mut self, data: &[u8]) -> postcard::Result<()> {
        self.count = self
            .count
            .checked_add(data.len())
            .filter(|&count| count <= self.limit)
            .ok_or(postcard::Error::SerializeBufferFull)?;
        Ok(())
    }

    fn finalize(self) -> postcard::Result<usize> {
        Ok(self.count)
    }
}

/// The bytes of `n`'s postcard varint.
pub(crate) fn varint_len(n: usize) -> usize {
    n.bit_width().max(1).div_ceil(7) as usize
}

/// A seed that refuses whatever it is given, without reading it: asked
/// for an item past a bound, so that the item is never decoded.
pub(crate) struct Refuse(pub(crate) usize);

impl<'de> DeserializeSeed<'de> for Refuse {
    type Value = ();

    fn deserialize<D: de::Deserializer<'de>>(self, _: D) -> Result<(), D::Error> {
        Err(de::Error::invalid_length(
            self.0.saturating_add(1),
            &"no more items than the bound",
        ))
    }
}

/// How many items to reserve room for before they arrive: those
/// declared, within the bound `most` and [`PREALLOC`] bytes.
pub(crate) fn reserve<T>(declared: Option<usize>, most: usize) -> usize {
    declared
        .unwrap_or(0)
        .min(most)
        .min(PREALLOC / size_of::<T>().max(1))
}

/// The newtype names by which bounded types tell [`walk`] what they are.
pub(crate) mod mark {
    /// A [`crate::Bounded`] list.
    pub(crate) const LIST: &str = "binbun_bounded::Bounded";
    /// A [`crate::Map`].
    pub(crate) const MAP: &str = "binbun_bounded::Map";
    /// A [`crate::Bytes`], [`crate::Exact`] or [`crate::Text`]: items
    /// with nothing inside to walk.
    pub(crate) const LEAF: &str = "binbun_bounded::Leaf";
}

#[cfg(test)]
mod tests {
    use super::varint_len;

    #[test]
    fn varint_lengths_are_postcards() {
        for n in [
            0usize,
            1,
            127,
            128,
            16_383,
            16_384,
            2_097_151,
            2_097_152,
            usize::MAX,
        ] {
            assert_eq!(
                varint_len(n),
                postcard::to_allocvec(&n).unwrap().len(),
                "{n}"
            );
        }
    }
}
