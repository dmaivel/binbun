//! Byte strings and text of bounded length.
//!
//! Each reads through a newtype named [`mark::LEAF`], whose visitor also
//! takes a unit: what [`crate::walk`] gives it, for a value of the least
//! length (postcard never does; it reads the newtype's contents).

use std::borrow::Borrow;
use std::fmt;
use std::ops::{Deref, DerefMut};

use serde::de::{self, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{Bounds, Error, Refuse, mark, reserve};

/// At most `N` bytes, at least `MIN`: a `Vec<u8>` whose decoder refuses
/// a declared length outside them before reading the bytes. Encoded as
/// the `Vec<u8>` is.
#[derive(Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Bytes<const N: usize, const MIN: usize = 0>(Vec<u8>);

impl<const N: usize, const MIN: usize> Bytes<N, MIN> {
    /// The most bytes.
    pub const MAX: usize = N;

    /// The bytes.
    pub fn into_vec(self) -> Vec<u8> {
        self.0
    }

    /// Whether `length` bytes are within the bounds.
    const fn fits(length: usize) -> bool {
        MIN <= length && length <= N
    }

    /// Why `length` bytes are refused.
    const fn refused(length: usize) -> Error {
        Error::Length {
            least: MIN,
            most: N,
            length,
        }
    }
}

impl<const N: usize, const MIN: usize> fmt::Debug for Bytes<N, MIN> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Bytes({})", self.0.len())
    }
}

impl<const N: usize, const MIN: usize> Deref for Bytes<N, MIN> {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl<const N: usize, const MIN: usize> DerefMut for Bytes<N, MIN> {
    fn deref_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl<const N: usize, const MIN: usize> AsRef<[u8]> for Bytes<N, MIN> {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<const N: usize, const MIN: usize> TryFrom<Vec<u8>> for Bytes<N, MIN> {
    type Error = Error;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Error> {
        if Self::fits(bytes.len()) {
            Ok(Self(bytes))
        } else {
            Err(Self::refused(bytes.len()))
        }
    }
}

impl<const N: usize, const MIN: usize> TryFrom<&[u8]> for Bytes<N, MIN> {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Error> {
        if Self::fits(bytes.len()) {
            Ok(Self(bytes.to_vec()))
        } else {
            Err(Self::refused(bytes.len()))
        }
    }
}

impl<const N: usize, const MIN: usize> From<Bytes<N, MIN>> for Vec<u8> {
    fn from(bytes: Bytes<N, MIN>) -> Self {
        bytes.0
    }
}

impl<const N: usize, const MIN: usize> Serialize for Bytes<N, MIN> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de, const N: usize, const MIN: usize> Deserialize<'de> for Bytes<N, MIN> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_newtype_struct(mark::LEAF, BytesVisitor::<N, MIN>)
    }
}

impl<const N: usize, const MIN: usize> Bounds for Bytes<N, MIN> {}

/// Reads a [`Bytes`].
struct BytesVisitor<const N: usize, const MIN: usize>;

impl<'de, const N: usize, const MIN: usize> Visitor<'de> for BytesVisitor<N, MIN> {
    type Value = Bytes<N, MIN>;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{MIN} to {N} bytes")
    }

    fn visit_newtype_struct<D: Deserializer<'de>>(self, inner: D) -> Result<Self::Value, D::Error> {
        inner.deserialize_byte_buf(self)
    }

    fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
        self.visit_bytes(&vec![0; MIN])
    }

    fn visit_bytes<E: de::Error>(self, bytes: &[u8]) -> Result<Self::Value, E> {
        if Bytes::<N, MIN>::fits(bytes.len()) {
            Ok(Bytes(bytes.to_vec()))
        } else {
            Err(E::invalid_length(bytes.len(), &self))
        }
    }

    fn visit_byte_buf<E: de::Error>(self, bytes: Vec<u8>) -> Result<Self::Value, E> {
        if Bytes::<N, MIN>::fits(bytes.len()) {
            Ok(Bytes(bytes))
        } else {
            Err(E::invalid_length(bytes.len(), &self))
        }
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        let declared = seq.size_hint();
        if let Some(length) = declared.filter(|&length| length > N) {
            return Err(de::Error::invalid_length(length, &self));
        }
        let mut bytes = Vec::with_capacity(reserve::<u8>(declared, N));
        while bytes.len() < N {
            match seq.next_element()? {
                Some(byte) => bytes.push(byte),
                None => break,
            }
        }
        if bytes.len() == N {
            seq.next_element_seed(Refuse(N))?;
        }
        if bytes.len() < MIN {
            return Err(de::Error::invalid_length(bytes.len(), &self));
        }
        Ok(Bytes(bytes))
    }
}

/// Exactly `N` bytes (a key wrap, a hash link): its decoder refuses any
/// other length. Encoded as a `Vec<u8>` of `N` bytes is.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Exact<const N: usize>([u8; N]);

impl<const N: usize> Exact<N> {
    /// The bytes.
    pub const fn as_array(&self) -> &[u8; N] {
        &self.0
    }
}

impl<const N: usize> Default for Exact<N> {
    fn default() -> Self {
        Self([0; N])
    }
}

impl<const N: usize> fmt::Debug for Exact<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Exact({N})")
    }
}

impl<const N: usize> Deref for Exact<N> {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl<const N: usize> AsRef<[u8]> for Exact<N> {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<const N: usize> From<[u8; N]> for Exact<N> {
    fn from(bytes: [u8; N]) -> Self {
        Self(bytes)
    }
}

impl<const N: usize> TryFrom<&[u8]> for Exact<N> {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Error> {
        <[u8; N]>::try_from(bytes)
            .map(Self)
            .map_err(|_| Error::Length {
                least: N,
                most: N,
                length: bytes.len(),
            })
    }
}

impl<const N: usize> Serialize for Exact<N> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de, const N: usize> Deserialize<'de> for Exact<N> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_newtype_struct(mark::LEAF, ExactVisitor::<N>)
    }
}

impl<const N: usize> Bounds for Exact<N> {}

/// Reads an [`Exact`].
struct ExactVisitor<const N: usize>;

impl<'de, const N: usize> Visitor<'de> for ExactVisitor<N> {
    type Value = Exact<N>;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "exactly {N} bytes")
    }

    fn visit_newtype_struct<D: Deserializer<'de>>(self, inner: D) -> Result<Self::Value, D::Error> {
        inner.deserialize_bytes(self)
    }

    fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
        Ok(Exact::default())
    }

    fn visit_bytes<E: de::Error>(self, bytes: &[u8]) -> Result<Self::Value, E> {
        <[u8; N]>::try_from(bytes)
            .map(Exact)
            .map_err(|_| E::invalid_length(bytes.len(), &self))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        if let Some(length) = seq.size_hint().filter(|&length| length != N) {
            return Err(de::Error::invalid_length(length, &self));
        }
        let mut bytes = [0; N];
        for (i, byte) in bytes.iter_mut().enumerate() {
            *byte = seq
                .next_element()?
                .ok_or_else(|| de::Error::invalid_length(i, &self))?;
        }
        seq.next_element_seed(Refuse(N))?;
        Ok(Exact(bytes))
    }
}

/// UTF-8 text of at most `N` bytes: a `String` whose decoder refuses a
/// declared length past `N` before reading the text. Encoded as the
/// `String` is.
#[derive(Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Text<const N: usize>(String);

impl<const N: usize> Text<N> {
    /// The most bytes.
    pub const MAX: usize = N;

    /// An empty one.
    pub const fn new() -> Self {
        Self(String::new())
    }

    /// As much of `text` as fits in `N` bytes, cut between characters.
    pub fn truncated(text: &str) -> Self {
        Self(
            text.get(..text.floor_char_boundary(N))
                .unwrap_or_default()
                .to_owned(),
        )
    }

    /// Drops the text.
    pub fn clear(&mut self) {
        self.0.clear();
    }

    /// The text.
    pub fn into_string(self) -> String {
        self.0
    }
}

impl<const N: usize> fmt::Debug for Text<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl<const N: usize> fmt::Display for Text<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl<const N: usize> Deref for Text<N> {
    type Target = str;

    fn deref(&self) -> &str {
        &self.0
    }
}

impl<const N: usize> AsRef<str> for Text<N> {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl<const N: usize> Borrow<str> for Text<N> {
    fn borrow(&self) -> &str {
        &self.0
    }
}

impl<const N: usize> PartialEq<str> for Text<N> {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

impl<const N: usize> PartialEq<&str> for Text<N> {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}

impl<const N: usize> PartialEq<String> for Text<N> {
    fn eq(&self, other: &String) -> bool {
        self.0 == *other
    }
}

impl<const N: usize> TryFrom<String> for Text<N> {
    type Error = Error;

    fn try_from(text: String) -> Result<Self, Error> {
        if text.len() <= N {
            Ok(Self(text))
        } else {
            Err(Error::Length {
                least: 0,
                most: N,
                length: text.len(),
            })
        }
    }
}

impl<const N: usize> TryFrom<&str> for Text<N> {
    type Error = Error;

    fn try_from(text: &str) -> Result<Self, Error> {
        Self::try_from(text.to_owned())
    }
}

impl<const N: usize> From<Text<N>> for String {
    fn from(text: Text<N>) -> Self {
        text.0
    }
}

impl<const N: usize> Serialize for Text<N> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de, const N: usize> Deserialize<'de> for Text<N> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_newtype_struct(mark::LEAF, TextVisitor::<N>)
    }
}

impl<const N: usize> Bounds for Text<N> {}

/// Reads a [`Text`].
struct TextVisitor<const N: usize>;

impl<'de, const N: usize> Visitor<'de> for TextVisitor<N> {
    type Value = Text<N>;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "text of at most {N} bytes")
    }

    fn visit_newtype_struct<D: Deserializer<'de>>(self, inner: D) -> Result<Self::Value, D::Error> {
        inner.deserialize_string(self)
    }

    fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
        Ok(Text::new())
    }

    fn visit_str<E: de::Error>(self, text: &str) -> Result<Self::Value, E> {
        if text.len() <= N {
            Ok(Text(text.to_owned()))
        } else {
            Err(E::invalid_length(text.len(), &self))
        }
    }

    fn visit_string<E: de::Error>(self, text: String) -> Result<Self::Value, E> {
        if text.len() <= N {
            Ok(Text(text))
        } else {
            Err(E::invalid_length(text.len(), &self))
        }
    }
}
