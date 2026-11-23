//! The engine's correction types as the log writes them: binbun's
//! [`Item`] and [`Bounds`] carry no serde of their own, so a value holding
//! one is written through these mirrors (a unit of data by its name, as
//! the project file names it).
//!
//! And the readers of every string and list a change's body holds: each
//! through a bounded type of `binbun-bounded`, so that decoding a body
//! another party wrote allocates no more than its bounds declare
//! ([`super::Body::decode`]).

use binbun::corrections::{Bounds, Data, Item, Unit};
use binbun_bounded::{Bounded, Bytes, Text};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::MAX_BODY;

/// The most items of a list in a body that nothing else bounds.
pub(crate) const LIST: usize = 65_535;

/// A string of at most [`MAX_BODY`] bytes.
///
/// # Errors
///
/// The deserializer's; a longer one.
pub(crate) fn text<'de, D: Deserializer<'de>>(d: D) -> Result<String, D::Error> {
    Text::<MAX_BODY>::deserialize(d).map(Text::into_string)
}

/// An optional string of at most [`MAX_BODY`] bytes.
///
/// # Errors
///
/// The deserializer's; a longer one.
pub(crate) fn opt_text<'de, D: Deserializer<'de>>(d: D) -> Result<Option<String>, D::Error> {
    Ok(Option::<Text<MAX_BODY>>::deserialize(d)?.map(Text::into_string))
}

/// Strings, at most [`LIST`], each of at most [`MAX_BODY`] bytes.
///
/// # Errors
///
/// The deserializer's; too many, or one too long.
pub(crate) fn texts<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<String>, D::Error> {
    Ok(Bounded::<Text<MAX_BODY>, LIST>::deserialize(d)?
        .into_vec()
        .into_iter()
        .map(Text::into_string)
        .collect())
}

/// Optional bytes, at most [`MAX_BODY`].
///
/// # Errors
///
/// The deserializer's; too many.
pub(crate) fn opt_bytes<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Vec<u8>>, D::Error> {
    Ok(Option::<Bytes<MAX_BODY>>::deserialize(d)?.map(Bytes::into_vec))
}

/// A list of at most `N` items.
///
/// # Errors
///
/// The deserializer's; too many.
pub(crate) fn list<'de, D: Deserializer<'de>, T: Deserialize<'de>, const N: usize>(
    d: D,
) -> Result<Vec<T>, D::Error> {
    Bounded::<T, N>::deserialize(d).map(Bounded::into_vec)
}

/// A body's ops: at most [`super::MAX_OPS`].
///
/// # Errors
///
/// The deserializer's; too many.
pub(crate) fn ops<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<super::Op>, D::Error> {
    list::<D, super::Op, { super::MAX_OPS }>(d)
}

/// An [`Item`] as written.
#[derive(Serialize, Deserialize)]
enum ItemWire {
    /// [`Item::Code`].
    Code,
    /// [`Item::Undefined`]: its size.
    Undefined(u64),
    /// [`Item::Data`]: its unit's name and count.
    Data(#[serde(deserialize_with = "text")] String, u64),
}

/// [`Bounds`] as written.
#[derive(Serialize, Deserialize)]
enum BoundsWire {
    /// [`Bounds::Function`]: its end, if given.
    Function(Option<u64>),
    /// [`Bounds::Deleted`].
    Deleted,
}

/// `Option<Item>` through [`ItemWire`].
pub(super) mod item {
    use super::{Data, Deserialize, Deserializer, Item, ItemWire, Serialize, Serializer, Unit};

    /// Writes `item`.
    ///
    /// # Errors
    ///
    /// The serializer's.
    #[expect(
        clippy::ref_option,
        reason = "serde's `with` passes the field by reference"
    )]
    pub(crate) fn serialize<S: Serializer>(item: &Option<Item>, s: S) -> Result<S::Ok, S::Error> {
        item.map(|item| match item {
            Item::Code => ItemWire::Code,
            Item::Undefined { size } => ItemWire::Undefined(size),
            Item::Data(data) => ItemWire::Data(data.unit.name().to_owned(), data.count),
        })
        .serialize(s)
    }

    /// Reads an item: one that is none (a unit with no such name, no
    /// bytes) reads as an item of no bytes, which no key takes
    /// ([`super::super::Value::fits`]), so it is refused as malformed.
    ///
    /// # Errors
    ///
    /// The deserializer's.
    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Item>, D::Error> {
        let Some(wire) = Option::<ItemWire>::deserialize(d)? else {
            return Ok(None);
        };
        let none = Item::Undefined { size: 0 };
        let item = match wire {
            ItemWire::Code => Item::Code,
            ItemWire::Undefined(size) if size > 0 => Item::Undefined { size },
            ItemWire::Data(unit, count) if count > 0 => {
                Unit::named(&unit).map_or(none, |unit| Item::Data(Data { unit, count }))
            }
            ItemWire::Undefined(_) | ItemWire::Data(..) => none,
        };
        Ok(Some(item))
    }

    /// Whether `item` is one: of some bytes.
    pub(crate) fn holds(item: &Item) -> bool {
        match item {
            Item::Code => true,
            Item::Undefined { size } => *size > 0,
            Item::Data(data) => data.count > 0,
        }
    }
}

/// `Option<Bounds>` through [`BoundsWire`].
pub(super) mod bounds {
    use super::{Bounds, BoundsWire, Deserialize, Deserializer, Serialize, Serializer};

    /// Writes `bounds`.
    ///
    /// # Errors
    ///
    /// The serializer's.
    #[expect(
        clippy::ref_option,
        reason = "serde's `with` passes the field by reference"
    )]
    pub(crate) fn serialize<S: Serializer>(
        bounds: &Option<Bounds>,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        bounds
            .map(|bounds| match bounds {
                Bounds::Function { end } => BoundsWire::Function(end),
                Bounds::Deleted => BoundsWire::Deleted,
            })
            .serialize(s)
    }

    /// Reads bounds.
    ///
    /// # Errors
    ///
    /// The deserializer's.
    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Bounds>, D::Error> {
        Ok(
            Option::<BoundsWire>::deserialize(d)?.map(|wire| match wire {
                BoundsWire::Function(end) => Bounds::Function { end },
                BoundsWire::Deleted => Bounds::Deleted,
            }),
        )
    }
}
