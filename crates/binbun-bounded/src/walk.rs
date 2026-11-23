//! A check that a type's decoding is bounded: [`walk`] visits its shape
//! through serde, every variant of every enum in it, and refuses any
//! list, map, string or byte string that is not one of this crate's
//! bounded types.

use std::collections::HashMap;
use std::fmt;

use serde::de::value::U32Deserializer;
use serde::de::{
    self, DeserializeOwned, DeserializeSeed, EnumAccess, MapAccess, SeqAccess, VariantAccess,
    Visitor,
};

use crate::mark;

/// The deepest a type's shape is walked: a recursive type goes past it.
const DEEPEST: usize = 64;

/// The most times a type is walked, to reach every variant.
const WALKS: usize = 100_000;

/// Whether every list, map, string and byte string `T` holds, in every
/// variant of every enum in it, is one of this crate's bounded types,
/// and `T` reads through serde's structural calls only (no
/// `deserialize_any`): so that [`crate::decode`] allocates no more than
/// those types declare. A type marked [`crate::Bounds`] is tested with
/// it.
///
/// # Errors
///
/// Where in `T` an unbounded part, a self-describing read or a
/// recursion past 64 levels is.
pub fn walk<T: DeserializeOwned>() -> Result<(), Unbounded> {
    let mut state = State::default();
    for _ in 0..WALKS {
        state.fresh.clear();
        state.fresh.push(false);
        state.path.clear();
        T::deserialize(&mut Walker {
            state: &mut state,
            allow: None,
        })?;
        if !state.fresh.pop().unwrap_or(false) {
            return Ok(());
        }
    }
    Err(Unbounded(format!(
        "{}: more than {WALKS} walks to reach every variant",
        std::any::type_name::<T>()
    )))
}

/// Where a type's decoding is not bounded, and why.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Unbounded(String);

impl fmt::Display for Unbounded {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Unbounded {}

impl de::Error for Unbounded {
    fn custom<M: fmt::Display>(message: M) -> Self {
        Self(message.to_string())
    }
}

/// How far an enum's variant has been walked.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Seen {
    /// Not yet.
    No,
    /// Once, with something inside it not walked to the end.
    Partly,
    /// Everything inside it.
    Wholly,
}

/// What the walks have seen.
#[derive(Default)]
struct State {
    /// Per enum (its name and variants), how far each variant is walked.
    enums: HashMap<(&'static str, &'static [&'static str]), Vec<Seen>>,
    /// Per enum variant being walked (and the whole type, first), whether
    /// this walk chose a variant not wholly walked before inside it.
    fresh: Vec<bool>,
    /// Where the walk is.
    path: Vec<String>,
}

impl State {
    /// Refuses what is at the walk's place, `what`.
    fn refuse(&self, what: &str) -> Unbounded {
        Unbounded(format!("{}: {what}", self.path.join(".")))
    }
}

/// What a bounded type said it is, for the read right after.
#[derive(Clone, Copy)]
enum Allow {
    /// A [`crate::Bounded`] list.
    List,
    /// A [`crate::Map`].
    Map,
}

/// The deserializer that walks.
struct Walker<'a> {
    /// What the walks have seen.
    state: &'a mut State,
    /// What the next read may be.
    allow: Option<Allow>,
}

impl Walker<'_> {
    /// A walker for what is inside the current value.
    fn inner(&mut self) -> Walker<'_> {
        Walker {
            state: self.state,
            allow: None,
        }
    }

    /// Steps into `place`, unless too deep.
    fn enter(&mut self, place: String) -> Result<(), Unbounded> {
        if self.state.path.len() >= DEEPEST {
            return Err(self
                .state
                .refuse("deeper than 64 levels (a recursive type?)"));
        }
        self.state.path.push(place);
        Ok(())
    }

    /// Steps out.
    fn leave(&mut self) {
        self.state.path.pop();
    }
}

macro_rules! zero {
    ($($method:ident => $visit:ident($value:expr)),* $(,)?) => {
        $(fn $method<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Unbounded> {
            visitor.$visit($value)
        })*
    };
}

macro_rules! unbounded {
    ($($method:ident => $what:literal),* $(,)?) => {
        $(fn $method<V: Visitor<'de>>(self, _: V) -> Result<V::Value, Unbounded> {
            Err(self.state.refuse($what))
        })*
    };
}

impl<'de> de::Deserializer<'de> for &mut Walker<'_> {
    type Error = Unbounded;

    zero! {
        deserialize_bool => visit_bool(false),
        deserialize_i8 => visit_i8(0),
        deserialize_i16 => visit_i16(0),
        deserialize_i32 => visit_i32(0),
        deserialize_i64 => visit_i64(0),
        deserialize_i128 => visit_i128(0),
        deserialize_u8 => visit_u8(0),
        deserialize_u16 => visit_u16(0),
        deserialize_u32 => visit_u32(0),
        deserialize_u64 => visit_u64(0),
        deserialize_u128 => visit_u128(0),
        deserialize_f32 => visit_f32(0.0),
        deserialize_f64 => visit_f64(0.0),
        deserialize_char => visit_char('\0'),
    }

    fn deserialize_unit<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Unbounded> {
        visitor.visit_unit()
    }

    unbounded! {
        deserialize_any => "read as self-describing (deserialize_any)",
        deserialize_ignored_any => "read as self-describing (deserialize_ignored_any)",
        deserialize_str => "a string with no bound (binbun_bounded::Text)",
        deserialize_string => "a string with no bound (binbun_bounded::Text)",
        deserialize_bytes => "bytes with no bound (binbun_bounded::Bytes)",
        deserialize_byte_buf => "bytes with no bound (binbun_bounded::Bytes)",
        deserialize_identifier => "an identifier outside an enum",
    }

    fn deserialize_option<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Unbounded> {
        visitor.visit_some(self)
    }

    fn deserialize_unit_struct<V: Visitor<'de>>(
        self,
        _: &'static str,
        visitor: V,
    ) -> Result<V::Value, Unbounded> {
        visitor.visit_unit()
    }

    fn deserialize_newtype_struct<V: Visitor<'de>>(
        self,
        name: &'static str,
        visitor: V,
    ) -> Result<V::Value, Unbounded> {
        let allow = match name {
            mark::LIST => Some(Allow::List),
            mark::MAP => Some(Allow::Map),
            // Bytes and text: a value of the least length, nothing inside.
            mark::LEAF => return visitor.visit_unit(),
            _ => None,
        };
        visitor.visit_newtype_struct(&mut Walker {
            state: self.state,
            allow,
        })
    }

    fn deserialize_seq<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Unbounded> {
        match self.allow.take() {
            Some(Allow::List) => visitor.visit_seq(Items {
                walker: self.inner(),
                names: None,
                left: 1,
                at: 0,
            }),
            Some(Allow::Map) | None => Err(self
                .state
                .refuse("a list with no bound (binbun_bounded::Bounded)")),
        }
    }

    fn deserialize_map<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Unbounded> {
        match self.allow.take() {
            Some(Allow::Map) => visitor.visit_map(Entry {
                walker: self.inner(),
                left: 1,
            }),
            Some(Allow::List) | None => Err(self
                .state
                .refuse("a map with no bound (binbun_bounded::Map)")),
        }
    }

    fn deserialize_tuple<V: Visitor<'de>>(
        self,
        length: usize,
        visitor: V,
    ) -> Result<V::Value, Unbounded> {
        visitor.visit_seq(Items {
            walker: self.inner(),
            names: None,
            left: length,
            at: 0,
        })
    }

    fn deserialize_tuple_struct<V: Visitor<'de>>(
        self,
        _: &'static str,
        length: usize,
        visitor: V,
    ) -> Result<V::Value, Unbounded> {
        self.deserialize_tuple(length, visitor)
    }

    fn deserialize_struct<V: Visitor<'de>>(
        self,
        _: &'static str,
        fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Unbounded> {
        visitor.visit_seq(Items {
            walker: self.inner(),
            names: Some(fields),
            left: fields.len(),
            at: 0,
        })
    }

    fn deserialize_enum<V: Visitor<'de>>(
        self,
        name: &'static str,
        variants: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Unbounded> {
        if variants.is_empty() {
            return Err(self.state.refuse("an enum with no variants"));
        }
        let seen = self
            .state
            .enums
            .entry((name, variants))
            .or_insert_with(|| vec![Seen::No; variants.len()]);
        let pick = seen
            .iter()
            .position(|&seen| seen == Seen::No)
            .or_else(|| seen.iter().position(|&seen| seen == Seen::Partly))
            .unwrap_or(0);
        let before = seen.get(pick).copied().unwrap_or(Seen::Wholly);
        let variant = variants.get(pick).copied().unwrap_or_default();
        self.enter(format!("{name}::{variant}"))?;
        self.state.fresh.push(false);
        let value = visitor.visit_enum(Variant {
            walker: self.inner(),
            pick,
        });
        let inside = self.state.fresh.pop().unwrap_or(false);
        let value = value?;
        self.leave();
        if let Some(seen) = self
            .state
            .enums
            .get_mut(&(name, variants))
            .and_then(|seen| seen.get_mut(pick))
        {
            *seen = if inside { Seen::Partly } else { Seen::Wholly };
        }
        if (inside || before != Seen::Wholly)
            && let Some(fresh) = self.state.fresh.last_mut()
        {
            *fresh = true;
        }
        Ok(value)
    }

    fn is_human_readable(&self) -> bool {
        false
    }
}

/// The items of a tuple, a struct's fields, or the one item walked of a
/// bounded list.
struct Items<'a> {
    /// The walker.
    walker: Walker<'a>,
    /// The struct's field names, if a struct.
    names: Option<&'static [&'static str]>,
    /// The items left.
    left: usize,
    /// The next item's index.
    at: usize,
}

impl<'de> SeqAccess<'de> for Items<'_> {
    type Error = Unbounded;

    fn next_element_seed<S: DeserializeSeed<'de>>(
        &mut self,
        seed: S,
    ) -> Result<Option<S::Value>, Unbounded> {
        if self.left == 0 {
            return Ok(None);
        }
        self.left -= 1;
        let place = match self.names.and_then(|names| names.get(self.at)) {
            Some(name) => (*name).to_owned(),
            None => format!("{}", self.at),
        };
        self.at += 1;
        self.walker.enter(place)?;
        let value = seed.deserialize(&mut self.walker.inner())?;
        self.walker.leave();
        Ok(Some(value))
    }

    fn size_hint(&self) -> Option<usize> {
        Some(self.left)
    }
}

/// The one entry walked of a bounded map.
struct Entry<'a> {
    /// The walker.
    walker: Walker<'a>,
    /// The entries left (keys not yet given).
    left: usize,
}

impl<'de> MapAccess<'de> for Entry<'_> {
    type Error = Unbounded;

    fn next_key_seed<S: DeserializeSeed<'de>>(
        &mut self,
        seed: S,
    ) -> Result<Option<S::Value>, Unbounded> {
        if self.left == 0 {
            return Ok(None);
        }
        self.left -= 1;
        self.walker.enter("key".to_owned())?;
        let key = seed.deserialize(&mut self.walker.inner())?;
        self.walker.leave();
        Ok(Some(key))
    }

    fn next_value_seed<S: DeserializeSeed<'de>>(&mut self, seed: S) -> Result<S::Value, Unbounded> {
        self.walker.enter("value".to_owned())?;
        let value = seed.deserialize(&mut self.walker.inner())?;
        self.walker.leave();
        Ok(value)
    }

    fn size_hint(&self) -> Option<usize> {
        Some(self.left)
    }
}

/// The variant an enum is walked in.
struct Variant<'a> {
    /// The walker.
    walker: Walker<'a>,
    /// The variant's index.
    pick: usize,
}

impl<'de, 'a> EnumAccess<'de> for Variant<'a> {
    type Error = Unbounded;
    type Variant = Walker<'a>;

    fn variant_seed<S: DeserializeSeed<'de>>(
        self,
        seed: S,
    ) -> Result<(S::Value, Walker<'a>), Unbounded> {
        let index = u32::try_from(self.pick)
            .map_err(|_| self.walker.state.refuse("an enum of too many variants"))?;
        let value = seed.deserialize(U32Deserializer::<Unbounded>::new(index))?;
        Ok((value, self.walker))
    }
}

impl<'de> VariantAccess<'de> for Walker<'_> {
    type Error = Unbounded;

    fn unit_variant(self) -> Result<(), Unbounded> {
        Ok(())
    }

    fn newtype_variant_seed<S: DeserializeSeed<'de>>(
        mut self,
        seed: S,
    ) -> Result<S::Value, Unbounded> {
        seed.deserialize(&mut self)
    }

    fn tuple_variant<V: Visitor<'de>>(
        mut self,
        length: usize,
        visitor: V,
    ) -> Result<V::Value, Unbounded> {
        de::Deserializer::deserialize_tuple(&mut self, length, visitor)
    }

    fn struct_variant<V: Visitor<'de>>(
        mut self,
        fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Unbounded> {
        de::Deserializer::deserialize_struct(&mut self, "", fields, visitor)
    }
}
