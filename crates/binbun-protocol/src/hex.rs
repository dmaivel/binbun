//! Addresses on the wire: hexadecimal strings (`"0x401000"`), since a
//! 64-bit address does not fit a JSON number for clients outside Rust.
//! Read back from such a string or from a JSON number.
//! `#[serde(with = "crate::hex")]` for a `u64`,
//! `crate::hex::option` for an `Option<u64>`, `crate::hex::list` for a
//! `Vec<u64>`.

use std::fmt;

use serde::de::{self, Visitor};
use serde::ser::SerializeSeq;
use serde::{Deserializer, Serializer};

/// `value` as `"0x…"`.
///
/// # Errors
///
/// As the serializer's.
pub fn serialize<S: Serializer>(value: &u64, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.collect_str(&format_args!("{value:#x}"))
}

/// An address from `"0x…"` (or decimal digits) or a number.
///
/// # Errors
///
/// It is neither.
pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
    deserializer.deserialize_any(Address)
}

/// The address `text` writes: `0x…` hexadecimal, else decimal.
pub fn parse(text: &str) -> Option<u64> {
    match text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        Some(hex) => u64::from_str_radix(hex, 16).ok(),
        None => text.parse().ok(),
    }
}

/// Reads an address.
struct Address;

impl Visitor<'_> for Address {
    type Value = u64;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("an address: \"0x…\" or a number")
    }

    fn visit_u64<E: de::Error>(self, value: u64) -> Result<u64, E> {
        Ok(value)
    }

    fn visit_i64<E: de::Error>(self, value: i64) -> Result<u64, E> {
        u64::try_from(value).map_err(|_| E::custom(format!("{value} is not an address")))
    }

    fn visit_str<E: de::Error>(self, text: &str) -> Result<u64, E> {
        parse(text).ok_or_else(|| E::custom(format!("{text:?} is not an address")))
    }
}

/// An `Option<u64>` as an address or `null`.
pub mod option {
    use serde::{Deserialize, Deserializer, Serializer};

    /// `value` as `"0x…"` or `null`.
    ///
    /// # Errors
    ///
    /// As the serializer's.
    pub fn serialize<S: Serializer>(value: &Option<u64>, serializer: S) -> Result<S::Ok, S::Error> {
        match value {
            Some(value) => super::serialize(value, serializer),
            None => serializer.serialize_none(),
        }
    }

    /// An address or `null`.
    ///
    /// # Errors
    ///
    /// It is neither.
    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<u64>, D::Error> {
        #[derive(Deserialize)]
        struct Wrapped(#[serde(with = "super")] u64);
        Ok(Option::<Wrapped>::deserialize(deserializer)?.map(|Wrapped(value)| value))
    }
}

/// A `Vec<u64>` as a list of addresses.
pub mod list {
    use serde::{Deserialize, Deserializer, Serializer};

    use super::SerializeSeq;

    /// `values` as `["0x…", …]`.
    ///
    /// # Errors
    ///
    /// As the serializer's.
    pub fn serialize<S: Serializer>(values: &[u64], serializer: S) -> Result<S::Ok, S::Error> {
        let mut seq = serializer.serialize_seq(Some(values.len()))?;
        for value in values {
            seq.serialize_element(&format!("{value:#x}"))?;
        }
        seq.end()
    }

    /// A list of addresses.
    ///
    /// # Errors
    ///
    /// An element is not one.
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u64>, D::Error> {
        #[derive(Deserialize)]
        struct Wrapped(#[serde(with = "super")] u64);
        Ok(Vec::<Wrapped>::deserialize(deserializer)?
            .into_iter()
            .map(|Wrapped(value)| value)
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use serde::{Deserialize, Serialize};

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct At {
        #[serde(with = "super")]
        address: u64,
        #[serde(with = "super::option")]
        end: Option<u64>,
        #[serde(with = "super::list")]
        targets: Vec<u64>,
    }

    #[test]
    fn addresses_cross_as_hex_strings_and_read_back_from_numbers_too() {
        let at = At {
            address: u64::MAX,
            end: None,
            targets: vec![0x40_1000, 0],
        };
        let text = serde_json::to_string(&at).unwrap();
        assert_eq!(
            text,
            r#"{"address":"0xffffffffffffffff","end":null,"targets":["0x401000","0x0"]}"#
        );
        assert_eq!(serde_json::from_str::<At>(&text).unwrap(), at);
        let numbers: At =
            serde_json::from_str(r#"{"address":4198400,"end":"16","targets":[1]}"#).unwrap();
        assert_eq!(
            numbers,
            At {
                address: 0x40_1000,
                end: Some(16),
                targets: vec![1],
            }
        );
        assert!(serde_json::from_str::<At>(r#"{"address":-1,"end":null,"targets":[]}"#).is_err());
        assert!(
            serde_json::from_str::<At>(r#"{"address":"0xg","end":null,"targets":[]}"#).is_err()
        );
    }
}
