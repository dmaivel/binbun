use core::fmt;

/// A fieldless enum where every variant has exactly one textual spelling.
///
/// Implement it with `#[derive(Keyword)]`, which also implements
/// [`FromStr`](core::str::FromStr) (with [`UnknownKeyword`] as the error) and
/// [`Display`](fmt::Display).
pub trait Keyword: Sized + 'static {
    /// Every variant, in declaration order.
    const ALL: &'static [Self];

    /// The variant's spelling.
    fn as_str(&self) -> &'static str;

    /// The variant spelled exactly `text`, if any. Matching is case-sensitive.
    fn from_keyword(text: &str) -> Option<Self>;

    /// The variant spelled `text` ignoring ASCII case, if exactly one matches.
    fn from_keyword_ignore_ascii_case(text: &str) -> Option<Self>
    where
        Self: Copy,
    {
        let mut matches = Self::ALL
            .iter()
            .filter(|variant| variant.as_str().eq_ignore_ascii_case(text));
        match (matches.next(), matches.next()) {
            (Some(&variant), None) => Some(variant),
            _ => None,
        }
    }
}

/// Text that is not the spelling of any variant of a [`Keyword`] enum.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnknownKeyword {
    kind: &'static str,
}

impl UnknownKeyword {
    /// An error for the keyword enum named `kind`.
    pub const fn new(kind: &'static str) -> Self {
        Self { kind }
    }

    /// Name of the keyword enum that rejected the text.
    pub const fn kind(&self) -> &'static str {
        self.kind
    }
}

impl fmt::Display for UnknownKeyword {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "not a {} keyword", self.kind)
    }
}

impl core::error::Error for UnknownKeyword {}

#[cfg(test)]
mod tests {
    use crate::core::{Keyword, UnknownKeyword};
    use alloc::string::ToString;

    #[derive(Clone, Copy, PartialEq, Eq, Debug, Keyword)]
    #[keyword(rename_all = "SCREAMING_SNAKE_CASE")]
    enum Access {
        #[keyword("r")]
        Read,
        ReadWrite,
        X87Pop,
    }

    #[test]
    fn explicit_spelling_overrides_rename_all() {
        assert_eq!(Access::Read.as_str(), "r");
        assert_eq!(Access::ReadWrite.as_str(), "READ_WRITE");
        assert_eq!(Access::X87Pop.to_string(), "X87_POP");
    }

    #[test]
    fn parses_every_spelling_back_to_its_variant() {
        for &variant in Access::ALL {
            assert_eq!(variant.as_str().parse::<Access>(), Ok(variant));
        }
        assert_eq!(Access::COUNT, 3);
    }

    #[test]
    fn matching_is_exact_and_case_sensitive() {
        assert_eq!("R".parse::<Access>(), Err(UnknownKeyword::new("Access")));
        assert_eq!(Access::from_keyword("read_write"), None);
        assert_eq!(Access::from_keyword("r "), None);
    }

    #[test]
    fn case_insensitive_lookup_rejects_ambiguity() {
        #[derive(Clone, Copy, PartialEq, Eq, Debug, Keyword)]
        enum Cased {
            #[keyword("ab")]
            Lower,
            #[keyword("AB")]
            Upper,
            #[keyword("cd")]
            Unique,
        }
        assert_eq!(
            Access::from_keyword_ignore_ascii_case("read_WRITE"),
            Some(Access::ReadWrite)
        );
        assert_eq!(
            Cased::from_keyword_ignore_ascii_case("CD"),
            Some(Cased::Unique)
        );
        assert_eq!(Cased::from_keyword_ignore_ascii_case("Ab"), None);
    }
}
