//! Semantic versions (semver 2.0.0) as binbun's releases are numbered:
//! `MAJOR.MINOR.PATCH`, an optional pre-release (`-rc.1`) and build
//! metadata (`+abc`, ignored), compared by semver's precedence: a
//! pre-release comes before its release, its identifiers compared one by
//! one (numbers as numbers, below words), the shorter list first when one
//! is the other's start.

use std::cmp::Ordering;
use std::fmt;
use std::str::FromStr;

/// One version.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Version {
    /// The major number.
    pub major: u64,
    /// The minor number.
    pub minor: u64,
    /// The patch number.
    pub patch: u64,
    /// The pre-release identifiers (empty for a release).
    pub pre: Vec<Identifier>,
}

/// A pre-release identifier.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Identifier {
    /// Digits only: compared as a number, below any word.
    Number(u64),
    /// Anything else: compared as ASCII text.
    Word(String),
}

/// Why a text is no version.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Invalid(pub String);

impl fmt::Display for Invalid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "not a version: {:?}", self.0)
    }
}

impl std::error::Error for Invalid {}

impl FromStr for Version {
    type Err = Invalid;

    /// `1.2.3`, `1.2.3-rc.1`, `1.2.3+build` (a leading `v` allowed).
    fn from_str(text: &str) -> Result<Self, Invalid> {
        let invalid = || Invalid(text.to_owned());
        let bare = text.strip_prefix('v').unwrap_or(text);
        let (rest, build) = match bare.split_once('+') {
            Some((rest, build)) => (rest, Some(build)),
            None => (bare, None),
        };
        if build.is_some_and(|build| build.split('.').any(|part| !is_identifier(part))) {
            return Err(invalid());
        }
        let (core, pre) = match rest.split_once('-') {
            Some((core, pre)) => (core, Some(pre)),
            None => (rest, None),
        };
        let mut numbers = core.split('.').map(number);
        let (Some(Some(major)), Some(Some(minor)), Some(Some(patch)), None) = (
            numbers.next(),
            numbers.next(),
            numbers.next(),
            numbers.next(),
        ) else {
            return Err(invalid());
        };
        let pre = match pre {
            None => Vec::new(),
            Some(pre) => pre
                .split('.')
                .map(|part| {
                    if !is_identifier(part) {
                        None
                    } else if part.bytes().all(|b| b.is_ascii_digit()) {
                        number(part).map(Identifier::Number)
                    } else {
                        Some(Identifier::Word(part.to_owned()))
                    }
                })
                .collect::<Option<_>>()
                .ok_or_else(invalid)?,
        };
        Ok(Self {
            major,
            minor,
            patch,
            pre,
        })
    }
}

/// A numeric identifier: digits, no leading zero.
fn number(text: &str) -> Option<u64> {
    if text.is_empty()
        || !text.bytes().all(|b| b.is_ascii_digit())
        || (text.len() > 1 && text.starts_with('0'))
    {
        return None;
    }
    text.parse().ok()
}

/// A non-empty run of `[0-9A-Za-z-]`.
fn is_identifier(text: &str) -> bool {
    !text.is_empty() && text.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> Ordering {
        (self.major, self.minor, self.patch)
            .cmp(&(other.major, other.minor, other.patch))
            .then_with(|| match (self.pre.is_empty(), other.pre.is_empty()) {
                (true, true) => Ordering::Equal,
                // A release after its pre-releases.
                (true, false) => Ordering::Greater,
                (false, true) => Ordering::Less,
                (false, false) => self.pre.cmp(&other.pre),
            })
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)?;
        for (i, part) in self.pre.iter().enumerate() {
            f.write_str(if i == 0 { "-" } else { "." })?;
            match part {
                Identifier::Number(n) => write!(f, "{n}")?,
                Identifier::Word(word) => f.write_str(word)?,
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(text: &str) -> Version {
        text.parse().unwrap()
    }

    #[test]
    fn semver_precedence_orders_releases_and_pre_releases() {
        // semver.org §11's example, in order.
        let ordered = [
            "1.0.0-alpha",
            "1.0.0-alpha.1",
            "1.0.0-alpha.beta",
            "1.0.0-beta",
            "1.0.0-beta.2",
            "1.0.0-beta.11",
            "1.0.0-rc.1",
            "1.0.0",
            "1.0.1",
            "1.1.0",
            "1.10.0",
            "2.0.0",
        ];
        for pair in ordered.windows(2) {
            let [older, newer] = pair else { continue };
            assert!(v(older) < v(newer), "{older} < {newer}");
            assert!(v(newer) > v(older), "{newer} > {older}");
        }
    }

    #[test]
    fn equal_versions_ignore_build_metadata_and_a_leading_v() {
        assert_eq!(v("0.2.0"), v("0.2.0+abc.5"));
        assert_eq!(v("v0.2.0").cmp(&v("0.2.0")), Ordering::Equal);
        assert_eq!(v("0.2.0-rc.1+x").to_string(), "0.2.0-rc.1");
        assert_eq!(v("10.20.30").to_string(), "10.20.30");
    }

    #[test]
    fn malformed_versions_are_refused() {
        for bad in [
            "",
            "1",
            "1.2",
            "1.2.3.4",
            "01.2.3",
            "1.2.x",
            "1.2.3-",
            "1.2.3-rc..1",
            "1.2.3-01",
            "1.2.3+",
            "1.2.3-rc_1",
            " 1.2.3",
            "-1.2.3",
            "1.2.99999999999999999999",
        ] {
            assert!(bad.parse::<Version>().is_err(), "{bad:?}");
        }
    }
}
