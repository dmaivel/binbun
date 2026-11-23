//! The atomic lattice: scalars with a width.
//!
//! Each width is its own tree, rooted at [`Atom::Bits`] (nothing known but
//! the width); atoms of different widths are incomparable. Within a width
//! `w`, `a ≤ b` reads "every `a` is a `b`":
//!
//! ```text
//!                 Bits(w)
//!                /       \
//!           Int(w)       Float(f)        (f.width() == w)
//!          /   |   \
//!   Signed(w) Bool(w) Unsigned(w)
//!      |    \             |    \
//! Char{signed} Enum   Char{unsigned} Enum  (Char: w == 8 only)
//! ```
//!
//! - A truth value is an integer whose sign does not matter, so
//!   [`Atom::Bool`] is below [`Atom::Int`] but neither below
//!   [`Atom::Signed`] nor [`Atom::Unsigned`]: were it below both, two
//!   demands `signed ⊓ unsigned` would meet at `Bool` and print as one.
//! - C's plain `char` is a type of its own whose signedness is the
//!   target's, so [`Atom::Char`] sits below the signed or the unsigned 8-bit
//!   integer as the target says.
//! - An enumeration's values ([`Atom::Enum`]) sit below its integer, so
//!   values of one enumeration join to it, of two enumerations (or of one
//!   and any other integer) to the integer, and an enumeration is below
//!   everything its integer is below. Its id is the caller's name for it
//!   in one system: a [`Scheme`](crate::Scheme) keeps its integer
//!   ([`Atom::integer`]).
//! - Because each width is a tree, the join of two atoms is their lowest
//!   common ancestor ([`Level::Top`] across widths) and their meet is the
//!   lower one if they are ordered, else [`Level::Bottom`].
//!
//! Pointers, records and code are constructors ([`Term`](crate::Term)),
//! not atoms: a pointer meeting an integer is a type error (BinSub's
//! `int16 ⊓ ptr(α, β) = ⊥`), which the solver records as a
//! [`Conflict`](crate::Conflict) where a lower bound meets an upper bound,
//! never a panic.

/// An IEEE 754 binary floating-point format (as `binbun_semantics`'s
/// `Format`, which this crate does not depend on).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Format {
    /// binary16.
    Half,
    /// binary32.
    Single,
    /// binary64.
    Double,
    /// The x87 80-bit extended format.
    Extended,
}

impl Format {
    /// Its width in bits.
    pub const fn width(self) -> u16 {
        match self {
            Self::Half => 16,
            Self::Single => 32,
            Self::Double => 64,
            Self::Extended => 80,
        }
    }
}

/// A scalar of a width (see the module's lattice; the derived `Ord` is
/// only a total order for sorting, not the lattice's).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Atom {
    /// Nothing known but the width, in bits: the top of its width.
    Bits(u16),
    /// An integer of this many bits, signedness unknown.
    Int(u16),
    /// A signed (two's complement) integer.
    Signed(u16),
    /// An unsigned integer.
    Unsigned(u16),
    /// A truth value, 0 or 1, in this many bits.
    Bool(u16),
    /// C's plain `char` (8 bits), signed or not as the target says.
    Char {
        /// Whether `char` is signed on the target.
        signed: bool,
    },
    /// A floating-point number of a format.
    Float(Format),
    /// A value of an enumeration (a C `enum`): an integer whose values
    /// have names.
    Enum {
        /// The caller's id for the enumeration (meaningful only in its
        /// own system).
        id: u32,
        /// Its width in bits.
        width: u16,
        /// Whether its integer is signed.
        signed: bool,
    },
}

impl Atom {
    /// Its width in bits.
    pub const fn width(self) -> u16 {
        match self {
            Self::Bits(w) | Self::Int(w) | Self::Signed(w) | Self::Unsigned(w) | Self::Bool(w) => w,
            Self::Char { .. } => 8,
            Self::Float(format) => format.width(),
            Self::Enum { width, .. } => width,
        }
    }

    /// The atom with an enumeration as its integer (any other as it is).
    #[must_use]
    pub const fn integer(self) -> Self {
        match self {
            Self::Enum {
                width,
                signed: true,
                ..
            } => Self::Signed(width),
            Self::Enum {
                width,
                signed: false,
                ..
            } => Self::Unsigned(width),
            Self::Bits(_)
            | Self::Int(_)
            | Self::Signed(_)
            | Self::Unsigned(_)
            | Self::Bool(_)
            | Self::Char { .. }
            | Self::Float(_) => self,
        }
    }

    /// The atom directly above it, `None` for [`Atom::Bits`].
    const fn parent(self) -> Option<Self> {
        match self {
            Self::Bits(_) => None,
            Self::Int(w) => Some(Self::Bits(w)),
            Self::Float(format) => Some(Self::Bits(format.width())),
            Self::Signed(w) | Self::Unsigned(w) | Self::Bool(w) => Some(Self::Int(w)),
            Self::Char { signed: true } => Some(Self::Signed(8)),
            Self::Char { signed: false } => Some(Self::Unsigned(8)),
            Self::Enum { .. } => Some(self.integer()),
        }
    }

    /// Whether every `self` is an `other` (`self ≤ other`).
    pub fn is_subtype_of(self, other: Self) -> bool {
        let mut at = Some(self);
        while let Some(atom) = at {
            if atom == other {
                return true;
            }
            at = atom.parent();
        }
        false
    }

    /// The least atom above both (their lowest common ancestor), or
    /// [`Level::Top`] across widths.
    pub fn join(self, other: Self) -> Level {
        let mut at = Some(self);
        while let Some(atom) = at {
            if other.is_subtype_of(atom) {
                return Level::Atom(atom);
            }
            at = atom.parent();
        }
        Level::Top
    }

    /// The greatest atom below both, or [`Level::Bottom`] where none is.
    pub fn meet(self, other: Self) -> Level {
        if self.is_subtype_of(other) {
            Level::Atom(self)
        } else if other.is_subtype_of(self) {
            Level::Atom(other)
        } else {
            Level::Bottom
        }
    }
}

/// An element of the atomic lattice with its bounds: what a join of lower
/// bounds or a meet of upper bounds gives (the derived `Ord` only sorts).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Level {
    /// Below every atom: no atomic lower bound, or upper bounds that
    /// disagree.
    Bottom,
    /// An atom.
    Atom(Atom),
    /// Above every atom: no atomic upper bound, or lower bounds that
    /// disagree (different widths).
    Top,
}

impl Level {
    /// The least level above both.
    #[must_use]
    pub fn join(self, other: Self) -> Self {
        match (self, other) {
            (Self::Bottom, level) | (level, Self::Bottom) => level,
            (Self::Top, _) | (_, Self::Top) => Self::Top,
            (Self::Atom(a), Self::Atom(b)) => a.join(b),
        }
    }

    /// The greatest level below both.
    #[must_use]
    pub fn meet(self, other: Self) -> Self {
        match (self, other) {
            (Self::Top, level) | (level, Self::Top) => level,
            (Self::Bottom, _) | (_, Self::Bottom) => Self::Bottom,
            (Self::Atom(a), Self::Atom(b)) => a.meet(b),
        }
    }

    /// Whether `self ≤ other`.
    pub fn is_subtype_of(self, other: Self) -> bool {
        self.join(other) == other
    }
}
