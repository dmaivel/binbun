//! L2's types: binbun types, not C's.
//!
//! - Types live in a [`Types`] table and are named by [`TypeId`]s.
//!   Structural types are interned: [`Types::intern`] gives equal types the
//!   same id, so ids compare like the types they name. Structs and unions
//!   are nominal: each one interned is a new type, whose fields can be
//!   filled in afterwards ([`Types::aggregate_mut`]), so a struct can hold
//!   a pointer to itself.
//! - Widths are in bits and exact (`Int(32)` is 32 bits); pointers are the
//!   table's pointer width.
//! - An enumeration ([`Type::Enum`]) is an integer whose values have
//!   names: the printer writes a constant of it by name where the names
//!   say the value exactly; everywhere else it is its integer.
//! - A type says what bits mean (signed, a pointer, a float), never how
//!   they are computed: every operation carries its own width and
//!   signedness, so passes can change a type without changing what the
//!   function does.
//! - How sure a type is is the [`Evidence`] next to it (on a
//!   [`Variable`](crate::ir::Variable)), so later evidence can replace a
//!   default.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use binbun_semantics::bits::MAX_WIDTH;
use binbun_semantics::ir::Format;

/// A type of a [`Types`] table.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TypeId(pub u32);

/// A binbun type.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Type {
    /// Nothing known but the width, in bits.
    Bits(u16),
    /// A signed (two's complement) integer of this many bits.
    Int(u16),
    /// An unsigned integer of this many bits.
    UInt(u16),
    /// C's plain `char` (8 bits): an integer whose signedness is the
    /// target's, a type of its own in C (neither `signed char` nor
    /// `unsigned char`), as declarations state it (`const char *`).
    Char {
        /// Whether `char` is signed on the target.
        signed: bool,
    },
    /// A truth value, 0 or 1, in this many bits: 1 for a condition, 8 for
    /// C's `_Bool` in memory.
    Bool(u16),
    /// An IEEE 754 binary floating-point number.
    Float(Format),
    /// A pointer to data of a type (`None`: nothing known about what it
    /// points to, C's `void *`).
    Pointer(Option<TypeId>),
    /// A pointer to code with a signature.
    Code(Signature),
    /// Fields at byte offsets.
    Struct(Aggregate),
    /// Fields all at offset 0.
    Union(Aggregate),
    /// Elements one after the other.
    Array {
        /// The element type (with a width).
        element: TypeId,
        /// How many (`None`: unbounded, as a C flexible array member).
        length: Option<u64>,
    },
    /// Lanes side by side in one value, lane 0 lowest.
    Vector {
        /// How many lanes.
        lanes: u16,
        /// The lane type: a scalar (bits, integer, boolean, float or
        /// pointer).
        element: TypeId,
    },
    /// An integer whose values have names: a C enumeration, or a set of
    /// flags combined with `|`.
    Enum(Enumeration),
}

/// What code takes and gives.
#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Signature {
    /// The parameters' types, in order (each fits a value).
    pub parameters: Vec<TypeId>,
    /// The return value's type (fits a value), or `None` for none.
    pub returns: Option<TypeId>,
    /// Whether more arguments may follow the parameters (C's `...`).
    pub variadic: bool,
}

/// A struct's or union's layout.
#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Aggregate {
    /// Its name, if known.
    pub name: Option<String>,
    /// Its size in bytes, padding included.
    pub size: u64,
    /// The fields, each within the size; in a union, all at offset 0.
    pub fields: Vec<Field>,
}

/// An integer type whose values have names ([`Type::Enum`]).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Enumeration {
    /// Its tag, if it has one.
    pub name: Option<String>,
    /// Its width in bits (1 to 64).
    pub width: u16,
    /// Whether it is signed.
    pub signed: bool,
    /// Whether its values are flags combined with `|` (as its declaration
    /// says; never guessed from the values).
    pub flags: bool,
    /// Whether its constants are macros in C's headers (`#define O_RDWR
    /// 02`), not enumeration constants: C names them as macros, and a
    /// value of it has the integer type the headers give.
    pub macros: bool,
    /// Its constants in declaration order: each name, with its value as
    /// `width` bits (above them 0).
    pub constants: Vec<(String, u128)>,
}

/// A value of an [`Enumeration`] by its constants' names
/// ([`Enumeration::named`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Named<'a> {
    /// The constants, in declaration order: the one equal to the value,
    /// or the flags it holds.
    pub names: Vec<&'a str>,
    /// The bits of the value no name stands for (0 for all of them).
    pub rest: u128,
}

impl Enumeration {
    /// The bits of its width (all ones).
    fn mask(&self) -> u128 {
        u128::MAX >> (128 - u32::from(self.width.clamp(1, 128)))
    }

    /// `bits` (of its width) by name: the constant equal to it; for flags
    /// whose value no constant equals, the constants whose bits it all
    /// holds, widest first and none overlapping another taken, with the
    /// bits left over. `None` where no constant names any of it.
    pub fn named(&self, bits: u128) -> Option<Named<'_>> {
        let bits = bits & self.mask();
        if let Some((name, _)) = self.constants.iter().find(|&&(_, value)| value == bits) {
            return Some(Named {
                names: vec![name.as_str()],
                rest: 0,
            });
        }
        if !self.flags {
            return None;
        }
        let mut candidates: Vec<&(String, u128)> = self
            .constants
            .iter()
            .filter(|&&(_, value)| value != 0 && value & bits == value)
            .collect();
        // Widest first: a mask named for several flags takes them together.
        candidates.sort_by_key(|&&(_, value)| core::cmp::Reverse(value.count_ones()));
        let mut rest = bits;
        let mut taken: Vec<&(String, u128)> = Vec::new();
        for candidate in candidates {
            if candidate.1 & rest == candidate.1 {
                rest &= !candidate.1;
                taken.push(candidate);
            }
        }
        if taken.is_empty() {
            return None;
        }
        // In declaration order.
        let names = self
            .constants
            .iter()
            .filter(|constant| taken.iter().any(|&t| core::ptr::eq(t, *constant)))
            .map(|(name, _)| name.as_str())
            .collect();
        Some(Named { names, rest })
    }

    /// Constant `value` as a number: its bits read as its signedness says.
    pub fn number(&self, value: u128) -> i128 {
        let width = u32::from(self.width.clamp(1, 128));
        let shift = 128 - width;
        if self.signed {
            (value << shift).cast_signed() >> shift
        } else {
            value.cast_signed()
        }
    }
}

/// A field of an [`Aggregate`].
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Field {
    /// Its first byte.
    pub offset: u64,
    /// Its type (with a width).
    pub ty: TypeId,
    /// Its name, if known.
    pub name: Option<String>,
}

/// Why a variable has its type, weakest first: a pass may replace a type
/// with one of at least the same evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Evidence {
    /// Nothing but the width: what lowering chose for a value it knows
    /// only the width of (the printer shows the natural C type for its use,
    /// as `int` for arithmetic).
    Default,
    /// Inferred from how the code uses it (operations, accesses,
    /// callees' prototypes).
    Deduced,
    /// Stated by a declaration to be a pointer, what it points to not
    /// described (a mangling's pointer to a class, whose layout it does
    /// not give): a pointer whose target is deduced as a
    /// [`Deduced`](Self::Deduced) pointer's is.
    DeclaredPointer,
    /// Stated by a declaration: a prototype from the type library, debug
    /// information, the user.
    Declared,
}

/// A table of types.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Types {
    pointer_width: u16,
    entries: Vec<Type>,
    /// The id of each structural type.
    interned: BTreeMap<Type, TypeId>,
}

impl Types {
    /// An empty table for an architecture whose pointers are
    /// `pointer_width` bits.
    pub fn new(pointer_width: u16) -> Self {
        Self {
            pointer_width,
            entries: Vec::new(),
            interned: BTreeMap::new(),
        }
    }

    /// The width of pointers (data and code), in bits.
    pub const fn pointer_width(&self) -> u16 {
        self.pointer_width
    }

    /// The id of `ty`: the same as before for a structural type already in
    /// the table; a new one for a new type, and for every struct and union.
    pub fn intern(&mut self, ty: Type) -> TypeId {
        let nominal = matches!(ty, Type::Struct(_) | Type::Union(_));
        if !nominal && let Some(&id) = self.interned.get(&ty) {
            return id;
        }
        let id = TypeId(u32::try_from(self.entries.len()).unwrap_or(u32::MAX));
        if !nominal {
            self.interned.insert(ty.clone(), id);
        }
        self.entries.push(ty);
        id
    }

    /// Type `id`.
    pub fn get(&self, id: TypeId) -> Option<&Type> {
        self.entries.get(id.0 as usize)
    }

    /// The layout of struct or union `id`, to change (`None` for any other
    /// type).
    pub fn aggregate_mut(&mut self, id: TypeId) -> Option<&mut Aggregate> {
        match self.entries.get_mut(id.0 as usize)? {
            Type::Struct(aggregate) | Type::Union(aggregate) => Some(aggregate),
            Type::Bits(_)
            | Type::Int(_)
            | Type::UInt(_)
            | Type::Char { .. }
            | Type::Bool(_)
            | Type::Float(_)
            | Type::Pointer(_)
            | Type::Code(_)
            | Type::Array { .. }
            | Type::Vector { .. }
            | Type::Enum(_) => None,
        }
    }

    /// How many types there are; ids run from 0 to this.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the table has no types.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The types with their ids, in id order.
    pub fn iter(&self) -> impl Iterator<Item = (TypeId, &Type)> {
        (0..)
            .zip(&self.entries)
            .map(|(index, ty)| (TypeId(index), ty))
    }

    /// The width of type `id` in bits, if it has one (not an unbounded
    /// array, nor a type missing from the table, nor one whose elements
    /// lead back to it).
    pub fn width(&self, id: TypeId) -> Option<u64> {
        // Arrays and vectors multiply their element's width: follow the
        // elements (at most once per type: a malformed table may have
        // cycles), then multiply.
        let mut count: u64 = 1;
        let mut id = id;
        for _ in 0..=self.entries.len() {
            let base = match self.get(id)? {
                &(Type::Bits(width) | Type::Int(width) | Type::UInt(width) | Type::Bool(width)) => {
                    u64::from(width)
                }
                Type::Char { .. } => 8,
                Type::Enum(enumeration) => u64::from(enumeration.width),
                Type::Float(format) => u64::from(format.width()),
                Type::Pointer(_) | Type::Code(_) => u64::from(self.pointer_width),
                Type::Struct(aggregate) | Type::Union(aggregate) => {
                    aggregate.size.checked_mul(8)?
                }
                &Type::Array { element, length } => {
                    count = count.checked_mul(length?)?;
                    id = element;
                    continue;
                }
                &Type::Vector { lanes, element } => {
                    count = count.checked_mul(u64::from(lanes))?;
                    id = element;
                    continue;
                }
            };
            return base.checked_mul(count);
        }
        None
    }

    /// The width of a value of type `id`: its width, if a value can hold
    /// it (1 to [`MAX_WIDTH`] bits).
    pub fn value_width(&self, id: TypeId) -> Option<u16> {
        let width = u16::try_from(self.width(id)?).ok()?;
        (1..=MAX_WIDTH).contains(&width).then_some(width)
    }

    /// The signature of code pointer type `id`.
    pub fn signature(&self, id: TypeId) -> Option<&Signature> {
        match self.get(id)? {
            Type::Code(signature) => Some(signature),
            Type::Bits(_)
            | Type::Int(_)
            | Type::UInt(_)
            | Type::Char { .. }
            | Type::Bool(_)
            | Type::Float(_)
            | Type::Pointer(_)
            | Type::Struct(_)
            | Type::Union(_)
            | Type::Array { .. }
            | Type::Vector { .. }
            | Type::Enum(_) => None,
        }
    }
}
