//! One type per global object of the image's data, over the whole
//! program (each global an abstract location of the solver, as a stack
//! slot is; the user's types and debug information above all): the
//! program's table of global types ([`Globals`]), which every function's
//! lowering reads, so every function declares and accesses a global as
//! the same type.
//!
//! - **Evidence** ([`Seen`]): each function's solve in the whole-program
//!   sweep says what its code shows of each global object it reaches
//!   (a named object: a data symbol with a size, an import's slot; or data
//!   no object names, at the address accessed): its reads and writes of
//!   the whole object as one value, the type its solve rounds them to (a
//!   pointer to a struct of the table where the values are one), with
//!   that type's strongest evidence and how many there are; and the
//!   fields its other accesses show (at constant offsets, through
//!   pointers into it, and where a pointer into it is passed to a
//!   declared `T *` parameter, `T` there at Declared strength), as a
//!   struct's fields are found ([`Layout`]), with how many accesses of
//!   each width.
//! - **The join** ([`Globals::settle`]), strongest source first:
//!   1. the user's type, then debug information's
//!      ([`Prototypes::global`]): the declared type, whatever the code
//!      shows;
//!   2. the struct the program's table has for the object (a function
//!      found it a struct, or one with others: [`Structs`]), where the
//!      object starts it and is its size (or `n` of an array's element);
//!   3. its whole reads and writes: of the width read and written most
//!      (data no object names; a named object's is its size), the type
//!      with the strongest evidence, then the more informative (a type
//!      over untyped bits, a pointer with a target over one without),
//!      then the one most functions show (then the first in the sweep);
//!      a pointer to nothing known is evidence against no pointer to a
//!      target a function's solve states (a scalar, code, a declared or
//!      other type C has no field type for): it says nothing of the
//!      target, so their join is the latter.
//!      A function whose values point to an array of pointers to a
//!      struct (indexed or strided pointer-wide elements only) shows a
//!      pointer to pointers to it ([`FieldType::Pointers`]), which
//!      refines one to as many untyped bits as a pointer has; where the
//!      other functions' elements point to one (united) struct, one that
//!      reads its elements' objects only at offsets that struct's fields
//!      hold (no struct of its own) shows the same ([`elements_read`]).
//!      A function whose values point to an array of pointers to a scalar
//!      or to nothing known (its solve's type, `char **`; read and written
//!      only as pointer-wide elements through an index or a stride of one
//!      element, none of them a typed scalar) shows a pointer to such
//!      pointers ([`FieldType::ScalarPointers`]), which, as an array's
//!      pointers to a struct do, refines a pointer to as many untyped bits
//!      as a pointer has, and a pointer to another known type (what a
//!      function reading one element without an index shows of it).
//!      The structs the values of one pointer global point to are one
//!      type ([`Structs`]' union: one size, overlapping fields alike), as
//!      two pointers met at one field are;
//!   4. else, for a named object only reached in parts, an array of the
//!      elements most of its accesses read and write (a width the object
//!      is a whole number of), typed as the strongest of its fields that
//!      wide (as 3), else untyped bits.
//!
//!   A global none of these types has no entry: its accesses keep the
//!   function's own lowering (bytes at its address).
//! - **Why** ([`GlobalType::clues`]): each function's evidence, kept for
//!   the reasons a type was chosen and the conflicts it overrode
//!   ([`GlobalType::conflicts`]: evidence of another type at the same
//!   place).
//!
//! Types change no value: the join only decides how C spells what the
//! machine code reads and writes, so soundness is not at stake.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::cmp::Reverse;

use binbun_ast::types::{Type, TypeId, Types};
use binbun_typeinfer::Strength;

use super::round::portable;
use super::strength;
use super::structs::{Field, FieldType, Layout, StructId, Structs, reads};
use crate::data::Data;
use crate::lower::{Interface, MAX_SCALAR, scalar_code, stated_code_type};
use crate::prototype::Prototypes;

/// The largest named object (in bytes) that is a variable, as lowering's.
const MAX_OBJECT: u64 = 1 << 32;

/// What one function's solve shows of one global object (see the
/// [module](self)).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Seen {
    /// Its reads and writes of the whole object (of data no object
    /// names: at its address) as one value: the field they make at offset
    /// 0, and how many there are.
    pub whole: Option<(Field, usize)>,
    /// The functions whose addresses its whole writes store (whose
    /// address reaches the object's value in its solve), by entry: their
    /// code types are the join's, from the program's final interfaces.
    pub functions: Vec<u64>,
    /// The fields its other accesses show, by offset from the object's
    /// start (an array's element where they step through it).
    pub parts: Layout,
    /// How many of those other accesses there are of each width (in
    /// bits).
    pub widths: BTreeMap<u16, usize>,
    /// The structs the pointers held in an array of pointers its whole
    /// values point to (`T **`, its elements) point to the start of: the
    /// elements of one array are one type.
    pub elements: Vec<StructId>,
    /// The fields its reads through the pointers held in such an array
    /// show of what they point to (by offset from where they point),
    /// where that is no struct: the only accesses of their objects, at
    /// one offset each.
    pub element_reads: Layout,
}

/// How a global's type is shaped ([`GlobalType::shape`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Shape {
    /// The user's or debug information's type
    /// ([`Prototypes::global`]).
    Declared,
    /// One value: a scalar, a pointer (to a struct of the table, to a
    /// scalar or to nothing known) or code.
    Value(FieldType),
    /// An array of values.
    Array {
        /// Its element.
        element: FieldType,
        /// How many there are.
        length: u64,
    },
    /// A struct of the program's table.
    Struct(StructId),
    /// An array of structs of the program's table.
    Structs {
        /// Its element.
        element: StructId,
        /// How many there are.
        length: u64,
    },
}

/// Where a global's type comes from, strongest first.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum GlobalSource {
    /// The user's type.
    User,
    /// Debug information.
    Debug,
    /// The program's table of synthesised structs.
    Table,
    /// The functions' accesses.
    Accesses,
}

/// One function's evidence about a global ([`GlobalType::clues`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GlobalClue {
    /// The entry of the function that shows it.
    pub function: u64,
    /// Its offset from the object's start, in bytes.
    pub offset: u64,
    /// The field it shows there: width, type and strongest evidence.
    pub field: Field,
    /// How many reads and writes of the whole object it stands for (0: a
    /// part of it).
    pub whole: usize,
}

/// The one type of a global object over the program ([`Globals::get`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GlobalType {
    /// The object's first byte.
    pub start: u64,
    /// Its size in bytes.
    pub size: u64,
    /// Whether it is a named object (a data symbol with a size, an
    /// import's slot), else data no object names, as wide as its type.
    pub named: bool,
    /// Its type.
    pub shape: Shape,
    /// Where the type comes from.
    pub source: GlobalSource,
    /// The strongest evidence of the type chosen (of an array's element;
    /// a declared type's above all).
    pub strength: Strength,
    /// The evidence of every function reaching it, in the sweep's order.
    pub clues: Vec<GlobalClue>,
    /// Evidence of another type at the same place that the type
    /// overrides.
    pub conflicts: usize,
}

impl GlobalType {
    /// Its type interned in `types` (the table's structs once per table:
    /// `interned`); `None` for a declared one (the declaration's,
    /// [`Prototypes::global`]).
    pub(crate) fn intern(
        &self,
        structs: &Structs,
        types: &mut Types,
        interned: &mut BTreeMap<StructId, TypeId>,
    ) -> Option<TypeId> {
        Some(match &self.shape {
            Shape::Declared => return None,
            Shape::Value(ty) => structs.field_type(ty, types, interned),
            Shape::Array { element, length } => {
                let element = structs.field_type(element, types, interned);
                types.intern(Type::Array {
                    element,
                    length: Some(*length),
                })
            }
            &Shape::Struct(id) => structs.intern(id, types, interned)?,
            &Shape::Structs { element, length } => {
                let element = structs.intern(element, types, interned)?;
                types.intern(Type::Array {
                    element,
                    length: Some(length),
                })
            }
        })
    }

    /// Its type laid out in a table of its own (pointers `pointer_width`
    /// bits wide), with the structs it holds or points to; `None` for a
    /// declared one.
    pub fn table(&self, structs: &Structs, pointer_width: u16) -> Option<(Types, TypeId)> {
        let mut types = Types::new(pointer_width);
        let ty = self.intern(structs, &mut types, &mut BTreeMap::new())?;
        Some((types, ty))
    }

    /// What kind of type it is, for counting.
    pub fn kind(&self) -> Kind {
        match &self.shape {
            Shape::Declared => Kind::Declared,
            Shape::Value(FieldType::Scalar(_)) => Kind::Scalar,
            Shape::Value(
                FieldType::Pointer(_)
                | FieldType::Opaque
                | FieldType::Struct(_)
                | FieldType::Pointers(_)
                | FieldType::ScalarPointers(_)
                | FieldType::Code { .. },
            ) => Kind::Pointer,
            Shape::Array { .. } => Kind::Array,
            Shape::Struct(_) | Shape::Structs { .. } => Kind::Struct,
        }
    }
}

/// What kind of type a global has ([`GlobalType::kind`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Kind {
    /// Declared by the user or debug information.
    Declared,
    /// A scalar.
    Scalar,
    /// A pointer (to data or code).
    Pointer,
    /// An array of scalars or pointers.
    Array,
    /// A struct of the table, or an array of them.
    Struct,
}

/// The program's global types ([module](self)).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Globals {
    /// What each function showed of each global, by the global's first
    /// byte, in the sweep's order.
    seen: BTreeMap<u64, Vec<(u64, Seen)>>,
    /// The joined types, by the global's first byte.
    types: BTreeMap<u64, GlobalType>,
}

impl Globals {
    /// No globals.
    pub const fn new() -> Self {
        Self {
            seen: BTreeMap::new(),
            types: BTreeMap::new(),
        }
    }

    /// Adds what the function at `entry` shows of the globals it reaches,
    /// by their first bytes.
    pub fn add(&mut self, entry: u64, seen: Vec<(u64, Seen)>) {
        for (start, seen) in seen {
            self.seen.entry(start).or_default().push((entry, seen));
        }
    }

    /// Joins what the functions showed into one type per global (the
    /// [module](self)'s rules), the image's objects from `data`, declared
    /// types from `prototypes` (interned in tables of pointers
    /// `pointer_width` bits wide), the code types of the functions stored
    /// in them from `prototypes` and the program's final `interfaces`;
    /// unites in `structs` the structs one pointer global's values point
    /// to, and (whatever their sizes: [`Structs::unite_one_type`]) those
    /// the elements of the array of pointers they point to point to.
    /// After the sweep and the interfaces, before the user's versions of
    /// structs are taken.
    pub fn settle(
        &mut self,
        structs: &mut Structs,
        data: &dyn Data,
        prototypes: &dyn Prototypes,
        interfaces: &BTreeMap<u64, Interface>,
        pointer_width: u16,
    ) {
        let mut scratch = Types::new(pointer_width);
        let mut held: BTreeMap<u64, StructId> = BTreeMap::new();
        for (&start, seen) in &self.seen {
            let mut elements: Vec<StructId> = seen
                .iter()
                .flat_map(|(_, seen)| seen.elements.iter().copied())
                .map(|id| structs.find(id))
                .collect();
            elements.sort_unstable_by_key(|&id| structs.rank(id));
            elements.dedup();
            structs.unite_one_type(&elements);
            if let Some(&first) = elements.first() {
                held.insert(start, structs.find(first));
            }
        }
        let mut codes: BTreeMap<u64, Option<FieldType>> = BTreeMap::new();
        for (_, seen) in self.seen.values().flatten() {
            for &function in &seen.functions {
                codes.entry(function).or_insert_with(|| {
                    let ty = stated_code_type(prototypes, interfaces, function, &mut scratch)?;
                    scalar_code(&scratch, ty)
                        .then(|| portable(&scratch, ty))
                        .flatten()
                });
            }
        }
        let code = |function: u64| codes.get(&function).cloned().flatten();
        let mut types = BTreeMap::new();
        for (&start, seen) in &self.seen {
            let read = held
                .get(&start)
                .and_then(|&id| elements_read(seen, structs, id));
            let seen = read.as_deref().unwrap_or(seen);
            if let Some(ty) = settle(start, seen, structs, data, prototypes, &code, pointer_width) {
                types.insert(start, ty);
            }
        }
        self.types = types;
    }

    /// The type of the global object starting at `start`, if one is
    /// settled.
    pub fn get(&self, start: u64) -> Option<&GlobalType> {
        self.types.get(&start)
    }

    /// The settled types, by the global's first byte.
    pub fn iter(&self) -> impl Iterator<Item = (u64, &GlobalType)> {
        self.types.iter().map(|(&start, ty)| (start, ty))
    }

    /// How many globals have a type.
    pub fn len(&self) -> usize {
        self.types.len()
    }

    /// Whether none has.
    pub fn is_empty(&self) -> bool {
        self.types.is_empty()
    }

    /// How many globals have each kind of type.
    pub fn kinds(&self) -> BTreeMap<Kind, usize> {
        let mut kinds = BTreeMap::new();
        for ty in self.types.values() {
            *kinds.entry(ty.kind()).or_default() += 1;
        }
        kinds
    }
}

/// `seen` (one pointer global's evidence) where a function reads the
/// pointers its values point to (the elements the others show point to
/// struct `id`, united: [`Structs::unite_one_type`]) only at offsets no
/// struct holds, but where `id`'s fields are ([`reads`]): its whole values
/// a pointer to pointers to `id`, as those functions' are; `None` where
/// no function's are.
fn elements_read(
    seen: &[(u64, Seen)],
    structs: &Structs,
    id: StructId,
) -> Option<Vec<(u64, Seen)>> {
    let layout = structs.layout(id)?;
    let read = |seen: &Seen| {
        seen.elements.is_empty()
            && seen.whole.is_some()
            && !seen.element_reads.fields.is_empty()
            && reads(layout, &seen.element_reads)
    };
    if !seen.iter().any(|(_, seen)| read(seen)) {
        return None;
    }
    Some(
        seen.iter()
            .map(|(function, seen)| {
                let mut seen = seen.clone();
                if read(&seen)
                    && let Some((field, _)) = &mut seen.whole
                {
                    *field = Field {
                        bits: field.bits,
                        ty: FieldType::Pointers(id),
                        strength: strength::ACCESS,
                    };
                }
                (*function, seen)
            })
            .collect(),
    )
}

/// The type of the global at `start` that the functions' evidence `seen`
/// shows, by the [module](self)'s rules; `code` gives the code type of a
/// function stored in it.
fn settle(
    start: u64,
    seen: &[(u64, Seen)],
    structs: &mut Structs,
    data: &dyn Data,
    prototypes: &dyn Prototypes,
    code: &dyn Fn(u64) -> Option<FieldType>,
    pointer_width: u16,
) -> Option<GlobalType> {
    let object = data
        .object(start)
        .filter(|object| object.start == start && (1..=MAX_OBJECT).contains(&object.size));
    let clues = clues(seen, code, pointer_width);
    let mut scratch = Types::new(pointer_width);
    if let Some(ty) = prototypes.global(start, &mut scratch) {
        let size = object
            .map(|object| object.size)
            .or_else(|| scratch.width(ty).map(|bits| bits / 8))?;
        let source = if prototypes.stated_by_user(start) {
            GlobalSource::User
        } else {
            GlobalSource::Debug
        };
        return Some(GlobalType {
            start,
            size,
            named: object.is_some(),
            shape: Shape::Declared,
            source,
            strength: Strength(u8::MAX),
            clues,
            conflicts: 0,
        });
    }
    let made =
        |shape: Shape, size: u64, source: GlobalSource, chosen: Option<(Strength, usize)>| {
            let (strength, conflicts) = chosen.unwrap_or_default();
            GlobalType {
                start,
                size,
                named: object.is_some(),
                shape,
                source,
                strength,
                clues: clues.clone(),
                conflicts,
            }
        };
    if let Some(object) = object
        && let Some(shape) = table_struct(structs, start, object.size)
    {
        return Some(made(shape, object.size, GlobalSource::Table, None));
    }
    // A whole access: a scalar C has, as wide as the named object.
    let fits = |field: &Field| {
        field.bits <= MAX_SCALAR
            && object.is_none_or(|object| u64::from(field.bits) == object.size.saturating_mul(8))
    };
    let whole: Vec<(Field, usize)> = clues
        .iter()
        .filter(|clue| clue.whole > 0 && fits(&clue.field))
        .map(|clue| (clue.field.clone(), clue.whole))
        .collect();
    let parts: usize = seen.iter().flat_map(|(_, seen)| seen.widths.values()).sum();
    let wholes: usize = seen
        .iter()
        .filter_map(|(_, seen)| seen.whole.as_ref())
        .filter(|(field, _)| fits(field))
        .map(|&(_, count)| count)
        .sum();
    let elements = object.and_then(|object| array(seen, object.size));
    if !whole.is_empty() && (wholes >= parts || elements.is_none()) {
        let (chosen, conflicts) = value(structs, whole)?;
        let size = u64::from(chosen.bits / 8);
        return Some(made(
            Shape::Value(chosen.ty),
            size,
            GlobalSource::Accesses,
            Some((chosen.strength, conflicts)),
        ));
    }
    let (shape, chosen) = elements?;
    let shape = if let Shape::Array {
        element: FieldType::Struct(id),
        length,
    } = shape
    {
        Shape::Array {
            element: FieldType::Struct(structs.find(id)),
            length,
        }
    } else {
        shape
    };
    let size = object.map_or(0, |object| object.size);
    Some(made(shape, size, GlobalSource::Accesses, chosen))
}

/// The value of the whole accesses `whole` (each a field with how many
/// accesses it stands for): of the width read and written most, the
/// type [`choose`] chooses, its pointee structs united in `structs`
/// ([`unite_pointees`]; `void *` where they stay several), with how
/// many candidates are of another type.
fn value(structs: &mut Structs, whole: Vec<(Field, usize)>) -> Option<(Field, usize)> {
    let mut widths: BTreeMap<u16, usize> = BTreeMap::new();
    for (field, count) in &whole {
        *widths.entry(field.bits).or_default() += count;
    }
    let bits = most(&widths)?;
    let mut candidates: Vec<(Field, usize)> = whole
        .into_iter()
        .filter(|(field, _)| field.bits == bits)
        .collect();
    let one = unite_pointees(structs, &mut candidates);
    let (chosen, conflicts) = choose(&candidates)?;
    let chosen = match chosen.ty {
        FieldType::Struct(_) if !one => Field {
            ty: FieldType::Pointer(None),
            ..chosen
        },
        FieldType::Scalar(_)
        | FieldType::Pointer(_)
        | FieldType::Opaque
        | FieldType::Struct(_)
        | FieldType::Pointers(_)
        | FieldType::ScalarPointers(_)
        | FieldType::Code { .. } => chosen,
    };
    Some((chosen, conflicts))
}

/// The array a named object of `size` bytes is by the accesses to parts
/// of it `seen` shows: of the elements most of them read and write (a
/// width the object is a whole number of, a scalar C has: at most
/// [`MAX_SCALAR`] bits; a wider access, a vector's, stays an access at
/// its address), typed as [`choose`] chooses among their fields that
/// wide (untyped bits if none), with the chosen evidence's strength and
/// how many fields are of another type.
fn array(seen: &[(u64, Seen)], size: u64) -> Option<(Shape, Option<(Strength, usize)>)> {
    let mut widths: BTreeMap<u16, usize> = BTreeMap::new();
    for (_, seen) in seen {
        for (&bits, &count) in &seen.widths {
            if (8..=MAX_SCALAR).contains(&bits) && size.is_multiple_of(u64::from(bits / 8)) {
                *widths.entry(bits).or_default() += count;
            }
        }
    }
    let bits = most(&widths)?;
    let bytes = u64::from(bits / 8);
    let fields: Vec<(Field, usize)> = seen
        .iter()
        .flat_map(|(_, seen)| {
            seen.parts
                .fields
                .iter()
                .filter(|&(&offset, field)| {
                    field.bits == bits && offset.is_multiple_of(bytes) && offset < size
                })
                .map(|(_, field)| (field.clone(), 1))
        })
        .collect();
    let (element, chosen) = match choose(&fields) {
        Some((field, conflicts)) => (field.ty, Some((field.strength, conflicts))),
        None => (FieldType::Scalar(Type::Bits(bits)), None),
    };
    let shape = Shape::Array {
        element,
        length: size / bytes,
    };
    Some((shape, chosen))
}

/// The table's struct for the object of `size` bytes at `start`, where
/// the object starts it and is its size (a struct), or a whole number of
/// an array's elements (structs), and its fields are scalars C has (at
/// most [`MAX_SCALAR`] bits: a vector's wider access stays an access at
/// its address in the function that makes it, not every function's).
fn table_struct(structs: &Structs, start: u64, size: u64) -> Option<Shape> {
    let (id, 0) = structs.global(start)? else {
        return None;
    };
    let layout = structs.layout(id)?;
    if layout.fields.values().any(|field| field.bits > MAX_SCALAR) {
        return None;
    }
    let bytes = layout.natural_size();
    if layout.element == 0 {
        return (bytes == size).then_some(Shape::Struct(id));
    }
    (bytes > 0 && size > bytes && size.is_multiple_of(bytes)).then_some(Shape::Structs {
        element: id,
        length: size / bytes,
    })
}

/// Every function's evidence of `seen` as clues: with each function it
/// stores, that function's code type (`code`: its prototype's or final
/// interface's, a pointer `pointer_width` bits wide at Access strength)
/// as one whole write. (The sweep's own type for such a value may be a
/// guess: the stored function's interface may not be found yet.)
fn clues(
    seen: &[(u64, Seen)],
    code: &dyn Fn(u64) -> Option<FieldType>,
    pointer_width: u16,
) -> Vec<GlobalClue> {
    let mut clues = Vec::new();
    for (function, seen) in seen {
        if let Some((field, count)) = &seen.whole {
            clues.push(GlobalClue {
                function: *function,
                offset: 0,
                field: field.clone(),
                whole: *count,
            });
        }
        for ty in seen.functions.iter().filter_map(|&stored| code(stored)) {
            clues.push(GlobalClue {
                function: *function,
                offset: 0,
                field: Field {
                    bits: pointer_width,
                    ty,
                    strength: strength::ACCESS,
                },
                whole: 1,
            });
        }
        for (&offset, field) in &seen.parts.fields {
            clues.push(GlobalClue {
                function: *function,
                offset,
                field: field.clone(),
                whole: 0,
            });
        }
    }
    clues
}

/// How informative a field type is: untyped bits least, then a pointer
/// to nothing known, then any other.
const fn informative(ty: &FieldType) -> u8 {
    match ty {
        FieldType::Scalar(Type::Bits(_)) => 0,
        FieldType::Pointer(None) => 1,
        FieldType::Scalar(_)
        | FieldType::Pointer(Some(_))
        | FieldType::Opaque
        | FieldType::Struct(_)
        | FieldType::Pointers(_)
        | FieldType::ScalarPointers(_)
        | FieldType::Code { .. } => 2,
    }
}

/// How a candidate of [`choose`] ranks (highest first): fewest accesses
/// against it, most informative, strongest.
type Rank = (Reverse<usize>, u8, Strength);

/// Whether a value of type `ty` (`bits` wide, as pointers are) is also
/// one of type `other`, saying more: the same type, or a pointer to a
/// target a function's solve states (a scalar, code, the pointers of an
/// array: [`FieldType::Pointers`], another type: [`FieldType::Opaque`])
/// where `other` is a pointer to nothing known; or an array's pointers
/// where `other` is a pointer to as many untyped bits as a pointer has
/// (untyped, they say only their width); or pointers to a scalar
/// ([`FieldType::ScalarPointers`]) where `other` is a pointer to another
/// known type (a function's rounding of a pointer to pointers, which no
/// other field type carries) or pointers to nothing known. A pointer whose target is
/// unknown constrains no target, so it contradicts none (as a struct's
/// field and a variable's type take the target, [`Layout::add`]). A
/// synthesised struct is not such a target: a function's evidence is
/// the struct its values point to ahead of its own rounding of them
/// ([`Seen`]), which may be another pointer (a buffer read at fixed
/// offsets, which the function holds as `char *`), so it needs the
/// other functions' agreement as before.
fn refines(ty: &FieldType, other: &FieldType, bits: u16) -> bool {
    ty == other
        || match other {
            FieldType::Pointer(None) => matches!(
                ty,
                FieldType::Pointer(Some(_))
                    | FieldType::Opaque
                    | FieldType::Pointers(_)
                    | FieldType::ScalarPointers(_)
                    | FieldType::Code { .. }
            ),
            &FieldType::Pointer(Some(Type::Bits(width))) => {
                width == bits && matches!(ty, FieldType::Pointers(_) | FieldType::ScalarPointers(_))
            }
            FieldType::Opaque => matches!(ty, FieldType::ScalarPointers(_)),
            FieldType::ScalarPointers(None) => matches!(ty, FieldType::ScalarPointers(Some(_))),
            FieldType::Scalar(_)
            | FieldType::Pointer(Some(_))
            | FieldType::Struct(_)
            | FieldType::Pointers(_)
            | FieldType::ScalarPointers(Some(_))
            | FieldType::Code { .. } => false,
        }
}

/// Of `candidates` (each function's field at one place, all one width,
/// with how many accesses it stands for), the type the fewest accesses
/// contradict with evidence at least as strong as the type's own (its
/// strongest): a function whose own evidence is weaker takes the
/// program's type (`generate`'s bound), so only those keep another
/// (a type contradicts none it [`refines`]: a pointer to nothing known
/// contradicts no pointer with a target, which is that pointer's join
/// with it; untyped bits contradict no scalar: C converts between
/// integers implicitly; but a function that only moves or computes with
/// the bits holds them as an integer, which C converts to and from a
/// pointer or code only with a cast, C11 6.3.2.3p5-6, so they contradict
/// those at any strength); then the more [`informative`], the one with
/// the stronger evidence, the first. With how many candidates are of
/// another type that it does not refine.
fn choose(candidates: &[(Field, usize)]) -> Option<(Field, usize)> {
    let mut best: Option<(Field, Rank)> = None;
    for (field, _) in candidates {
        let strength = candidates
            .iter()
            .filter(|(other, _)| other.ty == field.ty)
            .map(|(other, _)| other.strength)
            .max()
            .unwrap_or(field.strength);
        let scalar = matches!(field.ty, FieldType::Scalar(_));
        let against: usize = candidates
            .iter()
            .filter(|(other, _)| {
                !refines(&field.ty, &other.ty, field.bits)
                    && if matches!(other.ty, FieldType::Scalar(Type::Bits(_))) {
                        !scalar
                    } else {
                        other.strength >= strength
                    }
            })
            .map(|&(_, count)| count)
            .sum();
        let key = (Reverse(against), informative(&field.ty), strength);
        if best.as_ref().is_none_or(|(_, kept)| key > *kept) {
            let chosen = Field {
                strength,
                ..field.clone()
            };
            best = Some((chosen, key));
        }
    }
    let (chosen, _) = best?;
    let conflicts = candidates
        .iter()
        .filter(|(field, _)| !refines(&chosen.ty, &field.ty, chosen.bits))
        .count();
    Some((chosen, conflicts))
}

/// Unites in `structs` the structs the pointers of `candidates` (one
/// global's values, each function's) point to (one type: the values of
/// one global are one pointer), and points each candidate at its struct
/// as the union left it, so [`choose`] counts the functions that see one
/// struct as agreeing; whether they are one. (Where they stay several,
/// layouts that disagree, a struct chosen is `void *`, which C converts
/// to and from each of them.)
fn unite_pointees(structs: &mut Structs, candidates: &mut [(Field, usize)]) -> bool {
    let pointees: Vec<StructId> = candidates
        .iter()
        .filter_map(|(field, _)| match field.ty {
            FieldType::Struct(id) => Some(id),
            FieldType::Scalar(_)
            | FieldType::Pointer(_)
            | FieldType::Opaque
            | FieldType::Pointers(_)
            | FieldType::ScalarPointers(_)
            | FieldType::Code { .. } => None,
        })
        .collect();
    if let Some((&first, rest)) = pointees.split_first() {
        structs.unite_all(rest.iter().map(|&id| (first, id)).collect());
    }
    for (field, _) in candidates.iter_mut() {
        match field.ty {
            FieldType::Struct(id) => field.ty = FieldType::Struct(structs.find(id)),
            // The structs one array's elements point to are united
            // already ([`Globals::settle`]).
            FieldType::Pointers(id) => field.ty = FieldType::Pointers(structs.find(id)),
            FieldType::Scalar(_)
            | FieldType::Pointer(_)
            | FieldType::Opaque
            | FieldType::ScalarPointers(_)
            | FieldType::Code { .. } => {}
        }
    }
    pointees.iter().all(|&id| {
        pointees
            .first()
            .is_some_and(|&first| structs.find(first) == structs.find(id))
    })
}

/// The width counted most (the widest of those tied).
fn most(widths: &BTreeMap<u16, usize>) -> Option<u16> {
    widths
        .iter()
        .max_by_key(|&(&width, &count)| (count, width))
        .map(|(&width, _)| width)
}

#[cfg(test)]
mod tests {
    use super::*;
    use binbun_semantics::ir::RegisterId;

    use crate::data::{NoData, Object};
    use crate::mapping::{Piece, Source};
    use crate::prototype::NoPrototypes;
    use crate::typing::structs::Contribution;
    use alloc::vec;

    /// One object of 4 bytes at 0x5000, one of 16 at 0x6000, one of 8 at
    /// 0x7000.
    struct Objects;

    impl Data for Objects {
        fn object(&self, address: u64) -> Option<Object> {
            [(0x5000, 4), (0x6000, 16), (0x7000, 8)]
                .into_iter()
                .map(|(start, size)| Object {
                    start,
                    size,
                    read_only: false,
                })
                .find(|object| object.holds(address, 1))
        }

        fn data(&self, address: u64, bytes: u64) -> Option<bool> {
            NoData.data(address, bytes)
        }

        fn string(&self, address: u64) -> Option<u64> {
            NoData.string(address)
        }

        fn constant(&self, address: u64, bytes: u64) -> Option<Vec<u8>> {
            NoData.constant(address, bytes)
        }

        fn relocatable(&self) -> bool {
            true
        }
    }

    fn field(bits: u16, ty: FieldType, strength: u8) -> Field {
        Field {
            bits,
            ty,
            strength: Strength(strength),
        }
    }

    fn whole(field: Field, count: usize) -> Seen {
        Seen {
            whole: Some((field, count)),
            ..Seen::default()
        }
    }

    fn settled(globals: &mut Globals, structs: &mut Structs) {
        globals.settle(structs, &Objects, &NoPrototypes, &BTreeMap::new(), 64);
    }

    #[test]
    fn a_scalar_takes_the_type_fewest_accesses_as_strong_contradict() {
        let int = FieldType::Scalar(Type::Int(32));
        let uint = FieldType::Scalar(Type::UInt(32));
        let mut globals = Globals::new();
        // Three accesses read it signed by operations, one unsigned; a
        // fourth function only moves its bits (no evidence).
        globals.add(0x10, vec![(0x5000, whole(field(32, int.clone(), 3), 2))]);
        globals.add(0x20, vec![(0x5000, whole(field(32, uint.clone(), 3), 1))]);
        globals.add(0x30, vec![(0x5000, whole(field(32, int.clone(), 3), 1))]);
        let bits = FieldType::Scalar(Type::Bits(32));
        globals.add(0x40, vec![(0x5000, whole(field(32, bits, 0), 4))]);
        let mut structs = Structs::new();
        settled(&mut globals, &mut structs);
        let ty = globals.get(0x5000).unwrap();
        assert_eq!(ty.shape, Shape::Value(int));
        assert_eq!((ty.size, ty.named, ty.conflicts), (4, true, 2));
        assert_eq!(ty.strength, Strength(3));
        assert_eq!(ty.source, GlobalSource::Accesses);
        assert_eq!(ty.clues.len(), 4);
        // A declaration-strength use is contradicted by no access as
        // strong: it outranks how many accesses agree.
        globals.add(0x50, vec![(0x5000, whole(field(32, uint.clone(), 6), 1))]);
        settled(&mut globals, &mut structs);
        let ty = globals.get(0x5000).unwrap();
        assert_eq!((&ty.shape, ty.strength), (&Shape::Value(uint), Strength(6)));
        assert_eq!(globals.kinds().get(&Kind::Scalar), Some(&1));
    }

    #[test]
    fn data_no_object_names_is_as_wide_as_most_of_its_accesses() {
        let mut globals = Globals::new();
        let long = FieldType::Scalar(Type::Int(64));
        let int = FieldType::Scalar(Type::Int(32));
        globals.add(0x10, vec![(0x9000, whole(field(64, long.clone(), 3), 3))]);
        globals.add(0x20, vec![(0x9000, whole(field(32, int, 6), 1))]);
        let mut structs = Structs::new();
        settled(&mut globals, &mut structs);
        let ty = globals.get(0x9000).unwrap();
        assert_eq!(
            (&ty.shape, ty.size, ty.named),
            (&Shape::Value(long), 8, false)
        );
    }

    #[test]
    fn a_pointer_to_nothing_known_takes_the_target_others_show() {
        let unknown = FieldType::Pointer(None);
        let long = FieldType::Pointer(Some(Type::Int(64)));
        let ulong = FieldType::Pointer(Some(Type::UInt(64)));
        let settle = |evidence: &[(FieldType, u8, usize)]| {
            let mut globals = Globals::new();
            for (function, (ty, strength, count)) in (0x10..).step_by(0x10).zip(evidence) {
                let seen = whole(field(64, ty.clone(), *strength), *count);
                globals.add(function, vec![(0x7000, seen)]);
            }
            settled(&mut globals, &mut Structs::new());
            let ty = globals.get(0x7000).unwrap();
            (ty.shape.clone(), ty.strength, ty.conflicts)
        };
        // Most accesses, some stronger, say only that it is a pointer:
        // they contradict no target, so the one the others show is its
        // type, overriding nothing.
        assert_eq!(
            settle(&[
                (long.clone(), 4, 2),
                (unknown.clone(), 4, 5),
                (unknown.clone(), 6, 2)
            ]),
            (Shape::Value(long.clone()), Strength(4), 0)
        );
        // Two targets still disagree as before: the one fewer accesses
        // as strong contradict, whatever the pointers to nothing known.
        let both = [(long.clone(), 4, 1), (ulong.clone(), 4, 2)];
        let mut with_unknown = both.to_vec();
        with_unknown.push((unknown.clone(), 4, 5));
        assert_eq!(settle(&both), (Shape::Value(ulong.clone()), Strength(4), 1));
        assert_eq!(settle(&with_unknown), (Shape::Value(ulong), Strength(4), 1));
        // Where the targets disagree and only weaker evidence shows
        // them, the stronger pointer to nothing known stays `void *`.
        with_unknown.push((unknown.clone(), 6, 1));
        assert_eq!(
            settle(&with_unknown),
            (Shape::Value(unknown.clone()), Strength(6), 2)
        );
        // A pointer to code is a pointer with a target too.
        let code = FieldType::Code {
            parameters: vec![Type::Int(32)],
            returns: None,
            variadic: false,
        };
        assert_eq!(
            settle(&[(unknown.clone(), 4, 3), (code.clone(), 4, 1)]),
            (Shape::Value(code), Strength(4), 0)
        );
        // So is a pointer to a type no field type carries (a declared
        // `FILE *`, a `char **`): it contradicts another target, which
        // contradicts it.
        assert_eq!(
            settle(&[
                (long.clone(), 4, 2),
                (FieldType::Opaque, 4, 3),
                (unknown.clone(), 4, 1)
            ]),
            (Shape::Value(FieldType::Opaque), Strength(4), 1)
        );
        // A synthesised struct still needs the others' agreement.
        let pointee = FieldType::Struct(StructId {
            function: 0x10,
            k: 1,
        });
        assert_eq!(
            settle(&[(pointee, 4, 1), (unknown.clone(), 4, 2)]),
            (Shape::Value(unknown.clone()), Strength(4), 1)
        );
        // Untyped bits still contradict a pointer.
        let bits = FieldType::Scalar(Type::Bits(64));
        assert_eq!(
            settle(&[(long.clone(), 4, 1), (bits.clone(), 0, 2)]).0,
            Shape::Value(bits)
        );
        // An array's element is chosen alike.
        let mut parts = Layout::default();
        parts.add(0, field(64, unknown.clone(), 6));
        parts.add(8, field(64, unknown, 6));
        let mut typed = Layout::default();
        typed.add(8, field(64, long.clone(), 4));
        let mut globals = Globals::new();
        for (function, parts) in [(0x10, parts), (0x20, typed)] {
            let seen = Seen {
                parts,
                widths: BTreeMap::from([(64, 2)]),
                ..Seen::default()
            };
            globals.add(function, vec![(0x6000, seen)]);
        }
        settled(&mut globals, &mut Structs::new());
        let ty = globals.get(0x6000).unwrap();
        assert_eq!(
            (&ty.shape, ty.conflicts),
            (
                &Shape::Array {
                    element: long,
                    length: 2
                },
                0
            )
        );
    }

    #[test]
    fn an_array_of_pointers_to_one_struct_types_its_global() {
        // Two functions find the struct the pointers held in the array a
        // global points to point to; one reads the flags byte of an
        // element only, another moves elements as untyped bits, the
        // allocator passes the array to a `void *` parameter.
        let (a, b) = (
            StructId {
                function: 0x10,
                k: 1,
            },
            StructId {
                function: 0x20,
                k: 1,
            },
        );
        let flags = |bits: u16| {
            let mut layout = Layout::default();
            layout.add(0, field(32, FieldType::Scalar(Type::Int(32)), 4));
            layout.add(32, field(bits, FieldType::Scalar(Type::Bits(bits)), 4));
            layout
        };
        let mut structs = Structs::new();
        for (id, bits) in [(a, 32), (b, 8)] {
            structs.add(
                id.function,
                None,
                Contribution {
                    layouts: BTreeMap::from([(id, flags(bits))]),
                    ..Contribution::default()
                },
            );
        }
        let pointers = |id| Seen {
            whole: Some((field(64, FieldType::Pointers(id), 4), 1)),
            elements: vec![id],
            ..Seen::default()
        };
        let reading = |offset: u64, bits: u16| {
            let mut element_reads = Layout::default();
            element_reads.add(offset, field(bits, FieldType::Scalar(Type::UInt(bits)), 4));
            Seen {
                whole: Some((field(64, FieldType::Opaque, 4), 2)),
                element_reads,
                ..Seen::default()
            }
        };
        let settle = |structs: &mut Structs, read: Seen| {
            let mut globals = Globals::new();
            globals.add(0x10, vec![(0x7000, pointers(a))]);
            globals.add(0x20, vec![(0x7000, pointers(b))]);
            globals.add(0x30, vec![(0x7000, read)]);
            let bits = FieldType::Pointer(Some(Type::Bits(64)));
            globals.add(0x40, vec![(0x7000, whole(field(64, bits, 4), 3))]);
            let unknown = FieldType::Pointer(None);
            globals.add(0x50, vec![(0x7000, whole(field(64, unknown, 6), 2))]);
            settled(&mut globals, structs);
            globals.get(0x7000).unwrap().shape.clone()
        };
        // The byte read at the flags field (a part of it) is that struct's:
        // all agree, and the strong `void *` contradicts none.
        assert_eq!(
            settle(&mut structs, reading(32, 8)),
            Shape::Value(FieldType::Pointers(a))
        );
        assert_eq!(structs.find(b), a);
        // A read where the struct has no field stays as it was: two
        // accesses against the struct, and the `void *` stays.
        assert_eq!(
            settle(&mut structs, reading(36, 8)),
            Shape::Value(FieldType::Pointer(None))
        );
    }

    #[test]
    fn the_structs_one_pointer_global_points_to_are_one() {
        // Two functions each find the struct a global points to: one
        // type, the deeper function's (the first added), and the global
        // is a pointer to it.
        let mut structs = Structs::new();
        let layout = |bits: u16| {
            let mut layout = Layout::default();
            layout.add(0, field(32, FieldType::Scalar(Type::Int(32)), 4));
            layout.add(8, field(bits, FieldType::Scalar(Type::Int(bits)), 4));
            layout
        };
        let (a, b) = (
            StructId {
                function: 0x10,
                k: 1,
            },
            StructId {
                function: 0x20,
                k: 1,
            },
        );
        for (id, function) in [(a, 0x10), (b, 0x20)] {
            structs.add(
                function,
                None,
                Contribution {
                    layouts: BTreeMap::from([(id, layout(64))]),
                    ..Contribution::default()
                },
            );
        }
        let mut globals = Globals::new();
        globals.add(
            0x10,
            vec![(0x7000, whole(field(64, FieldType::Struct(a), 4), 1))],
        );
        globals.add(
            0x20,
            vec![(0x7000, whole(field(64, FieldType::Struct(b), 4), 1))],
        );
        settled(&mut globals, &mut structs);
        assert_eq!(structs.find(b), a);
        assert_eq!(
            globals.get(0x7000).unwrap().shape,
            Shape::Value(FieldType::Struct(a))
        );
        let (types, ty) = globals.get(0x7000).unwrap().table(&structs, 64).unwrap();
        let Some(&Type::Pointer(Some(target))) = types.get(ty) else {
            panic!("not a pointer");
        };
        assert!(matches!(types.get(target), Some(Type::Struct(_))));
    }

    #[test]
    fn an_object_reached_in_parts_is_an_array_of_its_most_accessed_width() {
        let long = FieldType::Scalar(Type::Int(64));
        let mut parts = Layout::default();
        parts.add(0, field(64, long.clone(), 4));
        parts.add(8, field(64, long.clone(), 4));
        let mut bytes = Layout::default();
        bytes.add(3, field(8, FieldType::Scalar(Type::UInt(8)), 4));
        let mut globals = Globals::new();
        globals.add(
            0x10,
            vec![(
                0x6000,
                Seen {
                    parts,
                    widths: BTreeMap::from([(64, 3)]),
                    ..Seen::default()
                },
            )],
        );
        globals.add(
            0x20,
            vec![(
                0x6000,
                Seen {
                    parts: bytes,
                    widths: BTreeMap::from([(8, 1)]),
                    ..Seen::default()
                },
            )],
        );
        let mut structs = Structs::new();
        settled(&mut globals, &mut structs);
        let ty = globals.get(0x6000).unwrap();
        assert_eq!(
            ty.shape,
            Shape::Array {
                element: long,
                length: 2
            }
        );
        assert_eq!(ty.kind(), Kind::Array);
        let (types, id) = ty.table(&structs, 64).unwrap();
        assert_eq!(types.width(id), Some(128));
    }

    #[test]
    fn a_struct_of_the_table_types_its_global() {
        let mut structs = Structs::new();
        let id = StructId {
            function: 0x10,
            k: 1,
        };
        let mut layout = Layout::default();
        layout.add(0, field(32, FieldType::Scalar(Type::Int(32)), 4));
        layout.add(8, field(64, FieldType::Pointer(None), 4));
        structs.add(
            0x10,
            None,
            Contribution {
                layouts: BTreeMap::from([(id, layout)]),
                globals: vec![(0x6000, id, 0)],
                ..Contribution::default()
            },
        );
        let mut globals = Globals::new();
        let int = FieldType::Scalar(Type::Int(32));
        let mut parts = Layout::default();
        parts.add(0, field(32, int, 4));
        globals.add(
            0x10,
            vec![(
                0x6000,
                Seen {
                    parts,
                    widths: BTreeMap::from([(32, 1)]),
                    ..Seen::default()
                },
            )],
        );
        settled(&mut globals, &mut structs);
        let ty = globals.get(0x6000).unwrap();
        assert_eq!(
            (&ty.shape, ty.source),
            (&Shape::Struct(id), GlobalSource::Table)
        );
        assert_eq!(ty.kind(), Kind::Struct);
    }

    #[test]
    fn a_hook_is_the_type_of_the_function_stored_in_it() {
        // The function at 0x900 takes one 64-bit argument and returns 32
        // bits (its final interface). Two functions store it in the hook
        // before the sweep found that interface: their own type is the
        // convention's guess, at Prior strength; a third calls through
        // the hook (a guess too); a fourth stores it after.
        let register = |n: u16, width: u16| Piece {
            register: RegisterId(n),
            offset: 0,
            width,
        };
        let interfaces = BTreeMap::from([(
            0x900,
            Interface {
                parameters: vec![Source::Register(register(7, 64))],
                returns: vec![register(0, 32)],
                ..Interface::default()
            },
        )]);
        let guess = FieldType::Code {
            parameters: vec![Type::Bits(64); 6],
            returns: Some(Type::Bits(64)),
            variadic: false,
        };
        let stored = |functions: Vec<u64>| Seen {
            whole: Some((field(64, guess.clone(), 0), 1)),
            functions,
            ..Seen::default()
        };
        let mut globals = Globals::new();
        globals.add(0x10, vec![(0x9000, stored(vec![0x900]))]);
        globals.add(0x20, vec![(0x9000, stored(vec![0x900]))]);
        globals.add(0x30, vec![(0x9000, whole(field(64, guess.clone(), 0), 2))]);
        globals.add(0x40, vec![(0x9000, stored(vec![0x900]))]);
        let mut structs = Structs::new();
        globals.settle(&mut structs, &Objects, &NoPrototypes, &interfaces, 64);
        let ty = globals.get(0x9000).unwrap();
        let one = FieldType::Code {
            parameters: vec![Type::Bits(64)],
            returns: Some(Type::Bits(32)),
            variadic: false,
        };
        assert_eq!((&ty.shape, ty.strength), (&Shape::Value(one), Strength(4)));
        // Without the interface the stores say only that it is code.
        globals.settle(&mut structs, &Objects, &NoPrototypes, &BTreeMap::new(), 64);
        let ty = globals.get(0x9000).unwrap();
        assert_eq!(
            (&ty.shape, ty.strength),
            (&Shape::Value(guess), Strength(0))
        );
    }
}
