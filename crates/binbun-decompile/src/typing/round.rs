//! Rounding: solved bounds to L2 types, a separate step that never feeds
//! back into the solve as evidence.
//!
//! - A type variable's type: code of a call's signature if a code bound
//!   stands that a call through a value stated (its signature: a value
//!   loaded and then called is code too), or of a function's code type
//!   if its address is a lower bound (if C can refer to it: scalars
//!   only); a pointer as a member of a pointer family (below); a pointer
//!   if a pointer bound stands (pointers win over atoms that also
//!   stand); else the join of its atomic lower bounds if informative
//!   (signed, unsigned, truth value, `char`, float), else the meet of its
//!   upper bounds if informative; else nothing (the printer's default).
//!   The type must be as wide as the value. Its strength is the strongest
//!   evidence among the bounds of the kind chosen. An enumeration's value
//!   (where every value flowing in is one: `binbun_typeinfer`'s rule) is that
//!   enumeration; everywhere else (fields, elements) its integer.
//! - A pointer family (`family`) is one object: if a member is a pointer
//!   by evidence of at least Access strength, every member is (its
//!   strength the strongest such), unless the member's own non-pointer
//!   evidence is stronger and at least Float. Its fields are the accesses
//!   through its members and the fields of the views its members'
//!   pointer bounds reach, at offsets from the family's root; through a
//!   member whose offset is known only modulo an index's scale (its
//!   modulus), only those whose width divides the modulus (an array walk:
//!   `p + i` read 16 bytes at a time is at no known element, and does not
//!   decide `p`'s). If every field has one width `w` (whole bytes) and
//!   every offset and the family's stride are multiples of `w / 8`, that
//!   is the element, and a member whose offset and modulus are multiples
//!   of `w / 8` points to it. Where they are not, the family's own
//!   accesses (not the fields a callee's scheme gives the memory it is
//!   passed) may still be an array of floats: their narrowest width `w`
//!   (32 or 64) a float's, every wider one a whole number of `w`-bit
//!   elements at a whole element's offset with a value of no type of its
//!   own (a SIMD load or store, `movups`: moved, not an integer by an
//!   operation), or, with none wider, a stride (an array walk); every
//!   offset and the stride whole elements. With no element (several
//!   widths: a struct),
//!   a member points to the element of the fields at its own offset
//!   (modulo the stride and its modulus); otherwise to nothing
//!   (`void *`).
//! - An element's type: the type of its fields' values with the
//!   strongest evidence (a declared `char *`'s `char` beats a `movzx`'s
//!   unsigned); types that differ at that strength give `bits(w)`; a field
//!   with no evidence says nothing; none: `bits(w)`. A pointer field is a
//!   pointer to its own family's element (one level; `void *` deeper or
//!   where it is the family itself); a field whose value is called (or
//!   declared code) is that code type, as the value rounds alone.
//! - A pointer outside a family: the fields of the records its load and
//!   store views reach (the solver merges a variable's pointer views, so a
//!   load through one copy sees stores through another), by the same
//!   element rule.
//! - A family that is a struct of the program's table (`structs`: by its
//!   accesses the table assigns, else by a callee's root it is passed to
//!   or holds the result of): a member at the struct's start points to
//!   the struct, one at a field to the field's type, one elsewhere to
//!   nothing; an exact access at a field of its width takes the field's
//!   type (the printer's `p->field_8`). A family with a stride is one only
//!   as an array of structs (`structs::element`): places in it are
//!   modulo the stride (`p + d·i` points to the struct: `&base[i]`), and
//!   accesses through members whose modulus is a multiple of it count as
//!   exact. A function's contribution to the
//!   table is its families' fields, each the element rule's type of the
//!   values accessed at that offset and width (a pointer to a struct's
//!   start: the struct), with the strongest evidence among them.
//! - Cells: the values stored to and loaded from one place (a stack slot,
//!   a global object accessed whole, a pointer-wide field of a family at
//!   one offset modulo its stride and the moduli of the members it is
//!   accessed through), with the place itself. A pointer that
//!   rounds to no target (`void *`), and an element's pointer field outside
//!   its own family with no target there, takes its cells' target: of the
//!   cell's members, each rounded alone, the strongest pointer with a
//!   target (the first on a tie), so every load and store of a place
//!   agrees (a pointer loaded from a field gets the target the stored
//!   pointer's family gives).
//! - An L2 variable (a class of coalesced values) takes the type of its
//!   members with the strongest evidence, but a pointer with a target
//!   beats `void *` whatever the strengths (a declaration only a
//!   pointer takes the target the accesses give); members of different
//!   types are a disagreement (counted; the first kept on a tie). A
//!   parameter's variable also counts its entry value or its stack slot.
//!   An enumeration only where every member is its value (a member of
//!   another type or of none makes it its integer).
//! - Loads and stores take the type of the value loaded or stored, but
//!   one wider than 64 bits through a family whose element is a float, at
//!   a whole element's place, a vector of as many elements (`f32x4`); the
//!   return value takes its variable's joined with the values returned (as
//!   a class, with the wider registers' values returned read at its
//!   width), else, where nothing speaks for those, the type of the
//!   classes holding the values returned where they agree; a global
//!   object accessed whole, or an address no object names, takes its
//!   variable's.
//! - Declared types are never changed: a declared parameter or return
//!   value gets nothing here; one declared only a pointer takes the
//!   pointer it rounds to, if it rounds to one.
//! - A callee's signature at its calls (one per callee, where its scheme
//!   is instantiated): each `bits` parameter takes the type of its
//!   instances' roots at that place (joined as a class over every call),
//!   the result likewise; the others stay, so the arguments a scheme
//!   types need no cast to an untyped parameter; a pointer-wide one
//!   whose root the program's table has at a struct's start is a pointer
//!   to that struct, as the callee's definition prints it. Where no
//!   instance of its scheme types a call, each `bits` or pointer
//!   parameter and the result take the program's signature's type
//!   ([`super::Schemes::signature`]) where it says more than a width.
//! - A global object a family reaches (`Generated::objects`) is typed as
//!   the struct the table has for it where the object is its size, or as
//!   `S g[n]` where it is an array of struct elements `S` and `n` of them
//!   fill it.
//! - The program's type of a global ([`super::Globals`]), where it has
//!   one, is every function's: it replaces what the function's own
//!   accesses round to.
//! - A pointer into a family passed for a parameter declared `T *` is a
//!   field of `T` there, at Declared strength, where no field of another
//!   width overlaps it (`getresuid(&u.uid, …)`: `uid` is a `uid_t`).

use alloc::collections::btree_map::Entry;
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

use binbun_ast::types::{Enumeration, Evidence as Stated, Type, TypeId, Types};
use binbun_semantics::ir::{Binary, Format as Lane};
use binbun_ssa::ir::{Definition, InstId, Op, Value};
use binbun_typeinfer::{Answer, Atom, Bound, Format, Level, Solution, Strength, Term, Var};

use super::GlobalShape;
use super::family::{Access, Family, counts, gcd, period};
use super::generate::{Generated, Parameter, Shape, View, format_of};
use super::globals::Seen;
use super::structs::{
    Contribution, Field, FieldType, Layout, StructId, bytes, counted, element, place, qualifies,
    uniform,
};
use super::{Argument, Arguments, Class, FunctionTypes, Root, strength as rank, strongest};
use crate::mapping::Source;

/// A class of coalesced values (an L2 local or a parameter's variable).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Members {
    /// Its values.
    pub(crate) values: Vec<Value>,
    /// Its variable's width.
    pub(crate) width: u16,
    /// The parameter it is, if it is one.
    pub(crate) parameter: Option<usize>,
}

/// The L2 types rounded from a solution (each with
/// [`Stated::Deduced`] evidence unless declared).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Rounded {
    /// Per class of lowering: its variable's type.
    pub(crate) classes: Vec<Option<TypeId>>,
    /// Per stack slot that is a variable: its type.
    pub(crate) slots: Vec<Option<TypeId>>,
    /// Per parameter: its type.
    pub(crate) parameters: Vec<Option<TypeId>>,
    /// Each load's and store's type, by instruction.
    pub(crate) accesses: BTreeMap<InstId, TypeId>,
    /// The return value's type.
    pub(crate) returns: Option<TypeId>,
    /// Each global object's type, by its first byte.
    pub(crate) globals: BTreeMap<u64, TypeId>,
    /// The signature of each callee whose scheme was instantiated, by its
    /// entry, where its instances type a parameter or the result.
    pub(crate) signatures: BTreeMap<u64, TypeId>,
    /// Classes whose members rounded to different types.
    pub(crate) disagreements: usize,
    /// Pointer families that are arrays (a stride, and an element: a
    /// scalar or a struct), and of those, arrays of structs.
    pub(crate) arrays: (usize, usize),
}

/// Rounds `solution` of `generated` (from `view`) for lowering's
/// `classes`, interning the types in `types`.
pub(crate) fn round(
    view: &View<'_>,
    generated: &Generated,
    solution: &Solution,
    classes: &[Members],
    types: &mut Types,
) -> Rounded {
    let mut state = Rounder::new(view, generated, solution, types);
    let mut rounded = Rounded::default();
    for class in classes {
        let members = class.values.iter().filter_map(|&v| generated.var(v));
        let (ty, disagree) = state.join(members, class.width);
        rounded.disagreements += usize::from(disagree);
        rounded.classes.push(ty);
    }
    for (&var, &width) in generated.slots.iter().zip(&view.slots) {
        let ty = var
            .zip(width)
            .and_then(|(var, width)| state.of(var, width))
            .map(|(ty, _)| ty);
        rounded.slots.push(ty);
    }
    for (index, parameter) in view.parameters.iter().enumerate() {
        rounded
            .parameters
            .push(state.parameter(index, parameter, classes));
    }
    state.accesses(&mut rounded.accesses);
    rounded.returns = state.returns();
    for (&start, &var) in &generated.objects {
        if let Some(ty) = state.global_object(start, var) {
            rounded.globals.insert(start, ty);
        }
    }
    for (&at, &(var, width)) in &generated.globals {
        if let Some((ty, _)) = state.of(var, width) {
            rounded.globals.insert(at, ty);
        }
    }
    // The program's type of each global, where it has one: every
    // function's (the [`super::Globals`] table); of those it accesses,
    // and of those whose address it has.
    let pointer = view.types.pointer_width();
    let addresses = view.shapes.iter().enumerate().filter_map(|(index, shape)| {
        let Some(Shape::Const(bits)) = shape else {
            return None;
        };
        let v = Value(u32::try_from(index).ok()?);
        if bits.width() != pointer || (view.data.relocatable() && view.immediate(v)) {
            return None;
        }
        Some(view.data.object(bits.low_u64())?.start)
    });
    let mut starts: Vec<u64> = generated
        .globals
        .keys()
        .chain(generated.objects.keys())
        .copied()
        .chain(addresses)
        .collect();
    starts.sort_unstable();
    starts.dedup();
    for start in starts {
        if let Some(ty) = state.program_global(start) {
            rounded.globals.insert(start, ty);
        }
    }
    for call in &view.calls {
        let Some(callee) = call.callee else {
            continue;
        };
        if !rounded.signatures.contains_key(&callee)
            && let Some(ty) = state.signature(callee, call.signature)
        {
            rounded.signatures.insert(callee, ty);
        }
    }
    rounded.arrays = state.arrays();
    rounded
}

/// What a pointer-wide value with a variable is, for coalescing: a class
/// holding a pointer is not coalesced with one holding an integer, nor
/// one holding a pointer to a struct with one holding a pointer to
/// anything else ([`Pointee`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Sort {
    /// It rounds to a pointer (a pointer family's member with pointer
    /// evidence, a pointer bound standing) or code, to what (`None`:
    /// `void *`, a target unknown).
    Pointer(Option<Pointee>),
    /// It rounds to an integer, a truth value or a float, or it is an
    /// integer computation ([`Generated::integers`]).
    Integer,
}

/// What a pointer [`Sort`] points to: a struct or union (its type), or
/// anything else (a scalar, an array, code: its type; a value rounded to
/// code is its own pointee). Two structs are two objects' types, and a
/// struct is no scalar's; scalars' types are a buffer's views.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Pointee {
    /// A struct or union.
    Struct(TypeId),
    /// Anything else.
    Other(TypeId),
}

impl Pointee {
    /// Whether one variable may hold pointers to `self` and to `other`:
    /// not to two structs, nor to a struct and anything else.
    pub(crate) fn agrees(self, other: Self) -> bool {
        match (self, other) {
            (Self::Struct(a), Self::Struct(b)) => a == b,
            (Self::Other(_), Self::Other(_)) => true,
            (Self::Struct(_), Self::Other(_)) | (Self::Other(_), Self::Struct(_)) => false,
        }
    }
}

/// Per L1 value: what `solution` of `generated` (from `view`) rounds it to
/// alone, where it is a pointer-wide variable; types interned in `types`.
pub(crate) fn sorts(
    view: &View<'_>,
    generated: &Generated,
    solution: &Solution,
    types: &mut Types,
) -> Vec<Option<Sort>> {
    let pointer = types.pointer_width();
    let mut state = Rounder::new(view, generated, solution, types);
    (0..view.canon.len())
        .map(|index| {
            let v = Value(u32::try_from(index).unwrap_or(u32::MAX));
            let v = view.canonical(v);
            let variable = view.variables.get(v.0 as usize).copied().unwrap_or(false);
            if !variable || view.width(v) != pointer {
                return None;
            }
            let rounded = generated
                .var(v)
                .and_then(|var| state.of(var, pointer))
                .and_then(|(ty, _)| Some((ty, state.types.get(ty)?)));
            match rounded {
                Some((_, &Type::Pointer(target))) => {
                    Some(Sort::Pointer(target.map(
                        |target| match state.types.get(target) {
                            Some(Type::Struct(_) | Type::Union(_)) => Pointee::Struct(target),
                            Some(_) | None => Pointee::Other(target),
                        },
                    )))
                }
                Some((ty, Type::Code(_))) => Some(Sort::Pointer(Some(Pointee::Other(ty)))),
                Some((
                    _,
                    Type::Int(_) | Type::UInt(_) | Type::Bool(_) | Type::Float(_) | Type::Enum(_),
                )) => Some(Sort::Integer),
                Some(_) | None => generated
                    .integers
                    .get(v.0 as usize)
                    .copied()
                    .unwrap_or(false)
                    .then_some(Sort::Integer),
            }
        })
        .collect()
}

/// What the calls `view` shows pass their callees ([`Arguments`]): per
/// call to a function of the program typed by its interface, per
/// argument, the [`Argument`] its values make (a constant zero, another
/// integer constant, or the [`Class`] its variable rounds to alone),
/// joined over the function's calls to that callee.
pub(crate) fn arguments(
    view: &View<'_>,
    generated: &Generated,
    solution: &Solution,
    types: &mut Types,
) -> Arguments {
    let mut state = Rounder::new(view, generated, solution, types);
    let mut arguments: Arguments = BTreeMap::new();
    for call in &view.calls {
        let Some(callee) = call.callee else {
            continue;
        };
        let passed: Vec<(Source, Argument)> = call
            .sources
            .iter()
            .zip(&call.arguments)
            .map(|(&source, values)| {
                let argument = values
                    .iter()
                    .map(|&value| state.argument(value))
                    .reduce(Argument::join)
                    .unwrap_or(Argument::Unknown);
                (source, argument)
            })
            .collect();
        match arguments.entry(callee) {
            Entry::Vacant(entry) => {
                entry.insert(passed);
            }
            Entry::Occupied(mut entry) => {
                let known = entry.get_mut();
                for (source, argument) in passed {
                    match known.iter_mut().find(|(at, _)| *at == source) {
                        Some((_, joined)) => *joined = joined.join(argument),
                        None => known.push((source, Argument::Unknown)),
                    }
                }
                // A parameter some call does not pass is not agreed on.
                for (source, joined) in known.iter_mut() {
                    if !call.sources.contains(source) {
                        *joined = Argument::Unknown;
                    }
                }
            }
        }
    }
    arguments
}

/// The signature of the function `view` shows by `solution` of
/// `generated` ([`FunctionTypes`]): each register parameter not declared as
/// its values round together (its entry value's, its slot's), the return
/// value not declared as its variable and the values returned round
/// together, each portably ([`portable`]; `bits` where nothing says
/// more); types interned in `types`.
pub(crate) fn own_signature(
    view: &View<'_>,
    generated: &Generated,
    solution: &Solution,
    types: &mut Types,
) -> FunctionTypes {
    let mut state = Rounder::new(view, generated, solution, types);
    let mut signature = FunctionTypes::default();
    for parameter in &view.parameters {
        if !matches!(parameter.evidence, Stated::Default | Stated::Deduced) {
            continue;
        }
        let Some(width) = state.types.value_width(parameter.ty) else {
            continue;
        };
        let vars: Vec<Var> = parameter
            .values
            .iter()
            .filter_map(|&v| generated.var(v))
            .chain(
                parameter
                    .slot
                    .and_then(|slot| generated.slots.get(slot).copied().flatten()),
            )
            .collect();
        let (ty, _) = state.join(vars.into_iter(), width);
        let ty = ty.unwrap_or_else(|| state.types.intern(Type::Bits(width)));
        if let Some(field) = portable(state.types, ty) {
            signature.parameters.push((parameter.source, field));
        }
    }
    let returns = &view.returns;
    if matches!(
        returns.evidence.unwrap_or(Stated::Default),
        Stated::Default | Stated::Deduced
    ) && let Some(var) = generated.returns
    {
        let returned = returns
            .values
            .iter()
            .chain(&returns.registers)
            .filter_map(|&v| generated.var(v));
        let vars: Vec<Var> = core::iter::once(var).chain(returned).collect();
        let (ty, _) = state.join(vars.into_iter(), returns.width);
        let ty = ty.unwrap_or_else(|| state.types.intern(Type::Bits(returns.width)));
        signature.returns = portable(state.types, ty);
    }
    signature
}

impl Rounder<'_, '_> {
    /// What argument `value` is, for [`arguments`]: the address of text
    /// in read-only data ([`View::text_at`]) a pointer to `char`.
    fn argument(&mut self, value: Value) -> Argument {
        match self.view.constant(value) {
            Some(0) => return Argument::Zero,
            Some(address) if self.view.text_at(value, address.cast_unsigned()) => {
                return Argument::Class(Class::Pointer(Some(Atom::Char { signed: true })));
            }
            Some(_) => return Argument::Integer,
            None => {}
        }
        let width = self.view.width(value);
        let class = self
            .generated
            .var(value)
            .and_then(|var| self.of(var, width))
            .and_then(|(ty, _)| self.class(ty));
        class.map_or(Argument::Unknown, Argument::Class)
    }

    /// The [`Class`] of type `ty`, if it has one.
    fn class(&self, ty: TypeId) -> Option<Class> {
        let ty = self.types.get(ty)?;
        Some(match *ty {
            Type::Pointer(target) => {
                Class::Pointer(target.and_then(|target| type_atom(self.types.get(target)?)))
            }
            Type::Code(_) => Class::Code,
            Type::Bits(_)
            | Type::Int(_)
            | Type::UInt(_)
            | Type::Char { .. }
            | Type::Bool(_)
            | Type::Float(_)
            | Type::Struct(_)
            | Type::Union(_)
            | Type::Array { .. }
            | Type::Vector { .. }
            | Type::Enum(_) => Class::Scalar(type_atom(ty)?),
        })
    }
}

/// The solver's atom of an L2 scalar `ty` (the inverse of [`scalar`]).
fn type_atom(ty: &Type) -> Option<Atom> {
    match *ty {
        Type::Int(width) => Some(Atom::Signed(width)),
        Type::UInt(width) => Some(Atom::Unsigned(width)),
        // Its integer: a class is portable between functions, and an
        // enumeration's atom names it only in its function's types.
        Type::Enum(Enumeration { width, signed, .. }) => Some(if signed {
            Atom::Signed(width)
        } else {
            Atom::Unsigned(width)
        }),
        Type::Char { signed } => Some(Atom::Char { signed }),
        Type::Bool(width) => Some(Atom::Bool(width)),
        Type::Float(format) => Some(Atom::Float(format_of(format))),
        Type::Bits(_)
        | Type::Pointer(_)
        | Type::Code(_)
        | Type::Struct(_)
        | Type::Union(_)
        | Type::Array { .. }
        | Type::Vector { .. } => None,
    }
}

/// Rounding's state.
struct Rounder<'r, 'a> {
    view: &'r View<'a>,
    generated: &'r Generated,
    solution: &'r Solution,
    types: &'r mut Types,
    /// Each variable's rounding, by width.
    memo: BTreeMap<(Var, u16), Option<(TypeId, Strength)>>,
    /// Each variable's rounding alone (without its cells' targets), by
    /// width.
    owns: BTreeMap<(Var, u16), Option<(TypeId, Strength)>>,
    /// The cells: the variables of the values stored to and loaded from
    /// one place (a stack slot, a global object, a pointer-wide field of
    /// a family), with the place's own variable.
    cells: Vec<Vec<Var>>,
    /// Each variable's cells.
    cell_of: BTreeMap<Var, Vec<usize>>,
    /// Each cell's target.
    cell_targets: BTreeMap<usize, Option<TypeId>>,
    /// Each family's object, by depth.
    objects: BTreeMap<(usize, u8), Object>,
    /// Each family's fields (offset from the root, width, value).
    layouts: BTreeMap<usize, Vec<(i64, u16, Option<Var>)>>,
    /// Each family member's target, by family, offset, modulus and depth.
    targets: BTreeMap<(usize, i64, u64, u8), Option<TypeId>>,
    /// Per family: the struct of the program's table it is, with the
    /// offset of its root in it ([`identify`]).
    identities: Vec<Option<(StructId, i64)>>,
    /// Each exact access into a struct: the struct, the offset in it and
    /// the width.
    fields: BTreeMap<InstId, (StructId, i64, u16)>,
    /// The structs interned in `types`.
    interned: BTreeMap<StructId, TypeId>,
}

/// What rounding makes of a pointer family (one object).
#[derive(Clone, Copy, Debug, Default)]
struct Object {
    /// The strongest evidence that a member is a pointer (`None`: none).
    strength: Option<Strength>,
    /// The element its accesses agree on: its width in bits and its type.
    element: Option<(u16, TypeId)>,
}

impl<'r, 'a> Rounder<'r, 'a> {
    /// Rounding of `solution` of `generated` (from `view`), interning in
    /// `types`.
    fn new(
        view: &'r View<'a>,
        generated: &'r Generated,
        solution: &'r Solution,
        types: &'r mut Types,
    ) -> Self {
        let pointer = types.pointer_width();
        let mut cells: Vec<Vec<Var>> = generated
            .cells
            .iter()
            .map(|(&place, values)| {
                let mut cell = values.clone();
                cell.push(place);
                cell
            })
            .collect();
        for family in &generated.families.families {
            // Pointer-wide fields at one offset modulo the stride and the
            // moduli of the members they are read through.
            let counted = family
                .accesses
                .iter()
                .filter(|access| access.bits == pointer && counts(access.modulus, access.bits));
            let period = counted
                .clone()
                .fold(family.stride, |period, access| gcd(period, access.modulus));
            let stride = i64::try_from(period).unwrap_or(0);
            let mut fields: BTreeMap<i64, Vec<Var>> = BTreeMap::new();
            for access in counted {
                if let Some(value) = access.value {
                    let offset = if stride > 0 {
                        access.offset.rem_euclid(stride)
                    } else {
                        access.offset
                    };
                    fields.entry(offset).or_default().push(value);
                }
            }
            cells.extend(fields.into_values());
        }
        let mut cell_of: BTreeMap<Var, Vec<usize>> = BTreeMap::new();
        for (index, cell) in cells.iter().enumerate() {
            for &var in cell {
                cell_of.entry(var).or_default().push(index);
            }
        }
        let identities = identify(view, generated, false).identities;
        let mut rounder = Self {
            view,
            generated,
            solution,
            types,
            memo: BTreeMap::new(),
            owns: BTreeMap::new(),
            cells,
            cell_of,
            cell_targets: BTreeMap::new(),
            objects: BTreeMap::new(),
            layouts: BTreeMap::new(),
            targets: BTreeMap::new(),
            identities: Vec::new(),
            fields: BTreeMap::new(),
            interned: BTreeMap::new(),
        };
        rounder.identified(identities);
        rounder
    }

    /// Takes `identities` as the families' structs.
    fn identified(&mut self, identities: Vec<Option<(StructId, i64)>>) {
        self.fields.clear();
        for (family, identity) in self.generated.families.families.iter().zip(&identities) {
            let Some((id, base)) = *identity else {
                continue;
            };
            for access in family
                .accesses
                .iter()
                .filter(|access| counted(access, family.stride))
            {
                self.fields.insert(
                    access.inst,
                    (id, place(access.offset, base, family.stride), access.bits),
                );
            }
        }
        self.identities = identities;
    }

    /// The struct family `index` is, with its root's offset in it, where a
    /// member of modulus `modulus` is at a known place in it (0, or a
    /// multiple of an array's element), and the family's stride (an
    /// array's element size; 0: none).
    fn struct_of(&self, index: usize, modulus: u64) -> Option<((StructId, i64), u64)> {
        let stride = self.stride(index);
        self.identities
            .get(index)
            .copied()
            .flatten()
            .filter(|_| modulus == 0 || (stride > 0 && modulus.is_multiple_of(stride)))
            .map(|identity| (identity, stride))
    }

    /// Family `index`'s stride.
    fn stride(&self, index: usize) -> u64 {
        self.generated
            .families
            .get(index)
            .map_or(0, |family| family.stride)
    }

    /// The type of the global object at `start` whose address is `var`
    /// (a member of the families): the struct the table has for it (else
    /// its family is), where the object starts it and is its size; `S
    /// g[n]` where it is an array of structs `S` whose first element the
    /// object starts and the object is `n` of. (Arrays of scalars are
    /// lowering's: the elements most of its accesses read.)
    fn global_object(&mut self, start: u64, var: Var) -> Option<TypeId> {
        let view = self.view;
        let size = view.data.object(start)?.size;
        let Some((index, offset, 0)) = self.generated.families.of(var) else {
            return None;
        };
        let structs = view.schemes.structs();
        let (id, at) = structs.global(start).or_else(|| {
            let ((id, base), stride) = self.struct_of(index, 0)?;
            Some((id, place(offset, base, stride)))
        })?;
        if at != 0 {
            return None;
        }
        let layout = structs.layout(id)?;
        let bytes = layout.natural_size();
        let element = layout.element > 0;
        let ty = structs.intern(id, self.types, &mut self.interned)?;
        if !element {
            return (bytes == size).then_some(ty);
        }
        (bytes > 0 && size > bytes && size.is_multiple_of(bytes)).then(|| {
            self.types.intern(Type::Array {
                element: ty,
                length: Some(size / bytes),
            })
        })
    }

    /// How many families are arrays whose members are pointers (by
    /// evidence of at least Access strength): with a stride, an element
    /// that is a struct ([`Self::struct_of`]) or a scalar; and how many of
    /// those are arrays of structs.
    fn arrays(&mut self) -> (usize, usize) {
        let mut found = (0, 0);
        for index in 0..self.generated.families.families.len() {
            if self.stride(index) == 0 {
                continue;
            }
            let object = self.object(index, 0);
            if object
                .strength
                .is_none_or(|strength| strength < rank::ACCESS)
            {
                continue;
            }
            if self.struct_of(index, 0).is_some() {
                found.0 += 1;
                found.1 += 1;
            } else if object.element.is_some() {
                found.0 += 1;
            }
        }
        found
    }

    /// The target of the member at `offset` of a family that is struct
    /// `id` with its root at `base` (offsets repeating by `stride`: an
    /// array's element, `p + d·i` is `&base[i]`): the struct at its
    /// start, a field's type at a field, else nothing.
    fn struct_target(
        &mut self,
        ((id, base), stride): ((StructId, i64), u64),
        offset: i64,
    ) -> Option<TypeId> {
        let view = self.view;
        let structs = view.schemes.structs();
        let at = place(offset, base, stride);
        if at == 0 {
            return structs.intern(id, self.types, &mut self.interned);
        }
        if let Ok(at) = u64::try_from(at)
            && let Some(declared) = structs.declared_field(id, at, 0, self.types)
        {
            return Some(declared);
        }
        let field = u64::try_from(at)
            .ok()
            .and_then(|at| structs.layout(id)?.fields.get(&at));
        field.map(|field| structs.field_type(&field.ty, self.types, &mut self.interned))
    }

    /// The type of the field access `inst` reaches, if it is an exact
    /// access into a struct at a field of its width.
    fn access_field(&mut self, inst: InstId) -> Option<TypeId> {
        let &(id, at, bits) = self.fields.get(&inst)?;
        let view = self.view;
        let structs = view.schemes.structs();
        if let Some(declared) = u64::try_from(at)
            .ok()
            .and_then(|at| structs.declared_field(id, at, bits, self.types))
        {
            return Some(declared);
        }
        let field = structs
            .layout(id)?
            .fields
            .get(&u64::try_from(at).ok()?)
            .filter(|field| field.bits == bits)?;
        Some(structs.field_type(&field.ty, self.types, &mut self.interned))
    }

    /// A pointer to the struct the values returned point to the start of
    /// ([`Self::returned_root`] at offset 0).
    fn returned_struct(&mut self) -> Option<TypeId> {
        let (id, 0) = self.returned_root()? else {
            return None;
        };
        let target = self
            .view
            .schemes
            .structs()
            .intern(id, self.types, &mut self.interned)?;
        Some(self.types.intern(Type::Pointer(Some(target))))
    }

    /// The struct and offset the values returned point into, if they all
    /// point into one at one offset.
    fn returned_root(&mut self) -> Option<(StructId, i64)> {
        let view = self.view;
        let generated = self.generated;
        if view.returns.width != self.types.pointer_width() {
            return None;
        }
        let mut found = None;
        for &value in &view.returns.values {
            let (index, offset, modulus) = generated.families.of(generated.var(value)?)?;
            let ((id, base), stride) = self.struct_of(index, modulus)?;
            let at = (id, place(offset, base, stride));
            if found.is_some_and(|known| known != at) {
                return None;
            }
            found = Some(at);
        }
        found
    }

    /// The type of the variables of one L2 variable `width` bits wide: the
    /// strongest, and whether they disagree. An enumeration only where
    /// every variable is its value; else its integer.
    fn join(&mut self, vars: impl Iterator<Item = Var>, width: u16) -> (Option<TypeId>, bool) {
        let mut best: Option<(TypeId, Strength)> = None;
        let mut disagree = false;
        let mut untyped = false;
        for var in vars {
            let Some((ty, strength)) = self.of(var, width) else {
                untyped = true;
                continue;
            };
            match best {
                None => best = Some((ty, strength)),
                Some((kept, kept_strength)) => {
                    disagree |= kept != ty;
                    let targeted = |ty: TypeId| match self.types.get(ty) {
                        Some(Type::Pointer(target)) => Some(target.is_some()),
                        _ => None,
                    };
                    let better = match (targeted(kept), targeted(ty)) {
                        // A pointer's target beats `void *` (a declaration
                        // only a pointer, or no access) whatever the strength.
                        (Some(false), Some(true)) => true,
                        (Some(true), Some(false)) => false,
                        _ => strength > kept_strength,
                    };
                    if better {
                        best = Some((ty, strength));
                    }
                }
            }
        }
        let ty = best.map(|(ty, _)| match self.types.get(ty) {
            Some(&Type::Enum(Enumeration {
                width: bits,
                signed,
                ..
            })) if disagree || untyped => self.types.intern(if signed {
                Type::Int(bits)
            } else {
                Type::UInt(bits)
            }),
            Some(_) | None => ty,
        });
        (ty, disagree)
    }

    /// Parameter `index`'s type: its class's members' and its entry
    /// value's or slot's; a declared one's only if declared a pointer and
    /// rounded to one.
    fn parameter(
        &mut self,
        index: usize,
        parameter: &Parameter,
        classes: &[Members],
    ) -> Option<TypeId> {
        let generated = self.generated;
        let width = self.types.value_width(parameter.ty)?;
        let mut vars: Vec<Var> = classes
            .iter()
            .filter(|class| class.parameter == Some(index))
            .flat_map(|class| class.values.iter().filter_map(|&v| generated.var(v)))
            .collect();
        vars.extend(parameter.values.iter().filter_map(|&v| generated.var(v)));
        vars.extend(
            parameter
                .slot
                .and_then(|slot| generated.slots.get(slot).copied().flatten()),
        );
        let (ty, _) = self.join(vars.into_iter(), width);
        self.keep_declared(ty, parameter.evidence)
    }

    /// The type the program's signature of the function at `entry`
    /// ([`super::Schemes::signature`]) gives its parameter at `source`
    /// (`None`: its return value), interned, where it says more than a
    /// width and is `width` bits.
    fn table_type(&mut self, entry: u64, source: Option<Source>, width: u16) -> Option<TypeId> {
        let view = self.view;
        let signature = view.schemes.signature(entry)?;
        let field = match source {
            Some(source) => signature.parameter(source),
            None => signature.returns(),
        }?;
        let ty = view
            .schemes
            .structs()
            .field_type(field, self.types, &mut self.interned);
        (self.types.value_width(ty) == Some(width)).then_some(ty)
    }

    /// Whether a callee's parameter or result of type `ty` at a call takes
    /// the program's signature: untyped bits, or a pointer.
    fn open(&self, ty: TypeId) -> bool {
        matches!(self.types.get(ty), Some(Type::Bits(_) | Type::Pointer(_)))
    }

    /// `ty` where a declaration of `evidence` allows a deduced type.
    fn keep_declared(&self, ty: Option<TypeId>, evidence: Stated) -> Option<TypeId> {
        match evidence {
            Stated::Default | Stated::Deduced => ty,
            Stated::DeclaredPointer => {
                ty.filter(|&ty| matches!(self.types.get(ty), Some(Type::Pointer(_))))
            }
            Stated::Declared => None,
        }
    }

    /// The signature `signature` of calls to `callee` with its `bits`
    /// parameters and result typed by the roots of its scheme's instances
    /// at each place, and those (`bits` or pointers) its roots in the
    /// program's table point to the start of a struct a pointer to that
    /// struct (the callee's own type, as its definition prints it);
    /// `None` if they type none.
    fn signature(&mut self, callee: u64, signature: TypeId) -> Option<TypeId> {
        let generated = self.generated;
        let view = self.view;
        let none = Vec::new();
        let instances = generated.instances.get(&callee).unwrap_or(&none);
        // A call no instance of its callee's scheme types takes the
        // program's signature.
        let unscheme = instances.is_empty();
        let mut typed = self.types.signature(signature)?.clone();
        let call = view.calls.iter().find(|c| c.callee == Some(callee))?;
        let sources = &call.sources;
        // An allocator wrapper's result stays `void *`: any object's.
        let allocates = call.alloc_size.is_some();
        let mut changed = false;
        for (index, slot) in typed.parameters.iter_mut().enumerate() {
            let Some(&source) = sources.get(index) else {
                continue;
            };
            let width = self.types.value_width(*slot).unwrap_or(0);
            if unscheme
                && self.open(*slot)
                && let Some(ty) = self.table_type(callee, Some(source), width)
            {
                *slot = ty;
                changed = true;
                continue;
            }
            if let Some(ty) = self.root_struct(callee, Root::Parameter(source, width), *slot) {
                *slot = ty;
                changed = true;
                continue;
            }
            let Some(&Type::Bits(width)) = self.types.get(*slot) else {
                continue;
            };
            let vars = instances
                .iter()
                .filter(|&&(root, _)| root == Root::Parameter(source, width))
                .map(|&(_, var)| var);
            if let (Some(ty), _) = self.join(vars, width) {
                *slot = ty;
                changed = true;
            }
        }
        if let Some(returns) = typed.returns.filter(|_| !allocates) {
            let width = self.types.value_width(returns).unwrap_or(0);
            let table = if unscheme && self.open(returns) {
                self.table_type(callee, None, width)
            } else {
                None
            };
            if let Some(ty) =
                table.or_else(|| self.root_struct(callee, Root::Return(width), returns))
            {
                typed.returns = Some(ty);
                changed = true;
            }
        }
        if let Some(&Type::Bits(width)) = typed.returns.and_then(|ty| self.types.get(ty)) {
            let vars = instances
                .iter()
                .filter(|&&(root, _)| root == Root::Return(width))
                .map(|&(_, var)| var);
            if let (Some(ty), _) = self.join(vars, width) {
                typed.returns = Some(ty);
                changed = true;
            }
        }
        changed.then(|| self.types.intern(Type::Code(typed)))
    }

    /// A pointer to the struct whose start root `root` of `callee` points
    /// to in the program's table (if `callee` came first), where
    /// `current`, the root's type at the call, is pointer-wide `bits` or a
    /// pointer.
    fn root_struct(&mut self, callee: u64, root: Root, current: TypeId) -> Option<TypeId> {
        let pointer = self.types.pointer_width();
        let open = match self.types.get(current)? {
            &Type::Bits(width) => width == pointer,
            Type::Pointer(_) => true,
            Type::Int(_)
            | Type::UInt(_)
            | Type::Char { .. }
            | Type::Bool(_)
            | Type::Float(_)
            | Type::Code(_)
            | Type::Struct(_)
            | Type::Union(_)
            | Type::Array { .. }
            | Type::Vector { .. }
            | Type::Enum(_) => false,
        };
        if !open {
            return None;
        }
        let view = self.view;
        let (id, 0) = view.schemes.struct_root(view.l1.entry, callee, root)? else {
            return None;
        };
        let target = view
            .schemes
            .structs()
            .intern(id, self.types, &mut self.interned)?;
        Some(self.types.intern(Type::Pointer(Some(target))))
    }

    /// The return value's type: its variable's with the values returned
    /// (joined as a class: what a returned value is demanded as before it
    /// is returned is evidence of the return type too).
    fn returns(&mut self) -> Option<TypeId> {
        let view = self.view;
        let returns = &view.returns;
        let var = self.generated.returns?;
        let generated = self.generated;
        let returned = returns
            .values
            .iter()
            .chain(&returns.registers)
            .filter_map(|&v| generated.var(v));
        let vars: Vec<Var> = core::iter::once(var).chain(returned).collect();
        let (mut ty, _) = self.join(vars.into_iter(), returns.width);
        if let Some(object) = self.returned_struct() {
            ty = Some(object);
        }
        self.keep_declared(ty, returns.evidence.unwrap_or(Stated::Default))
    }

    /// Loads' and stores' types: their values', but a field's of a struct
    /// where they access one exactly, and a vector of a family's float
    /// elements where they access several at once
    /// ([`Self::access_lanes`]).
    fn accesses(&mut self, out: &mut BTreeMap<InstId, TypeId>) {
        let view = self.view;
        let generated = self.generated;
        let through: BTreeMap<InstId, (usize, Access)> = generated
            .families
            .families
            .iter()
            .enumerate()
            .flat_map(|(index, family)| {
                family
                    .accesses
                    .iter()
                    .map(move |&access| (access.inst, (index, access)))
            })
            .collect();
        let loads = view.shapes.iter().enumerate().filter_map(|(index, shape)| {
            let Some(Shape::Load(inst)) = shape else {
                return None;
            };
            Some((*inst, Value(u32::try_from(index).unwrap_or(u32::MAX))))
        });
        let stores = view.stores.iter().filter_map(|&inst| {
            let Some(&Op::Store { value, .. }) = view.l1.inst(inst).map(|i| &i.op) else {
                return None;
            };
            Some((inst, value))
        });
        let accesses: Vec<(InstId, Value)> = loads.chain(stores).collect();
        for (inst, value) in accesses {
            if let Some(ty) = self.access_field(inst) {
                out.insert(inst, ty);
                continue;
            }
            if let Some(&(family, access)) = through.get(&inst)
                && let Some(ty) = self.access_lanes(family, &access)
            {
                out.insert(inst, ty);
                continue;
            }
            let Some(var) = self.generated.var(value) else {
                continue;
            };
            if let Some((ty, _)) = self.of(var, view.width(value)) {
                out.insert(inst, ty);
            }
        }
    }

    /// The type of `access` (of family `index`) where it reads or writes
    /// several of the family's float elements at once: a vector of them,
    /// as many as it is wide, where it is wider than any scalar and its
    /// place is a whole number of elements (its offset, and what that is
    /// known modulo: [`period`]). Not in a struct of the program's
    /// table, whose fields say what each access is.
    fn access_lanes(&mut self, index: usize, access: &Access) -> Option<TypeId> {
        let family = self.generated.families.get(index)?;
        if access.bits <= 64 || self.struct_of(index, access.modulus).is_some() {
            return None;
        }
        let period = period(family, access);
        let (bits, element) = self.object(index, 0).element?;
        let bytes = i64::from(bits / 8);
        let float = matches!(self.types.get(element), Some(Type::Float(_)));
        let lanes = access.bits / bits;
        let placed = access.offset % bytes == 0
            && period.is_multiple_of(bytes.unsigned_abs())
            && access.bits.is_multiple_of(bits);
        (float && placed && lanes > 1).then(|| self.types.intern(Type::Vector { lanes, element }))
    }

    /// Variable `var`'s type at `width` bits, with its strength: its own
    /// ([`Self::own`]), but a pointer with no target there takes its
    /// cells' target ([`Self::cell_target`]).
    fn of(&mut self, var: Var, width: u16) -> Option<(TypeId, Strength)> {
        if let Some(&known) = self.memo.get(&(var, width)) {
            return known;
        }
        let mut rounded = self.own(var, width);
        if let Some((ty, strength)) = rounded
            && matches!(self.types.get(ty), Some(Type::Pointer(None)))
            && let Some(target) = self.cell_target(var)
        {
            rounded = Some((self.types.intern(Type::Pointer(Some(target))), strength));
        }
        self.memo.insert((var, width), rounded);
        rounded
    }

    /// The target of the pointers stored to and loaded from a place
    /// `var` is stored to or loaded from (or is): of the cell's members'
    /// own roundings to a pointer with a target, the strongest (the first
    /// on a tie); the first of `var`'s cells with one.
    fn cell_target(&mut self, var: Var) -> Option<TypeId> {
        let pointer = self.types.pointer_width();
        let cells = self.cell_of.get(&var).cloned().unwrap_or_default();
        for cell in cells {
            if let Some(&known) = self.cell_targets.get(&cell) {
                if known.is_some() {
                    return known;
                }
                continue;
            }
            // Not yet known: none while it is being found (a cell reached
            // again through its members' families).
            self.cell_targets.insert(cell, None);
            let members = self.cells.get(cell).cloned().unwrap_or_default();
            let mut best: Option<(TypeId, Strength)> = None;
            for member in members {
                let Some((ty, strength)) = self.own(member, pointer) else {
                    continue;
                };
                let Some(&Type::Pointer(Some(target))) = self.types.get(ty) else {
                    continue;
                };
                if best.is_none_or(|(_, kept)| strength > kept) {
                    best = Some((target, strength));
                }
            }
            let target = best.map(|(target, _)| target);
            self.cell_targets.insert(cell, target);
            if target.is_some() {
                return target;
            }
        }
        None
    }

    /// Variable `var`'s own type at `width` bits, with its strength.
    fn own(&mut self, var: Var, width: u16) -> Option<(TypeId, Strength)> {
        if let Some(&known) = self.owns.get(&(var, width)) {
            return known;
        }
        let answer = self.solution.answer(var);
        let pointer = self.types.pointer_width();
        let code = if width == pointer {
            self.code(&answer)
        } else {
            None
        };
        let rounded = if let Some(code) = code {
            Some(code)
        } else if let Some(pointer) = self.member(var, &answer, width) {
            Some(pointer)
        } else if answer.pointer && width == pointer {
            let strength = self
                .strength(&answer, |term| matches!(term, Term::Pointer(_)))
                .unwrap_or_default();
            let target = self.target(&answer);
            Some((self.types.intern(Type::Pointer(target)), strength))
        } else {
            self.atom(&answer, width)
        };
        self.owns.insert((var, width), rounded);
        rounded
    }

    /// The signature of a call through a value whose code bound stands on
    /// `answer` (the strongest such, one a prototype or interface states
    /// over the convention's guess), with its strength.
    fn code(&self, answer: &Answer) -> Option<(TypeId, Strength)> {
        self.stated_code(answer)
            .map(|(signature, strength, _)| (signature, strength))
    }

    /// [`Self::code`], with whether the signature is the convention's
    /// guess (a call through an unknown pointer, the address of a
    /// function no prototype or interface describes yet): evidence that
    /// the value is code, not of its signature.
    fn stated_code(&self, answer: &Answer) -> Option<(TypeId, Strength, bool)> {
        let solution = self.solution;
        answer
            .lower
            .iter()
            .chain(&answer.upper)
            .filter_map(|bound| {
                let constraint = solution.constraint(solution.origin(bound.term)?)?;
                let &(signature, guessed) = match (&constraint.lhs, &constraint.rhs) {
                    (Term::Var(target), Term::Code(_)) => self.generated.called.get(target)?,
                    (Term::Code(_), Term::Var(function)) => {
                        let address = self.generated.functions.get(function)?;
                        self.view.codes.get(address)?
                    }
                    _ => return None,
                };
                Some((signature, bound.evidence.strength, guessed))
            })
            .max_by_key(|&(_, strength, guessed)| (strength, !guessed))
    }

    /// The functions whose addresses reach `var` (the origins of its code
    /// bounds that are a function's address), by entry, in order.
    fn functions_reaching(&self, var: Var) -> Vec<u64> {
        let solution = self.solution;
        let answer = solution.answer(var);
        let mut functions: Vec<u64> = answer
            .lower
            .iter()
            .chain(&answer.upper)
            .filter_map(|bound| {
                let constraint = solution.constraint(solution.origin(bound.term)?)?;
                match (&constraint.lhs, &constraint.rhs) {
                    (Term::Code(_), Term::Var(function)) => {
                        self.generated.functions.get(function).copied()
                    }
                    _ => None,
                }
            })
            .collect();
        functions.sort_unstable();
        functions.dedup();
        functions
    }

    /// The strongest evidence among `answer`'s standing bounds whose term
    /// passes `kind`, if one does.
    fn strength(&self, answer: &Answer, kind: impl Fn(&Term) -> bool) -> Option<Strength> {
        let mut found = false;
        let strength = strongest(
            answer
                .lower
                .iter()
                .chain(&answer.upper)
                .filter(|bound| self.solution.term(bound.term).is_some_and(&kind))
                .map(|bound| {
                    found = true;
                    bound.evidence.strength
                }),
        );
        found.then_some(strength)
    }

    /// The informative atom of `answer` at `width` bits: its lower bounds'
    /// join, else its upper bounds' meet; an enumeration's value its
    /// enumeration ([`Self::enumeration`]).
    fn atom(&mut self, answer: &Answer, width: u16) -> Option<(TypeId, Strength)> {
        let (atom, strength) = atom_of(answer, width)?;
        if let Some(ty) = self.enumeration(atom) {
            return Some((ty, strength));
        }
        let ty = scalar(atom)?;
        Some((self.types.intern(ty), strength))
    }

    /// The enumeration type `atom` is a value of: its id in the view's
    /// types (which `types` extends), where that is an enumeration of its
    /// width and signedness.
    fn enumeration(&self, atom: Atom) -> Option<TypeId> {
        let Atom::Enum { id, width, signed } = atom else {
            return None;
        };
        let ty = TypeId(id);
        let declared = self.view.types.get(ty)?;
        let Type::Enum(enumeration) = declared else {
            return None;
        };
        let same = enumeration.width == width && enumeration.signed == signed;
        (same && self.types.get(ty) == Some(declared)).then_some(ty)
    }

    /// The target of a pointer: its views' fields' type where they have
    /// one width dividing every offset, else nothing (`void *`).
    fn target(&mut self, answer: &Answer) -> Option<TypeId> {
        let solution = self.solution;
        let mut fields: Vec<(i64, u16, Option<Var>)> = Vec::new();
        for &view in answer.loads.iter().chain(&answer.stores) {
            let found = solution.answer(view).fields;
            fields.extend(
                found
                    .into_iter()
                    .map(|(field, var)| (field.offset, field.bits, Some(var))),
            );
        }
        self.element(&fields, 0, usize::MAX, 0).map(|(_, ty)| ty)
    }

    /// The pointer `var` (`width` bits) is as a member of a pointer
    /// family: where a member is a pointer by evidence of at least Access
    /// strength, every member is, unless its own non-pointer evidence is
    /// stronger and at least Float; its target is the family's element
    /// where its offset is a whole number of elements.
    fn member(&mut self, var: Var, answer: &Answer, width: u16) -> Option<(TypeId, Strength)> {
        if width != self.types.pointer_width() {
            return None;
        }
        let (family, offset, modulus) = self.generated.families.of(var)?;
        let object = self.object(family, 0);
        let strength = object.strength.filter(|&s| s >= rank::ACCESS)?;
        let other = self.strength(answer, |term| matches!(term, Term::Atom(_)));
        if other.is_some_and(|other| other > strength && other >= rank::FLOAT) {
            return None;
        }
        let target = match self.struct_of(family, modulus) {
            Some(identity) => self.struct_target(identity, offset),
            None => self.target_in(family, offset, modulus, 0),
        };
        Some((self.types.intern(Type::Pointer(target)), strength))
    }

    /// The target of the member of family `index` at `offset` from its
    /// root (known modulo `modulus`): the family's element where `offset`
    /// and `modulus` are whole numbers of elements; with no element
    /// (fields of several widths: a struct), the element of the fields at
    /// `offset` itself (modulo the stride and `modulus`).
    fn target_in(&mut self, index: usize, offset: i64, modulus: u64, depth: u8) -> Option<TypeId> {
        if let Some(&known) = self.targets.get(&(index, offset, modulus, depth)) {
            return known;
        }
        let object = self.object(index, depth);
        let target = if let Some((bits, ty)) = object.element {
            let bytes = bits / 8;
            (offset % i64::from(bytes) == 0 && modulus.is_multiple_of(u64::from(bytes)))
                .then_some(ty)
        } else {
            let stride = gcd(
                self.generated
                    .families
                    .get(index)
                    .map_or(0, |family| family.stride),
                modulus,
            );
            let at: Vec<(i64, u16, Option<Var>)> = self
                .layouts
                .get(&index)
                .map(|fields| {
                    fields
                        .iter()
                        .map(|&(at, bits, value)| (at.wrapping_sub(offset), bits, value))
                        .filter(|&(at, _, _)| match i64::try_from(stride) {
                            Ok(stride) if stride > 0 => at % stride == 0,
                            Ok(_) | Err(_) => at == 0,
                        })
                        .collect()
                })
                .unwrap_or_default();
            self.element(&at, stride, index, depth).map(|(_, ty)| ty)
        };
        self.targets.insert((index, offset, modulus, depth), target);
        target
    }

    /// Family `index` as one object, its pointer fields' targets rounded
    /// if `depth` is 0: its members' strongest pointer evidence, and the
    /// element of its fields (the accesses through members and the fields
    /// of the views their pointer bounds reach, at offsets from the root,
    /// where [`counts`] says they are at a known element): one width `w`
    /// (whole bytes) with every offset and the stride whole numbers of
    /// `w / 8` bytes; the fields' type if they agree, else `bits(w)`.
    /// Where they agree on none, the float its own accesses step through
    /// or move several of at once ([`Self::lanes`]): what a callee's
    /// scheme says of memory it is passed (`memcpy`'s words) does not
    /// decide that.
    fn object(&mut self, index: usize, depth: u8) -> Object {
        if let Some(&known) = self.objects.get(&(index, depth)) {
            return known;
        }
        let generated = self.generated;
        let solution = self.solution;
        let Some(family) = generated.families.get(index) else {
            return Object::default();
        };
        let mut strength = None;
        let mut fields: Vec<(i64, u16, Option<Var>)> = family
            .accesses
            .iter()
            .filter(|access| counts(access.modulus, access.bits))
            .map(|access| (access.offset, access.bits, access.value))
            .collect();
        for &(var, offset, modulus) in &family.members {
            let answer = solution.answer(var);
            if let Some(found) = self.strength(&answer, |term| matches!(term, Term::Pointer(_))) {
                strength = strength.max(Some(found));
            }
            for &view in answer.loads.iter().chain(&answer.stores) {
                for (field, value) in solution.answer(view).fields {
                    if counts(modulus, field.bits) {
                        fields.push((offset.wrapping_add(field.offset), field.bits, Some(value)));
                    }
                }
            }
        }
        let element = self
            .element(&fields, family.stride, index, depth)
            .or_else(|| {
                let own: Vec<(i64, u16, Option<Var>)> = family
                    .accesses
                    .iter()
                    .filter(|access| counts(access.modulus, access.bits))
                    .map(|access| (access.offset, access.bits, access.value))
                    .collect();
                self.lanes(&own, family.stride, index, depth)
            });
        self.layouts.insert(index, fields);
        let object = Object { strength, element };
        self.objects.insert((index, depth), object);
        object
    }

    /// The element of `fields` (offset, width, value) with offsets known
    /// modulo `stride`: see [`Self::object`].
    fn element(
        &mut self,
        fields: &[(i64, u16, Option<Var>)],
        stride: u64,
        within: usize,
        depth: u8,
    ) -> Option<(u16, TypeId)> {
        let &(_, bits, _) = fields.first()?;
        let bytes = i64::from(bits / 8);
        let aligned = bits % 8 == 0
            && bytes > 0
            && stride.is_multiple_of(bytes.unsigned_abs())
            && fields
                .iter()
                .all(|&(offset, width, _)| width == bits && offset % bytes == 0);
        if !aligned {
            return None;
        }
        let ty = self.fields_type(fields, bits, within, depth);
        Some((bits, self.types.intern(ty)))
    }

    /// The float element of `fields` (offset, width, value; offsets known
    /// modulo `stride`), a family's own accesses: of the narrowest width
    /// `w` (32 or 64 bits), a float's by the strongest evidence of the
    /// fields of that width, where every wider field is several such
    /// elements moved at once (a whole number of them, at an offset that
    /// is a whole number of elements, its value of no type of its own: a
    /// SIMD load or store of the array, `movups`, or a copy's word; not a
    /// value an operation makes an integer); with no wider field, only
    /// where the family steps through the array (a stride). Every offset
    /// and the stride are whole numbers of elements.
    fn lanes(
        &mut self,
        fields: &[(i64, u16, Option<Var>)],
        stride: u64,
        within: usize,
        depth: u8,
    ) -> Option<(u16, TypeId)> {
        let bits = fields.iter().map(|&(_, width, _)| width).min()?;
        let uniform = fields.iter().all(|&(_, width, _)| width == bits);
        if !matches!(bits, 32 | 64) || (uniform && stride == 0) {
            return None;
        }
        let bytes = i64::from(bits / 8);
        if !stride.is_multiple_of(bytes.unsigned_abs()) {
            return None;
        }
        let mut narrow = Vec::new();
        for &(offset, width, value) in fields {
            if offset % bytes != 0 || !width.is_multiple_of(bits) {
                return None;
            }
            if width == bits {
                narrow.push((offset, width, value));
            } else if value.is_some_and(|value| {
                self.field_type(value, width, within, depth)
                    .is_some_and(|(ty, _)| !matches!(ty, Type::Bits(_)))
            }) {
                return None;
            }
        }
        let ty = self.fields_type(&narrow, bits, within, depth);
        matches!(ty, Type::Float(_)).then(|| (bits, self.types.intern(ty)))
    }

    /// The type of `fields`' values (each `bits` wide): the strongest
    /// field type; types that differ at the strongest evidence give
    /// `bits(w)`. A field with no evidence says nothing; none: `bits(w)`.
    fn fields_type(
        &mut self,
        fields: &[(i64, u16, Option<Var>)],
        bits: u16,
        within: usize,
        depth: u8,
    ) -> Type {
        let mut best: Option<(Option<Type>, Strength)> = None;
        for &(_, _, value) in fields {
            let Some((ty, strength)) =
                value.and_then(|value| self.field_type(value, bits, within, depth))
            else {
                continue;
            };
            best = match best {
                Some((kept, kept_strength)) if kept_strength > strength => {
                    Some((kept, kept_strength))
                }
                Some((kept, kept_strength))
                    if kept_strength == strength && kept.as_ref() != Some(&ty) =>
                {
                    Some((None, strength))
                }
                Some(_) | None => Some((Some(ty), strength)),
            };
        }
        best.and_then(|(ty, _)| ty).unwrap_or(Type::Bits(bits))
    }

    /// A field's type, with its strength: code (a value loaded and called,
    /// as [`Self::own`] rounds it), a pointer (to its family's
    /// element if `depth` is 0 and it is not of family `within`, else to
    /// nothing known; where `depth` is 0, not of `within` and no target is
    /// found so, to its cells' target), else its informative atom.
    fn field_type(
        &mut self,
        var: Var,
        bits: u16,
        within: usize,
        depth: u8,
    ) -> Option<(Type, Strength)> {
        let answer = self.solution.answer(var);
        if bits == self.types.pointer_width() {
            if let Some((code, strength)) = self.code(&answer)
                && let Some(ty) = self.types.get(code)
            {
                return Some((ty.clone(), strength));
            }
            let found = self.generated.families.of(var);
            let outside = depth == 0 && found.is_none_or(|(family, _, _)| family != within);
            if let Some((family, offset, modulus)) = found
                && outside
            {
                let object = self.object(family, depth + 1);
                if let Some(strength) = object.strength.filter(|&s| s >= rank::ACCESS) {
                    let target = match self.struct_of(family, modulus) {
                        Some(identity) => self.struct_target(identity, offset),
                        None => match self.target_in(family, offset, modulus, depth + 1) {
                            Some(target) => Some(target),
                            None => self.cell_target(var),
                        },
                    };
                    return Some((Type::Pointer(target), strength));
                }
            }
            if let Some(strength) = self.strength(&answer, |term| matches!(term, Term::Pointer(_)))
            {
                let target = if outside { self.cell_target(var) } else { None };
                return Some((Type::Pointer(target), strength));
            }
        }
        let (atom, strength) = atom_of(&answer, bits)?;
        Some((scalar(atom)?, strength))
    }
}

/// The informative atom of `answer` at `width` bits, with its strength:
/// its lower bounds' join, else its upper bounds' meet.
fn atom_of(answer: &Answer, width: u16) -> Option<(Atom, Strength)> {
    let lower = informative(answer.lower_atom, width).map(|atom| (atom, &answer.lower));
    let upper = informative(answer.upper_atom, width).map(|atom| (atom, &answer.upper));
    let (atom, bounds) = lower.or(upper)?;
    let strength = strongest(
        bounds
            .iter()
            .filter(|bound| bound.atom.is_some())
            .map(|bound: &Bound| bound.evidence.strength),
    );
    Some((atom, strength))
}

/// Whether `family` may be a struct: with no stride, or as an array of
/// structs ([`element`]).
fn structured(family: &Family) -> bool {
    family.stride == 0 || element(family).is_some()
}

/// Per family of `generated` (from `view`): the struct of the program's
/// table it is, with the offset of its root in it ([`Identified`]). A
/// family with a stride is one only as an array of structs; one with an
/// access the table assigns is that access's; else one passed to a
/// callee (or holding a callee's result) whose root points into a struct
/// is that struct, and one loaded from or stored to a field of a struct
/// family that points to a struct is that struct (to a fixed point);
/// several claims at one offset are one struct (to unite; the first by
/// [`Structs::rank`](super::Structs) kept), at different offsets a
/// conflict (the first kept); else, if `born` and it qualifies
/// ([`qualifies`]), a new struct of this function, numbered from 1 by its
/// first access (the smallest instruction), with its root placed so that
/// its first object member (a parameter's value or a loaded pointer; else
/// its first access) and every access are at offsets from 0.
fn identify(view: &View<'_>, generated: &Generated, born: bool) -> Identified {
    let structs = view.schemes.structs();
    let entry = view.l1.entry;
    let families = &generated.families;
    let identities: Vec<Option<(StructId, i64)>> = families
        .families
        .iter()
        .map(|family| {
            if !structured(family) {
                return None;
            }
            family
                .accesses
                .iter()
                .find_map(|access| structs.access(entry, access.inst))
        })
        .collect();
    let mut found = Identified {
        identities,
        allocations: allocations(view, generated),
        ..Identified::default()
    };
    let mut claims: BTreeMap<usize, Vec<(StructId, i64)>> = BTreeMap::new();
    // A value in no family (passed on untouched) that callees' roots
    // claim is one object all the same.
    let mut loose: BTreeMap<Var, Vec<(StructId, i64)>> = BTreeMap::new();

    for call in &view.calls {
        let Some(callee) = call.callee else {
            continue;
        };
        let arguments = call
            .sources
            .iter()
            .zip(&call.arguments)
            .flat_map(|(&source, values)| {
                values
                    .iter()
                    .map(move |&value| (value, Root::Parameter(source, view.width(value))))
            });
        let results = call
            .result
            .iter()
            .map(|&value| (value, Root::Return(view.width(value))));
        for (value, root) in arguments.chain(results) {
            let Some((id, offset)) = view.schemes.struct_root(entry, callee, root) else {
                continue;
            };
            let Some(var) = generated.var(value) else {
                continue;
            };
            match families.of(var) {
                Some((index, at, 0)) => claims
                    .entry(index)
                    .or_default()
                    .push((id, offset.wrapping_sub(at))),
                Some(_) => {}
                None => loose.entry(var).or_default().push((id, offset)),
            }
        }
    }
    for (_, mut claimed) in loose {
        claimed.sort_unstable_by_key(|&(id, base)| (structs.rank(id), base));
        claimed.dedup();
        if let Some((&(kept, base), rest)) = claimed.split_first() {
            for &(id, at) in rest {
                if at == base && id != kept {
                    found.merges.push((kept, id));
                }
            }
        }
    }
    // A global object is the struct the table has for it, whatever its
    // accesses here look like (first: its identity is the program's).
    let mut globals: BTreeMap<usize, Vec<(StructId, i64)>> = BTreeMap::new();
    for (&start, &var) in &generated.objects {
        if let Some((id, offset)) = structs.global(start)
            && let Some((index, at, 0)) = families.of(var)
        {
            globals
                .entry(index)
                .or_default()
                .push((id, offset.wrapping_sub(at)));
        }
    }
    found.claim(view, generated, globals, true);
    found.claim(view, generated, claims, false);
    // The values one pointer global holds are the struct the program's
    // type of the global points to, as a field's are.
    let pointees = global_pointees(view, generated, &found.identities);
    found.claim(view, generated, pointees, false);
    // Fields that point to structs claim what is loaded from and stored
    // to them, to a fixed point (each round claims a family at most once).
    for _ in 0..families.families.len() {
        let (claims, merges) = field_claims(view, generated, &found.identities);
        if claims.is_empty() {
            found.merges.extend(merges);
            break;
        }
        found.claim(view, generated, claims, false);
    }
    if born {
        self::born(view, generated, &mut found.identities, &found.allocations);
    }
    found
}

/// What [`identify`] finds.
#[derive(Debug, Default)]
struct Identified {
    /// Per family: the struct it is, with the offset of its root in it.
    identities: Vec<Option<(StructId, i64)>>,
    /// Families claimed by structs at different offsets.
    conflicts: usize,
    /// Structs claiming one family at one offset (one struct).
    merges: Vec<(StructId, StructId)>,
    /// The families holding allocations of a known size ([`allocations`]).
    allocations: BTreeMap<usize, Option<(i64, u64)>>,
}

impl Identified {
    /// Takes `claims` (per family, the structs it is by its calls or its
    /// fields, with its root's offset in each): a family already
    /// identified at a claim's offset is one struct with it; an
    /// unidentified one takes the first by rank of the claims at the
    /// offset of the first, the others there one struct with it and
    /// those elsewhere a conflict. Unless `global` (the table's struct of
    /// a global object), not one holding a global its accesses show as
    /// an array of scalars ([`scalar_global`]). A claim on a family
    /// holding an allocation of known size is kept only where the
    /// allocation starts the struct and the struct fits it (as large as
    /// it where the table knows its size): not one object otherwise.
    fn claim(
        &mut self,
        view: &View<'_>,
        generated: &Generated,
        claims: BTreeMap<usize, Vec<(StructId, i64)>>,
        global: bool,
    ) {
        let structs = view.schemes.structs();
        for (index, claimed) in claims {
            let allocation = self.allocations.get(&index).copied().flatten();
            let stride = generated
                .families
                .get(index)
                .map_or(0, |family| family.stride);
            let before = claimed.len();
            let mut claimed: Vec<(StructId, i64)> = claimed
                .into_iter()
                .map(|(id, base)| (structs.find(id), base))
                .filter(|&(id, base)| {
                    allocation.is_none_or(|(offset, size)| {
                        structs.layout(id).is_some_and(|layout| {
                            place(offset, base, stride) == 0
                                && layout.natural_size() <= size
                                && (layout.allocated == 0 || layout.allocated == size)
                        })
                    })
                })
                .collect();
            self.conflicts += before - claimed.len();
            claimed.sort_unstable_by_key(|&(id, base)| (structs.rank(id), base));
            claimed.dedup();
            let free = generated.families.get(index).is_some_and(|family| {
                structured(family) && (global || !scalar_global(generated, family))
            });
            let Some(slot) = self.identities.get_mut(index) else {
                continue;
            };
            if slot.is_none() && free {
                *slot = claimed.first().copied();
            }
            let Some((kept, base)) = *slot else {
                continue;
            };
            for &(id, at) in &claimed {
                if at != base {
                    self.conflicts += 1;
                } else if id != kept {
                    self.merges.push((kept, id));
                }
            }
        }
    }
}

/// The claims fields make (see [`identify`]): per family not identified
/// by `identities` whose member (of modulus 0) is loaded from or stored
/// to a pointer-wide field of an identified family that the table types
/// as a pointer to a struct, that struct with the root's offset in it;
/// and for an identified family with such a member at that offset, the
/// pair of its struct and the field's where they differ (one struct).
fn field_claims(
    view: &View<'_>,
    generated: &Generated,
    identities: &[Option<(StructId, i64)>],
) -> (Claims, Vec<(StructId, StructId)>) {
    let structs = view.schemes.structs();
    let families = &generated.families;
    let pointer = view.types.pointer_width();
    let mut claims: BTreeMap<usize, Vec<(StructId, i64)>> = BTreeMap::new();
    let mut merges = Vec::new();
    for (family, identity) in families.families.iter().zip(identities) {
        let Some((id, base)) = *identity else {
            continue;
        };
        let Some(layout) = structs.layout(id) else {
            continue;
        };
        for access in &family.accesses {
            if access.bits != pointer || !counted(access, family.stride) {
                continue;
            }
            let Ok(at) = u64::try_from(place(access.offset, base, family.stride)) else {
                continue;
            };
            let Some(&FieldType::Struct(target)) = layout.fields.get(&at).map(|field| &field.ty)
            else {
                continue;
            };
            let Some((index, offset, 0)) = access.value.and_then(|value| families.of(value)) else {
                continue;
            };
            let target = structs.find(target);
            let claim = (target, offset.wrapping_neg());
            match identities.get(index).copied().flatten() {
                Some((known, at)) => {
                    if at == claim.1 && structs.find(known) != target {
                        merges.push((known, target));
                    }
                }
                None => {
                    if families
                        .get(index)
                        .is_some_and(|family| structured(family) && !indexed(family))
                    {
                        claims.entry(index).or_default().push(claim);
                    }
                }
            }
        }
    }
    (claims, merges)
}

/// Whether `family` is indexed (an access or a member with an index: an
/// array, whose start is no struct a field says).
fn indexed(family: &Family) -> bool {
    family.accesses.iter().any(|access| access.indexed)
        || family.members.iter().any(|&(_, _, modulus)| modulus != 0)
}

/// The claims pointer globals make (see [`identify`]): per family not
/// identified by `identities` whose member (of modulus 0) is loaded from
/// or stored to a global accessed whole whose program type
/// ([`super::Globals`]) is a pointer to a struct of the table, that struct
/// with the root's offset in it; where it is a pointer to pointers to a
/// struct ([`FieldType::Pointers`]), per such family whose member is an
/// element of an array of pointers ([`pointer_array`]) a value of the
/// global points to.
fn global_pointees(
    view: &View<'_>,
    generated: &Generated,
    identities: &[Option<(StructId, i64)>],
) -> Claims {
    let structs = view.schemes.structs();
    let globals = view.schemes.globals();
    let families = &generated.families;
    let pointer = view.types.pointer_width();
    let mut claims = Claims::new();
    for (&at, &(var, bits)) in &generated.globals {
        let Some(GlobalShape::Value(field)) = globals.get(at).map(|ty| &ty.shape) else {
            continue;
        };
        let (id, held) = match *field {
            FieldType::Struct(id) => (id, false),
            FieldType::Pointers(id) => (id, true),
            FieldType::Scalar(_)
            | FieldType::Pointer(_)
            | FieldType::Opaque
            | FieldType::ScalarPointers(_)
            | FieldType::Code { .. } => continue,
        };
        if bits != pointer {
            continue;
        }
        let id = structs.find(id);
        let cells = generated.cells.get(&var).into_iter().flatten().copied();
        let members: Vec<Var> = if held {
            cells
                .filter_map(|cell| families.of(cell))
                .filter_map(|(index, _, _)| families.get(index))
                .filter(|family| pointer_array(family, pointer))
                .flat_map(|family| family.accesses.iter().filter_map(|access| access.value))
                .collect()
        } else {
            cells.collect()
        };
        for cell in members {
            let Some((index, offset, 0)) = families.of(cell) else {
                continue;
            };
            let free = identities.get(index).is_some_and(Option::is_none);
            // An element's object reached only through accesses at the
            // struct's fields (a part of a wider one), else as today.
            let fits = !held
                || families.get(index).is_some_and(|family| {
                    structs.layout(id).is_some_and(|layout| {
                        family.accesses.iter().all(|access| {
                            u64::try_from(access.offset.wrapping_sub(offset))
                                .ok()
                                .and_then(|at| layout.fields.get(&at))
                                .is_some_and(|field| field.bits >= access.bits)
                        })
                    })
                });
            if free
                && fits
                && families
                    .get(index)
                    .is_some_and(|family| structured(family) && !indexed(family))
            {
                claims
                    .entry(index)
                    .or_default()
                    .push((id, offset.wrapping_neg()));
            }
        }
    }
    claims
}

/// Per family: the structs it is claimed to be, with its root's offset
/// in each.
type Claims = BTreeMap<usize, Vec<(StructId, i64)>>;

/// Whether `family` is an array of pointers (`pointer` bits wide): its
/// accesses all of one element, as wide as a pointer, through an index
/// (in the access or the member it is through) or a stride, at one offset
/// in it (their offsets alike modulo the element: `p[i]` and `p[i + 1]`),
/// each known modulo exactly one element ([`period`]: `p + i·16` read 8
/// bytes at a time is a field of an array of 16-byte elements).
fn pointer_array(family: &Family, pointer: u16) -> bool {
    let bytes = u64::from(pointer / 8);
    let element = i64::from(pointer / 8);
    family.accesses.first().is_some_and(|first| {
        family.accesses.iter().all(|access| {
            access.bits == pointer
                && period(family, access) == bytes
                && access.offset.rem_euclid(element) == first.offset.rem_euclid(element)
        })
    })
}

/// The size of the object family `index` (of no stride, its root at
/// `base` in its struct) is where it starts the struct: an allocation's
/// of known size (`allocations`), else a global object's of the image.
fn allocated(
    view: &View<'_>,
    generated: &Generated,
    allocations: &BTreeMap<usize, Option<(i64, u64)>>,
    index: usize,
    base: i64,
) -> Option<u64> {
    let starts = |offset: i64| offset.wrapping_add(base) == 0;
    if let Some(&Some((offset, size))) = allocations.get(&index)
        && starts(offset)
    {
        return Some(size);
    }
    let (&start, _) = generated.objects.iter().find(|&(_, &var)| {
        generated
            .families
            .of(var)
            .is_some_and(|(at, offset, modulus)| at == index && modulus == 0 && starts(offset))
    })?;
    Some(view.data.object(start)?.size)
}

/// The offset in `family` of the start of a global object it holds (the
/// smallest, if several), if it holds one.
fn global_start(generated: &Generated, family: &Family) -> Option<i64> {
    family
        .members
        .iter()
        .filter(|&&(var, _, modulus)| {
            modulus == 0 && generated.objects.values().any(|&object| object == var)
        })
        .map(|&(_, offset, _)| offset)
        .min()
}

/// Whether `family` holds a global object its accesses show as an array
/// of scalars ([`uniform`]: one width at multiples of it from the
/// object's start), so no struct (a table of pointers indexed by
/// constants is no struct, whatever it is passed to).
fn scalar_global(generated: &Generated, family: &Family) -> bool {
    global_start(generated, family).is_some_and(|origin| uniform(family, origin))
}

/// The structs born in the function `view` shows (as `generated` gives
/// it), for the families `identities` leaves unclaimed: the families one
/// value reaches (the values returned; those stored to and loaded from
/// one stack slot or global object) are one struct if any of them
/// qualifies ([`qualifies`]), numbered from 1 by their first access (the
/// smallest instruction); each family's root is placed so that its first
/// object member (a parameter's value or a loaded pointer; else its first
/// exact access) and every exact access are at offsets from 0; an array's
/// element (a family with a stride) starts where its stepped pointers
/// (scalar evolutions) point.
fn born(
    view: &View<'_>,
    generated: &Generated,
    identities: &mut [Option<(StructId, i64)>],
    allocations: &BTreeMap<usize, Option<(i64, u64)>>,
) {
    let families = &generated.families;
    let objects = objects(view, generated);
    let stepped = stepped(view, generated);
    let free = |index: usize| {
        identities.get(index).is_some_and(Option::is_none)
            && families.get(index).is_some_and(structured)
    };
    let parent = joined(view, generated, &free, &objects, allocations);
    let (polymorphic, tables) = polymorphic(view, generated);
    let mut groups: BTreeMap<usize, Group> = BTreeMap::new();
    for (index, family) in families.families.iter().enumerate() {
        if !free(index) {
            continue;
        }
        let fields = family
            .accesses
            .iter()
            .filter(|access| counted(access, family.stride));
        // An allocation its own accesses reach past is not one object.
        let overflows = allocations
            .get(&index)
            .copied()
            .flatten()
            .is_some_and(|(at, n)| {
                let end = at.wrapping_add(i64::try_from(n).unwrap_or(i64::MAX));
                family.stride == 0
                    && fields.clone().any(|access| {
                        access.offset < at
                            || access.offset.wrapping_add(i64::from(access.bits / 8)) > end
                    })
            });
        if overflows {
            continue;
        }
        let anchor = family
            .members
            .iter()
            .filter(|&&(var, _, modulus)| modulus == 0 && objects.contains(&var))
            .map(|&(_, offset, _)| offset)
            .min()
            .or_else(|| fields.clone().map(|access| access.offset).min())
            .unwrap_or(0);
        let lowest = fields.map(|access| access.offset).min().unwrap_or(anchor);
        // A global object starts its struct (or its first element); an
        // array's element starts where its stepped pointers point
        // (`p + d·i` is `&base[i]`), whatever it accesses first.
        let global = global_start(generated, family);
        let start = global.unwrap_or_else(|| {
            family
                .members
                .iter()
                .filter(|&&(var, _, _)| family.stride > 0 && stepped.contains(&var))
                .map(|&(_, offset, _)| offset)
                .min()
                .unwrap_or_else(|| anchor.min(lowest))
        });
        let group = groups.entry(root(&parent, index)).or_default();
        // A global's accesses of one width at multiples of it are an
        // array of scalars, not a struct; nor are bytes read one by one.
        let scalars = scalar_global(generated, family) || bytes(family);
        group.qualifies |= !scalars && qualifies(family, |var| objects.contains(&var))
            || polymorphic.contains(&index)
            || tables.contains(&index);
        let first = family.accesses.iter().map(|access| access.inst).min();
        group.first = match (group.first, first) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        group.members.push((index, start));
    }
    let mut new: Vec<(InstId, Vec<(usize, i64)>)> = groups
        .into_values()
        .filter_map(|group| Some((group.first.filter(|_| group.qualifies)?, group.members)))
        .collect();
    new.sort_unstable();
    let function = view.l1.entry;
    for (k, (_, members)) in (1u32..).zip(new) {
        for (index, start) in members {
            if let Some(slot) = identities.get_mut(index) {
                *slot = Some((StructId { function, k }, start.wrapping_neg()));
            }
        }
    }
}

/// The union-find of [`born`]'s groups over the families `free` admits:
/// those one value reaches (the values returned; those stored to and
/// loaded from one stack slot or global object) are one, but two
/// allocations of different sizes, or an allocation and an object whose
/// accesses (from its `objects` member, else its first access) reach past
/// it, are two objects.
fn joined(
    view: &View<'_>,
    generated: &Generated,
    free: &dyn Fn(usize) -> bool,
    objects: &BTreeSet<Var>,
    allocations: &BTreeMap<usize, Option<(i64, u64)>>,
) -> Vec<usize> {
    let families = &generated.families;
    let mut parent: Vec<usize> = (0..families.families.len()).collect();
    let returned = view.returns.values.iter().filter_map(|&v| generated.var(v));
    let sets = core::iter::once(returned.collect::<Vec<Var>>()).chain(
        generated
            .cells
            .iter()
            .map(|(&place, values)| values.iter().copied().chain([place]).collect()),
    );
    let size = |index: usize| {
        allocations
            .get(&index)
            .map(|allocation| allocation.map(|(_, size)| size))
    };
    // How far a family's accesses reach from its object's start (an
    // object member's offset, else its first access).
    let extent = |index: usize| {
        let family = families.get(index)?;
        let fields = family
            .accesses
            .iter()
            .filter(|access| counted(access, family.stride));
        let start = family
            .members
            .iter()
            .filter(|&&(var, _, modulus)| modulus == 0 && objects.contains(&var))
            .map(|&(_, offset, _)| offset)
            .min()
            .or_else(|| fields.clone().map(|access| access.offset).min())?;
        let end = fields
            .map(|access| access.offset.wrapping_add(i64::from(access.bits / 8)))
            .max()?;
        u64::try_from(end.wrapping_sub(start)).ok()
    };
    let apart = |a: usize, b: usize| match (size(a), size(b)) {
        // Two allocations of different sizes are two objects.
        (Some(x), Some(y)) => x != y,
        // An allocation is not an object whose fields reach past it.
        (Some(Some(n)), None) => extent(b).is_some_and(|reach| reach > n),
        (None, Some(Some(n))) => extent(a).is_some_and(|reach| reach > n),
        (Some(None) | None, None) | (None, Some(None)) => false,
    };
    for set in sets {
        let mut joined = set
            .iter()
            .filter_map(|&var| families.of(var))
            .filter(|&(index, _, modulus)| modulus == 0 && free(index))
            .map(|(index, _, _)| index);
        let Some(first) = joined.next() else {
            continue;
        };
        for other in joined {
            if apart(first, other) {
                continue;
            }
            let (a, b) = (root(&parent, first), root(&parent, other));
            if let Some(slot) = parent.get_mut(a.max(b)) {
                *slot = a.min(b);
            }
        }
    }
    parent
}

/// The root of `index` in the union-find `parent`.
fn root(parent: &[usize], mut index: usize) -> usize {
    while let Some(&up) = parent.get(index)
        && up != index
    {
        index = up;
    }
    index
}

/// Families one value reaches, to be one struct ([`born`]).
#[derive(Debug, Default)]
struct Group {
    /// Whether one of them qualifies as a struct.
    qualifies: bool,
    /// Their first access.
    first: Option<InstId>,
    /// Each family, with the offset its root is at.
    members: Vec<(usize, i64)>,
}

/// The variables of the objects of `view` (as `generated` gives them): its
/// parameters' values and the pointers it loads.
fn objects(view: &View<'_>, generated: &Generated) -> BTreeSet<Var> {
    let parameters = view
        .parameters
        .iter()
        .flat_map(|parameter| parameter.values.iter().copied());
    let loads = view
        .shapes
        .iter()
        .enumerate()
        .filter(|(_, shape)| matches!(shape, Some(Shape::Load(_))))
        .map(|(index, _)| Value(u32::try_from(index).unwrap_or(u32::MAX)));
    parameters
        .chain(loads)
        .filter_map(|value| generated.var(value))
        .collect()
}

/// The variables of the block parameters of `view` (as `generated` gives
/// them) that are scalar evolutions (`super::evolution`).
fn stepped(view: &View<'_>, generated: &Generated) -> BTreeSet<Var> {
    view.shapes
        .iter()
        .enumerate()
        .filter(|(_, shape)| matches!(shape, Some(Shape::Phi(_))))
        .map(|(index, _)| Value(u32::try_from(index).unwrap_or(u32::MAX)))
        .filter(|&value| view.evolutions.of(value).is_some())
        .filter_map(|value| generated.var(value))
        .collect()
}

/// Per family of `generated` (from `view`) holding the result of a call
/// to a callee declared `alloc_size` whose size arguments are constants:
/// the result's offset in the family and the object's size in bytes;
/// `None` where the family holds two allocations of different sizes at
/// one offset or at two offsets (not one object).
fn allocations(view: &View<'_>, generated: &Generated) -> BTreeMap<usize, Option<(i64, u64)>> {
    let mut found: BTreeMap<usize, Option<(i64, u64)>> = BTreeMap::new();
    for call in &view.calls {
        let Some(alloc) = call.alloc_size else {
            continue;
        };
        let argument = |index: usize| {
            let &value = call.arguments.get(index)?.first()?;
            u64::try_from(view.constant(value)?).ok()
        };
        let size = match alloc.count {
            Some(count) => argument(count)
                .zip(argument(alloc.size))
                .and_then(|(n, s)| n.checked_mul(s)),
            None => argument(alloc.size),
        };
        let Some(size) = size.filter(|&size| size > 0) else {
            continue;
        };
        for &value in &call.result {
            let Some((index, offset, 0)) = generated
                .var(value)
                .and_then(|var| generated.families.of(var))
            else {
                continue;
            };
            let entry = found.entry(index).or_insert(Some((offset, size)));
            if *entry != Some((offset, size)) {
                *entry = None;
            }
        }
    }
    found
}

/// What the function `view` shows adds to the program's structs
/// ([`Contribution`]), by `solution` of `generated`; types interned in
/// `types` (a scratch table: the contribution is portable).
pub(crate) fn contribution(
    view: &View<'_>,
    generated: &Generated,
    solution: &Solution,
    types: &mut Types,
) -> Contribution {
    let mut state = Rounder::new(view, generated, solution, types);
    let Identified {
        identities,
        conflicts,
        merges,
        allocations,
    } = identify(view, generated, true);
    state.identified(identities.clone());
    let objects = state.seen();
    let mut callees: Vec<u64> = view
        .calls
        .iter()
        .filter_map(|call| {
            call.callee.or_else(|| {
                let target = view.constant(call.target)?.cast_unsigned();
                view.functions.contains(&target).then_some(target)
            })
        })
        .collect();
    callees.sort_unstable();
    callees.dedup();
    let mut out = Contribution {
        conflicts,
        merges,
        callees,
        objects,
        ..Contribution::default()
    };
    for (index, identity) in identities.iter().enumerate() {
        let (Some((id, base)), Some(family)) = (*identity, generated.families.get(index)) else {
            continue;
        };
        let mut layout = state.layout(index, base);
        if family.stride == 0
            && let Some(size) = allocated(view, generated, &allocations, index, base)
        {
            layout.set_allocated(size);
        }
        out.layouts.entry(id).or_default().merge(layout);
        out.accesses
            .extend(family.accesses.iter().map(|access| (access.inst, id, base)));
        out.classes
            .extend(stored_classes(view, family, base).map(|class| (id, class)));
    }
    let (_, tables) = polymorphic(view, generated);
    out.tables.extend(
        tables
            .iter()
            .filter_map(|&index| Some(identities.get(index).copied().flatten()?.0)),
    );
    let at = |value: Value| {
        let (index, offset, modulus) = generated.families.of(generated.var(value)?)?;
        let (id, base) = identities.get(index).copied().flatten()?;
        let stride = generated.families.get(index)?.stride;
        (modulus == 0 || (stride > 0 && modulus.is_multiple_of(stride)))
            .then(|| (id, place(offset, base, stride)))
    };
    for (&start, &var) in &generated.objects {
        let Some((index, offset, 0)) = generated.families.of(var) else {
            continue;
        };
        let (Some((id, base)), Some(family)) = (
            identities.get(index).copied().flatten(),
            generated.families.get(index),
        ) else {
            continue;
        };
        out.globals
            .push((start, id, place(offset, base, family.stride)));
    }
    for parameter in &view.parameters {
        for &value in &parameter.values {
            if let Some((id, offset)) = at(value) {
                let root = Root::Parameter(parameter.source, view.width(value));
                out.roots.push((root, id, offset));
            }
        }
    }
    out.classes.extend(this_class(view, &at));
    if let Some((id, offset)) = state.returned_root() {
        out.roots
            .push((Root::Return(view.returns.width), id, offset));
    }
    out
}

/// The class whose primary virtual table's address point `access` (of
/// the function `view` shows) stores, as wide as a pointer, if it is such
/// a store.
fn vtable_stored(view: &View<'_>, access: &Access) -> Option<usize> {
    let Some(&Op::Store { value, .. }) = view.l1.inst(access.inst).map(|inst| &inst.op) else {
        return None;
    };
    if access.bits != view.types.pointer_width() {
        return None;
    }
    let address = view.constant(view.canonical(value))?.cast_unsigned();
    view.schemes.structs().classes().at_vtable(address)
}

/// The struct the first parameter of the function `view` shows points to
/// the start of (by `at`), as its class, where the function is a method
/// of one ([`Classes::method`](super::Classes::method)): `this`.
fn this_class(
    view: &View<'_>,
    at: &dyn Fn(Value) -> Option<(StructId, i64)>,
) -> Vec<(StructId, usize)> {
    let Some(class) = view.schemes.structs().classes().method(view.l1.entry) else {
        return Vec::new();
    };
    view.parameters
        .first()
        .into_iter()
        .flat_map(|this| this.values.iter())
        .filter_map(|&value| match at(value) {
            Some((id, 0)) => Some((id, class)),
            Some(_) | None => None,
        })
        .collect()
}

/// The classes whose virtual tables `family` (of the function `view`
/// shows, its root at `base` in its struct) stores at its struct's start
/// (a constructor's store: the object is that class).
fn stored_classes<'v>(
    view: &'v View<'_>,
    family: &'v Family,
    base: i64,
) -> impl Iterator<Item = usize> + 'v {
    family
        .accesses
        .iter()
        .filter(move |access| {
            family.stride == 0 && counted(access, 0) && place(access.offset, base, 0) == 0
        })
        .filter_map(|access| vtable_stored(view, access))
}

/// The families of `generated` (from `view`) that are structs whatever
/// their accesses, as C++ objects and virtual tables are (Itanium C++ ABI
/// §2.5): one a constructor stores a class's virtual table into
/// ([`vtable_stored`]); a method's `this`; and, at a virtual call (a call
/// through `*(*(p + o) + 8·k)` passing `p + o` first: the address of slot
/// `k` of the table loaded from the object's first word), the table and
/// the object. Returns the objects and the tables.
fn polymorphic(view: &View<'_>, generated: &Generated) -> (BTreeSet<usize>, BTreeSet<usize>) {
    let families = &generated.families;
    let mut out = BTreeSet::new();
    let mut tables = BTreeSet::new();
    for (index, family) in families.families.iter().enumerate() {
        if family.stride == 0
            && family
                .accesses
                .iter()
                .any(|access| counted(access, 0) && vtable_stored(view, access).is_some())
        {
            out.insert(index);
        }
    }
    let place = |value: Value| {
        let (index, at, modulus) = families.of(generated.var(view.canonical(value))?)?;
        (modulus == 0).then_some((index, at))
    };
    if view
        .schemes
        .structs()
        .classes()
        .method(view.l1.entry)
        .is_some()
        && let Some(this) = view.parameters.first()
    {
        out.extend(
            this.values
                .iter()
                .filter_map(|&value| Some(place(value)?.0)),
        );
    }
    for call in view.calls.iter().filter(|call| call.indirect) {
        let Some(slot) = loaded(view, call.target) else {
            continue;
        };
        let Some((table, _)) = place(slot) else {
            continue;
        };
        let Some(passed) = call
            .arguments
            .first()
            .and_then(|values| values.first())
            .and_then(|&this| place(this))
        else {
            continue;
        };
        // The table's start (the slot's address, or an operand of its
        // sum) is loaded from where the first argument points.
        let starts = match defined(view, slot) {
            Some(&Op::Binary(Binary::Add, a, b)) => [Some(a), Some(b)],
            _ => [Some(slot), None],
        };
        if starts
            .into_iter()
            .flatten()
            .any(|start| loaded(view, start).and_then(place) == Some(passed))
        {
            tables.insert(table);
            out.insert(passed.0);
        }
    }
    (out, tables)
}

/// The address the load `value` (of the function `view` shows) reads, if
/// it is a load's result.
fn loaded(view: &View<'_>, value: Value) -> Option<Value> {
    let &Op::Load { address, .. } = defined(view, value)? else {
        return None;
    };
    Some(view.canonical(address))
}

/// The operation defining `value` (seen through copies) in the function
/// `view` shows, if an instruction's result.
fn defined<'v>(view: &View<'v>, value: Value) -> Option<&'v Op> {
    match view.l1.value(view.canonical(value))?.definition {
        Definition::Result { inst, .. } => view.l1.inst(inst).map(|inst| &inst.op),
        Definition::Parameter { .. } => None,
    }
}

/// What access `access`'s offset is known modulo in its family (0:
/// exactly): its index's scale where one is added at it, its member's
/// modulus where the pointer it is through has one, or both's greatest
/// common divisor.
fn element_period(access: &Access) -> u64 {
    match (access.indexed, access.modulus) {
        (true, 0) => access.scale,
        (true, modulus) => gcd(modulus, access.scale),
        (false, modulus) => modulus,
    }
}

impl Rounder<'_, '_> {
    /// The fields the exact accesses of family `index` show, its root at
    /// `base` in its struct: per offset and width, the type rounding gives
    /// the values there (a pointer to a struct's start, the struct), with
    /// the strongest evidence among them; overlapping ones by
    /// [`Layout::add`]. A declared pointer parameter a pointer into it is
    /// passed to types the field there ([`Self::argument_fields`]) where
    /// the accesses show one of its width there, or none overlapping it.
    fn layout(&mut self, index: usize, base: i64) -> Layout {
        let generated = self.generated;
        let pointer = self.types.pointer_width();
        let mut groups: BTreeMap<(u64, u16), Vec<Option<Var>>> = BTreeMap::new();
        // Accesses at a constant offset plus an index scaled by their width
        // (added at the access, or to the pointer it is through: its
        // member's modulus): elements of an array starting there
        // (`p->a[i]`).
        let mut arrays: BTreeMap<(u64, u16), Vec<Option<Var>>> = BTreeMap::new();
        let Some(family) = generated.families.get(index) else {
            return Layout::default();
        };
        for access in &family.accesses {
            let at = u64::try_from(place(access.offset, base, family.stride));
            if let (true, Ok(at)) = (counted(access, family.stride), at) {
                groups
                    .entry((at, access.bits))
                    .or_default()
                    .push(access.value);
            } else if let Ok(at) = at
                && family.stride == 0
                && access.bits.is_multiple_of(8)
                && access.bits > 0
                && element_period(access) == u64::from(access.bits / 8)
            {
                arrays
                    .entry((at, access.bits))
                    .or_default()
                    .push(access.value);
            }
        }
        let mut layout = Layout::default();
        layout.set_element(family.stride);
        for ((offset, bits), values) in arrays {
            let element = self.scalar_field(&values, bits, index);
            layout.add_array(offset, element);
        }
        for ((offset, bits), values) in groups {
            let fields = if bits == pointer {
                self.struct_fields(&values)
            } else {
                Vec::new()
            };
            if fields.is_empty() {
                let field = self.scalar_field(&values, bits, index);
                layout.add(offset, field);
            }
            for field in fields {
                layout.add(offset, field);
            }
        }
        for (offset, field) in self.argument_fields(index, base) {
            let end = offset.saturating_add(u64::from(field.bits / 8));
            let mut overlapping = layout
                .fields
                .range(..end)
                .filter(|&(&at, kept)| offset < at.saturating_add(u64::from(kept.bits / 8)));
            let fits = match (overlapping.next(), overlapping.next()) {
                (None, _) => true,
                (Some((&at, kept)), None) => at == offset && kept.bits == field.bits,
                (Some(_), Some(_)) => false,
            };
            if fits {
                layout.add(offset, field);
            }
        }
        layout
    }

    /// The fields declared pointer parameters show of family `index`, its
    /// root at `base` in its struct: where a call passes a pointer into
    /// it (a member of modulus 0, or a constant address in a global
    /// object the family holds) for a parameter declared `T *`, a field
    /// of `T` there (as [`portable`] makes it), at Declared strength. A
    /// pointer to an incomplete or aggregate type says nothing, nor does
    /// one to a byte (`char *`, `uint8_t *`: C's pointer to any object's
    /// bytes, as strings and buffers are passed).
    fn argument_fields(&self, index: usize, base: i64) -> Vec<(u64, Field)> {
        let view = self.view;
        let generated = self.generated;
        let families = &generated.families;
        let Some(family) = families.get(index) else {
            return Vec::new();
        };
        let offset_of = |value: Value| -> Option<u64> {
            let at = match generated.var(value).and_then(|var| families.of(var)) {
                Some((at_index, at, 0)) if at_index == index => at,
                Some(_) => return None,
                None => {
                    if view.data.relocatable() && view.immediate(value) {
                        return None;
                    }
                    let address = view.constant(value)?.cast_unsigned();
                    let object = view.data.object(address)?;
                    let &var = generated.objects.get(&object.start)?;
                    let (at_index, at, 0) = families.of(var)? else {
                        return None;
                    };
                    if at_index != index {
                        return None;
                    }
                    at.checked_add(i64::try_from(address - object.start).ok()?)?
                }
            };
            u64::try_from(place(at, base, family.stride)).ok()
        };
        let mut out = Vec::new();
        for call in &view.calls {
            let Some(signature) = view.types.signature(call.signature) else {
                continue;
            };
            let parameters = signature.parameters.iter().chain(&call.variadic);
            for (values, &ty) in call.arguments.iter().zip(parameters) {
                let Some(&Type::Pointer(Some(target))) = view.types.get(ty) else {
                    continue;
                };
                let Some(bits) = view
                    .types
                    .value_width(target)
                    .filter(|&bits| bits > 8 && bits.is_multiple_of(8))
                else {
                    continue;
                };
                let Some(ty) = portable(view.types, target) else {
                    continue;
                };
                for &value in values {
                    if let Some(offset) = offset_of(value) {
                        let field = Field {
                            bits,
                            ty: ty.clone(),
                            strength: rank::DECLARED,
                        };
                        out.push((offset, field));
                    }
                }
            }
        }
        out
    }

    /// What the function shows of each global object it reaches
    /// ([`Seen`]), by the object's first byte: its reads and writes of
    /// the whole object as the field they make (a pointer to the struct
    /// their values point to, else their own rounding, with its
    /// strength, a pointer to a type no field type carries being
    /// [`FieldType::Opaque`], as is a pointer to nothing known where a
    /// declaration says what it points to ([`Self::declared_pointee`]);
    /// else untyped bits at Prior), and the fields
    /// ([`Self::layout`]) and widths of its other accesses, at offsets
    /// from the object's start.
    fn seen(&mut self) -> Vec<(u64, Seen)> {
        let generated = self.generated;
        let pointer = self.types.pointer_width();
        let mut seen: BTreeMap<u64, Seen> = BTreeMap::new();
        for (&at, &(var, bits)) in &generated.globals {
            let cells: Vec<Option<Var>> = generated
                .cells
                .get(&var)
                .map_or_else(Vec::new, |cells| cells.iter().copied().map(Some).collect());
            let structs = if bits == pointer {
                self.struct_fields(&cells)
            } else {
                Vec::new()
            };
            let elements = if bits == pointer {
                self.element_structs(&cells)
            } else {
                Vec::new()
            };
            // The pointers held in the array its values point to point to
            // a struct: a pointer to them (ahead of the rounding, which
            // holds no struct of the table).
            let held = elements.first().map(|&id| Field {
                bits,
                ty: FieldType::Pointers(id),
                strength: rank::ACCESS,
            });
            let field = structs.into_iter().next().or(held).or_else(|| {
                let (ty, strength) = self.of(var, bits)?;
                let mut found = portable(self.types, ty)?;
                if found == FieldType::Pointer(None)
                    && (self.types.get(ty) != Some(&Type::Pointer(None))
                        || self.declared_pointee(var))
                {
                    found = FieldType::Opaque;
                }
                // Pointers to a scalar its values point to, read and
                // written through only as such: `char **`.
                if found == FieldType::Opaque
                    && bits == pointer
                    && let Some(held) = self.held_scalar(ty)
                    && self.holds_pointers(&cells)
                {
                    found = held;
                }
                let ty = found;
                // Code whose signature is the convention's guess says the
                // global holds code, nothing of its signature: it gives way
                // to a signature a function's prototype or interface states.
                let guessed = matches!(ty, FieldType::Code { .. })
                    && self
                        .stated_code(&self.solution.answer(var))
                        .is_some_and(|(_, _, guessed)| guessed);
                Some(Field {
                    bits,
                    ty,
                    strength: if guessed { rank::PRIOR } else { strength },
                })
            });
            // Untyped, the accesses still say the object is one value.
            let field = field.unwrap_or(Field {
                bits,
                ty: FieldType::Scalar(Type::Bits(bits)),
                strength: rank::PRIOR,
            });
            let entry = seen.entry(at).or_default();
            entry.whole = Some((field, cells.len().max(1)));
            entry.functions = self.functions_reaching(var);
            entry.elements = elements;
            if bits == pointer {
                entry.element_reads = self.element_reads(&cells);
            }
        }
        for (&start, &var) in &generated.objects {
            let Some((index, offset, 0)) = generated.families.of(var) else {
                continue;
            };
            let Some(family) = generated.families.get(index) else {
                continue;
            };
            let base = offset.wrapping_neg();
            let parts = self.layout(index, base);
            let entry = seen.entry(start).or_default();
            for access in &family.accesses {
                if counted(access, family.stride) && place(access.offset, base, family.stride) >= 0
                {
                    *entry.widths.entry(access.bits).or_default() += 1;
                }
            }
            entry.parts = parts;
        }
        seen.into_iter().collect()
    }

    /// The program's type of the global object at `start`
    /// ([`super::Globals`]), interned, where it has one other than a
    /// declaration (the function's declared type is its own already).
    fn program_global(&mut self, start: u64) -> Option<TypeId> {
        let schemes = self.view.schemes;
        schemes
            .globals()
            .get(start)?
            .intern(schemes.structs(), self.types, &mut self.interned)
    }

    /// Whether one of `var`'s pointer bounds is a declaration's of a
    /// pointer to an aggregate or a vector ([`Generated::pointees`]): its
    /// target is known, though the solver's term does not carry it.
    fn declared_pointee(&self, var: Var) -> bool {
        let solution = self.solution;
        let answer = solution.answer(var);
        answer
            .lower
            .iter()
            .chain(&answer.upper)
            .filter(|bound| matches!(solution.term(bound.term), Some(Term::Pointer(_))))
            .any(|bound| {
                solution
                    .origin(bound.term)
                    .and_then(|origin| solution.constraint(origin))
                    .is_some_and(|constraint| {
                        [&constraint.lhs, &constraint.rhs].into_iter().any(|side| {
                            matches!(side, Term::Var(declared) if self.generated.pointees.contains(declared))
                        })
                    })
            })
    }

    /// A pointer field for each struct whose start `values` point to (one
    /// of the field's own family at its struct's start is a pointer to
    /// its own struct: a list's link; several structs in one field are
    /// one, by [`Layout::add`]).
    fn struct_fields(&self, values: &[Option<Var>]) -> Vec<Field> {
        let generated = self.generated;
        let mut fields: Vec<Field> = values
            .iter()
            .flatten()
            .filter_map(|&value| {
                let (family, offset, modulus) = generated.families.of(value)?;
                let ((id, base), stride) = self.struct_of(family, modulus)?;
                (place(offset, base, stride) == 0).then_some(Field {
                    bits: self.types.pointer_width(),
                    ty: FieldType::Struct(id),
                    strength: rank::ACCESS,
                })
            })
            .collect();
        fields.dedup();
        fields
    }

    /// Pointer type `ty` as a pointer to pointers to a scalar
    /// ([`portable`]'s) or to nothing known, if it is one: `char **`.
    fn held_scalar(&self, ty: TypeId) -> Option<FieldType> {
        let types = &*self.types;
        let &Type::Pointer(Some(held)) = types.get(ty)? else {
            return None;
        };
        let &Type::Pointer(target) = types.get(held)? else {
            return None;
        };
        if target.is_none() {
            return Some(FieldType::ScalarPointers(None));
        }
        match portable(types, held)? {
            FieldType::Pointer(Some(scalar)) => Some(FieldType::ScalarPointers(Some(scalar))),
            FieldType::Scalar(_)
            | FieldType::Pointer(None)
            | FieldType::Opaque
            | FieldType::Struct(_)
            | FieldType::Pointers(_)
            | FieldType::ScalarPointers(_)
            | FieldType::Code { .. } => None,
        }
    }

    /// Whether the objects `values` point to are read and written only as
    /// the elements of an array of pointers ([`pointer_array`]: through an
    /// index or a stride of one element), through at least one access, and
    /// no value read or written there is a typed scalar (an integer stored
    /// into an element: no array of pointers).
    fn holds_pointers(&mut self, values: &[Option<Var>]) -> bool {
        let generated = self.generated;
        let families = &generated.families;
        let pointer = self.types.pointer_width();
        let mut accessed = false;
        for (index, _, _) in values
            .iter()
            .flatten()
            .filter_map(|&value| families.of(value))
        {
            let Some(family) = families.get(index) else {
                continue;
            };
            if family.accesses.is_empty() {
                continue;
            }
            if !pointer_array(family, pointer) {
                return false;
            }
            for value in family.accesses.iter().filter_map(|access| access.value) {
                let scalar = self.of(value, pointer).is_some_and(|(ty, _)| {
                    matches!(
                        self.types.get(ty),
                        Some(
                            Type::Int(_)
                                | Type::UInt(_)
                                | Type::Char { .. }
                                | Type::Bool(_)
                                | Type::Float(_)
                                | Type::Enum(_)
                        )
                    )
                });
                if scalar {
                    return false;
                }
            }
            accessed = true;
        }
        accessed
    }

    /// The structs the elements of the arrays of pointers `values` point
    /// to point to the start of ([`Self::struct_fields`]): of each family
    /// of `values` that is an array of pointers ([`pointer_array`]: one
    /// array's elements, one type).
    fn element_structs(&self, values: &[Option<Var>]) -> Vec<StructId> {
        let families = &self.generated.families;
        let pointer = self.types.pointer_width();
        let mut held: Vec<Option<Var>> = Vec::new();
        for (index, _, _) in values
            .iter()
            .flatten()
            .filter_map(|&value| families.of(value))
        {
            let Some(family) = families.get(index) else {
                continue;
            };
            if pointer_array(family, pointer) {
                held.extend(family.accesses.iter().map(|access| access.value));
            }
        }
        let mut ids: Vec<StructId> = self
            .struct_fields(&held)
            .into_iter()
            .filter_map(|field| match field.ty {
                FieldType::Struct(id) => Some(id),
                FieldType::Scalar(_)
                | FieldType::Pointer(_)
                | FieldType::Opaque
                | FieldType::Pointers(_)
                | FieldType::ScalarPointers(_)
                | FieldType::Code { .. } => None,
            })
            .collect();
        ids.sort_unstable();
        ids.dedup();
        ids
    }

    /// The fields the reads through the elements of the arrays of
    /// pointers `values` point to show ([`Self::layout`], by offset from
    /// where the elements point), of the objects they point to that are
    /// no struct: one element's object read at one offset only, through
    /// no index.
    fn element_reads(&mut self, values: &[Option<Var>]) -> Layout {
        let families = &self.generated.families;
        let pointer = self.types.pointer_width();
        let mut objects: Vec<(usize, i64)> = Vec::new();
        for (index, _, _) in values
            .iter()
            .flatten()
            .filter_map(|&value| families.of(value))
        {
            let Some(family) = families
                .get(index)
                .filter(|family| pointer_array(family, pointer))
            else {
                continue;
            };
            for (object, offset, _) in family
                .accesses
                .iter()
                .filter_map(|access| families.of(access.value?))
                .filter(|&(_, _, modulus)| modulus == 0)
            {
                let single = families.get(object).is_some_and(|object| {
                    object.stride == 0
                        && !indexed(object)
                        && object.accesses.first().is_some_and(|first| {
                            object
                                .accesses
                                .iter()
                                .all(|access| access.offset == first.offset)
                        })
                });
                if single && self.struct_of(object, 0).is_none() {
                    objects.push((object, offset));
                }
            }
        }
        objects.sort_unstable();
        objects.dedup();
        let mut reads = Layout::default();
        for (object, offset) in objects {
            for (at, field) in self.layout(object, offset.wrapping_neg()).fields {
                reads.add(at, field);
            }
        }
        reads
    }

    /// A field of `bits` bits holding `values` (in family `within`):
    /// rounding's element of them, with the strongest evidence among them.
    fn scalar_field(&mut self, values: &[Option<Var>], bits: u16, within: usize) -> Field {
        let fields: Vec<(i64, u16, Option<Var>)> =
            values.iter().map(|&value| (0, bits, value)).collect();
        let ty = self
            .element(&fields, 0, within, 0)
            .and_then(|(_, ty)| portable(self.types, ty));
        let strength = strongest(values.iter().flatten().filter_map(|&value| {
            self.field_type(value, bits, within, 0)
                .map(|(_, strength)| strength)
        }));
        Field {
            bits,
            ty: ty.unwrap_or(FieldType::Scalar(Type::Bits(bits))),
            strength,
        }
    }
}

/// Type `ty` of `types` as a field's portable type: scalars as they are, a
/// pointer to a scalar or to nothing, code whose parameters and return
/// value are scalars or pointers to nothing as that code, other code as
/// `void *`.
pub(super) fn portable(types: &Types, ty: TypeId) -> Option<FieldType> {
    let scalar = |ty: &Type| match ty {
        Type::Bits(_)
        | Type::Int(_)
        | Type::UInt(_)
        | Type::Char { .. }
        | Type::Bool(_)
        | Type::Float(_)
        | Type::Enum(_) => Some(ty.clone()),
        Type::Pointer(_)
        | Type::Code(_)
        | Type::Struct(_)
        | Type::Union(_)
        | Type::Array { .. }
        | Type::Vector { .. } => None,
    };
    let ty = types.get(ty)?;
    match ty {
        Type::Pointer(target) => Some(FieldType::Pointer(
            target.and_then(|target| scalar(types.get(target)?)),
        )),
        Type::Code(signature) => {
            let simple = |id: TypeId| {
                let ty = types.get(id)?;
                if *ty == Type::Pointer(None) {
                    Some(Type::Pointer(None))
                } else {
                    scalar(ty)
                }
            };
            let parameters: Option<Vec<Type>> =
                signature.parameters.iter().map(|&id| simple(id)).collect();
            let returns = match signature.returns {
                Some(id) => simple(id).map(Some),
                None => Some(None),
            };
            Some(match (parameters, returns) {
                (Some(parameters), Some(returns)) => FieldType::Code {
                    parameters,
                    returns,
                    variadic: signature.variadic,
                },
                (None, _) | (_, None) => FieldType::Pointer(None),
            })
        }
        Type::Bits(_)
        | Type::Int(_)
        | Type::UInt(_)
        | Type::Char { .. }
        | Type::Bool(_)
        | Type::Float(_)
        | Type::Struct(_)
        | Type::Union(_)
        | Type::Array { .. }
        | Type::Vector { .. }
        | Type::Enum(_) => scalar(ty).map(FieldType::Scalar),
    }
}

/// How wide a value of field type `ty` is (pointers `pointer` bits), if
/// it says.
pub(super) fn field_width(ty: &FieldType, pointer: u16) -> Option<u16> {
    match ty {
        FieldType::Scalar(scalar) => match *scalar {
            Type::Bits(width) | Type::Int(width) | Type::UInt(width) | Type::Bool(width) => {
                Some(width)
            }
            Type::Char { .. } => Some(8),
            Type::Enum(Enumeration { width, .. }) => Some(width),
            Type::Float(_)
            | Type::Pointer(_)
            | Type::Code(_)
            | Type::Struct(_)
            | Type::Union(_)
            | Type::Array { .. }
            | Type::Vector { .. } => None,
        },
        FieldType::Pointer(_)
        | FieldType::Opaque
        | FieldType::Struct(_)
        | FieldType::Pointers(_)
        | FieldType::ScalarPointers(_)
        | FieldType::Code { .. } => Some(pointer),
    }
}

/// Whether `typed`, a class its callers agree on, may stand for a
/// parameter of field type `own` (its function's own): over `bits`, or
/// of its kind with no more said (an integer of its width for an
/// integer, a pointer to a scalar or to nothing for one), so the
/// callers' agreement chooses what the body's evidence leaves open.
pub(super) fn same_kind(own: &FieldType, typed: &FieldType) -> bool {
    let integer = |ty: &Type| matches!(ty, Type::Int(_) | Type::UInt(_) | Type::Char { .. });
    match (own, typed) {
        (FieldType::Scalar(Type::Bits(_)), _)
        | (FieldType::Pointer(_) | FieldType::Opaque, FieldType::Pointer(_)) => true,
        (FieldType::Scalar(a), FieldType::Scalar(b)) => integer(a) && integer(b),
        _ => false,
    }
}

/// Class `class` as a field type of `width` bits (pointers `pointer`
/// bits wide), where it is one that wide: a scalar, a pointer (to its
/// scalar target); not code, whose signature a class does not say.
pub(super) fn class_field(class: Class, width: u16, pointer: u16) -> Option<FieldType> {
    match class {
        Class::Scalar(atom) if atom.width() == width => scalar(atom).map(FieldType::Scalar),
        Class::Pointer(target) if width == pointer => {
            Some(FieldType::Pointer(target.and_then(scalar)))
        }
        Class::Scalar(_) | Class::Pointer(_) | Class::Code => None,
    }
}

/// The class of field type `ty`, where it has one that says more than a
/// width: a scalar's, a pointer's (to a scalar target, else to nothing
/// known), code's.
pub(super) fn field_class(ty: &FieldType) -> Option<Class> {
    match ty {
        FieldType::Scalar(scalar) => type_atom(scalar).map(Class::Scalar),
        FieldType::Pointer(target) => Some(Class::Pointer(target.as_ref().and_then(type_atom))),
        FieldType::Opaque
        | FieldType::Struct(_)
        | FieldType::Pointers(_)
        | FieldType::ScalarPointers(_) => Some(Class::Pointer(None)),
        FieldType::Code { .. } => Some(Class::Code),
    }
}

/// `level`'s atom if it says more than a width and is `width` bits.
fn informative(level: Level, width: u16) -> Option<Atom> {
    match level {
        Level::Atom(atom) if atom.width() == width && scalar(atom).is_some() => Some(atom),
        Level::Atom(_) | Level::Top | Level::Bottom => None,
    }
}

/// The L2 scalar of an informative atom.
fn scalar(atom: Atom) -> Option<Type> {
    match atom {
        Atom::Signed(width) => Some(Type::Int(width)),
        Atom::Unsigned(width) => Some(Type::UInt(width)),
        Atom::Bool(width) => Some(Type::Bool(width)),
        Atom::Char { signed } => Some(Type::Char { signed }),
        Atom::Float(format) => Some(Type::Float(match format {
            Format::Half => Lane::Half,
            Format::Single => Lane::Single,
            Format::Double => Lane::Double,
            Format::Extended => Lane::Extended,
        })),
        Atom::Bits(_) | Atom::Int(_) => None,
        // An enumeration's own type is the rounder's
        // ([`Rounder::enumeration`]): where nothing else is, its integer.
        Atom::Enum { .. } => scalar(atom.integer()),
    }
}
