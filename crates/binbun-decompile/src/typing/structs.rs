//! Synthesised structs: the program's table of the structs its pointer
//! families show, one identity and one layout per struct over the whole
//! program.
//!
//! - **Which families are structs** ([`qualifies`]): a family with no
//!   stride whose exact accesses (through a member of modulus 0, no index)
//!   are at two or more offsets, or at one offset other than the member's
//!   own where that member is a parameter's value or a loaded pointer (an
//!   object, not a scalar pointer), unless they are all one byte wide
//!   ([`bytes`]: a string's characters tested one by one are no
//!   members). A family with a stride (a loop's
//!   step: `p + d·i`) is an array; its element is a struct of the stride's
//!   size where its accesses are not one scalar width at multiples of it
//!   ([`element`]: an array of structs, its fields at offsets modulo the
//!   stride), else it stays as rounding makes it (an array of scalars).
//!   Indices' scales make no struct elements: after strength
//!   reduction (`i·24` as `(i·3) << 3`) a scale is the address mode's,
//!   not the element's size.
//! - **Identity** ([`StructId`]): the function the struct is born in and
//!   its number `k` there (from 1, in order of first access: the smallest
//!   access instruction). A family passed to a callee whose parameter
//!   points into a struct of the table, or holding a callee's result that
//!   does, is that struct (the deepest function's: callees come first),
//!   as is one loaded from or stored to a field the table types as a
//!   pointer to it, and a global object's family the struct the table has
//!   for the object. Structs claiming one family at one offset, or met at
//!   one pointer field, are one ([`Structs::find`]: united where their
//!   layouts agree and are one size, named by the deepest function, ties
//!   by address); at different offsets the first is kept and the
//!   disagreement counted. After the sweep, a struct refused only for its
//!   size, with one struct and no other, that is smaller and has no size
//!   of its own is a partial view of it and one with it
//!   ([`Structs::unite_partial_views`]: a callee reading a few fields of
//!   its parameter). The structs the elements of the array of
//!   pointers one pointer global points to point to are one type
//!   whatever their sizes ([`Structs::unite_one_type`], after the sweep:
//!   each function shows as much of an element as it reads), each tried
//!   with every other, and so the structs their fields point to; their
//!   fields need only agree at their offsets, two scalars of different
//!   widths at one offset being one field (the narrower read a part of the
//!   wider) and untyped bits over several fields a copy of them (the
//!   fields stay). Otherwise a family that qualifies is a new
//!   struct born in its function (an allocation of known size, a callee
//!   declared `alloc_size`, is not one object with one of another size or
//!   with one whose accesses reach past it). Each function's
//!   [`Contribution`] says which structs its families are (by their
//!   accesses' instructions), where its interface's roots point, and the
//!   fields its own accesses show; the whole-program sweep adds them
//!   callees first ([`Structs::add`]), so the table is deterministic, and
//!   every decompilation reads the finished table only.
//! - **Layout** ([`Layout`]): per offset, the field rounding gives the
//!   exact accesses there (the strongest evidence; a pointer to a family
//!   that is a struct, at its start, is a pointer to that struct: structs
//!   nest by reference only). Fields that overlap keep the strongest (the
//!   narrower on a tie, else the first), and a field whose type differs
//!   at one offset keeps the stronger (a pointer with a target over one
//!   without); each such conflict is counted, never a union. Its size
//!   is the object's where an allocation or a global object says (no
//!   field past it), else the end of its last field, rounded up to its
//!   fields' natural
//!   alignment where every field is at a multiple of its own (C's trailing
//!   padding, so the definition needs no `packed`: a packed struct makes
//!   every `&p->field` a warning); bytes between fields no access reaches
//!   are `unknown_<hex>[n]`, never padding, but where accesses index them
//!   from a constant offset by their width (`p->a[i]`: [`Layout::arrays`])
//!   they are an array of those elements from there to the next field
//!   (`int32_t field_20[3]`). An array's element
//!   ([`Layout::element`]) is the stride in size and holds no field past
//!   it.
//! - **Names**: `struct_<function>_<k>`, the function by its plain C name
//!   if it has one, else its address in hex; fields `field_<hex offset>`.
//!   A struct that is a C++ class, or a class's virtual table, is named
//!   by the class (the `named` submodule; [`super::classes`]) unless it
//!   has a declared identity (below), which outranks it; and it unites
//!   with another struct where their fields agree whatever their sizes
//!   (a class's objects are one type however much of them a function
//!   shows), but never where two declared types differ.
//! - **Declared identities** ([`super::declared`]): a struct a declared
//!   root points to takes the declared type (debug information's) as its
//!   identity, name and layout; a pointer field of the declared type to
//!   another named struct passes that struct's identity on to the struct
//!   the table's field points to (to a fixed point). Structs of two
//!   different declared types are never united, and a second declared
//!   type for one struct is a conflict (the first kept). The table keeps
//!   its own layout too (claims and unions read it); where an access of
//!   it reaches past the declared size or a declared field at its offset
//!   is of another width, the declared layout stays and the conflict is
//!   counted ([`Structs::declared_conflicts`]).

mod named;

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use binbun_ast::types::{Aggregate, Field as Member, Signature, Type, TypeId, Types};
use binbun_ssa::ir::InstId;
use binbun_typeinfer::{Strength, Var};

use super::Root;
use super::classes::Classes;
use super::declared::copy;
use super::family::{Access, Family};
use super::globals::Seen;

/// A synthesised struct: the function it is born in (its entry) and its
/// number there (from 1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StructId {
    /// The entry of the function it is born in.
    pub function: u64,
    /// Its number among the structs born there.
    pub k: u32,
}

/// A field's type, portable between functions' type tables.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FieldType {
    /// A scalar (an integer, `char`, a truth value, a float, bits).
    Scalar(Type),
    /// A pointer to a scalar, or to nothing known (`void *`).
    Pointer(Option<Type>),
    /// A pointer to a known type no other field type carries (a declared
    /// struct or union, a pointer, an array, a vector, code whose
    /// signature is not [`Self::Code`]'s): unlike [`Self::Pointer`]`(None)`
    /// it says what it points to, though not portably; `void *` in C. A
    /// global's whole value's evidence ([`Seen`]); a struct's fields keep
    /// [`Self::Pointer`]`(None)` for it.
    Opaque,
    /// A pointer to a synthesised struct.
    Struct(StructId),
    /// A pointer to pointers to a synthesised struct (`S **`: an array
    /// of them, its elements accessed through an index or a stride): a
    /// global's whole value's evidence ([`Seen`]), as [`Self::Opaque`].
    Pointers(StructId),
    /// A pointer to pointers to a scalar or to nothing known (`char **`,
    /// `void **`: an array of them, its elements accessed through an index
    /// or a stride): a global's whole value's evidence where its values
    /// are read through only as such ([`Seen`]); a struct's fields keep
    /// [`Self::Opaque`] for it.
    ScalarPointers(Option<Type>),
    /// A pointer to code whose parameters and return value are scalars or
    /// pointers to nothing known (a virtual table's slot, as called).
    Code {
        /// The parameters' types.
        parameters: Vec<Type>,
        /// The return value's type, if any.
        returns: Option<Type>,
        /// Whether more arguments may follow (C's `...`).
        variadic: bool,
    },
}

/// A field of a synthesised struct.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Field {
    /// Its width in bits (whole bytes).
    pub bits: u16,
    /// Its type.
    pub ty: FieldType,
    /// The strongest evidence for its type.
    pub strength: Strength,
}

impl Field {
    /// Its width in bytes.
    const fn bytes(&self) -> u64 {
        (self.bits / 8) as u64
    }
}

/// A synthesised struct's layout.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Layout {
    /// Its fields, by offset; none overlap.
    pub fields: BTreeMap<u64, Field>,
    /// The size of an array's element it is, in bytes (its loop's step:
    /// its size, and no field reaches past it); 0: none.
    pub element: u64,
    /// Evidence it did not keep: overlapping fields, and types that
    /// differed at one offset.
    pub conflicts: usize,
    /// Pairs of structs its pointer fields point to that met at one
    /// offset (one field points to one type: the table unites them).
    pub unify: Vec<(StructId, StructId)>,
    /// The size in bytes of the object it is, where an allocation (a
    /// callee declared `alloc_size`, its size arguments constants) or a
    /// global object of the image says (0: unknown): its size, and no
    /// field reaches past it.
    pub allocated: u64,
    /// The elements of the arrays its indexed accesses show (`p->a[i]`:
    /// an index scaled by the element's width, from a constant offset),
    /// by the array's first byte: where no field covers that byte, the
    /// bytes from it to the next field are that array ([`Structs::intern`]).
    pub arrays: BTreeMap<u64, Field>,
}

impl Layout {
    /// Adds an array of `element`s starting at `offset` (see
    /// [`Self::arrays`]): where one starts there already, the same width
    /// keeps the stronger element, another is a conflict (the first
    /// kept).
    pub fn add_array(&mut self, offset: u64, element: Field) {
        if element.bits == 0 || !element.bits.is_multiple_of(8) {
            return;
        }
        match self.arrays.get_mut(&offset) {
            None => {
                self.arrays.insert(offset, element);
            }
            Some(kept) if kept.bits == element.bits => {
                if element.strength > kept.strength {
                    *kept = element;
                }
            }
            Some(_) => self.conflicts += 1,
        }
    }

    /// Its size in bytes: the end of its last field.
    pub fn size(&self) -> u64 {
        self.fields
            .iter()
            .map(|(&offset, field)| offset.saturating_add(field.bytes()))
            .max()
            .unwrap_or(0)
    }

    /// Its size as C lays it out: [`size`](Self::size) rounded up to the
    /// largest natural alignment of its fields (a field's width rounded up
    /// to a power of two, at most 16 bytes), where every field is at a
    /// multiple of its own; else [`size`](Self::size) (the definition is
    /// packed). An array's element is its [`element`](Self::element) size
    /// (C's `sizeof` of the element is the array's stride: [`element`]
    /// admits only strides that are multiples of every field's natural
    /// alignment, so that is the natural size with its tail padding).
    pub fn natural_size(&self) -> u64 {
        if self.element > 0 {
            return self.element;
        }
        if self.allocated > 0 {
            return self.allocated;
        }
        let natural = |field: &Field| field.bytes().max(1).next_power_of_two().min(16);
        let aligned = self
            .fields
            .iter()
            .all(|(&offset, field)| offset.is_multiple_of(natural(field)));
        let size = self.size();
        if !aligned {
            return size;
        }
        let align = self.fields.values().map(natural).max().unwrap_or(1);
        size.next_multiple_of(align)
    }

    /// Makes it an array's element of `size` bytes (0: nothing), unless
    /// it is one of another size or its fields reach past `size` (a
    /// conflict either way).
    pub fn set_element(&mut self, size: u64) {
        if size == 0 || self.element == size {
            return;
        }
        if self.element == 0 && self.size() <= size {
            self.element = size;
        } else {
            self.conflicts += 1;
        }
    }

    /// Makes it the size of an object of `size` bytes (0: nothing), unless
    /// it is another's or an array's element, or its fields reach past
    /// `size` (a conflict either way: not one object).
    pub fn set_allocated(&mut self, size: u64) {
        if size == 0 || self.allocated == size {
            return;
        }
        if self.allocated == 0 && self.element == 0 && self.size() <= size {
            self.allocated = size;
        } else {
            self.conflicts += 1;
        }
    }

    /// Adds `field` at `offset`: where it overlaps fields, the stronger
    /// stays (on a tie, the narrower: a wide access over two fields, as a
    /// copy of both reads them, says less than the fields; else those
    /// already there), a conflict where they differ;
    /// one past an array's element is a conflict, not kept. Where it is
    /// as wide as a field at its offset: pointers to two structs are one
    /// struct ([`Self::unify`], the field kept), and a pointer with a
    /// target replaces one without (or untyped bits) whatever their
    /// strengths, as a variable's type does; likewise a typed scalar
    /// replaces untyped bits.
    pub fn add(&mut self, offset: u64, field: Field) {
        if field.bits == 0 || !field.bits.is_multiple_of(8) {
            return;
        }
        let end = offset.saturating_add(field.bytes());
        if (self.element > 0 && end > self.element) || (self.allocated > 0 && end > self.allocated)
        {
            self.conflicts += 1;
            return;
        }
        if let Some(kept) = self.fields.get_mut(&offset)
            && kept.bits == field.bits
        {
            match (&kept.ty, &field.ty) {
                (&FieldType::Struct(a), &FieldType::Struct(b)) if a != b => {
                    self.unify.push((a, b));
                    kept.strength = kept.strength.max(field.strength);
                    return;
                }
                (
                    FieldType::Pointer(None) | FieldType::Scalar(Type::Bits(_)),
                    FieldType::Struct(_)
                    | FieldType::Pointer(Some(_))
                    | FieldType::Opaque
                    | FieldType::Pointers(_)
                    | FieldType::ScalarPointers(_)
                    | FieldType::Code { .. },
                ) => {
                    let strength = kept.strength.max(field.strength);
                    *kept = Field { strength, ..field };
                    return;
                }
                (
                    FieldType::Struct(_)
                    | FieldType::Pointer(Some(_))
                    | FieldType::Opaque
                    | FieldType::Pointers(_)
                    | FieldType::ScalarPointers(_)
                    | FieldType::Code { .. },
                    FieldType::Pointer(None) | FieldType::Scalar(Type::Bits(_)),
                )
                | (FieldType::Scalar(_), FieldType::Scalar(Type::Bits(_))) => {
                    kept.strength = kept.strength.max(field.strength);
                    return;
                }
                // Untyped bits say only the width: a typed scalar there
                // is the field's type, whatever the strengths.
                (FieldType::Scalar(Type::Bits(_)), FieldType::Scalar(ty))
                    if !matches!(ty, Type::Bits(_)) =>
                {
                    let strength = kept.strength.max(field.strength);
                    *kept = Field { strength, ..field };
                    return;
                }
                _ => {}
            }
        }
        let overlapping: Vec<u64> = self
            .fields
            .iter()
            .filter(|&(&at, kept)| at < end && offset < at.saturating_add(kept.bytes()))
            .map(|(&at, _)| at)
            .collect();
        let same = overlapping.len() == 1
            && overlapping.first() == Some(&offset)
            && self.fields.get(&offset).is_some_and(|kept| *kept == field);
        if same {
            return;
        }
        let stronger = overlapping.iter().all(|at| {
            self.fields.get(at).is_none_or(|kept| {
                field.strength > kept.strength
                    || (field.strength == kept.strength && field.bits < kept.bits)
            })
        });
        if !overlapping.is_empty() {
            self.conflicts += 1;
        }
        if stronger {
            for at in overlapping {
                self.fields.remove(&at);
            }
            self.fields.insert(offset, field);
        }
    }
}

/// What one function adds to the program's table of structs.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Contribution {
    /// The fields its own accesses show of each struct its families are
    /// (born there or a callee's).
    pub(crate) layouts: BTreeMap<StructId, Layout>,
    /// Where its interface's roots point: into which struct, at which
    /// offset.
    pub(crate) roots: Vec<(Root, StructId, i64)>,
    /// Each access through a family that is a struct, with the struct and
    /// the offset of the family's root in it.
    pub(crate) accesses: Vec<(InstId, StructId, i64)>,
    /// Families that more than one struct claimed.
    pub(crate) conflicts: usize,
    /// Structs one family is (claimed by two, at one offset): one struct.
    pub(crate) merges: Vec<(StructId, StructId)>,
    /// The functions of the program it calls directly.
    pub(crate) callees: Vec<u64>,
    /// The struct each global object it reaches is (by the object's first
    /// byte), with the offset of the object's start in it.
    pub(crate) globals: Vec<(u64, StructId, i64)>,
    /// The C++ class each struct is claimed to be (by index in the
    /// program's [`Classes`]).
    pub(crate) classes: Vec<(StructId, usize)>,
    /// The structs that are virtual tables (read at virtual calls).
    pub(crate) tables: Vec<StructId>,
    /// The declared type (in [`Self::declared_types`]) of each struct its
    /// declared roots point to ([`super::declared::declare`]).
    pub(crate) declared: Vec<(StructId, TypeId)>,
    /// The types of [`Self::declared`] (none where it is empty).
    pub(crate) declared_types: Option<Types>,
    /// What it shows of each global object it reaches, by the object's
    /// first byte, for the program's global types
    /// ([`Globals`](super::Globals); not the table's).
    pub(crate) objects: Vec<(u64, Seen)>,
}

/// The program's synthesised structs.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Structs {
    /// Each struct's layout.
    layouts: BTreeMap<StructId, Layout>,
    /// How each function in which structs are born prints in their names.
    names: BTreeMap<u64, String>,
    /// Where each function's interface's roots point.
    roots: BTreeMap<u64, Vec<(Root, StructId, i64)>>,
    /// The struct each access is into, with the offset of its family's
    /// root, by function entry and instruction.
    accesses: BTreeMap<(u64, InstId), (StructId, i64)>,
    /// Evidence not kept: fields overlapping or differing at one offset,
    /// families more than one struct claimed.
    conflicts: usize,
    /// Each struct united with another, with the one it is now (the
    /// deepest function's: [`Self::rank`]).
    merged: BTreeMap<StructId, StructId>,
    /// Each function's height in the program's calls: 0 for one calling
    /// no function added before it, else one more than its highest such
    /// callee's.
    heights: BTreeMap<u64, u32>,
    /// The struct each global object is, by its first byte, with the
    /// offset of its start in it (its element's, for an array).
    globals: BTreeMap<u64, (StructId, i64)>,
    /// The program's C++ classes.
    classes: Classes,
    /// The class each struct is (`None`: claimed by classes with no
    /// common base).
    claims: BTreeMap<StructId, Option<usize>>,
    /// The struct each class is (as last claimed).
    by_class: BTreeMap<usize, StructId>,
    /// The structs that are virtual tables.
    tables: BTreeSet<StructId>,
    /// The declared type (in [`Self::declared`]) each struct is.
    identities: BTreeMap<StructId, TypeId>,
    /// The declared types of [`Self::identities`].
    declared: Option<Types>,
    /// Structs a second declared type claimed, and unions two declared
    /// types refused.
    identity_conflicts: usize,
    /// Pairs of structs evidence said were one that [`Self::unite`]
    /// refused only for their sizes (their fields agree at their offsets),
    /// for [`Self::unite_partial_views`].
    refused: Vec<(StructId, StructId)>,
}

impl Structs {
    /// No structs.
    pub const fn new() -> Self {
        Self {
            layouts: BTreeMap::new(),
            names: BTreeMap::new(),
            roots: BTreeMap::new(),
            accesses: BTreeMap::new(),
            conflicts: 0,
            merged: BTreeMap::new(),
            heights: BTreeMap::new(),
            globals: BTreeMap::new(),
            classes: Classes::empty(),
            claims: BTreeMap::new(),
            by_class: BTreeMap::new(),
            tables: BTreeSet::new(),
            identities: BTreeMap::new(),
            declared: None,
            identity_conflicts: 0,
            refused: Vec::new(),
        }
    }

    /// Adds what the function at `entry` (named `name`, if it has a
    /// symbol) contributes: its new structs, the fields its accesses show
    /// of its callees' (each by [`Layout::add`]), its roots and accesses;
    /// then unites the structs it found to be one ([`Self::unite`]).
    pub fn add(&mut self, entry: u64, name: Option<&str>, contribution: Contribution) {
        let Contribution {
            layouts,
            roots,
            accesses,
            conflicts,
            merges,
            callees,
            globals,
            classes,
            tables,
            declared,
            declared_types,
            objects: _,
        } = contribution;
        for id in tables {
            let id = self.find(id);
            self.tables.insert(id);
        }
        self.conflicts += conflicts;
        let height = callees
            .iter()
            .filter(|&&callee| callee != entry)
            .filter_map(|callee| self.heights.get(callee))
            .max()
            .map_or(0, |&height| height.saturating_add(1));
        self.heights.entry(entry).or_insert(height);
        let mut work = merges;
        for (id, layout) in layouts {
            if id.function == entry {
                self.names
                    .entry(entry)
                    .or_insert_with(|| plain(name).unwrap_or_else(|| format!("{entry:x}")));
            }
            let id = self.find(id);
            self.absorb(id, layout, &mut work);
        }
        if !roots.is_empty() {
            self.roots.insert(entry, roots);
        }
        for (inst, id, base) in accesses {
            self.accesses.insert((entry, inst), (id, base));
        }
        for (start, id, at) in globals {
            match self.globals.get(&start).copied() {
                None => {
                    self.globals.insert(start, (id, at));
                }
                Some((known, offset)) if offset == at => work.push((known, id)),
                Some(_) => self.conflicts += 1,
            }
        }
        for (id, class) in classes {
            self.claim(id, Some(class), &mut work);
        }
        while let Some((a, b)) = work.pop() {
            self.unite(a, b, &mut work);
        }
        if let Some(from) = declared_types {
            let mut map = BTreeMap::new();
            for (id, ty) in declared {
                let into = self
                    .declared
                    .get_or_insert_with(|| Types::new(from.pointer_width()));
                if let Some(ty) = copy(&from, ty, into, &mut map) {
                    let id = self.find(id);
                    self.identify(id, ty);
                }
            }
        }
        self.pass_identities();
    }

    /// Struct `id` (as it is now) is declared type `ty`, unless it is
    /// another already (a conflict).
    fn identify(&mut self, id: StructId, ty: TypeId) {
        match self.identities.get(&id) {
            None => {
                self.identities.insert(id, ty);
            }
            Some(&known) if known == ty => {}
            Some(_) => self.identity_conflicts += 1,
        }
    }

    /// Takes the user's versions of structs (`stated`: each struct by its
    /// identity, with its type in `from`) as their identities, over any
    /// declared one (the user's is the strongest evidence: it names the
    /// struct and lays it out, as a declared type does); after the sweep,
    /// so the table's structs and unions are the same as without them.
    /// A struct the table does not have is left out. A field of the
    /// user's pointing to a struct declared but not defined (empty, of
    /// size 0) that the table names points to the table's struct.
    pub fn state(&mut self, from: &Types, stated: &[(StructId, TypeId)]) {
        let mut map = BTreeMap::new();
        let mut into = self
            .declared
            .take()
            .unwrap_or_else(|| Types::new(from.pointer_width()));
        let names: BTreeMap<String, StructId> =
            self.layouts.keys().map(|&id| (self.name(id), id)).collect();
        let mut interned = BTreeMap::new();
        for &(id, ty) in stated {
            let id = self.find(id);
            if !self.layouts.contains_key(&id) {
                continue;
            }
            let Some(ty) = copy(from, ty, &mut into, &mut map) else {
                continue;
            };
            let Some(Type::Struct(aggregate) | Type::Union(aggregate)) = into.get(ty) else {
                continue;
            };
            let mut fields = aggregate.fields.clone();
            for member in &mut fields {
                let Some(&Type::Pointer(Some(target))) = into.get(member.ty) else {
                    continue;
                };
                let Some(Type::Struct(pointee) | Type::Union(pointee)) = into.get(target) else {
                    continue;
                };
                let table = pointee
                    .name
                    .as_ref()
                    .filter(|_| pointee.size == 0 && pointee.fields.is_empty())
                    .and_then(|name| names.get(name).copied());
                if let Some(full) =
                    table.and_then(|table| self.intern(table, &mut into, &mut interned))
                {
                    member.ty = into.intern(Type::Pointer(Some(full)));
                }
            }
            if let Some(aggregate) = into.aggregate_mut(ty) {
                aggregate.fields = fields;
            }
            self.identities.insert(id, ty);
        }
        self.declared = Some(into);
        self.pass_identities();
    }

    /// Struct `id` laid out in a table of its own, with the structs its
    /// fields point to: as decompilation interns it (its declared or
    /// stated identity's type, else its layout), for printing its
    /// definition alone.
    pub fn table(&self, id: StructId, pointer_width: u16) -> Option<(Types, TypeId)> {
        let mut types = Types::new(pointer_width);
        let ty = self.intern(id, &mut types, &mut BTreeMap::new())?;
        Some((types, ty))
    }

    /// Passes declared identities on through pointer fields, to a fixed
    /// point: where a struct's declared type has a field pointing to a
    /// named struct or union and its layout's field at that offset points
    /// to a struct with no identity, that struct is the field's target.
    fn pass_identities(&mut self) {
        let Some(declared) = &self.declared else {
            return;
        };
        let pointer = declared.pointer_width();
        loop {
            let mut found: Vec<(StructId, TypeId)> = Vec::new();
            for (&id, &ty) in &self.identities {
                let (Some(layout), Some(Type::Struct(aggregate) | Type::Union(aggregate))) =
                    (self.layouts.get(&id), declared.get(ty))
                else {
                    continue;
                };
                for member in &aggregate.fields {
                    let Some(&Type::Pointer(Some(target))) = declared.get(member.ty) else {
                        continue;
                    };
                    let named = matches!(
                        declared.get(target),
                        Some(
                            Type::Struct(Aggregate { name: Some(_), .. })
                                | Type::Union(Aggregate { name: Some(_), .. })
                        )
                    );
                    if let Some(Field {
                        ty: FieldType::Struct(next),
                        bits,
                        ..
                    }) = layout.fields.get(&member.offset)
                        && named
                        && *bits == pointer
                    {
                        let next = self.find(*next);
                        if !self.identities.contains_key(&next) {
                            found.push((next, target));
                        }
                    }
                }
            }
            if found.is_empty() {
                return;
            }
            for (id, ty) in found {
                self.identities.entry(id).or_insert(ty);
            }
        }
    }

    /// Adds `layout`'s fields to struct `id`'s (by [`Layout::add`], its
    /// pointers' structs as they are now), the pairs of structs that
    /// meet at a field to `work`.
    fn absorb(&mut self, id: StructId, mut layout: Layout, work: &mut Vec<(StructId, StructId)>) {
        let fields: Vec<(u64, Field)> = core::mem::take(&mut layout.fields)
            .into_iter()
            .map(|(offset, mut field)| {
                if let FieldType::Struct(target) = field.ty {
                    field.ty = FieldType::Struct(self.find(target));
                }
                (offset, field)
            })
            .collect();
        let kept = self.layouts.entry(id).or_default();
        let before = kept.conflicts;
        kept.set_element(layout.element);
        kept.set_allocated(layout.allocated);
        for (offset, field) in fields {
            kept.add(offset, field);
        }
        for (offset, element) in core::mem::take(&mut layout.arrays) {
            kept.add_array(offset, element);
        }
        work.append(&mut kept.unify);
        work.append(&mut layout.unify);
        self.conflicts += kept.conflicts - before + layout.conflicts;
        kept.conflicts += layout.conflicts;
    }

    /// Unites structs `a` and `b` (one type: a family both are, a field
    /// pointing to both) into the one [`Self::rank`] puts first, its
    /// fields the union of theirs (structs meeting at a field united
    /// next, by `work`); not where their layouts disagree
    /// ([`compatible`]: a conflict).
    fn unite(&mut self, a: StructId, b: StructId, work: &mut Vec<(StructId, StructId)>) {
        self.unite_as(a, b, work, true);
    }

    /// [`Self::unite`], the layouts' sizes compared only if `sized` (else
    /// the evidence says they are one type however much of it each shows:
    /// only their fields must [`overlap`] as one struct's).
    fn unite_as(
        &mut self,
        a: StructId,
        b: StructId,
        work: &mut Vec<(StructId, StructId)>,
        sized: bool,
    ) {
        let (a, b) = (self.find(a), self.find(b));
        if a == b {
            return;
        }
        let (keep, lose) = if self.rank(a) <= self.rank(b) {
            (a, b)
        } else {
            (b, a)
        };
        if let (Some(first), Some(second)) =
            (self.identities.get(&keep), self.identities.get(&lose))
            && first != second
        {
            self.identity_conflicts += 1;
            return;
        }
        let empty = Layout::default();
        let (first, second) = (
            self.layouts.get(&keep).unwrap_or(&empty),
            self.layouts.get(&lose).unwrap_or(&empty),
        );
        let agree = match self.classes_agree(keep, lose) {
            Some(agree) => agree && overlap(first, second, false),
            None if sized => compatible(first, second),
            None => overlap(first, second, true),
        };
        if !agree {
            if sized
                && self.classes_agree(keep, lose).is_none()
                && overlap(first, second, false)
                && overlap(second, first, false)
            {
                self.refused.push((keep, lose));
            }
            self.conflicts += 1;
            return;
        }
        let mut fields = self.layouts.remove(&lose).unwrap_or_default();
        if !sized && let Some(kept) = self.layouts.get_mut(&keep) {
            fit(kept, &fields);
            fit(&mut fields, kept);
        }
        self.merged.insert(lose, keep);
        self.carry(keep, lose, work);
        if let Some(lost) = self.identities.remove(&lose) {
            self.identities.entry(keep).or_insert(lost);
        }
        self.absorb(keep, fields, work);
    }

    /// The struct `id` is now (itself unless united with another).
    pub fn find(&self, mut id: StructId) -> StructId {
        while let Some(&next) = self.merged.get(&id) {
            id = next;
        }
        id
    }

    /// Unites each of `pairs` ([`Self::unite`]: one type where their
    /// layouts agree), and the structs that meets at fields.
    pub(crate) fn unite_all(&mut self, pairs: Vec<(StructId, StructId)>) {
        let mut work = pairs;
        while let Some((a, b)) = work.pop() {
            self.unite(a, b, &mut work);
        }
    }

    /// Unites `ids` as one type whatever their sizes (the structs one
    /// array's elements point to: each function shows as much of it as it
    /// reads), each with every other ([`Self::unite_as`]), and so the
    /// structs that meets at fields (a field of one type points to one
    /// type).
    pub(crate) fn unite_one_type(&mut self, ids: &[StructId]) {
        let mut work = Vec::new();
        for (a, b) in pairs(ids) {
            self.unite_as(a, b, &mut work, false);
        }
        while let Some((a, b)) = work.pop() {
            self.unite_as(a, b, &mut work, false);
        }
    }

    /// Unites each struct that is a partial view of one other (after the
    /// sweep): one that [`Self::unite`] refused to unite only for its
    /// size ([`Self::refused`]) with one struct and no other, smaller than
    /// it, with no size of its own (no allocation, no array's element),
    /// each of its fields of the same kind as the other's there
    /// ([`kinds_agree`]):
    /// a function that reads a few fields of its parameter (`tensor_t`'s
    /// in `tensor_matmul`) shows as much of it as it reads, and each value
    /// its callers pass there is the larger struct. A struct refused with
    /// several (a list's node passed with each struct holding one) stays
    /// apart, as does the larger one of a pair. Then, as
    /// [`Self::unite_one_type`], the structs that meet at fields.
    pub(crate) fn unite_partial_views(&mut self) {
        let mut partners: BTreeMap<StructId, BTreeSet<StructId>> = BTreeMap::new();
        for (a, b) in core::mem::take(&mut self.refused) {
            let (a, b) = (self.find(a), self.find(b));
            if a != b {
                partners.entry(a).or_default().insert(b);
                partners.entry(b).or_default().insert(a);
            }
        }
        let mut work = Vec::new();
        for (part, with) in partners {
            let &[whole] = with.iter().copied().collect::<Vec<_>>().as_slice() else {
                continue;
            };
            let (part, whole) = (self.find(part), self.find(whole));
            let partial = match (self.layouts.get(&part), self.layouts.get(&whole)) {
                (Some(part), Some(whole)) => {
                    part.allocated == 0
                        && part.element == 0
                        && part.natural_size() < whole.natural_size()
                        && part.fields.iter().all(|(offset, field)| {
                            whole
                                .fields
                                .get(offset)
                                .is_none_or(|other| kinds_agree(&field.ty, &other.ty))
                        })
                }
                (None, _) | (_, None) => false,
            };
            if partial && part != whole {
                self.unite_as(whole, part, &mut work, false);
            }
        }
        while let Some((a, b)) = work.pop() {
            self.unite_as(a, b, &mut work, false);
        }
    }

    /// Where struct `id` ranks as an identity (smallest first): born in
    /// the deepest function (the lowest height), ties by the function's
    /// address, then by number.
    pub(crate) fn rank(&self, id: StructId) -> (u32, u64, u32) {
        let id = self.find(id);
        let height = self.heights.get(&id.function).copied().unwrap_or(0);
        (height, id.function, id.k)
    }

    /// Struct `id`'s layout.
    pub fn layout(&self, id: StructId) -> Option<&Layout> {
        self.layouts.get(&self.find(id))
    }

    /// The structs, with their layouts, by identity.
    pub fn iter(&self) -> impl Iterator<Item = (StructId, &Layout)> {
        self.layouts.iter().map(|(&id, layout)| (id, layout))
    }

    /// How many structs there are.
    pub fn len(&self) -> usize {
        self.layouts.len()
    }

    /// Whether there are none.
    pub fn is_empty(&self) -> bool {
        self.layouts.is_empty()
    }

    /// Evidence not kept, over the program.
    pub const fn conflicts(&self) -> usize {
        self.conflicts
    }

    /// How many structs have a declared identity.
    pub fn declared(&self) -> usize {
        self.identities.len()
    }

    /// Evidence the declared layouts overrode, over the program: a struct
    /// a second declared type claimed or two declared types refused to
    /// unite, and a field of a struct's own layout that reaches past its
    /// declared type's size or meets a declared field of another width at
    /// its offset.
    pub fn declared_conflicts(&self) -> usize {
        let Some(declared) = &self.declared else {
            return self.identity_conflicts;
        };
        let mut conflicts = self.identity_conflicts;
        for (id, &ty) in &self.identities {
            let (Some(layout), Some(Type::Struct(aggregate) | Type::Union(aggregate))) =
                (self.layouts.get(id), declared.get(ty))
            else {
                continue;
            };
            for (&offset, field) in &layout.fields {
                let past = offset.saturating_add(field.bytes()) > aggregate.size;
                let other = aggregate.fields.iter().any(|member| {
                    member.offset == offset
                        && declared.width(member.ty) != Some(u64::from(field.bits))
                });
                if past || other {
                    conflicts += 1;
                }
            }
        }
        conflicts
    }

    /// The type of the declared field of struct `id` at byte `at` that is
    /// `bits` wide (any width: 0), interned in `types`, where the struct
    /// has a declared identity and the field holds a value (a scalar or a
    /// pointer, as the table's own fields: an array or an aggregate field
    /// is memory whose accesses round on their own).
    pub(crate) fn declared_field(
        &self,
        id: StructId,
        at: u64,
        bits: u16,
        types: &mut Types,
    ) -> Option<TypeId> {
        let declared = self.declared.as_ref()?;
        let &ty = self.identities.get(&self.find(id))?;
        let (Type::Struct(aggregate) | Type::Union(aggregate)) = declared.get(ty)? else {
            return None;
        };
        let member = aggregate.fields.iter().find(|member| {
            member.offset == at
                && (bits == 0 || declared.width(member.ty) == Some(u64::from(bits)))
                && declared.value_width(member.ty).is_some()
                && !matches!(
                    declared.get(member.ty),
                    Some(
                        Type::Struct(_) | Type::Union(_) | Type::Array { .. } | Type::Vector { .. }
                    )
                )
        })?;
        copy(declared, member.ty, types, &mut BTreeMap::new())
    }

    /// Struct `id`'s C name: its class's ([`Self::class_name`]), else
    /// `struct_<function>_<k>`. (A struct with a declared identity prints
    /// as its declared type, which [`Self::intern`] interns instead.)
    pub fn name(&self, id: StructId) -> String {
        let id = self.find(id);
        if let Some(name) = self.class_name(id) {
            return name;
        }
        match self.names.get(&id.function) {
            Some(function) => format!("struct_{function}_{}", id.k),
            None => format!("struct_{:x}_{}", id.function, id.k),
        }
    }

    /// Where root `root` of the function at `function` points, if into a
    /// struct.
    pub(crate) fn root(&self, function: u64, root: Root) -> Option<(StructId, i64)> {
        self.roots
            .get(&function)?
            .iter()
            .find(|&&(at, _, _)| at == root)
            .map(|&(_, id, offset)| (self.find(id), offset))
    }

    /// The struct access `inst` of the function at `entry` is into, with
    /// the offset of its family's root in it.
    pub(crate) fn access(&self, entry: u64, inst: InstId) -> Option<(StructId, i64)> {
        self.accesses
            .get(&(entry, inst))
            .map(|&(id, base)| (self.find(id), base))
    }

    /// The struct the global object at `start` is, with the offset of its
    /// start in it.
    pub(crate) fn global(&self, start: u64) -> Option<(StructId, i64)> {
        self.globals
            .get(&start)
            .map(|&(id, at)| (self.find(id), at))
    }

    /// Struct `id` interned in `types` (once per table: `interned`), with
    /// the structs its fields point to.
    pub(crate) fn intern(
        &self,
        id: StructId,
        types: &mut Types,
        interned: &mut BTreeMap<StructId, TypeId>,
    ) -> Option<TypeId> {
        let id = self.find(id);
        if let Some(&known) = interned.get(&id) {
            return Some(known);
        }
        if let (Some(&ty), Some(declared)) = (self.identities.get(&id), &self.declared) {
            let ty = copy(declared, ty, types, &mut BTreeMap::new())?;
            interned.insert(id, ty);
            return Some(ty);
        }
        let layout = self.layouts.get(&id)?;
        let ty = types.intern(Type::Struct(Aggregate {
            name: Some(self.name(id)),
            size: layout.natural_size(),
            fields: Vec::new(),
        }));
        interned.insert(id, ty);
        let byte = types.intern(Type::UInt(8));
        let mut members = Vec::new();
        let mut at = 0u64;
        for (&offset, field) in &layout.fields {
            if offset > at {
                self.gap(layout, (at, offset), byte, types, interned, &mut members);
            }
            let name = self
                .member_name(id, offset, field, &members)
                .unwrap_or_else(|| format!("field_{offset:x}"));
            members.push(Member {
                offset,
                ty: self.field_type(&field.ty, types, interned),
                name: Some(name),
            });
            at = offset.saturating_add(field.bytes());
        }
        if let Some(aggregate) = types.aggregate_mut(ty) {
            aggregate.fields = members;
        }
        Some(ty)
    }

    /// How many structs are arrays' elements.
    pub fn elements(&self) -> usize {
        self.layouts
            .values()
            .filter(|layout| layout.element > 0)
            .count()
    }

    /// The members of `layout` filling its bytes `at..end`, which no
    /// field covers: the first array of [`Layout::arrays`] starting there
    /// (at a multiple of its element's width, a power of two, as C aligns
    /// it), from its start to `end` where that is a whole number of
    /// elements, at least one; the bytes before it, or all of them where
    /// none is, bytes no access reaches (`unknown_<hex>`).
    fn gap(
        &self,
        layout: &Layout,
        (at, end): (u64, u64),
        byte: TypeId,
        types: &mut Types,
        interned: &mut BTreeMap<StructId, TypeId>,
        members: &mut Vec<Member>,
    ) {
        let unknown = |types: &mut Types, members: &mut Vec<Member>, from: u64, to: u64| {
            if to > from {
                let ty = types.intern(Type::Array {
                    element: byte,
                    length: Some(to - from),
                });
                members.push(Member {
                    offset: from,
                    ty,
                    name: Some(format!("unknown_{from:x}")),
                });
            }
        };
        let array = layout.arrays.range(at..end).find_map(|(&start, element)| {
            let bytes = element.bytes();
            let whole = bytes.is_power_of_two()
                && start.is_multiple_of(bytes)
                && (end - start).is_multiple_of(bytes);
            whole.then_some((start, element, (end - start) / bytes))
        });
        let Some((start, element, length)) = array else {
            unknown(types, members, at, end);
            return;
        };
        unknown(types, members, at, start);
        let element = self.field_type(&element.ty, types, interned);
        let ty = types.intern(Type::Array {
            element,
            length: Some(length),
        });
        members.push(Member {
            offset: start,
            ty,
            name: Some(format!("field_{start:x}")),
        });
    }

    /// Field type `ty` interned in `types`.
    pub(crate) fn field_type(
        &self,
        ty: &FieldType,
        types: &mut Types,
        interned: &mut BTreeMap<StructId, TypeId>,
    ) -> TypeId {
        match ty {
            FieldType::Scalar(scalar) => types.intern(scalar.clone()),
            FieldType::Pointer(target) => {
                let target = target.clone().map(|target| types.intern(target));
                types.intern(Type::Pointer(target))
            }
            FieldType::Opaque => types.intern(Type::Pointer(None)),
            &FieldType::Struct(id) => {
                let target = self.intern(id, types, interned);
                types.intern(Type::Pointer(target))
            }
            &FieldType::Pointers(id) => {
                let target = self.intern(id, types, interned);
                let held = types.intern(Type::Pointer(target));
                types.intern(Type::Pointer(Some(held)))
            }
            FieldType::ScalarPointers(target) => {
                let target = target.clone().map(|target| types.intern(target));
                let held = types.intern(Type::Pointer(target));
                types.intern(Type::Pointer(Some(held)))
            }
            FieldType::Code {
                parameters,
                returns,
                variadic,
            } => {
                let parameters = parameters
                    .iter()
                    .map(|parameter| types.intern(parameter.clone()))
                    .collect();
                let returns = returns.clone().map(|returns| types.intern(returns));
                types.intern(Type::Code(Signature {
                    parameters,
                    returns,
                    variadic: *variadic,
                }))
            }
        }
    }
}

/// Every pair of `ids` (structs one type: each is tried with every other,
/// so two that agree meet though a third disagrees with both), the
/// first of each pair the earlier.
fn pairs(ids: &[StructId]) -> Vec<(StructId, StructId)> {
    ids.iter()
        .enumerate()
        .flat_map(|(index, &a)| {
            ids.get(index + 1..)
                .unwrap_or_default()
                .iter()
                .map(move |&b| (a, b))
        })
        .collect()
}

/// `name` if it is a plain C identifier (not mangled, no version).
fn plain(name: Option<&str>) -> Option<String> {
    let name = name?;
    let mut chars = name.chars();
    let first = chars.next()?;
    let identifier = (first.is_ascii_alphabetic() || first == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_');
    (identifier && !name.starts_with("_Z")).then(|| String::from(name))
}

/// Whether two layouts may be one struct's: they are one size (as C
/// lays them out: a struct that is a prefix of another, a generic list
/// node's link alone, is not the other, or every list would be one), and
/// every field of one that overlaps a field of the other is at its
/// offset and as wide (types may differ: the stronger stays).
fn compatible(a: &Layout, b: &Layout) -> bool {
    if a.natural_size() != b.natural_size() {
        return false;
    }
    overlap(a, b, false)
}

/// Whether every field of `b` that overlaps a field of `a` is at its
/// offset and as wide; where `one` (the evidence says they are one type),
/// also two scalars of different widths at one offset (one a part of the
/// other: [`fit`]), or one of them untyped bits holding the other whole
/// (a copy of it).
fn overlap(a: &Layout, b: &Layout, one: bool) -> bool {
    let scalar = |field: &Field| matches!(field.ty, FieldType::Scalar(_));
    b.fields.iter().all(|(&offset, field)| {
        let end = offset.saturating_add(field.bytes());
        a.fields
            .range(..end)
            .filter(|&(&at, kept)| offset < at.saturating_add(kept.bytes()))
            .all(|(&at, kept)| {
                (at == offset
                    && (kept.bits == field.bits || (one && scalar(kept) && scalar(field))))
                    || (one && (holds(kept, at, field, offset) || holds(field, offset, kept, at)))
            })
    })
}

/// Whether `wide` (at byte `at`) is untyped bits wider than `narrow` (at
/// byte `offset`) and holds it whole.
fn holds(wide: &Field, at: u64, narrow: &Field, offset: u64) -> bool {
    matches!(wide.ty, FieldType::Scalar(Type::Bits(_)))
        && wide.bits > narrow.bits
        && at <= offset
        && offset.saturating_add(narrow.bytes()) <= at.saturating_add(wide.bytes())
}

/// What a field holds, as far as two views of one struct must agree on it
/// ([`kinds_agree`]).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Held {
    Integer,
    Float,
    Aggregate,
    StructPointer,
    ScalarPointer,
    Pointers,
    Code,
}

/// What field type `ty` holds; `None` where it says no more than its
/// width (untyped bits, a pointer to nothing known).
fn held(ty: &FieldType) -> Option<Held> {
    match ty {
        FieldType::Scalar(Type::Bits(_)) | FieldType::Pointer(None) | FieldType::Opaque => None,
        FieldType::Scalar(
            Type::Int(_) | Type::UInt(_) | Type::Char { .. } | Type::Bool(_) | Type::Enum(_),
        ) => Some(Held::Integer),
        FieldType::Scalar(Type::Float(_)) => Some(Held::Float),
        FieldType::Scalar(
            Type::Pointer(_)
            | Type::Code(_)
            | Type::Struct(_)
            | Type::Union(_)
            | Type::Array { .. }
            | Type::Vector { .. },
        ) => Some(Held::Aggregate),
        FieldType::Struct(_) => Some(Held::StructPointer),
        FieldType::Pointer(Some(_)) => Some(Held::ScalarPointer),
        FieldType::Pointers(_) | FieldType::ScalarPointers(_) => Some(Held::Pointers),
        FieldType::Code { .. } => Some(Held::Code),
    }
}

/// Whether two views' field types at one offset may be one field's: one
/// says no more than its width, or both hold the same kind of value (two
/// integers, two pointers to structs, which unite).
fn kinds_agree(a: &FieldType, b: &FieldType) -> bool {
    match (held(a), held(b)) {
        (None, _) | (_, None) => true,
        (Some(a), Some(b)) => a == b,
    }
}

/// Whether every field `parts` shows is a field of `whole` at its offset:
/// as wide, or a scalar part of a wider scalar there (as [`fit`] takes
/// it), and `whole`'s fields overlap it as one struct's ([`overlap`]).
pub(crate) fn reads(whole: &Layout, parts: &Layout) -> bool {
    let scalar = |field: &Field| matches!(field.ty, FieldType::Scalar(_));
    overlap(whole, parts, true)
        && parts.fields.iter().all(|(offset, part)| {
            whole.fields.get(offset).is_some_and(|field| {
                field.bits == part.bits || (scalar(field) && scalar(part) && field.bits > part.bits)
            })
        })
}

/// Drops from `a` (the layout of a struct one type with `other`'s) the
/// accesses `other` shows to be of other fields: untyped bits holding
/// two or more fields of `other` whole (a copy of them: the fields
/// stay), and a scalar at whose offset `other` has a wider scalar that
/// overlaps no other field of `a` (a narrower access of a scalar reads
/// part of it, a byte test of a flags word: an access never reaches
/// past its field, so the wider shows the field's width).
fn fit(a: &mut Layout, other: &Layout) {
    // How many fields of `layout` `field` overlaps, and whether it holds
    // each of them whole.
    let inside = |offset: u64, field: &Field, layout: &Layout| {
        let end = offset.saturating_add(field.bytes());
        layout
            .fields
            .range(..end)
            .filter(|&(&at, kept)| offset < at.saturating_add(kept.bytes()))
            .fold((0usize, true), |(count, all), (&at, kept)| {
                (count + 1, all && holds(field, offset, kept, at))
            })
    };
    let scalar = |field: &Field| matches!(field.ty, FieldType::Scalar(_));
    let dropped: Vec<u64> = a
        .fields
        .iter()
        .filter(|&(&offset, field)| {
            let (count, all) = inside(offset, field, other);
            let copy = count >= 2 && all;
            let part = scalar(field)
                && other.fields.get(&offset).is_some_and(|wide| {
                    scalar(wide)
                        && wide.bits > field.bits
                        && a.fields
                            .range(offset..offset.saturating_add(wide.bytes()))
                            .count()
                            == 1
                });
            copy || part
        })
        .map(|(&offset, _)| offset)
        .collect();
    for offset in dropped {
        a.fields.remove(&offset);
    }
}

/// Whether `family` is a struct (see the [module](self)): with a stride,
/// if it is an array of structs ([`element`]); else exact accesses at two
/// or more offsets, or at one offset other than that of the member they
/// are through where `object` says that member is an object (a
/// parameter's value or a loaded pointer).
pub(crate) fn qualifies(family: &Family, object: impl Fn(Var) -> bool) -> bool {
    if family.stride != 0 {
        return element(family).is_some();
    }
    let exact = family
        .accesses
        .iter()
        .filter(|access| access.modulus == 0 && !access.indexed && access.bits.is_multiple_of(8));
    let mut offsets: Vec<i64> = exact.clone().map(|access| access.offset).collect();
    offsets.sort_unstable();
    offsets.dedup();
    if offsets.len() >= 2 {
        return true;
    }
    exact.into_iter().any(|access| {
        let own = family
            .members
            .iter()
            .find(|&&(var, _, _)| var == access.through)
            .map(|&(_, offset, _)| offset);
        own.is_some_and(|own| own != access.offset) && object(access.through)
    })
}

/// Whether the exact accesses of `family` (with no stride) are all one
/// byte wide: bytes read one by one, as an unrolled test of a string's
/// first characters is (`p[0] == '/'`, `p[1] == '.'`, `p[2] == 0`), or a
/// buffer's first and last. Offsets and widths alone do not say whether
/// the source had `p[1]` or `p->member`; of a byte, `field_1` says no
/// more than `[1]` does, and a struct of three `char`s is a declaration
/// to read that shows three things where there was one. So such a
/// family is no struct of its own (it still is one where a callee, a
/// field or a declaration says so: those claim it before any is born).
/// Of bash's 818 synthesised structs 148 were such, every one a string
/// or a `char` buffer.
pub(crate) fn bytes(family: &Family) -> bool {
    let mut exact = family
        .accesses
        .iter()
        .filter(|access| counted(access, 0))
        .peekable();
    family.stride == 0 && exact.peek().is_some() && exact.all(|access| access.bits == 8)
}

/// Whether access `access` of a family whose offsets repeat by `period`
/// (its stride; 0: none) is at a known place in its struct (an element's
/// where `period` is not 0): whole bytes, no index, through a member
/// whose modulus is 0 or a multiple of `period`.
pub(crate) const fn counted(access: &Access, period: u64) -> bool {
    let modulus = access.modulus;
    !access.indexed
        && access.bits > 0
        && access.bits.is_multiple_of(8)
        && (modulus == 0 || (period > 0 && modulus.is_multiple_of(period)))
}

/// The place in its struct of `offset` from the root of a family whose
/// root is at `base` in it and whose offsets repeat by `period` (0:
/// exact): `offset + base`, modulo `period`.
pub(crate) fn place(offset: i64, base: i64, period: u64) -> i64 {
    let at = offset.wrapping_add(base);
    match i64::try_from(period) {
        Ok(period) if period > 0 => at.rem_euclid(period),
        Ok(_) | Err(_) => at,
    }
}

/// The size of the element of `family` as an array of structs: its
/// stride `s`, where its accesses ([`counted`]) each lie in one
/// element at offsets modulo `s` with no two overlapping unless alike (a
/// narrower read of a wider field says it is one, not a struct), each
/// at a multiple of its natural
/// alignment with `s` a multiple of it too (C lays the element out with
/// no `packed` and `sizeof` `s`), and they are not one width `w` at
/// multiples of `w` (an array of scalars: `s` itself, an unrolled walk of
/// `w`-byte elements, `p[0]`, `p[1]`, `p += 2`, or a strided scan,
/// `p[0]`, `p += 4`, which the same accesses show and which need no
/// invented type: a struct of one field and unknown bytes made bash's
/// pointers disagree with their other uses, 194 more casts).
pub(crate) fn element(family: &Family) -> Option<u64> {
    let stride = family.stride;
    let period = i64::try_from(stride).ok().filter(|&s| s > 0)?;
    let mut fields: Vec<(u64, u64)> = Vec::new();
    for access in &family.accesses {
        if !counted(access, stride) {
            continue;
        }
        let at = access.offset.rem_euclid(period).unsigned_abs();
        let bytes = u64::from(access.bits / 8);
        let natural = bytes.next_power_of_two().min(16);
        let fits = at.saturating_add(bytes) <= stride
            && at.is_multiple_of(natural)
            && stride.is_multiple_of(natural);
        if !fits {
            return None;
        }
        fields.push((at, bytes));
    }
    fields.sort_unstable();
    fields.dedup();
    let overlap = fields
        .windows(2)
        .any(|pair| matches!(pair, &[(at, bytes), (next, _)] if at.saturating_add(bytes) > next));
    if overlap {
        return None;
    }
    let &(_, width) = fields.first()?;
    let scalars = fields
        .iter()
        .all(|&(at, bytes)| bytes == width && at.is_multiple_of(width))
        && stride.is_multiple_of(width);
    (!scalars).then_some(stride)
}

/// Whether the exact accesses of `family` ([`counted`]) are at offsets
/// from `origin` that are multiples of their narrowest width `w`, each
/// `w` wide or a vector move (16 bytes or more) a multiple of `w` wide
/// (with the stride: an array of `w`-byte scalars, read whole or by a
/// vectorised copy).
pub(crate) fn uniform(family: &Family, origin: i64) -> bool {
    let fields = family
        .accesses
        .iter()
        .filter(|access| counted(access, family.stride))
        .map(|access| {
            (
                access.offset.wrapping_sub(origin),
                i64::from(access.bits / 8),
            )
        });
    let Some(width) = fields.clone().map(|(_, bytes)| bytes).min() else {
        return false;
    };
    let stride = i64::try_from(family.stride).unwrap_or(1);
    width > 0
        && stride % width == 0
        && fields.clone().all(|(offset, bytes)| {
            (bytes == width || (bytes >= 16 && bytes % width == 0)) && offset % width == 0
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::typing::family::{Access, Builder};
    use alloc::vec;

    fn vars(count: u32) -> Vec<Var> {
        let mut system = binbun_typeinfer::System::default();
        (0..count).map(|_| system.var()).collect()
    }

    fn access(inst: u32, through: Var, offset: i64, bits: u16) -> Access {
        Access {
            inst: InstId(inst),
            through,
            offset,
            bits,
            value: None,
            indexed: false,
            scale: 0,
            modulus: 0,
        }
    }

    fn field(bits: u16, ty: Type, strength: u8) -> Field {
        Field {
            bits,
            ty: FieldType::Scalar(ty),
            strength: Strength(strength),
        }
    }

    fn link(to: StructId) -> Field {
        Field {
            bits: 64,
            ty: FieldType::Struct(to),
            strength: Strength(4),
        }
    }

    /// A list node born in `function`: a link to itself at 0, `bits` of
    /// data at 8, of `allocated` bytes (0: unknown).
    fn node(function: u64, bits: u16, allocated: u64) -> (StructId, Layout) {
        let id = StructId { function, k: 1 };
        let mut layout = Layout::default();
        layout.set_allocated(allocated);
        layout.add(0, link(id));
        layout.add(8, field(bits, Type::Int(bits), 4));
        (id, layout)
    }

    fn born(id: StructId, layout: Layout, callees: Vec<u64>) -> Contribution {
        Contribution {
            layouts: BTreeMap::from([(id, layout)]),
            callees,
            ..Contribution::default()
        }
    }

    #[test]
    fn a_users_version_replaces_a_struct_and_names_the_tables_structs() {
        let mut structs = Structs::default();
        let (node, layout) = node(0x10, 64, 16);
        structs.add(0x10, None, born(node, layout, vec![]));
        let holder = StructId {
            function: 0x20,
            k: 1,
        };
        let mut layout = Layout::default();
        layout.add(0, link(node));
        layout.add(8, field(32, Type::Int(32), 4));
        structs.add(0x20, Some("holder"), born(holder, layout, vec![0x10]));
        // The user's: the node by its table name (declared, not defined),
        // and a field renamed and retyped.
        let mut from = Types::new(64);
        let incomplete = from.intern(Type::Struct(Aggregate {
            name: Some("struct_10_1".into()),
            size: 0,
            fields: Vec::new(),
        }));
        let next = from.intern(Type::Pointer(Some(incomplete)));
        let count = from.intern(Type::UInt(32));
        let mine = from.intern(Type::Struct(Aggregate {
            name: Some("mine".into()),
            size: 16,
            fields: vec![
                Member {
                    offset: 0,
                    ty: next,
                    name: Some("next".into()),
                },
                Member {
                    offset: 8,
                    ty: count,
                    name: Some("count".into()),
                },
            ],
        }));
        let before = structs.clone();
        structs.state(&from, &[(holder, mine)]);
        let mut types = Types::new(64);
        let ty = structs
            .intern(holder, &mut types, &mut BTreeMap::new())
            .unwrap();
        let Some(Type::Struct(aggregate)) = types.get(ty) else {
            panic!("{:?}", types.get(ty));
        };
        assert_eq!(aggregate.name.as_deref(), Some("mine"));
        let names: Vec<_> = aggregate
            .fields
            .iter()
            .map(|member| member.name.as_deref())
            .collect();
        assert_eq!(names, [Some("next"), Some("count")]);
        let Some(&Type::Pointer(Some(target))) = types.get(aggregate.fields[0].ty) else {
            panic!("not a pointer");
        };
        let Some(Type::Struct(pointee)) = types.get(target) else {
            panic!("not a struct");
        };
        assert_eq!(
            (pointee.name.as_deref(), pointee.size, pointee.fields.len()),
            (Some("struct_10_1"), 16, 2),
            "the table's struct, not the empty one"
        );
        // The user's type is the field's evidence.
        let field = structs.declared_field(holder, 8, 32, &mut types).unwrap();
        assert_eq!(types.get(field), Some(&Type::UInt(32)));
        // A struct the table does not have is left out.
        let mut other = before;
        let missing = StructId {
            function: 0x30,
            k: 1,
        };
        other.state(&from, &[(missing, mine)]);
        assert_eq!(other.declared(), 0);
    }

    #[test]
    fn a_list_node_two_functions_see_is_one_recursive_struct_of_the_deepest() {
        // `walk` (at the lower address) calls `make`; each sees a node
        // linking to itself; `use` passes one family to both (a merge).
        let (made, made_layout) = node(0x200, 64, 0);
        let (walked, walked_layout) = node(0x100, 64, 0);
        let mut structs = Structs::default();
        structs.add(0x200, Some("make"), born(made, made_layout, Vec::new()));
        structs.add(
            0x100,
            Some("walk"),
            born(walked, walked_layout, vec![0x200]),
        );
        structs.add(
            0x300,
            Some("use"),
            Contribution {
                merges: vec![(walked, made)],
                callees: vec![0x100, 0x200],
                ..Contribution::default()
            },
        );
        // One struct, named by the deepest function (`make`: it calls
        // nothing), not by the lowest address.
        assert_eq!(structs.len(), 1);
        assert_eq!(structs.find(walked), made);
        assert_eq!(structs.name(walked), "struct_make_1");
        let layout = structs.layout(walked).unwrap();
        assert_eq!(
            layout.fields.get(&0).map(|field| field.ty.clone()),
            Some(FieldType::Struct(made))
        );
        // Its link prints as a pointer to itself.
        let mut types = Types::new(64);
        let ty = structs
            .intern(walked, &mut types, &mut BTreeMap::new())
            .unwrap();
        let Some(Type::Struct(aggregate)) = types.get(ty) else {
            panic!("not a struct");
        };
        let link = aggregate.fields.first().unwrap().ty;
        assert_eq!(types.get(link), Some(&Type::Pointer(Some(ty))));
    }

    /// `struct word_desc { char *word; int flags; }` and `struct word_list
    /// { struct word_list *next; struct word_desc *word; }` in a table of
    /// their own, with `word_list`'s id.
    fn word_list() -> (Types, TypeId) {
        let mut types = Types::new(64);
        let character = types.intern(Type::Char { signed: true });
        let string = types.intern(Type::Pointer(Some(character)));
        let int = types.intern(Type::Int(32));
        let desc = types.intern(Type::Struct(Aggregate {
            name: Some("word_desc".into()),
            size: 16,
            fields: vec![
                Member {
                    offset: 0,
                    ty: string,
                    name: Some("word".into()),
                },
                Member {
                    offset: 8,
                    ty: int,
                    name: Some("flags".into()),
                },
            ],
        }));
        let list = types.intern(Type::Struct(Aggregate {
            name: Some("word_list".into()),
            size: 16,
            fields: Vec::new(),
        }));
        let next = types.intern(Type::Pointer(Some(list)));
        let word = types.intern(Type::Pointer(Some(desc)));
        types.aggregate_mut(list).unwrap().fields = vec![
            Member {
                offset: 0,
                ty: next,
                name: Some("next".into()),
            },
            Member {
                offset: 8,
                ty: word,
                name: Some("word".into()),
            },
        ];
        (types, list)
    }

    #[test]
    fn a_declared_struct_names_the_table_struct_and_passes_through_its_pointers() {
        // `copy` sees a node linking to itself at 0 and pointing to
        // another struct at 8 (accessed 8 bytes wide at 8, where the
        // declared `flags` is 4: a conflict); its parameter is declared
        // `struct word_list *`.
        let node = StructId {
            function: 0x100,
            k: 1,
        };
        let desc = StructId {
            function: 0x100,
            k: 2,
        };
        let mut layout = Layout::default();
        layout.add(0, link(node));
        layout.add(8, link(desc));
        let mut desc_layout = Layout::default();
        desc_layout.add(0, field(64, Type::Bits(64), 4));
        desc_layout.add(8, field(64, Type::Int(64), 4));
        let (declared, list) = word_list();
        let mut structs = Structs::default();
        structs.add(
            0x100,
            Some("copy"),
            Contribution {
                layouts: BTreeMap::from([(node, layout), (desc, desc_layout)]),
                declared: vec![(node, list)],
                declared_types: Some(declared),
                ..Contribution::default()
            },
        );
        assert_eq!(structs.declared(), 2);
        assert_eq!(structs.declared_conflicts(), 1);
        // Both print as the declared types, by name and layout: the
        // node's link is `struct word_list *`, its word `struct word_desc *`.
        let mut types = Types::new(64);
        let mut interned = BTreeMap::new();
        let ty = structs.intern(node, &mut types, &mut interned).unwrap();
        let Some(Type::Struct(aggregate)) = types.get(ty).cloned() else {
            panic!("not a struct");
        };
        assert_eq!(aggregate.name.as_deref(), Some("word_list"));
        assert_eq!(
            types.get(aggregate.fields[0].ty),
            Some(&Type::Pointer(Some(ty)))
        );
        let pointed = structs.intern(desc, &mut types, &mut interned).unwrap();
        assert_eq!(
            types.get(aggregate.fields[1].ty),
            Some(&Type::Pointer(Some(pointed)))
        );
        let Some(Type::Struct(word_desc)) = types.get(pointed) else {
            panic!("not a struct");
        };
        assert_eq!(word_desc.name.as_deref(), Some("word_desc"));
        // Its declared field, not the table's 64-bit access, types `flags`.
        let flags = structs.declared_field(desc, 8, 32, &mut types).unwrap();
        assert_eq!(types.get(flags), Some(&Type::Int(32)));
        assert_eq!(structs.declared_field(desc, 8, 64, &mut types), None);
    }

    #[test]
    fn structs_a_field_points_to_twice_are_one() {
        // A list whose link one function saw pointing to `a`, another to
        // `b`: one field points to one type.
        let a = StructId {
            function: 0x10,
            k: 1,
        };
        let b = StructId {
            function: 0x20,
            k: 1,
        };
        let list = StructId {
            function: 0x30,
            k: 1,
        };
        let mut structs = Structs::default();
        for id in [a, b] {
            let mut layout = Layout::default();
            layout.add(0, field(32, Type::Int(32), 4));
            structs.add(id.function, None, born(id, layout, Vec::new()));
        }
        let mut first = Layout::default();
        first.add(8, link(a));
        structs.add(0x30, None, born(list, first, Vec::new()));
        let mut second = Layout::default();
        second.add(8, link(b));
        structs.add(0x40, None, born(list, second, vec![0x30]));
        assert_eq!(structs.find(b), a);
        assert_eq!(structs.len(), 2);
    }

    #[test]
    fn allocations_of_different_sizes_are_not_one_object() {
        let (small, a) = node(0x10, 64, 16);
        let (large, b) = node(0x20, 64, 96);
        let mut structs = Structs::default();
        structs.add(0x10, None, born(small, a, Vec::new()));
        structs.add(0x20, None, born(large, b, Vec::new()));
        structs.add(
            0x30,
            None,
            Contribution {
                merges: vec![(small, large)],
                ..Contribution::default()
            },
        );
        assert_eq!(structs.len(), 2);
        assert_ne!(structs.find(large), structs.find(small));
        // A field past an allocation is not the object's.
        let mut grown = Layout::default();
        grown.add(16, field(32, Type::Int(32), 4));
        structs.add(0x40, None, born(small, grown, vec![0x10]));
        let layout = structs.layout(small).unwrap();
        assert_eq!((layout.natural_size(), layout.fields.len()), (16, 2));
        // As large as the allocation, so `malloc(16)` holds it.
        let mut types = Types::new(64);
        let ty = structs
            .intern(small, &mut types, &mut BTreeMap::new())
            .unwrap();
        assert_eq!(types.width(ty), Some(128));
    }

    #[test]
    fn a_global_table_is_one_struct_over_the_program() {
        // Two functions loop over one global table of 16-byte elements,
        // each finding its element first: the table has one.
        let element = |function: u64, bits: u16| {
            let mut layout = Layout::default();
            layout.set_element(16);
            layout.add(0, field(8, Type::UInt(8), 4));
            layout.add(8, field(bits, Type::Int(bits), 4));
            (StructId { function, k: 1 }, layout)
        };
        let (first, a) = element(0x10, 64);
        let (second, b) = element(0x20, 64);
        let mut structs = Structs::default();
        let mut contribution = born(first, a, Vec::new());
        contribution.globals = vec![(0x5000, first, 0)];
        structs.add(0x10, Some("get_flags"), contribution);
        let mut contribution = born(second, b, Vec::new());
        contribution.globals = vec![(0x5000, second, 0)];
        structs.add(0x20, Some("set_flags"), contribution);
        assert_eq!(structs.global(0x5000), Some((first, 0)));
        assert_eq!(structs.find(second), first);
        assert_eq!(structs.len(), 1);
        assert_eq!(structs.layout(second).map(Layout::natural_size), Some(16));
        assert_eq!(structs.name(second), "struct_get_flags_1");
    }

    #[test]
    fn at_a_tie_the_narrower_fields_stay() {
        let mut wide_first = Layout::default();
        wide_first.add(8, field(64, Type::Int(64), 4));
        wide_first.add(8, field(32, Type::Int(32), 4));
        wide_first.add(12, field(32, Type::Int(32), 4));
        let mut narrow_first = Layout::default();
        narrow_first.add(8, field(32, Type::Int(32), 4));
        narrow_first.add(12, field(32, Type::Int(32), 4));
        narrow_first.add(8, field(64, Type::Int(64), 4));
        for layout in [wide_first, narrow_first] {
            let kept: Vec<(u64, u16)> = layout
                .fields
                .iter()
                .map(|(&offset, field)| (offset, field.bits))
                .collect();
            assert_eq!(kept, [(8, 32), (12, 32)]);
        }
        // A stronger wide access still wins.
        let mut layout = Layout::default();
        layout.add(8, field(32, Type::Int(32), 4));
        layout.add(
            8,
            field(64, Type::Float(binbun_semantics::ir::Format::Double), 5),
        );
        assert_eq!(layout.fields.get(&8).map(|field| field.bits), Some(64));
    }

    #[test]
    fn structs_one_type_unite_by_their_fields_each_with_every_other() {
        let id = |function| StructId { function, k: 1 };
        let (whole, prefix, copied) = (id(0x10), id(0x20), id(0x30));
        let base = |layout: &mut Layout| {
            layout.add(0, field(32, Type::Int(32), 4));
            layout.add(8, field(64, Type::Bits(64), 4));
        };
        // 48 bytes, a 32-bit field at 32 (untyped: read whole, one field).
        let mut a = Layout::default();
        base(&mut a);
        a.add(16, field(64, Type::UInt(64), 4));
        a.add(24, field(64, Type::Int(64), 4));
        a.add(32, field(32, Type::Bits(32), 4));
        a.add(40, field(64, Type::Int(64), 4));
        // 40 bytes, a byte at 32; the second copying 16 to 31 at once.
        let mut b = Layout::default();
        base(&mut b);
        b.add(32, field(8, Type::UInt(8), 4));
        let mut c = b.clone();
        c.add(
            16,
            Field {
                bits: 128,
                ty: FieldType::Scalar(Type::Bits(128)),
                strength: Strength(4),
            },
        );
        let table = || {
            let mut structs = Structs::default();
            for (id, layout) in [(whole, &a), (prefix, &b), (copied, &c)] {
                structs.add(id.function, None, born(id, layout.clone(), Vec::new()));
            }
            structs
        };
        // Met otherwise (a family, a field), a prefix of another is not
        // it, nor one whose field at 32 is of another width.
        let mut sized = table();
        sized.unite_all(vec![(whole, prefix), (whole, copied)]);
        assert_eq!(sized.len(), 3);
        // One type whatever the sizes: one struct, the copy's fields the
        // narrower ones, the byte at 32 a part of the 32-bit field there
        // (no conflict).
        let mut one = table();
        let before = one.conflicts();
        one.unite_one_type(&[whole, prefix, copied]);
        assert_eq!(one.len(), 1);
        let layout = one.layout(copied).unwrap();
        let kept: Vec<(u64, u16)> = layout
            .fields
            .iter()
            .map(|(&offset, field)| (offset, field.bits))
            .collect();
        assert_eq!(
            kept,
            [(0, 32), (8, 64), (16, 64), (24, 64), (32, 32), (40, 64)]
        );
        assert_eq!(layout.natural_size(), 48);
        assert_eq!(one.conflicts(), before);
        // Fields that overlap at different offsets are no one struct; the
        // others still meet though the first agrees with neither.
        let mut askew = Layout::default();
        askew.add(4, field(64, Type::Int(64), 4));
        let mut structs = table();
        let other = id(0x08);
        structs.add(0x08, None, born(other, askew, Vec::new()));
        structs.unite_one_type(&[other, whole, prefix]);
        assert_ne!(structs.find(other), structs.find(whole));
        assert_eq!(structs.find(prefix), structs.find(whole));
    }

    #[test]
    fn two_fields_make_a_struct_and_a_stride_an_array() {
        let v = vars(2);
        let mut family = Family {
            members: vec![(v[0], 0, 0), (v[1], 8, 0)],
            stride: 0,
            accesses: vec![access(1, v[0], 0, 64), access(2, v[1], 8, 32)],
        };
        assert!(qualifies(&family, |_| false));
        family.stride = 8;
        assert!(!qualifies(&family, |_| true));
    }

    #[test]
    fn one_field_is_a_struct_only_off_an_object_pointer() {
        let v = vars(1);
        let family = Family {
            members: vec![(v[0], 0, 0)],
            stride: 0,
            accesses: vec![access(1, v[0], 8, 64), access(2, v[0], 8, 64)],
        };
        assert!(qualifies(&family, |var| var == v[0]));
        assert!(!qualifies(&family, |_| false));
        let scalar = Family {
            accesses: vec![access(1, v[0], 0, 64)],
            ..family
        };
        assert!(!qualifies(&scalar, |_| true));
    }

    #[test]
    fn a_conflict_keeps_the_strongest_field_and_no_union() {
        let mut layout = Layout::default();
        layout.add(0, field(64, Type::UInt(64), 3));
        layout.add(0, field(64, Type::Int(64), 4));
        layout.add(
            4,
            field(32, Type::Float(binbun_semantics::ir::Format::Single), 2),
        );
        layout.add(8, field(32, Type::Int(32), 4));
        assert_eq!(layout.fields.len(), 2);
        assert_eq!(
            layout.fields.get(&0).map(|f| f.ty.clone()),
            Some(FieldType::Scalar(Type::Int(64)))
        );
        assert_eq!(layout.conflicts, 2);
        assert_eq!(layout.size(), 12);
        let mut types = Types::new(64);
        let mut structs = Structs::default();
        let id = StructId {
            function: 0x4c2a0,
            k: 1,
        };
        structs.add(
            0x4c2a0,
            Some("make_word_list"),
            Contribution {
                layouts: BTreeMap::from([(id, layout)]),
                ..Contribution::default()
            },
        );
        let ty = structs
            .intern(id, &mut types, &mut BTreeMap::new())
            .unwrap();
        let Some(Type::Struct(aggregate)) = types.get(ty) else {
            panic!("not a struct");
        };
        assert_eq!(aggregate.name.as_deref(), Some("struct_make_word_list_1"));
        let names: Vec<_> = aggregate
            .fields
            .iter()
            .map(|f| f.name.clone().unwrap())
            .collect();
        assert_eq!(names, ["field_0", "field_8"]);
    }

    #[test]
    fn names_are_by_birth_function_and_number_not_visit_order() {
        let id = |function, k| StructId { function, k };
        let mut one = Structs::default();
        let layout = |offset| Layout {
            fields: BTreeMap::from([(offset, field(32, Type::Int(32), 4))]),
            ..Layout::default()
        };
        let a = Contribution {
            layouts: BTreeMap::from([(id(0x10, 1), layout(0)), (id(0x10, 2), layout(4))]),
            ..Contribution::default()
        };
        // A caller adds a field to its callee's struct.
        let b = Contribution {
            layouts: BTreeMap::from([(id(0x10, 2), layout(8))]),
            ..Contribution::default()
        };
        one.add(0x10, Some("_ZN3fooEv"), a);
        one.add(0x20, Some("caller"), b);
        assert_eq!(one.name(id(0x10, 2)), "struct_10_2");
        assert_eq!(one.layout(id(0x10, 2)).map(Layout::size), Some(12));
        assert_eq!(one.len(), 2);
    }

    #[test]
    fn unaccessed_bytes_between_fields_are_unknown() {
        let mut structs = Structs::default();
        let id = StructId {
            function: 0x10,
            k: 1,
        };
        let mut layout = Layout::default();
        layout.add(0, field(32, Type::Int(32), 4));
        layout.add(16, field(64, Type::Int(64), 4));
        structs.add(
            0x10,
            Some("f"),
            Contribution {
                layouts: BTreeMap::from([(id, layout)]),
                ..Contribution::default()
            },
        );
        let mut types = Types::new(64);
        let ty = structs
            .intern(id, &mut types, &mut BTreeMap::new())
            .unwrap();
        let Some(Type::Struct(aggregate)) = types.get(ty).cloned() else {
            panic!("not a struct");
        };
        assert_eq!(aggregate.size, 24);
        let gap = aggregate.fields.get(1).unwrap();
        assert_eq!(gap.name.as_deref(), Some("unknown_4"));
        let byte = types.intern(Type::UInt(8));
        assert_eq!(
            types.get(gap.ty),
            Some(&Type::Array {
                element: byte,
                length: Some(12)
            })
        );
    }

    fn strided(stride: u64, accesses: &[(i64, u16)]) -> Family {
        let v = vars(1);
        Family {
            members: vec![(v[0], 0, 0)],
            stride,
            accesses: accesses
                .iter()
                .zip(1..)
                .map(|(&(offset, bits), inst)| access(inst, v[0], offset, bits))
                .collect(),
        }
    }

    #[test]
    fn bytes_read_one_by_one_are_no_members() {
        // `p[0] == '/'`, `p[1] == '.'`, `p[2] == 0`: a string's first
        // characters; a buffer's first and last byte.
        assert!(bytes(&strided(0, &[(0, 8), (1, 8), (2, 8)])));
        assert!(bytes(&strided(0, &[(0, 8), (4095, 8)])));
        // A wider access among them is a member of something.
        assert!(!bytes(&strided(0, &[(0, 8), (4, 32)])));
        // A stride's accesses are judged as its element.
        assert!(!bytes(&strided(1, &[(0, 8)])));
    }

    #[test]
    fn a_stride_is_an_array_of_structs_only_with_fields_no_scalar_explains() {
        // 8 and 4 bytes at 0 and 8 of a 16-byte step, the next element's
        // first field at 16: an array of 16-byte structs.
        let pairs = strided(16, &[(0, 64), (8, 32), (16, 64), (-4, 32)]);
        assert_eq!(element(&pairs), Some(16));
        assert!(qualifies(&pairs, |_| false));
        // One width at multiples of it: scalars (an unrolled walk, a
        // strided scan).
        assert_eq!(element(&strided(16, &[(0, 64), (8, 64)])), None);
        assert_eq!(element(&strided(32, &[(0, 8)])), None);
        assert!(!qualifies(&strided(1, &[(0, 8)]), |_| true));
        // A field across two elements, a field C would misalign, a step
        // that is no multiple of a field's alignment: no element.
        assert_eq!(element(&strided(16, &[(0, 32), (12, 64)])), None);
        assert_eq!(element(&strided(16, &[(0, 32), (4, 64)])), None);
        assert_eq!(element(&strided(12, &[(0, 64), (8, 32)])), None);
        // Accesses whose place in the element is unknown say nothing.
        let mut indexed = strided(16, &[(0, 64), (8, 32)]);
        indexed.accesses.iter_mut().for_each(|a| a.indexed = true);
        assert_eq!(element(&indexed), None);
    }

    #[test]
    fn nested_loops_over_rows_are_one_dimension_of_the_inner_element() {
        // `base + 160·i + 16·j`: the outer step is a multiple of the
        // inner one, so the family's stride (their gcd) is the inner
        // element, and the row is not a type of its own.
        let v = vars(3);
        let mut builder = Builder::new(3);
        builder.relate(0, 1, 0, 0);
        builder.period(1, 160);
        builder.relate(1, 2, 0, 0);
        builder.period(2, 16);
        let vars: Vec<Option<Var>> = v.iter().copied().map(Some).collect();
        let mut families = builder.finish(&vars);
        families.access(InstId(1), v[2], 0, 64, None, 0);
        families.access(InstId(2), v[2], 8, 16, None, 0);
        let (index, _, _) = families.of(v[2]).unwrap();
        let family = families.get(index).unwrap();
        assert_eq!(family.stride, 16);
        assert_eq!(element(family), Some(16));
    }

    #[test]
    fn an_element_is_its_stride_in_size_and_holds_no_field_past_it() {
        let mut layout = Layout::default();
        layout.set_element(24);
        layout.add(0, field(64, Type::Int(64), 4));
        layout.add(8, field(32, Type::Int(32), 4));
        // The natural size would be 16; the element is the loop's step.
        assert_eq!(layout.natural_size(), 24);
        layout.add(20, field(64, Type::Int(64), 4));
        assert_eq!(layout.fields.len(), 2);
        assert_eq!(layout.conflicts, 1);
        // Another step for the same struct is a conflict; the first stays.
        layout.set_element(16);
        assert_eq!((layout.element, layout.conflicts), (24, 2));
        // A struct whose fields reach past a step is not that element.
        let mut wide = Layout::default();
        wide.add(16, field(64, Type::Int(64), 4));
        wide.set_element(16);
        assert_eq!((wide.element, wide.conflicts), (0, 1));
        let id = StructId {
            function: 0x10,
            k: 1,
        };
        let mut structs = Structs::default();
        structs.add(
            0x10,
            None,
            Contribution {
                layouts: BTreeMap::from([(id, layout)]),
                ..Contribution::default()
            },
        );
        let mut types = Types::new(64);
        let ty = structs
            .intern(id, &mut types, &mut BTreeMap::new())
            .unwrap();
        let Some(Type::Struct(aggregate)) = types.get(ty) else {
            panic!("not a struct");
        };
        assert_eq!(aggregate.size, 24);
        assert_eq!(structs.elements(), 1);
    }
}
