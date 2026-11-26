//! The decompiler's L2 variables mapped to the ground truth and scored.
//!
//! **Mapping**, most confident first:
//! - parameters by place: a source parameter's register or stack slot at
//!   the function's entry (its stated location there, else its place under
//!   the calling convention, [`abi_registers`], [`abi_stack`]) against the
//!   L2 parameter whose origin is that register or slot;
//! - the return value, by function (under Microsoft x64, parameters and
//!   returns of structs of other than 1, 2, 4 or 8 bytes are compared as
//!   the pointer to a copy the register holds);
//! - stack variables by frame offset: a source variable in one stack slot
//!   for all its stated ranges (canonical-frame-address relative, see
//!   [`Place::Stack`]) against the L2 variable made from the slot at the
//!   same offset from the entry stack pointer ([`cfa_to_entry`]: x86-64's
//!   canonical frame address is the entry stack pointer + 8, AArch64's is
//!   the entry stack pointer), or the field of a frame struct
//!   ([`Ast::frames`]) made from that slot;
//! - register locals by register and address: a source local in a
//!   register for some of its stated ranges (not in one stack slot for
//!   all of them) against the L2 local held in that register
//!   ([`Origin::Held`]) at the most of the instructions in those ranges
//!   that read or assign it (by the provenance of the statements and
//!   expressions that do, [`held_at`]); none on a tie. Several source
//!   locals may map to one L2 local ([`Report::register_shared`]).
//!
//! **Scores** per mapped variable: kind, width, signedness, pointer target,
//! and the distance, interval and conservativeness of TIE (Lee et al., NDSS
//! 2011) on the lattice of [`Node`]. For pointers to structs, the offsets
//! and widths the decompiler accesses through them against the declared
//! fields ([`FieldScore`]).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Write as _};

use binbun::Database;
use binbun::debug::cfa_to_entry;
use binbun::decompile::Options;
use binbun_ast::ir::{
    Expr, ExprId, Function as Ast, Origin, Place as AstPlace, Stmt, VarId, VarKind,
};
use binbun_ast::types::{Type as AstType, TypeId as AstTypeId};
use binbun_debuginfo::info::model::{
    DebugModel, Encoding, Function as DebugFunction, Place, Type, TypeId, Variable,
};
use binbun_loader::Format;
use binbun_semantics::ir::{Binary, Format as FloatFormat, RegisterId};

use crate::extras::{Extras, Registers};

/// What a type is, as far as the scores look: its class, width, signedness,
/// and for a pointer what it points to (one level).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Shape {
    /// The class.
    pub class: Class,
    /// The width in bytes, if it has one.
    pub bytes: Option<u64>,
    /// For a pointer: what it points to (`None`: unknown, `void *`).
    pub target: Option<Box<Shape>>,
    /// For a struct: its name and size, its identity across functions.
    pub identity: Option<(String, u64)>,
}

/// The classes of [`Shape`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Class {
    /// Nothing known but the width (L2's `bits(n)`).
    Bits,
    /// An integer of unknown signedness.
    Integer,
    /// A signed integer (signed `char`, signed enums).
    Signed,
    /// An unsigned integer.
    Unsigned,
    /// A boolean.
    Bool,
    /// A floating-point number.
    Float,
    /// A data pointer.
    Pointer,
    /// A pointer to code.
    Code,
    /// A struct, class or union by value.
    Struct,
    /// An array by value.
    Array,
    /// No value.
    Void,
    /// Anything else (vectors, complex numbers, unreadable types).
    Other,
}

/// A node of the lattice the distances are measured on, from the top:
///
/// ```text
/// ⊤
/// └ bits(n)                         width only
///   ├ num(n)                        an integer, signedness unknown
///   │ ├ int(n)                      signed (signed char, signed enums)
///   │ └ uint(n)                     unsigned (bool is not here)
///   ├ bool(n)
///   ├ float(n)
///   ├ ptr                           a data pointer, target unknown (void *)
///   │ ├ ptr(class of the target)    num, int, uint, float, struct, ptr...
///   │ └ code                        a pointer to code
///   ├ struct(n)                     by value
///   └ array(n)                      by value
/// ```
///
/// A type's node path is its chain from ⊤; the distance between two types
/// is the number of edges between their nodes; a type is conservative for
/// the truth when its node is the truth's or above it; its interval is how
/// many levels lie between its node and the leaves below it (0 for a leaf).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Node {
    /// `bits(n)`, by width in bytes (0: unknown).
    Bits(u64),
    /// `num(n)`.
    Num,
    /// `int(n)`.
    Int,
    /// `uint(n)`.
    UInt,
    /// `bool(n)`.
    Bool,
    /// `float(n)`.
    Float,
    /// `ptr`.
    Pointer,
    /// `ptr(class)`.
    PointerTo(Class),
    /// `code`.
    Code,
    /// `struct(n)`.
    Struct,
    /// `array(n)`.
    Array,
}

impl Shape {
    fn new(class: Class, bytes: Option<u64>) -> Self {
        Self {
            class,
            bytes,
            target: None,
            identity: None,
        }
    }

    /// The path from ⊤ (exclusive) to the shape's node.
    pub fn path(&self) -> Vec<Node> {
        let mut path = vec![Node::Bits(self.bytes.unwrap_or(0))];
        match self.class {
            Class::Bits | Class::Void | Class::Other => {}
            Class::Integer => path.push(Node::Num),
            Class::Signed => path.extend([Node::Num, Node::Int]),
            Class::Unsigned => path.extend([Node::Num, Node::UInt]),
            Class::Bool => path.push(Node::Bool),
            Class::Float => path.push(Node::Float),
            Class::Pointer => {
                path.push(Node::Pointer);
                if let Some(target) = &self.target {
                    path.push(Node::PointerTo(target.class));
                }
            }
            Class::Code => path.extend([Node::Pointer, Node::Code]),
            Class::Struct => path.push(Node::Struct),
            Class::Array => path.push(Node::Array),
        }
        if self.class == Class::Void {
            path.clear();
        }
        path
    }

    /// Levels between the shape's node and the leaves below it.
    pub fn interval(&self) -> usize {
        match self.class {
            Class::Void | Class::Other => 3,
            Class::Bits => 2,
            Class::Integer => 1,
            Class::Pointer if self.target.is_none() => 1,
            Class::Signed
            | Class::Unsigned
            | Class::Bool
            | Class::Float
            | Class::Pointer
            | Class::Code
            | Class::Struct
            | Class::Array => 0,
        }
    }
}

/// The edges between two nodes of the lattice.
pub fn distance(a: &Shape, b: &Shape) -> usize {
    let (a, b) = (a.path(), b.path());
    let common = a.iter().zip(&b).take_while(|(x, y)| x == y).count();
    a.len() + b.len() - 2 * common
}

/// Whether `inferred` is `truth`'s node or above it.
pub fn conservative(inferred: &Shape, truth: &Shape) -> bool {
    let (inferred, truth) = (inferred.path(), truth.path());
    truth.starts_with(&inferred)
}

/// A source type's shape (typedefs looked through).
pub fn debug_shape(model: &DebugModel, id: TypeId) -> Shape {
    debug_shape_within(model, id, 2)
}

fn debug_shape_within(model: &DebugModel, id: TypeId, depth: u32) -> Shape {
    let id = model.resolve(id);
    let bytes = model.size(id);
    match model.ty(id) {
        Type::Void => Shape::new(Class::Void, None),
        Type::Base { encoding, .. } => {
            let class = match encoding {
                Encoding::Signed | Encoding::Char { signed: true } => Class::Signed,
                Encoding::Unsigned | Encoding::Char { signed: false } => Class::Unsigned,
                Encoding::Bool => Class::Bool,
                Encoding::Float => Class::Float,
                Encoding::Other => Class::Other,
            };
            Shape::new(class, bytes)
        }
        Type::Enum { signed, .. } => Shape::new(
            if *signed {
                Class::Signed
            } else {
                Class::Unsigned
            },
            bytes,
        ),
        Type::Pointer { target, .. } => {
            let target = model.resolve(*target);
            match model.ty(target) {
                Type::Function { .. } => Shape::new(Class::Code, bytes),
                Type::Void => Shape::new(Class::Pointer, bytes),
                Type::Base { .. }
                | Type::Pointer { .. }
                | Type::Array { .. }
                | Type::Composite(_)
                | Type::Enum { .. }
                | Type::Typedef { .. }
                | Type::Unknown => {
                    let mut shape = Shape::new(Class::Pointer, bytes);
                    if let Some(depth) = depth.checked_sub(1) {
                        shape.target = Some(Box::new(debug_shape_within(model, target, depth)));
                    }
                    shape
                }
            }
        }
        Type::Array { .. } => Shape::new(Class::Array, bytes),
        Type::Composite(composite) => Shape {
            identity: composite
                .name
                .clone()
                .map(|name| (name, composite.size.unwrap_or(0))),
            ..Shape::new(Class::Struct, bytes)
        },
        Type::Function { .. } | Type::Typedef { .. } | Type::Unknown => {
            Shape::new(Class::Other, bytes)
        }
    }
}

/// An L2 type's shape.
pub fn l2_shape(ast: &Ast, id: AstTypeId) -> Shape {
    l2_shape_within(ast, id, 2)
}

fn l2_shape_within(ast: &Ast, id: AstTypeId, depth: u32) -> Shape {
    let bytes = ast.types.width(id).map(|bits| bits.div_ceil(8));
    let Some(ty) = ast.types.get(id) else {
        return Shape::new(Class::Other, None);
    };
    match ty {
        AstType::Bits(_) => Shape::new(Class::Bits, bytes),
        AstType::Int(_) | AstType::Char { signed: true } => Shape::new(Class::Signed, bytes),
        AstType::UInt(_) | AstType::Char { signed: false } => Shape::new(Class::Unsigned, bytes),
        AstType::Bool(_) => Shape::new(Class::Bool, bytes),
        AstType::Enum(enumeration) => Shape::new(
            if enumeration.signed {
                Class::Signed
            } else {
                Class::Unsigned
            },
            bytes,
        ),
        AstType::Float(format) => {
            let bytes = match format {
                FloatFormat::Half => 2,
                FloatFormat::Single => 4,
                FloatFormat::Double => 8,
                FloatFormat::Extended => 16,
            };
            Shape::new(Class::Float, Some(bytes))
        }
        AstType::Pointer(target) => {
            let mut shape = Shape::new(Class::Pointer, bytes);
            if let (Some(target), Some(depth)) = (target, depth.checked_sub(1)) {
                shape.target = Some(Box::new(l2_shape_within(ast, *target, depth)));
            }
            shape
        }
        AstType::Code(_) => Shape::new(Class::Code, bytes),
        AstType::Struct(aggregate) | AstType::Union(aggregate) => Shape {
            identity: aggregate.name.clone().map(|name| (name, aggregate.size)),
            ..Shape::new(Class::Struct, bytes)
        },
        AstType::Array { .. } => Shape::new(Class::Array, bytes),
        AstType::Vector { .. } => Shape::new(Class::Other, bytes),
    }
}

/// What a mapped variable's comparison found.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Tally {
    /// Variables compared.
    pub mapped: usize,
    /// Of them, the decompiler gave only a width (`bits(n)`).
    pub undecided: usize,
    /// Its class equals the truth's.
    pub class: usize,
    /// Its width equals the truth's.
    pub width: usize,
    /// Both integers: the decompiler's signedness is decided.
    pub sign_decided: usize,
    /// Of those, it equals the truth's.
    pub sign: usize,
    /// Both pointers with a known target in the truth.
    pub targets: usize,
    /// Of those, the decompiler's target has the truth's class and width.
    pub target: usize,
    /// The truth is a pointer to a named struct.
    pub struct_pointers: usize,
    /// Of those, the decompiler's target is a struct of the same name.
    pub struct_identity: usize,
    /// Per named struct the truth points to (name and size): the names of
    /// the decompiler's structs its pointer points to there, counted. One
    /// source struct under several names is split; one name over several
    /// source structs is merged ([`Self::identity_errors`]).
    pub identities: BTreeMap<(String, u64), BTreeMap<String, usize>>,
    /// The sum of TIE distances.
    pub distance: usize,
    /// The sum of TIE intervals.
    pub interval: usize,
    /// Conservative results.
    pub conservative: usize,
    /// Distances: how many at 0, 1, 2, ... (the last bucket: 4 and more).
    pub distances: [usize; 5],
    /// (truth class, decompiler class) pairs, counted.
    pub confusion: BTreeMap<(Class, Class), usize>,
}

impl Tally {
    /// Adds the comparison of `inferred` with `truth`; the problem found,
    /// if any.
    pub fn add(&mut self, inferred: &Shape, truth: &Shape) -> Option<String> {
        self.mapped += 1;
        *self
            .confusion
            .entry((truth.class, inferred.class))
            .or_default() += 1;
        let d = distance(inferred, truth);
        self.distance += d;
        if let Some(bucket) = self.distances.get_mut(d.min(4)) {
            *bucket += 1;
        }
        self.interval += inferred.interval();
        self.conservative += usize::from(conservative(inferred, truth));
        self.undecided += usize::from(inferred.class == Class::Bits);
        let class = classes_match(inferred.class, truth.class);
        self.class += usize::from(class);
        self.width += usize::from(inferred.bytes == truth.bytes);
        let integers = [Class::Signed, Class::Unsigned];
        if integers.contains(&truth.class) && integers.contains(&inferred.class) {
            self.sign_decided += 1;
            self.sign += usize::from(inferred.class == truth.class);
        }
        if truth.class == Class::Pointer
            && let Some(debug_target) = &truth.target
        {
            if inferred.class == Class::Pointer {
                self.targets += 1;
                self.target += usize::from(inferred.target.as_ref().is_some_and(|target| {
                    classes_match(target.class, debug_target.class)
                        && target.bytes == debug_target.bytes
                }));
            }
            if let Some(identity) = &debug_target.identity {
                self.struct_pointers += 1;
                self.struct_identity += usize::from(
                    inferred
                        .target
                        .as_ref()
                        .and_then(|target| target.identity.as_ref())
                        == Some(identity),
                );
                if let Some((name, _)) = inferred
                    .target
                    .as_ref()
                    .and_then(|target| target.identity.as_ref())
                {
                    *self
                        .identities
                        .entry(identity.clone())
                        .or_default()
                        .entry(name.clone())
                        .or_default() += 1;
                }
            }
        }
        (d > 0).then(|| format!("{} for {}", describe(inferred), describe(truth)))
    }

    fn merge(&mut self, other: &Self) {
        self.mapped += other.mapped;
        self.undecided += other.undecided;
        self.class += other.class;
        self.width += other.width;
        self.sign_decided += other.sign_decided;
        self.sign += other.sign;
        self.targets += other.targets;
        self.target += other.target;
        self.struct_pointers += other.struct_pointers;
        self.struct_identity += other.struct_identity;
        self.distance += other.distance;
        self.interval += other.interval;
        self.conservative += other.conservative;
        for (sum, add) in self.distances.iter_mut().zip(other.distances) {
            *sum += add;
        }
        for (pair, count) in &other.confusion {
            *self.confusion.entry(*pair).or_default() += count;
        }
        for (identity, names) in &other.identities {
            let kept = self.identities.entry(identity.clone()).or_default();
            for (name, count) in names {
                *kept.entry(name.clone()).or_default() += count;
            }
        }
    }

    /// The source structs the decompiler names several ways (split), and
    /// the decompiler's structs that are several source structs (merged),
    /// each with what it is seen as; most first. A struct no translation
    /// unit defines (an opaque handle: `sqlite3_stmt`, which the library
    /// casts to its `Vdbe`) says nothing of which struct its pointers
    /// point to: they are left out ([`IdentityErrors::opaque`]).
    #[must_use]
    pub fn identity_errors(&self) -> IdentityErrors {
        let (opaque, identities): (BTreeMap<_, _>, BTreeMap<_, _>) = self
            .defined_identities()
            .into_iter()
            .partition(|((_, size), _)| *size == 0);
        let mut sources: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
        let mut split = Vec::new();
        for ((source, _), names) in &identities {
            for name in names.keys() {
                sources.entry(name).or_default().insert(source);
            }
            if names.len() > 1 {
                split.push((source.clone(), names.keys().cloned().collect()));
            }
        }
        let decompiler = sources.len();
        let mut merged: Vec<(String, Vec<String>)> = sources
            .into_iter()
            .filter(|(_, sources)| sources.len() > 1)
            .map(|(name, sources)| {
                (
                    name.to_owned(),
                    sources.into_iter().map(str::to_owned).collect(),
                )
            })
            .collect();
        let most = |a: &(String, Vec<String>), b: &(String, Vec<String>)| {
            b.1.len().cmp(&a.1.len()).then_with(|| a.0.cmp(&b.0))
        };
        split.sort_by(most);
        merged.sort_by(most);
        // Pairs of compared pointers: to one source struct, to one
        // decompiler struct, and to both.
        let pairs = |count: usize| count * count.saturating_sub(1) / 2;
        let mut by_name: BTreeMap<&str, usize> = BTreeMap::new();
        let (mut same_source, mut both) = (0, 0);
        for names in identities.values() {
            same_source += pairs(names.values().sum());
            for (name, &count) in names {
                both += pairs(count);
                *by_name.entry(name).or_default() += count;
            }
        }
        let same_name = by_name.values().map(|&count| pairs(count)).sum();
        IdentityErrors {
            sources: identities.len(),
            decompiler,
            split,
            merged,
            same_source,
            same_name,
            both,
            pointers: self.struct_pointers,
            named: identities
                .values()
                .chain(opaque.values())
                .flat_map(BTreeMap::values)
                .sum(),
            opaque: opaque.values().flat_map(BTreeMap::values).sum(),
        }
    }

    /// [`Self::identities`] with each struct only declared where a pointer
    /// points to it (size 0: a translation unit that sees no definition,
    /// `struct lua_State;`) counted as the one struct of its name that is
    /// defined, where there is one: one source struct, not two.
    fn defined_identities(&self) -> BTreeMap<(String, u64), BTreeMap<String, usize>> {
        let mut sizes: BTreeMap<&str, BTreeSet<u64>> = BTreeMap::new();
        for (name, size) in self.identities.keys() {
            if *size > 0 {
                sizes.entry(name).or_default().insert(*size);
            }
        }
        let mut out: BTreeMap<(String, u64), BTreeMap<String, usize>> = BTreeMap::new();
        for ((name, size), names) in &self.identities {
            let size = match sizes.get(name.as_str()) {
                Some(defined) if *size == 0 && defined.len() == 1 => {
                    defined.first().copied().unwrap_or(0)
                }
                Some(_) | None => *size,
            };
            let kept = out.entry((name.clone(), size)).or_default();
            for (decompiled, count) in names {
                *kept.entry(decompiled.clone()).or_default() += count;
            }
        }
        out
    }
}

/// How the decompiler's structs line up with the source's named structs
/// over the struct pointers compared ([`Tally::identity_errors`]).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IdentityErrors {
    /// Source structs a pointer to which the decompiler typed as a pointer
    /// to one of its structs.
    pub sources: usize,
    /// The decompiler's structs those pointers point to.
    pub decompiler: usize,
    /// Source structs under several of the decompiler's names, with them.
    pub split: Vec<(String, Vec<String>)>,
    /// The decompiler's structs that are several source structs, with them.
    pub merged: Vec<(String, Vec<String>)>,
    /// Pairs of the pointers compared that point to one source struct.
    pub same_source: usize,
    /// Pairs that point to one of the decompiler's structs.
    pub same_name: usize,
    /// Pairs that point to one of each: of `same_source`, those the
    /// decompiler keeps together; of `same_name`, those it is right to.
    pub both: usize,
    /// The pointers compared whose truth is a pointer to a named struct.
    pub pointers: usize,
    /// Of them, those the decompiler typed as a pointer to one of its
    /// structs (the pairs' coverage: `void *` everywhere would be right
    /// and name nothing).
    pub named: usize,
    /// Of them, those whose struct no translation unit defines (an
    /// opaque handle), left out of the structs and the pairs.
    pub opaque: usize,
}

impl IdentityErrors {
    /// The names beyond one per source struct.
    fn extra_names(&self) -> usize {
        self.split.iter().map(|(_, names)| names.len() - 1).sum()
    }
}

/// Bool and integer classes are the same class when the decompiler has not
/// decided the signedness.
fn classes_match(inferred: Class, truth: Class) -> bool {
    inferred == truth
        || (inferred == Class::Integer && matches!(truth, Class::Signed | Class::Unsigned))
}

fn describe(shape: &Shape) -> String {
    let mut text = format!("{:?}", shape.class).to_lowercase();
    if let Some(bytes) = shape.bytes {
        let _ = write!(text, "{}", bytes * 8);
    }
    if let Some(target) = &shape.target {
        let _ = write!(text, "→{}", describe(target));
    }
    if let Some((name, _)) = &shape.identity {
        let _ = write!(text, " {name}");
    }
    text
}

/// How many source variables of a kind there were, and how many were
/// mapped.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Coverage {
    /// In the truth (of the functions compared).
    pub truth: usize,
    /// Mapped to an L2 variable.
    pub mapped: usize,
    /// L2 variables of the kind no source variable mapped to.
    pub extra: usize,
}

/// Field recall and precision through pointers to structs.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FieldScore {
    /// Structs (by name and size) reached through a mapped pointer.
    pub structs: usize,
    /// Their declared scalar fields (nested structs and arrays flattened to
    /// their scalars; an array counts its first element).
    pub declared: usize,
    /// Distinct (offset, width) accesses through the pointers.
    pub accessed: usize,
    /// Accesses at a declared field's offset with its width.
    pub matched: usize,
    /// Declared fields some access matched.
    pub recalled: usize,
}

/// One function's problems.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Problem {
    /// The entry.
    pub entry: u64,
    /// The name.
    pub name: String,
    /// The sum of its distances.
    pub distance: usize,
    /// What was wrong, per variable.
    pub notes: Vec<String>,
}

/// A binary's scores.
#[derive(Clone, Debug, Default)]
pub struct Report {
    /// Functions with code in the debug information.
    pub debug_functions: usize,
    /// Of them, recovered as functions by the decompiler.
    pub recovered: usize,
    /// Of those, decompiled.
    pub decompiled: usize,
    /// Parameters.
    pub parameters: Coverage,
    /// How parameters were mapped: by stated location (a register or stack
    /// slot), by convention.
    pub by_location: usize,
    /// Mapped by the convention.
    pub by_convention: usize,
    /// Returns (a function's return, void or not).
    pub returns: Coverage,
    /// Stack variables (in one stack slot for their whole life).
    pub stack: Coverage,
    /// Register locals (in a register for some of their life, not in one
    /// stack slot for all of it).
    pub registers: Coverage,
    /// Register locals mapped to an L2 local another register local of the
    /// function mapped to before.
    pub register_shared: usize,
    /// Source locals neither in one stack slot nor ever in a register
    /// (split, computed, frame-base relative, optimised out): not mapped.
    pub unmapped_locals: usize,
    /// The parameters' scores.
    pub parameter_scores: Tally,
    /// The returns' scores (non-void on both sides).
    pub return_scores: Tally,
    /// Void agreements: neither side returns a value.
    pub void_agree: usize,
    /// The truth returns nothing, the decompiler something.
    pub void_extra: usize,
    /// The truth returns a value, the decompiler nothing.
    pub void_missed: usize,
    /// The stack variables' scores.
    pub stack_scores: Tally,
    /// The register locals' scores.
    pub register_scores: Tally,
    /// Fields through pointers to structs.
    pub fields: FieldScore,
    /// Casts in the C of the decompiled functions.
    pub casts: usize,
    /// The worst functions, by distance.
    pub worst: Vec<Problem>,
    /// Damage in the debug information.
    pub damage: usize,
    /// Why L2 has extra parameters and return values ([`Extras`]).
    pub extras: Extras,
}

/// The register names of debug information and of the lifters as one: the
/// lifters' `zmm`/`ymm` are DWARF's `xmm`.
fn register_key(name: &str) -> String {
    let lower = name.to_ascii_lowercase();
    lower
        .strip_prefix("zmm")
        .or_else(|| lower.strip_prefix("ymm"))
        .map_or(lower.clone(), |n| format!("xmm{n}"))
}

/// The registers of `parameters` at entry under the calling convention, in
/// order: integers and pointers in the integer registers, floats in the
/// vector registers, by position (Microsoft x64) or each class's next
/// free one (System V, AAPCS64); a struct by value of at most 16 bytes
/// (System V, AAPCS64: one or two integer registers, not classified
/// further) or of 1, 2, 4 or 8 bytes (Microsoft: one; larger ones by
/// reference, one) takes integer registers. `None` where it is on the stack
/// or unknown.
pub fn abi_registers(
    model: &DebugModel,
    parameters: &[Variable],
    integer: &[String],
    float: &[String],
    positional: bool,
) -> Vec<Option<String>> {
    let (mut next_int, mut next_float) = (0usize, 0usize);
    let mut out = Vec::new();
    for (position, parameter) in parameters.iter().enumerate() {
        let shape = debug_shape(model, parameter.ty);
        let is_float = shape.class == Class::Float && shape.bytes.is_some_and(|bytes| bytes <= 8);
        let by_value = matches!(shape.class, Class::Struct | Class::Array);
        let words = if by_value && !positional {
            shape
                .bytes
                .filter(|&bytes| bytes <= 16)
                .map_or(0, |bytes| bytes.div_ceil(8))
        } else {
            1
        };
        let register = if positional {
            if is_float {
                float.get(position)
            } else {
                integer.get(position)
            }
            .cloned()
        } else if is_float {
            next_float += 1;
            float.get(next_float - 1).cloned()
        } else if words == 0 {
            None
        } else {
            next_int += usize::try_from(words).unwrap_or(1);
            integer
                .get(next_int - usize::try_from(words).unwrap_or(1))
                .cloned()
        };
        out.push(register);
    }
    out
}

/// Each of `parameters`' stack slots at entry, by offset from the entry
/// stack pointer (the first stack argument is at the canonical frame
/// address, `cfa_to_entry`), for those the convention gives no register
/// (`registers`, from [`abi_registers`]): by position (Microsoft x64:
/// eight bytes each, the first four in the home space), or each after the
/// last, in eight-byte words (System V, AAPCS64; alignment beyond eight
/// bytes is not modelled). `None` in a register, or past a stack parameter
/// of unknown size.
pub fn abi_stack(
    model: &DebugModel,
    parameters: &[Variable],
    registers: &[Option<String>],
    positional: bool,
    cfa_to_entry: i64,
) -> Vec<Option<i64>> {
    let mut next = Some(cfa_to_entry);
    parameters
        .iter()
        .zip(registers)
        .enumerate()
        .map(|(position, (parameter, register))| {
            if register.is_some() {
                return None;
            }
            if positional {
                return i64::try_from(position * 8).ok().map(|at| cfa_to_entry + at);
            }
            let at = next?;
            let bytes = debug_shape(model, parameter.ty)
                .bytes
                .and_then(|bytes| i64::try_from(bytes.div_ceil(8) * 8).ok());
            next = bytes.map(|bytes| at + bytes);
            Some(at)
        })
        .collect()
}

/// What the register holds for a parameter or return value of `shape`: under
/// Microsoft x64 (`positional`) a struct or array of other than 1, 2, 4 or
/// 8 bytes is passed (and returned) as a pointer to a copy.
fn passed(shape: Shape, positional: bool) -> Shape {
    let by_reference = positional
        && matches!(shape.class, Class::Struct | Class::Array)
        && !matches!(shape.bytes, Some(1 | 2 | 4 | 8));
    if !by_reference {
        return shape;
    }
    Shape {
        class: Class::Pointer,
        bytes: Some(8),
        target: Some(Box::new(shape)),
        identity: None,
    }
}

/// What the scorer needs of the image and the run.
#[derive(Debug)]
pub struct Setup {
    /// The integer argument registers.
    pub integer: Vec<String>,
    /// The vector argument registers.
    pub float: Vec<String>,
    /// Whether arguments take registers by position.
    pub positional: bool,
    /// [`cfa_to_entry`].
    pub cfa_to_entry: i64,
    /// The lifter's register names (lower case, `zmm`/`ymm` as `xmm`), by
    /// [`RegisterId`].
    pub registers: Vec<String>,
    /// How many worst functions to keep.
    pub worst: usize,
    /// The argument and environment registers, for [`Extras`].
    pub classes: Registers,
}

impl Setup {
    /// The setup for `database`'s image.
    pub fn new(database: &Database<'_>) -> Self {
        let image = database.image();
        let mut classes = Registers::default();
        let (integer, float, positional) = database.declarations().map_or_else(
            || (Vec::new(), Vec::new(), image.format == Format::Pe),
            |declarations| {
                let convention = binbun::target::convention(image, declarations);
                let name = |id| {
                    declarations
                        .info(id)
                        .map(|info| register_key(info.name))
                        .unwrap_or_default()
                };
                classes.environment = convention
                    .thread_pointer
                    .into_iter()
                    .chain(convention.float_control.iter().map(|c| c.register))
                    .map(name)
                    .collect();
                classes.arguments = convention
                    .arguments
                    .iter()
                    .chain(&convention.float_arguments)
                    .map(|&id| name(id))
                    .collect();
                (
                    convention.arguments.iter().map(|&id| name(id)).collect(),
                    convention
                        .float_arguments
                        .iter()
                        .map(|&id| name(id))
                        .collect(),
                    convention.positional,
                )
            },
        );
        let registers = database
            .declarations()
            .map_or_else(Vec::new, |declarations| {
                declarations
                    .registers
                    .iter()
                    .map(|info| register_key(info.name))
                    .collect()
            });
        Self {
            integer,
            float,
            positional,
            cfa_to_entry: cfa_to_entry(image.machine),
            registers,
            worst: 15,
            classes,
        }
    }

    fn register(&self, id: RegisterId) -> Option<String> {
        self.registers.get(usize::from(id.0)).cloned()
    }
}

/// Scores the decompilation of every function of `database` the truth
/// states (`casts` from the C, so the C is printed).
///
/// # Errors
///
/// `database` has debug information ([`Database::with_debug`]): the
/// oracle must not feed the answer.
pub fn score(database: &Database<'_>, model: &DebugModel, setup: &Setup) -> Result<Report, String> {
    if database.debug().is_some() {
        return Err("the decompiler is scored without debug information".to_owned());
    }
    let mut report = Report {
        debug_functions: model.functions.len(),
        damage: model.damage.len(),
        ..Report::default()
    };
    let options = Options {
        style: Some("kr".to_owned()),
        ..Options::default()
    };
    let mut problems = Vec::new();
    let mut fields = FieldCollector::default();
    database.decompile_all(
        &options,
        |output| output,
        |output| {
            let Some(function) = model.functions.get(&output.entry) else {
                if let Ok(decompiled) = &output.result {
                    record(&mut report.extras, &decompiled.l2, setup, None, false);
                }
                return;
            };
            report.recovered += 1;
            let Ok(decompiled) = output.result else {
                return;
            };
            report.decompiled += 1;
            report.casts += decompiled.c.as_ref().map_or(0, |c| c.casts);
            let name = output
                .name
                .or_else(|| function.name.clone())
                .unwrap_or_else(|| format!("{:x}", output.entry));
            let mut problem = Problem {
                entry: output.entry,
                name,
                distance: 0,
                notes: Vec::new(),
            };
            let (mapped, void_extra) = score_function(
                &mut report,
                &mut problem,
                &mut fields,
                model,
                function,
                &decompiled.l2,
                setup,
            );
            record(
                &mut report.extras,
                &decompiled.l2,
                setup,
                Some(mapped),
                void_extra,
            );
            if problem.distance > 0 {
                problems.push(problem);
            }
        },
    );
    report.extras.finish();
    report.fields = fields.finish(model);
    problems.sort_by(|a, b| b.distance.cmp(&a.distance).then(a.entry.cmp(&b.entry)));
    problems.truncate(setup.worst);
    report.worst = problems;
    Ok(report)
}

/// Records `ast` in `extras`: its parameters' registers, which map to
/// source parameters (`mapped`, if it has debug information), and
/// whether its return value is extra.
fn record(
    extras: &mut Extras,
    ast: &Ast,
    setup: &Setup,
    mapped: Option<Vec<bool>>,
    void_extra: bool,
) {
    let name = |id: VarId| parameter_register(ast, id, setup);
    extras.record(ast, &name, &setup.classes, mapped, void_extra);
}

/// The register parameter `id` of `ast` comes from, by its lifter name.
fn parameter_register(ast: &Ast, id: VarId, setup: &Setup) -> Option<String> {
    ast.var(id)?.origins.iter().find_map(|origin| match origin {
        Origin::Register(register) => setup.register(*register),
        Origin::Value(_)
        | Origin::Instruction(_)
        | Origin::Held(_)
        | Origin::Slot(_)
        | Origin::Block(_)
        | Origin::Absorbed(_)
        | Origin::Proved => None,
    })
}

/// Scores one function; returns which of its L2 parameters map to source
/// parameters, and whether its return value is extra.
fn score_function(
    report: &mut Report,
    problem: &mut Problem,
    fields: &mut FieldCollector,
    model: &DebugModel,
    function: &DebugFunction,
    ast: &Ast,
    setup: &Setup,
) -> (Vec<bool>, bool) {
    let used = score_parameters(report, problem, fields, model, function, ast, setup);
    let extra = report.void_extra;
    score_return(report, problem, model, function, ast, setup);
    let void_extra = report.void_extra > extra;
    score_stack(report, problem, model, function, ast, setup);
    score_registers(report, problem, model, function, ast, setup);
    let mapped = ast.parameters.iter().map(|id| used.contains(id)).collect();
    (mapped, void_extra)
}

impl Problem {
    /// Adds the comparison to `tally`, and what was wrong to the notes.
    fn compare(&mut self, tally: &mut Tally, what: &str, inferred: &Shape, truth: &Shape) {
        let before = tally.distance;
        if let Some(wrong) = tally.add(inferred, truth) {
            self.distance += tally.distance - before;
            self.notes.push(format!("{what}: {wrong}"));
        }
    }
}

/// Parameters, by register or entry stack slot (stated at entry, else
/// under the convention); returns the L2 parameters mapped.
fn score_parameters(
    report: &mut Report,
    problem: &mut Problem,
    fields: &mut FieldCollector,
    model: &DebugModel,
    function: &DebugFunction,
    ast: &Ast,
    setup: &Setup,
) -> BTreeSet<VarId> {
    let by_register: BTreeMap<String, VarId> = ast
        .parameters
        .iter()
        .filter_map(|&id| Some((parameter_register(ast, id, setup)?, id)))
        .collect();
    let by_slot: BTreeMap<i64, VarId> = ast
        .parameters
        .iter()
        .filter_map(|&id| {
            let slot = ast
                .var(id)?
                .origins
                .iter()
                .find_map(|origin| match origin {
                    Origin::Slot(offset) => Some(*offset),
                    Origin::Value(_)
                    | Origin::Instruction(_)
                    | Origin::Register(_)
                    | Origin::Held(_)
                    | Origin::Block(_)
                    | Origin::Absorbed(_)
                    | Origin::Proved => None,
                })?;
            Some((slot, id))
        })
        .collect();
    let convention = abi_registers(
        model,
        &function.parameters,
        &setup.integer,
        &setup.float,
        setup.positional,
    );
    let stack = abi_stack(
        model,
        &function.parameters,
        &convention,
        setup.positional,
        setup.cfa_to_entry,
    );
    let mut used = BTreeSet::new();
    for (index, parameter) in function.parameters.iter().enumerate() {
        report.parameters.truth += 1;
        let (var, stated) = match parameter.place_at(function.entry) {
            Some(Place::Register(register)) => (by_register.get(&register_key(register)), true),
            Some(Place::Stack(offset)) => (by_slot.get(&(offset + setup.cfa_to_entry)), true),
            Some(Place::Relative { .. } | Place::Other) | None => {
                let var = match (convention.get(index), stack.get(index)) {
                    (Some(Some(register)), _) => by_register.get(register),
                    (_, Some(Some(slot))) => by_slot.get(slot),
                    (Some(None) | None, Some(None) | None) => None,
                };
                (var, false)
            }
        };
        let Some(&var) = var else {
            continue;
        };
        let Some(variable) = ast.var(var) else {
            continue;
        };
        used.insert(var);
        report.parameters.mapped += 1;
        if stated {
            report.by_location += 1;
        } else {
            report.by_convention += 1;
        }
        let debug_shape = passed(debug_shape(model, parameter.ty), setup.positional);
        let inferred = l2_shape(ast, variable.ty);
        let what = format!("parameter {}", parameter.name.as_deref().unwrap_or("?"));
        problem.compare(&mut report.parameter_scores, &what, &inferred, &debug_shape);
        fields.collect(model, parameter.ty, ast, var);
    }
    report.parameters.extra += ast.parameters.len() - used.len().min(ast.parameters.len());
    used
}

fn score_return(
    report: &mut Report,
    problem: &mut Problem,
    model: &DebugModel,
    function: &DebugFunction,
    ast: &Ast,
    setup: &Setup,
) {
    report.returns.truth += 1;
    let returns = passed(debug_shape(model, function.returns), setup.positional);
    match (returns.class == Class::Void, ast.returns) {
        (true, None) => {
            report.returns.mapped += 1;
            report.void_agree += 1;
        }
        (true, Some(_)) => {
            report.void_extra += 1;
            problem
                .notes
                .push("returns a value; the source returns void".to_owned());
        }
        (false, None) => {
            report.void_missed += 1;
            problem.notes.push(format!(
                "returns nothing; the source returns {}",
                describe(&returns)
            ));
        }
        (false, Some(id)) => {
            report.returns.mapped += 1;
            problem.compare(
                &mut report.return_scores,
                "return",
                &l2_shape(ast, id),
                &returns,
            );
        }
    }
}

fn score_stack(
    report: &mut Report,
    problem: &mut Problem,
    model: &DebugModel,
    function: &DebugFunction,
    ast: &Ast,
    setup: &Setup,
) {
    // Each stack variable's type by frame offset: a frame struct's fields
    // (the bytes no slot holds are none), every other variable at its own.
    let mut by_slot: BTreeMap<i64, AstTypeId> = BTreeMap::new();
    for (index, variable) in ast.variables.iter().enumerate() {
        let id = VarId(u32::try_from(index).unwrap_or(u32::MAX));
        if let VarKind::Frame(offset) = variable.kind
            && ast.frames.contains(&id)
            && let Some(AstType::Struct(aggregate)) = ast.types.get(variable.ty)
        {
            for field in &aggregate.fields {
                let named = field
                    .name
                    .as_deref()
                    .is_some_and(|name| name.starts_with("at_"));
                let at = i64::try_from(field.offset)
                    .ok()
                    .map(|at| offset.saturating_add(at));
                if let (true, Some(at)) = (named, at) {
                    by_slot.entry(at).or_insert(field.ty);
                }
            }
            continue;
        }
        let slot = match variable.kind {
            VarKind::Frame(offset) => Some(offset),
            VarKind::Local => variable.origins.iter().find_map(|origin| {
                if let Origin::Slot(offset) = origin {
                    Some(*offset)
                } else {
                    None
                }
            }),
            VarKind::Parameter | VarKind::Global(_) | VarKind::Environment(_) => None,
        };
        if let Some(slot) = slot {
            by_slot.entry(slot).or_insert(variable.ty);
        }
    }
    let mut used = BTreeSet::new();
    for local in &function.locals {
        let Some(slot) = local.stack_slot() else {
            continue;
        };
        report.stack.truth += 1;
        let at = slot + setup.cfa_to_entry;
        let Some(&ty) = by_slot.get(&at) else {
            continue;
        };
        used.insert(at);
        report.stack.mapped += 1;
        let what = format!("local {}", local.name.as_deref().unwrap_or("?"));
        problem.compare(
            &mut report.stack_scores,
            &what,
            &l2_shape(ast, ty),
            &debug_shape(model, local.ty),
        );
    }
    report.stack.extra += by_slot.len() - used.len().min(by_slot.len());
}

/// Register locals: each source local not in one stack slot, by the
/// registers it is stated in over its ranges, against the L2 locals held
/// in them ([`held_at`]).
fn score_registers(
    report: &mut Report,
    problem: &mut Problem,
    model: &DebugModel,
    function: &DebugFunction,
    ast: &Ast,
    setup: &Setup,
) {
    let held = held_locals(ast, setup);
    let mut locals = Vec::new();
    for local in function
        .locals
        .iter()
        .filter(|local| local.stack_slot().is_none())
    {
        let spans: Vec<_> = local
            .location
            .iter()
            .filter_map(|span| match span.place {
                Place::Register(register) => Some((&span.range, register_key(register))),
                Place::Stack(_) | Place::Relative { .. } | Place::Other => None,
            })
            .collect();
        if spans.is_empty() {
            report.unmapped_locals += 1;
        } else {
            locals.push((local, spans));
        }
    }
    report.registers.truth += locals.len();
    if locals.is_empty() {
        report.registers.extra += held.len();
        return;
    }
    let at = held_at(ast, &held);
    let mut by_register: BTreeMap<&str, Vec<(VarId, &BTreeSet<u64>)>> = BTreeMap::new();
    for (var, addresses) in &at {
        if let Some(&register) = held.get(var) {
            by_register
                .entry(register)
                .or_default()
                .push((*var, addresses));
        }
    }
    let mut used: BTreeMap<VarId, usize> = BTreeMap::new();
    for (local, spans) in locals {
        let mut pairs: BTreeMap<VarId, usize> = BTreeMap::new();
        for (range, register) in spans {
            for (var, addresses) in by_register.get(register.as_str()).into_iter().flatten() {
                let inside = addresses.range(range.start..range.end).count();
                if inside > 0 {
                    *pairs.entry(*var).or_default() += inside;
                }
            }
        }
        let Some(var) = most(&pairs) else {
            continue;
        };
        let Some(variable) = ast.var(var) else {
            continue;
        };
        let mappings = used.entry(var).or_default();
        if *mappings > 0 {
            report.register_shared += 1;
        }
        *mappings += 1;
        report.registers.mapped += 1;
        let what = format!("register local {}", local.name.as_deref().unwrap_or("?"));
        problem.compare(
            &mut report.register_scores,
            &what,
            &l2_shape(ast, variable.ty),
            &debug_shape(model, local.ty),
        );
    }
    report.registers.extra += held.len() - used.len().min(held.len());
}

/// `ast`'s locals held in a register ([`Origin::Held`]), by the register's
/// lifter name.
fn held_locals<'s>(ast: &Ast, setup: &'s Setup) -> BTreeMap<VarId, &'s str> {
    ast.variables
        .iter()
        .enumerate()
        .filter(|(_, variable)| variable.kind == VarKind::Local)
        .filter_map(|(index, variable)| {
            let register = variable.origins.iter().find_map(|origin| {
                if let Origin::Held(register) = origin {
                    setup.registers.get(usize::from(register.0))
                } else {
                    None
                }
            })?;
            Some((VarId(u32::try_from(index).ok()?), register.as_str()))
        })
        .collect()
}

/// The key with the greatest count, if one has it alone.
fn most(counts: &BTreeMap<VarId, usize>) -> Option<VarId> {
    let mut best: Option<(VarId, usize)> = None;
    let mut tied = false;
    for (&var, &count) in counts {
        match best {
            Some((_, top)) if count < top => {}
            Some((_, top)) if count == top => tied = true,
            Some(_) | None => {
                best = Some((var, count));
                tied = false;
            }
        }
    }
    best.filter(|_| !tied).map(|(var, _)| var)
}

/// The instruction addresses at which each of the `held` locals is read or
/// assigned: the instructions of the statements that assign it
/// ([`Stmt::places`]), and of the expressions that read it
/// ([`Expr::Var`]) or assign it ([`Expr::Assign`]), an expression without
/// instructions of its own taking those of the expression or statement
/// it is in (a variable's read is its user's instruction's).
fn held_at(ast: &Ast, held: &BTreeMap<VarId, &str>) -> BTreeMap<VarId, BTreeSet<u64>> {
    let mut at: BTreeMap<VarId, BTreeSet<u64>> = BTreeMap::new();
    let mut note = |var: VarId, origins: &[Origin]| {
        if held.contains_key(&var) {
            at.entry(var).or_default().extend(instructions(origins));
        }
    };
    let mut blocks = vec![&ast.body];
    let mut exprs = Vec::new();
    while let Some(block) = blocks.pop() {
        for &id in block {
            let Some(stmt) = ast.stmt(id) else {
                continue;
            };
            blocks.extend(stmt.blocks());
            let origins = ast.provenance.stmt(id);
            for place in stmt.places() {
                if let AstPlace::Var(var) = *place {
                    note(var, origins);
                }
            }
            exprs.extend(stmt.roots().into_iter().map(|expr| (expr, origins)));
            while let Some((id, outer)) = exprs.pop() {
                let own = ast.provenance.expr(id);
                let origins = if instructions(own).next().is_some() {
                    own
                } else {
                    outer
                };
                let Some(expr) = ast.expr(id) else {
                    continue;
                };
                if let Expr::Var(var) | Expr::Assign { var, .. } = *expr {
                    note(var, origins);
                }
                exprs.extend(expr.operands(ast).map(|operand| (operand, origins)));
            }
        }
    }
    at
}

/// The instruction addresses among `origins`.
fn instructions(origins: &[Origin]) -> impl Iterator<Item = u64> + '_ {
    origins.iter().filter_map(|origin| {
        if let Origin::Instruction(address) = origin {
            Some(*address)
        } else {
            None
        }
    })
}

/// (offset, width) pairs in bytes.
type Accesses = BTreeSet<(u64, u64)>;

/// Accesses through pointers to structs, and the fields of the structs
/// their L2 types point to, by struct.
#[derive(Debug, Default)]
struct FieldCollector {
    /// By struct identity (name, size): a type of it, and the accesses.
    structs: BTreeMap<(String, u64), (TypeId, Accesses)>,
}

impl FieldCollector {
    /// Records the accesses through `var`, and the fields (not arrays) of
    /// the struct its L2 type points to, if `ty` is a pointer to a named
    /// struct.
    fn collect(&mut self, model: &DebugModel, ty: TypeId, ast: &Ast, var: VarId) {
        let Type::Pointer { target, .. } = model.ty(model.resolve(ty)) else {
            return;
        };
        let target = model.resolve(*target);
        let Type::Composite(composite) = model.ty(target) else {
            return;
        };
        let (Some(name), Some(size)) = (&composite.name, composite.size) else {
            return;
        };
        let entry = self
            .structs
            .entry((name.clone(), size))
            .or_insert_with(|| (target, BTreeSet::new()));
        entry.1.extend(accesses(ast, var));
        entry.1.extend(layout(ast, var));
    }

    fn finish(self, model: &DebugModel) -> FieldScore {
        let mut score = FieldScore::default();
        for (id, accessed) in self.structs.values() {
            let mut declared = BTreeSet::new();
            leaves(model, *id, 0, &mut declared, 8);
            score.structs += 1;
            score.declared += declared.len();
            score.accessed += accessed.len();
            score.matched += accessed.intersection(&declared).count();
            score.recalled += declared.intersection(accessed).count();
        }
        score
    }
}

/// The scalar fields of type `id` at `base`: (offset, width in bytes).
fn leaves(model: &DebugModel, id: TypeId, base: u64, out: &mut BTreeSet<(u64, u64)>, depth: u32) {
    let Some(depth) = depth.checked_sub(1) else {
        return;
    };
    let id = model.resolve(id);
    match model.ty(id) {
        Type::Composite(composite) => {
            for field in &composite.fields {
                if field.bits.is_none() {
                    leaves(model, field.ty, base + field.offset, out, depth);
                }
            }
        }
        Type::Array { element, .. } => leaves(model, *element, base, out, depth),
        Type::Base { .. } | Type::Pointer { .. } | Type::Enum { .. } => {
            if let Some(bytes) = model.size(id) {
                out.insert((base, bytes));
            }
        }
        Type::Void | Type::Typedef { .. } | Type::Function { .. } | Type::Unknown => {}
    }
}

/// The (offset, width in bytes) of the loads and stores whose address is
/// `var` or `var` plus a constant.
fn accesses(ast: &Ast, var: VarId) -> BTreeSet<(u64, u64)> {
    let mut out = BTreeSet::new();
    let mut record = |address, ty| {
        if let Some(offset) = offset_from(ast, address, var, 4)
            && let Some(bits) = ast.types.width(ty)
        {
            out.insert((offset, bits / 8));
        }
    };
    for expr in &ast.exprs {
        if let Expr::Load { address, ty } = *expr {
            record(address, ty);
        }
    }
    for stmt in &ast.stmts {
        let places: &[AstPlace] = match stmt {
            Stmt::Assign { place, .. } => std::slice::from_ref(place),
            Stmt::VaStart { list } => std::slice::from_ref(list),
            Stmt::Call { results, .. } | Stmt::Intrinsic { results, .. } => results,
            Stmt::Expr(_)
            | Stmt::If { .. }
            | Stmt::While { .. }
            | Stmt::DoWhile { .. }
            | Stmt::For { .. }
            | Stmt::Switch { .. }
            | Stmt::Break(_)
            | Stmt::Continue(_)
            | Stmt::Label(_)
            | Stmt::Goto(_)
            | Stmt::Return(_)
            | Stmt::Trap(_)
            | Stmt::Unreachable
            | Stmt::Escape { .. }
            | Stmt::Try { .. } => &[],
        };
        for place in places {
            if let AstPlace::Memory { address, ty } = *place {
                record(address, ty);
            }
        }
    }
    out
}

/// The fields (offset, width in bytes; not arrays: unknown bytes) of the
/// struct `var`'s L2 type points to, if it points to one.
fn layout(ast: &Ast, var: VarId) -> Accesses {
    let Some(AstType::Pointer(Some(target))) = ast.var(var).and_then(|v| ast.types.get(v.ty))
    else {
        return Accesses::new();
    };
    let Some(AstType::Struct(aggregate)) = ast.types.get(*target) else {
        return Accesses::new();
    };
    aggregate
        .fields
        .iter()
        .filter(|field| !matches!(ast.types.get(field.ty), Some(AstType::Array { .. })))
        .filter_map(|field| Some((field.offset, ast.types.width(field.ty)? / 8)))
        .collect()
}

/// `address` as `var` plus a constant: the constant.
fn offset_from(ast: &Ast, address: ExprId, var: VarId, depth: u32) -> Option<u64> {
    let depth = depth.checked_sub(1)?;
    let expr = ast.exprs.get(usize::try_from(address.0).ok()?)?;
    if let Expr::Var(v) = *expr {
        return (v == var).then_some(0);
    }
    if let Expr::Cast { value, .. } = *expr {
        return offset_from(ast, value, var, depth);
    }
    let Expr::Binary(Binary::Add, left, right) = *expr else {
        return None;
    };
    let constant = |id: ExprId| {
        let Expr::Const(bits) = ast.exprs.get(usize::try_from(id.0).ok()?)? else {
            return None;
        };
        u64::try_from(bits.low_u128()).ok()
    };
    if let Some(k) = constant(right) {
        offset_from(ast, left, var, depth)?.checked_add(k)
    } else {
        offset_from(ast, right, var, depth)?.checked_add(constant(left)?)
    }
}

fn percent(part: usize, whole: usize) -> String {
    if whole == 0 {
        return "-".to_owned();
    }
    #[allow(clippy::cast_precision_loss, reason = "counts far below 2^52")]
    let ratio = part as f64 * 100.0 / whole as f64;
    format!("{ratio:.1}%")
}

fn average(sum: usize, count: usize) -> String {
    if count == 0 {
        return "-".to_owned();
    }
    #[allow(clippy::cast_precision_loss, reason = "counts far below 2^52")]
    let average = sum as f64 / count as f64;
    format!("{average:.2}")
}

impl Tally {
    fn write(&self, f: &mut fmt::Formatter<'_>, what: &str) -> fmt::Result {
        writeln!(
            f,
            "  {what}: {} compared; class {} (undecided bits(n) {}), width {}, sign {} of {} decided, pointer target {} of {}, struct identity {} of {}",
            self.mapped,
            percent(self.class, self.mapped),
            percent(self.undecided, self.mapped),
            percent(self.width, self.mapped),
            percent(self.sign, self.sign_decided),
            self.sign_decided,
            percent(self.target, self.targets),
            self.targets,
            self.struct_identity,
            self.struct_pointers,
        )?;
        writeln!(
            f,
            "    TIE: distance {} (0/1/2/3/4+: {:?}), interval {}, conservative {}",
            average(self.distance, self.mapped),
            self.distances,
            average(self.interval, self.mapped),
            percent(self.conservative, self.mapped),
        )?;
        let mut pairs: Vec<_> = self.confusion.iter().collect();
        pairs.sort_by(|a, b| b.1.cmp(a.1));
        let pairs: Vec<String> = pairs
            .iter()
            .take(8)
            .map(|((truth, ours), count)| format!("{truth:?}→{ours:?} {count}"))
            .collect();
        writeln!(f, "    debuginfo→decompiler: {}", pairs.join(", "))
    }
}

impl Report {
    /// The totals only (for held-out binaries): coverage and the TIE
    /// averages, the struct identities split and merged, no functions or
    /// structs named.
    pub fn totals(&self) -> String {
        let all = self.all_scores();
        let identities = all.identity_errors();
        format!(
            "functions {}/{} decompiled; variables compared {}: class {}, width {}, sign {}, TIE distance {}, interval {}, conservative {}; casts {}; struct identities {} as {}, split {} (+{} names), merged {}, pairs together {}, right {}, named {}",
            self.decompiled,
            self.debug_functions,
            all.mapped,
            percent(all.class, all.mapped),
            percent(all.width, all.mapped),
            percent(all.sign, all.sign_decided),
            average(all.distance, all.mapped),
            average(all.interval, all.mapped),
            percent(all.conservative, all.mapped),
            self.casts,
            identities.sources,
            identities.decompiler,
            identities.split.len(),
            identities.extra_names(),
            identities.merged.len(),
            percent(identities.both, identities.same_source),
            percent(identities.both, identities.same_name),
            percent(identities.named, identities.pointers),
        )
    }

    /// The parameters', returns', stack variables' and register locals'
    /// scores together.
    fn all_scores(&self) -> Tally {
        let mut all = self.parameter_scores.clone();
        all.merge(&self.return_scores);
        all.merge(&self.stack_scores);
        // A register local is mapped by the addresses where its register
        // holds an L2 local, too loosely to say which struct a pointer is
        // (a register reused for another local's value): its types count,
        // not its struct identities.
        let mut registers = self.register_scores.clone();
        registers.identities.clear();
        registers.struct_pointers = 0;
        registers.struct_identity = 0;
        all.merge(&registers);
        all
    }
}

impl fmt::Display for Report {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "functions: {} in the debug information, {} recovered, {} decompiled; damage {}; casts {}",
            self.debug_functions, self.recovered, self.decompiled, self.damage, self.casts
        )?;
        let coverage = |c: &Coverage| {
            format!(
                "{}/{} mapped ({}), {} extra in L2",
                c.mapped,
                c.truth,
                percent(c.mapped, c.truth),
                c.extra
            )
        };
        writeln!(
            f,
            "parameters: {} (by stated location {}, by convention {})",
            coverage(&self.parameters),
            self.by_location,
            self.by_convention
        )?;
        writeln!(
            f,
            "returns: void agreed {}, value missed {}, value extra {}",
            self.void_agree, self.void_missed, self.void_extra
        )?;
        writeln!(f, "stack variables: {}", coverage(&self.stack))?;
        writeln!(
            f,
            "register locals: {} ({} to an L2 local another maps to); other locals not mapped {}",
            coverage(&self.registers),
            self.register_shared,
            self.unmapped_locals
        )?;
        self.parameter_scores.write(f, "parameters")?;
        self.return_scores.write(f, "returns")?;
        self.stack_scores.write(f, "stack variables")?;
        self.register_scores.write(f, "register locals")?;
        let fields = &self.fields;
        writeln!(
            f,
            "struct fields through mapped pointers: {} structs, {} declared scalar fields, {} distinct accesses; precision {}, recall {}",
            fields.structs,
            fields.declared,
            fields.accessed,
            percent(fields.matched, fields.accessed),
            percent(fields.recalled, fields.declared)
        )?;
        let identities = self.all_scores().identity_errors();
        writeln!(
            f,
            "struct identities through mapped pointers: {} source structs as {} decompiler structs; split {} (+{} names), merged {}; pairs of pointers to one source struct under one name {}, under one name to one source struct {}; pointers to a named struct typed as one of the decompiler's {}/{} ({}), {} of them to a struct no unit defines (left out)",
            identities.sources,
            identities.decompiler,
            identities.split.len(),
            identities.extra_names(),
            identities.merged.len(),
            percent(identities.both, identities.same_source),
            percent(identities.both, identities.same_name),
            identities.named,
            identities.pointers,
            percent(identities.named, identities.pointers),
            identities.opaque,
        )?;
        for (source, names) in identities.split.iter().take(8) {
            writeln!(f, "  split {source}: {}", names.join(", "))?;
        }
        for (name, sources) in identities.merged.iter().take(8) {
            writeln!(f, "  merged {name}: {}", sources.join(", "))?;
        }
        write!(f, "{}", self.extras)?;
        writeln!(f, "worst functions (sum of distances):")?;
        for problem in &self.worst {
            writeln!(
                f,
                "  {} ({:#x}) {}: {}",
                problem.name,
                problem.entry,
                problem.distance,
                problem.notes.join("; ")
            )?;
        }
        Ok(())
    }
}
