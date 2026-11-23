//! Terms, evidence, constraints, and the [`System`] that collects them.

use alloc::vec;
use alloc::vec::Vec;

use crate::atom::Atom;

/// A type variable, from [`System::var`]: ids are dense, from 0.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Var(pub(crate) u32);

impl Var {
    /// Its index (0 for the first variable of its system).
    pub const fn index(self) -> usize {
        self.0 as usize
    }
}

/// A field capability: `bits` bits at `offset` bytes from where a
/// pointer points (negative offsets reach before it, as `container_of`
/// does).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Field {
    /// Its first byte, from the record's start.
    pub offset: i64,
    /// Its width in bits.
    pub bits: u16,
}

/// A pointer `ptr(store, load)`: what may be stored through it
/// (contravariant) and what a load gives (covariant). Only
/// [`System::pointer`] makes one, adding BinSub's S-Pointer side condition
/// `store ≤ load`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Pointer {
    pub(crate) store: Var,
    pub(crate) load: Var,
}

impl Pointer {
    /// The store parameter.
    pub const fn store(self) -> Var {
        self.store
    }

    /// The load parameter.
    pub const fn load(self) -> Var {
        self.load
    }
}

/// A record of field capabilities, each to a variable. Width subtyping:
/// a record with more fields is a subtype of one with fewer; a field
/// missing on either side is unknown, not absent, so it constrains
/// nothing. Depth subtyping: fields are covariant.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Record {
    fields: Vec<(Field, Var)>,
}

impl Record {
    /// The record of these fields (in any order; a field may repeat, each
    /// occurrence constraining).
    pub fn new(fields: impl IntoIterator<Item = (Field, Var)>) -> Self {
        let mut fields: Vec<(Field, Var)> = fields.into_iter().collect();
        fields.sort_unstable();
        fields.dedup();
        Self { fields }
    }

    /// The record of one field.
    pub fn field(field: Field, var: Var) -> Self {
        Self {
            fields: vec![(field, var)],
        }
    }

    /// Its fields, ordered by field.
    pub fn fields(&self) -> &[(Field, Var)] {
        &self.fields
    }
}

/// Code (a function, or what a code pointer reaches, as `binbun_ast`'s
/// `Type::Code`): parameters by position (contravariant) and results by
/// position (covariant). A position missing on either side constrains
/// nothing (BinSub's partial functions: arity is open).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Code {
    params: Vec<(u32, Var)>,
    results: Vec<(u32, Var)>,
}

impl Code {
    /// Code of these parameters and results, each `(position, variable)`.
    pub fn new(
        params: impl IntoIterator<Item = (u32, Var)>,
        results: impl IntoIterator<Item = (u32, Var)>,
    ) -> Self {
        let mut params: Vec<(u32, Var)> = params.into_iter().collect();
        params.sort_unstable();
        params.dedup();
        let mut results: Vec<(u32, Var)> = results.into_iter().collect();
        results.sort_unstable();
        results.dedup();
        Self { params, results }
    }

    /// Its parameters, ordered by position.
    pub fn params(&self) -> &[(u32, Var)] {
        &self.params
    }

    /// Its results, ordered by position.
    pub fn results(&self) -> &[(u32, Var)] {
        &self.results
    }
}

/// A side of a constraint `lhs ≤ rhs`, and of the bounds it gives a
/// variable.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Side {
    /// A lower bound (`term ≤ var`): what flows in.
    Lower,
    /// An upper bound (`var ≤ term`): what is demanded.
    Upper,
}

/// A type. Constructors' arguments are variables (terms are shallow): a
/// nested type is a chain of variables, and a recursive type a cycle
/// through them (SimpleSub: no explicit `μ`).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Term {
    /// A type variable.
    Var(Var),
    /// Above every type.
    Top,
    /// Below every type.
    Bottom,
    /// A scalar.
    Atom(Atom),
    /// A data pointer.
    Pointer(Pointer),
    /// Field capabilities of what a pointer reaches.
    Record(Record),
    /// Code.
    Code(Code),
}

/// How strong evidence is, weakest first: the caller maps its ranks onto
/// it. Where a lower and an upper bound conflict, the stronger wins.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Strength(pub u8);

/// Why a constraint holds: the caller's reason, opaque here, and its
/// strength.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Evidence {
    /// The caller's reason (an index into its own table of reasons).
    pub tag: u32,
    /// How strong it is.
    pub strength: Strength,
}

/// An input constraint, by the order it was added.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ConstraintId(pub(crate) u32);

impl ConstraintId {
    /// Its index (0 for the first constraint of its system).
    pub const fn index(self) -> usize {
        self.0 as usize
    }
}

/// An input constraint `lhs ≤ rhs`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Constraint {
    /// The subtype.
    pub lhs: Term,
    /// The supertype.
    pub rhs: Term,
    /// Why it holds.
    pub evidence: Evidence,
}

/// A set of constraints over the variables it made: the solver's input
/// ([`System::solve`]).
#[derive(Clone, Debug, Default)]
pub struct System {
    pub(crate) vars: u32,
    pub(crate) constraints: Vec<Constraint>,
}

impl System {
    /// An empty system.
    pub fn new() -> Self {
        Self::default()
    }

    /// A fresh variable. Past `u32::MAX` variables, ids repeat and
    /// [`System::solve`] refuses.
    pub fn var(&mut self) -> Var {
        let var = Var(self.vars);
        self.vars = self.vars.saturating_add(1);
        var
    }

    /// How many variables it has made.
    pub fn var_count(&self) -> usize {
        self.vars as usize
    }

    /// Its constraints, in the order added.
    pub fn constraints(&self) -> &[Constraint] {
        &self.constraints
    }

    /// Adds `lhs ≤ rhs`.
    pub fn constrain(&mut self, lhs: Term, rhs: Term, evidence: Evidence) -> ConstraintId {
        let id = ConstraintId(u32::try_from(self.constraints.len()).unwrap_or(u32::MAX));
        self.constraints.push(Constraint { lhs, rhs, evidence });
        id
    }

    /// The pointer `ptr(store, load)`, adding its side condition
    /// `store ≤ load` (BinSub's S-Pointer) with `evidence`.
    pub fn pointer(&mut self, store: Var, load: Var, evidence: Evidence) -> Pointer {
        self.constrain(Term::Var(store), Term::Var(load), evidence);
        Pointer { store, load }
    }

    /// A load of `value` from `field` of what `address` points to:
    /// `address ≤ ptr(s, l)` and `l ≤ {field: value}` for fresh `s ≤ l`.
    /// Gives the pointer.
    pub fn load(&mut self, address: Var, field: Field, value: Var, evidence: Evidence) -> Pointer {
        let (store, load) = (self.var(), self.var());
        let pointer = self.pointer(store, load, evidence);
        self.constrain(Term::Var(address), Term::Pointer(pointer), evidence);
        self.constrain(
            Term::Var(load),
            Term::Record(Record::field(field, value)),
            evidence,
        );
        pointer
    }

    /// A store of `value` to `field` of what `address` points to:
    /// `address ≤ ptr(s, l)` and `{field: value} ≤ s` for fresh `s ≤ l`.
    /// Gives the pointer.
    pub fn store(&mut self, address: Var, field: Field, value: Var, evidence: Evidence) -> Pointer {
        let (store, load) = (self.var(), self.var());
        let pointer = self.pointer(store, load, evidence);
        self.constrain(Term::Var(address), Term::Pointer(pointer), evidence);
        self.constrain(
            Term::Record(Record::field(field, value)),
            Term::Var(store),
            evidence,
        );
        pointer
    }
}
