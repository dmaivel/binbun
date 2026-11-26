//! Types by constraint solving on L1, whose SSA values keep apart the
//! unrelated lives of one register or stack slot that L2's variables
//! merge: decompilation's type inference.
//!
//! Lowering ([`lower`](crate::lower)) runs this after folding, before
//! variables out of SSA:
//!
//! 1. **Generation** (`generate`): from a read-only [`View`] of lowering
//!    (what each kept canonical L1 value is, the frame's slots, the calls
//!    with their signatures, the parameters, the returned values), one
//!    type variable per kept canonical value, per stack slot lowered as a
//!    variable, per global object accessed, and for the return value; and
//!    subtyping constraints between them ([`binbun_typeinfer`]), each with an
//!    [`Evidence`](binbun_typeinfer::Evidence) whose strength is a rank
//!    (Prior 0, Related 1, Weak 2, Operation 3, Access 4, Float 5,
//!    Declared 6) and whose tag is a [`Reason`]:
//!    - dataflow, in its direction: a block argument below the block
//!      parameter, a select's arms below its value, a value stored in a
//!      slot below the slot, the slot below a value loaded from it, a
//!      returned value below the return value (where the register is
//!      wider than the return value, the low parts of what it takes
//!      through block parameters and selects, and of the wider values the
//!      returned low parts are of: lowering narrows the variable later);
//!      an operation that leaves its operand unchanged (`x | 0`, `x ^ 0`,
//!      `x ± 0`, `x & ~0`: AArch64's `mov` is `orr` with the zero
//!      register) is a copy, the operand below the result, and is seen
//!      through by addresses and families;
//!    - operations: signed and unsigned compares
//!      (operands; not an unsigned demand on a value lowering knows is an
//!      address: a stack address, an access's base), divisions and
//!      remainders, shifts right, extensions, carry and overflow flags
//!      (operands demand, results supply), a comparison's truth value,
//!      floating-point operands and results (lane 1 only); the low part
//!      of an extension no wider than it is the extended value (as wide:
//!      a copy, both ways) or its extension to that width; a sign
//!      extension of low bits wider than 32 of a pointer-wide value to
//!      that width is an address's canonical-form check (a copy, both
//!      ways), narrower ones an integer's;
//!    - accesses: `load`/`store [p + k]` of `w` bits is
//!      `p ≤ ptr(…, {(k, w): value})` (base and constant offset through
//!      lowering's canonical values and constants); `p + i·s` (an index)
//!      makes `p` a pointer only (of `p + i` with neither scaled, the
//!      operand that is not an integer computation: MSVC's `[off + p]`);
//!      an integer computation plus a constant (`i * 8 + table`) indexes
//!      the constant and makes nothing a pointer; an access at a constant
//!      address naming
//!      an object of [`Context::data`](crate::lower::Context::data) at its
//!      start is the object's variable, and one at a constant address in
//!      data no object names (an import's slot) is that address's
//!      variable, as wide as its first access;
//!    - pointer arithmetic: not constraints but pointer families beside
//!      them (`family`): `q = p ± k`, `q = p + i·s`, block parameters and
//!      selects with their inputs, as one object at offsets, with the
//!      accesses through each member;
//!    - calls: a declared parameter type is an upper bound on its
//!      argument, a declared result type a lower bound on the call's
//!      result (format-string types too, at Declared; where the register
//!      is wider and no low part of it is kept, on the whole register, as
//!      an atom as wide as the type that only rounding at that width
//!      reads, for arguments and results alike: a 32-bit parameter passed
//!      on whole), and a tail call's on the return value; untyped (`bits`)
//!      parameters and results give nothing; a target called through a
//!      value is below `Code`; a function's address is above `Code`; an
//!      argument declared code (a function-pointer parameter) rounds to
//!      the declared code type unless it is called through;
//!    - schemes: a call to a function of the program with no prototype
//!      (its arguments and result are its
//!      [`Interface`](crate::lower::Interface)'s) whose [`Summary`] came
//!      before this function ([`Schemes::before`]:
//!      callees first; in a cycle of calls, the first reached gets none
//!      of the others') instantiates it fresh: each argument below its
//!      parameter's instance (by where it is passed, as wide; constants
//!      give nothing), the result's instance below the call's result (a
//!      tail call's: below the return value), the callee's own evidence
//!      strengths capped at Float (a callee's deduction is not a
//!      declaration). At most [`INSTANCES`]
//!      constraints of instances per function: past it the largest
//!      schemes are not instantiated, largest first. A declared
//!      prototype outranks a scheme: such a call takes the declaration
//!      only;
//!    - the program's signatures ([`Schemes::signature`]): a call to a
//!      function of the program with no prototype that no instance of
//!      its scheme types (its callee later in a cycle of calls, a scheme
//!      not kept, instances past [`INSTANCES`]) takes the callee's
//!      signature instead, each parameter's class an upper bound on its
//!      arguments and the return value's a lower bound on its result, at
//!      Float strength;
//!    - the function's own declared parameters and return type bound
//!      their variables both ways (declared only a pointer: a pointer
//!      lower bound at Access for a parameter, at Prior for the return
//!      value); a stack address of a slot is a pointer to it
//!      (`ptr(o, o)` with `o` the record of the slot's variable).
//!    - the top-down specialisation: the [`Class`] every caller passes at
//!      an undeclared parameter ([`Context::specialised`](crate::lower::Context::specialised),
//!      from the program's [`Arguments`]) a lower bound on its values as
//!      wide as the class, at Related strength (1: callers' agreement says
//!      less than the body's own flags and operations); a pointer's
//!      scalar target at offset 0, as a declared pointer's.
//!
//!    Constants get no bound (zero is every type) and a width alone is
//!    none.
//! 2. **Solving** within a [`Budget`](binbun_typeinfer::Budget); a refusal
//!    with instances of schemes is solved again without them (the
//!    function's own evidence alone); a refusal then leaves the function
//!    untyped (lowering's defaults: `bits`, as correct) and
//!    [`Outcome::refused`] set.
//! 3. **Rounding** (`round`): see that module's documentation.
//!    Coalescing reads the solution first: what each pointer-wide
//!    variable rounds to alone (a pointer, or an integer: an integer
//!    computation is one whatever it rounds to) keeps pointers and
//!    integers in different variables ([`lower`](crate::lower) step 6).
//!
//! A function's [`Summary`] is its solved type over its register
//! parameters (by where they are) and return value
//! ([`binbun_typeinfer::scheme`]), from solving it after folding; one whose
//! instance would state more than [`SCHEME_SIZE`] constraints is not kept.
//! Under schemes a callee's signature at its calls is rounded too
//! (`round`): the parameters and result its instances type.
//!
//! Single-function decompilation equals the whole program's: generation
//! reads only the function's own lowering and the program's [`Schemes`],
//! computed once for the whole program (callees first) and read alike by
//! both, with one signature per function ([`FunctionTypes`]) settled
//! after the sweep
//! ([`Schemes::settle_signatures`]).

mod classes;
mod declared;
mod evolution;
mod explain;
mod family;
mod generate;
mod globals;
mod round;
mod structs;

pub use classes::{Classes, CxxClass};
pub(crate) use declared::Declared;
pub(crate) use evolution::Evolutions;
pub use explain::{BOUNDS, BoundShape, Clue, Explained, REASONS};
pub(crate) use generate::{Call, Generated, Parameter, Returns, Shape, View};
pub use globals::{
    GlobalClue, GlobalSource, GlobalType, Globals, Kind, Seen, Shape as GlobalShape,
};
pub(crate) use round::{Members, Rounded, Sort};
pub use structs::{Contribution, Field, FieldType, Layout, StructId, Structs};

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::fmt;

use binbun_ast::types::{Type, TypeId, Types};
use binbun_ssa::ir::{InstId, Value};
use binbun_typeinfer::{Atom, Budget, Scheme, Solution, Strength, Var};

use crate::data::Data;
use crate::lower::Interface;
use crate::mapping::Source;
use crate::prototype::Prototypes;

/// What the solver did for one function.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Outcome {
    /// Whether it ran and its types are the function's.
    pub typed: bool,
    /// Whether solving refused (past its budget): the function keeps
    /// lowering's defaults (`bits`).
    pub refused: bool,
    /// Type variables.
    pub variables: usize,
    /// Input constraints.
    pub constraints: usize,
    /// Steps solving took.
    pub steps: usize,
    /// Conflicts the solver recorded.
    pub conflicts: usize,
    /// L2 variables whose members' types disagreed (rounding kept the
    /// strongest).
    pub disagreements: usize,
    /// Pointer families typed as arrays (a loop's step, an element), and
    /// of those, arrays of structs.
    pub arrays: (usize, usize),
}

/// The steps one function's solve may take.
pub const BUDGET: Budget = Budget { steps: 1 << 22 };

/// Strengths of evidence, weakest first.
pub(crate) mod strength {
    use binbun_typeinfer::Strength;

    /// What an earlier pass deduced; a return type declared only a
    /// pointer.
    pub(crate) const PRIOR: Strength = Strength(0);
    /// Flags and narrow zero extensions, logical shifts right.
    pub(crate) const WEAK: Strength = Strength(2);
    /// Compares, divisions, arithmetic shifts, sign extensions, truth
    /// values.
    pub(crate) const OPERATION: Strength = Strength(3);
    /// Accesses, calls through a value, addresses of variables, declared
    /// open pointers.
    pub(crate) const ACCESS: Strength = Strength(4);
    /// Floating-point operations.
    pub(crate) const FLOAT: Strength = Strength(5);
    /// Prototypes, format strings, declarations.
    pub(crate) const DECLARED: Strength = Strength(6);
    /// The most a callee's scheme's bounds have at a call: their own
    /// strengths, capped below [`DECLARED`] (a callee's deduction is not
    /// a declaration).
    pub(crate) const SCHEME: Strength = Strength(5);
    /// What every caller passes a parameter, by the top-down
    /// specialisation: Related (1), below the body's own flags
    /// and operations, since callers' agreement says less than what the
    /// body itself does.
    pub(crate) const CALLERS: Strength = Strength(1);
}

/// Why a constraint holds: a constraint's tag indexes a function's table
/// of these ([`Generated::reason`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reason {
    /// A block argument flows into its parameter.
    Phi(Value),
    /// A select's arm flows into its value.
    Select(Value),
    /// A signed or unsigned comparison of the operands of this truth value.
    Compare {
        /// The comparison's truth value.
        at: Value,
        /// Whether it is signed.
        signed: bool,
    },
    /// A comparison gives a truth value.
    Truth(Value),
    /// A division or remainder.
    Division(Value),
    /// A shift right.
    Shift(Value),
    /// An extension.
    Extend(Value),
    /// An operation that leaves its operand unchanged (`x | 0`).
    Copy(Value),
    /// A carry, borrow or overflow flag.
    Flag(Value),
    /// A floating-point operation.
    Float(Value),
    /// A load or store through a pointer.
    Access(InstId),
    /// A load or store of a stack slot lowered as a variable.
    Slot(InstId),
    /// A load or store of a global object.
    Global(InstId),
    /// The address of a stack slot.
    AddressOf(Value),
    /// A call's argument and its declared parameter (`index`).
    Argument {
        /// The call's target value.
        call: Value,
        /// The argument's position.
        index: usize,
    },
    /// A call's result and its declared type.
    Result(Value),
    /// The instance of the callee's scheme at the call through this value.
    Scheme(Value),
    /// A call through a value.
    Called(Value),
    /// A function's address.
    Function(Value),
    /// The address of text in read-only data (a string and its NUL).
    String(Value),
    /// A byte tested only for being characters (two or more of them,
    /// one a printing one): text.
    Text(Value),
    /// The function's declared parameter `index`.
    Parameter(usize),
    /// The class every caller passes as the function's parameter `index`.
    Callers(usize),
    /// The program's type of the global object at this address: every
    /// function's evidence joined ([`Globals`]).
    Program(u64),
    /// A returned value, or the declared return type.
    Returned,
    /// A type the user states for the variable.
    User,
}

impl fmt::Display for Reason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::Phi(v) => write!(f, "block argument into v{}", v.0),
            Self::Select(v) => write!(f, "select arm into v{}", v.0),
            Self::Compare { at, signed } => {
                let sign = if signed { "signed" } else { "unsigned" };
                write!(f, "{sign} comparison v{}", at.0)
            }
            Self::Truth(v) => write!(f, "truth value v{}", v.0),
            Self::Division(v) => write!(f, "division v{}", v.0),
            Self::Shift(v) => write!(f, "shift right v{}", v.0),
            Self::Extend(v) => write!(f, "extension v{}", v.0),
            Self::Copy(v) => write!(f, "copy v{}", v.0),
            Self::Flag(v) => write!(f, "flag v{}", v.0),
            Self::Float(v) => write!(f, "floating-point operation v{}", v.0),
            Self::Access(inst) => write!(f, "access i{}", inst.0),
            Self::Slot(inst) => write!(f, "stack slot access i{}", inst.0),
            Self::Global(inst) => write!(f, "global access i{}", inst.0),
            Self::AddressOf(v) => write!(f, "stack address v{}", v.0),
            Self::Argument { call, index } => {
                write!(f, "argument {index} of the call through v{}", call.0)
            }
            Self::Result(v) => write!(f, "result of the call through v{}", v.0),
            Self::Scheme(v) => write!(f, "callee's scheme at the call through v{}", v.0),
            Self::Called(v) => write!(f, "called v{}", v.0),
            Self::Function(v) => write!(f, "function address v{}", v.0),
            Self::String(v) => write!(f, "string address v{}", v.0),
            Self::Text(v) => write!(f, "characters tested for v{}", v.0),
            Self::Parameter(index) => write!(f, "declared parameter {index}"),
            Self::Callers(index) => write!(f, "every caller's argument to parameter {index}"),
            Self::Program(address) => write!(f, "the program's type of the global at {address:#x}"),
            Self::Returned => f.write_str("return value"),
            Self::User => f.write_str("your type"),
        }
    }
}

/// One function's constraints, solved.
#[derive(Debug)]
pub(crate) struct Solved {
    generated: Generated,
    solution: Solution,
    outcome: Outcome,
}

/// Generation and solving for the function `view` shows; `Err` with the
/// [`Outcome`] past the budget. A solve its callees' schemes take past
/// the budget is solved again without them.
pub(crate) fn solve(view: &View<'_>) -> Result<Solved, Outcome> {
    let generated = generate::generate(view, true);
    if generated.instances.is_empty() {
        return solve_generated(generated);
    }
    solve_generated(generated).or_else(|_| solve_generated(generate::generate(view, false)))
}

/// Solving `generated`; `Err` with the [`Outcome`] past the budget.
fn solve_generated(mut generated: Generated) -> Result<Solved, Outcome> {
    let mut outcome = Outcome {
        variables: generated.system.var_count(),
        constraints: generated.system.constraints().len(),
        ..Outcome::default()
    };
    let system = core::mem::take(&mut generated.system);
    let Ok(solution) = system.solve(BUDGET) else {
        outcome.refused = true;
        return Err(outcome);
    };
    outcome.steps = solution.steps();
    outcome.conflicts = solution.conflicts().len();
    Ok(Solved {
        generated,
        solution,
        outcome,
    })
}

/// Rounding of `solved` (of the function `view` shows, the same as it
/// was solved from) for lowering's `classes`, its types interned in
/// `types`; with the [`Outcome`].
pub(crate) fn round(
    view: &View<'_>,
    solved: &Solved,
    classes: &[Members],
    types: &mut Types,
) -> (Rounded, Outcome) {
    let rounded = round::round(view, &solved.generated, &solved.solution, classes, types);
    let outcome = Outcome {
        typed: true,
        disagreements: rounded.disagreements,
        arrays: rounded.arrays,
        ..solved.outcome
    };
    (rounded, outcome)
}

/// Per L1 value: what `solved` (of the function `view` shows) rounds it
/// to alone, where it is a pointer-wide variable (for coalescing, which
/// keeps pointers and integers apart); types interned in `types`.
pub(crate) fn sorts(view: &View<'_>, solved: &Solved, types: &mut Types) -> Vec<Option<Sort>> {
    round::sorts(view, &solved.generated, &solved.solution, types)
}

/// Why `solved` typed `values` as it did ([`Explained`]).
pub(crate) fn explained(solved: &Solved, values: &[Value]) -> Explained {
    explain::explain(&solved.generated, &solved.solution, values)
}

/// What the calls of the function `view` shows pass their callees, by
/// `solved` ([`Arguments`]); types interned in `types`.
pub(crate) fn arguments(view: &View<'_>, solved: &Solved, types: &mut Types) -> Arguments {
    round::arguments(view, &solved.generated, &solved.solution, types)
}

/// What the function `view` shows adds to the program's synthesised
/// structs by `solved` ([`Contribution`]); types interned in `types`.
pub(crate) fn contribution(view: &View<'_>, solved: &Solved, types: &mut Types) -> Contribution {
    round::contribution(view, &solved.generated, &solved.solution, types)
}

/// The signature the function `view` shows by `solved` ([`FunctionTypes`]);
/// types interned in `types`.
pub(crate) fn signature(view: &View<'_>, solved: &Solved, types: &mut Types) -> FunctionTypes {
    round::own_signature(view, &solved.generated, &solved.solution, types)
}

/// Records in `contribution` the declared structs `roots` point to
/// and the globals it reaches are or point to ([`declared::declare`]).
pub(crate) fn declare(
    solved: &Solved,
    roots: &[Declared],
    prototypes: &dyn Prototypes,
    types: &mut Types,
    contribution: &mut Contribution,
) {
    declared::declare(&solved.generated, roots, prototypes, types, contribution);
}

/// Where a root of a [`Summary`] is in its function's interface.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Root {
    /// A register parameter's value of this width (its entry value, or a
    /// low part of it kept).
    Parameter(Source, u16),
    /// The return value, this wide.
    Return(u16),
}

/// A function's scheme: its solved type over its interface (its register
/// parameters by [`Source`], its return value), for its callers to
/// instantiate at each call ([`binbun_typeinfer::scheme`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Summary {
    scheme: Scheme,
    roots: Vec<Root>,
}

impl Summary {
    /// The scheme.
    pub fn scheme(&self) -> &Scheme {
        &self.scheme
    }
}

/// What a value rounds to alone, as the top-down specialisation compares
/// callers' arguments: portable between functions (no interned type).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Class {
    /// A scalar: an integer of a width and signedness, C's `char`, a
    /// truth value, a float.
    Scalar(Atom),
    /// A pointer to data, with its target where that is a scalar.
    Pointer(Option<Atom>),
    /// A pointer to code.
    Code,
}

/// What one function's calls to a callee pass as one parameter, over all
/// of them ([`Argument::join`]), for the top-down specialisation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Argument {
    /// Only the constant zero (every type).
    Zero,
    /// Integer constants (other than zero only): any integer.
    Integer,
    /// Values of this class (and integer constants where it is an
    /// integer, zero).
    Class(Class),
    /// Something else: no class, or classes that disagree.
    Unknown,
}

impl Argument {
    /// What `self` and `other` passed at the same parameter make: agreed
    /// classes stay, zero takes the other's, a non-zero integer constant
    /// only an integer's; anything else is [`Argument::Unknown`].
    #[must_use]
    pub fn join(self, other: Self) -> Self {
        let integer = |class: Class| match class {
            Class::Scalar(atom) => matches!(
                atom,
                Atom::Signed(_) | Atom::Unsigned(_) | Atom::Char { .. } | Atom::Bool(_)
            ),
            Class::Pointer(_) | Class::Code => false,
        };
        match (self, other) {
            (Self::Zero, other) | (other, Self::Zero) => other,
            (Self::Integer, Self::Integer) => Self::Integer,
            (Self::Integer, Self::Class(class)) | (Self::Class(class), Self::Integer)
                if integer(class) =>
            {
                Self::Class(class)
            }
            (Self::Class(a), Self::Class(b)) if a == b => Self::Class(a),
            (Self::Integer | Self::Class(_) | Self::Unknown, _) => Self::Unknown,
        }
    }

    /// The class all its values agree on, if any.
    pub fn class(self) -> Option<Class> {
        match self {
            Self::Class(class) => Some(class),
            Self::Zero | Self::Integer | Self::Unknown => None,
        }
    }
}

/// What a function's calls pass its callees: per callee (by entry) with a
/// scheme-typed call (no prototype), per parameter, over all its calls.
pub type Arguments = BTreeMap<u64, Vec<(Source, Argument)>>;

/// A function's signature, portably (no interned type): its register
/// parameters not declared, by where they are, and its return value if
/// not declared, each as its own solve rounds it (`bits` where nothing
/// says more), for the program's table of signatures
/// ([`Schemes::settle_signatures`]), which types the calls no instance of
/// its scheme reaches.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FunctionTypes {
    /// The parameters' types, by where they are.
    pub parameters: Vec<(Source, FieldType)>,
    /// The return value's type.
    pub returns: Option<FieldType>,
}

impl FunctionTypes {
    /// The type of the parameter at `source`, where it says more than a
    /// width.
    pub(crate) fn parameter(&self, source: Source) -> Option<&FieldType> {
        self.parameters
            .iter()
            .find(|(at, _)| *at == source)
            .map(|(_, ty)| ty)
            .filter(|ty| informative(ty))
    }

    /// The return value's type, where it says more than a width.
    pub(crate) fn returns(&self) -> Option<&FieldType> {
        self.returns.as_ref().filter(|ty| informative(ty))
    }
}

/// Whether field type `ty` says more than a width.
fn informative(ty: &FieldType) -> bool {
    !matches!(ty, FieldType::Scalar(Type::Bits(_)))
}

/// The schemes of a program's functions, with the order they were
/// computed in (callees first): a call reads its callee's scheme only if
/// the callee came before the caller ([`Schemes::before`]), so in a cycle
/// of calls the first reached gets none from the others, and a function
/// decompiled alone reads exactly what the whole program's does.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Schemes {
    /// Each function's place in the order, by entry.
    order: BTreeMap<u64, usize>,
    /// Each function's scheme, by entry (none where it was not solved).
    summaries: BTreeMap<u64, Summary>,
    /// The program's synthesised structs ([`structs`]).
    structs: Structs,
    /// The program's global types ([`globals`]).
    globals: Globals,
    /// The program's signatures ([`Self::settle_signatures`]), by entry.
    signatures: BTreeMap<u64, FunctionTypes>,
}

impl Schemes {
    /// No schemes.
    pub const fn new() -> Self {
        Self {
            order: BTreeMap::new(),
            summaries: BTreeMap::new(),
            structs: Structs::new(),
            globals: Globals::new(),
            signatures: BTreeMap::new(),
        }
    }

    /// The function at `entry` comes next in the order (unless already
    /// placed).
    pub fn visit(&mut self, entry: u64) {
        let next = self.order.len();
        self.order.entry(entry).or_insert(next);
    }

    /// The scheme of the function at `entry`.
    pub fn insert(&mut self, entry: u64, summary: Summary) {
        self.summaries.insert(entry, summary);
    }

    /// What the function at `entry` (named `name`, if it has a symbol)
    /// contributes to the program's structs ([`Structs::add`]) and what
    /// it shows of the globals it reaches ([`Globals::add`]).
    pub fn add_structs(&mut self, entry: u64, name: Option<&str>, mut contribution: Contribution) {
        let objects = core::mem::take(&mut contribution.objects);
        self.globals.add(entry, objects);
        self.structs.add(entry, name, contribution);
    }

    /// The program's synthesised structs.
    pub const fn structs(&self) -> &Structs {
        &self.structs
    }

    /// The program's global types ([`Globals::settle`]: after the sweep
    /// and the interfaces).
    pub const fn globals(&self) -> &Globals {
        &self.globals
    }

    /// Unites the structs that are partial views of one other
    /// ([`Structs::unite_partial_views`]), then joins what the sweep's
    /// functions showed of each global into one
    /// type ([`Globals::settle`]), the image's objects from `data`,
    /// declared types from `prototypes`, the code types of the functions
    /// stored in them from `prototypes` and the program's final
    /// `interfaces`, pointers `pointer_width` bits wide: after the sweep
    /// and the interfaces, before the user's versions of structs.
    pub fn settle_globals(
        &mut self,
        data: &dyn Data,
        prototypes: &dyn Prototypes,
        interfaces: &BTreeMap<u64, Interface>,
        pointer_width: u16,
    ) {
        self.structs.unite_partial_views();
        self.globals.settle(
            &mut self.structs,
            data,
            prototypes,
            interfaces,
            pointer_width,
        );
    }

    /// Takes the user's versions of structs ([`Structs::state`]): after
    /// the sweep.
    pub fn state_structs(&mut self, from: &Types, stated: &[(StructId, TypeId)]) {
        self.structs.state(from, stated);
    }

    /// Settles the program's one signature per function, which the calls
    /// to it no instance of its scheme types take ([`crate::typing`]):
    /// each function's own (`found`, by entry, as its sweep's solve rounds
    /// it), a parameter that leaves `bits`, or an integer or a pointer to a
    /// scalar or nothing, taking the class every caller passes there where
    /// that is of its kind (`specialised`, the top-down specialisation:
    /// those calls then pass what they hold), and a pointer-wide parameter
    /// or return value whose root the program's table has at the start of
    /// a struct a pointer to that struct (pointers `pointer` bits wide):
    /// after the sweep and [`Self::settle_globals`], whose structs it reads.
    pub fn settle_signatures(
        &mut self,
        found: BTreeMap<u64, FunctionTypes>,
        specialised: &BTreeMap<u64, Vec<(Source, Class)>>,
        pointer: u16,
    ) {
        let mut settled = BTreeMap::new();
        for (entry, mut signature) in found {
            let classes = specialised.get(&entry).map_or(&[][..], Vec::as_slice);
            for (source, ty) in &mut signature.parameters {
                if let Some(&(_, class)) = classes.iter().find(|(at, _)| at == source)
                    && let Some(width) = round::field_width(ty, pointer)
                    && let Some(typed) = round::class_field(class, width, pointer)
                    && round::same_kind(ty, &typed)
                {
                    *ty = typed;
                }
                self.root_struct(entry, Root::Parameter(*source, pointer), ty, pointer);
            }
            if let Some(ty) = &mut signature.returns {
                self.root_struct(entry, Root::Return(pointer), ty, pointer);
            }
            settled.insert(entry, signature);
        }
        self.signatures = settled;
    }

    /// `ty`, of root `root` of the function at `entry`, a pointer to the
    /// struct whose start the program's table has the root point to,
    /// where it is pointer-wide `bits` or a pointer.
    fn root_struct(&self, entry: u64, root: Root, ty: &mut FieldType, pointer: u16) {
        let open = match ty {
            FieldType::Scalar(Type::Bits(width)) => *width == pointer,
            FieldType::Pointer(_) | FieldType::Opaque => true,
            FieldType::Scalar(_)
            | FieldType::Struct(_)
            | FieldType::Pointers(_)
            | FieldType::ScalarPointers(_)
            | FieldType::Code { .. } => false,
        };
        if open && let Some((id, 0)) = self.structs.root(entry, root) {
            *ty = FieldType::Struct(id);
        }
    }

    /// The program's signature of the function at `entry`
    /// ([`Self::settle_signatures`]).
    pub(crate) fn signature(&self, entry: u64) -> Option<&FunctionTypes> {
        self.signatures.get(&entry)
    }

    /// Takes `classes` as the program's C++ classes, which name the
    /// structs that are them ([`Structs::set_classes`]): before the sweep.
    pub fn set_classes(&mut self, classes: Classes) {
        self.structs.set_classes(classes);
    }

    /// Where root `root` of the function at `called` points, for a call in
    /// the function at `at`, if into a struct: only if the called function
    /// came first (as [`Self::before`]).
    pub(crate) fn struct_root(&self, at: u64, called: u64, root: Root) -> Option<(StructId, i64)> {
        if self.order.get(&called)? < self.order.get(&at)? {
            self.structs.root(called, root)
        } else {
            None
        }
    }

    /// How many functions have a scheme.
    pub fn len(&self) -> usize {
        self.summaries.len()
    }

    /// Whether no function has a scheme.
    pub fn is_empty(&self) -> bool {
        self.summaries.is_empty()
    }

    /// The scheme of the function at `called` for a call in the function
    /// at `at`: only if the called function came first.
    pub(crate) fn before(&self, at: u64, called: u64) -> Option<&Summary> {
        if self.order.get(&called)? < self.order.get(&at)? {
            self.summaries.get(&called)
        } else {
            None
        }
    }
}

/// The most constraints a kept scheme's instance states: a larger scheme
/// is not kept (its callers get nothing from it, as with none), since
/// every call instantiates it again and solving is quadratic in the
/// bounds meeting at a variable.
pub const SCHEME_SIZE: usize = 1 << 10;

/// The most constraints the instances of its callees' schemes add to one
/// function: past it, the largest are not instantiated (largest first),
/// since each bound an instance puts on an argument meets every bound
/// already there, and a large function with many calls would otherwise
/// take its solve past [`BUDGET`].
pub const INSTANCES: usize = 1536;

/// The scheme of the function `view` shows, from `solved`: its register
/// parameters' values and its return value; `None` past
/// [`SCHEME_SIZE`].
pub(crate) fn summary(view: &View<'_>, solved: &Solved) -> Option<Summary> {
    let mut roots = Vec::new();
    let mut vars: Vec<Var> = Vec::new();
    for parameter in &view.parameters {
        for &value in &parameter.values {
            if let Some(var) = solved.generated.var(value) {
                roots.push(Root::Parameter(parameter.source, view.width(value)));
                vars.push(var);
            }
        }
    }
    if let Some(var) = solved.generated.returns {
        roots.push(Root::Return(view.returns.width));
        vars.push(var);
    }
    let scheme = Scheme::new(&solved.solution, &vars);
    (scheme.constraint_count() <= SCHEME_SIZE).then_some(Summary { scheme, roots })
}

/// The strongest of `strengths` (the weakest if none).
fn strongest(strengths: impl IntoIterator<Item = Strength>) -> Strength {
    strengths.into_iter().max().unwrap_or_default()
}
