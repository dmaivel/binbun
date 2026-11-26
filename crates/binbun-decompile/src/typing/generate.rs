//! Constraint generation: lowering's [`View`] to a [`System`] (the
//! parent module lists the constraints).

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec;
use alloc::vec::Vec;
use core::cmp::Reverse;

use binbun_ast::types::{Enumeration, Evidence as Stated, Type, TypeId, Types};
use binbun_semantics::bits::Bits;
use binbun_semantics::ir::{Binary, Flag, FloatOp, FloatOutput, Format as Lane, Unary};
use binbun_ssa::condition::{Relation, comparison, float_relation};
use binbun_ssa::constant::Constants;
use binbun_ssa::graph::Dominators;
use binbun_ssa::ir::{BlockId, Definition, Function, InstId, Op, Type as L1Type, Value, ValueInfo};
use binbun_typeinfer::{
    Atom, Code, Evidence, Field, Format, Pointer, Record, Side, Strength, System, Term, Var,
};

use super::evolution::Evolutions;
use super::family::{Builder, Families, gcd};
use super::{Class, FieldType, GlobalShape, INSTANCES, Reason, Root, Schemes, Summary, strength};
use crate::data::{Data, Object};
use crate::mapping::Source;
use crate::prototype::AllocSize;

/// The largest named object (in bytes) that is a global object of the
/// families (lowering's bound on a variable).
const MAX_OBJECT: u64 = 1 << 32;

/// How many operations deep [`Generator::multiple`] looks into an index.
const MULTIPLE_DEPTH: u8 = 8;

/// What a kept canonical L1 value is, as lowering sees it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Shape {
    /// A constant.
    Const(Bits),
    /// The address at this offset from the entry stack pointer.
    Address(i64),
    /// A block parameter, with its arguments from the lowered
    /// predecessors.
    Phi(Vec<Value>),
    /// A pure operation's result.
    Pure(InstId),
    /// A load's result.
    Load(InstId),
    /// Anything else (an entry value, a call's or intrinsic's result, an
    /// undefined value).
    Other,
}

/// A call or tail call, as lowering resolved it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Call {
    /// The L1 value of its target.
    pub(crate) target: Value,
    /// Whether it calls through a value (no constant target).
    pub(crate) indirect: bool,
    /// Whether it is a tail call (its result is the function's).
    pub(crate) tail: bool,
    /// Its signature (a `Code` type).
    pub(crate) signature: TypeId,
    /// Whether the signature is the convention's guess: no prototype or
    /// interface states it (it says only that the target is code).
    pub(crate) guessed: bool,
    /// The types of the arguments past the signature's parameters.
    pub(crate) variadic: Vec<TypeId>,
    /// Per argument: the L1 values that are it (the register's value, or
    /// the kept values that are its low part where the register is wider,
    /// the whole register where none is kept).
    pub(crate) arguments: Vec<Vec<Value>>,
    /// The L1 values that are its result, likewise (the whole register
    /// where it is wider and no low part is kept).
    pub(crate) result: Vec<Value>,
    /// The function called, where its arguments and result are its
    /// interface's (no prototype): its scheme, if any, applies.
    pub(crate) callee: Option<u64>,
    /// Where each argument is, in the state at the call.
    pub(crate) sources: Vec<Source>,
    /// The parameters its declaration says give the size of the object
    /// it returns (`alloc_size`), if it says.
    pub(crate) alloc_size: Option<AllocSize>,
}

/// A parameter of the function.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Parameter {
    /// Where it is at entry.
    pub(crate) source: Source,
    /// The values that are its entry value (a register parameter's: the
    /// register's, or the kept values that are its low part).
    pub(crate) values: Vec<Value>,
    /// Its slot (a stack parameter's).
    pub(crate) slot: Option<usize>,
    /// Its declared type, or `bits`.
    pub(crate) ty: TypeId,
    /// How it was declared.
    pub(crate) evidence: Stated,
}

/// The function's return value.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Returns {
    /// Its width (0: none).
    pub(crate) width: u16,
    /// The values returned, where the return value is one value.
    pub(crate) values: Vec<Value>,
    /// The registers' values returned, whole (wider than the return value
    /// where it is a low part).
    pub(crate) registers: Vec<Value>,
    /// Its declared type, if stated.
    pub(crate) ty: Option<TypeId>,
    /// How it was declared.
    pub(crate) evidence: Option<Stated>,
}

/// A read-only view of one lowering after folding: what generation reads.
pub(crate) struct View<'a> {
    /// The L1 function.
    pub(crate) l1: &'a Function,
    /// Constant propagation over it.
    pub(crate) constants: &'a Constants,
    /// The L2 types (signatures, declared types).
    pub(crate) types: &'a Types,
    /// The image's data.
    pub(crate) data: &'a dyn Data,
    /// The program's function entries.
    pub(crate) functions: &'a BTreeSet<u64>,
    /// Each value's canonical value.
    pub(crate) canon: &'a [Value],
    /// Per canonical value: what it is, `None` where lowering keeps nothing.
    pub(crate) shapes: Vec<Option<Shape>>,
    /// The block parameters that step by a constant per iteration of a
    /// loop ([`Evolutions`]).
    pub(crate) evolutions: Evolutions,
    /// Per canonical value: whether lowering makes it a variable (a local
    /// or a parameter), not an expression folded into its uses.
    pub(crate) variables: Vec<bool>,
    /// Per stack slot: its width in bits where every access is the whole
    /// slot (an abstract location, whether lowering makes it a variable or
    /// bytes of the frame's memory), or where lowering makes it a variable
    /// read in parts (only its whole accesses relate to it).
    pub(crate) slots: Vec<Option<u16>>,
    /// Per stack slot: whether it is memory an address used as a value
    /// may reach (a store through a pointer may change it unseen).
    pub(crate) reached: Vec<bool>,
    /// The block parameters and arguments (parameter, argument) where the
    /// argument is zero on every edge it arrives by: tested zero on the
    /// way (`if (p->next == 0) return p->next;`), a pointer holding no
    /// object, as a literal 0 holds none.
    pub(crate) nulls: BTreeSet<(Value, Value)>,
    /// The dominator tree of `l1`'s blocks.
    pub(crate) dominators: &'a Dominators,
    /// The slot of each load and store at a known offset from the entry
    /// stack pointer.
    pub(crate) slot_of: &'a BTreeMap<InstId, usize>,
    /// The stores lowered (not atomic, not a call's push).
    pub(crate) stores: Vec<InstId>,
    /// The conditions of branches and selects (canonical; lowering reads
    /// them back as comparisons, so most are not kept themselves).
    pub(crate) conditions: Vec<Value>,
    /// The calls and tail calls.
    pub(crate) calls: Vec<Call>,
    /// The parameters, in order.
    pub(crate) parameters: Vec<Parameter>,
    /// The return value.
    pub(crate) returns: Returns,
    /// The code type of each function whose address is a kept constant,
    /// by address, with whether it is the convention's guess (rounding's:
    /// generation does not read it).
    pub(crate) codes: BTreeMap<u64, (TypeId, bool)>,
    /// The schemes of the program's functions (a call reads its callee's
    /// if it came before this function).
    pub(crate) schemes: &'a Schemes,
    /// The class every caller passes at each parameter, where they all
    /// agree (the top-down specialisation).
    pub(crate) specialised: &'a [(Source, Class)],
    /// Every function's top-down specialisation, by entry (a call's
    /// instance of its callee's scheme takes the callee's).
    pub(crate) specialisations: &'a BTreeMap<u64, Vec<(Source, Class)>>,
    /// The values whose type the user states, with it.
    pub(crate) user_values: Vec<(Value, TypeId)>,
    /// The stack slots (by index) whose type the user states, with it.
    pub(crate) user_slots: Vec<(usize, TypeId)>,
}

impl View<'_> {
    /// `v` with copies seen through.
    pub(crate) fn canonical(&self, v: Value) -> Value {
        self.canon.get(v.0 as usize).copied().unwrap_or(v)
    }

    /// What `v` (seen through copies) is, if kept.
    pub(crate) fn shape(&self, v: Value) -> Option<&Shape> {
        self.shapes.get(self.canonical(v).0 as usize)?.as_ref()
    }

    /// The width of `v` (0 for memory).
    pub(crate) fn width(&self, v: Value) -> u16 {
        match self.l1.ty(v) {
            Some(L1Type::Bits(width)) => width,
            Some(L1Type::Memory) | None => 0,
        }
    }

    /// The constant `v` is, sign-extended from its width.
    pub(crate) fn constant(&self, v: Value) -> Option<i64> {
        match self.shape(v)? {
            Shape::Const(bits) if bits.width() <= 64 => Some(bits.sext(64).low_u64().cast_signed()),
            Shape::Const(_)
            | Shape::Address(_)
            | Shape::Phi(_)
            | Shape::Pure(_)
            | Shape::Load(_)
            | Shape::Other => None,
        }
    }

    /// Whether `v` is an immediate: a constant of the code, through
    /// extensions and extractions (not one computed, as from the program
    /// counter).
    pub(crate) fn immediate(&self, v: Value) -> bool {
        let mut v = self.canonical(v);
        for _ in 0..8 {
            let op = match self.l1.value(v).map(|info| &info.definition) {
                Some(&Definition::Result { inst, .. }) => self.l1.inst(inst).map(|i| &i.op),
                Some(Definition::Parameter { .. }) | None => None,
            };
            match op {
                Some(&(Op::Extend { value, .. } | Op::Extract { value, .. })) => {
                    v = self.canonical(value);
                }
                Some(Op::Const(_)) | None => return true,
                Some(_) => return false,
            }
        }
        true
    }

    /// Whether constant `v` (of value `address`) may be the image's
    /// address of text in read-only data: computed, where the image is
    /// relocatable (an immediate is never one of its addresses), and
    /// pointing to a string (at least one character, UTF-8 without control
    /// characters but whitespace, escape, bell, backspace) and its NUL
    /// that the program cannot change.
    pub(crate) fn text_at(&self, v: Value, address: u64) -> bool {
        if self.data.relocatable() && self.immediate(v) {
            return false;
        }
        let Some(length) = self.data.string(address).filter(|&length| length > 0) else {
            return false;
        };
        if self.data.data(address, length.saturating_add(1)) != Some(true) {
            return false;
        }
        self.data.constant(address, length).is_some_and(|bytes| {
            core::str::from_utf8(&bytes).is_ok_and(|text| {
                text.chars()
                    .all(|c| !c.is_control() || "\t\n\r\u{1b}\u{7}\u{8}\u{b}\u{c}".contains(c))
            })
        })
    }

    /// The operand pure operation `op` leaves unchanged, if it is one:
    /// `x | 0`, `x ^ 0`, `x + 0`, `x - 0`, `x & ~0` (AArch64's `mov` is
    /// `orr` with the zero register).
    fn identity(&self, op: &Op) -> Option<Value> {
        let &Op::Binary(op, a, b) = op else {
            return None;
        };
        let constant = |v: Value| {
            self.constants
                .constant(v)
                .filter(|bits| bits.width() <= 64)
                .map(|bits| bits.zext(64).low_u64())
        };
        let ones = |v: Value| u64::MAX >> 64u16.saturating_sub(self.width(v));
        let (x, k) = match (constant(a), constant(b)) {
            (_, Some(k)) => (a, k),
            (Some(k), None) => (b, k),
            (None, None) => return None,
        };
        let commutes = x == a || matches!(op, Binary::Or | Binary::Xor | Binary::Add | Binary::And);
        let unchanged = match op {
            Binary::Or | Binary::Xor | Binary::Add | Binary::Sub => k == 0,
            Binary::And => k == ones(x),
            Binary::Mul
            | Binary::Shl
            | Binary::LShr
            | Binary::AShr
            | Binary::Rol
            | Binary::Ror
            | Binary::UDiv
            | Binary::URem
            | Binary::SDiv
            | Binary::SRem
            | Binary::Eq
            | Binary::Ne
            | Binary::ULt
            | Binary::ULe
            | Binary::SLt
            | Binary::SLe => false,
        };
        (commutes && unchanged && self.width(x) > 0).then(|| self.canonical(x))
    }
}

/// The constraints of one function, with the variables they are over.
#[derive(Clone, Debug, Default)]
pub(crate) struct Generated {
    /// The constraints.
    pub(crate) system: System,
    /// Per L1 value: its canonical value's variable.
    pub(crate) values: Vec<Option<Var>>,
    /// Per stack slot that is a variable: its variable.
    pub(crate) slots: Vec<Option<Var>>,
    /// The return value's variable.
    pub(crate) returns: Option<Var>,
    /// The variable of each global object accessed whole, by its first
    /// byte, with its width in bits.
    pub(crate) globals: BTreeMap<u64, (Var, u16)>,
    /// The variables of the values stored to and loaded from each stack
    /// slot and global object (by the slot's or object's variable).
    pub(crate) cells: BTreeMap<Var, Vec<Var>>,
    /// The variables called through, with the call's signature, and those
    /// a declaration demands be code (an argument to a function-pointer
    /// parameter), with the declared code type (a call's wins); each with
    /// whether it is the convention's guess ([`Call::guessed`]).
    pub(crate) called: BTreeMap<Var, (TypeId, bool)>,
    /// The variables a declaration types as a pointer to an aggregate or
    /// a vector, a target its term does not carry ([`Generator::term`]).
    pub(crate) pointees: BTreeSet<Var>,
    /// The variables of functions' addresses, with the address.
    pub(crate) functions: BTreeMap<Var, u64>,
    /// The pointer families of the kept pointer-wide values, with the
    /// accesses through them ([`super::family`]).
    pub(crate) families: Families,
    /// The variable of the address of each named object of the image's
    /// data that pointer arithmetic or an access (not of the whole object)
    /// reaches at a constant address, by its first byte: a member of the
    /// families, so a global is one object with the pointers into it.
    pub(crate) objects: BTreeMap<u64, Var>,
    /// Per canonical value: whether it is an integer computation
    /// (`Generator::integers`).
    pub(crate) integers: Vec<bool>,
    /// The variables of the instances of each callee's scheme, by the
    /// callee's entry, with the roots they are of.
    pub(crate) instances: BTreeMap<u64, Vec<(Root, Var)>>,
    /// The reasons, by tag.
    reasons: Vec<Reason>,
}

impl Generated {
    /// The variable of L1 value `v`.
    pub(crate) fn var(&self, v: Value) -> Option<Var> {
        self.values.get(v.0 as usize).copied().flatten()
    }

    /// The reason of a constraint's tag.
    pub(crate) fn reason(&self, tag: u32) -> Option<Reason> {
        self.reasons.get(tag as usize).copied()
    }
}

/// The constraints of the function `view` shows; with its callees'
/// schemes instantiated only if `schemes`.
pub(crate) fn generate(view: &View<'_>, schemes: bool) -> Generated {
    let mut generator = Generator {
        view,
        out: Generated::default(),
        bases: BTreeSet::new(),
        schemes,
        texts: BTreeSet::new(),
    };
    generator.variables();
    generator.out.integers = generator.integers();
    generator.find_bases();
    generator.find_texts();
    generator.families();
    for (index, shape) in view.shapes.iter().enumerate() {
        let Some(shape) = shape else {
            continue;
        };
        let v = Value(u32::try_from(index).unwrap_or(u32::MAX));
        generator.value(v, shape);
    }
    for &store in &view.stores {
        generator.store(store);
    }
    for &condition in &view.conditions {
        if view.shape(condition).is_none() {
            generator.condition(condition, 0);
        }
    }
    generator.calls();
    generator.parameters();
    generator.user();
    generator.specialised();
    generator.program_globals();
    generator.returns();
    generator.texts();
    let mut out = generator.out;
    let values: Vec<Option<Var>> = view
        .canon
        .iter()
        .map(|&canonical| out.values.get(canonical.0 as usize).copied().flatten())
        .collect();
    out.values = values;
    out
}

/// Generation's state.
struct Generator<'v, 'a> {
    view: &'v View<'a>,
    out: Generated,
    /// The canonical values used as an access's base.
    bases: BTreeSet<Value>,
    /// Whether callees' schemes are instantiated at calls.
    schemes: bool,
    /// The bytes used as characters, by canonical value
    /// ([`Generator::find_texts`]).
    texts: BTreeSet<Value>,
}

/// An address split into a base, a constant offset in bytes, and whether
/// an index is added.
struct Split {
    base: Value,
    offset: i64,
    indexed: bool,
    /// The scale of the indices added (their greatest common divisor, 1
    /// where one's is unknown); 0 where none is.
    scale: u64,
}

impl Generator<'_, '_> {
    /// A variable per kept canonical value and per slot that is a
    /// variable.
    fn variables(&mut self) {
        let view = self.view;
        let mut values = Vec::with_capacity(view.shapes.len());
        for shape in &view.shapes {
            values.push(shape.as_ref().map(|_| self.out.system.var()));
        }
        self.out.values = values;
        let mut slots = Vec::with_capacity(view.slots.len());
        for slot in &view.slots {
            slots.push(slot.map(|_| self.out.system.var()));
        }
        self.out.slots = slots;
        if view.returns.width > 0 {
            self.out.returns = Some(self.out.system.var());
        }
    }

    /// The variable of `v` (seen through copies), if kept.
    fn var(&self, v: Value) -> Option<Var> {
        let v = self.view.canonical(v);
        self.out.values.get(v.0 as usize).copied().flatten()
    }

    /// Evidence for `reason` at `strength`.
    fn evidence(&mut self, reason: Reason, strength: Strength) -> Evidence {
        let tag = u32::try_from(self.out.reasons.len()).unwrap_or(u32::MAX);
        self.out.reasons.push(reason);
        Evidence { tag, strength }
    }

    /// `lhs ≤ rhs` between variables.
    fn edge(&mut self, lhs: Var, rhs: Var, evidence: Evidence) {
        self.out
            .system
            .constrain(Term::Var(lhs), Term::Var(rhs), evidence);
    }

    /// `v ≤ atom` (a use's demand), unless `v` is a constant or not kept.
    fn demand(&mut self, v: Value, atom: Atom, evidence: Evidence) {
        if self.view.constant(v).is_some() || self.view.width(v) != atom.width() {
            return;
        }
        if let Some(var) = self.var(v) {
            self.out
                .system
                .constrain(Term::Var(var), Term::Atom(atom), evidence);
        }
    }

    /// An unsigned demand on `v`, unless lowering knows it is an address
    /// (pointers compare unsigned).
    fn demand_unsigned(&mut self, v: Value, evidence: Evidence) {
        if !self.address(v) {
            self.demand(v, Atom::Unsigned(self.view.width(v)), evidence);
        }
    }

    /// Whether lowering knows `v` is an address: an access's base, a stack
    /// address.
    fn address(&self, v: Value) -> bool {
        self.bases.contains(&self.view.canonical(v))
            || matches!(self.view.shape(v), Some(Shape::Address(_)))
    }

    /// Unsigned demands on two operands compared, unless either is an
    /// address (then both are pointers compared: `p < end`).
    fn demand_unsigned_pair(&mut self, a: Value, b: Value, evidence: Evidence) {
        if !self.address(a) && !self.address(b) {
            self.demand(a, Atom::Unsigned(self.view.width(a)), evidence);
            self.demand(b, Atom::Unsigned(self.view.width(b)), evidence);
        }
    }

    /// `atom ≤ v` (what an operation gives).
    fn supply(&mut self, v: Value, atom: Atom, evidence: Evidence) {
        if self.view.width(v) != atom.width() {
            return;
        }
        if let Some(var) = self.var(v) {
            self.out
                .system
                .constrain(Term::Atom(atom), Term::Var(var), evidence);
        }
    }

    /// The canonical values used as the base of an access.
    fn find_bases(&mut self) {
        let view = self.view;
        let loads = view.shapes.iter().filter_map(|shape| match shape {
            Some(Shape::Load(inst)) => Some(*inst),
            Some(
                Shape::Const(_) | Shape::Address(_) | Shape::Phi(_) | Shape::Pure(_) | Shape::Other,
            )
            | None => None,
        });
        let accesses: Vec<InstId> = loads.chain(view.stores.iter().copied()).collect();
        for inst in accesses {
            let Some(&(Op::Load { address, .. } | Op::Store { address, .. })) =
                view.l1.inst(inst).map(|i| &i.op)
            else {
                continue;
            };
            let split = self.split(address);
            self.bases.insert(split.base);
        }
    }

    /// The pointer families of the kept pointer-wide values that are not
    /// constants ([`super::family`]), with the address of each named
    /// object a constant points into (as a scalar evolution's start: a
    /// loop over a global table; or as an access's address that is not
    /// the whole object) a member at the constant's offset in it.
    fn families(&mut self) {
        let view = self.view;
        let integers = &self.out.integers;
        let member = |v: Value| -> Option<u32> {
            let v = view.canonical(v);
            let kept = matches!(
                view.shape(v),
                Some(
                    Shape::Address(_)
                        | Shape::Phi(_)
                        | Shape::Pure(_)
                        | Shape::Load(_)
                        | Shape::Other
                )
            );
            let integer = integers.get(v.0 as usize).copied().unwrap_or(false);
            (kept && !integer && view.width(v) == view.types.pointer_width()).then_some(v.0)
        };
        let mut builder = Builder::new(view.shapes.len());
        let mut nodes: BTreeMap<u64, u32> = BTreeMap::new();
        let mut object = |builder: &mut Builder, v: Value| -> Option<(u32, i64)> {
            let (object, offset) = self.object_at(v)?;
            let node = *nodes.entry(object.start).or_insert_with(|| builder.add());
            Some((node, offset))
        };
        for (index, shape) in view.shapes.iter().enumerate() {
            let v = Value(u32::try_from(index).unwrap_or(u32::MAX));
            let Some(to) = member(v) else {
                continue;
            };
            match shape {
                Some(Shape::Phi(arguments)) => {
                    // An evolution's back edges close no cycle here: its
                    // step is the family's period ([`super::evolution`]).
                    let evolution = view.evolutions.of(v);
                    for &argument in arguments {
                        if evolution.is_some_and(|e| view.canonical(argument) != e.start) {
                            continue;
                        }
                        // A pointer proved null where it arrives says
                        // nothing of the objects the parameter holds.
                        if view.nulls.contains(&(v, argument)) {
                            continue;
                        }
                        if let Some(from) = member(argument) {
                            builder.relate(from, to, 0, 0);
                        } else if evolution.is_some()
                            && let Some((node, offset)) = object(&mut builder, argument)
                        {
                            builder.relate(node, to, offset, 0);
                        }
                    }
                    if let Some(evolution) = evolution {
                        builder.period(to, evolution.step.unsigned_abs());
                    }
                }
                &Some(Shape::Pure(inst)) => {
                    for (from, delta, scale) in self.steps(v, inst).into_iter().flatten() {
                        if let Some(from) = member(from) {
                            builder.relate(from, to, delta, scale);
                        }
                    }
                }
                Some(Shape::Const(_) | Shape::Address(_) | Shape::Load(_) | Shape::Other)
                | None => {}
            }
        }
        for (at, bits) in self.constant_accesses() {
            if let Some(object) = self.named(at)
                && !(object.start == at && object.size.saturating_mul(8) == u64::from(bits))
            {
                nodes.entry(object.start).or_insert_with(|| builder.add());
            }
        }
        let slots = self.slot_nodes(&mut builder, &member);
        let mut vars: Vec<Option<Var>> = (0..view.shapes.len())
            .map(|index| {
                let v = Value(u32::try_from(index).unwrap_or(u32::MAX));
                // A canonical value only: a copy has its variable, but
                // not its place in the families.
                member(v)
                    .filter(|&node| node == v.0)
                    .and_then(|_| self.var(v))
            })
            .collect();
        let mut by_node: Vec<(u32, u64)> = nodes.into_iter().map(|(start, n)| (n, start)).collect();
        by_node.sort_unstable();
        for (_, start) in by_node {
            let var = self.out.system.var();
            self.out.objects.insert(start, var);
            vars.push(Some(var));
        }
        vars.extend(slots.into_iter().map(Some));
        self.out.families = builder.finish(&vars);
    }

    /// A node of the families per pointer-wide stack slot that is a
    /// variable ([`Output::slots`]) no address reaches ([`View::reached`]:
    /// nothing else writes it), stored to once, before every load of it
    /// (the store dominates each): every load reads the value stored, as
    /// `-O0` code keeps a local assigned once in its slot and loads it
    /// again at each use. Its members are that value and the loads, at
    /// one offset. A slot stored to more than once is left out (an
    /// optimiser shares one slot among unrelated spilled values, which
    /// would make their objects one), as is one a load may read before
    /// the store (what was there before). Each node's variable is the
    /// slot's, in order of the nodes, which follow every other.
    fn slot_nodes(
        &self,
        builder: &mut Builder,
        member: &impl Fn(Value) -> Option<u32>,
    ) -> Vec<Var> {
        let view = self.view;
        let pointer = view.types.pointer_width();
        // Per slot: the values and instructions loading it, and its stores.
        let mut reads: BTreeMap<usize, Vec<(InstId, Value)>> = BTreeMap::new();
        let mut writes: BTreeMap<usize, Vec<(InstId, Value)>> = BTreeMap::new();
        let loads = view
            .shapes
            .iter()
            .enumerate()
            .filter_map(|(index, shape)| match shape {
                Some(Shape::Load(inst)) => {
                    Some((*inst, Value(u32::try_from(index).unwrap_or(u32::MAX))))
                }
                Some(
                    Shape::Const(_)
                    | Shape::Address(_)
                    | Shape::Phi(_)
                    | Shape::Pure(_)
                    | Shape::Other,
                )
                | None => None,
            });
        let stores =
            view.stores
                .iter()
                .filter_map(|&inst| match view.l1.inst(inst).map(|i| &i.op) {
                    Some(&Op::Store { value, .. }) => Some((inst, value)),
                    Some(_) | None => None,
                });
        let slot = |inst: &InstId| {
            let &slot = view.slot_of.get(inst)?;
            let kept = view.slots.get(slot).copied().flatten() == Some(pointer)
                && !view.reached.get(slot).copied().unwrap_or(true);
            kept.then_some(slot)
        };
        for (inst, value) in loads {
            if let Some(slot) = slot(&inst)
                && view.width(value) == pointer
            {
                reads.entry(slot).or_default().push((inst, value));
            }
        }
        for (inst, value) in stores {
            if let Some(slot) = slot(&inst) {
                writes.entry(slot).or_default().push((inst, value));
            }
        }
        // Where each instruction is: its block and index there.
        let mut at: BTreeMap<InstId, (BlockId, usize)> = BTreeMap::new();
        for (index, block) in view.l1.blocks.iter().enumerate() {
            let id = BlockId(u32::try_from(index).unwrap_or(u32::MAX));
            for (position, &inst) in block.insts.iter().enumerate() {
                at.insert(inst, (id, position));
            }
        }
        let before = |a: InstId, b: InstId| match (at.get(&a), at.get(&b)) {
            (Some(&(x, i)), Some(&(y, j))) if x == y => i < j,
            (Some(&(x, _)), Some(&(y, _))) => view.dominators.dominates(x, y),
            (None, _) | (_, None) => false,
        };
        let mut vars = Vec::new();
        for (slot, written) in writes {
            let &[(store, value)] = written.as_slice() else {
                continue;
            };
            let loads = reads.remove(&slot).unwrap_or_default();
            if loads.iter().any(|&(load, _)| !before(store, load)) {
                continue;
            }
            let Some(var) = self.out.slots.get(slot).copied().flatten() else {
                continue;
            };
            let members: Vec<u32> = core::iter::once(value)
                .chain(loads.into_iter().map(|(_, value)| value))
                .filter_map(member)
                .collect();
            if members.is_empty() {
                continue;
            }
            let node = builder.add();
            for to in members {
                builder.relate(node, to, 0, 0);
            }
            vars.push(var);
        }
        vars
    }

    /// The named object of the image's data holding `address`, if one
    /// does and is no larger than [`MAX_OBJECT`].
    fn named(&self, address: u64) -> Option<Object> {
        self.view
            .data
            .object(address)
            .filter(|object| (1..=MAX_OBJECT).contains(&object.size) && object.holds(address, 1))
    }

    /// The named object pointer-wide constant `v` points into, with its
    /// offset in it; in position-independent code only a computed one
    /// (an immediate is never one of the image's addresses there).
    fn object_at(&self, v: Value) -> Option<(Object, i64)> {
        let view = self.view;
        if view.width(v) != view.types.pointer_width() {
            return None;
        }
        if view.data.relocatable() && view.immediate(v) {
            return None;
        }
        let address = view.constant(v)?.cast_unsigned();
        let object = self.named(address)?;
        Some((object, i64::try_from(address - object.start).ok()?))
    }

    /// A pointer to `char` that a value is (what a load through it gives
    /// is one, at offset 0): a string's address.
    fn string_pointer(&mut self, evidence: Evidence) -> Pointer {
        let (store, load) = (self.out.system.var(), self.out.system.var());
        let pointer = self.out.system.pointer(store, load, evidence);
        let field = Field { offset: 0, bits: 8 };
        let (stored, loaded) = (self.out.system.var(), self.out.system.var());
        let term = Term::Atom(Atom::Char { signed: true });
        let record = |var: Var| Term::Record(Record::field(field, var));
        let system = &mut self.out.system;
        for (lhs, rhs) in [
            (record(loaded), Term::Var(load)),
            (term.clone(), Term::Var(loaded)),
            (Term::Var(store), record(stored)),
            (Term::Var(stored), term),
        ] {
            system.constrain(lhs, rhs, evidence);
        }
        pointer
    }

    /// The constant addresses the function's loads and stores access with
    /// no index (not the frame's), with their widths.
    fn constant_accesses(&self) -> Vec<(u64, u16)> {
        let view = self.view;
        let loads = view.shapes.iter().filter_map(|shape| match shape {
            Some(Shape::Load(inst)) => Some(*inst),
            Some(
                Shape::Const(_) | Shape::Address(_) | Shape::Phi(_) | Shape::Pure(_) | Shape::Other,
            )
            | None => None,
        });
        loads
            .chain(view.stores.iter().copied())
            .filter(|inst| !view.slot_of.contains_key(inst))
            .filter_map(|inst| {
                let (address, bits) = match view.l1.inst(inst).map(|i| &i.op) {
                    Some(&Op::Load { address, bytes, .. }) => (address, bytes.saturating_mul(8)),
                    Some(&Op::Store { address, value, .. }) => (address, view.width(value)),
                    Some(_) | None => return None,
                };
                let split = self.split(address);
                let base = view.constant(split.base).filter(|_| !split.indexed)?;
                Some((base.wrapping_add(split.offset).cast_unsigned(), bits))
            })
            .collect()
    }

    /// Per canonical value: whether it is an integer computation, never an
    /// address: an operation no address arithmetic is (a product, a
    /// quotient, a shift, an extension other than a canonical-form check,
    /// a comparison, a unary operation, an extraction), a difference of two
    /// values, or a sum or select of integer computations (a constant
    /// added to one is one too).
    fn integers(&self) -> Vec<bool> {
        let view = self.view;
        let mut integer = alloc::vec![false; view.shapes.len()];
        let is = |integer: &[bool], v: Value| {
            integer
                .get(view.canonical(v).0 as usize)
                .copied()
                .unwrap_or(false)
        };
        let mut changed = true;
        while changed {
            changed = false;
            for (index, shape) in view.shapes.iter().enumerate() {
                let &Some(Shape::Pure(inst)) = shape else {
                    continue;
                };
                if is(&integer, Value(u32::try_from(index).unwrap_or(u32::MAX))) {
                    continue;
                }
                let Some(instruction) = view.l1.inst(inst) else {
                    continue;
                };
                let now = if let Some(x) = view.identity(&instruction.op) {
                    is(&integer, x)
                } else {
                    match instruction.op {
                        Op::Binary(Binary::Add, a, b) => match (view.constant(a), view.constant(b))
                        {
                            (_, Some(_)) => is(&integer, a),
                            (Some(_), None) => is(&integer, b),
                            (None, None) => is(&integer, a) && is(&integer, b),
                        },
                        Op::Binary(Binary::Sub, a, b) => {
                            view.constant(b).is_none() || is(&integer, a)
                        }
                        // `p & -16` aligns an address.
                        Op::Binary(Binary::And | Binary::Or | Binary::Xor, ..)
                        | Op::Const(_)
                        | Op::Undefined(..)
                        | Op::Concat { .. }
                        | Op::Lanes { .. }
                        | Op::Float { .. }
                        | Op::Load { .. }
                        | Op::Store { .. }
                        | Op::Intrinsic { .. }
                        | Op::Call { .. }
                        | Op::SystemCall { .. }
                        | Op::Landing { .. } => false,
                        Op::Binary(..) | Op::Unary(..) | Op::Extract { .. } | Op::Flag(..) => true,
                        Op::Extend { signed, value, .. } => {
                            let width = view.width(Value(u32::try_from(index).unwrap_or(u32::MAX)));
                            self.canonical_form(signed, value, width).is_none()
                        }
                        Op::Select {
                            then, otherwise, ..
                        } => is(&integer, then) && is(&integer, otherwise),
                    }
                };
                if now && let Some(slot) = integer.get_mut(index) {
                    *slot = true;
                    changed = true;
                }
            }
        }
        integer
    }

    /// What pure operation `inst` (whose result is `v`) is of a pointer:
    /// the pointers it adds to, each with the constant added and the
    /// index's scale (0: none). `p ± k`, `p + i·s`, a select's arms, an
    /// address checked canonical.
    fn steps(&self, v: Value, inst: InstId) -> [Option<(Value, i64, u64)>; 2] {
        let view = self.view;
        let Some(instruction) = view.l1.inst(inst) else {
            return [None, None];
        };
        if let Some(x) = view.identity(&instruction.op) {
            return [Some((x, 0, 0)), None];
        }
        match instruction.op {
            Op::Binary(Binary::Add, a, b) => {
                let step = match (view.constant(a), view.constant(b)) {
                    (_, Some(added)) => Some((a, added, 0)),
                    (Some(added), None) => Some((b, added, 0)),
                    (None, None) => self.indexed_sum(a, b).map(|(base, scale)| (base, 0, scale)),
                };
                [step, None]
            }
            Op::Binary(Binary::Sub, a, b) => [
                view.constant(b).map(|added| (a, added.wrapping_neg(), 0)),
                None,
            ],
            Op::Select {
                then, otherwise, ..
            } => [Some((then, 0, 0)), Some((otherwise, 0, 0))],
            Op::Extend { signed, value, .. } => [
                self.canonical_form(signed, value, view.width(v))
                    .map(|whole| (whole, 0, 0)),
                None,
            ],
            Op::Const(_)
            | Op::Undefined(..)
            | Op::Unary(..)
            | Op::Binary(..)
            | Op::Extract { .. }
            | Op::Concat { .. }
            | Op::Lanes { .. }
            | Op::Flag(..)
            | Op::Float { .. }
            | Op::Load { .. }
            | Op::Store { .. }
            | Op::Intrinsic { .. }
            | Op::Call { .. }
            | Op::SystemCall { .. }
            | Op::Landing { .. } => [None, None],
        }
    }

    /// The constraints a kept canonical value's definition gives.
    fn value(&mut self, v: Value, shape: &Shape) {
        match shape {
            Shape::Phi(arguments) => {
                if let Some(var) = self.var(v) {
                    for &argument in arguments {
                        // Null where it arrives: no evidence of the
                        // parameter's type, nor it of the argument's (a
                        // pointer tested zero is any pointer there).
                        if self.view.nulls.contains(&(v, argument)) {
                            continue;
                        }
                        if let Some(from) = self.var(argument) {
                            let evidence = self.evidence(Reason::Phi(v), strength::PRIOR);
                            self.edge(from, var, evidence);
                        }
                    }
                }
            }
            &Shape::Pure(inst) => self.operation(v, inst),
            &Shape::Load(inst) => {
                if let Some(&Op::Load {
                    address,
                    bytes,
                    atomic: None,
                    ..
                }) = self.view.l1.inst(inst).map(|i| &i.op)
                {
                    let value = self.var(v);
                    self.access(inst, address, bytes.saturating_mul(8), value, Side::Upper);
                }
            }
            Shape::Address(_) => {
                if let Some(var) = self.var(v) {
                    let evidence = self.evidence(Reason::AddressOf(v), strength::ACCESS);
                    let target = self.out.system.var();
                    let pointer = self.out.system.pointer(target, target, evidence);
                    self.out
                        .system
                        .constrain(Term::Pointer(pointer), Term::Var(var), evidence);
                }
            }
            &Shape::Const(bits) => {
                let width = self.view.types.pointer_width();
                if bits.width() == width && self.view.functions.contains(&bits.low_u64()) {
                    let evidence = self.evidence(Reason::Function(v), strength::ACCESS);
                    if let Some(var) = self.var(v) {
                        self.out.system.constrain(
                            Term::Code(Code::new([], [])),
                            Term::Var(var),
                            evidence,
                        );
                        self.out.functions.insert(var, bits.low_u64());
                    }
                } else if bits.width() == width && self.view.text_at(v, bits.low_u64()) {
                    let evidence = self.evidence(Reason::String(v), strength::WEAK);
                    if let Some(var) = self.var(v) {
                        let pointer = self.string_pointer(evidence);
                        self.out
                            .system
                            .constrain(Term::Pointer(pointer), Term::Var(var), evidence);
                    }
                }
            }
            Shape::Other => {}
        }
        if self.view.width(v) == 1 {
            self.condition(v, 0);
        }
    }

    /// A comparison's operands and truth value.
    fn compare(&mut self, v: Value) {
        let view = self.view;
        let Some(compare) = comparison(view.l1, view.constants, v) else {
            return;
        };
        let signed = match compare.relation {
            Relation::SLt | Relation::SLe | Relation::SGt | Relation::SGe => Some(true),
            Relation::ULt | Relation::ULe | Relation::UGt | Relation::UGe => Some(false),
            Relation::Eq | Relation::Ne => None,
        };
        if let Some(signed) = signed {
            let evidence = self.evidence(Reason::Compare { at: v, signed }, strength::OPERATION);
            let (left, right) = (compare.left, compare.right);
            if signed {
                for operand in [left, right] {
                    self.demand(operand, Atom::Signed(view.width(operand)), evidence);
                }
            } else {
                self.demand_unsigned_pair(left, right, evidence);
            }
        }
        let evidence = self.evidence(Reason::Truth(v), strength::OPERATION);
        self.supply(v, Atom::Bool(1), evidence);
    }

    /// The byte `value` is: itself, the byte it extends, or the byte it
    /// is the low bits of an extension of (`movzx edx, byte ptr [rdi];
    /// cmp dl, 47`, or `cmp edx, 47`), by canonical value: the innermost
    /// value of 8 bits on the way (the low byte of a register a loop
    /// carries is as far as it goes).
    fn byte_of(&self, value: Value) -> Option<Value> {
        let view = self.view;
        let mut byte = view.canonical(value);
        let mut found = None;
        for _ in 0..4 {
            if view.width(byte) == 8 {
                found = Some(byte);
            }
            let Some(&ValueInfo {
                definition: Definition::Result { inst, .. },
                ..
            }) = view.l1.value(byte)
            else {
                break;
            };
            let Some(
                &(Op::Extend { value: from, .. }
                | Op::Extract {
                    value: from,
                    offset: 0,
                    ..
                }),
            ) = view.l1.inst(inst).map(|i| &i.op)
            else {
                break;
            };
            // The byte itself, not what it is the low bits of.
            if view.width(byte) == 8 && view.width(from) < 8 {
                break;
            }
            byte = view.canonical(from);
        }
        if view.width(byte) == 8 {
            found = Some(byte);
        }
        found
    }

    /// Finds the bytes used as characters ([`Generator::texts`]): those
    /// tested for being equal to constants that are all characters
    /// (printing ASCII, tab, newline, carriage return, NUL), two or more
    /// of them and one a printing one other than a space (`p[0] == '/'
    /// && p[1] == 0` is text; a flag byte tested for 64 alone is not
    /// taken for `'@'`), and the bytes those are merged from (a loop's
    /// character is each load it holds). Every comparison of the
    /// function is read, kept as a variable or not.
    fn find_texts(&mut self) {
        let view = self.view;
        // Per byte: the characters it is tested for, and whether it is
        // tested for anything else.
        let mut tested: BTreeMap<Value, (BTreeSet<u8>, bool)> = BTreeMap::new();
        for inst in &view.l1.insts {
            let Some(&condition) = inst.results.first() else {
                continue;
            };
            if view.width(condition) != 1 {
                continue;
            }
            let Some(compare) = comparison(view.l1, view.constants, condition) else {
                continue;
            };
            if !matches!(compare.relation, Relation::Eq | Relation::Ne) {
                continue;
            }
            for (value, other) in [(compare.left, compare.right), (compare.right, compare.left)] {
                let Some(bits) = view.constants.constant(other) else {
                    continue;
                };
                let Some(byte) = self.byte_of(value) else {
                    continue;
                };
                let (characters, others) = tested.entry(byte).or_default();
                match u8::try_from(bits.low_u64()) {
                    Ok(code)
                        if bits.width() <= 64
                            && matches!(code, 0 | b'\t' | b'\n' | b'\r' | 0x20..=0x7e) =>
                    {
                        characters.insert(code);
                    }
                    Ok(_) | Err(_) => *others = true,
                }
            }
        }
        self.texts = tested
            .into_iter()
            .filter(|(_, (characters, other))| {
                !other && characters.len() >= 2 && characters.iter().any(u8::is_ascii_graphic)
            })
            .map(|(byte, _)| byte)
            .collect();
        let mut work: Vec<Value> = self.texts.iter().copied().collect();
        while let Some(text) = work.pop() {
            let Some(&ValueInfo {
                definition: Definition::Parameter { block, index },
                ..
            }) = view.l1.value(text)
            else {
                continue;
            };
            if block.0 == 0 {
                continue;
            }
            let arguments = view
                .l1
                .blocks
                .iter()
                .flat_map(|from| from.terminator.targets())
                .filter(|target| target.block == block)
                .filter_map(|target| target.arguments.get(index as usize));
            for &argument in arguments {
                if let Some(byte) = self.byte_of(argument)
                    && self.texts.insert(byte)
                {
                    work.push(byte);
                }
            }
        }
    }

    /// A byte used as a character ([`Self::find_texts`]) is one: a
    /// comparison's evidence. The zero extension a compiler loads any
    /// byte with says nothing of these ([`Self::extend`]). What one is
    /// loaded through then points to `char`, and the printer writes the
    /// constants as characters.
    fn texts(&mut self) {
        for byte in self.texts.clone() {
            let evidence = self.evidence(Reason::Text(byte), strength::OPERATION);
            self.demand(byte, Atom::Char { signed: true }, evidence);
        }
    }

    /// A condition lowering does not keep: a comparison, else the truth
    /// values and flags it combines (`ZF | SF != OF`, which L1 does not read
    /// back as one comparison), to a small depth; a sign bit tested is a
    /// signed comparison with 0 (L2's rules read `jle` after `test` as
    /// `x <= 0` signed).
    fn condition(&mut self, v: Value, depth: u8) {
        let view = self.view;
        if let Some(compare) = comparison(view.l1, view.constants, v) {
            self.compare(v);
            // `SF != 0` (`test` clears the overflow flag): the sign bit.
            if matches!(compare.relation, Relation::Eq | Relation::Ne) && depth < 4 {
                for operand in [compare.left, compare.right] {
                    if view.width(operand) == 1 {
                        self.condition(operand, depth + 1);
                    }
                }
            }
            return;
        }
        // A relation between two floats (lowering reads the comparison's
        // flags back as one, so the comparison itself is often not
        // kept): its operands are floats.
        if let Some(relation) = float_relation(view.l1, view.constants, v) {
            let evidence = self.evidence(Reason::Float(v), strength::FLOAT);
            let float = Atom::Float(format_of(relation.format));
            for operand in [relation.left, relation.right] {
                self.demand(operand, float, evidence);
            }
            return;
        }
        if depth >= 4 {
            return;
        }
        let Some(&ValueInfo {
            definition: Definition::Result { inst, .. },
            ..
        }) = view.l1.value(view.canonical(v))
        else {
            return;
        };
        let Some(i) = view.l1.inst(inst) else {
            return;
        };
        match i.op {
            Op::Binary(Binary::And | Binary::Or | Binary::Xor, a, b) => {
                self.condition(a, depth + 1);
                self.condition(b, depth + 1);
            }
            Op::Unary(Unary::Not, a) => self.condition(a, depth + 1),
            Op::Flag(flag, a, b, _) => self.flag(v, flag, a, b),
            Op::Extract {
                value,
                offset,
                width: 1,
            } if offset.saturating_add(1) == view.width(value) => {
                let reason = Reason::Compare {
                    at: v,
                    signed: true,
                };
                let evidence = self.evidence(reason, strength::OPERATION);
                self.demand(value, Atom::Signed(view.width(value)), evidence);
            }
            Op::Const(_)
            | Op::Undefined(..)
            | Op::Unary(..)
            | Op::Binary(..)
            | Op::Extract { .. }
            | Op::Concat { .. }
            | Op::Extend { .. }
            | Op::Select { .. }
            | Op::Lanes { .. }
            | Op::Float { .. }
            | Op::Load { .. }
            | Op::Store { .. }
            | Op::Intrinsic { .. }
            | Op::Call { .. }
            | Op::SystemCall { .. }
            | Op::Landing { .. } => {}
        }
    }

    /// The constraints of pure operation `inst`, whose result is `v`.
    fn operation(&mut self, v: Value, inst: InstId) {
        let Some(i) = self.view.l1.inst(inst) else {
            return;
        };
        if let Some(x) = self.view.identity(&i.op) {
            // `x | 0` (AArch64's `mov` is `orr` with the zero register):
            // `x` flows into it, as into a block parameter.
            if let (Some(x), Some(y)) = (self.var(x), self.var(v)) {
                let evidence = self.evidence(Reason::Copy(v), strength::PRIOR);
                self.edge(x, y, evidence);
            }
            return;
        }
        match i.op {
            Op::Select {
                then, otherwise, ..
            } => {
                if let Some(var) = self.var(v) {
                    for arm in [then, otherwise] {
                        if let Some(from) = self.var(arm) {
                            let evidence = self.evidence(Reason::Select(v), strength::PRIOR);
                            self.edge(from, var, evidence);
                        }
                    }
                }
            }
            Op::Binary(op, a, b) => self.binary(v, op, a, b),
            Op::Extend { signed, value, .. } => self.extend(v, signed, value),
            Op::Extract {
                value, offset: 0, ..
            } => self.low_part(v, value),
            Op::Flag(flag, a, b, _) => self.flag(v, flag, a, b),
            Op::Float {
                op,
                format,
                lanes: 1,
                output: FloatOutput::Value,
                operands,
                ..
            } => self.float(v, op, format, operands),
            Op::Const(_)
            | Op::Undefined(..)
            | Op::Unary(..)
            | Op::Extract { .. }
            | Op::Concat { .. }
            | Op::Lanes { .. }
            | Op::Float { .. }
            | Op::Load { .. }
            | Op::Store { .. }
            | Op::Intrinsic { .. }
            | Op::Call { .. }
            | Op::SystemCall { .. }
            | Op::Landing { .. } => {}
        }
    }

    /// Divisions, remainders and shifts right.
    fn binary(&mut self, v: Value, op: Binary, a: Value, b: Value) {
        let width = self.view.width(v);
        match op {
            Binary::SDiv | Binary::SRem => {
                let evidence = self.evidence(Reason::Division(v), strength::OPERATION);
                self.demand(a, Atom::Signed(width), evidence);
                self.demand(b, Atom::Signed(width), evidence);
                self.supply(v, Atom::Signed(width), evidence);
            }
            Binary::UDiv | Binary::URem => {
                let evidence = self.evidence(Reason::Division(v), strength::OPERATION);
                self.demand(a, Atom::Unsigned(width), evidence);
                self.demand(b, Atom::Unsigned(width), evidence);
                self.supply(v, Atom::Unsigned(width), evidence);
            }
            Binary::AShr => {
                let evidence = self.evidence(Reason::Shift(v), strength::OPERATION);
                self.demand(a, Atom::Signed(width), evidence);
                self.supply(v, Atom::Signed(width), evidence);
            }
            Binary::LShr => {
                let evidence = self.evidence(Reason::Shift(v), strength::WEAK);
                self.demand_unsigned(a, evidence);
            }
            Binary::Add
            | Binary::Sub
            | Binary::Mul
            | Binary::And
            | Binary::Or
            | Binary::Xor
            | Binary::Shl
            | Binary::Rol
            | Binary::Ror
            | Binary::Eq
            | Binary::Ne
            | Binary::ULt
            | Binary::ULe
            | Binary::SLt
            | Binary::SLe => {}
        }
    }

    /// A sign extension (signed, operand and result), a zero extension
    /// from fewer than 32 bits (unsigned, weak; from 1 bit, a truth value:
    /// none).
    fn extend(&mut self, v: Value, signed: bool, value: Value) {
        let (from, to) = (self.view.width(value), self.view.width(v));
        if let Some(whole) = self.canonical_form(signed, value, to) {
            // `sext(extract(x, 0, 48))` is `x` where it is a canonical
            // address (the trap guard before it says so; L2 drops it): a
            // copy, both ways, and no signed operation.
            if let (Some(x), Some(y)) = (self.var(whole), self.var(v)) {
                let evidence = self.evidence(Reason::Extend(v), strength::PRIOR);
                self.edge(x, y, evidence);
                self.edge(y, x, evidence);
            }
            return;
        }
        if signed {
            let evidence = self.evidence(Reason::Extend(v), strength::OPERATION);
            self.demand(value, Atom::Signed(from), evidence);
            self.supply(v, Atom::Signed(to), evidence);
        } else if from > 1 && from < 32 {
            let evidence = self.evidence(Reason::Extend(v), strength::WEAK);
            // A character is loaded with `movzx` whatever its sign.
            if !self.texts.contains(&self.view.canonical(value)) {
                self.demand_unsigned(value, evidence);
            }
            self.supply(v, Atom::Unsigned(to), evidence);
        }
    }

    /// The low part `v` of `value` where `value` extends `inner` no wider
    /// than `v`: `inner` itself if as wide (a copy, both ways), else
    /// `inner` extended to `v`'s width (`(int32_t)(int64_t)x` is
    /// `(int32_t)x`).
    fn low_part(&mut self, v: Value, value: Value) {
        let view = self.view;
        let Some(&ValueInfo {
            definition: Definition::Result { inst, .. },
            ..
        }) = view.l1.value(view.canonical(value))
        else {
            return;
        };
        let Some(&Op::Extend {
            signed,
            value: inner,
            ..
        }) = view.l1.inst(inst).map(|i| &i.op)
        else {
            return;
        };
        let (from, to) = (view.width(inner), view.width(v));
        if from == to {
            if let (Some(x), Some(y)) = (self.var(inner), self.var(v)) {
                let evidence = self.evidence(Reason::Extend(v), strength::PRIOR);
                self.edge(x, y, evidence);
                self.edge(y, x, evidence);
            }
        } else if from < to {
            self.extend(v, signed, inner);
        }
    }

    /// Carry and borrow flags (unsigned operands), overflow flags (signed).
    fn flag(&mut self, v: Value, flag: Flag, a: Value, b: Value) {
        match flag {
            Flag::AddCarry | Flag::SubBorrow => {
                let evidence = self.evidence(Reason::Flag(v), strength::WEAK);
                self.demand_unsigned_pair(a, b, evidence);
            }
            Flag::AddOverflow | Flag::SubOverflow => {
                let evidence = self.evidence(Reason::Flag(v), strength::WEAK);
                self.demand(a, Atom::Signed(self.view.width(a)), evidence);
                self.demand(b, Atom::Signed(self.view.width(b)), evidence);
            }
            Flag::NibbleCarry => {}
        }
    }

    /// The value `x` that a sign extension of `value` to `width` bits is in
    /// canonical form, if `value` is `x`'s low bits and `x` is `width` bits
    /// (`sext(extract(x, 0, 48))`: an address checked canonical; low bits
    /// no wider than 32 are an integer's, `(int64_t)(int32_t)x`).
    fn canonical_form(&self, signed: bool, value: Value, width: u16) -> Option<Value> {
        let view = self.view;
        if !signed {
            return None;
        }
        let Some(&Shape::Pure(inst)) = view.shape(value) else {
            return None;
        };
        let Some(&Op::Extract {
            value: whole,
            offset: 0,
            width: low,
        }) = view.l1.inst(inst).map(|i| &i.op)
        else {
            return None;
        };
        (low > 32 && view.width(whole) == width && width == view.types.pointer_width())
            .then(|| view.canonical(whole))
    }

    /// A one-lane floating-point operation's operands and result.
    fn float(&mut self, v: Value, op: FloatOp, format: Lane, operands: [Value; 3]) {
        let evidence = self.evidence(Reason::Float(v), strength::FLOAT);
        let float = Atom::Float(format_of(format));
        for &operand in operands.iter().take(op.arity()) {
            let width = self.view.width(operand);
            let atom = match op {
                FloatOp::FromInt { signed: true } => Atom::Signed(width),
                FloatOp::FromInt { signed: false } => Atom::Unsigned(width),
                FloatOp::Add
                | FloatOp::Sub
                | FloatOp::Mul
                | FloatOp::Div
                | FloatOp::Sqrt
                | FloatOp::MulAdd
                | FloatOp::RoundToIntegral
                | FloatOp::Compare { .. }
                | FloatOp::Convert(_)
                | FloatOp::ToInt { .. } => float,
            };
            self.demand(operand, atom, evidence);
        }
        let result = match op {
            FloatOp::Compare { .. } => None,
            FloatOp::ToInt {
                signed: true,
                width,
            } => Some(Atom::Signed(width)),
            FloatOp::ToInt {
                signed: false,
                width,
            } => Some(Atom::Unsigned(width)),
            FloatOp::Convert(to) => Some(Atom::Float(format_of(to))),
            FloatOp::Add
            | FloatOp::Sub
            | FloatOp::Mul
            | FloatOp::Div
            | FloatOp::Sqrt
            | FloatOp::MulAdd
            | FloatOp::RoundToIntegral
            | FloatOp::FromInt { .. } => Some(float),
        };
        if let Some(result) = result {
            self.supply(v, result, evidence);
        }
    }

    /// A lowered store.
    fn store(&mut self, inst: InstId) {
        if let Some(&Op::Store {
            address,
            value,
            atomic: None,
            ..
        }) = self.view.l1.inst(inst).map(|i| &i.op)
        {
            let var = self.var(value);
            let bits = self.view.width(value);
            self.access(inst, address, bits, var, Side::Lower);
        }
    }

    /// `address` as a base, a constant offset and whether an index is
    /// added (`p + k`, `p - k`, `p + i * s`, nested), through the
    /// expressions lowering folds (a variable is a base itself: it is what
    /// C dereferences).
    fn split(&self, address: Value) -> Split {
        self.split_from(address, false)
    }

    /// [`Self::split`], through variables too if `through`.
    fn split_from(&self, address: Value, through: bool) -> Split {
        let view = self.view;
        let mut split = Split {
            base: view.canonical(address),
            offset: 0,
            indexed: false,
            scale: 0,
        };
        for _ in 0..8 {
            let variable = view.variables.get(split.base.0 as usize);
            if !through && variable.copied().unwrap_or(false) {
                break;
            }
            let Some(&Shape::Pure(inst)) = view.shape(split.base) else {
                break;
            };
            if let Some(x) = view.l1.inst(inst).and_then(|i| view.identity(&i.op)) {
                split.base = x;
                continue;
            }
            let Some(&Op::Binary(op, a, b)) = view.l1.inst(inst).map(|i| &i.op) else {
                break;
            };
            let (a, b) = (view.canonical(a), view.canonical(b));
            let next = match op {
                Binary::Add => match (view.constant(a), view.constant(b)) {
                    // `i * 8 + 0x40220`: an integer computation indexes
                    // the constant (an array of the image), no pointer.
                    (_, Some(_)) if self.integer(a) => {
                        split.indexed = true;
                        split.scale = gcd(split.scale, self.scaled(a).map_or(1, |(_, s)| s.max(1)));
                        Some((b, 0))
                    }
                    (Some(_), None) if self.integer(b) => {
                        split.indexed = true;
                        split.scale = gcd(split.scale, self.scaled(b).map_or(1, |(_, s)| s.max(1)));
                        Some((a, 0))
                    }
                    (_, Some(k)) => Some((a, k)),
                    (Some(k), None) => Some((b, k)),
                    (None, None) => self.indexed_sum(a, b).map(|(base, scale)| {
                        split.indexed = true;
                        split.scale = gcd(split.scale, scale.max(1));
                        (base, 0)
                    }),
                },
                Binary::Sub => view.constant(b).map(|k| (a, k.wrapping_neg())),
                Binary::Mul
                | Binary::UDiv
                | Binary::URem
                | Binary::SDiv
                | Binary::SRem
                | Binary::And
                | Binary::Or
                | Binary::Xor
                | Binary::Shl
                | Binary::LShr
                | Binary::AShr
                | Binary::Rol
                | Binary::Ror
                | Binary::Eq
                | Binary::Ne
                | Binary::ULt
                | Binary::ULe
                | Binary::SLt
                | Binary::SLe => None,
            };
            let Some((base, k)) = next else {
                break;
            };
            split.base = base;
            split.offset = split.offset.wrapping_add(k);
        }
        split
    }

    /// `v`'s index and scale if it is an index scaled by a constant
    /// (`i * s`, `i << s`: `s` times what the index is known a multiple
    /// of, [`Self::multiple`], so `[p + (i * 8 - 8) * 1]` is scaled by 8),
    /// or a sum of integer computations known a multiple of more than one
    /// (`i * 8 - 8`, itself the index).
    fn scaled(&self, v: Value) -> Option<(Value, u64)> {
        let view = self.view;
        let Some(&Shape::Pure(inst)) = view.shape(v) else {
            return None;
        };
        let Some(&Op::Binary(op, a, b)) = view.l1.inst(inst).map(|i| &i.op) else {
            return None;
        };
        let (index, scale) = match (op, view.constant(a), view.constant(b)) {
            (Binary::Mul, Some(s), _) => (b, s.unsigned_abs()),
            (Binary::Mul, None, Some(s)) => (a, s.unsigned_abs()),
            (Binary::Shl, _, Some(s)) => (
                a,
                u32::try_from(s)
                    .ok()
                    .and_then(|s| 1u64.checked_shl(s))
                    .unwrap_or(0),
            ),
            (Binary::Add | Binary::Sub, ..) if self.integer(v) => {
                let multiple = self.multiple(v, MULTIPLE_DEPTH);
                return (multiple > 1).then_some((v, multiple));
            }
            _ => return None,
        };
        let known = self.multiple(index, MULTIPLE_DEPTH).max(1);
        Some((index, scale.checked_mul(known).unwrap_or(scale)))
    }

    /// The constant integer value `v` is known a multiple of, looking
    /// `depth` operations deep: a constant's magnitude (0 for zero, a
    /// multiple of every one), a product's factors' product, a shift left
    /// by `s` its operand's times `2^s`, a sum's or difference's operands'
    /// greatest common divisor, a sign extension its operand's, a zero
    /// extension the power of two of its operand's (the low bits it
    /// keeps); 1 where none is known.
    fn multiple(&self, v: Value, depth: u8) -> u64 {
        let view = self.view;
        let v = view.canonical(v);
        if let Some(k) = view.constant(v) {
            return k.unsigned_abs();
        }
        let Some(depth) = depth.checked_sub(1) else {
            return 1;
        };
        let Some(&Shape::Pure(inst)) = view.shape(v) else {
            return 1;
        };
        let Some(instruction) = view.l1.inst(inst) else {
            return 1;
        };
        if let Some(x) = view.identity(&instruction.op) {
            return self.multiple(x, depth);
        }
        match instruction.op {
            Op::Binary(Binary::Mul, a, b) => self
                .multiple(a, depth)
                .checked_mul(self.multiple(b, depth))
                .unwrap_or(1),
            Op::Binary(Binary::Shl, a, b) => view
                .constant(b)
                .and_then(|s| u32::try_from(s).ok())
                .and_then(|s| 1u64.checked_shl(s))
                .and_then(|power| self.multiple(a, depth).checked_mul(power))
                .unwrap_or(1),
            Op::Binary(Binary::Add | Binary::Sub, a, b) => {
                gcd(self.multiple(a, depth), self.multiple(b, depth))
            }
            Op::Extend { signed, value, .. } => {
                let multiple = self.multiple(value, depth);
                if signed {
                    multiple
                } else {
                    multiple.isolate_lowest_one()
                }
            }
            Op::Const(_)
            | Op::Undefined(..)
            | Op::Unary(..)
            | Op::Binary(..)
            | Op::Extract { .. }
            | Op::Concat { .. }
            | Op::Lanes { .. }
            | Op::Flag(..)
            | Op::Float { .. }
            | Op::Select { .. }
            | Op::Load { .. }
            | Op::Store { .. }
            | Op::Intrinsic { .. }
            | Op::Call { .. }
            | Op::SystemCall { .. }
            | Op::Landing { .. } => 1,
        }
    }

    /// Whether `v` is an integer computation ([`Generated::integers`]).
    fn integer(&self, v: Value) -> bool {
        self.out
            .integers
            .get(self.view.canonical(v).0 as usize)
            .copied()
            .unwrap_or(false)
    }

    /// The pointer of a sum `a + b` of two values neither constant where
    /// one is a scaled index (`p + i * s`), with the index's scale: the
    /// other operand, unless that is an integer computation and the index
    /// is scaled by 1 (an address mode's base register holding an offset,
    /// its index register the pointer: `[off + p * 1]`), then the index.
    fn indexed_sum(&self, a: Value, b: Value) -> Option<(Value, u64)> {
        let pick = |unscaled: Value, (index, scale): (Value, u64)| {
            if scale == 1 && self.integer(unscaled) && !self.integer(index) {
                (index, 1)
            } else {
                (unscaled, scale)
            }
        };
        match (self.scaled(a), self.scaled(b)) {
            (_, Some(index)) => Some(pick(a, index)),
            (Some(index), None) => Some(pick(b, index)),
            (None, None) => None,
        }
    }

    /// Where an access's base is a variable holding `p + k` or `p + i * s`
    /// (C's `q = p + 1; *q`), `p` is a pointer too (no field: its offset is
    /// `q`'s business).
    fn underlying(&mut self, inst: InstId, base: Value) {
        let deep = self.split_from(base, true).base;
        if deep == base
            || matches!(
                self.view.shape(deep),
                Some(Shape::Const(_) | Shape::Address(_)) | None
            )
        {
            return;
        }
        let Some(var) = self.var(deep) else {
            return;
        };
        let evidence = self.evidence(Reason::Access(inst), strength::ACCESS);
        let (store, load) = (self.out.system.var(), self.out.system.var());
        let pointer = self.out.system.pointer(store, load, evidence);
        self.out
            .system
            .constrain(Term::Var(var), Term::Pointer(pointer), evidence);
    }

    /// A load (`side` upper: the value read) or a store (lower: the value
    /// written) of `bits` bits at `address`, `value` its variable.
    fn access(&mut self, inst: InstId, address: Value, bits: u16, value: Option<Var>, side: Side) {
        if let Some(&slot) = self.view.slot_of.get(&inst) {
            // A part of a variable's slot says nothing of the variable.
            if self.view.slots.get(slot).copied().flatten() != Some(bits) {
                return;
            }
            let slot = self.out.slots.get(slot).copied().flatten();
            if let (Some(slot), Some(value)) = (slot, value) {
                let evidence = self.evidence(Reason::Slot(inst), strength::PRIOR);
                match side {
                    Side::Upper => self.edge(slot, value, evidence),
                    Side::Lower => self.edge(value, slot, evidence),
                }
                self.out.cells.entry(slot).or_default().push(value);
            }
            return;
        }
        let split = self.split(address);
        self.underlying(inst, split.base);
        match self.view.shape(split.base) {
            Some(Shape::Const(_)) if split.indexed => return,
            Some(Shape::Const(bits_at)) => {
                let at = bits_at.low_u64().wrapping_add(split.offset.cast_unsigned());
                if let Some(object) = self.named(at)
                    && let Some(&node) = self.out.objects.get(&object.start)
                    && !(object.start == at && object.size.saturating_mul(8) == u64::from(bits))
                    && bits > 0
                {
                    // Part of a global object: an access through its
                    // address, at its offset in it, for the object's
                    // layout (no constraint: the values keep their own
                    // types, as before the object was one).
                    let offset = i64::try_from(at - object.start).unwrap_or(0);
                    self.out.families.access(inst, node, offset, bits, value, 0);
                    return;
                }
                self.global(inst, at, bits, value, side);
                return;
            }
            Some(Shape::Address(_)) => return,
            Some(Shape::Phi(_) | Shape::Pure(_) | Shape::Load(_) | Shape::Other) | None => {}
        }
        let Some(base) = self.var(split.base) else {
            return;
        };
        if bits > 0 {
            self.out
                .families
                .access(inst, base, split.offset, bits, value, split.scale);
        }
        let evidence = self.evidence(Reason::Access(inst), strength::ACCESS);
        if split.indexed || bits == 0 {
            let (store, load) = (self.out.system.var(), self.out.system.var());
            let pointer = self.out.system.pointer(store, load, evidence);
            self.out
                .system
                .constrain(Term::Var(base), Term::Pointer(pointer), evidence);
            return;
        }
        let value = value.unwrap_or_else(|| self.out.system.var());
        let field = Field {
            offset: split.offset,
            bits,
        };
        match side {
            Side::Upper => self.out.system.load(base, field, value, evidence),
            Side::Lower => self.out.system.store(base, field, value, evidence),
        };
    }

    /// An access at constant address `at`: the variable of the object of
    /// the image's data starting there, as wide as the access; or of the
    /// data no object names there (an import's slot), as wide as the
    /// access.
    fn global(&mut self, inst: InstId, at: u64, bits: u16, value: Option<Var>, side: Side) {
        let Some(value) = value else {
            return;
        };
        let data = self.view.data;
        let whole = if let Some(object) = data.object(at) {
            object.start == at && object.size.saturating_mul(8) == u64::from(bits)
        } else {
            let bytes = u64::from(bits / 8);
            let named = (1..bytes).any(|byte| data.object(at.saturating_add(byte)).is_some());
            bits.is_multiple_of(8) && !named && data.data(at, bytes).is_some()
        };
        if !whole {
            return;
        }
        let system = &mut self.out.system;
        let (global, width) = *self
            .out
            .globals
            .entry(at)
            .or_insert_with(|| (system.var(), bits));
        if width != bits {
            return;
        }
        let evidence = self.evidence(Reason::Global(inst), strength::PRIOR);
        match side {
            Side::Upper => self.edge(global, value, evidence),
            Side::Lower => self.edge(value, global, evidence),
        }
        self.out.cells.entry(global).or_default().push(value);
    }

    /// Declared types at calls: arguments below their parameters' types,
    /// results above theirs; targets called through a value below `Code`;
    /// callees' schemes, at most [`INSTANCES`] constraints of them.
    fn calls(&mut self) {
        let view = self.view;
        let mut schemes = Vec::new();
        for call in &view.calls {
            let Some(signature) = view.types.signature(call.signature) else {
                continue;
            };
            let parameters = signature.parameters.iter().chain(&call.variadic);
            for (index, (values, &ty)) in call.arguments.iter().zip(parameters).enumerate() {
                for &argument in values {
                    let reason = Reason::Argument {
                        call: call.target,
                        index,
                    };
                    self.declare(argument, ty, Side::Upper, reason, strength::DECLARED);
                }
            }
            if let Some(ty) = signature.returns {
                for &result in &call.result {
                    let reason = Reason::Result(call.target);
                    self.declare(result, ty, Side::Lower, reason, strength::DECLARED);
                }
                // A tail call's result is the function's return value.
                if let Some(returns) = self.out.returns
                    && call.tail
                    && view.types.value_width(ty) == Some(view.returns.width)
                {
                    let reason = Reason::Result(call.target);
                    self.bound(returns, ty, Side::Lower, reason, strength::DECLARED);
                }
            }
            if call.indirect
                && let Some(target) = self.var(call.target)
            {
                let evidence = self.evidence(Reason::Called(call.target), strength::ACCESS);
                self.out.system.constrain(
                    Term::Var(target),
                    Term::Code(Code::new([], [])),
                    evidence,
                );
                self.out
                    .called
                    .insert(target, (call.signature, call.guessed));
            }
            if self.schemes
                && let Some(callee) = call.callee
                && let Some(summary) = view.schemes.before(view.l1.entry, callee)
            {
                schemes.push((call, callee, summary));
            }
        }
        let size = |&(_, _, summary): &(&Call, u64, &Summary)| summary.scheme().constraint_count();
        // Past `INSTANCES` constraints in all, the largest schemes are not
        // instantiated, largest first (of equal ones, the earliest call's).
        let mut stated: usize = schemes.iter().map(size).sum();
        let mut largest: Vec<usize> = (0..schemes.len()).collect();
        largest.sort_by_key(|&index| Reverse(schemes.get(index).map_or(0, size)));
        let mut dropped = vec![false; schemes.len()];
        for index in largest {
            if stated <= INSTANCES {
                break;
            }
            stated -= schemes.get(index).map_or(0, size);
            if let Some(drop) = dropped.get_mut(index) {
                *drop = true;
            }
        }
        for ((call, callee, summary), dropped) in schemes.into_iter().zip(dropped) {
            if !dropped {
                self.instance(call, callee, summary);
            }
        }
    }

    /// A fresh instance of the callee's scheme `summary` at `call`: each
    /// argument below its parameter's instance (as wide; constants give
    /// nothing), the result's instance below the call's result (a tail
    /// call's: the return value); the callee's strengths capped at
    /// [`strength::SCHEME`]; the class every caller of the callee passes
    /// at a parameter ([`View::specialisations`]) below its instance, as
    /// in the callee's own solve ([`Self::specialised`]). The instance's
    /// roots are the callee's (`callee`) in [`Generated::instances`].
    fn instance(&mut self, call: &Call, callee: u64, summary: &Summary) {
        let view = self.view;
        let tag = self
            .evidence(Reason::Scheme(call.target), strength::SCHEME)
            .tag;
        let evidence = |stated: Evidence| Evidence {
            tag,
            strength: stated.strength.min(strength::SCHEME),
        };
        let edge = evidence(Evidence {
            tag,
            strength: strength::SCHEME,
        });
        let vars = summary.scheme.instantiate(&mut self.out.system, evidence);
        for (root, instance) in summary.roots.iter().zip(vars) {
            self.out
                .instances
                .entry(callee)
                .or_default()
                .push((*root, instance));
            match *root {
                Root::Parameter(source, width) => {
                    if let Some(&(_, class)) = view
                        .specialisations
                        .get(&callee)
                        .and_then(|classes| classes.iter().find(|(at, _)| *at == source))
                        && class_width(class, view.types.pointer_width()) == width
                    {
                        let index = call
                            .sources
                            .iter()
                            .position(|&at| at == source)
                            .unwrap_or_default();
                        let evidence = self.evidence(Reason::Callers(index), strength::CALLERS);
                        let term = self.class_term(class, evidence);
                        self.out
                            .system
                            .constrain(term, Term::Var(instance), evidence);
                    }
                    let arguments = call
                        .sources
                        .iter()
                        .zip(&call.arguments)
                        .filter(|&(&at, _)| at == source)
                        .flat_map(|(_, values)| values);
                    for &argument in arguments {
                        if view.width(argument) == width
                            && view.constant(argument).is_none()
                            && let Some(var) = self.var(argument)
                        {
                            self.edge(var, instance, edge);
                        }
                    }
                }
                Root::Return(width) => {
                    for &result in &call.result {
                        if view.width(result) == width
                            && let Some(var) = self.var(result)
                        {
                            self.edge(instance, var, edge);
                        }
                    }
                    if call.tail
                        && view.returns.width == width
                        && let Some(returns) = self.out.returns
                    {
                        self.edge(instance, returns, edge);
                    }
                }
            }
        }
    }

    /// Declared type `ty` as a bound on value `v` (`side`: upper, a
    /// demand; lower, what it is; on a wider value, its low part, as an
    /// atom as wide as `ty` that only rounding at that width reads).
    fn declare(&mut self, v: Value, ty: TypeId, side: Side, reason: Reason, strength: Strength) {
        let Some(var) = self.var(v) else {
            return;
        };
        let width = self.view.width(v);
        if self
            .view
            .types
            .value_width(ty)
            .is_some_and(|bits| bits <= width)
        {
            self.bound(var, ty, side, reason, strength);
        }
    }

    /// Declared type `ty` as a bound on `var`.
    fn bound(&mut self, var: Var, ty: TypeId, side: Side, reason: Reason, strength: Strength) {
        let evidence = self.evidence(reason, strength);
        if let Some(term) = self.term(ty, side, evidence, 0) {
            if side == Side::Upper && matches!(term, Term::Code(_)) {
                self.out.called.entry(var).or_insert((ty, false));
            }
            let types = self.view.types;
            if let Some(&Type::Pointer(Some(target))) = types.get(ty)
                && matches!(
                    types.get(target),
                    Some(
                        Type::Struct(_) | Type::Union(_) | Type::Array { .. } | Type::Vector { .. }
                    )
                )
            {
                self.out.pointees.insert(var);
            }
            let (lhs, rhs) = match side {
                Side::Upper => (Term::Var(var), demand(term)),
                Side::Lower => (term, Term::Var(var)),
            };
            self.out.system.constrain(lhs, rhs, evidence);
        }
    }

    /// The term of declared type `ty` on `side` of a variable: atoms, a
    /// pointer (with its target's field at offset 0, two levels deep),
    /// code; nothing for `bits` and aggregates. An enumeration is its
    /// value's atom ([`Atom::Enum`], by its id in the view's types), which
    /// only what a value is states: a demand takes its integer
    /// ([`demand`]).
    fn term(&mut self, ty: TypeId, side: Side, evidence: Evidence, depth: u8) -> Option<Term> {
        let atom = match *self.view.types.get(ty)? {
            Type::Int(width) => Atom::Signed(width),
            Type::UInt(width) => Atom::Unsigned(width),
            Type::Enum(Enumeration { width, signed, .. }) => Atom::Enum {
                id: ty.0,
                width,
                signed,
            },
            Type::Char { signed } => Atom::Char { signed },
            Type::Bool(width) => Atom::Bool(width),
            Type::Float(format) => Atom::Float(format_of(format)),
            Type::Pointer(target) => {
                let pointer = self.pointer(target, side, evidence, depth);
                return Some(Term::Pointer(pointer));
            }
            Type::Code(_) => return Some(Term::Code(Code::new([], []))),
            Type::Bits(_)
            | Type::Struct(_)
            | Type::Union(_)
            | Type::Array { .. }
            | Type::Vector { .. } => return None,
        };
        Some(Term::Atom(atom))
    }

    /// A declared pointer to `target` on `side`: what a load through it
    /// gives and a store puts there are the target, at offset 0.
    fn pointer(
        &mut self,
        target: Option<TypeId>,
        side: Side,
        evidence: Evidence,
        depth: u8,
    ) -> Pointer {
        let (store, load) = (self.out.system.var(), self.out.system.var());
        let pointer = self.out.system.pointer(store, load, evidence);
        let Some(target) = target.filter(|_| depth < 2) else {
            return pointer;
        };
        let Some(bits) = self.view.types.value_width(target) else {
            return pointer;
        };
        let Some(term) = self.term(target, side, evidence, depth.saturating_add(1)) else {
            return pointer;
        };
        let field = Field { offset: 0, bits };
        let (stored, loaded) = (self.out.system.var(), self.out.system.var());
        let system = &mut self.out.system;
        let record = |var: Var| Term::Record(Record::field(field, var));
        let constraints = match side {
            // A demand: what the user stores is the target; what it loads
            // must be one.
            Side::Upper => [
                (record(stored), Term::Var(store)),
                (term.clone(), Term::Var(stored)),
                (Term::Var(load), record(loaded)),
                (Term::Var(loaded), demand(term)),
            ],
            // What it is: a load gives the target; a store must put one.
            Side::Lower => [
                (record(loaded), Term::Var(load)),
                (term.clone(), Term::Var(loaded)),
                (Term::Var(store), record(stored)),
                (Term::Var(stored), demand(term)),
            ],
        };
        for (lhs, rhs) in constraints {
            system.constrain(lhs, rhs, evidence);
        }
        pointer
    }

    /// The function's own declared parameters, both ways.
    fn parameters(&mut self) {
        let view = self.view;
        for (index, parameter) in view.parameters.iter().enumerate() {
            let width = view.types.value_width(parameter.ty);
            let mut vars: Vec<Var> = parameter
                .values
                .iter()
                .filter(|&&value| Some(view.width(value)) == width)
                .filter_map(|&value| self.var(value))
                .collect();
            vars.extend(
                parameter
                    .slot
                    .and_then(|slot| self.out.slots.get(slot).copied().flatten()),
            );
            for var in vars {
                let reason = Reason::Parameter(index);
                self.stated(
                    var,
                    parameter.ty,
                    parameter.evidence,
                    reason,
                    strength::ACCESS,
                );
            }
        }
    }

    /// The user's types: both bounds, declared, on the values and slots
    /// as wide as the type (the strongest evidence there is).
    fn user(&mut self) {
        let view = self.view;
        for &(value, ty) in &view.user_values {
            if view.types.value_width(ty) == Some(view.width(value))
                && let Some(var) = self.var(value)
            {
                self.stated(var, ty, Stated::Declared, Reason::User, strength::ACCESS);
            }
        }
        for &(slot, ty) in &view.user_slots {
            if let Some(var) = self.out.slots.get(slot).copied().flatten() {
                self.stated(var, ty, Stated::Declared, Reason::User, strength::ACCESS);
            }
        }
    }

    /// A declared type on `var`: both bounds where declared; a pointer
    /// lower bound at `open` strength where declared only a pointer.
    fn stated(&mut self, var: Var, ty: TypeId, evidence: Stated, reason: Reason, open: Strength) {
        match evidence {
            Stated::Declared => {
                for side in [Side::Lower, Side::Upper] {
                    self.bound(var, ty, side, reason, strength::DECLARED);
                }
            }
            Stated::DeclaredPointer => {
                let evidence = self.evidence(reason, open);
                let (store, load) = (self.out.system.var(), self.out.system.var());
                let pointer = self.out.system.pointer(store, load, evidence);
                self.out
                    .system
                    .constrain(Term::Pointer(pointer), Term::Var(var), evidence);
            }
            Stated::Default | Stated::Deduced => {}
        }
    }

    /// Returned values below the return value; its declared type.
    fn returns(&mut self) {
        let view = self.view;
        let Some(returns) = self.out.returns else {
            return;
        };
        for &value in &view.returns.values {
            if let Some(var) = self.var(value)
                && view.width(value) == view.returns.width
            {
                let evidence = self.evidence(Reason::Returned, strength::PRIOR);
                self.edge(var, returns, evidence);
            }
        }
        if let (Some(ty), Some(evidence)) = (view.returns.ty, view.returns.evidence) {
            self.stated(returns, ty, evidence, Reason::Returned, strength::PRIOR);
        }
    }

    /// The top-down specialisation: the class every caller passes at an
    /// undeclared parameter ([`View::specialised`]) as a lower bound on its
    /// values as wide as the class, at [`strength::CALLERS`].
    fn specialised(&mut self) {
        let view = self.view;
        let pointer = view.types.pointer_width();
        for (index, parameter) in view.parameters.iter().enumerate() {
            if matches!(
                parameter.evidence,
                Stated::Declared | Stated::DeclaredPointer
            ) {
                continue;
            }
            let Some(&(_, class)) = view
                .specialised
                .iter()
                .find(|(source, _)| *source == parameter.source)
            else {
                continue;
            };
            let width = class_width(class, pointer);
            for &value in &parameter.values {
                if view.width(value) != width {
                    continue;
                }
                let Some(var) = self.var(value) else {
                    continue;
                };
                let evidence = self.evidence(Reason::Callers(index), strength::CALLERS);
                let term = self.class_term(class, evidence);
                self.out.system.constrain(term, Term::Var(var), evidence);
            }
        }
    }

    /// The program's type of each global this function reads or writes
    /// whole ([`View::schemes`]' [`Globals`](super::Globals): every
    /// function's evidence joined) as a lower bound on its variable, so
    /// the values loaded from it take that type unless their own evidence
    /// is stronger: at the strength of the evidence that chose it, capped
    /// at [`strength::SCHEME`] (another function's deduction is no
    /// declaration). A pointer to a struct of the table is a pointer here
    /// (the struct is its values' family's by [`super::round`]'s claims).
    fn program_globals(&mut self) {
        let view = self.view;
        let globals = view.schemes.globals();
        let pointer = view.types.pointer_width();
        let found: Vec<(u64, Var, u16)> = self
            .out
            .globals
            .iter()
            .map(|(&at, &(var, bits))| (at, var, bits))
            .collect();
        for (at, var, bits) in found {
            let Some(ty) = globals.get(at) else {
                continue;
            };
            let GlobalShape::Value(field) = &ty.shape else {
                continue;
            };
            let Some(class) = field_class(field) else {
                continue;
            };
            if ty.size.saturating_mul(8) != u64::from(bits) || class_width(class, pointer) != bits {
                continue;
            }
            let strength = ty.strength.min(strength::SCHEME);
            let evidence = self.evidence(Reason::Program(at), strength);
            let term = self.class_term(class, evidence);
            self.out.system.constrain(term, Term::Var(var), evidence);
        }
    }

    /// What a value of `class` is, as a lower bound (a pointer's target at
    /// offset 0, as [`Self::pointer`] states a declared one's).
    fn class_term(&mut self, class: Class, evidence: Evidence) -> Term {
        match class {
            Class::Scalar(atom) => Term::Atom(atom),
            Class::Code => Term::Code(Code::new([], [])),
            Class::Pointer(target) => {
                let system = &mut self.out.system;
                let (store, load) = (system.var(), system.var());
                let pointer = system.pointer(store, load, evidence);
                if let Some(atom) = target {
                    let field = Field {
                        offset: 0,
                        bits: atom.width(),
                    };
                    let (stored, loaded) = (system.var(), system.var());
                    let record = |var: Var| Term::Record(Record::field(field, var));
                    for (lhs, rhs) in [
                        (record(loaded), Term::Var(load)),
                        (Term::Atom(atom), Term::Var(loaded)),
                        (Term::Var(store), record(stored)),
                        (Term::Var(stored), Term::Atom(atom)),
                    ] {
                        system.constrain(lhs, rhs, evidence);
                    }
                }
                Term::Pointer(pointer)
            }
        }
    }
}

/// How wide a value of `class` is, `pointer` a pointer's width.
fn class_width(class: Class, pointer: u16) -> u16 {
    match class {
        Class::Scalar(atom) => atom.width(),
        Class::Pointer(_) | Class::Code => pointer,
    }
}

/// The class of a value of field type `ty`: a scalar's atom (none for
/// untyped bits), a pointer with its scalar target's atom (a struct's:
/// none), code.
fn field_class(ty: &FieldType) -> Option<Class> {
    let atom = |ty: &Type| match *ty {
        Type::Int(width) => Some(Atom::Signed(width)),
        Type::UInt(width) => Some(Atom::Unsigned(width)),
        Type::Enum(Enumeration { width, signed, .. }) => Some(if signed {
            Atom::Signed(width)
        } else {
            Atom::Unsigned(width)
        }),
        Type::Char { signed } => Some(Atom::Char { signed }),
        Type::Bool(width) => Some(Atom::Bool(width)),
        Type::Float(lane) => Some(Atom::Float(format_of(lane))),
        Type::Bits(_)
        | Type::Pointer(_)
        | Type::Code(_)
        | Type::Struct(_)
        | Type::Union(_)
        | Type::Array { .. }
        | Type::Vector { .. } => None,
    };
    match ty {
        FieldType::Scalar(scalar) => atom(scalar).map(Class::Scalar),
        FieldType::Pointer(target) => Some(Class::Pointer(target.as_ref().and_then(atom))),
        FieldType::Opaque
        | FieldType::Struct(_)
        | FieldType::Pointers(_)
        | FieldType::ScalarPointers(_) => Some(Class::Pointer(None)),
        FieldType::Code { .. } => Some(Class::Code),
    }
}

/// The solver's format of a floating-point format.
pub(super) const fn format_of(format: Lane) -> Format {
    match format {
        Lane::Half => Format::Half,
        Lane::Single => Format::Single,
        Lane::Double => Format::Double,
        Lane::Extended => Format::Extended,
    }
}

/// Declared term `term` as a demand: an enumeration as its integer (a use
/// declared to take one takes any of its integers, as C converts them;
/// only a value's source says it is one).
fn demand(term: Term) -> Term {
    match term {
        Term::Atom(atom) => Term::Atom(atom.integer()),
        other @ (Term::Var(_)
        | Term::Top
        | Term::Bottom
        | Term::Pointer(_)
        | Term::Record(_)
        | Term::Code(_)) => other,
    }
}
