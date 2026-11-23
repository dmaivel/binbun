//! Constant propagation: which values are the same constant on every path
//! that can run, and which blocks can run at all.
//!
//! Sparse conditional constant propagation (Wegman and Zadeck, "Constant
//! Propagation with Conditional Branches", 1991): each value starts not yet
//! known and only moves down, to a constant and then to "varies"; a block
//! is reached only along edges its predecessor can take (a branch on a
//! constant takes one side). Pure operations are evaluated by L0's own
//! evaluation ([`binbun_semantics::interpret`]), so L1 constants agree with
//! L0 bit for bit; a result with undefined bits varies. Loads fold where
//! [`ReadOnly`] knows the memory; calls, intrinsics and the function's
//! inputs vary. An operand that absorbs the other makes the result
//! constant whatever the other is: `x & 0` is 0 and `x | ~0` is `~0` (the
//! `or eax, -1` that returns -1 reads `eax` only in form).
//! So does an operation of a value with itself that gives one result
//! whatever the value: `xor eax, eax` and `sub eax, eax` are 0,
//! `pcmpeqd xmm0, xmm0` all ones (dependency-breaking idioms).
//!
//! Under the pass manager, [`Constants`] is an [`Analysis`] (in an
//! [`L1Env`], over its memory) and [`FoldBranches`] the pass that turns the
//! branches it proves constant into jumps.

use alloc::vec;
use alloc::vec::Vec;

use binbun_semantics::bits::Bits;
use binbun_semantics::core::pass::{Analyses, Analysis, Changed, Cx, Pass, Preserved, Refusal};
use binbun_semantics::interpret::{self, Value as Bitvalue};
use binbun_semantics::ir::{Binary, LaneOp};

use crate::groups::Groups;
use crate::ir::{BlockId, Definition, Function, InstId, Op, Target, Terminator, Type, Value};
use crate::pass::{L1Env, blocks};

/// What constant propagation knows about a value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Lattice {
    /// Nothing yet (no path that defines it has been found to run).
    Unknown,
    /// The same constant on every path that runs.
    Constant(Bits),
    /// Different values, or one not known.
    Varies,
}

impl Lattice {
    /// The greatest lower bound of `self` and `other`.
    #[must_use]
    pub fn meet(self, other: Self) -> Self {
        match (self, other) {
            (Self::Unknown, x) | (x, Self::Unknown) => x,
            (Self::Constant(a), Self::Constant(b)) if a == b => Self::Constant(a),
            (Self::Constant(_) | Self::Varies, Self::Constant(_) | Self::Varies) => Self::Varies,
        }
    }
}

/// Memory whose contents are known before the program runs and never
/// change (read-only parts of the file, without relocations).
pub trait ReadOnly {
    /// `bytes` bytes at `address`, if all are known read-only memory.
    fn read(&self, address: u64, bytes: u16) -> Option<Bits>;

    /// Whether the `bytes` bytes at `address` hold, from the moment the
    /// program starts, an address of the process that never changes but
    /// is not known here: an import slot the loader fills and makes
    /// read-only (an ELF GOT entry under `BIND_NOW` in RELRO, a PE IAT
    /// entry in a read-only section). Such an address is mapped, so
    /// canonical. None by default.
    fn fixed_address(&self, _address: u64, _bytes: u16) -> bool {
        false
    }
}

/// No memory is known.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NoMemory;

impl ReadOnly for NoMemory {
    fn read(&self, _: u64, _: u16) -> Option<Bits> {
        None
    }
}

/// The result: a [`Lattice`] per value and whether each block can run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Constants {
    values: Vec<Lattice>,
    reachable: Vec<bool>,
}

impl Constants {
    /// What is known about `value`.
    pub fn lattice(&self, value: Value) -> Lattice {
        self.values
            .get(value.0 as usize)
            .copied()
            .unwrap_or(Lattice::Varies)
    }

    /// `value`'s constant, if it has one.
    pub fn constant(&self, value: Value) -> Option<Bits> {
        match self.lattice(value) {
            Lattice::Constant(bits) => Some(bits),
            Lattice::Unknown | Lattice::Varies => None,
        }
    }

    /// Whether `block` can run.
    pub fn reachable(&self, block: BlockId) -> bool {
        self.reachable
            .get(block.0 as usize)
            .copied()
            .unwrap_or(false)
    }
}

impl<'e> Analysis<Function, L1Env<'e>> for Constants {
    fn compute(
        function: &Function,
        env: &L1Env<'e>,
        _: &mut Analyses<Function, L1Env<'e>>,
    ) -> Self {
        propagate(function, env.memory)
    }
}

/// Where a value is used.
#[derive(Clone, Copy, Debug)]
enum User {
    Inst(InstId, BlockId),
    Terminator(BlockId),
}

/// The pass `fold-branches`: every branch whose condition [`Constants`]
/// proves constant becomes a jump along the edge it takes. A block only
/// the other edge reached becomes unreachable, so analyses and lowering
/// that follow the graph from the entry skip it; no block or value is
/// removed or renumbered, and every path the function can run is kept.
///
/// Preserves [`Constants`]: propagation already took only that edge out of
/// such a branch, so over the folded function it reaches the same blocks
/// with the same values. The graph changes, so nothing built on it
/// survives ([`Dominators`](crate::graph::Dominators),
/// [`Stack`](crate::stack::Stack), which holds the predecessors). Fuel: a
/// unit per block.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FoldBranches;

impl<'e> Pass<Function, L1Env<'e>> for FoldBranches {
    fn name(&self) -> &'static str {
        "fold-branches"
    }

    fn run(
        &mut self,
        function: &mut Function,
        cx: &mut Cx<'_, Function, L1Env<'e>>,
    ) -> Result<Changed, Refusal> {
        cx.fuel.spend(blocks(function))?;
        let constants = cx.analysis::<Constants>(function);
        Ok(Changed::from(fold_branches(function, &constants) > 0))
    }

    fn preserves(&self, preserved: &mut Preserved) {
        preserved.keep::<Constants>();
    }
}

/// [`FoldBranches`] with `function`'s `constants`: how many branches were
/// folded.
fn fold_branches(function: &mut Function, constants: &Constants) -> usize {
    let mut folded = 0;
    for block in &mut function.blocks {
        let Terminator::Branch {
            condition,
            then,
            otherwise,
        } = &block.terminator
        else {
            continue;
        };
        let Some(taken) = constants.constant(*condition) else {
            continue;
        };
        let target = if taken.is_zero() { otherwise } else { then }.clone();
        block.terminator = Terminator::Jump(target);
        folded += 1;
    }
    folded
}

/// Constant propagation over `function`, folding loads `memory` knows.
pub fn propagate(function: &Function, memory: &dyn ReadOnly) -> Constants {
    // Every (operand, user) pair, then the users of each value.
    let mut pairs: Vec<(usize, User)> = Vec::new();
    for (index, block) in function.blocks.iter().enumerate() {
        let id = BlockId(u32::try_from(index).unwrap_or(u32::MAX));
        for &inst in &block.insts {
            if let Some(i) = function.inst(inst) {
                pairs.extend(
                    i.op.operands()
                        .into_iter()
                        .map(|operand| (operand.0 as usize, User::Inst(inst, id))),
                );
            }
        }
        let terminator = &block.terminator;
        let arguments = terminator
            .targets()
            .flat_map(|t| t.arguments.iter().copied());
        pairs.extend(
            terminator
                .operands()
                .chain(arguments)
                .map(|operand| (operand.0 as usize, User::Terminator(id))),
        );
    }
    let users = Groups::new(function.values.len(), pairs.iter().copied());
    drop(pairs);
    let mut p = Propagation {
        function,
        memory,
        values: vec![Lattice::Unknown; function.values.len()],
        reachable: vec![false; function.blocks.len()],
        blocks: Vec::new(),
        changed: Vec::new(),
    };
    // The function's inputs vary.
    if let Some(entry) = function.blocks.first() {
        for &parameter in &entry.parameters {
            p.set(parameter, Lattice::Varies);
        }
    }
    if let Some(entry) = p.reachable.first_mut() {
        *entry = true;
        p.blocks.push(BlockId(0));
    }
    loop {
        if let Some(block) = p.blocks.pop() {
            p.visit(block);
        } else if let Some(value) = p.changed.pop() {
            for &user in users.get(value.0 as usize) {
                match user {
                    User::Inst(inst, block) if p.is_reachable(block) => p.evaluate(inst),
                    User::Terminator(block) if p.is_reachable(block) => p.terminator(block),
                    User::Inst(..) | User::Terminator(_) => {}
                }
            }
        } else {
            break;
        }
    }
    Constants {
        values: p.values,
        reachable: p.reachable,
    }
}

struct Propagation<'a> {
    function: &'a Function,
    memory: &'a dyn ReadOnly,
    values: Vec<Lattice>,
    reachable: Vec<bool>,
    /// Blocks newly reachable, to visit.
    blocks: Vec<BlockId>,
    /// Values whose lattice changed, whose users need another look.
    changed: Vec<Value>,
}

impl Propagation<'_> {
    fn is_reachable(&self, block: BlockId) -> bool {
        self.reachable
            .get(block.0 as usize)
            .copied()
            .unwrap_or(false)
    }

    fn get(&self, value: Value) -> Lattice {
        self.values
            .get(value.0 as usize)
            .copied()
            .unwrap_or(Lattice::Varies)
    }

    /// Lowers `value` to `lattice` (met with what it was).
    fn set(&mut self, value: Value, lattice: Lattice) {
        let Some(slot) = self.values.get_mut(value.0 as usize) else {
            return;
        };
        // The bottom: nothing lowers it (and comparing constants costs).
        if matches!(slot, Lattice::Varies) {
            return;
        }
        let lowered = slot.meet(lattice);
        if lowered != *slot {
            *slot = lowered;
            self.changed.push(value);
        }
    }

    fn visit(&mut self, block: BlockId) {
        let Some(b) = self.function.block(block) else {
            return;
        };
        for &inst in &b.insts {
            self.evaluate(inst);
        }
        self.terminator(block);
    }

    /// Takes the edge to `target`: marks its block reachable and passes
    /// the arguments to its parameters.
    fn take(&mut self, target: &Target) {
        let to = target.block;
        let parameters = self
            .function
            .block(to)
            .map_or(&[][..], |b| b.parameters.as_slice());
        for (&parameter, &argument) in parameters.iter().zip(&target.arguments) {
            let lattice = self.get(argument);
            self.set(parameter, lattice);
        }
        if let Some(reached) = self.reachable.get_mut(to.0 as usize)
            && !*reached
        {
            *reached = true;
            self.blocks.push(to);
        }
    }

    fn terminator(&mut self, block: BlockId) {
        let function = self.function;
        let Some(b) = function.block(block) else {
            return;
        };
        match &b.terminator {
            Terminator::Jump(target) => self.take(target),
            Terminator::Branch {
                condition,
                then,
                otherwise,
            } => match self.get(*condition) {
                Lattice::Constant(bits) if bits.low_u64() != 0 => self.take(then),
                Lattice::Constant(_) => self.take(otherwise),
                Lattice::Varies => {
                    self.take(then);
                    self.take(otherwise);
                }
                Lattice::Unknown => {}
            },
            // The callee may return or throw.
            Terminator::Invoke { normal, unwind } => {
                self.take(normal);
                self.take(unwind);
            }
            Terminator::IndirectJump { address, targets } => {
                let lattice = self.get(*address);
                for target in targets {
                    let taken = match lattice {
                        Lattice::Constant(bits) => function
                            .block(target.block)
                            .is_some_and(|t| t.address == bits.low_u64()),
                        Lattice::Varies => true,
                        Lattice::Unknown => false,
                    };
                    if taken {
                        self.take(target);
                    }
                }
            }
            Terminator::Return { .. }
            | Terminator::Leave { .. }
            | Terminator::Trap(_)
            | Terminator::Stop
            | Terminator::Open => {}
        }
    }

    fn evaluate(&mut self, inst: InstId) {
        let Some(i) = self.function.inst(inst) else {
            return;
        };
        let result = match &i.op {
            Op::Intrinsic { .. }
            | Op::Call { .. }
            | Op::SystemCall { .. }
            | Op::Store { .. }
            | Op::Landing { .. } => {
                // Values the processor, a callee, the system or the
                // unwinder supply.
                for &value in &i.results {
                    self.set(value, Lattice::Varies);
                }
                return;
            }
            Op::Undefined(..) => Lattice::Varies,
            Op::Const(bits) => Lattice::Constant(*bits),
            Op::Load { address, bytes, .. } => match self.get(*address) {
                Lattice::Constant(bits) => self
                    .memory
                    .read(bits.low_u64(), *bytes)
                    .map_or(Lattice::Varies, Lattice::Constant),
                other @ (Lattice::Unknown | Lattice::Varies) => other,
            },
            op @ (Op::Unary(..)
            | Op::Binary(..)
            | Op::Flag(..)
            | Op::Extract { .. }
            | Op::Concat { .. }
            | Op::Extend { .. }
            | Op::Select { .. }
            | Op::Lanes { .. }
            | Op::Float { .. }) => self.pure(op),
        };
        if let Some(&value) = i.results.first() {
            let memory = self.function.ty(value) == Some(Type::Memory);
            self.set(value, if memory { Lattice::Varies } else { result });
        }
    }

    /// A pure operation on what is known of its operands.
    fn pure(&self, op: &Op) -> Lattice {
        // A select on a known condition needs only that arm.
        if let Op::Select {
            condition,
            then,
            otherwise,
        } = op
        {
            return match self.get(*condition) {
                Lattice::Constant(bits) if bits.low_u64() != 0 => self.get(*then),
                Lattice::Constant(_) => self.get(*otherwise),
                Lattice::Varies => self.get(*then).meet(self.get(*otherwise)),
                Lattice::Unknown => Lattice::Unknown,
            };
        }
        let mut operands = Vec::new();
        if let Op::Binary(binary @ (Binary::And | Binary::Or), a, b) = op {
            for side in [*a, *b] {
                if let Lattice::Constant(bits) = self.get(side)
                    && absorbs(*binary, &bits)
                {
                    return Lattice::Constant(bits);
                }
            }
        }
        if let Some(bits) = self.idiom(op) {
            return Lattice::Constant(bits);
        }
        for operand in op.operands() {
            match self.get(operand) {
                Lattice::Constant(bits) => operands.push(Bitvalue::defined(bits)),
                Lattice::Varies => return Lattice::Varies,
                Lattice::Unknown => return Lattice::Unknown,
            }
        }
        evaluate(op, &operands)
            .and_then(|value| value.known())
            .map_or(Lattice::Varies, Lattice::Constant)
    }

    /// A dependency-breaking idiom: an operation of a value with itself
    /// whose result is the same whatever the value (`xor eax, eax` and
    /// `sub eax, eax` are 0, `pcmpeqd xmm0, xmm0` and `vpcmpeqd ymm3,
    /// ymm3, ymm3` all ones, `pcmpgtb` 0), so it reads nothing: its
    /// constant.
    fn idiom(&self, op: &Op) -> Option<Bits> {
        let (binary, a, b, lanes) = if let Op::Binary(binary, a, b) = *op {
            (binary, a, b, None)
        } else if let Op::Lanes {
            lanes,
            op: LaneOp::Binary(binary),
            operands: [a, b, _],
        } = *op
        {
            (binary, a, b, Some(lanes))
        } else {
            return None;
        };
        let constant = matches!(
            binary,
            Binary::Xor
                | Binary::Sub
                | Binary::Eq
                | Binary::Ne
                | Binary::ULt
                | Binary::ULe
                | Binary::SLt
                | Binary::SLe
        );
        if !constant || !self.same(a, b, SAME_DEPTH) {
            return None;
        }
        let Some(Type::Bits(width)) = self.function.ty(a) else {
            return None;
        };
        // Any value gives the same: 0's.
        let zero = Bitvalue::defined(Bits::zero(width));
        let value = match lanes {
            Some(lanes) => interpret::lanes(LaneOp::Binary(binary), lanes, &[zero, zero]),
            None => interpret::binary(binary, zero, zero),
        };
        value.known()
    }

    /// Whether `a` and `b` are one value: the same, or each the result of
    /// the same pure operation of the same values (a register read twice:
    /// two extractions of its value), looking `depth` operations deep.
    fn same(&self, a: Value, b: Value, depth: u8) -> bool {
        if a == b {
            return true;
        }
        let function = self.function;
        let defining = |v: Value| match function.value(v)?.definition {
            Definition::Result { inst, index: 0 } => function.inst(inst).map(|i| &i.op),
            Definition::Result { .. } | Definition::Parameter { .. } => None,
        };
        let (Some(x), Some(y)) = (defining(a), defining(b)) else {
            return false;
        };
        let pure = matches!(
            x,
            Op::Unary(..)
                | Op::Binary(..)
                | Op::Extract { .. }
                | Op::Concat { .. }
                | Op::Extend { .. }
                | Op::Lanes { .. }
        );
        let (Some(depth), true) = (depth.checked_sub(1), pure) else {
            return false;
        };
        // `y` with `x`'s values is `x`: the same operation; then each pair
        // of values is one value.
        let mut xs = Vec::new();
        x.clone().map_values(&mut |v| {
            xs.push(v);
            v
        });
        let mut ys = Vec::new();
        let mut renamed = y.clone();
        renamed.map_values(&mut |v| {
            let at = xs.get(ys.len()).copied().unwrap_or(v);
            ys.push(v);
            at
        });
        renamed == *x
            && xs.len() == ys.len()
            && xs.iter().zip(&ys).all(|(&p, &q)| self.same(p, q, depth))
    }
}

/// How many operations deep [`Propagation::idiom`] looks for one value read
/// twice.
const SAME_DEPTH: u8 = 3;

/// The pure operation `op` of `operands` (its [`Op::operands`], in
/// order), by L0's own evaluation; `None` for an operation that is not
/// pure, or not of that many operands.
pub(crate) fn evaluate(op: &Op, operands: &[Bitvalue]) -> Option<Bitvalue> {
    Some(match (op, operands) {
        (Op::Unary(unary, _), [a]) => interpret::unary(*unary, *a),
        (Op::Binary(binary, ..), [a, b]) => interpret::binary(*binary, *a, *b),
        (Op::Flag(flag, ..), [a, b, c]) => interpret::flag(*flag, *a, *b, *c),
        (Op::Extract { offset, width, .. }, [a]) => interpret::extract(*a, *offset, *width),
        (Op::Concat { .. }, [high, low]) => interpret::concat(*high, *low),
        (Op::Extend { signed, width, .. }, [a]) => interpret::extend(*signed, *a, *width),
        (Op::Select { .. }, [condition, then, otherwise]) => {
            interpret::select(*condition, *then, *otherwise)
        }
        (Op::Lanes { lanes, op, .. }, values) => interpret::lanes(*op, *lanes, values),
        (
            Op::Float {
                op,
                format,
                lanes,
                output,
                ..
            },
            [rounding, values @ ..],
        ) => interpret::float(*op, *format, *lanes, *output, *rounding, values),
        _ => return None,
    })
}

/// Whether constant `bits` absorbs the other operand of `binary`: 0 for
/// `&`, all ones for `|`.
fn absorbs(binary: Binary, bits: &Bits) -> bool {
    match binary {
        Binary::And => bits.is_zero(),
        Binary::Or => *bits == Bits::ones(bits.width()),
        Binary::Xor
        | Binary::Add
        | Binary::Sub
        | Binary::Mul
        | Binary::UDiv
        | Binary::URem
        | Binary::SDiv
        | Binary::SRem
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
        | Binary::SLe => false,
    }
}
