//! Construction of a [`Function`] from the L0 of its machine instructions.
//!
//! 1. Labels: every block start of the input, and every constant jump
//!    target that is an instruction of the function (a `rep` jumps to
//!    itself, possibly in the middle of a block).
//! 2. Each instruction's L0 statements in order; `if`/`else` and
//!    `loop`/`break` become blocks; a constant jump to a label is a
//!    [`Terminator::Jump`], to anywhere else a [`Terminator::Leave`] (that
//!    returns unless the [`Environment`] knows the code it goes to does
//!    not); a computed jump is a
//!    [`Terminator::IndirectJump`] to the targets the [`Environment`]
//!    knows; control falls through to the next instruction.
//! 3. SSA after Braun et al. 2013 ("Simple and Efficient Construction of
//!    Static Single Assignment Form"): definitions per block; a variable a
//!    block reads before defining is a block parameter, given its
//!    arguments by a worklist once the code is built (no recursion: block
//!    chains are as long as functions); then trivial parameters (one
//!    value, or only themselves) removed.

use alloc::boxed::Box;
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt;

use binbun_semantics::Semantics;
use binbun_semantics::bits::Bits;
use binbun_semantics::ir::{
    Binary, Declarations, Expr, ExprId, IntrinsicId, Local, RegisterId, Stmt, View,
};

use crate::groups::Groups;
use crate::ir::{
    Block, BlockId, Definition, Function, Inst, InstId, Op, State, Target, Terminator, Type,
    Unknown, Value, ValueInfo,
};

/// One machine instruction of the function.
#[derive(Clone, Debug)]
pub struct Instruction {
    /// Its address.
    pub address: u64,
    /// The address after it.
    pub next: u64,
    /// What it does.
    pub semantics: Semantics,
}

/// A function's code as recovery found it: its blocks, each a run of
/// instructions, and its entry.
#[derive(Clone, Debug, Default)]
pub struct Code {
    /// The entry address (the first instruction of one of the blocks).
    pub entry: u64,
    /// The blocks; the order does not matter.
    pub blocks: Vec<Vec<Instruction>>,
}

/// What a call (or system call) does to the caller's state.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CallEffect {
    /// The registers it may change (each gets a new, unknown value).
    pub changes: Vec<RegisterId>,
    /// Registers of `changes` whose low bits it keeps, with how many: only
    /// the bits above get a new value (the callee keeps the low 64 bits of
    /// AAPCS64's `v8`–`v15`, the low 128 of Microsoft x64's
    /// `zmm6`–`zmm15`, and may change the rest).
    pub kept_low: Vec<(RegisterId, u16)>,
    /// Registers it leaves with a known value (after `changes`).
    pub known: Vec<(RegisterId, Bits)>,
    /// The stack pointer and what the call adds to it, from the call to the
    /// return (x86-64: 8, the popped return address).
    pub stack: Option<(RegisterId, i64)>,
    /// Whether it returns.
    pub returns: bool,
}

/// Where an exception unwinding through a call goes, and the state the
/// unwinder hands the code there (a call site of an exception table).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Unwind {
    /// The landing pad: an instruction of the function.
    pub pad: u64,
    /// The registers the unwinder restores to their value at the call (the
    /// convention's callee-saved ones).
    pub kept: Vec<RegisterId>,
    /// The stack pointer and what to add to its value at the call to get
    /// the caller's, as the unwinder restores it (x86-64: 8, the return
    /// address the call pushed; AArch64: 0).
    pub stack: Option<(RegisterId, i64)>,
    /// The registers the landing pad receives values in, in order (the
    /// Itanium C++ ABI's exception object and selector).
    pub receives: Vec<RegisterId>,
    /// Registers the landing pad receives as another register's value at
    /// the function's entry plus a constant: (register, the other, the
    /// constant). Microsoft x64 hands a funclet the establisher frame in
    /// `rdx`, the stack pointer after the function's prologue.
    pub frames: Vec<(RegisterId, RegisterId, i64)>,
    /// Where the pad goes when the runtime itself chooses among handlers
    /// (a Microsoft x64 C++ try's catch blocks): to the code at the
    /// address paired with the value of the last register it
    /// [`receives`](Self::receives) (the selector); with none of these
    /// values, to the pad, or where [`resume`](Self::resume) says.
    pub choices: Vec<(u64, u64)>,
    /// With none of the [`choices`](Self::choices) taken, unwinding goes
    /// on (rather than at the pad).
    pub resume: Option<Resume>,
}

/// Unwinding going on from code of the function: the runtime's, after a
/// handler that does not take the exception (Microsoft x64: an unwind
/// funclet's or termination handler's return, a try none of whose catch
/// blocks matches). L1 makes it a call to the runtime that does not
/// return, through which the exception unwinds as [`unwind`](Self::unwind)
/// says.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Resume {
    /// The runtime routine the call goes to (Microsoft x64: the function's
    /// exception handler).
    pub runtime: u64,
    /// Where unwinding goes on: a landing pad of the function, else out of
    /// it.
    pub unwind: Option<Box<Unwind>>,
}

/// What the return of a funclet built into the function (code the runtime
/// calls with the function's frame: Microsoft x64) does.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FuncletReturn {
    /// The runtime goes on unwinding (an unwind funclet's, a termination
    /// handler's return).
    Resume(Resume),
    /// The runtime goes on at the code of the function whose address is
    /// in `register` (a catch block's return value, its continuation), one
    /// of `targets`: a jump there (one target) or a computed jump.
    Continue {
        /// The register.
        register: RegisterId,
        /// The addresses it may hold.
        targets: Vec<u64>,
        /// Registers the runtime sets there as another register's value at
        /// the function's entry plus a constant, as [`Unwind::frames`]
        /// (Microsoft x64: the stack pointer, the establisher frame).
        frames: Vec<(RegisterId, RegisterId, i64)>,
    },
}

/// What construction asks about the code around the function.
pub trait Environment {
    /// What the call at `site` (to `target`, if constant) does.
    fn call(&self, site: u64, target: Option<u64>) -> CallEffect;
    /// What the system call at `site` does.
    fn system_call(&self, site: u64) -> CallEffect;
    /// Where the computed jump at `site` is known to go.
    fn jump_targets(&self, site: u64) -> Vec<u64>;
    /// Whether control may come back to the function's caller from the
    /// code at `target` outside the function, which a jump (or falling off
    /// the function's code) goes to: `false` where that code is known never
    /// to return, as for a call's [`CallEffect::returns`].
    fn jump_returns(&self, target: u64) -> bool;
    /// Whether the computed jump at `site` leaves the function for code
    /// outside it (an import, through its slot) rather than going to code
    /// of its own: `Some(returns)`, whether control may come back to the
    /// caller from there, as for [`jump_returns`](Self::jump_returns). The
    /// jump is then a [`Terminator::Leave`] to the address it computes.
    /// None by default (a computed jump goes where
    /// [`jump_targets`](Self::jump_targets) says).
    fn jump_leaves(&self, site: u64) -> Option<bool> {
        let _ = site;
        None
    }
    /// Where an exception unwinding through the call that returns to
    /// `return_address` goes, if to a landing pad of the function: the
    /// call then ends its block in a [`Terminator::Invoke`]. None by
    /// default (exceptions are not followed).
    fn unwind(&self, return_address: u64) -> Option<Unwind> {
        let _ = return_address;
        None
    }
    /// Addresses in the code that control reaches other than by its own
    /// jumps (a catch block's continuation): each starts a block. None by
    /// default.
    fn labels(&self) -> Vec<u64> {
        Vec::new()
    }
    /// The entry of the funclet built into the function that `site` is in
    /// and what a return (or tail jump: a call, then the return) there
    /// does, rather than return from the function. None by default.
    fn funclet_return(&self, site: u64) -> Option<(u64, FuncletReturn)> {
        let _ = site;
        None
    }
    /// The funclets built into the function: each one's entry (an
    /// instruction of the code) and the registers it keeps by the calling
    /// convention, which hold at its returns what they held at its entry.
    /// None by default.
    fn funclets(&self) -> Vec<(u64, Vec<RegisterId>)> {
        Vec::new()
    }
}

/// A reason the code cannot be built.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BuildError(pub String);

impl fmt::Display for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Builds `code` (registers and intrinsics of `declarations`) in SSA form.
///
/// # Errors
///
/// The entry is no instruction of the code, or an instruction's semantics
/// are malformed (use a local or expression they do not define).
pub fn build(
    code: &Code,
    declarations: &Declarations,
    environment: &dyn Environment,
) -> Result<Function, BuildError> {
    let mut builder = Builder::new(code, declarations, environment)?;
    for instructions in &code.blocks {
        for (i, instruction) in instructions.iter().enumerate() {
            let last = i + 1 == instructions.len();
            builder.instruction(instruction, last)?;
        }
    }
    builder.finish()
}

/// A variable: a full register or the memory.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Var {
    Register(RegisterId),
    Memory,
}

struct Builder<'a> {
    declarations: &'a Declarations,
    environment: &'a dyn Environment,
    f: Function,
    /// The block of each label (an instruction where a block starts).
    labels: BTreeMap<u64, BlockId>,
    /// The current definition of each variable at the end of each block:
    /// per block, per variable ([`Self::slot`]), one row per block.
    defs: Vec<Option<Value>>,
    /// Parameters still without arguments: block, variable, parameter.
    pending: Vec<(BlockId, Var, Value)>,
    /// The register each block parameter made for one is of, recorded as
    /// held once the parameters left are known ([`Self::compact`]): most
    /// are removed, and a map entry each is the cost.
    parameter_held: Vec<(Value, RegisterId)>,
    /// Each block's predecessors: the block and which of its targets.
    preds: Vec<Vec<(BlockId, usize)>>,
    /// Removed parameters and what replaces them, per value.
    replaced: Vec<Option<Value>>,
    /// The block being built; `None` where control cannot reach.
    current: Option<BlockId>,
    /// The machine instruction being built.
    address: u64,
    /// The address after it.
    next: u64,
    /// The register each undefined value of the instruction being built
    /// is written to, if one ([`written_undefined`]).
    undefined_registers: BTreeMap<ExprId, RegisterId>,
    /// The block where exceptions unwinding to each landing pad enter, by
    /// the pad's address: an [`Op::Landing`], then a jump to the pad's
    /// label.
    landings: BTreeMap<u64, BlockId>,
    /// What each block ending in an invoke passes on its unwind edge: the
    /// variables the unwinder restores, with their values at the call.
    unwound: BTreeMap<BlockId, Vec<(Var, Value)>>,
    /// Each register's value at the function's entry (the entry block's
    /// parameters).
    entry_values: Vec<Value>,
    /// The registers each funclet built in keeps, with their values at its
    /// entry (its entry block's parameters), by its entry.
    funclet_kept: BTreeMap<u64, Vec<(RegisterId, Value)>>,
    /// Per instruction: values of its expressions and locals.
    exprs: Vec<Option<Value>>,
    locals: Vec<Option<Value>>,
    /// Expressions given values in each open `if`/`loop` scope (forgotten
    /// when it closes: those values do not reach past it).
    scopes: Vec<Vec<ExprId>>,
    /// The exit block of each open loop, made when a `break` needs it.
    loops: Vec<Option<BlockId>>,
    atomic: Option<u32>,
    next_atomic: u32,
}

impl<'a> Builder<'a> {
    fn new(
        code: &Code,
        declarations: &'a Declarations,
        environment: &'a dyn Environment,
    ) -> Result<Self, BuildError> {
        let mut b = Builder {
            declarations,
            environment,
            f: Function {
                entry: code.entry,
                ..Function::default()
            },
            labels: BTreeMap::new(),
            defs: Vec::new(),
            pending: Vec::new(),
            parameter_held: Vec::new(),
            preds: Vec::new(),
            replaced: Vec::new(),
            current: None,
            address: code.entry,
            next: code.entry,
            undefined_registers: BTreeMap::new(),
            landings: BTreeMap::new(),
            unwound: BTreeMap::new(),
            entry_values: Vec::new(),
            funclet_kept: BTreeMap::new(),
            exprs: Vec::new(),
            locals: Vec::new(),
            scopes: Vec::new(),
            loops: Vec::new(),
            atomic: None,
            next_atomic: 0,
        };
        // The entry block: a parameter per register, then the memory.
        let entry = b.new_block(code.entry);
        for index in 0..declarations.registers.len() {
            let register = RegisterId(u16::try_from(index).unwrap_or(u16::MAX));
            let ty = b.var_type(Var::Register(register));
            let value = b.add_parameter(entry, ty);
            b.set_def(Var::Register(register), entry, value);
            b.f.held.insert(value, register);
            b.entry_values.push(value);
        }
        let memory = b.add_parameter(entry, Type::Memory);
        b.set_def(Var::Memory, entry, memory);
        // Labels: block starts, and constant jump targets among the
        // instructions.
        let addresses: BTreeSet<u64> = code
            .blocks
            .iter()
            .flatten()
            .map(|instruction| instruction.address)
            .collect();
        let mut starts: Vec<u64> = code
            .blocks
            .iter()
            .filter_map(|instructions| instructions.first())
            .map(|instruction| instruction.address)
            .collect();
        for instruction in code.blocks.iter().flatten() {
            jump_targets(
                &instruction.semantics,
                &instruction.semantics.body,
                &mut starts,
            );
        }
        starts.extend(environment.labels());
        for address in starts {
            if addresses.contains(&address) && !b.labels.contains_key(&address) {
                let block = b.new_block(address);
                b.labels.insert(address, block);
            }
        }
        for (funclet, kept) in environment.funclets() {
            let Some(&label) = b.labels.get(&funclet) else {
                continue;
            };
            let values = kept
                .into_iter()
                .map(|register| (register, b.read_var_in(Var::Register(register), label)))
                .collect();
            b.funclet_kept.insert(funclet, values);
        }
        let Some(&first) = b.labels.get(&code.entry) else {
            return Err(BuildError(format!(
                "the entry {:#x} is no instruction of the code",
                code.entry
            )));
        };
        b.current = Some(entry);
        let arguments = Vec::new();
        b.terminate(Terminator::Jump(Target {
            block: first,
            arguments,
        }));
        Ok(b)
    }

    // ---- Blocks, values, instructions -------------------------------

    fn new_block(&mut self, address: u64) -> BlockId {
        let id = BlockId(u32::try_from(self.f.blocks.len()).unwrap_or(u32::MAX));
        self.f.blocks.push(Block {
            address,
            end: address,
            parameters: Vec::new(),
            insts: Vec::new(),
            terminator: Terminator::Open,
        });
        self.preds.push(Vec::new());
        let row = self.defs.len() + self.declarations.registers.len() + 1;
        self.defs.resize(row, None);
        id
    }

    fn new_value(&mut self, ty: Type, definition: Definition) -> Value {
        let id = Value(u32::try_from(self.f.values.len()).unwrap_or(u32::MAX));
        self.f.values.push(ValueInfo { ty, definition });
        id
    }

    fn add_parameter(&mut self, block: BlockId, ty: Type) -> Value {
        let index = self
            .f
            .blocks
            .get(block.0 as usize)
            .map_or(0, |b| b.parameters.len());
        let value = self.new_value(
            ty,
            Definition::Parameter {
                block,
                index: u32::try_from(index).unwrap_or(u32::MAX),
            },
        );
        if let Some(b) = self.f.blocks.get_mut(block.0 as usize) {
            b.parameters.push(value);
        }
        value
    }

    /// Appends an instruction to `block`; returns its results.
    fn inst_in(&mut self, block: BlockId, op: Op, types: &[Type]) -> Vec<Value> {
        let id = InstId(u32::try_from(self.f.insts.len()).unwrap_or(u32::MAX));
        let results: Vec<Value> = types
            .iter()
            .enumerate()
            .map(|(index, &ty)| {
                self.new_value(
                    ty,
                    Definition::Result {
                        inst: id,
                        index: u32::try_from(index).unwrap_or(u32::MAX),
                    },
                )
            })
            .collect();
        self.f.insts.push(Inst {
            op,
            results: results.clone(),
            address: self.address,
        });
        if let Some(b) = self.f.blocks.get_mut(block.0 as usize) {
            b.insts.push(id);
        }
        results
    }

    /// An instruction in the current block with one result of type `ty`.
    fn inst(&mut self, op: Op, ty: Type) -> Value {
        let block = self.current.unwrap_or(BlockId(0));
        // As `inst_in`, without a second list of results.
        let id = InstId(u32::try_from(self.f.insts.len()).unwrap_or(u32::MAX));
        let result = self.new_value(ty, Definition::Result { inst: id, index: 0 });
        self.f.insts.push(Inst {
            op,
            results: vec![result],
            address: self.address,
        });
        if let Some(b) = self.f.blocks.get_mut(block.0 as usize) {
            b.insts.push(id);
        }
        result
    }

    fn constant(&mut self, width: u16, value: u64) -> Value {
        self.inst(Op::Const(Bits::from_u64(width, value)), Type::Bits(width))
    }

    fn width(&self, value: Value) -> u16 {
        match self.f.ty(value) {
            Some(Type::Bits(width)) => width,
            Some(Type::Memory) | None => 0,
        }
    }

    /// Ends the current block with `terminator`; control does not go on.
    fn terminate(&mut self, terminator: Terminator) {
        let Some(block) = self.current.take() else {
            return;
        };
        for (index, target) in terminator.targets().enumerate() {
            if let Some(preds) = self.preds.get_mut(target.block.0 as usize) {
                preds.push((block, index));
            }
        }
        if let Some(b) = self.f.blocks.get_mut(block.0 as usize) {
            b.terminator = terminator;
            b.end = self.address;
        }
    }

    fn jump(&mut self, block: BlockId) {
        self.terminate(Terminator::Jump(Target {
            block,
            arguments: Vec::new(),
        }));
    }

    // ---- Variables (Braun et al.) -------------------------------------

    fn var_type(&self, var: Var) -> Type {
        match var {
            Var::Register(register) => Type::Bits(
                self.declarations
                    .info(register)
                    .map_or(64, |info| info.width),
            ),
            Var::Memory => Type::Memory,
        }
    }

    fn find(&self, mut value: Value) -> Value {
        while let Some(next) = self.replaced.get(value.0 as usize).copied().flatten() {
            value = next;
        }
        value
    }

    /// The number of `var` among a block's definitions: registers in order,
    /// then the memory.
    fn slot(&self, var: Var) -> usize {
        match var {
            Var::Register(register) => register.0 as usize,
            Var::Memory => self.declarations.registers.len(),
        }
    }

    /// Where `var`'s definition at the end of `block` is in `defs`.
    fn def_index(&self, var: Var, block: BlockId) -> usize {
        (block.0 as usize) * (self.declarations.registers.len() + 1) + self.slot(var)
    }

    fn def(&self, var: Var, block: BlockId) -> Option<Value> {
        self.defs.get(self.def_index(var, block)).copied().flatten()
    }

    fn set_def(&mut self, var: Var, block: BlockId, value: Value) {
        let index = self.def_index(var, block);
        if let Some(entry) = self.defs.get_mut(index) {
            *entry = Some(value);
        }
    }

    fn write_var(&mut self, var: Var, value: Value) {
        if let Some(block) = self.current {
            self.set_def(var, block, value);
        }
        if let Var::Register(register) = var {
            self.hold(value, register);
        }
    }

    /// Records `value` as held in `register` (unless it was held in one
    /// before), and so what it extends: a load `movzx` or `movsd`
    /// zero-extends is held where its extension is.
    fn hold(&mut self, value: Value, register: RegisterId) {
        self.f.held.entry(value).or_insert(register);
        let extended = match self.f.value(value).map(|info| info.definition) {
            Some(Definition::Result { inst, .. }) => match self.f.inst(inst).map(|i| &i.op) {
                Some(&Op::Extend { value: inner, .. }) => Some(inner),
                _ => None,
            },
            Some(Definition::Parameter { .. }) | None => None,
        };
        if let Some(inner) = extended {
            self.f.held.entry(inner).or_insert(register);
        }
    }

    fn read_var(&mut self, var: Var) -> Value {
        let block = self.current.unwrap_or(BlockId(0));
        self.read_var_in(var, block)
    }

    /// `var`'s value at the end of `block` so far: its definition there,
    /// else a new parameter of the block, given its arguments once the code
    /// is built ([`Self::fill`]).
    fn read_var_in(&mut self, var: Var, block: BlockId) -> Value {
        if let Some(value) = self.def(var, block) {
            return self.find(value);
        }
        let ty = self.var_type(var);
        let parameter = self.add_parameter(block, ty);
        self.set_def(var, block, parameter);
        if let Var::Register(register) = var {
            self.parameter_held.push((parameter, register));
        }
        self.pending.push((block, var, parameter));
        parameter
    }

    /// Gives every parameter its arguments: from each predecessor, the
    /// variable's value at its end (a new parameter there if it has none,
    /// filled in turn). A worklist, not recursion: chains of blocks are as
    /// long as functions are.
    fn fill(&mut self) {
        // No value: a position no argument came for yet.
        const NONE: Value = Value(u32::MAX);
        // Edges are numbered by predecessor, then target position: the
        // first number of each block's edges.
        let mut first_edge = Vec::with_capacity(self.f.blocks.len());
        let mut edges = 0;
        for block in &self.f.blocks {
            first_edge.push(edges);
            edges += block.terminator.targets().count();
        }
        // Per edge: by parameter position (`NONE` where none came yet).
        let mut arguments: Vec<Vec<Value>> = vec![Vec::new(); edges];
        // Reading variables adds no blocks or edges.
        let preds = core::mem::take(&mut self.preds);
        while let Some((block, var, parameter)) = self.pending.pop() {
            let Some(Definition::Parameter { index, .. }) =
                self.f.value(parameter).map(|info| info.definition)
            else {
                continue;
            };
            let index = index as usize;
            for &(pred, edge) in preds.get(block.0 as usize).map_or(&[][..], Vec::as_slice) {
                let value = self
                    .unwound_value(pred, edge, var)
                    .unwrap_or_else(|| self.read_var_in(var, pred));
                let Some(list) = first_edge
                    .get(pred.0 as usize)
                    .and_then(|&first| arguments.get_mut(first + edge))
                else {
                    continue;
                };
                if list.len() <= index {
                    list.resize(index + 1, NONE);
                }
                if let Some(slot) = list.get_mut(index) {
                    *slot = value;
                }
            }
        }
        self.preds = preds;
        for (block, first) in self.f.blocks.iter_mut().zip(first_edge) {
            let lists = arguments.get_mut(first..).unwrap_or_default();
            for (target, list) in block.terminator.targets_mut().zip(lists) {
                if !list.is_empty() {
                    list.retain(|&value| value != NONE);
                    target.arguments = core::mem::take(list);
                }
            }
        }
    }

    /// The value `var` has on edge `edge` of `pred` if that is the unwind
    /// edge of an invoke (the state the unwinder restores), else `None`.
    fn unwound_value(&self, pred: BlockId, edge: usize, var: Var) -> Option<Value> {
        let invoke = matches!(
            self.f.block(pred).map(|b| &b.terminator),
            Some(Terminator::Invoke { .. })
        );
        if !invoke || edge != 1 {
            return None;
        }
        let (_, value) = self.unwound.get(&pred)?.iter().find(|(v, _)| *v == var)?;
        Some(self.find(*value))
    }

    // ---- Statements ---------------------------------------------------

    fn instruction(&mut self, instruction: &Instruction, last: bool) -> Result<(), BuildError> {
        if let Some(&label) = self.labels.get(&instruction.address) {
            if self.current.is_some() {
                // Falls through from the instruction before.
                self.jump(label);
            }
            self.current = Some(label);
        } else if self.current.is_none() {
            // After an instruction that does not go on, within one block:
            // unreachable, but built.
            let block = self.new_block(instruction.address);
            self.current = Some(block);
        }
        self.address = instruction.address;
        self.next = instruction.next;
        let semantics = &instruction.semantics;
        self.exprs.clear();
        self.exprs.resize(semantics.exprs.len(), None);
        self.locals.clear();
        self.locals.resize(semantics.locals.len(), None);
        self.undefined_registers = written_undefined(semantics);
        self.scopes.clear();
        self.loops.clear();
        self.atomic = None;
        // A funclet's return: not its semantics (which load and check the
        // address it returns to, the runtime's), but its pop (what a call's
        // return pops) and where the environment says it goes.
        if returns(&semantics.body)
            && let Some((funclet, resumed)) = self.environment.funclet_return(self.address)
        {
            if let Some((register, delta)) = self.environment.call(self.address, None).stack {
                let stack = self.read_var(Var::Register(register));
                let stack = self.offset(stack, delta);
                self.write_var(Var::Register(register), stack);
            }
            self.funclet_return(funclet, &resumed);
            return Ok(());
        }
        self.statements(semantics, &semantics.body)?;
        if self.current.is_some() {
            if let Some(&label) = self.labels.get(&instruction.next) {
                self.jump(label);
            } else if last {
                // Falls off the function's code (into another function).
                let address = self.constant(64, instruction.next);
                self.leave(instruction.next, address);
            }
        }
        Ok(())
    }

    fn statements(&mut self, s: &Semantics, statements: &[Stmt]) -> Result<(), BuildError> {
        for statement in statements {
            if self.current.is_none() {
                break;
            }
            self.statement(s, statement)?;
        }
        Ok(())
    }

    fn statement(&mut self, s: &Semantics, statement: &Stmt) -> Result<(), BuildError> {
        match statement {
            Stmt::Read { local, view } => {
                let value = self.read_view(*view);
                self.set_local(*local, value)?;
            }
            Stmt::Write { view, value } => {
                let value = self.expr(s, *value)?;
                self.write_view(*view, value);
            }
            Stmt::Load {
                local,
                address,
                bytes,
            } => self.load(s, *local, *address, *bytes)?,
            Stmt::Store { address, value } => {
                let address = self.expr(s, *address)?;
                let value = self.expr(s, *value)?;
                let memory = self.read_var(Var::Memory);
                let memory = self.inst(
                    Op::Store {
                        memory,
                        address,
                        value,
                        atomic: self.atomic,
                    },
                    Type::Memory,
                );
                self.write_var(Var::Memory, memory);
            }
            Stmt::If {
                condition,
                then,
                otherwise,
            } => self.if_statement(s, *condition, then, otherwise)?,
            Stmt::Loop(body) => self.loop_statement(s, body)?,
            Stmt::Break => {
                let exit = if let Some(exit) = self.loops.last().copied().flatten() {
                    exit
                } else {
                    let exit = self.new_block(self.address);
                    if let Some(slot) = self.loops.last_mut() {
                        *slot = Some(exit);
                    }
                    exit
                };
                self.jump(exit);
            }
            Stmt::Atomic(body) => {
                let outer = self.atomic;
                self.atomic = Some(self.next_atomic);
                self.next_atomic += 1;
                self.statements(s, body)?;
                self.atomic = outer;
            }
            Stmt::SystemCall => {
                let effect = self.environment.system_call(self.address);
                let memory = self.read_var(Var::Memory);
                let registers = self.registers();
                let op = Op::SystemCall {
                    memory,
                    registers,
                    changes: effect.changes.clone(),
                };
                self.effect(op, &effect);
            }
            Stmt::Intrinsic {
                intrinsic,
                inputs,
                outputs,
            } => self.intrinsic(s, *intrinsic, inputs, outputs)?,
            Stmt::Trap(trap) => self.terminate(Terminator::Trap(*trap)),
            Stmt::Jump { target } => self.jump_statement(s, *target)?,
            Stmt::Call {
                target,
                return_address,
            } => self.call(s, *target, *return_address)?,
            Stmt::Return { target } => {
                let address = self.expr(s, *target)?;
                let state = self.state();
                self.terminate(Terminator::Return { address, state });
            }
        }
        Ok(())
    }

    fn load(
        &mut self,
        s: &Semantics,
        local: Local,
        address: ExprId,
        bytes: u16,
    ) -> Result<(), BuildError> {
        let address = self.expr(s, address)?;
        let memory = self.read_var(Var::Memory);
        let value = self.inst(
            Op::Load {
                memory,
                address,
                bytes,
                atomic: self.atomic,
            },
            Type::Bits(bytes.saturating_mul(8)),
        );
        self.set_local(local, value)
    }

    fn loop_statement(&mut self, s: &Semantics, body: &[Stmt]) -> Result<(), BuildError> {
        let header = self.new_block(self.address);
        self.jump(header);
        self.current = Some(header);
        self.loops.push(None);
        self.scopes.push(Vec::new());
        self.statements(s, body)?;
        self.close_scope();
        if self.current.is_some() {
            self.jump(header);
        }
        self.current = self.loops.pop().flatten();
        Ok(())
    }

    fn intrinsic(
        &mut self,
        s: &Semantics,
        intrinsic: IntrinsicId,
        inputs: &[ExprId],
        outputs: &[Local],
    ) -> Result<(), BuildError> {
        let inputs = inputs
            .iter()
            .map(|&input| self.expr(s, input))
            .collect::<Result<Vec<_>, _>>()?;
        let memory = self.read_var(Var::Memory);
        let mut types: Vec<Type> = outputs
            .iter()
            .map(|local| Type::Bits(s.locals.get(local.0 as usize).copied().unwrap_or(0)))
            .collect();
        types.push(Type::Memory);
        let block = self.current.unwrap_or(BlockId(0));
        let op = Op::Intrinsic {
            intrinsic,
            memory,
            inputs,
        };
        let results = self.inst_in(block, op, &types);
        for (local, &value) in outputs.iter().zip(&results) {
            self.set_local(*local, value)?;
        }
        if let Some(&memory) = results.last() {
            self.write_var(Var::Memory, memory);
        }
        Ok(())
    }

    fn jump_statement(&mut self, s: &Semantics, target: ExprId) -> Result<(), BuildError> {
        let constant = constant_of(s, target);
        let address = self.expr(s, target)?;
        if let Some(to) = constant {
            self.jump_to(to, address);
        } else if let Some(returns) = self.environment.jump_leaves(self.address) {
            if self.funclet_tail_call(None, address) {
                return Ok(());
            }
            let state = self.state();
            self.terminate(Terminator::Leave {
                address,
                state,
                returns,
            });
        } else {
            let targets = self
                .environment
                .jump_targets(self.address)
                .into_iter()
                .filter_map(|to| self.labels.get(&to).copied())
                .map(|block| Target {
                    block,
                    arguments: Vec::new(),
                })
                .collect();
            self.terminate(Terminator::IndirectJump { address, targets });
        }
        Ok(())
    }

    fn call(
        &mut self,
        s: &Semantics,
        target: ExprId,
        return_address: ExprId,
    ) -> Result<(), BuildError> {
        let constant = constant_of(s, target);
        let target = self.expr(s, target)?;
        let return_address = self.expr(s, return_address)?;
        let effect = self.environment.call(self.address, constant);
        let memory = self.read_var(Var::Memory);
        let registers = self.registers();
        let landing = self
            .environment
            .unwind(self.next)
            .and_then(|unwind| Some((self.landing(&unwind)?, unwind)));
        let op = Op::Call {
            target,
            return_address,
            memory,
            registers,
            changes: effect.changes.clone(),
        };
        if let Some((landing, unwind)) = landing {
            self.invoke(op, &effect, landing, &unwind);
        } else {
            self.effect(op, &effect);
        }
        if !effect.returns {
            self.terminate(Terminator::Stop);
        }
        Ok(())
    }

    /// The block exceptions unwinding to `unwind`'s landing pad enter
    /// (made on first use), if the pad is an instruction of the function:
    /// an [`Op::Landing`] giving the memory and the registers the pad
    /// receives, every other register but the kept ones and the stack
    /// pointer undefined, then a jump to the pad.
    fn landing(&mut self, unwind: &Unwind) -> Option<BlockId> {
        if let Some(&block) = self.landings.get(&unwind.pad) {
            return Some(block);
        }
        let &label = self.labels.get(&unwind.pad)?;
        let (current, address) = (self.current, self.address);
        let block = self.new_block(unwind.pad);
        self.landings.insert(unwind.pad, block);
        self.current = Some(block);
        self.address = unwind.pad;
        let memory = self.read_var(Var::Memory);
        let mut types = vec![Type::Memory];
        types.extend(
            unwind
                .receives
                .iter()
                .map(|&register| self.var_type(Var::Register(register))),
        );
        let op = Op::Landing {
            memory,
            receives: unwind.receives.clone(),
        };
        let results = self.inst_in(block, op, &types);
        let mut results = results.into_iter();
        if let Some(memory) = results.next() {
            self.write_var(Var::Memory, memory);
        }
        for (&register, value) in unwind.receives.iter().zip(results) {
            self.write_var(Var::Register(register), value);
        }
        for &(register, base, offset) in &unwind.frames {
            if let Some(&value) = self.entry_values.get(usize::from(base.0)) {
                let value = self.offset(value, offset);
                self.write_var(Var::Register(register), value);
            }
        }
        let stack = unwind.stack.map(|(register, _)| register);
        for index in 0..self.declarations.registers.len() {
            let register = RegisterId(u16::try_from(index).unwrap_or(u16::MAX));
            if unwind.kept.contains(&register)
                || unwind.receives.contains(&register)
                || unwind.frames.iter().any(|&(frame, _, _)| frame == register)
                || stack == Some(register)
            {
                continue;
            }
            let ty = self.var_type(Var::Register(register));
            let value = self.inst(Op::Undefined(Unknown::Landing, Vec::new()), ty);
            self.write_var(Var::Register(register), value);
        }
        self.choose(unwind, label);
        self.current = current;
        self.address = address;
        Some(block)
    }

    /// The end of the landing block of `unwind`: a jump to the pad
    /// (`label`), or the runtime's choice among its
    /// [`choices`](Unwind::choices) by the selector, a branch per choice,
    /// then the pad or the [`resume`](Unwind::resume).
    fn choose(&mut self, unwind: &Unwind, label: BlockId) {
        if let Some(&selector) = unwind.receives.last()
            && !unwind.choices.is_empty()
        {
            let selector = self.read_var(Var::Register(selector));
            let width = self.width(selector);
            for &(value, address) in &unwind.choices {
                let Some(&then) = self.labels.get(&address) else {
                    continue;
                };
                let constant = self.constant(width, value);
                let condition =
                    self.inst(Op::Binary(Binary::Eq, selector, constant), Type::Bits(1));
                let otherwise = self.new_block(unwind.pad);
                self.terminate(Terminator::Branch {
                    condition,
                    then: Target {
                        block: then,
                        arguments: Vec::new(),
                    },
                    otherwise: Target {
                        block: otherwise,
                        arguments: Vec::new(),
                    },
                });
                self.current = Some(otherwise);
            }
        }
        match &unwind.resume {
            Some(resume) if !unwind.choices.is_empty() => self.resume(resume),
            Some(_) | None => self.jump(label),
        }
    }

    /// Unwinding goes on ([`Resume`]): a call to the runtime that does not
    /// return, an invoke if the exception unwinds to a landing pad of the
    /// function.
    fn resume(&mut self, resume: &Resume) {
        let target = self.constant(64, resume.runtime);
        let return_address = self.constant(64, self.next);
        let effect = CallEffect {
            returns: false,
            ..self.environment.call(self.address, Some(resume.runtime))
        };
        let memory = self.read_var(Var::Memory);
        let registers = self.registers();
        let op = Op::Call {
            target,
            return_address,
            memory,
            registers,
            changes: effect.changes.clone(),
        };
        let landing = resume
            .unwind
            .as_deref()
            .and_then(|unwind| Some((self.landing(unwind)?, unwind)));
        if let Some((landing, unwind)) = landing {
            self.invoke(op, &effect, landing, unwind);
        } else {
            self.effect(op, &effect);
        }
        self.terminate(Terminator::Stop);
    }

    /// The return of a funclet built into the function
    /// ([`Environment::funclet_return`]) whose entry is `funclet`: the
    /// registers it keeps hold their values at its entry.
    fn funclet_return(&mut self, funclet: u64, resumed: &FuncletReturn) {
        if let Some(kept) = self.funclet_kept.get(&funclet).cloned() {
            for (register, value) in kept {
                self.write_var(Var::Register(register), value);
            }
        }
        match resumed {
            FuncletReturn::Resume(resume) => self.resume(resume),
            FuncletReturn::Continue {
                register,
                targets,
                frames,
            } => {
                let address = self.read_var(Var::Register(*register));
                for &(register, base, offset) in frames {
                    if let Some(&value) = self.entry_values.get(usize::from(base.0)) {
                        let value = self.offset(value, offset);
                        self.write_var(Var::Register(register), value);
                    }
                }
                let targets: Vec<BlockId> = targets
                    .iter()
                    .filter_map(|to| self.labels.get(to).copied())
                    .collect();
                match targets.as_slice() {
                    &[target] => self.jump(target),
                    _ => self.terminate(Terminator::IndirectJump {
                        address,
                        targets: targets
                            .into_iter()
                            .map(|block| Target {
                                block,
                                arguments: Vec::new(),
                            })
                            .collect(),
                    }),
                }
            }
        }
    }

    /// A jump out of the function (to `to`, if constant; `address` its
    /// value) from a funclet built into it: a tail call, whose callee
    /// returns where the funclet would ([`Self::funclet_return`]). Whether
    /// the jump was one.
    fn funclet_tail_call(&mut self, to: Option<u64>, address: Value) -> bool {
        let Some((funclet, resumed)) = self.environment.funclet_return(self.address) else {
            return false;
        };
        let effect = self.environment.call(self.address, to);
        let return_address = self.constant(64, self.next);
        let memory = self.read_var(Var::Memory);
        let registers = self.registers();
        let op = Op::Call {
            target: address,
            return_address,
            memory,
            registers,
            changes: effect.changes.clone(),
        };
        self.effect(op, &effect);
        if effect.returns {
            self.funclet_return(funclet, &resumed);
        } else {
            self.terminate(Terminator::Stop);
        }
        true
    }

    /// Adds the call `op` with `effect` as the last instruction of its
    /// block, which ends in a [`Terminator::Invoke`] to a new block (where
    /// building goes on) or to `landing`, whose edge passes the state the
    /// unwinder restores (`unwind`). What the effect computes after the
    /// call (the stack pointer's change, known values) is computed before
    /// it, from the values at the call.
    fn invoke(&mut self, op: Op, effect: &CallEffect, landing: BlockId, unwind: &Unwind) {
        let memory = self.read_var(Var::Memory);
        let low = self.kept_low(effect);
        let mut restored = vec![(Var::Memory, memory)];
        for &register in &unwind.kept {
            restored.push((
                Var::Register(register),
                self.read_var(Var::Register(register)),
            ));
        }
        if let Some((register, delta)) = unwind.stack {
            let before = self.read_var(Var::Register(register));
            let caller = self.offset(before, delta);
            restored.retain(|(var, _)| *var != Var::Register(register));
            restored.push((Var::Register(register), caller));
        }
        let known: Vec<(RegisterId, Value)> = effect
            .known
            .iter()
            .map(|(register, bits)| {
                (
                    *register,
                    self.inst(Op::Const(*bits), Type::Bits(bits.width())),
                )
            })
            .collect();
        let stack = effect.stack.map(|(register, delta)| {
            let before = self.read_var(Var::Register(register));
            (register, self.offset(before, delta))
        });
        let mut types = vec![Type::Memory];
        types.extend(
            effect
                .changes
                .iter()
                .map(|&register| self.var_type(Var::Register(register))),
        );
        let Some(block) = self.current else {
            return;
        };
        let results = self.inst_in(block, op, &types);
        let mut results = results.into_iter();
        if let Some(memory) = results.next() {
            self.write_var(Var::Memory, memory);
        }
        for (&register, value) in effect.changes.iter().zip(results) {
            self.write_var(Var::Register(register), value);
        }
        for (register, value) in known.into_iter().chain(stack) {
            self.write_var(Var::Register(register), value);
        }
        let normal = self.new_block(self.address);
        self.unwound.insert(block, restored);
        self.terminate(Terminator::Invoke {
            normal: Target {
                block: normal,
                arguments: Vec::new(),
            },
            unwind: Target {
                block: landing,
                arguments: Vec::new(),
            },
        });
        self.current = Some(normal);
        // In the normal successor: the invoke ends its block.
        self.keep_low(low);
    }

    /// The low bits of each register a call of `effect` keeps
    /// ([`CallEffect::kept_low`]), as they are before the call.
    fn kept_low(&mut self, effect: &CallEffect) -> Vec<(RegisterId, Value)> {
        effect
            .kept_low
            .iter()
            .filter_map(|&(register, bits)| {
                let before = self.read_var(Var::Register(register));
                (bits < self.width(before)).then(|| {
                    let low = self.inst(
                        Op::Extract {
                            value: before,
                            offset: 0,
                            width: bits,
                        },
                        Type::Bits(bits),
                    );
                    (register, low)
                })
            })
            .collect()
    }

    /// Each register of `low` as the call left its high bits and its low
    /// bits as they were before ([`Self::kept_low`]).
    fn keep_low(&mut self, low: Vec<(RegisterId, Value)>) {
        for (register, low) in low {
            let after = self.read_var(Var::Register(register));
            let (width, bits) = (self.width(after), self.width(low));
            let high = self.inst(
                Op::Extract {
                    value: after,
                    offset: bits,
                    width: width - bits,
                },
                Type::Bits(width - bits),
            );
            let value = self.inst(Op::Concat { high, low }, Type::Bits(width));
            self.write_var(Var::Register(register), value);
        }
    }

    /// `value` plus the constant `delta`, at its width (`value` itself for
    /// 0).
    fn offset(&mut self, value: Value, delta: i64) -> Value {
        if delta == 0 {
            return value;
        }
        let width = self.width(value);
        let delta = self.constant(width, delta.cast_unsigned());
        self.inst(Op::Binary(Binary::Add, value, delta), Type::Bits(width))
    }

    fn if_statement(
        &mut self,
        s: &Semantics,
        condition: ExprId,
        then: &[Stmt],
        otherwise: &[Stmt],
    ) -> Result<(), BuildError> {
        let condition = self.expr(s, condition)?;
        let then_block = self.new_block(self.address);
        let mut join: Option<BlockId> = None;
        let else_block = if otherwise.is_empty() {
            let block = self.new_block(self.address);
            join = Some(block);
            block
        } else {
            self.new_block(self.address)
        };
        self.terminate(Terminator::Branch {
            condition,
            then: Target {
                block: then_block,
                arguments: Vec::new(),
            },
            otherwise: Target {
                block: else_block,
                arguments: Vec::new(),
            },
        });
        for (block, body) in [(then_block, then), (else_block, otherwise)] {
            if join == Some(block) {
                continue;
            }
            self.current = Some(block);
            self.scopes.push(Vec::new());
            self.statements(s, body)?;
            self.close_scope();
            if self.current.is_some() {
                let target = if let Some(join) = join {
                    join
                } else {
                    let block = self.new_block(self.address);
                    join = Some(block);
                    block
                };
                self.jump(target);
            }
        }
        self.current = join;
        Ok(())
    }

    /// A constant jump to `to` (`address` its value): to a label, or out of
    /// the function.
    fn jump_to(&mut self, to: u64, address: Value) {
        if let Some(&label) = self.labels.get(&to) {
            self.jump(label);
        } else {
            self.leave(to, address);
        }
    }

    /// Control leaves the function for the code at `to` (`address` its
    /// value).
    fn leave(&mut self, to: u64, address: Value) {
        if self.funclet_tail_call(Some(to), address) {
            return;
        }
        let state = self.state();
        let returns = self.environment.jump_returns(to);
        self.terminate(Terminator::Leave {
            address,
            state,
            returns,
        });
    }

    /// Adds a call or system call `op` and applies `effect`.
    fn effect(&mut self, op: Op, effect: &CallEffect) {
        let low = self.kept_low(effect);
        let mut types = vec![Type::Memory];
        types.extend(
            effect
                .changes
                .iter()
                .map(|&register| self.var_type(Var::Register(register))),
        );
        let stack_before = effect
            .stack
            .map(|(register, _)| self.read_var(Var::Register(register)));
        let block = self.current.unwrap_or(BlockId(0));
        let results = self.inst_in(block, op, &types);
        let mut results = results.into_iter();
        if let Some(memory) = results.next() {
            self.write_var(Var::Memory, memory);
        }
        for (&register, value) in effect.changes.iter().zip(results) {
            self.write_var(Var::Register(register), value);
        }
        self.keep_low(low);
        for (register, bits) in &effect.known {
            let value = self.inst(Op::Const(*bits), Type::Bits(bits.width()));
            self.write_var(Var::Register(*register), value);
        }
        if let (Some((register, delta)), Some(before)) = (effect.stack, stack_before) {
            let width = self.width(before);
            let delta = self.constant(width, delta.cast_unsigned());
            let after = self.inst(Op::Binary(Binary::Add, before, delta), Type::Bits(width));
            self.write_var(Var::Register(register), after);
        }
    }

    /// Every register's current value, in register order.
    fn registers(&mut self) -> Vec<Value> {
        (0..self.declarations.registers.len())
            .map(|index| {
                let register = RegisterId(u16::try_from(index).unwrap_or(u16::MAX));
                self.read_var(Var::Register(register))
            })
            .collect()
    }

    fn state(&mut self) -> State {
        let registers = self.registers();
        let memory = self.read_var(Var::Memory);
        State { registers, memory }
    }

    fn read_view(&mut self, view: View) -> Value {
        let whole = self.read_var(Var::Register(view.register));
        if view.offset == 0 && view.width == self.width(whole) {
            whole
        } else {
            let part = self.inst(
                Op::Extract {
                    value: whole,
                    offset: view.offset,
                    width: view.width,
                },
                Type::Bits(view.width),
            );
            // The part the code read, held in the register as the whole is.
            self.f.held.entry(part).or_insert(view.register);
            part
        }
    }

    fn write_view(&mut self, view: View, value: Value) {
        let var = Var::Register(view.register);
        let full = match self.var_type(var) {
            Type::Bits(width) => width,
            Type::Memory => 0,
        };
        if view.offset == 0 && view.width == full {
            self.write_var(var, value);
            return;
        }
        // The part the code wrote, held in the register as the whole is.
        self.hold(value, view.register);
        let old = self.read_var(var);
        let top = view.offset.saturating_add(view.width);
        let mut combined = value;
        if view.offset > 0 {
            let low = self.inst(
                Op::Extract {
                    value: old,
                    offset: 0,
                    width: view.offset,
                },
                Type::Bits(view.offset),
            );
            combined = self.inst(
                Op::Concat {
                    high: combined,
                    low,
                },
                Type::Bits(top),
            );
        }
        if top < full {
            let high = self.inst(
                Op::Extract {
                    value: old,
                    offset: top,
                    width: full - top,
                },
                Type::Bits(full - top),
            );
            combined = self.inst(
                Op::Concat {
                    high,
                    low: combined,
                },
                Type::Bits(full),
            );
        }
        self.write_var(var, combined);
    }

    fn set_local(&mut self, local: Local, value: Value) -> Result<(), BuildError> {
        match self.locals.get_mut(local.0 as usize) {
            Some(slot) => {
                *slot = Some(value);
                Ok(())
            }
            None => Err(self.malformed(&format!("no local l{}", local.0))),
        }
    }

    fn malformed(&self, message: &str) -> BuildError {
        BuildError(format!("{:#x}: {message}", self.address))
    }

    fn close_scope(&mut self) {
        for id in self.scopes.pop().unwrap_or_default() {
            if let Some(slot) = self.exprs.get_mut(id.0 as usize) {
                *slot = None;
            }
        }
    }

    /// The instruction of a lane-wise or floating-point expression.
    fn vector(&mut self, s: &Semantics, expr: Expr, ty: Type) -> Result<Value, BuildError> {
        Ok(match expr {
            Expr::Lanes {
                lanes,
                op,
                operands,
            } => {
                let operands = self.operands(s, operands)?;
                self.inst(
                    Op::Lanes {
                        lanes,
                        op,
                        operands,
                    },
                    ty,
                )
            }
            Expr::Float {
                op,
                format,
                lanes,
                output,
                rounding,
                operands,
            } => {
                let rounding = self.expr(s, rounding)?;
                let operands = self.operands(s, operands)?;
                self.inst(
                    Op::Float {
                        op,
                        format,
                        lanes,
                        output,
                        rounding,
                        operands,
                    },
                    ty,
                )
            }
            Expr::Const(_)
            | Expr::Local(_)
            | Expr::Undefined { .. }
            | Expr::Unary(..)
            | Expr::Binary(..)
            | Expr::Flag(..)
            | Expr::Extract { .. }
            | Expr::Concat { .. }
            | Expr::Extend { .. }
            | Expr::Select { .. } => return Err(self.malformed("not a vector expression")),
        })
    }

    /// The values of three operand expressions of `s`.
    fn operands(&mut self, s: &Semantics, ids: [ExprId; 3]) -> Result<[Value; 3], BuildError> {
        let [a, b, c] = ids;
        Ok([self.expr(s, a)?, self.expr(s, b)?, self.expr(s, c)?])
    }

    /// The undefined value `id` (`serial` in `s`) of type `ty`, with its
    /// site's inputs.
    fn undefined(
        &mut self,
        s: &Semantics,
        id: ExprId,
        serial: u32,
        ty: Type,
    ) -> Result<Value, BuildError> {
        let site = s.site(serial);
        let mut inputs = Vec::new();
        for &input in site.map_or(&[][..], |site| &site.inputs) {
            inputs.push(self.expr(s, input)?);
        }
        let unknown = Unknown::Architecture {
            address: self.address,
            register: self.undefined_registers.get(&id).copied(),
            site: site.map(|site| site.site),
        };
        Ok(self.inst(Op::Undefined(unknown, inputs), ty))
    }

    /// The value of expression `id` of `s` (made once per scope).
    fn expr(&mut self, s: &Semantics, id: ExprId) -> Result<Value, BuildError> {
        if let Some(value) = self.exprs.get(id.0 as usize).copied().flatten() {
            return Ok(value);
        }
        let Some((expr, width)) = s.expr(id) else {
            return Err(self.malformed(&format!("no expression e{}", id.0)));
        };
        let ty = Type::Bits(width);
        let value = match expr {
            Expr::Const(bits) => self.inst(Op::Const(bits), ty),
            Expr::Local(local) => self
                .locals
                .get(local.0 as usize)
                .copied()
                .flatten()
                .ok_or_else(|| {
                    self.malformed(&format!("l{} used before it is defined", local.0))
                })?,
            Expr::Undefined { serial, .. } => self.undefined(s, id, serial, ty)?,
            Expr::Unary(op, a) => {
                let a = self.expr(s, a)?;
                self.inst(Op::Unary(op, a), ty)
            }
            Expr::Binary(op, a, b) => {
                let a = self.expr(s, a)?;
                let b = self.expr(s, b)?;
                self.inst(Op::Binary(op, a, b), ty)
            }
            Expr::Flag(op, a, b, c) => {
                let a = self.expr(s, a)?;
                let b = self.expr(s, b)?;
                let c = self.expr(s, c)?;
                self.inst(Op::Flag(op, a, b, c), ty)
            }
            Expr::Extract {
                value,
                offset,
                width,
            } => {
                let value = self.expr(s, value)?;
                self.inst(
                    Op::Extract {
                        value,
                        offset,
                        width,
                    },
                    ty,
                )
            }
            Expr::Concat { high, low } => {
                let high = self.expr(s, high)?;
                let low = self.expr(s, low)?;
                self.inst(Op::Concat { high, low }, ty)
            }
            Expr::Extend {
                signed,
                value,
                width,
            } => {
                let value = self.expr(s, value)?;
                self.inst(
                    Op::Extend {
                        signed,
                        value,
                        width,
                    },
                    ty,
                )
            }
            Expr::Select {
                condition,
                then,
                otherwise,
            } => {
                let condition = self.expr(s, condition)?;
                let then = self.expr(s, then)?;
                let otherwise = self.expr(s, otherwise)?;
                self.inst(
                    Op::Select {
                        condition,
                        then,
                        otherwise,
                    },
                    ty,
                )
            }
            Expr::Lanes { .. } | Expr::Float { .. } => self.vector(s, expr, ty)?,
        };
        if let Some(slot) = self.exprs.get_mut(id.0 as usize) {
            *slot = Some(value);
        }
        if let Some(scope) = self.scopes.last_mut() {
            scope.push(id);
        }
        Ok(value)
    }

    // ---- Finishing ------------------------------------------------------

    fn finish(mut self) -> Result<Function, BuildError> {
        if let Some(block) = self.current {
            return Err(BuildError(format!(
                "block {} at {:#x} is still open",
                block.0,
                self.f.blocks.get(block.0 as usize).map_or(0, |b| b.address)
            )));
        }
        self.fill();
        self.remove_trivial_parameters();
        self.compact();
        Ok(self.f)
    }

    /// Replaces parameters that only ever get one value (other than
    /// themselves) by that value, until none is left; a parameter that
    /// gets none (a block nothing reaches, or a loop around nothing)
    /// becomes undefined (the memory: the entry's). A worklist: when a
    /// parameter goes, the parameters it is an argument of are looked at
    /// again.
    fn remove_trivial_parameters(&mut self) {
        let count = self.f.values.len();
        // Every (parameter, argument) pair; then per parameter, its
        // arguments, and per value, the parameters it is an argument of.
        let mut pairs: Vec<(Value, Value)> = Vec::new();
        for block in &self.f.blocks {
            for target in block.terminator.targets() {
                let parameters = self
                    .f
                    .blocks
                    .get(target.block.0 as usize)
                    .map_or(&[][..], |b| b.parameters.as_slice());
                pairs.extend(
                    parameters
                        .iter()
                        .copied()
                        .zip(target.arguments.iter().copied()),
                );
            }
        }
        let arguments = Groups::new(count, pairs.iter().map(|&(p, a)| (p.0 as usize, a)));
        let users = Groups::new(count, pairs.iter().map(|&(p, a)| (a.0 as usize, p)));
        drop(pairs);
        let mut work: Vec<Value> = self
            .f
            .blocks
            .iter()
            .skip(1)
            .flat_map(|b| b.parameters.iter().copied())
            .collect();
        while let Some(parameter) = work.pop() {
            if self
                .replaced
                .get(parameter.0 as usize)
                .copied()
                .flatten()
                .is_some()
            {
                continue;
            }
            let mut same: Option<Value> = None;
            let mut trivial = true;
            for &argument in arguments.get(parameter.0 as usize) {
                let argument = self.find(argument);
                if argument == parameter || Some(argument) == same {
                    continue;
                }
                if same.is_some() {
                    trivial = false;
                    break;
                }
                same = Some(argument);
            }
            if !trivial {
                continue;
            }
            let replacement = match same {
                Some(value) => value,
                None => self.nothing(parameter),
            };
            let slot = parameter.0 as usize;
            if self.replaced.len() <= slot {
                self.replaced.resize(slot + 1, None);
            }
            if let Some(entry) = self.replaced.get_mut(slot) {
                *entry = Some(replacement);
            }
            work.extend_from_slice(users.get(slot));
        }
    }

    /// What replaces `parameter` when it gets no value: undefined, or the
    /// entry's memory (which dominates everything).
    fn nothing(&mut self, parameter: Value) -> Value {
        let ty = self.f.ty(parameter).unwrap_or(Type::Bits(1));
        if ty == Type::Memory {
            return self
                .f
                .blocks
                .first()
                .and_then(|entry| entry.parameters.last().copied())
                .unwrap_or(parameter);
        }
        let saved = self.address;
        self.address = self.f.entry;
        let value = self
            .inst_in(
                BlockId(0),
                Op::Undefined(Unknown::Unwritten, Vec::new()),
                &[ty],
            )
            .first()
            .copied()
            .unwrap_or(parameter);
        self.address = saved;
        value
    }

    /// Drops removed parameters (and their arguments), replaces every use
    /// of them, and numbers the values left densely.
    fn compact(&mut self) {
        let replaced = core::mem::take(&mut self.replaced);
        let removed = |value: Value| replaced.get(value.0 as usize).copied().flatten().is_some();
        let find = |mut value: Value| {
            while let Some(next) = replaced.get(value.0 as usize).copied().flatten() {
                value = next;
            }
            value
        };
        // Which parameter positions survive: per block, a run of one list
        // (from its start to the next block's).
        let mut keep: Vec<bool> = Vec::new();
        let mut keep_start = Vec::with_capacity(self.f.blocks.len());
        for block in &mut self.f.blocks {
            keep_start.push(keep.len());
            keep.extend(block.parameters.iter().map(|&p| !removed(p)));
            block.parameters.retain(|&p| !removed(p));
        }
        keep_start.push(keep.len());
        for block in &mut self.f.blocks {
            for target in block.terminator.targets_mut() {
                let index = target.block.0 as usize;
                let mask = keep_start
                    .get(index..=index + 1)
                    .and_then(|run| keep.get(*run.first()?..*run.last()?));
                let mut position = 0;
                target.arguments.retain(|_| {
                    let kept = mask.and_then(|m| m.get(position)).copied().unwrap_or(true);
                    position += 1;
                    kept
                });
            }
        }
        // Dense numbering of the values still defined.
        let mut numbers: Vec<Option<Value>> = vec![None; self.f.values.len()];
        let mut values: Vec<ValueInfo> = Vec::new();
        let mut renumber = |old: Value, info: ValueInfo, values: &mut Vec<ValueInfo>| {
            let new = Value(u32::try_from(values.len()).unwrap_or(u32::MAX));
            values.push(info);
            if let Some(slot) = numbers.get_mut(old.0 as usize) {
                *slot = Some(new);
            }
        };
        for (index, block) in self.f.blocks.iter().enumerate() {
            for (position, &parameter) in block.parameters.iter().enumerate() {
                let ty = self.f.ty(parameter).unwrap_or(Type::Bits(1));
                let info = ValueInfo {
                    ty,
                    definition: Definition::Parameter {
                        block: BlockId(u32::try_from(index).unwrap_or(u32::MAX)),
                        index: u32::try_from(position).unwrap_or(u32::MAX),
                    },
                };
                renumber(parameter, info, &mut values);
            }
        }
        for inst in &self.f.insts {
            for &result in &inst.results {
                if let Some(&info) = self.f.value(result) {
                    renumber(result, info, &mut values);
                }
            }
        }
        let number = |v: Value| numbers.get(v.0 as usize).copied().flatten().unwrap_or(v);
        // Every use: the value that replaces it, numbered.
        let renamed = |v: Value| number(find(v));
        for block in &mut self.f.blocks {
            for parameter in &mut block.parameters {
                *parameter = number(*parameter);
            }
            block.terminator.map_values(&mut |v| renamed(v));
        }
        for inst in &mut self.f.insts {
            inst.op.map_values(&mut |v| renamed(v));
            for result in &mut inst.results {
                *result = number(*result);
            }
        }
        self.f.values = values;
        // A removed parameter's entry goes: what replaces it has its own.
        let renumbered = |value: Value| numbers.get(value.0 as usize).copied().flatten();
        let mut held: BTreeMap<Value, RegisterId> = core::mem::take(&mut self.f.held)
            .into_iter()
            .filter_map(|(value, register)| Some((renumbered(value)?, register)))
            .collect();
        for &(parameter, register) in &self.parameter_held {
            if let Some(parameter) = renumbered(parameter) {
                held.insert(parameter, register);
            }
        }
        self.f.held = held;
    }
}

/// The constant value of expression `id`, as an address.
fn constant_of(s: &Semantics, id: ExprId) -> Option<u64> {
    match s.expr(id) {
        Some((Expr::Const(bits), _)) => Some(bits.low_u64()),
        Some((
            Expr::Local(_)
            | Expr::Undefined { .. }
            | Expr::Unary(..)
            | Expr::Binary(..)
            | Expr::Flag(..)
            | Expr::Extract { .. }
            | Expr::Concat { .. }
            | Expr::Extend { .. }
            | Expr::Select { .. }
            | Expr::Lanes { .. }
            | Expr::Float { .. },
            _,
        ))
        | None => None,
    }
}

/// Constant jump targets in `statements`.
fn jump_targets(s: &Semantics, statements: &[Stmt], out: &mut Vec<u64>) {
    for statement in statements {
        match statement {
            Stmt::Jump { target } => out.extend(constant_of(s, *target)),
            Stmt::If {
                then, otherwise, ..
            } => {
                jump_targets(s, then, out);
                jump_targets(s, otherwise, out);
            }
            Stmt::Loop(body) | Stmt::Atomic(body) => jump_targets(s, body, out),
            Stmt::Read { .. }
            | Stmt::Write { .. }
            | Stmt::Load { .. }
            | Stmt::Store { .. }
            | Stmt::Break
            | Stmt::Trap(_)
            | Stmt::Call { .. }
            | Stmt::Return { .. }
            | Stmt::SystemCall
            | Stmt::Intrinsic { .. } => {}
        }
    }
}

/// Whether `statements` return (an instruction that returns).
fn returns(statements: &[Stmt]) -> bool {
    statements.iter().any(|statement| match statement {
        Stmt::Return { .. } => true,
        Stmt::If {
            then, otherwise, ..
        } => returns(then) || returns(otherwise),
        Stmt::Loop(body) | Stmt::Atomic(body) => returns(body),
        Stmt::Read { .. }
        | Stmt::Write { .. }
        | Stmt::Load { .. }
        | Stmt::Store { .. }
        | Stmt::Break
        | Stmt::Trap(_)
        | Stmt::Call { .. }
        | Stmt::Jump { .. }
        | Stmt::SystemCall
        | Stmt::Intrinsic { .. } => false,
    })
}

/// The register each undefined value of `s` is written to: the first
/// [`Stmt::Write`] whose value is it, or holds it whole as a piece, an
/// extension or a [`Expr::Select`] arm (not a part of it, nor an operand
/// computed from: SHRD's SF is a bit of its result and OF is computed
/// from it, whose undefined value is the destination's).
fn written_undefined(s: &Semantics) -> BTreeMap<ExprId, RegisterId> {
    let mut out = BTreeMap::new();
    if s.exprs
        .iter()
        .any(|(expr, _)| matches!(expr, Expr::Undefined { .. }))
    {
        undefined_writes(s, &s.body, &mut out);
    }
    out
}

/// [`written_undefined`] for `statements`, into `out`.
fn undefined_writes(s: &Semantics, statements: &[Stmt], out: &mut BTreeMap<ExprId, RegisterId>) {
    for statement in statements {
        match statement {
            Stmt::Write { view, value } => {
                let mut work = vec![*value];
                while let Some(id) = work.pop() {
                    match s.expr(id).map(|(expr, _)| expr) {
                        Some(Expr::Undefined { .. }) => {
                            out.entry(id).or_insert(view.register);
                        }
                        Some(
                            Expr::Select {
                                then: a,
                                otherwise: b,
                                ..
                            }
                            | Expr::Concat { high: a, low: b },
                        ) => work.extend([a, b]),
                        Some(Expr::Extend { value, .. }) => work.push(value),
                        Some(
                            Expr::Const(_)
                            | Expr::Local(_)
                            | Expr::Unary(..)
                            | Expr::Binary(..)
                            | Expr::Flag(..)
                            | Expr::Extract { .. }
                            | Expr::Lanes { .. }
                            | Expr::Float { .. },
                        )
                        | None => {}
                    }
                }
            }
            Stmt::If {
                then, otherwise, ..
            } => {
                undefined_writes(s, then, out);
                undefined_writes(s, otherwise, out);
            }
            Stmt::Loop(body) | Stmt::Atomic(body) => undefined_writes(s, body, out),
            Stmt::Read { .. }
            | Stmt::Load { .. }
            | Stmt::Store { .. }
            | Stmt::Break
            | Stmt::Trap(_)
            | Stmt::Call { .. }
            | Stmt::Jump { .. }
            | Stmt::Return { .. }
            | Stmt::SystemCall
            | Stmt::Intrinsic { .. } => {}
        }
    }
}
