//! Running a [`Function`] on concrete state, as L1's interpreter
//! ([`binbun_ssa::interpret`]) runs L1, so the two can be compared.
//!
//! - Values carry a mask of undefined bits as in L0
//!   ([`binbun_semantics::interpret`]), and every operation is evaluated by
//!   the same public functions L0's and L1's interpreters use.
//! - Parameters start as the arguments, locals as undefined values.
//! - A local declared at a statement ([`Function::declared`]) is
//!   undefined again each time control reaches that statement (before
//!   it runs), as C's object of a block is each time its declaration is
//!   reached: a value read across it is undefined.
//! - Memory is the [`Machine`]'s, and so is an environment variable
//!   ([`VarKind::Environment`]): its register's value when the run starts
//!   (the machine's registers are not used otherwise). A global is
//!   the bytes at its address; a [`VarKind::Frame`] variable the bytes at
//!   `stack` plus its offset, where `stack` is the value the stack pointer
//!   has on entry (the address of the return address on x86-64). Running
//!   L1 with that stack pointer puts the frame at the same addresses, so
//!   the runs' memories compare byte for byte.
//! - Operands are evaluated left to right (which matters only for which of
//!   two faulting loads faults). An expression used several times within
//!   one evaluation is evaluated once: expressions have no effects, so
//!   this is the same as evaluating each use.
//! - Statements and expressions are walked with explicit stacks, not
//!   recursion: nesting may be arbitrarily deep.
//! - Calls are not run: the run stops at them, as L1's does
//!   ([`Outcome::Call`]), a call in an expression once its callee and
//!   arguments are evaluated; intrinsics are answered by the machine.
//!   [`run_observed`] runs them as an [`Observer`] says (its result
//!   written where the call's goes, the run going on), and tells it each
//!   statement run, value assigned (by a statement or by an assignment
//!   expression in a condition), way decided and loop iteration.
//! - So no exception is thrown: a `Try` runs its body. A handler is
//!   entered only by a `goto` into it; one that propagates ends the run
//!   when it falls off its end ([`Outcome::Propagated`]).
//!   [`Expr::Exception`] is undefined.
//! - An undefined value of a site with inputs ([`Function::inputs`]) is
//!   the machine's choice ([`Machine::undefined_at`]), an input lowering
//!   did not keep being unknown bits: unknown where the choice depends on
//!   it, unless the machine knows the choice another run made at the same
//!   instruction. A choice with defined bits is told to the observer
//!   ([`Observer::chose`]).
//! - [`Stmt::VaStart`] does what [`Function::va`] says: each save, of
//!   its register's value when the run starts (a guarded save only where
//!   the guard's low byte is not 0; undetermined if it is undefined), then
//!   the `va_list`'s fields.
//! - `fuel` is the number of statements executed, loop iterations started
//!   and blocks entered by a `goto` that the run may take.

// The error is how a run ends, once per run.
#![expect(clippy::result_large_err, reason = "outcomes hold values")]

use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;

use binbun_semantics::bits::{Bits, MAX_WIDTH};
use binbun_semantics::interpret::{self, Fault, Machine, Value};
use binbun_semantics::ir::{Binary, SiteId, Trap};
use binbun_semantics::verify::{binary_width, float_width, lanes_width, unary_width};
use binbun_ssa::ir::Unknown;

use crate::ir::{
    Block, Call, CallId, CallSite, Callee, Escape, Expr, ExprId, Function, InputsId, LabelId,
    Logical, Place, SiteInput, Stmt, StmtId, Update, VaList, VarId, VarKind,
};
use crate::types::TypeId;

/// How a run of a function ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// A [`Stmt::Return`] (or the end of the body of a function that
    /// returns no value): the value returned.
    Returned(Option<Value>),
    /// A [`Stmt::Call`] or [`Expr::Call`], which the interpreter does not
    /// run.
    Call {
        /// The call.
        at: CallSite,
        /// The callee's address.
        target: u64,
        /// The arguments.
        arguments: Vec<Value>,
    },
    /// A [`Stmt::Trap`].
    Trap(Trap),
    /// A memory access faulted.
    Fault(Fault),
    /// A [`Stmt::Escape`], but [`Escape::Atomic`] and [`Escape::Update`],
    /// which run as the plain accesses they stand for (one run is one
    /// thread).
    Escape {
        /// The statement.
        at: StmtId,
        /// What it is.
        kind: Escape,
        /// Its operands.
        operands: Vec<Value>,
    },
    /// A [`Stmt::Unreachable`] was reached.
    Unreachable(StmtId),
    /// A handler of the [`Stmt::Try`] that propagates the exception
    /// (a cleanup) fell off its end: unwinding goes on.
    Propagated(StmtId),
    /// A condition, scrutinee or address depended on undefined bits.
    Undetermined,
    /// More statements ran than the fuel allows.
    OutOfFuel,
    /// The function is malformed (it does not pass the verifier), or the
    /// arguments do not fit its parameters.
    Malformed,
}

/// Runs `function` with `arguments` (one per parameter, of its width) on
/// `machine`'s memory, the stack pointer on entry being `stack`, for at
/// most `fuel` steps.
pub fn run(
    function: &Function,
    machine: &mut dyn Machine,
    arguments: &[Value],
    stack: u64,
    fuel: u64,
) -> Outcome {
    run_observed(function, machine, arguments, stack, fuel, &mut Stops)
}

/// What a run tells, and how its calls run ([`run_observed`]). Every
/// method but [`Observer::call`] only listens.
pub trait Observer {
    /// Statement `id` starts (each statement run, those of a `for`'s
    /// `init` and `step` included); or how the run stops before it (a
    /// budget spent, a run cancelled).
    ///
    /// # Errors
    ///
    /// The outcome the run stops with.
    fn statement(&mut self, id: StmtId) -> Result<(), Outcome> {
        let _ = id;
        Ok(())
    }

    /// Statement `id` (an assignment, a call with results, an intrinsic,
    /// a return) wrote `values`: one per place it writes, a call's result
    /// whole, a return's value.
    fn assigned(&mut self, id: StmtId, values: &[Value]) {
        let _ = (id, values);
    }

    /// Assignment expression `at` ([`Expr::Assign`]), evaluated for
    /// statement `id` (an `if`'s or a loop's condition, where L2 has
    /// them), wrote `value` to its variable: as it is made, before the
    /// statement decides; each one its condition makes, in order.
    fn assigned_in(&mut self, id: StmtId, at: ExprId, value: Value) {
        let _ = (id, at, value);
    }

    /// Statement `id` decided: an `if` took `then` (0) or `otherwise`
    /// (1); a loop entered its body (0) or ended (1); a switch took arm
    /// `arm` (the number of arms: none).
    fn decided(&mut self, id: StmtId, arm: usize) {
        let _ = (id, arm);
    }

    /// Loop `id` starts an iteration of its body.
    fn iteration(&mut self, id: StmtId) {
        let _ = id;
    }

    /// The machine chose `value` (some of its bits defined: a processor's
    /// profile) for the undefined value of `site` that the instruction at
    /// `address` leaves, in the statement running.
    fn chose(&mut self, address: u64, site: SiteId, value: Value) {
        let _ = (address, site, value);
    }

    /// Call `at` of `target` with `arguments` on `machine`, its result
    /// `width` bits where the caller takes one: the result ([`None`] for
    /// none), the run going on; or how the run stops. By default it
    /// stops ([`Outcome::Call`]).
    ///
    /// # Errors
    ///
    /// The outcome the run stops with.
    fn call(
        &mut self,
        machine: &mut dyn Machine,
        at: CallSite,
        target: u64,
        arguments: &[Value],
        width: Option<u16>,
    ) -> Result<Option<Value>, Outcome> {
        let _ = (machine, width);
        Err(Outcome::Call {
            at,
            target,
            arguments: arguments.to_vec(),
        })
    }
}

/// The [`Observer`] of [`run`]: listens to nothing, stops at calls.
struct Stops;

impl Observer for Stops {}

/// [`run`], telling `observer` what runs and running calls as it says.
/// A call whose result `observer` gives runs on: a statement's result is
/// written to its places (low bits first), an expression's is its value;
/// a result of another width than the call's is [`Outcome::Malformed`].
pub fn run_observed(
    function: &Function,
    machine: &mut dyn Machine,
    arguments: &[Value],
    stack: u64,
    fuel: u64,
    observer: &mut dyn Observer,
) -> Outcome {
    let Some((parents, labels)) = layout(function) else {
        return Outcome::Malformed;
    };
    let mut run = Run {
        function,
        machine,
        observer,
        stack,
        fuel,
        values: function
            .variables
            .iter()
            .map(|variable| Value::unknown(function.types.value_width(variable.ty).unwrap_or(1)))
            .collect(),
        parents,
        labels,
        frames: vec![Frame::Block {
            block: &function.body,
            next: 0,
        }],
        evaluating: None,
    };
    match run.enter(arguments).and_then(|()| run.execute()) {
        Ok(()) if function.returns.is_none() => Outcome::Returned(None),
        Ok(()) => Outcome::Malformed,
        Err(outcome) => outcome,
    }
}

/// Where a statement is: the statement holding its block (`None`: the
/// body), which of that statement's blocks ([`Stmt::blocks`]), and its
/// position there.
#[derive(Clone, Copy, Debug)]
struct Parent {
    owner: Option<StmtId>,
    child: usize,
    position: usize,
}

/// Where each statement is, and the statement defining each label.
type Layout = (Vec<Option<Parent>>, BTreeMap<LabelId, StmtId>);

/// Where each statement is, and the statement defining each label;
/// `None` if a statement is in more than one place or a label is defined
/// twice.
fn layout(function: &Function) -> Option<Layout> {
    let mut parents = vec![None; function.stmts.len()];
    let mut labels = BTreeMap::new();
    let mut work: Vec<(Option<StmtId>, usize, &Block)> = vec![(None, 0, &function.body)];
    while let Some((owner, child, block)) = work.pop() {
        for (position, &id) in block.iter().enumerate() {
            let slot = parents.get_mut(id.0 as usize)?;
            if slot.is_some() {
                return None;
            }
            *slot = Some(Parent {
                owner,
                child,
                position,
            });
            let stmt = function.stmt(id)?;
            if let &Stmt::Label(label) = stmt
                && labels.insert(label, id).is_some()
            {
                return None;
            }
            for (index, inner) in stmt.blocks().enumerate() {
                work.push((Some(id), index, inner));
            }
        }
    }
    Some((parents, labels))
}

/// An entry of the run's control stack.
#[derive(Clone, Copy, Debug)]
enum Frame<'a> {
    /// Running a block: the position of the next statement.
    Block { block: &'a Block, next: usize },
    /// Inside the body of this loop: when it is on top, the body has ended.
    Loop(StmtId),
    /// Inside arm `arm` of this switch: when it is on top, the arm has
    /// ended.
    Switch { id: StmtId, arm: usize },
    /// Inside a handler of this `Try` that propagates the exception: when
    /// it is on top, the handler has ended.
    Propagate(StmtId),
}

struct Run<'a> {
    function: &'a Function,
    machine: &'a mut dyn Machine,
    observer: &'a mut dyn Observer,
    stack: u64,
    fuel: u64,
    /// Each parameter's and local's value (unused for variables in memory).
    values: Vec<Value>,
    /// Where each statement is.
    parents: Vec<Option<Parent>>,
    /// The statement defining each label.
    labels: BTreeMap<LabelId, StmtId>,
    /// What is running, innermost last.
    frames: Vec<Frame<'a>>,
    /// The statement whose expressions are being evaluated, for
    /// [`Observer::assigned_in`].
    evaluating: Option<StmtId>,
}

impl<'a> Run<'a> {
    /// Binds the parameters to `arguments`.
    fn enter(&mut self, arguments: &[Value]) -> Result<(), Outcome> {
        let parameters = &self.function.parameters;
        if parameters.len() != arguments.len() {
            return Err(Outcome::Malformed);
        }
        for (&parameter, &argument) in parameters.iter().zip(arguments) {
            self.write_var(parameter, argument)?;
        }
        for (index, variable) in self.function.variables.iter().enumerate() {
            if let VarKind::Environment(register) = variable.kind {
                let value = self.machine.read(register);
                if self.function.types.value_width(variable.ty) != Some(value.width()) {
                    return Err(Outcome::Malformed);
                }
                let slot = self.values.get_mut(index).ok_or(Outcome::Malformed)?;
                *slot = value;
            }
        }
        Ok(())
    }

    /// Takes one step of fuel.
    fn tick(&mut self) -> Result<(), Outcome> {
        self.fuel = self.fuel.checked_sub(1).ok_or(Outcome::OutOfFuel)?;
        Ok(())
    }

    /// Makes the locals declared at statement `id` undefined.
    fn declare(&mut self, id: StmtId) {
        let function = self.function;
        for &var in function.declared.get(&id).map_or(&[][..], Vec::as_slice) {
            let width = function
                .var(var)
                .and_then(|variable| function.types.value_width(variable.ty));
            if let (Some(width), Some(slot)) = (width, self.values.get_mut(var.0 as usize)) {
                *slot = Value::unknown(width);
            }
        }
    }

    /// Statement `id`.
    fn statement(&self, id: StmtId) -> Result<&'a Stmt, Outcome> {
        let function: &'a Function = self.function;
        function.stmt(id).ok_or(Outcome::Malformed)
    }

    /// Runs until the body ends ([`Ok`]) or the run stops.
    fn execute(&mut self) -> Result<(), Outcome> {
        while let Some(frame) = self.frames.last_mut() {
            match frame {
                Frame::Block { block, next } => match block.get(*next) {
                    Some(&id) => {
                        *next += 1;
                        self.stmt(id)?;
                    }
                    None => {
                        self.frames.pop();
                    }
                },
                &mut Frame::Loop(id) => self.again(id)?,
                &mut Frame::Switch { id, arm } => self.fall(id, arm)?,
                &mut Frame::Propagate(id) => return Err(Outcome::Propagated(id)),
            }
        }
        Ok(())
    }

    /// Arm `arm` of switch `id` has ended: the next arm if it falls
    /// through, else the end of the switch.
    fn fall(&mut self, id: StmtId, arm: usize) -> Result<(), Outcome> {
        let Stmt::Switch { arms, .. } = self.statement(id)? else {
            return Err(Outcome::Malformed);
        };
        let current = arms.get(arm).ok_or(Outcome::Malformed)?;
        self.frames.pop();
        if let Some(following) = arms.get(arm + 1)
            && current.fallthrough
        {
            self.frames.push(Frame::Switch { id, arm: arm + 1 });
            self.frames.push(Frame::Block {
                block: &following.body,
                next: 0,
            });
        }
        Ok(())
    }

    /// Runs statement `id`: does it, or pushes what it runs.
    fn stmt(&mut self, id: StmtId) -> Result<(), Outcome> {
        self.tick()?;
        self.observer.statement(id)?;
        self.declare(id);
        let stmt = self.statement(id)?;
        self.evaluating = Some(id);
        match stmt {
            Stmt::If {
                condition,
                then,
                otherwise,
            } => {
                let (block, arm) = if self.condition(*condition)? {
                    (then, 0)
                } else {
                    (otherwise, 1)
                };
                self.observer.decided(id, arm);
                self.frames.push(Frame::Block { block, next: 0 });
            }
            Stmt::While { condition, body } => {
                let holds = self.condition(*condition)?;
                self.enter_loop(id, holds, body);
            }
            Stmt::DoWhile { body, .. } => {
                self.enter_loop(id, true, body);
            }
            Stmt::For {
                init,
                condition,
                body,
                ..
            } => {
                self.simple_block(init)?;
                self.evaluating = Some(id);
                let holds = self.condition(*condition)?;
                self.enter_loop(id, holds, body);
            }
            Stmt::Switch { scrutinee, arms } => {
                let value = self.eval(*scrutinee)?;
                let bits = value.known().ok_or(Outcome::Undetermined)?;
                let chosen = arms
                    .iter()
                    .position(|arm| arm.values.contains(&bits))
                    .or_else(|| arms.iter().position(|arm| arm.default));
                self.observer.decided(id, chosen.unwrap_or(arms.len()));
                if let Some(arm) = chosen.and_then(|index| Some((index, arms.get(index)?))) {
                    self.frames.push(Frame::Switch { id, arm: arm.0 });
                    self.frames.push(Frame::Block {
                        block: &arm.1.body,
                        next: 0,
                    });
                }
            }
            Stmt::Try { body, .. } => self.frames.push(Frame::Block {
                block: body,
                next: 0,
            }),
            &Stmt::Break(target) => {
                self.unwind(target, false)?;
                self.frames.pop();
            }
            &Stmt::Continue(target) => self.unwind(target, true)?,
            &Stmt::Goto(label) => self.goto(label)?,
            Stmt::Label(_) => {}
            Stmt::Assign { .. }
            | Stmt::Call { .. }
            | Stmt::Intrinsic { .. }
            | Stmt::Expr(_)
            | Stmt::Return(_)
            | Stmt::Trap(_)
            | Stmt::Unreachable
            | Stmt::Escape { .. }
            | Stmt::VaStart { .. } => self.simple(id, stmt)?,
        }
        Ok(())
    }

    /// Loop `id` first decides: enters `body` if `holds`.
    fn enter_loop(&mut self, id: StmtId, holds: bool, body: &'a Block) {
        self.observer.decided(id, usize::from(!holds));
        if holds {
            self.observer.iteration(id);
            self.frames.push(Frame::Loop(id));
            self.frames.push(Frame::Block {
                block: body,
                next: 0,
            });
        }
    }

    /// Pops frames until loop `target` (or, if not `loop_only`, switch
    /// `target`) is on top.
    fn unwind(&mut self, target: StmtId, loop_only: bool) -> Result<(), Outcome> {
        loop {
            match self.frames.last() {
                Some(&Frame::Loop(id)) if id == target => return Ok(()),
                Some(&Frame::Switch { id, .. }) if id == target && !loop_only => return Ok(()),
                Some(_) => {
                    self.frames.pop();
                }
                None => return Err(Outcome::Malformed),
            }
        }
    }

    /// Loop `id`'s body has ended (or continued): its step, then its
    /// condition, then its body again or the end of the loop.
    fn again(&mut self, id: StmtId) -> Result<(), Outcome> {
        let (condition, body) = match self.statement(id)? {
            Stmt::While { condition, body } | Stmt::DoWhile { body, condition } => {
                (*condition, body)
            }
            Stmt::For {
                condition,
                step,
                body,
                ..
            } => {
                self.simple_block(step)?;
                (*condition, body)
            }
            Stmt::Assign { .. }
            | Stmt::Call { .. }
            | Stmt::Intrinsic { .. }
            | Stmt::Expr(_)
            | Stmt::If { .. }
            | Stmt::Switch { .. }
            | Stmt::Try { .. }
            | Stmt::Break(_)
            | Stmt::Continue(_)
            | Stmt::Label(_)
            | Stmt::Goto(_)
            | Stmt::Return(_)
            | Stmt::Trap(_)
            | Stmt::Unreachable
            | Stmt::Escape { .. }
            | Stmt::VaStart { .. } => return Err(Outcome::Malformed),
        };
        self.tick()?;
        self.evaluating = Some(id);
        if self.condition(condition)? {
            self.observer.decided(id, 0);
            self.observer.iteration(id);
            self.frames.push(Frame::Block {
                block: body,
                next: 0,
            });
        } else {
            self.observer.decided(id, 1);
            self.frames.pop();
        }
        Ok(())
    }

    /// Runs a `for`'s `init` or `step`: simple statements.
    fn simple_block(&mut self, block: &Block) -> Result<(), Outcome> {
        for &inner in block {
            self.tick()?;
            self.observer.statement(inner)?;
            self.declare(inner);
            let stmt = self.statement(inner)?;
            self.evaluating = Some(inner);
            match stmt {
                Stmt::Assign { .. }
                | Stmt::Call { .. }
                | Stmt::Intrinsic { .. }
                | Stmt::Expr(_) => {
                    self.simple(inner, stmt)?;
                }
                Stmt::If { .. }
                | Stmt::While { .. }
                | Stmt::DoWhile { .. }
                | Stmt::For { .. }
                | Stmt::Switch { .. }
                | Stmt::Try { .. }
                | Stmt::Break(_)
                | Stmt::Continue(_)
                | Stmt::Label(_)
                | Stmt::Goto(_)
                | Stmt::Return(_)
                | Stmt::Trap(_)
                | Stmt::Unreachable
                | Stmt::Escape { .. }
                | Stmt::VaStart { .. } => return Err(Outcome::Malformed),
            }
        }
        Ok(())
    }

    /// Replaces the control stack with the way to `label`'s statement: the
    /// blocks around it, each resumed after the statement leading in, and
    /// the loops and switches it is inside. Entering a loop this way skips
    /// its condition until the body ends.
    fn goto(&mut self, label: LabelId) -> Result<(), Outcome> {
        let mut at = *self.labels.get(&label).ok_or(Outcome::Malformed)?;
        let mut path = Vec::new();
        loop {
            self.tick()?;
            let parent = self
                .parents
                .get(at.0 as usize)
                .copied()
                .flatten()
                .ok_or(Outcome::Malformed)?;
            path.push(parent);
            match parent.owner {
                Some(owner) => at = owner,
                None => break,
            }
        }
        self.frames.clear();
        for parent in path.into_iter().rev() {
            let block = match parent.owner {
                None => &self.function.body,
                Some(owner) => {
                    let stmt = self.statement(owner)?;
                    match (stmt, parent.child) {
                        (Stmt::While { .. } | Stmt::DoWhile { .. }, 0) | (Stmt::For { .. }, 2) => {
                            self.frames.push(Frame::Loop(owner));
                        }
                        (Stmt::Switch { .. }, arm) => {
                            self.frames.push(Frame::Switch { id: owner, arm });
                        }
                        (Stmt::If { .. }, _) | (Stmt::Try { .. }, 0) => {}
                        (Stmt::Try { handlers, .. }, handler) => {
                            let propagates = handlers
                                .get(handler - 1)
                                .ok_or(Outcome::Malformed)?
                                .kind
                                .propagates();
                            if propagates {
                                self.frames.push(Frame::Propagate(owner));
                            }
                        }
                        (_, _) => return Err(Outcome::Malformed),
                    }
                    stmt.blocks().nth(parent.child).ok_or(Outcome::Malformed)?
                }
            };
            self.frames.push(Frame::Block {
                block,
                next: parent.position + 1,
            });
        }
        Ok(())
    }

    /// Runs a statement that holds no blocks and does not jump.
    fn simple(&mut self, id: StmtId, stmt: &Stmt) -> Result<(), Outcome> {
        match stmt {
            &Stmt::Assign { place, value } => {
                let value = self.eval(value)?;
                self.write(place, value)?;
                self.observer.assigned(id, &[value]);
                Ok(())
            }
            Stmt::Call { call, results } => self.call_stmt(id, call, results),
            Stmt::Intrinsic {
                results,
                intrinsic,
                inputs,
            } => {
                let inputs = self.eval_all(inputs)?;
                let widths = results
                    .iter()
                    .map(|&place| self.place_width(place))
                    .collect::<Result<Vec<_>, _>>()?;
                let outputs = self.machine.intrinsic(*intrinsic, &inputs, &widths);
                if outputs.len() != results.len() {
                    return Err(Outcome::Malformed);
                }
                for (&place, &output) in results.iter().zip(&outputs) {
                    self.write(place, output)?;
                }
                self.observer.assigned(id, &outputs);
                Ok(())
            }
            &Stmt::Expr(value) => self.eval(value).map(drop),
            &Stmt::Return(value) => {
                let value = value.map(|value| self.eval(value)).transpose()?;
                let own = match self.function.returns {
                    Some(ty) => Some(
                        self.function
                            .types
                            .value_width(ty)
                            .ok_or(Outcome::Malformed)?,
                    ),
                    None => None,
                };
                if value.map(|value| value.width()) != own {
                    return Err(Outcome::Malformed);
                }
                if let Some(value) = value {
                    self.observer.assigned(id, &[value]);
                }
                Err(Outcome::Returned(value))
            }
            &Stmt::Trap(trap) => Err(Outcome::Trap(trap)),
            Stmt::Unreachable => Err(Outcome::Unreachable(id)),
            Stmt::Escape {
                kind: Escape::Atomic,
                operands,
                results,
            } => self.atomic(operands, results),
            Stmt::Escape {
                kind: Escape::Update(update),
                operands,
                results,
            } => self.update(*update, operands, results),
            Stmt::Escape { kind, operands, .. } => {
                let operands = self.eval_all(operands)?;
                Err(Outcome::Escape {
                    at: id,
                    kind: *kind,
                    operands,
                })
            }
            &Stmt::VaStart { list } => self.va_start(list),
            Stmt::If { .. }
            | Stmt::While { .. }
            | Stmt::DoWhile { .. }
            | Stmt::For { .. }
            | Stmt::Switch { .. }
            | Stmt::Try { .. }
            | Stmt::Break(_)
            | Stmt::Continue(_)
            | Stmt::Label(_)
            | Stmt::Goto(_) => Err(Outcome::Malformed),
        }
    }

    /// Runs a [`Stmt::VaStart`] of `list`: [`Function::va`]'s saves, then
    /// the `va_list`.
    /// Runs call statement `id` (`call`, its result to `results`) as the
    /// observer says.
    fn call_stmt(&mut self, id: StmtId, call: &Call, results: &[Place]) -> Result<(), Outcome> {
        let target = match call.callee {
            Callee::Address(address) => address,
            Callee::Import(slot) => self.import(slot)?,
            Callee::Expr(target) => self.address(target)?,
        };
        let arguments = self.eval_all(&call.arguments)?;
        let widths = results
            .iter()
            .map(|&place| self.place_width(place))
            .collect::<Result<Vec<_>, _>>();
        let width = widths.as_ref().ok().and_then(|widths| {
            widths
                .iter()
                .try_fold(0u16, |sum, &part| sum.checked_add(part))
        });
        let wanted = width.filter(|_| !results.is_empty());
        let result = self.observer.call(
            &mut *self.machine,
            CallSite::Stmt(id),
            target,
            &arguments,
            wanted,
        )?;
        let Some(result) = result.filter(|_| !results.is_empty()) else {
            return Ok(());
        };
        let widths = widths?;
        if Some(result.width()) != width {
            return Err(Outcome::Malformed);
        }
        let mut offset = 0;
        for (&place, &part) in results.iter().zip(&widths) {
            self.write(place, interpret::extract(result, offset, part))?;
            offset += part;
        }
        self.observer.assigned(id, &[result]);
        Ok(())
    }

    /// Runs a [`Stmt::VaStart`] of `list`: [`Function::va`]'s saves, then
    /// the `va_list`.
    fn va_start(&mut self, list: Place) -> Result<(), Outcome> {
        let va = self.function.va.as_ref().ok_or(Outcome::Malformed)?;
        let Place::Var(list) = list else {
            return Err(Outcome::Malformed);
        };
        for save in &va.saves {
            if let Some(guard) = save.guard {
                let count = interpret::extract(self.machine.read(guard), 0, 8);
                if count.known().ok_or(Outcome::Undetermined)?.is_zero() {
                    continue;
                }
            }
            let value = self.machine.read(save.register);
            let width = save.bytes.checked_mul(8).ok_or(Outcome::Malformed)?;
            if width > value.width() {
                return Err(Outcome::Malformed);
            }
            let address = self.stack.wrapping_add_signed(save.offset);
            self.machine
                .store(address, interpret::extract(value, 0, width))
                .map_err(Outcome::Fault)?;
        }
        let pointer = |offset: i64| {
            Value::defined(Bits::from_u64(
                self.function.types.pointer_width(),
                self.stack.wrapping_add_signed(offset),
            ))
        };
        match va.list {
            VaList::Tag {
                gp_offset,
                fp_offset,
                overflow,
                save_area,
            } => {
                let word = |value: u32| Value::defined(Bits::from_u64(32, u64::from(value)));
                let fields = [
                    (Some(word(gp_offset)), 4),
                    (fp_offset.map(word), 4),
                    (Some(pointer(overflow)), 8),
                    (Some(pointer(save_area)), 8),
                ];
                let mut address = self.memory_address(list)?;
                for (field, bytes) in fields {
                    if let Some(field) = field {
                        self.machine.store(address, field).map_err(Outcome::Fault)?;
                    }
                    address = address.wrapping_add(bytes);
                }
                Ok(())
            }
            VaList::Pointer(offset) => self.write_var(list, pointer(offset)),
            VaList::Aapcs64 {
                stack,
                gr_top,
                vr_top,
                gr_offs,
                vr_offs,
            } => {
                let word = |value: i32| {
                    Value::defined(Bits::from_u64(32, u64::from(value.cast_unsigned())))
                };
                let fields = [
                    (Some(pointer(stack)), 0),
                    (gr_top.map(pointer), 8),
                    (vr_top.map(pointer), 16),
                    (Some(word(gr_offs)), 24),
                    (Some(word(vr_offs)), 28),
                ];
                let address = self.memory_address(list)?;
                for (field, at) in fields {
                    if let Some(field) = field {
                        self.machine
                            .store(address.wrapping_add(at), field)
                            .map_err(Outcome::Fault)?;
                    }
                }
                Ok(())
            }
        }
    }

    /// Runs an [`Escape::Atomic`] access as the plain access it stands for
    /// (one run is one thread): `[address]` with one result loads the
    /// result's width; `[address, value]` with none stores the value.
    fn atomic(&mut self, operands: &[ExprId], results: &[Place]) -> Result<(), Outcome> {
        match (operands, results) {
            (&[address], &[place]) => {
                let address = self.address(address)?;
                let width = self.place_width(place)?;
                if width % 8 != 0 {
                    return Err(Outcome::Malformed);
                }
                let value = self
                    .machine
                    .load(address, width / 8)
                    .map_err(Outcome::Fault)?;
                self.write(place, value)
            }
            (&[address, value], &[]) => {
                let address = self.address(address)?;
                let value = self.eval(value)?;
                if value.width() % 8 != 0 {
                    return Err(Outcome::Malformed);
                }
                self.machine.store(address, value).map_err(Outcome::Fault)
            }
            _ => Err(Outcome::Malformed),
        }
    }

    /// Runs an [`Escape::Update`] (one run is one thread): its operands
    /// evaluated, the memory at the address read at their width, the
    /// update's value written back (a compare-and-exchange that fails
    /// writes back what it read, as `lock cmpxchg` does), then the value
    /// read given to the result.
    fn update(
        &mut self,
        update: Update,
        operands: &[ExprId],
        results: &[Place],
    ) -> Result<(), Outcome> {
        let Some((&address, values)) = operands.split_first() else {
            return Err(Outcome::Malformed);
        };
        let address = self.address(address)?;
        let values = self.eval_all(values)?;
        let (&first, last) = match (values.as_slice(), update.arity()) {
            ([value], 1) => (value, value),
            ([expected, desired], 2) => (expected, desired),
            _ => return Err(Outcome::Malformed),
        };
        let width = first.width();
        if width % 8 != 0 || last.width() != width || results.len() > 1 {
            return Err(Outcome::Malformed);
        }
        let old = self
            .machine
            .load(address, width / 8)
            .map_err(Outcome::Fault)?;
        let binary = |op| interpret::binary(op, old, first);
        let new = match update {
            Update::Exchange => first,
            Update::Add => binary(Binary::Add),
            Update::Sub => binary(Binary::Sub),
            Update::And => binary(Binary::And),
            Update::Or => binary(Binary::Or),
            Update::Xor => binary(Binary::Xor),
            Update::CompareExchange => interpret::select(binary(Binary::Eq), *last, old),
        };
        self.machine.store(address, new).map_err(Outcome::Fault)?;
        match results {
            &[place] => self.write(place, old),
            _ => Ok(()),
        }
    }

    /// Whether 1-bit condition `id` holds.
    fn condition(&mut self, id: ExprId) -> Result<bool, Outcome> {
        let value = self.eval(id)?;
        if value.width() != 1 {
            return Err(Outcome::Malformed);
        }
        let bits = value.known().ok_or(Outcome::Undetermined)?;
        Ok(!bits.is_zero())
    }

    /// The address `id` evaluates to: pointer-wide and defined.
    fn address(&mut self, id: ExprId) -> Result<u64, Outcome> {
        let value = self.eval(id)?;
        self.known_address(value)
    }

    /// The address the import slot at `slot` holds: a pointer-wide load
    /// of it.
    fn import(&mut self, slot: u64) -> Result<u64, Outcome> {
        let bytes = self.function.types.pointer_width() / 8;
        let value = self.machine.load(slot, bytes).map_err(Outcome::Fault)?;
        self.known_address(value)
    }

    /// The address `value` holds: pointer-wide and defined.
    fn known_address(&self, value: Value) -> Result<u64, Outcome> {
        if value.width() != self.function.types.pointer_width() {
            return Err(Outcome::Malformed);
        }
        value
            .known()
            .map(|bits| bits.low_u64())
            .ok_or(Outcome::Undetermined)
    }

    fn eval_all(&mut self, ids: &[ExprId]) -> Result<Vec<Value>, Outcome> {
        ids.iter().map(|&id| self.eval(id)).collect()
    }

    /// The value of expression `id`, its operands first (an explicit
    /// stack: expressions may be arbitrarily deep); a logical operation's
    /// right operand only if its left one does not decide.
    fn eval(&mut self, id: ExprId) -> Result<Value, Outcome> {
        let function = self.function;
        let mut done: BTreeMap<ExprId, Value> = BTreeMap::new();
        // (expression, stage): 0 to start, 1 with its operands done (a
        // logical operation's left one), 2 with a logical one's right one.
        let mut work = vec![(id, 0u8)];
        let mut operands = Vec::new();
        while let Some((at, stage)) = work.pop() {
            if done.contains_key(&at) {
                continue;
            }
            let expr = *function.expr(at).ok_or(Outcome::Malformed)?;
            if let Expr::Logical(op, left, right) = expr {
                if left >= at || right >= at {
                    return Err(Outcome::Malformed);
                }
                let operand = |id| {
                    let value: Value = *done.get(&id).ok_or(Outcome::Malformed)?;
                    if value.width() != 1 {
                        return Err(Outcome::Malformed);
                    }
                    value.known().ok_or(Outcome::Undetermined)
                };
                match stage {
                    0 => work.extend([(at, 1), (left, 0)]),
                    1 => {
                        let holds = !operand(left)?.is_zero();
                        // `&&` decides on 0, `||` on 1.
                        if holds == matches!(op, Logical::Or) {
                            done.insert(at, Value::defined(Bits::from_u64(1, u64::from(holds))));
                        } else {
                            work.extend([(at, 2), (right, 0)]);
                        }
                    }
                    _ => {
                        let value = operand(right)?;
                        done.insert(at, Value::defined(value));
                    }
                }
                continue;
            }
            if stage > 0 {
                operands.clear();
                for operand in expr.operands(function) {
                    operands.push(*done.get(&operand).ok_or(Outcome::Malformed)?);
                }
                if let Expr::Call(call) = expr {
                    let value = self.call(at, call, &operands)?;
                    done.insert(at, value);
                    continue;
                }
                if let Expr::Assign { var, .. } = expr {
                    let &[value] = operands.as_slice() else {
                        return Err(Outcome::Malformed);
                    };
                    self.write_var(var, value)?;
                    if let Some(stmt) = self.evaluating {
                        self.observer.assigned_in(stmt, at, value);
                    }
                    done.insert(at, value);
                    continue;
                }
                let value = self.apply(expr, &operands)?;
                done.insert(at, value);
            } else {
                work.push((at, 1));
                let start = work.len();
                for operand in expr.operands(function) {
                    // Operands come before their users, so this ends.
                    if operand >= at {
                        return Err(Outcome::Malformed);
                    }
                    work.push((operand, 0));
                }
                // The first operand on top: evaluated first.
                work.get_mut(start..).unwrap_or_default().reverse();
            }
        }
        done.get(&id).copied().ok_or(Outcome::Malformed)
    }

    /// The value of call expression `at` (call `id`) with its operands'
    /// `values` (a computed callee first), as the observer runs it, or how
    /// the run stops there.
    fn call(&mut self, at: ExprId, id: CallId, values: &[Value]) -> Result<Value, Outcome> {
        let function = self.function;
        let call = function.call(id).ok_or(Outcome::Malformed)?;
        let (target, arguments) = match (call.callee, values) {
            (Callee::Address(address), arguments) => (address, arguments),
            (Callee::Import(slot), arguments) => (self.import(slot)?, arguments),
            (Callee::Expr(_), [target, arguments @ ..]) => {
                (self.known_address(*target)?, arguments)
            }
            (Callee::Expr(_), []) => return Err(Outcome::Malformed),
        };
        let width = function
            .types
            .signature(call.signature)
            .and_then(|signature| signature.returns)
            .and_then(|ty| function.types.value_width(ty));
        let result = self.observer.call(
            &mut *self.machine,
            CallSite::Expr(at),
            target,
            arguments,
            width,
        )?;
        result
            .filter(|result| Some(result.width()) == width)
            .ok_or(Outcome::Malformed)
    }

    /// The value of `expr` with its operands' values (in
    /// [`Expr::operands`] order).
    fn apply(&mut self, expr: Expr, values: &[Value]) -> Result<Value, Outcome> {
        Ok(match (expr, values) {
            (Expr::Const(bits), []) => Value::defined(bits),
            // No exception is thrown here: the exception values are unknown.
            (Expr::Undefined(width, unknown, inputs), []) => self.undefined(width, unknown, inputs),
            (Expr::Exception { width, .. }, []) => Value::unknown(width),
            (Expr::Var(var), []) => self.read_var(var)?,
            (Expr::AddressOf(var), []) => {
                let address = self.memory_address(var)?;
                let width = self.function.types.pointer_width();
                Value::defined(Bits::from_u64(width, address))
            }
            (Expr::Unary(op, _), &[a]) => {
                fits(unary_width(op, a.width()))?;
                interpret::unary(op, a)
            }
            (Expr::Binary(op, ..), &[a, b]) => {
                fits(binary_width(op, a.width(), b.width()))?;
                interpret::binary(op, a, b)
            }
            (Expr::Flag(op, ..), &[a, b, c]) => {
                if a.width() != b.width() || a.width() != c.width() {
                    return Err(Outcome::Malformed);
                }
                interpret::flag(op, a, b, c)
            }
            (Expr::Extract { offset, width, .. }, &[value]) => {
                if width == 0 || u32::from(offset) + u32::from(width) > u32::from(value.width()) {
                    return Err(Outcome::Malformed);
                }
                interpret::extract(value, offset, width)
            }
            (Expr::Concat { .. }, &[high, low]) => {
                if u32::from(high.width()) + u32::from(low.width()) > u32::from(MAX_WIDTH) {
                    return Err(Outcome::Malformed);
                }
                interpret::concat(high, low)
            }
            (Expr::Extend { signed, width, .. }, &[value]) => {
                if width <= value.width() || width > MAX_WIDTH {
                    return Err(Outcome::Malformed);
                }
                interpret::extend(signed, value, width)
            }
            (Expr::Select { .. }, &[condition, then, otherwise]) => {
                if condition.width() != 1 || then.width() != otherwise.width() {
                    return Err(Outcome::Malformed);
                }
                interpret::select(condition, then, otherwise)
            }
            (Expr::Lanes { .. } | Expr::Float { .. }, values) => vector(expr, values)?,
            (Expr::Cast { ty, .. }, &[value]) => {
                if self.function.types.value_width(ty) != Some(value.width()) {
                    return Err(Outcome::Malformed);
                }
                value
            }
            (Expr::Load { ty, .. }, &[address]) => {
                let address = self.known_address(address)?;
                let bytes = self.bytes(ty)?;
                self.machine.load(address, bytes).map_err(Outcome::Fault)?
            }
            (
                Expr::Const(_)
                | Expr::Undefined(..)
                | Expr::Var(_)
                | Expr::AddressOf(_)
                | Expr::Unary(..)
                | Expr::Binary(..)
                | Expr::Logical(..)
                | Expr::Flag(..)
                | Expr::Extract { .. }
                | Expr::Concat { .. }
                | Expr::Extend { .. }
                | Expr::Select { .. }
                | Expr::Cast { .. }
                | Expr::Load { .. }
                | Expr::Call(_)
                | Expr::Exception { .. }
                | Expr::Assign { .. },
                _,
            ) => return Err(Outcome::Malformed),
        })
    }
}

/// The value of a lane-wise or floating-point operation with its operands'
/// values (a float's rounding first).
fn vector(expr: Expr, values: &[Value]) -> Result<Value, Outcome> {
    match (expr, values) {
        (Expr::Lanes { lanes, op, .. }, values) => {
            let widths: Vec<u16> = values.iter().map(Value::width).collect();
            fits(lanes_width(op, lanes, &widths))?;
            Ok(interpret::lanes(op, lanes, values))
        }
        (
            Expr::Float {
                op,
                format,
                lanes,
                output,
                ..
            },
            [rounding, values @ ..],
        ) => {
            let widths: Vec<u16> = values.iter().map(Value::width).collect();
            fits(float_width(
                op,
                format,
                lanes,
                output,
                rounding.width(),
                &widths,
            ))?;
            Ok(interpret::float(
                op, format, lanes, output, *rounding, values,
            ))
        }
        (
            Expr::Const(_)
            | Expr::Undefined(..)
            | Expr::Var(_)
            | Expr::AddressOf(_)
            | Expr::Unary(..)
            | Expr::Binary(..)
            | Expr::Logical(..)
            | Expr::Flag(..)
            | Expr::Extract { .. }
            | Expr::Concat { .. }
            | Expr::Extend { .. }
            | Expr::Select { .. }
            | Expr::Float { .. }
            | Expr::Cast { .. }
            | Expr::Load { .. }
            | Expr::Call(_)
            | Expr::Exception { .. }
            | Expr::Assign { .. },
            _,
        ) => Err(Outcome::Malformed),
    }
}

impl Run<'_> {
    /// An undefined value of `width` bits from `unknown`: the machine's
    /// choice at its site, if it has inputs (those not kept unknown).
    fn undefined(&mut self, width: u16, unknown: Unknown, inputs: Option<InputsId>) -> Value {
        let (
            Unknown::Architecture {
                address,
                site: Some(site),
                ..
            },
            Some(inputs),
        ) = (unknown, inputs)
        else {
            return Value::unknown(width);
        };
        let inputs: Vec<Value> = self
            .function
            .site_inputs(inputs)
            .iter()
            .map(|&input| match input {
                SiteInput::Kept(bits) => Value::defined(bits),
                SiteInput::NotKept(width) => Value::unknown(width),
            })
            .collect();
        let value = self.machine.undefined_at(address, site, &inputs, width);
        if value.width() != width {
            return Value::unknown(width);
        }
        if value.undefined != Bits::ones(width) {
            self.observer.chose(address, site, value);
        }
        value
    }

    /// The number of bytes a value of type `ty` takes in memory.
    fn bytes(&self, ty: TypeId) -> Result<u16, Outcome> {
        match self.function.types.value_width(ty) {
            Some(width) if width.is_multiple_of(8) => Ok(width / 8),
            Some(_) | None => Err(Outcome::Malformed),
        }
    }

    /// The address of variable `id`, which is in memory.
    fn memory_address(&self, id: VarId) -> Result<u64, Outcome> {
        match self.function.var(id).ok_or(Outcome::Malformed)?.kind {
            VarKind::Global(address) => Ok(address),
            VarKind::Frame(offset) => Ok(self.stack.wrapping_add_signed(offset)),
            VarKind::Parameter | VarKind::Local | VarKind::Environment(_) => {
                Err(Outcome::Malformed)
            }
        }
    }

    fn read_var(&mut self, id: VarId) -> Result<Value, Outcome> {
        let variable = self.function.var(id).ok_or(Outcome::Malformed)?;
        match variable.kind {
            VarKind::Parameter | VarKind::Local | VarKind::Environment(_) => self
                .values
                .get(id.0 as usize)
                .copied()
                .ok_or(Outcome::Malformed),
            VarKind::Global(_) | VarKind::Frame(_) => {
                let bytes = self.bytes(variable.ty)?;
                let address = self.memory_address(id)?;
                self.machine.load(address, bytes).map_err(Outcome::Fault)
            }
        }
    }

    fn write_var(&mut self, id: VarId, value: Value) -> Result<(), Outcome> {
        let variable = self.function.var(id).ok_or(Outcome::Malformed)?;
        match variable.kind {
            VarKind::Parameter | VarKind::Local => {
                if self.function.types.value_width(variable.ty) != Some(value.width()) {
                    return Err(Outcome::Malformed);
                }
                let slot = self
                    .values
                    .get_mut(id.0 as usize)
                    .ok_or(Outcome::Malformed)?;
                *slot = value;
                Ok(())
            }
            VarKind::Environment(_) => Err(Outcome::Malformed),
            VarKind::Global(_) | VarKind::Frame(_) => {
                if self.bytes(variable.ty)? * 8 != value.width() {
                    return Err(Outcome::Malformed);
                }
                let address = self.memory_address(id)?;
                self.machine.store(address, value).map_err(Outcome::Fault)
            }
        }
    }

    /// The width of `place`.
    fn place_width(&self, place: Place) -> Result<u16, Outcome> {
        let ty = match place {
            Place::Var(id) => self.function.var(id).ok_or(Outcome::Malformed)?.ty,
            Place::Memory { ty, .. } => ty,
        };
        self.function
            .types
            .value_width(ty)
            .ok_or(Outcome::Malformed)
    }

    /// Writes `value` to `place`, evaluating its address first.
    fn write(&mut self, place: Place, value: Value) -> Result<(), Outcome> {
        match place {
            Place::Var(id) => self.write_var(id, value),
            Place::Memory { address, ty } => {
                let address = self.address(address)?;
                if self.bytes(ty)? * 8 != value.width() {
                    return Err(Outcome::Malformed);
                }
                self.machine.store(address, value).map_err(Outcome::Fault)
            }
        }
    }
}

/// [`Outcome::Malformed`] where L0's width rules are broken.
fn fits<T, E>(rule: Result<T, E>) -> Result<(), Outcome> {
    rule.map(drop).map_err(|_| Outcome::Malformed)
}
