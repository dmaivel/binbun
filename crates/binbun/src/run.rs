//! Running one function from a named example state, recording the values
//! it produces: per C statement and per machine instruction, for the C and
//! the listing to show at their lines' ends.
//!
//! - The state ([`ExampleState`], [`state`]) is a TOML file: arguments by
//!   the prototype, memory regions, globals, registers and stubs; the
//!   ABI sets the stack, the return address and the thread pointer.
//!   Memory nothing sets is unmapped or, in a region, undefined: values
//!   carry undefined-bit masks, and an undefined value is never read as
//!   zero ([`memory`]).
//! - Two runs from the same entry state ([`run_decompiled`]): L2's, whose
//!   statements are the C's, so the values are what the C says
//!   ([`Recording`]); and the machine code's, instruction by instruction
//!   through each one's L0, with the registers and flags it writes
//!   ([`machine`]). Where both return, [`Run::agree`] says whether the
//!   machine's result registers ([`Mapping::returns`]) hold L2's value.
//! - Calls: a callee binbun decompiles is stepped into, [`Options::depth`]
//!   deep, unless a stub of the state matches it; an import, a system
//!   call, an unresolved target, or a callee past the depth with no stub
//!   stops the run with [`Stop::NeedsStub`] naming it. Nothing is faked.
//! - A run stops at a fault (non-canonical or unmapped, at the statement
//!   or instruction taking it), a trap, a decision on undefined bits,
//!   [`Options::steps`], or when cancelled.
//! - On a processor's profile ([`Options::profile`]), the values the
//!   architecture leaves undefined at its sites are the profile's rules':
//!   the machine code's run evaluates them on each instruction's inputs,
//!   and L2's on the inputs it kept, else takes the machine code's at that
//!   instruction (L2 keeps only the inputs lowering knows as constants).
//!   An occurrence that used one is marked ([`Occurrence::profile`]).
//!   The C does not change.

// A run's stop and the interpreter's outcome hold values, once per run.
#![expect(clippy::result_large_err, reason = "stops hold values")]

pub mod machine;
pub mod memory;
pub mod state;

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use binbun_ast::interpret::{self as l2, Observer, Outcome};
use binbun_ast::ir::{CallSite, Escape, ExprId, Function as Ast, Node, StmtId, VarKind};
use binbun_decompile::lower::Convention;
use binbun_decompile::mapping::{Mapping, Source};
use binbun_decompile::validate::{Link, Setup};
use binbun_print::layout::Span;
use binbun_semantics::interpret::{self as l0, Fault, Machine, Value};
use binbun_semantics::ir::{SiteId, Trap};

use crate::Database;
use crate::cfg::{Destination, Exit, FunctionId};
use crate::decompile::{Decompiled, Options as Decompiling, View};
use crate::profile::{Profile, fits};
use crate::target::{Abi, convention, setup};
pub use machine::Instructions;
pub use memory::{FaultKind, Fill, Memory};
pub use state::{Entry, ExampleState};

/// How a run goes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Options {
    /// The view whose L2 runs (the callees stepped into decompiled in it
    /// too).
    pub view: View,
    /// Steps at most: L2 statements, and machine instructions, each run
    /// (callees' included).
    pub steps: u64,
    /// How deep calls are stepped into.
    pub depth: usize,
    /// Occurrences kept per statement and instruction (the count goes on).
    pub cap: usize,
    /// Whether the machine code runs too.
    pub instructions: bool,
    /// The processor run on, if one: its profile's values at the sites
    /// (with one, the machine code runs whatever
    /// [`instructions`](Self::instructions) says: L2 takes its values
    /// where it lacks a site's inputs). None: the architecture, those
    /// values unknown.
    pub profile: Option<Arc<Profile>>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            view: View::Exact,
            steps: 100_000,
            depth: 4,
            cap: 64,
            instructions: true,
            profile: None,
        }
    }
}

/// What a callee is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CalleeKind {
    /// A function of the program.
    Function(FunctionId),
    /// An import (its address in [`memory::IMPORTS`], or a thunk jumping
    /// to it).
    Import,
    /// The operating system.
    SystemCall,
    /// No function binbun knows.
    Unresolved,
}

/// A call's target.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Callee {
    /// Its address (an import's: its thunk's, or in [`memory::IMPORTS`]).
    pub address: u64,
    /// Its name (a function's symbol, an import's name).
    pub name: Option<String>,
    /// What it is.
    pub kind: CalleeKind,
}

impl std::fmt::Display for Callee {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match (&self.name, self.kind) {
            (_, CalleeKind::SystemCall) => f.write_str("a system call"),
            (Some(name), _) => write!(f, "{name} ({:#x})", self.address),
            (None, _) => write!(f, "{:#x}", self.address),
        }
    }
}

/// Why a call needs a stub.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Need {
    /// It calls an import.
    Import,
    /// It enters the operating system.
    SystemCall,
    /// Its target is no function binbun knows.
    Unresolved,
    /// It is deeper than [`Options::depth`].
    Depth,
    /// The callee does not decompile, or its parameters are not the
    /// call's arguments.
    Interface,
}

/// How a run ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Stop {
    /// It returned, with the value (L2's; the machine's: `None`, its
    /// registers in [`Instructions::registers`]).
    Returned(Option<Value>),
    /// A call needs a stub.
    NeedsStub {
        /// The call's target.
        callee: Callee,
        /// Why.
        need: Need,
    },
    /// An access faulted.
    Fault {
        /// The address.
        address: u64,
        /// Whether it was a store.
        write: bool,
        /// Why.
        kind: FaultKind,
    },
    /// A trap (`binbun_trap`, a machine check).
    Trap(Trap),
    /// A decision, address or target depended on undefined bits.
    Undetermined,
    /// C cannot say what comes next ([`Escape`]).
    Escape(Escape),
    /// An `unreachable` was reached, or an exception propagated.
    Unreachable,
    /// [`Options::steps`] were taken.
    OutOfSteps,
    /// It was cancelled.
    Cancelled,
    /// The code is malformed (does not decode, does not verify).
    Malformed,
}

impl Stop {
    /// A short name of its kind.
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Returned(_) => "returned",
            Self::NeedsStub { .. } => "needs a stub",
            Self::Fault { .. } => "fault",
            Self::Trap(_) => "trap",
            Self::Undetermined => "undetermined",
            Self::Escape(_) => "escape",
            Self::Unreachable => "unreachable",
            Self::OutOfSteps => "out of steps",
            Self::Cancelled => "cancelled",
            Self::Malformed => "malformed",
        }
    }
}

impl std::fmt::Display for Stop {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Returned(Some(value)) => write!(f, "returned {}", show(value)),
            Self::Returned(None) => f.write_str("returned"),
            Self::NeedsStub { callee, need } => write!(f, "needs a stub: {callee} ({need:?})"),
            Self::Fault {
                address,
                write,
                kind,
            } => write!(
                f,
                "fault: {} {address:#x} ({kind:?})",
                if *write { "store to" } else { "load from" }
            ),
            Self::Trap(trap) => write!(f, "trap: {trap:?}"),
            Self::Escape(escape) => write!(f, "escape: {escape:?}"),
            Self::Undetermined
            | Self::Unreachable
            | Self::OutOfSteps
            | Self::Cancelled
            | Self::Malformed => f.write_str(self.kind()),
        }
    }
}

/// Every occurrence of something run: how many, and the first ones kept.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Trace<T> {
    /// How many times it ran.
    pub count: u64,
    /// The first [`Options::cap`] occurrences.
    pub shown: Vec<T>,
}

impl<T> Default for Trace<T> {
    fn default() -> Self {
        Self {
            count: 0,
            shown: Vec::new(),
        }
    }
}

impl<T> Trace<T> {
    /// Counts `occurrence`, keeping it if fewer than `cap` are.
    pub fn push(&mut self, occurrence: T, cap: usize) {
        self.count += 1;
        if self.shown.len() < cap {
            self.shown.push(occurrence);
        }
    }
}

/// One run of a statement.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Occurrence {
    /// The iteration of the innermost loop around it (from 1); a loop's
    /// own decision: the iteration it enters, or ends after.
    pub iteration: Option<u64>,
    /// What it wrote: an assignment's value, a call's result, an
    /// intrinsic's outputs, the value returned; for an `if` or a loop's
    /// decision, what the assignment expressions of its condition wrote
    /// (`if ((v = f()) != 0)`), in the order made.
    pub values: Vec<Value>,
    /// The way it decided: `if` then (0) or else (1); a loop entering its
    /// body (0) or ending (1); a switch's arm.
    pub decided: Option<usize>,
    /// Whether a value of a site that the run's processor profile gave
    /// went into it (an undefined value the architecture leaves to the
    /// processor): what it wrote or decided holds on that processor.
    pub profile: bool,
}

/// How a call was run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum How {
    /// Stepped into: the callee's run.
    Stepped(Box<Recording>),
    /// A stub of the state.
    Stubbed,
    /// Not: the run stopped there.
    Stopped,
}

/// One call made.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Call {
    /// Where (an L2 call statement or expression).
    pub at: CallSite,
    /// What it called.
    pub callee: Callee,
    /// The arguments.
    pub arguments: Vec<Value>,
    /// The result.
    pub result: Option<Value>,
    /// How it ran.
    pub how: How,
}

/// One L2 run: per statement, its occurrences.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Recording {
    /// The function's entry.
    pub entry: u64,
    /// Each statement run, by id.
    pub statements: BTreeMap<StmtId, Trace<Occurrence>>,
    /// Each loop's iterations, in all.
    pub iterations: BTreeMap<StmtId, u64>,
    /// The calls made, in order.
    pub calls: Vec<Call>,
    /// How it ended.
    pub stop: Stop,
    /// The statement it ended at, if one.
    pub at: Option<StmtId>,
}

impl Recording {
    /// The statements on each line of the C (`text`, its tokens `spans`)
    /// with their traces ([`statement_lines`]): what a view shows at each
    /// line's end.
    pub fn by_line(&self, text: &str, spans: &[Span]) -> BTreeMap<usize, Vec<StmtId>> {
        let mut lines: BTreeMap<usize, Vec<StmtId>> = BTreeMap::new();
        for (id, line) in statement_lines(text, spans) {
            if self.statements.contains_key(&id) {
                lines.entry(line).or_default().push(id);
            }
        }
        lines
    }
}

/// A run: L2's, and the machine code's.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Run {
    /// L2's: the C's values.
    pub c: Recording,
    /// The machine code's, if run.
    pub machine: Option<Instructions>,
    /// Where both returned: whether the machine's result registers hold
    /// L2's value; where both stopped at a call needing a stub: whether
    /// it is the same callee.
    pub agree: Option<bool>,
}

/// The line (from 0) of each statement's first token in `text`.
pub fn statement_lines(text: &str, spans: &[Span]) -> BTreeMap<StmtId, usize> {
    let mut lines = BTreeMap::new();
    let mut line = 0;
    let mut scanned = 0;
    for span in spans {
        let Some(Node::Stmt(id)) = span.node else {
            continue;
        };
        let start = span.range.start;
        if start >= scanned {
            line += text
                .get(scanned..start)
                .map_or(0, |gap| gap.matches('\n').count());
            scanned = start;
        }
        lines.entry(id).or_insert(line);
    }
    lines
}

/// `value` as a view shows it: decimal if small (signed if negative),
/// else hexadecimal; `?` for undefined digits, `?` alone if no bit is.
pub fn show(value: &Value) -> String {
    let Some(bits) = value.known() else {
        let text = state::format_value(value);
        return if text == "undefined" {
            "?".to_owned()
        } else {
            text
        };
    };
    if value.width() == 1 {
        return u8::from(!bits.is_zero()).to_string();
    }
    if value.width() <= 64 {
        let unsigned = bits.low_u64();
        let shift = 64 - u32::from(value.width());
        let signed = (unsigned << shift).cast_signed() >> shift;
        if unsigned < 0x1_0000 {
            return unsigned.to_string();
        }
        if (-0x1_0000..0).contains(&signed) {
            return signed.to_string();
        }
    }
    state::format_value(value)
}

/// A stub of the state, parsed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Stub {
    /// Its target: an address, or a name.
    target: Result<u64, String>,
    returns: state::Operand,
    copy: Option<[state::Operand; 3]>,
}

impl Stub {
    /// `stub` parsed.
    ///
    /// # Errors
    ///
    /// An operand is malformed.
    pub fn parse(stub: &state::Stub) -> Result<Self, String> {
        let target = state::parse_value(&stub.target, 64)
            .ok()
            .and_then(|value| value.known())
            .map(|bits| bits.low_u64())
            .ok_or_else(|| stub.target.clone());
        let returns = state::Operand::parse(stub.returns.as_deref().unwrap_or("unknown"), 64)?;
        let copy = stub
            .copy
            .as_ref()
            .map(|copy| -> Result<_, String> {
                Ok([
                    state::Operand::parse(&copy.from, 64)?,
                    state::Operand::parse(&copy.to, 64)?,
                    state::Operand::parse(&copy.bytes, 64)?,
                ])
            })
            .transpose()?;
        Ok(Self {
            target,
            returns,
            copy,
        })
    }

    /// Whether it is `callee`'s.
    fn matches(&self, callee: &Callee) -> bool {
        match &self.target {
            Ok(address) => *address == callee.address,
            Err(name) => callee.name.as_deref() == Some(name),
        }
    }

    /// The highest argument it reads, if any.
    fn arguments(&self) -> Option<usize> {
        let operands = core::iter::once(self.returns).chain(self.copy.into_iter().flatten());
        operands
            .filter_map(|operand| match operand {
                state::Operand::Argument(k) => Some(k),
                state::Operand::Value(_) | state::Operand::Unknown => None,
            })
            .max()
    }

    /// Its result, `width` bits wide, from the call's `arguments`.
    fn result(&self, arguments: &[Value], width: u16) -> Value {
        self.returns.value(arguments, width)
    }

    /// Makes its copy on `machine`, with the call's `arguments`.
    fn copy(&self, machine: &mut dyn Machine, arguments: &[Value]) -> Result<(), Fault> {
        let Some([from, to, bytes]) = self.copy else {
            return Ok(());
        };
        let known = |operand: state::Operand| {
            operand
                .value(arguments, 64)
                .known()
                .map(|bits| bits.low_u64())
        };
        let (Some(from), Some(to), Some(bytes)) = (known(from), known(to), known(bytes)) else {
            return Err(Fault {
                address: 0,
                write: false,
            });
        };
        for offset in 0..bytes.min(1 << 24) {
            let byte = machine.load(from.wrapping_add(offset), 1)?;
            machine.store(to.wrapping_add(offset), byte)?;
        }
        Ok(())
    }
}

/// What every part of one run shares.
pub(crate) struct Context<'d, 'a> {
    database: &'d Database<'a>,
    options: &'d Options,
    cancel: &'d AtomicBool,
    /// The function run's entry.
    entry: u64,
    setup: Setup<'static>,
    convention: Convention,
    abi: Abi,
    stubs: Vec<Stub>,
    /// Steps L2 has taken, callees' included.
    steps: Cell<u64>,
    /// The callees decompiled, in the run's view.
    decompiled: RefCell<BTreeMap<FunctionId, Option<Arc<Decompiled>>>>,
}

impl Context<'_, '_> {
    /// What `address` is as a call's target.
    fn resolve(&self, address: u64) -> Callee {
        let database = self.database;
        let image = database.image();
        let import = |slot: u64| image.imports.iter().find(|import| import.slot == slot);
        if let Some(index) = memory::import_index(image, address) {
            return Callee {
                address,
                name: image.imports.get(index).map(|import| import.name.clone()),
                kind: CalleeKind::Import,
            };
        }
        let Some(id) = database.function_at(address) else {
            return Callee {
                address,
                name: database.name(address).map(str::to_owned),
                kind: CalleeKind::Unresolved,
            };
        };
        let program = database.program();
        let thunk = database
            .function(id)
            .and_then(|function| match function.blocks.as_slice() {
                [only] => {
                    if let Exit::Jump(destination) = program.blocks.get(*only)?.exit {
                        Some(destination)
                    } else {
                        None
                    }
                }
                _ => None,
            });
        match thunk {
            Some(Destination::Import(slot)) if let Some(import) = import(slot) => Callee {
                address,
                name: Some(import.name.clone()),
                kind: CalleeKind::Import,
            },
            // A thunk through a slot that is no import's (an `IRELATIVE`
            // one): where it goes is the run's, unresolved here.
            Some(Destination::Pointer(_) | Destination::Indirect) => Callee {
                address,
                name: database.data_name(address),
                kind: CalleeKind::Unresolved,
            },
            _ => Callee {
                address,
                name: database.data_name(address),
                kind: CalleeKind::Function(id),
            },
        }
    }

    /// The state's stub for `callee`, if one.
    fn stub(&self, callee: &Callee) -> Option<&Stub> {
        self.stubs.iter().find(|stub| stub.matches(callee))
    }

    /// Function `id` decompiled in the run's view, kept.
    fn decompiled(&self, id: FunctionId) -> Option<Arc<Decompiled>> {
        let mut cache = self.decompiled.borrow_mut();
        cache
            .entry(id)
            .or_insert_with(|| {
                let options = Decompiling {
                    style: None,
                    view: self.options.view,
                    ..Decompiling::default()
                };
                self.database
                    .decompile(id, &options)
                    .result
                    .ok()
                    .map(Arc::new)
            })
            .clone()
    }
}

/// The L2 observer of one function's run.
struct Observe<'c, 'd, 'a> {
    context: &'c Context<'d, 'a>,
    function: &'c Ast,
    /// Its entry stack pointer.
    stack: u64,
    /// How deep in calls stepped into it is.
    depth: usize,
    /// The innermost loop around each statement.
    loops: Vec<Option<StmtId>>,
    /// The iteration each loop is in.
    counters: BTreeMap<StmtId, u64>,
    recording: Recording,
    /// The statement whose occurrence was kept last, if it was.
    open: Option<StmtId>,
    /// What the assignment expressions of the loop condition being
    /// evaluated wrote, for the occurrence of its decision.
    condition: Vec<Value>,
    /// Whether the profile gave a site's value since the last statement
    /// started, for a loop's decision.
    chosen: bool,
    /// How a callee's run stopped, which stops this one.
    pending: Option<Stop>,
}

/// The innermost loop around each statement of `function`.
fn innermost_loops(function: &Ast) -> Vec<Option<StmtId>> {
    let mut loops = vec![None; function.stmts.len()];
    let mut work = vec![(&function.body, None)];
    while let Some((block, around)) = work.pop() {
        for &id in block {
            if let Some(slot) = loops.get_mut(id.0 as usize) {
                *slot = around;
            }
            let Some(stmt) = function.stmt(id) else {
                continue;
            };
            let inner = if is_loop(function, id) {
                Some(id)
            } else {
                around
            };
            for child in stmt.blocks() {
                work.push((child, inner));
            }
        }
    }
    loops
}

/// Whether statement `id` of `function` is a loop.
fn is_loop(function: &Ast, id: StmtId) -> bool {
    use binbun_ast::ir::Stmt;
    matches!(
        function.stmt(id),
        Some(Stmt::While { .. } | Stmt::DoWhile { .. } | Stmt::For { .. })
    )
}

impl Observer for Observe<'_, '_, '_> {
    fn statement(&mut self, id: StmtId) -> Result<(), Outcome> {
        let context = self.context;
        if context.cancel.load(Ordering::Relaxed) {
            self.pending = Some(Stop::Cancelled);
            return Err(Outcome::OutOfFuel);
        }
        let steps = context.steps.get() + 1;
        context.steps.set(steps);
        if steps > context.options.steps {
            return Err(Outcome::OutOfFuel);
        }
        self.chosen = false;
        self.recording.at = Some(id);
        if is_loop(self.function, id) {
            self.counters.insert(id, 0);
            self.open = None;
            return Ok(());
        }
        let iteration = self
            .loops
            .get(id.0 as usize)
            .copied()
            .flatten()
            .and_then(|outer| self.counters.get(&outer).copied());
        let trace = self.recording.statements.entry(id).or_default();
        let kept = trace.shown.len() < context.options.cap;
        trace.push(
            Occurrence {
                iteration,
                ..Occurrence::default()
            },
            context.options.cap,
        );
        self.open = kept.then_some(id);
        Ok(())
    }

    fn assigned(&mut self, id: StmtId, values: &[Value]) {
        if self.open == Some(id)
            && let Some(last) = self
                .recording
                .statements
                .get_mut(&id)
                .and_then(|trace| trace.shown.last_mut())
        {
            last.values = values.to_vec();
        }
    }

    fn assigned_in(&mut self, id: StmtId, _: ExprId, value: Value) {
        // A loop's decision is an occurrence of its own, made after the
        // condition; an `if`'s is the occurrence its statement opened.
        if is_loop(self.function, id) {
            self.condition.push(value);
        } else if self.open == Some(id)
            && let Some(last) = self
                .recording
                .statements
                .get_mut(&id)
                .and_then(|trace| trace.shown.last_mut())
        {
            last.values.push(value);
        }
    }

    fn decided(&mut self, id: StmtId, arm: usize) {
        if is_loop(self.function, id) {
            let counter = self.counters.get(&id).copied().unwrap_or(0);
            let occurrence = Occurrence {
                iteration: Some(counter + u64::from(arm == 0)),
                values: std::mem::take(&mut self.condition),
                decided: Some(arm),
                profile: std::mem::take(&mut self.chosen),
            };
            let cap = self.context.options.cap;
            self.recording
                .statements
                .entry(id)
                .or_default()
                .push(occurrence, cap);
            return;
        }
        if self.open == Some(id)
            && let Some(last) = self
                .recording
                .statements
                .get_mut(&id)
                .and_then(|trace| trace.shown.last_mut())
        {
            last.decided = Some(arm);
        }
    }

    fn iteration(&mut self, id: StmtId) {
        *self.counters.entry(id).or_default() += 1;
        *self.recording.iterations.entry(id).or_default() += 1;
    }

    fn chose(&mut self, _: u64, _: SiteId, _: Value) {
        self.chosen = true;
        if let Some(id) = self.open
            && let Some(last) = self
                .recording
                .statements
                .get_mut(&id)
                .and_then(|trace| trace.shown.last_mut())
        {
            last.profile = true;
        }
    }

    fn call(
        &mut self,
        machine: &mut dyn Machine,
        at: CallSite,
        target: u64,
        arguments: &[Value],
        width: Option<u16>,
    ) -> Result<Option<Value>, Outcome> {
        let context = self.context;
        let mut call = Call {
            at,
            callee: context.resolve(target),
            arguments: arguments.to_vec(),
            result: None,
            how: How::Stopped,
        };
        let outcome = self.run_call(machine, &mut call, width);
        self.recording.calls.push(call);
        outcome
    }
}

impl Observe<'_, '_, '_> {
    /// Runs `call` (its result `width` bits wide, if one is taken) on
    /// `machine`: by a stub, stepped into, or not (the run stops).
    fn run_call(
        &mut self,
        machine: &mut dyn Machine,
        call: &mut Call,
        width: Option<u16>,
    ) -> Result<Option<Value>, Outcome> {
        let context = self.context;
        let stop = |need| Stop::NeedsStub {
            callee: call.callee.clone(),
            need,
        };
        if let Some(stub) = context.stub(&call.callee) {
            stub.copy(machine, &call.arguments)
                .map_err(Outcome::Fault)?;
            call.result = width.map(|width| stub.result(&call.arguments, width));
            call.how = How::Stubbed;
            return Ok(call.result);
        }
        let need = match call.callee.kind {
            CalleeKind::Function(_) if self.depth >= context.options.depth => Need::Depth,
            CalleeKind::Function(id) => {
                return self.step_into(machine, id, call, width);
            }
            CalleeKind::Import => Need::Import,
            CalleeKind::SystemCall => Need::SystemCall,
            CalleeKind::Unresolved => Need::Unresolved,
        };
        self.pending = Some(stop(need));
        Err(Outcome::Malformed)
    }

    /// Steps into function `id` for `call`.
    fn step_into(
        &mut self,
        machine: &mut dyn Machine,
        id: FunctionId,
        call: &mut Call,
        width: Option<u16>,
    ) -> Result<Option<Value>, Outcome> {
        let context = self.context;
        let interface = Stop::NeedsStub {
            callee: call.callee.clone(),
            need: Need::Interface,
        };
        let Some(decompiled) = context.decompiled(id) else {
            self.pending = Some(interface);
            return Err(Outcome::Malformed);
        };
        let callee = &decompiled.l2;
        let widths: Option<Vec<u16>> = callee
            .parameters
            .iter()
            .map(|&parameter| {
                callee
                    .var(parameter)
                    .and_then(|var| callee.types.value_width(var.ty))
            })
            .collect();
        let Some(widths) = widths.filter(|widths| widths.len() == call.arguments.len()) else {
            self.pending = Some(interface);
            return Err(Outcome::Malformed);
        };
        let arguments: Vec<Value> = call
            .arguments
            .iter()
            .zip(widths)
            .map(|(&argument, width)| state::fit(argument, width))
            .collect();
        let stack = callee_stack(self.function, self.stack, &context.setup);
        let mut inner = Observe::new(context, callee, stack, self.depth + 1);
        let outcome = l2::run_observed(
            callee,
            machine,
            &arguments,
            stack,
            context.options.steps.saturating_mul(4),
            &mut inner,
        );
        let recording = inner.finish(&outcome);
        let result = if let Stop::Returned(value) = &recording.stop {
            Ok(width.map(|width| {
                value.map_or_else(|| Value::unknown(width), |value| state::fit(value, width))
            }))
        } else {
            self.pending = Some(recording.stop.clone());
            Err(Outcome::Malformed)
        };
        call.result = result.clone().ok().flatten();
        call.how = How::Stepped(Box::new(recording));
        result
    }
}

/// Where a callee's frame goes: 256 bytes below the frame variables of
/// `caller` (entry stack pointer `stack`), 16-byte aligned, less the
/// return address the call pushes.
fn callee_stack(caller: &Ast, stack: u64, setup: &Setup<'_>) -> u64 {
    let low = caller
        .variables
        .iter()
        .filter_map(|var| match var.kind {
            VarKind::Frame(offset) => Some(offset),
            VarKind::Parameter | VarKind::Local | VarKind::Global(_) | VarKind::Environment(_) => {
                None
            }
        })
        .min()
        .unwrap_or(0)
        .min(0);
    let below = stack.wrapping_add_signed(low).wrapping_sub(256) & !15;
    match setup.link {
        Link::Stack { bytes } => below.wrapping_sub(u64::from(bytes)),
        Link::Register(_) => below,
    }
}

impl<'c, 'd, 'a> Observe<'c, 'd, 'a> {
    fn new(context: &'c Context<'d, 'a>, function: &'c Ast, stack: u64, depth: usize) -> Self {
        Self {
            context,
            function,
            stack,
            depth,
            loops: innermost_loops(function),
            counters: BTreeMap::new(),
            recording: Recording {
                entry: function.address,
                statements: BTreeMap::new(),
                iterations: BTreeMap::new(),
                calls: Vec::new(),
                stop: Stop::Malformed,
                at: None,
            },
            open: None,
            condition: Vec::new(),
            chosen: false,
            pending: None,
        }
    }

    /// The recording, the run having ended with `outcome`.
    fn finish(mut self, outcome: &Outcome) -> Recording {
        self.recording.stop = match self.pending.take() {
            Some(stop) => stop,
            None => match *outcome {
                Outcome::Returned(value) => Stop::Returned(value),
                Outcome::Call { target, .. } => Stop::NeedsStub {
                    callee: Callee {
                        address: target,
                        name: None,
                        kind: CalleeKind::Unresolved,
                    },
                    need: Need::Unresolved,
                },
                Outcome::Trap(trap) => Stop::Trap(trap),
                Outcome::Fault(fault) => Stop::Fault {
                    address: fault.address,
                    write: fault.write,
                    kind: if memory::canonical(fault.address) {
                        FaultKind::Unmapped
                    } else {
                        FaultKind::NonCanonical
                    },
                },
                Outcome::Escape {
                    kind: Escape::SystemCall,
                    ..
                } => Stop::NeedsStub {
                    callee: Callee {
                        address: 0,
                        name: None,
                        kind: CalleeKind::SystemCall,
                    },
                    need: Need::SystemCall,
                },
                // Control leaves through an unresolved jump or a call C
                // cannot say (its arguments unknown to L2): it needs a
                // stub of its target, named.
                Outcome::Escape {
                    kind: Escape::UnresolvedJump | Escape::NonStandardCall | Escape::ForeignJump,
                    ref operands,
                    ..
                } if let Some(target) = operands.first().and_then(Value::known) => {
                    Stop::NeedsStub {
                        callee: self.context.resolve(target.low_u64()),
                        need: Need::Unresolved,
                    }
                }
                Outcome::Escape { kind, .. } => Stop::Escape(kind),
                Outcome::Unreachable(_) | Outcome::Propagated(_) => Stop::Unreachable,
                Outcome::Undetermined => Stop::Undetermined,
                Outcome::OutOfFuel => Stop::OutOfSteps,
                Outcome::Malformed => Stop::Malformed,
            },
        };
        self.recording
    }
}

/// L2's arguments: [`Mapping::parameters`] of the entry state.
fn arguments(
    function: &Ast,
    mapping: &Mapping,
    entry: &mut Entry<'_>,
) -> Result<Vec<Value>, String> {
    if function.parameters.len() != mapping.parameters.len() {
        return Err(format!(
            "{} parameters, {} mapped",
            function.parameters.len(),
            mapping.parameters.len()
        ));
    }
    function
        .parameters
        .iter()
        .zip(&mapping.parameters)
        .map(|(&parameter, source)| {
            let value = match *source {
                Source::Register(piece) => entry
                    .registers
                    .get(usize::from(piece.register.0))
                    .map(|&value| l0::extract(value, piece.offset, piece.width)),
                Source::Stack { offset, bytes } => entry
                    .memory
                    .load(entry.stack.wrapping_add_signed(offset), bytes)
                    .ok(),
            };
            let value = value.ok_or_else(|| format!("cannot read {source:?}"))?;
            let width = function
                .var(parameter)
                .and_then(|var| function.types.value_width(var.ty));
            if width != Some(value.width()) {
                return Err(format!(
                    "a parameter of {width:?} bits is mapped to {}",
                    value.width()
                ));
            }
            Ok(value)
        })
        .collect()
}

/// Runs function `id` of `database`, decompiled in `options.view`, from
/// `state` ([`run_decompiled`]).
///
/// # Errors
///
/// It does not decompile, or the state does not fit it.
pub fn run(
    database: &Database<'_>,
    id: FunctionId,
    state: &ExampleState,
    options: &Options,
    cancel: &AtomicBool,
) -> Result<Run, String> {
    let decompiling = Decompiling {
        style: None,
        view: options.view,
        ..Decompiling::default()
    };
    let decompiled = database.decompile(id, &decompiling).result?;
    run_decompiled(database, &decompiled, state, options, cancel)
}

/// Runs `decompiled` (a function of `database`, in `options.view`) from
/// `state`: its L2, and, if [`Options::instructions`] or on a profile, its
/// machine code first (see the module documentation). `cancel` stops it
/// at the next step.
///
/// # Errors
///
/// The image's code is not lifted, or the state does not fit the
/// function (a malformed value, more arguments than parameters), or the
/// profile is another architecture's.
pub fn run_decompiled(
    database: &Database<'_>,
    decompiled: &Decompiled,
    state: &ExampleState,
    options: &Options,
    cancel: &AtomicBool,
) -> Result<Run, String> {
    let image = database.image();
    if let Some(profile) = &options.profile {
        fits(profile, image)?;
    }
    let entry_address = decompiled.l1.entry;
    let setup = setup(image, entry_address)?;
    let context = Context {
        database,
        options,
        cancel,
        entry: entry_address,
        convention: convention(image, setup.declarations),
        abi: Abi::of(image).map_err(|error| error.0)?,
        setup,
        stubs: state
            .stubs
            .iter()
            .map(Stub::parse)
            .collect::<Result<_, _>>()?,
        steps: Cell::new(0),
        decompiled: RefCell::new(BTreeMap::new()),
    };
    let names = |name: &str| {
        database
            .names()
            .iter()
            .find(|(_, candidate)| *candidate == name)
            .map(|(&address, _)| address)
    };
    let mut entry = state.entry(
        image,
        &context.setup,
        &context.convention,
        &decompiled.mapping,
        &names,
    )?;
    entry.memory.set_profile(options.profile.clone());
    let machine = (options.instructions || options.profile.is_some())
        .then(|| machine::run(&context, entry_address, &entry));
    if let Some(machine) = &machine {
        entry.memory.set_choices(machine.choices.clone());
    }
    let l2 = &decompiled.l2;
    let arguments = arguments(l2, &decompiled.mapping, &mut entry)?;
    let mut observe = Observe::new(&context, l2, entry.stack, 0);
    let outcome = l2::run_observed(
        l2,
        &mut entry.memory,
        &arguments,
        entry.stack,
        options.steps.saturating_mul(4),
        &mut observe,
    );
    let c = observe.finish(&outcome);
    let agree = machine
        .as_ref()
        .and_then(|machine| agreement(&decompiled.mapping, &c.stop, machine));
    Ok(Run { c, machine, agree })
}

/// Whether the L2 run's `stop` and the machine's agree ([`Run::agree`]).
fn agreement(mapping: &Mapping, stop: &Stop, machine: &Instructions) -> Option<bool> {
    match (stop, &machine.stop) {
        (Stop::Returned(value), Stop::Returned(_)) => {
            let mut pieces = mapping.returns.iter();
            let first = pieces.next();
            let expected = first.and_then(|first| {
                let mut whole = l0::extract(
                    *machine.registers.get(usize::from(first.register.0))?,
                    first.offset,
                    first.width,
                );
                for piece in pieces {
                    let part = l0::extract(
                        *machine.registers.get(usize::from(piece.register.0))?,
                        piece.offset,
                        piece.width,
                    );
                    whole = l0::concat(part, whole);
                }
                Some(whole)
            });
            Some(match (value, expected) {
                (None, None) => true,
                (Some(a), Some(b)) => same(a, &b),
                (Some(_), None) | (None, Some(_)) => false,
            })
        }
        (Stop::NeedsStub { callee: a, .. }, Stop::NeedsStub { callee: b, .. }) => {
            Some(a.address == b.address || (a.name.is_some() && a.name == b.name))
        }
        _ => None,
    }
}

/// Whether `a` and `b` agree on the bits both define.
pub fn same(a: &Value, b: &Value) -> bool {
    a.width() == b.width()
        && a.bits.and(&a.undefined.or(&b.undefined).invert())
            == b.bits.and(&a.undefined.or(&b.undefined).invert())
}

/// A state, named `name`, for the callee of the call `caller` (decompiled)
/// makes at the instruction at `at`: its arguments those of the first run
/// of the call in `given`'s recording (with the given state's fill,
/// regions, globals and stubs), else the constants the call passes, else
/// undefined.
///
/// # Errors
///
/// The caller makes no call at `at`.
pub fn call_site_state(
    caller: &Decompiled,
    at: u64,
    given: Option<(&ExampleState, &Recording)>,
    name: &str,
) -> Result<ExampleState, String> {
    use binbun_ast::ir::{Expr, Origin, Stmt};
    let l2 = &caller.l2;
    let here = |origins: &[Origin]| origins.contains(&Origin::Instruction(at));
    let statement = l2
        .stmts
        .iter()
        .zip(0u32..)
        .find_map(|(stmt, id)| match stmt {
            Stmt::Call { call, .. } if here(l2.provenance.stmt(StmtId(id))) => {
                Some((CallSite::Stmt(StmtId(id)), call))
            }
            Stmt::Call { .. }
            | Stmt::Assign { .. }
            | Stmt::Intrinsic { .. }
            | Stmt::Expr(_)
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
            | Stmt::Try { .. }
            | Stmt::VaStart { .. } => None,
        });
    let site = statement.or_else(|| {
        l2.exprs.iter().zip(0u32..).find_map(|(expr, id)| {
            let id = ExprId(id);
            let &Expr::Call(call) = expr else {
                return None;
            };
            here(l2.provenance.expr(id)).then_some(())?;
            Some((CallSite::Expr(id), l2.call(call)?))
        })
    });
    let (site, call) = site.ok_or_else(|| format!("no call at {at:#x}"))?;
    let recorded = given.and_then(|(_, recording)| {
        recording
            .calls
            .iter()
            .find(|call| call.at == site)
            .map(|call| call.arguments.clone())
    });
    let arguments = match recorded {
        Some(values) => values.iter().map(state::format_value).collect(),
        None => call
            .arguments
            .iter()
            .map(|&argument| match l2.expr(argument) {
                Some(&Expr::Const(bits)) => state::format_value(&Value::defined(bits)),
                _ => "undefined".to_owned(),
            })
            .collect(),
    };
    let mut state = given.map_or_else(|| ExampleState::scratch(name), |(state, _)| state.clone());
    name.clone_into(&mut state.name);
    state.function = None;
    state.arguments = arguments;
    state.registers.clear();
    Ok(state)
}
