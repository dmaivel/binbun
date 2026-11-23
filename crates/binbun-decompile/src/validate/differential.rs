//! L2's interpreter against L1's ([`differential`]).

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::ops::Range;
use core::sync::atomic::{AtomicBool, Ordering};

use binbun_ast::interpret::{self as ast_interpret, Outcome as L2};
use binbun_ast::ir::{self as ast, Escape, Function as Ast, Origin, VarKind};
use binbun_semantics::bits::Bits;
use binbun_semantics::interpret::{self, Machine, Value};
use binbun_semantics::profile::Choices;
use binbun_ssa::interpret::{self as ssa_interpret, Outcome as L1};
use binbun_ssa::ir::{self, Function, Op, Terminator};

use super::states::{Link, Oracle, Recorder, Setup, State};
use crate::mapping::{CallSite, Mapping, Piece, Source};

/// How many more steps L2's run may take than L1's blocks.
pub const L2_FUEL: u64 = 256;

/// A difference found from one state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Difference {
    /// The state's position.
    pub state: usize,
    /// What differs.
    pub message: String,
}

/// What [`differential`] found.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Report {
    /// States run.
    pub runs: usize,
    /// States where both runs ended the same way.
    pub agreed: usize,
    /// States not compared, by why ([`Skip`]).
    pub skips: BTreeMap<Skip, usize>,
    /// The differences.
    pub differences: Vec<Difference>,
}

impl Report {
    /// Whether no state found a difference.
    pub fn passed(&self) -> bool {
        self.differences.is_empty()
    }

    /// How many states were not compared.
    pub fn skipped(&self) -> usize {
        self.skips.values().sum()
    }
}

/// Why a state was not compared ([`differential`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Skip {
    /// The state's stack pointer is not a known value.
    Stack,
    /// L1's run entered more blocks than the fuel allows.
    L1Fuel,
    /// L2's run took more steps than its fuel allows.
    L2Fuel,
    /// L1's run depends on undefined bits (a branch, an address).
    Undetermined,
    /// L2 ends in a `StackTrick` escape, which L1 has no counterpart for.
    StackTrick,
    /// L2 ends in an `OverlappingCode` escape, which L1 has no
    /// counterpart for.
    OverlappingCode,
}

impl Skip {
    /// What it is, in a few words.
    pub const fn describe(self) -> &'static str {
        match self {
            Self::Stack => "stack pointer unknown",
            Self::L1Fuel => "L1 out of fuel",
            Self::L2Fuel => "L2 out of fuel",
            Self::Undetermined => "L1 depends on undefined bits",
            Self::StackTrick => "L2 stack trick",
            Self::OverlappingCode => "L2 overlapping code",
        }
    }
}

/// Runs `l1` and `l2` from each of `states` under `setup`, on `oracle`'s
/// memory and answers, and compares how they end.
///
/// Both runs start from one [`State`]: L1 with its registers, L2 with the
/// arguments [`Mapping::parameters`] reads from them and its environment
/// variables ([`VarKind::Environment`]) their registers, and the stack
/// pointer, so L2's frame variables are where L1's slots are. The
/// registers dropped from its interface ([`Mapping::dropped`]) are
/// undefined in it: the function is compared on the states its callers
/// start it from, or on states that differ from those only in registers
/// whose values no callee reads (both are the whole program's facts,
/// which the callers' own checks see as what they pass); so are
/// the bits above a declared parameter narrower than its register
/// ([`Mapping::declared`]: the calling convention leaves them
/// unspecified), and a variadic function's unnamed argument registers
/// ([`Mapping::unnamed`]: C reaches them only through the `va_list`, so
/// L2 passes none on to a callee in place). Both read
/// one memory and get one answer per intrinsic question ([`Oracle`]).
/// Neither interpreter runs calls, and neither can resume after one, so
/// runs are compared up to the first call, exit or escape:
///
/// | L1 | L2 |
/// |---|---|
/// | returns to the return address | returns ([`Mapping::returns`] of L1's registers) |
/// | a call (`Op::Call`) | a call with the L1 target value in its provenance, or a `NonStandardCall` escape: same target; arguments ([`CallSite::arguments`]) |
/// | leaves to an address (a tail call) | a call there (arguments as above), or a `ForeignJump` escape |
/// | a system call | a `SystemCall` escape |
/// | an unresolved computed jump | an `UnresolvedJump` escape to the same address |
/// | trap, fault, stop | the same trap, a fault, `unreachable` |
///
/// Then memory: every byte either run wrote, but those of the function's
/// own stack ([`Setup::frame`] bytes below the entry stack pointer, and
/// the [`Setup::shadow`] bytes above the return address) that
/// are not in an L2 frame variable or that a call takes (its stack
/// arguments and pushed return address, which L2 passes as values). Values
/// agree where both define their
/// bits; a call's arguments only where L2 also defines every bit L1 does
/// (a callee may read them all). A fault's address is not compared (L2 may load in another
/// order); neither is memory after one. Not compared at all (skipped): a
/// run out of fuel, an L1 run that depends on undefined bits, an L2
/// `StackTrick` or `OverlappingCode` escape. An L2 run that depends on
/// undefined bits where L1's does not is a difference.
///
/// To go on after a call, both interpreters would need to stop at it with
/// their state and resume from it with the call's results: L1's
/// `Outcome::Call` would carry the call's registers (here L1 is run again
/// on a copy cut at the call to get them) and a resume entry would take
/// the registers the call changes; L2's run would resume after the
/// statement with [`CallSite::results`] written to its result places.
pub fn differential(
    l1: &Function,
    l2: &Ast,
    mapping: &Mapping,
    setup: &Setup<'_>,
    oracle: &dyn Oracle,
    states: &[State],
) -> Report {
    let never = AtomicBool::new(false);
    differential_cancellable(l1, l2, mapping, setup, oracle, states, &never).unwrap_or_default()
}

/// [`differential`], stopped once `cancel` is set: checked between
/// states and before each statement of L2's runs. `None`: cancelled;
/// else the report [`differential`] makes of the same states.
pub fn differential_cancellable(
    l1: &Function,
    l2: &Ast,
    mapping: &Mapping,
    setup: &Setup<'_>,
    oracle: &dyn Oracle,
    states: &[State],
    cancel: &AtomicBool,
) -> Option<Report> {
    let mut run = Run {
        l1,
        l2,
        mapping,
        setup,
        oracle,
        cuts: BTreeMap::new(),
        cancel,
    };
    let mut report = Report::default();
    for (index, state) in states.iter().enumerate() {
        if cancel.load(Ordering::Relaxed) {
            return None;
        }
        report.runs += 1;
        let verdict = run.compare(state);
        if cancel.load(Ordering::Relaxed) {
            return None;
        }
        match verdict {
            Ok(Verdict::Agree) => report.agreed += 1,
            Ok(Verdict::Skip(why)) => *report.skips.entry(why).or_default() += 1,
            Err(message) => report.differences.push(Difference {
                state: index,
                message,
            }),
        }
    }
    Some(report)
}

/// Where the runs of L1 and L2 from one state part ([`localize`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Divergence {
    /// The first L2 assignment whose value differs from the L1 value its
    /// provenance names (`Origin::Value`), with that value and what each
    /// run assigned it; `None` if every assignment agrees (the runs part
    /// where they stop).
    pub assignment: Option<(ast::StmtId, ir::Value, Value, Value)>,
    /// The last L1 block L1's run entered.
    pub l1_stop: Option<ir::BlockId>,
    /// The last L2 statement L2's run started.
    pub l2_stop: Option<ast::StmtId>,
    /// The blocks L1's run entered.
    pub l1_steps: usize,
    /// The statements L2's run started.
    pub l2_steps: usize,
}

/// The most L2 assignments [`localize`] keeps from one run.
const ASSIGNMENTS: usize = 1 << 16;

/// Where the runs of `l1` and `l2` from `state` (as [`differential`]
/// runs them: the same masking, arguments, memory and fuel) part: L1's
/// run traced ([`ssa_interpret::run_traced`]), L2's observed, and each L2
/// assignment's value compared with the same occurrence of the L1 value
/// its statement stands for (the n-th run of an assignment of `v` with the
/// n-th definition of `v`), on the low bits both have and both define.
///
/// # Errors
///
/// The state has no known stack pointer, or L2's arguments cannot be
/// read from it.
pub fn localize(
    l1: &Function,
    l2: &Ast,
    mapping: &Mapping,
    setup: &Setup<'_>,
    oracle: &dyn Oracle,
    state: &State,
) -> Result<Divergence, String> {
    let never = AtomicBool::new(false);
    let run = Run {
        l1,
        l2,
        mapping,
        setup,
        oracle,
        cuts: BTreeMap::new(),
        cancel: &never,
    };
    let state = run.undefine(state);
    let stack = state
        .stack(setup)
        .ok_or_else(|| String::from("the stack pointer is not known"))?;
    let arguments = run.arguments(&state, stack)?;
    // L1 first: L2 takes its values at the sites whose inputs L2 lacks.
    let mut memory = Recorder::new(oracle, setup, &state);
    let (_, trace) = ssa_interpret::run_traced(
        l1,
        setup.declarations,
        &state.registers,
        &mut memory,
        setup.fuel,
    );
    let mut memory = Recorder::new(oracle, setup, &state)
        .with_registers(&state.registers)
        .with_choices(memory.choices);
    let mut watch = Watch::default();
    let _ = ast_interpret::run_observed(
        l2,
        &mut memory,
        &arguments,
        stack,
        setup.fuel.saturating_mul(L2_FUEL),
        &mut watch,
    );
    let mut defined: BTreeMap<ir::Value, Vec<Value>> = BTreeMap::new();
    for (value, contents) in trace.values {
        defined.entry(value).or_default().push(contents);
    }
    let mut seen: BTreeMap<ir::Value, usize> = BTreeMap::new();
    let mut assignment = None;
    for (stmt, expr, contents) in &watch.assigned {
        // An assignment expression has the origins of the statement it
        // was.
        let origins = match *expr {
            Some(expr) => l2.provenance.expr(expr),
            None => l2.provenance.stmt(*stmt),
        };
        let Some(value) = origins.iter().find_map(|origin| {
            if let Origin::Value(value) = origin {
                Some(*value)
            } else {
                None
            }
        }) else {
            continue;
        };
        let occurrence = seen.entry(value).or_default();
        let expected = defined
            .get(&value)
            .and_then(|list| list.get(*occurrence))
            .copied();
        *occurrence += 1;
        if let Some(expected) = expected
            && disagree(&expected, contents)
        {
            assignment = Some((*stmt, value, expected, *contents));
            break;
        }
    }
    Ok(Divergence {
        assignment,
        l1_stop: trace.blocks.last().copied(),
        l2_stop: watch.last,
        l1_steps: trace.blocks.len(),
        l2_steps: watch.statements,
    })
}

/// What [`localize`] hears of L2's run: the statements started, the
/// last, and the assignments' values (at most [`ASSIGNMENTS`]): each
/// statement's, and each assignment expression's with its statement.
#[derive(Default)]
struct Watch {
    statements: usize,
    last: Option<ast::StmtId>,
    assigned: Vec<(ast::StmtId, Option<ast::ExprId>, Value)>,
}

impl ast_interpret::Observer for Watch {
    fn statement(&mut self, id: ast::StmtId) -> Result<(), L2> {
        self.statements += 1;
        self.last = Some(id);
        Ok(())
    }

    fn assigned(&mut self, id: ast::StmtId, values: &[Value]) {
        if self.assigned.len() < ASSIGNMENTS
            && let [value] = values
        {
            self.assigned.push((id, None, *value));
        }
    }

    fn assigned_in(&mut self, id: ast::StmtId, at: ast::ExprId, value: Value) {
        if self.assigned.len() < ASSIGNMENTS {
            self.assigned.push((id, Some(at), value));
        }
    }
}

/// Whether `a` and `b` differ in a low bit both have and both define.
pub(super) fn disagree(a: &Value, b: &Value) -> bool {
    let width = a.width().min(b.width());
    let low = |value: &Value| {
        (
            value.bits.extract(0, width),
            value.undefined.extract(0, width),
        )
    };
    let ((a_bits, a_undefined), (b_bits, b_undefined)) = (low(a), low(b));
    let defined = a_undefined.or(&b_undefined).invert();
    !a_bits.xor(&b_bits).and(&defined).is_zero()
}

/// How a comparison ended, if not with a difference.
enum Verdict {
    Agree,
    Skip(Skip),
}

/// Where L1's run stopped, with the state there.
pub(super) enum Stop<'m> {
    /// A return or leave.
    Exit {
        returned: bool,
        address: u64,
        registers: Vec<Value>,
        memory: Recorder<'m>,
    },
    /// An `Op::Call`: its target value, address, and the state at it.
    Call {
        value: ir::Value,
        target: u64,
        registers: Vec<Value>,
        memory: Recorder<'m>,
    },
    /// A system call, with the profile's values at the sites before it.
    SystemCall(Choices),
    /// Anything else, as the interpreter said.
    Other(L1, Recorder<'m>),
}

impl Stop<'_> {
    /// The profile's values at the sites L1's run reached.
    pub(super) fn choices(&self) -> &Choices {
        match self {
            Self::Exit { memory, .. } | Self::Call { memory, .. } | Self::Other(_, memory) => {
                &memory.choices
            }
            Self::SystemCall(choices) => choices,
        }
    }
}

pub(super) struct Run<'a> {
    pub(super) l1: &'a Function,
    pub(super) l2: &'a Ast,
    pub(super) mapping: &'a Mapping,
    pub(super) setup: &'a Setup<'a>,
    pub(super) oracle: &'a dyn Oracle,
    /// L1 cut at each call reached, by the call's address: the copy and
    /// the call's target value.
    pub(super) cuts: BTreeMap<u64, Option<(Function, ir::Value)>>,
    /// Set: L2's runs stop before their next statement.
    pub(super) cancel: &'a AtomicBool,
}

/// The [`ast_interpret::Observer`] of [`Run::compare`]: stops L2's run
/// (as out of fuel) once `0` is set, and at calls as
/// [`ast_interpret::run`] does.
struct Cancel<'a>(&'a AtomicBool);

impl ast_interpret::Observer for Cancel<'_> {
    fn statement(&mut self, _: ast::StmtId) -> Result<(), L2> {
        if self.0.load(Ordering::Relaxed) {
            Err(L2::OutOfFuel)
        } else {
            Ok(())
        }
    }
}

impl<'a> Run<'a> {
    fn compare(&mut self, state: &State) -> Result<Verdict, String> {
        let undefined;
        let state = if self.mapping.dropped.is_empty()
            && self.mapping.unnamed.is_empty()
            && self.mapping.declared.is_empty()
        {
            state
        } else {
            undefined = self.undefine(state);
            &undefined
        };
        let Some(stack) = state.stack(self.setup) else {
            return Ok(Verdict::Skip(Skip::Stack));
        };
        let arguments = self.arguments(state, stack)?;
        // L1 first: a run of L1 out of fuel or depending on undefined bits
        // skips the state whatever L2 does ([`Self::pair`]), so L2 is not
        // run (on memory over a random state, L2 would otherwise run to
        // its fuel, [`L2_FUEL`] times L1's, for nothing).
        let l1 = self.run_l1(state)?;
        match &l1 {
            Stop::Other(L1::OutOfFuel, _) => return Ok(Verdict::Skip(Skip::L1Fuel)),
            Stop::Other(L1::Undetermined, _) => return Ok(Verdict::Skip(Skip::Undetermined)),
            Stop::Exit { .. } | Stop::Call { .. } | Stop::SystemCall(_) | Stop::Other(..) => {}
        }
        let mut memory = Recorder::new(self.oracle, self.setup, state)
            .with_registers(&state.registers)
            .with_choices(l1.choices().clone());
        let l2 = ast_interpret::run_observed(
            self.l2,
            &mut memory,
            &arguments,
            stack,
            self.setup.fuel.saturating_mul(L2_FUEL),
            &mut Cancel(self.cancel),
        );
        self.pair(state, stack, l1, &l2, &memory)
    }

    /// `state` with the registers dropped from the function's interface
    /// ([`Mapping::dropped`]), a variadic function's unnamed argument
    /// registers ([`Mapping::unnamed`]) and the bits above declared
    /// parameters narrower than their registers ([`Mapping::declared`])
    /// undefined: the states callers start the function from, up to what
    /// nothing reads.
    fn undefine(&self, state: &State) -> State {
        let mut state = state.clone();
        for register in self.mapping.dropped.iter().chain(&self.mapping.unnamed) {
            if let Some(value) = state.registers.get_mut(usize::from(register.0)) {
                *value = Value::unknown(value.width());
            }
        }
        for piece in &self.mapping.declared {
            if let Some(value) = state.registers.get_mut(usize::from(piece.register.0))
                && piece.width < value.width()
            {
                let above = Bits::ones(value.width()).shift_left(u32::from(piece.width));
                value.bits = value.bits.and(&above.invert());
                value.undefined = value.undefined.or(&above);
            }
        }
        state
    }

    /// L2's arguments: [`Mapping::parameters`] of the entry state.
    fn arguments(&self, state: &State, stack: u64) -> Result<Vec<Value>, String> {
        let (parameters, sources) = (&self.l2.parameters, &self.mapping.parameters);
        if parameters.len() != sources.len() {
            return Err(format!(
                "{} parameters, {} mapped",
                parameters.len(),
                sources.len()
            ));
        }
        let mut memory = Recorder::new(self.oracle, self.setup, state);
        parameters
            .iter()
            .zip(sources)
            .enumerate()
            .map(|(index, (&parameter, source))| {
                let value = read(*source, &state.registers, stack, &mut memory)
                    .ok_or_else(|| format!("parameter {index}: cannot read {source:?}"))?;
                let width = self
                    .l2
                    .var(parameter)
                    .and_then(|var| self.l2.types.value_width(var.ty));
                if width != Some(value.width()) {
                    return Err(format!(
                        "parameter {index}: {width:?} bits, mapped to {}",
                        value.width()
                    ));
                }
                Ok(value)
            })
            .collect()
    }

    /// Runs L1 from `state`, and at a call, its copy cut there for the
    /// state at the call.
    pub(super) fn run_l1(&mut self, state: &State) -> Result<Stop<'a>, String> {
        let (declarations, fuel) = (self.setup.declarations, self.setup.fuel);
        let mut memory = Recorder::new(self.oracle, self.setup, state);
        let outcome =
            ssa_interpret::run(self.l1, declarations, &state.registers, &mut memory, fuel);
        Ok(match outcome {
            L1::Exit {
                returned,
                address,
                registers,
            } => Stop::Exit {
                returned,
                address,
                registers,
                memory,
            },
            L1::Call(address) => {
                if self.is_system_call(address) {
                    return Ok(Stop::SystemCall(memory.choices));
                }
                let l1 = self.l1;
                let Some((cut, value)) =
                    self.cuts.entry(address).or_insert_with(|| cut(l1, address))
                else {
                    return Err(format!("L1 stopped at {address:#x}, which has no call"));
                };
                let mut memory = Recorder::new(self.oracle, self.setup, state);
                let outcome =
                    ssa_interpret::run(cut, declarations, &state.registers, &mut memory, fuel);
                let L1::Exit {
                    returned: false,
                    address: target,
                    registers,
                } = outcome
                else {
                    return Err(format!(
                        "L1 cut at the call at {address:#x} ends otherwise: {}",
                        describe_l1(&outcome)
                    ));
                };
                Stop::Call {
                    value: *value,
                    target,
                    registers,
                    memory,
                }
            }
            other @ (L1::Trap(_)
            | L1::Fault(_)
            | L1::Stop
            | L1::Unresolved(_)
            | L1::Undetermined
            | L1::OutOfFuel
            | L1::Malformed) => Stop::Other(other, memory),
        })
    }

    fn is_system_call(&self, address: u64) -> bool {
        self.l1
            .insts
            .iter()
            .any(|inst| inst.address == address && matches!(inst.op, Op::SystemCall { .. }))
    }

    /// Compares L1's stop with L2's outcome, then memory.
    fn pair(
        &self,
        state: &State,
        stack: u64,
        l1: Stop<'_>,
        l2: &L2,
        memory: &Recorder<'_>,
    ) -> Result<Verdict, String> {
        match (l1, l2) {
            (_, L2::OutOfFuel) => Ok(Verdict::Skip(Skip::L2Fuel)),
            (Stop::Other(L1::OutOfFuel, _), _) => Ok(Verdict::Skip(Skip::L1Fuel)),
            (Stop::Other(L1::Undetermined, _), _) => Ok(Verdict::Skip(Skip::Undetermined)),
            (
                _,
                L2::Escape {
                    kind: Escape::StackTrick,
                    ..
                },
            ) => Ok(Verdict::Skip(Skip::StackTrick)),
            (
                _,
                L2::Escape {
                    kind: Escape::OverlappingCode,
                    ..
                },
            ) => Ok(Verdict::Skip(Skip::OverlappingCode)),
            (_, L2::Undetermined) => Err("L2 depends on undefined bits where L1 does not".into()),
            (_, L2::Malformed) => Err("L2's run is malformed".into()),
            (Stop::Other(L1::Malformed, _), _) => Err("L1's run is malformed".into()),
            (
                Stop::Exit {
                    returned,
                    address,
                    registers,
                    memory: own,
                },
                l2,
            ) => {
                let passed = self.exit(state, returned, address, &registers, &own, l2)?;
                self.memory(stack, &own, memory, &passed)
            }
            (
                Stop::Call {
                    value,
                    target,
                    registers,
                    memory: own,
                },
                l2,
            ) => {
                let passed = self.call(value, target, &registers, &own, l2)?;
                self.memory(stack, &own, memory, &passed)
            }
            (Stop::SystemCall(_), l2) => {
                if matches!(
                    l2,
                    L2::Escape {
                        kind: Escape::SystemCall,
                        ..
                    }
                ) {
                    Ok(Verdict::Agree)
                } else {
                    Err(format!("L1 makes a system call, L2 {}", describe_l2(l2)))
                }
            }
            (Stop::Other(outcome, own), l2) => {
                let same = match (&outcome, l2) {
                    (L1::Trap(a), L2::Trap(b)) => a == b,
                    (L1::Stop, L2::Unreachable(_)) => true,
                    (L1::Fault(_), L2::Fault(_)) => return Ok(Verdict::Agree),
                    (
                        L1::Unresolved(address),
                        L2::Escape {
                            kind: Escape::UnresolvedJump,
                            operands,
                            ..
                        },
                    ) => operands.first().and_then(known) == Some(*address),
                    _ => false,
                };
                if !same {
                    return Err(format!(
                        "L1 {}, L2 {}",
                        describe_l1(&outcome),
                        describe_l2(l2)
                    ));
                }
                self.memory(stack, &own, memory, &[])
            }
        }
    }

    /// Compares L1's exit (`returned` or leaving to `address`) with L2's
    /// outcome: the bytes of its own stack a tail call passes.
    fn exit(
        &self,
        state: &State,
        returned: bool,
        address: u64,
        registers: &[Value],
        memory: &Recorder<'_>,
        l2: &L2,
    ) -> Result<Vec<Range<u64>>, String> {
        match l2 {
            L2::Returned(value) if returned && address == state.return_address => {
                let expected = pieces(&self.mapping.returns, registers)?;
                match (expected, value) {
                    (None, None) => Ok(Vec::new()),
                    (Some(expected), Some(value)) if agree(&expected, value) => Ok(Vec::new()),
                    (expected, value) => Err(format!(
                        "returns: L1 {}, L2 {}",
                        show(expected.as_ref()),
                        show(value.as_ref())
                    )),
                }
            }
            L2::Call {
                at,
                target,
                arguments,
            } if !returned => {
                if *target != address {
                    return Err(format!("tail call: L1 to {address:#x}, L2 to {target:#x}"));
                }
                let site = self.site(*at, None)?;
                self.compare_arguments(site, registers, memory, arguments)
            }
            L2::Escape {
                kind: Escape::ForeignJump,
                operands,
                ..
            } if !returned && operands.first().and_then(known) == Some(address) => Ok(Vec::new()),
            other @ (L2::Returned(_)
            | L2::Call { .. }
            | L2::Trap(_)
            | L2::Fault(_)
            | L2::Escape { .. }
            | L2::Unreachable(_)
            | L2::Propagated(_)
            | L2::Undetermined
            | L2::OutOfFuel
            | L2::Malformed) => Err(format!(
                "L1 {} to {address:#x}, L2 {}",
                if returned { "returns" } else { "leaves" },
                describe_l2(other)
            )),
        }
    }

    /// Compares L1's call (of target `value`, to `target`) with L2's
    /// outcome: the bytes of its own stack the call passes.
    fn call(
        &self,
        value: ir::Value,
        target: u64,
        registers: &[Value],
        memory: &Recorder<'_>,
        l2: &L2,
    ) -> Result<Vec<Range<u64>>, String> {
        match l2 {
            L2::Call {
                at,
                target: other,
                arguments,
            } => {
                if *other != target {
                    return Err(format!("call: L1 to {target:#x}, L2 to {other:#x}"));
                }
                let site = self.site(*at, Some(value))?;
                self.compare_arguments(site, registers, memory, arguments)
            }
            L2::Escape {
                kind: Escape::NonStandardCall,
                operands,
                ..
            } if operands.first().and_then(known) == Some(target) => Ok(Vec::new()),
            other @ (L2::Returned(_)
            | L2::Trap(_)
            | L2::Fault(_)
            | L2::Escape { .. }
            | L2::Unreachable(_)
            | L2::Propagated(_)
            | L2::Undetermined
            | L2::OutOfFuel
            | L2::Malformed) => Err(format!("L1 calls {target:#x}, L2 {}", describe_l2(other))),
        }
    }

    /// The call site of L2 call `at` (a statement or an expression): by
    /// the L1 target value in its provenance (`value`, where L1's call is
    /// known).
    fn site(&self, at: ast::CallSite, value: Option<ir::Value>) -> Result<&CallSite, String> {
        let origins = at.origins(&self.l2.provenance);
        let key = origins.iter().find_map(|origin| match origin {
            Origin::Value(candidate)
                if value.is_none_or(|value| value == *candidate)
                    && self.mapping.calls.contains_key(candidate) =>
            {
                Some(*candidate)
            }
            Origin::Value(_)
            | Origin::Instruction(_)
            | Origin::Register(_)
            | Origin::Held(_)
            | Origin::Slot(_)
            | Origin::Block(_)
            | Origin::Absorbed(_)
            | Origin::Proved => None,
        });
        key.and_then(|key| self.mapping.calls.get(&key))
            .ok_or_else(|| match value {
                Some(value) => format!(
                    "L2's call {} does not stand for L1's call of %v{} (or has no call site)",
                    node(at),
                    value.0
                ),
                None => format!("L2's call {} has no call site", node(at)),
            })
    }

    /// Compares L2's call `arguments` with `site`'s in L1's state: the
    /// bytes the call passes on the stack (its stack arguments and a pushed
    /// return address), which L2 passes as values instead.
    ///
    /// An argument agrees only where L2 defines every bit L1 defines: a
    /// callee may read any bit of an argument it takes, so L2 passing
    /// undefined bits where L1 passes a value changes what it gets.
    fn compare_arguments(
        &self,
        site: &CallSite,
        registers: &[Value],
        memory: &Recorder<'_>,
        arguments: &[Value],
    ) -> Result<Vec<Range<u64>>, String> {
        if site.arguments.len() != arguments.len() {
            return Err(format!(
                "call: {} arguments in L2, {} mapped",
                arguments.len(),
                site.arguments.len()
            ));
        }
        let stack = registers
            .get(usize::from(self.setup.stack_pointer.0))
            .and_then(Value::known)
            .map(|bits| bits.low_u64())
            .ok_or("the stack pointer at the call is not known")?;
        let mut memory = Snapshot(memory);
        let mut passed = Vec::new();
        if let Link::Stack { bytes } = self.setup.link {
            passed.push(stack..stack.saturating_add(u64::from(bytes)));
        }
        for (index, (source, argument)) in site.arguments.iter().zip(arguments).enumerate() {
            if let Source::Stack { offset, bytes } = *source {
                let start = stack.wrapping_add_signed(offset);
                passed.push(start..start.saturating_add(u64::from(bytes)));
            }
            let expected = read(*source, registers, stack, &mut memory)
                .ok_or_else(|| format!("argument {index}: cannot read {source:?}"))?;
            if !agree(&expected, argument)
                || !argument
                    .undefined
                    .and(&expected.undefined.invert())
                    .is_zero()
            {
                return Err(format!(
                    "argument {index}: L1 {}, L2 {}",
                    show(Some(&expected)),
                    show(Some(argument))
                ));
            }
        }
        Ok(passed)
    }

    /// Compares the bytes the runs wrote ([`differential`]), but those of
    /// the function's own stack that a call is `passed`.
    fn memory(
        &self,
        stack: u64,
        l1: &Recorder<'_>,
        l2: &Recorder<'_>,
        passed: &[Range<u64>],
    ) -> Result<Verdict, String> {
        let own = stack.saturating_sub(self.setup.frame)..stack;
        let link = match self.setup.link {
            Link::Stack { bytes } => u64::from(bytes),
            Link::Register(_) => 0,
        };
        let home = stack.saturating_add(link);
        let home = home..home.saturating_add(self.setup.shadow);
        let frames: Vec<Range<u64>> = self
            .l2
            .variables
            .iter()
            .filter_map(|var| match var.kind {
                VarKind::Frame(offset) => {
                    let start = stack.wrapping_add_signed(offset);
                    let bytes = self.l2.types.width(var.ty)? / 8;
                    Some(start..start.saturating_add(bytes))
                }
                VarKind::Parameter
                | VarKind::Local
                | VarKind::Global(_)
                | VarKind::Environment(_) => None,
            })
            .collect();
        let addresses = l1.writes.iter().chain(&l2.writes);
        for &address in addresses {
            let within =
                |ranges: &[Range<u64>]| ranges.iter().any(|range| range.contains(&address));
            let mine = own.contains(&address) || home.contains(&address);
            if mine && (!within(&frames) || within(passed)) {
                continue;
            }
            let (a, b) = (l1.byte(address), l2.byte(address));
            let same = match (a, b) {
                (Some((a, a_undefined)), Some((b, b_undefined))) => {
                    (a ^ b) & !(a_undefined | b_undefined) == 0
                }
                (None, None) => true,
                (Some(_), None) | (None, Some(_)) => false,
            };
            if !same {
                return Err(format!(
                    "memory at {address:#x}: L1 {}, L2 {}",
                    show_byte(a),
                    show_byte(b)
                ));
            }
        }
        Ok(Verdict::Agree)
    }
}

/// A copy of `l1` whose block holding the call at `address` ends before
/// it, leaving to its target with the registers at the call; and the
/// call's target value.
fn cut(l1: &Function, address: u64) -> Option<(Function, ir::Value)> {
    for (index, block) in l1.blocks.iter().enumerate() {
        for (position, &id) in block.insts.iter().enumerate() {
            let inst = l1.inst(id)?;
            let Op::Call {
                target,
                memory,
                registers,
                ..
            } = &inst.op
            else {
                continue;
            };
            if inst.address != address {
                continue;
            }
            let mut copy = l1.clone();
            let block = copy.blocks.get_mut(index)?;
            block.insts.truncate(position);
            block.terminator = Terminator::Leave {
                address: *target,
                state: ir::State {
                    registers: registers.clone(),
                    memory: *memory,
                },
                returns: true,
            };
            return Some((copy, *target));
        }
    }
    None
}

/// Reads a recorder's memory through a shared reference (loads do not
/// change it).
pub(super) struct Snapshot<'r, 'm>(pub(super) &'r Recorder<'m>);

/// Where a [`Source`] is read from.
pub(super) trait Bytes {
    fn load(&mut self, address: u64, bytes: u16) -> Option<Value>;
}

impl Bytes for Snapshot<'_, '_> {
    fn load(&mut self, address: u64, bytes: u16) -> Option<Value> {
        let mut values = Vec::with_capacity(usize::from(bytes));
        let mut undefined = Vec::with_capacity(usize::from(bytes));
        for offset in 0..u64::from(bytes) {
            let (value, mask) = self.0.byte(address.checked_add(offset)?)?;
            values.push(value);
            undefined.push(mask);
        }
        let width = bytes.checked_mul(8)?;
        Some(Value {
            bits: Bits::from_le_bytes(width, &values),
            undefined: Bits::from_le_bytes(width, &undefined),
        })
    }
}

impl Bytes for Recorder<'_> {
    fn load(&mut self, address: u64, bytes: u16) -> Option<Value> {
        Machine::load(self, address, bytes).ok()
    }
}

/// The value `source` names in a state: `registers`, the stack pointer
/// `stack`, and `memory`.
pub(super) fn read(
    source: Source,
    registers: &[Value],
    stack: u64,
    memory: &mut dyn Bytes,
) -> Option<Value> {
    match source {
        Source::Register(piece) => piece_of(piece, registers),
        Source::Stack { offset, bytes } => memory.load(stack.wrapping_add_signed(offset), bytes),
    }
}

/// The bits `piece` names in `registers`.
fn piece_of(piece: Piece, registers: &[Value]) -> Option<Value> {
    let register = registers.get(usize::from(piece.register.0))?;
    let end = u32::from(piece.offset) + u32::from(piece.width);
    (piece.width > 0 && end <= u32::from(register.width()))
        .then(|| interpret::extract(*register, piece.offset, piece.width))
}

/// `pieces` of `registers` joined, low bits first; `None` for no pieces.
///
/// # Errors
///
/// A piece is not within its register.
pub(super) fn pieces(pieces: &[Piece], registers: &[Value]) -> Result<Option<Value>, String> {
    let mut joined: Option<Value> = None;
    for &piece in pieces {
        let value = piece_of(piece, registers)
            .ok_or_else(|| format!("{piece:?} does not fit L1's registers"))?;
        joined = Some(match joined {
            Some(low) => interpret::concat(value, low),
            None => value,
        });
    }
    Ok(joined)
}

/// Whether `a` and `b` have one width and agree on the bits both define.
fn agree(a: &Value, b: &Value) -> bool {
    a.width() == b.width()
        && a.bits
            .xor(&b.bits)
            .and(&a.undefined.or(&b.undefined).invert())
            .is_zero()
}

/// The address `value` holds, if defined and pointer-like.
fn known(value: &Value) -> Option<u64> {
    value.known().map(|bits| bits.low_u64())
}

pub(super) fn show(value: Option<&Value>) -> String {
    match value {
        None => "nothing".to_string(),
        Some(value) if value.is_defined() => {
            format!("{:#x}:{}", value.bits.low_u128(), value.width())
        }
        Some(value) => format!(
            "{:#x}:{} (undefined {:#x})",
            value.bits.low_u128(),
            value.width(),
            value.undefined.low_u128()
        ),
    }
}

fn show_byte(byte: Option<(u8, u8)>) -> String {
    match byte {
        None => "a fault".to_string(),
        Some((value, 0)) => format!("{value:#04x}"),
        Some((value, undefined)) => format!("{value:#04x} (undefined {undefined:#04x})"),
    }
}

pub(super) fn describe_l1(outcome: &L1) -> String {
    match outcome {
        L1::Exit {
            returned, address, ..
        } => format!(
            "{} to {address:#x}",
            if *returned { "returns" } else { "leaves" }
        ),
        L1::Trap(trap) => format!("traps ({trap:?})"),
        L1::Fault(fault) => format!("faults at {:#x}", fault.address),
        L1::Stop => "stops".to_string(),
        L1::Call(address) => format!("calls at {address:#x}"),
        L1::Unresolved(address) => format!("jumps to unresolved {address:#x}"),
        L1::Undetermined => "is undetermined".to_string(),
        L1::OutOfFuel => "runs out of fuel".to_string(),
        L1::Malformed => "is malformed".to_string(),
    }
}

/// A call site as the text form names it: `s3` or `e3`.
fn node(at: ast::CallSite) -> String {
    match at {
        ast::CallSite::Stmt(id) => format!("s{}", id.0),
        ast::CallSite::Expr(id) => format!("e{}", id.0),
    }
}

fn describe_l2(outcome: &L2) -> String {
    match outcome {
        L2::Returned(value) => format!("returns {}", show(value.as_ref())),
        L2::Call { at, target, .. } => format!("calls {target:#x} at {}", node(*at)),
        L2::Trap(trap) => format!("traps ({trap:?})"),
        L2::Fault(fault) => format!("faults at {:#x}", fault.address),
        L2::Escape { at, kind, .. } => format!("escapes ({kind:?}) at s{}", at.0),
        L2::Unreachable(at) => format!("reaches unreachable s{}", at.0),
        L2::Propagated(at) => format!("propagates an exception from s{}", at.0),
        L2::Undetermined => "is undetermined".to_string(),
        L2::OutOfFuel => "runs out of fuel".to_string(),
        L2::Malformed => "is malformed".to_string(),
    }
}
