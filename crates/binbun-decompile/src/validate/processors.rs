//! Whether a function behaves differently on different processors: L1
//! run from the same states on each processor's profile
//! ([`Oracle::profile`]), observing what the differential observes of L1
//! (how the run ends; the return value, a call's target and arguments;
//! memory written outside the function's own stack), up to the first
//! call ([`compare_processors`]).

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

use binbun_ast::ir::Function as Ast;
use binbun_semantics::bits::Bits;
use binbun_semantics::interpret::Value;
use binbun_semantics::ir::SiteId;
use binbun_semantics::profile::Choices;
use binbun_ssa::interpret::Outcome as L1;
use binbun_ssa::ir::Function;

use super::differential::{Run, Snapshot, Stop, describe_l1, disagree, pieces, read, show};
use super::states::{Link, Oracle, Recorder, Setup, State};
use crate::mapping::Mapping;

/// What L1's run on one processor gave from one state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Output {
    /// It returned, with the return value (`None`: none).
    Returned(Option<Value>),
    /// It left to an address (a tail call).
    Left(u64),
    /// It called `target` with `arguments` (those L2's call passes, where
    /// lowering made one).
    Called {
        /// The call's target.
        target: u64,
        /// Its arguments.
        arguments: Vec<Value>,
    },
    /// It made a system call.
    SystemCall,
    /// It ended otherwise: how (a trap, a fault, ...).
    Other(String),
}

impl Output {
    /// As a report says it: `returns 0x1:32`.
    pub fn describe(&self) -> String {
        match self {
            Self::Returned(value) => format!("returns {}", show(value.as_ref())),
            Self::Left(address) => format!("leaves to {address:#x}"),
            Self::Called { target, arguments } => {
                let arguments: Vec<String> =
                    arguments.iter().map(|value| show(Some(value))).collect();
                format!("calls {target:#x}({})", arguments.join(", "))
            }
            Self::SystemCall => "makes a system call".into(),
            Self::Other(how) => how.clone(),
        }
    }
}

/// The site whose values decided a difference: the first instruction (by
/// address) where the processors' values at a site differ.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Decider {
    /// The instruction.
    pub address: u64,
    /// The site.
    pub site: SiteId,
    /// Per processor (in the oracles' order), its first value there that
    /// differs from another's (unknown if its run never reached it).
    pub values: Vec<Value>,
}

/// A state from which the processors' runs differ.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Differing {
    /// The state's position.
    pub state: usize,
    /// What differs (`the return value`, `memory at 0x...`).
    pub what: String,
    /// Per processor, how its run ended.
    pub outputs: Vec<Output>,
    /// Where a store differs (the runs ending alike), the byte.
    pub stored: Option<Stored>,
    /// The site that decided, if the runs' values at one differ.
    pub decider: Option<Decider>,
}

/// A byte written outside the function's own stack that the processors'
/// runs leave different.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Stored {
    /// Its address.
    pub address: u64,
    /// Per processor, the byte its run left there (undefined bits, or
    /// unknown where the run has no memory).
    pub bytes: Vec<Value>,
}

/// What [`compare_processors`] found.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Comparison {
    /// States run.
    pub runs: usize,
    /// States whose runs ended the same way on every processor.
    pub same: usize,
    /// States not compared: a run out of fuel, or depending on undefined
    /// bits (a site the profile has no rule for), or the stack pointer
    /// unknown.
    pub skipped: usize,
    /// States whose runs reached a site on some processor.
    pub reaching: usize,
    /// Per site, the states reaching it.
    pub reached: BTreeMap<SiteId, usize>,
    /// The states whose runs differ, in order.
    pub differing: Vec<Differing>,
}

/// Runs `l1` from each of `states` once per processor of `oracles` (each
/// with its [`Oracle::profile`]) and compares how the runs end. `l2` and
/// `mapping` say what a return and a call pass (the return value's and
/// the arguments' registers and stack slots). `None`: `cancel` was set.
pub fn compare_processors(
    l1: &Function,
    l2: &Ast,
    mapping: &Mapping,
    setup: &Setup<'_>,
    oracles: &[&dyn Oracle],
    states: &[State],
    cancel: &AtomicBool,
) -> Option<Comparison> {
    let mut runs: Vec<Run<'_>> = oracles
        .iter()
        .map(|&oracle| Run {
            l1,
            l2,
            mapping,
            setup,
            oracle,
            cuts: BTreeMap::new(),
            cancel,
        })
        .collect();
    let mut comparison = Comparison::default();
    for (index, state) in states.iter().enumerate() {
        if cancel.load(Ordering::Relaxed) {
            return None;
        }
        comparison.runs += 1;
        let Some(stack) = state.stack(setup) else {
            comparison.skipped += 1;
            continue;
        };
        let stops: Result<Vec<Stop<'_>>, String> =
            runs.iter_mut().map(|run| run.run_l1(state)).collect();
        let Ok(stops) = stops else {
            comparison.skipped += 1;
            continue;
        };
        let sites: BTreeSet<SiteId> = stops
            .iter()
            .flat_map(|stop| stop.choices().made().map(|(_, site, _)| site))
            .collect();
        if !sites.is_empty() {
            comparison.reaching += 1;
        }
        for site in sites {
            *comparison.reached.entry(site).or_default() += 1;
        }
        let (Some(run), Some(first)) = (runs.first(), stops.first()) else {
            continue;
        };
        if stops
            .iter()
            .any(|stop| matches!(stop, Stop::Other(L1::OutOfFuel | L1::Undetermined, _)))
        {
            comparison.skipped += 1;
            continue;
        }
        let seen: Vec<Output> = stops.iter().map(|stop| output(run, stop)).collect();
        let mut store = None;
        let what = seen.first().and_then(|ended| {
            seen.iter().zip(&stops).skip(1).find_map(|(other, stop)| {
                differ(ended, other).or_else(|| {
                    let address = memory(setup, stack, first, stop)?;
                    store = Some(address);
                    Some(format!("memory at {address:#x}"))
                })
            })
        });
        match what {
            None => comparison.same += 1,
            Some(what) => {
                let choices: Vec<&Choices> = stops.iter().map(Stop::choices).collect();
                let stored = store.map(|address| Stored {
                    address,
                    bytes: stops
                        .iter()
                        .map(|stop| {
                            recorder(stop).and_then(|r| r.byte(address)).map_or_else(
                                || Value::unknown(8),
                                |(byte, undefined)| Value {
                                    bits: Bits::from_u64(8, u64::from(byte & !undefined)),
                                    undefined: Bits::from_u64(8, u64::from(undefined)),
                                },
                            )
                        })
                        .collect(),
                });
                comparison.differing.push(Differing {
                    state: index,
                    what,
                    outputs: seen,
                    stored,
                    decider: decider(&choices),
                });
            }
        }
    }
    Some(comparison)
}

/// How `stop` ended, as compared.
fn output(run: &Run<'_>, stop: &Stop<'_>) -> Output {
    match stop {
        Stop::Exit {
            returned: true,
            registers,
            ..
        } => Output::Returned(pieces(&run.mapping.returns, registers).ok().flatten()),
        Stop::Exit { address, .. } => Output::Left(*address),
        Stop::Call {
            value,
            target,
            registers,
            memory,
        } => {
            let stack = registers
                .get(usize::from(run.setup.stack_pointer.0))
                .and_then(Value::known)
                .map(|bits| bits.low_u64());
            let mut bytes = Snapshot(memory);
            let arguments = match (run.mapping.calls.get(value), stack) {
                (Some(site), Some(stack)) => site
                    .arguments
                    .iter()
                    .map(|&source| {
                        read(source, registers, stack, &mut bytes)
                            .unwrap_or_else(|| Value::unknown(64))
                    })
                    .collect(),
                _ => Vec::new(),
            };
            Output::Called {
                target: *target,
                arguments,
            }
        }
        Stop::SystemCall(_) => Output::SystemCall,
        Stop::Other(outcome, _) => Output::Other(describe_l1(outcome)),
    }
}

/// What differs between two runs' ends, if anything: a value differs
/// where both define a bit.
fn differ(a: &Output, b: &Output) -> Option<String> {
    let values = |a: &[Value], b: &[Value]| {
        a.len() != b.len() || a.iter().zip(b).any(|(a, b)| disagree(a, b))
    };
    match (a, b) {
        (Output::Returned(a), Output::Returned(b)) => match (a, b) {
            (Some(a), Some(b)) if disagree(a, b) => Some("the return value".into()),
            (Some(_), None) | (None, Some(_)) => Some("the return value".into()),
            _ => None,
        },
        (Output::Left(a), Output::Left(b)) => (a != b).then(|| "where it leaves to".into()),
        (
            Output::Called {
                target: a,
                arguments: x,
            },
            Output::Called {
                target: b,
                arguments: y,
            },
        ) => {
            if a == b {
                values(x, y).then(|| "the call's arguments".into())
            } else {
                Some("the call's target".into())
            }
        }
        (Output::SystemCall, Output::SystemCall) => None,
        (Output::Other(a), Output::Other(b)) => (a != b).then(|| "how it ends".into()),
        _ => Some("how it ends".into()),
    }
}

/// The address of the first byte written outside the function's own
/// stack (from `stack`, the entry stack pointer) that the runs `a` and
/// `b` leave different, where both define its bits.
fn memory(setup: &Setup<'_>, stack: u64, a: &Stop<'_>, b: &Stop<'_>) -> Option<u64> {
    let (Some(a), Some(b)) = (recorder(a), recorder(b)) else {
        return None;
    };
    a.writes
        .iter()
        .chain(&b.writes)
        .find(|&&address| {
            !own(setup, stack, address)
                && match (a.byte(address), b.byte(address)) {
                    (Some((x, x_undefined)), Some((y, y_undefined))) => {
                        (x ^ y) & !(x_undefined | y_undefined) != 0
                    }
                    (None, None) => false,
                    (Some(_), None) | (None, Some(_)) => true,
                }
        })
        .copied()
}

/// The memory of a run that stopped as `stop`.
fn recorder<'s, 'm>(stop: &'s Stop<'m>) -> Option<&'s Recorder<'m>> {
    match stop {
        Stop::Exit { memory, .. } | Stop::Call { memory, .. } | Stop::Other(_, memory) => {
            Some(memory)
        }
        Stop::SystemCall(_) => None,
    }
}

/// The first instruction and site where the processors' values differ.
fn decider(choices: &[&Choices]) -> Option<Decider> {
    let mut all: BTreeMap<(u64, SiteId), Vec<Option<&[Value]>>> = BTreeMap::new();
    for (position, made) in choices.iter().enumerate() {
        for (address, site, values) in made.made() {
            let slot = all
                .entry((address, site))
                .or_insert_with(|| vec![None; choices.len()]);
            if let Some(slot) = slot.get_mut(position) {
                *slot = Some(values);
            }
        }
    }
    all.into_iter().find_map(|((address, site), per)| {
        let longest = per.iter().flatten().map(|values| values.len()).max()?;
        let at = (0..longest).find(|&k| {
            let values: Vec<Option<&Value>> = per
                .iter()
                .map(|values| values.and_then(|values| values.get(k)))
                .collect();
            values.iter().any(|a| {
                values.iter().any(|b| match (a, b) {
                    (Some(a), Some(b)) => disagree(a, b),
                    _ => a.is_some() != b.is_some(),
                })
            })
        })?;
        let values = per
            .iter()
            .map(|values| {
                values
                    .and_then(|values| values.get(at))
                    .copied()
                    .unwrap_or_else(|| Value::unknown(1))
            })
            .collect();
        Some(Decider {
            address,
            site,
            values,
        })
    })
}

/// Whether `address` is in the function's own stack: the frame below the
/// entry stack pointer `stack`, the return address and the home space.
fn own(setup: &Setup<'_>, stack: u64, address: u64) -> bool {
    let link = match setup.link {
        Link::Stack { bytes } => u64::from(bytes),
        Link::Register(_) => 0,
    };
    let below = stack.saturating_sub(setup.frame)..stack;
    let above = stack..stack.saturating_add(link + setup.shadow);
    below.contains(&address) || above.contains(&address)
}
