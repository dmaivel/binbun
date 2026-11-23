//! A function checked against its L1 on demand, in a view: the structure
//! check ([`structure`]), then L1 and L2 run from random states
//! and from states shaped by the function's types ([`shaped_states`]:
//! terminated strings and vectors, objects of a struct's size, small
//! counts) ([`differential`]) on the image's memory ([`ImageOracle`]),
//! with a fuel ([`Options::fuel`]; the interactive check's is
//! [`INTERACTIVE_FUEL`]). Exact: the
//! exact L1; the reading view: against the assumed L1 it is made from
//! (`binbun::decompile::reading_l1`), the sound comparison the corpus
//! test makes. The states come from a seed (the function's entry unless
//! given), so a run is reproducible; a difference comes with its state,
//! which [`replay`] runs again, and where the runs part ([`localize`]).
//! On a processor's profile ([`Options::profile`]), both runs take its
//! values at the sites, so a state that depends on one is checked, not
//! skipped (L2, which keeps only the inputs lowering knows as constants,
//! takes L1's value at that instruction where it lacks one).

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use binbun_ast::ir::{Function as Ast, Origin, StmtId};
use binbun_decompile::itanium::Exceptions;
use binbun_decompile::mapping::Mapping;
use binbun_decompile::validate::{
    Divergence, Mismatch, OnProcessor, Oracle, Report, Setup, Skip, State, differential,
    differential_cancellable, localize, random_states, shaped_states, structure,
};
use binbun_ssa::ir::{Definition, Function};

use super::{Lowered, lower, lower_prepared};
use crate::Database;
use crate::cfg::FunctionId;
use crate::decompile::{Interfaces, Prepared, View, stream_parallel};
use crate::memory::ImageOracle;
use crate::profile::{Profile, fits};
use crate::target::setup;

/// The random states a function runs from by default: the corpus
/// tests' count for libc and bash.
pub const STATES: usize = 16;

/// The states shaped by the function's types ([`shaped_states`]) a
/// function runs from by default, besides the random ones.
pub const SHAPED: usize = 8;

/// The fuel (blocks L1 may enter per run) of the check the GUI runs while
/// the user waits: a tenth of the full check's, so a state whose loop
/// does not end costs a tenth; a state out of fuel is skipped, so a
/// function every state of which runs out of it is not conclusive at
/// that fuel, not agreed ([`Verdict::NotCheckable`] says so).
pub const INTERACTIVE_FUEL: u64 = 1_000;

/// How to verify.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Options {
    /// The view checked.
    pub view: View,
    /// How many random states.
    pub states: usize,
    /// How many states shaped by the function's types, besides the random
    /// ones (none where no parameter has a shape).
    pub shaped: usize,
    /// The seed of the states; `None`: the function's entry.
    pub seed: Option<u64>,
    /// The blocks L1 may enter per run; `None`: the full check's
    /// ([`setup`]'s).
    pub fuel: Option<u64>,
    /// The passes not run, by name.
    pub disabled: Vec<String>,
    /// The processor the runs are on, if one: its profile's values at the
    /// sites. None: the architecture, a state depending on those values
    /// skipped.
    pub profile: Option<Arc<Profile>>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            view: View::Exact,
            states: STATES,
            shaped: SHAPED,
            seed: None,
            fuel: None,
            disabled: Vec::new(),
            profile: None,
        }
    }
}

impl Options {
    /// The check the GUI runs while the user waits on `view`: the default
    /// states with [`INTERACTIVE_FUEL`].
    pub fn interactive(view: View) -> Self {
        Self {
            view,
            fuel: Some(INTERACTIVE_FUEL),
            ..Self::default()
        }
    }
}

/// One function verified.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verification {
    /// The function's entry.
    pub entry: u64,
    /// The view checked.
    pub view: View,
    /// What the checks found.
    pub verdict: Verdict,
    /// The fuel the runs had (blocks L1 may enter per run).
    pub fuel: u64,
    /// What preparing and lowering it took (but what the database had
    /// computed already).
    pub lowering: Duration,
    /// What the checks took.
    pub checking: Duration,
}

/// What the checks found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Its control flow is L1's and every state compared agreed.
    Agreed(Agreement),
    /// It differs from L1.
    Differs(Difference),
    /// It cannot be checked: why.
    NotCheckable(String),
}

/// The states of a function that agreed.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Agreement {
    /// States run.
    pub states: usize,
    /// States where both runs ended the same way.
    pub agreed: usize,
    /// States not compared, by why.
    pub skips: BTreeMap<Skip, usize>,
}

/// How a function differs from its L1.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Difference {
    /// Its control flow is not L1's (the structure check).
    Structure(Mismatch),
    /// A state where L1's and L2's runs end differently.
    Run(Box<Counterexample>),
}

/// A state where L1's and L2's runs end differently.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Counterexample {
    /// The seed of the states.
    pub seed: u64,
    /// The state's position among them.
    pub index: usize,
    /// The state: every register and the return address, as both runs
    /// start from it ([`replay`] runs it again).
    pub state: State,
    /// What differs, as the differential says it.
    pub message: String,
    /// Where the runs part, if it can be found.
    pub divergence: Option<Divergence>,
    /// The machine instructions where they part: those of the first
    /// assignment that differs (its statement's and its L1 value's), else
    /// those where L2's run stopped.
    pub addresses: Vec<u64>,
}

impl Counterexample {
    /// The L2 statement where the runs part: the first assignment that
    /// differs, else where L2's run stopped.
    pub fn statement(&self) -> Option<StmtId> {
        let divergence = self.divergence.as_ref()?;
        divergence
            .assignment
            .map(|(stmt, ..)| stmt)
            .or(divergence.l2_stop)
    }
}

/// Function `id` of `database` verified under `options`.
pub fn verify(database: &Database<'_>, id: FunctionId, options: &Options) -> Verification {
    let never = AtomicBool::new(false);
    verify_cancellable(database, id, options, &never)
        .unwrap_or_else(|| not_checkable(0, options, String::new(), Duration::ZERO))
}

/// [`verify`], stopped once `cancel` is set (after lowering, between
/// states, inside L2's runs): `None` if it was, else the verification
/// [`verify`] makes. For a session's worker: a check can take minutes.
pub fn verify_cancellable(
    database: &Database<'_>,
    id: FunctionId,
    options: &Options,
    cancel: &AtomicBool,
) -> Option<Verification> {
    let entry = database.function(id).map_or(0, |function| function.entry);
    let start = Instant::now();
    let lowered = lower(database, id, options.view, &options.disabled);
    let lowering = start.elapsed();
    let (lowered, _) = match lowered {
        Ok(lowered) => lowered,
        Err(message) => return Some(not_checkable(entry, options, message, lowering)),
    };
    if cancel.load(Ordering::Relaxed) {
        return None;
    }
    verify_lowered(database, &lowered, options, lowering, cancel)
}

/// Every function of `database` verified under `options` on `threads`
/// threads, handed to `ready` callees first as the stream hands them over
/// (as [`Database::decompile_all_on`] decompiles them; the funclets built
/// into their functions included).
pub fn verify_all(
    database: &Database<'_>,
    options: &Options,
    threads: usize,
    ready: impl FnMut(Verification),
) {
    let callers = database.callers_in(options.view, &options.disabled);
    stream_parallel(
        database.image(),
        database.program(),
        database.summaries(),
        &callers,
        &options.disabled,
        threads,
        |id, prepared, interfaces| verify_prepared(database, id, prepared, interfaces, options),
        ready,
    );
}

/// Function `id`, `prepared` with its callees' `interfaces`, verified.
fn verify_prepared(
    database: &Database<'_>,
    id: FunctionId,
    prepared: Result<Prepared, String>,
    interfaces: &Interfaces,
    options: &Options,
) -> Verification {
    let entry = database.function(id).map_or(0, |function| function.entry);
    let start = Instant::now();
    let lowered = prepared.and_then(|prepared| {
        lower_prepared(
            database,
            prepared,
            interfaces,
            options.view,
            &options.disabled,
        )
    });
    let lowering = start.elapsed();
    let never = AtomicBool::new(false);
    match lowered {
        Ok(lowered) => verify_lowered(database, &lowered, options, lowering, &never)
            .unwrap_or_else(|| not_checkable(entry, options, String::new(), lowering)),
        Err(message) => not_checkable(entry, options, message, lowering),
    }
}

fn not_checkable(
    entry: u64,
    options: &Options,
    message: String,
    lowering: Duration,
) -> Verification {
    Verification {
        entry,
        view: options.view,
        verdict: Verdict::NotCheckable(message),
        fuel: options.fuel.unwrap_or_default(),
        lowering,
        checking: Duration::ZERO,
    }
}

/// `lowered` (of `database`) verified under `options`; `None`: `cancel`
/// was set.
fn verify_lowered(
    database: &Database<'_>,
    lowered: &Lowered,
    options: &Options,
    lowering: Duration,
    cancel: &AtomicBool,
) -> Option<Verification> {
    let start = Instant::now();
    let entry = lowered.entry;
    let setup = setup(database.image(), entry).map(|mut setup| {
        setup.fuel = options.fuel.unwrap_or(setup.fuel);
        setup
    });
    let fuel = setup
        .as_ref()
        .map_or(options.fuel.unwrap_or_default(), |setup| setup.fuel);
    let image = ImageOracle::new(database.image());
    let processor;
    let oracle: &dyn Oracle = match &options.profile {
        Some(profile) => {
            processor = OnProcessor {
                oracle: &image,
                profile,
            };
            &processor
        }
        None => &image,
    };
    let fitting = match &options.profile {
        Some(profile) => fits(profile, database.image()),
        None => Ok(()),
    };
    let verdict = match setup.and_then(|setup| fitting.map(|()| setup)) {
        Ok(setup) => check_cancellable(
            &lowered.prepared.l1,
            &lowered.l2,
            &lowered.mapping,
            &Checks {
                setup: &setup,
                oracle,
                exceptions: database.exceptions(),
                states: options.states,
                shaped: options.shaped,
                seed: options.seed.unwrap_or(entry),
            },
            cancel,
        )?,
        Err(message) => Verdict::NotCheckable(message),
    };
    Some(Verification {
        entry,
        view: options.view,
        verdict,
        fuel,
        lowering,
        checking: start.elapsed(),
    })
}

/// What [`check`] runs under.
pub struct Checks<'a> {
    /// The architecture, convention and fuel.
    pub setup: &'a Setup<'a>,
    /// The memory and intrinsics' answers both runs share.
    pub oracle: &'a dyn Oracle,
    /// The image's exceptions (the structure check reads them).
    pub exceptions: &'a Exceptions,
    /// How many random states.
    pub states: usize,
    /// How many states shaped by the function's types, besides
    /// ([`shaped_states`]).
    pub shaped: usize,
    /// Their seed.
    pub seed: u64,
}

impl std::fmt::Debug for Checks<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Checks")
            .field("setup", self.setup)
            .field("states", &self.states)
            .field("shaped", &self.shaped)
            .field("seed", &self.seed)
            .finish_non_exhaustive()
    }
}

/// `l2` (with its `mapping`) checked against `l1`: the structure check,
/// then the differential from `checks.states` random states of
/// `checks.seed` and, after them, `checks.shaped` states shaped by the
/// function's types ([`shaped_states`]). The first state that differs is
/// the counterexample; a function every state of which is skipped is not
/// checkable, and where every one ran out of fuel, not conclusive at
/// that fuel.
pub fn check(l1: &Function, l2: &Ast, mapping: &Mapping, checks: &Checks<'_>) -> Verdict {
    let never = AtomicBool::new(false);
    check_cancellable(l1, l2, mapping, checks, &never)
        .unwrap_or_else(|| Verdict::NotCheckable(String::new()))
}

/// [`check`], stopped once `cancel` is set (between states and inside
/// L2's runs): `None` if it was, else the verdict [`check`] gives.
pub fn check_cancellable(
    l1: &Function,
    l2: &Ast,
    mapping: &Mapping,
    checks: &Checks<'_>,
    cancel: &AtomicBool,
) -> Option<Verdict> {
    if let Err(mismatch) = structure(l1, l2, checks.exceptions) {
        return Some(Verdict::Differs(Difference::Structure(mismatch)));
    }
    let mut states = random_states(checks.setup, checks.states, checks.seed);
    states.extend(shaped_states(
        checks.setup,
        l2,
        mapping,
        checks.shaped,
        checks.seed,
    ));
    let report = differential_cancellable(
        l1,
        l2,
        mapping,
        checks.setup,
        checks.oracle,
        &states,
        cancel,
    )?;
    if let Some(difference) = report.differences.first()
        && let Some(state) = states.get(difference.state)
    {
        let divergence = localize(l1, l2, mapping, checks.setup, checks.oracle, state).ok();
        let addresses = divergence
            .as_ref()
            .map(|divergence| addresses(l1, l2, divergence))
            .unwrap_or_default();
        return Some(Verdict::Differs(Difference::Run(Box::new(
            Counterexample {
                seed: checks.seed,
                index: difference.state,
                state: state.clone(),
                message: difference.message.clone(),
                divergence,
                addresses,
            },
        ))));
    }
    if report.agreed == 0 && report.runs > 0 {
        let why: Vec<String> = report
            .skips
            .iter()
            .map(|(skip, count)| format!("{} {count}", skip.describe()))
            .collect();
        if report
            .skips
            .keys()
            .all(|skip| matches!(skip, Skip::L1Fuel | Skip::L2Fuel))
        {
            return Some(Verdict::NotCheckable(format!(
                "not conclusive at a fuel of {} blocks: every state ran out of it: {}",
                checks.setup.fuel,
                why.join(", ")
            )));
        }
        return Some(Verdict::NotCheckable(format!(
            "every state skipped: {}",
            why.join(", ")
        )));
    }
    Some(Verdict::Agreed(Agreement {
        states: report.runs,
        agreed: report.agreed,
        skips: report.skips,
    }))
}

/// `l2` (with its `mapping`) run against `l1` from `state` alone: the
/// differential's report of that one state, to reproduce a
/// [`Counterexample`].
pub fn replay(
    l1: &Function,
    l2: &Ast,
    mapping: &Mapping,
    setup: &Setup<'_>,
    oracle: &dyn Oracle,
    state: &State,
) -> Report {
    differential(l1, l2, mapping, setup, oracle, core::slice::from_ref(state))
}

/// The machine instructions where the runs part ([`Counterexample::addresses`]).
fn addresses(l1: &Function, l2: &Ast, divergence: &Divergence) -> Vec<u64> {
    let mut out: Vec<u64> = Vec::new();
    let statement = divergence
        .assignment
        .map(|(stmt, ..)| stmt)
        .or(divergence.l2_stop);
    if let Some(stmt) = statement {
        out.extend(l2.provenance.stmt(stmt).iter().filter_map(|origin| {
            if let Origin::Instruction(address) = origin {
                Some(*address)
            } else {
                None
            }
        }));
    }
    if let Some((_, value, ..)) = divergence.assignment
        && let Some(info) = l1.value(value)
        && let Definition::Result { inst, .. } = info.definition
        && let Some(inst) = l1.inst(inst)
    {
        out.push(inst.address);
    }
    out.sort_unstable();
    out.dedup();
    out
}
