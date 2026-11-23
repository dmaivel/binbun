//! Whether a function behaves differently on different processors:
//! verify's states (random, and shaped by the function's types) run
//! through the function's exact L1 on each processor's profile, compared
//! as the differential compares
//! ([`compare_processors`]: how the run ends, the return value, a call's
//! target and arguments, memory written outside the function's own
//! stack). Answers: the same on all (with how many states reached a site
//! at all), differs (the differing states grouped by how they differ,
//! each kept state with the outputs per processor, the site that decided
//! with each processor's rule there, and the state as an example state
//! that opens as a run), or not reached (no state reached a site: no
//! answer).

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

pub use binbun_decompile::validate::{Decider, Output, Stored};
use binbun_decompile::validate::{
    Differing as Found, OnProcessor, Oracle, State, compare_processors, random_states,
    shaped_states,
};
use binbun_semantics::Declarations;
use binbun_semantics::ir::SiteId;

use super::verify::{SHAPED, STATES};
use super::{Lowered, lower, lower_prepared};
use crate::Database;
use crate::cfg::FunctionId;
use crate::decompile::{Interfaces, Prepared, View, stream_parallel};
use crate::memory::ImageOracle;
use crate::profile::{Choice, Profile, embedded, fits};
use crate::run::state::{Region, RegisterValue, format_value};
use crate::run::{ExampleState, Fill};
use crate::target::setup;

/// The differing states a comparison keeps: the first of each way they
/// differ (up to this many ways), then the next ones, in order.
pub const KEPT: usize = 4;

/// How to compare.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Options {
    /// The processors, at least two.
    pub profiles: Vec<Arc<Profile>>,
    /// How many random states.
    pub states: usize,
    /// How many states shaped by the function's types, besides.
    pub shaped: usize,
    /// The seed of the states; `None`: the function's entry.
    pub seed: Option<u64>,
    /// The blocks L1 may enter per run; `None`: the full check's.
    pub fuel: Option<u64>,
}

impl Default for Options {
    /// Every shipped profile, verify's states.
    fn default() -> Self {
        Self {
            profiles: embedded().to_vec(),
            states: STATES,
            shaped: SHAPED,
            seed: None,
            fuel: None,
        }
    }
}

/// A state from which the processors' runs differ.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Differing {
    /// The state's position among the states.
    pub index: usize,
    /// The state as the runs start from it.
    pub state: State,
    /// The state as an example state, to open as a run (on either
    /// processor).
    pub example: ExampleState,
    /// What differs (`the return value`).
    pub what: String,
    /// Per processor (in [`Options::profiles`]' order), how its run ended.
    pub outputs: Vec<Output>,
    /// Where a store differs (the runs ending alike), the byte.
    pub stored: Option<Stored>,
    /// The site that decided, if the runs' values at one differ.
    pub decider: Option<Decider>,
    /// Per processor, its rule at the deciding site (`unknown` where it
    /// has none); empty without one.
    pub rules: Vec<String>,
    /// The way it differs: its position in [`Comparison::ways`].
    pub way: usize,
}

/// What the comparison found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Every state compared ended the same way on every processor, and
    /// some reached a site.
    Same,
    /// No state reached a site: the processors cannot differ from them.
    NotReached,
    /// Some states' runs differ: the first ones ([`KEPT`]).
    Differs(Vec<Differing>),
    /// It cannot be compared: why.
    NotCheckable(String),
}

/// One function compared.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Comparison {
    /// The function's entry.
    pub entry: u64,
    /// The processors' labels (`intel-raptor-cove r1`), in order.
    pub profiles: Vec<String>,
    /// The seed of the states.
    pub seed: u64,
    /// States run.
    pub states: usize,
    /// States whose runs ended the same way on every processor.
    pub same: usize,
    /// States not compared (a run out of fuel, or undetermined on one).
    pub skipped: usize,
    /// States that reached a site on some processor.
    pub reaching: usize,
    /// Per site, the states reaching it.
    pub reached: BTreeMap<SiteId, usize>,
    /// Per way the states differ (what differs and the deciding site
    /// with its values), in the order first seen, how many states differ
    /// that way.
    pub ways: Vec<usize>,
    /// The answer.
    pub verdict: Verdict,
}

impl Comparison {
    /// One that could not run: `why`.
    fn not_checkable(entry: u64, options: &Options, why: String) -> Self {
        Self {
            entry,
            profiles: options.profiles.iter().map(|p| p.label()).collect(),
            seed: options.seed.unwrap_or(entry),
            states: 0,
            same: 0,
            skipped: 0,
            reaching: 0,
            reached: BTreeMap::new(),
            ways: Vec::new(),
            verdict: Verdict::NotCheckable(why),
        }
    }
}

/// Function `id` of `database` compared under `options`.
pub fn compare(database: &Database<'_>, id: FunctionId, options: &Options) -> Comparison {
    let never = AtomicBool::new(false);
    let entry = database.function(id).map_or(0, |function| function.entry);
    compare_cancellable(database, id, options, &never)
        .unwrap_or_else(|| Comparison::not_checkable(entry, options, String::new()))
}

/// [`compare`], stopped once `cancel` is set (between states): `None` if
/// it was.
pub fn compare_cancellable(
    database: &Database<'_>,
    id: FunctionId,
    options: &Options,
    cancel: &AtomicBool,
) -> Option<Comparison> {
    let entry = database.function(id).map_or(0, |function| function.entry);
    match lower(database, id, View::Exact, &[]) {
        Ok((lowered, _)) => compare_lowered(database, &lowered, options, cancel),
        Err(why) => Some(Comparison::not_checkable(entry, options, why)),
    }
}

/// Every function of `database` compared under `options` on `threads`
/// threads, handed to `ready` callees first.
pub fn compare_all(
    database: &Database<'_>,
    options: &Options,
    threads: usize,
    ready: impl FnMut(Comparison),
) {
    let callers = database.callers(&[]);
    stream_parallel(
        database.image(),
        database.program(),
        database.summaries(),
        &callers,
        &[],
        threads,
        |id, prepared, interfaces| compare_prepared(database, id, prepared, interfaces, options),
        ready,
    );
}

/// Function `id`, `prepared` with its callees' `interfaces`, compared.
fn compare_prepared(
    database: &Database<'_>,
    id: FunctionId,
    prepared: Result<Prepared, String>,
    interfaces: &Interfaces,
    options: &Options,
) -> Comparison {
    let entry = database.function(id).map_or(0, |function| function.entry);
    let never = AtomicBool::new(false);
    match prepared
        .and_then(|prepared| lower_prepared(database, prepared, interfaces, View::Exact, &[]))
    {
        Ok(lowered) => compare_lowered(database, &lowered, options, &never)
            .unwrap_or_else(|| Comparison::not_checkable(entry, options, String::new())),
        Err(why) => Comparison::not_checkable(entry, options, why),
    }
}

/// `lowered` (of `database`) compared under `options`; `None`: `cancel`
/// was set.
fn compare_lowered(
    database: &Database<'_>,
    lowered: &Lowered,
    options: &Options,
    cancel: &AtomicBool,
) -> Option<Comparison> {
    let entry = lowered.entry;
    let failed = |why: String| Some(Comparison::not_checkable(entry, options, why));
    if options.profiles.len() < 2 {
        return failed("two processors or more are compared".to_owned());
    }
    let image = database.image();
    for profile in &options.profiles {
        if let Err(why) = fits(profile, image) {
            return failed(why);
        }
    }
    let mut setup = match setup(image, entry) {
        Ok(setup) => setup,
        Err(why) => return failed(why),
    };
    setup.fuel = options.fuel.unwrap_or(setup.fuel);
    let seed = options.seed.unwrap_or(entry);
    let mut states = random_states(&setup, options.states, seed);
    states.extend(shaped_states(
        &setup,
        &lowered.l2,
        &lowered.mapping,
        options.shaped,
        seed,
    ));
    let memory = ImageOracle::new(image);
    let processors: Vec<OnProcessor<'_>> = options
        .profiles
        .iter()
        .map(|profile| OnProcessor {
            oracle: &memory,
            profile,
        })
        .collect();
    let oracles: Vec<&dyn Oracle> = processors.iter().map(|p| p as &dyn Oracle).collect();
    let found = compare_processors(
        &lowered.prepared.l1,
        &lowered.l2,
        &lowered.mapping,
        &setup,
        &oracles,
        &states,
        cancel,
    )?;
    if cancel.load(Ordering::Relaxed) {
        return None;
    }
    let (ways, way_of) = ways(&found.differing);
    let kept = kept(&way_of, ways.len());
    let differing: Vec<Differing> = found
        .differing
        .into_iter()
        .zip(way_of)
        .enumerate()
        .filter(|(position, _)| kept.contains(position))
        .filter_map(|(_, (differing, way))| {
            let state = states.get(differing.state)?.clone();
            let name = format!("differs-{}", differing.state);
            let example = example_state(setup.declarations, &state, &name, database.name(entry));
            Some(kept_state(
                differing,
                state,
                example,
                way,
                &options.profiles,
            ))
        })
        .collect();
    let verdict = if !differing.is_empty() {
        Verdict::Differs(differing)
    } else if found.reaching == 0 {
        Verdict::NotReached
    } else if found.same == 0 {
        Verdict::NotCheckable(format!(
            "{} states reached a site, none compared ({} skipped)",
            found.reaching, found.skipped
        ))
    } else {
        Verdict::Same
    };
    Some(Comparison {
        entry,
        profiles: options.profiles.iter().map(|p| p.label()).collect(),
        seed,
        states: found.runs,
        same: found.same,
        skipped: found.skipped,
        reaching: found.reaching,
        reached: found.reached,
        ways,
        verdict,
    })
}

/// `state` as an example state named `name` for `function`: its
/// registers (those with a defined value), the memory it sets, over
/// hashed memory, as the comparison ran it.
pub fn example_state(
    declarations: &Declarations,
    state: &State,
    name: &str,
    function: Option<&str>,
) -> ExampleState {
    let registers = declarations
        .registers
        .iter()
        .zip(&state.registers)
        .filter(|(_, value)| value.is_defined())
        .map(|(info, value)| RegisterValue {
            name: info.name.to_owned(),
            value: format_value(value),
        })
        .collect();
    let regions = state
        .memory
        .iter()
        .map(|(start, bytes)| Region {
            address: format!("{start:#x}"),
            bytes: Some(bytes.iter().fold(String::new(), |mut hex, byte| {
                let _ = write!(hex, "{byte:02x}");
                hex
            })),
            ..Region::default()
        })
        .collect();
    ExampleState {
        function: function.map(str::to_owned),
        fill: Fill::Hashed,
        registers,
        regions,
        ..ExampleState::scratch(name)
    }
}

/// `found` from `state` (as `example`), the way `way`, as kept: with each
/// of `profiles`' rule at the deciding site.
fn kept_state(
    found: Found,
    state: State,
    example: ExampleState,
    way: usize,
    profiles: &[Arc<Profile>],
) -> Differing {
    let rules = found
        .decider
        .as_ref()
        .map_or_else(Vec::new, |decider| rules(profiles, decider.site));
    Differing {
        index: found.state,
        state,
        example,
        what: found.what,
        outputs: found.outputs,
        stored: found.stored,
        decider: found.decider,
        rules,
        way,
    }
}

/// Each of `profiles`' rule at `site` (`unknown` where it has none).
fn rules(profiles: &[Arc<Profile>], site: SiteId) -> Vec<String> {
    profiles
        .iter()
        .map(|profile| {
            profile
                .choice(site)
                .map_or("unknown", Choice::text)
                .to_owned()
        })
        .collect()
}

/// The ways `differing` states differ (what differs, the deciding site
/// and its values), in the order first seen: how many differ each way,
/// and each state's way.
fn ways(differing: &[Found]) -> (Vec<usize>, Vec<usize>) {
    let mut keys: Vec<(&str, Option<&Decider>)> = Vec::new();
    let mut ways: Vec<usize> = Vec::new();
    let mut way_of: Vec<usize> = Vec::with_capacity(differing.len());
    for state in differing {
        let key = (state.what.as_str(), state.decider.as_ref());
        let way = keys.iter().position(|k| *k == key).unwrap_or_else(|| {
            keys.push(key);
            ways.push(0);
            keys.len() - 1
        });
        if let Some(count) = ways.get_mut(way) {
            *count += 1;
        }
        way_of.push(way);
    }
    (ways, way_of)
}

/// The positions of the differing states kept, of `ways` ways, `way_of`
/// giving each state's: the first of each way (up to [`KEPT`]), then the
/// next ones up to [`KEPT`], in order.
fn kept(way_of: &[usize], ways: usize) -> Vec<usize> {
    let mut kept: Vec<usize> = (0..ways)
        .take(KEPT)
        .filter_map(|way| way_of.iter().position(|&w| w == way))
        .collect();
    for position in 0..way_of.len() {
        if kept.len() >= KEPT {
            break;
        }
        if !kept.contains(&position) {
            kept.push(position);
        }
    }
    kept.sort_unstable();
    kept
}
