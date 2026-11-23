//! Passes over a function and the analyses they share: the rule every pass
//! is admitted under (it declares what it invalidates, a verifier runs
//! after it, it has a budget and metrics) in code rather than prose.
//!
//! - An [`Analysis`] computes a fact about a function `F` in its
//!   environment `E` (what the function alone does not say: declarations,
//!   read-only memory, the calling convention); it may ask for other
//!   analyses while it computes (not for itself).
//! - A [`Pass`] may change the function, and says whether it did
//!   ([`Changed`]) and which analyses survive a change ([`Pass::preserves`]).
//!   A pass that refuses ([`Refusal`]) leaves the function as it was.
//! - A [`Manager`] runs passes, one after another or to a fixed point
//!   ([`Manager::fixpoint`]), and holds what they share:
//!   - the analyses computed so far ([`Analyses`]): each computed on first
//!     use; after a pass that changed the function, every analysis it does
//!     not declare preserved is dropped, so a stale fact is never read
//!     (forgetting to declare one costs a recomputation, never a wrong
//!     answer);
//!   - one budget, [`Fuel`], that every pass draws from;
//!   - the verifier, run after every pass that changed the function;
//!   - passes disabled by name (to bisect which one does what);
//!   - counts per pass and per analysis;
//!   - on request ([`Manager::record`]), the function as each pass that
//!     changed it left it (an IR viewer's stages); off, it costs nothing.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::rc::Rc;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::any::{Any, TypeId, type_name};
use core::fmt;
use core::marker::PhantomData;

/// A fact about a function `F` in its environment `E`.
pub trait Analysis<F, E>: Sized + 'static {
    /// The fact about `function`, asking `analyses` for those it builds on
    /// (never, through them, for itself).
    fn compute(function: &F, env: &E, analyses: &mut Analyses<F, E>) -> Self;
}

/// The analyses of one function computed so far.
pub struct Analyses<F, E> {
    cache: BTreeMap<TypeId, Rc<dyn Any>>,
    computed: BTreeMap<&'static str, usize>,
    marker: PhantomData<fn(&F, &E)>,
}

impl<F, E> Default for Analyses<F, E> {
    fn default() -> Self {
        Self {
            cache: BTreeMap::new(),
            computed: BTreeMap::new(),
            marker: PhantomData,
        }
    }
}

impl<F, E> fmt::Debug for Analyses<F, E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Analyses")
            .field("cached", &self.cache.len())
            .field("computed", &self.computed)
            .finish()
    }
}

impl<F, E> Analyses<F, E> {
    /// Analysis `A` of `function`: the one computed before if no change
    /// dropped it, else computed now.
    pub fn get<A: Analysis<F, E>>(&mut self, function: &F, env: &E) -> Rc<A> {
        let key = TypeId::of::<A>();
        if let Some(found) = self.cache.get(&key).cloned()
            && let Ok(found) = found.downcast::<A>()
        {
            return found;
        }
        let computed = Rc::new(A::compute(function, env, self));
        *self.computed.entry(type_name::<A>()).or_default() += 1;
        let shared: Rc<dyn Any> = Rc::clone(&computed) as Rc<dyn Any>;
        self.cache.insert(key, shared);
        computed
    }

    /// How many times each analysis was computed, by type name.
    pub fn computed(&self) -> impl Iterator<Item = (&'static str, usize)> + '_ {
        self.computed.iter().map(|(&name, &count)| (name, count))
    }

    /// Drops every analysis but those `preserved` names.
    fn retain(&mut self, preserved: &Preserved) {
        self.cache.retain(|key, _| preserved.0.contains(key));
    }
}

/// Whether a pass changed the function.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Changed {
    /// It is as it was.
    No,
    /// It changed.
    Yes,
}

impl Changed {
    /// Whether either changed it.
    #[must_use]
    pub fn or(self, other: Self) -> Self {
        if self == Self::Yes || other == Self::Yes {
            Self::Yes
        } else {
            Self::No
        }
    }
}

impl From<bool> for Changed {
    fn from(changed: bool) -> Self {
        if changed { Self::Yes } else { Self::No }
    }
}

/// Why a pass did not run; the function is as it was.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The budget ([`Fuel`]) ran out.
    OutOfFuel,
    /// The function is not what the pass requires (its precondition).
    Malformed(String),
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OutOfFuel => f.write_str("out of fuel"),
            Self::Malformed(reason) => write!(f, "malformed: {reason}"),
        }
    }
}

/// Work every pass on a function draws from, in units each pass defines
/// (a step of its work list, a node visited).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fuel {
    left: u64,
}

impl Fuel {
    /// `units` of work.
    #[must_use]
    pub fn new(units: u64) -> Self {
        Self { left: units }
    }

    /// Spends `units`.
    ///
    /// # Errors
    ///
    /// [`Refusal::OutOfFuel`] if fewer are left (then none are spent).
    pub fn spend(&mut self, units: u64) -> Result<(), Refusal> {
        self.left = self.left.checked_sub(units).ok_or(Refusal::OutOfFuel)?;
        Ok(())
    }

    /// The units left.
    #[must_use]
    pub fn left(&self) -> u64 {
        self.left
    }
}

/// The analyses that survive a pass's change.
#[derive(Debug, Default)]
pub struct Preserved(Vec<TypeId>);

impl Preserved {
    /// Analysis `A` survives.
    pub fn keep<A: 'static>(&mut self) -> &mut Self {
        self.0.push(TypeId::of::<A>());
        self
    }
}

/// What a running pass may use: the environment, the analyses, the fuel.
pub struct Cx<'m, F, E> {
    /// The function's environment.
    pub env: &'m E,
    /// The analyses computed so far.
    pub analyses: &'m mut Analyses<F, E>,
    /// The budget.
    pub fuel: &'m mut Fuel,
}

impl<F, E> fmt::Debug for Cx<'_, F, E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Cx")
            .field("analyses", &self.analyses)
            .field("fuel", &self.fuel)
            .finish_non_exhaustive()
    }
}

impl<F, E> Cx<'_, F, E> {
    /// Analysis `A` of `function` (computed before the pass changes it:
    /// a pass that changes the function keeps what it asked for, which
    /// says what the function was).
    pub fn analysis<A: Analysis<F, E>>(&mut self, function: &F) -> Rc<A> {
        self.analyses.get(function, self.env)
    }
}

/// A pass over functions `F` in environments `E`.
pub trait Pass<F, E> {
    /// Its name, unique among the passes run together (to disable it, and
    /// in counts and errors).
    fn name(&self) -> &'static str;

    /// Runs on `function`.
    ///
    /// # Errors
    ///
    /// A [`Refusal`]; the function must then be as it was.
    fn run(&mut self, function: &mut F, cx: &mut Cx<'_, F, E>) -> Result<Changed, Refusal>;

    /// The analyses still true after a change (none by default).
    fn preserves(&self, _preserved: &mut Preserved) {}
}

/// Counts of one pass.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PassStats {
    /// Times it ran (refusals included).
    pub runs: usize,
    /// Times it changed the function.
    pub changed: usize,
    /// Times it refused.
    pub refused: usize,
}

/// A pass left the function failing its verifier: a bug in the pass.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Broken {
    /// The pass.
    pub pass: &'static str,
    /// The verifier's error.
    pub message: String,
}

impl fmt::Display for Broken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "after {}: {}", self.pass, self.message)
    }
}

impl core::error::Error for Broken {}

/// How a [`Manager::fixpoint`] ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fixpoint {
    /// Whether any pass changed the function.
    pub changed: Changed,
    /// Whether a whole round changed nothing (else the round limit ended
    /// it: the passes undo each other, or need more rounds).
    pub stable: bool,
}

/// A function's verifier: `Err` with its first error.
pub type Verifier<F, E> = fn(&F, &E) -> Result<(), String>;

/// Runs passes on one function, with what they share.
pub struct Manager<F, E> {
    analyses: Analyses<F, E>,
    fuel: Fuel,
    verifier: Option<Verifier<F, E>>,
    disabled: BTreeSet<String>,
    stats: BTreeMap<&'static str, PassStats>,
    refusals: Vec<(&'static str, Refusal)>,
    recording: Option<Recording<F>>,
}

/// The function as each pass that changed it left it ([`Manager::record`]).
struct Recording<F> {
    /// How the function is copied.
    copy: fn(&F) -> F,
    /// The copies, in order, with the pass that made each.
    taken: Vec<(&'static str, F)>,
}

impl<F, E> fmt::Debug for Manager<F, E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Manager")
            .field("analyses", &self.analyses)
            .field("fuel", &self.fuel)
            .field("disabled", &self.disabled)
            .field("stats", &self.stats)
            .field("refusals", &self.refusals)
            .field("recording", &self.recording.is_some())
            .finish_non_exhaustive()
    }
}

impl<F, E> Manager<F, E> {
    /// A manager with `fuel` for every pass it runs.
    #[must_use]
    pub fn new(fuel: Fuel) -> Self {
        Self {
            analyses: Analyses::default(),
            fuel,
            verifier: None,
            disabled: BTreeSet::new(),
            stats: BTreeMap::new(),
            refusals: Vec::new(),
            recording: None,
        }
    }

    /// With `verifier` run after every pass that changes the function.
    #[must_use]
    pub fn with_verifier(mut self, verifier: Verifier<F, E>) -> Self {
        self.verifier = Some(verifier);
        self
    }

    /// The pass named `name` is not run.
    pub fn disable(&mut self, name: &str) {
        self.disabled.insert(name.to_string());
    }

    /// From now on, keeps a copy of the function after each pass that
    /// changes it (after its verifier), with the pass's name: what
    /// [`Manager::recorded`] returns. Without it nothing is copied.
    pub fn record(&mut self)
    where
        F: Clone,
    {
        self.recording = Some(Recording {
            copy: F::clone,
            taken: Vec::new(),
        });
    }

    /// The copies kept since [`Manager::record`] or the last call, in
    /// order, each with the pass that made it (none if not recording).
    pub fn recorded(&mut self) -> Vec<(&'static str, F)> {
        self.recording
            .as_mut()
            .map(|recording| core::mem::take(&mut recording.taken))
            .unwrap_or_default()
    }

    /// Runs `pass` on `function`: a refusal is recorded and changes
    /// nothing; a change drops the analyses the pass does not preserve and
    /// runs the verifier.
    ///
    /// # Errors
    ///
    /// The verifier fails after the pass changed the function.
    pub fn run(
        &mut self,
        pass: &mut dyn Pass<F, E>,
        function: &mut F,
        env: &E,
    ) -> Result<Changed, Broken> {
        let name = pass.name();
        if self.disabled.contains(name) {
            return Ok(Changed::No);
        }
        let outcome = {
            let mut cx = Cx {
                env,
                analyses: &mut self.analyses,
                fuel: &mut self.fuel,
            };
            pass.run(function, &mut cx)
        };
        let stats = self.stats.entry(name).or_default();
        stats.runs += 1;
        match outcome {
            Ok(Changed::No) => Ok(Changed::No),
            Ok(Changed::Yes) => {
                stats.changed += 1;
                let mut preserved = Preserved::default();
                pass.preserves(&mut preserved);
                self.analyses.retain(&preserved);
                if let Some(verifier) = self.verifier {
                    verifier(function, env).map_err(|message| Broken {
                        pass: name,
                        message,
                    })?;
                }
                if let Some(recording) = &mut self.recording {
                    recording.taken.push((name, (recording.copy)(function)));
                }
                Ok(Changed::Yes)
            }
            Err(refusal) => {
                stats.refused += 1;
                self.refusals.push((name, refusal));
                Ok(Changed::No)
            }
        }
    }

    /// Runs `passes` in order, round after round, until a round changes
    /// nothing or `rounds` rounds have run.
    ///
    /// # Errors
    ///
    /// As for [`Manager::run`].
    pub fn fixpoint(
        &mut self,
        passes: &mut [&mut dyn Pass<F, E>],
        rounds: usize,
        function: &mut F,
        env: &E,
    ) -> Result<Fixpoint, Broken> {
        let mut changed = Changed::No;
        for _ in 0..rounds {
            let mut round = Changed::No;
            for pass in passes.iter_mut() {
                round = round.or(self.run(&mut **pass, function, env)?);
            }
            changed = changed.or(round);
            if round == Changed::No {
                return Ok(Fixpoint {
                    changed,
                    stable: true,
                });
            }
        }
        Ok(Fixpoint {
            changed,
            stable: false,
        })
    }

    /// Analysis `A` of `function`, as passes see it.
    pub fn analysis<A: Analysis<F, E>>(&mut self, function: &F, env: &E) -> Rc<A> {
        self.analyses.get(function, env)
    }

    /// The counts of each pass that ran, by name.
    pub fn stats(&self) -> impl Iterator<Item = (&'static str, PassStats)> + '_ {
        self.stats.iter().map(|(&name, &stats)| (name, stats))
    }

    /// How many times each analysis was computed, by type name.
    pub fn computed(&self) -> impl Iterator<Item = (&'static str, usize)> + '_ {
        self.analyses.computed()
    }

    /// The refusals, in order, with the pass that refused.
    pub fn refusals(&self) -> &[(&'static str, Refusal)] {
        &self.refusals
    }

    /// The fuel left.
    #[must_use]
    pub fn fuel(&self) -> Fuel {
        self.fuel
    }
}
