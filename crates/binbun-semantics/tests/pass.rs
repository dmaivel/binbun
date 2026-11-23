#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers fail loudly"
)]

//! The pass manager on a toy function (a list of numbers): a stale
//! analysis is never read, a preserved one is not recomputed, a fixed
//! point stops (or says it did not), a refusal changes nothing, a broken
//! function names the pass that broke it.

use binbun_semantics::core::pass::{
    Analyses, Analysis, Changed, Cx, Fuel, Manager, Pass, Preserved, Refusal,
};

type Numbers = Vec<i64>;

/// The sum of the numbers.
struct Sum(i64);

impl Analysis<Numbers, ()> for Sum {
    fn compute(function: &Numbers, (): &(), _: &mut Analyses<Numbers, ()>) -> Self {
        Self(function.iter().sum())
    }
}

/// Twice the sum, from [`Sum`].
struct Doubled(i64);

impl Analysis<Numbers, ()> for Doubled {
    fn compute(function: &Numbers, env: &(), analyses: &mut Analyses<Numbers, ()>) -> Self {
        Self(2 * analyses.get::<Sum>(function, env).0)
    }
}

fn computed(manager: &Manager<Numbers, ()>, analysis: &str) -> usize {
    manager
        .computed()
        .find(|(name, _)| name.ends_with(analysis))
        .map_or(0, |(_, count)| count)
}

/// Adds one to each number, spending one unit each.
struct AddOne;

impl Pass<Numbers, ()> for AddOne {
    fn name(&self) -> &'static str {
        "add-one"
    }
    fn run(&mut self, f: &mut Numbers, cx: &mut Cx<'_, Numbers, ()>) -> Result<Changed, Refusal> {
        cx.fuel.spend(f.len() as u64)?;
        for n in f.iter_mut() {
            *n += 1;
        }
        Ok(Changed::from(!f.is_empty()))
    }
}

/// Reverses the numbers: the sum stays.
struct Reverse;

impl Pass<Numbers, ()> for Reverse {
    fn name(&self) -> &'static str {
        "reverse"
    }
    fn run(&mut self, f: &mut Numbers, _: &mut Cx<'_, Numbers, ()>) -> Result<Changed, Refusal> {
        f.reverse();
        Ok(Changed::Yes)
    }
    fn preserves(&self, preserved: &mut Preserved) {
        preserved.keep::<Sum>();
    }
}

/// Halves the even numbers.
struct HalveEvens;

impl Pass<Numbers, ()> for HalveEvens {
    fn name(&self) -> &'static str {
        "halve-evens"
    }
    fn run(&mut self, f: &mut Numbers, _: &mut Cx<'_, Numbers, ()>) -> Result<Changed, Refusal> {
        let mut changed = false;
        for n in f.iter_mut().filter(|n| **n != 0 && **n % 2 == 0) {
            *n /= 2;
            changed = true;
        }
        Ok(Changed::from(changed))
    }
}

/// Subtracts 10 from the first number.
struct Subtract;

impl Pass<Numbers, ()> for Subtract {
    fn name(&self) -> &'static str {
        "subtract"
    }
    fn run(&mut self, f: &mut Numbers, _: &mut Cx<'_, Numbers, ()>) -> Result<Changed, Refusal> {
        let first = f.first_mut().ok_or(Refusal::Malformed("empty".into()))?;
        *first -= 10;
        Ok(Changed::Yes)
    }
}

/// No number may be negative.
#[allow(
    clippy::trivially_copy_pass_by_ref,
    reason = "the signature of every verifier"
)]
fn non_negative(f: &Numbers, (): &()) -> Result<(), String> {
    match f.iter().find(|&&n| n < 0) {
        Some(n) => Err(format!("{n} is negative")),
        None => Ok(()),
    }
}

#[test]
fn a_change_drops_the_analyses_it_does_not_preserve() {
    let mut m = Manager::new(Fuel::new(100));
    let mut f = vec![1, 2, 3];
    assert_eq!(m.analysis::<Doubled>(&f, &()).0, 12);
    // A pass that changes nothing keeps everything.
    m.run(&mut HalveEvens, &mut vec![1, 3], &()).unwrap();
    // Reverse keeps the sum, not what is built on it.
    m.run(&mut Reverse, &mut f, &()).unwrap();
    assert_eq!(m.analysis::<Doubled>(&f, &()).0, 12);
    assert_eq!((computed(&m, "Sum"), computed(&m, "Doubled")), (1, 2));
    // AddOne preserves nothing: the next answer is the new one.
    m.run(&mut AddOne, &mut f, &()).unwrap();
    assert_eq!(m.analysis::<Doubled>(&f, &()).0, 18);
    assert_eq!((computed(&m, "Sum"), computed(&m, "Doubled")), (2, 3));
}

#[test]
fn a_fixed_point_stops_when_a_round_changes_nothing() {
    let mut f = vec![8, 3, 12];
    let mut m = Manager::new(Fuel::new(100));
    let done = m.fixpoint(&mut [&mut HalveEvens], 10, &mut f, &()).unwrap();
    assert!(done.stable);
    assert_eq!(done.changed, Changed::Yes);
    assert_eq!(f, [1, 3, 3]);
    // 8 needs three halvings: two rounds are not enough, and it says so.
    let mut g = vec![8];
    let short = m.fixpoint(&mut [&mut HalveEvens], 2, &mut g, &()).unwrap();
    assert!(!short.stable);
    assert_eq!(g, [2]);
}

#[test]
fn refusals_change_nothing_and_disabled_passes_do_not_run() {
    let mut m = Manager::new(Fuel::new(2));
    let mut f = vec![1, 2, 3];
    // Three units needed, two left: refused, the function as it was, the
    // fuel unspent, and the next pass still runs.
    assert_eq!(m.run(&mut AddOne, &mut f, &()).unwrap(), Changed::No);
    assert_eq!(f, [1, 2, 3]);
    assert_eq!(m.fuel().left(), 2);
    assert_eq!(m.refusals(), [("add-one", Refusal::OutOfFuel)]);
    m.disable("reverse");
    assert_eq!(m.run(&mut Reverse, &mut f, &()).unwrap(), Changed::No);
    assert_eq!(f, [1, 2, 3]);
    let stats: Vec<_> = m.stats().collect();
    assert_eq!(stats.len(), 1);
    assert_eq!((stats[0].1.runs, stats[0].1.refused), (1, 1));
}

#[test]
fn the_verifier_names_the_pass_that_broke_the_function() {
    let mut m = Manager::new(Fuel::new(100)).with_verifier(non_negative);
    let mut f = vec![15, 1];
    m.run(&mut Subtract, &mut f, &()).unwrap();
    let broken = m.run(&mut Subtract, &mut f, &()).unwrap_err();
    assert_eq!(broken.pass, "subtract");
    assert_eq!(broken.message, "-5 is negative");
}

#[test]
fn recording_keeps_the_function_after_each_change_and_only_then() {
    let mut m = Manager::new(Fuel::new(100));
    let mut f = vec![4, 3];
    // Not recording: nothing kept.
    m.run(&mut AddOne, &mut f, &()).unwrap();
    assert_eq!(m.recorded(), []);
    m.record();
    m.fixpoint(&mut [&mut HalveEvens, &mut Reverse], 3, &mut f, &())
        .unwrap();
    // A pass that changes nothing (the third round's halving) is not
    // kept; each change is, in order.
    assert_eq!(
        m.recorded(),
        [
            ("halve-evens", vec![5, 2]),
            ("reverse", vec![2, 5]),
            ("halve-evens", vec![1, 5]),
            ("reverse", vec![5, 1]),
            ("reverse", vec![1, 5]),
        ]
    );
    // Taken: the next call starts afresh.
    assert_eq!(m.recorded(), []);
}
