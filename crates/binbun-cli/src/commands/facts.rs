//! `binbun verify`, `binbun why` and `binbun origin`: the engine's
//! queries beside a function's C ([`binbun::queries`]) as text.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::time::{Duration, Instant};

use binbun::Database;
use binbun::analysis::Seeds;
use binbun::decompile::{View, threads};
use binbun::profile::{self, Profile};
use binbun::queries::compare;
use binbun::queries::evidence::{self, Explanation, Item, NameSource, Source};
use binbun::queries::origin::{self, Kind, Origins, Query, Remote, Start, Step, Trivial};
use binbun::queries::verify::{self, Difference, Options, Verdict, Verification};
use binbun::queries::{Lowered, each, values_of};
use binbun_ast::ir::VarKind;
use binbun_decompile::typing::{FieldType, Structs};
use binbun_decompile::validate::State;
use binbun_print::style::Style;
use binbun_semantics::ir::SiteId;
use binbun_session::Edits;
use binbun_session::project::Project;

use super::xrefs::resolve;
use super::{USAGE, database, load, read};

/// The flags and positional arguments of the three commands.
struct Arguments<'a> {
    positional: Vec<&'a str>,
    view: View,
    states: usize,
    shaped: usize,
    seed: Option<u64>,
    fuel: Option<u64>,
    depth: usize,
    steps: usize,
    sample: Option<usize>,
    all: bool,
    global: Option<&'a str>,
    /// A project directory whose corrections recovery takes.
    project: Option<&'a str>,
    /// The processor runs are on (a shipped profile's name or a file).
    profile: Option<&'a str>,
    /// The processors compared, comma-separated.
    compare: Option<&'a str>,
    /// Where a comparison saves the states that differ.
    save: Option<&'a str>,
    /// Whether a comparison prints each kept differing state whole.
    states_full: bool,
}

fn arguments(args: &[String]) -> Result<Arguments<'_>, String> {
    let query = Query::default();
    let mut out = Arguments {
        positional: Vec::new(),
        view: View::Exact,
        states: verify::STATES,
        shaped: verify::SHAPED,
        seed: None,
        fuel: None,
        depth: query.depth,
        steps: query.steps,
        sample: None,
        all: false,
        global: None,
        project: None,
        profile: None,
        compare: None,
        save: None,
        states_full: false,
    };
    let mut args = args.iter();
    let number = |arg: Option<&String>| -> Result<u64, String> {
        let arg = arg.ok_or_else(|| USAGE.to_owned())?;
        match arg.strip_prefix("0x") {
            Some(hex) => u64::from_str_radix(hex, 16),
            None => arg.parse(),
        }
        .map_err(|_| USAGE.to_owned())
    };
    let size = |n: u64| usize::try_from(n).map_err(|_| USAGE.to_owned());
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--view" => {
                out.view = match args.next().map(String::as_str) {
                    Some("exact") => View::Exact,
                    Some("reading") => View::Reading,
                    _ => return Err(USAGE.to_owned()),
                };
            }
            "--states" => out.states = size(number(args.next())?)?,
            "--shaped" => out.shaped = size(number(args.next())?)?,
            "--seed" => out.seed = Some(number(args.next())?),
            "--fuel" => out.fuel = Some(number(args.next())?),
            "--depth" => out.depth = size(number(args.next())?)?,
            "--steps" => out.steps = size(number(args.next())?)?,
            "--sample" => out.sample = Some(size(number(args.next())?)?),
            "--all" => out.all = true,
            "--states-full" => out.states_full = true,
            "--global" => {
                out.global = Some(args.next().ok_or_else(|| USAGE.to_owned())?.as_str());
            }
            "--project" => {
                out.project = Some(args.next().ok_or_else(|| USAGE.to_owned())?.as_str());
            }
            "--profile" => {
                out.profile = Some(args.next().ok_or_else(|| USAGE.to_owned())?.as_str());
            }
            "--compare" => {
                out.compare = Some(args.next().ok_or_else(|| USAGE.to_owned())?.as_str());
            }
            "--save" => {
                out.save = Some(args.next().ok_or_else(|| USAGE.to_owned())?.as_str());
            }
            _ if arg.starts_with("--") => return Err(USAGE.to_owned()),
            _ => out.positional.push(arg.as_str()),
        }
    }
    Ok(out)
}

fn view_name(view: View) -> &'static str {
    match view {
        View::Exact => "exact",
        View::Reading => "reading",
    }
}

/// `verify FILE [FUNCTION] [--view exact|reading] [--states N] [--shaped
/// N] [--seed N] [--fuel N] [--project DIR] [--profile NAME|PATH]`: one
/// function checked against its L1 (the
/// structure check and the differential from N random states, 16 by
/// default, and N states shaped by its types, 8 by default, of the seed,
/// its entry by default, each run with the fuel, the full check's by
/// default), with the counterexample where it differs; without a
/// function, every function, with the counts and the time. With
/// `--project`, the functions are recovered with the corrections of the
/// project in `DIR` (as the GUI keeps it). With `--profile`, the runs are
/// on that processor: the values the architecture leaves undefined are
/// its rules'. With `--compare P,Q`, the function (or each) runs on
/// those processors instead, and the report says whether it behaves
/// differently on them ([`compare`]): one example state per way the
/// states differ (`--states-full`: each state kept, with its registers
/// and memory); `--save DIR` writes each differing state kept there as
/// an example state (`binbun run --state`).
///
/// The report and the exit status ([`status`]), or what went wrong (exit
/// status [`FAILED`]).
pub fn verify(args: &[String]) -> Result<(String, u8), String> {
    let flags = arguments(args)?;
    let (path, wanted) = match flags.positional[..] {
        [path] => (path, None),
        [path, wanted] => (path, Some(wanted)),
        _ => return Err(USAGE.to_owned()),
    };
    if let Some(list) = flags.compare {
        return compare_command(&flags, path, wanted, list);
    }
    let data = read(path)?;
    let image = load(path, &data)?;
    let database = match flags.project {
        Some(dir) => {
            let edits = Edits::load(&Project::new(dir).edits())?;
            Database::with_corrections(&image, Seeds::ALL, None, edits.corrections().clone())
                .map_err(|error| format!("{path}: {error}"))?
        }
        None => database(path, &image, Seeds::ALL)?,
    };
    let profile = flags.profile.map(profile::resolve).transpose()?;
    let options = Options {
        view: flags.view,
        states: flags.states,
        shaped: flags.shaped,
        seed: flags.seed,
        fuel: flags.fuel,
        disabled: Vec::new(),
        profile,
    };
    match wanted {
        Some(wanted) => {
            let id = database.find_function(wanted)?;
            let verification = verify::verify(&database, id, &options);
            let text =
                describe_verification(&database, wanted, &verification, options.profile.as_deref());
            let (checked, differ) = match verification.verdict {
                Verdict::Agreed(_) => (1, 0),
                Verdict::Differs(_) => (1, 1),
                Verdict::NotCheckable(_) => (0, 0),
            };
            Ok((text, status(checked, differ)))
        }
        None => Ok(verify_every(&database, path, &options)),
    }
}

/// `verify`'s exit status: everything it checked agreed (some functions
/// not checkable beside them).
pub const AGREES: u8 = 0;
/// `verify`'s exit status: a function differs (from its L1, or with
/// `--compare`, between the processors).
pub const DIFFERS: u8 = 1;
/// `verify`'s exit status: it went wrong (a file it cannot read, a
/// function it cannot find, a usage error), as diff(1)'s trouble.
pub const FAILED: u8 = 2;
/// `verify`'s exit status: nothing could be checked (the function, or
/// every one, not checkable).
pub const UNCHECKED: u8 = 3;

/// The exit status of `verify` having checked `checked` functions (any
/// verdict but not checkable), `differ` of which differ.
fn status(checked: usize, differ: usize) -> u8 {
    if differ > 0 {
        DIFFERS
    } else if checked > 0 {
        AGREES
    } else {
        UNCHECKED
    }
}

/// `verify --compare`: the function `wanted` (or every one) of the file
/// at `path` compared on the processors of `list`; the report and the
/// exit status ([`status`]: the same, or no state reaching a site, agree).
fn compare_command(
    flags: &Arguments<'_>,
    path: &str,
    wanted: Option<&str>,
    list: &str,
) -> Result<(String, u8), String> {
    let profiles = list
        .split(',')
        .map(|name| profile::resolve(name.trim()))
        .collect::<Result<Vec<_>, _>>()?;
    if profiles.len() < 2 {
        return Err(USAGE.to_owned());
    }
    let options = compare::Options {
        profiles,
        states: flags.states,
        shaped: flags.shaped,
        seed: flags.seed,
        fuel: flags.fuel,
    };
    let data = read(path)?;
    let image = load(path, &data)?;
    let database = database(path, &image, Seeds::ALL)?;
    let mut out = String::new();
    let checkable =
        |verdict: &compare::Verdict| !matches!(verdict, compare::Verdict::NotCheckable(_));
    let differs = |verdict: &compare::Verdict| matches!(verdict, compare::Verdict::Differs(_));
    let found = if let Some(wanted) = wanted {
        let id = database.find_function(wanted)?;
        let comparison = compare::compare(&database, id, &options);
        describe_comparison(&mut out, &database, wanted, &comparison, &options, flags)?;
        status(
            usize::from(checkable(&comparison.verdict)),
            usize::from(differs(&comparison.verdict)),
        )
    } else {
        let start = Instant::now();
        let mut all: Vec<compare::Comparison> = Vec::new();
        compare::compare_all(&database, &options, threads(), |c| all.push(c));
        let count =
            |test: fn(&compare::Verdict) -> bool| all.iter().filter(|c| test(&c.verdict)).count();
        let _ = writeln!(
            out,
            "{path} on {}: {} functions: differ {}, same {}, no state reached a site {}, not checkable {} ({:.2?})",
            options
                .profiles
                .iter()
                .map(|p| p.label())
                .collect::<Vec<_>>()
                .join(", "),
            all.len(),
            count(|v| matches!(v, compare::Verdict::Differs(_))),
            count(|v| matches!(v, compare::Verdict::Same)),
            count(|v| matches!(v, compare::Verdict::NotReached)),
            count(|v| matches!(v, compare::Verdict::NotCheckable(_))),
            start.elapsed()
        );
        for comparison in all
            .iter()
            .filter(|c| matches!(c.verdict, compare::Verdict::Differs(_)))
        {
            let name = database
                .name(comparison.entry)
                .map_or_else(|| format!("{:#x}", comparison.entry), str::to_owned);
            describe_comparison(&mut out, &database, &name, comparison, &options, flags)?;
        }
        status(
            all.iter().filter(|c| checkable(&c.verdict)).count(),
            all.iter().filter(|c| differs(&c.verdict)).count(),
        )
    };
    Ok((out, found))
}

/// One function's comparison as text: the verdict, then per way the
/// states differ its first state with the outputs per processor and the
/// site that decided with each processor's rule, and how many more
/// differ that way (with `--states-full`, every state kept, with the
/// state); the states kept saved to `--save`'s directory if given.
fn describe_comparison(
    out: &mut String,
    database: &Database<'_>,
    name: &str,
    comparison: &compare::Comparison,
    options: &compare::Options,
    flags: &Arguments<'_>,
) -> Result<(), String> {
    let sites = database.declarations().map(|d| d.sites).unwrap_or_default();
    let site_name = |site: SiteId| {
        sites
            .get(usize::from(site.0))
            .map_or_else(|| format!("site {}", site.0), |info| info.name.to_owned())
    };
    let reached: Vec<String> = comparison
        .reached
        .iter()
        .map(|(&site, count)| format!("{} {count}", site_name(site)))
        .collect();
    let verdict = match &comparison.verdict {
        compare::Verdict::Same => "same".to_owned(),
        compare::Verdict::NotReached => "same: no state reached a site".to_owned(),
        compare::Verdict::Differs(_) => "differs".to_owned(),
        compare::Verdict::NotCheckable(why) => format!("not checkable: {why}"),
    };
    let _ = writeln!(
        out,
        "{name} at {:#x} on {}: {verdict}: {} states, {} same, {} skipped, {} reached a site{}",
        comparison.entry,
        comparison.profiles.join(", "),
        comparison.states,
        comparison.same,
        comparison.skipped,
        comparison.reaching,
        if reached.is_empty() {
            String::new()
        } else {
            format!(" ({})", reached.join(", "))
        }
    );
    let compare::Verdict::Differs(differing) = &comparison.verdict else {
        return Ok(());
    };
    let mut shown_ways = BTreeSet::new();
    let mut unshown = Vec::new();
    for state in differing {
        let first = shown_ways.insert(state.way);
        if !first && !flags.states_full {
            unshown.push(state);
            continue;
        }
        let _ = writeln!(
            out,
            "  state {} of seed {:#x}: {} differs",
            state.index, comparison.seed, state.what
        );
        describe_difference(out, comparison, options, state, &site_name);
        if flags.states_full {
            let _ = writeln!(out, "    state: {}", state_text(database, &state.state));
        }
        let alike = comparison.ways.get(state.way).copied().unwrap_or(1);
        if first && alike > 1 {
            let more = alike - 1;
            let _ = writeln!(
                out,
                "    {more} more {} the same way",
                if more == 1 {
                    "state differs"
                } else {
                    "states differ"
                }
            );
        }
        if let Some(dir) = flags.save {
            let file = save_state(dir, name, state)?;
            let _ = writeln!(out, "    saved: {file}");
        }
    }
    let other: usize = comparison
        .ways
        .iter()
        .enumerate()
        .filter(|(way, _)| !shown_ways.contains(way))
        .map(|(_, count)| count)
        .sum();
    if other > 0 {
        let ways = comparison.ways.len() - shown_ways.len();
        let _ = writeln!(
            out,
            "  {other} more {} in {ways} other {}",
            if other == 1 {
                "state differs"
            } else {
                "states differ"
            },
            if ways == 1 { "way" } else { "ways" }
        );
    }
    if let Some(dir) = flags.save {
        for state in unshown {
            let file = save_state(dir, name, state)?;
            let _ = writeln!(out, "  state {} saved: {file}", state.index);
        }
    }
    Ok(())
}

/// How `state`'s runs differ, as text: each processor's output, the store
/// that differs, and the deciding site (named by `site_name`) with each
/// processor's value and rule.
fn describe_difference(
    out: &mut String,
    comparison: &compare::Comparison,
    options: &compare::Options,
    state: &compare::Differing,
    site_name: &dyn Fn(SiteId) -> String,
) {
    for (label, output) in comparison.profiles.iter().zip(&state.outputs) {
        let _ = writeln!(out, "    {label}: {}", output.describe());
    }
    if let Some(stored) = &state.stored {
        let bytes: Vec<String> = comparison
            .profiles
            .iter()
            .zip(&stored.bytes)
            .map(|(label, byte)| format!("{label} {}", show(byte)))
            .collect();
        let _ = writeln!(
            out,
            "    stored at {:#x}: {}",
            stored.address,
            bytes.join("; ")
        );
    }
    if let Some(decider) = &state.decider {
        let rules: Vec<String> = options
            .profiles
            .iter()
            .zip(&decider.values)
            .zip(&state.rules)
            .map(|((profile, value), rule)| format!("{} {} by `{rule}`", profile.id, show(value)))
            .collect();
        let _ = writeln!(
            out,
            "    decided by {} at {:#x}: {}",
            site_name(decider.site),
            decider.address,
            rules.join("; ")
        );
    }
}

/// Writes differing `state` of function `name` to directory `dir` as an
/// example state; its path.
fn save_state(dir: &str, name: &str, state: &compare::Differing) -> Result<String, String> {
    let file = std::path::Path::new(dir).join(format!(
        "{}-{}.toml",
        name.replace(['/', '\\'], "_"),
        state.example.name
    ));
    std::fs::create_dir_all(dir).map_err(|e| format!("{dir}: {e}"))?;
    std::fs::write(&file, state.example.to_toml()?)
        .map_err(|e| format!("{}: {e}", file.display()))?;
    Ok(file.display().to_string())
}

fn describe_verification(
    database: &Database<'_>,
    name: &str,
    v: &Verification,
    profile: Option<&Profile>,
) -> String {
    let mut out = format!("{name} at {:#x}, {} view", v.entry, view_name(v.view));
    if let Some(profile) = profile {
        let _ = write!(out, ", on {}", profile.label());
    }
    out.push_str(": ");
    match &v.verdict {
        Verdict::Agreed(agreement) => {
            let _ = write!(
                out,
                "agreed on {} of {} sampled states",
                agreement.agreed, agreement.states
            );
            if !agreement.skips.is_empty() {
                let skips: Vec<String> = agreement
                    .skips
                    .iter()
                    .map(|(skip, count)| format!("{} {count}", skip.describe()))
                    .collect();
                let _ = write!(out, ", skipped: {}", skips.join(", "));
            }
            out.push('\n');
        }
        Verdict::NotCheckable(why) => {
            let _ = writeln!(out, "not checkable: {why}");
        }
        Verdict::Differs(Difference::Structure(mismatch)) => {
            let _ = writeln!(out, "differs: structure: {mismatch}");
        }
        Verdict::Differs(Difference::Run(counterexample)) => {
            let _ = writeln!(
                out,
                "differs: state {} of seed {:#x}: {}",
                counterexample.index, counterexample.seed, counterexample.message
            );
            let at: Vec<String> = counterexample
                .addresses
                .iter()
                .map(|address| format!("{address:#x}"))
                .collect();
            match &counterexample.divergence {
                Some(divergence) => {
                    if let Some((stmt, value, l1, l2)) = divergence.assignment {
                        let _ = writeln!(
                            out,
                            "  first diverging assignment: s{} ({}): v{} is {} in L1, {} in L2",
                            stmt.0,
                            at.join(", "),
                            value.0,
                            show(&l1),
                            show(&l2)
                        );
                    } else {
                        let _ = writeln!(
                            out,
                            "  every assignment agrees; the runs part where they stop: L1 block {}, L2 statement {} ({})",
                            divergence
                                .l1_stop
                                .map_or_else(|| "-".to_owned(), |b| format!("b{}", b.0)),
                            divergence
                                .l2_stop
                                .map_or_else(|| "-".to_owned(), |s| format!("s{}", s.0)),
                            at.join(", ")
                        );
                    }
                    let _ = writeln!(
                        out,
                        "  L1 entered {} blocks, L2 started {} statements",
                        divergence.l1_steps, divergence.l2_steps
                    );
                }
                None => out.push_str("  where the runs part is not recorded\n"),
            }
            let _ = writeln!(
                out,
                "  state: {}",
                state_text(database, &counterexample.state)
            );
        }
    }
    let _ = writeln!(
        out,
        "cost: lowering {:.2?}, checks {:.2?}",
        v.lowering, v.checking
    );
    out
}

/// A value as hexadecimal, its undefined bits as `?` where any.
fn show(value: &binbun_semantics::interpret::Value) -> String {
    if value.undefined.is_zero() {
        format!("{:#x}", value.bits.low_u128())
    } else {
        format!(
            "{:#x} (undefined {:#x})",
            value.bits.low_u128(),
            value.undefined.low_u128()
        )
    }
}

/// A state's registers by name (those with a defined value), return
/// address, and the memory it sets (a shaped state's objects), each
/// region's bytes in hexadecimal.
fn state_text(database: &Database<'_>, state: &State) -> String {
    let declarations = database.declarations();
    let mut parts: Vec<String> = state
        .registers
        .iter()
        .enumerate()
        .filter(|(_, value)| value.undefined.is_zero())
        .map(|(index, value)| {
            let name = declarations
                .and_then(|d| d.registers.get(index).map(|info| info.name.to_owned()))
                .unwrap_or_else(|| format!("r{index}"));
            format!("{name}={:#x}", value.bits.low_u128())
        })
        .collect();
    parts.push(format!("return={:#x}", state.return_address));
    for (start, bytes) in &state.memory {
        let mut region = format!("[{start:#x}]=");
        for byte in bytes {
            let _ = write!(region, "{byte:02x}");
        }
        parts.push(region);
    }
    parts.join(" ")
}

/// The cause of a message: its words up to the first detail.
fn cause(message: &str) -> String {
    let mut words: Vec<&str> = message.split_whitespace().take(6).collect();
    words.retain(|word| !word.starts_with("0x") && !word.starts_with('v'));
    words.join(" ")
}

/// Every function of `database` (the file at `path`) checked: the report
/// and the exit status ([`status`]).
fn verify_every(database: &Database<'_>, path: &str, options: &Options) -> (String, u8) {
    let start = Instant::now();
    let mut all: Vec<Verification> = Vec::new();
    verify::verify_all(database, options, threads(), |v| all.push(v));
    let wall = start.elapsed();
    let (mut agreeing, mut differs, mut unchecked) = (0usize, Vec::new(), BTreeMap::new());
    let (mut states, mut agreed) = (0usize, 0usize);
    let mut skips: BTreeMap<&str, usize> = BTreeMap::new();
    let (mut lowering, mut checking) = (Duration::ZERO, Duration::ZERO);
    for v in &all {
        lowering += v.lowering;
        checking += v.checking;
        match &v.verdict {
            Verdict::Agreed(agreement) => {
                agreeing += 1;
                states += agreement.states;
                agreed += agreement.agreed;
                for (skip, count) in &agreement.skips {
                    *skips.entry(skip.describe()).or_default() += count;
                }
            }
            Verdict::Differs(_) => differs.push(v),
            Verdict::NotCheckable(why) => {
                *unchecked.entry(cause(why)).or_insert(0usize) += 1;
            }
        }
    }
    let mut out = String::new();
    let _ = writeln!(
        out,
        "{path}, {} view, {} random and up to {} shaped states each{}: {} functions: agreed {agreeing}, differs {}, not checkable {}",
        view_name(options.view),
        options.states,
        options.shaped,
        options
            .fuel
            .map(|fuel| format!(", fuel {fuel}"))
            .unwrap_or_default()
            + &options
                .profile
                .as_ref()
                .map(|profile| format!(", on {}", profile.label()))
                .unwrap_or_default(),
        all.len(),
        differs.len(),
        unchecked.values().sum::<usize>()
    );
    let skipped: Vec<String> = skips.iter().map(|(why, n)| format!("{why} {n}")).collect();
    let _ = writeln!(
        out,
        "  states of the functions that agreed: {states} run, {agreed} agreed, skipped: {}",
        skipped.join(", ")
    );
    let _ = writeln!(
        out,
        "  time: {wall:.2?} wall on {} threads; summed: lowering {lowering:.2?}, checks {checking:.2?}",
        threads()
    );
    let mut causes: Vec<(&String, &usize)> = unchecked.iter().collect();
    causes.sort_by_key(|&(_, &n)| std::cmp::Reverse(n));
    for (why, n) in causes.into_iter().take(10) {
        let _ = writeln!(out, "  not checkable: {why}: {n}");
    }
    for v in differs.iter().take(20) {
        let name = database
            .data_name(v.entry)
            .unwrap_or_else(|| format!("{:#x}", v.entry));
        out.push_str(&describe_verification(
            database,
            &name,
            v,
            options.profile.as_deref(),
        ));
    }
    let mut slowest: Vec<&Verification> = all.iter().collect();
    slowest.sort_by_key(|v| std::cmp::Reverse(v.lowering + v.checking));
    for v in slowest.into_iter().take(5) {
        let name = database
            .data_name(v.entry)
            .unwrap_or_else(|| format!("{:#x}", v.entry));
        let _ = writeln!(
            out,
            "  slow: {name}: lowering {:.2?}, checks {:.2?}",
            v.lowering, v.checking
        );
    }
    (out, status(agreeing + differs.len(), differs.len()))
}

/// `why FILE FUNCTION [VAR] [--view exact|reading] [--project DIR]`: where
/// the function's name comes from (with `--project`, the project's edits:
/// the user's, or a library signature's with its pack and how it
/// matched), then each variable (or `VAR` alone) and the return value
/// with its printed type and name and their evidence; `FUNCTION` may be a
/// name the project gives. `why FILE --all`: over every function, the share of
/// variables whose type has a source other than the default; `why FILE
/// --global TARGET`: the one type of the global `TARGET` names (a name or
/// a hexadecimal address) over the program, with every function's
/// evidence and each field's references.
pub fn why(args: &[String]) -> Result<String, String> {
    let flags = arguments(args)?;
    let Some((&path, rest)) = flags.positional.split_first() else {
        return Err(USAGE.to_owned());
    };
    if let Some(global) = flags.global {
        if !rest.is_empty() || flags.all {
            return Err(USAGE.to_owned());
        }
        let data = read(path)?;
        let image = load(path, &data)?;
        let database = database_of(path, &image)?;
        return why_global(&database, global);
    }
    if rest.len() > 2 || flags.all != rest.is_empty() {
        return Err(USAGE.to_owned());
    }
    let data = read(path)?;
    let image = load(path, &data)?;
    let edits = flags
        .project
        .map(|dir| Edits::load(&Project::new(dir).edits()))
        .transpose()?;
    let database = match &edits {
        Some(edits) => {
            Database::with_corrections(&image, Seeds::ALL, None, edits.corrections().clone())
                .map_err(|error| format!("{path}: {error}"))?
        }
        None => database_of(path, &image)?,
    };
    match rest {
        [] => Ok(coverage(&database, path, flags.view)),
        [function, rest @ ..] => {
            let edited = edits.as_ref().and_then(|edits| {
                edits
                    .functions()
                    .find(|(_, name)| name == function)
                    .and_then(|(entry, _)| database.function_at(entry))
            });
            let id = match edited {
                Some(id) => id,
                None => database.find_function(function)?,
            };
            let explanation = evidence::explain(&database, id, flags.view)?;
            let items: Vec<&Item> = match rest.first() {
                Some(name) => vec![
                    explanation
                        .named(name)
                        .ok_or_else(|| format!("{function} has no variable {name}"))?,
                ],
                None => explanation.items.iter().collect(),
            };
            let mut out = String::new();
            if rest.is_empty()
                && let Some(entry) = database.function(id).map(|f| f.entry)
            {
                out.push_str(&function_name(&database, entry, edits.as_ref()));
            }
            for item in items {
                out.push_str(&describe_item(item));
            }
            Ok(out)
        }
    }
}

fn database_of<'a>(
    path: &str,
    image: &'a binbun_loader::Image<'a>,
) -> Result<Database<'a>, String> {
    database(path, image, Seeds::ALL)
}

/// Where the name of the function at `entry` comes from: the project's
/// `edits` (a library signature's match: its pack, library, object and
/// how; else an edit), else the binary's symbol or debug information,
/// else binbun's own; and a signature match the user rejected.
fn function_name(database: &Database<'_>, entry: u64, edits: Option<&Edits>) -> String {
    let signature = edits.and_then(|edits| edits.signature(entry));
    let edited = edits.and_then(|edits| edits.function(entry));
    let mut out = match (edited, signature) {
        (Some(name), Some(s)) if !s.rejected && s.name == name => format!(
            "function {name} at {entry:#x}: name from a library signature: {} {}, {} (pack {}), {}\n",
            s.library, s.version, s.object, s.pack, s.how
        ),
        (Some(name), _) => format!("function {name} at {entry:#x}: name from an edit\n"),
        (None, _) => match database.name(entry) {
            Some(name) => {
                let symbol = database
                    .image()
                    .symbols
                    .iter()
                    .any(|symbol| symbol.address == entry && symbol.name == name);
                let source = if symbol {
                    "the binary's symbol"
                } else {
                    "debug information"
                };
                format!("function {name} at {entry:#x}: name from {source}\n")
            }
            None => format!("function sub_{entry:X} at {entry:#x}: no name (binbun's)\n"),
        },
    };
    if let Some(s) = signature {
        if s.rejected {
            let _ = writeln!(
                out,
                "  rejected: {} ({} {}, pack {}, {})",
                s.name, s.library, s.version, s.pack, s.how
            );
        } else if edited != Some(s.name.as_str()) {
            let _ = writeln!(
                out,
                "  a library signature says {} ({} {}, pack {}, {}); the edit stays",
                s.name, s.library, s.version, s.pack, s.how
            );
        }
        if s.no_return && !s.rejected {
            out.push_str("  declared noreturn (type library)\n");
        }
    }
    out
}

/// The one type of the global `wanted` names in `database`
/// ([`Database::global_type`]): its declaration, where it comes from,
/// every function's evidence (offset, width, type, strength; whole reads
/// and writes counted) and each field's references
/// ([`Database::global_fields`]).
fn why_global(database: &Database<'_>, wanted: &str) -> Result<String, String> {
    let address = resolve(database, wanted)?;
    let ty = database
        .global_type(address)
        .ok_or_else(|| format!("no function's code types the global at {address:#x}"))?;
    let callers = database.callers(&[]);
    let name = database
        .data_name(ty.start)
        .unwrap_or_else(|| format!("g_{:x}", ty.start));
    let declaration = database
        .global_declaration(&callers, &ty, &name, &Style::kr())
        .unwrap_or_else(|| name.clone());
    let mut out = format!(
        "{declaration}; /* {:#x}, {} bytes */\n  from {:?}, evidence strength {}, {} other types overridden\n",
        ty.start, ty.size, ty.source, ty.strength.0, ty.conflicts
    );
    let structs = callers.schemes.structs();
    for clue in &ty.clues {
        let function = database
            .name(clue.function)
            .map_or_else(|| format!("{:#x}", clue.function), str::to_owned);
        let what = match clue.whole {
            0 => String::from("part"),
            count => format!("whole x{count}"),
        };
        let _ = writeln!(
            out,
            "  {function}: +{:#x} {} bits {} (strength {}, {what})",
            clue.offset,
            clue.field.bits,
            field_type(structs, &clue.field.ty),
            clue.field.strength.0,
        );
    }
    for field in database.global_fields(&callers, &ty) {
        let _ = writeln!(
            out,
            "  field +{:#x} {} ({} bytes): {} references",
            field.offset, field.name, field.bytes, field.references
        );
    }
    Ok(out)
}

/// A field type of a global's evidence, as text.
fn field_type(structs: &Structs, ty: &FieldType) -> String {
    match ty {
        FieldType::Scalar(scalar) => format!("{scalar:?}"),
        FieldType::Pointer(target) => format!("pointer to {target:?}"),
        FieldType::Opaque => "pointer to another known type".to_owned(),
        &FieldType::Struct(id) => format!("pointer to struct {}", structs.name(id)),
        &FieldType::Pointers(id) => {
            format!("pointer to pointers to struct {}", structs.name(id))
        }
        FieldType::ScalarPointers(target) => format!("pointer to pointers to {target:?}"),
        FieldType::Code {
            parameters,
            returns,
            variadic,
        } => {
            let mut parameters: Vec<String> = parameters.iter().map(|p| format!("{p:?}")).collect();
            if *variadic {
                parameters.push("...".to_owned());
            }
            let returns = returns
                .as_ref()
                .map_or_else(|| "void".to_owned(), |r| format!("{r:?}"));
            format!("code ({}) -> {returns}", parameters.join(", "))
        }
    }
}

fn source_text(source: &Source) -> String {
    let callee = |c: &evidence::Callee| {
        let name = c
            .name
            .clone()
            .or_else(|| c.address.map(|a| format!("{a:#x}")))
            .unwrap_or_else(|| "an unknown callee".to_owned());
        let what = c
            .parameter
            .map_or_else(|| "result".to_owned(), |p| format!("parameter {p}"));
        let calls: Vec<String> = c.calls.iter().map(|a| format!("{a:#x}")).collect();
        format!("{name}'s {what} (call at {})", calls.join(", "))
    };
    match source {
        Source::User => "your type".to_owned(),
        Source::Debug => "debug information".to_owned(),
        Source::Prototype => "its declared prototype".to_owned(),
        Source::Platform => "the platform".to_owned(),
        Source::Declaration => "the global's declaration".to_owned(),
        Source::Promoted => "a callee's pointer parameter (promoted)".to_owned(),
        Source::Callee(c) => format!("the prototype of {}", callee(c)),
        Source::Scheme(c) => format!("the solved type of {}", callee(c)),
        Source::Callers => "what every caller passes".to_owned(),
        Source::Program => "the program's type of the global (every function's)".to_owned(),
        Source::Solver => "the type solver (its own code)".to_owned(),
        Source::Default => "default (width only)".to_owned(),
    }
}

fn describe_item(item: &Item) -> String {
    let name_source = match item.name_source {
        NameSource::Debug => "debug information",
        NameSource::Symbol => "a symbol",
        NameSource::User => "the user",
        NameSource::Convention => "the convention",
        NameSource::Declared => "the declared prototype",
        NameSource::Argument => "a callee's declared parameter",
        NameSource::Counter => "a for loop's counter",
        NameSource::Result => "the returned variable",
        NameSource::Printer => "the printer",
    };
    let mut out = format!(
        "{} ({:?}): {}: {} [{:?}]; name from {name_source}\n",
        item.name,
        item.subject,
        item.ty,
        source_text(&item.source),
        item.evidence
    );
    for (clues, label) in [(&item.clues, ""), (&item.conflicts, "conflict: ")] {
        for clue in clues {
            let at: Vec<String> = clue.addresses.iter().map(|a| format!("{a:#x}")).collect();
            let _ = writeln!(
                out,
                "    {label}{} {} strength {}: {} at {}",
                if clue.lower { "lower" } else { "upper" },
                evidence::shape_c(clue.shape),
                clue.strength,
                clue.reason,
                if at.is_empty() {
                    "-".to_owned()
                } else {
                    at.join(", ")
                }
            );
        }
    }
    out
}

/// Over every function: how many variables, of them typed by a source
/// other than the default, by source and by name source.
fn coverage(database: &Database<'_>, path: &str, view: View) -> String {
    let start = Instant::now();
    let (mut items, mut sourced, mut failed) = (0usize, 0usize, 0usize);
    let mut by_source: BTreeMap<String, usize> = BTreeMap::new();
    let mut by_name: BTreeMap<String, usize> = BTreeMap::new();
    each(
        database,
        view,
        &[],
        threads(),
        |_, lowered, interfaces| {
            lowered
                .and_then(|lowered| evidence::explain_lowered(database, &lowered, interfaces, view))
        },
        |explained: Result<Explanation, String>| {
            let Ok(explanation) = explained else {
                failed += 1;
                return;
            };
            for item in &explanation.items {
                items += 1;
                if item.source != Source::Default {
                    sourced += 1;
                }
                let kind = match &item.source {
                    Source::Callee(_) => "callee prototype".to_owned(),
                    Source::Scheme(_) => "callee scheme".to_owned(),
                    other @ (Source::User
                    | Source::Debug
                    | Source::Prototype
                    | Source::Platform
                    | Source::Declaration
                    | Source::Promoted
                    | Source::Callers
                    | Source::Program
                    | Source::Solver
                    | Source::Default) => format!("{other:?}"),
                };
                *by_source.entry(kind).or_default() += 1;
                *by_name
                    .entry(format!("{:?}", item.name_source))
                    .or_default() += 1;
            }
        },
    );
    #[allow(clippy::cast_precision_loss, reason = "a share for a report")]
    let share = 100.0 * sourced as f64 / items.max(1) as f64;
    let mut out = format!(
        "{path}, {} view: {items} variables and return values, {sourced} ({share:.1}%) with a source other than the default; {failed} functions not decompiled; {:.2?}\n",
        view_name(view),
        start.elapsed()
    );
    for (source, n) in by_source {
        let _ = writeln!(out, "  type from {source}: {n}");
    }
    for (source, n) in by_name {
        let _ = writeln!(out, "  name from {source}: {n}");
    }
    out
}

/// `origin FILE FUNCTION VAR [--view exact|reading] [--depth N] [--steps
/// N]`: where variable `VAR` (as the C names it) comes from and where it
/// goes; `origin FILE --sample N [--seed S]`: N variables of N functions
/// picked by the seed, with chain-length statistics.
pub fn origin(args: &[String]) -> Result<String, String> {
    let flags = arguments(args)?;
    let query = Query {
        view: flags.view,
        depth: flags.depth,
        steps: flags.steps,
    };
    match (flags.sample, &flags.positional[..]) {
        (Some(count), [path]) => {
            let data = read(path)?;
            let image = load(path, &data)?;
            let database = database_of(path, &image)?;
            Ok(sample(
                &database,
                path,
                count,
                flags.seed.unwrap_or(0),
                &query,
            ))
        }
        (None, [path, function, name]) => {
            let data = read(path)?;
            let image = load(path, &data)?;
            let database = database_of(path, &image)?;
            let id = database.find_function(function)?;
            let explanation = evidence::explain(&database, id, flags.view)?;
            let var = explanation
                .named(name)
                .and_then(|item| item.var)
                .ok_or_else(|| format!("{function} has no variable {name}"))?;
            let origins = origin::origins(&database, id, Start::Var(var), &query)?;
            Ok(describe_origins(&database, name, &origins))
        }
        _ => Err(USAGE.to_owned()),
    }
}

fn describe_origins(database: &Database<'_>, name: &str, origins: &Origins) -> String {
    let mut out = format!(
        "{name} in {} at {:#x}: {} values\n",
        database.data_name(origins.entry).unwrap_or_default(),
        origins.entry,
        origins.values.len()
    );
    for chain in &origins.chains {
        describe_step(chain, 1, &mut out);
    }
    if !origins.uses.is_empty() {
        out.push_str("uses:\n");
        for used in &origins.uses {
            let _ = writeln!(out, "  {:#x}: {}", used.address, used.kind);
        }
    }
    out
}

fn describe_step(step: &Step, indent: usize, out: &mut String) {
    let pad = "  ".repeat(indent);
    let kind = match &step.kind {
        Kind::Constant(c) => format!("constant {c:#x}"),
        Kind::Undefined => "undefined".to_owned(),
        Kind::Parameter {
            register, index, ..
        } => format!(
            "parameter {} ({register})",
            index.map_or_else(|| "-".to_owned(), |i| i.to_string())
        ),
        Kind::Load { address, bytes } => format!("load {bytes} bytes from {address}"),
        Kind::Call {
            call, callee, name, ..
        } => format!(
            "result of the call at {call:#x} to {}",
            name.clone()
                .or_else(|| callee.map(|c| format!("{c:#x}")))
                .unwrap_or_else(|| "a computed address".to_owned())
        ),
        Kind::Operation(op) => op.clone(),
        Kind::Join => "join of".to_owned(),
        Kind::Other(what) => what.clone(),
        Kind::Cut => "(not followed)".to_owned(),
    };
    let at: Vec<String> = step.addresses.iter().map(|a| format!("{a:#x}")).collect();
    let folded: Vec<String> = step
        .folded
        .iter()
        .map(|f| format!("{:?}", f.kind).to_lowercase())
        .collect();
    let _ = write!(out, "{pad}v{}: {kind} at {}", step.value.0, at.join(", "));
    if !folded.is_empty() {
        let _ = write!(out, " (folded: {})", folded.join(", "));
    }
    out.push('\n');
    let remotes: &[Remote] = match &step.kind {
        Kind::Parameter { sites, .. } => sites,
        Kind::Call { returns, .. } => returns,
        Kind::Constant(_)
        | Kind::Undefined
        | Kind::Load { .. }
        | Kind::Operation(_)
        | Kind::Join
        | Kind::Other(_)
        | Kind::Cut => &[],
    };
    for remote in remotes {
        let _ = writeln!(
            out,
            "{pad}  in {} at {:#x}:",
            remote
                .name
                .clone()
                .unwrap_or_else(|| format!("{:#x}", remote.function)),
            remote.address
        );
        if let Some(chain) = &remote.chain {
            describe_step(chain, indent + 2, out);
        }
    }
    for input in &step.inputs {
        describe_step(input, indent + 1, out);
    }
}

/// A 64-bit mix (`SplitMix64`'s finalizer).
fn mix(mut x: u64) -> u64 {
    x ^= x >> 30;
    x = x.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x ^= x >> 27;
    x = x.wrapping_mul(0x94d0_49bb_1331_11eb);
    x ^ (x >> 31)
}

/// What one sampled query found.
struct Sampled {
    chains: Vec<(usize, usize, usize)>,
    folds: BTreeMap<Trivial, usize>,
    uses: usize,
    time: Duration,
}

/// Origin queries on one variable of each of `count` functions picked by
/// `seed`: chain sizes, depths and folds.
fn sample(database: &Database<'_>, path: &str, count: usize, seed: u64, query: &Query) -> String {
    let mut entries: Vec<u64> = database.functions().map(|(_, f)| f.entry).collect();
    entries.sort_by_key(|&entry| mix(entry ^ seed));
    let picked: BTreeSet<u64> = entries.into_iter().take(count).collect();
    let start = Instant::now();
    let mut found: Vec<Sampled> = Vec::new();
    let mut failed = 0usize;
    each(
        database,
        query.view,
        &[],
        threads(),
        |_, lowered: Result<Lowered, String>, _| {
            let lowered = lowered.ok()?;
            if !picked.contains(&lowered.entry) {
                return None;
            }
            Some(query_one(database, &lowered, seed, query))
        },
        |one| match one {
            Some(Some(one)) => found.push(one),
            Some(None) => failed += 1,
            None => {}
        },
    );
    let mut sizes: Vec<usize> = found
        .iter()
        .flat_map(|s| s.chains.iter().map(|c| c.0))
        .collect();
    let mut depths: Vec<usize> = found
        .iter()
        .flat_map(|s| s.chains.iter().map(|c| c.1))
        .collect();
    let folded: usize = found
        .iter()
        .flat_map(|s| s.chains.iter().map(|c| c.2))
        .sum();
    sizes.sort_unstable();
    depths.sort_unstable();
    let mut folds: BTreeMap<Trivial, usize> = BTreeMap::new();
    for one in &found {
        for (kind, n) in &one.folds {
            *folds.entry(*kind).or_default() += n;
        }
    }
    let summary = |list: &[usize]| {
        let median = list.get(list.len() / 2).copied().unwrap_or(0);
        let max = list.last().copied().unwrap_or(0);
        #[allow(clippy::cast_precision_loss, reason = "a mean for a report")]
        let mean = list.iter().sum::<usize>() as f64 / list.len().max(1) as f64;
        format!("mean {mean:.1}, median {median}, max {max}")
    };
    let slowest = found.iter().map(|s| s.time).max().unwrap_or_default();
    let uses: usize = found.iter().map(|s| s.uses).sum();
    let mut out = format!(
        "{path}, {} view: {} variables queried ({} functions picked, {failed} without a variable), {} chains, {:.2?}, slowest {slowest:.2?}\n",
        view_name(query.view),
        found.len(),
        picked.len(),
        sizes.len(),
        start.elapsed()
    );
    let _ = writeln!(out, "  chain steps: {}", summary(&sizes));
    let _ = writeln!(out, "  chain depth: {}", summary(&depths));
    let _ = writeln!(
        out,
        "  trivial steps folded: {folded} ({folds:?}); uses listed: {uses}"
    );
    out
}

/// The origins of the variable of `lowered` the seed picks, if it has
/// one with L1 values.
fn query_one(
    database: &Database<'_>,
    lowered: &Lowered,
    seed: u64,
    query: &Query,
) -> Option<Sampled> {
    let l1 = &lowered.prepared.l1;
    let var = lowered
        .l2
        .variables
        .iter()
        .enumerate()
        .filter(|(_, v)| {
            !matches!(v.kind, VarKind::Global(_)) && !values_of(l1, v.kind, &v.origins).is_empty()
        })
        .min_by_key(|(index, _)| mix(lowered.entry ^ seed ^ (*index as u64).rotate_left(32)))
        .map(|(index, _)| binbun_ast::ir::VarId(u32::try_from(index).unwrap_or(u32::MAX)))?;
    let start = Instant::now();
    let mut budget = query.steps;
    let origins = origin::origins_lowered(database, lowered, Start::Var(var), query, &mut budget);
    let mut folds: BTreeMap<Trivial, usize> = BTreeMap::new();
    let mut stack: Vec<&Step> = origins.chains.iter().collect();
    while let Some(step) = stack.pop() {
        for folded in &step.folded {
            *folds.entry(folded.kind).or_default() += 1;
        }
        stack.extend(&step.inputs);
    }
    Some(Sampled {
        chains: origins
            .chains
            .iter()
            .map(|c| (c.size(), c.depth(), c.folds()))
            .collect(),
        folds,
        uses: origins.uses.len(),
        time: start.elapsed(),
    })
}
