//! `binbun sig`: library signature packs made, checked, shown, compared,
//! and matched against a binary ([`binbun::signatures`]).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use binbun::analysis::Seeds;
use binbun::signatures::{self, How, MakeOptions, Match, MatchOptions};
use binbun_loader::SymbolKind;
use binbun_sigpack::pack::{self as packs, Built, Check, Entry, Pack};
use binbun_sigpack::rust;
use msvc_demangler::DemangleFlags;

use super::{database, load, read};

/// The usage of `binbun sig`.
const USAGE: &str = "usage:
  binbun sig make --library NAME --version V --licence SPDX [--notice TEXT]
                  [--source PACKAGE --sha256 H [--url URL]] [--build ID] [--toolchain T] [--flags F]
                  [--code] [--no-separators] [--add-to PACK] INPUT... -o PACK.jsonl.zst
                  [--plain: -o PACK.jsonl]
                  (zstd-compressed by binbun's own encoder: a quarter of the JSON Lines;
                  `zstd -19` of a --plain pack makes it a sixteenth, as binbun's shipped packs are)
  binbun sig check PACK
  binbun sig show PACK [NAME]
  binbun sig compare PACK PACK
  binbun sig match FILE --pack PACK... [--behaviour] [--sweep] [--answers UNSTRIPPED]
  binbun sig eval CASES --packs DIR [--sweep|--no-sweep]";

/// `sig SUBCOMMAND ...`.
pub fn sig(args: &[String]) -> Result<String, String> {
    let (command, rest) = args
        .split_first()
        .map_or(("", &[][..]), |(c, r)| (c.as_str(), r));
    match command {
        "make" => make(rest),
        "check" => check(rest),
        "show" => show(rest),
        "compare" => compare(rest),
        "match" => matching(rest),
        "eval" => eval(rest),
        _ => Err(USAGE.to_owned()),
    }
}

/// The value after flag `flag`.
fn value<'a>(flag: &str, args: &mut impl Iterator<Item = &'a String>) -> Result<String, String> {
    args.next()
        .cloned()
        .ok_or_else(|| format!("{flag} needs a value\n{USAGE}"))
}

/// The pack at `path` (JSON Lines, or zstd-compressed JSON Lines).
fn pack(path: &str) -> Result<Pack, String> {
    let text = packs::text(read(path)?).map_err(|e| format!("{path}: {e}"))?;
    Pack::read(&text).map_err(|e| format!("{path}: {e}"))
}

/// `sig make ...`: a pack of the inputs' functions, written to `-o`
/// (merged into `--add-to`'s pack as a further build), compressed with
/// zstd (`.jsonl.zst`) unless `--plain` (`.jsonl`, to review).
fn make(args: &[String]) -> Result<String, String> {
    let mut options = MakeOptions {
        build: "default".into(),
        separators: true,
        ..MakeOptions::default()
    };
    let mut inputs = Vec::new();
    let mut output = None;
    let mut add_to = None;
    let mut sha256 = None;
    let mut url = None;
    let mut plain = false;
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--library" => options.library = value(arg, &mut args)?,
            "--version" => options.version = value(arg, &mut args)?,
            "--licence" | "--license" => options.licence = value(arg, &mut args)?,
            "--notice" => options.notice = Some(value(arg, &mut args)?),
            "--source" => {
                options.source = Some(binbun_sigpack::pack::Source {
                    package: value(arg, &mut args)?,
                    url: None,
                    sha256: String::new(),
                });
            }
            "--sha256" => sha256 = Some(value(arg, &mut args)?),
            "--url" => url = Some(value(arg, &mut args)?),
            "--build" => options.build = value(arg, &mut args)?,
            "--toolchain" => options.toolchain = Some(value(arg, &mut args)?),
            "--flags" => options.flags = Some(value(arg, &mut args)?),
            "--code" => options.code = true,
            "--no-separators" => options.separators = false,
            "--add-to" => add_to = Some(value(arg, &mut args)?),
            "-o" => output = Some(value(arg, &mut args)?),
            "--plain" => plain = true,
            _ if arg.starts_with('-') => return Err(USAGE.to_owned()),
            _ => inputs.push(arg.clone()),
        }
    }
    if let Some(source) = &mut options.source {
        source.sha256 = sha256.ok_or("--source needs --sha256")?;
        source.url = url;
    } else if url.is_some() || sha256.is_some() {
        return Err("--url and --sha256 describe a --source PACKAGE".into());
    }
    if options.library.is_empty() || options.version.is_empty() {
        return Err(format!("sig make needs --library and --version\n{USAGE}"));
    }
    if options.licence.is_empty() {
        return Err(
            "sig make writes no pack without --licence (the library's licence, SPDX)".into(),
        );
    }
    let output = output.ok_or_else(|| format!("sig make needs -o PACK\n{USAGE}"))?;
    // The name says which the file is: discovery reads `.jsonl` and
    // `.jsonl.zst` files.
    let suffix = if plain { ".jsonl" } else { ".jsonl.zst" };
    if !output.ends_with(suffix) {
        return Err(format!(
            "{output}: sig make writes {}: name it PACK{suffix}",
            if plain {
                "JSON Lines with --plain"
            } else {
                "zstd-compressed JSON Lines (--plain: PACK.jsonl, uncompressed)"
            }
        ));
    }
    if inputs.is_empty() {
        return Err(USAGE.to_owned());
    }
    let data = inputs
        .iter()
        .map(|path| Ok((path.clone(), read(path)?)))
        .collect::<Result<Vec<_>, String>>()?;
    let made = signatures::make(&data, &options)?;
    let mut pack = match add_to {
        Some(path) => {
            let mut existing = pack(&path)?;
            existing.merge(made)?;
            existing
        }
        None => made,
    };
    pack.functions
        .sort_by(|a, b| (&a.name, &a.object).cmp(&(&b.name, &b.object)));
    let text = pack.write()?;
    let bytes = if plain {
        text.into_bytes()
    } else {
        packs::compress(&text)
    };
    std::fs::write(&output, &bytes).map_err(|e| format!("{output}: {e}"))?;
    Ok(format!("{output}: {}\n", summary(&pack, bytes.len())))
}

/// A pack's counts: functions, builds, recordings, groups, separators.
fn summary(pack: &Pack, bytes: usize) -> String {
    let records: Vec<_> = pack.records().collect();
    let recorded = records
        .iter()
        .filter(|(_, _, build)| matches!(build.check, Some(Check::Recorded(_))))
        .count();
    let code = records
        .iter()
        .filter(|(_, _, build)| matches!(build.check, Some(Check::Code(_))))
        .count();
    let trivial = records.iter().filter(|(_, _, build)| build.trivial).count();
    let groups: BTreeSet<&str> = pack
        .functions
        .iter()
        .filter_map(|e| e.group.as_deref())
        .collect();
    let separators: usize = pack.functions.iter().map(|e| e.separators.len()).sum();
    format!(
        "{} {} ({} builds): {} functions, {} records ({trivial} trivial, {recorded} recorded, {code} with code), {} groups, {separators} separators, {bytes} bytes",
        pack.header.library,
        pack.header.version,
        pack.header.builds.len(),
        pack.functions.len(),
        records.len(),
        groups.len(),
    )
}

/// `sig check PACK`: the pack read and checked.
fn check(args: &[String]) -> Result<String, String> {
    let [path] = args else {
        return Err(USAGE.to_owned());
    };
    let data = read(path)?;
    let bytes = data.len();
    let text = packs::text(data).map_err(|e| format!("{path}: {e}"))?;
    let pack = Pack::read(&text).map_err(|e| format!("{path}: {e}"))?;
    let (errors, notes) = pack.check();
    let mut out = format!("{path}: {}\n", summary(&pack, bytes));
    if pack.write()? != text {
        out.push_str(
            "error: the pack is not in its written form (sorted, one line per function)\n",
        );
    }
    for error in &errors {
        let _ = writeln!(out, "error: {error}");
    }
    for note in &notes {
        let _ = writeln!(out, "note: {note}");
    }
    if errors.is_empty() { Ok(out) } else { Err(out) }
}

/// `sig show PACK [NAME]`: the header and every function's name, object
/// and builds; or one function's lines.
#[expect(
    clippy::too_many_lines,
    reason = "the pack's list, or every field of one function"
)]
fn show(args: &[String]) -> Result<String, String> {
    let (path, name) = match args {
        [path] => (path, None),
        [path, name] => (path, Some(name)),
        _ => return Err(USAGE.to_owned()),
    };
    let pack = pack(path)?;
    let mut out = String::new();
    match name {
        None => {
            let _ = writeln!(
                out,
                "{} {} for {}-{}, {}; builds: {}",
                pack.header.library,
                pack.header.version,
                pack.header.target.arch,
                pack.header.target.os,
                pack.header.licence,
                pack.header
                    .builds
                    .iter()
                    .map(|b| b.id.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            provenance(&mut out, &pack.header);
            for entry in &pack.functions {
                let _ = writeln!(
                    out,
                    "{} {} [{}]{}",
                    entry.name,
                    entry.object,
                    entry.builds.keys().cloned().collect::<Vec<_>>().join(" "),
                    entry
                        .group
                        .as_ref()
                        .map_or_else(String::new, |g| format!(" group {g}"))
                );
            }
        }
        Some(name) => {
            for entry in pack
                .functions
                .iter()
                .filter(|e| &e.name == name || e.aliases.contains(name))
            {
                let _ = writeln!(out, "{} ({})", entry.name, entry.object);
                if !entry.aliases.is_empty() {
                    let _ = writeln!(out, "  aliases: {}", entry.aliases.join(", "));
                }
                if entry.copies > 1 {
                    let _ = writeln!(out, "  identical definitions: {}", entry.copies);
                }
                if let Some(group) = &entry.group {
                    let _ = writeln!(out, "  group: {group}");
                }
                if !entry.look_alikes.is_empty() {
                    let _ = writeln!(out, "  look-alikes: {}", entry.look_alikes.join(", "));
                }
                if let Some(prototype) = &entry.prototype {
                    let _ = writeln!(out, "  prototype: {prototype}");
                }
                for (id, built) in &entry.builds {
                    let Some(build) = pack.build(entry, id) else {
                        continue;
                    };
                    let same = match built {
                        Built::Same(other) => format!(" (as {})", other.trim_start_matches('=')),
                        Built::Record(_) => String::new(),
                    };
                    let check = match &build.check {
                        Some(Check::Recorded(recording)) => format!(
                            "{} states recorded, shape {}",
                            recording.states.len(),
                            recording.shape
                        ),
                        Some(Check::Code(code)) => format!("{} bytes of code", code.code.len() / 2),
                        None => "not checkable".into(),
                    };
                    let _ = writeln!(
                        out,
                        "  {id}{same}: {} {}{}, {check}; calls {}",
                        build.identity,
                        build.bytes,
                        if build.trivial { " (trivial)" } else { "" },
                        if build.callees.is_empty() {
                            "nothing".to_owned()
                        } else {
                            build.callees.join(", ")
                        }
                    );
                }
                for separator in &entry.separators {
                    let _ = writeln!(
                        out,
                        "  told from {} by state {}",
                        separator.from, separator.state
                    );
                }
            }
            if out.is_empty() {
                return Err(format!("{path}: no function {name}"));
            }
        }
    }
    Ok(out)
}

/// The provenance `header` records, a line each, `# `-prefixed: the
/// notice, the source, each build's toolchain, flags and inputs, and what
/// made the pack.
fn provenance(out: &mut String, header: &binbun_sigpack::pack::Header) {
    if let Some(notice) = &header.notice {
        let _ = writeln!(out, "# notice: {notice}");
    }
    if let Some(source) = &header.source {
        let _ = writeln!(
            out,
            "# source: {}{} sha256:{}",
            source.package,
            source
                .url
                .as_ref()
                .map_or_else(String::new, |url| format!(" <{url}>")),
            source.sha256
        );
    }
    for build in &header.builds {
        let inputs: Vec<String> = build
            .inputs
            .iter()
            .zip(&build.sha256)
            .map(|(input, sha256)| format!("{input} sha256:{sha256}"))
            .collect();
        let _ = writeln!(
            out,
            "# build {}: {}; flags {}; {}",
            build.id,
            build.toolchain.as_deref().unwrap_or("toolchain not given"),
            build.flags.as_deref().unwrap_or("not given"),
            inputs.join(", ")
        );
    }
    let _ = writeln!(out, "# made by {}", header.made_by);
}

/// `sig compare PACK PACK`: how many functions of one name have the same
/// identity, or the same masked bytes, in the two packs' first builds
/// (Rust names compared without crate hashes, [`key`]).
fn compare(args: &[String]) -> Result<String, String> {
    let [a, b] = args else {
        return Err(USAGE.to_owned());
    };
    let (a, b) = (pack(a)?, pack(b)?);
    let first = |pack: &Pack| {
        let id = pack
            .header
            .builds
            .first()
            .map(|b| b.id.clone())
            .unwrap_or_default();
        pack.functions
            .iter()
            .filter_map(|e| Some((key(&e.name), pack.build(e, &id)?.clone())))
            .collect::<BTreeMap<_, _>>()
    };
    let (x, y) = (first(&a), first(&b));
    let mut shared = 0;
    let mut identity = 0;
    let mut bytes = 0;
    let mut either = 0;
    let mut differing = Vec::new();
    for (name, build) in &x {
        let Some(other) = y.get(name) else { continue };
        shared += 1;
        let same_identity = build.identity == other.identity;
        if !same_identity {
            differing.push(name.as_str());
        }
        let same_bytes = build.bytes == other.bytes;
        identity += usize::from(same_identity);
        bytes += usize::from(same_bytes);
        either += usize::from(same_identity || same_bytes);
    }
    let percent = |n: usize| percent(n, shared);
    let mut out = format!(
        "{shared} functions in both: identity {identity} ({:.1}%), masked bytes {bytes} ({:.1}%), either {either} ({:.1}%)\n",
        percent(identity),
        percent(bytes),
        percent(either)
    );
    if !differing.is_empty() {
        let _ = writeln!(
            out,
            "# identity differs: {}{}",
            differing
                .iter()
                .take(30)
                .copied()
                .collect::<Vec<_>>()
                .join(", "),
            if differing.len() > 30 { ", ..." } else { "" }
        );
    }
    Ok(out)
}

/// `sig match FILE --pack PACK... [--behaviour] [--sweep] [--answers
/// UNSTRIPPED]`: each function's name from the packs (with its aliases),
/// how it was found, or its candidates; with `--answers`, the names
/// scored against the symbols of the same program unstripped.
fn matching(args: &[String]) -> Result<String, String> {
    let mut packs = Vec::new();
    let mut options = MatchOptions::default();
    let mut answers = None;
    let mut paths = Vec::new();
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--pack" => packs.push(pack(&value(arg, &mut args)?)?),
            "--behaviour" | "--behavior" => options.behaviour = true,
            "--sweep" => options.sweep = true,
            "--answers" => answers = Some(value(arg, &mut args)?),
            _ if arg.starts_with('-') => return Err(USAGE.to_owned()),
            _ => paths.push(arg),
        }
    }
    let [path] = paths[..] else {
        return Err(USAGE.to_owned());
    };
    if packs.is_empty() {
        return Err(format!("sig match needs --pack\n{USAGE}"));
    }
    let data = read(path)?;
    let image = load(path, &data)?;
    let db = database(path, &image, Seeds::ALL)?;
    let started = std::time::Instant::now();
    let mut matches = signatures::match_image(&db, &packs, options)?;
    let elapsed = started.elapsed();
    matches.sort_by_key(|m| m.entry);
    let entry = |key: (usize, usize)| packs.get(key.0).and_then(|p| p.functions.get(key.1));
    let entry_name = |key: (usize, usize)| entry(key).map_or_else(String::new, |e| e.name.clone());
    // The name and, after it, the aliases.
    let full_name = |key: (usize, usize)| {
        entry(key).map_or_else(String::new, |e| {
            if e.aliases.is_empty() {
                e.name.clone()
            } else {
                format!("{} (also {})", e.name, e.aliases.join(", "))
            }
        })
    };
    let mut out = String::new();
    for m in &matches {
        let found = if m.found { " [found]" } else { "" };
        match &m.named {
            Some((key, How::Exact)) => {
                let _ = writeln!(out, "{:#x} {} exact{found}", m.entry, full_name(*key));
            }
            Some((key, How::Behaviour { states, rivals })) => {
                let _ = writeln!(
                    out,
                    "{:#x} {} behaviour: {states} states agreed, {} ruled out{found}",
                    m.entry,
                    full_name(*key),
                    rivals.len()
                );
            }
            None if !m.candidates.is_empty() => {
                let names: BTreeSet<String> = m.candidates.iter().map(|&k| entry_name(k)).collect();
                let _ = writeln!(
                    out,
                    "{:#x} - candidates: {}{}",
                    m.entry,
                    names.into_iter().collect::<Vec<_>>().join(", "),
                    m.why
                        .as_ref()
                        .map_or_else(String::new, |why| format!(" ({why})"))
                );
            }
            None => {}
        }
    }
    let named = matches.iter().filter(|m| m.named.is_some()).count();
    let found = matches.iter().filter(|m| m.found).count();
    let exact = matches
        .iter()
        .filter(|m| matches!(m.named, Some((_, How::Exact))))
        .count();
    let listed = matches
        .iter()
        .filter(|m| m.named.is_none() && !m.candidates.is_empty())
        .count();
    let _ = writeln!(
        out,
        "# {} functions: {named} named ({exact} exact, {} by behaviour; {found} found by the packs), {listed} listed with candidates; {:.1} s",
        matches.len(),
        named - exact,
        elapsed.as_secs_f64()
    );
    if let Some(answers) = answers {
        let answers_data = read(&answers)?;
        let tally = Tally::new(&truth(&answers, &answers_data, &data)?, &matches, &packs);
        out.push_str(&tally.text(&answers));
    }
    Ok(out)
}

/// Names given scored against the answers (the function symbols of the
/// same program unstripped, or the PDB of the program matched;
/// [`truth`]): precision over names given (an alias is right, another
/// member of its group is not), recall over the functions whose name a
/// pack has (matchable), of those recovered and of all in the answers;
/// and how often the index proposed the right entry for a matchable
/// function of another identity. Rust names compare as paths without
/// crate hashes, and an entry's names also as a PDB names procedures
/// ([`key`]).
#[derive(Debug, Default)]
struct Tally {
    /// Recovered functions whose answer a pack names.
    matchable: usize,
    /// Names given, and of them right.
    named: usize,
    correct: usize,
    /// Names given by an exact identity, and of them right.
    exact: usize,
    exact_right: usize,
    /// Names given to functions the packs found, and of them right.
    found: usize,
    found_right: usize,
    /// Matchable functions of another identity than every right entry's,
    /// and of them those the index proposed the right entry for.
    other_identity: usize,
    proposed_right: usize,
    /// Functions left unnamed with the right entry among the candidates.
    listed_right: usize,
    /// The answers' functions a pack names, recovered or not.
    all: usize,
    /// Each wrong name: where, what was given, how, what it is.
    wrong: Vec<String>,
}

impl Tally {
    /// `matches` (of `packs`) scored against `truth`, the answers' function
    /// names by address as [`truth`] has them.
    fn new(truth: &BTreeMap<u64, BTreeSet<String>>, matches: &[Match], packs: &[Pack]) -> Self {
        let entry = |key: (usize, usize)| packs.get(key.0).and_then(|p| p.functions.get(key.1));
        // Each entry's names and aliases as compared (as they are, and as
        // [`key`] has them), by pack and entry.
        let entry_names: Vec<Vec<Vec<String>>> = packs
            .iter()
            .map(|pack| {
                pack.functions
                    .iter()
                    .map(|e: &Entry| {
                        core::iter::once(&e.name)
                            .chain(&e.aliases)
                            .flat_map(|n| [n.clone(), key(n)])
                            .collect()
                    })
                    .collect()
            })
            .collect();
        let names_of = |(p, e): (usize, usize)| {
            entry_names
                .get(p)
                .and_then(|pack| pack.get(e))
                .map_or(&[][..], Vec::as_slice)
        };
        let known: BTreeSet<&String> = entry_names.iter().flatten().flatten().collect();
        // A name is right when it or an alias is the symbol's: never
        // another member of its group.
        let right = |key: (usize, usize), names: &BTreeSet<String>| {
            names_of(key).iter().any(|n| names.contains(n))
        };
        let mut tally = Self {
            all: truth
                .values()
                .filter(|names| names.iter().any(|n| known.contains(n)))
                .count(),
            ..Self::default()
        };
        let none = BTreeSet::new();
        for m in matches {
            let answer = truth.get(&m.entry).unwrap_or(&none);
            let is_matchable = answer.iter().any(|n| known.contains(n));
            tally.matchable += usize::from(is_matchable);
            if is_matchable {
                // The index: the right entry among those proposed, for
                // matchable functions whose identity no right entry has.
                let identical = packs.iter().enumerate().any(|(p, pack)| {
                    pack.functions.iter().enumerate().any(|(e, entry)| {
                        right((p, e), answer)
                            && entry
                                .builds
                                .keys()
                                .filter_map(|id| pack.build(entry, id))
                                .any(|b| b.identity == m.identity)
                    })
                });
                if !identical {
                    tally.other_identity += 1;
                    tally.proposed_right +=
                        usize::from(m.proposed.iter().any(|&key| right(key, answer)));
                }
            }
            let Some((key, how)) = &m.named else {
                tally.listed_right +=
                    usize::from(is_matchable && m.candidates.iter().any(|&key| right(key, answer)));
                continue;
            };
            let ok = right(*key, answer);
            let exact = matches!(how, How::Exact);
            tally.named += 1;
            tally.correct += usize::from(ok);
            tally.found += usize::from(m.found);
            tally.found_right += usize::from(m.found && ok);
            tally.exact += usize::from(exact);
            tally.exact_right += usize::from(exact && ok);
            if !ok {
                tally.wrong.push(format!(
                    "{:#x} named {} ({}), is {}",
                    m.entry,
                    entry(*key).map_or("?", |e| e.name.as_str()),
                    if exact { "exact" } else { "behaviour" },
                    answer.iter().cloned().collect::<Vec<_>>().join("/")
                ));
            }
        }
        tally
    }

    /// Names given that are wrong.
    fn wrong(&self) -> usize {
        self.named - self.correct
    }

    /// The tally as `sig match --answers` prints it.
    fn text(&self, answers: &str) -> String {
        let Self {
            matchable,
            named,
            correct,
            exact,
            exact_right,
            found,
            found_right,
            other_identity,
            proposed_right,
            listed_right,
            all,
            ..
        } = self;
        let mut out = format!(
            "# answers {answers}: {matchable} matchable functions; named {named}: {correct} match the answer key, {} mismatch it; precision {:.2}%, recall {:.1}% (exact {exact_right}/{exact}, behaviour {}/{}); {listed_right} more listed with a matching candidate\n",
            self.wrong(),
            percent(*correct, *named),
            percent(*correct, *matchable),
            correct - exact_right,
            named - exact,
        );
        let _ = writeln!(
            out,
            "# of the answers' {all} functions a pack names: {correct} named as the answer key does ({:.1}%), {found_right}/{found} of them found by the packs; the index proposed a matching entry for {proposed_right}/{other_identity} matchable functions of another identity ({:.1}%)",
            percent(*correct, *all),
            percent(*proposed_right, *other_identity),
        );
        for line in self.wrong.iter().take(40) {
            let _ = writeln!(out, "# mismatch: {line}");
        }
        out
    }
}

/// A class of evaluation case and the recall targeted for it (matchable
/// functions named right); every case's targets are also a precision of
/// [`PRECISION`], and no wrong name at all with the shipped packs or the
/// same toolchain.
struct Class {
    name: &'static str,
    what: &'static str,
    recall: Option<f64>,
}

/// The classes of `sig eval`'s cases.
const CLASSES: [Class; 6] = [
    Class {
        name: "same",
        what: "the toolchain and flags of a build in the packs",
        recall: Some(95.0),
    },
    Class {
        name: "flags",
        what: "the compiler of a build in the packs, other flags",
        recall: Some(80.0),
    },
    Class {
        name: "compiler",
        what: "another compiler than the packs' builds'",
        recall: Some(60.0),
    },
    Class {
        name: "rust-n",
        what: "Rust built by the toolchain of the std pack (N)",
        recall: Some(95.0),
    },
    Class {
        name: "rust-n1",
        what: "Rust built by the toolchain after the std pack's (N+1), or before",
        recall: Some(65.0),
    },
    Class {
        name: "rust-n2",
        what: "Rust two toolchains from the std pack's (reported, no recall target)",
        recall: None,
    },
];

/// The precision (names given that are right, %) every case is held to.
const PRECISION: f64 = 99.9;

/// One case of `sig eval`: its name, class, packs (`shipped` or files),
/// the stripped program and its answers (unstripped).
struct Case<'c> {
    name: String,
    class: &'c Class,
    packs: String,
    stripped: String,
    answers: String,
}

/// A case scored: its tally, how long matching took, and the targets it
/// missed.
struct Scored<'c> {
    case: Case<'c>,
    tally: Tally,
    seconds: f64,
    missed: Vec<String>,
}

/// `sig eval CASES --packs DIR [--sweep|--no-sweep]`: each case of the
/// file CASES (lines `NAME CLASS PACKS STRIPPED ANSWERS`, `#` comments;
/// paths relative to it; PACKS `shipped`, the packs in DIR as a session
/// reads them, or pack files separated by commas) matched with behaviour
/// checking (and the sweep as a session's default, unless told) and
/// scored against its answers: a table of names, precision, recall and
/// time per case and class against their targets ([`CLASSES`]); an
/// error, the same table, if one is missed.
fn eval(args: &[String]) -> Result<String, String> {
    let mut options = MatchOptions {
        behaviour: true,
        sweep: binbun_session::signatures::Options::default().sweep,
    };
    let mut shipped = None;
    let mut files = Vec::new();
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--packs" => shipped = Some(value(arg, &mut args)?),
            "--sweep" => options.sweep = true,
            "--no-sweep" => options.sweep = false,
            _ if arg.starts_with('-') => return Err(USAGE.to_owned()),
            _ => files.push(arg),
        }
    }
    let [path] = files[..] else {
        return Err(USAGE.to_owned());
    };
    let cases = cases(path)?;
    if cases.is_empty() {
        return Err(format!("{path}: no case"));
    }
    // One set of packs read at a time (cases of one set are best kept
    // together: the shipped packs are large).
    let mut loaded: Option<(String, Vec<Pack>)> = None;
    let mut scored = Vec::new();
    for case in cases {
        if loaded.as_ref().is_none_or(|(set, _)| *set != case.packs) {
            // The set before is dropped first.
            drop(loaded.take());
            let packs = if case.packs == "shipped" {
                let dir = shipped
                    .as_ref()
                    .ok_or_else(|| format!("{path}: case {} needs --packs DIR", case.name))?;
                let (packs, left_out) =
                    binbun_session::signatures::read_folders(&[std::path::PathBuf::from(dir)]);
                if let Some(why) = left_out.first() {
                    return Err(format!("{dir}: {why}"));
                }
                packs
            } else {
                case.packs
                    .split(',')
                    .map(pack)
                    .collect::<Result<Vec<_>, String>>()?
            };
            if packs.is_empty() {
                return Err(format!("{path}: case {}: no pack", case.name));
            }
            loaded = Some((case.packs.clone(), packs));
        }
        let Some((_, packs)) = &loaded else {
            continue;
        };
        let data = read(&case.stripped)?;
        let image = load(&case.stripped, &data)?;
        let db = database(&case.stripped, &image, Seeds::ALL)?;
        let started = std::time::Instant::now();
        let matches = signatures::match_image(&db, packs, options)?;
        let seconds = started.elapsed().as_secs_f64();
        let answers = read(&case.answers)?;
        let tally = Tally::new(&truth(&case.answers, &answers, &data)?, &matches, packs);
        let missed = missed(&case, &tally);
        scored.push(Scored {
            case,
            tally,
            seconds,
            missed,
        });
    }
    let table = eval_table(&scored, options);
    if scored.iter().any(|s| !s.missed.is_empty()) {
        // An error is printed with a line end of its own.
        Err(table.trim_end().to_owned())
    } else {
        Ok(table)
    }
}

/// The cases of the file at `path`, their paths made relative to it.
fn cases(path: &str) -> Result<Vec<Case<'static>>, String> {
    let text = String::from_utf8(read(path)?).map_err(|e| format!("{path}: {e}"))?;
    let base = std::path::Path::new(path)
        .parent()
        .unwrap_or_else(|| std::path::Path::new(""));
    let at = |file: &str| base.join(file).to_string_lossy().into_owned();
    let mut cases = Vec::new();
    for (number, line) in text.lines().enumerate() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let [name, class, packs, stripped, answers] =
            line.split_whitespace().collect::<Vec<_>>()[..]
        else {
            return Err(format!(
                "{path}:{}: not NAME CLASS PACKS STRIPPED ANSWERS",
                number + 1
            ));
        };
        let class = CLASSES.iter().find(|c| c.name == class).ok_or_else(|| {
            let names: Vec<_> = CLASSES.iter().map(|c| c.name).collect();
            format!(
                "{path}:{}: no class {class} (one of {})",
                number + 1,
                names.join(", ")
            )
        })?;
        cases.push(Case {
            name: name.to_owned(),
            class,
            packs: if packs == "shipped" {
                packs.to_owned()
            } else {
                packs.split(',').map(at).collect::<Vec<_>>().join(",")
            },
            stripped: at(stripped),
            answers: at(answers),
        });
    }
    Ok(cases)
}

/// The targets `case` missed, scored as `tally`.
fn missed(case: &Case<'_>, tally: &Tally) -> Vec<String> {
    let mut missed = Vec::new();
    let precision = percent(tally.correct, tally.named);
    if tally.named > 0 && precision < PRECISION {
        missed.push(format!("precision {precision:.2}% < {PRECISION}%"));
    }
    if tally.wrong() > 0 && (case.packs == "shipped" || case.class.name == "same") {
        missed.push(format!("{} mismatched names", tally.wrong()));
    }
    let recall = percent(tally.correct, tally.matchable);
    if let Some(target) = case.class.recall
        && recall < target
    {
        missed.push(format!("recall {recall:.1}% < {target}%"));
    }
    missed
}

/// `sig eval`'s table: a row per case, then per class, then the verdict.
fn eval_table(scored: &[Scored<'_>], options: MatchOptions) -> String {
    let mut out = format!(
        "# sig eval: behaviour checking, sweep {}; precision target {PRECISION}%, no name that mismatches the answer key with the shipped packs or the same toolchain\n",
        if options.sweep { "on" } else { "off" }
    );
    let _ = writeln!(
        out,
        "{:<40} {:<9} {:<9} {:>6} {:>7} {:>8} {:>9} {:>9} {:>7} {:>7} {:>7}  verdict",
        "case",
        "class",
        "packs",
        "named",
        "matches",
        "mismatch",
        "precision",
        "matchable",
        "recall",
        "target",
        "seconds"
    );
    let target = |class: &Class| {
        class
            .recall
            .map_or_else(|| "-".to_owned(), |t| format!("{t}%"))
    };
    for s in scored {
        let t = &s.tally;
        let _ = writeln!(
            out,
            "{:<40} {:<9} {:<9} {:>6} {:>7} {:>8} {:>8.2}% {:>9} {:>6.1}% {:>7} {:>7.1}  {}",
            s.case.name,
            s.case.class.name,
            if s.case.packs == "shipped" {
                "shipped"
            } else {
                "one build"
            },
            t.named,
            t.correct,
            t.wrong(),
            percent(t.correct, t.named),
            t.matchable,
            percent(t.correct, t.matchable),
            target(s.case.class),
            s.seconds,
            if s.missed.is_empty() {
                "met".to_owned()
            } else {
                format!("MISSED: {}", s.missed.join("; "))
            }
        );
    }
    for class in &CLASSES {
        let rows: Vec<&Scored<'_>> = scored
            .iter()
            .filter(|s| core::ptr::eq(s.case.class, class))
            .collect();
        if rows.is_empty() {
            continue;
        }
        let sum = |f: fn(&Tally) -> usize| rows.iter().map(|s| f(&s.tally)).sum::<usize>();
        let (named, correct, matchable) =
            (sum(|t| t.named), sum(|t| t.correct), sum(|t| t.matchable));
        let _ = writeln!(
            out,
            "# {} ({}): {} cases; named {named}, {} mismatched, precision {:.2}%; recall {:.1}% of {matchable} (target {}); {}",
            class.name,
            class.what,
            rows.len(),
            named - correct,
            percent(correct, named),
            percent(correct, matchable),
            target(class),
            if rows.iter().all(|s| s.missed.is_empty()) {
                "met"
            } else {
                "MISSED"
            }
        );
    }
    for s in scored {
        for line in s.tally.wrong.iter().take(20) {
            let _ = writeln!(out, "# mismatch in {}: {line}", s.case.name);
        }
    }
    let missed = scored.iter().filter(|s| !s.missed.is_empty()).count();
    if missed == 0 {
        let _ = writeln!(out, "# every target met ({} cases)", scored.len());
    } else {
        let _ = writeln!(out, "# {missed} of {} cases missed a target", scored.len());
    }
    out
}

/// The function names at each address of the answers `data` (at `path`)
/// as scores compare them: an image's function symbols ([`key`]); or a
/// PDB's for the PE image `image`, the public symbol at an address as it
/// is (a C++ function's decorated name), else the procedure's name
/// ([`key`]: a function the program's object has to itself, `static`).
fn truth(path: &str, data: &[u8], image: &[u8]) -> Result<BTreeMap<u64, BTreeSet<String>>, String> {
    let mut names: BTreeMap<u64, BTreeSet<String>> = BTreeMap::new();
    if binbun_debuginfo::info::pdb::is_pdb(data) {
        let model =
            binbun_debuginfo::info::read(data, image).map_err(|e| format!("{path}: {e}"))?;
        for (&address, public) in &model.publics {
            names.entry(address).or_default().insert(public.clone());
        }
        for (&address, function) in &model.functions {
            if let Some(name) = &function.name {
                let at = names.entry(address).or_default();
                if at.is_empty() {
                    at.insert(key(name));
                }
            }
        }
        return Ok(names);
    }
    let image = load(path, data)?;
    for symbol in &image.symbols {
        if symbol.kind == SymbolKind::Function {
            names
                .entry(symbol.address)
                .or_default()
                .insert(key(&symbol.name));
        }
    }
    Ok(names)
}

/// A name as scores compare it: a Rust mangling as its path without crate
/// hashes; an MSVC decorated name, or a PDB's procedure name, as the
/// qualified name without parameters, class keywords or spaces (as a PDB
/// names a procedure: `std::_Locinfo::_Locinfo_ctor`), template arguments
/// spelled as the demangler spells them (a PDB's `__int64` is its
/// `int64_t`); anything else as itself.
fn key(name: &str) -> String {
    if let Some(path) = rust::path(name) {
        return path;
    }
    let name = if name.starts_with('?') {
        let flags = DemangleFlags::NAME_ONLY | DemangleFlags::NO_CLASS_TYPE;
        msvc_demangler::demangle(name, flags).unwrap_or_else(|_| name.to_owned())
    } else {
        name.to_owned()
    };
    name.replace(' ', "")
        .replace("unsigned__int64", "uint64_t")
        .replace("__int64", "int64_t")
}

/// `part` of `whole` as a percentage (0 for nothing).
fn percent(part: usize, whole: usize) -> f64 {
    let ratio = |n: usize| f64::from(u32::try_from(n).unwrap_or(u32::MAX));
    100.0 * ratio(part) / ratio(whole.max(1))
}
