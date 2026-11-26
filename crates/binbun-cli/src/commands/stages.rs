//! `binbun stages`: one function through every stage of decompilation
//! ([`binbun::stages`]): the list of stages with their counts, one
//! stage's text, or its difference from the stage before.

use std::fmt::Write as _;

use binbun::analysis::Seeds;
use binbun::decompile::{Options as Decompiling, View};
use binbun::profile;
use binbun::stages::{Change, Level, Options, Stage, Stages, stages};

use super::{USAGE, database, int_spelling, load, naming, placement, read, spacing};

/// `stages FILE FUNCTION [--view exact|reading] [--stage NAME] [--diff]
/// [--types fixed|plain] [--declarations scoped|top]
/// [--names numbered|registers] [--spacing paragraphs|compact]
/// [--profile NAME|PATH]`:
/// without `--stage`, each stage (its label, level, lines, and lines
/// added, changed and removed against the stage before) and each pass's
/// counts with its refusals; with it, that stage's text (a label, or a
/// name for its first stage); with `--diff` too, its lines marked `+`
/// (added), `~` (changed, after its old form marked `<`) or `-`
/// (removed, where they were), each pass's reason below its line after
/// `!`. With `--profile NAME|PATH`, then each site of the function's
/// undefined values (its instruction and site) with that processor's
/// rule there; the stages do not change with a processor.
/// `--declarations` says where the C stage declares locals, `--names` how
/// it names variables with no name of their own, `--spacing` whether
/// empty lines part its blocks' statements.
pub fn stages_command(args: &[String]) -> Result<String, String> {
    let mut positional = Vec::new();
    let mut view = View::Exact;
    let mut types = Options::default().types;
    let mut declarations = Options::default().declarations;
    let mut names = Options::default().names;
    let mut parted = Options::default().spacing;
    let mut wanted = None;
    let mut diff = false;
    let mut processor = None;
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--view" => {
                view = match args.next().map(String::as_str) {
                    Some("exact") => View::Exact,
                    Some("reading") => View::Reading,
                    _ => return Err(USAGE.to_owned()),
                };
            }
            "--types" => types = int_spelling(args.next())?,
            "--declarations" => declarations = placement(args.next())?,
            "--names" => names = naming(args.next())?,
            "--spacing" => parted = spacing(args.next())?,
            "--stage" => wanted = Some(args.next().ok_or_else(|| USAGE.to_owned())?),
            "--diff" => diff = true,
            "--profile" => {
                let name = args.next().ok_or_else(|| USAGE.to_owned())?;
                processor = Some(profile::resolve(name)?);
            }
            _ if arg.starts_with("--") => return Err(USAGE.to_owned()),
            _ => positional.push(arg.as_str()),
        }
    }
    let [path, function] = positional[..] else {
        return Err(USAGE.to_owned());
    };
    if diff && wanted.is_none() {
        return Err(USAGE.to_owned());
    }
    let data = read(path)?;
    let image = load(path, &data)?;
    let database = database(path, &image, Seeds::ALL)?;
    let id = database.find_function(function)?;
    let options = Options {
        view,
        types,
        declarations,
        names,
        spacing: parted,
        ..Options::default()
    };
    let made = stages(&database, id, &options)?;
    let mut out = match wanted {
        None => list(&made),
        Some(wanted) => {
            let index = made.find(wanted).ok_or_else(|| {
                let labels: Vec<&str> = made.stages.iter().map(|s| s.label.as_str()).collect();
                format!("no stage {wanted}; stages: {}", labels.join(", "))
            })?;
            let stage = made.stages.get(index).ok_or_else(|| USAGE.to_owned())?;
            if diff {
                let before = index.checked_sub(1).and_then(|i| made.stages.get(i));
                marked(stage, before)
            } else {
                stage.text.clone()
            }
        }
    };
    if let Some(processor) = processor {
        profile::fits(&processor, &image)?;
        let decompiled = database
            .decompile(
                id,
                &Decompiling {
                    view,
                    ..Decompiling::default()
                },
            )
            .result?;
        let sites = database.declarations().map(|d| d.sites).unwrap_or_default();
        let _ = writeln!(out, "\nsites on {}:", processor.label());
        for (address, site) in profile::sites(&decompiled.l1) {
            let name = sites.get(usize::from(site.0)).map_or("?", |info| info.name);
            let rule = processor.choice(site).map_or("unknown", |c| c.text());
            let _ = writeln!(out, "  {address:#x}  {name}: {rule}");
        }
    }
    Ok(out)
}

fn level_name(level: Level) -> &'static str {
    match level {
        Level::Machine => "machine",
        Level::L1 => "L1",
        Level::L2 => "L2",
        Level::C => "C",
    }
}

/// The stages and the passes' counts.
fn list(made: &Stages) -> String {
    let mut out = String::new();
    let width = made
        .stages
        .iter()
        .map(|stage| stage.label.len())
        .max()
        .unwrap_or(0);
    for (index, stage) in made.stages.iter().enumerate() {
        let _ = write!(
            out,
            "{index:>3}  {:<width$}  {:<7}  {:>6} lines",
            stage.label,
            level_name(stage.level),
            stage.lines.len(),
        );
        if stage.compared {
            let (added, changed, removed) = stage.counts();
            let _ = write!(out, "  +{added} ~{changed} -{removed}");
        }
        out.push('\n');
    }
    out.push_str("\npasses (runs, changed, refused):\n");
    for pass in &made.passes {
        let _ = writeln!(
            out,
            "  {:<2}  {:<30} {:>3} {:>3} {:>3}",
            level_name(pass.level),
            pass.name,
            pass.stats.runs,
            pass.stats.changed,
            pass.stats.refused,
        );
        for refusal in &pass.refusals {
            let _ = writeln!(out, "        refused: {refusal}");
        }
    }
    out
}

/// `stage`'s lines marked against the stage `before` it.
fn marked(stage: &Stage, before: Option<&Stage>) -> String {
    let mut out = String::new();
    let mut gone: Vec<_> = stage.removed.iter().collect();
    gone.sort_by_key(|gone| gone.before);
    let mut removed = gone.into_iter().peekable();
    for (index, line) in stage.lines.iter().enumerate() {
        while let Some(gone) = removed.next_if(|gone| gone.before <= index) {
            let _ = writeln!(out, "- {}", gone.text);
        }
        let mark = match line.change {
            Some(Change::Added) => '+',
            Some(Change::Changed) => {
                if let (Some(before), Some(was)) = (before, line.was) {
                    let _ = writeln!(out, "< {}", before.line_text(was));
                }
                '~'
            }
            None => ' ',
        };
        let _ = writeln!(out, "{mark} {}", stage.line_text(index));
        if let Some(reason) = &line.reason {
            let _ = writeln!(out, "! {reason}");
        }
    }
    for gone in removed {
        let _ = writeln!(out, "- {}", gone.text);
    }
    out
}
