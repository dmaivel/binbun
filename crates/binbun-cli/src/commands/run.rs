//! `binbun run`: one function run from an example state, its C printed
//! with each line's values at its end ([`binbun::run`]).

use std::fmt::Write as _;
use std::sync::atomic::AtomicBool;

use binbun::analysis::Seeds;
use binbun::decompile::{Options, View};
use binbun::profile;
use binbun::run::{self, ExampleState, How, Occurrence, Recording, show};
use binbun_ast::ir::StmtId;
use binbun_print::layout::render_spans;
use binbun_print::style::{IntSpelling, Naming, Placement, Style};

use super::{USAGE, database, int_spelling, load, naming, placement, read};

/// The column values start at.
const COLUMN: usize = 56;

/// `run FILE FUNCTION --state STATE [--view exact|reading]
/// [--types fixed|plain] [--declarations scoped|top]
/// [--names numbered|registers] [--depth N]
/// [--steps N] [--profile NAME|PATH]`: the function's C (its integer
/// types as `--types` says, its locals declared where `--declarations`
/// says), each line ending
/// with what its statements did (a loop's iterations; a statement in a
/// loop, a column per iteration), then how the run ended, its calls, and
/// the machine code's run. On a processor's profile (a shipped one's
/// name, or a file), the values the architecture leaves undefined are
/// its rules', and a statement's values that used one are marked with
/// the profile's name.
pub(crate) fn run(args: &[String]) -> Result<String, String> {
    let Arguments {
        positional,
        state,
        options,
        types,
        declarations: placement,
        names,
    } = arguments(args)?;
    let (&[path, wanted], Some(state_path)) = (positional.as_slice(), state) else {
        return Err(USAGE.to_owned());
    };
    let text = std::fs::read_to_string(state_path).map_err(|e| format!("{state_path}: {e}"))?;
    let state = ExampleState::parse(&text).map_err(|e| format!("{state_path}: {e}"))?;
    let data = read(path)?;
    let image = load(path, &data)?;
    let database = database(path, &image, Seeds::ALL)?;
    let id = database.find_function(wanted)?;
    let decompiling = Options {
        style: None,
        view: options.view,
        ..Options::default()
    };
    let decompiled = database
        .decompile(id, &decompiling)
        .result
        .map_err(|e| format!("{wanted}: {e}"))?;
    let declarations = database
        .declarations()
        .ok_or("the image's code is not lifted")?;
    let style = Style::preset("kr")
        .ok_or("no style kr")?
        .with_int_spelling(types)
        .with_declarations(placement)
        .with_naming(names);
    let printed = binbun_print::c::function(
        &decompiled.l2,
        declarations,
        &style,
        database.data(),
        decompiling.view.opaque(),
    )
    .map_err(|e| format!("{wanted}: cannot print: {e}"))?;
    let (c, spans) = render_spans(&printed.document, &style);
    let cancel = AtomicBool::new(false);
    let start = std::time::Instant::now();
    let result = run::run_decompiled(&database, &decompiled, &state, &options, &cancel)?;
    let elapsed = start.elapsed();
    let lines = result.c.by_line(&c, &spans);
    let stopped = result
        .c
        .at
        .and_then(|at| run::statement_lines(&c, &spans).get(&at).copied());
    let mut out = String::new();
    let mark = options
        .profile
        .as_ref()
        .map_or_else(String::new, |profile| format!(" [{}]", profile.id));
    for (number, line) in c.lines().enumerate() {
        out.push_str(line);
        let mut notes: Vec<String> = lines
            .get(&number)
            .into_iter()
            .flatten()
            .filter_map(|id| note(&result.c, *id, &mark))
            .collect();
        if stopped == Some(number) && !matches!(result.c.stop, run::Stop::Returned(_)) {
            notes.push(format!("<- {}", result.c.stop));
        }
        if !notes.is_empty() {
            let pad = COLUMN.saturating_sub(line.chars().count()).max(2);
            let _ = write!(out, "{:pad$}// {}", "", notes.join("; "));
        }
        out.push('\n');
    }
    let _ = writeln!(
        out,
        "\n/* run {:?} ({:?} view, {}): {}; {} statements in {:.3} ms */",
        state.name,
        options.view,
        profile::label(options.profile.as_deref()),
        result.c.stop,
        result.c.statements.values().map(|t| t.count).sum::<u64>(),
        elapsed.as_secs_f64() * 1e3
    );
    calls(&mut out, &result.c, 0);
    if let Some(machine) = &result.machine {
        let _ = writeln!(
            out,
            "/* machine code: {} instructions, {} at {:#x}; agrees with the C: {} */",
            machine.steps,
            machine.stop,
            machine.at,
            result
                .agree
                .map_or_else(|| "not compared".to_owned(), |agree| agree.to_string())
        );
    }
    Ok(out)
}

/// `run`'s arguments.
struct Arguments<'a> {
    /// The positional ones.
    positional: Vec<&'a str>,
    /// `--state`'s.
    state: Option<&'a str>,
    /// The run's options.
    options: run::Options,
    /// How the C spells integer types (`--types`).
    types: IntSpelling,
    /// Where the C declares locals (`--declarations`).
    declarations: Placement,
    /// How the C names variables with no name of their own (`--names`).
    names: Naming,
}

/// `run`'s arguments of `args`.
fn arguments(args: &[String]) -> Result<Arguments<'_>, String> {
    let mut positional = Vec::new();
    let mut state = None;
    let mut options = run::Options::default();
    let mut types = IntSpelling::Fixed;
    let mut declarations = Placement::Scoped;
    let mut names = Naming::Numbered;
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        let mut value = || args.next().ok_or_else(|| USAGE.to_owned());
        match arg.as_str() {
            "--state" => state = Some(value()?.as_str()),
            "--types" => types = int_spelling(Some(value()?))?,
            "--declarations" => declarations = placement(Some(value()?))?,
            "--names" => names = naming(Some(value()?))?,
            "--view" => {
                options.view = match value()?.as_str() {
                    "exact" => View::Exact,
                    "reading" => View::Reading,
                    _ => return Err(USAGE.to_owned()),
                };
            }
            "--depth" => options.depth = value()?.parse().map_err(|_| USAGE.to_owned())?,
            "--steps" => options.steps = value()?.parse().map_err(|_| USAGE.to_owned())?,
            "--profile" => options.profile = Some(profile::resolve(value()?)?),
            _ if arg.starts_with("--") => return Err(USAGE.to_owned()),
            _ => positional.push(arg.as_str()),
        }
    }
    Ok(Arguments {
        positional,
        state,
        options,
        types,
        declarations,
        names,
    })
}

/// What statement `id` did, as a line's end shows it; an occurrence that
/// used a site's value the processor profile gave ends with `mark`.
fn note(recording: &Recording, id: StmtId, mark: &str) -> Option<String> {
    let trace = recording.statements.get(&id)?;
    if let Some(&total) = recording.iterations.get(&id) {
        return Some(format!("loop: {total} iterations"));
    }
    let shown: Vec<String> = trace
        .shown
        .iter()
        .filter_map(|o| occurrence(o).map(|text| if o.profile { text + mark } else { text }))
        .collect();
    if shown.is_empty() {
        return None;
    }
    let mut text = if trace.shown.iter().any(|o| o.iteration.is_some()) {
        trace
            .shown
            .iter()
            .zip(&shown)
            .map(|(o, s)| format!("[{}] {s}", o.iteration.unwrap_or(0)))
            .collect::<Vec<_>>()
            .join(" | ")
    } else {
        shown.join(" | ")
    };
    if trace.count > trace.shown.len() as u64 {
        let _ = write!(text, " ... ({} in all)", trace.count);
    }
    Some(text)
}

/// One occurrence as shown: its values, or the way it decided.
fn occurrence(occurrence: &Occurrence) -> Option<String> {
    match (occurrence.values.as_slice(), occurrence.decided) {
        ([], Some(0)) => Some("then".to_owned()),
        ([], Some(1)) => Some("else".to_owned()),
        ([], Some(arm)) => Some(format!("arm {arm}")),
        ([], None) => None,
        (values, _) => Some(values.iter().map(show).collect::<Vec<_>>().join(", ")),
    }
}

/// The calls of `recording` (and of those stepped into, indented).
fn calls(out: &mut String, recording: &Recording, depth: usize) {
    for call in &recording.calls {
        let arguments: Vec<String> = call.arguments.iter().map(show).collect();
        let how = match &call.how {
            How::Stepped(inner) => format!("stepped into: {}", inner.stop),
            How::Stubbed => "stubbed".to_owned(),
            How::Stopped => "needs a stub".to_owned(),
        };
        let _ = writeln!(
            out,
            "/* {:indent$}call {}({}) = {}: {how} */",
            "",
            call.callee,
            arguments.join(", "),
            call.result.as_ref().map_or_else(|| "-".to_owned(), show),
            indent = depth * 2
        );
        if let How::Stepped(inner) = &call.how {
            calls(out, inner, depth + 1);
        }
    }
}
