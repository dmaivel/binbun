//! A session used as a GUI uses it, timed: `session FILE A B C D
//! [--project DIR]` opens FILE, asks for function A's C as soon as the
//! functions are recovered and then B's (during the analysis), C's and
//! D's once the warming is over, renames C and a variable of D, and prints
//! when each stage was reached and how long each answer took. Functions
//! by name or hexadecimal address. The renames are saved only with
//! `--project` (a project directory in place of the binary's own).

use std::env;
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::mpsc::Receiver;
use std::time::{Duration, Instant};

use binbun::cfg::FunctionId;
use binbun_ast::ir::Node;
use binbun_session::{Document, Event, Options, Session, Stage};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("session: {message}");
            ExitCode::FAILURE
        }
    }
}

/// Milliseconds, for the table.
fn ms(duration: Duration) -> String {
    format!("{:.1} ms", duration.as_secs_f64() * 1000.0)
}

/// Waits on `events` for the answer to `request`, reporting the stages
/// reached on the way (since `opened`).
fn answer(
    events: &Receiver<Event>,
    request: u64,
    opened: Instant,
) -> Result<Arc<Document>, String> {
    for event in events {
        match event {
            Event::Document {
                request: answered,
                result,
                ..
            } if answered == request => return result,
            Event::Stage(stage) => println!("{:>12}  stage {stage:?}", ms(opened.elapsed())),
            Event::Failed(message) => return Err(message),
            Event::Document { .. }
            | Event::Progress { .. }
            | Event::Changed(_)
            | Event::Unresolved(_)
            | Event::Symbols(_)
            | Event::Answer { .. }
            | Event::History(_)
            | Event::Conflicts(_)
            | Event::Thread(_)
            | Event::Mentioned(_)
            | Event::Bookmarks
            | Event::Reanalysed { .. } => {}
        }
    }
    Err("the session stopped".to_owned())
}

/// Asks for `function`'s document and waits for it; how long it took.
fn timed(
    session: &Session,
    events: &Receiver<Event>,
    function: FunctionId,
    opened: Instant,
) -> Result<(Arc<Document>, Duration), String> {
    let start = Instant::now();
    let request = session.request(function);
    let document = answer(events, request, opened)?;
    Ok((document, start.elapsed()))
}

fn run() -> Result<(), String> {
    let mut args: Vec<String> = env::args().skip(1).collect();
    let mut options = Options {
        autosave: false,
        ..Options::default()
    };
    if let Some(at) = args.iter().position(|arg| arg == "--project") {
        options.project = Some(args.get(at + 1).ok_or("--project DIR")?.into());
        options.autosave = true;
        args.drain(at..at + 2);
    }
    let [file, a, b, c, d] = &args[..] else {
        return Err("usage: session FILE A B C D [--project DIR]".to_owned());
    };
    let opened = Instant::now();
    let session = Session::open(file, options).map_err(|error| error.to_string())?;
    let events = session.subscribe(None);
    for event in &events {
        match event {
            Event::Stage(stage) => {
                println!("{:>12}  stage {stage:?}", ms(opened.elapsed()));
                if stage >= Stage::Analysed {
                    break;
                }
            }
            Event::Failed(message) => return Err(message),
            Event::Document { .. }
            | Event::Progress { .. }
            | Event::Changed(_)
            | Event::Unresolved(_)
            | Event::Symbols(_)
            | Event::Answer { .. }
            | Event::History(_)
            | Event::Conflicts(_)
            | Event::Thread(_)
            | Event::Mentioned(_)
            | Event::Bookmarks
            | Event::Reanalysed { .. } => {}
        }
    }
    let database = session.database().ok_or("not analysed")?;
    let find = |name: &str| database.find_function(name);
    let (a, b, c, d) = (find(a)?, find(b)?, find(c)?, find(d)?);
    let (_, first) = timed(&session, &events, a, opened)?;
    println!("{:>12}  first C during the analysis", ms(first));
    let (_, second) = timed(&session, &events, b, opened)?;
    println!("{:>12}  second C during the analysis", ms(second));
    for event in &events {
        if let Event::Stage(stage) = event {
            println!("{:>12}  stage {stage:?}", ms(opened.elapsed()));
            if stage == Stage::Warmed {
                break;
            }
        }
    }
    let (third, first) = timed(&session, &events, c, opened)?;
    println!("{:>12}  first C after the analysis", ms(first));
    let (fourth, second) = timed(&session, &events, d, opened)?;
    println!("{:>12}  second C after the analysis", ms(second));
    // Renamed as `N` does: the change, then the documents it names asked
    // for again; the time to the first.
    let start = Instant::now();
    let change = session
        .rename_function(third.entry, Some("renamed_by_user"))
        .map_err(|error| error.to_string())?;
    let (renamed, _) = timed(&session, &events, c, opened)?;
    println!(
        "{:>12}  function renamed -> its document ({} documents changed)",
        ms(start.elapsed()),
        change.documents.len()
    );
    if !renamed.text.contains("renamed_by_user") {
        return Err("the rename did not print".to_owned());
    }
    let var = fourth.spans.iter().find_map(|span| match span.node {
        Some(Node::Var(var)) if span.kind.is_variable() => Some(var),
        _ => None,
    });
    if let Some(var) = var {
        let start = Instant::now();
        session
            .rename_variable(d, var, Some("renamed_local"))
            .map_err(|error| error.to_string())?;
        let (renamed, _) = timed(&session, &events, d, opened)?;
        println!(
            "{:>12}  variable renamed -> its document",
            ms(start.elapsed())
        );
        if !renamed.text.contains("renamed_local") {
            return Err("the rename did not print".to_owned());
        }
    }
    session.close();
    Ok(())
}
