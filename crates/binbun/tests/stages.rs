//! A function through every stage ([`binbun::stages`]) on the checked-in
//! fixtures: the last stages are what decompilation prints (recording
//! changes nothing), each compared stage accounts for every line of the
//! one before, the reasons the passes record reach their lines, the
//! reading view's folded checks show, and a cursor follows a line
//! through the levels.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers fail loudly"
)]

use std::sync::atomic::AtomicBool;

use binbun::Database;
use binbun::analysis::Seeds;
use binbun::decompile::{Options as DecompileOptions, View};
use binbun::stages::{Change, Key, Level, Options, Part, Stages, stages, stages_cancellable};
use binbun_loader::Image;

fn fixture(name: &str) -> Vec<u8> {
    let path = format!("{}/../../tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

fn options(view: View) -> Options {
    Options {
        view,
        ..Options::default()
    }
}

/// Every stage's accounting: a compared stage's lines are the old ones
/// paired (each at most once), plus those added, and every old line is
/// paired or removed.
fn accounted(made: &Stages) {
    for pair in made.stages.windows(2) {
        let (before, stage) = (&pair[0], &pair[1]);
        if !stage.compared {
            assert!(stage.removed.is_empty() && stage.lines.iter().all(|l| l.change.is_none()));
            continue;
        }
        assert_eq!(before.level, stage.level, "{}", stage.label);
        let mut seen = vec![false; before.lines.len()];
        for line in &stage.lines {
            match line.was {
                Some(was) => {
                    assert!(!std::mem::replace(&mut seen[was], true));
                    let same = before.line_text(was) == &stage.text[line.range.clone()];
                    assert_eq!(line.change.is_none(), same, "{}", stage.label);
                }
                None => assert_eq!(line.change, Some(Change::Added)),
            }
        }
        for gone in &stage.removed {
            let index = before
                .lines
                .iter()
                .position(|l| l.key == gone.key && before.text[l.range.clone()] == gone.text)
                .unwrap();
            assert!(
                !std::mem::replace(&mut seen[index], true),
                "{}",
                stage.label
            );
            assert!(gone.before <= stage.lines.len());
        }
        assert!(
            seen.iter().all(|&s| s),
            "{}: an old line unaccounted",
            stage.label
        );
    }
}

#[test]
fn the_last_stages_are_what_decompilation_prints_in_both_views() {
    for name in [
        "program-x86_64.elf",
        "rodata-x86_64.elf",
        "dozen-aarch64.elf",
    ] {
        let data = fixture(name);
        let image = Image::parse(&data).unwrap();
        let database = Database::new(&image, Seeds::ALL).unwrap();
        let declarations = database.declarations().unwrap();
        for view in [View::Exact, View::Reading] {
            let decompile = DecompileOptions {
                style: Some("kr".to_owned()),
                view,
                ..DecompileOptions::default()
            };
            for (id, function) in database.functions() {
                let output = database.decompile(id, &decompile);
                let Ok(decompiled) = output.result else {
                    assert!(stages(&database, id, &options(view)).is_err());
                    continue;
                };
                let made = stages(&database, id, &options(view)).unwrap();
                assert_eq!(made.entry, function.entry);
                let at = |level| made.stages.iter().rposition(|s| s.level == level).unwrap();
                let names: Vec<&str> = made.stages.iter().map(|s| s.name).collect();
                assert_eq!(names[..2], ["machine", "lifting"]);
                assert_eq!(made.stages[at(Level::C)].text, decompiled.c.unwrap().text);
                assert_eq!(
                    made.stages[at(Level::L2)].text,
                    binbun_ast::text::print(&decompiled.l2, declarations)
                );
                assert_eq!(
                    made.stages[at(Level::L1)].text,
                    binbun_ssa::text::print(&decompiled.l1, declarations)
                );
                // The levels come in order, a pass's stage only where it
                // changed the function.
                assert!(made.stages.windows(2).all(|w| w[0].level <= w[1].level));
                for stage in &made.stages {
                    if let Some(pass) = made.pass(made.find(&stage.label).unwrap()) {
                        assert!(pass.stats.changed > 0, "{}", stage.label);
                    }
                }
                accounted(&made);
            }
        }
    }
}

#[test]
fn loop_rules_give_their_reasons_and_a_cursor_follows_the_loop() {
    let data = fixture("program-x86_64.elf");
    let image = Image::parse(&data).unwrap();
    let database = Database::new(&image, Seeds::ALL).unwrap();
    let id = database.find_function("loop_sum").unwrap();
    let made = stages(&database, id, &options(View::Exact)).unwrap();
    let loops = made.find("loops").unwrap();
    let stage = &made.stages[loops];
    // The rotated `do`-`while` became a `for`: the same statement, changed,
    // its rules on its line.
    let line = stage
        .lines
        .iter()
        .position(|l| stage.text[l.range.clone()].contains(": for ("))
        .unwrap();
    let at = &stage.lines[line];
    assert_eq!(at.change, Some(Change::Changed));
    let reason = at.reason.as_deref().unwrap();
    assert!(reason.contains("loop rule 4"), "{reason}");
    let Some(Key::Stmt {
        part: Part::First, ..
    }) = at.key
    else {
        panic!("{:?}", at.key);
    };
    let before = &made.stages[loops - 1];
    assert!(before.line_text(at.was.unwrap()).contains(": do {"));
    // Through the stages: the same statement in the C, its instructions in
    // L1 and the machine code.
    let c = made.find("c").unwrap();
    let in_c = made.follow(loops, line, c).unwrap();
    assert!(made.stages[c].line_text(in_c).contains("for ("));
    assert_eq!(made.follow(c, in_c, loops), Some(line));
    let machine = made.find("machine").unwrap();
    let instruction = made.follow(loops, line, machine).unwrap();
    let address = made.stages[machine].lines[instruction].addresses[0];
    assert!(at.addresses.contains(&address));
    let lifting = made.find("lifting").unwrap();
    let in_l1 = made.follow(machine, instruction, lifting).unwrap();
    assert!(
        made.stages[lifting].lines[in_l1]
            .addresses
            .contains(&address)
    );
}

#[test]
fn the_reading_view_shows_each_check_it_assumed() {
    let mut found = 0;
    for name in ["program-x86_64.elf", "rodata-x86_64.elf"] {
        let data = fixture(name);
        let image = Image::parse(&data).unwrap();
        let database = Database::new(&image, Seeds::ALL).unwrap();
        let decompile = DecompileOptions {
            view: View::Reading,
            ..DecompileOptions::default()
        };
        for (id, _) in database.functions() {
            let Ok(decompiled) = database.decompile(id, &decompile).result else {
                continue;
            };
            // x86: canonical-address checks, and floating-point ones.
            let [assumed, aligned, authenticated, ..] = decompiled.stats.assumed.kinds;
            assert_eq!([aligned, authenticated], [0, 0]);
            let made = stages(&database, id, &options(View::Reading)).unwrap();
            let Some(index) = made.find("assume-dereferenced-canonical") else {
                assert_eq!(assumed, 0);
                continue;
            };
            found += 1;
            let stage = &made.stages[index];
            let folded: Vec<&str> = stage
                .lines
                .iter()
                .filter(|l| l.change.is_some())
                .map(|l| {
                    assert!(matches!(l.key, Some(Key::Terminator(_))));
                    assert!(l.reason.as_deref().unwrap().contains("reading view"));
                    &stage.text[l.range.clone()]
                })
                .collect();
            assert_eq!(folded.len(), assumed);
            // Each site is an instruction the stage's lines stand for.
            for &site in &decompiled.stats.assumed.sites[..assumed] {
                assert!(stage.lines.iter().any(|l| l.addresses.contains(&site)));
            }
            assert!(
                folded
                    .iter()
                    .all(|text| text.trim_start().starts_with("jump "))
            );
            // The exact view has no such stage.
            let exact = stages(&database, id, &options(View::Exact)).unwrap();
            assert_eq!(exact.find("assume-dereferenced-canonical"), None);
        }
    }
    assert!(found > 0, "no fixture function assumes a check");
}

#[test]
fn cancelled_stages_stop() {
    let data = fixture("program-x86_64.elf");
    let image = Image::parse(&data).unwrap();
    let database = Database::new(&image, Seeds::ALL).unwrap();
    let id = database.find_function("main").unwrap();
    let cancel = AtomicBool::new(true);
    assert!(stages_cancellable(&database, id, &Options::default(), &cancel).is_none());
}

#[test]
fn a_line_at_an_address_is_the_closest_below_where_none_names_it() {
    let data = fixture("program-x86_64.elf");
    let image = Image::parse(&data).unwrap();
    let database = Database::new(&image, Seeds::ALL).unwrap();
    let id = database.find_function("checked").unwrap();
    let made = stages(&database, id, &Options::default()).unwrap();
    let machine = &made.stages[made.find("machine").unwrap()];
    let second = machine.lines[1].addresses[0];
    assert_eq!(machine.line_at(second), Some(1));
    // The second instruction's last byte: still the second line.
    let third = machine.lines[2].addresses[0];
    assert_eq!(machine.line_at(third - 1), Some(1));
    assert_eq!(machine.line_at(made.entry.wrapping_sub(1)), None);
}
