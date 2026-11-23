//! The queries beside a function's C ([`binbun::queries`]) on the
//! checked-in fixtures: verification in both views and a forced
//! difference's counterexample, which reproduces when run again; the
//! evidence of a parameter typed by a callee's prototype; an origin chain
//! that folds a spill, and one that reaches the callers.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers fail loudly"
)]

use std::sync::atomic::AtomicBool;

use binbun::Database;
use binbun::analysis::Seeds;
use binbun::cfg::FunctionId;
use binbun::decompile::View;
use binbun::memory::ImageOracle;
use binbun::queries::evidence::{Source, Subject, explain};
use binbun::queries::origin::{Kind, Query, Start, Step, Trivial, origins, origins_lowered};
use binbun::queries::verify::{
    self, Checks, Difference, Options, Verdict, check, replay, verify_all,
};
use binbun::queries::{each, lower, values_of};
use binbun::target::setup;
use binbun_ast::ir::{Expr, Origin, Place, Stmt, StmtId, VarId, VarKind};
use binbun_loader::Image;
use binbun_semantics::bits::Bits;
use binbun_semantics::ir::Binary;
use binbun_ssa::ir::Definition;

fn fixture(name: &str) -> Vec<u8> {
    let path = format!("{}/../../tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

/// The function at symbol `name`.
fn function(database: &Database<'_>, name: &str) -> FunctionId {
    database.find_function(name).unwrap()
}

#[test]
fn every_fixture_function_verifies_in_both_views() {
    for name in [
        "program-x86_64.elf",
        "rodata-x86_64.elf",
        "variadic-gcc-x86_64.elf",
    ] {
        let data = fixture(name);
        let image = Image::parse(&data).unwrap();
        let database = Database::new(&image, Seeds::ALL).unwrap();
        for view in [View::Exact, View::Reading] {
            let options = Options {
                view,
                ..Options::default()
            };
            let mut agreed = 0;
            verify_all(&database, &options, 2, |verification| {
                match verification.verdict {
                    Verdict::Agreed(agreement) => {
                        // Every random state, and the shaped ones where a
                        // parameter has a shape.
                        assert!(
                            [verify::STATES, verify::STATES + verify::SHAPED]
                                .contains(&agreement.states),
                            "{name}: {} states",
                            agreement.states
                        );
                        agreed += 1;
                    }
                    Verdict::Differs(difference) => {
                        panic!("{name} {:#x}: {difference:?}", verification.entry)
                    }
                    Verdict::NotCheckable(_) => {}
                }
            });
            assert!(agreed >= 8, "{name}: {agreed} agreed");
        }
    }
}

#[test]
fn the_same_seed_gives_the_same_verdict() {
    let data = fixture("program-x86_64.elf");
    let image = Image::parse(&data).unwrap();
    let database = Database::new(&image, Seeds::ALL).unwrap();
    let id = function(&database, "loop_sum");
    let options = Options {
        seed: Some(7),
        ..Options::default()
    };
    let first = verify::verify(&database, id, &options);
    let second = verify::verify(&database, id, &options);
    assert_eq!(first.verdict, second.verdict);
    assert!(matches!(first.verdict, Verdict::Agreed(_)));
}

#[test]
fn a_cancellable_verification_gives_the_same_verdict_and_stops_when_cancelled() {
    let data = fixture("program-x86_64.elf");
    let image = Image::parse(&data).unwrap();
    let database = Database::new(&image, Seeds::ALL).unwrap();
    let never = AtomicBool::new(false);
    let cancelled = AtomicBool::new(true);
    for name in ["loop_sum", "classify"] {
        let id = function(&database, name);
        for view in [View::Exact, View::Reading] {
            let options = Options {
                view,
                seed: Some(3),
                ..Options::default()
            };
            let plain = verify::verify(&database, id, &options);
            let cancellable = verify::verify_cancellable(&database, id, &options, &never).unwrap();
            assert_eq!(plain.verdict, cancellable.verdict, "{name} {view:?}");
            assert!(matches!(plain.verdict, Verdict::Agreed(_)), "{name}");
            assert_eq!(
                verify::verify_cancellable(&database, id, &options, &cancelled),
                None
            );
        }
    }
}

#[test]
fn a_forced_difference_is_a_counterexample_that_reproduces() {
    let data = fixture("program-x86_64.elf");
    let image = Image::parse(&data).unwrap();
    let database = Database::new(&image, Seeds::ALL).unwrap();
    let id = function(&database, "classify");
    let (lowered, _) = lower(&database, id, View::Exact, &[]).unwrap();
    let setup = setup(&image, lowered.entry).unwrap();
    let oracle = ImageOracle::new(&image);
    let checks = Checks {
        setup: &setup,
        oracle: &oracle,
        exceptions: database.exceptions(),
        states: 16,
        shaped: verify::SHAPED,
        seed: 1,
    };
    let l1 = &lowered.prepared.l1;
    assert!(matches!(
        check(l1, &lowered.l2, &lowered.mapping, &checks),
        Verdict::Agreed(_)
    ));
    // Every returned value plus one.
    let mut broken = lowered.l2.clone();
    let width = broken
        .returns
        .and_then(|ty| broken.types.value_width(ty))
        .unwrap();
    let mut returns = Vec::new();
    for index in 0..broken.stmts.len() {
        if let Stmt::Return(Some(value)) = broken.stmts[index] {
            let one = broken.add_expr(Expr::Const(Bits::from_u64(width, 1)));
            let sum = broken.add_expr(Expr::Binary(Binary::Add, value, one));
            broken.stmts[index] = Stmt::Return(Some(sum));
            returns.push(index);
        }
    }
    let Verdict::Differs(Difference::Run(counterexample)) =
        check(l1, &broken, &lowered.mapping, &checks)
    else {
        panic!("no counterexample");
    };
    // The runs part at a return: every assignment before agrees.
    let divergence = counterexample.divergence.as_ref().unwrap();
    assert_eq!(divergence.assignment, None);
    let stop = counterexample.statement().unwrap();
    assert!(returns.contains(&(stop.0 as usize)), "{divergence:?}");
    // The state alone reproduces it, and the function as decompiled
    // agrees on it.
    let again = replay(
        l1,
        &broken,
        &lowered.mapping,
        &setup,
        &oracle,
        &counterexample.state,
    );
    assert_eq!(again.differences.len(), 1);
    assert_eq!(again.differences[0].message, counterexample.message);
    let original = replay(
        l1,
        &lowered.l2,
        &lowered.mapping,
        &setup,
        &oracle,
        &counterexample.state,
    );
    assert!(original.passed());
}

#[test]
fn a_forced_wrong_assignment_is_located_at_its_statement() {
    let data = fixture("program-x86_64.elf");
    let image = Image::parse(&data).unwrap();
    let database = Database::new(&image, Seeds::ALL).unwrap();
    let mut located = 0;
    for name in ["main", "loop_sum", "checked"] {
        let id = function(&database, name);
        let (lowered, _) = lower(&database, id, View::Exact, &[]).unwrap();
        let setup = setup(&image, lowered.entry).unwrap();
        let oracle = ImageOracle::new(&image);
        let checks = Checks {
            setup: &setup,
            oracle: &oracle,
            exceptions: database.exceptions(),
            states: 16,
            shaped: verify::SHAPED,
            seed: 3,
        };
        // Each assignment of the body to a variable standing for an L1
        // value, plus one: where the runs then differ, they part there.
        let l2 = &lowered.l2;
        let mut body: Vec<StmtId> = Vec::new();
        let mut blocks = vec![&l2.body];
        while let Some(block) = blocks.pop() {
            for &id in block {
                body.push(id);
                blocks.extend(l2.stmt(id).unwrap().blocks());
            }
        }
        for id in body {
            let Stmt::Assign {
                place: place @ Place::Var(var),
                value,
            } = *l2.stmt(id).unwrap()
            else {
                continue;
            };
            let stands = l2
                .provenance
                .stmt(id)
                .iter()
                .any(|origin| matches!(origin, Origin::Value(_)));
            if !stands {
                continue;
            }
            let mut broken = l2.clone();
            let width = broken
                .types
                .value_width(broken.var(var).unwrap().ty)
                .unwrap();
            let one = broken.add_expr(Expr::Const(Bits::from_u64(width, 1)));
            let sum = broken.add_expr(Expr::Binary(Binary::Add, value, one));
            broken.stmts[id.0 as usize] = Stmt::Assign { place, value: sum };
            let verdict = check(&lowered.prepared.l1, &broken, &lowered.mapping, &checks);
            if let Verdict::Differs(Difference::Run(counterexample)) = verdict {
                let (at, value, ..) = counterexample.divergence.unwrap().assignment.unwrap();
                assert_eq!(at, id, "{name}");
                // The addresses name the instruction of the L1 value.
                let l1 = &lowered.prepared.l1;
                let Definition::Result { inst, .. } = l1.value(value).unwrap().definition else {
                    panic!("{value:?}");
                };
                assert!(
                    counterexample
                        .addresses
                        .contains(&l1.inst(inst).unwrap().address)
                );
                located += 1;
            }
        }
    }
    // Most of these assignments are read only after a call, where the
    // differential stops; loop_sum's counter is passed to one.
    assert!(located >= 1, "{located}");
}

#[test]
fn a_parameter_typed_by_a_callees_prototype_says_which() {
    let data = fixture("program-x86_64.elf");
    let image = Image::parse(&data).unwrap();
    let database = Database::new(&image, Seeds::ALL).unwrap();
    let id = function(&database, "fail");
    let explanation = explain(&database, id, View::Exact).unwrap();
    let parameter = explanation
        .items
        .iter()
        .find(|item| item.subject == Subject::Parameter(0))
        .unwrap();
    assert_eq!(parameter.ty, "char *");
    let Source::Callee(callee) = &parameter.source else {
        panic!("{parameter:?}");
    };
    assert_eq!(callee.name.as_deref(), Some("puts"));
    assert_eq!(callee.parameter, Some(0));
    assert_eq!(callee.calls.len(), 1);
    // The deciding clue links the call.
    let clue = &parameter.clues[0];
    assert_eq!(clue.strength, 6);
    assert!(clue.addresses.contains(&callee.calls[0]));
}

#[test]
fn every_printed_variable_is_explained_once() {
    let data = fixture("rodata-x86_64.elf");
    let image = Image::parse(&data).unwrap();
    let database = Database::new(&image, Seeds::ALL).unwrap();
    let id = function(&database, "main");
    let explanation = explain(&database, id, View::Exact).unwrap();
    let (lowered, _) = lower(&database, id, View::Exact, &[]).unwrap();
    let vars: Vec<VarId> = explanation
        .items
        .iter()
        .filter_map(|item| item.var)
        .collect();
    let mut unique = vars.clone();
    unique.sort_unstable();
    unique.dedup();
    assert_eq!(unique.len(), vars.len());
    for &parameter in &lowered.l2.parameters {
        assert!(vars.contains(&parameter));
    }
    // A function-pointer local's declarator is whole.
    assert!(
        explanation
            .items
            .iter()
            .any(|item| item.ty.starts_with("int64_t (*)(")),
        "{explanation:?}"
    );
    assert_eq!(explanation.items.last().unwrap().subject, Subject::Return);
}

#[test]
fn an_origin_chain_folds_a_spill() {
    let data = fixture("variadic-clang-x86_64.elf");
    let image = Image::parse(&data).unwrap();
    let database = Database::new(&image, Seeds::ALL).unwrap();
    let query = Query::default();
    let mut found = 0;
    each(
        &database,
        View::Exact,
        &[],
        1,
        |_, lowered, _| {
            let Ok(lowered) = lowered else { return 0 };
            let mut found = 0;
            for (index, variable) in lowered.l2.variables.iter().enumerate() {
                if values_of(&lowered.prepared.l1, variable.kind, &variable.origins).is_empty() {
                    continue;
                }
                let var = VarId(u32::try_from(index).unwrap());
                let mut budget = query.steps;
                let origins =
                    origins_lowered(&database, &lowered, Start::Var(var), &query, &mut budget);
                let mut steps: Vec<&Step> = origins.chains.iter().collect();
                while let Some(step) = steps.pop() {
                    steps.extend(&step.inputs);
                    // Each reload folded is a load the stack analysis
                    // forwards to the stored value the chain goes on from.
                    for (position, folded) in step.folded.iter().enumerate() {
                        if folded.kind != Trivial::Reload {
                            continue;
                        }
                        let next = step
                            .folded
                            .get(position + 1)
                            .map_or(step.value, |next| next.value);
                        let l1 = &lowered.prepared.l1;
                        assert_eq!(lowered.prepared.facts.stack.resolve(l1, folded.value), next);
                        assert!(step.addresses.contains(&folded.address.unwrap()));
                        found += 1;
                    }
                }
            }
            found
        },
        |n| found += n,
    );
    assert!(found > 0);
}

#[test]
fn a_parameters_origin_reaches_its_call_sites() {
    let data = fixture("program-x86_64.elf");
    let image = Image::parse(&data).unwrap();
    let database = Database::new(&image, Seeds::ALL).unwrap();
    let id = function(&database, "loop_sum");
    let (lowered, _) = lower(&database, id, View::Exact, &[]).unwrap();
    let parameter = lowered.l2.parameters[0];
    assert_eq!(lowered.l2.var(parameter).unwrap().kind, VarKind::Parameter);
    let found = origins(&database, id, Start::Var(parameter), &Query::default()).unwrap();
    assert_eq!(found.chains.len(), 1);
    let Kind::Parameter { index, sites, .. } = &found.chains[0].kind else {
        panic!("{found:?}");
    };
    assert_eq!(*index, Some(0));
    // main passes argc + 5.
    assert_eq!(sites.len(), 1);
    let argument = sites[0].chain.as_ref().unwrap();
    assert_eq!(argument.kind, Kind::Operation("Add".to_owned()));
    assert!(
        argument
            .inputs
            .iter()
            .any(|input| input.kind == Kind::Constant(5))
    );
    // It is compared with the counter.
    assert!(
        found.uses.iter().any(|used| used.kind == "Sub"),
        "{found:?}"
    );
    // Depth 0: no call sites.
    let local = origins(
        &database,
        id,
        Start::Var(parameter),
        &Query {
            depth: 0,
            ..Query::default()
        },
    )
    .unwrap();
    let Kind::Parameter { sites, .. } = &local.chains[0].kind else {
        panic!("{local:?}");
    };
    assert!(matches!(sites.as_slice(), []));
}

/// A comparison groups its differing states by the way they differ (what
/// differs, the deciding site and its values): `shrd_jo`'s OF is 1 on
/// one processor and 0 on the other, either way round, so two ways; the
/// first state of each is kept, then the next ones, in order, each with
/// the processors' rules at the deciding site.
#[test]
fn a_comparison_groups_its_states_by_the_way_they_differ() {
    use binbun::profile::embedded;
    use binbun::queries::compare::{self, KEPT, Verdict as Compared};

    let data = fixture("undefined-x86_64.elf");
    let image = Image::parse(&data).unwrap();
    let database = Database::new(&image, Seeds::ALL).unwrap();
    let comparison = compare::compare(
        &database,
        function(&database, "shrd_jo"),
        &compare::Options::default(),
    );
    let Compared::Differs(kept) = &comparison.verdict else {
        panic!("{comparison:?}");
    };
    let differing = comparison.states - comparison.same - comparison.skipped;
    assert_eq!(comparison.ways.iter().sum::<usize>(), differing);
    assert_eq!(comparison.ways.len(), 2, "{:?}", comparison.ways);
    assert_eq!(kept.len(), KEPT.min(differing));
    assert!(kept.windows(2).all(|pair| pair[0].index < pair[1].index));
    for way in 0..comparison.ways.len() {
        assert!(kept.iter().any(|state| state.way == way), "way {way}");
    }
    // A way is one deciding value per processor, in order of first seen.
    let first = |way: usize| kept.iter().find(|state| state.way == way).unwrap();
    let values = |way: usize| first(way).decider.as_ref().unwrap().values.clone();
    assert_ne!(values(0), values(1));
    assert!(first(0).index < first(1).index);
    for state in kept {
        assert_eq!(state.decider.as_ref().unwrap().values, values(state.way));
        assert!(state.stored.is_none());
        let site = state.decider.as_ref().unwrap().site;
        let rules: Vec<String> = embedded()
            .iter()
            .map(|profile| profile.choice(site).unwrap().text().to_owned())
            .collect();
        assert_eq!(state.rules, rules);
        assert_ne!(rules[0], rules[1]);
    }
}
