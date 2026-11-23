//! The call graph, paths, data reachability and call sites' arguments on
//! the checked-in `program-x86_64.elf` (`tests/fixtures/program.c`):
//! `main` calls `loop_sum(argc + 5)`, which calls `checked(i % 7)`, which
//! calls `fail("negative")` when `x < 0` and `classify(x)` after. (The
//! range facts' own cases are `binbun_decompile::range::Values`' tests:
//! here `x < 0` is decompiled as a sign bit test, `(x >> 31) & 1`, which
//! they do not read.)

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers fail loudly"
)]

use std::sync::atomic::AtomicBool;

use binbun::Database;
use binbun::analysis::Seeds;
use binbun::calls::sites::{Known, sites};
use binbun::calls::{Kind, Node, PathQuery, data};
use binbun::cfg::FunctionId;
use binbun::decompile::{Options, View};
use binbun_ast::ir::Node as L2Node;
use binbun_loader::Image;

fn fixture(name: &str) -> Vec<u8> {
    let path = format!("{}/../../tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

fn function(database: &Database<'_>, name: &str) -> FunctionId {
    database.find_function(name).unwrap()
}

fn node(database: &Database<'_>, name: &str) -> Node {
    Node::Function(function(database, name))
}

/// The name of `node`.
fn name(database: &Database<'_>, node: Node) -> String {
    match node {
        Node::Function(id) => {
            let entry = database.function(id).unwrap().entry;
            database
                .data_name(entry)
                .unwrap_or_else(|| format!("{entry:x}"))
        }
        Node::Import(slot) => database.calls().import_name(slot).unwrap().to_owned(),
    }
}

#[test]
fn graph_and_paths() {
    let data = fixture("program-x86_64.elf");
    let image = Image::parse(&data).unwrap();
    let database = Database::new(&image, Seeds::ALL).unwrap();
    let graph = database.calls();

    let checked = function(&database, "checked");
    let mut called: Vec<String> = graph
        .callees(checked)
        .iter()
        .map(|call| name(&database, call.callee))
        .collect();
    called.sort();
    assert_eq!(called, ["classify", "fail"]);
    assert!(graph.callees(checked).iter().all(|c| c.kind == Kind::Call));
    let callers: Vec<FunctionId> = graph
        .callers(node(&database, "classify"))
        .map(|call| call.caller)
        .collect();
    assert_eq!(callers, [checked]);

    let never = AtomicBool::new(false);
    let query = PathQuery {
        from: Some(node(&database, "main")),
        to: Some(node(&database, "classify")),
        limit: 8,
        ..PathQuery::default()
    };
    let found = graph.paths(&query, &never).unwrap();
    assert_eq!(found.shortest, Some(3));
    let path: Vec<String> = found.paths[0]
        .iter()
        .map(|hop| name(&database, hop.node))
        .collect();
    assert_eq!(path, ["main", "loop_sum", "checked", "classify"]);
    assert_eq!(found.subgraph.nodes.len(), 4);

    // Through `fail` there is no way to `classify`; avoiding `checked`
    // neither.
    let through = PathQuery {
        through: vec![node(&database, "fail")],
        ..query.clone()
    };
    assert_eq!(graph.paths(&through, &never).unwrap().shortest, None);
    let avoiding = PathQuery {
        avoid: vec![node(&database, "checked")],
        ..query
    };
    let avoided = graph.paths(&avoiding, &never).unwrap();
    assert_eq!((avoided.shortest, avoided.paths.len()), (None, 0));

    // Down from `main` two levels: `loop_sum` and `printf`'s thunk, then
    // `checked` and the import.
    let around = graph.neighbourhood(node(&database, "main"), 1, 2, 64);
    let names: Vec<String> = around.nodes.iter().map(|&n| name(&database, n)).collect();
    assert!(names.contains(&"loop_sum".to_owned()), "{names:?}");
    assert!(names.contains(&"checked".to_owned()), "{names:?}");
    assert_eq!(around.levels[0], 0);
}

#[test]
fn data_reaches_along_arguments() {
    let data = fixture("program-x86_64.elf");
    let image = Image::parse(&data).unwrap();
    let database = Database::new(&image, Seeds::ALL).unwrap();
    let never = AtomicBool::new(false);

    // `checked`'s `x` goes on to `classify(x)` only.
    let flows = data::flows(&database, function(&database, "checked"));
    let classify = database
        .calls()
        .callers(node(&database, "classify"))
        .next()
        .unwrap();
    assert!(
        flows
            .iter()
            .any(|f| f.site == classify.site && f.parameter == 0 && f.argument == 0),
        "{flows:?}"
    );
    let fail = database
        .calls()
        .callers(node(&database, "fail"))
        .next()
        .unwrap();
    assert!(!flows.iter().any(|f| f.site == fail.site), "{flows:?}");

    // `main`'s `argc` reaches `loop_sum`, whose `n` bounds the loop but
    // is not passed on: data never reaches `classify`, calls do.
    let to_loop = PathQuery {
        from: Some(node(&database, "main")),
        to: Some(node(&database, "loop_sum")),
        limit: 4,
        ..PathQuery::default()
    };
    let reached = data::paths(&database, &to_loop, 0, &never).unwrap();
    assert_eq!(reached.shortest, Some(1));
    assert_eq!(reached.paths[0][1].argument, Some(0));
    let to_classify = PathQuery {
        to: Some(node(&database, "classify")),
        ..to_loop
    };
    assert_eq!(
        data::paths(&database, &to_classify, 0, &never)
            .unwrap()
            .shortest,
        None
    );
    let from_checked = PathQuery {
        from: Some(node(&database, "checked")),
        ..to_classify
    };
    assert_eq!(
        data::paths(&database, &from_checked, 0, &never)
            .unwrap()
            .shortest,
        Some(1)
    );
}

#[test]
fn call_sites_know_ranges_and_constants() {
    let data = fixture("program-x86_64.elf");
    let image = Image::parse(&data).unwrap();
    let database = Database::new(&image, Seeds::ALL).unwrap();
    let checked = function(&database, "checked");
    let options = Options {
        view: View::Reading,
        ..Options::default()
    };
    let decompiled = database.decompile(checked, &options).result.unwrap();
    let at: Vec<u64> = database
        .calls()
        .callees(checked)
        .iter()
        .map(|call| call.site)
        .collect();
    let fail = database
        .calls()
        .callers(node(&database, "fail"))
        .next()
        .unwrap()
        .site;
    let found = sites(&decompiled.l2, &at);
    for (site, &address) in found.iter().zip(&at) {
        let site = site.as_ref().unwrap();
        assert_eq!(site.at, address);
        if address == fail {
            // `fail("negative")`: the string's address, a constant.
            let string = database
                .strings(4)
                .into_iter()
                .find(|s| s.text == "negative")
                .unwrap()
                .address;
            assert_eq!(site.arguments, [Known::Constant(string)], "{site:?}");
        } else {
            // `classify(a1)` in `return classify(a1) * 2;`: a call inside
            // the return statement's expression.
            assert!(matches!(site.node, L2Node::Expr(_)));
            assert_eq!(site.arguments.len(), 1);
        }
    }
    // An instruction that makes no call has no site.
    assert_eq!(sites(&decompiled.l2, &[1]), [None]);
}
