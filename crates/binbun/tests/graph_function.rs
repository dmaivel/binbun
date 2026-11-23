//! Function graphs of the checked-in fixtures (and bash, ignored by
//! default): the model's blocks and edges agree with the listing and the
//! control flow, and every function's layout is clean.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers fail loudly"
)]

use binbun::Database;
use binbun::analysis::Seeds;
use binbun::graph::layout::{Size, Spacing, layout};
use binbun::graph::svg::Metrics;
use binbun::graph::{EdgeKind, Exit, FunctionGraph, block_line, measure};
use binbun::listing::{LineKind, Listing, Options};
use binbun_loader::Image;

fn fixture(name: &str) -> Vec<u8> {
    let path = format!("{}/../../tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

/// Block sizes as the CLI measures them: characters and lines, room for
/// the terminal mark.
fn sizes(graph: &FunctionGraph, listing: &Listing, db: &Database<'_>) -> Vec<Size> {
    let metrics = Metrics::default();
    graph
        .blocks
        .iter()
        .map(|b| {
            let chars = b
                .lines
                .iter()
                .map(|&n| {
                    block_line(listing.render(db, n))
                        .rendered
                        .text()
                        .chars()
                        .count()
                })
                .max()
                .unwrap_or(0);
            metrics.size(chars, b.lines.len(), b.exit)
        })
        .collect()
}

/// Checks every function of `data`; returns how many blocks and edges of
/// each kind were seen.
fn check_image(data: &[u8], only: Option<&str>) -> (usize, Vec<EdgeKind>) {
    let image = Image::parse(data).unwrap();
    let db = Database::new(&image, Seeds::ALL).unwrap();
    let listing = Listing::build(&db, &Options::default());
    let mut blocks = 0;
    let mut kinds = Vec::new();
    for (id, function) in db.functions() {
        if only.is_some_and(|name| db.name(function.entry) != Some(name)) {
            continue;
        }
        let graph = FunctionGraph::build(&db, &listing, id).unwrap();
        let name = db.name(function.entry).unwrap_or("?").to_owned();
        // The entry's block first; blocks apart, each holding its lines.
        assert_eq!(graph.blocks[0].start, function.entry, "{name}");
        assert_eq!(graph.block_of(function.entry), Some(0));
        let mut spans: Vec<(u64, u64)> = graph.blocks.iter().map(|b| (b.start, b.end)).collect();
        spans.sort_unstable();
        assert!(
            spans.windows(2).all(|w| w[0].1 <= w[1].0),
            "{name}: blocks overlap"
        );
        for (i, b) in graph.blocks.iter().enumerate() {
            assert_eq!(graph.block_of(b.start), Some(i));
            let instructions: Vec<u64> = b
                .lines
                .iter()
                .filter_map(|&n| listing.line(n))
                .filter(|l| l.kind == LineKind::Instruction)
                .map(|l| l.address)
                .collect();
            assert_eq!(instructions.first(), Some(&b.start), "{name}: block {i}");
            assert!(instructions.iter().all(|a| (b.start..b.end).contains(a)));
            assert!(b.lines.iter().all(|&n| {
                let kind = listing.line(n).unwrap().kind;
                !matches!(
                    kind,
                    LineKind::Xref | LineKind::Separator | LineKind::Banner
                )
            }));
            // A block no edge leaves says how it ends; one with edges out
            // does not.
            let leaves = graph.edges.iter().any(|e| e.from == i);
            assert_eq!(
                b.exit == Exit::Edges,
                leaves,
                "{name}: block {i} {:?}",
                b.exit
            );
        }
        // Every instruction of the function's blocks is in one block.
        let recovered: u64 = function
            .blocks
            .iter()
            .filter_map(|&b| db.program().blocks.get(b))
            .map(|b| u64::from(b.instructions))
            .sum();
        let shown: u64 = graph
            .blocks
            .iter()
            .flat_map(|b| &b.lines)
            .filter(|&&n| listing.line(n).unwrap().kind == LineKind::Instruction)
            .count() as u64;
        assert!(
            shown >= recovered,
            "{name}: {shown} of {recovered} instructions"
        );
        for e in &graph.edges {
            assert!(e.from < graph.blocks.len() && e.to < graph.blocks.len());
            // A conditional's two edges leave one block.
            if e.kind == EdgeKind::Taken {
                assert!(
                    graph
                        .edges
                        .iter()
                        .any(|f| f.from == e.from && f.kind == EdgeKind::NotTaken),
                    "{name}: taken without not taken"
                );
            }
            kinds.push(e.kind);
        }
        let edges = graph.layout_edges();
        let laid = layout(
            &sizes(&graph, &listing, &db),
            &edges,
            0,
            &Spacing::default(),
        );
        let q = measure(&laid, &edges);
        assert!(q.is_clean(), "{name}: {q:?}");
        assert!(
            laid.nodes.iter().all(|r| r.y >= laid.nodes[0].y),
            "{name}: entry not on top"
        );
        blocks += graph.blocks.len();
    }
    (blocks, kinds)
}

#[test]
fn fixtures_lay_out_cleanly() {
    let mut kinds = Vec::new();
    for name in [
        "exceptions-x86_64.elf",
        "classes-gcc-x86_64.elf",
        "handlers-clang-x86_64.elf",
        "eh-x86_64.exe",
        "msvc-x86_64.exe",
        "dozen-aarch64.elf",
    ] {
        let (blocks, k) = check_image(&fixture(name), None);
        assert!(blocks > 0, "{name}");
        kinds.extend(k);
    }
    for kind in [
        EdgeKind::Taken,
        EdgeKind::NotTaken,
        EdgeKind::Jump,
        EdgeKind::Next,
        EdgeKind::Unwind,
    ] {
        assert!(kinds.contains(&kind), "no {kind:?} edge in the fixtures");
    }
}

/// Every function of bash, `main` and its switches among them.
#[test]
#[ignore = "reads /usr/bin/bash"]
fn bash_lays_out_cleanly() {
    let data = std::fs::read("/usr/bin/bash").unwrap();
    let (_, kinds) = check_image(&data, Some("main"));
    assert!(kinds.contains(&EdgeKind::Taken));
    let (blocks, kinds) = check_image(&data, None);
    assert!(blocks > 10_000);
    assert!(kinds.contains(&EdgeKind::Case));
}
