//! The layout's invariants on small graphs: nodes apart, the root on top,
//! every edge routed from its source's bottom to its target's top in
//! vertical and horizontal runs, no runs on each other, through nodes or
//! along their borders, distinct ports, conditional edges on their sides,
//! the same input laid out the same.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    reason = "test helpers fail loudly; sizes and seeds are small"
)]

use binbun::graph::layout::{Edge, Layout, Size, Spacing, layout};
use binbun::graph::measure;

fn sizes(n: usize) -> Vec<Size> {
    (0..n)
        .map(|i| Size {
            width: 80.0 + 37.0 * ((i * 7) % 5) as f32,
            height: 30.0 + 17.0 * ((i * 3) % 4) as f32,
        })
        .collect()
}

fn edges(list: &[(usize, usize, u8)]) -> Vec<Edge> {
    list.iter()
        .map(|&(from, to, order)| Edge { from, to, order })
        .collect()
}

/// Lays out and checks every invariant.
fn check(n: usize, list: &[(usize, usize, u8)]) -> Layout {
    let sizes = sizes(n);
    let edges = edges(list);
    let laid = layout(&sizes, &edges, 0, &Spacing::default());
    let q = measure(&laid, &edges);
    assert!(q.is_clean(), "{q:?}");
    let top = laid.nodes[0].y;
    assert!(laid.nodes.iter().all(|r| r.y >= top), "root not on top");
    assert_eq!(laid, layout(&sizes, &edges, 0, &Spacing::default()));
    for (i, r) in laid.nodes.iter().enumerate() {
        assert_eq!((r.width, r.height), (sizes[i].width, sizes[i].height));
        assert!(r.x >= -0.01 && r.right() <= laid.width + 0.01);
        assert!(r.y >= -0.01 && r.bottom() <= laid.height + 0.01);
    }
    laid
}

#[test]
fn a_chain_is_one_straight_column() {
    let laid = check(4, &[(0, 1, 1), (1, 2, 1), (2, 3, 1)]);
    for (e, route) in laid.edges.iter().enumerate() {
        assert_eq!(route.points.len(), 2, "edge {e} bends: {:?}", route.points);
        assert!((route.points[0].x - route.points[1].x).abs() < 0.01);
    }
    for w in laid.nodes.windows(2) {
        assert!(w[0].bottom() < w[1].y);
    }
}

#[test]
fn a_diamond_puts_not_taken_left_and_taken_right() {
    let laid = check(4, &[(0, 1, 0), (0, 2, 2), (1, 3, 1), (2, 3, 1)]);
    let (left, right) = (&laid.edges[0], &laid.edges[1]);
    assert!(left.points[0].x < right.points[0].x);
    assert!(laid.nodes[1].x < laid.nodes[2].x);
    let joins: Vec<f32> = [2, 3]
        .iter()
        .map(|&e| laid.edges[e].points.last().unwrap().x)
        .collect();
    assert!(
        (joins[0] - joins[1]).abs() >= 1.0,
        "ports shared: {joins:?}"
    );
}

#[test]
fn loops_go_back_up_beside_the_layers() {
    // A loop: 0 -> 1 (header) -> 2 (body) -> 1, 1 -> 3 (exit); a self-loop.
    let laid = check(
        5,
        &[
            (0, 1, 1),
            (1, 2, 0),
            (1, 3, 2),
            (2, 1, 1),
            (3, 3, 0),
            (3, 4, 1),
        ],
    );
    assert!(laid.edges[3].back && laid.edges[4].back);
    assert!(!laid.edges[0].back);
    let header = laid.nodes[1];
    let back = &laid.edges[3].points;
    assert!(back.iter().any(|p| p.y < header.y), "{back:?}");
}

#[test]
fn a_skip_beside_a_long_edge_stays_near() {
    // 0 branches far down to 6; on the way, 1 and 3 each skip a block.
    let laid = check(
        7,
        &[
            (0, 1, 0),
            (0, 6, 2),
            (1, 2, 0),
            (1, 3, 2),
            (2, 3, 1),
            (3, 4, 0),
            (3, 5, 2),
            (4, 5, 1),
            (5, 6, 1),
        ],
    );
    // The skip from 1 to 3 passes 2 on its right, before the long edge.
    let skip = &laid.edges[3];
    let long = &laid.edges[1];
    let max = |r: &binbun::graph::Route| r.points.iter().map(|p| p.x).fold(f32::MIN, f32::max);
    assert!(
        max(skip) < max(long),
        "skip {:?} long {:?}",
        skip.points,
        long.points
    );
}

#[test]
fn a_switch_spreads_its_cases() {
    let mut list = vec![(0, 1, 1)];
    for case in 2..10 {
        list.push((1, case, 1));
        list.push((case, 10, 1));
    }
    list.push((1, 10, 1));
    let laid = check(11, &list);
    let starts: Vec<f32> = laid.edges[1..]
        .iter()
        .step_by(2)
        .map(|r| r.points[0].x)
        .collect();
    assert!(starts.windows(2).all(|w| w[0] < w[1]), "{starts:?}");
}

#[test]
fn several_components_and_bad_edges() {
    let laid = check(5, &[(0, 1, 1), (2, 3, 1), (3, 2, 1), (4, 4, 1)]);
    assert_eq!(laid.nodes.len(), 5);
    let bad = layout(
        &sizes(2),
        &edges(&[(0, 7, 1), (0, 1, 1)]),
        0,
        &Spacing::default(),
    );
    assert_eq!(bad.edges[0].points, vec![]);
    assert_eq!(bad.edges[1].points.len(), 2);
    let empty = layout(&[], &edges(&[(0, 1, 1)]), 0, &Spacing::default());
    assert_eq!((empty.nodes.len(), empty.edges.len()), (0, 1));
}

/// Pseudo-random graphs shaped as control flow: every node reached from
/// the root, conditionals, loops, joins.
#[test]
fn random_control_flow_graphs_are_clean() {
    let mut seed = 0x2545_f491_4f6c_dd1du64;
    let mut next = |n: u64| {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed % n
    };
    for round in 0..400 {
        let n = 3 + next(40) as usize;
        let mut list = Vec::new();
        for v in 0..n - 1 {
            // Falls into the next, maybe also branches anywhere.
            if next(3) == 0 {
                list.push((v, v + 1, 1));
            } else {
                let target = next(n as u64) as usize;
                list.push((v, v + 1, 0));
                list.push((v, target, 2));
            }
        }
        let laid = layout(&sizes(n), &edges(&list), 0, &Spacing::default());
        let q = measure(&laid, &edges(&list));
        assert!(q.is_clean(), "round {round}: {n} {list:?} {q:?}");
        check(n, &list);
    }
}
