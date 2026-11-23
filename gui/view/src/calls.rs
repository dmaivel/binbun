//! The call graph's views without the drawing (questions answered in
//! panels, not hairballs):
//!
//! - [`CallView`]: a function's neighbourhood (callers so many levels up,
//!   callees so many down) or a path search's listed paths (their union,
//!   [`listed`]; the whole subgraph one toggle away), laid out with
//!   `binbun::graph`'s layered layout as compact boxes (name, address),
//!   each pair's calls one edge with their count; hit testing.
//! - [`CallsPane`]: a listing pane's call graph mode: what it shows, the
//!   selected node, the viewport.
//! - [`Pathfinder`]: the Pathfinder panel's question (from, to, waypoints,
//!   functions avoided, data only), saved per project.
//! - [`CallerRow`]: the cross-references tab's callers mode: each call
//!   site's C line and its arguments' known values, sortable by any.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::Arc;

use binbun::calls::sites::Known;
use binbun::calls::{CallGraph, Edge as Call, Node, PathQuery, Paths, Subgraph};
use binbun::graph::layout::{Edge, Layout, Spacing, layout};
pub use binbun::graph::layout::{Point, Rect, Size};

use crate::crash_safe;
use crate::graph::GraphPane;

/// The most nodes a neighbourhood shows.
pub const MOST: usize = 160;

/// The deepest level a neighbourhood reaches.
pub const DEEPEST: usize = 6;

/// The most paths a search lists.
pub const PATHS: usize = 64;

/// What a call graph shows.
#[derive(Clone, Debug, PartialEq)]
pub enum Shown {
    /// A node's callers `up` levels up and callees `down` levels down.
    Around {
        /// The node.
        centre: Node,
        /// Caller levels.
        up: usize,
        /// Callee levels.
        down: usize,
    },
    /// A path search's answer: the union of the paths it lists, or
    /// (`whole`) its whole subgraph (every node on some path and the calls
    /// between them on paths).
    Paths {
        /// The answer.
        paths: Arc<Paths>,
        /// Whether the whole subgraph is shown.
        whole: bool,
    },
}

/// A node as drawn.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CallNode {
    /// The function or import.
    pub node: Node,
    /// Its name as shown.
    pub name: String,
    /// Its address: a function's entry, an import's slot.
    pub address: u64,
    /// Its level: callees positive, callers negative (a path's: its
    /// distance from the start).
    pub level: i32,
    /// Its calls whose destination is not known.
    pub unresolved: usize,
}

/// The calls from one node to another.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CallEdge {
    /// The caller's index.
    pub from: usize,
    /// The callee's.
    pub to: usize,
    /// The call sites.
    pub sites: Vec<u64>,
}

/// The text metrics a call graph is laid out with.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Metrics {
    /// A character's width.
    pub char_width: f32,
    /// A line's height.
    pub line_height: f32,
    /// The padding inside a box.
    pub padding: f32,
}

/// A call graph laid out (zoom 1).
#[derive(Clone, Debug)]
pub struct CallView {
    /// What it shows.
    pub shown: Shown,
    /// The nodes; the first is the centre or the start.
    pub nodes: Vec<CallNode>,
    /// The edges.
    pub edges: Vec<CallEdge>,
    /// Where they are: a node's box, then the edges' routes.
    pub layout: Layout,
    /// The metrics.
    pub metrics: Metrics,
    /// Whether a neighbourhood was cut at [`MOST`] nodes.
    pub cut: bool,
}

impl CallView {
    /// `shown` of `graph` laid out for `metrics`, each node named by
    /// `name` (its name and address).
    pub fn build(
        graph: &CallGraph,
        shown: Shown,
        name: &dyn Fn(Node) -> (String, u64),
        metrics: Metrics,
    ) -> Self {
        let (subgraph, cut) = match &shown {
            Shown::Around { centre, up, down } => {
                let around = graph.neighbourhood(*centre, *up, *down, MOST);
                let cut = around.nodes.len() >= MOST;
                (around, cut)
            }
            Shown::Paths { paths, whole: true } => (paths.subgraph.clone(), false),
            Shown::Paths {
                paths,
                whole: false,
            } => (listed(paths), false),
        };
        let nodes: Vec<CallNode> = subgraph
            .nodes
            .iter()
            .enumerate()
            .map(|(i, &node)| {
                let (name, address) = name(node);
                CallNode {
                    node,
                    name,
                    address,
                    level: subgraph.levels.get(i).copied().unwrap_or(0),
                    unresolved: subgraph.unresolved.get(i).copied().unwrap_or(0),
                }
            })
            .collect();
        // A neighbourhood draws the calls from each level to the next (a
        // callee's own calls among the callees are not what it shows).
        let around = matches!(shown, Shown::Around { .. });
        let level = |i: usize| nodes.get(i).map_or(0, |n| n.level);
        let edges: Vec<CallEdge> = subgraph
            .edges
            .iter()
            .filter(|e| !around || level(e.to) == level(e.from) + 1)
            .map(|e| CallEdge {
                from: e.from,
                to: e.to,
                sites: e.sites.clone(),
            })
            .collect();
        let sizes: Vec<Size> = nodes.iter().map(|n| metrics.size(n)).collect();
        let one_level = matches!(shown, Shown::Around { up, down, .. } if up <= 1 && down <= 1);
        if one_level && let Some(layout) = grid(&nodes, &edges, &sizes, &metrics) {
            return Self {
                shown,
                nodes,
                edges,
                layout,
                metrics,
                cut,
            };
        }
        let spacing = Spacing {
            node: metrics.char_width * 3.0,
            layer: metrics.line_height * 2.0,
            track: (metrics.line_height * 0.45).round(),
        };
        let laid: Vec<Edge> = edges
            .iter()
            .map(|e| Edge {
                from: e.from,
                to: e.to,
                order: 0,
            })
            .collect();
        let layout = layout(&sizes, &laid, 0, &spacing);
        Self {
            shown,
            nodes,
            edges,
            layout,
            metrics,
            cut,
        }
    }

    /// Node `i`'s box.
    pub fn rect(&self, i: usize) -> Option<Rect> {
        self.layout.nodes.get(i).copied()
    }

    /// The node at `p` (graph coordinates).
    pub fn hit(&self, p: Point) -> Option<usize> {
        self.layout
            .nodes
            .iter()
            .position(|r| p.x >= r.x && p.x < r.right() && p.y >= r.y && p.y < r.bottom())
    }

    /// The index of `node`.
    pub fn find(&self, node: Node) -> Option<usize> {
        self.nodes.iter().position(|n| n.node == node)
    }

    /// The index of the node at `address` (its entry or slot).
    pub fn at(&self, address: u64) -> Option<usize> {
        self.nodes.iter().position(|n| n.address == address)
    }

    /// The edges on `path` of a path search (each hop's caller to it), by
    /// index into [`Self::edges`].
    pub fn path_edges(&self, path: usize) -> Vec<usize> {
        let Shown::Paths { paths, .. } = &self.shown else {
            return Vec::new();
        };
        let Some(hops) = paths.paths.get(path) else {
            return Vec::new();
        };
        hops.windows(2)
            .filter_map(|pair| {
                let [a, b] = pair else { return None };
                let (from, to) = (self.find(a.node)?, self.find(b.node)?);
                self.edges.iter().position(|e| e.from == from && e.to == to)
            })
            .collect()
    }
}

impl Metrics {
    /// The box of `node`: its name, two spaces and its address on one line,
    /// room for the verification dot before them.
    fn size(&self, node: &CallNode) -> Size {
        let chars = label(node).chars().count() + 2;
        Size {
            width: count(chars) * self.char_width + 2.0 * self.padding,
            height: self.line_height + 2.0 * self.padding,
        }
    }
}

/// The text of `node`'s box: its name, then its address.
pub fn label(node: &CallNode) -> String {
    format!("{}  {:X}", node.name, node.address)
}

/// The union of the paths `paths` lists: their nodes (the start first,
/// then in the subgraph's order, each at its level there) and the calls
/// they take between them (each pair's sites those the paths go through).
pub fn listed(paths: &Paths) -> Subgraph {
    let mut calls: BTreeMap<(Node, Node), BTreeSet<u64>> = BTreeMap::new();
    let mut on: BTreeSet<Node> = BTreeSet::new();
    for hops in &paths.paths {
        on.extend(hops.iter().map(|hop| hop.node));
        for pair in hops.windows(2) {
            if let [from, to] = pair {
                let sites = calls.entry((from.node, to.node)).or_default();
                sites.extend(to.site);
            }
        }
    }
    let whole = &paths.subgraph;
    let kept: Vec<usize> = (0..whole.nodes.len())
        .filter(|&i| whole.nodes.get(i).is_some_and(|node| on.contains(node)))
        .collect();
    let index: BTreeMap<Node, usize> = kept
        .iter()
        .enumerate()
        .filter_map(|(at, &i)| Some((*whole.nodes.get(i)?, at)))
        .collect();
    let edges = calls
        .into_iter()
        .filter_map(|((from, to), sites)| {
            Some(Call {
                from: *index.get(&from)?,
                to: *index.get(&to)?,
                sites: sites.into_iter().collect(),
            })
        })
        .collect();
    Subgraph {
        nodes: kept
            .iter()
            .filter_map(|&i| whole.nodes.get(i).copied())
            .collect(),
        levels: kept
            .iter()
            .map(|&i| whole.levels.get(i).copied().unwrap_or(0))
            .collect(),
        edges,
        unresolved: kept
            .iter()
            .map(|&i| whole.unresolved.get(i).copied().unwrap_or(0))
            .collect(),
    }
}

fn count(n: usize) -> f32 {
    f32::from(u16::try_from(n).unwrap_or(u16::MAX))
}

/// The most nodes in a row of a neighbourhood's level laid out as a grid.
const ROW: usize = 8;

/// A neighbourhood of one level each way laid out as a grid, if a level
/// is too wide for one row ([`ROW`]): the centre alone in its row, its
/// callees in rows below and its callers in rows above, each level in
/// equal cells (the widest box's), half left and half right of an aisle
/// under the centre, each row read left to right; callees in the order
/// the centre calls them, callers by name. Each edge runs along the aisle
/// (the centre's trunk) to a bus
/// just above (callees) or below (callers) its node's row, then to the
/// node, so no edge crosses a box.
fn grid(nodes: &[CallNode], edges: &[CallEdge], sizes: &[Size], m: &Metrics) -> Option<Layout> {
    let (below, above) = (grid_side(nodes, edges, 1), grid_side(nodes, edges, -1));
    if below.len().max(above.len()) <= ROW {
        return None;
    }
    let centre = *sizes.first()?;
    let gap = m.char_width * 2.0;
    let aisle = m.char_width * 4.0;
    let bus = m.line_height * 0.8;
    let widest = |list: &[usize]| {
        list.iter()
            .filter_map(|&i| sizes.get(i))
            .map(|s| s.width)
            .fold(0.0f32, f32::max)
    };
    let cell = widest(&below).max(widest(&above));
    let half = count(ROW / 2);
    let width = (2.0 * half * (cell + gap) + aisle).max(centre.width);
    let middle = width / 2.0;
    let row_h = centre.height;
    let mut rects = vec![Rect::default(); nodes.len()];
    // Rows of a side, from the centre outwards: each node's cell.
    let place = |list: &[usize], rects: &mut Vec<Rect>, top: &dyn Fn(usize) -> f32| {
        for (k, &i) in list.iter().enumerate() {
            let (row, column) = (k / ROW, k % ROW);
            let left = column < ROW / 2;
            let x = if left {
                middle - aisle / 2.0 - count(ROW / 2 - column) * (cell + gap) + gap
            } else {
                middle + aisle / 2.0 + count(column - ROW / 2) * (cell + gap)
            };
            let w = sizes.get(i).map_or(cell, |s| s.width);
            // Left cells hug the aisle, as right ones do.
            let x = if left { x + cell - w } else { x };
            if let Some(r) = rects.get_mut(i) {
                *r = Rect {
                    x,
                    y: top(row),
                    width: w,
                    height: row_h,
                };
            }
        }
    };
    let rows = |n: usize| count(n.div_ceil(ROW));
    let callers_height = rows(above.len()) * (row_h + bus);
    let centre_top = callers_height + if above.is_empty() { 0.0 } else { bus };
    let first_below = centre_top + row_h + bus;
    place(&below, &mut rects, &|row| {
        first_below + count(row) * (row_h + bus)
    });
    place(&above, &mut rects, &|row| {
        callers_height - (count(row) + 1.0) * (row_h + bus)
    });
    if let Some(r) = rects.first_mut() {
        *r = Rect {
            x: middle - centre.width / 2.0,
            y: centre_top,
            width: centre.width,
            height: row_h,
        };
    }
    let mut routes = grid_routes(edges, &rects, middle, bus)?;
    // Everything moved so the top left is at 0, 0.
    let top = rects.iter().map(|r| r.y).fold(f32::MAX, f32::min).min(0.0);
    for r in &mut rects {
        r.y -= top;
    }
    for route in &mut routes {
        for p in &mut route.points {
            p.y -= top;
        }
    }
    let height = rects.iter().map(Rect::bottom).fold(0.0f32, f32::max);
    Some(Layout {
        nodes: rects,
        edges: routes,
        width,
        height,
    })
}

/// The grid's nodes on one side of the centre: its callees (`sign` 1) in
/// the order the centre calls them, or its callers (-1) by name.
fn grid_side(nodes: &[CallNode], edges: &[CallEdge], sign: i32) -> Vec<usize> {
    let mut out: Vec<usize> = (0..nodes.len())
        .filter(|&i| nodes.get(i).is_some_and(|n| n.level.signum() == sign))
        .collect();
    let first_site = |i: usize| {
        edges
            .iter()
            .filter(|e| e.to == i || e.from == i)
            .filter_map(|e| e.sites.first().copied())
            .min()
            .unwrap_or(u64::MAX)
    };
    if sign > 0 {
        out.sort_by_key(|&i| (first_site(i), i));
    } else {
        out.sort_by(|&a, &b| {
            let name = |i: usize| nodes.get(i).map(|n| n.name.as_str());
            name(a).cmp(&name(b)).then(a.cmp(&b))
        });
    }
    out
}

/// The grid's edges routed along the aisle at `middle` (the centre is
/// `rects[0]`) and the buses `bus` high between the rows.
fn grid_routes(
    edges: &[CallEdge],
    rects: &[Rect],
    middle: f32,
    bus: f32,
) -> Option<Vec<binbun::graph::layout::Route>> {
    let centre = *rects.first()?;
    let mut routes = vec![binbun::graph::layout::Route::default(); edges.len()];
    for (e, route) in edges.iter().zip(routes.iter_mut()) {
        let (Some(from), Some(to)) = (rects.get(e.from), rects.get(e.to)) else {
            continue;
        };
        let points = if e.from == 0 {
            // Down the aisle to the bus above the callee's row.
            let y = to.y - bus / 2.0;
            let x = to.x + to.width / 2.0;
            vec![
                Point {
                    x: middle,
                    y: centre.bottom(),
                },
                Point { x: middle, y },
                Point { x, y },
                Point { x, y: to.y },
            ]
        } else {
            // From the caller to the bus below its row, up the aisle's
            // other way: down into the centre.
            let y = from.bottom() + bus / 2.0;
            let x = from.x + from.width / 2.0;
            vec![
                Point {
                    x,
                    y: from.bottom(),
                },
                Point { x, y },
                Point { x: middle, y },
                Point {
                    x: middle,
                    y: centre.y,
                },
            ]
        };
        *route = binbun::graph::layout::Route {
            points,
            back: false,
        };
    }
    Some(routes)
}

/// A listing pane's call graph mode.
#[derive(Clone, Debug, Default)]
pub struct CallsPane {
    /// The pane shows the call graph.
    pub on: bool,
    /// The pane showed the control-flow graph before (restored when it
    /// leaves).
    pub graph: bool,
    /// What it shows, once chosen.
    pub shown: Option<Shown>,
    /// The selected node (the pane's cursor).
    pub selected: Option<usize>,
    /// The path of a search drawn brighter.
    pub path: Option<usize>,
    /// The shared cursor moved here: its function selected (or, for a
    /// neighbourhood, shown) when next drawn.
    pub target: Option<u64>,
    /// The view, its glide and drags (as the control-flow graph's).
    pub nav: GraphPane,
    /// The view lands on the selection when next drawn.
    pub landing: bool,
}

/// The Pathfinder's question: by addresses (a function's entry, an
/// import's slot), so it survives renames and is saved as such.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Pathfinder {
    /// Where paths start.
    pub from: Option<u64>,
    /// Where they end.
    pub to: Option<u64>,
    /// What they pass, in order.
    pub through: Vec<u64>,
    /// What they never pass.
    pub avoid: Vec<u64>,
    /// Only along calls where the start's parameter goes on.
    pub data: bool,
    /// That parameter (0 the first).
    pub parameter: u8,
}

impl Pathfinder {
    /// The engine's query, each address made a node by `node` (`None` if
    /// the ends are not both set or one names nothing).
    pub fn query(&self, node: impl Fn(u64) -> Option<Node>) -> Option<PathQuery> {
        Some(PathQuery {
            from: Some(node(self.from?)?),
            to: Some(node(self.to?)?),
            through: self.through.iter().filter_map(|&a| node(a)).collect(),
            avoid: self.avoid.iter().filter_map(|&a| node(a)).collect(),
            limit: PATHS,
        })
    }

    /// The parameter followed, if data only.
    pub fn data(&self) -> Option<u8> {
        self.data.then_some(self.parameter)
    }

    /// Saves it to `path`, crash-safely.
    ///
    /// # Errors
    ///
    /// It cannot be written.
    pub fn save(&self, path: &Path) -> Result<(), String> {
        let mut doc = toml_edit::DocumentMut::new();
        let hex = |a: u64| toml_edit::Value::from(format!("0x{a:X}"));
        if let Some(from) = self.from {
            doc.insert("from", toml_edit::Item::Value(hex(from)));
        }
        if let Some(to) = self.to {
            doc.insert("to", toml_edit::Item::Value(hex(to)));
        }
        let list = |addresses: &[u64]| {
            toml_edit::Item::Value(toml_edit::Value::Array(
                addresses.iter().map(|&a| hex(a)).collect(),
            ))
        };
        doc.insert("through", list(&self.through));
        doc.insert("avoid", list(&self.avoid));
        doc.insert("data", toml_edit::value(self.data));
        doc.insert("parameter", toml_edit::value(i64::from(self.parameter)));
        crash_safe::write(path, doc.to_string().as_bytes())
            .map_err(|e| format!("{}: {e}", path.display()))
    }

    /// The question saved at `path`; the default if there is none.
    ///
    /// # Errors
    ///
    /// The file is there but cannot be read or is not TOML.
    pub fn load(path: &Path) -> Result<Self, String> {
        let text = match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(e) => return Err(format!("{}: {e}", path.display())),
        };
        let doc: toml_edit::DocumentMut = text
            .parse()
            .map_err(|e| format!("{}: {e}", path.display()))?;
        let address = |value: &toml_edit::Value| {
            let text = value.as_str()?;
            u64::from_str_radix(text.trim_start_matches("0x"), 16).ok()
        };
        let one = |key: &str| doc.get(key)?.as_value().and_then(address);
        let list = |key: &str| -> Vec<u64> {
            doc.get(key)
                .and_then(toml_edit::Item::as_array)
                .map(|array| array.iter().filter_map(address).collect())
                .unwrap_or_default()
        };
        Ok(Self {
            from: one("from"),
            to: one("to"),
            through: list("through"),
            avoid: list("avoid"),
            data: doc
                .get("data")
                .and_then(toml_edit::Item::as_bool)
                .unwrap_or(false),
            parameter: doc
                .get("parameter")
                .and_then(toml_edit::Item::as_integer)
                .and_then(|p| u8::try_from(p).ok())
                .unwrap_or(0),
        })
    }
}

/// A row of the cross-references tab's callers mode.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CallerRow {
    /// The call instruction.
    pub site: u64,
    /// The caller's entry.
    pub caller: u64,
    /// The caller's name as shown.
    pub name: String,
    /// The C line making the call, if known.
    pub line: Option<String>,
    /// What is known of each argument.
    pub arguments: Vec<Known>,
}

/// What a callers table is sorted by.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SortBy {
    /// The call's address.
    #[default]
    Site,
    /// The caller's name.
    Caller,
    /// The C line.
    Line,
    /// An argument's known value (its least), unknown last.
    Argument(usize),
}

/// Sorts `rows` by `by`, descending if `descending`; rows with nothing
/// known of the argument come last either way, ties by site.
pub fn sort_rows(rows: &mut [CallerRow], by: SortBy, descending: bool) {
    let directed = |o: Ordering| if descending { o.reverse() } else { o };
    rows.sort_by(|a, b| {
        let order = match by {
            SortBy::Site => directed(a.site.cmp(&b.site)),
            SortBy::Caller => directed(a.name.cmp(&b.name)),
            SortBy::Line => directed(a.line.cmp(&b.line)),
            SortBy::Argument(k) => {
                let key = |row: &CallerRow| row.arguments.get(k).and_then(Known::key);
                match (key(a), key(b)) {
                    (Some(x), Some(y)) => directed(x.cmp(&y)),
                    (Some(_), None) => Ordering::Less,
                    (None, Some(_)) => Ordering::Greater,
                    (None, None) => Ordering::Equal,
                }
            }
        };
        order.then(a.site.cmp(&b.site))
    });
}

/// How an argument's known value reads in a column: a constant in
/// hexadecimal (decimal below 10), a range as `lo..=hi`, nothing if
/// unknown.
pub fn argument_text(known: &Known) -> String {
    let number = |v: i128| {
        if (-9..=9).contains(&v) {
            v.to_string()
        } else if v < 0 {
            format!("-0x{:X}", v.unsigned_abs())
        } else {
            format!("0x{v:X}")
        }
    };
    match *known {
        Known::Constant(v) => number(i128::from(v)),
        Known::Range { lo, hi, .. } => format!("{}..={}", number(lo), number(hi)),
        Known::Unknown => String::new(),
    }
}

/// How many argument columns `rows` need.
pub fn argument_columns(rows: &[CallerRow]) -> usize {
    rows.iter().map(|r| r.arguments.len()).max().unwrap_or(0)
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::indexing_slicing,
        reason = "tests fail loudly"
    )]

    use binbun::Database;
    use binbun::analysis::Seeds;
    use binbun_loader::Image;

    use super::*;

    fn fixture() -> Vec<u8> {
        let path = format!(
            "{}/../../tests/fixtures/program-x86_64.elf",
            env!("CARGO_MANIFEST_DIR")
        );
        std::fs::read(&path).unwrap()
    }

    const METRICS: Metrics = Metrics {
        char_width: 8.0,
        line_height: 17.0,
        padding: 4.0,
    };

    #[test]
    fn neighbourhood_puts_callers_above_and_callees_below() {
        let data = fixture();
        let image = Image::parse(&data).unwrap();
        let db = Database::new(&image, Seeds::ALL).unwrap();
        let graph = db.calls();
        let checked = Node::Function(db.find_function("checked").unwrap());
        let name = |node: Node| match node {
            Node::Function(id) => {
                let entry = db.function(id).unwrap().entry;
                (db.data_name(entry).unwrap_or_default(), entry)
            }
            Node::Import(slot) => (graph.import_name(slot).unwrap_or("").to_owned(), slot),
        };
        let shown = Shown::Around {
            centre: checked,
            up: 1,
            down: 1,
        };
        let view = CallView::build(graph, shown, &name, METRICS);
        assert_eq!(view.nodes[0].node, checked);
        let y = |name: &str| {
            let i = view.nodes.iter().position(|n| n.name == name).unwrap();
            view.rect(i).unwrap().y
        };
        assert!(y("loop_sum") < y("checked"));
        assert!(y("checked") < y("classify"));
        assert!(y("checked") < y("fail"));
        // A box is as wide as its label, and a click inside it hits it.
        let r = view.rect(0).unwrap();
        assert_eq!(
            r.width,
            8.0 * (count(label(&view.nodes[0]).len()) + 2.0) + 8.0
        );
        let inside = Point {
            x: r.x + 1.0,
            y: r.y + 1.0,
        };
        assert_eq!(view.hit(inside), Some(0));
        assert_eq!(view.at(view.nodes[0].address), Some(0));
    }

    #[test]
    fn pathfinder_round_trips_and_makes_the_query() {
        let path = std::env::temp_dir().join(format!(
            "binbun-pathfinder-{}.pathfinder.toml",
            std::process::id()
        ));
        let question = Pathfinder {
            from: Some(0x1000),
            to: Some(0x2000),
            through: vec![0x1800],
            avoid: vec![0x3000, 0x3100],
            data: true,
            parameter: 2,
        };
        question.save(&path).unwrap();
        assert_eq!(Pathfinder::load(&path).unwrap(), question);
        std::fs::remove_file(&path).unwrap();
        assert_eq!(Pathfinder::load(&path).unwrap(), Pathfinder::default());

        // Addresses naming nothing drop out of the lists; an end naming
        // nothing makes no query.
        let node = |a: u64| (a != 0x3100).then_some(Node::Import(a));
        let query = question.query(node).unwrap();
        assert_eq!(query.avoid, [Node::Import(0x3000)]);
        assert_eq!(query.through, [Node::Import(0x1800)]);
        assert_eq!(question.data(), Some(2));
        let dangling = Pathfinder {
            to: Some(0x3100),
            ..question
        };
        assert!(dangling.query(node).is_none());
    }

    fn row(site: u64, name: &str, first: Known) -> CallerRow {
        CallerRow {
            site,
            caller: site & !0xff,
            name: name.to_owned(),
            line: None,
            arguments: vec![first],
        }
    }

    #[test]
    fn rows_sort_by_an_argument_with_unknowns_last() {
        let mut rows = vec![
            row(1, "a", Known::Unknown),
            row(2, "b", Known::Constant(0x200)),
            row(
                3,
                "c",
                Known::Range {
                    lo: 16,
                    hi: 32,
                    signed: false,
                },
            ),
            row(4, "d", Known::Constant(8)),
        ];
        sort_rows(&mut rows, SortBy::Argument(0), false);
        let sites: Vec<u64> = rows.iter().map(|r| r.site).collect();
        assert_eq!(sites, [4, 3, 2, 1]);
        sort_rows(&mut rows, SortBy::Argument(0), true);
        let sites: Vec<u64> = rows.iter().map(|r| r.site).collect();
        assert_eq!(sites, [2, 3, 4, 1]);
        sort_rows(&mut rows, SortBy::Caller, true);
        assert_eq!(rows[0].name, "d");
        assert_eq!(argument_text(&Known::Constant(0x200)), "0x200");
        assert_eq!(argument_text(&Known::Constant(8)), "8");
        assert_eq!(
            argument_text(&Known::Range {
                lo: -1,
                hi: 0x7FFF,
                signed: true
            }),
            "-1..=0x7FFF"
        );
        assert_eq!(argument_columns(&rows), 1);
    }

    #[test]
    fn a_search_shows_the_union_of_its_listed_paths_and_the_whole_on_request() {
        use binbun::calls::Hop;
        let node = Node::Import;
        let hop = |n: u64, site: Option<u64>| Hop {
            node: node(n),
            site,
            argument: None,
        };
        let call = |from: usize, to: usize, sites: &[u64]| Call {
            from,
            to,
            sites: sites.to_vec(),
        };
        // Start 0 reaches 4 through 1 or 2; 3 reaches 2 but no listed
        // path goes through it (the search's limit cut it).
        let subgraph = Subgraph {
            nodes: (0..5).map(node).collect(),
            levels: vec![0, 1, 1, 1, 2],
            edges: vec![
                call(0, 1, &[0x10]),
                call(1, 4, &[0x20]),
                call(0, 2, &[0x30, 0x31]),
                call(2, 4, &[0x40]),
                call(0, 3, &[0x50]),
                call(3, 2, &[0x60]),
            ],
            unresolved: vec![0, 0, 2, 0, 0],
        };
        let paths = Arc::new(Paths {
            paths: vec![
                vec![hop(0, None), hop(1, Some(0x10)), hop(4, Some(0x20))],
                vec![hop(0, None), hop(2, Some(0x30)), hop(4, Some(0x40))],
            ],
            shortest: Some(2),
            subgraph,
            complete: false,
        });
        let union = listed(&paths);
        assert_eq!(union.nodes, [0, 1, 2, 4].map(node));
        assert_eq!(union.levels, [0, 1, 1, 2]);
        assert_eq!(union.unresolved, [0, 0, 2, 0]);
        let mut edges: Vec<(usize, usize, Vec<u64>)> = union
            .edges
            .iter()
            .map(|e| (e.from, e.to, e.sites.clone()))
            .collect();
        edges.sort();
        // Only the call the paths take from 0 to 2.
        assert_eq!(
            edges,
            [
                (0, 1, vec![0x10]),
                (0, 2, vec![0x30]),
                (1, 3, vec![0x20]),
                (2, 3, vec![0x40]),
            ]
        );
        let name = |n: Node| (format!("{n:?}"), 0);
        let shown = |whole: bool| {
            let graph = CallGraph::default();
            let paths = Arc::clone(&paths);
            CallView::build(&graph, Shown::Paths { paths, whole }, &name, METRICS)
        };
        let (union, whole) = (shown(false), shown(true));
        assert_eq!((union.nodes.len(), union.edges.len()), (4, 4));
        assert_eq!((whole.nodes.len(), whole.edges.len()), (5, 6));
        // A path's edges are found in either.
        assert_eq!(union.path_edges(1).len(), 2);
        assert_eq!(whole.path_edges(1).len(), 2);
    }
}
