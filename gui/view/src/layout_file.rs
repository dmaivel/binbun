//! The window's layout saved per project, in its `layout.toml`
//! ([`binbun_session::Project::layout`], beside the Pathfinder's question
//! and the user's overlays): the split tree with its sizes, each pane's tabs that
//! can be restored (the listing, a function's C by its entry and view,
//! the strings, the cross-references to an address, the console), the
//! active tab of each pane and the focused pane, the map's and the right
//! dock's widths, and each hex pane's side area share under its bytes.
//! A file written while the console was a dock under the panes
//! (`console = true`) has it as a tab under the code.
//! A tab of code also keeps its place (its cursor's address) and whether
//! it was a graph. A file of another format (written before panes were
//! views, [`FORMAT`]) is not read: the window opens as it does the first
//! time.
//!
//! The file's top level is the window tab shown (a tab of a place: the
//! settings and structs are not saved); the others are `[[other]]` tables
//! of the same keys, in the strip's order, and `shown` says where among
//! them the shown one goes. A file without them has one tab.
//!
//! The GUI maps its tabs to [`SavedTab`]s and back with
//! [`Layout::map_tabs`]: a tab that cannot be saved, or no longer
//! restored (a function gone), is dropped, and a pane left without tabs
//! closes.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::path::Path;

use toml_edit::{Array, ArrayOfTables, DocumentMut, InlineTable, Item, Table, TableLike, Value};

use crate::View;
use crate::crash_safe;
use crate::graph_memory::Pan;
use crate::hex::Anchor;
use crate::hex_tree::Step;
use crate::layout::{Axis, Layout, Node, Pane, PaneId, Tab, TabId};
use crate::unified::{Expanded, Fold, Layers, UnifiedView};

/// The format this module writes and reads (`format = 2`): panes as views.
pub const FORMAT: i64 = 2;

/// A tab as saved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SavedTab {
    /// The listing.
    Listing,
    /// A function's C: its entry (none: the C tab has no function yet and
    /// follows the cursor) and view.
    C {
        /// The function's entry.
        entry: Option<u64>,
        /// The view.
        view: View,
    },
    /// The strings.
    Strings,
    /// The cross-references to `len` bytes from `of`.
    Xrefs {
        /// The first address referred to.
        of: u64,
        /// How many bytes from it.
        len: u64,
    },
    /// A folder of the map as a list (Open as Tab): its key.
    Folder(String),
    /// The Python console.
    Console,
}

/// A window tab as saved: its panes, their hex side areas, its tabs'
/// places.
#[derive(Clone, Debug)]
pub struct SavedSplit {
    /// The panes, their tabs and splits, the focused pane.
    pub layout: Layout<SavedTab>,
    /// The side area's share of each hex pane's height under its bytes,
    /// where it is not the default.
    pub hex_sides: Vec<(PaneId, f32)>,
    /// Each tab's place, by its identity in `layout`.
    pub places: HashMap<TabId, SavedPlace>,
}

/// The window's layout as saved: the window tab shown, the others.
#[derive(Clone, Debug)]
pub struct SavedLayout {
    /// The panes, their tabs and splits, the focused pane.
    pub layout: Layout<SavedTab>,
    /// The map's width (logical).
    pub sidebar_width: f32,
    /// The right dock's width (logical), if it was dragged.
    pub dock_width: Option<f32>,
    /// The side area's share of each hex pane's height under its bytes,
    /// where it is not the default.
    pub hex_sides: Vec<(PaneId, f32)>,
    /// Each tab's place, by its identity in `layout` (which
    /// [`Layout::map_tabs`] keeps).
    pub places: HashMap<TabId, SavedPlace>,
    /// The other window tabs of places, in the strip's order.
    pub others: Vec<SavedSplit>,
    /// Where among `others` the shown tab goes (0: first).
    pub shown: usize,
}

/// Where a tab of code was, its view, and where its graph was left (its
/// zoom, the last function's pan).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct SavedPlace {
    /// Its cursor's address.
    pub at: Option<u64>,
    /// Its listing was shown as the graph.
    pub graph: bool,
    /// Its graph's zoom.
    pub zoom: Option<f32>,
    /// Its graph's pan for the function shown last (what it followed is
    /// not saved).
    pub pan: Option<Pan>,
    /// Its listing was shown as the unified listing.
    pub unified: bool,
    /// Its unified listing's layers and folds.
    pub unified_view: UnifiedView,
}

impl SavedLayout {
    /// The layout as TOML.
    pub fn to_toml(&self) -> String {
        let mut doc = DocumentMut::new();
        doc.insert("format", toml_edit::value(FORMAT));
        if !self.others.is_empty() {
            doc.insert("shown", toml_edit::value(index(self.shown)));
        }
        doc.insert("sidebar", toml_edit::value(rounded(self.sidebar_width)));
        if let Some(dock) = self.dock_width {
            doc.insert("dock", toml_edit::value(rounded(dock)));
        }
        write_split(&mut doc, &self.layout, &self.hex_sides, &self.places);
        if !self.others.is_empty() {
            let mut others = ArrayOfTables::new();
            for other in &self.others {
                let mut table = Table::new();
                write_split(&mut table, &other.layout, &other.hex_sides, &other.places);
                others.push(table);
            }
            doc.insert("other", Item::ArrayOfTables(others));
        }
        doc.to_string()
    }

    /// The layout read from `text`.
    ///
    /// # Errors
    ///
    /// The text is not TOML, or not a layout: the shown tab's tree's panes
    /// are not the panes listed, each once (another tab that is not a
    /// layout is skipped).
    pub fn from_toml(text: &str) -> Result<Self, String> {
        let doc: DocumentMut = text.parse().map_err(|e| format!("{e}"))?;
        let mut shown = read_split(doc.as_table())?;
        if doc.get("console").and_then(Item::as_bool) == Some(true) {
            console_from_dock(&mut shown.layout);
        }
        let others: Vec<SavedSplit> = doc
            .get("other")
            .and_then(Item::as_array_of_tables)
            .into_iter()
            .flat_map(ArrayOfTables::iter)
            .filter_map(|table| read_split(table).ok())
            .collect();
        #[expect(clippy::cast_possible_truncation, reason = "a width in pixels")]
        let width = |key: &str| {
            doc.get(key)
                .and_then(Item::as_float)
                .map(|w| w as f32)
                .filter(|w| w.is_finite() && *w > 0.0)
        };
        Ok(Self {
            layout: shown.layout,
            sidebar_width: width("sidebar").ok_or("no sidebar width")?,
            dock_width: width("dock"),
            hex_sides: shown.hex_sides,
            places: shown.places,
            shown: doc
                .get("shown")
                .and_then(Item::as_integer)
                .and_then(|s| usize::try_from(s).ok())
                .unwrap_or(0)
                .min(others.len()),
            others,
        })
    }

    /// Writes the layout to `path` crash-safely (a temporary file, synced,
    /// renamed over it).
    ///
    /// # Errors
    ///
    /// The file cannot be written.
    pub fn save(&self, path: &Path) -> Result<(), String> {
        crash_safe::write(path, self.to_toml().as_bytes())
            .map_err(|e| format!("{}: {e}", path.display()))
    }

    /// The layout saved at `path`; `None` if there is none, or it is of
    /// another [`FORMAT`] (written before: not read).
    ///
    /// # Errors
    ///
    /// The file is there but cannot be read or is not a layout.
    pub fn load(path: &Path) -> Result<Option<Self>, String> {
        match std::fs::read_to_string(path) {
            Ok(text) if format_of(&text) != Some(FORMAT) => Ok(None),
            Ok(text) => Self::from_toml(&text)
                .map(Some)
                .map_err(|e| format!("{}: {e}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(format!("{}: {e}", path.display())),
        }
    }
}

/// The format a layout's `text` says it is in, if it says (a file written
/// before formats were says none).
fn format_of(text: &str) -> Option<i64> {
    let doc: DocumentMut = text.parse().ok()?;
    doc.get("format").and_then(Item::as_integer)
}

/// Writes a window tab's split into `table`: its focused pane, its tree,
/// its panes with their tabs and places.
fn write_split(
    table: &mut Table,
    layout: &Layout<SavedTab>,
    hex_sides: &[(PaneId, f32)],
    places: &HashMap<TabId, SavedPlace>,
) {
    table.insert("focused", toml_edit::value(i64::from(layout.focused().0)));
    table.insert("tree", Item::Value(node_value(layout.tree())));
    let mut panes = ArrayOfTables::new();
    for pane in layout.panes() {
        let mut entry = Table::new();
        entry.insert("id", toml_edit::value(i64::from(pane.id.0)));
        entry.insert("active", toml_edit::value(index(pane.active)));
        entry.insert("synced", toml_edit::value(pane.synced));
        if let Some(&(_, share)) = hex_sides.iter().find(|(id, _)| *id == pane.id) {
            entry.insert("hex_side", toml_edit::value(rounded(share)));
        }
        let tabs: Array = pane
            .tabs
            .iter()
            .map(|tab| {
                let mut value = tab_value(tab);
                if let (Value::InlineTable(table), Some(place)) =
                    (&mut value, places.get(&tab.id()))
                {
                    place_value(table, place);
                }
                value
            })
            .collect();
        entry.insert("tabs", Item::Value(Value::Array(tabs)));
        panes.push(entry);
    }
    table.insert("pane", Item::ArrayOfTables(panes));
}

/// The console of a file written while it was a dock under the panes, as
/// a tab under the code: in the pane of lists if there is one, else in a
/// new pane under the focused one; the focus kept.
fn console_from_dock(layout: &mut Layout<SavedTab>) {
    if layout
        .panes()
        .any(|p| p.tabs.iter().any(|t| t.content == SavedTab::Console))
    {
        return;
    }
    let focused = layout.focused();
    let lists = layout
        .panes()
        .find(|p| {
            !p.tabs.is_empty()
                && p.tabs.iter().all(|t| {
                    matches!(
                        t.content,
                        SavedTab::Strings | SavedTab::Xrefs { .. } | SavedTab::Folder(_)
                    )
                })
        })
        .map(|p| p.id);
    match lists {
        Some(pane) => layout.open(pane, SavedTab::Console, false),
        None => {
            layout.split(focused, Axis::Column, SavedTab::Console);
        }
    }
    layout.focus(focused);
}

/// A window tab's split read from `table` (the file's top level, or an
/// `[[other]]`).
///
/// # Errors
///
/// No tree, a pane without an id, or the tree's panes are not the panes
/// listed, each once.
fn read_split(table: &Table) -> Result<SavedSplit, String> {
    let tree = table
        .get("tree")
        .and_then(Item::as_table_like)
        .and_then(read_node)
        .ok_or("no tree")?;
    let mut panes = Vec::new();
    let mut hex_sides = Vec::new();
    // Each tab with a place read: its pane and its index there.
    let mut read_places = Vec::new();
    for entry in table
        .get("pane")
        .and_then(Item::as_array_of_tables)
        .into_iter()
        .flat_map(ArrayOfTables::iter)
    {
        let id = entry
            .get("id")
            .and_then(Item::as_integer)
            .and_then(|id| u32::try_from(id).ok())
            .map(PaneId)
            .ok_or("a pane without an id")?;
        let mut tabs = Vec::new();
        for value in entry
            .get("tabs")
            .and_then(Item::as_array)
            .into_iter()
            .flat_map(Array::iter)
        {
            if let Some((tab, place)) = value
                .as_inline_table()
                .and_then(|tab| Some((read_tab(tab)?, read_place(tab))))
            {
                read_places.extend(place.map(|place| (id, tabs.len(), place)));
                tabs.push(tab);
            }
        }
        if let Some(share) = entry.get("hex_side").and_then(Item::as_float) {
            #[expect(clippy::cast_possible_truncation, reason = "a share of one")]
            hex_sides.push((id, share as f32));
        }
        panes.push(Pane {
            id,
            tabs,
            active: entry
                .get("active")
                .and_then(Item::as_integer)
                .and_then(|a| usize::try_from(a).ok())
                .unwrap_or(0),
            synced: entry.get("synced").and_then(Item::as_bool).unwrap_or(true),
        });
    }
    let focused = table
        .get("focused")
        .and_then(Item::as_integer)
        .and_then(|f| u32::try_from(f).ok())
        .map_or(PaneId(0), PaneId);
    let layout =
        Layout::from_parts(tree, panes, focused).ok_or("the tree's panes are not the panes")?;
    let places = resolve_places(&layout, &read_places);
    Ok(SavedSplit {
        layout,
        hex_sides,
        places,
    })
}

/// `v` to four decimals, as written (`0.3`, not `0.30000001192092896`).
fn rounded(v: f32) -> f64 {
    (f64::from(v) * 1e4).round() / 1e4
}

/// `i` as a TOML integer.
fn index(i: usize) -> i64 {
    i64::try_from(i).unwrap_or(i64::MAX)
}

/// An address as written: `0x` and upper-case hexadecimal.
fn address(a: u64) -> Value {
    Value::from(format!("0x{a:X}"))
}

/// An address read back.
fn read_address(value: &Value) -> Option<u64> {
    u64::from_str_radix(value.as_str()?.trim_start_matches("0x"), 16).ok()
}

/// A split's axis as written.
fn axis_name(axis: Axis) -> &'static str {
    match axis {
        Axis::Row => "row",
        Axis::Column => "column",
    }
}

/// `node` as an inline table: `{ pane = N }`, or `{ split = "row",
/// sizes = [..], children = [..] }`.
fn node_value(node: &Node) -> Value {
    let mut table = InlineTable::new();
    match node {
        Node::Pane(id) => {
            table.insert("pane", Value::from(i64::from(id.0)));
        }
        Node::Split {
            axis,
            children,
            sizes,
        } => {
            table.insert("split", Value::from(axis_name(*axis)));
            let sizes: Array = sizes.iter().map(|&s| rounded(s)).collect();
            table.insert("sizes", Value::Array(sizes));
            let children: Array = children.iter().map(node_value).collect();
            table.insert("children", Value::Array(children));
        }
    }
    Value::InlineTable(table)
}

/// A node read back; `None` if it is neither a pane nor a split.
fn read_node(table: &dyn TableLike) -> Option<Node> {
    if let Some(id) = table.get("pane").and_then(Item::as_integer) {
        return Some(Node::Pane(PaneId(u32::try_from(id).ok()?)));
    }
    let axis = match table.get("split").and_then(Item::as_str)? {
        "row" => Axis::Row,
        "column" => Axis::Column,
        _ => return None,
    };
    let children = table
        .get("children")
        .and_then(Item::as_array)?
        .iter()
        .map(|child| read_node(child.as_inline_table()?))
        .collect::<Option<Vec<_>>>()?;
    #[expect(clippy::cast_possible_truncation, reason = "shares of one")]
    let sizes = table
        .get("sizes")
        .and_then(Item::as_array)
        .map(|sizes| {
            sizes
                .iter()
                .filter_map(Value::as_float)
                .map(|s| s as f32)
                .collect()
        })
        .unwrap_or_default();
    Some(Node::Split {
        axis,
        children,
        sizes,
    })
}

/// A tab as an inline table: its kind, what it shows, whether it is a
/// preview.
fn tab_value(tab: &Tab<SavedTab>) -> Value {
    let mut table = InlineTable::new();
    match &tab.content {
        SavedTab::Listing => {
            table.insert("kind", Value::from("listing"));
        }
        SavedTab::C { entry, view } => {
            table.insert("kind", Value::from("c"));
            if let Some(entry) = entry {
                table.insert("entry", address(*entry));
            }
            let view = match view {
                View::Reading => "reading",
                View::Exact => "exact",
            };
            table.insert("view", Value::from(view));
        }
        SavedTab::Strings => {
            table.insert("kind", Value::from("strings"));
        }
        SavedTab::Xrefs { of, len } => {
            table.insert("kind", Value::from("xrefs"));
            table.insert("of", address(*of));
            table.insert("len", Value::from(i64::try_from(*len).unwrap_or(i64::MAX)));
        }
        SavedTab::Folder(key) => {
            table.insert("kind", Value::from("folder"));
            table.insert("key", Value::from(key.as_str()));
        }
        SavedTab::Console => {
            table.insert("kind", Value::from("console"));
        }
    }
    if tab.preview {
        table.insert("preview", Value::from(true));
    }
    Value::InlineTable(table)
}

/// A tab read back; `None` if its kind is unknown or it misses what it
/// shows.
fn read_tab(table: &InlineTable) -> Option<Tab<SavedTab>> {
    let content = match table.get("kind")?.as_str()? {
        "listing" => SavedTab::Listing,
        "c" => SavedTab::C {
            entry: match table.get("entry") {
                Some(entry) => Some(read_address(entry)?),
                None => None,
            },
            view: match table.get("view").and_then(Value::as_str)? {
                "reading" => View::Reading,
                "exact" => View::Exact,
                _ => return None,
            },
        },
        "strings" => SavedTab::Strings,
        "xrefs" => SavedTab::Xrefs {
            of: read_address(table.get("of")?)?,
            len: u64::try_from(table.get("len")?.as_integer()?).ok()?,
        },
        "folder" => SavedTab::Folder(table.get("key")?.as_str()?.to_owned()),
        "console" => SavedTab::Console,
        _ => return None,
    };
    let preview = table
        .get("preview")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    Some(Tab::new(content, preview))
}

/// A tab's place written into its inline table: `at`, `graph = true`,
/// its graph's zoom and pan.
fn place_value(table: &mut InlineTable, place: &SavedPlace) {
    if let Some(at) = place.at {
        table.insert("at", address(at));
    }
    if place.graph {
        table.insert("graph", Value::from(true));
    }
    if let Some(zoom) = place.zoom {
        table.insert("zoom", Value::from(rounded(zoom)));
    }
    if let Some(pan) = place.pan {
        let mut at = InlineTable::new();
        at.insert("entry", address(pan.entry));
        at.insert("x", Value::from(rounded(pan.x)));
        at.insert("y", Value::from(rounded(pan.y)));
        table.insert("pan", Value::InlineTable(at));
    }
    if place.unified {
        table.insert("unified", Value::from(true));
    }
    let view = &place.unified_view;
    if view.layers != Layers::default() {
        let mut layers = InlineTable::new();
        layers.insert("bytes", Value::from(view.layers.bytes));
        layers.insert("hex", Value::from(view.layers.hex));
        layers.insert("structure", Value::from(view.layers.structure));
        table.insert("layers", Value::InlineTable(layers));
    }
    if !view.folds.is_empty() {
        let folds: Array = view.folds.iter().map(|&f| fold_text(f)).collect();
        table.insert("folds", Value::Array(folds));
    }
    if !view.expanded.is_empty() {
        let rows: Array = view.expanded.iter().map(expanded_text).collect();
        table.insert("expanded", Value::Array(rows));
    }
}

/// A tree's expanded row as written: its overlay's place (`a` an address,
/// `f` a file offset) and each step (`m` a member, `c` a chunk, `e` an
/// element, `b` a bit-field), `a0x404040/m0/e3`.
fn expanded_text(row: &Expanded) -> String {
    let mut text = match row.anchor {
        Anchor::Address(at) => format!("a0x{at:X}"),
        Anchor::File(at) => format!("f0x{at:X}"),
    };
    for step in &row.steps {
        let _ = match step {
            Step::Member(i) => write!(text, "/m{i}"),
            Step::Chunk(i) => write!(text, "/c{i}"),
            Step::Element(i) => write!(text, "/e{i}"),
            Step::Bit(i) => write!(text, "/b{i}"),
        };
    }
    text
}

/// A tree's expanded row read back ([`expanded_text`]); `None` if it does
/// not read.
fn read_expanded(text: &str) -> Option<Expanded> {
    let mut parts = text.split('/');
    let place = parts.next()?;
    let at = |s: &str| u64::from_str_radix(s.strip_prefix("0x")?, 16).ok();
    let anchor = match place.split_at_checked(1)? {
        ("a", rest) => Anchor::Address(at(rest)?),
        ("f", rest) => Anchor::File(at(rest)?),
        _ => return None,
    };
    let steps = parts
        .map(|step| {
            let (kind, n) = step.split_at_checked(1)?;
            Some(match kind {
                "m" => Step::Member(n.parse().ok()?),
                "c" => Step::Chunk(n.parse().ok()?),
                "e" => Step::Element(n.parse().ok()?),
                "b" => Step::Bit(n.parse().ok()?),
                _ => return None,
            })
        })
        .collect::<Option<Vec<Step>>>()?;
    Some(Expanded { anchor, steps })
}

/// A fold as written: its kind's letter and where it starts (`f:0x401000`;
/// an item's file offset and address, `i:0x40:0x400040`).
fn fold_text(fold: Fold) -> String {
    match fold {
        Fold::Item(offset, None) => format!("i:0x{offset:X}"),
        Fold::Item(offset, Some(address)) => format!("i:0x{offset:X}:0x{address:X}"),
        Fold::Function(address) => format!("f:0x{address:X}"),
        Fold::Bytes(offset) => format!("x:0x{offset:X}"),
        Fold::Block(address) => format!("b:0x{address:X}"),
    }
}

/// A fold read back ([`fold_text`]); `None` if it does not read.
fn read_fold(text: &str) -> Option<Fold> {
    let number = |s: &str| u64::from_str_radix(s.strip_prefix("0x")?, 16).ok();
    let mut parts = text.split(':');
    let kind = parts.next()?;
    let first = number(parts.next()?)?;
    let second = parts.next().map(number);
    if parts.next().is_some() {
        return None;
    }
    Some(match (kind, second) {
        ("i", None) => Fold::Item(first, None),
        ("i", Some(address)) => Fold::Item(first, Some(address?)),
        ("f", None) => Fold::Function(first),
        ("x", None) => Fold::Bytes(first),
        ("b", None) => Fold::Block(first),
        _ => return None,
    })
}

/// A tab's place read back; `None` if it has none of it. A graph's zoom or
/// pan that does not read is left out.
fn read_place(table: &InlineTable) -> Option<SavedPlace> {
    let at = table.get("at").and_then(read_address);
    let graph = table.get("graph").and_then(Value::as_bool).unwrap_or(false);
    #[expect(clippy::cast_possible_truncation, reason = "graph units, as written")]
    let float = |value: Option<&Value>| {
        value
            .and_then(Value::as_float)
            .map(|v| v as f32)
            .filter(|v| v.is_finite())
    };
    let zoom = float(table.get("zoom")).filter(|&z| z > 0.0);
    let pan = table
        .get("pan")
        .and_then(Value::as_inline_table)
        .and_then(|pan| {
            Some(Pan {
                entry: read_address(pan.get("entry")?)?,
                x: float(pan.get("x"))?,
                y: float(pan.get("y"))?,
                followed: None,
            })
        });
    let unified = table
        .get("unified")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let layers = table
        .get("layers")
        .and_then(Value::as_inline_table)
        .map_or_else(Layers::default, |layers| {
            let on = |name: &str, default: bool| {
                layers.get(name).and_then(Value::as_bool).unwrap_or(default)
            };
            let all = Layers::default();
            Layers {
                bytes: on("bytes", all.bytes),
                hex: on("hex", all.hex),
                structure: on("structure", all.structure),
            }
        });
    let folds = table
        .get("folds")
        .and_then(Value::as_array)
        .into_iter()
        .flat_map(Array::iter)
        .filter_map(|f| read_fold(f.as_str()?))
        .collect();
    let expanded = table
        .get("expanded")
        .and_then(Value::as_array)
        .into_iter()
        .flat_map(Array::iter)
        .filter_map(|row| read_expanded(row.as_str()?))
        .collect();
    let place = SavedPlace {
        at,
        graph,
        zoom,
        pan,
        unified,
        unified_view: UnifiedView {
            layers,
            folds,
            expanded,
        },
    };
    (place != SavedPlace::default()).then_some(place)
}

/// The places read (`read`: each tab's pane, index there and place) by the
/// tabs' identities in `layout`.
fn resolve_places(
    layout: &Layout<SavedTab>,
    read: &[(PaneId, usize, SavedPlace)],
) -> HashMap<TabId, SavedPlace> {
    let tab_at = |pane: PaneId, index: usize| {
        layout
            .pane(pane)
            .and_then(|p| p.tabs.get(index))
            .map(Tab::id)
    };
    read.iter()
        .filter_map(|(pane, index, place)| Some((tab_at(*pane, *index)?, place.clone())))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Listing | (C of 0x401000 / Strings, Xrefs, the console), sized, the
    /// C pane unsynced, a hex side area dragged.
    fn saved() -> SavedLayout {
        let mut layout = Layout::new(SavedTab::Listing);
        let c = layout
            .split(
                PaneId(0),
                Axis::Row,
                SavedTab::C {
                    entry: Some(0x40_1000),
                    view: View::Reading,
                },
            )
            .unwrap();
        layout.pane_mut(c).unwrap().synced = false;
        let lists = layout.split(c, Axis::Column, SavedTab::Strings).unwrap();
        layout.open(
            lists,
            SavedTab::Xrefs {
                of: 0x40_2000,
                len: 8,
            },
            true,
        );
        layout.open(
            lists,
            SavedTab::C {
                entry: None,
                view: View::Exact,
            },
            false,
        );
        layout.open(lists, SavedTab::Console, false);
        layout.activate(lists, 1);
        layout.drag_divider(&[], 1, 30.0, 100.0, 0.0);
        layout.drag_divider(&[1], 1, 75.0, 100.0, 0.0);
        layout.focus(c);
        SavedLayout {
            layout,
            sidebar_width: 312.0,
            dock_width: Some(380.5),
            hex_sides: vec![(PaneId(0), 0.35)],
            places: HashMap::new(),
            others: Vec::new(),
            shown: 0,
        }
    }

    fn tabs(layout: &Layout<SavedTab>, id: u32) -> Vec<(SavedTab, bool)> {
        layout
            .pane(PaneId(id))
            .unwrap()
            .tabs
            .iter()
            .map(|t| (t.content.clone(), t.preview))
            .collect()
    }

    /// Whether `a` and `b` are the same tree, their sizes within 1e-4.
    fn same_tree(a: &Node, b: &Node) -> bool {
        match (a, b) {
            (Node::Pane(x), Node::Pane(y)) => x == y,
            (
                Node::Split {
                    axis: a1,
                    children: c1,
                    sizes: s1,
                },
                Node::Split {
                    axis: a2,
                    children: c2,
                    sizes: s2,
                },
            ) => {
                a1 == a2
                    && c1.len() == c2.len()
                    && s1.len() == s2.len()
                    && s1.iter().zip(s2).all(|(x, y)| (x - y).abs() < 1e-4)
                    && c1.iter().zip(c2).all(|(x, y)| same_tree(x, y))
            }
            (Node::Pane(_), Node::Split { .. }) | (Node::Split { .. }, Node::Pane(_)) => false,
        }
    }

    #[test]
    fn a_layout_round_trips() {
        let before = saved();
        let text = before.to_toml();
        let after = SavedLayout::from_toml(&text).unwrap();
        assert!(same_tree(after.layout.tree(), before.layout.tree()));
        assert_eq!(after.layout.focused(), PaneId(1));
        for id in 0..3 {
            assert_eq!(tabs(&after.layout, id), tabs(&before.layout, id));
            let (one, two) = (
                after.layout.pane(PaneId(id)).unwrap(),
                before.layout.pane(PaneId(id)).unwrap(),
            );
            assert_eq!((one.active, one.synced), (two.active, two.synced));
        }
        assert_eq!(after.layout.pane(PaneId(2)).unwrap().active, 1);
        assert!(!after.layout.pane(PaneId(1)).unwrap().synced);
        assert!((after.sidebar_width - 312.0).abs() < 1e-3);
        assert!((after.dock_width.unwrap() - 380.5).abs() < 1e-3);
        assert_eq!(after.hex_sides.len(), 1);
        assert!((after.hex_sides[0].1 - 0.35).abs() < 1e-4);
        // Written again, the same text.
        assert_eq!(after.to_toml(), text);

        // Through a file.
        let dir = std::env::temp_dir().join(format!("binbun-layout-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = binbun_session::Project::new(&dir).layout();
        assert!(SavedLayout::load(&path).unwrap().is_none());
        before.save(&path).unwrap();
        let loaded = SavedLayout::load(&path).unwrap().unwrap();
        assert_eq!(loaded.to_toml(), text);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn other_window_tabs_round_trip_around_the_shown_one() {
        let mut before = saved();
        let other = |entry: u64, first: u32| {
            let layout = Layout::new(SavedTab::C {
                entry: Some(entry),
                view: View::Reading,
            });
            let (layout, _) = layout.copied(first, |_| true).unwrap();
            let tab = layout.active_tab(PaneId(first)).unwrap();
            let place = SavedPlace {
                at: Some(entry + 0x10),
                ..SavedPlace::default()
            };
            SavedSplit {
                layout,
                hex_sides: Vec::new(),
                places: HashMap::from([(tab, place)]),
            }
        };
        before.others = vec![other(0x40_3000, 10), other(0x40_4000, 20)];
        before.shown = 1;
        let text = before.to_toml();
        let after = SavedLayout::from_toml(&text).unwrap();
        assert_eq!(after.shown, 1);
        assert_eq!(after.others.len(), 2);
        for (one, (two, first)) in after.others.iter().zip(before.others.iter().zip([10, 20])) {
            assert_eq!(tabs(&one.layout, first), tabs(&two.layout, first));
            let tab = one.layout.active_tab(PaneId(first)).unwrap();
            assert_eq!(
                one.places.get(&tab).and_then(|p| p.at),
                two.places.values().next().and_then(|p| p.at)
            );
        }
        // The shown tab is the top level, as in a file of one tab.
        assert_eq!(tabs(&after.layout, 0), tabs(&before.layout, 0));
        assert_eq!(after.to_toml(), text);
        // A file of one tab: no others, shown first.
        let one = SavedLayout::from_toml(&saved().to_toml()).unwrap();
        assert!(one.others.is_empty() && one.shown == 0);
        // Another tab that is no layout is skipped; `shown` stays in range.
        let broken = text.replacen(
            "[[other]]\nfocused = 10\ntree = { pane = 10 }",
            "[[other]]\nfocused = 10\ntree = { pane = 99 }",
            1,
        );
        assert_ne!(broken, text);
        let read = SavedLayout::from_toml(&broken).unwrap();
        assert_eq!((read.others.len(), read.shown), (1, 1));
    }

    #[test]
    fn a_stale_tab_is_skipped() {
        let saved = SavedLayout::from_toml(&saved().to_toml()).unwrap();
        // The function at 0x401000 is gone: its tab is dropped and its
        // pane, left empty, closes; its space goes to its neighbour.
        let restored = saved.layout.map_tabs(|tab| match tab {
            SavedTab::C {
                entry: Some(0x40_1000),
                ..
            } => None,
            other @ (SavedTab::Listing
            | SavedTab::C { .. }
            | SavedTab::Strings
            | SavedTab::Xrefs { .. }
            | SavedTab::Folder(_)
            | SavedTab::Console) => Some(other.clone()),
        });
        let ids: Vec<u32> = restored.panes().map(|p| p.id.0).collect();
        assert_eq!(ids, vec![0, 2]);
        // The focus was on it: the pane that took its place has it.
        assert_eq!(restored.focused(), PaneId(2));
        assert_eq!(
            tabs(&restored, 2),
            vec![
                (SavedTab::Strings, false),
                (
                    SavedTab::Xrefs {
                        of: 0x40_2000,
                        len: 8
                    },
                    true
                ),
                (
                    SavedTab::C {
                        entry: None,
                        view: View::Exact
                    },
                    false
                ),
                (SavedTab::Console, false),
            ]
        );
        assert_eq!(restored.pane(PaneId(2)).unwrap().active, 1);
        match restored.tree() {
            Node::Split { sizes, .. } => {
                assert!((sizes[0] - 0.3).abs() < 1e-4 && (sizes[1] - 0.7).abs() < 1e-4);
            }
            Node::Pane(_) => panic!("a split"),
        }
    }

    #[test]
    fn unreadable_entries_are_skipped_and_bad_layouts_refused() {
        let text = r#"
focused = 9
sidebar = 240.0
tree = { split = "row", sizes = [1.0, 1.0], children = [{ pane = 0 }, { pane = 1 }] }

[[pane]]
id = 0
tabs = [{ kind = "listing" }, { kind = "settings" }, { kind = "c", view = "sideways" }]

[[pane]]
id = 1
active = 4
tabs = [{ kind = "xrefs", of = "0x10" }, { kind = "strings", preview = true }]
"#;
        let saved = SavedLayout::from_toml(text).unwrap();
        // Unknown kinds and tabs missing what they show are dropped; the
        // active tab clamped; the focus on a pane that exists.
        assert_eq!(tabs(&saved.layout, 0), vec![(SavedTab::Listing, false)]);
        assert_eq!(tabs(&saved.layout, 1), vec![(SavedTab::Strings, true)]);
        assert_eq!(saved.layout.pane(PaneId(1)).unwrap().active, 0);
        assert_eq!(saved.layout.focused(), PaneId(0));
        assert!(saved.dock_width.is_none());
        // Written before tabs kept places: none.
        assert!(saved.places.is_empty(), "{:?}", saved.places);
        match saved.layout.tree() {
            Node::Split { sizes, .. } => assert_eq!(sizes, &vec![0.5, 0.5]),
            Node::Pane(_) => panic!("a split"),
        }

        // A tree naming a pane not listed; no tree; not TOML.
        let missing = text.replace("{ pane = 1 }", "{ pane = 2 }");
        assert!(SavedLayout::from_toml(&missing).is_err());
        assert!(SavedLayout::from_toml("sidebar = 1.0").is_err());
        assert!(SavedLayout::from_toml("tree = [").is_err());
    }

    #[test]
    fn places_and_a_graph_round_trip() {
        let mut before = saved();
        let source = before.layout.active_tab(PaneId(0)).unwrap();
        let c = before.layout.active_tab(PaneId(1)).unwrap();
        // A graph in the lists' pane, behind.
        let graph = before
            .layout
            .open_new(PaneId(2), SavedTab::Listing, false)
            .unwrap();
        // The unified listing, a layer off, folds of each kind flipped.
        let listing = SavedPlace {
            at: Some(0x40_1010),
            unified: true,
            unified_view: UnifiedView {
                layers: Layers {
                    bytes: false,
                    ..Layers::default()
                },
                folds: vec![
                    Fold::Item(0x40, None),
                    Fold::Item(0x1000, Some(0x40_1000)),
                    Fold::Function(0x40_1000),
                    Fold::Bytes(0x2000),
                    Fold::Block(0x40_1020),
                ],
                expanded: vec![
                    Expanded {
                        anchor: Anchor::File(0),
                        steps: vec![Step::Member(2), Step::Chunk(1), Step::Element(3)],
                    },
                    Expanded {
                        anchor: Anchor::Address(0x40_4040),
                        steps: vec![Step::Member(0), Step::Bit(4)],
                    },
                ],
            },
            ..SavedPlace::default()
        };
        // A graph zoomed out and panned on its function.
        let following = SavedPlace {
            at: Some(0x40_1010),
            graph: true,
            zoom: Some(0.625),
            pan: Some(Pan {
                entry: 0x40_1000,
                x: -40.25,
                y: 1312.5,
                followed: None,
            }),
            ..SavedPlace::default()
        };
        let in_c = SavedPlace {
            at: Some(0x40_1004),
            ..SavedPlace::default()
        };
        before.places.insert(source, listing.clone());
        before.places.insert(graph, following.clone());
        before.places.insert(c, in_c.clone());
        let text = before.to_toml();
        let after = SavedLayout::from_toml(&text).unwrap();
        let tab =
            |pane: u32, index: usize| after.layout.pane(PaneId(pane)).unwrap().tabs[index].id();
        let (source, graph, c) = (tab(0, 0), tab(2, 2), tab(1, 0));
        assert_eq!(after.places.len(), 3);
        assert_eq!(after.places.get(&source), Some(&listing));
        assert_eq!(after.places.get(&graph), Some(&following));
        assert_eq!(after.places.get(&c), Some(&in_c));
        assert_eq!(after.to_toml(), text);
        // Where its graph was left reads back, and one not reading (a
        // zoom that is no zoom, a pan without its function) is left out.
        let broken = text
            .replace("zoom = 0.625", "zoom = -1.0")
            .replace("entry = \"0x401000\", ", "");
        assert_ne!(broken, text);
        let partly = SavedLayout::from_toml(&broken).unwrap();
        let kept = partly.places.get(&graph).unwrap();
        assert_eq!((kept.zoom, kept.pan), (None, None));
        assert_eq!(kept.at, Some(0x40_1010));
        // A fold that does not read is left out, the others kept.
        let odd = text.replace("\"f:0x401000\"", "\"q:0x401000\"");
        assert_ne!(odd, text);
        let partly = SavedLayout::from_toml(&odd).unwrap();
        let folds = &partly.places.get(&source).unwrap().unified_view.folds;
        assert_eq!(folds.len(), 4);
        assert!(!folds.contains(&Fold::Function(0x40_1000)));

        // Restored, the tabs keep their identities (and so their places).
        let restored = after.layout.map_tabs(|t| Some(t.clone()));
        assert_eq!(restored.pane(PaneId(2)).unwrap().tabs[2].id(), graph);
    }

    #[test]
    fn a_layout_of_another_format_is_not_read() {
        let dir = std::env::temp_dir().join(format!("binbun-layout-format-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("layout.toml");
        let text = saved().to_toml();
        assert!(text.starts_with("format = 2\n"), "{text}");
        std::fs::write(&path, &text).unwrap();
        assert!(SavedLayout::load(&path).unwrap().is_some());
        // Written before panes were views: no format, not read.
        std::fs::write(&path, text.replacen("format = 2\n", "", 1)).unwrap();
        assert!(SavedLayout::load(&path).unwrap().is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn two_tabs_of_the_listing_keep_their_own_views() {
        let mut before = saved();
        let pane = PaneId(0);
        let text = before.layout.active_tab(pane).unwrap();
        let graph = before
            .layout
            .open_new(pane, SavedTab::Listing, false)
            .unwrap();
        before.places.insert(
            text,
            SavedPlace {
                at: Some(0x40_1000),
                ..SavedPlace::default()
            },
        );
        before.places.insert(
            graph,
            SavedPlace {
                at: Some(0x40_1010),
                graph: true,
                ..SavedPlace::default()
            },
        );
        let toml = before.to_toml();
        let after = SavedLayout::from_toml(&toml).unwrap();
        let tab =
            |after: &SavedLayout, index: usize| after.layout.pane(pane).unwrap().tabs[index].id();
        let view = |after: &SavedLayout, index: usize| {
            after.places.get(&tab(after, index)).map(|p| p.graph)
        };
        assert_eq!(view(&after, 0), Some(false), "the first a listing");
        assert_eq!(view(&after, 1), Some(true), "the second a graph");
        // A file written before views were saved: every tab a listing.
        let old = toml.replace(", graph = true", "");
        assert_ne!(old, toml);
        let after = SavedLayout::from_toml(&old).unwrap();
        assert_eq!(view(&after, 1), Some(false));
    }

    #[test]
    fn tabs_moved_around_are_restored_where_they_were_put_with_their_places() {
        use crate::layout::{Direction, TabDrop};
        let mut before = saved();
        // The Xrefs tab dragged to the listing's pane, first; the strings
        // to a new pane below the C, following nothing but placed.
        let xrefs = before.layout.pane(PaneId(2)).unwrap().tabs[1].id();
        let strings = before.layout.pane(PaneId(2)).unwrap().tabs[0].id();
        before
            .layout
            .move_tab(
                xrefs,
                TabDrop::Into {
                    pane: PaneId(0),
                    at: 0,
                },
            )
            .unwrap();
        let below = before
            .layout
            .move_tab(
                strings,
                TabDrop::Edge {
                    pane: PaneId(1),
                    side: Direction::Down,
                },
            )
            .unwrap();
        let listing = before.layout.pane(PaneId(0)).unwrap().tabs[1].id();
        let place = SavedPlace {
            at: Some(0x40_2020),
            ..SavedPlace::default()
        };
        before.places.insert(listing, place.clone());
        let text = before.to_toml();
        let after = SavedLayout::from_toml(&text).unwrap();
        assert!(same_tree(after.layout.tree(), before.layout.tree()));
        for pane in before.layout.panes() {
            assert_eq!(
                tabs(&after.layout, pane.id.0),
                tabs(&before.layout, pane.id.0)
            );
        }
        // The Xrefs tab, moved, no preview any more.
        assert_eq!(
            tabs(&after.layout, 0),
            vec![
                (
                    SavedTab::Xrefs {
                        of: 0x40_2000,
                        len: 8
                    },
                    false
                ),
                (SavedTab::Listing, false)
            ]
        );
        assert_eq!(
            tabs(&after.layout, below.0),
            vec![(SavedTab::Strings, false)]
        );
        let listing = after.layout.pane(PaneId(0)).unwrap().tabs[1].id();
        assert_eq!(after.places.get(&listing), Some(&place));
    }

    #[test]
    fn a_folder_tab_keeps_its_key_and_one_without_is_skipped() {
        let mut before = saved();
        let key = "/functions/std::vector<int, \"a\">".to_owned();
        before
            .layout
            .open(PaneId(0), SavedTab::Folder(key.clone()), false);
        let text = before.to_toml();
        let after = SavedLayout::from_toml(&text).unwrap();
        assert_eq!(
            tabs(&after.layout, 0),
            vec![(SavedTab::Listing, false), (SavedTab::Folder(key), false)]
        );
        // A folder tab missing its key is dropped, the rest kept.
        let broken = text.replacen("kind = \"folder\", key = ", "kind = \"folder\", name = ", 1);
        assert_ne!(broken, text);
        let read = SavedLayout::from_toml(&broken).unwrap();
        assert_eq!(tabs(&read.layout, 0), vec![(SavedTab::Listing, false)]);
    }

    /// A file written while the console was a dock under the panes
    /// (`console = true`) has it as a tab under the code: in a new pane
    /// under the focused one, else in the pane of lists; the focus stays,
    /// and the file written again has no dock.
    #[test]
    fn a_docked_console_comes_back_as_a_tab_under_the_code() {
        let alone = r#"
format = 2
focused = 0
sidebar = 240.0
console = true
console_height = 300.0
tree = { pane = 0 }

[[pane]]
id = 0
tabs = [{ kind = "listing" }]
"#;
        let saved = SavedLayout::from_toml(alone).unwrap();
        let ids: Vec<u32> = saved.layout.panes().map(|p| p.id.0).collect();
        assert_eq!(ids.len(), 2, "{ids:?}");
        assert_eq!(
            tabs(&saved.layout, ids[1]),
            vec![(SavedTab::Console, false)]
        );
        assert!(matches!(
            saved.layout.tree(),
            Node::Split {
                axis: Axis::Column,
                ..
            }
        ));
        assert_eq!(saved.layout.focused(), PaneId(0));
        let again = saved.to_toml();
        assert!(!again.contains("console =") && !again.contains("console_height"));
        assert!(again.contains("kind = \"console\""), "{again}");

        let lists = r#"
format = 2
focused = 0
sidebar = 240.0
console = true
tree = { split = "column", sizes = [0.7, 0.3], children = [{ pane = 0 }, { pane = 1 }] }

[[pane]]
id = 0
tabs = [{ kind = "listing" }]

[[pane]]
id = 1
tabs = [{ kind = "strings" }]
"#;
        let saved = SavedLayout::from_toml(lists).unwrap();
        assert_eq!(saved.layout.panes().count(), 2);
        assert_eq!(
            tabs(&saved.layout, 1),
            vec![(SavedTab::Strings, false), (SavedTab::Console, false)]
        );
        assert_eq!(saved.layout.focused(), PaneId(0));
    }
}
