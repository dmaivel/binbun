//! The hex view's structure tree: each overlay a root, its records,
//! unions and arrays collapsing and expanding (a file tree's keys: Left
//! and Right collapse and expand, Up and Down move), bit-fields as
//! children with their bit
//! ranges, a large array's elements in chunks of [`CHUNK`] so a
//! 10,000-entry table opens as a hundred rows. A row selects its bytes; a
//! byte selects its deepest row ([`deepest`]), the tree expanded to it.
//!
//! ```
//! use binbun_gui_view::hex::{Anchor, user_overlay};
//! use binbun_gui_view::hex_tree::{StructTree, Step, deepest};
//! use binbun_gui_view::hex_types::{DataModel, TypeSet};
//!
//! let mut types = TypeSet::new(DataModel::LP64);
//! let text = "struct p { int x; short y[300]; }";
//! let overlays = [user_overlay(Anchor::Address(0x1000), types.apply(text).unwrap(), text)];
//! let mut tree = StructTree::default();
//! assert_eq!(tree.lines(&overlays).len(), 1);
//! // Byte 4 + 2 * 250 is `y[250]`, in the third chunk.
//! let key = deepest(&overlays, 0, 4 + 2 * 250).unwrap();
//! assert_eq!(key.steps, [Step::Member(1), Step::Chunk(2), Step::Element(250)]);
//! tree.reveal(&key);
//! // The root, x, y, y's three chunks, the third's 100 elements.
//! assert_eq!(tree.lines(&overlays).len(), 1 + 2 + 3 + 100);
//! ```

use std::collections::HashSet;
use std::ops::Range;

use crate::hex::Overlay;
use crate::hex_types::{BitField, Node, Shape};

/// The most elements an expanded array shows at once; a longer one shows
/// chunks of this many.
pub const CHUNK: u64 = 100;

/// A step from a row to one of its children.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Step {
    /// A record's member, by index.
    Member(usize),
    /// A long array's chunk, by index (elements `CHUNK * n` on).
    Chunk(u64),
    /// An array's element, by index (in its chunk, if the array has them).
    Element(u64),
    /// A bit-field of a run, by index.
    Bit(usize),
}

/// A row of the tree: its overlay's index and the steps to it.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Key {
    /// The overlay's index.
    pub root: usize,
    /// The steps from the overlay's type.
    pub steps: Vec<Step>,
}

impl Key {
    /// The overlay's own row.
    pub fn root(root: usize) -> Self {
        Self {
            root,
            steps: Vec::new(),
        }
    }

    /// The row above it, if it is not a root.
    pub fn parent(&self) -> Option<Self> {
        let (_, steps) = self.steps.split_last()?;
        Some(Self {
            root: self.root,
            steps: steps.to_vec(),
        })
    }

    /// Its child by `step`.
    #[must_use]
    pub fn child(&self, step: Step) -> Self {
        let mut steps = self.steps.clone();
        steps.push(step);
        Self {
            root: self.root,
            steps,
        }
    }
}

/// What a row is.
#[derive(Clone, Copy, Debug)]
pub enum Item<'a> {
    /// A node of a layout.
    Node(&'a Node),
    /// Elements `first..end` of an array of `element`.
    Chunk {
        /// One element.
        element: &'a Node,
        /// Its first element's index.
        first: u64,
        /// Past its last element's index.
        end: u64,
    },
    /// A bit-field of the run `run`.
    Bit {
        /// The field.
        field: &'a BitField,
        /// The run.
        run: &'a Node,
    },
}

impl Item<'_> {
    /// Its children's steps.
    fn children(&self) -> Vec<Step> {
        match *self {
            Item::Node(node) => match &node.shape {
                Shape::Record { members, .. } => (0..members.len()).map(Step::Member).collect(),
                Shape::Array { count, .. } if *count > CHUNK => {
                    (0..count.div_ceil(CHUNK)).map(Step::Chunk).collect()
                }
                Shape::Array { count, .. } => (0..*count).map(Step::Element).collect(),
                Shape::Bits(fields) => (0..fields.len()).map(Step::Bit).collect(),
                Shape::Scalar { .. } | Shape::Text => Vec::new(),
            },
            Item::Chunk { first, end, .. } => (first..end).map(Step::Element).collect(),
            Item::Bit { .. } => Vec::new(),
        }
    }

    /// Whether it has children.
    fn expandable(&self) -> bool {
        match *self {
            Item::Node(node) => match &node.shape {
                Shape::Record { members, .. } => !members.is_empty(),
                Shape::Array { count, .. } => *count > 0,
                Shape::Bits(fields) => !fields.is_empty(),
                Shape::Scalar { .. } | Shape::Text => false,
            },
            Item::Chunk { first, end, .. } => first < end,
            Item::Bit { .. } => false,
        }
    }
}

/// A row found by its key: what it is, where, its name.
#[derive(Clone, Debug)]
pub struct Found<'a> {
    /// What it is.
    pub item: Item<'a>,
    /// Its first byte from its overlay's start.
    pub offset: u64,
    /// Its size in bytes.
    pub size: u64,
    /// Its name in the tree: a member's, `[3]`, `[100…199]`, the
    /// overlay's.
    pub name: String,
}

/// A member's name in the tree: its own, else (anonymous) its bit-fields'
/// or its type.
fn member_name(node: &Node) -> String {
    if !node.name.is_empty() {
        return node.name.clone();
    }
    match &node.shape {
        Shape::Bits(fields) => fields
            .iter()
            .map(|f| f.name.as_str())
            .collect::<Vec<_>>()
            .join(", "),
        Shape::Scalar { .. } | Shape::Text | Shape::Array { .. } | Shape::Record { .. } => {
            node.ty.clone()
        }
    }
}

/// The row `key` names among `overlays`' trees.
pub fn resolve<'a>(overlays: &'a [Overlay], key: &Key) -> Option<Found<'a>> {
    let overlay = overlays.get(key.root)?;
    let mut found = Found {
        item: Item::Node(&overlay.layout.root),
        offset: 0,
        size: overlay.layout.size,
        name: overlay.name.clone(),
    };
    for &step in &key.steps {
        found = match (found.item, step) {
            (Item::Node(node), Step::Member(i)) => {
                let Shape::Record { members, .. } = &node.shape else {
                    return None;
                };
                let member = members.get(i)?;
                Found {
                    item: Item::Node(member),
                    offset: found.offset + member.offset,
                    size: member.size,
                    name: member_name(member),
                }
            }
            (Item::Node(node), Step::Chunk(c)) => {
                let Shape::Array { element, count } = &node.shape else {
                    return None;
                };
                let first = c.checked_mul(CHUNK).filter(|&f| f < *count)?;
                let end = (first + CHUNK).min(*count);
                Found {
                    item: Item::Chunk {
                        element,
                        first,
                        end,
                    },
                    offset: found.offset + first * element.size,
                    size: (end - first) * element.size,
                    name: format!("[{first}…{}]", end - 1),
                }
            }
            (Item::Node(node), Step::Element(i)) => {
                let Shape::Array { element, count } = &node.shape else {
                    return None;
                };
                if i >= *count {
                    return None;
                }
                Found {
                    item: Item::Node(element),
                    offset: found.offset + i * element.size,
                    size: element.size,
                    name: format!("[{i}]"),
                }
            }
            (
                Item::Chunk {
                    element,
                    first,
                    end,
                },
                Step::Element(i),
            ) => {
                if !(first..end).contains(&i) {
                    return None;
                }
                Found {
                    item: Item::Node(element),
                    offset: found.offset + (i - first) * element.size,
                    size: element.size,
                    name: format!("[{i}]"),
                }
            }
            (Item::Node(run), Step::Bit(i)) => {
                let Shape::Bits(fields) = &run.shape else {
                    return None;
                };
                let field = fields.get(i)?;
                Found {
                    item: Item::Bit { field, run },
                    offset: found.offset,
                    size: run.size,
                    name: field.name.clone(),
                }
            }
            _ => return None,
        };
    }
    Some(found)
}

/// The deepest row of overlay `root` holding its byte `offset` (from its
/// start): a member, an element (in its chunk), down to a scalar, text or
/// a run of bit-fields; `None` if the byte is not the overlay's.
pub fn deepest(overlays: &[Overlay], root: usize, offset: u64) -> Option<Key> {
    let layout = &overlays.get(root)?.layout;
    if !layout.holds(offset) {
        return None;
    }
    let mut key = Key::root(root);
    let mut node = &layout.root;
    let mut rel = offset;
    loop {
        match &node.shape {
            Shape::Record { members, .. } => {
                let Some((i, member)) = members
                    .iter()
                    .enumerate()
                    .find(|(_, m)| (m.offset..m.offset + m.size).contains(&rel))
                else {
                    break;
                };
                key.steps.push(Step::Member(i));
                rel -= member.offset;
                node = member;
            }
            Shape::Array { element, count } => {
                let stride = element.size;
                if stride == 0 || rel / stride >= *count {
                    break;
                }
                let i = rel / stride;
                if *count > CHUNK {
                    key.steps.push(Step::Chunk(i / CHUNK));
                }
                key.steps.push(Step::Element(i));
                rel -= i * stride;
                node = element;
            }
            Shape::Scalar { .. } | Shape::Text | Shape::Bits(_) => break,
        }
    }
    Some(key)
}

/// A line of the tree as shown: a row's key, depth and state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Line {
    /// The row.
    pub key: Key,
    /// How deep it is (a root: 0).
    pub depth: usize,
    /// Whether it has children.
    pub expandable: bool,
    /// Whether they are shown.
    pub expanded: bool,
}

/// A row as the table shows it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Row {
    /// Its name.
    pub name: String,
    /// Its type as C writes it (`Elf64_Phdr[13]`, `unsigned int : 3`).
    pub ty: String,
    /// Its first byte from its overlay's start.
    pub offset: u64,
    /// Its size in bytes.
    pub size: u64,
    /// A bit-field's first bit (in its run) and width.
    pub bits: Option<(u64, u32)>,
    /// Its value as C writes it (a scalar's, text, an array of scalars'),
    /// or its part's name (a section header's section).
    pub value: String,
}

/// Row `key` of `overlays` as the table shows it; `bytes` reads an
/// overlay's bytes (from its start), `little` is the byte order, `name`
/// names a pointer's target.
pub fn row(
    overlays: &[Overlay],
    key: &Key,
    bytes: &dyn Fn(&Overlay, Range<u64>) -> Vec<u8>,
    little: bool,
    name: &dyn Fn(u64) -> Option<String>,
) -> Option<Row> {
    let overlay = overlays.get(key.root)?;
    let found = resolve(overlays, key)?;
    let range = found.offset..found.offset + found.size;
    let (ty, bits, value) = match found.item {
        Item::Node(node) => {
            let value = if node.is_leaf() && node.size <= 4096 {
                node.value(&bytes(overlay, range), little, name)
            } else {
                overlay.label(&range).unwrap_or_default().to_owned()
            };
            (node.ty.clone(), None, value)
        }
        Item::Chunk {
            element,
            first,
            end,
        } => (
            format!("{}[{}]", element.ty, end - first),
            None,
            String::new(),
        ),
        Item::Bit { field, .. } => (
            format!("{} : {}", field.ty, field.width),
            Some((field.bit, field.width)),
            field.value(&bytes(overlay, range), little),
        ),
    };
    Some(Row {
        name: found.name,
        ty,
        offset: found.offset,
        size: found.size,
        bits,
        value,
    })
}

/// The tree's state: what is expanded, the selected row.
#[derive(Clone, Debug, Default)]
pub struct StructTree {
    expanded: HashSet<Key>,
    /// The selected row.
    pub selected: Option<Key>,
}

/// A key the tree takes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Move {
    /// The row above.
    Up,
    /// The row below.
    Down,
    /// Collapse, else the parent.
    Left,
    /// Expand, else the first child.
    Right,
}

impl StructTree {
    /// Whether `key`'s children are shown.
    pub fn is_expanded(&self, key: &Key) -> bool {
        self.expanded.contains(key)
    }

    /// Shows or hides `key`'s children.
    pub fn toggle(&mut self, key: &Key) {
        if !self.expanded.remove(key) {
            self.expanded.insert(key.clone());
        }
    }

    /// Selects `key`, every row above it expanded.
    pub fn reveal(&mut self, key: &Key) {
        let mut above = key.parent();
        while let Some(parent) = above {
            above = parent.parent();
            self.expanded.insert(parent);
        }
        self.selected = Some(key.clone());
    }

    /// The lines shown: each overlay's row, and the children of each
    /// expanded row, depth first.
    pub fn lines(&self, overlays: &[Overlay]) -> Vec<Line> {
        let mut out = Vec::new();
        for root in 0..overlays.len() {
            self.push(overlays, &Key::root(root), 0, &mut out);
        }
        out
    }

    /// `key`'s line and, if it is expanded, its children's.
    fn push(&self, overlays: &[Overlay], key: &Key, depth: usize, out: &mut Vec<Line>) {
        let Some(found) = resolve(overlays, key) else {
            return;
        };
        let expandable = found.item.expandable();
        let expanded = expandable && self.expanded.contains(key);
        let children = if expanded {
            found.item.children()
        } else {
            Vec::new()
        };
        out.push(Line {
            key: key.clone(),
            depth,
            expandable,
            expanded,
        });
        for step in children {
            self.push(overlays, &key.child(step), depth + 1, out);
        }
    }

    /// Moves the selection as `key` says over `lines` (as shown), or
    /// collapses or expands; whether the selection moved.
    pub fn press(&mut self, key: Move, lines: &[Line]) -> bool {
        let at = self
            .selected
            .as_ref()
            .and_then(|s| lines.iter().position(|l| l.key == *s));
        let Some(at) = at else {
            self.selected = lines.first().map(|l| l.key.clone());
            return self.selected.is_some();
        };
        let Some(line) = lines.get(at) else {
            return false;
        };
        let to = match key {
            Move::Up => at.checked_sub(1),
            Move::Down => Some(at + 1).filter(|&n| n < lines.len()),
            Move::Left if line.expanded => {
                self.expanded.remove(&line.key);
                return false;
            }
            Move::Left => {
                let parent = line.key.parent();
                lines.iter().position(|l| Some(&l.key) == parent.as_ref())
            }
            Move::Right if line.expandable && !line.expanded => {
                self.expanded.insert(line.key.clone());
                return false;
            }
            Move::Right if line.expanded => Some(at + 1).filter(|&n| n < lines.len()),
            Move::Right => None,
        };
        match to.and_then(|n| lines.get(n)) {
            Some(next) => {
                self.selected = Some(next.key.clone());
                true
            }
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::indexing_slicing,
        reason = "tests fail loudly"
    )]

    use super::*;
    use crate::hex::{Anchor, user_overlay};
    use crate::hex_types::{DataModel, TypeSet};

    fn overlays(c: &str, ty: &str) -> Vec<Overlay> {
        let mut types = TypeSet::new(DataModel::LP64);
        types.define(c).unwrap();
        let layout = types.layout(ty).unwrap();
        vec![user_overlay(Anchor::Address(0x1000), layout, ty)]
    }

    #[test]
    fn keys_walk_the_tree_as_a_file_tree() {
        let overlays = overlays(
            "struct in { int a; int b; }; struct out { char tag; struct in inner; int last; };",
            "struct out",
        );
        let mut tree = StructTree::default();
        let names = |tree: &StructTree| -> Vec<(String, usize)> {
            tree.lines(&overlays)
                .iter()
                .map(|l| (resolve(&overlays, &l.key).unwrap().name, l.depth))
                .collect()
        };
        let expected = |pairs: &[(&str, usize)]| -> Vec<(String, usize)> {
            pairs.iter().map(|&(n, d)| (n.to_owned(), d)).collect()
        };
        // Nothing selected: the first row.
        assert!(tree.press(Move::Down, &tree.lines(&overlays)));
        assert_eq!(tree.selected, Some(Key::root(0)));
        // Right expands, then goes to the first child.
        assert!(!tree.press(Move::Right, &tree.lines(&overlays)));
        assert_eq!(names(&tree).len(), 4);
        assert!(tree.press(Move::Right, &tree.lines(&overlays)));
        assert!(tree.press(Move::Down, &tree.lines(&overlays)));
        let inner = Key::root(0).child(Step::Member(1));
        assert_eq!(tree.selected, Some(inner));
        assert!(!tree.press(Move::Right, &tree.lines(&overlays)));
        assert_eq!(
            names(&tree),
            expected(&[
                ("struct out", 0),
                ("tag", 1),
                ("inner", 1),
                ("a", 2),
                ("b", 2),
                ("last", 1),
            ])
        );
        // Left collapses, then goes to the parent; a leaf's Right does
        // nothing.
        assert!(!tree.press(Move::Left, &tree.lines(&overlays)));
        assert_eq!(names(&tree).len(), 4);
        assert!(tree.press(Move::Left, &tree.lines(&overlays)));
        assert_eq!(tree.selected, Some(Key::root(0)));
        tree.selected = Some(Key::root(0).child(Step::Member(0)));
        assert!(!tree.press(Move::Right, &tree.lines(&overlays)));
        assert!(!tree.press(Move::Up, &[]), "no lines");
    }

    #[test]
    fn a_long_array_opens_in_chunks_and_a_byte_finds_its_row() {
        let overlays = overlays(
            "struct e { uint32_t key; uint8_t flags : 3; uint8_t kind : 5; };
             struct t { uint64_t n; struct e items[10000]; };",
            "struct t",
        );
        let key = deepest(&overlays, 0, 8 + 8 * 4321 + 4).unwrap();
        assert_eq!(
            key.steps,
            [
                Step::Member(1),
                Step::Chunk(43),
                Step::Element(4321),
                Step::Member(1)
            ]
        );
        let found = resolve(&overlays, &key).unwrap();
        assert_eq!((found.offset, found.size), (8 + 8 * 4321 + 4, 1));
        assert_eq!(found.name, "flags, kind");
        let mut tree = StructTree::default();
        tree.reveal(&key);
        let lines = tree.lines(&overlays);
        // The root, n, items, its 100 chunks, chunk 43's 100 elements,
        // element 4321's two members.
        assert_eq!(lines.len(), 1 + 2 + 100 + 100 + 2);
        let at = lines.iter().position(|l| l.key == key).unwrap();
        assert_eq!(lines[at].depth, 4);
        assert!(lines[at].expandable && !lines[at].expanded);
        let chunk = resolve(&overlays, &key.parent().unwrap().parent().unwrap()).unwrap();
        assert_eq!(chunk.name, "[4300…4399]");
        // Bit-fields with their bit ranges and values.
        let bytes = |_: &Overlay, range: Range<u64>| -> Vec<u8> {
            range
                .map(|at| {
                    if at == 8 + 8 * 4321 + 4 {
                        0b1011_0101
                    } else {
                        0
                    }
                })
                .collect()
        };
        let kind = row(&overlays, &key.child(Step::Bit(1)), &bytes, true, &|_| None).unwrap();
        assert_eq!(
            (
                kind.name.as_str(),
                kind.ty.as_str(),
                kind.bits,
                kind.value.as_str()
            ),
            ("kind", "unsigned char : 5", Some((3, 5)), "22")
        );
        // A byte between members (padding) is its record's; one past the
        // type is no row.
        let padded = overlays_padded();
        let key = deepest(&padded, 0, 2).unwrap();
        assert_eq!(key, Key::root(0));
        assert_eq!(deepest(&padded, 0, 8), None);
    }

    fn overlays_padded() -> Vec<Overlay> {
        overlays("struct p { char c; int i; };", "struct p")
    }
}
