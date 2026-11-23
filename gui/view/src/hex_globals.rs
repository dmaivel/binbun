//! The whole program's typed globals in the hex view: each global of the
//! image's data whose type the whole-program
//! table knows (a struct, an array, a pointer, a scalar) is an overlay
//! named as the C names it, its fields the type's, under the debug
//! information's and the user's overlays ([`layered`]). A global is laid
//! out only once wanted (its bytes or its tree row in view, [`Self::lay_out`]),
//! so a program's hundreds of globals cost what is shown; until then it
//! is a root of its size without fields. Each row of a global's tree
//! counts the references starting in its bytes ([`references`]).
//!
//! ```
//! use binbun_gui_view::hex_globals::{Global, ProgramGlobals};
//!
//! let globals = ProgramGlobals::new(
//!     vec![
//!         Global { start: 0x4040, size: 8, name: "global_command".to_owned() },
//!         Global { start: 0x4000, size: 48, name: "current_user".to_owned() },
//!     ],
//!     &[],
//! );
//! // The bytes 0x4020..0x4048 in view: both.
//! assert_eq!(globals.overlapping(0x4020..0x4048), vec![0, 1]);
//! assert_eq!(globals.overlapping(0x4028..0x4040), vec![0]);
//! assert!(globals.overlapping(0x4030..0x4040).is_empty());
//! ```

use std::collections::HashSet;
use std::ops::Range;
use std::sync::Arc;

use binbun_session::GlobalTable;

use crate::hex::{Anchor, Overlay, Source};
use crate::hex_tree::{Key, Line, resolve};
use crate::hex_types::{Layout, Node, Shape, from_table};

/// A global of the whole-program table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Global {
    /// Its first byte's address.
    pub start: u64,
    /// Its size in bytes.
    pub size: u64,
    /// Its name as the C names it (`current_user`, `g_4010`).
    pub name: String,
}

/// The typed globals of the table read last, each laid out once wanted.
#[derive(Clone, Debug, Default)]
pub struct ProgramGlobals {
    /// The globals, by first byte.
    globals: Vec<Global>,
    /// Each one's type laid out, once wanted (by the globals' order).
    laid: Vec<Option<Arc<Layout>>>,
    /// The largest global's size (how far before a range a global
    /// overlapping it may start).
    largest: u64,
}

impl ProgramGlobals {
    /// The table's `globals` (any order), none laid out yet, but those
    /// the `debug` information's overlays type (they state them: their
    /// own overlays stand).
    pub fn new(mut globals: Vec<Global>, debug: &[Overlay]) -> Self {
        let stated: HashSet<Anchor> = debug.iter().map(|d| d.anchor).collect();
        globals.retain(|g| !stated.contains(&Anchor::Address(g.start)));
        globals.sort_by_key(|g| g.start);
        let largest = globals.iter().map(|g| g.size).max().unwrap_or(0);
        Self {
            laid: vec![None; globals.len()],
            globals,
            largest,
        }
    }

    /// The globals, by first byte.
    pub fn globals(&self) -> &[Global] {
        &self.globals
    }

    /// Renames the globals as `name` names them now (the user renamed
    /// one); whether a name changed.
    pub fn rename(&mut self, name: impl Fn(u64) -> String) -> bool {
        let mut changed = false;
        for global in &mut self.globals {
            let now = name(global.start);
            if now != global.name {
                global.name = now;
                changed = true;
            }
        }
        changed
    }

    /// The indices of the globals with a byte in `range` (addresses).
    pub fn overlapping(&self, range: Range<u64>) -> Vec<usize> {
        let from = self
            .globals
            .partition_point(|g| g.start.saturating_add(self.largest) <= range.start);
        self.globals
            .iter()
            .enumerate()
            .skip(from)
            .take_while(|(_, g)| g.start < range.end)
            .filter(|(_, g)| g.start.saturating_add(g.size) > range.start)
            .map(|(i, _)| i)
            .collect()
    }

    /// Whether global `index` is laid out.
    pub fn is_laid(&self, index: usize) -> bool {
        self.laid.get(index).is_some_and(Option::is_some)
    }

    /// Lays out the globals `wanted` (indices) not laid out yet, each with
    /// `table` (its type's table by its first byte; a global it has none
    /// for stays as it is); whether any was laid out now.
    pub fn lay_out(
        &mut self,
        wanted: impl IntoIterator<Item = usize>,
        table: impl Fn(u64) -> Option<GlobalTable>,
    ) -> bool {
        let mut any = false;
        for index in wanted {
            let (Some(global), Some(slot)) = (self.globals.get(index), self.laid.get_mut(index))
            else {
                continue;
            };
            if slot.is_some() {
                continue;
            }
            if let Some(layout) = table(global.start).and_then(|t| from_table(&t)) {
                *slot = Some(Arc::new(layout));
                any = true;
            }
        }
        any
    }

    /// The overlays, by the globals' order: each laid out, else a whole
    /// of its size without fields.
    pub fn overlays(&self) -> Vec<Overlay> {
        self.globals
            .iter()
            .zip(&self.laid)
            .map(|(global, laid)| Overlay {
                anchor: Anchor::Address(global.start),
                layout: laid.clone().unwrap_or_else(|| {
                    let whole = Node::new(
                        String::new(),
                        String::new(),
                        0,
                        global.size,
                        Shape::Record {
                            union: false,
                            members: Vec::new(),
                        },
                    );
                    Arc::new(Layout::new(String::new(), whole))
                }),
                source: Source::Program,
                name: global.name.clone(),
                text: None,
                labels: Vec::new(),
            })
            .collect()
    }
}

/// Every overlay, weakest first (a byte shows the last one holding it):
/// the file's `headers`, the whole program's typed globals (`program`),
/// debug information's (`debug`), the user's (`user`).
pub fn layered(
    headers: &[Overlay],
    program: Vec<Overlay>,
    debug: &[Overlay],
    user: &[Overlay],
) -> Vec<Overlay> {
    let mut all = headers.to_vec();
    all.extend(program);
    all.extend_from_slice(debug);
    all.extend_from_slice(user);
    all
}

/// The globals (their indices in `globals`, whose overlays are the
/// overlays from `first` on) whose root rows are among `lines`.
pub fn roots_in(lines: &[Line], first: usize, globals: &ProgramGlobals) -> Vec<usize> {
    lines
        .iter()
        .filter(|l| l.key.steps.is_empty())
        .filter_map(|l| l.key.root.checked_sub(first))
        .filter(|&i| i < globals.globals().len())
        .collect()
}

/// How many references (`within`: the references starting in a range of
/// addresses) start in the bytes of row `key` of a whole-program global
/// among `overlays`; `None` for a row of another overlay, or one nothing
/// references.
pub fn references(
    overlays: &[Overlay],
    key: &Key,
    within: impl Fn(Range<u64>) -> usize,
) -> Option<usize> {
    let count = within(row_bytes(overlays, key)?);
    (count > 0).then_some(count)
}

/// The bytes (addresses) of row `key` of a whole-program global among
/// `overlays`, if it is one: what its references are into.
pub fn row_bytes(overlays: &[Overlay], key: &Key) -> Option<Range<u64>> {
    let overlay = overlays.get(key.root)?;
    let Anchor::Address(start) = overlay.anchor else {
        return None;
    };
    if overlay.source != Source::Program {
        return None;
    }
    let found = resolve(overlays, key)?;
    let first = start.checked_add(found.offset)?;
    Some(first..first.saturating_add(found.size))
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::indexing_slicing,
        reason = "tests fail loudly"
    )]

    use std::cell::Cell;

    use binbun_ast::types::{Aggregate, Field, Type, Types};
    use binbun_loader::Image;

    use super::*;
    use crate::hex::{HexImage, Mode, user_overlay};
    use crate::hex_tree::Step;
    use crate::hex_types::{DataModel, TypeSet};

    /// `struct pair { uint32_t tag; char *name; int16_t v[4]; }` as the
    /// whole-program table has it, each type named.
    fn pair() -> GlobalTable {
        let mut types = Types::new(64);
        let tag = types.intern(Type::UInt(32));
        let char = types.intern(Type::Char { signed: true });
        let name = types.intern(Type::Pointer(Some(char)));
        let short = types.intern(Type::Int(16));
        let v = types.intern(Type::Array {
            element: short,
            length: Some(4),
        });
        let field = |offset, ty, name: &str| Field {
            offset,
            ty,
            name: Some(name.to_owned()),
        };
        let ty = types.intern(Type::Struct(Aggregate {
            name: Some("pair".to_owned()),
            size: 24,
            fields: vec![
                field(0, tag, "tag"),
                field(8, name, "name"),
                field(16, v, "v"),
            ],
        }));
        let names = [
            "uint32_t",
            "char",
            "char *",
            "int16_t",
            "int16_t[4]",
            "struct pair",
        ]
        .map(|n| Some(n.to_owned()))
        .to_vec();
        GlobalTable { types, ty, names }
    }

    fn globals() -> Vec<Global> {
        vec![
            Global {
                start: 0x4020,
                size: 8,
                name: "global_command".to_owned(),
            },
            Global {
                start: 0x3f00,
                size: 24,
                name: "current_user".to_owned(),
            },
        ]
    }

    #[test]
    fn a_global_is_laid_out_once_wanted_and_its_rows_count_their_references() {
        let mut program = ProgramGlobals::new(globals(), &[]);
        let asked = Cell::new(0);
        let table = |start: u64| {
            asked.set(asked.get() + 1);
            (start == 0x3f00).then(pair)
        };
        // Only the bytes of the first in view: only it is laid out.
        assert!(program.lay_out(program.overlapping(0x3f08..0x3f10), table));
        assert!(program.is_laid(0) && !program.is_laid(1));
        assert!(!program.lay_out([0], table), "laid out once");
        assert_eq!(asked.get(), 1);
        let overlays = program.overlays();
        let root = &overlays[0].layout.root;
        let Shape::Record { members, .. } = &root.shape else {
            panic!("{root:?}");
        };
        let fields: Vec<(&str, &str, u64)> = members
            .iter()
            .map(|m| (m.name.as_str(), m.ty.as_str(), m.offset))
            .collect();
        assert_eq!(
            fields,
            [
                ("tag", "uint32_t", 0),
                ("name", "char *", 8),
                ("v", "int16_t[4]", 16)
            ]
        );
        assert_eq!(
            (overlays[0].name.as_str(), root.ty.as_str()),
            ("current_user", "struct pair")
        );
        // Not laid out: a whole of its size, no fields.
        assert_eq!(overlays[1].layout.size, 8);
        assert!(overlays[1].layout.root.is_leaf());
        // References start at these addresses.
        let refs = [0x3f00, 0x3f08, 0x3f09, 0x3f12];
        let within = |r: Range<u64>| refs.iter().filter(|a| r.contains(a)).count();
        let count = |steps: Vec<Step>| references(&overlays, &Key { root: 0, steps }, within);
        assert_eq!(count(vec![]), Some(4));
        assert_eq!(count(vec![Step::Member(1)]), Some(2));
        assert_eq!(count(vec![Step::Member(2)]), Some(1));
        assert_eq!(count(vec![Step::Member(2), Step::Element(1)]), Some(1));
        // Nothing into `v[0]`: no count, not 0.
        assert_eq!(count(vec![Step::Member(2), Step::Element(0)]), None);
        assert_eq!(
            row_bytes(
                &overlays,
                &Key {
                    root: 0,
                    steps: vec![Step::Member(2)]
                }
            ),
            Some(0x3f10..0x3f18)
        );
        // A name the user gave since.
        assert!(program.rename(|start| format!("g_{start:x}")));
        assert_eq!(program.overlays()[0].name, "g_3f00");
    }

    #[test]
    fn the_users_and_debug_informations_overlays_win_over_the_programs() {
        let path = format!(
            "{}/../../tests/fixtures/program-x86_64.elf",
            env!("CARGO_MANIFEST_DIR")
        );
        let data = std::fs::read(path).unwrap();
        let image = Image::parse(&data).unwrap();
        let hex = HexImage::new(&data, &image);
        let mut types = TypeSet::new(DataModel::LP64);
        let at = |a: u64, text: &str, types: &mut TypeSet| {
            user_overlay(Anchor::Address(a), types.apply(text).unwrap(), text)
        };
        // Debug information types the global at 0x4020 itself.
        let mut debug = at(0x4020, "uint64_t", &mut types);
        debug.source = Source::Debug;
        let mut program = ProgramGlobals::new(globals(), &[debug.clone()]);
        assert_eq!(program.globals().len(), 1, "debug information's stands");
        program.lay_out([0], |_| Some(pair()));
        let user = at(0x3f08, "uint64_t", &mut types);
        let headers = hex.headers();
        let all = layered(headers, program.overlays(), &[debug], &[user]);
        let shown = |a: u64| hex.placed(&all, Mode::Address, a..a + 1).pop().unwrap();
        let first = headers.len();
        // `tag` is the program's; `name` the user's over it.
        assert_eq!(
            (shown(0x3f00).overlay, shown(0x3f00).path.as_str()),
            (first, "tag")
        );
        assert_eq!(shown(0x3f08).overlay, first + 2);
        assert_eq!(shown(0x4020).overlay, first + 1);
    }
}
