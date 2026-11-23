//! The binary's map: the left sidebar's tree, as an editor's file tree is
//! the project's. The root is the file; under it one folder per kind of
//! item: the bookmarks (pinned first, only when there are some: one's own,
//! shared and private, then a folder per other person, collapsed at
//! first), the sections, the functions (grouped into folders by their
//! source file when debug information names one, a folder per directory
//! below the one every source file shares, else by their C++ namespace or
//! class, else flat), the imports by library, the exports, the named data
//! and the types.
//!
//! [`Map::build`] makes the tree from an [`Input`] (filled from the
//! session by [`input`]); [`Map::rows`] flattens it into the rows shown,
//! from the folders the user opened and the filter typed.
//!
//! What the engine gives: sections, functions (C++ ones demangled from
//! their Itanium manglings and grouped by scope; with their source files
//! when the session found debug information: `Session::source_unit`),
//! imports (by DLL in a PE; in an ELF by the library their symbol version
//! names, unversioned ones under `(unknown)`), exports, named data
//! symbols, and as the types the C++ classes found from RTTI, the
//! synthesised structs and the user's definitions ([`TypeNames`]).

use std::collections::{BTreeMap, HashMap, HashSet};
use std::hash::BuildHasher;
use std::sync::Arc;

use binbun::Database;
use binbun_demangle::demangle;
use binbun_loader::{Format, Image, Machine, SymbolKind, SymbolSource};
use binbun_session::Synthesised;
use binbun_session::journal::PublicKey;

use crate::fuzzy::Query;
use crate::listing::Listing;
use crate::session::{Session, StringItem};

/// What a node is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Kind {
    /// The binary (the root).
    File,
    /// One of the root's folders.
    Group(Group),
    /// A folder of functions (a compilation unit, a namespace or class).
    Folder,
    /// A library imports come from.
    Library,
    /// A section.
    Section,
    /// A function.
    Function,
    /// An import.
    Import,
    /// An export.
    Export,
    /// A named global.
    Data,
    /// A type.
    Type,
    /// A string in the data.
    String,
    /// One of this person's bookmarks, shared.
    Bookmark,
    /// One of this person's bookmarks, private (never sent).
    PrivateBookmark,
    /// Another person's bookmarks: a folder named after them.
    Person,
    /// A bookmark of another person's.
    TheirBookmark,
}

impl Kind {
    /// Whether nodes of this kind hold others.
    pub fn is_folder(self) -> bool {
        matches!(
            self,
            Self::File | Self::Group(_) | Self::Folder | Self::Library | Self::Person
        )
    }

    /// Whether it is a bookmark (anyone's).
    pub fn is_bookmark(self) -> bool {
        matches!(
            self,
            Self::Bookmark | Self::PrivateBookmark | Self::TheirBookmark
        )
    }
}

/// The root's folders, in order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Group {
    /// The bookmarks (pinned first, only when there are some).
    Bookmarks,
    /// The sections.
    Sections,
    /// The functions.
    Functions,
    /// The imports, by library.
    Imports,
    /// The exports.
    Exports,
    /// The globals: the symbols', the detected ones, the strings.
    Data,
    /// The types.
    Types,
}

impl Group {
    /// Every group, in the tree's order.
    pub const ALL: [Self; 7] = [
        Self::Bookmarks,
        Self::Sections,
        Self::Functions,
        Self::Imports,
        Self::Exports,
        Self::Data,
        Self::Types,
    ];

    /// Its title.
    pub fn title(self) -> &'static str {
        match self {
            Self::Bookmarks => "Bookmarks",
            Self::Sections => "Sections",
            Self::Functions => "Functions",
            Self::Imports => "Imports",
            Self::Exports => "Exports",
            Self::Data => "Data",
            Self::Types => "Types",
        }
    }

    /// Its folder's key.
    pub fn key(self) -> &'static str {
        match self {
            Self::Bookmarks => "/bookmarks",
            Self::Sections => "/sections",
            Self::Functions => "/functions",
            Self::Imports => "/imports",
            Self::Exports => "/exports",
            Self::Data => "/data",
            Self::Types => "/types",
        }
    }

    /// The group a folder's `key` is in (its own, or one under it).
    pub fn of_key(key: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|g| {
            key.strip_prefix(g.key())
                .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
        })
    }
}

/// A named item at an address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Item {
    /// Its name.
    pub name: String,
    /// Its address.
    pub address: u64,
}

/// A function as the map groups it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Function {
    /// Its name as shown (the user's, else the binary's, demangled).
    pub name: String,
    /// Its entry.
    pub address: u64,
    /// Its source file's path (its compilation unit's), from debug
    /// information.
    pub unit: Option<String>,
    /// Its C++ scope, outermost first (`std`, `vector<int>`), from its
    /// demangled name; empty for a free function.
    pub scope: Vec<String>,
    /// Its name without the scope (`push_back(int const&)`).
    pub leaf: String,
    /// The library and object a signature says it is from (`musl 1.2.5`,
    /// `src/string/strcpy.o`).
    pub library: Option<(String, String)>,
}

/// An import.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Import {
    /// Its name.
    pub name: String,
    /// The library it comes from, if the binary says.
    pub library: Option<String>,
    /// Where it is (its slot or stub).
    pub address: u64,
}

/// Another person's bookmarks, as their folder shows them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Shelf {
    /// Whose.
    pub key: PublicKey,
    /// Their name (the folder's).
    pub name: String,
    /// Their bookmarks.
    pub items: Vec<Item>,
}

/// The key of the folder of `key`'s bookmarks.
pub fn person_key(key: PublicKey) -> String {
    use std::fmt::Write as _;
    key.0
        .iter()
        .fold(format!("{}/", Group::Bookmarks.key()), |mut out, b| {
            let _ = write!(out, "{b:02x}");
            out
        })
}

/// What the map is made of.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Input {
    /// The file's name.
    pub file: String,
    /// The sections, in address order.
    pub sections: Vec<Item>,
    /// The functions.
    pub functions: Vec<Function>,
    /// The imports.
    pub imports: Vec<Import>,
    /// The exports.
    pub exports: Vec<Item>,
    /// The globals: the data symbols and those the analysis found.
    pub data: Vec<Item>,
    /// The type names.
    pub types: Vec<String>,
    /// The strings found, each named by its text (quoted) unless the user
    /// named it.
    pub strings: Vec<Item>,
    /// The bookmarks: their names and addresses.
    pub bookmarks: Vec<Item>,
    /// This person's private bookmarks.
    pub private: Vec<Item>,
    /// The others' bookmarks, by person.
    pub others: Vec<Shelf>,
}

/// A node of the tree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Node {
    /// What it is.
    pub kind: Kind,
    /// Its label.
    pub name: String,
    /// Where it goes, if anywhere.
    pub address: Option<u64>,
    /// A folder's key: stable across rebuilds, so what is open stays open.
    pub key: String,
    /// Whose bookmarks it is or holds (another person's folder and its
    /// bookmarks).
    pub author: Option<PublicKey>,
    /// How many items it stands for (the root's folders and the strings).
    pub count: Option<usize>,
    /// Its children, in order.
    pub children: Vec<usize>,
}

/// A row of the tree as shown.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Row {
    /// The node.
    pub node: usize,
    /// Its depth (the root's is 0).
    pub depth: usize,
    /// Whether it is an open folder.
    pub open: bool,
    /// The filter's matched byte positions in its label.
    pub positions: Vec<usize>,
}

/// How the functions are grouped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Grouping {
    /// By compilation unit.
    Unit,
    /// By namespace and class.
    Scope,
    /// Not grouped.
    Flat,
}

/// The tree.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Map {
    nodes: Vec<Node>,
}

/// The root's key.
pub const ROOT: &str = "/";

/// A folder trie, before it becomes nodes.
#[derive(Default)]
struct Trie {
    folders: BTreeMap<String, Trie>,
    leaves: Vec<(String, u64)>,
}

impl Trie {
    fn insert(&mut self, path: &[String], leaf: String, address: u64) {
        match path.split_first() {
            Some((first, rest)) => self
                .folders
                .entry(first.clone())
                .or_default()
                .insert(rest, leaf, address),
            None => self.leaves.push((leaf, address)),
        }
    }

    /// Each folder holding one leaf and nothing else gives it to its
    /// parent (a library's objects: most hold one function, `atoi.lo`
    /// its `atoi`).
    fn hoist_lone_leaves(&mut self) {
        for (name, mut sub) in std::mem::take(&mut self.folders) {
            sub.hoist_lone_leaves();
            if sub.folders.is_empty() && sub.leaves.len() == 1 {
                self.leaves.append(&mut sub.leaves);
            } else {
                self.folders.insert(name, sub);
            }
        }
    }
}

impl Map {
    /// The tree of `input`.
    pub fn build(input: &Input) -> Self {
        let mut map = Self {
            nodes: vec![Node {
                kind: Kind::File,
                name: input.file.clone(),
                address: None,
                key: ROOT.to_owned(),
                author: None,
                count: None,
                children: Vec::new(),
            }],
        };
        for group in Group::ALL {
            if group == Group::Bookmarks
                && input.bookmarks.is_empty()
                && input.private.is_empty()
                && input.others.iter().all(|shelf| shelf.items.is_empty())
            {
                continue;
            }
            let g = map.push(0, Kind::Group(group), group.title(), None, group.key());
            match group {
                Group::Bookmarks => map.bookmarks(g, input),
                Group::Sections => {
                    for s in &input.sections {
                        map.leaf(g, Kind::Section, &s.name, s.address);
                    }
                }
                Group::Functions => map.functions(g, &input.functions),
                Group::Imports => map.imports(g, &input.imports),
                Group::Exports => map.items(g, Kind::Export, &input.exports),
                Group::Data => map.data(g, input),
                Group::Types => {
                    let mut names: Vec<&String> = input.types.iter().collect();
                    names.sort_unstable();
                    names.dedup();
                    for name in names {
                        map.push(g, Kind::Type, name, None, "");
                    }
                }
            }
            let count = map.leaves(g).len();
            if let Some(node) = map.nodes.get_mut(g) {
                node.count = Some(count);
            }
        }
        map
    }

    /// How `functions` are grouped: by unit if debug info names one for
    /// any, else by scope if any has one, else flat.
    pub fn grouping(functions: &[Function]) -> Grouping {
        if functions.iter().any(|f| f.unit.is_some()) {
            Grouping::Unit
        } else if functions.iter().any(|f| !f.scope.is_empty()) {
            Grouping::Scope
        } else {
            Grouping::Flat
        }
    }

    /// Node `i`.
    pub fn node(&self, i: usize) -> Option<&Node> {
        self.nodes.get(i)
    }

    /// How many nodes there are.
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Whether the tree is empty (never built).
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// The parent of node `i`.
    pub fn parent(&self, i: usize) -> Option<usize> {
        self.nodes.iter().position(|n| n.children.contains(&i))
    }

    /// The folder whose key is `key`.
    pub fn folder(&self, key: &str) -> Option<usize> {
        self.nodes
            .iter()
            .position(|n| n.kind.is_folder() && n.key == key)
    }

    /// The items under node `i`, every folder's below it too (a folder's
    /// own, then its folders' in order): each with the folder holding it.
    pub fn leaves(&self, i: usize) -> Vec<(usize, usize)> {
        let mut out = Vec::new();
        let mut stack = vec![i];
        while let Some(at) = stack.pop() {
            let Some(node) = self.nodes.get(at) else {
                continue;
            };
            // Depth first, in order: the children pushed last first.
            for &c in node.children.iter().rev() {
                if self.nodes.get(c).is_some_and(|n| n.kind.is_folder()) {
                    stack.push(c);
                }
            }
            for &c in &node.children {
                if self.nodes.get(c).is_some_and(|n| !n.kind.is_folder()) {
                    out.push((c, at));
                }
            }
        }
        out
    }

    /// The folders open by default: the root, the bookmarks and the
    /// functions.
    pub fn default_open() -> HashSet<String> {
        [ROOT, Group::Bookmarks.key(), Group::Functions.key()]
            .into_iter()
            .map(str::to_owned)
            .collect()
    }

    /// The rows shown. Without a filter: every node whose folders are all
    /// in `open`. With one: the nodes whose label matches it, under their
    /// folders shown open.
    pub fn rows<S: BuildHasher>(&self, open: &HashSet<String, S>, filter: &str) -> Vec<Row> {
        let mut out = Vec::new();
        if self.nodes.is_empty() {
            return out;
        }
        let query = Query::new(filter);
        if query.is_empty() {
            self.walk_open(0, 0, open, &mut out);
        } else {
            self.walk_filtered(0, 0, &query, &mut out);
        }
        out
    }

    fn walk_open<S: BuildHasher>(
        &self,
        i: usize,
        depth: usize,
        open: &HashSet<String, S>,
        out: &mut Vec<Row>,
    ) {
        let Some(node) = self.nodes.get(i) else {
            return;
        };
        let is_open = node.kind.is_folder() && open.contains(&node.key);
        out.push(Row {
            node: i,
            depth,
            open: is_open,
            positions: Vec::new(),
        });
        if is_open {
            for &c in &node.children {
                self.walk_open(c, depth + 1, open, out);
            }
        }
    }

    /// Pushes the rows under `i` that match; whether any did.
    fn walk_filtered(&self, i: usize, depth: usize, query: &Query, out: &mut Vec<Row>) -> bool {
        let Some(node) = self.nodes.get(i) else {
            return false;
        };
        let at = out.len();
        let matched = if i == 0 {
            None
        } else {
            query.score(&node.name)
        };
        out.push(Row {
            node: i,
            depth,
            open: false,
            positions: matched
                .as_ref()
                .map(|m| m.positions.clone())
                .unwrap_or_default(),
        });
        let mut any = false;
        for &c in &node.children {
            any |= self.walk_filtered(c, depth + 1, query, out);
        }
        if let Some(row) = out.get_mut(at) {
            row.open = any;
        }
        if any || matched.is_some() || i == 0 {
            true
        } else {
            out.truncate(at);
            false
        }
    }

    fn push(
        &mut self,
        parent: usize,
        kind: Kind,
        name: &str,
        address: Option<u64>,
        key: &str,
    ) -> usize {
        let i = self.nodes.len();
        self.nodes.push(Node {
            kind,
            name: name.to_owned(),
            address,
            key: key.to_owned(),
            author: None,
            count: None,
            children: Vec::new(),
        });
        if let Some(p) = self.nodes.get_mut(parent) {
            p.children.push(i);
        }
        i
    }

    fn leaf(&mut self, parent: usize, kind: Kind, name: &str, address: u64) {
        self.push(parent, kind, name, Some(address), "");
    }

    fn items(&mut self, parent: usize, kind: Kind, items: &[Item]) {
        let mut sorted: Vec<&Item> = items.iter().collect();
        sorted.sort_by_key(|item| item.address);
        for item in sorted {
            self.leaf(parent, kind, &item.name, item.address);
        }
    }

    /// The data's folder: a folder of the globals and one of the strings
    /// (each only when it has some, with its count), in address order;
    /// a string where a global is named is the global. An import's
    /// pointer slot is the import's (under Imports), not a global.
    fn data(&mut self, parent: usize, input: &Input) {
        let slots: HashSet<u64> = input.imports.iter().map(|i| i.address).collect();
        let globals: Vec<Item> = input
            .data
            .iter()
            .filter(|g| !slots.contains(&g.address))
            .cloned()
            .collect();
        let named: HashSet<u64> = input.data.iter().map(|item| item.address).collect();
        let strings: Vec<Item> = input
            .strings
            .iter()
            .filter(|s| !named.contains(&s.address))
            .cloned()
            .collect();
        let held = format!("{}/globals", Group::Data.key());
        let texts = format!("{}/strings", Group::Data.key());
        for (title, key, kind, items) in [
            ("Globals", held.as_str(), Kind::Data, globals.as_slice()),
            ("Strings", texts.as_str(), Kind::String, strings.as_slice()),
        ] {
            if items.is_empty() {
                continue;
            }
            let f = self.push(parent, Kind::Folder, title, None, key);
            if let Some(node) = self.nodes.get_mut(f) {
                node.count = Some(items.len());
            }
            self.items(f, kind, items);
        }
    }

    /// The bookmarks' folder: this person's own, shared and private, in
    /// address order; then a folder per other person, by name, each with
    /// theirs.
    fn bookmarks(&mut self, parent: usize, input: &Input) {
        let mut own: Vec<(Kind, &Item)> = input
            .bookmarks
            .iter()
            .map(|item| (Kind::Bookmark, item))
            .chain(
                input
                    .private
                    .iter()
                    .map(|item| (Kind::PrivateBookmark, item)),
            )
            .collect();
        own.sort_by_key(|(_, item)| item.address);
        for (kind, item) in own {
            self.leaf(parent, kind, &item.name, item.address);
        }
        let mut shelves: Vec<&Shelf> = input
            .others
            .iter()
            .filter(|shelf| !shelf.items.is_empty())
            .collect();
        shelves.sort_by_cached_key(|shelf| (shelf.name.to_lowercase(), shelf.key));
        for shelf in shelves {
            let folder = self.push(
                parent,
                Kind::Person,
                &shelf.name,
                None,
                &person_key(shelf.key),
            );
            self.owned(folder, shelf.key);
            let mut items: Vec<&Item> = shelf.items.iter().collect();
            items.sort_by_key(|item| item.address);
            for item in items {
                let leaf = self.push(
                    folder,
                    Kind::TheirBookmark,
                    &item.name,
                    Some(item.address),
                    "",
                );
                self.owned(leaf, shelf.key);
            }
        }
    }

    /// Node `i` is `author`'s.
    fn owned(&mut self, i: usize, author: PublicKey) {
        if let Some(node) = self.nodes.get_mut(i) {
            node.author = Some(author);
        }
    }

    fn functions(&mut self, parent: usize, functions: &[Function]) {
        // Library functions under their library (as imports are) and
        // object, an object of one function only that function; the others
        // grouped as they would be alone.
        let (library, functions): (Vec<Function>, Vec<Function>) =
            functions.iter().cloned().partition(|f| f.library.is_some());
        let functions = functions.as_slice();
        let mut libraries: BTreeMap<String, Trie> = BTreeMap::new();
        for f in &library {
            if let Some((name, object)) = &f.library {
                let path: Vec<String> = object
                    .split(['/', '\\'])
                    .filter(|part| !part.is_empty())
                    .map(str::to_owned)
                    .collect();
                libraries
                    .entry(name.clone())
                    .or_default()
                    .insert(&path, f.name.clone(), f.address);
            }
        }
        for (name, mut trie) in libraries {
            trie.hoist_lone_leaves();
            let key = format!("{}/{name}", Group::Functions.key());
            let node = self.push(parent, Kind::Library, &name, None, &key);
            self.emit(node, &key, trie, "/");
        }
        let mut trie = Trie::default();
        let grouping = Self::grouping(functions);
        match grouping {
            Grouping::Unit => {
                let prefix = common_dir(functions.iter().filter_map(|f| f.unit.as_deref()));
                for f in functions {
                    let path: Vec<String> = f
                        .unit
                        .as_deref()
                        .map(|u| {
                            u.get(prefix..)
                                .unwrap_or(u)
                                .split(['/', '\\'])
                                .filter(|part| !part.is_empty())
                                .map(str::to_owned)
                                .collect()
                        })
                        .unwrap_or_default();
                    trie.insert(&path, f.name.clone(), f.address);
                }
            }
            Grouping::Scope => {
                for f in functions {
                    let leaf = if f.scope.is_empty() {
                        f.name.clone()
                    } else {
                        f.leaf.clone()
                    };
                    trie.insert(&f.scope, leaf, f.address);
                }
            }
            Grouping::Flat => {
                for f in functions {
                    trie.insert(&[], f.name.clone(), f.address);
                }
            }
        }
        let joint = if grouping == Grouping::Unit {
            "/"
        } else {
            "::"
        };
        self.emit(parent, Group::Functions.key(), trie, joint);
    }

    /// Adds `trie` under `parent`: folders first (by name, case aside; a
    /// folder whose only content is one folder folds into it,
    /// joined by `joint`: `std::__cxx11`, `lib/sh`), then the leaves by
    /// address.
    fn emit(&mut self, parent: usize, key: &str, trie: Trie, joint: &str) {
        let mut folders: Vec<(String, Trie)> = trie.folders.into_iter().collect();
        folders.sort_by_cached_key(|(name, _)| name.to_lowercase());
        for (name, mut sub) in folders {
            let mut label = name;
            while sub.leaves.is_empty() && sub.folders.len() == 1 {
                let Some((next, inner)) = sub.folders.pop_first() else {
                    break;
                };
                label = format!("{label}{joint}{next}");
                sub = inner;
            }
            let key = format!("{key}/{label}");
            let f = self.push(parent, Kind::Folder, &label, None, &key);
            self.emit(f, &key, sub, joint);
        }
        let mut leaves = trie.leaves;
        leaves.sort_by_key(|&(_, address)| address);
        for (name, address) in leaves {
            self.leaf(parent, Kind::Function, &name, address);
        }
    }

    fn imports(&mut self, parent: usize, imports: &[Import]) {
        let mut by_library: BTreeMap<Option<&str>, Vec<&Import>> = BTreeMap::new();
        for import in imports {
            by_library
                .entry(import.library.as_deref())
                .or_default()
                .push(import);
        }
        let single = by_library.len() == 1 && by_library.contains_key(&None);
        let mut libraries: Vec<(Option<&str>, Vec<&Import>)> = by_library.into_iter().collect();
        libraries
            .sort_by_cached_key(|(library, _)| (library.is_none(), library.map(str::to_lowercase)));
        for (library, mut list) in libraries {
            list.sort_by(|a, b| a.name.cmp(&b.name));
            let under = match library {
                _ if single => parent,
                Some(name) => {
                    let key = format!("{}/{name}", Group::Imports.key());
                    self.push(parent, Kind::Library, name, None, &key)
                }
                None => {
                    let key = format!("{}/?", Group::Imports.key());
                    self.push(parent, Kind::Library, "(unknown)", None, &key)
                }
            };
            for import in list {
                self.leaf(under, Kind::Import, &import.name, import.address);
            }
        }
    }
}

/// The longest directory prefix (up to and with a `/` or `\`) every path
/// in `paths` shares, in bytes.
fn common_dir<'a>(paths: impl Iterator<Item = &'a str>) -> usize {
    let mut prefix: Option<&str> = None;
    for path in paths {
        let p = match prefix {
            None => path,
            Some(p) => {
                let n = p
                    .char_indices()
                    .zip(path.chars())
                    .take_while(|((_, a), b)| a == b)
                    .last()
                    .map_or(0, |((i, a), _)| i + a.len_utf8());
                p.get(..n).unwrap_or("")
            }
        };
        prefix = Some(p);
    }
    prefix.map_or(0, |p| p.rfind(['/', '\\']).map_or(0, |i| i + 1))
}

/// The image's format and architecture as the status bar says them
/// (`x86-64 ELF`).
pub fn format_label(image: &Image<'_>) -> String {
    let machine = match image.machine {
        Machine::X86 => "x86",
        Machine::X86_64 => "x86-64",
        Machine::Aarch64 => "AArch64",
        Machine::Arm => "ARM",
        Machine::Other => "?",
    };
    let format = match image.format {
        Format::Elf => "ELF",
        Format::Pe => "PE",
        Format::MachO => "Mach-O",
    };
    format!("{machine} {format}")
}

/// The C++ classes of `db`'s image (from RTTI), by name: the map's types.
pub fn types(db: &Database<'_>) -> Vec<String> {
    let classes = binbun::classes::classes(db.image());
    (0..classes.len())
        .filter_map(|i| classes.get(i).map(|c| c.name.clone()))
        .collect()
}

/// The map's types, kept between its builds: the C++ classes (read once
/// per binary), the synthesised structs of the table the session found
/// last, the user's definitions. The table comes after the map's first
/// build (the callers pass) and is found again after a type edit:
/// [`TypeNames::take`] says when its names changed, the map to be built
/// again.
#[derive(Clone, Debug, Default)]
pub struct TypeNames {
    /// The C++ classes, once read.
    classes: Option<Vec<String>>,
    /// The synthesised structs last taken.
    synthesised: Option<Arc<Vec<Synthesised>>>,
}

impl TypeNames {
    /// Takes the session's synthesised structs now (`None`: no table is
    /// known, those taken before kept); whether their names differ from
    /// those taken before.
    pub fn take(&mut self, synthesised: Option<Arc<Vec<Synthesised>>>) -> bool {
        let Some(now) = synthesised else {
            return false;
        };
        let same = self.synthesised.as_ref().is_some_and(|kept| {
            Arc::ptr_eq(kept, &now) || kept.iter().map(|s| &s.key).eq(now.iter().map(|s| &s.key))
        });
        self.synthesised = Some(now);
        !same
    }

    /// The names: the C++ classes (`classes` reads them, the first time
    /// only), the synthesised structs taken last, the user's
    /// `definitions`.
    pub fn names(
        &mut self,
        classes: impl FnOnce() -> Vec<String>,
        definitions: impl IntoIterator<Item = String>,
    ) -> Vec<String> {
        let mut names = self.classes.get_or_insert_with(classes).clone();
        names.extend(
            self.synthesised
                .iter()
                .flat_map(|s| s.iter().map(|s| s.key.clone())),
        );
        names.extend(definitions);
        names
    }
}

/// The map's input from `session`'s binary as `listing` names it (the
/// user's names over the binary's), with `types` (see [`TypeNames`]) and
/// `strings` (in the data). `demangled` remembers each mangling's text
/// across calls; `name` names the others whose bookmarks have a folder.
/// The globals the analysis found join the data symbols once the
/// whole-program pass is known.
pub fn input<S: BuildHasher>(
    session: &Session,
    listing: &Listing,
    types: &[String],
    strings: &[StringItem],
    demangled: &mut HashMap<String, Option<String>, S>,
    name: &dyn Fn(PublicKey) -> String,
) -> Input {
    let items = |marks: &BTreeMap<u64, String>| -> Vec<Item> {
        marks
            .iter()
            .map(|(&address, name)| Item {
                name: name.clone(),
                address,
            })
            .collect()
    };
    let mut input = Input {
        file: session.file_name(),
        types: types.to_vec(),
        bookmarks: items(&session.overlay().bookmarks),
        private: items(session.private_bookmarks()),
        others: session
            .others_bookmarks()
            .iter()
            .map(|(&key, marks)| Shelf {
                key,
                name: name(key),
                items: items(marks),
            })
            .collect(),
        ..Input::default()
    };
    let Some(db) = session.database() else {
        return input;
    };
    let image = db.image();
    let overlay = session.overlay();
    let mut readable = |name: &str| -> String {
        demangled
            .entry(name.to_owned())
            .or_insert_with(|| demangle(name))
            .clone()
            .unwrap_or_else(|| name.to_owned())
    };
    input.sections = image
        .sections
        .iter()
        .filter(|s| !s.name.is_empty() && s.size > 0)
        .map(|s| Item {
            name: s.name.clone(),
            address: s.start,
        })
        .collect();
    input.functions = db
        .functions()
        .map(|(_, f)| {
            let name = listing
                .shown_name(f.entry, overlay)
                .map_or_else(|| format!("sub_{:X}", f.entry), &mut readable);
            let (scope, leaf) = split_scope(&name);
            Function {
                name,
                address: f.entry,
                unit: session.source_file(f.entry),
                scope,
                leaf,
                library: session
                    .signature(f.entry)
                    .map(|i| (format!("{} {}", i.library, i.version), i.object)),
            }
        })
        .collect();
    input.imports = image
        .imports
        .iter()
        .map(|i| Import {
            name: readable(&i.name),
            library: i.library.clone(),
            address: i.slot,
        })
        .collect();
    let mut seen = HashSet::new();
    for symbol in &image.symbols {
        if symbol.address == 0 || !seen.insert((symbol.address, symbol.kind)) {
            continue;
        }
        let mut item = || Item {
            name: overlay
                .names
                .get(&symbol.address)
                .cloned()
                .unwrap_or_else(|| readable(&symbol.name)),
            address: symbol.address,
        };
        if matches!(symbol.source, SymbolSource::Export | SymbolSource::Dynamic) {
            input.exports.push(item());
        }
        if symbol.kind == SymbolKind::Data {
            input.data.push(item());
        }
    }
    let found = detected_globals(session, db, &input.data);
    input.data.extend(found);
    input.strings = string_items(session, strings);
    input
}

/// `strings` as the data's items: each named by the user, else by its
/// text, quoted and escaped.
fn string_items(session: &Session, strings: &[StringItem]) -> Vec<Item> {
    let names = &session.overlay().names;
    strings
        .iter()
        .map(|s| Item {
            name: names
                .get(&s.address)
                .cloned()
                .unwrap_or_else(|| format!("\"{}\"", s.text.escape_debug())),
            address: s.address,
        })
        .collect()
}

/// The globals in the image the whole program's pass found (none until
/// it is known) that `named` does not hold, named as the C names them.
fn detected_globals(session: &Session, db: &Database<'_>, named: &[Item]) -> Vec<Item> {
    let Some(callers) = db.known_callers(&[]) else {
        return Vec::new();
    };
    let named: HashSet<u64> = named.iter().map(|item| item.address).collect();
    let sections = &db.image().sections;
    let in_image = |a: u64| {
        sections
            .iter()
            .any(|s| (s.start..s.start.saturating_add(s.size)).contains(&a))
    };
    callers
        .schemes
        .globals()
        .iter()
        .map(|(start, _)| start)
        .filter(|&start| !named.contains(&start) && in_image(start))
        .map(|start| Item {
            name: session.global_name(start),
            address: start,
        })
        .collect()
}

/// A C++ demangled name split into its scope and its own name, at the
/// `::` outside template arguments and parameter lists:
/// `std::vector<int>::push_back(int const&)` → (`std`, `vector<int>`),
/// `push_back(int const&)`. A name with no scope gives an empty scope.
pub fn split_scope(name: &str) -> (Vec<String>, String) {
    let mut parts = Vec::new();
    let mut depth = 0usize;
    let mut start = 0;
    let bytes = name.as_bytes();
    let mut i = 0;
    while let Some(&b) = bytes.get(i) {
        match b {
            b'(' if depth == 0 => break,
            b'<' | b'(' | b'[' => depth += 1,
            b'>' | b')' | b']' => depth = depth.saturating_sub(1),
            b':' if depth == 0 && bytes.get(i + 1) == Some(&b':') => {
                if let Some(part) = name.get(start..i) {
                    parts.push(part.to_owned());
                }
                i += 2;
                start = i;
                continue;
            }
            _ => {}
        }
        i += 1;
    }
    let leaf = name.get(start..).unwrap_or(name).to_owned();
    // An operator's own `::` cannot occur; an empty part (a leading `::`)
    // is dropped.
    parts.retain(|p| !p.is_empty());
    (parts, leaf)
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::sync::Arc;

    use binbun_session::Synthesised;
    use binbun_session::journal::PublicKey;

    use super::{
        Function, Group, Import, Input, Item, Kind, Map, Row, Shelf, TypeNames, demangle,
        person_key, split_scope,
    };

    #[test]
    fn itanium_manglings_read_as_cpp_and_split_into_their_scope() {
        let text = demangle("_ZNKSt6locale4nameB5cxx11Ev").unwrap();
        assert_eq!(text, "std::locale::name[abi:cxx11]() const");
        assert_eq!(
            split_scope(&text),
            (
                vec!["std".to_owned(), "locale".to_owned()],
                "name[abi:cxx11]() const".to_owned()
            )
        );
        let text = demangle("_ZNSt6vectorIiSaIiEE9push_backERKi").unwrap();
        assert_eq!(
            text,
            "std::vector<int, std::allocator<int> >::push_back(int const&)"
        );
        assert_eq!(
            split_scope(&text),
            (
                vec![
                    "std".to_owned(),
                    "vector<int, std::allocator<int> >".to_owned()
                ],
                "push_back(int const&)".to_owned()
            )
        );
        assert_eq!(demangle("main"), None);
        assert_eq!(demangle("_Z"), None);
    }

    fn function(name: &str, address: u64, unit: Option<&str>) -> Function {
        let (scope, leaf) = split_scope(name);
        Function {
            name: name.to_owned(),
            address,
            unit: unit.map(str::to_owned),
            scope,
            leaf,
            library: None,
        }
    }

    /// The rows as `depth label` lines.
    fn shown(map: &Map, rows: &[Row]) -> Vec<String> {
        rows.iter()
            .map(|r| {
                let node = map.node(r.node).unwrap();
                format!("{}{}", "  ".repeat(r.depth), node.name)
            })
            .collect()
    }

    fn open_all(map: &Map) -> HashSet<String> {
        (0..map.len())
            .filter_map(|i| map.node(i))
            .filter(|n| n.kind.is_folder())
            .map(|n| n.key.clone())
            .collect()
    }

    #[test]
    fn the_root_folders_count_their_items_and_the_data_holds_globals_then_strings() {
        let item = |name: &str, address: u64| Item {
            name: name.to_owned(),
            address,
        };
        let input = Input {
            file: "a.out".to_owned(),
            functions: vec![
                function("main", 0x10, Some("src/a.c")),
                function("helper", 0x20, Some("src/b.c")),
            ],
            // The import's pointer slot, found as a global too, is the
            // import's.
            imports: vec![Import {
                name: "puts".to_owned(),
                library: None,
                address: 0x4200,
            }],
            data: vec![
                item("table", 0x4000),
                item("g_4100", 0x4100),
                item("puts_ptr", 0x4200),
            ],
            // One string is the named global's bytes: the global's name
            // stays.
            strings: vec![item("\"usage\"", 0x2000), item("\"t\"", 0x4000)],
            types: vec!["struct a".to_owned(), "struct a".to_owned()],
            ..Input::default()
        };
        let map = Map::build(&input);
        let open = HashSet::from([
            super::ROOT.to_owned(),
            Group::Data.key().to_owned(),
            "/data/globals".to_owned(),
            "/data/strings".to_owned(),
        ]);
        let rows = map.rows(&open, "");
        let counted: Vec<(String, Kind, Option<usize>)> = rows
            .iter()
            .filter_map(|r| map.node(r.node))
            .map(|n| (n.name.clone(), n.kind, n.count))
            .collect();
        let folder = |group: Group, count: usize| {
            (group.title().to_owned(), Kind::Group(group), Some(count))
        };
        let leaf = |name: &str, kind: Kind| (name.to_owned(), kind, None);
        let sub = |name: &str, count: usize| (name.to_owned(), Kind::Folder, Some(count));
        assert_eq!(
            counted,
            vec![
                ("a.out".to_owned(), Kind::File, None),
                folder(Group::Sections, 0),
                // The functions under their units' folders, counted.
                folder(Group::Functions, 2),
                folder(Group::Imports, 1),
                folder(Group::Exports, 0),
                folder(Group::Data, 3),
                sub("Globals", 2),
                leaf("table", Kind::Data),
                leaf("g_4100", Kind::Data),
                sub("Strings", 1),
                leaf("\"usage\"", Kind::String),
                // The type listed twice is one.
                folder(Group::Types, 1),
            ]
        );
        // No strings found yet: no Strings folder.
        let none = Map::build(&Input {
            strings: Vec::new(),
            ..input
        });
        let names: Vec<&str> = (0..none.len())
            .filter_map(|i| none.node(i))
            .filter(|n| n.kind == Kind::Folder)
            .map(|n| n.name.as_str())
            .collect();
        assert!(
            names.contains(&"Globals") && !names.contains(&"Strings"),
            "{names:?}"
        );
    }

    #[test]
    fn scopes_split_outside_templates_and_parameters() {
        assert_eq!(
            split_scope("std::vector<std::pair<int, int>>::push_back(std::pair<int, int> const&)"),
            (
                vec!["std".to_owned(), "vector<std::pair<int, int>>".to_owned()],
                "push_back(std::pair<int, int> const&)".to_owned()
            )
        );
        assert_eq!(split_scope("main"), (Vec::new(), "main".to_owned()));
        assert_eq!(
            split_scope("f(std::string)"),
            (Vec::new(), "f(std::string)".to_owned())
        );
        assert_eq!(
            split_scope("ns::operator<<(int)"),
            (vec!["ns".to_owned()], "operator<<(int)".to_owned())
        );
    }

    #[test]
    fn functions_group_by_scope_folding_single_folder_chains() {
        let input = Input {
            file: "libstdc++.so.6".to_owned(),
            functions: vec![
                function(
                    "std::__cxx11::basic_string<char>::append(char const*)",
                    0x30,
                    None,
                ),
                function("std::__cxx11::basic_string<char>::size() const", 0x20, None),
                function("std::locale::locale()", 0x40, None),
                function("abort_message", 0x10, None),
            ],
            ..Input::default()
        };
        let map = Map::build(&input);
        let mut open = open_all(&map);
        open.remove("/sections");
        let rows = map.rows(&open, "");
        let lines = shown(&map, &rows);
        let functions = lines.iter().position(|l| l == "  Functions").unwrap();
        assert_eq!(
            lines[functions + 1..functions + 8],
            [
                "    std",
                "      __cxx11::basic_string<char>",
                "        size() const",
                "        append(char const*)",
                "      locale",
                "        locale()",
                "    abort_message",
            ]
        );
    }

    /// Functions a signature names sit under their library and object
    /// (folded as paths are), an object of one function only that
    /// function; the others are grouped as they would be alone (here
    /// flat, though a library function's object is a path).
    #[test]
    fn library_functions_group_by_library_and_object() {
        let library = |name: &str, address: u64, object: &str| Function {
            library: Some(("musl 1.2.5".to_owned(), object.to_owned())),
            ..function(name, address, None)
        };
        let input = Input {
            file: "wc".to_owned(),
            functions: vec![
                library("strcpy", 0x30, "src/string/strcpy.o"),
                library("__stpcpy", 0x50, "src/string/strcpy.o"),
                library("strlen", 0x20, "src/string/strlen.o"),
                library("exit", 0x40, "src/exit/exit.o"),
                function("sub_10", 0x10, None),
            ],
            ..Input::default()
        };
        let map = Map::build(&input);
        let rows = map.rows(&open_all(&map), "");
        let lines = shown(&map, &rows);
        let functions = lines.iter().position(|l| l == "  Functions").unwrap();
        assert_eq!(
            lines[functions + 1..functions + 9],
            [
                "    musl 1.2.5",
                "      src",
                "        string",
                "          strcpy.o",
                "            strcpy",
                "            __stpcpy",
                "          strlen",
                "        exit",
            ]
        );
        assert_eq!(lines[functions + 9], "    sub_10");
    }

    #[test]
    fn functions_group_by_unit_under_the_common_directory() {
        let input = Input {
            file: "python313.dll".to_owned(),
            functions: vec![
                function(
                    "PyList_Append",
                    0x200,
                    Some("C:\\py\\Objects\\listobject.c"),
                ),
                function("PyDict_New", 0x100, Some("C:\\py\\Objects\\dictobject.c")),
                function("list_dealloc", 0x180, Some("C:\\py\\Objects\\listobject.c")),
                function("Py_Main", 0x300, Some("C:\\py\\Modules\\main.c")),
                function(
                    "hash_new",
                    0x400,
                    Some("C:\\py\\Modules\\_hashlib\\impl\\hash.c"),
                ),
                function("_DllMainCRTStartup", 0x10, None),
            ],
            ..Input::default()
        };
        let map = Map::build(&input);
        let rows = map.rows(&open_all(&map), "");
        let lines = shown(&map, &rows);
        let functions = lines.iter().position(|l| l == "  Functions").unwrap();
        // Folders by path below the shared `C:\py\`; a folder holding only
        // one folder folds into it (`_hashlib/impl/hash.c`).
        assert_eq!(
            lines[functions + 1..functions + 13],
            [
                "    Modules",
                "      _hashlib/impl/hash.c",
                "        hash_new",
                "      main.c",
                "        Py_Main",
                "    Objects",
                "      dictobject.c",
                "        PyDict_New",
                "      listobject.c",
                "        list_dealloc",
                "        PyList_Append",
                "    _DllMainCRTStartup",
            ]
        );
    }

    #[test]
    fn plain_functions_stay_flat_by_address_and_imports_group_by_library() {
        let input = Input {
            file: "bash".to_owned(),
            functions: vec![function("main", 0x20, None), function("_start", 0x10, None)],
            imports: vec![
                Import {
                    name: "malloc".to_owned(),
                    library: Some("libc.so.6".to_owned()),
                    address: 0x1000,
                },
                Import {
                    name: "tgetent".to_owned(),
                    library: Some("libtinfo.so.6".to_owned()),
                    address: 0x1008,
                },
                Import {
                    name: "free".to_owned(),
                    library: Some("libc.so.6".to_owned()),
                    address: 0x1010,
                },
                Import {
                    name: "Sleep".to_owned(),
                    library: Some("KERNEL32.dll".to_owned()),
                    address: 0x1018,
                },
                Import {
                    name: "BCryptGenRandom".to_owned(),
                    library: Some("bcrypt.dll".to_owned()),
                    address: 0x1020,
                },
            ],
            exports: vec![Item {
                name: "main".to_owned(),
                address: 0x20,
            }],
            types: vec![
                "struct b".to_owned(),
                "struct a".to_owned(),
                "struct a".to_owned(),
            ],
            ..Input::default()
        };
        let map = Map::build(&input);
        assert_eq!(Map::grouping(&input.functions), super::Grouping::Flat);
        let rows = map.rows(&open_all(&map), "");
        assert_eq!(
            shown(&map, &rows),
            [
                "bash",
                "  Sections",
                "  Functions",
                "    _start",
                "    main",
                "  Imports",
                "    bcrypt.dll",
                "      BCryptGenRandom",
                "    KERNEL32.dll",
                "      Sleep",
                "    libc.so.6",
                "      free",
                "      malloc",
                "    libtinfo.so.6",
                "      tgetent",
                "  Exports",
                "    main",
                "  Data",
                "  Types",
                "    struct a",
                "    struct b",
            ]
        );
        let tgetent = rows
            .iter()
            .find(|r| map.node(r.node).unwrap().name == "tgetent")
            .unwrap();
        assert_eq!(map.node(tgetent.node).unwrap().kind, Kind::Import);
        assert_eq!(map.node(tgetent.node).unwrap().address, Some(0x1008));
        let library = map.parent(tgetent.node).unwrap();
        assert_eq!(map.node(library).unwrap().kind, Kind::Library);
    }

    #[test]
    fn closed_folders_hide_their_content_and_default_shows_functions() {
        let input = Input {
            file: "bash".to_owned(),
            sections: vec![Item {
                name: ".text".to_owned(),
                address: 0x10,
            }],
            functions: vec![function("main", 0x20, None)],
            ..Input::default()
        };
        let map = Map::build(&input);
        let rows = map.rows(&Map::default_open(), "");
        assert_eq!(
            shown(&map, &rows),
            [
                "bash",
                "  Sections",
                "  Functions",
                "    main",
                "  Imports",
                "  Exports",
                "  Data",
                "  Types"
            ]
        );
        assert!(rows[0].open && !rows[1].open && rows[2].open);
        let functions = map.node(rows[2].node).unwrap();
        assert_eq!(functions.kind, Kind::Group(Group::Functions));
        assert_eq!(map.rows(&HashSet::<String>::new(), "").len(), 1);
    }

    #[test]
    fn the_filter_shows_matches_under_open_folders_whatever_is_open() {
        let input = Input {
            file: "libstdc++.so.6".to_owned(),
            functions: vec![
                function("std::locale::locale()", 0x40, None),
                function("std::locale::name() const", 0x50, None),
                function("std::ios_base::Init::Init()", 0x60, None),
                function("abort_message", 0x10, None),
            ],
            ..Input::default()
        };
        let map = Map::build(&input);
        let rows = map.rows(&HashSet::<String>::new(), "name");
        assert_eq!(
            shown(&map, &rows),
            [
                "libstdc++.so.6",
                "  Functions",
                "    std",
                "      locale",
                "        name() const",
            ]
        );
        assert!(rows[..4].iter().all(|r| r.open));
        assert_eq!(rows[4].positions, vec![0, 1, 2, 3]);
        assert_eq!(map.rows(&Map::default_open(), "zzzz").len(), 1);
    }

    /// A synthesised struct of key `key`, born in `main`.
    fn synthesised(key: &str, k: u32) -> Synthesised {
        Synthesised {
            function: 0x20,
            k,
            key: key.to_owned(),
            size: 16,
            c: format!("{key} {{\n    int64_t field_0;\n    int64_t field_8;\n}};"),
            stated: false,
        }
    }

    #[test]
    fn the_types_list_the_synthesised_structs_once_the_table_is_found_and_again_when_renamed() {
        let mut types = TypeNames::default();
        let mut read = 0;
        let mut classes = || {
            read += 1;
            vec!["Shape".to_owned()]
        };
        let user = || vec!["struct pair".to_owned()];
        // The map's first build: no table yet.
        assert!(!types.take(None));
        assert_eq!(types.names(&mut classes, user()), ["Shape", "struct pair"]);
        // The callers pass found it: the map is built again with its structs.
        let table = Arc::new(vec![synthesised("struct struct_main_1", 1)]);
        assert!(types.take(Some(Arc::clone(&table))));
        let names = types.names(&mut classes, user());
        assert_eq!(names, ["Shape", "struct struct_main_1", "struct pair"]);
        let input = Input {
            file: "bash".to_owned(),
            types: names,
            ..Input::default()
        };
        let map = Map::build(&input);
        let rows = map.rows(&HashSet::<String>::new(), "struct_main_1");
        assert_eq!(
            shown(&map, &rows),
            ["bash", "  Types", "    struct struct_main_1"]
        );
        assert_eq!(map.node(rows[2].node).unwrap().kind, Kind::Type);
        // The same list, or the table being found again: nothing to build.
        assert!(!types.take(Some(Arc::clone(&table))));
        assert!(!types.take(None));
        // Found again with the same names (a definition's text changed).
        let mut edited = synthesised("struct struct_main_1", 1);
        edited.c = "struct struct_main_1 {\n    void *top;\n    int64_t n;\n};".to_owned();
        assert!(!types.take(Some(Arc::new(vec![edited]))));
        // The user's version renames it.
        let mut renamed = synthesised("struct frame", 1);
        renamed.stated = true;
        assert!(types.take(Some(Arc::new(vec![renamed]))));
        assert_eq!(
            types.names(&mut classes, user()),
            ["Shape", "struct frame", "struct pair"]
        );
        assert_eq!(read, 1, "the classes are read once");
    }

    #[test]
    fn bookmarks_are_pinned_first_only_when_there_are_some_and_folders_list_their_items() {
        let item = |name: &str, address| Item {
            name: name.to_owned(),
            address,
        };
        let mut input = Input {
            file: "sh".to_owned(),
            functions: vec![
                function("main", 0x30, None),
                function("lib::parse", 0x20, None),
                function("lib::glob", 0x10, None),
            ],
            imports: vec![
                Import {
                    name: "read".to_owned(),
                    library: Some("libc.so.6".to_owned()),
                    address: 0x90,
                },
                Import {
                    name: "tgetent".to_owned(),
                    library: Some("libtinfo.so.6".to_owned()),
                    address: 0x98,
                },
            ],
            ..Input::default()
        };
        let groups = |map: &Map| -> Vec<String> {
            map.node(0)
                .unwrap()
                .children
                .iter()
                .map(|&c| map.node(c).unwrap().name.clone())
                .collect()
        };
        let map = Map::build(&input);
        assert_eq!(groups(&map).first().map(String::as_str), Some("Sections"));
        assert_eq!(map.folder("/bookmarks"), None);
        input.bookmarks = vec![item("later", 0x40), item("start", 0x30)];
        let map = Map::build(&input);
        assert_eq!(groups(&map).first().map(String::as_str), Some("Bookmarks"));
        let rows = map.rows(&Map::default_open(), "");
        assert_eq!(
            shown(&map, &rows).get(..4).unwrap(),
            ["sh", "  Bookmarks", "    start", "    later"]
        );
        let bookmark = map.node(rows[2].node).unwrap();
        assert_eq!(
            (bookmark.kind, bookmark.address),
            (Kind::Bookmark, Some(0x30))
        );
        // A folder's items, its folders' too, each with its folder.
        let functions = map.folder("/functions").unwrap();
        let names = |leaves: &[(usize, usize)]| -> Vec<(String, String)> {
            leaves
                .iter()
                .map(|&(n, f)| {
                    (
                        map.node(n).unwrap().name.clone(),
                        map.node(f).unwrap().name.clone(),
                    )
                })
                .collect()
        };
        let pair = |a: &str, b: &str| (a.to_owned(), b.to_owned());
        // The folder's own first, then its folders'.
        assert_eq!(
            names(&map.leaves(functions)),
            [
                pair("main", "Functions"),
                pair("glob", "lib"),
                pair("parse", "lib")
            ]
        );
        let lib = map.folder("/functions/lib").unwrap();
        assert_eq!(
            names(&map.leaves(lib)),
            [pair("glob", "lib"), pair("parse", "lib")]
        );
        let imports = map.folder("/imports").unwrap();
        assert_eq!(
            names(&map.leaves(imports)),
            [pair("read", "libc.so.6"), pair("tgetent", "libtinfo.so.6")]
        );
        // A leaf is no folder; a key's group is its prefix's.
        assert_eq!(map.folder("/functions/lib/glob"), None);
        assert_eq!(Group::of_key("/functions/lib"), Some(Group::Functions));
        assert_eq!(Group::of_key("/imports/libc.so.6"), Some(Group::Imports));
        assert_eq!(Group::of_key("/bookmarks"), Some(Group::Bookmarks));
        assert_eq!(Group::of_key("/functionsx"), None);
        assert_eq!(Group::of_key("/"), None);
    }

    #[test]
    fn ones_own_bookmarks_come_first_then_a_closed_folder_per_other_person() {
        let item = |name: &str, address| Item {
            name: name.to_owned(),
            address,
        };
        let (bob, carol) = (PublicKey([2; 32]), PublicKey([3; 32]));
        // Someone else's alone show the folder too.
        let alone = Input {
            others: vec![Shelf {
                key: bob,
                name: "Bob".to_owned(),
                items: vec![item("his", 0x10)],
            }],
            ..Input::default()
        };
        assert!(Map::build(&alone).folder("/bookmarks").is_some());
        // One's own, shared and private, by address; then a folder per
        // person by name, case aside, closed at first.
        let input = Input {
            file: "sh".to_owned(),
            bookmarks: vec![item("later", 0x40), item("start", 0x30)],
            private: vec![item("mine only", 0x38)],
            others: vec![
                Shelf {
                    key: carol,
                    name: "carol".to_owned(),
                    items: vec![item("hers", 0x50)],
                },
                Shelf {
                    key: bob,
                    name: "Bob".to_owned(),
                    items: vec![item("b2", 0x60), item("b1", 0x20)],
                },
                // One whose bookmarks are all gone has no folder.
                Shelf {
                    key: PublicKey([4; 32]),
                    name: "Dan".to_owned(),
                    items: Vec::new(),
                },
            ],
            ..Input::default()
        };
        let people = Map::build(&input);
        let rows = people.rows(&Map::default_open(), "");
        assert_eq!(
            shown(&people, &rows).get(1..7).unwrap(),
            [
                "  Bookmarks",
                "    start",
                "    mine only",
                "    later",
                "    Bob",
                "    carol"
            ]
        );
        let kinds: Vec<Kind> = rows[2..5]
            .iter()
            .map(|r| people.node(r.node).unwrap().kind)
            .collect();
        assert_eq!(
            kinds,
            [Kind::Bookmark, Kind::PrivateBookmark, Kind::Bookmark]
        );
        // Opened, Bob's folder holds his, by address, each his.
        let bob_key = person_key(bob);
        let folder = people.folder(&bob_key).unwrap();
        assert_eq!(people.node(folder).unwrap().author, Some(bob));
        let mut open = Map::default_open();
        open.insert(bob_key);
        let rows = people.rows(&open, "");
        let his: Vec<(&str, Kind, Option<PublicKey>)> = rows[6..8]
            .iter()
            .map(|r| {
                let n = people.node(r.node).unwrap();
                (n.name.as_str(), n.kind, n.author)
            })
            .collect();
        assert_eq!(
            his,
            [
                ("b1", Kind::TheirBookmark, Some(bob)),
                ("b2", Kind::TheirBookmark, Some(bob))
            ]
        );
        // A person's folder opens as the bookmarks' tab.
        assert_eq!(Group::of_key(&person_key(carol)), Some(Group::Bookmarks));
    }
}
