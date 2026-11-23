//! C++ classes: the program's table of the classes its run-time type
//! information shows (the Itanium C++ ABI's virtual tables and
//! `type_info` objects, read by `binbun`'s `classes`), which names the
//! structs that are them.
//!
//! - **A class** ([`CxxClass`]): its name (demangled), its `type_info`
//!   object, the address point of its primary virtual table (the address
//!   its objects' first word holds: past the offset to top and the
//!   `type_info` pointer), its virtual functions in slot order, and its
//!   primary base (the base class at offset 0 that is not virtual: a
//!   pointer to the class is a pointer to it).
//! - **Which struct is a class**: a struct whose first word receives a
//!   class's address point (a constructor's store), and the struct a
//!   method's `this` points to (a function in a primary virtual table
//!   whose mangling is a member of that class, or a constructor or
//!   destructor of it: [`Classes::method`]). A struct claimed by several
//!   classes is their nearest common primary base ([`Classes::join`]: a
//!   pointer that holds a `Square` or a `Rectangle` is a `Shape *`); by
//!   none if they have none.
//! - **Names**: a class's C identifier ([`Classes::identifier`]) is its
//!   name with `::` as `_` and every other character no identifier has
//!   as `_` (numbered where two would be one), its virtual table struct
//!   `<identifier>_vtbl`, the first field `vptr`, and the table's fields
//!   its slots' methods' names ([`Classes::slot`]: the last component of
//!   the mangling; a destructor `destructor`, a deleting one
//!   `deleting_destructor`), else `slot_<k>`.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

/// A C++ class of the program.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CxxClass {
    /// Its name, demangled (`std::exception`).
    pub name: String,
    /// Its `type_info` object, if found.
    pub type_info: Option<u64>,
    /// The address point of its primary virtual table, if the image has
    /// one.
    pub vtable: Option<u64>,
    /// Its virtual functions in slot order (`None`: not a function of the
    /// image, as `__cxa_pure_virtual` or an import).
    pub slots: Vec<Option<u64>>,
    /// The method name of each slot, if known (a C identifier).
    pub names: Vec<Option<String>>,
    /// Its primary base (index in the table): its base class at offset 0
    /// that is not virtual.
    pub base: Option<usize>,
}

/// The program's C++ classes.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Classes {
    /// The classes.
    table: Vec<CxxClass>,
    /// Each class's C identifier.
    identifiers: Vec<String>,
    /// Each class's slot names: its own, else those every class deriving
    /// from it agrees on.
    slots: Vec<Vec<Option<String>>>,
    /// The class of each primary virtual table, by address point.
    vtables: BTreeMap<u64, usize>,
    /// The class whose `this` each method takes, by entry.
    methods: BTreeMap<u64, usize>,
}

impl Classes {
    /// No classes.
    pub const fn empty() -> Self {
        Self {
            table: Vec::new(),
            identifiers: Vec::new(),
            slots: Vec::new(),
            vtables: BTreeMap::new(),
            methods: BTreeMap::new(),
        }
    }

    /// The table of `classes`, with the class whose `this` each method
    /// (by entry) takes.
    pub fn new(classes: Vec<CxxClass>, methods: BTreeMap<u64, usize>) -> Self {
        let mut taken: BTreeSet<String> = BTreeSet::new();
        let identifiers = classes
            .iter()
            .enumerate()
            .map(|(index, class)| {
                let plain = identifier(&class.name);
                let unique = if taken.contains(&plain) {
                    format!("{plain}_{index}")
                } else {
                    plain
                };
                taken.insert(unique.clone());
                unique
            })
            .collect();
        let vtables = classes
            .iter()
            .enumerate()
            .filter_map(|(index, class)| Some((class.vtable?, index)))
            .collect();
        let methods = methods
            .into_iter()
            .filter(|&(_, class)| class < classes.len())
            .collect();
        let mut table = Self {
            table: classes,
            identifiers,
            slots: Vec::new(),
            vtables,
            methods,
        };
        table.slots = (0..table.table.len())
            .map(|index| table.inherited(index))
            .collect();
        table
    }

    /// The slot names of class `index`: its own where it has a virtual
    /// table; else, slot by slot, the name every class deriving from it
    /// with a virtual table gives (an override keeps its method's name).
    fn inherited(&self, index: usize) -> Vec<Option<String>> {
        let Some(class) = self.table.get(index) else {
            return Vec::new();
        };
        if class.vtable.is_some() {
            return class.names.clone();
        }
        let derived: Vec<&CxxClass> = self
            .table
            .iter()
            .enumerate()
            .filter(|&(other, derived)| {
                other != index && derived.vtable.is_some() && self.derives(other, index)
            })
            .map(|(_, derived)| derived)
            .collect();
        let length = derived
            .iter()
            .map(|class| class.names.len())
            .min()
            .unwrap_or(0);
        (0..length)
            .map(|k| {
                let mut names = derived
                    .iter()
                    .map(|class| class.names.get(k).cloned().flatten());
                let first = names.next().flatten()?;
                names
                    .all(|name| name.as_deref() == Some(first.as_str()))
                    .then_some(first)
            })
            .collect()
    }

    /// Whether class `a` is class `b` or derives from it through primary
    /// bases.
    fn derives(&self, a: usize, b: usize) -> bool {
        self.primaries(a).any(|class| class == b)
    }

    /// Class `index` and its primary bases, nearest first.
    fn primaries(&self, index: usize) -> impl Iterator<Item = usize> + '_ {
        let mut seen = BTreeSet::new();
        core::iter::successors(Some(index), |&class| self.table.get(class)?.base)
            .take_while(move |&class| seen.insert(class))
    }

    /// The nearest class both `a` and `b` are (each itself or deriving
    /// from it through primary bases), if any.
    pub fn join(&self, a: usize, b: usize) -> Option<usize> {
        self.primaries(a).find(|&class| self.derives(b, class))
    }

    /// The class whose primary virtual table has its address point at
    /// `address`.
    pub fn at_vtable(&self, address: u64) -> Option<usize> {
        self.vtables.get(&address).copied()
    }

    /// The class whose `this` the function at `entry` takes, if it is a
    /// method of one ([`Self::new`]).
    pub fn method(&self, entry: u64) -> Option<usize> {
        self.methods.get(&entry).copied()
    }

    /// Class `index`.
    pub fn get(&self, index: usize) -> Option<&CxxClass> {
        self.table.get(index)
    }

    /// Class `index`'s C identifier.
    pub fn identifier(&self, index: usize) -> Option<&str> {
        self.identifiers.get(index).map(String::as_str)
    }

    /// The name of slot `k` of class `index`'s virtual table, if known.
    pub fn slot(&self, index: usize, k: u64) -> Option<&str> {
        let k = usize::try_from(k).ok()?;
        self.slots.get(index)?.get(k)?.as_deref()
    }

    /// How many classes there are.
    pub fn len(&self) -> usize {
        self.table.len()
    }

    /// Whether there are none.
    pub fn is_empty(&self) -> bool {
        self.table.is_empty()
    }

    /// How many classes have a primary virtual table in the image.
    pub fn vtables(&self) -> usize {
        self.vtables.len()
    }

    /// How many functions are methods of a class.
    pub fn methods(&self) -> usize {
        self.methods.len()
    }
}

/// `name` as a C identifier: `::` as `_`, every other character no
/// identifier has as `_`, runs of them as one, none at either end.
fn identifier(name: &str) -> String {
    let mut out = String::new();
    let mut pending = false;
    for c in name.chars() {
        if c.is_ascii_alphanumeric() || c == '_' {
            if pending && !out.is_empty() {
                out.push('_');
            }
            pending = false;
            out.push(c);
        } else {
            pending = true;
        }
    }
    if out.is_empty() || out.starts_with(|c: char| c.is_ascii_digit()) {
        out.insert_str(0, "class_");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn class(name: &str, vtable: Option<u64>, names: &[&str], base: Option<usize>) -> CxxClass {
        CxxClass {
            name: String::from(name),
            vtable,
            slots: names.iter().map(|_| None).collect(),
            names: names.iter().map(|name| Some(String::from(*name))).collect(),
            base,
            ..CxxClass::default()
        }
    }

    /// A base without a virtual table of its own takes the slot names its
    /// derived classes agree on; the join of two siblings is their base,
    /// of a class and its base the base, of unrelated classes none.
    #[test]
    fn joins_and_inherited_slots() {
        let classes = Classes::new(
            vec![
                class("Shape", None, &[], None),
                class(
                    "Square",
                    Some(0x10),
                    &["destructor", "deleting_destructor", "area", "name"],
                    Some(0),
                ),
                class(
                    "Rectangle",
                    Some(0x40),
                    &["destructor", "deleting_destructor", "area", "name", "extra"],
                    Some(0),
                ),
                class("std::exception", Some(0x80), &["what"], None),
            ],
            BTreeMap::new(),
        );
        assert_eq!(classes.join(1, 2), Some(0));
        assert_eq!(classes.join(1, 0), Some(0));
        assert_eq!(classes.join(1, 1), Some(1));
        assert_eq!(classes.join(1, 3), None);
        assert_eq!(classes.slot(0, 2), Some("area"));
        assert_eq!(classes.slot(0, 4), None);
        assert_eq!(classes.identifier(3), Some("std_exception"));
    }

    /// Names that are one identifier are numbered apart.
    #[test]
    fn identifiers_are_unique() {
        let classes = Classes::new(
            vec![
                class("a::b", None, &[], None),
                class("a_b", None, &[], None),
                class("std::pair<int, long>", None, &[], None),
            ],
            BTreeMap::new(),
        );
        assert_eq!(classes.identifier(0), Some("a_b"));
        assert_eq!(classes.identifier(1), Some("a_b_1"));
        assert_eq!(classes.identifier(2), Some("std_pair_int_long"));
    }
}
