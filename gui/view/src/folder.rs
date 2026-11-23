//! A folder of the map opened as a tab (Open as Tab): the folder's items
//! as a table of rows (the name, the
//! address, and the columns the items' kind has: a function's or a
//! section's size, an import's library, a global's type), sorted by any
//! column and filtered by what is typed, as the map's tree filters.

use std::cmp::Ordering;

use crate::fuzzy::Query;
use crate::map::Group;

/// A column of a folder's table.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Column {
    /// The item's name.
    Name,
    /// Its address.
    #[default]
    Address,
    /// Its size in bytes (a function's, a section's).
    Size,
    /// The library it comes from (an import).
    Library,
    /// Its type (a global).
    Type,
    /// How many references there are to it (a function's).
    Refs,
}

impl Column {
    /// Its title.
    pub fn title(self) -> &'static str {
        match self {
            Self::Name => "Name",
            Self::Address => "Address",
            Self::Size => "Size",
            Self::Library => "Library",
            Self::Type => "Type",
            Self::Refs => "Refs",
        }
    }
}

/// The columns of a folder of `group`, in order.
pub fn columns(group: Group) -> &'static [Column] {
    use Column as C;
    match group {
        Group::Functions => &[C::Name, C::Address, C::Size, C::Refs],
        Group::Sections => &[C::Name, C::Address, C::Size],
        Group::Imports => &[C::Name, C::Address, C::Library],
        Group::Data => &[C::Name, C::Address, C::Type],
        Group::Bookmarks | Group::Exports => &[C::Name, C::Address],
        Group::Types => &[C::Name],
    }
}

/// A row of a folder's table.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Row {
    /// The item's name.
    pub name: String,
    /// Its address (a type has none).
    pub address: Option<u64>,
    /// Its size in bytes, if its kind has one.
    pub size: Option<u64>,
    /// Its library, if it is an import.
    pub library: Option<String>,
    /// Its type, if known.
    pub ty: Option<String>,
    /// How many references there are to it, once counted (a function's).
    pub refs: Option<usize>,
}

/// How a folder's table is sorted.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Sort {
    /// By which column.
    pub by: Column,
    /// Largest first.
    pub descending: bool,
}

impl Sort {
    /// Sorted by `by`: the other way if it already is, else ascending.
    #[must_use]
    pub fn toggled(self, by: Column) -> Self {
        Self {
            by,
            descending: self.by == by && !self.descending,
        }
    }
}

/// The order of `rows` under `sort`: indices of `rows`. A row without
/// the column's value comes last either way; ties go by address, then
/// name.
pub fn order(rows: &[Row], sort: Sort) -> Vec<usize> {
    let directed = |o: Ordering| if sort.descending { o.reverse() } else { o };
    let mut out: Vec<usize> = (0..rows.len()).collect();
    out.sort_by(|&a, &b| {
        let (Some(x), Some(y)) = (rows.get(a), rows.get(b)) else {
            return Ordering::Equal;
        };
        let first = match sort.by {
            Column::Name => directed(x.name.to_lowercase().cmp(&y.name.to_lowercase())),
            Column::Address => known(x.address, y.address, directed),
            Column::Size => known(x.size, y.size, directed),
            Column::Library => known(x.library.as_deref(), y.library.as_deref(), directed),
            Column::Type => known(x.ty.as_deref(), y.ty.as_deref(), directed),
            Column::Refs => known(x.refs, y.refs, directed),
        };
        first
            .then_with(|| x.address.cmp(&y.address))
            .then_with(|| x.name.cmp(&y.name))
    });
    out
}

/// `a` against `b` as `directed` orders them, a missing value after
/// either way.
fn known<T: Ord>(a: Option<T>, b: Option<T>, directed: impl Fn(Ordering) -> Ordering) -> Ordering {
    match (a, b) {
        (Some(a), Some(b)) => directed(a.cmp(&b)),
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        (None, None) => Ordering::Equal,
    }
}

/// The type of a global declared as `c` (as the C prints it) named
/// `name`: the declaration without the name (`uint32_t g_4010[4]` →
/// `uint32_t[4]`, `char *p` → `char *`); `None` if `name` is not a word of
/// it.
pub fn declared_type(c: &str, name: &str) -> Option<String> {
    let is_word = |ch: char| ch.is_alphanumeric() || ch == '_';
    let (at, _) = c.match_indices(name).find(|&(at, name)| {
        c.get(..at).is_some_and(|b| !b.ends_with(is_word))
            && c.get(at + name.len()..)
                .is_some_and(|a| !a.starts_with(is_word))
    })?;
    let before = c.get(..at)?.trim_end();
    let after = c.get(at + name.len()..)?.trim();
    Some(format!("{before}{after}"))
}

/// The rows of `order` whose names match `filter` (as the map's tree
/// matches: fuzzily, case-blind unless it has a capital), in that order,
/// each with its name's matched byte positions.
pub fn filtered(rows: &[Row], order: &[usize], filter: &str) -> Vec<(usize, Vec<usize>)> {
    let query = Query::new(filter);
    order
        .iter()
        .filter_map(|&i| {
            let row = rows.get(i)?;
            if query.is_empty() {
                return Some((i, Vec::new()));
            }
            query.score(&row.name).map(|m| (i, m.positions))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{Column, Row, Sort, declared_type, filtered, order};

    fn row(name: &str, address: u64, size: Option<u64>, library: Option<&str>) -> Row {
        Row {
            name: name.to_owned(),
            address: Some(address),
            size,
            library: library.map(str::to_owned),
            ty: None,
            refs: None,
        }
    }

    fn names(rows: &[Row], order: &[usize]) -> Vec<String> {
        order.iter().map(|&i| rows[i].name.clone()).collect()
    }

    #[test]
    fn rows_sort_by_each_column_unknowns_last_ties_by_address() {
        let rows = vec![
            row("strlen", 0x30, Some(16), Some("libc.so.6")),
            row("Main", 0x10, Some(400), None),
            row("abort", 0x20, None, Some("libc.so.6")),
            row("tgetent", 0x40, Some(16), Some("libtinfo.so.6")),
        ];
        let by = |by, descending| names(&rows, &order(&rows, Sort { by, descending }));
        assert_eq!(
            by(Column::Address, false),
            ["Main", "abort", "strlen", "tgetent"]
        );
        assert_eq!(
            by(Column::Address, true),
            ["tgetent", "strlen", "abort", "Main"]
        );
        // Names case-blind.
        assert_eq!(
            by(Column::Name, false),
            ["abort", "Main", "strlen", "tgetent"]
        );
        // Equal sizes by address; no size last, descending too.
        assert_eq!(
            by(Column::Size, false),
            ["strlen", "tgetent", "Main", "abort"]
        );
        assert_eq!(
            by(Column::Size, true),
            ["Main", "strlen", "tgetent", "abort"]
        );
        assert_eq!(
            by(Column::Library, false),
            ["abort", "strlen", "tgetent", "Main"]
        );
        assert_eq!(
            by(Column::Library, true),
            ["tgetent", "abort", "strlen", "Main"]
        );
    }

    #[test]
    fn a_header_click_sorts_then_reverses() {
        let sort = Sort::default();
        assert_eq!(
            sort,
            Sort {
                by: Column::Address,
                descending: false
            }
        );
        let sort = sort.toggled(Column::Size);
        assert_eq!(
            sort,
            Sort {
                by: Column::Size,
                descending: false
            }
        );
        let sort = sort.toggled(Column::Size);
        assert!(sort.descending);
        assert_eq!(
            sort.toggled(Column::Size),
            Sort {
                by: Column::Size,
                descending: false
            }
        );
        assert_eq!(
            sort.toggled(Column::Name),
            Sort {
                by: Column::Name,
                descending: false
            }
        );
    }

    #[test]
    fn the_filter_keeps_the_sorted_order_and_marks_the_matches() {
        let rows = vec![
            row("parse_word", 0x30, None, None),
            row("main", 0x10, None, None),
            row("parse_args", 0x20, None, None),
        ];
        let sorted = order(&rows, Sort::default());
        let all = filtered(&rows, &sorted, "");
        assert_eq!(all, [(1, vec![]), (2, vec![]), (0, vec![])]);
        let found = filtered(&rows, &sorted, "pars");
        assert_eq!(
            found.iter().map(|(i, _)| *i).collect::<Vec<_>>(),
            [2, 0],
            "in the sorted order, not by score"
        );
        assert_eq!(found[0].1, [0, 1, 2, 3]);
        // Fuzzy, as the tree: the letters in order, not together.
        assert_eq!(filtered(&rows, &sorted, "pwd").len(), 1);
        assert_eq!(filtered(&rows, &sorted, "xyz"), []);
        // A capital asks for its case.
        assert_eq!(filtered(&rows, &sorted, "Main"), []);
    }

    #[test]
    fn a_globals_type_is_its_declaration_without_its_name() {
        assert_eq!(
            declared_type("uint32_t g_4010[4]", "g_4010").as_deref(),
            Some("uint32_t[4]")
        );
        assert_eq!(
            declared_type("struct user current_user", "current_user").as_deref(),
            Some("struct user")
        );
        assert_eq!(declared_type("char *p", "p").as_deref(), Some("char *"));
        // The name as a word, not inside another (`n` in `int`).
        assert_eq!(declared_type("int n", "n").as_deref(), Some("int"));
        assert_eq!(
            declared_type("struct n_s n", "n").as_deref(),
            Some("struct n_s")
        );
        assert_eq!(declared_type("int count", "g"), None);
    }
}
