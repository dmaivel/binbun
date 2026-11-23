//! Compiling the decode-time checks (`undefined.rs` and the syntax-reserved
//! values of `reserved.rs`) into per-encoding tests.

use xtask::aarchmrs::Package;

use super::cond::{self, field_mask};
use super::cube::{Cube, cubes};
use super::model::Encoding;
use super::reserved;
use super::undefined::{self, Check, Constraint, Kind, Select};
use crate::Result;

/// Most cubes a hand-written check compiles to before it becomes a table.
const MAX_CUBES: usize = 8;

/// Widest field concatenation a table may be indexed by.
const MAX_TABLE_BITS: u32 = 16;

/// A test of whether a word is rejected.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Test {
    /// The word is in one of the cubes (which leave out the encoding's fixed
    /// bits).
    Cubes(Vec<Cube>),
    /// Bit `index` of table `table` is set, `index` being the values of
    /// `fields` (lowest bit, width) concatenated, the first field most
    /// significant. For checks such as register overlaps, which are many
    /// cubes.
    Table {
        fields: Vec<(u32, u32)>,
        table: usize,
    },
}

/// The words of each encoding that decode-time checks reject.
#[derive(Debug, Default)]
pub struct Rejected {
    /// UNDEFINED: hand-written checks and syntax-reserved values.
    pub undefined: Vec<Vec<Test>>,
    /// CONSTRAINED UNPREDICTABLE words LLVM rejects.
    pub unpredictable: Vec<Vec<Test>>,
    /// The bit tables of [`Test::Table`], 64 bits per element.
    pub tables: Vec<Vec<u64>>,
}

impl Rejected {
    /// Encodings with tests and the number of tests (cubes and tables) of
    /// `lists`.
    pub fn count(lists: &[Vec<Test>]) -> (usize, usize) {
        let encodings = lists.iter().filter(|list| !list.is_empty()).count();
        let tests = lists
            .iter()
            .flatten()
            .map(|test| match test {
                Test::Cubes(cubes) => cubes.len(),
                Test::Table { .. } => 1,
            })
            .sum();
        (encodings, tests)
    }

    /// The index of a table with these bits, added if new.
    fn table(&mut self, bits: Vec<u64>) -> usize {
        if let Some(index) = self.tables.iter().position(|table| *table == bits) {
            return index;
        }
        self.tables.push(bits);
        self.tables.len() - 1
    }
}

/// What `constraint` rejects in `encoding`: cubes, or a table if the cubes
/// are many. `None` if it rejects nothing.
fn compile(
    constraint: &Constraint,
    encoding: &Encoding<'_>,
    rejected: &mut Rejected,
) -> Result<Option<Test>> {
    let (fields, when) = match constraint.check {
        Check::ShouldBe => {
            let should_be = encoding.should_be;
            let found = cubes(encoding.fixed, should_be.mask, |word| {
                !should_be.contains(word)
            })?;
            return Ok((!found.is_empty()).then_some(Test::Cubes(found)));
        }
        Check::Fields { fields, when } => (fields, when),
    };
    let ranges = field_ranges(encoding, fields)?;
    let values = |word: u32| -> Vec<u64> {
        ranges
            .iter()
            .map(|&range| cond::extract(word, range))
            .collect()
    };
    let bits = ranges
        .iter()
        .fold(0, |bits, &range| bits | field_mask(range));
    let found = cubes(encoding.fixed, bits, |word| when(&values(word)))?;
    if found.len() <= MAX_CUBES {
        return Ok((!found.is_empty()).then_some(Test::Cubes(found)));
    }
    let width: u32 = ranges.iter().map(|&(_, width)| width).sum();
    if width > MAX_TABLE_BITS {
        return Err(format!(
            "{}: a check over {width} bits is too wide for a table",
            encoding.name()
        )
        .into());
    }
    let mut table = vec![0u64; (1usize << width).div_ceil(64)];
    for index in 0..1u64 << width {
        let mut rest = index;
        let mut field_values = vec![0; ranges.len()];
        for (value, &(_, width)) in field_values.iter_mut().zip(&ranges).rev() {
            *value = rest & ((1 << width) - 1);
            rest >>= width;
        }
        if when(&field_values) {
            table[(index / 64) as usize] |= 1 << (index % 64);
        }
    }
    let table = rejected.table(table);
    Ok(Some(Test::Table {
        fields: ranges,
        table,
    }))
}

/// The `(lowest bit, width)` of each of `fields`, in order; fails on a field
/// the encoding does not have, so that values stay paired with their fields.
fn field_ranges(encoding: &Encoding<'_>, fields: &[&str]) -> Result<Vec<(u32, u32)>> {
    fields
        .iter()
        .map(|field| {
            encoding
                .field(field)
                .ok_or_else(|| format!("{} has no field {field}", encoding.name()).into())
        })
        .collect()
}

/// Checks that every encoding a `Names` or `AllExcept` selection names
/// exists.
fn check_names(encodings: &[Encoding<'_>]) -> Result<()> {
    for constraint in undefined::CONSTRAINTS {
        if let Select::Names(names) | Select::AllExcept(names) = constraint.select
            && let Some(missing) = names
                .iter()
                .find(|name| encodings.iter().all(|e| e.name() != **name))
        {
            return Err(format!("the UNDEFINED table names unknown encoding {missing}").into());
        }
    }
    Ok(())
}

/// Compiles every check for every encoding. Fails if a check names an
/// unknown encoding or field, or rejects no word at all.
pub fn rejected(encodings: &[Encoding<'_>], package: &Package) -> Result<Rejected> {
    check_names(encodings)?;
    let constraints = undefined::CONSTRAINTS;
    let mut effective = vec![false; constraints.len()];
    let mut rejected = Rejected::default();
    for encoding in encodings {
        let mut lists = [(Vec::new(), Vec::new()), (Vec::new(), Vec::new())];
        for (constraint, effective) in constraints.iter().zip(&mut effective) {
            if !constraint.select.selects(encoding.name()) {
                continue;
            }
            let Some(test) = compile(constraint, encoding, &mut rejected)? else {
                continue;
            };
            *effective = true;
            let (cubes, tables) = &mut lists[usize::from(constraint.kind == Kind::Unpredictable)];
            match test {
                Test::Cubes(found) => cubes.extend(found),
                table @ Test::Table { .. } => tables.push(table),
            }
        }
        for (fields, allowed) in reserved::reserved_values(encoding, &package.assembly_rules) {
            let ranges = field_ranges(encoding, &fields)?;
            let bits = ranges
                .iter()
                .fold(0, |bits, &range| bits | field_mask(range));
            lists[0].0.extend(cubes(encoding.fixed, bits, |word| {
                !allowed.iter().any(|patterns| {
                    patterns
                        .iter()
                        .zip(&ranges)
                        .all(|(pattern, &range)| pattern.matches(cond::extract(word, range)))
                })
            })?);
        }
        let [undefined, unpredictable] = lists.map(|(cubes, tables)| {
            let cubes = simplify(cubes);
            (!cubes.is_empty())
                .then_some(Test::Cubes(cubes))
                .into_iter()
                .chain(tables)
                .collect::<Vec<_>>()
        });
        rejected.undefined.push(undefined);
        rejected.unpredictable.push(unpredictable);
    }
    if let Some(index) = effective.iter().position(|effective| !effective) {
        return Err(format!("UNDEFINED table entry {index} rejects no word").into());
    }
    Ok(rejected)
}

/// `cubes` sorted, without duplicates and cubes inside others.
fn simplify(mut cubes: Vec<Cube>) -> Vec<Cube> {
    cubes.sort_unstable();
    cubes.dedup();
    cubes
        .iter()
        .enumerate()
        .filter(|&(i, cube)| {
            !cubes
                .iter()
                .enumerate()
                .any(|(j, other)| j != i && cube.within(*other))
        })
        .map(|(_, cube)| *cube)
        .collect()
}
