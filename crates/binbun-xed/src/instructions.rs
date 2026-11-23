//! Instruction records: the `{ KEY : value … }` blocks in sections whose name
//! contains `INSTRUCTIONS` (XED's `read_structured_input`).
//!
//! A section body holds records, `UDELETE : uname` lines that drop the record
//! with that `UNAME`, and `DELETE : iclass` lines that drop every record of an
//! iclass. Sections with the same name form one [`Table`]; deletions apply to
//! the whole table regardless of where they appear in it.
//!
//! Values are kept as written. Interpreting them (pattern tokens, operand
//! specifiers, flag effects) is left to the modules that consume them.

use std::cmp::Ordering;
use std::collections::HashMap;
use std::collections::hash_map::Entry;

use crate::lines::Line;
use crate::section::{Datafile, Section};
use crate::{Error, ErrorKind};

/// All records of one instruction nonterminal, e.g. `INSTRUCTIONS` or
/// `EVEX_INSTRUCTIONS`, before deletions and version selection.
#[derive(Debug, Clone, Default)]
pub struct Table<'a> {
    /// Section name, e.g. `AVX_INSTRUCTIONS`.
    pub name: &'a str,
    /// Records in file order.
    pub records: Vec<Record<'a>>,
    /// `UNAME`s named by `UDELETE` lines.
    pub deleted_unames: Vec<&'a str>,
    /// Iclasses named by `DELETE` lines.
    pub deleted_iclasses: Vec<&'a str>,
}

/// One `{ … }` instruction record.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Record<'a> {
    /// Line of the opening `{`.
    pub line: u32,
    /// `ICLASS`, the instruction class (roughly the mnemonic).
    pub iclass: &'a str,
    /// `UNAME`, a unique name `UDELETE` can refer to.
    pub uname: Option<&'a str>,
    /// `VERSION`; records of an iclass with a higher version replace lower ones. Defaults to 0.
    pub version: u32,
    /// `CATEGORY`.
    pub category: &'a str,
    /// `EXTENSION`.
    pub extension: &'a str,
    /// `ISA_SET`; defaults to the extension.
    pub isa_set: &'a str,
    /// `CPL`: the least privileged ring allowed to execute the instruction (`0` or `3`).
    pub cpl: Option<&'a str>,
    /// `ATTRIBUTES`, as written. XED compares them in uppercase.
    pub attributes: Vec<&'a str>,
    /// `FLAGS`: the flag-effect specification, unparsed.
    pub flags: Option<&'a str>,
    /// `EXCEPTIONS`: the exception class.
    pub exceptions: Option<&'a str>,
    /// `DISASM` or `DISASM_INTEL`: an Intel-syntax mnemonic override.
    pub disasm_intel: Option<&'a str>,
    /// `DISASM` or `DISASM_ATTSV`: an AT&T-syntax mnemonic override.
    pub disasm_att: Option<&'a str>,
    /// `UCODE`.
    pub ucode: Option<&'a str>,
    /// `COMMENT`.
    pub comment: Option<&'a str>,
    /// `PATTERN` / `OPERANDS` / `IFORM` groups, at least one.
    pub forms: Vec<Form<'a>>,
    /// Keys XED stores without interpreting (for example `REAL_OPCODE`), in order.
    pub extra: Vec<(&'a str, &'a str)>,
}

impl<'a> Record<'a> {
    /// The value of an uninterpreted key such as `REAL_OPCODE`.
    pub fn extra(&self, key: &str) -> Option<&'a str> {
        self.extra
            .iter()
            .find_map(|&(k, value)| (k == key).then_some(value))
    }

    /// Whether the record has `attribute`, compared case-insensitively as XED does.
    pub fn has_attribute(&self, attribute: &str) -> bool {
        self.attributes
            .iter()
            .any(|a| a.eq_ignore_ascii_case(attribute))
    }
}

/// One encoding of a record: a decode pattern, its operands, and an
/// optional explicit iform name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Form<'a> {
    /// Line of the `PATTERN`.
    pub line: u32,
    /// `PATTERN`: the decode pattern, unparsed.
    pub pattern: &'a str,
    /// `OPERANDS`: the operand specifiers, unparsed. May be empty.
    pub operands: &'a str,
    /// `IFORM`, if the record names the iform instead of letting XED derive it.
    pub iform: Option<&'a str>,
}

impl<'a> Table<'a> {
    /// Records that survive `DELETE`, `UDELETE` and version selection, in the
    /// order XED's `remove_overridden_versions` produces.
    ///
    /// Within an iclass, a record with a higher `VERSION` than the ones kept
    /// so far replaces them, an equal version is kept alongside them, and a
    /// lower one is dropped. Iclasses keep the order in which their surviving
    /// version was first seen; a replaced iclass moves to the end.
    pub fn selected(&self) -> Vec<&Record<'a>> {
        // Slots in insertion order; a replaced iclass vacates its slot.
        let mut slots: Vec<Option<(u32, Vec<&Record<'a>>)>> = Vec::new();
        let mut slot_of: HashMap<&str, usize> = HashMap::new();
        for record in &self.records {
            let deleted = self.deleted_iclasses.contains(&record.iclass)
                || record
                    .uname
                    .is_some_and(|uname| self.deleted_unames.contains(&uname));
            if deleted {
                continue;
            }
            let next = slots.len();
            match slot_of.entry(record.iclass) {
                Entry::Vacant(entry) => {
                    entry.insert(next);
                    slots.push(Some((record.version, vec![record])));
                }
                Entry::Occupied(mut entry) => {
                    let slot = *entry.get();
                    let Some(Some((version, kept))) = slots.get_mut(slot) else {
                        unreachable!("every slot index in the map refers to an occupied slot");
                    };
                    match record.version.cmp(version) {
                        Ordering::Equal => kept.push(record),
                        Ordering::Greater => {
                            if let Some(old) = slots.get_mut(slot) {
                                *old = None;
                            }
                            entry.insert(next);
                            slots.push(Some((record.version, vec![record])));
                        }
                        Ordering::Less => {}
                    }
                }
            }
        }
        slots
            .into_iter()
            .flatten()
            .flat_map(|(_version, records)| records)
            .collect()
    }
}

/// Parses every instruction section of `file` into tables, merging sections
/// with the same name. Tables are in order of their first section.
///
/// # Errors
///
/// The first malformed line, see [`ErrorKind`].
pub fn parse<'a>(file: &'a Datafile<'_>) -> Result<Vec<Table<'a>>, Error> {
    let mut tables: Vec<Table<'a>> = Vec::new();
    for section in file.sections()? {
        if !section.header.name.contains("INSTRUCTIONS") {
            continue;
        }
        let existing = tables
            .iter()
            .position(|table| table.name == section.header.name);
        let index = existing.unwrap_or_else(|| {
            tables.push(Table {
                name: section.header.name,
                ..Table::default()
            });
            tables.len() - 1
        });
        if let Some(table) = tables.get_mut(index) {
            parse_section(&section, table)?;
        }
    }
    Ok(tables)
}

fn parse_section<'a>(section: &Section<'a>, table: &mut Table<'a>) -> Result<(), Error> {
    let mut lines = section.body.iter();
    while let Some(line) = lines.next() {
        let text = line.text();
        if text == "{" {
            table.records.push(parse_record(line.number, &mut lines)?);
        } else if let Some(uname) = directive(text, "UDELETE") {
            table.deleted_unames.push(uname);
        } else if let Some(iclass) = directive(text, "DELETE") {
            table.deleted_iclasses.push(iclass);
        } else {
            return Err(Error::new(line.number, ErrorKind::ExpectedRecord));
        }
    }
    Ok(())
}

/// `KEYWORD : value` with a single-word value.
fn directive<'a>(text: &'a str, keyword: &str) -> Option<&'a str> {
    let (key, value) = text.split_once(':')?;
    let value = value.trim();
    (key.trim() == keyword && !value.is_empty() && !value.contains(char::is_whitespace))
        .then_some(value)
}

/// Keys that may appear at most once per record (all but the form keys).
const SINGLE_KEYS: [&str; 15] = [
    "ICLASS",
    "UNAME",
    "CATEGORY",
    "EXTENSION",
    "ISA_SET",
    "STATE",
    "ATTRIBUTES",
    "UCODE",
    "FLAGS",
    "VERSION",
    "CPL",
    "COMMENT",
    "EXCEPTIONS",
    "DISASM_INTEL",
    "DISASM_ATTSV",
];

fn parse_record<'a>(
    open: u32,
    lines: &mut std::slice::Iter<'a, Line<'a>>,
) -> Result<Record<'a>, Error> {
    let mut builder = RecordBuilder {
        record: Record {
            line: open,
            ..Record::default()
        },
        seen: [false; SINGLE_KEYS.len()],
        isa_set: None,
        operands_pending: false,
    };
    loop {
        let Some(line) = lines.next() else {
            return Err(Error::new(open, ErrorKind::UnterminatedRecord));
        };
        let text = line.text();
        if text == "}" {
            return builder.finish(line.number);
        }
        let (key, value) = text
            .split_once(':')
            .map(|(key, value)| (key.trim(), value.trim()))
            .ok_or(Error::new(line.number, ErrorKind::MissingColon))?;
        builder.set(line.number, key, value)?;
    }
}

/// A record being read, with the bookkeeping XED's `read_structured_flexible` does.
struct RecordBuilder<'a> {
    record: Record<'a>,
    /// Which [`SINGLE_KEYS`] have been seen.
    seen: [bool; SINGLE_KEYS.len()],
    isa_set: Option<&'a str>,
    /// The last `PATTERN` has no `OPERANDS` yet.
    operands_pending: bool,
}

impl<'a> RecordBuilder<'a> {
    fn set(&mut self, line: u32, key: &'a str, value: &'a str) -> Result<(), Error> {
        if value.starts_with(':') {
            return Err(Error::new(line, ErrorKind::MalformedValue(key.to_owned())));
        }
        if let Some(slot) = SINGLE_KEYS.iter().position(|&single| single == key) {
            let already = self
                .seen
                .get_mut(slot)
                .is_none_or(|seen| std::mem::replace(seen, true));
            if already {
                let key = SINGLE_KEYS.get(slot).copied().unwrap_or_default();
                return Err(Error::new(line, ErrorKind::DuplicateKey(key)));
            }
        }
        let record = &mut self.record;
        match key {
            "ICLASS" => record.iclass = value,
            "UNAME" => record.uname = Some(value),
            "CATEGORY" => record.category = value,
            "EXTENSION" => record.extension = value,
            "ISA_SET" => self.isa_set = Some(value),
            "CPL" => record.cpl = Some(value),
            "ATTRIBUTES" => record.attributes = value.split_whitespace().collect(),
            "FLAGS" => record.flags = Some(value),
            "EXCEPTIONS" => record.exceptions = Some(value),
            "UCODE" => record.ucode = Some(value),
            "COMMENT" => record.comment = Some(value),
            "VERSION" => {
                record.version = value
                    .parse()
                    .map_err(|_| Error::new(line, ErrorKind::NotANumber(value.to_owned())))?;
            }
            "DISASM" => {
                record.disasm_intel = Some(value);
                record.disasm_att = Some(value);
            }
            "DISASM_INTEL" => record.disasm_intel = Some(value),
            "DISASM_ATTSV" => record.disasm_att = Some(value),
            "PATTERN" => {
                if self.operands_pending {
                    return Err(Error::new(line, ErrorKind::WithoutOperands));
                }
                record.forms.push(Form {
                    line,
                    pattern: value,
                    operands: "",
                    iform: None,
                });
                self.operands_pending = true;
            }
            "OPERANDS" => {
                let form = record.forms.last_mut();
                form.ok_or(Error::new(line, ErrorKind::WithoutPattern("OPERANDS")))?
                    .operands = value;
                self.operands_pending = false;
            }
            "IFORM" => {
                let form = record.forms.last_mut();
                form.ok_or(Error::new(line, ErrorKind::WithoutPattern("IFORM")))?
                    .iform = Some(value);
            }
            _ => record.extra.push((key, value)),
        }
        Ok(())
    }

    fn finish(self, close: u32) -> Result<Record<'a>, Error> {
        let mut record = self.record;
        if self.operands_pending {
            return Err(Error::new(close, ErrorKind::WithoutOperands));
        }
        for (key, value) in [
            ("ICLASS", record.iclass),
            ("CATEGORY", record.category),
            ("EXTENSION", record.extension),
        ] {
            if value.is_empty() {
                return Err(Error::new(close, ErrorKind::MissingKey(key)));
            }
        }
        if record.forms.is_empty() {
            return Err(Error::new(close, ErrorKind::MissingKey("PATTERN")));
        }
        record.isa_set = self.isa_set.unwrap_or(record.extension);
        Ok(record)
    }
}

#[cfg(test)]
mod tests {
    use super::{Form, parse};
    use crate::{Datafile, ErrorKind};

    const SOURCE: &str = "\
INSTRUCTIONS()::
{
ICLASS    : ADD
CATEGORY  : BINARY
EXTENSION : BASE
ATTRIBUTES: lock_prefix SCALABLE
REAL_OPCODE: Y
PATTERN   : 0x00 MOD[mm] MOD!=3
OPERANDS  : MEM0:rw:b REG0=GPR8_R():r
IFORM     : ADD_MEMb_GPR8
PATTERN   : 0x00 MOD[0b11]
OPERANDS  : REG0=GPR8_B():rw REG1=GPR8_R():r
}
UDELETE : OLD
{
ICLASS    : NOP
UNAME     : OLD
CATEGORY  : NOP
EXTENSION : BASE
ISA_SET   : PPRO
PATTERN   : 0x90
OPERANDS  :
}
";

    #[test]
    fn reads_fields_forms_defaults_and_unknown_keys() {
        let file = Datafile::new(SOURCE);
        let tables = parse(&file).unwrap();
        let [table] = tables.as_slice() else {
            panic!("expected one table")
        };
        let [add, nop] = table.records.as_slice() else {
            panic!("expected two records")
        };

        assert_eq!((add.iclass, add.isa_set, add.version), ("ADD", "BASE", 0));
        assert!(add.has_attribute("LOCK_PREFIX"));
        assert_eq!(add.extra("REAL_OPCODE"), Some("Y"));
        assert_eq!(
            add.forms,
            [
                Form {
                    line: 8,
                    pattern: "0x00 MOD[mm] MOD!=3",
                    operands: "MEM0:rw:b REG0=GPR8_R():r",
                    iform: Some("ADD_MEMb_GPR8")
                },
                Form {
                    line: 11,
                    pattern: "0x00 MOD[0b11]",
                    operands: "REG0=GPR8_B():rw REG1=GPR8_R():r",
                    iform: None
                },
            ]
        );
        assert_eq!((nop.isa_set, nop.uname), ("PPRO", Some("OLD")));
        assert_eq!(nop.forms.first().map(|form| form.operands), Some(""));
        assert_eq!(table.deleted_unames, ["OLD"]);
    }

    #[test]
    fn udelete_applies_to_records_before_and_after_it() {
        let file = Datafile::new(SOURCE);
        let tables = parse(&file).unwrap();
        let iclasses: Vec<_> = tables[0]
            .selected()
            .iter()
            .map(|record| record.iclass)
            .collect();
        assert_eq!(iclasses, ["ADD"]);
    }

    fn record(iclass: &str, version: u32, extension: &str) -> String {
        format!(
            "{{\nICLASS: {iclass}\nVERSION: {version}\nCATEGORY: C\nEXTENSION: {extension}\n\
             PATTERN: 0x00\nOPERANDS:\n}}\n"
        )
    }

    #[test]
    fn higher_versions_replace_lower_ones_and_move_to_the_end() {
        let source = [
            "INSTRUCTIONS()::\n".to_owned(),
            record("A", 0, "a0"),
            record("B", 0, "b0"),
            record("A", 0, "a0bis"),
            record("A", 2, "a2"),
            record("A", 1, "a1"),
            record("A", 2, "a2bis"),
            "DELETE : C\n".to_owned(),
            record("C", 0, "c0"),
        ]
        .concat();
        let file = Datafile::new(&source);
        let tables = parse(&file).unwrap();
        let kept: Vec<_> = tables[0]
            .selected()
            .iter()
            .map(|record| record.extension)
            .collect();
        assert_eq!(kept, ["b0", "a2", "a2bis"]);
    }

    #[test]
    fn sections_with_the_same_name_share_one_table() {
        let source = format!(
            "A_INSTRUCTIONS()::\n{}B()::\nx\nA_INSTRUCTIONS()::\nUDELETE : X\n",
            record("A", 0, "e")
        );
        let file = Datafile::new(&source);
        let tables = parse(&file).unwrap();
        let [table] = tables.as_slice() else {
            panic!("expected one table")
        };
        assert_eq!(
            (table.records.len(), table.deleted_unames.as_slice()),
            (1, ["X"].as_slice())
        );
    }

    #[test]
    fn rejects_malformed_records() {
        let cases = [
            (
                "{\nICLASS: A\nICLASS: B\n}",
                ErrorKind::DuplicateKey("ICLASS"),
                4,
            ),
            (
                "{\nOPERANDS: x\n}",
                ErrorKind::WithoutPattern("OPERANDS"),
                3,
            ),
            (
                "{\nICLASS: A\nCATEGORY: C\nEXTENSION: E\nPATTERN: p\nPATTERN: q\nOPERANDS:\n}",
                ErrorKind::WithoutOperands,
                7,
            ),
            (
                "{\nICLASS: A\nCATEGORY: C\nPATTERN: p\nOPERANDS:\n}",
                ErrorKind::MissingKey("EXTENSION"),
                7,
            ),
            ("{\nICLASS: A\n", ErrorKind::UnterminatedRecord, 2),
            ("{\nICLASS A\n}", ErrorKind::MissingColon, 3),
            ("stray", ErrorKind::ExpectedRecord, 2),
        ];
        for (body, kind, line) in cases {
            let source = format!("INSTRUCTIONS()::\n{body}");
            let error = parse(&Datafile::new(&source)).unwrap_err();
            assert_eq!((error.kind, error.line), (kind, line), "{body}");
        }
    }
}
