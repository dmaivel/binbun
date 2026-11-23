//! `db.listing`: the session's continuous listing (the GUI's listing) with
//! the user's names, comments and numbers' forms laid over it.

use std::sync::Arc;

use binbun_protocol::Write;
use binbun_session::listing::{LineKind, Listing as Lines, Options, Role};
use binbun_session::{NumberForm, Session};
use pyo3::exceptions::{PyOverflowError, PyValueError};
use pyo3::prelude::*;

use crate::database::{Address, Db};
use crate::errors::Raise;
use crate::writes::write;

/// `kind`'s name.
const fn line_kind(kind: LineKind) -> &'static str {
    match kind {
        LineKind::Blank => "blank",
        LineKind::SegmentBorder => "segment_border",
        LineKind::SegmentType => "segment_type",
        LineKind::SegmentPermissions => "segment_permissions",
        LineKind::Banner => "banner",
        LineKind::Attributes => "attributes",
        LineKind::Prototype => "prototype",
        LineKind::Public => "public",
        LineKind::Proc => "proc",
        LineKind::Frame => "frame",
        LineKind::Label => "label",
        LineKind::Xref => "xref",
        LineKind::Preview => "preview",
        LineKind::Instruction => "instruction",
        LineKind::Data => "data",
        LineKind::Separator => "separator",
        LineKind::End => "end",
        LineKind::Comment => "comment",
    }
}

/// `role`'s name.
fn role_name(role: Role) -> String {
    let debug = format!("{role:?}");
    let mut name = String::with_capacity(debug.len() + 2);
    for (i, c) in debug.chars().enumerate() {
        if c.is_ascii_uppercase() && i > 0 {
            name.push('_');
        }
        name.push(c.to_ascii_lowercase());
    }
    name
}

/// The listing of a database (built the first time it is read, on the
/// calling thread with the GIL released): every mapped byte as lines.
#[pyclass(frozen, module = "binbun._native")]
#[derive(Debug)]
pub(crate) struct Listing {
    db: Arc<Db>,
}

impl Listing {
    pub(crate) fn new(db: &Arc<Db>) -> Self {
        Self { db: Arc::clone(db) }
    }

    /// The session and its listing under the default options.
    fn lines(&self, py: Python<'_>) -> PyResult<(Arc<Session>, Arc<Lines>)> {
        let session = self.db.analysed(py)?;
        let lines = py
            .detach(|| session.listing(&Options::default()))
            .ok_or_else(|| Raise::NotAnalysed.err(py, "the functions are not recovered yet"))?;
        Ok((session, lines))
    }
}

#[pymethods]
impl Listing {
    fn __len__(&self, py: Python<'_>) -> PyResult<usize> {
        usize::try_from(self.lines(py)?.1.len())
            .map_err(|_| PyOverflowError::new_err("more listing lines than an index holds"))
    }

    /// The line of the item holding `ea` (else the nearest after it).
    fn line_of(&self, py: Python<'_>, ea: Address) -> PyResult<u64> {
        Ok(self.lines(py)?.1.line_of(ea.0))
    }

    /// `count` lines from line number `line`, as shown.
    #[pyo3(name = "lines")]
    fn lines_at(&self, py: Python<'_>, line: u64, count: u64) -> PyResult<Vec<ListingLine>> {
        let (session, lines) = self.lines(py)?;
        let overlay = session.overlay();
        let Some(database) = session.database() else {
            return Ok(Vec::new());
        };
        Ok((line..line.saturating_add(count).min(lines.len()))
            .filter_map(|n| {
                let item = lines.line(n)?;
                let rendered = lines.render(database, n, &overlay);
                Some(ListingLine {
                    number: n,
                    address: item.address,
                    kind: line_kind(item.kind),
                    text: rendered.text(),
                    tokens: rendered
                        .tokens
                        .into_iter()
                        .map(|t| (t.text, role_name(t.role), t.target))
                        .collect(),
                })
            })
            .collect())
    }

    /// The text of the lines of the items from `start` up to `end`,
    /// one per line, as shown.
    fn text(&self, py: Python<'_>, start: Address, end: Address) -> PyResult<String> {
        let (session, lines) = self.lines(py)?;
        let overlay = session.overlay();
        let Some(database) = session.database() else {
            return Ok(String::new());
        };
        let mut out = String::new();
        let mut n = lines.line_of(start.0);
        while let Some(line) = lines.line(n) {
            if line.address >= end.0 {
                break;
            }
            out.push_str(&lines.render(database, n, &overlay).text());
            out.push('\n');
            n += 1;
        }
        Ok(out)
    }

    /// Writes the number `value` the instruction at `ea` uses in `form` (a
    /// `NumberForm`; `None`: as the listing and the printer choose), in
    /// the listing and the C (the GUI's `H`, `R`).
    #[pyo3(signature = (ea, value, form = None))]
    fn set_number_form(
        &self,
        py: Python<'_>,
        ea: Address,
        value: u64,
        form: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<()> {
        let form = form
            .filter(|form| !form.is_none())
            .map(|form| {
                let name: String = form
                    .getattr("value")
                    .unwrap_or_else(|_| form.clone())
                    .extract()?;
                match name.as_str() {
                    "hex" => Ok(NumberForm::Hex),
                    "decimal" => Ok(NumberForm::Decimal),
                    "char" => Ok(NumberForm::Char),
                    other => Err(PyValueError::new_err(format!(
                        "no number form {other:?} (hex, decimal, char)"
                    ))),
                }
            })
            .transpose()?;
        let address = ea.0;
        write(
            py,
            &self.db,
            &Write::NumberForm {
                address,
                value,
                form,
            },
        )
        .map(drop)
    }

    /// Writes the number `value` the instruction at `ea` uses by the
    /// constants of the enumeration `name` names (a typedef's, or `enum
    /// tag`; the type library's or one `Types.define` made), in the
    /// listing and the C (the GUI's `M`): the constant equal to it, or the
    /// flags it holds. Raises `CDeclarationError` if `name` names no
    /// enumeration.
    fn set_enum_form(&self, py: Python<'_>, ea: Address, value: u64, name: String) -> PyResult<()> {
        write(
            py,
            &self.db,
            &Write::NumberForm {
                address: ea.0,
                value,
                form: Some(NumberForm::Enum(name)),
            },
        )
        .map(drop)
    }
}

/// A line of the listing as shown.
#[pyclass(frozen, get_all, module = "binbun._native")]
#[derive(Debug)]
pub(crate) struct ListingLine {
    /// Its number.
    number: u64,
    /// The address of its item.
    pub(crate) address: u64,
    /// What it is: `instruction`, `data`, `label`, `comment`, `blank`,
    /// `banner`, `proc`, `end`, `xref`, … (the listing's kinds).
    kind: &'static str,
    /// Its text.
    text: String,
    /// Its tokens: `(text, role, target)`, the role its colour
    /// (`mnemonic`, `register`, `number`, …; a mnemonic's by its
    /// instruction's class: `jump_mnemonic`, `call_mnemonic`,
    /// `return_mnemonic`, `padding_mnemonic`; `operand_keyword` for
    /// `short`, `qword ptr`, `offset` and segments), the target the address
    /// a reference goes to.
    tokens: Vec<(String, String, Option<u64>)>,
}

#[pymethods]
impl ListingLine {
    fn __repr__(&self) -> String {
        format!("ListingLine({}, {:?})", self.number, self.text)
    }

    fn __str__(&self) -> String {
        self.text.clone()
    }
}
