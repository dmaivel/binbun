//! What the image holds and the user wrote over it: names, comments,
//! bookmarks, bytes (and the searches through them, the listing and the
//! C: the session's), segments, sections, string literals, entries,
//! imports.

use std::collections::BTreeMap;
use std::sync::Arc;

use binbun::Database as Engine;
use binbun::strings::{Encoding, Literal};
use binbun_demangle::demangle;
use binbun_loader::{Image, SymbolKind, SymbolSource};
use binbun_protocol::Write;
use binbun_protocol::talk::EvidenceRefData;
use binbun_session::Session;
use binbun_session::listing::Options as ListingOptions;
use binbun_session::search::{
    ByteMode, BytePattern, Matcher, Query, Search, Source, TextHit as Hit,
};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;

use crate::database::{Address, Db, view_of};
use crate::errors::{Raise, named};
use crate::functions::{Function, engine};
use crate::remote::cited;
use crate::wait::wait_for;
use crate::writes::write;

/// The image of `session`, once parsed.
fn image<'s>(py: Python<'_>, session: &'s Session) -> PyResult<&'s Image<'s>> {
    session
        .image()
        .ok_or_else(|| Raise::NotAnalysed.err(py, "the image is not parsed yet"))
}

/// Every item `search` finds, waited for with the GIL released (Ctrl-C
/// drops it: it stops).
fn drain<T: Send + 'static>(py: Python<'_>, mut search: Search<T>) -> PyResult<Vec<T>> {
    let mut found = Vec::new();
    wait_for(
        py,
        None,
        "searching",
        |slice| {
            if let Some(batch) = search.wait(slice) {
                found.extend(batch.items);
            }
            if search.is_running() {
                return None;
            }
            found.extend(search.poll().into_iter().flat_map(|batch| batch.items));
            Some(())
        },
        || {},
    )?;
    Ok(found)
}

/// Wakes no one: Python waits on the search itself.
fn quiet() -> binbun_session::Wake {
    Arc::new(|| {})
}

/// The names of a database (`db.names`).
#[pyclass(frozen, module = "binbun._native")]
#[derive(Debug)]
pub(crate) struct Names {
    db: Arc<Db>,
}

impl Names {
    pub(crate) fn new(db: &Arc<Db>) -> Self {
        Self { db: Arc::clone(db) }
    }
}

#[pymethods]
impl Names {
    /// The name of `ea`: the user's, else the image's (a symbol, an import
    /// thunk's or pointer slot's).
    fn get_at(&self, py: Python<'_>, ea: Address) -> PyResult<Option<String>> {
        Ok(self.db.analysed(py)?.name(ea.0))
    }

    /// The name of `ea` as the listing shows it (with its dummy names:
    /// `sub_`, `loc_`, `off_`, a string's `a…`). Builds the listing the
    /// first time.
    fn get_display_at(&self, py: Python<'_>, ea: Address) -> PyResult<Option<String>> {
        let session = self.db.analysed(py)?;
        let listing = py
            .detach(|| session.listing(&ListingOptions::default()))
            .ok_or_else(|| Raise::NotAnalysed.err(py, "no listing"))?;
        let overlay = session.overlay();
        Ok(listing.shown_name(ea.0, &overlay).map(str::to_owned))
    }

    /// The address named `name` (the user's names first), if one is.
    fn get_ea(&self, py: Python<'_>, name: &str) -> PyResult<Option<u64>> {
        let session = self.db.analysed(py)?;
        let database = engine(py, &session)?;
        let overlay = session.overlay();
        Ok(overlay
            .names
            .iter()
            .find(|(_, given)| *given == name)
            .map(|(&address, _)| address)
            .or_else(|| {
                database
                    .names()
                    .iter()
                    .find(|(_, own)| *own == name)
                    .map(|(&address, _)| address)
            }))
    }

    /// Every name, by address (`binbun.Named(address, name)`s): the
    /// image's, the user's over them.
    fn get_all<'py>(&self, py: Python<'py>) -> PyResult<Vec<Bound<'py, PyAny>>> {
        let session = self.db.analysed(py)?;
        let database = engine(py, &session)?;
        let mut all: BTreeMap<u64, String> = database.names().clone();
        all.extend(session.overlay().names.clone());
        all.into_iter()
            .map(|fields| named(py, "Named", fields))
            .collect()
    }

    /// An Itanium C++ mangling (`_Z…`) as C++ text, if it reads as one.
    #[staticmethod]
    fn demangle(name: &str) -> Option<String> {
        demangle(name)
    }

    /// Names `ea` `name` (`None` or empty: its own name again): the
    /// function starting there, else the global.
    fn set_name(&self, py: Python<'_>, ea: Address, name: Option<String>) -> PyResult<()> {
        let address = ea.0;
        write(py, &self.db, &Write::Name { address, name }).map(drop)
    }
}

/// The user's comments (one kind; `\n` separates lines).
#[pyclass(frozen, module = "binbun._native")]
#[derive(Debug)]
pub(crate) struct Comments {
    db: Arc<Db>,
}

impl Comments {
    pub(crate) fn new(db: &Arc<Db>) -> Self {
        Self { db: Arc::clone(db) }
    }
}

#[pymethods]
impl Comments {
    /// The comment at `ea`, if there is one.
    fn get_at(&self, py: Python<'_>, ea: Address) -> PyResult<Option<String>> {
        Ok(self.db.session(py)?.overlay().comments.get(&ea.0).cloned())
    }

    /// Comments `ea` with `text` (`\n` between lines; `None` or empty: no
    /// comment). It shows in the listing and in the C.
    fn set_at(&self, py: Python<'_>, ea: Address, text: Option<String>) -> PyResult<()> {
        let address = ea.0;
        write(py, &self.db, &Write::Comment { address, text }).map(drop)
    }

    /// Every comment, by address: `binbun.Comment(address, text)`s.
    fn get_all<'py>(&self, py: Python<'py>) -> PyResult<Vec<Bound<'py, PyAny>>> {
        self.db
            .session(py)?
            .overlay()
            .comments
            .iter()
            .map(|(&a, t)| named(py, "Comment", (a, t.as_str())))
            .collect()
    }
}

/// The user's bookmarks (the GUI's `Alt+M`).
#[pyclass(frozen, module = "binbun._native")]
#[derive(Debug)]
pub(crate) struct Bookmarks {
    db: Arc<Db>,
}

impl Bookmarks {
    pub(crate) fn new(db: &Arc<Db>) -> Self {
        Self { db: Arc::clone(db) }
    }
}

#[pymethods]
impl Bookmarks {
    /// The bookmark at `ea`, if there is one.
    fn get_at(&self, py: Python<'_>, ea: Address) -> PyResult<Option<String>> {
        Ok(self.db.session(py)?.overlay().bookmarks.get(&ea.0).cloned())
    }

    /// Bookmarks `ea` as `name` (`None` or empty: no bookmark).
    fn set_at(&self, py: Python<'_>, ea: Address, name: Option<String>) -> PyResult<()> {
        let address = ea.0;
        write(py, &self.db, &Write::Bookmark { address, name }).map(drop)
    }

    /// Every bookmark, by address: `binbun.Named(address, name)`s.
    fn get_all<'py>(&self, py: Python<'py>) -> PyResult<Vec<Bound<'py, PyAny>>> {
        self.db
            .session(py)?
            .overlay()
            .bookmarks
            .iter()
            .map(|(&a, n)| named(py, "Named", (a, n.as_str())))
            .collect()
    }
}

/// The bytes of the image (read-only), and the searches through it, its
/// listing and its C.
#[pyclass(frozen, module = "binbun._native")]
#[derive(Debug)]
pub(crate) struct Bytes {
    db: Arc<Db>,
}

impl Bytes {
    pub(crate) fn new(db: &Arc<Db>) -> Self {
        Self { db: Arc::clone(db) }
    }

    /// `size` bytes at `ea` within its segment (zero past the file's bytes
    /// of a segment, as a `.bss`); `None` if unmapped or past the segment.
    fn read(&self, py: Python<'_>, ea: u64, size: usize) -> PyResult<Option<Vec<u8>>> {
        let session = self.db.session(py)?;
        let image = image(py, &session)?;
        let Some(segment) = image.segment(ea) else {
            return Ok(None);
        };
        let offset = ea - segment.start;
        let size64 = u64::try_from(size).unwrap_or(u64::MAX);
        if offset.saturating_add(size64) > segment.size {
            return Ok(None);
        }
        let start = usize::try_from(offset).unwrap_or(usize::MAX);
        let mut out = vec![0; size];
        if let Some(have) = segment.bytes.get(start..) {
            let n = have.len().min(size);
            if let (Some(to), Some(from)) = (out.get_mut(..n), have.get(..n)) {
                to.copy_from_slice(from);
            }
        }
        Ok(Some(out))
    }

    /// A little-endian number of `N` bytes at `ea`; `None` if they are not
    /// all in one segment.
    fn number<const N: usize>(&self, py: Python<'_>, ea: u64) -> PyResult<Option<u64>> {
        Ok(self.read(py, ea, N)?.map(|bytes| {
            bytes
                .iter()
                .rev()
                .fold(0u64, |value, &byte| value << 8 | u64::from(byte))
        }))
    }
}

#[pymethods]
impl Bytes {
    /// `size` bytes at `ea` (zero where a segment has no file bytes);
    /// `None` if they are not all in one segment.
    fn get_bytes_at<'py>(
        &self,
        py: Python<'py>,
        ea: Address,
        size: usize,
    ) -> PyResult<Option<Bound<'py, PyBytes>>> {
        Ok(self
            .read(py, ea.0, size)?
            .map(|bytes| PyBytes::new(py, &bytes)))
    }

    /// The byte at `ea`; `None` if unmapped.
    fn get_byte_at(&self, py: Python<'_>, ea: Address) -> PyResult<Option<u64>> {
        self.number::<1>(py, ea.0)
    }

    /// The 16-bit word at `ea` (little-endian); `None` if its bytes are not
    /// all in one segment.
    fn get_word_at(&self, py: Python<'_>, ea: Address) -> PyResult<Option<u64>> {
        self.number::<2>(py, ea.0)
    }

    /// The 32-bit word at `ea`; as `get_word_at`.
    fn get_dword_at(&self, py: Python<'_>, ea: Address) -> PyResult<Option<u64>> {
        self.number::<4>(py, ea.0)
    }

    /// The 64-bit word at `ea`; as `get_word_at`.
    fn get_qword_at(&self, py: Python<'_>, ea: Address) -> PyResult<Option<u64>> {
        self.number::<8>(py, ea.0)
    }

    /// The NUL-terminated string at `ea` (at most `max_length` bytes,
    /// UTF-8, invalid bytes replaced); `None` if unmapped.
    #[pyo3(signature = (ea, max_length = 1024))]
    fn get_cstring_at(
        &self,
        py: Python<'_>,
        ea: Address,
        max_length: usize,
    ) -> PyResult<Option<String>> {
        let session = self.db.session(py)?;
        let image = image(py, &session)?;
        let Some(segment) = image.segment(ea.0) else {
            return Ok(None);
        };
        let start = usize::try_from(ea.0 - segment.start).unwrap_or(usize::MAX);
        let bytes = segment.bytes.get(start..).unwrap_or_default();
        let end = bytes
            .iter()
            .take(max_length)
            .position(|&b| b == 0)
            .unwrap_or(bytes.len().min(max_length));
        Ok(Some(
            String::from_utf8_lossy(bytes.get(..end).unwrap_or_default()).into_owned(),
        ))
    }

    /// Whether `ea` is mapped.
    fn is_mapped(&self, py: Python<'_>, ea: Address) -> PyResult<bool> {
        let session = self.db.session(py)?;
        Ok(image(py, &session)?.is_mapped(ea.0))
    }

    /// Whether `ea` is code.
    fn is_code_at(&self, py: Python<'_>, ea: Address) -> PyResult<bool> {
        let session = self.db.session(py)?;
        Ok(image(py, &session)?.is_code(ea.0))
    }

    /// The whole file.
    fn file_bytes<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        let session = self.db.session(py)?;
        let bytes = session
            .bytes()
            .ok_or_else(|| Raise::NotAnalysed.err(py, "the file is not read yet"))?;
        Ok(PyBytes::new(py, bytes))
    }

    /// Where `pattern` is in the segments, sorted: hexadecimal text with
    /// `??` (or `?` nibbles) for any (`"48 8b ?? 0?"`), or `bytes`; only
    /// in `start..end` if given. Searched on threads of their own.
    #[pyo3(signature = (pattern, start = None, end = None))]
    fn find_bytes(
        &self,
        py: Python<'_>,
        pattern: &Bound<'_, PyAny>,
        start: Option<Address>,
        end: Option<Address>,
    ) -> PyResult<Vec<u64>> {
        let text = if let Ok(bytes) = pattern.cast::<PyBytes>() {
            bytes
                .as_bytes()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<_>>()
                .join(" ")
        } else {
            pattern.extract::<String>()?
        };
        let pattern = Arc::new(
            BytePattern::parse(&text, ByteMode::Hex, true).map_err(PyValueError::new_err)?,
        );
        let session = self.db.session(py)?;
        let search = session
            .search_bytes(&pattern, false, &quiet())
            .ok_or_else(|| Raise::NotAnalysed.err(py, "the image is not parsed yet"))?;
        let mut found: Vec<u64> = drain(py, search)?
            .into_iter()
            .map(|hit| hit.at)
            .filter(|&at| within(at, start, end))
            .collect();
        found.sort_unstable();
        found.dedup();
        Ok(found)
    }

    /// The instructions with an operand that is `value` (at its width or
    /// another: `-1` is `0FFFFFFFFh`), as the listing shows them; only in
    /// `start..end` if given.
    #[pyo3(signature = (value, start = None, end = None))]
    fn find_immediate(
        &self,
        py: Python<'_>,
        value: i128,
        start: Option<Address>,
        end: Option<Address>,
    ) -> PyResult<Vec<u64>> {
        let bits = u64::try_from(value)
            .or_else(|_| i64::try_from(value).map(i64::cast_unsigned))
            .map_err(|_| PyValueError::new_err(format!("{value} does not fit 64 bits")))?;
        let session = self.db.analysed(py)?;
        let listing = py
            .detach(|| session.listing(&ListingOptions::default()))
            .ok_or_else(|| Raise::NotAnalysed.err(py, "no listing"))?;
        let search = session.search_immediate(Some(&listing), None, bits, &quiet());
        let mut found: Vec<u64> = drain(py, search)?
            .into_iter()
            .map(|hit| hit.address)
            .filter(|&at| within(at, start, end))
            .collect();
        found.sort_unstable();
        found.dedup();
        Ok(found)
    }

    /// The lines with `text` (a regular expression if `regex`; its case
    /// ignored unless `case`): of the listing as shown (`where="listing"`)
    /// or of every function's C in `view` (`where="c"`, decompiling every
    /// function not yet).
    #[pyo3(signature = (text, *, r#where = "listing", regex = false, case = false, view = None))]
    fn find_text(
        &self,
        py: Python<'_>,
        text: &str,
        r#where: &str,
        regex: bool,
        case: bool,
        view: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<Vec<TextHit>> {
        let matcher = Matcher::new(&Query {
            text: text.to_owned(),
            case,
            regex,
        })
        .map_err(PyValueError::new_err)?;
        let Some(matcher) = matcher.map(Arc::new) else {
            return Ok(Vec::new());
        };
        let session = self.db.analysed(py)?;
        let search = match r#where {
            "listing" => {
                let listing = py
                    .detach(|| session.listing(&ListingOptions::default()))
                    .ok_or_else(|| Raise::NotAnalysed.err(py, "no listing"))?;
                session.search_text(Some(&listing), None, &matcher, &quiet())
            }
            "c" => {
                let view = view_of(view, self.db.view)?;
                session.search_text(None, Some(view), &matcher, &quiet())
            }
            other => {
                return Err(PyValueError::new_err(format!(
                    "where={other:?}: listing or c"
                )));
            }
        };
        let mut hits: Vec<TextHit> = drain(py, search)?
            .into_iter()
            .map(|hit| TextHit::of(&self.db, hit))
            .collect();
        hits.sort_by(|a, b| (a.address, &a.text).cmp(&(b.address, &b.text)));
        Ok(hits)
    }
}

/// Whether `at` is in `start..end` (either open).
fn within(at: u64, start: Option<Address>, end: Option<Address>) -> bool {
    start.is_none_or(|s| at >= s.0) && end.is_none_or(|e| at < e.0)
}

/// A line found by a text search: where, and its text with the matches.
#[pyclass(frozen, module = "binbun._native")]
#[derive(Debug)]
pub(crate) struct TextHit {
    db: Arc<Db>,
    /// Its address (a C line's first instruction, else its function's
    /// entry).
    #[pyo3(get)]
    pub(crate) address: u64,
    /// The entry of the function holding it.
    function_entry: Option<u64>,
    /// `listing` or `c`.
    #[pyo3(get)]
    source: &'static str,
    /// The line (a listing line without its address prefix), its
    /// indentation trimmed.
    #[pyo3(get)]
    text: String,
    /// The matches: `(start, end)` byte ranges of `text`.
    #[pyo3(get)]
    ranges: Vec<(usize, usize)>,
}

impl TextHit {
    /// `hit` of `db`.
    fn of(db: &Arc<Db>, hit: Hit) -> Self {
        Self {
            db: Arc::clone(db),
            address: hit.address,
            function_entry: hit.function,
            source: match hit.source {
                Source::Listing => "listing",
                Source::C => "c",
                Source::Declaration => "declaration",
            },
            ranges: hit.ranges.iter().map(|r| (r.start, r.end)).collect(),
            text: hit.text,
        }
    }
}

#[pymethods]
impl TextHit {
    fn __repr__(&self) -> String {
        format!(
            "TextHit({:#x}, {}, {:?})",
            self.address, self.source, self.text
        )
    }

    /// The function holding it, if one does.
    #[getter]
    fn function(&self) -> Option<Function> {
        self.function_entry
            .map(|entry| Function::new(&self.db, entry))
    }
}

/// The name of the section of `image` holding `address`, if one does.
fn section_of(image: &Image<'_>, address: u64) -> Option<String> {
    image
        .sections
        .iter()
        .filter(|s| s.start != 0 && s.name != ".tbss")
        .find(|s| (s.start..s.start.saturating_add(s.size)).contains(&address))
        .map(|s| s.name.clone())
}

/// A segment: mapped bytes with permissions.
#[pyclass(frozen, get_all, module = "binbun._native")]
#[derive(Debug, Clone)]
pub(crate) struct Segment {
    /// Its first address.
    pub(crate) start: u64,
    /// The address after it.
    end: u64,
    /// Readable.
    readable: bool,
    /// Writable.
    writable: bool,
    /// Executable.
    executable: bool,
    /// Where its bytes are in the file (`None` if it has none there).
    file_offset: Option<u64>,
    /// The section at its start, if any.
    name: Option<String>,
}

#[pymethods]
impl Segment {
    fn __repr__(&self) -> String {
        format!("Segment({:#x}..{:#x})", self.start, self.end)
    }
}

/// The segments, in address order.
#[pyclass(frozen, module = "binbun._native")]
#[derive(Debug)]
pub(crate) struct Segments {
    db: Arc<Db>,
}

impl Segments {
    pub(crate) fn new(db: &Arc<Db>) -> Self {
        Self { db: Arc::clone(db) }
    }
}

#[pymethods]
impl Segments {
    /// Every segment.
    fn get_all(&self, py: Python<'_>) -> PyResult<Vec<Segment>> {
        let session = self.db.session(py)?;
        let image = image(py, &session)?;
        let file = session.bytes().unwrap_or_default();
        let base = file.as_ptr() as usize;
        Ok(image
            .segments
            .iter()
            .map(|s| Segment {
                start: s.start,
                end: s.end(),
                readable: s.permissions.read,
                writable: s.permissions.write,
                executable: s.permissions.execute,
                file_offset: (!s.bytes.is_empty())
                    .then(|| (s.bytes.as_ptr() as usize).wrapping_sub(base))
                    .filter(|&offset| offset < file.len())
                    .map(|offset| offset as u64),
                name: section_of(image, s.start),
            })
            .collect())
    }

    /// The segment holding `ea`, if one does.
    fn get_at(&self, py: Python<'_>, ea: Address) -> PyResult<Option<Segment>> {
        Ok(self
            .get_all(py)?
            .into_iter()
            .find(|s| (s.start..s.end).contains(&ea.0)))
    }

    fn __len__(&self, py: Python<'_>) -> PyResult<usize> {
        let session = self.db.session(py)?;
        Ok(image(py, &session)?.segments.len())
    }

    fn __iter__<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        self.get_all(py)?
            .into_pyobject(py)?
            .try_iter()
            .map(Bound::into_any)
    }
}

/// A section of the file.
#[pyclass(frozen, get_all, module = "binbun._native")]
#[derive(Debug, Clone)]
pub(crate) struct Section {
    /// Its name.
    name: String,
    /// Its first address.
    pub(crate) start: u64,
    /// The address after it.
    end: u64,
    /// Whether it holds code.
    is_code: bool,
}

#[pymethods]
impl Section {
    fn __repr__(&self) -> String {
        format!("Section({}, {:#x}..{:#x})", self.name, self.start, self.end)
    }
}

/// The sections, as the file lists them.
#[pyclass(frozen, module = "binbun._native")]
#[derive(Debug)]
pub(crate) struct Sections {
    db: Arc<Db>,
}

impl Sections {
    pub(crate) fn new(db: &Arc<Db>) -> Self {
        Self { db: Arc::clone(db) }
    }
}

#[pymethods]
impl Sections {
    /// Every section.
    fn get_all(&self, py: Python<'_>) -> PyResult<Vec<Section>> {
        let session = self.db.session(py)?;
        let image = image(py, &session)?;
        Ok(image
            .sections
            .iter()
            .map(|s| Section {
                name: s.name.clone(),
                start: s.start,
                end: s.start.saturating_add(s.size),
                is_code: s.size > 0 && image.is_code(s.start),
            })
            .collect())
    }

    /// The section named `name`, if there is one.
    fn get_by_name(&self, py: Python<'_>, name: &str) -> PyResult<Option<Section>> {
        Ok(self.get_all(py)?.into_iter().find(|s| s.name == name))
    }

    fn __len__(&self, py: Python<'_>) -> PyResult<usize> {
        let session = self.db.session(py)?;
        Ok(image(py, &session)?.sections.len())
    }

    fn __iter__<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        self.get_all(py)?
            .into_pyobject(py)?
            .try_iter()
            .map(Bound::into_any)
    }
}

/// A string literal of the image's data (`binbun strings`). As evidence
/// (`evidence=[...]`): the string at its address; a thread's anchor
/// (`db.threads.create(item, ...)`): the data item there.
#[pyclass(frozen, get_all, module = "binbun._native")]
#[derive(Debug, Clone)]
pub(crate) struct StringItem {
    /// Its first byte.
    pub(crate) address: u64,
    /// Its length in characters.
    length: usize,
    /// Its size in bytes, without the NUL.
    size: u64,
    /// `utf8` or `utf16`.
    encoding: &'static str,
    /// Its text.
    text: String,
    /// How many references there are to its first byte.
    references: usize,
    /// Whether anything refers to it.
    referenced: bool,
    /// Whether the program cannot change it.
    read_only: bool,
    /// The section holding it, if any.
    section: Option<String>,
}

#[pymethods]
impl StringItem {
    fn __repr__(&self) -> String {
        format!("StringItem({:#x}, {:?})", self.address, self.text)
    }

    fn __str__(&self) -> String {
        self.text.clone()
    }

    /// What it is cited as: the string at its address.
    fn _cite(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        cited(
            py,
            &EvidenceRefData::String {
                address: self.address,
            },
        )
    }
}

/// `literal` of `image` as a [`StringItem`].
fn string_item(image: &Image<'_>, literal: &Literal) -> StringItem {
    StringItem {
        address: literal.address,
        length: literal.text.chars().count(),
        size: literal.bytes,
        encoding: match literal.encoding {
            Encoding::Utf8 => "utf8",
            Encoding::Utf16 => "utf16",
        },
        text: literal.text.clone(),
        references: literal.references,
        referenced: literal.references > 0,
        read_only: literal.read_only,
        section: section_of(image, literal.address),
    }
}

/// The string literals: those referred to, and those of at least
/// `min_length` characters found by scanning.
#[pyclass(frozen, module = "binbun._native")]
#[derive(Debug)]
pub(crate) struct Strings {
    db: Arc<Db>,
}

impl Strings {
    pub(crate) fn new(db: &Arc<Db>) -> Self {
        Self { db: Arc::clone(db) }
    }

    /// The literals of at least 4 characters, indexed once.
    fn indexed<T>(
        &self,
        py: Python<'_>,
        read: impl FnOnce(&Engine<'_>, &BTreeMap<u64, Literal>) -> T,
    ) -> PyResult<T> {
        let session = self.db.analysed(py)?;
        let database = engine(py, &session)?;
        let strings = py.detach(|| self.db.strings(&session, database));
        Ok(read(database, &strings))
    }
}

#[pymethods]
impl Strings {
    /// Every literal, in address order.
    #[pyo3(signature = (*, min_length = 4))]
    fn get_all(&self, py: Python<'_>, min_length: usize) -> PyResult<Vec<StringItem>> {
        if min_length == 4 {
            return self.indexed(py, |database, strings| {
                strings
                    .values()
                    .map(|l| string_item(database.image(), l))
                    .collect()
            });
        }
        let session = self.db.analysed(py)?;
        let database = engine(py, &session)?;
        let literals = py.detach(|| database.strings(min_length.max(1)));
        Ok(literals
            .iter()
            .map(|l| string_item(database.image(), l))
            .collect())
    }

    /// The literal starting at `ea`, if one does.
    fn get_at(&self, py: Python<'_>, ea: Address) -> PyResult<Option<StringItem>> {
        self.indexed(py, |database, strings| {
            strings.get(&ea.0).map(|l| string_item(database.image(), l))
        })
    }

    fn __len__(&self, py: Python<'_>) -> PyResult<usize> {
        self.indexed(py, |_, strings| strings.len())
    }

    fn __iter__<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        self.get_all(py, 4)?
            .into_pyobject(py)?
            .try_iter()
            .map(Bound::into_any)
    }
}

/// An entry point or an export.
#[pyclass(frozen, get_all, module = "binbun._native")]
#[derive(Debug, Clone)]
pub(crate) struct EntryInfo {
    /// Its address.
    pub(crate) address: u64,
    /// Its name, if it has one.
    name: Option<String>,
    /// `entry` (the image's entry point) or `export`.
    kind: &'static str,
}

#[pymethods]
impl EntryInfo {
    fn __repr__(&self) -> String {
        match &self.name {
            Some(name) => format!("EntryInfo({:#x}, {name:?}, {})", self.address, self.kind),
            None => format!("EntryInfo({:#x}, None, {})", self.address, self.kind),
        }
    }
}

/// The image's entry point and exported functions.
#[pyclass(frozen, module = "binbun._native")]
#[derive(Debug)]
pub(crate) struct Entries {
    db: Arc<Db>,
}

impl Entries {
    pub(crate) fn new(db: &Arc<Db>) -> Self {
        Self { db: Arc::clone(db) }
    }
}

#[pymethods]
impl Entries {
    /// The entry point first, then the exported functions by address.
    fn get_all(&self, py: Python<'_>) -> PyResult<Vec<EntryInfo>> {
        let session = self.db.analysed(py)?;
        let database = engine(py, &session)?;
        let image = database.image();
        let mut exports: BTreeMap<u64, String> = BTreeMap::new();
        for symbol in &image.symbols {
            if symbol.kind == SymbolKind::Function
                && matches!(symbol.source, SymbolSource::Dynamic | SymbolSource::Export)
            {
                exports
                    .entry(symbol.address)
                    .or_insert_with(|| symbol.name.clone());
            }
        }
        let mut out: Vec<EntryInfo> = image
            .entry
            .map(|entry| EntryInfo {
                address: entry,
                name: database.data_name(entry),
                kind: "entry",
            })
            .into_iter()
            .collect();
        out.extend(exports.into_iter().map(|(address, name)| EntryInfo {
            address,
            name: Some(name),
            kind: "export",
        }));
        Ok(out)
    }

    fn __len__(&self, py: Python<'_>) -> PyResult<usize> {
        Ok(self.get_all(py)?.len())
    }

    fn __iter__<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        self.get_all(py)?
            .into_pyobject(py)?
            .try_iter()
            .map(Bound::into_any)
    }
}

/// An import: its pointer slot, name and library.
#[pyclass(frozen, get_all, module = "binbun._native")]
#[derive(Debug, Clone)]
pub(crate) struct ImportInfo {
    /// The address of its pointer slot.
    pub(crate) address: u64,
    /// Its name.
    name: String,
    /// The library it comes from, if the image says.
    module: Option<String>,
}

#[pymethods]
impl ImportInfo {
    fn __repr__(&self) -> String {
        format!("ImportInfo({:#x}, {:?})", self.address, self.name)
    }
}

/// The image's imports.
#[pyclass(frozen, module = "binbun._native")]
#[derive(Debug)]
pub(crate) struct Imports {
    db: Arc<Db>,
}

impl Imports {
    pub(crate) fn new(db: &Arc<Db>) -> Self {
        Self { db: Arc::clone(db) }
    }
}

#[pymethods]
impl Imports {
    /// Every import, as the image lists them.
    fn get_all(&self, py: Python<'_>) -> PyResult<Vec<ImportInfo>> {
        let session = self.db.session(py)?;
        let image = image(py, &session)?;
        Ok(image
            .imports
            .iter()
            .map(|import| ImportInfo {
                address: import.slot,
                name: import.name.clone(),
                module: import.library.clone(),
            })
            .collect())
    }

    fn __len__(&self, py: Python<'_>) -> PyResult<usize> {
        let session = self.db.session(py)?;
        Ok(image(py, &session)?.imports.len())
    }

    fn __iter__<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        self.get_all(py)?
            .into_pyobject(py)?
            .try_iter()
            .map(Bound::into_any)
    }
}
