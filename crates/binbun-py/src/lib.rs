//! `binbun._native`: binbun as a Python library, the extension behind the
//! pure-Python `binbun` package. One
//! binary opened is a `binbun-session` session in process
//! ([`database::Database`]); every handle (functions, blocks, documents)
//! is keyed by what survives re-analysis and found again on use.
//!
//! - **Stable ABI** from Python 3.11 (`abi3-py311`); never links
//!   libpython (maturin builds it as an extension module).
//! - **No threads at import**: the session's threads start with
//!   `binbun.open`.
//! - **The GIL is released** while waiting for the analysis, a document,
//!   an answer, a search; waits run in slices and Ctrl-C cancels them
//!   ([`wait`]).
//! - **Errors** are `binbun._errors`' classes (each also the built-in it
//!   refines); enums are `binbun._enums`' ([`errors`]).
//! - **Writes** through the session's journal ([`writes`]): transactions
//!   of one thread (one undo step each, rolled back on an exception),
//!   writes outside one each an undo step, undo, redo, the history;
//!   corrections analysed anew and swapped in, handles found again by
//!   entry.
//! - **Connections** ([`remote`]): `binbun.connect()` to a running GUI or
//!   a script's `db.serve()` over the user's socket; the run group;
//!   `mode="local"` follows the server's change log.
//! - **Folders** ([`paths`]): `binbun.paths()`, where binbun keeps its
//!   files, as `binbun paths --json`.
//! - **Decoders** without a database ([`x86`], [`aarch64`]): submodules
//!   `_native.x86` and `_native.aarch64`, re-exported as `binbun.x86` and
//!   `binbun.aarch64`, speaking the C API's vocabulary ([`disasm`]); and
//!   one decoder for both ([`generic`]: `binbun.Decoder`,
//!   `binbun.Instruction`, `binbun.disassemble`), over `binbun-disasm`.

mod aarch64;
mod database;
mod disasm;
mod document;
mod errors;
mod events;
mod facts;
mod functions;
mod generic;
mod image;
mod listing;
mod paths;
mod remote;
mod signatures;
mod wait;
mod writes;
mod x86;
mod xrefs;

use pyo3::prelude::*;

/// binbun's engine, in process: `binbun.open(path)` and what it returns;
/// the decoders, in submodules `x86` and `aarch64`.
#[pymodule]
fn _native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    m.add_function(wrap_pyfunction!(database::open, m)?)?;
    m.add_function(wrap_pyfunction!(database::_touched, m)?)?;
    m.add_function(wrap_pyfunction!(database::_address, m)?)?;
    m.add_function(wrap_pyfunction!(events::_event, m)?)?;
    m.add_function(wrap_pyfunction!(writes::_history_entry, m)?)?;
    m.add_function(wrap_pyfunction!(paths::paths, m)?)?;
    m.add_function(wrap_pyfunction!(paths::startup_path, m)?)?;
    m.add_class::<database::Database>()?;
    m.add_class::<database::Revision>()?;
    m.add_class::<functions::Functions>()?;
    m.add_class::<functions::FunctionIter>()?;
    m.add_class::<functions::Function>()?;
    m.add_class::<functions::Block>()?;
    m.add_class::<xrefs::Xref>()?;
    m.add_class::<xrefs::Xrefs>()?;
    m.add_class::<xrefs::XrefTable>()?;
    m.add_class::<image::Names>()?;
    m.add_class::<image::Comments>()?;
    m.add_class::<image::Bookmarks>()?;
    m.add_class::<image::Bytes>()?;
    m.add_class::<image::TextHit>()?;
    m.add_class::<image::Segment>()?;
    m.add_class::<image::Segments>()?;
    m.add_class::<image::Section>()?;
    m.add_class::<image::Sections>()?;
    m.add_class::<image::StringItem>()?;
    m.add_class::<image::Strings>()?;
    m.add_class::<image::EntryInfo>()?;
    m.add_class::<image::Entries>()?;
    m.add_class::<image::ImportInfo>()?;
    m.add_class::<image::Imports>()?;
    m.add_class::<listing::Listing>()?;
    m.add_class::<listing::ListingLine>()?;
    m.add_class::<document::CDocument>()?;
    m.add_class::<document::CLine>()?;
    m.add_class::<document::CToken>()?;
    m.add_class::<document::CVariable>()?;
    m.add_class::<document::DecompileAll>()?;
    m.add_class::<facts::Verification>()?;
    m.add_class::<facts::Explanation>()?;
    m.add_class::<facts::ExplanationItem>()?;
    m.add_class::<facts::Origins>()?;
    m.add_class::<facts::OriginStep>()?;
    m.add_class::<facts::Run>()?;
    m.add_class::<facts::Stages>()?;
    m.add_class::<facts::StageText>()?;
    m.add_class::<events::Events>()?;
    m.add_class::<events::EventQueue>()?;
    m.add_class::<events::StageReached>()?;
    m.add_class::<events::Progress>()?;
    m.add_class::<events::Changed>()?;
    m.add_class::<events::Failed>()?;
    m.add_class::<events::Unresolved>()?;
    m.add_class::<events::HistoryChanged>()?;
    m.add_class::<events::Reanalysed>()?;
    m.add_class::<events::ThreadChanged>()?;
    m.add_class::<events::Mentioned>()?;
    m.add_class::<writes::Transaction>()?;
    m.add_class::<writes::HistoryEntry>()?;
    m.add_class::<writes::Types>()?;
    m.add_class::<writes::Corrections>()?;
    m.add_class::<signatures::Signatures>()?;
    m.add_class::<signatures::SignatureMatch>()?;
    m.add_class::<writes::StructLayout>()?;
    m.add_class::<writes::StructMember>()?;
    m.add_class::<remote::Connection>()?;
    m.add_class::<remote::Server>()?;
    m.add_class::<disasm::Branch>()?;
    m.add_class::<disasm::Token>()?;
    m.add_class::<disasm::Invalid>()?;
    m.add_class::<disasm::Sweep>()?;
    m.add_class::<generic::Decoder>()?;
    m.add_class::<generic::Instruction>()?;
    m.add_function(wrap_pyfunction!(generic::disassemble, m)?)?;
    m.add_submodule(&x86::module(m.py())?)?;
    m.add_submodule(&aarch64::module(m.py())?)?;
    Ok(())
}
