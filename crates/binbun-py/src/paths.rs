//! `binbun.paths()`: binbun's folders ([`binbun_paths`]), as `binbun
//! paths --json` lists them.

use pyo3::prelude::*;
use pyo3::types::PyDict;

/// binbun's folders in order (`config`, `data`, `state`, `cache`,
/// `runtime`), each `{"path": str | None, "size": int | None}`: its path
/// (`None` without a place) and the bytes of its files, not counting
/// another of the folders inside it (`None` without a place or with
/// `sizes=False`, which does not walk them). The GIL is released while
/// they are walked.
#[pyfunction]
#[pyo3(signature = (*, sizes = true))]
pub(crate) fn paths(py: Python<'_>, sizes: bool) -> PyResult<Bound<'_, PyDict>> {
    let folders = py.detach(|| binbun_paths::folders(sizes));
    let listed = PyDict::new(py);
    for folder in folders {
        let entry = PyDict::new(py);
        let size = folder.path.as_ref().and(folder.size);
        entry.set_item(
            "path",
            folder.path.map(|path| path.to_string_lossy().into_owned()),
        )?;
        entry.set_item("size", size)?;
        listed.set_item(folder.dir.name(), entry)?;
    }
    Ok(listed)
}

/// The console's startup script's path ([`binbun_paths::Place::Startup`]),
/// for `binbun.console`; `None` without a configuration folder.
#[pyfunction]
#[pyo3(name = "_startup_path")]
pub(crate) fn startup_path() -> Option<String> {
    binbun_paths::Place::Startup
        .path()
        .map(|path| path.to_string_lossy().into_owned())
}
