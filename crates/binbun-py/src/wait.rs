//! Waiting without holding the GIL, and never deaf to Ctrl-C: every wait
//! runs in slices of at most [`SLICE`] with the GIL released, the
//! interpreter's signal handlers run between them (a `KeyboardInterrupt`
//! cancels what was waited for and is raised), and a `timeout=` raises
//! binbun's `TimeoutError` (the job goes on; asking again finds what it
//! made).

use std::time::{Duration, Instant};

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

use crate::errors::Raise;

/// The longest the GIL is released at a time while waiting.
pub(crate) const SLICE: Duration = Duration::from_millis(50);

/// `timeout` (seconds; `None`: none) as a deadline from now.
///
/// # Errors
///
/// `ValueError` for a negative or not finite timeout.
pub(crate) fn deadline(timeout: Option<f64>) -> PyResult<Option<Instant>> {
    let Some(seconds) = timeout else {
        return Ok(None);
    };
    let duration = Duration::try_from_secs_f64(seconds)
        .map_err(|_| PyValueError::new_err(format!("timeout must be >= 0, not {seconds}")))?;
    Ok(Instant::now().checked_add(duration))
}

/// Calls `step` with the GIL released, each time with at most [`SLICE`]
/// to wait, until it gives a result; between calls, checks the signals
/// (a `KeyboardInterrupt` calls `cancel` and is raised) and `timeout`
/// (binbun's `TimeoutError`, saying `what`).
///
/// # Errors
///
/// A signal handler's exception, or the timeout.
pub(crate) fn wait_for<T: Send>(
    py: Python<'_>,
    timeout: Option<f64>,
    what: &str,
    mut step: impl FnMut(Duration) -> Option<T> + Send,
    cancel: impl FnOnce(),
) -> PyResult<T> {
    let deadline = deadline(timeout)?;
    loop {
        let slice = match deadline {
            None => SLICE,
            Some(deadline) => deadline
                .checked_duration_since(Instant::now())
                .unwrap_or_default()
                .min(SLICE),
        };
        if let Some(done) = py.detach(|| step(slice)) {
            return Ok(done);
        }
        if let Err(interrupted) = py.check_signals() {
            cancel();
            return Err(interrupted);
        }
        if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            return Err(Raise::Timeout.err(py, format!("{what}: the time ran out")));
        }
    }
}
