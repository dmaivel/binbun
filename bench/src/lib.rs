//! What both benchmarks share. Each writes its raw results as JSON to
//! `results/`; `plot.py` turns them into Markdown reports and SVG charts.

use std::path::Path;

use serde::Serialize;

/// The CPU model from `/proc/cpuinfo`, or `unknown`.
pub fn cpu() -> String {
    std::fs::read_to_string("/proc/cpuinfo")
        .ok()
        .and_then(|info| {
            info.lines().find_map(|line| {
                line.strip_prefix("model name")
                    .and_then(|rest| rest.split_once(':'))
                    .map(|(_, name)| name.trim().to_owned())
            })
        })
        .unwrap_or_else(|| "unknown".to_owned())
}

/// Writes `value` as pretty-printed JSON to `path`, creating its directory.
///
/// # Errors
///
/// If the directory or file cannot be written, or `value` cannot be
/// serialised.
pub fn write_json(path: &Path, value: &impl Serialize) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let text = serde_json::to_string_pretty(value).map_err(std::io::Error::other)?;
    std::fs::write(path, text + "\n")
}
