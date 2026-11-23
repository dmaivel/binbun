//! The console's history: the cells run, oldest first, kept across
//! sessions in [`binbun_paths::Place::ConsoleHistory`], one cell a line as a JSON
//! string (a cell can have several lines); at most [`KEPT`], a cell equal
//! to the one before it not kept again. Up and Down at the input's first
//! and last line walk it, the text being typed kept to come back to.

use std::fs;
use std::path::{Path, PathBuf};

use crate::crash_safe;

/// The most cells kept.
pub const KEPT: usize = 1000;

/// Where the history is kept ([`binbun_paths::Place::ConsoleHistory`]).
pub fn path() -> Option<PathBuf> {
    binbun_paths::Place::ConsoleHistory.path()
}

/// The cells in `text`, oldest first (a line that is not a JSON string
/// skipped).
pub fn parse(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|line| serde_json::from_str::<String>(line).ok())
        .collect()
}

/// `cells` as the file keeps them.
pub fn render(cells: &[String]) -> String {
    cells
        .iter()
        .map(|cell| serde_json::Value::String(cell.clone()).to_string() + "\n")
        .collect()
}

/// `cells` with `cell` run last: not again if it is the last already,
/// never an empty one, the oldest dropped beyond [`KEPT`].
pub fn pushed(mut cells: Vec<String>, cell: &str) -> Vec<String> {
    if !cell.trim().is_empty() && cells.last().is_none_or(|last| last != cell) {
        cells.push(cell.to_owned());
    }
    let over = cells.len().saturating_sub(KEPT);
    cells.drain(..over);
    cells
}

/// The history, and where Up and Down are in it.
#[derive(Debug, Default)]
pub struct History {
    cells: Vec<String>,
    path: Option<PathBuf>,
    /// The cell shown, while walking.
    at: Option<usize>,
    /// What was typed before walking began.
    draft: String,
}

impl History {
    /// The history kept at `path` (none: kept for this session only).
    pub fn load(path: Option<PathBuf>) -> Self {
        let cells = path
            .as_deref()
            .and_then(|p| fs::read_to_string(p).ok())
            .map(|text| parse(&text))
            .unwrap_or_default();
        Self {
            cells,
            path,
            at: None,
            draft: String::new(),
        }
    }

    /// The cells, oldest first.
    pub fn cells(&self) -> &[String] {
        &self.cells
    }

    /// `cell` was run: kept (in the file too, with what other windows
    /// added to it meanwhile), and walking starts over.
    ///
    /// # Errors
    ///
    /// The file cannot be written (the cell is kept for this session).
    pub fn push(&mut self, cell: &str) -> Result<(), String> {
        self.at = None;
        self.draft.clear();
        let Some(path) = self.path.clone() else {
            self.cells = pushed(std::mem::take(&mut self.cells), cell);
            return Ok(());
        };
        let on_disk = fs::read_to_string(&path)
            .map_or_else(|_| std::mem::take(&mut self.cells), |text| parse(&text));
        self.cells = pushed(on_disk, cell);
        save(&path, &self.cells).map_err(|e| format!("{}: {e}", path.display()))
    }

    /// Up: the cell before the one shown (the newest first), `current`
    /// kept as the draft when walking begins; `None` at the oldest.
    pub fn older(&mut self, current: &str) -> Option<&str> {
        let at = match self.at {
            None => {
                if self.cells.is_empty() {
                    return None;
                }
                current.clone_into(&mut self.draft);
                self.cells.len() - 1
            }
            Some(0) => return None,
            Some(at) => at - 1,
        };
        self.at = Some(at);
        self.cells.get(at).map(String::as_str)
    }

    /// Down: the cell after the one shown, the draft after the newest;
    /// `None` when not walking.
    pub fn newer(&mut self) -> Option<&str> {
        let at = self.at?;
        if at + 1 < self.cells.len() {
            self.at = Some(at + 1);
            self.cells.get(at + 1).map(String::as_str)
        } else {
            self.at = None;
            Some(&self.draft)
        }
    }

    /// Walking stops (the input was edited).
    pub fn reset(&mut self) {
        self.at = None;
    }
}

/// Writes `cells` to `path` crash-safely (a temporary file, synced,
/// renamed over it), its directory made first.
fn save(path: &Path, cells: &[String]) -> std::io::Result<()> {
    crash_safe::write(path, render(cells).as_bytes())
}

#[cfg(test)]
mod tests {
    use super::{History, KEPT, parse, pushed, render};

    /// A directory of its own under the system's temporary one.
    fn scratch(name: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("binbun-console-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn equal_neighbours_and_empty_cells_are_kept_once_and_the_oldest_dropped() {
        let mut cells = Vec::new();
        for cell in ["a", "a", "  ", "b", "a"] {
            cells = pushed(cells, cell);
        }
        assert_eq!(cells, ["a", "b", "a"]);
        let many: Vec<String> = (0..KEPT + 5).map(|n| n.to_string()).collect();
        let bounded = pushed(many, "last");
        assert_eq!(bounded.len(), KEPT);
        assert_eq!(bounded.first().map(String::as_str), Some("6"));
        assert_eq!(bounded.last().map(String::as_str), Some("last"));
    }

    #[test]
    fn multi_line_cells_survive_the_file() {
        let cells = vec![
            "for f in db.functions:\n    print(f)\n".to_owned(),
            "x = \"\\\"\"".to_owned(),
        ];
        assert_eq!(parse(&render(&cells)), cells);
        assert_eq!(parse("not json\n\"ok\"\n"), ["ok"]);
    }

    #[test]
    fn the_history_persists_and_merges_another_windows_cells() {
        let dir = scratch("persist");
        let path = dir.join("binbun").join("console_history");
        let mut one = History::load(Some(path.clone()));
        let mut two = History::load(Some(path.clone()));
        one.push("first\nsecond line").unwrap();
        two.push("from two").unwrap();
        one.push("third").unwrap();
        let again = History::load(Some(path));
        assert_eq!(again.cells(), ["first\nsecond line", "from two", "third"]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn up_and_down_walk_the_cells_and_come_back_to_the_draft() {
        let mut history = History::load(None);
        history.push("a").unwrap();
        history.push("b").unwrap();
        assert_eq!(history.newer(), None);
        assert_eq!(history.older("typing"), Some("b"));
        assert_eq!(history.older("b"), Some("a"));
        assert_eq!(history.older("a"), None);
        assert_eq!(history.newer(), Some("b"));
        assert_eq!(history.newer(), Some("typing"));
        assert_eq!(history.newer(), None);
        // A push starts the walk over at the newest.
        assert_eq!(history.older(""), Some("b"));
        history.push("c").unwrap();
        assert_eq!(history.older(""), Some("c"));
    }
}
