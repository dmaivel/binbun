//! Values the protocol carries besides writes: the view, the revision, a
//! history entry.

use std::time::{SystemTime, UNIX_EPOCH};

use binbun_session::journal::{HistoryEntry, PublicKey, Skipped};
use binbun_session::{Revision, Stage, View};
use serde::{Deserialize, Serialize};

/// `stage` as `binbun.Stage`'s value (as the wire and Python number the
/// stages).
pub const fn stage_number(stage: Stage) -> u8 {
    match stage {
        Stage::Opening => 0,
        Stage::Image => 1,
        Stage::Analysed => 2,
        Stage::Referenced => 3,
        Stage::Signatures => 4,
        Stage::Callers => 5,
        Stage::Warmed => 6,
    }
}

/// The view a document is printed in (`binbun_session::View`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Viewed {
    /// What the machine code does (`binbun decompile`'s default).
    #[default]
    Exact,
    /// For reading.
    Reading,
}

impl Viewed {
    /// The session's view.
    pub const fn view(self) -> View {
        match self {
            Self::Exact => View::Exact,
            Self::Reading => View::Reading,
        }
    }

    /// `view` as this.
    pub const fn of(view: View) -> Self {
        match view {
            View::Exact => Self::Exact,
            View::Reading => Self::Reading,
        }
    }
}

/// How far a database's state has come (`binbun_session::Revision`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RevisionData {
    /// Analyses before this one.
    pub analysis: u64,
    /// Changes made or taken.
    pub edits: u64,
}

impl From<Revision> for RevisionData {
    fn from(revision: Revision) -> Self {
        Self {
            analysis: revision.analysis,
            edits: revision.edits,
        }
    }
}

/// A change in the history (`binbun_session::HistoryEntry`), as a client
/// shows it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoryItem {
    /// The change: its chain (hexadecimal) and number there; empty for a
    /// private bookmark's edit undone or made again alone (local: no
    /// change, [`Self::private`]).
    pub id: String,
    /// What it did.
    pub label: String,
    /// Who or what made it: `user`, `script:<name>`, `plugin:<id>`,
    /// `agent`, `undo`, `redo`, `import:<what>`, `accept`.
    pub author: String,
    /// Its author's identity key, hexadecimal.
    pub key: String,
    /// When, in milliseconds since the Unix epoch.
    pub millis: u64,
    /// How many edits it made.
    pub edits: usize,
    /// Whether this install made it.
    pub mine: bool,
    /// The keys an undo or redo left alone (changed by someone since),
    /// each as text; empty otherwise.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub skipped: Vec<String>,
    /// Who made the suggestion it accepted, if it accepted one (`author`
    /// is then `accept`, `key` the person who accepted it).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suggested_by: Option<AuthorData>,
}

/// Who made something: an identity key and as whom.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorData {
    /// The identity key, hexadecimal.
    pub key: String,
    /// As whom: `user`, `script:<name>`, `plugin:<id>`, `agent`, ...
    pub author: String,
}

impl HistoryItem {
    /// `entry` as a client shows it, with what an undo or redo skipped.
    pub fn of(entry: &HistoryEntry, skipped: &[Skipped]) -> Self {
        Self {
            id: format!("{}:{}", entry.id.chain, entry.id.seq),
            label: entry.label.clone(),
            author: entry.origin.to_string(),
            key: entry.author.to_string(),
            millis: entry.time.millis(),
            edits: entry.edits,
            mine: entry.mine,
            skipped: skipped
                .iter()
                .map(|skipped| format!("{:?}", skipped.key))
                .collect(),
            suggested_by: entry.suggested_by.as_ref().map(AuthorData::of),
        }
    }

    /// A private bookmark's edit alone (the GUI's, never sent) undone, or
    /// made again if `redo`, by `key`'s install now: no change, so no id
    /// and no edits; labelled `label`.
    pub fn private(label: &str, redo: bool, key: PublicKey) -> Self {
        let millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |since| {
                u64::try_from(since.as_millis()).unwrap_or(u64::MAX)
            });
        Self {
            id: String::new(),
            label: label.to_owned(),
            author: if redo { "redo" } else { "undo" }.to_owned(),
            key: key.to_string(),
            millis,
            edits: 0,
            mine: true,
            skipped: Vec::new(),
            suggested_by: None,
        }
    }
}
