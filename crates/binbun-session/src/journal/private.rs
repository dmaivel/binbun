//! Bookmarks beside this author's own: every other author's as the keys
//! show them ([`Journal::others_bookmarks`]), and this install's private
//! ones ([`Private`]): local, never a key, so never in the log, an export
//! or anything sent; kept in the project's `private.toml` (a project file
//! holding bookmarks only, written crash-safely), in memory in an
//! ephemeral session. A private bookmark's edit is an undo step as a
//! change is ([`Step`]), in order with this author's changes; a bookmark
//! moved between shared and private is one step of both.
//!
//! The file also keeps the private halves of this author's undo and redo
//! steps, with the steps' order and this author's last change when it was
//! written ([`File`]), so that after reopening an old step undoes and is
//! made again whole: a private bookmark's edit alone, or a bookmark's move
//! between shared and private. Steps the log has moved past since (a
//! crash between the two files) keep their private halves where their
//! change is still a step; a private edit alone is then dropped from
//! undo, the bookmarks kept as they are.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::{ChainId, ChangeId, Journal, Key, PublicKey, Value};
use crate::edits::address;
use crate::project::write_safely;

/// What undoing or making again a private bookmark's edit alone is
/// labelled.
pub(crate) const LABEL: &str = "Private bookmark";

/// The private bookmarks' file's format.
const FORMAT: u32 = 1;

/// A private bookmark's edit: at which address, its name before and
/// after (`None`: none there).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PrivateEdit {
    /// Where.
    pub(crate) address: u64,
    /// The name before.
    pub(crate) before: Option<String>,
    /// The name after.
    pub(crate) after: Option<String>,
}

impl PrivateEdit {
    /// The edit undoing it.
    pub(crate) fn inverse(&self) -> Self {
        Self {
            address: self.address,
            before: self.after.clone(),
            after: self.before.clone(),
        }
    }
}

/// One of this author's undo steps: a change, a private bookmark's edit,
/// or both (a bookmark moved between shared and private).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Step {
    /// The change.
    pub(crate) change: Option<ChangeId>,
    /// The private bookmark's edit made with it.
    pub(crate) private: Option<PrivateEdit>,
}

impl Step {
    /// Change `id` alone.
    pub(crate) fn change(id: ChangeId) -> Self {
        Self {
            change: Some(id),
            private: None,
        }
    }
}

/// This install's private bookmarks of a project, and the file keeping
/// them.
#[derive(Clone, Debug, Default)]
pub(crate) struct Private {
    /// The bookmarks' names, by address.
    bookmarks: BTreeMap<u64, String>,
    /// The processor runs and verifications are on: a profile's name or
    /// file (`None`: the architecture's, any processor).
    processor: Option<String>,
    /// Where they are kept; none in an ephemeral session.
    file: Option<PathBuf>,
    /// Whether they changed since the file was last written.
    unsaved: bool,
    /// Whether this author's steps changed since the file was last
    /// written.
    steps_unsaved: bool,
    /// Whether the file holds steps.
    holds_steps: bool,
    /// The steps the file held when read, until the journal takes them
    /// ([`Journal::restore_steps`]).
    kept: Option<Kept>,
}

/// This author's undo and redo steps as the file kept them.
#[derive(Clone, Debug, Default)]
struct Kept {
    /// This author's last change when they were written (0: none).
    head: u64,
    /// The undo steps, last last.
    undo: Vec<Step>,
    /// The redo steps, last last, each with the change undoing it.
    redo: Vec<(Step, Option<ChangeId>)>,
}

impl Private {
    /// Those kept in `file` (none if there is no file), kept there.
    ///
    /// # Errors
    ///
    /// The file cannot be read, or is not a private bookmarks' file.
    pub(crate) fn load(file: PathBuf) -> Result<Self, String> {
        let read = File::load(&file)?;
        let holds_steps = read.holds_steps();
        let failed = |error: String| format!("{}: {error}", file.display());
        let bookmarks = read
            .bookmarks
            .iter()
            .map(|bookmark| Ok((address(&bookmark.address)?, bookmark.name.clone())))
            .collect::<Result<_, String>>()
            .map_err(failed)?;
        let kept = read.kept().map_err(failed)?;
        Ok(Self {
            bookmarks,
            processor: read.processor,
            file: Some(file),
            unsaved: false,
            steps_unsaved: false,
            holds_steps,
            kept: Some(kept),
        })
    }
}

/// Whether the private bookmarks' file at `path` holds anything (a
/// bookmark or a step), or cannot be read.
pub(crate) fn holds(path: &Path) -> bool {
    File::load(path).map_or(true, |file| {
        !file.bookmarks.is_empty() || file.holds_steps()
    })
}

/// The private bookmarks' file (`private.toml`): its bookmarks, and the
/// private halves of this author's undo and redo steps. The steps are
/// listed by their changes' numbers in this author's chain (`chain`; 0:
/// a private bookmark's edit alone), as they stood when this author's
/// last change was `head`; each private half (`step`) names its stack and
/// place there.
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct File {
    /// Its format's version ([`FORMAT`]).
    format: u32,
    /// The processor this install's runs and verifications are on (a
    /// profile's name or file), if one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    processor: Option<String>,
    /// This author's chain, in hexadecimal (written with the steps).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    chain: Option<String>,
    /// This author's last change's number when written (0: none).
    #[serde(default, skip_serializing_if = "is_zero")]
    head: u64,
    /// The undo steps' changes, last last.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    undo: Vec<u64>,
    /// The redo steps' changes, last last, each with the change undoing
    /// it (0: none).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    redo: Vec<[u64; 2]>,
    /// The bookmarks.
    #[serde(default, rename = "bookmark", skip_serializing_if = "Vec::is_empty")]
    bookmarks: Vec<Bookmark>,
    /// The steps' private halves.
    #[serde(default, rename = "step", skip_serializing_if = "Vec::is_empty")]
    steps: Vec<StepEdit>,
}

/// A private bookmark.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Bookmark {
    /// The address, in hexadecimal.
    address: String,
    /// The name.
    name: String,
}

/// Which of this author's stacks a step is on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Stack {
    /// To undo.
    Undo,
    /// Undone, to make again.
    Redo,
}

/// A step's private half: its private bookmark's edit.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StepEdit {
    /// The step's stack.
    stack: Stack,
    /// The step's place there, from 0 (its bottom).
    index: usize,
    /// The bookmark's address, in hexadecimal.
    address: String,
    /// Its name before.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    before: Option<String>,
    /// Its name after.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    after: Option<String>,
}

/// Whether `value` is 0.
#[expect(
    clippy::trivially_copy_pass_by_ref,
    reason = "serde's skip_serializing_if passes a reference"
)]
fn is_zero(value: &u64) -> bool {
    *value == 0
}

impl File {
    /// The file at `path` (empty if there is none).
    ///
    /// # Errors
    ///
    /// It cannot be read, is not TOML, not this format or a later
    /// version.
    fn load(path: &Path) -> Result<Self, String> {
        let text = match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self::default());
            }
            Err(error) => return Err(format!("{}: {error}", path.display())),
        };
        let file: Self =
            toml::from_str(&text).map_err(|error| format!("{}: {error}", path.display()))?;
        if file.format > FORMAT {
            return Err(format!(
                "{}: format {} is newer than this binbun's ({FORMAT})",
                path.display(),
                file.format
            ));
        }
        Ok(file)
    }

    /// Whether it holds steps.
    fn holds_steps(&self) -> bool {
        !self.undo.is_empty() || !self.redo.is_empty()
    }

    /// The steps it keeps.
    ///
    /// # Errors
    ///
    /// The chain or an address is not hexadecimal, or a step's private
    /// half names no step.
    fn kept(&self) -> Result<Kept, String> {
        let chain = match &self.chain {
            Some(text) => Some(chain_id(text)?),
            None => None,
        };
        let change = |seq: u64| match (seq, chain) {
            (0, _) => Ok(None),
            (seq, Some(chain)) => Ok(Some(ChangeId { chain, seq })),
            (_, None) => Err("a step's change without the chain".to_owned()),
        };
        let step = |seq: u64| {
            Ok::<_, String>(Step {
                change: change(seq)?,
                private: None,
            })
        };
        let mut undo: Vec<Step> = self
            .undo
            .iter()
            .map(|&seq| step(seq))
            .collect::<Result<_, _>>()?;
        let mut redo: Vec<(Step, Option<ChangeId>)> = self
            .redo
            .iter()
            .map(|&[seq, by]| Ok((step(seq)?, change(by)?)))
            .collect::<Result<_, String>>()?;
        for edit in &self.steps {
            let step = match edit.stack {
                Stack::Undo => undo.get_mut(edit.index),
                Stack::Redo => redo.get_mut(edit.index).map(|(step, _)| step),
            }
            .ok_or_else(|| format!("no {:?} step {}", edit.stack, edit.index))?;
            step.private = Some(PrivateEdit {
                address: address(&edit.address)?,
                before: edit.before.clone(),
                after: edit.after.clone(),
            });
        }
        Ok(Kept {
            head: self.head,
            undo,
            redo,
        })
    }
}

/// The chain `text` (32 hexadecimal digits) names.
fn chain_id(text: &str) -> Result<ChainId, String> {
    let bad = || format!("not a chain: {text:?}");
    let mut id = [0; 16];
    if text.len() != 32 || !text.is_ascii() {
        return Err(bad());
    }
    for (byte, digits) in id.iter_mut().zip(text.as_bytes().chunks(2)) {
        let digits = std::str::from_utf8(digits).map_err(|_| bad())?;
        *byte = u8::from_str_radix(digits, 16).map_err(|_| bad())?;
    }
    Ok(ChainId(id))
}

impl Journal {
    /// Every other author's bookmarks as shown (each key's winner; one
    /// removed is gone), by author; an author with none is left out.
    pub(crate) fn others_bookmarks(&self) -> BTreeMap<PublicKey, BTreeMap<u64, String>> {
        let me = self.author();
        let bookmarks = Key::Bookmark(PublicKey([0; 32]), 0)
            ..=Key::Bookmark(PublicKey([u8::MAX; 32]), u64::MAX);
        let mut others: BTreeMap<PublicKey, BTreeMap<u64, String>> = BTreeMap::new();
        for key in self.registers.range(bookmarks).map(|(key, _)| key) {
            if let Key::Bookmark(author, address) = key
                && *author != me
                && let Some(name) = self.shown(key).and_then(Value::text)
            {
                others.entry(*author).or_default().insert(*address, name);
            }
        }
        others
    }

    /// Whether one of `keys` is another author's bookmark.
    pub(crate) fn others_bookmark<'a>(&self, mut keys: impl Iterator<Item = &'a Key>) -> bool {
        let me = self.author();
        keys.any(|key| matches!(key, Key::Bookmark(author, _) if *author != me))
    }

    /// This install's private bookmarks' names, by address.
    pub(crate) fn private(&self) -> &BTreeMap<u64, String> {
        &self.private.bookmarks
    }

    /// The processor this install's runs and verifications of the project
    /// are on (a profile's name or file), if one.
    pub(crate) fn processor(&self) -> Option<&str> {
        self.private.processor.as_deref()
    }

    /// Sets the processor ([`Self::processor`]); whether it changed.
    pub(crate) fn set_processor(&mut self, processor: Option<String>) -> bool {
        if self.private.processor == processor {
            return false;
        }
        self.private.processor = processor;
        self.private.unsaved = true;
        true
    }

    /// Makes `edit`: the private bookmark at its address named as it says
    /// after.
    pub(crate) fn keep_private(&mut self, edit: &PrivateEdit) {
        match &edit.after {
            Some(name) => self.private.bookmarks.insert(edit.address, name.clone()),
            None => self.private.bookmarks.remove(&edit.address),
        };
        self.private.unsaved = true;
    }

    /// Bookmarks `address` privately as `name` (`None`: no private
    /// bookmark there): an undo step of its own, ending redo. The edit;
    /// none if it changes nothing.
    pub(crate) fn bookmark_private(
        &mut self,
        address: u64,
        name: Option<String>,
    ) -> Option<PrivateEdit> {
        let before = self.private.bookmarks.get(&address).cloned();
        if before == name {
            return None;
        }
        let edit = PrivateEdit {
            address,
            before,
            after: name,
        };
        self.keep_private(&edit);
        self.undo.push(Step {
            change: None,
            private: Some(edit.clone()),
        });
        self.redo.clear();
        self.private.steps_unsaved = true;
        Some(edit)
    }

    /// Undoes this author's last step if it is a private bookmark's edit
    /// alone, to redo. The edit undoing it; none if the last step is
    /// not one.
    pub(crate) fn undo_private(&mut self) -> Option<PrivateEdit> {
        let step = self.undo.last().filter(|step| step.change.is_none())?;
        let edit = step.private.as_ref()?.inverse();
        let step = self.undo.pop()?;
        self.keep_private(&edit);
        self.redo.push((step, None));
        self.private.steps_unsaved = true;
        Some(edit)
    }

    /// Makes the last step undone again if it is a private bookmark's
    /// edit alone, to undo. The edit; none if the last undone is not one.
    pub(crate) fn redo_private(&mut self) -> Option<PrivateEdit> {
        let (step, _) = self.redo.last().filter(|(step, _)| step.change.is_none())?;
        let edit = step.private.clone()?;
        let (step, _) = self.redo.pop()?;
        self.keep_private(&edit);
        self.undo.push(step);
        self.private.steps_unsaved = true;
        Some(edit)
    }

    /// Makes `edit` part of the undo step of the group open (none open:
    /// nothing): a bookmark moved between shared and private. The journal
    /// only keeps it with the step; making it is the caller's.
    pub(crate) fn attach_private(&mut self, edit: PrivateEdit) {
        if let Some(pending) = &mut self.pending {
            pending.private = Some(edit);
        }
    }

    /// This author's steps changed (a change of theirs was made): the
    /// file's are written again at the next save if it keeps any.
    pub(crate) fn steps_changed(&mut self) {
        self.private.steps_unsaved = true;
    }

    /// The number of this author's last change in their chain (0: none).
    fn head(&self) -> u64 {
        let chain = self.chain;
        self.records
            .range(
                ChangeId { chain, seq: 0 }..=ChangeId {
                    chain,
                    seq: u64::MAX,
                },
            )
            .next_back()
            .map_or(0, |(id, _)| id.seq)
    }

    /// Takes the steps the private bookmarks' file kept (once, as the
    /// project opens, after the log's changes made the undo and redo):
    /// whole if this author made no change since they were written (each
    /// change they name is this author's, taken), else each private half
    /// joined to its change's step where that is still one.
    pub(crate) fn restore_steps(&mut self) {
        let Some(kept) = self.private.kept.take() else {
            return;
        };
        let ours = |id: &Option<ChangeId>| {
            id.is_none_or(|id| id.chain == self.chain && self.records.contains_key(&id))
        };
        let whole = kept.head == self.head()
            && kept.undo.iter().all(|step| ours(&step.change))
            && kept
                .redo
                .iter()
                .all(|(step, by)| ours(&step.change) && ours(by));
        if whole {
            self.undo = kept.undo;
            self.redo = kept.redo;
            return;
        }
        let halves: BTreeMap<ChangeId, PrivateEdit> = kept
            .undo
            .into_iter()
            .chain(kept.redo.into_iter().map(|(step, _)| step))
            .filter_map(|step| Some((step.change?, step.private?)))
            .collect();
        let steps = self
            .undo
            .iter_mut()
            .chain(self.redo.iter_mut().map(|(step, _)| step));
        for step in steps {
            if let Some(change) = step.change {
                step.private = halves.get(&change).cloned();
            }
        }
        self.private.steps_unsaved = true;
    }

    /// The private bookmarks' file as it stands: the bookmarks, and the
    /// steps if `steps`.
    fn private_file(&self, steps: bool) -> File {
        let mut file = File {
            format: FORMAT,
            processor: self.private.processor.clone(),
            bookmarks: self
                .private
                .bookmarks
                .iter()
                .map(|(&address, name)| Bookmark {
                    address: format!("{address:#x}"),
                    name: name.clone(),
                })
                .collect(),
            ..File::default()
        };
        if !steps {
            return file;
        }
        // The steps are this author's chain's changes (each made by the
        // journal under it, or adopted with it).
        let seq = |id: Option<ChangeId>| id.map_or(0, |id| id.seq);
        let half = |stack: Stack, index: usize, step: &Step| {
            step.private.as_ref().map(|edit| StepEdit {
                stack,
                index,
                address: format!("{:#x}", edit.address),
                before: edit.before.clone(),
                after: edit.after.clone(),
            })
        };
        file.chain = Some(self.chain.to_string());
        file.head = self.head();
        file.undo = self.undo.iter().map(|step| seq(step.change)).collect();
        file.redo = self
            .redo
            .iter()
            .map(|(step, by)| [seq(step.change), seq(*by)])
            .collect();
        file.steps = self
            .undo
            .iter()
            .enumerate()
            .filter_map(|(index, step)| half(Stack::Undo, index, step))
            .chain(
                self.redo
                    .iter()
                    .enumerate()
                    .filter_map(|(index, (step, _))| half(Stack::Redo, index, step)),
            )
            .collect();
        file
    }

    /// Writes the private bookmarks' file (crash-safely) if the bookmarks
    /// changed since it was last written, or this author's steps did and
    /// it keeps steps or a step has a private half; nothing in an
    /// ephemeral session.
    ///
    /// # Errors
    ///
    /// The file cannot be written.
    pub(crate) fn save_private(&mut self) -> Result<(), String> {
        if self.private.file.is_none() || !(self.private.unsaved || self.private.steps_unsaved) {
            return Ok(());
        }
        let steps = self
            .undo
            .iter()
            .chain(self.redo.iter().map(|(step, _)| step))
            .any(|step| step.private.is_some());
        if !self.private.unsaved && !steps && !self.private.holds_steps {
            self.private.steps_unsaved = false;
            return Ok(());
        }
        let text = toml::to_string(&self.private_file(steps)).map_err(|error| error.to_string())?;
        if let Some(file) = &self.private.file {
            write_safely(file, &text)?;
        }
        self.private.unsaved = false;
        self.private.steps_unsaved = false;
        self.private.holds_steps = steps;
        Ok(())
    }
}
