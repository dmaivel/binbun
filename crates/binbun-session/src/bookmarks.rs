//! Bookmarks beside this identity's own ([`Session::bookmark`], the
//! overlay's): every other author's as the journal shows them
//! ([`Session::others_bookmarks`]; a front end names each author as it
//! knows them), and this install's private ones
//! ([`Session::bookmark_private`]): local, never in the log, an export or
//! anything sent, kept in the project's `private.toml`
//! ([`crate::Project::private`]; in memory in an ephemeral session), each
//! edit an undo step in order with this identity's changes
//! ([`Session::undo`]). A bookmark moves between shared and private in
//! one undo step ([`Session::set_bookmark_private`]); another's is copied
//! into one's own by bookmarking its address ([`Session::bookmark`]).
//! What may change them is told as [`Event::Bookmarks`].

use std::collections::BTreeMap;

use crate::journal::{Journal, Origin, PRIVATE_LABEL, PrivateEdit, PublicKey, Undone};
use crate::worker::State;
use crate::{Error, Event, Session, given, write};

impl Session {
    /// Every other author's bookmarks as shown (each one's winning name;
    /// one removed is gone), by author and address: never this
    /// identity's (the overlay's, [`crate::listing::Overlay::bookmarks`]),
    /// and no author with none. Told as [`Event::Bookmarks`] when they may
    /// have changed.
    pub fn others_bookmarks(&self) -> BTreeMap<PublicKey, BTreeMap<u64, String>> {
        self.shared.state().journal.others_bookmarks()
    }

    /// This install's private bookmarks of the project, by address
    /// ([`Self::bookmark_private`]).
    pub fn private_bookmarks(&self) -> BTreeMap<u64, String> {
        self.shared.state().journal.private().clone()
    }

    /// Bookmarks `address` privately as `name` (`None` or empty: no
    /// private bookmark there): local only, never in the journal's log,
    /// an export or anything sent; saved (if autosaving) to the project's
    /// private bookmarks' file ([`crate::Project::private`]), kept in
    /// memory in an ephemeral session. An undo step of its own, in order
    /// with this identity's changes ([`Self::undo`]). Told as
    /// [`Event::Bookmarks`]; nothing if it changes nothing.
    ///
    /// # Errors
    ///
    /// The private bookmarks' file cannot be written ([`Error::Project`]):
    /// the bookmark is made all the same, saved at the next save.
    pub fn bookmark_private(&self, address: u64, name: Option<&str>) -> Result<(), Error> {
        let name = given(name);
        let saved = {
            let mut state = self.shared.state();
            if state.journal.bookmark_private(address, name).is_none() {
                return Ok(());
            }
            Self::save_private(&mut state)
        };
        self.shared.emit(&Event::Bookmarks);
        saved
    }

    /// Moves this identity's bookmark at `address` from shared to private
    /// (`private`: its removal written as a change, which others see, and
    /// its name kept privately in place of any private one there) or back
    /// (its private name written as a change, and dropped from the private
    /// ones): one undo step either way. Told as an edit is
    /// ([`Event::Changed`], [`Event::History`]) and as
    /// [`Event::Bookmarks`]. The private one is kept before the removal is
    /// written and dropped after the addition is, so a crash between loses
    /// nothing.
    ///
    /// # Errors
    ///
    /// A group is open, there is no such bookmark to move (none shared
    /// there to make private, none private to share), or the change
    /// cannot be made ([`Error::Transaction`]).
    pub fn set_bookmark_private(&self, address: u64, private: bool) -> Result<(), Error> {
        let edit = {
            let state = self.shared.state();
            if state.journal.in_group() {
                return Err(write::group_open());
            }
            let kept = state.journal.private().get(&address).cloned();
            if private {
                let shared = state.edits.bookmark(address).map(str::to_owned);
                let shared = shared.ok_or_else(|| missing("shared", address))?;
                PrivateEdit {
                    address,
                    before: kept,
                    after: Some(shared),
                }
            } else {
                let kept = kept.ok_or_else(|| missing("private", address))?;
                PrivateEdit {
                    address,
                    before: Some(kept),
                    after: None,
                }
            }
        };
        let (label, shared) = if private {
            ("Make bookmark private", None)
        } else {
            ("Share bookmark", edit.before.clone())
        };
        self.with_private(Some(&edit), || {
            self.begin(label, Origin::User);
            self.shared.state().journal.attach_private(edit.clone());
            self.bookmark(address, shared.as_deref())?;
            self.commit()
        })?;
        Ok(())
    }

    /// Makes `change` (a change written in a group of its own) with the
    /// private bookmark's edit `edit` (none: `change` alone): the private
    /// bookmark kept before the change if it adds one, dropped after it if
    /// it removes one (dropped again if the change cannot be made), told
    /// as [`Event::Bookmarks`]. What `change` came to.
    pub(crate) fn with_private<R>(
        &self,
        edit: Option<&PrivateEdit>,
        change: impl FnOnce() -> Result<R, Error>,
    ) -> Result<R, Error> {
        let Some(edit) = edit else {
            return change();
        };
        let adding = edit.after.is_some();
        if adding {
            self.make_private(edit);
        }
        let made = change();
        match (&made, adding) {
            (Err(_), true) => self.make_private(&edit.inverse()),
            (Ok(_), false) => self.make_private(edit),
            (Err(_), false) | (Ok(_), true) => {}
        }
        if made.is_ok() {
            self.shared.emit(&Event::Bookmarks);
        }
        made
    }

    /// Undoes or makes again (`step`: [`Journal::undo_private`],
    /// [`Journal::redo_private`]) this identity's last step if it is a
    /// private bookmark's edit alone, told as [`Event::Bookmarks`]; none
    /// if it is not one.
    ///
    /// # Errors
    ///
    /// A group is open ([`Error::Transaction`]).
    pub(crate) fn step_private(
        &self,
        step: impl FnOnce(&mut Journal) -> Option<PrivateEdit>,
    ) -> Result<Option<Undone>, Error> {
        let saved = {
            let mut state = self.shared.state();
            if state.journal.in_group() {
                return Err(write::group_open());
            }
            if step(&mut state.journal).is_none() {
                return Ok(None);
            }
            Self::save_private(&mut state)
        };
        if let Err(error) = saved {
            self.shared.emit(&Event::Failed(error.to_string()));
        }
        self.shared.emit(&Event::Bookmarks);
        Ok(Some(Undone {
            target: None,
            label: PRIVATE_LABEL.to_owned(),
            change: None,
            skipped: Vec::new(),
        }))
    }

    /// Makes the private bookmark's edit `edit`, saved (if autosaving); a
    /// failure to save is told ([`Event::Failed`]).
    fn make_private(&self, edit: &PrivateEdit) {
        let saved = {
            let mut state = self.shared.state();
            state.journal.keep_private(edit);
            Self::save_private(&mut state)
        };
        if let Err(error) = saved {
            self.shared.emit(&Event::Failed(error.to_string()));
        }
    }

    /// Writes the private bookmarks' file if autosaving and they changed.
    fn save_private(state: &mut State) -> Result<(), Error> {
        if !state.autosave {
            return Ok(());
        }
        state.journal.save_private().map_err(Error::Project)
    }
}

/// No `which` bookmark of this identity's at `address` to move.
fn missing(which: &str, address: u64) -> Error {
    Error::Transaction(format!("no {which} bookmark of yours at {address:#x}"))
}
