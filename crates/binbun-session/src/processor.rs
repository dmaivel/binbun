//! The processor this install's runs and verifications of the project are
//! on: a processor profile's name
//! (`intel-raptor-cove`) or file, or none (the architecture: any
//! processor). Per project and per person, kept with the private
//! bookmarks in the project's `private.toml` ([`crate::Project::private`];
//! in memory in an ephemeral session): never in the log, an export or
//! anything sent. The C never changes with it; runs and verifications
//! asked with it ([`crate::facts::Question`]) take its values at the
//! sites where the architecture leaves one undefined.

use std::sync::Arc;

use binbun::profile::{self, Profile};

use crate::{Error, Session, given};

impl Session {
    /// The processor setting: a profile's name or file, `None` for the
    /// architecture.
    pub fn processor(&self) -> Option<String> {
        self.shared.state().journal.processor().map(str::to_owned)
    }

    /// The processor setting's profile, read (`None`: the architecture, or
    /// a file that no longer reads as a profile).
    pub fn profile(&self) -> Option<Arc<Profile>> {
        self.processor()
            .and_then(|name| profile::resolve(&name).ok())
    }

    /// Sets the processor: a shipped profile's name or a profile file's
    /// path (`None` or empty: the architecture), saved (if autosaving) to
    /// the project's private file.
    ///
    /// # Errors
    ///
    /// It is not a profile ([`Error::Project`], nothing set), or the
    /// private file cannot be written ([`Error::Project`]: set all the
    /// same, saved at the next save).
    pub fn set_processor(&self, name: Option<&str>) -> Result<(), Error> {
        let name = given(name);
        if let Some(name) = &name {
            profile::resolve(name).map_err(Error::Project)?;
        }
        let mut state = self.shared.state();
        if !state.journal.set_processor(name) || !state.autosave {
            return Ok(());
        }
        state.journal.save_private().map_err(Error::Project)
    }
}
