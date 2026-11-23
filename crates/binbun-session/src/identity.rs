//! This install's identity: an
//! ed25519 key that signs every change made here, and an X25519 key that
//! will receive a shared project's keys. Both are made at the first write
//! to a project, kept in binbun's data folder ([`root`]:
//! `identity`, [`binbun_paths::Place::Identity`]) readable by their owner
//! only (the directory 0700, the files 0600, on
//! Unix; on Windows what the user's profile gives what is made in it:
//! the user, SYSTEM and the Administrators), and never leave it. Made
//! whole beside their place, then linked into it, so two binbuns making
//! them at once end with one.

use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use x25519_dalek::{PublicKey as AgreementKey, StaticSecret};

use crate::journal::{PublicKey, Signer, random};

/// The signing key's file.
const SECRET: &str = "secret.key";
/// The agreement key's file.
const AGREEMENT: &str = "agreement.key";

/// An identity: its signing key and its agreement key.
#[derive(Clone)]
pub struct Identity {
    signer: Signer,
    agreement: StaticSecret,
}

impl fmt::Debug for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Identity")
            .field("public", &self.public())
            .finish_non_exhaustive()
    }
}

impl Identity {
    /// The identity kept in `dir`, made there first if it is not.
    ///
    /// # Errors
    ///
    /// The directory or a key cannot be read or written, or a key file is
    /// not one (32 bytes).
    pub fn load_or_create(dir: &Path) -> Result<Self, String> {
        create_private_dir(dir)?;
        let secret = key_file(dir, SECRET)?;
        let agreement = key_file(dir, AGREEMENT)?;
        Ok(Self {
            signer: Signer::from_seed(&secret),
            agreement: StaticSecret::from(agreement),
        })
    }

    /// A new identity kept nowhere (an ephemeral session's).
    ///
    /// # Errors
    ///
    /// The system has no randomness.
    pub fn ephemeral() -> Result<Self, String> {
        Ok(Self {
            signer: Signer::from_seed(&random()?),
            agreement: StaticSecret::from(random::<32>()?),
        })
    }

    /// Its public signing key: who it is.
    pub fn public(&self) -> PublicKey {
        self.signer.public()
    }

    /// Its public agreement key.
    pub fn agreement(&self) -> [u8; 32] {
        AgreementKey::from(&self.agreement).to_bytes()
    }

    /// Its signing key's secret: what makes it its peer's endpoint
    /// (`binbun-collab`, whose keys are the identity's). Never to leave
    /// the process.
    pub fn secret(&self) -> [u8; 32] {
        self.signer.secret()
    }

    /// Its agreement key's secret: what opens a shared project's keys
    /// wrapped to it (`binbun-collab`). Never to leave the process.
    pub fn agreement_secret(&self) -> [u8; 32] {
        self.agreement.to_bytes()
    }

    /// What signs its changes.
    pub(crate) fn signer(&self) -> &Signer {
        &self.signer
    }
}

/// Where this install's identity is kept ([`binbun_paths::Place::Identity`]);
/// `None` without binbun's configuration directory.
pub fn root() -> Option<PathBuf> {
    binbun_paths::Place::Identity.path()
}

/// Makes `dir` (its parents as usual), itself readable by its owner only.
fn create_private_dir(dir: &Path) -> Result<(), String> {
    let failed = |error: io::Error| format!("{}: {error}", dir.display());
    if let Some(parent) = dir.parent() {
        fs::create_dir_all(parent).map_err(failed)?;
    }
    #[cfg_attr(not(unix), expect(unused_mut, reason = "only Unix sets a mode"))]
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    match builder.create(dir) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => Ok(()),
        Err(error) => Err(failed(error)),
    }
}

/// The key in `dir`'s file `name`, made first (32 random bytes) if there
/// is none: written whole to a file of its own, readable by its owner
/// only, then linked into place unless another was meanwhile.
fn key_file(dir: &Path, name: &str) -> Result<[u8; 32], String> {
    let path = dir.join(name);
    let failed = |path: &Path, error: io::Error| format!("{}: {error}", path.display());
    match fs::read(&path) {
        Ok(bytes) => {
            return <[u8; 32]>::try_from(bytes.as_slice())
                .map_err(|_| format!("{}: not a key (32 bytes)", path.display()));
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(failed(&path, error)),
    }
    let key = random::<32>()?;
    // Its own name: threads and processes making it at once never share one.
    let salt = u64::from_le_bytes(random()?);
    let temporary = dir.join(format!(".{name}.{salt:016x}.tmp"));
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut file = options
        .open(&temporary)
        .map_err(|error| failed(&temporary, error))?;
    file.write_all(&key)
        .and_then(|()| file.sync_all())
        .map_err(|error| failed(&temporary, error))?;
    drop(file);
    let linked = fs::hard_link(&temporary, &path);
    let _ = fs::remove_file(&temporary);
    match linked {
        Ok(()) => {
            // The link flushed in its directory before the key is used
            // (on Unix; elsewhere the link itself is what the platform
            // guarantees). One that fails leaves the key unused: the next
            // read finds it, or makes another.
            #[cfg(unix)]
            fs::File::open(dir)
                .and_then(|directory| directory.sync_all())
                .map_err(|error| failed(dir, error))?;
            Ok(key)
        }
        // Another binbun made it meanwhile: its key is the one.
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => key_file(dir, name),
        Err(error) => Err(failed(&path, error)),
    }
}

#[cfg(test)]
mod tests {
    use super::Identity;

    #[test]
    fn an_identity_is_made_once_kept_private_and_read_again() {
        let dir = std::env::temp_dir().join(format!("binbun-identity-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let made = Identity::load_or_create(&dir).unwrap();
        let again = Identity::load_or_create(&dir).unwrap();
        assert_eq!(again.public(), made.public());
        assert_eq!(again.agreement(), made.agreement());
        assert_ne!(made.public(), Identity::ephemeral().unwrap().public());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            use std::path::Path;
            let bits = |path: &Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
            assert_eq!(bits(&dir), 0o700);
            assert_eq!(bits(&dir.join("secret.key")), 0o600);
            assert_eq!(bits(&dir.join("agreement.key")), 0o600);
        }
        // A file that is not a key is refused, never replaced.
        std::fs::write(dir.join("secret.key"), b"short").unwrap();
        assert!(Identity::load_or_create(&dir).is_err());
        assert_eq!(std::fs::read(dir.join("secret.key")).unwrap(), b"short");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
