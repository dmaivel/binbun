//! A binary's projects as the window offers them (`collab-sync-v2.md`
//! §14.6): its private one (`<sha256>-<name>`) and one per share joined
//! (`<sha256>-<name>@<share>`), each a project in its own right, with its
//! own title and Recent entry; they never sync with each other.
//!
//! - **Opening** ([`opening`]): with one project for the bytes, it is
//!   opened; with several, they are offered, used last first
//!   ([`ProjectRow`]); with none, a new private one. Whether any binary
//!   has several is seen from the projects directory's names alone
//!   ([`may_have_several`]), so the common case reads no file's bytes
//!   twice.
//! - **Titles** ([`project_title`]): a share's project is "bash, shared by
//!   Ann", its owner as this install saw them ([`SharedBy`], kept in the
//!   share's project as `collab/shared-by.toml`), else their fingerprint's
//!   start.

use std::path::{Path, PathBuf};

use binbun_session::journal::PublicKey;
use binbun_session::project::{self, Choice, Chosen, Key};
use toml_edit::{DocumentMut, Item, value};

use crate::collab::{fingerprint, hex, shown_name, unhex};

/// The short name of the share whose project is in `dir`
/// (`<sha256>-<name>@<share>`), if it is a share's.
pub fn share_of(dir: &Path) -> Option<String> {
    let name = dir.file_name()?.to_str()?;
    name.rsplit_once('@').map(|(_, share)| share.to_owned())
}

/// The owner of a share as this install saw them: their key, and the name
/// they gave once seen in the session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SharedBy {
    /// Their identity key.
    pub owner: PublicKey,
    /// Their name, if seen.
    pub name: Option<String>,
}

impl SharedBy {
    /// Where it is kept in the share's project directory `dir`.
    pub fn path(dir: &Path) -> PathBuf {
        dir.join("collab").join("shared-by.toml")
    }

    /// The one kept in `dir`, if one is and it reads.
    pub fn load(dir: &Path) -> Option<Self> {
        let text = std::fs::read_to_string(Self::path(dir)).ok()?;
        let document = text.parse::<DocumentMut>().ok()?;
        let owner = document
            .get("owner")
            .and_then(Item::as_str)
            .and_then(unhex)?;
        let name = document
            .get("name")
            .and_then(Item::as_str)
            .map(str::to_owned);
        Some(Self { owner, name })
    }

    /// Keeps it in `dir`.
    ///
    /// # Errors
    ///
    /// The file cannot be written.
    pub fn save(&self, dir: &Path) -> Result<(), String> {
        let mut document = DocumentMut::new();
        document.insert("owner", value(hex(self.owner)));
        if let Some(name) = &self.name {
            document.insert("name", value(name.as_str()));
        }
        let path = Self::path(dir);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| format!("{}: {e}", parent.display()))?;
        }
        let text =
            format!("# The owner of the share this project is of, as last seen.\n{document}");
        std::fs::write(&path, text).map_err(|e| format!("{}: {e}", path.display()))
    }

    /// How the owner is named: their name as shown ([`shown_name`]), else
    /// their fingerprint's first two groups.
    pub fn who(&self) -> String {
        match &self.name {
            Some(name) if !name.trim().is_empty() => shown_name(name),
            _ => fingerprint(self.owner).chars().take(9).collect(),
        }
    }
}

/// A share's project's title for the file named `file`: "bash, shared by
/// Ann" (`by` its owner, if known), else "bash, shared".
pub fn share_title(file: &str, by: Option<&SharedBy>) -> String {
    match by {
        Some(by) => format!("{file}, shared by {}", by.who()),
        None => format!("{file}, shared"),
    }
}

/// The title of the file named `file` open in the project directory `dir`:
/// the file's name for a private project (or an owner's, shared in
/// place), [`share_title`] for a share's.
pub fn project_title(file: &str, dir: Option<&Path>) -> String {
    match dir.filter(|dir| share_of(dir).is_some()) {
        Some(dir) => share_title(file, SharedBy::load(dir).as_ref()),
        None => file.to_owned(),
    }
}

/// Whether some binary may have several projects in the projects
/// directory `root`: two of its directories' names start with the same
/// SHA-256. If not, opening any file opens its one project (or a new one)
/// with no need to ask.
pub fn may_have_several(root: &Path) -> bool {
    let Ok(entries) = std::fs::read_dir(root) else {
        return false;
    };
    let mut seen = std::collections::HashSet::new();
    entries
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let name = entry.file_name().into_string().ok()?;
            let hex = name.get(..64)?;
            (name.get(64..65) == Some("-")).then(|| hex.to_owned())
        })
        .any(|hex| !seen.insert(hex))
}

/// How a binary opens.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Opening {
    /// In this project directory (its only one), or a new private one
    /// (`None`): no question.
    Direct(Option<PathBuf>),
    /// One of these, used last first: asked.
    Choose(Vec<PathBuf>),
}

/// How the binary `key` opens, of the projects in `root`: its one project,
/// or several offered, used last first.
///
/// # Errors
///
/// The projects directory cannot be read as `project::locate` reads it.
pub fn opening(root: &Path, key: &Key) -> Result<Opening, String> {
    let located = project::locate(root, key, &Choice::Any)?;
    Ok(match located.chosen {
        Chosen::New => Opening::Direct(None),
        Chosen::Only | Chosen::Asked => Opening::Direct(Some(located.project.dir().to_path_buf())),
        Chosen::LastUsed => Opening::Choose(
            located
                .all
                .iter()
                .map(|project| project.dir().to_path_buf())
                .collect(),
        ),
    })
}

/// A project offered when a binary has several.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProjectRow {
    /// Its directory.
    pub dir: PathBuf,
    /// Its title ([`project_title`]).
    pub title: String,
    /// What it is: private, or which share.
    pub detail: String,
}

/// The rows offering `dirs` (used last first) for the file named `file`.
pub fn rows(file: &str, dirs: &[PathBuf]) -> Vec<ProjectRow> {
    dirs.iter()
        .map(|dir| ProjectRow {
            dir: dir.clone(),
            title: project_title(file, Some(dir)),
            detail: share_of(dir).map_or_else(
                || "your own project".to_owned(),
                |share| format!("share {share}"),
            ),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::path::Path;
    use std::time::{Duration, SystemTime};

    use binbun_session::journal::PublicKey;
    use binbun_session::project::Key;

    use super::{Opening, SharedBy, may_have_several, opening, project_title, rows, share_title};

    /// Marks the project directory `dir` used at `when` (as `locate`
    /// reads it: the directory's own time).
    fn used(dir: &Path, when: SystemTime) {
        std::fs::create_dir_all(dir).unwrap();
        open_dir(dir).set_modified(when).unwrap();
    }

    /// The directory `dir`, opened so its time can be set.
    #[cfg(not(windows))]
    fn open_dir(dir: &Path) -> File {
        File::open(dir).unwrap()
    }

    /// The directory `dir`, opened so its time can be set: Windows opens
    /// a directory only with `FILE_FLAG_BACKUP_SEMANTICS`, and setting
    /// its time needs `FILE_WRITE_ATTRIBUTES`.
    #[cfg(windows)]
    fn open_dir(dir: &Path) -> File {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_WRITE_ATTRIBUTES: u32 = 0x0100;
        const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
        std::fs::OpenOptions::new()
            .access_mode(FILE_WRITE_ATTRIBUTES)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(dir)
            .unwrap()
    }

    /// One project for the bytes opens with no question; a second (a
    /// share's) makes both offered, the one used last first, and using
    /// the other puts it first.
    #[test]
    fn several_projects_are_offered_used_last_first_and_one_opens_directly() {
        let root = std::env::temp_dir().join(format!("binbun-projects-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let key = Key::new(b"bytes", "bash");
        assert_eq!(opening(&root, &key).unwrap(), Opening::Direct(None));
        assert!(!may_have_several(&root));
        let private = root.join(key.dir_name());
        let share = root.join(key.share_dir_name(&[7; 32]));
        let then = SystemTime::now() - Duration::from_secs(3600);
        used(&private, then);
        assert_eq!(
            opening(&root, &key).unwrap(),
            Opening::Direct(Some(private.clone()))
        );
        assert!(!may_have_several(&root));
        // Another binary's project is no second project of this one.
        used(&root.join(Key::new(b"other", "bash").dir_name()), then);
        assert!(!may_have_several(&root));
        used(&share, then + Duration::from_secs(60));
        assert!(may_have_several(&root));
        assert_eq!(
            opening(&root, &key).unwrap(),
            Opening::Choose(vec![share.clone(), private.clone()])
        );
        used(&private, then + Duration::from_secs(120));
        assert_eq!(
            opening(&root, &key).unwrap(),
            Opening::Choose(vec![private.clone(), share.clone()])
        );
        let offered = rows("bash", &[private, share]);
        assert_eq!(offered[0].title, "bash");
        assert_eq!(offered[1].title, "bash, shared");
        let _ = std::fs::remove_dir_all(root);
    }

    /// A share's project is titled with its owner: by name once seen, by
    /// fingerprint before; a private project by its file alone. What a
    /// peer named themselves cannot hide or reorder the title.
    #[test]
    fn a_share_is_titled_by_its_owner() {
        let root = std::env::temp_dir().join(format!("binbun-share-title-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let key = Key::new(b"bytes", "bash");
        let share = root.join(key.share_dir_name(&[9; 32]));
        let private = root.join(key.dir_name());
        assert_eq!(project_title("bash", Some(&private)), "bash");
        assert_eq!(project_title("bash", None), "bash");
        assert_eq!(project_title("bash", Some(&share)), "bash, shared");
        let mut by = SharedBy {
            owner: PublicKey([3; 32]),
            name: None,
        };
        by.save(&share).unwrap();
        let unnamed = project_title("bash", Some(&share));
        assert!(unnamed.starts_with("bash, shared by "), "{unnamed}");
        assert_eq!(unnamed.len(), "bash, shared by ".len() + 9);
        by.name = Some("Ann".to_owned());
        by.save(&share).unwrap();
        assert_eq!(SharedBy::load(&share), Some(by.clone()));
        assert_eq!(project_title("bash", Some(&share)), "bash, shared by Ann");
        by.name = Some("Ann\u{202e}".to_owned());
        assert_eq!(
            share_title("bash", Some(&by)),
            "bash, shared by Ann\\u{202e}"
        );
        let _ = std::fs::remove_dir_all(root);
    }
}
