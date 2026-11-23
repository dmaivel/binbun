//! The binaries opened before, for the start page and File › Open Recent:
//! pinned ones first, then the newest first; one a line in
//! [`binbun_paths::Place::Recent`] as
//! `SECONDS<TAB>pin|-<TAB>SHA256<TAB>PROJECT<TAB>PATH`, the SHA-256 the
//! file had when last opened and the project it was opened in (its
//! directory's name in the projects directory: a binary may have a private
//! project and one per share, each its own entry). Earlier versions wrote
//! `SECONDS<TAB>pin|-<TAB>SHA256|-<TAB>PATH` (no project: the binary's
//! one, or the one used last), `SECONDS<TAB>pin|-<TAB>PATH` (of unknown
//! SHA-256) and a bare path (an unpinned file opened at an unknown time).
//! Each file's format and architecture come from its header alone
//! ([`platform`]), its edits mark from its project ([`has_project`]).

use std::fmt::Write as _;
use std::fs;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use binbun_session::project;

/// The most unpinned files kept.
pub const KEPT: usize = 20;

/// A file opened before.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Recent {
    /// Its path.
    pub path: PathBuf,
    /// When it was last opened (seconds since the Unix epoch; 0: unknown).
    pub opened: u64,
    /// Whether it stays at the top.
    pub pinned: bool,
    /// Its SHA-256 (lower-case hexadecimal) when last opened, if known:
    /// what finds its project without reading it again.
    pub sha256: Option<String>,
    /// The name of the project directory it was opened in (in the
    /// projects directory), if known: opened in it again.
    pub project: Option<String>,
}

impl Recent {
    /// Whether it is the entry of `path` opened in `project`.
    pub fn is(&self, path: &Path, project: Option<&str>) -> bool {
        self.path == path && self.project.as_deref() == project
    }
}

/// Where the list is kept ([`binbun_paths::Place::Recent`]).
pub fn path() -> Option<PathBuf> {
    binbun_paths::Place::Recent.path()
}

/// The list in `text`, in order (pinned first).
pub fn parse(text: &str) -> Vec<Recent> {
    let list = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(|line| {
            let mut fields = line.splitn(3, '\t');
            match (fields.next(), fields.next(), fields.next()) {
                (Some(opened), Some(pin), Some(rest)) if opened.parse::<u64>().is_ok() => {
                    let (sha256, path) = match rest.split_once('\t') {
                        Some(("-", path)) => (None, path),
                        Some((sha256, path)) if is_sha256(sha256) => {
                            (Some(sha256.to_owned()), path)
                        }
                        _ => (None, rest),
                    };
                    // A project's name never starts as an absolute path
                    // does, so a path of an earlier line is not taken
                    // for one.
                    let (project, path) = match path.split_once('\t') {
                        Some((project, path)) if sha256.is_some() && is_project(project) => {
                            (Some(project.to_owned()), path)
                        }
                        _ => (None, path),
                    };
                    Recent {
                        path: PathBuf::from(path),
                        opened: opened.parse().unwrap_or(0),
                        pinned: pin == "pin",
                        sha256,
                        project,
                    }
                }
                _ => Recent {
                    path: PathBuf::from(line),
                    opened: 0,
                    pinned: false,
                    sha256: None,
                    project: None,
                },
            }
        })
        .collect();
    ordered(list)
}

/// Whether `text` is a SHA-256 in lower-case hexadecimal.
fn is_sha256(text: &str) -> bool {
    text.len() == 64
        && text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Whether `text` is a project directory's name: a SHA-256, `-`, a name
/// (one path component).
fn is_project(text: &str) -> bool {
    text.get(..64).is_some_and(is_sha256)
        && text.get(64..65) == Some("-")
        && !text.contains(['/', '\\'])
}

/// `list` pinned first, each kind in its order, at most [`KEPT`] unpinned.
fn ordered(list: Vec<Recent>) -> Vec<Recent> {
    let (pinned, rest): (Vec<Recent>, Vec<Recent>) = list.into_iter().partition(|r| r.pinned);
    pinned
        .into_iter()
        .chain(rest.into_iter().take(KEPT))
        .collect()
}

/// `list` with `opened` opened at `now` in the project directory named
/// `project` (`None`: none, an ephemeral session), its bytes' SHA-256
/// `sha256` (lower-case hexadecimal): first among the pinned if it is
/// one, else first among the others. The same file in another project is
/// another entry; an entry of the file with no project known (an earlier
/// version's) becomes this one. Only a file opened (its image parsed) is
/// recorded, so that every entry is a file binbun opened.
pub fn opened(
    list: &[Recent],
    opened: &Path,
    sha256: &str,
    project: Option<&str>,
    now: u64,
) -> Vec<Recent> {
    let same = |r: &Recent| r.is(opened, project) || (r.path == opened && r.project.is_none());
    let before = list.iter().find(|r| same(r));
    let entry = Recent {
        path: opened.to_path_buf(),
        opened: now,
        pinned: before.is_some_and(|r| r.pinned),
        sha256: Some(sha256.to_owned()),
        project: project.map(str::to_owned),
    };
    ordered(
        std::iter::once(entry)
            .chain(list.iter().filter(|r| !same(r)).cloned())
            .collect(),
    )
}

/// `list` without the entry of `path` in `project`.
pub fn remove(list: &[Recent], path: &Path, project: Option<&str>) -> Vec<Recent> {
    list.iter()
        .filter(|r| !r.is(path, project))
        .cloned()
        .collect()
}

/// `list` with the entry of `path` in `project` pinned, or unpinned if it
/// was.
pub fn toggle_pin(list: &[Recent], path: &Path, project: Option<&str>) -> Vec<Recent> {
    ordered(
        list.iter()
            .map(|r| Recent {
                pinned: if r.is(path, project) {
                    !r.pinned
                } else {
                    r.pinned
                },
                ..r.clone()
            })
            .collect(),
    )
}

/// Whether `recent` is a file binbun opened: an absolute path (as every
/// file opened is recorded) still there, or gone but opened once (its
/// SHA-256 known), as a file moved or on a drive not mounted is, shown
/// muted. An entry of what never opened (a mistyped name, a flag taken
/// for a file by earlier versions) is neither.
fn once_opened(recent: &Recent) -> bool {
    recent.path.is_absolute() && (recent.sha256.is_some() || recent.path.exists())
}

/// The list at `path` (empty if there is none), without the entries of
/// files never opened ([`once_opened`]).
pub fn load(path: &Path) -> Vec<Recent> {
    fs::read_to_string(path)
        .map(|t| parse(&t).into_iter().filter(once_opened).collect())
        .unwrap_or_default()
}

/// Writes `list` to `path`, making its directory.
///
/// # Errors
///
/// It cannot be written.
pub fn save(path: &Path, list: &[Recent]) -> Result<(), String> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    }
    let mut text = String::new();
    for r in list {
        let pin = if r.pinned { "pin" } else { "-" };
        let sha256 = r.sha256.as_deref().unwrap_or("-");
        let _ = write!(text, "{}\t{pin}\t{sha256}\t", r.opened);
        if let Some(project) = r.project.as_deref().filter(|_| r.sha256.is_some()) {
            let _ = write!(text, "{project}\t");
        }
        let _ = writeln!(text, "{}", r.path.to_string_lossy());
    }
    fs::write(path, text).map_err(|e| format!("{}: {e}", path.display()))
}

/// How long ago `then` was at `now` (seconds), shortly: `now`, `5 min`,
/// `2 h`, `3 d`, `6 w`, `4 mo`, `2 y`; nothing if unknown.
pub fn ago(then: u64, now: u64) -> String {
    if then == 0 {
        return String::new();
    }
    let s = now.saturating_sub(then);
    match s {
        0..60 => "now".to_owned(),
        60..3_600 => format!("{} min", s / 60),
        3_600..86_400 => format!("{} h", s / 3_600),
        86_400..1_209_600 => format!("{} d", s / 86_400),
        1_209_600..5_184_000 => format!("{} w", s / 604_800),
        5_184_000..31_536_000 => format!("{} mo", s / 2_592_000),
        _ => format!("{} y", s / 31_536_000),
    }
}

/// The format and architecture a file's `header` (its first bytes) says,
/// as the status bar names them (`x86-64 ELF`, `x86-64 PE`): ELF's
/// `e_machine`, PE's COFF `Machine` (through `e_lfanew`), Mach-O's
/// `cputype`; a universal Mach-O is `Universal Mach-O` (the status bar
/// names the slice opened).
pub fn platform(header: &[u8]) -> Option<String> {
    let u16_at = |at: usize, little: bool| {
        let bytes: [u8; 2] = header.get(at..at + 2)?.try_into().ok()?;
        Some(if little {
            u16::from_le_bytes(bytes)
        } else {
            u16::from_be_bytes(bytes)
        })
    };
    if header.starts_with(b"\x7fELF") {
        let little = header.get(5) != Some(&2);
        let machine = match u16_at(18, little)? {
            3 => "x86",
            62 => "x86-64",
            183 => "AArch64",
            40 => "ARM",
            _ => "?",
        };
        return Some(format!("{machine} ELF"));
    }
    if header.starts_with(b"MZ") {
        let at =
            usize::try_from(u32::from_le_bytes(header.get(0x3c..0x40)?.try_into().ok()?)).ok()?;
        if header.get(at..at + 4)? != b"PE\0\0" {
            return None;
        }
        let machine = match u16_at(at + 4, true)? {
            0x14c => "x86",
            0x8664 => "x86-64",
            0xaa64 => "AArch64",
            0x1c0 | 0x1c4 => "ARM",
            _ => "?",
        };
        return Some(format!("{machine} PE"));
    }
    macho(header)
}

/// [`platform`] of a Mach-O header: thin (either width, either byte order)
/// or universal (`fat_header`, big-endian; 32- or 64-bit `fat_arch`). A
/// universal header counts only with 1 to 16 slices of known CPUs, since
/// Java class files begin with the same magic.
fn macho(header: &[u8]) -> Option<String> {
    let cpu = |cputype: u32| match cputype {
        7 => Some("x86"),
        0x0100_0007 => Some("x86-64"),
        12 => Some("ARM"),
        0x0100_000c | 0x0200_000c => Some("AArch64"),
        _ => None,
    };
    let u32_at = |at: usize, little: bool| {
        let bytes: [u8; 4] = header.get(at..at + 4)?.try_into().ok()?;
        Some(if little {
            u32::from_le_bytes(bytes)
        } else {
            u32::from_be_bytes(bytes)
        })
    };
    match u32_at(0, false)? {
        // feedface or feedfacf stored little-endian, then big-endian.
        0xcefa_edfe | 0xcffa_edfe => {
            Some(format!("{} Mach-O", cpu(u32_at(4, true)?).unwrap_or("?")))
        }
        0xfeed_face | 0xfeed_facf => {
            Some(format!("{} Mach-O", cpu(u32_at(4, false)?).unwrap_or("?")))
        }
        magic @ (0xcafe_babe | 0xcafe_babf) => {
            let count = usize::try_from(u32_at(4, false)?).ok()?;
            if !(1..=16).contains(&count) {
                return None;
            }
            let entry = if magic == 0xcafe_babe { 20 } else { 32 };
            for i in 0..count {
                cpu(u32_at(8 + i * entry, false)?)?;
            }
            Some("Universal Mach-O".to_owned())
        }
        _ => None,
    }
}

/// [`platform`] of the file at `path`, from its first 4 KiB.
pub fn platform_of(path: &Path) -> Option<String> {
    let mut header = Vec::with_capacity(4096);
    fs::File::open(path)
        .ok()?
        .take(4096)
        .read_to_end(&mut header)
        .ok()?;
    platform(&header)
}

/// Whether `recent`'s project in the projects directory `root` holds the
/// user's work ([`project::Project::has_edits`]): the one it was opened
/// in, else the one found by the SHA-256 the file had when last opened;
/// either only if the file has not been modified since (else its bytes,
/// and so its project, are unknown until it is opened again).
pub fn has_project(recent: &Recent, root: &Path) -> bool {
    let Some(sha256) = &recent.sha256 else {
        return false;
    };
    let modified = fs::metadata(&recent.path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|m| m.duration_since(UNIX_EPOCH).ok());
    if modified.is_none_or(|m| m.as_secs() > recent.opened) {
        return false;
    }
    match &recent.project {
        Some(name) => project::Project::new(root.join(name)).has_edits(),
        None => project::find(root, sha256).is_some_and(|p| p.has_edits()),
    }
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use binbun_session::Key;
    use binbun_session::project;

    use super::{KEPT, Recent, ago, has_project, opened, parse, platform, toggle_pin};

    fn paths(list: &[Recent]) -> Vec<&Path> {
        list.iter().map(|r| r.path.as_path()).collect()
    }

    fn add(list: &[Recent], path: &Path, now: u64) -> Vec<Recent> {
        opened(list, path, &"00".repeat(32), None, now)
    }

    #[test]
    fn opening_moves_to_the_front_pinned_stay_first_and_the_list_is_bounded() {
        let list = parse("/a\n\n100\tpin\t/p\n /c \n");
        assert_eq!(
            paths(&list),
            [Path::new("/p"), Path::new("/a"), Path::new("/c")]
        );
        assert_eq!(list[0].opened, 100);
        let list = add(&list, Path::new("/c"), 500);
        assert_eq!(
            paths(&list),
            [Path::new("/p"), Path::new("/c"), Path::new("/a")]
        );
        assert_eq!(list[1].opened, 500);
        // Opening a pinned file keeps it pinned.
        let list = add(&list, Path::new("/p"), 600);
        assert!(list[0].pinned);
        let list = toggle_pin(&list, Path::new("/a"), None);
        assert_eq!(
            paths(&list),
            [Path::new("/p"), Path::new("/a"), Path::new("/c")]
        );
        let many: Vec<Recent> = (0..30)
            .map(|i| Recent {
                path: PathBuf::from(format!("/{i}")),
                opened: 1,
                pinned: false,
                sha256: None,
                project: None,
            })
            .collect();
        let list = add(&many, Path::new("/new"), 2);
        assert_eq!(list.len(), KEPT);
        assert_eq!(list[KEPT - 1].path, PathBuf::from("/18"));
    }

    /// A file opened in its private project and in a share's is two
    /// entries, each remembering its project; an earlier version's entry
    /// of the file (no project) becomes the first opened.
    #[test]
    fn each_project_of_a_file_is_its_own_entry_and_round_trips() {
        let sha = "ab".repeat(32);
        let root = if cfg!(windows) { r"C:\" } else { "/" };
        let file = PathBuf::from(format!("{root}bash"));
        let private = format!("{sha}-bash");
        let share = format!("{sha}-bash@0123456789abcdef");
        let list = parse(&format!("5\tpin\t{sha}\t{}\n", file.display()));
        let list = opened(&list, &file, &sha, Some(&private), 10);
        assert_eq!(list.len(), 1);
        assert!(list[0].pinned);
        let list = opened(&list, &file, &sha, Some(&share), 20);
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].project.as_deref(), Some(private.as_str()));
        assert_eq!(list[1].project.as_deref(), Some(share.as_str()));
        let list = toggle_pin(&list, &file, Some(&private));
        assert!(list.iter().all(|r| !r.pinned));
        let list = toggle_pin(&list, &file, Some(&share));
        assert_eq!(list[0].project.as_deref(), Some(share.as_str()));
        assert!(list[0].pinned && !list[1].pinned);
        let dir =
            std::env::temp_dir().join(format!("binbun-recent-projects-{}", std::process::id()));
        let saved = dir.join("recent");
        super::save(&saved, &list).unwrap();
        let read = parse(&std::fs::read_to_string(&saved).unwrap());
        assert_eq!(read, list);
        let _ = std::fs::remove_dir_all(dir);
        let list = super::remove(&list, &file, Some(&share));
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].project.as_deref(), Some(private.as_str()));
    }

    #[test]
    fn the_file_round_trips() {
        let sha = "ab".repeat(32);
        // Absolute paths, as every file opened is recorded.
        let root = if cfg!(windows) { r"C:\" } else { "/" };
        let list = parse(&format!(
            "5\tpin\t{root}x y\n7\t-\t{sha}\t{root}z\n9\t-\t{sha}\t{root}t\tab\n"
        ));
        assert_eq!(list[0].sha256, None);
        assert_eq!(list[1].sha256.as_deref(), Some(sha.as_str()));
        assert_eq!(list[1].path, Path::new(&format!("{root}z")));
        assert_eq!(list[2].path, Path::new(&format!("{root}t\tab")));
        let dir = std::env::temp_dir().join(format!("binbun-recent-{}", std::process::id()));
        let file = dir.join("recent");
        super::save(&file, &list).unwrap();
        // `x y`, of no SHA-256 and not there, never opened.
        assert_eq!(super::load(&file), list[1..]);
        let _ = std::fs::remove_dir_all(dir);
    }

    /// What never opened (a flag or a command taken for a file, a file
    /// not there) is not listed; a file opened once is, there or not.
    #[test]
    fn only_files_opened_once_are_listed() {
        let dir = std::env::temp_dir().join(format!("binbun-recent-once-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let here = dir.join("here");
        std::fs::write(&here, b"bytes").unwrap();
        let gone = dir.join("gone");
        let sha = "ab".repeat(32);
        let list = [
            ("--help", Some(sha.as_str())),
            ("functions", None),
            (gone.to_str().unwrap(), None),
            (gone.to_str().unwrap(), Some(sha.as_str())),
            (here.to_str().unwrap(), None),
        ]
        .map(|(path, sha256)| Recent {
            path: PathBuf::from(path),
            opened: 1,
            pinned: false,
            sha256: sha256.map(str::to_owned),
            project: None,
        });
        let file = dir.join("recent");
        super::save(&file, &list).unwrap();
        assert_eq!(super::load(&file), list[3..]);
        let _ = std::fs::remove_dir_all(dir);
    }

    /// The edits mark: the project of the SHA-256 last read, while the
    /// file is as it was then, holding edits.
    #[test]
    fn the_edits_mark_follows_the_project_of_the_bytes_last_opened() {
        let dir = std::env::temp_dir().join(format!("binbun-recent-mark-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let root = dir.join("projects");
        let binary = dir.join("bash");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(&binary, b"bytes").unwrap();
        let key = Key::new(b"bytes", "elsewhere");
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 1;
        let list = opened(&[], &binary, &key.hex(), None, now);
        // A project of the same bytes under another name is its project;
        // a layout alone is no edit.
        let project = project::locate(&root, &key, &project::Choice::Any)
            .unwrap()
            .project;
        std::fs::create_dir_all(project.dir()).unwrap();
        std::fs::write(project.layout(), "format = 1\n").unwrap();
        assert!(!has_project(&list[0], &root));
        std::fs::write(project.overlays(), "").unwrap();
        assert!(has_project(&list[0], &root));
        // Opened again as other bytes: the project of those.
        let list = add(&list, &binary, now);
        assert!(!has_project(&list[0], &root));
        // Modified since it was opened: its bytes are unknown.
        let list = opened(&list, &binary, &key.hex(), None, now - 3600);
        assert!(!has_project(&list[0], &root));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn ago_rounds_down_to_one_unit() {
        assert_eq!(ago(0, 100), "");
        assert_eq!(ago(100, 130), "now");
        assert_eq!(ago(1, 7_200), "1 h");
        assert_eq!(ago(1, 1 + 3 * 86_400 + 5), "3 d");
        assert_eq!(ago(1, 1 + 400 * 86_400), "1 y");
    }

    #[test]
    fn headers_name_format_and_machine() {
        let mut elf = vec![0x7f, b'E', b'L', b'F', 2, 1];
        elf.resize(20, 0);
        elf[18] = 62;
        assert_eq!(platform(&elf).as_deref(), Some("x86-64 ELF"));
        let mut pe = vec![0u8; 0x90];
        pe[0] = b'M';
        pe[1] = b'Z';
        pe[0x3c] = 0x80;
        pe[0x80..0x84].copy_from_slice(b"PE\0\0");
        pe[0x84..0x86].copy_from_slice(&0xaa64u16.to_le_bytes());
        assert_eq!(platform(&pe).as_deref(), Some("AArch64 PE"));
        pe[0x80] = b'X';
        assert_eq!(platform(&pe), None);
        assert_eq!(platform(b"#!/bin/sh"), None);
        // A thin 64-bit Mach-O for arm64, as stored on disk (little-endian).
        let mut thin = 0xfeed_facfu32.to_le_bytes().to_vec();
        thin.extend(0x0100_000cu32.to_le_bytes());
        assert_eq!(platform(&thin).as_deref(), Some("AArch64 Mach-O"));
        // A universal one: big-endian header, one 20-byte entry per slice.
        let mut fat = 0xcafe_babeu32.to_be_bytes().to_vec();
        fat.extend(2u32.to_be_bytes());
        for cpu in [0x0100_0007u32, 0x0100_000c] {
            fat.extend(cpu.to_be_bytes());
            fat.extend([0u8; 16]);
        }
        assert_eq!(platform(&fat).as_deref(), Some("Universal Mach-O"));
        // A Java class file shares the magic: its "count" is a version.
        let mut class = 0xcafe_babeu32.to_be_bytes().to_vec();
        class.extend([0, 0, 0, 52]);
        assert_eq!(platform(&class), None);
    }
}
