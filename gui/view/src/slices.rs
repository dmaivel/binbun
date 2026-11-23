//! The slices of a universal Mach-O file as the window offers them: which
//! a file has ([`of_file`], from its header alone), the one offered first
//! ([`preferred`]: this machine's instruction set's, else the first), and
//! the slice chosen for each file, remembered for opening it again
//! ([`binbun_paths::Place::Slices`], beside the recent files: one line a
//! file, `ARCH<TAB>PATH`, the newest first, at most [`KEPT`]).

use std::fmt::Write as _;
use std::fs;
use std::io::Read as _;
use std::path::{Path, PathBuf};

use binbun_loader::Machine;
pub use binbun_loader::Slice;

/// The most files whose slice is remembered.
pub const KEPT: usize = 200;

/// How much of a file's start its slices are read from: the universal
/// header and its table (20 or 32 bytes a slice).
const HEADER: u64 = 64 * 1024;

/// The slices of the universal Mach-O file at `path`, in the file's
/// order; none for any other file (or one that cannot be read).
pub fn of_file(path: &Path) -> Vec<Slice> {
    let mut header = Vec::new();
    let read = fs::File::open(path).and_then(|file| file.take(HEADER).read_to_end(&mut header));
    if read.is_err() {
        return Vec::new();
    }
    binbun_loader::slices(&header).unwrap_or_default()
}

/// Whether the universal Mach-O file `data` has a slice of architecture
/// `arch`.
pub fn has(data: &[u8], arch: &str) -> bool {
    binbun_loader::slices(data)
        .unwrap_or_default()
        .iter()
        .any(|slice| slice.arch == arch)
}

/// The place in `slices` of the one offered first: this machine's
/// instruction set's, else the first.
pub fn preferred(slices: &[Slice]) -> usize {
    binbun_loader::preferred(slices)
        .and_then(|chosen| slices.iter().position(|slice| slice == chosen))
        .unwrap_or(0)
}

/// `slice`'s instruction set, as the picker names it beside its
/// architecture.
pub fn machine(slice: &Slice) -> &'static str {
    match slice.machine {
        Machine::X86 => "x86",
        Machine::X86_64 => "x86-64",
        Machine::Aarch64 => "AArch64",
        Machine::Arm => "ARM",
        Machine::Other => "not supported",
    }
}

/// The slices chosen, newest first: each file's path and architecture.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Chosen(Vec<(PathBuf, String)>);

impl Chosen {
    /// The list in `text` (lines `ARCH<TAB>PATH`; others skipped).
    pub fn parse(text: &str) -> Self {
        Self(
            text.lines()
                .filter_map(|line| {
                    let (arch, path) = line.split_once('\t')?;
                    (!arch.is_empty() && !path.is_empty())
                        .then(|| (PathBuf::from(path), arch.to_owned()))
                })
                .take(KEPT)
                .collect(),
        )
    }

    /// The list as its file holds it.
    pub fn text(&self) -> String {
        let mut text = String::new();
        for (path, arch) in &self.0 {
            let _ = writeln!(text, "{arch}\t{}", path.to_string_lossy());
        }
        text
    }

    /// The slice chosen for the file at `path`, if one was.
    pub fn of(&self, path: &Path) -> Option<&str> {
        self.0
            .iter()
            .find(|(chosen, _)| chosen == path)
            .map(|(_, arch)| arch.as_str())
    }

    /// The slice `arch` chosen for the file at `path`: first, in place of
    /// the one chosen before; the oldest past [`KEPT`] forgotten.
    pub fn choose(&mut self, path: &Path, arch: &str) {
        self.0.retain(|(chosen, _)| chosen != path);
        self.0.insert(0, (path.to_path_buf(), arch.to_owned()));
        self.0.truncate(KEPT);
    }

    /// The list at `path` (empty if there is none).
    pub fn load(path: &Path) -> Self {
        fs::read_to_string(path)
            .map(|text| Self::parse(&text))
            .unwrap_or_default()
    }

    /// Writes the list to `path`, making its directory.
    ///
    /// # Errors
    ///
    /// It cannot be written.
    pub fn save(&self, path: &Path) -> Result<(), String> {
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        }
        fs::write(path, self.text()).map_err(|e| format!("{}: {e}", path.display()))
    }
}

/// Where the slices chosen are kept ([`binbun_paths::Place::Slices`]).
pub fn path() -> Option<PathBuf> {
    binbun_paths::Place::Slices.path()
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use super::{Chosen, KEPT, has, machine, of_file, preferred};

    fn fixture(name: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures")
            .join(name)
    }

    #[test]
    fn a_universal_files_slices_come_from_its_header_and_the_hosts_is_offered_first() {
        let path = fixture("program-universal.macho");
        let slices = of_file(&path);
        let arches: Vec<&str> = slices.iter().map(|s| s.arch.as_str()).collect();
        assert_eq!(arches, ["x86_64", "arm64", "arm64e"]);
        assert_eq!(
            slices.iter().map(machine).collect::<Vec<_>>(),
            ["x86-64", "AArch64", "AArch64"]
        );
        let offered = &slices[preferred(&slices)].arch;
        let host = if cfg!(target_arch = "aarch64") {
            "arm64"
        } else {
            "x86_64"
        };
        assert_eq!(offered, host);
        // Read from its first bytes alone, as the whole file says.
        let data = std::fs::read(&path).unwrap();
        assert_eq!(binbun_loader::slices(&data).unwrap(), slices);
        assert!(has(&data, "arm64e") && !has(&data, "i386"));
        // Any other file has none.
        assert_eq!(of_file(&fixture("program-x86_64.elf")), []);
        assert_eq!(of_file(&fixture("no such file")), []);
    }

    #[test]
    fn the_slice_chosen_is_remembered_per_file_newest_first() {
        let dir = std::env::temp_dir().join(format!("binbun-slices-{}", std::process::id()));
        let file = dir.join("state/binbun/slices");
        let (a, b) = (Path::new("/bin/a"), Path::new("/bin/b c"));
        let mut chosen = Chosen::load(&file);
        assert_eq!(chosen.of(a), None);
        chosen.choose(a, "arm64e");
        chosen.choose(b, "x86_64");
        chosen.choose(a, "x86_64");
        assert_eq!(chosen.of(a), Some("x86_64"));
        assert_eq!(chosen.text(), "x86_64\t/bin/a\nx86_64\t/bin/b c\n");
        chosen.save(&file).unwrap();
        assert_eq!(Chosen::load(&file), chosen);
        // A line without both fields is skipped.
        assert_eq!(
            Chosen::parse("arm64\n\t/x\nx86_64\t/bin/a\n").of(a),
            Some("x86_64")
        );
        // The oldest past KEPT is forgotten.
        for n in 0..KEPT {
            chosen.choose(&PathBuf::from(format!("/f/{n}")), "arm64");
        }
        assert_eq!(chosen.of(b), None);
        assert_eq!(chosen.of(Path::new("/f/0")), Some("arm64"));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
