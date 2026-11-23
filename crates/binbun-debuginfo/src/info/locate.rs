//! Where an image's debug information is, by the documented conventions
//! ([`Search`]), and reading it from there.
//!
//! - **ELF** (GDB's "Separate Debug Files"): the image itself if it has a
//!   `.debug_info` section; by build ID (`NT_GNU_BUILD_ID`),
//!   `<debug directory>/.build-id/xx/yyyy.debug` (`xx` the ID's first
//!   byte, `yyyy` the rest, in hexadecimal); by `.gnu_debuglink`'s file
//!   name, in the image's directory, its `.debug` subdirectory and the
//!   image's directory under the debug directory; then the debuginfod
//!   client's cache, `<cache>/<build ID>/debuginfo`. A separate file is the
//!   image's if its build ID is the image's; without a build ID in the
//!   image, if its CRC-32 is the one `.gnu_debuglink` states (as GDB
//!   checks).
//! - **PE**: the PDB the `CodeView` debug record names, at its path (if
//!   absolute here: on Windows, where it was built), then by its file name
//!   in the image's directory, then by the image's own name with `.pdb`
//!   there (a PDB renamed with its image); [`crate::pdb::read`] checks it
//!   is the image's (GUID and age).
//! - **Mach-O**: the dSYM bundle beside the image,
//!   `<image>.dSYM/Contents/Resources/DWARF/<image>`, as `dsymutil` names
//!   it; [`crate::dsym::slice`] checks it is the image's (`LC_UUID`). The
//!   image's bytes are one slice of a universal file.
//!
//! A candidate that exists but is not the image's (another build's) is
//! passed over, never read as its; [`Search::search`] says which and why.
//! An empty file is taken as no file: the debuginfod client leaves one
//! where a download would go to remember a failed query.

use std::env;
use std::ffi::OsStr;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::str;
use std::{fs, io};

use object::{BinaryFormat, Object, ObjectSection};

use crate::info::{DebugModel, read};

/// Debug information found for an image.
#[derive(Clone, Debug)]
pub struct Found {
    /// The file it was read from (the image's own path for its own DWARF).
    pub path: PathBuf,
    /// What it states.
    pub model: DebugModel,
}

/// What a search found ([`Search::search`]).
#[derive(Clone, Debug, Default)]
pub struct Searched {
    /// The debug information of the first candidate that is the image's.
    pub found: Option<Found>,
    /// The candidates before it that exist but were passed over, and why:
    /// another build's (its GUID and age, build ID or UUID differ), or
    /// unreadable.
    pub passed: Vec<(PathBuf, String)>,
}

/// Where separate debug files are looked for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Search {
    /// The global debug directory (GDB's `debug-file-directory`):
    /// `/usr/lib/debug`.
    pub debug_directory: PathBuf,
    /// The debuginfod client's cache, if there is one.
    pub debuginfod_cache: Option<PathBuf>,
}

/// How a candidate file is checked to be the image's.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Check {
    /// The image itself.
    Itself,
    /// Its build ID equals the image's, else (the image has none) its
    /// CRC-32 is `.gnu_debuglink`'s.
    Elf,
    /// A PDB: the reader checks the `CodeView` GUID and age.
    Pdb,
    /// A dSYM file: the reader checks the UUID.
    Dsym,
}

impl Search {
    /// The conventional places: `/usr/lib/debug`, and the debuginfod
    /// cache `debuginfod-client-config(7)` documents:
    /// `$DEBUGINFOD_CACHE_PATH`, else `$HOME/.debuginfod_client_cache` if
    /// it exists, else `$XDG_CACHE_HOME/debuginfod_client`, else
    /// `$HOME/.cache/debuginfod_client`.
    pub fn from_environment() -> Self {
        Self {
            debug_directory: PathBuf::from("/usr/lib/debug"),
            debuginfod_cache: debuginfod_cache(),
        }
    }

    /// The files the debug information of the image at `path` (whose
    /// bytes are `data`) may be in, in the order they are tried.
    pub fn candidates(&self, path: &Path, data: &[u8]) -> Vec<PathBuf> {
        self.checked(path, data)
            .into_iter()
            .map(|(candidate, _)| candidate)
            .collect()
    }

    /// The debug information of the image at `path` (whose bytes are
    /// `data`): from the first of its [`Self::candidates`] that is the
    /// image's and reads.
    pub fn find(&self, path: &Path, data: &[u8]) -> Option<Found> {
        self.search(path, data).found
    }

    /// [`Self::find`], with the candidates that exist but were passed over
    /// before the one found (all of them if none is), and why.
    pub fn search(&self, path: &Path, data: &[u8]) -> Searched {
        let mut searched = Searched::default();
        let Ok(file) = object::File::parse(data) else {
            return searched;
        };
        let build_id = file.build_id().ok().flatten();
        let crc = file.gnu_debuglink().ok().flatten().map(|(_, crc)| crc);
        for (candidate, check) in self.checked(path, data) {
            let model = match check {
                Check::Itself => read(data, data),
                Check::Elf | Check::Pdb | Check::Dsym => match fs::read(&candidate) {
                    Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                    Err(error) => Err(error.to_string()),
                    Ok(debug) if debug.is_empty() => continue,
                    Ok(debug) if check == Check::Elf && !is_elf_debug_of(&debug, build_id, crc) => {
                        Err("another build's debug file (its build ID or CRC differs)".to_owned())
                    }
                    Ok(debug) => read(&debug, data),
                },
            };
            match model {
                Ok(model) => {
                    searched.found = Some(Found {
                        path: candidate,
                        model,
                    });
                    break;
                }
                Err(reason) => searched.passed.push((candidate, reason)),
            }
        }
        searched
    }

    /// [`Self::candidates`], each with how it is checked.
    fn checked(&self, path: &Path, data: &[u8]) -> Vec<(PathBuf, Check)> {
        let Ok(file) = object::File::parse(data) else {
            return Vec::new();
        };
        let directory = binbun_paths::canonical(path)
            .ok()
            .and_then(|path| path.parent().map(Path::to_owned))
            .or_else(|| path.parent().map(Path::to_owned))
            .unwrap_or_default();
        let format = file.format();
        if format == BinaryFormat::Elf {
            self.elf(path, &directory, &file)
        } else if format == BinaryFormat::Pe {
            pe(path, &directory, &file)
        } else if format == BinaryFormat::MachO {
            dsym(path, &directory)
        } else {
            Vec::new()
        }
    }

    /// The candidates of the ELF image `file` at `path`, in `directory`.
    fn elf(&self, path: &Path, directory: &Path, file: &object::File<'_>) -> Vec<(PathBuf, Check)> {
        let mut out = Vec::new();
        if file
            .section_by_name(".debug_info")
            .is_some_and(|section| section.size() > 0)
        {
            out.push((path.to_owned(), Check::Itself));
        }
        let build_id = file.build_id().ok().flatten().filter(|id| !id.is_empty());
        if let Some((first, rest)) = build_id.and_then(<[u8]>::split_first) {
            out.push((
                self.debug_directory
                    .join(".build-id")
                    .join(hex(&[*first]))
                    .join(format!("{}.debug", hex(rest))),
                Check::Elf,
            ));
        }
        if let Some((name, _)) = file.gnu_debuglink().ok().flatten()
            && let Some(name) = file_name(name)
        {
            let itself = directory.join(path.file_name().unwrap_or_default());
            let under = directory.strip_prefix("/").unwrap_or(directory);
            for candidate in [
                directory.join(name),
                directory.join(".debug").join(name),
                self.debug_directory.join(under).join(name),
            ] {
                if candidate != path && candidate != itself {
                    out.push((candidate, Check::Elf));
                }
            }
        }
        if let (Some(id), Some(cache)) = (build_id, &self.debuginfod_cache) {
            out.push((cache.join(hex(id)).join("debuginfo"), Check::Elf));
        }
        out
    }
}

/// Reads the debug information at `debug` for the image at `path` (whose
/// bytes are `data`): a separate ELF debug file, a PDB, or the image
/// itself (`debug` is `path`); a dSYM bundle (its DWARF file) or file.
///
/// # Errors
///
/// If `debug` cannot be read, is no file a reader reads, or is a PDB or
/// dSYM that is not the image's.
pub fn open(debug: &Path, path: &Path, data: &[u8]) -> Result<DebugModel, String> {
    let at = |error: String| format!("{}: {error}", debug.display());
    if debug == path {
        return read(data, data).map_err(at);
    }
    let file = if debug.is_dir() {
        bundled(debug).map_err(at)?
    } else {
        debug.to_owned()
    };
    let bytes = fs::read(file).map_err(|error| at(error.to_string()))?;
    read(&bytes, data).map_err(at)
}

/// The DWARF file of the dSYM bundle `bundle`: the one file in its
/// `Contents/Resources/DWARF`.
fn bundled(bundle: &Path) -> Result<PathBuf, String> {
    let dwarf = bundle.join("Contents").join("Resources").join("DWARF");
    let mut files = fs::read_dir(&dwarf)
        .map_err(|error| format!("no dSYM bundle: {error}"))?
        .filter_map(Result::ok)
        .map(|entry| entry.path());
    match (files.next(), files.next()) {
        (Some(file), None) => Ok(file),
        (None, _) => Err("no file in the dSYM bundle's Contents/Resources/DWARF".to_owned()),
        (Some(_), Some(_)) => {
            Err("more than one file in the dSYM bundle's Contents/Resources/DWARF".to_owned())
        }
    }
}

/// The candidate of the Mach-O image at `path` in `directory`: the DWARF
/// file of the dSYM bundle beside it, named after it.
fn dsym(path: &Path, directory: &Path) -> Vec<(PathBuf, Check)> {
    let Some(name) = path.file_name() else {
        return Vec::new();
    };
    let mut bundle = name.to_owned();
    bundle.push(".dSYM");
    vec![(
        directory
            .join(bundle)
            .join("Contents")
            .join("Resources")
            .join("DWARF")
            .join(name),
        Check::Dsym,
    )]
}

/// The candidates of the PE image `file` at `path`, in `directory`: the
/// PDB its `CodeView` record names, at the stated path (if absolute here:
/// a Windows path is not on another system), then beside the image, then
/// the image's name with `.pdb` beside it.
fn pe(path: &Path, directory: &Path, file: &object::File<'_>) -> Vec<(PathBuf, Check)> {
    let Some(codeview) = file.pdb_info().ok().flatten() else {
        return Vec::new();
    };
    let Some(name) = file_name(codeview.path()) else {
        return Vec::new();
    };
    let stated = PathBuf::from(String::from_utf8_lossy(codeview.path()).into_owned());
    let beside = directory.join(name);
    let mut out = Vec::new();
    if stated.is_absolute() && stated != beside {
        out.push((stated, Check::Pdb));
    }
    let renamed = path
        .file_stem()
        .map(|stem| directory.join(stem).with_extension("pdb"))
        .filter(|renamed| *renamed != beside);
    out.push((beside, Check::Pdb));
    out.extend(renamed.map(|renamed| (renamed, Check::Pdb)));
    out
}

/// Whether `debug` is a separate ELF debug file of an image with build ID
/// `build_id`, else (the image has none) with `.gnu_debuglink` CRC `crc`.
fn is_elf_debug_of(debug: &[u8], build_id: Option<&[u8]>, crc: Option<u32>) -> bool {
    match build_id {
        Some(id) => object::File::parse(debug)
            .ok()
            .and_then(|file| file.build_id().ok().flatten())
            .is_some_and(|own| own == id),
        None => crc == Some(crc32(debug)),
    }
}

/// The debuginfod client's cache directory ([`Search::from_environment`]).
fn debuginfod_cache() -> Option<PathBuf> {
    if let Some(path) = env::var_os("DEBUGINFOD_CACHE_PATH").filter(|path| !path.is_empty()) {
        return Some(PathBuf::from(path));
    }
    let home = binbun_paths::home();
    if let Some(legacy) = home
        .as_ref()
        .map(|home| home.join(".debuginfod_client_cache"))
        && legacy.is_dir()
    {
        return Some(legacy);
    }
    env::var_os("XDG_CACHE_HOME")
        .filter(|cache| !cache.is_empty())
        .map(PathBuf::from)
        .or_else(|| home.map(|home| home.join(".cache")))
        .map(|cache| cache.join("debuginfod_client"))
}

/// The last component of a path as a file states it (`/` or `\`
/// separated), if any.
fn file_name(path: &[u8]) -> Option<&OsStr> {
    let name = path.rsplit(|&byte| byte == b'/' || byte == b'\\').next()?;
    let name = str::from_utf8(name).ok()?;
    (!name.is_empty() && name != "." && name != "..").then(|| OsStr::new(name))
}

/// `bytes` in lower-case hexadecimal.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut text, byte| {
        let _ = write!(text, "{byte:02x}");
        text
    })
}

/// CRC-32 (ISO-HDLC: reflected polynomial `0xedb88320`), as
/// `.gnu_debuglink` states it; bit by bit (checked only for images
/// without a build ID).
fn crc32(data: &[u8]) -> u32 {
    !data.iter().fold(!0u32, |crc, &byte| {
        (0..8).fold(crc ^ u32::from(byte), |crc, _| {
            if crc & 1 == 1 {
                0xedb8_8320 ^ (crc >> 1)
            } else {
                crc >> 1
            }
        })
    })
}
