//! The databases binbun embeds, and those it finds in the database
//! directory at run time.

use std::collections::BTreeSet;
use std::fs::File;
use std::io::{self, BufRead as _, BufReader, Read};
use std::path::{Path, PathBuf};
use std::sync::{LazyLock, OnceLock};
use std::{fmt, fs};

use ruzstd::decoding::StreamingDecoder;

use crate::database::{Database, Header};
use crate::jsonl;
use crate::{LoadError, TypeLibrary};

/// The embedded databases (every `data/*.jsonl`), by file name, as `build.rs`
/// compressed them with zstd, in the order a target's are added to its
/// library.
const EMBEDDED_FILES: &[(&str, &[u8])] = &include!(concat!(env!("OUT_DIR"), "/embedded.rs"));

/// zstd's magic number: a compressed file's first four bytes.
const ZSTD_MAGIC: [u8; 4] = [0x28, 0xb5, 0x2f, 0xfd];

/// The most memory set aside for a decompressed text before reading it,
/// whatever size its frame header gives: a larger text grows as it is read.
const MOST_RESERVED: u64 = 1 << 28;

/// A database: its header, read when the databases are listed, and the
/// database, decompressed and parsed when first asked for.
struct Lazy {
    /// The file: its name (embedded) or path (in the database directory).
    path: PathBuf,
    /// The embedded database's compressed text; `None`: the file's.
    embedded: Option<&'static [u8]>,
    header: Header,
    database: OnceLock<Result<Database, FileError>>,
}

impl Lazy {
    /// The database, read and parsed on the first call.
    fn database(&self) -> Result<&Database, FileError> {
        self.database
            .get_or_init(|| {
                let text = match self.embedded {
                    Some(compressed) => decompress(compressed),
                    None => fs::read(&self.path).and_then(text),
                }
                .map_err(|error| file_error(&self.path, &error))?;
                jsonl::parse(&text).map_err(|error| file_error(&self.path, &error))
            })
            .as_ref()
            .map_err(Clone::clone)
    }

    fn is_for(&self, arch: &str, os: &str) -> bool {
        self.header.target.arch == arch && self.header.target.os == os
    }
}

static EMBEDDED: LazyLock<Vec<Lazy>> = LazyLock::new(embedded_files);

static FOUND: LazyLock<Result<Vec<Lazy>, FileError>> =
    LazyLock::new(|| database_dir().map_or_else(|| Ok(Vec::new()), |dir| list(&dir)));

/// The embedded databases, with their headers.
fn embedded_files() -> Vec<Lazy> {
    EMBEDDED_FILES
        .iter()
        .map(|&(name, compressed)| {
            let path = PathBuf::from(name);
            let header = first_line(compressed)
                .map_err(|error| file_error(&path, &error))
                .and_then(|line| jsonl::header(&line).map_err(|error| file_error(&path, &error)))
                .unwrap_or_else(|error| panic!("data/{error}"));
            Lazy {
                path,
                embedded: Some(compressed),
                header,
                database: OnceLock::new(),
            }
        })
        .collect()
}

/// The databases binbun embeds (`data/*.jsonl`: Linux x86-64 and AArch64
/// glibc and C++ runtime ABI (`cxxabi.h`, `unwind.h`), Linux x86-64
/// system calls; the Windows x86-64 and ARM64 C runtime, the UCRT's and
/// vcruntime's for any library and msvcrt.dll's others; Windows x86-64's
/// and ARM64's native API, ntdll.dll's, with the TEB and the structures it
/// reaches; Win32, from Microsoft's metadata, and what Windows kernel-mode
/// code imports, from the WDK's metadata, for x86-64 and ARM64 each; macOS
/// x86-64 and arm64's C library and C++
/// runtime ABI) whose target is `arch` and `os`, by file name, in the
/// order they are added to a library. Each is embedded compressed, and
/// decompressed and parsed once, when first asked for: of another
/// target's, only the header line (its target) is ever decompressed.
///
/// # Panics
///
/// If an embedded database does not parse (a test checks they do).
pub fn embedded(arch: &str, os: &str) -> Vec<(&'static str, &'static Database)> {
    EMBEDDED
        .iter()
        .filter(|database| database.is_for(arch, os))
        .map(|database| {
            let name = database.path.to_str().unwrap_or_default();
            let parsed = database
                .database()
                .unwrap_or_else(|error| panic!("data/{error}"));
            (name, parsed)
        })
        .collect()
}

/// The database directory ([`binbun_paths::Place::TypeDb`]: `$BINBUN_TYPEDB`,
/// else `~/.cache/binbun-typedb`); `None` without either. Its databases
/// are added to the embedded ones; one with an embedded one's file name
/// replaces it.
pub fn database_dir() -> Option<PathBuf> {
    binbun_paths::Place::TypeDb.path()
}

/// What code a library is for: a process's (user mode) or, on Windows, the
/// kernel's and its drivers' (kernel mode). It decides which of the
/// target's databases describe the system the code calls, by what each
/// declares (its file name's last part: `windows-x86_64-kernel.jsonl`
/// declares `kernel`): `kernel` (what drivers import from the kernel) is
/// kernel mode's; `win32` (the Win32 API) and `native` (ntdll.dll's native
/// API, with the TEB) are user mode's; the others (the C runtime, which
/// the kernel exports too) are both's.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Mode {
    /// A process's code.
    #[default]
    User,
    /// The kernel's and its drivers' code.
    Kernel,
}

impl Mode {
    /// Whether the database of name `name` (its file name, without a
    /// `.zst`) is for code of this mode.
    fn has(self, name: &str) -> bool {
        let declares = name
            .strip_suffix(".jsonl")
            .unwrap_or(name)
            .rsplit('-')
            .next()
            .unwrap_or_default();
        match declares {
            "kernel" => self == Self::Kernel,
            "win32" | "native" => self == Self::User,
            _ => true,
        }
    }
}

/// The databases in the [`database_dir`] (its `*.jsonl` files and
/// zstd-compressed `*.jsonl.zst` files, by name; of a `.jsonl` and a
/// `.jsonl.zst` of the same name, the `.jsonl`) whose target is `arch`
/// and `os`; none if the directory does not exist. Each file's header is
/// read once, and the database parsed once, when first asked for.
///
/// # Errors
///
/// If the directory or a file in it cannot be read, or a database for the
/// target cannot be parsed.
pub fn found(arch: &str, os: &str) -> Result<Vec<(&'static Path, &'static Database)>, FileError> {
    found_where(arch, os, |_| true)
}

/// [`found`], of the databases whose name (the file's, without a `.zst`)
/// `wanted` says.
fn found_where(
    arch: &str,
    os: &str,
    wanted: impl Fn(&str) -> bool,
) -> Result<Vec<(&'static Path, &'static Database)>, FileError> {
    let files = FOUND.as_ref().map_err(Clone::clone)?;
    files
        .iter()
        .filter(|file| file.is_for(arch, os))
        .filter(|file| database_name(&file.path).is_some_and(&wanted))
        .map(|file| Ok((file.path.as_path(), file.database()?)))
        .collect()
}

/// The name of the database in file `path`: its file name without `.zst`,
/// if that ends in `.jsonl`.
fn database_name(path: &Path) -> Option<&str> {
    let name = path.file_name()?.to_str()?;
    let name = name.strip_suffix(".zst").unwrap_or(name);
    Path::new(name)
        .extension()
        .is_some_and(|extension| extension == "jsonl")
        .then_some(name)
}

fn file_error(path: &Path, error: &dyn fmt::Display) -> FileError {
    FileError {
        path: path.to_owned(),
        message: error.to_string(),
    }
}

/// The database files in `dir`, with their headers.
fn list(dir: &Path) -> Result<Vec<Lazy>, FileError> {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(file_error(dir, &error)),
    };
    let mut paths = entries
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| file_error(dir, &error))?;
    paths.sort();
    let mut names = BTreeSet::new();
    paths.retain(|path| database_name(path).is_some_and(|name| names.insert(name.to_owned())));
    paths
        .into_iter()
        .map(|path| {
            let first = File::open(&path)
                .and_then(first_line)
                .map_err(|error| file_error(&path, &error))?;
            let header = jsonl::header(&first).map_err(|error| file_error(&path, &error))?;
            Ok(Lazy {
                path,
                embedded: None,
                header,
                database: OnceLock::new(),
            })
        })
        .collect()
}

/// The first line of the database file read from `reader`, decompressed
/// first if it is zstd's: only as much of it as that line needs.
fn first_line(reader: impl Read) -> io::Result<String> {
    let mut reader = BufReader::new(reader);
    let mut line = String::new();
    if reader.fill_buf()?.starts_with(&ZSTD_MAGIC) {
        let decoder = StreamingDecoder::new(reader).map_err(io::Error::other)?;
        BufReader::new(decoder).read_line(&mut line)?;
    } else {
        reader.read_line(&mut line)?;
    }
    Ok(line)
}

/// The text of a database file of `bytes`: decompressed if they are zstd's.
fn text(bytes: Vec<u8>) -> io::Result<String> {
    if bytes.starts_with(&ZSTD_MAGIC) {
        decompress(&bytes)
    } else {
        String::from_utf8(bytes).map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
    }
}

/// The text zstd compressed to `compressed`.
fn decompress(compressed: &[u8]) -> io::Result<String> {
    let mut decoder = StreamingDecoder::new(compressed).map_err(io::Error::other)?;
    let size = decoder.decoder.content_size().min(MOST_RESERVED);
    let mut text = String::with_capacity(usize::try_from(size).unwrap_or_default());
    decoder.read_to_string(&mut text)?;
    Ok(text)
}

/// A database file that cannot be read or parsed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileError {
    /// The file (or directory).
    pub path: PathBuf,
    /// What is wrong.
    pub message: String,
}

impl fmt::Display for FileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.path.display(), self.message)
    }
}

impl std::error::Error for FileError {}

/// Why [`TypeLibrary::for_mode`] cannot build a library.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LibraryError {
    /// A file in the database directory cannot be read or parsed.
    File(FileError),
    /// A database cannot be added.
    Load {
        /// The database's file name.
        database: String,
        /// Why.
        error: LoadError,
    },
}

impl fmt::Display for LibraryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::File(error) => error.fmt(f),
            Self::Load { database, error } => write!(f, "{database}: {error}"),
        }
    }
}

impl std::error::Error for LibraryError {}

impl TypeLibrary {
    /// The library for user-mode code of `arch` and `os`
    /// ([`for_mode`](Self::for_mode)).
    ///
    /// # Errors
    ///
    /// If a database in the directory for the target cannot be read,
    /// parsed or added.
    ///
    /// # Panics
    ///
    /// If an embedded database does not parse.
    pub fn for_target(arch: &str, os: &str) -> Result<Self, LibraryError> {
        Self::for_mode(arch, os, Mode::User)
    }

    /// The [`builtin`](Self::builtin) facts with the [`embedded`]
    /// databases, then those [`found`] in the database directory, whose
    /// target is `arch` and `os` (`x86_64`, `linux`) and that are for code
    /// of `mode`; a database found with an embedded one's name
    /// (`windows-x86_64-win32.jsonl`, or `.jsonl.zst`) replaces it. The C
    /// library's functions then take their system calls' flag sets
    /// ([`with_syscall_flags`](Self::with_syscall_flags)).
    ///
    /// # Errors
    ///
    /// If a database in the directory for the target cannot be read,
    /// parsed or added.
    ///
    /// # Panics
    ///
    /// If an embedded database does not parse.
    pub fn for_mode(arch: &str, os: &str, mode: Mode) -> Result<Self, LibraryError> {
        let found = found_where(arch, os, |name| mode.has(name)).map_err(LibraryError::File)?;
        Self::with_embedded(&EMBEDDED, arch, os, mode, &found)
    }

    /// The [`builtin`](Self::builtin) facts with the databases of
    /// `embedded` for `arch`, `os` and `mode` but those of the names of
    /// `found` (path, database), then `found`.
    fn with_embedded(
        embedded: &[Lazy],
        arch: &str,
        os: &str,
        mode: Mode,
        found: &[(&Path, &Database)],
    ) -> Result<Self, LibraryError> {
        let replaced: Vec<&str> = found
            .iter()
            .filter_map(|(path, _)| database_name(path))
            .collect();
        let mut library = Self::builtin();
        let embedded = embedded
            .iter()
            .filter(|database| {
                let name = database.path.to_str().unwrap_or_default();
                database.is_for(arch, os) && mode.has(name) && !replaced.contains(&name)
            })
            .map(|database| {
                let parsed = database
                    .database()
                    .unwrap_or_else(|error| panic!("data/{error}"));
                (database.path.display().to_string(), parsed)
            });
        let found = found
            .iter()
            .map(|&(path, database)| (path.display().to_string(), database));
        for (name, database) in embedded.chain(found) {
            library.add(database).map_err(|error| LibraryError::Load {
                database: name,
                error,
            })?;
        }
        library.with_syscall_flags();
        Ok(library)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests fail loudly")]

    use std::fs;
    use std::path::{Path, PathBuf};

    use ruzstd::encoding::{CompressionLevel, compress_to_vec};

    use super::{EMBEDDED, EMBEDDED_FILES, Mode, decompress, embedded_files, list};
    use crate::types::Record;
    use crate::{Origin, Type, TypeId, TypeLibrary, jsonl};

    /// A fresh directory for `test` in the build's `OUT_DIR`.
    fn scratch(test: &str) -> PathBuf {
        let dir = Path::new(env!("OUT_DIR")).join(format!("test-{test}"));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// An embedded database's text.
    fn text(name: &str) -> String {
        let (_, compressed) = EMBEDDED_FILES.iter().find(|(n, _)| *n == name).unwrap();
        decompress(compressed).unwrap()
    }

    #[test]
    fn the_directory_reads_plain_and_compressed_files_alike() {
        let dir = scratch("directory");
        let text = text("linux-x86_64-cxxabi.jsonl");
        fs::write(dir.join("a.jsonl"), &text).unwrap();
        // Shadowed by a.jsonl: never read.
        fs::write(dir.join("a.jsonl.zst"), b"not zstd").unwrap();
        let compressed = compress_to_vec(text.as_bytes(), CompressionLevel::Fastest);
        fs::write(dir.join("b.jsonl.zst"), compressed).unwrap();
        fs::write(dir.join("c.toml"), b"not a database").unwrap();
        let files = list(&dir).unwrap();
        let names: Vec<_> = files
            .iter()
            .map(|file| file.path.file_name().unwrap().to_str().unwrap())
            .collect();
        assert_eq!(names, ["a.jsonl", "b.jsonl.zst"]);
        let (plain, compressed) = (files[0].database().unwrap(), files[1].database().unwrap());
        assert_eq!(plain, compressed);
        assert_eq!(files[1].header, compressed.header);
        assert_eq!(jsonl::write(compressed).unwrap(), text);
    }

    #[test]
    fn a_damaged_compressed_file_is_an_error() {
        let dir = scratch("damaged");
        // Several blocks: the header, in the first, reads; the rest not.
        let text = text("linux-x86_64-libc.jsonl");
        let mut compressed = compress_to_vec(text.as_bytes(), CompressionLevel::Fastest);
        compressed.truncate(compressed.len() / 2);
        fs::write(dir.join("a.jsonl.zst"), compressed).unwrap();
        let files = list(&dir).unwrap();
        let error = files[0].database().unwrap_err();
        assert_eq!(error.path, dir.join("a.jsonl.zst"));
    }

    /// Opening a Linux binary decompresses none of the Windows databases
    /// (Win32's 21.5 MB). Of its own databases: other tests decompress
    /// Windows' in [`EMBEDDED`].
    #[test]
    fn another_targets_databases_stay_compressed() {
        let embedded = embedded_files();
        TypeLibrary::with_embedded(&embedded, "x86_64", "linux", Mode::User, &[]).unwrap();
        for database in &embedded {
            let linux = database.is_for("x86_64", "linux");
            assert_eq!(
                database.database.get().is_some(),
                linux,
                "{}",
                database.path.display()
            );
        }
    }

    /// The embedded databases for Windows x86-64 code of `mode`.
    fn windows(mode: Mode) -> TypeLibrary {
        TypeLibrary::with_embedded(&EMBEDDED, "x86_64", "windows", mode, &[]).unwrap()
    }

    /// The structure `key` of `library`.
    fn record<'l>(library: &'l TypeLibrary, key: &str) -> &'l Record<TypeId> {
        let Some(Type::Record(record)) = library.ty(library.named(key).unwrap()) else {
            panic!("{key} is no record");
        };
        record
    }

    /// The number of parameters `library` declares function `name` of
    /// `module` to take, and their origin.
    fn arity(library: &TypeLibrary, module: &str, name: &str) -> Option<(usize, Origin)> {
        let prototype = library.function(Some(module), name)?.prototype.as_ref()?;
        Some((prototype.value.params.len(), prototype.origin))
    }

    #[test]
    fn kernel_mode_code_imports_the_kernels_functions_not_a_processs() {
        let kernel = windows(Mode::Kernel);
        let user = windows(Mode::User);
        // The kernel's exports, the WDK's metadata's: only for kernel mode.
        let io_create_device = Some((7, Origin::Winmd));
        assert_eq!(
            arity(&kernel, "ntoskrnl.exe", "IoCreateDevice"),
            io_create_device
        );
        assert_eq!(arity(&user, "ntoskrnl.exe", "IoCreateDevice"), None);
        // The native API it declares as ntdll.dll's, as the kernel's.
        assert_eq!(
            arity(&kernel, "NTOSKRNL.exe", "RtlInitUnicodeString"),
            Some((2, Origin::Winmd))
        );
        // The process's native API (phnt's, for ntdll.dll) and its TEB:
        // user mode's only.
        assert!(arity(&user, "ntdll.dll", "NtClose").is_some());
        assert_eq!(arity(&kernel, "ntdll.dll", "NtClose"), None);
        assert!(user.named("struct _TEB").is_some());
        assert_eq!(kernel.named("struct _TEB"), None);
        // The C runtime, which the kernel exports too: both's.
        for library in [&kernel, &user] {
            assert_eq!(
                arity(library, "ntoskrnl.exe", "memcpy"),
                Some((3, Origin::Header))
            );
        }
        // A driver's entry's prototype is there.
        assert!(
            kernel
                .named("Windows.Wdk.Foundation.DRIVER_INITIALIZE")
                .is_some()
        );
    }

    /// The kernel's structures are laid out as MSVC compiles the WDK's
    /// headers: the sizes and offsets the fixture driver's PDB states
    /// (`tests/fixtures/driver-x86_64.pdb`), which the metadata does not.
    #[test]
    fn the_kernels_structures_are_laid_out_as_msvc_lays_them_out() {
        let kernel = windows(Mode::Kernel);
        for (key, size, fields) in [
            (
                "struct Windows.Wdk.Foundation.DRIVER_OBJECT",
                Some(0x150),
                &[
                    ("DeviceObject", 0x8),
                    ("DriverInit", 0x58),
                    ("DriverUnload", 0x68),
                    ("MajorFunction", 0x70),
                ][..],
            ),
            (
                "struct Windows.Wdk.Foundation.IRP",
                Some(0xd0),
                &[("IoStatus", 0x30), ("Cancel", 0x44), ("UserBuffer", 0x70)],
            ),
            (
                "struct Windows.Win32.Foundation.UNICODE_STRING",
                Some(0x10),
                &[("MaximumLength", 2), ("Buffer", 8)],
            ),
            // 0x150 in the PDB: the header aligns it to 16
            // (`DECLSPEC_ALIGN`), which the metadata does not record.
            (
                "struct Windows.Wdk.Foundation.DEVICE_OBJECT",
                None,
                &[
                    ("Flags", 0x30),
                    ("DeviceExtension", 0x40),
                    ("DeviceType", 0x48),
                ],
            ),
        ] {
            let record = record(&kernel, key);
            if size.is_some() {
                assert_eq!(record.size, size, "{key}");
            }
            for &(name, offset) in fields {
                let field = record
                    .fields
                    .iter()
                    .flatten()
                    .find(|field| field.name.as_deref() == Some(name))
                    .unwrap();
                assert_eq!(field.bit_offset, Some(offset * 8), "{key}.{name}");
            }
        }
    }

    /// Windows on ARM64 has its own databases: Win32's functions take its
    /// structures (its `CONTEXT`, not x64's), the native API (ARM64
    /// ntdll.dll's exports, with its TEB) for user mode, and the kernel's
    /// for kernel mode; the C runtime for both.
    #[test]
    fn windows_on_arm64_has_its_own_databases() {
        let library =
            |mode| TypeLibrary::with_embedded(&EMBEDDED, "aarch64", "windows", mode, &[]).unwrap();
        let (user, kernel) = (library(Mode::User), library(Mode::Kernel));
        let system_info = user.named("struct Windows.Win32.System.SystemInformation.SYSTEM_INFO");
        let prototype = &user
            .function(Some("KERNEL32.dll"), "GetSystemInfo")
            .unwrap()
            .prototype
            .as_ref()
            .unwrap()
            .value;
        assert_eq!(
            user.ty(prototype.params[0].ty),
            Some(&Type::Pointer(system_info.unwrap()))
        );
        assert_eq!(
            record(
                &user,
                "struct Windows.Win32.System.SystemInformation.SYSTEM_INFO"
            )
            .size,
            Some(48)
        );
        // ARM64's CONTEXT (winnt.h's 0x390 bytes, Pc at 0x108); x64's is
        // not there.
        let context = record(
            &user,
            "struct Windows.Win32.System.Diagnostics.Debug.CONTEXT",
        );
        assert_eq!(context.size, Some(0x390));
        let pc = context
            .fields
            .iter()
            .flatten()
            .find(|field| field.name.as_deref() == Some("Pc"))
            .unwrap();
        assert_eq!(pc.bit_offset, Some(0x108 * 8));
        assert_eq!(
            user.named("struct Windows.Win32.System.Diagnostics.Debug.ARM64_NT_CONTEXT"),
            None
        );
        assert_eq!(
            arity(&kernel, "ntoskrnl.exe", "IoCreateDevice"),
            Some((7, Origin::Winmd))
        );
        assert_eq!(arity(&user, "ntoskrnl.exe", "IoCreateDevice"), None);
        // The native API and its TEB: user mode's only.
        assert_eq!(
            arity(&user, "ntdll.dll", "NtClose"),
            Some((1, Origin::Header))
        );
        assert_eq!(arity(&kernel, "ntdll.dll", "NtClose"), None);
        assert!(user.named("struct _TEB").is_some());
        assert_eq!(kernel.named("struct _TEB"), None);
        for library in [&kernel, &user] {
            assert_eq!(
                arity(library, "VCRUNTIME140.dll", "memcpy"),
                Some((3, Origin::Header))
            );
        }
    }

    #[test]
    fn a_database_is_for_the_mode_its_name_says_it_declares() {
        for (name, user, kernel) in [
            ("windows-x86_64-kernel.jsonl", false, true),
            ("windows-x86_64-win32.jsonl", true, false),
            ("windows-x86_64-native.jsonl", true, false),
            ("windows-aarch64-native.jsonl", true, false),
            ("windows-x86_64-ucrt.jsonl", true, true),
            ("linux-x86_64-libc.jsonl", true, true),
            // Only the last part counts.
            ("kernel-x86_64-libc.jsonl", true, true),
        ] {
            assert_eq!(
                (Mode::User.has(name), Mode::Kernel.has(name)),
                (user, kernel),
                "{name}"
            );
        }
    }
}
