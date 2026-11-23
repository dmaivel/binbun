//! Which debug information an image needs, as symbol servers file it
//! ([`Identity`]), and whether a file is it ([`Identity::verify`]).
//!
//! - **PE**: the PDB the image's `CodeView` (`RSDS`) debug record names,
//!   with the record's GUID and age. A symbol store files it under
//!   `<name>/<GUID><age>/<name>`: the GUID's fields in upper-case
//!   hexadecimal without dashes (`Data1`, `Data2`, `Data3` as numbers,
//!   `Data4` byte by byte), the age in upper-case hexadecimal without
//!   padding. A server may also hold it compressed, as a cabinet named
//!   with the name's last character replaced by `_` (`foo.pd_`).
//! - **ELF**: the separate debug file of the image's build ID
//!   (`NT_GNU_BUILD_ID`), filed as debuginfod serves it,
//!   `buildid/<lower-case hexadecimal>/debuginfo`.
//! - **Mach-O**: none (no public symbol server).

use std::fmt::{self, Write as _};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::str::FromStr;

use object::{BinaryFormat, Object};

/// A PDB's GUID, as the `CodeView` record stores it (little-endian
/// `Data1`, `Data2`, `Data3`, then the eight bytes of `Data4`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Guid(pub [u8; 16]);

impl fmt::Display for Guid {
    /// Upper-case hexadecimal without dashes, as a symbol store's
    /// directory names it: `Data1`, `Data2`, `Data3` as numbers, then
    /// `Data4`'s bytes.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [a0, a1, a2, a3, b0, b1, c0, c1, rest @ ..] = self.0;
        let data1 = u32::from_le_bytes([a0, a1, a2, a3]);
        let data2 = u16::from_le_bytes([b0, b1]);
        let data3 = u16::from_le_bytes([c0, c1]);
        write!(f, "{data1:08X}{data2:04X}{data3:04X}")?;
        rest.iter().try_for_each(|byte| write!(f, "{byte:02X}"))
    }
}

impl FromStr for Guid {
    type Err = String;

    /// A GUID as written: `{0123ABCD-…}` or 32 hexadecimal digits, in
    /// either case, with or without braces and dashes.
    fn from_str(text: &str) -> Result<Self, String> {
        let digits: Vec<u8> = text
            .trim()
            .trim_start_matches('{')
            .trim_end_matches('}')
            .bytes()
            .filter(|&byte| byte != b'-')
            .map(|byte| {
                char::from(byte)
                    .to_digit(16)
                    .and_then(|digit| u8::try_from(digit).ok())
            })
            .collect::<Option<_>>()
            .ok_or_else(|| format!("{text:?} is no GUID"))?;
        let bytes: Vec<u8> = digits
            .as_chunks::<2>()
            .0
            .iter()
            .map(|[high, low]| high << 4 | low)
            .collect();
        let Ok(fields) = <[u8; 16]>::try_from(bytes.as_slice()) else {
            return Err(format!("{text:?} is no GUID"));
        };
        if digits.len() != 32 {
            return Err(format!("{text:?} is no GUID"));
        }
        // Written as numbers: `Data1`, `Data2`, `Data3` are stored
        // little-endian.
        let [a0, a1, a2, a3, b0, b1, c0, c1, rest @ ..] = fields;
        let mut stored = [0; 16];
        let (head, tail) = stored.split_at_mut(8);
        head.copy_from_slice(&[a3, a2, a1, a0, b1, b0, c1, c0]);
        tail.copy_from_slice(&rest);
        Ok(Self(stored))
    }
}

/// The PDB a PE image's `CodeView` record names.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Pdb {
    /// Its file name (the record's path's last component, as written).
    pub name: String,
    /// Its GUID.
    pub guid: Guid,
    /// Its age.
    pub age: u32,
}

/// The debug information an image needs, as symbol servers file it.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Identity {
    /// A PE image's PDB.
    Pdb(Pdb),
    /// An ELF image's separate debug file, by build ID.
    BuildId(Vec<u8>),
}

/// Why a file is not an image's debug information.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Mismatch {
    /// It cannot be read, or is no file of the kind (a PDB, an ELF file).
    Unreadable(String),
    /// A PDB of another GUID or age.
    Pdb {
        /// Its GUID.
        guid: Guid,
        /// Its age (`None`: it states none).
        age: Option<u32>,
    },
    /// An ELF file of another build ID (`None`: it has none).
    BuildId(Option<Vec<u8>>),
}

impl fmt::Display for Mismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unreadable(message) => f.write_str(message),
            Self::Pdb {
                guid,
                age: Some(age),
            } => {
                write!(f, "mismatched GUID or age ({guid}, age {age})")
            }
            Self::Pdb { guid, age: None } => write!(f, "mismatched GUID or age ({guid})"),
            Self::BuildId(Some(id)) => write!(f, "mismatched build ID ({})", hex(id)),
            Self::BuildId(None) => f.write_str("no build ID"),
        }
    }
}

/// The magic a PDB (MSF 7.0) starts with.
const MSF: &[u8] = b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\0\0\0";

impl Identity {
    /// The debug information the image `data` needs: its `CodeView`
    /// record's PDB (PE), its build ID (ELF); `None` for other formats
    /// and for images that state neither.
    pub fn of(data: &[u8]) -> Option<Self> {
        let file = object::File::parse(data).ok()?;
        let format = file.format();
        if format == BinaryFormat::Pe {
            let codeview = file.pdb_info().ok().flatten()?;
            let name = file_name(codeview.path())?;
            Some(Self::Pdb(Pdb {
                name,
                guid: Guid(codeview.guid()),
                age: codeview.age(),
            }))
        } else if format == BinaryFormat::Elf {
            let id = file.build_id().ok().flatten()?;
            (!id.is_empty()).then(|| Self::BuildId(id.to_vec()))
        } else {
            None
        }
    }

    /// The build ID given in hexadecimal, in either case.
    ///
    /// # Errors
    ///
    /// If `text` is empty or not an even number of hexadecimal digits.
    pub fn build_id(text: &str) -> Result<Self, String> {
        let digits: Option<Vec<u8>> = text
            .bytes()
            .map(|byte| {
                char::from(byte)
                    .to_digit(16)
                    .and_then(|digit| u8::try_from(digit).ok())
            })
            .collect();
        match digits {
            Some(digits) if !digits.is_empty() && digits.len() % 2 == 0 => Ok(Self::BuildId(
                digits
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|[high, low]| high << 4 | low)
                    .collect(),
            )),
            Some(_) | None => Err(format!("{text:?} is no build ID")),
        }
    }

    /// The file's name as a store files it: the PDB's, or `debuginfo`.
    pub fn file_name(&self) -> &str {
        match self {
            Self::Pdb(pdb) => &pdb.name,
            Self::BuildId(_) => "debuginfo",
        }
    }

    /// The store's key: the GUID then the age (`3A1B…F1`), or the build ID
    /// in lower-case hexadecimal.
    pub fn key(&self) -> String {
        match self {
            Self::Pdb(pdb) => format!("{}{:X}", pdb.guid, pdb.age),
            Self::BuildId(id) => hex(id),
        }
    }

    /// Where a symbol store (and a server, as a URL path) files it:
    /// `<name>/<key>/<name>`, or `buildid/<key>/debuginfo`.
    pub fn store_path(&self) -> PathBuf {
        match self {
            Self::Pdb(pdb) => Path::new(&pdb.name).join(self.key()).join(&pdb.name),
            Self::BuildId(_) => Path::new("buildid").join(self.key()).join("debuginfo"),
        }
    }

    /// The URLs it is fetched from on the server at `server` (a URL
    /// without the trailing `/`), in order, each with whether it is the
    /// compressed form (a cabinet): a PDB's plain file, then its `_` form;
    /// debuginfod's `buildid/<key>/debuginfo`.
    pub fn urls(&self, server: &str) -> Vec<(String, bool)> {
        let server = server.trim_end_matches('/');
        match self {
            Self::Pdb(pdb) => {
                let key = self.key();
                let name = &pdb.name;
                let mut out = vec![(format!("{server}/{name}/{key}/{name}"), false)];
                if let Some(compressed) = compressed_name(name) {
                    out.push((format!("{server}/{name}/{key}/{compressed}"), true));
                }
                out
            }
            Self::BuildId(_) => vec![(format!("{server}/buildid/{}/debuginfo", self.key()), false)],
        }
    }

    /// Checks the file at `path` is this debug information: a PDB of the
    /// GUID and age (the DBI stream's age, as [`crate::info`] checks it),
    /// an ELF file of the build ID.
    ///
    /// # Errors
    ///
    /// Why it is not ([`Mismatch`]).
    pub fn verify(&self, path: &Path) -> Result<(), Mismatch> {
        let unreadable = |error: &dyn fmt::Display| Mismatch::Unreadable(error.to_string());
        match self {
            Self::Pdb(pdb) => {
                let mut file = File::open(path).map_err(|error| unreadable(&error))?;
                let mut magic = [0; MSF.len()];
                file.read_exact(&mut magic)
                    .map_err(|_| Mismatch::Unreadable("not a PDB".to_owned()))?;
                if magic != MSF {
                    return Err(Mismatch::Unreadable("not a PDB".to_owned()));
                }
                file.seek(SeekFrom::Start(0))
                    .map_err(|error| unreadable(&error))?;
                let mut opened = pdb2::PDB::open(file).map_err(|error| unreadable(&error))?;
                let guid = Guid(
                    opened
                        .pdb_information()
                        .map_err(|error| unreadable(&error))?
                        .guid
                        .to_bytes_le(),
                );
                let age = opened
                    .debug_information()
                    .map_err(|error| unreadable(&error))?
                    .age();
                if guid == pdb.guid && age == Some(pdb.age) {
                    Ok(())
                } else {
                    Err(Mismatch::Pdb { guid, age })
                }
            }
            Self::BuildId(id) => {
                let data = std::fs::read(path).map_err(|error| unreadable(&error))?;
                let file = object::File::parse(data.as_slice())
                    .map_err(|_| Mismatch::Unreadable("not an ELF file".to_owned()))?;
                if file.format() != BinaryFormat::Elf {
                    return Err(Mismatch::Unreadable("not an ELF file".to_owned()));
                }
                match file.build_id().ok().flatten() {
                    Some(own) if own == id.as_slice() => Ok(()),
                    own => Err(Mismatch::BuildId(own.map(<[u8]>::to_vec))),
                }
            }
        }
    }
}

impl fmt::Display for Identity {
    /// `name GUIDage`, or `build ID hex`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pdb(pdb) => write!(f, "{} {}", pdb.name, self.key()),
            Self::BuildId(_) => write!(f, "build ID {}", self.key()),
        }
    }
}

/// The compressed form's name: `name` with its last character replaced by
/// `_` (`foo.pdb` → `foo.pd_`).
fn compressed_name(name: &str) -> Option<String> {
    let (at, _) = name.char_indices().next_back()?;
    let stem = name.get(..at)?;
    (!stem.is_empty()).then(|| format!("{stem}_"))
}

/// The last component of a path as a `CodeView` record states it (`/` or
/// `\` separated), if any.
fn file_name(path: &[u8]) -> Option<String> {
    let name = path.rsplit(|&byte| byte == b'/' || byte == b'\\').next()?;
    let name = std::str::from_utf8(name).ok()?;
    (!name.is_empty() && name != "." && name != "..").then(|| name.to_owned())
}

/// `bytes` in lower-case hexadecimal.
pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut text, byte| {
        let _ = write!(text, "{byte:02x}");
        text
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `{12345678-9ABC-DEF0-1122-334455667788}` as a `CodeView` record
    /// stores it.
    const STORED: [u8; 16] = [
        0x78, 0x56, 0x34, 0x12, 0xbc, 0x9a, 0xf0, 0xde, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88,
    ];

    fn pdb(age: u32) -> Identity {
        Identity::Pdb(Pdb {
            name: "ntdll.pdb".to_owned(),
            guid: Guid(STORED),
            age,
        })
    }

    #[test]
    fn a_guid_prints_its_fields_as_numbers_then_data4_bytes() {
        assert_eq!(Guid(STORED).to_string(), "123456789ABCDEF01122334455667788");
    }

    #[test]
    fn a_guid_reads_in_either_case_with_or_without_dashes_and_braces() {
        for text in [
            "{12345678-9abc-def0-1122-334455667788}",
            "12345678-9ABC-DEF0-1122-334455667788",
            "123456789abcdef01122334455667788",
        ] {
            assert_eq!(text.parse::<Guid>(), Ok(Guid(STORED)), "{text}");
        }
        for bad in [
            "",
            "1234",
            "123456789abcdef01122334455667788ff",
            "g23456789abcdef01122334455667788",
        ] {
            assert!(bad.parse::<Guid>().is_err(), "{bad}");
        }
    }

    #[test]
    fn the_key_is_the_guid_then_the_age_in_upper_case_hex_unpadded() {
        assert_eq!(pdb(1).key(), "123456789ABCDEF011223344556677881");
        assert_eq!(pdb(10).key(), "123456789ABCDEF01122334455667788A");
        assert_eq!(pdb(0x2f).key(), "123456789ABCDEF011223344556677882F");
    }

    #[test]
    fn urls_and_store_paths_follow_symstore_and_debuginfod() {
        let identity = pdb(0x1b);
        assert_eq!(
            identity.urls("https://msdl.microsoft.com/download/symbols/"),
            vec![
                (
                    "https://msdl.microsoft.com/download/symbols/ntdll.pdb/123456789ABCDEF01122334455667788\
                     1B/ntdll.pdb"
                        .to_owned(),
                    false
                ),
                (
                    "https://msdl.microsoft.com/download/symbols/ntdll.pdb/123456789ABCDEF01122334455667788\
                     1B/ntdll.pd_"
                        .to_owned(),
                    true
                ),
            ]
        );
        assert_eq!(
            identity.store_path(),
            Path::new("ntdll.pdb/123456789ABCDEF011223344556677881B/ntdll.pdb")
        );
        let elf = Identity::build_id("57C5971FF5BB2919cbb8f5019827167cddaa69f6").unwrap();
        assert_eq!(elf.key(), "57c5971ff5bb2919cbb8f5019827167cddaa69f6");
        assert_eq!(
            elf.urls("https://debuginfod.example"),
            vec![(
                "https://debuginfod.example/buildid/57c5971ff5bb2919cbb8f5019827167cddaa69f6/debuginfo"
                    .to_owned(),
                false
            )]
        );
        assert_eq!(
            elf.store_path(),
            Path::new("buildid/57c5971ff5bb2919cbb8f5019827167cddaa69f6/debuginfo")
        );
        assert!(Identity::build_id("abc").is_err());
        assert!(Identity::build_id("").is_err());
    }

    #[test]
    fn the_compressed_name_replaces_the_last_character() {
        assert_eq!(compressed_name("ntdll.pdb").as_deref(), Some("ntdll.pd_"));
        assert_eq!(compressed_name("x").as_deref(), None);
    }

    #[test]
    fn a_codeview_path_gives_its_last_component() {
        assert_eq!(
            file_name(br"D:\a\_work\1\s\PCbuild\amd64\python313.pdb").as_deref(),
            Some("python313.pdb")
        );
        assert_eq!(file_name(b"/build/x.pdb").as_deref(), Some("x.pdb"));
        assert_eq!(file_name(b"dir\\").as_deref(), None);
    }
}
