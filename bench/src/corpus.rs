//! The code being decoded: executable sections of x86-64 or AArch64 ELF and
//! PE files.

use std::path::{Path, PathBuf};

use object::{Architecture, Object, ObjectSection, SectionKind};

use crate::Arch;

/// One executable section.
#[derive(Debug)]
pub struct Section {
    pub address: u64,
    pub bytes: Vec<u8>,
}

/// Every input file and the code taken from it.
#[derive(Debug)]
pub struct Corpus {
    /// The architecture every file is for.
    pub arch: Arch,
    pub files: Vec<(PathBuf, usize)>,
    pub sections: Vec<Section>,
}

impl Corpus {
    /// Loads `paths`, which must all be for the same architecture.
    pub fn load(paths: &[PathBuf]) -> Result<Self, Box<dyn std::error::Error>> {
        let mut arch = None;
        let mut files = Vec::new();
        let mut sections = Vec::new();
        for path in paths {
            let (file_arch, code) =
                Self::load_file(path).map_err(|error| format!("{}: {error}", path.display()))?;
            match arch {
                None => arch = Some(file_arch),
                Some(arch) if arch != file_arch => {
                    return Err(format!(
                        "{}: {} code, but the files before it are {}",
                        path.display(),
                        file_arch.name(),
                        arch.name()
                    )
                    .into());
                }
                Some(_) => {}
            }
            files.push((path.clone(), code.iter().map(|s| s.bytes.len()).sum()));
            sections.extend(code);
        }
        let arch = arch.ok_or("no input files")?;
        let corpus = Self {
            arch,
            files,
            sections,
        };
        if corpus.bytes() == 0 {
            return Err(format!("the corpus has no {} code", arch.name()).into());
        }
        Ok(corpus)
    }

    fn load_file(path: &Path) -> Result<(Arch, Vec<Section>), Box<dyn std::error::Error>> {
        let data = std::fs::read(path)?;
        let file = object::File::parse(&*data)?;
        let arch = match file.architecture() {
            Architecture::X86_64 => Arch::X86_64,
            Architecture::Aarch64 => Arch::Aarch64,
            other => return Err(format!("neither x86-64 nor AArch64 but {other:?}").into()),
        };
        let mut sections = Vec::new();
        for section in file.sections() {
            if section.kind() == SectionKind::Text {
                let mut bytes = section.data()?;
                if arch == Arch::Aarch64 {
                    // Whole 4-byte words only.
                    bytes = &bytes[..bytes.len() & !3];
                }
                sections.push(Section {
                    address: section.address(),
                    bytes: bytes.to_vec(),
                });
            }
        }
        Ok((arch, sections))
    }

    pub fn bytes(&self) -> usize {
        self.sections
            .iter()
            .map(|section| section.bytes.len())
            .sum()
    }
}
