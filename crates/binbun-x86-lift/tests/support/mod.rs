//! Instructions from real code: a linear sweep of a file's `.text`.

use binbun_loader::Image;
use binbun_semantics::core::memory::Memory as _;
use binbun_x86::{Instruction, Mode, decode};

/// One decoded instruction: its address, bytes and decoding.
#[allow(dead_code, reason = "each test file uses a different part")]
pub struct Found {
    pub address: u64,
    pub bytes: Vec<u8>,
    pub instruction: Instruction,
}

/// The instructions of `path`'s `.text` sections (64-bit code), skipping a
/// byte wherever nothing decodes.
pub fn sweep(path: &str) -> Vec<Found> {
    let data = std::fs::read(path).unwrap_or_else(|e| panic!("{path}: {e}"));
    let image = Image::parse(&data).unwrap_or_else(|e| panic!("{path}: {e}"));
    let mut found = Vec::new();
    for section in image.sections.iter().filter(|s| s.name == ".text") {
        let mut bytes = vec![0u8; usize::try_from(section.size).unwrap()];
        let read = image.read(section.start, &mut bytes).unwrap();
        let mut at = 0;
        while at < read {
            match decode(&bytes[at..read], Mode::Bits64) {
                Ok(instruction) => {
                    let length = instruction.len();
                    found.push(Found {
                        address: section.start + at as u64,
                        bytes: bytes[at..at + length].to_vec(),
                        instruction,
                    });
                    at += length;
                }
                Err(_) => at += 1,
            }
        }
    }
    found
}

/// A fixture's path.
pub fn fixture(name: &str) -> String {
    format!("{}/../../tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"))
}
