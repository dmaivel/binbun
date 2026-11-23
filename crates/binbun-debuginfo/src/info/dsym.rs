//! A Mach-O image's DWARF, which the linker leaves in the object files and
//! `dsymutil` gathers into a dSYM bundle beside the image
//! (`<image>.dSYM/Contents/Resources/DWARF/<image>`): a Mach-O file (a
//! universal one for a universal image) whose `__DWARF` segment holds the
//! sections, matched to the image by `LC_UUID`.

use object::read::macho::{FatArch, MachOFatFile32, MachOFatFile64};
use object::{FileKind, Object};

/// The bytes of debug file `data` that describe the Mach-O image `image`
/// (one slice's, not a universal file): of a universal dSYM file, the
/// slice with the image's UUID; any other file whole.
///
/// # Errors
///
/// `data` is universal and no slice of it has the image's UUID, or it is
/// a Mach-O file whose UUID is another image's.
pub fn slice<'data>(data: &'data [u8], image: &[u8]) -> Result<&'data [u8], String> {
    let Some(uuid) = uuid(image) else {
        return Ok(data);
    };
    let slices = match FileKind::parse(data) {
        Ok(FileKind::MachOFat32) => arches(data, MachOFatFile32::parse(data).map(|f| f.arches())),
        Ok(FileKind::MachOFat64) => arches(data, MachOFatFile64::parse(data).map(|f| f.arches())),
        Ok(FileKind::MachO64 | FileKind::MachO32) => {
            return match self::uuid(data) {
                Some(own) if own != uuid => Err(mismatch(uuid)),
                Some(_) | None => Ok(data),
            };
        }
        Ok(_) | Err(_) => return Ok(data),
    };
    slices
        .into_iter()
        .find(|slice| self::uuid(slice) == Some(uuid))
        .ok_or_else(|| mismatch(uuid))
}

/// The slices of universal file `data`, whose header `arches` reads.
fn arches<'data, A: FatArch>(
    data: &'data [u8],
    arches: object::Result<&'data [A]>,
) -> Vec<&'data [u8]> {
    arches
        .unwrap_or_default()
        .iter()
        .filter_map(|arch| arch.data(data).ok())
        .collect()
}

/// The UUID (`LC_UUID`) of the Mach-O file `data`, if it is one with one.
fn uuid(data: &[u8]) -> Option<[u8; 16]> {
    object::File::parse(data).ok()?.mach_uuid().ok().flatten()
}

/// Why a debug file is not the image's of UUID `uuid`.
fn mismatch(uuid: [u8; 16]) -> String {
    let hex = u128::from_be_bytes(uuid);
    format!("no debug information for the image's UUID {hex:032X}")
}
