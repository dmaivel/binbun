//! What debug information states about a binary's functions, variables
//! and types, in one model for DWARF and PDB: the decompiler's strongest
//! evidence where a binary has it (`binbun::debug`), and the ground truth
//! `binbun eval types` scores the decompiler against on the stripped
//! binary.
//!
//! - [`model`]: what debug information states, one model for both formats:
//!   functions by entry address, their parameters, return types and local
//!   variables with their locations and the compilation units they come
//!   from, the global variables by address, and the types they reference.
//! - [`dwarf`]: the DWARF reader (`gimli`).
//! - [`dsym`]: which slice of a Mach-O image's dSYM file is its DWARF
//!   (by `LC_UUID`).
//! - [`pdb`]: the PDB reader (`pdb2`).
//! - [`locate`]: where an image's debug information is, by the documented
//!   conventions (the image's own DWARF, build ID, `.gnu_debuglink`, the
//!   debuginfod cache; the PDB a PE image's `CodeView` record names; a
//!   Mach-O image's dSYM bundle beside it), and reading it from there.

pub mod dsym;
pub mod dwarf;
pub mod locate;
pub mod model;
pub mod pdb;

pub use model::DebugModel;

/// Reads the debug information in `data` for the image `image`: a PDB
/// ([`pdb::read`], which needs the image's base, unwind information and
/// `CodeView` record), else DWARF in an ELF or Mach-O file
/// ([`dwarf::read`]; of a dSYM file, the slice with a Mach-O image's
/// UUID, [`dsym::slice`]). A Mach-O `image` is one slice, not a
/// universal file.
///
/// # Errors
///
/// If `data` is no file a reader reads, or a PDB or dSYM that is not
/// `image`'s.
pub fn read(data: &[u8], image: &[u8]) -> Result<DebugModel, String> {
    if pdb::is_pdb(data) {
        pdb::read(data, image)
    } else {
        dwarf::read(dsym::slice(data, image)?)
    }
}
