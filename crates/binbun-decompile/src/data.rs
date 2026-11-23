//! The image's data as lowering sees it, for globals: the objects its
//! symbols and import slots name, the memory it maps as data, and the
//! strings in its read-only data. They come through the [`Data`] trait,
//! so this crate does not depend on where they come from: the CLI's glue
//! reads them from the loaded image.

use alloc::vec::Vec;

/// An object the image names: the bytes of a data symbol with a size, or
/// an import's pointer slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Object {
    /// Its first byte.
    pub start: u64,
    /// Its size in bytes (at least 1).
    pub size: u64,
    /// Whether the program cannot change it once loaded (read-only
    /// memory, or memory the dynamic loader makes read-only after
    /// relocating it).
    pub read_only: bool,
}

impl Object {
    /// Whether it holds all of the `bytes` bytes at `address`.
    pub fn holds(&self, address: u64, bytes: u64) -> bool {
        let end = self.start.saturating_add(self.size);
        address >= self.start && address.checked_add(bytes).is_some_and(|last| last <= end)
    }
}

/// What lowering knows about the image's data.
pub trait Data {
    /// The named object holding the byte at `address`, if one does.
    fn object(&self, address: u64) -> Option<Object>;

    /// Whether all `bytes` bytes at `address` are data the image maps (not
    /// code): `Some(read_only)`, with whether the program cannot change
    /// them; `None` where any is unmapped or code.
    fn data(&self, address: u64, bytes: u64) -> Option<bool>;

    /// The length of the string at `address` (its bytes before the first
    /// NUL), if it and its NUL are in read-only data.
    fn string(&self, address: u64) -> Option<u64>;

    /// The length in 16-bit units of the wide string at `address` (UTF-16
    /// little-endian: its units before the first zero one), if it and its
    /// terminator are in read-only data and every unit is a byte's value
    /// (1 to 255, which C writes in a `u"…"` literal as the character or
    /// an octal escape). None by default.
    fn wide_string(&self, _address: u64) -> Option<u64> {
        None
    }

    /// The `bytes` bytes at `address`, if the program cannot change them
    /// and the image says what they are (a [`string`](Self::string)'s
    /// characters).
    fn constant(&self, address: u64, bytes: u64) -> Option<Vec<u8>>;

    /// Whether the image is loaded at an address of the loader's choosing
    /// (position-independent): then an immediate in its code is never one
    /// of its addresses, which are computed from the program counter or
    /// loaded.
    fn relocatable(&self) -> bool;

    /// Whether the `bytes` bytes at `slot` are the slot of an import the
    /// loader fills before the program runs and that never changes after
    /// (a call through it is a call of the import,
    /// [`Callee::Import`](binbun_ast::ir::Callee::Import)). None by
    /// default.
    fn fixed_import(&self, _slot: u64, _bytes: u16) -> bool {
        false
    }

    /// Whether `slot` is the pointer slot of an import, however the
    /// loader binds it (lazily too: its value changes once, from a stub
    /// to the import): a call through it is a call of code outside the
    /// image. None by default.
    fn import_slot(&self, _slot: u64) -> bool {
        false
    }
}

/// No data known: every constant address stays an address.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct NoData;

impl Data for NoData {
    fn object(&self, _: u64) -> Option<Object> {
        None
    }

    fn data(&self, _: u64, _: u64) -> Option<bool> {
        None
    }

    fn string(&self, _: u64) -> Option<u64> {
        None
    }

    fn constant(&self, _: u64, _: u64) -> Option<Vec<u8>> {
        None
    }

    fn relocatable(&self) -> bool {
        true
    }
}
