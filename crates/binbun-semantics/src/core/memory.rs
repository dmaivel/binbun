//! Address spaces that analyses read code and data from: a loaded file, a
//! raw dump, or a live target whose reads can fail.

use core::fmt;

/// Access permissions of memory.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Permissions {
    /// Readable.
    pub read: bool,
    /// Writable.
    pub write: bool,
    /// Executable.
    pub execute: bool,
}

impl Permissions {
    /// Read, write and execute.
    pub const ALL: Self = Self {
        read: true,
        write: true,
        execute: true,
    };
}

/// A range of mapped addresses with the same permissions.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Region {
    /// The first address.
    pub start: u64,
    /// The address after the last (`start + size`, saturated at the top of
    /// the address space).
    pub end: u64,
    /// Its permissions.
    pub permissions: Permissions,
}

impl Region {
    /// Whether `address` is in the region.
    pub const fn contains(&self, address: u64) -> bool {
        self.start <= address && address < self.end
    }
}

/// A read that failed for a reason other than unmapped memory (a live
/// target that timed out or refused).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ReadError;

impl fmt::Display for ReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("memory could not be read")
    }
}

impl core::error::Error for ReadError {}

/// An address space.
pub trait Memory {
    /// Reads into `buffer` from `address`, stopping at the first unmapped
    /// address: returns how many bytes were read (0 if `address` is not
    /// mapped).
    ///
    /// # Errors
    ///
    /// When the memory exists but cannot be read now.
    fn read(&self, address: u64, buffer: &mut [u8]) -> Result<usize, ReadError>;

    /// The region `address` is in, if it is mapped.
    fn region(&self, address: u64) -> Option<Region>;
}

impl<M: Memory + ?Sized> Memory for &M {
    fn read(&self, address: u64, buffer: &mut [u8]) -> Result<usize, ReadError> {
        (**self).read(address, buffer)
    }

    fn region(&self, address: u64) -> Option<Region> {
        (**self).region(address)
    }
}

/// Bytes mapped at one address with one set of permissions: a raw dump, a
/// shellcode blob, a test fixture.
#[derive(Clone, Copy, Debug)]
pub struct Flat<'a> {
    /// The address of the first byte.
    pub base: u64,
    /// The bytes.
    pub bytes: &'a [u8],
    /// Their permissions.
    pub permissions: Permissions,
}

impl<'a> Flat<'a> {
    /// `bytes` at `base`, readable, writable and executable.
    pub const fn new(base: u64, bytes: &'a [u8]) -> Self {
        Self {
            base,
            bytes,
            permissions: Permissions::ALL,
        }
    }
}

impl Memory for Flat<'_> {
    fn read(&self, address: u64, buffer: &mut [u8]) -> Result<usize, ReadError> {
        let Some(rest) = address
            .checked_sub(self.base)
            .and_then(|offset| usize::try_from(offset).ok())
            .and_then(|offset| self.bytes.get(offset..))
        else {
            return Ok(0);
        };
        let count = rest.len().min(buffer.len());
        if let (Some(dest), Some(source)) = (buffer.get_mut(..count), rest.get(..count)) {
            dest.copy_from_slice(source);
        }
        Ok(count)
    }

    fn region(&self, address: u64) -> Option<Region> {
        let region = Region {
            start: self.base,
            end: self.base.saturating_add(self.bytes.len() as u64),
            permissions: self.permissions,
        };
        region.contains(address).then_some(region)
    }
}

#[cfg(test)]
mod tests {
    use super::{Flat, Memory};

    #[test]
    fn flat_reads_stop_at_the_end_and_miss_outside() {
        let memory = Flat::new(0x1000, &[1, 2, 3, 4]);
        let mut buffer = [0u8; 8];
        assert_eq!(memory.read(0x1002, &mut buffer), Ok(2));
        assert_eq!(buffer[..2], [3, 4]);
        assert_eq!(memory.read(0x1004, &mut buffer), Ok(0));
        assert_eq!(memory.read(0xfff, &mut buffer), Ok(0));
        assert_eq!(
            memory.region(0x1003).map(|r| (r.start, r.end)),
            Some((0x1000, 0x1004))
        );
        assert!(memory.region(0x1004).is_none());
    }
}
