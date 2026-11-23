//! The memory of an image that the program cannot change once it is
//! loaded ([`ImageMemory`]), which constant propagation, recovery's
//! pointer slots and the image's data read; and the differential check's
//! memory of the image ([`ImageOracle`]).

use std::ops::Range;

use binbun_decompile::validate::{Hashed, Oracle};
use binbun_loader::{Fixup, Image, Relocation};
use binbun_semantics::Bits;
use binbun_semantics::bits::MAX_WIDTH;
use binbun_semantics::core::Memory as _;
use binbun_semantics::interpret::Value;
use binbun_semantics::ir::IntrinsicId;
use binbun_ssa::constant::ReadOnly;

/// The memory of an image that the program cannot change once it is
/// loaded ([`ReadOnly`]): bytes of non-writable segments and of RELRO
/// ranges ([`Image::relro`]), as the loader maps them (from the file, or
/// zeros past it), outside what the dynamic loader writes
/// ([`Image::fixups`]). A read of exactly one written slot whose value is
/// known at the image's addresses ([`Fixup::value`]: a relative
/// relocation's target) gives that value; any other read overlapping a
/// written range is unknown.
///
/// A PLT slot of a function the image defines (`JUMP_SLOT`,
/// [`Relocation::JumpSlot`]) reads as that function's address wherever it
/// lies: the slot is the dynamic loader's, which binds it when the image
/// is loaded or at the first call through it, and until then it holds the
/// address of its stub's own code that asks for the binding, so a jump
/// through it reaches the function either way (no compiler's code reads
/// or writes one otherwise).
///
/// The slots of fixed imports ([`binbun_loader::Import::fixed`]) are its
/// [`fixed addresses`](ReadOnly::fixed_address).
#[derive(Clone, Debug)]
pub struct ImageMemory<'a> {
    image: &'a Image<'a>,
    /// For each of the image's fixups (sorted by start), the furthest end
    /// of it and those before it: the fixups overlapping a range start
    /// from the first whose reach passes the range's start.
    reach: Vec<u64>,
    /// The fixed imports' slots, sorted: start and size.
    fixed: Vec<(u64, u8)>,
    /// The PLT slots of the functions the image defines, sorted.
    bound: Vec<u64>,
}

impl<'a> ImageMemory<'a> {
    /// The read-only memory of `image`.
    pub fn new(image: &'a Image<'a>) -> Self {
        let reach = image
            .fixups
            .iter()
            .scan(0, |reach: &mut u64, fixup| {
                *reach = (*reach).max(fixup.end());
                Some(*reach)
            })
            .collect();
        let mut fixed: Vec<(u64, u8)> = image
            .imports
            .iter()
            .filter(|import| import.fixed)
            .map(|import| (import.slot, import.size))
            .collect();
        fixed.sort_unstable();
        let mut bound: Vec<u64> = image
            .pointers
            .iter()
            .filter(|pointer| pointer.relocation == Relocation::JumpSlot)
            .map(|pointer| pointer.at)
            .collect();
        bound.sort_unstable();
        Self {
            image,
            reach,
            fixed,
            bound,
        }
    }

    /// Whether the slot of a fixed import is exactly `bytes` bytes at
    /// `address`.
    pub(crate) fn fixed_slot(&self, address: u64, bytes: u16) -> bool {
        self.fixed
            .binary_search_by_key(&address, |&(slot, _)| slot)
            .ok()
            .and_then(|index| self.fixed.get(index))
            .is_some_and(|&(_, size)| u16::from(size) == bytes)
    }

    /// Whether the program cannot change any of `start..end` once loaded:
    /// all of it is mapped, in non-writable segments or RELRO ranges.
    pub(crate) fn unchanging(&self, start: u64, end: u64) -> bool {
        let mut at = start;
        while at < end {
            let Some(segment) = self.image.segment(at) else {
                return false;
            };
            let mut next = segment.end().min(end);
            if segment.permissions.write {
                let Some(relro) = self.relro(at) else {
                    return false;
                };
                next = next.min(relro.end);
            }
            at = next;
        }
        true
    }

    /// The RELRO range `address` is in.
    fn relro(&self, address: u64) -> Option<&'a Range<u64>> {
        self.image
            .relro
            .iter()
            .find(|range| range.contains(&address))
    }

    /// Whether the dynamic loader writes any of `start..end`
    /// ([`Image::fixups`]).
    pub(crate) fn written(&self, start: u64, end: u64) -> bool {
        self.overlapping(start, end).next().is_some()
    }

    /// The fixups overlapping `start..end`.
    fn overlapping(&self, start: u64, end: u64) -> impl Iterator<Item = &'a Fixup> {
        let fixups = &self.image.fixups;
        let first = self.reach.partition_point(|&reach| reach <= start);
        let last = fixups.partition_point(|fixup| fixup.start < end);
        fixups
            .get(first..last)
            .unwrap_or_default()
            .iter()
            .filter(move |fixup| fixup.end() > start)
    }
}

impl ReadOnly for ImageMemory<'_> {
    fn read(&self, address: u64, bytes: u16) -> Option<Bits> {
        let width = bytes.checked_mul(8).filter(|&width| width <= MAX_WIDTH)?;
        let size = u64::from(bytes);
        let end = address.checked_add(size)?;
        let bound = self.bound.binary_search(&address).is_ok();
        if bytes == 0 || !(bound || self.unchanging(address, end)) {
            return None;
        }
        let mut overlapping = self.overlapping(address, end);
        let fixup = overlapping.next();
        if overlapping.next().is_some() {
            return None;
        }
        if let Some(fixup) = fixup {
            let whole = fixup.start == address && fixup.size == size;
            return fixup
                .value
                .filter(|_| whole)
                .map(|value| Bits::from_u64(width, value));
        }
        let mut buffer = [0u8; MAX_WIDTH as usize / 8];
        let buffer = buffer.get_mut(..usize::from(bytes))?;
        let read = self.image.read(address, buffer).ok()?;
        (read == buffer.len()).then(|| Bits::from_le_bytes(width, buffer))
    }

    fn fixed_address(&self, address: u64, bytes: u16) -> bool {
        self.fixed_slot(address, bytes)
    }
}

/// The memory both runs of the differential check read
/// ([`binbun_decompile::validate::differential`]): the image's bytes
/// where they cannot change ([`ImageMemory`], which lowering's constants
/// come from; a byte of a relocated 8-byte slot from the slot's value),
/// else [`Hashed`]'s; intrinsics answer as [`Hashed`]'s.
#[derive(Clone, Debug)]
pub struct ImageOracle<'a>(pub ImageMemory<'a>);

impl<'a> ImageOracle<'a> {
    /// The oracle of `image`.
    pub fn new(image: &'a Image<'a>) -> Self {
        Self(ImageMemory::new(image))
    }
}

impl Oracle for ImageOracle<'_> {
    fn byte(&self, address: u64) -> Option<u8> {
        if let Some(bits) = self.0.read(address, 1) {
            return u8::try_from(bits.low_u64()).ok();
        }
        for back in 0..8u16 {
            if let Some(start) = address.checked_sub(u64::from(back))
                && let Some(bits) = self.0.read(start, 8)
            {
                return u8::try_from(bits.extract(back * 8, 8).low_u64()).ok();
            }
        }
        Hashed.byte(address)
    }

    fn intrinsic(&self, intrinsic: IntrinsicId, inputs: &[Value], outputs: &[u16]) -> Vec<Value> {
        Hashed.intrinsic(intrinsic, inputs, outputs)
    }
}
