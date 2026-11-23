//! The memory a run reads and writes ([`Memory`]): the example state's
//! bytes and the run's writes over the image as the loader maps it, the
//! state's regions (their unset bytes undefined), and nothing else; and
//! the processor the run is on: its profile's values at the sites
//! (recorded by the machine code's run, taken by L2's where it lacks a
//! site's inputs, [`Choices`]).

use std::collections::BTreeMap;
use std::ops::Range;
use std::sync::Arc;

use binbun_decompile::validate::{Hashed, Oracle as _};
use binbun_loader::Image;
use binbun_semantics::bits::Bits;
use binbun_semantics::interpret::{Fault, Machine, Value};
use binbun_semantics::ir::{IntrinsicId, RegisterId, SiteId};
use serde::{Deserialize, Serialize};

use crate::profile::{Choices, Profile};

/// Where the import slots point in a run: import `k` (in
/// [`Image::imports`] order) is at this address plus 16 `k`, canonical
/// and mapped by nothing, so a call through a slot names its import.
pub const IMPORTS: u64 = 0x7fff_e000_0000;

/// What memory no region, write or image byte covers reads as.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Fill {
    /// It is not mapped: an access faults.
    #[default]
    Unmapped,
    /// Every byte at or above 0x1000 is a hash of its address, and an
    /// intrinsic's outputs a hash of its inputs ([`Hashed`]): the memory
    /// the differential check's random states run on.
    Hashed,
}

/// Why an access faulted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FaultKind {
    /// The address is not canonical (its bits 63 to 47 differ).
    NonCanonical,
    /// Nothing is mapped there.
    Unmapped,
    /// A store to a segment of the image that is not writable.
    ReadOnly,
}

/// The memory of one run.
#[derive(Clone, Debug)]
pub struct Memory<'a> {
    image: &'a Image<'a>,
    /// Each import's slot, sorted: start, size and the address it holds
    /// ([`IMPORTS`]).
    slots: Vec<(u64, u64, u64)>,
    /// Bytes the state sets and the run wrote: value and undefined bits.
    bytes: BTreeMap<u64, (u8, u8)>,
    /// The state's regions, sorted by start: mapped, their unset bytes
    /// undefined.
    mapped: Vec<Range<u64>>,
    fill: Fill,
    /// The entry registers, which L2's environment variables read.
    registers: Vec<Value>,
    /// The processor's profile, if the run is on one.
    profile: Option<Arc<Profile>>,
    /// Its values at the sites so far.
    choices: Choices,
}

/// Whether `address` is canonical for 48-bit virtual addresses.
pub const fn canonical(address: u64) -> bool {
    let top = address.cast_signed() >> 47;
    top == 0 || top == -1
}

/// The import of `image` (by position in [`Image::imports`]) whose slot
/// holds `address` in a run, if `address` is one's ([`IMPORTS`]).
pub fn import_index(image: &Image<'_>, address: u64) -> Option<usize> {
    let offset = address.checked_sub(IMPORTS)?;
    (offset.is_multiple_of(16))
        .then(|| usize::try_from(offset / 16).ok())
        .flatten()
        .filter(|&index| index < image.imports.len())
}

impl<'a> Memory<'a> {
    /// The image's memory alone, under `fill`.
    pub fn new(image: &'a Image<'a>, fill: Fill) -> Self {
        let mut slots: Vec<(u64, u64, u64)> = image
            .imports
            .iter()
            .zip(0u64..)
            .map(|(import, index)| {
                (
                    import.slot,
                    u64::from(import.size),
                    IMPORTS.wrapping_add(index * 16),
                )
            })
            .collect();
        slots.sort_unstable();
        Self {
            image,
            slots,
            bytes: BTreeMap::new(),
            mapped: Vec::new(),
            fill,
            registers: Vec::new(),
            profile: None,
            choices: Choices::default(),
        }
    }

    /// The import (by position in [`Image::imports`]) whose slot holds
    /// `address`, if `address` is one's.
    pub fn import_at(&self, address: u64) -> Option<usize> {
        import_index(self.image, address)
    }

    /// Maps `range`: its bytes not set are undefined.
    pub fn map(&mut self, range: Range<u64>) {
        let at = self.mapped.partition_point(|r| r.start < range.start);
        self.mapped.insert(at, range);
    }

    /// Sets the byte at `address` (value, undefined bits).
    pub fn set(&mut self, address: u64, byte: (u8, u8)) {
        self.bytes.insert(address, (byte.0 & !byte.1, byte.1));
    }

    /// Sets `value` at `address`, little-endian.
    pub fn set_value(&mut self, address: u64, value: &Value) {
        let pairs = value.bits.to_le_bytes().zip(value.undefined.to_le_bytes());
        for ((bits, undefined), at) in pairs.zip(address..) {
            self.set(at, (bits, undefined));
        }
    }

    /// The entry registers L2's environment variables read.
    pub fn set_registers(&mut self, registers: Vec<Value>) {
        self.registers = registers;
    }

    /// Runs on `profile`'s processor (none: the architecture's unknown
    /// values).
    pub fn set_profile(&mut self, profile: Option<Arc<Profile>>) {
        self.profile = profile;
    }

    /// The profile's values at the sites so far, taken.
    pub fn take_choices(&mut self) -> Choices {
        std::mem::take(&mut self.choices)
    }

    /// Takes the profile's values another run of the same state recorded
    /// (the machine code's), for the sites whose inputs L2 lacks.
    pub fn set_choices(&mut self, choices: Choices) {
        self.choices = choices;
    }

    /// The value of site `site` of the instruction at `address`, run with
    /// all its `inputs` (the machine code's run): the profile's, recorded;
    /// unknown without a profile.
    pub fn choose(&mut self, address: u64, site: SiteId, inputs: &[Value], width: u16) -> Value {
        let Some(profile) = &self.profile else {
            return Value::unknown(width);
        };
        let value = profile.value(site, inputs, width);
        self.choices.record(address, site, value);
        value
    }

    /// What memory not otherwise known reads as.
    pub const fn fill(&self) -> Fill {
        self.fill
    }

    /// Whether `address` is in one of the state's regions.
    fn in_region(&self, address: u64) -> bool {
        self.mapped.iter().any(|range| range.contains(&address))
    }

    /// The image's byte at `address`, if a segment maps it: an import
    /// slot's [`IMPORTS`] address, a relocated slot's known value or
    /// undefined, else the file's byte (zero past it).
    fn image_byte(&self, address: u64) -> Option<(u8, u8)> {
        let segment = self.image.segment(address)?;
        let slot = self
            .slots
            .partition_point(|&(start, _, _)| start <= address);
        if let Some(&(start, size, value)) = slot.checked_sub(1).and_then(|i| self.slots.get(i))
            && address < start.saturating_add(size)
        {
            return Some((byte_of(value, address - start), 0));
        }
        let fixups = &self.image.fixups;
        let after = fixups.partition_point(|fixup| fixup.start <= address);
        let start = after.saturating_sub(8);
        if let Some(fixup) = fixups
            .get(start..after)
            .unwrap_or_default()
            .iter()
            .rev()
            .find(|fixup| address < fixup.end())
        {
            return Some(match fixup.value {
                Some(value) => (byte_of(value, address - fixup.start), 0),
                None => (0, 0xff),
            });
        }
        let offset = usize::try_from(address - segment.start).ok()?;
        Some((segment.bytes.get(offset).copied().unwrap_or(0), 0))
    }

    /// The byte at `address` and its undefined bits, or why reading it
    /// faults.
    ///
    /// # Errors
    ///
    /// Why reading it faults.
    pub fn byte(&self, address: u64) -> Result<(u8, u8), FaultKind> {
        if !canonical(address) {
            return Err(FaultKind::NonCanonical);
        }
        if let Some(&byte) = self.bytes.get(&address) {
            return Ok(byte);
        }
        if let Some(byte) = self.image_byte(address) {
            return Ok(byte);
        }
        if self.in_region(address) {
            return Ok((0, 0xff));
        }
        match self.fill {
            Fill::Hashed => Hashed.byte(address).map(|byte| (byte, 0)),
            Fill::Unmapped => None,
        }
        .ok_or(FaultKind::Unmapped)
    }

    /// Why a store to `address` faults, if it does.
    fn writable(&self, address: u64) -> Result<(), FaultKind> {
        if let Some(segment) = self.image.segment(address)
            && !segment.permissions.write
        {
            return Err(FaultKind::ReadOnly);
        }
        self.byte(address).map(drop)
    }

    /// Why `fault` happened (as [`Self::byte`] and stores see it).
    pub fn why(&self, fault: Fault) -> FaultKind {
        let result = if fault.write {
            self.writable(fault.address)
        } else {
            self.byte(fault.address).map(drop)
        };
        result.err().unwrap_or(FaultKind::Unmapped)
    }

    /// Copies `bytes` bytes from `from` to `to`, undefined bits with them.
    ///
    /// # Errors
    ///
    /// The fault of the first byte that cannot be read or written.
    pub fn copy(&mut self, from: u64, to: u64, bytes: u64) -> Result<(), Fault> {
        for offset in 0..bytes {
            let (source, target) = (from.wrapping_add(offset), to.wrapping_add(offset));
            let byte = self.byte(source).map_err(|_| Fault {
                address: source,
                write: false,
            })?;
            self.writable(target).map_err(|_| Fault {
                address: target,
                write: true,
            })?;
            self.set(target, byte);
        }
        Ok(())
    }
}

/// Byte `index` of `value`, little-endian.
fn byte_of(value: u64, index: u64) -> u8 {
    usize::try_from(index)
        .ok()
        .and_then(|index| value.to_le_bytes().get(index).copied())
        .unwrap_or(0)
}

impl Machine for Memory<'_> {
    /// The register's value on entry (L2's environment variables).
    fn read(&mut self, register: RegisterId) -> Value {
        self.registers
            .get(usize::from(register.0))
            .copied()
            .unwrap_or_else(|| Value::unknown(1))
    }

    /// Unused: L2 keeps its variables itself.
    fn write(&mut self, _register: RegisterId, _value: Value) {}

    fn load(&mut self, address: u64, bytes: u16) -> Result<Value, Fault> {
        let mut values = Vec::with_capacity(usize::from(bytes));
        let mut undefined = Vec::with_capacity(usize::from(bytes));
        for offset in 0..u64::from(bytes) {
            let at = address.wrapping_add(offset);
            let (value, mask) = self.byte(at).map_err(|_| Fault {
                address: at,
                write: false,
            })?;
            values.push(value);
            undefined.push(mask);
        }
        let width = bytes * 8;
        Ok(Value {
            bits: Bits::from_le_bytes(width, &values),
            undefined: Bits::from_le_bytes(width, &undefined),
        })
    }

    fn store(&mut self, address: u64, value: Value) -> Result<(), Fault> {
        let bytes = u64::from(value.width() / 8);
        for offset in 0..bytes {
            let at = address.wrapping_add(offset);
            self.writable(at).map_err(|_| Fault {
                address: at,
                write: true,
            })?;
        }
        self.set_value(address, &value);
        Ok(())
    }

    fn intrinsic(
        &mut self,
        intrinsic: IntrinsicId,
        inputs: &[Value],
        outputs: &[u16],
    ) -> Vec<Value> {
        match self.fill {
            Fill::Hashed => Hashed.intrinsic(intrinsic, inputs, outputs),
            Fill::Unmapped => outputs.iter().map(|&width| Value::unknown(width)).collect(),
        }
    }

    /// L2's site values: the profile's on the inputs L2 kept, else the
    /// machine code's run's at that instruction.
    fn undefined_at(&mut self, address: u64, site: SiteId, inputs: &[Value], width: u16) -> Value {
        match &self.profile {
            Some(profile) => self.choices.choose(profile, address, site, inputs, width),
            None => Value::unknown(width),
        }
    }
}
