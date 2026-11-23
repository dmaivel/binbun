//! What an instruction reads and writes: per-operand access, the memory it
//! accesses, the registers it uses without naming them and the condition
//! flags.
//!
//! Everything here is computed from the word on demand by generated code
//! (`xtask/src/aarch64/access`): the access of each operand from Arm's
//! names for the operands (`<Xd>` is written, `<Xn>` read, `<Zdn>` both,
//! `<Xt>` by the memory access) and hand-written rules for what the names do
//! not say (accumulating and inserting forms, merging predication,
//! compare-and-swap, …).

use core::ops::BitOr;

use crate::Instruction;
use crate::generated::{access as generated, syntax};
use crate::operand::{Condition, MAX_OPERANDS, Register};

/// How an instruction accesses an operand.
///
/// Registers, register lists and ZA operands are read, written or both. A
/// [`Memory`](crate::operand::Memory) operand's access is the memory
/// access: [`Read`](Self::Read) for loads and prefetches,
/// [`Write`](Self::Write) for stores, [`ReadWrite`](Self::ReadWrite) for
/// atomic read-modify-writes; its base and offset registers are always read
/// and the base is written back as its `writeback` says (not repeated here).
/// Operands that are values (immediates, shifts, extends, labels, conditions,
/// names) are [`Read`](Self::Read); a system register is written by `MSR` and
/// `MSRR`, a PSTATE field by `MSR (immediate)`. The zero register as a
/// destination is still [`Write`](Self::Write).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Access {
    /// Read only.
    Read,
    /// Written only: no part of the old value survives.
    Write,
    /// Read and written, or written in part (an inserted element, a merging
    /// predicated destination, an accumulator).
    ReadWrite,
}

impl Access {
    /// Whether the operand is read.
    pub const fn reads(self) -> bool {
        matches!(self, Self::Read | Self::ReadWrite)
    }

    /// Whether the operand is written.
    pub const fn writes(self) -> bool {
        matches!(self, Self::Write | Self::ReadWrite)
    }
}

/// The access of each operand, in the order of
/// [`Instruction::operands`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Accesses {
    accesses: [Access; MAX_OPERANDS],
    len: u8,
}

impl Default for Accesses {
    fn default() -> Self {
        Self::new()
    }
}

impl Accesses {
    /// No accesses.
    pub const fn new() -> Self {
        Self {
            accesses: [Access::Read; MAX_OPERANDS],
            len: 0,
        }
    }

    /// Appends `access`; the generated code pushes one per operand, and
    /// operands never exceed [`MAX_OPERANDS`].
    pub fn push(&mut self, access: Access) {
        if let Some(slot) = self.accesses.get_mut(usize::from(self.len)) {
            *slot = access;
            self.len += 1;
        }
    }

    /// The accesses as a slice.
    pub fn as_slice(&self) -> &[Access] {
        self.accesses
            .get(..usize::from(self.len))
            .unwrap_or_default()
    }

    /// Number of accesses (the number of operands).
    pub const fn len(&self) -> usize {
        self.len as usize
    }

    /// Whether there are none.
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The accesses.
    pub fn iter(&self) -> core::slice::Iter<'_, Access> {
        self.as_slice().iter()
    }
}

impl<'a> IntoIterator for &'a Accesses {
    type Item = &'a Access;
    type IntoIter = core::slice::Iter<'a, Access>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// What kind of memory access an instruction makes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MemoryKind {
    /// A load (including literal, structure, SVE, SME and acquiring loads,
    /// `LDRAA`, `LD64B`).
    Load,
    /// A store (including releasing stores, `STZG` and `STGP`, which also
    /// store allocation tags, `ST64BV`, and the memory set instructions).
    Store,
    /// An atomic read-modify-write: `LDADD` and the other LSE atomics (also
    /// as `STADD`…), `SWP`, `CAS`, `CASP`, the floating-point atomics, the
    /// 128-bit atomics and the read-check-write instructions.
    Atomic,
    /// A load exclusive (`LDXR`, `LDAXP`, …), which marks the address for a
    /// later store exclusive.
    LoadExclusive,
    /// A store exclusive (`STXR`, `STLXP`, …), which stores only if the
    /// exclusive monitor still holds and writes its status to a register.
    StoreExclusive,
    /// A prefetch hint (`PRFM`, `PRFUM`, `RPRFM`, SVE `PRF*`): no data is
    /// accessed.
    Prefetch,
    /// A memory copy (`CPY*`): the first memory operand is written, the
    /// second read.
    Copy,
    /// A load of allocation tags (`LDG`, `LDGM`).
    LoadTag,
    /// A store of allocation tags only (`STG`, `ST2G`, `STGM`).
    StoreTag,
}

/// An instruction's memory access.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct MemoryAccess {
    /// The kind.
    pub kind: MemoryKind,
    /// Bytes accessed in total for a fixed-size access (both registers of a
    /// pair, every register of a structure, the 16-byte granule of a tag
    /// access); 0 when it depends on the vector length (SVE, SME), the
    /// implementation (`LDGM`, `STGM`, `STZGM`) or a register (memory copy
    /// and set), and for prefetches.
    pub size: u32,
}

/// Registers an instruction uses without naming them as operands.
///
/// Covered: x30 of branches with link and of `ret` without an operand,
/// x30, SP, x15, x16 and x17 of the pointer authentication instructions
/// that work on fixed registers (`paciasp`, `pacia1716`, `retaa`, …), and
/// the SVE first-fault register FFR ([`RegisterClass::Ffr`](crate::operand::RegisterClass::Ffr)) of
/// first-fault and non-fault loads, `rdffr`, `setffr` and `wrffr`. The
/// condition flags are [`Instruction::flags`]. Floating-point control and
/// status (FPCR read, FPSR cumulative exception flags written by most
/// floating-point instructions), system registers an instruction reads or
/// writes as a side effect (`ELR` of `eret`, `ACCDATA_EL1` of `st64bv0`) and
/// the ZA storage of `smstart`/`smstop` are not listed: they are left to
/// lifting.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Implicit {
    /// Registers read.
    pub reads: &'static [Register],
    /// Registers written.
    pub writes: &'static [Register],
}

impl Implicit {
    /// No implicit registers.
    pub const NONE: Self = Self {
        reads: &[],
        writes: &[],
    };
}

/// A set of the condition flags N, Z, C and V.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub struct FlagSet(u8);

impl FlagSet {
    /// No flags.
    pub const NONE: Self = Self(0);
    /// Negative.
    pub const N: Self = Self(0b1000);
    /// Zero.
    pub const Z: Self = Self(0b0100);
    /// Carry.
    pub const C: Self = Self(0b0010);
    /// Overflow.
    pub const V: Self = Self(0b0001);
    /// All four.
    pub const NZCV: Self = Self(0b1111);

    /// The set with bits N = 8, Z = 4, C = 2, V = 1 (the order of `NZCV`
    /// and of `RMIF`'s mask); higher bits are ignored.
    pub const fn from_bits(bits: u8) -> Self {
        Self(bits & 0b1111)
    }

    /// The bits, N = 8, Z = 4, C = 2, V = 1.
    pub const fn bits(self) -> u8 {
        self.0
    }

    /// Both sets' flags.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Whether every flag of `other` is in the set.
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// Whether the set is empty.
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// The flags an A64 condition field `cond` (0–15, `eq` to `nv`)
    /// tests: `eq` and `ne` Z, `hi` and `ls` C and Z, `gt` and `le` N, Z
    /// and V, `al` and `nv` none.
    pub const fn tested_by(cond: u8) -> Self {
        match (cond >> 1) & 7 {
            // eq, ne
            0 => Self::Z,
            // hs, lo
            1 => Self::C,
            // mi, pl
            2 => Self::N,
            // vs, vc
            3 => Self::V,
            // hi, ls
            4 => Self(Self::C.0 | Self::Z.0),
            // ge, lt
            5 => Self(Self::N.0 | Self::V.0),
            // gt, le
            6 => Self(Self::N.0 | Self::Z.0 | Self::V.0),
            // al, nv
            _ => Self::NONE,
        }
    }
}

impl BitOr for FlagSet {
    type Output = Self;

    fn bitor(self, other: Self) -> Self {
        self.union(other)
    }
}

/// The condition flags an instruction reads and writes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub struct Flags {
    /// Flags read: those its condition tests (`eq` reads Z, `hi` C and Z,
    /// `al` and `nv` none), the carry of `adc`, ….
    pub read: FlagSet,
    /// Flags written (set from the result or to constants).
    pub written: FlagSet,
}

impl Flags {
    /// Reads and writes no flags.
    pub const NONE: Self = Self {
        read: FlagSet::NONE,
        written: FlagSet::NONE,
    };
}

impl Condition {
    /// The condition flags the condition tests.
    pub const fn flags(self) -> FlagSet {
        FlagSet::tested_by(self as u8)
    }
}

impl Instruction {
    /// The access of each operand of [`Instruction::operands`], in the same
    /// order: one entry per operand, for every word.
    pub fn access(self) -> Accesses {
        let mut accesses = Accesses::new();
        let alias = syntax::select(self.encoding(), self.word());
        generated::access(self.encoding(), alias, self.word(), &mut accesses);
        accesses
    }

    /// The access of each operand of [`Instruction::encoding_operands`]
    /// (the encoding's own syntax, not the alias's), in the same order.
    pub fn encoding_access(self) -> Accesses {
        let mut accesses = Accesses::new();
        generated::access(self.encoding(), 0, self.word(), &mut accesses);
        accesses
    }

    /// The memory access, `None` for an instruction that accesses no
    /// memory through an operand (system instructions such as `dc zva` are
    /// not covered).
    pub fn memory(self) -> Option<MemoryAccess> {
        generated::memory(self.encoding(), self.word())
    }

    /// The registers the instruction uses without naming them; see
    /// [`Implicit`].
    pub fn implicit(self) -> Implicit {
        generated::implicit(self.encoding(), self.word())
    }

    /// The condition flags the instruction reads and writes.
    pub fn flags(self) -> Flags {
        generated::flags(self.encoding(), self.word())
    }
}
