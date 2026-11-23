//! The CPUID bits an instruction's feature set ([`IsaSet`]) needs, from
//! XED's `cpuid.txt` files.
//!
//! An ISA set lists groups of fields: a CPU supports it if every field of
//! one group has its value. Most sets have one group; AVX-512 sets also
//! have an AVX10 group (listed first). Sets that every x86 CPU has (`I86`)
//! have none.

use crate::IsaSet;
use crate::generated::cpuid::groups;

/// A CPUID output register.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CpuidRegister {
    /// `EAX`
    Eax,
    /// `EBX`
    Ebx,
    /// `ECX`
    Ecx,
    /// `EDX`
    Edx,
}

impl CpuidRegister {
    /// Lower-case name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Eax => "eax",
            Self::Ebx => "ebx",
            Self::Ecx => "ecx",
            Self::Edx => "edx",
        }
    }
}

/// Bits `low..=high` of `register` from CPUID leaf `leaf`, subleaf
/// `subleaf`, which must equal `value`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CpuidField {
    /// The CPUID leaf (`EAX` input).
    pub leaf: u32,
    /// The subleaf (`ECX` input).
    pub subleaf: u32,
    /// The output register.
    pub register: CpuidRegister,
    /// Lowest bit of the field.
    pub low: u8,
    /// Highest bit of the field.
    pub high: u8,
    /// The value the field needs.
    pub value: u32,
}

impl IsaSet {
    /// The CPUID groups that each enable this set: any one suffices, and
    /// one needs all of its fields. Empty for sets every CPU has.
    pub fn cpuid(self) -> &'static [&'static [CpuidField]] {
        groups(self)
    }
}
