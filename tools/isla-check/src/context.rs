//! Where binbun's AArch64 state lives in sail-arm.
//!
//! binbun's registers (`binbun_aarch64_lift::AARCH64`, matched by name):
//! `x0`–`x30` are Sail's `R0`–`R30`, `sp` is `SP_EL0` (EL0 with
//! `PSTATE.SP = 0`), `n`, `z`, `c`, `v` and `btype` are fields of `PSTATE`,
//! `pc` is `_PC`. The vector registers, `fpcr` and `fpsr` are not mapped
//! yet: a path that writes Sail's counterparts is reported unsupported.

/// Where a binbun register lives in Sail.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Location {
    /// A whole Sail register.
    Register(String),
    /// A field of `PSTATE`.
    Pstate(&'static str),
    /// The program counter, `_PC`.
    ProgramCounter,
}

/// The `PSTATE` fields binbun models, with binbun's names.
pub const PSTATE_FIELDS: [(&str, &str); 8] = [
    ("N", "n"),
    ("Z", "z"),
    ("C", "c"),
    ("V", "v"),
    ("BTYPE", "btype"),
    ("DIT", "dit"),
    ("SSBS", "ssbs"),
    ("TCO", "tco"),
];

/// Whole Sail registers binbun maps besides the general ones: Sail's name
/// and binbun's.
const REGISTERS: [(&str, &str); 3] = [
    ("SP_EL0", "sp"),
    ("TPIDR_EL0", "tpidr_el0"),
    ("TPIDRRO_EL0", "tpidrro_el0"),
];

/// Sail registers binbun reads through its `system_register` intrinsic,
/// with their encodings (`op0:op1:CRn:CRm:op2`): the value Sail reads is
/// the intrinsic's on that encoding.
pub const SYSTEM_REGISTERS: [(&str, u16); 3] = [
    ("CTR_EL0", 0xd801),
    ("DCZID_EL0", 0xd807),
    ("CNTFRQ_EL0", 0xdf00),
];

/// Where binbun's register `name` lives, if it is mapped.
pub fn location(name: &str) -> Option<Location> {
    if let Some(number) = name.strip_prefix('x')
        && let Ok(number) = number.parse::<u8>()
        && number <= 30
    {
        return Some(Location::Register(format!("R{number}")));
    }
    if let Some((sail, _)) = REGISTERS.iter().find(|(_, binbun)| *binbun == name) {
        return Some(Location::Register((*sail).into()));
    }
    match name {
        "pc" => Some(Location::ProgramCounter),
        _ => PSTATE_FIELDS
            .iter()
            .find(|(_, binbun)| *binbun == name)
            .map(|(sail, _)| Location::Pstate(sail)),
    }
}

/// binbun's name for Sail's whole register `sail`, if mapped.
pub fn binbun_register(sail: &str) -> Option<String> {
    if let Some((_, binbun)) = REGISTERS.iter().find(|(name, _)| *name == sail) {
        return Some((*binbun).into());
    }
    let number: u8 = sail.strip_prefix('R')?.parse().ok()?;
    (number <= 30).then(|| format!("x{number}"))
}

/// Sail registers whose writes record the instruction's progress rather
/// than architectural state binbun models: decode bookkeeping, branch
/// hints, the next BTYPE (compared separately), the exclusive monitor's
/// and statistical profiling's internals.
pub const BOOKKEEPING: [&str; 13] = [
    "SEE",
    "__BranchTaken",
    "Branchtypetaken",
    "BTypeCompatible",
    "BTypeNext",
    "__ThisInstr",
    "__ThisInstrEnc",
    "__currentInstrLength",
    "ShouldAdvanceIT",
    "__ExclusiveMonitorSet",
    "SPESampleInFlight",
    "__LSMultiple",
    "InGuardedPage",
];

/// Sail registers whose write means an exception was taken (the syndrome
/// registers of the exception levels).
pub const SYNDROMES: [&str; 3] = ["ESR_EL1", "ESR_EL2", "ESR_EL3"];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registers_map_both_ways() {
        for number in 0..=30 {
            let binbun = format!("x{number}");
            let Some(Location::Register(sail)) = location(&binbun) else {
                panic!("{binbun} unmapped");
            };
            assert_eq!(binbun_register(&sail).as_deref(), Some(binbun.as_str()));
        }
        assert_eq!(location("x31"), None);
        assert_eq!(binbun_register("R31"), None);
        assert_eq!(location("sp"), Some(Location::Register("SP_EL0".into())));
        assert_eq!(binbun_register("SP_EL0").as_deref(), Some("sp"));
        assert_eq!(location("btype"), Some(Location::Pstate("BTYPE")));
        assert_eq!(location("v0"), None);
        assert_eq!(location("fpcr"), None);
    }
}
