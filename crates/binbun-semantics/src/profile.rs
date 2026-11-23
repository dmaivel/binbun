//! Processor profiles: per site ([`crate::ir::SiteInfo`]), what one
//! microarchitecture does where an
//! architecture's semantics leave a value undefined: a [`Rule`],
//! `unknown` or `varies`. A profile never changes what is defined; a run
//! on a profile's machine asks it for each site's value
//! ([`crate::interpret::Machine::undefined`]).
//!
//! Profiles are read from their files by the architecture that has them
//! (x86: `binbun-x86-lift`'s `profiles` feature); here is what they say,
//! and their values.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use crate::interpret::Value;
use crate::ir::SiteId;
use crate::rule::Rule;

/// What a profile says about one site.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Choice {
    /// The processor computes this.
    Rule(Rule),
    /// No rule of the library fits: the value stays unknown.
    Unknown,
    /// The same input gave two answers: the value stays unknown.
    Varies,
}

impl Choice {
    /// As a profile file writes it: the rule's text, `unknown` or
    /// `varies`.
    pub fn text(&self) -> &str {
        match self {
            Self::Rule(rule) => rule.text(),
            Self::Unknown => "unknown",
            Self::Varies => "varies",
        }
    }
}

/// One machine a profile was measured on (the file's first
/// `[[measured]]`): what a tooltip says of where its rules come from.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Measured {
    /// The processor's brand string (`Intel(R) Core(TM) i9-14900F`).
    pub cpu: String,
    /// The CPUs measured (`0-15`).
    pub cpus: String,
    /// The microcode revision (`0x137`).
    pub microcode: String,
    /// The day (`2026-11-13`).
    pub date: String,
}

/// A processor profile: its rules indexed by [`SiteId`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Profile {
    /// Its identifier (`intel-raptor-cove`).
    pub id: String,
    /// What it describes (`Intel Raptor Cove (P-cores of 13th- and
    /// 14th-generation Core)`).
    pub title: String,
    /// Its revision: a profile's rules change only with a new one.
    pub revision: u32,
    /// Where it was measured.
    pub measured: Measured,
    /// Per site, what it says (`None`: the file lacks the site).
    pub choices: Vec<Option<Choice>>,
}

impl Profile {
    /// Its identifier and revision, as every result made under it names
    /// it: `intel-raptor-cove r1`.
    pub fn label(&self) -> String {
        alloc::format!("{} r{}", self.id, self.revision)
    }

    /// What it says about `site`, if anything.
    pub fn choice(&self, site: SiteId) -> Option<&Choice> {
        self.choices.get(usize::from(site.0))?.as_ref()
    }

    /// The rule of `site`, if it has one.
    pub fn rule(&self, site: SiteId) -> Option<&Rule> {
        match self.choice(site)? {
            Choice::Rule(rule) => Some(rule),
            Choice::Unknown | Choice::Varies => None,
        }
    }

    /// What the processor gives at `site` for `inputs`, `width` bits:
    /// unknown where the profile has no rule, where the rule does not fit
    /// these widths, and in the bits that depend on an undefined input.
    pub fn value(&self, site: SiteId, inputs: &[Value], width: u16) -> Value {
        let widths: Vec<u16> = inputs.iter().map(Value::width).collect();
        self.rule(site)
            .and_then(|rule| rule.instantiate(&widths, width).ok())
            .and_then(|compiled| compiled.eval(inputs).ok())
            .filter(|value| value.width() == width)
            .unwrap_or_else(|| Value::unknown(width))
    }
}

/// The values a profile gave at sites in one run, by instruction and site,
/// in the order given. A run that has every site's inputs (L0's, L1's)
/// records them ([`Choices::record`]); a run of the same function from
/// the same state that lacks some inputs (L2's, which keeps only those
/// lowering knows as constants) takes them in the same order
/// ([`Choices::choose`]): the processor's choice at that instruction, on
/// the inputs it had there.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Choices {
    /// Per instruction and site, each value given, in order.
    made: BTreeMap<(u64, SiteId), Vec<Value>>,
    /// Per instruction and site, how many [`Choices::choose`] has taken.
    taken: BTreeMap<(u64, SiteId), usize>,
}

impl Choices {
    /// Records that the instruction at `address` got `value` at `site`.
    pub fn record(&mut self, address: u64, site: SiteId, value: Value) {
        self.made.entry((address, site)).or_default().push(value);
    }

    /// The value `profile` gives at `site` of the instruction at
    /// `address` for `inputs`, where it defines every bit; else the next
    /// one recorded there, if any; else the profile's (unknown where an
    /// input it reads is).
    pub fn choose(
        &mut self,
        profile: &Profile,
        address: u64,
        site: SiteId,
        inputs: &[Value],
        width: u16,
    ) -> Value {
        let own = profile.value(site, inputs, width);
        let taken = self.taken.entry((address, site)).or_default();
        let recorded = self
            .made
            .get(&(address, site))
            .and_then(|values| values.get(*taken))
            .copied();
        *taken += 1;
        match recorded {
            Some(recorded) if !own.is_defined() && recorded.width() == width => recorded,
            _ => own,
        }
    }

    /// Each instruction and site given a value, with the values in order.
    pub fn made(&self) -> impl Iterator<Item = (u64, SiteId, &[Value])> {
        self.made
            .iter()
            .map(|(&(address, site), values)| (address, site, values.as_slice()))
    }

    /// Whether no site was given a value.
    pub fn is_empty(&self) -> bool {
        self.made.is_empty()
    }
}
