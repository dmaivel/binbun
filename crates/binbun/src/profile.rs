//! Processor profiles for runs, verification and the views: what one
//! microarchitecture does where the architecture leaves a value undefined.
//! A run or a verification under a profile takes its rules' values at the
//! sites
//! ([`run::Options::profile`](crate::run::Options::profile),
//! [`verify::Options::profile`](crate::queries::verify::Options::profile));
//! without one, those values stay unknown, as the architecture says. The
//! C never changes with a profile.
//!
//! Only x86-64 has profiles: the shipped ones ([`embedded`]), and files of
//! their format ([`resolve`]).

use std::sync::{Arc, LazyLock};

use binbun_loader::{Image, Machine};
use binbun_semantics::ir::SiteId;
use binbun_semantics::rule::Rule;
use binbun_ssa::ir::{Function, Op, Unknown};
use binbun_x86_lift::profiles;

pub use binbun_semantics::profile::{Choice, Choices, Measured, Profile};

/// The shipped profiles, read on first use.
static EMBEDDED: LazyLock<Vec<Arc<Profile>>> =
    LazyLock::new(|| profiles::embedded().into_iter().map(Arc::new).collect());

/// The shipped profiles (the i9-14900F's P-cores, then its E-cores), read
/// once.
pub fn embedded() -> &'static [Arc<Profile>] {
    &EMBEDDED
}

/// The shipped profile named `name` (`intel-raptor-cove`), else the
/// profile file at path `name`.
///
/// # Errors
///
/// Neither, or the file is not a profile for this version's sites.
pub fn resolve(name: &str) -> Result<Arc<Profile>, String> {
    if let Some(profile) = embedded().iter().find(|profile| profile.id == name) {
        return Ok(Arc::clone(profile));
    }
    profiles::resolve(name).map(Arc::new)
}

/// Whether `profile` describes a processor of `image`'s architecture.
///
/// # Errors
///
/// It does not (profiles are x86-64's).
pub fn fits(profile: &Profile, image: &Image<'_>) -> Result<(), String> {
    if image.machine == Machine::X86_64 {
        Ok(())
    } else {
        Err(format!(
            "{} describes an x86-64 processor; the image is {:?}",
            profile.id, image.machine
        ))
    }
}

/// How a result names the processor it was made for: the profile's label
/// (`intel-raptor-cove r1`), or the architecture alone.
pub fn label(profile: Option<&Profile>) -> String {
    profile.map_or_else(|| "architecture (any processor)".to_owned(), Profile::label)
}

/// Whether the shipped profiles agree at a site.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Agreement {
    /// They have one rule there.
    Agree,
    /// Their rules differ.
    Differ,
    /// Some has no rule there (`unknown`, `varies`, or none).
    Unknown,
}

/// Whether the shipped profiles' rules at `site` are one rule (as
/// written), differ, or are not all known.
pub fn agreement(site: SiteId) -> Agreement {
    let rules: Option<Vec<&str>> = embedded()
        .iter()
        .map(|profile| profile.rule(site).map(Rule::text))
        .collect();
    match rules {
        None => Agreement::Unknown,
        Some(rules) if rules.windows(2).all(|pair| pair.first() == pair.last()) => Agreement::Agree,
        Some(_) => Agreement::Differ,
    }
}

/// The sites of `l1`'s undefined values: each instruction's address and
/// site, in order, once.
pub fn sites(l1: &Function) -> Vec<(u64, SiteId)> {
    let mut sites: Vec<(u64, SiteId)> = l1
        .insts
        .iter()
        .filter_map(|inst| {
            if let Op::Undefined(
                Unknown::Architecture {
                    address,
                    site: Some(site),
                    ..
                },
                _,
            ) = &inst.op
            {
                Some((*address, *site))
            } else {
                None
            }
        })
        .collect();
    sites.sort_unstable();
    sites.dedup();
    sites
}
