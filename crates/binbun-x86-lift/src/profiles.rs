//! x86's processor profiles: the files in `profiles/` (measured by
//! `tests/profile.rs`), embedded, and any other file of the same format,
//! read into [`binbun_semantics::profile::Profile`]s over [`X86`]'s sites.
//!
//! A file names the site table it was measured against
//! ([`site_table_hash`]); one measured against another is refused, as is
//! a rule for a site that does not exist or does not read.

use alloc::borrow::ToOwned;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use binbun_semantics::profile::{Choice, Measured, Profile};
use binbun_semantics::rule::Rule;

use crate::X86;

/// The shipped profiles' text, by identifier: the i9-14900F's P-cores and
/// E-cores.
pub const EMBEDDED: [(&str, &str); 2] = [
    (
        "intel-raptor-cove",
        include_str!("../profiles/intel-raptor-cove.toml"),
    ),
    (
        "intel-gracemont",
        include_str!("../profiles/intel-gracemont.toml"),
    ),
];

/// The site table as profiles name it: each site's name and inputs, in
/// order, hashed (`blake3:...`).
pub fn site_table_hash() -> String {
    let mut hasher = blake3::Hasher::new();
    for site in X86.sites {
        hasher.update(site.name.as_bytes());
        for input in site.inputs {
            hasher.update(b",");
            hasher.update(input.as_bytes());
        }
        hasher.update(b";");
    }
    format!("blake3:{}", hasher.finalize().to_hex())
}

/// The shipped profiles, in [`EMBEDDED`]'s order.
///
/// # Panics
///
/// If a shipped file does not read (the tests read each).
pub fn embedded() -> Vec<Profile> {
    EMBEDDED
        .iter()
        .map(|(id, text)| parse(text).unwrap_or_else(|error| panic!("{id}: {error}")))
        .collect()
}

/// The shipped profile `name` (`intel-raptor-cove`), else the file at
/// path `name`.
///
/// # Errors
///
/// No profile of that name and no readable file there, or the file is
/// not a profile ([`parse`]).
pub fn resolve(name: &str) -> Result<Profile, String> {
    if let Some((_, text)) = EMBEDDED.iter().find(|(id, _)| *id == name) {
        return parse(text);
    }
    let text = std::fs::read_to_string(name).map_err(|error| {
        let known: Vec<&str> = EMBEDDED.iter().map(|(id, _)| *id).collect();
        format!(
            "{name}: not a shipped profile ({}) nor a readable file: {error}",
            known.join(", ")
        )
    })?;
    parse(&text).map_err(|error| format!("{name}: {error}"))
}

/// A TOML value as text: a string as it is, an integer in hexadecimal,
/// a date as written (an array or a table: nothing). Not `toml`'s
/// `Display`, which needs its `display` feature.
fn text(value: Option<&toml::Value>) -> String {
    match value {
        Some(toml::Value::String(text)) => text.clone(),
        Some(toml::Value::Integer(number)) => format!("{number:#x}"),
        Some(toml::Value::Float(number)) => number.to_string(),
        Some(toml::Value::Boolean(flag)) => flag.to_string(),
        Some(toml::Value::Datetime(date)) => date.to_string(),
        Some(toml::Value::Array(_) | toml::Value::Table(_)) | None => String::new(),
    }
}

/// Reads a profile's text.
///
/// # Errors
///
/// Not a profile of format 1 for this site table, a site that does not
/// exist, or a rule that does not read.
pub fn parse(source: &str) -> Result<Profile, String> {
    let table: toml::Table = toml::from_str(source).map_err(|error| error.to_string())?;
    let string = |key: &str| {
        table
            .get(key)
            .and_then(toml::Value::as_str)
            .ok_or_else(|| format!("no `{key}`"))
    };
    if table.get("format").and_then(toml::Value::as_integer) != Some(1) {
        return Err("not format 1".to_owned());
    }
    if string("architecture")? != "x86-64" {
        return Err(format!("for {}, not x86-64", string("architecture")?));
    }
    let hash = site_table_hash();
    if string("sites")? != hash {
        return Err(format!(
            "measured against another site table ({}, now {hash})",
            string("sites")?
        ));
    }
    let revision = table
        .get("revision")
        .and_then(toml::Value::as_integer)
        .and_then(|revision| u32::try_from(revision).ok())
        .ok_or("no `revision`")?;
    let first = table
        .get("measured")
        .and_then(toml::Value::as_array)
        .and_then(|list| list.first());
    let field = |key: &str| text(first.and_then(|first| first.get(key)));
    let measured = Measured {
        cpu: field("cpu"),
        cpus: field("cpus"),
        microcode: field("microcode"),
        date: field("date"),
    };
    let mut choices = vec![None; X86.sites.len()];
    let sites = table
        .get("site")
        .and_then(toml::Value::as_table)
        .ok_or("no sites")?;
    for (name, entry) in sites {
        let id = X86
            .find_site(name)
            .ok_or_else(|| format!("no site {name}"))?;
        let info = X86.site(id).ok_or_else(|| format!("no site {name}"))?;
        let rule = entry
            .get("rule")
            .and_then(toml::Value::as_str)
            .ok_or_else(|| format!("{name}: no rule"))?;
        let choice = match rule {
            "unknown" => Choice::Unknown,
            "varies" => Choice::Varies,
            text => Choice::Rule(
                Rule::parse(text, info.inputs).map_err(|error| format!("{name}: {error}"))?,
            ),
        };
        if let Some(slot) = choices.get_mut(usize::from(id.0)) {
            *slot = Some(choice);
        }
    }
    Ok(Profile {
        id: string("id")?.to_owned(),
        title: string("title")?.to_owned(),
        revision,
        measured,
        choices,
    })
}
