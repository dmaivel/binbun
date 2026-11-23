//! `binbun strings` and `binbun xrefs`: the engine's string literals and
//! cross-references ([`Database::strings`], [`Database::references`]) as
//! text, one per line.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use binbun::Database;
use binbun::analysis::Seeds;
use binbun::references::{Kind, Origin, Reference};
use binbun::strings::{Encoding, Literal, MIN_SCANNED};
use binbun_loader::{Image, Relocation};
use binbun_print::c::string_literal;

use super::{USAGE, database, load, read};

/// `strings FILE [--min N] [--referenced]`: the string literals of the
/// image's data, one per line: address, section, encoding, length in
/// characters, references to its first byte, and the text as a C literal.
/// Those found by scanning have at least `--min` characters (4); with
/// `--referenced`, only those referred to.
pub fn strings(args: &[String]) -> Result<String, String> {
    let mut min = MIN_SCANNED;
    let mut referenced = false;
    let mut paths = Vec::new();
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--min" => {
                min = args
                    .next()
                    .and_then(|n| n.parse().ok())
                    .filter(|&n| n > 0)
                    .ok_or_else(|| USAGE.to_owned())?;
            }
            "--referenced" => referenced = true,
            _ if arg.starts_with("--") => return Err(USAGE.to_owned()),
            _ => paths.push(arg),
        }
    }
    let [path] = paths[..] else {
        return Err(USAGE.to_owned());
    };
    let data = read(path)?;
    let image = load(path, &data)?;
    let database = database(path, &image, Seeds::ALL)?;
    let literals = database.strings(min);
    let referred = literals.iter().filter(|s| s.references > 0).count();
    let mut out = format!(
        "# {} strings: {referred} referred to, {} found by scanning only (at least {min} characters)\n# address section encoding length references text\n",
        literals.len(),
        literals.len() - referred,
    );
    for literal in literals.iter().filter(|s| !referenced || s.references > 0) {
        let encoding = match literal.encoding {
            Encoding::Utf8 => "utf8",
            Encoding::Utf16 => "utf16",
        };
        let _ = writeln!(
            out,
            "{:#x} {} {encoding} {} {} {}",
            literal.address,
            section(&image, literal.address),
            literal.text.chars().count(),
            literal.references,
            c_literal(literal),
        );
    }
    Ok(out)
}

/// `literal` as a C string literal ([`string_literal`]'s escapes; `u"…"`
/// for UTF-16, with other than ASCII as universal character names).
fn c_literal(literal: &Literal) -> String {
    match literal.encoding {
        Encoding::Utf8 => string_literal(literal.text.as_bytes()),
        Encoding::Utf16 => {
            let mut out = String::from("u\"");
            let mut previous = '\0';
            for c in literal.text.chars() {
                match u8::try_from(c) {
                    Ok(b'?') if previous == '?' => out.push_str("\\?"),
                    Ok(byte) if byte.is_ascii() => {
                        let quoted = string_literal(&[byte]);
                        let inner = quoted.strip_prefix('"').and_then(|q| q.strip_suffix('"'));
                        out.push_str(inner.unwrap_or_default());
                    }
                    Ok(_) | Err(_) if u32::from(c) <= 0xffff => {
                        let _ = write!(out, "\\u{:04x}", u32::from(c));
                    }
                    Ok(_) | Err(_) => {
                        let _ = write!(out, "\\U{:08x}", u32::from(c));
                    }
                }
                previous = c;
            }
            out.push('"');
            out
        }
    }
}

/// The name of the section of `image` holding `address` (`-` if none).
fn section<'a>(image: &'a Image<'_>, address: u64) -> &'a str {
    image
        .sections
        .iter()
        .filter(|s| s.start != 0 && s.name != ".tbss")
        .find(|s| (s.start..s.start.saturating_add(s.size)).contains(&address))
        .map_or("-", |s| s.name.as_str())
}

/// `xrefs FILE TARGET` and `xrefs FILE --from FUNCTION`: the references
/// to an address (a name or a hexadecimal address; all of a data object
/// of known size), one per line: where, what makes it (a function and
/// offset, or the section and object of a pointer), how; or what a
/// function refers to.
pub fn xrefs(args: &[String]) -> Result<String, String> {
    let (path, from, wanted) = match args {
        [path, flag, wanted] if flag == "--from" => (path, true, wanted),
        [path, wanted] if !wanted.starts_with("--") => (path, false, wanted),
        _ => return Err(USAGE.to_owned()),
    };
    let data = read(path)?;
    let image = load(path, &data)?;
    let database = database(path, &image, Seeds::ALL)?;
    let mut out = if from {
        referred_from(&database, wanted)?
    } else {
        referring_to(&database, wanted)?
    };
    let references = database.references();
    let unlifted = references.unlifted().len();
    if unlifted > 0 {
        let _ = writeln!(
            out,
            "# {unlifted} functions do not lift: only their calls and jumps are recovered"
        );
    }
    if references.scanned() {
        out.push_str("# pointers in data found by scanning (the image has no relocations)\n");
    }
    Ok(out)
}

/// The references to what `wanted` names in `database`.
fn referring_to(database: &Database<'_>, wanted: &str) -> Result<String, String> {
    let address = resolve(database, wanted)?;
    let references = database.references();
    let object = database
        .object(address)
        .filter(|object| object.start == address);
    let found = object
        .clone()
        .map_or_else(|| references.to(address), |o| references.within(o));
    let name = describe(database, address);
    let mut out = format!("# {} references to {name}", found.len());
    if name != format!("{address:#x}") {
        let _ = write!(out, " ({address:#x})");
    }
    if let Some(object) = object {
        let _ = write!(out, ", an object of {} bytes", object.end - object.start);
    }
    out.push('\n');
    for reference in found {
        out.push_str(&line(database, reference, reference.target != address));
        // A GOT or PLT slot's users refer to the target through it.
        if matches!(
            reference.kind,
            Kind::Pointer(Origin::Relocation(
                Relocation::GlobDat | Relocation::JumpSlot
            ))
        ) {
            for through in references.to(reference.from) {
                let _ = write!(out, "    through {:#x}: ", reference.from);
                out.push_str(&line(database, through, false));
            }
        }
    }
    Ok(out)
}

/// The references function `wanted` of `database` makes, with the string
/// each refers to, if one.
fn referred_from(database: &Database<'_>, wanted: &str) -> Result<String, String> {
    let id = database.find_function(wanted)?;
    let references = database.references();
    let strings: BTreeMap<u64, Literal> = database
        .strings(MIN_SCANNED)
        .into_iter()
        .map(|literal| (literal.address, literal))
        .collect();
    let made: Vec<&Reference> = references.from_function(id).collect();
    let mut out = format!(
        "# {} references from {}\n",
        made.len(),
        database
            .function(id)
            .map_or_else(String::new, |f| describe(database, f.entry)),
    );
    for reference in made {
        let _ = write!(
            out,
            "{:#x} {:<8} {}",
            reference.from,
            kind(reference.kind),
            describe(database, reference.target)
        );
        if let Some(literal) = strings.get(&reference.target) {
            let _ = write!(out, " {}", c_literal(literal));
        }
        out.push('\n');
    }
    Ok(out)
}

/// The address `wanted` names in `database`: a symbol, an import thunk or
/// an import (its pointer slot), else a hexadecimal address (`0x`
/// optional).
pub(crate) fn resolve(database: &Database<'_>, wanted: &str) -> Result<u64, String> {
    database
        .names()
        .iter()
        .find(|(_, name)| *name == wanted)
        .map(|(&address, _)| address)
        .or_else(|| {
            database
                .functions()
                .map(|(_, function)| function.entry)
                .find(|&entry| database.data_name(entry).as_deref() == Some(wanted))
        })
        .or_else(|| {
            let slot = wanted.strip_suffix("_ptr").unwrap_or(wanted);
            database
                .image()
                .imports
                .iter()
                .find(|import| import.name == slot)
                .map(|import| import.slot)
        })
        .or_else(|| u64::from_str_radix(wanted.trim_start_matches("0x"), 16).ok())
        .ok_or_else(|| format!("no symbol, import or address {wanted}"))
}

/// One line for `reference`: where it is made, how, and (`offset`) the
/// address it refers to. A reference made in a part of a function (a cold
/// part placed apart) is placed from that part's start.
fn line(database: &Database<'_>, reference: &Reference, offset: bool) -> String {
    let place = match reference.function.and_then(|id| database.function(id)) {
        Some(function) => {
            let start = core::iter::once(function.entry)
                .chain(function.parts.iter().copied())
                .filter(|&start| start <= reference.from)
                .max()
                .unwrap_or(function.entry);
            let name = describe(database, start);
            let delta = reference.from.wrapping_sub(start);
            if delta == 0 {
                name
            } else {
                format!("{name}+{delta:#x}")
            }
        }
        None => format!(
            "{} {}",
            section(database.image(), reference.from),
            describe(database, reference.from)
        ),
    };
    let mut text = format!("{:#x} {:<8} {place}", reference.from, kind(reference.kind));
    if offset {
        let _ = write!(text, " -> {}", describe(database, reference.target));
    }
    text.push('\n');
    text
}

/// How a reference refers, as a word.
fn kind(kind: Kind) -> &'static str {
    match kind {
        Kind::Call => "call",
        Kind::Jump => "jump",
        Kind::Read => "read",
        Kind::Write => "write",
        Kind::Address => "address",
        Kind::Pointer(Origin::Scan) => "pointer(scan)",
        Kind::Pointer(Origin::Relocation(relocation)) => match relocation {
            Relocation::Relative => "pointer(relative)",
            Relocation::Absolute => "pointer(absolute)",
            Relocation::GlobDat => "pointer(glob_dat)",
            Relocation::JumpSlot => "pointer(jump_slot)",
            Relocation::Base => "pointer(base)",
            Relocation::Rebase => "pointer(rebase)",
        },
    }
}

/// `address` in `database`'s names: its name, or the object holding it
/// plus an offset, or the address.
fn describe(database: &Database<'_>, address: u64) -> String {
    if let Some(name) = database.data_name(address) {
        return name;
    }
    database
        .object(address)
        .and_then(|object| {
            let name = database.data_name(object.start)?;
            Some(format!("{name}+{:#x}", address - object.start))
        })
        .unwrap_or_else(|| format!("{address:#x}"))
}
