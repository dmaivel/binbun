//! What the peek card shows for a name: the
//! target's kind, name and address; its body (a function's C, which the
//! session supplies, or the item's own listing lines: typed data, a
//! label's first instructions); and the cross-references to it, the first
//! nine numbered so a digit goes there.

use std::sync::Arc;

use binbun::Database;
use binbun::cfg::FunctionId;
use binbun::profile::{self, Choice, Profile};
use binbun::references::Kind as ReferenceKind;
use binbun_semantics::ir::SiteId;
use binbun_session::Identified;

use crate::listing::{Item, LineKind, Listing, Overlay, Rendered, Role};

/// What a peeked name names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// A function's entry.
    Function,
    /// An import (its thunk or pointer slot).
    Import,
    /// Code that is not a function's entry (a label).
    Code,
    /// A string literal.
    String,
    /// Other data.
    Data,
}

impl Kind {
    /// Its name on the card.
    pub fn label(self) -> &'static str {
        match self {
            Self::Function => "function",
            Self::Import => "import",
            Self::Code => "label",
            Self::String => "string",
            Self::Data => "data",
        }
    }
}

/// A cross-reference on the card.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Xref {
    /// Where it is made.
    pub from: u64,
    /// Where that is, as a name and an offset (`main+58`).
    pub place: String,
    /// How (`call`, `jump`, `read`, `write`, `address`, `pointer`).
    pub how: &'static str,
}

/// The cross-references the card lists (a digit 1–9 follows one).
pub const XREFS: usize = 9;

/// The listing lines a data or label body shows at most.
pub const BODY_LINES: usize = 8;

/// A peek card's content.
#[derive(Clone, Debug)]
pub struct Peek {
    /// The address peeked at.
    pub address: u64,
    /// Its name as shown.
    pub name: String,
    /// What it is.
    pub kind: Kind,
    /// The function starting there, whose C is the body.
    pub function: Option<FunctionId>,
    /// The listing lines shown when there is no C.
    pub lines: Vec<Rendered>,
    /// The first cross-references to it.
    pub xrefs: Vec<Xref>,
    /// How many cross-references there are in all.
    pub total_xrefs: usize,
    /// What the card says above the body, if anything: why the token
    /// peeked from names this place ([`undefined_note`]).
    pub note: Option<String>,
}

/// The card for `address` (the cross-references only once `db`'s are
/// built: `referenced`).
pub fn peek(
    listing: &Listing,
    db: &Database<'_>,
    overlay: &Overlay,
    address: u64,
    referenced: bool,
) -> Peek {
    let function = db.function_at(address);
    let line = listing.line(listing.line_of(address));
    let item = line.filter(|l| l.address == address).map(|l| l.item);
    let first = listing.render(db, listing.line_of(address), overlay);
    let import = first
        .tokens
        .iter()
        .any(|t| t.role == Role::ImportName && t.target == Some(address));
    let string = first.tokens.iter().any(|t| t.role == Role::String);
    let kind = match (function, item) {
        _ if import => Kind::Import,
        (Some(_), _) => Kind::Function,
        (None, Some(Item::Function | Item::Code)) => Kind::Code,
        (None, Some(Item::Data | Item::Unexplored) | None) if string => Kind::String,
        (None, Some(Item::Data | Item::Unexplored) | None) => Kind::Data,
    };
    let lines = if kind == Kind::Function {
        Vec::new()
    } else {
        body(listing, db, overlay, address, kind)
    };
    let (xrefs, total_xrefs) = if referenced {
        let to = db.references().to(address);
        let xrefs = to
            .iter()
            .take(XREFS)
            .map(|r| Xref {
                from: r.from,
                place: listing.describe(r.from),
                how: how(r.kind),
            })
            .collect();
        (xrefs, to.len())
    } else {
        (Vec::new(), 0)
    };
    Peek {
        address,
        name: listing
            .shown_name(address, overlay)
            .map_or_else(|| listing.describe(address), str::to_owned),
        kind,
        function,
        lines,
        xrefs,
        total_xrefs,
        note: None,
    }
}

/// A run's value at an undefined value's site: the processor it ran on
/// and the values it gave there, as shown (`1`, `1 · 0 ×4`).
#[derive(Clone, Copy, Debug)]
pub struct RunValue<'a> {
    /// The processor's profile.
    pub profile: &'a Profile,
    /// The values.
    pub values: &'a str,
}

/// The note of the card for a function a library signature names: the
/// pack, the object and how it matched (`musl 1.2.5 · src/string/strcpy.o
/// · exact`, `… · behaviour: 48 of 48 states agreed, 7 ruled out`).
pub fn provenance(identified: &Identified) -> String {
    format!(
        "{} {} · {} · {} (pack {})",
        identified.library, identified.version, identified.object, identified.how, identified.pack
    )
}

/// The note of the card for the instruction that leaves the value a C
/// token stands for undefined (`_OF_undefined`), one line each: `what`
/// (the register's name, if it leaves one) and its site (`shrd.of`, if
/// the architecture names one); what each processor profile does there,
/// the setting's (`chosen`) first, then the shipped ones; and what
/// `run` gave there.
pub fn undefined_note(
    what: Option<&str>,
    site: Option<(SiteId, &str)>,
    chosen: Option<&Profile>,
    run: Option<RunValue<'_>>,
) -> String {
    let what = what.map_or_else(|| String::from("This value"), str::to_ascii_uppercase);
    let Some((site, name)) = site else {
        return format!(
            "{what} is left undefined by this instruction: the architecture does not say what it is, and processors differ (AMD, Intel's P-cores and its E-cores set it differently)"
        );
    };
    let mut lines = vec![format!(
        "{what} is left undefined by this instruction ({name}): the architecture does not say what it is"
    )];
    let shipped = profile::embedded()
        .iter()
        .map(Arc::as_ref)
        .filter(|p| chosen.is_none_or(|c| c.id != p.id));
    for profile in chosen.into_iter().chain(shipped) {
        let short = short_title(profile);
        lines.push(match profile.choice(site) {
            Some(Choice::Rule(rule)) => format!("{short} gives {}", rule.text()),
            Some(Choice::Varies) => format!("{short} varies here"),
            Some(Choice::Unknown) | None => format!("{short} is not known here"),
        });
    }
    if let Some(run) = run {
        lines.push(format!(
            "This run on {} gave {}",
            short_title(run.profile),
            run.values
        ));
    }
    lines.join("\n")
}

/// A profile's title without what it adds in parentheses: `Intel Raptor
/// Cove`.
pub fn short_title(profile: &Profile) -> &str {
    profile
        .title
        .split_once(" (")
        .map_or(profile.title.as_str(), |(short, _)| short)
}

/// The item's content lines (a label's: its next instructions), at most
/// [`BODY_LINES`].
fn body(
    listing: &Listing,
    db: &Database<'_>,
    overlay: &Overlay,
    address: u64,
    kind: Kind,
) -> Vec<Rendered> {
    let mut lines = Vec::new();
    let mut n = listing.line_of(address);
    while lines.len() < BODY_LINES
        && let Some(line) = listing.line(n)
    {
        let same_item = line.address == address;
        let shown = matches!(
            line.kind,
            LineKind::Instruction | LineKind::Data | LineKind::Preview
        );
        if !same_item && kind != Kind::Code {
            break;
        }
        if kind == Kind::Code && line.kind == LineKind::End {
            break;
        }
        if shown {
            lines.push(listing.render(db, n, overlay));
        }
        n += 1;
    }
    lines
}

/// A reference's kind as the card says it.
pub fn how(kind: ReferenceKind) -> &'static str {
    match kind {
        ReferenceKind::Call => "call",
        ReferenceKind::Jump => "jump",
        ReferenceKind::Read => "read",
        ReferenceKind::Write => "write",
        ReferenceKind::Address => "address",
        ReferenceKind::Pointer(_) => "pointer",
    }
}

#[cfg(test)]
mod tests {
    use binbun::profile::{self, Agreement};
    use binbun_semantics::ir::SiteId;

    use super::{RunValue, short_title, undefined_note};

    /// At a site where the shipped profiles differ, the note lists each
    /// one's rule, the setting's first, then the run's value on its
    /// processor; without a site it says only that processors differ.
    #[test]
    fn the_undefined_note_lists_each_processors_rule_the_chosen_first() {
        let [p, e] = profile::embedded() else {
            panic!("two shipped profiles");
        };
        let site = (0..u16::MAX)
            .map(SiteId)
            .find(|&site| profile::agreement(site) == Agreement::Differ)
            .unwrap();
        let rule = |profile: &profile::Profile| profile.rule(site).unwrap().text().to_owned();
        assert_ne!(rule(p), rule(e));
        let unchosen = undefined_note(Some("of"), Some((site, "x.of")), None, None);
        assert_eq!(
            unchosen.lines().collect::<Vec<_>>(),
            [
                "OF is left undefined by this instruction (x.of): the architecture does not say what it is".to_owned(),
                format!("{} gives {}", short_title(p), rule(p)),
                format!("{} gives {}", short_title(e), rule(e)),
            ]
        );
        assert_eq!(short_title(e), "Intel Gracemont");
        let chosen = undefined_note(
            Some("of"),
            Some((site, "x.of")),
            Some(e),
            Some(RunValue {
                profile: e,
                values: "1",
            }),
        );
        let lines: Vec<&str> = chosen.lines().collect();
        assert_eq!(lines.len(), 4, "{chosen}");
        assert_eq!(lines[1], format!("Intel Gracemont gives {}", rule(e)));
        assert_eq!(lines[2], format!("{} gives {}", short_title(p), rule(p)));
        assert_eq!(lines[3], "This run on Intel Gracemont gave 1");
        let bare = undefined_note(None, None, Some(e), None);
        assert!(!bare.contains('\n') && bare.starts_with("This value is left undefined"));
    }
}
