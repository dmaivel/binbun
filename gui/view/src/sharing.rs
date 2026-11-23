//! A shared project's own work as the window shows it
//! (`collab-sync-v2.md` §4.5, §5.1, §14.6), without the network:
//!
//! - **Edits off** ([`EditsOff`]): while the window joins a share (until
//!   the share's own project is open and its journal is the share's), and
//!   while view-only in the session, every edit command is off and the
//!   window says why ([`EditsOff::text`]).
//! - **Not yet shared** ([`pending_text`]): this install's changes on the
//!   share's chains made while no link was a reader's, shown on top of the
//!   admitted state until the share judges them.
//! - **Not in this project** ([`local_rows`]): what the share refused and
//!   what was kept apart, with its values: copied out as text
//!   ([`copy_text`]), or brought in again where the role allows
//!   ([`may_bring`], [`brought`]).
//! - **Bring** ([`bring_rows`], [`bring_text`]): values of a private
//!   project of the same binary, chosen, brought into the share as one new
//!   change of this install's; only this author's chosen at first, others'
//!   and agents' named as such.
//! - **Flush** ([`Flushed`], [`flush_text`]): on leaving or stopping, who
//!   said they hold this window's changes, who had not after the wait, who
//!   went first.
//! - **The history a share lists** ([`Listed`], [`listed_text`],
//!   [`listing_text`]): sharing a project anew, each chain of its history
//!   share's first record would list, whose and how long; only those
//!   left chosen are listed.
//! - **The slice joined** ([`reopen_as`]): a file open as another slice
//!   than the one the owner's signed chain names is opened again as that
//!   one; the slice a ticket names, unsigned, decides nothing.

use binbun_session::journal::{Bringable, ChainId, LocalEdit, PublicKey};

use crate::collab::{Role, key_text, shown_name, value_text};

/// Why the window takes no edits now.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EditsOff {
    /// It is joining a share: there is no share's project to edit yet.
    Joining,
    /// It is view-only in the session, and why.
    ViewOnly(String),
}

impl EditsOff {
    /// Why edits are off, if they are: joining first (nothing typed then
    /// may land in another project), else view-only.
    pub fn of(joining: bool, view_only: Option<String>) -> Option<Self> {
        if joining {
            Some(Self::Joining)
        } else {
            view_only.map(Self::ViewOnly)
        }
    }

    /// What an edit tried meanwhile is told.
    pub fn text(&self) -> String {
        match self {
            Self::Joining => {
                "Joining the share: edits are off until its project is open".to_owned()
            }
            Self::ViewOnly(why) => format!("View-only in this session ({why}): edits are refused"),
        }
    }
}

/// The status line of `count` changes not yet shared ("3 edits not yet
/// shared"), none for none.
pub fn pending_text(count: usize) -> Option<String> {
    match count {
        0 => None,
        1 => Some("1 edit not yet shared".to_owned()),
        n => Some(format!("{n} edits not yet shared")),
    }
}

/// One value of a local edit as listed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValueRow {
    /// What it is about.
    pub what: String,
    /// Its address, if it has one (a click goes there).
    pub address: Option<u64>,
    /// The value.
    pub value: String,
}

/// A local edit as listed: what it did, its values.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalRow {
    /// What it did.
    pub label: String,
    /// Its values.
    pub values: Vec<ValueRow>,
}

/// `edits` as listed, in order.
pub fn local_rows(edits: &[LocalEdit]) -> Vec<LocalRow> {
    edits
        .iter()
        .map(|edit| LocalRow {
            label: edit.label.clone(),
            values: edit
                .values
                .iter()
                .map(|(key, value)| {
                    let (what, address) = key_text(key);
                    ValueRow {
                        what,
                        address,
                        value: value_text(value),
                    }
                })
                .collect(),
        })
        .collect()
}

/// `edit` as text to copy out: what it did, then each value on a line.
pub fn copy_text(edit: &LocalEdit) -> String {
    let mut text = edit.label.clone();
    for row in local_rows(std::slice::from_ref(edit))
        .into_iter()
        .flat_map(|row| row.values)
    {
        text.push('\n');
        text.push_str(&row.what);
        text.push_str(": ");
        text.push_str(&row.value);
    }
    text
}

/// Whether a share's project may bring values in, with role `role` in the
/// session (`live`: in one now). Not in one, it may: what it brings is
/// pending, judged when it next links. In one, only a role that edits may.
pub fn may_bring(role: Option<Role>, live: bool) -> bool {
    if !live {
        return true;
    }
    matches!(role, Some(Role::Owner | Role::Editor | Role::Agent))
}

/// The values of `edits` (kept apart) to bring into the share again, as
/// [`binbun_session::Session::bring`] takes them, each by its author.
pub fn brought(edits: &[LocalEdit]) -> Vec<Bringable> {
    edits
        .iter()
        .flat_map(|edit| {
            edit.values.iter().map(|(key, value)| Bringable {
                key: key.clone(),
                value: value.clone(),
                writer: edit.author,
                origin: edit.origin.clone(),
            })
        })
        .collect()
}

/// A value of a private project offered to bring.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BringRow {
    /// The value as listed.
    pub row: ValueRow,
    /// Whether this install's key wrote it (else another author's or an
    /// agent's, named as such).
    pub mine: bool,
    /// Whether it is chosen at first: only this author's.
    pub chosen: bool,
}

/// `values` (a private project's, [`binbun_session::project::Project::bringable`])
/// as offered to bring, `me` this install's key.
pub fn bring_rows(values: &[Bringable], me: PublicKey) -> Vec<BringRow> {
    values
        .iter()
        .map(|brought| {
            let (what, address) = key_text(&brought.key);
            let mine = brought.writer == me;
            BringRow {
                row: ValueRow {
                    what,
                    address,
                    value: value_text(&brought.value),
                },
                mine,
                chosen: mine,
            }
        })
        .collect()
}

/// What Bring says before it is made: how much, and where it goes.
pub fn bring_text(count: usize, into: &str) -> String {
    let values = if count == 1 { "value" } else { "values" };
    format!("Bring {count} {values} into {into} as one change of yours")
}

/// A chain of the project's own history that sharing it anew could list
/// in the share's first record (`collab-sync-v2.md` §14.6): the owner
/// sees each and lists only those left chosen.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Listed {
    /// The chain.
    pub chain: ChainId,
    /// Its author.
    pub author: PublicKey,
    /// The name of this install's agent that wrote it, if one did.
    pub agent: Option<String>,
    /// Whether this install (itself, or an agent of it) wrote it.
    pub mine: bool,
    /// How many of its changes would be listed.
    pub changes: u64,
    /// Whether it is listed unless the owner leaves it out: this install's
    /// own chains and its agents', the longest few.
    pub chosen: bool,
}

/// What Share says of `listed`: whose it is (`name`: another author's
/// name as known) and how many changes would go: "Yours, 12 changes",
/// "Your agent Claude's, 3 changes", "Ann's, 1 change"; each name
/// escaped ([`shown_name`]).
pub fn listed_text(listed: &Listed, name: &str) -> String {
    let whose = match (&listed.agent, listed.mine) {
        (Some(agent), _) => format!("Your agent {}'s", shown_name(agent)),
        (None, true) => "Yours".to_owned(),
        (None, false) => format!("{}'s", shown_name(name)),
    };
    let changes = if listed.changes == 1 {
        "change"
    } else {
        "changes"
    };
    format!("{whose}, {} {changes}", listed.changes)
}

/// What Share says of the history it lists: `chosen` of `chains` go to
/// those who join; the others stay in this project only, kept apart.
pub fn listing_text(chosen: usize, chains: usize) -> String {
    let left = chains.saturating_sub(chosen);
    let go = match (chosen, chains) {
        (0, _) => "None of this project's history goes to those who join".to_owned(),
        (c, n) if c == n => "All of this project's history goes to those who join".to_owned(),
        (c, n) => format!("{c} of the {n} chains of this project's history go to those who join"),
    };
    if left == 0 {
        format!("{go}.")
    } else {
        format!("{go}; what is left out stays in this project only, kept apart.")
    }
}

/// What a flush on leaving came to, each member by name.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Flushed {
    /// Those who said they hold this window's changes.
    pub acknowledged: Vec<String>,
    /// Those still linked who had not said so when the wait ran out.
    pub unacknowledged: Vec<String>,
    /// Those whose link went before they said so.
    pub disconnected: Vec<String>,
}

/// What the status bar says of `flushed` after the window stopped sharing
/// (`hosting`) or left, the wait `seconds` long.
pub fn flush_text(flushed: &Flushed, hosting: bool, seconds: u64) -> String {
    let done = if hosting {
        "Stopped sharing"
    } else {
        "Left the share"
    };
    let Flushed {
        acknowledged,
        unacknowledged,
        disconnected,
    } = flushed;
    if acknowledged.is_empty() && unacknowledged.is_empty() && disconnected.is_empty() {
        return format!("{done}: no one was linked to take your changes");
    }
    let mut parts = Vec::new();
    if !acknowledged.is_empty() {
        parts.push(format!(
            "{} said they hold your changes",
            acknowledged.join(", ")
        ));
    }
    if !unacknowledged.is_empty() {
        parts.push(format!(
            "{} had not said so after {seconds} s",
            unacknowledged.join(", ")
        ));
    }
    if !disconnected.is_empty() {
        parts.push(format!(
            "{} disconnected before saying so",
            disconnected.join(", ")
        ));
    }
    format!("{done}: {}", parts.join("; "))
}

/// Whether a join opens the file open again, and as which slice:
/// decided by the slice the owner's signed membership chain names
/// (`signed`: once a visit verified it, `None` before; within it, `None`
/// for a file of no slice), never by the slice a ticket names, which is
/// unsigned and not asked for here. `None`: it joins as it is open (open
/// as the signed slice, `open`, in the share's own project, `in_share`),
/// or nothing is verified yet; `Some(arch)`: opened again as `arch` in the
/// share's project.
pub fn reopen_as(
    open: Option<&str>,
    in_share: bool,
    signed: Option<Option<&str>>,
) -> Option<Option<String>> {
    let signed = signed?;
    (!in_share || open != signed).then(|| signed.map(str::to_owned))
}

#[cfg(test)]
mod tests {
    use binbun_session::journal::{ChainId, ChangeId, Key, LocalEdit, Origin, PublicKey, Value};

    use super::{
        EditsOff, Flushed, Listed, brought, copy_text, flush_text, listed_text, listing_text,
        local_rows, may_bring, pending_text, reopen_as,
    };
    use crate::collab::Role;
    use crate::commands::{self, Command, Facts};

    /// A ticket naming `arm64` while `x86_64` is open in the share's
    /// project: its word alone (nothing verified yet) opens nothing again;
    /// a signed `x86_64` joins as open; a signed `arm64` opens it again.
    #[test]
    fn only_a_signed_slice_opens_the_file_again_never_a_tickets() {
        assert_eq!(reopen_as(Some("x86_64"), true, None), None);
        assert_eq!(reopen_as(Some("x86_64"), true, Some(Some("x86_64"))), None);
        assert_eq!(
            reopen_as(Some("x86_64"), true, Some(Some("arm64"))),
            Some(Some("arm64".to_owned()))
        );
        // Open in another project: opened again in the share's, as the
        // signed slice.
        assert_eq!(
            reopen_as(Some("x86_64"), false, Some(Some("x86_64"))),
            Some(Some("x86_64".to_owned()))
        );
        // A file of no slice, in the share's project: joins.
        assert_eq!(reopen_as(None, true, Some(None)), None);
    }

    /// Share names whose each chain is and how much of it goes, a peer's
    /// or agent's name escaped, and says what is left out stays here.
    #[test]
    fn the_history_a_share_lists_is_named_by_author_and_length() {
        let chain = |agent: Option<&str>, mine: bool, changes: u64| Listed {
            chain: ChainId([1; 16]),
            author: PublicKey([2; 32]),
            agent: agent.map(str::to_owned),
            mine,
            changes,
            chosen: mine,
        };
        assert_eq!(
            listed_text(&chain(None, true, 12), "You"),
            "Yours, 12 changes"
        );
        assert_eq!(
            listed_text(&chain(Some("Claude\u{202e}"), true, 1), "x"),
            "Your agent Claude\\u{202e}'s, 1 change"
        );
        assert_eq!(
            listed_text(&chain(None, false, 3), "Ann\n"),
            "Ann\\u{a}'s, 3 changes"
        );
        assert_eq!(
            listing_text(2, 2),
            "All of this project's history goes to those who join."
        );
        assert!(listing_text(1, 3).starts_with("1 of the 3 chains"));
        assert!(listing_text(0, 3).ends_with("stays in this project only, kept apart."));
    }

    fn edit(author: PublicKey, values: Vec<(Key, Value)>) -> LocalEdit {
        LocalEdit {
            change: ChangeId {
                chain: ChainId([1; 16]),
                seq: 3,
            },
            author,
            label: "Rename".to_owned(),
            origin: Origin::User,
            values,
        }
    }

    /// While joining, every edit is off whatever the role, and the window
    /// says it is joining (not view-only); once joined, a view-only
    /// session says why; else edits are on.
    #[test]
    fn the_joining_window_takes_no_edits() {
        let off = EditsOff::of(true, Some("another build".to_owned()));
        assert_eq!(off, Some(EditsOff::Joining));
        let facts = Facts {
            open: true,
            view_only: off.is_some(),
            ..Facts::default()
        };
        for command in [Command::Rename, Command::Comment, Command::Undo] {
            assert!(commands::edits(command));
            assert!(!commands::state(command, &facts).enabled, "{command:?}");
        }
        assert!(off.unwrap().text().starts_with("Joining the share"));
        let view_only = EditsOff::of(false, Some("another build".to_owned())).unwrap();
        assert_eq!(view_only, EditsOff::ViewOnly("another build".to_owned()));
        assert!(view_only.text().contains("another build"));
        assert_eq!(EditsOff::of(false, None), None);
    }

    /// The list of what is not in this project shows each refused edit's
    /// values; copying one gives its values as text; bringing them again
    /// takes each value by its author, and only a role that edits may
    /// while in the session.
    #[test]
    fn what_is_not_in_this_project_is_listed_with_its_values() {
        let me = PublicKey([5; 32]);
        let refused = edit(
            me,
            vec![
                (
                    Key::FunctionName(0x1000),
                    Value::Text(Some("parse".to_owned())),
                ),
                (Key::Comment(0x1004), Value::Text(None)),
            ],
        );
        let rows = local_rows(std::slice::from_ref(&refused));
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].label, "Rename");
        let values: Vec<(&str, Option<u64>, &str)> = rows[0]
            .values
            .iter()
            .map(|v| (v.what.as_str(), v.address, v.value.as_str()))
            .collect();
        assert_eq!(
            values,
            [
                ("Function name at 1000", Some(0x1000), "`parse`"),
                ("Comment at 1004", Some(0x1004), "nothing (removed)"),
            ]
        );
        assert_eq!(
            copy_text(&refused),
            "Rename\nFunction name at 1000: `parse`\nComment at 1004: nothing (removed)"
        );
        let again = brought(std::slice::from_ref(&refused));
        assert_eq!(again.len(), 2);
        assert!(
            again
                .iter()
                .all(|b| b.writer == me && b.origin == Origin::User)
        );
        assert_eq!(again[0].value, Value::Text(Some("parse".to_owned())));
        assert!(may_bring(Some(Role::Editor), true));
        assert!(!may_bring(Some(Role::Viewer), true));
        assert!(!may_bring(None, true));
        assert!(may_bring(None, false));
        assert_eq!(pending_text(0), None);
        assert_eq!(pending_text(2).as_deref(), Some("2 edits not yet shared"));
    }

    /// Leaving says who holds this window's changes, who had not said so,
    /// who went first; with no one linked, that no one took them.
    #[test]
    fn the_flush_on_leaving_is_said() {
        let flushed = Flushed {
            acknowledged: vec!["Ann".to_owned(), "Bob".to_owned()],
            unacknowledged: vec!["Cy".to_owned()],
            disconnected: vec!["Dee".to_owned()],
        };
        assert_eq!(
            flush_text(&flushed, false, 5),
            "Left the share: Ann, Bob said they hold your changes; Cy had not said so after \
             5 s; Dee disconnected before saying so"
        );
        let only = Flushed {
            disconnected: vec!["Dee".to_owned()],
            ..Flushed::default()
        };
        assert_eq!(
            flush_text(&only, true, 5),
            "Stopped sharing: Dee disconnected before saying so"
        );
        assert_eq!(
            flush_text(&Flushed::default(), true, 5),
            "Stopped sharing: no one was linked to take your changes"
        );
    }
}
