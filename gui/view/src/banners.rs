//! The banners across the top of the window, one stack: each banner has a
//! kind (one per kind), a priority, its own buttons and a close button
//! where it can be put away. The two most important show; the rest wait
//! behind a "+N more" line that expands. A banner put away stays away for
//! the window's session unless what it says changes (another version,
//! another error); one that offers it goes for good (Skip this version,
//! No, Always: their settings and files, not the stack).
//!
//! Its users: the symbol server's bar ([`crate::symbols`]), the settings
//! file's problems ([`settings_error`]), the first launch's question and
//! the update offer ([`crate::updates`]), in a shared session an analysis
//! that differs from a peer's ([`crate::collab::analysis_banner`]), and a
//! coding agent running in a terminal without binbun's tools (the app's
//! `terminal_view`).

use std::collections::HashSet;

use binbun_session::journal::PublicKey;

use crate::commands::Command;

/// Which banner comes first: a security update, then failures, a peer's
/// analysis differing, the question asked once, the symbol server, then
/// an ordinary update.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Priority {
    /// A security release is out.
    Security,
    /// Something failed (the settings file).
    Failure,
    /// The shared session: this analysis differs from a peer's.
    Session,
    /// The first launch's question (update checks).
    Question,
    /// The binary's debug information on a symbol server.
    Symbols,
    /// A newer release is out.
    Update,
}

/// What a banner is about: at most one of each shows.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Kind {
    /// The settings file's problems.
    Settings,
    /// Whether to check for updates.
    UpdateQuestion,
    /// The symbol server's bar.
    Symbols,
    /// A newer release.
    Update,
    /// This analysis differs from a peer's (debug files, fingerprint).
    Analysis,
    /// A coding agent runs in a terminal but has not connected: binbun's
    /// setup offered for it.
    Agent,
}

/// A banner's icon and colour.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tone {
    /// Something to know or decide.
    Info,
    /// Something running (a spinner).
    Busy,
    /// Something to do soon (a security release).
    Warning,
    /// Something failed.
    Error,
}

/// What a button does.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    /// Runs a command of the registry (the palette and keys run it too).
    Command(Command),
    /// Opens a web page.
    Open(String),
    /// Skips the version offered, for good (until a newer one).
    SkipVersion,
    /// Answers the question: check for updates, or never.
    CheckUpdates(bool),
    /// Fetches the debug file this participant's analysis read, which
    /// they send ([`crate::collab::analysis_banner`]).
    FetchDebug(PublicKey),
    /// Adds binbun's MCP server to the harness named (its own command, or
    /// Connect an Agent where a config file takes it).
    SetUpAgent(String),
    /// Never offers the harness named binbun's setup again.
    QuietAgent(String),
}

/// A button of a banner.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Button {
    /// Its label.
    pub label: String,
    /// What it does.
    pub action: Action,
}

/// One banner.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Banner {
    /// What it is about.
    pub kind: Kind,
    /// Where it goes in the stack.
    pub priority: Priority,
    /// What it says, as far as putting it away goes: once closed it
    /// stays away until this changes.
    pub about: String,
    /// Its one line.
    pub text: String,
    /// Its icon and colour.
    pub tone: Tone,
    /// Its buttons, in order.
    pub buttons: Vec<Button>,
    /// Whether it has a close button.
    pub closable: bool,
}

/// The banner of the settings file's problems (`message`): closed, it
/// stays away until another problem comes.
pub fn settings_error(message: &str) -> Banner {
    Banner {
        kind: Kind::Settings,
        priority: Priority::Failure,
        about: message.to_owned(),
        text: message.to_owned(),
        tone: Tone::Error,
        buttons: vec![Button {
            label: "Open settings".to_owned(),
            action: Action::Command(Command::OpenSettingsFile),
        }],
        closable: true,
    }
}

/// The banners of one window: what was put away, whether the overflow is
/// expanded.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Stack {
    closed: HashSet<(Kind, String)>,
    expanded: bool,
}

/// What the stack shows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Shown {
    /// The banners shown, most important first.
    pub banners: Vec<Banner>,
    /// How many there are beyond [`Stack::SHOWN`] (0: no "+N more" line).
    pub more: usize,
    /// Whether they are shown too (the line then folds them).
    pub expanded: bool,
}

impl Stack {
    /// How many banners show before the "+N more" line.
    pub const SHOWN: usize = 2;

    /// What shows of `offered`: those not put away, one per kind (the more
    /// important one), most important first (equals in the order
    /// offered), two of them unless expanded.
    pub fn arrange(&self, offered: impl IntoIterator<Item = Banner>) -> Shown {
        let mut banners: Vec<Banner> = Vec::new();
        for banner in offered {
            if self.closed.contains(&(banner.kind, banner.about.clone())) {
                continue;
            }
            match banners.iter_mut().find(|shown| shown.kind == banner.kind) {
                Some(shown) if banner.priority < shown.priority => *shown = banner,
                Some(_) => {}
                None => banners.push(banner),
            }
        }
        banners.sort_by_key(|banner| banner.priority);
        let more = banners.len().saturating_sub(Self::SHOWN);
        let expanded = self.expanded && more > 0;
        if !expanded {
            banners.truncate(Self::SHOWN);
        }
        Shown {
            banners,
            more,
            expanded,
        }
    }

    /// Puts `banner` away for the session, until what it says changes.
    pub fn close(&mut self, banner: &Banner) {
        self.closed.insert((banner.kind, banner.about.clone()));
    }

    /// The "+N more" line: shows the rest, or folds them again.
    pub fn toggle(&mut self) {
        self.expanded = !self.expanded;
    }
}

/// The overflow line: "+2 more", or "Show fewer" when expanded.
pub fn more_text(shown: &Shown) -> String {
    if shown.expanded {
        "Show fewer".to_owned()
    } else {
        format!("+{} more", shown.more)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn banner(kind: Kind, priority: Priority, about: &str) -> Banner {
        Banner {
            kind,
            priority,
            about: about.to_owned(),
            text: about.to_owned(),
            tone: Tone::Info,
            buttons: Vec::new(),
            closable: true,
        }
    }

    fn kinds(shown: &Shown) -> Vec<(Kind, Priority)> {
        shown.banners.iter().map(|b| (b.kind, b.priority)).collect()
    }

    #[test]
    fn banners_show_by_priority_two_at_most() {
        let stack = Stack::default();
        let shown = stack.arrange([
            banner(Kind::Update, Priority::Update, "0.2.0"),
            banner(Kind::Symbols, Priority::Symbols, "offer"),
            banner(Kind::Settings, Priority::Failure, "bad key"),
            banner(Kind::UpdateQuestion, Priority::Question, ""),
        ]);
        assert_eq!(
            kinds(&shown),
            [
                (Kind::Settings, Priority::Failure),
                (Kind::UpdateQuestion, Priority::Question)
            ]
        );
        assert_eq!(shown.more, 2);
        assert_eq!(more_text(&shown), "+2 more");
        // A security release goes before a failure.
        let shown = stack.arrange([
            banner(Kind::Settings, Priority::Failure, "bad key"),
            banner(Kind::Update, Priority::Security, "0.2.1"),
        ]);
        assert_eq!(
            kinds(&shown),
            [
                (Kind::Update, Priority::Security),
                (Kind::Settings, Priority::Failure)
            ]
        );
        assert_eq!(shown.more, 0);
    }

    #[test]
    fn one_banner_per_kind_the_more_important() {
        let shown = Stack::default().arrange([
            banner(Kind::Update, Priority::Update, "0.2.0"),
            banner(Kind::Update, Priority::Security, "0.2.1"),
            banner(Kind::Update, Priority::Update, "0.3.0"),
        ]);
        assert_eq!(shown.banners.len(), 1);
        assert_eq!(shown.banners[0].about, "0.2.1");
        assert_eq!(shown.more, 0);
    }

    #[test]
    fn the_overflow_expands_and_folds() {
        let mut stack = Stack::default();
        let offered = [
            banner(Kind::Symbols, Priority::Symbols, "offer"),
            banner(Kind::Update, Priority::Update, "0.2.0"),
            banner(Kind::Settings, Priority::Failure, "bad key"),
        ];
        assert_eq!(stack.arrange(offered.clone()).banners.len(), 2);
        stack.toggle();
        let shown = stack.arrange(offered.clone());
        assert_eq!(
            kinds(&shown),
            [
                (Kind::Settings, Priority::Failure),
                (Kind::Symbols, Priority::Symbols),
                (Kind::Update, Priority::Update)
            ]
        );
        assert_eq!(more_text(&shown), "Show fewer");
        // Nothing beyond two: no line, whatever was expanded.
        let two = stack.arrange(offered.iter().take(2).cloned());
        assert_eq!((two.more, two.expanded), (0, false));
        stack.toggle();
        assert_eq!(stack.arrange(offered).banners.len(), 2);
    }

    #[test]
    fn a_closed_banner_stays_away_until_what_it_says_changes() {
        let mut stack = Stack::default();
        let update = banner(Kind::Update, Priority::Update, "0.2.0");
        let error = banner(Kind::Settings, Priority::Failure, "bad key");
        let symbols = banner(Kind::Symbols, Priority::Symbols, "offer");
        stack.close(&update);
        let shown = stack.arrange([update, error.clone(), symbols]);
        assert_eq!(
            kinds(&shown),
            [
                (Kind::Settings, Priority::Failure),
                (Kind::Symbols, Priority::Symbols)
            ]
        );
        // The closed one does not count behind "+N more".
        assert_eq!(shown.more, 0);
        // A newer version, another error: shown again.
        let shown = stack.arrange([banner(Kind::Update, Priority::Update, "0.2.1")]);
        assert_eq!(shown.banners.len(), 1);
        stack.close(&error);
        assert_eq!(stack.arrange([error]).banners, []);
        assert_eq!(
            stack
                .arrange([banner(Kind::Settings, Priority::Failure, "other")])
                .banners
                .len(),
            1
        );
    }
}
