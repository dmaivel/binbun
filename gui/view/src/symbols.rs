//! The bar across the top of the workspace about the open binary's debug
//! information on a symbol server (`symbols.download`): offered (Download,
//! Not now, Always), being downloaded, or why it was not. Never blocks:
//! the analysis goes on, and a download is taken by decompiling again.

use std::path::PathBuf;

use binbun_session::SymbolState;

use crate::banners::{Action, Banner, Button, Kind, Priority, Tone};
use crate::commands::Command;

/// What the bar shows, if anything.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Bar {
    /// The debug information is on a server and not fetched: Download,
    /// Not now, Always.
    Offer {
        /// The binary's file name.
        binary: String,
        /// The server's host.
        server: String,
    },
    /// It is being downloaded.
    Downloading {
        /// The binary's file name.
        binary: String,
        /// The server's host.
        server: String,
    },
    /// It could not be fetched (dismissable).
    Failed {
        /// The binary's file name.
        binary: String,
        /// Why, in one line.
        reason: String,
    },
}

impl Bar {
    /// The bar's one line.
    pub fn text(&self) -> String {
        match self {
            Self::Offer { binary, server } => {
                format!("Debug information for {binary} is on {server}.")
            }
            Self::Downloading { binary, server } => {
                format!("Downloading debug information for {binary} from {server}…")
            }
            Self::Failed { binary, reason } => {
                format!("Debug information for {binary} was not downloaded: {reason}.")
            }
        }
    }

    /// The bar in the banner stack: the offer's buttons are the
    /// registry's commands; a failure closes (until something new
    /// happens: [`SymbolsBar::dismiss`]).
    pub fn banner(&self) -> Banner {
        let button = |label: &str, command| Button {
            label: label.to_owned(),
            action: Action::Command(command),
        };
        let (tone, buttons) = match self {
            Self::Offer { .. } => (
                Tone::Info,
                vec![
                    button("Download", Command::DownloadSymbols),
                    button("Not now", Command::SymbolsNotNow),
                    button("Always", Command::AlwaysDownloadSymbols),
                ],
            ),
            Self::Downloading { .. } => (Tone::Busy, Vec::new()),
            Self::Failed { .. } => (Tone::Error, Vec::new()),
        };
        let text = self.text();
        Banner {
            kind: Kind::Symbols,
            priority: Priority::Symbols,
            about: text.clone(),
            text,
            tone,
            buttons,
            closable: matches!(self, Self::Failed { .. }),
        }
    }
}

/// The bar's state for one opened binary.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SymbolsBar {
    /// What the session told last.
    state: Option<SymbolState>,
    /// Whether the user put the bar away (Not now, or a failure
    /// dismissed) until something new happens.
    dismissed: bool,
    /// The session in use has debug information (fetched, a peer's, given):
    /// nothing more to offer for this binary, whatever is told.
    debugged: bool,
}

impl SymbolsBar {
    /// Takes the session's new `state`; the file to decompile again with
    /// when it is fetched (none once the session in use has debug
    /// information).
    pub fn update(&mut self, state: SymbolState) -> Option<PathBuf> {
        if self.debugged {
            return None;
        }
        let fetched = match &state {
            SymbolState::Fetched { path, .. } => Some(path.clone()),
            SymbolState::Fetching { .. } => {
                // The user (or the setting) asked for it: shown again.
                self.dismissed = false;
                None
            }
            SymbolState::Failed { .. } => {
                self.dismissed = false;
                None
            }
            SymbolState::Available { .. } => None,
        };
        self.state = Some(state);
        fetched
    }

    /// What the bar shows: nothing once dismissed, fetched, or with
    /// nothing to offer.
    pub fn bar(&self) -> Option<Bar> {
        if self.dismissed || self.debugged {
            return None;
        }
        match self.state.clone()? {
            SymbolState::Available { binary, server } => Some(Bar::Offer { binary, server }),
            SymbolState::Fetching { binary, server } => Some(Bar::Downloading { binary, server }),
            SymbolState::Failed { binary, reason } => Some(Bar::Failed { binary, reason }),
            SymbolState::Fetched { .. } => None,
        }
    }

    /// Puts the bar away: Not now (until the binary is opened again), or a
    /// failure dismissed.
    pub fn dismiss(&mut self) {
        self.dismissed = true;
    }

    /// The session in use has debug information (however it came: a
    /// download, a peer's file, one given): the bar goes, and nothing told
    /// after (by the session it replaced, or a new analysis) brings it
    /// back for this binary.
    pub fn debugged(&mut self) {
        self.debugged = true;
        self.state = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn available() -> SymbolState {
        SymbolState::Available {
            binary: "python313.dll".to_owned(),
            server: "msdl.microsoft.com".to_owned(),
        }
    }

    fn fetching() -> SymbolState {
        SymbolState::Fetching {
            binary: "python313.dll".to_owned(),
            server: "msdl.microsoft.com".to_owned(),
        }
    }

    #[test]
    fn an_offer_reads_as_one_line_and_not_now_puts_it_away() {
        let mut bar = SymbolsBar::default();
        assert_eq!(bar.bar(), None);
        assert_eq!(bar.update(available()), None);
        assert_eq!(
            bar.bar().map(|bar| bar.text()).as_deref(),
            Some("Debug information for python313.dll is on msdl.microsoft.com.")
        );
        bar.dismiss();
        assert_eq!(bar.bar(), None);
        // Nothing new: still away.
        assert_eq!(bar.update(available()), None);
        assert_eq!(bar.bar(), None);
    }

    #[test]
    fn once_the_session_has_debug_information_the_bar_goes_for_good() {
        let mut bar = SymbolsBar::default();
        bar.update(available());
        assert!(matches!(bar.bar(), Some(Bar::Offer { .. })));
        // A peer's file taken (no download told): the offer goes.
        bar.debugged();
        assert_eq!(bar.bar(), None);
        // Told again (an analysis anew offering it, a fetch ending): it
        // stays away, and a fetched file is not taken a second time.
        assert_eq!(bar.update(available()), None);
        assert_eq!(bar.update(fetching()), None);
        assert_eq!(
            bar.update(SymbolState::Fetched {
                binary: "python313.dll".to_owned(),
                path: PathBuf::from("/cache/python313.pdb"),
                server: "msdl.microsoft.com".to_owned(),
            }),
            None
        );
        assert_eq!(bar.bar(), None);
    }

    #[test]
    fn a_download_shows_until_it_is_fetched_then_gives_its_file_once() {
        let mut bar = SymbolsBar::default();
        bar.update(available());
        bar.dismiss();
        // Always (the setting) after Not now: the download shows.
        bar.update(fetching());
        assert!(matches!(bar.bar(), Some(Bar::Downloading { .. })));
        let path = PathBuf::from("/cache/python313.pdb/X1/python313.pdb");
        assert_eq!(
            bar.update(SymbolState::Fetched {
                binary: "python313.dll".to_owned(),
                path: path.clone(),
                server: "msdl.microsoft.com".to_owned(),
            }),
            Some(path)
        );
        assert_eq!(bar.bar(), None);
    }

    #[test]
    fn a_failure_says_why_until_dismissed() {
        let mut bar = SymbolsBar::default();
        bar.update(fetching());
        bar.update(SymbolState::Failed {
            binary: "bash".to_owned(),
            reason: "not found on debuginfod.archlinux.org".to_owned(),
        });
        assert_eq!(
            bar.bar().map(|bar| bar.text()).as_deref(),
            Some(
                "Debug information for bash was not downloaded: not found on debuginfod.archlinux.org."
            )
        );
        bar.dismiss();
        assert_eq!(bar.bar(), None);
        // Tried again: the download shows.
        bar.update(fetching());
        assert!(matches!(bar.bar(), Some(Bar::Downloading { .. })));
    }
}
