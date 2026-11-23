//! The bar about the open binary's debug information on a symbol server
//! (`symbols.download` = ask), a banner of the stack (`banners`; the
//! banner itself is `binbun_gui_view::symbols::Bar::banner`). Offered:
//! Download, Not now (until the binary is opened again), Always (sets the
//! setting); downloading: a spinner; failed: why, and a close button. A
//! download is taken by decompiling again (`binbun_gui_view::session`).
//! The offer's buttons are the registry's commands (Download Symbols, Not
//! Now, Always Download Symbols): the palette and keys run them too, while
//! the bar offers.

use binbun_gui_view::commands::Command;
use binbun_gui_view::settings::Setting;
use gpui_kit::{Context, Window};

use crate::workspace::Workspace;

impl Workspace {
    /// Runs the bar's `command`; whether it was one.
    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "the bar takes three of the registry's commands; `run` the rest"
    )]
    pub fn symbols_command(
        &mut self,
        command: Command,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> bool {
        match command {
            Command::DownloadSymbols => {
                if let Some(session) = &self.session {
                    session.fetch_symbols();
                }
            }
            Command::SymbolsNotNow => {
                if let Some(session) = &mut self.session {
                    session.dismiss_symbols();
                }
            }
            Command::AlwaysDownloadSymbols => {
                self.set_setting(
                    "symbols.download",
                    &Setting::Text("always".to_owned()),
                    window,
                    cx,
                );
                if let Some(session) = &self.session {
                    session.fetch_symbols();
                }
            }
            _ => return false,
        }
        cx.notify();
        true
    }
}
