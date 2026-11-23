//! binbun's symbol cache in the window (`binbun_gui_view::symbol_cache`):
//! Reveal Symbol Cache opens it in the file manager; Clear Symbol Cache
//! asks once, with the size it frees, then removes that directory alone;
//! the settings pane's Symbols group shows its path and size. Counting
//! and removing run off the UI thread.

use binbun_gui_view::commands::Command;
use binbun_gui_view::symbol_cache;
use binbun_paths::size_text;
use gpui_kit::prelude::*;
use gpui_kit::{AnyElement, ClickEvent, Context, MouseButton, Task, Window, div};

use crate::sidebar::tabular;
use crate::theme::hsla;
use crate::workspace::{ICON_BUTTON, Workspace};

/// The cache's state in the window.
#[derive(Default)]
pub struct SymbolCacheUi {
    /// Its size as last counted (`None`: not yet, or it changed since).
    pub size: Option<u64>,
    /// Clear was asked: the question shows once the count is in.
    asking: bool,
    /// The question is shown, with the size it frees.
    pub question: Option<u64>,
    /// The count running.
    count: Option<Task<()>>,
    /// The removal running.
    clearing: Option<Task<()>>,
}

impl Workspace {
    /// Runs the cache's `command`; whether it was one.
    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "the cache takes two of the registry's commands; `run` the rest"
    )]
    pub fn symbol_cache_command(
        &mut self,
        command: Command,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> bool {
        match command {
            Command::RevealSymbolCache => {
                // A cache nothing was downloaded to yet is shown empty.
                self.reveal(&symbol_cache::path(), cx);
            }
            Command::ClearSymbolCache => {
                self.close_overlays(window, cx);
                self.symbol_cache.asking = true;
                self.count_symbol_cache(window, cx);
            }
            _ => return false,
        }
        true
    }

    /// Counts the cache's size off the UI thread (anew: what the disk
    /// holds now), then shows the question if Clear was asked.
    pub fn count_symbol_cache(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if self.symbol_cache.clearing.is_some() {
            return;
        }
        let dir = symbol_cache::path();
        let counted = cx
            .background_executor()
            .spawn(async move { binbun_paths::size(&dir) });
        self.symbol_cache.count = Some(cx.spawn_in(window, async move |this, cx| {
            let size = counted.await;
            let _ = this.update_in(cx, |this, window, cx| {
                let ui = &mut this.symbol_cache;
                ui.count = None;
                ui.size = Some(size);
                if std::mem::take(&mut ui.asking) {
                    ui.question = Some(size);
                    window.focus(&this.overlay_focus, cx);
                }
                cx.notify();
            });
        }));
    }

    /// Enter on Clear's question: removes the cache; whether it was shown.
    pub fn answer_clear_question(&mut self, window: &mut Window, cx: &mut Context<Self>) -> bool {
        let shown = self.symbol_cache.question.is_some();
        if shown {
            self.clear_symbol_cache(window, cx);
        }
        shown
    }

    /// Clear, answered: removes the cache off the UI thread.
    fn clear_symbol_cache(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.close_overlays(window, cx);
        let dir = symbol_cache::path();
        let shown = dir.display().to_string();
        let removed = cx
            .background_executor()
            .spawn(async move { symbol_cache::clear(&dir) });
        self.symbol_cache.count = None;
        self.symbol_cache.clearing = Some(cx.spawn_in(window, async move |this, cx| {
            let result = removed.await;
            let _ = this.update_in(cx, |this, window, cx| {
                this.symbol_cache.clearing = None;
                if let Err(error) = result {
                    this.error = Some(format!("{shown}: {error}"));
                }
                // What is left, if anything could not be removed.
                this.count_symbol_cache(window, cx);
                cx.notify();
            });
        }));
    }

    /// The settings pane's line under its Symbols group: the cache's path
    /// and size, quiet (counted the first time it shows).
    pub fn symbol_cache_row(
        &mut self,
        height: f32,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        let ui = &self.symbol_cache;
        if ui.size.is_none() && ui.count.is_none() {
            self.count_symbol_cache(window, cx);
        }
        let muted = hsla(self.theme.text_muted);
        div()
            .flex()
            .items_center()
            .justify_between()
            .gap(self.z(16.0))
            .h(self.z(height))
            .px(self.z(8.0))
            .text_color(muted)
            .child(
                div()
                    .min_w_0()
                    .overflow_hidden()
                    .whitespace_nowrap()
                    .text_ellipsis()
                    .child(symbol_cache::path().display().to_string()),
            )
            .child(
                div()
                    .flex_none()
                    .font_features(tabular())
                    .child(self.symbol_cache.size.map(size_text).unwrap_or_default()),
            )
            .into_any_element()
    }

    /// Clear's question, if shown: the size it frees and the directory;
    /// Enter clears, Esc (or a click outside) does not.
    pub fn render_clear_question(&self, cx: &mut Context<Self>) -> Option<AnyElement> {
        let size = self.symbol_cache.question?;
        let theme = self.theme;
        let button = |id: &'static str, label: &'static str, default: bool| {
            div()
                .id(id)
                .flex()
                .items_center()
                .h(self.z(ICON_BUTTON))
                .px(self.z(10.0))
                .rounded(self.z(4.0))
                .text_color(hsla(theme.text))
                .when(default, |d| d.bg(hsla(theme.element_selected)))
                .hover(|s| s.bg(hsla(theme.element_hover)))
                .on_mouse_down(MouseButton::Left, |_, window, cx| {
                    window.prevent_default();
                    cx.stop_propagation();
                })
                .child(label)
        };
        Some(
            div()
                .id("clear-symbol-cache")
                .track_focus(&self.overlay_focus)
                .p(self.z(12.0))
                .flex()
                .flex_col()
                .gap(self.z(4.0))
                .child(format!("Clear the symbol cache ({})?", size_text(size)))
                .child(
                    div()
                        .text_color(hsla(theme.text_muted))
                        .overflow_hidden()
                        .whitespace_nowrap()
                        .text_ellipsis()
                        .child(symbol_cache::path().display().to_string()),
                )
                .child(
                    div()
                        .pt(self.z(8.0))
                        .flex()
                        .justify_end()
                        .gap(self.z(6.0))
                        .child(
                            button("clear-cancel", "Cancel", false).on_click(cx.listener(
                                |this, _: &ClickEvent, window, cx| {
                                    this.close_overlays(window, cx);
                                    cx.notify();
                                },
                            )),
                        )
                        .child(button("clear-confirm", "Clear", true).on_click(cx.listener(
                            |this, _: &ClickEvent, window, cx| {
                                this.clear_symbol_cache(window, cx);
                            },
                        ))),
                )
                .into_any_element(),
        )
    }
}
