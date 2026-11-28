//! The banners across the top of the workspace, one stack
//! (`binbun_gui_view::banners`): each one line, a notification's look,
//! dense, never blocking: an icon, the line, its buttons, a close
//! button where it can be put away; two at most, the rest behind a
//! "+N more" line that expands them. Its banners: the symbol server's
//! (`symbols_bar`), the settings file's problems, the first launch's
//! update question, the update offer (`binbun_gui_view::updates`) and
//! binbun's setup offered to a coding agent in a terminal (`terminal_view`),
//! and binbun's Python unable to run binbun (`python_setup`).
//!
//! Update checks run once agreed: every half second the window asks the
//! process's checks (shared by its windows) whether one is due (at
//! launch, then hourly); it is fetched off the UI thread, failures
//! silent, and every window draws the offer when it changes.

use std::f32::consts::TAU;
use std::time::Instant;

use binbun_gui_view::banners::{self, Action, Banner, Kind, Shown, Stack, Tone, more_text};
use binbun_gui_view::session::Session;
use binbun_gui_view::settings::Setting;
use binbun_gui_view::updates::{self, Updates};
use gpui_kit::assets::IconName;
use gpui_kit::prelude::*;
use gpui_kit::{
    AnyElement, ClickEvent, Context, Global, MouseButton, SharedString, Stateful, Transformation,
    Window, div, px, radians,
};

use crate::STARTED;
use crate::icons::icon;
use crate::theme::hsla;
use crate::workspace::{ICON, ICON_BUTTON, STATUS_PAD, TOOLBAR_PAD, Workspace};

/// The banners of one window.
#[derive(Debug, Default)]
pub struct BannerUi {
    /// What was put away, whether the overflow is expanded.
    stack: Stack,
    /// The process's update offer last drawn ([`Updates::generation`]).
    seen: u64,
}

/// The process's update checks, shared by its windows.
pub struct UpdateChecks(Updates);

impl Default for UpdateChecks {
    fn default() -> Self {
        Self(Updates::new(
            updates::build(),
            binbun_cli::update::url(),
            updates::skipped_path(),
        ))
    }
}

impl Global for UpdateChecks {}

impl Workspace {
    /// The banners offered now, in no order.
    fn offered_banners(&self, cx: &Context<Self>) -> Vec<Banner> {
        let mut offered = Vec::new();
        if let Some(bar) = self.session.as_ref().and_then(Session::symbols_bar) {
            offered.push(bar.banner());
        }
        if let Some(error) = &self.settings_error {
            offered.push(banners::settings_error(error));
        }
        offered.extend(self.analysis_banner());
        offered.extend(self.agent_banners());
        offered.extend(self.python_banner());
        let build = updates::build();
        if updates::asks(&build, self.settings.updates) {
            offered.push(updates::question());
        }
        if updates::checks(&build, self.settings.updates)
            && let Some(offer) = cx.try_global::<UpdateChecks>().and_then(|u| u.0.offer())
        {
            offered.push(updates::banner(&offer));
        }
        offered
    }

    /// The stack, when there is something to say.
    pub fn render_banners(
        &self,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Option<AnyElement> {
        let shown = self.banners.stack.arrange(self.offered_banners(cx));
        if shown.banners.is_empty() {
            return None;
        }
        let more = (shown.more > 0).then(|| self.banners_more(&shown, cx));
        let rows: Vec<AnyElement> = shown
            .banners
            .iter()
            .enumerate()
            .map(|(index, banner)| self.render_banner(index, banner, window, cx))
            .collect();
        Some(
            div()
                .id("banners")
                .flex()
                .flex_col()
                .flex_none()
                .children(rows)
                .children(more)
                .into_any_element(),
        )
    }

    /// One banner's line.
    fn render_banner(
        &self,
        index: usize,
        banner: &Banner,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        let theme = self.theme;
        let (glyph, color) = match (banner.tone, banner.kind) {
            (Tone::Info, Kind::Update) => (IconName::CircleArrowUp, theme.accent),
            (Tone::Info, Kind::Agent) => (IconName::Bot, theme.accent),
            (
                Tone::Info,
                Kind::Settings
                | Kind::UpdateQuestion
                | Kind::Symbols
                | Kind::Analysis
                | Kind::Python,
            ) => (IconName::Info, theme.text_muted),
            (Tone::Busy, _) => (IconName::LoaderCircle, theme.text_muted),
            (Tone::Warning, _) => (IconName::ShieldAlert, theme.error),
            (Tone::Error, _) => (IconName::CircleAlert, theme.error),
        };
        let mut glyph = icon(glyph, self.z(ICON), hsla(color));
        if banner.tone == Tone::Busy {
            window.request_animation_frame();
            let turn = STARTED.elapsed().as_secs_f32().fract();
            glyph = glyph.with_transformation(Transformation::rotate(radians(turn * TAU)));
        }
        let buttons: Vec<AnyElement> = banner
            .buttons
            .iter()
            .enumerate()
            .map(|(at, button)| {
                let action = button.action.clone();
                self.bar_field(format!("banner-{index}-{at}"))
                    .px(self.z(8.0))
                    .text_color(hsla(theme.text))
                    .on_click(cx.listener(move |this, _: &ClickEvent, window, cx| {
                        this.banner_action(&action, window, cx);
                    }))
                    .child(SharedString::from(button.label.clone()))
                    .into_any_element()
            })
            .collect();
        let close = banner.closable.then(|| {
            let closed = banner.clone();
            self.bar_field(format!("banner-{index}-close"))
                .justify_center()
                .w(self.z(ICON_BUTTON))
                .on_click(cx.listener(move |this, _: &ClickEvent, _, cx| {
                    this.close_banner(&closed);
                    cx.notify();
                }))
                .child(icon(IconName::X, self.z(ICON), hsla(theme.text_muted)))
                .into_any_element()
        });
        div()
            .id(SharedString::from(format!("banner-{index}")))
            .flex()
            .flex_none()
            .items_center()
            .gap(self.z(6.0))
            .h(self.bar(TOOLBAR_PAD))
            .pl(self.z(10.0))
            .pr(self.z(4.0))
            // Its items centred on the bar as drawn, its bottom line in it.
            .pt(px(1.0))
            .bg(hsla(theme.tab_bar))
            .border_b_1()
            .border_color(hsla(theme.border))
            .child(glyph)
            .child(
                div()
                    .flex_1()
                    .min_w_0()
                    .overflow_hidden()
                    .whitespace_nowrap()
                    .text_ellipsis()
                    .text_color(hsla(theme.text))
                    .child(banner.text.clone()),
            )
            .children(buttons)
            .children(close)
            .into_any_element()
    }

    /// The "+N more" line under the banners shown: expands the rest, or
    /// folds them again.
    fn banners_more(&self, shown: &Shown, cx: &mut Context<Self>) -> AnyElement {
        let theme = self.theme;
        let chevron = if shown.expanded {
            IconName::ChevronUp
        } else {
            IconName::ChevronDown
        };
        div()
            .id("banners-more")
            .flex()
            .flex_none()
            .items_center()
            .gap(self.z(6.0))
            .h(self.bar(STATUS_PAD))
            .pl(self.z(10.0))
            .pt(px(1.0))
            .bg(hsla(theme.tab_bar))
            .border_b_1()
            .border_color(hsla(theme.border))
            .text_color(hsla(theme.text_muted))
            .hover(|s| s.bg(hsla(theme.element_hover)))
            .on_mouse_down(MouseButton::Left, |_, window, cx| {
                window.prevent_default();
                cx.stop_propagation();
            })
            .on_click(cx.listener(|this, _: &ClickEvent, _, cx| {
                this.banners.stack.toggle();
                cx.notify();
            }))
            .child(icon(chevron, self.z(ICON), hsla(theme.text_muted)))
            .child(more_text(shown))
            .into_any_element()
    }

    /// A clickable field of a banner's height for buttons.
    fn bar_field(&self, id: String) -> Stateful<gpui_kit::Div> {
        let theme = self.theme;
        div()
            .id(SharedString::from(id))
            .flex()
            .flex_none()
            .items_center()
            .h(self.z(ICON_BUTTON))
            .rounded(self.z(4.0))
            .hover(|s| s.bg(hsla(theme.element_hover)))
            .on_mouse_down(MouseButton::Left, |_, window, cx| {
                window.prevent_default();
                cx.stop_propagation();
            })
    }

    /// A banner's button.
    fn banner_action(&mut self, action: &Action, window: &mut Window, cx: &mut Context<Self>) {
        match action {
            Action::Command(command) => self.run(*command, window, cx),
            Action::Open(url) => cx.open_url(url),
            Action::FetchDebug(from) => self.fetch_debug(*from, cx),
            Action::SetUpAgent(name) => self.set_up_agent(name, window, cx),
            Action::QuietAgent(name) => self.quiet_agent(name),
            Action::SetUpPython => self.set_up_python(window, cx),
            Action::SkipVersion => {
                if let Err(error) = cx.default_global::<UpdateChecks>().0.skip() {
                    self.error = Some(error);
                }
            }
            Action::CheckUpdates(yes) => {
                let answer = if *yes { "always" } else { "never" };
                self.set_setting(
                    "updates.check",
                    &Setting::Text(answer.to_owned()),
                    window,
                    cx,
                );
                self.check_updates(cx);
            }
        }
        cx.notify();
    }

    /// A banner's close button: the symbol server's bar as Not now does,
    /// the others for the session (until what they say changes).
    fn close_banner(&mut self, banner: &Banner) {
        match banner.kind {
            Kind::Symbols => {
                if let Some(session) = &mut self.session {
                    session.dismiss_symbols();
                }
            }
            Kind::Settings
            | Kind::UpdateQuestion
            | Kind::Update
            | Kind::Analysis
            | Kind::Agent
            | Kind::Python => {
                self.banners.stack.close(banner);
            }
        }
    }

    /// Every half second: the update check due, if agreed, fetched off the
    /// UI thread; drawn again when the process's offer changed.
    pub fn check_updates(&mut self, cx: &mut Context<Self>) {
        let setting = self.settings.updates;
        let checks = cx.default_global::<UpdateChecks>();
        if let Some(request) = checks.0.start(Instant::now(), setting) {
            let fetched = cx
                .background_executor()
                .spawn(async move { request.send() });
            cx.spawn(async move |_, cx| {
                let result = fetched.await;
                if let Err(error) = &result {
                    trace!("update check: {error}");
                }
                cx.update_global::<UpdateChecks, _>(|checks, _| checks.0.finish(result));
            })
            .detach();
        }
        let generation = cx.global::<UpdateChecks>().0.generation();
        if generation != self.banners.seen {
            self.banners.seen = generation;
            cx.notify();
        }
    }
}
