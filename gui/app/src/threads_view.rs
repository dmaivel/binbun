//! Conversation in the window: the threads panel and the history panel in
//! the right dock,
//! a thread started on the cursor's line, the mentions' badge.
//!
//! - **Starting a thread** (Start Thread, `Ctrl+K C`, the code's context
//!   menu): on the cursor's line of the listing, the graph or the C,
//!   anchored as the engine anchors (a listing line by its instruction or
//!   data item, a C line by the first instruction it was made from), the
//!   line's text kept as its quote. The thread is made with its first post.
//! - **The threads panel** (`Ctrl+K D`): the function's threads or all,
//!   the suggestions waiting, detached threads by their quotes. A thread:
//!   where it is (a click goes there), its posts grouped by author as the
//!   chat groups messages, the reply box (Enter sends, Shift+Enter breaks
//!   the line; `@` offers the participants), each post's menu (Edit and
//!   Delete one's own; the owner's Remove on anyone's), Resolve and Reopen.
//! - **A suggestion's card**: who (an agent marked), what, why, how sure;
//!   each proposed edit with a checkbox, what its key shows now against
//!   the proposal and whether it moved since; the evidence (a click goes to
//!   what it cites), asked again as the card opens and marked where it no
//!   longer says what was quoted; Accept Selected (one undo step) and
//!   Dismiss with a reason. Viewers see it, the buttons off, why in their
//!   tooltips.
//! - **Unread**: the status bar's threads button's dot, the accent for
//!   new threads and replies in threads one is part of, red for a mention;
//!   a click opens the newest mention's thread, else the newest unread
//!   one. A thread's are seen once it shows in the panel.
//! - **The history panel** (`Ctrl+K H`): every change, newest first, by
//!   whom, and for an accepted suggestion who suggested it.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use binbun_gui_view::collab::{avatar_rgb, local_clock, local_full};
use binbun_gui_view::commands::{self, Command};
use binbun_gui_view::listing::{LineKind, Role as TokenRole};
use binbun_gui_view::session::Session;
use binbun_gui_view::talk::{
    AnchorShown, Chosen, EvidenceRow, Goes, Participant, PostGroup, PostText, ThreadsUnread,
    anchor_shown, complete, completions, edit_rows, evidence_rows, group_posts, history_line,
    may_decide, mention_at, mentions_in, quote_of, state_text,
};
use binbun_gui_view::{FunctionId, View};
use binbun_session::journal::{OpId, PublicKey};
use binbun_session::talk::{Anchor, Mentioned, Say, Suggestion, SuggestionState, Talked, Thread};
use binbun_session::{HistoryEntry, Located, Rechecked};
use gpui_kit::assets::IconName;
use gpui_kit::base::Textarea;
use gpui_kit::component::Disableable as _;
use gpui_kit::component::checkbox::Checkbox;
use gpui_kit::component::input::{Input, InputEvent, InputState, TextareaState};
use gpui_kit::component::tooltip::Tooltip;
use gpui_kit::prelude::*;
use gpui_kit::{
    AnyElement, App, ClickEvent, Context, Div, ElementId, Entity, Focusable, FontWeight, Hsla,
    Keystroke, MouseButton, MouseDownEvent, SharedString, Stateful, Subscription, Window, div, px,
};
use jiff::tz::TimeZone;

use crate::collab::avatar_color;
use crate::context_menu::OwnItem;
use crate::icons::icon;
use crate::start_page::unix_now;
use crate::theme::hsla;
use crate::workspace::{ICON, ICON_BUTTON, TOOLBAR_PAD, TabKind, Workspace};

/// The right dock's width while the threads or the history are in it.
pub const DOCK_WIDTH: f32 = 380.0;

/// The most history rows drawn (newest first).
const HISTORY_ROWS: usize = 400;

/// What the right dock shows of conversation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dock {
    /// The threads and suggestions.
    Threads,
    /// The history.
    History,
}

/// A thread being started: where, its quote, its title.
#[derive(Clone, Debug)]
pub struct Composing {
    /// What it is about.
    pub anchor: Anchor,
    /// The line's text.
    pub quote: String,
    /// Where, as its title says it.
    pub title: String,
}

/// The `@` completion open under a message box (the threads' reply box,
/// the chat's).
#[derive(Clone, Debug)]
pub(crate) struct Completion {
    /// The bytes of the mention being typed.
    range: std::ops::Range<usize>,
    /// Who it may mean.
    offered: Vec<Participant>,
    /// The one Enter or Tab takes.
    selected: usize,
}

impl Completion {
    /// The completion offered for the mention typed before byte `cursor`
    /// of `text`, among `people`, if any.
    pub(crate) fn offer(text: &str, cursor: usize, people: &[Participant]) -> Option<Self> {
        mention_at(text, cursor).and_then(|(range, query)| {
            let offered: Vec<Participant> =
                completions(people, &query).into_iter().cloned().collect();
            (!offered.is_empty()).then_some(Self {
                range,
                offered,
                selected: 0,
            })
        })
    }

    /// Key `key` (unmodified) while `completion` is open over `input`: Up
    /// and Down move, Enter and Tab write the one chosen in, Escape
    /// closes. Whether it took the key.
    pub(crate) fn key(
        completion: &mut Option<Self>,
        key: &str,
        input: &Entity<TextareaState>,
        window: &mut Window,
        cx: &mut App,
    ) -> bool {
        let Some(open) = completion else {
            return false;
        };
        let len = open.offered.len();
        match key {
            "up" => open.selected = (open.selected + len - 1) % len.max(1),
            "down" => open.selected = (open.selected + 1) % len.max(1),
            "escape" => *completion = None,
            "enter" | "tab" => {
                let Some(who) = open.offered.get(open.selected).cloned() else {
                    return false;
                };
                let range = open.range.clone();
                *completion = None;
                let text = input.read(cx).value().to_string();
                let (written, cursor) = complete(&text, range, &who);
                input.update(cx, |s, cx| {
                    s.set_value(written, window, cx);
                    s.set_selected_range(cursor..cursor, cx);
                });
            }
            _ => return false,
        }
        true
    }
}

/// The conversation's state of the window.
#[derive(Default)]
pub struct ThreadsUi {
    /// What the right dock shows of it, if anything.
    pub dock: Option<Dock>,
    /// Every thread, as of the last event.
    pub all: Vec<Thread>,
    /// The suggestions waiting, as of the last event.
    pub pending: Vec<Suggestion>,
    /// The history, newest first, as of the last event.
    pub history: Vec<HistoryEntry>,
    /// What is not seen of the threads (the threads button's dot).
    pub unread: ThreadsUnread,
    /// The thread open in the panel.
    pub open: Option<OpId>,
    /// The suggestion whose card is open.
    pub card: Option<OpId>,
    /// All threads, else the function's at the cursor.
    pub every: bool,
    /// A thread being started.
    pub composing: Option<Composing>,
    /// The reply box.
    reply: Option<Entity<TextareaState>>,
    /// A post being edited, and its box.
    editing: Option<(OpId, Entity<TextareaState>)>,
    /// The dismissal's reason, while asked.
    reason: Option<Entity<InputState>>,
    completion: Option<Completion>,
    /// Each card's evidence asked again, by suggestion.
    pub rechecked: HashMap<OpId, Arc<[Rechecked]>>,
    /// Each card's edits chosen.
    chosen: HashMap<OpId, Chosen>,
    subs: Vec<Subscription>,
    /// Why the last write was refused.
    pub error: Option<String>,
}

impl std::fmt::Debug for ThreadsUi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ThreadsUi")
            .field("dock", &self.dock)
            .field("open", &self.open)
            .field("card", &self.card)
            .finish_non_exhaustive()
    }
}

/// Where a click on an anchor goes, through the C of a function kept.
fn line_address(session: &Session, entry: u64, view: View, line: usize) -> Option<u64> {
    let id: FunctionId = session.database()?.function_at(entry)?;
    session
        .document(id, view)?
        .lines
        .get(line)?
        .addresses
        .first()
        .copied()
}

impl Workspace {
    // ---- the dock ----

    /// Whether the right dock shows `dock` (the Origin panel and the
    /// Pathfinder come first).
    pub fn talk_shown(&self, dock: Dock) -> bool {
        self.right_sidebar
            && self.threads.dock == Some(dock)
            && self.facts.origin.is_none()
            && !self.pathfinder_shown()
    }

    /// Opens `dock` in the right dock, or closes it if shown.
    fn toggle_talk(&mut self, dock: Dock) {
        if self.talk_shown(dock) {
            self.threads.dock = None;
            self.right_sidebar = false;
            return;
        }
        self.show_talk(dock);
    }

    /// Shows `dock` in the right dock (the Pathfinder closed).
    fn show_talk(&mut self, dock: Dock) {
        self.calls.pathfinder.open = false;
        self.threads.dock = Some(dock);
        self.right_sidebar = true;
        self.refresh_talk();
    }

    /// The conversation commands; whether `command` was one.
    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "three of the registry's commands; `run` the rest"
    )]
    pub fn talk_command(
        &mut self,
        command: Command,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> bool {
        match command {
            Command::Threads => self.toggle_talk(Dock::Threads),
            Command::History => self.toggle_talk(Dock::History),
            Command::StartThread => self.start_thread(window, cx),
            _ => return false,
        }
        cx.notify();
        true
    }

    /// The thread shown in the panel, if any.
    fn thread_shown(&self) -> Option<OpId> {
        self.talk_shown(Dock::Threads)
            .then_some(self.threads.open)
            .flatten()
    }

    /// The threads, suggestions and history taken again from the session.
    pub fn refresh_talk(&mut self) {
        self.take_talk(&[]);
    }

    /// Conversation came: taken again, what is new in `talked`'s threads
    /// unread.
    pub fn on_talked(&mut self, talked: &Talked) {
        self.take_talk(&talked.threads);
    }

    /// The threads, suggestions and history taken again from the session,
    /// `talked` the threads with something new.
    fn take_talk(&mut self, talked: &[OpId]) {
        let Some(session) = &self.session else {
            self.threads.all.clear();
            self.threads.pending.clear();
            self.threads.history.clear();
            self.threads.unread = ThreadsUnread::default();
            return;
        };
        self.threads.all = session.threads();
        self.threads.pending = session.pending_suggestions();
        let me = session.identity();
        if self.talk_shown(Dock::History) {
            self.threads.history = session.history();
        }
        let open = self.thread_shown();
        self.threads
            .unread
            .take(&self.threads.all, talked, me, open);
    }

    /// The history grew: kept if shown.
    pub fn talk_history(&mut self) {
        if self.talk_shown(Dock::History)
            && let Some(session) = &self.session
        {
            self.threads.history = session.history();
        }
    }

    /// A post mentions this person: unread until its thread shows (at
    /// once, if it is the one shown); said in the status bar.
    pub fn on_mentioned(&mut self, mentioned: &Mentioned) {
        let open = self.thread_shown();
        if self.threads.unread.mentioned(mentioned, open) {
            let who = self.talk_name(mentioned.by.key);
            self.collab.notice = Some((format!("{who} mentioned you"), Instant::now()));
        }
    }

    /// Whether the threads panel's reply or edit box has the focus.
    fn typing_talk(&self, window: &Window, cx: &Context<Self>) -> bool {
        let focused =
            |input: &Entity<TextareaState>| input.read(cx).focus_handle(cx).is_focused(window);
        self.threads.reply.as_ref().is_some_and(focused)
            || self
                .threads
                .editing
                .as_ref()
                .is_some_and(|(_, input)| focused(input))
    }

    /// Who `key` is, as the conversation names them: this person by the
    /// name they share as (else You), the others as the session does.
    pub fn talk_name(&self, key: PublicKey) -> String {
        let me = self.session.as_ref().map(Session::identity);
        if me == Some(key) {
            let name = self.collab.my_name();
            return if name.is_empty() { "You" } else { name }.to_owned();
        }
        self.person_name(key)
    }

    /// What an address is called: a function by its name, else where it
    /// is (`main+58`).
    pub fn place_name(&self, address: u64) -> String {
        let (Some(listing), Some(session)) = (&self.listing, &self.session) else {
            return format!("{address:X}");
        };
        let entry = listing.function_of(address).map(|(_, entry)| entry);
        if entry == Some(address)
            && let Some(name) = listing.shown_name(address, session.overlay())
        {
            return name.to_owned();
        }
        listing.describe(address)
    }

    /// Who can be mentioned: the others in the session, and every person,
    /// script or agent who wrote here (oneself as the person aside).
    fn participants(&self) -> Vec<Participant> {
        let me = self.session.as_ref().map(Session::identity);
        let mut out: Vec<Participant> = self
            .collab
            .people()
            .iter()
            .map(|person| Participant {
                key: person.key,
                agent: None,
                name: person.name.clone(),
            })
            .collect();
        let authors = self
            .threads
            .all
            .iter()
            .flat_map(|t| t.posts.iter().map(|p| &p.author))
            .chain(self.threads.pending.iter().map(|s| &s.author));
        for author in authors {
            let agent = author.agent();
            if Some(author.key) == me && agent.is_none() {
                continue;
            }
            let found = out.iter().any(|p| p.key == author.key && p.agent == agent);
            if !found {
                out.push(Participant {
                    key: author.key,
                    agent,
                    name: self.talk_name(author.key),
                });
            }
        }
        out
    }

    // ---- starting a thread ----

    /// Whether a thread can start on the focused pane's cursor line.
    pub fn threadable(&self) -> bool {
        self.thread_place().is_some()
    }

    /// The focused pane's cursor line as a thread's anchor, its quote and
    /// title: a listing's (or its graph's) item, a C line by its first
    /// instruction (a line made from none: the function).
    fn thread_place(&self) -> Option<Composing> {
        let id = self.layout.focused();
        let state = self.panes.get(&id)?;
        let session = self.session.as_ref()?;
        let listing = self.listing.as_ref()?;
        match self.layout.active(id)? {
            TabKind::Listing if !state.hex.on && !state.calls.on => {
                let n = if state.graph.on {
                    listing.line_of(self.cursor_address(id)?)
                } else {
                    state.listing.cursor
                };
                let line = listing.line(n)?;
                let address = line.address;
                // An item's line by its address; a header or label line at
                // a function's entry, the function.
                let entry = listing
                    .function_of(address)
                    .is_some_and(|(_, e)| e == address);
                let anchor = if line.kind == LineKind::Data {
                    Anchor::Data(address)
                } else if line.kind != LineKind::Instruction && entry {
                    Anchor::Function(address)
                } else {
                    Anchor::Instruction(address)
                };
                let db = session.database()?;
                let rendered = listing.render(db, n, session.overlay());
                let text: String = rendered
                    .tokens
                    .iter()
                    .filter(|t| t.role != TokenRole::Prefix)
                    .map(|t| t.text.as_str())
                    .collect();
                Some(Composing {
                    title: format!("{} \u{b7} {address:X}", self.place_name(address)),
                    quote: quote_of(&text),
                    anchor,
                })
            }
            kind @ TabKind::C { view, .. } if !state.ir.on => {
                let document = self.document(kind)?;
                let n = document.comment_owner(state.c.line);
                let line = document.lines.get(n)?;
                let anchor = match line.addresses.first() {
                    Some(&address) => Anchor::Line {
                        function: document.entry,
                        reading: *view == View::Reading,
                        address,
                    },
                    None => Anchor::Function(document.entry),
                };
                Some(Composing {
                    title: format!("{} \u{b7} line {}", self.place_name(document.entry), n + 1),
                    quote: quote_of(document.line_text(n)),
                    anchor,
                })
            }
            TabKind::Listing
            | TabKind::C { .. }
            | TabKind::Settings
            | TabKind::Strings
            | TabKind::Xrefs { .. }
            | TabKind::Struct(_)
            | TabKind::Found(_)
            | TabKind::Folder(_) => None,
        }
    }

    /// Start Thread: the panel open on a new thread at the cursor's line,
    /// its first post typed in the reply box.
    fn start_thread(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let Some(place) = self.thread_place() else {
            return;
        };
        self.show_talk(Dock::Threads);
        self.threads.open = None;
        self.threads.card = None;
        self.threads.composing = Some(place);
        self.focus_reply(window, cx);
    }

    /// Opens thread `id` in the panel: what is new in it seen, the reply box
    /// focused.
    pub fn open_thread(&mut self, id: OpId, window: &mut Window, cx: &mut Context<Self>) {
        self.show_talk(Dock::Threads);
        self.threads.open = Some(id);
        self.threads.card = None;
        self.threads.composing = None;
        self.threads.editing = None;
        self.threads.unread.seen(id);
        self.focus_reply(window, cx);
        cx.notify();
    }

    /// Opens suggestion `id`'s card: its evidence asked again.
    fn open_card(&mut self, id: OpId) {
        self.threads.card = Some(id);
        self.threads.open = None;
        self.threads.composing = None;
        self.threads.reason = None;
        if let Some(session) = &self.session {
            self.threads.rechecked.remove(&id);
            session.recheck(id);
        }
    }

    /// The reply box, made once, empty and focused.
    fn focus_reply(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let input = self.reply_box(window, cx);
        input.update(cx, |s, cx| {
            s.set_value("", window, cx);
            s.focus(window, cx);
        });
        self.threads.completion = None;
    }

    /// The reply box (Enter sends, Shift+Enter breaks the line, `@`
    /// completes a participant), made once with its key interception.
    fn reply_box(&mut self, window: &mut Window, cx: &mut Context<Self>) -> Entity<TextareaState> {
        if let Some(input) = &self.threads.reply {
            return input.clone();
        }
        let input = cx.new(|cx| {
            TextareaState::new(window, cx)
                .auto_grow(1, 8)
                .submit_on_enter(true)
                .placeholder("Reply")
        });
        let changes =
            cx.subscribe_in(
                &input,
                window,
                |this, input, e: &InputEvent, window, cx| match e {
                    InputEvent::Change => {
                        let (text, cursor) = {
                            let state = input.read(cx);
                            (state.value().to_string(), state.cursor())
                        };
                        this.typed_reply(&text, cursor);
                        cx.notify();
                    }
                    InputEvent::PressEnter { shift: true, .. }
                    | InputEvent::Focus
                    | InputEvent::Blur => {}
                    InputEvent::PressEnter { .. } => this.send_reply(window, cx),
                },
            );
        let this = cx.weak_entity();
        let handle = window.window_handle();
        let keys = cx.intercept_keystrokes(move |event, window, cx| {
            if window.window_handle() != handle {
                return;
            }
            let taken = this
                .update(cx, |this, cx| {
                    this.completion_key(&event.keystroke, window, cx)
                })
                .unwrap_or(false);
            if taken {
                cx.stop_propagation();
            }
        });
        self.threads.subs.push(changes);
        self.threads.subs.push(keys);
        self.threads.reply = Some(input.clone());
        input
    }

    /// The reply box reads `text`, its cursor at byte `cursor`: the `@`
    /// completion offered for the mention typed there, if any.
    fn typed_reply(&mut self, text: &str, cursor: usize) {
        self.threads.completion = Completion::offer(text, cursor, &self.participants());
    }

    /// A key while the `@` completion is open over the focused reply box:
    /// Up and Down move, Enter and Tab take, Escape closes. Whether it
    /// took the key.
    fn completion_key(
        &mut self,
        keystroke: &Keystroke,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> bool {
        if keystroke.modifiers.modified() || !self.typing_talk(window, cx) {
            return false;
        }
        let Some(input) = self.threads.reply.clone() else {
            return false;
        };
        let taken = Completion::key(
            &mut self.threads.completion,
            &keystroke.key,
            &input,
            window,
            cx,
        );
        if taken {
            cx.notify();
        }
        taken
    }

    /// Enter in the reply box: the thread being started made with this
    /// first post, or the post added to the thread open; the mentions it
    /// names taken.
    fn send_reply(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let Some(input) = self.threads.reply.clone() else {
            return;
        };
        let body = input.read(cx).value().trim().to_owned();
        if body.is_empty() {
            return;
        }
        let mentions = mentions_in(&body, &self.participants());
        let Some(session) = &self.session else {
            return;
        };
        let say = Say {
            body,
            mentions,
            ..Say::default()
        };
        let posted = match (self.threads.composing.take(), self.threads.open) {
            (Some(new), _) => session
                .open_thread(new.anchor, &new.quote)
                .and_then(|thread| session.post(thread, say).map(|_| thread)),
            (None, Some(thread)) => session.post(thread, say).map(|_| thread),
            (None, None) => return,
        };
        match posted {
            Ok(thread) => {
                self.threads.error = None;
                self.threads.open = Some(thread);
                input.update(cx, |s, cx| s.set_value("", window, cx));
                self.refresh_talk();
            }
            Err(why) => self.threads.error = Some(why),
        }
        cx.notify();
    }

    /// Edits post `post` in place: its box focused, Enter saves it,
    /// Escape leaves it.
    fn edit_post(&mut self, post: OpId, body: String, window: &mut Window, cx: &mut Context<Self>) {
        let input = cx.new(|cx| {
            TextareaState::new(window, cx)
                .auto_grow(1, 8)
                .submit_on_enter(true)
                .default_value(body)
        });
        let sub = cx.subscribe_in(
            &input,
            window,
            move |this, input, e: &InputEvent, _, cx| match e {
                InputEvent::PressEnter { shift: false, .. } => {
                    let body = input.read(cx).value().trim().to_owned();
                    let edited = this.session.as_ref().map(|s| s.edit_post(post, &body));
                    if let Some(Err(why)) = edited {
                        this.threads.error = Some(why);
                    }
                    this.threads.editing = None;
                    this.refresh_talk();
                    cx.notify();
                }
                InputEvent::Blur => {
                    this.threads.editing = None;
                    cx.notify();
                }
                InputEvent::PressEnter { .. } | InputEvent::Change | InputEvent::Focus => {}
            },
        );
        input.update(cx, |s, cx| s.focus(window, cx));
        self.threads.subs.push(sub);
        self.threads.editing = Some((post, input));
        cx.notify();
    }

    /// Deletes post `post` (one's own; anyone's as the owner).
    fn delete_post(&mut self, post: OpId) {
        if let Some(Err(why)) = self.session.as_ref().map(|s| s.delete_post(post)) {
            self.threads.error = Some(why);
        }
        self.refresh_talk();
    }

    /// A right click on a post: Edit and Delete one's own, the owner's
    /// Remove on another's.
    fn post_menu(
        &mut self,
        post: OpId,
        mine: bool,
        body: String,
        e: &MouseDownEvent,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let mut items = Vec::new();
        if mine {
            items.push(OwnItem::new("Edit", move |this, window, cx| {
                this.edit_post(post, body.clone(), window, cx);
            }));
            items.push(OwnItem::new("Delete", move |this, _, _| {
                this.delete_post(post);
            }));
        } else if self.collab.owner() {
            items.push(OwnItem::new("Remove", move |this, _, _| {
                this.delete_post(post);
            }));
        }
        if !items.is_empty() {
            self.open_own_menu(e.position, items, window, cx);
        }
    }

    /// Goes where `goes` says: an address, or a C line (its first
    /// instruction, the focused C pane on that line if it shows the
    /// function).
    fn talk_go(&mut self, goes: Goes, cx: &mut Context<Self>) {
        match goes {
            Goes::Address(address) => self.jump(address, cx),
            Goes::Line {
                function,
                view,
                line,
            } => {
                let address = self
                    .session
                    .as_ref()
                    .and_then(|s| line_address(s, function, view, line))
                    .unwrap_or(function);
                self.jump(address, cx);
                let id = self.layout.focused();
                let shows = self.layout.active(id).cloned().is_some_and(|kind| {
                    matches!(kind, TabKind::C { view: v, .. } if v == view)
                        && self.document(&kind).is_some_and(|d| d.entry == function)
                });
                if shows && let Some(state) = self.panes.get_mut(&id) {
                    state.c.line = line;
                    self.moved(id);
                }
            }
        }
        cx.notify();
    }

    // ---- drawing ----

    /// A muted line of the panel.
    fn quiet(&self, text: impl Into<SharedString>) -> Div {
        div()
            .text_color(hsla(self.theme.text_muted))
            .child(text.into())
    }

    /// A small button of the panel.
    fn talk_button(
        &self,
        id: impl Into<ElementId>,
        label: &str,
        strong: bool,
        enabled: bool,
    ) -> Stateful<Div> {
        let theme = self.theme;
        div()
            .id(id)
            .flex()
            .flex_none()
            .items_center()
            .h(self.z(ICON_BUTTON))
            .px(self.z(8.0))
            .rounded(self.z(4.0))
            .text_color(hsla(if enabled {
                theme.text
            } else {
                theme.text_placeholder
            }))
            .when(strong && enabled, |d| d.bg(hsla(theme.element_selected)))
            .when(enabled, |d| {
                d.hover(|s| s.bg(hsla(theme.element_hover)))
                    .cursor_pointer()
            })
            .child(label.to_owned())
    }

    /// A small tag (`agent`, `detached`, `stale`, `moved`) in `color`.
    fn tag(&self, text: &str, color: u32) -> Div {
        div()
            .flex_none()
            .px(self.z(4.0))
            .rounded(self.z(3.0))
            .border_1()
            .border_color(hsla(color))
            .text_color(hsla(color))
            .text_size(self.z(11.0))
            .line_height(self.z(15.0))
            .child(text.to_owned())
    }

    /// The user's time zone, and now in Unix milliseconds.
    fn talk_clock(&self) -> (TimeZone, u64) {
        let zone = self.collab.zone.clone().unwrap_or_else(TimeZone::system);
        (zone, unix_now().saturating_mul(1000))
    }

    /// An author's header: avatar, name (an agent marked), local time.
    fn author_header(
        &self,
        id: impl Into<ElementId>,
        key: PublicKey,
        agent: Option<&str>,
        time: u64,
    ) -> (Div, Div) {
        let theme = self.theme;
        let name = self.talk_name(key);
        let face = self.face(key, &name);
        let (zone, now) = self.talk_clock();
        let full = local_full(time, &zone);
        let header = div()
            .flex()
            .items_center()
            .gap(self.z(6.0))
            .min_w_0()
            .child(div().font_weight(FontWeight::BOLD).child(name))
            .children(agent.map(|agent| {
                div()
                    .flex()
                    .items_center()
                    .gap(self.z(3.0))
                    .child(icon(IconName::Bot, self.z(12.0), hsla(theme.text_muted)))
                    .child(self.tag(agent, theme.text_muted))
            }))
            .child(
                div()
                    .id(id)
                    .text_size(self.z(11.0))
                    .text_color(hsla(theme.text_muted))
                    .tooltip(move |window, cx| Tooltip::new(full.clone()).build(window, cx))
                    .child(local_clock(time, now, &zone)),
            );
        (self.avatar_circle(&face, 22.0).flex_none(), header)
    }

    /// The right dock's conversation panel, if it shows one.
    pub fn render_talk_dock(
        &mut self,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Option<AnyElement> {
        if self.talk_shown(Dock::History) {
            return Some(self.render_history(cx));
        }
        if !self.talk_shown(Dock::Threads) {
            return None;
        }
        let reply = self.reply_box(window, cx);
        Some(self.render_threads(&reply, cx))
    }

    /// The panel's header: its icon and title, `extra` (the scope), close.
    fn dock_header(
        &self,
        glyph: IconName,
        title: &str,
        extra: Option<Div>,
        cx: &mut Context<Self>,
    ) -> Div {
        let theme = self.theme;
        div()
            .flex()
            .flex_none()
            .items_center()
            .gap(self.z(6.0))
            .h(self.bar(TOOLBAR_PAD))
            .px(self.z(10.0))
            .border_b_1()
            .border_color(hsla(theme.border_variant))
            .child(icon(glyph, self.z(ICON), hsla(theme.text_muted)))
            .child(div().flex_1().child(title.to_owned()))
            .children(extra)
            .child(
                div()
                    .id("talk-close")
                    .flex()
                    .items_center()
                    .justify_center()
                    .size(self.z(ICON_BUTTON))
                    .rounded(self.z(4.0))
                    .hover(|s| s.bg(hsla(theme.element_hover)))
                    .on_click(cx.listener(|this, _, _, cx| {
                        this.threads.dock = None;
                        this.right_sidebar = false;
                        cx.notify();
                    }))
                    .child(icon(IconName::X, self.z(ICON), hsla(theme.text_muted))),
            )
    }

    /// The threads panel.
    fn render_threads(&self, reply: &Entity<TextareaState>, cx: &mut Context<Self>) -> AnyElement {
        let theme = self.theme;
        let scope = div()
            .flex()
            .gap(self.z(2.0))
            .child(
                self.talk_button("talk-scope-function", "Function", !self.threads.every, true)
                    .on_click(cx.listener(|this, _: &ClickEvent, _, cx| {
                        this.threads.every = false;
                        cx.notify();
                    })),
            )
            .child(
                self.talk_button("talk-scope-all", "All", self.threads.every, true)
                    .on_click(cx.listener(|this, _: &ClickEvent, _, cx| {
                        this.threads.every = true;
                        cx.notify();
                    })),
            );
        let listing = self.threads.open.is_none()
            && self.threads.card.is_none()
            && self.threads.composing.is_none();
        let header = self.dock_header(
            IconName::MessageSquareText,
            "Threads",
            listing.then_some(scope),
            cx,
        );
        let body = if let Some(new) = &self.threads.composing {
            self.render_composing(new, cx)
        } else if let Some(id) = self.threads.card {
            self.render_card(id, cx)
        } else if let Some(thread) = self
            .threads
            .open
            .and_then(|id| self.threads.all.iter().find(|t| t.id == id))
        {
            self.render_thread(thread, cx)
        } else {
            self.render_thread_list(cx)
        };
        let typing = self.threads.composing.is_some() || self.threads.open.is_some();
        let completion = self
            .threads
            .completion
            .as_ref()
            .filter(|_| typing)
            .map(|c| self.render_completion(c));
        let input = typing.then(|| {
            div().flex_none().p(self.z(8.0)).children(completion).child(
                div()
                    .px(self.z(8.0))
                    .py(self.z(4.0))
                    .rounded(self.z(6.0))
                    .bg(hsla(theme.editor))
                    .border_1()
                    .border_color(hsla(theme.border))
                    .child(Textarea::new(reply)),
            )
        });
        div()
            .id("threads")
            .size_full()
            .flex()
            .flex_col()
            .child(header)
            .child(
                div()
                    .id("threads-body")
                    .flex_1()
                    .min_h_0()
                    .overflow_y_scroll()
                    .p(self.z(10.0))
                    .child(body),
            )
            .children(self.threads.error.clone().map(|e| {
                div()
                    .px(self.z(10.0))
                    .text_color(hsla(theme.error))
                    .child(e)
            }))
            .children(input)
            .into_any_element()
    }

    /// The `@` completion: who it may mean, the one Enter takes lit.
    pub(crate) fn render_completion(&self, completion: &Completion) -> Div {
        let theme = self.theme;
        div()
            .mb(self.z(4.0))
            .p(self.z(4.0))
            .rounded(self.z(6.0))
            .bg(hsla(theme.panel))
            .border_1()
            .border_color(hsla(theme.border))
            .children(completion.offered.iter().enumerate().map(|(i, who)| {
                let face = self.face(who.key, &who.name);
                div()
                    .flex()
                    .items_center()
                    .gap(self.z(6.0))
                    .px(self.z(6.0))
                    .rounded(self.z(4.0))
                    .when(i == completion.selected, |d| {
                        d.bg(hsla(theme.element_selected))
                    })
                    .child(self.avatar_circle(&face, 16.0))
                    .child(who.name.clone())
                    .children(who.agent.as_deref().map(|a| self.tag(a, theme.text_muted)))
            }))
    }

    /// A thread being started: where, the line's text.
    fn render_composing(&self, new: &Composing, cx: &mut Context<Self>) -> AnyElement {
        let theme = self.theme;
        div()
            .flex()
            .flex_col()
            .gap(self.z(6.0))
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap(self.z(6.0))
                    .child(
                        div()
                            .id("composing-back")
                            .cursor_pointer()
                            .on_click(cx.listener(|this, _: &ClickEvent, _, cx| {
                                this.threads.composing = None;
                                cx.notify();
                            }))
                            .child(icon(
                                IconName::ChevronLeft,
                                self.z(ICON),
                                hsla(theme.text_muted),
                            )),
                    )
                    .child(
                        div()
                            .font_weight(FontWeight::SEMIBOLD)
                            .child(new.title.clone()),
                    ),
            )
            .child(self.code_quote(&new.quote))
            .into_any_element()
    }

    /// A line's text as a thread keeps it, in the code font.
    fn code_quote(&self, quote: &str) -> Div {
        let theme = self.theme;
        div()
            .px(self.z(6.0))
            .py(self.z(2.0))
            .rounded(self.z(4.0))
            .bg(hsla(theme.editor))
            .font_family(self.settings.code_font.clone())
            .text_color(hsla(theme.editor_foreground))
            .overflow_hidden()
            .whitespace_nowrap()
            .text_ellipsis()
            .child(quote.to_owned())
    }

    /// Where `thread` is now, as its title shows it.
    fn anchor_of(&self, thread: &Thread) -> AnchorShown {
        let located = self
            .session
            .as_ref()
            .map_or(Located::Detached, |s| s.locate(&thread.anchor));
        anchor_shown(thread, &located, &|address| self.place_name(address))
    }

    /// The panel's list: the suggestions waiting, the threads (the
    /// function's or all), the detached ones by their quotes.
    fn render_thread_list(&self, cx: &mut Context<Self>) -> AnyElement {
        let theme = self.theme;
        let entry = self
            .current_address()
            .and_then(|a| self.listing.as_ref()?.function_of(a))
            .map(|(_, entry)| entry);
        let scoped: Vec<Thread> = if self.threads.every {
            self.threads.all.clone()
        } else {
            entry
                .and_then(|e| self.session.as_ref().map(|s| s.threads_of(e)))
                .unwrap_or_default()
        };
        let shown: Vec<(Thread, AnchorShown)> = scoped
            .into_iter()
            .filter(|t| !matches!(t.anchor, Anchor::Suggestion(_)))
            .map(|t| {
                let anchor = self.anchor_of(&t);
                (t, anchor)
            })
            .collect();
        let (detached, attached): (Vec<_>, Vec<_>) =
            shown.into_iter().partition(|(_, a)| a.detached);
        let section = |title: &str| {
            div()
                .pt(self.z(6.0))
                .text_size(self.z(11.0))
                .font_weight(FontWeight::SEMIBOLD)
                .text_color(hsla(theme.text_muted))
                .child(title.to_owned())
        };
        let mut list = div().flex().flex_col().gap(self.z(4.0));
        if !self.threads.pending.is_empty() {
            list = list.child(section("Suggestions"));
            for (i, s) in self.threads.pending.iter().enumerate() {
                list = list.child(self.suggestion_row(i, s, cx));
            }
        }
        if !attached.is_empty() {
            list = list.child(section("Threads"));
            for (i, (t, a)) in attached.iter().enumerate() {
                list = list.child(self.thread_row(("thread-row", i), t, a, cx));
            }
        }
        if !detached.is_empty() {
            list = list.child(section("Detached"));
            for (i, (t, a)) in detached.iter().enumerate() {
                list = list.child(self.thread_row(("detached-row", i), t, a, cx));
            }
        }
        list.into_any_element()
    }

    /// A suggestion waiting, as the list shows it: who, what, how many
    /// edits; a click opens its card.
    fn suggestion_row(&self, i: usize, s: &Suggestion, cx: &mut Context<Self>) -> Stateful<Div> {
        let theme = self.theme;
        let id = s.id;
        let name = self.talk_name(s.author.key);
        let face = self.face(s.author.key, &name);
        let by = match s.author.agent() {
            Some(agent) => format!("{name} \u{b7} {agent}"),
            None => name,
        };
        div()
            .id(("suggestion-row", i))
            .flex()
            .items_center()
            .gap(self.z(8.0))
            .p(self.z(6.0))
            .rounded(self.z(4.0))
            .border_1()
            .border_color(hsla(theme.border))
            .hover(|d| d.bg(hsla(theme.element_hover)))
            .cursor_pointer()
            .on_click(cx.listener(move |this, _: &ClickEvent, _, cx| {
                this.open_card(id);
                cx.notify();
            }))
            .child(self.avatar_circle(&face, 20.0).flex_none())
            .child(
                div()
                    .flex()
                    .flex_col()
                    .min_w_0()
                    .child(
                        div()
                            .font_weight(FontWeight::SEMIBOLD)
                            .child(s.label.clone()),
                    )
                    .child(self.quiet(format!(
                        "{by} \u{b7} {} {}",
                        s.edits.len(),
                        if s.edits.len() == 1 { "edit" } else { "edits" }
                    ))),
            )
    }

    /// A thread as the list shows it: where, its first post, how many,
    /// resolved muted, unread mentions marked; a click opens it.
    fn thread_row(
        &self,
        id: impl Into<ElementId>,
        thread: &Thread,
        anchor: &AnchorShown,
        cx: &mut Context<Self>,
    ) -> Stateful<Div> {
        let theme = self.theme;
        let open = thread.id;
        let first = thread
            .posts
            .first()
            .map(|p| PostText::of(p).shown().to_owned())
            .unwrap_or_default();
        let count = thread.posts.len();
        let unread = self.threads.unread.has(thread.id);
        let ink = if thread.resolved {
            theme.text_placeholder
        } else {
            theme.text
        };
        div()
            .id(id)
            .flex()
            .flex_col()
            .gap(self.z(2.0))
            .p(self.z(6.0))
            .rounded(self.z(4.0))
            .hover(|d| d.bg(hsla(theme.element_hover)))
            .cursor_pointer()
            .on_click(cx.listener(move |this, _: &ClickEvent, window, cx| {
                this.open_thread(open, window, cx);
            }))
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap(self.z(6.0))
                    .when(unread, |d| {
                        d.child(
                            div()
                                .flex_none()
                                .size(self.z(7.0))
                                .rounded_full()
                                .bg(hsla(theme.accent)),
                        )
                    })
                    .child(
                        div()
                            .flex_1()
                            .min_w_0()
                            .overflow_hidden()
                            .whitespace_nowrap()
                            .text_ellipsis()
                            .text_color(hsla(ink))
                            .font_weight(FontWeight::SEMIBOLD)
                            .child(anchor.text.clone()),
                    )
                    .when(anchor.detached, |d| {
                        d.child(self.tag("detached", theme.text_muted))
                    })
                    .when(thread.resolved, |d| {
                        d.child(self.tag("resolved", theme.text_placeholder))
                    })
                    .child(self.quiet(count.to_string())),
            )
            .child(
                div()
                    .overflow_hidden()
                    .whitespace_nowrap()
                    .text_ellipsis()
                    .text_color(hsla(if thread.resolved {
                        theme.text_placeholder
                    } else {
                        theme.text_muted
                    }))
                    .child(first),
            )
    }

    /// A thread open: where (a click goes there), Resolve or Reopen, its
    /// posts grouped by author.
    fn render_thread(&self, thread: &Thread, cx: &mut Context<Self>) -> AnyElement {
        let theme = self.theme;
        let anchor = self.anchor_of(thread);
        let goes = anchor.goes;
        let id = thread.id;
        let resolved = thread.resolved;
        let me = self.session.as_ref().map(Session::identity);
        let groups = me
            .map(|me| group_posts(&thread.posts, me))
            .unwrap_or_default();
        let title = div()
            .flex()
            .items_center()
            .gap(self.z(6.0))
            .child(
                div()
                    .id("thread-back")
                    .cursor_pointer()
                    .on_click(cx.listener(|this, _: &ClickEvent, _, cx| {
                        this.threads.open = None;
                        this.threads.editing = None;
                        cx.notify();
                    }))
                    .child(icon(
                        IconName::ChevronLeft,
                        self.z(ICON),
                        hsla(theme.text_muted),
                    )),
            )
            .child(
                div()
                    .id("thread-anchor")
                    .flex_1()
                    .min_w_0()
                    .overflow_hidden()
                    .whitespace_nowrap()
                    .text_ellipsis()
                    .font_weight(FontWeight::SEMIBOLD)
                    .when(goes.is_some(), |d| {
                        d.cursor_pointer()
                            .hover(|s| s.text_color(hsla(theme.accent)))
                    })
                    .on_click(cx.listener(move |this, _: &ClickEvent, _, cx| {
                        if let Some(goes) = goes {
                            this.talk_go(goes, cx);
                        }
                    }))
                    .child(if anchor.detached {
                        "Detached".to_owned()
                    } else {
                        anchor.text.clone()
                    }),
            )
            .when(anchor.detached, |d| {
                d.child(self.tag("detached", theme.text_muted))
            })
            .child(
                self.talk_button(
                    "thread-resolve",
                    if resolved { "Reopen" } else { "Resolve" },
                    false,
                    true,
                )
                .on_click(cx.listener(move |this, _: &ClickEvent, _, cx| {
                    if let Some(Err(why)) = this
                        .session
                        .as_ref()
                        .map(|s| s.resolve_thread(id, !resolved))
                    {
                        this.threads.error = Some(why);
                    }
                    this.refresh_talk();
                    cx.notify();
                })),
            );
        div()
            .flex()
            .flex_col()
            .gap(self.z(10.0))
            .child(title)
            .child(self.code_quote(&thread.quote))
            .children(
                groups
                    .iter()
                    .enumerate()
                    .map(|(i, group)| self.render_group(i, group, thread, cx)),
            )
            .into_any_element()
    }

    /// An author's posts under their header; each post's menu on a right
    /// click; the one being edited as its box.
    fn render_group(
        &self,
        i: usize,
        group: &PostGroup,
        thread: &Thread,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        let theme = self.theme;
        let (face, header) = self.author_header(
            ("post-time", i),
            group.author,
            group.agent.as_deref(),
            group.time,
        );
        let owner = self.collab.owner();
        let posts = group.posts.iter().enumerate().map(|(j, line)| {
            if let Some((editing, input)) = &self.threads.editing
                && *editing == line.id
            {
                return div()
                    .px(self.z(6.0))
                    .rounded(self.z(4.0))
                    .bg(hsla(theme.editor))
                    .border_1()
                    .border_color(hsla(theme.border_focused))
                    .child(Textarea::new(input))
                    .into_any_element();
            }
            let post = line.id;
            let mine = line.mine;
            let gone = line.text.gone();
            let body = thread
                .posts
                .iter()
                .find(|p| p.id == post)
                .map(|p| p.body.clone())
                .unwrap_or_default();
            let menu = !gone && (mine || owner);
            div()
                .id(("post", i * 1000 + j))
                .flex()
                .flex_wrap()
                .gap(self.z(4.0))
                .when(gone, |d| d.italic().text_color(hsla(theme.text_muted)))
                .when(menu, |d| {
                    d.on_mouse_down(
                        MouseButton::Right,
                        cx.listener(move |this, e: &MouseDownEvent, window, cx| {
                            this.post_menu(post, mine, body.clone(), e, window, cx);
                        }),
                    )
                })
                .child(div().child(line.text.shown().to_owned()))
                .when(line.edited, |d| d.child(self.quiet("(edited)")))
                .when(line.evidence > 0, |d| {
                    d.child(self.tag(
                        &format!(
                            "{} {}",
                            line.evidence,
                            if line.evidence == 1 {
                                "item of evidence"
                            } else {
                                "items of evidence"
                            }
                        ),
                        theme.text_muted,
                    ))
                })
                .into_any_element()
        });
        div()
            .flex()
            .gap(self.z(8.0))
            .child(face)
            .child(
                div()
                    .flex()
                    .flex_col()
                    .flex_1()
                    .min_w_0()
                    .gap(self.z(2.0))
                    .child(header)
                    .children(posts),
            )
            .into_any_element()
    }

    /// Suggestion `id`'s card.
    fn render_card(&self, id: OpId, cx: &mut Context<Self>) -> AnyElement {
        let theme = self.theme;
        let Some(s) = self
            .session
            .as_ref()
            .and_then(|session| session.suggestion(id))
        else {
            return self.quiet("No such suggestion").into_any_element();
        };
        let (face, header) = self.author_header(
            "card-time",
            s.author.key,
            s.author.agent().as_deref(),
            s.time.millis(),
        );
        let decided = s.decided_by.as_ref().map(|a| self.talk_name(a.key));
        let state = state_text(&s, decided.as_deref());
        let back = div()
            .id("card-back")
            .cursor_pointer()
            .on_click(cx.listener(|this, _: &ClickEvent, _, cx| {
                this.threads.card = None;
                cx.notify();
            }))
            .child(icon(
                IconName::ChevronLeft,
                self.z(ICON),
                hsla(theme.text_muted),
            ));
        div()
            .flex()
            .flex_col()
            .gap(self.z(8.0))
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap(self.z(8.0))
                    .child(back)
                    .child(face)
                    .child(header),
            )
            .child(div().font_weight(FontWeight::BOLD).child(s.label.clone()))
            .children(state.map(|t| self.quiet(t)))
            .when(!s.rationale.is_empty(), |d| {
                d.child(div().child(s.rationale.clone()))
            })
            .child(self.render_edits(&s, cx))
            .child(self.render_evidence(&s, cx))
            .children((s.state == SuggestionState::Pending).then(|| self.render_decision(&s, cx)))
            .into_any_element()
    }

    /// A card's proposed edits: a checkbox each, what, now against
    /// proposed, moved since marked.
    fn render_edits(&self, s: &Suggestion, cx: &mut Context<Self>) -> Div {
        let theme = self.theme;
        let rows = edit_rows(s, &|key| self.engine_name(key));
        let chosen = self.threads.chosen.get(&s.id).cloned().unwrap_or_default();
        let pending = s.state == SuggestionState::Pending;
        let id = s.id;
        let this = cx.entity().downgrade();
        div()
            .flex()
            .flex_col()
            .gap(self.z(4.0))
            .children(rows.into_iter().map(|row| {
                let n = row.n;
                let this = this.clone();
                let address = row.address;
                div()
                    .flex()
                    .items_start()
                    .gap(self.z(6.0))
                    .p(self.z(6.0))
                    .rounded(self.z(4.0))
                    .border_1()
                    .border_color(hsla(theme.border))
                    .child(
                        Checkbox::new(("edit-chosen", n))
                            .checked(chosen.is_on(n))
                            .disabled(!pending)
                            .on_click(move |_, _, cx| {
                                let _ = this.update(cx, |this, cx| {
                                    this.threads.chosen.entry(id).or_default().toggle(n);
                                    cx.notify();
                                });
                            }),
                    )
                    .child(
                        div()
                            .flex()
                            .flex_col()
                            .flex_1()
                            .min_w_0()
                            .child(
                                div()
                                    .id(("edit-what", n))
                                    .flex()
                                    .items_center()
                                    .gap(self.z(6.0))
                                    .when(address.is_some(), |d| {
                                        d.cursor_pointer()
                                            .hover(|s| s.text_color(hsla(theme.accent)))
                                    })
                                    .on_click(cx.listener(move |this, _: &ClickEvent, _, cx| {
                                        if let Some(address) = address {
                                            this.talk_go(Goes::Address(address), cx);
                                        }
                                    }))
                                    .child(self.quiet(row.what.clone()))
                                    .when(row.moved, |d| {
                                        d.child(self.tag("moved since", theme.error))
                                    }),
                            )
                            .child(
                                div()
                                    .flex()
                                    .flex_wrap()
                                    .gap(self.z(6.0))
                                    .font_family(self.settings.code_font.clone())
                                    .when_some(row.now, |d, now| {
                                        d.child(
                                            div()
                                                .text_color(hsla(theme.text_muted))
                                                .line_through()
                                                .child(now),
                                        )
                                        .child(self.quiet("\u{2192}"))
                                    })
                                    .child(div().text_color(hsla(theme.text)).child(row.proposed)),
                            ),
                    )
            }))
    }

    /// A card's evidence: each item (a click goes to what it cites), its
    /// quote, stale ones marked with what they say now.
    fn render_evidence(&self, s: &Suggestion, cx: &mut Context<Self>) -> Div {
        let theme = self.theme;
        let rechecked = self.threads.rechecked.get(&s.id);
        let rows: Vec<EvidenceRow> =
            evidence_rows(&s.evidence, rechecked.map(AsRef::as_ref), &|a| {
                self.place_name(a)
            });
        let asking = rechecked.is_none() && !rows.is_empty();
        div()
            .flex()
            .flex_col()
            .gap(self.z(4.0))
            .when(!rows.is_empty(), |d| {
                d.child(
                    div()
                        .flex()
                        .items_center()
                        .gap(self.z(6.0))
                        .text_size(self.z(11.0))
                        .font_weight(FontWeight::SEMIBOLD)
                        .text_color(hsla(theme.text_muted))
                        .child("Evidence")
                        .when(asking, |d| {
                            d.child(icon(
                                IconName::LoaderCircle,
                                self.z(12.0),
                                hsla(theme.text_muted),
                            ))
                        }),
                )
            })
            .children(rows.into_iter().enumerate().map(|(i, row)| {
                let goes = row.goes;
                div()
                    .flex()
                    .flex_col()
                    .gap(self.z(2.0))
                    .child(
                        div()
                            .id(("evidence", i))
                            .flex()
                            .items_center()
                            .gap(self.z(6.0))
                            .when(goes.is_some(), |d| {
                                d.cursor_pointer()
                                    .hover(|s| s.text_color(hsla(theme.accent)))
                            })
                            .on_click(cx.listener(move |this, _: &ClickEvent, _, cx| {
                                if let Some(goes) = goes {
                                    this.talk_go(goes, cx);
                                }
                            }))
                            .child(div().child(row.what.clone()))
                            .when(row.stale.is_some(), |d| {
                                d.child(self.tag("stale", theme.error))
                            }),
                    )
                    .children(row.quote.clone().map(|q| self.code_quote(&q)))
                    .children(row.stale.map(|now| {
                        div()
                            .flex()
                            .gap(self.z(4.0))
                            .child(self.quiet("now"))
                            .child(self.code_quote(&now).flex_1().text_color(hsla(theme.error)))
                    }))
            }))
    }

    /// Accept Selected and Dismiss (its reason asked first); off with the
    /// reason in the tooltip for those who may not decide.
    fn render_decision(&self, s: &Suggestion, cx: &mut Context<Self>) -> Div {
        let theme = self.theme;
        let id = s.id;
        let chosen = self
            .threads
            .chosen
            .get(&id)
            .cloned()
            .unwrap_or_default()
            .chosen(s.edits.len());
        let allowed = may_decide(self.collab.role()).err();
        let none = chosen.is_empty().then_some("Choose at least one edit");
        let accept_why = allowed.or(none);
        let dismiss_why = allowed;
        let tip = |why: Option<&'static str>, b: Stateful<Div>| match why {
            Some(why) => b.tooltip(move |window, cx| Tooltip::new(why).build(window, cx)),
            None => b,
        };
        let accept = tip(
            accept_why,
            self.talk_button("card-accept", "Accept Selected", true, accept_why.is_none()),
        )
        .when(accept_why.is_none(), |d| {
            d.on_click(cx.listener(move |this, _: &ClickEvent, _, cx| {
                let done = this.session.as_mut().map(|s| s.accept(id, &chosen));
                match done {
                    Some(Err(why)) => this.threads.error = Some(why),
                    Some(Ok(())) => {
                        this.threads.error = None;
                        this.ensure_documents();
                    }
                    None => {}
                }
                this.refresh_talk();
                cx.notify();
            }))
        });
        let asking = self.threads.reason.clone();
        let dismiss = tip(
            dismiss_why,
            self.talk_button("card-dismiss", "Dismiss", false, dismiss_why.is_none()),
        )
        .when(dismiss_why.is_none(), |d| {
            d.on_click(cx.listener(move |this, _: &ClickEvent, window, cx| {
                this.dismiss_card(id, window, cx);
            }))
        });
        div()
            .flex()
            .flex_col()
            .gap(self.z(6.0))
            .children(asking.map(|input| {
                div()
                    .px(self.z(6.0))
                    .rounded(self.z(4.0))
                    .bg(hsla(theme.editor))
                    .border_1()
                    .border_color(hsla(theme.border))
                    .child(Input::new(&input).appearance(false))
            }))
            .child(
                div()
                    .flex()
                    .justify_end()
                    .gap(self.z(6.0))
                    .child(dismiss)
                    .child(accept),
            )
    }

    /// Dismiss: the reason asked first (Enter or a second Dismiss
    /// dismisses).
    fn dismiss_card(&mut self, id: OpId, window: &mut Window, cx: &mut Context<Self>) {
        if let Some(input) = self.threads.reason.take() {
            let reason = input.read(cx).value().trim().to_owned();
            if let Some(Err(why)) = self.session.as_ref().map(|s| s.dismiss(id, &reason)) {
                self.threads.error = Some(why);
            }
            self.refresh_talk();
            cx.notify();
            return;
        }
        let input = cx.new(|cx| InputState::new(window, cx).placeholder("Why"));
        let sub = cx.subscribe_in(
            &input,
            window,
            move |this, _, e: &InputEvent, window, cx| {
                if matches!(e, InputEvent::PressEnter { .. }) {
                    this.dismiss_card(id, window, cx);
                }
            },
        );
        input.update(cx, |s, cx| s.focus(window, cx));
        self.threads.subs.push(sub);
        self.threads.reason = Some(input);
        cx.notify();
    }

    /// The history panel: every change, newest first, by whom, and who
    /// suggested what was accepted.
    fn render_history(&self, cx: &mut Context<Self>) -> AnyElement {
        let theme = self.theme;
        let header = self.dock_header(IconName::FileClock, "History", None, cx);
        let (zone, now) = self.talk_clock();
        let rows = self
            .threads
            .history
            .iter()
            .take(HISTORY_ROWS)
            .enumerate()
            .map(|(i, entry)| {
                let line =
                    history_line(entry, &|key| self.talk_name(key), &|key| self.is_agent(key));
                let name = self.talk_name(entry.author);
                let face = self.face(entry.author, &name);
                let time = entry.time.millis();
                let full = local_full(time, &zone);
                div()
                    .flex()
                    .items_start()
                    .gap(self.z(8.0))
                    .py(self.z(3.0))
                    .child(self.avatar_circle(&face, 18.0).flex_none())
                    .child(
                        div()
                            .flex()
                            .flex_col()
                            .flex_1()
                            .min_w_0()
                            .child(
                                div()
                                    .flex()
                                    .items_center()
                                    .gap(self.z(6.0))
                                    .child(div().font_weight(FontWeight::SEMIBOLD).child(line.who))
                                    .child(
                                        div()
                                            .id(("history-time", i))
                                            .ml_auto()
                                            .text_size(self.z(11.0))
                                            .text_color(hsla(theme.text_muted))
                                            .tooltip(move |window, cx| {
                                                Tooltip::new(full.clone()).build(window, cx)
                                            })
                                            .child(local_clock(time, now, &zone)),
                                    ),
                            )
                            .child(div().child(line.what)),
                    )
            });
        div()
            .id("history")
            .size_full()
            .flex()
            .flex_col()
            .child(header)
            .child(
                div()
                    .id("history-body")
                    .flex_1()
                    .min_h_0()
                    .overflow_y_scroll()
                    .p(self.z(10.0))
                    .children(rows),
            )
            .into_any_element()
    }

    // ---- marks ----

    /// The gutter's mark of a line `threads` are about: a speech mark
    /// (muted when all are resolved, the accent when one has a mention not
    /// seen), their first posts in its tooltip; a click opens the first.
    pub fn thread_mark(
        &self,
        id: impl Into<ElementId>,
        threads: &[OpId],
        resolved: bool,
        (x, row_h): (f32, f32),
        cx: &mut Context<Self>,
    ) -> AnyElement {
        let theme = self.theme;
        let unread = threads.iter().any(|t| self.threads.unread.has(*t));
        let color = if unread {
            theme.accent
        } else if resolved {
            theme.text_placeholder
        } else {
            theme.hint
        };
        let tip: Vec<String> = threads
            .iter()
            .filter_map(|t| self.threads.all.iter().find(|thread| thread.id == *t))
            .map(|thread| {
                let first = thread.posts.first();
                let who = first
                    .map(|p| self.talk_name(p.author.key))
                    .unwrap_or_default();
                let text = first
                    .map(|p| PostText::of(p).shown().to_owned())
                    .unwrap_or_default();
                let text: String = text.chars().take(120).collect();
                let replies = thread.posts.len().saturating_sub(1);
                if replies == 0 {
                    format!("{who}: {text}")
                } else {
                    format!("{who}: {text} (+{replies})")
                }
            })
            .collect();
        let tip = tip.join("\n");
        let first = threads
            .iter()
            .find(|t| {
                self.threads
                    .all
                    .iter()
                    .any(|thread| thread.id == **t && !thread.resolved)
            })
            .or(threads.first())
            .copied();
        let size = (f32::from(self.z(11.0))).min(row_h - 2.0);
        div()
            .id(id)
            .absolute()
            .left(px(x))
            .top(px(((row_h - size) / 2.0).round()))
            .size(px(size))
            .cursor_pointer()
            .tooltip(move |window, cx| Tooltip::new(tip.clone()).build(window, cx))
            .on_mouse_down(MouseButton::Left, |_, window, cx| {
                window.prevent_default();
                cx.stop_propagation();
            })
            .on_click(cx.listener(move |this, _: &ClickEvent, window, cx| {
                if let Some(first) = first {
                    this.open_thread(first, window, cx);
                }
            }))
            .child(icon(IconName::MessageSquareText, px(size), hsla(color)))
            .into_any_element()
    }

    /// The status bar's threads button (left, beside the session), the
    /// threads' notification place: the dot as the chat icon's (the accent
    /// for new threads and replies unread, red for a mention unread). A
    /// click opens the newest mention's thread, else the newest unread
    /// one, else shows or hides the panel (as Ctrl+K D).
    pub fn threads_status(&self, cx: &mut Context<Self>) -> Option<AnyElement> {
        self.session.as_ref()?;
        let theme = self.theme;
        let on = self.talk_shown(Dock::Threads);
        let title = commands::lookup(Command::Threads).map_or("", |i| i.title);
        Some(
            div()
                .id("threads-toggle")
                .relative()
                .flex()
                .flex_none()
                .items_center()
                .justify_center()
                .size(self.z(ICON_BUTTON))
                .rounded(self.z(4.0))
                .when(on, |d| d.bg(hsla(theme.element_selected)))
                .hover(|s| s.bg(hsla(theme.element_hover)))
                .tooltip(self.key_tooltip(title, Command::Threads))
                .on_mouse_down(MouseButton::Left, |_, window, cx| {
                    window.prevent_default();
                    cx.stop_propagation();
                })
                .on_click(cx.listener(|this, _: &ClickEvent, window, cx| {
                    match this.threads.unread.newest() {
                        Some(thread) => this.open_thread(thread, window, cx),
                        None => this.run(Command::Threads, window, cx),
                    }
                }))
                .child(icon(
                    IconName::MessageSquareText,
                    self.z(ICON),
                    hsla(if on { theme.text } else { theme.text_muted }),
                ))
                .children(
                    self.threads
                        .unread
                        .dot()
                        .map(|dot| self.notification_dot(dot)),
                )
                .into_any_element(),
        )
    }

    /// The colour of `key`'s avatar on this theme.
    pub fn person_color(&self, key: PublicKey) -> Hsla {
        let name = self.talk_name(key);
        avatar_color(&self.collab.colours.avatar(key, &name), self.theme.dark)
    }

    /// The colour of `key`'s avatar on this theme, as `0xRRGGBBAA`.
    pub fn person_rgba(&self, key: PublicKey) -> u32 {
        let name = self.talk_name(key);
        let slot = self.collab.colours.avatar(key, &name).slot;
        (avatar_rgb(slot, self.theme.dark) << 8) | 0xff
    }
}
