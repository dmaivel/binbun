//! A shared session in the window: the Share and Join dialogs, the
//! approval card, the avatars in
//! the title bar (a click follows), the others' cursors in the listing and
//! the C, follow mode, and the session panel (people and their roles,
//! chat, conflicts, refused changes). The network side is `collab_net`
//! (the `collab` feature), or `collab_off`, which says it is not built.
//!
//! Follow mode: the leader's cursor, each time it moves, is where the
//! focused pane goes; the user's own move (a key, a click, the wheel)
//! stops it. `BINBUN_TRACE=1` traces each cursor sent and each landing for
//! a leader, with the wall clock, to measure the lag across windows.
//!
//! Files by hash: the Share dialog's checkboxes send the binary and
//! its debug file to those who join (off by default; on or off while
//! sharing too). Joining asks the host first: if it sends a binary this
//! window lacks, the Join dialog offers it (or a file of the same bytes
//! opened before, from the recent files), shows how far the fetch is, then
//! opens it here and joins with it. The analysis banner's "Get it from
//! …" fetches the debug file a peer analyses with and analyses again with
//! it, its progress in the banner.
//!
//! Members by card: File → Copy My Identity Card (and the Join dialog's
//! Copy identity card) copies one's card; the owner's Members row (the
//! Share dialog while sharing, the session's popover) lists the members
//! and adds one from their card, who can then join through any member
//! linked with an ordinary ticket.
//! Before sharing, the Share dialog lists the cards to add, each with its
//! role, added before the ticket is out, let in with nothing asked.
//! Others holding the ticket ask to join: each request has an approval
//! card of its own, all of them shown at once, each answer bound to its
//! request's id. The one switch, off by default, admits people admitted
//! before without asking.
//!
//! A share's project in the window (`collab-sync-v2.md` §4.5, §5.1,
//! §14.6): joined in a project directory of its own, titled with its
//! owner; no edits while joining; the session panel's Your Edits lists
//! the edits not yet shared and those not in this project (Copy, Bring);
//! File › Bring From Your Own Project… brings chosen values of the
//! binary's private project in. Stopping or leaving says what the flush
//! came to, in the status bar.
//!
//! Agents: an agent connected to this window (its harness through
//! `binbun mcp`, `serving`) is among the people whether shared or not:
//! its avatar in the title bar (its harness's mark), its cursor where its
//! code works, followed as anyone's. Sharing as the owner, each one
//! connected is added as a member with the agent's role, once; in a
//! session, the peer speaks for each one connected that is a member, so
//! the others see its avatar and cursor too, until it disconnects or is
//! removed. File › Connect an Agent… shows how each harness starts
//! `binbun mcp`.

use std::collections::{HashSet, VecDeque};
use std::fmt::Write as _;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::mpsc::{self, Receiver, Sender};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use binbun_gui_view::agents::{self, Agent, SetupRow, setup_rows};
use binbun_gui_view::banners::Banner;
use binbun_gui_view::chat::{self, Places};
use binbun_gui_view::collab::{
    Analysis, Approvals, Avatar, CardRefused, ChatItem, ChatLine, Colours, Cursor, Fetching,
    Follow, Known, Offered, Person, Place, Role, Trust, admits_unasked, analysis_banner,
    avatar_rgb, card_refused, card_text, change_text, conflict_text, fetch_text, fingerprint,
    key_text, link_text, remove_chat, shown_name, size_text, stop_text, trust_text, value_text,
};
use binbun_gui_view::commands::Command;
use binbun_gui_view::layout::PaneId;
use binbun_gui_view::listing::{Listing, Overlay};
use binbun_gui_view::projects::{SharedBy, project_title, share_of};
use binbun_gui_view::session::Session;
use binbun_gui_view::session::project;
use binbun_gui_view::sharing::{
    EditsOff, Flushed, Listed, LocalRow, bring_rows, bring_text, brought, copy_text, flush_text,
    listed_text, listing_text, local_rows, may_bring,
};
use binbun_gui_view::talk::{ChatUnread, Participant, mentions_in};
use binbun_gui_view::{Stage, View};
use binbun_protocol::messages::Member;
use binbun_session::identity::{self, Identity};
use binbun_session::journal::{Bringable, EngineVersion, LocalEdit, PublicKey};
use binbun_session::{Conflict, HistoryEntry};
use gpui_kit::component::input::{Input, InputEvent, InputState, Textarea, TextareaState};
use gpui_kit::component::switch::Switch;
use gpui_kit::component::tooltip::Tooltip;
use gpui_kit::component::{Disableable as _, Sizable as _};
use gpui_kit::prelude::*;
use gpui_kit::{
    AnyElement, Bounds, ClickEvent, ClipboardItem, Context, Div, ElementId, Entity, Focusable,
    FontWeight, Hsla, MouseButton, Pixels, ScrollAnchor, ScrollHandle, SharedString, Stateful,
    Subscription, Task, Window, black, canvas, div, fill, point, px, rgba, size, white,
};
use jiff::tz::TimeZone;

use crate::collab_net::{
    Asked, Decision, FLUSH, Mode, Net, NetEvent, Report, Sends, card_of, default_name, listable,
    my_card,
};
use crate::start_page::unix_now;
use crate::theme::hsla;
use crate::threads_view::Completion;
use crate::workspace::{ICON_BUTTON, TabKind, Workspace, titled_file, window_title};

#[path = "presence.rs"]
mod presence;

pub use presence::{TickStyle, c_column, caret_bar, caret_wash, selection_wash, token_column};

/// The session panel's width (logical).
const PANEL: f32 = 320.0;

/// The chat lines kept (as the peer keeps them).
const CHAT: usize = 100;

/// The share dialog's QR code's module (logical pixels).
const MODULE: f32 = 3.0;

/// The image a chat message's places are looked up in: the listing's
/// names and the user's, the addresses Go To finds.
struct Image<'a> {
    listing: &'a Listing,
    overlay: &'a Overlay,
}

impl Places for Image<'_> {
    fn named(&self, name: &str) -> Option<u64> {
        // `find` reads an address written out too: that is no name.
        let written = u64::from_str_radix(name.trim_start_matches("0x").trim_end_matches('h'), 16);
        self.listing
            .find(name, self.overlay)
            .filter(|&address| written != Ok(address))
    }

    fn mapped(&self, address: u64) -> bool {
        self.listing.find(&format!("{address:X}"), self.overlay) == Some(address)
    }
}

/// How long quitting waits for this peer's changes to reach those
/// linked.
const QUIT_FLUSH: Duration = Duration::from_secs(5);

/// An open dialog.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dialog {
    /// Share: the ticket and its QR code.
    Share,
    /// Join: a ticket pasted.
    Join,
    /// Connect an Agent: each harness's setup.
    Agents,
    /// Bring: values of the binary's private project chosen to bring into
    /// the share's.
    Bring,
}

/// What a Copy button copies.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Copied {
    /// The host's.
    Ticket,
    /// This user's identity card (the Join dialog's).
    Card,
}

impl Copied {
    /// Its button's id, and its label until it copies.
    fn button(self) -> (&'static str, &'static str) {
        match self {
            Self::Ticket => ("collab-copy", "Copy ticket"),
            Self::Card => ("collab-copy-card", "Copy identity card"),
        }
    }
}

/// What the session panel shows: the chat, or a list the status bar's
/// counters open.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tab {
    /// The session's chat.
    Chat,
    /// Concurrent edits left with two values.
    Conflicts,
    /// Changes refused, and why.
    Refused,
    /// This window's own edits in a share's project: those not yet
    /// shared, and those not in this project (refused, kept apart).
    Local,
}

/// The title bar's popover open.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Popover {
    /// Someone's card (their avatar clicked): Follow, the owner's say.
    Person(PublicKey),
    /// The session's (its button): the ticket, who is in, Stop sharing
    /// or Leave; `stopping` while Stop asks first (others are linked).
    Session { stopping: bool },
}

/// A join asked for: its ticket, the name and the way to reach the host.
#[derive(Clone, Debug)]
pub struct Joining {
    ticket: String,
    name: String,
    mode: Mode,
}

/// A member to add before sharing: their identity card, as listed, with
/// the role they get.
#[derive(Clone, Debug)]
struct Adding {
    /// The card as pasted.
    card: String,
    /// Its key.
    key: PublicKey,
    /// Its name.
    name: String,
    /// The role they get.
    role: Role,
}

/// The Bring dialog's values: a private project's, each chosen or not.
#[derive(Debug, Default)]
pub(crate) struct Bringing {
    /// The private project's values, and whether each is chosen.
    values: Vec<(Bringable, bool)>,
    /// This install's key (whose values are chosen at first).
    me: Option<PublicKey>,
    /// Still being read.
    reading: bool,
    /// Why they cannot be read, or why Bring failed.
    error: Option<String>,
}

/// A share's project's own edits, as last read from its journal.
#[derive(Debug, Default)]
pub(crate) struct LocalEdits {
    /// Not yet shared: pending, judged when a link is a reader's.
    pub(crate) pending: Vec<LocalEdit>,
    /// Not in this project: refused, or kept apart.
    pub(crate) apart: Vec<LocalEdit>,
}

/// A chat message gone to from the title bar's chat icon (the newest
/// mention of this person): scrolled to once drawn, washed in the accent
/// for a moment.
pub(crate) struct ChatJump {
    /// The message.
    pub(crate) id: u64,
    /// Its place in the chat's scroll.
    pub(crate) anchor: ScrollAnchor,
    /// Not scrolled to yet.
    pub(crate) pending: bool,
    /// Ends the wash.
    pub(crate) _timer: Task<()>,
}

/// The shared session as the window has it.
#[derive(Default)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "independent states of the session in the window"
)]
pub struct CollabUi {
    /// The network side, while sharing or joined.
    net: Option<Net>,
    /// Polls the network side whenever it signals.
    wake: Option<Task<()>>,
    /// Signals the window (threads computing the analysis fingerprint).
    signal: Option<async_channel::Sender<()>>,
    /// The open dialog.
    pub dialog: Option<Dialog>,
    /// The session panel's tab, if shown.
    pub panel: Option<Tab>,
    follow: Follow,
    /// The leader's move is being made (not the user's).
    following_move: bool,
    /// The joiner followed the host once (on join).
    followed_host: bool,
    people: Vec<Person>,
    /// The people in the order they came (the avatars' stack, newest
    /// last).
    pub(crate) order: Vec<PublicKey>,
    /// Who has which avatar colour: from the membership chain, alike on
    /// every peer.
    pub(crate) colours: Colours,
    /// The last frame's places showing the others' cursors.
    pub(crate) drawn: presence::Drawn,

    /// The title bar's popover open.
    pub(crate) popover: Option<Popover>,
    /// The popover last closed by a press outside it, and when (the press
    /// on its own button closes it, and its click must not open it again).
    pub(crate) dismissed: Option<(Popover, Instant)>,
    /// A line for the status bar (a peer's change, following), and when.
    pub(crate) notice: Option<(String, Instant)>,
    /// Draws the window again once the notice is to go.
    pub(crate) notice_timer: Option<Task<()>>,
    /// The user's time zone (the chat's times), read once.
    pub(crate) zone: Option<TimeZone>,
    pub(crate) chat: VecDeque<ChatItem>,
    /// The chat's scroll (the session panel's body while it shows the
    /// chat).
    pub(crate) chat_scroll: ScrollHandle,
    /// The message a click on the chat icon went to, while washed.
    pub(crate) chat_jump: Option<ChatJump>,
    /// What is not seen of the chat (the chat icon's dot).
    pub(crate) unread: ChatUnread,
    /// The chat messages the owner removed (one may come after its
    /// removal: shown removed).
    removed_chat: HashSet<u64>,
    /// Insert Location's texts in the message box and their places
    /// (linked whole on sending while they stay as inserted).
    placed: Vec<(String, u64)>,
    /// The `@` completion open over the message box.
    completion: Option<Completion>,
    /// The link the pointer is on: its message and its number.
    hovered: Option<(u64, usize)>,
    /// The requests to join waiting, by id, each with a card.
    asked: Approvals<(Asked, Trust)>,
    known: Option<Known>,
    /// Admit those admitted before without asking.
    admit_known: bool,
    /// The name this window shares or joins as.
    my_name: String,
    status: Option<String>,
    /// The Copy button that copied since the dialog or the session's
    /// popover opened: it says Copied until either opens again.
    copied: Option<Copied>,
    error: Option<String>,
    ticket: Option<String>,
    /// The ticket's QR code: its width and its dark modules, row by row.
    qr: Option<(usize, Vec<bool>)>,
    /// The shared project's members now, in the order admitted (the
    /// owner's Members row).
    members: Vec<(PublicKey, Role)>,
    /// The Members row's field: an identity card pasted.
    card_input: Option<Entity<InputState>>,
    /// Its Enter.
    card_sub: Option<Subscription>,
    /// Why the card pasted was not added.
    member_error: Option<String>,
    mode: Mode,
    /// This window's analysis, and where its computation reports.
    analysis: Option<Analysis>,
    analysed: Option<Receiver<Analysis>>,
    pub(crate) conflicts: Vec<Conflict>,
    /// The last cursor sent.
    sent: Option<Cursor>,
    name: Option<Entity<InputState>>,
    ticket_input: Option<Entity<InputState>>,
    chat_input: Option<Entity<TextareaState>>,
    subs: Vec<Subscription>,
    /// The message box's subscriptions (kept apart from the dialogs').
    chat_subs: Vec<Subscription>,
    /// What sharing sends to those who join.
    sends: Sends,
    /// The binary the host sends, which this window lacks (the Join
    /// dialog asks what to do).
    offered: Option<Offered>,
    /// A fetch under way.
    fetching: Option<Fetching>,
    /// The join asked for, while the host is visited.
    joining: Option<Joining>,
    /// The join to make once the binary fetched is open.
    pending: Option<Joining>,
    /// The agents connected to this window (`binbun mcp`): among the
    /// people, in a session or not.
    agents: Vec<Person>,
    /// The agents this install signs for (the session's), by key: their
    /// names.
    local_agents: Vec<(PublicKey, String)>,
    /// The agents this owner added as members in this session (once
    /// each).
    added_agents: HashSet<PublicKey>,
    /// The members to add before sharing (the Share dialog lists them).
    adding: Vec<Adding>,
    /// The next card added is a viewer's (else an editor's, the default).
    card_viewer: bool,
    /// Sharing a project anew: each chain of its history the share would
    /// list, and whether it is chosen (`None`: a share's project, which
    /// lists nothing anew).
    history: Option<Vec<(Listed, bool)>>,
    /// Where what a flush came to is told (the window shows it).
    flushes: Option<async_channel::Sender<String>>,
    /// Shows what each flush came to.
    flush_task: Option<Task<()>>,
    /// A share's project's own edits.
    pub(crate) local: LocalEdits,
    /// The Bring dialog's values.
    pub(crate) bringing: Bringing,
    /// The share's owner as last kept in its project (its title).
    shared_by: Option<SharedBy>,
    /// The Connect an Agent dialog's rows, each with its text's
    /// read-only field (selectable).
    setup: Vec<(SetupRow, Entity<TextareaState>)>,
    /// The Connect an Agent row whose Copy copied since it opened.
    setup_copied: Option<usize>,
    /// The window drawn again when a setup field grows to its wrapped
    /// text (laid out after the frame that showed it).
    setup_grown: Vec<Subscription>,
}

impl std::fmt::Debug for CollabUi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CollabUi")
            .field("live", &self.net.is_some())
            .field("dialog", &self.dialog)
            .field("panel", &self.panel)
            .finish_non_exhaustive()
    }
}

impl CollabUi {
    /// Whether the project is shared or joined.
    pub fn live(&self) -> bool {
        self.net.is_some()
    }

    /// Why this window is view-only in the session, if it is: its edits
    /// are off, since every peer would refuse them.
    pub fn read_only(&self) -> Option<String> {
        self.net.as_ref().and_then(Net::read_only)
    }

    /// Whether this window is joining a share: asking the host, getting
    /// or opening the binary, or joined before the share's journal is
    /// this project's. It takes no edits meanwhile.
    pub fn joining(&self) -> bool {
        self.pending.is_some() || self.net.as_ref().is_some_and(Net::joining)
    }

    /// This peer's role in the session, if in one.
    pub fn role(&self) -> Option<Role> {
        self.net.as_ref().and_then(Net::role)
    }

    /// Whether this peer owns the shared session (removes anyone's chat
    /// messages and posts).
    pub fn owner(&self) -> bool {
        self.role() == Some(Role::Owner)
    }

    /// The others in the session.
    pub fn people(&self) -> &[Person] {
        &self.people
    }

    /// The name this window shares or joins as.
    pub fn my_name(&self) -> &str {
        &self.my_name
    }

    /// Removes chat message `id` for everyone (the owner's).
    ///
    /// # Errors
    ///
    /// Not in a session; not the owner.
    pub fn remove_chat(&self, id: u64) -> Result<(), String> {
        self.net.as_ref().map_or_else(
            || Err("not in a session".to_owned()),
            |net| net.remove_chat(id),
        )
    }

    /// Stops the session (quitting): this peer's changes flushed to those
    /// linked, waiting 5 s at most.
    pub fn quit(&mut self) {
        if let Some(net) = self.net.take() {
            net.stop(QUIT_FLUSH, None);
        }
    }

    /// A session starts: the last one's chat (kept after it stopped, to be
    /// read) goes, so that this one's chat is its own.
    fn begin(&mut self) {
        self.chat.clear();
        self.chat_jump = None;
        self.unread = ChatUnread::default();
        self.removed_chat.clear();
    }

    /// Stops the session (`why`: it ended by itself), the flush going on
    /// behind so as not to block the window; what it came to is shown
    /// once done, if the peer was up.
    pub fn close(&mut self, why: Option<String>) {
        if let Some(net) = self.net.take() {
            let report = self.flush_report(&net);
            net.stop(Duration::ZERO, report);
        }
        self.wake = None;
        self.ticket = None;
        self.members.clear();
        self.member_error = None;
        self.qr = None;
        self.popover = None;
        // The agents connected stay.
        self.people.clone_from(&self.agents);
        self.added_agents.clear();
        self.colours = Colours::default();
        self.asked.clear();
        self.follow.stop();
        self.followed_host = false;
        self.known = None;
        self.sent = None;
        self.offered = None;
        self.fetching = None;
        self.joining = None;
        self.completion = None;
        self.shared_by = None;
        self.status.clone_from(&why);
        self.error = why;
    }

    /// What tells the window what the flush of `net` came to, each member
    /// by the name they had here: none if its peer was never up (a join
    /// still asking the host, or a share not started).
    fn flush_report(&self, net: &Net) -> Option<Report> {
        let told = self.flushes.clone()?;
        net.owner()?;
        let hosting = net.hosting();
        let names: Vec<(PublicKey, String)> = self
            .people
            .iter()
            .map(|person| (person.key, person.name.clone()))
            .collect();
        Some(Box::new(move |[held, waited, gone]| {
            let who = |keys: Vec<PublicKey>| -> Vec<String> {
                keys.into_iter()
                    .map(|key| {
                        names.iter().find(|(k, _)| *k == key).map_or_else(
                            || fingerprint(key).chars().take(9).collect(),
                            |(_, name)| shown_name(name),
                        )
                    })
                    .collect()
            };
            let flushed = Flushed {
                acknowledged: who(held),
                unacknowledged: who(waited),
                disconnected: who(gone),
            };
            let _ = told.try_send(flush_text(&flushed, hosting, FLUSH.as_secs()));
        }))
    }

    /// The binary closed: its agents are gone.
    pub fn forget_agents(&mut self) {
        self.agents.clear();
        self.local_agents.clear();
        self.people.retain(|person| person.agent.is_none());
    }

    /// Lists the member whose identity card is pasted as `text` to be
    /// added as `role` once sharing starts (before the ticket is out).
    ///
    /// # Errors
    ///
    /// Not an identity card, or not signed by its key; one's own; listed
    /// already.
    fn queue_member(&mut self, text: &str, role: Role) -> Result<(), String> {
        let (key, name) = card_of(text)?;
        let me = my_identity()?.public();
        let listed: Vec<(PublicKey, Role)> = self.adding.iter().map(|a| (a.key, a.role)).collect();
        match card_refused(key, me, &listed) {
            Some(CardRefused::Own) => return Err("Your own identity card".to_owned()),
            Some(CardRefused::Member) => {
                return Err(format!("{} is listed already", shown_name(&name)));
            }
            None => {}
        }
        let card = card_text(text).map_err(|not| not.text().to_owned())?;
        self.adding.push(Adding {
            card,
            key,
            name,
            role,
        });
        Ok(())
    }
}

/// The wall clock, in Unix milliseconds (traced to compare windows).
fn unix_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis())
}

/// `avatar`'s colour on a dark theme or a light one.
pub(crate) fn avatar_color(avatar: &Avatar, dark: bool) -> Hsla {
    rgba((avatar_rgb(avatar.slot, dark) << 8) | 0xff).into()
}

/// `n` as a float (a QR code's modules: a few hundred at most).
fn small(n: usize) -> f32 {
    f32::from(u16::try_from(n).unwrap_or(u16::MAX))
}

impl Workspace {
    /// The collaboration commands; whether `command` was one.
    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "the session takes five of the registry's commands; `run` the rest"
    )]
    pub fn collab_command(
        &mut self,
        command: Command,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> bool {
        match command {
            // In a session, Share shows it: the ticket, who is in, Stop.
            Command::ShareProject if self.collab.live() => {
                let session = Popover::Session { stopping: false };
                self.collab.popover = match self.collab.popover {
                    Some(Popover::Session { .. }) => None,
                    Some(Popover::Person(_)) | None if self.collab.just_dismissed(session) => None,
                    Some(Popover::Person(_)) | None => Some(session),
                };
                if self.collab.popover.is_some() {
                    self.collab.copied = None;
                    self.new_card_input(window, cx);
                }
            }
            Command::ShareProject => self.open_collab_dialog(Dialog::Share, window, cx),
            Command::JoinSession => self.open_collab_dialog(Dialog::Join, window, cx),
            Command::ConnectAgent => self.open_agents_dialog(window, cx),
            Command::CopyIdentityCard => {
                let name = if self.collab.my_name.is_empty() {
                    default_name()
                } else {
                    self.collab.my_name.clone()
                };
                match my_card(&name) {
                    Ok(card) => cx.write_to_clipboard(ClipboardItem::new_string(card)),
                    Err(why) => self.error = Some(why),
                }
            }
            Command::LeaveSession => self.leave_session(None, cx),
            Command::SessionPanel => {
                self.collab.panel = match self.collab.panel {
                    Some(_) => None,
                    None => Some(Tab::Chat),
                };
            }
            Command::InsertLocation => self.insert_location(window, cx),
            Command::Conflicts => self.collab.panel = Some(Tab::Conflicts),
            Command::BringValues => self.open_bring(window, cx),
            _ => return false,
        }
        cx.notify();
        true
    }

    /// Opens `dialog`, its fields focused.
    fn open_collab_dialog(&mut self, dialog: Dialog, window: &mut Window, cx: &mut Context<Self>) {
        self.close_overlays(window, cx);
        self.collab.error = None;
        let name = cx.new(|cx| {
            InputState::new(window, cx)
                .default_value(default_name())
                .placeholder("Your name, as others see it")
        });
        self.collab.subs.clear();
        let enter = cx.subscribe_in(&name, window, |this, _, e: &InputEvent, window, cx| {
            if matches!(e, InputEvent::PressEnter { .. }) {
                this.collab_confirm(window, cx);
            }
        });
        self.collab.subs.push(enter);
        if dialog == Dialog::Join {
            let ticket = cx.new(|cx| InputState::new(window, cx).placeholder("binbun…"));
            let pasted = cx.subscribe_in(
                &ticket,
                window,
                |this, input, e: &InputEvent, window, cx| {
                    match e {
                        InputEvent::PressEnter { .. } => this.collab_confirm(window, cx),
                        InputEvent::Change => {
                            // A ticket for the LAN only: joined so.
                            let text = input.read(cx).value().to_string();
                            if let Some(lan) = Net::lan_only(&text) {
                                this.collab.mode = if lan { Mode::Lan } else { Mode::Relay };
                            }
                            cx.notify();
                        }
                        InputEvent::Focus | InputEvent::Blur => {}
                    }
                },
            );
            self.collab.subs.push(pasted);
            ticket.update(cx, |s, cx| s.focus(window, cx));
            self.collab.ticket_input = Some(ticket);
        } else {
            self.new_card_input(window, cx);
            name.update(cx, |s, cx| {
                s.select_all(window, cx);
                s.focus(window, cx);
            });
        }
        self.collab.name = Some(name);
        self.collab.copied = None;
        if dialog == Dialog::Share && !self.collab.live() {
            let listed = self.session.as_ref().map(|s| listable(&s.core()));
            self.collab.history = match listed {
                Some(Ok(Some(chains))) => Some(
                    chains
                        .into_iter()
                        .map(|chain| {
                            let on = chain.chosen;
                            (chain, on)
                        })
                        .collect(),
                ),
                Some(Err(why)) => {
                    self.collab.error = Some(why);
                    None
                }
                Some(Ok(None)) | None => None,
            };
        }
        self.collab.dialog = Some(dialog);
        cx.notify();
    }

    /// Enter in a dialog: Start sharing, Join.
    fn collab_confirm(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        match self.collab.dialog {
            Some(Dialog::Share) if !self.collab.live() => self.start_sharing(window, cx),
            Some(Dialog::Join) => self.start_joining(window, cx),
            Some(Dialog::Share | Dialog::Agents) | None => {}
            Some(Dialog::Bring) => self.bring_chosen(cx),
        }
    }

    /// Opens Connect an Agent: each harness's setup for this binbun's
    /// command (`agents::setup_binbun`: the `binbun` on `PATH` that is
    /// it, else its own path), in read-only fields.
    fn open_agents_dialog(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.close_overlays(window, cx);
        let bin = std::env::current_exe().map_or_else(
            |_| PathBuf::from("binbun"),
            |exe| {
                agents::setup_binbun(
                    &agents::own_command(exe),
                    std::env::var_os("PATH").as_deref(),
                )
            },
        );
        self.collab.setup = setup_rows(&bin)
            .into_iter()
            .map(|row| {
                let text = row.text.clone();
                // As tall as the text wrapped to the field's width.
                let field = cx.new(|cx| {
                    TextareaState::new(window, cx)
                        .auto_grow(1, usize::MAX)
                        .default_value(text)
                });
                (row, field)
            })
            .collect();
        self.collab.setup_grown = self
            .collab
            .setup
            .iter()
            .map(|(_, field)| cx.observe(field, |_, _, cx| cx.notify()))
            .collect();
        self.collab.setup_copied = None;
        self.collab.dialog = Some(Dialog::Agents);
        cx.notify();
    }

    /// The Members row's field, empty, its Enter adding the card pasted.
    fn new_card_input(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let input = cx.new(|cx| InputState::new(window, cx).placeholder("binbunid…"));
        self.collab.card_sub =
            Some(
                cx.subscribe_in(&input, window, |this, _, e: &InputEvent, window, cx| {
                    if matches!(e, InputEvent::PressEnter { .. }) {
                        this.add_member(window, cx);
                    }
                }),
            );
        self.collab.card_input = Some(input);
        self.collab.member_error = None;
    }

    /// The Members row's Add: the member whose identity card is pasted
    /// added with the role chosen (an editor by default), kept as known
    /// under the card's name; before sharing, listed to be added before
    /// the ticket is out; else why not.
    fn add_member(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let Some(input) = self.collab.card_input.clone() else {
            return;
        };
        let text = input.read(cx).value().to_string();
        let role = if self.collab.card_viewer {
            Role::Viewer
        } else {
            Role::Editor
        };
        let Some(net) = &self.collab.net else {
            match self.collab.queue_member(&text, role) {
                Ok(()) => {
                    input.update(cx, |s, cx| s.set_value("", window, cx));
                    self.collab.member_error = None;
                }
                Err(why) => self.collab.member_error = Some(why),
            }
            cx.notify();
            return;
        };
        match net.add_card(&text, role) {
            Ok((key, name)) => {
                input.update(cx, |s, cx| s.set_value("", window, cx));
                self.collab.member_error = None;
                if self.collab.known.is_none() {
                    self.load_known();
                }
                if let Some(known) = &mut self.collab.known {
                    known.admit(key, &name, unix_now());
                    if let Err(why) = known.save() {
                        self.collab.member_error = Some(why);
                    }
                }
                self.refresh_people();
            }
            Err(why) => self.collab.member_error = Some(why),
        }
        cx.notify();
    }

    /// The name typed in the open dialog.
    fn typed_name(&self, cx: &Context<Self>) -> String {
        self.collab
            .name
            .as_ref()
            .map(|input| input.read(cx).value().trim().to_owned())
            .filter(|name| !name.is_empty())
            .unwrap_or_else(default_name)
    }

    /// A wake for the network side, polling it on the UI thread.
    fn collab_wake(
        &mut self,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Arc<dyn Fn() + Send + Sync> {
        if self.collab.flushes.is_none() {
            // What each flush on leaving came to, for as long as the
            // window lives (it comes after the session is closed).
            let (told, flushed) = async_channel::unbounded::<String>();
            self.collab.flushes = Some(told);
            self.collab.flush_task = Some(cx.spawn_in(window, async move |this, cx| {
                while let Ok(text) = flushed.recv().await {
                    let shown = this.update(cx, |this, cx| {
                        this.projects.notice = Some(text);
                        cx.notify();
                    });
                    if shown.is_err() {
                        break;
                    }
                }
            }));
        }
        let (tx, rx) = wake_channel();
        self.collab.signal = Some(tx.clone());
        self.collab.wake = Some(cx.spawn_in(window, async move |this, cx| {
            while rx.recv().await.is_ok() {
                while rx.try_recv().is_ok() {}
                if this.update_in(cx, Workspace::poll_collab).is_err() {
                    break;
                }
            }
        }));
        Arc::new(move || {
            let _ = tx.try_send(());
        })
    }

    /// Share's button: the project shared.
    fn start_sharing(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let Some(core) = self.session.as_ref().map(Session::core) else {
            return;
        };
        let name = self.typed_name(cx);
        let wake = self.collab_wake(window, cx);
        let members = self
            .collab
            .adding
            .iter()
            .map(|adding| (adding.card.clone(), adding.role))
            .collect();
        match Net::share(
            core,
            &name,
            self.collab.mode,
            &self.settings.collab_relay,
            self.collab.sends,
            members,
            self.collab.history.as_ref().map(|chains| {
                chains
                    .iter()
                    .filter(|(_, on)| *on)
                    .map(|(chain, _)| chain.chain)
                    .collect()
            }),
            wake,
        ) {
            Ok(net) => {
                self.collab.net = Some(net);
                self.collab.my_name = name;
                self.collab.status = Some("Starting…".to_owned());
                self.collab.error = None;
                // The last session's chat and what its stop came to are over.
                self.collab.begin();
                self.projects.notice = None;
                self.compute_analysis();
            }
            Err(error) => self.collab.error = Some(error),
        }
        cx.notify();
    }

    /// Join's button: the host asked to admit this window; the session
    /// joined with the binary open if it is the one shared, else the one
    /// the host sends offered ([`NetEvent::Offer`]).
    fn start_joining(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let ticket = self
            .collab
            .ticket_input
            .as_ref()
            .map(|input| input.read(cx).value().trim().to_owned())
            .unwrap_or_default();
        let name = self.typed_name(cx);
        self.join_with(
            Joining {
                ticket,
                name,
                mode: self.collab.mode,
            },
            window,
            cx,
        );
    }

    /// Joins as `joining` says, with the binary open if any.
    fn join_with(&mut self, joining: Joining, window: &mut Window, cx: &mut Context<Self>) {
        let core = self.session.as_ref().map(Session::core);
        let with_binary = core.is_some();
        let wake = self.collab_wake(window, cx);
        match Net::join(
            core,
            &joining.name,
            &joining.ticket,
            joining.mode,
            &self.settings.collab_relay,
            wake,
        ) {
            Ok(net) => {
                self.collab.net = Some(net);
                self.collab.my_name.clone_from(&joining.name);
                self.collab.mode = joining.mode;
                self.collab.joining = Some(joining);
                self.collab.status = Some("Asking the host…".to_owned());
                self.collab.error = None;
                // The last session's chat and what its stop came to are over.
                self.collab.begin();
                self.projects.notice = None;
                // With no binary, the dialog stays: what the host sends
                // comes there.
                if with_binary {
                    self.collab.dialog = None;
                    self.collab.panel = Some(Tab::Chat);
                    self.compute_analysis();
                    let id = self.layout.focused();
                    self.focus_pane(id, window, cx);
                }
            }
            Err(error) => self.collab.error = Some(error),
        }
        cx.notify();
    }

    /// The join left until the binary fetched was open, once its project
    /// is read.
    pub fn join_pending(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if self.collab.pending.is_none()
            || self
                .session
                .as_ref()
                .is_none_or(|session| session.core().project().is_none())
        {
            return;
        }
        if let Some(joining) = self.collab.pending.take() {
            self.join_with(joining, window, cx);
        }
    }

    /// The Join dialog's answer to the binary offered.
    fn decide_offer(&mut self, decision: Decision, cx: &mut Context<Self>) {
        if let Some(net) = &self.collab.net {
            net.decide(decision.clone());
        }
        self.collab.offered = None;
        self.collab.status = Some(match decision {
            Decision::Fetch => "Getting the binary…".to_owned(),
            Decision::Open(path) => format!("Opening {}…", path.display()),
            Decision::Cancel => "Not joined".to_owned(),
        });
        cx.notify();
    }

    /// The banner's "Get it from …": the debug file `from` analyses with,
    /// fetched, then analysed with.
    pub fn fetch_debug(&mut self, from: PublicKey, cx: &mut Context<Self>) {
        if let Some(net) = &self.collab.net {
            net.fetch_debug(from);
            self.collab.status = Some(format!(
                "Asking {} for their debug file…",
                shown_name(&self.person_name(from))
            ));
        }
        cx.notify();
    }

    /// Sends the binary (`debug`: the debug file) to those who join, or
    /// no longer: the Share dialog's switch, before sharing or while.
    fn set_send(&mut self, debug: bool, on: bool, cx: &mut Context<Self>) {
        if debug {
            self.collab.sends.debug = on;
        } else {
            self.collab.sends.binary = on;
        }
        if self.collab.ticket.is_some()
            && let Some(net) = &self.collab.net
        {
            net.send(debug, on);
        }
        cx.notify();
    }

    /// A file fetched: the binary opened here (its slice `arch`, in the
    /// project directory `project`: the share's) and joined with, or the
    /// debug file analysed with.
    fn on_fetched(
        &mut self,
        debug: bool,
        path: PathBuf,
        arch: Option<String>,
        project: Option<PathBuf>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.collab.fetching = None;
        let name = path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        if debug {
            if let Some(session) = &mut self.session {
                session.analyse_with_debug(path);
                self.collab.status = Some(format!("Analysing again with {name}"));
            }
            return;
        }
        let joining = self.collab.joining.take();
        self.open_as(path, arch, project, window, cx);
        self.collab.pending = joining;
        self.collab.status = Some(format!("Opened {name}: joining with it once it is read"));
    }

    /// Stops sharing or leaves (`why`: the session ended by itself).
    fn leave_session(&mut self, why: Option<String>, cx: &mut Context<Self>) {
        self.collab.close(why);
        // Its chat is gone, and with it what was unread there.
        self.collab.unread.seen();
        // The agents connected stay among the people.
        self.refresh_people();
        self.refresh_local();
        cx.notify();
    }

    /// This window's analysis fingerprint, computed off the UI thread
    /// once the functions are recovered, then told to the others.
    fn compute_analysis(&mut self) {
        let (Some(session), Some(signal)) = (self.session.as_ref(), self.collab.signal.clone())
        else {
            return;
        };
        let core = session.core();
        let (tx, rx): (Sender<Analysis>, Receiver<Analysis>) = mpsc::channel();
        self.collab.analysed = Some(rx);
        let _ = std::thread::Builder::new()
            .name("binbun-fingerprint".to_owned())
            .spawn(move || {
                core.wait(Stage::Analysed, None);
                if let Some(print) = core.fingerprint() {
                    let _ = tx.send(Analysis {
                        fingerprint: print.analysis,
                        debug: print.debug.map(|d| (d.name, d.sha256)),
                    });
                    let _ = signal.try_send(());
                }
            });
    }

    /// The binary analysed anew took the place of the one before: the
    /// peer goes on with it, and its fingerprint is told again.
    pub fn collab_reopened(&mut self) {
        if let (Some(net), Some(session)) = (&self.collab.net, &self.session) {
            net.set_session(session.core());
            self.compute_analysis();
        }
    }

    /// The session's history grew: a peer's change said in the status
    /// bar for a while ("Bob renamed v15 → fd").
    pub fn collab_history(&mut self, entries: &[HistoryEntry]) {
        self.refresh_local();
        if let Some(entry) = entries.iter().find(|entry| !entry.mine) {
            let who = self.person_name(entry.author);
            let edits = self
                .session
                .as_ref()
                .map(|s| s.core().edits_of(entry.id))
                .unwrap_or_default();
            let text = change_text(&who, &entry.label, &edits, &|key| self.engine_name(key));
            self.collab.notice = Some((text, Instant::now()));
        }
    }

    /// Takes the network side's events.
    pub fn poll_collab(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let analysed = if let Some(analysis) = self
            .collab
            .analysed
            .as_ref()
            .and_then(|rx| rx.try_iter().last())
        {
            if let Some(net) = &self.collab.net {
                net.announce(Some(&analysis));
            }
            self.collab.analysis = Some(analysis);
            true
        } else {
            false
        };
        let Some(net) = &self.collab.net else {
            return;
        };
        let events = net.poll();
        // What the others' cursors show now: a frame only if their moves
        // change it (or anything else came).
        let shown = self.presence_shown();
        let mut redraw = analysed;
        let mut people = false;
        let mut local = false;

        for event in events {
            redraw |= !matches!(event, NetEvent::Cursor(..));
            match event {
                NetEvent::Ticket(ticket) => {
                    self.on_ticket(ticket);
                    // The peer is up: the agents connected join as members.
                    people = true;
                }
                NetEvent::Asked(asked) => self.on_asked(asked),
                NetEvent::Withdrawn(id) => self.on_withdrawn(id),
                NetEvent::Said(line) => self.collab.status = Some(line),
                NetEvent::ViewOnly(why) => {
                    self.collab.status = Some(format!("View-only in this session: {why}"));
                }
                NetEvent::Ended(why) => {
                    self.leave_session(Some(why), cx);
                    return;
                }
                NetEvent::Failed(why) => self.collab.status = Some(format!("Failed: {why}")),
                NetEvent::Offer(offered) => {
                    self.collab.offered = Some(offered);
                    self.collab.dialog = Some(Dialog::Join);
                    self.collab.status = None;
                }
                NetEvent::Fetching(fetching) => self.collab.fetching = Some(fetching),
                NetEvent::Fetched {
                    debug,
                    path,
                    arch,
                    project,
                } => {
                    self.on_fetched(debug, path, arch, project, window, cx);
                    if !debug {
                        // The window's session is the one fetched now.
                        return;
                    }
                }
                NetEvent::FetchFailed(why) => {
                    self.collab.fetching = None;
                    self.collab.status = Some(format!("Not fetched: {why}"));
                }
                NetEvent::Took => {
                    if let Some(session) = &mut self.session {
                        session.took_remote();
                    }
                    local = true;
                }
                NetEvent::Refused | NetEvent::Members | NetEvent::People => people = true,
                NetEvent::Cursor(key, cursor) => redraw |= self.on_cursor(key, cursor),
                NetEvent::Chat(line) => self.take_chat(line),
                NetEvent::ChatRemoved(id) => {
                    self.collab.removed_chat.insert(id);
                    self.collab.unread.removed(id);
                    remove_chat(self.collab.chat.iter_mut(), id);
                }
            }
        }
        if people {
            self.refresh_people();
            self.note_owner(window);
        }
        if people || local {
            // Judged on linking, refused, or the role changed: what is
            // pending or kept apart.
            self.refresh_local();
        }
        self.drop_notice_later(cx);
        // The popovers say where each one is.
        if redraw || self.collab.popover.is_some() || self.presence_shown() != shown {
            cx.notify();
        }
    }

    /// `key`'s cursor moved to `cursor`: whether this window followed it.
    fn on_cursor(&mut self, key: PublicKey, cursor: Cursor) -> bool {
        trace!(
            "collab: heard {:#x} from {} at {} ms",
            cursor.address,
            shown_name(&self.person_name(key)),
            unix_ms()
        );
        if let Some(person) = self.collab.people.iter_mut().find(|p| p.key == key) {
            person.cursor = Some(cursor);
        }
        let to = self.collab.follow.moved(key, cursor);
        if let Some(to) = to {
            self.land_on(to);
        }
        to.is_some()
    }

    /// Sharing: the ticket made, its QR code; the members added before
    /// sharing kept as known under their cards' names.
    fn on_ticket(&mut self, ticket: String) {
        trace!("collab: sharing, the ticket made");
        self.collab.qr = qr(&ticket);
        self.collab.ticket = Some(ticket);
        self.collab.status = Some("Sharing: waiting for people to join".to_owned());
        self.load_known();
        let added = std::mem::take(&mut self.collab.adding);
        if let Some(known) = &mut self.collab.known
            && !added.is_empty()
        {
            for adding in &added {
                known.admit(adding.key, &adding.name, unix_now());
            }
            if let Err(why) = known.save() {
                self.collab.member_error = Some(why);
            }
        }
    }

    /// A chat message came: named as of now (the name it had when said;
    /// one's own under one's name, as the others see it), blank if the
    /// owner removed it before it came, unread while the chat is not
    /// shown (a mention of this person counted apart, and said in the
    /// status bar).
    fn take_chat(&mut self, mut line: ChatLine) {
        let me = self.collab.net.as_ref().map(Net::me);
        line.name = if me == Some(line.from) {
            self.collab.my_name.clone()
        } else {
            self.person_name(line.from)
        };
        line.removed = self.collab.removed_chat.contains(&line.id);
        let shown = self.collab.panel == Some(Tab::Chat);
        let mentions_me =
            !line.removed && me.is_some_and(|me| me != line.from && line.mentions.contains(&me));
        if me != Some(line.from) {
            self.collab.unread.chat(line.id, mentions_me, shown);
        }
        if mentions_me && !shown {
            self.collab.notice = Some((
                format!("{} mentioned you in the chat", shown_name(&line.name)),
                Instant::now(),
            ));
        }
        if line.removed {
            line.text.clear();
            line.links.clear();
            line.mentions.clear();
        }
        self.collab.say(ChatItem::Message(line));
    }

    /// The people as the peer has them now, and the agents connected here
    /// (in a session or not); a joiner follows the host once, when it
    /// first knows them. An owner adds the agents connected as members,
    /// and the peer speaks for those members; the server hears of
    /// everyone.
    fn refresh_people(&mut self) {
        let net = self.collab.net.as_ref();
        let mut people = net.map(Net::people).unwrap_or_default();
        let members = net.map(Net::members).unwrap_or_default();
        for agent in &self.collab.agents {
            if !people.iter().any(|p| p.key == agent.key) {
                let role = members.iter().find(|(k, _)| *k == agent.key).map(|m| m.1);
                people.push(Person {
                    role,
                    ..agent.clone()
                });
            }
        }
        if let Some(net) = net {
            self.collab.colours = Colours::of(&net.admitted());
        }
        let hosting = net.is_none_or(Net::hosting);
        let before = std::mem::replace(&mut self.collab.people, people);
        self.collab.members = members;
        self.note_comings_and_goings(&before);
        if self.collab.live() && self.collab.known.is_none() {
            self.load_known();
        }
        if !hosting && !self.collab.followed_host {
            // The joiner's one link is the host's.
            let host = self
                .collab
                .people
                .iter()
                .find(|p| p.path.is_some())
                .map(|p| (p.key, p.cursor));
            if let Some((key, cursor)) = host {
                self.collab.followed_host = true;
                self.follow_person(key, cursor);
            }
        }
        self.add_agents();
        self.host_agents();
        self.publish_people();
    }

    /// The agents connected here, as the server says them now: among the
    /// people, their code's place their cursor (a leader's followed).
    pub fn agents_changed(&mut self, cx: &mut Context<Self>) {
        let Some((_, ui, _)) = &self.served else {
            return;
        };
        let agents: Vec<Person> = ui
            .agents()
            .into_iter()
            .map(|here| Person {
                key: here.key,
                name: agents::shown_name(&here.name),
                engine: EngineVersion::this(),
                analysis: None,
                cursor: here.at.map(|address| Cursor {
                    place: Place::Listing,
                    address,
                    column: 0,
                    selection: None,
                }),
                following: None,
                role: None,
                path: None,
                view_only: None,
                agent: Some(Agent {
                    version: here.version,
                }),
            })
            .collect();
        let leader = self.collab.follow.leader();
        if leader.is_some_and(|leader| {
            self.collab.agents.iter().any(|a| a.key == leader)
                && !agents.iter().any(|a| a.key == leader)
        }) {
            self.unfollow();
        }
        for agent in &agents {
            if let Some(cursor) = agent.cursor
                && let Some(to) = self.collab.follow.moved(agent.key, cursor)
            {
                self.land_on(to);
            }
        }
        self.collab.agents = agents;
        self.remember_agents();
        self.refresh_people();
        self.drop_notice_later(cx);
        cx.notify();
    }

    /// Reads the agents this install signs for again (one connected
    /// first is new).
    pub fn remember_agents(&mut self) {
        self.collab.local_agents = self
            .session
            .as_ref()
            .map(Session::agents)
            .unwrap_or_default();
    }

    /// Whether `key` is an agent's: one this install signs for, one
    /// connected, a member of the agent's role.
    pub(crate) fn is_agent(&self, key: PublicKey) -> bool {
        self.collab.local_agents.iter().any(|(k, _)| *k == key)
            || self
                .collab
                .people
                .iter()
                .any(|p| p.key == key && p.agent.is_some())
            || self
                .collab
                .members
                .iter()
                .any(|&(k, role)| k == key && role == Role::Agent)
    }

    /// The avatar of `key` named `name`: an agent's with its face.
    pub(crate) fn face(&self, key: PublicKey, name: &str) -> Avatar {
        if self.is_agent(key) {
            self.collab.colours.agent_avatar(key, name)
        } else {
            self.collab.colours.avatar(key, name)
        }
    }

    /// The owner adds each agent connected here as a member, with the
    /// agent's role, once in a session (one removed stays removed).
    fn add_agents(&mut self) {
        let (Some(net), Some(session)) = (&self.collab.net, &self.session) else {
            return;
        };
        if net.role() != Some(Role::Owner) {
            return;
        }
        let mut added = Vec::new();
        for agent in &self.collab.agents {
            if self.collab.added_agents.contains(&agent.key)
                || self.collab.members.iter().any(|(k, _)| *k == agent.key)
            {
                continue;
            }
            let Some(identity) = session.agent_identity(agent.key) else {
                continue;
            };
            match net.add_agent(&identity, &agent.name) {
                Ok(()) => added.push((agent.key, agent.name.clone())),
                Err(why) => {
                    let (name, why) = (shown_name(&agent.name), shown_name(&why));
                    self.collab.status = Some(format!("{name} not added: {why}"));
                }
            }
            self.collab.added_agents.insert(agent.key);
        }
        if added.is_empty() {
            return;
        }
        if self.collab.known.is_none() {
            self.load_known();
        }
        if let Some(known) = &mut self.collab.known {
            for (key, name) in &added {
                known.admit(*key, name, unix_now());
            }
            if let Err(why) = known.save() {
                self.collab.member_error = Some(why);
            }
        }
    }

    /// The peer speaks for the agents connected here, as this window
    /// shows them (those members: the others see them).
    fn host_agents(&self) {
        let (Some(net), Some(session)) = (&self.collab.net, &self.session) else {
            return;
        };
        let agents: Vec<(Identity, Person)> = self
            .collab
            .agents
            .iter()
            .filter_map(|agent| Some((session.agent_identity(agent.key)?, agent.clone())))
            .collect();
        net.host_agents(&agents);
    }

    /// Tells the server the people as this window knows them
    /// (`session.members`): this user, and in a session every member
    /// of a person's or an agent's role, the agents among them.
    pub(crate) fn publish_people(&self) {
        let (Some((_, ui, _)), Some(session)) = (&self.served, &self.session) else {
            return;
        };
        let me = session.identity();
        let net = self.collab.net.as_ref();
        let name = if self.collab.my_name.is_empty() {
            default_name()
        } else {
            self.collab.my_name.clone()
        };
        let mut people = vec![Member {
            key: me.to_string(),
            name,
            kind: "person".to_owned(),
            role: net.and_then(Net::role).map(|role| role.name().to_owned()),
            online: true,
            you: true,
        }];
        for &(key, role) in &self.collab.members {
            if key == me || net.is_some_and(|net| net.me() == key) || role == Role::Store {
                continue;
            }
            let agent = role == Role::Agent || self.is_agent(key);
            people.push(Member {
                key: key.to_string(),
                name: self.person_name(key),
                kind: if agent { "agent" } else { "person" }.to_owned(),
                role: Some(role.name().to_owned()),
                online: self.collab.people.iter().any(|p| p.key == key),
                you: false,
            });
        }
        ui.set_people(people);
    }

    /// The known identities of the shared project, once its id is known.
    fn load_known(&mut self) {
        let (Some(net), Some(project)) = (
            &self.collab.net,
            self.session.as_ref().and_then(|s| s.project()),
        ) else {
            return;
        };
        if let Some(id) = net.project() {
            self.collab.known = Some(Known::load(Known::path_in(project.dir(), &id)));
        }
    }

    /// Someone asks to join: admitted at once if known and the host said
    /// so (never an impostor), else asked.
    fn on_asked(&mut self, asked: Asked) {
        if self.collab.known.is_none() {
            self.load_known();
        }
        let mut others: Vec<(PublicKey, String)> = self
            .collab
            .people
            .iter()
            .map(|p| (p.key, p.name.clone()))
            .collect();
        if let Some(net) = &self.collab.net {
            others.push((net.me(), self.collab.my_name.clone()));
        }
        let trust = self.collab.known.as_ref().map_or(Trust::New, |known| {
            known.judge(asked.key, &asked.name, &others)
        });
        if admits_unasked(&trust, self.collab.admit_known) {
            self.answer_asked(&asked, Some(Role::Editor));
            return;
        }
        self.collab.asked.push(asked.id, (asked, trust));
    }

    /// A request to join was withdrawn before it was answered (the asker
    /// gone, the invite forgotten): its card goes, the projects it
    /// brought with it.
    fn on_withdrawn(&mut self, id: u64) {
        if self.collab.asked.take(id).is_some() {
            self.collab.status =
                Some("A request to join was withdrawn before it was answered".to_owned());
        }
    }

    /// Answers `asked`: admitted as `role` (kept as known), or not.
    fn answer_asked(&mut self, asked: &Asked, role: Option<Role>) {
        if let Some(net) = &self.collab.net {
            net.answer(asked.id, role);
        }
        if role.is_some()
            && let Some(known) = &mut self.collab.known
        {
            known.admit(asked.key, &asked.name, unix_now());
            if let Err(error) = known.save() {
                self.collab.error = Some(error);
            }
        }
    }

    /// The approval card's buttons, drawn for request `id`: it answered,
    /// if it still waits; nothing else.
    fn decide(&mut self, id: u64, role: Option<Role>, window: &mut Window, cx: &mut Context<Self>) {
        if let Some((asked, _)) = self.collab.asked.take(id) {
            self.answer_asked(&asked, role);
        }
        if self.collab.asked.is_empty() {
            let id = self.layout.focused();
            self.focus_pane(id, window, cx);
        }
        cx.notify();
    }

    /// What `key` is called: "You", their name, an agent's this install
    /// signs for (`Codex`), a known name, else their fingerprint's start.
    pub fn person_name(&self, key: PublicKey) -> String {
        if self.collab.net.as_ref().is_some_and(|net| net.me() == key) {
            return "You".to_owned();
        }
        if let Some(person) = self.collab.people.iter().find(|p| p.key == key) {
            return person.name.clone();
        }
        if let Some((_, name)) = self.collab.local_agents.iter().find(|(k, _)| *k == key) {
            return agents::shown_name(name);
        }
        if let Some(name) = self
            .collab
            .known
            .as_ref()
            .and_then(|known| known.people().get(&key))
            .and_then(|person| person.names.last())
        {
            return name.clone();
        }
        fingerprint(key).chars().take(9).collect()
    }

    // ---- presence and follow mode ----

    /// Where pane `id`'s cursor is, as presence says it.
    fn presence_cursor(&self, id: PaneId) -> Option<Cursor> {
        let address = self.cursor_address(id)?;
        let state = self.panes.get(&id)?;
        let mut column = 0;
        let place = match self.layout.active(id)? {
            TabKind::Listing if state.hex.on => Place::Hex,
            TabKind::Listing if state.graph.on => Place::Graph {
                function: self.listing.as_ref()?.function_of(address)?.1,
            },
            TabKind::Listing => {
                column = self.listing_column(state.listing.cursor, state.listing.token);
                Place::Listing
            }
            kind @ TabKind::C { view, .. } => {
                let document = self.document(kind)?;
                column = c_column(document, state.c.line, state.c.span);
                Place::C {
                    function: document.entry,
                    reading: *view == View::Reading,
                    line: u32::try_from(state.c.line).unwrap_or(u32::MAX),
                }
            }
            TabKind::Xrefs { .. } => Place::Xrefs,
            TabKind::Settings
            | TabKind::Console
            | TabKind::Strings
            | TabKind::Struct(_)
            | TabKind::Found(_)
            | TabKind::Folder(_) => {
                return None;
            }
        };
        Some(Cursor {
            place,
            address,
            column,
            selection: self.presence_selection(id),
        })
    }

    /// Pane `id`'s cursor moved: told to the others if it is the focused
    /// pane's; a move of the user's own stops following (an agent's too,
    /// out of a session).
    pub fn collab_moved(&mut self, id: PaneId) {
        if id != self.layout.focused() {
            return;
        }
        if !self.collab.following_move {
            self.unfollow();
        }
        self.collab_publish();
    }

    /// Tells the others where the focused pane's cursor is, if it moved
    /// since it was last told (its line, or only its token: each frame
    /// looks).
    pub fn collab_publish(&mut self) {
        if self.collab.net.is_none() {
            return;
        }
        let Some(cursor) = self.presence_cursor(self.layout.focused()) else {
            return;
        };
        if self.collab.sent == Some(cursor) {
            return;
        }
        self.collab.sent = Some(cursor);
        trace!(
            "collab: sent {:#x} {:?} at {} ms",
            cursor.address,
            cursor.place,
            unix_ms()
        );
        if let Some(net) = &self.collab.net {
            net.set_cursor(cursor);
        }
    }

    /// The user scrolled, typed or clicked: following stops.
    pub fn unfollow(&mut self) {
        if self.collab.following_move {
            return;
        }
        if let Some(leader) = self.collab.follow.stop() {
            trace!("collab: stopped following at {} ms", unix_ms());
            let said = format!(
                "Stopped following {}",
                shown_name(&self.person_name(leader))
            );
            self.collab.notice = Some((said, Instant::now()));
            if let Some(net) = &self.collab.net {
                net.follow(None);
            }
        }
    }

    /// Follows `key` (their cursor now, if known), or stops if already.
    fn follow_person(&mut self, key: PublicKey, cursor: Option<Cursor>) {
        if self.collab.follow.leader() == Some(key) {
            self.unfollow();
            return;
        }
        let to = self.collab.follow.start(key, cursor);
        let name = shown_name(&self.person_name(key));
        trace!("collab: following {name} at {} ms", unix_ms());
        self.collab.notice = Some((format!("Following {name}"), Instant::now()));
        if let Some(net) = &self.collab.net {
            net.follow(Some(key));
        }
        if let Some(to) = to {
            self.land_on(to);
        }
    }

    /// Goes where the leader's cursor is, in the linked panes (a pane on
    /// its own, a reference, is never moved; the focus stays where it is):
    /// their C line if the pane shows the same function in the same view,
    /// else their address (through provenance).
    fn land_on(&mut self, cursor: Cursor) {
        self.collab.following_move = true;
        let focused = self.layout.focused();
        let id = self.linked_code_pane(focused);
        self.layout.focus(id);
        self.go(cursor.address, None);
        let kind = self.layout.active(id).cloned();
        if let (
            Place::C {
                function,
                reading,
                line,
            },
            Some(kind @ TabKind::C { view, .. }),
        ) = (cursor.place, &kind)
            && (*view == View::Reading) == reading
            && self.document(kind).is_some_and(|d| d.entry == function)
            && let Some(state) = self.panes.get_mut(&id)
        {
            state.c.line = usize::try_from(line).unwrap_or(state.c.line);
            self.moved(id);
        }
        self.layout.focus(focused);
        self.collab.following_move = false;
        trace!("collab: followed {:#x} at {} ms", cursor.address, unix_ms());
    }

    /// How far `person` is trusted, among those known.
    pub(crate) fn trust_of(&self, person: &Person) -> Trust {
        let others: Vec<(PublicKey, String)> = self
            .collab
            .people
            .iter()
            .map(|p| (p.key, p.name.clone()))
            .collect();
        self.collab.known.as_ref().map_or(Trust::New, |known| {
            known.judge(person.key, &person.name, &others)
        })
    }

    /// The banner of an analysis that differs from a peer's.
    pub fn analysis_banner(&self) -> Option<Banner> {
        let linked: Vec<PublicKey> = self
            .collab
            .people
            .iter()
            .filter(|person| person.path.is_some())
            .map(|person| person.key)
            .collect();
        analysis_banner(
            self.collab.analysis.as_ref(),
            &self.collab.people,
            &linked,
            self.collab.fetching.as_ref(),
        )
    }

    // ---- dialogs ----

    /// A button of the dialogs and the panel.
    fn collab_button(
        &self,
        id: impl Into<ElementId>,
        label: String,
        strong: bool,
    ) -> Stateful<Div> {
        let theme = self.theme;
        div()
            .id(id)
            .flex()
            .flex_none()
            .items_center()
            .h(self.z(ICON_BUTTON))
            .px(self.z(10.0))
            .rounded(self.z(4.0))
            .text_color(hsla(theme.text))
            .when(strong, |d| d.bg(hsla(theme.element_selected)))
            .hover(|s| s.bg(hsla(theme.element_hover)))
            .cursor_pointer()
            .on_mouse_down(MouseButton::Left, |_, window, cx| {
                window.prevent_default();
                cx.stop_propagation();
            })
            .child(label)
    }

    /// A muted line.
    fn muted(&self, text: impl Into<SharedString>) -> Div {
        div()
            .text_color(hsla(self.theme.text_muted))
            .child(text.into())
    }

    /// The open dialog's card and its width, if one is open: the approval
    /// cards first.
    pub fn render_collab_dialog(&self, cx: &mut Context<Self>) -> Option<(f32, AnyElement)> {
        if !self.collab.asked.is_empty() {
            return Some((460.0, self.render_approvals(cx)));
        }
        match self.collab.dialog? {
            Dialog::Share => Some((520.0, self.render_share(cx))),
            Dialog::Join => Some((520.0, self.render_join(cx))),
            Dialog::Agents => Some((600.0, self.render_agents(cx))),
            Dialog::Bring => Some((560.0, self.render_bring(cx))),
        }
    }

    /// Connect an Agent: one row per harness, its name (and the file a
    /// config entry goes in), its setup selectable in the code font, Copy.
    fn render_agents(&self, cx: &mut Context<Self>) -> AnyElement {
        let theme = self.theme;
        let rows = self
            .collab
            .setup
            .iter()
            .enumerate()
            .map(|(i, (row, field))| {
                let text = row.text.clone();
                let label = if self.collab.setup_copied == Some(i) {
                    "Copied"
                } else {
                    "Copy"
                };
                div()
                    .flex()
                    .items_start()
                    .gap(self.z(8.0))
                    .child(
                        div()
                            .w(self.z(96.0))
                            .flex_none()
                            .pt(self.z(4.0))
                            .flex()
                            .flex_col()
                            .child(div().font_weight(FontWeight::SEMIBOLD).child(row.name))
                            .children(
                                row.file
                                    .map(|file| self.muted(file).text_size(self.z(11.0))),
                            ),
                    )
                    .child(
                        div()
                            .flex_1()
                            .min_w_0()
                            .px(self.z(4.0))
                            .rounded(self.z(4.0))
                            .bg(hsla(theme.editor))
                            .text_size(self.z(11.5))
                            .font_family(self.settings.code_font.clone())
                            .child(Textarea::new(field).readonly(true).appearance(false)),
                    )
                    .child(
                        self.collab_button(("agent-copy", i), label.to_owned(), false)
                            .on_click(cx.listener(move |this, _: &ClickEvent, _, cx| {
                                cx.write_to_clipboard(ClipboardItem::new_string(text.clone()));
                                this.collab.setup_copied = Some(i);
                                cx.notify();
                            })),
                    )
            });
        div()
            .id("connect-agent")
            .min_h_0()
            .overflow_y_scroll()
            .p(self.z(14.0))
            .flex()
            .flex_col()
            .gap(self.z(8.0))
            .child(
                div()
                    .font_weight(FontWeight::BOLD)
                    .child("Connect an Agent"),
            )
            .children(rows)
            .into_any_element()
    }

    /// The relay choice: the `collab.relay` setting's relay, none, the LAN
    /// only.
    fn render_modes(&self, cx: &mut Context<Self>) -> AnyElement {
        let modes = [Mode::Relay, Mode::NoRelay, Mode::Lan].map(|mode| {
            self.collab_button(
                ("collab-mode", mode as usize),
                mode.label(&self.settings.collab_relay).to_owned(),
                self.collab.mode == mode,
            )
            .on_click(cx.listener(move |this, _: &ClickEvent, _, cx| {
                this.collab.mode = mode;
                cx.notify();
            }))
        });
        div()
            .flex()
            .items_center()
            .gap(self.z(4.0))
            .child(self.muted("Reach:").mr(self.z(4.0)))
            .children(modes)
            .into_any_element()
    }

    /// The Share dialog: before, the name, the relay, what is sent, the
    /// members to add by identity card (each with a role, members before
    /// anyone connects) and whether others holding the ticket may ask (off
    /// by default); then the ticket, its QR code, Copy, Stop sharing.
    fn render_share(&self, cx: &mut Context<Self>) -> AnyElement {
        let theme = self.theme;
        let mut card = div()
            .id("collab-share")
            .p(self.z(14.0))
            .flex()
            .flex_col()
            .gap(self.z(8.0))
            .child(
                div()
                    .font_weight(FontWeight::BOLD)
                    .child("Share this project"),
            );
        if let Some(ticket) = &self.collab.ticket {
            card = card.child(self.render_ticket(ticket, cx));
        } else {
            if let Some(name) = &self.collab.name {
                card = card
                    .child(self.muted("Your name, as the others see it"))
                    .child(
                        div()
                            .px(self.z(4.0))
                            .rounded(self.z(4.0))
                            .border_1()
                            .border_color(hsla(theme.border))
                            .child(Input::new(name).appearance(false)),
                    );
            }
            card = card
                .child(self.render_modes(cx))
                .child(self.render_sends(cx))
                .child(self.render_adding(cx))
                .child(self.admit_known_toggle(cx))
                .children(self.render_share_history(cx))
                .child(
                    div().flex().justify_end().child(
                        self.collab_button(
                            "collab-start",
                            if self.collab.live() {
                                "Starting…"
                            } else {
                                "Start sharing"
                            }
                            .to_owned(),
                            true,
                        )
                        .on_click(cx.listener(
                            |this, _: &ClickEvent, window, cx| {
                                if !this.collab.live() {
                                    this.start_sharing(window, cx);
                                }
                            },
                        )),
                    ),
                );
        }
        card.children(self.collab.status.clone().map(|s| self.muted(s)))
            .children(
                self.collab
                    .error
                    .clone()
                    .map(|e| div().text_color(hsla(theme.error)).child(e)),
            )
            .into_any_element()
    }

    /// The share's ticket: what holding it means, its QR code and text,
    /// whether people admitted before come in unasked, Copy (Stop sharing
    /// is the session's popover's, which shows the ticket again).
    fn render_ticket(&self, ticket: &str, cx: &mut Context<Self>) -> Div {
        let about = "Members you added join with this ticket; anyone else holding it can ask to \
                     join, and you approve each. It holds no secret, but it carries your IP \
                     addresses.";
        div()
            .flex()
            .flex_col()
            .gap(self.z(8.0))
            .child(self.muted(about))
            .child(self.ticket_code(ticket))
            .child(self.admit_known_toggle(cx))
            .child(self.render_sends(cx))
            .children(self.render_members(cx))
            .child(
                div()
                    .flex()
                    .justify_end()
                    .gap(self.z(6.0))
                    .child(self.copy_button(ticket, cx)),
            )
    }

    /// The ticket's QR code beside its text.
    fn ticket_code(&self, ticket: &str) -> Div {
        div()
            .flex()
            .gap(self.z(12.0))
            .child(self.render_qr())
            .child(
                div()
                    .flex_1()
                    .min_w_0()
                    .p(self.z(6.0))
                    .rounded(self.z(4.0))
                    .bg(hsla(self.theme.editor))
                    .text_size(self.z(11.0))
                    .font_family(self.settings.code_font.clone())
                    .child(ticket.to_owned()),
            )
    }

    /// Whether people admitted before come in unasked.
    fn admit_known_toggle(&self, cx: &mut Context<Self>) -> AnyElement {
        self.share_switch(
            "collab-admit-known",
            "Admit people admitted before without asking",
            Some(self.collab.admit_known),
            |this, on, cx| {
                this.collab.admit_known = on;
                cx.notify();
            },
            cx,
        )
    }

    /// Sharing a project anew, the history the share lists: each chain of
    /// it, whose and how long, chosen or left out (this install's own and
    /// its agents' chosen at first); none for a share's project.
    fn render_share_history(&self, cx: &mut Context<Self>) -> Option<Div> {
        let chains = self.collab.history.as_ref().filter(|c| !c.is_empty())?;
        let chosen = chains.iter().filter(|(_, on)| *on).count();
        let rows = chains.iter().enumerate().map(|(i, (chain, on))| {
            self.share_switch(
                ("collab-history", i),
                listed_text(chain, &self.person_name(chain.author)),
                Some(*on),
                move |this, on, cx| {
                    if let Some(chain) = this.collab.history.as_mut().and_then(|c| c.get_mut(i)) {
                        chain.1 = on;
                    }
                    cx.notify();
                },
                cx,
            )
        });
        Some(
            div()
                .flex()
                .flex_col()
                .gap(self.z(4.0))
                .child(div().font_weight(FontWeight::SEMIBOLD).child("History"))
                .child(self.muted(listing_text(chosen, chains.len())))
                .children(rows),
        )
    }

    /// The role buttons of the next card added: editor (the default) or
    /// viewer.
    pub(crate) fn card_role_buttons(&self, cx: &mut Context<Self>) -> Div {
        let viewer = self.collab.card_viewer;
        let button = |id: &'static str, label: &str, this_one: bool, set: bool| {
            self.collab_button(id, label.to_owned(), this_one)
                .on_click(cx.listener(move |this, _: &ClickEvent, _, cx| {
                    this.collab.card_viewer = set;
                    cx.notify();
                }))
        };
        div()
            .flex()
            .items_center()
            .gap(self.z(2.0))
            .child(button("collab-card-editor", "Editor", !viewer, false))
            .child(button("collab-card-viewer", "Viewer", viewer, true))
    }

    /// Before sharing: the members to add, each by name, fingerprint and
    /// role (Remove), and the field to paste a card in, its role, Add.
    fn render_adding(&self, cx: &mut Context<Self>) -> Div {
        let theme = self.theme;
        let rows = self.collab.adding.iter().enumerate().map(|(i, adding)| {
            div()
                .flex()
                .items_center()
                .gap(self.z(6.0))
                .child(div().flex_none().child(shown_name(&adding.name)))
                .child(
                    self.muted(fingerprint(adding.key))
                        .flex_1()
                        .min_w_0()
                        .overflow_hidden()
                        .whitespace_nowrap()
                        .text_ellipsis(),
                )
                .child(self.muted(adding.role.name()))
                .child(
                    self.collab_button(("collab-adding-remove", i), "Remove".to_owned(), false)
                        .on_click(cx.listener(move |this, _: &ClickEvent, _, cx| {
                            if i < this.collab.adding.len() {
                                this.collab.adding.remove(i);
                            }
                            cx.notify();
                        })),
                )
        });
        let rows: Vec<Div> = rows.collect();
        let field = self.collab.card_input.as_ref().map(|input| {
            div()
                .flex()
                .items_center()
                .gap(self.z(6.0))
                .child(
                    div()
                        .flex_1()
                        .min_w_0()
                        .px(self.z(4.0))
                        .rounded(self.z(4.0))
                        .border_1()
                        .border_color(hsla(theme.border))
                        .child(Input::new(input).appearance(false)),
                )
                .child(self.card_role_buttons(cx))
                .child(
                    self.collab_button("collab-add-member", "Add".to_owned(), false)
                        .on_click(cx.listener(|this, _: &ClickEvent, window, cx| {
                            this.add_member(window, cx);
                        })),
                )
        });
        div()
            .flex()
            .flex_col()
            .gap(self.z(6.0))
            .child(self.muted("Members"))
            .child(self.muted(
                "Add people by their identity card (File › Copy My Identity Card gives one's \
                 own): they are members before anyone connects, and join with the ticket.",
            ))
            .children(rows)
            .children(field)
            .children(
                self.collab
                    .member_error
                    .clone()
                    .map(|e| div().text_color(hsla(theme.error)).child(e)),
            )
    }

    /// A choice of the share as a switch, `label` beside it (the settings'
    /// control): a click on either, or Space once it has the focus, sets
    /// it, through `set`. `on` `None`: it cannot be changed (shown off,
    /// greyed).
    fn share_switch(
        &self,
        id: impl Into<ElementId>,
        label: impl Into<SharedString>,
        on: Option<bool>,
        set: impl Fn(&mut Self, bool, &mut Context<Self>) + 'static,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        let this = cx.entity().downgrade();
        div()
            .text_color(hsla(self.theme.text))
            .child(
                Switch::new(id)
                    .small()
                    .checked(on.unwrap_or(false))
                    .disabled(on.is_none())
                    .label(label.into())
                    .on_click(move |checked, _, cx| {
                        let _ = this.update(cx, |this, cx| set(this, *checked, cx));
                    }),
            )
            .into_any_element()
    }

    /// The Join dialog's Copy identity card: this user's card under the
    /// name typed, for the owner to add them by.
    fn copy_card_button(&self, cx: &mut Context<Self>) -> Stateful<Div> {
        self.copy_shaped(Copied::Card, false).on_click(cx.listener(
            |this, _: &ClickEvent, _, cx| {
                match my_card(&this.typed_name(cx)) {
                    Ok(card) => {
                        cx.write_to_clipboard(ClipboardItem::new_string(card));
                        this.collab.copied = Some(Copied::Card);
                        this.collab.error = None;
                    }
                    Err(why) => this.collab.error = Some(why),
                }
                cx.notify();
            },
        ))
    }

    /// Copy ticket.
    fn copy_button(&self, ticket: &str, cx: &mut Context<Self>) -> Stateful<Div> {
        let copied = ticket.to_owned();
        self.copy_shaped(Copied::Ticket, true).on_click(cx.listener(
            move |this, _: &ClickEvent, _, cx| {
                cx.write_to_clipboard(ClipboardItem::new_string(copied.clone()));
                this.collab.copied = Some(Copied::Ticket);
                cx.notify();
            },
        ))
    }

    /// The Copy button `which` (`primary` or not), saying Copied once it
    /// copied, until its dialog or popover opens again.
    fn copy_shaped(&self, which: Copied, primary: bool) -> Stateful<Div> {
        let (id, label) = which.button();
        let label = if self.collab.copied == Some(which) {
            "Copied"
        } else {
            label
        };
        self.collab_button(id, label.to_owned(), primary)
    }

    /// Stop sharing and Copy ticket (the session's popover); Stop asks
    /// first while others are linked (they would be disconnected).
    pub(crate) fn stop_row(&self, ticket: &str, cx: &mut Context<Self>) -> Div {
        let asking = matches!(
            self.collab.popover,
            Some(Popover::Session { stopping: true })
        );
        let stop = |primary: bool| {
            self.collab_button("collab-stop", "Stop sharing".to_owned(), primary)
                .on_click(cx.listener(|this, _: &ClickEvent, window, cx| {
                    let linked: Vec<String> =
                        this.collab.people.iter().map(|p| p.name.clone()).collect();
                    let asked = matches!(
                        this.collab.popover,
                        Some(Popover::Session { stopping: true })
                    );
                    if asked || stop_text(&linked).is_none() {
                        this.leave_session(None, cx);
                        this.close_overlays(window, cx);
                    } else {
                        this.collab.popover = Some(Popover::Session { stopping: true });
                        cx.notify();
                    }
                }))
        };
        let row = div().flex().justify_end().gap(self.z(6.0));
        let linked: Vec<String> = self.collab.people.iter().map(|p| p.name.clone()).collect();
        match stop_text(&linked).filter(|_| asking) {
            Some(question) => div()
                .flex()
                .flex_col()
                .gap(self.z(6.0))
                .child(div().text_color(hsla(self.theme.error)).child(question))
                .child(
                    row.child(
                        self.collab_button("collab-stop-cancel", "Cancel".to_owned(), false)
                            .on_click(cx.listener(|this, _: &ClickEvent, _, cx| {
                                this.collab.popover = Some(Popover::Session { stopping: false });
                                cx.notify();
                            })),
                    )
                    .child(stop(true)),
                ),
            None => row
                .child(stop(false))
                .child(div().flex_1())
                .child(self.copy_button(ticket, cx)),
        }
    }

    /// What sharing sends to those who join: the binary, the debug file
    /// the analysis read (greyed if it read none); nothing by default.
    fn render_sends(&self, cx: &mut Context<Self>) -> Div {
        let debug = self.session.as_ref().and_then(|session| {
            session
                .core()
                .debug_file()
                .and_then(|path| path.file_name())
                .map(|name| name.to_string_lossy().into_owned())
        });
        let sends = self.collab.sends;
        div()
            .flex()
            .flex_col()
            .gap(self.z(8.0))
            .child(self.share_switch(
                "collab-send-binary",
                "Send the binary to people who join",
                Some(sends.binary),
                |this, on, cx| this.set_send(false, on, cx),
                cx,
            ))
            .child(match debug {
                Some(name) => self.share_switch(
                    "collab-send-debug",
                    format!("Send the debug file ({name})"),
                    Some(sends.debug),
                    |this, on, cx| this.set_send(true, on, cx),
                    cx,
                ),
                None => self.share_switch(
                    "collab-send-debug",
                    "Send the debug file (the analysis read none)",
                    None,
                    |_, _, _| {},
                    cx,
                ),
            })
            .child(self.muted(
                "Sealed before it leaves: only members can open it. Someone who has the \
                 binary never fetches it.",
            ))
    }

    /// The binary the host sends, which this window lacks: fetch it, use a
    /// file of the same bytes opened before (the recent files), or not
    /// join.
    fn render_offer(&self, offered: &Offered, cx: &mut Context<Self>) -> Div {
        let hex = offered.sha256.iter().fold(String::new(), |mut hex, byte| {
            let _ = write!(hex, "{byte:02x}");
            hex
        });
        let here = self
            .recent
            .iter()
            .find(|recent| recent.sha256.as_deref() == Some(hex.as_str()) && recent.path.exists())
            .map(|recent| recent.path.clone());
        let lacking = if self.session.is_some() {
            "which is not the one open here"
        } else {
            "which this window does not have"
        };
        let mut buttons = div().flex().justify_end().gap(self.z(6.0)).child(
            self.collab_button("collab-offer-cancel", "Cancel".to_owned(), false)
                .on_click(cx.listener(|this, _: &ClickEvent, _, cx| {
                    this.decide_offer(Decision::Cancel, cx);
                })),
        );
        if let Some(path) = here.clone() {
            buttons = buttons.child(
                self.collab_button("collab-offer-open", "Use it".to_owned(), false)
                    .on_click(cx.listener(move |this, _: &ClickEvent, _, cx| {
                        this.decide_offer(Decision::Open(path.clone()), cx);
                    })),
            );
        }
        div()
            .flex()
            .flex_col()
            .gap(self.z(6.0))
            .child(div().child(format!(
                "The host sends the binary {} ({}{}), {lacking}.",
                offered.name,
                offered
                    .arch
                    .as_ref()
                    .map_or_else(String::new, |arch| format!("the {arch} slice, ")),
                size_text(offered.length)
            )))
            .child(self.muted(format!("SHA-256 {}…", hex.get(..16).unwrap_or_default())))
            .children(here.map(|path| self.muted(format!("You have it: {}", path.display()))))
            .child(
                buttons.child(
                    self.collab_button(
                        "collab-offer-fetch",
                        "Get it from the host".to_owned(),
                        true,
                    )
                    .on_click(cx.listener(|this, _: &ClickEvent, _, cx| {
                        this.decide_offer(Decision::Fetch, cx);
                    })),
                ),
            )
    }

    /// How far a fetch is: a line and a bar.
    fn render_fetching(&self, fetching: &Fetching) -> Div {
        let theme = self.theme;
        // Before joining, the people are not known yet: the binary comes
        // from the host.
        let from = if fetching.debug {
            self.person_name(fetching.from)
        } else {
            "the host".to_owned()
        };
        let width = 480.0;
        div()
            .flex()
            .flex_col()
            .gap(self.z(4.0))
            .child(self.muted(fetch_text(fetching, &from)))
            .child(
                div()
                    .w(self.z(width))
                    .h(self.z(6.0))
                    .rounded(self.z(3.0))
                    .bg(hsla(theme.border))
                    .child(
                        div()
                            .h_full()
                            .w(self.z(width * fetching.fraction()))
                            .rounded(self.z(3.0))
                            .bg(hsla(theme.accent)),
                    ),
            )
    }

    /// The ticket's QR code, painted.
    fn render_qr(&self) -> AnyElement {
        let Some((width, modules)) = self.collab.qr.clone() else {
            return div().into_any_element();
        };
        let module = f32::from(self.z(MODULE));
        // A quiet zone of 4 modules, as the standard wants.
        let side = module * (small(width) + 8.0);
        canvas(
            |_, _, _| {},
            move |bounds: Bounds<Pixels>, (), window, _| {
                window.paint_quad(fill(bounds, white()));
                for (i, dark) in modules.iter().enumerate() {
                    if !*dark {
                        continue;
                    }
                    let (x, y) = (small(i % width) + 4.0, small(i / width) + 4.0);
                    window.paint_quad(fill(
                        Bounds::new(
                            point(
                                bounds.origin.x + px(x * module),
                                bounds.origin.y + px(y * module),
                            ),
                            size(px(module), px(module)),
                        ),
                        black(),
                    ));
                }
            },
        )
        .flex_none()
        .w(px(side))
        .h(px(side))
        .into_any_element()
    }

    /// The Join dialog: the ticket, the name, the relay.
    fn render_join(&self, cx: &mut Context<Self>) -> AnyElement {
        let theme = self.theme;
        let field = |input: &Entity<InputState>| {
            div()
                .px(self.z(4.0))
                .rounded(self.z(4.0))
                .border_1()
                .border_color(hsla(theme.border))
                .child(Input::new(input).appearance(false))
        };
        let about = match self.session.as_ref().map(Session::file_name) {
            Some(file) => format!(
                "With {file}: the binary shared must be this one, unless the host sends it. \
                 The share opens in a project of its own; yours stays as it is. The owner \
                 approves you when you ask, unless they added you by your identity card."
            ),
            None => "The owner approves you when you ask, unless they added you by your \
                     identity card; if the host sends the binary, you can get it from them."
                .to_owned(),
        };
        let card = div()
            .id("collab-join")
            .p(self.z(14.0))
            .flex()
            .flex_col()
            .gap(self.z(8.0))
            .child(
                div()
                    .font_weight(FontWeight::BOLD)
                    .child("Join a shared project"),
            );
        if let Some(offered) = &self.collab.offered {
            return card
                .child(self.render_offer(offered, cx))
                .into_any_element();
        }
        if let Some(fetching) = self.collab.fetching.as_ref().filter(|f| !f.debug) {
            return card
                .child(self.render_fetching(fetching))
                .into_any_element();
        }
        if self.collab.live() {
            return card
                .children(self.collab.status.clone().map(|s| self.muted(s)))
                .into_any_element();
        }
        card.child(self.muted(about))
            .child(self.muted("Ticket"))
            .children(self.collab.ticket_input.as_ref().map(field))
            .child(self.muted("Your name, as the others see it"))
            .children(self.collab.name.as_ref().map(field))
            .child(self.render_modes(cx))
            .child(
                div()
                    .flex()
                    .justify_end()
                    .gap(self.z(6.0))
                    .child(self.copy_card_button(cx))
                    .child(
                        self.collab_button("collab-join-go", "Join".to_owned(), true)
                            .on_click(cx.listener(|this, _: &ClickEvent, window, cx| {
                                this.start_joining(window, cx);
                            })),
                    ),
            )
            .children(
                self.collab
                    .error
                    .clone()
                    .map(|e| div().text_color(hsla(theme.error)).child(e)),
            )
            .into_any_element()
    }

    /// The requests to join waiting, a card each, the first `SHOWN` in
    /// the order they came, then how many more wait: every one can be
    /// answered, in any order.
    fn render_approvals(&self, cx: &mut Context<Self>) -> AnyElement {
        /// The cards shown at once.
        const SHOWN: usize = 4;
        let theme = self.theme;
        let more = self.collab.asked.len().saturating_sub(SHOWN);
        div()
            .id("collab-approve")
            .track_focus(&self.overlay_focus)
            .flex()
            .flex_col()
            .children(self.collab.asked.iter().take(SHOWN).enumerate().map(
                |(n, (_, (asked, trust)))| {
                    div()
                        .when(n > 0, |d| {
                            d.border_t_1().border_color(hsla(theme.border_variant))
                        })
                        .child(self.render_approval(asked, trust, cx))
                },
            ))
            .when(more > 0, |d| {
                d.child(
                    div()
                        .px(self.z(14.0))
                        .pb(self.z(12.0))
                        .child(self.muted(format!("{more} more waiting"))),
                )
            })
            .into_any_element()
    }

    /// An approval card: who asks, their fingerprint, how far they are
    /// trusted (an impostor in red), their link and binbun; admit as an
    /// editor or a viewer, or deny.
    fn render_approval(&self, asked: &Asked, trust: &Trust, cx: &mut Context<Self>) -> AnyElement {
        let theme = self.theme;
        let face = self.collab.colours.avatar(asked.key, &asked.name);
        let (said, red) = trust_text(trust, &asked.name);
        let name = shown_name(&asked.name);
        div()
            .id((
                "collab-request",
                usize::try_from(asked.id).unwrap_or(usize::MAX),
            ))
            .p(self.z(14.0))
            .flex()
            .flex_col()
            .gap(self.z(8.0))
            .when(red, |d| {
                d.border_2()
                    .border_color(hsla(theme.error))
                    .rounded(self.z(8.0))
            })
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap(self.z(10.0))
                    .child(
                        div()
                            .flex_none()
                            .rounded_full()
                            .when(red, |d| d.border_2().border_color(hsla(theme.error)))
                            .child(self.avatar_circle(&face, 36.0)),
                    )
                    .child(
                        div()
                            .flex()
                            .flex_col()
                            .child(
                                div()
                                    .font_weight(FontWeight::BOLD)
                                    .child(format!("{name} asks to join")),
                            )
                            .child(self.muted(format!("Fingerprint {}", fingerprint(asked.key)))),
                    ),
            )
            .child(
                div()
                    .when(red, |d| {
                        d.text_color(hsla(theme.error))
                            .font_weight(FontWeight::BOLD)
                    })
                    .when(!red, |d| d.text_color(hsla(theme.text_muted)))
                    .child(said),
            )
            .child({
                // How the link goes; its addresses in the tooltip only.
                let paths = asked.path.replace(", ", "\n");
                div()
                    .id("approve-path")
                    .text_color(hsla(theme.text_muted))
                    .tooltip(move |window, cx| Tooltip::new(paths.clone()).build(window, cx))
                    .child(format!("Via {}", link_text(&asked.path)))
            })
            .child(self.muted(version_text(&asked.engine)))
            .child(self.approval_buttons(asked.id, red, cx))
            .into_any_element()
    }

    /// The approval card's answers to request `id`, the one it shows;
    /// admitting as an editor is the default unless the joiner may be an
    /// impostor (`red`).
    fn approval_buttons(&self, id: u64, red: bool, cx: &mut Context<Self>) -> Div {
        div()
            .pt(self.z(6.0))
            .flex()
            .justify_end()
            .gap(self.z(6.0))
            .child(
                self.collab_button("collab-deny", "Deny".to_owned(), red)
                    .on_click(cx.listener(move |this, _: &ClickEvent, window, cx| {
                        this.decide(id, None, window, cx);
                    })),
            )
            .child(
                self.collab_button("collab-viewer", "Admit as viewer".to_owned(), false)
                    .on_click(cx.listener(move |this, _: &ClickEvent, window, cx| {
                        this.decide(id, Some(Role::Viewer), window, cx);
                    })),
            )
            .child(
                self.collab_button("collab-editor", "Admit as editor".to_owned(), !red)
                    .on_click(cx.listener(move |this, _: &ClickEvent, window, cx| {
                        this.decide(id, Some(Role::Editor), window, cx);
                    })),
            )
    }

    /// Esc on a dialog: closed (the approval card stays until answered).
    pub fn close_collab_dialog(&mut self) -> bool {
        self.collab.dialog.take().is_some()
    }

    /// The chat's message box, made once: Enter sends, Shift+Enter breaks
    /// the line (it grows to five), `@` completes a person in the
    /// session.
    pub(crate) fn ensure_chat_input(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if self.collab.chat_input.is_some() {
            return;
        }
        let input = cx.new(|cx| {
            TextareaState::new(window, cx)
                .auto_grow(1, 5)
                .submit_on_enter(true)
                .placeholder("Message the session")
        });
        let sub = cx.subscribe_in(
            &input,
            window,
            |this, input, e: &InputEvent, window, cx| match e {
                InputEvent::Change => {
                    let (text, cursor) = {
                        let state = input.read(cx);
                        (state.value().to_string(), state.cursor())
                    };
                    this.collab.completion =
                        Completion::offer(&text, cursor, &this.chat_participants());
                    cx.notify();
                }
                InputEvent::PressEnter { shift: true, .. }
                | InputEvent::Focus
                | InputEvent::Blur => {}
                InputEvent::PressEnter { .. } => this.send_chat(window, cx),
            },
        );
        let this = cx.weak_entity();
        let handle = window.window_handle();
        let keys = cx.intercept_keystrokes(move |event, window, cx| {
            if window.window_handle() != handle || event.keystroke.modifiers.modified() {
                return;
            }
            let taken = this
                .update(cx, |this, cx| {
                    let Some(input) = this.collab.chat_input.clone() else {
                        return false;
                    };
                    if !input.read(cx).focus_handle(cx).is_focused(window) {
                        return false;
                    }
                    let taken = Completion::key(
                        &mut this.collab.completion,
                        &event.keystroke.key,
                        &input,
                        window,
                        cx,
                    );
                    if taken {
                        cx.notify();
                    }
                    taken
                })
                .unwrap_or(false);
            if taken {
                cx.stop_propagation();
            }
        });
        self.collab.chat_subs.push(sub);
        self.collab.chat_subs.push(keys);
        self.collab.chat_input = Some(input);
    }

    /// Who a chat message can mention: the others in the session.
    fn chat_participants(&self) -> Vec<Participant> {
        self.collab
            .people
            .iter()
            .map(|person| Participant {
                key: person.key,
                agent: None,
                name: person.name.clone(),
            })
            .collect()
    }

    /// Enter in the message box: the message sent with the places it
    /// names (resolved now, against this window's image and names) and
    /// whom it mentions.
    fn send_chat(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let Some(input) = self.collab.chat_input.clone() else {
            return;
        };
        let text = input.read(cx).value().to_string();
        if text.trim().is_empty() {
            return;
        }
        let links = match (&self.listing, &self.session) {
            (Some(listing), Some(session)) => chat::links(
                &text,
                &self.collab.placed,
                &Image {
                    listing,
                    overlay: session.overlay(),
                },
            ),
            _ => Vec::new(),
        };
        let mentions: Vec<PublicKey> = mentions_in(&text, &self.chat_participants())
            .into_iter()
            .map(|mention| mention.key)
            .collect();
        let sent = self.collab.net.as_ref().map_or_else(
            || Err("not in a session".to_owned()),
            |net| net.chat(&text, &links, &mentions),
        );
        match sent {
            Ok(()) => {
                input.update(cx, |s, cx| s.set_value("", window, cx));
                self.collab.placed.clear();
                self.collab.completion = None;
            }
            Err(error) => self.collab.notice = Some((error, Instant::now())),
        }
        cx.notify();
    }

    /// Insert Location: the cursor's place written into the message box
    /// (`push_stream · 1E720`, linked whole on sending), the chat shown
    /// and its box focused.
    fn insert_location(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let (Some(address), Some(listing), Some(session)) =
            (self.current_address(), &self.listing, &self.session)
        else {
            return;
        };
        let overlay = session.overlay();
        let name = listing
            .function_of(address)
            .map_or(address, |(_, entry)| entry);
        let text = chat::location_text(listing.shown_name(name, overlay), address);
        self.collab.panel = Some(Tab::Chat);
        self.ensure_chat_input(window, cx);
        let Some(input) = self.collab.chat_input.clone() else {
            return;
        };
        let spaced = {
            let state = input.read(cx);
            let value = state.value();
            value
                .get(..state.cursor())
                .and_then(|before| before.chars().next_back())
                .is_some_and(|c| !c.is_whitespace())
        };
        let written = if spaced {
            format!(" {text} ")
        } else {
            format!("{text} ")
        };
        input.update(cx, |s, cx| {
            s.insert(written, window, cx);
            s.focus(window, cx);
        });
        self.collab.placed.push((text, address));
    }

    /// The owner's buttons for member `key`: editor, viewer, agent (an
    /// agent's), remove.
    pub(crate) fn role_buttons(
        &self,
        i: usize,
        key: PublicKey,
        role: Option<Role>,
        agent: bool,
        cx: &mut Context<Self>,
    ) -> Vec<Stateful<Div>> {
        let set = |id: &'static str, label: &str, to: Role| {
            self.collab_button((id, i), label.to_owned(), role == Some(to))
                .on_click(cx.listener(move |this, _: &ClickEvent, _, cx| {
                    if let Some(net) = &this.collab.net
                        && let Err(error) = net.set_role(key, to)
                    {
                        this.collab.status = Some(error);
                    }
                    this.refresh_people();
                    cx.notify();
                }))
        };
        let mut buttons = vec![
            set("as-editor", "Editor", Role::Editor),
            set("as-viewer", "Viewer", Role::Viewer),
        ];
        if agent {
            buttons.push(set("as-agent", "Agent", Role::Agent));
        }
        buttons.push(
            self.collab_button(("remove", i), "Remove".to_owned(), false)
                .on_click(cx.listener(move |this, _: &ClickEvent, _, cx| {
                    if let Some(net) = &this.collab.net
                        && let Err(error) = net.remove(key)
                    {
                        this.collab.status = Some(error);
                    }
                    this.refresh_people();
                    cx.notify();
                })),
        );
        buttons
    }

    /// The conflicts tab: each conflict's card, its values to keep or
    /// use; its title goes to its address.
    pub(crate) fn render_conflicts(&self, cx: &mut Context<Self>) -> AnyElement {
        let theme = self.theme;
        if self.collab.conflicts.is_empty() {
            return self
                .muted("No conflicts: concurrent edits of one thing show here.")
                .into_any_element();
        }
        let name = |key: PublicKey| self.person_name(key);
        div()
            .flex()
            .flex_col()
            .gap(self.z(10.0))
            .children(
                self.collab
                    .conflicts
                    .iter()
                    .enumerate()
                    .map(|(i, conflict)| {
                        let (what, address) = key_text(&conflict.key);
                        let buttons: Vec<Stateful<Div>> = conflict
                            .leaves
                            .iter()
                            .enumerate()
                            .map(|(j, leaf)| {
                                let key = conflict.key.clone();
                                let value = leaf.value.clone();
                                let shown = leaf.op == conflict.shown;
                                let label = format!(
                                    "{} {}",
                                    if shown { "Keep" } else { "Use" },
                                    value_text(&leaf.value)
                                );
                                self.collab_button(("resolve", i * 64 + j), label, shown)
                                    .on_click(cx.listener(move |this, _: &ClickEvent, _, cx| {
                                        if let Some(session) = &mut this.session
                                            && let Err(error) =
                                                session.resolve(key.clone(), value.clone())
                                        {
                                            this.collab.status = Some(error);
                                        }
                                        cx.notify();
                                    }))
                            })
                            .collect();
                        div()
                            .flex()
                            .flex_col()
                            .gap(self.z(4.0))
                            .p(self.z(6.0))
                            .rounded(self.z(4.0))
                            .border_1()
                            .border_color(hsla(theme.border))
                            .child(
                                div()
                                    .id(("conflict", i))
                                    .font_weight(FontWeight::BOLD)
                                    .cursor_pointer()
                                    .on_click(cx.listener(move |this, _: &ClickEvent, _, cx| {
                                        if let Some(address) = address {
                                            this.jump(address, cx);
                                        }
                                    }))
                                    .child(what),
                            )
                            .child(div().child(conflict_text(conflict, &name)))
                            .child(div().flex().flex_wrap().gap(self.z(4.0)).children(buttons))
                    }),
            )
            .into_any_element()
    }

    /// The refused changes, by this peer's checks and the session's: the
    /// change, its author, why.
    fn refused_lines(&self) -> Vec<String> {
        let mut refused = self
            .collab
            .net
            .as_ref()
            .map(Net::refused)
            .or_else(|| self.session.as_ref().map(Session::refused))
            .unwrap_or_default();
        refused.dedup();
        refused
            .into_iter()
            .map(|r| {
                let change = r.change.map_or_else(
                    || "A change".to_owned(),
                    |id| format!("Change {}:{}", id.chain, id.seq),
                );
                let by = r
                    .author
                    .map_or_else(|| "someone".to_owned(), |a| self.person_name(a));
                format!("{change} by {by}: {}", r.why)
            })
            .collect()
    }

    /// Why this window takes no edits now, if it does not: it is joining
    /// a share (asking the host, getting or opening the binary, or joined
    /// before the share's journal is this project's), or it is view-only
    /// in the session.
    pub fn edits_off(&self) -> Option<EditsOff> {
        let joining = self.collab.joining()
            || self
                .session
                .as_ref()
                .is_some_and(|session| session.core().joining());
        EditsOff::of(joining, self.collab.read_only())
    }

    /// Whether the project open is a share's.
    pub fn share_open(&self) -> bool {
        self.session
            .as_ref()
            .is_some_and(|session| session.core().genesis().is_some())
    }

    /// Reads again the share's project's own edits: those not yet shared
    /// and those not in this project (none in a private project).
    pub fn refresh_local(&mut self) {
        let core = self
            .session
            .as_ref()
            .map(Session::core)
            .filter(|core| core.genesis().is_some());
        self.collab.local = core.map_or_else(LocalEdits::default, |core| LocalEdits {
            pending: core.pending(),
            apart: core.not_in_project(),
        });
    }

    /// A joiner keeps who owns the share in its project (the window's
    /// title and Recent say "bash, shared by Ann"): their key, and their
    /// name once seen.
    fn note_owner(&mut self, window: &mut Window) {
        let Some(net) = self.collab.net.as_ref().filter(|net| !net.hosting()) else {
            return;
        };
        let Some(owner) = net.owner() else {
            return;
        };
        let Some(dir) = self
            .session
            .as_ref()
            .and_then(Session::project)
            .map(|project| project.dir().to_path_buf())
            .filter(|dir| share_of(dir).is_some())
        else {
            return;
        };
        let kept = self
            .collab
            .shared_by
            .clone()
            .or_else(|| SharedBy::load(&dir))
            .filter(|kept| kept.owner == owner);
        let seen = self
            .collab
            .people
            .iter()
            .find(|person| person.key == owner)
            .map(|person| person.name.clone());
        let now = SharedBy {
            owner,
            name: seen.or_else(|| kept.as_ref().and_then(|kept| kept.name.clone())),
        };
        if kept.as_ref() != Some(&now) {
            if let Err(why) = now.save(&dir) {
                self.collab.status = Some(why);
            }
            if let Some(session) = &self.session {
                window.set_window_title(&window_title(session));
            }
        }
        self.collab.shared_by = Some(now);
    }

    /// Bring From Your Own Project…: the values of the binary's private
    /// project read (on a thread: through the session open if it is its
    /// project, an owner's, else its log alone, held meanwhile), then
    /// offered to choose.
    fn open_bring(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.close_overlays(window, cx);
        let Some((key, core)) = self
            .session
            .as_ref()
            .and_then(|s| Some((s.key().cloned()?, s.core())))
        else {
            return;
        };
        if !self.share_open() {
            self.error =
                Some("Bring goes into a share's project: this one is not a share's".to_owned());
            return;
        }
        let Some(root) = project::root() else {
            self.error = Some(binbun_paths::Place::Projects.missing());
            return;
        };
        let from = match project::locate(&root, &key, &project::Choice::Private) {
            Ok(located) if located.chosen != project::Chosen::New => located.project,
            Ok(_) => {
                self.error =
                    Some("This binary has no project of your own to bring from".to_owned());
                return;
            }
            Err(why) => {
                self.error = Some(why);
                return;
            }
        };
        self.collab.bringing = Bringing {
            reading: true,
            ..Bringing::default()
        };
        self.collab.dialog = Some(Dialog::Bring);
        let (told, read) = async_channel::bounded(1);
        let _ = std::thread::Builder::new()
            .name("binbun-bringable".to_owned())
            .spawn(move || {
                let values = my_identity().and_then(|identity| {
                    Ok((identity.public(), core.bringable_from(&from, &identity)?))
                });
                let _ = told.try_send(values);
            });
        cx.spawn_in(window, async move |this, cx| {
            if let Ok(values) = read.recv().await {
                let _ = this.update(cx, |this, cx| {
                    let bringing = &mut this.collab.bringing;
                    bringing.reading = false;
                    match values {
                        Ok((me, values)) => {
                            let rows = bring_rows(&values, me);
                            bringing.me = Some(me);
                            bringing.values = values
                                .into_iter()
                                .zip(rows)
                                .map(|(value, row)| (value, row.chosen))
                                .collect();
                        }
                        Err(why) => bringing.error = Some(why),
                    }
                    cx.notify();
                });
            }
        })
        .detach();
        cx.notify();
    }

    /// The Bring dialog's Bring: the values chosen brought into the
    /// share's project as one change of this install's.
    fn bring_chosen(&mut self, cx: &mut Context<Self>) {
        let chosen: Vec<Bringable> = self
            .collab
            .bringing
            .values
            .iter()
            .filter(|(_, chosen)| *chosen)
            .map(|(value, _)| value.clone())
            .collect();
        if chosen.is_empty() {
            return;
        }
        match self.bring(&chosen) {
            Ok(()) => {
                self.collab.dialog = None;
                self.collab.bringing = Bringing::default();
            }
            Err(why) => self.collab.bringing.error = Some(why),
        }
        cx.notify();
    }

    /// Brings `values` into the share's project open as one change of
    /// this install's, said in the status bar.
    ///
    /// # Errors
    ///
    /// The session refuses it (joining, a role that may not write it).
    fn bring(&mut self, values: &[Bringable]) -> Result<(), String> {
        if let Some(off) = self.edits_off() {
            return Err(off.text());
        }
        let core = self
            .session
            .as_ref()
            .map(Session::core)
            .ok_or("No binary open")?;
        let brought = core.bring(values, "Bring").map_err(|e| e.to_string())?;
        self.projects.notice = Some(match brought {
            Some(_) if self.collab.live() => format!(
                "Brought {} as one change of yours",
                values_text(values.len())
            ),
            Some(_) => format!(
                "Brought {} as one change of yours: not yet shared",
                values_text(values.len())
            ),
            None => "Nothing to bring".to_owned(),
        });
        self.refresh_local();
        Ok(())
    }

    /// The Bring dialog: where the values go, each value of the private
    /// project with who wrote it (only this author's chosen at first),
    /// Bring.
    fn render_bring(&self, cx: &mut Context<Self>) -> AnyElement {
        let theme = self.theme;
        let bringing = &self.collab.bringing;
        let into = self.session.as_ref().map_or_else(String::new, |session| {
            project_title(
                &titled_file(session),
                session.project().map(project::Project::dir),
            )
        });
        let me = bringing.me.unwrap_or(PublicKey([0; 32]));
        let values: Vec<Bringable> = bringing.values.iter().map(|(v, _)| v.clone()).collect();
        let rows = bring_rows(&values, me);
        let chosen = bringing.values.iter().filter(|(_, on)| *on).count();
        let lines = rows.into_iter().enumerate().map(|(i, row)| {
            let on = bringing.values.get(i).is_some_and(|(_, on)| *on);
            let by = if row.mine {
                String::new()
            } else {
                " (another author's or an agent's)".to_owned()
            };
            self.share_switch(
                ("bring-value", i),
                format!("{}: {}{by}", row.row.what, row.row.value),
                Some(on),
                move |this, on, cx| {
                    if let Some(value) = this.collab.bringing.values.get_mut(i) {
                        value.1 = on;
                    }
                    cx.notify();
                },
                cx,
            )
        });
        let mut card = div()
            .id("collab-bring")
            .min_h_0()
            .overflow_y_scroll()
            .p(self.z(14.0))
            .flex()
            .flex_col()
            .gap(self.z(8.0))
            .child(
                div()
                    .font_weight(FontWeight::BOLD)
                    .child("Bring from your own project"),
            )
            .child(self.muted(
                "The values chosen go into the share as one new change of yours, labelled as \
                 brought by you. Nothing of your own project's history goes with them.",
            ));
        if bringing.reading {
            card = card.child(self.muted("Reading your own project…"));
        } else if bringing.values.is_empty() && bringing.error.is_none() {
            card = card.child(self.muted("Your own project has no values to bring."));
        }
        card.children(lines)
            .children(
                bringing
                    .error
                    .clone()
                    .map(|e| div().text_color(hsla(theme.error)).child(e)),
            )
            .child(
                div()
                    .flex()
                    .items_center()
                    .justify_end()
                    .gap(self.z(6.0))
                    .when(chosen > 0, |d| {
                        d.child(self.muted(bring_text(chosen, &into)).flex_1())
                    })
                    .child(
                        self.collab_button("collab-bring-cancel", "Cancel".to_owned(), false)
                            .on_click(cx.listener(|this, _: &ClickEvent, _, cx| {
                                this.collab.dialog = None;
                                this.collab.bringing = Bringing::default();
                                cx.notify();
                            })),
                    )
                    .child(
                        self.collab_button("collab-bring-go", "Bring".to_owned(), chosen > 0)
                            .on_click(cx.listener(|this, _: &ClickEvent, _, cx| {
                                this.bring_chosen(cx);
                            })),
                    ),
            )
            .into_any_element()
    }

    /// The session panel's Your Edits: those not yet shared, then those
    /// not in this project with their values (Copy; Bring where the role
    /// allows); Bring From Your Own Project….
    pub(crate) fn render_local(&self, cx: &mut Context<Self>) -> AnyElement {
        let local = &self.collab.local;
        if !self.share_open() {
            return self
                .muted("This project is not a share's: every edit is in it.")
                .into_any_element();
        }
        let bring = may_bring(self.collab.role(), self.collab.live()) && self.edits_off().is_none();
        let pending: Vec<Div> = local_rows(&local.pending)
            .into_iter()
            .map(|row| self.local_card(row))
            .collect();
        let apart = local
            .apart
            .iter()
            .zip(local_rows(&local.apart))
            .enumerate()
            .map(|(i, (edit, row))| {
                self.local_card(row)
                    .child(self.apart_buttons(i, edit, bring, cx))
            })
            .collect::<Vec<Div>>();
        let heading = |text: String| div().font_weight(FontWeight::SEMIBOLD).child(text);
        div()
            .flex()
            .flex_col()
            .gap(self.z(8.0))
            .child(heading(format!("Not yet shared ({})", local.pending.len())))
            .child(self.muted(if local.pending.is_empty() {
                "None."
            } else {
                "Shown here on top of the share; the share judges them once you are linked."
            }))
            .children(pending)
            .child(heading(format!(
                "Not in this project ({})",
                local.apart.len()
            )))
            .child(self.muted(if local.apart.is_empty() {
                "None."
            } else if bring {
                "Refused by the share or kept apart: applied to nothing. Copy their values, or \
                 bring them in as a new change of yours."
            } else {
                "Refused by the share or kept apart: applied to nothing. Copy their values."
            }))
            .children(apart)
            .when(bring, |d| {
                d.child(
                    div().flex().justify_end().child(
                        self.collab_button(
                            "local-bring",
                            "Bring From Your Own Project…".to_owned(),
                            false,
                        )
                        .on_click(cx.listener(
                            |this, _: &ClickEvent, window, cx| {
                                this.run(Command::BringValues, window, cx);
                            },
                        )),
                    ),
                )
            })
            .into_any_element()
    }

    /// A local edit's card: what it did, its values.
    fn local_card(&self, row: LocalRow) -> Div {
        let theme = self.theme;
        div()
            .flex()
            .flex_col()
            .gap(self.z(4.0))
            .p(self.z(6.0))
            .rounded(self.z(4.0))
            .border_1()
            .border_color(hsla(theme.border))
            .child(div().font_weight(FontWeight::BOLD).child(row.label))
            .children(row.values.into_iter().map(|value| {
                div()
                    .text_color(hsla(theme.text_muted))
                    .child(format!("{}: {}", value.what, value.value))
            }))
    }

    /// The buttons of `edit`, the `i`th not in this project: Copy its
    /// values; Bring them in as a change of this install's (`bring`: the
    /// role allows it).
    fn apart_buttons(
        &self,
        i: usize,
        edit: &LocalEdit,
        bring: bool,
        cx: &mut Context<Self>,
    ) -> Div {
        let copied = copy_text(edit);
        let again = brought(std::slice::from_ref(edit));
        div()
            .flex()
            .justify_end()
            .gap(self.z(4.0))
            .child(
                self.collab_button(("apart-copy", i), "Copy".to_owned(), false)
                    .on_click(cx.listener(move |_, _: &ClickEvent, _, cx| {
                        cx.write_to_clipboard(ClipboardItem::new_string(copied.clone()));
                    })),
            )
            .when(bring, |d| {
                d.child(
                    self.collab_button(("apart-bring", i), "Bring".to_owned(), false)
                        .on_click(cx.listener(move |this, _: &ClickEvent, _, cx| {
                            if let Err(why) = this.bring(&again) {
                                this.error = Some(why);
                            }
                            cx.notify();
                        })),
                )
            })
    }
}

/// This install's identity (the key signing its changes).
fn my_identity() -> Result<Identity, String> {
    let root = identity::root().ok_or_else(|| binbun_paths::Place::Identity.missing())?;
    Identity::load_or_create(&root)
}

/// `n` values, for people.
fn values_text(n: usize) -> String {
    if n == 1 {
        "1 value".to_owned()
    } else {
        format!("{n} values")
    }
}

/// A joiner's binbun as the approval card says it: another build than
/// this one is view-only in the session.
fn version_text(engine: &EngineVersion) -> String {
    let build = if engine.build.is_empty() {
        String::new()
    } else {
        format!(" ({})", shown_name(&engine.build))
    };
    let other = if *engine == EngineVersion::this() {
        ""
    } else {
        ": another build than yours, view-only in this session"
    };
    format!("binbun {}{build}{other}", shown_name(&engine.release))
}

/// The window's wake: a notification of capacity one (I37), so however
/// often the network side wakes it before it takes its events, one wake
/// waits.
fn wake_channel() -> (async_channel::Sender<()>, async_channel::Receiver<()>) {
    async_channel::bounded(1)
}

/// `ticket`'s QR code: its width and its dark modules.
fn qr(ticket: &str) -> Option<(usize, Vec<bool>)> {
    // Tickets are lower-case base32: upper case fits the alphanumeric
    // mode, smaller; the ticket reads in either case.
    let code = qrcode::QrCode::with_error_correction_level(
        ticket.to_ascii_uppercase().as_bytes(),
        qrcode::EcLevel::L,
    )
    .ok()?;
    let width = code.width();
    let modules = code
        .to_colors()
        .into_iter()
        .map(|color| color == qrcode::Color::Dark)
        .collect();
    Some((width, modules))
}

#[cfg(test)]
mod tests {
    use super::wake_channel;

    /// Wakes the window has not taken yet are one wake, however many
    /// came: a stalled window holds no more for them.
    #[test]
    fn wakes_not_taken_are_one() {
        let (wake, woken) = wake_channel();
        for _ in 0..1000 {
            let _ = wake.try_send(());
        }
        assert_eq!(woken.len(), 1);
        assert!(woken.try_recv().is_ok());
        assert!(wake.try_send(()).is_ok());
    }
}
