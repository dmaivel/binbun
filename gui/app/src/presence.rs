//! The people of a shared session in the window:
//!
//! - **Avatars**: one element everywhere (the title bar, the chat, the
//!   approval card): a filled circle in the person's colour, their initials
//!   centred in the ink that reads best on it. In the title bar they stack,
//!   overlapping, newest last; the one followed is ringed in the accent;
//!   hovering says who and their role; a click opens their card (Follow,
//!   and for the owner Editor, Viewer, Remove). A button beside them shares
//!   the project (in a session, shows the session); right of it, in a
//!   session, the chat's button: a small accent dot while messages came
//!   unseen, a red count instead of mentions of this person.
//!   An agent connected is among them, shared or not: its harness's mark
//!   on its circle (the Bot glyph for one unknown), its card the same.
//! - **Carets**: each other's cursor where it is, at its column in the
//!   listing and the C, a bar in their colour, their line washed in it;
//!   who is on the line, their avatar and name, muted, right after the
//!   line's text (the code is never covered; the pane's edge cuts them).
//! - **Where everyone is**: the session's popover and each one's card say
//!   where they are (function, address, view; a click goes there), and
//!   the listing's scrollbar and the hex overview strip carry a tick in
//!   each one's colour at their address (named in its tooltip; a click
//!   goes there), ticks at about one spot kept apart.
//! - **The status bar** says the session: how many are in it, the link (how
//!   it goes and its round trip; addresses only in its tooltip), a peer's
//!   last change for a while, and the conflicts and refused changes when
//!   there are any (a click opens their list).
//! - **The session panel** is the chat (messages grouped by author, the
//!   session's comings and goings small and muted, their time only in a
//!   tooltip, the times in the user's
//!   zone; the places a message names as links, resolved when it was sent
//!   (`binbun_gui_view::chat`), code in the code font, mentions in the
//!   accent; a message box with `@` completion and Insert Location), or
//!   the conflicts or refused changes the status bar opened.

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::hash::{DefaultHasher, Hash, Hasher};
use std::ops::{Range, RangeInclusive};
use std::rc::Rc;
use std::sync::Arc;
use std::time::{Duration, Instant};

use binbun_gui_view::agents::{self, Face};
use binbun_gui_view::cdoc::CDocument;
use binbun_gui_view::chat;
use binbun_gui_view::collab::{
    AVATAR_INK, Avatar, ChatGroup, ChatItem, ChatText, Colours, Cursor, Person, Place, Role,
    Selection, Trust, Whereabouts, fingerprint, group_chat, initials_size, link_text, local_clock,
    local_full, spread_ticks, stack,
};
use binbun_gui_view::commands::{self, Command};
use binbun_gui_view::feature_map::Across;
use binbun_gui_view::layout::PaneId;
use binbun_gui_view::listing::{Listing, Role as TokenRole, Token};
use binbun_gui_view::selection::{TextPos, item_lines};
use binbun_gui_view::session::Session;
use binbun_gui_view::sharing::pending_text;
use binbun_gui_view::talk::{Dot, Participant, mention_ranges};
use binbun_gui_view::{Node, View};
use binbun_session::journal::{EngineVersion, Key, PublicKey};
use gpui_kit::assets::IconName;
use gpui_kit::base::{TextSelection, Textarea};
use gpui_kit::component::input::{Input, TextareaState};
use gpui_kit::component::tooltip::Tooltip;
use gpui_kit::prelude::*;
use gpui_kit::{
    AnyElement, App, Bounds, ClickEvent, ClipboardItem, Context, Div, ElementId, Entity, Font,
    FontWeight, HighlightStyle, Hsla, InteractiveText, MouseButton, MouseDownEvent, Pixels, Point,
    ScrollAnchor, SharedString, Stateful, StyledText, TextRenderingMode, TextRun, UnderlineStyle,
    Window, canvas, div, font, img, point, px, rgba, svg,
};
use jiff::tz::TimeZone;

use super::{CHAT, ChatJump, CollabUi, PANEL, Popover, Tab, avatar_color, unix_ms};
use crate::collab_net::Net;
use crate::context_menu::OwnItem;
use crate::fonts::{AVATAR_FAMILY, avatar_ink};
use crate::icons::icon;
use crate::listing_view::SCROLLBAR;
use crate::selectable_text::SelectableText;
use crate::theme::{hsla, solid, with_alpha};
use crate::workspace::{ICON, ICON_BUTTON, TAB_PAD, TITLE_PAD, Workspace};

/// How long the status bar says a peer's change or a follow.
const NOTICE: Duration = Duration::from_secs(6);

/// How long the chat message gone to from the chat icon stays washed.
const CHAT_WASH: Duration = Duration::from_millis(1500);

/// The gap between a line's text and the badges of who is on it
/// (logical).
const BADGE_GAP: f32 = 24.0;

/// A map tick's height (logical); two are a pixel more apart at least.
const TICK: f32 = 4.0;

/// How a strip draws the others' ticks.
#[derive(Clone, Copy, Debug)]
pub enum TickStyle {
    /// A scrollbar's or the hex overview's: a short bar across the strip
    /// at its far edge.
    Bar,
    /// The feature map's: a tick across its band, edged in the panel's
    /// colour so it reads on any band, and an arrow in the lane beside it
    /// (where these lie across the strip).
    Band(Across),
}

/// The places of the last frame that show the others' cursors: the
/// strips with their ticks and the lines in view with their carets and
/// selections. A move of theirs that leaves what these show as it is
/// needs no frame (`Workspace::poll_collab`).
#[derive(Default)]
pub struct Drawn {
    sites: RefCell<Vec<Site>>,
}

impl Drawn {
    /// A new frame: none yet.
    pub fn clear(&self) {
        self.sites.borrow_mut().clear();
    }

    fn push(&self, site: Site) {
        self.sites.borrow_mut().push(site);
    }
}

/// Where a cursor is along a strip (0 to 1), if on it.
type Fraction = Rc<dyn Fn(&Cursor) -> Option<f32>>;

/// A place of a frame that shows the others' cursors.
enum Site {
    /// A strip `length` long, its ticks `long` along it, `fraction`
    /// placing a cursor on it.
    Ticks {
        length: f32,
        long: f32,
        fraction: Fraction,
    },
    /// A listing's lines in view.
    Listing {
        listing: Arc<Listing>,
        lines: Range<u64>,
    },
    /// A C document's lines in view.
    C {
        document: Arc<CDocument>,
        lines: Range<usize>,
    },
}

/// The ink on every avatar ([`AVATAR_INK`]).
fn ink() -> Hsla {
    rgba((AVATAR_INK << 8) | 0xff).into()
}

/// Paints `initials` (or the stack's `+N`) in `color` centred on the
/// avatar circle `bounds`, Gmail's way: across by their ink (the outlines' bounds, not the
/// advance), down by their capitals (the baseline half the capitals'
/// height below the centre, so descenders such as Q's tail hang below);
/// sized by [`initials_size`] so both land on pixel edges. Antialiased in
/// grey: the LCD antialiasing of the rest of the text fringes them in
/// colour on the circle (GPUI's mode is the application's, read as each
/// glyph is painted, so it is switched around these alone).
fn paint_initials(
    initials: &str,
    color: Hsla,
    bounds: Bounds<Pixels>,
    window: &mut Window,
    cx: &mut App,
) {
    let text_system = Rc::clone(window.text_system());
    let face = Font {
        weight: FontWeight::MEDIUM,
        ..font(AVATAR_FAMILY)
    };
    let font_id = text_system.resolve_font(&face);
    let scale = window.scale_factor();
    let (size, cap) = initials_size(
        f32::from(bounds.size.height) * scale,
        f32::from(text_system.cap_height(font_id, px(1.0))),
        initials.chars().count(),
    );
    let size = px(size / scale);
    let run = TextRun {
        len: initials.len(),
        font: face,
        color,
        background_color: None,
        underline: None,
        strikethrough: None,
    };
    let line = text_system.shape_line(initials.to_owned().into(), size, &[run], None);
    // The ink's left and right edges from the pen's start.
    let (mut left, mut right) = (f32::INFINITY, f32::NEG_INFINITY);
    for glyph in line.runs.iter().flat_map(|run| &run.glyphs) {
        let letter = initials.get(glyph.index..).and_then(|s| s.chars().next());
        if let Some((l, r)) = letter.and_then(avatar_ink) {
            let x = f32::from(glyph.position.x);
            left = left.min(l.mul_add(f32::from(size), x));
            right = right.max(r.mul_add(f32::from(size), x));
        }
    }
    if left > right {
        (left, right) = (0.0, f32::from(line.width));
    }
    let centre = bounds.center();
    let pen = point(
        centre.x - px(f32::midpoint(left, right)),
        centre.y + px(cap / scale / 2.0),
    );
    let mode = cx.text_rendering_mode();
    cx.set_text_rendering_mode(TextRenderingMode::Grayscale);
    for run in &line.runs {
        for glyph in &run.glyphs {
            // A glyph the atlas cannot take is left out, as GPUI's text does.
            let _ = window.paint_glyph(pen + glyph.position, run.font_id, glyph.id, size, color);
        }
    }
    cx.set_text_rendering_mode(mode);
}

/// The column, in characters, of token `index` on a listing line of
/// `tokens` (of a gap between tokens, where the token after it starts);
/// with none, of the line's first token after its address (the mnemonic,
/// a label, a directive).
pub fn token_column(tokens: &[Token], index: Option<usize>) -> u32 {
    let chars = |tokens: &[Token]| tokens.iter().map(|t| t.text.chars().count()).sum::<usize>();
    let column = match index {
        Some(i) => {
            let gap = tokens.get(i).is_some_and(|t| t.role == TokenRole::Space);
            chars(tokens.get(..i + usize::from(gap)).unwrap_or(tokens))
        }
        None => tokens
            .iter()
            .position(|t| !matches!(t.role, TokenRole::Prefix | TokenRole::Space))
            .map_or(0, |i| chars(tokens.get(..i).unwrap_or(tokens))),
    };
    u32::try_from(column).unwrap_or(u32::MAX)
}

/// The column, in characters, of C line `line`'s span `span` (if it is on
/// it), else of the line's first character after its indentation.
pub fn c_column(document: &CDocument, line: usize, span: Option<usize>) -> u32 {
    let Some(l) = document.lines.get(line) else {
        return 0;
    };
    let start = span
        .and_then(|s| document.spans.get(s))
        .map(|s| s.range.start)
        .filter(|start| l.range.contains(start));
    let chars = match start {
        Some(start) => document
            .text
            .get(l.range.start..start)
            .map_or(0, |t| t.chars().count()),
        None => document
            .text
            .get(l.range.clone())
            .map_or(0, |t| t.chars().take_while(|c| c.is_whitespace()).count()),
    };
    u32::try_from(chars).unwrap_or(u32::MAX)
}

/// Someone's caret on a line: their column (`None`: where the line's code
/// starts), who, in their colour on the theme.
#[derive(Clone, Debug)]
pub struct RemoteCaret {
    /// Their column on the line.
    pub column: Option<u32>,
    /// Their avatar (colour, initials).
    pub avatar: Avatar,
    /// Their name.
    pub name: String,
    /// Their colour on the theme.
    pub color: Hsla,
}

impl RemoteCaret {
    /// `person`'s caret, at `column` if their cursor's column is known, in
    /// their colour of `colours` on a dark theme or a light one.
    fn of(person: &Person, column: Option<u32>, colours: &Colours, dark: bool) -> Self {
        let avatar = person.avatar(colours);
        Self {
            column,
            color: avatar_color(&avatar, dark),
            avatar,
            name: person.name.clone(),
        }
    }
}

/// A caret drawn at `x`, `y` (in its pane) on a line `row_h` high: a bar
/// in `color` (someone's, or the theme's caret colour for one's own); who
/// another's is says [`Workspace::line_badges`].
pub fn caret_bar(color: Hsla, (x, y, row_h): (f32, f32, f32)) -> AnyElement {
    div()
        .absolute()
        .left(px(x - 1.0))
        .top(px(y))
        .w(px(2.0))
        .h(px(row_h))
        .bg(color)
        .into_any_element()
}

/// A faint wash of `caret`'s colour over a line `row_h` high.
pub fn caret_wash(caret: &RemoteCaret, row_h: f32) -> AnyElement {
    div()
        .absolute()
        .top_0()
        .left_0()
        .right_0()
        .h(px(row_h))
        .bg(caret.color.opacity(0.12))
        .into_any_element()
}

/// A wash of `color` over a row `row_h` high from `left`, `width` wide
/// (none: to the row's end): a selection's, drawn under the row's text.
pub fn selection_wash(color: Hsla, (left, width): (f32, Option<f32>), row_h: f32) -> AnyElement {
    let wash = div()
        .absolute()
        .top_0()
        .left(px(left))
        .h(px(row_h))
        .bg(color);
    match width {
        Some(width) => wash.w(px(width)),
        None => wash.right_0(),
    }
    .into_any_element()
}

/// The colour of `avatar`'s selection on a dark theme or a light one: a
/// faint wash of theirs.
fn others_selection(avatar: &Avatar, dark: bool) -> Hsla {
    avatar_color(avatar, dark).opacity(0.10)
}

/// What `person`'s card says under their name, and the version below it
/// (whether it is another build): an agent "Agent" (and its role in a
/// session if another) and its harness's version if it said; a person
/// their role and their binbun.
fn card_header(person: &Person) -> (String, Option<String>, bool) {
    if let Some(agent) = &person.agent {
        (
            match person.role {
                None | Some(Role::Agent) => "Agent".to_owned(),
                Some(role) => format!("Agent \u{b7} {}", role.name()),
            },
            agent
                .version
                .as_ref()
                .map(|v| format!("{} {v}", person.name)),
            false,
        )
    } else {
        let (version, other) = person.version(&EngineVersion::this());
        (
            person.role.map_or("joining", Role::name).to_owned(),
            Some(version),
            other,
        )
    }
}

impl CollabUi {
    /// Whether `which` was closed by this very press (its own button's).
    pub(crate) fn just_dismissed(&self, which: Popover) -> bool {
        self.dismissed.is_some_and(|(was, at)| {
            at.elapsed() < Duration::from_millis(300)
                && match (was, which) {
                    (Popover::Person(a), Popover::Person(b)) => a == b,
                    (Popover::Session { .. }, Popover::Session { .. }) => true,
                    (Popover::Person(_), Popover::Session { .. })
                    | (Popover::Session { .. }, Popover::Person(_)) => false,
                }
        })
    }

    /// Closes the popover (a press outside it), noting which and when.
    pub(crate) fn dismiss(&mut self) {
        if let Some(popover) = self.popover.take() {
            self.dismissed = Some((popover, Instant::now()));
        }
    }

    /// Keeps `item` in the chat (the last [`CHAT`]).
    pub(crate) fn say(&mut self, item: ChatItem) {
        self.chat.push_back(item);
        while self.chat.len() > CHAT {
            self.chat.pop_front();
        }
    }
}

impl Workspace {
    // ---- presence's bookkeeping ----

    /// Where `cursor` is: its function (by the name shown), address and
    /// view.
    pub(crate) fn whereabouts(&self, cursor: &Cursor) -> Whereabouts {
        let function = match cursor.place {
            Place::C { function, .. } | Place::Graph { function } => Some(function),
            Place::Listing | Place::Hex | Place::Xrefs => self
                .listing
                .as_ref()
                .and_then(|l| l.function_of(cursor.address))
                .map(|(_, entry)| entry),
        };
        let name = function.map(|entry| {
            self.listing
                .as_ref()
                .zip(self.session.as_ref())
                .and_then(|(l, s)| l.shown_name(entry, s.overlay()).map(str::to_owned))
                .unwrap_or_else(|| format!("sub_{entry:X}"))
        });
        Whereabouts::of(cursor, name)
    }

    /// Goes where `key`'s cursor is, in the focused pane, as following
    /// would, without following them (following another stops).
    pub(crate) fn go_to_person(&mut self, key: PublicKey) {
        let Some(cursor) = self
            .collab
            .people
            .iter()
            .find(|p| p.key == key)
            .and_then(|p| p.cursor)
        else {
            return;
        };
        if self.collab.follow.leader() != Some(key) {
            self.unfollow();
        }
        self.land_on(cursor);
    }

    /// The column of the listing's cursor on line `line` (its token's).
    pub(crate) fn listing_column(&self, line: u64, token: Option<usize>) -> u32 {
        let (Some(listing), Some(session)) = (&self.listing, &self.session) else {
            return 0;
        };
        let Some(db) = session.database() else {
            return 0;
        };
        token_column(&listing.render(db, line, session.overlay()).tokens, token)
    }

    /// The name the engine gives `key` where the user gave none (`v15`,
    /// `g_1299a8`, `sub_1E680`), as the views showed it before a peer's
    /// change.
    pub(crate) fn engine_name(&self, key: &Key) -> Option<String> {
        let session = self.session.as_ref()?;
        match key {
            Key::FunctionName(entry) => Some(
                session
                    .database()
                    .and_then(|db| db.name(*entry).map(str::to_owned))
                    .unwrap_or_else(|| format!("sub_{entry:X}")),
            ),
            Key::GlobalName(address) => Some(
                session
                    .database()
                    .and_then(|db| db.name(*address).map(str::to_owned))
                    .unwrap_or_else(|| format!("g_{address:x}")),
            ),
            Key::VariableName(variable) => {
                // The C shown before the change, if kept: the variable's
                // token there.
                let (function, _) = self.listing.as_ref()?.function_of(variable.function)?;
                let core = session.core();
                [View::Reading, View::Exact].into_iter().find_map(|view| {
                    let document = session.document(function, view)?;
                    document.spans.iter().find_map(|span| {
                        let Some(Node::Var(var)) = span.node else {
                            return None;
                        };
                        (core.variable(function, view, var).ok().as_ref() == Some(variable))
                            .then(|| document.text.get(span.range.clone()).map(str::to_owned))
                            .flatten()
                    })
                })
            }
            Key::Slot(..)
            | Key::Comment(_)
            | Key::Bookmark(..)
            | Key::Number(..)
            | Key::Type(_)
            | Key::Definition(_)
            | Key::Item(_)
            | Key::Bounds(_)
            | Key::DebugFile
            | Key::Thread(_)
            | Key::Post(_)
            | Key::Suggestion(_)
            | Key::Signature(_) => None,
        }
    }

    /// The people came and gone since the last look (`before`: the people
    /// then, whose names those gone go by): the avatars' order kept
    /// (newest last), a line in the chat for each while in a session. In
    /// time linear in the people.
    pub(crate) fn note_comings_and_goings(&mut self, before: &[Person]) {
        let time = u64::try_from(unix_ms()).unwrap_or(u64::MAX);
        let live = self.collab.live();
        let now: HashSet<PublicKey> = self.collab.people.iter().map(|p| p.key).collect();
        let was: HashMap<PublicKey, &str> =
            before.iter().map(|p| (p.key, p.name.as_str())).collect();
        let mut ordered: HashSet<PublicKey> = HashSet::with_capacity(now.len());
        let mut order = Vec::with_capacity(now.len());
        let mut lines = Vec::new();
        for key in &self.collab.order {
            if now.contains(key) {
                ordered.insert(*key);
                order.push(*key);
            } else if live {
                let name = was
                    .get(key)
                    .map_or_else(|| self.person_name(*key), |name| (*name).to_owned());
                lines.push(format!("{name} left"));
            }
        }
        for person in &self.collab.people {
            if ordered.insert(person.key) {
                order.push(person.key);
                if live {
                    let me = self
                        .collab
                        .net
                        .as_ref()
                        .is_some_and(|net| net.me() == person.key);
                    let name = if me { "You" } else { person.name.as_str() };
                    lines.push(format!("{name} joined"));
                }
            }
        }
        self.collab.order = order;
        for text in lines {
            self.collab.say(ChatItem::System { text, time });
        }
    }

    /// Draws the window again once the status bar's notice is to go.
    pub(crate) fn drop_notice_later(&mut self, cx: &mut Context<Self>) {
        let Some((_, at)) = &self.collab.notice else {
            return;
        };
        let left = NOTICE.saturating_sub(at.elapsed());
        self.collab.notice_timer = Some(cx.spawn(async move |this, cx| {
            cx.background_executor()
                .timer(left + Duration::from_millis(50))
                .await;
            let _ = this.update(cx, |_, cx| cx.notify());
        }));
    }

    // ---- avatars ----

    /// The avatar of `avatar`, `size` logical pixels across: a filled
    /// circle in its colour, its initials centred ([`paint_initials`]).
    /// An agent's has its face in place of the initials, as large: its
    /// harness's mark in the initials' ink (its single-colour form drawn
    /// as a mask: rasterized at the device's scale, crisp), or in its own
    /// colours where every one reads on the circle; else the Bot glyph in
    /// the ink.
    pub(crate) fn avatar_circle(&self, avatar: &Avatar, size: f32) -> Div {
        let dark = self.theme.dark;
        let circle = div()
            .size(self.z(size))
            .flex_none()
            .rounded_full()
            .bg(avatar_color(avatar, dark));
        match avatar.agent {
            Some(Face::Mark(mark)) => {
                let drawn = agents::drawn(&mark, avatar.slot, dark);
                // The file is framed square on its ink (`icons.rs`): drawn
                // the circle's size, on the circle's device pixels, its ink
                // is centred on it.
                let face = match drawn.tint {
                    Some(rgb) => svg()
                        .path(drawn.file)
                        .size_full()
                        .text_color(Hsla::from(rgba((rgb << 8) | 0xff)))
                        .into_any_element(),
                    None => img(drawn.file).size_full().into_any_element(),
                };
                return circle.child(face);
            }
            Some(Face::Bot) => {
                return circle.flex().items_center().justify_center().child(icon(
                    IconName::Bot,
                    self.z(size * 0.6),
                    ink(),
                ));
            }
            None => {}
        }
        let initials = avatar.initials.clone();
        let color = ink();
        circle.child(
            canvas(
                |_, _, _| {},
                move |bounds, (), window, cx| {
                    paint_initials(&initials, color, bounds, window, cx);
                },
            )
            .size_full(),
        )
    }

    /// The title bar's right side: the others' avatars, stacked newest
    /// last, then the session's button (Share, or the chat once in one).
    pub fn collab_titlebar(&self, cx: &mut Context<Self>) -> Vec<AnyElement> {
        let theme = self.theme;
        let leader = self.collab.follow.leader();
        let (shown, hidden) = stack(&self.collab.order, leader);
        let people: Vec<&Person> = shown
            .iter()
            .filter_map(|key| self.collab.people.iter().find(|p| p.key == *key))
            .collect();
        let mut avatars: Vec<AnyElement> = people
            .into_iter()
            .enumerate()
            .map(|(i, person)| {
                let key = person.key;
                let impostor = person.agent.is_none()
                    && matches!(self.trust_of(person), Trust::Impostor { .. });
                let ring = if impostor {
                    theme.error
                } else if leader == Some(key) {
                    theme.accent
                } else {
                    // A ring of the bar's own colour parts the overlapping
                    // circles.
                    theme.background
                };
                let followed = if leader == Some(key) {
                    ", followed"
                } else {
                    ""
                };
                let tip = match &person.agent {
                    // `Codex 0.42 — agent`.
                    Some(agent) => format!(
                        "{}{} \u{2014} {}{followed}",
                        person.name,
                        agent
                            .version
                            .as_ref()
                            .map(|v| format!(" {v}"))
                            .unwrap_or_default(),
                        person.role.map_or("agent", Role::name),
                    ),
                    None => format!(
                        "{} \u{2014} {}{followed}",
                        person.name,
                        person.role.map_or("joining", Role::name),
                    ),
                };
                div()
                    .id(("avatar", i))
                    .flex_none()
                    .rounded_full()
                    .border_2()
                    .border_color(hsla(ring))
                    .when(i > 0, |d| d.ml(self.z(-6.0)))
                    .cursor_pointer()
                    .tooltip(move |window, cx| Tooltip::new(tip.clone()).build(window, cx))
                    .on_mouse_down(MouseButton::Left, |_, window, cx| {
                        window.prevent_default();
                        cx.stop_propagation();
                    })
                    .on_click(cx.listener(move |this, _: &ClickEvent, _, cx| {
                        let card = Popover::Person(key);
                        this.collab.popover = if this.collab.popover == Some(card)
                            || this.collab.just_dismissed(card)
                        {
                            None
                        } else {
                            Some(card)
                        };
                        cx.notify();
                    }))
                    .child(self.avatar_circle(&person.avatar(&self.collab.colours), 20.0))
                    .into_any_element()
            })
            .collect();
        if hidden > 0 {
            avatars.push(self.more_chip(hidden, cx));
        }
        let enabled = self.session.is_some();
        // Share; in a session, its popover (the chat: the status bar's).
        let button = self
            .icon_button(
                "collab-button",
                IconName::Users,
                Command::ShareProject,
                enabled,
                matches!(self.collab.popover, Some(Popover::Session { .. })),
                cx,
            )
            .ml(self.z(6.0))
            .into_any_element();
        // Avatars · chat · share.
        let mut out = vec![
            div()
                .flex()
                .items_center()
                .children(avatars)
                .into_any_element(),
        ];
        if self.collab.live() {
            out.push(self.chat_button(cx));
        }
        out.push(button);
        out
    }

    /// A surface's notification dot on its button's top-right corner (over
    /// it, nothing moves): the accent for `Dot::Unread`, red for a mention.
    pub(crate) fn notification_dot(&self, dot: Dot) -> Div {
        let theme = self.theme;
        div()
            .absolute()
            .top(self.z(3.0))
            .right(self.z(3.0))
            .size(self.z(7.0))
            .rounded_full()
            .border_1()
            .border_color(hsla(theme.background))
            .bg(hsla(match dot {
                Dot::Mention => theme.error,
                Dot::Unread => theme.accent,
            }))
    }

    /// The title bar's chat button, in a session only, the chat's
    /// notification place: its dot in the accent while chat messages are
    /// unread, red while a mention of this person in the chat is not seen.
    /// A click goes to the newest mention, else shows or hides the chat (as
    /// Ctrl+K S).
    fn chat_button(&self, cx: &mut Context<Self>) -> AnyElement {
        let theme = self.theme;
        let open = self.collab.panel == Some(Tab::Chat);
        let mark = self
            .collab
            .unread
            .dot()
            .map(|dot| self.notification_dot(dot));
        div()
            .id("chat-button")
            .relative()
            .flex()
            .flex_none()
            .items_center()
            .justify_center()
            .ml(self.z(2.0))
            .size(self.z(ICON_BUTTON))
            .rounded(self.z(4.0))
            .when(open, |d| d.bg(hsla(theme.element_selected)))
            .hover(|s| s.bg(hsla(theme.element_hover)))
            .tooltip(self.key_tooltip("Chat", Command::SessionPanel))
            .on_mouse_down(MouseButton::Left, |_, window, cx| {
                window.prevent_default();
                cx.stop_propagation();
            })
            .on_click(cx.listener(|this, _: &ClickEvent, _, cx| {
                match this.collab.unread.newest() {
                    Some(id) => this.jump_to_chat(id, cx),
                    None => {
                        this.collab.panel = if this.collab.panel == Some(Tab::Chat) {
                            None
                        } else {
                            Some(Tab::Chat)
                        };
                    }
                }
                cx.notify();
            }))
            .child(icon(
                IconName::MessageSquare,
                self.z(ICON),
                hsla(if open { theme.text } else { theme.text_muted }),
            ))
            .children(mark)
            .into_any_element()
    }

    /// Shows the chat scrolled to message `id` (a mention of this person),
    /// the message washed in the accent for a moment.
    fn jump_to_chat(&mut self, id: u64, cx: &mut Context<Self>) {
        self.collab.panel = Some(Tab::Chat);
        let timer = cx.spawn(async move |this, cx| {
            cx.background_executor().timer(CHAT_WASH).await;
            let _ = this.update(cx, |this, cx| {
                this.collab.chat_jump = None;
                cx.notify();
            });
        });
        self.collab.chat_jump = Some(ChatJump {
            id,
            anchor: ScrollAnchor::for_handle(self.collab.chat_scroll.clone()),
            pending: true,
            _timer: timer,
        });
    }

    /// Chat message `id`'s `line`, anchored for the chat's scroll and
    /// washed in the accent while it is the one gone to ([`ChatJump`]).
    fn jumped_to(&self, line: Stateful<Div>, id: u64) -> Stateful<Div> {
        match &self.collab.chat_jump {
            Some(jump) if jump.id == id => line
                .anchor_scroll(Some(jump.anchor.clone()))
                .bg(hsla(with_alpha(self.theme.accent, 0x30)))
                .rounded(self.z(3.0)),
            _ => line,
        }
    }

    /// The card of the avatar clicked: who, their role and binbun; Follow,
    /// and for the owner their role controls.
    pub fn render_avatar_popover(&self, cx: &mut Context<Self>) -> Option<AnyElement> {
        let Some(Popover::Person(key)) = self.collab.popover else {
            return None;
        };
        let person = self.collab.people.iter().find(|p| p.key == key)?;
        let theme = self.theme;
        let owner = self.collab.net.as_ref().and_then(Net::role) == Some(Role::Owner);
        let following = self.collab.follow.leader() == Some(key);
        let cursor = person.cursor;
        let (what, version, other) = card_header(person);
        let buttons = div().flex().child(
            self.collab_button(
                "popover-follow",
                if following {
                    "Stop following"
                } else {
                    "Follow"
                }
                .to_owned(),
                !following,
            )
            .on_click(cx.listener(move |this, _: &ClickEvent, _, cx| {
                this.collab.popover = None;
                this.follow_person(key, cursor);
                cx.notify();
            })),
        );
        // The owner's say over the others: a row of its own.
        let roles = (owner && person.role.is_some_and(|r| r != Role::Owner)).then(|| {
            div()
                .flex()
                .gap(self.z(4.0))
                .pt(self.z(6.0))
                .border_t_1()
                .border_color(hsla(theme.border))
                .children(self.role_buttons(0, key, person.role, person.agent.is_some(), cx))
        });
        Some(
            div()
                .id("avatar-popover")
                .absolute()
                .top(self.bar(TITLE_PAD))
                .right(self.z(8.0))
                .w(self.z(280.0))
                .p(self.z(12.0))
                .flex()
                .flex_col()
                .gap(self.z(6.0))
                .bg(hsla(theme.panel))
                .border_1()
                .border_color(hsla(theme.border))
                .rounded(self.z(8.0))
                .shadow_lg()
                .on_any_mouse_down(|_, _, cx| cx.stop_propagation())
                .on_mouse_down_out(cx.listener(|this, _, _, cx| {
                    this.collab.dismiss();
                    cx.notify();
                }))
                .child(
                    div()
                        .flex()
                        .items_center()
                        .gap(self.z(8.0))
                        .child(self.avatar_circle(&person.avatar(&self.collab.colours), 32.0))
                        .child(
                            div()
                                .flex()
                                .flex_col()
                                .child(
                                    div()
                                        .font_weight(FontWeight::BOLD)
                                        .child(person.name.clone()),
                                )
                                .child(self.muted(what)),
                        ),
                )
                .children(version.map(|version| {
                    div()
                        .text_color(hsla(if other { theme.error } else { theme.text_muted }))
                        .child(if other {
                            format!("{version}: another build, view-only")
                        } else {
                            version
                        })
                }))
                .children(cursor.map(|cursor| {
                    let location = self.whereabouts(&cursor);
                    self.location_row("popover-where", key, &location, cx)
                        .child(self.location_line(&location))
                }))
                .children(person.view_only.clone().map(|why| {
                    div()
                        .text_color(hsla(theme.error))
                        .child(format!("View-only: {why}"))
                }))
                .child(self.muted(format!("Fingerprint {}", fingerprint(key))))
                .child(buttons)
                .children(roles)
                .into_any_element(),
        )
    }

    /// One of the session's people: avatar, name, role.
    fn person_line(&self, avatar: &Avatar, name: String, you: bool, role: &str) -> Div {
        div()
            .flex()
            .items_center()
            .gap(self.z(8.0))
            .child(self.avatar_circle(avatar, 20.0))
            .child(div().text_color(hsla(self.theme.text)).child(name))
            .when(you, |d| d.child(self.muted("you")))
            .child(div().flex_1())
            .child(self.muted(role.to_owned()))
    }

    /// Where someone is, in one muted line: their function, address (in
    /// the code font) and view.
    fn location_line(&self, location: &Whereabouts) -> Div {
        let dot = || div().flex_none().child("\u{b7}");
        div()
            .flex()
            .items_center()
            .min_w_0()
            .gap(self.z(4.0))
            .text_size(self.z(11.5))
            .text_color(hsla(self.theme.text_muted))
            .whitespace_nowrap()
            .children(location.function.clone().map(|function| {
                div()
                    .min_w_0()
                    .overflow_hidden()
                    .text_ellipsis()
                    .child(function)
            }))
            .children(location.function.is_some().then(dot))
            .child(
                div()
                    .flex_none()
                    .font_family(self.settings.code_font.clone())
                    .child(location.address.clone()),
            )
            .child(dot())
            .child(div().flex_none().child(location.view))
    }

    /// A row that goes where `key` is when clicked (closing the popover),
    /// lit under the pointer.
    fn location_row(
        &self,
        id: impl Into<ElementId>,
        key: PublicKey,
        location: &Whereabouts,
        cx: &mut Context<Self>,
    ) -> Stateful<Div> {
        let tip = format!("Go to {}", location.text());
        div()
            .id(id)
            .flex()
            .flex_col()
            .gap(self.z(2.0))
            .mx(self.z(-6.0))
            .px(self.z(6.0))
            .py(self.z(3.0))
            .rounded(self.z(4.0))
            .cursor_pointer()
            .hover(|s| s.bg(hsla(self.theme.element_hover)))
            .tooltip(move |window, cx| Tooltip::new(tip.clone()).build(window, cx))
            .on_click(cx.listener(move |this, _: &ClickEvent, _, cx| {
                this.collab.popover = None;
                this.go_to_person(key);
                cx.notify();
            }))
    }

    /// The session's popover (the title bar's button while in one): for
    /// the host the ticket and its QR code, who is in, what it sends and
    /// Stop sharing; for a joiner who is in and Leave.
    pub fn render_session_popover(&self, cx: &mut Context<Self>) -> Option<AnyElement> {
        let Some(Popover::Session { .. }) = self.collab.popover else {
            return None;
        };
        let net = self.collab.net.as_ref()?;
        let theme = self.theme;
        let hosting = net.hosting();
        let me = self.collab.colours.avatar(net.me(), &self.collab.my_name);
        let my_role = net.role().map_or("joining", Role::name);
        let people: Vec<AnyElement> = self
            .collab
            .order
            .iter()
            .filter_map(|key| self.collab.people.iter().find(|p| p.key == *key))
            .enumerate()
            .map(|(i, p)| {
                let role = p.role.map_or(
                    if p.agent.is_some() {
                        "agent"
                    } else {
                        "joining"
                    },
                    Role::name,
                );
                let face = p.avatar(&self.collab.colours);
                let line = self.person_line(&face, p.name.clone(), false, role);
                match p.cursor.map(|cursor| self.whereabouts(&cursor)) {
                    Some(location) => self
                        .location_row(("person-where", i), p.key, &location, cx)
                        .child(line)
                        .child(self.location_line(&location).pl(self.z(28.0)))
                        .into_any_element(),
                    None => line.into_any_element(),
                }
            })
            .collect();
        let mut card = div()
            .id("session-popover")
            .absolute()
            .top(self.bar(TITLE_PAD))
            .right(self.z(8.0))
            .w(self.z(if hosting { 400.0 } else { 280.0 }))
            .p(self.z(12.0))
            .flex()
            .flex_col()
            .gap(self.z(8.0))
            .bg(hsla(theme.panel))
            .border_1()
            .border_color(hsla(theme.border))
            .rounded(self.z(8.0))
            .shadow_lg()
            .on_any_mouse_down(|_, _, cx| cx.stop_propagation())
            .on_mouse_down_out(cx.listener(|this, _, _, cx| {
                this.collab.dismiss();
                cx.notify();
            }))
            .child(div().font_weight(FontWeight::BOLD).child(if hosting {
                "Sharing this project"
            } else {
                "In the session"
            }))
            .child(
                div()
                    .flex()
                    .flex_col()
                    .gap(self.z(6.0))
                    .child(self.person_line(&me, self.collab.my_name.clone(), true, my_role))
                    .children(people),
            );
        let rule = || div().h(px(1.0)).bg(hsla(theme.border));
        if let Some(members) = self.render_members(cx) {
            card = card.child(rule()).child(members);
        }
        if hosting {
            if let Some(ticket) = &self.collab.ticket {
                card = card
                    .child(rule())
                    .child(
                        self.muted("Anyone holding this ticket can ask to join; you approve each."),
                    )
                    .child(self.ticket_code(ticket))
                    .child(self.admit_known_toggle(cx))
                    .child(self.render_sends(cx))
                    .child(self.stop_row(ticket, cx));
            }
        } else {
            card = card.child(rule()).child(
                div().flex().justify_end().child(
                    self.collab_button("session-leave", "Leave session".to_owned(), false)
                        .on_click(cx.listener(|this, _: &ClickEvent, window, cx| {
                            this.leave_session(None, cx);
                            this.close_overlays(window, cx);
                        })),
                ),
            );
        }
        Some(card.into_any_element())
    }

    /// The owner's Members row: the shared project's members (who is not
    /// in the session too), and a field to add one by their identity
    /// card; why one was not added in the error colour. None for the
    /// others.
    pub(crate) fn render_members(&self, cx: &mut Context<Self>) -> Option<Div> {
        let net = self.collab.net.as_ref()?;
        if net.role() != Some(Role::Owner) {
            return None;
        }
        let theme = self.theme;
        let me = net.me();
        let rows = self.collab.members.iter().map(|&(key, role)| {
            let name = if key == me {
                self.collab.my_name.clone()
            } else {
                self.person_name(key)
            };
            let face = self.face(key, &name);
            self.person_line(&face, name, key == me, role.name())
        });
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
        Some(
            div()
                .flex()
                .flex_col()
                .gap(self.z(6.0))
                .child(self.muted("Members"))
                .children(rows)
                .children(field)
                .children(
                    self.collab
                        .member_error
                        .clone()
                        .map(|e| div().text_color(hsla(theme.error)).child(e)),
                ),
        )
    }

    // ---- carets ----

    /// The stack's last place when more came than it shows: "+N", opening
    /// the session's popover (everyone).
    fn more_chip(&self, hidden: usize, cx: &mut Context<Self>) -> AnyElement {
        let theme = self.theme;
        let tip = format!("{hidden} more in the session");
        let more = format!("+{hidden}");
        let color = hsla(theme.text);
        div()
            .id("avatar-more")
            .flex_none()
            .rounded_full()
            .border_2()
            .border_color(hsla(theme.background))
            .ml(self.z(-6.0))
            .cursor_pointer()
            .tooltip(move |window, cx| Tooltip::new(tip.clone()).build(window, cx))
            .on_click(cx.listener(|this, _: &ClickEvent, window, cx| {
                this.run(Command::ShareProject, window, cx);
            }))
            .child(
                div()
                    .size(self.z(20.0))
                    .rounded_full()
                    .bg(hsla(theme.element_selected))
                    // Set as the avatars' initials are, beside them.
                    .child(
                        canvas(
                            |_, _, _| {},
                            move |bounds, (), window, cx| {
                                paint_initials(&more, color, bounds, window, cx);
                            },
                        )
                        .size_full(),
                    ),
            )
            .into_any_element()
    }

    /// The colour of one's own caret: the theme's caret colour, at half
    /// strength in a pane without the focus.
    pub fn own_caret(&self, focused: bool) -> Hsla {
        let color = hsla(self.theme.accent);
        if focused { color } else { color.opacity(0.5) }
    }

    /// The others' carets on the listing's lines, by line: their column
    /// where their cursor is in the listing, else where the line starts.
    pub fn listing_carets(&self, listing: &Listing) -> HashMap<u64, Vec<RemoteCaret>> {
        let mut carets: HashMap<u64, Vec<RemoteCaret>> = HashMap::new();
        for person in &self.collab.people {
            if let Some(cursor) = person.cursor {
                let column = matches!(cursor.place, Place::Listing).then_some(cursor.column);
                carets
                    .entry(listing.line_of(cursor.address))
                    .or_default()
                    .push(RemoteCaret::of(
                        person,
                        column,
                        &self.collab.colours,
                        self.theme.dark,
                    ));
            }
        }
        carets
    }

    /// The others' carets on `document`'s lines, by line: their C line and
    /// column where they read the same function in the same view, else the
    /// line of their address if it is in it (where its code starts).
    pub fn c_carets(&self, document: &CDocument) -> HashMap<usize, Vec<RemoteCaret>> {
        let mut carets: HashMap<usize, Vec<RemoteCaret>> = HashMap::new();
        for person in &self.collab.people {
            let Some(cursor) = person.cursor else {
                continue;
            };
            let (line, column) = match cursor.place {
                Place::C {
                    function,
                    reading,
                    line,
                } if function == document.entry && reading == (document.view == View::Reading) => {
                    (usize::try_from(line).ok(), Some(cursor.column))
                }
                Place::Listing
                | Place::C { .. }
                | Place::Hex
                | Place::Graph { .. }
                | Place::Xrefs => (
                    self.listing
                        .as_ref()
                        .and_then(|l| l.function_of(cursor.address))
                        .filter(|(f, _)| *f == document.function)
                        .and_then(|_| document.line_for(cursor.address)),
                    None,
                ),
            };
            if let Some(line) = line {
                carets.entry(line).or_default().push(RemoteCaret::of(
                    person,
                    column,
                    &self.collab.colours,
                    self.theme.dark,
                ));
            }
        }
        carets
    }

    /// The others' selections of addresses on the listing: the lines of
    /// their items, each with its wash.
    pub fn listing_selections(&self, listing: &Listing) -> Vec<(RangeInclusive<u64>, Hsla)> {
        self.collab
            .people
            .iter()
            .filter_map(|person| {
                let Some(Selection::Addresses { first, last }) = person.cursor?.selection else {
                    return None;
                };
                let lines = item_lines(listing, first.min(last), first.max(last));
                Some((
                    lines,
                    others_selection(&person.avatar(&self.collab.colours), self.theme.dark),
                ))
            })
            .collect()
    }

    /// The others' selections of `document`'s text (theirs where they read
    /// its function in its view): where each starts and ends, with its
    /// wash.
    pub fn c_selections(&self, document: &CDocument) -> Vec<((TextPos, TextPos), Hsla)> {
        let reading = document.view == View::Reading;
        self.collab
            .people
            .iter()
            .filter_map(|person| {
                let cursor = person.cursor?;
                let Place::C {
                    function,
                    reading: theirs,
                    ..
                } = cursor.place
                else {
                    return None;
                };
                let Some(Selection::Text { from, to }) = cursor.selection else {
                    return None;
                };
                if function != document.entry || theirs != reading {
                    return None;
                }
                let pos = |(line, column): (u32, u32)| {
                    TextPos::new(
                        usize::try_from(line).unwrap_or(usize::MAX),
                        usize::try_from(column).unwrap_or(usize::MAX),
                    )
                };
                let (from, to) = (pos(from), pos(to));
                Some((
                    (from.min(to), from.max(to)),
                    others_selection(&person.avatar(&self.collab.colours), self.theme.dark),
                ))
            })
            .collect()
    }

    /// Who is on a line `row_h` high: each one's avatar and name, muted,
    /// side by side; the last of the line's row (after its text and
    /// anything at its end), so never over the code, cut by the pane's
    /// edge.
    pub fn line_badges(&self, carets: &[&RemoteCaret], row_h: f32) -> AnyElement {
        let size = (f32::from(self.z(16.0))).min(row_h - 2.0) / self.settings.ui_scale;
        div()
            .flex()
            .flex_none()
            .h_full()
            .items_center()
            .ml(self.z(BADGE_GAP))
            .gap(self.z(10.0))
            // Names, not code: in the interface's font.
            .font_family(self.settings.ui_font.clone())
            .children(carets.iter().map(|caret| {
                div()
                    .flex()
                    .flex_none()
                    .items_center()
                    .gap(self.z(4.0))
                    .child(self.avatar_circle(&caret.avatar, size))
                    .child(
                        div()
                            .text_color(hsla(self.theme.text_muted))
                            .text_size(self.z(11.0))
                            .whitespace_nowrap()
                            .child(caret.name.clone()),
                    )
            }))
            .into_any_element()
    }

    /// The others' ticks on a strip `h` long (pane `id`'s scrollbar or map
    /// strip, at its right, or the feature map; down it if `vertical`,
    /// else along it), drawn as `style` says: each in their colour at the
    /// `fraction` (0 to 1) of the strip their cursor is at, if it is on
    /// it, kept a pixel apart; named with where they are in its tooltip;
    /// a click goes there.
    pub(crate) fn person_ticks(
        &self,
        id: PaneId,
        h: f32,
        vertical: bool,
        style: TickStyle,
        fraction: impl Fn(&Cursor) -> Option<f32> + 'static,
        cx: &mut Context<Self>,
    ) -> Vec<AnyElement> {
        let tick = f32::from(self.z(TICK));
        // How long along the strip each one's mark is.
        let long = match style {
            TickStyle::Bar => tick,
            TickStyle::Band(strip) => strip.arrow_base().max(tick.round() + 2.0),
        };
        let fraction: Fraction = Rc::new(fraction);
        let (on, tops) = self.tick_places(h, long, &*fraction);
        self.collab.drawn.push(Site::Ticks {
            length: h,
            long,
            fraction,
        });
        on.into_iter()
            .zip(tops)
            .enumerate()
            .map(|(i, ((person, cursor), top))| {
                let key = person.key;
                let tip = format!(
                    "{} \u{2014} {}",
                    person.name,
                    self.whereabouts(&cursor).text()
                );
                let color = avatar_color(&person.avatar(&self.collab.colours), self.theme.dark);
                let mark = div().id(("person-tick", i)).absolute();
                let mark = match style {
                    TickStyle::Bar => {
                        let across = self.z(SCROLLBAR) - px(4.0);
                        let mark = if vertical {
                            mark.top(px(top)).right(px(1.0)).w(across).h(px(tick))
                        } else {
                            mark.left(px(top)).bottom(px(1.0)).h(across).w(px(tick))
                        };
                        mark.rounded(px(1.0)).bg(color)
                    }
                    TickStyle::Band(strip) => self.band_mark(mark, strip, top, long, color),
                };
                mark.cursor_pointer()
                    .tooltip(move |window, cx| Tooltip::new(tip.clone()).build(window, cx))
                    // Not the strip's own press (a drag of its thumb).
                    .on_mouse_down(MouseButton::Left, |_, window, cx| {
                        window.prevent_default();
                        cx.stop_propagation();
                    })
                    .on_click(cx.listener(move |this, _: &ClickEvent, window, cx| {
                        this.focus_pane(id, window, cx);
                        this.go_to_person(key);
                        cx.notify();
                    }))
                    .into_any_element()
            })
            .collect()
    }

    /// Where the others' ticks are on a strip `h` long, marks `long` along
    /// it, `fraction` placing a cursor on it: who, at what cursor, and the
    /// tops, kept a pixel apart, on whole pixels (a move within one moves
    /// no tick).
    fn tick_places(
        &self,
        h: f32,
        long: f32,
        fraction: &dyn Fn(&Cursor) -> Option<f32>,
    ) -> (Vec<(&Person, Cursor)>, Vec<f32>) {
        let (on, at): (Vec<(&Person, Cursor)>, Vec<f32>) = self
            .collab
            .order
            .iter()
            .filter_map(|key| self.collab.people.iter().find(|p| p.key == *key))
            .filter_map(|p| {
                let cursor = p.cursor?;
                let at = fraction(&cursor)?.clamp(0.0, 1.0) * (h - long);
                Some(((p, cursor), at))
            })
            .unzip();
        let tops = spread_ticks(&at, long + 1.0, h)
            .into_iter()
            .map(f32::round)
            .collect();
        (on, tops)
    }

    /// Notes that this frame shows the others' carets and selections on
    /// `listing`'s lines `lines`.
    pub(crate) fn drawn_listing(&self, listing: &Arc<Listing>, lines: Range<u64>) {
        self.collab.drawn.push(Site::Listing {
            listing: Arc::clone(listing),
            lines,
        });
    }

    /// Notes that this frame shows the others' carets and selections on
    /// `document`'s lines `lines`.
    pub(crate) fn drawn_c(&self, document: &Arc<CDocument>, lines: Range<usize>) {
        self.collab.drawn.push(Site::C {
            document: Arc::clone(document),
            lines,
        });
    }

    /// What the last frame's places showing the others' cursors would show
    /// of them now, hashed: the same as when it was drawn if their moves
    /// since change nothing on screen.
    pub(crate) fn presence_shown(&self) -> u64 {
        let mut hash = DefaultHasher::new();
        let sites = self.collab.drawn.sites.borrow();
        for site in sites.iter() {
            match site {
                Site::Ticks {
                    length,
                    long,
                    fraction,
                } => {
                    let (on, tops) = self.tick_places(*length, *long, &**fraction);
                    for ((person, _), top) in on.iter().zip(tops) {
                        (person.key, top.to_bits()).hash(&mut hash);
                    }
                }
                Site::Listing { listing, lines } => {
                    let mut carets: Vec<(u64, &str, Option<u32>)> = Vec::new();
                    let found = self.listing_carets(listing);
                    for (line, on) in found.iter().filter(|(line, _)| lines.contains(line)) {
                        carets.extend(on.iter().map(|c| (*line, c.name.as_str(), c.column)));
                    }
                    carets.sort_unstable();
                    carets.hash(&mut hash);
                    for (selected, _) in self.listing_selections(listing) {
                        let from = (*selected.start()).max(lines.start);
                        let to = (*selected.end()).min(lines.end.saturating_sub(1));
                        (from <= to).then_some((from, to)).hash(&mut hash);
                    }
                }
                Site::C { document, lines } => {
                    let mut carets: Vec<(usize, &str, Option<u32>)> = Vec::new();
                    let found = self.c_carets(document);
                    for (line, on) in found.iter().filter(|(line, _)| lines.contains(line)) {
                        carets.extend(on.iter().map(|c| (*line, c.name.as_str(), c.column)));
                    }
                    carets.sort_unstable();
                    carets.hash(&mut hash);
                    for ((from, to), _) in self.c_selections(document) {
                        let seen = from.line < lines.end && to.line >= lines.start;
                        seen.then_some((from.line, from.column, to.line, to.column))
                            .hash(&mut hash);
                    }
                }
            }
        }
        hash.finish()
    }

    /// `mark` as a person's mark on the feature map, `long` along it from
    /// `at`, in `color`: a tick across `strip`'s band, edged in the
    /// panel's colour, and an arrow in its lane pointing at the tick.
    fn band_mark(
        &self,
        mark: Stateful<Div>,
        strip: Across,
        at: f32,
        long: f32,
        color: Hsla,
    ) -> Stateful<Div> {
        let width = f32::from(self.z(TICK)).round() + 2.0;
        let from = ((long - width) / 2.0).round();
        let total = strip.thickness + strip.depth;
        let tick = div()
            .absolute()
            .bg(color)
            .border_1()
            .border_color(hsla(solid(self.theme.panel)));
        let arrow = strip
            .arrow(long / 2.0)
            .into_iter()
            .map(|(start, length, row)| {
                let r = div().absolute().bg(color);
                if strip.vertical {
                    r.top(px(start)).left(px(row)).h(px(length)).w(px(1.0))
                } else {
                    r.left(px(start)).top(px(row)).w(px(length)).h(px(1.0))
                }
            });
        let (mark, tick) = if strip.vertical {
            (
                mark.top(px(at)).left_0().h(px(long)).w(px(total)),
                tick.top(px(from))
                    .left(px(strip.band))
                    .h(px(width))
                    .w(px(strip.thickness)),
            )
        } else {
            (
                mark.left(px(at)).top_0().w(px(long)).h(px(total)),
                tick.left(px(from))
                    .top(px(strip.band))
                    .w(px(width))
                    .h(px(strip.thickness)),
            )
        };
        mark.child(tick).children(arrow)
    }

    // ---- the status bar ----

    /// A status bar item's frame.
    fn status_item(&self, id: &'static str) -> Stateful<Div> {
        div()
            .id(id)
            .flex()
            .flex_none()
            .items_center()
            .gap(self.z(4.0))
            .h(self.z(ICON_BUTTON))
            .px(self.z(6.0))
            .rounded(self.z(4.0))
            .hover(|s| s.bg(hsla(self.theme.element_hover)))
    }

    /// The status bar's session item, status only (no badge: the title
    /// bar's chat button and the threads button carry those): how many,
    /// sharing or joined, the link (its addresses in the tooltip only); a
    /// click shows the chat.
    fn status_session(&self, hosting: bool, cx: &mut Context<Self>) -> Stateful<Div> {
        let theme = self.theme;
        let count = self.collab.people.len() + 1;
        let paths: Vec<String> = self
            .collab
            .people
            .iter()
            .filter_map(|p| p.path.clone())
            .collect();
        let link = paths.first().map(|p| link_text(p));
        let tip = if paths.is_empty() {
            format!("{count} in the session")
        } else {
            format!("{count} in the session\n{}", paths.join("\n"))
        };

        self.status_item("status-session")
            .tooltip(move |window, cx| Tooltip::new(tip.clone()).build(window, cx))
            .on_click(cx.listener(|this, _: &ClickEvent, window, cx| {
                this.run(Command::SessionPanel, window, cx);
            }))
            .child(icon(IconName::Users, self.z(ICON), hsla(theme.accent)))
            .child(div().text_color(hsla(theme.text)).child(count.to_string()))
            .child(self.muted(if hosting {
                "sharing"
            } else if self.collab.joining() {
                "joining"
            } else {
                "joined"
            }))
            .children(link.map(|l| self.muted(format!("\u{b7} {l}"))))
    }

    /// The status bar's session part: the people and the link, `threads`
    /// (the threads button) beside them, a peer's last change; the
    /// conflicts and refused changes when there are any, and in a share's
    /// project the edits not yet shared and those not in it.
    pub fn render_collab_status(
        &self,
        threads: Option<AnyElement>,
        cx: &mut Context<Self>,
    ) -> Option<AnyElement> {
        let theme = self.theme;
        let conflicts = self.session.as_ref().map_or(0, |s| s.conflicts().len());
        let refused = self
            .collab
            .net
            .as_ref()
            .map_or(0, |net| net.refused().len());
        let net = self.collab.net.as_ref();
        let (pending, apart) = (
            self.collab.local.pending.len(),
            self.collab.local.apart.len(),
        );
        if net.is_none() && conflicts == 0 && threads.is_none() && pending == 0 && apart == 0 {
            return None;
        }
        let session = net.map(|net| self.status_session(net.hosting(), cx));
        let item = |id: &'static str| self.status_item(id);
        let counter = |id: &'static str, glyph: IconName, n: usize, label: &str, tab: Tab| {
            (n > 0).then(|| {
                item(id)
                    .text_color(hsla(theme.error))
                    .on_click(cx.listener(move |this, _: &ClickEvent, _, cx| {
                        this.collab.panel = Some(tab);
                        cx.notify();
                    }))
                    .child(icon(glyph, self.z(ICON), hsla(theme.error)))
                    .child(format!("{n} {label}"))
            })
        };
        let conflicts = counter(
            "status-conflicts",
            IconName::GitMergeConflict,
            conflicts,
            if conflicts == 1 {
                "conflict"
            } else {
                "conflicts"
            },
            Tab::Conflicts,
        );
        let refused = counter(
            "status-refused",
            IconName::Ban,
            refused,
            "refused",
            Tab::Refused,
        );
        let not_in = counter(
            "status-apart",
            IconName::Ban,
            apart,
            "not in this project",
            Tab::Local,
        );
        let pending = pending_text(pending).map(|text| {
            item("status-pending")
                .on_click(cx.listener(|this, _: &ClickEvent, _, cx| {
                    this.collab.panel = Some(Tab::Local);
                    cx.notify();
                }))
                .child(icon(IconName::Upload, self.z(ICON), hsla(theme.text_muted)))
                .child(self.muted(text))
        });
        let notice = self
            .collab
            .notice
            .as_ref()
            .filter(|(_, at)| at.elapsed() < NOTICE)
            .map(|(text, at)| {
                // Fades through its last second.
                let left = NOTICE.saturating_sub(at.elapsed()).as_secs_f32().min(1.0);
                div()
                    .min_w_0()
                    .pl(self.z(6.0))
                    .overflow_hidden()
                    .whitespace_nowrap()
                    .text_ellipsis()
                    .opacity(left.max(0.2))
                    .child(text.clone())
            });
        Some(
            div()
                .flex()
                .items_center()
                .min_w_0()
                .children(session)
                .children(threads)
                .children(conflicts)
                .children(refused)
                .children(pending)
                .children(not_in)
                .children(notice)
                .into_any_element(),
        )
    }

    // ---- the session panel ----

    /// The session panel, if shown: the chat, or the conflicts or refused
    /// changes, under a title with a close button.
    pub fn render_session_panel(
        &mut self,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Option<AnyElement> {
        let tab = self.collab.panel?;
        self.collab.conflicts = self
            .session
            .as_ref()
            .map(Session::conflicts)
            .unwrap_or_default();
        if tab == Tab::Chat {
            self.collab.unread.seen();
            self.ensure_chat_input(window, cx);
        }
        let theme = self.theme;
        let (title, glyph) = match tab {
            Tab::Chat => ("Chat", IconName::MessageSquare),
            Tab::Conflicts => ("Conflicts", IconName::GitMergeConflict),
            Tab::Refused => ("Refused changes", IconName::Ban),
            Tab::Local => ("Your edits", IconName::Upload),
        };
        let body = match tab {
            Tab::Chat => self.render_chat_panel(window.modifiers().secondary(cx), cx),
            Tab::Conflicts => self.render_conflicts(cx),
            Tab::Local => self.render_local(cx),
            Tab::Refused => div()
                .flex()
                .flex_col()
                .gap(self.z(6.0))
                .children(
                    self.refused_lines()
                        .into_iter()
                        .map(|line| div().child(line)),
                )
                .into_any_element(),
        };
        let header = div()
            .flex()
            .flex_none()
            .items_center()
            .justify_between()
            .h(self.bar(TAB_PAD))
            .px(self.z(10.0))
            .border_b_1()
            .border_color(hsla(theme.border))
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap(self.z(6.0))
                    .child(icon(glyph, self.z(ICON), hsla(theme.text_muted)))
                    .child(div().font_weight(FontWeight::SEMIBOLD).child(title)),
            )
            .child(self.icon_button(
                "session-close",
                IconName::X,
                Command::SessionPanel,
                true,
                false,
                cx,
            ));
        let input = (tab == Tab::Chat)
            .then(|| self.collab.chat_input.clone())
            .flatten()
            .map(|input| {
                self.render_composer(&input, cx)
                    .rounded_b(self.island_corner())
            });
        // The message gone to: scrolled to once this frame has placed it.
        if tab == Tab::Chat
            && let Some(jump) = &mut self.collab.chat_jump
            && std::mem::take(&mut jump.pending)
        {
            jump.anchor.scroll_to(window, cx);
            window.request_animation_frame();
        }
        Some(
            self.panel_island()
                .id("session-panel")
                .w(self.z(PANEL))
                .flex_none()
                .when(!self.settings.islands, |d| {
                    d.border_l_1().border_color(hsla(theme.border))
                })
                .child(header)
                .child(
                    div()
                        .id("session-body")
                        .flex_1()
                        .min_h_0()
                        .overflow_y_scroll()
                        .when(tab == Tab::Chat, |d| {
                            d.track_scroll(&self.collab.chat_scroll)
                        })
                        .p(self.z(10.0))
                        .child(body),
                )
                .children(input)
                .children(self.island_edge())
                .into_any_element(),
        )
    }

    /// The chat: messages grouped by author (avatar, name, time, then each
    /// message), the session's own lines small and muted.
    fn render_chat_panel(&mut self, ctrl: bool, cx: &mut Context<Self>) -> AnyElement {
        let theme = self.theme;
        if self.collab.chat.is_empty() {
            return div().into_any_element();
        }
        let zone = self
            .collab
            .zone
            .get_or_insert_with(TimeZone::system)
            .clone();
        let now = u64::try_from(unix_ms()).unwrap_or(u64::MAX);
        let groups = group_chat(&self.collab.chat);
        let line = |text: ChatText| {
            let id = text.id;
            self.jumped_to(
                div().id(ElementId::Name(format!("chat-line-{id:x}").into())),
                id,
            )
            .when(text.removed, |d| {
                d.italic().text_color(hsla(theme.text_muted))
            })
            .when(!text.removed, |d| {
                let whole = text.text.clone();
                d.on_mouse_down(
                    MouseButton::Right,
                    cx.listener(move |this, e: &MouseDownEvent, window, cx| {
                        this.open_chat_menu(id, &whole, e.position, window, cx);
                    }),
                )
            })
            .when(!text.removed, |d| {
                d.child(self.chat_message(&text, ctrl, cx))
            })
            .when(text.removed, |d| d.child(text.shown().to_owned()))
        };
        div()
            .flex()
            .flex_col()
            .gap(self.z(10.0))
            .children(groups.into_iter().enumerate().map(|(i, group)| {
                match group {
                    // Its time only on hover, as a message's full time.
                    ChatGroup::System(text, time) => {
                        let full = local_full(time, &zone);
                        div()
                            .id(("chat-system", i))
                            .text_size(self.z(11.0))
                            .text_color(hsla(theme.text_placeholder))
                            .tooltip(move |window, cx| Tooltip::new(full.clone()).build(window, cx))
                            .child(text)
                            .into_any_element()
                    }
                    ChatGroup::Messages {
                        from,
                        name,
                        time,
                        texts,
                    } => {
                        let face = self.face(from, &name);
                        let full = local_full(time, &zone);
                        div()
                            .flex()
                            .gap(self.z(8.0))
                            .child(self.avatar_circle(&face, 22.0))
                            .child(
                                div()
                                    .flex()
                                    .flex_col()
                                    .min_w_0()
                                    .gap(self.z(2.0))
                                    .child(
                                        div()
                                            .flex()
                                            .items_center()
                                            .gap(self.z(6.0))
                                            .child(div().font_weight(FontWeight::BOLD).child(name))
                                            .child(
                                                div()
                                                    .id(("chat-time", i))
                                                    .text_size(self.z(11.0))
                                                    .text_color(hsla(theme.text_muted))
                                                    .tooltip(move |window, cx| {
                                                        Tooltip::new(full.clone()).build(window, cx)
                                                    })
                                                    .child(local_clock(time, now, &zone)),
                                            ),
                                    )
                                    .children(texts.into_iter().map(&line)),
                            )
                            .into_any_element()
                    }
                }
            }))
            .into_any_element()
    }

    /// A chat message's text: its links in the accent (an ordinary word
    /// that is a name only while Ctrl is held, underlined then), the one
    /// under the pointer underlined, a click going there (the focused pane
    /// and its sync group), the pointer resting on one opening its peek
    /// card; code in the code font; mentions in the accent, this person's
    /// on a wash of it. `ctrl`: Ctrl (Cmd on macOS) is held.
    fn chat_message(&self, text: &ChatText, ctrl: bool, cx: &Context<Self>) -> AnyElement {
        let theme = self.theme;
        let me = self.session.as_ref().map(Session::identity);
        let mut marks: Vec<(Range<usize>, bool)> = Vec::new();
        for &key in &text.mentions {
            let name = if Some(key) == me {
                self.collab.my_name().to_owned()
            } else {
                self.person_name(key)
            };
            let handle = Participant {
                key,
                agent: None,
                name,
            }
            .handle();
            marks.extend(
                mention_ranges(&text.text, &handle)
                    .into_iter()
                    .map(|range| (range, Some(key) == me)),
            );
        }
        marks.sort_by_key(|(range, _)| range.start);
        let shown = chat::shown(&text.text, &text.links, &marks);
        let id = text.id;
        let hovered = self
            .collab
            .hovered
            .and_then(|(message, n)| (message == id).then_some(n));
        let accent = hsla(theme.accent);
        let underline = UnderlineStyle {
            thickness: px(1.0),
            color: Some(accent),
            wavy: false,
        };
        let code_font = SharedString::from(self.settings.code_font.clone());
        let mut highlights = Vec::new();
        let mut code = Vec::new();
        let mut links: Vec<(Range<usize>, u64, usize)> = Vec::new();
        for piece in &shown.pieces {
            let mut style = HighlightStyle::default();
            if let Some(mine) = piece.mention {
                style.color = Some(accent);
                style.font_weight = Some(FontWeight::SEMIBOLD);
                if mine {
                    style.background_color = Some(hsla(with_alpha(theme.accent, 0x30)));
                }
            }
            if let Some((n, address, word)) = piece.link
                && (!word || ctrl)
            {
                style.color = Some(accent);
                if word || hovered == Some(n) {
                    style.underline = Some(underline);
                }
                links.push((piece.range.clone(), address, n));
            }
            if piece.code {
                code.push((piece.range.clone(), code_font.clone()));
            }
            highlights.push((piece.range.clone(), style));
        }
        let shown = SharedString::from(shown.text);
        let styled = StyledText::new(shown.clone())
            .with_highlights(highlights)
            .with_font_family_overrides(code);
        let ranges: Vec<Range<usize>> = links.iter().map(|(range, _, _)| range.clone()).collect();
        let goes: Vec<u64> = links.iter().map(|&(_, address, _)| address).collect();
        let this = cx.weak_entity();
        let hovering = this.clone();
        let interact = move |text: InteractiveText| {
            text.on_click(ranges, move |ix, _, cx| {
                if let Some(&address) = goes.get(ix) {
                    let _ = this.update(cx, |this, cx| this.jump(address, cx));
                }
            })
            .on_hover(move |index, event, window, cx| {
                let on = index
                    .and_then(|i| links.iter().find(|(range, _, _)| range.contains(&i)))
                    .map(|&(_, address, n)| (n, address));
                let _ = hovering.update(cx, |this, cx| {
                    this.hover_chat_link(id, on, event.position, window, cx);
                });
            })
        };
        SelectableText::new(
            ElementId::Name(format!("chat-text-{id:x}").into()),
            shown,
            styled,
            hsla(theme.selection),
            interact,
        )
        .into_any_element()
    }

    /// The pointer over link `on` (its number and address) of chat
    /// message `id`, or over none: the link underlined, its peek card.
    fn hover_chat_link(
        &mut self,
        id: u64,
        on: Option<(usize, u64)>,
        position: Point<Pixels>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let hovered = on.map(|(n, _)| (id, n));
        if self.collab.hovered != hovered {
            self.collab.hovered = hovered;
            cx.notify();
        }
        self.hover_peek(on.map(|(_, address)| address), None, position, window, cx);
    }

    /// A right click on chat message `id` (its text `whole`): Copy (the
    /// text selected, else the message), and for the owner Remove.
    fn open_chat_menu(
        &mut self,
        id: u64,
        whole: &str,
        position: Point<Pixels>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        // The selection as it is now: the press on the menu clears it
        // before the item runs.
        let selected = TextSelection::selected_text(window, cx);
        let copied = if selected.is_empty() {
            whole.to_owned()
        } else {
            selected
        };
        let mut items = vec![OwnItem::new("Copy", move |_, _, cx| {
            cx.write_to_clipboard(ClipboardItem::new_string(copied.clone()));
        })];
        if self.collab.owner() {
            items.push(OwnItem::new("Remove", move |this, _, _| {
                if let Err(why) = this.collab.remove_chat(id) {
                    this.collab.notice = Some((why, Instant::now()));
                }
            }));
        }
        self.open_own_menu(position, items, window, cx);
    }

    /// The chat's message box: flat, the whole area under a thin top
    /// border filled with a raised colour, small Insert Location and Send
    /// icons at the right of the text's last line. The `@` completion over
    /// it; the placeholder its only text.
    fn render_composer(&self, input: &Entity<TextareaState>, cx: &mut Context<Self>) -> Div {
        let theme = self.theme;
        let completion = self
            .collab
            .completion
            .as_ref()
            .map(|c| self.render_completion(c));
        let typed = !input.read(cx).value().trim().is_empty();
        let locate = commands::state(Command::InsertLocation, &self.facts()).enabled;
        let insert = self
            .composer_button("chat-insert-location", IconName::MapPin, locate, false)
            .tooltip(self.key_tooltip("Insert Location", Command::InsertLocation))
            .when(locate, |d| {
                d.on_click(cx.listener(|this, _: &ClickEvent, window, cx| {
                    this.run(Command::InsertLocation, window, cx);
                }))
            });
        let send = self
            .composer_button("chat-send", IconName::SendHorizontal, typed, typed)
            .tooltip(self.keyed_tooltip("Send", Some("Enter".to_owned())))
            .when(typed, |d| {
                d.on_click(cx.listener(|this, _: &ClickEvent, window, cx| {
                    this.send_chat(window, cx);
                }))
            });
        let field = div().flex_1().min_w_0().child(Textarea::new(input));
        div()
            .flex_none()
            .key_context("Chat")
            .border_t_1()
            .border_color(hsla(theme.border))
            .bg(hsla(solid(theme.editor)))
            .px(self.z(10.0))
            .py(self.z(6.0))
            .children(completion)
            .child(
                div()
                    .flex()
                    .items_end()
                    .gap(self.z(2.0))
                    .child(field.pb(self.z(2.0)))
                    .child(insert)
                    .child(send),
            )
    }

    /// A small icon button of the message box: `glyph` muted, in the
    /// accent when `lit`, faint when not `enabled`.
    fn composer_button(
        &self,
        id: &'static str,
        glyph: IconName,
        enabled: bool,
        lit: bool,
    ) -> Stateful<Div> {
        let theme = self.theme;
        let color = if !enabled {
            theme.text_placeholder
        } else if lit {
            theme.accent
        } else {
            theme.text_muted
        };
        div()
            .id(id)
            .flex()
            .flex_none()
            .items_center()
            .justify_center()
            .size(self.z(22.0))
            .rounded(self.z(4.0))
            .when(enabled, |d| d.hover(|s| s.bg(hsla(theme.element_hover))))
            .on_mouse_down(MouseButton::Left, |_, window, cx| {
                window.prevent_default();
                cx.stop_propagation();
            })
            .child(icon(glyph, self.z(14.0), hsla(color)))
    }
}

#[cfg(test)]
mod tests {
    use binbun_gui_view::listing::{Role, Token};

    use super::token_column;

    fn token(text: &str, role: Role) -> Token {
        Token {
            text: text.to_owned(),
            role,
            target: None,
            automatic: false,
        }
    }

    #[test]
    fn a_listing_caret_sits_on_its_token_or_where_the_code_starts() {
        let tokens = [
            token(".text:01E6D5", Role::Prefix),
            token("    ", Role::Space),
            token("jz", Role::Mnemonic),
            token("      ", Role::Space),
            token("short", Role::Keyword),
            token(" ", Role::Space),
            token("loc_1E720", Role::CodeName),
        ];
        // On the label: past the prefix, the mnemonic and the spaces.
        assert_eq!(token_column(&tokens, Some(6)), 12 + 4 + 2 + 6 + 5 + 1);
        // On a gap (a click between the columns): where the next token
        // starts, not where the gap does.
        assert_eq!(token_column(&tokens, Some(3)), 12 + 4 + 2 + 6);
        assert_eq!(token_column(&tokens, Some(1)), 16);
        // No token: the mnemonic's column, not the address's.
        assert_eq!(token_column(&tokens, None), 16);
        assert_eq!(token_column(&tokens[..1], None), 0);
    }
}
