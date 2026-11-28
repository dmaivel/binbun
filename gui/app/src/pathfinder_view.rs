//! The Pathfinder in the right dock: from and to (typed with
//! go-anywhere's matching over functions and imports), waypoints passed
//! in order and functions avoided, and "data only" (along calls where the
//! start's parameter goes on); the answer as a list of paths, each a
//! breadcrumb of functions (a name goes to the function, the separator
//! before it to the call), "N paths, M nodes, shortest K", and the
//! subgraph shown in a call graph pane. The question is saved per project
//! (its `pathfinder.toml`) and asked again on every change.

use std::path::PathBuf;
use std::sync::Arc;

use binbun::calls::{Node, Paths};
use binbun_gui_view::calls::{Pathfinder, Shown};
use binbun_gui_view::fuzzy::{Query, filter};
use binbun_gui_view::layout::PaneId;
use binbun_gui_view::session::{Project, Session};
use binbun_gui_view::{Answer, Asked, PathRequest, Question, View};
use gpui_kit::assets::IconName;
use gpui_kit::component::input::{Input, InputEvent, InputState};
use gpui_kit::component::tooltip::Tooltip;
use gpui_kit::prelude::*;
use gpui_kit::{
    AnyElement, Context, Entity, KeyDownEvent, ListAlignment, ListState, Subscription, Window, div,
    list, px,
};

use crate::icons::icon;
use crate::right_dock::Panel;
use crate::theme::hsla;
use crate::workspace::{ICON, ICON_BUTTON, TOOLBAR_PAD, Workspace};

/// The right dock's width while the Pathfinder is in it.
pub const PATHFINDER_WIDTH: f32 = 420.0;

/// The most matches a field offers.
const MATCHES: usize = 8;
/// How far past the paths list's edges its rows are laid out (logical).
const PATHS_OVERDRAW: f32 = 200.0;

/// Which of the question's parts a field sets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Slot {
    /// The start.
    From,
    /// The end.
    To,
    /// A waypoint added.
    Through,
    /// A function avoided added.
    Avoid,
}

/// A field being typed in.
pub struct FieldEdit {
    slot: Slot,
    input: Entity<InputState>,
    /// The matching candidates (indices), best first.
    rows: Vec<usize>,
    selected: usize,
    _sub: Subscription,
}

/// The Pathfinder panel's state.
#[derive(Default)]
pub struct PathfinderUi {
    /// The question.
    pub question: Pathfinder,
    /// The project's file it was loaded from (and is saved to).
    loaded: Option<PathBuf>,
    /// The field being typed in.
    field: Option<FieldEdit>,
    /// Every function and import by its shown name (made when a field
    /// opens).
    candidates: Vec<(String, u64)>,
    /// The search asked and not answered.
    asked: Option<Asked>,
    /// The answer to the last search.
    pub found: Option<Arc<Paths>>,
    /// The answer's paths as a list laying out only the rows in view (a
    /// path's breadcrumb wraps, so its height is measured once).
    paths: Option<ListState>,
    /// Why there is no search (an end that is no function).
    error: Option<String>,
    /// The path chosen (drawn brighter in the call graph).
    pub chosen: Option<usize>,
}

impl Workspace {
    /// The Pathfinder opened in the right dock: its question read from the
    /// project if it was not yet, and asked if it was not.
    pub(crate) fn pathfinder_opened(&mut self) {
        self.load_pathfinder();
        if self.calls.pathfinder.found.is_none() {
            self.search_paths();
        }
    }

    /// The Pathfinder closed: the field typed in left.
    pub(crate) fn pathfinder_closed(&mut self) {
        self.calls.pathfinder.field = None;
    }

    /// The project's question, read once per project.
    fn load_pathfinder(&mut self) {
        let Some(file) = self
            .session
            .as_ref()
            .and_then(Session::project)
            .map(Project::pathfinder)
        else {
            return;
        };
        let ui = &mut self.calls.pathfinder;
        if ui.loaded.as_ref() == Some(&file) {
            return;
        }
        match Pathfinder::load(&file) {
            Ok(question) => ui.question = question,
            Err(error) => self.error = Some(error),
        }
        let ui = &mut self.calls.pathfinder;
        ui.loaded = Some(file);
        ui.found = None;
        ui.chosen = None;
    }

    /// Saves the question and asks it again.
    fn pathfinder_changed(&mut self) {
        if let Some(file) = &self.calls.pathfinder.loaded
            && let Err(error) = self.calls.pathfinder.question.save(file)
        {
            self.error = Some(error);
        }
        self.search_paths();
    }

    /// The function at the cursor made the start (`from`) or the end.
    pub fn path_end(&mut self, from: bool) {
        let entry = self
            .current_address()
            .and_then(|a| self.listing.as_ref()?.function_of(a))
            .map(|(_, entry)| entry);
        let Some(entry) = entry else {
            return;
        };
        self.open_panel(Panel::Pathfinder);
        let question = &mut self.calls.pathfinder.question;
        if from {
            question.from = Some(entry);
        } else {
            question.to = Some(entry);
        }
        self.pathfinder_changed();
    }

    /// Asks the session for the paths of the question (the one asked
    /// before cancelled).
    fn search_paths(&mut self) {
        let ui = &mut self.calls.pathfinder;
        if let Some(asked) = ui.asked.take() {
            asked.cancel();
        }
        ui.found = None;
        ui.paths = None;
        ui.chosen = None;
        ui.error = None;
        let question = ui.question.clone();
        let Some(query) = question.query(|a| self.node_at(a)) else {
            return;
        };
        let Some(Node::Function(start)) = query.from else {
            self.calls.pathfinder.error = Some("the start is no function".to_owned());
            return;
        };
        let Some(session) = &self.session else {
            return;
        };
        let request = PathRequest {
            query,
            data: question.data(),
        };
        let asked = session.ask(start, View::Exact, Question::Paths(Arc::new(request)));
        self.calls.pathfinder.asked = Some(asked);
    }

    /// Takes `answer` if it answers a call graph question asked here;
    /// whether it did.
    pub fn calls_answer(&mut self, request: u64, answer: &Answer) -> bool {
        if let Answer::Paths(found) = answer
            && self
                .calls
                .pathfinder
                .asked
                .as_ref()
                .is_some_and(|a| a.request == request)
        {
            let ui = &mut self.calls.pathfinder;
            ui.asked = None;
            ui.paths = Some(ListState::new(
                found.paths.len(),
                ListAlignment::Top,
                px(PATHS_OVERDRAW),
            ));
            ui.found = Some(Arc::clone(found));
            ui.chosen = None;
            // A call graph showing the previous answer shows this one (the
            // whole subgraph if it showed that).
            let shown: Vec<(PaneId, bool)> = self
                .panes
                .iter()
                .filter(|(_, s)| s.calls.on)
                .filter_map(|(&id, s)| match s.calls.shown {
                    Some(Shown::Paths { whole, .. }) => Some((id, whole)),
                    Some(Shown::Around { .. }) | None => None,
                })
                .collect();
            for (id, whole) in shown {
                if let Some(state) = self.panes.get_mut(&id) {
                    state.calls.shown = Some(Shown::Paths {
                        paths: Arc::clone(found),
                        whole,
                    });
                    state.calls.path = None;
                    state.calls.landing = true;
                }
            }
            return true;
        }
        self.callers_answer(request, answer)
    }

    /// Shows the answer's listed paths in a call graph pane (their union;
    /// the whole subgraph one toggle away): one showing an answer already,
    /// else the focused pane.
    fn show_paths_graph(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let Some(found) = self.calls.pathfinder.found.clone() else {
            return;
        };
        let id = self
            .panes
            .iter()
            .find(|(_, s)| s.calls.on && matches!(s.calls.shown, Some(Shown::Paths { .. })))
            .map_or_else(|| self.layout.focused(), |(&id, _)| id);
        let shown = Shown::Paths {
            paths: found,
            whole: false,
        };
        self.show_in_calls(id, shown, window, cx);
        let chosen = self.calls.pathfinder.chosen;
        if let Some(state) = self.panes.get_mut(&id) {
            state.calls.path = chosen;
        }
        self.focus_pane(id, window, cx);
    }

    /// Chooses path `k`: drawn brighter in the call graphs showing it.
    fn choose_path(&mut self, k: usize) {
        self.calls.pathfinder.chosen = Some(k);
        for state in self.panes.values_mut() {
            if matches!(state.calls.shown, Some(Shown::Paths { .. })) {
                state.calls.path = Some(k);
            }
        }
    }

    /// Opens a field for `slot`, typing matched against every function and
    /// import.
    fn open_path_field(&mut self, slot: Slot, window: &mut Window, cx: &mut Context<Self>) {
        self.calls.pathfinder.candidates = self.path_candidates();
        let input = cx.new(|cx| InputState::new(window, cx));
        let sub = cx.subscribe_in(
            &input,
            window,
            |this, input, e: &InputEvent, _window, cx| match e {
                InputEvent::PressEnter { .. } => {
                    this.pick_path_field();
                    cx.notify();
                }
                InputEvent::Change => {
                    let text = input.read(cx).value().to_string();
                    this.filter_path_field(&text);
                    cx.notify();
                }
                InputEvent::Focus | InputEvent::Blur => {}
            },
        );
        input.update(cx, |s, cx| s.focus(window, cx));
        self.calls.pathfinder.field = Some(FieldEdit {
            slot,
            input,
            rows: Vec::new(),
            selected: 0,
            _sub: sub,
        });
    }

    /// Every function and import by its shown name.
    fn path_candidates(&self) -> Vec<(String, u64)> {
        let mut out: Vec<(String, u64)> = self
            .functions
            .iter()
            .map(|&(entry, _)| (self.node_name_at(entry), entry))
            .collect();
        if let Some(db) = self.session.as_ref().and_then(|s| s.database()) {
            out.extend(
                db.calls()
                    .imports()
                    .map(|(slot, name)| (name.to_owned(), slot)),
            );
        }
        out
    }

    /// The shown name of the node at `address`, else the address.
    fn node_name_at(&self, address: u64) -> String {
        self.node_at(address)
            .map_or_else(|| format!("{address:X}"), |n| self.node_name(n).0)
    }

    fn filter_path_field(&mut self, text: &str) {
        let ui = &mut self.calls.pathfinder;
        let Some(field) = &mut ui.field else {
            return;
        };
        let query = Query::new(text);
        field.rows = if query.is_empty() {
            Vec::new()
        } else {
            filter(
                &query,
                ui.candidates.iter().map(|(name, _)| name.as_str()),
                MATCHES,
            )
            .into_iter()
            .map(|(i, _)| i)
            .collect()
        };
        field.selected = 0;
    }

    /// The field's selected match set in the question.
    fn pick_path_field(&mut self) {
        let ui = &mut self.calls.pathfinder;
        let Some(field) = ui.field.take() else {
            return;
        };
        let Some(&(_, address)) = field
            .rows
            .get(field.selected)
            .and_then(|&i| ui.candidates.get(i))
        else {
            return;
        };
        let question = &mut ui.question;
        match field.slot {
            Slot::From => question.from = Some(address),
            Slot::To => question.to = Some(address),
            Slot::Through => question.through.push(address),
            Slot::Avoid => {
                if !question.avoid.contains(&address) {
                    question.avoid.push(address);
                }
            }
        }
        self.pathfinder_changed();
    }

    /// Up, down and Esc in the field.
    fn path_field_keys(&mut self, e: &KeyDownEvent, cx: &mut Context<Self>) {
        let Some(field) = &mut self.calls.pathfinder.field else {
            return;
        };
        match e.keystroke.key.as_str() {
            "up" => field.selected = field.selected.saturating_sub(1),
            "down" => field.selected = (field.selected + 1).min(field.rows.len().saturating_sub(1)),
            "escape" => self.calls.pathfinder.field = None,
            _ => return,
        }
        cx.stop_propagation();
        cx.notify();
    }

    /// The Pathfinder panel.
    #[expect(
        clippy::too_many_lines,
        reason = "the question's rows, then the answer"
    )]
    pub fn render_pathfinder(&self, cx: &mut Context<Self>) -> AnyElement {
        let theme = self.theme;
        let ui = &self.calls.pathfinder;
        let question = &ui.question;
        let code = self.settings.code_font.clone();
        let label = |text: &'static str| {
            div()
                .flex_none()
                .w(self.z(64.0))
                .h(self.z(22.0))
                .flex()
                .items_center()
                .text_color(hsla(theme.text_muted))
                .child(text)
        };
        // A field: the end's name (a click types another), or the input
        // with its matches.
        let field = |slot: Slot, value: Option<u64>, cx: &mut Context<Self>| -> AnyElement {
            if let Some(edit) = ui.field.as_ref().filter(|f| f.slot == slot) {
                let matches: Vec<AnyElement> = edit
                    .rows
                    .iter()
                    .enumerate()
                    .filter_map(|(k, &i)| {
                        let (name, address) = ui.candidates.get(i)?;
                        let selected = k == edit.selected;
                        Some(
                            div()
                                .id(("path-match", k))
                                .flex()
                                .gap(self.z(8.0))
                                .px(self.z(6.0))
                                .h(self.z(22.0))
                                .items_center()
                                .when(selected, |d| d.bg(hsla(theme.element_selected)))
                                .hover(|s| s.bg(hsla(theme.element_hover)))
                                .on_click(cx.listener(move |this, _, _, cx| {
                                    if let Some(f) = &mut this.calls.pathfinder.field {
                                        f.selected = k;
                                    }
                                    this.pick_path_field();
                                    cx.notify();
                                }))
                                .child(
                                    div()
                                        .flex_1()
                                        .min_w_0()
                                        .overflow_hidden()
                                        .text_ellipsis()
                                        .font_family(code.clone())
                                        .text_color(hsla(theme.function))
                                        .child(name.clone()),
                                )
                                .child(
                                    div()
                                        .font_family(code.clone())
                                        .text_color(hsla(theme.text_muted))
                                        .child(format!("{address:X}")),
                                )
                                .into_any_element(),
                        )
                    })
                    .collect();
                return div()
                    .flex_1()
                    .min_w_0()
                    .flex()
                    .flex_col()
                    .capture_key_down(cx.listener(|this, e: &KeyDownEvent, _, cx| {
                        this.path_field_keys(e, cx);
                    }))
                    .child(
                        div()
                            .px(self.z(6.0))
                            .rounded(self.z(4.0))
                            .border_1()
                            .border_color(hsla(theme.border_focused))
                            .child(Input::new(&edit.input).appearance(false)),
                    )
                    .children(matches)
                    .into_any_element();
            }
            let name = value.map(|a| self.node_name_at(a));
            div()
                .id(match slot {
                    Slot::From => "path-from",
                    Slot::To => "path-to",
                    Slot::Through => "path-through",
                    Slot::Avoid => "path-avoid",
                })
                .flex_1()
                .min_w_0()
                .h(self.z(22.0))
                .px(self.z(6.0))
                .flex()
                .items_center()
                .rounded(self.z(4.0))
                .border_1()
                .border_color(hsla(theme.border_variant))
                .hover(|s| s.bg(hsla(theme.element_hover)))
                .font_family(code.clone())
                .text_color(hsla(theme.function))
                .overflow_hidden()
                .text_ellipsis()
                .whitespace_nowrap()
                .on_click(cx.listener(move |this, _, window, cx| {
                    this.open_path_field(slot, window, cx);
                    cx.notify();
                }))
                .children(name)
                .into_any_element()
        };
        // A list of chips (waypoints, avoided), each removable, then an
        // add button.
        let chips = |slot: Slot, list: &[u64], cx: &mut Context<Self>| -> AnyElement {
            let mut row = div()
                .flex_1()
                .min_w_0()
                .min_h(self.z(22.0))
                .flex()
                .flex_wrap()
                .items_center()
                .gap(self.z(4.0));
            for (k, &address) in list.iter().enumerate() {
                row = row.child(
                    div()
                        .id(match slot {
                            Slot::Through => ("through-chip", k),
                            Slot::From | Slot::To | Slot::Avoid => ("avoid-chip", k),
                        })
                        .flex()
                        .items_center()
                        .gap(self.z(4.0))
                        .px(self.z(6.0))
                        .h(self.z(20.0))
                        .rounded(self.z(4.0))
                        .bg(hsla(theme.element_hover))
                        .font_family(code.clone())
                        .text_color(hsla(theme.function))
                        .child(self.node_name_at(address))
                        .child(
                            div()
                                .id(("chip-remove", k))
                                .on_click(cx.listener(move |this, _, _, cx| {
                                    let q = &mut this.calls.pathfinder.question;
                                    let list = if slot == Slot::Through {
                                        &mut q.through
                                    } else {
                                        &mut q.avoid
                                    };
                                    if k < list.len() {
                                        list.remove(k);
                                    }
                                    this.pathfinder_changed();
                                    cx.notify();
                                }))
                                .child(icon(
                                    IconName::X,
                                    self.z(ICON - 4.0),
                                    hsla(theme.text_muted),
                                )),
                        ),
                );
            }
            if ui.field.as_ref().is_some_and(|f| f.slot == slot) {
                row = row.child(field(slot, None, cx));
            } else {
                row = row.child(
                    div()
                        .id(match slot {
                            Slot::Through => "through-add",
                            Slot::From | Slot::To | Slot::Avoid => "avoid-add",
                        })
                        .flex()
                        .items_center()
                        .justify_center()
                        .size(self.z(20.0))
                        .rounded(self.z(4.0))
                        .hover(|s| s.bg(hsla(theme.element_hover)))
                        .on_click(cx.listener(move |this, _, window, cx| {
                            this.open_path_field(slot, window, cx);
                            cx.notify();
                        }))
                        .child(icon(IconName::Plus, self.z(ICON), hsla(theme.text_muted))),
                );
            }
            row.into_any_element()
        };
        let row = || {
            div()
                .flex()
                .items_start()
                .gap(self.z(8.0))
                .px(self.z(10.0))
                .py(self.z(3.0))
        };
        let data = question.data;
        let parameter = question.parameter;
        // The parameter stepper's buttons.
        let step = |id: &'static str, glyph: IconName| {
            div()
                .id(id)
                .flex()
                .items_center()
                .justify_center()
                .size(self.z(20.0))
                .rounded(self.z(4.0))
                .hover(|s| s.bg(hsla(theme.element_hover)))
                .child(icon(glyph, self.z(ICON), hsla(theme.text_muted)))
        };
        let data_row = row()
            .items_center()
            .child(label(""))
            .child(
                div()
                    .id("path-data")
                    .flex()
                    .items_center()
                    .gap(self.z(6.0))
                    .on_click(cx.listener(|this, _, _, cx| {
                        let q = &mut this.calls.pathfinder.question;
                        q.data = !q.data;
                        this.pathfinder_changed();
                        cx.notify();
                    }))
                    .child(icon(
                        if data {
                            IconName::SquareCheck
                        } else {
                            IconName::Square
                        },
                        self.z(ICON),
                        hsla(if data { theme.text } else { theme.text_muted }),
                    ))
                    .child("Data only"),
            )
            .when(data, |d| {
                d.child(div().flex_1()).child(
                    div()
                        .flex()
                        .items_center()
                        .gap(self.z(2.0))
                        .child(step("param-less", IconName::Minus).on_click(cx.listener(
                            |this, _, _, cx| {
                                let q = &mut this.calls.pathfinder.question;
                                q.parameter = q.parameter.saturating_sub(1);
                                this.pathfinder_changed();
                                cx.notify();
                            },
                        )))
                        .child(
                            div()
                                .font_family(code.clone())
                                .child(format!("a{}", parameter + 1)),
                        )
                        .child(step("param-more", IconName::Plus).on_click(cx.listener(
                            |this, _, _, cx| {
                                let q = &mut this.calls.pathfinder.question;
                                q.parameter = (q.parameter + 1).min(7);
                                this.pathfinder_changed();
                                cx.notify();
                            },
                        ))),
                )
            });
        // The answer.
        let searching = ui.asked.is_some();
        let summary = ui.found.as_ref().map(|found| {
            let nodes = found.subgraph.nodes.len();
            match found.shortest {
                Some(shortest) => {
                    let count = found.paths.len();
                    let plural = if count == 1 { "path" } else { "paths" };
                    format!("{count} {plural}, {nodes} nodes, shortest {shortest}")
                }
                None => "No path".to_owned(),
            }
        });
        let answer_bar = div()
            .flex()
            .items_center()
            .gap(self.z(6.0))
            .h(self.bar(TOOLBAR_PAD))
            .px(self.z(10.0))
            .border_t_1()
            .border_b_1()
            .border_color(hsla(theme.border_variant))
            .text_color(hsla(theme.text_muted))
            .when(searching, |d| d.child("Searching…"))
            .children(
                ui.error
                    .clone()
                    .map(|e| div().text_color(hsla(theme.error)).child(e)),
            )
            .children(summary.filter(|_| !searching))
            .child(div().flex_1())
            .when(
                ui.found.as_ref().is_some_and(|f| f.shortest.is_some()),
                |d| {
                    d.child(
                        div()
                            .id("paths-graph")
                            .flex()
                            .items_center()
                            .justify_center()
                            .size(self.z(ICON_BUTTON))
                            .rounded(self.z(4.0))
                            .hover(|s| s.bg(hsla(theme.element_hover)))
                            .tooltip(|window, cx| Tooltip::new("Show as Graph").build(window, cx))
                            .on_click(cx.listener(|this, _, window, cx| {
                                this.show_paths_graph(window, cx);
                                cx.notify();
                            }))
                            .child(icon(
                                IconName::Network,
                                self.z(ICON),
                                hsla(theme.text_muted),
                            )),
                    )
                },
            );
        // Only the rows in view are laid out and painted: an answer has
        // up to thousands of paths.
        let paths = div()
            .flex_1()
            .min_h_0()
            .children(ui.paths.clone().map(|state| {
                list(
                    state,
                    cx.processor(|this, k: usize, _, cx| this.render_path(k, cx)),
                )
                .size_full()
            }));
        div()
            .id("pathfinder")
            .size_full()
            .flex()
            .flex_col()
            .child(
                div()
                    .flex_none()
                    .flex()
                    .flex_col()
                    .py(self.z(6.0))
                    .child(
                        row()
                            .child(label("From"))
                            .child(field(Slot::From, question.from, cx)),
                    )
                    .child(
                        row()
                            .child(label("To"))
                            .child(field(Slot::To, question.to, cx)),
                    )
                    .child(row().child(label("Through")).child(chips(
                        Slot::Through,
                        &question.through,
                        cx,
                    )))
                    .child(row().child(label("Avoid")).child(chips(
                        Slot::Avoid,
                        &question.avoid,
                        cx,
                    )))
                    .child(data_row),
            )
            .child(answer_bar)
            .child(paths)
            .into_any_element()
    }

    /// Path `k` of the answer: a breadcrumb of its functions (a name goes
    /// to the function, the separator before it to the call), chosen by a
    /// click.
    fn render_path(&self, k: usize, cx: &mut Context<Self>) -> AnyElement {
        let theme = self.theme;
        let ui = &self.calls.pathfinder;
        let Some(hops) = ui.found.as_ref().and_then(|found| found.paths.get(k)) else {
            return div().into_any_element();
        };
        let data = ui.question.data;
        let mut crumb = div()
            .id(("path", k))
            .flex()
            .flex_wrap()
            .items_center()
            .gap(self.z(4.0))
            .px(self.z(10.0))
            .py(self.z(3.0))
            .font_family(self.settings.code_font.clone())
            .when(ui.chosen == Some(k), |d| d.bg(hsla(theme.element_selected)))
            .hover(|s| s.bg(hsla(theme.element_hover)))
            .on_click(cx.listener(move |this, _, _, cx| {
                this.choose_path(k);
                cx.notify();
            }));
        for (h, hop) in hops.iter().enumerate() {
            let (name, address) = self.node_name(hop.node);
            if let Some(site) = hop.site {
                crumb = crumb.child(
                    div()
                        .id(("hop-site", h))
                        .text_color(hsla(theme.text_placeholder))
                        .hover(|s| s.text_color(hsla(theme.text)))
                        .on_click(cx.listener(move |this, _, _, cx| {
                            cx.stop_propagation();
                            this.jump(site, cx);
                        }))
                        .child("›"),
                );
            }
            crumb = crumb.child(
                div()
                    .id(("hop", h))
                    .flex()
                    .gap(px(1.0))
                    .text_color(hsla(theme.function))
                    .hover(Styled::underline)
                    .on_click(cx.listener(move |this, _, _, cx| {
                        cx.stop_propagation();
                        this.jump(address, cx);
                    }))
                    .child(name)
                    .children(hop.argument.filter(|_| data).map(|a| {
                        div()
                            .text_color(hsla(theme.text_muted))
                            .child(format!("(a{})", u16::from(a) + 1))
                    })),
            );
        }
        crumb.into_any_element()
    }
}
