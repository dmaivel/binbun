//! The questions binbun answers beside the C, drawn: the verification
//! chip in a C pane's toolbar (checked once the cursor rests on a
//! function, cancelled on navigation, kept), the dotted underline of
//! weak evidence and its why card, the Origin panel in the right dock,
//! and a run's values at line ends with the example-state selector, its
//! compact form and the stub picker. The view models are
//! `binbun_gui_view::facts`; the session answers on its lanes.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use binbun::profile::{self, Profile};
use binbun::queries::compare::{Comparison, Verdict as Compared};
use binbun::queries::evidence::Explanation;
use binbun::queries::origin::{Origins, Start};
use binbun::queries::verify::Verification;
use binbun::run::state::Stub;
use binbun::run::{ExampleState, Run, show};
use binbun_gui_view::cdoc::{CDocument, Reveal, UndefinedValue};
use binbun_gui_view::commands::Processor;
use binbun_gui_view::facts::{
    Card, Chip, ComparisonCard, OriginRow, Values, Why, counterexample_state, item_of, load_states,
    origin_rows, processor_dependent, save_state, scratch_state, trail,
};
use binbun_gui_view::layout::{Axis, PaneId};
use binbun_gui_view::session::Session;
use binbun_gui_view::{Answer, Asked, FunctionId, Node, Question, View};
use gpui_kit::assets::IconName;
use gpui_kit::base::Input as FieldInput;
use gpui_kit::component::input::{InputEvent, InputState};
use gpui_kit::component::tooltip::Tooltip;
use gpui_kit::prelude::*;
use gpui_kit::{
    AnyElement, Context, Entity, MouseButton, Pixels, Point, Subscription, Task, Window, div, px,
};

use crate::icons::icon;
use crate::theme::{Theme, hsla, solid};
use crate::workspace::{ICON, ICON_BUTTON, TOOLBAR_PAD, TabKind, Workspace, f};

/// A function in a view.
pub type Key = (FunctionId, bool);

fn key(function: FunctionId, view: View) -> Key {
    (function, view == View::Reading)
}

const fn view_of(key: Key) -> View {
    if key.1 { View::Reading } else { View::Exact }
}

/// How long the cursor rests on a function before it is verified.
const IDLE: Duration = Duration::from_millis(500);

/// The right dock's width while the Origin panel is in it.
pub const ORIGIN_WIDTH: f32 = 420.0;

/// What a question asked was for.
#[derive(Clone, Debug)]
enum Pending {
    Verify(Key, Instant),
    Compare(Key, Instant),
    Explain(Key),
    Origin(Instant),
    Run(Key, Instant),
}

/// What a why card explains.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Explained {
    /// An item of a function's explanation.
    Item(Key, usize),
    /// The name of the function at this entry.
    Function(u64),
}

/// The why card: the item of a function's explanation under the pointer,
/// or a function's name.
#[derive(Clone, Debug)]
pub struct WhyCard {
    explained: Explained,
    position: Point<Pixels>,
    hovered: bool,
    /// Opened by the Why command: it stays until Esc or a click outside.
    pinned: bool,
}

/// The Origin panel.
pub struct OriginPanel {
    key: Key,
    title: String,
    request: u64,
    origins: Option<Arc<Origins>>,
    error: Option<String>,
    open: BTreeSet<Vec<u32>>,
    forward: bool,
    /// The C nodes and instructions of its rows (highlighted while open).
    nodes: HashSet<Node>,
    addresses: HashSet<u64>,
}

/// A run shown on a function.
struct Shown {
    state: Arc<ExampleState>,
    /// The processor it runs on, if one.
    profile: Option<Arc<Profile>>,
    run: Option<Arc<Run>>,
    error: Option<String>,
    /// The values on the document they were laid over (its pointer).
    values: Option<(usize, Arc<Values>)>,
    asked: Option<Asked>,
}

/// A reading document's hidden checks by line, found once it came (not on
/// every frame: a long function's take milliseconds).
pub struct FoundReveals {
    /// The reading document they were found on.
    pub on: Arc<CDocument>,
    /// Its lines hiding checks, each with the exact C's lines there.
    pub by_line: Arc<BTreeMap<usize, Reveal>>,
}

/// The compact form making a state from scratch.
pub struct StateForm {
    key: Key,
    function: String,
    inputs: Vec<(String, Entity<InputState>)>,
    error: Option<String>,
    _subs: Vec<Subscription>,
}

/// The Compare Processors card as drawn: its summary over its table, the
/// table in the code font with a column per processor.
#[derive(Clone)]
struct Table {
    card: ComparisonCard,
    /// The code font's advance and size, and the gap between columns
    /// (pixels).
    char_w: f32,
    size: f32,
    gap: f32,
    font: String,
    theme: &'static Theme,
}

impl Table {
    fn render(&self) -> AnyElement {
        let theme = self.theme;
        let card = &self.card;
        let chars = |text: &str| text.chars().count();
        let width = |n: usize| px(f(n as u64) * self.char_w);
        let label_w = width(
            card.rows
                .iter()
                .map(|row| chars(&row.label))
                .max()
                .unwrap_or(0),
        );
        let columns: Vec<Pixels> = card
            .processors
            .iter()
            .enumerate()
            .map(|(k, head)| {
                width(
                    card.rows
                        .iter()
                        .filter_map(|row| row.cells.get(k))
                        .map(|cell| chars(cell))
                        .fold(chars(head), usize::max),
                )
            })
            .collect();
        let line = |label: &str, cells: &[String], label_color: u32, color: u32| {
            div()
                .flex()
                .gap(px(self.gap))
                .whitespace_nowrap()
                .child(
                    div()
                        .w(label_w)
                        .flex_none()
                        .text_color(hsla(label_color))
                        .child(label.to_owned()),
                )
                .children(cells.iter().zip(&columns).map(|(cell, &w)| {
                    div()
                        .w(w)
                        .flex_none()
                        .text_color(hsla(color))
                        .child(cell.clone())
                }))
        };
        let table = (!card.processors.is_empty()).then(|| {
            div()
                .flex()
                .flex_col()
                .font_family(self.font.clone())
                .text_size(px(self.size))
                .child(line(
                    "",
                    &card.processors,
                    theme.text_muted,
                    theme.text_muted,
                ))
                .children(card.rows.iter().map(|row| {
                    line(
                        &row.label,
                        &row.cells,
                        theme.text_muted,
                        if row.rule {
                            theme.text_muted
                        } else {
                            theme.text
                        },
                    )
                }))
        });
        div()
            .flex()
            .flex_col()
            .gap(px(4.0))
            .child(card.summary.clone())
            .children(table)
            .into_any_element()
    }
}

/// The facts' state of the window.
#[derive(Default)]
pub struct FactsUi {
    pending: HashMap<u64, Pending>,
    pub(crate) verified: HashMap<Key, Arc<Verification>>,
    verifying: Option<(Key, Asked)>,
    /// The processors' comparisons, by function.
    compared: HashMap<Key, Arc<Comparison>>,
    /// The comparison running (cancelled on navigation or a click).
    comparing: Option<(Key, Asked)>,
    due: Option<(Key, Instant)>,
    timer: Option<Task<()>>,
    explanations: HashMap<Key, Arc<Explanation>>,
    explaining: HashSet<Key>,
    why: HashMap<Key, (usize, Arc<Why>)>,
    pub card: Option<WhyCard>,
    pub origin: Option<OriginPanel>,
    states: HashMap<FunctionId, Vec<Arc<ExampleState>>>,
    runs: HashMap<Key, Shown>,
    /// The pane whose state menu is open.
    pub menu: Option<PaneId>,
    pub form: Option<StateForm>,
    /// The stub picker: the function and the callee.
    pub stub: Option<(Key, String)>,
    /// Run from Here: the function whose compact form opens once its C
    /// is shown.
    pub run_pending: Option<u64>,
    /// The reading view's hidden checks, by function.
    pub reveals: HashMap<FunctionId, FoundReveals>,
    /// The saved processor setting ignored: for another architecture than
    /// the image's (an old project's).
    ignored_processor: Option<String>,
}

impl Workspace {
    /// The C shown where the facts look: the focused pane's, else the first
    /// C pane's.
    fn facts_target(&self) -> Option<(PaneId, Arc<CDocument>)> {
        let focused = self.layout.focused();
        let panes = std::iter::once(focused).chain(self.layout.panes().map(|p| p.id));
        for id in panes {
            if let Some(kind @ TabKind::C { .. }) = self.layout.active(id)
                && let Some(document) = self.document(kind)
            {
                return Some((id, Arc::clone(document)));
            }
        }
        None
    }

    /// Keeps the questions in step with what is shown (called before each
    /// frame): the shown function's explanation asked for; its
    /// verification after [`IDLE`] (setting `c.auto_verify`), another
    /// one in progress cancelled.
    pub fn facts_tick(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if self.session.is_none() {
            return;
        }
        let target = self.facts_target();
        let shown = target.as_ref().map(|(_, d)| key(d.function, d.view));
        // Navigation cancels a check of another function.
        if let Some((k, asked)) = &self.facts.verifying
            && Some(*k) != shown
        {
            asked.cancel();
            self.facts.verifying = None;
        }
        if let Some((k, asked)) = &self.facts.comparing
            && Some(*k) != shown
        {
            asked.cancel();
            self.facts.comparing = None;
        }
        let Some((_, document)) = target else {
            self.facts.due = None;
            return;
        };
        let k = key(document.function, document.view);
        if self.facts.run_pending == Some(document.entry) {
            self.facts.run_pending = None;
            self.open_state_form(k, window, cx);
        }
        let Some(session) = &self.session else {
            return;
        };
        if !self.facts.explanations.contains_key(&k) && self.facts.explaining.insert(k) {
            let asked = session.ask(document.function, document.view, Question::Explain);
            self.facts
                .pending
                .insert(asked.request, Pending::Explain(k));
        }
        if let Some(explanation) = self.facts.explanations.get(&k) {
            let pointer = Arc::as_ptr(&document) as usize;
            if self.facts.why.get(&k).is_none_or(|(p, _)| *p != pointer) {
                let why = Why::new(&document, explanation);
                self.facts.why.insert(k, (pointer, Arc::new(why)));
            }
        }
        let pointer = Arc::as_ptr(&document) as usize;
        let stale = self.facts.runs.get(&k).is_some_and(|shown| {
            shown.run.is_some() && shown.values.as_ref().is_none_or(|(p, _)| *p != pointer)
        });
        if stale {
            let names = self.register_names();
            if let Some(shown) = self.facts.runs.get_mut(&k)
                && let Some(run) = &shown.run
            {
                let values = Values::new(&document, run, shown.profile.as_deref(), &|id| {
                    names.get(id).cloned()
                });
                shown.values = Some((pointer, Arc::new(values)));
            }
        }
        let checked = self.facts.verified.contains_key(&k)
            || self.facts.verifying.as_ref().is_some_and(|(v, _)| *v == k);
        if !self.settings.auto_verify || checked {
            self.facts.due = None;
            return;
        }
        match self.facts.due {
            Some((due, at)) if due == k => {
                if at.elapsed() >= IDLE {
                    self.facts.due = None;
                    self.verify(k);
                }
            }
            _ => {
                self.facts.due = Some((k, Instant::now()));
                self.facts.timer = Some(cx.spawn_in(window, async move |this, cx| {
                    cx.background_executor().timer(IDLE).await;
                    let _ = this.update(cx, |_, cx| cx.notify());
                }));
            }
        }
    }

    /// Verifies function `k` now (the chip says checking until the answer).
    fn verify(&mut self, k: Key) {
        let Some(session) = &self.session else {
            return;
        };
        if let Some((_, asked)) = self.facts.verifying.take() {
            asked.cancel();
        }
        let asked = session.ask(k.0, view_of(k), Question::Verify(self.processor_profile()));
        self.facts
            .pending
            .insert(asked.request, Pending::Verify(k, Instant::now()));
        self.facts.verifying = Some((k, asked));
    }

    /// The Verify command: the shown function, now.
    pub fn verify_now(&mut self) {
        if let Some((_, document)) = self.facts_target() {
            let k = key(document.function, document.view);
            self.facts.verified.remove(&k);
            self.verify(k);
        }
    }

    /// The Compare Processors command: the shown function on the shipped
    /// processors' profiles, now (a comparison running is cancelled).
    pub fn compare_now(&mut self) {
        let Some((_, document)) = self.facts_target() else {
            return;
        };
        let Some(session) = &self.session else {
            return;
        };
        let k = key(document.function, document.view);
        if let Some((_, asked)) = self.facts.comparing.take() {
            asked.cancel();
        }
        self.facts.compared.remove(&k);
        let asked = session.ask(k.0, view_of(k), Question::Compare);
        self.facts
            .pending
            .insert(asked.request, Pending::Compare(k, Instant::now()));
        self.facts.comparing = Some((k, asked));
    }

    /// Whether `profile` fits the open image's architecture
    /// (`binbun::profile::fits`); none before the image is parsed.
    fn processor_fit(&self, profile: &Profile) -> Option<Result<(), String>> {
        let core = self.session.as_ref()?.core();
        core.image().map(|image| profile::fits(profile, image))
    }

    /// Which of [`Processor::SHIPPED`] fit the open image.
    pub fn processor_fitting(&self) -> [bool; 2] {
        Processor::SHIPPED.map(|shipped| {
            shipped
                .name()
                .and_then(|name| profile::embedded().iter().find(|p| p.id == name))
                .is_some_and(|p| self.processor_fit(p).is_some_and(|fit| fit.is_ok()))
        })
    }

    /// The processor setting, unless ignored ([`Self::check_processor`]).
    pub fn processor_setting(&self) -> Option<String> {
        let name = self.session.as_ref()?.core().processor()?;
        (self.facts.ignored_processor.as_ref() != Some(&name)).then_some(name)
    }

    /// The setting's profile, as runs and verifications take it (`None`:
    /// the architecture, or a file that no longer reads as a profile).
    pub fn processor_profile(&self) -> Option<Arc<Profile>> {
        profile::resolve(&self.processor_setting()?).ok()
    }

    /// The image is parsed: a saved processor for another architecture (an
    /// old project's) is ignored, not applied, and the status bar says so.
    pub fn check_processor(&mut self) {
        self.facts.ignored_processor = None;
        let Some(name) = self.processor_setting() else {
            return;
        };
        let Ok(profile) = profile::resolve(&name) else {
            return;
        };
        if let Some(Err(why)) = self.processor_fit(&profile) {
            self.projects.notice = Some(format!("Processor setting ignored: {why}"));
            self.facts.ignored_processor = Some(name);
        }
    }

    /// Sets the processor runs and verifications are on (`None`: the
    /// architecture), refused for another architecture than the image's:
    /// the checks made on another are dropped (the shown function's is
    /// made again, if verifying on its own), the runs shown run again on
    /// it.
    pub fn set_processor(&mut self, name: Option<&str>) {
        if let Some(name) = name
            && let Ok(profile) = profile::resolve(name)
            && let Some(Err(why)) = self.processor_fit(&profile)
        {
            self.error = Some(why);
            return;
        }
        let Some(session) = &self.session else {
            return;
        };
        if let Err(error) = session.core().set_processor(name) {
            self.error = Some(error.to_string());
            return;
        }
        self.facts.ignored_processor = None;
        if let Some((_, asked)) = self.facts.verifying.take() {
            asked.cancel();
        }
        self.facts.verified.clear();
        let shown: Vec<(Key, Arc<ExampleState>)> = self
            .facts
            .runs
            .iter()
            .map(|(&k, shown)| (k, Arc::clone(&shown.state)))
            .collect();
        for (k, state) in shown {
            self.choose_state(k, Some(state));
        }
    }

    /// Asks for a profile file and sets the processor to it.
    pub fn prompt_processor_file(window: &mut Window, cx: &mut Context<Self>) {
        let paths = cx.prompt_for_paths(gpui_kit::PathPromptOptions {
            files: true,
            directories: false,
            multiple: false,
            prompt: None,
        });
        cx.spawn_in(window, async move |this, cx| {
            if let Ok(Ok(Some(paths))) = paths.await
                && let Some(path) = paths.into_iter().next()
            {
                let _ = this.update(cx, |this, cx| {
                    this.set_processor(Some(&path.to_string_lossy()));
                    cx.notify();
                });
            }
        })
        .detach();
    }

    /// Takes an answer from the session.
    pub fn on_answer(&mut self, request: u64, answer: Answer) {
        let Some(pending) = self.facts.pending.remove(&request) else {
            return;
        };
        match (pending, answer) {
            (Pending::Verify(k, at), Answer::Verified(verification)) => {
                trace!(
                    "verify {k:?}: {:.1} ms (lowering {:.1}, checking {:.1})",
                    at.elapsed().as_secs_f64() * 1e3,
                    verification.lowering.as_secs_f64() * 1e3,
                    verification.checking.as_secs_f64() * 1e3
                );
                if self
                    .facts
                    .verifying
                    .as_ref()
                    .is_some_and(|(v, a)| *v == k && a.request == request)
                {
                    self.facts.verifying = None;
                }
                self.facts.verified.insert(k, verification);
            }
            (Pending::Compare(k, at), Answer::Compared(comparison)) => {
                trace!("compare {k:?}: {:.1} ms", at.elapsed().as_secs_f64() * 1e3);
                if self
                    .facts
                    .comparing
                    .as_ref()
                    .is_some_and(|(c, a)| *c == k && a.request == request)
                {
                    self.facts.comparing = None;
                }
                self.facts.compared.insert(k, comparison);
            }
            (Pending::Explain(k), Answer::Explained(result)) => {
                self.facts.explaining.remove(&k);
                if let Ok(explanation) = result {
                    self.facts.explanations.insert(k, explanation);
                }
            }
            (Pending::Origin(at), Answer::Origins(result)) => {
                trace!("origin: {:.1} ms", at.elapsed().as_secs_f64() * 1e3);
                if let Some(panel) = &mut self.facts.origin
                    && panel.request == request
                {
                    match result {
                        Ok(origins) => panel.origins = Some(origins),
                        Err(error) => panel.error = Some(error),
                    }
                    self.refresh_origin_marks();
                }
            }
            (Pending::Run(k, at), Answer::Ran(result)) => {
                trace!("run {k:?}: {:.1} ms", at.elapsed().as_secs_f64() * 1e3);
                if let Some(shown) = self.facts.runs.get_mut(&k)
                    && shown.asked.as_ref().is_some_and(|a| a.request == request)
                {
                    shown.asked = None;
                    match result {
                        Ok(run) => {
                            shown.run = Some(run);
                            shown.error = None;
                        }
                        Err(error) => {
                            self.error = Some(error.clone());
                            shown.error = Some(error);
                        }
                    }
                    shown.values = None;
                }
            }
            _ => {}
        }
    }

    /// Every register's name, by number.
    pub fn register_names(&self) -> Vec<String> {
        self.session
            .as_ref()
            .and_then(|s| s.database())
            .and_then(binbun::Database::declarations)
            .map(|d| d.registers.iter().map(|r| r.name.to_owned()).collect())
            .unwrap_or_default()
    }

    /// The name of the function at `entry` as shown.
    fn function_name(&self, entry: u64) -> String {
        self.listing
            .as_ref()
            .zip(self.session.as_ref())
            .and_then(|(l, s)| l.shown_name(entry, s.overlay()))
            .map_or_else(|| format!("sub_{entry:X}"), str::to_owned)
    }

    // ---- the chip ----

    /// The verification mark of C pane `id`, if its function was checked
    /// or is being checked: a circle checked (agreed), crossed (differs:
    /// a click runs the differing state), dashed (not checkable) or empty
    /// (checking); hovering it shows what the check found.
    pub fn verify_chip(&self, id: PaneId, cx: &mut Context<Self>) -> Option<AnyElement> {
        let theme = self.theme;
        let document = self.document(self.layout.active(id)?)?;
        let k = key(document.function, document.view);
        let verification = self.facts.verified.get(&k).map(Arc::as_ref);
        let chip = if self.facts.verifying.as_ref().is_some_and(|(v, _)| *v == k) {
            Chip::Checking
        } else {
            Chip::of(verification?)
        };
        let (mark, color) = match chip {
            Chip::Agreed(_) => (IconName::CircleCheck, theme.agreed),
            Chip::Differs => (IconName::CircleX, theme.error),
            Chip::NotCheckable(_) => (IconName::CircleDashed, theme.text_muted),
            Chip::Checking => (IconName::Circle, theme.text_muted),
        };
        let mut lines = chip.card(verification);
        let names = self.register_names();
        lines.extend(processor_dependent(
            document.processor_dependent,
            &document.undefined_values,
            &|id| names.get(usize::from(id.0)).cloned(),
        ));
        let differs = chip == Chip::Differs;
        Some(
            div()
                .id(("verify-chip", id.0))
                .flex()
                .flex_none()
                .items_center()
                .justify_center()
                .size(self.z(ICON_BUTTON))
                .rounded(self.z(4.0))
                .tooltip(move |window, cx| {
                    let lines = lines.clone();
                    Tooltip::element(move |_, _| div().flex().flex_col().children(lines.clone()))
                        .build(window, cx)
                })
                .when(differs, |d| {
                    d.hover(|s| s.bg(hsla(theme.element_hover)))
                        .on_click(cx.listener(move |this, _, _, cx| {
                            this.run_counterexample(k);
                            cx.notify();
                        }))
                })
                .child(icon(mark, self.z(ICON), hsla(color)))
                .into_any_element(),
        )
    }

    /// Opens the counterexample of function `k` as its run state.
    fn run_counterexample(&mut self, k: Key) {
        let Some(verification) = self.facts.verified.get(&k).cloned() else {
            return;
        };
        let names = self.register_names();
        let name = self.function_name(verification.entry);
        if let Some(state) =
            counterexample_state(&verification, &name, &|id| names.get(id).cloned())
        {
            self.choose_state(k, Some(Arc::new(state)));
        }
    }

    /// The Compare Processors mark of C pane `id`, if its function was
    /// compared or is being compared: coloured as the answer (a click
    /// cancels a comparison running, and opens a differing state as the
    /// run); hovering it shows the card.
    pub fn compare_chip(&self, id: PaneId, cx: &mut Context<Self>) -> Option<AnyElement> {
        let theme = self.theme;
        let document = self.document(self.layout.active(id)?)?;
        let k = key(document.function, document.view);
        let comparing = self.facts.comparing.as_ref().is_some_and(|(c, _)| *c == k);
        let comparison = if comparing {
            None
        } else {
            Some(self.facts.compared.get(&k)?)
        };
        let color = match comparison.map(|c| &c.verdict) {
            None | Some(Compared::NotReached | Compared::NotCheckable(_)) => theme.text_muted,
            Some(Compared::Same) => theme.agreed,
            Some(Compared::Differs(_)) => theme.error,
        };
        let clickable =
            comparing || comparison.is_some_and(|c| matches!(c.verdict, Compared::Differs(_)));
        let sites = self
            .session
            .as_ref()
            .and_then(|s| s.database())
            .and_then(binbun::Database::declarations)
            .map(|d| d.sites)
            .unwrap_or_default();
        let card = ComparisonCard::new(
            comparison.map(Arc::as_ref),
            &|site| {
                sites
                    .get(usize::from(site.0))
                    .map_or_else(|| format!("site {}", site.0), |info| info.name.to_owned())
            },
            &|address| self.function_name(address),
        );
        let table = Table {
            card,
            char_w: self.char_width.unwrap_or(8.0),
            size: self.code_size(),
            gap: f32::from(self.z(12.0)),
            font: self.settings.code_font.clone(),
            theme,
        };
        Some(
            div()
                .id(("compare-chip", id.0))
                .flex()
                .flex_none()
                .items_center()
                .justify_center()
                .size(self.z(ICON_BUTTON))
                .rounded(self.z(4.0))
                .tooltip(move |window, cx| {
                    let table = table.clone();
                    Tooltip::element(move |_, _| table.render()).build(window, cx)
                })
                .when(clickable, |d| {
                    d.hover(|s| s.bg(hsla(theme.element_hover)))
                        .on_click(cx.listener(move |this, _, _, cx| {
                            this.click_comparison(k);
                            cx.notify();
                        }))
                })
                .child(icon(
                    if comparing {
                        IconName::LoaderCircle
                    } else {
                        IconName::ArrowRightLeft
                    },
                    self.z(ICON),
                    hsla(color),
                ))
                .into_any_element(),
        )
    }

    /// A click on function `k`'s comparison mark: cancels the comparison
    /// running, else opens the first differing state as the run.
    fn click_comparison(&mut self, k: Key) {
        if let Some((c, asked)) = &self.facts.comparing
            && *c == k
        {
            asked.cancel();
            self.facts.comparing = None;
            return;
        }
        let Some(comparison) = self.facts.compared.get(&k) else {
            return;
        };
        if let Compared::Differs(differing) = &comparison.verdict
            && let Some(first) = differing.first()
        {
            let mut state = first.example.clone();
            state.function = Some(self.function_name(comparison.entry));
            self.choose_state(k, Some(Arc::new(state)));
        }
    }

    /// What the run shown on `document` gave at `value`'s site, on its
    /// processor: the profile and the values (`1`, `1 · 0 ×4`).
    pub fn run_value(
        &self,
        document: &CDocument,
        value: UndefinedValue,
    ) -> Option<(Arc<Profile>, String)> {
        let shown = self
            .facts
            .runs
            .get(&key(document.function, document.view))?;
        let profile = Arc::clone(shown.profile.as_ref()?);
        let site = value.site?;
        let machine = shown.run.as_ref()?.machine.as_ref()?;
        let (.., values) = machine
            .choices
            .made()
            .find(|&(address, at, _)| address == value.address && at == site)?;
        let texts: Vec<String> = values.iter().map(show).collect();
        Some((profile, trail(&texts, texts.len() as u64)))
    }

    // ---- why ----

    /// The why marks of `document`, if its explanation came.
    pub fn why_marks(&self, document: &CDocument) -> Option<Arc<Why>> {
        let k = key(document.function, document.view);
        self.facts.why.get(&k).map(|(_, why)| Arc::clone(why))
    }

    /// The pointer is over span `span` of `document` at `position`: the
    /// why card opens on a marked one, closes off it.
    pub fn hover_why(
        &mut self,
        document: &CDocument,
        span: Option<usize>,
        position: Point<Pixels>,
    ) {
        let k = key(document.function, document.view);
        let item = span.and_then(|s| {
            self.facts
                .why
                .get(&k)
                .and_then(|(_, why)| why.marks.get(&s).copied())
        });
        match item {
            Some(item) => {
                if self
                    .facts
                    .card
                    .as_ref()
                    .is_none_or(|c| c.explained != Explained::Item(k, item))
                {
                    self.facts.card = Some(WhyCard {
                        explained: Explained::Item(k, item),
                        position,
                        hovered: false,
                        pinned: false,
                    });
                }
            }
            None => {
                self.leave_why();
            }
        }
    }

    /// The pointer left the marked tokens: the card closes unless the
    /// pointer is on it (it gets there across the gap: the card's own
    /// hover keeps it, and closes it when the pointer leaves it).
    pub fn leave_why(&mut self) {
        if self
            .facts
            .card
            .as_ref()
            .is_some_and(|c| !c.hovered && !c.pinned)
        {
            self.facts.card = None;
        }
    }

    /// The item of the shown explanation for the variable under the
    /// focused C pane's cursor, if it has something to say.
    pub fn why_item_at_cursor(&self) -> Option<(Key, usize)> {
        if self.menu_subject.is_some() {
            return None;
        }
        let id = self.layout.focused();
        let document = self.document(self.layout.active(id)?)?;
        let var = document.variable(self.panes.get(&id)?.c.span?)?;
        let k = key(document.function, document.view);
        let item = item_of(self.facts.explanations.get(&k)?, var)?;
        Some((k, item))
    }

    /// The function whose name is under the focused pane's cursor (its
    /// own name, a call's callee), for the Why card.
    pub fn why_function_at_cursor(&self) -> Option<u64> {
        let target = self.target_under_cursor()?;
        self.functions
            .binary_search_by_key(&target, |&(e, _)| e)
            .is_ok()
            .then_some(target)
    }

    /// The function Reject Signature is about, if a library signature
    /// names it: the one named under the cursor, else the cursor's (not
    /// the cursor's when another function is named there).
    pub fn signature_at_cursor(&self) -> Option<u64> {
        let entry = if let Some(entry) = self.why_function_at_cursor() {
            entry
        } else {
            let at = self.current_address()?;
            self.listing.as_ref()?.function_of(at)?.1
        };
        self.session.as_ref()?.signature(entry).map(|_| entry)
    }

    /// Reject Signature: the library signature naming the function under
    /// the cursor (else the cursor's) is rejected, its name and prototype
    /// back as before it (undoable); the C printed again.
    pub fn reject_signature_at_cursor(&mut self) {
        let Some(entry) = self.signature_at_cursor() else {
            return;
        };
        let Some(session) = &mut self.session else {
            return;
        };
        if let Err(error) = session.reject_signature(entry) {
            self.error = Some(error);
            return;
        }
        self.facts.card = None;
        self.pin_active(self.layout.focused());
        self.ensure_documents();
    }

    /// The Why command: the card of the variable under the cursor, under
    /// its token, else of the function's name there (where it comes
    /// from), until Esc or a click outside.
    pub fn open_why_at_cursor(&mut self) {
        let Some(explained) = self
            .why_item_at_cursor()
            .map(|(k, item)| Explained::Item(k, item))
            .or_else(|| self.why_function_at_cursor().map(Explained::Function))
        else {
            return;
        };
        let id = self.layout.focused();
        let in_c = matches!(self.layout.active(id), Some(TabKind::C { .. }));
        let Some(position) = in_c
            .then(|| self.panes.get(&id).and_then(|s| s.c.span))
            .flatten()
            .and_then(|span| self.c_span_point(id, span))
            .or_else(|| self.under_cursor_line(id))
        else {
            return;
        };
        self.close_peek();
        self.facts.card = Some(WhyCard {
            explained,
            position,
            hovered: false,
            pinned: true,
        });
    }

    /// Run from Here: the compact form of a new example state for the
    /// function named under the cursor, else the cursor's function (one
    /// without parameters runs at once); its C shown first (a C pane
    /// beside the focused one if none shows C).
    pub fn run_from_here(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let Some(listing) = self.listing.clone() else {
            return;
        };
        let named = self
            .target_under_cursor()
            .filter(|a| self.functions.binary_search_by_key(a, |&(e, _)| e).is_ok());
        let Some(entry) = named.or_else(|| {
            let at = self.current_address()?;
            listing.function_of(at).map(|(_, entry)| entry)
        }) else {
            self.error = Some("No function at the cursor to run".to_owned());
            return;
        };
        let shows_c = self.layout.panes().any(|p| {
            matches!(
                p.tabs.get(p.active).map(|t| &t.content),
                Some(TabKind::C { .. })
            )
        });
        if !shows_c {
            let id = self.layout.focused();
            let view = self.default_view();
            if let Some(new) = self.layout.split(
                id,
                Axis::Row,
                TabKind::C {
                    function: None,
                    view,
                },
            ) {
                self.ensure_pane(new, cx);
                self.focus_pane(id, window, cx);
            }
        }
        if self
            .current_address()
            .and_then(|a| listing.function_of(a))
            .map(|(_, e)| e)
            != Some(entry)
        {
            self.jump(entry, cx);
        }
        self.facts.form = None;
        self.facts.run_pending = Some(entry);
        self.ensure_documents();
    }

    /// The why card, in the peek card's style.
    #[expect(clippy::too_many_lines, reason = "the card's header and lines")]
    pub fn render_why_card(&self, window: &Window, cx: &mut Context<Self>) -> Option<AnyElement> {
        let theme = self.theme;
        let card = self.facts.card.as_ref()?;
        let shown = match card.explained {
            Explained::Item(k, item) => {
                Card::new(self.facts.explanations.get(&k)?.items.get(item)?)
            }
            Explained::Function(entry) => {
                let session = self.session.as_ref()?;
                let name = self.function_name(entry);
                let name = self
                    .demangled
                    .get(&name)
                    .and_then(Clone::clone)
                    .unwrap_or(name);
                // An agent's rename names the agent.
                let agent = session
                    .name_writer(entry)
                    .filter(|&key| self.is_agent(key))
                    .map(|key| self.talk_name(key));
                Card::function(
                    &name,
                    session.name_source(entry).as_ref(),
                    agent.as_deref(),
                    session.signature_record(entry).as_ref(),
                )
            }
        };
        // The labels' column as wide as the longest label in the UI
        // font's average advance, 36 at least.
        let label_width =
            self.z((0.6 * self.settings.ui_font_size * f(shown.label_chars() as u64)).max(36.0));
        let code = self.settings.code_font.clone();
        let lines: Vec<AnyElement> = shown
            .lines
            .iter()
            .enumerate()
            .map(|(n, line)| {
                let links: Vec<AnyElement> = line
                    .addresses
                    .iter()
                    .take(6)
                    .enumerate()
                    .map(|(k, &address)| {
                        div()
                            .id(("why-link", n * 16 + k))
                            .px(self.z(3.0))
                            .rounded(self.z(3.0))
                            .text_color(hsla(theme.accent))
                            .hover(|s| s.bg(hsla(theme.element_hover)))
                            .on_click(cx.listener(move |this, _, _, cx| {
                                this.facts.card = None;
                                this.jump(address, cx);
                            }))
                            .child(format!("{address:X}"))
                            .into_any_element()
                    })
                    .collect();
                div()
                    .flex()
                    .gap(self.z(8.0))
                    .px(self.z(10.0))
                    .min_h(self.z(22.0))
                    .items_center()
                    .child(
                        div()
                            .w(label_width)
                            .flex_none()
                            .text_color(hsla(theme.text_muted))
                            .child(line.label.clone()),
                    )
                    .child(
                        div()
                            .flex_1()
                            .min_w_0()
                            .overflow_hidden()
                            .text_ellipsis()
                            .whitespace_nowrap()
                            .text_color(hsla(if line.conflict {
                                theme.error
                            } else {
                                theme.text
                            }))
                            .child(line.text.clone()),
                    )
                    .child(
                        div()
                            .flex()
                            .flex_none()
                            .font_family(code.clone())
                            .children(links),
                    )
                    .into_any_element()
            })
            .collect();
        let width = self.z(520.0);
        let viewport = window.viewport_size();
        let x = card
            .position
            .x
            .min(viewport.width - width - self.z(8.0))
            .max(px(0.0));
        let height = self.z(30.0 + 8.0 + 22.0 * f(lines.len() as u64));
        let below = card.position.y + self.z(6.0);
        let y = if below + height > viewport.height {
            (card.position.y - height - self.z(4.0)).max(px(0.0))
        } else {
            below
        };
        Some(
            self.card()
                .id("why")
                .absolute()
                .left(x)
                .top(y)
                .w(width)
                .text_size(self.z(self.settings.ui_font_size))
                .on_hover(cx.listener(|this, hovered: &bool, _, cx| {
                    if let Some(card) = &mut this.facts.card {
                        card.hovered = *hovered;
                        if !*hovered && !card.pinned {
                            this.facts.card = None;
                        }
                        cx.notify();
                    }
                }))
                .on_mouse_down(MouseButton::Left, |_, _, cx| cx.stop_propagation())
                .on_mouse_down_out(cx.listener(|this, _, _, cx| {
                    this.facts.card = None;
                    cx.notify();
                }))
                .child(
                    div()
                        .flex()
                        .items_center()
                        .px(self.z(10.0))
                        .h(self.z(30.0))
                        .border_b_1()
                        .border_color(hsla(theme.border_variant))
                        .font_family(code)
                        .child(shown.title),
                )
                .child(div().py(self.z(4.0)).children(lines))
                .into_any_element(),
        )
    }

    // ---- origin ----

    /// Opens the Origin panel for the value under the focused pane's
    /// cursor: a C token's (its variable, or its node), or a listing
    /// line's instruction (the C node it came to).
    pub fn open_origin(&mut self) {
        let id = self.layout.focused();
        let Some(kind) = self.layout.active(id).cloned() else {
            return;
        };
        let (document, start, title) = match &kind {
            TabKind::C { .. } => {
                let Some(document) = self.document(&kind).cloned() else {
                    return;
                };
                let Some(s) = self.panes.get(&id).and_then(|p| p.c.span) else {
                    return;
                };
                let Some(node) = document.spans.get(s).and_then(|s| s.node) else {
                    return;
                };
                let start = match node {
                    Node::Var(var) => Start::Var(var),
                    Node::Expr(_) | Node::Stmt(_) | Node::Type(_) => Start::Node(node),
                };
                let title = document.span_text(s).to_owned();
                (document, start, title)
            }
            TabKind::Listing => {
                let Some(address) = self.cursor_address(id) else {
                    return;
                };
                let Some(function) = self
                    .listing
                    .as_ref()
                    .and_then(|l| l.function_of(address))
                    .map(|(f, _)| f)
                else {
                    return;
                };
                let view = self.default_view();
                let Some(document) = self
                    .session
                    .as_ref()
                    .and_then(|s| s.document(function, view))
                    .cloned()
                else {
                    return;
                };
                let Some(s) = document.spans_of(address).first().copied() else {
                    return;
                };
                let Some(node) = document.spans.get(s).and_then(|s| s.node) else {
                    return;
                };
                (document, Start::Node(node), format!("{address:X}"))
            }
            TabKind::Settings
            | TabKind::Console
            | TabKind::Terminal(_)
            | TabKind::Strings
            | TabKind::Xrefs { .. }
            | TabKind::Struct(_)
            | TabKind::Found(_)
            | TabKind::Folder(_) => return,
        };
        let Some(session) = &self.session else {
            return;
        };
        let asked = session.ask(document.function, document.view, Question::Origins(start));
        self.facts
            .pending
            .insert(asked.request, Pending::Origin(Instant::now()));
        self.facts.origin = Some(OriginPanel {
            key: key(document.function, document.view),
            title,
            request: asked.request,
            origins: None,
            error: None,
            open: BTreeSet::new(),
            forward: false,
            nodes: HashSet::new(),
            addresses: HashSet::new(),
        });
        self.right_sidebar = true;
    }

    /// The Origin panel's rows.
    fn origin_rows(&self) -> Vec<OriginRow> {
        let Some(panel) = &self.facts.origin else {
            return Vec::new();
        };
        let Some(origins) = &panel.origins else {
            return Vec::new();
        };
        let document = self
            .session
            .as_ref()
            .and_then(|s| s.document(panel.key.0, view_of(panel.key)));
        origin_rows(
            origins,
            document.map(AsRef::as_ref),
            &panel.open,
            panel.forward,
        )
    }

    /// The nodes and instructions the panel's rows highlight.
    fn refresh_origin_marks(&mut self) {
        let rows = self.origin_rows();
        if let Some(panel) = &mut self.facts.origin {
            panel.nodes = rows.iter().flat_map(|r| r.nodes.iter().copied()).collect();
            panel.addresses = rows
                .iter()
                .flat_map(|r| r.addresses.iter().copied())
                .collect();
        }
    }

    /// Whether the Origin panel highlights C node `node` of function `k`.
    pub fn origin_node(&self, document: &CDocument, node: Node) -> bool {
        self.facts.origin.as_ref().is_some_and(|p| {
            p.key == key(document.function, document.view) && p.nodes.contains(&node)
        })
    }

    /// Whether the Origin panel highlights the instruction at `address`.
    pub fn origin_address(&self, address: u64) -> bool {
        self.facts
            .origin
            .as_ref()
            .is_some_and(|p| p.addresses.contains(&address))
    }

    /// The Origin panel (the right dock's content).
    #[expect(clippy::too_many_lines, reason = "the header and each row's parts")]
    pub fn render_origin(&self, cx: &mut Context<Self>) -> Option<AnyElement> {
        let theme = self.theme;
        let panel = self.facts.origin.as_ref()?;
        let rows = self.origin_rows();
        let indent = self.z(12.0);
        let items: Vec<AnyElement> = rows
            .iter()
            .enumerate()
            .map(|(n, row)| {
                let address = row.addresses.first().copied();
                let path = row.path.clone();
                let foldable = row.folds > 0 && !row.folded;
                let chevron = foldable.then(|| {
                    let open = row.open;
                    div()
                        .id(("origin-fold", n))
                        .flex_none()
                        .on_mouse_down(MouseButton::Left, |_, _, cx| cx.stop_propagation())
                        .on_click(cx.listener(move |this, _, _, cx| {
                            if let Some(panel) = &mut this.facts.origin
                                && !panel.open.remove(&path)
                            {
                                panel.open.insert(path.clone());
                            }
                            this.refresh_origin_marks();
                            cx.notify();
                        }))
                        .child(icon(
                            if open {
                                IconName::ChevronDown
                            } else {
                                IconName::ChevronRight
                            },
                            self.z(ICON - 2.0),
                            hsla(theme.text_muted),
                        ))
                });
                let text_color = if row.folded {
                    theme.text_muted
                } else {
                    theme.text
                };
                div()
                    .id(("origin-row", n))
                    .flex()
                    .items_center()
                    .gap(self.z(6.0))
                    .h(self.z(22.0))
                    .pl(indent * f(row.depth as u64) + self.z(8.0))
                    .pr(self.z(8.0))
                    .whitespace_nowrap()
                    .overflow_hidden()
                    .hover(|s| s.bg(hsla(theme.element_hover)))
                    .when_some(address, |d, address| {
                        d.on_click(cx.listener(move |this, _, _, cx| this.jump(address, cx)))
                    })
                    .child(div().w(self.z(ICON - 2.0)).flex_none().children(chevron))
                    .when(row.fork, |d| {
                        d.child(div().text_color(hsla(theme.text_muted)).child("⑂"))
                    })
                    .child(div().text_color(hsla(text_color)).child(row.text.clone()))
                    .when(foldable, |d| {
                        d.child(
                            div()
                                .text_color(hsla(theme.text_muted))
                                .child(format!("+{}", row.folds)),
                        )
                    })
                    .child(div().flex_1())
                    .when_some(row.excerpt.clone(), |d, excerpt| {
                        d.child(
                            div()
                                .min_w_0()
                                .overflow_hidden()
                                .text_ellipsis()
                                .font_family(self.settings.code_font.clone())
                                .text_color(hsla(theme.text_muted))
                                .child(excerpt),
                        )
                    })
                    .when_some(address, |d, address| {
                        d.child(
                            div()
                                .flex_none()
                                .font_family(self.settings.code_font.clone())
                                .text_color(hsla(theme.text_muted))
                                .child(format!("{address:X}")),
                        )
                    })
                    .into_any_element()
            })
            .collect();
        let forward = panel.forward;
        let header = div()
            .flex()
            .flex_none()
            .items_center()
            .gap(self.z(6.0))
            .h(self.bar(TOOLBAR_PAD))
            .px(self.z(8.0))
            .border_b_1()
            .border_color(hsla(theme.border_variant))
            .child(
                div()
                    .flex_1()
                    .min_w_0()
                    .overflow_hidden()
                    .text_ellipsis()
                    .whitespace_nowrap()
                    .font_family(self.settings.code_font.clone())
                    .child(panel.title.clone()),
            )
            .child(
                div()
                    .id("origin-direction")
                    .flex()
                    .items_center()
                    .justify_center()
                    .size(self.z(ICON_BUTTON))
                    .rounded(self.z(4.0))
                    .when(forward, |d| d.bg(hsla(theme.element_selected)))
                    .hover(|s| s.bg(hsla(theme.element_hover)))
                    .tooltip(move |window, cx| {
                        Tooltip::new(if forward { "Uses" } else { "Origins" }).build(window, cx)
                    })
                    .on_click(cx.listener(|this, _, _, cx| {
                        if let Some(panel) = &mut this.facts.origin {
                            panel.forward = !panel.forward;
                        }
                        this.refresh_origin_marks();
                        cx.notify();
                    }))
                    .child(icon(
                        if forward {
                            IconName::ArrowRight
                        } else {
                            IconName::ArrowLeft
                        },
                        self.z(ICON),
                        hsla(theme.text_muted),
                    )),
            )
            .child(
                div()
                    .id("origin-close")
                    .flex()
                    .items_center()
                    .justify_center()
                    .size(self.z(ICON_BUTTON))
                    .rounded(self.z(4.0))
                    .hover(|s| s.bg(hsla(theme.element_hover)))
                    .on_click(cx.listener(|this, _, _, cx| {
                        this.facts.origin = None;
                        this.right_sidebar = false;
                        cx.notify();
                    }))
                    .child(icon(IconName::X, self.z(ICON), hsla(theme.text_muted))),
            );
        let pending = panel.origins.is_none() && panel.error.is_none();
        Some(
            div()
                .flex()
                .flex_col()
                .size_full()
                .child(header)
                .when(pending, |d| {
                    d.child(div().h(px(2.0)).w_full().bg(hsla(theme.accent)))
                })
                .when_some(panel.error.clone(), |d, e| {
                    d.child(
                        div()
                            .px(self.z(8.0))
                            .py(self.z(4.0))
                            .text_color(hsla(theme.error))
                            .child(e),
                    )
                })
                .child(
                    div()
                        .id("origin-rows")
                        .flex_1()
                        .min_h_0()
                        .overflow_y_scroll()
                        .py(self.z(4.0))
                        .children(items),
                )
                .into_any_element(),
        )
    }

    // ---- run with values ----

    /// The states saved for function `function` (named `name`), loaded once.
    fn states_of(&mut self, function: FunctionId, name: &str) -> Vec<Arc<ExampleState>> {
        if let Some(states) = self.facts.states.get(&function) {
            return states.clone();
        }
        let Some(project) = self.session.as_ref().and_then(Session::project) else {
            return Vec::new();
        };
        let states: Vec<Arc<ExampleState>> = load_states(&project.states(), name)
            .into_iter()
            .map(Arc::new)
            .collect();
        self.facts.states.insert(function, states.clone());
        states
    }

    /// Chooses `state` for function `k` (`None`: no values) and runs it.
    pub fn choose_state(&mut self, k: Key, state: Option<Arc<ExampleState>>) {
        if let Some(old) = self.facts.runs.remove(&k)
            && let Some(asked) = old.asked
        {
            asked.cancel();
        }
        let Some(state) = state else {
            return;
        };
        let Some(session) = &self.session else {
            return;
        };
        let profile = self.processor_profile();
        let asked = session.ask(
            k.0,
            view_of(k),
            Question::Run(Arc::clone(&state), profile.clone()),
        );
        self.facts
            .pending
            .insert(asked.request, Pending::Run(k, Instant::now()));
        self.facts.runs.insert(
            k,
            Shown {
                state,
                profile,
                run: None,
                error: None,
                values: None,
                asked: Some(asked),
            },
        );
    }

    /// Saves `state` in the project and adds it to its function's.
    fn keep_state(&mut self, function: FunctionId, state: &ExampleState) {
        let Some(project) = self.session.as_ref().and_then(Session::project) else {
            return;
        };
        match save_state(&project.states(), state) {
            Ok(_) => {
                let states = self.facts.states.entry(function).or_default();
                states.retain(|s| s.name != state.name);
                states.push(Arc::new(state.clone()));
                states.sort_by(|a, b| a.name.cmp(&b.name));
            }
            Err(error) => self.error = Some(error),
        }
    }

    /// The run values on `document`, if a state is chosen and ran.
    pub fn run_values(&self, document: &CDocument) -> Option<Arc<Values>> {
        let shown = self
            .facts
            .runs
            .get(&key(document.function, document.view))?;
        shown.values.as_ref().map(|(_, v)| Arc::clone(v))
    }

    /// The registers the shown run wrote at `address`.
    pub fn run_registers(&self, address: u64) -> Option<String> {
        self.facts.runs.values().find_map(|shown| {
            shown
                .values
                .as_ref()
                .and_then(|(_, v)| v.registers.get(&address).cloned())
        })
    }

    /// The example-state selector of C pane `id`.
    pub fn state_selector(&self, id: PaneId, cx: &mut Context<Self>) -> Option<AnyElement> {
        let theme = self.theme;
        let document = self.document(self.layout.active(id)?)?;
        let k = key(document.function, document.view);
        let shown = self.facts.runs.get(&k);
        let label = shown.map(|s| s.state.name.clone());
        let failed = shown.and_then(|s| s.error.clone()).or_else(|| {
            shown
                .and_then(|s| s.run.as_ref())
                .filter(|r| !matches!(r.c.stop, binbun::run::Stop::Returned(_)))
                .map(|r| r.c.stop.to_string())
        });
        Some(
            div()
                .id(("state-selector", id.0))
                .flex()
                .flex_none()
                .items_center()
                .gap(self.z(4.0))
                .h(self.z(ICON_BUTTON))
                .px(self.z(4.0))
                .rounded(self.z(4.0))
                .hover(|s| s.bg(hsla(theme.element_hover)))
                .when_some(failed, |d, why| {
                    d.tooltip(move |window, cx| Tooltip::new(why.clone()).build(window, cx))
                })
                .on_mouse_down(MouseButton::Left, |_, window, cx| {
                    window.prevent_default();
                    cx.stop_propagation();
                })
                .on_click(cx.listener(move |this, _, _, cx| {
                    this.facts.menu = if this.facts.menu == Some(id) {
                        None
                    } else {
                        Some(id)
                    };
                    cx.notify();
                }))
                .child(icon(
                    IconName::Play,
                    self.z(ICON - 2.0),
                    hsla(if label.is_some() {
                        theme.text
                    } else {
                        theme.text_muted
                    }),
                ))
                .when_some(label, |d, label| {
                    d.child(div().text_color(hsla(theme.text)).child(label))
                })
                .into_any_element(),
        )
    }

    /// The open state menu (under its pane's toolbar, right-aligned).
    pub fn render_state_menu(&mut self, cx: &mut Context<Self>) -> Option<AnyElement> {
        let theme = self.theme;
        let id = self.facts.menu?;
        let document = Arc::clone(self.document(self.layout.active(id)?)?);
        let k = key(document.function, document.view);
        let name = self.function_name(document.entry);
        let states = self.states_of(document.function, &name);
        let bounds = self.panes.get(&id)?.bounds.get();
        let item = |id: (&'static str, usize), text: String, muted: bool| {
            div()
                .id(id)
                .flex()
                .items_center()
                .px(self.z(10.0))
                .h(self.z(24.0))
                .rounded(self.z(4.0))
                .whitespace_nowrap()
                .text_color(hsla(if muted { theme.text_muted } else { theme.text }))
                .hover(|s| s.bg(hsla(theme.element_hover)))
                .child(text)
        };
        let mut entries: Vec<AnyElement> = vec![
            item(("state-none", 0), "None".to_owned(), true)
                .on_click(cx.listener(move |this, _, _, cx| {
                    this.choose_state(k, None);
                    this.facts.menu = None;
                    cx.notify();
                }))
                .into_any_element(),
        ];
        for (n, state) in states.into_iter().enumerate() {
            entries.push(
                item(("state", n), state.name.clone(), false)
                    .on_click(cx.listener(move |this, _, _, cx| {
                        this.choose_state(k, Some(Arc::clone(&state)));
                        this.facts.menu = None;
                        cx.notify();
                    }))
                    .into_any_element(),
            );
        }
        entries.push(
            div()
                .my(self.z(4.0))
                .h(px(1.0))
                .bg(hsla(theme.border_variant))
                .into_any_element(),
        );
        entries.push(
            item(("state-new", 0), "New…".to_owned(), false)
                .on_click(cx.listener(move |this, _, window, cx| {
                    this.facts.menu = None;
                    this.open_state_form(k, window, cx);
                    cx.notify();
                }))
                .into_any_element(),
        );
        entries.push(
            item(("state-random", 0), "Random".to_owned(), false)
                .on_click(cx.listener(move |this, _, _, cx| {
                    this.facts.menu = None;
                    this.random_state(k);
                    cx.notify();
                }))
                .into_any_element(),
        );
        entries.push(
            item(("state-site", 0), "From a Call Site".to_owned(), false)
                .on_click(cx.listener(move |this, _, _, cx| {
                    this.facts.menu = None;
                    this.call_site_state(k);
                    cx.notify();
                }))
                .into_any_element(),
        );
        let width = self.z(220.0);
        let x = bounds.origin.x + bounds.size.width - width - self.z(8.0);
        let y = bounds.origin.y + self.z(2.0);
        Some(
            div()
                .id("state-menu")
                .absolute()
                .left(x)
                .top(y)
                .w(width)
                .p(self.z(4.0))
                .bg(hsla(solid(theme.panel)))
                .border_1()
                .border_color(hsla(theme.border_variant))
                .rounded(self.z(6.0))
                .shadow_lg()
                .occlude()
                .on_mouse_down_out(cx.listener(|this, _, _, cx| {
                    this.facts.menu = None;
                    cx.notify();
                }))
                .children(entries)
                .into_any_element(),
        )
    }

    /// A state from the differential's random states (the next seed of
    /// the function's), saved and run.
    fn random_state(&mut self, k: Key) {
        let Some(db) = self.session.as_ref().and_then(|s| s.database()) else {
            return;
        };
        let Some(entry) = db.function(k.0).map(|f| f.entry) else {
            return;
        };
        let Ok(setup) = binbun::target::setup(db.image(), entry) else {
            return;
        };
        let name = self.function_name(entry);
        let count = self.states_of(k.0, &name).len() as u64;
        let seed = entry ^ (count + 1).wrapping_mul(0x9e37_79b9_7f4a_7c15);
        let mut state = ExampleState::random(&setup, seed, &format!("random{}", count + 1));
        state.function = Some(name);
        self.keep_state(k.0, &state);
        self.choose_state(k, Some(Arc::new(state)));
    }

    /// A state from the first call site of the function whose caller's C
    /// is here (asked for if not: the next try finds it).
    fn call_site_state(&mut self, k: Key) {
        let Some(session) = &mut self.session else {
            return;
        };
        let Some(db) = session.database() else {
            return;
        };
        let Some(entry) = db.function(k.0).map(|f| f.entry) else {
            return;
        };
        let sites: Vec<(FunctionId, u64)> = db
            .references()
            .to(entry)
            .iter()
            .filter_map(|r| Some((r.function?, r.from)))
            .collect();
        let found = sites.iter().find_map(|&(caller, at)| {
            let decompiled = session.document(caller, view_of(k))?.decompiled.clone()?;
            binbun::run::call_site_state(&decompiled, at, None, &format!("site{at:x}")).ok()
        });
        if let Some(mut state) = found {
            let name = self.function_name(entry);
            state.function = Some(name);
            self.keep_state(k.0, &state);
            self.choose_state(k, Some(Arc::new(state)));
        } else if let Some(session) = &mut self.session {
            for (caller, _) in sites.into_iter().take(1) {
                session.ensure(caller, view_of(k));
            }
        }
    }

    /// Opens the compact form: one field per parameter; a function without
    /// parameters gets its state at once, saved and run.
    fn open_state_form(&mut self, k: Key, window: &mut Window, cx: &mut Context<Self>) {
        let Some(session) = &self.session else {
            return;
        };
        let Some(document) = session.document(k.0, view_of(k)).cloned() else {
            return;
        };
        let parameters: Vec<String> = document
            .parameters
            .iter()
            .map(|(_, name)| name.clone())
            .collect();
        let function = self.function_name(document.entry);
        if parameters.is_empty() {
            self.facts.form = None;
            if let Err(error) = self.new_state(k, &function, &[]) {
                self.error = Some(error);
            }
            return;
        }
        let mut inputs = Vec::new();
        let mut subs = Vec::new();
        for (n, parameter) in parameters.into_iter().enumerate() {
            let input = cx.new(|cx| InputState::new(window, cx));
            subs.push(cx.subscribe_in(
                &input,
                window,
                move |this, _, e: &InputEvent, window, cx| {
                    if let InputEvent::PressEnter { .. } = e {
                        this.commit_state_form(window, cx);
                    }
                },
            ));
            if n == 0 {
                input.update(cx, |s, cx| s.focus(window, cx));
            }
            inputs.push((parameter, input));
        }
        self.facts.form = Some(StateForm {
            key: k,
            function,
            inputs,
            error: None,
            _subs: subs,
        });
    }

    /// A new state of function `k` (named `function`) from `arguments`,
    /// after those saved (`state3`), saved and run.
    fn new_state(&mut self, k: Key, function: &str, arguments: &[String]) -> Result<(), String> {
        let count = self.states_of(k.0, function).len();
        let state = scratch_state(&format!("state{}", count + 1), function, arguments)?;
        self.keep_state(k.0, &state);
        self.choose_state(k, Some(Arc::new(state)));
        Ok(())
    }

    /// Makes the form's state, saves and runs it.
    fn commit_state_form(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let Some(form) = &self.facts.form else {
            return;
        };
        let arguments: Vec<String> = form
            .inputs
            .iter()
            .map(|(_, input)| input.read(cx).value().to_string())
            .collect();
        let (k, function) = (form.key, form.function.clone());
        match self.new_state(k, &function, &arguments) {
            Ok(()) => {
                self.facts.form = None;
                let id = self.layout.focused();
                self.focus_pane(id, window, cx);
            }
            Err(error) => {
                if let Some(form) = &mut self.facts.form {
                    form.error = Some(error);
                }
            }
        }
        cx.notify();
    }

    /// The compact form, as a card under the toolbar.
    pub fn render_state_form(&self, cx: &mut Context<Self>) -> Option<AnyElement> {
        let theme = self.theme;
        let form = self.facts.form.as_ref()?;
        let (id, _) = self.facts_target()?;
        let bounds = self.panes.get(&id)?.bounds.get();
        let rows: Vec<AnyElement> = form
            .inputs
            .iter()
            .map(|(name, input)| {
                div()
                    .flex()
                    .items_center()
                    .gap(self.z(8.0))
                    .h(self.z(26.0))
                    .child(
                        div()
                            .w(self.z(90.0))
                            .flex_none()
                            .overflow_hidden()
                            .text_ellipsis()
                            .font_family(self.settings.code_font.clone())
                            .text_color(hsla(theme.text_muted))
                            .child(name.clone()),
                    )
                    .child(
                        div()
                            .flex_1()
                            .h(self.z(22.0))
                            .px(self.z(4.0))
                            .bg(hsla(solid(theme.editor)))
                            .border_1()
                            .rounded(self.z(3.0))
                            .border_color(hsla(theme.border_variant))
                            .font_family(self.settings.code_font.clone())
                            .child(FieldInput::new(input)),
                    )
                    .into_any_element()
            })
            .collect();
        let width = self.z(380.0);
        let x = bounds.origin.x + bounds.size.width - width - self.z(8.0);
        Some(
            div()
                .id("state-form")
                .absolute()
                .left(x)
                .top(bounds.origin.y + self.z(2.0))
                .w(width)
                .p(self.z(8.0))
                .bg(hsla(solid(theme.panel)))
                .border_1()
                .border_color(hsla(theme.border_variant))
                .rounded(self.z(6.0))
                .shadow_lg()
                .occlude()
                .on_mouse_down_out(cx.listener(|this, _, _, cx| {
                    this.facts.form = None;
                    cx.notify();
                }))
                .children(rows)
                .when_some(form.error.clone(), |d, e| {
                    d.child(div().pt(self.z(4.0)).text_color(hsla(theme.error)).child(e))
                })
                .into_any_element(),
        )
    }

    /// The ▶ of the call needing a stub, on its line: opens the stub
    /// picker.
    pub fn stub_button(
        &self,
        document: &CDocument,
        callee: String,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        let theme = self.theme;
        let k = key(document.function, document.view);
        div()
            .id("stub-button")
            .flex()
            .items_center()
            .justify_center()
            .size(self.z(16.0))
            .rounded(self.z(3.0))
            .hover(|s| s.bg(hsla(theme.element_hover)))
            .on_mouse_down(MouseButton::Left, |_, _, cx| cx.stop_propagation())
            .on_click(cx.listener(move |this, _, _, cx| {
                this.facts.stub = Some((k, callee.clone()));
                cx.notify();
            }))
            .child(icon(
                IconName::Play,
                self.z(ICON - 3.0),
                hsla(theme.text_muted),
            ))
            .into_any_element()
    }

    /// The stub picker: what the call returns (a value, an argument,
    /// unknown); saved in the state, run again.
    pub fn render_stub_menu(&self, cx: &mut Context<Self>) -> Option<AnyElement> {
        let theme = self.theme;
        let (k, callee) = self.facts.stub.clone()?;
        let (id, _) = self.facts_target()?;
        let bounds = self.panes.get(&id)?.bounds.get();
        let choices: Vec<(String, String)> = ["0", "1", "arg0", "arg1", "unknown"]
            .iter()
            .map(|r| {
                let text = match *r {
                    "unknown" => "Returns unknown".to_owned(),
                    a if a.starts_with("arg") => format!("Returns argument {}", &a[3..]),
                    v => format!("Returns {v}"),
                };
                ((*r).to_owned(), text)
            })
            .collect();
        let entries: Vec<AnyElement> = choices
            .into_iter()
            .enumerate()
            .map(|(n, (returns, text))| {
                let callee = callee.clone();
                div()
                    .id(("stub", n))
                    .flex()
                    .items_center()
                    .px(self.z(10.0))
                    .h(self.z(24.0))
                    .rounded(self.z(4.0))
                    .hover(|s| s.bg(hsla(theme.element_hover)))
                    .on_click(cx.listener(move |this, _, _, cx| {
                        this.facts.stub = None;
                        this.add_stub(k, &callee, &returns);
                        cx.notify();
                    }))
                    .child(text)
                    .into_any_element()
            })
            .collect();
        let width = self.z(220.0);
        Some(
            div()
                .id("stub-menu")
                .absolute()
                .left(bounds.origin.x + bounds.size.width - width - self.z(8.0))
                .top(bounds.origin.y + self.z(2.0))
                .w(width)
                .p(self.z(4.0))
                .bg(hsla(solid(theme.panel)))
                .border_1()
                .border_color(hsla(theme.border_variant))
                .rounded(self.z(6.0))
                .shadow_lg()
                .occlude()
                .on_mouse_down_out(cx.listener(|this, _, _, cx| {
                    this.facts.stub = None;
                    cx.notify();
                }))
                .child(
                    div()
                        .px(self.z(10.0))
                        .h(self.z(24.0))
                        .flex()
                        .items_center()
                        .font_family(self.settings.code_font.clone())
                        .text_color(hsla(theme.text_muted))
                        .child(callee),
                )
                .children(entries)
                .into_any_element(),
        )
    }

    /// Adds a stub of `callee` returning `returns` to function `k`'s state,
    /// saves it and runs again.
    fn add_stub(&mut self, k: Key, callee: &str, returns: &str) {
        let Some(shown) = self.facts.runs.get(&k) else {
            return;
        };
        let mut state = (*shown.state).clone();
        state.stubs.retain(|s| s.target != callee);
        state.stubs.push(Stub {
            target: callee.to_owned(),
            returns: Some(returns.to_owned()),
            copy: None,
        });
        self.keep_state(k.0, &state);
        self.choose_state(k, Some(Arc::new(state)));
    }
}
