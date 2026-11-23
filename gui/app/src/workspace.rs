//! The window's state and its commands: the session, the panes and their
//! tabs, the shared cursor of the sync group, the one history, the
//! settings (watched), and the overlays. Rendering lives beside it
//! (`panes`, `listing_view`, `c_view`, `overlays`, `titlebar`, `sidebar`,
//! `settings_pane`); what is shown comes from the view models.

use std::cell::Cell;
use std::collections::{HashMap, HashSet};
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::Arc;
use std::time::{Duration, Instant};

use binbun_gui_view::calls::CallsPane;
use binbun_gui_view::cdoc::{Anchor, CDocument, Field};
use binbun_gui_view::commands::{self, Binding, Command, Facts, Processor};
use binbun_gui_view::context::Target;
use binbun_gui_view::graph::{GraphPane, Graphs};
use binbun_gui_view::hex::HexPane;
use binbun_gui_view::history::{Location, Trails};
use binbun_gui_view::ir::IrPane;
use binbun_gui_view::layout::{Axis, Direction, Layout, PaneId, TabId};
use binbun_gui_view::listing::{Listing, Numbers as ListingNumbers, Options as ListingOptions};
use binbun_gui_view::map::{Map, Row as MapRow, TypeNames};
use binbun_gui_view::number::{Radix, Written};
use binbun_gui_view::peek::Peek;
use binbun_gui_view::projects::{self, ProjectRow, may_have_several, project_title};
use binbun_gui_view::recent::Recent;
use binbun_gui_view::scroll::{ScrollAnchor, Scroller, Sideways};
use binbun_gui_view::selection::{Lines, Text, TextPos};
use binbun_gui_view::session::project::{self, Project};
use binbun_gui_view::session::{Event, Session, StringItem};
use binbun_gui_view::settings::{
    self, CView, FeatureMap, File, ListingView, Numbers, Setting, Settings, Theme as ThemeSetting,
    Watch,
};
use binbun_gui_view::slices::{self, Chosen, Slice};
use binbun_gui_view::structedit::StructTarget;
use binbun_gui_view::symbols::Bar;
use binbun_gui_view::tabs::{Opening, Places, retarget};
use binbun_gui_view::{Answer, FunctionId, Node, NumberForm, Stage, View};
use binbun_session::journal::Origin;
use gpui_kit::base::TextSelection;
use gpui_kit::component::input::InputState;
use gpui_kit::{
    Bounds, ClipboardItem, Context, Entity, FocusHandle, Font, FontFeatures, PathPromptOptions,
    Pixels, Point, ScrollHandle, Subscription, Task, Window, WindowAppearance,
    WindowBackgroundAppearance, font, px,
};

use crate::actions;
use crate::arrows::Hit as ArrowHit;
use crate::banners::BannerUi;
use crate::calls_view::CallsUi;
use crate::collab::CollabUi;
use crate::comment_field::CommentEdit;
use crate::console_view::ConsoleUi;
use crate::context_menu::ContextMenu;
use crate::facts_view::FactsUi;
use crate::feature_map_view::FeatureMapUi;
use crate::files_and_folders::FilesAndFoldersUi;
use crate::folder_view::FolderUi;
use crate::hex_view::HexUi;
use crate::ir_view::IrUi;
use crate::project_files::ProjectsUi;
use crate::scrolling::{Area, AreaScroll};
use crate::search_view::SearchUi;
use crate::selection::{BOTTOM, TOP, indentation};
use crate::serving::{self, Told, WindowUi};
use crate::sidebar::WIDTH as SIDEBAR_WIDTH;
use crate::start_page::StartFacts;
use crate::struct_editor::{InlineStruct, StructEditor};
use crate::symbol_cache::SymbolCacheUi;
use crate::theme::{self, Theme, Themes};
use crate::threads_view::{Dock, ThreadsUi};
use crate::type_field::CTypeField;
use crate::window_tabs::WindowTabs;

/// What a tab shows.
#[derive(Clone, Debug, PartialEq)]
pub enum TabKind {
    /// The continuous listing.
    Listing,
    /// A function's C (following the cursor while its pane is synced).
    C {
        /// The function, once the cursor is in one.
        function: Option<FunctionId>,
        /// The view.
        view: View,
    },
    /// The settings.
    Settings,
    /// The strings found in the binary (Shift+F12).
    Strings,
    /// The cross-references to bytes from an address (X: the
    /// address itself; a hex view field's: its bytes).
    Xrefs {
        /// The first address referred to.
        of: u64,
        /// How many bytes from it.
        len: u64,
    },
    /// A struct or union as C (the struct editor).
    Struct(StructTarget),
    /// A search's results, or the bookmarks (`search_view`'s tab of this
    /// number).
    Found(u32),
    /// A folder of the map as a list (Open as Tab): its key.
    Folder(String),
}

/// What the C view highlights: a node's occurrences (a variable), or
/// equal text (a function name, a constant).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CHighlight {
    /// Every token standing for this node.
    Node(Node),
    /// Every token with this text.
    Text(String),
}

/// A listing viewport's state.
#[derive(Debug, Default)]
pub struct ListingState {
    /// The viewport's scrolling.
    pub scroll: Scroller,
    /// The viewport's sideways scrolling.
    pub side: Sideways,
    /// The cursor's line.
    pub cursor: u64,
    /// The lines selected, from their anchor to the cursor.
    pub selection: Lines,
    /// The token under the cursor.
    pub token: Option<usize>,
    /// The text whose occurrences are highlighted.
    pub highlight: Option<String>,
    /// The lit function: its entry and lines.
    pub lit: Option<(u64, Range<u64>)>,
    /// The branch arrow under the pointer: its lines (from, to).
    pub arrow: Option<(u64, u64)>,
    /// Where the gutter's arrows were last drawn, for the pointer.
    pub arrow_hits: Vec<ArrowHit>,
}

/// A C viewport's state.
#[derive(Debug, Default)]
pub struct CState {
    /// The viewport's scrolling.
    pub scroll: Scroller,
    /// The viewport's sideways scrolling.
    pub side: Sideways,
    /// The cursor's line.
    pub line: usize,
    /// The cursor's column on its line, in characters: where a selection's
    /// moving end is.
    pub column: usize,
    /// The characters selected, from their anchor to the cursor.
    pub selection: Text,
    /// The token under the cursor.
    pub span: Option<usize>,
    /// What is highlighted.
    pub highlight: Option<CHighlight>,
    /// Where the cursor goes when the document arrives: a node, a member
    /// or a struct's definition, its occurrence.
    pub restore: Option<(Anchor, usize)>,
    /// The address the cursor goes to when the document arrives.
    pub target: Option<u64>,
    /// The reading view's line whose reveal mark the pointer is on (its
    /// card shows the exact C there).
    pub reveal: Option<usize>,
}

/// A list tab's state (strings, cross-references): typing filters it.
#[derive(Debug, Default)]
pub struct ListState {
    /// The filter.
    pub query: String,
    /// The rows shown (indices into the list, matched positions).
    pub rows: Vec<(usize, Vec<usize>)>,
    /// What the rows were made for: the tab and the list's length (a
    /// folder's: the map's build).
    pub made_for: Option<(TabKind, usize)>,
    /// The selected row.
    pub selected: usize,
    /// The rows' scrolling.
    pub scroll: Scroller,
}

/// A pane's state beside its tabs.
pub struct PaneState {
    /// Its focus.
    pub focus: FocusHandle,
    /// Its content's bounds, as last drawn.
    pub bounds: Rc<Cell<Bounds<Pixels>>>,
    /// Its listing viewport.
    pub listing: ListingState,
    /// Its C viewport.
    pub c: CState,
    /// Its list tab.
    pub list: ListState,
    /// Its listing shown as a graph.
    pub graph: GraphPane,
    /// Its listing shown as the hex view.
    pub hex: HexPane,
    /// Its C pane shown as the IR viewer.
    pub ir: IrPane,
    /// Its listing shown as the call graph.
    pub calls: CallsPane,
    /// Its tab bar's sideways scroll (the wheel and a touchpad
    /// move it, no scrollbar).
    pub tab_scroll: ScrollHandle,
    /// The active tab (its identity and index) the tab bar last scrolled
    /// into view.
    pub tab_revealed: Cell<Option<(TabId, usize)>>,
}

/// The rename field open in a C pane.
pub struct FieldEdit {
    /// The pane.
    pub pane: PaneId,
    /// The field.
    pub field: Field,
    /// The input.
    pub input: Entity<InputState>,
    /// The text was refused.
    pub error: bool,
    pub(crate) _changes: Subscription,
}

/// A rename committed while the C it changes prints again (a member's
/// users are decompiled again): its name stays on the document it was
/// typed over until the pane shows another.
pub struct Renamed {
    /// The pane.
    pub pane: PaneId,
    /// The document the name was typed over.
    pub document: Arc<CDocument>,
    /// The field as committed.
    pub field: Field,
}

/// What a prompt edits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PromptKind {
    /// The name of the function or global at the address.
    Rename(u64),
    /// The name of a frame slot: its function's entry, its offset from
    /// the stack pointer on entry.
    Slot(u64, i64),
    /// The name of a bookmark at the address.
    Bookmark(u64),
    /// The count of an array made at the address (`*`).
    Array(u64),
    /// The end of the function holding the address (Edit Function).
    FunctionEnd(u64),
}

/// A one-line prompt (a function's, a global's or a frame slot's name).
pub struct Prompt {
    /// What it edits.
    pub kind: PromptKind,
    /// The input.
    pub input: Entity<InputState>,
    /// The text was refused.
    pub error: bool,
    pub(crate) _sub: Subscription,
}

/// A go-anywhere candidate.
#[derive(Clone, Debug)]
pub struct Candidate {
    /// The name.
    pub name: String,
    /// The address.
    pub address: u64,
    /// Its kind's badge.
    pub badge: &'static str,
}

/// An open picker: go anywhere, or the command palette.
pub struct Picker {
    /// Which.
    pub kind: PickerKind,
    /// The query.
    pub input: Entity<InputState>,
    /// The rows matching it (indices of the candidates).
    pub rows: Vec<(usize, Vec<usize>)>,
    /// The address the query spells, if it is one in the image.
    pub address: Option<u64>,
    /// The selected row.
    pub selected: usize,
    pub(crate) _sub: Subscription,
}

/// What a picker picks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PickerKind {
    /// A name or an address.
    GoTo,
    /// A command or a setting.
    Palette,
    /// A binary opened before.
    Recent,
    /// A theme, previewed as it is selected.
    Theme,
    /// The slice of a universal Mach-O file to open ([`Slicing`]).
    Slice,
    /// The project of a binary that has several to open it in
    /// ([`Choosing`]).
    Project,
    /// The enumeration to show the number under the cursor by (`M`).
    Enum,
    /// The enumeration to edit.
    EditEnum,
}

impl PickerKind {
    /// Whether its rows are narrowed by what is typed above them: all but
    /// the project picker's, a binary's few projects, shown without a
    /// field (its rows chosen by the arrows and Enter, or a click).
    pub fn typed(self) -> bool {
        self != Self::Project
    }
}

/// A universal Mach-O file whose slice the slice picker asks for.
#[derive(Clone, Debug)]
pub struct Slicing {
    /// The file.
    pub path: PathBuf,
    /// Its slices, in the file's order.
    pub slices: Vec<Slice>,
}

/// A binary with several projects, which the project picker asks for.
#[derive(Clone, Debug)]
pub struct Choosing {
    /// The file.
    pub path: PathBuf,
    /// Its slice, of a universal file.
    pub arch: Option<String>,
    /// Its projects, used last first.
    pub rows: Vec<ProjectRow>,
}

/// A palette row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PaletteItem {
    /// A command.
    Command(Command),
    /// A setting (its key).
    Setting(&'static str),
}

/// The peek card.
pub struct PeekCard {
    /// What it shows.
    pub peek: Peek,
    /// Where it is (the window's coordinates of the token it is for).
    pub position: Point<Pixels>,
    /// Whether the pointer is on it.
    pub hovered: bool,
}

/// A hover that links C and listing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Link {
    /// Instructions hovered in the listing.
    Listing(u64),
    /// A C token hovered: its function, view and instructions.
    C {
        /// The function.
        function: FunctionId,
        /// The view.
        view: View,
        /// The token.
        span: usize,
        /// Its instructions.
        addresses: Vec<u64>,
    },
}

/// The left sidebar: the binary's map.
pub struct Sidebar {
    /// Its focus.
    pub focus: FocusHandle,
    /// The tree.
    pub map: Map,
    /// The keys of the open folders.
    pub open: HashSet<String>,
    /// The filter typed while it has the focus.
    pub query: String,
    /// The rows shown.
    pub rows: Vec<MapRow>,
    /// The selected row.
    pub selected: usize,
    /// The rows' scrolling.
    pub scroll: Scroller,
    /// The list's bounds.
    pub bounds: Rc<Cell<Bounds<Pixels>>>,
    /// How many times the tree was built (a folder tab's rows are made
    /// again after).
    pub built: u64,
}

/// The open menu of the menu bar.
pub struct OpenMenu {
    /// Which.
    pub menu: commands::Menu,
    /// Its popup.
    pub popup: Entity<gpui_kit::component::menu::PopupMenu>,
    pub(crate) _sub: Subscription,
}

/// Latencies measured, for the trace.
#[derive(Debug, Default)]
pub struct Clocks {
    /// When the window opened.
    pub opened: Option<Instant>,
    /// C requests sent, by function and view.
    pub requests: HashMap<(FunctionId, bool), Instant>,
    /// When the last rename was committed.
    pub rename: Option<Instant>,
    /// When the last correction of recovery was made.
    pub corrected: Option<Instant>,
}

/// An edge or divider the pointer drags.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EdgeDrag {
    /// The map's right edge.
    Map,
    /// The right dock's left edge.
    Dock,
    /// The divider before child `index` of the split at `path` (child
    /// indices from the root).
    Split {
        /// The split.
        path: Vec<usize>,
        /// The child after the divider.
        index: usize,
    },
    /// The divider between a hex pane's bytes and its side area under
    /// them.
    HexSide(PaneId),
    /// The console's top edge.
    Console,
}

/// The layout's sizes beside the split tree's, what the pointer drags, and
/// the layout as last saved.
#[derive(Debug, Default)]
pub struct LayoutUi {
    /// The right dock's width (logical) once its edge was dragged; else
    /// its content's own.
    pub dock_width: Option<f32>,
    /// The edge or divider being dragged.
    pub drag: Option<EdgeDrag>,
    /// Each split's bounds as last drawn, by its path.
    pub split_bounds: HashMap<Vec<usize>, Rc<Cell<Bounds<Pixels>>>>,
    /// The layout as last saved or restored (`None` until the binary's
    /// saved layout was restored: nothing is saved before).
    pub saved: Option<String>,
    /// Saving the layout failed (said once per binary).
    pub save_failed: bool,
    /// A restored layout's focused pane takes the focus when next drawn.
    pub refocus: bool,
    /// A tab dragged over a pane's body: the pane, and the side a new pane
    /// would take (none: into the pane).
    pub tab_drop: Option<(PaneId, Option<Direction>)>,
}

/// The window.
#[expect(
    clippy::struct_excessive_bools,
    reason = "independent window toggles, not a state machine"
)]
pub struct Workspace {
    pub settings: Settings,
    pub settings_file: File,
    pub settings_path: Option<PathBuf>,
    pub settings_watch: Option<Watch>,
    pub settings_error: Option<String>,
    pub theme: &'static Theme,
    /// The bundled themes and the user's (watched).
    pub themes: Themes,
    /// The theme the Select Theme picker shows while it is open.
    pub theme_preview: Option<String>,
    /// The theme's problems as shown in `settings_error`, so a reload can
    /// replace them.
    pub theme_error: Option<String>,
    pub keymap: Vec<Binding>,
    pub session: Option<Session>,
    pub listing: Option<Arc<Listing>>,
    pub strings: Arc<Vec<StringItem>>,
    /// Every function's entry, sorted, and its id.
    pub functions: Vec<(u64, FunctionId)>,
    pub stage: Stage,
    pub error: Option<String>,
    pub layout: Layout<TabKind>,
    pub panes: HashMap<PaneId, PaneState>,
    /// Each tab's place and view.
    pub places: Places,
    /// The back/forward trails: the linked panes', each pane on its own's.
    pub trails: Trails,
    /// The linked panes' place.
    pub shared: Option<u64>,
    /// The window's tabs not shown (the shown one's state is the fields
    /// above: its layout, panes, places, trails and place).
    pub window_tabs: WindowTabs,
    pub left_sidebar: bool,
    pub right_sidebar: bool,
    pub sidebar: Option<Sidebar>,
    /// The map's width (logical; dragged by its edge).
    pub sidebar_width: f32,
    /// The dock's width, dragging, the layout as saved.
    pub layout_ui: LayoutUi,
    /// The map's types (the C++ classes read once per binary, the
    /// synthesised structs as last taken).
    pub map_types: TypeNames,
    /// Every mangling's C++ text, once read.
    pub demangled: HashMap<String, Option<String>>,
    /// The pane shown alone over the others.
    pub maximized: Option<PaneId>,
    pub picker: Option<Picker>,
    /// The file the slice picker opens, while it is open.
    pub slicing: Option<Slicing>,
    /// The binary whose project the project picker asks for.
    pub choosing: Option<Choosing>,
    /// Go anywhere's candidates (built when it opens).
    pub candidates: Vec<Candidate>,
    /// Go anywhere's last query (preselected when it opens again).
    pub last_goto: String,
    /// The enumeration pickers' rows (built when one opens): each name,
    /// with how the number reads by it (Show as Enum) or nothing (Edit
    /// Enum).
    pub enum_choices: Vec<(String, String)>,
    /// The number Show as Enum shows: its instruction, as written.
    pub enum_number: Option<(u64, Written)>,
    pub prompt: Option<Prompt>,
    pub field: Option<FieldEdit>,
    /// The comment field open in place.
    pub comment: Option<CommentEdit>,
    /// The rename committed, shown until its C is printed again.
    pub renamed: Option<Renamed>,
    /// The open Set type field.
    pub c_type: Option<CTypeField>,
    /// The open struct editors (one per struct tab).
    pub struct_editors: Vec<StructEditor>,
    /// The struct definition open for editing in place in a C pane.
    pub inline_struct: Option<InlineStruct>,
    pub peek: Option<PeekCard>,
    pub peek_task: Option<Task<()>>,
    pub link: Option<Link>,
    /// The landing pulse: the pane, the line, when it started.
    pub pulse: Option<(PaneId, u64, Instant)>,
    pub menu: Option<OpenMenu>,
    /// The open context menu.
    pub context_menu: Option<ContextMenu>,
    /// The address a context menu opened on a row (the map's, a list's) is
    /// about: the commands act on it, not on the cursor's.
    pub menu_subject: Option<u64>,
    /// The map's folder a context menu opened on (its key): Open as Tab
    /// opens it.
    pub menu_folder: Option<String>,
    pub settings_search: Option<Entity<InputState>>,
    pub font_menu: Option<(
        &'static str,
        Entity<gpui_kit::component::menu::PopupMenu>,
        Subscription,
    )>,
    /// The pane whose scrollbar's thumb is dragged, and where along the
    /// thumb it was taken (pixels from its top).
    pub scrollbar_drag: Option<(PaneId, f32)>,
    /// The pane whose horizontal scrollbar's thumb is dragged, and where
    /// along the thumb it was taken (pixels from its left edge).
    pub sideways_drag: Option<(PaneId, f32)>,
    pub smooth_at: Option<Instant>,
    /// The pixel surfaces' scrolling ([`Workspace::scroll_area`]).
    pub areas: HashMap<Area, AreaScroll>,
    /// The settings pane's fields (its number boxes, a program's and a
    /// relay's URL), by key, each with the setting it last showed.
    pub setting_inputs: HashMap<&'static str, (Entity<InputState>, Subscription, String)>,
    /// Custom is chosen for the relay in the settings pane, its URL not
    /// yet set.
    pub relay_custom: bool,
    /// The error a URL typed in the relay's field was refused with: it
    /// goes once a valid URL is entered there, the one set too.
    pub relay_refused: Option<String>,
    pub char_width: Option<f32>,
    pub dark_system: bool,
    /// The installed monospace families (found when a font picker first
    /// opens).
    pub mono_fonts: Option<Vec<String>>,
    /// Alt is down alone (released alone, it opens the menu bar).
    pub alt_tap: bool,
    /// The binaries opened before, newest first.
    pub recent: Vec<Recent>,
    /// The start page's focus (its recent files).
    pub start_focus: FocusHandle,
    /// The start page's selected recent file.
    pub start_selected: usize,
    /// Each recent file's format, whether it exists and has edits, read
    /// once.
    pub start_facts: HashMap<(PathBuf, Option<String>), StartFacts>,
    /// The About card is open.
    pub about: bool,
    /// What an overlay opened by a key or a menu takes the focus with (the
    /// About card, a peek card opened by its key).
    pub overlay_focus: FocusHandle,
    pub clocks: Clocks,
    /// The questions beside the C: verification, why, origin, run.
    pub facts: FactsUi,
    /// The IR viewer's stages, by function and view.
    pub ir: IrUi,
    /// Every function's graph laid out so far.
    pub graphs: Graphs,
    /// Graphs show their overview.
    pub overview: bool,
    /// The view last chosen for a listing pane: the graph.
    pub last_graph: bool,
    /// The hex view's byte space, overlays and inspector.
    pub hex: HexUi,
    /// The feature map: its bands, marks and hover.
    pub feature_map: FeatureMapUi,
    /// The map's folders opened as tabs: their rows, each tab's sort.
    pub folders: FolderUi,
    /// The call graph, the Pathfinder and the callers tables.
    pub calls: CallsUi,
    /// binbun's symbol cache: its size, Clear's question.
    pub symbol_cache: SymbolCacheUi,
    /// Files and Folders' overlay.
    pub files_and_folders: FilesAndFoldersUi,
    /// The binary's project: what is said of it, Import's question.
    pub projects: ProjectsUi,
    /// The find bars and the results tabs.
    pub search: SearchUi,
    /// The banner stack: what was put away, the overflow expanded.
    pub banners: BannerUi,
    /// The shared session: its dialogs, panel, people, follow mode.
    pub collab: CollabUi,
    /// Conversation: the threads and history panels, mentions unread.
    pub threads: ThreadsUi,
    /// The console in the bottom dock.
    pub console: ConsoleUi,
    /// Polls the session whenever it signals new results.
    pub(crate) wake: Option<Task<()>>,
    /// The binary served to scripts: its number on the server, the
    /// window's side, what the server tells it (jumps, agents).
    pub(crate) served: Option<(u64, Arc<WindowUi>, Task<()>)>,
    pub(crate) _watch: Task<()>,
    pub(crate) _appearance: Subscription,
    /// Tells the server this window is the one focused last.
    pub(crate) _activation: Subscription,
    /// Records the window's focus once it is still active
    /// [`FOCUS_SETTLE`] after an activation.
    pub(crate) focus_check: Option<Task<()>>,
    /// Esc (and Enter on the About card) for the open overlays, before
    /// any element sees the key: it works wherever the focus is.
    pub(crate) _overlay_keys: Subscription,
}

/// How long the landing pulse lasts.
pub const PULSE: Duration = Duration::from_millis(250);

// The chrome's bars are a line of the interface font plus padding,
// nothing more (`ui_line`: 17 px at the default 13 px).

/// The title bar's padding: 32 px at 13 px text.
pub const TITLE_PAD: f32 = 15.0;
/// The tab bar's padding: 28 px.
pub const TAB_PAD: f32 = 11.0;
/// The breadcrumb toolbar's padding: 30 px.
pub const TOOLBAR_PAD: f32 = 13.0;
/// The status bar's padding: 26 px.
pub const STATUS_PAD: f32 = 9.0;
/// A tree or list row's padding: 22 px.
pub const ROW_PAD: f32 = 5.0;
/// The chrome's icons.
pub const ICON: f32 = 14.0;
/// An icon button's square.
pub const ICON_BUTTON: f32 = 22.0;

/// How long a window stays active before it counts as the one the user
/// focused (`binbun mcp` and `binbun.connect()` attach to it).
const FOCUS_SETTLE: Duration = Duration::from_millis(300);

impl Workspace {
    /// The window, opening `path` if given.
    #[expect(clippy::too_many_lines, reason = "one line per field")]
    pub fn new(path: Option<PathBuf>, window: &mut Window, cx: &mut Context<Self>) -> Self {
        let settings_path = settings::path();
        let (settings_file, settings, settings_error) = match &settings_path {
            Some(path) => match settings::load(path) {
                Ok((file, settings, problems)) => (file, settings, problems_text(&problems)),
                Err(error) => (File::default(), Settings::default(), Some(error)),
            },
            None => (File::default(), Settings::default(), None),
        };
        let (keymap, unknown) = actions::bind(&[], &settings.keys, cx);
        let watch = cx.spawn_in(window, async move |this, cx| {
            loop {
                cx.background_executor()
                    .timer(Duration::from_millis(500))
                    .await;
                if this.update_in(cx, Workspace::watch).is_err() {
                    break;
                }
            }
        });
        let appearance = cx.observe_window_appearance(window, |this, window, cx| {
            this.dark_system = is_dark(window.appearance());
            this.apply_theme(window, cx);
        });
        // The window has the user's focus once it is still active a moment
        // after an activation: a window manager (XWayland) can hand a
        // window a passing focus-in while another is being focused, which
        // must not count as the user's choice of window.
        let activation = cx.observe_window_activation(window, |this, window, cx| {
            if !window.is_window_active() || this.served.is_none() {
                return;
            }
            this.focus_check = Some(cx.spawn_in(window, async move |this, cx| {
                cx.background_executor().timer(FOCUS_SETTLE).await;
                let _ = this.update_in(cx, |this, window, _| {
                    if window.is_window_active()
                        && let Some((id, _, _)) = &this.served
                    {
                        serving::focus(*id);
                    }
                });
            }));
        });
        let overlay_keys = Self::intercept_overlay_keys(window, cx);
        let first = PaneId(0);
        let themes = Themes::new(binbun_paths::Place::Themes.path());
        let mut this = Self {
            settings_file,
            settings_watch: settings_path.clone().map(Watch::new),
            settings_path,
            settings_error: settings_error.or_else(|| unknown_keys(&unknown)),
            theme: theme::default_theme(true),
            themes,
            theme_preview: None,
            theme_error: None,
            keymap,
            session: None,
            listing: None,
            strings: Arc::default(),
            functions: Vec::new(),
            stage: Stage::Opening,
            error: None,
            layout: Layout::new(TabKind::Listing),
            panes: HashMap::new(),
            places: Places::default(),
            window_tabs: WindowTabs::default(),
            trails: Trails::default(),
            shared: None,
            left_sidebar: true,
            right_sidebar: false,
            sidebar: None,
            sidebar_width: SIDEBAR_WIDTH,
            layout_ui: LayoutUi::default(),
            map_types: TypeNames::default(),
            demangled: HashMap::new(),
            maximized: None,
            picker: None,
            slicing: None,
            choosing: None,
            candidates: Vec::new(),
            last_goto: String::new(),
            enum_choices: Vec::new(),
            enum_number: None,
            prompt: None,
            field: None,
            comment: None,
            renamed: None,
            c_type: None,
            struct_editors: Vec::new(),
            inline_struct: None,
            peek: None,
            peek_task: None,
            link: None,
            pulse: None,
            menu: None,
            context_menu: None,
            menu_subject: None,
            menu_folder: None,
            settings_search: None,
            font_menu: None,
            scrollbar_drag: None,
            sideways_drag: None,
            smooth_at: None,
            areas: HashMap::new(),
            setting_inputs: HashMap::new(),
            relay_custom: false,
            relay_refused: None,
            char_width: None,
            dark_system: is_dark(window.appearance()),
            mono_fonts: None,
            alt_tap: false,
            recent: binbun_gui_view::recent::path()
                .map(|p| binbun_gui_view::recent::load(&p))
                .unwrap_or_default(),
            start_focus: cx.focus_handle(),
            start_selected: 0,
            start_facts: HashMap::new(),
            about: false,
            overlay_focus: cx.focus_handle(),
            clocks: Clocks::default(),
            facts: FactsUi::default(),
            ir: IrUi::default(),
            graphs: Graphs::default(),
            overview: true,
            last_graph: false,
            hex: HexUi::default(),
            feature_map: FeatureMapUi::default(),
            folders: FolderUi::default(),
            calls: CallsUi::default(),
            symbol_cache: SymbolCacheUi::default(),
            files_and_folders: FilesAndFoldersUi::default(),
            projects: ProjectsUi::default(),
            search: SearchUi::default(),
            banners: BannerUi::default(),
            collab: CollabUi::default(),
            threads: ThreadsUi::default(),
            console: ConsoleUi::default(),
            settings,
            wake: None,
            served: None,
            _watch: watch,
            _appearance: appearance,
            _activation: activation,
            focus_check: None,
            _overlay_keys: overlay_keys,
        };
        this.first_layout(first, path, window, cx);
        this
    }

    /// The first panes (the listing, the C beside it), then `path` opened,
    /// else the start page with the focus.
    fn first_layout(
        &mut self,
        first: PaneId,
        path: Option<PathBuf>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.ensure_pane(first, cx);
        let view = self.default_view();
        if let Some(c) = self.layout.split(
            first,
            Axis::Row,
            TabKind::C {
                function: None,
                view,
            },
        ) {
            self.ensure_pane(c, cx);
            self.layout.focus(first);
        }
        self.apply_theme(window, cx);
        self.make_sidebar(cx);
        cx.on_app_quit(|this, _| {
            this.save_layout();
            // This peer's changes reach those linked first (5 s at most).
            this.collab.quit();
            serving::stop();
            async {}
        })
        .detach();
        if let Some(path) = path {
            self.open_focused(path, window, cx);
        } else {
            window.set_window_title("binbun");
            window.focus(&self.start_focus, cx);
        }
    }

    // ---- the session ----

    /// Opens the binary at `path`, closing the one open; an exported
    /// project (`.binbun`) is imported instead. Of a universal Mach-O
    /// file, the slice chosen for it before is opened, else the slice
    /// picker asks which ([`Self::ask_slice`]).
    pub fn open(&mut self, path: PathBuf, window: &mut Window, cx: &mut Context<Self>) {
        self.open_in(path, None, window, cx);
    }

    /// [`Self::open`] in the project directory `project` (`None`: the
    /// binary's one, or one of its several asked for).
    fn open_in(
        &mut self,
        path: PathBuf,
        project: Option<PathBuf>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if path.extension().is_some_and(|e| e == project::EXTENSION) {
            self.import_project(&path, window, cx);
            return;
        }
        let slices = slices::of_file(&path);
        if slices.is_empty() {
            self.open_as(path, None, project, window, cx);
            return;
        }
        let full = binbun_paths::canonical(&path).unwrap_or_else(|_| path.clone());
        let chosen = slices::path().map(|file| Chosen::load(&file));
        let known = chosen
            .as_ref()
            .and_then(|chosen| chosen.of(&full))
            .filter(|&arch| slices.iter().any(|slice| slice.arch == arch))
            .map(str::to_owned);
        match known {
            Some(arch) => self.open_as(path, Some(arch), project, window, cx),
            None => self.ask_slice(path, slices, window, cx),
        }
    }

    /// Opens the binary at `path` ([`Self::open`]) and gives the focused
    /// pane the keys, unless the slice picker asks which slice first: it
    /// keeps them while it is open.
    pub fn open_focused(&mut self, path: PathBuf, window: &mut Window, cx: &mut Context<Self>) {
        self.open_in_focused(path, None, window, cx);
    }

    /// [`Self::open_focused`] in the project directory `project` (`None`:
    /// the binary's one, or one of its several asked for).
    pub fn open_in_focused(
        &mut self,
        path: PathBuf,
        project: Option<PathBuf>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.open_in(path, project, window, cx);
        let asking = self
            .picker
            .as_ref()
            .is_some_and(|picker| matches!(picker.kind, PickerKind::Slice | PickerKind::Project));
        if !asking {
            let id = self.layout.focused();
            self.focus_pane(id, window, cx);
        }
    }

    /// The slice picker over the universal file at `path` (its `slices`):
    /// the slice open selected if it is this file's, else this machine's.
    pub fn ask_slice(
        &mut self,
        path: PathBuf,
        slices: Vec<Slice>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let open = self
            .session
            .as_ref()
            .filter(|session| same_file(session.path(), &path))
            .and_then(Session::slice)
            .and_then(|arch| slices.iter().position(|slice| slice.arch == arch));
        let selected = open.unwrap_or_else(|| slices::preferred(&slices));
        self.slicing = Some(Slicing { path, slices });
        self.open_picker(PickerKind::Slice, window, cx);
        if let Some(picker) = &mut self.picker
            && let Some(k) = picker.rows.iter().position(|(i, _)| *i == selected)
        {
            picker.selected = k;
        }
        cx.notify();
    }

    /// Opens the binary at `path` (of a universal Mach-O file, its slice
    /// `arch`) in the project directory `project`, closing the one open.
    /// With none given, its project is found by its bytes: if they have
    /// several (its own and shares' joined), the project picker offers
    /// them, used last first ([`PickerKind::Project`]); else the one there
    /// is (or a new one) opens with no question. Whether they may have
    /// several is seen from the projects directory's names first, so the
    /// bytes are read here only when some binary has several.
    pub fn open_as(
        &mut self,
        path: PathBuf,
        arch: Option<String>,
        project: Option<PathBuf>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let root = project::root().filter(|root| project.is_none() && may_have_several(root));
        let Some(root) = root else {
            self.open_project(path, arch, project, window, cx);
            return;
        };
        let (told, opening) = async_channel::bounded(1);
        let (file, slice) = (path.clone(), arch.clone());
        let _ = std::thread::Builder::new()
            .name("binbun-projects".to_owned())
            .spawn(move || {
                let key = project::Key::of_file_slice(&file, slice.as_deref())
                    .map_err(|error| format!("{}: {error}", file.display()));
                let _ = told.try_send(key.and_then(|key| projects::opening(&root, &key)));
            });
        cx.spawn_in(window, async move |this, cx| {
            let Ok(opening) = opening.recv().await else {
                return;
            };
            let _ = this.update_in(cx, |this, window, cx| match opening {
                Ok(projects::Opening::Choose(dirs)) => {
                    this.ask_project(path, arch, &dirs, window, cx);
                }
                // One project, or none, or the file unread: opened as
                // ever (the session finds its project, or says why not).
                Ok(projects::Opening::Direct(_)) | Err(_) => {
                    this.open_project(path, arch, None, window, cx);
                }
            });
        })
        .detach();
    }

    /// The project picker over the projects `dirs` (used last first) of
    /// the binary at `path` (its slice `arch`): the one used last
    /// selected.
    fn ask_project(
        &mut self,
        path: PathBuf,
        arch: Option<String>,
        dirs: &[PathBuf],
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let file = path.file_name().map_or_else(
            || path.display().to_string(),
            |name| name.to_string_lossy().into_owned(),
        );
        let file = match &arch {
            Some(arch) => format!("{file} ({arch})"),
            None => file,
        };
        self.choosing = Some(Choosing {
            path,
            arch,
            rows: projects::rows(&file, dirs),
        });
        self.open_picker(PickerKind::Project, window, cx);
        cx.notify();
    }

    /// Opens the binary at `path` (of a universal Mach-O file, its slice
    /// `arch`, remembered for opening it again) in the project directory
    /// `project` (`None`: its own, found by its bytes), closing the one
    /// open.
    pub fn open_project(
        &mut self,
        path: PathBuf,
        arch: Option<String>,
        project: Option<PathBuf>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if let (Some(arch), Some(file)) = (&arch, slices::path()) {
            let full = binbun_paths::canonical(&path).unwrap_or_else(|_| path.clone());
            let mut chosen = Chosen::load(&file);
            if chosen.of(&full) != Some(arch.as_str()) {
                chosen.choose(&full, arch);
                if let Err(why) = chosen.save(&file) {
                    self.error = Some(why);
                }
            }
        }
        let (tx, rx) = async_channel::unbounded::<()>();
        let wake = Arc::new(move || {
            let _ = tx.try_send(());
        });
        self.close_session();
        self.clocks.opened = Some(Instant::now());
        match Session::open(
            path.clone(),
            arch,
            project,
            self.listing_options(),
            self.settings.symbols,
            self.settings.signature_options(),
            wake,
        ) {
            Ok(session) => {
                session.set_style(self.settings.c_style(session.style()));
                window.set_window_title(&window_title(&session));
                self.serve(&session, window, cx);
                let full = binbun_paths::canonical(&path).unwrap_or(path);
                self.start_facts.retain(|(path, _), _| *path != full);
                self.session = Some(session);
                self.remember_agents();
                self.publish_people();
                self.wake = Some(cx.spawn_in(window, async move |this, cx| {
                    while rx.recv().await.is_ok() {
                        while rx.try_recv().is_ok() {}
                        // A join waiting for this binary (fetched from a
                        // share) starts once its project is read.
                        let polled = this.update_in(cx, |this, window, cx| {
                            this.poll(cx);
                            this.join_pending(window, cx);
                        });
                        if polled.is_err() {
                            break;
                        }
                    }
                }));
            }
            Err(error) => self.error = Some(error),
        }
        cx.notify();
    }

    /// Serves `session`'s binary to scripts (`binbun.connect()`): a
    /// script's move of the cursor is a jump here, an agent connected is
    /// among the participants. The window is the one focused last.
    fn serve(&mut self, session: &Session, window: &mut Window, cx: &mut Context<Self>) {
        let (told, hears) = async_channel::unbounded::<Told>();
        let ui = Arc::new(WindowUi::new(told));
        match serving::serve(session, Arc::clone(&ui)) {
            Ok(id) => {
                let hearing = cx.spawn_in(window, async move |this, cx| {
                    while let Ok(told) = hears.recv().await {
                        let taken = this.update(cx, |this, cx| match told {
                            Told::Goto(address) => this.jump(address, cx),
                            Told::Agents => this.agents_changed(cx),
                        });
                        if taken.is_err() {
                            break;
                        }
                    }
                });
                serving::focus(id);
                self.served = Some((id, ui, hearing));
            }
            Err(why) => self.error = Some(why),
        }
    }

    /// Tells scripts where the cursor is and what is selected (each
    /// frame: cheap).
    pub fn publish_cursor(&self) {
        if let Some((_, ui, _)) = &self.served {
            ui.show(self.current_address(), self.selected_bytes());
        }
    }

    /// Closes the binary open: its layout saved, what showed it dropped.
    pub fn close_session(&mut self) {
        if let Some((id, _, _)) = self.served.take() {
            serving::withdraw(id);
        }
        self.collab.forget_agents();
        // Its console was connected to the database closed.
        self.console.stop();
        self.save_layout();
        self.collab.close(None);
        self.threads = ThreadsUi::default();
        self.projects.closed();
        self.search = SearchUi::default();
        self.layout_ui.saved = None;
        self.session = None;
        self.wake = None;
        self.listing = None;
        self.strings = Arc::default();
        self.functions.clear();
        self.map_types = TypeNames::default();
        self.demangled.clear();
        self.maximized = None;
        self.stage = Stage::Opening;
        self.error = None;
        self.trails = Trails::default();
        self.shared = None;
        self.places.clear();
        self.forget_window_tabs();
        self.peek = None;
        self.link = None;
        self.facts = FactsUi::default();
        self.ir = IrUi::default();
        self.calls = CallsUi::default();
        for state in self.panes.values_mut() {
            state.listing = ListingState::default();
            state.c = CState::default();
            state.list = ListState::default();
            state.ir = IrPane {
                on: state.ir.on,
                ..IrPane::default()
            };
            state.calls = CallsPane::default();
        }
        let ids: Vec<PaneId> = self.layout.panes().map(|p| p.id).collect();
        for id in ids {
            if let Some(TabKind::C { function, .. }) = self.layout.active_mut(id) {
                *function = None;
            }
        }
    }

    /// The binary was opened again with fetched debug information: the
    /// questions asked of the session before are dropped (asked again as
    /// the views need them); panes, cursors and history stay, and the
    /// documents shown stay until their new ones come. Analysed again with
    /// corrections, each C tab shows its function by its id now (none, if
    /// it is gone).
    fn on_reopened(&mut self, functions: &HashMap<FunctionId, FunctionId>) {
        // The download went to the symbol cache.
        self.symbol_cache.size = None;
        self.facts = FactsUi::default();
        self.ir = IrUi::default();
        self.calls = CallsUi::default();
        self.peek = None;
        let ids: Vec<PaneId> = self.layout.panes().map(|p| p.id).collect();
        for id in ids {
            let Some(pane) = self.layout.pane_mut(id) else {
                continue;
            };
            for tab in &mut pane.tabs {
                if let TabKind::C { function, .. } = &mut tab.content
                    && let Some(old) = *function
                {
                    *function = functions.get(&old).copied();
                }
            }
        }
        for state in self.panes.values_mut() {
            state.ir = IrPane {
                on: state.ir.on,
                ..IrPane::default()
            };
            state.calls = CallsPane::default();
        }
    }

    /// Takes the session's events.
    pub fn poll(&mut self, cx: &mut Context<Self>) {
        let Some(session) = &mut self.session else {
            return;
        };
        let events = session.poll();
        for event in events {
            match event {
                Event::Stage(stage) => {
                    // Crossed once per session (the first stage told may be
                    // past both: the session was analysed already).
                    let before = std::mem::replace(&mut self.stage, stage);
                    trace!("[{:>8.1} ms] stage {stage:?}", crate::since_start());
                    // The hex view's byte space as soon as the image is
                    // parsed: its toggle is enabled by it, and a hex view
                    // is only drawn after the toggle.
                    if stage >= Stage::Image {
                        self.ensure_hex();
                        self.project_known();
                    }
                    if before < Stage::Image && stage >= Stage::Image {
                        self.check_processor();
                    }
                    // The references counted; the globals the whole
                    // program's pass found, in the data.
                    if (before < Stage::Referenced && stage >= Stage::Referenced)
                        || (before < Stage::Callers && stage >= Stage::Callers)
                    {
                        self.refresh_sidebar();
                    }
                    if before < Stage::Analysed && stage >= Stage::Analysed {
                        self.refresh_talk();
                    }
                }
                Event::Listing(listing) => self.set_listing(listing, cx),
                Event::Strings(strings) => {
                    self.strings = strings;
                    self.refresh_sidebar();
                }
                Event::Document {
                    function,
                    view,
                    result,
                } => self.on_document(function, view, result.as_ref().ok()),
                Event::Changed(change) => {
                    if let Some(at) = self.clocks.rename.take() {
                        trace!(
                            "rename → change event: {:.2} ms",
                            at.elapsed().as_secs_f64() * 1e3
                        );
                        self.clocks.rename = Some(at);
                    }
                    self.refresh_sidebar();
                    let _ = change;
                    self.hex_renamed();
                    self.lay_comments();
                }
                Event::Failed(message) => self.error = Some(message),
                // The bar reads the session's state as it draws, and the
                // session panel its conflicts.
                Event::Symbols(_) | Event::Conflicts(_) => {}
                Event::Reopened(functions) => {
                    // The new session's stages come next.
                    self.stage = Stage::Opening;
                    self.on_reopened(&functions);
                    self.collab_reopened();
                    self.refresh_talk();
                }
                Event::History(entries) => {
                    self.collab_history(&entries);
                    self.talk_history();
                }
                Event::Talked(talked) => self.on_talked(&talked),
                Event::Mentioned(mentioned) => self.on_mentioned(&mentioned),
                // The map's folders, the gutters and the feature map read
                // them as they draw.
                Event::Bookmarks => self.refresh_sidebar(),
                Event::Rechecked { suggestion, items } => {
                    self.threads.rechecked.insert(suggestion, items);
                }
                Event::Answer {
                    request,
                    answer: Answer::Staged(result),
                    ..
                } => self.on_stages(request, result),
                Event::Answer {
                    request, answer, ..
                } => {
                    if !self.calls_answer(request, &answer) {
                        self.on_answer(request, answer);
                    }
                }
            }
        }
        self.take_synthesised();
        self.poll_searches();
        self.ensure_documents();
        cx.notify();
    }

    fn set_listing(&mut self, mut listing: Arc<Listing>, cx: &mut Context<Self>) {
        if *listing.options() != self.listing_options() {
            return;
        }
        if let Some(session) = &self.session {
            Arc::make_mut(&mut listing).set_comments(&session.overlay().comments);
        }
        let listing = &listing;
        if let Some(opened) = self.clocks.opened.take() {
            trace!(
                "open → listing: {:.1} ms ({} lines)",
                opened.elapsed().as_secs_f64() * 1e3,
                listing.len()
            );
        }
        if let Some(corrected) = self.clocks.corrected.take() {
            trace!(
                "correction → listing: {:.1} ms ({} lines)",
                corrected.elapsed().as_secs_f64() * 1e3,
                listing.len()
            );
        }
        let old = self.listing.replace(Arc::clone(listing));
        // Another analysis: what bytes are may differ (the overviews and
        // the feature map are made again).
        self.hex.forget_overview();
        if let Some(db) = self.session.as_ref().and_then(Session::database) {
            let mut functions: Vec<(u64, FunctionId)> =
                db.functions().map(|(id, f)| (f.entry, id)).collect();
            functions.sort_unstable_by_key(|&(entry, _)| entry);
            self.functions = functions;
        }
        let ids: Vec<PaneId> = self.panes.keys().copied().collect();
        match old {
            None => {
                // Into a tab of a place (the settings may be shown).
                self.leave_tool_tab();
                self.restore_layout(cx);
                self.settle_restored();
            }
            Some(old) => {
                for id in ids {
                    let Some(state) = self.panes.get_mut(&id) else {
                        continue;
                    };
                    let row = state
                        .listing
                        .cursor
                        .saturating_sub(state.listing.scroll.anchor.line);
                    if let Some(line) = old.line(state.listing.cursor) {
                        state.listing.cursor = listing.line_of(line.address);
                        state.listing.scroll.anchor.line = state.listing.cursor.saturating_sub(row);
                        state.listing.scroll.anchor.offset = 0.0;
                    }
                    // The selection's anchor stays on its item's line.
                    let anchor = state.listing.selection.anchor.and_then(|n| old.line(n));
                    state.listing.selection.anchor = anchor.map(|l| listing.line_of(l.address));
                    state.listing.lit = None;
                    state.listing.scroll.smooth.stop();
                    // A C tab whose function went away (deleted, the
                    // session's reopening said) shows one made again at
                    // its place.
                    let place = self.layout.active_tab(id).and_then(|t| self.places.at(t));
                    if let Some(TabKind::C {
                        function: function @ None,
                        ..
                    }) = self.layout.active_mut(id)
                        && let Some(made) = retarget(None, place, listing)
                    {
                        *function = Some(made);
                        if let Some(address) = place {
                            self.set_cursor(id, address, false);
                        }
                    }
                }
            }
        }
        self.refresh_sidebar();
    }

    /// Where the listing starts: `main` if there is one, else the entry
    /// point, else the first function.
    fn start_address(&self) -> Option<u64> {
        let listing = self.listing.as_ref()?;
        let session = self.session.as_ref()?;
        listing
            .find("main", session.overlay())
            .or_else(|| session.database()?.image().entry)
            .or_else(|| self.functions.first().map(|&(entry, _)| entry))
    }

    fn on_document(&mut self, function: FunctionId, view: View, document: Option<&Arc<CDocument>>) {
        let k = (function, view == View::Reading);
        if let Some(sent) = self.clocks.requests.remove(&k) {
            trace!(
                "C request → document: {:.1} ms ({} lines)",
                sent.elapsed().as_secs_f64() * 1e3,
                document.map_or(0, |d| d.lines.len())
            );
        }
        if let Some(at) = self.clocks.rename.take() {
            trace!(
                "rename → document printed: {:.2} ms",
                at.elapsed().as_secs_f64() * 1e3
            );
        }
        let Some(document) = document else {
            return;
        };
        self.find_reveals(function);
        let ids: Vec<PaneId> = self.layout.panes().map(|p| p.id).collect();
        for id in ids {
            let shows = matches!(
                self.layout.active(id),
                Some(TabKind::C { function: Some(f), view: v }) if *f == function && *v == view
            );
            if shows {
                self.land_c(id, document);
            }
        }
    }

    /// Puts pane `id`'s C cursor where it was asked to go once `document`
    /// came.
    fn land_c(&mut self, id: PaneId, document: &Arc<CDocument>) {
        let rows = self.rows(id, self.settings.c_line_height);
        let Some(state) = self.panes.get_mut(&id) else {
            return;
        };
        let total = document.lines.len() as u64;
        // Printed again: its characters are not those selected.
        state.c.selection = Text::default();
        if let Some((anchor, ordinal)) = state.c.restore.take() {
            state.c.span = document.nth_anchor(&anchor, ordinal);
            if let Some(line) = state.c.span.and_then(|s| document.line_of_span(s)) {
                state.c.line = line;
                state.c.column = indentation(document, line);
                state.c.scroll.anchor.reveal(line as u64, total, rows, 3);
            }
            state.c.target = None;
        } else if let Some(address) = state.c.target.take() {
            let line = document.line_for(address).unwrap_or(0);
            state.c.line = line;
            state.c.column = indentation(document, line);
            state.c.span = None;
            state
                .c
                .scroll
                .anchor
                .reveal(line as u64, total, rows, rows / 3);
        }
        state.c.line = state.c.line.min(document.lines.len().saturating_sub(1));
    }

    /// Asks for the C every visible C tab, the peek card and the shown
    /// cross-references show.
    pub fn ensure_documents(&mut self) {
        self.show_tabs();
        if self.session.as_ref().is_none_or(|s| s.database().is_none()) {
            return;
        }
        let mut wanted: Vec<(FunctionId, View)> = self
            .layout
            .panes()
            .filter_map(|p| match p.tabs.get(p.active).map(|t| &t.content) {
                Some(TabKind::C {
                    function: Some(f),
                    view,
                }) => Some((*f, *view)),
                Some(
                    TabKind::C { function: None, .. }
                    | TabKind::Listing
                    | TabKind::Settings
                    | TabKind::Strings
                    | TabKind::Xrefs { .. }
                    | TabKind::Struct(_)
                    | TabKind::Found(_)
                    | TabKind::Folder(_),
                )
                | None => None,
            })
            .collect();
        // A reading view's reveals show the exact C: it comes along.
        let exact: Vec<(FunctionId, View)> = wanted
            .iter()
            .filter(|&&(f, view)| {
                view == View::Reading
                    && self
                        .session
                        .as_ref()
                        .and_then(|s| s.document(f, view))
                        .is_some_and(|d| !d.assumed().is_empty())
            })
            .map(|&(f, _)| (f, View::Exact))
            .collect();
        wanted.extend(exact);
        let view = match self.settings.c_view {
            CView::Reading => View::Reading,
            CView::Exact => View::Exact,
        };
        if let Some(f) = self.peek.as_ref().and_then(|p| p.peek.function) {
            wanted.push((f, view));
        }
        wanted.extend(self.xref_functions().into_iter().map(|f| (f, view)));
        let Some(session) = &mut self.session else {
            return;
        };
        for (function, view) in wanted {
            if session.ensure(function, view) {
                self.clocks
                    .requests
                    .insert((function, view == View::Reading), Instant::now());
            }
        }
        self.ensure_stages();
    }

    /// The C document a tab shows, if it is here.
    pub fn document(&self, kind: &TabKind) -> Option<&Arc<CDocument>> {
        match kind {
            TabKind::C {
                function: Some(f),
                view,
            } => self.session.as_ref()?.document(*f, *view),
            TabKind::C { function: None, .. }
            | TabKind::Listing
            | TabKind::Settings
            | TabKind::Strings
            | TabKind::Xrefs { .. }
            | TabKind::Struct(_)
            | TabKind::Found(_)
            | TabKind::Folder(_) => None,
        }
    }

    // ---- panes and the cursor ----

    pub fn ensure_pane(&mut self, id: PaneId, cx: &mut Context<Self>) {
        let graph = self.new_listing_graph();
        self.panes.entry(id).or_insert_with(|| PaneState {
            focus: cx.focus_handle(),
            bounds: Rc::new(Cell::new(Bounds::default())),
            listing: ListingState::default(),
            c: CState::default(),
            list: ListState::default(),
            graph: GraphPane {
                on: graph,
                landing: true,
                ..GraphPane::default()
            },
            hex: HexPane::default(),
            ir: IrPane::default(),
            calls: CallsPane::default(),
            tab_scroll: ScrollHandle::new(),
            tab_revealed: Cell::new(None),
        });
    }

    /// Whether a listing pane, or a tab of the listing opened from none,
    /// starts as the graph (the setting).
    pub fn new_listing_graph(&self) -> bool {
        match self.settings.listing_view {
            ListingView::Last => self.last_graph,
            ListingView::Text => false,
            ListingView::Graph => true,
        }
    }

    /// Focuses pane `id`.
    pub fn focus_pane(&mut self, id: PaneId, window: &mut Window, cx: &mut Context<Self>) {
        self.layout.focus(id);
        if self.shows_start() {
            window.focus(&self.start_focus, cx);
        } else if let Some(state) = self.panes.get(&id) {
            window.focus(&state.focus, cx);
        }
        cx.notify();
    }

    /// Whether the editor area is the start page: no binary is open and
    /// the focused pane does not show the settings.
    pub fn shows_start(&self) -> bool {
        self.session.is_none()
            && self.layout.active(self.layout.focused()) != Some(&TabKind::Settings)
    }

    /// The cursor's address in pane `id`.
    pub fn cursor_address(&self, id: PaneId) -> Option<u64> {
        let state = self.panes.get(&id)?;
        match self.layout.active(id)? {
            TabKind::Listing if state.hex.on => self.hex_address(id),
            TabKind::Listing if state.calls.on => self.calls_address(id),
            TabKind::Listing => self
                .listing
                .as_ref()?
                .line(state.listing.cursor)
                .map(|l| l.address),
            TabKind::C { .. } if state.ir.on => self.ir_address(id),
            kind @ TabKind::C { .. } => {
                // Its document not here yet (or no function there): where
                // it is going, else its place.
                let Some(document) = self.document(kind) else {
                    return state
                        .c
                        .target
                        .or_else(|| self.places.at(self.layout.active_tab(id)?));
                };
                // A further line of a comment: its statement's line's.
                document
                    .lines
                    .get(document.comment_owner(state.c.line))
                    .and_then(|l| l.addresses.first().copied())
                    .or(Some(document.entry))
            }
            TabKind::Settings
            | TabKind::Strings
            | TabKind::Xrefs { .. }
            | TabKind::Struct(_)
            | TabKind::Found(_)
            | TabKind::Folder(_) => None,
        }
    }

    /// The cursor's address: the row a context menu is about, else the
    /// focused pane's, else the sync group's.
    pub fn current_address(&self) -> Option<u64> {
        self.menu_subject
            .or_else(|| self.cursor_address(self.layout.focused()))
            .or(self.shared)
    }

    /// Moves pane `id`'s cursor to `address`; `focus`: as a jump (the
    /// target on the third row), else revealed with a third of the rows
    /// around it.
    pub fn set_cursor(&mut self, id: PaneId, address: u64, focus: bool) {
        let Some(kind) = self.layout.active(id).cloned() else {
            return;
        };
        let rows_l = self.rows(id, self.settings.listing_line_height);
        let rows_c = self.rows(id, self.settings.c_line_height);
        match kind {
            TabKind::Listing => {
                let Some(listing) = self.listing.clone() else {
                    return;
                };
                let Some(state) = self.panes.get_mut(&id) else {
                    return;
                };
                state.listing.scroll.smooth.stop();
                state.listing.cursor = listing.line_of(address);
                state.listing.selection.clear();
                state.listing.token = None;
                state.graph.landing = focus;
                state.hex.target = Some((address, focus));
                state.calls.target = Some(address);
                if focus {
                    state
                        .listing
                        .scroll
                        .anchor
                        .focus(state.listing.cursor, listing.len(), rows_l);
                } else {
                    state.listing.scroll.anchor.reveal(
                        state.listing.cursor,
                        listing.len(),
                        rows_l,
                        rows_l / 3,
                    );
                }
            }
            TabKind::C { function, view } => {
                let target = self
                    .listing
                    .as_ref()
                    .and_then(|l| l.function_of(address))
                    .map(|(f, _)| f);
                if target.is_none() {
                    // A tab showing no function (its own deleted) is at
                    // the address, which it says is in none; one showing a
                    // function keeps it.
                    if function.is_none() {
                        self.placed(id, address);
                    }
                    return;
                }
                if target != function
                    && let Some(TabKind::C { function, .. }) = self.layout.active_mut(id)
                {
                    *function = target;
                }
                let document =
                    target.and_then(|f| self.session.as_ref()?.document(f, view).cloned());
                let Some(state) = self.panes.get_mut(&id) else {
                    return;
                };
                state.c.scroll.smooth.stop();
                state.c.restore = None;
                state.c.selection = Text::default();
                if let Some(document) = document {
                    let line = document.line_for(address).unwrap_or(0);
                    state.c.line = line;
                    state.c.column = indentation(&document, line);
                    state.c.span = None;
                    state.c.target = None;
                    if target != function {
                        state.c.scroll.anchor = ScrollAnchor::default();
                    }
                    state.c.scroll.anchor.reveal(
                        line as u64,
                        document.lines.len() as u64,
                        rows_c,
                        rows_c / 3,
                    );
                } else {
                    state.c.target = Some(address);
                    state.c.scroll.anchor = ScrollAnchor::default();
                }
            }
            TabKind::Settings
            | TabKind::Strings
            | TabKind::Xrefs { .. }
            | TabKind::Struct(_)
            | TabKind::Found(_)
            | TabKind::Folder(_) => {}
        }
        if self.shows_ir(id) {
            self.ir_land(id, address, focus);
        }
        if matches!(kind, TabKind::Listing | TabKind::C { .. }) {
            self.placed(id, address);
        }
    }

    /// The shown window tab, as restored, at one place: the linked panes'
    /// is the first linked pane of code's as restored, else the start; a
    /// pane on its own at its own, else the start.
    pub(crate) fn settle_restored(&mut self) {
        let start = self.start_address();
        let linked: Vec<PaneId> = self
            .layout
            .panes()
            .filter(|p| p.synced)
            .map(|p| p.id)
            .collect();
        self.shared = linked
            .iter()
            .filter(|&&id| crate::tabs::is_code(self.layout.active(id)))
            .find_map(|&id| self.restored_place(id))
            .or(start);
        let ids: Vec<PaneId> = self.panes.keys().copied().collect();
        for id in ids {
            let at = if linked.contains(&id) {
                self.shared
            } else {
                self.restored_place(id).or(start)
            };
            if let Some(address) = at {
                self.set_cursor(id, address, true);
            }
        }
    }

    /// Where pane `id`'s shown tab was left, as restored: its saved place,
    /// else the entry of its C's function.
    fn restored_place(&self, id: PaneId) -> Option<u64> {
        let place = self.layout.active_tab(id).and_then(|t| self.places.at(t));
        let entry = || {
            let Some(TabKind::C {
                function: Some(f), ..
            }) = self.layout.active(id)
            else {
                return None;
            };
            self.functions
                .iter()
                .find(|(_, function)| function == f)
                .map(|&(entry, _)| entry)
        };
        place.or_else(entry)
    }

    /// Pane `id`'s cursor moved: its tab's place with it (and the tabs
    /// following it); the sync group follows (but a tab following
    /// another's cursor, which follows only that).
    pub fn moved(&mut self, id: PaneId) {
        let address = self.cursor_address(id);
        if let Some(address) = address
            && matches!(
                self.layout.active(id),
                Some(TabKind::Listing | TabKind::C { .. })
            )
        {
            self.placed(id, address);
        }
        let synced = self.layout.pane(id).is_some_and(|p| p.synced);
        if synced && let Some(address) = address {
            self.shared = Some(address);
            let others: Vec<PaneId> = self
                .layout
                .panes()
                .filter(|p| p.synced && p.id != id)
                .map(|p| p.id)
                .collect();
            for other in others {
                self.set_cursor(other, address, false);
            }
            self.share_selection(id);
        }
        self.ensure_documents();
        self.collab_moved(id);
    }

    /// Where the user is, for the history.
    pub fn location(&self) -> Location {
        let id = self.layout.focused();
        let node = self.layout.active(id).and_then(|kind| {
            let document = self.document(kind)?;
            let span = self.panes.get(&id)?.c.span?;
            document.spans.get(span)?.node
        });
        Location {
            address: self.current_address().unwrap_or(0),
            node,
        }
    }

    /// Jumps to `address` in the focused pane, remembering where it was on
    /// its trail (the linked panes', or its own).
    pub fn jump(&mut self, address: u64, cx: &mut Context<Self>) {
        self.leave_tool_tab();
        let from = self.location();
        self.focused_trail().push(from);
        self.go(address, None);
        cx.notify();
    }

    /// The focused pane's back/forward trail: the linked panes' if it is
    /// linked, else its own.
    pub fn focused_trail(&mut self) -> &mut binbun_gui_view::history::History {
        let id = self.layout.focused();
        let linked = self.layout.pane(id).is_some_and(|p| p.synced);
        self.trails.of(id, linked)
    }

    /// The focused pane's trail, to read (`None` for a pane on its own
    /// with none yet).
    pub fn focused_trail_ref(&self) -> Option<&binbun_gui_view::history::History> {
        let id = self.layout.focused();
        let linked = self.layout.pane(id).is_some_and(|p| p.synced);
        self.trails.get(id, linked)
    }

    /// Goes to `address` in the focused pane (and its sync group), with
    /// the landing pulse; in a C pane, to `node` if given.
    pub fn go(&mut self, address: u64, node: Option<Node>) {
        let id = self.layout.focused();
        self.set_cursor(id, address, true);
        if let Some(node) = node
            && let Some(state) = self.panes.get_mut(&id)
        {
            state.c.restore = Some((Anchor::Node(node), 0));
            state.c.target = None;
        }
        if let Some(kind) = self.layout.active(id).cloned()
            && let Some(document) = self.document(&kind).cloned()
            && node.is_some()
        {
            self.land_c(id, &document);
        }
        if let Some(listing) = &self.listing {
            self.pulse = Some((id, listing.line_of(address), Instant::now()));
        }
        self.moved(id);
    }

    /// Back on the focused pane's trail.
    pub fn back(&mut self, cx: &mut Context<Self>) {
        let here = self.location();
        if let Some(to) = self.focused_trail().back(here) {
            self.go(to.address, to.node);
        }
        cx.notify();
    }

    /// Forward on the focused pane's trail.
    pub fn forward(&mut self, cx: &mut Context<Self>) {
        let here = self.location();
        if let Some(to) = self.focused_trail().forward(here) {
            self.go(to.address, to.node);
        }
        cx.notify();
    }

    // ---- geometry ----

    /// The window's zoom applied to `v` logical pixels.
    pub fn z(&self, v: f32) -> Pixels {
        px(v * self.settings.ui_scale)
    }

    /// A line of the interface font (logical): its size × 1.3, rounded.
    pub fn ui_line(&self) -> f32 {
        (self.settings.ui_font_size * 1.3).round()
    }

    /// A bar `pad` logical pixels taller than a line of the interface
    /// font, zoomed.
    pub fn bar(&self, pad: f32) -> Pixels {
        self.z(self.ui_line() + pad)
    }

    /// The code font's size, zoomed.
    pub fn code_size(&self) -> f32 {
        self.settings.code_font_size * self.settings.ui_scale
    }

    /// A row of `height` logical pixels, zoomed.
    pub fn row(&self, height: f32) -> f32 {
        height * self.settings.ui_scale
    }

    /// How many rows of `height` (logical) pane `id` shows.
    pub fn rows(&self, id: PaneId, height: f32) -> u64 {
        let h = self
            .panes
            .get(&id)
            .map_or(0.0, |s| f32::from(s.bounds.get().size.height));
        let h = if h > 0.0 { h } else { 900.0 };
        rows_in(h, self.row(height))
    }

    /// The code font's advance.
    pub fn char_width(&mut self, window: &Window) -> f32 {
        if let Some(w) = self.char_width {
            return w;
        }
        let size = self.code_size();
        let ts = window.text_system();
        let id = ts.resolve_font(&self.code_font());
        let w = ts
            .advance(id, px(size), 'm')
            .map_or(size * 0.5, |s| f32::from(s.width));
        self.char_width = Some(w);
        w
    }

    /// The code font, its ligatures as set.
    pub fn code_font(&self) -> Font {
        let mut f = font(self.settings.code_font.clone());
        f.features = self.font_features();
        f
    }

    /// Ligatures off unless set: contextual alternates and ligatures.
    pub fn font_features(&self) -> FontFeatures {
        if self.settings.ligatures {
            FontFeatures::default()
        } else {
            FontFeatures(Arc::new(vec![
                ("calt".to_owned(), 0),
                ("liga".to_owned(), 0),
            ]))
        }
    }

    // ---- settings ----

    /// The listing's options from the settings.
    pub fn listing_options(&self) -> ListingOptions {
        ListingOptions {
            opcode_bytes: usize::try_from(self.settings.opcode_bytes).unwrap_or(0),
            numbers: match self.settings.numbers {
                Numbers::Masm => ListingNumbers::Masm,
                Numbers::C => ListingNumbers::C,
            },
            symbolic: self.settings.symbolic,
            xrefs: usize::try_from(self.settings.xrefs).unwrap_or(0),
        }
    }

    /// The view new C tabs open in.
    pub fn default_view(&self) -> View {
        match self.settings.c_view {
            CView::Reading => View::Reading,
            CView::Exact => View::Exact,
        }
    }

    /// Whether the theme is dark now.
    pub fn is_dark(&self) -> bool {
        match self.settings.theme {
            ThemeSetting::Dark => true,
            ThemeSetting::Light => false,
            ThemeSetting::System => self.dark_system,
        }
    }

    pub fn apply_theme(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let background = self.resolve_theme(cx);
        window.set_background_appearance(background);
        trace!(
            "window background {background:?}, editor {:08x}, panel {:08x}",
            self.theme.editor, self.theme.panel
        );
        let rem = self.settings.ui_font_size / 0.875 * self.settings.ui_scale;
        window.set_rem_size(px(rem));
        self.char_width = None;
        cx.notify();
    }

    /// Makes the window's theme the one the settings choose (or the
    /// picker previews), with the window's background applied, and gives
    /// the GPUI background it needs. Its problems show as a settings
    /// error.
    pub fn resolve_theme(&mut self, cx: &mut Context<Self>) -> WindowBackgroundAppearance {
        let dark = self.is_dark();
        let name = self.theme_preview.clone().unwrap_or_else(|| {
            if dark {
                self.settings.dark_theme.clone()
            } else {
                self.settings.light_theme.clone()
            }
        });
        let loaded = self.themes.load(&name, dark);
        let (window_theme, background) = loaded
            .theme
            .for_window(self.settings.backdrop, self.settings.opacity);
        self.theme = theme::intern(window_theme);
        let error = loaded
            .problems
            .first()
            .map(|first| match loaded.problems.len() {
                1 => format!("theme {name}: {first}"),
                n => format!("theme {name}: {first} (and {} more)", n - 1),
            });
        let shown = std::mem::replace(&mut self.theme_error, error);
        if self.settings_error.is_none() || self.settings_error == shown {
            self.settings_error.clone_from(&self.theme_error);
        }
        // GPUI Kit's components write their text at 0.875 rem and its root
        // makes the rem its theme's font size: that size is set so their
        // text is the interface font's size.
        let rem = self.settings.ui_font_size / 0.875 * self.settings.ui_scale;
        self.theme.apply(&self.settings.ui_font, rem, cx);
        cx.notify();
        background
    }

    /// Sets setting `key` to `value`: applied at once and saved to the
    /// settings file.
    pub fn set_setting(
        &mut self,
        key: &str,
        value: &Setting,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let mut next = self.settings.clone();
        if let Err(error) = next.set(key, value) {
            self.settings_error = Some(error);
            cx.notify();
            return;
        }
        if let Err(error) = self.settings_file.set(key, value) {
            self.settings_error = Some(error);
        } else if let Some(path) = &self.settings_path {
            match settings::save(path, &self.settings_file) {
                Ok(()) => {
                    self.settings_error = None;
                    if let Some(watch) = &mut self.settings_watch {
                        watch.mark();
                    }
                }
                Err(error) => self.settings_error = Some(error),
            }
        }
        self.apply_settings(next, window, cx);
    }

    /// Makes `next` the settings, applying what changed.
    pub fn apply_settings(&mut self, next: Settings, window: &mut Window, cx: &mut Context<Self>) {
        let before = std::mem::replace(&mut self.settings, next);
        if before.keys != self.settings.keys {
            let (keymap, unknown) = actions::bind(&self.keymap, &self.settings.keys, cx);
            self.keymap = keymap;
            if let Some(message) = unknown_keys(&unknown) {
                self.settings_error = Some(message);
            }
        }
        let options = self.listing_options();
        if self
            .listing
            .as_ref()
            .is_some_and(|l| *l.options() != options)
            && let Some(session) = &self.session
        {
            session.relist(options);
        }
        // The C options (`c.types`, `c.declarations`, `c.names`): the C
        // panes print again at once.
        if let Some(session) = &self.session {
            session.set_style(self.settings.c_style(session.style()));
        }
        self.apply_theme(window, cx);
        cx.notify();
    }

    /// Every half second: the settings file reloaded if it changed, the
    /// layout saved if it changed, the update check due started.
    fn watch(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.check_settings(window, cx);
        if self.themes.changed() {
            self.apply_theme(window, cx);
        }
        self.save_layout();
        self.check_updates(cx);
    }

    /// Reloads the settings file if it changed on disk.
    fn check_settings(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let (Some(watch), Some(path)) = (&mut self.settings_watch, &self.settings_path) else {
            return;
        };
        if !watch.changed() {
            return;
        }
        match settings::load(path) {
            Ok((file, settings, problems)) => {
                self.settings_file = file;
                self.settings_error = problems_text(&problems);
                self.apply_settings(settings, window, cx);
            }
            Err(error) => {
                self.settings_error = Some(error);
                cx.notify();
            }
        }
    }

    /// Opens the settings file in the system's editor, writing the
    /// commented defaults first if it does not exist.
    fn open_settings_file(&mut self, cx: &mut Context<Self>) {
        let Some(path) = self.settings_path.clone() else {
            return;
        };
        if !path.exists() {
            let written = path
                .parent()
                .map_or(Ok(()), std::fs::create_dir_all)
                .and_then(|()| std::fs::write(&path, File::defaults_text()));
            if let Err(error) = written {
                self.settings_error = Some(format!("{}: {error}", path.display()));
                return;
            }
            if let Some(watch) = &mut self.settings_watch {
                watch.mark();
            }
        }
        cx.open_with_system(&path);
    }

    /// Flips a toggle setting.
    fn toggle_setting(&mut self, key: &'static str, window: &mut Window, cx: &mut Context<Self>) {
        if let Some(Setting::Bool(on)) = self.settings.get(key) {
            self.set_setting(key, &Setting::Bool(!on), window, cx);
        }
    }

    /// Moves a choice setting to its next value.
    pub fn cycle_setting(
        &mut self,
        key: &'static str,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let (Some(info), Some(Setting::Text(now))) = (settings::info(key), self.settings.get(key))
        else {
            return;
        };
        if let settings::Kind::Choice(names) = info.kind {
            let i = names
                .iter()
                .position(|n| *n == now)
                .map_or(0, |i| (i + 1) % names.len());
            if let Some(next) = names.get(i) {
                self.set_setting(key, &Setting::Text((*next).to_owned()), window, cx);
            }
        }
    }

    /// Zooms the whole window by `step` (0: back to 100%).
    fn zoom(&mut self, step: f32, window: &mut Window, cx: &mut Context<Self>) {
        let scale = if step == 0.0 {
            1.0
        } else {
            ((self.settings.ui_scale + step) * 10.0).round() / 10.0
        };
        self.set_setting(
            "window.scale",
            &Setting::Number(f64::from(scale.clamp(0.5, 3.0))),
            window,
            cx,
        );
    }

    // ---- commands ----

    /// What decides the commands' states.
    pub fn facts(&self) -> Facts {
        let id = self.layout.focused();
        let kind = self.layout.active(id);
        let target = self.cursor_target();
        let named = matches!(target, Target::Function | Target::Name);
        let number = self.number_under_cursor();
        let symbols = self.session.as_ref().and_then(Session::symbols_bar);
        Facts {
            open: self.session.is_some(),
            processor: Processor::of(self.processor_setting().as_deref()),
            fitting: self.processor_fitting(),
            stage: match self.stage {
                Stage::Opening => 0,
                Stage::Image => 1,
                Stage::Analysed => 2,
                Stage::Referenced => 3,
                Stage::Signatures => 4,
                Stage::Callers => 5,
                Stage::Warmed => 6,
            },
            renamable: self.listing.is_some()
                && (self.menu_subject.is_some()
                    || matches!(kind, Some(TabKind::Listing | TabKind::C { .. }))),
            subject: self.menu_subject.is_some(),
            structure: self.struct_key_at_cursor().is_some(),
            typed: self.struct_tab_key(id).is_some(),
            explained: self.why_item_at_cursor().is_some()
                || self.why_function_at_cursor().is_some(),
            signature: self.signature_at_cursor().is_some(),
            number: number.is_some(),
            printable: number
                .is_some_and(|(_, written)| NumberForm::Char.spell(written, Radix::Masm).is_some()),
            named,
            address: self.current_address().is_some(),
            selection: self.selects(),
            selectable: self.selects_all(),
            undo: self.session.as_ref().is_some_and(Session::can_undo),
            redo: self.session.as_ref().is_some_and(Session::can_redo),
            back: self
                .focused_trail_ref()
                .is_some_and(binbun_gui_view::history::History::can_back),
            forward: self
                .focused_trail_ref()
                .is_some_and(binbun_gui_view::history::History::can_forward),
            reading: matches!(
                kind,
                Some(TabKind::C {
                    view: View::Reading,
                    ..
                })
            ),
            settings: kind == Some(&TabKind::Settings),
            ir: self.shows_ir(id),
            ir_diff: self.shows_ir(id) && self.panes.get(&id).is_some_and(|s| s.ir.diff),
            synced: self.layout.pane(id).is_some_and(|p| p.synced),
            panes: self.layout.len() > 1,
            maximized: self.maximized.is_some(),
            left_sidebar: self.left_sidebar,
            right_sidebar: self.right_sidebar,
            console: self.console.open,
            feature_map: self.settings.feature_map != FeatureMap::Off,
            feature_map_top: self.settings.feature_map == FeatureMap::Top,
            folder: self.folder_key().is_some(),
            dark: self.is_dark(),
            opcode_bytes: self.settings.opcode_bytes > 0,
            c_numbers: self.settings.numbers == Numbers::C,
            symbolic: self.settings.symbolic,
            ligatures: self.settings.ligatures,
            islands: self.settings.islands,
            graph: self.shows_graph(id),
            function: self
                .current_address()
                .zip(self.listing.as_ref())
                .is_some_and(|(a, l)| l.function_of(a).is_some()),
            overview: self.overview,
            symbols_offer: matches!(symbols, Some(Bar::Offer { .. })),
            downloading: matches!(symbols, Some(Bar::Downloading { .. })),
            listing: self.shows_listing(),
            refusals: self.refusals(),
            live: self.collab.live(),
            session_panel: self.collab.panel.is_some(),
            threads_panel: self.talk_shown(Dock::Threads),
            history_panel: self.talk_shown(Dock::History),
            threadable: self.threadable(),
            view_only: self.edits_off().is_some(),
            share: self.share_open(),
            universal: self.session.as_ref().and_then(Session::slice).is_some(),
            ..self.search_facts(self.calls_facts(self.hex_facts()))
        }
    }

    /// Runs `command`.
    pub fn run(&mut self, command: Command, window: &mut Window, cx: &mut Context<Self>) {
        // A disabled command does nothing, whichever way it came (its
        // keys, the palette, a menu).
        if !commands::state(command, &self.facts()).enabled {
            // An edit while joining or in a view-only session: said why,
            // as the CLI does.
            if (commands::edits(command) || command == Command::BringValues)
                && let Some(off) = self.edits_off()
            {
                self.error = Some(off.text());
                cx.notify();
            }
            self.menu_subject = None;
            self.menu_folder = None;
            return;
        }
        self.run_enabled(command, window, cx);
        // A row's context menu is about its row for one command.
        self.menu_subject = None;
        self.menu_folder = None;
        cx.notify();
    }

    #[expect(clippy::too_many_lines, reason = "one arm per command")]
    fn run_enabled(&mut self, command: Command, window: &mut Window, cx: &mut Context<Self>) {
        let id = self.layout.focused();
        // A key binding with Alt (`Alt+Q`) is no lone Alt tap: its release
        // must not open the menu bar (a bound keystroke never reaches
        // `menu_keys`).
        self.alt_tap = false;
        if self.correction_command(command, window, cx)
            || self.hex_command(command, window, cx)
            || self.calls_command(command, window, cx)
            || self.struct_command(command, window, cx)
            || self.symbols_command(command, window, cx)
            || self.symbol_cache_command(command, window, cx)
            || self.folders_command(command, window, cx)
            || self.project_command(command, window, cx)
            || self.search_command(command, window, cx)
            || self.collab_command(command, window, cx)
            || self.talk_command(command, window, cx)
        {
            cx.notify();
            return;
        }
        match command {
            Command::Open => Self::prompt_open(window, cx),
            Command::OpenRecent if self.session.is_none() => {
                window.focus(&self.start_focus, cx);
            }
            Command::OpenRecent => self.open_picker(PickerKind::Recent, window, cx),
            Command::ReopenSlice => {
                if let Some(path) = self.session.as_ref().map(|s| s.path().to_path_buf()) {
                    let slices = slices::of_file(&path);
                    if !slices.is_empty() {
                        self.ask_slice(path, slices, window, cx);
                    }
                }
            }
            Command::About => self.open_about(window, cx),
            Command::StageImage
            | Command::StageFunctions
            | Command::StageReferences
            | Command::StageCallers
            | Command::StageWarmed
            // Taken by `hex_command` where they apply.
            | Command::ToggleHex
            | Command::ShowInHex
            | Command::HexFileOffsets
            | Command::HexEntropy
            | Command::HexSide
            | Command::ApplyType
            | Command::RemoveType
            | Command::CopyHex
            | Command::CopyEscaped
            | Command::CopyCArray
            // Taken by `calls_command`.
            | Command::ToggleCalls
            | Command::MoreCallers
            | Command::FewerCallers
            | Command::MoreCallees
            | Command::FewerCallees
            | Command::Pathfinder
            | Command::PathFrom
            | Command::PathTo
            | Command::WholeSubgraph
            | Command::CallerArguments
            | Command::KeepTab
            // Taken by `struct_command`.
            | Command::EditStruct
            | Command::NewStruct
            | Command::NewEnum
            | Command::EditEnum
            | Command::Data
            // Taken by `correction_command`.
            | Command::MakeCode
            | Command::Undefine
            | Command::MakeString
            | Command::MakeArray
            | Command::MakeFunction
            | Command::EditFunction
            | Command::DeleteFunction
            // Taken by `symbols_command`, `symbol_cache_command` and
            // `folders_command`.
            | Command::DownloadSymbols
            | Command::SymbolsNotNow
            | Command::AlwaysDownloadSymbols
            | Command::RevealSymbolCache
            | Command::ClearSymbolCache
            | Command::FilesAndFolders
            | Command::RevealProjects
            // Taken by `project_command`.
            | Command::ExportProject
            | Command::ImportProject
            // Taken by `collab_command`.
            | Command::ShareProject
            | Command::JoinSession
            | Command::CopyIdentityCard
            | Command::ConnectAgent
            | Command::LeaveSession
            | Command::SessionPanel
            | Command::InsertLocation
            | Command::Conflicts
            | Command::BringValues
            // Taken by `talk_command`.
            | Command::Threads
            | Command::StartThread
            | Command::History
            // Taken by `search_command`.
            | Command::Find
            | Command::FindNext
            | Command::FindPrevious
            | Command::SearchEverywhere
            | Command::SearchBytes
            | Command::SearchImmediate
            | Command::StopSearch
            | Command::Bookmark
            | Command::Bookmarks => {}
            Command::SaveProject => {
                self.apply_struct_tab(id, window, cx);
                if let Some(Err(error)) = self.session.as_ref().map(Session::save) {
                    self.error = Some(error);
                }
            }
            Command::Close => {
                self.close_session();
                window.set_window_title("binbun");
                self.start_selected = 0;
                window.focus(&self.start_focus, cx);
            }
            Command::Quit => cx.quit(),
            Command::Undo | Command::Redo => {
                if let Some(session) = &mut self.session {
                    // An agent's change undone is said in the status bar.
                    let agents = (command == Command::Undo)
                        .then(|| session.next_undo())
                        .flatten()
                        .filter(|entry| entry.origin == Origin::Agent);
                    let done = if command == Command::Undo {
                        session.undo()
                    } else {
                        session.redo()
                    };
                    match done {
                        Err(error) => self.error = Some(error),
                        Ok(()) => {
                            if let Some(entry) = agents {
                                self.collab.notice =
                                    Some((format!("Undid {}", entry.label), Instant::now()));
                                self.drop_notice_later(cx);
                            }
                        }
                    }
                }
                self.ensure_documents();
            }
            Command::Rename => self.rename(window, cx),
            Command::SetType => {
                self.open_c_type(window, cx);
            }
            Command::Comment => self.open_comment(window, cx),
            Command::CopyAddress => {
                if let Some(address) = self.current_address() {
                    cx.write_to_clipboard(ClipboardItem::new_string(format!("{address:X}")));
                }
            }
            Command::CopyName => {
                // Text selected with the mouse (the chat's), else the
                // listing's or the C's selection as shown, else the name
                // under the cursor.
                let selected = TextSelection::selected_text(window, cx);
                if !selected.is_empty() {
                    cx.write_to_clipboard(ClipboardItem::new_string(selected));
                } else if !self.copy_selection(cx)
                    && let Some(name) = self.name_under_cursor()
                {
                    cx.write_to_clipboard(ClipboardItem::new_string(name));
                }
            }
            Command::SelectAll => self.select_all(),
            Command::NumberHex => self.convert_number(NumberForm::Hex),
            Command::NumberDecimal => self.convert_number(NumberForm::Decimal),
            Command::NumberChar => self.convert_number(NumberForm::Char),
            Command::NumberEnum => self.open_enum_picker(window, cx),
            Command::OpenInNewPane => self.open_in_new_pane(window, cx),
            Command::Why => self.open_why_at_cursor(),
            Command::RejectSignature => self.reject_signature_at_cursor(),
            Command::RunFromHere => self.run_from_here(window, cx),
            Command::CompareProcessors => self.compare_now(),
            Command::ProcessorArchitecture
            | Command::ProcessorRaptorCove
            | Command::ProcessorGracemont => {
                let name = Processor::chosen_by(command).and_then(Processor::name);
                self.set_processor(name);
            }
            Command::ProcessorFile => Self::prompt_processor_file(window, cx),
            Command::OpenListing => {
                self.set_code_view(id, &TabKind::Listing);
                self.focus_pane(id, window, cx);
            }
            Command::OpenC => {
                let view = self.default_view();
                self.set_code_view(
                    id,
                    &TabKind::C {
                        function: None,
                        view,
                    },
                );
                self.focus_pane(id, window, cx);
            }
            Command::SplitRight | Command::SplitDown => {
                let axis = if command == Command::SplitRight {
                    Axis::Row
                } else {
                    Axis::Column
                };
                let content = self.layout.active(id).cloned().unwrap_or(TabKind::Listing);
                // Read before the split: the new pane takes the focus.
                let address = self.current_address();
                if let Some(new) = self.layout.split(id, axis, content) {
                    self.ensure_pane(new, cx);
                    if let Some(address) = address {
                        self.set_cursor(new, address, true);
                    }
                    self.focus_pane(new, window, cx);
                }
            }
            Command::ToggleLeftSidebar => {
                self.left_sidebar = !self.left_sidebar;
                if !self.left_sidebar {
                    self.focus_pane(id, window, cx);
                }
            }
            Command::ToggleRightSidebar => self.right_sidebar = !self.right_sidebar,
            Command::ToggleConsole => self.toggle_console(window, cx),
            Command::ToggleFeatureMap => self.toggle_feature_map(window, cx),
            Command::MoveFeatureMap => self.move_feature_map(window, cx),
            Command::OpenAsTab => {
                if let Some(key) = self.folder_key() {
                    self.open_folder(key, window, cx);
                }
            }
            Command::ToggleMaximize => {
                self.maximized = (self.maximized.is_none() && self.layout.len() > 1).then_some(id);
            }
            Command::ToggleTheme => {
                let next = if self.is_dark() { "light" } else { "dark" };
                self.set_setting("window.theme", &Setting::Text(next.to_owned()), window, cx);
            }
            Command::SelectTheme => self.open_picker(PickerKind::Theme, window, cx),
            Command::ZoomIn if self.shows_graph(id) => self.zoom_graph(id, Some(1.25)),
            Command::ZoomOut if self.shows_graph(id) => self.zoom_graph(id, Some(0.8)),
            Command::ZoomReset if self.shows_graph(id) => self.zoom_graph(id, None),
            Command::ZoomIn => self.zoom(0.1, window, cx),
            Command::ZoomOut => self.zoom(-0.1, window, cx),
            Command::ZoomReset => self.zoom(0.0, window, cx),
            Command::ToggleGraph => self.toggle_graph(id),
            Command::OpenGraphInSplit => self.open_graph_in_split(window, cx),
            Command::FitGraph => self.fit_graph(id),
            Command::ToggleOverview => self.overview = !self.overview,
            Command::ToggleReadingView => self.toggle_view(id),
            Command::ShowInIr => self.show_in_ir(window, cx),
            Command::IrPreviousStage => self.ir_step(id, -1),
            Command::IrNextStage => self.ir_step(id, 1),
            Command::ToggleIrDiff => self.toggle_ir_diff(id),
            Command::ToggleOpcodeBytes => {
                let bytes = if self.settings.opcode_bytes == 0 {
                    8.0
                } else {
                    0.0
                };
                self.set_setting("listing.opcode_bytes", &Setting::Number(bytes), window, cx);
            }
            Command::ToggleNumbers => self.cycle_setting("listing.numbers", window, cx),
            Command::ToggleSymbolic => self.toggle_setting("listing.symbolic", window, cx),
            Command::CycleXrefs => {
                let next = match self.settings.xrefs {
                    0 => 2.0,
                    1..=2 => 5.0,
                    _ => 0.0,
                };
                self.set_setting("listing.xrefs", &Setting::Number(next), window, cx);
            }
            Command::ToggleLigatures => self.toggle_setting("font.ligatures", window, cx),
            Command::ToggleIslands => self.toggle_setting("window.islands", window, cx),
            Command::Settings => self.open_tab(id, TabKind::Settings, window, cx),
            Command::Palette | Command::KeyMap => self.open_picker(PickerKind::Palette, window, cx),
            Command::GoAnywhere => self.open_picker(PickerKind::GoTo, window, cx),
            Command::Back => self.back(cx),
            Command::Forward => self.forward(cx),
            Command::Follow => self.follow(window, cx),
            Command::Xrefs => self.open_xrefs(window, cx),
            Command::Functions => self.focus_map(window, cx),
            Command::Strings => self.open_tab(id, TabKind::Strings, window, cx),
            Command::Peek => self.peek_at_cursor(window, cx),
            Command::Origin => self.open_origin(),
            Command::Verify => self.verify_now(),
            Command::NextFunction | Command::PreviousFunction => {
                let entries: Vec<u64> = self.functions.iter().map(|&(e, _)| e).collect();
                let target =
                    self.listing
                        .as_ref()
                        .zip(self.current_address())
                        .and_then(|(l, a)| {
                            l.neighbour_function(&entries, a, command == Command::NextFunction)
                        });
                if let Some(target) = target {
                    self.jump(target, cx);
                }
            }
            Command::CloseTab => {
                // A pane of code (its one tab, a view) or the settings: the
                // strip's tab closes; the last tab of a place stays (Close
                // Pane closes a pane). A pane of lists: its list closes.
                let index = self.window_tabs_active();
                let code = self.layout.pane(id).is_some_and(|p| {
                    !p.tabs.iter().any(|t| crate::tabs::is_list(&t.content))
                });
                if self.shows_tool() || code {
                    if self.can_close_window_tab(index) {
                        self.close_window_tab(index, window, cx);
                    }
                    return;
                }
                if let Some(pane) = self.layout.pane(id) {
                    let active = pane.active;
                    self.layout.close_tab(id, active);
                }
                self.after_layout(window, cx);
            }
            Command::ClosePane => {
                if self.shows_tool() {
                    let index = self.window_tabs_active();
                    self.close_window_tab(index, window, cx);
                    return;
                }
                self.layout.close_pane(id);
                self.after_layout(window, cx);
            }
            Command::NextTab | Command::PreviousTab => {
                // A pane of code: the strip's tabs; one of lists: its own.
                if self.layout.pane(id).is_some_and(|p| {
                    !p.tabs.iter().any(|t| crate::tabs::is_list(&t.content))
                }) {
                    self.cycle_window_tab(command == Command::NextTab, window, cx);
                } else {
                    self.layout.cycle(id, command == Command::NextTab);
                    self.ensure_documents();
                }
            }
            Command::MoveTabLeft | Command::MoveTabRight => {
                self.step_tab(id, command == Command::MoveTabRight, window, cx);
            }
            Command::MoveTabToNextPane => self.tab_to_next_pane(id, window, cx),
            Command::FocusLeft => self.focus_toward(Direction::Left, window, cx),
            Command::FocusRight => self.focus_toward(Direction::Right, window, cx),
            Command::FocusUp => self.focus_toward(Direction::Up, window, cx),
            Command::FocusDown => self.focus_toward(Direction::Down, window, cx),
            Command::FocusNextPane => {
                let to = self.layout.focus_next();
                self.focus_pane(to, window, cx);
            }
            Command::SwitchView => self.switch_view(window, cx),
            Command::ToggleSync => {
                let address = self.shared;
                if let Some(pane) = self.layout.pane_mut(id) {
                    pane.synced = !pane.synced;
                    if pane.synced
                        && let Some(address) = address
                    {
                        self.set_cursor(id, address, false);
                    }
                }
            }
            Command::OpenSettingsFile => self.open_settings_file(cx),
            Command::MoveUp if self.shows_graph(id) => self.graph_step(id, false),
            Command::MoveDown if self.shows_graph(id) => self.graph_step(id, true),
            Command::MoveUp => self.move_cursor(-1, false),
            Command::MoveDown => self.move_cursor(1, false),
            Command::PageUp => self.move_cursor(-self.page(id), false),
            Command::PageDown => self.move_cursor(self.page(id), false),
            Command::Top => self.move_cursor(TOP, false),
            Command::Bottom => self.move_cursor(BOTTOM, false),
        }
    }

    /// The lines a page moves pane `id`'s cursor: the rows shown but two.
    pub fn page(&self, id: PaneId) -> i64 {
        let height = self.line_height(id);
        i64::try_from(self.rows(id, height)).unwrap_or(2).max(3) - 2
    }

    /// The row height (logical) of pane `id`'s active tab: the code's, or
    /// a list's (a line of the interface font, as the map's rows).
    pub fn line_height(&self, id: PaneId) -> f32 {
        match self.layout.active(id) {
            Some(TabKind::C { .. }) if self.shows_ir(id) => self.settings.listing_line_height,
            Some(TabKind::C { .. }) => self.settings.c_line_height,
            Some(
                TabKind::Strings | TabKind::Xrefs { .. } | TabKind::Found(_) | TabKind::Folder(_),
            ) => self.ui_line() + ROW_PAD,
            Some(TabKind::Listing | TabKind::Settings | TabKind::Struct(_)) | None => {
                self.settings.listing_line_height
            }
        }
    }

    pub(crate) fn after_layout(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let live: Vec<PaneId> = self.layout.panes().map(|p| p.id).collect();
        self.panes.retain(|id, _| live.contains(id));
        if self.maximized.is_some_and(|m| !live.contains(&m)) || live.len() < 2 {
            self.maximized = None;
        }
        let focused = self.layout.focused();
        self.focus_pane(focused, window, cx);
        self.ensure_documents();
    }

    /// Opens `kind` in pane `id` (pinned; a list as [`Workspace::open_list`]
    /// places it, the settings in a tab of the strip of their own), its
    /// cursor on the shared one.
    pub fn open_tab(
        &mut self,
        id: PaneId,
        kind: TabKind,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let settings = kind == TabKind::Settings;
        let id = if settings {
            self.open_tool_tab(kind, cx)
        } else if crate::tabs::is_list(&kind) {
            self.open_list(id, kind, false, cx)
        } else {
            self.layout.open(id, kind, false);
            id
        };
        if let Some(address) = self.shared.or_else(|| self.current_address()) {
            self.set_cursor(id, address, false);
        }
        self.ensure_documents();
        self.focus_pane(id, window, cx);
        if settings {
            let search = self.settings_search(window, cx);
            search.update(cx, |s, cx| s.focus(window, cx));
        }
    }

    /// Switches pane `id`'s C between the reading view and the exact C,
    /// the cursor kept on its instruction.
    pub fn toggle_view(&mut self, id: PaneId) {
        let address = self.cursor_address(id);
        if let Some(TabKind::C { view, .. }) = self.layout.active_mut(id) {
            *view = match view {
                View::Exact => View::Reading,
                View::Reading => View::Exact,
            };
        }
        if let Some(address) = address {
            self.set_cursor(id, address, false);
        }
        self.ensure_documents();
    }

    /// Sets pane `id`'s C view.
    pub fn set_view(&mut self, id: PaneId, to: View) {
        if matches!(self.layout.active(id), Some(TabKind::C { view, .. }) if *view != to) {
            self.toggle_view(id);
        }
    }

    /// Moves the focus between a listing and a C pane (Tab), the cursor
    /// kept; with no other pane showing the other, the pane's view of code
    /// switches to it in place, where the pane is.
    fn switch_view(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let id = self.layout.focused();
        let want_c = matches!(self.layout.active(id), Some(TabKind::Listing));
        let wanted = |kind: Option<&TabKind>| {
            matches!(
                (kind, want_c),
                (Some(TabKind::C { .. }), true) | (Some(TabKind::Listing), false)
            )
        };
        let other = self
            .layout
            .panes()
            .find(|p| p.id != id && wanted(p.tabs.get(p.active).map(|t| &t.content)));
        if let Some(other) = other.map(|p| p.id) {
            if let Some(address) = self.cursor_address(id) {
                self.set_cursor(other, address, false);
            }
            self.focus_pane(other, window, cx);
            return;
        }
        if !crate::tabs::is_code(self.layout.active(id)) {
            return;
        }
        let kind = if want_c {
            TabKind::C {
                function: None,
                view: self.default_view(),
            }
        } else {
            TabKind::Listing
        };
        self.set_code_view(id, &kind);
        self.focus_pane(id, window, cx);
    }

    /// Moves the focused pane's cursor `delta` lines, extending the
    /// listing's or the C's selection with `extend` (Shift), else dropping
    /// it.
    pub fn move_cursor(&mut self, delta: i64, extend: bool) {
        let id = self.layout.focused();
        if self.shows_ir(id) {
            self.ir_move(id, delta);
            return;
        }
        let Some(kind) = self.layout.active(id).cloned() else {
            return;
        };
        let height = self.line_height(id);
        let rows = self.rows(id, height);
        let total = match &kind {
            TabKind::Listing => self.listing.as_ref().map_or(0, |l| l.len()),
            TabKind::C { .. } => self.document(&kind).map_or(0, |d| d.lines.len() as u64),
            TabKind::Strings | TabKind::Xrefs { .. } | TabKind::Folder(_) => {
                self.panes.get(&id).map_or(0, |s| s.list.rows.len() as u64)
            }
            TabKind::Settings | TabKind::Struct(_) | TabKind::Found(_) => 0,
        };
        let Some(state) = self.panes.get_mut(&id) else {
            return;
        };
        if total == 0 {
            return;
        }
        let step = |current: u64| {
            if delta < 0 {
                current.saturating_sub(delta.unsigned_abs())
            } else {
                current.saturating_add(delta.unsigned_abs()).min(total - 1)
            }
        };
        match kind {
            TabKind::Listing => {
                state.listing.selection.leave(state.listing.cursor, extend);
                state.listing.cursor = step(state.listing.cursor);
                state.listing.token = None;
                state
                    .listing
                    .scroll
                    .reveal(state.listing.cursor, total, rows, 2);
            }
            TabKind::C { .. } => {
                let at = TextPos::new(state.c.line, state.c.column);
                state.c.selection.leave(at, extend);
                let line = step(state.c.line as u64);
                state.c.line = usize::try_from(line).unwrap_or(0);
                state.c.span = None;
                state.c.scroll.reveal(line, total, rows, 2);
            }
            TabKind::Strings | TabKind::Xrefs { .. } | TabKind::Folder(_) => {
                let to = step(state.list.selected as u64);
                state.list.selected = usize::try_from(to).unwrap_or(0);
                // Under the header: the rows but one.
                let shown = rows.saturating_sub(1).max(1);
                state.list.scroll.reveal(to, total, shown, 0);
                self.ensure_documents();
                return;
            }
            TabKind::Settings | TabKind::Struct(_) | TabKind::Found(_) => return,
        }
        self.moved(id);
    }

    /// Follows the reference under the cursor; in a list, goes to the
    /// selected row.
    fn follow(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let id = self.layout.focused();
        if matches!(
            self.layout.active(id),
            Some(TabKind::Strings | TabKind::Xrefs { .. } | TabKind::Folder(_))
        ) {
            self.list_open(id, Opening::Linked { focus: true }, window, cx);
            return;
        }
        // A `goto`'s label: where it is defined, in the same C.
        if self.menu_subject.is_none()
            && let Some(kind @ TabKind::C { .. }) = self.layout.active(id)
            && let Some(document) = self.document(kind).cloned()
            && let Some(span) = self.panes.get(&id).and_then(|s| s.c.span)
            && self.follow_label(id, &document, span, cx)
        {
            return;
        }
        if let Some(target) = self.target_under_cursor() {
            self.jump(target, cx);
        }
    }

    /// The address the token under the focused pane's cursor names.
    pub fn target_under_cursor(&self) -> Option<u64> {
        if let Some(subject) = self.menu_subject {
            return Some(subject);
        }
        let id = self.layout.focused();
        let state = self.panes.get(&id)?;
        let listing = self.listing.as_ref()?;
        let session = self.session.as_ref()?;
        match self.layout.active(id)? {
            TabKind::Listing => {
                let db = session.database()?;
                let rendered = listing.render(db, state.listing.cursor, session.overlay());
                state
                    .listing
                    .token
                    .and_then(|i| rendered.tokens.get(i))
                    .and_then(|t| t.target)
                    .or_else(|| rendered.tokens.iter().skip(1).find_map(|t| t.target))
            }
            kind @ TabKind::C { .. } => {
                let document = self.document(kind)?;
                let span = state.c.span?;
                if document.variable(span).is_some() {
                    return None;
                }
                self.c_name_address(document, span)
            }
            TabKind::Settings
            | TabKind::Strings
            | TabKind::Xrefs { .. }
            | TabKind::Struct(_)
            | TabKind::Found(_)
            | TabKind::Folder(_) => None,
        }
    }

    /// The name under the cursor (a token's, else the cursor item's).
    fn name_under_cursor(&self) -> Option<String> {
        let id = self.layout.focused();
        let state = self.panes.get(&id)?;
        if self.menu_subject.is_none()
            && let Some(kind @ TabKind::C { .. }) = self.layout.active(id)
            && let Some(span) = state.c.span
        {
            return self.document(kind).map(|d| d.span_text(span).to_owned());
        }
        let session = self.session.as_ref()?;
        let address = self
            .target_under_cursor()
            .or_else(|| self.current_address())?;
        self.listing
            .as_ref()?
            .shown_name(address, session.overlay())
            .map(str::to_owned)
    }

    /// Focuses the pane beside the focused one toward `direction`, if any.
    fn focus_toward(&mut self, direction: Direction, window: &mut Window, cx: &mut Context<Self>) {
        if self.layout.move_focus(direction) {
            let to = self.layout.focused();
            self.focus_pane(to, window, cx);
        }
    }

    fn prompt_open(window: &mut Window, cx: &mut Context<Self>) {
        let paths = cx.prompt_for_paths(PathPromptOptions {
            files: true,
            directories: false,
            multiple: false,
            prompt: None,
        });
        cx.spawn_in(window, async move |this, cx| {
            if let Ok(Ok(Some(paths))) = paths.await
                && let Some(path) = paths.into_iter().next()
            {
                let _ = this.update_in(cx, |this, window, cx| this.open(path, window, cx));
            }
        })
        .detach();
    }
}

/// How many rows of `row` pixels fill `height` (one more for the partly
/// shown last).
#[expect(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "a window's height over a row's: small and positive"
)]
pub fn rows_in(height: f32, row: f32) -> u64 {
    (height / row.max(1.0)).ceil().max(1.0) as u64
}

/// How many whole rows of `row` pixels fit in `height` (at least one).
#[expect(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "a window's height over a row's: small and positive"
)]
pub fn whole_rows_in(height: f32, row: f32) -> u64 {
    (height / row.max(1.0)).floor().max(1.0) as u64
}

/// `n` as pixels (a line offset on screen).
#[expect(clippy::cast_precision_loss, reason = "lines on screen")]
pub fn f(n: u64) -> f32 {
    n as f32
}

/// Whether `appearance` is a dark one.
fn is_dark(appearance: WindowAppearance) -> bool {
    matches!(
        appearance,
        WindowAppearance::Dark | WindowAppearance::VibrantDark
    )
}

/// The settings file's problems, as their banner says them.
fn problems_text(problems: &[settings::Problem]) -> Option<String> {
    (!problems.is_empty()).then(|| {
        let all: Vec<String> = problems
            .iter()
            .map(|p| format!("{}: {}", p.key, p.message))
            .collect();
        format!("settings: {}", all.join("; "))
    })
}

/// What is wrong with `[keys]`, as the settings banner says it.
fn unknown_keys(unknown: &[String]) -> Option<String> {
    (!unknown.is_empty()).then(|| format!("settings: keys: {}", unknown.join("; ")))
}

/// The window's title with `session` open: its file ([`titled_file`]); a
/// share's project's says whose share it is ("bash, shared by Ann").
pub(crate) fn window_title(session: &Session) -> String {
    let file = titled_file(session);
    let title = project_title(&file, session.project().map(Project::dir));
    format!("{title} — binbun")
}

/// `session`'s file as the titles name it (the window's, the command
/// center's): its name, and the slice open of a universal file.
pub(crate) fn titled_file(session: &Session) -> String {
    match session.slice() {
        Some(arch) => format!("{} ({arch})", session.file_name()),
        None => session.file_name(),
    }
}

/// Whether `a` and `b` name the same file.
pub(crate) fn same_file(a: &Path, b: &Path) -> bool {
    match (std::fs::canonicalize(a), std::fs::canonicalize(b)) {
        (Ok(a), Ok(b)) => a == b,
        _ => a == b,
    }
}
