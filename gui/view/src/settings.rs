//! User settings: their values, the registry the settings pane and the
//! command palette show, and the TOML file they are kept in.
//!
//! The file is [`binbun_paths::Place::Settings`]. It is edited in place: setting a
//! value rewrites only that value, so the user's comments, blank lines and
//! order stay as written. Each setting lives in a table named by the first
//! part of its key (`font.code` is `code` in `[font]`); `[keys]` holds key
//! binding overrides. A missing key has its default; a wrong one keeps its
//! default and is reported as a [`Problem`], never dropped from the file.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use binbun_print::style::{IntSpelling, Naming, Placement, Spacing, Style};
use binbun_session::signatures::Options as SignatureOptions;
use toml_edit::{DocumentMut, Item, Table, TableLike, Value};

use crate::crash_safe;

/// Which of the dark and the light theme is used.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Theme {
    /// Light text on a dark background.
    #[default]
    Dark,
    /// Dark text on a light background.
    Light,
    /// The system's light or dark preference.
    System,
}

impl Theme {
    fn name(self) -> &'static str {
        match self {
            Self::Dark => "dark",
            Self::Light => "light",
            Self::System => "system",
        }
    }

    fn from_name(name: &str) -> Option<Self> {
        match name {
            "dark" => Some(Self::Dark),
            "light" => Some(Self::Light),
            "system" => Some(Self::System),
            _ => None,
        }
    }
}

/// How the window's background shows what is behind it (GPUI's
/// `WindowBackgroundAppearance`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Backdrop {
    /// As the theme says (`--background-appearance`), else opaque.
    #[default]
    Theme,
    /// Nothing behind the window shows.
    Opaque,
    /// What is behind shows through the background surfaces.
    Transparent,
    /// What is behind shows blurred, where the platform can blur.
    Blurred,
    /// Windows 11's Mica material.
    Mica,
    /// Windows 11's Mica Alt material.
    MicaAlt,
}

impl Backdrop {
    fn name(self) -> &'static str {
        match self {
            Self::Theme => "theme",
            Self::Opaque => "opaque",
            Self::Transparent => "transparent",
            Self::Blurred => "blurred",
            Self::Mica => "mica",
            Self::MicaAlt => "mica-alt",
        }
    }

    /// The backdrop named `name` (the setting's names; a theme's
    /// `--background-appearance` uses them too, without `theme`).
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "theme" => Some(Self::Theme),
            "opaque" => Some(Self::Opaque),
            "transparent" => Some(Self::Transparent),
            "blurred" => Some(Self::Blurred),
            "mica" => Some(Self::Mica),
            "mica-alt" => Some(Self::MicaAlt),
            _ => None,
        }
    }
}

/// What a file dropped on a window with a binary open does.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Dropped {
    /// It replaces the binary open (the edits are saved as they are made).
    #[default]
    Replace,
    /// It opens in a new window.
    NewWindow,
}

impl Dropped {
    fn name(self) -> &'static str {
        match self {
            Self::Replace => "replace",
            Self::NewWindow => "new window",
        }
    }

    fn from_name(name: &str) -> Option<Self> {
        match name {
            "replace" => Some(Self::Replace),
            "new window" => Some(Self::NewWindow),
            _ => None,
        }
    }
}

/// Where the feature map is.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum FeatureMap {
    /// A horizontal band above the panes.
    #[default]
    Top,
    /// A vertical strip at the right of the panes.
    Right,
    /// Not shown.
    Off,
}

impl FeatureMap {
    /// Its name in the settings file.
    pub fn name(self) -> &'static str {
        match self {
            Self::Right => "right",
            Self::Top => "top",
            Self::Off => "off",
        }
    }

    fn from_name(name: &str) -> Option<Self> {
        match name {
            "right" => Some(Self::Right),
            "top" => Some(Self::Top),
            "off" => Some(Self::Off),
            _ => None,
        }
    }
}

/// How the listing writes numbers.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Numbers {
    /// Intel (MASM) style: `88h`.
    #[default]
    Masm,
    /// C style: `0x88`.
    C,
}

impl Numbers {
    fn name(self) -> &'static str {
        match self {
            Self::Masm => "masm",
            Self::C => "c",
        }
    }

    fn from_name(name: &str) -> Option<Self> {
        match name {
            "masm" => Some(Self::Masm),
            "c" => Some(Self::C),
            _ => None,
        }
    }
}

/// The view a listing pane opens in: text or graph.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum ListingView {
    /// The view last chosen in any pane.
    #[default]
    Last,
    /// The text (continuous listing).
    Text,
    /// The graph of the function at the cursor.
    Graph,
}

impl ListingView {
    fn name(self) -> &'static str {
        match self {
            Self::Last => "last",
            Self::Text => "text",
            Self::Graph => "graph",
        }
    }

    fn from_name(name: &str) -> Option<Self> {
        match name {
            "last" => Some(Self::Last),
            "text" => Some(Self::Text),
            "graph" => Some(Self::Graph),
            _ => None,
        }
    }
}

/// The view the C pane opens in.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum CView {
    /// The reading view.
    #[default]
    Reading,
    /// The exact view.
    Exact,
}

impl CView {
    fn name(self) -> &'static str {
        match self {
            Self::Reading => "reading",
            Self::Exact => "exact",
        }
    }

    fn from_name(name: &str) -> Option<Self> {
        match name {
            "reading" => Some(Self::Reading),
            "exact" => Some(Self::Exact),
            _ => None,
        }
    }
}

/// How the C spells integer types.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum CTypes {
    /// Fixed-width: `int32_t`, `uint8_t`.
    #[default]
    Fixed,
    /// C's own names for the binary's platform: `int`, `unsigned char`,
    /// `long` (`long long` on Windows).
    Plain,
}

impl CTypes {
    fn name(self) -> &'static str {
        match self {
            Self::Fixed => "fixed",
            Self::Plain => "plain",
        }
    }

    fn from_name(name: &str) -> Option<Self> {
        match name {
            "fixed" => Some(Self::Fixed),
            "plain" => Some(Self::Plain),
            _ => None,
        }
    }
}

/// `c.declarations`' name of `placement`.
fn placement_name(placement: Placement) -> &'static str {
    match placement {
        Placement::Scoped => "scoped",
        Placement::Top => "top",
    }
}

/// The placement `c.declarations` names `name`.
fn placement_from_name(name: &str) -> Option<Placement> {
    match name {
        "scoped" => Some(Placement::Scoped),
        "top" => Some(Placement::Top),
        _ => None,
    }
}

/// `c.names`' name of `naming`.
fn naming_name(naming: Naming) -> &'static str {
    match naming {
        Naming::Numbered => "numbered",
        Naming::Registers => "registers",
    }
}

/// The naming `c.names` names `name`.
fn naming_from_name(name: &str) -> Option<Naming> {
    match name {
        "numbered" => Some(Naming::Numbered),
        "registers" => Some(Naming::Registers),
        _ => None,
    }
}

/// `c.spacing`' name of `spacing`.
fn spacing_name(spacing: Spacing) -> &'static str {
    match spacing {
        Spacing::Paragraphs => "paragraphs",
        Spacing::Compact => "compact",
    }
}

/// The spacing `c.spacing` names `name`.
fn spacing_from_name(name: &str) -> Option<Spacing> {
    match name {
        "paragraphs" => Some(Spacing::Paragraphs),
        "compact" => Some(Spacing::Compact),
        _ => None,
    }
}

/// Whether debug information is fetched from symbol servers: a request
/// tells the server which binary is open.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum SymbolDownload {
    /// Ask with a bar across the workspace, each time a binary is opened.
    #[default]
    Ask,
    /// Fetch without asking.
    Always,
    /// Never fetch.
    Never,
}

impl SymbolDownload {
    fn name(self) -> &'static str {
        match self {
            Self::Ask => "ask",
            Self::Always => "always",
            Self::Never => "never",
        }
    }

    fn from_name(name: &str) -> Option<Self> {
        match name {
            "ask" => Some(Self::Ask),
            "always" => Some(Self::Always),
            "never" => Some(Self::Never),
            _ => None,
        }
    }
}

/// Whether binbun checks for a newer version of itself (at launch, then
/// hourly; a request tells binbun.org nothing but binbun's version).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum UpdateCheck {
    /// Ask once with a banner; the answer becomes always or never.
    #[default]
    Ask,
    /// Check.
    Always,
    /// Never check.
    Never,
}

impl UpdateCheck {
    fn name(self) -> &'static str {
        match self {
            Self::Ask => "ask",
            Self::Always => "always",
            Self::Never => "never",
        }
    }

    fn from_name(name: &str) -> Option<Self> {
        match name {
            "ask" => Some(Self::Ask),
            "always" => Some(Self::Always),
            "never" => Some(Self::Never),
            _ => None,
        }
    }
}

/// The relay a shared session reaches peers through when no direct path
/// works (`collab.relay`).
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub enum CollabRelay {
    /// binbun's relay, `us-east.relay.binbun.org`.
    #[default]
    Binbun,
    /// n0's public relays.
    N0,
    /// The relay at this URL.
    Custom(String),
}

impl CollabRelay {
    /// Its value in the file: `binbun`, `n0`, or the URL.
    pub fn name(&self) -> &str {
        match self {
            Self::Binbun => "binbun",
            Self::N0 => "n0",
            Self::Custom(url) => url,
        }
    }

    /// Its label in the Share and Join dialogs.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Binbun => "binbun relay",
            Self::N0 => "n0 relays",
            Self::Custom(_) => "Custom relay",
        }
    }

    /// `binbun`, `n0`, or an `http` or `https` URL with a host.
    fn from_text(text: &str) -> Result<Self, String> {
        let text = text.trim();
        match text {
            "binbun" => return Ok(Self::Binbun),
            "n0" => return Ok(Self::N0),
            _ => {}
        }
        let host = text
            .strip_prefix("https://")
            .or_else(|| text.strip_prefix("http://"))
            .map(|rest| rest.split(['/', '?', '#']).next().unwrap_or_default());
        match host {
            Some(host) if !host.is_empty() && !text.contains(char::is_whitespace) => {
                Ok(Self::Custom(text.to_owned()))
            }
            _ => Err(format!(
                "expected \"binbun\", \"n0\" or a relay's URL (https://…), found {text:?}"
            )),
        }
    }
}

/// Every user setting. `Default` gives the defaults listed on each field.
#[derive(Clone, Debug, PartialEq)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "each bool is an independent user setting"
)]
pub struct Settings {
    /// The monospace font of the listing and the C pane (`font.code`,
    /// default "Iosevka").
    pub code_font: String,
    /// The code font's size in pixels (`font.code_size`, default 13, 6 to 40).
    pub code_font_size: f32,
    /// The font of everything that is not code (`font.ui`, default
    /// "IBM Plex Sans").
    pub ui_font: String,
    /// The interface font's size in pixels (`font.ui_size`, default 13, 8 to
    /// 32).
    pub ui_font_size: f32,
    /// The whole window's zoom (`window.scale`, default 1.0, 0.5 to 3.0).
    pub ui_scale: f32,
    /// The listing's line height in pixels (`listing.line_height`, default
    /// 17, 12 to 48).
    pub listing_line_height: f32,
    /// The C pane's line height in pixels (`c.line_height`, default 17, 12
    /// to 48).
    pub c_line_height: f32,
    /// Whether the dark or the light theme is used, or the system's
    /// preference picks (`window.theme`, default dark).
    pub theme: Theme,
    /// The theme used when the window is dark, by name
    /// (`window.dark_theme`, default "One Dark").
    pub dark_theme: String,
    /// The theme used when the window is light, by name
    /// (`window.light_theme`, default "One Light").
    pub light_theme: String,
    /// How the window's background shows what is behind it
    /// (`window.background`, default theme).
    pub backdrop: Backdrop,
    /// The alpha the background surfaces are scaled by when the
    /// background is not opaque (`window.opacity`, default 1.0, 0 to 1).
    pub opacity: f32,
    /// Whether the code font draws ligatures (`font.ligatures`, default
    /// false).
    pub ligatures: bool,
    /// How many opcode bytes the listing shows before each instruction
    /// (`listing.opcode_bytes`, default 0, 0 to 16).
    pub opcode_bytes: u32,
    /// How the listing writes numbers (`listing.numbers`, default masm).
    pub numbers: Numbers,
    /// Whether operands show names; false shows raw addresses
    /// (`listing.symbolic`, default true).
    pub symbolic: bool,
    /// How many cross-references the listing shows per line
    /// (`listing.xrefs`, default 2, 0 to 16).
    pub xrefs: u32,
    /// How many lanes the listing's branch-arrow gutter has; an arrow past
    /// them is a stub at each end (`listing.arrow_lanes`, default 10, 2 to
    /// 24).
    pub arrow_lanes: u32,
    /// The view new listing panes open in (`listing.default_view`, default
    /// last).
    pub listing_view: ListingView,
    /// The C pane's default view (`c.view`, default reading).
    pub c_view: CView,
    /// How the C spells integer types (`c.types`, default fixed).
    pub c_types: CTypes,
    /// Where the C declares locals (`c.declarations`, default scoped: in
    /// the blocks using them; top: all at the top of each function).
    pub declarations: Placement,
    /// How the C names variables with no name of their own (`c.names`,
    /// default numbered: `a1`, `v7`; registers: `arg1`, `rax`, `var_58`).
    pub names: Naming,
    /// Whether empty lines part a block's statements (`c.spacing`,
    /// default paragraphs; compact: none).
    pub spacing: Spacing,
    /// Whether the shown function is verified once the cursor rests
    /// (`c.auto_verify`, default true).
    pub auto_verify: bool,
    /// Whether panes are drawn as islands; false draws flat panes
    /// with hairlines (`window.islands`, default false).
    pub islands: bool,
    /// What a file dropped on a window with a binary open does
    /// (`window.drop`, default replace).
    pub drop: Dropped,
    /// Where the feature map is (`window.feature_map`, default top).
    pub feature_map: FeatureMap,
    /// Whether scrolling is animated (`scrolling.smooth`, default true).
    pub smooth_scroll: bool,
    /// How long a smooth scroll lasts, in milliseconds
    /// (`scrolling.smooth_ms`, default 120, 0 to 1000).
    pub smooth_scroll_ms: u32,
    /// How long the pointer rests on a name before its peek opens, in
    /// milliseconds (`peek.delay_ms`, default 300, 0 to 5000).
    pub peek_delay_ms: u32,
    /// Whether debug information is fetched from symbol servers
    /// (`symbols.download`, default ask).
    pub symbols: SymbolDownload,
    /// Whether library functions are named by the signature packs
    /// installed when a binary opens (`signatures.apply`, default true).
    pub signatures: bool,
    /// Whether the signatures' background pass also looks for the packs'
    /// functions in code nothing reaches (`signatures.sweep`, default as
    /// [`binbun_session::signatures::Options`]'s).
    pub signatures_sweep: bool,
    /// Whether binbun checks for a newer version (`updates.check`, default
    /// ask). Without effect in a build with the check compiled out
    /// (`BINBUN_UPDATE_CHECK=off`).
    pub updates: UpdateCheck,
    /// The relay a shared session uses (`collab.relay`, default binbun).
    pub collab_relay: CollabRelay,
    /// The Python the console runs, a path or a name on `PATH`
    /// (`python.interpreter`, default "python3").
    pub python_interpreter: String,
    /// Key binding overrides from `[keys]`: command id to GPUI keystrokes
    /// such as "ctrl-shift-p" (`ctrl-` is Ctrl everywhere, `cmd-` Cmd,
    /// `secondary-` Cmd on macOS and Ctrl elsewhere); an empty list unbinds
    /// the command. Default empty. Not in [`SETTINGS`] and not reachable
    /// through `get`/`set`.
    pub keys: BTreeMap<String, Vec<String>>,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            code_font: "Iosevka".to_owned(),
            code_font_size: 13.0,
            ui_font: "IBM Plex Sans".to_owned(),
            ui_font_size: 13.0,
            ui_scale: 1.0,
            listing_line_height: 17.0,
            c_line_height: 17.0,
            theme: Theme::Dark,
            dark_theme: "One Dark".to_owned(),
            light_theme: "One Light".to_owned(),
            backdrop: Backdrop::Theme,
            opacity: 1.0,
            ligatures: false,
            opcode_bytes: 0,
            numbers: Numbers::Masm,
            symbolic: true,
            xrefs: 2,
            arrow_lanes: 10,
            listing_view: ListingView::Last,
            c_view: CView::Reading,
            c_types: CTypes::Fixed,
            declarations: Placement::Scoped,
            names: Naming::Numbered,
            spacing: Spacing::Paragraphs,
            auto_verify: true,
            islands: false,
            drop: Dropped::Replace,
            feature_map: FeatureMap::Top,
            smooth_scroll: true,
            smooth_scroll_ms: 120,
            peek_delay_ms: 300,
            symbols: SymbolDownload::Ask,
            signatures: true,
            signatures_sweep: SignatureOptions::default().sweep,
            updates: UpdateCheck::Ask,
            collab_relay: CollabRelay::Binbun,
            python_interpreter: "python3".to_owned(),
            keys: BTreeMap::new(),
        }
    }
}

/// What kind of control a setting has, and what values it takes.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Kind {
    /// On or off: [`Setting::Bool`].
    Toggle,
    /// One of these names: [`Setting::Text`].
    Choice(&'static [&'static str]),
    /// A number from `min` to `max` inclusive, moved by `step` in the
    /// pane: [`Setting::Number`].
    Number {
        /// The smallest value.
        min: f64,
        /// The largest value.
        max: f64,
        /// The pane's increment.
        step: f64,
    },
    /// A font family name: [`Setting::Text`].
    Font {
        /// Whether the pane offers only monospace fonts.
        monospace: bool,
    },
    /// A theme's name: [`Setting::Text`].
    Theme {
        /// Whether it is the dark theme's setting.
        dark: bool,
    },
    /// A program, a path or a name on `PATH`: [`Setting::Text`].
    Program,
    /// A relay: `binbun`, `n0`, or a URL: [`Setting::Text`].
    Relay,
}

/// One setting as the settings pane and the command palette show it.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Info {
    /// The key in the file: table, a dot, then the name in it (`font.code`).
    pub key: &'static str,
    /// The group heading in the pane (`Font`).
    pub group: &'static str,
    /// The display name (`Code font`).
    pub name: &'static str,
    /// One plain sentence saying what it does.
    pub tooltip: &'static str,
    /// The control and the values it takes.
    pub kind: Kind,
}

const THEMES: &[&str] = &["dark", "light", "system"];
const BACKDROPS: &[&str] = &[
    "theme",
    "opaque",
    "transparent",
    "blurred",
    "mica",
    "mica-alt",
];
const NUMBER_STYLES: &[&str] = &["masm", "c"];
const C_VIEWS: &[&str] = &["reading", "exact"];
const C_TYPES: &[&str] = &["fixed", "plain"];
const DECLARATIONS: &[&str] = &["scoped", "top"];
const NAMES: &[&str] = &["numbered", "registers"];
const SPACINGS: &[&str] = &["paragraphs", "compact"];
const LISTING_VIEWS: &[&str] = &["last", "text", "graph"];
const DROPS: &[&str] = &["replace", "new window"];
const FEATURE_MAPS: &[&str] = &["top", "right", "off"];
const DOWNLOADS: &[&str] = &["ask", "always", "never"];

/// The table holding key binding overrides.
const KEYS: &str = "keys";

/// The settings stored as `u32`: the file takes only integers for them.
const WHOLE: &[&str] = &[
    "listing.opcode_bytes",
    "listing.xrefs",
    "listing.arrow_lanes",
    "scrolling.smooth_ms",
    "peek.delay_ms",
];

/// Every setting in display order, grouped: Font, Window, Listing, C,
/// Scrolling, Peek, Symbols, Signatures, Updates, Collaboration, Python.
pub const SETTINGS: &[Info] = &[
    Info {
        key: "font.code",
        group: "Font",
        name: "Code font",
        tooltip: "The monospace font of the listing and the C pane.",
        kind: Kind::Font { monospace: true },
    },
    Info {
        key: "font.code_size",
        group: "Font",
        name: "Code font size",
        tooltip: "The size of the code font, in pixels.",
        kind: Kind::Number {
            min: 6.0,
            max: 40.0,
            step: 1.0,
        },
    },
    Info {
        key: "font.ui",
        group: "Font",
        name: "Interface font",
        tooltip: "The font of menus, tabs, panels and dialogs.",
        kind: Kind::Font { monospace: false },
    },
    Info {
        key: "font.ui_size",
        group: "Font",
        name: "Interface font size",
        tooltip: "The size of the interface font, in pixels.",
        kind: Kind::Number {
            min: 8.0,
            max: 32.0,
            step: 1.0,
        },
    },
    Info {
        key: "font.ligatures",
        group: "Font",
        name: "Ligatures",
        tooltip: "Draws character pairs such as -> and != as ligatures in the code font.",
        kind: Kind::Toggle,
    },
    Info {
        key: "window.scale",
        group: "Window",
        name: "Zoom",
        tooltip: "Scales the whole window.",
        kind: Kind::Number {
            min: 0.5,
            max: 3.0,
            step: 0.1,
        },
    },
    Info {
        key: "window.theme",
        group: "Window",
        name: "Theme",
        tooltip: "Dark, light, or the system's preference: which of the two themes below is used.",
        kind: Kind::Choice(THEMES),
    },
    Info {
        key: "window.dark_theme",
        group: "Window",
        name: "Dark theme",
        tooltip: "The theme of a dark window: a bundled theme or a .css file in the themes folder beside the settings.",
        kind: Kind::Theme { dark: true },
    },
    Info {
        key: "window.light_theme",
        group: "Window",
        name: "Light theme",
        tooltip: "The theme of a light window: a bundled theme or a .css file in the themes folder beside the settings.",
        kind: Kind::Theme { dark: false },
    },
    Info {
        key: "window.islands",
        group: "Window",
        name: "Islands",
        tooltip: "Draws panes as separate islands; off draws flat panes.",
        kind: Kind::Toggle,
    },
    Info {
        key: "window.background",
        group: "Window",
        name: "Background",
        tooltip: "What shows behind the window: as the theme says, nothing (opaque), the desktop (transparent, blurred), or Windows 11's Mica. Blur and Mica fall back where the platform lacks them.",
        kind: Kind::Choice(BACKDROPS),
    },
    Info {
        key: "window.opacity",
        group: "Window",
        name: "Opacity",
        tooltip: "How opaque the window's surfaces are when the background is not opaque; text and code stay opaque.",
        kind: Kind::Number {
            min: 0.0,
            max: 1.0,
            step: 0.05,
        },
    },
    Info {
        key: "window.drop",
        group: "Window",
        name: "Dropped file",
        tooltip: "Whether a file dropped on a window with a binary open replaces it or opens in a new window.",
        kind: Kind::Choice(DROPS),
    },
    Info {
        key: "window.feature_map",
        group: "Window",
        name: "Feature map",
        tooltip: "Where the strip standing for the whole image is: along the top of the panes, at their right, or off.",
        kind: Kind::Choice(FEATURE_MAPS),
    },
    Info {
        key: "listing.line_height",
        group: "Listing",
        name: "Line height",
        tooltip: "The height of a listing line, in pixels.",
        kind: Kind::Number {
            min: 12.0,
            max: 48.0,
            step: 1.0,
        },
    },
    Info {
        key: "listing.opcode_bytes",
        group: "Listing",
        name: "Opcode bytes",
        tooltip: "How many instruction bytes to show before each instruction; 0 hides them.",
        kind: Kind::Number {
            min: 0.0,
            max: 16.0,
            step: 1.0,
        },
    },
    Info {
        key: "listing.numbers",
        group: "Listing",
        name: "Number style",
        tooltip: "Writes numbers as 88h (masm) or as 0x88 (c).",
        kind: Kind::Choice(NUMBER_STYLES),
    },
    Info {
        key: "listing.symbolic",
        group: "Listing",
        name: "Symbolic operands",
        tooltip: "Shows names in operands; off shows raw addresses.",
        kind: Kind::Toggle,
    },
    Info {
        key: "listing.xrefs",
        group: "Listing",
        name: "Cross-references",
        tooltip: "How many cross-references to show beside each line; 0 hides them.",
        kind: Kind::Number {
            min: 0.0,
            max: 16.0,
            step: 1.0,
        },
    },
    Info {
        key: "listing.default_view",
        group: "Listing",
        name: "Default view",
        tooltip: "The view new listing panes open in: the last one used, text, or graph.",
        kind: Kind::Choice(LISTING_VIEWS),
    },
    Info {
        key: "listing.arrow_lanes",
        group: "Listing",
        name: "Arrow lanes",
        tooltip: "How many lanes the branch-arrow gutter has; a jump past them is a labelled stub at each end.",
        kind: Kind::Number {
            min: 2.0,
            max: 24.0,
            step: 1.0,
        },
    },
    Info {
        key: "c.line_height",
        group: "C",
        name: "Line height",
        tooltip: "The height of a C line, in pixels.",
        kind: Kind::Number {
            min: 12.0,
            max: 48.0,
            step: 1.0,
        },
    },
    Info {
        key: "c.view",
        group: "C",
        name: "Default view",
        tooltip: "The view the C pane opens in: reading or exact.",
        kind: Kind::Choice(C_VIEWS),
    },
    Info {
        key: "c.types",
        group: "C",
        name: "Integer types",
        tooltip: "How the C spells integer types: fixed-width (int32_t, uint8_t) or plain, as C programmers write them for the binary's platform (int, unsigned char, long; long long on Windows).",
        kind: Kind::Choice(C_TYPES),
    },
    Info {
        key: "c.declarations",
        group: "C",
        name: "Declarations",
        tooltip: "Where locals are declared: scoped (in the innermost block using each, at its first assignment, a loop counter in its for) or top (all at the top of the function).",
        kind: Kind::Choice(DECLARATIONS),
    },
    Info {
        key: "c.names",
        group: "C",
        name: "Variable names",
        tooltip: "How variables with no name of their own are named: numbered (parameters a1, a2, locals v7) or registers, by where the machine code kept them (parameters arg1, a local by its register: rax, or rax_1, rax_2 where several were; a stack variable by its offset: var_58).",
        kind: Kind::Choice(NAMES),
    },
    Info {
        key: "c.spacing",
        group: "C",
        name: "Spacing",
        tooltip: "Whether empty lines part a block's statements: paragraphs (after declarations, after an if, a loop or a switch that another statement follows, and before a label) or compact (none).",
        kind: Kind::Choice(SPACINGS),
    },
    Info {
        key: "c.auto_verify",
        group: "C",
        name: "Verify automatically",
        tooltip: "Checks the shown function against its machine code once the cursor rests.",
        kind: Kind::Toggle,
    },
    Info {
        key: "scrolling.smooth",
        group: "Scrolling",
        name: "Smooth scrolling",
        tooltip: "Animates scrolling instead of jumping.",
        kind: Kind::Toggle,
    },
    Info {
        key: "scrolling.smooth_ms",
        group: "Scrolling",
        name: "Smooth scrolling time",
        tooltip: "How long a smooth scroll lasts, in milliseconds.",
        kind: Kind::Number {
            min: 0.0,
            max: 1000.0,
            step: 10.0,
        },
    },
    Info {
        key: "peek.delay_ms",
        group: "Peek",
        name: "Peek delay",
        tooltip: "How long the pointer rests on a name before its peek opens, in milliseconds.",
        kind: Kind::Number {
            min: 0.0,
            max: 5000.0,
            step: 50.0,
        },
    },
    Info {
        key: "symbols.download",
        group: "Symbols",
        name: "Download debug information",
        tooltip: "Whether debug information is fetched from symbol servers: ask, always, or never. A request tells the server which binary is open.",
        kind: Kind::Choice(DOWNLOADS),
    },
    Info {
        key: "signatures.apply",
        group: "Signatures",
        name: "Name library functions",
        tooltip: "Names a binary's library functions from the signature packs installed when it opens: by their code, then by their behaviour in the background.",
        kind: Kind::Toggle,
    },
    Info {
        key: "signatures.sweep",
        group: "Signatures",
        name: "Search unreached code",
        tooltip: "Looks for the packs' functions in code nothing calls too, and makes those found functions.",
        kind: Kind::Toggle,
    },
    Info {
        key: "updates.check",
        group: "Updates",
        name: "Check for updates",
        tooltip: "Whether binbun checks binbun.org for a newer version at launch and hourly: ask, always, or never. The request sends nothing but binbun's version.",
        kind: Kind::Choice(DOWNLOADS),
    },
    Info {
        key: "collab.relay",
        group: "Collaboration",
        name: "Relay",
        tooltip: "The relay that forwards a shared session's encrypted traffic when peers have no direct path: binbun's (us-east.relay.binbun.org), n0's public relays, or another at its URL.",
        kind: Kind::Relay,
    },
    Info {
        key: "python.interpreter",
        group: "Python",
        name: "Interpreter",
        tooltip: "The Python the console runs, a path or a name on PATH: Python 3.11 or newer with binbun installed (pip install binbun).",
        kind: Kind::Program,
    },
];

/// A setting's value. A [`Kind::Choice`] value is the choice's name
/// (`Text("dark")`).
#[derive(Clone, Debug, PartialEq)]
pub enum Setting {
    /// A [`Kind::Toggle`] value.
    Bool(bool),
    /// A [`Kind::Number`] value.
    Number(f64),
    /// A [`Kind::Choice`], [`Kind::Font`], [`Kind::Theme`],
    /// [`Kind::Program`] or [`Kind::Relay`] value.
    Text(String),
}

/// A mutable reference to the field behind a key.
#[derive(Debug)]
enum Slot<'a> {
    Bool(&'a mut bool),
    Float(&'a mut f32),
    Whole(&'a mut u32),
    Text(&'a mut String),
    Name(&'a mut String),
    Program(&'a mut String),
    Theme(&'a mut Theme),
    Backdrop(&'a mut Backdrop),
    Dropped(&'a mut Dropped),
    FeatureMap(&'a mut FeatureMap),
    Numbers(&'a mut Numbers),
    CView(&'a mut CView),
    CTypes(&'a mut CTypes),
    Placement(&'a mut Placement),
    Naming(&'a mut Naming),
    Spacing(&'a mut Spacing),
    ListingView(&'a mut ListingView),
    Download(&'a mut SymbolDownload),
    Updates(&'a mut UpdateCheck),
    Relay(&'a mut CollabRelay),
}

impl Settings {
    /// The value of the setting `key` (`font.code`), or `None` when `key` is
    /// not in [`SETTINGS`].
    pub fn get(&self, key: &str) -> Option<Setting> {
        let name = |name: &str| Setting::Text(name.to_owned());
        let whole = |value: u32| Setting::Number(f64::from(value));
        Some(match key {
            "font.code" => Setting::Text(self.code_font.clone()),
            "font.code_size" => Setting::Number(widen(self.code_font_size)),
            "font.ui" => Setting::Text(self.ui_font.clone()),
            "font.ui_size" => Setting::Number(widen(self.ui_font_size)),
            "font.ligatures" => Setting::Bool(self.ligatures),
            "window.scale" => Setting::Number(widen(self.ui_scale)),
            "window.theme" => name(self.theme.name()),
            "window.dark_theme" => Setting::Text(self.dark_theme.clone()),
            "window.light_theme" => Setting::Text(self.light_theme.clone()),
            "window.background" => name(self.backdrop.name()),
            "window.opacity" => Setting::Number(widen(self.opacity)),
            "window.islands" => Setting::Bool(self.islands),
            "window.drop" => name(self.drop.name()),
            "window.feature_map" => name(self.feature_map.name()),
            "listing.line_height" => Setting::Number(widen(self.listing_line_height)),
            "listing.opcode_bytes" => whole(self.opcode_bytes),
            "listing.numbers" => name(self.numbers.name()),
            "listing.symbolic" => Setting::Bool(self.symbolic),
            "listing.xrefs" => whole(self.xrefs),
            "listing.default_view" => name(self.listing_view.name()),
            "listing.arrow_lanes" => whole(self.arrow_lanes),
            "c.line_height" => Setting::Number(widen(self.c_line_height)),
            "c.view" => name(self.c_view.name()),
            "c.types" => name(self.c_types.name()),
            "c.declarations" => name(placement_name(self.declarations)),
            "c.names" => name(naming_name(self.names)),
            "c.spacing" => name(spacing_name(self.spacing)),
            "c.auto_verify" => Setting::Bool(self.auto_verify),
            "scrolling.smooth" => Setting::Bool(self.smooth_scroll),
            "scrolling.smooth_ms" => whole(self.smooth_scroll_ms),
            "peek.delay_ms" => whole(self.peek_delay_ms),
            "symbols.download" => name(self.symbols.name()),
            "signatures.apply" => Setting::Bool(self.signatures),
            "signatures.sweep" => Setting::Bool(self.signatures_sweep),
            "updates.check" => name(self.updates.name()),
            "collab.relay" => name(self.collab_relay.name()),
            "python.interpreter" => Setting::Text(self.python_interpreter.clone()),
            _ => return None,
        })
    }

    /// Sets `key` to `value` after checking its type, range or choice.
    ///
    /// # Errors
    ///
    /// A message when `key` is not in [`SETTINGS`] or `value` is not valid
    /// for it; `self` is then unchanged.
    pub fn set(&mut self, key: &str, value: &Setting) -> Result<(), String> {
        let info = info(key).ok_or_else(|| unknown(key))?;
        let slot = self.slot(key).ok_or_else(|| unknown(key))?;
        match slot {
            Slot::Bool(field) => *field = expect_bool(value)?,
            Slot::Float(field) => *field = narrow(in_range(info, expect_number(value)?)?),
            Slot::Whole(field) => *field = whole(in_range(info, expect_number(value)?)?)?,
            Slot::Text(field) => {
                let text = expect_text(value)?;
                if text.trim().is_empty() {
                    return Err("expected a font name, found an empty string".to_owned());
                }
                text.clone_into(field);
            }
            Slot::Name(field) => {
                let text = expect_text(value)?;
                if text.trim().is_empty() {
                    return Err("expected a theme name, found an empty string".to_owned());
                }
                text.clone_into(field);
            }
            Slot::Program(field) => {
                let text = expect_text(value)?;
                if text.trim().is_empty() {
                    return Err("expected a program, found an empty string".to_owned());
                }
                text.trim().clone_into(field);
            }
            Slot::Theme(field) => *field = choose(info, value, Theme::from_name)?,
            Slot::Backdrop(field) => *field = choose(info, value, Backdrop::from_name)?,
            Slot::Dropped(field) => *field = choose(info, value, Dropped::from_name)?,
            Slot::FeatureMap(field) => *field = choose(info, value, FeatureMap::from_name)?,
            Slot::Numbers(field) => *field = choose(info, value, Numbers::from_name)?,
            Slot::CView(field) => *field = choose(info, value, CView::from_name)?,
            Slot::CTypes(field) => *field = choose(info, value, CTypes::from_name)?,
            Slot::Placement(field) => *field = choose(info, value, placement_from_name)?,
            Slot::Naming(field) => *field = choose(info, value, naming_from_name)?,
            Slot::Spacing(field) => *field = choose(info, value, spacing_from_name)?,
            Slot::ListingView(field) => *field = choose(info, value, ListingView::from_name)?,
            Slot::Download(field) => *field = choose(info, value, SymbolDownload::from_name)?,
            Slot::Updates(field) => *field = choose(info, value, UpdateCheck::from_name)?,
            Slot::Relay(field) => *field = CollabRelay::from_text(expect_text(value)?)?,
        }
        Ok(())
    }

    fn slot(&mut self, key: &str) -> Option<Slot<'_>> {
        Some(match key {
            "font.code" => Slot::Text(&mut self.code_font),
            "font.code_size" => Slot::Float(&mut self.code_font_size),
            "font.ui" => Slot::Text(&mut self.ui_font),
            "font.ui_size" => Slot::Float(&mut self.ui_font_size),
            "font.ligatures" => Slot::Bool(&mut self.ligatures),
            "window.scale" => Slot::Float(&mut self.ui_scale),
            "window.theme" => Slot::Theme(&mut self.theme),
            "window.dark_theme" => Slot::Name(&mut self.dark_theme),
            "window.light_theme" => Slot::Name(&mut self.light_theme),
            "window.background" => Slot::Backdrop(&mut self.backdrop),
            "window.opacity" => Slot::Float(&mut self.opacity),
            "window.islands" => Slot::Bool(&mut self.islands),
            "window.drop" => Slot::Dropped(&mut self.drop),
            "window.feature_map" => Slot::FeatureMap(&mut self.feature_map),
            "listing.line_height" => Slot::Float(&mut self.listing_line_height),
            "listing.opcode_bytes" => Slot::Whole(&mut self.opcode_bytes),
            "listing.numbers" => Slot::Numbers(&mut self.numbers),
            "listing.symbolic" => Slot::Bool(&mut self.symbolic),
            "listing.xrefs" => Slot::Whole(&mut self.xrefs),
            "listing.default_view" => Slot::ListingView(&mut self.listing_view),
            "listing.arrow_lanes" => Slot::Whole(&mut self.arrow_lanes),
            "c.line_height" => Slot::Float(&mut self.c_line_height),
            "c.view" => Slot::CView(&mut self.c_view),
            "c.types" => Slot::CTypes(&mut self.c_types),
            "c.declarations" => Slot::Placement(&mut self.declarations),
            "c.names" => Slot::Naming(&mut self.names),
            "c.spacing" => Slot::Spacing(&mut self.spacing),
            "c.auto_verify" => Slot::Bool(&mut self.auto_verify),
            "scrolling.smooth" => Slot::Bool(&mut self.smooth_scroll),
            "scrolling.smooth_ms" => Slot::Whole(&mut self.smooth_scroll_ms),
            "peek.delay_ms" => Slot::Whole(&mut self.peek_delay_ms),
            "symbols.download" => Slot::Download(&mut self.symbols),
            "signatures.apply" => Slot::Bool(&mut self.signatures),
            "signatures.sweep" => Slot::Bool(&mut self.signatures_sweep),
            "updates.check" => Slot::Updates(&mut self.updates),
            "collab.relay" => Slot::Relay(&mut self.collab_relay),
            "python.interpreter" => Slot::Program(&mut self.python_interpreter),
            _ => return None,
        })
    }

    /// How a binary opened now names its library functions
    /// (`signatures.apply`, `signatures.sweep`): every pack installed.
    pub fn signature_options(&self) -> SignatureOptions {
        SignatureOptions {
            enabled: self.signatures,
            sweep: self.signatures_sweep,
            ..SignatureOptions::default()
        }
    }

    /// `style` with the C options these settings set (`c.types`,
    /// `c.declarations`, `c.names`, `c.spacing`): what a session's C is
    /// laid out in ([`crate::session::Session::set_style`]).
    pub fn c_style(&self, style: Style) -> Style {
        style
            .with_int_spelling(match self.c_types {
                CTypes::Fixed => IntSpelling::Fixed,
                CTypes::Plain => IntSpelling::Plain,
            })
            .with_declarations(self.declarations)
            .with_naming(self.names)
            .with_spacing(self.spacing)
    }
}

/// The registry entry for `key`, or `None` when it is not a setting.
pub fn info(key: &str) -> Option<&'static Info> {
    SETTINGS.iter().find(|info| info.key == key)
}

/// Whether `info` matches the settings pane's search `query`: every
/// character of the query, ignoring case and whitespace, appears in order in
/// its group, name and key. A substring therefore always matches; an empty
/// query matches everything.
pub fn matches(info: &Info, query: &str) -> bool {
    let mut haystack = info
        .group
        .chars()
        .chain(info.name.chars())
        .chain(info.key.chars())
        .flat_map(char::to_lowercase);
    query
        .chars()
        .filter(|c| !c.is_whitespace())
        .flat_map(char::to_lowercase)
        .all(|wanted| haystack.any(|c| c == wanted))
}

fn unknown(key: &str) -> String {
    format!("`{key}` is not a setting")
}

/// `value` as the shortest decimal that reads back as it, so 1.1 stays 1.1.
fn widen(value: f32) -> f64 {
    value
        .to_string()
        .parse()
        .unwrap_or_else(|_| f64::from(value))
}

/// `value` rounded to the nearest `f32`.
fn narrow(value: f64) -> f32 {
    value.to_string().parse().unwrap_or(f32::NAN)
}

fn whole(value: f64) -> Result<u32, String> {
    value
        .to_string()
        .parse()
        .map_err(|_| format!("expected a whole number, found {value}"))
}

fn in_range(info: &Info, value: f64) -> Result<f64, String> {
    match info.kind {
        Kind::Number { min, max, .. } => {
            if (min..=max).contains(&value) {
                Ok(value)
            } else {
                Err(format!(
                    "expected a number from {min} to {max}, found {value}"
                ))
            }
        }
        Kind::Toggle
        | Kind::Choice(_)
        | Kind::Font { .. }
        | Kind::Theme { .. }
        | Kind::Program
        | Kind::Relay => Ok(value),
    }
}

fn describe(value: &Setting) -> String {
    match value {
        Setting::Bool(value) => value.to_string(),
        Setting::Number(value) => value.to_string(),
        Setting::Text(value) => format!("{value:?}"),
    }
}

fn expect_bool(value: &Setting) -> Result<bool, String> {
    match value {
        Setting::Bool(value) => Ok(*value),
        Setting::Number(_) | Setting::Text(_) => {
            Err(format!("expected true or false, found {}", describe(value)))
        }
    }
}

fn expect_number(value: &Setting) -> Result<f64, String> {
    match value {
        Setting::Number(value) => Ok(*value),
        Setting::Bool(_) | Setting::Text(_) => {
            Err(format!("expected a number, found {}", describe(value)))
        }
    }
}

fn expect_text(value: &Setting) -> Result<&str, String> {
    match value {
        Setting::Text(value) => Ok(value),
        Setting::Bool(_) | Setting::Number(_) => {
            Err(format!("expected a string, found {}", describe(value)))
        }
    }
}

fn choose<T>(info: &Info, value: &Setting, from_name: fn(&str) -> Option<T>) -> Result<T, String> {
    let text = expect_text(value)?;
    from_name(text).ok_or_else(|| format!("expected {}, found {text:?}", choices(info)))
}

/// "one of "dark", "light", "system"" for a choice.
fn choices(info: &Info) -> String {
    match info.kind {
        Kind::Choice(names) => {
            let quoted: Vec<String> = names.iter().map(|name| format!("{name:?}")).collect();
            format!("one of {}", quoted.join(", "))
        }
        Kind::Toggle
        | Kind::Number { .. }
        | Kind::Font { .. }
        | Kind::Theme { .. }
        | Kind::Program
        | Kind::Relay => "a valid value".to_owned(),
    }
}

/// The table part of a key: `font` for `font.code`.
fn table_of(key: &str) -> &str {
    key.split_once('.').map_or(key, |(table, _)| table)
}

/// The name part of a key: `code` for `font.code`.
fn name_of(key: &str) -> &str {
    key.split_once('.').map_or(key, |(_, name)| name)
}

/// A setting or a binding the file could not use, or that binbun does not
/// know.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Problem {
    /// The key it is about: `window.theme`, `keys.go.anywhere`, or a table
    /// name for a whole table.
    pub key: String,
    /// What is wrong, in one line.
    pub message: String,
}

/// The settings file as a TOML document that keeps the user's formatting.
#[derive(Clone, Debug, Default)]
pub struct File {
    doc: DocumentMut,
}

impl File {
    /// Parses `text` into the file, the settings it gives and its problems.
    /// A missing key has its default. A value of the wrong type, out of range
    /// or not one of its choices keeps its default and is reported. Unknown
    /// keys and tables are reported and kept in the document.
    ///
    /// # Errors
    ///
    /// The parser's message when `text` is not TOML.
    pub fn parse(text: &str) -> Result<(File, Settings, Vec<Problem>), String> {
        let doc = text
            .parse::<DocumentMut>()
            .map_err(|error| error.to_string())?;
        let file = Self { doc };
        let (settings, problems) = file.read();
        Ok((file, settings, problems))
    }

    fn read(&self) -> (Settings, Vec<Problem>) {
        let mut settings = Settings::default();
        let mut problems = Vec::new();
        for (group, item) in self.doc.as_table() {
            if group == KEYS {
                read_keys(item, &mut settings.keys, &mut problems);
            } else {
                read_group(group, item, &mut settings, &mut problems);
            }
        }
        (settings, problems)
    }

    /// Sets `key` to `value`, checked as [`Settings::set`] checks it. An
    /// existing value is replaced in place, keeping its comments; a missing
    /// key is appended to its table, and a missing table is appended to the
    /// document. Everything else stays as written.
    ///
    /// # Errors
    ///
    /// A message when `key` is not in [`SETTINGS`] or `value` is not valid
    /// for it; the document is then unchanged.
    pub fn set(&mut self, key: &str, value: &Setting) -> Result<(), String> {
        let info = info(key).ok_or_else(|| unknown(key))?;
        let mut checked = Settings::default();
        checked.set(key, value)?;
        let value = checked.get(key).ok_or_else(|| unknown(key))?;
        write_item(
            &mut self.doc,
            table_of(key),
            name_of(key),
            toml_value(info, &value),
        );
        Ok(())
    }

    /// Removes `key` from the document, so it has its default again. Its
    /// table stays. Does nothing for a key not in [`SETTINGS`].
    pub fn reset(&mut self, key: &str) {
        if info(key).is_some() {
            remove_item(&mut self.doc, table_of(key), name_of(key));
        }
    }

    /// Binds command `id` to `keys` in `[keys]`: a string for one
    /// keystroke, an array otherwise (an empty array unbinds). Kept in
    /// place like [`File::set`]; `[keys]` is appended when missing.
    pub fn set_keys(&mut self, id: &str, keys: &[String]) {
        let value = match keys {
            [key] => Value::from(key.as_str()),
            _ => Value::Array(keys.iter().map(String::as_str).collect()),
        };
        write_item(&mut self.doc, KEYS, id, value);
    }

    /// Removes command `id` from `[keys]`, so it has its default bindings.
    pub fn reset_keys(&mut self, id: &str) {
        remove_item(&mut self.doc, KEYS, id);
    }

    /// The document as text.
    pub fn text(&self) -> String {
        self.doc.to_string()
    }

    /// The defaults as a commented file: every setting under its table, in
    /// registry order, with its description as a comment above it, then an
    /// empty `[keys]` table with a commented example. Parses to
    /// `Settings::default()` with no problems.
    pub fn defaults_text() -> String {
        let defaults = Settings::default();
        let mut text = String::from(
            "# binbun settings, applied as soon as this file is saved.\n\
             # A setting left out has its default.\n",
        );
        let mut table = "";
        for info in SETTINGS {
            if table_of(info.key) == table {
                text.push('\n');
            } else {
                table = table_of(info.key);
                let _ = write!(text, "\n[{table}]\n");
            }
            let Some(value) = defaults.get(info.key) else {
                continue;
            };
            let value = toml_value(info, &value);
            let hint = match info.kind {
                Kind::Choice(names) => {
                    let quoted: Vec<String> =
                        names.iter().map(|name| format!("{name:?}")).collect();
                    format!("  # {}", quoted.join(" | "))
                }
                Kind::Number { min, max, .. } => format!("  # {min} to {max}"),
                Kind::Relay => "  # \"binbun\" | \"n0\" | a relay's URL".to_owned(),
                Kind::Toggle | Kind::Font { .. } | Kind::Theme { .. } | Kind::Program => {
                    String::new()
                }
            };
            let _ = write!(
                text,
                "# {}\n{} = {value}{hint}\n",
                info.tooltip,
                name_of(info.key)
            );
        }
        text.push_str(
            "\n# Key bindings: a command id and a keystroke or a list of keystrokes;\n\
             # an empty list unbinds the command. ctrl- is Ctrl everywhere, cmd- is\n\
             # Cmd, secondary- is Cmd on macOS and Ctrl elsewhere.\n\
             [keys]\n\
             # \"go.anywhere\" = \"g\"\n",
        );
        text
    }
}

/// Reads one table of settings into `settings`, reporting what it cannot
/// use.
fn read_group(group: &str, item: &Item, settings: &mut Settings, problems: &mut Vec<Problem>) {
    if !SETTINGS.iter().any(|info| table_of(info.key) == group) {
        let message = if item.is_table_like() {
            "unknown table, kept as written"
        } else {
            "unknown setting, kept as written"
        };
        problems.push(Problem {
            key: group.to_owned(),
            message: message.to_owned(),
        });
        return;
    }
    let Some(table) = item.as_table_like() else {
        problems.push(Problem {
            key: group.to_owned(),
            message: format!("expected a table, found {}", item.type_name()),
        });
        return;
    };
    for (name, item) in table.iter() {
        let key = format!("{group}.{name}");
        let result = match info(&key) {
            Some(info) => setting_of(info, item).and_then(|value| settings.set(&key, &value)),
            None => Err("unknown setting, kept as written".to_owned()),
        };
        if let Err(message) = result {
            problems.push(Problem { key, message });
        }
    }
}

/// Reads `[keys]` into `keys`, skipping and reporting entries that are not
/// a string or an array of strings.
fn read_keys(item: &Item, keys: &mut BTreeMap<String, Vec<String>>, problems: &mut Vec<Problem>) {
    let Some(table) = item.as_table_like() else {
        problems.push(Problem {
            key: KEYS.to_owned(),
            message: format!("expected a table, found {}", item.type_name()),
        });
        return;
    };
    for (id, item) in table.iter() {
        match keystrokes(item) {
            Ok(strokes) => {
                keys.insert(id.to_owned(), strokes);
            }
            Err(message) => problems.push(Problem {
                key: format!("{KEYS}.{id}"),
                message,
            }),
        }
    }
}

fn keystrokes(item: &Item) -> Result<Vec<String>, String> {
    let expected = || {
        format!(
            "expected a keystroke or a list of keystrokes, found {}",
            item.type_name()
        )
    };
    let value = item.as_value().ok_or_else(expected)?;
    if let Some(stroke) = value.as_str() {
        return Ok(vec![stroke.to_owned()]);
    }
    let strokes = value.as_array().ok_or_else(expected)?;
    strokes
        .iter()
        .map(|stroke| {
            stroke.as_str().map(str::to_owned).ok_or_else(|| {
                format!(
                    "expected a list of keystrokes, found {} in it",
                    stroke.type_name()
                )
            })
        })
        .collect()
}

/// A TOML item as a value for `info`, checking only its TOML type.
fn setting_of(info: &Info, item: &Item) -> Result<Setting, String> {
    let value = item.as_value();
    let (setting, expected) = match info.kind {
        Kind::Toggle => (
            value.and_then(Value::as_bool).map(Setting::Bool),
            "true or false",
        ),
        Kind::Choice(_) => (
            value
                .and_then(Value::as_str)
                .map(|text| Setting::Text(text.to_owned())),
            "a string",
        ),
        Kind::Font { .. } => (
            value
                .and_then(Value::as_str)
                .map(|text| Setting::Text(text.to_owned())),
            "a font name",
        ),
        Kind::Theme { .. } => (
            value
                .and_then(Value::as_str)
                .map(|text| Setting::Text(text.to_owned())),
            "a theme name",
        ),
        Kind::Program => (
            value
                .and_then(Value::as_str)
                .map(|text| Setting::Text(text.to_owned())),
            "a program",
        ),
        Kind::Relay => (
            value
                .and_then(Value::as_str)
                .map(|text| Setting::Text(text.to_owned())),
            "a string",
        ),
        Kind::Number { .. } if WHOLE.contains(&info.key) => (
            value
                .and_then(Value::as_integer)
                .map(|number| Setting::Number(integer(number))),
            "a whole number",
        ),
        Kind::Number { .. } => (
            value.and_then(|value| {
                value
                    .as_float()
                    .or_else(|| value.as_integer().map(integer))
                    .map(Setting::Number)
            }),
            "a number",
        ),
    };
    setting.ok_or_else(|| format!("expected {expected}, found {}", item.type_name()))
}

/// `value` as the nearest `f64`.
fn integer(value: i64) -> f64 {
    value.to_string().parse().unwrap_or(f64::NAN)
}

/// A checked value as TOML: whole numbers of settings with whole steps as
/// integers, other numbers as floats.
fn toml_value(info: &Info, value: &Setting) -> Value {
    match value {
        Setting::Bool(value) => Value::from(*value),
        Setting::Text(value) => Value::from(value.as_str()),
        Setting::Number(number) => {
            let whole_steps = match info.kind {
                Kind::Number { step, .. } => step >= 1.0,
                Kind::Toggle
                | Kind::Choice(_)
                | Kind::Font { .. }
                | Kind::Theme { .. }
                | Kind::Program
                | Kind::Relay => true,
            };
            match number.to_string().parse::<i64>() {
                Ok(integer) if whole_steps => Value::from(integer),
                Ok(_) | Err(_) => Value::from(*number),
            }
        }
    }
}

/// The table `name` at the document's root, appended when missing and
/// replacing a value that is not a table.
fn group_mut<'a>(doc: &'a mut DocumentMut, name: &str) -> Option<&'a mut dyn TableLike> {
    let item = doc
        .as_table_mut()
        .entry(name)
        .or_insert_with(|| Item::Table(Table::new()));
    if !item.is_table_like() {
        *item = Item::Table(Table::new());
    }
    item.as_table_like_mut()
}

/// Sets `name` in table `group` to `value`: in place, keeping the old
/// value's comment, or appended to the table.
fn write_item(doc: &mut DocumentMut, group: &str, name: &str, mut value: Value) {
    let Some(table) = group_mut(doc, group) else {
        return;
    };
    match table.get_mut(name) {
        Some(item) => {
            if let Some(old) = item.as_value() {
                *value.decor_mut() = old.decor().clone();
            }
            *item = Item::Value(value);
        }
        None => {
            table.insert(name, Item::Value(value));
        }
    }
}

fn remove_item(doc: &mut DocumentMut, group: &str, name: &str) {
    if let Some(table) = doc
        .as_table_mut()
        .get_mut(group)
        .and_then(Item::as_table_like_mut)
    {
        table.remove(name);
    }
}

/// The settings file's path ([`binbun_paths::Place::Settings`]); `None`
/// without binbun's configuration directory.
pub fn path() -> Option<PathBuf> {
    binbun_paths::Place::Settings.path()
}

/// Loads the file at `path`. A missing file gives an empty [`File`], the
/// defaults and no problems.
///
/// # Errors
///
/// A message naming `path` when it cannot be read or is not TOML.
pub fn load(path: &Path) -> Result<(File, Settings, Vec<Problem>), String> {
    match fs::read_to_string(path) {
        Ok(text) => File::parse(&text).map_err(|error| format!("{}: {error}", path.display())),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            Ok((File::default(), Settings::default(), Vec::new()))
        }
        Err(error) => Err(format!("{}: {error}", path.display())),
    }
}

/// Writes `file` to `path` so a crash leaves either the old or the new
/// file: into a temporary file beside it, synced, then renamed over it.
/// Creates the directory when missing.
///
/// # Errors
///
/// A message naming `path` when the directory or the file cannot be
/// written; the temporary file is removed.
pub fn save(path: &Path, file: &File) -> Result<(), String> {
    crash_safe::write(path, file.text().as_bytes())
        .map_err(|error| format!("{}: {error}", path.display()))
}

/// A file's modification time and length, or `None` when it does not exist.
type Stamp = Option<(Option<SystemTime>, u64)>;

fn stamp(path: &Path) -> Stamp {
    fs::metadata(path)
        .ok()
        .map(|metadata| (metadata.modified().ok(), metadata.len()))
}

/// Polls a file for changes by its modification time and length, for live
/// reload without a watcher thread.
#[derive(Debug)]
pub struct Watch {
    path: PathBuf,
    last: Stamp,
}

impl Watch {
    /// Watches `path`, recording its current stamp.
    pub fn new(path: PathBuf) -> Self {
        let last = stamp(&path);
        Self { path, last }
    }

    /// Whether the file appeared, disappeared or changed since the last
    /// call, [`Watch::new`] or [`Watch::mark`]; records the new stamp.
    pub fn changed(&mut self) -> bool {
        let now = stamp(&self.path);
        if now == self.last {
            false
        } else {
            self.last = now;
            true
        }
    }

    /// Records the current stamp, so our own save is not seen as a change.
    pub fn mark(&mut self) {
        self.last = stamp(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn c_types_sets_how_the_c_spells_integers() {
        let mut settings = Settings::default();
        assert_eq!(
            settings.get("c.types"),
            Some(Setting::Text("fixed".to_owned()))
        );
        assert_eq!(
            settings.c_style(Style::kr()).int_spelling,
            IntSpelling::Fixed
        );
        settings
            .set("c.types", &Setting::Text("plain".to_owned()))
            .unwrap();
        // Plain spelling; the rest of the style is the session's.
        assert_eq!(
            settings.c_style(Style::llvm()),
            Style::llvm().with_int_spelling(IntSpelling::Plain)
        );
    }

    #[test]
    fn c_declarations_sets_where_the_c_declares_locals() {
        let mut settings = Settings::default();
        assert_eq!(
            settings.get("c.declarations"),
            Some(Setting::Text("scoped".to_owned()))
        );
        settings
            .set("c.declarations", &Setting::Text("top".to_owned()))
            .unwrap();
        // At the top; the rest of the style is the session's.
        assert_eq!(
            settings.c_style(Style::llvm()),
            Style::llvm().with_declarations(Placement::Top)
        );
    }

    #[test]
    fn c_names_sets_how_the_c_names_variables() {
        let mut settings = Settings::default();
        assert_eq!(
            settings.get("c.names"),
            Some(Setting::Text("numbered".to_owned()))
        );
        settings
            .set("c.names", &Setting::Text("registers".to_owned()))
            .unwrap();
        // By register; the rest of the style is the session's.
        assert_eq!(
            settings.c_style(Style::llvm()),
            Style::llvm().with_naming(Naming::Registers)
        );
        assert!(
            settings
                .set("c.names", &Setting::Text("ida".to_owned()))
                .is_err()
        );
    }

    const USER: &str = "\
# my settings

[font]
# the face I like
code = \"Lilex\"  # monospace
ui_size = 13

# scrolling below
[scrolling]
smooth = false
";

    /// A valid value of `info` different from its default.
    fn other(info: &Info) -> Setting {
        match info.kind {
            Kind::Toggle => {
                let Some(Setting::Bool(value)) = Settings::default().get(info.key) else {
                    panic!("{} is not a bool", info.key);
                };
                Setting::Bool(!value)
            }
            Kind::Number { min, max, .. } => {
                if Settings::default().get(info.key) == Some(Setting::Number(max)) {
                    Setting::Number(min)
                } else {
                    Setting::Number(max)
                }
            }
            Kind::Choice(names) => Setting::Text((*names.last().unwrap()).to_owned()),
            Kind::Font { .. } => Setting::Text("Lilex".to_owned()),
            Kind::Theme { .. } => Setting::Text("Nord".to_owned()),
            Kind::Program => Setting::Text("/usr/bin/python3.14".to_owned()),
            Kind::Relay => Setting::Text("https://relay.example.org".to_owned()),
        }
    }

    #[test]
    fn set_keeps_comments_blank_lines_and_order() {
        let (mut file, settings, problems) = File::parse(USER).unwrap();
        assert!(problems.is_empty(), "{problems:?}");
        assert_eq!(settings.code_font, "Lilex");
        assert!(!settings.smooth_scroll);

        file.set("font.code", &Setting::Text("Iosevka".to_owned()))
            .unwrap();
        file.set("font.ligatures", &Setting::Bool(true)).unwrap();
        file.set("peek.delay_ms", &Setting::Number(500.0)).unwrap();
        let text = file.text();
        assert!(
            text.starts_with(
                "# my settings\n\n[font]\n# the face I like\ncode = \"Iosevka\"  # monospace\n\
                 ui_size = 13\nligatures = true\n\n# scrolling below\n[scrolling]\nsmooth = false\n"
            ),
            "{text}"
        );
        assert!(
            text.ends_with("smooth = false\n\n[peek]\ndelay_ms = 500\n"),
            "{text}"
        );

        let (_, settings, problems) = File::parse(&text).unwrap();
        assert!(problems.is_empty(), "{problems:?}");
        assert_eq!(settings.code_font, "Iosevka");
        assert!(settings.ligatures);
        assert_eq!(settings.peek_delay_ms, 500);
        assert!(!settings.smooth_scroll);

        file.reset("font.ligatures");
        file.reset("font.code");
        let text = file.text();
        assert!(!text.contains("ligatures"), "{text}");
        assert!(text.contains("[font]\n"), "{text}");
        let (_, settings, _) = File::parse(&text).unwrap();
        assert_eq!(settings.code_font, Settings::default().code_font);
    }

    #[test]
    fn unknown_and_invalid_values_are_reported_and_kept() {
        let text = "\
[font]
code_size = \"big\"
ui_size = 100
ligatures = true
shadow = 3

[window]
theme = \"blue\"

[listing]
xrefs = 2.5
symbolic = false

[mystery]
x = 1
";
        let (file, settings, problems) = File::parse(text).unwrap();
        let keys: Vec<&str> = problems.iter().map(|p| p.key.as_str()).collect();
        assert_eq!(
            keys,
            [
                "font.code_size",
                "font.ui_size",
                "font.shadow",
                "window.theme",
                "listing.xrefs",
                "mystery"
            ]
        );
        let defaults = Settings::default();
        for key in ["font.code_size", "font.ui_size"] {
            assert_eq!(settings.get(key), defaults.get(key), "{key}");
        }
        assert_eq!(settings.theme, Theme::Dark);
        assert_eq!(settings.xrefs, 2);
        assert!(settings.ligatures);
        assert!(!settings.symbolic);
        assert_eq!(file.text(), text);
        assert!(File::parse("[font\n").is_err());
    }

    #[test]
    fn defaults_text_parses_to_defaults() {
        let text = File::defaults_text();
        let (_, settings, problems) = File::parse(&text).unwrap();
        assert!(problems.is_empty(), "{problems:?}");
        assert_eq!(settings, Settings::default());
        for info in SETTINGS {
            assert!(text.contains(info.tooltip), "{}", info.key);
        }
    }

    #[test]
    fn every_setting_round_trips() {
        let (mut file, _, _) = File::parse(&File::defaults_text()).unwrap();
        let mut empty = File::default();
        let mut settings = Settings::default();
        for info in SETTINGS {
            let value = Settings::default().get(info.key).unwrap();
            let mut same = Settings::default();
            same.set(info.key, &value).unwrap();
            assert_eq!(same, Settings::default(), "{}", info.key);

            let value = other(info);
            settings.set(info.key, &value).unwrap();
            assert_eq!(settings.get(info.key), Some(value.clone()), "{}", info.key);
            file.set(info.key, &value).unwrap();
            empty.set(info.key, &value).unwrap();
        }
        assert_ne!(settings, Settings::default());
        for file in [file, empty] {
            let (_, read, problems) = File::parse(&file.text()).unwrap();
            assert!(problems.is_empty(), "{problems:?}");
            assert_eq!(read, settings);
        }
    }

    #[test]
    fn settings_set_rejects_invalid_values() {
        let mut settings = Settings::default();
        let bad = [
            ("window.scale", Setting::Number(5.0)),
            ("font.code_size", Setting::Number(f64::NAN)),
            ("listing.xrefs", Setting::Number(17.0)),
            ("listing.xrefs", Setting::Number(1.5)),
            ("window.theme", Setting::Text("blue".to_owned())),
            ("c.view", Setting::Bool(true)),
            ("c.types", Setting::Text("long".to_owned())),
            ("font.code", Setting::Text("  ".to_owned())),
            ("font.ligatures", Setting::Number(1.0)),
            ("window.nothing", Setting::Bool(true)),
        ];
        for (key, value) in &bad {
            assert!(settings.set(key, value).is_err(), "{key} = {value:?}");
            assert_eq!(settings, Settings::default(), "{key}");
        }
        let mut file = File::default();
        assert!(
            file.set("window.theme", &Setting::Text("blue".to_owned()))
                .is_err()
        );
        assert_eq!(file.text(), "");
    }

    /// `collab.relay` is binbun's by default, `n0`, or an http(s) URL with
    /// a host; anything else keeps the default and is reported.
    #[test]
    fn collab_relay_takes_binbun_n0_or_a_url() {
        let relay = |text: &str| {
            let (_, settings, problems) = File::parse(text).unwrap();
            let keys: Vec<String> = problems.into_iter().map(|p| p.key).collect();
            (settings.collab_relay, keys)
        };
        assert_eq!(relay(""), (CollabRelay::Binbun, vec![]));
        assert_eq!(
            relay("[collab]\nrelay = \"n0\"\n"),
            (CollabRelay::N0, vec![])
        );
        assert_eq!(
            relay("[collab]\nrelay = \"https://relay.example.org:8443/\"\n"),
            (
                CollabRelay::Custom("https://relay.example.org:8443/".to_owned()),
                vec![]
            )
        );
        for bad in [
            "\"none\"",
            "\"relay.example.org\"",
            "\"https://\"",
            "\"https://a b\"",
            "1",
        ] {
            let text = format!("[collab]\nrelay = {bad}\n");
            assert_eq!(
                relay(&text),
                (CollabRelay::Binbun, vec!["collab.relay".to_owned()]),
                "{bad}"
            );
        }
    }

    #[test]
    fn arrow_lanes_take_whole_numbers_from_2_to_24() {
        let lanes = |text: &str| {
            let (_, settings, problems) = File::parse(text).unwrap();
            let keys: Vec<String> = problems.into_iter().map(|p| p.key).collect();
            (settings.arrow_lanes, keys)
        };
        assert_eq!(lanes("[listing]\narrow_lanes = 4\n"), (4, vec![]));
        assert_eq!(lanes("[listing]\narrow_lanes = 2\n"), (2, vec![]));
        assert_eq!(lanes("[listing]\narrow_lanes = 24\n"), (24, vec![]));
        // Out of range, fractional or not a number: the default, reported.
        for bad in ["1", "25", "4.5", "\"4\""] {
            let text = format!("[listing]\narrow_lanes = {bad}\n");
            assert_eq!(
                lanes(&text),
                (10, vec!["listing.arrow_lanes".to_owned()]),
                "{bad}"
            );
        }
    }

    #[test]
    fn keys_parse_report_and_round_trip() {
        let text = "\
[keys]
# the palette
\"palette.open\" = \"ctrl-shift-p\"
\"go.anywhere\" = [\"g\", \"ctrl-p\"]
unbound = []
bad = 3
";
        let (mut file, settings, problems) = File::parse(text).unwrap();
        assert_eq!(
            problems.iter().map(|p| p.key.as_str()).collect::<Vec<_>>(),
            ["keys.bad"]
        );
        let strokes = |list: &[&str]| list.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
        assert_eq!(settings.keys["palette.open"], strokes(&["ctrl-shift-p"]));
        assert_eq!(settings.keys["go.anywhere"], strokes(&["g", "ctrl-p"]));
        assert_eq!(settings.keys["unbound"], strokes(&[]));
        assert!(!settings.keys.contains_key("bad"));

        file.set_keys("palette.open", &strokes(&["f1"]));
        file.set_keys("new.command", &strokes(&["a", "b"]));
        file.reset_keys("unbound");
        let text = file.text();
        assert!(
            text.starts_with("[keys]\n# the palette\n\"palette.open\" = \"f1\"\n"),
            "{text}"
        );
        assert!(text.contains("bad = 3"), "{text}");
        let (_, settings, _) = File::parse(&text).unwrap();
        assert_eq!(settings.keys["palette.open"], strokes(&["f1"]));
        assert_eq!(settings.keys["new.command"], strokes(&["a", "b"]));
        assert!(!settings.keys.contains_key("unbound"));

        let mut empty = File::default();
        empty.set_keys("go.anywhere", &strokes(&[]));
        let (_, settings, problems) = File::parse(&empty.text()).unwrap();
        assert!(problems.is_empty(), "{problems:?}");
        assert_eq!(settings.keys["go.anywhere"], strokes(&[]));
    }

    #[test]
    fn search_matches_substrings_and_subsequences() {
        let code = info("font.code").unwrap();
        assert!(matches(code, ""));
        assert!(matches(code, "code font"));
        assert!(matches(code, "FONT.CODE"));
        assert!(matches(code, "cdfnt"));
        assert!(!matches(code, "theme"));
    }

    #[test]
    fn watch_sees_writes_and_removals_but_not_marked_saves() {
        let nanos = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir =
            std::env::temp_dir().join(format!("binbun-settings-{}-{nanos}", std::process::id()));
        let path = dir.join("settings.toml");
        let (_, settings, problems) = load(&path).unwrap();
        assert_eq!(settings, Settings::default());
        assert_eq!(problems, Vec::new());

        let mut watch = Watch::new(path.clone());
        assert!(!watch.changed());
        let (file, _, _) = File::parse(&File::defaults_text()).unwrap();
        save(&path, &file).unwrap();
        assert!(watch.changed());
        assert!(!watch.changed());

        fs::write(&path, "[peek]\ndelay_ms = 0\n").unwrap();
        assert!(watch.changed());
        assert_eq!(load(&path).unwrap().1.peek_delay_ms, 0);

        fs::remove_file(&path).unwrap();
        assert!(watch.changed());
        assert!(!watch.changed());

        save(&path, &file).unwrap();
        watch.mark();
        assert!(!watch.changed());

        fs::remove_dir_all(&dir).unwrap();
    }
}
