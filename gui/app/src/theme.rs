//! Themes as CSS files: a theme sets one custom property per role of
//! [`Theme`]
//! (`binbun_gui_view::theme_css` reads them). The bundled themes are the
//! files of `gui/app/themes/`, built in; the user's are
//! `themes/*.css` beside the settings file, reloaded when saved. A file
//! may start with `@import "<theme or file>";`: what it does not set, or
//! sets wrongly, is its base's. A role still unset is the default
//! theme's (One Dark, One Light), and said so.
//!
//! The window's background:
//! [`Theme::for_window`] gives the theme the window draws with, its
//! background surfaces (title and status bars, panels, tab bars, the
//! editor, the islands' gap) carrying the opacity; text, code and
//! highlights keep theirs. Those surfaces never lie on one another while
//! translucent: a container whose children paint their own surfaces
//! paints [`Theme::under`], and what floats over them (popovers, cards,
//! fields, graph nodes) paints [`solid`] colours.
//!
//! Colours are `0xRRGGBBAA`.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{LazyLock, Mutex, PoisonError};
use std::time::SystemTime;

use binbun_gui_view::feature_map::Feature;
use binbun_gui_view::listing::Item;
use binbun_gui_view::settings::Backdrop;
use binbun_gui_view::theme_css::{self, Diagnostic, Kind, Pos, Resolver, Sheet, Value};
use gpui_kit::component::{Theme as KitTheme, ThemeMode};
use gpui_kit::{App, BoxShadow, Hsla, SharedString, WindowBackgroundAppearance, px, rgba};

/// `0xRRGGBBAA` as a GPUI colour.
pub fn hsla(c: u32) -> Hsla {
    rgba(c).into()
}

/// `c` with its alpha replaced by `alpha`.
pub fn with_alpha(c: u32, alpha: u8) -> u32 {
    (c & 0xffff_ff00) | u32::from(alpha)
}

/// The dimmer tone of `c` for a long number's alternate digit groups.
pub fn dim(c: u32) -> u32 {
    with_alpha(c, 0xa8)
}

/// `c` fully opaque: what floats over the background surfaces (popovers,
/// cards, fields, graph nodes) is drawn so, whatever the window's opacity.
pub fn solid(c: u32) -> u32 {
    c | 0xff
}

/// Defines [`Theme`], one `u32` field per role, and [`ROLES`], each
/// role's property.
macro_rules! theme {
    ($($(#[$doc:meta])* $field:ident: $css:literal,)*) => {
        /// One theme's colours, each set by its role's property in the
        /// theme file (the field's name in kebab case, `type_` being
        /// `--type`).
        #[derive(Clone, Debug, PartialEq)]
        pub struct Theme {
            /// Whether it is a dark theme (`--appearance`).
            pub dark: bool,
            /// The window background the theme asks for
            /// (`--background-appearance`), if it does.
            pub backdrop: Option<Backdrop>,
            /// Whether its background surfaces let what is behind the
            /// window show (a window's theme: [`Theme::for_window`]).
            pub translucent: bool,
            /// How strongly automatic names (`v17`, `sub_a9090`,
            /// `field_38`) are drawn, 0 to 1 (`--auto-name-alpha`,
            /// [`AUTO_NAME_ALPHA`] when unset).
            pub auto_name_alpha: f32,
            /// How strongly a cast's parentheses and type are drawn, 0 to 1
            /// (`--cast-alpha`, [`CAST_ALPHA`] when unset).
            pub cast_alpha: f32,
            $($(#[$doc])* pub $field: u32,)*
        }

        /// Every role's property, in [`Theme`]'s order.
        pub const ROLES: &[&str] = &[$($css),*];

        impl Theme {
            /// Every role transparent: what a theme is built on.
            const EMPTY: Self = Self {
                dark: true,
                backdrop: None,
                translucent: false,
                auto_name_alpha: AUTO_NAME_ALPHA,
                cast_alpha: CAST_ALPHA,
                $($field: 0,)*
            };

            /// The colour of the role whose property is `css`.
            pub fn by_name(&self, css: &str) -> Option<u32> {
                match css {
                    $($css => Some(self.$field),)*
                    _ => None,
                }
            }

            fn by_name_mut(&mut self, css: &str) -> Option<&mut u32> {
                match css {
                    $($css => Some(&mut self.$field),)*
                    _ => None,
                }
            }
        }
    };
}

theme! {
    /// Title and status bars.
    background: "--background",
    /// The window behind the islands.
    gap: "--gap",
    /// The tab bar under the inactive tabs.
    tab_bar: "--tab-bar",
    /// Sidebars, tab rows, popovers, cards.
    panel: "--panel",
    /// The editor's background.
    editor: "--editor",
    /// The main hairlines.
    border: "--border",
    /// The subtler hairlines.
    border_variant: "--border-variant",
    /// The focused element's border.
    border_focused: "--border-focused",
    /// A row or button under the pointer.
    element_hover: "--element-hover",
    /// A selected row or button.
    element_selected: "--element-selected",
    /// The scrollbar's thumb.
    scrollbar_thumb: "--scrollbar-thumb",
    /// The scrollbar track's edge.
    scrollbar_track_border: "--scrollbar-track-border",
    /// The interface's text.
    text: "--text",
    /// Secondary text.
    text_muted: "--text-muted",
    /// Placeholders and what is disabled.
    text_placeholder: "--text-placeholder",
    /// Links, the caret, matched characters.
    accent: "--accent",
    /// The editor's text.
    editor_foreground: "--editor-foreground",
    /// Line numbers.
    line_number: "--line-number",
    /// The cursor line's number.
    active_line_number: "--active-line-number",
    /// Errors.
    error: "--error",
    /// What went well (an IR stage's added lines).
    success: "--success",
    /// The cursor's line.
    active_line: "--active-line",
    /// The selection.
    selection: "--selection",
    /// Search matches.
    search_match: "--search-match",
    /// The current match: the landing pulse.
    active_match: "--active-match",
    /// The branch arrows not touching the cursor.
    arrow: "--arrow",
    /// Keywords.
    keyword: "--keyword",
    /// Types and operators.
    type_: "--type",
    /// Functions.
    function: "--function",
    /// Parameters and stack variables.
    parameter: "--parameter",
    /// String literals.
    string: "--string",
    /// Numbers.
    number: "--number",
    /// Constants and data names.
    constant: "--constant",
    /// Comments.
    comment: "--comment",
    /// Documentation comments.
    comment_doc: "--comment-doc",
    /// The listing's comments, import names.
    hint: "--hint",
    /// Punctuation.
    punctuation: "--punctuation",
    /// Special punctuation, relocations.
    punctuation_special: "--punctuation-special",
    /// Plain code text.
    embedded: "--embedded",
    /// Variables.
    variable: "--variable",
    /// Labels.
    label: "--label",
    /// The listing's mnemonics.
    mnemonic: "--mnemonic",
    /// The listing's registers.
    register: "--register",
    /// A function line's address.
    address_function: "--address-function",
    /// A code line's address.
    address_code: "--address-code",
    /// A data line's address.
    address_data: "--address-data",
    /// An unexplored line's address.
    address_unexplored: "--address-unexplored",
    /// Code cross-reference comments.
    code_xref: "--code-xref",
    /// Data cross-reference comments.
    data_xref: "--data-xref",
    /// The first link tint.
    tint_1: "--tint-1",
    /// The second link tint.
    tint_2: "--tint-2",
    /// The third link tint.
    tint_3: "--tint-3",
    /// The fourth link tint.
    tint_4: "--tint-4",
    /// The lit area: the function under the cursor.
    lit_area: "--lit",
    /// The lit area's edge band.
    lit_band: "--lit-edge",
    /// A check that agreed (a verification, a comparison).
    agreed: "--agreed",
    /// The listing's branch arrows, first colour of eight ([`Theme::arrows`]).
    arrow_1: "--arrow-1",
    /// The second branch-arrow colour.
    arrow_2: "--arrow-2",
    /// The third branch-arrow colour.
    arrow_3: "--arrow-3",
    /// The fourth branch-arrow colour.
    arrow_4: "--arrow-4",
    /// The fifth branch-arrow colour.
    arrow_5: "--arrow-5",
    /// The sixth branch-arrow colour.
    arrow_6: "--arrow-6",
    /// The seventh branch-arrow colour.
    arrow_7: "--arrow-7",
    /// The eighth branch-arrow colour.
    arrow_8: "--arrow-8",
    /// Control-flow keywords: `if`, `else`, `for`, `while`, `do`,
    /// `switch`, `case`, `default`, `return`, `goto`, `break`, `continue`
    /// (else `--keyword`). `--keyword` is the rest: `struct`, `extern`,
    /// `static`, `unsigned`, `const`, `sizeof`…
    keyword_control: "--keyword-control",
    /// Builtin types: C's own (`int`, `char`, `void`, `bool`) and the
    /// fixed-width typedefs binbun's C writes as primitives (`int8_t` to
    /// `uint64_t`, `size_t`, `uintptr_t`, `__int128`); `--type` is the
    /// named ones (typedefs, struct, union and enum names). Else `--type`.
    type_builtin: "--type-builtin",
    /// Global variables (else `--variable`).
    global: "--global",
    /// Struct members (else `--variable`).
    field: "--field",
    /// Macros, `binbun_*` intrinsics, `__attribute__` (else `--function`).
    macro_: "--macro",
    /// Operators (else `--punctuation`).
    operator: "--operator",
    /// Jump mnemonics: `jmp`, `jcc`, `b.cond`, `cbz`… (else `--mnemonic`).
    mnemonic_jump: "--mnemonic-jump",
    /// Call mnemonics (else `--mnemonic`).
    mnemonic_call: "--mnemonic-call",
    /// Return mnemonics (else `--mnemonic`).
    mnemonic_return: "--mnemonic-return",
    /// No-op mnemonics: `nop`, `int3`, `align`, padding (else `--comment`).
    mnemonic_nop: "--mnemonic-nop",
    /// The feature map's code of functions (else `--function`).
    map_function: "--map-function",
    /// The feature map's code of library functions (else `--type`).
    map_library: "--map-library",
    /// The feature map's code outside functions (else `--error`).
    map_code: "--map-code",
    /// The feature map's data (else `--comment-doc`).
    map_data: "--map-data",
    /// The feature map's strings (else `--string`).
    map_string: "--map-string",
    /// The feature map's imports and externs (else `--keyword`).
    map_import: "--map-import",
    /// The feature map's unexplored bytes (else `--number`).
    map_unexplored: "--map-unexplored",
}

impl Theme {
    /// The listing's branch-arrow palette, `--arrow-1` to `--arrow-8`:
    /// eight distinct colours of the theme's own, each readable on the
    /// editor, neighbours far apart.
    pub fn arrows(&self) -> [u32; 8] {
        [
            self.arrow_1,
            self.arrow_2,
            self.arrow_3,
            self.arrow_4,
            self.arrow_5,
            self.arrow_6,
            self.arrow_7,
            self.arrow_8,
        ]
    }

    /// Link tint `k` (one of four).
    pub fn tint(&self, k: u8) -> u32 {
        match k % 4 {
            0 => self.tint_1,
            1 => self.tint_2,
            2 => self.tint_3,
            _ => self.tint_4,
        }
    }

    /// The feature map's colour of `feature`.
    pub fn feature(&self, feature: Feature) -> u32 {
        match feature {
            Feature::Function => self.map_function,
            Feature::Library => self.map_library,
            Feature::Code => self.map_code,
            Feature::Data => self.map_data,
            Feature::String => self.map_string,
            Feature::Import => self.map_import,
            Feature::Unexplored => self.map_unexplored,
        }
    }

    /// The lit area: the function under the cursor.
    pub fn lit(&self) -> u32 {
        self.lit_area
    }

    /// The lit area's edge band.
    pub fn lit_edge(&self) -> u32 {
        self.lit_band
    }

    /// A switch's knob and its track when off, on a dark theme (`None`:
    /// a light theme's are GPUI Kit's own): the knob the editor's colour,
    /// as it is on the accent when on; the track the text over the editor,
    /// just strong enough that the knob stands out on it by
    /// [`SWITCH_CONTRAST`] (a dark grey track under a near-black knob does
    /// not read).
    pub fn switch_off(&self) -> Option<(u32, u32)> {
        if !self.dark {
            return None;
        }
        let knob = solid(self.editor);
        let text = solid(self.text);
        let track = (0..=u8::MAX)
            .map(|alpha| over(with_alpha(text, alpha), knob))
            .find(|&track| contrast(track, knob) >= SWITCH_CONTRAST)
            .unwrap_or(text);
        Some((track, knob))
    }

    /// The wash of the listing's instructions behind the C's cursor line
    /// or selection: the selection's colour at half its strength.
    pub fn provenance(&self) -> u32 {
        with_alpha(
            self.selection,
            u8::try_from((self.selection & 0xff) / 2).unwrap_or(0),
        )
    }

    /// The colour of a container whose children paint their own
    /// surfaces: `c`, or nothing while the surfaces are translucent (it
    /// would lie under theirs).
    pub fn under(&self, c: u32) -> u32 {
        if self.translucent { 0 } else { c }
    }

    /// The shadow of a card over the panes (peek, why, reveal): GPUI's
    /// large shadow, dark enough to show on the editor's colour (a tenth of
    /// black disappears on One Dark).
    pub fn card_shadow(&self) -> Vec<BoxShadow> {
        let alpha = if self.dark { 0.45 } else { 0.18 };
        vec![
            BoxShadow::new(px(0.0), px(6.0), Hsla::black().opacity(alpha))
                .blur_radius(px(16.0))
                .spread_radius(px(-2.0)),
            BoxShadow::new(px(0.0), px(2.0), Hsla::black().opacity(alpha * 0.6))
                .blur_radius(px(4.0))
                .spread_radius(px(-1.0)),
        ]
    }

    /// The prefix's colour: by what the item is.
    pub fn prefix(&self, item: Item) -> u32 {
        match item {
            Item::Function => self.address_function,
            Item::Code => self.address_code,
            Item::Data => self.address_data,
            Item::Unexplored => self.address_unexplored,
        }
    }

    /// The background surfaces: what the window's opacity scales.
    fn surfaces_mut(&mut self) -> [&mut u32; 5] {
        [
            &mut self.background,
            &mut self.gap,
            &mut self.tab_bar,
            &mut self.panel,
            &mut self.editor,
        ]
    }

    /// The theme a window draws with, and the GPUI background it asks
    /// for: `backdrop` (the setting; [`Backdrop::Theme`] takes the
    /// theme's, else opaque) where the platform has it (Mica is blurred
    /// off Windows; GPUI itself draws blur as plain transparency where the
    /// compositor cannot blur). Opaque, the background surfaces are made
    /// opaque; otherwise their alpha is scaled by `opacity` (0 to 1).
    pub fn for_window(
        &self,
        backdrop: Backdrop,
        opacity: f32,
    ) -> (Self, WindowBackgroundAppearance) {
        let chosen = match backdrop {
            Backdrop::Theme => self.backdrop.unwrap_or(Backdrop::Opaque),
            chosen @ (Backdrop::Opaque
            | Backdrop::Transparent
            | Backdrop::Blurred
            | Backdrop::Mica
            | Backdrop::MicaAlt) => chosen,
        };
        let appearance = match chosen {
            Backdrop::Theme | Backdrop::Opaque => WindowBackgroundAppearance::Opaque,
            Backdrop::Transparent => WindowBackgroundAppearance::Transparent,
            Backdrop::Mica if cfg!(windows) => WindowBackgroundAppearance::MicaBackdrop,
            Backdrop::MicaAlt if cfg!(windows) => WindowBackgroundAppearance::MicaAltBackdrop,
            Backdrop::Blurred | Backdrop::Mica | Backdrop::MicaAlt => {
                WindowBackgroundAppearance::Blurred
            }
        };
        let mut theme = self.clone();
        let opaque = appearance == WindowBackgroundAppearance::Opaque;
        let opacity = f64::from(opacity.clamp(0.0, 1.0));
        for c in theme.surfaces_mut() {
            *c = if opaque {
                solid(*c)
            } else {
                scale_alpha(*c, opacity)
            };
        }
        theme.translucent = !opaque && theme.surfaces_mut().iter().any(|c| **c & 0xff != 0xff);
        (theme, appearance)
    }

    /// Makes GPUI Kit's components draw with the same tokens, in `ui_font`
    /// with `rem` as their rem. Its root draws nothing while the surfaces
    /// are translucent (the workspace's surfaces are the background), and
    /// its popovers and lists are opaque.
    pub fn apply(&self, ui_font: &str, rem: f32, cx: &mut App) {
        KitTheme::change(
            if self.dark {
                ThemeMode::Dark
            } else {
                ThemeMode::Light
            },
            None,
            cx,
        );
        KitTheme::update(cx, |t| {
            t.font_family = SharedString::from(ui_font.to_owned());
            t.font_size = px(rem);
            let c = &mut t.colors;
            c.background = hsla(self.under(self.editor));
            c.foreground = hsla(self.text);
            c.border = hsla(self.border);
            c.input = hsla(self.border_variant);
            c.ring = hsla(self.border_focused);
            c.caret = hsla(self.accent);
            c.selection = hsla(self.selection);
            c.accent = hsla(self.element_selected);
            c.accent_foreground = hsla(self.text);
            c.muted = hsla(solid(self.panel));
            c.muted_foreground = hsla(self.text_muted);
            c.popover = hsla(solid(self.panel));
            c.popover_foreground = hsla(self.text);
            c.list = hsla(solid(self.panel));
            c.list_hover = hsla(self.element_hover);
            c.list_active = hsla(self.element_selected);
            c.list_active_border = hsla(self.element_selected);
            c.primary = hsla(self.accent);
            c.primary_foreground = hsla(solid(self.editor));
            c.link = hsla(self.accent);
            c.danger = hsla(self.error);
            c.drag_border = hsla(self.border_focused);
            c.scrollbar = hsla(self.under(self.panel));
            c.scrollbar_thumb = hsla(self.scrollbar_thumb);
            c.title_bar = hsla(self.background);
            c.title_bar_border = hsla(self.border);
            c.secondary = hsla(solid(self.panel));
            c.secondary_hover = hsla(self.element_hover);
            c.secondary_active = hsla(self.element_selected);
            c.secondary_foreground = hsla(self.text);
            if let Some((track, knob)) = self.switch_off() {
                c.switch = hsla(track);
                c.switch_thumb = hsla(knob);
            }
        });
    }
}

/// How far a switch's knob stands out on its track when off, at least (a
/// WCAG contrast ratio: what a control's parts need).
pub const SWITCH_CONTRAST: f64 = 3.0;

/// WCAG 2's relative luminance of an opaque colour.
fn luminance(c: u32) -> f64 {
    let linear = |shift: u32| {
        let v = f64::from((c >> shift) & 0xff) / 255.0;
        if v <= 0.040_45 {
            v / 12.92
        } else {
            ((v + 0.055) / 1.055).powf(2.4)
        }
    };
    0.2126 * linear(24) + 0.7152 * linear(16) + 0.0722 * linear(8)
}

/// `fg` composited over the opaque `bg`.
fn over(fg: u32, bg: u32) -> u32 {
    let a = f64::from(fg & 0xff) / 255.0;
    let mix = |shift: u32| {
        let f = f64::from((fg >> shift) & 0xff);
        let b = f64::from((bg >> shift) & 0xff);
        #[expect(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            reason = "0..=255"
        )]
        let v = (f * a + b * (1.0 - a)).round() as u32;
        v << shift
    };
    mix(24) | mix(16) | mix(8) | 0xff
}

/// WCAG 2's contrast ratio of `fg` (composited) on `bg`.
fn contrast(fg: u32, bg: u32) -> f64 {
    let (a, b) = (luminance(over(fg, bg)), luminance(bg));
    (a.max(b) + 0.05) / (a.min(b) + 0.05)
}

/// `c` with its alpha multiplied by `factor` (0 to 1).
#[expect(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "the product is within 0..=255"
)]
fn scale_alpha(c: u32, factor: f64) -> u32 {
    let alpha = (f64::from(c & 0xff) * factor).round().clamp(0.0, 255.0) as u32;
    (c & 0xffff_ff00) | alpha
}

/// `theme` for as long as the program runs, each distinct theme once: a
/// window's views copy `&'static Theme` freely. A value cache, not a
/// lifetime escape: a theme equal to one seen before is that one, so what
/// stays allocated is one [`Theme`] (a few hundred bytes) per distinct
/// theme shown, however often themes are applied, previewed or reloaded.
pub fn intern(theme: Theme) -> &'static Theme {
    static SEEN: Mutex<Vec<&'static Theme>> = Mutex::new(Vec::new());
    let mut seen = SEEN.lock().unwrap_or_else(PoisonError::into_inner);
    if let Some(&known) = seen.iter().find(|t| ***t == theme) {
        return known;
    }
    let leaked: &'static Theme = Box::leak(Box::new(theme));
    seen.push(leaked);
    leaked
}

/// The bundled themes' files: the defaults first.
const BUNDLED: &[(&str, &str)] = &[
    ("one-dark.css", include_str!("../themes/one-dark.css")),
    ("one-light.css", include_str!("../themes/one-light.css")),
    ("dark-modern.css", include_str!("../themes/dark-modern.css")),
    (
        "light-modern.css",
        include_str!("../themes/light-modern.css"),
    ),
    ("github-dark.css", include_str!("../themes/github-dark.css")),
    (
        "github-dark-dimmed.css",
        include_str!("../themes/github-dark-dimmed.css"),
    ),
    (
        "github-light.css",
        include_str!("../themes/github-light.css"),
    ),
    (
        "catppuccin-mocha.css",
        include_str!("../themes/catppuccin-mocha.css"),
    ),
    (
        "catppuccin-macchiato.css",
        include_str!("../themes/catppuccin-macchiato.css"),
    ),
    (
        "catppuccin-frappe.css",
        include_str!("../themes/catppuccin-frappe.css"),
    ),
    (
        "catppuccin-latte.css",
        include_str!("../themes/catppuccin-latte.css"),
    ),
    (
        "gruvbox-dark.css",
        include_str!("../themes/gruvbox-dark.css"),
    ),
    (
        "gruvbox-light.css",
        include_str!("../themes/gruvbox-light.css"),
    ),
    ("nord.css", include_str!("../themes/nord.css")),
    ("dracula.css", include_str!("../themes/dracula.css")),
    ("alucard.css", include_str!("../themes/alucard.css")),
    ("tokyo-night.css", include_str!("../themes/tokyo-night.css")),
    (
        "tokyo-night-storm.css",
        include_str!("../themes/tokyo-night-storm.css"),
    ),
    (
        "tokyo-night-moon.css",
        include_str!("../themes/tokyo-night-moon.css"),
    ),
    (
        "tokyo-night-day.css",
        include_str!("../themes/tokyo-night-day.css"),
    ),
    (
        "solarized-dark.css",
        include_str!("../themes/solarized-dark.css"),
    ),
    (
        "solarized-light.css",
        include_str!("../themes/solarized-light.css"),
    ),
    ("monokai.css", include_str!("../themes/monokai.css")),
];

/// The default dark and light themes' names.
pub const DEFAULT_DARK: &str = "One Dark";
/// The default light theme's name.
pub const DEFAULT_LIGHT: &str = "One Light";

/// The `--background-appearance` keywords.
const BACKDROPS: &[&str] = &["opaque", "transparent", "blurred", "mica", "mica-alt"];

/// `--auto-name-alpha` when a theme does not set it.
pub const AUTO_NAME_ALPHA: f32 = 1.0;
/// `--cast-alpha` when a theme does not set it.
pub const CAST_ALPHA: f32 = 1.0;

/// The finer roles and the role each falls back to, silently, when a
/// theme leaves it out: so a theme sets the finer roles only where it
/// tells them apart. A no-op instruction falls back to the comment
/// colour (a theme's own colour for what matters least) rather than a
/// dimmed mnemonic, so it stays an opaque colour of the theme.
const PARENTS: &[(&str, &str)] = &[
    ("--keyword-control", "--keyword"),
    ("--type-builtin", "--type"),
    ("--global", "--variable"),
    ("--field", "--variable"),
    ("--macro", "--function"),
    ("--operator", "--punctuation"),
    ("--mnemonic-jump", "--mnemonic"),
    ("--mnemonic-call", "--mnemonic"),
    ("--mnemonic-return", "--mnemonic"),
    ("--mnemonic-nop", "--comment"),
    ("--map-function", "--function"),
    ("--map-library", "--type"),
    ("--map-code", "--error"),
    ("--map-data", "--comment-doc"),
    ("--map-string", "--string"),
    ("--map-import", "--keyword"),
    ("--map-unexplored", "--number"),
];

/// `n` (a checked fraction, 0 to 1) as an `f32`.
#[expect(clippy::cast_possible_truncation, reason = "0 to 1, checked")]
fn narrow(n: f64) -> f32 {
    n as f32
}

/// What each property must be.
fn kind(name: &str) -> Kind {
    match name {
        "--name" => Kind::Text,
        "--appearance" => Kind::Keyword(&["dark", "light"]),
        "--background-appearance" => Kind::Keyword(BACKDROPS),
        "--auto-name-alpha" | "--cast-alpha" => Kind::Fraction,
        _ if ROLES.contains(&name) => Kind::Color,
        _ => Kind::Any,
    }
}

/// The name a file gives itself (`--name`, read in the file alone),
/// else `fallback`.
fn own_name(sheet: &Sheet, fallback: &str) -> String {
    let layers = std::slice::from_ref(sheet);
    match Resolver::new(layers, kind).get("--name") {
        Some(Value::Text(name)) if !name.trim().is_empty() => name,
        _ => fallback.to_owned(),
    }
}

/// The bundled themes, parsed once: name and file.
static SHEETS: LazyLock<Vec<(String, Sheet)>> = LazyLock::new(|| {
    BUNDLED
        .iter()
        .map(|(file, text)| {
            let sheet = theme_css::parse(file, text);
            (own_name(&sheet, file), sheet)
        })
        .collect()
});

fn bundled() -> &'static [(String, Sheet)] {
    &SHEETS
}

/// The bundled themes as the picker lists them.
static LISTED: LazyLock<Vec<Listed>> = LazyLock::new(|| {
    bundled()
        .iter()
        .map(|(name, sheet)| Listed {
            name: name.clone(),
            dark: build(std::slice::from_ref(sheet), None).0.dark,
            user: false,
        })
        .collect()
});

/// A theme built from its layers, base first: every role its layers set,
/// the rest `fallback`'s; the problems, in the files and the roles unset.
fn build(layers: &[Sheet], fallback: Option<&Theme>) -> (Theme, Vec<Diagnostic>) {
    let mut resolver = Resolver::new(layers, kind);
    let appearance = resolver.get("--appearance");
    let dark = !matches!(&appearance, Some(Value::Keyword(k)) if k == "light");
    let mut theme = fallback.cloned().unwrap_or(Theme::EMPTY);
    theme.dark = dark;
    theme.backdrop = match resolver.get("--background-appearance") {
        Some(Value::Keyword(k)) => Backdrop::from_name(&k),
        _ => None,
    };
    let mut unset = Vec::new();
    for &role in ROLES {
        let value = match resolver.get(role) {
            Some(Value::Color(c)) => Some(c),
            // A finer role the file leaves out is its parent's, silently.
            Some(_) | None => PARENTS
                .iter()
                .find(|(child, _)| *child == role)
                .and_then(|&(_, parent)| theme.by_name(parent)),
        };
        match (value, theme.by_name_mut(role)) {
            (Some(c), Some(field)) => *field = c,
            (None, _) | (Some(_), None) => unset.push(role),
        }
    }
    for (name, field) in [
        ("--auto-name-alpha", &mut theme.auto_name_alpha),
        ("--cast-alpha", &mut theme.cast_alpha),
    ] {
        if let Some(Value::Number(n)) = resolver.get(name) {
            *field = narrow(n);
        }
    }
    let mut diagnostics = resolver.finish();
    if let Some(top) = layers.last() {
        let start = Pos { line: 1, column: 1 };
        let place = |message: String| Diagnostic {
            file: top.file.clone(),
            line: start.line,
            column: start.column,
            message,
        };
        if appearance.is_none() {
            diagnostics.push(place(
                "`--appearance` (dark or light) is not set; taken as dark".to_owned(),
            ));
        }
        if !unset.is_empty() {
            let default = if dark { DEFAULT_DARK } else { DEFAULT_LIGHT };
            diagnostics.push(place(format!(
                "no usable value for {}, and no imported theme gives one; {default}'s are used",
                unset.join(", ")
            )));
        }
    }
    (theme, diagnostics)
}

/// The default dark and light themes (bundled: no imports).
static DEFAULTS: LazyLock<[&'static Theme; 2]> = LazyLock::new(|| {
    [DEFAULT_DARK, DEFAULT_LIGHT].map(|name| {
        let layers: Vec<Sheet> = bundled()
            .iter()
            .filter(|(n, _)| n == name)
            .map(|(_, s)| s.clone())
            .collect();
        intern(build(&layers, None).0)
    })
});

/// The default theme of a dark or a light window.
pub fn default_theme(dark: bool) -> &'static Theme {
    let [dark_theme, light_theme] = *DEFAULTS;
    if dark { dark_theme } else { light_theme }
}

/// A theme as the picker lists it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Listed {
    /// Its name.
    pub name: String,
    /// Whether it is dark.
    pub dark: bool,
    /// Whether it is the user's (a file in the themes folder).
    pub user: bool,
}

/// A theme loaded by name.
#[derive(Debug)]
pub struct Loaded {
    /// The theme (the default one when none has the name).
    pub theme: &'static Theme,
    /// Its problems, one line each: a file's, `file:line:column: what`.
    pub problems: Vec<String>,
}

/// One of the user's theme files.
#[derive(Clone, Debug)]
struct UserTheme {
    name: String,
    path: PathBuf,
    sheet: Sheet,
}

/// A file's modification time and length.
type Stamp = (PathBuf, Option<SystemTime>, u64);

/// The bundled themes and the user's, and the user's folder watched.
#[derive(Debug)]
pub struct Themes {
    dir: Option<PathBuf>,
    user: Vec<UserTheme>,
    stamps: Vec<Stamp>,
}

/// The most `@import`s one theme may chain.
const MAX_IMPORTS: usize = 8;

impl Themes {
    /// The themes, the user's read from `dir` (`themes` beside the
    /// settings file) if there is one.
    pub fn new(dir: Option<PathBuf>) -> Self {
        let mut themes = Self {
            dir,
            user: Vec::new(),
            stamps: Vec::new(),
        };
        themes.stamps = themes.stamp();
        themes.read_user();
        themes
    }

    fn stamp(&self) -> Vec<Stamp> {
        let Some(dir) = &self.dir else {
            return Vec::new();
        };
        let mut stamps: Vec<Stamp> = fs::read_dir(dir)
            .into_iter()
            .flatten()
            .flatten()
            .map(|entry| entry.path())
            .filter(|path| path.extension().is_some_and(|e| e == "css"))
            .map(|path| {
                let meta = fs::metadata(&path).ok();
                let modified = meta.as_ref().and_then(|m| m.modified().ok());
                let len = meta.map_or(0, |m| m.len());
                (path, modified, len)
            })
            .collect();
        stamps.sort();
        stamps
    }

    fn read_user(&mut self) {
        self.user = self
            .stamps
            .iter()
            .filter_map(|(path, _, _)| {
                let text = fs::read_to_string(path).ok()?;
                let file = path.display().to_string();
                let sheet = theme_css::parse(&file, &text);
                let stem = path.file_stem()?.to_string_lossy().into_owned();
                Some(UserTheme {
                    name: own_name(&sheet, &stem),
                    path: path.clone(),
                    sheet,
                })
            })
            .collect();
    }

    /// Whether a file in the user's folder appeared, changed or went
    /// since the last call; re-reads them when so.
    pub fn changed(&mut self) -> bool {
        let now = self.stamp();
        if now == self.stamps {
            return false;
        }
        self.stamps = now;
        self.read_user();
        true
    }

    /// Every theme: the bundled ones, then the user's by name. A user's
    /// theme with a bundled one's name replaces it.
    pub fn list(&self) -> Vec<Listed> {
        let mut user: Vec<Listed> = self
            .user
            .iter()
            .map(|u| Listed {
                name: u.name.clone(),
                dark: build(&self.chain(u.sheet.clone(), u.path.parent()).0, None)
                    .0
                    .dark,
                user: true,
            })
            .collect();
        user.sort_by(|a, b| a.name.cmp(&b.name));
        let mut all: Vec<Listed> = LISTED
            .iter()
            .filter(|b| !user.iter().any(|u| u.name.eq_ignore_ascii_case(&b.name)))
            .cloned()
            .collect();
        all.append(&mut user);
        all
    }

    /// The theme named `name` (ignoring ASCII case; the user's first),
    /// else the default of a `dark` or light window, said so.
    pub fn load(&self, name: &str, dark: bool) -> Loaded {
        let found = self
            .user
            .iter()
            .find(|u| u.name.eq_ignore_ascii_case(name))
            .map(|u| (u.sheet.clone(), u.path.parent().map(Path::to_path_buf)))
            .or_else(|| {
                bundled()
                    .iter()
                    .find(|(n, _)| n.eq_ignore_ascii_case(name))
                    .map(|(_, s)| (s.clone(), None))
            });
        let Some((sheet, dir)) = found else {
            let default = if dark { DEFAULT_DARK } else { DEFAULT_LIGHT };
            return Loaded {
                theme: default_theme(dark),
                problems: vec![format!("no theme is named {name:?}; {default} is used")],
            };
        };
        let (layers, mut diagnostics) = self.chain(sheet, dir.as_deref());
        let appearance_dark = build(&layers, None).0.dark;
        let (theme, built) = build(&layers, Some(default_theme(appearance_dark)));
        diagnostics.extend(built);
        Loaded {
            theme: intern(theme),
            problems: diagnostics.iter().map(ToString::to_string).collect(),
        }
    }

    /// `top` and the themes it imports, base first, and the imports that
    /// failed. `dir` is `top`'s folder (a bundled theme has none).
    fn chain(&self, top: Sheet, dir: Option<&Path>) -> (Vec<Sheet>, Vec<Diagnostic>) {
        let mut layers = vec![top];
        let mut dirs = vec![dir.map(Path::to_path_buf)];
        let mut problems = Vec::new();
        while let Some(last) = layers.last() {
            let Some((name, pos)) = last.import.clone() else {
                break;
            };
            let file = last.file.clone();
            let place = |message: String| Diagnostic {
                file: file.clone(),
                line: pos.line,
                column: pos.column,
                message,
            };
            if layers.len() > MAX_IMPORTS {
                problems.push(place(format!("more than {MAX_IMPORTS} imports in a row")));
                break;
            }
            let from = dirs.last().cloned().flatten();
            let Some((sheet, next_dir)) = self.import(&name, from.as_deref()) else {
                problems.push(place(format!(
                    "`@import \"{name}\"`: no bundled theme, theme or file has that name"
                )));
                break;
            };
            if layers.iter().any(|l| l.file == sheet.file) {
                problems.push(place(format!("`@import \"{name}\"` imports itself")));
                break;
            }
            layers.push(sheet);
            dirs.push(next_dir);
        }
        layers.reverse();
        (layers, problems)
    }

    /// The theme `@import "name"` means: a `.css` file (beside the
    /// importing one, or absolute), else a bundled theme, else a user's.
    fn import(&self, name: &str, dir: Option<&Path>) -> Option<(Sheet, Option<PathBuf>)> {
        if Path::new(name).extension().is_some_and(|e| e == "css") {
            let path = match dir {
                Some(dir) => dir.join(name),
                None => PathBuf::from(name),
            };
            let text = fs::read_to_string(&path).ok()?;
            let sheet = theme_css::parse(&path.display().to_string(), &text);
            return Some((sheet, path.parent().map(Path::to_path_buf)));
        }
        if let Some((_, sheet)) = bundled().iter().find(|(n, _)| n.eq_ignore_ascii_case(name)) {
            return Some((sheet.clone(), None));
        }
        self.user
            .iter()
            .find(|u| u.name.eq_ignore_ascii_case(name))
            .map(|u| (u.sheet.clone(), u.path.parent().map(Path::to_path_buf)))
    }
}

#[cfg(test)]
mod tests;
