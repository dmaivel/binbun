use std::fmt::Write as _;
use std::fs;
use std::path::PathBuf;

use binbun_gui_view::settings::{Backdrop, Settings, Theme as Mode};

use super::*;
use crate::hex_view::BAND;

/// The bundled themes, by name, and whether each is dark.
const NAMES: &[(&str, bool)] = &[
    ("One Dark", true),
    ("One Light", false),
    ("Dark Modern", true),
    ("Light Modern", false),
    ("GitHub Dark", true),
    ("GitHub Dark Dimmed", true),
    ("GitHub Light", false),
    ("Catppuccin Mocha", true),
    ("Catppuccin Macchiato", true),
    ("Catppuccin Frappé", true),
    ("Catppuccin Latte", false),
    ("Gruvbox Dark", true),
    ("Gruvbox Light", false),
    ("Nord", true),
    ("Dracula", true),
    ("Alucard", false),
    ("Tokyo Night", true),
    ("Tokyo Night Storm", true),
    ("Tokyo Night Moon", true),
    ("Tokyo Night Day", false),
    ("Solarized Dark", true),
    ("Solarized Light", false),
    ("Monokai", true),
];

#[test]
fn every_bundled_theme_loads_without_problems() {
    let themes = Themes::new(None);
    let listed: Vec<(String, bool)> = themes
        .list()
        .into_iter()
        .map(|l| (l.name, l.dark))
        .collect();
    let wanted: Vec<(String, bool)> = NAMES.iter().map(|&(n, d)| (n.to_owned(), d)).collect();
    assert_eq!(listed, wanted);
    for &(name, dark) in NAMES {
        let loaded = themes.load(name, !dark);
        assert!(loaded.problems.is_empty(), "{name}: {:#?}", loaded.problems);
        assert_eq!(loaded.theme.dark, dark, "{name}");
        // Every role set by the file: none left as built on.
        let alone = build(
            &themes
                .chain(
                    bundled()
                        .iter()
                        .find(|(n, _)| n == name)
                        .map(|(_, s)| s.clone())
                        .unwrap(),
                    None,
                )
                .0,
            None,
        );
        assert!(alone.1.is_empty(), "{name}: {:#?}", alone.1);
        assert_eq!(&alone.0, loaded.theme, "{name}");
    }
}

/// One Dark and One Light as binbun drew them before themes were files:
/// its constants, and the roles it derived from them.
#[expect(
    clippy::too_many_lines,
    reason = "two themes' constants, one line each"
)]
fn before(dark: bool) -> Vec<(&'static str, u32)> {
    let (one, players, panel): (Vec<(&str, u32)>, [u32; 4], u32) = if dark {
        (
            vec![
                ("--background", 0x3b41_4dff),
                ("--gap", 0x2125_2bff),
                ("--tab-bar", 0x2125_2bff),
                ("--panel", 0x2f34_3eff),
                ("--editor", 0x282c_33ff),
                ("--border", 0x464b_57ff),
                ("--border-variant", 0x363c_46ff),
                ("--border-focused", 0x4767_9eff),
                ("--element-hover", 0x363c_46ff),
                ("--element-selected", 0x454a_56ff),
                ("--text", 0xdce0_e5ff),
                ("--text-muted", 0xa9af_bcff),
                ("--text-placeholder", 0x878a_98ff),
                ("--accent", 0x74ad_e8ff),
                ("--editor-foreground", 0xacb2_beff),
                ("--line-number", 0x4e5a_5fff),
                ("--active-line-number", 0xd0d4_daff),
                ("--active-line", 0x2f34_3ebf),
                ("--selection", 0x74ad_e83d),
                ("--search-match", 0x74ad_e866),
                ("--active-match", 0xe8af_7466),
                ("--scrollbar-thumb", 0xc8cc_d44c),
                ("--scrollbar-track-border", 0x2e33_3cff),
                ("--error", 0xd072_77ff),
                ("--success", 0xa1c1_81ff),
                ("--arrow", 0xb157_4bff),
                ("--keyword", 0xb477_cfff),
                ("--type", 0x6eb4_bfff),
                ("--function", 0x73ad_e9ff),
                ("--parameter", 0xd072_77ff),
                ("--string", 0xa1c1_81ff),
                ("--number", 0xbf95_6aff),
                ("--constant", 0xdfc1_84ff),
                ("--comment", 0x5d63_6fff),
                ("--comment-doc", 0x878e_98ff),
                ("--hint", 0x788c_a6ff),
                ("--punctuation", 0xb2b9_c6ff),
                ("--punctuation-special", 0xb157_4bff),
                ("--embedded", 0xdce0_e5ff),
                ("--variable", 0xacb2_beff),
                ("--label", 0x74ad_e8ff),
            ],
            [0x74ad_e8ff, 0xb477_cfff, 0xdec1_84ff, 0xa1c1_81ff],
            0x2f34_3eff,
        )
    } else {
        (
            vec![
                ("--background", 0xdcdc_ddff),
                ("--gap", 0xdcdc_ddff),
                ("--tab-bar", 0xebeb_ecff),
                ("--panel", 0xebeb_ecff),
                ("--editor", 0xfafa_faff),
                ("--border", 0xc9c9_caff),
                ("--border-variant", 0xdfdf_e0ff),
                ("--border-focused", 0x7d82_e8ff),
                ("--element-hover", 0xdfdf_e0ff),
                ("--element-selected", 0xcaca_caff),
                ("--text", 0x2425_29ff),
                ("--text-muted", 0x5858_5aff),
                ("--text-placeholder", 0x7e80_86ff),
                ("--accent", 0x5c78_e2ff),
                ("--editor-foreground", 0x2425_29ff),
                ("--line-number", 0xb4b4_bbff),
                ("--active-line-number", 0x4445_4bff),
                ("--active-line", 0xebeb_ecbf),
                ("--selection", 0x5c78_e23d),
                ("--search-match", 0x5c79_e266),
                ("--active-match", 0xd0a9_2366),
                ("--scrollbar-thumb", 0x383a_414c),
                ("--scrollbar-track-border", 0xeeee_eeff),
                ("--error", 0xd361_51ff),
                ("--success", 0x669f_59ff),
                ("--arrow", 0xa488_19ff),
                ("--keyword", 0xa449_abff),
                ("--type", 0x3882_b7ff),
                ("--function", 0x5b79_e3ff),
                ("--parameter", 0xd360_4fff),
                ("--string", 0x649f_57ff),
                ("--number", 0xad6e_25ff),
                ("--constant", 0xc184_01ff),
                ("--comment", 0xa2a3_a7ff),
                ("--comment-doc", 0x7c7e_86ff),
                ("--hint", 0x7274_a7ff),
                ("--punctuation", 0x4d4f_52ff),
                ("--punctuation-special", 0xb92b_46ff),
                ("--embedded", 0x2425_29ff),
                ("--variable", 0x2425_29ff),
                ("--label", 0x5c78_e2ff),
            ],
            [0x5c78_e2ff, 0xa349_abff, 0xa488_19ff, 0x669f_59ff],
            0xebeb_ecff,
        )
    };
    let of = |role: &str| one.iter().find(|(r, _)| *r == role).map_or(0, |(_, c)| *c);
    // The roles binbun derived: `Theme::role`, `prefix`, `tint`, `lit`,
    // `lit_edge` and the verification chip as they were.
    let derived = [
        ("--mnemonic", of("--embedded")),
        ("--register", of("--type")),
        ("--address-function", of("--comment")),
        ("--address-code", of("--parameter")),
        ("--address-data", of("--comment-doc")),
        ("--address-unexplored", of("--constant")),
        ("--code-xref", of("--punctuation-special")),
        ("--data-xref", of("--comment-doc")),
        ("--tint-1", with_alpha(players[0], 0x30)),
        ("--tint-2", with_alpha(players[1], 0x30)),
        ("--tint-3", with_alpha(players[2], 0x30)),
        ("--tint-4", with_alpha(players[3], 0x30)),
        ("--lit", with_alpha(panel, 0x80)),
        ("--lit-edge", of("--border-focused")),
        ("--agreed", of("--success")),
    ];
    one.iter().copied().chain(derived).collect()
}

#[test]
fn one_dark_and_one_light_are_as_before() {
    let themes = Themes::new(None);
    for (name, dark) in [("One Dark", true), ("One Light", false)] {
        let theme = themes.load(name, dark).theme;
        let expected = before(dark);
        // Every role but the branch-arrow palette and the finer roles
        // (new with theme files).
        assert_eq!(expected.len() + 8 + PARENTS.len(), ROLES.len());
        for (role, colour) in expected {
            assert_eq!(theme.by_name(role), Some(colour), "{name} {role}");
        }
        assert_eq!(theme.dark, dark);
        // Opaque, the window draws them unchanged.
        let (window, appearance) = theme.for_window(Backdrop::Theme, 1.0);
        assert_eq!(&window, theme);
        assert_eq!(appearance, WindowBackgroundAppearance::Opaque);
    }
}

const BODY: &[&str] = &["--text", "--editor-foreground"];
const CODE: &[&str] = &[
    "--keyword",
    "--type",
    "--function",
    "--parameter",
    "--string",
    "--number",
    "--constant",
    "--comment",
    "--comment-doc",
    "--hint",
    "--punctuation",
    "--punctuation-special",
    "--embedded",
    "--variable",
    "--label",
    "--mnemonic",
    "--register",
    "--address-function",
    "--address-code",
    "--address-data",
    "--address-unexplored",
    "--code-xref",
    "--data-xref",
    "--arrow-1",
    "--arrow-2",
    "--arrow-3",
    "--arrow-4",
    "--arrow-5",
    "--arrow-6",
    "--arrow-7",
    "--arrow-8",
    "--keyword-control",
    "--type-builtin",
    "--global",
    "--field",
    "--macro",
    "--operator",
    "--mnemonic-jump",
    "--mnemonic-call",
    "--mnemonic-return",
    "--mnemonic-nop",
];

/// Where an upstream theme's own colours fall short, measured: theme,
/// role, ratio against its editor. binbun keeps upstream colours as they
/// are (One Dark and One Light as binbun drew them before, its address
/// roles included: function addresses took the comment colour, code
/// xrefs the special punctuation). Every other theme's own roles reach
/// 3:1.
const SHORT: &[(&str, &str, f64)] = &[
    ("One Dark", "--comment", 2.32),
    ("One Dark", "--punctuation-special", 2.89),
    ("One Dark", "--address-function", 2.32),
    ("One Dark", "--code-xref", 2.89),
    ("One Light", "--comment", 2.41),
    ("One Light", "--address-function", 2.41),
    ("Catppuccin Mocha", "--hint", 2.46),
    ("Catppuccin Macchiato", "--hint", 2.38),
    ("Catppuccin Frappé", "--hint", 2.23),
    ("Catppuccin Latte", "--type", 2.31),
    ("Catppuccin Latte", "--string", 2.96),
    ("Catppuccin Latte", "--number", 2.64),
    ("Catppuccin Latte", "--constant", 2.64),
    ("Catppuccin Latte", "--hint", 1.91),
    ("Nord", "--comment", 2.43),
    ("Alucard", "--hint", 1.56),
    ("Tokyo Night", "--text", 4.18),
    ("Tokyo Night", "--comment", 2.5),
    ("Tokyo Night", "--comment-doc", 2.5),
    ("Tokyo Night Storm", "--text", 4.26),
    ("Tokyo Night Storm", "--comment", 2.74),
    ("Tokyo Night Storm", "--comment-doc", 2.74),
    ("Tokyo Night Storm", "--punctuation-special", 2.9),
    ("Tokyo Night Moon", "--text", 3.74),
    ("Tokyo Night Moon", "--comment", 2.47),
    ("Tokyo Night Moon", "--comment-doc", 2.47),
    ("Tokyo Night Moon", "--hint", 2.12),
    ("Tokyo Night Day", "--text", 3.8),
    ("Tokyo Night Day", "--editor-foreground", 3.57),
    ("Tokyo Night Day", "--comment", 2.33),
    ("Tokyo Night Day", "--comment-doc", 2.33),
    ("Solarized Dark", "--comment", 2.79),
    ("Solarized Light", "--editor-foreground", 4.13),
    ("Solarized Light", "--string", 2.93),
    ("Solarized Light", "--constant", 2.98),
    ("Solarized Light", "--comment", 2.48),
    ("Solarized Light", "--hint", 2.74),
    ("Solarized Light", "--keyword-control", 2.97),
    ("Solarized Light", "--operator", 2.97),
];

#[test]
fn bundled_themes_keep_text_and_code_readable() {
    let themes = Themes::new(None);
    let mut found = Vec::new();
    for &(name, dark) in NAMES {
        let theme = themes.load(name, dark).theme;
        let bg = theme.editor;
        assert_eq!(bg & 0xff, 0xff, "{name}'s editor is opaque");
        for (roles, least) in [(BODY, 4.5), (CODE, 3.0)] {
            for &role in roles {
                let ratio = contrast(theme.by_name(role).unwrap(), bg);
                if ratio < least {
                    found.push((name, role, (ratio * 100.0).round() / 100.0));
                }
            }
        }
    }
    let listed: Vec<(&str, &str, f64)> = SHORT.to_vec();
    assert_eq!(
        found, listed,
        "measured shortfalls differ from the listed ones"
    );
}

#[test]
fn a_switch_reads_off_and_on_in_every_dark_theme_and_light_ones_are_kits() {
    let themes = Themes::new(None);
    for &(name, dark) in NAMES {
        let theme = themes.load(name, dark).theme;
        let Some((track, knob)) = theme.switch_off() else {
            assert!(!dark, "{name}: a dark theme's switch is its own");
            continue;
        };
        assert!(dark, "{name}: a light theme's switch is GPUI Kit's");
        // Off, the knob stands out on the track, the track (no stronger
        // than it needs) under the text; on, the knob on the accent.
        let off = contrast(knob, track);
        assert!(
            (SWITCH_CONTRAST..SWITCH_CONTRAST + 0.2).contains(&off),
            "{name}: {off}"
        );
        assert!(luminance(track) < luminance(solid(theme.text)), "{name}");
        let on = contrast(knob, solid(theme.accent));
        assert!(on >= SWITCH_CONTRAST, "{name}: on, {on}");
    }
}

/// A scratch folder of this process's, removed when dropped.
struct Scratch(PathBuf);

/// CIE L*a*b* (D65) of an opaque sRGB colour.
fn lab(colour: u32) -> [f64; 3] {
    let linear = |shift: u32| {
        let value = f64::from((colour >> shift) & 0xff) / 255.0;
        if value <= 0.040_45 {
            value / 12.92
        } else {
            ((value + 0.055) / 1.055).powf(2.4)
        }
    };
    let (red, green, blue) = (linear(24), linear(16), linear(8));
    let x_n = (0.4124 * red + 0.3576 * green + 0.1805 * blue) / 0.950_47;
    let y_n = 0.2126 * red + 0.7152 * green + 0.0722 * blue;
    let z_n = (0.0193 * red + 0.1192 * green + 0.9505 * blue) / 1.088_83;
    let curve = |ratio: f64| {
        if ratio > 0.008_856 {
            ratio.cbrt()
        } else {
            7.787 * ratio + 16.0 / 116.0
        }
    };
    [
        116.0 * curve(y_n) - 16.0,
        500.0 * (curve(x_n) - curve(y_n)),
        200.0 * (curve(y_n) - curve(z_n)),
    ]
}

#[test]
fn branch_arrows_are_eight_distinct_colours_neighbours_apart() {
    let themes = Themes::new(None);
    for &(name, dark) in NAMES {
        let arrows = themes.load(name, dark).theme.arrows();
        for (k, &c) in arrows.iter().enumerate() {
            assert_eq!(c & 0xff, 0xff, "{name} --arrow-{} is opaque", k + 1);
            assert!(
                !arrows[..k].contains(&c),
                "{name} --arrow-{} repeats",
                k + 1
            );
            // Lanes repeat: the eighth's neighbour is the first.
            let next = arrows[(k + 1) % 8];
            let [l1, a1, b1] = lab(c);
            let [l2, a2, b2] = lab(next);
            let delta = ((l1 - l2).powi(2) + (a1 - a2).powi(2) + (b1 - b2).powi(2)).sqrt();
            assert!(
                delta >= 20.0,
                "{name} --arrow-{} and its neighbour: ΔE {delta:.1}",
                k + 1
            );
        }
    }
}

#[test]
fn the_feature_maps_kinds_are_distinct_colours_off_the_panel() {
    let themes = Themes::new(None);
    let delta = |x: u32, y: u32| {
        let [l1, a1, b1] = lab(x);
        let [l2, a2, b2] = lab(y);
        ((l1 - l2).powi(2) + (a1 - a2).powi(2) + (b1 - b2).powi(2)).sqrt()
    };
    let mut found = Vec::new();
    for &(name, dark) in NAMES {
        let theme = themes.load(name, dark).theme;
        // As the strip draws them: at the bands' alpha over the panel.
        let panel = solid(theme.panel);
        let drawn = |c: u32| over(with_alpha(c, BAND), panel);
        let colours: Vec<(Feature, u32)> = Feature::ALL
            .iter()
            .map(|&k| (k, drawn(theme.feature(k))))
            .collect();
        for (i, &(kind, c)) in colours.iter().enumerate() {
            let on_panel = delta(c, panel);
            if on_panel < 15.0 {
                found.push(format!("{name} {kind:?} on the panel: ΔE {on_panel:.1}"));
            }
            for &(other, d) in &colours[..i] {
                let apart = delta(c, d);
                if apart < 15.0 {
                    found.push(format!("{name} {kind:?} and {other:?}: ΔE {apart:.1}"));
                }
            }
        }
    }
    assert!(found.is_empty(), "{found:#?}");
}

impl Scratch {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("binbun-themes-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }

    fn write(&self, file: &str, text: &str) {
        fs::write(self.0.join(file), text).unwrap();
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn a_user_theme_overrides_its_import_and_reloads_when_saved() {
    let scratch = Scratch::new("user");
    scratch.write(
        "mine.css",
        "@import \"Dark Modern\";\n:root {\n  --name: \"Mine\";\n  --keyword: #ff0000;\n  --type: nonsense;\n}\n",
    );
    let mut themes = Themes::new(Some(scratch.0.clone()));
    let base = themes.load("Dark Modern", true).theme;
    let mine = themes.load("mine", true);
    assert_eq!(mine.theme.keyword, 0xff00_00ff);
    // The unusable value falls back to the base's, said where it is.
    assert_eq!(mine.theme.type_, base.type_);
    assert_eq!(mine.problems.len(), 1, "{:?}", mine.problems);
    let file = scratch.0.join("mine.css").display().to_string();
    assert!(
        mine.problems[0].starts_with(&format!("{file}:5:3: `--type` must be a colour")),
        "{:?}",
        mine.problems
    );
    assert!(
        themes
            .list()
            .iter()
            .any(|l| l.name == "Mine" && l.user && l.dark)
    );

    assert!(!themes.changed());
    scratch.write(
        "mine.css",
        "@import \"Dark Modern\";\n:root { --name: \"Mine\"; --keyword: #00ff00; }\n",
    );
    assert!(themes.changed());
    let mine = themes.load("Mine", true);
    assert_eq!(mine.theme.keyword, 0x00ff_00ff);
    assert!(mine.problems.is_empty(), "{:?}", mine.problems);
}

#[test]
fn broken_imports_are_reported_and_the_default_fills_in() {
    let scratch = Scratch::new("imports");
    scratch.write(
        "lost.css",
        "@import \"Nowhere\";\n:root { --appearance: light; --keyword: red; }",
    );
    scratch.write("a.css", "@import \"b.css\";\n:root { --name: \"A\"; }");
    scratch.write("b.css", "@import \"a.css\";\n:root { --name: \"B\"; }");
    let themes = Themes::new(Some(scratch.0.clone()));

    let lost = themes.load("lost", false);
    assert_eq!(lost.theme.keyword, 0xff00_00ff);
    // Everything else is the default light theme's.
    assert_eq!(lost.theme.editor, default_theme(false).editor);
    assert!(!lost.theme.dark);
    assert!(
        lost.problems
            .iter()
            .any(|p| p.contains(":1:1: `@import \"Nowhere\"`")),
        "{:?}",
        lost.problems
    );
    assert!(
        lost.problems
            .iter()
            .any(|p| p.contains("One Light's are used")),
        "{:?}",
        lost.problems
    );

    let a = themes.load("A", true);
    assert!(
        a.problems.iter().any(|p| p.contains("imports itself")),
        "{:?}",
        a.problems
    );

    let missing = themes.load("Nothing Of The Sort", false);
    assert!(std::ptr::eq(missing.theme, default_theme(false)));
    assert_eq!(missing.problems.len(), 1);
}

#[test]
fn window_opacity_scales_only_the_background_surfaces() {
    let theme = default_theme(true);
    let (window, appearance) = theme.for_window(Backdrop::Transparent, 0.85);
    assert_eq!(appearance, WindowBackgroundAppearance::Transparent);
    assert!(window.translucent);
    for (surface, original) in [
        (window.background, theme.background),
        (window.gap, theme.gap),
        (window.tab_bar, theme.tab_bar),
        (window.panel, theme.panel),
        (window.editor, theme.editor),
    ] {
        assert_eq!(surface, with_alpha(original, 0xd9));
    }
    // Text, code and highlights keep their alpha.
    for role in ROLES
        .iter()
        .filter(|r| !["--background", "--gap", "--tab-bar", "--panel", "--editor"].contains(r))
    {
        assert_eq!(window.by_name(role), theme.by_name(role), "{role}");
    }
    // A container under surfaces draws nothing; what floats is opaque.
    assert_eq!(window.under(window.editor), 0);
    assert_eq!(solid(window.panel), solid(theme.panel));
    assert_eq!(theme.under(theme.editor), theme.editor);
}

#[test]
fn the_setting_wins_over_the_themes_background() {
    let scratch = Scratch::new("backdrop");
    scratch.write(
        "glass.css",
        "@import \"Dark Modern\";\n:root { --name: \"Glass\"; --background-appearance: blurred; --editor: #10101080; }",
    );
    let themes = Themes::new(Some(scratch.0.clone()));
    let glass = themes.load("Glass", true).theme;
    assert_eq!(glass.backdrop, Some(Backdrop::Blurred));

    // As the theme says: blurred, its alpha scaled by the opacity.
    let (window, appearance) = glass.for_window(Backdrop::Theme, 0.5);
    assert_eq!(appearance, WindowBackgroundAppearance::Blurred);
    assert_eq!(window.editor, 0x1010_1040);
    // The setting wins: opaque makes every surface opaque.
    let (window, appearance) = glass.for_window(Backdrop::Opaque, 0.5);
    assert_eq!(appearance, WindowBackgroundAppearance::Opaque);
    assert_eq!(window.editor, 0x1010_10ff);
    assert!(!window.translucent);
    // Mica is blurred where there is no Mica.
    let (_, appearance) = glass.for_window(Backdrop::MicaAlt, 1.0);
    let expected = if cfg!(windows) {
        WindowBackgroundAppearance::MicaAltBackdrop
    } else {
        WindowBackgroundAppearance::Blurred
    };
    assert_eq!(appearance, expected);
    // Transparent at full opacity with opaque colours draws as opaque.
    let (window, _) = default_theme(true).for_window(Backdrop::Transparent, 1.0);
    assert!(!window.translucent);
}

#[test]
fn a_new_user_gets_one_dark() {
    let settings = Settings::default();
    assert_eq!(settings.theme, Mode::Dark);
    let loaded = Themes::new(None).load(&settings.dark_theme, true);
    assert_eq!(loaded.problems, Vec::<String>::new());
    assert!(std::ptr::eq(loaded.theme, default_theme(true)));
    let named = bundled()
        .iter()
        .find(|(_, s)| s.file == "one-dark.css")
        .map(|(n, _)| n.as_str());
    assert_eq!(named, Some(DEFAULT_DARK));
}

/// A theme file setting every role but the finer ones, from `theme`'s
/// colours, with `extra` declarations after them.
fn parents_only(theme: &Theme, extra: &str) -> String {
    let mut text = String::from(":root {\n  --name: \"Plain\";\n  --appearance: light;\n");
    for role in ROLES
        .iter()
        .filter(|r| !PARENTS.iter().any(|(child, _)| child == *r))
    {
        let colour = theme.by_name(role).unwrap();
        let _ = writeln!(text, "  {role}: #{colour:08x};");
    }
    text.push_str(extra);
    text.push_str("}\n");
    text
}

#[test]
fn finer_roles_left_out_are_their_parents() {
    let scratch = Scratch::new("parents");
    let source = default_theme(false);
    scratch.write("plain.css", &parents_only(source, ""));
    let themes = Themes::new(Some(scratch.0.clone()));
    let plain = themes.load("Plain", false);
    assert_eq!(plain.problems, Vec::<String>::new());
    for &(child, parent) in PARENTS {
        assert_eq!(
            plain.theme.by_name(child),
            plain.theme.by_name(parent),
            "{child} is {parent}"
        );
    }
    assert_eq!(
        plain.theme.auto_name_alpha.to_bits(),
        AUTO_NAME_ALPHA.to_bits()
    );
    assert_eq!(plain.theme.cast_alpha.to_bits(), CAST_ALPHA.to_bits());

    // Set, they are their own; a wrong one is said and falls back.
    scratch.write(
        "plain.css",
        &parents_only(
            source,
            "  --macro: #123456;\n  --operator: 12px;\n  --auto-name-alpha: 50%;\n  --cast-alpha: 2;\n",
        ),
    );
    let mut themes = themes;
    assert!(themes.changed());
    let set = themes.load("Plain", false);
    assert_eq!(set.theme.macro_, 0x1234_56ff);
    assert_eq!(set.theme.operator, set.theme.punctuation);
    assert_eq!(set.theme.auto_name_alpha.to_bits(), 0.5f32.to_bits());
    assert_eq!(set.theme.cast_alpha.to_bits(), CAST_ALPHA.to_bits());
    assert_eq!(set.problems.len(), 2, "{:?}", set.problems);
    assert!(
        set.problems.iter().any(|p| p.contains("`px`")),
        "{:?}",
        set.problems
    );
    assert!(
        set.problems.iter().any(|p| p.contains("from 0 to 1")),
        "{:?}",
        set.problems
    );
}
