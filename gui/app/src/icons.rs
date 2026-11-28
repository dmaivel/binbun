//! The chrome's icons: GPUI Kit's Lucide set (ISC; `gpui-kit-assets`),
//! only those used embedded, beside the components' own. Monochrome,
//! drawn in the text colour they are given (the muted one at rest).
//! The agents' marks are embedded too, as their vendors publish them,
//! and served in their avatar's square frame.

use std::borrow::Cow;

use binbun_gui_view::agents::{self, HARNESSES};
use gpui_kit::assets::{Assets, IconName, icon_assets};
use gpui_kit::{AssetSource, Hsla, Pixels, SharedString, Styled, Svg, svg};

icon_assets!(
    ChromeIcons,
    [
        Activity,
        ArrowDown,
        ArrowLeft,
        ArrowRight,
        ArrowRightLeft,
        ArrowUp,
        ArrowUpFromLine,
        AtSign,
        Ban,
        Binary,
        BookOpenText,
        Bookmark,
        Bot,
        Braces,
        CaseSensitive,
        ChevronDown,
        ChevronLeft,
        ChevronRight,
        ChevronUp,
        Circle,
        CircleAlert,
        CircleArrowUp,
        CircleCheck,
        CircleDashed,
        CircleX,
        Columns2,
        CodeXml,
        Database,
        Diff,
        File,
        FileClock,
        FileCode,
        FileDigit,
        Folder,
        FolderOpen,
        GitMergeConflict,
        Grid3x3,
        Hash,
        Import,
        Info,
        Layers,
        Library,
        Link2Off,
        LoaderCircle,
        Lock,
        MapPin,
        Maximize2,
        Minimize2,
        MessageSquare,
        MessageSquareText,
        Minus,
        Network,
        PanelLeft,
        PanelRight,
        Pencil,
        Pin,
        Play,
        Plus,
        Route,
        Square,
        SquareCheck,
        TextAlignStart,
        Variable,
        Waypoints,
        Workflow,
        Wrench,
        Quote,
        Regex,
        Search,
        SendHorizontal,
        Settings,
        Shapes,
        ShieldAlert,
        SquareFunction,
        SquareTerminal,
        Terminal,
        Users,
        X,
    ]
);

/// The window's assets: the chrome's icons, then GPUI Kit's.
#[derive(Clone, Copy, Debug, Default)]
pub struct AppAssets;

/// The logo's asset path: the owner's drawing with its fills taken out so
/// it draws in one colour (`assets/logo/binbun-mono.svg`; the original is
/// `binbun.svg` beside it). Swapping the logo is replacing that file.
pub const LOGO: &str = "logo/binbun-mono.svg";

impl AssetSource for AppAssets {
    fn load(&self, path: &str) -> gpui_kit::Result<Option<Cow<'static, [u8]>>> {
        if path == LOGO {
            return Ok(Some(Cow::Borrowed(include_bytes!(
                "../assets/logo/binbun-mono.svg"
            ))));
        }
        if let Some(bytes) = ChromeIcons.load(path)? {
            return Ok(Some(bytes));
        }
        if let Some(bytes) = framed_mark(path) {
            return Ok(Some(Cow::Owned(bytes)));
        }
        Assets.load(path)
    }

    fn list(&self, path: &str) -> gpui_kit::Result<Vec<SharedString>> {
        let mut paths = Assets.list(path)?;
        paths.extend(ChromeIcons.list(path)?);
        paths.sort();
        paths.dedup();
        Ok(paths)
    }
}

/// The agents' marks, by the asset path `binbun_gui_view::agents`'s table
/// names them by (`agents/codex-light.svg`): the files the avatars draw,
/// the vendors' unaltered and two single-colour forms made of their paths
/// (`assets/agents/README.md`).
fn agent_mark(path: &str) -> Option<&'static [u8]> {
    /// `agents/<file>` and its bytes.
    macro_rules! marks {
        ($($file:literal),* $(,)?) => {
            match path.strip_prefix("agents/")? {
                $($file => include_bytes!(concat!("../assets/agents/", $file)),)*
                _ => return None,
            }
        };
    }
    Some(marks!(
        "antigravity.svg",
        "claude-code.svg",
        "codex-light.svg",
        "cursor-light.svg",
        "fx-light.svg",
        "grok-light.svg",
        "kiro-mono.svg",
        "muse.svg",
        "omp.svg",
        "opencode-mono.svg",
        "pi-light.svg",
    ))
}

/// The agent's mark at `path` as an avatar draws it: its file in its
/// mark's square frame ([`agents::Mark::frame`]), so that drawn over the whole
/// circle its ink is centred on it.
fn framed_mark(path: &str) -> Option<Vec<u8>> {
    let mark = HARNESSES
        .iter()
        .filter_map(|h| h.mark)
        .find(|m| m.mono == path || m.colours.is_some_and(|(file, _)| file == path))?;
    let text = std::str::from_utf8(agent_mark(path)?).ok()?;
    agents::framed(text, mark.frame()).map(String::into_bytes)
}

/// Icon `name`, `size` square, drawn in `color`.
pub fn icon(name: IconName, size: Pixels, color: Hsla) -> Svg {
    svg()
        .path(name.path())
        .flex_none()
        .size(size)
        .text_color(color)
}

#[cfg(test)]
mod tests {
    use binbun_gui_view::agents::HARNESSES;

    use super::{agent_mark, framed_mark};

    #[test]
    fn every_mark_the_agents_table_names_is_bundled() {
        for harness in HARNESSES {
            let files = harness
                .mark
                .iter()
                .flat_map(|m| [Some(m.mono), m.colours.map(|c| c.0)]);
            for file in files.flatten() {
                assert!(
                    agent_mark(file).is_some(),
                    "{}: {} not bundled",
                    harness.name,
                    file
                );
            }
        }
    }

    /// Each mark as served, drawn over a circle as GPUI draws it (its
    /// renderer, the square the circle's size): its ink centred within a
    /// quarter of a percent of the circle, its longer side its share
    /// within one percent.
    #[test]
    fn every_mark_is_drawn_centred_on_its_circle() {
        use resvg::{tiny_skia, usvg};
        const SIDE: u32 = 400;
        for mark in HARNESSES.iter().filter_map(|h| h.mark) {
            let files = [Some(mark.mono), mark.colours.map(|c| c.0)];
            for file in files.into_iter().flatten() {
                let bytes = framed_mark(file).expect("served");
                let tree =
                    usvg::Tree::from_data(&bytes, &usvg::Options::default()).expect("parses");
                let mut pixmap = tiny_skia::Pixmap::new(SIDE, SIDE).expect("a size");
                #[expect(clippy::cast_precision_loss, reason = "small")]
                let side = SIDE as f32;
                let file_size = tree.size();
                resvg::render(
                    &tree,
                    tiny_skia::Transform::from_scale(
                        side / file_size.width(),
                        side / file_size.height(),
                    ),
                    &mut pixmap.as_mut(),
                );
                // The ink's bounds (left, top, right, bottom), its faintest
                // edge (a fiftieth) aside.
                let mut ink = [f32::MAX, f32::MAX, f32::MIN, f32::MIN];
                for (index, pixel) in pixmap.pixels().iter().enumerate() {
                    if pixel.alpha() <= 5 {
                        continue;
                    }
                    let index = u32::try_from(index).expect("small");
                    #[expect(clippy::cast_precision_loss, reason = "small")]
                    let (column, row) = ((index % SIDE) as f32, (index / SIDE) as f32);
                    ink = [
                        ink[0].min(column),
                        ink[1].min(row),
                        ink[2].max(column + 1.0),
                        ink[3].max(row + 1.0),
                    ];
                }
                let centre = (f32::midpoint(ink[0], ink[2]), f32::midpoint(ink[1], ink[3]));
                assert!(
                    (centre.0 - side / 2.0).abs() <= 1.0 && (centre.1 - side / 2.0).abs() <= 1.0,
                    "{file}: ink {ink:?} off the centre"
                );
                let longer = (ink[2] - ink[0]).max(ink[3] - ink[1]);
                let share = side * f32::from(mark.across) / 100.0;
                assert!(
                    (longer - share).abs() <= 4.0,
                    "{file}: ink {longer} across, not {share}"
                );
            }
        }
    }
}
