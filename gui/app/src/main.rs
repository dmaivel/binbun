//! `binbun [FILE]`: binbun's GUI. GPUI
//! renders the view models of `binbun-gui-view` and routes input to them.
//! The same `binbun` runs every command of the CLI's (`binbun decompile
//! FILE`, `binbun --help`: [`binbun_cli::main`]) without opening a
//! window; no command, or a file alone, opens the GUI.
//!
//! On Windows it is a GUI program: no console window, and a shell neither
//! waits for it nor shows its output (its commands still write to
//! redirected output). The release zip's command is `bin\binbun.exe`
//! beside it, the root workspace's `binbun-cli`, a console program, which
//! starts this one for what opens the GUI.
//!
//! The settings are `settings.toml` in binbun's config folder
//! (`binbun paths config`; watched: edits apply at once); the user's
//! themes are `themes/*.css` there (watched too; the bundled ones are
//! credited in `gui/THEMES`).
//! `BINBUN_TRACE=1` prints timings on stderr;
//! `BINBUN_FRAME_TRACE=1` prints each frame's CPU time, from the window's
//! render to the end of its paint (`frame 3.71 ms`).
//! `BINBUN_UPDATE_URL` replaces `https://binbun.org/latest.json` for the
//! update checks agreed to (`updates.check`; tests: a local server).

#![cfg_attr(windows, windows_subsystem = "windows")]

/// `eprintln!` when `BINBUN_TRACE` is set.
macro_rules! trace {
    ($($arg:tt)*) => {
        if *crate::TRACE {
            eprintln!($($arg)*);
        }
    };
}

mod actions;
mod arrows;
mod banners;
mod c_view;
mod callers_view;
mod calls_view;
mod collab;
#[cfg(feature = "collab")]
mod collab_net;
#[cfg(not(feature = "collab"))]
#[path = "collab_off.rs"]
mod collab_net;
mod comment_field;
mod console_view;
mod context_menu;
mod corrections;
mod facts_view;
mod feature_map_view;
mod files_and_folders;
mod folder_view;
mod fonts;
mod graph_view;
mod hex_view;
mod highlight;
mod icons;
mod ir_view;
mod layout_save;
mod listing_view;
mod lists;
mod overlays;
mod panes;
mod pathfinder_view;
mod popup;
mod project_files;
mod scrolling;
mod search_view;
mod selectable_text;
mod selection;
mod serving;
mod settings_pane;
mod sidebar;
mod start_page;
mod struct_editor;
mod symbol_cache;
mod symbols_bar;
mod tab_drag;
mod tabs;
mod terminal_view;
mod theme;
mod threads_view;
mod titlebar;
mod type_field;
mod unified_rows;
mod unified_view;
mod window_tabs;
mod workspace;

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::LazyLock;
use std::time::Instant;

use gpui_kit::App;

/// jemalloc: the analysis allocates and frees on many threads at once,
/// faster than with the system's allocator (none on MSVC, which jemalloc
/// does not build for).
#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static ALLOCATOR: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

/// When the process started.
pub static STARTED: LazyLock<Instant> = LazyLock::new(Instant::now);

/// Whether `BINBUN_TRACE` asks for timings on stderr.
pub static TRACE: LazyLock<bool> = LazyLock::new(|| std::env::var_os("BINBUN_TRACE").is_some());

/// Whether `BINBUN_FRAME_TRACE` asks for each frame's CPU time on stderr.
pub static FRAME_TRACE: LazyLock<bool> =
    LazyLock::new(|| std::env::var_os("BINBUN_FRAME_TRACE").is_some());

/// Milliseconds since the process started.
pub fn since_start() -> f64 {
    STARTED.elapsed().as_secs_f64() * 1e3
}

fn main() -> ExitCode {
    LazyLock::force(&STARTED);
    binbun_cli::main(Some(gui))
}

/// The GUI, `path` open in it (else the start page).
fn gui(path: Option<PathBuf>) -> ExitCode {
    let app = gpui_kit::application().with_assets(icons::AppAssets);
    // macOS keeps the app running when its last window closes (GPUI's
    // default there, the platform's convention); a click on its Dock icon
    // then opens the start page again. Elsewhere the app quits with its
    // last window.
    app.on_reopen(|cx| {
        if cx.windows().is_empty() {
            start_page::open_window(None, cx);
        }
    });
    app.run(move |cx: &mut App| {
        gpui_kit::init(cx);
        fonts::load(cx);
        actions::register_app(cx);
        if !start_page::open_window(path.as_deref(), cx) {
            cx.quit();
        }
        cx.activate(true);
    });
    ExitCode::SUCCESS
}
