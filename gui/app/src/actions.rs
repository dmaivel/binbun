//! A GPUI action for every command of the registry
//! (`binbun_gui_view::commands`), and the key map built from it with the
//! user's overrides: the menus, the palette and the keys all dispatch the
//! same actions.
//!
//! The workspace's root listens for every action; the App listens too
//! ([`register_app`]), so a command dispatched where no workspace element
//! is on the focus path (the focus on nothing, on the start page, in a
//! closed menu) still runs, on the active window's workspace.

use std::collections::BTreeMap;
use std::rc::Rc;

use binbun_gui_view::commands::{self, Binding, Command, bindings};
use gpui_kit::{
    Action, AnyWindowHandle, App, Context, Entity, Global, InteractiveElement, KeyBinding,
    KeyBindingContextPredicate, NoAction, WeakEntity,
};

#[cfg(target_os = "macos")]
use crate::titlebar::native_menus;
use crate::workspace::Workspace;

/// Defines one action per command and the two mappings between them.
macro_rules! command_actions {
    ($($name:ident),* $(,)?) => {
        gpui_kit::actions!(binbun, [$($name),*]);

        /// The action `command` dispatches.
        pub fn action(command: Command) -> Box<dyn Action> {
            match command {
                $(Command::$name => Box::new($name),)*
            }
        }

        /// `element` with every command's action running the command on
        /// the workspace.
        pub fn listen<E: InteractiveElement>(element: E, cx: &mut Context<Workspace>) -> E {
            element
                $(.on_action(cx.listener(|this, _: &$name, window, cx| {
                    this.run(Command::$name, window, cx);
                })))*
        }

        /// Listens for every command's action at the App level: those no
        /// workspace element took run on the active window's workspace.
        pub fn register_app(cx: &mut App) {
            $(cx.on_action(|_: &$name, cx| run_anywhere(Command::$name, cx));)*
        }
    };
}

command_actions!(
    Open,
    OpenRecent,
    ReopenSlice,
    SaveProject,
    ExportProject,
    ImportProject,
    ShareProject,
    JoinSession,
    CopyIdentityCard,
    ConnectAgent,
    LeaveSession,
    BringValues,
    SessionPanel,
    InsertLocation,
    Conflicts,
    Threads,
    History,
    Close,
    Quit,
    Undo,
    Redo,
    Rename,
    SetType,
    Data,
    MakeCode,
    Undefine,
    MakeString,
    MakeArray,
    MakeFunction,
    EditFunction,
    DeleteFunction,
    EditStruct,
    NewStruct,
    Comment,
    StartThread,
    CopyAddress,
    CopyName,
    SelectAll,
    NumberHex,
    NumberDecimal,
    NumberChar,
    OpenListing,
    OpenC,
    SplitRight,
    SplitDown,
    ToggleLeftSidebar,
    ToggleRightSidebar,
    ToggleConsole,
    NewTerminal,
    ToggleFeatureMap,
    MoveFeatureMap,
    OpenAsTab,
    ToggleMaximize,
    ToggleTheme,
    SelectTheme,
    ZoomIn,
    ZoomOut,
    ZoomReset,
    ToggleGraph,
    OpenGraphInSplit,
    FitGraph,
    ToggleOverview,
    ToggleReadingView,
    ShowInIr,
    IrPreviousStage,
    IrNextStage,
    ToggleIrDiff,
    ToggleOpcodeBytes,
    ToggleNumbers,
    ToggleSymbolic,
    CycleXrefs,
    ToggleLigatures,
    ToggleIslands,
    Settings,
    Palette,
    GoAnywhere,
    Back,
    Forward,
    Follow,
    Xrefs,
    OpenInNewPane,
    Peek,
    Origin,
    Verify,
    Why,
    RejectSignature,
    RunFromHere,
    CompareProcessors,
    ProcessorArchitecture,
    ProcessorRaptorCove,
    ProcessorGracemont,
    ProcessorFile,
    NextFunction,
    PreviousFunction,
    Functions,
    Strings,
    StageImage,
    StageFunctions,
    StageReferences,
    StageCallers,
    StageWarmed,
    CloseTab,
    ClosePane,
    NextTab,
    PreviousTab,
    MoveTabLeft,
    MoveTabRight,
    MoveTabToNextPane,
    FocusLeft,
    FocusRight,
    FocusUp,
    FocusDown,
    FocusNextPane,
    ToggleSync,
    SwitchView,
    About,
    FilesAndFolders,
    OpenSettingsFile,
    RevealSymbolCache,
    RevealProjects,
    ClearSymbolCache,
    DownloadSymbols,
    SymbolsNotNow,
    AlwaysDownloadSymbols,
    KeyMap,
    MoveUp,
    MoveDown,
    PageUp,
    PageDown,
    Top,
    Bottom,
    ToggleHex,
    ToggleUnified,
    ShowInHex,
    HexFileOffsets,
    HexEntropy,
    HexSide,
    ApplyType,
    RemoveType,
    CopyHex,
    CopyEscaped,
    CopyCArray,
    ToggleCalls,
    MoreCallers,
    FewerCallers,
    MoreCallees,
    FewerCallees,
    Pathfinder,
    PathFrom,
    PathTo,
    WholeSubgraph,
    CallerArguments,
    KeepTab,
    Find,
    FindNext,
    FindPrevious,
    SearchEverywhere,
    SearchBytes,
    SearchImmediate,
    StopSearch,
    Bookmark,
    Bookmarks,
    NumberEnum,
    NewEnum,
    EditEnum,
);

/// Every open window's workspace.
#[derive(Default)]
struct Workspaces(Vec<(AnyWindowHandle, WeakEntity<Workspace>)>);

impl Global for Workspaces {}

/// Remembers `workspace` as window `handle`'s, for [`register_app`].
pub fn register_window(handle: AnyWindowHandle, workspace: &Entity<Workspace>, cx: &mut App) {
    let list = &mut cx.default_global::<Workspaces>().0;
    list.retain(|(_, w)| w.upgrade().is_some());
    list.push((handle, workspace.downgrade()));
}

/// Runs `command` on the active window's workspace (else the first open
/// one's), once the dispatch that brought it is over (its window is
/// busy until then). Quit needs no window; any other command with none
/// open (macOS keeps the app running when its last window closes, its
/// convention: the menu bar still sends commands) opens the start page
/// and runs there, so File → Open shows its dialog.
fn run_anywhere(command: Command, cx: &mut App) {
    if command == Command::Quit {
        cx.quit();
        return;
    }
    let active = cx.active_window();
    let live: Vec<(AnyWindowHandle, WeakEntity<Workspace>)> = cx
        .try_global::<Workspaces>()
        .map(|w| {
            w.0.iter()
                .filter(|(_, w)| w.upgrade().is_some())
                .cloned()
                .collect()
        })
        .unwrap_or_default();
    let target = live
        .iter()
        .find(|(handle, _)| Some(*handle) == active)
        .or_else(|| live.first())
        .cloned();
    let Some((handle, workspace)) = target else {
        // The window registers as it opens, so this runs once.
        if crate::start_page::open_window(None, cx) {
            run_anywhere(command, cx);
        }
        return;
    };
    cx.defer(move |cx| {
        let _ = handle.update(cx, |_, window, cx| {
            let _ = workspace.update(cx, |this, cx| {
                if commands::state(command, &this.facts()).enabled {
                    this.run(command, window, cx);
                }
            });
        });
    });
}

/// Binds the registry's keys with the user's `overrides`; the keys of
/// `before` (the previous key map) no longer in it are unbound. The key
/// map, and what is wrong with the overrides (ids naming no command,
/// keystrokes that do not parse).
pub fn bind(
    before: &[Binding],
    overrides: &BTreeMap<String, Vec<String>>,
    cx: &mut App,
) -> (Vec<Binding>, Vec<String>) {
    let (map, mut problems) = bindings(overrides);
    let load = |keys: &str, action: Box<dyn Action>, context: Option<&str>, cx: &App| {
        let predicate = context
            .and_then(|c| KeyBindingContextPredicate::parse(c).ok())
            .map(Rc::new);
        KeyBinding::load(keys, action, predicate, false, None, cx)
    };
    let mut keys = Vec::new();
    for old in before.iter().filter(|old| !map.contains(old)) {
        if let Ok(binding) = load(&old.keys, Box::new(NoAction), old.scope.context(), cx) {
            keys.push(binding);
        }
    }
    // GPUI shows (and prefers) the binding bound last: bound in reverse,
    // a command's first key (`N` before `F2`) is the one the menus show,
    // as the palette does.
    for new in map.iter().rev().filter(|new| !before.contains(new)) {
        match load(&new.keys, action(new.command), new.scope.context(), cx) {
            Ok(binding) => keys.push(binding),
            Err(_) => problems.push(format!("{:?} is not a keystroke", new.keys)),
        }
    }
    cx.bind_keys(keys);
    // The native menus show the keys bound when they are made.
    #[cfg(target_os = "macos")]
    native_menus(cx);
    (map, problems)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use binbun_gui_view::commands::bindings;
    use gpui_kit::{Keystroke, OperatingSystem};

    /// GPUI binds the default keys' `secondary-` as Cmd on macOS; on Linux
    /// and Windows every default key is the one the same keys written with
    /// `ctrl-` were.
    #[test]
    fn default_keys_bind_cmd_on_macos_and_ctrl_elsewhere() {
        let (map, _) = bindings(&BTreeMap::new());
        let parse = |stroke: &str, os| Keystroke::parse_with_os(stroke, os).unwrap();
        for stroke in map.iter().flat_map(|b| b.keys.split_whitespace()) {
            let ctrl = stroke.replace("secondary-", "ctrl-");
            for os in [OperatingSystem::Linux, OperatingSystem::Windows] {
                assert_eq!(parse(stroke, os), parse(&ctrl, os), "{stroke}");
            }
            let cmd = stroke.replace("secondary-", "cmd-");
            let mac = parse(stroke, OperatingSystem::Mac);
            assert_eq!(mac, parse(&cmd, OperatingSystem::Mac), "{stroke}");
            assert_eq!(
                mac.modifiers.platform,
                stroke.contains("secondary-"),
                "{stroke}"
            );
        }
    }
}
