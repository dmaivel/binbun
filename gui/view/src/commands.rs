//! Every action of the GUI in one registry ([`COMMANDS`]): its id, title,
//! menu, default keys (the usual disassembler keys where there is one)
//! and, from the state of the
//! window ([`Facts`]), whether it is enabled and checked ([`state`]). The
//! menu bar ([`menu`]), the command palette and the key map
//! ([`bindings`], with the user's overrides) all read it, so they never
//! disagree.
//!
//! A default key's `secondary-` is Cmd on macOS and Ctrl elsewhere (GPUI
//! resolves it as it binds); `ctrl-` is Ctrl everywhere, kept where macOS
//! apps use Ctrl too (the console's Ctrl+Backtick; Ctrl+M, Cmd+M being the
//! window's Minimize there). Key labels follow the platform
//! ([`key_label`]: `Ctrl-O` elsewhere, `⌘O` on macOS).

use std::collections::BTreeMap;

use binbun_session::HistoryEntry;
use binbun_session::journal::Origin;

/// An action.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Command {
    /// Opens a binary (a file dialog).
    Open,
    /// Opens one of the binaries opened before.
    OpenRecent,
    /// Opens another slice of the universal Mach-O file open (the slice
    /// picker).
    ReopenSlice,
    /// Saves the edits to the project file.
    SaveProject,
    /// Writes the binary's project to one portable file (`<name>.binbun`).
    ExportProject,
    /// Installs an exported project as its binary's (a file dialog).
    ImportProject,
    /// Shares the project with others: the Share dialog (a ticket).
    ShareProject,
    /// Joins a project someone shares: the Join dialog (their ticket).
    JoinSession,
    /// Copies this user's identity card (`binbunid…`), by which a
    /// project's owner adds them as a member.
    CopyIdentityCard,
    /// Shows how each coding agent's harness connects to binbun (`binbun
    /// mcp`): the Connect an Agent dialog.
    ConnectAgent,
    /// Stops sharing, or leaves the session joined.
    LeaveSession,
    /// Brings chosen values of the binary's own (private) project into the
    /// share's project open, as one new change of this install's.
    BringValues,
    /// Shows or hides the session panel (people, chat, conflicts,
    /// refused changes).
    SessionPanel,
    /// Writes a link to the cursor's place into the chat's message box
    /// (`push_stream · 1E720`), the chat opened.
    InsertLocation,
    /// Shows the conflicts: concurrent edits left with two values.
    Conflicts,
    /// Shows or hides the threads panel (the right dock's): the threads
    /// about the function at the cursor and all, suggestions to review.
    Threads,
    /// Starts a thread on the cursor's line (listing, C, graph).
    StartThread,
    /// Shows or hides the history panel (the right dock's): every change,
    /// by whom, newest first.
    History,
    /// Closes the binary.
    Close,
    /// Quits.
    Quit,
    /// Undoes the last edit.
    Undo,
    /// Makes the last undone edit again.
    Redo,
    /// Renames the item under the cursor (`N`).
    Rename,
    /// Types the variable, parameter, global or function (its prototype)
    /// under the cursor as C typed in place (`Y`).
    SetType,
    /// `D`: in the listing and the hex view, data at the cursor, its
    /// width cycled through byte, word, dword and qword (a correction of
    /// recovery); on a struct member in the C, its width so, as an edit of
    /// its struct.
    Data,
    /// Code from the cursor, decoded and followed (`C`).
    MakeCode,
    /// The item at the cursor undefined: its bytes typed by nothing, and
    /// what recovery found only from it gone (`U`).
    Undefine,
    /// A string at the cursor, C or UTF-16 by what the bytes are (`A`).
    MakeString,
    /// An array of the item at the cursor's units, its count typed (`*`).
    MakeArray,
    /// A function from the cursor, its bounds recovered from there (`P`).
    MakeFunction,
    /// The end of the function at the cursor, typed.
    EditFunction,
    /// The function at the cursor deleted: its code stays code.
    DeleteFunction,
    /// Opens the struct under the cursor (a struct's name, a variable of
    /// a struct or a pointer to one) in the struct editor.
    EditStruct,
    /// Opens the struct editor on a new struct.
    NewStruct,
    /// Comments the cursor's address (`;`).
    Comment,
    /// Copies the cursor's address.
    CopyAddress,
    /// Copies the name under the cursor.
    CopyName,
    /// Selects the focused pane's text: the C's whole function, the
    /// listing's lines of the function under the cursor.
    SelectAll,
    /// Shows the number under the cursor in hexadecimal (`H`).
    NumberHex,
    /// Shows the number under the cursor in decimal.
    NumberDecimal,
    /// Shows the number under the cursor as a character (`R`).
    NumberChar,
    /// Opens a listing tab.
    OpenListing,
    /// Opens a C tab.
    OpenC,
    /// Splits the pane to the right.
    SplitRight,
    /// Splits the pane down.
    SplitDown,
    /// Shows or hides the left sidebar.
    ToggleLeftSidebar,
    /// Shows or hides the right sidebar.
    ToggleRightSidebar,
    /// Hides the Python console or the terminal used last where it is
    /// shown, else brings it under the code of the window tab shown.
    ToggleConsole,
    /// Opens a terminal under the code: the user's shell, in the binary's
    /// folder.
    NewTerminal,
    /// Starts the coding agent the robot in the status bar starts (the
    /// one started last; asked the first time) in a pane to the right.
    NewAgent,
    /// Shows or hides the feature map (the strip standing for the whole
    /// image).
    ToggleFeatureMap,
    /// Puts the feature map at the top of the panes, or back at their
    /// right.
    MoveFeatureMap,
    /// Opens the map's folder (the context menu's, else the selected one)
    /// as a list tab in the focused pane.
    OpenAsTab,
    /// Shows the focused pane alone, or the panes again.
    ToggleMaximize,
    /// Switches between the dark and the light theme.
    ToggleTheme,
    /// Picks the theme from a list, previewing each as it is selected.
    SelectTheme,
    /// Zooms the whole window in.
    ZoomIn,
    /// Zooms the whole window out.
    ZoomOut,
    /// Zooms the whole window back to 100%.
    ZoomReset,
    /// Shows the pane's listing as the graph of the function at the
    /// cursor, or the listing again (Space).
    ToggleGraph,
    /// Shows the graph of the function at the cursor in the other pane (a
    /// split made if there is none), following this tab's cursor.
    OpenGraphInSplit,
    /// Zooms the graph to show all of it.
    FitGraph,
    /// Shows or hides the graph's overview.
    ToggleOverview,
    /// Shows the pane's listing as the structured hex view, or the
    /// listing again.
    ToggleHex,
    /// Shows the pane's listing as the unified listing (the whole file in
    /// order: headers, tables, code and data), or the listing again.
    ToggleUnified,
    /// Shows the cursor's address in a hex view.
    ShowInHex,
    /// Switches the hex view between addresses and file offsets.
    HexFileOffsets,
    /// Switches the hex view's overview between kinds and entropy.
    HexEntropy,
    /// Shows or hides the hex view's side area (the structure tree and
    /// the data inspector).
    HexSide,
    /// Lays a C type over the bytes at the hex cursor (`Alt+Q`).
    ApplyType,
    /// Removes the user's type at the hex cursor.
    RemoveType,
    /// Copies the hex selection as hexadecimal bytes.
    CopyHex,
    /// Copies the hex selection as a C string of escaped bytes.
    CopyEscaped,
    /// Copies the hex selection as a C array.
    CopyCArray,
    /// Shows the pane's listing as the call graph around the function at
    /// the cursor, or the listing again.
    ToggleCalls,
    /// Shows one more level of callers in the call graph.
    MoreCallers,
    /// Shows one level of callers fewer.
    FewerCallers,
    /// Shows one more level of callees in the call graph.
    MoreCallees,
    /// Shows one level of callees fewer.
    FewerCallees,
    /// Opens the Pathfinder in the right dock.
    Pathfinder,
    /// Makes the function at the cursor the Pathfinder's start.
    PathFrom,
    /// Makes the function at the cursor the Pathfinder's end.
    PathTo,
    /// Shows a path search's whole subgraph in the call graph, or only
    /// the paths it lists.
    WholeSubgraph,
    /// Shows a cross-references tab's callers with each call's C line and
    /// arguments, or the references again.
    CallerArguments,
    /// Keeps the active tab (a preview tab is pinned).
    KeepTab,
    /// Switches the C pane between the reading view and the exact C.
    ToggleReadingView,
    /// Shows the function at the cursor through every stage of its
    /// decompilation (the IR viewer), or the C pane showing it its C again.
    ShowInIr,
    /// The IR viewer's stage before (`<`).
    IrPreviousStage,
    /// The IR viewer's stage after (`>`).
    IrNextStage,
    /// Shows the IR viewer's stage as a diff against the stage before
    /// (else as it is).
    ToggleIrDiff,
    /// Shows or hides the listing's opcode bytes.
    ToggleOpcodeBytes,
    /// Switches the listing's numbers between `88h` and `0x88`.
    ToggleNumbers,
    /// Switches the listing's operands between names and raw values.
    ToggleSymbolic,
    /// Cycles the cross-references shown per item (0, 2, 5).
    CycleXrefs,
    /// Turns the code font's ligatures on or off.
    ToggleLigatures,
    /// Switches between island panes and flat panes.
    ToggleIslands,
    /// Opens the settings pane.
    Settings,
    /// Opens the command palette.
    Palette,
    /// Goes to a name or an address (`G`).
    GoAnywhere,
    /// Goes back (`Esc`).
    Back,
    /// Goes forward.
    Forward,
    /// Follows the reference under the cursor (`Enter`).
    Follow,
    /// Opens the cross-references to the cursor's item in a tab (`X`).
    Xrefs,
    /// Opens what the name under the cursor names in a new pane.
    OpenInNewPane,
    /// Peeks at the name under the cursor.
    Peek,
    /// Opens where the value under the cursor comes from (`Shift+X`:
    /// "value xrefs").
    Origin,
    /// Verifies the shown function against its machine code now.
    Verify,
    /// Opens the card saying why the variable under the cursor has its
    /// name and type, or where the name of the function under it comes
    /// from.
    Why,
    /// Rejects the library signature that named the function under the
    /// cursor (or the cursor's).
    RejectSignature,
    /// Runs the function at the cursor from a new example state.
    RunFromHere,
    /// Compares the shown function's runs on the shipped processors'
    /// profiles.
    CompareProcessors,
    /// Runs and verifies on the architecture: undefined values stay
    /// unknown.
    ProcessorArchitecture,
    /// Runs and verifies on Intel's Raptor Cove (P-cores) profile.
    ProcessorRaptorCove,
    /// Runs and verifies on Intel's Gracemont (E-cores) profile.
    ProcessorGracemont,
    /// Runs and verifies on a profile file chosen.
    ProcessorFile,
    /// Goes to the next function.
    NextFunction,
    /// Goes to the previous function.
    PreviousFunction,
    /// Focuses the map's functions.
    Functions,
    /// Opens the strings in a tab.
    Strings,
    /// Opens the find bar over the focused pane.
    Find,
    /// The find bar's next match (`F3`).
    FindNext,
    /// The find bar's previous match (`Shift+F3`).
    FindPrevious,
    /// Searches the listing and every function's C (`Alt+T`), the results
    /// in a tab.
    SearchEverywhere,
    /// Searches the image's bytes for a pattern or a string (`Alt+B`),
    /// the results in a tab.
    SearchBytes,
    /// Searches for instructions and C literals of a value (`Alt+I`), the
    /// results in a tab.
    SearchImmediate,
    /// Stops the focused results tab's search.
    StopSearch,
    /// Bookmarks the cursor's address with a name (`Alt+M`).
    Bookmark,
    /// Opens the bookmarks in a tab (`Ctrl+M`).
    Bookmarks,
    /// The image is parsed (a stage, not an action).
    StageImage,
    /// The functions are recovered.
    StageFunctions,
    /// The cross-references are built.
    StageReferences,
    /// What callers read is computed.
    StageCallers,
    /// Every function's interface is found.
    StageWarmed,
    /// Closes the active tab.
    CloseTab,
    /// Closes the active pane.
    ClosePane,
    /// The next tab of the pane.
    NextTab,
    /// The previous tab of the pane.
    PreviousTab,
    /// Moves the focused tab one place left along its bar.
    MoveTabLeft,
    /// Moves the focused tab one place right along its bar.
    MoveTabRight,
    /// Moves the focused tab to the next pane (its pane closed if emptied).
    MoveTabToNextPane,
    /// Moves the focus to the pane on the left.
    FocusLeft,
    /// Moves the focus to the pane on the right.
    FocusRight,
    /// Moves the focus to the pane above.
    FocusUp,
    /// Moves the focus to the pane below.
    FocusDown,
    /// Moves the focus to the next pane.
    FocusNextPane,
    /// Makes the pane follow the shared cursor, or leave it.
    ToggleSync,
    /// Switches the focus between the listing and the C.
    SwitchView,
    /// About binbun.
    About,
    /// Lists binbun's folders with their sizes, each revealed in the file
    /// manager.
    FilesAndFolders,
    /// Opens the settings file.
    OpenSettingsFile,
    /// Opens binbun's symbol cache in the file manager.
    RevealSymbolCache,
    /// Opens binbun's projects folder in the file manager.
    RevealProjects,
    /// Removes binbun's symbol cache, once asked with the size it frees.
    ClearSymbolCache,
    /// Downloads the debug information the symbols bar offers.
    DownloadSymbols,
    /// Puts the symbols bar's offer away until the binary is opened again.
    SymbolsNotNow,
    /// Downloads the offered debug information, and from now on without
    /// asking (the setting).
    AlwaysDownloadSymbols,
    /// Shows every command and its keys (the palette).
    KeyMap,
    /// The cursor one line up.
    MoveUp,
    /// The cursor one line down.
    MoveDown,
    /// The cursor a page up.
    PageUp,
    /// The cursor a page down.
    PageDown,
    /// The cursor to the first line.
    Top,
    /// The cursor to the last line.
    Bottom,
    /// Shows the number under the cursor by the constants of an
    /// enumeration (`M`): a picker of those naming it.
    NumberEnum,
    /// Opens the type editor on a new enumeration.
    NewEnum,
    /// Opens the type editor on an enumeration: the one the number under
    /// the cursor is shown by, else one picked.
    EditEnum,
}

/// The menus of the menu bar, in order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Menu {
    /// File.
    File,
    /// Edit.
    Edit,
    /// View.
    View,
    /// Go.
    Go,
    /// Search.
    Search,
    /// Analysis.
    Analysis,
    /// Window.
    Window,
    /// Help.
    Help,
}

impl Menu {
    /// Every menu, in the menu bar's order.
    pub const ALL: [Self; 8] = [
        Self::File,
        Self::Edit,
        Self::View,
        Self::Go,
        Self::Search,
        Self::Analysis,
        Self::Window,
        Self::Help,
    ];

    /// Its title.
    pub fn title(self) -> &'static str {
        match self {
            Self::File => "File",
            Self::Edit => "Edit",
            Self::View => "View",
            Self::Go => "Go",
            Self::Search => "Search",
            Self::Analysis => "Analysis",
            Self::Window => "Window",
            Self::Help => "Help",
        }
    }
}

/// The most entries a menu (or a submenu) holds at one level, so that it
/// fits a 1280×720 window's height with its separators: more go in
/// submenus.
pub const MENU_LIMIT: usize = 22;

/// The submenus of the menus (Edit's and View's, Appearance),
/// each after its menu's own commands, in this order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Submenu {
    /// Edit: the number's form (hexadecimal, decimal, character, enum).
    Number,
    /// Edit: making, editing and deleting functions.
    Functions,
    /// Edit: the structs, and types laid over bytes.
    Structs,
    /// Edit: the hex selection copied as source.
    CopyAs,
    /// View: the theme, the fonts, the zoom, the feature map's place.
    Appearance,
    /// View: what the listing shows.
    ListingOptions,
    /// View: the graph's.
    GraphOptions,
    /// View: the hex view's.
    HexOptions,
    /// View: the call graph's levels.
    CallGraphLevels,
    /// View: the IR viewer's stages.
    IrStages,
    /// Analysis: the processor runs and verifications are on.
    Processor,
}

impl Submenu {
    /// Every submenu, in its menu's order.
    pub const ALL: [Self; 11] = [
        Self::Number,
        Self::Functions,
        Self::Structs,
        Self::CopyAs,
        Self::Appearance,
        Self::ListingOptions,
        Self::GraphOptions,
        Self::HexOptions,
        Self::CallGraphLevels,
        Self::IrStages,
        Self::Processor,
    ];

    /// Its title.
    pub fn title(self) -> &'static str {
        match self {
            Self::Number => "Number",
            Self::Functions => "Functions",
            Self::Structs => "Structs",
            Self::CopyAs => "Copy As",
            Self::Appearance => "Appearance",
            Self::ListingOptions => "Listing Options",
            Self::GraphOptions => "Graph Options",
            Self::HexOptions => "Hex Options",
            Self::CallGraphLevels => "Call Graph Levels",
            Self::IrStages => "IR Stages",
            Self::Processor => "Processor",
        }
    }

    /// The menu it is in.
    pub fn menu(self) -> Menu {
        match self {
            Self::Number | Self::Functions | Self::Structs | Self::CopyAs => Menu::Edit,
            Self::Appearance
            | Self::ListingOptions
            | Self::GraphOptions
            | Self::HexOptions
            | Self::CallGraphLevels
            | Self::IrStages => Menu::View,
            Self::Processor => Menu::Analysis,
        }
    }

    /// Its commands (of its menu; in the registry's order there).
    fn commands(self) -> &'static [Command] {
        use Command as C;
        match self {
            Self::Number => &[C::NumberHex, C::NumberDecimal, C::NumberChar, C::NumberEnum],
            Self::Functions => &[C::MakeFunction, C::EditFunction, C::DeleteFunction],
            Self::Structs => &[
                C::EditStruct,
                C::NewStruct,
                C::ApplyType,
                C::RemoveType,
                C::EditEnum,
                C::NewEnum,
            ],
            Self::CopyAs => &[C::CopyHex, C::CopyEscaped, C::CopyCArray],
            Self::Appearance => &[
                C::ToggleTheme,
                C::SelectTheme,
                C::ToggleLigatures,
                C::ToggleIslands,
                C::ZoomIn,
                C::ZoomOut,
                C::ZoomReset,
                C::MoveFeatureMap,
            ],
            Self::ListingOptions => &[
                C::ToggleOpcodeBytes,
                C::ToggleNumbers,
                C::ToggleSymbolic,
                C::CycleXrefs,
            ],
            Self::GraphOptions => &[C::FitGraph, C::ToggleOverview],
            Self::HexOptions => &[C::HexFileOffsets, C::HexEntropy, C::HexSide],
            Self::CallGraphLevels => &[
                C::MoreCallers,
                C::FewerCallers,
                C::MoreCallees,
                C::FewerCallees,
            ],
            Self::IrStages => &[C::IrPreviousStage, C::IrNextStage, C::ToggleIrDiff],
            Self::Processor => &[
                C::ProcessorArchitecture,
                C::ProcessorRaptorCove,
                C::ProcessorGracemont,
                C::ProcessorFile,
            ],
        }
    }
}

/// Where a command's keys work.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Scope {
    /// Anywhere in the window.
    Window,
    /// In a listing or C pane (not while typing in a field).
    Code,
    /// In a pane whose find bar is open (its field too).
    Find,
    /// Anywhere in the window but a pane whose find bar is open (there
    /// `Shift+F3`, Functions, is the find bar's Find Previous).
    OutsideFind,
    /// In the chat's message box.
    Chat,
}

impl Scope {
    /// The key context it binds in (GPUI's `key_context`).
    pub fn context(self) -> Option<&'static str> {
        match self {
            Self::Window => None,
            Self::Code => Some("Code"),
            Self::Find => Some("Find"),
            Self::OutsideFind => Some("!Find"),
            Self::Chat => Some("Chat"),
        }
    }
}

/// What the registry says of a command.
#[derive(Clone, Copy, Debug)]
pub struct Info {
    /// The command.
    pub command: Command,
    /// Its stable id (`[keys]` in the settings file names it).
    pub id: &'static str,
    /// Its title, in menus and the palette.
    pub title: &'static str,
    /// Its menu, if it has one.
    pub menu: Option<Menu>,
    /// Its default keys (GPUI keystrokes, `secondary-` Cmd on macOS and
    /// Ctrl elsewhere; a space separates the strokes of a sequence).
    pub keys: &'static [&'static str],
    /// Where its keys work.
    pub scope: Scope,
}

const fn info(
    command: Command,
    id: &'static str,
    title: &'static str,
    menu: Option<Menu>,
    keys: &'static [&'static str],
    scope: Scope,
) -> Info {
    Info {
        command,
        id,
        title,
        menu,
        keys,
        scope,
    }
}

use Command as C;
use Menu as M;
use Scope::{Code, Window};

/// Every command, in menu order.
pub const COMMANDS: &[Info] = &[
    info(
        C::Open,
        "file.open",
        "Open…",
        Some(M::File),
        &["secondary-o"],
        Window,
    ),
    info(
        C::OpenRecent,
        "file.open_recent",
        "Open Recent…",
        Some(M::File),
        &["secondary-r"],
        Window,
    ),
    info(
        C::ReopenSlice,
        "file.reopen_slice",
        "Reopen as Slice…",
        Some(M::File),
        &[],
        Window,
    ),
    info(
        C::SaveProject,
        "file.save",
        "Save Project",
        Some(M::File),
        &["secondary-s"],
        Window,
    ),
    info(
        C::ExportProject,
        "file.export_project",
        "Export Project…",
        Some(M::File),
        &[],
        Window,
    ),
    info(
        C::ImportProject,
        "file.import_project",
        "Import Project…",
        Some(M::File),
        &[],
        Window,
    ),
    info(
        C::ShareProject,
        "file.share",
        "Share…",
        Some(M::File),
        &[],
        Window,
    ),
    info(
        C::JoinSession,
        "file.join",
        "Join…",
        Some(M::File),
        &[],
        Window,
    ),
    info(
        C::CopyIdentityCard,
        "file.copy_identity_card",
        "Copy My Identity Card",
        Some(M::File),
        &[],
        Window,
    ),
    info(
        C::ConnectAgent,
        "file.connect_agent",
        "Connect an Agent…",
        Some(M::File),
        &[],
        Window,
    ),
    info(
        C::LeaveSession,
        "file.leave_session",
        "Stop Sharing",
        Some(M::File),
        &[],
        Window,
    ),
    info(
        C::BringValues,
        "file.bring_values",
        "Bring From Your Own Project…",
        Some(M::File),
        &[],
        Window,
    ),
    info(
        C::SessionPanel,
        "window.session",
        "Session",
        Some(M::Window),
        &["secondary-k s"],
        Window,
    ),
    info(
        C::InsertLocation,
        "chat.insert_location",
        "Insert Location",
        None,
        &["secondary-l"],
        Scope::Chat,
    ),
    info(
        C::Conflicts,
        "window.conflicts",
        "Conflicts",
        Some(M::Window),
        &[],
        Window,
    ),
    info(
        C::Threads,
        "window.threads",
        "Threads",
        Some(M::Window),
        &["secondary-k d"],
        Window,
    ),
    info(
        C::History,
        "window.history",
        "History",
        Some(M::Window),
        &["secondary-k h"],
        Window,
    ),
    info(
        C::Settings,
        "view.settings",
        "Settings…",
        Some(M::File),
        &["secondary-,"],
        Window,
    ),
    info(
        C::OpenSettingsFile,
        "help.settings_file",
        "Open Settings File",
        Some(M::File),
        &[],
        Window,
    ),
    info(
        C::KeyMap,
        "help.keymap",
        "Key Map",
        Some(M::File),
        &[],
        Window,
    ),
    info(
        C::RevealSymbolCache,
        "file.reveal_symbol_cache",
        "Reveal Symbol Cache",
        Some(M::File),
        &[],
        Window,
    ),
    info(
        C::RevealProjects,
        "file.reveal_projects",
        "Reveal Projects",
        Some(M::File),
        &[],
        Window,
    ),
    info(
        C::ClearSymbolCache,
        "file.clear_symbol_cache",
        "Clear Symbol Cache…",
        Some(M::File),
        &[],
        Window,
    ),
    info(C::Close, "file.close", "Close", Some(M::File), &[], Window),
    info(
        C::Quit,
        "file.quit",
        "Quit",
        Some(M::File),
        &["secondary-q"],
        Window,
    ),
    info(
        C::Undo,
        "edit.undo",
        "Undo",
        Some(M::Edit),
        &["secondary-z"],
        Window,
    ),
    info(
        C::Redo,
        "edit.redo",
        "Redo",
        Some(M::Edit),
        &["secondary-shift-z", "secondary-y"],
        Window,
    ),
    info(
        C::Rename,
        "edit.rename",
        "Rename",
        Some(M::Edit),
        &["n", "f2"],
        Code,
    ),
    info(
        C::SetType,
        "edit.set_type",
        "Set Type…",
        Some(M::Edit),
        &["y"],
        Code,
    ),
    info(
        C::EditStruct,
        "edit.struct",
        "Edit Struct",
        Some(M::Edit),
        &[],
        Code,
    ),
    info(
        C::NewStruct,
        "edit.new_struct",
        "New Struct",
        Some(M::Edit),
        &[],
        Window,
    ),
    info(
        C::Comment,
        "edit.comment",
        "Comment",
        Some(M::Edit),
        &[";"],
        Code,
    ),
    info(
        C::StartThread,
        "edit.start_thread",
        "Start Thread",
        Some(M::Edit),
        &["secondary-k c"],
        Code,
    ),
    info(
        C::MakeCode,
        "edit.code",
        "Code",
        Some(M::Edit),
        &["c"],
        Code,
    ),
    info(
        C::Undefine,
        "edit.undefine",
        "Undefine",
        Some(M::Edit),
        &["u"],
        Code,
    ),
    info(C::Data, "edit.data", "Data", Some(M::Edit), &["d"], Code),
    info(
        C::MakeString,
        "edit.string",
        "String",
        Some(M::Edit),
        &["a"],
        Code,
    ),
    info(
        C::MakeArray,
        "edit.array",
        "Array…",
        Some(M::Edit),
        &["*"],
        Code,
    ),
    info(
        C::MakeFunction,
        "edit.function",
        "Create Function",
        Some(M::Edit),
        &["p"],
        Code,
    ),
    info(
        C::EditFunction,
        "edit.function_end",
        "Edit Function…",
        Some(M::Edit),
        &["alt-p"],
        Code,
    ),
    info(
        C::DeleteFunction,
        "edit.delete_function",
        "Delete Function",
        Some(M::Edit),
        &[],
        Code,
    ),
    info(
        C::CopyAddress,
        "edit.copy_address",
        "Copy Address",
        Some(M::Edit),
        &["secondary-shift-c"],
        Code,
    ),
    info(
        C::CopyName,
        "edit.copy_name",
        "Copy Name",
        Some(M::Edit),
        &["secondary-c"],
        Code,
    ),
    info(
        C::SelectAll,
        "edit.select_all",
        "Select All",
        Some(M::Edit),
        &["secondary-a"],
        Code,
    ),
    info(
        C::NumberHex,
        "edit.number_hex",
        "Hexadecimal",
        Some(M::Edit),
        &["h"],
        Code,
    ),
    info(
        C::NumberDecimal,
        "edit.number_decimal",
        "Decimal",
        Some(M::Edit),
        &[],
        Code,
    ),
    info(
        C::NumberChar,
        "edit.number_char",
        "Character",
        Some(M::Edit),
        &["r"],
        Code,
    ),
    info(
        C::CopyHex,
        "edit.copy_hex",
        "Copy as Hex",
        Some(M::Edit),
        &[],
        Code,
    ),
    info(
        C::CopyEscaped,
        "edit.copy_escaped",
        "Copy as Escaped Bytes",
        Some(M::Edit),
        &[],
        Code,
    ),
    info(
        C::CopyCArray,
        "edit.copy_c_array",
        "Copy as C Array",
        Some(M::Edit),
        &[],
        Code,
    ),
    info(
        C::ApplyType,
        "edit.apply_type",
        "Apply Type…",
        Some(M::Edit),
        &["alt-q"],
        Code,
    ),
    info(
        C::RemoveType,
        "edit.remove_type",
        "Remove Type",
        Some(M::Edit),
        &[],
        Code,
    ),
    info(
        C::OpenListing,
        "view.listing",
        "Listing",
        Some(M::View),
        &[],
        Window,
    ),
    info(C::OpenC, "view.c", "C", Some(M::View), &["f5"], Window),
    info(
        C::ToggleReadingView,
        "view.reading",
        "Reading View",
        Some(M::View),
        &["secondary-k r"],
        Window,
    ),
    info(
        C::ToggleGraph,
        "view.graph_toggle",
        "Graph View",
        Some(M::View),
        &["space"],
        Code,
    ),
    info(
        C::ToggleHex,
        "view.hex",
        "Hex View",
        Some(M::View),
        &[],
        Code,
    ),
    info(
        C::ToggleUnified,
        "view.unified",
        "Unified View",
        Some(M::View),
        &[],
        Code,
    ),
    info(
        C::ToggleCalls,
        "view.calls",
        "Call Graph",
        Some(M::View),
        &["secondary-f12"],
        Code,
    ),
    info(
        C::ShowInIr,
        "view.ir",
        "IR View",
        Some(M::View),
        &["secondary-k i"],
        Window,
    ),
    info(
        C::SplitRight,
        "view.split_right",
        "Split Right",
        Some(M::View),
        &["secondary-k right"],
        Window,
    ),
    info(
        C::SplitDown,
        "view.split_down",
        "Split Down",
        Some(M::View),
        &["secondary-k down"],
        Window,
    ),
    info(
        C::OpenGraphInSplit,
        "view.graph_in_split",
        "Open Graph in Split",
        Some(M::View),
        &["secondary-k g"],
        Window,
    ),
    info(
        C::ToggleLeftSidebar,
        "view.left_sidebar",
        "Left Sidebar",
        Some(M::View),
        &["secondary-b"],
        Window,
    ),
    info(
        C::ToggleRightSidebar,
        "view.right_sidebar",
        "Right Sidebar",
        Some(M::View),
        &["secondary-alt-b"],
        Window,
    ),
    info(
        C::ToggleConsole,
        "view.console",
        "Console",
        Some(M::View),
        // Ctrl on macOS too, as VS Code's terminal (Cmd+Backtick cycles the
        // app's windows there).
        &["ctrl-`"],
        Window,
    ),
    info(
        C::NewTerminal,
        "window.new_terminal",
        "New Terminal",
        // Beside the panes the Window menu opens (View is full).
        Some(M::Window),
        // Ctrl+Shift+Backtick (the key a shifted backtick types, as the
        // other shifted keys); Ctrl on macOS too, as the console's.
        &["ctrl-~"],
        Window,
    ),
    info(
        C::NewAgent,
        "window.new_agent",
        "New Agent",
        Some(M::Window),
        &[],
        Window,
    ),
    info(
        C::ToggleFeatureMap,
        "view.feature_map",
        "Feature Map",
        Some(M::View),
        &[],
        Window,
    ),
    info(
        C::Palette,
        "view.palette",
        "Command Palette",
        Some(M::View),
        &["secondary-shift-p"],
        Window,
    ),
    info(
        C::OpenAsTab,
        "view.open_as_tab",
        "Open as Tab",
        None,
        &[],
        Window,
    ),
    info(
        C::IrPreviousStage,
        "view.ir_previous",
        "Previous IR Stage",
        Some(M::View),
        &["<"],
        Code,
    ),
    info(
        C::IrNextStage,
        "view.ir_next",
        "Next IR Stage",
        Some(M::View),
        &[">"],
        Code,
    ),
    info(
        C::ToggleIrDiff,
        "view.ir_diff",
        "IR Diff with Previous",
        Some(M::View),
        &[],
        Window,
    ),
    info(
        C::ToggleOpcodeBytes,
        "view.opcode_bytes",
        "Opcode Bytes",
        Some(M::View),
        &[],
        Window,
    ),
    info(
        C::ToggleNumbers,
        "view.c_numbers",
        "C-Style Numbers",
        Some(M::View),
        &[],
        Window,
    ),
    info(
        C::ToggleSymbolic,
        "view.symbolic",
        "Names in Operands",
        Some(M::View),
        &[],
        Window,
    ),
    info(
        C::CycleXrefs,
        "view.xrefs",
        "Cross-References per Item",
        Some(M::View),
        &[],
        Window,
    ),
    info(
        C::ToggleTheme,
        "view.theme",
        "Dark Theme",
        Some(M::View),
        &["secondary-k t"],
        Window,
    ),
    info(
        C::SelectTheme,
        "view.select_theme",
        "Select Theme…",
        Some(M::View),
        &["secondary-k secondary-t"],
        Window,
    ),
    info(
        C::ToggleLigatures,
        "view.ligatures",
        "Ligatures",
        Some(M::View),
        &[],
        Window,
    ),
    info(
        C::ToggleIslands,
        "view.islands",
        "Island Panes",
        Some(M::View),
        &[],
        Window,
    ),
    info(
        C::ZoomIn,
        "view.zoom_in",
        "Zoom In",
        Some(M::View),
        &["secondary-=", "secondary-+"],
        Window,
    ),
    info(
        C::ZoomOut,
        "view.zoom_out",
        "Zoom Out",
        Some(M::View),
        &["secondary--"],
        Window,
    ),
    info(
        C::ZoomReset,
        "view.zoom_reset",
        "Actual Size",
        Some(M::View),
        &["secondary-0"],
        Window,
    ),
    info(
        C::MoveFeatureMap,
        "view.feature_map_place",
        "Feature Map at the Top",
        Some(M::View),
        &[],
        Window,
    ),
    info(
        C::FitGraph,
        "view.fit_graph",
        "Fit Graph",
        Some(M::View),
        &["w"],
        Code,
    ),
    info(
        C::ToggleOverview,
        "view.graph_overview",
        "Graph Overview",
        Some(M::View),
        &["alt-o"],
        Code,
    ),
    info(
        C::HexFileOffsets,
        "view.hex_offsets",
        "File Offsets",
        Some(M::View),
        &[],
        Code,
    ),
    info(
        C::HexEntropy,
        "view.hex_entropy",
        "Overview by Entropy",
        Some(M::View),
        &[],
        Code,
    ),
    info(
        C::HexSide,
        "view.hex_side",
        "Structure and Inspector",
        Some(M::View),
        &[],
        Code,
    ),
    info(
        C::MoreCallers,
        "view.calls_more_callers",
        "More Caller Levels",
        Some(M::View),
        &[],
        Code,
    ),
    info(
        C::FewerCallers,
        "view.calls_fewer_callers",
        "Fewer Caller Levels",
        Some(M::View),
        &[],
        Code,
    ),
    info(
        C::MoreCallees,
        "view.calls_more_callees",
        "More Callee Levels",
        Some(M::View),
        &[],
        Code,
    ),
    info(
        C::FewerCallees,
        "view.calls_fewer_callees",
        "Fewer Callee Levels",
        Some(M::View),
        &[],
        Code,
    ),
    info(
        C::Find,
        "search.find",
        "Find…",
        Some(M::Search),
        &["secondary-f"],
        Window,
    ),
    info(
        C::FindNext,
        "search.next",
        "Find Next",
        Some(M::Search),
        &["f3"],
        Scope::Find,
    ),
    info(
        C::FindPrevious,
        "search.previous",
        "Find Previous",
        Some(M::Search),
        &["shift-f3"],
        Scope::Find,
    ),
    info(
        C::SearchEverywhere,
        "search.everywhere",
        "Search Everywhere…",
        Some(M::Search),
        &["secondary-shift-f", "alt-t"],
        Window,
    ),
    info(
        C::SearchBytes,
        "search.bytes",
        "Search Bytes…",
        Some(M::Search),
        &["alt-b"],
        Window,
    ),
    info(
        C::SearchImmediate,
        "search.immediate",
        "Search Immediate…",
        Some(M::Search),
        &["alt-i"],
        Window,
    ),
    info(
        C::StopSearch,
        "search.stop",
        "Stop Search",
        Some(M::Search),
        &[],
        Window,
    ),
    info(
        C::GoAnywhere,
        "go.anywhere",
        "Go Anywhere…",
        Some(M::Go),
        &["g"],
        Code,
    ),
    info(
        C::Back,
        "go.back",
        "Back",
        Some(M::Go),
        &["escape", "alt-left"],
        Code,
    ),
    info(
        C::Forward,
        "go.forward",
        "Forward",
        Some(M::Go),
        &["secondary-enter", "alt-right"],
        Code,
    ),
    info(
        C::Follow,
        "go.follow",
        "Follow",
        Some(M::Go),
        &["enter"],
        Code,
    ),
    info(
        C::ShowInHex,
        "go.show_in_hex",
        "Show in Hex",
        Some(M::Go),
        &[],
        Code,
    ),
    info(
        C::Pathfinder,
        "go.pathfinder",
        "Pathfinder",
        Some(M::Go),
        &[],
        Window,
    ),
    info(
        C::PathFrom,
        "go.path_from",
        "Path from Here",
        Some(M::Go),
        &[],
        Code,
    ),
    info(
        C::PathTo,
        "go.path_to",
        "Path to Here",
        Some(M::Go),
        &[],
        Code,
    ),
    info(
        C::WholeSubgraph,
        "go.whole_subgraph",
        "Whole Subgraph",
        Some(M::Go),
        &[],
        Window,
    ),
    info(
        C::CallerArguments,
        "go.caller_arguments",
        "Callers with Arguments",
        Some(M::Go),
        &[],
        Window,
    ),
    info(
        C::Xrefs,
        "go.xrefs",
        "Cross-References",
        Some(M::Go),
        &["x"],
        Code,
    ),
    info(
        C::OpenInNewPane,
        "go.new_pane",
        "Open in New Pane",
        Some(M::Go),
        &[],
        Code,
    ),
    info(
        C::Peek,
        "go.peek",
        "Peek",
        Some(M::Go),
        &["secondary-k secondary-i"],
        Code,
    ),
    info(
        C::Origin,
        "go.origin",
        "Value Origin",
        Some(M::Go),
        &["shift-x"],
        Code,
    ),
    info(
        C::Verify,
        "analysis.verify",
        "Verify Function",
        Some(M::Analysis),
        &[],
        Window,
    ),
    info(C::Why, "analysis.why", "Why…", Some(M::Analysis), &[], Code),
    info(
        C::RejectSignature,
        "analysis.reject_signature",
        "Reject Signature",
        Some(M::Analysis),
        &[],
        Code,
    ),
    info(
        C::RunFromHere,
        "analysis.run",
        "Run from Here…",
        Some(M::Analysis),
        &[],
        Code,
    ),
    info(
        C::CompareProcessors,
        "analysis.compare_processors",
        "Compare Processors",
        Some(M::Analysis),
        &[],
        Window,
    ),
    info(
        C::ProcessorArchitecture,
        "analysis.processor.architecture",
        "Architecture",
        Some(M::Analysis),
        &[],
        Window,
    ),
    info(
        C::ProcessorRaptorCove,
        "analysis.processor.raptor_cove",
        "Intel Raptor Cove",
        Some(M::Analysis),
        &[],
        Window,
    ),
    info(
        C::ProcessorGracemont,
        "analysis.processor.gracemont",
        "Intel Gracemont",
        Some(M::Analysis),
        &[],
        Window,
    ),
    info(
        C::ProcessorFile,
        "analysis.processor.file",
        "Profile File…",
        Some(M::Analysis),
        &[],
        Window,
    ),
    info(
        C::NextFunction,
        "go.next_function",
        "Next Function",
        Some(M::Go),
        &["secondary-down"],
        Code,
    ),
    info(
        C::PreviousFunction,
        "go.previous_function",
        "Previous Function",
        Some(M::Go),
        &["secondary-up"],
        Code,
    ),
    info(
        C::Functions,
        "go.functions",
        "Functions",
        Some(M::Go),
        &["shift-f3"],
        Scope::OutsideFind,
    ),
    info(
        C::Strings,
        "go.strings",
        "Strings",
        Some(M::Go),
        &["shift-f12"],
        Window,
    ),
    info(
        C::Bookmark,
        "go.bookmark",
        "Bookmark…",
        Some(M::Go),
        &["alt-m"],
        Code,
    ),
    info(
        C::Bookmarks,
        "go.bookmarks",
        "Bookmarks",
        Some(M::Go),
        // Ctrl on macOS too: Cmd+M is the window's Minimize there.
        &["ctrl-m"],
        Window,
    ),
    info(
        C::StageImage,
        "analysis.image",
        "Image Parsed",
        Some(M::Analysis),
        &[],
        Window,
    ),
    info(
        C::StageFunctions,
        "analysis.functions",
        "Functions Recovered",
        Some(M::Analysis),
        &[],
        Window,
    ),
    info(
        C::StageReferences,
        "analysis.references",
        "Cross-References Built",
        Some(M::Analysis),
        &[],
        Window,
    ),
    info(
        C::StageCallers,
        "analysis.callers",
        "Callers Read",
        Some(M::Analysis),
        &[],
        Window,
    ),
    info(
        C::StageWarmed,
        "analysis.warmed",
        "Interfaces Found",
        Some(M::Analysis),
        &[],
        Window,
    ),
    info(
        C::FocusNextPane,
        "window.next_pane",
        "Next Pane",
        Some(M::Window),
        &["secondary-k secondary-o"],
        Window,
    ),
    info(
        C::FocusLeft,
        "window.focus_left",
        "Focus Left",
        Some(M::Window),
        &["secondary-k secondary-left"],
        Window,
    ),
    info(
        C::FocusRight,
        "window.focus_right",
        "Focus Right",
        Some(M::Window),
        &["secondary-k secondary-right"],
        Window,
    ),
    info(
        C::FocusUp,
        "window.focus_up",
        "Focus Up",
        Some(M::Window),
        &["secondary-k secondary-up"],
        Window,
    ),
    info(
        C::FocusDown,
        "window.focus_down",
        "Focus Down",
        Some(M::Window),
        &["secondary-k secondary-down"],
        Window,
    ),
    info(
        C::SwitchView,
        "window.switch_view",
        "Switch Listing and C",
        Some(M::Window),
        &["tab"],
        Code,
    ),
    info(
        C::ToggleSync,
        "window.sync",
        "Link Pane",
        Some(M::Window),
        &[],
        Window,
    ),
    info(
        C::NextTab,
        "window.next_tab",
        "Next Tab",
        Some(M::Window),
        &["secondary-pagedown"],
        Window,
    ),
    info(
        C::PreviousTab,
        "window.previous_tab",
        "Previous Tab",
        Some(M::Window),
        &["secondary-pageup"],
        Window,
    ),
    info(
        C::MoveTabLeft,
        "view.move_tab_left",
        "Move Tab Left",
        Some(M::Window),
        &["secondary-shift-pageup"],
        Window,
    ),
    info(
        C::MoveTabRight,
        "view.move_tab_right",
        "Move Tab Right",
        Some(M::Window),
        &["secondary-shift-pagedown"],
        Window,
    ),
    info(
        C::MoveTabToNextPane,
        "view.move_tab_to_next_pane",
        "Move Tab to Next Pane",
        Some(M::Window),
        &["secondary-k m"],
        Window,
    ),
    info(
        C::CloseTab,
        "window.close_tab",
        "Close Tab",
        Some(M::Window),
        &["secondary-w"],
        Window,
    ),
    info(
        C::KeepTab,
        "window.keep_tab",
        "Keep Tab",
        Some(M::Window),
        &[],
        Window,
    ),
    info(
        C::ClosePane,
        "window.close_pane",
        "Close Pane",
        Some(M::Window),
        &["secondary-k w"],
        Window,
    ),
    info(
        C::ToggleMaximize,
        "window.maximize",
        "Maximize Pane",
        Some(M::Window),
        &["shift-escape"],
        Window,
    ),
    info(
        C::FilesAndFolders,
        "help.files_and_folders",
        "Files and Folders…",
        Some(M::Help),
        &[],
        Window,
    ),
    info(
        C::About,
        "help.about",
        "About binbun",
        Some(M::Help),
        &[],
        Window,
    ),
    info(
        C::DownloadSymbols,
        "symbols.fetch",
        "Download Symbols",
        None,
        &[],
        Window,
    ),
    info(
        C::SymbolsNotNow,
        "symbols.not_now",
        "Not Now",
        None,
        &[],
        Window,
    ),
    info(
        C::AlwaysDownloadSymbols,
        "symbols.always",
        "Always Download Symbols",
        None,
        &[],
        Window,
    ),
    info(C::MoveUp, "cursor.up", "Cursor Up", None, &["up"], Code),
    info(
        C::MoveDown,
        "cursor.down",
        "Cursor Down",
        None,
        &["down"],
        Code,
    ),
    info(
        C::PageUp,
        "cursor.page_up",
        "Page Up",
        None,
        &["pageup"],
        Code,
    ),
    info(
        C::PageDown,
        "cursor.page_down",
        "Page Down",
        None,
        &["pagedown"],
        Code,
    ),
    info(
        C::Top,
        "cursor.top",
        "Cursor to the Top",
        None,
        &["secondary-home"],
        Code,
    ),
    info(
        C::Bottom,
        "cursor.bottom",
        "Cursor to the Bottom",
        None,
        &["secondary-end"],
        Code,
    ),
    info(
        C::NumberEnum,
        "edit.number_enum",
        "Enum…",
        Some(M::Edit),
        &["m"],
        Code,
    ),
    info(
        C::EditEnum,
        "edit.edit_enum",
        "Edit Enum…",
        Some(M::Edit),
        &[],
        Window,
    ),
    info(
        C::NewEnum,
        "edit.new_enum",
        "New Enum",
        Some(M::Edit),
        &[],
        Window,
    ),
];

/// Where separators go in the menus and submenus: before these commands.
const GROUPS: &[Command] = &[
    C::SaveProject,
    C::Settings,
    C::Close,
    C::Rename,
    C::MakeCode,
    C::CopyAddress,
    C::ApplyType,
    C::SplitRight,
    C::ToggleLeftSidebar,
    C::ZoomIn,
    C::MoveFeatureMap,
    C::Palette,
    C::MoreCallees,
    C::Follow,
    C::Pathfinder,
    C::NextFunction,
    C::Functions,
    C::Bookmark,
    C::StageImage,
    C::SearchEverywhere,
    C::SwitchView,
    C::NextTab,
    C::MoveTabLeft,
    C::CloseTab,
    C::About,
];

/// The registry's entry for `command`.
pub fn lookup(command: Command) -> Option<&'static Info> {
    COMMANDS.iter().find(|info| info.command == command)
}

/// Whether the command palette lists `info`'s command: every command a
/// menu holds but the analysis stages (the Analysis menu's marks of how
/// far it got, not actions), and the window's commands no menu holds
/// (not the cursor moves of a view).
pub fn in_palette(info: &Info) -> bool {
    match info.menu {
        Some(_) => !matches!(
            info.command,
            C::StageImage
                | C::StageFunctions
                | C::StageReferences
                | C::StageCallers
                | C::StageWarmed
        ),
        None => info.scope == Window,
    }
}

/// `command`'s title under `facts`: the graph's toggle names the view it
/// switches to; Copy Name over a listing's or the C's selection copies it.
pub fn title(command: Command, facts: &Facts) -> &'static str {
    if command == C::ToggleGraph && facts.graph {
        return "Text View";
    }
    if command == C::CopyName && facts.selection {
        return "Copy";
    }
    if command == C::MoveFeatureMap && facts.feature_map_top {
        return "Feature Map at the Right";
    }
    lookup(command).map_or("", |i| i.title)
}

/// Undo's title when the change it would undo (`next`) is an agent's:
/// `Undo Codex: Rename helpers of main` (its label names the agent); else
/// none (the registry's `Undo`).
pub fn undo_title(next: Option<&HistoryEntry>) -> Option<String> {
    next.filter(|entry| entry.origin == Origin::Agent)
        .map(|entry| format!("Undo {}", entry.label))
}

/// The entry with id `id`.
pub fn by_id(id: &str) -> Option<&'static Info> {
    COMMANDS.iter().find(|info| info.id == id)
}

/// An entry of a menu.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Entry {
    /// A command.
    Command(Command),
    /// A submenu: its title and entries.
    Submenu {
        /// Its title.
        label: &'static str,
        /// Its entries.
        entries: Vec<Entry>,
    },
    /// A separator.
    Separator,
}

/// Menu `menu`'s entries, in order, separators between groups: its own
/// commands, then its submenus.
pub fn menu(menu: Menu) -> Vec<Entry> {
    let mut entries = grouped(
        |c| Submenu::ALL.iter().all(|s| !s.commands().contains(&c)),
        menu,
    );
    for sub in Submenu::ALL.into_iter().filter(|s| s.menu() == menu) {
        if matches!(entries.last(), Some(Entry::Command(_))) {
            entries.push(Entry::Separator);
        }
        entries.push(Entry::Submenu {
            label: sub.title(),
            entries: grouped(|c| sub.commands().contains(&c), menu),
        });
    }
    entries
}

/// Menu `menu`'s entries as the window shows them now: [`menu`]'s, less
/// the processors that do not fit the open image ([`Processor::fits`]).
pub fn menu_for(menu: Menu, facts: &Facts) -> Vec<Entry> {
    fn listed(entries: Vec<Entry>, facts: &Facts) -> Vec<Entry> {
        entries
            .into_iter()
            .filter_map(|entry| match entry {
                Entry::Command(c) => Processor::chosen_by(c)
                    .is_none_or(|p| p.fits(facts))
                    .then_some(entry),
                Entry::Submenu { label, entries } => Some(Entry::Submenu {
                    label,
                    entries: listed(entries, facts),
                }),
                Entry::Separator => Some(entry),
            })
            .collect()
    }
    listed(self::menu(menu), facts)
}

/// The commands of `menu` that `keep` keeps, in the registry's order,
/// separators between groups.
fn grouped(keep: impl Fn(Command) -> bool, menu: Menu) -> Vec<Entry> {
    let mut entries = Vec::new();
    for info in COMMANDS
        .iter()
        .filter(|info| info.menu == Some(menu) && keep(info.command))
    {
        if !entries.is_empty() && GROUPS.contains(&info.command) {
            entries.push(Entry::Separator);
        }
        entries.push(Entry::Command(info.command));
    }
    entries
}

/// The processor runs and verifications are on (the project's private
/// setting, [`binbun_session::Session::processor`]).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Processor {
    /// None: the architecture, undefined values unknown.
    #[default]
    Architecture,
    /// The shipped `intel-raptor-cove`.
    RaptorCove,
    /// The shipped `intel-gracemont`.
    Gracemont,
    /// A profile file.
    File,
}

impl Processor {
    /// Every choice, in the submenu's order.
    pub const ALL: [Self; 4] = [
        Self::Architecture,
        Self::RaptorCove,
        Self::Gracemont,
        Self::File,
    ];

    /// The shipped profiles, in the submenu's order ([`Facts::fitting`]).
    pub const SHIPPED: [Self; 2] = [Self::RaptorCove, Self::Gracemont];

    /// The setting `name` (a shipped profile's name or a file's path).
    pub fn of(name: Option<&str>) -> Self {
        let Some(name) = name else {
            return Self::Architecture;
        };
        Self::ALL
            .into_iter()
            .find(|p| p.name() == Some(name))
            .unwrap_or(Self::File)
    }

    /// The choice `command` makes, if it chooses the processor.
    pub fn chosen_by(command: Command) -> Option<Self> {
        Self::ALL.into_iter().find(|p| p.command() == command)
    }

    /// Whether it may be chosen for the open image: the architecture
    /// always, a shipped profile if it fits ([`Facts::fitting`]), a file
    /// where any does (profiles are for one architecture).
    pub fn fits(self, facts: &Facts) -> bool {
        match self {
            Self::Architecture => true,
            Self::File => facts.fitting.contains(&true),
            Self::RaptorCove | Self::Gracemont => Self::SHIPPED
                .into_iter()
                .zip(facts.fitting)
                .any(|(shipped, fits)| shipped == self && fits),
        }
    }

    /// The shipped profile's name, if it is one.
    pub const fn name(self) -> Option<&'static str> {
        match self {
            Self::RaptorCove => Some("intel-raptor-cove"),
            Self::Gracemont => Some("intel-gracemont"),
            Self::Architecture | Self::File => None,
        }
    }

    /// The command choosing it.
    pub const fn command(self) -> Command {
        match self {
            Self::Architecture => C::ProcessorArchitecture,
            Self::RaptorCove => C::ProcessorRaptorCove,
            Self::Gracemont => C::ProcessorGracemont,
            Self::File => C::ProcessorFile,
        }
    }
}

/// What decides whether commands are enabled and checked.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "independent facts about the window"
)]
pub struct Facts {
    /// A binary is open.
    pub open: bool,
    /// The processor runs and verifications are on.
    pub processor: Processor,
    /// Whether each of [`Processor::SHIPPED`] fits the open image's
    /// architecture (`binbun::profile::fits`; none before it is parsed).
    pub fitting: [bool; 2],
    /// How far its analysis is: 0 opening, 1 image, 2 functions, 3
    /// references, 4 callers, 5 warmed.
    pub stage: u8,
    /// Something renamable is under the cursor.
    pub renamable: bool,
    /// A row's context menu is open: its commands are about its row.
    pub subject: bool,
    /// A struct is under the cursor (its name, or a variable of it or a
    /// pointer to it).
    pub structure: bool,
    /// The focused pane shows a type in a tab of its own (Cross
    /// References finds where it is used).
    pub typed: bool,
    /// The variable under the cursor has evidence to explain (not only
    /// defaults), or a function's name is under it.
    pub explained: bool,
    /// A library signature names the function under the cursor (else the
    /// cursor's).
    pub signature: bool,
    /// A number is under the cursor.
    pub number: bool,
    /// The number under the cursor is printable as a character constant.
    pub printable: bool,
    /// A name of an address (a function, a global) is under the cursor.
    pub named: bool,
    /// The cursor is on an address.
    pub address: bool,
    /// The focused listing or C selects something (Copy takes it).
    pub selection: bool,
    /// The focused pane shows text Select All takes: the C, or the
    /// listing (as text) within a function.
    pub selectable: bool,
    /// There is an edit to undo.
    pub undo: bool,
    /// There is an undone edit to redo.
    pub redo: bool,
    /// The history goes back.
    pub back: bool,
    /// The history goes forward.
    pub forward: bool,
    /// The focused pane shows C in the reading view.
    pub reading: bool,
    /// The focused pane shows the settings.
    pub settings: bool,
    /// The focused pane shows the IR viewer.
    pub ir: bool,
    /// The focused pane's IR viewer shows the removed lines.
    pub ir_diff: bool,
    /// The focused pane follows the shared cursor.
    pub synced: bool,
    /// More than one pane is open.
    pub panes: bool,
    /// The focused pane is shown alone.
    pub maximized: bool,
    /// The left sidebar is shown.
    pub left_sidebar: bool,
    /// The right sidebar is shown.
    pub right_sidebar: bool,
    /// The console is shown.
    pub console: bool,
    /// The feature map is shown.
    pub feature_map: bool,
    /// It is at the top of the panes (else at their right).
    pub feature_map_top: bool,
    /// A folder of the map is the context menu's subject, or selected in
    /// the map: Open as Tab opens it.
    pub folder: bool,
    /// The theme is dark.
    pub dark: bool,
    /// The listing shows opcode bytes.
    pub opcode_bytes: bool,
    /// The listing writes numbers as C does.
    pub c_numbers: bool,
    /// The listing writes names in operands.
    pub symbolic: bool,
    /// Ligatures are on.
    pub ligatures: bool,
    /// Panes are islands.
    pub islands: bool,
    /// The focused pane shows a graph.
    pub graph: bool,
    /// The cursor is in a function (its graph can be shown).
    pub function: bool,
    /// Graphs show their overview.
    pub overview: bool,
    /// The focused pane shows the hex view.
    pub hex: bool,
    /// The focused pane shows the unified listing.
    pub unified: bool,
    /// The focused hex view shows file offsets.
    pub file_offsets: bool,
    /// The focused hex view's overview shows entropy.
    pub entropy: bool,
    /// The focused hex view's side area is on (not hidden by the user).
    pub hex_side: bool,
    /// The user laid a type over the hex cursor.
    pub user_type: bool,
    /// The focused pane shows the call graph.
    pub calls: bool,
    /// The Pathfinder is open.
    pub pathfinder: bool,
    /// The focused call graph shows a path search's answer.
    pub paths: bool,
    /// It shows the search's whole subgraph.
    pub whole_subgraph: bool,
    /// The focused pane shows cross-references to a function.
    pub callers: bool,
    /// The focused cross-references tab shows the callers' arguments.
    pub caller_arguments: bool,
    /// The focused pane's active tab is a preview tab.
    pub preview: bool,
    /// The symbols bar offers the binary's debug information.
    pub symbols_offer: bool,
    /// The binary's debug information is being downloaded.
    pub downloading: bool,
    /// The focused pane shows what a find bar searches (a listing, a hex
    /// view, C).
    pub findable: bool,
    /// The focused pane's find bar is open.
    pub finding: bool,
    /// The focused results tab's search is running.
    pub searching: bool,
    /// The focused pane shows the listing (as text or as the graph).
    pub listing: bool,
    /// Why each correction of recovery cannot apply at the cursor.
    pub refusals: Refusals,
    /// The project is shared or joined (a live session).
    pub live: bool,
    /// The session panel is shown.
    pub session_panel: bool,
    /// The right dock shows the threads.
    pub threads_panel: bool,
    /// The right dock shows the history.
    pub history_panel: bool,
    /// A thread can start at the cursor (a listing, C or graph line).
    pub threadable: bool,
    /// This window is view-only in the shared session (a viewer, or
    /// another build than the host's): its edits would be refused.
    pub view_only: bool,
    /// The project open is a share's: values may be brought into it.
    pub share: bool,
    /// The binary open is one slice of a universal Mach-O file.
    pub universal: bool,
}

/// Why each correction of recovery ([`crate::corrections::Op`]) cannot
/// apply at the cursor of the listing or the hex view; `None`: it can.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Refusals {
    /// Code ([`Command::MakeCode`]).
    pub code: Option<&'static str>,
    /// Undefine ([`Command::Undefine`]).
    pub undefine: Option<&'static str>,
    /// Data ([`Command::Data`]).
    pub data: Option<&'static str>,
    /// A string ([`Command::MakeString`]).
    pub string: Option<&'static str>,
    /// An array ([`Command::MakeArray`]).
    pub array: Option<&'static str>,
    /// A function ([`Command::MakeFunction`]).
    pub function: Option<&'static str>,
    /// A function's end ([`Command::EditFunction`]).
    pub end: Option<&'static str>,
    /// A function deleted ([`Command::DeleteFunction`]).
    pub delete: Option<&'static str>,
}

/// A command's state in the menus and the palette.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct State {
    /// Whether it can run now.
    pub enabled: bool,
    /// Whether it is checked, if it is a toggle.
    pub checked: Option<bool>,
}

/// The call graph's, the Pathfinder's and the callers table's commands,
/// as a pattern: [`state`] hands them to [`calls_state`].
macro_rules! calls_commands {
    () => {
        C::ToggleCalls
            | C::MoreCallers
            | C::FewerCallers
            | C::MoreCallees
            | C::FewerCallees
            | C::Pathfinder
            | C::PathFrom
            | C::PathTo
            | C::WholeSubgraph
            | C::CallerArguments
            | C::KeepTab
    };
}

/// Whether `command` edits the project (its changes go into the log).
pub fn edits(command: Command) -> bool {
    matches!(
        command,
        C::Undo
            | C::Redo
            | C::Rename
            | C::SetType
            | C::Data
            | C::MakeCode
            | C::Undefine
            | C::MakeString
            | C::MakeArray
            | C::MakeFunction
            | C::EditFunction
            | C::DeleteFunction
            | C::EditStruct
            | C::NewStruct
            | C::Comment
            | C::RejectSignature
            | C::NumberHex
            | C::NumberDecimal
            | C::NumberChar
            | C::Bookmark
            | C::NumberEnum
            | C::NewEnum
            | C::EditEnum
    )
}

/// `command`'s state under `facts`: an edit is off in a view-only
/// session.
pub fn state(command: Command, facts: &Facts) -> State {
    let state = state_of(command, facts);
    if facts.view_only && edits(command) {
        return State {
            enabled: false,
            ..state
        };
    }
    state
}

/// `command`'s state under `facts`, edits allowed.
#[expect(clippy::too_many_lines, reason = "one arm per command")]
fn state_of(command: Command, facts: &Facts) -> State {
    let pane_toggle = |checked: bool| pane_toggle(facts, checked);
    let stage = |reached: u8| stage(facts, reached);
    let analysed = facts.open && facts.stage >= 2;
    // A hex view's toggle: on in a hex view, checked as it is.
    let hex_toggle = |checked: bool| State {
        enabled: facts.hex,
        checked: Some(checked),
    };
    match command {
        C::Open
        | C::OpenRecent
        | C::ImportProject
        | C::CopyIdentityCard
        | C::ConnectAgent
        | C::Quit
        | C::Settings
        | C::Palette
        | C::About
        | C::OpenSettingsFile
        | C::KeyMap
        | C::ZoomIn
        | C::ZoomOut
        | C::ZoomReset
        | C::CycleXrefs
        | C::SelectTheme
        | C::FilesAndFolders
        | C::RevealSymbolCache
        | C::RevealProjects => on(true),
        // Not under a download writing to it.
        C::ClearSymbolCache => on(!facts.downloading),
        C::DownloadSymbols | C::SymbolsNotNow | C::AlwaysDownloadSymbols => on(facts.symbols_offer),
        // The panes are there only while a binary is open (else the start
        // page is).
        C::SplitRight
        | C::SplitDown
        | C::NextTab
        | C::PreviousTab
        | C::MoveTabLeft
        | C::MoveTabRight
        | C::FocusLeft
        | C::FocusRight
        | C::FocusUp
        | C::FocusDown
        | C::SwitchView
        | C::OpenListing
        | C::OpenC
        | C::MoveUp
        | C::MoveDown
        | C::PageUp
        | C::PageDown
        | C::Top
        | C::Bottom
        | C::SaveProject
        | C::Close
        | C::Conflicts
        // The start page has no panes to open it in.
        | C::NewTerminal
        | C::NewAgent => on(facts.open),
        // The project is known once the image is parsed (its key read).
        // Bytes are searched once the image is parsed too.
        C::ExportProject | C::SearchBytes => on(facts.open && facts.stage >= 1),
        // Not in a shared session: it shares the slice open.
        C::ReopenSlice => on(facts.open && facts.universal && !facts.live),
        // Into a share's project, while it takes edits.
        C::BringValues => on(facts.open && facts.share && !facts.view_only),
        // The settings open over the start page close as a tab.
        C::CloseTab => on(facts.open || facts.settings),
        C::Undo => on(facts.undo),
        C::Redo => on(facts.redo),
        // The IR's variables are not the C's: renamed or typed only from
        // the C (or a row's menu).
        // `D` is a correction in the listing and the hex view, a member's
        // width in the C.
        C::Data if facts.listing || facts.hex => correction(command, facts),
        C::Rename | C::SetType | C::Data => renaming(facts),
        C::MakeCode
        | C::Undefine
        | C::MakeString
        | C::MakeArray
        | C::MakeFunction
        | C::EditFunction
        | C::DeleteFunction => correction(command, facts),
        C::EditStruct | C::NewStruct => structs(command, facts),
        C::NumberHex | C::NumberDecimal | C::NumberEnum => on(facts.number),
        C::NumberChar => on(facts.number && facts.printable),
        C::OpenInNewPane => on(facts.named),
        C::Why => on(facts.explained),
        C::RejectSignature => on(facts.signature),
        C::RunFromHere | C::OpenGraphInSplit => on(analysed && facts.function),
        C::CopyName => on(facts.address || facts.selection),
        C::SelectAll => on(facts.selectable),
        C::Comment | C::CopyAddress | C::Follow | C::Peek | C::Origin => on(facts.address),
        C::ToggleGraph => State {
            enabled: analysed && (facts.function || facts.graph),
            checked: Some(facts.graph),
        },
        C::FitGraph => on(facts.graph || facts.calls),
        C::ToggleOverview => toggle(facts.overview),
        C::ToggleHex => State {
            enabled: facts.open && facts.stage >= 1,
            checked: Some(facts.hex),
        },
        C::ToggleUnified => State {
            enabled: facts.open && facts.stage >= 1,
            checked: Some(facts.unified),
        },
        C::ShowInHex => on(facts.open && facts.stage >= 1 && facts.address),
        C::HexFileOffsets => hex_toggle(facts.file_offsets),
        C::HexEntropy => hex_toggle(facts.entropy),
        C::HexSide => hex_toggle(facts.hex_side),
        // Bytes: the hex view's, the unified listing's rows'.
        C::ApplyType | C::CopyHex | C::CopyEscaped | C::CopyCArray => {
            on(facts.hex || facts.unified)
        }
        C::RemoveType => on((facts.hex || facts.unified) && facts.user_type),
        calls_commands!() => calls_state(command, facts),
        C::Back => on(facts.back),
        C::Forward => on(facts.forward),
        C::GoAnywhere
        | C::NextFunction
        | C::PreviousFunction
        | C::Functions
        | C::Strings
        | C::SearchEverywhere
        | C::SearchImmediate
        | C::Bookmarks
        | C::NewEnum
        | C::EditEnum => on(analysed),
        C::Find => on(facts.open && facts.findable),
        C::FindNext | C::FindPrevious => on(facts.finding),
        C::StopSearch => on(facts.searching),
        C::Xrefs => on(analysed && (facts.address || facts.typed)),
        C::Verify | C::Bookmark => on(analysed && facts.address),
        C::CompareProcessors => on(analysed
            && facts.address
            && facts.fitting.iter().filter(|&&fits| fits).count() >= 2),
        C::ProcessorArchitecture
        | C::ProcessorRaptorCove
        | C::ProcessorGracemont
        | C::ProcessorFile => {
            let chosen = Processor::chosen_by(command);
            checked(
                facts.open && chosen.is_some_and(|p| p.fits(facts)),
                chosen == Some(facts.processor),
            )
        }
        C::ClosePane | C::FocusNextPane | C::MoveTabToNextPane => on(facts.open && facts.panes),
        C::ToggleMaximize => State {
            enabled: facts.open && facts.panes,
            checked: Some(facts.maximized),
        },
        C::ToggleLeftSidebar => pane_toggle(facts.left_sidebar),
        C::ToggleRightSidebar => pane_toggle(facts.right_sidebar),
        // Sharing needs the project's id, known once the image is parsed;
        // joining too, unless no binary is open (the host may send it). In
        // a session Share shows it (the ticket again, who is in, Stop).
        C::ShareProject => on((facts.open && facts.stage >= 1) || facts.live),
        C::JoinSession => on((!facts.open || facts.stage >= 1) && !facts.live),
        C::LeaveSession => on(facts.live),
        C::SessionPanel => pane_toggle(facts.session_panel),
        C::InsertLocation => on(facts.live && facts.address),
        C::Threads => pane_toggle(facts.threads_panel),
        C::History => pane_toggle(facts.history_panel),
        C::StartThread => on(analysed && facts.threadable),
        C::ToggleConsole => pane_toggle(facts.console),
        C::ToggleFeatureMap => pane_toggle(facts.feature_map),
        C::MoveFeatureMap => on(facts.open && facts.feature_map),
        C::OpenAsTab => on(facts.open && facts.folder),
        C::ToggleTheme => toggle(facts.dark),
        C::ToggleReadingView => pane_toggle(facts.reading),
        C::ShowInIr => checked(analysed && (facts.function || facts.ir), facts.ir),
        C::IrPreviousStage | C::IrNextStage => on(facts.ir),
        C::ToggleIrDiff => checked(facts.ir, facts.ir_diff),
        C::ToggleOpcodeBytes => toggle(facts.opcode_bytes),
        C::ToggleNumbers => toggle(facts.c_numbers),
        C::ToggleSymbolic => toggle(facts.symbolic),
        C::ToggleLigatures => toggle(facts.ligatures),
        C::ToggleIslands => toggle(facts.islands),
        C::ToggleSync => pane_toggle(facts.synced),
        C::StageImage => stage(1),
        C::StageFunctions => stage(2),
        C::StageReferences => stage(3),
        C::StageCallers => stage(4),
        C::StageWarmed => stage(5),
    }
}

/// A command that can run when `enabled`, not a toggle.
fn on(enabled: bool) -> State {
    State {
        enabled,
        checked: None,
    }
}

/// Renaming and typing: where something is renamable, from the C or a
/// row's menu (the IR's variables are not the C's).
fn renaming(facts: &Facts) -> State {
    on(facts.renamable && (facts.subject || !facts.ir))
}

/// A correction of recovery: once the functions are recovered, where it
/// applies ([`correction_refusal`]).
fn correction(command: Command, facts: &Facts) -> State {
    on(facts.open && facts.stage >= 2 && correction_refusal(command, facts).is_none())
}

/// Why the correction `command` makes cannot apply: not in the listing
/// (data, strings and arrays: nor the hex view), or the reason at the
/// cursor ([`Facts::refusals`]).
#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "only the corrections' commands are asked about"
)]
fn correction_refusal(command: Command, facts: &Facts) -> Option<&'static str> {
    let r = &facts.refusals;
    let (refusal, bytes) = match command {
        C::MakeCode => (r.code, false),
        C::Undefine => (r.undefine, false),
        C::Data => (r.data, true),
        C::MakeString => (r.string, true),
        C::MakeArray => (r.array, true),
        C::MakeFunction => (r.function, false),
        C::EditFunction => (r.end, false),
        C::DeleteFunction => (r.delete, false),
        _ => return None,
    };
    if facts.listing || (bytes && facts.hex) {
        refusal
    } else if bytes {
        Some("in the listing or the hex view")
    } else {
        Some("in the listing")
    }
}

/// Why `command` cannot run under `facts`, where it would otherwise (what
/// the palette says beside it): only reasons not plain from the window.
#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "most commands are off for plain reasons"
)]
pub fn reason(command: Command, facts: &Facts) -> Option<&'static str> {
    match command {
        C::Rename | C::SetType if facts.renamable && facts.ir && !facts.subject => {
            Some("the IR's variables are not the C's")
        }
        // In the C, `D` is a member's width.
        C::Data if !facts.listing && !facts.hex => None,
        C::Data
        | C::MakeCode
        | C::Undefine
        | C::MakeString
        | C::MakeArray
        | C::MakeFunction
        | C::EditFunction
        | C::DeleteFunction
            if facts.open && facts.stage >= 2 =>
        {
            correction_refusal(command, facts)
        }
        _ => None,
    }
}

/// A toggle that can run when `enabled`, `checked` or not.
fn checked(enabled: bool, checked: bool) -> State {
    State {
        enabled,
        checked: Some(checked),
    }
}

/// A toggle that can always run, `checked` or not.
fn toggle(checked: bool) -> State {
    State {
        enabled: true,
        checked: Some(checked),
    }
}

/// The struct editor's commands: a new struct once the functions are
/// recovered, the struct under the cursor where there is one.
fn structs(command: Command, facts: &Facts) -> State {
    on(if command == C::NewStruct {
        facts.open && facts.stage >= 2
    } else {
        facts.structure
    })
}

/// A toggle of the open binary's panes: off without one.
fn pane_toggle(facts: &Facts, checked: bool) -> State {
    State {
        enabled: facts.open,
        checked: Some(checked),
    }
}

/// An analysis stage shown as reached or not; never run from a menu.
fn stage(facts: &Facts, reached: u8) -> State {
    State {
        enabled: false,
        checked: Some(facts.open && facts.stage >= reached),
    }
}

/// The call graph's, the Pathfinder's and the callers table's commands'
/// states under `facts`.
#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "`state` hands over only these commands"
)]
fn calls_state(command: Command, facts: &Facts) -> State {
    let analysed = facts.open && facts.stage >= 2;
    match command {
        C::ToggleCalls => State {
            enabled: analysed && (facts.function || facts.calls),
            checked: Some(facts.calls),
        },
        C::MoreCallers | C::FewerCallers | C::MoreCallees | C::FewerCallees => on(facts.calls),
        C::Pathfinder => State {
            enabled: analysed,
            checked: Some(facts.pathfinder),
        },
        C::PathFrom | C::PathTo => on(analysed && facts.function),
        C::WholeSubgraph => checked(facts.paths, facts.whole_subgraph),
        C::CallerArguments => State {
            enabled: facts.callers && facts.stage >= 3,
            checked: Some(facts.caller_arguments),
        },
        C::KeepTab => on(facts.open && facts.preview),
        _ => on(false),
    }
}

/// A key bound to a command.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Binding {
    /// The command.
    pub command: Command,
    /// The keystrokes (GPUI's syntax).
    pub keys: String,
    /// Where it works.
    pub scope: Scope,
}

/// The key map: every command's default keys, but those the user set
/// (`overrides`, command id → keys; an empty list unbinds); and the ids
/// of `overrides` naming no command.
pub fn bindings(overrides: &BTreeMap<String, Vec<String>>) -> (Vec<Binding>, Vec<String>) {
    let mut out = Vec::new();
    for info in COMMANDS {
        let keys: Vec<String> = match overrides.get(info.id) {
            Some(keys) => keys.clone(),
            None => info.keys.iter().map(|&key| key.to_owned()).collect(),
        };
        out.extend(keys.into_iter().map(|keys| Binding {
            command: info.command,
            keys,
            scope: info.scope,
        }));
    }
    let unknown = overrides
        .keys()
        .filter(|id| by_id(id).is_none())
        .cloned()
        .collect();
    (out, unknown)
}

/// The first of `bindings` for `command`, as this platform's key labels
/// write it ([`label_of`]).
pub fn key_label(bindings: &[Binding], command: Command) -> Option<String> {
    label_of(bindings, command, cfg!(target_os = "macos"))
}

/// The first of `bindings` for `command` as key labels write it, a
/// sequence's strokes spaced: `secondary-shift-p` and `ctrl-shift-p` are
/// `Ctrl-Shift-P`; on macOS (`mac`) as its menus write them, the
/// modifiers' symbols in its order, then the key: `secondary-shift-p` is
/// `⇧⌘P`, `ctrl-m` `⌃M`.
fn label_of(bindings: &[Binding], command: Command, mac: bool) -> Option<String> {
    let binding = bindings.iter().find(|binding| binding.command == command)?;
    Some(
        binding
            .keys
            .split(' ')
            .map(|stroke| stroke_label(stroke, mac))
            .collect::<Vec<_>>()
            .join(" "),
    )
}

/// One keystroke as a key label writes it (`ctrl-p` → `Ctrl-P`; on macOS
/// `secondary-p` → `⌘P`).
fn stroke_label(stroke: &str, mac: bool) -> String {
    if stroke == "-" {
        return stroke.to_owned();
    }
    let mut parts: Vec<&str> = stroke.split('-').collect();
    // `ctrl--`: the last key is the minus.
    if stroke.ends_with("--") {
        parts.retain(|part| !part.is_empty());
        parts.push("-");
    }
    if mac {
        return mac_stroke_label(&parts);
    }
    parts
        .iter()
        .map(|part| match *part {
            "ctrl" | "secondary" => "Ctrl".to_owned(),
            "alt" => "Alt".to_owned(),
            "shift" => "Shift".to_owned(),
            "cmd" | "super" => "Super".to_owned(),
            "escape" => "Esc".to_owned(),
            "pageup" => "PgUp".to_owned(),
            "pagedown" => "PgDn".to_owned(),
            key => capitalised(key),
        })
        .collect::<Vec<_>>()
        .join("-")
}

/// A keystroke's `parts` (its modifiers, then its key) as macOS's menus
/// write them: the modifiers' symbols in its order (⌃⌥⇧⌘), then the key
/// (arrows and the like as symbols).
fn mac_stroke_label(parts: &[&str]) -> String {
    let Some((key, modifiers)) = parts.split_last() else {
        return String::new();
    };
    let mut label = String::new();
    for (names, symbol) in [
        (&["ctrl"][..], '⌃'),
        (&["alt"], '⌥'),
        (&["shift"], '⇧'),
        (&["secondary", "cmd", "super"], '⌘'),
    ] {
        if modifiers.iter().any(|modifier| names.contains(modifier)) {
            label.push(symbol);
        }
    }
    let symbol = match *key {
        "escape" => "⎋",
        "enter" => "↩",
        "tab" => "⇥",
        "backspace" => "⌫",
        "delete" => "⌦",
        "up" => "↑",
        "down" => "↓",
        "left" => "←",
        "right" => "→",
        "pageup" => "⇞",
        "pagedown" => "⇟",
        "home" => "↖",
        "end" => "↘",
        key => {
            label.push_str(&capitalised(key));
            return label;
        }
    };
    label.push_str(symbol);
    label
}

/// `key` with its first letter upper case (`f12` → `F12`).
fn capitalised(key: &str) -> String {
    let mut chars = key.chars();
    chars.next().map_or_else(String::new, |first| {
        first.to_uppercase().chain(chars).collect()
    })
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use super::{
        COMMANDS, Command, Entry, Facts, MENU_LIMIT, Menu, Processor, State, Submenu, bindings,
        in_palette, label_of, lookup, menu, menu_for, reason, state, title,
    };

    #[test]
    fn ids_and_commands_are_unique() {
        let ids: BTreeSet<&str> = COMMANDS.iter().map(|info| info.id).collect();
        let commands: BTreeSet<Command> = COMMANDS.iter().map(|info| info.command).collect();
        assert_eq!(ids.len(), COMMANDS.len());
        assert_eq!(commands.len(), COMMANDS.len());
    }

    /// The palette lists the Analysis menu's actions (Run from Here, the
    /// processors), never its stage marks, nor a view's cursor moves.
    #[test]
    fn the_palette_lists_the_analysis_actions_but_not_the_stages() {
        let listed: BTreeSet<Command> = COMMANDS
            .iter()
            .filter(|info| in_palette(info))
            .map(|info| info.command)
            .collect();
        let stages = [
            Command::StageImage,
            Command::StageFunctions,
            Command::StageReferences,
            Command::StageCallers,
            Command::StageWarmed,
        ];
        for info in COMMANDS.iter().filter(|info| info.menu.is_some()) {
            assert_eq!(
                listed.contains(&info.command),
                !stages.contains(&info.command),
                "{}",
                info.id
            );
        }
        assert!(listed.contains(&Command::RunFromHere));
        assert!(listed.contains(&Command::ProcessorGracemont));
    }

    /// Checks one level of a menu (`path` names it) and the submenus
    /// under it: not empty, no separator at an end or after another, at
    /// most [`MENU_LIMIT`] entries; collects its commands into `seen`,
    /// each once.
    fn check_level(path: &str, entries: &[Entry], seen: &mut BTreeSet<Command>) {
        assert!(!entries.is_empty(), "{path} is empty");
        assert_ne!(entries.first(), Some(&Entry::Separator), "{path}");
        assert_ne!(entries.last(), Some(&Entry::Separator), "{path}");
        assert!(
            entries
                .windows(2)
                .all(|w| w != [Entry::Separator, Entry::Separator]),
            "{path}"
        );
        let items = entries.iter().filter(|e| **e != Entry::Separator).count();
        assert!(items <= MENU_LIMIT, "{path} holds {items} entries");
        for entry in entries {
            match entry {
                Entry::Command(command) => {
                    assert!(seen.insert(*command), "{command:?} twice");
                }
                Entry::Submenu { label, entries } => {
                    check_level(&format!("{path} > {label}"), entries, seen);
                }
                Entry::Separator => {}
            }
        }
    }

    #[test]
    fn menus_hold_their_commands_once_with_separators_between_groups() {
        let mut seen = BTreeSet::new();
        for m in Menu::ALL {
            check_level(m.title(), &menu(m), &mut seen);
        }
        let with_menu = COMMANDS.iter().filter(|info| info.menu.is_some()).count();
        assert_eq!(seen.len(), with_menu);
        // A submenu's commands are its menu's.
        for sub in Submenu::ALL {
            for &command in sub.commands() {
                let info = lookup(command).map(|info| info.menu);
                assert_eq!(info, Some(Some(sub.menu())), "{sub:?} {command:?}");
            }
        }
    }

    #[test]
    fn submenus_close_their_menu_after_its_own_commands() {
        for m in Menu::ALL {
            let entries = menu(m);
            let Some(first) = entries
                .iter()
                .position(|e| matches!(e, Entry::Submenu { .. }))
            else {
                continue;
            };
            assert!(
                entries
                    .iter()
                    .skip(first)
                    .all(|e| matches!(e, Entry::Submenu { .. })),
                "{m:?}"
            );
            let before = first.checked_sub(1).and_then(|i| entries.get(i));
            assert!(matches!(before, None | Some(Entry::Separator)), "{m:?}");
        }
    }

    #[test]
    fn overrides_replace_defaults_unbind_and_report_unknown_ids() {
        let overrides = BTreeMap::from([
            ("go.anywhere".to_owned(), vec!["ctrl-g".to_owned()]),
            ("edit.rename".to_owned(), Vec::new()),
            ("no.such".to_owned(), vec!["f1".to_owned()]),
        ]);
        let (map, unknown) = bindings(&overrides);
        let keys = |command| {
            map.iter()
                .filter(|binding| binding.command == command)
                .map(|binding| binding.keys.as_str())
                .collect::<Vec<_>>()
        };
        assert_eq!(keys(Command::GoAnywhere), ["ctrl-g"]);
        assert_eq!(keys(Command::Rename), Vec::<&str>::new());
        assert_eq!(keys(Command::Back), ["escape", "alt-left"]);
        assert_eq!(unknown, ["no.such"]);
        // A user's `ctrl-` is Ctrl on macOS too.
        assert_eq!(
            label_of(&map, Command::GoAnywhere, false).as_deref(),
            Some("Ctrl-G")
        );
        assert_eq!(
            label_of(&map, Command::GoAnywhere, true).as_deref(),
            Some("⌃G")
        );
        assert_eq!(label_of(&map, Command::Rename, false), None);
    }

    #[test]
    fn key_labels_capitalise_each_key() {
        let (map, _) = bindings(&BTreeMap::new());
        let label = |command| label_of(&map, command, false).unwrap();
        assert_eq!(label(Command::Palette), "Ctrl-Shift-P");
        assert_eq!(label(Command::ZoomOut), "Ctrl--");
        assert_eq!(label(Command::SplitRight), "Ctrl-K Right");
        assert_eq!(label(Command::Back), "Esc");
    }

    /// The default keys are Cmd on macOS and Ctrl elsewhere (`secondary-`),
    /// but for those Ctrl keeps there (the console's and the terminal's,
    /// as VS Code's, and the bookmarks'); elsewhere every label is the one
    /// the same keys with `ctrl-` had.
    #[test]
    fn default_keys_are_cmd_on_macos_and_ctrl_elsewhere() {
        let (map, _) = bindings(&BTreeMap::new());
        let literal_ctrl: BTreeSet<Command> = map
            .iter()
            .filter(|b| b.keys.split([' ', '-']).any(|part| part == "ctrl"))
            .map(|b| b.command)
            .collect();
        assert_eq!(
            literal_ctrl,
            BTreeSet::from([
                Command::ToggleConsole,
                Command::NewTerminal,
                Command::Bookmarks
            ])
        );
        assert!(
            map.iter()
                .all(|b| !b.keys.contains("cmd-") && !b.keys.contains("super-")),
            "a default key names Cmd itself rather than secondary-"
        );
        for info in COMMANDS {
            let (Some(ours), Some(old)) = (
                label_of(&map, info.command, false),
                info.keys
                    .first()
                    .map(|keys| keys.replace("secondary-", "ctrl-")),
            ) else {
                continue;
            };
            let old = [super::Binding {
                command: info.command,
                keys: old,
                scope: info.scope,
            }];
            assert_eq!(
                Some(ours),
                label_of(&old, info.command, false),
                "{}",
                info.id
            );
        }
        let mac = |command| label_of(&map, command, true).unwrap();
        assert_eq!(mac(Command::Open), "⌘O");
        assert_eq!(mac(Command::Quit), "⌘Q");
        assert_eq!(mac(Command::Palette), "⇧⌘P");
        assert_eq!(mac(Command::Redo), "⇧⌘Z");
        assert_eq!(mac(Command::ZoomOut), "⌘-");
        assert_eq!(mac(Command::SplitRight), "⌘K →");
        assert_eq!(mac(Command::SelectTheme), "⌘K ⌘T");
        assert_eq!(mac(Command::Back), "⎋");
        assert_eq!(mac(Command::ToggleConsole), "⌃`");
        assert_eq!(mac(Command::NewTerminal), "⌃~");
        assert_eq!(mac(Command::Bookmarks), "⌃M");
        assert_eq!(mac(Command::NextFunction), "⌘↓");
    }

    #[test]
    fn renaming_is_the_cs_and_the_whole_subgraph_a_searchs_toggle() {
        let open = Facts {
            open: true,
            stage: 3,
            address: true,
            ..Facts::default()
        };
        // Renaming and typing are the C's: off while the IR is shown, with
        // why; a row's menu still names its row.
        let named = Facts {
            renamable: true,
            ..open
        };
        assert!(state(Command::Rename, &named).enabled);
        assert_eq!(reason(Command::Rename, &named), None);
        let ir_named = Facts { ir: true, ..named };
        for command in [Command::Rename, Command::SetType] {
            assert!(!state(command, &ir_named).enabled, "{command:?}");
            assert!(reason(command, &ir_named).is_some(), "{command:?}");
        }
        let ir = Facts { ir: true, ..open };
        assert_eq!(reason(Command::Rename, &ir), None, "nothing to rename");
        let row = Facts {
            subject: true,
            ..ir_named
        };
        assert!(state(Command::Rename, &row).enabled);
        assert_eq!(reason(Command::Rename, &row), None);
        assert!(!state(Command::WholeSubgraph, &open).enabled);
        let paths = Facts {
            calls: true,
            paths: true,
            ..open
        };
        assert_eq!(
            state(Command::WholeSubgraph, &paths),
            State {
                enabled: true,
                checked: Some(false)
            }
        );
    }

    #[test]
    fn copy_takes_a_selection_else_the_name() {
        let selecting = Facts {
            open: true,
            selection: true,
            ..Facts::default()
        };
        // Ctrl+C copies a selection, named so, with no address under the
        // cursor too; else the name.
        assert!(state(Command::CopyName, &selecting).enabled);
        assert_eq!(title(Command::CopyName, &selecting), "Copy");
        assert!(!state(Command::CopyName, &Facts::default()).enabled);
        assert_eq!(title(Command::CopyName, &Facts::default()), "Copy Name");
    }

    #[test]
    fn another_slice_opens_only_of_a_universal_file_outside_a_session() {
        let thin = Facts {
            open: true,
            stage: 2,
            ..Facts::default()
        };
        assert!(!state(Command::ReopenSlice, &thin).enabled);
        let universal = Facts {
            universal: true,
            ..thin
        };
        assert!(state(Command::ReopenSlice, &universal).enabled);
        // A shared session shares the slice open.
        let shared = Facts {
            live: true,
            ..universal
        };
        assert!(!state(Command::ReopenSlice, &shared).enabled);
        assert!(!state(Command::ReopenSlice, &Facts::default()).enabled);
    }

    #[test]
    fn a_view_only_session_turns_edits_off_and_nothing_else() {
        let editing = Facts {
            open: true,
            stage: 5,
            renamable: true,
            address: true,
            undo: true,
            live: true,
            signature: true,
            ..Facts::default()
        };
        let viewing = Facts {
            view_only: true,
            ..editing
        };
        for command in [
            Command::Rename,
            Command::Comment,
            Command::Undo,
            Command::Bookmark,
            Command::RejectSignature,
        ] {
            assert!(state(command, &editing).enabled, "{command:?}");
            assert!(!state(command, &viewing).enabled, "{command:?}");
        }
        // Rejecting needs a signature's name under the cursor.
        let unnamed = Facts {
            signature: false,
            ..editing
        };
        assert!(!state(Command::RejectSignature, &unnamed).enabled);
        for command in [Command::GoAnywhere, Command::Xrefs, Command::LeaveSession] {
            assert!(state(command, &viewing).enabled, "{command:?}");
        }
    }

    #[test]
    fn search_commands_follow_the_pane_and_the_analysis() {
        let image = Facts {
            open: true,
            stage: 1,
            ..Facts::default()
        };
        // Bytes are there once the image is; names and C once analysed.
        assert!(state(Command::SearchBytes, &image).enabled);
        assert!(!state(Command::SearchEverywhere, &image).enabled);
        assert!(!state(Command::SearchImmediate, &image).enabled);
        assert!(!state(Command::Bookmarks, &image).enabled);
        let analysed = Facts { stage: 2, ..image };
        assert!(state(Command::SearchEverywhere, &analysed).enabled);
        assert!(state(Command::Bookmarks, &analysed).enabled);
        // A bookmark needs an address; Find a pane it searches; the
        // steps an open bar; Stop a running search.
        assert!(!state(Command::Bookmark, &analysed).enabled);
        assert!(!state(Command::Find, &analysed).enabled);
        assert!(!state(Command::FindNext, &analysed).enabled);
        assert!(!state(Command::StopSearch, &analysed).enabled);
        let finding = Facts {
            address: true,
            findable: true,
            finding: true,
            searching: true,
            ..analysed
        };
        for command in [
            Command::Bookmark,
            Command::Find,
            Command::FindNext,
            Command::FindPrevious,
            Command::StopSearch,
        ] {
            assert!(state(command, &finding).enabled, "{command:?}");
        }
        // Shift+F3 is Find Previous where a find bar is open and Functions
        // everywhere else: the two never both apply (GPUI would
        // prefer the one bound without a context).
        let (map, _) = bindings(&BTreeMap::new());
        let shift_f3: Vec<_> = map
            .iter()
            .filter(|b| b.keys == "shift-f3")
            .map(|b| (b.command, b.scope.context()))
            .collect();
        assert_eq!(
            shift_f3,
            [
                (Command::FindPrevious, Some("Find")),
                (Command::Functions, Some("!Find"))
            ]
        );
    }

    /// A project exports once it is known: the file read and parsed.
    #[test]
    fn exporting_waits_for_the_project() {
        let opening = Facts {
            open: true,
            ..Facts::default()
        };
        assert!(!state(Command::ExportProject, &opening).enabled);
        let image = Facts {
            stage: 1,
            ..opening
        };
        assert!(state(Command::ExportProject, &image).enabled);
    }

    #[test]
    fn the_feature_map_moves_only_when_shown_and_its_title_names_where_to() {
        let open = Facts {
            open: true,
            ..Facts::default()
        };
        let hidden = state(Command::ToggleFeatureMap, &open);
        assert_eq!((hidden.enabled, hidden.checked), (true, Some(false)));
        assert!(!state(Command::MoveFeatureMap, &open).enabled);
        let right = Facts {
            feature_map: true,
            ..open
        };
        assert_eq!(state(Command::ToggleFeatureMap, &right).checked, Some(true));
        assert!(state(Command::MoveFeatureMap, &right).enabled);
        assert_eq!(
            title(Command::MoveFeatureMap, &right),
            "Feature Map at the Top"
        );
        let top = Facts {
            feature_map_top: true,
            ..right
        };
        assert_eq!(
            title(Command::MoveFeatureMap, &top),
            "Feature Map at the Right"
        );
        // Open as Tab needs a folder.
        assert!(!state(Command::OpenAsTab, &open).enabled);
        assert!(
            state(
                Command::OpenAsTab,
                &Facts {
                    folder: true,
                    ..open
                }
            )
            .enabled
        );
        assert!(
            !state(
                Command::OpenAsTab,
                &Facts {
                    folder: true,
                    ..Facts::default()
                }
            )
            .enabled
        );
    }

    #[test]
    fn state_follows_the_facts() {
        let closed = Facts::default();
        assert!(!state(Command::SaveProject, &closed).enabled);
        assert!(!state(Command::ExportProject, &closed).enabled);
        assert!(!state(Command::GoAnywhere, &closed).enabled);
        assert_eq!(state(Command::StageImage, &closed).checked, Some(false));
        // The start page: what needs no binary works, the panes' commands
        // are greyed.
        for command in [
            Command::Open,
            Command::OpenRecent,
            Command::ImportProject,
            Command::Quit,
            Command::Settings,
            Command::About,
            Command::FilesAndFolders,
            Command::RevealProjects,
            Command::Palette,
            Command::ToggleTheme,
        ] {
            assert!(state(command, &closed).enabled, "{command:?}");
        }
        for command in [
            Command::SplitRight,
            Command::CloseTab,
            Command::NextTab,
            Command::OpenC,
            Command::SwitchView,
            Command::MoveDown,
            Command::ToggleLeftSidebar,
            Command::ToggleReadingView,
            Command::ToggleSync,
        ] {
            assert!(!state(command, &closed).enabled, "{command:?}");
        }
        let two_panes = Facts {
            panes: true,
            ..closed
        };
        assert!(!state(Command::ClosePane, &two_panes).enabled);
        let settings = Facts {
            settings: true,
            ..closed
        };
        assert!(state(Command::CloseTab, &settings).enabled);
        let open = Facts {
            open: true,
            stage: 3,
            address: true,
            dark: true,
            ..Facts::default()
        };
        assert!(state(Command::GoAnywhere, &open).enabled);
        assert!(state(Command::Xrefs, &open).enabled);
        assert_eq!(state(Command::StageReferences, &open).checked, Some(true));
        assert_eq!(state(Command::StageCallers, &open).checked, Some(false));
        assert!(!state(Command::StageCallers, &open).enabled);
        assert_eq!(state(Command::ToggleTheme, &open).checked, Some(true));
        assert!(!state(Command::Rename, &open).enabled);
        assert!(!state(Command::ToggleMaximize, &open).enabled);
        // The IR viewer's stage keys only in an IR pane; showing it needs a
        // function under the cursor, leaving it does not.
        assert!(!state(Command::IrNextStage, &open).enabled);
        assert!(!state(Command::ShowInIr, &open).enabled);
        let ir = Facts {
            ir: true,
            ir_diff: true,
            ..open
        };
        assert!(state(Command::IrNextStage, &ir).enabled);
        assert_eq!(
            state(Command::ShowInIr, &ir),
            State {
                enabled: true,
                checked: Some(true)
            }
        );
        assert_eq!(state(Command::ToggleIrDiff, &ir).checked, Some(true));
        let split = Facts {
            panes: true,
            maximized: true,
            ..open
        };
        assert!(state(Command::ToggleMaximize, &split).enabled);
        assert_eq!(state(Command::ToggleMaximize, &split).checked, Some(true));
    }

    #[test]
    fn the_byte_commands_follow_the_view() {
        let open = Facts {
            open: true,
            stage: 3,
            address: true,
            ..Facts::default()
        };
        // The byte commands need the hex view or the unified listing shown
        // (the hex view's own toggles, the hex view); removing a type needs
        // one the user laid.
        assert!(state(Command::ToggleHex, &open).enabled);
        assert!(!state(Command::ApplyType, &open).enabled);
        assert!(!state(Command::CopyCArray, &open).enabled);
        let hex = Facts { hex: true, ..open };
        assert!(state(Command::ApplyType, &hex).enabled);
        assert!(!state(Command::RemoveType, &hex).enabled);
        let unified = Facts {
            unified: true,
            ..open
        };
        assert!(state(Command::ApplyType, &unified).enabled);
        assert!(state(Command::CopyCArray, &unified).enabled);
        assert!(!state(Command::HexEntropy, &unified).enabled);
        assert!(
            state(
                Command::RemoveType,
                &Facts {
                    user_type: true,
                    ..unified
                }
            )
            .enabled
        );
        assert!(
            state(
                Command::RemoveType,
                &Facts {
                    user_type: true,
                    ..hex
                }
            )
            .enabled
        );
    }

    #[test]
    fn the_symbols_commands_follow_the_bar_and_the_download() {
        let open = Facts {
            open: true,
            stage: 2,
            ..Facts::default()
        };
        // The bar's commands run while it offers, and only then.
        let bar = [
            Command::DownloadSymbols,
            Command::SymbolsNotNow,
            Command::AlwaysDownloadSymbols,
        ];
        let offer = Facts {
            symbols_offer: true,
            ..open
        };
        let downloading = Facts {
            downloading: true,
            ..open
        };
        for command in bar {
            assert!(!state(command, &open).enabled, "{command:?}");
            assert!(state(command, &offer).enabled, "{command:?}");
            assert!(!state(command, &downloading).enabled, "{command:?}");
        }
        // The cache is there with no binary open; it is not cleared under
        // a download.
        let closed = Facts::default();
        assert!(state(Command::RevealSymbolCache, &closed).enabled);
        assert!(state(Command::ClearSymbolCache, &closed).enabled);
        assert!(!state(Command::ClearSymbolCache, &downloading).enabled);
        assert!(state(Command::RevealSymbolCache, &downloading).enabled);
    }

    #[test]
    fn call_graph_commands_follow_the_facts() {
        let open = Facts {
            open: true,
            stage: 2,
            ..Facts::default()
        };
        // The call graph needs a function at the cursor, or to be shown
        // (to leave it); its levels need it shown.
        assert!(!state(Command::ToggleCalls, &open).enabled);
        assert!(!state(Command::PathFrom, &open).enabled);
        let function = Facts {
            function: true,
            ..open
        };
        assert!(state(Command::ToggleCalls, &function).enabled);
        assert!(state(Command::PathTo, &function).enabled);
        assert!(!state(Command::MoreCallers, &function).enabled);
        let shown = Facts {
            calls: true,
            ..open
        };
        assert_eq!(state(Command::ToggleCalls, &shown).checked, Some(true));
        assert!(state(Command::FewerCallees, &shown).enabled);
        // `w` fits the call graph as it fits a function's graph.
        assert!(!state(Command::FitGraph, &open).enabled);
        assert!(state(Command::FitGraph, &shown).enabled);
        // The Pathfinder needs the functions; it is a toggle.
        assert!(!state(Command::Pathfinder, &Facts::default()).enabled);
        assert_eq!(state(Command::Pathfinder, &open).checked, Some(false));
        // Callers' arguments need a callers' tab and the references.
        let callers = Facts {
            callers: true,
            ..open
        };
        assert!(!state(Command::CallerArguments, &callers).enabled);
        assert!(
            state(
                Command::CallerArguments,
                &Facts {
                    stage: 3,
                    ..callers
                }
            )
            .enabled
        );
        assert!(!state(Command::KeepTab, &open).enabled);
        assert!(
            state(
                Command::KeepTab,
                &Facts {
                    preview: true,
                    ..open
                }
            )
            .enabled
        );
    }

    /// The Processor submenu checks exactly the setting's entry (a path
    /// checks the file's), and only with a binary open.
    #[test]
    fn the_processor_submenu_checks_the_setting() {
        let submenu = menu(Menu::Analysis)
            .into_iter()
            .find_map(|entry| match entry {
                Entry::Submenu {
                    label: "Processor",
                    entries,
                } => Some(entries),
                Entry::Submenu { .. } | Entry::Command(_) | Entry::Separator => None,
            })
            .unwrap();
        let commands: Vec<Command> = Processor::ALL.map(Processor::command).to_vec();
        assert_eq!(
            submenu,
            commands
                .iter()
                .copied()
                .map(Entry::Command)
                .collect::<Vec<_>>()
        );
        for (name, chosen) in [
            (None, Processor::Architecture),
            (Some("intel-raptor-cove"), Processor::RaptorCove),
            (Some("intel-gracemont"), Processor::Gracemont),
            (Some("/home/me/zen4.toml"), Processor::File),
        ] {
            let facts = Facts {
                open: true,
                processor: Processor::of(name),
                fitting: [true; 2],
                ..Facts::default()
            };
            for &command in &commands {
                let checked = state(command, &facts);
                assert!(checked.enabled, "{command:?}");
                assert_eq!(
                    checked.checked,
                    Some(command == chosen.command()),
                    "{name:?} {command:?}"
                );
            }
            assert_eq!(
                chosen.name().or(name.filter(|_| chosen == Processor::File)),
                name
            );
        }
        assert!(!state(Command::ProcessorGracemont, &Facts::default()).enabled);
    }

    /// The Processor submenu lists only the processors fitting the image:
    /// on x86-64 all of them, on AArch64 (no shipped profile fits) the
    /// architecture alone, checked; Compare Processors wants two.
    #[test]
    fn the_processor_submenu_lists_what_fits_the_image() {
        let submenu = |facts: &Facts| {
            menu_for(Menu::Analysis, facts)
                .into_iter()
                .find_map(|entry| match entry {
                    Entry::Submenu {
                        label: "Processor",
                        entries,
                    } => Some(entries),
                    Entry::Submenu { .. } | Entry::Command(_) | Entry::Separator => None,
                })
                .unwrap()
        };
        let x86_64 = Facts {
            open: true,
            stage: 2,
            address: true,
            fitting: [true; 2],
            ..Facts::default()
        };
        let all: Vec<Entry> = Processor::ALL.map(|p| Entry::Command(p.command())).to_vec();
        assert_eq!(submenu(&x86_64), all);
        assert!(state(Command::CompareProcessors, &x86_64).enabled);
        let aarch64 = Facts {
            fitting: [false; 2],
            ..x86_64
        };
        assert_eq!(
            submenu(&aarch64),
            vec![Entry::Command(Command::ProcessorArchitecture)]
        );
        let architecture = state(Command::ProcessorArchitecture, &aarch64);
        assert_eq!(
            (architecture.enabled, architecture.checked),
            (true, Some(true))
        );
        for command in [
            Command::ProcessorRaptorCove,
            Command::ProcessorGracemont,
            Command::ProcessorFile,
            Command::CompareProcessors,
        ] {
            assert!(!state(command, &aarch64).enabled, "{command:?}");
        }
        // One shipped profile fitting: it and a file, no comparison.
        let one = Facts {
            fitting: [false, true],
            ..x86_64
        };
        assert_eq!(
            submenu(&one),
            [
                Command::ProcessorArchitecture,
                Command::ProcessorGracemont,
                Command::ProcessorFile
            ]
            .map(Entry::Command)
            .to_vec()
        );
        assert!(!state(Command::CompareProcessors, &one).enabled);
    }
}
