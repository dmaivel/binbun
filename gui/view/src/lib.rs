//! binbun's GUI without the framework:
//! everything that is not drawing. The GUI renders these and routes input
//! to them; the same models could serve a terminal or an agent.
//!
//! - [`session`]: one binary opened through `binbun-session`; the listing
//!   (the session's) built on a thread of its own, C documents as
//!   [`cdoc::CDocument`]s, undo; events out, the UI never blocks.
//! - [`listing`]: the session's continuous listing (`binbun::listing`)
//!   with the user's names and comments laid over it.
//! - [`corrections`]: the user's corrections of recovery as `C`,
//!   `U`, `D`, `A`, `*`, `P`, Edit and Delete Function make them at the
//!   cursor, or why they cannot apply there.
//! - [`cdoc`]: one function's C as lines of tokens with provenance, the
//!   statement tints linking it to the listing, and the rename field.
//! - [`comment`]: the comment field, typed in place in the listing and
//!   the C.
//! - [`graph`]: the graph view of a function: blocks laid out once, the
//!   viewport, hit testing, the cursor's moves along edges.
//! - [`graph_memory`]: where a tab's graph was left (its zoom, each
//!   function's pan), and as little scrolling as shows the cursor.
//! - [`calls`]: the call graph view (a neighbourhood, a path search's
//!   subgraph), the Pathfinder's question, the callers table's rows.
//! - [`hex`]: the structured hex view: the byte space partitioned by what
//!   bytes are, its rows, typed overlays, the selection, copying.
//! - [`hex_types`]: C as the hex view's template language: structs laid
//!   out as trees, the ELF and PE headers built in.
//! - [`hex_tree`]: the hex view's structure tree: the overlays as roots,
//!   expanding, chunked arrays, a byte's deepest row.
//! - [`settype`]: Set type's inline field over a type in the C, the C it
//!   reads as, completion of type names.
//! - [`structedit`]: the struct editor: a struct as C, checked as typed,
//!   its members' offsets beside their lines.
//! - [`inspect`]: the data inspector: the selection read as every type.
//! - [`peek`]: what the peek card shows for a name.
//! - [`ir`]: the IR viewer: a function through every stage, the cursor
//!   kept through them, each stage's changes and tokens by role.
//! - [`facts`]: the verification chip, the why marks and card, the
//!   origin panel's rows, a run's values, the example states.
//! - [`map`]: the binary's map, the left sidebar's tree.
//! - [`folder`]: a map folder opened as a tab: its items as a sortable,
//!   filterable table.
//! - [`feature_map`]: the strip standing for the whole image: addresses
//!   to pixels and back (gaps compressed), each part's kind.
//! - [`layout`]: panes, splits and their sizes, tabs, preview tabs, focus
//!   moves.
//! - [`layout_file`]: the layout saved per project and restored.
//! - [`tabs`]: tabs as things: each tab's place, a graph following
//!   another tab's cursor, how a click opens what it names, what a C tab
//!   shows where no function is.
//! - [`history`]: one back/forward history across every view.
//! - [`commands`]: every action, its menu, keys and state.
//! - [`console`]: the console pane's model: the user's Python run as
//!   `python -m binbun.console`, its protocol, transcript, history,
//!   completions and signatures, Python coloured.
//! - [`context`]: the context menus, by surface and what is under the
//!   pointer, from the commands.
//! - [`settings`]: the user's settings file.
//! - [`theme_css`]: theme files, CSS in a strict subset: parsed, their
//!   import chains resolved, every problem placed.
//! - [`symbols`]: the bar offering the binary's debug information from a
//!   symbol server, downloading it, or saying why not.
//! - [`banners`]: the banners across the window, one stack: by priority,
//!   one per kind, two shown and "+N more", closed for the session.
//! - [`collab`]: a shared session as the window shows it: trust on first
//!   use and impostors, avatars, follow mode, chat lines, conflict cards,
//!   an analysis that differs from a peer's.
//! - [`agents`]: the coding agents known by name: their marks on their
//!   avatars and how each harness starts `binbun mcp`.
//! - [`chat`]: the chat's messages: the places a message names found as
//!   it is sent (links), how a message shows them, its code and its
//!   mentions, Insert Location's text.
//! - [`talk`]: conversation as the window shows it: threads' marks and
//!   anchors, posts grouped, mentions completed and unread, suggestions'
//!   rows, choices and evidence, the history's lines.
//! - [`updates`]: update checks, once agreed: the first launch's
//!   question, the hourly check, the offer, skipped versions.
//! - [`recent`]: the binaries opened before.
//! - [`projects`]: a binary's projects (its own, one per share joined):
//!   opening the one there is or offering several, a share's title.
//! - [`sharing`]: a shared project's local edits as the window shows them
//!   (not yet shared, not in this project), Bring, edits off while
//!   joining, what leaving flushed.
//! - [`slices`]: a universal Mach-O file's slices, the one offered first,
//!   the one chosen per file.
//! - [`symbol_cache`]: binbun's own symbol cache: its path, its size,
//!   clearing it.
//! - [`fuzzy`]: matching for go-anywhere, the palette and the lists.
//! - [`search`]: finding text, bytes and immediates (the session's
//!   searches), a pane's matches as they come.
//! - [`scroll`]: 64-bit scroll anchors and smooth wheel scrolling.

pub mod agents;
pub mod banners;
pub mod calls;
pub mod cdoc;
pub mod chat;
pub mod collab;
pub mod commands;
pub mod comment;
pub mod console;
pub mod context;
pub mod corrections;
mod crash_safe;
pub mod facts;
pub mod feature_map;
pub mod folder;
pub mod fuzzy;
pub mod graph;
pub mod graph_memory;
pub mod hex;
pub mod hex_globals;
pub mod hex_tree;
pub mod hex_types;
pub mod history;
pub mod inspect;
pub mod ir;
pub mod layout;
pub mod layout_file;
pub mod map;
pub mod peek;
pub mod projects;
pub mod recent;
pub mod scroll;
pub mod search;
pub mod selection;
pub mod session;
pub mod settings;
pub mod settype;
pub mod sharing;
pub mod slices;
pub mod structedit;
pub mod symbol_cache;
pub mod symbols;
pub mod tabs;
pub mod talk;
pub mod theme_css;
pub mod updates;

/// A local symbol server for the tests (the engine's, shared).
#[cfg(test)]
#[path = "../../../crates/binbun-debuginfo/tests/support/server.rs"]
mod test_server;

pub use binbun::cfg::FunctionId;
pub use binbun_ast::ir::{Node, VarId, VarKind};
pub use binbun_print::document::TokenKind as CTokenKind;
pub use binbun_session::{
    Answer, Asked, CError, EnumLayout, MemberEdit, NumberForm, PathRequest, Question, Stage,
    StructLayout, StructMember, Synthesised, TypeLayout, Typed, View, listing, number,
};
