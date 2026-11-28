+++
title = "The GUI"
weight = 30
+++

## Panes, views and tabs

A pane can show the listing, the unified listing, its graph, decompiled C, hex, a call graph or IR. A button in its header names what it shows (`Listing`, `Unified`, `Graph`, `Hex`, `Calls`, `C`, `Exact C` or `IR`) and opens a menu of every view with its keys; choosing there, or pressing a view's key, is the only thing that changes a pane's view. `C` is the reading view, `Exact C` the exact one. **View** holds the commands; the command palette (`Ctrl+Shift+P`) finds them by name. `Space` changes listing and graph in place. `F5` shows C. `Tab` switches between listing and C, switching the current pane if no other pane shows the requested view.

These pages write shortcuts as on Linux and Windows. On macOS `Ctrl` is `Cmd` (`⌘O` opens a file, `⌘Q` quits), except `Ctrl+M` (Bookmarks), `Ctrl+Backtick` (Console), `Ctrl+Shift+Backtick` (New Terminal) and the console's own `Ctrl+C` and `Ctrl+L`, which stay `Ctrl`; the menus and the palette show each key as your platform writes it.

The tabs along the top are places, each titled by the function it is in. A tab's panes all show its place and share its Back/Forward trail: a double-click on a call in the C moves the whole tab there, and `Escape` in any of its panes returns it. `Ctrl+click` or a middle-click on a name, a row of the map or a list opens it in a new tab after the current one, with the same panes and views (with `Shift`, the current tab stays shown); `+` opens one at the current place. Nothing moves a tab but what is done in it. `Ctrl+PageDown` and `Ctrl+PageUp` go to the next and previous tab, and `Ctrl+W` or a middle-click on a tab closes it (the last tab of a place stays). Lists whose rows go places (cross-references, search results, strings, a map folder) open as tabs of the [bottom dock](#bottom-dock), so clicking a row moves the code while the list stays in view; there `Ctrl+W` closes the list shown. The settings and a struct being edited are tabs along the top of their own; a navigation from one goes to a tab of a place. Use **Split Right** (`Ctrl+K`, then `Right`) or **Split Down** (`Ctrl+K`, then `Down`) for another view of the tab's place, and **Close Pane** (`Ctrl+K`, then `W`, or the × at a pane's top right when its tab has more than one) to close one. **Open Graph in Split** adds a graph beside the current pane. Every tab of a place, its panes and each pane's view are saved per project, and come back in order, each at its place, when the binary is opened again.

**Window → Link Pane** sets a pane on its own within its tab, or links it again. In linked panes, selecting C highlights the corresponding instructions; selecting an instruction highlights its C where there is a mapping. This is provenance, not a one-to-one line correspondence. Several instructions may become one expression, and instructions that produce no C may have no matching line.

## The unified listing

**View → Unified View** (or `Unified` in a pane's view menu) shows the whole binary as one document in file order, rather than a function at a time. The file's headers and tables are typed trees and each section is a card. In a section, each function is a card over its code, headed by its signature where its C has been printed, with its blocks under their labels; globals are typed trees, and bytes nothing explains are hex rows. The cards holding the top row stay pinned while what they hold scrolls by.

`Enter`, or a card's chevron, folds and opens the card; `Left` folds the card under the cursor (else goes up to the card holding the row), `Right` opens it (else goes to its first row). A loop folds whole at its header, which says its size. The toolbar's toggles show the instruction bytes, untyped bytes as hex rows (else a row for each run), and the file's structure (its headers, its tables, what is not mapped). A tab keeps its layers, folds and expanded rows.

References to an item are a chip beside it: one goes to where it is made, several open a menu of them. A branch arrow is a line between its ends, also when it jumps to another part of its function, so it looks the same wherever you scroll. Where its other end is under a closed card, or past another function's code, it is a stub instead: hover it to peek at that end, click it to go there. In linked panes the unified listing and the C follow each other, as the listing does.

`Shift` with the arrows, a drag or `Shift`+click selects rows, and `Ctrl+A` selects the rows of the card the cursor is in; **Copy** takes them as they show. **Copy as Hex**, **Copy as C Array**, **Apply Type…** (`Alt+Q`) and **Remove Type** take the selected rows' bytes, as in the hex view, and `Y` sets the type of the global the cursor is in. In the find bar (`Ctrl+F`), the bytes toggle searches the binary's bytes for the hex typed instead of the listing's text. The hex view remains for work a byte at a time: its byte cursor, data inspector, entropy and file offsets.

## The map

The map on the left lists what the binary holds: its sections, functions (by source file or namespace), imports, exports, data and types, each folder with how many items it has. With the map focused, `Ctrl+F` (or just typing) filters it by name, closed folders included; `Escape` clears the filter. **Data** holds two folders: **Globals** (the symbol table's and those the analysis found once the whole program is analysed, whatever their type) and **Strings** (each by its text), each in address order; a string the symbol table names is a global. **Open as Tab** in a folder's right-click menu opens it as a table: type to filter, click a column's title to sort by it. The functions' table has each function's size and how many references there are to it; the data's has each global's type (a string's is its characters' array). `Ctrl+B` hides the map.

## Navigate

| Action | Default key |
| --- | --- |
| Go Anywhere… | `G` |
| Follow a name or address | `Enter` |
| Back / Forward | `Escape` / `Ctrl+Enter` |
| Cross-References | `X` |
| Next / Previous Function | `Ctrl+Down` / `Ctrl+Up` |
| Find in the current view | `Ctrl+F` |
| Search Everywhere… | `Ctrl+Shift+F` |
| Search Bytes… / Search Immediate… | `Alt+B` / `Alt+I` |
| Strings | `Shift+F12` |
| Fit Graph | `W` |
| Call Graph | `Ctrl+F12` |

The **Go** menu also has **Pathfinder**, **Path from Here**, **Path to Here** and **Callers with Arguments**. The hex view can show file offsets or mapped addresses; they are not interchangeable. **Show in Hex** opens the bytes for the current location.

## Rename, comment and type

`N` or `F2` renames the item under the cursor. `Y` opens **Set Type…**; `;` edits a comment. The target matters: a local, a function, a global and a struct member are different edits. Use the context menu when there is more than one plausible target.

Struct definitions printed above a function's C can be edited there. Rename a member with `N`, change its type with `Y`, or change its size with `D`. An edit that would move or overlap another member is refused. **Edit → Structs** contains **New Struct**, **Edit Struct**, **New Enum** and **Edit Enum…**. On a number, `M` chooses an enum representation and `H` returns to hexadecimal.

A type opened from the map's **Types** folder shows its C with each member's offset beside it, a row of `??` where bytes no member uses are, and the type's size beside `};`. Press `Enter` or double-click to edit it; `Esc` goes back while nothing is changed, and `Ctrl+S` applies. Double-click a type's name to open that type. `X` lists where the type is used: every line of the C that names it.

The listing's `C`, `U`, `D`, `A`, `*` and `P` correct code, undefined bytes, data, strings, arrays and function boundaries. These are analysis edits, not binary patches. Undo with `Ctrl+Z`; redo with `Ctrl+Shift+Z` or `Ctrl+Y`.

## Bookmarks and evidence

`Alt+M` opens **Bookmark…**; `Ctrl+M` opens **Bookmarks**. Your bookmarks appear at the top level. In a shared project, other people's bookmarks are grouped by author. A private bookmark stays local and is not exported. You can copy another person's bookmark into your own.

The evidence controls beside the C answer different questions. **Analysis → Why…** explains a name or type. **Go → Value Origin** (`Shift+X`) follows a value's sources and uses. **Verify Function** reports the checks for the current view. **Run from Here…** records a run from explicit inputs. The [verification](@/docs/verify.md) and [profiles](@/docs/profiles.md) pages explain their limits.

Hover a C token for its peek card and the contributing instructions. **View → IR View** (`Ctrl+K`, then `I`) exposes the intermediate representations; `<` and `>` move between stages, and **IR Diff with Previous** shows what changed. These views are useful when the C looks wrong: inspect the evidence before changing its presentation.

## Bottom dock

The bottom dock runs under the code, the whole width of its panes: lists of results, the Python console, terminals and agents open there, as tabs. It belongs to the window: switching tabs along the top keeps it as it is. `Ctrl+Backtick` or the console button in the status bar shows it with the console or the terminal you used last, and hides it when that is what it shows; the ⌄ at its top right hides it too, and **Bottom Dock** in the command palette shows or hides it as it is. Hidden, everything in it keeps running. Drag its top edge to resize it, or maximize it. Drag a tab out of it onto the code for a pane of its own, and onto the dock to put it back; the dock takes lists and shells only. It goes when its last tab closes. Its tabs, whether it is shown and its height are saved with the layout; a layout saved before the dock has its panes of lists and shells moved into it.

## Terminals

**Window → New Terminal** (`Ctrl+Shift+Backtick`) opens your shell in the binary's folder, in a tab of the [bottom dock](#bottom-dock). Drag its tab like any other. A terminal runs until its tab closes; closing it while a program the shell started still runs asks first (on Windows, which cannot tell, it never asks), and the shell exiting without an error closes its tab. `Ctrl+Backtick` shows and hides the dock with the console or the terminal you used last, and a hidden terminal keeps running. Right-click the console button in the status bar to choose the console, a terminal or a new one. A saved layout's terminal reopens as a fresh shell.

A coding agent started in a terminal that isn't connected to binbun gets a banner offering to set it up; see [Agents](@/docs/agents.md). Every terminal is told its window's script socket and binary (`BINBUN_SOCKET`, `BINBUN_DATABASE`), so `binbun mcp` started by an agent there works on that binary.

Keys go to the program except `Ctrl+Backtick`, the `Ctrl+Shift` chords and, on macOS, the `Cmd` chords. `Ctrl+Shift+C` copies the selection; `Ctrl+Shift+V` or `Shift+Insert` pastes (`⌘C` and `⌘V` on macOS). `Shift+Enter` sends a line feed, which agent CLIs take as a new line. Drag to select, double-click for a word, triple-click for a line, right-click for Copy and Paste. A program that takes the mouse gets it; hold `Shift` to select there instead. The wheel scrolls back through the history, or goes to the program. The terminal draws in the code font and the theme's code colours, with the standard 16-colour palette. Text from input methods (IME composition) does not reach it yet.

## Agents

The robot in the status bar, beside the console button, starts a coding agent in a terminal tab of the [bottom dock](#bottom-dock): your login shell runs its command (`claude`, `codex`, `pi`, …) in the binary's folder, as typed in a terminal. A click starts the agent you started last; the first time, it asks which. **Window → New Agent** does the same. Right-click the robot for the agents it started that are running, a new one of each agent, each with its mark, then **Change Agent…**, **Hide Agents Not Found** and **Customize…**, which opens **Settings › Agents**. Agents whose program your shell's `PATH` lacks are left out; turn off **Hide Agents Not Found** to list them greyed, "not found". In Settings › Agents each agent's command can be changed (`claude --model opus`; emptied, it is the agent's own again) and agents of your own added, a name and a command, or removed with ×. The settings file keeps them as `[agents.commands]` and `[[agents.custom]]`. An agent's tab closes when the agent exits without an error; otherwise its note says how it ended, with **Restart**.

## Themes and settings

Open **File → Settings…** with `Ctrl+,`. Settings cover fonts, window appearance, listing, C, scrolling, peek cards, symbols, signatures, updates, the collaboration relay and the Python interpreter. **Select Theme…** (`Ctrl+K`, then `Ctrl+T`) chooses among the bundled and user themes. **Dark Theme** (`Ctrl+K`, then `T`) switches the dark/light choice.

User themes are CSS files in the configuration directory's `themes` folder. They use an optional leading `@import` of a base theme and `:root` custom properties. Colour values, `var()` and `color-mix(in srgb, …)` are supported; this is not a general browser stylesheet. Unsupported syntax produces a file, line and column diagnostic.

**Open Settings File** opens `settings.toml`. Each group is a TOML table. A `[keys]` table maps command IDs to key strings or arrays; an empty array unbinds a command. For example, the existing command ID `edit.rename` controls Rename. In a key string `ctrl-` is Ctrl on every platform, `cmd-` is Cmd, and `secondary-` is Cmd on macOS and Ctrl elsewhere (`"file.open" = "secondary-o"`). Invalid settings are reported and keep their defaults. **Help → Files and Folders…** shows where the files live.
