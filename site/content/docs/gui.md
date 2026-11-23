+++
title = "The GUI"
weight = 30
+++

## Panes, views and tabs

A pane can show the listing, its graph, decompiled C, hex, a call graph or IR. A button in its header names what it shows (`Listing`, `Graph`, `Hex`, `Calls`, `C`, `Exact C` or `IR`) and opens a menu of every view with its keys; choosing there, or pressing a view's key, is the only thing that changes a pane's view. `C` is the reading view, `Exact C` the exact one. **View** holds the commands; the command palette (`Ctrl+Shift+P`) finds them by name. `Space` changes listing and graph in place. `F5` shows C. `Tab` switches between listing and C, switching the current pane if no other pane shows the requested view.

These pages write shortcuts as on Linux and Windows. On macOS `Ctrl` is `Cmd` (`⌘O` opens a file, `⌘Q` quits), except `Ctrl+M` (Bookmarks), `Ctrl+Backtick` (Console) and the console's own `Ctrl+C` and `Ctrl+L`, which stay `Ctrl`; the menus and the palette show each key as your platform writes it.

The tabs along the top are places, each titled by the function it is in. A tab's panes all show its place and share its Back/Forward trail: a double-click on a call in the C moves the whole tab there, and `Escape` in any of its panes returns it. `Ctrl+click` or a middle-click on a name, a row of the map or a list opens it in a new tab after the current one, with the same panes and views (with `Shift`, the current tab stays shown); `+` opens one at the current place. Nothing moves a tab but what is done in it. `Ctrl+PageDown` and `Ctrl+PageUp` go to the next and previous tab, and `Ctrl+W` or a middle-click on a tab closes it (the last tab of a place stays). Lists whose rows go places (cross-references, search results, strings, a map folder) open in a pane of their own below the code, later ones as tabs there, so clicking a row moves the code while the list stays in view; in that pane `Ctrl+W` closes the list shown. The settings and a struct being edited are tabs along the top of their own; a navigation from one goes to a tab of a place. Use **Split Right** (`Ctrl+K`, then `Right`) or **Split Down** (`Ctrl+K`, then `Down`) for another view of the tab's place, and **Close Pane** (`Ctrl+K`, then `W`, or the × at a pane's top right when its tab has more than one) to close one. **Open Graph in Split** adds a graph beside the current pane. Every tab of a place, its panes and each pane's view are saved per project, and come back in order, each at its place, when the binary is opened again.

**Window → Link Pane** sets a pane on its own within its tab, or links it again. In linked panes, selecting C highlights the corresponding instructions; selecting an instruction highlights its C where there is a mapping. This is provenance, not a one-to-one line correspondence. Several instructions may become one expression, and instructions that produce no C may have no matching line.

## The map

The map on the left lists what the binary holds: its sections, functions (by source file or namespace), imports, exports, data and types, each folder with how many items it has. **Data** holds two folders: **Globals** (the symbol table's and those the analysis found once the whole program is analysed, whatever their type) and **Strings** (each by its text), each in address order; a string the symbol table names is a global. **Open as Tab** in a folder's right-click menu opens it as a table: type to filter, click a column's title to sort by it. The functions' table has each function's size and how many references there are to it; the data's has each global's type (a string's is its characters' array). `Ctrl+B` hides the map.

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

## Themes and settings

Open **File → Settings…** with `Ctrl+,`. Settings cover fonts, window appearance, listing, C, scrolling, peek cards, symbols, signatures, updates, the collaboration relay and the Python interpreter. **Select Theme…** (`Ctrl+K`, then `Ctrl+T`) chooses among the bundled and user themes. **Dark Theme** (`Ctrl+K`, then `T`) switches the dark/light choice.

User themes are CSS files in the configuration directory's `themes` folder. They use an optional leading `@import` of a base theme and `:root` custom properties. Colour values, `var()` and `color-mix(in srgb, …)` are supported; this is not a general browser stylesheet. Unsupported syntax produces a file, line and column diagnostic.

**Open Settings File** opens `settings.toml`. Each group is a TOML table. A `[keys]` table maps command IDs to key strings or arrays; an empty array unbinds a command. For example, the existing command ID `edit.rename` controls Rename. In a key string `ctrl-` is Ctrl on every platform, `cmd-` is Cmd, and `secondary-` is Cmd on macOS and Ctrl elsewhere (`"file.open" = "secondary-o"`). Invalid settings are reported and keep their defaults. **Help → Files and Folders…** shows where the files live.
