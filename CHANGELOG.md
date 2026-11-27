# Changelog

<!--
How this file is kept (written by hand; never generated from commits):

- Every change a user can notice gets a line under "## Unreleased" in the
  commit that makes it: the app, the `binbun` command, the Python
  package, the C library, the decoder crates, project files, install and
  update. Internal work (refactors, tests, CI) gets none.
- Lines go under one of: ### Added, ### Changed, ### Fixed, ### Removed,
  and ### Security for a fix to a security problem (the release is then
  announced to running binbuns as a security release, which a skipped
  version doesn't silence).
- Say what users can do or what they will see, not how it was done:
  "Opening a PE without a .pdata section no longer hangs", not "Fix loop
  in pdata parser". Name the surface where it isn't obvious (GUI, CLI,
  Python, C API). A breaking change says what to do instead.
- To release: rename "## Unreleased" to "## vX.Y.Z (YYYY-MM-DD)", start a
  new empty "## Unreleased" above it, set the version in both workspaces
  (Cargo.toml, gui/Cargo.toml), the crates.io crates' pins on each other
  (Cargo.toml's [workspace.dependencies], `version = "=X.Y.Z"`) and the
  C library's constants (core.h, binbun-capi's lib.rs), and tag
  vX.Y.Z;
  `scripts/release/check-release.sh vX.Y.Z` says first what is missing.
  The release workflow refuses a tag whose version has no section here
  or an empty one, and publishes the section as the release's notes.
- scripts/release/changelog-draft.sh lists the commit subjects since the
  last tag: raw material to check against this section, not to paste.

While binbun is 0.x, a 0.Y release may break the Rust crates' APIs, the
command's subcommands and flags, and the Python API outside
binbun.API_VERSION's promise; a 0.Y.Z release doesn't. Project files are
always read by later versions.
-->

## Unreleased

### Added

- GUI: in the hex view the byte under the pointer is lit in both the digits and the characters.
- GUI: the unified listing (**View → Unified View**, or `Unified` in a pane's view menu) shows the whole binary as one document in file order: the file's headers and tables as typed trees, each section as a card, each function as a card over its code (headed by its signature where its C is printed, its blocks under their labels, a loop foldable whole at its header), globals as typed trees, bytes nothing explains as hex rows. Cards fold and stay pinned at the top while what they hold scrolls by; the toolbar shows or hides the instruction bytes, untyped bytes as hex rows, and the file's structure. References are chips (one jumps, several open a menu), and a branch arrow whose other end is off screen is a stub that peeks at it on hover and goes there on a click. Rows select with `Shift` and copy as they show; Copy as Hex, Copy as C Array, Apply Type (`Alt+Q`) and Remove Type take the selected rows' bytes, and the find bar's bytes toggle searches the binary's bytes. A tab keeps its layers, folds and expanded rows.
- GUI: the hex view's structure tree types the file's own tables: an ELF's symbol tables (each symbol by its name), relocations, dynamic section and symbol versions; a PE's data directories (the import descriptors by library, the unwind table, the debug directory, the load configuration, the base relocation blocks); a Mach-O's load commands by their kinds (a library's and the dynamic linker's by their paths), its symbols and its link-edit data.
- Empty lines part a function's statements into paragraphs: after a run of declarations, after an `if`, a loop or a `switch` that another statement follows, and before a label. It is every style's default; `binbun decompile --spacing compact` (and `run`, `stages`), the GUI's C › Spacing setting and Python's `Database.set_style(spacing="compact")` print the statements without them, as before.
- `binbun eval types` says how the decompiler's structs line up with the debug information's named structs through the pointers it compares: source structs split under several of the decompiler's names, decompiler structs that merge several source structs (named, the worst first; `--totals` gives the counts), of the pairs of pointers to one source struct the share under one name, of those under one name the share to one source struct, and how many of those pointers it names a struct at all (a struct a translation unit only declares is the one of its name defined elsewhere; one no unit defines, an opaque handle as SQLite's `sqlite3_stmt`, which the library casts to its `Vdbe`, is left out of the structs and the pairs, and counted). It also scores the source's locals that live in registers ("register locals", in the totals too): each against the decompiler's local held in that register at the most of the instructions in the local's ranges that read or write it; their types count, not their struct identities (a register reused for another value maps too loosely to say which struct a pointer is).

### Changed

- GUI: the status bar no longer names the C view (`Reading` or `Exact`); the pane's view button does.
- GUI: `Ctrl+F` in the map (the left sidebar) opens its filter field, empty, for typing a name; typing there filtered before, but nothing showed it. `Escape` clears the filter, then closes the field.
- A struct on the stack whose address is passed to calls is one struct for all of them, and where a library function's declaration types the parameter it is passed as (`gettimeofday`'s `struct timeval *`), it is that declared struct: `difftimeval(struct timeval *, struct timeval *, struct timeval *)` instead of three structs of `difftimeval`'s own. On bash built with debug information, `struct timeval` is one struct instead of twelve names. The declared type names the struct only where its fields fit it, and not where they fit its first member alone: a stack slot the compiler reuses for a `scratch_buffer` and for `uname`'s `struct utsname` is no `utsname`, and `print_timeval(&self.ru_utime)` takes no `struct rusage *`.
- A function of the program that returns, on every path, what an allocator returns for its own unchanged size parameter (`xmalloc`, `xrealloc`, wrappers of those) is an allocator too: it and every call to it return `void *` (`void *xmalloc(uint64_t);` and `v = xmalloc(24);` instead of `char *xmalloc(uint64_t);` and `v = (struct s *)xmalloc(24);`), and its calls' sizes are allocation sizes, as a declared `malloc`'s are.
- The reading view assumes that no code steps back from an address of a function's stack frame that the function passes or stores (as `container_of` does), and says so in its header: the locals below every such address are variables of their own instead of fields of the frame struct (most of an `-O0` function's locals).
- A stack slot that is accessed in parts and lives outside the frame struct has the type of its whole accesses (`int64_t frame_m78`) instead of being bytes (`uint8_t frame_m78[8]`).
- A pointer to an array of floats that its function's own code steps through, or reads as floats and writes with SIMD moves (`movups`), is a `float *` even where a callee is passed it as something else, and those moves are of `f32x4` (or `f64x2`) values: `*(f32x4 *)p = (f32x4){1.0f, 2.0f, 3.0f, 4.0f};` instead of a 128-bit integer constant.
- Vector constants of floats print their lanes as float literals (`(f32x4){1.0f, 0.5f, -0.0f, 3.0f}`) where every lane is a number.
- Nested loops that walk a matrix with pointers (a row pointer stepped beside its loop's counter, a column pointer stepped at the start of its body) are `for` loops of two indices reading `a[i + j * 4]`, where they were pointer loops whose offsets did not cancel.
- Sums print with their constants together (`p + i * 4` instead of `(p + 64) + i * 4 - 64`).
- A call's stack arguments pushed as 8 bytes and passed as 4 are passed as their values (`f(…, 4, p, 4)`) instead of through `uint8_t var_98[8]` and `*(int32_t *)var_98`.
- A choice by a constant condition is the arm it chooses: `rep stos`'s step prints `p = p + 1`, not `p = 0 ? p - 1 : p + 1`.
- A stack slot the compiler reuses for different values (an `int` spilled there, a pointer later; or one pointer saved across a call and another across the next, of one width) is a local per value instead of one variable read through casts (`*(int32_t *)&frame_m10 = result;`), and the values' types and structs no longer meet in it: SQLite's JSON functions no longer type a `JsonParse *` as the `sqlite3_context *` saved in the same slot. A spill and its reload around a call disappear. On bash, casts fall from 17,579 to 16,847 (exact view) and from 16,490 to 14,795 (reading view); on SQLite's shell built with debug information, pairs of pointers under one name to one source struct rise from 98.6% to 99.2% (Lua's interpreter: 98.7% to 99.2%, and pointers to one source struct under one name from 93.4% to 95.0%).
- A stack slot in memory read and written in several widths at its first byte is a union of those views, each access naming its own: `frame.at_m28.w32 = v;` instead of `*(int32_t *)&frame.at_m28 = v;`.
- Arithmetic on a `void *` is printed in bytes as GCC and Clang take it, without a byte pointer: `*(int32_t *)(v3 - 32)` instead of `*(int32_t *)((uint8_t *)v3 - 32)`.
- A 32- or 64-bit sum or product with a literal that must be unsigned gets an unsigned literal instead of a cast: `v0 - 14U <= 1` instead of `(uint32_t)(v0 - 14) <= 1`.
- A call to a function of the program whose type summary does not reach it (in a cycle of calls, or past the summaries' limits) passes and takes the types the callee's own code gives its parameters and return value: `bind_variable("_", "", 0)` instead of `(int32_t *)bind_variable(0xedb47, 0xee82b, 0)`.
- A load or store at a constant base plus an index its own definition bounds (a mask, a narrow zero extension, a shift) is an element of the named object or of a table of the unnamed data it reaches: `is_basic_table[((uint8_t)c >> 5) & 7]` instead of `*(uint32_t *)((((uint8_t)c >> 5) & 7) * 4L + 0x102e40)`, `g_1b88a0[x & 0x3f]` instead of `*(int32_t *)((x & 0x3f) * 4 + 0x1b88a0)`.
- A local integer whose type nothing declares is signed or unsigned as fewer casts are then printed in the statements that read or write it (alone, or together with the locals it is compared with), instead of as its strongest evidence says: `uint32_t v8 = a1->field_8; if (v8 > 6) … v8 * 4L` instead of `int32_t v8 = a1->field_8; if ((uint32_t)v8 > 6) … (uint32_t)v8 * 4L`.
- A local `void *` or byte pointer whose type nothing declares points to the type that needs fewest casts in the statements that use it (one it is loaded or stored as, cast to, passed as or copied from, a byte, or `void`): `int32_t *v; … v[1] + v[2]` instead of `void *v; … *(int32_t *)(v + 4) + *(int32_t *)(v + 8)`. On bash 5–6% fewer casts, on libc 4–7%.
- A struct field read narrower than it is somewhere (`(int)p->len` loads the low half of a `long`) keeps its width, instead of becoming the narrower field and turning every other access into a cast; and two views of one struct where one reads a field narrower, or copies two fields at once, are one struct instead of two names. On bash built with debug information, pairs of pointers to one source struct under one name rise from 23% to 43%.
- A struct's pointer field that points to structs of different layouts in different functions, or to a struct in one and to characters in another (a hash bucket's `data`, a variable's `value`), is `void *` instead of a pointer to the first struct seen: its stores and loads need no casts, and the structs it points to are no longer merged through it.
- A variable no longer holds pointers to two different structs, or to a struct and to anything else: a hash bucket and the data it holds are two variables (`v3 = hash_search(…); … result = v3[2];`) instead of one typed as the bucket and read through casts; and where a pointer proved null on the way to a join is copied, the copy is of `0` (`if (v3 == 0) result = 0;`) instead of joining the tested variable with the result.
- Views of one struct that functions show different parts of (each reads the handle's first fields and some of its own, some narrower) are one struct where they read two fields alike, instead of a struct per size: on SQLite's shell built with debug information, pairs of pointers to one source struct under one name rise from 35% to 61% (Lua's interpreter: 49% to 93%; bash: 44% to 46%), with as few wrong.
- A function that returns a pointer to a struct or a null (`return 0;` on failure) returns a pointer to that struct, and its callers' values are that struct, instead of nothing being known of the struct; a field one function stores values of several struct types into (a parser's value stack: a word, a list of words, a command) is `void *` instead of uniting those that look alike; a buffer only ever read a byte at a time (`p[0]`, `p[1]`, `p[8]`) is a `char *`, not a struct; and a `malloc(32)` stored where a larger struct's pointer is kept stays `void *`, so no allocation is too small for its type. On bash built with debug information, pairs of pointers to one source struct under one name rise from 49% to 56%, and pointers typed as a struct at all from 64% to 68%.

### Fixed

- A function of very many blocks no longer takes time quadratic in them to lift (its stack offsets were found by sweeping every block until none changed): a 73,000-instruction function of zellij lifts in 2 s instead of 40 s, and every function of perf decompiles in the exact view in 95 s instead of 113 s, as before.
- Finding every function's callers (the GUI's "Reading callers" stage, `binbun decompile` of a whole program) keeps at most about 2 GB of the functions' lifted code between its passes, lifting the others again, instead of all of it: on a 50 MB program of 38,000 functions (zellij) it finishes at a peak of 9.6 GB where it ran the machine out of memory past 19 GB; on perf (7,600 functions) it peaks at 3.4 GB instead of 4.3 GB and takes 51 s instead of 47 s; bash's is all kept, as before.
- GUI: a pane's view button, pressed again, closes its open menu instead of opening it anew.
- GUI: a font button in Settings, pressed again, closes its open menu instead of opening it anew.
- A variable or object that holds allocations of known sizes (`malloc(3)` and `malloc(2)` on two paths) is no pointer to a struct larger than the smallest of them, so clang no longer warns that an allocation is too small for its type: on bash, 14 of those warnings go from the exact view.
- A struct that starts some bytes into an object a call returns (Lua's `lua_State`, 8 bytes into the `LG` its `global_State` follows) takes no fields from that function's accesses to the object, so it is not printed as large as the whole object: on Lua's interpreter, struct field precision rises from 61% to 67%, and pointer parameters whose pointee has the right size from 36% to 43%.
- A string constant held in a local and passed to two calls prints as the string literal at both, not as its address.
- GUI: the graph's taken and not-taken edges are green and red in every bundled theme. Taken edges took the theme's string colour (orange in Dark Modern, blue in the GitHub themes, yellow in Dracula and Monokai, cyan in Solarized), and Solarized Dark's not-taken edges were near white. A theme sets them with `--branch-taken` and `--branch-not-taken`, else its `--success` and `--error`.

## v0.1.0 (2026-11-23)

First release of binbun.
