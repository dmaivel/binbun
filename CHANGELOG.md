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

### Changed

- The reading view assumes that no code steps back from an address of a function's stack frame that the function passes or stores (as `container_of` does), and says so in its header: the locals below every such address are variables of their own instead of fields of the frame struct (most of an `-O0` function's locals).
- A stack slot that is accessed in parts and lives outside the frame struct has the type of its whole accesses (`int64_t frame_m78`) instead of being bytes (`uint8_t frame_m78[8]`).
- A pointer to an array of floats that its function's own code steps through, or reads as floats and writes with SIMD moves (`movups`), is a `float *` even where a callee is passed it as something else, and those moves are of `f32x4` (or `f64x2`) values: `*(f32x4 *)p = (f32x4){1.0f, 2.0f, 3.0f, 4.0f};` instead of a 128-bit integer constant.
- Vector constants of floats print their lanes as float literals (`(f32x4){1.0f, 0.5f, -0.0f, 3.0f}`) where every lane is a number.
- Nested loops that walk a matrix with pointers (a row pointer stepped beside its loop's counter, a column pointer stepped at the start of its body) are `for` loops of two indices reading `a[i + j * 4]`, where they were pointer loops whose offsets did not cancel.
- Sums print with their constants together (`p + i * 4` instead of `(p + 64) + i * 4 - 64`).
- A call's stack arguments pushed as 8 bytes and passed as 4 are passed as their values (`f(…, 4, p, 4)`) instead of through `uint8_t var_98[8]` and `*(int32_t *)var_98`.
- A choice by a constant condition is the arm it chooses: `rep stos`'s step prints `p = p + 1`, not `p = 0 ? p - 1 : p + 1`.
- A stack slot the compiler reuses for values of different types (an `int` spilled there, a pointer later) is a local per value instead of one variable read through casts (`*(int32_t *)&frame_m10 = result;`); a spill and its reload around a call disappear.
- Arithmetic on a `void *` is printed in bytes as GCC and Clang take it, without a byte pointer: `*(int32_t *)(v3 - 32)` instead of `*(int32_t *)((uint8_t *)v3 - 32)`.
- A 32- or 64-bit sum or product with a literal that must be unsigned gets an unsigned literal instead of a cast: `v0 - 14U <= 1` instead of `(uint32_t)(v0 - 14) <= 1`.

### Fixed

- A string constant held in a local and passed to two calls prints as the string literal at both, not as its address.

## v0.1.0 (2026-11-23)

First release of binbun.
