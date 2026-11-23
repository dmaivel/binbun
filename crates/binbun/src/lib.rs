//! The binbun engine: one loaded executable as a program database
//! ([`Database`]), what joins the loader, the type library, control-flow
//! recovery, lifting and decompilation.
//!
//! - [`analysis`]: an image's seeds, what is known about its imports, the
//!   decoder for its machine, and recovery itself, computed jumps and
//!   calls resolved through the pointer slots they load or their tables
//!   ([`analysis::resolve`]); [`corrections`]: the user's corrections of
//!   what recovery finds (code, data, functions' bounds), as its seeds.
//! - [`target`]: the image's architecture and calling convention, as L1,
//!   lowering and the differential check need them.
//! - [`lift`]: recovered functions in SSA form (L1); [`summary`]: what
//!   they do to registers and the stack, callees first; [`funclets`]: the
//!   funclets of Microsoft x64 exception handlers built into their
//!   functions' L1.
//! - [`decompile`]: the pipeline from L1 to L2 and C, with the image's
//!   data ([`data`], [`memory`]) and its imports' prototypes
//!   ([`prototypes`]), and its debug information where given ([`debug`]).
//! - [`classes`]: the C++ classes an image's run-time type information
//!   shows (virtual tables, `type_info` objects), which name the structs
//!   that are them.
//! - [`eval`]: how well recovery found the functions the file states, and
//!   how much of the code lifts.
//! - [`references`]: every reference to an address, from code (calls,
//!   jumps, reads, writes, addresses taken, from L1's constants) and from
//!   data (relocated or scanned pointers), indexed by target and by
//!   function; [`strings`]: the string literals of the image's data, those
//!   referred to and those found by scanning.
//! - [`calls`]: the call graph, paths through it (by calls, or along
//!   which a parameter's value goes on), and call sites' known argument
//!   values.
//! - [`run`]: one function run from a named example state, the values
//!   of each C statement and machine instruction recorded.
//! - [`profile`]: processor profiles, what one microarchitecture does
//!   where the architecture leaves a value undefined, for runs and
//!   verification.
//! - [`queries`]: what the reading view shows beside a function's C: its
//!   verification against L1 on demand, why its variables have their
//!   types and names, where a value comes from and goes.
//! - [`stages`]: one function through every stage of decompilation
//!   (machine code, L1 after each pass, L2 after each pass, the C), each
//!   line's instructions and change, for an IR viewer.
//! - [`signatures`]: library signatures: packs made from static
//!   libraries, objects and linked files with symbols, and a binary's
//!   functions named by matching them.
//! - [`user`]: the user's types (prototypes, globals, frame and register
//!   variables), read from C, over every other declaration.
//! - [`cfg`]: architecture-neutral control-flow recovery: basic blocks,
//!   functions and which calls return, over any memory.
//! - [`listing`]: the continuous listing of an image in the usual
//!   disassembler layout: every mapped byte as lines of role-tagged tokens
//!   over a 64-bit line space.
//! - [`graph`]: graphs of a binary as disassemblers draw them: a function's
//!   blocks and edges with their listing lines, and a layered layout with
//!   orthogonal edges for any graph of sized nodes.

pub mod analysis;
pub mod calls;
pub mod cfg;
pub mod classes;
pub mod corrections;
pub mod data;
pub mod database;
pub mod debug;
pub mod decompile;
pub mod eval;
pub mod funclets;
pub mod graph;
pub mod lift;
pub mod listing;
pub mod manglings;
pub mod memory;
pub mod profile;
pub mod progress;
pub mod prototypes;
pub mod queries;
pub mod references;
pub mod run;
pub mod signatures;
pub mod stages;
pub mod strings;
pub mod summary;
pub mod target;
pub mod user;

pub use database::{Database, Error, GlobalField};
