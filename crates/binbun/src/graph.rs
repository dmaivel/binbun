//! Graphs of a binary drawn in the usual disassembler layout, without any
//! drawing framework:
//!
//! - [`cfg`]: a function's control-flow graph from a [`binbun::Database`]:
//!   basic blocks as a disassembler's graph has them (calls do not end
//!   one; cold parts and funclets joined to the function are blocks of
//!   it), each block's lines of the [`listing`](crate::listing), edges
//!   with their kinds (taken, not taken, jump, fall-through, switch case,
//!   unwinding).
//! - [`layout`]: a layered layout of any graph of sized nodes (a call
//!   graph as well): root on top, few crossings, vertical chains straight,
//!   orthogonal edges with a track each between layers, deterministic.
//! - [`quality`]: what makes a drawing hard to follow, counted.
//! - [`svg`]: a laid out function graph as SVG (the CLI's `graph`).
//!
//! A front end measures each block (its lines in its font), calls
//! [`layout::layout`] once per function and size, and draws.

pub mod cfg;
pub mod layout;
pub mod quality;
pub mod svg;

pub use cfg::{Block, BlockLine, Edge, EdgeKind, Exit, FunctionGraph, Target, block_line};
pub use layout::{Layout, Point, Rect, Route, Size, Spacing};
pub use quality::{Quality, measure};
