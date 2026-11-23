//! A function's control-flow graph as a disassembler draws it: its basic
//! blocks (recovery's blocks joined across calls, which do not end a block
//! in the graph), with the parts and funclets joined to it, each with its
//! listing lines, and the edges between them with their kinds.

use std::collections::{BTreeMap, BTreeSet};
use std::ops::Range;

use crate::Database;
use crate::cfg::{
    Block as Recovered, BlockId, Destination, EdgeKind as Flow, Exit as Leave, FunctionId, Returns,
};
use crate::graph::layout;
use crate::listing::{LineKind, Listing, Rendered, Role, Token};

/// Why control goes from one block to another, as the graph colours it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EdgeKind {
    /// A conditional jump, taken.
    Taken,
    /// A conditional jump, not taken.
    NotTaken,
    /// An unconditional jump.
    Jump,
    /// Falling into the next block (after a call, or into a jump target).
    Next,
    /// A computed jump to one of its table's targets (a switch's case).
    Case,
    /// An exception unwinding through a call to its landing pad.
    Unwind,
}

impl EdgeKind {
    /// Where it leaves its block among the block's edges
    /// ([`layout::Edge::order`]): not taken on the left, taken on the
    /// right, unwinding rightmost.
    pub fn order(self) -> u8 {
        match self {
            Self::NotTaken => 0,
            Self::Jump | Self::Next | Self::Case => 1,
            Self::Taken => 2,
            Self::Unwind => 3,
        }
    }
}

/// A block of the graph.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Block {
    /// Its first instruction's address.
    pub start: u64,
    /// The address after its last instruction.
    pub end: u64,
    /// Its listing lines: the function's header for the entry, labels,
    /// instructions (no blank lines but one after a header, no
    /// separators, no cross-reference lines).
    pub lines: Vec<u64>,
    /// How control leaves it when no edge of the graph does.
    pub exit: Exit,
}

/// Where control goes outside the function.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Target {
    /// Code at an address (another function).
    Address(u64),
    /// An import, by its pointer slot.
    Import(u64),
}

/// How control leaves a block, for a block no edge of the graph leaves:
/// what its terminal mark says.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Exit {
    /// Along its edges.
    Edges,
    /// A return to the caller.
    Return,
    /// A call to a function that never returns (its target if known).
    NoReturn(Option<Target>),
    /// A trap or a halt, or code that does not decode.
    Stop,
    /// A jump recovery could not resolve: not an end, an unknown target.
    Unknown,
    /// A jump (or a fall) into other code: a tail call.
    Tail(Target),
}

impl Exit {
    /// How `block` ends, by recovery's exit.
    fn of(block: &Recovered) -> Self {
        let target = |d: Destination| match d {
            Destination::Address(a) => Some(Target::Address(a)),
            Destination::Import(slot) => Some(Target::Import(slot)),
            Destination::Pointer(_) | Destination::Indirect | Destination::Far => None,
        };
        match block.exit {
            Leave::Return => Self::Return,
            Leave::Stop | Leave::Invalid | Leave::Limit => Self::Stop,
            Leave::Call {
                callee,
                returns: Returns::No,
            } => Self::NoReturn(target(callee)),
            Leave::Call { .. } | Leave::Next => Self::Tail(Target::Address(block.end)),
            Leave::Jump(d) | Leave::Branch(d) => target(d).map_or(Self::Unknown, Self::Tail),
        }
    }
}

/// An edge of the graph, by block index.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Edge {
    /// Its source block.
    pub from: usize,
    /// Its target block.
    pub to: usize,
    /// Why control goes there.
    pub kind: EdgeKind,
}

/// A function's control-flow graph.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FunctionGraph {
    /// The function.
    pub function: FunctionId,
    /// Its entry.
    pub entry: u64,
    /// Its blocks: the entry's first, the rest by address.
    pub blocks: Vec<Block>,
    /// Its edges, by source block, in the order recovery states them.
    pub edges: Vec<Edge>,
    /// Block indices by start address.
    by_start: Vec<(u64, usize)>,
}

impl FunctionGraph {
    /// The graph of `function` in `db`, with lines from `listing` (built
    /// from the same database). `None` if there is no such function.
    pub fn build(db: &Database<'_>, listing: &Listing, function: FunctionId) -> Option<Self> {
        let program = db.program();
        let f = db.function(function)?;
        let mut ids: Vec<BlockId> = f.blocks.clone();
        let mut starts: BTreeSet<u64> = BTreeSet::new();
        starts.insert(f.entry);
        starts.extend(&f.parts);
        starts.extend(&f.landing_pads);
        for &funclet in &f.funclets {
            starts.insert(funclet);
            if let Some(g) = program.function_at(funclet).and_then(|id| db.function(id)) {
                ids.extend(&g.blocks);
                starts.extend(&g.landing_pads);
            }
        }
        let mut raw: Vec<(u64, u64, BlockId)> = ids
            .iter()
            .filter_map(|&id| program.blocks.get(id).map(|b| (b.start, b.end, id)))
            .collect();
        raw.sort_unstable_by_key(|r| (r.0, r.1));
        raw.dedup_by_key(|r| r.0);
        let index: BTreeMap<u64, usize> = raw.iter().enumerate().map(|(i, r)| (r.0, i)).collect();
        let successors: Vec<Vec<(Flow, usize)>> = raw
            .iter()
            .map(|&(_, _, id)| {
                program
                    .successors(id)
                    .filter_map(|(kind, target)| index.get(&target).map(|&j| (kind, j)))
                    .collect()
            })
            .collect();
        let joined = joined(&raw, &successors, &starts);
        // Groups of joined blocks, the entry's first.
        let mut group = vec![0usize; raw.len()];
        let mut spans: Vec<(u64, u64, BlockId)> = Vec::new();
        for (j, &(start, end, id)) in raw.iter().enumerate() {
            if joined.get(j) == Some(&true)
                && let Some(last) = spans.last_mut()
            {
                last.1 = end;
                last.2 = id;
            } else {
                spans.push((start, end, id));
            }
            if let Some(g) = group.get_mut(j) {
                *g = spans.len() - 1;
            }
        }
        let entry_group = index
            .get(&f.entry)
            .and_then(|&i| group.get(i).copied())
            .unwrap_or(0);
        let mut place: Vec<usize> = (0..spans.len()).collect();
        // The entry's group first, the others after it in address order.
        for p in &mut place {
            *p = match (*p).cmp(&entry_group) {
                std::cmp::Ordering::Less => *p + 1,
                std::cmp::Ordering::Equal => 0,
                std::cmp::Ordering::Greater => *p,
            };
        }
        let mut blocks: Vec<Block> = Vec::with_capacity(spans.len());
        let mut order: Vec<(usize, (u64, u64, BlockId))> =
            place.iter().copied().zip(spans).collect();
        order.sort_unstable_by_key(|o| o.0);
        for (_, (start, end, last)) in order {
            blocks.push(Block {
                start,
                end,
                lines: block_lines(listing, start..end),
                exit: program.blocks.get(last).map_or(Exit::Stop, Exit::of),
            });
        }
        let node = |raw: usize| group.get(raw).and_then(|&g| place.get(g)).copied();
        let edges = edges(&successors, &joined, &node);
        for (i, block) in blocks.iter_mut().enumerate() {
            if edges.iter().any(|e| e.from == i) {
                block.exit = Exit::Edges;
            }
        }
        let mut by_start: Vec<(u64, usize)> = blocks
            .iter()
            .enumerate()
            .map(|(i, b)| (b.start, i))
            .collect();
        by_start.sort_unstable();
        Some(Self {
            function,
            entry: f.entry,
            blocks,
            edges,
            by_start,
        })
    }

    /// The block holding `address`.
    pub fn block_of(&self, address: u64) -> Option<usize> {
        let i = self
            .by_start
            .partition_point(|&(start, _)| start <= address);
        let &(_, block) = self.by_start.get(i.checked_sub(1)?)?;
        self.blocks
            .get(block)
            .filter(|b| address < b.end)
            .map(|_| block)
    }

    /// The edges to lay out, in the order of [`Self::edges`].
    pub fn layout_edges(&self) -> Vec<layout::Edge> {
        self.edges
            .iter()
            .map(|e| layout::Edge {
                from: e.from,
                to: e.to,
                order: e.kind.order(),
            })
            .collect()
    }
}

/// Which blocks of `raw` (sorted by address, with their `successors` by
/// index) join the one before them: it only falls or returns from a call
/// into them, nothing else enters them, and they start nothing in
/// `starts` (the function's entry, its parts', funclets' and landing
/// pads').
fn joined(
    raw: &[(u64, u64, BlockId)],
    successors: &[Vec<(Flow, usize)>],
    starts: &BTreeSet<u64>,
) -> Vec<bool> {
    let mut predecessors = vec![0usize; raw.len()];
    for list in successors {
        for &(_, j) in list {
            if let Some(p) = predecessors.get_mut(j) {
                *p += 1;
            }
        }
    }
    raw.iter()
        .enumerate()
        .map(|(j, &(start, _, _))| {
            let Some(i) = j.checked_sub(1) else {
                return false;
            };
            let flows: Vec<&(Flow, usize)> = successors
                .get(i)
                .into_iter()
                .flatten()
                .filter(|(kind, _)| *kind != Flow::Unwind)
                .collect();
            raw.get(i).is_some_and(|r| r.1 == start)
                && matches!(flows.as_slice(), [(Flow::Next | Flow::CallReturn, t)] if *t == j)
                && predecessors.get(j) == Some(&1)
                && !starts.contains(&start)
        })
        .collect()
}

/// The edges between blocks (by `node` of a raw block), from the raw
/// blocks' `successors` without those inside a block (`joined`), each
/// once, by source block.
fn edges(
    successors: &[Vec<(Flow, usize)>],
    joined: &[bool],
    node: &dyn Fn(usize) -> Option<usize>,
) -> Vec<Edge> {
    let mut edges: Vec<Edge> = Vec::new();
    for (i, list) in successors.iter().enumerate() {
        for &(kind, j) in list {
            if joined.get(j) == Some(&true) && j == i + 1 && kind != Flow::Unwind {
                continue;
            }
            let (Some(from), Some(to)) = (node(i), node(j)) else {
                continue;
            };
            let kind = match kind {
                Flow::Next | Flow::CallReturn => EdgeKind::Next,
                Flow::Jump => EdgeKind::Jump,
                Flow::Taken => EdgeKind::Taken,
                Flow::NotTaken => EdgeKind::NotTaken,
                Flow::Table => EdgeKind::Case,
                Flow::Unwind => EdgeKind::Unwind,
            };
            let edge = Edge { from, to, kind };
            if !edges.contains(&edge) {
                edges.push(edge);
            }
        }
    }
    edges.sort_by_key(|e| e.from);
    edges
}

/// The first line of `listing` at or after `address`.
fn first_line(listing: &Listing, address: u64) -> u64 {
    let (mut low, mut high) = (0, listing.len());
    while low < high {
        let mid = low + (high - low) / 2;
        if listing.line(mid).is_some_and(|l| l.address < address) {
            low = mid + 1;
        } else {
            high = mid;
        }
    }
    low
}

/// The lines of `listing` a block of `addresses` shows.
fn block_lines(listing: &Listing, addresses: Range<u64>) -> Vec<u64> {
    let mut lines = Vec::new();
    let mut after_header = false;
    for n in first_line(listing, addresses.start)..first_line(listing, addresses.end) {
        let Some(line) = listing.line(n) else { break };
        let keep = match line.kind {
            LineKind::Attributes
            | LineKind::Prototype
            | LineKind::Public
            | LineKind::Proc
            | LineKind::Frame
            | LineKind::Label
            | LineKind::Preview
            | LineKind::Instruction
            | LineKind::Comment => true,
            LineKind::Blank => after_header,
            LineKind::SegmentBorder
            | LineKind::SegmentType
            | LineKind::SegmentPermissions
            | LineKind::Banner
            | LineKind::Xref
            | LineKind::Data
            | LineKind::Separator
            | LineKind::End => false,
        };
        after_header = matches!(line.kind, LineKind::Proc | LineKind::Frame);
        if keep {
            lines.push(n);
        }
    }
    lines
}

/// A listing line as a block shows it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BlockLine {
    /// Its tokens.
    pub rendered: Rendered,
    /// Each token's index among the listing line's.
    pub origin: Vec<usize>,
}

/// A listing line as a block shows it: without the address prefix (the
/// columns after it kept), and without cross-references (the edges show
/// them).
pub fn block_line(rendered: Rendered) -> BlockLine {
    let mut tokens: Vec<Token> = Vec::with_capacity(rendered.tokens.len());
    let mut origin: Vec<usize> = Vec::with_capacity(rendered.tokens.len());
    let mut prefix = 0;
    for (i, token) in rendered.tokens.into_iter().enumerate() {
        match token.role {
            Role::Prefix => prefix += token.text.chars().count(),
            Role::CodeXref | Role::DataXref => {}
            Role::Space
            | Role::OpcodeBytes
            | Role::Mnemonic
            | Role::JumpMnemonic
            | Role::CallMnemonic
            | Role::ReturnMnemonic
            | Role::PaddingMnemonic
            | Role::Register
            | Role::Number
            | Role::Punctuation
            | Role::Keyword
            | Role::OperandKeyword
            | Role::Directive
            | Role::CodeName
            | Role::DataName
            | Role::ImportName
            | Role::LocalName
            | Role::String
            | Role::Comment
            | Role::AutoComment => {
                tokens.push(token);
                origin.push(i);
            }
        }
    }
    // The prefix's own space, and as much of the padding after it, goes.
    let mut cut = prefix + 1;
    while cut > 0 {
        let Some(first) = tokens.first_mut() else {
            break;
        };
        if first.role != Role::Space {
            break;
        }
        let len = first.text.chars().count();
        if len <= cut {
            cut -= len;
            tokens.remove(0);
            origin.remove(0);
        } else {
            first.text = " ".repeat(len - cut);
            cut = 0;
        }
    }
    while tokens.last().is_some_and(|t| t.role == Role::Space) {
        tokens.pop();
        origin.pop();
    }
    BlockLine {
        rendered: Rendered { tokens },
        origin,
    }
}
