//! Which machine instructions each piece of a function's C came from
//! ([`Provenance`]): every token's L2 node, every node's instructions
//! (its origins; an L1 value by the instruction defining it, a block
//! parameter by its block's start), every line's instructions (those of
//! its expressions and statements; the signature's, the prologue's; the
//! closing brace's, the epilogue's). What links a C line to the listing
//! and back, for every front end: the GUI's C view, the Python API's
//! documents, and the session's own printing (a comment goes at the end
//! of the first line made from its instruction, a number takes the form
//! chosen at an instruction of its line).

use std::collections::{HashMap, HashSet};
use std::ops::Range;

use binbun_ast::ir::{Function as Ast, Node, Origin};
use binbun_ssa::ir::{Definition, Function as L1};

/// A line of a function's C and the instructions it came from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Line {
    /// Its bytes in the text, without the newline.
    pub range: Range<usize>,
    /// Its tokens, as indices of the spans.
    pub spans: Range<usize>,
    /// The instructions its expressions and statements came from, sorted,
    /// each once.
    pub addresses: Vec<u64>,
}

/// The provenance of a function's C: its lines' instructions, its tokens'
/// nodes and their instructions.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Provenance {
    lines: Vec<Line>,
    /// Each token's node.
    nodes: Vec<Option<Node>>,
    /// The instructions each node among the tokens came from, sorted.
    addresses: HashMap<Node, Vec<u64>>,
}

impl Provenance {
    /// The provenance of `text`, its tokens' `spans` (each its bytes in
    /// `text` and its node, in order), the nodes being of `l2`, lowered
    /// from `l1`; `definition`: the line where the function's definition
    /// starts (its signature), which its prologue's instructions
    /// ([`Ast`]'s `provenance.entry()`) go to, as its epilogue's
    /// (`provenance.exit()`) go to its closing brace (the last line
    /// that is one), each but those a line came from already.
    pub fn new(
        text: &str,
        spans: impl IntoIterator<Item = (Range<usize>, Option<Node>)>,
        l2: &Ast,
        l1: &L1,
        definition: Option<usize>,
    ) -> Self {
        let (ranges, nodes): (Vec<Range<usize>>, Vec<Option<Node>>) = spans.into_iter().unzip();
        let mut addresses: HashMap<Node, Vec<u64>> = HashMap::new();
        for &node in nodes.iter().flatten() {
            addresses
                .entry(node)
                .or_insert_with(|| node_addresses(node, l2, l1));
        }
        let mut lines = Vec::new();
        let mut start = 0;
        let mut span = 0;
        for piece in text.split('\n') {
            let end = start + piece.len();
            let first = span;
            while ranges.get(span).is_some_and(|r| r.start <= end) {
                span += 1;
            }
            let mut on_line: Vec<u64> = nodes
                .get(first..span)
                .unwrap_or_default()
                .iter()
                .flatten()
                .filter(|n| matches!(n, Node::Expr(_) | Node::Stmt(_)))
                .flat_map(|n| addresses.get(n).into_iter().flatten().copied())
                .collect();
            on_line.sort_unstable();
            on_line.dedup();
            lines.push(Line {
                range: start..end,
                spans: first..span,
                addresses: on_line,
            });
            start = end + 1;
        }
        if let Some(definition) = definition {
            frame(&mut lines, text, definition, l2, l1);
        }
        Self {
            lines,
            nodes,
            addresses,
        }
    }

    /// The lines, in order.
    pub fn lines(&self) -> &[Line] {
        &self.lines
    }

    /// The instructions line `n` came from, sorted (none past the last
    /// line).
    pub fn addresses_of(&self, n: usize) -> &[u64] {
        self.lines
            .get(n)
            .map_or(&[], |line| line.addresses.as_slice())
    }

    /// The lines made from the instruction at `address`, in order.
    pub fn lines_of(&self, address: u64) -> impl Iterator<Item = usize> + '_ {
        self.lines
            .iter()
            .enumerate()
            .filter(move |(_, line)| line.addresses.binary_search(&address).is_ok())
            .map(|(n, _)| n)
    }

    /// The line token `s` is on.
    pub fn line_of_span(&self, s: usize) -> Option<usize> {
        let n = self.lines.partition_point(|line| line.spans.end <= s);
        (n < self.lines.len()).then_some(n)
    }

    /// Token `s`'s node.
    pub fn node(&self, s: usize) -> Option<Node> {
        self.nodes.get(s).copied().flatten()
    }

    /// The instructions `node` came from, sorted (none for a node no token
    /// stands for).
    pub fn node_addresses(&self, node: Node) -> &[u64] {
        self.addresses.get(&node).map_or(&[], Vec::as_slice)
    }

    /// The instructions token `s` stands for: its node's (an expression's
    /// or a statement's), else its line's.
    pub fn span_addresses(&self, s: usize) -> &[u64] {
        let node = self
            .node(s)
            .filter(|n| matches!(n, Node::Expr(_) | Node::Stmt(_)));
        match node.map(|n| self.node_addresses(n)) {
            Some(addresses) if !addresses.is_empty() => addresses,
            _ => self
                .line_of_span(s)
                .map_or(&[], |line| self.addresses_of(line)),
        }
    }

    /// The tokens standing for an expression or statement made from the
    /// instruction at `address`: the narrowest such nodes' tokens (an
    /// enclosing statement's are left out when an expression of it came
    /// from the instruction).
    pub fn spans_of(&self, address: u64) -> Vec<usize> {
        let made = |node: Node| self.node_addresses(node).binary_search(&address).is_ok();
        let tokens = |exprs_only: bool| -> Vec<usize> {
            self.nodes
                .iter()
                .enumerate()
                .filter(|(_, node)| match node {
                    Some(n @ Node::Expr(_)) => made(*n),
                    Some(n @ Node::Stmt(_)) => !exprs_only && made(*n),
                    Some(Node::Var(_) | Node::Type(_)) | None => false,
                })
                .map(|(s, _)| s)
                .collect()
        };
        let exprs = tokens(true);
        if exprs.is_empty() {
            tokens(false)
        } else {
            exprs
        }
    }
}

/// The instructions `node` of `l2` came from (lowered from `l1`): its
/// origins (a variable's: what it was made from), sorted, each once.
pub fn node_addresses(node: Node, l2: &Ast, l1: &L1) -> Vec<u64> {
    let origins: &[Origin] = match node {
        Node::Expr(e) => l2.provenance.expr(e),
        Node::Stmt(s) => l2.provenance.stmt(s),
        Node::Var(v) => usize::try_from(v.0)
            .ok()
            .and_then(|v| l2.variables.get(v))
            .map_or(&[], |v| v.origins.as_slice()),
        Node::Type(_) => &[],
    };
    let mut out: Vec<u64> = origins
        .iter()
        .filter_map(|origin| instruction(origin, l1))
        .collect();
    out.sort_unstable();
    out.dedup();
    out
}

/// Adds the instructions of `l2`'s frame code to `lines` (of `text`): its
/// prologue's to line `definition`, its epilogue's to the last line that
/// is a closing brace; each but those a line came from already, which
/// keep their line.
fn frame(lines: &mut [Line], text: &str, definition: usize, l2: &Ast, l1: &L1) {
    let brace = text
        .split('\n')
        .enumerate()
        .filter(|&(n, piece)| n >= definition && piece.trim() == "}")
        .map(|(n, _)| n)
        .last();
    let made: HashSet<u64> = lines
        .iter()
        .flat_map(|line| line.addresses.iter().copied())
        .collect();
    let parts = [
        (Some(definition), l2.provenance.entry()),
        (brace, l2.provenance.exit()),
    ];
    for (at, origins) in parts {
        let Some(line) = at.and_then(|n| lines.get_mut(n)) else {
            continue;
        };
        let before = line.addresses.len();
        line.addresses.extend(
            origins
                .iter()
                .filter_map(|origin| instruction(origin, l1))
                .filter(|address| !made.contains(address)),
        );
        if line.addresses.len() > before {
            line.addresses.sort_unstable();
            line.addresses.dedup();
        }
    }
}

/// The instruction `origin` names: itself, or the one defining its L1
/// value (a block parameter's: its block's start).
fn instruction(origin: &Origin, l1: &L1) -> Option<u64> {
    match *origin {
        Origin::Instruction(address) => Some(address),
        Origin::Value(value) => match l1.values.get(usize::try_from(value.0).ok()?)?.definition {
            Definition::Result { inst, .. } => l1.inst(inst).map(|i| i.address),
            Definition::Parameter { block, .. } => l1.block(block).map(|b| b.address),
        },
        Origin::Register(_)
        | Origin::Held(_)
        | Origin::Slot(_)
        | Origin::Block(_)
        | Origin::Absorbed(_)
        | Origin::Proved => None,
    }
}

#[cfg(test)]
mod tests {
    use binbun_ast::ir::{ExprId, Function as Ast, Node, StmtId, VarId};
    use binbun_ast::types::Types;
    use binbun_ssa::ir::Function as L1;

    use super::Provenance;

    /// `a = b;` / `if (c)` / `{` over three lines, without an L2 to find
    /// instructions in: lines and tokens only.
    #[test]
    fn tokens_go_to_the_line_they_start_on() {
        let text = "a = b;\nif (c)\n{";
        let spans = [
            (0..1, Some(Node::Var(VarId(0)))),
            (2..3, None),
            (4..5, Some(Node::Expr(ExprId(0)))),
            (7..9, Some(Node::Stmt(StmtId(0)))),
            (11..12, Some(Node::Expr(ExprId(1)))),
            (14..15, None),
        ];
        let l2 = Ast::new(0, Types::new(64));
        let provenance = Provenance::new(text, spans, &l2, &L1::default(), None);
        let lines: Vec<_> = provenance
            .lines()
            .iter()
            .map(|l| (l.range.clone(), l.spans.clone()))
            .collect();
        assert_eq!(lines, vec![(0..6, 0..3), (7..13, 3..5), (14..15, 5..6)]);
        assert_eq!(provenance.line_of_span(4), Some(1));
        assert_eq!(provenance.line_of_span(6), None);
        assert_eq!(provenance.node(3), Some(Node::Stmt(StmtId(0))));
        // No origins: nothing made from any instruction.
        assert_eq!(provenance.span_addresses(2), &[] as &[u64]);
        assert_eq!(provenance.spans_of(0x10), Vec::<usize>::new());
        assert_eq!(provenance.lines_of(0x10).count(), 0);
    }
}
