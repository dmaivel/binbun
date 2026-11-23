//! One function's C as the view shows it: lines of
//! tokens, each with its kind and the L2 node it stands for, and for every
//! node the machine instructions it came from (its provenance), so the C
//! and the listing follow each other.
//!
//! - **Linked by colour**: each line with
//!   instructions gets one of [`TINTS`] tints in turn ([`CLine::tint`]);
//!   its instructions take the same tint in the listing
//!   ([`CDocument::tint_of`]).
//! - **Hover links**: a token's instructions ([`CDocument::span_addresses`])
//!   and an instruction's tokens ([`CDocument::spans_of`]), as the
//!   session's document's provenance has them ([`Provenance`]).
//! - **Editing**: a variable's name is a field
//!   ([`Field`]); while it is edited every occurrence shows the new text
//!   as it is typed, an empty field shows the default name dimmed; on commit the
//!   session renames the variable and prints again, and the cursor finds
//!   it again by identity ([`Node`]), not by offset.
//!   A member's name is a field the same way, wherever it is printed (its
//!   line of the struct's definition, `p->name`, `v.name`): its
//!   occurrences are the struct's ([`CDocument::members`]); the cursor
//!   finds it again by the struct's key and the new name ([`Anchor`]).
//! - **Definitions**: the struct and union definitions the C prints, each
//!   a block of lines ([`CDocument::definition_at`]) edited in place as
//!   the struct editor edits it.
//! - **Comments**: the user's comments, printed by the session at the end
//!   of the lines made from their instructions (`/* text */`), are shown
//!   as `// text` ([`CDocument::comments`]); a comment typed on a line
//!   goes to the address [`CDocument::comment_address`] says.
//! - **Reveals**: the reading view hides the checks it assumed away, never
//!   lies; each line hiding one is marked, and the mark shows the exact
//!   C's lines there ([`CDocument::reveals`]), found through provenance,
//!   each check in its short form (`binbun_check_canonical(p);`) where
//!   the exact C spells its test out ([`CDocument::card_lines`]).

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::ops::Range;
use std::sync::Arc;

use binbun::cfg::FunctionId;
use binbun::decompile::Decompiled;
use binbun_ast::ir::{Expr, ExprId, Function as Ast, Node, Origin, Stmt, StmtId, VarId};
use binbun_ast::types::TypeId;
use binbun_print::document::TokenKind;
use binbun_semantics::ir::{RegisterId, SiteId, Trap};
use binbun_session::number::{Written, parse};
use binbun_session::{Document, Provenance, View};
use binbun_ssa::ir::{BlockId, Definition, Function as L1, Terminator, Unknown};

/// How many tints link C lines to instructions.
pub const TINTS: u8 = 4;

/// The most exact C lines a check's reveal spans from its first line to
/// its last (a check is a few lines; past this, only its own lines).
pub const REVEAL_SPAN: usize = 12;

/// A line of a reveal card ([`CDocument::card_lines`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CardLine {
    /// A line of the exact C, as it is.
    Line(usize),
    /// A check's line, in its short form (indented as it).
    Check {
        /// The line.
        line: usize,
        /// The short form.
        text: String,
    },
}

/// The short form of the canonical-address check C line `text` spells
/// out (`if ((uint64_t)sext_n((uint64_t)p, 48) != (uint64_t)p) break;`),
/// trapping with `trap`: `binbun_check_canonical(p);` (#GP) or
/// `binbun_check_canonical_stack(p);` (#SS), indented as `text`. `None`
/// for any other line.
fn short_check(text: &str, trap: Trap) -> Option<String> {
    let name = if trap == Trap::Protection {
        "binbun_check_canonical"
    } else if trap == Trap::Stack {
        "binbun_check_canonical_stack"
    } else {
        return None;
    };
    let indent = text.len() - text.trim_start().len();
    let open = text.find("if (")? + "if ".len();
    // The `)` closing the condition.
    let mut depth = 0usize;
    let close = text.get(open..)?.char_indices().find_map(|(at, c)| {
        match c {
            '(' => depth += 1,
            ')' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Some(open + at);
                }
            }
            _ => {}
        }
        None
    })?;
    let condition = text.get(open + 1..close)?;
    let (extended, p) = condition.split_once(" != ")?;
    if !extended.contains("sext_n(") || !extended.ends_with(", 48)") {
        return None;
    }
    let p = p.strip_prefix("(uint64_t)").unwrap_or(p);
    Some(format!("{}{name}({p});", text.get(..indent)?))
}

/// A line of the reading view that hides checks the exact C makes: what
/// the exact C has there.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reveal {
    /// The instructions whose checks the line hides, sorted.
    pub sites: Vec<u64>,
    /// The exact C's lines there (of its document), in order: each
    /// check's lines from its first to its last.
    pub exact: Vec<usize>,
}

/// A token of the C.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CSpan {
    /// Its bytes in [`CDocument::text`].
    pub range: Range<usize>,
    /// What it is.
    pub kind: TokenKind,
    /// The L2 node it stands for.
    pub node: Option<Node>,
    /// Whether it is a name binbun made up (`v17`, `sub_401000`).
    pub automatic: bool,
    /// Whether it is part of a cast (its parentheses or type).
    pub cast: bool,
}

/// A line of the C.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CLine {
    /// Its bytes in [`CDocument::text`], without the newline.
    pub range: Range<usize>,
    /// Its tokens, as indices of [`CDocument::spans`].
    pub spans: Range<usize>,
    /// The instructions its expressions and statements came from, sorted.
    pub addresses: Vec<u64>,
    /// Its link tint (below [`TINTS`]), if it has instructions.
    pub tint: Option<u8>,
}

/// A value the architecture leaves undefined, as the C shows it
/// (`_OF_undefined`): processors differ there.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UndefinedValue {
    /// The instruction leaving it undefined.
    pub address: u64,
    /// The register it leaves undefined, if one.
    pub register: Option<RegisterId>,
    /// Its site, if the architecture names one (`shrd.of`).
    pub site: Option<SiteId>,
}

/// One function's C, printed.
#[derive(Clone, Debug)]
pub struct CDocument {
    /// The function.
    pub function: FunctionId,
    /// Its entry.
    pub entry: u64,
    /// The view it is in.
    pub view: View,
    /// The text.
    pub text: String,
    /// The tokens, in order.
    pub spans: Vec<CSpan>,
    /// The lines.
    pub lines: Vec<CLine>,
    /// Each variable's name without the user's (what an empty field
    /// resets to).
    pub defaults: BTreeMap<VarId, String>,
    /// The parameters, in order, with their printed names.
    pub parameters: Vec<(VarId, String)>,
    /// The function decompiled (what a run or a call site's state is made
    /// from), if it came from a session's document.
    pub decompiled: Option<Arc<Decompiled>>,
    /// Each member name's span (its line of a struct's definition, or a
    /// use: `p->name`) with the struct or union it is a member of.
    pub members: BTreeMap<usize, TypeId>,
    /// The user's comments' spans (one per line of a comment, shown as
    /// `// text`), each with the address its comment is at.
    pub comments: BTreeMap<usize, u64>,
    /// How many values the C shows that the architecture leaves undefined
    /// (processors differ there).
    pub processor_dependent: usize,
    /// Those values' instructions, registers and sites, in order, once.
    pub undefined_values: Vec<UndefinedValue>,
    /// Which instructions each line and token came from: the session's
    /// document's, or made from the parts given.
    provenance: Arc<Provenance>,
    /// Each instruction's tint: its first line's.
    tints: HashMap<u64, u8>,
    /// The statements of the checks L0 makes at each instruction (an
    /// access's canonical-address checks, by the instruction): each
    /// deciding one and its arms' jumps ([`checks`]).
    checks: HashMap<u64, Vec<Node>>,
    /// The trap of the check at each instruction of [`Self::checks`].
    traps: HashMap<u64, Trap>,
    /// The condition (or scrutinee) of each statement with one among the
    /// tokens: an `if`, a loop, a `switch`.
    conditions: HashMap<StmtId, ExprId>,
}

/// A piece of a line as shown: a token or the text between tokens.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Piece {
    /// Its bytes in [`ShownLine::text`] (never empty).
    pub range: Range<usize>,
    /// The token it shows, if it is one.
    pub span: Option<usize>,
    /// Whether it stands in for an empty field: the default name, dimmed.
    pub placeholder: bool,
}

/// A line as shown while a field may be edited: the text and the pieces
/// that cover it exactly, in order (what a renderer's text runs need).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShownLine {
    /// The text.
    pub text: String,
    /// The pieces, covering [`Self::text`] end to end.
    pub pieces: Vec<Piece>,
    /// The piece of the field's own occurrence, where the editor goes.
    pub field: Option<usize>,
}

impl CDocument {
    /// The checks the reading view assumed in this document, by the
    /// instruction each guards (none in the exact view, or without the
    /// decompiled function).
    pub fn assumed(&self) -> &[u64] {
        self.decompiled
            .as_ref()
            .filter(|_| self.view == View::Reading)
            .map_or(&[], |d| d.stats.assumed.sites.as_slice())
    }

    /// The line standing for the instruction at `address` most narrowly:
    /// the first line of the narrowest tokens made from it
    /// ([`Self::spans_of`]) or, when they are a statement's deciding on a
    /// condition, that condition's line (a `do`'s `while`), else the
    /// nearest line for it ([`Self::line_for`]).
    pub fn site_line(&self, address: u64) -> Option<usize> {
        let first = self.spans_of(address).first().copied();
        let condition = first
            .and_then(|s| match self.spans.get(s)?.node? {
                Node::Stmt(stmt) => self.conditions.get(&stmt).copied(),
                Node::Expr(_) | Node::Var(_) | Node::Type(_) => None,
            })
            .and_then(|c| self.occurrences(Node::Expr(c)).next());
        condition
            .or(first)
            .and_then(|s| self.line_of_span(s))
            .or_else(|| self.line_for(address))
    }

    /// The lines of the checks L0 makes at the instruction at `address`:
    /// the first line of each statement deciding one and of its arms'
    /// jumps (an L1 branch on a value the instruction computes, one way
    /// only trapping, is one).
    pub fn check_lines(&self, address: u64) -> BTreeSet<usize> {
        self.checks
            .get(&address)
            .into_iter()
            .flatten()
            .filter_map(|&node| self.occurrences(node).next())
            .filter_map(|s| self.line_of_span(s))
            .collect()
    }

    /// The lines of this (reading) document that hide the checks at
    /// `sites` (the instructions each guards, [`Self::assumed`]), each with
    /// what `exact` (the exact C of the same function, if here) has there:
    /// for each, its checks' lines ([`Self::check_lines`]) and the access
    /// after them (the first line below them made from the instruction),
    /// from the first to the last when they are close ([`REVEAL_SPAN`]).
    /// Where the exact C has no check statement for it, the lines made
    /// from the instruction.
    pub fn reveals(&self, sites: &[u64], exact: Option<&Self>) -> BTreeMap<usize, Reveal> {
        let mut out: BTreeMap<usize, (BTreeSet<u64>, BTreeSet<usize>)> = BTreeMap::new();
        for &site in sites {
            let Some(line) = self.site_line(site) else {
                continue;
            };
            let (on_line, shown) = out.entry(line).or_default();
            on_line.insert(site);
            let Some(exact) = exact else {
                continue;
            };
            let made: BTreeSet<usize> = exact
                .spans_of(site)
                .into_iter()
                .filter_map(|s| exact.line_of_span(s))
                .collect();
            let mut lines = exact.check_lines(site);
            match lines.last().copied() {
                Some(last) => lines.extend(made.range(last + 1..).next()),
                None => lines = made,
            }
            match (lines.first(), lines.last()) {
                (Some(&first), Some(&last)) if last - first < REVEAL_SPAN => {
                    shown.extend(first..=last);
                }
                _ => shown.extend(lines),
            }
        }
        out.into_iter()
            .map(|(line, (sites, exact))| {
                let reveal = Reveal {
                    sites: sites.into_iter().collect(),
                    exact: exact.into_iter().collect(),
                };
                (line, reveal)
            })
            .collect()
    }

    /// What a reveal card shows of `lines` (of this exact C), in order:
    /// each line, but a check whose test the C spells out (`if (sext_n(p,
    /// 48) != p) break;`, its trap elsewhere) in `binbun_defs.h`'s short form,
    /// as the C writes a check whose trap is alone in its arm
    /// (`binbun_check_canonical(p);`), its jumps' lines left out.
    pub fn card_lines(&self, lines: &[usize]) -> Vec<CardLine> {
        let mut short: HashMap<usize, String> = HashMap::new();
        let mut hidden: BTreeSet<usize> = BTreeSet::new();
        for (address, nodes) in &self.checks {
            let Some((&decides, jumps)) = nodes.split_first() else {
                continue;
            };
            let line_of = |node| {
                self.occurrences(node)
                    .next()
                    .and_then(|s| self.line_of_span(s))
            };
            let (Some(line), Some(&trap)) = (line_of(decides), self.traps.get(address)) else {
                continue;
            };
            let Some(text) = short_check(self.line_text(line), trap) else {
                continue;
            };
            short.insert(line, text);
            hidden.extend(
                jumps
                    .iter()
                    .filter_map(|&jump| line_of(jump))
                    .filter(|&l| l != line),
            );
        }
        lines
            .iter()
            .filter(|n| !hidden.contains(n))
            .map(|&n| match short.remove(&n) {
                Some(text) => CardLine::Check { line: n, text },
                None => CardLine::Line(n),
            })
            .collect()
    }

    /// The indentation `lines` share: the fewest leading spaces of those
    /// with text (what a card showing them alone drops).
    pub fn indent(&self, lines: &[usize]) -> usize {
        lines
            .iter()
            .map(|&n| self.line_text(n))
            .filter(|text| !text.trim().is_empty())
            .map(|text| text.len() - text.trim_start_matches(' ').len())
            .min()
            .unwrap_or(0)
    }

    /// The view of `document`.
    pub fn new(document: &Arc<Document>) -> Self {
        let decompiled = &document.decompiled;
        let (text, spans) = shown_comments(document);
        let mut this = Self::over(
            document.function,
            document.entry,
            document.view,
            text,
            spans,
            document.defaults.clone(),
            Arc::clone(&document.provenance),
            &decompiled.l2,
            &decompiled.l1,
        );
        this.decompiled = Some(Arc::clone(decompiled));
        this.processor_dependent = document.counts.unknowns.architecture;
        let mut undefined: Vec<UndefinedValue> = (0..this.spans.len())
            .filter_map(|s| this.undefined(s))
            .collect();
        undefined.sort_unstable();
        undefined.dedup();
        this.undefined_values = undefined;
        this.members = document.members.clone();
        this.comments = document
            .comments
            .iter()
            .map(|(&span, &(address, _))| (span, address))
            .collect();
        this
    }

    /// The document of `text` and its `spans`, for function `function` at
    /// `entry`, with provenance from its `l2` and `l1` (its frame code's
    /// instructions on no line: where its definition starts is not
    /// known).
    #[expect(clippy::too_many_arguments, reason = "the parts of a document")]
    pub fn from_parts(
        function: FunctionId,
        entry: u64,
        view: View,
        text: String,
        spans: Vec<CSpan>,
        defaults: BTreeMap<VarId, String>,
        l2: &Ast,
        l1: &L1,
    ) -> Self {
        let made = spans.iter().map(|s| (s.range.clone(), s.node));
        let provenance = Arc::new(Provenance::new(&text, made, l2, l1, None));
        Self::over(
            function, entry, view, text, spans, defaults, provenance, l2, l1,
        )
    }

    /// The document of `text` and its `spans` (as their `provenance` has
    /// them, its lines `text`'s), for function `function` at `entry`; its
    /// conditions and checks from its `l2` and `l1`.
    #[expect(clippy::too_many_arguments, reason = "the parts of a document")]
    fn over(
        function: FunctionId,
        entry: u64,
        view: View,
        text: String,
        spans: Vec<CSpan>,
        defaults: BTreeMap<VarId, String>,
        provenance: Arc<Provenance>,
        l2: &Ast,
        l1: &L1,
    ) -> Self {
        let mut conditions = HashMap::new();
        for node in spans.iter().filter_map(|s| s.node) {
            if let Node::Stmt(s) = node
                && let Some(condition) = l2.stmt(s).and_then(condition)
            {
                conditions.insert(s, condition);
            }
        }
        let mut lines = Vec::new();
        let mut tints = HashMap::new();
        let (checks, traps) = checks(l2, l1);
        let mut next_tint = 0u8;
        let mut start = 0;
        for (n, piece) in text.split('\n').enumerate() {
            let end = start + piece.len();
            let (on_spans, on_line) = provenance
                .lines()
                .get(n)
                .map_or((0..0, Vec::new()), |line| {
                    (line.spans.clone(), line.addresses.clone())
                });
            let tint = (!on_line.is_empty()).then(|| {
                let tint = next_tint;
                next_tint = (next_tint + 1) % TINTS;
                for &address in &on_line {
                    tints.entry(address).or_insert(tint);
                }
                tint
            });
            lines.push(CLine {
                range: start..end,
                spans: on_spans,
                addresses: on_line,
                tint,
            });
            start = end + 1;
        }
        Self {
            parameters: l2
                .parameters
                .iter()
                .map(|&var| {
                    let name = spans
                        .iter()
                        .find(|s| s.node == Some(Node::Var(var)))
                        .and_then(|s| text.get(s.range.clone()))
                        .map_or_else(|| format!("a{}", var.0), str::to_owned);
                    (var, name)
                })
                .collect(),
            decompiled: None,
            processor_dependent: 0,
            undefined_values: Vec::new(),
            members: BTreeMap::new(),
            comments: BTreeMap::new(),
            function,
            entry,
            view,
            text,
            spans,
            lines,
            defaults,
            provenance,
            tints,
            checks,
            traps,
            conditions,
        }
    }

    /// The text of line `n`.
    pub fn line_text(&self, n: usize) -> &str {
        self.lines
            .get(n)
            .and_then(|l| self.text.get(l.range.clone()))
            .unwrap_or("")
    }

    /// The user's comments line `n` shows, as spans, in order.
    fn line_comments(&self, n: usize) -> impl Iterator<Item = usize> + '_ {
        self.lines
            .get(n)
            .map_or(0..0, |line| line.spans.clone())
            .filter(|s| self.comments.contains_key(s))
    }

    /// Whether line `n` shows only the user's comments: a further line of
    /// a comment of a line above.
    fn comment_only(&self, n: usize) -> bool {
        self.lines.get(n).is_some_and(|line| {
            !line.spans.is_empty() && line.spans.clone().all(|s| self.comments.contains_key(&s))
        })
    }

    /// The line whose comments line `n` shows: itself, or, on a further
    /// line of a comment, the line the comment is at the end of.
    pub fn comment_owner(&self, n: usize) -> usize {
        let mut owner = n;
        while owner > 0 && self.comment_only(owner) {
            owner -= 1;
        }
        owner
    }

    /// The lines showing the comments of line `n`'s owner
    /// ([`Self::comment_owner`]): it and the further lines under it.
    pub fn comment_lines(&self, n: usize) -> Range<usize> {
        let owner = self.comment_owner(n);
        let mut end = owner + 1;
        while self.comment_only(end) {
            end += 1;
        }
        owner..end
    }

    /// The bytes of line `n` before its comments (its code, without the
    /// space before them).
    pub fn code_end(&self, n: usize) -> usize {
        let text = self.line_text(n);
        let start = self.lines.get(n).map_or(0, |line| line.range.start);
        self.line_comments(n)
            .next()
            .and_then(|s| self.spans.get(s))
            .map_or(text.len(), |span| {
                text.get(..span.range.start - start)
                    .map_or(0, |code| code.trim_end().len())
            })
    }

    /// Where a comment typed on line `n` goes: the address of the first
    /// comment its owner line ([`Self::comment_owner`]) shows (a line
    /// showing several edits the first one's); else the line's first
    /// instruction: the lowest it is made from among those it is the
    /// first line of (a comment shows on the first line made from its
    /// instruction, so it shows here), else the lowest. `None` for a line
    /// made from no instruction.
    pub fn comment_address(&self, n: usize) -> Option<u64> {
        let owner = self.comment_owner(n);
        if let Some(&address) = self
            .line_comments(owner)
            .next()
            .and_then(|s| self.comments.get(&s))
        {
            return Some(address);
        }
        let addresses = &self.lines.get(owner)?.addresses;
        addresses
            .iter()
            .copied()
            .find(|&address| self.lines_of(address).next() == Some(owner))
            .or_else(|| addresses.first().copied())
    }

    /// The first line of the function's definition (its signature), past
    /// the file's comments, includes and declarations: the last line
    /// starting at column 0 before the first statement, `{` aside.
    pub fn body_start(&self) -> usize {
        let first = self
            .lines
            .iter()
            .position(|l| {
                self.spans
                    .get(l.spans.clone())
                    .is_some_and(|s| s.iter().any(|s| matches!(s.node, Some(Node::Stmt(_)))))
            })
            .unwrap_or(0);
        (0..first)
            .rev()
            .find(|&n| {
                let text = self.line_text(n);
                text.starts_with(|c: char| !c.is_whitespace()) && !text.starts_with('{')
            })
            .unwrap_or(first)
    }

    /// The text of span `s`.
    pub fn span_text(&self, s: usize) -> &str {
        self.spans
            .get(s)
            .and_then(|s| self.text.get(s.range.clone()))
            .unwrap_or("")
    }

    /// The line span `s` is on.
    pub fn line_of_span(&self, s: usize) -> Option<usize> {
        let i = self.lines.partition_point(|l| l.spans.end <= s);
        (i < self.lines.len()).then_some(i)
    }

    /// The number token `s` writes, with its literal's span: of a
    /// literal, or of the `-` right before one. The printer writes a
    /// negative number as the operator `-` and a literal (`-1`): a `-`
    /// ending where a literal starts is its sign, so either token is the
    /// whole number (the listing's `0FFFFFFFFh`, not `1`).
    pub fn number(&self, s: usize) -> Option<(usize, Written)> {
        let literal = if self.is_sign(s) { s + 1 } else { s };
        if self.spans.get(literal)?.kind != TokenKind::Number {
            return None;
        }
        let written = parse(self.span_text(literal))?;
        let signed = literal.checked_sub(1).is_some_and(|m| self.is_sign(m));
        Some((literal, if signed { written.negated() } else { written }))
    }

    /// Whether span `s` is a `-` ending where a literal starts: its sign
    /// ([`Self::number`]).
    fn is_sign(&self, s: usize) -> bool {
        let (Some(minus), Some(next)) = (self.spans.get(s), self.spans.get(s + 1)) else {
            return false;
        };
        minus.kind == TokenKind::Operator
            && next.kind == TokenKind::Number
            && minus.range.end == next.range.start
            && self.span_text(s) == "-"
    }

    /// The span at byte `column` of line `n`, if a token is there.
    pub fn span_at(&self, n: usize, column: usize) -> Option<usize> {
        let line = self.lines.get(n)?;
        let at = line.range.start + column;
        line.spans
            .clone()
            .find(|&s| self.spans.get(s).is_some_and(|s| s.range.contains(&at)))
    }

    /// The label `s` names (a `goto`'s, `goto label_3;`): the span of its
    /// definition (`label_3:`), unless `s` is that.
    pub fn label_definition(&self, s: usize) -> Option<usize> {
        if self.spans.get(s)?.kind != TokenKind::Label {
            return None;
        }
        let name = self.span_text(s);
        let defined = (0..self.spans.len()).find(|&t| {
            self.spans.get(t).is_some_and(|span| {
                span.kind == TokenKind::Label
                    && self.span_text(t) == name
                    && self
                        .text
                        .get(span.range.end..)
                        .is_some_and(|rest| rest.starts_with(':'))
            })
        })?;
        (defined != s).then_some(defined)
    }

    /// The address of the function the name `s` stands for, as the C says
    /// it, whatever the name (a C name differs from its symbol's when
    /// that is no C identifier or is taken: `main_2`): the definition's
    /// entry (its own name, a recursive call), else the address the
    /// name's declaration notes (`int f(int); /* 0x1450 */`).
    pub fn function_address(&self, s: usize) -> Option<u64> {
        if self.spans.get(s)?.kind != TokenKind::Function {
            return None;
        }
        let name = self.span_text(s);
        let named_on = |n: usize| {
            self.lines.get(n).and_then(|line| {
                line.spans.clone().find(|&t| {
                    self.spans
                        .get(t)
                        .is_some_and(|span| span.kind == TokenKind::Function)
                })
            })
        };
        if named_on(self.body_start()).is_some_and(|t| self.span_text(t) == name) {
            return Some(self.entry);
        }
        (0..self.lines.len()).find_map(|n| {
            let line = self.lines.get(n)?;
            if named_on(n).is_none_or(|t| self.span_text(t) != name) {
                return None;
            }
            let note = line.spans.clone().rev().find(|&t| {
                self.spans
                    .get(t)
                    .is_some_and(|span| span.kind == TokenKind::Comment)
            })?;
            let hex = self.span_text(note).strip_prefix("/* 0x")?;
            let digits = hex.split(|c: char| !c.is_ascii_hexdigit()).next()?;
            u64::from_str_radix(digits, 16).ok()
        })
    }

    /// The instructions node `node` came from.
    pub fn node_addresses(&self, node: Node) -> &[u64] {
        self.provenance.node_addresses(node)
    }

    /// The instructions span `s` stands for: its node's (an expression's or
    /// a statement's), else its line's.
    pub fn span_addresses(&self, s: usize) -> &[u64] {
        self.provenance.span_addresses(s)
    }

    /// The tokens standing for an expression or statement made from the
    /// instruction at `address`: the narrowest such nodes' tokens (an
    /// enclosing statement's are left out when an expression of it came
    /// from the instruction).
    pub fn spans_of(&self, address: u64) -> Vec<usize> {
        self.provenance.spans_of(address)
    }

    /// The tint of the instruction at `address`, if a line has it.
    pub fn tint_of(&self, address: u64) -> Option<u8> {
        self.tints.get(&address).copied()
    }

    /// The lines that stand for the instruction at `address`.
    pub fn lines_of(&self, address: u64) -> impl Iterator<Item = usize> + '_ {
        self.lines
            .iter()
            .enumerate()
            .filter(move |(_, l)| l.addresses.binary_search(&address).is_ok())
            .map(|(i, _)| i)
    }

    /// The line that stands for `address`: one holding it, else the first
    /// line with an instruction after it (the nearest statement below).
    pub fn line_for(&self, address: u64) -> Option<usize> {
        self.lines_of(address).next().or_else(|| {
            self.lines
                .iter()
                .enumerate()
                .filter_map(|(i, l)| l.addresses.first().map(|&a| (i, a)))
                .filter(|&(_, a)| a >= address)
                .min_by_key(|&(_, a)| a)
                .map(|(i, _)| i)
        })
    }

    /// The lines marks at addresses (bookmarks, in `marks`) show on, each
    /// line with its marks in address order: the lines made from a marked
    /// instruction; the entry's mark on the signature line
    /// ([`Self::body_start`]); a mark at an instruction of this function
    /// (`inside` says which are) no line is made from (one the decompiler
    /// folded away) on the nearest statement after it, where a cursor
    /// there shows ([`Self::line_for`]).
    pub fn marked_lines<'a, T>(
        &self,
        marks: &'a BTreeMap<u64, T>,
        inside: impl Fn(u64) -> bool,
    ) -> BTreeMap<usize, Vec<(u64, &'a T)>> {
        let mut out: BTreeMap<usize, Vec<(u64, &'a T)>> = BTreeMap::new();
        if marks.is_empty() {
            return out;
        }
        let mut shown: BTreeSet<u64> = BTreeSet::new();
        if let Some(mark) = marks.get(&self.entry) {
            out.entry(self.body_start())
                .or_default()
                .push((self.entry, mark));
            shown.insert(self.entry);
        }
        // No statement follows a mark past the last instruction a line is
        // made from.
        let mut last = None;
        for (n, line) in self.lines.iter().enumerate() {
            for &address in &line.addresses {
                last = last.max(Some(address));
                if let Some(mark) = marks.get(&address) {
                    out.entry(n).or_default().push((address, mark));
                    shown.insert(address);
                }
            }
        }
        for (&address, mark) in last.map_or_else(|| marks.range(..0), |last| marks.range(..last)) {
            if shown.contains(&address) || !inside(address) {
                continue;
            }
            if let Some(n) = self.line_for(address) {
                out.entry(n).or_default().push((address, mark));
            }
        }
        for line in out.values_mut() {
            line.sort_by_key(|&(address, _)| address);
            line.dedup_by_key(|&mut (address, _)| address);
        }
        out
    }

    /// The spans standing for `node`, in order.
    pub fn occurrences(&self, node: Node) -> impl Iterator<Item = usize> + '_ {
        self.spans
            .iter()
            .enumerate()
            .filter(move |(_, s)| s.node == Some(node))
            .map(|(i, _)| i)
    }

    /// The variable span `s` names, if it is a variable's name.
    pub fn variable(&self, s: usize) -> Option<VarId> {
        let span = self.spans.get(s)?;
        match span.node? {
            Node::Var(v) if span.kind.is_variable() => Some(v),
            Node::Var(_) | Node::Type(_) | Node::Expr(_) | Node::Stmt(_) => None,
        }
    }

    /// The value the architecture leaves undefined that span `s` stands
    /// for (`_OF_undefined`, or `binbun_undefined_bool()`), if it stands
    /// for one.
    pub fn undefined(&self, s: usize) -> Option<UndefinedValue> {
        let Node::Expr(id) = self.spans.get(s)?.node? else {
            return None;
        };
        let Expr::Undefined(
            _,
            Unknown::Architecture {
                address,
                register,
                site,
            },
            _,
        ) = *self.decompiled.as_ref()?.l2.expr(id)?
        else {
            return None;
        };
        Some(UndefinedValue {
            address,
            register,
            site,
        })
    }

    /// The `ordinal`th span standing for `node` (the last if there are
    /// fewer): where the cursor goes back to after a re-print.
    pub fn nth_occurrence(&self, node: Node, ordinal: usize) -> Option<usize> {
        let all: Vec<usize> = self.occurrences(node).collect();
        all.get(ordinal).or(all.last()).copied()
    }

    /// The struct or union span `s` names a member of, if it is a
    /// member's name.
    pub fn member(&self, s: usize) -> Option<TypeId> {
        self.members.get(&s).copied()
    }

    /// The key (`struct pair`) the document prints the struct or union
    /// `of` as.
    pub fn struct_key(&self, of: TypeId) -> Option<String> {
        let keyword = self.spans.iter().position(|span| {
            span.node == Some(Node::Type(of))
                && span.kind == TokenKind::Keyword
                && matches!(self.text.get(span.range.clone()), Some("struct" | "union"))
        })?;
        let tag = keyword + 1;
        (self.spans.get(tag)?.kind == TokenKind::Type)
            .then(|| format!("{} {}", self.span_text(keyword), self.span_text(tag)))
    }

    /// The struct or union the document prints with key `key`.
    fn struct_of(&self, key: &str) -> Option<TypeId> {
        let (keyword, tag) = key.split_once(' ')?;
        self.spans
            .iter()
            .enumerate()
            .find_map(|(s, span)| match span.node {
                Some(Node::Type(of))
                    if span.kind == TokenKind::Keyword
                        && self.span_text(s) == keyword
                        && self.span_text(s + 1) == tag =>
                {
                    Some(of)
                }
                Some(_) | None => None,
            })
    }

    /// The spans naming member `name` of the struct or union `of`, in
    /// order: its line of the definition and its uses.
    pub fn member_occurrences<'a>(
        &'a self,
        of: TypeId,
        name: &'a str,
    ) -> impl Iterator<Item = usize> + 'a {
        self.members
            .iter()
            .filter(move |&(&s, &o)| o == of && self.span_text(s) == name)
            .map(|(&s, _)| s)
    }

    /// The span of member `name`'s declaration in the definition of the
    /// struct or union `of`, if the document prints it.
    pub fn member_declaration(&self, of: TypeId, name: &str) -> Option<usize> {
        self.member_occurrences(of, name).find(|&s| {
            self.spans
                .get(s)
                .is_some_and(|span| span.node == Some(Node::Type(of)))
        })
    }

    /// Where `anchor` is now: its `ordinal`th occurrence (the last if
    /// there are fewer).
    pub fn nth_anchor(&self, anchor: &Anchor, ordinal: usize) -> Option<usize> {
        match anchor {
            &Anchor::Node(node) => self.nth_occurrence(node, ordinal),
            Anchor::Member { key, name } => {
                let all: Vec<usize> = self
                    .member_occurrences(self.struct_of(key)?, name)
                    .collect();
                all.get(ordinal).or(all.last()).copied()
            }
            Anchor::Struct(key) => {
                let of = self.struct_of(key)?;
                self.definitions()
                    .find(|(o, _)| *o == of)
                    .and_then(|(_, lines)| self.lines.get(lines.start))
                    .map(|line| line.spans.start)
            }
        }
    }

    /// The struct and union definitions the document prints, each with
    /// its lines: from the one opening it (`struct pair {`, its keyword
    /// at the line's start) to the one closing it (`};`).
    pub fn definitions(&self) -> impl Iterator<Item = (TypeId, Range<usize>)> + '_ {
        self.lines.iter().enumerate().filter_map(|(n, line)| {
            let first = self.spans.get(line.spans.start)?;
            let Some(Node::Type(of)) = first.node else {
                return None;
            };
            let text = self.line_text(n);
            if first.range.start != line.range.start
                || first.kind != TokenKind::Keyword
                || text.trim_end().ends_with(';')
            {
                return None;
            }
            let end = (n + 1..self.lines.len()).find(|&m| self.line_text(m).starts_with('}'))?;
            Some((of, n..end + 1))
        })
    }

    /// The definition line `n` is in, if any: its struct's key and lines.
    pub fn definition_at(&self, n: usize) -> Option<(String, Range<usize>)> {
        let (of, lines) = self.definitions().find(|(_, lines)| lines.contains(&n))?;
        Some((self.struct_key(of)?, lines))
    }

    /// The text of `lines`, joined.
    pub fn lines_text(&self, lines: Range<usize>) -> String {
        lines
            .map(|n| self.line_text(n))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Line `n` as shown while `field` is edited: every occurrence of its
    /// variable or member shows the field's text, or, while the
    /// field is empty, the default name as a placeholder. The pieces are
    /// made from the text shown, so they always cover it exactly.
    pub fn shown_line(&self, n: usize, field: Option<&Field>) -> ShownLine {
        let mut out = ShownLine {
            text: String::new(),
            pieces: Vec::new(),
            field: None,
        };
        let Some(line) = self.lines.get(n) else {
            return out;
        };
        let field_span = field.and_then(|f| f.span(self));
        let push = |out: &mut ShownLine, text: &str, span: Option<usize>, placeholder: bool| {
            if text.is_empty() {
                return;
            }
            let start = out.text.len();
            out.text.push_str(text);
            if span.is_some() && span == field_span {
                out.field = Some(out.pieces.len());
            }
            out.pieces.push(Piece {
                range: start..out.text.len(),
                span,
                placeholder,
            });
        };
        let mut at = line.range.start;
        for s in line.spans.clone() {
            let Some(span) = self.spans.get(s) else {
                continue;
            };
            if span.range.start > at {
                let between = self.text.get(at..span.range.start).unwrap_or("");
                push(&mut out, between, None, false);
            }
            let edited = field.filter(|f| f.names(self, s));
            match edited {
                Some(f) if f.text.is_empty() => {
                    push(&mut out, f.default(self), Some(s), true);
                }
                Some(f) => push(&mut out, &f.text, Some(s), false),
                None => push(&mut out, self.span_text(s), Some(s), false),
            }
            at = at.max(span.range.end);
        }
        if line.range.end > at {
            let rest = self.text.get(at..line.range.end).unwrap_or("");
            push(&mut out, rest, None, false);
        }
        debug_assert!(out.covers(), "pieces must cover the shown text: {out:?}");
        out
    }
}

impl ShownLine {
    /// Whether the pieces cover the text exactly, in order, none empty.
    pub fn covers(&self) -> bool {
        let mut at = 0;
        for p in &self.pieces {
            if p.range.start != at || p.range.end <= p.range.start {
                return false;
            }
            at = p.range.end;
        }
        at == self.text.len()
    }
}

/// `document`'s text and spans with the user's comments shown as `// text`
/// (printed `/* text */`): the spans keep their indices.
fn shown_comments(document: &Document) -> (String, Vec<CSpan>) {
    let mut text = String::with_capacity(document.text.len());
    let mut spans = Vec::with_capacity(document.spans.len());
    let mut at = 0;
    for (s, span) in document.spans.iter().enumerate() {
        text.push_str(document.text.get(at..span.range.start).unwrap_or(""));
        let start = text.len();
        match document.comments.get(&s) {
            Some((_, line)) if line.is_empty() => text.push_str("//"),
            Some((_, line)) => {
                text.push_str("// ");
                text.push_str(line);
            }
            None => text.push_str(document.text.get(span.range.clone()).unwrap_or("")),
        }
        at = span.range.end;
        spans.push(CSpan {
            range: start..text.len(),
            kind: span.kind,
            node: span.node,
            automatic: span.automatic,
            cast: span.cast,
        });
    }
    text.push_str(document.text.get(at..).unwrap_or(""));
    (text, spans)
}

/// What `stmt` decides on, if it decides: an `if`'s or a loop's
/// condition, the value a `switch` switches on.
fn condition(stmt: &Stmt) -> Option<ExprId> {
    match *stmt {
        Stmt::If { condition, .. }
        | Stmt::While { condition, .. }
        | Stmt::DoWhile { condition, .. }
        | Stmt::For { condition, .. } => Some(condition),
        Stmt::Switch { scrutinee, .. } => Some(scrutinee),
        Stmt::Assign { .. }
        | Stmt::Call { .. }
        | Stmt::Intrinsic { .. }
        | Stmt::Expr(_)
        | Stmt::Break(_)
        | Stmt::Continue(_)
        | Stmt::Label(_)
        | Stmt::Goto(_)
        | Stmt::Return(_)
        | Stmt::Trap(_)
        | Stmt::Unreachable
        | Stmt::Escape { .. }
        | Stmt::Try { .. }
        | Stmt::VaStart { .. } => None,
    }
}

/// The checks L0 makes at each instruction, as `l2` decides them: an L1
/// branch of `l1` whose condition the instruction computes and whose one
/// way only traps (a block of no instructions ending in a trap, as an
/// access at a non-canonical address does) is one; the statements naming
/// its block ([`Origin::Block`]) that decide something are its, each with
/// the jumps its arms are (an `if (…) break;`'s `break`). A check's
/// statements name the block's first instruction, not the access it
/// guards, so its instruction is found this way.
///
/// With each instruction's trap (`Protection`, #GP; `Stack`, #SS).
fn checks(l2: &Ast, l1: &L1) -> (HashMap<u64, Vec<Node>>, HashMap<u64, Trap>) {
    let trap = |block: BlockId| match l1.block(block) {
        Some(b) if b.insts.is_empty() => match b.terminator {
            Terminator::Trap(kind) => Some(kind),
            Terminator::Jump(_)
            | Terminator::Branch { .. }
            | Terminator::IndirectJump { .. }
            | Terminator::Return { .. }
            | Terminator::Leave { .. }
            | Terminator::Stop
            | Terminator::Invoke { .. }
            | Terminator::Open => None,
        },
        Some(_) | None => None,
    };
    let mut at: HashMap<BlockId, u64> = HashMap::new();
    let mut kinds = HashMap::new();
    for (index, block) in l1.blocks.iter().enumerate() {
        let Terminator::Branch {
            condition,
            then,
            otherwise,
        } = &block.terminator
        else {
            continue;
        };
        let Some(kind) = trap(then.block).or_else(|| trap(otherwise.block)) else {
            continue;
        };
        let address = match l1.value(*condition).map(|v| &v.definition) {
            Some(&Definition::Result { inst, .. }) => l1.inst(inst).map(|i| i.address),
            Some(Definition::Parameter { .. }) | None => None,
        };
        if let (Some(address), Ok(index)) = (address, u32::try_from(index)) {
            at.insert(BlockId(index), address);
            kinds.insert(address, kind);
        }
    }
    let mut out: HashMap<u64, Vec<Node>> = HashMap::new();
    if at.is_empty() {
        return (out, kinds);
    }
    let jump = |s: &StmtId| {
        l2.stmt(*s).is_some_and(|s| {
            matches!(
                s,
                Stmt::Break(_) | Stmt::Continue(_) | Stmt::Goto(_) | Stmt::Trap(_)
            )
        })
    };
    for (index, stmt) in l2.stmts.iter().enumerate() {
        let Ok(index) = u32::try_from(index) else {
            break;
        };
        if condition(stmt).is_none() {
            continue;
        }
        let id = StmtId(index);
        for origin in l2.provenance.stmt(id) {
            let Origin::Block(block) = origin else {
                continue;
            };
            let Some(&address) = at.get(block) else {
                continue;
            };
            let nodes = out.entry(address).or_default();
            nodes.push(Node::Stmt(id));
            if let Stmt::If {
                then, otherwise, ..
            } = stmt
            {
                let arms = then.iter().chain(otherwise).filter(|s| jump(s));
                nodes.extend(arms.map(|&s| Node::Stmt(s)));
            }
        }
    }
    (out, kinds)
}

/// What the cursor goes back to after a re-print: a node, a member (by
/// its struct's key and its name, the struct's types being the new
/// print's), a struct's definition (by its key).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Anchor {
    /// A node's occurrence.
    Node(Node),
    /// A member's occurrence.
    Member {
        /// Its struct's key (`struct pair`).
        key: String,
        /// Its name.
        name: String,
    },
    /// The first line of a struct's definition, by its key.
    Struct(String),
}

/// What a name field renames.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Named {
    /// A variable.
    Var(VarId),
    /// A member of a struct or union.
    Member {
        /// The struct or union (of the document's types).
        of: TypeId,
        /// Its key (`struct pair`).
        key: String,
    },
}

/// A variable's or a member's name being edited in place.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Field {
    /// What it renames.
    pub named: Named,
    /// Its name before the edit.
    pub original: String,
    /// The text so far.
    pub text: String,
    /// Which of its occurrences the cursor is on.
    pub ordinal: usize,
}

impl Field {
    /// A field over the variable or member span `s` of `doc` names, if it
    /// names one.
    pub fn open(doc: &CDocument, s: usize) -> Option<Self> {
        let named = match (doc.variable(s), doc.member(s)) {
            (Some(var), _) => Named::Var(var),
            (None, Some(of)) => Named::Member {
                of,
                key: doc.struct_key(of)?,
            },
            (None, None) => return None,
        };
        let original = doc.span_text(s).to_owned();
        let mut field = Self {
            named,
            text: original.clone(),
            original,
            ordinal: 0,
        };
        field.ordinal = field.occurrences(doc).iter().position(|&o| o == s)?;
        Some(field)
    }

    /// The variable it renames, if it renames one.
    pub const fn var(&self) -> Option<VarId> {
        match self.named {
            Named::Var(var) => Some(var),
            Named::Member { .. } => None,
        }
    }

    /// Whether span `s` of `doc` is one of its occurrences.
    pub fn names(&self, doc: &CDocument, s: usize) -> bool {
        match self.named {
            Named::Var(var) => doc
                .spans
                .get(s)
                .is_some_and(|span| span.node == Some(Node::Var(var)) && span.kind.is_variable()),
            Named::Member { of, .. } => {
                doc.member(s) == Some(of) && doc.span_text(s) == self.original
            }
        }
    }

    /// Its occurrences in `doc`, in order.
    pub fn occurrences(&self, doc: &CDocument) -> Vec<usize> {
        (0..doc.spans.len())
            .filter(|&s| self.names(doc, s))
            .collect()
    }

    /// Its own occurrence (the cursor's) in `doc`.
    pub fn span(&self, doc: &CDocument) -> Option<usize> {
        let all = self.occurrences(doc);
        all.get(self.ordinal).or(all.last()).copied()
    }

    /// What an empty field shows: a variable's default name; a member's
    /// name (a member has no default to reset to).
    pub fn default<'d>(&'d self, doc: &'d CDocument) -> &'d str {
        match self.named {
            Named::Var(var) => doc
                .defaults
                .get(&var)
                .map_or(self.original.as_str(), String::as_str),
            Named::Member { .. } => &self.original,
        }
    }

    /// Where the cursor goes back to once the name is `name` and the C is
    /// printed again.
    pub fn anchor(&self, name: Option<&str>) -> Anchor {
        match &self.named {
            &Named::Var(var) => Anchor::Node(Node::Var(var)),
            Named::Member { key, .. } => Anchor::Member {
                key: key.clone(),
                name: name.unwrap_or(&self.original).to_owned(),
            },
        }
    }

    /// The name to commit: `None` to reset to the default (an empty
    /// field), else the text if it is a C identifier.
    ///
    /// # Errors
    ///
    /// The text is not a C identifier.
    pub fn commit(&self) -> Result<Option<String>, String> {
        identifier(&self.text)
    }
}

/// `text` trimmed as a name to commit: `None` if empty (back to the
/// default), else the text if it is a C identifier (ASCII only: the
/// printer spells any other character of a name as `_`).
///
/// # Errors
///
/// The text is not a C identifier.
pub fn identifier(text: &str) -> Result<Option<String>, String> {
    let text = text.trim();
    if text.is_empty() {
        return Ok(None);
    }
    let mut chars = text.chars();
    let first_ok = chars
        .next()
        .is_some_and(|c| c == '_' || c.is_ascii_alphabetic());
    if first_ok && chars.all(|c| c == '_' || c.is_ascii_alphanumeric()) {
        Ok(Some(text.to_owned()))
    } else {
        Err(format!(
            "{text:?} is not a C identifier (ASCII letters, digits, _)"
        ))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::collections::BTreeMap;

    use super::{Anchor, CDocument, CSpan, Field, Named, REVEAL_SPAN, identifier};
    use binbun::cfg::FunctionId;
    use binbun_ast::ir::{Function as Ast, Node, VarId};
    use binbun_ast::types::Types;
    use binbun_print::document::TokenKind;
    use binbun_semantics::core::Id as _;
    use binbun_session::View;
    use binbun_ssa::ir::Function as L1;

    use crate::session::without_signatures;

    /// Every document of bash (else of the fixture): each line's
    /// instructions are its function's, each line is among the lines of
    /// each of its instructions, and the view's lines, tokens' and
    /// instructions' links are the session's document's (one
    /// provenance, both front ends).
    #[test]
    fn the_views_links_are_the_documents_provenance_on_every_bash_function() {
        use std::path::{Path, PathBuf};
        use std::sync::Arc;
        use std::time::Duration;

        use binbun_session::{DebugSource, Options, Session, Stage, Waited};

        let bash = Path::new("/usr/bin/bash");
        let path = if bash.exists() {
            bash.to_owned()
        } else {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../tests/fixtures/program-x86_64.elf")
        };
        let session = Arc::new(
            Session::open(
                path,
                Options {
                    ephemeral: true,
                    warm: false,
                    debug: DebugSource::Without,
                    signatures: without_signatures(),
                    ..Options::default()
                },
            )
            .unwrap(),
        );
        let waited = session.wait(Stage::Callers, Some(Duration::from_secs(600)));
        assert!(matches!(waited, Waited::Reached(_)), "{waited:?}");
        let database = session.database().unwrap();
        let program = database.program();
        let functions: Vec<_> = database.functions().collect();
        let threads = std::thread::available_parallelism().map_or(4, |n| n.get().min(8));
        let checked: usize = std::thread::scope(|scope| {
            let workers: Vec<_> = (0..threads)
                .map(|t| {
                    let (session, functions) = (&session, &functions);
                    scope.spawn(move || {
                        let mut lines = 0;
                        for &(id, function) in functions.iter().skip(t).step_by(threads) {
                            let Ok(document) = session.document_here(id, View::Exact) else {
                                continue;
                            };
                            let within = |a: u64| {
                                function.blocks.iter().any(|&b| {
                                    let block = &program.blocks[b];
                                    (block.start..block.end).contains(&a)
                                })
                            };
                            let view = CDocument::new(&document);
                            assert_eq!(view.lines.len(), document.lines().len());
                            for (n, line) in document.lines().iter().enumerate() {
                                for &a in &line.addresses {
                                    assert!(within(a), "{a:#x} in {:#x}", function.entry);
                                    assert!(document.lines_of(a).any(|m| m == n));
                                    assert!(view.lines_of(a).any(|m| m == n));
                                    assert_eq!(view.spans_of(a), document.provenance.spans_of(a));
                                }
                                assert_eq!(view.lines[n].addresses, line.addresses);
                                assert_eq!(view.lines[n].spans, line.spans);
                                for s in line.spans.clone() {
                                    assert_eq!(view.span_addresses(s), document.span_addresses(s));
                                }
                                lines += 1;
                            }
                        }
                        lines
                    })
                })
                .collect();
            workers.into_iter().map(|w| w.join().unwrap()).sum()
        });
        assert!(checked > 100, "{checked} lines");
    }

    /// `int64_t v1;` / `v1 = v1 + a2;`: v1 (var 0) three times, twice on
    /// one line.
    fn document() -> CDocument {
        let text = "int64_t v1;\nv1 = v1 + a2;".to_owned();
        let v1 = Some(Node::Var(VarId(0)));
        let a2 = Some(Node::Var(VarId(1)));
        let spans = [
            (0..7, TokenKind::BuiltinType, None),
            (8..10, TokenKind::Local, v1),
            (10..11, TokenKind::Punctuation, None),
            (12..14, TokenKind::Local, v1),
            (15..16, TokenKind::Operator, None),
            (17..19, TokenKind::Local, v1),
            (20..21, TokenKind::Operator, None),
            (22..24, TokenKind::Parameter, a2),
            (24..25, TokenKind::Punctuation, None),
        ]
        .into_iter()
        .map(|(range, kind, node)| CSpan {
            range,
            kind,
            node,
            automatic: true,
            cast: false,
        })
        .collect();
        let l2 = Ast::new(0, Types::new(64));
        CDocument::from_parts(
            FunctionId::from_raw(0),
            0,
            View::Reading,
            text,
            spans,
            BTreeMap::from([(VarId(0), "v1".to_owned())]),
            &l2,
            &L1::default(),
        )
    }

    /// Every line covers its text and shows `shown` for each v1.
    fn check(doc: &CDocument, field: Option<&Field>, shown: &str) {
        for n in 0..doc.lines.len() {
            let line = doc.shown_line(n, field);
            assert!(line.covers(), "{line:?}");
            assert_eq!(line.text, doc.line_text(n).replace("v1", shown), "{line:?}");
            let placeholder = line.pieces.iter().filter(|p| p.placeholder).count();
            let expected = if field.is_some_and(|f| f.text.is_empty()) {
                [1, 2][n]
            } else {
                0
            };
            assert_eq!(placeholder, expected, "{line:?}");
        }
        let own = doc.shown_line(1, field).field;
        match field {
            Some(_) => {
                let line = doc.shown_line(1, field);
                assert_eq!(own.and_then(|p| line.pieces[p].span), Some(3));
            }
            None => assert_eq!(own, None),
        }
    }

    #[test]
    fn shown_lines_cover_their_text_through_every_edit() {
        let doc = document();
        let mut field = Field::open(&doc, 3).expect("v1 is a variable");
        assert_eq!(
            (field.var(), field.ordinal, field.original.as_str()),
            (Some(VarId(0)), 1, "v1")
        );
        check(&doc, Some(&field), "v1");
        while field.text.pop().is_some() {
            let shown = if field.text.is_empty() {
                "v1".to_owned()
            } else {
                field.text.clone()
            };
            check(&doc, Some(&field), &shown);
        }
        assert_eq!(field.commit(), Ok(None));
        for c in "count".chars() {
            field.text.push(c);
            check(&doc, Some(&field), &field.text.clone());
        }
        assert_eq!(field.commit(), Ok(Some("count".to_owned())));
        for text in ["x".to_owned(), "名前".to_owned(), "n".repeat(300)] {
            field.text.clone_from(&text);
            check(&doc, Some(&field), &text);
        }
        check(&doc, None, "v1");
        assert!(doc.shown_line(1, Some(&field)).text.ends_with("a2;"));
    }

    /// `struct pair` (type 7) defined (its forward declaration first),
    /// then used: `p->first` twice and `q.first` of another struct
    /// (type 8) whose member has the same name; the spans as a session's
    /// document has them (member names known by their struct).
    fn structs() -> CDocument {
        use TokenKind::{
            BuiltinType as B, ControlKeyword as C, Field as F, Keyword as K, Local as L,
            Operator as O, Type as T,
        };
        use binbun_ast::types::TypeId;
        let text = "struct pair;\n\
                    struct pair {\n    char *first;\n    int64_t second;\n};\n\
                    p->first = q.first;\n\
                    return p->first;"
            .to_owned();
        let pair = Some(Node::Type(TypeId(7)));
        let mut spans = Vec::new();
        let mut at = 0;
        let mut token = |word: &str, kind, node| {
            let start = at + text[at..].find(word).unwrap();
            at = start + word.len();
            spans.push(CSpan {
                range: start..at,
                kind,
                node,
                automatic: false,
                cast: false,
            });
        };
        token("struct", K, pair);
        token("pair", T, None);
        token("struct", K, pair);
        token("pair", T, None);
        token("char", B, None);
        token("first", F, pair);
        token("int64_t", B, None);
        token("second", F, pair);
        token("p", L, Some(Node::Var(VarId(0))));
        token("->", O, None);
        token("first", F, None);
        token("q", L, Some(Node::Var(VarId(1))));
        token(".", O, None);
        token("first", F, None);
        token("return", C, None);
        token("p", L, Some(Node::Var(VarId(0))));
        token("->", O, None);
        token("first", F, None);
        let l2 = Ast::new(0, Types::new(64));
        let mut doc = CDocument::from_parts(
            FunctionId::from_raw(0),
            0,
            View::Exact,
            text,
            spans,
            BTreeMap::new(),
            &l2,
            &L1::default(),
        );
        doc.members = BTreeMap::from([
            (5, TypeId(7)),
            (7, TypeId(7)),
            (10, TypeId(7)),
            (13, TypeId(8)),
            (17, TypeId(7)),
        ]);
        doc
    }

    #[test]
    fn a_members_field_edits_its_structs_occurrences_only() {
        use binbun_ast::types::TypeId;
        let doc = structs();
        assert_eq!(doc.struct_key(TypeId(7)).as_deref(), Some("struct pair"));
        // From its use: the definition's line and both uses, not the other
        // struct's member of the same name.
        let mut field = Field::open(&doc, 17).expect("a member");
        assert_eq!(
            field.named,
            Named::Member {
                of: TypeId(7),
                key: "struct pair".to_owned()
            }
        );
        assert_eq!(field.occurrences(&doc), [5, 10, 17]);
        assert_eq!((field.ordinal, field.span(&doc)), (2, Some(17)));
        assert_eq!(field.var(), None);
        field.text = "key".to_owned();
        let shown: Vec<String> = (0..doc.lines.len())
            .map(|n| doc.shown_line(n, Some(&field)).text)
            .collect();
        assert_eq!(shown[2], "    char *key;");
        assert_eq!(shown[5], "p->key = q.first;");
        assert_eq!(shown[6], "return p->key;");
        // `return`, the space, `p`, `->`, then the field's own piece.
        assert_eq!(doc.shown_line(6, Some(&field)).field, Some(4));
        // Emptied: the name it has, dimmed (a member has no default).
        field.text.clear();
        let line = doc.shown_line(2, Some(&field));
        assert_eq!(line.text, "    char *first;");
        assert!(line.pieces.iter().any(|p| p.placeholder));
        // Found again after the print by the struct's key and new name.
        let anchor = field.anchor(Some("first"));
        assert_eq!(doc.nth_anchor(&anchor, 1), Some(10));
        assert_eq!(doc.nth_anchor(&anchor, 9), Some(17));
        assert_eq!(
            doc.nth_anchor(&Anchor::Struct("struct pair".to_owned()), 0),
            Some(2)
        );
        // A field opens on a member's declaration too, and on no keyword.
        assert_eq!(Field::open(&doc, 5).map(|f| f.ordinal), Some(0));
        assert_eq!(doc.member_declaration(TypeId(7), "second"), Some(7));
        assert_eq!(Field::open(&doc, 14), None);
    }

    #[test]
    fn a_definition_is_its_lines_from_the_keyword_to_the_closing_brace() {
        let doc = structs();
        // Not the forward declaration on line 0; nothing after `};`.
        assert_eq!(doc.definition_at(0), None);
        for n in 1..=4 {
            assert_eq!(
                doc.definition_at(n),
                Some(("struct pair".to_owned(), 1..5)),
                "line {n}"
            );
        }
        assert_eq!(doc.definition_at(5), None);
        assert_eq!(
            doc.lines_text(1..5),
            "struct pair {\n    char *first;\n    int64_t second;\n};"
        );
    }

    /// `x = -1 - 0x10;`: the printer's `-1` is the operator `-` and the
    /// literal `1`, then a binary `-` (spaced) and `0x10`.
    #[test]
    fn a_minus_right_before_a_literal_is_its_sign_on_either_token() {
        use binbun_session::number::Written;
        let text = "x = -1 - 0x10;".to_owned();
        let spans = [
            (0..1, TokenKind::Local),
            (2..3, TokenKind::Operator),
            (4..5, TokenKind::Operator),
            (5..6, TokenKind::Number),
            (7..8, TokenKind::Operator),
            (9..13, TokenKind::Number),
            (13..14, TokenKind::Punctuation),
        ]
        .into_iter()
        .map(|(range, kind)| CSpan {
            range,
            kind,
            node: None,
            automatic: false,
            cast: false,
        })
        .collect();
        let l2 = Ast::new(0, Types::new(64));
        let doc = CDocument::from_parts(
            FunctionId::from_raw(0),
            0,
            View::Exact,
            text,
            spans,
            BTreeMap::new(),
            &l2,
            &L1::default(),
        );
        let minus_one = Some((
            3,
            Written {
                bits: u64::MAX,
                negative: true,
            },
        ));
        // The sign and the digits: one number, -1 (the listing's
        // `0FFFFFFFFh`), on the literal's span.
        assert_eq!(doc.number(2), minus_one);
        assert_eq!(doc.number(3), minus_one);
        // A spaced binary minus is no sign: `0x10` is 16, the `-` nothing.
        assert_eq!(doc.number(4), None);
        assert_eq!(
            doc.number(5),
            Some((
                5,
                Written {
                    bits: 0x10,
                    negative: false,
                }
            ))
        );
        assert_eq!(doc.number(0), None);
        assert_eq!(doc.number(1), None);
        assert_eq!(doc.number(6), None);
    }

    #[test]
    fn identifiers_are_validated_and_empty_resets() {
        assert_eq!(identifier("  count "), Ok(Some("count".to_owned())));
        assert_eq!(identifier(""), Ok(None));
        assert!(identifier("名前").is_err());
        assert!(identifier("2x").is_err());
        assert!(identifier("a-b").is_err());
    }

    #[test]
    fn the_body_starts_at_the_signature_past_the_preamble() {
        use binbun_ast::ir::StmtId;
        let text =
            "/* f */\nint g(int);\nint f(int a,\n    int b)\n{\n    int v;\n    return v;\n}";
        let at = text.find("return").unwrap();
        let spans = vec![CSpan {
            range: at..at + 6,
            kind: TokenKind::ControlKeyword,
            node: Some(Node::Stmt(StmtId(0))),
            automatic: false,
            cast: false,
        }];
        let l2 = Ast::new(0, Types::new(64));
        let doc = CDocument::from_parts(
            FunctionId::from_raw(0),
            0,
            View::Exact,
            text.to_owned(),
            spans,
            BTreeMap::new(),
            &l2,
            &L1::default(),
        );
        assert_eq!(doc.body_start(), 2);
        assert_eq!(document().body_start(), 0);
    }

    #[test]
    fn names_lead_to_their_functions_and_gotos_to_their_labels() {
        use TokenKind::{Comment as M, ControlKeyword as C, Function as F, Label as L};
        use binbun_ast::ir::{ExprId, StmtId};
        let text = "int32_t step(int64_t); /* 0x1450 */\n\
                    int32_t main_2(int32_t) BINBUN_SYMBOL(\"main\"); /* 0x1070 main */\n\
                    int32_t f(int64_t a1)\n{\n    \
                    if (step(a1)) goto label_3;\n    main_2(f(a1));\n\
                    label_3:\n    return 0;\n}"
            .to_owned();
        let call = Some(Node::Expr(ExprId(0)));
        let stmt = Some(Node::Stmt(StmtId(0)));
        let mut spans = Vec::new();
        let mut at = 0;
        let mut token = |word: &str, kind, node| {
            let start = at + text[at..].find(word).unwrap();
            at = start + word.len();
            spans.push(CSpan {
                range: start..at,
                kind,
                node,
                automatic: false,
                cast: false,
            });
            spans.len() - 1
        };
        token("step", F, None);
        token("/* 0x1450 */", M, None);
        token("main_2", F, None);
        token("/* 0x1070 main */", M, None);
        let defined = token("f", F, None);
        token("if", C, stmt);
        let step = token("step", F, call);
        let goto = token("label_3", L, stmt);
        let main = token("main_2", F, call);
        let recursive = token("f", F, call);
        let label = token("label_3", L, stmt);
        let ret = token("return", C, stmt);
        let l2 = Ast::new(0, Types::new(64));
        let doc = CDocument::from_parts(
            FunctionId::from_raw(0),
            0x1000,
            View::Exact,
            text,
            spans,
            BTreeMap::new(),
            &l2,
            &L1::default(),
        );
        // By the declarations' notes, whatever the C name.
        assert_eq!(doc.function_address(step), Some(0x1450));
        assert_eq!(doc.function_address(main), Some(0x1070));
        // The function itself, defined or called.
        assert_eq!(doc.function_address(defined), Some(0x1000));
        assert_eq!(doc.function_address(recursive), Some(0x1000));
        assert_eq!(doc.function_address(goto), None);
        // A goto's label is its definition; the definition leads nowhere.
        assert_eq!(doc.label_definition(goto), Some(label));
        assert_eq!(doc.label_definition(label), None);
        assert_eq!(doc.label_definition(ret), None);
    }

    #[test]
    fn lines_split_spans_and_find_tokens() {
        let doc = document();
        assert_eq!(doc.lines.len(), 2);
        assert_eq!(doc.lines[0].spans, 0..3);
        assert_eq!(doc.lines[1].spans, 3..9);
        assert_eq!(doc.span_at(1, 5), Some(5));
        assert_eq!(doc.span_at(1, 4), None);
        assert_eq!(doc.line_of_span(7), Some(1));
        assert_eq!(doc.nth_occurrence(Node::Var(VarId(0)), 9), Some(5));
        // No provenance: no tints, no links.
        assert!(doc.lines.iter().all(|l| l.tint.is_none()));
        assert_eq!(doc.spans_of(0), Vec::<usize>::new());
    }

    /// A document of `lines`, each one statement token over the line made
    /// from the instructions given (provenance set as a session's would).
    pub(crate) fn made(view: View, lines: &[(&str, &[u64])]) -> CDocument {
        use binbun_ast::ir::{Origin, StmtId};
        let text = lines.iter().map(|(t, _)| *t).collect::<Vec<_>>().join("\n");
        let mut at = 0;
        let mut spans = Vec::new();
        for (k, (line, _)) in lines.iter().enumerate() {
            let start = at + line.len() - line.trim_start().len();
            spans.push(CSpan {
                range: start..at + line.len(),
                kind: TokenKind::Keyword,
                node: Some(Node::Stmt(StmtId(u32::try_from(k).unwrap()))),
                automatic: false,
                cast: false,
            });
            at += line.len() + 1;
        }
        // Each line's statement made from its instructions.
        let mut l2 = Ast::new(0, Types::new(64));
        for (k, (_, addresses)) in lines.iter().enumerate() {
            for &address in *addresses {
                let stmt = StmtId(u32::try_from(k).unwrap());
                l2.provenance
                    .add_stmt_origin(stmt, Origin::Instruction(address));
            }
        }
        CDocument::from_parts(
            FunctionId::from_raw(0),
            0,
            view,
            text,
            spans,
            BTreeMap::new(),
            &l2,
            &L1::default(),
        )
    }

    /// Bookmarks in the C: on the lines made from their instructions, the
    /// entry's on the signature; one at an instruction of the function no
    /// line is made from on the next statement (as a cursor there shows),
    /// none for another function's address or past the last statement.
    #[test]
    fn marks_go_to_their_lines_or_the_next_statement_inside_the_function() {
        let mut doc = made(
            View::Exact,
            &[
                ("struct s { int x; };", &[]),
                ("int f(void)", &[]),
                ("{", &[]),
                ("    a = 1;", &[0x10]),
                ("    b = 2;", &[0x18, 0x1c]),
                ("    return b;", &[0x24]),
                ("}", &[]),
            ],
        );
        for span in &mut doc.spans[..3] {
            span.node = None;
        }
        let marks: BTreeMap<u64, char> = [
            (0x0, 'e'),
            (0x8, 'o'),
            (0x10, 'a'),
            (0x14, 'f'),
            (0x1c, 'b'),
            (0x20, 'g'),
            (0x30, 'p'),
            (0x50, 'x'),
        ]
        .into();
        // 0x8 is another function's (a chunk between this one's parts).
        let inside = |a: u64| a < 0x40 && a != 0x8;
        let lines: Vec<(usize, Vec<(u64, char)>)> = doc
            .marked_lines(&marks, inside)
            .into_iter()
            .map(|(n, marks)| (n, marks.into_iter().map(|(a, &m)| (a, m)).collect()))
            .collect();
        assert_eq!(
            lines,
            [
                (1, vec![(0x0, 'e')]),
                (3, vec![(0x10, 'a')]),
                (4, vec![(0x14, 'f'), (0x1c, 'b')]),
                (5, vec![(0x20, 'g')]),
            ]
        );
    }

    #[test]
    fn each_hidden_check_marks_its_reading_line_with_the_exact_lines_there() {
        use binbun_ast::ir::{ExprId, StmtId};
        // strvec_len: two checks, at 0x10 (`*a1`) and 0x30 (`*v3`). As the
        // engine makes them: each check's statement names its block's first
        // instruction (0x0c, 0x2c), not the access.
        let mut exact = made(
            View::Exact,
            &[
                ("{", &[]),
                ("    binbun_check_canonical(a1);", &[0x0c]),
                ("    if (*a1 == 0)", &[0x10, 0x14]),
                ("        return 0;", &[0x18]),
                ("    while (1) {", &[0x20]),
                ("        v3 = a1 + v2;", &[0x30]),
                ("        if (sext_n(v3, 48) != v3)", &[0x2c]),
                ("            break;", &[]),
                ("        if (*v3 == 0)", &[0x30, 0x34]),
                ("            return v2;", &[0x38]),
                ("    }", &[]),
                ("    binbun_trap(BINBUN_TRAP_PROTECTION);", &[0x30]),
            ],
        );
        let stmt = |k| Node::Stmt(StmtId(k));
        exact.checks.insert(0x10, vec![stmt(1)]);
        exact.checks.insert(0x30, vec![stmt(6), stmt(7)]);
        let mut reading = made(
            View::Reading,
            &[
                ("{", &[]),
                ("    if (*a1 == 0)", &[0x10, 0x14]),
                ("        return 0;", &[0x18]),
                ("    do {", &[0x30, 0x34]),
                ("    } while (*v3 != 0);", &[]),
            ],
        );
        // One `do` statement over lines 3 and 4, its condition on line 4.
        reading.spans[4].node = Some(Node::Expr(ExprId(9)));
        reading.conditions.insert(StmtId(3), ExprId(9));
        let reveals = reading.reveals(&[0x10, 0x30], Some(&exact));
        assert_eq!(reveals.keys().copied().collect::<Vec<_>>(), vec![1, 4]);
        assert_eq!(reveals[&1].sites, vec![0x10]);
        // The check, then the access below it.
        assert_eq!(reveals[&1].exact, vec![1, 2]);
        // The check and its `break`, then the access: not the address
        // computed before it nor the trap the `break` leads to.
        assert_eq!(reveals[&4].exact, vec![6, 7, 8]);
        assert_eq!(exact.indent(&reveals[&4].exact), 8);
        assert_eq!(exact.indent(&[0, 1]), 0);
        // Without the exact C yet: the marks alone.
        let marks = reading.reveals(&[0x30, 0x10, 0x30], None);
        assert_eq!(marks[&4].sites, vec![0x30]);
        assert!(marks.values().all(|r| r.exact.is_empty()));
        // A site no line names goes to the nearest line below it.
        assert_eq!(reading.reveals(&[0x2c], None)[&3].sites, vec![0x2c]);
        // Without check statements, the lines made from the instruction,
        // first to last.
        exact.checks.clear();
        let fallback = reading.reveals(&[0x30], Some(&exact));
        assert_eq!(fallback[&4].exact, (5..=11).collect::<Vec<_>>());
    }

    #[test]
    fn a_card_shows_a_spelled_out_check_in_its_short_form() {
        use super::CardLine;
        use binbun_ast::ir::StmtId;
        use binbun_semantics::ir::Trap;
        // strvec_len's exact C: the check spelled out (its trap after the
        // loop), then one on a single line, then one the C already writes
        // short.
        let mut exact = made(
            View::Exact,
            &[
                (
                    "        if ((uint64_t)sext_n((uint64_t)v3, 48) != (uint64_t)v3)",
                    &[0x2c],
                ),
                ("            break;", &[]),
                ("        if (*v3 == 0)", &[0x30]),
                (
                    "    if ((uint64_t)sext_n((uint64_t)(a3 + 8), 48) != (uint64_t)(a3 + 8)) goto label_2;",
                    &[0x40],
                ),
                ("    binbun_check_canonical(a1);", &[0x50]),
                ("    if (sext_n(x, 32) != x)", &[0x60]),
            ],
        );
        let stmt = |k| Node::Stmt(StmtId(k));
        exact.checks.insert(0x30, vec![stmt(0), stmt(1)]);
        exact.checks.insert(0x40, vec![stmt(3), stmt(3)]);
        exact.checks.insert(0x50, vec![stmt(4)]);
        exact.checks.insert(0x60, vec![stmt(5)]);
        exact.traps.insert(0x30, Trap::Protection);
        exact.traps.insert(0x40, Trap::Stack);
        exact.traps.insert(0x50, Trap::Protection);
        exact.traps.insert(0x60, Trap::Protection);
        let check = |line, text: &str| CardLine::Check {
            line,
            text: text.to_owned(),
        };
        assert_eq!(
            exact.card_lines(&[0, 1, 2, 3, 4, 5]),
            [
                check(0, "        binbun_check_canonical(v3);"),
                // The `break;` left out, the access as it is.
                CardLine::Line(2),
                check(3, "    binbun_check_canonical_stack((a3 + 8));"),
                CardLine::Line(4),
                // Not the canonical-address test: as it is.
                CardLine::Line(5),
            ]
        );
        // Only the lines asked for.
        assert_eq!(exact.card_lines(&[2]), [CardLine::Line(2)]);
    }

    #[test]
    fn checks_are_the_branches_with_a_trapping_way_by_the_instruction_deciding_them() {
        use binbun_ast::ir::{ExprId, Origin, Place, Stmt, StmtId};
        use binbun_semantics::ir::Trap;
        use binbun_ssa::ir::{
            Block, BlockId, Definition, Inst, InstId, Op, Target, Terminator, Type, Unknown, Value,
            ValueInfo,
        };
        let to = |b| Target {
            block: BlockId(b),
            arguments: Vec::new(),
        };
        let branch = |v, then, otherwise| Terminator::Branch {
            condition: Value(v),
            then: to(then),
            otherwise: to(otherwise),
        };
        let block = |address, insts: &[u32], terminator| Block {
            address,
            end: address,
            parameters: Vec::new(),
            insts: insts.iter().map(|&i| InstId(i)).collect(),
            terminator,
        };
        // b0 checks the value of 0x10 (its other way b1 traps); b2 branches
        // on 0x20's with neither way trapping; b4 checks 0x30's, the trap
        // its `then` (b6); b3 traps but has an instruction.
        let l1 = L1 {
            entry: 0,
            blocks: vec![
                block(0x0c, &[0], branch(0, 2, 1)),
                block(0x10, &[], Terminator::Trap(Trap::Protection)),
                block(0x20, &[1], branch(1, 3, 4)),
                block(0x24, &[3], Terminator::Trap(Trap::Protection)),
                block(0x2c, &[2], branch(2, 6, 5)),
                block(0x34, &[], Terminator::Stop),
                block(0x30, &[], Terminator::Trap(Trap::Stack)),
            ],
            insts: [0x10, 0x20, 0x30, 0x24]
                .into_iter()
                .zip(0..)
                .map(|(address, v)| Inst {
                    op: Op::Undefined(Unknown::Lowering, Vec::new()),
                    results: vec![Value(v)],
                    address,
                })
                .collect(),
            values: (0..4)
                .map(|i| ValueInfo {
                    ty: Type::Bits(1),
                    definition: Definition::Result {
                        inst: InstId(i),
                        index: 0,
                    },
                })
                .collect(),
            ..L1::default()
        };
        let mut l2 = Ast::new(0, Types::new(64));
        let trap = l2.add_stmt(Stmt::Trap(Trap::Protection));
        let check = l2.add_stmt(Stmt::If {
            condition: ExprId(0),
            then: vec![trap],
            otherwise: Vec::new(),
        });
        let code = l2.add_stmt(Stmt::Assign {
            place: Place::Var(VarId(0)),
            value: ExprId(1),
        });
        let plain = l2.add_stmt(Stmt::If {
            condition: ExprId(2),
            then: vec![code],
            otherwise: Vec::new(),
        });
        let leave = l2.add_stmt(Stmt::Break(StmtId(9)));
        let loop_check = l2.add_stmt(Stmt::If {
            condition: ExprId(3),
            then: vec![leave, code],
            otherwise: Vec::new(),
        });
        let origins = [
            (check, 0),
            (code, 0),
            (plain, 2),
            (loop_check, 4),
            (loop_check, 9),
        ];
        for (s, b) in origins {
            l2.provenance.add_stmt_origin(s, Origin::Block(BlockId(b)));
        }
        let (found, traps) = super::checks(&l2, &l1);
        let nodes = |s: &[StmtId]| s.iter().map(|&s| Node::Stmt(s)).collect::<Vec<_>>();
        assert_eq!(found.len(), 2, "{found:?}");
        // The deciding statement and its arm's trap, not the block's code.
        assert_eq!(found[&0x10], nodes(&[check, trap]));
        // Of the arm, only the jump.
        assert_eq!(found[&0x30], nodes(&[loop_check, leave]));
        // Each with its trap's kind.
        assert_eq!(
            traps,
            std::collections::HashMap::from([(0x10, Trap::Protection), (0x30, Trap::Stack)])
        );
    }

    #[test]
    fn a_check_made_far_apart_shows_only_its_own_lines() {
        let mut lines: Vec<(&str, &[u64])> = vec![("    a = *p;", &[0x10])];
        lines.extend(std::iter::repeat_n(("    b++;", &[0x20][..]), REVEAL_SPAN));
        lines.push(("    c = *p;", &[0x10]));
        let exact = made(View::Exact, &lines);
        let reading = made(View::Reading, &[("    a = *p;", &[0x10])]);
        let reveals = reading.reveals(&[0x10], Some(&exact));
        assert_eq!(reveals[&0].exact, vec![0, REVEAL_SPAN + 1]);
    }

    /// The fixture's `shrd rdx, rdx, 0x1d; jo`: in each view every token
    /// of the overflow flag SHRD leaves undefined (the reading view's
    /// `_OF_undefined`, declared and read; the exact view's helper) leads
    /// to that instruction and OF, which the peek card shows; the other
    /// values (the parameter, the returned constants) do not; and the
    /// document counts it as processor-dependent.
    #[test]
    fn an_undefined_flags_tokens_lead_to_the_instruction_leaving_it() {
        use std::path::PathBuf;
        use std::sync::Arc;
        use std::time::Duration;

        use binbun_session::{DebugSource, Options, Session, Stage, Waited};

        use super::RegisterId;
        use super::UndefinedValue;

        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/undefined-x86_64.elf");
        let session = Session::open(
            path,
            Options {
                ephemeral: true,
                warm: false,
                debug: DebugSource::Without,
                signatures: without_signatures(),
                ..Options::default()
            },
        )
        .unwrap();
        let waited = session.wait(Stage::Callers, Some(Duration::from_secs(600)));
        assert!(matches!(waited, Waited::Reached(_)), "{waited:?}");
        let database = session.database().unwrap();
        let id = database.find_function("shrd_jo").unwrap();
        let of = database
            .declarations()
            .unwrap()
            .registers
            .iter()
            .position(|r| r.name.eq_ignore_ascii_case("of"))
            .map(|i| RegisterId(u16::try_from(i).unwrap()))
            .unwrap();
        let site = database
            .declarations()
            .unwrap()
            .find_site("shrd.of")
            .unwrap();
        let expected = UndefinedValue {
            address: 0x0020_116a,
            register: Some(of),
            site: Some(site),
        };
        for (view, token, count) in [
            (View::Reading, "_OF_undefined", 2),
            (View::Exact, "binbun_undefined_bool", 1),
        ] {
            let document = Arc::new(session.document_here(id, view).unwrap());
            let c = CDocument::new(&document);
            assert_eq!(c.processor_dependent, 1, "{view:?}: {}", c.text);
            assert_eq!(c.undefined_values, [expected], "{view:?}");
            let mut found = 0;
            for s in 0..c.spans.len() {
                let undefined = c.undefined(s);
                if c.span_text(s) == token {
                    assert_eq!(undefined, Some(expected), "{view:?}");
                    found += 1;
                } else if matches!(c.span_text(s), "a1" | "1" | "2") {
                    assert_eq!(undefined, None, "{view:?}: {}", c.span_text(s));
                }
            }
            assert_eq!(found, count, "{view:?}: {}", c.text);
        }
    }
}
