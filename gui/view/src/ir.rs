//! The IR viewer: one function
//! through every stage of decompilation ([`binbun::stages`]) in a C pane.
//! A pane's state ([`IrPane`]): the stage shown (kept by its label as the
//! function changes), the cursor kept through the stages (the same line
//! by identity, value or node, else the same instruction), the
//! difference from the stage before shown as a unified diff or folded,
//! the rows that makes ([`rows`]), each line's tokens by role
//! ([`roles`]), and the tokens a changed line changed ([`changed_tokens`]).

use std::ops::Range;

use binbun::stages::{Change, Level, Stage, Stages};

use crate::scroll::{Scroller, Sideways};

/// A row shown: a line of the stage, or a line of the stage before (the
/// form a changed line had, a line removed), or removed lines folded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Row {
    /// Line `n` of the stage.
    Line(usize),
    /// The form line `n` of the stage had in the stage before (it
    /// changed).
    Was(usize),
    /// The stage's removed line `n` ([`Stage::removed`]).
    Removed(usize),
    /// The `count` removed lines that were before line `before` of the
    /// stage (its line count: at its end), folded to one row.
    Folded {
        /// The line they were before ([`Removed::before`](binbun::stages::Removed::before)).
        before: usize,
        /// How many.
        count: usize,
    },
}

/// The rows of `stage`: its lines with its removed lines where they were
/// (before the line they preceded); with `diff` (a unified diff) each
/// removed line and the stage before's form of each changed line just
/// above it, else each group of removed lines folded to one row unless
/// `open` has the line it was before.
pub fn rows(stage: &Stage, diff: bool, open: &[usize]) -> Vec<Row> {
    let mut removed: Vec<(usize, usize)> = stage
        .removed
        .iter()
        .enumerate()
        .map(|(index, gone)| (gone.before, index))
        .collect();
    removed.sort_by_key(|&(before, _)| before);
    let mut out = Vec::with_capacity(stage.lines.len() * 2 + removed.len());
    let mut gone = removed.into_iter().peekable();
    let mut group = |out: &mut Vec<Row>, before: usize| {
        let start = out.len();
        while let Some((_, index)) = gone.next_if(|&(at, _)| at == before) {
            out.push(Row::Removed(index));
        }
        let count = out.len() - start;
        if !diff && count > 0 && !open.contains(&before) {
            out.truncate(start);
            out.push(Row::Folded { before, count });
        }
    };
    for (line, at) in stage.lines.iter().enumerate() {
        group(&mut out, line);
        if diff && at.change == Some(Change::Changed) && at.was.is_some() {
            out.push(Row::Was(line));
        }
        out.push(Row::Line(line));
    }
    group(&mut out, stage.lines.len());
    out
}

/// The stage shown when none was chosen: the last L2 (the IR the C is
/// printed from), else the last.
pub fn default_stage(stages: &Stages) -> usize {
    stages
        .stages
        .iter()
        .rposition(|stage| stage.level == Level::L2)
        .unwrap_or_else(|| stages.stages.len().saturating_sub(1))
}

/// A stage's change against the one before, as the scrubber's dropdown
/// says it (`+3 ~2 -1`; nothing for a stage not compared or unchanged
/// lines).
pub fn summary(stage: &Stage) -> String {
    if !stage.compared {
        return String::new();
    }
    let (added, changed, removed) = stage.counts();
    let mut parts = Vec::new();
    if added > 0 {
        parts.push(format!("+{added}"));
    }
    if changed > 0 {
        parts.push(format!("~{changed}"));
    }
    if removed > 0 {
        parts.push(format!("-{removed}"));
    }
    parts.join(" ")
}

/// A pane's IR viewer.
#[derive(Debug)]
pub struct IrPane {
    /// The pane shows the IR (else its C).
    pub on: bool,
    /// The stage chosen, by label; `None`: [`default_stage`].
    pub wanted: Option<String>,
    /// The cursor's row.
    pub cursor: usize,
    /// The stage shown as a unified diff against the stage before (else
    /// as it is, its removed lines folded).
    pub diff: bool,
    /// The folded groups of removed lines opened, by the line they were
    /// before (until the stage or [`Self::diff`] changes).
    pub open: Vec<usize>,
    /// The rows' scrolling.
    pub scroll: Scroller,
    /// The rows' sideways scrolling.
    pub side: Sideways,
    /// The stages' dropdown is open.
    pub dropdown: bool,
    /// The address the cursor goes to when the stages arrive.
    pub target: Option<u64>,
}

impl Default for IrPane {
    /// Off, on the default stage, shown as a unified diff.
    fn default() -> Self {
        Self {
            on: false,
            wanted: None,
            cursor: 0,
            diff: true,
            open: Vec::new(),
            scroll: Scroller::default(),
            side: Sideways::default(),
            dropdown: false,
            target: None,
        }
    }
}

impl IrPane {
    /// The stage shown of `stages`.
    pub fn stage(&self, stages: &Stages) -> usize {
        self.wanted
            .as_deref()
            .and_then(|label| stages.find(label))
            .unwrap_or_else(|| default_stage(stages))
    }

    /// The rows of the stage shown of `stages` ([`rows`]).
    pub fn rows(&self, stages: &Stages) -> Vec<Row> {
        stages
            .stages
            .get(self.stage(stages))
            .map_or_else(Vec::new, |stage| rows(stage, self.diff, &self.open))
    }

    /// The line of the stage shown the cursor is on (a removed row: the
    /// line it was before, else the last).
    pub fn line(&self, stages: &Stages) -> Option<usize> {
        let stage = stages.stages.get(self.stage(stages))?;
        line_of(stage, self.rows(stages).get(self.cursor).copied()?)
    }

    /// The address the cursor stands for: its line's (or removed line's)
    /// lowest instruction.
    pub fn address(&self, stages: &Stages) -> Option<u64> {
        let stage = stages.stages.get(self.stage(stages))?;
        match self.rows(stages).get(self.cursor)? {
            Row::Line(n) | Row::Was(n) => stage.lines.get(*n)?.addresses.first().copied(),
            Row::Removed(n) => stage.removed.get(*n)?.addresses.first().copied(),
            Row::Folded { before, .. } => stage
                .removed
                .iter()
                .find(|gone| gone.before == *before)?
                .addresses
                .first()
                .copied(),
        }
    }

    /// Shows stage `to` of `stages`, the cursor on the line standing for
    /// the one it was on ([`Stages::follow`]); whether the stage changed.
    pub fn go(&mut self, stages: &Stages, to: usize) -> bool {
        let from = self.stage(stages);
        let Some(target) = stages.stages.get(to) else {
            return false;
        };
        if to == from {
            return false;
        }
        let line = self
            .line(stages)
            .and_then(|line| stages.follow(from, line, to));
        self.wanted = Some(target.label.clone());
        self.open.clear();
        self.cursor = line.map_or(0, |line| row_of(target, self.diff, &self.open, line));
        true
    }

    /// The stage `delta` stages on from the one shown (`<` and `>`);
    /// whether it moved.
    pub fn step(&mut self, stages: &Stages, delta: isize) -> bool {
        let to = self.stage(stages).saturating_add_signed(delta);
        to < stages.stages.len() && self.go(stages, to)
    }

    /// Shows the stage as a unified diff or as it is, the cursor kept on
    /// its line.
    pub fn set_diff(&mut self, stages: &Stages, diff: bool) {
        let line = self.line(stages);
        self.diff = diff;
        self.open.clear();
        if let (Some(line), Some(stage)) = (line, stages.stages.get(self.stage(stages))) {
            self.cursor = row_of(stage, diff, &self.open, line);
        }
    }

    /// Opens the folded removed lines on row `row` in place, the cursor on
    /// their first; whether it was such a row.
    pub fn unfold(&mut self, stages: &Stages, row: usize) -> bool {
        let Some(&Row::Folded { before, .. }) = self.rows(stages).get(row) else {
            return false;
        };
        self.open.push(before);
        self.cursor = row;
        true
    }

    /// The cursor on the line of the stage shown that stands for the
    /// instruction at `address` ([`Stage::line_at`]); whether there is one.
    pub fn land(&mut self, stages: &Stages, address: u64) -> bool {
        let Some(stage) = stages.stages.get(self.stage(stages)) else {
            return false;
        };
        match stage.line_at(address) {
            Some(line) => {
                self.cursor = row_of(stage, self.diff, &self.open, line);
                true
            }
            None => false,
        }
    }
}

/// The line row `row` of `stage` is or was before.
fn line_of(stage: &Stage, row: Row) -> Option<usize> {
    match row {
        Row::Line(n) | Row::Was(n) => Some(n),
        Row::Removed(n) => {
            let before = stage.removed.get(n)?.before;
            Some(before.min(stage.lines.len().checked_sub(1)?))
        }
        Row::Folded { before, .. } => Some(before.min(stage.lines.len().checked_sub(1)?)),
    }
}

/// The row line `line` of `stage` is shown on.
fn row_of(stage: &Stage, diff: bool, open: &[usize], line: usize) -> usize {
    if !diff && stage.removed.is_empty() {
        return line;
    }
    rows(stage, diff, open)
        .iter()
        .position(|&row| row == Row::Line(line))
        .unwrap_or(0)
}

/// What differs between a changed line's two forms: byte ranges of each,
/// in order, to show stronger.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TokenDiff {
    /// In the form it had.
    pub old: Vec<Range<usize>>,
    /// In the form it has.
    pub new: Vec<Range<usize>>,
}

/// The most token pairs [`changed_tokens`] compares before it marks the
/// whole lines.
const PAIRS: usize = 1 << 16;

/// The tokens that differ between line `old` and line `new` of a stage of
/// `level`: those outside a longest common subsequence of their tokens
/// ([`roles`]' tokens; punctuation, comments and plain words split at
/// spaces and brackets), of those the one leaving the fewest runs of
/// them ([`align`]), each run (spaces between joined) one range; when
/// most tokens differ, each whole line (its text without the leading and
/// trailing blanks). Identical lines: none.
///
/// ```
/// use binbun::stages::Level;
/// use binbun_gui_view::ir::changed_tokens;
///
/// let (old, new) = ("  v3:64 = add v1, v2", "  v3:64 = add v1, v5");
/// let diff = changed_tokens(Level::L1, old, new);
/// assert_eq!(diff.old, [18..20]);
/// assert_eq!(diff.new, [18..20]);
/// ```
pub fn changed_tokens(level: Level, old: &str, new: &str) -> TokenDiff {
    if old == new {
        return TokenDiff::default();
    }
    let was = tokens(level, old);
    let now = tokens(level, new);
    let same = |i: usize, j: usize| {
        was.get(i)
            .zip(now.get(j))
            .is_some_and(|(token, other)| old.get(token.clone()) == new.get(other.clone()))
    };
    // The common head and tail, then a longest common subsequence of
    // what is between.
    let shorter = was.len().min(now.len());
    let head = (0..shorter).take_while(|&i| same(i, i)).count();
    let tail = (0..shorter - head)
        .take_while(|&back| same(was.len() - 1 - back, now.len() - 1 - back))
        .count();
    let (n, m) = (was.len() - head - tail, now.len() - head - tail);
    let whole = || TokenDiff {
        old: whole_line(old),
        new: whole_line(new),
    };
    if n.saturating_mul(m) > PAIRS {
        return whole();
    }
    let ends = |len: usize| (0..len).map(|at| at < head || at >= len - tail).collect();
    let mut kept_was: Vec<bool> = ends(was.len());
    let mut kept_now: Vec<bool> = ends(now.len());
    let pairs = align(n, m, |i, j| same(head + i, head + j));
    for &(i, j) in &pairs {
        if let Some(kept) = kept_was.get_mut(head + i) {
            *kept = true;
        }
        if let Some(kept) = kept_now.get_mut(head + j) {
            *kept = true;
        }
    }
    let common = head + tail + pairs.len();
    if common * 2 < was.len().max(now.len()) {
        return whole();
    }
    TokenDiff {
        old: runs(old, &was, &kept_was),
        new: runs(new, &now, &kept_now),
    }
}

/// The tokens of two lists (`n` and `m` long, `same`: whether the `i`th
/// of the first is the `j`th of the second) paired, in order: a longest
/// common subsequence, of those the one leaving the fewest runs of
/// unpaired tokens in the two (`and-then(A, B)` from `A`: `A` paired with
/// the `A` it was, not its head with that `A` and its tail with `B`'s).
fn align(n: usize, m: usize, same: impl Fn(usize, usize) -> bool) -> Vec<(usize, usize)> {
    // `best[(i, j, open)]`: the best score from the `i`th and `j`th tokens
    // on, `open` saying which list has a run of unpaired tokens open
    // (bit 0 the first, bit 1 the second); a pair is worth more than
    // every run there can be.
    let pair = i32::try_from(n + m + 1).unwrap_or(i32::MAX);
    let at = |i: usize, j: usize, open: usize| (i * (m + 1) + j) * 4 + open;
    let mut best = vec![0i32; (n + 1) * (m + 1) * 4];
    let score = |best: &[i32], i: usize, j: usize, open: usize| {
        best.get(at(i, j, open)).copied().unwrap_or(i32::MIN / 2)
    };
    // The choices at `(i, j, open)`, each its score: pairing, leaving the
    // first's token, leaving the second's.
    let choices = |best: &[i32], i: usize, j: usize, open: usize| {
        let skip = |bit: usize| i32::from(open & bit == 0);
        [
            (i < n && j < m && same(i, j)).then(|| pair + score(best, i + 1, j + 1, 0)),
            (i < n).then(|| score(best, i + 1, j, open | 1) - skip(1)),
            (j < m).then(|| score(best, i, j + 1, open | 2) - skip(2)),
        ]
    };
    for i in (0..=n).rev() {
        for j in (0..=m).rev() {
            for open in 0..4 {
                let value = choices(&best, i, j, open).into_iter().flatten().max();
                if let (Some(value), Some(cell)) = (value, best.get_mut(at(i, j, open))) {
                    *cell = value;
                }
            }
        }
    }
    let mut out = Vec::new();
    let (mut i, mut j, mut open) = (0, 0, 0);
    while i < n || j < m {
        let goal = score(&best, i, j, open);
        match choices(&best, i, j, open)
            .iter()
            .position(|&choice| choice == Some(goal))
        {
            Some(0) => {
                out.push((i, j));
                (i, j, open) = (i + 1, j + 1, 0);
            }
            Some(1) => (i, open) = (i + 1, open | 1),
            Some(_) | None if j < m => (j, open) = (j + 1, open | 2),
            Some(_) | None => (i, open) = (i + 1, open | 1),
        }
    }
    out
}

/// Line `text` without its leading and trailing blanks, as one range
/// (none if blank).
fn whole_line(text: &str) -> Vec<Range<usize>> {
    let range = leading(text)..text.trim_end().len();
    if range.is_empty() {
        Vec::new()
    } else {
        vec![range]
    }
}

/// The runs of `tokens` of `text` not `kept`, those with only blanks
/// between joined (tokens are never blank, so a kept one between is not).
fn runs(text: &str, tokens: &[Range<usize>], kept: &[bool]) -> Vec<Range<usize>> {
    let mut out: Vec<Range<usize>> = Vec::new();
    for (token, &kept) in tokens.iter().zip(kept) {
        if kept {
            continue;
        }
        match out.last_mut() {
            Some(last)
                if text
                    .get(last.end..token.start)
                    .is_some_and(|gap| gap.trim().is_empty()) =>
            {
                last.end = token.end;
            }
            _ => out.push(token.clone()),
        }
    }
    out
}

/// The tokens of line `text` of a stage of `level`, blanks left out:
/// [`roles`]' tokens, with punctuation, comments and plain text split
/// again ([`split`]).
fn tokens(level: Level, text: &str) -> Vec<Range<usize>> {
    let mut out = Vec::new();
    for (range, role) in roles(level, text) {
        match role {
            Role::Punctuation | Role::Comment | Role::Plain => split(text, range, &mut out),
            Role::Address
            | Role::Mnemonic
            | Role::Register
            | Role::Operation
            | Role::Value
            | Role::Variable
            | Role::Block
            | Role::Node
            | Role::Type
            | Role::Number
            | Role::Keyword
            | Role::Function
            | Role::String => out.push(range),
        }
    }
    out
}

/// Splits `range` of `text` into tokens on `out`: words (letters, digits
/// and `_ . % ^ ~ @`), each bracket, comma or semicolon alone, other
/// symbols together (`!=`, `->`); blanks left out.
fn split(text: &str, range: Range<usize>, out: &mut Vec<Range<usize>>) {
    let Some(part) = text.get(range.clone()) else {
        return;
    };
    let word = |c: char| c.is_alphanumeric() || matches!(c, '_' | '.' | '%' | '^' | '~' | '@');
    let alone = |c: char| matches!(c, '(' | ')' | '[' | ']' | '{' | '}' | ',' | ';');
    let mut chars = part.char_indices().peekable();
    while let Some((at, c)) = chars.next() {
        if c.is_whitespace() {
            continue;
        }
        let mut end = at + c.len_utf8();
        if !alone(c) {
            let kind = word(c);
            while let Some(&(next, d)) = chars.peek() {
                if d.is_whitespace() || alone(d) || word(d) != kind {
                    break;
                }
                end = next + d.len_utf8();
                chars.next();
            }
        }
        out.push(range.start + at..range.start + end);
    }
}

/// The runs line `text` of a stage of `level` is drawn in: its tokens by
/// role ([`roles`]), cut where the ranges `marked` (in order, apart)
/// start and end, each with whether it is marked.
///
/// ```
/// use binbun::stages::Level;
/// use binbun_gui_view::ir::{Role, marked_roles};
///
/// let runs = marked_roles(Level::L1, "jump b12()", &[5..8]);
/// assert_eq!(runs[2], (5..8, Role::Block, true));
/// assert_eq!(runs[3], (8..10, Role::Punctuation, false));
/// ```
pub fn marked_roles(
    level: Level,
    text: &str,
    marked: &[Range<usize>],
) -> Vec<(Range<usize>, Role, bool)> {
    let mut out = Vec::new();
    let mut marks = marked.iter().peekable();
    for (range, role) in roles(level, text) {
        let mut at = range.start;
        while at < range.end {
            while marks.next_if(|mark| mark.end <= at).is_some() {}
            let (end, on) = match marks.peek() {
                Some(mark) if mark.start <= at => (mark.end.min(range.end), true),
                Some(mark) => (mark.start.min(range.end), false),
                None => (range.end, false),
            };
            out.push((at..end, role, on));
            at = end;
        }
    }
    out
}

/// What a token of a stage's text is, for its colour.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Role {
    /// An instruction's address at the start of a line.
    Address,
    /// A machine instruction's mnemonic.
    Mnemonic,
    /// A register.
    Register,
    /// An L1 or L2 operation (`add`, `load`, `branch`, `mem`).
    Operation,
    /// An L1 value (`v12`, L2's `%v12`).
    Value,
    /// An L2 variable (`v3`).
    Variable,
    /// An L1 block (`b3`, L2's `^b3`).
    Block,
    /// An L2 statement's number (`s5:`).
    Node,
    /// A type or width (`int32`, `:64`, `uint8_t`).
    Type,
    /// A number.
    Number,
    /// A keyword (L2's `if`, `while`, `return`; C's).
    Keyword,
    /// A C call's callee.
    Function,
    /// A string.
    String,
    /// A comment (C's; L2's provenance after `;`).
    Comment,
    /// Punctuation.
    Punctuation,
    /// Anything else.
    Plain,
}

/// L2's words that are its statements' and declarations' keywords.
const L2_KEYWORDS: &[&str] = &[
    "function",
    "type",
    "var",
    "param",
    "local",
    "global",
    "frame",
    "env",
    "va",
    "save",
    "if",
    "else",
    "while",
    "do",
    "for",
    "switch",
    "case",
    "default",
    "fallthrough",
    "break",
    "continue",
    "label",
    "goto",
    "return",
    "trap",
    "unreachable",
    "eval",
    "call",
    "intrinsic",
    "escape",
    "va_start",
    "try",
    "catch",
    "cleanup",
    "landing",
    "unexpected",
    "except",
    "finally",
    "struct",
    "union",
    "size",
    "void",
];

/// L2's evidence words.
const L2_EVIDENCE: &[&str] = &[
    "default",
    "deduced",
    "declared",
    "declared-pointer",
    "proved",
];

/// C's keywords.
const C_KEYWORDS: &[&str] = &[
    "if",
    "else",
    "while",
    "do",
    "for",
    "switch",
    "case",
    "default",
    "break",
    "continue",
    "return",
    "goto",
    "sizeof",
    "struct",
    "union",
    "enum",
    "typedef",
    "static",
    "extern",
    "const",
    "volatile",
    "unsigned",
    "signed",
    "#include",
    "try",
    "catch",
    "__try",
    "__except",
    "__finally",
];

/// Whether `word` names an L2 type (`int32`, `bits64`, `ptr`, ...).
fn l2_type(word: &str) -> bool {
    let sized = ["bits", "int", "uint", "bool"]
        .iter()
        .any(|prefix| word.strip_prefix(prefix).is_some_and(all_digits));
    sized
        || matches!(
            word,
            "char"
                | "uchar"
                | "half"
                | "single"
                | "double"
                | "extended"
                | "ptr"
                | "code"
                | "array"
                | "vector"
        )
        || numbered(word, 't')
}

/// Whether `word` names a C type.
fn c_type(word: &str) -> bool {
    word.ends_with("_t")
        || matches!(
            word,
            "void" | "char" | "short" | "int" | "long" | "float" | "double" | "bool" | "_Bool"
        )
}

fn all_digits(text: &str) -> bool {
    !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit())
}

/// Whether `word` is `prefix` and a number (`v12`).
fn numbered(word: &str, prefix: char) -> bool {
    word.strip_prefix(prefix).is_some_and(all_digits)
}

/// The tokens of line `text` of a stage of `level`, by role, in order and
/// covering it (whitespace as [`Role::Plain`]).
pub fn roles(level: Level, text: &str) -> Vec<(Range<usize>, Role)> {
    let bytes = text.as_bytes();
    let mut out: Vec<(Range<usize>, Role)> = Vec::new();
    let mut at = 0;
    let from = |at: usize| text.get(at..).unwrap_or_default();
    // Machine code: the first word after the address is the mnemonic.
    let mut mnemonic = level == Level::Machine;
    let push = |out: &mut Vec<(Range<usize>, Role)>, range: Range<usize>, role: Role| match out
        .last_mut()
    {
        Some((last, was)) if *was == role && last.end == range.start => last.end = range.end,
        _ => out.push((range, role)),
    };
    while at < bytes.len() {
        let rest = from(at);
        let c = rest.chars().next().unwrap_or(' ');
        let start = at;
        // Comments: L2's provenance, C's.
        if (level == Level::L2 && rest.starts_with("  ; "))
            || (level == Level::C && (rest.starts_with("/*") || rest.starts_with("//")))
        {
            push(&mut out, start..text.len(), Role::Comment);
            break;
        }
        if c == '"' {
            let end = from(at + 1).find('"').map_or(text.len(), |e| at + e + 2);
            push(&mut out, start..end, Role::String);
            at = end;
            continue;
        }
        if c.is_whitespace() {
            at += c.len_utf8();
            push(&mut out, start..at, Role::Plain);
            continue;
        }
        // Sigils of L2's origins: `%v12`, `^b3`, `~b3`, `@0x…`.
        if level == Level::L2 && matches!(c, '%' | '^' | '~' | '@') {
            let end = at + 1 + word_len(from(at + 1), level);
            let role = match c {
                '%' => Role::Value,
                '@' => Role::Address,
                _ => Role::Block,
            };
            push(&mut out, start..end, role);
            at = end;
            continue;
        }
        if c.is_ascii_digit() {
            let end = at + number_len(rest);
            let role = if level != Level::C && start == leading(text) {
                Role::Address
            } else {
                Role::Number
            };
            push(&mut out, start..end, role);
            at = end;
            // A width after a constant (`0x8:64`).
            if level != Level::C && from(at).starts_with(':') {
                let width = 1 + word_len(from(at + 1), level);
                push(&mut out, at..at + width, Role::Type);
                at += width;
            }
            continue;
        }
        if c.is_alphabetic() || c == '_' || (level == Level::C && c == '#') {
            let end = at + c.len_utf8() + word_len(from(at + c.len_utf8()), level);
            let word = text.get(start..end).unwrap_or_default();
            let next = from(end).chars().next();
            let role = word_role(level, word, next, &mut mnemonic);
            push(&mut out, start..end, role);
            at = end;
            // L1's types after a value (`v12:64`, `v3:mem`).
            if level == Level::L1 && role == Role::Value && from(at).starts_with(':') {
                let width = 1 + word_len(from(at + 1), level);
                push(&mut out, at..at + width, Role::Type);
                at += width;
            }
            continue;
        }
        at += c.len_utf8();
        push(&mut out, start..at, Role::Punctuation);
    }
    out
}

/// Where the first non-blank byte of `text` is.
fn leading(text: &str) -> usize {
    text.len() - text.trim_start().len()
}

/// The length of the word at the start of `text` (letters, digits, `_`;
/// in L1 and L2 also `-` and `.`, which their operation names take).
fn word_len(text: &str, level: Level) -> usize {
    text.char_indices()
        .find(|&(_, c)| {
            !(c.is_alphanumeric()
                || c == '_'
                || (matches!(level, Level::L1 | Level::L2) && matches!(c, '-' | '.')))
        })
        .map_or(text.len(), |(i, _)| i)
}

/// The length of the number at the start of `text` (`0x1f`, `12`).
fn number_len(text: &str) -> usize {
    let hex = text.starts_with("0x") || text.starts_with("0X");
    let skip = if hex { 2 } else { 0 };
    let digits = text.get(skip..).unwrap_or_default();
    skip + digits
        .char_indices()
        .find(|&(_, c)| !(c.is_ascii_hexdigit() || (!hex && c.is_ascii_alphanumeric())))
        .map_or(digits.len(), |(i, _)| i)
}

/// The role of `word` in a line of `level`, the character after it
/// `next`; `mnemonic`: the machine line's mnemonic is still to come.
fn word_role(level: Level, word: &str, next: Option<char>, mnemonic: &mut bool) -> Role {
    match level {
        Level::Machine => {
            if std::mem::take(mnemonic) {
                Role::Mnemonic
            } else if matches!(
                word,
                "ptr" | "byte" | "word" | "dword" | "qword" | "xmmword"
            ) {
                Role::Plain
            } else {
                Role::Register
            }
        }
        Level::L1 => {
            if numbered(word, 'v') {
                Role::Value
            } else if numbered(word, 'b') {
                Role::Block
            } else {
                Role::Operation
            }
        }
        Level::L2 => {
            if numbered(word, 's') && next == Some(':') {
                Role::Node
            } else if numbered(word, 'v') {
                Role::Variable
            } else if l2_type(word) {
                Role::Type
            } else if L2_KEYWORDS.contains(&word) || L2_EVIDENCE.contains(&word) {
                Role::Keyword
            } else if numbered(word, 'l') {
                Role::Block
            } else {
                Role::Operation
            }
        }
        Level::C => {
            if C_KEYWORDS.contains(&word) {
                Role::Keyword
            } else if c_type(word) {
                Role::Type
            } else if next == Some('(') {
                Role::Function
            } else {
                Role::Plain
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use binbun::decompile::View;
    use binbun::stages::{Change, Key, Line, Removed, Stage, Stages};

    use super::{
        IrPane, Level, Role, Row, changed_tokens, default_stage, marked_roles, roles, rows, summary,
    };

    fn line(text: &mut String, key: Key, addresses: &[u64], content: &str) -> Line {
        let start = text.len();
        text.push_str(content);
        let range = start..text.len();
        text.push('\n');
        Line {
            range,
            key: Some(key),
            addresses: addresses.to_vec(),
            defines: Vec::new(),
            change: None,
            was: None,
            reason: None,
        }
    }

    /// Three stages: machine code, L1, and L1 after a pass that folded a
    /// branch and removed a line.
    fn stages() -> Stages {
        let mut machine = String::new();
        let lines = vec![
            line(
                &mut machine,
                Key::Instruction(0x10),
                &[0x10],
                "0x10  test rdi, rdi",
            ),
            line(
                &mut machine,
                Key::Instruction(0x13),
                &[0x13],
                "0x13  jz 0x20",
            ),
            line(&mut machine, Key::Instruction(0x20), &[0x20], "0x20  ret"),
        ];
        let machine = Stage {
            name: "machine",
            label: "machine".to_owned(),
            level: Level::Machine,
            text: machine,
            lines,
            removed: Vec::new(),
            compared: false,
        };
        let mut l1 = String::new();
        let lines = vec![
            line(&mut l1, Key::Block(0), &[0x10], "b0 @0x10 (v0:64 rdi):"),
            line(&mut l1, Key::Inst(0), &[0x10], "  0x10  v1:1 = eq v0, v0"),
            line(
                &mut l1,
                Key::Terminator(0),
                &[0x13],
                "  branch v1, b1(), b1()",
            ),
            line(&mut l1, Key::Block(1), &[0x20], "b1 @0x20 ():"),
        ];
        let lifting = Stage {
            name: "lifting",
            label: "lifting".to_owned(),
            level: Level::L1,
            text: l1,
            lines,
            removed: Vec::new(),
            compared: false,
        };
        let mut folded = String::new();
        let mut lines = vec![
            line(&mut folded, Key::Block(0), &[0x10], "b0 @0x10 (v0:64 rdi):"),
            line(&mut folded, Key::Terminator(0), &[0x13], "  jump b1()"),
            line(&mut folded, Key::Block(1), &[0x20], "b1 @0x20 ():"),
        ];
        lines[0].was = Some(0);
        lines[1].was = Some(2);
        lines[1].change = Some(Change::Changed);
        lines[2].was = Some(3);
        let fold = Stage {
            name: "fold-branches",
            label: "fold-branches".to_owned(),
            level: Level::L1,
            text: folded,
            lines,
            removed: vec![Removed {
                before: 1,
                text: "  0x10  v1:1 = eq v0, v0".to_owned(),
                key: Some(Key::Inst(0)),
                addresses: vec![0x10],
            }],
            compared: true,
        };
        Stages {
            entry: 0x10,
            view: View::Exact,
            stages: vec![machine, lifting, fold],
            passes: Vec::new(),
        }
    }

    #[test]
    fn removed_lines_show_where_they_were_folded_unless_diffing() {
        let stages = stages();
        let fold = &stages.stages[2];
        assert_eq!(
            rows(fold, false, &[]),
            [
                Row::Line(0),
                Row::Folded {
                    before: 1,
                    count: 1
                },
                Row::Line(1),
                Row::Line(2)
            ]
        );
        assert_eq!(
            rows(fold, false, &[1]),
            [Row::Line(0), Row::Removed(0), Row::Line(1), Row::Line(2)]
        );
        assert_eq!(
            rows(fold, true, &[]),
            [
                Row::Line(0),
                Row::Removed(0),
                Row::Was(1),
                Row::Line(1),
                Row::Line(2)
            ]
        );
        assert_eq!(summary(fold), "~1 -1");
        assert_eq!(summary(&stages.stages[1]), "");
    }

    #[test]
    fn folded_groups_open_one_at_a_time() {
        let mut stages = stages();
        let fold = &mut stages.stages[2];
        // Two more removed lines: one at the end, one with the first.
        fold.removed.push(gone(3, "  ret"));
        fold.removed.insert(1, gone(1, "  nop"));
        let folded = |before, count| Row::Folded { before, count };
        assert_eq!(
            rows(&stages.stages[2], false, &[]),
            [
                Row::Line(0),
                folded(1, 2),
                Row::Line(1),
                Row::Line(2),
                folded(3, 1)
            ]
        );
        let mut pane = IrPane::default();
        assert!(pane.diff, "the diff is shown by default");
        pane.set_diff(&stages, false);
        assert!(!pane.unfold(&stages, 0));
        assert!(pane.unfold(&stages, 1));
        assert_eq!(pane.cursor, 1);
        assert_eq!(
            pane.rows(&stages),
            [
                Row::Line(0),
                Row::Removed(0),
                Row::Removed(1),
                Row::Line(1),
                Row::Line(2),
                folded(3, 1)
            ]
        );
        assert_eq!(pane.address(&stages), Some(0x10));
        // On the group at the end: the line before it.
        pane.cursor = 5;
        assert_eq!(pane.line(&stages), Some(2));
        // The diff and back: folded again.
        pane.set_diff(&stages, true);
        pane.set_diff(&stages, false);
        assert_eq!(pane.rows(&stages).len(), 5);
    }

    fn gone(before: usize, text: &str) -> Removed {
        Removed {
            before,
            text: text.to_owned(),
            key: None,
            addresses: Vec::new(),
        }
    }

    #[test]
    fn the_cursor_is_kept_through_the_stages() {
        let stages = stages();
        // The default stage is the last of L1/L2 (here: fold-branches).
        assert_eq!(default_stage(&stages), 2);
        let mut pane = IrPane::default();
        // On the jump (the folded branch).
        assert!(pane.land(&stages, 0x13));
        assert_eq!(pane.line(&stages), Some(1));
        // Diffing: the removed row and the jump's old form above it.
        assert_eq!(pane.cursor, 3);
        // Back a stage: the same terminator, by identity.
        assert!(pane.step(&stages, -1));
        assert_eq!(pane.wanted.as_deref(), Some("lifting"));
        assert_eq!(pane.line(&stages), Some(2));
        // Back again: the machine instruction it stands for.
        assert!(pane.step(&stages, -1));
        assert_eq!(pane.line(&stages), Some(1));
        assert!(!pane.step(&stages, -1));
        // Forward twice: the removed row and the jump's old form shift the
        // cursor's row.
        assert!(pane.step(&stages, 2));
        assert_eq!((pane.cursor, pane.line(&stages)), (3, Some(1)));
        // On the old form: the line's address.
        pane.cursor = 2;
        assert_eq!(pane.address(&stages), Some(0x13));
        // On the removed row: its address; diff off, the line it preceded
        // (below the folded row).
        pane.cursor = 1;
        assert_eq!(pane.address(&stages), Some(0x10));
        pane.set_diff(&stages, false);
        assert_eq!((pane.cursor, pane.line(&stages)), (2, Some(1)));
        // The folded row stands for its first line's address.
        pane.cursor = 1;
        assert_eq!(pane.address(&stages), Some(0x10));
        assert!(!pane.step(&stages, 1));
    }

    /// The texts [`changed_tokens`] marks in `old` and `new`.
    fn marked<'a>(level: Level, old: &'a str, new: &'a str) -> (Vec<&'a str>, Vec<&'a str>) {
        let diff = changed_tokens(level, old, new);
        (
            diff.old.into_iter().map(|r| &old[r]).collect(),
            diff.new.into_iter().map(|r| &new[r]).collect(),
        )
    }

    #[test]
    fn a_changed_line_marks_the_tokens_it_changed() {
        // A substituted operand.
        assert_eq!(
            marked(
                Level::L1,
                "  0x10  v4:64 = add v1, v2",
                "  0x10  v4:64 = add v1, 0x8:64"
            ),
            (vec!["v2"], vec!["0x8:64"])
        );
        // An inserted sub-expression: one run, its comma before it.
        assert_eq!(
            marked(
                Level::L2,
                "    s5: v1 = add(v2, v3)",
                "    s5: v1 = add(mul(v2, 0x4:64), v3)"
            ),
            (vec![], vec!["mul(", ", 0x4:64)"])
        );
        // A decision merged with another: the old one is the first, whole,
        // the second one run (not the old's tail paired with the second).
        assert_eq!(
            marked(
                Level::L2,
                "    s55: if eq(f(v388), 0x0:64) {",
                "    s55: if and-then(eq(f(v388), 0x0:64), eq(f(v480), 0x0:64)) {"
            ),
            (vec![], vec!["and-then(", "), eq(f(v480), 0x0:64)"])
        );
        // A renamed value, everywhere it is.
        assert_eq!(
            marked(
                Level::L2,
                "    s7: v3 = load(v3)  ; %v12",
                "    s7: v8 = load(v8)  ; %v12"
            ),
            (vec!["v3", "v3"], vec!["v8", "v8"])
        );
        // A changed provenance: only its new value.
        assert_eq!(
            marked(
                Level::L2,
                "    s7: v3 = v1  ; %v12",
                "    s7: v3 = v1  ; %v12, %v14"
            ),
            (vec![], vec![", %v14"])
        );
        // Identical lines: nothing.
        assert_eq!(
            changed_tokens(Level::L1, "  jump b1()", "  jump b1()"),
            super::TokenDiff::default()
        );
        // A line entirely different: each whole, not its scattered
        // coincidences (`v1`, the commas).
        assert_eq!(
            marked(
                Level::L1,
                "  branch v1, b1(), b2()",
                "  0x13  v9:1 = eq v1, 0x0:64"
            ),
            (
                vec!["branch v1, b1(), b2()"],
                vec!["0x13  v9:1 = eq v1, 0x0:64"]
            )
        );
    }

    #[test]
    fn marks_cut_the_runs_by_role() {
        let text = "  v4:64 = add v1, v2";
        let runs = marked_roles(Level::L1, text, &[10..13, 18..20]);
        let on: Vec<(&str, Role)> = runs
            .iter()
            .filter(|(_, _, on)| *on)
            .map(|(range, role, _)| (&text[range.clone()], *role))
            .collect();
        assert_eq!(on, [("add", Role::Operation), ("v2", Role::Value)]);
        // The runs cover the line, in order.
        assert_eq!(runs.first().map(|r| r.0.start), Some(0));
        assert_eq!(runs.last().map(|r| r.0.end), Some(text.len()));
        assert!(runs.windows(2).all(|w| w[0].0.end == w[1].0.start));
        // A mark across tokens: each piece marked.
        let runs = marked_roles(Level::L1, text, std::slice::from_ref(&(2..7)));
        assert_eq!(
            runs.iter()
                .filter(|r| r.2)
                .map(|r| r.0.clone())
                .collect::<Vec<_>>(),
            [2..4, 4..7]
        );
    }

    fn of(level: Level, text: &str) -> Vec<(&str, Role)> {
        roles(level, text)
            .into_iter()
            .filter(|(_, role)| *role != Role::Plain)
            .map(|(range, role)| (&text[range], role))
            .collect()
    }

    #[test]
    fn tokens_take_their_roles() {
        assert_eq!(
            of(Level::L1, "  0x401004  v31:8 = load v28, v30, 1"),
            [
                ("0x401004", Role::Address),
                ("v31", Role::Value),
                (":8", Role::Type),
                ("=", Role::Punctuation),
                ("load", Role::Operation),
                ("v28", Role::Value),
                (",", Role::Punctuation),
                ("v30", Role::Value),
                (",", Role::Punctuation),
                ("1", Role::Number),
            ]
        );
        assert_eq!(
            of(Level::L1, "  branch v32, b2(v30), b3()")[..3],
            [
                ("branch", Role::Operation),
                ("v32", Role::Value),
                (",", Role::Punctuation),
            ]
        );
        assert_eq!(
            of(Level::L2, "    s5: v1 = add-carry(v1, 0x1:32)  ; %v12, ^b3"),
            [
                ("s5", Role::Node),
                (":", Role::Punctuation),
                ("v1", Role::Variable),
                ("=", Role::Punctuation),
                ("add-carry", Role::Operation),
                ("(", Role::Punctuation),
                ("v1", Role::Variable),
                (",", Role::Punctuation),
                ("0x1", Role::Number),
                (":32", Role::Type),
                (")", Role::Punctuation),
                ("  ; %v12, ^b3", Role::Comment),
            ]
        );
        assert_eq!(
            of(Level::L2, "  var v3 local int32 \"n\" deduced [%v12]"),
            [
                ("var", Role::Keyword),
                ("v3", Role::Variable),
                ("local", Role::Keyword),
                ("int32", Role::Type),
                ("\"n\"", Role::String),
                ("deduced", Role::Keyword),
                ("[", Role::Punctuation),
                ("%v12", Role::Value),
                ("]", Role::Punctuation),
            ]
        );
        assert_eq!(
            of(Level::Machine, "0x1004  mov rax, qword ptr [rbp-0x8]"),
            [
                ("0x1004", Role::Address),
                ("mov", Role::Mnemonic),
                ("rax", Role::Register),
                (",", Role::Punctuation),
                ("[", Role::Punctuation),
                ("rbp", Role::Register),
                ("-", Role::Punctuation),
                ("0x8", Role::Number),
                ("]", Role::Punctuation),
            ]
        );
        assert_eq!(
            of(Level::C, "    while (count(a1) != 0) { /* x */"),
            [
                ("while", Role::Keyword),
                ("(", Role::Punctuation),
                ("count", Role::Function),
                ("(", Role::Punctuation),
                (")", Role::Punctuation),
                ("!=", Role::Punctuation),
                ("0", Role::Number),
                (")", Role::Punctuation),
                ("{", Role::Punctuation),
                ("/* x */", Role::Comment),
            ]
        );
    }
}
