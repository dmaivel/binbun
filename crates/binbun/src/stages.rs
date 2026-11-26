//! One function through every stage of decompilation, for an IR viewer
//! and as a debugging tool: [`stages`].
//!
//! The stages, in order ([`Stage::name`]):
//!
//! 1. `machine`: the function's instructions, block by block, as its
//!    decoder prints them;
//! 2. `lifting`: L1 as built ([`binbun_ssa::text::print`]);
//! 3. L1 after each L1 pass that changed it (`assume-canonical`,
//!    `fold-branches`, `fold-implied-branches`; in the reading view then
//!    `assume-dereferenced-canonical` and `fold-branches` again);
//! 4. `lowering`: L2 as lowered ([`binbun_ast::text::print`]);
//! 5. L2 after each L2 pass that changed it, in the pass manager's order
//!    ([`l2_passes`](crate::decompile::l2_passes));
//! 6. `naming`: L2 with its variables named, if naming changed it;
//! 7. `c`: the C, as `binbun decompile` prints it.
//!
//! Each stage's lines say which instructions they stand for (L1 lines
//! carry their addresses, L2's come through provenance, the C's through
//! its tokens' nodes), what they define (L1 values, L2 statements and
//! variables) and, within a level, how they differ from the stage before
//! ([`diff`]: by identity where a line has one, by text otherwise), with
//! the lines removed. Where a pass records why it did something (the
//! loop rules, the switches, short-circuits, proved first tests, catch
//! dispatch's floors, the L1 passes' folded branches) the lines it
//! touched carry the reason.
//!
//! The snapshots come from the pass managers' recording hook
//! ([`binbun_semantics::core::pass::Manager::record`]), which normal decompilation
//! leaves off: recording costs nothing there and changes no output (the
//! `c` stage is the C [`Database::decompile`] prints).

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt::Write as _;
use std::ops::Range;
use std::sync::atomic::{AtomicBool, Ordering};

use binbun_ast::ir::{Expr, ExprId, Function as Ast, Logical, Node, Origin, Stmt, StmtId, VarId};
use binbun_ast::text::print as print_l2;
use binbun_decompile::names;
use binbun_decompile::pass::{Feeds, L2Env};
use binbun_decompile::structure::Rotated;
use binbun_print::c::function as print_c;
use binbun_print::layout::{Span, render_spans};
use binbun_print::style::{IntSpelling, Naming, Placement, Spacing, Style};
use binbun_semantics::core::pass::{PassStats, Refusal};
use binbun_semantics::ir::Declarations;
use binbun_ssa::ir::{Definition, Function, Value};
use binbun_ssa::text::print as print_l1;

use crate::Database;
use crate::cfg::FunctionId;
use crate::decompile::{
    Assumed, Passed, View, exact_l1, l2_passes_recorded, lift_l1, lower_function, reading_comment,
    reading_l1_recorded,
};
use crate::lift::disassemble;

/// How a function's stages are made.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Options {
    /// Which view: the reading view's stages start from its assumed L1.
    pub view: View,
    /// The passes not run, by name.
    pub disabled: Vec<String>,
    /// The style preset the C is laid out in.
    pub style: String,
    /// How the C spells integer types ([`crate::decompile::Options::types`]).
    pub types: IntSpelling,
    /// Where the C declares locals.
    pub declarations: Placement,
    /// How the C names variables with no name of their own
    /// ([`crate::decompile::Options::names`]).
    pub names: Naming,
    /// Whether empty lines part a block's statements
    /// ([`crate::decompile::Options::spacing`]).
    pub spacing: Spacing,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            view: View::Exact,
            disabled: Vec::new(),
            style: "kr".to_owned(),
            types: IntSpelling::Fixed,
            declarations: Placement::Scoped,
            names: Naming::Numbered,
            spacing: Spacing::Paragraphs,
        }
    }
}

/// What a stage's text is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Level {
    /// Machine instructions.
    Machine,
    /// L1 (SSA over L0).
    L1,
    /// L2 (the structured AST).
    L2,
    /// The C.
    C,
}

/// What a line is, by identity, within its level: what the same line of
/// another stage of the level has ([`diff`], [`Stages::follow`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Key {
    /// The function's header line.
    Header,
    /// A machine instruction, by address.
    Instruction(u64),
    /// An L1 block's header, by block number.
    Block(u32),
    /// An L1 instruction, by number.
    Inst(u32),
    /// An L1 block's terminator, by block number.
    Terminator(u32),
    /// An L2 struct or union, by type number.
    Type(u32),
    /// An L2 variable, by number.
    Var(u32),
    /// The n-th line of an L2 function's `va_start` facts.
    Facts(u32),
    /// L2's opening brace of the body.
    Open,
    /// L2's closing brace of the body.
    Close,
    /// A line of an L2 statement.
    Stmt {
        /// The statement.
        id: u32,
        /// Which of its lines.
        part: Part,
        /// Its number among the statement's lines of that part.
        ordinal: u32,
    },
}

/// Which line of an L2 statement.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Part {
    /// The line with its number (`s5: …`).
    First,
    /// A closing brace (`}`).
    Close,
    /// `} else {`.
    Else,
    /// A `do`-`while`'s `} while e`.
    While,
    /// A switch arm's `case …:`.
    Case,
    /// A switch arm's `default:`.
    Default,
    /// A switch arm's `fallthrough`.
    Fallthrough,
    /// A `Try`'s handler (`} catch … {`, `} landing … {`, …).
    Handler,
}

/// Something a line defines.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Item {
    /// An L1 value.
    Value(Value),
    /// An L2 node.
    Node(Node),
    /// An L2 variable.
    Var(VarId),
}

/// How a line differs from the stage before.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Change {
    /// It is new.
    Added,
    /// The same line (by identity) reads differently.
    Changed,
}

/// One line of a stage.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Line {
    /// Its text in [`Stage::text`], without the newline.
    pub range: Range<usize>,
    /// What it is, if it has an identity.
    pub key: Option<Key>,
    /// The instructions it stands for, by address, ascending.
    pub addresses: Vec<u64>,
    /// What it defines.
    pub defines: Vec<Item>,
    /// How it differs from the stage before (`None`: as it was, or the
    /// stage is not compared).
    pub change: Option<Change>,
    /// The line of the stage before it is (`None`: added, or the stage
    /// is not compared).
    pub was: Option<usize>,
    /// Why the stage's pass made it what it is, where the pass says.
    pub reason: Option<String>,
}

/// A line of the stage before that is not in a stage.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Removed {
    /// The line of the stage it was before (the stage's line count: at
    /// its end).
    pub before: usize,
    /// Its text.
    pub text: String,
    /// What it was.
    pub key: Option<Key>,
    /// The instructions it stood for.
    pub addresses: Vec<u64>,
}

/// One stage of a function.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Stage {
    /// Its name: `machine`, `lifting`, the pass that made it, `lowering`,
    /// `naming` or `c`.
    pub name: &'static str,
    /// Its name, numbered (`sink#2`) where a pass made more than one.
    pub label: String,
    /// What its text is.
    pub level: Level,
    /// The text.
    pub text: String,
    /// Its lines.
    pub lines: Vec<Line>,
    /// The lines of the stage before that it no longer has.
    pub removed: Vec<Removed>,
    /// Whether it is compared with the stage before (the first stage of
    /// each level is not).
    pub compared: bool,
}

impl Stage {
    /// Line `index`'s text.
    pub fn line_text(&self, index: usize) -> &str {
        self.lines
            .get(index)
            .and_then(|line| self.text.get(line.range.clone()))
            .unwrap_or_default()
    }

    /// How many of its lines are added and changed, and how many were
    /// removed.
    pub fn counts(&self) -> (usize, usize, usize) {
        let count = |change| {
            self.lines
                .iter()
                .filter(|line| line.change == Some(change))
                .count()
        };
        (
            count(Change::Added),
            count(Change::Changed),
            self.removed.len(),
        )
    }

    /// The line standing for the instruction at `address`: the first line
    /// of code (not a declaration: L2's header, types and variables) that
    /// names it, else the first line that does, else the code line before
    /// it in address order (the one whose highest address is the closest
    /// below).
    pub fn line_at(&self, address: u64) -> Option<usize> {
        let names = |line: &Line| line.addresses.binary_search(&address).is_ok();
        if let Some(found) = self.lines.iter().position(|line| code(line) && names(line)) {
            return Some(found);
        }
        if let Some(found) = self.lines.iter().position(names) {
            return Some(found);
        }
        self.lines
            .iter()
            .enumerate()
            .filter(|(_, line)| code(line))
            .filter_map(|(index, line)| {
                let below = line.addresses.iter().rev().find(|&&a| a < address)?;
                Some((*below, index))
            })
            .max_by_key(|&(below, index)| (below, core::cmp::Reverse(index)))
            .map(|(_, index)| index)
    }
}

/// A pass's counts and refusals.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PassCount {
    /// The pass.
    pub name: &'static str,
    /// What it runs on.
    pub level: Level,
    /// Its counts.
    pub stats: PassStats,
    /// Why it refused, each time it did.
    pub refusals: Vec<String>,
}

/// A function through every stage ([`stages`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Stages {
    /// The function's entry.
    pub entry: u64,
    /// The view.
    pub view: View,
    /// The stages, in order.
    pub stages: Vec<Stage>,
    /// Each pass's counts, the L1 passes' then the L2 passes'.
    pub passes: Vec<PassCount>,
}

impl Stages {
    /// The stage labelled `wanted`, else the first named so.
    pub fn find(&self, wanted: &str) -> Option<usize> {
        self.stages
            .iter()
            .position(|stage| stage.label == wanted)
            .or_else(|| self.stages.iter().position(|stage| stage.name == wanted))
    }

    /// The counts of the pass that made stage `index`, if a pass did.
    pub fn pass(&self, index: usize) -> Option<&PassCount> {
        let stage = self.stages.get(index)?;
        self.passes.iter().find(|pass| pass.name == stage.name)
    }

    /// The line of stage `to` standing for line `line` of stage `from`
    /// (a cursor kept through the stages): the same line by identity
    /// within a level, else one defining the same value or node (L2 and
    /// the C share their nodes), else the first standing for one of its
    /// instructions ([`Stage::line_at`] of its lowest address last).
    pub fn follow(&self, from: usize, line: usize, to: usize) -> Option<usize> {
        let source = self.stages.get(from)?;
        let target = self.stages.get(to)?;
        let at = source.lines.get(line)?;
        if source.level == target.level
            && let Some(key) = at.key
            && let Some(found) = target.lines.iter().position(|l| l.key == Some(key))
        {
            return Some(found);
        }
        if let Some(found) = at.defines.iter().find_map(|item| {
            target
                .lines
                .iter()
                .position(|l| l.defines.contains(item) && l.key.is_none_or(first_part))
        }) {
            return Some(found);
        }
        if let Some(found) = at.addresses.iter().find_map(|address| {
            target
                .lines
                .iter()
                .position(|l| l.addresses.binary_search(address).is_ok())
        }) {
            return Some(found);
        }
        at.addresses.first().and_then(|&a| target.line_at(a))
    }
}

/// Whether a key is a statement's first line (or not a statement's).
fn first_part(key: Key) -> bool {
    !matches!(key, Key::Stmt { part, .. } if part != Part::First)
}

/// Whether `line` is code (not one of L2's declarations).
fn code(line: &Line) -> bool {
    !matches!(
        line.key,
        Some(Key::Header | Key::Type(_) | Key::Var(_) | Key::Facts(_))
    )
}

/// Function `id` of `database` through every stage (see the module
/// documentation) under `options`.
///
/// # Errors
///
/// The function is not lifted, a pass leaves it failing its verifier,
/// lowering fails, or the C cannot be printed.
pub fn stages(
    database: &Database<'_>,
    id: FunctionId,
    options: &Options,
) -> Result<Stages, String> {
    stages_cancellable(database, id, options, &AtomicBool::new(false))
        .unwrap_or_else(|| Err("cancelled".to_owned()))
}

/// [`stages`], stopping between its steps once `cancel` is set: `None`
/// then.
pub fn stages_cancellable(
    database: &Database<'_>,
    id: FunctionId,
    options: &Options,
    cancel: &AtomicBool,
) -> Option<Result<Stages, String>> {
    Maker {
        database,
        cancel,
        options,
    }
    .make(id)
    .transpose()
}

struct Maker<'d, 'a> {
    database: &'d Database<'a>,
    cancel: &'d AtomicBool,
    options: &'d Options,
}

/// A stage before its lines are compared.
struct Raw {
    name: &'static str,
    level: Level,
    text: String,
    lines: Vec<Line>,
}

impl Maker<'_, '_> {
    fn cancelled(&self) -> bool {
        self.cancel.load(Ordering::Relaxed)
    }

    /// The stages, `Ok(None)` if cancelled.
    #[allow(
        clippy::too_many_lines,
        reason = "the pipeline's steps in order, each a few lines"
    )]
    fn make(&self, id: FunctionId) -> Result<Option<Stages>, String> {
        let database = self.database;
        let image = database.image();
        let disabled = &self.options.disabled;
        let declarations = database
            .declarations()
            .ok_or_else(|| "the image's code is not lifted".to_owned())?;
        let style = Style::preset(&self.options.style)
            .ok_or_else(|| format!("no style preset {:?}", self.options.style))?
            .with_int_spelling(self.options.types)
            .with_declarations(self.options.declarations)
            .with_naming(self.options.names)
            .with_spacing(self.options.spacing);
        let function = database
            .function(id)
            .ok_or_else(|| "not a function of the program".to_owned())?;
        let entry = function.entry;
        let mut raw = vec![self.machine(id)];
        let (_, interfaces) = database.prepare_in(id, self.options.view, disabled);
        if self.cancelled() {
            return Ok(None);
        }
        let lifted = lift_l1(
            image,
            database.program(),
            id,
            database.summaries(),
            disabled,
        )?;
        raw.push(l1_stage("lifting", &lifted, declarations));
        let (mut prepared, recorded) = exact_l1(image, lifted, disabled, true)?;
        let mut pass_counts = counts(Level::L1, &prepared.passes, &recorded.refusals);
        raw.extend(
            recorded
                .stages
                .iter()
                .map(|(name, l1)| l1_stage(name, l1, declarations)),
        );
        let mut assumed = Assumed::default();
        if self.options.view == View::Reading {
            let (reading, folded, recorded) =
                reading_l1_recorded(image, &prepared, disabled, true)?;
            let exact = prepared.passes.len();
            pass_counts.extend(counts(
                Level::L1,
                reading.passes.get(exact..).unwrap_or_default(),
                &recorded.refusals,
            ));
            raw.extend(
                recorded
                    .stages
                    .iter()
                    .map(|(name, l1)| l1_stage(name, l1, declarations)),
            );
            prepared = reading;
            assumed = folded;
        }
        if self.cancelled() {
            return Ok(None);
        }
        let prototypes = database.prototypes();
        let (mut l2, _, _) =
            lower_function(image, &prepared, &interfaces, &prototypes, database.data())?;
        l2.name = database.data_name(entry);
        let l1 = &prepared.l1;
        let lowered = l2.clone();
        if self.cancelled() {
            return Ok(None);
        }
        let feeds = Feeds::new(l1);
        let env = L2Env {
            declarations,
            exceptions: database.exceptions(),
            feeds: Some(&feeds),
        };
        let mut passed = l2_passes_recorded(&mut l2, &env, disabled, true)?;
        let mut lowering = l2_stage("lowering", &lowered, l1, declarations);
        floors_l2(&mut lowering, &passed);
        raw.push(lowering);
        drop(lowered);
        let recorded: Vec<(&'static str, Ast)> = passed.manager.recorded();
        let refusals = passed.manager.refusals().to_vec();
        pass_counts.extend(counts(
            Level::L2,
            &passed.manager.stats().collect::<Vec<_>>(),
            &refusals,
        ));
        let mut l2_stages: Vec<(&'static str, &Ast)> =
            recorded.iter().map(|(name, ast)| (*name, ast)).collect();
        let before = l2.clone();
        names::name(&mut l2, &prototypes);
        if l2 != before {
            l2_stages.push(("naming", &l2));
        }
        for &(name, ast) in &l2_stages {
            if self.cancelled() {
                return Ok(None);
            }
            let mut stage = l2_stage(name, ast, l1, declarations);
            reasons_l2(&mut stage, ast, &passed);
            floors_l2(&mut stage, &passed);
            raw.push(stage);
        }
        let printed = print_c(
            &l2,
            declarations,
            &style,
            database.data(),
            self.options.view.opaque(),
        )
        .map_err(|error| format!("cannot print: {error}"))?;
        let (text, spans) = render_spans(&printed.document, &style);
        let prefix = if self.options.view == View::Reading && !assumed.is_empty() {
            reading_comment(&assumed)
        } else {
            String::new()
        };
        raw.push(c_stage(&prefix, &text, &spans, &l2, l1));
        Ok(Some(Stages {
            entry,
            view: self.options.view,
            stages: compare(raw),
            passes: pass_counts,
        }))
    }

    /// The `machine` stage: function `id`'s instructions, block by block
    /// in address order.
    fn machine(&self, id: FunctionId) -> Raw {
        let database = self.database;
        let program = database.program();
        let mut blocks: Vec<(u64, u64)> = database
            .function(id)
            .map(|function| {
                function
                    .blocks
                    .iter()
                    .filter_map(|&block| program.blocks.get(block))
                    .map(|block| (block.start, block.end))
                    .collect()
            })
            .unwrap_or_default();
        blocks.sort_unstable();
        blocks.dedup();
        let mut text = String::new();
        let mut lines = Vec::new();
        for (start, end) in blocks {
            let mut at = start;
            while at < end {
                let begin = text.len();
                let next = match disassemble(database.image(), at) {
                    Ok((instruction, next)) => {
                        let _ = write!(text, "{at:#x}  {instruction}");
                        next
                    }
                    Err(error) => {
                        let _ = write!(text, "{at:#x}  ?? {error}");
                        end
                    }
                };
                lines.push(Line {
                    range: begin..text.len(),
                    key: Some(Key::Instruction(at)),
                    addresses: vec![at],
                    defines: Vec::new(),
                    change: None,
                    was: None,
                    reason: None,
                });
                text.push('\n');
                at = next.max(at.saturating_add(1));
            }
        }
        Raw {
            name: "machine",
            level: Level::Machine,
            text,
            lines,
        }
    }
}

/// Pass counts of `level` from `stats`, with their `refusals`.
fn counts(
    level: Level,
    stats: &[(&'static str, PassStats)],
    refusals: &[(&'static str, Refusal)],
) -> Vec<PassCount> {
    stats
        .iter()
        .map(|&(name, stats)| PassCount {
            name,
            level,
            stats,
            refusals: refusals
                .iter()
                .filter(|(pass, _)| *pass == name)
                .map(|(_, refusal)| refusal.to_string())
                .collect(),
        })
        .collect()
}

/// The line `range` of a stage's text, `key` its identity, without
/// metadata.
fn bare(range: Range<usize>, key: Option<Key>) -> Line {
    Line {
        range,
        key,
        addresses: Vec::new(),
        defines: Vec::new(),
        change: None,
        was: None,
        reason: None,
    }
}

/// The ranges of `text`'s lines, without their newlines.
fn ranges(text: &str) -> Vec<Range<usize>> {
    let mut out = Vec::new();
    let mut start = 0;
    for piece in text.split_inclusive('\n') {
        let end = start + piece.len();
        out.push(start..end - usize::from(piece.ends_with('\n')));
        start = end;
    }
    out
}

/// The address of the instruction defining `value` of `l1` (a block
/// parameter: the block's).
fn value_address(l1: &Function, value: Value) -> Option<u64> {
    match l1.value(value)?.definition {
        Definition::Result { inst, .. } => l1.inst(inst).map(|inst| inst.address),
        Definition::Parameter { block, .. } => l1.block(block).map(|block| block.address),
    }
}

/// The addresses `origins` name (of instructions, and of L1 values'
/// definitions in `l1`), into `out`.
fn origin_addresses(l1: &Function, origins: &[Origin], out: &mut Vec<u64>) {
    for origin in origins {
        match *origin {
            Origin::Value(value) => out.extend(value_address(l1, value)),
            Origin::Instruction(address) => out.push(address),
            Origin::Register(_)
            | Origin::Held(_)
            | Origin::Slot(_)
            | Origin::Block(_)
            | Origin::Absorbed(_)
            | Origin::Proved => {}
        }
    }
}

/// The addresses of expressions `roots` of `ast` and everything they
/// read, into `out`.
fn expr_addresses(ast: &Ast, l1: &Function, roots: Vec<ExprId>, out: &mut Vec<u64>) {
    let mut work = roots;
    let mut seen = BTreeSet::new();
    while let Some(id) = work.pop() {
        if !seen.insert(id) {
            continue;
        }
        origin_addresses(l1, ast.provenance.expr(id), out);
        if let Some(expr) = ast.expr(id) {
            work.extend(expr.operands(ast));
        }
    }
}

/// An L1 stage: `function`'s text, a line per block header, instruction
/// and terminator.
fn l1_stage(name: &'static str, function: &Function, declarations: &Declarations) -> Raw {
    let text = print_l1(function, declarations);
    let ranges = ranges(&text);
    let mut lines = Vec::with_capacity(ranges.len());
    let mut ranges = ranges.into_iter();
    let mut next = |key, addresses: Vec<u64>, defines: Vec<Item>| {
        if let Some(range) = ranges.next() {
            lines.push(Line {
                addresses,
                defines,
                ..bare(range, Some(key))
            });
        }
    };
    next(Key::Header, Vec::new(), Vec::new());
    for (index, block) in (0u32..).zip(&function.blocks) {
        next(
            Key::Block(index),
            vec![block.address],
            block.parameters.iter().copied().map(Item::Value).collect(),
        );
        let mut last = block.address;
        for &inst in &block.insts {
            let (addresses, defines) = function.inst(inst).map_or_else(Default::default, |i| {
                last = i.address;
                (
                    vec![i.address],
                    i.results.iter().copied().map(Item::Value).collect(),
                )
            });
            next(Key::Inst(inst.0), addresses, defines);
        }
        next(Key::Terminator(index), vec![last], Vec::new());
    }
    Raw {
        name,
        level: Level::L1,
        text,
        lines,
    }
}

/// Whether statement `stmt` holds blocks (its lines end with a brace).
fn compound(stmt: &Stmt) -> bool {
    matches!(
        stmt,
        Stmt::If { .. }
            | Stmt::While { .. }
            | Stmt::DoWhile { .. }
            | Stmt::For { .. }
            | Stmt::Switch { .. }
            | Stmt::Try { .. }
    )
}

/// The statement number `s5: ` at the start of `text`, if one.
fn statement_number(text: &str) -> Option<u32> {
    let rest = text.strip_prefix('s')?;
    let digits = rest.find(|c: char| !c.is_ascii_digit())?;
    rest.get(digits..)?.starts_with(": ").then_some(())?;
    rest.get(..digits)?.parse().ok()
}

/// The number after `prefix` at the start of `text` (`  var v12 …`).
fn numbered(text: &str, prefix: &str) -> Option<u32> {
    let rest = text.strip_prefix(prefix)?;
    let digits = rest
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(rest.len());
    rest.get(..digits)?.parse().ok()
}

/// Which continuation line of a statement `trimmed` is.
fn part(trimmed: &str) -> Part {
    if trimmed == "}" {
        Part::Close
    } else if trimmed == "} else {" {
        Part::Else
    } else if trimmed.starts_with("} while ") {
        Part::While
    } else if trimmed.starts_with("case ") {
        Part::Case
    } else if trimmed.starts_with("default") {
        Part::Default
    } else if trimmed == "fallthrough" {
        Part::Fallthrough
    } else {
        Part::Handler
    }
}

/// An L2 stage: `ast`'s text, each line's statement or variable from the
/// text's numbers (`s5:`, `var v3`) and the statements open around it.
fn l2_stage(name: &'static str, ast: &Ast, l1: &Function, declarations: &Declarations) -> Raw {
    let text = print_l2(ast, declarations);
    let mut lines = Vec::new();
    let mut body = false;
    let mut facts = 0;
    let mut open: Vec<u32> = Vec::new();
    let mut ordinals: BTreeMap<(u32, Part), u32> = BTreeMap::new();
    for range in ranges(&text) {
        let line = text.get(range.clone()).unwrap_or_default();
        let trimmed = line.trim_start();
        let mut addresses = Vec::new();
        let mut defines = Vec::new();
        let key = if !body {
            if line.starts_with("function ") {
                Key::Header
            } else if let Some(n) = numbered(line, "  type t") {
                Key::Type(n)
            } else if let Some(n) = numbered(line, "  var v") {
                let var = VarId(n);
                if let Some(variable) = ast.var(var) {
                    origin_addresses(l1, &variable.origins, &mut addresses);
                }
                defines.push(Item::Var(var));
                Key::Var(n)
            } else if line == "{" {
                body = true;
                Key::Open
            } else {
                facts += 1;
                Key::Facts(facts - 1)
            }
        } else if let Some(n) = statement_number(trimmed) {
            let id = StmtId(n);
            if let Some(stmt) = ast.stmt(id) {
                statement_line(ast, l1, id, stmt, &mut addresses, &mut defines);
                if compound(stmt) {
                    open.push(n);
                }
            }
            Key::Stmt {
                id: n,
                part: Part::First,
                ordinal: 0,
            }
        } else if let Some(&id) = open.last() {
            let part = part(trimmed);
            if matches!(part, Part::Close | Part::While) {
                open.pop();
            }
            if part == Part::While
                && let Some(&Stmt::DoWhile { condition, .. }) = ast.stmt(StmtId(id))
            {
                expr_addresses(ast, l1, vec![condition], &mut addresses);
            }
            let ordinal = ordinals.entry((id, part)).or_default();
            *ordinal += 1;
            Key::Stmt {
                id,
                part,
                ordinal: *ordinal - 1,
            }
        } else {
            Key::Close
        };
        addresses.sort_unstable();
        addresses.dedup();
        lines.push(Line {
            addresses,
            defines,
            ..bare(range, Some(key))
        });
    }
    Raw {
        name,
        level: Level::L2,
        text,
        lines,
    }
}

/// What statement `id` (`stmt`) of `ast` stands for on its first line:
/// its provenance and its expressions' (a `do`-`while`'s condition is on
/// its last line; a `for`'s `init` and `step` are on its first).
fn statement_line(
    ast: &Ast,
    l1: &Function,
    id: StmtId,
    stmt: &Stmt,
    addresses: &mut Vec<u64>,
    defines: &mut Vec<Item>,
) {
    let mut ids = vec![id];
    if let Stmt::For { init, step, .. } = stmt {
        ids.extend(init.iter().chain(step));
    }
    for id in ids {
        origin_addresses(l1, ast.provenance.stmt(id), addresses);
        if let Some(stmt) = ast.stmt(id)
            && !matches!(stmt, Stmt::DoWhile { .. })
        {
            expr_addresses(ast, l1, stmt.roots(), addresses);
        }
        defines.push(Item::Node(Node::Stmt(id)));
    }
}

/// The C stage: `prefix` then `text`, each line's nodes from `spans`
/// (of `ast`, lowered from `l1`).
fn c_stage(prefix: &str, text: &str, spans: &[Span], ast: &Ast, l1: &Function) -> Raw {
    let full = format!("{prefix}{text}");
    let ranges = ranges(&full);
    let mut lines: Vec<Line> = ranges
        .iter()
        .map(|range| bare(range.clone(), None))
        .collect();
    let starts: Vec<usize> = ranges.iter().map(|range| range.start).collect();
    for span in spans {
        let Some(node) = span.node else {
            continue;
        };
        let at = prefix.len() + span.range.start;
        let index = starts
            .partition_point(|&start| start <= at)
            .saturating_sub(1);
        let Some(line) = lines.get_mut(index) else {
            continue;
        };
        match node {
            Node::Stmt(id) => {
                origin_addresses(l1, ast.provenance.stmt(id), &mut line.addresses);
                if !line.defines.contains(&Item::Node(node)) {
                    line.defines.push(Item::Node(node));
                }
            }
            Node::Expr(id) => origin_addresses(l1, ast.provenance.expr(id), &mut line.addresses),
            Node::Var(var) => {
                if let Some(variable) = ast.var(var) {
                    origin_addresses(l1, &variable.origins, &mut line.addresses);
                }
                if !line.defines.contains(&Item::Var(var)) {
                    line.defines.push(Item::Var(var));
                }
            }
            Node::Type(_) => {}
        }
    }
    for line in &mut lines {
        line.addresses.sort_unstable();
        line.addresses.dedup();
    }
    Raw {
        name: "c",
        level: Level::C,
        text: full,
        lines,
    }
}

/// The L2 passes' reasons on the lines of `stage` (made by its pass, of
/// `ast`), from what `passed` recorded and what the pass leaves in the
/// function.
fn reasons_l2(stage: &mut Raw, ast: &Ast, passed: &Passed<'_>) {
    for line in &mut stage.lines {
        let Some(Key::Stmt {
            id,
            part: Part::First,
            ..
        }) = line.key
        else {
            continue;
        };
        let id = StmtId(id);
        let Some(stmt) = ast.stmt(id) else {
            continue;
        };
        line.reason = match stage.name {
            "loops" => loop_reason(passed, id),
            "switches" => {
                if let Stmt::Switch { arms, .. } = stmt {
                    Some(format!(
                        "switches: a chain of {} comparisons of one value",
                        arms.iter().map(|arm| arm.values.len()).sum::<usize>()
                    ))
                } else {
                    None
                }
            }
            "short-circuit" => {
                if let Stmt::If { condition, .. } | Stmt::While { condition, .. } = stmt {
                    match ast.expr(*condition) {
                        Some(Expr::Logical(Logical::And, ..)) => {
                            Some("short-circuit: an inner decision merged with &&".to_owned())
                        }
                        Some(Expr::Logical(Logical::Or, ..)) => {
                            Some("short-circuit: an inner decision merged with ||".to_owned())
                        }
                        _ => None,
                    }
                } else {
                    None
                }
            }
            _ => None,
        };
        if line.reason.is_none() && ast.provenance.stmt(id).contains(&Origin::Proved) {
            line.reason = Some(
                "its first test always holds on entry (range analysis): entering it decides nothing"
                    .to_owned(),
            );
        }
    }
}

/// Why the loop rules made statement `id` what it is.
fn loop_reason(passed: &Passed<'_>, id: StmtId) -> Option<String> {
    let rule = |rule: u8| -> String {
        let what = match rule {
            1 => "if and do-while on one condition as while".to_owned(),
            2 => "for formation".to_owned(),
            3 => "exit condition as the counted loop's test".to_owned(),
            4 => match passed.outcomes.get(&id) {
                Some(Rotated::Guarded) => "counted loop, its guard as the first test".to_owned(),
                _ => "counted loop, the first test proved".to_owned(),
            },
            _ => "the first test implied by the code before".to_owned(),
        };
        format!("loop rule {rule}: {what}")
    };
    match passed.rules.get(&id) {
        Some(rules) => Some(
            rules
                .iter()
                .map(|&number| rule(number))
                .collect::<Vec<_>>()
                .join("; "),
        ),
        None => match passed.outcomes.get(&id) {
            Some(Rotated::Left(refused)) => Some(format!("loop rules: still do-while ({refused})")),
            _ => None,
        },
    }
}

/// Catch dispatch's floors on the `landing` handlers of `stage`.
fn floors_l2(stage: &mut Raw, passed: &Passed<'_>) {
    for line in &mut stage.lines {
        if !matches!(
            line.key,
            Some(Key::Stmt {
                part: Part::Handler,
                ..
            })
        ) {
            continue;
        }
        let text = stage.text.get(line.range.clone()).unwrap_or_default();
        let pad = text
            .trim_start()
            .strip_prefix("} landing 0x")
            .and_then(|rest| rest.split_whitespace().next())
            .and_then(|hex| u64::from_str_radix(hex, 16).ok());
        if let Some(floor) = pad.and_then(|pad| passed.floors.get(&pad)) {
            line.reason = Some(format!("catch dispatch left it a landing pad: {floor}"));
        }
    }
}

/// Why each L1 pass changed a terminator.
fn l1_reason(pass: &str) -> Option<&'static str> {
    match pass {
        "assume-canonical" => Some(
            "under the ABI's assumption that the stack and return address are canonical, the check cannot fail",
        ),
        "assume-dereferenced-canonical" => Some(
            "the reading view's assumption: the address dereferenced is canonical, the check's trap is gone",
        ),
        "assume-aligned-stack" => Some(
            "the reading view's assumption: the stack pointer is aligned at entry as the ABI says, the check's trap is gone",
        ),
        "assume-authenticated-returns" => Some(
            "the reading view's assumption: the signed return address authenticates, the check's trap is gone",
        ),
        "assume-default-float-controls" => Some(
            "the reading view's assumption: the floating-point controls are what a process starts with",
        ),
        "assume-float-results" => Some(
            "the reading view's assumption: a NaN is not told from another, a float converted to an integer is in its range",
        ),
        "assume-empty-x87-stack" => {
            Some("the reading view's assumption: the x87 stack is empty at entry, TOP 0")
        }
        "fold-branches" => Some("the condition is constant: the branch goes one way"),
        "fold-implied-branches" => {
            Some("an earlier test of the same value decides it: the branch goes one way")
        }
        _ => None,
    }
}

/// The stages, each compared with the one before within its level, and
/// labelled.
fn compare(raw: Vec<Raw>) -> Vec<Stage> {
    let mut seen: BTreeMap<&str, usize> = BTreeMap::new();
    for stage in &raw {
        *seen.entry(stage.name).or_default() += 1;
    }
    let mut numbered: BTreeMap<&str, usize> = BTreeMap::new();
    let mut out: Vec<Stage> = Vec::with_capacity(raw.len());
    for stage in raw {
        let label = if seen.get(stage.name).copied().unwrap_or(0) > 1 {
            let n = numbered.entry(stage.name).or_default();
            *n += 1;
            format!("{}#{n}", stage.name)
        } else {
            stage.name.to_owned()
        };
        let previous = out.last().filter(|before| {
            before.level == stage.level && matches!(stage.level, Level::L1 | Level::L2)
        });
        let Raw {
            name,
            level,
            text,
            mut lines,
        } = stage;
        let mut removed = Vec::new();
        let compared = previous.is_some();
        if let Some(previous) = previous {
            let old: Vec<(Option<Key>, &str)> = (0..previous.lines.len())
                .map(|index| {
                    (
                        previous.lines.get(index).and_then(|line| line.key),
                        previous.line_text(index),
                    )
                })
                .collect();
            let new: Vec<(Option<Key>, &str)> = lines
                .iter()
                .map(|line| (line.key, text.get(line.range.clone()).unwrap_or_default()))
                .collect();
            let found = diff(&old, &new);
            for ((line, change), was) in lines.iter_mut().zip(found.changes).zip(found.paired) {
                line.change = change;
                line.was = was;
                if level == Level::L1
                    && change == Some(Change::Changed)
                    && matches!(line.key, Some(Key::Terminator(_)))
                {
                    line.reason = l1_reason(name).map(str::to_owned);
                }
            }
            removed = found
                .removed
                .into_iter()
                .map(|(before, index)| {
                    let line = previous.lines.get(index);
                    Removed {
                        before,
                        text: previous.line_text(index).to_owned(),
                        key: line.and_then(|line| line.key),
                        addresses: line.map(|line| line.addresses.clone()).unwrap_or_default(),
                    }
                })
                .collect();
        }
        out.push(Stage {
            name,
            label,
            level,
            text,
            lines,
            removed,
            compared,
        });
    }
    out
}

/// How one list of lines differs from another ([`diff`]).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Diff {
    /// Each new line's change (`None`: as it was).
    pub changes: Vec<Option<Change>>,
    /// The old line each new line is (`None`: added).
    pub paired: Vec<Option<usize>>,
    /// The old lines not in the new, in order: the new line each was
    /// before (the new count: at the end) and its index among the old.
    pub removed: Vec<(usize, usize)>,
}

/// How lines `new` differ from lines `old`, each a key (its identity, if
/// it has one) and its text: a line is the old line of its key (changed
/// if its text differs), else the first unpaired old line of the same
/// text, else added; old lines paired with none are removed, each placed
/// before the new line paired with the next old line after it.
///
/// ```
/// use binbun::stages::{Change, Key, diff};
///
/// let old = [(Some(Key::Var(0)), "var v0 int32"), (None, "}"), (Some(Key::Var(1)), "var v1")];
/// let new = [(Some(Key::Var(0)), "var v0 int64"), (Some(Key::Var(2)), "var v2"), (None, "}")];
/// let diff = diff(&old, &new);
/// assert_eq!(diff.changes, [Some(Change::Changed), Some(Change::Added), None]);
/// assert_eq!(diff.removed, [(3, 2)]);
/// ```
pub fn diff(old: &[(Option<Key>, &str)], new: &[(Option<Key>, &str)]) -> Diff {
    let by_key: BTreeMap<Key, usize> = old
        .iter()
        .enumerate()
        .rev()
        .filter_map(|(index, &(key, _))| Some((key?, index)))
        .collect();
    let mut paired: Vec<Option<usize>> = vec![None; new.len()];
    let mut used = vec![false; old.len()];
    for (slot, &(key, _)) in paired.iter_mut().zip(new) {
        if let Some(&index) = key.and_then(|key| by_key.get(&key))
            && let Some(taken) = used.get_mut(index)
            && !*taken
        {
            *taken = true;
            *slot = Some(index);
        }
    }
    let mut by_text: BTreeMap<&str, VecDeque<usize>> = BTreeMap::new();
    for (index, &(_, text)) in old.iter().enumerate() {
        if !used.get(index).copied().unwrap_or(true) {
            by_text.entry(text).or_default().push_back(index);
        }
    }
    for (slot, &(_, text)) in paired.iter_mut().zip(new) {
        if slot.is_none()
            && let Some(index) = by_text.get_mut(text).and_then(VecDeque::pop_front)
        {
            if let Some(taken) = used.get_mut(index) {
                *taken = true;
            }
            *slot = Some(index);
        }
    }
    let changes = paired
        .iter()
        .zip(new)
        .map(|(slot, &(_, text))| match slot {
            None => Some(Change::Added),
            Some(index) if old.get(*index).is_some_and(|&(_, was)| was != text) => {
                Some(Change::Changed)
            }
            Some(_) => None,
        })
        .collect();
    let mut at_old: Vec<Option<usize>> = vec![None; old.len()];
    for (position, slot) in paired.iter().enumerate() {
        if let Some(cell) = slot.and_then(|index| at_old.get_mut(index)) {
            *cell = Some(position);
        }
    }
    let mut removed = Vec::new();
    let mut next = new.len();
    for (index, at) in at_old.iter().enumerate().rev() {
        match at {
            Some(position) => next = *position,
            None => removed.push((next, index)),
        }
    }
    removed.reverse();
    Diff {
        changes,
        paired,
        removed,
    }
}
