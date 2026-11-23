//! What the C pane shows of the questions binbun answers beside a
//! function's C, framework-free:
//!
//! - [`Chip`]: the verification as the toolbar's mark, and what its card
//!   says ([`Chip::card`]).
//! - [`Why`]: which variables and types rest on real but weak evidence (a
//!   dotted underline) and the card a hover opens ([`Card`]); defaults
//!   are never marked (their form, `v12`, `int32_t`, says so already).
//! - [`origin_rows`]: an origin chain as the Origin panel's rows, folded
//!   steps expandable, forks visible; or the value's uses.
//! - [`Values`]: a run's values at line ends (C) and the registers each
//!   instruction wrote (listing), the call needing a stub marked.
//! - [`scratch_state`]: an example state from the compact form (arguments
//!   by prototype, strings and string vectors laid out as regions), and
//!   the states saved in the project ([`binbun_session::Project::states`]:
//!   [`load_states`], [`save_state`]).

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use binbun::decompile::View;
use binbun::profile::{self, Agreement, Profile};
use binbun::queries::compare::{self, Comparison, Output};
use binbun::queries::evidence::{Clue, Explanation, Item, NameSource, Source, Subject, shape_c};
use binbun::queries::origin::{Kind, Origins, Remote, Step, Trivial};
use binbun::queries::verify::{Difference, Verdict, Verification};
use binbun::run::state::Region;
use binbun::run::{Callee, CalleeKind, ExampleState, How, Run, Stop, show};
use binbun_ast::ir::{Node, StmtId, VarId};
use binbun_ast::types::Evidence;
use binbun_print::document::TokenKind;
use binbun_semantics::interpret::Value;
use binbun_semantics::ir::{RegisterId, SiteId};
use binbun_session::Identified;
use binbun_session::journal::Origin;
use binbun_session::signatures::NameSource as FunctionName;

use crate::cdoc::{CDocument, UndefinedValue};
use crate::crash_safe;
use crate::peek::short_title;

/// The verification chip of a C pane's toolbar.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Chip {
    /// The check is running.
    Checking,
    /// Its control flow is L1's and every state compared agreed: how many
    /// states were compared.
    Agreed(usize),
    /// It differs from L1 (a counterexample's state, if a run differs).
    Differs,
    /// It cannot be checked: why, in one sentence.
    NotCheckable(String),
}

impl Chip {
    /// The chip of `verification`.
    pub fn of(verification: &Verification) -> Self {
        match &verification.verdict {
            Verdict::Agreed(agreement) => Self::Agreed(agreement.agreed),
            Verdict::Differs(_) => Self::Differs,
            Verdict::NotCheckable(why) => Self::NotCheckable(sentence(why)),
        }
    }

    /// What its card says, line by line: the verdict, then what it rests
    /// on ([`Verification`] if one is shown: the states not compared, how
    /// a run differs, the reading view's assumption).
    pub fn card(&self, verification: Option<&Verification>) -> Vec<String> {
        let mut lines = vec![match self {
            Self::Checking => "Checking the C against L1…".to_owned(),
            Self::Agreed(1) => "Agreed: the C and L1 agree on 1 sampled state.".to_owned(),
            Self::Agreed(states) => {
                format!("Agreed: the C and L1 agree on {states} sampled states.")
            }
            Self::Differs => "Differs from L1.".to_owned(),
            Self::NotCheckable(why) => why.clone(),
        }];
        let Some(verification) = verification.filter(|_| *self != Self::Checking) else {
            return lines;
        };
        match &verification.verdict {
            Verdict::Agreed(agreement) if !agreement.skips.is_empty() => {
                let skipped: Vec<String> = agreement
                    .skips
                    .iter()
                    .map(|(skip, n)| format!("{} ({n})", skip.describe()))
                    .collect();
                lines.push(format!("Not compared: {}.", skipped.join(", ")));
            }
            Verdict::Differs(Difference::Structure(_)) => {
                lines.push("Its control flow is not L1's.".to_owned());
            }
            Verdict::Differs(Difference::Run(counterexample)) => {
                lines.push(sentence(&counterexample.message));
            }
            Verdict::Agreed(_) | Verdict::NotCheckable(_) => {}
        }
        if verification.view == View::Reading {
            lines.push(
                "Under the reading view's assumption: dereferenced addresses are canonical."
                    .to_owned(),
            );
        }
        lines
    }
}

/// The card's line for `count` values the C shows that the architecture
/// leaves undefined, if any, `values` split by whether the shipped
/// processors' profiles differ there (each named: its register by
/// `register`, and its instruction), agree, or are not all known.
pub fn processor_dependent(
    count: usize,
    values: &[UndefinedValue],
    register: &dyn Fn(RegisterId) -> Option<String>,
) -> Option<String> {
    let shown = match count {
        0 => return None,
        1 => "1 value".to_owned(),
        n => format!("{n} values"),
    };
    let mut differ = Vec::new();
    let (mut agree, mut unknown) = (0, 0);
    for value in values {
        match value.site.map_or(Agreement::Unknown, profile::agreement) {
            Agreement::Differ => differ.push(value),
            Agreement::Agree => agree += 1,
            Agreement::Unknown => unknown += 1,
        }
    }
    if differ.is_empty() && agree == 0 {
        return Some(format!(
            "Processor-dependent: {shown} the architecture leaves undefined; processors differ there."
        ));
    }
    let named: Vec<String> = differ
        .iter()
        .map(|value| {
            let what = value
                .register
                .and_then(register)
                .map_or_else(|| "a value".to_owned(), |name| name.to_ascii_uppercase());
            format!("{what} at {:#x}", value.address)
        })
        .collect();
    let mut split = vec![if named.is_empty() {
        "differ on 0".to_owned()
    } else {
        format!("differ on {} ({})", differ.len(), named.join(", "))
    }];
    split.push(format!("agree on {agree}"));
    if unknown > 0 {
        split.push(format!("are not all known on {unknown}"));
    }
    Some(format!(
        "Processor-dependent: {shown} the architecture leaves undefined; the shipped processors {}.",
        split.join(", ")
    ))
}

/// A row of the Compare Processors card's table: what it is, then a cell
/// per processor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Row {
    /// What differs (`printf argument 2`, `return`, `store 4010`), or the
    /// deciding site (`shrd.of 1154`), or `rule`.
    pub label: String,
    /// Per processor, its value (or its rule).
    pub cells: Vec<String>,
    /// Whether the cells are rules.
    pub rule: bool,
}

/// The Compare Processors chip's card: a summary (`16 of 16 inputs
/// differ`), then for the first
/// differing state a table with a column per processor: a row per output
/// that differs, the deciding site's values and each processor's rule
/// there.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ComparisonCard {
    /// The verdict in a few words.
    pub summary: String,
    /// The table's column heads, the processors (empty: no table).
    pub processors: Vec<String>,
    /// The table's rows.
    pub rows: Vec<Row>,
}

impl ComparisonCard {
    /// The card of `comparison` (`None`: still comparing), sites named by
    /// `site` and addresses (a call's target) by `name`.
    pub fn new(
        comparison: Option<&Comparison>,
        site: &dyn Fn(SiteId) -> String,
        name: &dyn Fn(u64) -> String,
    ) -> Self {
        let Some(comparison) = comparison else {
            return Self {
                summary: "Comparing processors…".to_owned(),
                ..Self::default()
            };
        };
        let states = comparison.states;
        let mut summary = match &comparison.verdict {
            compare::Verdict::Same if comparison.reaching == states => {
                format!("Same on {}", inputs(states))
            }
            compare::Verdict::Same => format!(
                "Same on {}, {} reaching a site",
                inputs(states),
                comparison.reaching
            ),
            compare::Verdict::NotReached => format!("No input of {states} reaches a site"),
            compare::Verdict::Differs(_) => {
                let differ = states.saturating_sub(comparison.same + comparison.skipped);
                let mut text = format!("{differ} of {} differ", inputs(states));
                if comparison.ways.len() > 1 {
                    let _ = write!(text, " in {} ways", comparison.ways.len());
                }
                text
            }
            compare::Verdict::NotCheckable(why) => {
                return Self {
                    summary: sentence(why).trim_end_matches('.').to_owned(),
                    ..Self::default()
                };
            }
        };
        if comparison.skipped > 0 {
            let _ = write!(summary, ", {} not compared", comparison.skipped);
        }
        let compare::Verdict::Differs(differing) = &comparison.verdict else {
            return Self {
                summary,
                ..Self::default()
            };
        };
        let Some(first) = differing.first() else {
            return Self {
                summary,
                ..Self::default()
            };
        };
        let mut rows = match &first.stored {
            Some(stored) => vec![Row {
                label: format!("store {:X}", stored.address),
                cells: stored.bytes.iter().map(number).collect(),
                rule: false,
            }],
            None => output_rows(&first.outputs, name),
        };
        if let Some(decider) = &first.decider {
            rows.push(Row {
                label: format!("{} {:X}", site(decider.site), decider.address),
                cells: decider.values.iter().map(number).collect(),
                rule: false,
            });
            if !first.rules.is_empty() {
                rows.push(Row {
                    label: "rule".to_owned(),
                    cells: first.rules.clone(),
                    rule: true,
                });
            }
        }
        Self {
            summary,
            processors: comparison
                .profiles
                .iter()
                .map(|label| processor_name(label))
                .collect(),
            rows,
        }
    }
}

/// `n` inputs, in words.
fn inputs(n: usize) -> String {
    if n == 1 {
        "1 input".to_owned()
    } else {
        format!("{n} inputs")
    }
}

/// A processor's name as a column head: a shipped profile's short title
/// for its `label` (`intel-raptor-cove r2`: `Intel Raptor Cove`), else the
/// label.
fn processor_name(label: &str) -> String {
    profile::embedded()
        .iter()
        .find(|profile| profile.label() == label)
        .map_or_else(
            || label.to_owned(),
            |profile| short_title(profile).to_owned(),
        )
}

/// The rows of what differs between the processors' `outputs`: a call's
/// arguments that differ (one row each), else its target; the return
/// value; where it leaves to; else how each ended. Call targets named by
/// `name`.
fn output_rows(outputs: &[Output], name: &dyn Fn(u64) -> String) -> Vec<Row> {
    let row = |label: String, cells: Vec<String>| Row {
        label,
        cells,
        rule: false,
    };
    let calls: Option<Vec<(u64, &[Value])>> = outputs
        .iter()
        .map(|output| match output {
            Output::Called { target, arguments } => Some((*target, arguments.as_slice())),
            Output::Returned(_) | Output::Left(_) | Output::SystemCall | Output::Other(_) => None,
        })
        .collect();
    if let Some(calls) = calls
        && let Some(&(target, _)) = calls.first()
    {
        if calls.iter().any(|&(other, _)| other != target) {
            return vec![row(
                "call".to_owned(),
                calls.iter().map(|&(target, _)| name(target)).collect(),
            )];
        }
        let count = calls.iter().map(|(_, a)| a.len()).max().unwrap_or(0);
        let rows: Vec<Row> = (0..count)
            .filter_map(|k| {
                let values: Vec<String> = calls
                    .iter()
                    .map(|(_, arguments)| arguments.get(k).map_or_else(String::new, number))
                    .collect();
                values
                    .iter()
                    .any(|value| Some(value) != values.first())
                    .then(|| row(format!("{} argument {}", name(target), k + 1), values))
            })
            .collect();
        if !rows.is_empty() {
            return rows;
        }
    }
    let returns: Option<Vec<String>> = outputs
        .iter()
        .map(|output| match output {
            Output::Returned(value) => {
                Some(value.as_ref().map_or_else(|| "none".to_owned(), number))
            }
            Output::Left(_) | Output::Called { .. } | Output::SystemCall | Output::Other(_) => None,
        })
        .collect();
    if let Some(cells) = returns {
        return vec![row("return".to_owned(), cells)];
    }
    let left: Option<Vec<String>> = outputs
        .iter()
        .map(|output| match output {
            Output::Left(address) => Some(name(*address)),
            Output::Returned(_) | Output::Called { .. } | Output::SystemCall | Output::Other(_) => {
                None
            }
        })
        .collect();
    if let Some(cells) = left {
        return vec![row("leaves to".to_owned(), cells)];
    }
    vec![row(
        "ends".to_owned(),
        outputs
            .iter()
            .map(|output| match output {
                Output::Returned(value) => format!(
                    "returns {}",
                    value.as_ref().map_or_else(|| "none".to_owned(), number)
                ),
                Output::Left(address) => format!("leaves to {}", name(*address)),
                Output::Called { target, .. } => format!("calls {}", name(*target)),
                Output::SystemCall => "system call".to_owned(),
                Output::Other(how) => how.clone(),
            })
            .collect(),
    )]
}

/// A value as the comparison's card and a stopped call show it: a bit as
/// 0 or 1, below 10 in decimal, else in hexadecimal (as the C writes
/// constants); partly known as a run shows it.
pub fn number(value: &Value) -> String {
    match value.known() {
        Some(bits) if value.width() <= 64 => {
            let n = bits.low_u64();
            if n < 10 {
                n.to_string()
            } else {
                format!("{n:#x}")
            }
        }
        _ => show(value),
    }
}

/// Why a function is not checkable, as one sentence: the engine's
/// "every state skipped: L2 out of fuel 9, L1 depends on undefined bits 7"
/// as "Every state was skipped: L2 out of fuel (9), L1 depends on
/// undefined bits (7)."
pub fn sentence(why: &str) -> String {
    let body = if let Some(reasons) = why.strip_prefix("every state skipped: ") {
        let reasons: Vec<String> = reasons
            .split(", ")
            .map(|reason| match reason.rsplit_once(' ') {
                Some((what, count)) if count.chars().all(|c| c.is_ascii_digit()) => {
                    format!("{what} ({count})")
                }
                _ => reason.to_owned(),
            })
            .collect();
        format!("Every state was skipped: {}", reasons.join(", "))
    } else {
        let mut chars = why.chars();
        chars.next().map_or_else(String::new, |first| {
            first.to_uppercase().chain(chars).collect()
        })
    };
    if body.ends_with('.') {
        body
    } else {
        body + "."
    }
}

/// The highest strength a clue has that is still weak evidence: what an
/// earlier pass deduced, callers' agreement, flags (`Clue::strength` 0
/// to 2); operations, accesses, floating point and declarations are
/// strong.
pub const WEAK: u8 = 2;

/// Whether `item`'s type rests on real but weak evidence: deduced (by the
/// solver, or from what callers pass) from clues none stronger than
/// [`WEAK`]. Strong evidence draws nothing, and neither does a default
/// (nothing but the width, or a deduction with no clue to show): its
/// form says so already.
pub fn weak(item: &Item) -> bool {
    match item.evidence {
        Evidence::Default | Evidence::Declared | Evidence::DeclaredPointer => false,
        Evidence::Deduced => match item.source {
            Source::Solver | Source::Callers | Source::Program => item
                .clues
                .iter()
                .map(|clue| clue.strength)
                .max()
                .is_some_and(|strength| strength <= WEAK),
            Source::Default
            | Source::User
            | Source::Debug
            | Source::Prototype
            | Source::Platform
            | Source::Declaration
            | Source::Promoted
            | Source::Callee(_)
            | Source::Scheme(_) => false,
        },
    }
}

/// Whether a why card for `item` has something to say: its name or type
/// comes from somewhere, or the solver left clues or conflicts. A default
/// name with a width-only type has nothing (the card does not open on
/// defaults alone).
pub fn explained(item: &Item) -> bool {
    item.name_source != NameSource::Printer
        || (item.evidence != Evidence::Default && item.source != Source::Default)
        || !item.clues.is_empty()
        || !item.conflicts.is_empty()
}

/// The item of `explanation` for variable `var` (none for a variable it
/// has nothing to say about: [`explained`]).
pub fn item_of(explanation: &Explanation, var: VarId) -> Option<usize> {
    explanation
        .items
        .iter()
        .position(|item| item.var == Some(var))
        .filter(|&k| explanation.items.get(k).is_some_and(explained))
}

/// A function's explanation laid over its document: the tokens to
/// underline (weak evidence) and the item each stands for.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Why {
    /// Each underlined span (of the document) and its item (of the
    /// explanation).
    pub marks: BTreeMap<usize, usize>,
}

impl Why {
    /// The marks of `explanation` on `document`: every occurrence of a
    /// variable on real but weak evidence ([`weak`]), and the type tokens
    /// just before its declarations (and before the function's name for
    /// the return value).
    pub fn new(document: &CDocument, explanation: &Explanation) -> Self {
        let mut by_var: HashMap<VarId, usize> = HashMap::new();
        let mut returns = None;
        for (index, item) in explanation.items.iter().enumerate() {
            if !weak(item) {
                continue;
            }
            match (item.var, item.subject) {
                (Some(var), _) => {
                    by_var.insert(var, index);
                }
                (None, Subject::Return) => returns = Some(index),
                (None, _) => {}
            }
        }
        let mut marks = BTreeMap::new();
        for (s, span) in document.spans.iter().enumerate() {
            let Some(Node::Var(var)) = span.node else {
                continue;
            };
            let Some(&item) = by_var.get(&var) else {
                continue;
            };
            marks.insert(s, item);
            for t in type_before(document, s) {
                marks.insert(t, item);
            }
        }
        if let Some(item) = returns {
            let line = document.body_start();
            let name = document.lines.get(line).and_then(|l| {
                l.spans.clone().find(|&s| {
                    document
                        .spans
                        .get(s)
                        .is_some_and(|span| span.kind == TokenKind::Function)
                })
            });
            if let Some(name) = name {
                for t in type_before(document, name) {
                    marks.insert(t, item);
                }
            }
        }
        Self { marks }
    }
}

/// The type tokens just before span `s` on its line (a declaration's),
/// skipping the declarator's `*`s; none if a type token is not there.
fn type_before(document: &CDocument, s: usize) -> Vec<usize> {
    let Some(line) = document.line_of_span(s).and_then(|l| document.lines.get(l)) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut at = s;
    while at > line.spans.start {
        at -= 1;
        let Some(span) = document.spans.get(at) else {
            break;
        };
        match span.kind {
            TokenKind::Type | TokenKind::BuiltinType => out.push(at),
            TokenKind::Operator | TokenKind::Punctuation
                if out.is_empty() && document.span_text(at) == "*" => {}
            TokenKind::Keyword if !out.is_empty() && document.span_text(at) == "struct" => {
                out.push(at);
            }
            TokenKind::ControlKeyword
            | TokenKind::Keyword
            | TokenKind::Function
            | TokenKind::Local
            | TokenKind::Parameter
            | TokenKind::Global
            | TokenKind::Field
            | TokenKind::Macro
            | TokenKind::Number
            | TokenKind::String
            | TokenKind::Operator
            | TokenKind::Punctuation
            | TokenKind::Comment
            | TokenKind::Label => break,
        }
    }
    out
}

/// One line of a why card.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CardLine {
    /// Its label (`name`, `type`, a clue's strength).
    pub label: String,
    /// Its text.
    pub text: String,
    /// The instructions it comes from (links).
    pub addresses: Vec<u64>,
    /// Whether it is a conflict (evidence the type does not follow).
    pub conflict: bool,
}

/// What a why card shows for an item.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Card {
    /// The name and type, as printed (`char **a1`).
    pub title: String,
    /// The lines: the name's source, the type's source and strength, the
    /// solver's clues, the conflicts.
    pub lines: Vec<CardLine>,
}

impl Card {
    /// The card of `item`.
    pub fn new(item: &Item) -> Self {
        let mut lines = vec![
            CardLine {
                label: "name".to_owned(),
                text: name_source(item.name_source).to_owned(),
                addresses: Vec::new(),
                conflict: false,
            },
            CardLine {
                label: "type".to_owned(),
                text: format!(
                    "{} · {}",
                    source_text(&item.source),
                    evidence_text(item.evidence)
                ),
                addresses: match &item.source {
                    Source::Callee(callee) | Source::Scheme(callee) => callee.calls.clone(),
                    Source::User
                    | Source::Debug
                    | Source::Prototype
                    | Source::Platform
                    | Source::Declaration
                    | Source::Promoted
                    | Source::Callers
                    | Source::Program
                    | Source::Solver
                    | Source::Default => Vec::new(),
                },
                conflict: false,
            },
        ];
        lines.extend(item.clues.iter().map(|clue| clue_line(clue, false)));
        lines.extend(item.conflicts.iter().map(|clue| clue_line(clue, true)));
        let title = if item.subject == Subject::Return {
            format!("{} returns {}", item.name, item.ty)
        } else {
            format!("{} {}", item.ty, item.name)
        };
        Self { title, lines }
    }

    /// The card of a function's name `name`: where it comes from
    /// (`source`, `None` for a name binbun made; `agent`, the agent whose
    /// rename it is, by name, if known) and what the library
    /// signature `identified` says of the function, a match the user
    /// rejected too (its library, object, how it matched, its pack, its
    /// prototype, whether it returns).
    pub fn function(
        name: &str,
        source: Option<&FunctionName>,
        agent: Option<&str>,
        identified: Option<&Identified>,
    ) -> Self {
        let line = |label: &str, text: String| CardLine {
            label: label.to_owned(),
            text,
            addresses: Vec::new(),
            conflict: false,
        };
        let mut lines = vec![line("name", function_name_source(source, agent))];
        if let Some(identified) = identified {
            if identified.rejected {
                lines.push(line("rejected", identified.name.clone()));
            }
            lines.push(line(
                "library",
                format!("{} {}", identified.library, identified.version),
            ));
            lines.push(line("object", identified.object.clone()));
            lines.push(line("match", identified.how.to_string()));
            lines.push(line("pack", identified.pack.clone()));
            if let Some(prototype) = &identified.prototype {
                lines.push(line("type", prototype.clone()));
            }
            if identified.no_return {
                lines.push(line(
                    "returns",
                    "declared noreturn (library signature)".to_owned(),
                ));
            }
        }
        Self {
            title: name.to_owned(),
            lines,
        }
    }

    /// How wide its labels' column is, in characters: its longest label's.
    pub fn label_chars(&self) -> usize {
        self.lines
            .iter()
            .map(|line| line.label.chars().count())
            .max()
            .unwrap_or(0)
    }
}

/// Where a function's name comes from, as its card says: a library
/// signature (the card's next lines say which), else the edit's origin,
/// the binary's symbol, its debug information; binbun's own name
/// (`sub_…`) if `source` is `None`. An agent's rename names the agent
/// (`agent`) if known.
fn function_name_source(source: Option<&FunctionName>, agent: Option<&str>) -> String {
    match source {
        None => "default".to_owned(),
        Some(FunctionName::Signature) => "signature".to_owned(),
        Some(FunctionName::Edit(Origin::Signature(pack))) => format!("signature {pack}"),
        Some(FunctionName::Symbol) => "symbol".to_owned(),
        Some(FunctionName::Debug) => "debug information".to_owned(),
        Some(FunctionName::Edit(Origin::User | Origin::Undo(_) | Origin::Redo(_))) => {
            "your rename".to_owned()
        }
        Some(FunctionName::Edit(Origin::Accept(_))) => "an accepted suggestion".to_owned(),
        Some(FunctionName::Edit(Origin::Import(from))) => format!("imported from {from}"),
        Some(FunctionName::Edit(Origin::Script(script))) => format!("script {script}"),
        Some(FunctionName::Edit(Origin::Plugin(plugin))) => format!("plugin {plugin}"),
        Some(FunctionName::Edit(Origin::Agent)) => agent.unwrap_or("an agent").to_owned(),
    }
}

fn clue_line(clue: &Clue, conflict: bool) -> CardLine {
    let mut text = format!(
        "{} {}: {}",
        if clue.lower { "≥" } else { "≤" },
        shape_c(clue.shape),
        clue.reason
    );
    if let Some(callee) = &clue.callee {
        let name = callee.name.clone().unwrap_or_else(|| {
            callee
                .address
                .map_or_else(|| "a call".to_owned(), |a| format!("{a:#x}"))
        });
        // The reason says which argument or the result; this, of what.
        let _ = write!(text, " ({name})");
    }
    CardLine {
        label: format!("{}", clue.strength),
        text,
        addresses: clue.addresses.clone(),
        conflict,
    }
}

fn name_source(source: NameSource) -> &'static str {
    match source {
        NameSource::User => "your rename",
        NameSource::Debug => "debug information",
        NameSource::Symbol => "symbol",
        NameSource::Convention => "calling convention",
        NameSource::Declared => "the function's declaration",
        NameSource::Argument => "a callee's parameter",
        NameSource::Counter => "loop counter",
        NameSource::Result => "the returned value",
        NameSource::Printer => "default",
    }
}

fn source_text(source: &Source) -> String {
    let callee = |callee: &binbun::queries::evidence::Callee, what: &str| {
        let name = callee.name.clone().unwrap_or_else(|| "a callee".to_owned());
        match callee.parameter {
            Some(p) => format!("{what} of {name}, parameter {}", p + 1),
            None => format!("{what} of {name}, result"),
        }
    };
    match source {
        Source::User => "your type".to_owned(),
        Source::Debug => "debug information".to_owned(),
        Source::Prototype => "own prototype".to_owned(),
        Source::Platform => "platform".to_owned(),
        Source::Declaration => "declaration".to_owned(),
        Source::Promoted => "promoted by a callee".to_owned(),
        Source::Callee(c) => callee(c, "prototype"),
        Source::Scheme(c) => callee(c, "solved type"),
        Source::Callers => "what callers pass".to_owned(),
        Source::Program => "the program's type".to_owned(),
        Source::Solver => "solver".to_owned(),
        Source::Default => "width only".to_owned(),
    }
}

fn evidence_text(evidence: Evidence) -> &'static str {
    match evidence {
        Evidence::Default => "default",
        Evidence::Deduced => "deduced",
        Evidence::DeclaredPointer => "declared pointer",
        Evidence::Declared => "declared",
    }
}

/// A row of the Origin panel.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OriginRow {
    /// Where it is in the tree: the indices taken from the chains down.
    pub path: Vec<u32>,
    /// How deep it is.
    pub depth: usize,
    /// What it is (`load [rdi + 8]`, `parameter 1`, `join`).
    pub text: String,
    /// The C line its first node is on, as an excerpt.
    pub excerpt: Option<String>,
    /// Its instructions.
    pub addresses: Vec<u64>,
    /// The C nodes standing for it.
    pub nodes: Vec<Node>,
    /// How many trivial steps it folds (expandable when not zero).
    pub folds: usize,
    /// Whether its folded steps are shown.
    pub open: bool,
    /// Whether it is a fork (a join of different values).
    pub fork: bool,
    /// Whether it is a folded step shown.
    pub folded: bool,
}

/// The Origin panel's rows of `origins` (backward chains, or `forward`:
/// the uses), the folded steps of the rows whose paths are in `open`
/// shown, excerpts from `document`.
pub fn origin_rows(
    origins: &Origins,
    document: Option<&CDocument>,
    open: &BTreeSet<Vec<u32>>,
    forward: bool,
) -> Vec<OriginRow> {
    let mut rows = Vec::new();
    if forward {
        for (i, used) in (0u32..).zip(&origins.uses) {
            rows.push(OriginRow {
                path: vec![i],
                depth: 0,
                text: used.kind.clone(),
                excerpt: excerpt(document, &used.nodes),
                addresses: vec![used.address],
                nodes: used.nodes.clone(),
                folds: 0,
                open: false,
                fork: false,
                folded: false,
            });
        }
        return rows;
    }
    for (i, chain) in (0u32..).zip(&origins.chains) {
        step_rows(chain, &[i], 0, document, open, &mut rows);
    }
    rows
}

fn step_rows(
    step: &Step,
    path: &[u32],
    depth: usize,
    document: Option<&CDocument>,
    open: &BTreeSet<Vec<u32>>,
    rows: &mut Vec<OriginRow>,
) {
    let shown = open.contains(path);
    rows.push(OriginRow {
        path: path.to_vec(),
        depth,
        text: kind_text(&step.kind),
        excerpt: excerpt(document, &step.nodes),
        addresses: step.addresses.clone(),
        nodes: step.nodes.clone(),
        folds: step.folded.len(),
        open: shown,
        fork: matches!(step.kind, Kind::Join) && step.inputs.len() > 1,
        folded: false,
    });
    if shown {
        for folded in &step.folded {
            rows.push(OriginRow {
                path: path.to_vec(),
                depth: depth + 1,
                text: trivial_text(folded.kind).to_owned(),
                excerpt: None,
                addresses: folded.address.into_iter().collect(),
                nodes: Vec::new(),
                folds: 0,
                open: false,
                fork: false,
                folded: true,
            });
        }
    }
    for (i, input) in (0u32..).zip(&step.inputs) {
        let mut next = path.to_vec();
        next.push(i);
        step_rows(input, &next, depth + 1, document, open, rows);
    }
    let remotes: &[Remote] = match &step.kind {
        Kind::Parameter { sites, .. } => sites,
        Kind::Call { returns, .. } => returns,
        Kind::Constant(_)
        | Kind::Undefined
        | Kind::Load { .. }
        | Kind::Operation(_)
        | Kind::Join
        | Kind::Other(_)
        | Kind::Cut => &[],
    };
    let base = u32::try_from(step.inputs.len()).unwrap_or(u32::MAX);
    for (i, remote) in (base..).zip(remotes) {
        let mut next = path.to_vec();
        next.push(i);
        let name = remote
            .name
            .clone()
            .unwrap_or_else(|| format!("sub_{:X}", remote.function));
        rows.push(OriginRow {
            path: next.clone(),
            depth: depth + 1,
            text: if matches!(step.kind, Kind::Parameter { .. }) {
                format!("passed by {name}")
            } else {
                format!("returned by {name}")
            },
            excerpt: None,
            addresses: vec![remote.address],
            nodes: Vec::new(),
            folds: 0,
            open: false,
            fork: false,
            folded: false,
        });
        if let Some(chain) = &remote.chain {
            // Another function's chain: its nodes are not this document's.
            let mut inner = next;
            inner.push(0);
            step_rows(chain, &inner, depth + 2, None, open, rows);
        }
    }
}

fn kind_text(kind: &Kind) -> String {
    match kind {
        Kind::Constant(value) => {
            if *value < 0x1_0000 {
                format!("constant {value}")
            } else {
                format!("constant {value:#x}")
            }
        }
        Kind::Undefined => "undefined".to_owned(),
        Kind::Parameter {
            register, index, ..
        } => match index {
            Some(index) => format!("parameter {} ({register})", index + 1),
            None => format!("entry {register}"),
        },
        Kind::Load { address, bytes } => format!("load {bytes} bytes [{address}]"),
        Kind::Call { name, callee, .. } => {
            let name = name
                .clone()
                .or_else(|| callee.map(|c| format!("sub_{c:X}")))
                .unwrap_or_else(|| "a call".to_owned());
            format!("result of {name}")
        }
        Kind::Operation(op) => op.clone(),
        Kind::Join => "join".to_owned(),
        Kind::Other(what) => what.clone(),
        Kind::Cut => "…".to_owned(),
    }
}

const fn trivial_text(kind: Trivial) -> &'static str {
    match kind {
        Trivial::Truncation => "truncation",
        Trivial::Extension => "extension",
        Trivial::Copy => "copy",
        Trivial::Reload => "spill reload",
        Trivial::BlockArgument => "block argument",
    }
}

/// The C line `nodes`' first printed one is on, trimmed.
fn excerpt(document: Option<&CDocument>, nodes: &[Node]) -> Option<String> {
    let document = document?;
    let span = nodes
        .iter()
        .find_map(|&node| document.occurrences(node).next())?;
    let line = document.line_of_span(span)?;
    Some(document.line_text(line).trim().to_owned())
}

/// How many occurrences a line-end shows before the count.
pub const SHOWN: usize = 3;

/// A statement's values at its line's end.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pill {
    /// The values, as shown (`0x1 · 0x2 ×5`).
    pub text: String,
    /// Whether a value the run's processor profile gave at a site went
    /// into one (it holds on that processor only).
    pub profile: bool,
}

/// A run laid over its document and the listing.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Values {
    /// Each C line's values (pills, in statement order).
    pub lines: BTreeMap<usize, Vec<Pill>>,
    /// The processor the run was on (its profile's short title), if one.
    pub processor: Option<String>,
    /// The line of the call that needs a stub, with the callee's name.
    pub stub: Option<(usize, String)>,
    /// Each instruction's written registers, as the listing shows them.
    pub registers: HashMap<u64, String>,
    /// How the run ended.
    pub stop: String,
}

impl Values {
    /// The values of `run` on `document`, run on `profile` if one;
    /// register names by `register`.
    pub fn new(
        document: &CDocument,
        run: &Run,
        profile: Option<&Profile>,
        register: &dyn Fn(usize) -> Option<String>,
    ) -> Self {
        let lines_of = statement_lines(document);
        let mut lines: BTreeMap<usize, Vec<Pill>> = BTreeMap::new();
        for (stmt, trace) in &run.c.statements {
            let Some(&line) = lines_of.get(stmt) else {
                continue;
            };
            let values: Vec<String> = trace
                .shown
                .iter()
                .filter_map(|occurrence| occurrence.values.first().map(show))
                .collect();
            if values.is_empty() {
                continue;
            }
            lines.entry(line).or_default().push(Pill {
                text: trail(&values, trace.count),
                profile: trace.shown.iter().any(|occurrence| occurrence.profile),
            });
        }
        let stub = match &run.c.stop {
            Stop::NeedsStub { callee, .. } => run
                .c
                .at
                .and_then(|at| lines_of.get(&at).copied())
                .map(|line| (line, callee_name(callee))),
            Stop::Returned(_)
            | Stop::Fault { .. }
            | Stop::Trap(_)
            | Stop::Undetermined
            | Stop::Escape(_)
            | Stop::Unreachable
            | Stop::OutOfSteps
            | Stop::Cancelled
            | Stop::Malformed => None,
        };
        // The call the run stopped at: what it was called with (on a
        // processor, what that processor's values made of it).
        if let Some((line, name)) = &stub
            && let Some(call) = run.c.calls.last().filter(|c| c.how == How::Stopped)
        {
            let arguments: Vec<String> = call.arguments.iter().map(number).collect();
            let profile = run
                .c
                .at
                .and_then(|at| run.c.statements.get(&at))
                .and_then(|trace| trace.shown.last())
                .is_some_and(|occurrence| occurrence.profile);
            lines.entry(*line).or_default().push(Pill {
                text: format!("{name}({})", arguments.join(", ")),
                profile,
            });
        }
        let mut registers = HashMap::new();
        if let Some(machine) = &run.machine {
            for (&address, trace) in &machine.traces {
                let mut by_register: BTreeMap<usize, Vec<String>> = BTreeMap::new();
                for writes in &trace.shown {
                    for (id, value) in writes {
                        if value.width() > 1 {
                            by_register
                                .entry(usize::from(id.0))
                                .or_default()
                                .push(show(value));
                        }
                    }
                }
                let text: Vec<String> = by_register
                    .into_iter()
                    .filter_map(|(id, values)| {
                        Some(format!("{}={}", register(id)?, trail(&values, trace.count)))
                    })
                    .collect();
                if !text.is_empty() {
                    registers.insert(address, text.join("  "));
                }
            }
        }
        Self {
            lines,
            processor: profile.map(|profile| short_title(profile).to_owned()),
            stub,
            registers,
            stop: run.c.stop.to_string(),
        }
    }
}

/// `values` (the first occurrences of `count`) as a line-end shows them:
/// the first [`SHOWN`], and `×count` if it ran more often than that.
pub fn trail(values: &[String], count: u64) -> String {
    let shown = values.get(..SHOWN).unwrap_or(values);
    let mut text = shown.join(" · ");
    if count > shown.len() as u64 {
        let _ = write!(text, " ×{count}");
    }
    text
}

/// How a run names `callee`: its name, else its address (`syscall` for a
/// system call).
fn callee_name(callee: &Callee) -> String {
    callee.name.clone().unwrap_or_else(|| match callee.kind {
        CalleeKind::SystemCall => "syscall".to_owned(),
        CalleeKind::Function(_) | CalleeKind::Import | CalleeKind::Unresolved => {
            format!("{:#x}", callee.address)
        }
    })
}

/// The line each statement's first token is on.
pub fn statement_lines(document: &CDocument) -> BTreeMap<StmtId, usize> {
    let mut out = BTreeMap::new();
    for (s, span) in document.spans.iter().enumerate() {
        if let Some(Node::Stmt(id)) = span.node
            && let Some(line) = document.line_of_span(s)
        {
            out.entry(id).or_insert(line);
        }
    }
    out
}

/// The states saved in `dir` for function `function` (by name), sorted by
/// name; files that do not parse are left out.
pub fn load_states(dir: &Path, function: &str) -> Vec<ExampleState> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut states: Vec<ExampleState> = entries
        .filter_map(Result::ok)
        .filter(|entry| entry.path().extension().is_some_and(|e| e == "toml"))
        .filter_map(|entry| std::fs::read_to_string(entry.path()).ok())
        .filter_map(|text| ExampleState::parse(&text).ok())
        .filter(|state| state.function.as_deref() == Some(function))
        .collect();
    states.sort_by(|a, b| a.name.cmp(&b.name));
    states
}

/// Saves `state` in `dir` as `<function>.<name>.toml`, crash-safely.
///
/// # Errors
///
/// It cannot be written.
pub fn save_state(dir: &Path, state: &ExampleState) -> Result<PathBuf, String> {
    let file: String = format!(
        "{}.{}.toml",
        state.function.as_deref().unwrap_or("any"),
        state.name
    )
    .chars()
    .map(|c| {
        if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
            c
        } else {
            '_'
        }
    })
    .collect();
    let path = dir.join(file);
    let text = state.to_toml()?;
    crash_safe::write(&path, text.as_bytes()).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(path)
}

/// Where the compact form lays out its strings and vectors: one region
/// every 64 KiB from here.
pub const REGIONS: u64 = 0x10_0000;

/// A state named `name` for `function` from the compact form's
/// `arguments` (by prototype): a number as itself, `"text"` as a pointer
/// to the string, `["a", "b"]` as a pointer to a NULL-terminated vector
/// of string pointers (`argv`), empty as undefined. Each string and
/// vector gets a region of its own from [`REGIONS`].
///
/// # Errors
///
/// An argument is a malformed string or vector.
pub fn scratch_state(
    name: &str,
    function: &str,
    arguments: &[String],
) -> Result<ExampleState, String> {
    let mut state = ExampleState::scratch(name);
    state.function = Some(function.to_owned());
    let mut next = REGIONS;
    let mut region = |state: &mut ExampleState, mut region: Region| {
        let at = next;
        next += 0x1_0000;
        region.address = format!("{at:#x}");
        state.regions.push(region);
        at
    };
    for argument in arguments {
        let text = argument.trim();
        let value = if text.is_empty() {
            "undefined".to_owned()
        } else if let Some(inner) = text.strip_prefix('[') {
            let inner = inner
                .strip_suffix(']')
                .ok_or_else(|| format!("unclosed vector: {text}"))?;
            let strings = strings(inner)?;
            let mut pointers = Vec::with_capacity(strings.len() + 1);
            for string in strings {
                let at = region(
                    &mut state,
                    Region {
                        string: Some(string),
                        ..Region::default()
                    },
                );
                pointers.push(format!("ptr:{at:#x}"));
            }
            pointers.push("ptr:0".to_owned());
            let at = region(
                &mut state,
                Region {
                    values: pointers,
                    ..Region::default()
                },
            );
            format!("{at:#x}")
        } else if text.starts_with('"') {
            let mut list = strings(text)?;
            if list.len() != 1 {
                return Err(format!("one string expected: {text}"));
            }
            let at = region(
                &mut state,
                Region {
                    string: list.pop(),
                    ..Region::default()
                },
            );
            format!("{at:#x}")
        } else {
            text.to_owned()
        };
        state.arguments.push(value);
    }
    Ok(state)
}

/// The double-quoted strings of `text`, separated by commas (`\"` and
/// `\\` escaped).
fn strings(text: &str) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    let mut chars = text.chars().peekable();
    loop {
        while chars.peek().is_some_and(|c| c.is_whitespace() || *c == ',') {
            chars.next();
        }
        match chars.next() {
            None => return Ok(out),
            Some('"') => {}
            Some(c) => return Err(format!("a string expected at {c:?}")),
        }
        let mut string = String::new();
        loop {
            match chars.next() {
                None => return Err(format!("unclosed string: {text}")),
                Some('"') => break,
                Some('\\') => string.extend(chars.next()),
                Some(c) => string.push(c),
            }
        }
        out.push(string);
    }
}

/// The counterexample of a differing verification, as an example state
/// for function `function`: its registers (those with a defined value)
/// over hashed memory, as the differential ran it.
pub fn counterexample_state(
    verification: &Verification,
    function: &str,
    registers: &dyn Fn(usize) -> Option<String>,
) -> Option<ExampleState> {
    let Verdict::Differs(Difference::Run(counterexample)) = &verification.verdict else {
        return None;
    };
    let mut state = ExampleState::scratch(&format!("differs-{}", counterexample.index));
    state.function = Some(function.to_owned());
    state.fill = binbun::run::Fill::Hashed;
    state.registers = counterexample
        .state
        .registers
        .iter()
        .enumerate()
        .filter_map(|(id, value)| {
            Some(binbun::run::state::RegisterValue {
                name: registers(id)?,
                value: binbun::run::state::format_value(value),
            })
        })
        .collect();
    Some(state)
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use binbun::cfg::FunctionId;
    use binbun::queries::evidence::{Clue, Explanation, Item, NameSource, Source, Subject};
    use binbun::queries::origin::{Folded, Kind, Origins, Step, Trivial, Use};
    use binbun::run::state::parse_value;
    use binbun_ast::ir::{Function as Ast, Node, VarId};
    use binbun_ast::types::{Evidence, Types};
    use binbun_decompile::typing::BoundShape;
    use binbun_print::document::TokenKind;
    use binbun_semantics::core::Id as _;
    use binbun_session::View;
    use binbun_ssa::ir::{Function as L1, Value};

    use super::{
        Chip, WEAK, Why, item_of, load_states, origin_rows, save_state, scratch_state, sentence,
        trail,
    };
    use crate::cdoc::{CDocument, CSpan};

    /// The processor-dependent line names the values where the shipped
    /// profiles differ and counts those where they agree or are not all
    /// known; with no site known it says only that processors differ.
    #[test]
    fn the_processor_dependent_line_splits_differ_and_agree() {
        use binbun::profile::{Agreement, agreement};
        use binbun_semantics::ir::{RegisterId, SiteId};

        use super::processor_dependent;
        use crate::cdoc::UndefinedValue;

        let site = |wanted: Agreement| {
            (0..u16::MAX)
                .map(SiteId)
                .find(|&site| agreement(site) == wanted)
                .unwrap()
        };
        let value = |address: u64, site: Option<SiteId>| UndefinedValue {
            address,
            register: Some(RegisterId(7)),
            site,
        };
        let register = |id: RegisterId| (id.0 == 7).then(|| "of".to_owned());
        assert_eq!(processor_dependent(0, &[], &register), None);
        let values = [
            value(0x10, Some(site(Agreement::Differ))),
            value(0x20, Some(site(Agreement::Agree))),
            value(0x30, Some(site(Agreement::Agree))),
            value(0x40, None),
        ];
        assert_eq!(
            processor_dependent(4, &values, &register).unwrap(),
            "Processor-dependent: 4 values the architecture leaves undefined; the shipped processors differ on 1 (OF at 0x10), agree on 2, are not all known on 1."
        );
        assert_eq!(
            processor_dependent(1, &values[1..2], &register).unwrap(),
            "Processor-dependent: 1 value the architecture leaves undefined; the shipped processors differ on 0, agree on 1."
        );
        assert_eq!(
            processor_dependent(1, &values[3..], &register).unwrap(),
            "Processor-dependent: 1 value the architecture leaves undefined; processors differ there."
        );
    }

    /// The comparison card of `comparison`: sites named `site3`, 0x1030
    /// named `printf`.
    fn card(comparison: Option<&binbun::queries::compare::Comparison>) -> super::ComparisonCard {
        super::ComparisonCard::new(comparison, &|id| format!("site{}", id.0), &|address| {
            match address {
                0x1030 => "printf".to_owned(),
                other => format!("sub_{other:X}"),
            }
        })
    }

    /// A comparison of 24 states on processors `p r1` and `e r1`: 22 the
    /// same, 2 skipped, 20 reaching site 3.
    fn same() -> binbun::queries::compare::Comparison {
        use binbun::queries::compare::{Comparison, Verdict};
        use binbun_semantics::ir::SiteId;

        Comparison {
            entry: 0x1000,
            profiles: vec!["p r1".to_owned(), "e r1".to_owned()],
            seed: 1,
            states: 24,
            same: 22,
            skipped: 2,
            reaching: 20,
            reached: BTreeMap::from([(SiteId(3), 20)]),
            ways: Vec::new(),
            verdict: Verdict::Same,
        }
    }

    /// A row of a comparison card's table.
    fn row(label: &str, cells: &[&str], rule: bool) -> super::Row {
        super::Row {
            label: label.to_owned(),
            cells: cells.iter().map(|&c| c.to_owned()).collect(),
            rule,
        }
    }

    /// A defined value of `width` bits.
    fn int(width: u16, value: u64) -> binbun_semantics::interpret::Value {
        binbun_semantics::interpret::Value::defined(binbun_semantics::bits::Bits::from_u64(
            width, value,
        ))
    }

    /// State 5 differing in its return value, ending as `outputs` (and
    /// storing `stored`), decided by site 3 at 0x1003 (1 against 0, by
    /// `msb(dst)` against `unknown`).
    fn differing(
        outputs: Vec<binbun::queries::compare::Output>,
        stored: Option<binbun::queries::compare::Stored>,
        way: usize,
    ) -> binbun::queries::compare::Differing {
        use binbun::queries::compare::{Decider, Differing};
        use binbun::run::ExampleState;
        use binbun_decompile::validate::State;
        use binbun_semantics::ir::SiteId;

        Differing {
            index: 5,
            state: State {
                registers: Vec::new(),
                return_address: 0,
                memory: Vec::new(),
            },
            example: ExampleState::scratch("s5"),
            what: "the return value".to_owned(),
            outputs,
            stored,
            decider: Some(Decider {
                address: 0x1003,
                site: SiteId(3),
                values: vec![int(1, 1), int(1, 0)],
            }),
            rules: vec!["msb(dst)".to_owned(), "unknown".to_owned()],
            way,
        }
    }

    /// The comparison card's summary: comparing; the same, with how many
    /// inputs reached a site and how many were not compared; none
    /// reached; not checkable; no table without a difference.
    #[test]
    fn the_comparison_cards_summary_says_the_verdict() {
        use binbun::queries::compare::{Comparison, Verdict};

        use super::ComparisonCard;

        assert_eq!(
            card(None),
            ComparisonCard {
                summary: "Comparing processors…".to_owned(),
                ..ComparisonCard::default()
            }
        );
        let shown = card(Some(&same()));
        assert_eq!(
            shown.summary,
            "Same on 24 inputs, 20 reaching a site, 2 not compared"
        );
        assert!(shown.processors.is_empty() && shown.rows.is_empty());
        let all = Comparison {
            same: 24,
            skipped: 0,
            reaching: 24,
            ..same()
        };
        assert_eq!(card(Some(&all)).summary, "Same on 24 inputs");
        let none = Comparison {
            reaching: 0,
            reached: BTreeMap::new(),
            verdict: Verdict::NotReached,
            ..all.clone()
        };
        assert_eq!(card(Some(&none)).summary, "No input of 24 reaches a site");
        let failed = Comparison {
            verdict: Verdict::NotCheckable("every state skipped: L2 out of fuel 9".to_owned()),
            ..all
        };
        assert_eq!(
            card(Some(&failed)).summary,
            "Every state was skipped: L2 out of fuel (9)"
        );
    }

    /// A difference's table: a column per processor (a shipped one by its
    /// short title), a row per output that differs (a call's differing
    /// arguments only, its target, a return, a store), then the deciding
    /// site's values and the rules there; the summary counts the ways.
    #[test]
    fn the_comparison_cards_table_has_a_row_per_difference() {
        use binbun::profile::embedded;
        use binbun::queries::compare::{Comparison, Output, Verdict};

        use super::ComparisonCard;

        // A return that differs, decided by a site.
        let returns = Comparison {
            same: 0,
            skipped: 0,
            reaching: 24,
            ways: vec![24],
            verdict: Verdict::Differs(vec![differing(
                vec![
                    Output::Returned(Some(int(32, 1))),
                    Output::Returned(Some(int(32, 0xbeef))),
                ],
                None,
                0,
            )]),
            ..same()
        };
        assert_eq!(
            card(Some(&returns)),
            ComparisonCard {
                summary: "24 of 24 inputs differ".to_owned(),
                processors: vec!["p r1".to_owned(), "e r1".to_owned()],
                rows: vec![
                    row("return", &["1", "0xbeef"], false),
                    row("site3 1003", &["1", "0"], false),
                    row("rule", &["msb(dst)", "unknown"], true),
                ],
            }
        );
        // A call: only the arguments that differ, under the shipped
        // processors' short titles; two ways, some not compared.
        let shipped: Vec<String> = embedded().iter().map(|p| p.label()).collect();
        let call = |second| Output::Called {
            target: 0x1030,
            arguments: vec![int(64, 0x2004), int(64, second)],
        };
        let calls = Comparison {
            profiles: shipped,
            states: 16,
            same: 0,
            skipped: 1,
            ways: vec![10, 5],
            verdict: Verdict::Differs(vec![differing(vec![call(0xbeef), call(0xdead)], None, 0)]),
            ..same()
        };
        let shown = card(Some(&calls));
        assert_eq!(
            shown.summary,
            "15 of 16 inputs differ in 2 ways, 1 not compared"
        );
        assert_eq!(shown.processors, ["Intel Raptor Cove", "Intel Gracemont"]);
        assert_eq!(
            shown.rows.first(),
            Some(&row("printf argument 2", &["0xbeef", "0xdead"], false))
        );
        assert_eq!(shown.rows.len(), 3);
    }

    /// Calls of different targets: their targets; a store, where the
    /// runs end alike: its bytes.
    #[test]
    fn the_comparison_cards_table_shows_targets_and_stores() {
        use binbun::queries::compare::{Comparison, Output, Stored, Verdict};

        let calls = Comparison {
            same: 0,
            skipped: 0,
            ways: vec![24],
            ..same()
        };
        let targets = Comparison {
            verdict: Verdict::Differs(vec![differing(
                vec![
                    Output::Called {
                        target: 0x1030,
                        arguments: Vec::new(),
                    },
                    Output::Called {
                        target: 0x2000,
                        arguments: Vec::new(),
                    },
                ],
                None,
                0,
            )]),
            ..calls.clone()
        };
        assert_eq!(
            card(Some(&targets)).rows.first(),
            Some(&row("call", &["printf", "sub_2000"], false))
        );
        let stored = Comparison {
            verdict: Verdict::Differs(vec![differing(
                vec![Output::Returned(None), Output::Returned(None)],
                Some(Stored {
                    address: 0x4010,
                    bytes: vec![int(8, 0x2a), int(8, 7)],
                }),
                0,
            )]),
            ..calls
        };
        assert_eq!(
            card(Some(&stored)).rows.first(),
            Some(&row("store 4010", &["0x2a", "7"], false))
        );
    }

    #[test]
    fn the_marks_card_says_what_the_check_rests_on() {
        use std::time::Duration;

        use binbun::decompile::View as Decompiled;
        use binbun::queries::verify::{Agreement, Verdict, Verification};
        use binbun_decompile::validate::Skip;

        let checked = |view, verdict| Verification {
            entry: 0x1000,
            view,
            verdict,
            fuel: 1000,
            lowering: Duration::ZERO,
            checking: Duration::ZERO,
        };
        let all = Agreement {
            states: 24,
            agreed: 24,
            skips: BTreeMap::new(),
        };
        let exact = checked(Decompiled::Exact, Verdict::Agreed(all));
        let chip = Chip::of(&exact);
        assert_eq!(chip, Chip::Agreed(24));
        assert_eq!(
            chip.card(Some(&exact)),
            ["Agreed: the C and L1 agree on 24 sampled states."]
        );
        // The states not compared, and the reading view's assumption.
        let some = Agreement {
            states: 24,
            agreed: 21,
            skips: BTreeMap::from([(Skip::L2Fuel, 2), (Skip::Undetermined, 1)]),
        };
        let reading = checked(Decompiled::Reading, Verdict::Agreed(some));
        assert_eq!(
            Chip::of(&reading).card(Some(&reading)),
            [
                "Agreed: the C and L1 agree on 21 sampled states.",
                "Not compared: L2 out of fuel (2), L1 depends on undefined bits (1).",
                "Under the reading view's assumption: dereferenced addresses are canonical.",
            ]
        );
        // A check under way says only that, whatever was found before.
        assert_eq!(
            Chip::Checking.card(Some(&reading)),
            ["Checking the C against L1…"]
        );
        let not = checked(
            Decompiled::Exact,
            Verdict::NotCheckable("the function is not lifted".to_owned()),
        );
        assert_eq!(
            Chip::of(&not).card(Some(&not)),
            ["The function is not lifted."]
        );
    }

    #[test]
    fn not_checkable_reads_as_one_sentence() {
        assert_eq!(
            sentence("every state skipped: L2 out of fuel 9, L1 depends on undefined bits 7"),
            "Every state was skipped: L2 out of fuel (9), L1 depends on undefined bits (7)."
        );
        assert_eq!(
            sentence("the function is not lifted"),
            "The function is not lifted."
        );
    }

    #[test]
    fn a_line_end_shows_the_first_values_and_the_count_past_them() {
        let values: Vec<String> = ["1", "2", "3", "4"].map(str::to_owned).to_vec();
        assert_eq!(trail(values.get(..1).unwrap_or_default(), 1), "1");
        assert_eq!(trail(values.get(..3).unwrap_or_default(), 3), "1 · 2 · 3");
        assert_eq!(trail(&values, 4), "1 · 2 · 3 ×4");
        // Fewer kept than ran (the cap): the count says so.
        assert_eq!(trail(values.get(..2).unwrap_or_default(), 70), "1 · 2 ×70");
    }

    #[test]
    fn the_compact_form_lays_out_strings_and_a_terminated_vector() {
        let form = [r#"["a", "b\"c"]"#, "7", "", r#""x""#].map(str::to_owned);
        let state = scratch_state("three", "strvec_len", &form).unwrap();
        assert_eq!(state.function.as_deref(), Some("strvec_len"));
        // Strings first, then the vector pointing at them, NULL last.
        assert_eq!(state.arguments, ["0x120000", "7", "undefined", "0x130000"]);
        let strings: Vec<_> = state.regions.iter().map(|r| r.string.clone()).collect();
        assert_eq!(
            strings,
            [
                Some("a".to_owned()),
                Some("b\"c".to_owned()),
                None,
                Some("x".to_owned())
            ]
        );
        let vector = state.regions.get(2).unwrap_or_else(|| unreachable!());
        assert_eq!(vector.address, "0x120000");
        assert_eq!(vector.values, ["ptr:0x100000", "ptr:0x110000", "ptr:0"]);
        for argument in &state.arguments {
            assert!(parse_value(argument, 64).is_ok(), "{argument}");
        }
        assert!(scratch_state("bad", "f", &[r#"["a""#.to_owned()]).is_err());
        assert!(scratch_state("bad", "f", &[r#""a"#.to_owned()]).is_err());
    }

    #[test]
    fn states_are_saved_in_the_project_and_loaded_per_function() {
        let root = std::env::temp_dir().join(format!("binbun-states-{}", std::process::id()));
        let dir = binbun_session::Project::new(&root).states();
        for (name, function) in [("zero", "f"), ("argv", "f"), ("other", "g")] {
            let state = scratch_state(name, function, &["0".to_owned()]).unwrap();
            save_state(&dir, &state).unwrap();
        }
        let names: Vec<String> = load_states(&dir, "f").into_iter().map(|s| s.name).collect();
        assert_eq!(names, ["argv", "zero"]);
        let _ = std::fs::remove_dir_all(&root);
    }

    fn step(kind: Kind, inputs: Vec<Step>, folded: Vec<Folded>) -> Step {
        Step {
            value: Value(0),
            kind,
            addresses: vec![0x10],
            nodes: Vec::new(),
            folded,
            inputs,
        }
    }

    #[test]
    fn origin_rows_fold_trivial_steps_until_opened_and_show_forks() {
        let reload = Folded {
            kind: Trivial::Reload,
            value: Value(1),
            address: Some(0x20),
        };
        let join = step(
            Kind::Join,
            vec![
                step(Kind::Constant(1), Vec::new(), Vec::new()),
                step(Kind::Undefined, Vec::new(), vec![reload]),
            ],
            Vec::new(),
        );
        let origins = Origins {
            entry: 0,
            values: vec![Value(0)],
            chains: vec![join],
            uses: vec![Use {
                address: 0x30,
                kind: "store".to_owned(),
                nodes: Vec::new(),
            }],
        };
        let closed = origin_rows(&origins, None, &BTreeSet::new(), false);
        let texts: Vec<(usize, &str)> = closed.iter().map(|r| (r.depth, r.text.as_str())).collect();
        assert_eq!(texts, [(0, "join"), (1, "constant 1"), (1, "undefined")]);
        assert!(closed.first().is_some_and(|r| r.fork));
        assert_eq!(closed.get(2).map(|r| r.folds), Some(1));
        let open = BTreeSet::from([vec![0, 1]]);
        let opened = origin_rows(&origins, None, &open, false);
        let last = opened.last().unwrap_or_else(|| unreachable!());
        assert!(last.folded);
        assert_eq!(
            (last.depth, last.text.as_str(), last.addresses.as_slice()),
            (2, "spill reload", [0x20].as_slice())
        );
        let forward = origin_rows(&origins, None, &BTreeSet::new(), true);
        assert_eq!(
            forward
                .iter()
                .map(|r| r.addresses.clone())
                .collect::<Vec<_>>(),
            [vec![0x30]]
        );
    }

    fn item(var: Option<VarId>, subject: Subject, evidence: Evidence, source: Source) -> Item {
        Item {
            subject,
            var,
            name: String::new(),
            name_source: NameSource::Printer,
            ty: String::new(),
            evidence,
            source,
            clues: Vec::new(),
            conflicts: Vec::new(),
        }
    }

    #[test]
    #[expect(clippy::too_many_lines, reason = "one document, its cases in turn")]
    fn weak_variables_and_their_declared_types_are_marked_strong_and_default_ones_not() {
        // `int64_t f(char **a1)` / `uint64_t v1;` / `v1 = a1;`
        let text = "int64_t f(char **a1)\nuint64_t v1;\nv1 = a1;".to_owned();
        let (a1, v1) = (Some(Node::Var(VarId(0))), Some(Node::Var(VarId(1))));
        let spans = [
            (0..7, TokenKind::BuiltinType, None),
            (8..9, TokenKind::Function, None),
            (9..10, TokenKind::Punctuation, None),
            (10..14, TokenKind::BuiltinType, None),
            (15..16, TokenKind::Operator, None),
            (16..17, TokenKind::Operator, None),
            (17..19, TokenKind::Parameter, a1),
            (19..20, TokenKind::Punctuation, None),
            (21..29, TokenKind::BuiltinType, None),
            (30..32, TokenKind::Local, v1),
            (32..33, TokenKind::Punctuation, None),
            (34..36, TokenKind::Local, v1),
            (37..38, TokenKind::Operator, None),
            (39..41, TokenKind::Parameter, a1),
            (41..42, TokenKind::Punctuation, None),
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
        let document = CDocument::from_parts(
            FunctionId::from_raw(0),
            0,
            View::Exact,
            text,
            spans,
            BTreeMap::new(),
            &l2,
            &L1::default(),
        );
        let weak_clue = |strength| Clue {
            lower: true,
            shape: BoundShape::Pointer,
            strength,
            reason: String::new(),
            callee: None,
            addresses: Vec::new(),
            path: Vec::new(),
        };
        let guessed = |var, subject, strength| Item {
            clues: vec![weak_clue(strength)],
            ..item(var, subject, Evidence::Deduced, Source::Solver)
        };
        // The marks with the declared a1, then v1 and the return value as
        // given.
        let marks = |v1: Item, returns: Item| {
            let explanation = Explanation {
                entry: 0,
                view: View::Exact,
                items: vec![
                    item(
                        Some(VarId(0)),
                        Subject::Parameter(0),
                        Evidence::Declared,
                        Source::Prototype,
                    ),
                    v1,
                    returns,
                ],
            };
            Why::new(&document, &explanation).marks
        };
        // v1's two occurrences and `uint64_t`; the return's `int64_t`
        // (solver types from weak clues); nothing of the declared a1.
        assert_eq!(
            marks(
                guessed(Some(VarId(1)), Subject::Local, WEAK),
                guessed(None, Subject::Return, 1)
            ),
            BTreeMap::from([(0, 2), (8, 1), (9, 1), (11, 1)])
        );
        // Defaults are never marked: nothing but the width, or a
        // deduction with no clue; nor is a type a strong clue decided.
        let default = item(
            Some(VarId(1)),
            Subject::Local,
            Evidence::Default,
            Source::Default,
        );
        let clueless = item(None, Subject::Return, Evidence::Deduced, Source::Solver);
        assert!(marks(default, clueless.clone()).is_empty());
        let strong = guessed(Some(VarId(1)), Subject::Local, WEAK + 1);
        assert!(marks(strong.clone(), clueless.clone()).is_empty());
        // The card opens on anything with a source, never on a default.
        let explanation = Explanation {
            entry: 0,
            view: View::Exact,
            items: vec![
                item(
                    Some(VarId(0)),
                    Subject::Local,
                    Evidence::Default,
                    Source::Default,
                ),
                strong,
                Item {
                    name_source: NameSource::User,
                    ..item(
                        Some(VarId(2)),
                        Subject::Local,
                        Evidence::Default,
                        Source::Default,
                    )
                },
                clueless,
            ],
        };
        assert_eq!(item_of(&explanation, VarId(0)), None);
        assert_eq!(item_of(&explanation, VarId(1)), Some(1));
        assert_eq!(item_of(&explanation, VarId(2)), Some(2));
        assert_eq!(item_of(&explanation, VarId(3)), None);
    }

    #[test]
    fn a_cards_evidence_reads_in_c_words() {
        use binbun::queries::evidence::Callee;
        use binbun_typeinfer::Atom;
        let clue = |shape, reason: &str, callee| Clue {
            lower: true,
            shape,
            strength: 3,
            reason: reason.to_owned(),
            callee,
            addresses: vec![0x1cc29],
            path: Vec::new(),
        };
        let strlen = Callee {
            calls: vec![0x1d2f0],
            address: Some(0x1030),
            name: Some("strlen".to_owned()),
            parameter: Some(0),
        };
        let card = super::Card::new(&Item {
            clues: vec![
                clue(
                    BoundShape::Atom(Atom::Unsigned(32)),
                    "zero extension of v7470 at 1CC29",
                    None,
                ),
                clue(
                    BoundShape::Pointer,
                    "argument 1 of a call at 1D2F0",
                    Some(strlen),
                ),
            ],
            ..item(
                Some(VarId(0)),
                Subject::Local,
                Evidence::Deduced,
                Source::Solver,
            )
        });
        let texts: Vec<&str> = card.lines.iter().map(|l| l.text.as_str()).collect();
        assert_eq!(
            texts[2..],
            [
                "≥ uint32_t: zero extension of v7470 at 1CC29",
                "≥ void *: argument 1 of a call at 1D2F0 (strlen)",
            ]
        );
    }

    /// A function's card says where its name comes from: a signature with
    /// its library, object, match and pack; a match the user rejected,
    /// as rejected beside the name that replaced it; the binary's own
    /// names; a script's or the user's rename; binbun's default.
    #[test]
    fn a_function_names_card_says_where_the_name_comes_from() {
        use binbun_session::journal::Origin;
        use binbun_session::signatures::NameSource as Name;
        use binbun_session::{Identified, Matched};
        let strcpy = Identified {
            pack: "musl-1.2.5@1".to_owned(),
            library: "musl".to_owned(),
            version: "1.2.5".to_owned(),
            name: "strcpy".to_owned(),
            object: "src/string/strcpy.o".to_owned(),
            how: Matched::Behaviour {
                states: 48,
                ruled_out: 7,
            },
            prototype: Some("char *strcpy(char *, const char *)".to_owned()),
            no_return: false,
            rejected: false,
        };
        let rows = |card: &super::Card| -> Vec<(String, String)> {
            card.lines
                .iter()
                .map(|l| (l.label.clone(), l.text.clone()))
                .collect()
        };
        let pairs = |list: &[(&str, &str)]| -> Vec<(String, String)> {
            list.iter()
                .map(|(l, t)| ((*l).to_owned(), (*t).to_owned()))
                .collect()
        };
        let card = super::Card::function("strcpy", Some(&Name::Signature), None, Some(&strcpy));
        assert_eq!(card.title, "strcpy");
        assert_eq!(
            rows(&card),
            pairs(&[
                ("name", "signature"),
                ("library", "musl 1.2.5"),
                ("object", "src/string/strcpy.o"),
                ("match", "behaviour: 48 of 48 states agreed, 7 ruled out"),
                ("pack", "musl-1.2.5@1"),
                ("type", "char *strcpy(char *, const char *)"),
            ])
        );
        assert_eq!(card.label_chars(), "library".len());
        // Rejected, and renamed since by the user: the name is theirs,
        // the match still said, as rejected; one declared noreturn says
        // so.
        let rejected = Identified {
            rejected: true,
            how: Matched::Exact,
            prototype: None,
            no_return: true,
            ..strcpy
        };
        let card = super::Card::function(
            "copy_name",
            Some(&Name::Edit(Origin::User)),
            None,
            Some(&rejected),
        );
        assert_eq!(
            rows(&card),
            pairs(&[
                ("name", "your rename"),
                ("rejected", "strcpy"),
                ("library", "musl 1.2.5"),
                ("object", "src/string/strcpy.o"),
                ("match", "exact"),
                ("pack", "musl-1.2.5@1"),
                ("returns", "declared noreturn (library signature)"),
            ])
        );
        // No signature: one line, the name's source.
        for (source, text) in [
            (Some(Name::Symbol), "symbol"),
            (Some(Name::Debug), "debug information"),
            (
                Some(Name::Edit(Origin::Script("rename.py".to_owned()))),
                "script rename.py",
            ),
            (None, "default"),
        ] {
            let card = super::Card::function("f", source.as_ref(), None, None);
            assert_eq!(rows(&card), pairs(&[("name", text)]), "{source:?}");
        }
        // An agent's rename: by the agent's name when known.
        let agent = Some(Name::Edit(Origin::Agent));
        let card = super::Card::function("f", agent.as_ref(), Some("Codex"), None);
        assert_eq!(rows(&card), pairs(&[("name", "Codex")]));
        let card = super::Card::function("f", agent.as_ref(), None, None);
        assert_eq!(rows(&card), pairs(&[("name", "an agent")]));
    }
}
