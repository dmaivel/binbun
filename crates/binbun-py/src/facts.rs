//! What binbun answers about a function, each a question the session's
//! lanes answer (kept per function, view and question): verification,
//! why its variables are as they are, origins, a run, the stages of its
//! decompilation. Waited for with the GIL released; Ctrl-C cancels the
//! question.

use std::collections::BTreeMap;
use std::sync::Arc;

use binbun::profile::{self, Profile};
use binbun::queries::evidence::{NameSource, Source};
use binbun::queries::origin::{Kind as StepKind, Start, Step};
use binbun::queries::verify::{Difference, Verdict};
use binbun::run::{ExampleState, Stop};
use binbun::stages::Level;
use binbun_ast::ir::Node;
use binbun_protocol::Viewed;
use binbun_protocol::talk::{EvidenceRefData, VariableData};
use binbun_session::{Answer, Question, Unanswered, View};
use pyo3::exceptions::{PyTypeError, PyValueError};
use pyo3::prelude::*;

use crate::database::view_object;
use crate::document::{CToken, CVariable};
use crate::errors::{Raise, named};
use crate::functions::Function;
use crate::remote::cited;
use crate::wait::wait_for;

/// Asks `question` of `function` in `view` and waits for the answer.
///
/// # Errors
///
/// No function; the timeout (the question goes on); Ctrl-C (it is
/// cancelled); never answered.
fn ask(
    py: Python<'_>,
    function: &Function,
    view: View,
    question: Question,
    timeout: Option<f64>,
) -> PyResult<Answer> {
    let (session, id) = function.resolve(py)?;
    let asked = session.ask(id, view, question);
    let waited = wait_for(
        py,
        timeout,
        "waiting for the answer",
        |slice| match asked.wait(Some(slice)) {
            Err(Unanswered::TimedOut) => None,
            done @ (Ok(_) | Err(Unanswered::Cancelled | Unanswered::Dropped)) => Some(done),
        },
        || asked.cancel(),
    )?;
    waited.map_err(|why| match why {
        Unanswered::Cancelled => Raise::Cancelled.err(py, "the question was cancelled"),
        Unanswered::TimedOut | Unanswered::Dropped => {
            Raise::Binbun.err(py, "the question is not answered: the session stopped")
        }
    })
}

/// The answer was not of the question's kind (never: each question has
/// its own).
fn mismatched(py: Python<'_>) -> PyErr {
    Raise::Binbun.err(py, "the answer is to another question")
}

/// Whether a function's C does what its machine code does: the
/// differential check's verdict (`binbun verify`). As evidence
/// (`evidence=[...]`): the verdict of its function in its view.
#[pyclass(frozen, module = "binbun._native")]
#[derive(Debug)]
pub(crate) struct Verification {
    /// The function.
    #[pyo3(get)]
    function: Function,
    view: View,
    /// `agreed`, `differs` or `not_checkable`.
    #[pyo3(get)]
    verdict: &'static str,
    /// States run (agreed).
    #[pyo3(get)]
    states: usize,
    /// States where both runs ended the same way (agreed).
    #[pyo3(get)]
    agreed: usize,
    /// States not compared, by why (agreed).
    #[pyo3(get)]
    skips: BTreeMap<&'static str, usize>,
    /// How it differs: `structure` or `run` (differs).
    #[pyo3(get)]
    difference: Option<&'static str>,
    /// What differs, or why it cannot be checked.
    #[pyo3(get)]
    message: Option<String>,
    /// The counterexample's seed and index among the states (a run that
    /// differs).
    #[pyo3(get)]
    counterexample: Option<(u64, usize)>,
    /// The instructions where the runs part (a run that differs).
    #[pyo3(get)]
    addresses: Vec<u64>,
    /// The fuel the runs had (blocks L1 may enter per run).
    #[pyo3(get)]
    fuel: u64,
    /// Seconds spent lowering.
    #[pyo3(get)]
    lowering_s: f64,
    /// Seconds spent checking.
    #[pyo3(get)]
    checking_s: f64,
    /// The processor it ran on: a profile's label (`intel-raptor-cove
    /// r1`), or `None` for the architecture.
    #[pyo3(get)]
    profile: Option<String>,
}

#[pymethods]
impl Verification {
    fn __repr__(&self) -> String {
        match self.verdict {
            "agreed" => format!(
                "Verification({:#x}: agreed on {} of {} sampled states)",
                self.function.entry, self.agreed, self.states
            ),
            other => format!(
                "Verification({:#x}: {other}: {})",
                self.function.entry,
                self.message.as_deref().unwrap_or("")
            ),
        }
    }

    /// The view checked.
    #[getter]
    fn view<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        view_object(py, self.view)
    }

    /// What it is cited as: its function's verdict in its view.
    fn _cite(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        cited(
            py,
            &EvidenceRefData::Verification {
                function: self.function.entry,
                view: Viewed::of(self.view),
            },
        )
    }
}

/// `function` checked in `view`.
pub(crate) fn verify(
    py: Python<'_>,
    function: &Function,
    view: View,
    profile: Option<&str>,
    timeout: Option<f64>,
) -> PyResult<Verification> {
    let profile = processor(profile)?;
    let label = profile.as_ref().map(|profile| profile.label());
    let Answer::Verified(v) = ask(py, function, view, Question::Verify(profile), timeout)? else {
        return Err(mismatched(py));
    };
    let mut out = Verification {
        function: Function::new(&function.db, v.entry),
        view: v.view,
        verdict: "agreed",
        states: 0,
        agreed: 0,
        skips: BTreeMap::new(),
        difference: None,
        message: None,
        counterexample: None,
        addresses: Vec::new(),
        fuel: v.fuel,
        lowering_s: v.lowering.as_secs_f64(),
        checking_s: v.checking.as_secs_f64(),
        profile: label,
    };
    match &v.verdict {
        Verdict::Agreed(agreement) => {
            out.states = agreement.states;
            out.agreed = agreement.agreed;
            out.skips = agreement
                .skips
                .iter()
                .map(|(skip, &count)| (skip.describe(), count))
                .collect();
        }
        Verdict::Differs(Difference::Structure(mismatch)) => {
            out.verdict = "differs";
            out.difference = Some("structure");
            out.message = Some(mismatch.to_string());
        }
        Verdict::Differs(Difference::Run(counterexample)) => {
            out.verdict = "differs";
            out.difference = Some("run");
            out.message = Some(counterexample.message.clone());
            out.counterexample = Some((counterexample.seed, counterexample.index));
            out.addresses.clone_from(&counterexample.addresses);
        }
        Verdict::NotCheckable(why) => {
            out.verdict = "not_checkable";
            out.message = Some(why.clone());
        }
    }
    Ok(out)
}

/// Why each variable of a function has its type and name (`binbun why`).
#[pyclass(frozen, module = "binbun._native")]
#[derive(Debug)]
pub(crate) struct Explanation {
    /// The function.
    #[pyo3(get)]
    function: Function,
    /// One item per variable (and the return value).
    #[pyo3(get)]
    items: Vec<ExplanationItem>,
}

/// Why one variable has its type and name. As evidence (`evidence=[...]`):
/// why its variable has them, in the view asked (the return value's item
/// names no variable: not cited).
#[pyclass(frozen, module = "binbun._native")]
#[derive(Clone, Debug)]
pub(crate) struct ExplanationItem {
    /// Its function.
    #[pyo3(get)]
    function: Function,
    /// The view asked.
    view: View,
    /// The L2 variable, if it is one (not the return value).
    #[pyo3(get)]
    var: Option<u32>,
    /// Its variable's identity (what it was made from, its place among
    /// those), where the session has it.
    identity: Option<(Vec<String>, usize)>,
    /// Its name.
    #[pyo3(get)]
    name: String,
    /// Where the name comes from: `user`, `debug`, `symbol`,
    /// `convention`, `declared`, `argument`, `counter`, `result`,
    /// `printer`.
    #[pyo3(get)]
    name_source: &'static str,
    /// Its type, as C.
    #[pyo3(get, name = "type")]
    r#type: String,
    /// Where the type comes from: `user`, `debug`, `prototype`,
    /// `platform`, `declaration`, `promoted`, `callee`, `scheme`,
    /// `callers`, `program`, `solver`, `default`.
    #[pyo3(get)]
    source: &'static str,
    /// The solver's clues for it, as their reasons.
    #[pyo3(get)]
    clues: Vec<String>,
    /// The clues that lost a conflict.
    #[pyo3(get)]
    conflicts: Vec<String>,
}

#[pymethods]
impl ExplanationItem {
    fn __repr__(&self) -> String {
        format!(
            "ExplanationItem({:?}: {} from {}, named by {})",
            self.name, self.r#type, self.source, self.name_source
        )
    }

    /// The view asked: a `View`.
    #[getter]
    fn view<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        view_object(py, self.view)
    }

    /// What it is cited as: why its variable has its type and name.
    fn _cite(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        let Some((origins, ordinal)) = &self.identity else {
            return Err(PyValueError::new_err(if self.var.is_none() {
                "the return value's item names no variable: it cannot be cited"
            } else {
                "its variable's identity is not available: it cannot be cited"
            }));
        };
        cited(
            py,
            &EvidenceRefData::Why {
                view: Viewed::of(self.view),
                variable: VariableData {
                    function: self.function.entry,
                    origins: origins.clone(),
                    ordinal: *ordinal,
                },
            },
        )
    }
}

const fn name_source(source: NameSource) -> &'static str {
    match source {
        NameSource::User => "user",
        NameSource::Debug => "debug",
        NameSource::Symbol => "symbol",
        NameSource::Convention => "convention",
        NameSource::Declared => "declared",
        NameSource::Argument => "argument",
        NameSource::Counter => "counter",
        NameSource::Result => "result",
        NameSource::Printer => "printer",
    }
}

const fn type_source(source: &Source) -> &'static str {
    match source {
        Source::User => "user",
        Source::Debug => "debug",
        Source::Prototype => "prototype",
        Source::Platform => "platform",
        Source::Declaration => "declaration",
        Source::Promoted => "promoted",
        Source::Callee(_) => "callee",
        Source::Scheme(_) => "scheme",
        Source::Callers => "callers",
        Source::Program => "program",
        Source::Solver => "solver",
        Source::Default => "default",
    }
}

/// Why `function`'s variables in `view` are as they are.
pub(crate) fn why(
    py: Python<'_>,
    function: &Function,
    view: View,
    timeout: Option<f64>,
) -> PyResult<Explanation> {
    let Answer::Explained(explained) = ask(py, function, view, Question::Explain, timeout)? else {
        return Err(mismatched(py));
    };
    let explanation = explained.map_err(|message| Raise::Decompile.err(py, message))?;
    let (session, id) = function.resolve(py)?;
    // Its variables' identities are read from the decompilation its
    // document is printed from.
    let documented = py.detach(|| session.document_view(id, view)).is_ok();
    let of = Function::new(&function.db, explanation.entry);
    Ok(Explanation {
        function: of.clone(),
        items: explanation
            .items
            .iter()
            .map(|item| ExplanationItem {
                function: of.clone(),
                view,
                var: item.var.map(|v| v.0),
                identity: item
                    .var
                    .filter(|_| documented)
                    .and_then(|var| session.variable(id, view, var).ok())
                    .map(|variable| (variable.origins, variable.ordinal)),
                name: item.name.clone(),
                name_source: name_source(item.name_source),
                r#type: item.ty.clone(),
                source: type_source(&item.source),
                clues: item.clues.iter().map(|c| c.reason.clone()).collect(),
                conflicts: item.conflicts.iter().map(|c| c.reason.clone()).collect(),
            })
            .collect(),
    })
}

/// Where a value comes from and where it goes (`binbun origin`).
#[pyclass(frozen, module = "binbun._native")]
#[derive(Debug)]
pub(crate) struct Origins {
    /// The function.
    #[pyo3(get)]
    function: Function,
    /// Each value's chain back to where it comes from.
    #[pyo3(get)]
    chains: Vec<OriginStep>,
    /// Where the values go.
    uses: Vec<(u64, String)>,
}

#[pymethods]
impl Origins {
    fn __repr__(&self) -> String {
        format!(
            "Origins({:#x}: {} chains, {} uses)",
            self.function.entry,
            self.chains.len(),
            self.uses.len()
        )
    }

    /// Where the values go: `binbun.Use(address, how)`s.
    #[getter]
    fn uses<'py>(&self, py: Python<'py>) -> PyResult<Vec<Bound<'py, PyAny>>> {
        self.uses
            .iter()
            .map(|(address, how)| named(py, "Use", (*address, how.as_str())))
            .collect()
    }
}

/// A step of a value's origin: the value, what made it, the
/// instructions, the steps it was made from.
#[pyclass(frozen, get_all, module = "binbun._native")]
#[derive(Clone, Debug)]
pub(crate) struct OriginStep {
    /// The L1 value (`v12`). Unstable.
    value: String,
    /// What made it: `constant`, `undefined`, `parameter`, `load`,
    /// `call`, `operation`, `join`, `other` or `cut`.
    kind: &'static str,
    /// What made it, in words (the constant, the register, the address
    /// loaded, the callee, the operation).
    detail: String,
    /// The instructions it was made at.
    addresses: Vec<u64>,
    /// The steps it was made from.
    inputs: Vec<OriginStep>,
}

#[pymethods]
impl OriginStep {
    fn __repr__(&self) -> String {
        if self.detail.is_empty() {
            format!("OriginStep({}: {})", self.value, self.kind)
        } else {
            format!(
                "OriginStep({}: {} {:?})",
                self.value, self.kind, self.detail
            )
        }
    }
}

/// `step` as an [`OriginStep`].
fn origin_step(step: &Step) -> OriginStep {
    let (kind, detail) = match &step.kind {
        StepKind::Constant(value) => ("constant", format!("{value:#x}")),
        StepKind::Undefined => ("undefined", String::new()),
        StepKind::Parameter { register, .. } => ("parameter", register.clone()),
        StepKind::Load { address, bytes } => ("load", format!("{bytes} bytes at {address}")),
        StepKind::Call { call, name, .. } => {
            ("call", name.clone().unwrap_or_else(|| format!("{call:#x}")))
        }
        StepKind::Operation(operation) => ("operation", operation.clone()),
        StepKind::Join => ("join", String::new()),
        StepKind::Other(what) => ("other", what.clone()),
        StepKind::Cut => ("cut", String::new()),
    };
    OriginStep {
        value: format!("v{}", step.value.0),
        kind,
        detail,
        addresses: step.addresses.clone(),
        inputs: step.inputs.iter().map(origin_step).collect(),
    }
}

/// Where the value `of` (a `CVariable`, or a `CToken`'s node) of
/// `function` in `view` comes from.
pub(crate) fn origins(
    py: Python<'_>,
    function: &Function,
    of: &Bound<'_, PyAny>,
    view: View,
    timeout: Option<f64>,
) -> PyResult<Origins> {
    let start = if let Ok(variable) = of.cast::<CVariable>() {
        Start::Var(variable.get().var())
    } else if let Ok(token) = of.cast::<CToken>() {
        match token.get().node {
            Some(Node::Var(var)) => Start::Var(var),
            Some(node) => Start::Node(node),
            None => return Err(PyValueError::new_err("the token stands for no node")),
        }
    } else {
        return Err(PyTypeError::new_err("origins of a CVariable or a CToken"));
    };
    let Answer::Origins(found) = ask(py, function, view, Question::Origins(start), timeout)? else {
        return Err(mismatched(py));
    };
    let found = found.map_err(|message| Raise::Decompile.err(py, message))?;
    Ok(Origins {
        function: Function::new(&function.db, found.entry),
        chains: found.chains.iter().map(origin_step).collect(),
        uses: found
            .uses
            .iter()
            .map(|u| (u.address, u.kind.clone()))
            .collect(),
    })
}

/// A function's C and its machine code run from an example state
/// (`binbun run`).
#[pyclass(frozen, get_all, module = "binbun._native")]
#[derive(Debug)]
pub(crate) struct Run {
    /// Where both returned, whether the machine's result is the C's; where
    /// both stopped at a call needing a stub, whether the same callee;
    /// else `None`.
    agree: Option<bool>,
    /// How the C's run stopped: `returned`, `needs_stub`, `fault`, `trap`,
    /// `undetermined`, `escape`, `unreachable`, `out_of_steps`,
    /// `cancelled` or `malformed`.
    stop: &'static str,
    /// How it stopped, in words (the value returned, the access that
    /// faulted, the callee needing a stub).
    detail: String,
    /// The statements the C's run executed.
    statements: usize,
    /// The calls it made.
    calls: usize,
    /// Whether the machine code ran too.
    machine: bool,
    /// The processor it ran on: a profile's label (`intel-raptor-cove
    /// r1`), or `None` for the architecture.
    profile: Option<String>,
}

#[pymethods]
impl Run {
    fn __repr__(&self) -> String {
        let agree = match self.agree {
            Some(true) => "True",
            Some(false) => "False",
            None => "None",
        };
        format!("Run(agree={agree}, stop={}, {:?})", self.stop, self.detail)
    }
}

/// `stop`'s word.
const fn stop_word(stop: &Stop) -> &'static str {
    match stop {
        Stop::Returned(_) => "returned",
        Stop::NeedsStub { .. } => "needs_stub",
        Stop::Fault { .. } => "fault",
        Stop::Trap(_) => "trap",
        Stop::Undetermined => "undetermined",
        Stop::Escape(_) => "escape",
        Stop::Unreachable => "unreachable",
        Stop::OutOfSteps => "out_of_steps",
        Stop::Cancelled => "cancelled",
        Stop::Malformed => "malformed",
    }
}

/// `function` run in `view` from the example state `state` (TOML;
/// `None`: a scratch state).
pub(crate) fn run(
    py: Python<'_>,
    function: &Function,
    state: Option<&str>,
    view: View,
    profile: Option<&str>,
    timeout: Option<f64>,
) -> PyResult<Run> {
    let state = match state {
        None => ExampleState::scratch("scratch"),
        Some(toml) => ExampleState::parse(toml).map_err(PyValueError::new_err)?,
    };
    let profile = processor(profile)?;
    let label = profile.as_ref().map(|profile| profile.label());
    let question = Question::Run(Arc::new(state), profile);
    let Answer::Ran(ran) = ask(py, function, view, question, timeout)? else {
        return Err(mismatched(py));
    };
    let ran = ran.map_err(|message| Raise::Decompile.err(py, message))?;
    Ok(Run {
        agree: ran.agree,
        stop: stop_word(&ran.c.stop),
        detail: ran.c.stop.to_string(),
        statements: ran.c.statements.len(),
        calls: ran.c.calls.len(),
        machine: ran.machine.is_some(),
        profile: label,
    })
}

/// The processor profile named `name` (a shipped one's name or a file).
fn processor(name: Option<&str>) -> PyResult<Option<Arc<Profile>>> {
    name.map(|name| profile::resolve(name).map_err(PyValueError::new_err))
        .transpose()
}

/// A function through every stage of decompilation (`binbun stages`),
/// as text. Unstable: the stages and their text change with the engine.
#[pyclass(frozen, module = "binbun._native")]
#[derive(Debug)]
pub(crate) struct Stages {
    /// The function.
    #[pyo3(get)]
    function: Function,
    /// The stages, in order.
    #[pyo3(get)]
    stages: Vec<StageText>,
}

#[pymethods]
impl Stages {
    fn __repr__(&self) -> String {
        format!(
            "Stages({:#x}, {} stages)",
            self.function.entry,
            self.stages.len()
        )
    }

    fn __len__(&self) -> usize {
        self.stages.len()
    }

    /// The stage named `name` (`machine`, a pass's name, `c`), if there
    /// is one.
    fn get(&self, name: &str) -> Option<StageText> {
        self.stages.iter().find(|s| s.name == name).cloned()
    }

    /// The names of the stages, in order.
    fn names(&self) -> Vec<String> {
        self.stages.iter().map(|s| s.name.clone()).collect()
    }
}

/// One stage of a function's decompilation, as text. Unstable.
#[pyclass(frozen, get_all, module = "binbun._native")]
#[derive(Clone, Debug)]
pub(crate) struct StageText {
    /// Its name.
    name: String,
    /// What the viewer calls it.
    label: String,
    /// `machine`, `l1`, `l2` or `c`.
    level: &'static str,
    /// Its text.
    text: String,
    /// The instructions each line came from.
    lines: Vec<Vec<u64>>,
}

#[pymethods]
impl StageText {
    fn __repr__(&self) -> String {
        format!("StageText({:?}, {} lines)", self.name, self.lines.len())
    }
}

/// `level`'s name.
const fn level_name(level: Level) -> &'static str {
    match level {
        Level::Machine => "machine",
        Level::L1 => "l1",
        Level::L2 => "l2",
        Level::C => "c",
    }
}

/// `function`'s stages in `view`.
pub(crate) fn stages(
    py: Python<'_>,
    function: &Function,
    view: View,
    timeout: Option<f64>,
) -> PyResult<Stages> {
    let Answer::Staged(staged) = ask(py, function, view, Question::Stages, timeout)? else {
        return Err(mismatched(py));
    };
    let staged = staged.map_err(|message| Raise::Decompile.err(py, message))?;
    Ok(Stages {
        function: Function::new(&function.db, staged.entry),
        stages: staged
            .stages
            .iter()
            .map(|stage| StageText {
                name: stage.name.to_owned(),
                label: stage.label.clone(),
                level: level_name(stage.level),
                text: stage.text.clone(),
                lines: stage.lines.iter().map(|l| l.addresses.clone()).collect(),
            })
            .collect(),
    })
}
