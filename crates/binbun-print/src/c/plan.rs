//! The conversion plan: for each use of a value in a function's C (an
//! operand, an argument, an assignment's value, a condition, …), what
//! the use asks of the value, what the value is ([`Form`]), and the
//! conversions [`super::convert`]'s rules give, by statement; the casts
//! each statement prints; and the C types chosen for variables.
//!
//! The plan is made by the printer itself in a walk that notes each
//! conversion it decides and discards the tokens ([`Planner`]): one place
//! for each rule, at the cost of printing the body once more. Printing
//! then follows it ([`planned`]): the printer still decides each
//! conversion by the rules, so a value is never printed wrong, and counts
//! each the plan lacks or gives otherwise ([`super::Counts::unplanned`]).
//!
//! A [`Planner`] plans statements again under other types for variables
//! ([`Planner::retype`], [`Planner::replan`]), to compare what each
//! choice costs ([`Plan::statement`]).

use alloc::boxed::Box;
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

use binbun_ast::ir::{Function, Node, StmtId, VarId};
use binbun_ast::types::Type;
use binbun_semantics::Declarations;

use super::convert::{Ask, Class, Conversion, Form, Operands, Refusal};
use super::{Image, Opaque, PrintError, Printed, Printer};
use crate::document::{Doc, TokenKind};
use crate::style::Style;

/// A use of one value: what it asks, what the value is, and the
/// conversion the rules give.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct One {
    /// The node being printed: what uses the value.
    pub node: Option<Node>,
    pub ask: Ask,
    pub form: Form,
    pub conversion: Result<Conversion, Refusal>,
}

/// A use of an operation's two operands: what it asks
/// ([`super::convert::operands`]), what they are, and their conversions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Two {
    /// The node being printed: the operation.
    pub node: Option<Node>,
    pub need: Class,
    pub compare: bool,
    pub bitwise: bool,
    pub forms: (Form, Form),
    pub operands: Operands,
}

/// One use's conversions, as decided.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Entry {
    One(One),
    Two(Box<Two>),
}

impl Entry {
    /// How many conversions it makes that are not implicit: casts,
    /// literals printed again, helpers and masks.
    fn conversions(&self) -> usize {
        match self {
            Self::One(one) => usize::from(matches!(
                one.conversion,
                Ok(conversion) if conversion != Conversion::Keep
            )),
            Self::Two(two) => two
                .operands
                .steps()
                .iter()
                .filter(|(_, conversion)| *conversion != Conversion::Keep)
                .count(),
        }
    }
}

/// What printing a statement costs, or a whole function.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Cost {
    /// Casts printed (each `(T)`), but those of the statements it holds.
    pub casts: usize,
    /// Conversions that are not implicit: casts, literals printed again,
    /// helpers and masks.
    pub conversions: usize,
}

/// The uses planned in one statement, in the order printed, and its own
/// casts.
#[derive(Clone, Debug, Default)]
struct Planned {
    uses: Vec<Entry>,
    casts: usize,
}

/// Where a statement is printed: the loops and switches around it,
/// innermost last, and how deep its block nests.
#[derive(Clone, Debug, Default)]
pub(super) struct Site {
    pub breakable: Vec<StmtId>,
    pub nesting: usize,
}

/// A function's conversion plan.
#[derive(Clone, Debug, Default)]
pub struct Plan {
    /// By statement (`None`: outside every statement).
    statements: BTreeMap<Option<StmtId>, Planned>,
    /// Where each statement was printed ([`Planner::replan`]).
    sites: BTreeMap<StmtId, Site>,
    /// The variables' types chosen for printing, in place of their L2
    /// types.
    types: BTreeMap<VarId, Type>,
}

impl Plan {
    /// What printing statement `id` costs (not the statements it holds).
    pub fn statement(&self, id: StmtId) -> Cost {
        self.statements
            .get(&Some(id))
            .map_or_else(Cost::default, |planned| Cost {
                casts: planned.casts,
                conversions: planned.uses.iter().map(Entry::conversions).sum(),
            })
    }

    /// What printing the body costs: its statements' costs together.
    pub fn cost(&self) -> Cost {
        self.statements
            .keys()
            .flatten()
            .map(|&id| self.statement(id))
            .fold(Cost::default(), |sum, cost| Cost {
                casts: sum.casts + cost.casts,
                conversions: sum.conversions + cost.conversions,
            })
    }

    /// The variables' types chosen for printing, in place of their L2
    /// types ([`Planner::retype`]).
    pub fn types(&self) -> &BTreeMap<VarId, Type> {
        &self.types
    }
}

/// Whether the printer makes a plan or follows one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Record,
    Follow,
}

/// The plan a printer makes or follows, as it prints.
#[derive(Debug)]
pub(super) struct Ledger {
    mode: Mode,
    plan: Plan,
    /// The statements being printed, innermost last.
    open: Vec<StmtId>,
    /// Following: the uses of each statement met so far.
    cursors: BTreeMap<Option<StmtId>, usize>,
    /// Making: the statements whose uses this walk makes again.
    walked: BTreeSet<Option<StmtId>>,
    /// Making: the casts of the statements printed so far, those they
    /// hold counted once.
    counted: usize,
    /// Following: the uses the plan lacks or gives otherwise.
    unplanned: usize,
}

impl Ledger {
    /// A plan to make, from `plan`.
    pub(super) fn making(plan: Plan) -> Self {
        Self::new(Mode::Record, plan)
    }

    /// `plan` to follow.
    fn following(plan: Plan) -> Self {
        Self::new(Mode::Follow, plan)
    }

    fn new(mode: Mode, plan: Plan) -> Self {
        Self {
            mode,
            plan,
            open: Vec::new(),
            cursors: BTreeMap::new(),
            walked: BTreeSet::new(),
            counted: 0,
            unplanned: 0,
        }
    }

    /// The uses the plan lacked or gave otherwise.
    pub(super) const fn unplanned(&self) -> usize {
        self.unplanned
    }

    /// The variables' types chosen ([`Plan::types`]).
    pub(super) const fn types(&self) -> &BTreeMap<VarId, Type> {
        &self.plan.types
    }

    /// The statement `id`'s record, made again if this walk has not
    /// printed it yet.
    fn record(&mut self, id: Option<StmtId>) -> &mut Planned {
        if self.walked.insert(id) {
            self.plan.statements.insert(id, Planned::default());
        }
        self.plan.statements.entry(id).or_default()
    }

    /// `one`, decided in the statement being printed: noted, or checked
    /// against the plan.
    pub(super) fn note_one(&mut self, one: One) {
        match self.mode {
            Mode::Record => self.push(Entry::One(one)),
            Mode::Follow => self.check(|planned| matches!(planned, Entry::One(p) if *p == one)),
        }
    }

    /// `two`, decided in the statement being printed: noted, or checked
    /// against the plan.
    pub(super) fn note_two(&mut self, two: Two) {
        match self.mode {
            Mode::Record => self.push(Entry::Two(Box::new(two))),
            Mode::Follow => self.check(|planned| matches!(planned, Entry::Two(p) if **p == two)),
        }
    }

    /// `entry` noted in the statement being printed.
    fn push(&mut self, entry: Entry) {
        let id = self.open.last().copied();
        self.record(id).uses.push(entry);
    }

    /// The next use the plan has in the statement being printed, counted
    /// unplanned unless it is there and `holds` of it.
    fn check(&mut self, holds: impl FnOnce(&Entry) -> bool) {
        let id = self.open.last().copied();
        let cursor = self.cursors.entry(id).or_insert(0);
        let planned = self
            .plan
            .statements
            .get(&id)
            .and_then(|planned| planned.uses.get(*cursor));
        *cursor += 1;
        if !planned.is_some_and(holds) {
            self.unplanned += 1;
        }
    }

    /// Statement `id` starts printing, at `site`; gives the casts
    /// counted so far ([`Self::leave`]).
    pub(super) fn enter(&mut self, id: StmtId, site: impl FnOnce() -> Site) -> usize {
        self.open.push(id);
        if self.mode == Mode::Record {
            self.record(Some(id));
            self.plan.sites.insert(id, site());
        }
        self.counted
    }

    /// Statement `id` printed as `docs`, `before` the casts counted when
    /// it started ([`Self::enter`]).
    pub(super) fn leave(&mut self, id: StmtId, before: usize, docs: &[&[Doc]]) {
        self.open.pop();
        if self.mode == Mode::Record {
            let total: usize = docs.iter().map(|docs| casts(docs)).sum();
            let held = self.counted.saturating_sub(before);
            self.record(Some(id)).casts += total.saturating_sub(held);
            self.counted = before + total;
        }
    }

    /// Statement `id` will be planned again: where it was printed.
    fn again(&mut self, id: StmtId) -> Option<Site> {
        self.open.clear();
        self.walked.clear();
        self.plan.sites.get(&id).cloned()
    }
}

/// The casts in `docs`: their operator parentheses.
fn casts(docs: &[Doc]) -> usize {
    docs.iter()
        .map(|doc| match doc {
            Doc::Token(token) => {
                usize::from(token.kind == TokenKind::Operator && token.text == "(")
            }
            Doc::Group(items)
            | Doc::Nest(items)
            | Doc::Outdent(items)
            | Doc::Block { body: items, .. } => casts(items),
            Doc::Space
            | Doc::Line
            | Doc::SoftLine
            | Doc::HardLine
            | Doc::BlankLine
            | Doc::AfterBlock => 0,
        })
        .sum()
}

/// A function's conversion plan as it is made: the body printed once,
/// its tokens discarded; then statements planned again under other types
/// for variables.
pub struct Planner<'a> {
    printer: Printer<'a>,
}

impl core::fmt::Debug for Planner<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Planner")
            .field("plan", &self.printer.ledger.plan)
            .finish_non_exhaustive()
    }
}

impl<'a> Planner<'a> {
    /// The plan of `function` as [`super::shown`] gives it, printed under
    /// `style` as [`super::function`] prints it.
    ///
    /// # Errors
    ///
    /// The printer refuses the function.
    pub fn new(
        function: &'a Function,
        declarations: &'a Declarations,
        style: &'a Style,
        image: &'a dyn Image,
        opaque: Opaque,
    ) -> Result<Self, PrintError> {
        let mut printer = Printer::started(
            function,
            declarations,
            style,
            image,
            opaque,
            Ledger::making(Plan::default()),
        )?;
        printer.block(&function.body)?;
        Ok(Self { printer })
    }

    /// The plan so far.
    pub fn plan(&self) -> &Plan {
        &self.printer.ledger.plan
    }

    /// The plan.
    pub fn into_plan(self) -> Plan {
        self.printer.ledger.plan
    }

    /// Variable `var` printed as of type `ty` from now on (`None`: its L2
    /// type). The statements already planned keep their plans
    /// ([`Self::replan`]).
    pub fn retype(&mut self, var: VarId, ty: Option<Type>) {
        if let Some(ty) = ty {
            let id = self.printer.types.intern(ty.clone());
            self.printer.var_types.insert(var, id);
            self.printer.ledger.plan.types.insert(var, ty);
        } else {
            self.printer.var_types.remove(&var);
            self.printer.ledger.plan.types.remove(&var);
        }
    }

    /// Statements `ids` planned again, each with the statements it holds,
    /// where the plan printed them.
    ///
    /// # Errors
    ///
    /// The printer refuses one of them (as it is now typed).
    pub fn replan(&mut self, ids: &[StmtId]) -> Result<(), PrintError> {
        for &id in ids {
            let site = self.printer.ledger.again(id).unwrap_or_default();
            self.printer.replan(id, site)?;
        }
        Ok(())
    }
}

/// `function` as [`super::shown`] gives it, as C printed under `style`
/// following `plan` (made for the same function, declarations, style,
/// image and view): as [`super::function`] prints it, with the variables'
/// types `plan` chose ([`Plan::types`]) and its conversions checked
/// ([`super::Counts::unplanned`]).
///
/// # Errors
///
/// The printer refuses the function.
pub fn planned(
    function: &Function,
    declarations: &Declarations,
    style: &Style,
    image: &dyn Image,
    opaque: Opaque,
    plan: Plan,
) -> Result<Printed, PrintError> {
    Printer::started(
        function,
        declarations,
        style,
        image,
        opaque,
        Ledger::following(plan),
    )?
    .finish()
}
