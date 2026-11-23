//! A call site as the C shows it ([`Site`]): the call in the caller's L2
//! whose provenance names the call instruction (a call statement, or a
//! call inside an expression), and each argument's known value where the
//! call runs: a constant (a global's address among them: a string
//! literal's), or the range the range facts give it (the conditions
//! before the call that it passed, a variable's last write of a
//! constant: [`Values`]), so a list of callers can be sorted by an
//! argument ("which callers pass a size above 0x100?").

use binbun_ast::ir::{Expr, ExprId, Function as Ast, Node, Origin, Stmt, StmtId, VarKind};
use binbun_decompile::range::{Bounds, Interval, Values};

/// What is known of an argument's value at a call.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Known {
    /// One value (its bits, read unsigned).
    Constant(u64),
    /// The values from `lo` to `hi`, read signed or not.
    Range {
        /// The least.
        lo: i128,
        /// The greatest.
        hi: i128,
        /// Whether read signed.
        signed: bool,
    },
    /// Nothing.
    Unknown,
}

impl Known {
    /// What `bounds` say: one value, else the narrower of its readings if
    /// either is narrower than every value.
    fn of(bounds: Bounds) -> Self {
        if let Some(value) = bounds.constant() {
            return Self::Constant(u64::try_from(value).unwrap_or(u64::MAX));
        }
        if !bounds.known() {
            return Self::Unknown;
        }
        let span = |i: Interval| i.hi - i.lo;
        let (interval, signed) = if span(bounds.signed) < span(bounds.unsigned) {
            (bounds.signed, true)
        } else {
            (bounds.unsigned, false)
        };
        Self::Range {
            lo: interval.lo,
            hi: interval.hi,
            signed,
        }
    }

    /// Its least value, for sorting (unknown last).
    pub fn key(&self) -> Option<i128> {
        match *self {
            Self::Constant(value) => Some(i128::from(value)),
            Self::Range { lo, .. } => Some(lo),
            Self::Unknown => None,
        }
    }
}

/// A call site in a caller's L2.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Site {
    /// The call instruction.
    pub at: u64,
    /// The node standing for the call: its statement, or its expression.
    pub node: Node,
    /// The statement making it.
    pub statement: StmtId,
    /// What is known of each argument, in order.
    pub arguments: Vec<Known>,
}

/// The call sites of `l2` made by the instructions at `at`, each `None` if
/// no call of `l2` names it.
pub fn sites(l2: &Ast, at: &[u64]) -> Vec<Option<Site>> {
    let values = Values::new(l2);
    let live = live(l2);
    at.iter()
        .map(|&address| site(l2, &values, &live, address))
        .collect()
}

/// Whether each statement of `l2`'s arena is in its body: one a pass took
/// out (a call whose value moved into its one reader) keeps its origins,
/// but makes no call.
fn live(l2: &Ast) -> Vec<bool> {
    let mut live = vec![false; l2.stmts.len()];
    let mut blocks = vec![&l2.body];
    while let Some(block) = blocks.pop() {
        for &id in block {
            if let Some(stmt) = l2.stmt(id)
                && let Some(slot) = live.get_mut(id.0 as usize)
                && !*slot
            {
                *slot = true;
                blocks.extend(stmt.blocks());
            }
        }
    }
    live
}

/// The call site of `l2` (whose range facts are `values`) made by the
/// instruction at `at`, among its statements in the body (`live`).
fn site(l2: &Ast, values: &Values<'_>, live: &[bool], at: u64) -> Option<Site> {
    let here = |origins: &[Origin]| origins.contains(&Origin::Instruction(at));
    let mut in_body =
        (l2.stmts.iter().zip(0u32..).zip(live)).filter_map(|(pair, &live)| live.then_some(pair));
    let statement = in_body.find_map(|(stmt, id)| {
        let id = StmtId(id);
        match stmt {
            Stmt::Call { call, .. } if here(l2.provenance.stmt(id)) => {
                Some((Node::Stmt(id), id, call))
            }
            Stmt::Call { .. }
            | Stmt::Assign { .. }
            | Stmt::Intrinsic { .. }
            | Stmt::Expr(_)
            | Stmt::If { .. }
            | Stmt::While { .. }
            | Stmt::DoWhile { .. }
            | Stmt::For { .. }
            | Stmt::Switch { .. }
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
    });
    let (node, statement, call) = statement.or_else(|| {
        l2.exprs.iter().zip(0u32..).find_map(|(expr, id)| {
            let id = ExprId(id);
            let &Expr::Call(call) = expr else {
                return None;
            };
            here(l2.provenance.expr(id)).then_some(())?;
            Some((Node::Expr(id), values.statement(id)?, l2.call(call)?))
        })
    })?;
    let arguments = call
        .arguments
        .iter()
        .map(|&argument| known(l2, values, statement, argument))
        .collect();
    Some(Site {
        at,
        node,
        statement,
        arguments,
    })
}

/// What is known of `argument` of `l2` where `statement` runs.
fn known(l2: &Ast, values: &Values<'_>, statement: StmtId, argument: ExprId) -> Known {
    let mut at = argument;
    while let Some(&Expr::Cast { value, .. }) = l2.expr(at) {
        at = value;
    }
    if let Some(&Expr::AddressOf(var)) = l2.expr(at)
        && let Some(VarKind::Global(address)) = l2.var(var).map(|v| v.kind)
    {
        return Known::Constant(address);
    }
    values
        .at(statement, argument)
        .map_or(Known::Unknown, Known::of)
}
