//! Names for an L2 function's variables from evidence, strongest first:
//! debug information and the convention (named in lowering, kept), the
//! function's own declared parameter names, the declared names of the
//! callees' parameters a variable is passed as (`fd`, `buf`, `stream`),
//! then structural roles: the counter a `for` loop steps (`i`, `j`, `k`
//! by how many `for`s enclose it) and the one variable the function
//! returns (`result`).
//!
//! Each variable gets one name, of its strongest evidence; of several of
//! that strength, the one seen most (then the first in order). Declared
//! names lose their leading underscores (glibc's `__fd` is `fd`). Names
//! are presentation only and carry their origin ([`NameOrigin`]); the
//! printer makes them unique C identifiers.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use binbun_ast::ir::{
    Block, Call, Callee, Expr, ExprId, Function, Name, NameOrigin, Place, Stmt, VarId, VarKind,
};
use binbun_ast::types::Evidence as TypeEvidence;

use crate::prototype::Prototypes;

/// The names of the counters of `for` loops, by how many `for`s enclose
/// the loop.
const COUNTERS: [&str; 6] = ["i", "j", "k", "l", "m", "n"];

/// Names the unnamed parameters and locals of `function` from the
/// evidence `prototypes` give and its structure (the module's rules).
pub fn name(function: &mut Function, prototypes: &dyn Prototypes) {
    let mut evidence = Evidence::default();
    let own = prototypes.parameter_names(function.address);
    // As many parameters as the declaration names, or more where lowering
    // placed the declared ones first, of the types it states, and added
    // the inputs it does not declare after them (an argument register a
    // callee of unknown interface may read).
    let stated = |var: &VarId| {
        function.var(*var).is_some_and(|variable| {
            matches!(
                variable.evidence,
                TypeEvidence::Declared | TypeEvidence::DeclaredPointer
            )
        })
    };
    if own.len() == function.parameters.len()
        || function
            .parameters
            .get(..own.len())
            .is_some_and(|leading| !leading.is_empty() && leading.iter().all(stated))
    {
        for (&var, declared) in function.parameters.iter().zip(&own) {
            if let Some(declared) = declared {
                evidence.add(var, NameOrigin::Declared, declared);
            }
        }
    }
    let mut walk = Walk {
        function,
        prototypes,
        evidence,
        returned: Vec::new(),
        returns_other: false,
    };
    walk.block(&function.body, 0);
    let Walk {
        mut evidence,
        returned,
        returns_other,
        ..
    } = walk;
    if let Some(&first) = returned.first()
        && !returns_other
        && returned.iter().all(|&var| var == first)
        && function
            .var(first)
            .is_some_and(|variable| variable.kind == VarKind::Local)
    {
        evidence.add(first, NameOrigin::Result, "result");
    }
    for (var, (origin, votes)) in evidence.best {
        let Some(variable) = function.variables.get_mut(var.0 as usize) else {
            continue;
        };
        let nameable = match variable.kind {
            VarKind::Parameter | VarKind::Local => true,
            VarKind::Frame(_) => function.promoted.contains(&var),
            VarKind::Global(_) | VarKind::Environment(_) => false,
        };
        if !nameable || variable.name.is_some() {
            continue;
        }
        let chosen = votes.into_iter().fold(
            None,
            |best: Option<(String, usize)>, (text, count)| match best {
                Some((_, most)) if most >= count => best,
                Some(_) | None => Some((text, count)),
            },
        );
        if let Some((text, _)) = chosen {
            variable.name = Some(Name::new(text, origin));
        }
    }
}

/// The names seen for each variable: of its strongest origin only, with
/// how often each was seen.
#[derive(Default)]
struct Evidence {
    best: BTreeMap<VarId, (NameOrigin, BTreeMap<String, usize>)>,
}

impl Evidence {
    /// `text` (a declared name: its leading underscores dropped) seen
    /// for `var`, from `origin`.
    fn add(&mut self, var: VarId, origin: NameOrigin, text: &str) {
        let text = text.trim_start_matches('_');
        if text.is_empty() || !text.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            return;
        }
        let entry = self
            .best
            .entry(var)
            .or_insert_with(|| (origin, BTreeMap::new()));
        if origin < entry.0 {
            *entry = (origin, BTreeMap::new());
        }
        if origin == entry.0 {
            *entry.1.entry(String::from(text)).or_insert(0) += 1;
        }
    }
}

/// A walk of the statements the body holds.
struct Walk<'a> {
    function: &'a Function,
    prototypes: &'a dyn Prototypes,
    evidence: Evidence,
    /// The variables returned, one per `return` of a variable.
    returned: Vec<VarId>,
    /// Whether a `return` returns what is neither a variable nor a
    /// constant.
    returns_other: bool,
}

impl Walk<'_> {
    /// The statements of `block`, inside `fors` `for` loops.
    fn block(&mut self, block: &Block, fors: usize) {
        for &id in block {
            let Some(stmt) = self.function.stmt(id) else {
                continue;
            };
            match stmt {
                Stmt::Call { call, .. } => self.call(call),
                Stmt::For { step, .. } => {
                    if let Some(var) = self.counter(step)
                        && let Some(&counter) = COUNTERS.get(fors)
                    {
                        self.evidence.add(var, NameOrigin::Counter, counter);
                    }
                }
                &Stmt::Return(Some(value)) => match self.function.expr(value) {
                    Some(&Expr::Var(var)) => self.returned.push(var),
                    Some(Expr::Const(_)) => {}
                    Some(_) | None => self.returns_other = true,
                },
                Stmt::Assign { .. }
                | Stmt::Intrinsic { .. }
                | Stmt::Expr(_)
                | Stmt::If { .. }
                | Stmt::While { .. }
                | Stmt::DoWhile { .. }
                | Stmt::Switch { .. }
                | Stmt::Break(_)
                | Stmt::Continue(_)
                | Stmt::Label(_)
                | Stmt::Goto(_)
                | Stmt::Return(None)
                | Stmt::Trap(_)
                | Stmt::Unreachable
                | Stmt::Escape { .. }
                | Stmt::Try { .. }
                | Stmt::VaStart { .. } => {}
            }
            for root in stmt.roots() {
                self.calls_in(root);
            }
            let inner = fors + usize::from(matches!(stmt, Stmt::For { .. }));
            for block in stmt.blocks() {
                self.block(block, inner);
            }
        }
    }

    /// The calls in expression `root` and its operands.
    fn calls_in(&mut self, root: ExprId) {
        let mut work = alloc::vec![root];
        while let Some(id) = work.pop() {
            let Some(expr) = self.function.expr(id) else {
                continue;
            };
            if let &Expr::Call(call) = expr
                && let Some(call) = self.function.call(call)
            {
                self.call(call);
            }
            work.extend(expr.operands(self.function));
        }
    }

    /// The variables `call` passes, named after the parameters they are
    /// passed as where the callee's declaration names them.
    fn call(&mut self, call: &Call) {
        let declared = match call.callee {
            Callee::Address(address) => self.prototypes.parameter_names(address),
            Callee::Import(slot) => self.prototypes.parameter_names_through(slot),
            Callee::Expr(_) => return,
        };
        for (&argument, declared) in call.arguments.iter().zip(&declared) {
            if let Some(declared) = declared
                && let Some(var) = self.passed(argument)
            {
                self.evidence.add(var, NameOrigin::Argument, declared);
            }
        }
    }

    /// The variable argument `id` passes: itself, or cast.
    fn passed(&self, id: ExprId) -> Option<VarId> {
        let id = match self.function.expr(id)? {
            &Expr::Cast { value, .. } => value,
            Expr::Const(_)
            | Expr::Undefined(..)
            | Expr::Var(_)
            | Expr::AddressOf(_)
            | Expr::Unary(..)
            | Expr::Binary(..)
            | Expr::Logical(..)
            | Expr::Flag(..)
            | Expr::Extract { .. }
            | Expr::Concat { .. }
            | Expr::Extend { .. }
            | Expr::Select { .. }
            | Expr::Lanes { .. }
            | Expr::Float { .. }
            | Expr::Load { .. }
            | Expr::Call(_)
            | Expr::Exception { .. }
            | Expr::Assign { .. } => id,
        };
        let &Expr::Var(var) = self.function.expr(id)? else {
            return None;
        };
        Some(var)
    }

    /// The counter of a `for` loop whose step is `step`: the one variable
    /// it assigns, if it assigns one alone.
    fn counter(&self, step: &Block) -> Option<VarId> {
        let mut assigned = step.iter().map(|&id| match self.function.stmt(id) {
            Some(&Stmt::Assign {
                place: Place::Var(var),
                ..
            }) => Some(var),
            Some(_) | None => None,
        });
        let first = assigned.next()??;
        assigned.all(|var| var == Some(first)).then_some(first)
    }
}
