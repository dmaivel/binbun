//! Pointer loops as array loops (a pointer stepped through an array is
//! the array's index): [`ArrayLoops`].

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec;
use alloc::vec::Vec;

use binbun_ast::ir::{Expr, ExprId, Function, Place, Stmt, StmtId, VarId, VarKind, Variable};
use binbun_ast::types::{Evidence, Type};
use binbun_semantics::bits::Bits;
use binbun_semantics::core::pass::{Changed, Cx, Pass, Refusal};
use binbun_semantics::ir::Binary;

use super::refine::always;
use crate::pass::{L2Env, size};
use crate::range::{Index, Interval, Known, Term, WIDEST, before};
use crate::simplify::expr::{Info, map_roots, rebuild, same};

/// Pointer loops as array loops (pass `array-loops`), on a structured
/// function before the loop rules ([`super::Loops`]): a local `p` of type
/// `T *` stepped through a loop `L` by `d = sizeof(T)` bytes from its
/// start `A` to an end `E = A + d·n` becomes the base of an array indexed
/// by a new counter `i` (`uint64_t`, as wide as a pointer): `p` keeps `A`,
/// each step `p = p + d` becomes `i = i + 1`, `i = 0` goes just before
/// `L`, each exit test of `p` against `E` tests `i` against `n`, and every
/// other read of `p` in `L` and after it is `p + d·i` (`&p[i]`; an access
/// at `p + k` is `p[i]` or `p[i + m].f`). The loop rules then make a
/// `do`-`while` a `for (i = 0; i < n; i++)` where they prove `0 < n`
/// (rule 4). Dead code ([`Prune`](crate::simplify::copies::Prune)) runs
/// after it: an end only the tests read goes.
///
/// Counting down, the mirror image: `p` stepped by `p = p - d` from `A =
/// E + d·n` down to `E` is `E + d·i` with `i` counting down from `n` to
/// 0: `p = E; i = n` go just before `L`, each step becomes `i = i - 1`,
/// each exit test of `p` against `E` tests `i` against 0 (`p != E` is
/// `i != 0`, `E < p` is `0 < i`), and every other read of `p` is `p +
/// d·i` as above (the usual `p[-1]` of such loops reads `p[i - 1]`). `i`
/// stays unsigned and its test `i != 0` (`for (i = n; i != 0; i--)`): one
/// invariant, `p == &E[i]`, holds everywhere as it does counting up, and
/// needs no sign; `for (i = n - 1; i >= 0; i--)` would need a signed `i`,
/// `n - 1` below the signed maximum proved, and every read shifted by one.
///
/// The end is a constant `E` with a constant start `A` (a number, a
/// global's address, a sum of them): `n = (E - A) / d`; or a variable `e` whose last
/// assignment before `L`, in `L`'s block, is `e = x + d·n` (`n * d`,
/// `d * n`, `n << log2(d)`) with `x` the variable `p` is assigned from (not
/// written between the two assignments) or `p` itself (before `L`), `n` a
/// local or parameter (through casts and extensions), and neither `e` nor
/// `n` written from there through `L`: then the tests compare `i` with
/// `n` (a copy, without casts). Counting down, `n = (A - E) / d` of
/// constants; or `p`'s assignment is `p = x + d·n` with `x` the variable
/// the tests compare `p` with, a local or parameter not written from there
/// through `L`, and `n` as above, not written from there to `L` (`i = n`
/// reads it there).
///
/// It applies where (each needed for the rewrite to compute what the
/// program computes, or to read as an array):
///
/// - `p` is a local not in memory, a pointer to a type of `d` bytes (the
///   element the solver gave it from the step: an evolution of `d`), its
///   address not taken; its writes are assignments only: one before `L`,
///   in the block `L` is in, and in `L` steps `p = p + d`, or all `p = p -
///   d` (nothing in an inner loop, `switch` or `try`);
/// - a constant end: `A <= E`, `E - A` a multiple of `d`, `n >= 1` and
///   `E + d` within the pointer's range: for `0 <= i <= n + 1`, `p` is
///   `A + d·i` with no wrap, so `p == E` is `i == n`, `p < E` is `i < n`,
///   `p <= E` is `i <= n` (unsigned). Counting down: `E < A`, `A - E` a
///   multiple of `d` (`p` stays within `E..=A`), tests `p != E`, `E < p`
///   or exit tests;
/// - a variable end: tests by `==` and `!=` only. `p == e` is `d·i ==
///   d·n` modulo the pointer's range (counting down, `d·i == 0`), which
///   is `i == n` (`i == 0`) for every `i` where `d` is 1; for a larger
///   `d`, only where neither wraps: `n·d` below `2^w` (`w` the pointer's
///   width, `i` then in `0..=n`) and, where the first test follows a step
///   (a `do`-`while`, an exit test), `n >= 1`. Both from `n`'s values at
///   `L`: through a zero extension the operand's, through a truncation
///   or sign extension the operand's where they fit; a variable's as
///   the [`Ranges`](crate::range) facts give them at `L` (the conditions
///   of the code dominating `L`: `if (n < k)`, `if (n == 0) return`,
///   `n`'s width), narrowed by its last assignment where the walk back
///   finds it: `y >> k` (logical: at most `(2^w - 1) >> k`), `y / c`,
///   `y & m`, a zero extension, a constant, or, read signed, `y >> k`
///   (arithmetic) and `y / c` (signed, `c > 0`), which bound it only
///   where the facts make it non-negative (`n = (end - start) >> 3` of a
///   pointer difference is `n·8 <= end - start` read unsigned; read
///   signed, `end < start` gives a negative `n`). `n >= 1` also where
///   `L`'s block is the branch of an `if` taken where `n != 0` (`n`
///   compared with 0 by `!=` or `==`, not written before `L`);
/// - every step is followed by an exit test before any other step, so
///   that `i <= n + 1` wherever a test is evaluated: the step is the last
///   statement of a `do`-`while` or `while` body whose condition is `p !=
///   E`, `p < E` or `p <= E` (a `continue` reaches the test without a
///   step); or a later statement of the step's block is `if (p == E)`
///   whose `then` (`if (p != E)`: whose `else`) ends with a `break` of
///   `L`, holds no `continue` of `L` and writes no `p`, with nothing
///   between holding a `continue` of `L`. The first step happens at `i =
///   0 < n` (for a variable end where `d` is 1, no bound is needed);
/// - no label is in `L` or after it in its block (control reaches them
///   only through `L`'s `i = 0`), and `p` is read only after its
///   assignment in that block: those reads before `L` see `A` and stay;
/// - every load or store at `p + k` fits one element (`k` and `k + size -
///   1` in one `d`-byte element), so it names `p[i + m]` or a field of it.
///
/// Every value is the program's: `p + d·i` is `p`'s value wherever it was
/// read (`i` counts the steps since `L` began, or down from `n`), and the
/// tests decide as they did. `i` has no L1 counterpart: the differential
/// check compares what both runs do (memory, calls, returns), never
/// locals; the structure check sees `i = 0` (and `p = E; i = n`) as
/// statements without a block (control passes through them) and `i = i +
/// 1` (or `i = i - 1`) as the step's statement, of its block.
///
/// Preserves nothing. Fuel: a unit per statement and expression, per loop
/// rewritten.
#[derive(Clone, Copy, Debug, Default)]
pub struct ArrayLoops {
    rewritten: usize,
}

impl ArrayLoops {
    /// How many loops it rewrote in the function it last ran on.
    pub const fn rewritten(&self) -> usize {
        self.rewritten
    }
}

impl<'e> Pass<Function, L2Env<'e>> for ArrayLoops {
    fn name(&self) -> &'static str {
        "array-loops"
    }

    fn run(
        &mut self,
        function: &mut Function,
        cx: &mut Cx<'_, Function, L2Env<'e>>,
    ) -> Result<Changed, Refusal> {
        self.rewritten = 0;
        let mut tried = BTreeSet::new();
        loop {
            cx.fuel.spend(size(function))?;
            let tree = Tree::new(function);
            let uses = Uses::new(function, &tree);
            let found = uses
                .writes
                .keys()
                .filter(|&&var| tried.insert(var))
                .find_map(|&var| plan(function, &tree, &uses, var));
            let Some(found) = found else {
                break;
            };
            apply(function, &tree, &found);
            self.rewritten += 1;
        }
        Ok((self.rewritten > 0).into())
    }
}

/// Where each statement is: the blocks of the body.
struct Tree {
    /// Each block: the statement holding it (`None`: the body), which of
    /// its blocks it is ([`Stmt::blocks`]), its statements.
    blocks: Vec<(Option<StmtId>, usize, Vec<StmtId>)>,
    /// Each statement's block and position in it.
    at: BTreeMap<StmtId, (usize, usize)>,
}

impl Tree {
    fn new(function: &Function) -> Self {
        let mut tree = Self {
            blocks: vec![(None, 0, function.body.clone())],
            at: BTreeMap::new(),
        };
        let mut next = 0;
        while let Some((_, _, block)) = tree.blocks.get(next) {
            let block = block.clone();
            for (position, &id) in block.iter().enumerate() {
                tree.at.insert(id, (next, position));
                if let Some(stmt) = function.stmt(id) {
                    for (nth, inner) in stmt.blocks().enumerate() {
                        tree.blocks.push((Some(id), nth, inner.clone()));
                    }
                }
            }
            next += 1;
        }
        tree
    }

    /// The statement holding the block statement `id` is in (`None`: the
    /// body's).
    fn parent(&self, id: StmtId) -> Option<StmtId> {
        let &(block, _) = self.at.get(&id)?;
        self.blocks.get(block)?.0
    }

    /// The statements of `block` from `from` on.
    fn from(&self, block: usize, from: usize) -> &[StmtId] {
        self.blocks
            .get(block)
            .and_then(|(_, _, ids)| ids.get(from..))
            .unwrap_or(&[])
    }
}

/// `ids` and the statements they hold.
fn held(function: &Function, ids: &[StmtId]) -> Vec<StmtId> {
    let mut out = Vec::new();
    let mut work: Vec<StmtId> = ids.iter().rev().copied().collect();
    while let Some(id) = work.pop() {
        out.push(id);
        if let Some(stmt) = function.stmt(id) {
            for block in stmt.blocks() {
                work.extend(block.iter().rev());
            }
        }
    }
    out
}

/// The places statement `stmt` writes.
fn places(stmt: &Stmt) -> &[Place] {
    match stmt {
        Stmt::Assign { place, .. } => core::slice::from_ref(place),
        Stmt::Call { results, .. }
        | Stmt::Intrinsic { results, .. }
        | Stmt::Escape { results, .. } => results,
        Stmt::Expr(_)
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
        | Stmt::Try { .. }
        | Stmt::VaStart { .. } => &[],
    }
}

/// The variables' writes and readers.
struct Uses {
    /// Per local variable: the assignments to it.
    writes: BTreeMap<VarId, Vec<StmtId>>,
    /// Variables written other than by an assignment, or whose address
    /// is taken.
    other: BTreeSet<VarId>,
    /// Per variable: the statements reading it.
    readers: BTreeMap<VarId, BTreeSet<StmtId>>,
}

impl Uses {
    fn new(function: &Function, tree: &Tree) -> Self {
        let mut uses = Self {
            writes: BTreeMap::new(),
            other: BTreeSet::new(),
            readers: BTreeMap::new(),
        };
        for &id in tree.at.keys() {
            let Some(stmt) = function.stmt(id) else {
                continue;
            };
            if let &Stmt::Assign {
                place: Place::Var(var),
                ..
            } = stmt
            {
                uses.writes.entry(var).or_default().push(id);
            } else {
                for place in places(stmt) {
                    if let &Place::Var(var) = place {
                        uses.other.insert(var);
                    }
                }
            }
            let mut seen = BTreeSet::new();
            let mut work = stmt.roots();
            while let Some(expr) = work.pop() {
                if !seen.insert(expr) {
                    continue;
                }
                match function.expr(expr) {
                    Some(&Expr::Var(var)) => {
                        uses.readers.entry(var).or_default().insert(id);
                    }
                    Some(&Expr::AddressOf(var)) => {
                        uses.other.insert(var);
                    }
                    Some(node) => work.extend(node.operands(function)),
                    None => {}
                }
            }
        }
        uses
    }
}

/// A pointer loop to rewrite.
struct Plan {
    /// The pointer.
    var: VarId,
    /// The loop.
    lp: StmtId,
    /// Its step, in bytes.
    step: u64,
    /// Counting down (`p = p - d`): the end `E`, which `p` is set to just
    /// before the loop (the base `i` indexes from `n` down to 0).
    down: Option<End>,
    /// The count `n`.
    count: Count,
    /// The steps.
    steps: Vec<StmtId>,
    /// The statements whose condition is an exit test, with the comparison
    /// of `i` and `n` it becomes.
    tests: Vec<(StmtId, Binary)>,
    /// The statements whose reads of the pointer become `p + d·i`: the
    /// loop and those after it in its block, and those they hold.
    rewrite: Vec<StmtId>,
}

/// The count `n` of a loop: a constant, or the program's expression for
/// it (variables, casts and extensions, copied into each test without its
/// casts).
#[derive(Clone, Copy, Debug)]
enum Count {
    Const(u64),
    Expr(ExprId),
}

/// What an exit test compares the pointer with: a constant, or a variable
/// (through casts).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum End {
    Const(u64),
    Var(VarId),
}

/// The rewrite of `var`'s loop, if [`ArrayLoops`] applies.
fn plan(function: &Function, tree: &Tree, uses: &Uses, var: VarId) -> Option<Plan> {
    let width = function.types.pointer_width();
    let variable = function.var(var)?;
    if !matches!(variable.kind, VarKind::Local | VarKind::Parameter) || uses.other.contains(&var) {
        return None;
    }
    let Some(&Type::Pointer(Some(target))) = function.types.get(variable.ty) else {
        return None;
    };
    let step = function
        .types
        .width(target)
        .filter(|&bits| bits > 0 && bits % 8 == 0)?
        / 8;
    let writes = uses.writes.get(&var)?;
    let (steps, inits): (Vec<StmtId>, Vec<StmtId>) = writes
        .iter()
        .partition(|&&id| stepped(function, id, var, step, width).is_some());
    let up = stepped(function, *steps.first()?, var, step, width)?;
    if steps
        .iter()
        .any(|&id| stepped(function, id, var, step, width) != Some(up))
    {
        return None;
    }
    let lp = enclosing_loop(function, tree, *steps.first()?)?;
    if steps
        .iter()
        .any(|&id| enclosing_loop(function, tree, id) != Some(lp))
    {
        return None;
    }
    let &(block, at_loop) = tree.at.get(&lp)?;
    let rewrite = held(function, tree.from(block, at_loop));
    if rewrite
        .iter()
        .any(|&id| matches!(function.stmt(id), Some(Stmt::Label(_))))
    {
        return None;
    }
    let (at_init, value) = start_of(function, tree, uses, var, &inits, lp, &rewrite)?;
    let (end, tests) = tests(function, tree, lp, var, &steps, up)?;
    let count = match (
        value.and_then(|value| constant(function, value, width)),
        end,
    ) {
        (Some(start), End::Const(end)) if up => constant_count(start, end, step, width)?,
        (Some(start), End::Const(end)) => descending_count(start, end, step)?,
        (_, End::Var(end)) => {
            // Without a constant range only `==` and `!=` read the same of
            // `i` and `n`.
            if tests
                .iter()
                .any(|&(_, op)| !matches!(op, Binary::Eq | Binary::Ne))
            {
                return None;
            }
            let guarded = !matches!(function.stmt(lp), Some(Stmt::While { .. }))
                || tests.iter().any(|&(test, _)| test != lp);
            let found = Found {
                function,
                tree,
                uses,
                var,
                lp,
                block,
                at_init,
                at_loop,
            };
            Count::Expr(if up {
                found.symbolic(value, end, step, guarded)?
            } else {
                found.descending(value?, end, step, guarded)?
            })
        }
        (None, End::Const(_)) => return None,
    };
    if !fits(function, &held(function, &[lp]), var, step, width) {
        return None;
    }
    Some(Plan {
        var,
        lp,
        step,
        down: (!up).then_some(end),
        count,
        steps,
        tests,
        rewrite,
    })
}

/// Where pointer `var` (assigned by `inits` but its steps, in loop `lp`)
/// starts, if its reads outside `rewrite` (the loop and what follows it in
/// its block) see that start: its assignment's position in the loop's
/// block and value, with every read after it; or, for a parameter never
/// assigned, the function's entry (no position, no value), with every
/// read before the loop in the order of the code, no loop around the
/// loop and no label in the function (so nothing runs again after it).
fn start_of(
    function: &Function,
    tree: &Tree,
    uses: &Uses,
    var: VarId,
    inits: &[StmtId],
    lp: StmtId,
    rewrite: &[StmtId],
) -> Option<(Option<usize>, Option<ExprId>)> {
    let &(block, at_loop) = tree.at.get(&lp)?;
    let readers = uses.readers.get(&var);
    if let &[init] = inits {
        let &(init_block, at_init) = tree.at.get(&init)?;
        if init_block != block || at_init >= at_loop {
            return None;
        }
        let Some(&Stmt::Assign { value, .. }) = function.stmt(init) else {
            return None;
        };
        // Reads only after the assignment, in its block.
        let allowed: BTreeSet<StmtId> = held(function, tree.from(block, at_init + 1))
            .into_iter()
            .collect();
        if readers.is_some_and(|readers| readers.iter().any(|id| !allowed.contains(id))) {
            return None;
        }
        return Some((Some(at_init), Some(value)));
    }
    if !inits.is_empty() || function.var(var)?.kind != VarKind::Parameter {
        return None;
    }
    let order = held(function, &function.body);
    if order
        .iter()
        .any(|&id| matches!(function.stmt(id), Some(Stmt::Label(_))))
    {
        return None;
    }
    let mut at = lp;
    while let Some(parent) = tree.parent(at) {
        if matches!(
            function.stmt(parent),
            Some(Stmt::While { .. } | Stmt::DoWhile { .. } | Stmt::For { .. })
        ) {
            return None;
        }
        at = parent;
    }
    let position = order.iter().position(|&id| id == lp)?;
    let before: BTreeSet<StmtId> = order.get(..position)?.iter().copied().collect();
    let after: BTreeSet<StmtId> = rewrite.iter().copied().collect();
    if readers.is_some_and(|readers| {
        readers
            .iter()
            .any(|id| !before.contains(id) && !after.contains(id))
    }) {
        return None;
    }
    Some((None, None))
}

/// The count from constant `start` to constant `end` by `step` (see
/// [`ArrayLoops`]): at least 1, with no wrap up to `end + step`.
fn constant_count(start: u64, end: u64, step: u64, width: u16) -> Option<Count> {
    let span = end.wrapping_sub(start);
    let max = if width >= 64 {
        u64::MAX
    } else {
        (1u64 << width) - 1
    };
    let last = end.checked_add(step)?;
    (start <= end && span.is_multiple_of(step) && span >= step && last <= max)
        .then_some(Count::Const(span / step))
}

/// The count from constant `start` down to constant `end` by `step` (see
/// [`ArrayLoops`]): at least 1 (`p` stays within `end..=start`, so no step
/// wraps).
fn descending_count(start: u64, end: u64, step: u64) -> Option<Count> {
    let span = start.checked_sub(end)?;
    (span.is_multiple_of(step) && span >= step).then_some(Count::Const(span / step))
}

/// A pointer loop's place: the pointer `var`, assigned at `at_init` of
/// block `block` (of `tree`; `None`: a parameter never assigned), whose
/// loop `lp` is at `at_loop`.
struct Found<'a> {
    function: &'a Function,
    tree: &'a Tree,
    uses: &'a Uses,
    var: VarId,
    lp: StmtId,
    block: usize,
    at_init: Option<usize>,
    at_loop: usize,
}

impl Found<'_> {
    /// The count `n` where the pointer starts at `start` (an expression;
    /// `None`: its value at the function's entry)
    /// and its tests compare it with variable `end`, assigned once in the
    /// loop's block before it as `x + d·n` (`d` the `step`) with `x` the
    /// pointer's start (the variable it is assigned from, or the pointer
    /// before the loop), `n` a variable (through casts and extensions)
    /// not written from there through the loop. `p == end` is then `d·i
    /// == d·n` modulo the pointer's range: `i == n` where [`Found::exact`].
    fn symbolic(
        &self,
        start: Option<ExprId>,
        end: VarId,
        step: u64,
        guarded: bool,
    ) -> Option<ExprId> {
        let function = self.function;
        // `end`'s last assignment before the loop, in its block.
        let (at_end, assigned) = self
            .uses
            .writes
            .get(&end)?
            .iter()
            .filter_map(|id| match self.tree.at.get(id) {
                Some(&(block, at)) if block == self.block && at < self.at_loop => Some((at, *id)),
                Some(_) | None => None,
            })
            .max()?;
        let Some(&Stmt::Assign { value, .. }) = function.stmt(assigned) else {
            return None;
        };
        let Expr::Binary(Binary::Add, a, b) = *function.expr(uncast(function, value))? else {
            return None;
        };
        let source = |id| match function.expr(uncast(function, id)) {
            Some(&Expr::Var(x)) => Some(x),
            Some(_) | None => None,
        };
        let from = start.and_then(source);
        let (x, scaled) = if source(a).is_some_and(|x| Some(x) == from || x == self.var) {
            (source(a)?, b)
        } else {
            (source(b)?, a)
        };
        if Some(x) != from && x != self.var {
            return None;
        }
        // A variable in memory may change through a pointer between.
        if x != self.var && !matches!(function.var(x)?.kind, VarKind::Local | VarKind::Parameter) {
            return None;
        }
        // `x` is the pointer's start at `end`'s assignment.
        if self.written(end, &self.between(at_end + 1, self.at_loop + 1)) {
            return None;
        }
        if x == self.var {
            if self.at_init.is_some_and(|at_init| at_end < at_init) {
                return None;
            }
        } else {
            let at_init = self.at_init?;
            let (low, high) = (at_end.min(at_init), at_end.max(at_init));
            if self.written(x, &self.between(low + 1, high)) {
                return None;
            }
        }
        let count = self.count(scaled, step)?;
        let mut read = BTreeSet::new();
        bound_vars(function, count, &mut read)?;
        let after = self.between(at_end + 1, self.at_loop + 1);
        if read.contains(&end) || read.iter().any(|&n| self.written(n, &after)) {
            return None;
        }
        self.exact(count, &read, step, guarded).then_some(count)
    }

    /// The count `n` where the pointer counts down from `start`, `x + d·n`
    /// (`d` the `step`; its assignment's value) with `x` the variable
    /// `end` its tests compare it with, to `end`: `x` a local or parameter
    /// not written from that assignment through the loop, `n` a variable
    /// (through casts and extensions) not written from there to the loop.
    /// With `p` set to `x` before the loop, `p == x` is `d·i == 0` modulo
    /// the pointer's range, `i` counting down from `n`: `i == 0` where
    /// [`Found::exact`].
    fn descending(&self, start: ExprId, end: VarId, step: u64, guarded: bool) -> Option<ExprId> {
        let function = self.function;
        let at_init = self.at_init?;
        let Expr::Binary(Binary::Add, a, b) = *function.expr(uncast(function, start))? else {
            return None;
        };
        let is_end =
            |id| matches!(function.expr(uncast(function, id)), Some(&Expr::Var(x)) if x == end);
        let scaled = if is_end(a) {
            b
        } else if is_end(b) {
            a
        } else {
            return None;
        };
        if !matches!(function.var(end)?.kind, VarKind::Local | VarKind::Parameter)
            || self.written(end, &self.between(at_init + 1, self.at_loop + 1))
        {
            return None;
        }
        let count = self.count(scaled, step)?;
        let mut read = BTreeSet::new();
        bound_vars(function, count, &mut read)?;
        let between = self.between(at_init + 1, self.at_loop);
        if read.contains(&self.var) || read.iter().any(|&n| self.written(n, &between)) {
            return None;
        }
        self.exact(count, &read, step, guarded).then_some(count)
    }

    /// The statements of the loop's block from `low` to before `high`, and
    /// those they hold.
    fn between(&self, low: usize, high: usize) -> Vec<StmtId> {
        held(
            self.function,
            self.tree
                .from(self.block, low)
                .get(..high.saturating_sub(low))
                .unwrap_or(&[]),
        )
    }

    /// Whether the steps `d·i` of count `n` (`count`, reading `read`, as
    /// [`bound_vars`] accepts it) stay exact: `d` is 1, or `n·d` is below
    /// the pointer's range (`n`'s values at the loop, [`Found::count_range`])
    /// and, if `guarded` (the first test follows a step), `n >= 1` (by its
    /// values, or the loop's block is the branch of an `if` deciding `n !=
    /// 0`).
    fn exact(&self, count: ExprId, read: &BTreeSet<VarId>, step: u64, guarded: bool) -> bool {
        if step == 1 {
            return true;
        }
        let Some((low, high)) = self.count_range(count) else {
            return false;
        };
        let width = self.function.types.pointer_width();
        let fits = high
            .checked_mul(u128::from(step))
            .is_some_and(|last| last <= mask(width));
        fits && (!guarded
            || low >= 1
            || self.nonzero(count, read, &self.between(0, self.at_loop + 1)))
    }

    /// The values of count `id` (as [`bound_vars`] accepts it) at the loop,
    /// unsigned, from its variable's ([`Found::var_range`]): a truncation
    /// keeps them where they fit; a zero extension keeps them, a sign
    /// extension where they are below its operand's sign bit.
    fn count_range(&self, id: ExprId) -> Option<(u128, u128)> {
        let function = self.function;
        let id = uncast(function, id);
        let expr = *function.expr(id)?;
        if let Expr::Var(var) = expr {
            return self.var_range(var);
        }
        if let Expr::Extract {
            value,
            offset: 0,
            width,
        } = expr
        {
            let (low, high) = self.count_range(value)?;
            return Some(if high <= mask(width) {
                (low, high)
            } else {
                (0, mask(width))
            });
        }
        let Expr::Extend {
            signed,
            value,
            width,
        } = expr
        else {
            return None;
        };
        let (low, high) = self.count_range(value)?;
        let from = function.width(value)?;
        Some(if !signed || high <= mask(from.checked_sub(1)?) {
            (low, high)
        } else {
            (0, mask(width))
        })
    }

    /// The values of variable `var` at the loop, unsigned: those the facts
    /// there allow (the conditions of the code dominating it, as the
    /// [`Ranges`](crate::range::Ranges) analysis finds them), narrowed by
    /// its last assignment before the loop if the walk back finds it
    /// ([`computed`]).
    fn var_range(&self, var: VarId) -> Option<(u128, u128)> {
        let function = self.function;
        let width = function.types.value_width(function.var(var)?.ty)?;
        if width == 0 {
            return None;
        }
        if width > WIDEST {
            return (width < 128).then(|| (0, mask(width)));
        }
        let index = Index::new(function);
        let entered = before(function, &index, self.lp, var);
        let known = Known::new(&entered.facts);
        let mut unsigned = known.interval(Term::Var(var), false, width);
        let mut signed = known.interval(Term::Var(var), true, width);
        if let Some((_, value)) = entered.init {
            computed(function, value, width, &mut unsigned, &mut signed);
        }
        if signed.lo >= 0 {
            unsigned = unsigned.meet(signed);
        } else if signed.hi < 0 {
            let span = 1i128 << width;
            unsigned = unsigned.meet(Interval {
                lo: signed.lo + span,
                hi: signed.hi + span,
            });
        }
        if unsigned.is_empty() {
            return None;
        }
        Some((
            u128::try_from(unsigned.lo).ok()?,
            u128::try_from(unsigned.hi).ok()?,
        ))
    }

    /// `n` where `scaled` is `n·step`: `n` scaled by constant factors
    /// (`n * c`, `c * n`, `n << k`, through casts) whose product is `step`
    /// (`48·n` as `(n * 3) << 4`); `n` itself for a step of 1.
    fn count(&self, scaled: ExprId, step: u64) -> Option<ExprId> {
        let function = self.function;
        let constant = |id| match function.expr(id) {
            Some(&Expr::Const(bits)) => Some(bits.low_u64()),
            Some(_) | None => None,
        };
        let (mut node, mut factor) = (scaled, 1u64);
        while factor != step {
            let Expr::Binary(op, a, b) = *function.expr(uncast(function, node))? else {
                return None;
            };
            let (inner, by) = match (op, constant(a), constant(b)) {
                (Binary::Mul, None, Some(c)) => (a, c),
                (Binary::Mul, Some(c), None) => (b, c),
                (Binary::Shl, None, Some(k)) if k < 64 => (a, 1u64 << k),
                _ => return None,
            };
            factor = factor
                .checked_mul(by)
                .filter(|&f| f != 0 && step.is_multiple_of(f))?;
            node = inner;
        }
        Some(node)
    }

    /// Whether `var` is written by one of `ids`, or other than by an
    /// assignment.
    fn written(&self, var: VarId, ids: &[StmtId]) -> bool {
        self.uses.other.contains(&var)
            || self
                .uses
                .writes
                .get(&var)
                .is_some_and(|writes| writes.iter().any(|id| ids.contains(id)))
    }

    /// Whether the loop's block is the branch of an `if` taken only where
    /// `count` is not 0: `x != 0` or `x == 0` with `x` the same tree as
    /// `count` but for casts and extensions (which keep 0 and only 0 at
    /// 0), the variables it reads (`read`) not written in `before` (the
    /// block up to the loop).
    fn nonzero(&self, count: ExprId, read: &BTreeSet<VarId>, before: &[StmtId]) -> bool {
        let function = self.function;
        let Some(&(Some(owner), nth, _)) = self.tree.blocks.get(self.block) else {
            return false;
        };
        let Some(&Stmt::If { condition, .. }) = function.stmt(owner) else {
            return false;
        };
        let Some(&Expr::Binary(op, a, b)) = function.expr(condition) else {
            return false;
        };
        let zero = |id| matches!(function.expr(uncast(function, id)), Some(Expr::Const(bits)) if bits.is_zero());
        let core = |mut id| loop {
            id = uncast(function, id);
            match function.expr(id) {
                Some(&Expr::Extend { value, .. }) => id = value,
                Some(_) | None => break id,
            }
        };
        let is_count = |id| same(function, core(id), core(count));
        let tests = (is_count(a) && zero(b)) || (is_count(b) && zero(a));
        let taken = (op == Binary::Ne && nth == 0) || (op == Binary::Eq && nth == 1);
        tests && taken && !read.iter().any(|&n| self.written(n, before))
    }
}

/// `id` without the casts around it.
fn uncast(function: &Function, mut id: ExprId) -> ExprId {
    while let Some(&Expr::Cast { value, .. }) = function.expr(id) {
        id = value;
    }
    id
}

/// The greatest value of `width` bits (at most 128), unsigned.
fn mask(width: u16) -> u128 {
    u128::MAX
        .checked_shr(128 - u32::from(width.min(128)))
        .unwrap_or(0)
}

/// `unsigned` and `signed`, the values of a `width`-bit variable read so,
/// narrowed by what its assignment's `value` computes: a constant; a
/// logical shift right by `k` (at most `max >> k`), an unsigned division
/// by `c` (at most `max / c`), a mask (at most it), a zero extension (at
/// most its operand's maximum); an arithmetic shift right or a signed
/// division by a positive constant, read signed likewise.
fn computed(
    function: &Function,
    value: ExprId,
    width: u16,
    unsigned: &mut Interval,
    signed: &mut Interval,
) {
    let constant = |id| match function.expr(id) {
        Some(&Expr::Const(bits)) if bits.width() <= 64 => Some(bits),
        Some(_) | None => None,
    };
    let top = i128::try_from(mask(width)).unwrap_or(i128::MAX);
    let (least, greatest) = (-(1i128 << (width - 1)), (1i128 << (width - 1)) - 1);
    let at_most = |unsigned: &mut Interval, high: i128| {
        *unsigned = unsigned.meet(Interval { lo: 0, hi: high });
    };
    let value = uncast(function, value);
    match function.expr(value).copied() {
        Some(Expr::Const(bits)) if bits.width() == width && width <= 64 => {
            *unsigned = unsigned.meet(Interval::point(i128::from(bits.low_u64())));
        }
        Some(Expr::Binary(op, _, b)) => {
            let Some(c) = constant(b).map(|bits| bits.low_u64()) else {
                return;
            };
            let c = i128::from(c);
            if op == Binary::LShr && c < i128::from(width) {
                at_most(unsigned, top >> c);
            } else if op == Binary::UDiv && c != 0 {
                at_most(unsigned, top / c);
            } else if op == Binary::And {
                at_most(unsigned, c);
            } else if op == Binary::AShr && c < i128::from(width) {
                *signed = signed.meet(Interval {
                    lo: least >> c,
                    hi: greatest >> c,
                });
            } else if op == Binary::SDiv && c > 0 && c <= greatest {
                *signed = signed.meet(Interval {
                    lo: least / c,
                    hi: greatest / c,
                });
            }
        }
        Some(Expr::Extend {
            signed: false,
            value: inner,
            ..
        }) => {
            if let Some(from) = function.width(inner) {
                at_most(unsigned, i128::try_from(mask(from)).unwrap_or(i128::MAX));
            }
        }
        Some(_) | None => {}
    }
}

/// A copy of count `id` (as [`bound_vars`] accepts it) without its casts
/// (which change no bits).
fn copy(function: &mut Function, id: ExprId) -> ExprId {
    let id = uncast(function, id);
    match function.expr(id).copied() {
        Some(Expr::Extend {
            signed,
            value,
            width,
        }) => {
            let value = copy(function, value);
            function.add_expr(Expr::Extend {
                signed,
                value,
                width,
            })
        }
        Some(Expr::Extract {
            value,
            offset,
            width,
        }) => {
            let value = copy(function, value);
            function.add_expr(Expr::Extract {
                value,
                offset,
                width,
            })
        }
        Some(node) => function.add_expr(node),
        None => id,
    }
}

/// The variables (locals and parameters, not in memory) of count `id`, a
/// tree of reads, casts, zero or sign extensions and truncations (low
/// bits), into `read`; `None` if it is not such a tree.
fn bound_vars(function: &Function, id: ExprId, read: &mut BTreeSet<VarId>) -> Option<()> {
    let id = uncast(function, id);
    let expr = *function.expr(id)?;
    if let Expr::Var(var) = expr {
        let variable = function.var(var)?;
        if !matches!(variable.kind, VarKind::Local | VarKind::Parameter) {
            return None;
        }
        read.insert(var);
        return Some(());
    }
    if let Expr::Extract {
        value, offset: 0, ..
    }
    | Expr::Extend { value, .. } = expr
    {
        bound_vars(function, value, read)
    } else {
        None
    }
}

/// The exit tests following `steps` (`var`'s, in loop `lp`), if each step
/// has one before any other step (see [`ArrayLoops`]): the end `E`
/// they all compare `var` with, and each test's statement with the
/// comparison it becomes (`i` with `n` counting `up`, else `i` with 0).
fn tests(
    function: &Function,
    tree: &Tree,
    lp: StmtId,
    var: VarId,
    steps: &[StmtId],
    up: bool,
) -> Option<(End, Vec<(StmtId, Binary)>)> {
    let width = function.types.pointer_width();
    let (&Stmt::DoWhile {
        ref body,
        condition,
    }
    | &Stmt::While {
        condition,
        ref body,
    }) = function.stmt(lp)?
    else {
        return None;
    };
    let looping = if always(function, condition) {
        None
    } else {
        continuing(function, condition, var, width, up)
    };
    let mut end = None;
    let mut tests: Vec<(StmtId, Binary)> = Vec::new();
    for &id in steps {
        let (test, op, e) = if body.last() == Some(&id)
            && let Some((op, e)) = looping
        {
            (lp, op, e)
        } else {
            let &(block, position) = tree.at.get(&id)?;
            let (_, _, ids) = tree.blocks.get(block)?;
            let mut found = None;
            for &next in ids.get(position + 1..)? {
                if let Some((op, e)) = exit_test(function, next, var, lp, width) {
                    found = Some((next, op, e));
                    break;
                }
                if held(function, &[next]).iter().any(|&held| {
                    matches!(function.stmt(held), Some(&Stmt::Continue(target)) if target == lp)
                        || steps.contains(&held)
                }) {
                    return None;
                }
            }
            found?
        };
        if *end.get_or_insert(e) != e {
            return None;
        }
        if !tests.iter().any(|&(t, _)| t == test) {
            tests.push((test, op));
        }
    }
    Some((end?, tests))
}

/// Whether statement `id` is `var = var + step` (`Some(true)`) or `var =
/// var - step` (`Some(false)`: also `var + -step`), `width`-bit.
fn stepped(function: &Function, id: StmtId, var: VarId, step: u64, width: u16) -> Option<bool> {
    let Some(&Stmt::Assign { value, .. }) = function.stmt(id) else {
        return None;
    };
    let Some(&Expr::Binary(op @ (Binary::Add | Binary::Sub), a, b)) = function.expr(value) else {
        return None;
    };
    let is_var = |id| matches!(function.expr(id), Some(&Expr::Var(v)) if v == var);
    let by = |id| match function.expr(id) {
        Some(&Expr::Const(bits)) if bits.width() == width => Some(bits.low_u64()),
        Some(_) | None => None,
    };
    let ones = if width >= 64 {
        u64::MAX
    } else {
        (1u64 << width) - 1
    };
    let back = step.wrapping_neg() & ones;
    let added = if op == Binary::Add && is_var(a) {
        by(b)?
    } else if op == Binary::Add && is_var(b) {
        by(a)?
    } else if op == Binary::Sub && is_var(a) {
        by(b)?.wrapping_neg() & ones
    } else {
        return None;
    };
    if added == step {
        Some(true)
    } else if added == back {
        Some(false)
    } else {
        None
    }
}

/// The loop (`while` or `do`-`while`) statement `id` is in, through `if`s
/// only.
fn enclosing_loop(function: &Function, tree: &Tree, id: StmtId) -> Option<StmtId> {
    let mut at = tree.parent(id)?;
    loop {
        let stmt = function.stmt(at)?;
        if matches!(stmt, Stmt::If { .. }) {
            at = tree.parent(at)?;
        } else {
            return matches!(stmt, Stmt::While { .. } | Stmt::DoWhile { .. }).then_some(at);
        }
    }
}

/// The value of `id` if it is a constant (`width`-bit): a number, a
/// global's address, a cast or sum of them.
fn constant(function: &Function, id: ExprId, width: u16) -> Option<u64> {
    let expr = *function.expr(id)?;
    if let Expr::Const(bits) = expr {
        (bits.width() == width).then(|| bits.low_u64())
    } else if let Expr::Cast { value, .. } = expr {
        constant(function, value, width)
    } else if let Expr::AddressOf(var) = expr
        && let VarKind::Global(address) = function.var(var)?.kind
    {
        Some(address)
    } else if let Expr::Binary(Binary::Add, a, b) = expr {
        Some(constant(function, a, width)?.wrapping_add(constant(function, b, width)?))
    } else {
        None
    }
}

/// Whether `id` reads `var` (through a cast).
fn reads_var(function: &Function, id: ExprId, var: VarId) -> bool {
    if let Some(&Expr::Cast { value, .. }) = function.expr(id) {
        reads_var(function, value, var)
    } else {
        function.expr(id) == Some(&Expr::Var(var))
    }
}

/// Condition `id` as `var` compared with an end `E` (a constant, or a
/// variable through casts): the comparison `op`, whether `var` is its
/// left operand, and `E`.
fn compared(
    function: &Function,
    id: ExprId,
    var: VarId,
    width: u16,
) -> Option<(Binary, bool, End)> {
    let Some(&Expr::Binary(op, a, b)) = function.expr(id) else {
        return None;
    };
    let end = |id| {
        if let Some(value) = constant(function, id, width) {
            return Some(End::Const(value));
        }
        match function.expr(uncast(function, id)) {
            Some(&Expr::Var(end)) if end != var => Some(End::Var(end)),
            Some(_) | None => None,
        }
    };
    if reads_var(function, a, var) {
        Some((op, true, end(b)?))
    } else if reads_var(function, b, var) {
        Some((op, false, end(a)?))
    } else {
        None
    }
}

/// A loop condition that holds while `var` has not reached `E`: counting
/// `up`, `var != E`, `var < E`, `var <= E` (unsigned), its comparison of
/// `i` with `n`; counting down, `var != E` or `E < var` (unsigned), its
/// comparison of `i` with 0 (`i != 0`, `0 < i`). And `E`.
fn continuing(
    function: &Function,
    id: ExprId,
    var: VarId,
    width: u16,
    up: bool,
) -> Option<(Binary, End)> {
    let (op, left, end) = compared(function, id, var, width)?;
    let continues = op == Binary::Ne
        || if up {
            left && matches!(op, Binary::ULt | Binary::ULe)
        } else {
            !left && op == Binary::ULt
        };
    continues.then_some((op, end))
}

/// Statement `id` as an exit test of loop `lp`: `if (var == E)` whose
/// `then` (`if (var != E)`: whose `else`) ends with a `break` of `lp`,
/// holding no `continue` of it nor a write of `var`; its comparison of
/// `i` with `n`, and `E`.
fn exit_test(
    function: &Function,
    id: StmtId,
    var: VarId,
    lp: StmtId,
    width: u16,
) -> Option<(Binary, End)> {
    let Some(Stmt::If {
        condition,
        then,
        otherwise,
    }) = function.stmt(id)
    else {
        return None;
    };
    let (op, _, end) = compared(function, *condition, var, width)?;
    let exit = if op == Binary::Eq {
        then
    } else if op == Binary::Ne {
        otherwise
    } else {
        return None;
    };
    if exit
        .last()
        .is_none_or(|&last| function.stmt(last) != Some(&Stmt::Break(lp)))
    {
        return None;
    }
    let clean = held(function, exit).iter().all(|&id| {
        let stmt = function.stmt(id);
        stmt != Some(&Stmt::Continue(lp))
            && stmt.is_none_or(|stmt| !places(stmt).contains(&Place::Var(var)))
    });
    clean.then_some((op, end))
}

/// Whether every load and store at `var + k` among statements `ids` fits
/// one `step`-byte element.
fn fits(function: &Function, ids: &[StmtId], var: VarId, step: u64, width: u16) -> bool {
    let step = i128::from(step);
    let offset = |address: ExprId| -> Option<i128> {
        if reads_var(function, address, var) {
            return Some(0);
        }
        let Some(&Expr::Binary(op @ (Binary::Add | Binary::Sub), a, b)) = function.expr(address)
        else {
            return None;
        };
        let k = |id| {
            let Some(&Expr::Const(bits)) = function.expr(id) else {
                return None;
            };
            let shift = 64 - u32::from(width.min(64));
            (bits.width() == width)
                .then(|| i128::from(bits.low_u64().cast_signed() << shift >> shift))
        };
        if reads_var(function, a, var) {
            k(b).map(|k| if op == Binary::Sub { -k } else { k })
        } else if op == Binary::Add && reads_var(function, b, var) {
            k(a)
        } else {
            None
        }
    };
    let bytes = |ty| {
        function
            .types
            .width(ty)
            .map_or(0, |bits| i128::from(bits.div_ceil(8)))
    };
    let mut seen = BTreeSet::new();
    for &id in ids {
        let Some(stmt) = function.stmt(id) else {
            continue;
        };
        let mut work = stmt.roots();
        let mut accesses = Vec::new();
        for result in places(stmt) {
            if let &Place::Memory { address, ty } = result {
                accesses.push((address, ty));
            }
        }
        while let Some(expr) = work.pop() {
            if !seen.insert(expr) {
                continue;
            }
            let Some(node) = function.expr(expr) else {
                continue;
            };
            if let &Expr::Load { address, ty } = node {
                accesses.push((address, ty));
            }
            work.extend(node.operands(function));
        }
        for (address, ty) in accesses {
            if let Some(k) = offset(address) {
                let last = k + bytes(ty).max(1) - 1;
                if k.div_euclid(step) != last.div_euclid(step) {
                    return false;
                }
            }
        }
    }
    true
}

/// Rewrites `plan`'s loop (see [`ArrayLoops`]).
fn apply(function: &mut Function, tree: &Tree, plan: &Plan) {
    let width = function.types.pointer_width();
    let ty = function.types.intern(Type::UInt(width));
    let index = function.add_var(Variable {
        kind: VarKind::Local,
        name: None,
        ty,
        evidence: Evidence::Deduced,
        origins: Vec::new(),
    });
    let constant = |function: &mut Function, value: u64| {
        function.add_expr(Expr::Const(Bits::from_u64(width, value)))
    };
    let count = |function: &mut Function| match plan.count {
        Count::Const(value) => constant(function, value),
        Count::Expr(count) => copy(function, count),
    };
    // `i = 0` just before the loop; counting down, `p = E; i = n`.
    let first = if plan.down.is_some() {
        count(function)
    } else {
        constant(function, 0)
    };
    let mut before = vec![function.add_stmt(Stmt::Assign {
        place: Place::Var(index),
        value: first,
    })];
    if let Some(end) = plan.down {
        let base = match end {
            End::Const(value) => constant(function, value),
            End::Var(var) => function.add_expr(Expr::Var(var)),
        };
        let reset = function.add_stmt(Stmt::Assign {
            place: Place::Var(plan.var),
            value: base,
        });
        before.insert(0, reset);
    }
    if let Some(&(block, position)) = tree.at.get(&plan.lp) {
        let slot = match tree.blocks.get(block) {
            Some(&(None, _, _)) => Some(&mut function.body),
            Some(&(Some(owner), nth, _)) => function
                .stmts
                .get_mut(owner.0 as usize)
                .and_then(|stmt| stmt.blocks_mut().nth(nth)),
            None => None,
        };
        if let Some(slot) = slot {
            slot.splice(position..position, before);
        }
    }
    // Each step `i = i + 1` (counting down `i = i - 1`), as the step's
    // statement.
    let op = if plan.down.is_some() {
        Binary::Sub
    } else {
        Binary::Add
    };
    for &id in &plan.steps {
        let read = function.add_expr(Expr::Var(index));
        let one = constant(function, 1);
        let sum = function.add_expr(Expr::Binary(op, read, one));
        if let Some(Stmt::Assign { value, .. }) = function.stmt(id) {
            let origins = function.provenance.expr(*value).to_vec();
            function.provenance.set_expr(sum, &origins);
        }
        if let Some(stmt) = function.stmts.get_mut(id.0 as usize) {
            *stmt = Stmt::Assign {
                place: Place::Var(index),
                value: sum,
            };
        }
    }
    // Each exit test of `i` against `n` (counting down, against 0: `E < p`
    // is `0 < i`), with the condition's origins.
    for &(id, op) in &plan.tests {
        let read = function.add_expr(Expr::Var(index));
        let test = if plan.down.is_none() {
            let n = count(function);
            function.add_expr(Expr::Binary(op, read, n))
        } else {
            let zero = constant(function, 0);
            if op == Binary::ULt {
                function.add_expr(Expr::Binary(op, zero, read))
            } else {
                function.add_expr(Expr::Binary(op, read, zero))
            }
        };
        let Some(stmt) = function.stmts.get_mut(id.0 as usize) else {
            continue;
        };
        if let Stmt::If { condition, .. }
        | Stmt::While { condition, .. }
        | Stmt::DoWhile { condition, .. } = stmt
        {
            let old = core::mem::replace(condition, test);
            let origins = function.provenance.expr(old).to_vec();
            function.provenance.set_expr(test, &origins);
        }
    }
    rebase(function, plan, index);
}

/// Every other read of `plan`'s pointer `p` from the loop on as `p +
/// d·i` (`index` is `i`).
fn rebase(function: &mut Function, plan: &Plan, index: VarId) {
    let width = function.types.pointer_width();
    let mut info = Info::new(function);
    let (var, step) = (plan.var, plan.step);
    for &id in &plan.rewrite {
        let Some(mut stmt) = function.stmts.get(id.0 as usize).cloned() else {
            continue;
        };
        let mut memo = BTreeMap::new();
        map_roots(&mut stmt, &mut |root| {
            rebuild(
                function,
                &mut info,
                root,
                &mut memo,
                &mut |function: &mut Function, info: &mut Info, node: ExprId| {
                    // `p - k` is `(p + d·i) + -k`: an access before the
                    // element `p` reached (`p[i - 1].f`).
                    let (read_p, negated) = match function.expr(node) {
                        Some(&Expr::Binary(Binary::Sub, a, b))
                            if function.expr(a) == Some(&Expr::Var(var)) =>
                        {
                            let Some(&Expr::Const(k)) = function.expr(b) else {
                                return None;
                            };
                            (a, Some(k.wrapping_neg()))
                        }
                        Some(&Expr::Var(v)) if v == var => (node, None),
                        Some(_) | None => return None,
                    };
                    let read = function.add_expr(Expr::Var(index));
                    let scaled = if step == 1 {
                        read
                    } else {
                        let size = function.add_expr(Expr::Const(Bits::from_u64(width, step)));
                        function.add_expr(Expr::Binary(Binary::Mul, read, size))
                    };
                    let mut sum = function.add_expr(Expr::Binary(Binary::Add, read_p, scaled));
                    if let Some(k) = negated {
                        let k = function.add_expr(Expr::Const(k));
                        sum = function.add_expr(Expr::Binary(Binary::Add, sum, k));
                    }
                    let origins = function.provenance.expr(node).to_vec();
                    function.provenance.set_expr(sum, &origins);
                    info.update(function);
                    Some(sum)
                },
                &mut |_: &mut Function, _: &mut Info, _: ExprId| None,
            )
        });
        if let Some(slot) = function.stmts.get_mut(id.0 as usize) {
            *slot = stmt;
        }
    }
}
