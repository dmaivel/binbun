//! Loop rules: [`Loops`].

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec;
use alloc::vec::Vec;
use core::{fmt, mem};

use binbun_ast::ir::{
    Block, Expr, ExprId, Function, LabelId, Origin, Place, Stmt, StmtId, VarId, VarKind, Variable,
};
use binbun_ast::types::{Evidence, Type};
use binbun_semantics::bits::Bits;
use binbun_semantics::core::pass::{Changed, Cx, Pass, Refusal};
use binbun_semantics::ir::{Binary, Unary};
use binbun_ssa::ir::BlockId;

use super::refine::always;
use crate::pass::{L2Env, size};
use crate::range::{Counted, Ranges, Refused};
use crate::simplify::expr::{Info, in_memory, map_roots, reads, rebuild, same};

/// The loop rules (pass `loops`), on a structured function, inner loops
/// first, reading the [`Ranges`] analysis (counted loops: a counter `i`
/// stepped by a constant, a bound `n`, the test `c'` the condition is
/// equivalent to, what holds at entry; see [`crate::range`] for the
/// rules and their soundness):
///
/// 1. *De-inversion*: `if (c) { do { B } while (c'); }` (no `else`) is
///    `while (c) { B }` where `c` and `c'` are the same tree
///    ([`same`]: the same operations on the same variables, evaluated at
///    the same point, nothing between them), one decision (not split
///    over blocks), making no call. The loop then decides at entry as
///    the `if`'s block and at each iteration as the latch's: its
///    statement names both ([`Origin::Block`], entry first), which the
///    structure check reads.
///
///    The guard of an inverted `for` has assignments `I` before the loop
///    in its `then`: `if (g) { I; do { B } while (c); }` (no `else`;
///    `if (n > 0) { i = 0; do { …; i++; } while ((int32_t)i < n); }`) is
///    `I; while (c) { B }` where `g` decides as `c` does with each
///    variable `I` assigns read as its value ([`decides_as`]: `(int32_t)i
///    < n` with `i = 0` is `0 < n`, which `!(n <= 0)` is), both one
///    decision making no call: `c`'s first test, now after `I`, decides
///    as `g` did. `I` assigns only variables not in memory, values that
///    neither load nor call (nothing `g` reads changes, nothing faults
///    ahead of it); no label is in the `then` (control enters it only
///    through `g`); and nothing outside the `if` reads a variable `I`
///    assigns (where `g` fails, `I` now runs too, unseen). This is done
///    before the rules of the blocks the `if` holds, so the loop's own
///    (rule 4's proved form in the `then`) do not take it first. `I`'s
///    statements name no block (control passes through them as through
///    the copies on an edge: their block's code is gone); the loop's
///    statement names the `if`'s block and the latch's, as above, and
///    takes the `if`'s other origins. Rule 2 then makes it `for (i = 0;
///    c; i++)`.
/// 2. *`for` formation*: `i = a; while (c) { B; S }`, where `c` reads `i`
///    and `S` is the body's last statement and assigns `i`, is
///    `for (i = a; c; S) { B }`, if no `continue` of the loop is in `B`
///    (it skips `S`; in a `for` it would not). A label just before `S`
///    that only `goto`s in `B` name is the place `continue` goes: those
///    `goto`s become `continue`s. A `for` with no `init` (rule 4's) takes
///    `i = a` likewise. Assignments between `i = a` and the loop may stay
///    before it if they are of the same L1 block (the structure check
///    sees one block's code either way) or name none (a value sinking
///    moved there: the check does not see it), write variables `a` does not
///    read, do not read `i` and make no call, and `a` neither loads nor
///    calls: then `i = a` runs after them with the same effect.
///    Without such an `i = a`, the `while` is `for (; c; S) { B }` on the
///    same terms (`for (; p != 0; p = p->next)`).
/// 3. *Exit conditions*: a `while` or `for` whose condition is a counted
///    loop's `i != n` (or a test under `!`) gets the equivalent `c'`
///    (`i < n`, read signed or unsigned as the facts at entry prove),
///    where the counter counts up (`i < n` is the idiom) or its values
///    read the same signed and unsigned (the test then says nothing about
///    its type); counting down from a value of unknown sign, `i != 0`
///    stays: `0 < i` would read no better and make `i` unsigned or signed
///    where nothing else does.
/// 4. *Rotated loops*: a counted `do { B; S } while (c)` is
///    `for (; c'; S) { B }` (`c'` as rule 3 would choose it; else `c`):
///    - if it alone is the `then` of an `if (g)` with no `else`, where `g`
///      holds for exactly the values `c'` holds for at the first
///      iteration ([`Counted::guard`]), the `if` goes: the `for`'s test
///      decides at entry as the `if`'s block (whose decision it is: the
///      same values) and at each iteration as the latch's, its statement
///      naming both as rule 1's does (the `if`'s condition one decision,
///      making no call, its block not the latch's);
///    - otherwise, where the analysis proves `c'` at the first iteration
///      (from the code before the loop: `if (n <= 0) return 0; i = 0;`),
///      the `for`'s first test always holds (`c` too: `k < n` gives `k !=
///      n`) and decides nothing: its
///      statement is [`Origin::Proved`], and the `if` that proved it
///      stays (it decides what L1's guard decides, which may be an exit
///      of its own, as `loop_sum`'s `return 0`).
///
///    Either way the code between the guard and the loop stays where it
///    is (rule 2 may then take `i = k` into the `for`), and `c` ⇔ `c'` at
///    every later iteration is the analysis's.
/// 5. *Implied first tests*: a `do { B } while (c)` (any loop, counted or
///    not) is `while (c) { B }` where the code before it decides `c`: it
///    follows, in its block, an `if (g)` with no `else` whose arm never
///    goes on (`!g` holds after it), or starts the arm of an `if (g)`
///    (`g` holds in `then`, `!g` in `else`); `c` is that fact (`g`, or
///    `!g`: `c` is `!g`, `g` is `!c`, or `==` against `!=` of the same
///    operands), both read only variables not in memory and make no
///    call, and between the two only assignments and calls write, none
///    a variable `c` reads (no label: control reaches the loop's top
///    only from the test). The first test always holds and decides
///    nothing: the statement names the latch's block and
///    [`Origin::Proved`], as rule 4's proved form; rule 2 may then make
///    it a `for`. A pointer chase `if (p == 0) return 0; do { …; p =
///    p->next; } while (p != 0);` reads `while (p != 0)`.
///
///    The code between may also assign variables `c` reads where each
///    last assignment's value neither loads nor calls and reads no
///    variable written before it there: `c` then holds where `g` decides
///    so with those variables read as their values ([`decides_as`]: `if
///    (n <= 0) return 0; i = 0; do { … } while ((int32_t)i < n);`). The
///    fact and `c` may read memory (a global, a load) where nothing
///    between them calls or writes memory: they read the same values.
/// 6. *Narrow counters*: a local `i` of `w` bits (untyped, or a deduced
///    integer), not in memory, whose every write is an assignment of a
///    constant in `0..2^(k-1)` or the step `i = i + 1` of a `for` whose
///    test is `(intk_t)i < n` (`n` of `k < w` bits; also as `!(n <=
///    (intk_t)i)`), whose body and test write no `i` and hold no label,
///    holds values in `0..2^(k-1)` only: each step runs where its loop's
///    test held at the top of that iteration (the body runs after it,
///    writes no `i`, and is entered only through it; a `continue` goes
///    to the step), so `i < n <= 2^(k-1) - 1` there and `i + 1` is in
///    range, and every other write is. `i` is then the sign extension of
///    its low `k` bits everywhere: it becomes a `k`-bit signed variable
///    (`int32_t`), each read of its low `k` bits (or fewer) a read of it
///    (or its low bits), each other read its sign extension (C's own
///    conversion: `g[i]` for `g + i·8`), each constant assigned its
///    low `k` bits and each step `i = i + 1` in `k` bits. The old variable
///    is left unused. (Locals are written before they are read, as
///    lowering makes them; as [`crate::simplify::copies::Narrow`]'s.)
///
/// Preserves nothing. Fuel: a unit per statement and expression.
#[derive(Clone, Debug, Default)]
pub struct Loops {
    rotated: BTreeMap<Rotated, usize>,
    at: BTreeMap<StmtId, Rotated>,
    applied: BTreeMap<StmtId, BTreeSet<u8>>,
}

impl Loops {
    /// What became of the `do`-`while`s of the function it last ran on.
    pub fn rotated(&self) -> &BTreeMap<Rotated, usize> {
        &self.rotated
    }

    /// What became of each `do`-`while` of the function it last ran on,
    /// by the statement that is the loop now (a rule naming it).
    pub fn outcomes(&self) -> &BTreeMap<StmtId, Rotated> {
        &self.at
    }

    /// The rules (1 to 6, as numbered above) applied to each loop of the
    /// function it last ran on, by the statement that is the loop now.
    pub fn applied(&self) -> &BTreeMap<StmtId, BTreeSet<u8>> {
        &self.applied
    }
}

/// What became of a `do`-`while` (a rotated loop).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Rotated {
    /// A `while`: its guard is its own condition (rule 1).
    Inverted,
    /// A `for` whose first test is its guard's decision (rule 4).
    Guarded,
    /// A `for` whose first test is proved (rule 4).
    Proved,
    /// A `while` whose first test the code before it decides (rule 5).
    Implied,
    /// Still a `do`-`while`: why it is not a counted loop.
    Left(Refused),
}

impl fmt::Display for Rotated {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Inverted => f.write_str("while"),
            Self::Guarded => f.write_str("for, guard"),
            Self::Proved => f.write_str("for, proved"),
            Self::Implied => f.write_str("while, implied"),
            Self::Left(refused) => write!(f, "do, {refused}"),
        }
    }
}

impl<'e> Pass<Function, L2Env<'e>> for Loops {
    fn name(&self) -> &'static str {
        "loops"
    }

    fn run(
        &mut self,
        function: &mut Function,
        cx: &mut Cx<'_, Function, L2Env<'e>>,
    ) -> Result<Changed, Refusal> {
        self.rotated.clear();
        self.at.clear();
        self.applied.clear();
        cx.fuel.spend(size(function))?;
        let ranges = cx.analysis::<Ranges>(function);
        // The walk takes blocks out as it goes: the `goto`s first.
        let mut gotos: BTreeMap<LabelId, Vec<StmtId>> = BTreeMap::new();
        let mut all = Vec::new();
        for &id in &function.body {
            collect(function, id, &mut all);
        }
        let mut rotated = BTreeMap::new();
        for id in all {
            match function.stmt(id) {
                Some(&Stmt::Goto(label)) => gotos.entry(label).or_default().push(id),
                Some(Stmt::DoWhile { condition, .. }) if !always(function, *condition) => {
                    let left = match ranges.outcome(id) {
                        Some(Err(refused)) => refused,
                        Some(Ok(_)) | None => Refused::Entry,
                    };
                    rotated.insert(id, Rotated::Left(left));
                }
                Some(_) | None => {}
            }
        }
        let (readers, parents) = readers(function);
        let mut rules = Rules {
            function,
            ranges: &ranges,
            gotos,
            rotated,
            readers,
            parents,
            applied: BTreeMap::new(),
            changed: false,
        };
        let body = mem::take(&mut rules.function.body);
        let body = rules.block(body, None);
        rules.function.body = body;
        for loop_id in narrow_counters(rules.function) {
            rules.applied(loop_id, 6);
        }
        for outcome in rules.rotated.values() {
            *self.rotated.entry(*outcome).or_default() += 1;
        }
        self.at = rules.rotated;
        self.applied = rules.applied;
        Ok(rules.changed.into())
    }
}

struct Rules<'f> {
    function: &'f mut Function,
    ranges: &'f Ranges,
    /// The `goto`s to each label.
    gotos: BTreeMap<LabelId, Vec<StmtId>>,
    /// What became of each `do`-`while`.
    rotated: BTreeMap<StmtId, Rotated>,
    /// The statements reading each variable not in memory (in the
    /// expressions they evaluate themselves), as the pass found them.
    readers: BTreeMap<VarId, Vec<StmtId>>,
    /// The statement holding each statement, as the pass found them (a
    /// statement's subtree changes only after rule 1 has looked at it).
    parents: BTreeMap<StmtId, StmtId>,
    /// The rules applied to each loop.
    applied: BTreeMap<StmtId, BTreeSet<u8>>,
    changed: bool,
}

impl Rules<'_> {
    /// Rule `rule` applied to loop `id`.
    fn applied(&mut self, id: StmtId, rule: u8) {
        self.applied.entry(id).or_default().insert(rule);
        self.changed = true;
    }

    /// `block`, its statements' blocks done first, then the rules;
    /// `entry` what holds at its start, if known: a condition and whether
    /// it holds or not (rule 5).
    fn block(&mut self, mut block: Block, entry: Option<(ExprId, bool)>) -> Block {
        self.initialise(&mut block);
        for &id in &block {
            self.inner(id);
        }
        self.deinvert(&mut block);
        self.rotate(&mut block);
        self.imply(&block, entry);
        self.form(&mut block);
        for &id in &block {
            self.exit(id);
        }
        block
    }

    /// The blocks statement `id` holds, each done (an `if`'s arms knowing
    /// its condition).
    fn inner(&mut self, id: StmtId) {
        let Some(stmt) = self.function.stmts.get_mut(id.0 as usize) else {
            return;
        };
        let decided = match stmt {
            Stmt::If { condition, .. } => Some(*condition),
            Stmt::Assign { .. }
            | Stmt::Call { .. }
            | Stmt::Intrinsic { .. }
            | Stmt::Expr(_)
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
        };
        let taken: Vec<Block> = stmt.blocks_mut().map(mem::take).collect();
        let done: Vec<Block> = (0..)
            .zip(taken)
            .map(|(arm, block)| self.block(block, decided.map(|condition| (condition, arm == 0))))
            .collect();
        if let Some(stmt) = self.function.stmts.get_mut(id.0 as usize) {
            for (slot, block) in stmt.blocks_mut().zip(done) {
                *slot = block;
            }
        }
    }

    /// Rule 5 on each `do`-`while` of `block`, `entry` holding at its
    /// start (but a loop alone in an `if`'s `then`: rule 1's, which takes
    /// the `if` too).
    fn imply(&mut self, block: &[StmtId], entry: Option<(ExprId, bool)>) {
        let alone = block.len() == 1 && entry.is_some_and(|(_, holds)| holds);
        let mut known = entry.filter(|_| !alone);
        let mut written = BTreeSet::new();
        let mut assigned = Assigned::new();
        // Whether the code since the fact may have changed memory.
        let mut effects = false;
        for &id in block {
            let function = &*self.function;
            match function.stmt(id) {
                Some(&Stmt::DoWhile { condition, .. }) => {
                    if let Some(fact) = known
                        && !always(function, condition)
                    {
                        let mut read = BTreeSet::new();
                        reads(function, condition, &mut read);
                        let through = || {
                            let memory = !pure(function, fact.0) || !pure(function, condition);
                            !(memory && effects)
                                && through(function, fact, condition, &written, &assigned)
                        };
                        if (implies(function, fact, condition) && read.is_disjoint(&written))
                            || through()
                        {
                            self.implied(id, condition);
                        }
                    }
                    known = None;
                }
                Some(Stmt::If {
                    condition,
                    then,
                    otherwise,
                }) if otherwise.is_empty() && !goes_on(function, then) => {
                    known = Some((*condition, false));
                    written.clear();
                    assigned.clear();
                    effects = false;
                }
                Some(&Stmt::Assign { place, value }) => {
                    effects |= calls(function, value);
                    match place {
                        Place::Var(var) if !in_memory(function, var) => {
                            assign(function, &mut assigned, &mut written, var, value);
                        }
                        Place::Var(var) => {
                            written.insert(var);
                            effects = true;
                        }
                        Place::Memory { .. } => effects = true,
                    }
                }
                Some(Stmt::Call { results, .. }) => {
                    for place in results {
                        if let &Place::Var(var) = place {
                            written.insert(var);
                            assigned.remove(&var);
                        }
                    }
                    effects = true;
                }
                Some(_) | None => known = None,
            }
        }
    }

    /// Makes `do`-`while` `loop_id` (of condition `latch`) a `while`
    /// whose first test is proved (rule 5).
    fn implied(&mut self, loop_id: StmtId, latch: ExprId) {
        let Some(iteration) = block_of(self.function.provenance.stmt(loop_id)) else {
            return;
        };
        let Some(&node) = self.function.expr(latch) else {
            return;
        };
        let condition = self.function.add_expr(node);
        let origins = unblocked(self.function.provenance.expr(latch));
        self.function.provenance.set_expr(condition, &origins);
        if self
            .retest(
                loop_id,
                condition,
                &[Origin::Block(iteration), Origin::Proved],
            )
            .is_some()
        {
            self.rotated.insert(loop_id, Rotated::Implied);
            self.applied(loop_id, 5);
        }
    }

    /// Rule 1 on each `if` of `block`.
    fn deinvert(&mut self, block: &mut Block) {
        for slot in block.iter_mut() {
            if let Some(loop_id) = self.inverted(*slot) {
                *slot = loop_id;
                self.rotated.insert(loop_id, Rotated::Inverted);
                self.applied(loop_id, 1);
            }
        }
    }

    /// Rule 1 on each `if` of `block` whose `then` is assignments and a
    /// `do`-`while` (the guard of an inverted `for`), ahead of the rules
    /// of the blocks it holds: the loop is a `while` after the
    /// assignments.
    fn initialise(&mut self, block: &mut Block) {
        let mut out = Vec::with_capacity(block.len());
        for &id in block.iter() {
            match self.initialised(id) {
                Some((inits, loop_id)) => {
                    out.extend(inits);
                    out.push(loop_id);
                    self.rotated.insert(loop_id, Rotated::Inverted);
                    self.applied(loop_id, 1);
                }
                None => out.push(id),
            }
        }
        *block = out;
    }

    /// `if` statement `id` as the assignments of its `then` and the
    /// `while` it guards, if rule 1 applies with assignments before the
    /// loop: the assignments (naming no block now) and the loop's id.
    fn initialised(&mut self, id: StmtId) -> Option<(Vec<StmtId>, StmtId)> {
        let function = &*self.function;
        let Some(Stmt::If {
            condition: guard,
            then,
            otherwise,
        }) = function.stmt(id)
        else {
            return None;
        };
        let (&loop_id, inits) = then.split_last()?;
        if inits.is_empty() || !otherwise.is_empty() {
            return None;
        }
        let &Stmt::DoWhile {
            condition: latch, ..
        } = function.stmt(loop_id)?
        else {
            return None;
        };
        let (entry, iteration) = decisions(function, id, loop_id)?;
        let (mut assigned, mut written) = (Assigned::new(), BTreeSet::new());
        for &init in inits {
            let &Stmt::Assign {
                place: Place::Var(var),
                value,
            } = function.stmt(init)?
            else {
                return None;
            };
            if in_memory(function, var) || !pure(function, value) {
                return None;
            }
            assign(function, &mut assigned, &mut written, var, value);
        }
        if !through(function, (*guard, true), latch, &written, &assigned) {
            return None;
        }
        let mut inside = Vec::new();
        for &stmt in then {
            collect(function, stmt, &mut inside);
        }
        if inside
            .iter()
            .any(|&stmt| matches!(function.stmt(stmt), Some(Stmt::Label(_))))
            || written.iter().any(|&var| self.read_elsewhere(var, id))
        {
            return None;
        }
        let inits = inits.to_vec();
        let guarded = unblocked(function.provenance.stmt(id));
        let node = *function.expr(latch)?;
        let condition = self.function.add_expr(node);
        let origins = unblocked(self.function.provenance.expr(latch));
        self.function.provenance.set_expr(condition, &origins);
        self.retest(
            loop_id,
            condition,
            &[Origin::Block(entry), Origin::Block(iteration)],
        )?;
        self.function.provenance.absorb_stmt(loop_id, &guarded);
        for &init in &inits {
            let origins = unblocked(self.function.provenance.stmt(init));
            self.function.provenance.set_stmt(init, &origins);
        }
        Some((inits, loop_id))
    }

    /// Whether a statement outside statement `except` (and those it holds)
    /// reads variable `var`.
    fn read_elsewhere(&self, var: VarId, except: StmtId) -> bool {
        self.readers.get(&var).is_some_and(|readers| {
            readers.iter().any(|&reader| {
                let mut at = Some(reader);
                while let Some(id) = at {
                    if id == except {
                        return false;
                    }
                    at = self.parents.get(&id).copied();
                }
                true
            })
        })
    }

    /// `if` statement `id` as the `while` it guards, if rule 1 applies:
    /// the loop's id.
    fn inverted(&mut self, id: StmtId) -> Option<StmtId> {
        let function = &*self.function;
        let (guard, loop_id) = guarded_loop(function, id)?;
        let Some(&Stmt::DoWhile {
            condition: latch, ..
        }) = function.stmt(loop_id)
        else {
            return None;
        };
        let (entry, iteration) = decisions(function, id, loop_id)?;
        if !same(function, guard, latch) || !plain(function, latch) || calls(function, latch) {
            return None;
        }
        // The condition's own root, without a block: the statement says
        // which block decides when.
        let node = *function.expr(latch)?;
        let condition = self.function.add_expr(node);
        let origins = unblocked(self.function.provenance.expr(latch));
        self.function.provenance.set_expr(condition, &origins);
        self.retest(
            loop_id,
            condition,
            &[Origin::Block(entry), Origin::Block(iteration)],
        )?;
        Some(loop_id)
    }

    /// Makes `do`-`while` `loop_id` the loop of condition `condition`
    /// whose statement is `named` (its blocks) and its other origins: a
    /// `while`, or with a step a `for` (`step` the body's last statement).
    fn retest(&mut self, loop_id: StmtId, condition: ExprId, named: &[Origin]) -> Option<()> {
        let mut statement = named.to_vec();
        statement.extend(unblocked(self.function.provenance.stmt(loop_id)));
        let stmt = self.function.stmts.get_mut(loop_id.0 as usize)?;
        let Stmt::DoWhile { body, .. } = stmt else {
            return None;
        };
        let body = mem::take(body);
        *stmt = Stmt::While { condition, body };
        self.function.provenance.set_stmt(loop_id, &statement);
        Some(())
    }

    /// Rule 4 on each `if` and `do`-`while` of `block`.
    fn rotate(&mut self, block: &mut Block) {
        for slot in block.iter_mut() {
            match self.function.stmt(*slot) {
                Some(Stmt::If { .. }) => {
                    let Some((_, loop_id)) = guarded_loop(self.function, *slot) else {
                        continue;
                    };
                    if self.rotated(loop_id, Some(*slot)) {
                        *slot = loop_id;
                    } else {
                        // Its guard cannot stand for its first test: proved,
                        // inside the `if`.
                        self.rotated(loop_id, None);
                    }
                }
                Some(Stmt::DoWhile { .. }) => {
                    // A loop its guard stands for waits for the guard's
                    // block (rule 4's first form).
                    if self
                        .ranges
                        .counted(*slot)
                        .is_none_or(|counted| counted.guard.is_none())
                    {
                        self.rotated(*slot, None);
                    }
                }
                Some(_) | None => {}
            }
        }
    }

    /// Makes counted `do`-`while` `loop_id` a `for`, its first test
    /// `guard`'s decision (which then goes) or, without one, proved: whether
    /// it did.
    fn rotated(&mut self, loop_id: StmtId, guard: Option<StmtId>) -> bool {
        let function = &*self.function;
        let Some(&counted) = self.ranges.counted(loop_id) else {
            return false;
        };
        let Some(&Stmt::DoWhile {
            condition: latch, ..
        }) = function.stmt(loop_id)
        else {
            return false;
        };
        let Some(named) = named(function, &counted, loop_id, guard) else {
            return false;
        };
        let condition = if guard.is_some() || rewrites(&counted) {
            self.canonical(&counted, latch)
        } else {
            let Some(&node) = self.function.expr(latch) else {
                return false;
            };
            let copy = self.function.add_expr(node);
            let origins = unblocked(self.function.provenance.expr(latch));
            self.function.provenance.set_expr(copy, &origins);
            copy
        };
        if self.retest(loop_id, condition, &named).is_none() {
            return false;
        }
        let Some(stmt) = self.function.stmts.get_mut(loop_id.0 as usize) else {
            return false;
        };
        let Stmt::While { condition, body } = stmt else {
            return false;
        };
        let (condition, mut body) = (*condition, mem::take(body));
        let step = body.pop().into_iter().collect();
        *stmt = Stmt::For {
            init: Vec::new(),
            condition,
            step,
            body,
        };
        self.rotated.insert(
            loop_id,
            if guard.is_some() {
                Rotated::Guarded
            } else {
                Rotated::Proved
            },
        );
        self.applied(loop_id, 4);
        true
    }

    /// `counted`'s test `c'` for condition `condition`, over reads of the
    /// counter and the bound of its own (a read the condition shared with
    /// another statement would be that statement's too, and the range
    /// facts are the loop's: [`Ranges::nonnegative`]); each with its
    /// read's origins and the test with the condition's, but blocks (the
    /// statement says which block decides when).
    fn canonical(&mut self, counted: &Counted, condition: ExprId) -> ExprId {
        let bound = self.function.expr(counted.bound_read).copied();
        let mut fresh = |read: ExprId| {
            let node = self.function.expr(read).copied()?;
            let id = self.function.add_expr(node);
            let origins = unblocked(self.function.provenance.expr(read));
            self.function.provenance.set_expr(id, &origins);
            Some(id)
        };
        let i = fresh(counted.counter_read).unwrap_or(counted.counter_read);
        // An extended bound: its variable's read is its own too.
        let n = if let Some(Expr::Extend {
            signed,
            value,
            width,
        }) = bound
            && let Some(read) = fresh(value)
        {
            let id = self.function.add_expr(Expr::Extend {
                signed,
                value: read,
                width,
            });
            let origins = unblocked(self.function.provenance.expr(counted.bound_read));
            self.function.provenance.set_expr(id, &origins);
            id
        } else {
            fresh(counted.bound_read).unwrap_or(counted.bound_read)
        };
        let (a, b) = counted.test.operands(i, n);
        let id = self
            .function
            .add_expr(Expr::Binary(counted.test.op(), a, b));
        let origins = unblocked(self.function.provenance.expr(condition));
        self.function.provenance.set_expr(id, &origins);
        id
    }

    /// Rule 2 on each `while`, and each `for` with no `init`, of `block`.
    fn form(&mut self, block: &mut Block) {
        let mut at = 0;
        while at < block.len() {
            let Some(&loop_id) = block.get(at) else {
                break;
            };
            match self.init_of(block, at, loop_id) {
                Some(init) if self.for_loop(Some(init), loop_id) => {
                    if let Some(index) = block.iter().position(|&id| id == init) {
                        block.remove(index);
                        at -= 1;
                    }
                    self.applied(loop_id, 2);
                }
                Some(_) | None => {
                    if matches!(self.function.stmt(loop_id), Some(Stmt::While { .. }))
                        && self.for_loop(None, loop_id)
                    {
                        self.applied(loop_id, 2);
                    }
                }
            }
            at += 1;
        }
    }

    /// The assignment `i = a` before loop `loop_id` (at `at` in `block`)
    /// that rule 2 may take into it: a `while` whose body's last statement
    /// or a `for` with no `init` whose step assigns `i`; between them only
    /// assignments that may stay before it.
    fn init_of(&self, block: &[StmtId], at: usize, loop_id: StmtId) -> Option<StmtId> {
        let function = &*self.function;
        let last = if let Stmt::While { body, .. } = function.stmt(loop_id)? {
            *body.last()?
        } else if let Stmt::For { init, step, .. } = function.stmt(loop_id)?
            && init.is_empty()
        {
            *step.last()?
        } else {
            return None;
        };
        let &Stmt::Assign {
            place: Place::Var(var),
            ..
        } = function.stmt(last)?
        else {
            return None;
        };
        let mut between = Vec::new();
        for &id in block.get(..at)?.iter().rev() {
            let &Stmt::Assign { place, value } = function.stmt(id)? else {
                return None;
            };
            let Place::Var(target) = place else {
                return None;
            };
            if target == var {
                let mut read = BTreeSet::new();
                reads(function, value, &mut read);
                let block = block_of(function.provenance.stmt(id));
                let independent = |&other: &StmtId| {
                    let origins = function.provenance.stmt(other);
                    stays(function, other, var, &read)
                        && (block_of(origins) == block || !names_block(origins))
                };
                return (between.is_empty()
                    || (pure(function, value) && between.iter().all(independent)))
                .then_some(id);
            }
            between.push(id);
        }
        None
    }

    /// Makes `while` statement `loop_id`, or `for` with no `init`, after
    /// assignment `init` (or with none, a `while`), a `for`, if rule 2
    /// applies.
    fn for_loop(&mut self, init: Option<StmtId>, loop_id: StmtId) -> bool {
        let function = &*self.function;
        let (condition, body, step) = match function.stmt(loop_id) {
            Some(Stmt::While { condition, body }) => {
                let Some((&step, rest)) = body.split_last() else {
                    return false;
                };
                (*condition, rest.to_vec(), step)
            }
            Some(Stmt::For {
                init: none,
                condition,
                step,
                body,
            }) if none.is_empty() => {
                let &[step] = step.as_slice() else {
                    return false;
                };
                (*condition, body.clone(), step)
            }
            Some(_) | None => return false,
        };
        let Some(&Stmt::Assign {
            place: Place::Var(var),
            ..
        }) = function.stmt(init.unwrap_or(step))
        else {
            return false;
        };
        let mut read = BTreeSet::new();
        reads(function, condition, &mut read);
        if in_memory(function, var) || always(function, condition) || !read.contains(&var) {
            return false;
        }
        if !matches!(function.stmt(step), Some(&Stmt::Assign { place: Place::Var(target), .. }) if target == var)
        {
            return false;
        }
        // A label before the step, where `goto`s in the rest go.
        let (rest, label) = match body.split_last() {
            Some((&last, before)) => match function.stmt(last) {
                Some(&Stmt::Label(label)) => (before.to_vec(), Some(label)),
                Some(_) | None => (body.clone(), None),
            },
            None => (body.clone(), None),
        };
        if continued(function, &rest, loop_id)
            && matches!(function.stmt(loop_id), Some(Stmt::While { .. }))
        {
            return false;
        }
        let gotos = label.map(|label| self.gotos.get(&label).cloned().unwrap_or_default());
        if let Some(gotos) = &gotos {
            let mut inside = Vec::new();
            for &id in &rest {
                collect(function, id, &mut inside);
            }
            if gotos.iter().any(|goto| !inside.contains(goto)) {
                return false;
            }
        }
        for goto in gotos.unwrap_or_default() {
            if let Some(slot) = self.function.stmts.get_mut(goto.0 as usize) {
                *slot = Stmt::Continue(loop_id);
            }
        }
        if let Some(slot) = self.function.stmts.get_mut(loop_id.0 as usize) {
            *slot = Stmt::For {
                init: init.into_iter().collect(),
                condition,
                step: vec![step],
                body: rest,
            };
        }
        true
    }

    /// Rule 3 on statement `id`, if a `while` or `for` of a counted loop
    /// whose condition is not its test yet.
    fn exit(&mut self, id: StmtId) {
        let function = &*self.function;
        let condition = match function.stmt(id) {
            Some(Stmt::While { condition, .. } | Stmt::For { condition, .. }) => *condition,
            Some(_) | None => return,
        };
        let Some(&counted) = self.ranges.counted(id) else {
            return;
        };
        let rewritable = matches!(
            function.expr(condition),
            Some(Expr::Binary(Binary::Ne, ..) | Expr::Unary(Unary::Not, _))
        );
        if counted.canonical || !rewritable || !rewrites(&counted) {
            return;
        }
        let new = self.canonical(&counted, condition);
        if let Some(Stmt::While { condition, .. } | Stmt::For { condition, .. }) =
            self.function.stmts.get_mut(id.0 as usize)
        {
            *condition = new;
            self.applied(id, 3);
        }
    }
}

/// `if` statement `id`'s condition and the `do`-`while` that alone is its
/// `then` (with no `else`).
fn guarded_loop(function: &Function, id: StmtId) -> Option<(ExprId, StmtId)> {
    let Some(Stmt::If {
        condition,
        then,
        otherwise,
    }) = function.stmt(id)
    else {
        return None;
    };
    let (&[loop_id], true) = (then.as_slice(), otherwise.is_empty()) else {
        return None;
    };
    matches!(function.stmt(loop_id), Some(Stmt::DoWhile { .. })).then_some((*condition, loop_id))
}

/// The blocks deciding `if` `guard_id` and loop `loop_id`, if two: a loop
/// may decide at entry as the first and at each iteration as the second.
fn decisions(function: &Function, guard_id: StmtId, loop_id: StmtId) -> Option<(BlockId, BlockId)> {
    let entry = block_of(function.provenance.stmt(guard_id))?;
    let iteration = block_of(function.provenance.stmt(loop_id))?;
    (entry != iteration).then_some((entry, iteration))
}

/// What the `for` rule 4 makes of `do`-`while` `loop_id` (`counted`)
/// names: the blocks deciding at entry and at each iteration (`guard`'s,
/// whose condition is its own decision and makes no call, then the
/// latch's), or without a guard the latch's block and
/// [`Origin::Proved`].
fn named(
    function: &Function,
    counted: &Counted,
    loop_id: StmtId,
    guard: Option<StmtId>,
) -> Option<Vec<Origin>> {
    let Some(id) = guard else {
        let iteration = block_of(function.provenance.stmt(loop_id))?;
        return Some(vec![Origin::Block(iteration), Origin::Proved]);
    };
    let &Stmt::If {
        condition: test, ..
    } = function.stmt(id)?
    else {
        return None;
    };
    let (entry, iteration) = decisions(function, id, loop_id)?;
    (counted.guard == Some(id) && plain(function, test) && !calls(function, test))
        .then(|| vec![Origin::Block(entry), Origin::Block(iteration)])
}

/// `origins` but the blocks.
fn unblocked(origins: &[Origin]) -> Vec<Origin> {
    origins
        .iter()
        .copied()
        .filter(|origin| !matches!(origin, Origin::Block(_) | Origin::Proved))
        .collect()
}

/// Whether rule 3 gives `counted`'s loop its test `c'` (see [`Loops`]):
/// it counts up, or its counter's values read the same signed and
/// unsigned.
const fn rewrites(counted: &Counted) -> bool {
    counted.test.up || counted.counter_free
}

/// Whether assignment `id` may stay before `i = a` (`var` is `i`, `read`
/// what `a` reads): it writes a variable not in memory that `a` does not
/// read, does not read `i`, and makes no call.
fn stays(function: &Function, id: StmtId, var: VarId, read: &BTreeSet<VarId>) -> bool {
    let Some(&Stmt::Assign {
        place: Place::Var(target),
        value,
    }) = function.stmt(id)
    else {
        return false;
    };
    let mut its = BTreeSet::new();
    reads(function, value, &mut its);
    !in_memory(function, target)
        && !read.contains(&target)
        && !its.contains(&var)
        && !calls(function, value)
}

/// Whether `id` neither loads nor calls nor is undefined: only constants,
/// variables not in memory and operations on them.
fn pure(function: &Function, id: ExprId) -> bool {
    let mut work = vec![id];
    while let Some(at) = work.pop() {
        match function.expr(at) {
            Some(
                Expr::Load { .. }
                | Expr::Call(_)
                | Expr::Assign { .. }
                | Expr::Undefined(..)
                | Expr::Exception { .. },
            )
            | None => return false,
            Some(&Expr::Var(var)) if in_memory(function, var) => return false,
            Some(expr) => work.extend(expr.operands(function)),
        }
    }
    true
}

/// Whether `origins` name any block.
fn names_block(origins: &[Origin]) -> bool {
    origins
        .iter()
        .any(|origin| matches!(origin, Origin::Block(_)))
}

/// The block among `origins`, if exactly one.
fn block_of(origins: &[Origin]) -> Option<BlockId> {
    let mut blocks = origins.iter().filter_map(|origin| match *origin {
        Origin::Block(block) => Some(block),
        Origin::Value(_)
        | Origin::Instruction(_)
        | Origin::Register(_)
        | Origin::Held(_)
        | Origin::Slot(_)
        | Origin::Absorbed(_)
        | Origin::Proved => None,
    });
    match (blocks.next(), blocks.next()) {
        (Some(block), None) => Some(block),
        _ => None,
    }
}

/// Whether condition `id` is one decision: no `&&`/`||` and no `!` of
/// one, and no part naming a block of its own below its root.
fn plain(function: &Function, id: ExprId) -> bool {
    match function.expr(id) {
        Some(&Expr::Unary(Unary::Not, inner)) => {
            block_of(function.provenance.expr(inner)).is_none() && plain(function, inner)
        }
        Some(Expr::Logical(..)) | None => false,
        Some(_) => true,
    }
}

/// Whether evaluating `id` makes a call.
fn calls(function: &Function, id: ExprId) -> bool {
    let mut work = vec![id];
    while let Some(at) = work.pop() {
        match function.expr(at) {
            Some(Expr::Call(_)) => return true,
            Some(expr) => work.extend(expr.operands(function)),
            None => {}
        }
    }
    false
}

/// Statement `id` and those it holds, into `out`.
fn collect(function: &Function, id: StmtId, out: &mut Vec<StmtId>) {
    let mut work = vec![id];
    while let Some(at) = work.pop() {
        out.push(at);
        if let Some(stmt) = function.stmt(at) {
            work.extend(stmt.blocks().flatten().copied());
        }
    }
}

/// Whether condition `c` holds where `fact` does (a condition, and
/// whether it holds or not): both one decision of variables not in
/// memory making no call, `c` the same tree as the condition, or as its
/// negation (rule 5).
fn implies(function: &Function, (g, holds): (ExprId, bool), c: ExprId) -> bool {
    let simple = |id| pure(function, id) && plain(function, id);
    if !simple(g) || !simple(c) {
        return false;
    }
    if holds {
        same(function, g, c)
    } else {
        negation(function, g, c) || negation(function, c, g)
    }
}

/// Whether `a` is the negation of `b`: `!b`, or `x == y` for `b` of
/// `x != y`.
fn negation(function: &Function, a: ExprId, b: ExprId) -> bool {
    if let Some(&Expr::Unary(Unary::Not, inner)) = function.expr(a) {
        return same(function, inner, b);
    }
    if let (Some(&Expr::Binary(Binary::Eq, x, y)), Some(&Expr::Binary(Binary::Ne, u, v))) =
        (function.expr(a), function.expr(b))
    {
        return same(function, x, u) && same(function, y, v);
    }
    false
}

/// Whether control may go on after `block`: `true` unless its last
/// statement never does (a `return`, a jump, a trap).
fn goes_on(function: &Function, block: &[StmtId]) -> bool {
    !matches!(
        block.last().and_then(|&last| function.stmt(last)),
        Some(
            Stmt::Return(_)
                | Stmt::Goto(_)
                | Stmt::Break(_)
                | Stmt::Continue(_)
                | Stmt::Trap(_)
                | Stmt::Unreachable
        )
    )
}

/// What the code between a decision and a loop assigned, as the loop's
/// first test reads it (rules 1 and 5): each variable (not in memory) whose
/// last assignment there has a value that neither loads nor calls and
/// reads no variable written there before it, to that value (which then
/// reads what it read at the decision).
type Assigned = BTreeMap<VarId, ExprId>;

/// Records assignment `var = value` (`var` not in memory) of the code
/// after a decision into `assigned` and `written` ([`Assigned`]).
fn assign(
    function: &Function,
    assigned: &mut Assigned,
    written: &mut BTreeSet<VarId>,
    var: VarId,
    value: ExprId,
) {
    let mut read = BTreeSet::new();
    reads(function, value, &mut read);
    if pure(function, value) && read.is_disjoint(written) {
        assigned.insert(var, value);
    } else {
        assigned.remove(&var);
    }
    written.insert(var);
}

/// Whether loop condition `c`, evaluated after code that wrote the
/// variables `written` (those of `assigned` with their values there), holds
/// where `fact` (a condition evaluated before that code, and whether it
/// holds) does: both one decision making no call, each variable `c` reads
/// that the code wrote one of `assigned`, read as its value
/// ([`decides_as`]).
fn through(
    function: &Function,
    fact: (ExprId, bool),
    c: ExprId,
    written: &BTreeSet<VarId>,
    assigned: &Assigned,
) -> bool {
    let (g, _) = fact;
    if !plain(function, g)
        || !plain(function, c)
        || !effectless(function, g)
        || !effectless(function, c)
    {
        return false;
    }
    let mut read = BTreeSet::new();
    reads(function, c, &mut read);
    let mut values = Assigned::new();
    for var in read.intersection(written) {
        let Some(&value) = assigned.get(var) else {
            return false;
        };
        values.insert(*var, value);
    }
    decides_as(function, fact, c, &values)
}

/// How deep [`decides_as`] compares operands through `values`.
const OPERAND_DEPTH: usize = 8;

/// Whether condition `c`, each variable of `values` read as its value
/// there, holds exactly where condition `g` does if `holds` (else where it
/// does not): both comparisons (under any number of `!`, a negated one its
/// complement with the operands swapped: `!(a <= b)` is `b < a`) of one
/// operator, `==` and `!=` either way round, over operands that are the
/// same tree ([`same`]) or constants of one value (`(int32_t)i` with `i =
/// 0` is `0`), a variable of `values` matching what its value matches.
fn decides_as(
    function: &Function,
    (decision, holds): (ExprId, bool),
    test: ExprId,
    values: &Assigned,
) -> bool {
    let (Some((op, left, right)), Some((other, first, second))) = (
        comparison(function, decision, !holds, 8),
        comparison(function, test, false, 8),
    ) else {
        return false;
    };
    if op != other {
        return false;
    }
    let matched = |g: ExprId, c: ExprId| operand(function, g, c, values, OPERAND_DEPTH);
    (matched(left, first) && matched(right, second))
        || (matches!(op, Binary::Eq | Binary::Ne) && matched(left, second) && matched(right, first))
}

/// Condition `id` (negated if `negated`) as a comparison: its operator and
/// operands, `!` taken as the complement with the operands swapped.
fn comparison(
    function: &Function,
    id: ExprId,
    negated: bool,
    depth: usize,
) -> Option<(Binary, ExprId, ExprId)> {
    let expr = *function.expr(id)?;
    if let Expr::Unary(Unary::Not, inner) = expr {
        return comparison(function, inner, !negated, depth.checked_sub(1)?);
    }
    let Expr::Binary(op, a, b) = expr else {
        return None;
    };
    let complement = match op {
        Binary::Eq => (Binary::Ne, a, b),
        Binary::Ne => (Binary::Eq, a, b),
        Binary::ULt => (Binary::ULe, b, a),
        Binary::ULe => (Binary::ULt, b, a),
        Binary::SLt => (Binary::SLe, b, a),
        Binary::SLe => (Binary::SLt, b, a),
        Binary::Add
        | Binary::Sub
        | Binary::Mul
        | Binary::UDiv
        | Binary::URem
        | Binary::SDiv
        | Binary::SRem
        | Binary::And
        | Binary::Or
        | Binary::Xor
        | Binary::Shl
        | Binary::LShr
        | Binary::AShr
        | Binary::Rol
        | Binary::Ror => return None,
    };
    Some(if negated { complement } else { (op, a, b) })
}

/// Whether operand `c` of a loop's test, each variable of `values` read as
/// its value, is operand `g` of a decision before it: constants of one
/// value, the same tree where it reads none of `values`, else nodes of one
/// kind over such operands (`depth` levels at most).
fn operand(function: &Function, g: ExprId, c: ExprId, values: &Assigned, depth: usize) -> bool {
    let none = Assigned::new();
    if let (Some(x), Some(y)) = (
        constant(function, g, &none, depth),
        constant(function, c, values, depth),
    ) {
        return x == y;
    }
    let mut read = BTreeSet::new();
    reads(function, c, &mut read);
    if !read.iter().any(|var| values.contains_key(var)) {
        return same(function, g, c);
    }
    let (Some(&x), Some(&y)) = (function.expr(g), function.expr(c)) else {
        return false;
    };
    if depth == 0 || matches!(x, Expr::Call(_)) || matches!(y, Expr::Call(_)) {
        return false;
    }
    if let Expr::Var(var) = y
        && let Some(&value) = values.get(&var)
    {
        return operand(function, g, value, &none, depth - 1);
    }
    let mut left = Vec::new();
    let shell_x = x.map_own(&mut |operand| {
        left.push(operand);
        ExprId(0)
    });
    let mut right = Vec::new();
    let shell_y = y.map_own(&mut |operand| {
        right.push(operand);
        ExprId(0)
    });
    shell_x == shell_y
        && left.len() == right.len()
        && left
            .into_iter()
            .zip(right)
            .all(|(g, c)| operand(function, g, c, values, depth - 1))
}

/// Expression `id`'s value if a constant: a constant, a variable of
/// `values` whose value is one, or an extraction or extension of one.
fn constant(function: &Function, id: ExprId, values: &Assigned, depth: usize) -> Option<Bits> {
    let depth = depth.checked_sub(1)?;
    let expr = *function.expr(id)?;
    if let Expr::Const(bits) = expr {
        return Some(bits);
    }
    if let Expr::Var(var) = expr {
        return constant(function, *values.get(&var)?, &Assigned::new(), depth);
    }
    if let Expr::Extract {
        value,
        offset,
        width,
    } = expr
    {
        return Some(constant(function, value, values, depth)?.extract(offset, width));
    }
    let Expr::Extend {
        signed,
        value,
        width,
    } = expr
    else {
        return None;
    };
    let value = constant(function, value, values, depth)?;
    Some(if signed {
        value.sext(width)
    } else {
        value.zext(width)
    })
}

/// Whether evaluating `id` changes nothing and gives one value each time
/// for the same state: no call, no assignment, no undefined value (two
/// reads of one may differ), no exception value.
fn effectless(function: &Function, id: ExprId) -> bool {
    let mut work = vec![id];
    while let Some(at) = work.pop() {
        match function.expr(at) {
            Some(
                Expr::Call(_) | Expr::Assign { .. } | Expr::Undefined(..) | Expr::Exception { .. },
            )
            | None => return false,
            Some(expr) => work.extend(expr.operands(function)),
        }
    }
    true
}

/// The statements of `function` reading each variable not in memory (in
/// the expressions they evaluate themselves), and the statement holding
/// each statement.
fn readers(function: &Function) -> (BTreeMap<VarId, Vec<StmtId>>, BTreeMap<StmtId, StmtId>) {
    let mut readers: BTreeMap<VarId, Vec<StmtId>> = BTreeMap::new();
    let mut parents = BTreeMap::new();
    let mut work: Vec<StmtId> = function.body.clone();
    while let Some(id) = work.pop() {
        let Some(stmt) = function.stmt(id) else {
            continue;
        };
        let mut read = BTreeSet::new();
        for root in stmt.roots() {
            reads(function, root, &mut read);
        }
        for var in read {
            readers.entry(var).or_default().push(id);
        }
        for &inner in stmt.blocks().flatten() {
            parents.insert(inner, id);
            work.push(inner);
        }
    }
    (readers, parents)
}

/// Whether a `continue` of `loop_id` is among `block`'s statements (and
/// those they hold).
fn continued(function: &Function, block: &[StmtId], loop_id: StmtId) -> bool {
    let mut all = Vec::new();
    for &id in block {
        collect(function, id, &mut all);
    }
    all.into_iter()
        .any(|id| function.stmt(id) == Some(&Stmt::Continue(loop_id)))
}

/// A counter rule 6 narrows: its width read (`k`), and the steps of the
/// `for` loops counting it, with the loops.
struct Counter {
    width: u16,
    steps: BTreeMap<StmtId, StmtId>,
}

/// Rule 6 on `function`: the `for` loops whose counter it narrowed.
fn narrow_counters(function: &mut Function) -> Vec<StmtId> {
    let mut all = Vec::new();
    for &id in &function.body {
        collect(function, id, &mut all);
    }
    let mut counters: BTreeMap<VarId, Counter> = BTreeMap::new();
    let mut refused: BTreeSet<VarId> = BTreeSet::new();
    for &id in &all {
        let Some(Stmt::For {
            condition,
            step,
            body,
            ..
        }) = function.stmt(id)
        else {
            continue;
        };
        let Some((var, width, step)) = counting(function, *condition, step, body) else {
            continue;
        };
        let counter = counters.entry(var).or_insert(Counter {
            width,
            steps: BTreeMap::new(),
        });
        if counter.width != width {
            refused.insert(var);
        }
        counter.steps.insert(step, id);
    }
    for &id in &all {
        let Some(stmt) = function.stmt(id) else {
            continue;
        };
        for var in written(function, stmt) {
            let Some(counter) = counters.get(&var) else {
                continue;
            };
            let start = match *stmt {
                Stmt::Assign { value, .. } => match function.expr(value) {
                    Some(Expr::Const(bits)) => Some(*bits),
                    Some(_) | None => None,
                },
                Stmt::Call { .. }
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
            };
            let in_range = start.is_some_and(|bits| {
                bits.low_u128() < 1u128 << (counter.width - 1) && bits.width() <= 128
            });
            if !counter.steps.contains_key(&id) && !in_range {
                refused.insert(var);
            }
        }
    }
    let mut narrowed = Vec::new();
    let mut info = Info::new(function);
    for (var, counter) in counters {
        if refused.contains(&var) {
            continue;
        }
        narrow(function, &mut info, &all, var, &counter);
        narrowed.extend(counter.steps.into_values());
    }
    narrowed
}

/// The counter `for` loop of test `condition`, step `step` and body `body`
/// counts as rule 6 reads it, its width read and its step, if one: a step
/// `i = i + 1` of a local `i` (untyped, or a deduced integer) not in
/// memory, a test `(intk_t)i < n` with `n` reading no `i`, neither the
/// test nor the body writing `i`, no label in the body.
fn counting(
    function: &Function,
    condition: ExprId,
    step: &[StmtId],
    body: &[StmtId],
) -> Option<(VarId, u16, StmtId)> {
    let &[step] = step else {
        return None;
    };
    let &Stmt::Assign {
        place: Place::Var(var),
        value,
    } = function.stmt(step)?
    else {
        return None;
    };
    let variable = function.var(var)?;
    let ((&Type::Bits(wide), Evidence::Default) | (&Type::Int(wide), Evidence::Deduced)) =
        (function.types.get(variable.ty)?, variable.evidence)
    else {
        return None;
    };
    if variable.kind != VarKind::Local || in_memory(function, var) {
        return None;
    }
    let Expr::Binary(Binary::Add, counter, one) = *function.expr(value)? else {
        return None;
    };
    if function.expr(counter) != Some(&Expr::Var(var))
        || function.expr(one) != Some(&Expr::Const(Bits::from_u64(wide, 1)))
    {
        return None;
    }
    let (Binary::SLt, low, bound) = comparison(function, condition, false, 8)? else {
        return None;
    };
    let Expr::Extract {
        value: read,
        offset: 0,
        width,
    } = *function.expr(low)?
    else {
        return None;
    };
    let mut bound_reads = BTreeSet::new();
    reads(function, bound, &mut bound_reads);
    if function.expr(read) != Some(&Expr::Var(var))
        || !(2..wide).contains(&width)
        || bound_reads.contains(&var)
        || !effectless(function, condition)
    {
        return None;
    }
    let mut inside = Vec::new();
    for &id in body {
        collect(function, id, &mut inside);
    }
    let touched = inside.iter().any(|&id| {
        function.stmt(id).is_some_and(|stmt| {
            matches!(stmt, Stmt::Label(_)) || written(function, stmt).contains(&var)
        })
    });
    (!touched).then_some((var, width, step))
}

/// The variables statement `stmt` itself writes (not those of the
/// blocks it holds): its places', and those its expressions assign.
fn written(function: &Function, stmt: &Stmt) -> Vec<VarId> {
    let var = |place: &Place| match *place {
        Place::Var(var) => Some(var),
        Place::Memory { .. } => None,
    };
    let mut out: Vec<VarId> = match stmt {
        Stmt::Assign { place, .. } | Stmt::VaStart { list: place } => {
            var(place).into_iter().collect()
        }
        Stmt::Call { results, .. }
        | Stmt::Intrinsic { results, .. }
        | Stmt::Escape { results, .. } => results.iter().filter_map(var).collect(),
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
        | Stmt::Try { .. } => Vec::new(),
    };
    let mut work = stmt.roots();
    while let Some(id) = work.pop() {
        let Some(expr) = function.expr(id) else {
            continue;
        };
        if let Expr::Assign { var, .. } = *expr {
            out.push(var);
        }
        work.extend(expr.operands(function));
    }
    out
}

/// Narrows counter `var` (rule 6) in the statements `all`: a new signed
/// variable of `counter.width` bits for it.
fn narrow(function: &mut Function, info: &mut Info, all: &[StmtId], var: VarId, counter: &Counter) {
    let Some(old) = function.var(var).cloned() else {
        return;
    };
    let Some(wide) = function.types.value_width(old.ty) else {
        return;
    };
    let width = counter.width;
    let ty = function.types.intern(Type::Int(width));
    let new = function.add_var(Variable {
        kind: VarKind::Local,
        name: old.name,
        ty,
        evidence: Evidence::Deduced,
        origins: old.origins,
    });
    for &id in all {
        if let Some(&Stmt::Assign {
            place: Place::Var(target),
            value,
        }) = function.stmt(id)
            && target == var
        {
            let fresh = if counter.steps.contains_key(&id) {
                let read = function.add_expr(Expr::Var(new));
                let one = function.add_expr(Expr::Const(Bits::from_u64(width, 1)));
                function.add_expr(Expr::Binary(Binary::Add, read, one))
            } else {
                let Some(&Expr::Const(bits)) = function.expr(value) else {
                    continue;
                };
                function.add_expr(Expr::Const(bits.extract(0, width)))
            };
            let origins = function.provenance.expr(value).to_vec();
            function.provenance.set_expr(fresh, &origins);
            if let Some(slot) = function.stmts.get_mut(id.0 as usize) {
                *slot = Stmt::Assign {
                    place: Place::Var(new),
                    value: fresh,
                };
            }
            info.update(function);
            continue;
        }
        let Some(mut stmt) = function.stmts.get(id.0 as usize).cloned() else {
            continue;
        };
        let mut memo = BTreeMap::new();
        map_roots(&mut stmt, &mut |root| {
            rebuild(
                function,
                info,
                root,
                &mut memo,
                &mut |function: &mut Function, info: &mut Info, node: ExprId| {
                    let expr = *function.expr(node)?;
                    let replaced = if let Expr::Extract {
                        value,
                        offset: 0,
                        width: low,
                    } = expr
                        && low <= width
                        && function.expr(value) == Some(&Expr::Var(var))
                    {
                        let read = function.add_expr(Expr::Var(new));
                        if low == width {
                            read
                        } else {
                            function.add_expr(Expr::Extract {
                                value: read,
                                offset: 0,
                                width: low,
                            })
                        }
                    } else if expr == Expr::Var(var) {
                        let read = function.add_expr(Expr::Var(new));
                        function.add_expr(Expr::Extend {
                            signed: true,
                            value: read,
                            width: wide,
                        })
                    } else {
                        return None;
                    };
                    let origins = function.provenance.expr(node).to_vec();
                    function.provenance.set_expr(replaced, &origins);
                    info.update(function);
                    Some(replaced)
                },
                &mut |_: &mut Function, _: &mut Info, _: ExprId| None,
            )
        });
        if let Some(slot) = function.stmts.get_mut(id.0 as usize) {
            *slot = stmt;
        }
    }
}
