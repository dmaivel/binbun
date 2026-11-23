//! Copy coalescing: [`Coalesce`].

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec;
use alloc::vec::Vec;
use core::mem;

use binbun_ast::ir::{Expr, ExprId, Function, Place, Stmt, StmtId, VarId, VarKind};
use binbun_ast::types::{Evidence, Type, TypeId, Types};
use binbun_semantics::core::pass::{Changed, Cx, Fuel, Pass, Refusal};

use super::expr::{Info, append, in_memory, map_roots, reads, rebuild, roots};
use super::flow::{Flow, Point};
use crate::pass::L2Env;

/// Copy coalescing (pass `coalesce`), after Boissinot et al.,
/// "Revisiting Out-of-SSA Translation for Correctness, Code Quality, and
/// Efficiency" (2009), on structured L2: the two variables of a copy
/// `x = y` (locals or a parameter, not in memory) become one, and the
/// copy `x = x` (which [`Prune`](super::copies::Prune) removes), where
/// they never hold different values while both are live. Liveness runs
/// over the statements' control flow (loops, `break`, `continue`,
/// `goto`); values are numbered forward, a copy giving its target its
/// source's value and a join where they differ a value of its own (as
/// SSA's φ), so `v13 = v19 + v12; v19 = v13; … return v13` is one
/// variable: where both are live they hold one value. Two variables
/// interfere where one is written (or both start, at the entry) while
/// the other is live after with another value. Copies in loops go first,
/// then in order; a class keeps at most one parameter (it is the one
/// left) and at most one type with evidence, but for deduced `void *`
/// beside other pointers (the solver's `void *` is a pointer whose target
/// it does not know: the class takes the pointer that has one); the
/// variable left is the parameter, else a named one, else one with
/// evidence, else the first. Only variables in copies take part.
/// Preserves nothing.
#[derive(Clone, Copy, Debug, Default)]
pub struct Coalesce;

impl<'e> Pass<Function, L2Env<'e>> for Coalesce {
    fn name(&self) -> &'static str {
        "coalesce"
    }

    fn run(
        &mut self,
        function: &mut Function,
        cx: &mut Cx<'_, Function, L2Env<'e>>,
    ) -> Result<Changed, Refusal> {
        let flow = Flow::new(function);
        let facts = Facts::new(function, &flow);
        if facts.copies.is_empty() {
            return Ok(Changed::No);
        }
        let live = facts.liveness(&flow, cx.fuel)?;
        let values = facts.values(&flow, cx.fuel)?;
        let interference = facts.interference(&live, &values);
        let classes = facts.classes(function, &interference);
        if classes.is_empty() {
            return Ok(Changed::No);
        }
        rename(function, &classes);
        Ok(Changed::Yes)
    }
}

/// A variable's index among those that take part ([`Facts::vars`]).
type Index = usize;

/// A node's reads and writes of the variables that take part.
#[derive(Clone, Debug, Default)]
struct Node {
    uses: Vec<Index>,
    /// Without repeats.
    defs: Vec<Index>,
    /// A copy between two of them: (target, source).
    copy: Option<(Index, Index)>,
}

impl Node {
    /// Whether the node gives variable `var` a value of its own (a copy
    /// its source's), so its value before does not matter.
    fn sets(&self, var: Index) -> bool {
        match self.copy {
            Some((target, _)) => target == var,
            None => self.defs.contains(&var),
        }
    }
}

/// The variables in copies, and what each node does with them.
struct Facts {
    vars: Vec<VarId>,
    nodes: Vec<Node>,
    /// The copies, loop depth first (deepest first), then in order.
    copies: Vec<(Index, Index)>,
}

/// A set of variable indices.
type Bits = Vec<u64>;

fn has(bits: &[u64], index: Index) -> bool {
    bits.get(index / 64)
        .is_some_and(|word| word & (1 << (index % 64)) != 0)
}

fn insert(bits: &mut [u64], index: Index) {
    if let Some(word) = bits.get_mut(index / 64) {
        *word |= 1 << (index % 64);
    }
}

/// Whether variable `var` takes part: not in memory, a local or a
/// parameter, and not the `va_list` (`va`: what `va_start` writes is its
/// own variable).
fn eligible(function: &Function, var: VarId, va: Option<VarId>) -> bool {
    !in_memory(function, var)
        && va != Some(var)
        && function
            .var(var)
            .is_some_and(|variable| matches!(variable.kind, VarKind::Local | VarKind::Parameter))
}

impl Facts {
    fn new(function: &Function, flow: &Flow) -> Self {
        // The copies, with their loop depth and place.
        let mut found: Vec<(u32, u32, VarId, VarId)> = Vec::new();
        let va = function.va_list();
        for (node, point) in (0u32..).zip(&flow.points) {
            let &Point::Simple(id) = point else {
                continue;
            };
            if let Some(&Stmt::Assign {
                place: Place::Var(target),
                value,
            }) = function.stmt(id)
                && let Some(&Expr::Var(source)) = function.expr(value)
                && target != source
                && eligible(function, target, va)
                && eligible(function, source, va)
            {
                let depth = flow.depth.get(node as usize).copied().unwrap_or(0);
                found.push((depth, node, target, source));
            }
        }
        let vars: Vec<VarId> = found
            .iter()
            .flat_map(|&(_, _, target, source)| [target, source])
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let index: BTreeMap<VarId, Index> = vars.iter().enumerate().map(|(i, &v)| (v, i)).collect();
        let mut nodes = vec![Node::default(); flow.points.len()];
        if let Some(entry) = nodes.get_mut(Flow::ENTRY as usize) {
            entry.defs = (0..vars.len()).collect();
        }
        for (node, point) in nodes.iter_mut().zip(&flow.points) {
            let (Point::Simple(id) | Point::Test(id)) = *point else {
                continue;
            };
            let Some(stmt) = function.stmt(id) else {
                continue;
            };
            let mut read = BTreeSet::new();
            for root in roots(stmt) {
                reads(function, root, &mut read);
            }
            node.uses = read
                .iter()
                .filter_map(|var| index.get(var).copied())
                .collect();
            if let Point::Simple(_) = point {
                node.defs = written(stmt)
                    .into_iter()
                    .filter_map(|var| index.get(&var).copied())
                    .collect();
                node.defs.sort_unstable();
                node.defs.dedup();
            }
        }
        found.sort_by_key(|&(depth, node, ..)| (core::cmp::Reverse(depth), node));
        let mut copies = Vec::with_capacity(found.len());
        for (_, node, target, source) in found {
            let (Some(&t), Some(&s)) = (index.get(&target), index.get(&source)) else {
                continue;
            };
            if let Some(slot) = nodes.get_mut(node as usize) {
                slot.copy = Some((t, s));
            }
            copies.push((t, s));
        }
        Self {
            vars,
            nodes,
            copies,
        }
    }

    fn words(&self) -> usize {
        self.vars.len().div_ceil(64)
    }

    /// The variables live after each node (backward, to a fixed point),
    /// a unit of fuel per node visited.
    fn liveness(&self, flow: &Flow, fuel: &mut Fuel) -> Result<Vec<Bits>, Refusal> {
        let words = self.words();
        let count = self.nodes.len();
        let mut live_in = vec![vec![0u64; words]; count];
        let mut live_out = vec![vec![0u64; words]; count];
        let predecessors = flow.predecessors();
        let mut work: Vec<u32> = (0..u32::try_from(count).unwrap_or(u32::MAX)).collect();
        let mut queued = vec![true; count];
        while let Some(node) = work.pop() {
            fuel.spend(1)?;
            let n = node as usize;
            if let Some(flag) = queued.get_mut(n) {
                *flag = false;
            }
            let mut out = vec![0u64; words];
            for &next in flow.successors.get(n).map_or(&[][..], Vec::as_slice) {
                if let Some(other) = live_in.get(next as usize) {
                    for (word, bits) in out.iter_mut().zip(other) {
                        *word |= bits;
                    }
                }
            }
            let mut input = out.clone();
            let Some(own) = self.nodes.get(n) else {
                continue;
            };
            for &def in &own.defs {
                if let Some(word) = input.get_mut(def / 64) {
                    *word &= !(1 << (def % 64));
                }
            }
            for &used in &own.uses {
                insert(&mut input, used);
            }
            if let Some(slot) = live_out.get_mut(n) {
                *slot = out;
            }
            if live_in.get(n) != Some(&input) {
                if let Some(slot) = live_in.get_mut(n) {
                    *slot = input;
                }
                for &previous in predecessors.get(n).map_or(&[][..], Vec::as_slice) {
                    if let Some(flag) = queued.get_mut(previous as usize)
                        && !*flag
                    {
                        *flag = true;
                        work.push(previous);
                    }
                }
            }
        }
        Ok(live_out)
    }

    /// The value each variable holds after each node (forward, to a fixed
    /// point): 0 for none yet, else a number standing for one value, a
    /// write's or a join's where its predecessors differ ([`Numbering`]).
    /// The work list takes the nodes in the order a recomputation of every
    /// variable at every visit would (a node again when its values
    /// changed), which the result depends on (a join that sees two values
    /// in passing keeps a value of its own); a visit looks only at the
    /// variables a predecessor changed since the last. A unit of fuel per
    /// node visited and per 64 of its variables.
    fn values(&self, flow: &Flow, fuel: &mut Fuel) -> Result<Values, Refusal> {
        let count = self.nodes.len();
        let words = self.words();
        let cost = 1 + u64::try_from(self.vars.len() / 64).unwrap_or(u64::MAX);
        let predecessors = flow.predecessors();
        let mut numbering = Numbering::new(self, &predecessors)?;
        // The variables each node's predecessors changed since its visit,
        // a set of `words` words per node.
        let mut pending = vec![0u64; count.checked_mul(words).ok_or(Refusal::OutOfFuel)?];
        let mut work: Vec<usize> = (0..count).rev().collect();
        let mut queued = vec![true; count];
        let mut inputs = Vec::new();
        let mut changed = Vec::new();
        while let Some(n) = work.pop() {
            fuel.spend(cost)?;
            if let Some(flag) = queued.get_mut(n) {
                *flag = false;
            }
            inputs.clear();
            if let Some(row) = pending.get_mut(n * words..(n + 1) * words) {
                for (at, word) in (0..).step_by(64).zip(row) {
                    let mut bits = mem::take(word);
                    while bits != 0 {
                        inputs.push(at + bits.trailing_zeros() as usize);
                        bits &= bits - 1;
                    }
                }
            }
            changed.clear();
            numbering.visit(n, &inputs, &mut changed)?;
            if !changed.is_empty() {
                for &next in flow.successors.get(n).map_or(&[][..], Vec::as_slice) {
                    let next = next as usize;
                    if let Some(row) = pending.get_mut(next * words..(next + 1) * words) {
                        for &var in &changed {
                            insert(row, var);
                        }
                    }
                    if let Some(flag) = queued.get_mut(next)
                        && !*flag
                    {
                        *flag = true;
                        work.push(next);
                    }
                }
            }
        }
        Ok(numbering.values)
    }

    /// Which variables interfere, each a set: where one is written, the
    /// other is live after with another value.
    fn interference(&self, live: &[Bits], values: &Values) -> Vec<Bits> {
        let words = self.words();
        let mut interference = vec![vec![0u64; words]; self.vars.len()];
        for (index, (node, live)) in self.nodes.iter().zip(live).enumerate() {
            let values = values.after(index);
            for &def in &node.defs {
                let own = values.get(def).copied().unwrap_or(0);
                for other in 0..self.vars.len() {
                    let differ = own == 0 || values.get(other).copied().unwrap_or(0) != own;
                    if other != def && has(live, other) && differ {
                        if let Some(set) = interference.get_mut(def) {
                            insert(set, other);
                        }
                        if let Some(set) = interference.get_mut(other) {
                            insert(set, def);
                        }
                    }
                }
            }
        }
        interference
    }

    /// The classes of variables to make one (each with more than one
    /// member), by representative.
    fn classes(&self, function: &Function, interference: &[Bits]) -> BTreeMap<VarId, Vec<VarId>> {
        let count = self.vars.len();
        let mut parent: Vec<Index> = (0..count).collect();
        let mut members: Vec<Bits> = (0..count)
            .map(|index| {
                let mut bits = vec![0u64; self.words()];
                insert(&mut bits, index);
                bits
            })
            .collect();
        let mut against: Vec<Bits> = interference.to_vec();
        let find = |parent: &[Index], mut index: Index| {
            while let Some(&up) = parent.get(index) {
                if up == index {
                    break;
                }
                index = up;
            }
            index
        };
        for &(target, source) in &self.copies {
            let (a, b) = (find(&parent, target), find(&parent, source));
            if a == b {
                continue;
            }
            let (Some(left), Some(right)) = (members.get(a), members.get(b)) else {
                continue;
            };
            let clash = against
                .get(a)
                .is_some_and(|set| set.iter().zip(right).any(|(x, y)| x & y != 0));
            if clash || !self.compatible(function, left, right) {
                continue;
            }
            let joined: Bits = left.iter().zip(right).map(|(x, y)| x | y).collect();
            let opposed: Bits = against
                .get(a)
                .zip(against.get(b))
                .map(|(x, y)| x.iter().zip(y).map(|(p, q)| p | q).collect())
                .unwrap_or_default();
            if let Some(slot) = parent.get_mut(b) {
                *slot = a;
            }
            if let Some(slot) = members.get_mut(a) {
                *slot = joined;
            }
            if let Some(slot) = against.get_mut(a) {
                *slot = opposed;
            }
        }
        let mut classes: BTreeMap<Index, Vec<VarId>> = BTreeMap::new();
        for (index, &var) in self.vars.iter().enumerate() {
            classes.entry(find(&parent, index)).or_default().push(var);
        }
        classes
            .into_values()
            .filter(|class| class.len() > 1)
            .filter_map(|class| Some((representative(function, &class)?, class)))
            .collect()
    }

    /// Whether the classes `left` and `right` may be one: one parameter
    /// at most, one type with evidence at most ([`class_type`]), one
    /// width.
    fn compatible(&self, function: &Function, left: &Bits, right: &Bits) -> bool {
        let mut parameters = 0;
        let mut typed = Vec::new();
        let mut widths = BTreeSet::new();
        for (index, &var) in self.vars.iter().enumerate() {
            if !has(left, index) && !has(right, index) {
                continue;
            }
            let Some(variable) = function.var(var) else {
                return false;
            };
            parameters += usize::from(variable.kind == VarKind::Parameter);
            typed.push((variable.ty, variable.evidence));
            widths.insert(function.types.value_width(variable.ty));
        }
        parameters <= 1 && widths.len() == 1 && class_type(&function.types, &typed).is_ok()
    }
}

/// The type with evidence of a class whose members have `members`
/// (`Ok(None)`: none has evidence), or `Err` where they have several:
/// every member with evidence has one type, but deduced `void *` members
/// give way to another pointer.
fn class_type(
    types: &Types,
    members: &[(TypeId, Evidence)],
) -> Result<Option<(TypeId, Evidence)>, ()> {
    let opaque = |(ty, evidence): (TypeId, Evidence)| {
        evidence == Evidence::Deduced && types.get(ty) == Some(&Type::Pointer(None))
    };
    let pointer = |ty: TypeId| matches!(types.get(ty), Some(Type::Pointer(_)));
    let with = members
        .iter()
        .copied()
        .filter(|&(_, evidence)| evidence != Evidence::Default);
    let mut kept: Option<(TypeId, Evidence)> = None;
    for member in with {
        kept = match kept {
            None => Some(member),
            Some(old) if old.0 == member.0 => Some(member),
            Some(old) if opaque(old) && pointer(member.0) => Some(member),
            Some(old) if opaque(member) && pointer(old.0) => Some(old),
            Some(_) => return Err(()),
        };
    }
    Ok(kept)
}

/// The value each variable holds after each node ([`Facts::values`]).
struct Values {
    /// Node by node, a value per variable: 0 for none yet, else a number
    /// standing for one value.
    table: Vec<Vec<u32>>,
}

impl Values {
    /// The values after node `node`, by variable.
    fn after(&self, node: usize) -> &[u32] {
        self.table.get(node).map_or(&[], Vec::as_slice)
    }
}

/// [`Facts::values`] in progress: the values, and how they are numbered.
/// Each write of a variable has a number of its own (from 1, node by
/// node), then each join where a variable's predecessors differ (as SSA's
/// φ), numbered as they are found; a join's value of its own, once taken,
/// stays (so each join changes at most twice and the iteration ends).
struct Numbering<'a> {
    nodes: &'a [Node],
    predecessors: &'a [Vec<u32>],
    values: Values,
    /// The number of each node's first write.
    first_write: Vec<u32>,
    /// The first join's number.
    first_join: u32,
    /// Each join's node and variable, by number from [`Self::first_join`].
    joins: Vec<(usize, Index)>,
}

impl<'a> Numbering<'a> {
    /// Nothing known yet; [`Refusal::OutOfFuel`] if the writes' numbers do
    /// not fit.
    fn new(facts: &'a Facts, predecessors: &'a [Vec<u32>]) -> Result<Self, Refusal> {
        let vars = facts.vars.len();
        let mut first_write = Vec::with_capacity(facts.nodes.len());
        let mut next = 1u32;
        for node in &facts.nodes {
            first_write.push(next);
            next = u32::try_from(node.defs.len())
                .ok()
                .and_then(|defs| next.checked_add(defs))
                .ok_or(Refusal::OutOfFuel)?;
        }
        Ok(Self {
            nodes: &facts.nodes,
            predecessors,
            values: Values {
                table: vec![vec![0; vars]; facts.nodes.len()],
            },
            first_write,
            first_join: next,
            joins: Vec::new(),
        })
    }

    fn get(&self, node: usize, var: Index) -> u32 {
        self.values.after(node).get(var).copied().unwrap_or(0)
    }

    /// Variable `var` holds `value` after node `node`; if that is new, `var`
    /// is pushed on `changed`.
    fn set(&mut self, node: usize, var: Index, value: u32, changed: &mut Vec<Index>) {
        if let Some(slot) = self
            .values
            .table
            .get_mut(node)
            .and_then(|row| row.get_mut(var))
            && *slot != value
        {
            *slot = value;
            changed.push(var);
        }
    }

    /// Node `node` again, its predecessors having changed the variables
    /// `inputs` (sorted, without repeats) since its last visit: the
    /// variables whose value after it changed pushed on `changed`.
    fn visit(
        &mut self,
        node: usize,
        inputs: &[Index],
        changed: &mut Vec<Index>,
    ) -> Result<(), Refusal> {
        let Some(own) = self.nodes.get(node) else {
            return Ok(());
        };
        for &var in inputs {
            if !own.sets(var) {
                let value = self.join(node, var)?;
                self.set(node, var, value, changed);
            }
        }
        if let Some((target, source)) = own.copy {
            let value = self.get(node, source);
            self.set(node, target, value, changed);
        } else {
            let first = self.first_write.get(node).copied().unwrap_or(0);
            for (&def, value) in own.defs.iter().zip(first..) {
                self.set(node, def, value, changed);
            }
        }
        Ok(())
    }

    /// Variable `var`'s value before node `node` (which does not set it):
    /// its predecessors' (those with one), or the node's own where they
    /// differ or did before.
    fn join(&mut self, node: usize, var: Index) -> Result<u32, Refusal> {
        let current = self.get(node, var);
        let own = current
            .checked_sub(self.first_join)
            .and_then(|number| self.joins.get(number as usize));
        if own == Some(&(node, var)) {
            return Ok(current);
        }
        let mut joined = 0;
        let mut differ = false;
        for &previous in self.predecessors.get(node).map_or(&[][..], Vec::as_slice) {
            let value = self.get(previous as usize, var);
            if value == 0 || value == joined {
                continue;
            }
            if joined != 0 {
                differ = true;
                break;
            }
            joined = value;
        }
        if !differ {
            return Ok(joined);
        }
        let number = u32::try_from(self.joins.len())
            .ok()
            .and_then(|count| self.first_join.checked_add(count))
            .ok_or(Refusal::OutOfFuel)?;
        self.joins.push((node, var));
        Ok(number)
    }
}

/// The variable `class` becomes: its parameter, else a named one, else
/// one with evidence, else the first.
fn representative(function: &Function, class: &[VarId]) -> Option<VarId> {
    let rank = |var: &VarId| {
        let variable = function.var(*var)?;
        Some((
            variable.kind != VarKind::Parameter,
            variable.name.is_none(),
            variable.evidence == Evidence::Default,
            *var,
        ))
    };
    class.iter().min_by_key(|var| rank(var)).copied()
}

/// The variables not in memory statement `stmt` writes (itself, not the
/// statements it holds).
fn written(stmt: &Stmt) -> Vec<VarId> {
    let places: &[Place] = match stmt {
        Stmt::Assign { place, .. } => core::slice::from_ref(place),
        Stmt::VaStart { list } => core::slice::from_ref(list),
        Stmt::Call { results, .. }
        | Stmt::Intrinsic { results, .. }
        | Stmt::Escape { results, .. } => results,
        Stmt::Expr(_)
        | Stmt::If { .. }
        | Stmt::While { .. }
        | Stmt::DoWhile { .. }
        | Stmt::For { .. }
        | Stmt::Switch { .. }
        | Stmt::Try { .. }
        | Stmt::Break(_)
        | Stmt::Continue(_)
        | Stmt::Label(_)
        | Stmt::Goto(_)
        | Stmt::Return(_)
        | Stmt::Trap(_)
        | Stmt::Unreachable => &[],
    };
    places
        .iter()
        .filter_map(|place| match *place {
            Place::Var(var) => Some(var),
            Place::Memory { .. } => None,
        })
        .collect()
}

/// Makes each class one variable, its representative: reads and writes
/// renamed, the representative given the class's type with evidence and
/// every member's origins.
fn rename(function: &mut Function, classes: &BTreeMap<VarId, Vec<VarId>>) {
    let mut to: BTreeMap<VarId, VarId> = BTreeMap::new();
    for (&representative, class) in classes {
        let mut origins = Vec::new();
        let mut typed = Vec::new();
        for &var in class {
            if let Some(variable) = function.var(var) {
                origins.extend(variable.origins.iter().copied());
                typed.push((variable.ty, variable.evidence));
            }
            if var != representative {
                to.insert(var, representative);
            }
        }
        let typed = class_type(&function.types, &typed).ok().flatten();
        if let Some(variable) = function.variables.get_mut(representative.0 as usize) {
            for origin in origins {
                if !variable.origins.contains(&origin) {
                    variable.origins.push(origin);
                }
            }
            if let Some((ty, evidence)) = typed {
                variable.ty = ty;
                variable.evidence = evidence;
            }
        }
    }
    let mut info = Info::new(function);
    let mut statements = Vec::new();
    super::rules::statements(function, &function.body, &mut statements);
    for id in statements {
        rename_stmt(function, &mut info, id, &to);
    }
}

/// Statement `id` with the variables of `to` renamed.
fn rename_stmt(function: &mut Function, info: &mut Info, id: StmtId, to: &BTreeMap<VarId, VarId>) {
    let Some(stmt) = function.stmt(id) else {
        return;
    };
    let mut memo = BTreeMap::new();
    let mut before = |function: &mut Function, info: &mut Info, at: ExprId| {
        let Some(&Expr::Var(var)) = function.expr(at) else {
            return None;
        };
        let &new = to.get(&var)?;
        Some(append(function, info, Expr::Var(new), at))
    };
    for root in roots(stmt) {
        rebuild(
            function,
            info,
            root,
            &mut memo,
            &mut before,
            &mut |_, _, _| None,
        );
    }
    let Some(stmt) = function.stmts.get_mut(id.0 as usize) else {
        return;
    };
    map_roots(stmt, &mut |root| memo.get(&root).copied().unwrap_or(root));
    let rename = |place: &mut Place| {
        if let Place::Var(var) = place
            && let Some(&new) = to.get(var)
        {
            *var = new;
        }
    };
    match stmt {
        Stmt::Assign { place, .. } => rename(place),
        Stmt::VaStart { list } => rename(list),
        Stmt::Call { results, .. }
        | Stmt::Intrinsic { results, .. }
        | Stmt::Escape { results, .. } => results.iter_mut().for_each(rename),
        Stmt::Expr(_)
        | Stmt::If { .. }
        | Stmt::While { .. }
        | Stmt::DoWhile { .. }
        | Stmt::For { .. }
        | Stmt::Switch { .. }
        | Stmt::Try { .. }
        | Stmt::Break(_)
        | Stmt::Continue(_)
        | Stmt::Label(_)
        | Stmt::Goto(_)
        | Stmt::Return(_)
        | Stmt::Trap(_)
        | Stmt::Unreachable => {}
    }
}
