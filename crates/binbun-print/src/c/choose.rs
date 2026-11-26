//! Presentation chosen on the conversion plan, where L2 leaves it free:
//! each local integer's signedness ([`Planner::choose_signs`]) and what a
//! local byte or `void` pointer points to ([`Planner::choose_pointees`]),
//! as fewer casts are then needed. The printer makes every read what its
//! use needs whatever the type (pointer arithmetic stays in bytes,
//! through a byte pointer where the pointee is wider), so a choice changes
//! only the casts and conversions printed, never a value; and it is
//! presentation only: L2's types stay as they are, the choice lives in
//! the plan ([`super::Plan::types`]).
//!
//! Like Boomerang's signedness hints, a choice by the uses; unlike them
//! (a vote of the operations) and Ghidra's most specific type (one
//! unsigned read makes a variable unsigned), each choice is costed by
//! planning again the statements that read or write the locals, exactly
//! as they would print.

use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;

use binbun_ast::ir::{Call, Expr, ExprId, Function, Place, Stmt, StmtId, VarId, VarKind};
use binbun_ast::types::{Evidence, Type, TypeId};
use binbun_semantics::ir::Binary;

use super::PrintError;
use super::plan::{Cost, Plan, Planner};

/// The most rounds over the choices (a change leaves fewer casts, so it
/// ends; few functions take more than two).
const ROUNDS: usize = 4;

/// The most pointee types tried for one pointer from its uses, besides a
/// byte and `void`.
const ASKED: usize = 4;

/// Locals that take one of several spellings together (one, or several
/// compared with each other), each spelling a type for each, and the
/// statements with plans of their own that read or write any of them.
struct Choice {
    vars: Vec<VarId>,
    options: Vec<Vec<Type>>,
    statements: Vec<StmtId>,
}

impl Planner<'_> {
    /// Each local whose signedness L2 leaves free ([`Uses::free_width`])
    /// given the one that costs fewer casts, then fewer conversions, in the
    /// statements that read or write it, planned again under each
    /// ([`Cost`]): first each set of such locals compared with each other
    /// together (which alone would each keep the other's signedness to
    /// agree with it), then each alone, in the order of the locals, a tie
    /// keeping the spelling; over and again while one changes, at most
    /// [`ROUNDS`] times.
    ///
    /// # Errors
    ///
    /// The printer refuses a statement under the types it had planned
    /// (which it planned before).
    pub fn choose_signs(&mut self) -> Result<(), PrintError> {
        let uses = Uses::of(self.function(), self.plan());
        let choices = sign_choices(self.function(), &uses);
        self.choose_all(&choices)
    }

    /// Each local byte or `void` pointer whose type nothing declared
    /// ([`Uses::loose_pointer`]) given the pointee that costs fewer casts,
    /// then fewer conversions, in the statements that read or write it
    /// ([`Cost`]): of the types its uses ask for (what is loaded or stored
    /// through it, what it is cast to, what parameter it is passed as,
    /// the pointer it is copied to or from; the [`ASKED`] most asked), a
    /// byte, and `void`; in the order of the locals, a tie keeping the
    /// spelling, over and again while one changes, at most [`ROUNDS`]
    /// times.
    ///
    /// # Errors
    ///
    /// The printer refuses a statement under the types it had planned
    /// (which it planned before).
    pub fn choose_pointees(&mut self) -> Result<(), PrintError> {
        let uses = Uses::of(self.function(), self.plan());
        let choices = pointee_choices(self.function(), &uses);
        self.choose_all(&choices)
    }

    /// Each of `choices` made, over and again while one changes, at most
    /// [`ROUNDS`] times.
    fn choose_all(&mut self, choices: &[Choice]) -> Result<(), PrintError> {
        for _ in 0..ROUNDS {
            let mut changed = false;
            for choice in choices {
                changed |= self.choose(choice)?;
            }
            if !changed {
                break;
            }
        }
        Ok(())
    }

    /// The locals of `choice` given the option that costs least in their
    /// statements (or kept as they are, a tie keeping them); whether that
    /// changed a spelling.
    fn choose(&mut self, choice: &Choice) -> Result<bool, PrintError> {
        let now: Vec<Option<Type>> = choice
            .vars
            .iter()
            .map(|var| self.plan().types().get(var).cloned())
            .collect();
        let mut best = (self.cost_of(&choice.statements), None);
        let mut last = None;
        for (at, option) in choice.options.iter().enumerate() {
            let mut same = true;
            for (&var, ty) in choice.vars.iter().zip(option) {
                same &= self.spelled_as(var, ty);
            }
            if same {
                continue;
            }
            for (&var, ty) in choice.vars.iter().zip(option) {
                self.retype(var, Some(ty.clone()));
            }
            last = Some(at);
            // Refused so typed: never chosen.
            if self.replan(&choice.statements).is_ok() {
                let cost = self.cost_of(&choice.statements);
                if cost < best.0 {
                    best = (cost, Some(at));
                }
            }
        }
        if last != best.1 {
            let chosen = best.1.and_then(|at| choice.options.get(at));
            for (index, (&var, was)) in choice.vars.iter().zip(now).enumerate() {
                let ty = match chosen {
                    Some(option) => option.get(index).cloned(),
                    None => was,
                };
                self.retype(var, ty);
            }
            self.replan(&choice.statements)?;
        }
        Ok(best.1.is_some())
    }

    /// What `statements` cost as planned now.
    fn cost_of(&self, statements: &[StmtId]) -> Cost {
        statements
            .iter()
            .map(|&id| self.plan().statement(id))
            .fold(Cost::default(), |sum, cost| Cost {
                casts: sum.casts + cost.casts,
                conversions: sum.conversions + cost.conversions,
            })
    }
}

/// How a function's statements with plans of their own use its locals.
struct Uses {
    /// By local: the statements that read or write it (`None`: one is
    /// read or written elsewhere, or its address is taken).
    statements: BTreeMap<VarId, Option<Vec<StmtId>>>,
    /// The pairs of locals compared with each other (by `==`, `!=`, `<`
    /// or `<=`).
    links: Vec<(VarId, VarId)>,
    /// By local: the pointee types its uses ask for (`None`: `void`), and
    /// how often.
    asked: BTreeMap<VarId, BTreeMap<Option<TypeId>, u32>>,
}

impl Uses {
    /// How the statements of `function` that `plan` holds use its locals.
    fn of(function: &Function, plan: &Plan) -> Self {
        let mut uses = Self {
            statements: BTreeMap::new(),
            links: Vec::new(),
            asked: BTreeMap::new(),
        };
        let mut seen = vec![u32::MAX; function.exprs.len()];
        for (at, owner) in held(function, plan) {
            let Some(stmt) = function.stmt(at) else {
                continue;
            };
            for place in stmt.places() {
                match *place {
                    Place::Var(var) => uses.note(var, owner),
                    Place::Memory { address, ty } => uses.ask_through(function, address, Some(ty)),
                }
            }
            uses.statement_asks(function, stmt);
            let mut work = stmt.roots();
            while let Some(id) = work.pop() {
                let Some(mark) = seen.get_mut(id.0 as usize) else {
                    continue;
                };
                if *mark == at.0 {
                    continue;
                }
                *mark = at.0;
                let Some(&expr) = function.expr(id) else {
                    continue;
                };
                uses.expression(function, expr, owner);
                work.extend(expr.operands(function));
            }
        }
        for list in uses.statements.values_mut().flatten() {
            list.sort_unstable();
            list.dedup();
        }
        uses
    }

    /// Local `var` read or written by statement `owner` (`None`: not one
    /// with a plan of its own).
    fn note(&mut self, var: VarId, owner: Option<StmtId>) {
        let slot = self
            .statements
            .entry(var)
            .or_insert_with(|| Some(Vec::new()));
        match (slot.as_mut(), owner) {
            (Some(list), Some(owner)) => list.push(owner),
            (Some(_) | None, Some(_) | None) => *slot = None,
        }
    }

    /// Pointee `target` asked of the local expression `id` is, if it is
    /// one.
    fn ask(&mut self, function: &Function, id: ExprId, target: Option<TypeId>) {
        if let Some(var) = local(function, id) {
            *self
                .asked
                .entry(var)
                .or_default()
                .entry(target)
                .or_insert(0) += 1;
        }
    }

    /// A load or store of `ty` at `address`: asked of the local it is
    /// at, or at an offset from.
    fn ask_through(&mut self, function: &Function, address: ExprId, ty: Option<TypeId>) {
        let mut at = address;
        for _ in 0..3 {
            match function.expr(at) {
                Some(&Expr::Binary(Binary::Add, a, b)) => {
                    at = if local(function, b).is_some() { b } else { a };
                }
                Some(_) | None => break,
            }
        }
        self.ask(function, at, ty);
    }

    /// The pointees a pointer type `ty` asks of the local expression `id`.
    fn ask_pointer(&mut self, function: &Function, id: ExprId, ty: TypeId) {
        if let Some(&Type::Pointer(target)) = function.types.get(ty) {
            self.ask(function, id, target);
        }
    }

    /// The pointees `call` asks of the locals passed as its parameters.
    fn ask_call(&mut self, function: &Function, call: &Call) {
        let Some(signature) = function.types.signature(call.signature) else {
            return;
        };
        for (&argument, &parameter) in call.arguments.iter().zip(&signature.parameters) {
            self.ask_pointer(function, argument, parameter);
        }
    }

    /// What statement `stmt` asks itself: a call's parameters, and a copy
    /// between a local and a variable of a pointer type.
    fn statement_asks(&mut self, function: &Function, stmt: &Stmt) {
        match stmt {
            Stmt::Call { call, .. } => self.ask_call(function, call),
            &Stmt::Assign {
                place: Place::Var(to),
                value,
            } => {
                if let Some(ty) = function.var(to).map(|variable| variable.ty) {
                    self.ask_pointer(function, value, ty);
                }
                if let Some(from) = local(function, value)
                    && let Some(variable) = function.var(from)
                    && let Some(&Type::Pointer(target)) = function.types.get(variable.ty)
                {
                    *self.asked.entry(to).or_default().entry(target).or_insert(0) += 1;
                }
            }
            Stmt::Assign { .. }
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
            | Stmt::VaStart { .. } => {}
        }
    }

    /// What expression `expr` of a statement with plan `owner` uses and
    /// asks.
    fn expression(&mut self, function: &Function, expr: Expr, owner: Option<StmtId>) {
        match expr {
            Expr::Var(var) | Expr::Assign { var, .. } => self.note(var, owner),
            Expr::AddressOf(var) => self.note(var, None),
            Expr::Binary(
                Binary::Eq | Binary::Ne | Binary::ULt | Binary::ULe | Binary::SLt | Binary::SLe,
                a,
                b,
            ) => {
                if let (Some(a), Some(b)) = (local(function, a), local(function, b))
                    && a != b
                {
                    self.links.push((a, b));
                }
            }
            Expr::Load { address, ty } => self.ask_through(function, address, Some(ty)),
            Expr::Cast { value, ty } => self.ask_pointer(function, value, ty),
            Expr::Call(call) => {
                if let Some(call) = function.call(call) {
                    self.ask_call(function, call);
                }
            }
            Expr::Binary(..)
            | Expr::Const(_)
            | Expr::Undefined(..)
            | Expr::Unary(..)
            | Expr::Logical(..)
            | Expr::Flag(..)
            | Expr::Extract { .. }
            | Expr::Concat { .. }
            | Expr::Extend { .. }
            | Expr::Select { .. }
            | Expr::Lanes { .. }
            | Expr::Float { .. }
            | Expr::Exception { .. } => {}
        }
    }

    /// Local `var`, a choice's own: its statements, if they all have plans
    /// of their own, and its type, if nothing declared it.
    fn free(&self, function: &Function, var: VarId) -> Option<(Vec<StmtId>, TypeId)> {
        let statements = self.statements.get(&var)?.clone()?;
        let variable = function.var(var)?;
        (variable.kind == VarKind::Local
            && matches!(variable.evidence, Evidence::Default | Evidence::Deduced))
        .then_some((statements, variable.ty))
    }

    /// The width of local `var`, if its signedness is free ([`Self::free`]):
    /// an integer or untyped bits of 8, 16, 32 or 64 bits.
    fn free_width(&self, function: &Function, var: VarId) -> Option<(Vec<StmtId>, u16)> {
        let (statements, ty) = self.free(function, var)?;
        match *function.types.get(ty)? {
            Type::Bits(width) | Type::Int(width) | Type::UInt(width)
                if matches!(width, 8 | 16 | 32 | 64) =>
            {
                Some((statements, width))
            }
            Type::Bits(_)
            | Type::Int(_)
            | Type::UInt(_)
            | Type::Char { .. }
            | Type::Bool(_)
            | Type::Float(_)
            | Type::Pointer(_)
            | Type::Code(_)
            | Type::Struct(_)
            | Type::Union(_)
            | Type::Array { .. }
            | Type::Vector { .. }
            | Type::Enum(_) => None,
        }
    }

    /// The statements of local `var`, if its pointee is free
    /// ([`Self::free`]): a pointer to a byte (`char` or an 8-bit integer)
    /// or to `void`.
    fn loose_pointer(&self, function: &Function, var: VarId) -> Option<Vec<StmtId>> {
        let (statements, ty) = self.free(function, var)?;
        let &Type::Pointer(target) = function.types.get(ty)? else {
            return None;
        };
        match target.and_then(|target| function.types.get(target)) {
            None | Some(Type::Char { .. } | Type::UInt(8) | Type::Int(8) | Type::Bits(8)) => {
                Some(statements)
            }
            Some(_) => None,
        }
    }
}

/// The signedness choices of `function`'s locals ([`Uses::free_width`]):
/// each set of two or more compared with each other, then each alone, in
/// the order of the locals; each all signed or all unsigned.
fn sign_choices(function: &Function, uses: &Uses) -> Vec<Choice> {
    let singles: Vec<(VarId, u16, Vec<StmtId>)> = uses
        .statements
        .keys()
        .filter_map(|&var| {
            let (statements, width) = uses.free_width(function, var)?;
            Some((var, width, statements))
        })
        .collect();
    let index: BTreeMap<VarId, usize> = (0..)
        .zip(&singles)
        .map(|(at, single)| (single.0, at))
        .collect();
    let mut root: Vec<usize> = (0..singles.len()).collect();
    let find = |root: &[usize], mut at: usize| {
        while let Some(&up) = root.get(at).filter(|&&up| up != at) {
            at = up;
        }
        at
    };
    for (a, b) in &uses.links {
        if let (Some(&a), Some(&b)) = (index.get(a), index.get(b)) {
            let (a, b) = (find(&root, a), find(&root, b));
            if let Some(slot) = root.get_mut(a.max(b)) {
                *slot = a.min(b);
            }
        }
    }
    let mut groups: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for at in 0..singles.len() {
        groups.entry(find(&root, at)).or_default().push(at);
    }
    let members = |list: &[usize]| {
        let mut vars = Vec::new();
        let mut widths = Vec::new();
        let mut statements = Vec::new();
        for &(var, width, ref own) in list.iter().filter_map(|&at| singles.get(at)) {
            vars.push(var);
            widths.push(width);
            statements.extend(own);
        }
        statements.sort_unstable();
        statements.dedup();
        Choice {
            options: vec![
                widths.iter().map(|&width| Type::Int(width)).collect(),
                widths.iter().map(|&width| Type::UInt(width)).collect(),
            ],
            vars,
            statements,
        }
    };
    let mut out: Vec<Choice> = groups
        .values()
        .filter(|list| list.len() > 1)
        .map(|list| members(list))
        .collect();
    out.extend((0..singles.len()).map(|at| members(&[at])));
    out
}

/// The pointee choices of `function`'s locals ([`Uses::loose_pointer`]),
/// in the order of the locals: the [`ASKED`] pointees their uses ask for
/// most, a byte, and `void`.
fn pointee_choices(function: &Function, uses: &Uses) -> Vec<Choice> {
    let byte = function
        .types
        .iter()
        .find(|(_, ty)| matches!(ty, Type::UInt(8)))
        .or_else(|| {
            function
                .types
                .iter()
                .find(|(_, ty)| matches!(ty, Type::Char { .. }))
        })
        .map(|(id, _)| id);
    uses.statements
        .keys()
        .filter_map(|&var| {
            let statements = uses.loose_pointer(function, var)?;
            let mut asked: Vec<(u32, Option<TypeId>)> = uses
                .asked
                .get(&var)
                .map(|asked| {
                    asked
                        .iter()
                        .map(|(&target, &count)| (count, target))
                        .collect()
                })
                .unwrap_or_default();
            asked.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
            let mut targets: Vec<Option<TypeId>> = asked
                .into_iter()
                .map(|(_, target)| target)
                .filter(|&target| pointee(function, target))
                .take(ASKED)
                .collect();
            for extra in [byte.map(Some), Some(None)].into_iter().flatten() {
                if !targets.contains(&extra) {
                    targets.push(extra);
                }
            }
            Some(Choice {
                vars: vec![var],
                options: targets
                    .into_iter()
                    .map(|target| vec![Type::Pointer(target)])
                    .collect(),
                statements,
            })
        })
        .collect()
}

/// Whether a pointer may be printed as pointing to `target`: `void`, or a
/// type with a size (not a function, nor an array of unknown length).
fn pointee(function: &Function, target: Option<TypeId>) -> bool {
    target.is_none_or(|target| {
        !matches!(function.types.get(target), Some(Type::Code(_)) | None)
            && function.types.width(target).is_some_and(|width| width > 0)
    })
}

/// The variable expression `id` reads or assigns, if it does.
fn local(function: &Function, id: ExprId) -> Option<VarId> {
    match *function.expr(id)? {
        Expr::Var(var) | Expr::Assign { var, .. } => Some(var),
        Expr::Const(_)
        | Expr::Undefined(..)
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
        | Expr::Cast { .. }
        | Expr::Load { .. }
        | Expr::Call(_)
        | Expr::Exception { .. } => None,
    }
}

/// The statements of `function` its body holds, each with the statement
/// whose plan holds its conversions: the innermost of it and the
/// statements around it with a plan of its own (`None`: none has).
fn held(function: &Function, plan: &Plan) -> Vec<(StmtId, Option<StmtId>)> {
    let mut held = Vec::new();
    let mut work: Vec<(StmtId, Option<StmtId>)> =
        function.body.iter().rev().map(|&id| (id, None)).collect();
    while let Some((id, around)) = work.pop() {
        let owner = if plan.has(id) { Some(id) } else { around };
        held.push((id, owner));
        let Some(stmt) = function.stmt(id) else {
            continue;
        };
        for block in stmt.blocks() {
            work.extend(block.iter().rev().map(|&child| (child, owner)));
        }
    }
    held
}
