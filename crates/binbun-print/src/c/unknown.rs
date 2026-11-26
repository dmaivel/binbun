//! Unknown values ([`Expr::Undefined`](binbun_ast::ir::Expr::Undefined)),
//! never printed as a constant.
//!
//! - One the architecture leaves undefined ([`Unknown::Architecture`]),
//!   which processors set differently: the exact view
//!   ([`Opaque::Calls`]) calls `binbun_defs.h`'s `binbun_undefined_bool()` or
//!   `binbun_undefined_u8()` to `binbun_undefined_u128()`, which no
//!   compiler folds, at each use; the reading view ([`Opaque::Asm`])
//!   gives it a register-style name after what the instruction leaves
//!   undefined, `_OF_undefined` (one name per instruction and register: a
//!   second instruction's is `_OF_undefined_2`).
//! - A register a call may change ([`Unknown::Call`]): `_RDX_clobbered`;
//!   an entry value the function takes no parameter in
//!   ([`Unknown::Entry`]): `_RCX_entry`; lowering's fallback
//!   ([`Unknown::Lowering`]): `_unknown`. In both views.
//! - One of a width no helper gives (a `zmm` register's 384 bits above a
//!   value written to its low 128) is named at the width of the
//!   concatenation it is the top of, the value replacing that name's low
//!   lane ([`Printer::under`]).
//!
//! Each name is declared first thing from that helper, with a comment
//! saying where the value comes from. A parameter's bits above its
//! declared width ([`Unknown::Parameter`]) never print: the parameter
//! prints at its declared width
//! ([`Printer::declared_width`]). The others (at a landing pad, read
//! before any write) still print as `0`, counted.
//!
//! The reading view hides, never lies: a local merged from several paths
//! is not assigned on a path where it would take a named unknown value
//! other than the architecture's ([`unassigned`]), and a name used
//! nowhere else is not declared. The exact view keeps every assignment.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use binbun_ast::ir::{
    Block, Callee as AstCallee, Expr, ExprId, Function, Node, Origin, Place, Stmt, StmtId, VarId,
    VarKind,
};
use binbun_ast::types::{Type, TypeId};
use binbun_semantics::bits::Bits;
use binbun_semantics::ir::RegisterId;
use binbun_ssa::ir::Unknown;

use super::convert::Class;
use super::stmt::MAX_NESTING;
use super::types::container;
use super::unlifted::pure;
use super::value::Value;
use super::{Opaque, PrintError, Printer, comment};
use crate::document::{Doc, TokenKind};

/// Unknown values printed, by where they come from ([`Unknown`]): the
/// distinct expressions.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Unknowns {
    /// Bits the architecture leaves undefined, which processors set
    /// differently ([`Unknown::Architecture`]).
    pub architecture: usize,
    /// A parameter's bits above its declared width
    /// ([`Unknown::Parameter`]) printed on their own (not as the
    /// parameter at its declared width).
    pub parameter: usize,
    /// A register a call may change ([`Unknown::Call`]), named.
    pub call: usize,
    /// A register the unwinder does not restore ([`Unknown::Landing`]),
    /// printed as 0.
    pub landing: usize,
    /// An entry value the function takes no parameter in
    /// ([`Unknown::Entry`]), named.
    pub entry: usize,
    /// A variable or stack slot read before any write
    /// ([`Unknown::Unwritten`]), printed as 0.
    pub unwritten: usize,
    /// Lowering's fallback ([`Unknown::Lowering`]), named.
    pub lowering: usize,
}

impl Unknowns {
    /// Counts one more from `unknown`.
    fn add(&mut self, unknown: Unknown) {
        let count = match unknown {
            Unknown::Architecture { .. } => &mut self.architecture,
            Unknown::Parameter => &mut self.parameter,
            Unknown::Call { .. } => &mut self.call,
            Unknown::Landing => &mut self.landing,
            Unknown::Entry { .. } => &mut self.entry,
            Unknown::Unwritten => &mut self.unwritten,
            Unknown::Lowering => &mut self.lowering,
        };
        *count += 1;
    }
}

/// The name of an unknown value, declared from a helper.
#[derive(Clone, Debug)]
pub(super) struct UnknownName {
    /// Where the value comes from and its width, and the expression if
    /// that does not say which value it is (lowering's fallback, a stack
    /// slot's entry value): one name each.
    key: (Unknown, u16, Option<ExprId>),
    /// The name (`_OF_undefined`, `_RDX_clobbered`).
    name: String,
    /// Its L2 type.
    ty: TypeId,
    /// The first expression printed by it.
    expr: ExprId,
}

/// `binbun_defs.h`'s helper giving an unknown value of `width` bits:
/// `binbun_undefined_bool` for 1 bit, else `binbun_undefined_u8` to
/// `binbun_undefined_u128` by the C integer holding it, and
/// `binbun_undefined_u256` and `_u512` (a `u64x4`, a `u64x8`).
fn helper(width: u16) -> Option<String> {
    if width == 1 {
        return Some(String::from("binbun_undefined_bool"));
    }
    if matches!(width, 256 | 512) {
        return Some(format!("binbun_undefined_u{width}"));
    }
    container(width).map(|bits| format!("binbun_undefined_u{bits}"))
}

/// Whether `unknown` prints as a name ([`Printer::unknown`]), not `0`.
const fn named(unknown: Unknown) -> bool {
    match unknown {
        Unknown::Architecture { .. }
        | Unknown::Call { .. }
        | Unknown::Entry { .. }
        | Unknown::Lowering => true,
        Unknown::Parameter | Unknown::Landing | Unknown::Unwritten => false,
    }
}

/// Whether `id` of `f` is a named unknown value that is not the
/// architecture's (what a call left, an entry value, lowering's
/// fallback), or bits of one, as any type.
fn unassigned_value(f: &Function, mut id: ExprId) -> bool {
    loop {
        match f.expr(id) {
            Some(&(Expr::Cast { value, .. } | Expr::Extract { value, .. })) => id = value,
            Some(&Expr::Undefined(_, unknown, _)) => {
                return named(unknown) && !unknown.architectural();
            }
            Some(_) | None => return false,
        }
    }
}

/// The places `stmt` writes itself (not those of the blocks it holds).
fn places(stmt: &Stmt) -> &[Place] {
    match stmt {
        Stmt::Assign { place, .. } | Stmt::VaStart { list: place } => core::slice::from_ref(place),
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
        | Stmt::Try { .. } => &[],
    }
}

/// The assignments the reading view does not print: of a named unknown
/// value that is not the architecture's ([`unassigned_value`]) to a local
/// merged from several paths (written more than once), where no other
/// write of the local can reach it (`v8 = (int64_t *)_RDX_clobbered_4;`
/// on the path where a call left the register, the other paths giving
/// `v8` something else). The local is simply not assigned on that path,
/// which hides the value and claims nothing else: an earlier value of the
/// local never seems to flow on. The value's name, used nowhere else, is
/// not declared.
pub(super) fn unassigned(f: &Function, held: &(Vec<bool>, Vec<bool>)) -> BTreeSet<StmtId> {
    let (stmts, exprs) = held;
    let mut candidates: BTreeMap<StmtId, VarId> = BTreeMap::new();
    let mut written: BTreeMap<VarId, usize> = BTreeMap::new();
    for (index, stmt) in (0..).zip(&f.stmts) {
        if !stmts.get(index as usize).copied().unwrap_or(false) {
            continue;
        }
        if let &Stmt::Assign {
            place: Place::Var(var),
            value,
        } = stmt
            && f.var(var).is_some_and(|v| v.kind == VarKind::Local)
            && unassigned_value(f, value)
        {
            candidates.insert(StmtId(index), var);
        }
        for place in places(stmt) {
            if let Place::Var(var) = *place {
                *written.entry(var).or_default() += 1;
            }
        }
    }
    for (index, expr) in f.exprs.iter().enumerate() {
        if let &Expr::Assign { var, .. } = expr
            && exprs.get(index).copied().unwrap_or(false)
        {
            *written.entry(var).or_default() += 1;
        }
    }
    candidates.retain(|_, var| written.get(var).is_some_and(|&count| count > 1));
    if candidates.is_empty() {
        return BTreeSet::new();
    }
    // Every candidate is hidden until a write of its local may reach it;
    // that printed, its write may reach others: again until none changes.
    let mut walk = Reaching {
        f,
        candidates,
        printed: BTreeSet::new(),
    };
    loop {
        let before = walk.printed.len();
        let mut every = BTreeSet::new();
        walk.writes(&f.body, &mut every, 0);
        walk.walk(&f.body, BTreeSet::new(), &every, 0);
        if walk.printed.len() == before {
            break;
        }
    }
    let Reaching {
        candidates,
        printed,
        ..
    } = walk;
    candidates
        .into_keys()
        .filter(|id| !printed.contains(id))
        .collect()
}

/// Which writes of locals may reach which statements, over the structured
/// body ([`unassigned`]): a write in a loop reaches all of it, one
/// anywhere reaches a label (a `goto` may come from there), one in a
/// `try` body reaches its handlers, and a switch's arm falls through
/// into the next.
struct Reaching<'f> {
    f: &'f Function,
    /// The assignments that may go unprinted, and their locals.
    candidates: BTreeMap<StmtId, VarId>,
    /// Those printed: a write of their local may reach them.
    printed: BTreeSet<StmtId>,
}

impl Reaching<'_> {
    /// Adds the variables statement `id` writes itself (its places, the
    /// assignment expressions it evaluates) to `out`: none for a candidate
    /// not printed.
    fn own_writes(&self, id: StmtId, stmt: &Stmt, out: &mut BTreeSet<VarId>) {
        if self.candidates.contains_key(&id) && !self.printed.contains(&id) {
            return;
        }
        for place in places(stmt) {
            if let Place::Var(var) = *place {
                out.insert(var);
            }
        }
        let mut work = stmt.roots();
        let mut seen = BTreeSet::new();
        while let Some(e) = work.pop() {
            if !seen.insert(e) {
                continue;
            }
            let Some(expr) = self.f.expr(e) else {
                continue;
            };
            if let &Expr::Assign { var, .. } = expr {
                out.insert(var);
            }
            work.extend(expr.operands(self.f));
        }
    }

    /// Adds every variable `block` writes, nested blocks too, to `out`.
    fn writes(&self, block: &Block, out: &mut BTreeSet<VarId>, depth: usize) {
        if depth > MAX_NESTING {
            return;
        }
        for &id in block {
            if let Some(stmt) = self.f.stmt(id) {
                self.own_writes(id, stmt, out);
                for inner in stmt.blocks() {
                    self.writes(inner, out, depth + 1);
                }
            }
        }
    }

    /// Walks `block` from `state` (the locals a write may have reached
    /// it with), printing each candidate a write of its local reaches;
    /// the state after. `every`: what the whole function writes.
    fn walk(
        &mut self,
        block: &Block,
        mut state: BTreeSet<VarId>,
        every: &BTreeSet<VarId>,
        depth: usize,
    ) -> BTreeSet<VarId> {
        if depth > MAX_NESTING {
            return state;
        }
        let f = self.f;
        for &id in block {
            let Some(stmt) = f.stmt(id) else {
                continue;
            };
            if let Some(&var) = self.candidates.get(&id) {
                if state.contains(&var) {
                    self.printed.insert(id);
                }
                if self.printed.contains(&id) {
                    state.insert(var);
                }
                continue;
            }
            self.own_writes(id, stmt, &mut state);
            match stmt {
                Stmt::If {
                    then, otherwise, ..
                } => {
                    let after = self.walk(then, state.clone(), every, depth + 1);
                    state = self.walk(otherwise, state, every, depth + 1);
                    state.extend(after);
                }
                Stmt::While { .. } | Stmt::DoWhile { .. } | Stmt::For { .. } => {
                    for inner in stmt.blocks() {
                        self.writes(inner, &mut state, depth + 1);
                    }
                    for inner in stmt.blocks() {
                        self.walk(inner, state.clone(), every, depth + 1);
                    }
                }
                Stmt::Switch { arms, .. } => {
                    let mut through = state.clone();
                    for arm in arms {
                        let after = self.walk(&arm.body, through.clone(), every, depth + 1);
                        through.extend(after);
                    }
                    state = through;
                }
                Stmt::Try { body, handlers } => {
                    let mut thrown = state.clone();
                    self.writes(body, &mut thrown, depth + 1);
                    state = self.walk(body, state, every, depth + 1);
                    for handler in handlers {
                        let after = self.walk(&handler.body, thrown.clone(), every, depth + 1);
                        state.extend(after);
                    }
                }
                Stmt::Label(_) => state.extend(every.iter().copied()),
                Stmt::Assign { .. }
                | Stmt::Call { .. }
                | Stmt::Intrinsic { .. }
                | Stmt::Expr(_)
                | Stmt::Break(_)
                | Stmt::Continue(_)
                | Stmt::Goto(_)
                | Stmt::Return(_)
                | Stmt::Trap(_)
                | Stmt::Unreachable
                | Stmt::Escape { .. }
                | Stmt::VaStart { .. } => {}
            }
        }
        state
    }
}

/// `f` without the statements `hidden`, nor the `if`s that leaves with
/// both arms empty and a condition without effects.
pub(super) fn without(f: &Function, hidden: &BTreeSet<StmtId>) -> Function {
    let mut f = f.clone();
    let mut removed = hidden.clone();
    loop {
        f.body.retain(|id| !removed.contains(id));
        for stmt in &mut f.stmts {
            for block in stmt.blocks_mut() {
                block.retain(|id| !removed.contains(id));
            }
        }
        let empty: Vec<StmtId> = (0..)
            .zip(&f.stmts)
            .filter(|&(index, stmt)| {
                matches!(stmt, Stmt::If { condition, then, otherwise }
                    if then.is_empty() && otherwise.is_empty() && pure(&f, *condition))
                    && !removed.contains(&StmtId(index))
            })
            .map(|(index, _)| StmtId(index))
            .collect();
        if empty.is_empty() {
            return f;
        }
        removed.extend(empty);
    }
}

impl Printer<'_> {
    /// Whether `id` is a named unknown value of a width no `binbun_defs.h`
    /// helper gives (`undefined:384`, a `zmm` register's bits above its
    /// low 128): it prints only above a value in a concatenation
    /// ([`Printer::under`]), named at the concatenation's width.
    pub(super) fn unknown_without_helper(&self, id: ExprId) -> bool {
        matches!(
            self.f.expr(id),
            Some(&Expr::Undefined(width, unknown, _)) if named(unknown) && helper(width).is_none()
        )
    }

    /// Unknown value `id` of `width` bits, from `unknown`.
    pub(super) fn unknown(
        &mut self,
        id: ExprId,
        width: u16,
        unknown: Unknown,
    ) -> Result<Value, PrintError> {
        if self.unknowns_printed.insert(id) {
            self.counts.unknowns.add(unknown);
        }
        if !named(unknown) {
            if width > 128 {
                return self.wide_constant(Bits::zero(width));
            }
            return self.constant(Bits::zero(width), Class::Zero, false);
        }
        let ty = self.types.intern(Type::UInt(width));
        let helper = helper(width)
            .ok_or_else(|| self.unsupported(self.node, "unknown values over 128 bits"))?;
        let mut value = if unknown.architectural() && self.opaque == Opaque::Calls {
            let (doc, _) = self.call_doc(vec![self.helper_name(&helper)], Vec::new(), 0);
            let mut value = self.named(String::new(), ty)?;
            value.doc = doc;
            // Each call is its own: kept where it is evaluated.
            value.loads = true;
            value
        } else {
            let which = matches!(
                unknown,
                Unknown::Lowering | Unknown::Entry { register: None }
            )
            .then_some(id);
            let key = (unknown, width, which);
            let name = if let Some(named) = self.unknown_names.iter().find(|n| n.key == key) {
                named.name.clone()
            } else {
                let name = self.names.fresh(&self.unknown_base(unknown));
                self.unknown_names.push(UnknownName {
                    key,
                    name: name.clone(),
                    ty,
                    expr: id,
                });
                name
            };
            self.named(name, ty)?
        };
        value.lvalue = false;
        Ok(value)
    }

    /// The upper-case name of `register` (`RDX`), if it has one.
    fn register_name(&self, register: Option<RegisterId>) -> Option<String> {
        register
            .and_then(|register| self.declarations.info(register))
            .map(|info| info.name.to_ascii_uppercase())
    }

    /// The name an unknown value from `unknown` takes, before it is made
    /// unique.
    fn unknown_base(&self, unknown: Unknown) -> String {
        let register = |register| {
            self.register_name(register)
                .map_or_else(String::new, |name| format!("_{name}"))
        };
        match unknown {
            Unknown::Architecture { register: r, .. } => format!("{}_undefined", register(r)),
            Unknown::Call { register: r, .. } => format!("{}_clobbered", register(Some(r))),
            Unknown::Entry { register: Some(r) } => format!("{}_entry", register(Some(r))),
            Unknown::Entry { register: None } => String::from("_stack_entry"),
            Unknown::Parameter | Unknown::Landing | Unknown::Unwritten | Unknown::Lowering => {
                String::from("_unknown")
            }
        }
    }

    /// The text of the instruction at `address`, and the address.
    fn instruction_at(&self, address: u64) -> String {
        self.image.instruction(address).map_or_else(
            || format!("the instruction at {address:#x}"),
            |text| format!("{text} at {address:#x}"),
        )
    }

    /// The name of what the call at `address` calls, as printed, if it
    /// calls a function or an import.
    fn callee_at(&self, address: u64) -> Option<String> {
        let f = self.f;
        let at = |origins: &[Origin]| origins.contains(&Origin::Instruction(address));
        let statement = (0..).zip(&f.stmts).find_map(|(id, stmt)| {
            if let Stmt::Call { call, .. } = stmt
                && at(f.provenance.stmt(StmtId(id)))
            {
                Some(call)
            } else {
                None
            }
        });
        let call = statement.or_else(|| {
            (0..).zip(&f.exprs).find_map(|(id, expr)| {
                if let &Expr::Call(call) = expr
                    && at(f.provenance.expr(ExprId(id)))
                {
                    f.call(call)
                } else {
                    None
                }
            })
        })?;
        let named = match call.callee {
            AstCallee::Address(target) => self.callees.get(&(target, call.signature)),
            AstCallee::Import(slot) => self.imports.get(&(slot, call.signature)),
            AstCallee::Expr(_) => None,
        };
        named.map(|callee| callee.name.clone())
    }

    /// What the comment on a name's declaration says of the value.
    fn unknown_comment(&self, unknown: Unknown) -> String {
        match unknown {
            Unknown::Architecture {
                address, register, ..
            } => {
                let what = self
                    .register_name(register)
                    .unwrap_or_else(|| String::from("this value"));
                format!(
                    "{} leaves {what} undefined: processors differ",
                    self.instruction_at(address)
                )
            }
            Unknown::Call { address, register } => {
                let what = self
                    .register_name(Some(register))
                    .unwrap_or_else(|| String::from("this register"));
                self.callee_at(address).map_or_else(
                    || format!("the call at {address:#x} may change {what}"),
                    |callee| format!("{callee} called at {address:#x} may change {what}"),
                )
            }
            Unknown::Entry { register } => {
                let what = self
                    .register_name(register)
                    .unwrap_or_else(|| String::from("a stack slot"));
                format!("{what} at entry: no parameter of the function")
            }
            Unknown::Parameter | Unknown::Landing | Unknown::Unwritten | Unknown::Lowering => {
                String::from("a value binbun has no expression for")
            }
        }
    }

    /// The declarations of the names of unknown values (in the order first
    /// printed), each from `binbun_defs.h`'s helper with a comment saying
    /// where the value comes from: `bool _OF_undefined =
    /// binbun_undefined_bool(); /* shrd rdx, rdx, 0x1d at 0x4012a0 leaves
    /// OF undefined: processors differ */`.
    pub(super) fn unknown_declarations(&mut self) -> Result<Vec<Doc>, PrintError> {
        let mut out = Vec::new();
        for named in self.unknown_names.clone() {
            let node = Some(Node::Expr(named.expr));
            let width = self.type_width(named.ty)?;
            let helper = helper(width)
                .ok_or_else(|| self.unsupported(node, "unknown values over 128 bits"))?;
            let declarator = vec![Doc::name(TokenKind::Local, named.name, true, node)];
            let mut line = self.declare(named.ty, declarator)?;
            line.extend([
                Doc::Space,
                Doc::punct("=", None),
                Doc::Space,
                Doc::macro_name(helper, node),
                Doc::punct("(", None),
                Doc::punct(")", None),
                Doc::punct(";", None),
                Doc::Space,
            ]);
            let (unknown, ..) = named.key;
            line.push(Doc::comment(comment(&self.unknown_comment(unknown)), node));
            out.push(Doc::Group(line));
        }
        Ok(out)
    }

    /// Whether `id` is a value whose bits from its low part `low` up are
    /// unknown but not processor-dependent (a parameter's bits above its
    /// declared width, those of a register a call returns in above its
    /// return value): it prints as `low` at its declared width, C's
    /// conversions giving the rest, never as a chosen constant.
    pub(super) fn declared_width(&self, id: ExprId) -> Option<ExprId> {
        let &Expr::Concat { high, low } = self.f.expr(id)? else {
            return None;
        };
        // Bits of an unknown value are unknown.
        let high = if let Expr::Extract { value, .. } = *self.f.expr(high)? {
            value
        } else {
            high
        };
        matches!(self.f.expr(high)?, Expr::Undefined(_, unknown, _) if !unknown.architectural())
            .then_some(low)
    }
}
