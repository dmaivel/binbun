//! Checking a [`Function`] against L2's rules:
//!
//! - Types: every type named exists; a type other than a struct or union
//!   is named only by types after it (fields may name any type, so
//!   structs can be recursive); widths are 1 to
//!   [`MAX_WIDTH`] bits where a value must hold the type (parameters,
//!   returns, vector lanes); fields lie within their aggregate, a union's
//!   at offset 0.
//! - Variables: parameters and locals fit a value; variables in memory
//!   have a whole number of bytes; [`Function::parameters`] lists every
//!   [`VarKind::Parameter`] once and nothing else; an environment variable
//!   ([`VarKind::Environment`]) is as wide as its declared register and
//!   never written.
//! - Expressions, every one in the arena whether used or not: operands
//!   come before their users, widths follow L0's rules, variables exist,
//!   only variables in memory have their address taken, addresses are
//!   pointer-wide, loads and casts have types of the right width.
//! - Statements: each is in at most one block; conditions are 1 bit;
//!   assignments, results, arguments and returns have the widths their
//!   places, signatures and intrinsics call for; `break` names an
//!   enclosing loop or switch and `continue` an enclosing loop; each label
//!   is defined once and every `goto`'s label is defined; switch values
//!   are distinct and of the scrutinee's width, at most one arm is the
//!   default, the last does not fall through; a `for`'s `init` and `step`
//!   hold only simple statements.
//! - Declarations ([`Function::declared`]): each at a statement in the
//!   body, of a [`VarKind::Local`] declared nowhere else.
//! - Exceptions: a `Try` has a handler; a `Landing` handler is its only
//!   one, and a catch-all or cleanup is the last; an exception object
//!   ([`Expr::Exception`]) is pointer-wide.
//! - `va_start` ([`Stmt::VaStart`]): only in a variadic function with
//!   [`Function::va`], whose saves are of declared registers as wide as
//!   the bytes saved, guarded by declared registers; its `va_list` is a
//!   whole variable: a 24-byte one in memory for System V's
//!   ([`VaList::Tag`]), a pointer-wide parameter or local for a pointer.
//! - Effects in order: a statement with several results writes distinct
//!   variables; a call's, intrinsic's or escape's result in memory has an
//!   address that reads no memory (the effect may change it, and C does
//!   not order the two). Calls in expressions ([`Expr::Call`]) are in an
//!   assignment, an expression statement, a return, a decision or the
//!   arguments of a call statement, each evaluated once, in an order C
//!   fixes ([`ordered`]). An assignment expression ([`Expr::Assign`])
//!   writes a parameter or local of its width, only in the condition of
//!   an `if` or a loop, where no node reading or writing its variable is
//!   evaluated twice ([`single`]), each evaluated once in an order C
//!   fixes, nothing C does not order with it reading or writing its
//!   variable.
//!
//! Errors name the node ([`Node`]): `t3`, `v3`, `e3` or `s3`.
//!
//! Statements are walked with an explicit work stack and expressions in
//! arena order, never recursively: nesting may be arbitrarily deep.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt;

use binbun_semantics::bits::{Bits, MAX_WIDTH};
use binbun_semantics::ir::Declarations;
use binbun_semantics::verify::{binary_width, float_width, lanes_width, unary_width};

use crate::ir::{
    Arm, Block, Call, Callee, Escape, ExceptionValue, Expr, ExprId, Function, Handler, HandlerKind,
    LabelId, Node, Place, Stmt, StmtId, Update, VaList, VarId, VarKind,
};
use crate::types::{Type, TypeId, Types};

/// A broken rule, and the node that breaks it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifyError {
    /// The node (`None`: the function as a whole).
    pub node: Option<Node>,
    /// The rule broken.
    pub message: String,
}

impl fmt::Display for Node {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Type(id) => write!(f, "t{}", id.0),
            Self::Var(id) => write!(f, "v{}", id.0),
            Self::Expr(id) => write!(f, "e{}", id.0),
            Self::Stmt(id) => write!(f, "s{}", id.0),
        }
    }
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.node {
            Some(node) => write!(f, "{node}: {}", self.message),
            None => f.write_str(&self.message),
        }
    }
}

/// An error at `node`.
fn at(node: Node) -> impl Fn(String) -> VerifyError {
    move |message| VerifyError {
        node: Some(node),
        message,
    }
}

/// Checks `function` against L2's rules, with the registers and
/// intrinsics of `declarations`.
///
/// # Errors
///
/// The first broken rule found, with the node that breaks it.
pub fn verify(function: &Function, declarations: &Declarations) -> Result<(), VerifyError> {
    for (id, ty) in function.types.iter() {
        check_type(&function.types, id, ty).map_err(at(Node::Type(id)))?;
    }
    variables(function, declarations)?;
    let mut widths = Vec::with_capacity(function.exprs.len());
    let mut reads = Vec::with_capacity(function.exprs.len());
    let mut calls: Vec<u32> = Vec::with_capacity(function.exprs.len());
    let mut assigns: Vec<bool> = Vec::with_capacity(function.exprs.len());
    for (index, expr) in function.exprs.iter().enumerate() {
        let id = ExprId(u32::try_from(index).unwrap_or(u32::MAX));
        let width = expr_width(function, expr, &mut |operand| {
            if operand >= id {
                return Err(format!("operand e{} is not before its user", operand.0));
            }
            widths
                .get(operand.0 as usize)
                .copied()
                .ok_or_else(String::new)
        })
        .map_err(at(Node::Expr(id)))?;
        widths.push(width);
        // Operands come first, so whether they read memory is known.
        let memory = |var: VarId| {
            function.var(var).is_some_and(|variable| {
                matches!(variable.kind, VarKind::Global(_) | VarKind::Frame(_))
            })
        };
        let call = matches!(*expr, Expr::Call(_));
        let assign = matches!(*expr, Expr::Assign { .. });
        let own = call
            || matches!(*expr, Expr::Load { .. })
            || matches!(*expr, Expr::Var(var) if memory(var));
        let below = expr
            .operands(function)
            .any(|operand| reads.get(operand.0 as usize) == Some(&true));
        reads.push(own || below);
        // Effects (calls, assignments) each evaluation makes: a node used
        // twice is evaluated twice.
        let made = expr
            .operands(function)
            .map(|operand| calls.get(operand.0 as usize).copied().unwrap_or(0))
            .fold(u32::from(call || assign), u32::saturating_add);
        calls.push(made);
        let assigning = assign
            || expr
                .operands(function)
                .any(|operand| assigns.get(operand.0 as usize) == Some(&true));
        assigns.push(assigning);
    }
    let mut checker = Checker {
        function,
        declarations,
        widths,
        reads,
        calls,
        assigns,
        seen: vec![false; function.stmts.len()],
        open: vec![false; function.stmts.len()],
        labels: BTreeMap::new(),
        gotos: Vec::new(),
    };
    checker.body()?;
    for (stmt, label) in checker.gotos {
        if !checker.labels.contains_key(&label) {
            return Err(at(Node::Stmt(stmt))(format!(
                "goto l{}, which is not defined",
                label.0
            )));
        }
    }
    let mut declared = BTreeSet::new();
    for (&stmt, vars) in &function.declared {
        if checker.seen.get(stmt.0 as usize) != Some(&true) {
            return Err(at(Node::Stmt(stmt))(String::from(
                "declarations at a statement in no block",
            )));
        }
        for &var in vars {
            let local = function
                .var(var)
                .is_some_and(|variable| variable.kind == VarKind::Local);
            if !local {
                return Err(at(Node::Var(var))(String::from(
                    "declared in a block, but not a local",
                )));
            }
            if !declared.insert(var) {
                return Err(at(Node::Var(var))(String::from("declared twice")));
            }
        }
    }
    Ok(())
}

/// Checks that C's order of evaluation fixes the order of the calls and
/// assignments in expressions ([`Expr::Call`], [`Expr::Assign`]) that
/// `roots` (a statement's, as
/// [`Stmt::roots`] lists them) make, and what each reads of memory: an
/// expression evaluated in either order with a call, or interleaved with
/// it, holds no other call and reads no memory (`reads`: a load, a
/// variable in memory or a call) the call could change; nor, with an
/// assignment, another effect or a read of the variable it writes
/// (6.5p2); each call and assignment is evaluated once. `calls` says
/// whether evaluating an expression makes a call or an assignment.
///
/// What C sequences (ISO/IEC 9899:2018): a call's function designator
/// and arguments before the call (6.5.2.2p10), the left operand of `&&`
/// and `||` before the right (6.5.13p4, 6.5.14p4), a conditional's
/// condition before its arm (6.5.15p4; but L2's select evaluates both
/// arms, C one: no call in an arm). Everything else is unsequenced: the
/// operands of every other operator, a call's arguments among
/// themselves, an assignment's value and address (6.5.16p3), a call
/// statement's arguments and its results' addresses. A statement's own
/// effect (a call statement's call, an assignment's store) follows what
/// it evaluates, so `f(g(x), y)` with `y` a local is in order and
/// `f(g(x), *p)` or `f(g(x), h(y))` is not; nor is `(v = e) + v`, but
/// `(v = e) != 0 && v < n` is (an assignment's value is its operand's,
/// computed before it writes).
///
/// # Errors
///
/// Why the order is not fixed.
///
/// # Examples
///
/// ```
/// use binbun_ast::ir::{Call, Callee, Expr, Function};
/// use binbun_ast::types::{Signature, Type, Types};
/// use binbun_ast::verify::ordered;
/// use binbun_semantics::bits::Bits;
///
/// let mut f = Function::new(0x1000, Types::new(64));
/// let int = f.types.intern(Type::Int(64));
/// let signature = f.types.intern(Type::Code(Signature {
///     parameters: vec![int],
///     returns: Some(int),
///     variadic: false,
/// }));
/// let one = f.add_expr(Expr::Const(Bits::from_u64(64, 1)));
/// let inner = f.add_call(Call {
///     callee: Callee::Address(0x2000),
///     arguments: vec![one],
///     signature,
///     variadic: Vec::new(),
/// });
/// let inner = f.add_expr(Expr::Call(inner));
/// let calls = |id| id == inner;
/// // f(g(1), 1): `g` is made before `f`, and nothing beside it reads memory.
/// assert!(ordered(&f, &[inner, one], &calls, &calls).is_ok());
/// // g(1) + g(1) through one node: one call made twice, unordered.
/// assert!(ordered(&f, &[inner, inner], &calls, &calls).is_err());
/// ```
pub fn ordered(
    function: &Function,
    roots: &[ExprId],
    calls: &dyn Fn(ExprId) -> bool,
    reads: &dyn Fn(ExprId) -> bool,
) -> Result<(), String> {
    // Groups of expressions C evaluates in any order among themselves.
    let mut groups: Vec<Vec<ExprId>> = vec![roots.to_vec()];
    let mut made: Vec<ExprId> = Vec::new();
    // Whether any assignment is evaluated: then the variables each effect
    // writes are compared with what is beside it.
    let assigning = assigns_any(function, roots);
    while let Some(group) = groups.pop() {
        let mut calling = group.iter().copied().filter(|&id| calls(id));
        let Some(hot) = calling.next() else {
            continue;
        };
        if calling.next().is_some() {
            return Err(format!(
                "calls beside e{} in an order C does not fix",
                hot.0
            ));
        }
        if let Some(&beside) = group.iter().find(|&&id| id != hot && reads(id)) {
            return Err(format!(
                "e{} reads memory beside a call, which C does not order",
                beside.0
            ));
        }
        let expr = function
            .expr(hot)
            .ok_or_else(|| format!("no expression e{}", hot.0))?;
        if assigning {
            let written = assigned(function, hot);
            if let Some(&beside) = group
                .iter()
                .find(|&&id| id != hot && touches(function, id, &written))
            {
                return Err(format!(
                    "e{} reads a variable e{} assigns, in an order C does not fix",
                    beside.0, hot.0
                ));
            }
        }
        match *expr {
            Expr::Call(_) | Expr::Assign { .. } => {
                if made.contains(&hot) {
                    return Err(format!("effect e{} made twice", hot.0));
                }
                made.push(hot);
                groups.push(expr.operands(function).collect());
            }
            Expr::Logical(_, left, right) => {
                groups.push(vec![left]);
                groups.push(vec![right]);
            }
            Expr::Select {
                condition,
                then,
                otherwise,
            } => {
                if calls(then) || calls(otherwise) {
                    return Err(format!("a call in an arm of select e{}", hot.0));
                }
                groups.push(vec![condition]);
            }
            Expr::Const(_)
            | Expr::Undefined(..)
            | Expr::Var(_)
            | Expr::AddressOf(_)
            | Expr::Unary(..)
            | Expr::Binary(..)
            | Expr::Flag(..)
            | Expr::Extract { .. }
            | Expr::Concat { .. }
            | Expr::Extend { .. }
            | Expr::Lanes { .. }
            | Expr::Float { .. }
            | Expr::Cast { .. }
            | Expr::Load { .. }
            | Expr::Exception { .. } => groups.push(expr.operands(function).collect()),
        }
    }
    Ok(())
}

/// The expressions `roots` reach, each once.
fn reached(function: &Function, roots: &[ExprId]) -> Vec<ExprId> {
    let mut seen = BTreeSet::new();
    let mut work = roots.to_vec();
    while let Some(id) = work.pop() {
        if seen.insert(id)
            && let Some(expr) = function.expr(id)
        {
            work.extend(expr.operands(function));
        }
    }
    seen.into_iter().collect()
}

/// Whether evaluating `roots` makes an assignment.
fn assigns_any(function: &Function, roots: &[ExprId]) -> bool {
    reached(function, roots)
        .into_iter()
        .any(|id| matches!(function.expr(id), Some(Expr::Assign { .. })))
}

/// The variables the assignments evaluating `id` makes write.
fn assigned(function: &Function, id: ExprId) -> Vec<VarId> {
    reached(function, &[id])
        .into_iter()
        .filter_map(|at| match function.expr(at) {
            Some(&Expr::Assign { var, .. }) => Some(var),
            Some(_) | None => None,
        })
        .collect()
}

/// Whether evaluating `id` reads or writes one of `vars`.
fn touches(function: &Function, id: ExprId, vars: &[VarId]) -> bool {
    !vars.is_empty()
        && reached(function, &[id]).into_iter().any(|at| {
            matches!(function.expr(at), Some(&Expr::Var(var) | &Expr::Assign { var, .. }) if vars.contains(&var))
        })
}

/// Checks that in `roots` (a condition with assignment expressions,
/// [`Expr::Assign`]) every node that reads or writes a variable one of
/// them writes is evaluated once: a read before an assignment and one
/// after it are different nodes, each evaluated when it is reached (an
/// evaluation computes a node once).
///
/// # Errors
///
/// The node evaluated twice.
pub fn single(function: &Function, roots: &[ExprId]) -> Result<(), String> {
    let written: Vec<VarId> = roots
        .iter()
        .flat_map(|&root| assigned(function, root))
        .collect();
    let mut seen = BTreeSet::new();
    let mut work = roots.to_vec();
    while let Some(id) = work.pop() {
        if !seen.insert(id) {
            if touches(function, id, &written) {
                return Err(format!(
                    "e{} evaluated twice where it reads or writes a variable an assignment expression writes",
                    id.0
                ));
            }
            continue;
        }
        if let Some(expr) = function.expr(id) {
            work.extend(expr.operands(function));
        }
    }
    Ok(())
}

/// Checks that type `id` exists.
fn exists(types: &Types, id: TypeId) -> Result<&Type, String> {
    types.get(id).ok_or_else(|| format!("no type t{}", id.0))
}

/// The width of a value of type `id`.
fn value_width(types: &Types, id: TypeId) -> Result<u16, String> {
    exists(types, id)?;
    types
        .value_width(id)
        .ok_or_else(|| format!("t{} does not fit a value", id.0))
}

/// The width of a value of type `id` in memory: a whole number of bytes.
fn memory_width(types: &Types, id: TypeId) -> Result<u16, String> {
    let width = value_width(types, id)?;
    if !width.is_multiple_of(8) {
        return Err(format!("t{} is {width} bits, not whole bytes", id.0));
    }
    Ok(width)
}

/// Checks that type `own` may refer to `target`: a struct or union
/// anywhere, any other type only before `own` (so following references
/// that are not through an aggregate always ends).
fn earlier(types: &Types, own: TypeId, target: TypeId) -> Result<(), String> {
    let aggregate = matches!(exists(types, target)?, Type::Struct(_) | Type::Union(_));
    if aggregate || target < own {
        Ok(())
    } else {
        Err(format!("refers to t{}, which is not before it", target.0))
    }
}

/// The types `ty` refers to other than through its fields: some, and a
/// return type.
fn references(ty: &Type) -> (&[TypeId], Option<TypeId>) {
    match ty {
        Type::Pointer(Some(target)) => (core::slice::from_ref(target), None),
        Type::Array { element, .. } | Type::Vector { element, .. } => {
            (core::slice::from_ref(element), None)
        }
        Type::Code(signature) => (&signature.parameters, signature.returns),
        Type::Bits(_)
        | Type::Int(_)
        | Type::UInt(_)
        | Type::Char { .. }
        | Type::Bool(_)
        | Type::Float(_)
        | Type::Pointer(None)
        | Type::Struct(_)
        | Type::Union(_)
        | Type::Enum(_) => (&[], None),
    }
}

fn check_type(types: &Types, id: TypeId, ty: &Type) -> Result<(), String> {
    let (referred, returns) = references(ty);
    for &target in referred.iter().chain(&returns) {
        earlier(types, id, target)?;
    }
    match ty {
        &(Type::Bits(width) | Type::Int(width) | Type::UInt(width) | Type::Bool(width)) => {
            if width == 0 || width > MAX_WIDTH {
                return Err(format!("width {width} out of range"));
            }
        }
        Type::Char { .. } | Type::Float(_) | Type::Pointer(None) => {}
        Type::Enum(enumeration) => {
            let width = enumeration.width;
            if width == 0 || width > 64 {
                return Err(format!("enumeration of width {width}"));
            }
            let above = u128::MAX.checked_shl(u32::from(width)).unwrap_or(0);
            if let Some((name, _)) = enumeration
                .constants
                .iter()
                .find(|&&(_, value)| value & above != 0)
            {
                return Err(format!(
                    "enumeration constant {name} wider than {width} bits"
                ));
            }
        }
        &Type::Pointer(Some(target)) => {
            exists(types, target)?;
        }
        Type::Code(signature) => {
            for &parameter in &signature.parameters {
                value_width(types, parameter)?;
            }
            if let Some(returns) = signature.returns {
                value_width(types, returns)?;
            }
        }
        Type::Struct(aggregate) | Type::Union(aggregate) => {
            let union = matches!(ty, Type::Union(_));
            for field in &aggregate.fields {
                exists(types, field.ty)?;
                let width = types
                    .width(field.ty)
                    .ok_or_else(|| format!("field at {} has no width", field.offset))?;
                let end = field
                    .offset
                    .checked_mul(8)
                    .and_then(|start| start.checked_add(width));
                if end.is_none_or(|end| end > aggregate.size.saturating_mul(8)) {
                    return Err(format!("field at {} past the end", field.offset));
                }
                if union && field.offset != 0 {
                    return Err(format!("union field at {}", field.offset));
                }
            }
        }
        &Type::Array { element, .. } => {
            exists(types, element)?;
            if types.width(element).is_none() {
                return Err(format!("array of t{}, which has no width", element.0));
            }
        }
        &Type::Vector { lanes, element } => {
            let scalar = matches!(
                exists(types, element)?,
                Type::Bits(_)
                    | Type::Int(_)
                    | Type::UInt(_)
                    | Type::Char { .. }
                    | Type::Bool(_)
                    | Type::Float(_)
                    | Type::Pointer(_)
            );
            let lane = types.width(element).unwrap_or(0);
            if !scalar || lanes == 0 || lane.saturating_mul(u64::from(lanes)) > u64::from(MAX_WIDTH)
            {
                return Err(format!("vector of {lanes} lanes of t{}", element.0));
            }
        }
    }
    Ok(())
}

/// Checks the variables and the signature.
fn variables(function: &Function, declarations: &Declarations) -> Result<(), VerifyError> {
    let types = &function.types;
    let mut listed = vec![0usize; function.variables.len()];
    for &parameter in &function.parameters {
        let count = listed
            .get_mut(parameter.0 as usize)
            .ok_or_else(|| VerifyError {
                node: None,
                message: format!("parameter v{} does not exist", parameter.0),
            })?;
        *count += 1;
    }
    for ((index, variable), count) in (0..).zip(&function.variables).zip(listed) {
        let error = at(Node::Var(VarId(index)));
        let check = || match variable.kind {
            VarKind::Parameter | VarKind::Local => value_width(types, variable.ty).map(drop),
            VarKind::Environment(register) => {
                let width = value_width(types, variable.ty)?;
                match declarations.info(register) {
                    Some(info) if info.width == width => Ok(()),
                    Some(info) => Err(format!(
                        "{width} bits, but register {} has {}",
                        info.name, info.width
                    )),
                    None => Err(format!("register {} is not declared", register.0)),
                }
            }
            VarKind::Global(_) | VarKind::Frame(_) => {
                exists(types, variable.ty)?;
                match types.width(variable.ty) {
                    Some(width) if width.is_multiple_of(8) => Ok(()),
                    Some(_) | None => Err(String::from("in memory, but not whole bytes")),
                }
            }
        };
        check().map_err(&error)?;
        let parameter = variable.kind == VarKind::Parameter;
        if count != usize::from(parameter) {
            return Err(error(format!(
                "listed {count} times among the parameters, but is {}a parameter",
                if parameter { "" } else { "not " }
            )));
        }
    }
    if let Some(returns) = function.returns {
        value_width(types, returns).map_err(|message| VerifyError {
            node: None,
            message: format!("return type: {message}"),
        })?;
    }
    Ok(())
}

/// The width of a read of variable `id`.
fn read_width(function: &Function, id: VarId) -> Result<u16, String> {
    let variable = function
        .var(id)
        .ok_or_else(|| format!("v{} is not declared", id.0))?;
    match variable.kind {
        VarKind::Parameter | VarKind::Local | VarKind::Environment(_) => {
            value_width(&function.types, variable.ty)
        }
        VarKind::Global(_) | VarKind::Frame(_) => memory_width(&function.types, variable.ty),
    }
}

/// The width of the address of variable `id`, which is in memory.
fn address_width(function: &Function, id: VarId) -> Result<u16, String> {
    let variable = function
        .var(id)
        .ok_or_else(|| format!("v{} is not declared", id.0))?;
    match variable.kind {
        VarKind::Global(_) | VarKind::Frame(_) => Ok(function.types.pointer_width()),
        VarKind::Parameter | VarKind::Local | VarKind::Environment(_) => {
            Err(format!("address of v{}, which is not in memory", id.0))
        }
    }
}

/// The width of `expr` (an expression of `function`), by L0's rules, with
/// its operands' widths from `operand`.
///
/// # Errors
///
/// The rule `expr` breaks, or `operand`'s error.
pub fn expr_width(
    function: &Function,
    expr: &Expr,
    operand: &mut dyn FnMut(ExprId) -> Result<u16, String>,
) -> Result<u16, String> {
    let types = &function.types;
    let width = match *expr {
        Expr::Const(bits) => bits.width(),
        Expr::Undefined(width, ..) => width,
        Expr::Var(id) => read_width(function, id)?,
        Expr::AddressOf(id) => address_width(function, id)?,
        Expr::Unary(op, a) => unary_width(op, operand(a)?)?,
        Expr::Binary(op, a, b) => binary_width(op, operand(a)?, operand(b)?)?,
        Expr::Logical(op, a, b) => {
            let (a, b) = (operand(a)?, operand(b)?);
            if a != 1 || b != 1 {
                return Err(format!("{op:?} of {a}- and {b}-bit operands"));
            }
            1
        }
        Expr::Flag(op, a, b, c) => {
            let (a, b, c) = (operand(a)?, operand(b)?, operand(c)?);
            if a != b || a != c {
                return Err(format!("{op:?} of {a}-, {b}- and {c}-bit operands"));
            }
            1
        }
        Expr::Extract {
            value,
            offset,
            width,
        } => {
            let source = operand(value)?;
            if u32::from(offset) + u32::from(width) > u32::from(source) {
                return Err(format!("extract past the end of a {source}-bit value"));
            }
            width
        }
        Expr::Concat { high, low } => {
            let sum = u32::from(operand(high)?) + u32::from(operand(low)?);
            u16::try_from(sum).map_err(|_| String::from("concatenation too wide"))?
        }
        Expr::Extend { value, width, .. } => {
            let source = operand(value)?;
            if width <= source {
                return Err(format!("extension of {source} bits to {width}"));
            }
            width
        }
        Expr::Select {
            condition,
            then,
            otherwise,
        } => {
            if operand(condition)? != 1 {
                return Err("select condition is not 1 bit".into());
            }
            let (then, otherwise) = (operand(then)?, operand(otherwise)?);
            if then != otherwise {
                return Err(format!("select of {then}- and {otherwise}-bit values"));
            }
            then
        }
        Expr::Lanes { .. } | Expr::Float { .. } => vector_width(expr, operand)?,
        Expr::Cast { value, ty } => {
            let (source, own) = (operand(value)?, value_width(types, ty)?);
            if source != own {
                return Err(format!("cast of {source} bits to t{}, {own} bits", ty.0));
            }
            own
        }
        Expr::Load { address, ty } => {
            pointer(types, operand(address)?)?;
            memory_width(types, ty)?
        }
        Expr::Call(id) => {
            let call = function.call(id).ok_or("no such call")?;
            let returns = signature(function, call, operand)?.ok_or("no value returned")?;
            value_width(types, returns)?
        }
        Expr::Exception { value, width } => exception_width(types, value, width)?,
        Expr::Assign { var, value } => {
            let variable = function
                .var(var)
                .ok_or_else(|| format!("no variable v{}", var.0))?;
            if !matches!(variable.kind, VarKind::Local | VarKind::Parameter) {
                return Err(format!(
                    "an assignment expression to v{}, not a local or parameter",
                    var.0
                ));
            }
            let (own, width) = (value_width(types, variable.ty)?, operand(value)?);
            if own != width {
                return Err(format!("{width} bits assigned to v{}, {own} bits", var.0));
            }
            own
        }
    };
    if width == 0 || width > MAX_WIDTH {
        return Err(format!("width {width} out of range"));
    }
    Ok(width)
}

/// The width of an exception value `width` bits wide: an exception
/// object is pointer-wide.
fn exception_width(types: &Types, value: ExceptionValue, width: u16) -> Result<u16, String> {
    if value == ExceptionValue::Object && width != types.pointer_width() {
        return Err(format!("{width}-bit exception object, not pointer-wide"));
    }
    Ok(width)
}

/// Checks `call` against its signature (its callee and arguments' widths
/// from `operand`): its return type, if any.
fn signature(
    function: &Function,
    call: &Call,
    operand: &mut dyn FnMut(ExprId) -> Result<u16, String>,
) -> Result<Option<TypeId>, String> {
    let types = &function.types;
    let signature = types
        .signature(call.signature)
        .ok_or_else(|| format!("t{} is not a code pointer", call.signature.0))?;
    if let Callee::Expr(target) = call.callee {
        pointer(types, operand(target)?)?;
    }
    let count = signature.parameters.len();
    if call.arguments.len() < count || (!signature.variadic && call.arguments.len() > count) {
        return Err(format!(
            "{} arguments for {count} parameters",
            call.arguments.len()
        ));
    }
    for (position, &argument) in call.arguments.iter().enumerate() {
        let width = operand(argument)?;
        let stated = signature.parameters.get(position).or_else(|| {
            position
                .checked_sub(count)
                .and_then(|index| call.variadic.get(index))
        });
        if let Some(&ty) = stated
            && value_width(types, ty)? != width
        {
            return Err(format!("argument {position} is {width} bits"));
        }
    }
    let extra = call.arguments.len().saturating_sub(count);
    if call.variadic.len() > extra {
        return Err(format!(
            "{} variadic types for {extra} variadic arguments",
            call.variadic.len()
        ));
    }
    Ok(signature.returns)
}

/// The width of a lane-wise or floating-point operation.
fn vector_width(
    expr: &Expr,
    operand: &mut dyn FnMut(ExprId) -> Result<u16, String>,
) -> Result<u16, String> {
    match *expr {
        Expr::Lanes {
            lanes,
            op,
            operands,
        } => {
            let widths = operands
                .iter()
                .take(op.arity())
                .map(|&a| operand(a))
                .collect::<Result<Vec<u16>, String>>()?;
            lanes_width(op, lanes, &widths)
        }
        Expr::Float {
            op,
            format,
            lanes,
            output,
            rounding,
            operands,
        } => {
            let rounding = operand(rounding)?;
            let widths = operands
                .iter()
                .take(op.arity())
                .map(|&a| operand(a))
                .collect::<Result<Vec<u16>, String>>()?;
            float_width(op, format, lanes, output, rounding, &widths)
        }
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
        | Expr::Cast { .. }
        | Expr::Load { .. }
        | Expr::Call(_)
        | Expr::Exception { .. }
        | Expr::Assign { .. } => Err("not a vector operation".into()),
    }
}

/// Checks that an address is `width` bits: pointer-wide.
fn pointer(types: &Types, width: u16) -> Result<(), String> {
    if width == types.pointer_width() {
        Ok(())
    } else {
        Err(format!(
            "{width}-bit address, not {}",
            types.pointer_width()
        ))
    }
}

struct Checker<'a> {
    function: &'a Function,
    declarations: &'a Declarations,
    /// Every expression's width.
    widths: Vec<u16>,
    /// Whether each expression reads memory.
    reads: Vec<bool>,
    /// How many calls each evaluation of each expression makes.
    calls: Vec<u32>,
    /// Whether evaluating each expression makes an assignment.
    assigns: Vec<bool>,
    /// Whether each statement has been seen in a block.
    seen: Vec<bool>,
    /// Whether each statement is a loop or switch around the current one.
    open: Vec<bool>,
    /// Where each label seen is defined.
    labels: BTreeMap<LabelId, StmtId>,
    /// Every goto seen, and its label.
    gotos: Vec<(StmtId, LabelId)>,
}

/// An item of the verifier's work stack.
#[derive(Clone, Copy)]
enum Work {
    /// Check a statement, then the ones it holds.
    Enter(StmtId),
    /// The statements a loop or switch holds are done.
    Leave(StmtId),
}

impl<'a> Checker<'a> {
    /// Checks the body, each statement before those it holds, in order.
    /// An explicit work stack, not recursion: nesting may be arbitrarily
    /// deep.
    fn body(&mut self) -> Result<(), VerifyError> {
        let function = self.function;
        let mut work: Vec<Work> = function
            .body
            .iter()
            .rev()
            .map(|&id| Work::Enter(id))
            .collect();
        while let Some(item) = work.pop() {
            match item {
                Work::Enter(id) => {
                    let stmt = self.stmt(id)?;
                    if stmt.is_loop() || matches!(stmt, Stmt::Switch { .. }) {
                        self.set_open(id, true);
                        work.push(Work::Leave(id));
                    }
                    let blocks: Vec<&Block> = stmt.blocks().collect();
                    for block in blocks.into_iter().rev() {
                        work.extend(block.iter().rev().map(|&child| Work::Enter(child)));
                    }
                }
                Work::Leave(id) => self.set_open(id, false),
            }
        }
        Ok(())
    }

    fn set_open(&mut self, id: StmtId, open: bool) {
        if let Some(slot) = self.open.get_mut(id.0 as usize) {
            *slot = open;
        }
    }

    /// The width of expression `id`.
    fn width(&self, id: ExprId) -> Result<u16, String> {
        self.widths
            .get(id.0 as usize)
            .copied()
            .ok_or_else(|| format!("no expression e{}", id.0))
    }

    /// Checks that `id` is a 1-bit condition.
    fn condition(&self, id: ExprId) -> Result<(), String> {
        match self.width(id)? {
            1 => Ok(()),
            width => Err(format!("condition e{} is {width} bits", id.0)),
        }
    }

    /// Checks statement `id` (not the statements it holds).
    fn stmt(&mut self, id: StmtId) -> Result<&'a Stmt, VerifyError> {
        let error = at(Node::Stmt(id));
        let function = self.function;
        let stmt = function.stmt(id).ok_or_else(|| VerifyError {
            node: None,
            message: format!("no statement s{}", id.0),
        })?;
        match self.seen.get_mut(id.0 as usize) {
            Some(seen) if !*seen => *seen = true,
            Some(_) | None => return Err(error("in more than one place".into())),
        }
        match stmt {
            Stmt::If { condition, .. }
            | Stmt::While { condition, .. }
            | Stmt::DoWhile { condition, .. } => self.condition(*condition),
            Stmt::For {
                init,
                condition,
                step,
                ..
            } => {
                for &simple in init.iter().chain(step) {
                    match function.stmt(simple) {
                        Some(
                            Stmt::Assign { .. }
                            | Stmt::Call { .. }
                            | Stmt::Intrinsic { .. }
                            | Stmt::Expr(_),
                        )
                        | None => {}
                        Some(_) => {
                            return Err(error(format!(
                                "s{} in init or step is not a simple statement",
                                simple.0
                            )));
                        }
                    }
                }
                self.condition(*condition)
            }
            Stmt::Switch { scrutinee, arms } => self.switch(*scrutinee, arms),
            Stmt::Try { handlers, .. } => handlers_rule(handlers),
            Stmt::Assign { .. }
            | Stmt::Call { .. }
            | Stmt::Intrinsic { .. }
            | Stmt::Expr(_)
            | Stmt::Break(_)
            | Stmt::Continue(_)
            | Stmt::Label(_)
            | Stmt::Goto(_)
            | Stmt::Return(_)
            | Stmt::Trap(_)
            | Stmt::Unreachable
            | Stmt::Escape { .. }
            | Stmt::VaStart { .. } => self.simple(id, stmt),
        }
        .and_then(|()| self.effects(stmt))
        .map_err(error)?;
        Ok(stmt)
    }

    /// Checks the rule for calls in expressions ([`Expr::Call`]): a
    /// statement evaluating them is an assignment, an expression
    /// statement, a return, a decision or a call statement (whose call
    /// follows its arguments), and C's order of evaluation fixes their
    /// order and what they read ([`ordered`]); and for assignment
    /// expressions ([`Expr::Assign`]): a statement evaluating them is an
    /// `if` or a loop, no node touching their variables shared
    /// ([`single`]).
    fn effects(&self, stmt: &Stmt) -> Result<(), String> {
        let roots = stmt.roots();
        let calls = |id: ExprId| self.calls.get(id.0 as usize).is_none_or(|&count| count > 0);
        let reads = |id: ExprId| self.reads.get(id.0 as usize) != Some(&false);
        if !roots.iter().any(|&root| calls(root)) {
            return Ok(());
        }
        if roots
            .iter()
            .any(|&root| self.assigns.get(root.0 as usize) != Some(&false))
        {
            if !matches!(
                stmt,
                Stmt::If { .. } | Stmt::While { .. } | Stmt::DoWhile { .. } | Stmt::For { .. }
            ) {
                return Err("an assignment expression outside a condition".into());
            }
            single(self.function, &roots)?;
        }
        match stmt {
            Stmt::Assign { .. }
            | Stmt::Expr(_)
            | Stmt::Return(_)
            | Stmt::If { .. }
            | Stmt::While { .. }
            | Stmt::DoWhile { .. }
            | Stmt::For { .. }
            | Stmt::Switch { .. }
            | Stmt::Try { .. }
            | Stmt::VaStart { .. }
            | Stmt::Call { .. } => {}
            Stmt::Intrinsic { .. }
            | Stmt::Escape { .. }
            | Stmt::Break(_)
            | Stmt::Continue(_)
            | Stmt::Label(_)
            | Stmt::Goto(_)
            | Stmt::Trap(_)
            | Stmt::Unreachable => {
                return Err("a call in an expression beside another effect".into());
            }
        }
        ordered(self.function, &roots, &calls, &reads)
    }

    /// Checks a statement that holds no blocks.
    fn simple(&mut self, id: StmtId, stmt: &Stmt) -> Result<(), String> {
        let function = self.function;
        match stmt {
            Stmt::Assign { place, value } => {
                let (own, value) = (self.place(place)?, self.width(*value)?);
                if own != value {
                    return Err(format!("{value}-bit value assigned to {own} bits"));
                }
            }
            Stmt::Call { results, call } => self.call(results, call)?,
            Stmt::Intrinsic {
                results,
                intrinsic,
                inputs,
            } => {
                let info = self
                    .declarations
                    .intrinsic(*intrinsic)
                    .ok_or_else(|| format!("no intrinsic {}", intrinsic.0))?;
                let widths = inputs
                    .iter()
                    .map(|&input| self.width(input))
                    .collect::<Result<Vec<_>, _>>()?;
                let places = self.results(results)?;
                // An opaque one's inputs and outputs are its own.
                if info.opaque {
                    return Ok(());
                }
                if widths != info.inputs {
                    return Err(format!("{} of {widths:?} bits", info.name));
                }
                if places != info.outputs {
                    return Err(format!("{} outputs to {places:?} bits", info.name));
                }
            }
            Stmt::Escape {
                kind: Escape::Atomic,
                operands,
                results,
            } => self.atomic(operands, results)?,
            Stmt::Escape {
                kind: Escape::Update(update),
                operands,
                results,
            } => self.update(*update, operands, results)?,
            Stmt::Escape {
                operands, results, ..
            } => {
                for &operand in operands {
                    self.width(operand)?;
                }
                self.results(results)?;
            }
            &Stmt::Expr(value) => {
                self.width(value)?;
            }
            &Stmt::Break(target) => self.target(target, false)?,
            &Stmt::Continue(target) => self.target(target, true)?,
            &Stmt::Label(label) => {
                if label.0 >= function.labels {
                    return Err(format!("label l{} does not exist", label.0));
                }
                if let Some(first) = self.labels.insert(label, id) {
                    return Err(format!("l{} is also defined at s{}", label.0, first.0));
                }
            }
            &Stmt::Goto(label) => self.gotos.push((id, label)),
            &Stmt::Return(value) => {
                let value = value.map(|value| self.width(value)).transpose()?;
                let own = function
                    .returns
                    .map(|ty| value_width(&function.types, ty))
                    .transpose()?;
                if value != own {
                    return Err(format!(
                        "returns {value:?} bits from a function returning {own:?}"
                    ));
                }
            }
            Stmt::Trap(_) | Stmt::Unreachable => {}
            &Stmt::VaStart { list } => self.va_start(list)?,
            Stmt::If { .. }
            | Stmt::While { .. }
            | Stmt::DoWhile { .. }
            | Stmt::For { .. }
            | Stmt::Switch { .. }
            | Stmt::Try { .. } => return Err("not a simple statement".into()),
        }
        Ok(())
    }

    /// Checks a `va_start` of `list` against [`Function::va`].
    fn va_start(&self, list: Place) -> Result<(), String> {
        let function = self.function;
        let va = match &function.va {
            Some(va) if function.variadic => va,
            Some(_) | None => return Err("va_start outside a variadic function's ABI".into()),
        };
        let width = |register| {
            self.declarations
                .info(register)
                .map(|info| info.width)
                .ok_or_else(|| format!("register {} is not declared", register.0))
        };
        for save in &va.saves {
            if save.bytes == 0 || u32::from(save.bytes) * 8 > u32::from(width(save.register)?) {
                return Err(format!(
                    "saves {} bytes of register {}",
                    save.bytes, save.register.0
                ));
            }
            if let Some(guard) = save.guard {
                width(guard)?;
            }
        }
        let Place::Var(id) = list else {
            return Err("the va_list is not a variable".into());
        };
        let variable = function
            .var(id)
            .ok_or_else(|| format!("variable v{} does not exist", id.0))?;
        let memory = matches!(variable.kind, VarKind::Global(_) | VarKind::Frame(_));
        let fits = match va.list {
            VaList::Tag { .. } => memory && function.types.width(variable.ty) == Some(24 * 8),
            VaList::Aapcs64 {
                gr_offs, vr_offs, ..
            } => {
                memory
                    && function.types.width(variable.ty) == Some(32 * 8)
                    && gr_offs <= 0
                    && vr_offs <= 0
                    && va
                        .saves
                        .iter()
                        .all(|save| matches!(save.bytes, 8 | 16) && save.guard.is_none())
            }
            VaList::Pointer(_) => {
                matches!(variable.kind, VarKind::Parameter | VarKind::Local)
                    && function.types.value_width(variable.ty)
                        == Some(function.types.pointer_width())
            }
        };
        if fits {
            Ok(())
        } else {
            Err(format!("v{} does not fit the va_list", id.0))
        }
    }

    /// Checks that `target` is an enclosing loop (or, for a break, switch).
    fn target(&self, target: StmtId, loop_only: bool) -> Result<(), String> {
        let what = if loop_only { "continue" } else { "break" };
        let encloses = self.open.get(target.0 as usize) == Some(&true);
        let is_loop = self.function.stmt(target).is_some_and(Stmt::is_loop);
        if !encloses || (loop_only && !is_loop) {
            return Err(format!(
                "{what} s{}, which is not an enclosing {}",
                target.0,
                if loop_only { "loop" } else { "loop or switch" }
            ));
        }
        Ok(())
    }

    /// Checks a switch's scrutinee and arms (not their bodies).
    fn switch(&self, scrutinee: ExprId, arms: &[Arm]) -> Result<(), String> {
        let width = self.width(scrutinee)?;
        let mut values: Vec<&Bits> = Vec::new();
        for arm in arms {
            for value in &arm.values {
                if value.width() != width {
                    return Err(format!(
                        "case {value}:{} on a {width}-bit value",
                        value.width()
                    ));
                }
                values.push(value);
            }
        }
        values.sort_unstable();
        if let Some(pair) = values.windows(2).find(|pair| pair.first() == pair.last()) {
            let value = pair.first().copied().copied().unwrap_or(Bits::zero(1));
            return Err(format!("case {value}:{width} twice"));
        }
        if arms.iter().filter(|arm| arm.default).count() > 1 {
            return Err("more than one default".into());
        }
        if arms.last().is_some_and(|arm| arm.fallthrough) {
            return Err("the last arm falls through".into());
        }
        Ok(())
    }

    /// The width of `place`.
    fn place(&self, place: &Place) -> Result<u16, String> {
        let function = self.function;
        match *place {
            Place::Var(id) => {
                let variable = function
                    .var(id)
                    .ok_or_else(|| format!("v{} is not declared", id.0))?;
                let ty = variable.ty;
                match variable.kind {
                    VarKind::Parameter | VarKind::Local => value_width(&function.types, ty),
                    VarKind::Environment(_) => Err(format!("v{} is read only", id.0)),
                    VarKind::Global(_) | VarKind::Frame(_) => memory_width(&function.types, ty),
                }
            }
            Place::Memory { address, ty } => {
                pointer(&function.types, self.width(address)?)?;
                memory_width(&function.types, ty)
            }
        }
    }

    /// The widths of the results of a call, intrinsic or escape, checking
    /// the one-effect rule.
    fn results(&self, results: &[Place]) -> Result<Vec<u16>, String> {
        if results.len() > 1 {
            for (index, place) in results.iter().enumerate() {
                let Place::Var(id) = place else {
                    return Err("one of several results in memory: two effects".into());
                };
                if results.iter().skip(index + 1).any(|other| other == place) {
                    return Err(format!("v{} written twice: two effects", id.0));
                }
            }
        }
        if let Some(&Place::Memory { address, .. }) = results.first()
            && self.reads.get(address.0 as usize) == Some(&true)
        {
            return Err("result stored at an address that reads memory: two effects".into());
        }
        results.iter().map(|place| self.place(place)).collect()
    }

    /// Checks an [`Escape::Atomic`] access: a load (`[address]`, one
    /// result) or a store (`[address, value]`, no result), of whole bytes
    /// at a pointer-wide address.
    fn atomic(&self, operands: &[ExprId], results: &[Place]) -> Result<(), String> {
        let types = &self.function.types;
        let width = match (operands, results) {
            (&[address], [place]) => {
                pointer(types, self.width(address)?)?;
                self.results(results)?;
                self.place(place)?
            }
            (&[address, value], []) => {
                pointer(types, self.width(address)?)?;
                self.width(value)?
            }
            _ => return Err("atomic: not one load or one store".into()),
        };
        if width % 8 == 0 {
            Ok(())
        } else {
            Err(format!("atomic access of {width} bits"))
        }
    }

    /// Checks an [`Escape::Update`]: a pointer-wide address, then the
    /// update's operands, of one width of whole bytes, and at most one
    /// result of that width.
    fn update(&self, update: Update, operands: &[ExprId], results: &[Place]) -> Result<(), String> {
        let types = &self.function.types;
        let Some((&address, values)) = operands.split_first() else {
            return Err("atomic update: no address".into());
        };
        pointer(types, self.width(address)?)?;
        if values.len() != update.arity() || results.len() > 1 {
            return Err(format!(
                "atomic update: {} operands, {} results",
                values.len(),
                results.len()
            ));
        }
        let mut widths = self.results(results)?;
        for &value in values {
            widths.push(self.width(value)?);
        }
        match widths.split_first() {
            Some((&width, rest)) if width % 8 == 0 && rest.iter().all(|&w| w == width) => Ok(()),
            Some(_) | None => Err(format!("atomic update of {widths:?} bits")),
        }
    }

    /// Checks a call against its signature.
    fn call(&self, results: &[Place], call: &Call) -> Result<(), String> {
        let types = &self.function.types;
        let returns = signature(self.function, call, &mut |id| self.width(id))?;
        let places = self.results(results)?;
        if !places.is_empty() {
            let returns = returns.ok_or("results from a call that returns nothing")?;
            let sum: u32 = places.iter().map(|&width| u32::from(width)).sum();
            if sum != u32::from(value_width(types, returns)?) {
                return Err(format!("results of {sum} bits for t{}", returns.0));
            }
        }
        Ok(())
    }
}

/// Checks a `Try`'s handlers: at least one; a `Landing` alone; a
/// catch-all or cleanup only last.
fn handlers_rule(handlers: &[Handler]) -> Result<(), String> {
    let Some((_, before)) = handlers.split_last() else {
        return Err("a try without handlers".into());
    };
    if handlers.len() > 1
        && handlers
            .iter()
            .any(|handler| matches!(handler.kind, HandlerKind::Landing(_)))
    {
        return Err("a landing handler beside others".into());
    }
    if before
        .iter()
        .any(|handler| matches!(handler.kind, HandlerKind::CatchAll) || handler.kind.cleans_up())
    {
        return Err("a catch-all or cleanup handler before another".into());
    }
    Ok(())
}
