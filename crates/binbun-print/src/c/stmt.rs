//! Statements: assignments, calls, intrinsics, the structured statements,
//! L0's canonical-address checks (`binbun_check_canonical(p);`), jumps (a
//! `break` or `continue` C cannot say becomes a `goto`), and what C cannot
//! say through `binbun_defs.h`'s escape helpers.

use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use binbun_ast::ir::{
    Arm, Block, Call, Callee, CatchType, Escape, Expr, ExprId, Function, Handler, HandlerKind,
    Node, Place, SehFilter, Stmt, StmtId, Update, VarId,
};
use binbun_ast::types::{Type, TypeId};
use binbun_semantics::bits::Bits;
use binbun_semantics::ir::{Binary, IntrinsicId, Trap, Unary};

use super::convert::{self, Class, IntTy, constant_value};
use super::enums::Context;
use super::expr::{Shape, Shift};
use super::types::{CTy, container, native, with_specifier};
use super::unlifted::{is_unlifted, pure};
use super::value::{Op, Value};
use super::{Intrinsic, Opaque, PrintError, Printer, error};
use crate::document::{BlockKind, Braces, Doc, TokenKind};

/// How deep statements may nest (C11 asks compilers for 127 levels of
/// blocks; the printer recurses on statement depth, and must fit a 2 MiB
/// thread unoptimized).
pub(super) const MAX_NESTING: usize = 100;

/// A block's items, whether it is one simple statement, and whether its
/// last item is a label (which needs a statement after it).
struct Items {
    docs: Vec<Doc>,
    simple: bool,
    label_last: bool,
}

impl Printer<'_> {
    /// The items of `block`, one per line.
    pub(super) fn block(&mut self, block: &Block) -> Result<Vec<Doc>, PrintError> {
        let mut items = self.items(block)?;
        if items.label_last {
            items.docs.push(Doc::Group(vec![Doc::punct(";", None)]));
        }
        Ok(items.docs)
    }

    fn items(&mut self, block: &Block) -> Result<Items, PrintError> {
        self.nesting += 1;
        if self.nesting > MAX_NESTING {
            return Err(error(
                None,
                format!("statements nested deeper than {MAX_NESTING}"),
            ));
        }
        let mut items = Items {
            docs: Vec::new(),
            simple: false,
            label_last: false,
        };
        let mut simple_count = 0;
        let mut position = 0;
        while let Some(&id) = block.get(position) {
            if self.opaque == Opaque::Asm && self.unlifted_at(id) {
                // One block also across the assignments not printed.
                let run: Vec<StmtId> = block
                    .get(position..)
                    .unwrap_or_default()
                    .iter()
                    .copied()
                    .take_while(|&next| self.unlifted_at(next) || self.unprinted.contains(&next))
                    .collect();
                position += run.len();
                // The locals declared in the run, before it (no use of
                // them comes before their declaration in the block).
                let mut declared = Vec::new();
                for &next in &run {
                    declared.extend(self.scoped_declarations(next, true)?);
                }
                if !declared.is_empty() {
                    after_label(&mut items);
                    items.docs.extend(declared);
                }
                let run: Vec<StmtId> = run
                    .into_iter()
                    .filter(|&next| self.unlifted_at(next))
                    .collect();
                items.docs.extend(self.asm_block(&run)?);
                items.label_last = false;
                simple_count += 2;
                continue;
            }
            position += 1;
            let saved = self.node;
            self.node = Some(Node::Stmt(id));
            let declared = self.scoped_declarations(id, false);
            let printed = declared.and_then(|declared| Ok((declared, self.statement(id)?)));
            self.node = saved;
            let (declared, (docs, simple, label)) = printed?;
            // A statement that is a declaration (`T v = e;`) is one too:
            // its block keeps its braces.
            let declaring =
                !declared.is_empty() || (self.initializes(id).is_some() && !docs.is_empty());
            if declaring {
                after_label(&mut items);
                simple_count += 2;
            }
            items.docs.extend(declared);
            if docs.is_empty() {
                continue;
            }
            simple_count += if simple { docs.len() } else { 2 };
            items.label_last = label;
            items.docs.extend(docs);
            if let Some(name) = self.break_labels.get(&id).cloned() {
                items.docs.push(self.label(name));
                items.label_last = true;
                simple_count += 2;
            }
        }
        items.simple = simple_count == 1 && items.docs.len() == 1;
        self.nesting -= 1;
        Ok(items)
    }

    /// `name:` one level left.
    fn label(&self, name: String) -> Doc {
        Doc::Outdent(vec![
            Doc::name(TokenKind::Label, name, true, self.node),
            Doc::punct(":", self.node),
        ])
    }

    /// One statement line: `tokens;`.
    pub(super) fn line(&self, tokens: Vec<Doc>) -> Doc {
        Doc::Group(vec![Doc::Nest(tokens), Doc::punct(";", self.node)])
    }

    /// A keyword of control flow.
    fn keyword(&self, text: &str) -> Doc {
        Doc::control(text, self.node)
    }

    /// A macro of `binbun_defs.h`'s (or the standard's) for the statement.
    fn macro_name(&self, text: &str) -> Doc {
        Doc::macro_name(text, self.node)
    }

    /// A statement's items, whether it is simple, and whether it is a
    /// label.
    fn statement(&mut self, id: StmtId) -> Result<(Vec<Doc>, bool, bool), PrintError> {
        let stmt = self
            .f
            .stmt(id)
            .cloned()
            .ok_or_else(|| error(Some(Node::Stmt(id)), "no such statement"))?;
        let simple = |docs| Ok((docs, true, false));
        let compound = |doc| Ok((vec![doc], false, false));
        match stmt {
            Stmt::Assign { .. } if self.unprinted.contains(&id) => Ok((Vec::new(), false, false)),
            Stmt::Assign { place, value } => simple(self.assign_statement(id, &place, value)?),
            Stmt::Call { results, call } => simple(self.call(&results, &call)?),
            Stmt::Intrinsic {
                results,
                intrinsic,
                inputs,
            } => simple(self.intrinsic(&results, intrinsic, &inputs)?),
            Stmt::Expr(expr) => {
                let tokens = self.evaluated(expr)?;
                simple(vec![self.line(tokens)])
            }
            Stmt::If {
                condition,
                then,
                otherwise,
            } => {
                if let Some((name, address)) = self.canonical_check(condition, &then, &otherwise) {
                    return simple(vec![self.canonical_statement(name, address)?]);
                }
                compound(self.if_statement(condition, &then, &otherwise)?)
            }
            Stmt::While { condition, body } => {
                let doc = self.while_loop(id, condition, &body)?;
                compound(doc)
            }
            Stmt::DoWhile { body, condition } => compound(self.do_loop(id, &body, condition)?),
            Stmt::For {
                init,
                condition,
                step,
                body,
            } => Ok((
                self.for_loop(id, &init, condition, &step, &body)?,
                false,
                false,
            )),
            Stmt::Switch { scrutinee, arms } => compound(self.switch(id, scrutinee, &arms)?),
            Stmt::Break(target) => simple(vec![self.jump(target, true)?]),
            Stmt::Continue(target) => simple(vec![self.jump(target, false)?]),
            Stmt::Label(label) => match self.labels.get(&label).cloned() {
                Some(name) => Ok((vec![self.label(name)], false, true)),
                None => Ok((Vec::new(), false, false)),
            },
            Stmt::Goto(label) => {
                let name = self
                    .labels
                    .get(&label)
                    .cloned()
                    .ok_or_else(|| error(self.node, "goto to a label never defined"))?;
                self.counts.gotos += 1;
                simple(vec![self.line(vec![
                    self.keyword("goto"),
                    Doc::Space,
                    Doc::name(TokenKind::Label, name, true, self.node),
                ])])
            }
            Stmt::Return(value) => simple(self.return_statement(value)?),
            Stmt::Trap(Trap::Interrupt(vector)) => {
                let vector = Doc::number(super::number(u128::from(vector), true), self.node);
                let call = self.statement_call("binbun_interrupt", vec![vec![vector]]);
                simple(vec![self.line(call)])
            }
            Stmt::Trap(trap) => {
                let kind = trap_name(trap);
                let call = self.statement_call("binbun_trap", vec![vec![self.macro_name(kind)]]);
                simple(vec![self.line(call)])
            }
            Stmt::Unreachable => {
                let call = self.statement_call("binbun_unreachable", Vec::new());
                simple(vec![self.line(call)])
            }
            Stmt::Escape {
                kind,
                operands,
                results,
            } => simple(self.escape(kind, &operands, &results)?),
            Stmt::Try { body, handlers } => compound(self.try_statement(&body, &handlers)?),
            Stmt::VaStart { list } => simple(self.va_start(list)?),
        }
    }

    /// `va_start(list, last);`, `last` the last parameter; then
    /// `binbun_va_walk(list);` where the function reads the list by its
    /// fields ([`Self::walks`]), which makes the compiler's `va_start`
    /// fill all of it (`binbun_defs.h` says why).
    fn va_start(&mut self, list: Place) -> Result<Vec<Doc>, PrintError> {
        let f = self.f;
        let (Place::Var(list), Some(&named)) = (list, f.parameters.last()) else {
            return Err(error(
                self.node,
                "va_start without a variable and a parameter",
            ));
        };
        self.used.insert(list);
        let arguments = [list, named]
            .into_iter()
            .map(|id| vec![self.var(id)])
            .collect();
        let call = self.statement_call("va_start", arguments);
        let mut lines = vec![self.line(call)];
        if self.walks(list) {
            let walk = self.statement_call("binbun_va_walk", vec![vec![self.var(list)]]);
            lines.push(self.line(walk));
        }
        Ok(lines)
    }

    /// Whether the function reads or writes `va_list` `list` by its
    /// fields: a load or a store at its address or one bytes on from it
    /// (a `va_arg` the compiler expanded in place). Passing it on whole
    /// is no such access.
    fn walks(&self, list: VarId) -> bool {
        let f = self.f;
        let within = |address: ExprId| {
            let mut at = address;
            for _ in 0..4 {
                match f.expr(at) {
                    Some(&Expr::AddressOf(var)) => return var == list,
                    Some(&Expr::Binary(Binary::Add, base, _)) => at = base,
                    Some(_) | None => return false,
                }
            }
            false
        };
        let loads = f
            .exprs
            .iter()
            .any(|expr| matches!(expr, &Expr::Load { address, .. } if within(address)));
        let stores = f.stmts.iter().any(|stmt| {
            matches!(
                stmt,
                &Stmt::Assign {
                    place: Place::Memory { address, .. },
                    ..
                } if within(address)
            )
        });
        loads || stores
    }

    /// `name(arguments)` as statement tokens, `name` a macro.
    fn statement_call(&self, name: &str, arguments: Vec<Vec<Doc>>) -> Vec<Doc> {
        self.call_doc(vec![self.macro_name(name)], arguments, 0).0
    }

    /// For L0's check of a 64-bit address `p` as L2 keeps it, `if
    /// (sext(extract(p, 0, 48)) != p) trap;` (either operand order) with
    /// a `Protection` or `Stack` trap alone in the arm and no `else`:
    /// `binbun_defs.h`'s macro saying it (`binbun_check_canonical`,
    /// `binbun_check_canonical_stack`) and `p`.
    fn canonical_check(
        &self,
        condition: ExprId,
        then: &Block,
        otherwise: &Block,
    ) -> Option<(&'static str, ExprId)> {
        let ([trap], []) = (then.as_slice(), otherwise.as_slice()) else {
            return None;
        };
        let &Stmt::Trap(trap) = self.f.stmt(*trap)? else {
            return None;
        };
        let name = if trap == Trap::Protection {
            "binbun_check_canonical"
        } else if trap == Trap::Stack {
            "binbun_check_canonical_stack"
        } else {
            return None;
        };
        let &Expr::Binary(Binary::Ne, a, b) = self.f.expr(condition)? else {
            return None;
        };
        let address = self
            .canonical_operand(a, b)
            .or_else(|| self.canonical_operand(b, a))?;
        Some((name, address))
    }

    /// `other` if `extended` is `sext(extract(other, 0, 48), 64)`, the two
    /// copies of `other` the same tree.
    fn canonical_operand(&self, extended: ExprId, other: ExprId) -> Option<ExprId> {
        let &Expr::Extend {
            signed: true,
            value,
            width: 64,
        } = self.f.expr(extended)?
        else {
            return None;
        };
        let &Expr::Extract {
            value,
            offset: 0,
            width: 48,
        } = self.f.expr(value)?
        else {
            return None;
        };
        (self.width(other) == 64 && same_tree(self.f, value, other)).then_some(other)
    }

    /// `name(address);` ([`Printer::canonical_check`]): `address` as it is,
    /// any integer or pointer (the macro takes its 64 bits), or the bits of
    /// a float or an aggregate.
    fn canonical_statement(&mut self, name: &str, address: ExprId) -> Result<Doc, PrintError> {
        let value = self.expr(address)?;
        let value = match value.ty {
            CTy::Float(_) | CTy::Other(_) | CTy::Vector(_) => self.int_view(value)?,
            CTy::Int { .. } | CTy::Bool | CTy::Bytes | CTy::Pointer(_) | CTy::Code(_) => value,
        };
        let call = self.statement_call(name, vec![value.doc]);
        Ok(self.line(call))
    }

    /// `break;`, `continue;`, or the `goto` that stands for one.
    fn jump(&mut self, target: StmtId, exit: bool) -> Result<Doc, PrintError> {
        let innermost = if exit {
            self.breakable.last().copied()
        } else {
            let f = self.f;
            self.breakable
                .iter()
                .rev()
                .copied()
                .find(|&id| f.stmt(id).is_some_and(Stmt::is_loop))
        };
        if innermost == Some(target) && (exit || !self.late_steps.contains(&target)) {
            return Ok(self.line(vec![self.keyword(if exit { "break" } else { "continue" })]));
        }
        let labels = if exit {
            &self.break_labels
        } else {
            &self.continue_labels
        };
        let name = labels.get(&target).cloned().ok_or_else(|| {
            error(
                self.node,
                "break or continue to a statement that does not enclose it",
            )
        })?;
        self.counts.gotos += 1;
        Ok(self.line(vec![
            self.keyword("goto"),
            Doc::Space,
            Doc::name(TokenKind::Label, name, true, self.node),
        ]))
    }

    /// `place = value` (or `x += k`, `x++`, or a segment intrinsic's
    /// write at the thread pointer) tokens.
    fn assignment(&mut self, place: &Place, value: ExprId) -> Result<Vec<Doc>, PrintError> {
        if let Place::Var(var) = *place
            && let Some(tokens) = self.compound(var, value)?
        {
            return Ok(tokens);
        }
        if let Some(tokens) = self.segment_store(place, value)? {
            return Ok(tokens);
        }
        let host_va_list = self.host_va_list(value);
        let value = self.expr(value)?;
        let (lhs, ty) = self.place(place)?;
        let value = self.host_va_list_to(value, ty, host_va_list)?;
        self.store(lhs, ty, value)
    }

    /// Whether `expr` reads Microsoft's `va_list` (a pointer in L2, not
    /// System V's array): the C output declares it as the compiler's
    /// `va_list`, which on a System V host converts to `void *` only.
    fn host_va_list(&self, expr: ExprId) -> bool {
        let Some(&Expr::Var(var)) = self.f.expr(expr) else {
            return false;
        };
        self.f.va_list() == Some(var)
            && self.f.var(var).is_some_and(|variable| {
                matches!(self.types.get(variable.ty), Some(Type::Pointer(_)))
            })
    }

    /// The type of variable `var`.
    fn var_type(&self, var: VarId) -> Result<TypeId, PrintError> {
        self.f
            .var(var)
            .map(|variable| variable.ty)
            .ok_or_else(|| error(Some(Node::Var(var)), "no such variable"))
    }

    /// The lines of assignment statement `id` of `value` to `place`:
    /// `T v = e;` where it declares `v` ([`Printer::initializes`]), else
    /// a store (or the stores of a wide one).
    fn assign_statement(
        &mut self,
        id: StmtId,
        place: &Place,
        value: ExprId,
    ) -> Result<Vec<Doc>, PrintError> {
        if let Some(var) = self.initializes(id) {
            let host_va_list = self.host_va_list(value);
            let value = self.expr(value)?;
            let ty = self.var_type(var)?;
            let value = self.host_va_list_to(value, ty, host_va_list)?;
            let tokens = self.initialized(var, value)?;
            return Ok(vec![self.line(tokens)]);
        }
        if let Some(lines) = self.wide_store(place, value)? {
            return Ok(lines);
        }
        let tokens = self.assignment(place, value)?;
        Ok(vec![self.line(tokens)])
    }

    /// `T v = value` tokens: local `var` declared as `value` (converted to
    /// its type, as an assignment converts it) initializes it
    /// ([`Printer::initializes`]).
    fn initialized(&mut self, var: VarId, value: Value) -> Result<Vec<Doc>, PrintError> {
        let ty = self.var_type(var)?;
        let value = self.converted(value, ty)?;
        self.used.insert(var);
        self.declared_in_body.insert(var);
        let mut tokens = self.declare(ty, vec![self.var(var)])?;
        tokens.extend([Doc::Space, Doc::op("=", self.node), Doc::Space]);
        tokens.extend(value.doc);
        Ok(tokens)
    }

    /// A store wider than C's integers (over 128 bits) of a concatenation
    /// of 128-bit values (the lanes of an instruction without semantics'
    /// vector output), all without loads or calls, to an address computed
    /// without them: one store for each 128 bits, the low bits at the
    /// lowest address (both targets are little-endian). `None` for any
    /// other store.
    fn wide_store(&mut self, place: &Place, value: ExprId) -> Result<Option<Vec<Doc>>, PrintError> {
        let Place::Memory { address, ty } = *place else {
            return Ok(None);
        };
        if self.type_width(ty)? <= 128 || !pure(self.f, address) || !pure(self.f, value) {
            return Ok(None);
        }
        let Shape::Load {
            base,
            index,
            scale,
            offset,
        } = self.address_shape(address)
        else {
            return Ok(None);
        };
        // The 128-bit lanes, low first.
        let mut lanes = Vec::new();
        let mut work = vec![value];
        while let Some(id) = work.pop() {
            match self.f.expr(id) {
                _ if self.width(id) == 128 => lanes.push(id),
                Some(&Expr::Concat { high, low }) if self.width(id) > 128 => {
                    work.extend([high, low]);
                }
                _ => return Ok(None),
            }
        }
        let lane_ty = self.types.intern(Type::Bits(128));
        let mut stores = Vec::with_capacity(lanes.len());
        for (lane, at) in lanes.into_iter().zip((0..).step_by(16)) {
            let storing = core::mem::replace(&mut self.storing, true);
            let target = self.expr(base);
            self.storing = storing;
            let target = target?;
            let bounds = self.bounds(index);
            let index = match index {
                Some(index) => Some((self.expr(index)?, scale)),
                None => None,
            };
            let storing = core::mem::replace(&mut self.storing, true);
            let lhs = self.deref(target, (index, bounds), offset + at, lane_ty, false);
            self.storing = storing;
            let (lhs, held) = lhs?;
            let value = self.expr(lane)?;
            let tokens = self.store(lhs, held, value)?;
            stores.push(self.line(tokens));
        }
        Ok(Some(stores))
    }

    /// `value`, Microsoft's `va_list` where `host_va_list`
    /// ([`Self::host_va_list`]), cast to `ty` where that is a pointer to a
    /// known type (to `void *` C converts it itself).
    fn host_va_list_to(
        &mut self,
        value: Value,
        ty: TypeId,
        host_va_list: bool,
    ) -> Result<Value, PrintError> {
        if !host_va_list {
            return Ok(value);
        }
        let target = self.cty(ty)?;
        let typed = target.is_pointer() && !matches!(self.pointee(target), Some((None, _)));
        Ok(if typed {
            self.cast(value, target)
        } else {
            value
        })
    }

    /// `lhs = value`, `value` converted to `lhs`'s L2 type `ty`.
    pub(super) fn store(
        &mut self,
        lhs: Value,
        ty: TypeId,
        value: Value,
    ) -> Result<Vec<Doc>, PrintError> {
        let (lhs, value) =
            if matches!(lhs.ty, CTy::Other(_)) && (value.ty != lhs.ty || self.is_array(ty)) {
                let lhs = self.pun(lhs)?;
                let value = if let CTy::Vector(vector) = lhs.ty {
                    self.vector_view(value, vector)?
                } else {
                    let value = self.int_view(value)?;
                    self.coerce(value, Class::Low)?
                };
                (lhs, value)
            } else {
                let value = self.converted(value, ty)?;
                (lhs, value)
            };
        let mut tokens = self.operand(lhs, Op::Unary, false);
        tokens.extend([Doc::Space, Doc::op("=", self.node), Doc::Space]);
        tokens.extend(value.doc);
        Ok(tokens)
    }

    fn is_array(&self, ty: TypeId) -> bool {
        matches!(self.types.get(ty), Some(Type::Array { .. }))
    }

    /// `value` as C converts it on assignment to L2 type `ty` (not an
    /// aggregate), cast or made clean where that conversion would not
    /// give the same bits; a pointer to a struct converted to a pointer to
    /// its first member's type is that member's address instead
    /// ([`Self::first_member`]); a constant of an enumeration's type by
    /// its names ([`Self::by_name`]).
    pub(super) fn converted(&mut self, value: Value, ty: TypeId) -> Result<Value, PrintError> {
        let target = self.cty(ty)?;
        match target {
            CTy::Int { .. } | CTy::Bool => {
                let value = self.converted_integer(value, ty)?;
                if self.is_char(ty) {
                    return Ok(self.by_character(value));
                }
                Ok(self.by_name(value, ty, Context::Converted))
            }
            CTy::Float(format) => self.as_float(value, format),
            CTy::Pointer(_) | CTy::Code(_) | CTy::Bytes => {
                if value.ty.is_pointer() || matches!(value.ty, CTy::Code(_)) {
                    let void = |printer: &Self, ty: CTy| {
                        matches!(printer.pointee(ty), Some((None, _))) && ty != CTy::Bytes
                    };
                    let same = self.key(value.ty)? == self.key(target)?;
                    let data = value.ty.is_pointer() && target.is_pointer();
                    let either_void = void(self, value.ty) || void(self, target);
                    if convert::implicit_pointer(same, data, either_void) {
                        return Ok(value);
                    }
                    if data && let Some(member) = self.first_member(&value, target)? {
                        return Ok(member);
                    }
                    return Ok(self.cast(value, target));
                }
                if value.form().null() {
                    return Ok(value);
                }
                self.int_to_pointer(value, target)
            }
            CTy::Other(_) => {
                if value.ty == target {
                    Ok(value)
                } else {
                    Err(self.unsupported(self.node, "an aggregate assigned from another type"))
                }
            }
            CTy::Vector(vector) => self.vector_view(value, vector),
        }
    }

    /// `value` as C converts it on assignment to integer type `ty`
    /// ([`Self::converted`], [`convert::assigned`]).
    fn converted_integer(&mut self, value: Value, ty: TypeId) -> Result<Value, PrintError> {
        let value = self.int_view(value)?;
        let rep = self
            .int_rep(ty)
            .ok_or_else(|| error(self.node, "not an integer type"))?;
        let conversion = convert::assigned(value.form(), rep).map_err(|r| self.refused(r))?;
        Ok(self.apply(value, conversion))
    }

    /// `x op= b`, `x++`, `x--` for `x = x op b` on a variable of a native
    /// integer type (C computes those exactly).
    fn compound(&mut self, var: VarId, value: ExprId) -> Result<Option<Vec<Doc>>, PrintError> {
        let Some(&Expr::Binary(op, x, b)) = self.f.expr(value) else {
            return Ok(None);
        };
        let Some(variable) = self.f.var(var) else {
            return Ok(None);
        };
        let reads = matches!(self.f.expr(x), Some(&Expr::Var(read)) if read == var);
        let Some(rep) = self.int_rep(variable.ty) else {
            return Ok(None);
        };
        if !reads || rep.boolean || !native(rep.width) {
            return Ok(None);
        }
        let width = rep.width;
        let count = || match self.f.expr(b) {
            Some(Expr::Const(bits)) if bits.low_u128() < u128::from(width) => true,
            Some(_) | None => false,
        };
        let text = match op {
            Binary::Add => "+=",
            Binary::Sub => "-=",
            Binary::Mul => "*=",
            Binary::And => "&=",
            Binary::Or => "|=",
            Binary::Xor => "^=",
            Binary::Shl if count() => "<<=",
            Binary::LShr if count() && !rep.signed => ">>=",
            Binary::AShr if count() && rep.signed => ">>=",
            Binary::Shl
            | Binary::LShr
            | Binary::AShr
            | Binary::UDiv
            | Binary::URem
            | Binary::SDiv
            | Binary::SRem
            | Binary::Rol
            | Binary::Ror
            | Binary::Eq
            | Binary::Ne
            | Binary::ULt
            | Binary::ULe
            | Binary::SLt
            | Binary::SLe => return Ok(None),
        };
        let saved = self.node;
        self.node = Some(Node::Expr(value));
        let target = self.var_value(var)?;
        let operand = self.expr(b)?;
        let operand = self.int_view(operand)?;
        let mut text = text;
        let mut operand = operand;
        if let (Binary::Add | Binary::Sub, Some(bits)) = (op, operand.constant) {
            let (negative, magnitude) = constant_value(bits, Class::Sign);
            if magnitude == 1 {
                let increment = negative == (op == Binary::Sub);
                let mut tokens = target.doc;
                tokens.push(Doc::op(if increment { "++" } else { "--" }, self.node));
                self.node = saved;
                return Ok(Some(tokens));
            }
            if negative && magnitude < 1 << (width.min(32) - 1) {
                text = if op == Binary::Add { "-=" } else { "+=" };
                operand = self.constant(Bits::from_u128(width, magnitude), Class::Zero, false)?;
            }
        }
        let bitwise = matches!(op, Binary::And | Binary::Or | Binary::Xor);
        let operand = match operand.constant {
            Some(bits) if matches!(op, Binary::Shl | Binary::LShr | Binary::AShr) => {
                self.literal_number(u64::try_from(bits.low_u128()).unwrap_or(0), false)
            }
            Some(bits) => self.constant(
                bits,
                if rep.signed && !bitwise {
                    Class::Sign
                } else {
                    Class::Zero
                },
                bitwise,
            )?,
            None => operand,
        };
        let mut tokens = target.doc;
        tokens.extend([Doc::Space, Doc::op(text, self.node), Doc::Space]);
        tokens.extend(operand.doc);
        self.node = saved;
        Ok(Some(tokens))
    }

    fn return_statement(&mut self, value: Option<ExprId>) -> Result<Vec<Doc>, PrintError> {
        let Some(value) = value else {
            return Ok(vec![self.line(vec![self.keyword("return")])]);
        };
        let returns = self
            .f
            .returns
            .ok_or_else(|| error(self.node, "a value returned from a function returning none"))?;
        let value = self.expr(value)?;
        let mut out = Vec::new();
        let value =
            if matches!(self.cty(returns)?, CTy::Other(_)) && value.ty != self.cty(returns)? {
                let name = self.temp(returns);
                let temp = self.named(name, returns)?;
                let tokens = self.store(temp.clone(), returns, value)?;
                out.push(self.line(tokens));
                temp
            } else {
                self.converted(value, returns)?
            };
        let mut tokens = vec![self.keyword("return"), Doc::Space];
        tokens.extend(value.doc);
        out.push(self.line(tokens));
        Ok(out)
    }

    /// A temporary or other name of L2 type `ty` as an lvalue.
    pub(super) fn named(&mut self, name: String, ty: TypeId) -> Result<Value, PrintError> {
        let cty = self.cty(ty)?;
        let width = self.type_width(ty)?;
        let class = match self.int_rep(ty) {
            Some(rep) if rep.signed && !rep.boolean => Class::Sign,
            Some(_) => Class::Zero,
            None => Class::Low,
        };
        Ok(Value {
            doc: vec![self.temp_name(name)],
            op: Op::Postfix,
            ty: cty,
            class,
            width,
            constant: None,
            lvalue: true,
            loads: false,
            depth: 0,
            address_of: None,
            unsigned_literal: None,
        })
    }

    /// The statements of a call: `f(a);`, `x = f(a);` (`T x = f(a);` where
    /// it declares `x`, [`Self::distribute`]), or the result in a temporary
    /// split over the places.
    fn call(&mut self, results: &[Place], call: &Call) -> Result<Vec<Doc>, PrintError> {
        let mut operands = Vec::with_capacity(call.arguments.len() + 1);
        for operand in call.operands() {
            operands.push(self.expr(operand)?);
        }
        let (doc, value) = self.call_value(call, operands)?;
        let Some(value) = value.filter(|_| !results.is_empty()) else {
            return Ok(vec![self.line(doc)]);
        };
        let returns = self.returned(call)?;
        self.distribute(results, returns, value)
    }

    /// The return type of `call`'s signature, which has one.
    fn returned(&self, call: &Call) -> Result<TypeId, PrintError> {
        match self.types.get(call.signature) {
            Some(Type::Code(signature)) => signature
                .returns
                .ok_or_else(|| error(self.node, "a call's value, but it returns none")),
            Some(_) | None => Err(error(self.node, "a call's type is not a code type")),
        }
    }

    /// `call` as C, its operands' values given (a computed callee, then
    /// the arguments): the call's tokens, and its value if it returns one.
    pub(super) fn call_value(
        &mut self,
        call: &Call,
        operands: Vec<Value>,
    ) -> Result<(Vec<Doc>, Option<Value>), PrintError> {
        let signature = match self.types.get(call.signature) {
            Some(Type::Code(signature)) => signature.clone(),
            Some(_) | None => return Err(error(self.node, "a call's type is not a code type")),
        };
        let mut operands = operands.into_iter();
        let target = match call.callee {
            Callee::Address(_) | Callee::Import(_) => None,
            Callee::Expr(_) => Some(
                operands
                    .next()
                    .ok_or_else(|| error(self.node, "a call without its callee"))?,
            ),
        };
        let callee = self.callee(call, target)?;
        let mut arguments = Vec::with_capacity(call.arguments.len());
        let mut depth = 0;
        for (position, value) in operands.enumerate() {
            let stated = signature.parameters.get(position).or_else(|| {
                position
                    .checked_sub(signature.parameters.len())
                    .and_then(|index| call.variadic.get(index))
            });
            let host_va_list = call
                .arguments
                .get(position)
                .is_some_and(|&argument| self.host_va_list(argument));
            let value = match stated {
                Some(&ty) => {
                    let value = self.host_va_list_to(value, ty, host_va_list)?;
                    self.converted(value, ty)?
                }
                None => self.variadic(value)?,
            };
            depth = depth.max(value.depth);
            arguments.push(value.doc);
        }
        let (doc, depth) = self.call_doc(callee, arguments, depth);
        let Some(returns) = signature.returns else {
            return Ok((doc, None));
        };
        let mut value = self.named(String::new(), returns)?;
        value.doc.clone_from(&doc);
        value.lvalue = false;
        // A call reads memory and may have effects: evaluated exactly
        // when L2 evaluates it.
        value.loads = true;
        value.depth = depth;
        Ok((doc, Some(value)))
    }

    /// The result `value` (of L2 type `ty`) of the statement being printed
    /// stored to `results`: whole (`T v = f(a);` where the statement
    /// declares the one variable, [`Printer::initializes`]), or through a
    /// temporary in parts, low bits first. A struct or union that is not
    /// the one place's own type goes through the temporary too: C reads
    /// the bits of one in memory only ([`Self::pun`]).
    pub(super) fn distribute(
        &mut self,
        results: &[Place],
        ty: TypeId,
        value: Value,
    ) -> Result<Vec<Doc>, PrintError> {
        let whole = match (results, value.ty) {
            ([place], CTy::Other(_)) => self.place(place)?.0.ty == value.ty,
            _ => true,
        };
        if whole
            && let (&[Place::Var(var)], Some(Node::Stmt(id))) = (results, self.node)
            && self.initializes(id) == Some(var)
        {
            let tokens = self.initialized(var, value)?;
            return Ok(vec![self.line(tokens)]);
        }
        if whole && let [place] = results {
            let (lhs, place_ty) = self.place(place)?;
            let tokens = self.store(lhs, place_ty, value)?;
            return Ok(vec![self.line(tokens)]);
        }
        let name = self.temp(ty);
        let temp = self.named(name, ty)?;
        let first = self.store(temp.clone(), ty, value)?;
        let mut out = vec![self.line(first)];
        let mut offset = 0;
        for place in results {
            let (lhs, place_ty) = self.place(place)?;
            let width = self.type_width(place_ty)?;
            let whole = self.int_view(temp.clone())?;
            let part = self.part(whole, offset, width)?;
            let tokens = self.store(lhs, place_ty, part)?;
            out.push(self.line(tokens));
            offset += width;
        }
        Ok(out)
    }

    /// Bits `offset..offset + width` of `value`.
    fn part(&mut self, value: Value, offset: u16, width: u16) -> Result<Value, PrintError> {
        if offset == 0 {
            let mut part = value.with_width(width);
            part.class = Class::Low;
            return Ok(part);
        }
        let source = value.width;
        let mut part = self.shift_by(Shift::Logical, value, offset, source)?;
        part.width = width;
        part.class = Class::Low;
        Ok(part)
    }

    /// An argument past a variadic signature's parameters: of the
    /// promoted type of its width.
    fn variadic(&mut self, value: Value) -> Result<Value, PrintError> {
        if matches!(value.ty, CTy::Float(_)) || value.ty.is_pointer() {
            return Ok(value);
        }
        let value = self.int_view(value)?;
        let bits = container(value.width).unwrap_or(128).max(32);
        if value.form().promoted().is_some_and(|ty| ty.1 == bits) {
            return Ok(value);
        }
        let signed = value.form().is(Class::Sign) && !value.form().is(Class::Zero);
        Ok(self.exact(value, signed, bits))
    }

    /// What a call calls: a function by name (one name per address and
    /// signature, named before printing), or a code pointer (`target`, its
    /// value).
    fn callee(&mut self, call: &Call, target: Option<Value>) -> Result<Vec<Doc>, PrintError> {
        let node = self.node;
        match (call.callee, target) {
            (Callee::Address(address), _) => {
                let (name, automatic) = match self.callees.get(&(address, call.signature)) {
                    Some(callee) => (callee.name.clone(), callee.automatic),
                    None if address == self.f.address => {
                        (self.function_name.clone(), self.function_automatic)
                    }
                    None => return Err(error(node, "a callee not named")),
                };
                Ok(vec![Doc::name(TokenKind::Function, name, automatic, node)])
            }
            (Callee::Import(slot), _) => {
                let callee = self
                    .imports
                    .get(&(slot, call.signature))
                    .ok_or_else(|| error(node, "an import not named"))?;
                Ok(vec![Doc::name(
                    TokenKind::Function,
                    callee.name.clone(),
                    callee.automatic,
                    node,
                )])
            }
            (Callee::Expr(_), None) => Err(error(node, "a call without its callee")),
            (Callee::Expr(_), Some(value)) => {
                let target = CTy::Code(call.signature);
                if matches!(value.ty, CTy::Code(_)) && self.key(value.ty)? == self.key(target)? {
                    return Ok(self.operand(value, Op::Postfix, false));
                }
                let cast = if value.ty.is_pointer() || matches!(value.ty, CTy::Code(_)) {
                    self.cast(value, target)
                } else {
                    self.int_to_pointer(value, target)?
                };
                Ok(self.operand(cast, Op::Postfix, false))
            }
        }
    }

    /// The statements of an intrinsic: `x = name(a);`, or outputs through
    /// pointers to temporaries.
    fn intrinsic(
        &mut self,
        results: &[Place],
        id: IntrinsicId,
        inputs: &[ExprId],
    ) -> Result<Vec<Doc>, PrintError> {
        let info = *self
            .declarations
            .intrinsic(id)
            .ok_or_else(|| error(self.node, "an intrinsic not declared"))?;
        if info.opaque {
            return match (self.opaque, self.node) {
                (Opaque::Asm, Some(Node::Stmt(stmt))) => self.asm_block(&[stmt]),
                (Opaque::Asm | Opaque::Calls, _) => self.unlifted_call(results),
            };
        }
        let name = if let Some(intrinsic) = self.intrinsics.get(&id.0) {
            intrinsic.name.clone()
        } else {
            let name = self.names.fresh(info.name);
            self.intrinsics
                .insert(id.0, Intrinsic { name: name.clone() });
            name
        };
        let mut arguments = Vec::new();
        for &input in inputs {
            let value = self.expr(input)?;
            let value = self.int_view(value)?;
            let value = if native(value.width) {
                self.arg(value, false)?
            } else {
                self.coerce(value, Class::Zero)?
            };
            arguments.push(value.doc);
        }
        let mut temps = Vec::new();
        if info.outputs.len() > 1 {
            for &width in info.outputs {
                let ty = self.uint_type(width)?;
                let temp = self.temp(ty);
                arguments.push(vec![Doc::op("&", self.node), self.temp_name(temp.clone())]);
                temps.push((temp, ty));
            }
        }
        let function = Doc::token(TokenKind::Function, name, self.node);
        let (doc, _) = self.call_doc(vec![function], arguments, 0);
        if info.outputs.len() == 1 && !results.is_empty() {
            let ty = self.uint_type(info.outputs.first().copied().unwrap_or(64))?;
            let mut value = self.named(String::new(), ty)?;
            value.doc = doc;
            value.lvalue = false;
            return self.distribute(results, ty, value);
        }
        let mut out = vec![self.line(doc)];
        for (place, (temp, ty)) in results.iter().zip(temps) {
            let (lhs, place_ty) = self.place(place)?;
            let value = self.named(temp, ty)?;
            let tokens = self.store(lhs, place_ty, value)?;
            out.push(self.line(tokens));
        }
        Ok(out)
    }

    /// The L2 type of an unsigned integer of `width` bits (held in its
    /// container).
    fn uint_type(&mut self, width: u16) -> Result<TypeId, PrintError> {
        if width > 128 {
            return Err(self.unsupported(self.node, "intrinsic values over 128 bits"));
        }
        Ok(self.types.intern(Type::UInt(width)))
    }

    /// The prototype of a callee: `int name(int, char *)`, `name` its
    /// name's token.
    pub(super) fn prototype(
        &mut self,
        name: Doc,
        signature: TypeId,
    ) -> Result<Vec<Doc>, PrintError> {
        let Some(Type::Code(signature)) = self.types.get(signature).cloned() else {
            return Err(error(Some(Node::Type(signature)), "not a code type"));
        };
        let mut inner = vec![name];
        inner.extend(self.parameters(&signature.parameters, signature.variadic)?);
        match signature.returns {
            Some(returns) => self.declare(returns, inner),
            None => Ok(with_specifier(
                vec![Doc::token(TokenKind::BuiltinType, "void", None)],
                inner,
            )),
        }
    }

    /// The prototype of an intrinsic: its inputs, then a pointer per
    /// output if it has several, else its output as the return value.
    pub(super) fn intrinsic_prototype(
        &mut self,
        id: u16,
        name: &str,
    ) -> Result<Vec<Doc>, PrintError> {
        let info = *self
            .declarations
            .intrinsic(IntrinsicId(id))
            .ok_or_else(|| error(None, "an intrinsic not declared"))?;
        let mut parameters = Vec::new();
        for &width in info.inputs {
            parameters.push(self.uint_type(width)?);
        }
        if info.outputs.len() > 1 {
            for &width in info.outputs {
                let ty = self.uint_type(width)?;
                parameters.push(self.pointer_type(ty));
            }
        }
        let mut inner = vec![Doc::token(TokenKind::Function, name, None)];
        inner.extend(self.parameters(&parameters, false)?);
        match info.outputs {
            [width] => {
                let ty = self.uint_type(*width)?;
                self.declare(ty, inner)
            }
            _ => Ok(with_specifier(
                vec![Doc::token(TokenKind::BuiltinType, "void", None)],
                inner,
            )),
        }
    }

    /// Whether a `for` step statement can be said in the loop's header
    /// (as one expression).
    pub(super) fn expressible(&self, id: StmtId) -> bool {
        match self.f.stmt(id) {
            Some(Stmt::Assign { .. } | Stmt::Expr(_)) => true,
            Some(Stmt::Call { results, .. }) => results.len() <= 1,
            Some(
                stmt @ Stmt::Intrinsic {
                    results, intrinsic, ..
                },
            ) => {
                results.len() <= 1
                    && !is_unlifted(stmt, self.declarations)
                    && self
                        .declarations
                        .intrinsic(*intrinsic)
                        .is_some_and(|info| info.outputs.len() <= 1)
            }
            Some(_) | None => false,
        }
    }

    /// An escape: a `binbun_defs.h` helper with its operands' values.
    fn escape(
        &mut self,
        kind: Escape,
        operands: &[ExprId],
        results: &[Place],
    ) -> Result<Vec<Doc>, PrintError> {
        // C says an atomic update: no escape.
        if let Escape::Update(update) = kind {
            return self.update(update, operands, results);
        }
        self.counts.escapes += 1;
        if kind == Escape::Atomic {
            return self.atomic(operands, results);
        }
        let mut arguments = Vec::new();
        for &operand in operands {
            let value = self.expr(operand)?;
            let value = self.int_view(value)?;
            if value.width > 64 {
                return Err(self.unsupported(self.node, "escape operands over 64 bits"));
            }
            arguments.push(self.coerce(value, Class::Zero)?.doc);
        }
        let name = match kind {
            Escape::UnresolvedJump => "binbun_unresolved_jump",
            Escape::ForeignJump => "binbun_foreign_jump",
            Escape::OverlappingCode => "binbun_overlapping_code",
            Escape::NonStandardCall => "binbun_non_standard_call",
            Escape::StackTrick => "binbun_stack_trick",
            Escape::SystemCall | Escape::Atomic | Escape::Update(_) => "binbun_syscall",
        };
        let doc = self.statement_call(name, arguments);
        let Some((first, rest)) = results.split_first() else {
            return Ok(vec![self.line(doc)]);
        };
        let mut out = Vec::new();
        let ty = self.uint_type(64)?;
        let mut value = self.named(String::new(), ty)?;
        value.doc = doc;
        value.lvalue = false;
        for (index, place) in core::iter::once(first).chain(rest).enumerate() {
            let (lhs, place_ty) = self.place(place)?;
            let width = self.type_width(place_ty)?;
            if width > 64 {
                return Err(self.unsupported(self.node, "escape results over 64 bits"));
            }
            let source = if index == 0 {
                value.clone()
            } else {
                let mut result = value.clone();
                result.doc = self.statement_call(
                    "binbun_result",
                    vec![vec![Doc::number(format!("{index}"), self.node)]],
                );
                result
            };
            let mut source = source.with_width(width);
            source.class = Class::Low;
            let tokens = self.store(lhs, place_ty, source)?;
            out.push(self.line(tokens));
        }
        Ok(out)
    }

    /// An atomic access: `x = binbun_atomic_load32(p);`,
    /// `binbun_atomic_store32(p, v);`.
    fn atomic(&mut self, operands: &[ExprId], results: &[Place]) -> Result<Vec<Doc>, PrintError> {
        let (&address, value) = operands
            .split_first()
            .ok_or_else(|| error(self.node, "an atomic access without an address"))?;
        let address = self.atomic_address(address)?;
        match (value, results) {
            ([], [place]) => {
                let (lhs, place_ty) = self.place(place)?;
                let width = self.type_width(place_ty)?;
                if !native(width) {
                    return Err(
                        self.unsupported(self.node, "atomic accesses of 3, 5, 6 or 7 bytes")
                    );
                }
                let name = format!("binbun_atomic_load{width}");
                let value = self.helper(
                    &name,
                    vec![address],
                    CTy::Int {
                        signed: false,
                        bits: width,
                    },
                    Class::Zero,
                    width,
                );
                let tokens = self.store(lhs, place_ty, value)?;
                Ok(vec![self.line(tokens)])
            }
            ([value], []) => {
                let value = self.expr(*value)?;
                let value = self.int_view(value)?;
                let width = value.width;
                if !native(width) {
                    return Err(
                        self.unsupported(self.node, "atomic accesses of 3, 5, 6 or 7 bytes")
                    );
                }
                let value = self.arg(value, false)?;
                let name = format!("binbun_atomic_store{width}");
                let doc = self.statement_call(&name, vec![address.doc, value.doc]);
                Ok(vec![self.line(doc)])
            }
            _ => Err(error(
                self.node,
                "an atomic access is a load with one result or a store without",
            )),
        }
    }

    /// The address of an atomic access, as a pointer.
    fn atomic_address(&mut self, address: ExprId) -> Result<Value, PrintError> {
        let address = self.expr(address)?;
        if address.ty.is_pointer() {
            return Ok(address);
        }
        let void = self.types.intern(Type::Pointer(None));
        self.int_to_pointer(address, CTy::Pointer(void))
    }

    /// An atomic update, by `binbun_defs.h`'s helper of its width over the
    /// compilers' `__atomic` builtins (sequentially consistent, as a
    /// locked instruction is), which gives the value read:
    /// `x = binbun_atomic_fetch_add32(p, v);`,
    /// `binbun_atomic_exchange64(p, v);`,
    /// `x = binbun_atomic_compare_exchange32(p, expected, desired);`.
    fn update(
        &mut self,
        update: Update,
        operands: &[ExprId],
        results: &[Place],
    ) -> Result<Vec<Doc>, PrintError> {
        let (&address, values) = operands
            .split_first()
            .ok_or_else(|| error(self.node, "an atomic update without an address"))?;
        let mut arguments = vec![self.atomic_address(address)?];
        let mut width = 0;
        for &value in values {
            let value = self.expr(value)?;
            let value = self.int_view(value)?;
            width = value.width;
            if !native(width) {
                return Err(self.unsupported(self.node, "atomic accesses of 3, 5, 6 or 7 bytes"));
            }
            arguments.push(self.arg(value, false)?);
        }
        let stem = match update {
            Update::Exchange => "exchange",
            Update::Add => "fetch_add",
            Update::Sub => "fetch_sub",
            Update::And => "fetch_and",
            Update::Or => "fetch_or",
            Update::Xor => "fetch_xor",
            Update::CompareExchange => "compare_exchange",
        };
        let name = format!("binbun_atomic_{stem}{width}");
        match results {
            [] => {
                let arguments = arguments.into_iter().map(|value| value.doc).collect();
                let doc = self.statement_call(&name, arguments);
                Ok(vec![self.line(doc)])
            }
            [place] => {
                let ty = CTy::Int {
                    signed: false,
                    bits: width,
                };
                let value = self.helper(&name, arguments, ty, Class::Zero, width);
                let (lhs, place_ty) = self.place(place)?;
                let tokens = self.store(lhs, place_ty, value)?;
                Ok(vec![self.line(tokens)])
            }
            _ => Err(error(self.node, "an atomic update with several results")),
        }
    }

    /// A condition's tokens (negated: `negate`).
    fn condition(&mut self, id: ExprId, negate: bool) -> Result<Vec<Doc>, PrintError> {
        let saved = self.node;
        let expr = self.f.expr(id).copied();
        let doc = match expr {
            Some(Expr::Binary(
                op @ (Binary::Eq
                | Binary::Ne
                | Binary::ULt
                | Binary::ULe
                | Binary::SLt
                | Binary::SLe),
                a,
                b,
            )) if negate => {
                let spelling = self.spelling(a, b);
                let (a, b) = (self.expr(a)?, self.expr(b)?);
                self.node = Some(Node::Expr(id));
                let value = self.compare(op, a, b, true, spelling);
                self.node = saved;
                value?.doc
            }
            Some(Expr::Unary(Unary::Not, inner)) if negate && self.width(inner) == 1 => {
                let value = self.expr(inner)?;
                self.truthy(value)?.doc
            }
            _ => {
                let value = self.expr(id)?;
                let value = self.truthy(value)?;
                if negate {
                    let mut doc = vec![Doc::op("!", Some(Node::Expr(id)))];
                    doc.extend(self.operand(value, Op::Unary, false));
                    doc
                } else {
                    value.doc
                }
            }
        };
        Ok(doc)
    }

    /// `keyword (condition)`.
    fn header(
        &mut self,
        keyword: &str,
        condition: ExprId,
        negate: bool,
    ) -> Result<Doc, PrintError> {
        let condition = self.condition(condition, negate)?;
        let mut doc = vec![
            self.keyword(keyword),
            Doc::Space,
            Doc::punct("(", self.node),
        ];
        doc.push(Doc::Nest(condition));
        doc.push(Doc::punct(")", self.node));
        Ok(Doc::Group(doc))
    }

    /// A statement's braced body.
    fn body(&mut self, block: &Block, extra: Vec<Doc>) -> Result<Doc, PrintError> {
        let mut items = self.items(block)?;
        let mut label_last = items.label_last;
        if !extra.is_empty() {
            items.simple = false;
            label_last = matches!(extra.last(), Some(Doc::Outdent(_)));
            items.docs.extend(extra);
        }
        if label_last {
            items.docs.push(Doc::Group(vec![Doc::punct(";", None)]));
            items.simple = false;
        }
        Ok(Doc::Block {
            kind: BlockKind::Statement,
            braces: if items.simple {
                Braces::Optional
            } else {
                Braces::Required
            },
            body: items.docs,
            node: self.node,
        })
    }

    fn if_statement(
        &mut self,
        condition: ExprId,
        then: &Block,
        otherwise: &Block,
    ) -> Result<Doc, PrintError> {
        let negate = then.is_empty() && !otherwise.is_empty();
        let (then, otherwise) = if negate {
            (otherwise, then)
        } else {
            (then, otherwise)
        };
        let mut docs = vec![self.header("if", condition, negate)?];
        docs.push(self.body(then, Vec::new())?);
        if !otherwise.is_empty() {
            docs.push(Doc::AfterBlock);
            docs.push(self.keyword("else"));
            let chained = match otherwise.as_slice() {
                [only] => match self.f.stmt(*only) {
                    Some(Stmt::If {
                        condition,
                        then,
                        otherwise,
                    }) if !self.break_labels.contains_key(only)
                        && !self.scoped.contains_key(only)
                        && self.canonical_check(*condition, then, otherwise).is_none() =>
                    {
                        Some((*only, *condition, then.clone(), otherwise.clone()))
                    }
                    Some(_) | None => None,
                },
                _ => None,
            };
            if let Some((id, condition, then, otherwise)) = chained {
                let saved = self.node;
                self.node = Some(Node::Stmt(id));
                self.nesting += 1;
                let nested = self.if_statement(condition, &then, &otherwise);
                self.nesting -= 1;
                self.node = saved;
                docs.push(Doc::Space);
                docs.push(nested?);
            } else {
                docs.push(self.body(otherwise, Vec::new())?);
            }
        }
        Ok(Doc::Group(docs))
    }

    /// `BINBUN_TRY { … } BINBUN_CATCH(type) { … } …` (`binbun_defs.h`'s
    /// macros: the body runs, the handlers never do); `BINBUN_SEH_TRY {
    /// … } BINBUN_EXCEPT(filter) { … }` when every handler is an
    /// `__except` or a `__finally` block's (`BINBUN_FINALLY`).
    fn try_statement(&mut self, body: &Block, handlers: &[Handler]) -> Result<Doc, PrintError> {
        let seh = handlers
            .iter()
            .all(|handler| matches!(handler.kind, HandlerKind::Except(_) | HandlerKind::Finally));
        let head = if seh { "BINBUN_SEH_TRY" } else { "BINBUN_TRY" };
        let mut docs = vec![self.macro_name(head), self.braced(body)?];
        for handler in handlers {
            docs.push(Doc::AfterBlock);
            if let HandlerKind::Except(filter) = handler.kind {
                let (name, argument) = match filter {
                    SehFilter::Constant(value) => ("BINBUN_EXCEPT", format!("{value}")),
                    SehFilter::Funclet(funclet) => {
                        ("BINBUN_EXCEPT_FUNCLET", format!("{funclet:#x}"))
                    }
                };
                docs.push(Doc::Group(vec![
                    self.macro_name(name),
                    Doc::punct("(", self.node),
                    Doc::number(argument, self.node),
                    Doc::punct(")", self.node),
                ]));
                docs.push(self.braced(&handler.body)?);
                continue;
            }
            let (name, types) = match &handler.kind {
                HandlerKind::Landing(_) => ("BINBUN_LANDING", None),
                HandlerKind::Catch(ty) => ("BINBUN_CATCH", Some(core::slice::from_ref(ty))),
                HandlerKind::CatchAll => ("BINBUN_CATCH_ALL", None),
                HandlerKind::Cleanup => ("BINBUN_CLEANUP", None),
                HandlerKind::Unexpected(types) => ("BINBUN_UNEXPECTED", Some(types.as_slice())),
                HandlerKind::Finally => ("BINBUN_FINALLY", None),
                HandlerKind::Except(_) => continue,
            };
            let mut header = vec![self.macro_name(name)];
            if let Some(types) = types {
                header.push(Doc::punct("(", self.node));
                for (position, ty) in types.iter().enumerate() {
                    if position > 0 {
                        header.push(Doc::punct(",", self.node));
                        header.push(Doc::Space);
                    }
                    header.push(Doc::token(TokenKind::Type, catch_type(ty), self.node));
                }
                header.push(Doc::punct(")", self.node));
            }
            docs.push(Doc::Group(header));
            docs.push(self.braced(&handler.body)?);
        }
        Ok(Doc::Group(docs))
    }

    /// A statement's body, always in braces.
    fn braced(&mut self, block: &Block) -> Result<Doc, PrintError> {
        let mut body = self.body(block, Vec::new())?;
        if let Doc::Block { braces, .. } = &mut body {
            *braces = Braces::Required;
        }
        Ok(body)
    }

    /// The label at the end of a loop body that a `continue` by `goto`
    /// reaches.
    fn continue_label(&self, id: StmtId) -> Vec<Doc> {
        self.continue_labels
            .get(&id)
            .map(|name| vec![self.label(name.clone())])
            .unwrap_or_default()
    }

    fn while_loop(
        &mut self,
        id: StmtId,
        condition: ExprId,
        body: &Block,
    ) -> Result<Doc, PrintError> {
        let header = self.header("while", condition, false)?;
        self.breakable.push(id);
        let extra = self.continue_label(id);
        let body = self.body(body, extra);
        self.breakable.pop();
        Ok(Doc::Group(vec![header, body?]))
    }

    fn do_loop(&mut self, id: StmtId, body: &Block, condition: ExprId) -> Result<Doc, PrintError> {
        self.breakable.push(id);
        let extra = self.continue_label(id);
        let body = self.body(body, extra);
        self.breakable.pop();
        let mut body = body?;
        if let Doc::Block { braces, .. } = &mut body {
            *braces = Braces::Required;
        }
        let header = self.header("while", condition, false)?;
        Ok(Doc::Group(vec![
            self.keyword("do"),
            body,
            Doc::AfterBlock,
            header,
            Doc::punct(";", self.node),
        ]))
    }

    /// A `for` loop: init and step in the header when they are
    /// expressions, else before the loop and at the end of its body.
    fn for_loop(
        &mut self,
        id: StmtId,
        init: &Block,
        condition: ExprId,
        step: &Block,
        body: &Block,
    ) -> Result<Vec<Doc>, PrintError> {
        let late = self.late_steps.contains(&id);
        let mut out = Vec::new();
        let init_inline = init.iter().all(|&s| self.expressible(s));
        let init_tokens = if init_inline {
            self.expression_list(init)?
        } else {
            out.extend(self.block(init)?);
            Vec::new()
        };
        let step_tokens = if late {
            Vec::new()
        } else {
            self.expression_list(step)?
        };
        let mut extra = self.continue_label(id);
        if late {
            extra.extend(self.block(step)?);
        }
        let header = if init_tokens.is_empty() && step_tokens.is_empty() {
            self.header("while", condition, false)?
        } else {
            let condition = self.condition(condition, false)?;
            let mut doc = vec![self.keyword("for"), Doc::Space, Doc::punct("(", self.node)];
            let mut inner = init_tokens;
            inner.push(Doc::punct(";", self.node));
            inner.push(Doc::Line);
            inner.extend(condition);
            inner.push(Doc::punct(";", self.node));
            if !step_tokens.is_empty() {
                inner.push(Doc::Line);
                inner.extend(step_tokens);
            }
            doc.push(Doc::Nest(inner));
            doc.push(Doc::punct(")", self.node));
            Doc::Group(doc)
        };
        self.breakable.push(id);
        let body = self.body(body, extra);
        self.breakable.pop();
        out.push(Doc::Group(vec![header, body?]));
        Ok(out)
    }

    /// Statements as one comma expression (for a `for` header).
    fn expression_list(&mut self, block: &Block) -> Result<Vec<Doc>, PrintError> {
        let mut out = Vec::new();
        for &id in block {
            let saved = self.node;
            self.node = Some(Node::Stmt(id));
            let docs = self.statement(id);
            self.node = saved;
            for doc in docs?.0 {
                if !out.is_empty() {
                    out.push(Doc::punct(",", self.node));
                    out.push(Doc::Line);
                }
                out.extend(strip_semicolon(doc));
            }
        }
        Ok(out)
    }

    fn switch(&mut self, id: StmtId, scrutinee: ExprId, arms: &[Arm]) -> Result<Doc, PrintError> {
        let value = self.expr(scrutinee)?;
        let value = self.int_view(value)?;
        let need = if value.form().is(Class::Sign) && !value.form().is(Class::Zero) {
            Class::Sign
        } else {
            Class::Zero
        };
        let value = self.coerce(value, need)?;
        let control = value.form().promoted().unwrap_or((true, 32));
        let enumeration = self.enum_type(scrutinee);
        let characters = enumeration.is_none() && self.character(scrutinee);
        self.breakable.push(id);
        let named = enumeration.map(|ty| (ty, control));
        let arms_printed = self.arms(arms, need, named, characters);
        self.breakable.pop();
        let (body, unnamed) = arms_printed?;
        // On a value declared with an enumeration's tag, a case its
        // constants do not name, or no default, is warned of: the switch
        // is on its integer type.
        let default = arms.iter().any(|arm| arm.default);
        let declared = matches!(
            self.f.expr(scrutinee),
            Some(Expr::Var(_) | Expr::Assign { .. } | Expr::Call(_))
        );
        let value = match enumeration {
            Some(ty) if declared && (unnamed || !default) && self.enum_tag(ty).is_some() => {
                let ty = value.ty;
                self.cast(value, ty)
            }
            Some(_) | None => value,
        };
        let mut header = vec![
            self.keyword("switch"),
            Doc::Space,
            Doc::punct("(", self.node),
        ];
        header.push(Doc::Nest(value.doc));
        header.push(Doc::punct(")", self.node));
        Ok(Doc::Group(vec![
            Doc::Group(header),
            Doc::Block {
                kind: BlockKind::Statement,
                braces: Braces::Required,
                body,
                node: self.node,
            },
        ]))
    }

    /// A switch's arms, its cases read as `need` says, by the names of
    /// enumeration `named`'s constants where the switch is on one (with its
    /// promoted type), as characters where it is on one (`characters`);
    /// whether a case of an enumeration is a number no constant names.
    fn arms(
        &mut self,
        arms: &[Arm],
        need: Class,
        named: Option<(TypeId, IntTy)>,
        characters: bool,
    ) -> Result<(Vec<Doc>, bool), PrintError> {
        let mut body = Vec::new();
        let mut unnamed = false;
        for (position, arm) in arms.iter().enumerate() {
            for &value in &arm.values {
                let literal = self.constant(value, need, false)?;
                let literal = match named {
                    Some((ty, control)) => {
                        let number = literal.doc.clone();
                        let literal = self.by_name(literal, ty, Context::Case(control));
                        unnamed |= literal.doc == number;
                        literal
                    }
                    None if characters => self.by_character(literal),
                    None => literal,
                };
                let mut doc = vec![self.keyword("case"), Doc::Space];
                doc.extend(literal.doc);
                doc.push(Doc::punct(":", self.node));
                body.push(Doc::Outdent(doc));
            }
            if arm.default {
                body.push(Doc::Outdent(vec![
                    self.keyword("default"),
                    Doc::punct(":", self.node),
                ]));
            }
            let mut items = self.items(&arm.body)?;
            let last = position + 1 == arms.len();
            let falls = self.falls_off(&arm.body);
            if !last && falls && arm.fallthrough && !items.docs.is_empty() {
                items
                    .docs
                    .push(self.line(vec![self.macro_name("__attribute__((fallthrough))")]));
                items.label_last = false;
            } else if !last && falls && !arm.fallthrough {
                items.docs.push(self.line(vec![self.keyword("break")]));
                items.label_last = false;
            }
            if items.label_last {
                items.docs.push(Doc::Group(vec![Doc::punct(";", None)]));
            }
            body.extend(items.docs);
        }
        Ok((body, unnamed))
    }

    /// Whether control may reach the end of `block`.
    fn falls_off(&self, block: &Block) -> bool {
        let last = block.iter().rev().find(|&&id| match self.f.stmt(id) {
            Some(Stmt::Label(label)) => self.labels.contains_key(label),
            Some(_) | None => true,
        });
        let Some(&last) = last else {
            return true;
        };
        if self.break_labels.contains_key(&last) {
            return true;
        }
        !matches!(
            self.f.stmt(last),
            Some(
                Stmt::Break(_)
                    | Stmt::Continue(_)
                    | Stmt::Goto(_)
                    | Stmt::Return(_)
                    | Stmt::Trap(_)
                    | Stmt::Unreachable
                    | Stmt::Escape {
                        kind: Escape::UnresolvedJump
                            | Escape::ForeignJump
                            | Escape::OverlappingCode,
                        ..
                    }
            )
        )
    }
}

/// A statement line's tokens without its `;` (for a `for` header).
fn strip_semicolon(doc: Doc) -> Vec<Doc> {
    let Doc::Group(mut items) = doc else {
        return vec![doc];
    };
    if matches!(items.last(), Some(Doc::Token(token)) if token.text == ";") {
        items.pop();
    }
    items
}

/// Before a declaration in `items`: a `;` after a label they end with
/// (C17 puts no declaration right after a label).
fn after_label(items: &mut Items) {
    if items.label_last {
        items.docs.push(Doc::Group(vec![Doc::punct(";", None)]));
        items.label_last = false;
    }
}

/// A caught type as a `binbun_defs.h` handler macro's argument (which the
/// expansion drops): its C++ name when the preprocessor reads it as
/// tokens (balanced parentheses, nothing that would start a comment,
/// character or string literal, or directive), else its type information
/// symbol, else that object's address.
fn catch_type(ty: &CatchType) -> String {
    let tokens = |name: &&String| {
        let mut depth = 0_usize;
        name.chars().all(|c| match c {
            '(' => {
                depth += 1;
                true
            }
            ')' => depth.checked_sub(1).map(|d| depth = d).is_some(),
            c => c.is_ascii_alphanumeric() || "_:<>,[]*&~. -".contains(c),
        }) && depth == 0
            && !name.trim().is_empty()
    };
    let identifier = |name: &&String| {
        name.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
            && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
    };
    if let Some(name) = ty.name.as_ref().filter(tokens) {
        return name.clone();
    }
    if let Some(symbol) = ty.symbol.as_ref().filter(identifier) {
        return symbol.clone();
    }
    ty.address.map_or_else(
        || String::from("unknown"),
        |address| format!("{address:#x}"),
    )
}

/// How many node pairs [`same_tree`] compares before it gives up.
const SAME_TREE_NODES: usize = 256;

/// Whether `a` and `b` are the same tree (the same node, or nodes of the
/// same kind over the same trees), so one evaluation of either is the
/// value of both: no call and no undefined value in them (each is its
/// own), within [`SAME_TREE_NODES`] pairs.
fn same_tree(f: &Function, a: ExprId, b: ExprId) -> bool {
    let mut work = vec![(a, b)];
    let mut visited = 0;
    while let Some((a, b)) = work.pop() {
        visited += 1;
        if visited > SAME_TREE_NODES {
            return false;
        }
        let (Some(&left), Some(&right)) = (f.expr(a), f.expr(b)) else {
            return false;
        };
        if matches!(left, Expr::Call(_) | Expr::Undefined(..)) {
            return false;
        }
        if a == b {
            work.extend(left.operands(f).map(|operand| (operand, operand)));
            continue;
        }
        let blank = |expr: Expr| expr.map_own(&mut |_| ExprId(0));
        if blank(left) != blank(right) {
            return false;
        }
        let (lefts, rights): (Vec<ExprId>, Vec<ExprId>) =
            (left.operands(f).collect(), right.operands(f).collect());
        if lefts.len() != rights.len() {
            return false;
        }
        work.extend(lefts.into_iter().zip(rights));
    }
    true
}

/// `binbun_defs.h`'s name of a trap (an interrupt is `binbun_interrupt`'s
/// vector).
const fn trap_name(trap: Trap) -> &'static str {
    match trap {
        Trap::Divide => "BINBUN_TRAP_DIVIDE",
        Trap::InvalidInstruction => "BINBUN_TRAP_INVALID_INSTRUCTION",
        Trap::Breakpoint => "BINBUN_TRAP_BREAKPOINT",
        Trap::Protection => "BINBUN_TRAP_PROTECTION",
        Trap::Stack => "BINBUN_TRAP_STACK",
        Trap::FloatingPoint => "BINBUN_TRAP_FLOATING_POINT",
        Trap::Authentication => "BINBUN_TRAP_AUTHENTICATION",
        Trap::Alignment => "BINBUN_TRAP_ALIGNMENT",
        Trap::Interrupt(_) => "BINBUN_TRAP_INTERRUPT",
    }
}
