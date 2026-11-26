//! Variables, addresses and memory accesses: `v`, `&v`, `*p`, `p[i]`,
//! `p->field`, `v.field[k]`, `p->field[i]` where the index is proved in
//! the array ([`Function::indices`]), `p[i].field` (and `&p[i].field`)
//! into an array of structs, and `*(T *)((char *)p + k)` where the types
//! say nothing better.
//!
//! [`Function::indices`]: binbun_ast::ir::Function::indices

use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt::Write as _;

use binbun_ast::ir::{Expr, ExprId, Node, Place, Stmt, VarId, VarKind};
use binbun_ast::types::{Type, TypeId};
use binbun_semantics::bits::Bits;
use binbun_semantics::ir::Binary;

use super::convert::{Class, constant_value};
use super::expr::Shape;
use super::types::{CTy, FieldName, field_names};
use super::value::{Op, Value, cast_parentheses};
use super::{PrintError, Printer, error};
use crate::document::{Doc, TokenKind};

/// How an access reaches its bytes from an object or a pointer's target.
/// A field's form names it with the struct or union it is a member of
/// ([`member`]).
enum Form {
    /// The whole object: `v`, `*p`.
    Whole,
    /// An element: `v[k]`, `p[i + k]`.
    Subscript(i128),
    /// A field: `v.f`, `p->f`.
    Field(FieldName, TypeId),
    /// A member of a union field: `v.f.m`, `p->f.m` (the field's name and
    /// aggregate, the member's name and union).
    FieldMember(FieldName, TypeId, FieldName, TypeId),
    /// An element of an array field: `v.f[k]`, `p->f[k]`.
    FieldSubscript(FieldName, i128, TypeId),
    /// An element of an array's struct element: `p[i + k].f`.
    ElementField(i128, FieldName, TypeId),
}

/// An access's index, if it has one (its value and scale), with the
/// values proved for it ([`Function::indices`]).
///
/// [`Function::indices`]: binbun_ast::ir::Function::indices
pub(super) type Indexed = (Option<(Value, u64)>, Option<(i128, i128)>);

/// A member's name where it is used (`p->name`, `v.name`): its node is
/// the struct or union `of` it is a member of (as on the member's line of
/// that struct's definition), so a view finds the member from its uses;
/// the `->` or `.` before it carries the access's node.
fn member(name: FieldName, of: TypeId) -> Doc {
    name.doc(Some(Node::Type(of)))
}

/// Which declared types an access may name an object or field of.
#[derive(Clone, Copy)]
enum Fit<'a> {
    /// Only one of the access's own C type (its key).
    Exact(&'a str),
    /// Any integer or pointer of these many bits, which C converts to and
    /// from the access's own type keeping every bit: a field read or
    /// written as itself rather than through a pun of its address.
    Bits(u16),
}

impl Printer<'_> {
    /// Variable `id` read (or written) as an lvalue.
    pub(super) fn var_value(&mut self, id: VarId) -> Result<Value, PrintError> {
        let (Some(variable), Some(ty)) = (self.f.var(id), self.var_ty(id)) else {
            return Err(error(Some(Node::Var(id)), "no such variable"));
        };
        let kind = variable.kind;
        if self.thread_variable(id) {
            return self.environment_value(id);
        }
        self.used.insert(id);
        if !self.storing {
            self.read_objects.insert(id);
        }
        let cty = self.cty(ty)?;
        // An object (a frame struct) may be wider than a value's width can
        // say: only its fields are accessed.
        let width = match self.types.get(ty) {
            Some(Type::Struct(_) | Type::Union(_) | Type::Array { .. }) => self
                .types
                .width(ty)
                .filter(|&width| width > 0)
                .map(|width| u16::try_from(width).unwrap_or(u16::MAX))
                .ok_or_else(|| error(Some(Node::Type(ty)), "a type without a width"))?,
            Some(_) | None => self.type_width(ty)?,
        };
        let class = match self.int_rep(ty) {
            Some(rep) if rep.signed && !rep.boolean => Class::Sign,
            Some(_) => Class::Zero,
            None => Class::Low,
        };
        Ok(Value {
            doc: vec![self.var(id)],
            op: Op::Postfix,
            ty: cty,
            class,
            width,
            constant: None,
            lvalue: true,
            loads: matches!(kind, VarKind::Global(_) | VarKind::Frame(_)),
            depth: 0,
            address_of: None,
            unsigned_literal: None,
        })
    }

    /// The width of a value of type `ty`, in bits.
    pub(super) fn type_width(&self, ty: TypeId) -> Result<u16, PrintError> {
        self.types
            .width(ty)
            .and_then(|width| u16::try_from(width).ok())
            .filter(|&width| width > 0)
            .ok_or_else(|| error(Some(Node::Type(ty)), "a type without a width"))
    }

    /// `&v` (an array: `v`, its first element's address; a `char` array
    /// in read-only memory holding a string: that string's literal).
    pub(super) fn address_of(&mut self, id: VarId) -> Result<Value, PrintError> {
        let ty = self
            .var_ty(id)
            .ok_or_else(|| error(Some(Node::Var(id)), "no such variable"))?;
        if let Some((literal, element)) = self.string_literal(id) {
            let pointer_ty = self.pointer_type(element);
            return Ok(Value {
                doc: vec![Doc::string(literal, self.node)],
                op: Op::Postfix,
                ty: CTy::Pointer(pointer_ty),
                class: Class::Low,
                width: self.pointer_width(),
                constant: None,
                lvalue: false,
                loads: false,
                depth: 0,
                address_of: None,
                unsigned_literal: None,
            });
        }
        self.used.insert(id);
        if !self.storing {
            self.read_objects.insert(id);
        }
        let name = self.var(id);
        let (doc, op, pointee) = match self.types.get(ty) {
            Some(&Type::Array { element, .. }) => (vec![name], Op::Postfix, element),
            Some(_) | None => (vec![Doc::op("&", self.node), name], Op::Unary, ty),
        };
        let pointer_ty = self.pointer_type(pointee);
        Ok(Value {
            doc,
            op,
            ty: CTy::Pointer(pointer_ty),
            class: Class::Low,
            width: self.pointer_width(),
            constant: None,
            lvalue: false,
            loads: false,
            depth: 0,
            address_of: Some(id),
            unsigned_literal: None,
        })
    }

    /// Global `id` as a string literal (and its element type), if it is
    /// an array of `char` in read-only memory whose bytes are a string
    /// and its NUL; or an array of 16-bit unsigned integers there whose
    /// units are a byte's value each (1 to 255) up to the last, zero: a
    /// `u"…"` literal (C11's `char16_t`, `uint_least16_t`: `uint16_t`
    /// where that exists), the same units.
    fn string_literal(&self, id: VarId) -> Option<(String, TypeId)> {
        let variable = self.f.var(id)?;
        let VarKind::Global(address) = variable.kind else {
            return None;
        };
        let &Type::Array {
            element,
            length: Some(length),
        } = self.types.get(self.var_ty(id)?)?
        else {
            return None;
        };
        let wide = match self.types.get(element)? {
            Type::Char { .. } => false,
            Type::UInt(16) => true,
            Type::Bits(_)
            | Type::Int(_)
            | Type::UInt(_)
            | Type::Bool(_)
            | Type::Float(_)
            | Type::Pointer(_)
            | Type::Code(_)
            | Type::Struct(_)
            | Type::Union(_)
            | Type::Array { .. }
            | Type::Vector { .. }
            | Type::Enum(_) => return None,
        };
        let bytes = if wide { length.checked_mul(2)? } else { length };
        if !self.image.read_only(address, bytes) {
            return None;
        }
        let bytes = self.image.constant(address, bytes)?;
        if wide {
            let units: Vec<u16> = bytes
                .as_chunks::<2>()
                .0
                .iter()
                .map(|&unit| u16::from_le_bytes(unit))
                .collect();
            let (&last, text) = units.split_last()?;
            let text: Vec<u8> = text
                .iter()
                .map(|&unit| u8::try_from(unit).ok().filter(|&byte| byte != 0))
                .collect::<Option<_>>()?;
            return (last == 0).then(|| (format!("u{}", string_literal(&text)), element));
        }
        let (&last, text) = bytes.split_last()?;
        (last == 0 && !text.contains(&0)).then(|| (string_literal(text), element))
    }

    /// `&f` for the constant cast to a code type that expression `id` is
    /// ([`Printer::function_constant`]): the function at that address,
    /// declared with that type.
    pub(super) fn function_ref(&mut self, id: ExprId) -> Result<Option<Value>, PrintError> {
        let Some((address, ty)) = self.function_constant(id) else {
            return Ok(None);
        };
        let (name, automatic) = match self.callees.get(&(address, ty)) {
            Some(callee) => (callee.name.clone(), callee.automatic),
            None if address == self.f.address => {
                (self.function_name.clone(), self.function_automatic)
            }
            None => return Err(error(self.node, "a function not named")),
        };
        Ok(Some(Value {
            doc: vec![
                Doc::op("&", self.node),
                Doc::name(TokenKind::Function, name, automatic, self.node),
            ],
            op: Op::Unary,
            ty: CTy::Code(ty),
            class: Class::Low,
            width: self.pointer_width(),
            constant: None,
            lvalue: false,
            loads: false,
            depth: 0,
            address_of: None,
            unsigned_literal: None,
        }))
    }

    /// Whether a statement writes variable `id` (in memory) itself: the
    /// whole of it, or bytes at its address plus an offset and index (a
    /// global written is not declared `const`, even in read-only memory:
    /// the write faults, and C refuses it).
    pub(super) fn writes(&self, id: VarId) -> bool {
        let f = self.f;
        f.stmts
            .iter()
            .flat_map(|stmt| match stmt {
                Stmt::Assign { place, .. } => core::slice::from_ref(place),
                Stmt::VaStart { list } => core::slice::from_ref(list),
                Stmt::Call { results, .. }
                | Stmt::Intrinsic { results, .. }
                | Stmt::Escape { results, .. } => results.as_slice(),
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
            })
            .any(|place| match *place {
                Place::Var(var) => var == id,
                Place::Memory { address, .. } => {
                    let Shape::Load { base, .. } = self.address_shape(address) else {
                        return false;
                    };
                    f.expr(base) == Some(&Expr::AddressOf(id))
                }
            })
    }

    /// The parts of an address: `base + index * scale + offset`, peeling
    /// a constant offset, and an index only off a base that is surely a
    /// pointer.
    pub(super) fn address_shape(&self, address: ExprId) -> Shape {
        let mut base = address;
        let mut offset = 0;
        if let Some(&Expr::Binary(op @ (Binary::Add | Binary::Sub), x, y)) = self.f.expr(base)
            && let Some(&Expr::Const(k)) = self.f.expr(y)
        {
            let (negative, magnitude) = constant_value(k, Class::Sign);
            let magnitude = i128::try_from(magnitude).unwrap_or(0);
            offset = if negative == (op == Binary::Add) {
                -magnitude
            } else {
                magnitude
            };
            base = x;
        }
        let mut index = None;
        let mut scale = 1;
        if let Some(&Expr::Binary(Binary::Add, x, y)) = self.f.expr(base) {
            for (pointer, term) in [(x, y), (y, x)] {
                // The pointer, or a constant offset on it (`p + k + i * s`,
                // as L2 orders it: the access is at `p`'s offset `k`).
                let (pointer, k) = match self.f.expr(pointer) {
                    Some(&Expr::Binary(Binary::Add, p, k))
                        if self.pointerish(p) && matches!(self.f.expr(k), Some(Expr::Const(_))) =>
                    {
                        let Some(&Expr::Const(bits)) = self.f.expr(k) else {
                            continue;
                        };
                        let (negative, magnitude) = constant_value(bits, Class::Sign);
                        let magnitude = i128::try_from(magnitude).unwrap_or(0);
                        (p, if negative { -magnitude } else { magnitude })
                    }
                    Some(_) | None => (pointer, 0),
                };
                if self.pointerish(pointer) {
                    let (term, factor) = self.scaled(term);
                    base = pointer;
                    index = Some(term);
                    scale = factor;
                    offset += k;
                    break;
                }
            }
        }
        Shape::Load {
            base,
            index,
            scale,
            offset,
        }
    }

    /// `i * s` or `i << c` as `(i, s)`; anything else as `(term, 1)`.
    pub(super) fn scaled(&self, term: ExprId) -> (ExprId, u64) {
        let constant = |id| match self.f.expr(id) {
            Some(Expr::Const(bits)) if bits.low_u128() < 1 << 32 => {
                u64::try_from(bits.low_u128()).ok()
            }
            Some(_) | None => None,
        };
        match self.f.expr(term) {
            Some(&Expr::Binary(Binary::Mul, i, s)) => match (constant(s), constant(i)) {
                (Some(factor), _) => (i, factor),
                (None, Some(factor)) => (s, factor),
                (None, None) => (term, 1),
            },
            Some(&Expr::Binary(Binary::Shl, i, c)) => match constant(c) {
                Some(count) if count < 32 => (i, 1 << count),
                Some(_) | None => (term, 1),
            },
            Some(_) | None => (term, 1),
        }
    }

    /// The lvalue `ty` at `base + index * scale + offset`; `volatile` for
    /// a load kept for its fault, and for any access at a constant address
    /// (no variable's: a deliberate fault such as GCC's store to address 0
    /// before `ud2`, or device memory), which C would let a compiler
    /// remove or reorder. Gives the type of the C object it names: `ty`,
    /// or for an integer or pointer field of `ty`'s width but another type,
    /// the field's (`p->f`, not `*(T *)&p->f`), which a store converts to.
    pub(super) fn deref(
        &mut self,
        base: Value,
        (index, bounds): Indexed,
        offset: i128,
        ty: TypeId,
        volatile: bool,
    ) -> Result<(Value, TypeId), PrintError> {
        let volatile = volatile || (base.constant.is_some() && index.is_none());
        let cty = self.cty(ty)?;
        let width = self.type_width(ty)?;
        if let Some(rep) = self.int_rep(ty)
            && !rep.boolean
            && rep.width != rep.bits
        {
            return Err(self.unsupported(self.node, "memory accesses of 3, 5, 6 or 7 bytes"));
        }
        let want = self.key(cty)?;
        let scale = index.as_ref().map(|&(_, scale)| scale);
        let mut access = None;
        if !volatile {
            let bits = self.scalar_bits(ty).map(Fit::Bits);
            for fit in core::iter::once(Fit::Exact(&want)).chain(bits) {
                let exact = matches!(fit, Fit::Exact(_));
                let held = |held| if exact { ty } else { held };
                if let Some(var) = base.address_of {
                    let var_ty = self.var_ty(var);
                    if let Some(var_ty) = var_ty
                        && let Some((form, found)) =
                            self.form(var_ty, (scale, bounds), offset, fit)?
                        && !matches!(form, Form::ElementField(..))
                        // A variable that is no array is no subscript's base
                        // (`x[k]`): through its address it is (`(&x)[k]`).
                        && (!matches!(form, Form::Subscript(_))
                            || matches!(self.types.get(var_ty), Some(Type::Array { .. })))
                    {
                        let object = self.var_value(var)?;
                        let value = self.access(object, true, form, index.clone())?;
                        access = Some((value, held(found)));
                    }
                }
                if access.is_none()
                    && let Some((Some(target), _)) = self.pointee(base.ty)
                    && let Some((form, found)) = self.form(target, (scale, bounds), offset, fit)?
                {
                    let value = self.access(base.clone(), false, form, index.clone())?;
                    access = Some((value, held(found)));
                }
                if access.is_some() {
                    break;
                }
            }
        }
        let (mut value, held) = if let Some(found) = access {
            found
        } else {
            // An access past the field it starts in, in a variable that is
            // a struct, is on the variable's bytes.
            let bytes = u64::from(width / 8);
            let spans = index.is_none()
                && base
                    .address_of
                    .is_some_and(|var| self.spans_fields(var, offset, bytes));
            let base = if spans {
                self.cast(base, CTy::Bytes)
            } else {
                base
            };
            let address = self.pointer_add(base, index, offset)?;
            (self.raw_access(address, cty, &want, volatile)?, ty)
        };
        let held_cty = self.cty(held)?;
        value.ty = held_cty;
        value.width = width;
        value.lvalue = true;
        value.loads = true;
        value.class = match self.int_rep(held) {
            Some(rep) if rep.signed && !rep.boolean => Class::Sign,
            Some(_) => Class::Zero,
            None => Class::Low,
        };
        // A field of another integer or pointer type than the access's is
        // read as itself and converted where it is used, except to a
        // pointer to a known type or to code, which accesses and calls
        // need: `(T *)p->f` (the same bits, as C converts them).
        let typed = matches!(cty, CTy::Code(_)) || matches!(self.pointee(cty), Some((Some(_), _)));
        if !self.storing && typed && self.key(held_cty)? != want {
            let mut cast = self.cast(value, cty);
            cast.loads = true;
            return Ok((cast, ty));
        }
        Ok((value, held))
    }

    /// The width of L2 type `ty` if it is an integer (not `bool`) of a
    /// width C has, or a data or code pointer: a type whose values C
    /// converts to and from any other such type of its width keeping every
    /// bit (integers modulo 2^w, as `-fwrapv` and GCC's documented
    /// conversions give; pointers as the integer of their address).
    fn scalar_bits(&self, ty: TypeId) -> Option<u16> {
        match self.types.get(ty)? {
            Type::Pointer(_) | Type::Code(_) => Some(self.pointer_width()),
            Type::Bits(_) | Type::Int(_) | Type::UInt(_) | Type::Char { .. } | Type::Enum(_) => {
                let rep = self.int_rep(ty)?;
                (!rep.boolean && rep.width == rep.bits).then_some(rep.bits)
            }
            Type::Bool(_)
            | Type::Float(_)
            | Type::Struct(_)
            | Type::Union(_)
            | Type::Array { .. }
            | Type::Vector { .. } => None,
        }
    }

    /// Whether an access that `fit` describes may name an object of type
    /// `ty`.
    fn fits(&mut self, ty: TypeId, fit: Fit<'_>) -> Result<bool, PrintError> {
        Ok(match fit {
            Fit::Exact(want) => {
                let cty = self.cty(ty)?;
                self.key(cty)? == want
            }
            Fit::Bits(bits) => self.scalar_bits(ty) == Some(bits),
        })
    }

    /// `*(T *)address` (`volatile T` for `volatile`), or `*address` where
    /// it points to a `T` (whose type is `want`) already.
    fn raw_access(
        &mut self,
        address: Value,
        cty: CTy,
        want: &str,
        volatile: bool,
    ) -> Result<Value, PrintError> {
        let bits = self.pointer_width();
        let address = if address.ty.is_pointer()
            || address.form().promoted().is_some_and(|own| own.1 == bits)
        {
            address
        } else {
            let address = self.coerce(address, Class::Zero)?;
            self.exact(address, false, bits)
        };
        let mut doc = vec![Doc::op("*", self.node)];
        let target = match self.pointee(address.ty) {
            Some((Some(target), _)) => Some(self.cty(target)?),
            Some((None, _)) | None => None,
        };
        let fits = match target {
            Some(target) => !volatile && self.key(target)? == want,
            None => false,
        };
        if !fits {
            doc.extend(self.access_cast_tokens(cty, volatile)?);
        }
        let depth = address.depth;
        let operand = self.operand(address, Op::Unary, false);
        self.append(&mut doc, operand);
        Ok(self.lvalue(doc, Op::Unary, depth))
    }

    /// How an access that `fit` describes at `offset` (and an index scaled
    /// by `scale`) reaches into an object of type `object`, if its type
    /// says, and the type of what it names there.
    fn form(
        &mut self,
        object: TypeId,
        (scale, bounds): (Option<u64>, Option<(i128, i128)>),
        offset: i128,
        fit: Fit<'_>,
    ) -> Result<Option<(Form, TypeId)>, PrintError> {
        if scale.is_none() && offset == 0 && self.fits(object, fit)? {
            return Ok(Some((Form::Whole, object)));
        }
        let element_of = |printer: &Self, ty| match printer.types.get(ty) {
            Some(&Type::Array { element, .. }) => Some(element),
            Some(_) | None => None,
        };
        if let Some(element) = element_of(self, object).or(Some(object)) {
            let size = self.types.width(element).map_or(0, |width| width / 8);
            if size > 0
                && self.fits(element, fit)?
                && offset % i128::from(size) == 0
                && scale.is_none_or(|scale| scale == size)
                && (element != object || scale.is_some() || offset != 0)
            {
                return Ok(Some((Form::Subscript(offset / i128::from(size)), element)));
            }
        }
        if let Some(scale) = scale {
            if let Some(bounds) = bounds
                && let Some(found) = self.field_index(object, scale, offset, bounds, fit)?
            {
                return Ok(Some(found));
            }
            return self.element_field(object, Some(scale), offset, fit);
        }
        let fields = match self.types.get(object) {
            Some(Type::Struct(aggregate) | Type::Union(aggregate)) => field_names(aggregate),
            Some(_) | None => return Ok(None),
        };
        for (field_offset, field_ty, name) in fields {
            let start = i128::from(field_offset);
            if start == offset && self.fits(field_ty, fit)? {
                return Ok(Some((Form::Field(name, object), field_ty)));
            }
            // A union field at the offset: the member the access fits.
            let members = match self.types.get(field_ty) {
                Some(Type::Union(union)) if start == offset => field_names(union),
                Some(_) | None => Vec::new(),
            };
            for (member_offset, member_ty, member_name) in members {
                if member_offset == 0 && self.fits(member_ty, fit)? {
                    let form = Form::FieldMember(name, object, member_name, field_ty);
                    return Ok(Some((form, member_ty)));
                }
            }
            if let Some(element) = element_of(self, field_ty) {
                let size = i128::from(self.types.width(element).map_or(0, |width| width / 8));
                let end = start + i128::from(self.types.width(field_ty).unwrap_or(0) / 8);
                if size > 0
                    && (start..end).contains(&offset)
                    && (offset - start) % size == 0
                    && self.fits(element, fit)?
                {
                    let form = Form::FieldSubscript(name, (offset - start) / size, object);
                    return Ok(Some((form, element)));
                }
            }
        }
        Ok(None)
    }

    /// `p[i + k].f`: an access that `fit` describes at `offset` with an index
    /// scaled by `scale` into an array of `object` (a struct of `scale`
    /// bytes), at a field of that type (not an array) of its element
    /// `k = offset / scale`.
    fn element_field(
        &mut self,
        object: TypeId,
        scale: Option<u64>,
        offset: i128,
        fit: Fit<'_>,
    ) -> Result<Option<(Form, TypeId)>, PrintError> {
        let Some(Type::Struct(aggregate)) = self.types.get(object) else {
            return Ok(None);
        };
        let size = i128::from(aggregate.size);
        if size == 0 || scale.is_none_or(|scale| i128::from(scale) != size) {
            return Ok(None);
        }
        let (element, within) = (offset.div_euclid(size), offset.rem_euclid(size));
        for (at, ty, name) in field_names(aggregate) {
            if i128::from(at) != within || matches!(self.types.get(ty), Some(Type::Array { .. })) {
                continue;
            }
            if self.fits(ty, fit)? {
                return Ok(Some((Form::ElementField(element, name, object), ty)));
            }
        }
        Ok(None)
    }

    /// `p->f[i + k]`: an access that `fit` describes at `offset` with an
    /// index scaled by `scale` into `object` (a struct), in an array field
    /// `f` of elements of `scale` bytes, `k = (offset - f's offset) /
    /// scale`, where the index's proved values `bounds` ([`Function::indices`])
    /// keep `i + k` in the array, as C requires of a subscript (past it
    /// the bytes are the next field's: their address, not the array's
    /// element).
    ///
    /// [`Function::indices`]: binbun_ast::ir::Function::indices
    fn field_index(
        &mut self,
        object: TypeId,
        scale: u64,
        offset: i128,
        (lo, hi): (i128, i128),
        fit: Fit<'_>,
    ) -> Result<Option<(Form, TypeId)>, PrintError> {
        let fields = match self.types.get(object) {
            Some(Type::Struct(aggregate)) => field_names(aggregate),
            Some(_) | None => return Ok(None),
        };
        let scale = i128::from(scale);
        for (at, ty, name) in fields {
            let Some(&Type::Array {
                element,
                length: Some(length),
            }) = self.types.get(ty)
            else {
                continue;
            };
            let start = i128::from(at);
            let size = i128::from(self.types.width(element).map_or(0, |width| width / 8));
            let length = i128::from(length);
            if size != scale || offset < start || (offset - start) % size != 0 {
                continue;
            }
            let k = (offset - start) / size;
            if lo + k >= 0 && hi + k < length && self.fits(element, fit)? {
                return Ok(Some((Form::FieldSubscript(name, k, object), element)));
            }
        }
        Ok(None)
    }

    /// The values proved for index expression `index`, if it is one
    /// ([`Function::indices`]).
    ///
    /// [`Function::indices`]: binbun_ast::ir::Function::indices
    pub(super) fn bounds(&self, index: Option<ExprId>) -> Option<(i128, i128)> {
        self.f.indices.get(&index?).copied()
    }

    /// The array field of struct `target` holding `offset` with elements of
    /// `scale` bytes, its element type, and `k = (offset - its offset) /
    /// scale`, where the index's proved values `bounds` keep `i + k` in it
    /// and its element's address may be taken: the field
    /// `p + i * scale + offset` is an element of (`&p->f[i + k]`).
    pub(super) fn array_field_at(
        &self,
        target: TypeId,
        scale: u64,
        offset: i128,
        bounds: Option<(i128, i128)>,
    ) -> Option<(FieldName, TypeId, TypeId, i128)> {
        let (lo, hi) = bounds?;
        let Some(Type::Struct(aggregate)) = self.types.get(target) else {
            return None;
        };
        let scale = i128::from(scale);
        field_names(aggregate)
            .into_iter()
            .find_map(|(at, ty, name)| {
                let &Type::Array {
                    element,
                    length: Some(length),
                } = self.types.get(ty)?
                else {
                    return None;
                };
                let start = i128::from(at);
                let size = i128::from(self.types.width(element)? / 8);
                if size != scale || offset < start || (offset - start) % size != 0 {
                    return None;
                }
                let k = (offset - start) / size;
                let inside = lo + k >= 0 && hi + k < i128::from(length);
                (inside && self.field_addressable(element, target))
                    .then_some((name, element, target, k))
            })
    }

    /// `&p->f[i + k]`, the address of an element of array field `name` of
    /// struct `of` that `base` points to ([`Self::array_field_at`]): a
    /// pointer to its type `element`.
    pub(super) fn array_address(
        &mut self,
        base: Value,
        (index, scale): (Value, u64),
        (name, element, of, k): (FieldName, TypeId, TypeId, i128),
    ) -> Result<Value, PrintError> {
        let node = self.node;
        let loads = base.loads || index.loads;
        let depth = base.depth.max(index.depth);
        let ty = CTy::Pointer(self.pointer_type(element));
        let mut operand = self.operand(base, Op::Postfix, false);
        operand.push(Doc::op("->", node));
        operand.push(member(name, of));
        let subscript = self.subscript(Some((index, scale)), k)?;
        operand.push(Doc::punct("[", node));
        self.append(&mut operand, subscript);
        operand.push(Doc::punct("]", node));
        let mut doc = vec![Doc::op("&", node)];
        self.append(&mut doc, operand);
        Ok(Value {
            doc,
            op: Op::Unary,
            ty,
            class: Class::Low,
            width: self.pointer_width(),
            constant: None,
            lvalue: false,
            loads,
            depth,
            address_of: None,
            unsigned_literal: None,
        })
    }

    /// The access `form` into `object` (an lvalue if `is_object`, else a
    /// pointer to it).
    fn access(
        &mut self,
        object: Value,
        is_object: bool,
        form: Form,
        index: Option<(Value, u64)>,
    ) -> Result<Value, PrintError> {
        let node = self.node;
        let depth = object.depth;
        // An array field's subscript: `f[k]`, or `f[i + k]` with an index
        // ([`Self::field_index`]).
        let element = match form {
            Form::FieldSubscript(_, constant, _) if index.is_some() => {
                Some(self.subscript(index.clone(), constant)?)
            }
            Form::FieldSubscript(_, constant, _) => {
                Some(vec![Doc::number(format!("{constant}"), node)])
            }
            Form::Whole
            | Form::Subscript(_)
            | Form::Field(..)
            | Form::FieldMember(..)
            | Form::ElementField(..) => None,
        };
        let doc = match form {
            Form::Whole if is_object => object.doc,
            Form::Whole => {
                let mut doc = vec![Doc::op("*", node)];
                let operand = self.operand(object, Op::Unary, false);
                self.append(&mut doc, operand);
                return Ok(self.lvalue(doc, Op::Unary, depth));
            }
            Form::Subscript(constant) => {
                let mut doc = self.operand(object, Op::Postfix, false);
                let subscript = self.subscript(index, constant)?;
                doc.push(Doc::punct("[", node));
                self.append(&mut doc, subscript);
                doc.push(Doc::punct("]", node));
                doc
            }
            Form::ElementField(constant, name, of) => {
                let mut doc = self.operand(object, Op::Postfix, false);
                let subscript = self.subscript(index, constant)?;
                doc.push(Doc::punct("[", node));
                self.append(&mut doc, subscript);
                doc.push(Doc::punct("]", node));
                doc.push(Doc::op(".", node));
                doc.push(member(name, of));
                doc
            }
            Form::Field(name, of) | Form::FieldSubscript(name, _, of) if is_object => {
                let mut doc = self.operand(object, Op::Postfix, false);
                doc.push(Doc::op(".", node));
                doc.push(member(name, of));
                doc
            }
            Form::Field(name, of) | Form::FieldSubscript(name, _, of) => {
                let mut doc = self.operand(object, Op::Postfix, false);
                doc.push(Doc::op("->", node));
                doc.push(member(name, of));
                doc
            }
            Form::FieldMember(name, of, member_name, union) => {
                let mut doc = self.operand(object, Op::Postfix, false);
                doc.push(Doc::op(if is_object { "." } else { "->" }, node));
                doc.push(member(name, of));
                doc.push(Doc::op(".", node));
                doc.push(member(member_name, union));
                doc
            }
        };
        let mut doc = doc;
        if let Some(subscript) = element {
            doc.push(Doc::punct("[", node));
            self.append(&mut doc, subscript);
            doc.push(Doc::punct("]", node));
        }
        Ok(self.lvalue(doc, Op::Postfix, depth))
    }

    fn lvalue(&self, doc: Vec<Doc>, op: Op, depth: u8) -> Value {
        Value {
            doc,
            op,
            ty: CTy::Bytes,
            class: Class::Low,
            width: self.pointer_width(),
            constant: None,
            lvalue: true,
            loads: true,
            depth,
            address_of: None,
            unsigned_literal: None,
        }
    }

    /// A subscript: `i`, `i + k`, `k`; an index that is not an integer
    /// (a pointer the types gave a register that also holds one) through
    /// its integer view, as C requires.
    fn subscript(
        &mut self,
        index: Option<(Value, u64)>,
        constant: i128,
    ) -> Result<Vec<Doc>, PrintError> {
        let width = self.pointer_width();
        let bits = Bits::from_u128(width, constant.cast_unsigned());
        Ok(match index {
            Some((index, _)) if constant == 0 => self.int_view(index)?.doc,
            Some((index, _)) => {
                let index = self.int_view(index)?;
                let constant = self.constant(bits, Class::Zero, false)?;
                self.binary(Binary::Add, index, constant, width)?.doc
            }
            None => self.constant(bits, Class::Sign, false)?.doc,
        })
    }

    /// `base + index * scale + offset` as a pointer (scaled where the
    /// pointee's size allows, else in bytes: on a `void *` as it is,
    /// another pointer as a `uint8_t *`) or, for an integer base, an
    /// integer; a pointer `base` itself where nothing is added (any
    /// pointer converts to the `T *` an access needs directly).
    pub(super) fn pointer_add(
        &mut self,
        base: Value,
        index: Option<(Value, u64)>,
        offset: i128,
    ) -> Result<Value, PrintError> {
        let width = self.pointer_width();
        let base = if matches!(base.ty, CTy::Code(_)) {
            self.int_view(base)?
        } else {
            base
        };
        if !base.ty.is_pointer() {
            let mut sum = self.int_view(base)?;
            if let Some((index, scale)) = index {
                let term = self.scale(index, scale)?;
                sum = self.binary(Binary::Add, sum, term, width)?;
            }
            if offset != 0 {
                let constant = self.constant(
                    Bits::from_u128(width, offset.cast_unsigned()),
                    Class::Zero,
                    false,
                )?;
                sum = self.binary(Binary::Add, sum, constant, width)?;
            }
            return Ok(sum);
        }
        if index.is_none() && offset == 0 {
            return Ok(base);
        }
        if index.is_none()
            && let Some(var) = base.address_of
            && let Some(value) = self.member_address(var, offset)
        {
            return Ok(value);
        }
        if index.is_none()
            && let Some((name, field, of)) = self.field_at(base.ty, offset)
        {
            // The address of a field: `&p->field`, a pointer to its type.
            return self.field_address(base, None, (name, of), field);
        }
        if let Some((index, scale)) = index.clone()
            && let Some((element, name, field, of)) = self.element_field_at(base.ty, scale, offset)
        {
            // The address of a field of an array's struct element:
            // `&p[i + k].field`, a pointer to its type.
            return self.field_address(base, Some((index, scale, element)), (name, of), field);
        }
        let size = self
            .pointee(base.ty)
            .and_then(|(_, size)| size)
            .map_or(0, i128::from);
        let scaled = size > 0
            && offset % size == 0
            && index
                .as_ref()
                .is_none_or(|&(_, scale)| i128::from(scale) == size);
        let (mut sum, divisor) = if scaled {
            (base, size)
        } else if base.ty == CTy::Bytes || self.is_void(base.ty) {
            (base, 1)
        } else {
            (self.cast(base, CTy::Bytes), 1)
        };
        if let Some((index, scale)) = index {
            // An index typed a pointer (C adds no pointer to a pointer):
            // its integer view.
            let index = self.int_view(index)?;
            let term = if scaled {
                index
            } else {
                self.scale(index, scale)?
            };
            sum = self.pointer_term(sum, "+", term);
        }
        if offset != 0 {
            let magnitude = (offset / divisor).unsigned_abs();
            let literal = self.constant(Bits::from_u128(width, magnitude), Class::Zero, false)?;
            sum = self.pointer_term(sum, if offset < 0 { "-" } else { "+" }, literal);
        }
        Ok(sum)
    }

    /// `index * scale` at the pointer width.
    pub(super) fn scale(&mut self, index: Value, scale: u64) -> Result<Value, PrintError> {
        if scale == 1 {
            return Ok(index);
        }
        let width = self.pointer_width();
        let factor = self.constant(Bits::from_u64(width, scale), Class::Zero, false)?;
        self.binary(Binary::Mul, index, factor, width)
    }

    /// The address of field `name` (of type `field`) of the struct `of`
    /// that `base` points to (`&p->name`), or of element `p[i + k]` of the
    /// array of them it points into, `element` giving the index, its scale
    /// and `k` (`&p[i + k].name`): a pointer to the field's type.
    fn field_address(
        &mut self,
        base: Value,
        element: Option<(Value, u64, i128)>,
        (name, of): (FieldName, TypeId),
        field: TypeId,
    ) -> Result<Value, PrintError> {
        let node = self.node;
        let mut loads = base.loads;
        let mut depth = base.depth;
        let ty = CTy::Pointer(self.pointer_type(field));
        let mut operand = self.operand(base, Op::Postfix, false);
        if let Some((index, scale, k)) = element {
            loads |= index.loads;
            depth = depth.max(index.depth);
            let subscript = self.subscript(Some((index, scale)), k)?;
            operand.push(Doc::punct("[", node));
            self.append(&mut operand, subscript);
            operand.push(Doc::punct("]", node));
            operand.push(Doc::op(".", node));
        } else {
            operand.push(Doc::op("->", node));
        }
        operand.push(member(name, of));
        let mut doc = vec![Doc::op("&", node)];
        self.append(&mut doc, operand);
        Ok(Value {
            doc,
            op: Op::Unary,
            ty,
            class: Class::Low,
            width: self.pointer_width(),
            constant: None,
            lvalue: false,
            loads,
            depth,
            address_of: None,
            unsigned_literal: None,
        })
    }

    /// The name and type of the field (not an array) that starts `offset`
    /// bytes into the struct `pointer` points to, and that struct, if one
    /// does and its address may be taken ([`Self::field_addressable`];
    /// else the address stays a byte offset).
    fn field_at(&self, pointer: CTy, offset: i128) -> Option<(FieldName, TypeId, TypeId)> {
        let (target, _) = self.pointee(pointer)?;
        let target = target?;
        let Some(Type::Struct(aggregate)) = self.types.get(target) else {
            return None;
        };
        field_names(aggregate)
            .into_iter()
            .find(|&(at, ty, _)| {
                i128::from(at) == offset
                    && !matches!(self.types.get(ty), Some(Type::Array { .. }))
                    && self.field_addressable(ty, target)
            })
            .map(|(_, ty, name)| (name, ty, target))
    }

    /// The address `offset` bytes into variable `var`, a struct, where a
    /// field says it: `&v.f` for a field (not an array) starting there and
    /// aligned as [`Self::field_at`] requires, a pointer to its type; `v.f`
    /// or `v.f + k` inside an array field, at a whole element, a pointer
    /// to its element.
    fn member_address(&mut self, var: VarId, offset: i128) -> Option<Value> {
        let ty = self.var_ty(var)?;
        let Some(Type::Struct(aggregate)) = self.types.get(ty) else {
            return None;
        };
        if !self.storing {
            self.read_objects.insert(var);
        }
        let node = self.node;
        let object = self.var(var);
        for (at, field, name) in field_names(aggregate) {
            let start = i128::from(at);
            let size = i128::from(self.types.width(field)? / 8);
            if offset < start || offset >= start + size {
                continue;
            }
            if let Some(&Type::Array { element, .. }) = self.types.get(field) {
                let element_size = i128::from(self.types.width(element)? / 8);
                if element_size == 0 || (offset - start) % element_size != 0 {
                    return None;
                }
                let k = (offset - start) / element_size;
                let pointer = CTy::Pointer(self.pointer_type(element));
                let mut doc = vec![object, Doc::op(".", node), member(name, ty)];
                let mut op = Op::Postfix;
                if k != 0 {
                    doc.extend([
                        Doc::Space,
                        Doc::op("+", node),
                        Doc::Space,
                        Doc::number(format!("{k}"), node),
                    ]);
                    op = Op::Additive;
                }
                return Some(self.address_value(doc, op, pointer));
            }
            if offset != start || !self.field_addressable(field, ty) {
                return None;
            }
            let pointer = CTy::Pointer(self.pointer_type(field));
            let doc = vec![
                Doc::op("&", node),
                object,
                Doc::op(".", node),
                member(name, ty),
            ];
            return Some(self.address_value(doc, Op::Unary, pointer));
        }
        None
    }

    /// An address (no lvalue, reading no memory) of pointer type `ty`.
    fn address_value(&self, doc: Vec<Doc>, op: Op, ty: CTy) -> Value {
        Value {
            doc,
            op,
            ty,
            class: Class::Low,
            width: self.pointer_width(),
            constant: None,
            lvalue: false,
            loads: false,
            depth: 0,
            address_of: None,
            unsigned_literal: None,
        }
    }

    /// `value`, a pointer to a struct, as a pointer to the struct's first
    /// member where that is a `target` (C11 6.7.2.1p15: a pointer to a
    /// structure, suitably converted, points to its initial member, so
    /// the address is the same and no cast is needed): `&v.f` for the
    /// address of a struct variable, `&p->f` for another pointer. Not for
    /// a byte (`char *`: a pointer to any object's bytes, as buffers are
    /// passed; `&p->f` would say only `f`'s byte is reached).
    pub(super) fn first_member(
        &mut self,
        value: &Value,
        target: CTy,
    ) -> Result<Option<Value>, PrintError> {
        if self
            .pointee(target)
            .and_then(|(_, size)| size)
            .is_none_or(|size| size <= 1)
        {
            return Ok(None);
        }
        let member = if let Some(var) = value.address_of {
            let Some(ty) = self.var_ty(var) else {
                return Ok(None);
            };
            let first = match self.types.get(ty) {
                Some(Type::Struct(aggregate)) => field_names(aggregate)
                    .into_iter()
                    .find(|&(at, _, _)| at == 0)
                    .map(|(_, field, _)| field),
                Some(_) | None => None,
            };
            let Some(field) = first else {
                return Ok(None);
            };
            let pointer = CTy::Pointer(self.pointer_type(field));
            if self.key(pointer)? != self.key(target)? {
                return Ok(None);
            }
            self.member_address(var, 0)
        } else if let Some((name, field, of)) = self.field_at(value.ty, 0) {
            let pointer = CTy::Pointer(self.pointer_type(field));
            if self.key(pointer)? != self.key(target)? {
                return Ok(None);
            }
            Some(self.field_address(value.clone(), None, (name, of), field)?)
        } else {
            None
        };
        Ok(member)
    }

    /// Whether the `bytes` bytes `offset` bytes into variable `var`, a
    /// struct, are not all of the one field holding the first.
    fn spans_fields(&self, var: VarId, offset: i128, bytes: u64) -> bool {
        let Some(ty) = self.var_ty(var) else {
            return false;
        };
        let Some(Type::Struct(aggregate)) = self.types.get(ty) else {
            return false;
        };
        let end = offset.saturating_add(i128::from(bytes));
        !aggregate.fields.iter().any(|field| {
            let start = i128::from(field.offset);
            let size = i128::from(self.types.width(field.ty).unwrap_or(0) / 8);
            start <= offset && end <= start + size
        })
    }

    /// `(uint8_t *)&frame + k` for expression `id` where it is a frame
    /// struct's address plus a constant `k`
    /// ([`Function::frames`](binbun_ast::ir::Function::frames)): the
    /// base of arithmetic that may cross its fields, on its bytes.
    pub(super) fn frame_bytes(&mut self, id: ExprId) -> Result<Option<Value>, PrintError> {
        let (var, offset) = match self.f.expr(id) {
            Some(&Expr::AddressOf(var)) => (var, 0),
            Some(&Expr::Binary(op @ (Binary::Add | Binary::Sub), x, y)) => {
                let (Some(&Expr::AddressOf(var)), Some(&Expr::Const(k))) =
                    (self.f.expr(x), self.f.expr(y))
                else {
                    return Ok(None);
                };
                let (negative, magnitude) = constant_value(k, Class::Sign);
                let magnitude = i128::try_from(magnitude).unwrap_or(0);
                let offset = if negative == (op == Binary::Add) {
                    -magnitude
                } else {
                    magnitude
                };
                (var, offset)
            }
            Some(_) | None => return Ok(None),
        };
        if !self.f.frames.contains(&var) {
            return Ok(None);
        }
        let base = self.address_of(var)?;
        let base = self.cast(base, CTy::Bytes);
        self.pointer_add(base, None, offset).map(Some)
    }

    /// The element `k`, and the name and type of the field (not an
    /// array, aligned as [`Self::field_at`] requires, not at the element's
    /// start: that address is `p + i` itself) that `offset` bytes plus an
    /// index scaled by `scale` reach in the array of structs `pointer`
    /// points into, where `scale` is the struct's size; and the struct.
    fn element_field_at(
        &self,
        pointer: CTy,
        scale: u64,
        offset: i128,
    ) -> Option<(i128, FieldName, TypeId, TypeId)> {
        let (target, _) = self.pointee(pointer)?;
        let target = target?;
        let Some(Type::Struct(aggregate)) = self.types.get(target) else {
            return None;
        };
        let size = i128::from(aggregate.size);
        if size == 0 || i128::from(scale) != size {
            return None;
        }
        let (element, within) = (offset.div_euclid(size), offset.rem_euclid(size));
        field_names(aggregate)
            .into_iter()
            .find(|&(at, ty, _)| {
                within != 0
                    && i128::from(at) == within
                    && !matches!(self.types.get(ty), Some(Type::Array { .. }))
                    && self.field_addressable(ty, target)
            })
            .map(|(_, ty, name)| (element, name, ty, target))
    }

    /// `base + index` (`base - index` for `minus`), `index` an integer of
    /// the pointer width counting bytes: arithmetic in bytes (on `base`
    /// itself where it points to bytes or is a `void *`, else on
    /// `(uint8_t *)base`), not through an integer. `index` is zero- or
    /// sign-extended exactly as C converts it, else cast to the
    /// pointer-wide unsigned type.
    pub(super) fn byte_offset(
        &mut self,
        base: Value,
        minus: bool,
        index: Value,
    ) -> Result<Value, PrintError> {
        let index = self.int_view(index)?;
        let index = if index.form().is(Class::Zero) || index.form().is(Class::Sign) {
            index
        } else {
            self.coerce(index, Class::Zero)?
        };
        let base = if self.pointee(base.ty).and_then(|(_, size)| size) == Some(1)
            || self.is_void(base.ty)
        {
            base
        } else {
            self.cast(base, CTy::Bytes)
        };
        Ok(self.pointer_term(base, if minus { "-" } else { "+" }, index))
    }

    /// Whether `ty` is `void *`, on which GCC and Clang do arithmetic in
    /// bytes (a GNU extension: `void`'s size is 1 to them).
    pub(super) fn is_void(&self, ty: CTy) -> bool {
        matches!(ty, CTy::Pointer(_)) && self.pointee(ty) == Some((None, None))
    }

    /// `pointer op term` (a pointer).
    fn pointer_term(&self, pointer: Value, op: &str, term: Value) -> Value {
        let ty = pointer.ty;
        let loads = pointer.loads || term.loads;
        let (doc, depth) = self.binary_doc(pointer, op, Op::Additive, term);
        Value {
            doc,
            op: Op::Additive,
            ty,
            class: Class::Low,
            width: self.pointer_width(),
            constant: None,
            lvalue: false,
            loads,
            depth,
            address_of: None,
            unsigned_literal: None,
        }
    }

    /// A place as an lvalue, and the L2 type of the C object it names (a
    /// store converts to it): the place's own, or a field's
    /// ([`Self::deref`]).
    pub(super) fn place(&mut self, place: &Place) -> Result<(Value, TypeId), PrintError> {
        match *place {
            Place::Var(id) => {
                let ty = self
                    .var_ty(id)
                    .ok_or_else(|| error(Some(Node::Var(id)), "no such variable"))?;
                let storing = core::mem::replace(&mut self.storing, true);
                let value = self.var_value(id);
                self.storing = storing;
                Ok((value?, ty))
            }
            Place::Memory { address, ty } => {
                if let Some(Shape::Rows {
                    base,
                    rows: (rows, by_rows),
                    columns: (columns, by_columns),
                    scale,
                    offset,
                }) = self.rows_shape(address)
                {
                    let storing = core::mem::replace(&mut self.storing, true);
                    let base = self.expr(base);
                    self.storing = storing;
                    let base = base?;
                    let rows = self.expr(rows)?;
                    let columns = self.expr(columns)?;
                    let index = self.rows_index((rows, by_rows), (columns, by_columns))?;
                    let storing = core::mem::replace(&mut self.storing, true);
                    let place = self.deref(base, (Some((index, scale)), None), offset, ty, false);
                    self.storing = storing;
                    return place;
                }
                let Shape::Load {
                    base,
                    index,
                    scale,
                    offset,
                } = self.address_shape(address)
                else {
                    return Err(error(self.node, "not an address"));
                };
                // The base of a store is no read of the object it is the
                // address of ([`Printer::read_objects`]).
                let storing = core::mem::replace(&mut self.storing, true);
                let base = self.expr(base);
                self.storing = storing;
                let base = base?;
                let bounds = self.bounds(index);
                let index = match index {
                    Some(index) => Some((self.expr(index)?, scale)),
                    None => None,
                };
                let storing = core::mem::replace(&mut self.storing, true);
                let place = self.deref(base, (index, bounds), offset, ty, false);
                self.storing = storing;
                place
            }
        }
    }

    /// `(void)*(volatile T *)p`-style statement tokens for a load kept for
    /// its fault (`(void)__readgsqword(k)` relative to a segment's thread
    /// pointer), or `(void)e` for any other expression.
    pub(super) fn evaluated(&mut self, id: ExprId) -> Result<Vec<Doc>, PrintError> {
        let value = match self.f.expr(id) {
            Some(&Expr::Load { address, ty }) => {
                let Shape::Load {
                    base,
                    index,
                    scale,
                    offset,
                } = self.address_shape(address)
                else {
                    return Err(error(self.node, "not an address"));
                };
                let base_id = base;
                let base = self.expr(base)?;
                let bounds = self.bounds(index);
                let index = match index {
                    Some(index) => Some((self.expr(index)?, scale)),
                    None => None,
                };
                self.access_at(base_id, base, (index, bounds), offset, ty, true)?
            }
            Some(_) | None => self.expr(id)?,
        };
        let void = vec![Doc::token(TokenKind::BuiltinType, "void", self.node)];
        let mut doc = cast_parentheses(void, self.node);
        doc.extend(self.operand(value, Op::Unary, false));
        Ok(doc)
    }

    /// The value of `ty` at `base + index * scale + offset`, `base` the
    /// value of expression `base_id`: a segment intrinsic's read where
    /// `base_id` is the thread pointer of a platform that reaches it by
    /// segment and one reads `ty`, else [`Self::deref`] (`volatile` as
    /// there).
    pub(super) fn access_at(
        &mut self,
        base_id: ExprId,
        base: Value,
        (index, bounds): Indexed,
        offset: i128,
        ty: TypeId,
        volatile: bool,
    ) -> Result<Value, PrintError> {
        if self.segment(base_id)
            && let Some(value) = self.segment_read(base_id, index.clone(), offset, ty)?
        {
            return Ok(value);
        }
        Ok(self.deref(base, (index, bounds), offset, ty, volatile)?.0)
    }

    /// A store of `value` to memory `place` as a segment intrinsic's
    /// write (`__writegsqword(k, value)`), where its address is the thread
    /// pointer of a platform that reaches it by segment plus an offset and
    /// one writes its type; `None` otherwise (and nothing printed).
    pub(super) fn segment_store(
        &mut self,
        place: &Place,
        value: ExprId,
    ) -> Result<Option<Vec<Doc>>, PrintError> {
        let Place::Memory { address, ty } = *place else {
            return Ok(None);
        };
        let Shape::Load {
            base,
            index,
            scale,
            offset,
        } = self.address_shape(address)
        else {
            return Ok(None);
        };
        if !self.segment(base) || self.segment_access(ty)?.is_none() {
            return Ok(None);
        }
        let value = self.expr(value)?;
        let index = match index {
            Some(index) => Some((self.expr(index)?, scale)),
            None => None,
        };
        self.segment_write(base, index, offset, ty, value)
    }
}

/// `text` as a C string literal: printable ASCII as itself, the usual
/// escapes, anything else in octal (never `\x`, which would swallow a
/// following hex digit), and `?` after `?` escaped (no trigraph).
pub fn string_literal(text: &[u8]) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    let mut previous = 0u8;
    for &byte in text {
        match byte {
            b'"' => out.push_str("\\\""),
            b'\\' => out.push_str("\\\\"),
            b'\n' => out.push_str("\\n"),
            b'\t' => out.push_str("\\t"),
            b'\r' => out.push_str("\\r"),
            b'?' if previous == b'?' => out.push_str("\\?"),
            b' '..=b'~' => out.push(char::from(byte)),
            _ => {
                let _ = write!(out, "\\{byte:03o}");
            }
        }
        previous = byte;
    }
    out.push('"');
    out
}
