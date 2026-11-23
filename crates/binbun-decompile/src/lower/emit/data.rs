//! Constant addresses in the image's data and code, as globals, from the
//! context's [`Data`](crate::data::Data):
//!
//! - An access (load, store, atomic) at a constant address inside a
//!   named object (a data symbol with a size, an import's pointer slot) is
//!   that object's `Global` variable: the variable itself where it covers
//!   the whole object, else bytes at the variable's address plus an
//!   offset (and an index, for a constant base plus a computed index).
//!   One at a constant address in data no object names is a `Global`
//!   variable at that address, as wide as the program's type for it
//!   ([`crate::typing::Globals`]), else as most accesses there in the
//!   function (of its debug information's scalar type, else the
//!   program's, else the solver's type for it ([`crate::typing`]), if
//!   that wide). A store into
//!   read-only memory is neither (it faults: the
//!   printer keeps it `volatile`), nor is an access outside the image's
//!   data.
//! - A named object's variable is of its debug information's type where
//!   that is the object's size (asserted); else of the program's type for
//!   it (one over all functions, [`crate::typing::Globals`]); else as
//!   wide as the object where that is a value's width and it is accessed
//!   whole; else an array of the elements most of its aligned accesses
//!   read and write.
//! - A constant passed where a declared `char *` is expected that points
//!   to a string in read-only data is that string's `Global` variable (a
//!   `char` array, its NUL included), by address; one passed where a
//!   pointer to a 16-bit unsigned integer is expected (Windows' `WCHAR
//!   *`) that points to a wide string ([`Data::wide_string`]) is that
//!   string's variable, an array of those integers, its zero unit
//!   included.
//! - A constant passed, stored or returned that is the image's address of
//!   a function is that function (a cast of the constant to its code
//!   type); one inside a named object is the object's address plus an
//!   offset. In position-independent code an immediate is never an
//!   address of the image (addresses are computed from the program
//!   counter, or loaded), so only a computed constant, or one passed for
//!   a declared pointer, is taken as one: an immediate that happens to
//!   equal an address stays a number.
//!
//! Every replacement has the constant's value: `&g + k` is the address
//! `g` lives at plus `k`, the cast keeps the bits.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use binbun_ast::ir::{Expr, ExprId, Place, VarId, VarKind};
use binbun_ast::types::{Evidence, Type, TypeId};
use binbun_semantics::bits::Bits;
use binbun_semantics::ir::Binary;
use binbun_ssa::ir::{Op, Value};

use super::{Emit, Kind, scalar};
use crate::data::Object;
use crate::lower::calls::MAX_SCALAR;
use crate::typing::{GlobalShape, StructId};

/// The largest object (in bytes) that is a variable: a symbol's size past
/// this is no object C can declare.
const MAX_OBJECT: u64 = 1 << 32;

/// A `Global` variable of the image's data.
#[derive(Clone, Debug)]
pub(super) struct Global {
    var: VarId,
    /// The named object's size in bytes; `None` for data no object names.
    size: Option<u64>,
    /// Whether it is read or written whole (its type is then fixed).
    whole: bool,
    /// How many accesses through its address there are of each width (in
    /// bits), at an offset that is a multiple of their size.
    widths: BTreeMap<u16, usize>,
}

/// Where an access at a constant address goes.
enum Access {
    /// The whole of a variable.
    Var(VarId),
    /// The bytes at an address: a variable's plus an offset.
    Address(ExprId),
}

/// What [`Emit`] keeps about the image's data.
#[derive(Clone, Debug, Default)]
pub(super) struct Globals {
    /// The variables of objects and data, by their first byte.
    vars: BTreeMap<u64, Global>,
    /// The variables of strings, by address and character type.
    strings: BTreeMap<(u64, TypeId), VarId>,
    /// How many accesses at each constant address there are of each width
    /// (in bits), counted on first use.
    accesses: Option<BTreeMap<u64, BTreeMap<u16, usize>>>,
    /// The program's structs interned for [`Emit::program_global`].
    interned: BTreeMap<StructId, TypeId>,
}

impl Emit<'_, '_, '_> {
    /// The value of a load of `bytes` bytes at `address` (of L1 value
    /// `value`), if the address is in the image's data: the variable read,
    /// or a load at its address.
    pub(super) fn data_load(
        &mut self,
        address: ExprId,
        value: Value,
        bytes: u16,
    ) -> Option<ExprId> {
        let width = bytes.saturating_mul(8);
        match self.data_access(address, value, bytes, false)? {
            Access::Var(var) => Some(self.read(var)),
            Access::Address(address) => {
                let ty = self.bits(width);
                Some(self.add(Expr::Load { address, ty }, width))
            }
        }
    }

    /// The place of a store of `bytes` bytes at `address` (of L1 value
    /// `value`), if the address is in the image's data (and not
    /// read-only): the variable written, or the bytes at its address.
    pub(super) fn data_store(
        &mut self,
        address: ExprId,
        value: Value,
        bytes: u16,
    ) -> Option<Place> {
        let width = bytes.saturating_mul(8);
        Some(match self.data_access(address, value, bytes, true)? {
            Access::Var(var) => Place::Var(var),
            Access::Address(address) => Place::Memory {
                address,
                ty: self.bits(width),
            },
        })
    }

    /// `address` (of L1 value `value`) of an atomic access of `bytes`
    /// bytes (`write`: one that stores): in the image's data, a variable's
    /// address plus an offset.
    pub(super) fn data_address(
        &mut self,
        address: ExprId,
        value: Value,
        bytes: u16,
        write: bool,
    ) -> ExprId {
        match self.data_access(address, value, bytes, write) {
            Some(Access::Var(var)) => self.address_of(var),
            Some(Access::Address(address)) => address,
            None => address,
        }
    }

    /// An argument `expr` (of L1 value `value`, if known) for a parameter
    /// of type `ty` (if declared): a string's variable's address where a
    /// `char *` is expected and it points to a string in read-only data;
    /// else as [`value`](Self::value), a declared pointer being evidence
    /// that a constant is an address.
    pub(super) fn argument(
        &mut self,
        expr: ExprId,
        value: Option<Value>,
        ty: Option<TypeId>,
    ) -> ExprId {
        let types = &self.ast.types;
        let pointee = ty.and_then(|ty| match types.get(ty) {
            Some(&Type::Pointer(target)) => Some(target),
            Some(_) | None => None,
        });
        let declared =
            pointee.is_some() || ty.is_some_and(|ty| matches!(types.get(ty), Some(Type::Code(_))));
        let character = pointee
            .flatten()
            .filter(|&target| matches!(types.get(target), Some(Type::Char { .. })));
        let wide = pointee
            .flatten()
            .filter(|&target| types.get(target) == Some(&Type::UInt(16)));
        let relocatable = self.lw.cx.data.relocatable();
        let computed = value.is_some_and(|value| !self.lw.immediate(value));
        if let Some(character) = character
            && (computed || !relocatable)
            && let Some(address) = self.pointer_constant(expr)
            && let Some(length) = self.lw.cx.data.string(address)
            && let Some(var) = self.string_var(address, length, character)
        {
            return self.address_of(var);
        }
        if let Some(unit) = wide
            && (computed || !relocatable)
            && let Some(address) = self.pointer_constant(expr)
            && let Some(length) = self.lw.cx.data.wide_string(address)
            && let Some(var) = self.string_var(address, length, unit)
        {
            return self.address_of(var);
        }
        self.value(expr, computed || (declared && !relocatable))
    }

    /// `expr`, of L1 value `value`, passed, stored or returned:
    /// [`value`](Self::value), with evidence that a constant is an
    /// address where it is computed.
    pub(super) fn passed(&mut self, expr: ExprId, value: Value) -> ExprId {
        let evidence = !self.lw.immediate(value);
        self.value(expr, evidence)
    }

    /// A constant `expr` passed, stored or returned, where there is
    /// `evidence` that it is an address: the function whose entry it is,
    /// or the address of the named object holding it plus an offset; else
    /// `expr` as it is.
    fn value(&mut self, expr: ExprId, evidence: bool) -> ExprId {
        if !evidence {
            return expr;
        }
        let Some(address) = self.pointer_constant(expr) else {
            return expr;
        };
        let lw = self.lw;
        if lw.cx.functions.contains(&address) {
            if let Some(ty) = lw.scalar_code_type(address, &mut self.ast.types) {
                return self.add(Expr::Cast { value: expr, ty }, lw.pointer);
            }
            return expr;
        }
        let Some(object) = self.object(address) else {
            return expr;
        };
        let var = self.object_var(object);
        let base = self.address_of(var);
        self.plus(base, address - object.start)
    }

    /// Whether the constant part of address `v` (an L1 value: a constant,
    /// or a constant plus something) may be one of the image's addresses:
    /// computed, or anything where the image is at a fixed address.
    fn image_address(&self, v: Value) -> bool {
        if !self.lw.cx.data.relocatable() {
            return true;
        }
        let lw = self.lw;
        let v = lw.canonical(v);
        if matches!(lw.kind(v), Kind::Const(_)) {
            return !lw.immediate(v);
        }
        let Some(&Op::Binary(Binary::Add, a, b)) = lw.defining(v).map(|(_, op)| op) else {
            return false;
        };
        [a, b]
            .into_iter()
            .find(|&operand| matches!(lw.kind(operand), Kind::Const(_)))
            .is_some_and(|constant| !lw.immediate(constant))
    }

    /// The access of `bytes` bytes at `address` (of L1 value `value`;
    /// `write`: a store), if the address is a constant in the image's
    /// data, or a named object's constant address plus a computed index,
    /// and may be one of the image's ([`image_address`](Self::image_address)).
    fn data_access(
        &mut self,
        address: ExprId,
        value: Value,
        bytes: u16,
        write: bool,
    ) -> Option<Access> {
        if bytes == 0 || bytes.saturating_mul(8) > MAX_SCALAR || !self.image_address(value) {
            return None;
        }
        if let Some(constant) = self.pointer_constant(address) {
            return self.constant_access(constant, bytes, write);
        }
        let Some(&Expr::Binary(Binary::Add, a, b)) = self.ast.expr(address) else {
            return None;
        };
        let (constant, index) = match (self.pointer_constant(a), self.pointer_constant(b)) {
            (Some(constant), None) => (constant, b),
            (None, Some(constant)) => (constant, a),
            (Some(_), Some(_)) | (None, None) => return None,
        };
        let object = self.object(constant)?;
        if write && object.read_only {
            return None;
        }
        let var = self.object_var(object);
        let offset = constant - object.start;
        self.count(object.start, offset, bytes);
        let base = self.address_of(var);
        let pointer = self.lw.pointer;
        let indexed = self.add(Expr::Binary(Binary::Add, base, index), pointer);
        Some(Access::Address(self.plus(indexed, offset)))
    }

    /// The access of `bytes` bytes at constant address `address`
    /// (`write`: a store), if it is in the image's data.
    fn constant_access(&mut self, address: u64, bytes: u16, write: bool) -> Option<Access> {
        let size = u64::from(bytes);
        let width = bytes.saturating_mul(8);
        if let Some(object) = self.object(address) {
            if !object.holds(address, size) || (write && object.read_only) {
                return None;
            }
            let var = self.object_var(object);
            let offset = address - object.start;
            if offset == 0 && self.var_width(var) == Some(width) {
                if let Some(global) = self.globals.vars.get_mut(&object.start) {
                    global.whole = true;
                }
                return Some(Access::Var(var));
            }
            self.count(object.start, offset, bytes);
            let base = self.address_of(var);
            return Some(Access::Address(self.plus(base, offset)));
        }
        let data = self.lw.cx.data;
        let read_only = data.data(address, size)?;
        if write && read_only {
            return None;
        }
        if (1..size).any(|byte| data.object(address.saturating_add(byte)).is_some()) {
            return None;
        }
        let var = self.anonymous_var(address, width);
        if self.var_width(var) == Some(width) {
            return Some(Access::Var(var));
        }
        Some(Access::Address(self.address_of(var)))
    }

    /// The named object holding `address`, if one does and is not too
    /// large to be a variable.
    fn object(&self, address: u64) -> Option<Object> {
        self.lw
            .cx
            .data
            .object(address)
            .filter(|object| (1..=MAX_OBJECT).contains(&object.size) && object.holds(address, 1))
    }

    /// The variable of `object`: of its debug information's type where
    /// that is the object's size
    /// ([`Prototypes::global`](crate::prototype::Prototypes::global)); as
    /// wide as the
    /// object where a value can be (to be read or written whole), else
    /// its bytes (retyped by [`finish_globals`](Self::finish_globals)).
    fn object_var(&mut self, object: Object) -> VarId {
        if let Some(global) = self.globals.vars.get(&object.start) {
            return global.var;
        }
        let declared = self
            .lw
            .cx
            .prototypes
            .global(object.start, &mut self.ast.types)
            .filter(|&ty| self.ast.types.width(ty) == Some(object.size * 8));
        let solved = self
            .lw
            .typed
            .as_ref()
            .and_then(|typed| typed.globals.get(&object.start).copied())
            .or_else(|| self.program_global(object.start))
            .filter(|&ty| self.ast.types.width(ty) == Some(object.size * 8));
        let (ty, evidence) = match (object.size, declared, solved) {
            (_, Some(ty), _) => (ty, Evidence::Declared),
            (_, None, Some(ty)) => (ty, Evidence::Deduced),
            (1 | 2 | 4 | 8 | 16, None, None) => (
                self.bits(u16::try_from(object.size * 8).unwrap_or(8)),
                Evidence::Default,
            ),
            (size, None, None) => {
                let element = self.bits(8);
                let ty = self.ast.types.intern(Type::Array {
                    element,
                    length: Some(size),
                });
                (ty, Evidence::Default)
            }
        };
        let var = self.var(VarKind::Global(object.start), ty, evidence, Vec::new());
        self.globals.vars.insert(
            object.start,
            Global {
                var,
                size: Some(object.size),
                whole: declared.is_some() || solved.is_some(),
                widths: BTreeMap::new(),
            },
        );
        var
    }

    /// The variable of the data no object names at `address`: as wide as
    /// most accesses at that address in the function (`width` if none
    /// is counted), of its debug information's type, else the solver's,
    /// if a scalar that wide.
    fn anonymous_var(&mut self, address: u64, width: u16) -> VarId {
        if let Some(global) = self.globals.vars.get(&address) {
            return global.var;
        }
        let program = self
            .lw
            .cx
            .schemes
            .globals()
            .get(address)
            .filter(|ty| ty.shape != GlobalShape::Declared)
            .and_then(|ty| u16::try_from(ty.size.saturating_mul(8)).ok());
        let width = match program {
            Some(bits) => bits,
            None => self
                .access_widths()
                .get(&address)
                .and_then(most)
                .unwrap_or(width),
        };
        let declared = self
            .lw
            .cx
            .prototypes
            .global(address, &mut self.ast.types)
            .filter(|&ty| {
                self.ast.types.value_width(ty) == Some(width) && scalar(self.ast.types.get(ty))
            });
        let solved = self
            .lw
            .typed
            .as_ref()
            .and_then(|typed| typed.globals.get(&address).copied())
            .or_else(|| self.program_global(address))
            .filter(|&ty| self.ast.types.value_width(ty) == Some(width));
        let (ty, evidence) = match (declared, solved) {
            (Some(ty), _) => (ty, Evidence::Declared),
            (None, Some(ty)) => (ty, Evidence::Deduced),
            (None, None) => (self.bits(width), Evidence::Default),
        };
        let var = self.var(VarKind::Global(address), ty, evidence, Vec::new());
        self.globals.vars.insert(
            address,
            Global {
                var,
                size: None,
                whole: true,
                widths: BTreeMap::new(),
            },
        );
        var
    }

    /// The variable of the string of `length` characters at `address`: an
    /// array of `character`s, its NUL included.
    fn string_var(&mut self, address: u64, length: u64, character: TypeId) -> Option<VarId> {
        if let Some(&var) = self.globals.strings.get(&(address, character)) {
            return Some(var);
        }
        let length = length
            .checked_add(1)
            .filter(|&length| length <= MAX_OBJECT)?;
        let ty = self.ast.types.intern(Type::Array {
            element: character,
            length: Some(length),
        });
        let var = self.var(VarKind::Global(address), ty, Evidence::Declared, Vec::new());
        self.globals.strings.insert((address, character), var);
        Some(var)
    }

    /// The program's type of the global at `start`
    /// ([`crate::typing::Globals`]) where the function's solve did not run
    /// (rounding gives it otherwise, as the solver's type), interned.
    fn program_global(&mut self, start: u64) -> Option<TypeId> {
        if self.lw.typed.is_some() {
            return None;
        }
        let schemes = self.lw.cx.schemes;
        schemes.globals().get(start)?.intern(
            schemes.structs(),
            &mut self.ast.types,
            &mut self.globals.interned,
        )
    }

    /// The widths of the loads and stores at each constant address of the
    /// function (not the frame's), counted once.
    fn access_widths(&mut self) -> &BTreeMap<u64, BTreeMap<u16, usize>> {
        let lw = self.lw;
        self.globals.accesses.get_or_insert_with(|| {
            let mut accesses: BTreeMap<u64, BTreeMap<u16, usize>> = BTreeMap::new();
            for (_, block) in lw.blocks() {
                for &inst in &block.insts {
                    let (address, width) = match lw.l1.inst(inst).map(|i| &i.op) {
                        Some(&Op::Load { address, bytes, .. }) => {
                            (address, bytes.saturating_mul(8))
                        }
                        Some(&Op::Store { address, value, .. }) => (address, lw.width(value)),
                        Some(_) | None => continue,
                    };
                    if width > MAX_SCALAR || lw.frame.accesses.contains_key(&inst) {
                        continue;
                    }
                    if let Kind::Const(bits) = lw.kind(address) {
                        *accesses
                            .entry(bits.low_u64())
                            .or_default()
                            .entry(width)
                            .or_default() += 1;
                    }
                }
            }
            accesses
        })
    }

    /// Counts an access of `bytes` bytes at `offset` into the object at
    /// `start`, if the offset is a multiple of its size.
    fn count(&mut self, start: u64, offset: u64, bytes: u16) {
        if bytes == 0 || !offset.is_multiple_of(u64::from(bytes)) {
            return;
        }
        if let Some(global) = self.globals.vars.get_mut(&start) {
            *global.widths.entry(bytes.saturating_mul(8)).or_default() += 1;
        }
    }

    /// Types the named objects' variables not accessed whole: an array of
    /// the elements most of their aligned accesses are, where the object
    /// is a whole number of them.
    pub(super) fn finish_globals(&mut self) {
        let globals: Vec<Global> = self.globals.vars.values().cloned().collect();
        for global in globals {
            let Some(size) = global.size else {
                continue;
            };
            if global.whole {
                continue;
            }
            let fits = global
                .widths
                .iter()
                .filter(|&(&width, _)| width >= 8 && size.is_multiple_of(u64::from(width / 8)))
                .map(|(&width, &count)| (width, count))
                .collect::<BTreeMap<u16, usize>>();
            let Some(width) = most(&fits) else {
                continue;
            };
            let element = self.bits(width);
            let ty = self.ast.types.intern(Type::Array {
                element,
                length: Some(size / u64::from(width / 8)),
            });
            if let Some(variable) = self.ast.variables.get_mut(global.var.0 as usize) {
                variable.ty = ty;
            }
        }
    }

    /// The pointer-wide constant `expr` is, if it is one.
    fn pointer_constant(&self, expr: ExprId) -> Option<u64> {
        if let Some(&Expr::Const(bits)) = self.ast.expr(expr)
            && bits.width() == self.lw.pointer
        {
            return Some(bits.low_u64());
        }
        None
    }

    /// The width of variable `var`'s value, if it has one.
    fn var_width(&self, var: VarId) -> Option<u16> {
        let variable = self.ast.var(var)?;
        self.ast.types.value_width(variable.ty)
    }

    /// `&var`.
    fn address_of(&mut self, var: VarId) -> ExprId {
        self.add(Expr::AddressOf(var), self.lw.pointer)
    }

    /// `base + offset` (`base` for 0).
    fn plus(&mut self, base: ExprId, offset: u64) -> ExprId {
        if offset == 0 {
            return base;
        }
        let pointer = self.lw.pointer;
        let offset = self.constant(Bits::from_u64(pointer, offset));
        self.add(Expr::Binary(Binary::Add, base, offset), pointer)
    }
}

/// The width counted most (the widest of those tied).
fn most(widths: &BTreeMap<u16, usize>) -> Option<u16> {
    widths
        .iter()
        .max_by_key(|&(&width, &count)| (count, width))
        .map(|(&width, _)| width)
}
