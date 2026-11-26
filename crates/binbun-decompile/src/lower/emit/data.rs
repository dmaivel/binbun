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
//! - An access at a constant base plus a computed index whose bytes the
//!   index's values keep inside one named object is that object's
//!   element, whether the address is computed where it is used or held
//!   in a variable (its definition is then the variable's address plus
//!   the index), where the object is an array of elements as wide as the
//!   access, the base a whole number of them from its start and the index
//!   a count of them (scaled by their size); else it keeps its address
//!   arithmetic. One whose bytes they keep in data no object
//!   names is an element of a table there: a `Global` variable at its
//!   first byte, an array of the elements most of its accesses read and
//!   write (of their type where they all have one), from the first byte
//!   the accesses through all addresses whose reaches overlap may reach to
//!   the last, aligned to an element; where none of those bytes is a
//!   named object's, the bytes are data of one section (writable where
//!   one of them stores), no access at a constant address in the function
//!   is partly in them, and no other table takes them; an access is its
//!   element as in a named object. An access at a
//!   constant address inside a table is its element (at the table's
//!   address plus an offset), a string there is no variable of its own,
//!   and one partly inside it stays a number: the C declares no two
//!   objects that share a byte. The index's values are those its
//!   definition shows ([`Emit::index_values`]: a zero extension, a mask,
//!   a shift, a remainder, a scale); an index they do not bound keeps
//!   its access as address arithmetic, since C lets a compiler assume an
//!   array's index stays in it, and the accesses through it apart from
//!   every other object.
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
use alloc::vec;
use alloc::vec::Vec;

use binbun_ast::ir::{Expr, ExprId, Origin, Place, Stmt, StmtId, VarId, VarKind};
use binbun_ast::types::{Evidence, Type, TypeId};
use binbun_semantics::bits::Bits;
use binbun_semantics::ir::Binary;
use binbun_ssa::ir::{InstId, Op, Value};

use super::{Emit, Kind, scalar};
use crate::data::Object;
use crate::lower::calls::MAX_SCALAR;
use crate::typing::{GlobalShape, StructId};

/// The largest object (in bytes) that is a variable: a symbol's size past
/// this is no object C can declare.
const MAX_OBJECT: u64 = 1 << 32;

/// The largest table (in bytes) of data no object names that is a
/// variable: each of its bytes is checked for a named object.
const MAX_TABLE: u64 = 1 << 16;

/// How many operations deep [`Emit::index_values`] reads an index's
/// definition.
const DEPTH: u8 = 8;

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

/// What holds the bytes the accesses through one address of a constant
/// base plus an index reach ([`Tables::indexed`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Within {
    /// The named object starting at this byte.
    Object(u64),
    /// The table starting at this byte.
    Table(u64),
}

/// A table of data no object names (see the [module](self)).
#[derive(Clone, Debug)]
struct Table {
    /// Its size in bytes.
    size: u64,
    /// Whether the program cannot change its bytes.
    read_only: bool,
    /// Its type: an array of its elements.
    ty: TypeId,
    /// The evidence of that type.
    evidence: Evidence,
    /// Its variable, once made.
    var: Option<VarId>,
}

/// The function's accesses at a constant base plus an index whose bytes
/// the index's values keep inside one named object or one table.
#[derive(Clone, Debug, Default)]
pub(super) struct Tables {
    /// By address (a canonical L1 value): its base, what holds the bytes
    /// its accesses reach, and the width of each (in bits).
    indexed: BTreeMap<Value, (u64, Within, Vec<u16>)>,
    /// The tables, by first byte.
    tables: BTreeMap<u64, Table>,
}

/// The accesses through one address of a constant base plus an index
/// ([`Emit::find_tables`]).
struct Through {
    /// The base.
    base: u64,
    /// The first byte they may reach.
    low: u64,
    /// The byte past the last they may reach.
    high: u64,
    /// Whether one of them stores.
    write: bool,
    /// Each one's instruction and width (in bits).
    accesses: Vec<(InstId, u16)>,
}

/// A variable's definition that is a constant base plus an index into an
/// object or a table ([`Emit::held_addresses`]).
struct Held {
    /// The statement defining it.
    stmt: StmtId,
    /// Its value: the base plus the index.
    old: ExprId,
    /// The index.
    index: ExprId,
    /// The base.
    base: u64,
    /// The widths (in bits) of the accesses through it.
    widths: Vec<u16>,
    /// The first byte of the object or table.
    start: u64,
    /// Its variable.
    var: VarId,
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
    /// The accesses through a constant base plus a bounded index, found on
    /// first use.
    tables: Option<Tables>,
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
            && self
                .table_bytes(address, length.saturating_add(1))
                .is_none()
            && let Some(var) = self.string_var(address, length, character)
        {
            return self.address_of(var);
        }
        if let Some(unit) = wide
            && (computed || !relocatable)
            && let Some(address) = self.pointer_constant(expr)
            && let Some(length) = self.lw.cx.data.wide_string(address)
            && self
                .table_bytes(address, length.saturating_add(1).saturating_mul(2))
                .is_none()
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
    /// or a constant plus an index its values keep inside a named object
    /// or a table ([`Tables::indexed`]), and may be one of the image's
    /// ([`image_address`](Self::image_address)).
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
        let Some(object) = self.object(constant) else {
            let canonical = self.lw.canonical(value);
            let (base, within) = self
                .tables()
                .indexed
                .get(&canonical)
                .map(|&(base, within, _)| (base, within))?;
            if base != constant || (write && self.read_only(within)) {
                return None;
            }
            let bits = bytes.saturating_mul(8);
            let (start, var) = self.within_var(within, constant, &[bits])?;
            // A named object's type still to be found ([`finish_globals`])
            // counts this access.
            let pending = matches!(within, Within::Object(_))
                && self
                    .globals
                    .vars
                    .get(&start)
                    .is_some_and(|global| !global.whole);
            if !pending && !self.elements(var, start, constant, index, &[bits]) {
                return None;
            }
            return Some(Access::Address(self.indexed(var, start, constant, index)));
        };
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
        // In a table: its element, or (partly in it) a number.
        if let Some((start, holds)) = self.table_bytes(address, size) {
            if !holds {
                return None;
            }
            let var = self.table_var(start)?;
            let base = self.address_of(var);
            return Some(Access::Address(self.plus(base, address - start)));
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
    /// is a whole number of them (counting the accesses through variables
    /// holding an address that is a constant plus an index into a named
    /// object or a table: [`held_addresses`](Self::held_addresses)); then
    /// the definitions of those variables whose accesses are its elements
    /// become its variable's address plus the index.
    pub(super) fn finish_globals(&mut self) {
        let held = self.held_addresses();
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
        for held in held {
            if !self.elements(held.var, held.start, held.base, held.index, &held.widths) {
                continue;
            }
            let address = self.indexed(held.var, held.start, held.base, held.index);
            let origins = self.ast.provenance.expr(held.old).to_vec();
            if !origins.is_empty() {
                self.ast.provenance.set_expr(address, &origins);
            }
            if let Some(Stmt::Assign { value, .. } | Stmt::Expr(value)) =
                self.ast.stmts.get_mut(held.stmt.0 as usize)
            {
                *value = address;
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

    /// The definitions of the variables that hold an address in
    /// [`Tables::indexed`] (their statements' L1 value), where each is the
    /// address's base plus its index, with the variable of the object or
    /// table holding the bytes ([`within_var`](Self::within_var)). A
    /// definition rewritten is a new expression, built after its operands,
    /// with the old one's origins.
    fn held_addresses(&mut self) -> Vec<Held> {
        self.tables();
        let Some(tables) = self.globals.tables.as_ref() else {
            return Vec::new();
        };
        if tables.indexed.is_empty() {
            return Vec::new();
        }
        let mut found_all = Vec::new();
        for (id, stmt) in (0..).zip(&self.ast.stmts) {
            let (Stmt::Assign { value, .. } | Stmt::Expr(value)) = *stmt else {
                continue;
            };
            let found = self
                .ast
                .provenance
                .stmt(StmtId(id))
                .iter()
                .find_map(|origin| {
                    if let Origin::Value(v) = origin {
                        tables.indexed.get(v)
                    } else {
                        None
                    }
                });
            if let Some((base, within, widths)) = found {
                found_all.push((StmtId(id), value, *base, *within, widths.clone()));
            }
        }
        let mut held = Vec::new();
        for (stmt, old, base, within, widths) in found_all {
            let Some(&Expr::Binary(Binary::Add, a, b)) = self.ast.expr(old) else {
                continue;
            };
            let index = match (self.pointer_constant(a), self.pointer_constant(b)) {
                (Some(constant), None) if constant == base => b,
                (None, Some(constant)) if constant == base => a,
                _ => continue,
            };
            let Some((start, var)) = self.within_var(within, base, &widths) else {
                continue;
            };
            held.push(Held {
                stmt,
                old,
                index,
                base,
                widths,
                start,
                var,
            });
        }
        held
    }

    /// The first byte and variable of the object or table `within` that
    /// holds the bytes of accesses `widths` bits wide at constant `base`
    /// plus an index (counted into a named object, as at its constant
    /// address).
    fn within_var(&mut self, within: Within, base: u64, widths: &[u16]) -> Option<(u64, VarId)> {
        Some(match within {
            Within::Object(start) => {
                let object = self.object(start)?;
                let var = self.object_var(object);
                if let Some(offset) = base.checked_sub(start) {
                    for &bits in widths {
                        self.count(start, offset, bits / 8);
                    }
                }
                (start, var)
            }
            Within::Table(start) => (start, self.table_var(start)?),
        })
    }

    /// Whether accesses `widths` bits wide at constant `base` plus `index`
    /// are elements of variable `var` (starting at `start`): an array of
    /// elements that wide, `base` a whole number of them from its start,
    /// and the index a count of them (a product or left shift by a
    /// constant giving their size, or one byte's).
    fn elements(&self, var: VarId, start: u64, base: u64, index: ExprId, widths: &[u16]) -> bool {
        let Some(variable) = self.ast.var(var) else {
            return false;
        };
        let Some(&Type::Array { element, .. }) = self.ast.types.get(variable.ty) else {
            return false;
        };
        let Some(bits) = self.ast.types.width(element) else {
            return false;
        };
        let size = i128::from(bits / 8);
        size > 0
            && widths.iter().all(|&width| u64::from(width) == bits)
            && (i128::from(base) - i128::from(start)).rem_euclid(size) == 0
            && self.stride(index) == size
    }

    /// The bytes one step of index expression `index` moves: the constant
    /// of a product, a power of two for a left shift by a constant, else 1.
    fn stride(&self, index: ExprId) -> i128 {
        let constant = |id: ExprId| match self.ast.expr(id) {
            Some(Expr::Const(bits)) if bits.width() <= 64 => Some(i128::from(bits.low_u64())),
            Some(_) | None => None,
        };
        match self.ast.expr(index) {
            Some(&Expr::Binary(Binary::Mul, a, b)) => {
                constant(b).or_else(|| constant(a)).unwrap_or(1)
            }
            Some(&Expr::Binary(Binary::Shl, _, b)) => constant(b)
                .filter(|&count| count < 32)
                .map_or(1, |count| 1 << count),
            Some(_) | None => 1,
        }
    }

    /// `index` plus constant `base`, inside variable `var` starting at
    /// `start`: the variable's address plus the index plus the base's
    /// offset from it.
    fn indexed(&mut self, var: VarId, start: u64, base: u64, index: ExprId) -> ExprId {
        let address = self.address_of(var);
        let pointer = self.lw.pointer;
        let indexed = self.add(Expr::Binary(Binary::Add, address, index), pointer);
        self.plus(indexed, base.wrapping_sub(start))
    }

    /// Whether the program cannot change the bytes of the object or table
    /// `within`.
    fn read_only(&self, within: Within) -> bool {
        match within {
            Within::Object(start) => self.object(start).is_none_or(|object| object.read_only),
            Within::Table(start) => self
                .globals
                .tables
                .as_ref()
                .and_then(|tables| tables.tables.get(&start))
                .is_none_or(|table| table.read_only),
        }
    }

    /// The table the `bytes` bytes at `address` meet, by first byte, and
    /// whether it holds them all (tables share no byte).
    fn table_bytes(&mut self, address: u64, bytes: u64) -> Option<(u64, bool)> {
        let end = address.saturating_add(bytes);
        let (&start, table) = self.tables().tables.range(..end).next_back()?;
        let last = start.saturating_add(table.size);
        (last > address).then_some((start, start <= address && end <= last))
    }

    /// The variable of the table starting at `start`, made on first use.
    fn table_var(&mut self, start: u64) -> Option<VarId> {
        let table = self.globals.tables.as_ref()?.tables.get(&start)?;
        if let Some(var) = table.var {
            return Some(var);
        }
        let (ty, evidence) = (table.ty, table.evidence);
        let var = self.var(VarKind::Global(start), ty, evidence, Vec::new());
        if let Some(table) = self
            .globals
            .tables
            .as_mut()
            .and_then(|tables| tables.tables.get_mut(&start))
        {
            table.var = Some(var);
        }
        Some(var)
    }

    /// The function's accesses at a constant base plus a bounded index and
    /// its tables ([`find_tables`](Self::find_tables)), found once.
    fn tables(&mut self) -> &Tables {
        if self.globals.tables.is_none() {
            let tables = self.find_tables();
            self.globals.tables = Some(tables);
        }
        self.globals.tables.get_or_insert_default()
    }

    /// The loads and stores (not the frame's) at a constant base plus an
    /// index ([`reach`](Self::reach)), by address: those whose bytes one
    /// named object holds are in it; the others, grouped where their
    /// reaches overlap, make the tables the [module](self)'s rules allow.
    fn find_tables(&mut self) -> Tables {
        let lw = self.lw;
        let mut through: BTreeMap<Value, Through> = BTreeMap::new();
        let mut constants: Vec<(u64, u64)> = Vec::new();
        for (_, block) in lw.blocks() {
            for &inst in &block.insts {
                let (address, bits, write) = match lw.l1.inst(inst).map(|i| &i.op) {
                    Some(&Op::Load { address, bytes, .. }) => {
                        (address, bytes.saturating_mul(8), false)
                    }
                    Some(&Op::Store { address, value, .. }) => (address, lw.width(value), true),
                    Some(_) | None => continue,
                };
                if bits == 0
                    || !bits.is_multiple_of(8)
                    || bits > MAX_SCALAR
                    || lw.frame.accesses.contains_key(&inst)
                {
                    continue;
                }
                let bytes = u64::from(bits / 8);
                if let Kind::Const(at) = lw.kind(address) {
                    constants.push((at.low_u64(), bytes));
                    continue;
                }
                let address = lw.canonical(address);
                let Some((base, low, high)) = self.reach(address, bytes) else {
                    continue;
                };
                let entry = through.entry(address).or_insert(Through {
                    base,
                    low,
                    high,
                    write: false,
                    accesses: Vec::new(),
                });
                entry.low = entry.low.min(low);
                entry.high = entry.high.max(high);
                entry.write |= write;
                entry.accesses.push((inst, bits));
            }
        }
        let mut tables = Tables::default();
        let mut anonymous: Vec<(Value, Through)> = Vec::new();
        for (address, through) in through {
            let Some(object) = self.object(through.low) else {
                anonymous.push((address, through));
                continue;
            };
            if object.holds(through.low, through.high - through.low)
                && !(through.write && object.read_only)
            {
                let widths = through.accesses.iter().map(|&(_, bits)| bits).collect();
                let within = Within::Object(object.start);
                tables
                    .indexed
                    .insert(address, (through.base, within, widths));
            }
        }
        anonymous.sort_by_key(|(_, through)| through.low);
        let mut groups: Vec<Vec<(Value, Through)>> = Vec::new();
        let mut end = 0;
        for (address, through) in anonymous {
            match groups.last_mut() {
                Some(group) if through.low < end => {
                    end = end.max(through.high);
                    group.push((address, through));
                }
                Some(_) | None => {
                    end = through.high;
                    groups.push(vec![(address, through)]);
                }
            }
        }
        let mut taken = 0;
        for group in groups {
            let Some((start, table)) = self.table(&group, &constants) else {
                continue;
            };
            if start < taken {
                continue;
            }
            taken = start + table.size;
            tables.tables.insert(start, table);
            for (address, through) in group {
                let widths = through.accesses.iter().map(|&(_, bits)| bits).collect();
                let within = Within::Table(start);
                tables
                    .indexed
                    .insert(address, (through.base, within, widths));
            }
        }
        tables
    }

    /// The table of data no object names that the accesses `group` (whose
    /// reaches overlap) make, by first byte, where the [module](self)'s
    /// rules allow one: no access at a constant address (`constants`:
    /// address and size) is partly in it.
    fn table(
        &mut self,
        group: &[(Value, Through)],
        constants: &[(u64, u64)],
    ) -> Option<(u64, Table)> {
        let mut widths: BTreeMap<u16, usize> = BTreeMap::new();
        for (_, through) in group {
            for &(_, bits) in &through.accesses {
                *widths.entry(bits).or_default() += 1;
            }
        }
        let bits = most(&widths)?;
        let element = u64::from(bits / 8);
        let low = group.iter().map(|(_, through)| through.low).min()?;
        let high = group.iter().map(|(_, through)| through.high).max()?;
        let start = low - low % element;
        let end = high.checked_next_multiple_of(element)?;
        let size = end - start;
        if size > MAX_TABLE {
            return None;
        }
        let data = self.lw.cx.data;
        let read_only = data.data(start, size)?;
        if read_only && group.iter().any(|(_, through)| through.write) {
            return None;
        }
        if (start..end).any(|byte| data.object(byte).is_some()) {
            return None;
        }
        let partly = |&(at, bytes): &(u64, u64)| {
            let last = at.saturating_add(bytes);
            at < end && last > start && (at < start || last > end)
        };
        if constants.iter().any(partly) {
            return None;
        }
        let insts: Vec<InstId> = group
            .iter()
            .flat_map(|(_, through)| &through.accesses)
            .filter(|&&(_, width)| width == bits)
            .map(|&(inst, _)| inst)
            .collect();
        let untyped = self.bits(bits);
        let mut types = insts.into_iter().map(|inst| self.access_type(inst, bits));
        let first = types.next().unwrap_or(untyped);
        let agreed = types.all(|ty| ty == first) && scalar(self.ast.types.get(first));
        let (element_ty, evidence) = if agreed && first != untyped {
            (first, Evidence::Deduced)
        } else {
            (untyped, Evidence::Default)
        };
        let ty = self.ast.types.intern(Type::Array {
            element: element_ty,
            length: Some(size / element),
        });
        let table = Table {
            size,
            read_only,
            ty,
            evidence,
            var: None,
        };
        Some((start, table))
    }

    /// Where address `v` (a canonical L1 value) is a constant base plus a
    /// pointer-wide index and may be one of the image's
    /// ([`image_address`](Self::image_address)): the base, and the first
    /// byte an access of `bytes` bytes there may reach and the one past
    /// the last, as the index's values ([`index_values`](Self::index_values))
    /// keep them, where those are addresses (no wrap around).
    fn reach(&self, v: Value, bytes: u64) -> Option<(u64, u64, u64)> {
        let lw = self.lw;
        if !self.image_address(v) {
            return None;
        }
        let Some(&Op::Binary(Binary::Add, a, b)) = lw.defining(v).map(|(_, op)| op) else {
            return None;
        };
        let (base, index) = match (lw.kind(a), lw.kind(b)) {
            (Kind::Const(base), _) => (base, b),
            (_, Kind::Const(base)) => (base, a),
            _ => return None,
        };
        let pointer = lw.pointer;
        if pointer > 64 || lw.width(index) != pointer {
            return None;
        }
        let (low, high) = self.index_values(index, DEPTH)?;
        let base = base.low_u64();
        let first = i128::from(base) + low;
        let last = i128::from(base) + high + i128::from(bytes);
        if first < 0 || last > 1_i128 << pointer {
            return None;
        }
        Some((base, u64::try_from(first).ok()?, u64::try_from(last).ok()?))
    }

    /// The values `v` (an L1 value of at most 64 bits) may have, read
    /// signed, as its definition shows (`depth` operations deep): a sign
    /// extension's are its operand's, a zero extension's its operand's
    /// read unsigned ([`unsigned_max`](Self::unsigned_max)), a sum's,
    /// difference's, product or left shift by a constant's, and
    /// arithmetic right shift by a constant's from its operands' where
    /// they do not wrap around; else those of its unsigned reading where
    /// that is below the sign bit; else every value of its width.
    fn index_values(&self, v: Value, depth: u8) -> Option<(i128, i128)> {
        let lw = self.lw;
        let width = lw.width(v);
        if width == 0 || width > 64 {
            return None;
        }
        let half = 1_i128 << (width - 1);
        let all = (-half, half - 1);
        let signed = |bits: Bits| {
            let value = i128::from(bits.low_u64() & (u64::MAX >> (64 - width)));
            if value >= half {
                value - 2 * half
            } else {
                value
            }
        };
        if let Kind::Const(bits) = lw.kind(v) {
            let value = signed(bits);
            return Some((value, value));
        }
        if depth == 0 {
            return Some(all);
        }
        let depth = depth - 1;
        let constant = |x: Value| {
            if let Kind::Const(bits) = lw.kind(x) {
                Some(signed(bits))
            } else {
                None
            }
        };
        let values = |x: Value| self.index_values(x, depth);
        let scaled = |(low, high): (i128, i128), k: i128| {
            let (first, last) = (low.checked_mul(k)?, high.checked_mul(k)?);
            Some((first.min(last), first.max(last)))
        };
        let found = match lw.defining(v).map(|(_, op)| op) {
            Some(&Op::Extend {
                signed: true,
                value,
                ..
            }) => values(value),
            Some(&Op::Extend {
                signed: false,
                value,
                ..
            }) => self
                .unsigned_max(value, depth)
                .and_then(|max| i128::try_from(max).ok())
                .map(|max| (0, max)),
            Some(&Op::Binary(Binary::Add, a, b)) => values(a)
                .zip(values(b))
                .map(|((low_a, high_a), (low_b, high_b))| (low_a + low_b, high_a + high_b)),
            Some(&Op::Binary(Binary::Sub, a, b)) => values(a)
                .zip(values(b))
                .map(|((low_a, high_a), (low_b, high_b))| (low_a - high_b, high_a - low_b)),
            Some(&Op::Binary(Binary::Mul, a, b)) => match (constant(a), constant(b)) {
                (_, Some(k)) => values(a).and_then(|range| scaled(range, k)),
                (Some(k), None) => values(b).and_then(|range| scaled(range, k)),
                (None, None) => None,
            },
            Some(&Op::Binary(Binary::Shl, a, b)) => constant(b)
                .filter(|&k| (0..i128::from(width)).contains(&k))
                .and_then(|k| values(a).and_then(|range| scaled(range, 1 << k))),
            Some(&Op::Binary(Binary::AShr, a, b)) => constant(b)
                .filter(|&k| (0..i128::from(width)).contains(&k))
                .and_then(|k| values(a).map(|(low, high)| (low >> k, high >> k))),
            Some(_) | None => None,
        };
        if let Some((low, high)) = found
            && low >= all.0
            && high <= all.1
        {
            return Some((low, high));
        }
        let max = self.unsigned_max(v, depth)?;
        Some(match i128::try_from(max) {
            Ok(max) if max <= all.1 => (0, max),
            Ok(_) | Err(_) => all,
        })
    }

    /// The largest value `v` (an L1 value of at most 128 bits) may have,
    /// read unsigned, as its definition shows (`depth` operations deep):
    /// a constant; a zero extension's operand's (a sign extension's where
    /// that is not negative: [`index_values`](Self::index_values)); an
    /// `and`'s smaller operand's; an `or`'s or exclusive `or`'s bits; a
    /// logical right shift, quotient or remainder by a constant's; a sum,
    /// product or left shift by a constant's; the bits extracted; either
    /// value selected; at most all of its bits set.
    fn unsigned_max(&self, v: Value, depth: u8) -> Option<u128> {
        let lw = self.lw;
        let width = lw.width(v);
        if width == 0 || width > 128 {
            return None;
        }
        let all = u128::MAX >> (128 - width);
        if let Kind::Const(bits) = lw.kind(v) {
            return Some(bits.low_u128() & all);
        }
        if depth == 0 {
            return Some(all);
        }
        let depth = depth - 1;
        let constant = |x: Value| {
            if let Kind::Const(bits) = lw.kind(x) {
                Some(bits.low_u128())
            } else {
                None
            }
        };
        let max = |x: Value| self.unsigned_max(x, depth);
        let found = match lw.defining(v).map(|(_, op)| op) {
            Some(&Op::Extend {
                signed: false,
                value,
                ..
            }) => max(value),
            Some(&Op::Extend {
                signed: true,
                value,
                ..
            }) => self
                .index_values(value, depth)
                .filter(|&(low, _)| low >= 0)
                .and_then(|_| max(value)),
            Some(&Op::Extract { value, offset, .. }) => {
                max(value).map(|max| max.checked_shr(u32::from(offset)).unwrap_or(0))
            }
            Some(&Op::Select {
                then, otherwise, ..
            }) => max(then)
                .zip(max(otherwise))
                .map(|(first, second)| first.max(second)),
            Some(&Op::Binary(op, a, b)) => {
                let (left, right) = (max(a), max(b));
                let shift = |count: u128| u32::try_from(count).ok().filter(|&count| count < 128);
                match op {
                    Binary::And => match (left, right) {
                        (Some(first), Some(second)) => Some(first.min(second)),
                        (first, second) => first.or(second),
                    },
                    Binary::Or | Binary::Xor => left
                        .zip(right)
                        .map(|(first, second)| u128::MAX >> first.max(second).leading_zeros()),
                    Binary::LShr => constant(b).and_then(|count| {
                        left.map(|first| shift(count).map_or(0, |count| first >> count))
                    }),
                    Binary::UDiv => constant(b)
                        .filter(|&divisor| divisor > 0)
                        .and_then(|divisor| left.map(|first| first / divisor)),
                    Binary::URem => constant(b)
                        .filter(|&divisor| divisor > 0)
                        .map(|divisor| left.map_or(divisor - 1, |first| first.min(divisor - 1))),
                    Binary::Add => left
                        .zip(right)
                        .and_then(|(first, second)| first.checked_add(second)),
                    Binary::Mul => left
                        .zip(right)
                        .and_then(|(first, second)| first.checked_mul(second)),
                    Binary::Shl => constant(b)
                        .and_then(shift)
                        .and_then(|count| left?.checked_mul(1 << count)),
                    Binary::Sub
                    | Binary::SDiv
                    | Binary::SRem
                    | Binary::AShr
                    | Binary::Rol
                    | Binary::Ror
                    | Binary::Eq
                    | Binary::Ne
                    | Binary::ULt
                    | Binary::ULe
                    | Binary::SLt
                    | Binary::SLe => None,
                }
            }
            Some(_) | None => None,
        };
        // Past its bits a sum, product or shift wraps around: any value.
        Some(found.map_or(all, |found| found.min(all)))
    }
}

/// The width counted most (the widest of those tied).
fn most(widths: &BTreeMap<u16, usize>) -> Option<u16> {
    widths
        .iter()
        .max_by_key(|&(&width, &count)| (count, width))
        .map(|(&width, _)| width)
}
