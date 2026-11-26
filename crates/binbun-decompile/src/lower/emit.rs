//! Building the L2 function: variables, expressions (folded values built
//! at their use, with an explicit stack), statements block by block, the
//! copies on edges, and the [`Mapping`]; constant addresses in the
//! image's data and code as its variables and functions ([`data`]).

mod data;
mod folded;
mod frame_code;

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use binbun_ast::ir::{
    Arm, Call, Callee as AstCallee, Escape, Expr, ExprId, Function as Ast, Handler, HandlerKind,
    LabelId, Name, NameOrigin, Origin, Place, SiteInput, Stmt, StmtId, VarId, VarKind, Variable,
};
use binbun_ast::types::{Aggregate, Evidence, Field, Type, TypeId, Types};
use binbun_semantics::bits::Bits;
use binbun_semantics::ir::{Binary, FloatOp, FloatOutput, LaneOp, RegisterId};
use binbun_ssa::condition::{FloatRelation, Relation};
use binbun_ssa::ir::{BlockId, Definition, InstId, Op, Target, Terminator, Unknown, Value};

use super::calls::{Callee, classed, integer_class, vector_class};
use super::facts::{Def, Kind, Lowering, Site};
use super::frame::{Home, Region};
use super::needed::{Role, Use};
use super::variadic::Walked;
use super::{DebugCounts, LowerError};
use crate::itanium::exception_value;
use crate::mapping::{CallSite, Mapping, Piece, Source};

/// The L2 function being built.
struct Emit<'e, 'a, 'c> {
    lw: &'e Lowering<'a, 'c>,
    ast: Ast,
    /// The width of each expression built.
    widths: Vec<u16>,
    /// The variable of each class.
    classes: Vec<Option<VarId>>,
    /// The parameters' variables.
    params: Vec<VarId>,
    /// The environment variables: the thread pointer's, the
    /// floating-point control register's.
    environment: Vec<(RegisterId, VarId)>,
    /// The variable of each local's slot.
    slots: BTreeMap<usize, VarId>,
    /// The `Frame` variables: the frame's regions, then the anchor.
    regions: Vec<(Region, VarId)>,
    /// The region addresses are taken from where no region holds them.
    anchor: Option<usize>,
    /// Each block's label.
    labels: BTreeMap<u32, LabelId>,
    /// The expression of each value built (a variable's read, a folded
    /// value's expression).
    memo: BTreeMap<Value, ExprId>,
    mapping: Mapping,
    copies: usize,
    /// The variables of the image's data.
    globals: data::Globals,
    /// The `va_list` a `va_start` writes ([`Lowering::va`]).
    va_list: Option<VarId>,
    /// The `va_list`'s `reg_save_area` and `overflow_arg_area` as its
    /// `va_start` left them, where the function reads its unnamed
    /// arguments through them itself ([`Self::walked`]).
    va_save: Option<VarId>,
    va_stack: Option<VarId>,
    /// The debug information's frame variables ([`Lowering::debug`])
    /// that name an L2 variable or field, and whether each types it too.
    named: BTreeMap<usize, bool>,
    /// The instructions of the copies and constants seen through where
    /// values were used since the last statement ([`Self::expr`]): the
    /// next statement's ([`Self::stmt`]), which reads them.
    seen: Vec<u64>,
}

impl Lowering<'_, '_> {
    /// The L2 function and its mapping.
    pub(super) fn emit(&mut self) -> Result<(Ast, Mapping), LowerError> {
        let mut emit = Emit::new(self);
        emit.variables();
        emit.body()?;
        emit.finish_globals();
        let copies = emit.copies;
        let debug_counts = emit.debug_counts();
        let Emit { ast, mapping, .. } = emit;
        self.copies = copies;
        self.debug_counts = debug_counts;
        Ok((ast, mapping))
    }
}

impl<'e, 'a, 'c> Emit<'e, 'a, 'c> {
    fn new(lw: &'e Lowering<'a, 'c>) -> Self {
        let mut ast = Ast::new(lw.l1.entry, lw.types.clone());
        ast.returns = lw.returns.ty;
        if lw.returns.stated {
            ast.returns_evidence = if lw.returns.open {
                Evidence::DeclaredPointer
            } else {
                Evidence::Declared
            };
        }
        if let Some(ty) = lw.typed.as_ref().and_then(|typed| typed.returns) {
            ast.returns = Some(ty);
            ast.returns_evidence = deduced(ast.returns_evidence);
        }
        // What is returned in a vector register is, to C, a
        // floating-point value.
        if let ([piece], Some(ty)) = (&lw.returns.pieces[..], ast.returns)
            && lw.cx.convention.float_results.contains(&piece.register)
        {
            ast.returns = Some(vector_class(&mut ast.types, ty));
        }
        if let Some(va) = &lw.va {
            ast.variadic = true;
            ast.va = Some(va.va.clone());
        }
        Self {
            lw,
            ast,
            widths: Vec::new(),
            classes: Vec::new(),
            params: Vec::new(),
            environment: Vec::new(),
            slots: BTreeMap::new(),
            regions: Vec::new(),
            anchor: None,
            labels: BTreeMap::new(),
            memo: BTreeMap::new(),
            mapping: Mapping {
                parameters: lw
                    .needed
                    .parameters
                    .iter()
                    .map(|parameter| parameter.source)
                    .collect(),
                returns: lw.returns.pieces.clone(),
                dropped: lw.cx.dropped.to_vec(),
                unnamed: lw
                    .va
                    .as_ref()
                    .map(|va| va.unnamed.clone())
                    .unwrap_or_default(),
                declared: lw
                    .needed
                    .parameters
                    .iter()
                    .filter(|parameter| {
                        matches!(
                            parameter.evidence,
                            Evidence::Declared | Evidence::DeclaredPointer
                        )
                    })
                    .filter_map(|parameter| match parameter.source {
                        Source::Register(piece) if piece.offset == 0 => Some(piece),
                        Source::Register(_) | Source::Stack { .. } => None,
                    })
                    .collect(),
                ..Mapping::default()
            },
            copies: 0,
            globals: data::Globals::default(),
            va_list: None,
            va_save: None,
            va_stack: None,
            named: BTreeMap::new(),
            seen: Vec::new(),
        }
    }

    fn bits(&mut self, width: u16) -> TypeId {
        self.ast.types.intern(Type::Bits(width))
    }

    /// The solver's type of load or store `inst`, else `bits(width)`.
    fn access_type(&mut self, inst: InstId, width: u16) -> TypeId {
        let typed = self
            .lw
            .typed
            .as_ref()
            .and_then(|typed| typed.accesses.get(&inst).copied())
            .filter(|&ty| self.ast.types.value_width(ty) == Some(width));
        typed.unwrap_or_else(|| self.bits(width))
    }

    fn var(
        &mut self,
        kind: VarKind,
        ty: TypeId,
        evidence: Evidence,
        origins: Vec<Origin>,
    ) -> VarId {
        self.ast.add_var(Variable {
            kind,
            name: None,
            ty,
            evidence,
            origins,
        })
    }

    /// A new local of `width` bits.
    fn temporary(&mut self, width: u16) -> VarId {
        let ty = self.bits(width);
        self.var(VarKind::Local, ty, Evidence::Default, Vec::new())
    }

    /// The type of a parameter at `origin` whose value has type `ty`:
    /// what is passed in a vector register is, to C, a floating-point
    /// value or a vector ([`vector_class`]), and what is passed in
    /// another register is not ([`integer_class`]).
    fn passed_type(&mut self, origin: Origin, ty: TypeId) -> TypeId {
        match origin {
            Origin::Register(register)
                if self.lw.cx.convention.float_arguments.contains(&register) =>
            {
                vector_class(&mut self.ast.types, ty)
            }
            Origin::Register(_) => integer_class(&mut self.ast.types, ty),
            Origin::Value(_)
            | Origin::Instruction(_)
            | Origin::Held(_)
            | Origin::Slot(_)
            | Origin::Block(_)
            | Origin::Absorbed(_)
            | Origin::Proved => ty,
        }
    }

    /// The parameters, the environment variable, the classes' variables,
    /// the locals of slots and the frame's regions.
    fn variables(&mut self) {
        let lw = self.lw;
        let typed = lw.typed.as_ref();
        for (index, parameter) in lw.needed.parameters.iter().enumerate() {
            let (ty, evidence) =
                match typed.and_then(|t| t.parameters.get(index).copied().flatten()) {
                    Some(ty) => (ty, deduced(parameter.evidence)),
                    None => (parameter.ty, parameter.evidence),
                };
            let ty = self.passed_type(parameter.origin, ty);
            let var = self.var(VarKind::Parameter, ty, evidence, vec![parameter.origin]);
            self.params.push(var);
            self.ast.parameters.push(var);
        }
        self.debug_parameters();
        for &register in &lw.needed.environment {
            let width = lw
                .cx
                .declarations
                .info(register)
                .map_or(0, |info| info.width);
            // The thread pointer has the type its platform declares.
            let declared = if lw.cx.convention.thread_pointer == Some(register) {
                lw.cx
                    .prototypes
                    .thread_pointer(&mut self.ast.types)
                    .filter(|&ty| self.ast.types.value_width(ty) == Some(width))
            } else {
                None
            };
            let (ty, evidence) = match declared {
                Some(ty) => (ty, Evidence::Declared),
                None => (self.bits(width), Evidence::Default),
            };
            let var = self.var(
                VarKind::Environment(register),
                ty,
                evidence,
                vec![Origin::Register(register)],
            );
            self.environment.push((register, var));
        }
        for (index, class) in lw.classes.sets.iter().enumerate() {
            if class.members.is_empty() {
                self.classes.push(None);
                continue;
            }
            let parameter = class.parameter.and_then(|index| self.params.get(index));
            let var = if let Some(&var) = parameter {
                var
            } else {
                let solved = typed.and_then(|t| t.classes.get(index).copied().flatten());
                // A type found for the whole value is none for its lane.
                let solved =
                    solved.filter(|&ty| self.ast.types.value_width(ty) == Some(class.width));
                let user = lw.user.of_values(class.members.iter().map(|v| v.0));
                let (ty, evidence) = self.typed(user, solved, class.width);
                self.var(VarKind::Local, ty, evidence, origins(lw.l1, &class.members))
            };
            self.classes.push(Some(var));
        }
        for (index, slot) in lw.frame.slots.iter().enumerate() {
            let read = lw.needed.slots.get(index).copied().unwrap_or(false);
            if slot.home != Home::Local || !read {
                continue;
            }
            let width = u16::try_from(slot.bytes().saturating_mul(8)).unwrap_or(u16::MAX);
            let solved = typed
                .and_then(|t| t.slots.get(index).copied().flatten())
                .filter(|&ty| self.ast.types.value_width(ty) == Some(width));
            let (ty, evidence) = self.typed(lw.user.at(slot.offset), solved, width);
            let var = self.var(
                VarKind::Local,
                ty,
                evidence,
                vec![Origin::Slot(slot.offset)],
            );
            self.slots.insert(index, var);
            let typing = if evidence == Evidence::Declared {
                Typing::Kept
            } else {
                Typing::Value
            };
            self.debug_variable(var, slot.offset, slot.bytes(), typing);
        }
        let list = lw.va.as_ref().and_then(|va| va.list);
        for (index, &region) in lw.frame.regions.iter().enumerate() {
            let frame_struct = lw.frame.is_struct(index, list);
            self.region(region, frame_struct);
        }
        if lw.va.as_ref().is_some_and(|va| va.start.is_some()) {
            // Microsoft's `va_list` is `char *` (its `char` is signed).
            let character = self.ast.types.intern(Type::Char { signed: true });
            let ty = self.ast.types.intern(Type::Pointer(Some(character)));
            let var = self.var(VarKind::Local, ty, Evidence::Default, Vec::new());
            self.va_list = Some(var);
        }
        if let Some(var) = self.va_list
            && let Some(variable) = self.ast.variables.get_mut(var.0 as usize)
        {
            variable.name = Some(Name::new("ap", NameOrigin::Convention));
        }
        self.walked_variables();
    }

    /// The variables holding the `va_list`'s `reg_save_area` and
    /// `overflow_arg_area` as `va_start` leaves them (`ap_registers`,
    /// `ap_stack`: byte pointers), where a needed value is an address in
    /// the save area or among the caller's stack arguments, or an
    /// unnamed integer register's entry value ([`Plan::walked`],
    /// [`Plan::saved`]): what a `va_arg` the compiler expanded in place
    /// computes with. The `va_start` assigns them ([`Self::va_start`]).
    fn walked_variables(&mut self) {
        let lw = self.lw;
        let Some(plan) = &lw.va else {
            return;
        };
        let (mut save, mut stack) = (false, false);
        for index in 0..lw.l1.values.len() {
            let value = Value(u32::try_from(index).unwrap_or(u32::MAX));
            if lw.canonical(value) != value || !lw.is_needed(value) {
                continue;
            }
            if let Kind::Address(offset) = lw.kind(value) {
                save |= matches!(plan.walked(offset), Some(Walked::Save(_)));
                stack |= matches!(plan.walked(offset), Some(Walked::Stack(_)));
            } else if let Kind::Undefined(
                _,
                Unknown::Entry {
                    register: Some(register),
                },
            ) = lw.kind(value)
            {
                save |= plan.saved(register).is_some();
            }
        }
        let byte = self.bits(8);
        let ty = self.ast.types.intern(Type::Pointer(Some(byte)));
        let named = |emit: &mut Self, name: &str| {
            let var = emit.var(VarKind::Local, ty, Evidence::Default, Vec::new());
            if let Some(variable) = emit.ast.variables.get_mut(var.0 as usize) {
                variable.name = Some(Name::new(name, NameOrigin::Convention));
            }
            var
        };
        if save {
            self.va_save = Some(named(self, "ap_registers"));
        }
        if stack {
            self.va_stack = Some(named(self, "ap_stack"));
        }
    }

    /// A variable's type of `width` bits and its evidence: the user's
    /// (declared) where as wide, else the solver's (deduced), else bits.
    fn typed(
        &mut self,
        user: Option<TypeId>,
        solved: Option<TypeId>,
        width: u16,
    ) -> (TypeId, Evidence) {
        match (
            user.filter(|&ty| self.ast.types.value_width(ty) == Some(width)),
            solved,
        ) {
            (Some(ty), _) => (ty, Evidence::Declared),
            (None, Some(ty)) => (ty, Evidence::Deduced),
            (None, None) => (self.bits(width), Evidence::Default),
        }
    }

    /// System V's `struct __va_list_tag` (24 bytes), whose array of one is
    /// its `va_list`: the one the types hold already (a declared
    /// prototype's `va_list` parameter, a pointer to it), so that passing
    /// the `va_list` on needs no cast (L2's structs are nominal), else a
    /// new one.
    fn va_tag(&mut self) -> TypeId {
        let existing = self.ast.types.iter().find_map(|(id, ty)| {
            let Type::Struct(aggregate) = ty else {
                return None;
            };
            (aggregate.name.as_deref() == Some("__va_list_tag") && aggregate.size == 24)
                .then_some(id)
        });
        if let Some(existing) = existing {
            return existing;
        }
        let offset = self.ast.types.intern(Type::UInt(32));
        let pointer = self.ast.types.intern(Type::Pointer(None));
        let fields = [
            (0, offset, "gp_offset"),
            (4, offset, "fp_offset"),
            (8, pointer, "overflow_arg_area"),
            (16, pointer, "reg_save_area"),
        ]
        .into_iter()
        .map(|(offset, ty, name)| Field {
            offset,
            ty,
            name: Some(name.into()),
        })
        .collect();
        self.ast.types.intern(Type::Struct(Aggregate {
            name: Some("__va_list_tag".into()),
            size: 24,
            fields,
        }))
    }

    /// A `Frame` variable for `region`: System V's `va_list` (an array of
    /// one `__va_list_tag`); a promoted object, of its declared type; a
    /// frame struct ([`Self::frame_struct`]) where `frame_struct`; one
    /// value, of its slot's solved type; exactly one slot accessed in
    /// parts, of the type its field of a frame struct would have
    /// ([`Self::field_type`]); else bytes.
    fn region(&mut self, region: Region, frame_struct: bool) -> usize {
        let list = self.lw.va.as_ref().and_then(|va| va.list) == Some(region.offset);
        let mut evidence = Evidence::Default;
        // A frame struct keeps its fields (the slots' variables).
        let user = self
            .lw
            .user
            .at(region.offset)
            .filter(|_| !list && !frame_struct)
            .filter(|&ty| self.ast.types.width(ty) == region.bytes.checked_mul(8));
        let ty = if let Some(ty) = user {
            evidence = Evidence::Declared;
            ty
        } else if list {
            let element = self.va_tag();
            self.ast.types.intern(Type::Array {
                element,
                length: Some(1),
            })
        } else if let Some(ty) = region.promoted {
            evidence = Evidence::Declared;
            ty
        } else if frame_struct {
            self.frame_struct(region)
        } else if region.whole {
            let width = u16::try_from(region.bytes.saturating_mul(8)).unwrap_or(u16::MAX);
            let solved = self.slot_type(region.offset, region.end(), width);
            if solved.is_some() {
                evidence = Evidence::Deduced;
            }
            solved.unwrap_or_else(|| self.bits(width))
        } else if let Some(index) = self.only_slot(region) {
            self.field_type(index, region)
        } else {
            let element = self.bits(8);
            self.ast.types.intern(Type::Array {
                element,
                length: Some(region.bytes),
            })
        };
        let var = self.var(
            VarKind::Frame(region.offset),
            ty,
            evidence,
            vec![Origin::Slot(region.offset)],
        );
        if list {
            self.va_list = Some(var);
        } else if user.is_some() {
            self.debug_variable(var, region.offset, region.bytes, Typing::Kept);
        } else if region.promoted.is_some() {
            self.ast.promoted.push(var);
            self.debug_variable(var, region.offset, region.bytes, Typing::Kept);
        } else if frame_struct {
            self.ast.frames.push(var);
        } else {
            let typing = if region.whole {
                Typing::Value
            } else {
                Typing::Memory
            };
            self.debug_variable(var, region.offset, region.bytes, typing);
        }
        self.regions.push((region, var));
        self.regions.len() - 1
    }

    /// The solver's type of the slot in memory of exactly the bytes
    /// `offset..end`, if it has one of `width` bits.
    fn slot_type(&self, offset: i64, end: i64, width: u16) -> Option<TypeId> {
        let index = self.lw.frame.slots.iter().position(|slot| {
            slot.home == Home::Frame && slot.shape && slot.offset == offset && slot.end == end
        })?;
        self.lw
            .typed
            .as_ref()
            .and_then(|typed| typed.slots.get(index).copied().flatten())
            .filter(|&ty| self.ast.types.value_width(ty) == Some(width))
    }

    /// The slot in memory that is exactly the bytes of `region`, if one
    /// is.
    fn only_slot(&self, region: Region) -> Option<usize> {
        self.lw.frame.slots.iter().position(|slot| {
            slot.home == Home::Frame && slot.offset == region.offset && slot.end == region.end()
        })
    }

    /// The struct of the frame's bytes `region`: a field per slot in
    /// memory inside it, at its offset in the region, named by its offset
    /// from the entry stack pointer (`at_m28`: entry−0x28; `at_p8`:
    /// entry+8); of the solved type of its accesses of the whole slot
    /// where it has any and that C type is exactly that wide, else of its
    /// width in bits where that is a C integer's, else bytes; the bytes no
    /// slot holds are
    /// `unknown_m<hex>[n]` (by offset likewise). Its size is the region's:
    /// C's tail padding past it is no byte of the frame's. Where a field is
    /// not at a multiple of its alignment (the struct is packed), a debug
    /// variable's field of an aggregate or array type aligned past a byte
    /// is its bytes (taking a packed member's address warns; the slots'
    /// fields are scalars).
    fn frame_struct(&mut self, region: Region) -> TypeId {
        let lw = self.lw;
        let end = region.end();
        let byte = self.ast.types.intern(Type::UInt(8));
        let mut fields = Vec::new();
        let mut at = region.offset;
        let gap = |types: &mut Types, from: i64, to: i64| {
            let ty = types.intern(Type::Array {
                element: byte,
                length: Some(to.abs_diff(from)),
            });
            Field {
                offset: from.abs_diff(region.offset),
                ty,
                name: Some(format!("unknown_{}", entry_offset(from))),
            }
        };
        // Debug information's variables inside the region whose bytes no
        // slot straddles are fields of their own, in place of the slots
        // inside them.
        let mut stated = self.debug_fields(region);
        let mut debug = Vec::new();
        let mut slots = lw.frame.slots.iter().enumerate().peekable();
        loop {
            let next_slot = slots.peek().map(|(_, slot)| slot.offset);
            if let Some(&(offset, bytes, local)) = stated.first()
                && next_slot.is_none_or(|next| offset <= next)
            {
                stated.remove(0);
                let field_end = offset.saturating_add_unsigned(bytes);
                if offset < at {
                    continue;
                }
                if offset > at {
                    fields.push(gap(&mut self.ast.types, at, offset));
                }
                let (name, ty) = self.debug_field(local, bytes);
                debug.push((fields.len(), local));
                fields.push(Field {
                    offset: offset.abs_diff(region.offset),
                    ty,
                    name: Some(name),
                });
                at = field_end;
                continue;
            }
            let Some((index, slot)) = slots.next() else {
                break;
            };
            if slot.home != Home::Frame || slot.offset < at || slot.end > end {
                continue;
            }
            if slot.offset > at {
                fields.push(gap(&mut self.ast.types, at, slot.offset));
            }
            let ty = self.field_type(index, region);
            fields.push(Field {
                offset: slot.offset.abs_diff(region.offset),
                ty,
                name: Some(format!("at_{}", entry_offset(slot.offset))),
            });
            at = slot.end;
        }
        if at < end {
            fields.push(gap(&mut self.ast.types, at, end));
        }
        let types = &self.ast.types;
        let packed = fields
            .iter()
            .any(|field| !field.offset.is_multiple_of(alignment(types, field.ty)));
        if packed {
            for (index, local) in debug {
                let Some(field) = fields.get(index) else {
                    continue;
                };
                let types = &self.ast.types;
                if scalar(types.get(field.ty)) || alignment(types, field.ty) == 1 {
                    continue;
                }
                let Some(bytes) = types.width(field.ty).map(|width| width / 8) else {
                    continue;
                };
                let element = self.bits(8);
                let ty = self.ast.types.intern(Type::Array {
                    element,
                    length: Some(bytes),
                });
                if let Some(field) = fields.get_mut(index) {
                    field.ty = ty;
                }
                self.named.insert(local, false);
            }
        }
        self.ast.types.intern(Type::Struct(Aggregate {
            name: None,
            size: region.bytes,
            fields,
        }))
    }

    /// Names the parameters from debug information where the function's
    /// prototype is its debug information's (placed where the code has its
    /// parameters: [`Prototypes::debug`](crate::prototype::Prototypes::debug)):
    /// each L2 parameter from a declared one takes its name.
    fn debug_parameters(&mut self) {
        let lw = self.lw;
        let (Some(debug), Some(declared)) = (lw.debug.as_ref(), lw.returns.declared.as_ref())
        else {
            return;
        };
        if debug.unplaced.is_some() {
            return;
        }
        for (parameter, &var) in lw.needed.parameters.iter().zip(&self.params) {
            let name = declared
                .iter()
                .position(|(source, ..)| *source == parameter.source)
                .and_then(|position| debug.parameters.get(position).cloned().flatten());
            if let Some(variable) = self.ast.variables.get_mut(var.0 as usize) {
                variable.name = name.map(|name| Name::new(name, NameOrigin::Debug));
            }
        }
    }

    /// The debug information's frame variable of exactly the bytes
    /// `offset` and `bytes` on, if one alone is (two in one place, of
    /// different scopes, name neither).
    fn debug_local(&self, offset: i64, bytes: u64) -> Option<usize> {
        let locals = &self.lw.debug.as_ref()?.locals;
        let mut found = locals
            .iter()
            .enumerate()
            .filter(|(_, local)| local.offset == offset && local.bytes == bytes)
            .map(|(index, _)| index);
        let first = found.next()?;
        found.next().is_none().then_some(first)
    }

    /// Names `var` (of the frame's bytes `offset` and `bytes` on) after
    /// the debug information's variable there, and where its type is as
    /// wide and `typing` takes it, types it (asserted:
    /// [`Evidence::Declared`]).
    fn debug_variable(&mut self, var: VarId, offset: i64, bytes: u64, typing: Typing) {
        let Some(index) = self.debug_local(offset, bytes) else {
            return;
        };
        let Some(local) = self.lw.debug.as_ref().and_then(|d| d.locals.get(index)) else {
            return;
        };
        let types = &self.ast.types;
        let ty = local
            .ty
            .filter(|&ty| types.width(ty) == bytes.checked_mul(8))
            .filter(|&ty| match typing {
                Typing::Kept => false,
                Typing::Memory => true,
                Typing::Value => scalar(types.get(ty)),
            });
        let Some(variable) = self.ast.variables.get_mut(var.0 as usize) else {
            return;
        };
        variable.name = Some(Name::new(local.name.clone(), NameOrigin::Debug));
        if let Some(ty) = ty {
            variable.ty = ty;
            variable.evidence = Evidence::Declared;
        }
        self.named.insert(index, ty.is_some());
    }

    /// The debug information's variables inside `region` (offset, bytes,
    /// index) no slot of the region straddles and no other overlaps, by
    /// offset: the frame struct's fields in their place.
    fn debug_fields(&self, region: Region) -> Vec<(i64, u64, usize)> {
        let Some(debug) = self.lw.debug.as_ref() else {
            return Vec::new();
        };
        let slots = &self.lw.frame.slots;
        let mut inside: Vec<(i64, u64, usize)> = debug
            .locals
            .iter()
            .enumerate()
            .filter(|(_, local)| {
                local.bytes > 0
                    && region.contains(local.offset)
                    && local.offset.saturating_add_unsigned(local.bytes) <= region.end()
            })
            .filter(|(_, local)| {
                let end = local.offset.saturating_add_unsigned(local.bytes);
                slots.iter().all(|slot| {
                    slot.home != Home::Frame
                        || slot.end <= local.offset
                        || slot.offset >= end
                        || (slot.offset >= local.offset && slot.end <= end)
                })
            })
            .map(|(index, local)| (local.offset, local.bytes, index))
            .collect();
        inside.sort_unstable();
        let overlapping: BTreeSet<usize> = inside
            .windows(2)
            .filter_map(|pair| match pair {
                [(a, bytes, i), (b, _, j)] if a.saturating_add_unsigned(*bytes) > *b => {
                    Some([*i, *j])
                }
                _ => None,
            })
            .flatten()
            .collect();
        inside.retain(|(_, _, index)| !overlapping.contains(index));
        inside
    }

    /// The name and type of the frame struct's field for the debug
    /// information's variable `index` of `bytes` bytes: its type where it
    /// is as wide, else bytes.
    fn debug_field(&mut self, index: usize, bytes: u64) -> (String, TypeId) {
        let local = self.lw.debug.as_ref().and_then(|d| d.locals.get(index));
        let name = local.map_or_else(String::new, |local| local.name.clone());
        let ty = local
            .and_then(|local| local.ty)
            .filter(|&ty| self.ast.types.width(ty) == bytes.checked_mul(8));
        self.named.insert(index, ty.is_some());
        let ty = ty.unwrap_or_else(|| {
            let element = self.bits(8);
            self.ast.types.intern(Type::Array {
                element,
                length: Some(bytes),
            })
        });
        (name, ty)
    }

    /// What became of the debug information's statements.
    fn debug_counts(&self) -> DebugCounts {
        let Some(debug) = self.lw.debug.as_ref() else {
            return DebugCounts::default();
        };
        let parameters_named = self
            .params
            .iter()
            .filter(|var| {
                self.ast
                    .variables
                    .get(var.0 as usize)
                    .is_some_and(|variable| variable.name.is_some())
            })
            .count();
        DebugCounts {
            stated: true,
            unplaced: debug.unplaced,
            parameters: self.params.len(),
            parameters_named,
            locals: debug.locals.len(),
            locals_named: self.named.len(),
            locals_typed: self.named.values().filter(|&&typed| typed).count(),
            registers: debug.registers,
        }
    }

    /// The type of slot `index`'s field in the frame struct of `region`
    /// ([`Self::frame_struct`]): the solved type of a slot of one shape;
    /// of a slot of at most 8 bytes accessed in several widths all at its
    /// first byte, a union of those views ([`Self::views`]); of one also
    /// accessed in other parts, the type most of its accesses of the whole
    /// slot have (the parts read or write its bytes; no constraint joins
    /// the whole accesses, which may be of different variables sharing the
    /// slot; 16 bytes accessed whole and in parts are an aggregate's copy,
    /// which stays bytes); bytes for a slot no access is all of,
    /// and for one the function never writes where no address into the
    /// region is taken (what it reads there nothing in the function wrote:
    /// C would see a field read uninitialized).
    fn field_type(&mut self, index: usize, region: Region) -> TypeId {
        let Some(slot) = self.lw.frame.slots.get(index) else {
            return self.bits(8);
        };
        let bytes = slot.bytes();
        let width = u16::try_from(bytes.saturating_mul(8)).unwrap_or(u16::MAX);
        let written = slot.written
            || self
                .lw
                .frame
                .taken
                .iter()
                .any(|&offset| region.contains(offset));
        let scalar = slot.shape || bytes <= 8;
        if written && slot.whole && scalar && matches!(bytes, 1 | 2 | 4 | 8 | 16) {
            if !slot.shape
                && let Some(views) = self.views(index)
            {
                return views;
            }
            let solved = if slot.shape {
                self.lw
                    .typed
                    .as_ref()
                    .and_then(|typed| typed.slots.get(index).copied().flatten())
            } else {
                self.whole_access_type(index, width)
            };
            let solved = solved.filter(|&ty| self.field_scalar(ty, width));
            return solved.unwrap_or_else(|| self.bits(width));
        }
        let element = self.bits(8);
        self.ast.types.intern(Type::Array {
            element,
            length: Some(bytes),
        })
    }

    /// Whether `ty` is a scalar a field holds in exactly `width` bits (no
    /// x87 extended float).
    fn field_scalar(&self, ty: TypeId, width: u16) -> bool {
        self.ast.types.value_width(ty) == Some(width)
            && match self.ast.types.get(ty) {
                Some(
                    Type::Bits(_)
                    | Type::Int(_)
                    | Type::UInt(_)
                    | Type::Char { .. }
                    | Type::Bool(_)
                    | Type::Pointer(_)
                    | Type::Code(_)
                    | Type::Enum(_),
                ) => true,
                Some(Type::Float(format)) => {
                    !matches!(format, binbun_semantics::ir::Format::Extended)
                }
                Some(
                    Type::Struct(_) | Type::Union(_) | Type::Array { .. } | Type::Vector { .. },
                )
                | None => false,
            }
    }

    /// The views of slot `index` in memory, accessed in several widths
    /// every one at its first byte (a load or store, no call's stack
    /// argument), as a union: a member `w<bits>` per width, of the solved
    /// type most of that width's accesses have where one does and is a
    /// scalar ([`Self::field_scalar`]), else bits. The members are the
    /// same bytes, so each access names its own (`frame.at_m28.w32`)
    /// instead of a cast of the slot's address.
    fn views(&mut self, index: usize) -> Option<TypeId> {
        let lw = self.lw;
        let slot = lw.frame.slots.get(index)?;
        if lw.frame.arguments.values().any(|&s| s == index) {
            return None;
        }
        let mut widths = BTreeSet::new();
        for (&inst, _) in lw.frame.accesses.iter().filter(|&(_, &s)| s == index) {
            let (address, bytes) = match lw.l1.inst(inst).map(|i| &i.op) {
                Some(&Op::Load { address, bytes, .. }) => (address, bytes),
                Some(&Op::Store { address, value, .. }) => (address, lw.width(value).div_ceil(8)),
                Some(_) | None => return None,
            };
            if lw.address(address) != Some(slot.offset) || !matches!(bytes, 1 | 2 | 4 | 8) {
                return None;
            }
            widths.insert(bytes * 8);
        }
        if widths.len() < 2 {
            return None;
        }
        let mut fields = Vec::new();
        for width in widths {
            let solved = self
                .whole_access_type(index, width)
                .filter(|&ty| self.field_scalar(ty, width));
            let ty = solved.unwrap_or_else(|| self.bits(width));
            fields.push(Field {
                offset: 0,
                ty,
                name: Some(format!("w{width}")),
            });
        }
        Some(self.ast.types.intern(Type::Union(Aggregate {
            name: None,
            size: slot.bytes(),
            fields,
        })))
    }

    /// The solved type most of the `width`-bit accesses of slot `index`
    /// have, if one does (a tie is none).
    fn whole_access_type(&self, index: usize, width: u16) -> Option<TypeId> {
        let typed = self.lw.typed.as_ref()?;
        let mut counts: BTreeMap<TypeId, usize> = BTreeMap::new();
        for (inst, _) in self
            .lw
            .frame
            .accesses
            .iter()
            .filter(|&(_, &slot)| slot == index)
        {
            if let Some(&ty) = typed.accesses.get(inst)
                && self.ast.types.value_width(ty) == Some(width)
            {
                *counts.entry(ty).or_default() += 1;
            }
        }
        let most = counts.values().copied().max()?;
        let mut best = counts.iter().filter(|&(_, &count)| count == most);
        let (&ty, _) = best.next()?;
        best.next().is_none().then_some(ty)
    }

    /// The type of the field (not an aggregate) of `width` bits that
    /// starts at `offset` in the frame struct or promoted object holding
    /// it, or of a member of a union field there, if one does: an access
    /// there takes it (the same bits, typed as the object is).
    fn field_at(&self, offset: i64, width: u16) -> Option<TypeId> {
        let &(region, var) = self.regions.iter().find(|(r, _)| r.contains(offset))?;
        let ty = self.ast.var(var)?.ty;
        let types = &self.ast.types;
        let fields = |ty| match types.get(ty) {
            Some(Type::Struct(aggregate) | Type::Union(aggregate)) => Some(&aggregate.fields),
            Some(_) | None => None,
        };
        let within = offset.abs_diff(region.offset);
        fields(ty)?
            .iter()
            .filter(|field| field.offset == within)
            .find_map(|field| {
                let Some(Type::Union(_)) = types.get(field.ty) else {
                    return (types.value_width(field.ty) == Some(width)).then_some(field.ty);
                };
                fields(field.ty)?
                    .iter()
                    .find(|member| types.value_width(member.ty) == Some(width))
                    .map(|member| member.ty)
            })
    }

    // Expressions.

    /// Adds `expr` of `width` bits, standing for `origins`.
    fn add(&mut self, expr: Expr, width: u16) -> ExprId {
        let id = self.ast.add_expr(expr);
        self.widths.push(width);
        id
    }

    fn width_of(&self, id: ExprId) -> u16 {
        self.widths.get(id.0 as usize).copied().unwrap_or(0)
    }

    fn constant(&mut self, bits: Bits) -> ExprId {
        self.add(Expr::Const(bits), bits.width())
    }

    fn undefined(&mut self, width: u16, unknown: Unknown) -> ExprId {
        self.add(Expr::Undefined(width, unknown, None), width)
    }

    /// The unknown value `x` (`width` bits, from `unknown`), with its
    /// site's inputs if L1 gives it some: those L1 knows as constants;
    /// the others not kept, since an input is no use of its value
    /// ([`Ast::inputs`]).
    fn site_undefined(&mut self, x: Value, width: u16, unknown: Unknown) -> ExprId {
        let l1 = self.lw.l1;
        let inputs = match l1.value(x).map(|info| info.definition) {
            Some(Definition::Result { inst, .. }) => match l1.inst(inst).map(|i| &i.op) {
                Some(op) => op.inputs(),
                None => &[],
            },
            Some(Definition::Parameter { .. }) | None => &[],
        };
        if inputs.is_empty() {
            return self.undefined(width, unknown);
        }
        let lw = self.lw;
        let inputs = inputs
            .iter()
            .map(|&input| match lw.constants.constant(input) {
                Some(bits) => SiteInput::Kept(bits),
                None => SiteInput::NotKept(lw.width(input)),
            })
            .collect();
        let inputs = self.ast.add_inputs(inputs);
        self.add(Expr::Undefined(width, unknown, Some(inputs)), width)
    }

    fn read(&mut self, var: VarId) -> ExprId {
        let width = self
            .ast
            .var(var)
            .and_then(|v| self.ast.types.value_width(v.ty))
            .unwrap_or(0);
        self.add(Expr::Var(var), width)
    }

    fn concat(&mut self, high: ExprId, low: ExprId) -> ExprId {
        let width = self.width_of(high).saturating_add(self.width_of(low));
        self.add(Expr::Concat { high, low }, width)
    }

    /// `width` bits of `value` from `offset`, simplified through
    /// concatenations, extensions, extractions and constants, and
    /// through a bitwise operation on a vector register's width (the
    /// bits of `andps`'s result are those bits of its operands and-ed:
    /// a `double`'s sign cleared, not a lane of a vector). Bits on both
    /// sides of a concatenation that wide are those of each side,
    /// concatenated: what a later extraction leaves out of them (the
    /// bits above the lane a variable holds, which nothing has) is then
    /// in no expression.
    fn extract(&mut self, mut value: ExprId, mut offset: u16, width: u16) -> ExprId {
        loop {
            if offset == 0 && width == self.width_of(value) {
                return value;
            }
            match self.ast.expr(value).copied() {
                Some(
                    Expr::Binary(op @ (Binary::And | Binary::Or | Binary::Xor), a, b)
                    | Expr::Lanes {
                        op: LaneOp::Binary(op @ (Binary::And | Binary::Or | Binary::Xor)),
                        operands: [a, b, _],
                        ..
                    },
                ) if self.width_of(value) > 64 && width <= 64 => {
                    let (a, b) = (
                        self.extract(a, offset, width),
                        self.extract(b, offset, width),
                    );
                    return self.add(Expr::Binary(op, a, b), width);
                }
                Some(Expr::Concat { high, low }) => {
                    let low_width = self.width_of(low);
                    if offset.saturating_add(width) <= low_width {
                        value = low;
                    } else if offset >= low_width {
                        value = high;
                        offset -= low_width;
                    } else if self.width_of(value) > 128 {
                        let above = offset.saturating_add(width).saturating_sub(low_width);
                        let high = self.extract(high, 0, above);
                        let low = self.extract(low, offset, low_width - offset);
                        return self.concat(high, low);
                    } else {
                        break;
                    }
                }
                Some(Expr::Extend { value: inner, .. })
                    if offset.saturating_add(width) <= self.width_of(inner) =>
                {
                    value = inner;
                }
                Some(Expr::Extract {
                    value: inner,
                    offset: first,
                    ..
                }) => {
                    value = inner;
                    offset = offset.saturating_add(first);
                }
                Some(Expr::Const(bits)) => return self.constant(bits.extract(offset, width)),
                // Part of a site's value is none: no inputs.
                Some(Expr::Undefined(_, unknown, _)) => return self.undefined(width, unknown),
                _ => break,
            }
        }
        self.add(
            Expr::Extract {
                value,
                offset,
                width,
            },
            width,
        )
    }

    /// Variable `var` (of `inner` bits) as a value of `width` bits whose
    /// bits from `offset` it holds, the others unknown (from `unknown`).
    fn widen(
        &mut self,
        var: VarId,
        inner: u16,
        width: u16,
        offset: u16,
        unknown: Unknown,
    ) -> ExprId {
        let mut expr = self.read(var);
        if offset > 0 {
            let low = self.undefined(offset, unknown);
            expr = self.concat(expr, low);
        }
        let high = width.saturating_sub(offset.saturating_add(inner));
        if high > 0 {
            let top = self.undefined(high, unknown);
            expr = self.concat(top, expr);
        }
        if self.width_of(expr) > width {
            expr = self.extract(expr, 0, width);
        }
        expr
    }

    /// The address `offset` bytes from the entry stack pointer.
    fn address(&mut self, offset: i64) -> ExprId {
        // Microsoft's `va_list` points to the first unnamed argument.
        if let Some(var) = self.va_list
            && self.lw.va.as_ref().and_then(|va| va.start) == Some(offset)
        {
            return self.read(var);
        }
        // System V's save area and the caller's stack arguments, which
        // C has through the `va_list` alone.
        let walked = self.lw.va.as_ref().and_then(|va| va.walked(offset));
        if let Some((Some(var), delta)) = walked.map(|walked| match walked {
            Walked::Save(delta) => (self.va_save, delta),
            Walked::Stack(delta) => (self.va_stack, delta),
        }) {
            let base = self.read(var);
            return self.moved(base, delta);
        }
        let index = match self.regions.iter().position(|(r, _)| r.contains(offset)) {
            Some(index) => index,
            None => self.anchor(),
        };
        let Some(&(region, var)) = self.regions.get(index) else {
            return self.undefined(self.lw.pointer, Unknown::Lowering);
        };
        let pointer = self.lw.pointer;
        let base = self.add(Expr::AddressOf(var), pointer);
        let delta = offset.wrapping_sub(region.offset);
        self.moved(base, delta)
    }

    /// Address `base` moved `delta` bytes on.
    fn moved(&mut self, base: ExprId, delta: i64) -> ExprId {
        let pointer = self.lw.pointer;
        if delta == 0 {
            return base;
        }
        let (op, amount) = if delta > 0 {
            (Binary::Add, delta.unsigned_abs())
        } else {
            (Binary::Sub, delta.unsigned_abs())
        };
        let amount = self.constant(Bits::from_u64(pointer, amount));
        self.add(Expr::Binary(op, base, amount), pointer)
    }

    /// The region stack addresses no region holds are taken from: the one
    /// holding the entry stack pointer's byte, else a new one there (the
    /// return address, where a call leaves it on the stack).
    fn anchor(&mut self) -> usize {
        if let Some(index) = self.anchor {
            return index;
        }
        let index = if let Some(index) = self.regions.iter().position(|(r, _)| r.contains(0)) {
            index
        } else {
            let link = self.lw.cx.link_bytes();
            let bytes = if link == 0 { self.lw.pointer / 8 } else { link };
            self.region(
                Region {
                    offset: 0,
                    bytes: u64::from(bytes),
                    whole: true,
                    promoted: None,
                    memory: true,
                },
                false,
            )
        };
        self.anchor = Some(index);
        index
    }

    /// `value` as a variable of `width` bits holds it: its low bits
    /// where the variable is the low lane of a wider value.
    fn fitted(&mut self, value: ExprId, width: u16) -> ExprId {
        if width > 0 && width < self.width_of(value) {
            self.extract(value, 0, width)
        } else {
            value
        }
    }

    /// The variable of `v`'s class, if it has one.
    fn class_var(&self, v: Value) -> Option<VarId> {
        let class = self.lw.classes.of(self.lw.canonical(v))?;
        self.classes.get(class).copied().flatten()
    }

    /// Where a statement writes value `v`: its variable, else a new one
    /// (named, as a class's, by the register `v` was held in).
    fn place_of(&mut self, v: Value) -> Place {
        if let Some(var) = self.class_var(v) {
            return Place::Var(var);
        }
        let canonical = self.lw.canonical(v);
        let width = self.lw.var_width(canonical);
        let var = self.temporary(width);
        let held = self
            .lw
            .l1
            .held
            .get(&v)
            .or_else(|| self.lw.l1.held.get(&canonical));
        if let Some(&register) = held
            && let Some(variable) = self.ast.variables.get_mut(var.0 as usize)
        {
            variable.origins.push(Origin::Held(register));
        }
        Place::Var(var)
    }

    /// The expression of value `v` where it is used.
    fn expr(&mut self, v: Value) -> ExprId {
        let lw = self.lw;
        let root = lw.canonical(v);
        self.see(v);
        let mut work = vec![(root, false)];
        while let Some((x, ready)) = work.pop() {
            if self.memo.contains_key(&x) {
                continue;
            }
            // A pure value nothing needs whole (the bits of a register
            // above those used) is still computed where it is read.
            let rebuilt = match lw.role(x) {
                Role::Fold(_) => true,
                Role::None => matches!(lw.kind(x), Kind::Pure(_)),
                Role::Inline | Role::Parameter(_) | Role::Drop | Role::Var => false,
            };
            if !rebuilt {
                let fresh = self.ast.exprs.len();
                let e = self.leaf(x);
                // An inline load is its instruction's; a variable's read,
                // a parameter's, a constant and a stack address stand for
                // no instruction of their own.
                if lw.role(x) == Role::Inline && matches!(lw.kind(x), Kind::Load(_)) {
                    self.tag(x, e, fresh);
                }
                self.memo.insert(x, e);
                continue;
            }
            if ready {
                let fresh = self.ast.exprs.len();
                let e = self.build(x);
                self.tag(x, e, fresh);
                self.memo.insert(x, e);
            } else {
                work.push((x, true));
                for operand in self.operands(x) {
                    let operand = lw.canonical(operand);
                    if !self.memo.contains_key(&operand) {
                        work.push((operand, false));
                    }
                }
            }
        }
        match self.memo.get(&root) {
            Some(&e) => e,
            None => self.undefined(lw.width(root), Unknown::Lowering),
        }
    }

    /// The expression computing value `v` (with a variable) from its
    /// operands, for its assignment.
    fn definition(&mut self, v: Value) -> ExprId {
        for operand in self.operands(v) {
            self.expr(operand);
        }
        let fresh = self.ast.exprs.len();
        let e = self.build(v);
        self.tag(v, e, fresh);
        e
    }

    /// The values [`build`](Self::build) reads for `x`.
    fn operands(&self, x: Value) -> Vec<Value> {
        let lw = self.lw;
        lw.inputs(x)
            .into_iter()
            .filter_map(|item| match item {
                Use::Value(value, _) => Some(value),
                Use::Slot(_) => None,
            })
            .collect()
    }

    /// The expression of `x` where it is not built from operands.
    fn leaf(&mut self, x: Value) -> ExprId {
        let lw = self.lw;
        let width = lw.width(x);
        match lw.role(x) {
            Role::Parameter(index) => {
                let Some(&var) = self.params.get(index) else {
                    return self.undefined(width, Unknown::Lowering);
                };
                let inner = lw.var_width(x);
                self.widen(var, inner, width, 0, Unknown::Parameter)
            }
            Role::Var => {
                let Some(var) = self.class_var(x) else {
                    return self.undefined(width, Unknown::Lowering);
                };
                match lw.kind(x) {
                    Kind::CallView {
                        inst,
                        offset,
                        width: inner,
                    } => {
                        let unknown = match (lw.l1.inst(inst), lw.call_register(inst, x)) {
                            (Some(i), Some(register)) => Unknown::Call {
                                address: i.address,
                                register,
                            },
                            _ => Unknown::Lowering,
                        };
                        self.widen(var, inner, width, offset, unknown)
                    }
                    Kind::None
                    | Kind::Const(_)
                    | Kind::Undefined(..)
                    | Kind::Address(_)
                    | Kind::Entry(_)
                    | Kind::Load(_)
                    | Kind::Result(_) => self.read(var),
                    // Its variable may hold the low lane alone
                    // ([`Lowering::var_width`]).
                    Kind::Phi | Kind::Pure(_) => {
                        let inner = lw.var_width(x);
                        if inner < width {
                            self.widen(var, inner, width, 0, Unknown::Lowering)
                        } else {
                            self.read(var)
                        }
                    }
                }
            }
            Role::Inline => match lw.kind(x) {
                Kind::Const(bits) => self.constant(bits),
                Kind::Address(offset) => self.address(offset),
                Kind::Load(inst) => self.load(inst),
                Kind::Entry(register) => {
                    match self.environment.iter().find(|&&(r, _)| r == register) {
                        Some(&(_, var)) => self.read(var),
                        None => self.undefined(
                            width,
                            Unknown::Entry {
                                register: Some(register),
                            },
                        ),
                    }
                }
                // An unnamed integer argument register C has in the
                // save area the `va_start` wrote.
                Kind::Undefined(
                    _,
                    Unknown::Entry {
                        register: Some(register),
                    },
                ) if let Some(delta) = lw.va.as_ref().and_then(|va| va.saved(register))
                    && let Some(var) = self.va_save =>
                {
                    let base = self.read(var);
                    let address = self.moved(base, delta);
                    let ty = self.bits(64);
                    let saved = self.add(Expr::Load { address, ty }, 64);
                    self.extract(saved, 0, width)
                }
                Kind::Undefined(_, unknown) => self.site_undefined(x, width, unknown),
                Kind::None
                | Kind::Phi
                | Kind::Pure(_)
                | Kind::Result(_)
                | Kind::CallView { .. } => self.undefined(width, Unknown::Lowering),
            },
            Role::Fold(_) | Role::Drop | Role::None => self.undefined(width, Unknown::Lowering),
        }
    }

    /// The memoized expression of operand `v`.
    fn m(&mut self, v: Value) -> ExprId {
        let v = self.lw.canonical(v);
        match self.memo.get(&v) {
            Some(&e) => e,
            None => self.expr(v),
        }
    }

    /// A float relation as L2: the comparison's outcome (one of four
    /// bits) masked with the outcomes it holds for, not 0. The
    /// comparison is made here from its operands, so each condition on
    /// one `ucomisd` is its own comparison of them and the flags between
    /// are not computed. Its rounding is to nearest: a comparison rounds
    /// nothing.
    fn float_relation(&mut self, relation: FloatRelation) -> ExprId {
        let (left, right) = (self.m(relation.left), self.m(relation.right));
        let rounding = self.constant(Bits::zero(2));
        let outcome = self.add(
            Expr::Float {
                op: FloatOp::Compare {
                    signaling: relation.signaling,
                },
                format: relation.format,
                lanes: 1,
                output: FloatOutput::Value,
                rounding,
                operands: [left, right, left],
            },
            4,
        );
        let holds = self.constant(Bits::from_u64(4, u64::from(relation.holds)));
        let masked = self.add(Expr::Binary(Binary::And, outcome, holds), 4);
        let zero = self.constant(Bits::zero(4));
        self.add(Expr::Binary(Binary::Ne, masked, zero), 1)
    }

    /// The expression of `x` from its operands' (already built).
    fn build(&mut self, x: Value) -> ExprId {
        let lw = self.lw;
        let width = lw.width(x);
        match lw.kind(x) {
            Kind::Pure(inst) => {
                if let Some(relation) = lw.float_relation(x) {
                    let holds = self.float_relation(relation);
                    if width == 1 {
                        return holds;
                    }
                    return self.add(
                        Expr::Extend {
                            signed: false,
                            value: holds,
                            width,
                        },
                        width,
                    );
                }
                if width == 1
                    && let Some(compare) = lw.compare(x)
                {
                    let (left, right) = (self.m(compare.left), self.m(compare.right));
                    let (op, a, b) = match compare.relation {
                        Relation::Eq => (Binary::Eq, left, right),
                        Relation::Ne => (Binary::Ne, left, right),
                        Relation::ULt => (Binary::ULt, left, right),
                        Relation::ULe => (Binary::ULe, left, right),
                        Relation::UGt => (Binary::ULt, right, left),
                        Relation::UGe => (Binary::ULe, right, left),
                        Relation::SLt => (Binary::SLt, left, right),
                        Relation::SLe => (Binary::SLe, left, right),
                        Relation::SGt => (Binary::SLt, right, left),
                        Relation::SGe => (Binary::SLe, right, left),
                    };
                    return self.add(Expr::Binary(op, a, b), 1);
                }
                self.pure(inst, width)
            }
            Kind::Load(inst) => self.load(inst),
            Kind::None
            | Kind::Const(_)
            | Kind::Undefined(..)
            | Kind::Address(_)
            | Kind::Entry(_)
            | Kind::Phi
            | Kind::Result(_)
            | Kind::CallView { .. } => self.leaf(x),
        }
    }

    /// Atomic load `inst` of `bytes` bytes at `address`, whose value is
    /// `old`: the update its group is
    /// ([`Lowering::find_atomics`]), with the value read as its result
    /// where something uses it, else the load alone.
    fn atomic_load(
        &mut self,
        inst: InstId,
        address: Value,
        bytes: u16,
        old: Option<Value>,
    ) -> Stmt {
        let lw = self.lw;
        let expr = self.expr(address);
        let mut operands = vec![self.data_address(expr, address, bytes, false)];
        let Some((update, values)) = lw.atomics.updates.get(&inst) else {
            return Stmt::Escape {
                kind: Escape::Atomic,
                operands,
                results: old.map(|r| self.place_of(r)).into_iter().collect(),
            };
        };
        let at = old.map_or(Def::NONE, |old| lw.def(old));
        for &value in values {
            operands.push(self.early(value, at));
        }
        let results = old
            .filter(|&old| lw.is_needed(old))
            .map(|old| self.place_of(old))
            .into_iter()
            .collect();
        Stmt::Escape {
            kind: Escape::Update(*update),
            operands,
            results,
        }
    }

    /// The expression of an atomic update's operand `value` where the
    /// update is evaluated (`at`): its own if it is available there,
    /// else the bits of what it is an extraction from or an extension of
    /// ([`Lowering::early`]).
    fn early(&mut self, value: Value, at: Def) -> ExprId {
        let lw = self.lw;
        let value = lw.canonical(value);
        if lw.early(value, at) == Some(value) {
            return self.expr(value);
        }
        match lw.defining(value).map(|(_, op)| op) {
            Some(&Op::Extract {
                value: from,
                offset,
                width,
            }) => {
                let from = self.early(from, at);
                self.extract(from, offset, width)
            }
            Some(&Op::Extend {
                signed,
                value: from,
                width,
            }) => {
                let value = self.early(from, at);
                self.add(
                    Expr::Extend {
                        signed,
                        value,
                        width,
                    },
                    width,
                )
            }
            Some(_) | None => self.undefined(lw.width(value), Unknown::Lowering),
        }
    }

    /// `a & b` of `width` bits, each operand as far as the result reads
    /// it ([`Lowering::and_reads`]).
    fn and(&mut self, a: Value, b: Value, width: u16) -> ExprId {
        let lw = self.lw;
        let (low_a, low_b) = lw.and_reads(a, b);
        // The bits read, masked with exactly those bits, are themselves.
        for (operand, low, mask) in [(a, low_a, b), (b, low_b, a)] {
            if low < width && lw.kind(mask) == Kind::Const(Bits::ones(low).zext(width)) {
                return self.low_bits(operand, low);
            }
        }
        let (a, b) = (self.low_bits(a, low_a), self.low_bits(b, low_b));
        self.add(Expr::Binary(Binary::And, a, b), width)
    }

    /// Operand `v` of an `and` that reads only its low `low` bits
    /// ([`Lowering::and_reads`]): those bits zero-extended, so that the
    /// high part of the concatenation it is, which nothing needs, is not
    /// read; `v` itself where the `and` reads all of it.
    fn low_bits(&mut self, v: Value, low: u16) -> ExprId {
        let whole = self.m(v);
        let width = self.width_of(whole);
        if low >= width {
            return whole;
        }
        let value = self.extract(whole, 0, low);
        self.add(
            Expr::Extend {
                signed: false,
                value,
                width,
            },
            width,
        )
    }

    /// Pure operation `inst` of `width` bits.
    fn pure(&mut self, inst: InstId, width: u16) -> ExprId {
        let Some(i) = self.lw.l1.inst(inst) else {
            return self.undefined(width, Unknown::Lowering);
        };
        let expr = match i.op {
            Op::Const(bits) => Expr::Const(bits),
            Op::Unary(op, a) => Expr::Unary(op, self.m(a)),
            Op::Binary(Binary::And, a, b) => return self.and(a, b, width),
            Op::Binary(op, a, b) => Expr::Binary(op, self.m(a), self.m(b)),
            Op::Flag(op, a, b, c) => Expr::Flag(op, self.m(a), self.m(b), self.m(c)),
            Op::Extract {
                value,
                offset,
                width,
            } => {
                let value = self.m(value);
                return self.extract(value, offset, width);
            }
            Op::Concat { high, low } => Expr::Concat {
                high: self.m(high),
                low: self.m(low),
            },
            Op::Extend {
                signed,
                value,
                width,
            } => Expr::Extend {
                signed,
                value: self.m(value),
                width,
            },
            Op::Select {
                condition,
                then,
                otherwise,
            } => {
                // A constant condition between a value and an unknown one
                // (SHRD's OF, for a count other than 1): the arm it takes,
                // exactly, so the unknown value shows where it is taken
                // and nowhere else.
                let lw = self.lw;
                if let Kind::Const(bits) = lw.kind(condition)
                    && [then, otherwise]
                        .into_iter()
                        .any(|arm| matches!(lw.kind(arm), Kind::Undefined(..)))
                {
                    return self.m(if bits.is_zero() { otherwise } else { then });
                }
                Expr::Select {
                    condition: self.m(condition),
                    then: self.m(then),
                    otherwise: self.m(otherwise),
                }
            }
            Op::Lanes {
                lanes,
                op,
                operands: [a, b, c],
            } => {
                let arity = op.arity();
                let first = self.m(a);
                let second = if arity > 1 { self.m(b) } else { first };
                let third = if arity > 2 { self.m(c) } else { first };
                Expr::Lanes {
                    lanes,
                    op,
                    operands: [first, second, third],
                }
            }
            Op::Float {
                op,
                format,
                lanes,
                output,
                rounding,
                operands: [a, b, c],
            } => {
                let arity = op.arity();
                let rounding = self.m(rounding);
                let first = if arity > 0 { self.m(a) } else { rounding };
                let second = if arity > 1 { self.m(b) } else { first };
                let third = if arity > 2 { self.m(c) } else { first };
                Expr::Float {
                    op,
                    format,
                    lanes,
                    output,
                    rounding,
                    operands: [first, second, third],
                }
            }
            Op::Undefined(unknown, _) => Expr::Undefined(width, unknown, None),
            Op::Load { .. }
            | Op::Store { .. }
            | Op::Intrinsic { .. }
            | Op::Call { .. }
            | Op::SystemCall { .. }
            | Op::Landing { .. } => Expr::Undefined(width, Unknown::Lowering, None),
        };
        self.add(expr, width)
    }

    /// The `Frame` variable that is exactly `bytes` bytes at `offset`.
    fn whole_region(&self, offset: i64, bytes: u64) -> Option<VarId> {
        self.regions
            .iter()
            .find(|(r, _)| r.whole && r.offset == offset && r.bytes == bytes)
            .map(|&(_, var)| var)
    }

    /// The bytes of slot `slot` (a stack access of `bytes` bytes at
    /// `offset`) read, by load `inst` if one (the frame's bytes then take
    /// its solved type); of a local read in part, those bits of it.
    fn slot_read(&mut self, slot: usize, offset: i64, bytes: u16, inst: Option<InstId>) -> ExprId {
        let lw = self.lw;
        let width = bytes.saturating_mul(8);
        match lw.home(slot) {
            Home::Local => match self.slots.get(&slot) {
                Some(&var) => {
                    let read = self.read(var);
                    let start = lw.frame.slots.get(slot).map_or(offset, |slot| slot.offset);
                    let from = u16::try_from(offset.saturating_sub(start).saturating_mul(8));
                    match from {
                        Ok(from) if self.width_of(read) != width => self.add(
                            Expr::Extract {
                                value: read,
                                offset: from,
                                width,
                            },
                            width,
                        ),
                        Ok(_) | Err(_) => read,
                    }
                }
                None => self.undefined(width, Unknown::Unwritten),
            },
            Home::Parameter => {
                let var = lw
                    .needed
                    .stack
                    .get(&slot)
                    .and_then(|&index| self.params.get(index))
                    .copied();
                match var {
                    Some(var) => self.read(var),
                    None => self.undefined(width, Unknown::Entry { register: None }),
                }
            }
            Home::Frame => {
                if let Some(var) = self.whole_region(offset, u64::from(bytes)) {
                    return self.read(var);
                }
                let address = self.address(offset);
                let ty = match (self.field_at(offset, width), inst) {
                    (Some(ty), _) => ty,
                    (None, Some(inst)) => self.access_type(inst, width),
                    (None, None) => self.bits(width),
                };
                self.add(Expr::Load { address, ty }, width)
            }
        }
    }

    /// The value load `inst` reads.
    fn load(&mut self, inst: InstId) -> ExprId {
        let lw = self.lw;
        let Some(&Op::Load { address, bytes, .. }) = lw.l1.inst(inst).map(|i| &i.op) else {
            return self.undefined(0, Unknown::Lowering);
        };
        let width = bytes.saturating_mul(8);
        if let Some(&slot) = lw.frame.accesses.get(&inst)
            && let Some(offset) = lw.address(address)
        {
            return self.slot_read(slot, offset, bytes, Some(inst));
        }
        let value = address;
        let address = self.m(value);
        if let Some(value) = self.data_load(address, value, bytes) {
            return value;
        }
        let ty = self.access_type(inst, width);
        self.add(Expr::Load { address, ty }, width)
    }

    // Statements.

    fn stmt(&mut self, stmt: Stmt, origins: &[Origin]) -> StmtId {
        let id = self.ast.add_stmt(stmt);
        if !origins.is_empty() {
            self.ast.provenance.set_stmt(id, origins);
        }
        if !self.seen.is_empty() {
            let seen: Vec<Origin> = self.seen.drain(..).map(Origin::Instruction).collect();
            self.ast.provenance.absorb_stmt(id, &seen);
        }
        id
    }

    fn label(&mut self, block: BlockId) -> LabelId {
        if let Some(&label) = self.labels.get(&block.0) {
            return label;
        }
        let label = self.ast.add_label();
        self.labels.insert(block.0, label);
        label
    }

    /// The body: each block lowered, in order, the entry first (without a
    /// label); every other block starts with its label and ends with one
    /// explicit terminator (a goto, even to the label that follows). The
    /// statements of a block's code and its terminator (not those in the
    /// terminator's arms: the copies on its edges, the gotos, a switch's
    /// default; nor a `Try`, which may come to hold several blocks' code)
    /// have the block as an [`Origin::Block`].
    ///
    /// The frame code ([`Self::frame_code`]) goes to the function's
    /// entry and exit ([`Provenance::entry`](binbun_ast::ir::Provenance::entry)),
    /// but where epilogues come before several returns: each to the
    /// statement of its return.
    fn body(&mut self) -> Result<(), LowerError> {
        let lw = self.lw;
        let frame = self.frame_code();
        let entry: Vec<Origin> = frame
            .entry
            .iter()
            .copied()
            .map(Origin::Instruction)
            .collect();
        self.ast.provenance.set_entry(&entry);
        let returns = frame.exits.keys().filter(|block| block.is_some()).count();
        let mut exits = frame.exits;
        if returns < 2 {
            let exit: Vec<Origin> = exits
                .values()
                .flatten()
                .copied()
                .map(Origin::Instruction)
                .collect();
            self.ast.provenance.set_exit(&exit);
            exits.clear();
        } else if let Some(unplaced) = exits.remove(&None) {
            let exit: Vec<Origin> = unplaced.into_iter().map(Origin::Instruction).collect();
            self.ast.provenance.set_exit(&exit);
        }
        let mut body: Vec<StmtId> = Vec::new();
        for (id, block) in lw.blocks() {
            self.seen.clear();
            if id.0 != 0 {
                let label = self.label(id);
                let stmt = self.stmt(Stmt::Label(label), &[]);
                body.push(stmt);
            }
            let start = body.len();
            if id.0 == 0 {
                self.entry_values(Origin::Instruction(block.address), &mut body);
            }
            if id.0 == 0 && lw.va.as_ref().is_some_and(|va| va.at.is_none()) {
                let at = Origin::Instruction(block.address);
                self.va_start(at, &mut body);
            }
            // Where the statements of an invoke's call start.
            let mut call = body.len();
            for &inst in &block.insts {
                call = body.len();
                self.instruction(inst, &mut body);
            }
            self.terminator(id, &block.terminator, call, &mut body)?;
            if let Some(epilogue) = exits.remove(&Some(id))
                && let Some(&last) = body.last()
            {
                let epilogue: Vec<Origin> = epilogue.into_iter().map(Origin::Instruction).collect();
                self.ast.provenance.absorb_stmt(last, &epilogue);
            }
            for &stmt in body.get(start..).unwrap_or_default() {
                if !matches!(self.ast.stmt(stmt), Some(Stmt::Goto(_) | Stmt::Try { .. })) {
                    self.ast.provenance.add_stmt_origin(stmt, Origin::Block(id));
                }
            }
        }
        self.ast.body = body;
        Ok(())
    }

    /// The frame's bytes that hold a stack argument the function reads
    /// ([`Needed::entry`](super::needed::Needed::entry)) assigned their
    /// parameter's value, at the entry (`at`): in L2 they are the memory
    /// the caller wrote, in C a variable of the function's own, which
    /// only the parameter gives the argument.
    fn entry_values(&mut self, at: Origin, out: &mut Vec<StmtId>) {
        let lw = self.lw;
        for &(offset, bytes, parameter) in &lw.needed.entry {
            let Some(&var) = self.params.get(parameter) else {
                continue;
            };
            let width = bytes.saturating_mul(8);
            let whole = self.read(var);
            if self.width_of(whole) < width {
                continue;
            }
            let value = self.extract(whole, 0, width);
            let place = if let Some(region) = self.whole_region(offset, u64::from(bytes)) {
                Place::Var(region)
            } else {
                let address = self.address(offset);
                let ty = match self.field_at(offset, width) {
                    Some(ty) => ty,
                    None => self.bits(width),
                };
                Place::Memory { address, ty }
            };
            let stmt = self.stmt(Stmt::Assign { place, value }, &[at]);
            out.push(stmt);
        }
    }

    /// The statements of instruction `inst`.
    fn instruction(&mut self, inst: InstId, out: &mut Vec<StmtId>) {
        let lw = self.lw;
        let Some(i) = lw.l1.inst(inst) else {
            return;
        };
        self.seen.clear();
        let at = Origin::Instruction(i.address);
        if lw.va.as_ref().is_some_and(|va| va.at == Some(inst)) {
            self.va_start(at, out);
            return;
        }
        // A keyed hash no value needs has no effect to show.
        if lw.idle_hash(inst) {
            return;
        }
        // An atomic group's other accesses: the update is the group.
        if lw.atomics.absorbed.contains(&inst) {
            return;
        }
        let stmt = match &i.op {
            Op::Store {
                address,
                value,
                atomic,
                ..
            } => {
                let Some(stmt) = self.store(inst, *address, *value, atomic.is_some()) else {
                    return;
                };
                stmt
            }
            Op::Load {
                address,
                bytes,
                atomic: Some(_),
                ..
            } => self.atomic_load(inst, *address, *bytes, i.results.first().copied()),
            Op::Call {
                target, registers, ..
            } => {
                self.call_instruction(inst, *target, registers, at, out);
                return;
            }
            Op::Landing { .. } => {
                self.landing(&i.results, at, out);
                return;
            }
            Op::Intrinsic {
                intrinsic, inputs, ..
            } => {
                let inputs = inputs.iter().map(|&v| self.expr(v)).collect();
                Stmt::Intrinsic {
                    results: self.outputs(&i.results, true),
                    intrinsic: *intrinsic,
                    inputs,
                }
            }
            Op::SystemCall { registers, .. } => self.system_call(inst, registers, &i.results),
            Op::Load { atomic: None, .. }
            | Op::Const(_)
            | Op::Undefined(..)
            | Op::Unary(..)
            | Op::Binary(..)
            | Op::Flag(..)
            | Op::Extract { .. }
            | Op::Concat { .. }
            | Op::Extend { .. }
            | Op::Select { .. }
            | Op::Lanes { .. }
            | Op::Float { .. } => {
                if let Some(&result) = i.results.first()
                    && lw.canonical(result) == result
                    && let Some(stmt) = self.assignment(result)
                {
                    let stmt = self.stmt(stmt, &[Origin::Value(result), at]);
                    out.push(stmt);
                }
                return;
            }
        };
        let stmt = self.stmt(stmt, &[at]);
        out.push(stmt);
    }

    /// The escape of system call `inst`: the registers its convention
    /// passes, of `registers`, and its `results`.
    fn system_call(&mut self, inst: InstId, registers: &[Value], results: &[Value]) -> Stmt {
        let mut operands = Vec::new();
        for register in self.lw.system_call_registers(inst) {
            if let Some(&value) = registers.get(usize::from(register.0)) {
                operands.push(self.expr(value));
            }
        }
        Stmt::Escape {
            kind: Escape::SystemCall,
            operands,
            results: self.outputs(results, false),
        }
    }

    /// The `va_start` of [`Lowering::va`], standing for `at` and the
    /// blocks it absorbed.
    fn va_start(&mut self, at: Origin, out: &mut Vec<StmtId>) {
        let (Some(va), Some(list)) = (&self.lw.va, self.va_list) else {
            return;
        };
        let guard = va.guard.map(|(guard, _)| guard);
        let origins: Vec<Origin> = core::iter::once(at)
            .chain(
                va.blocks
                    .iter()
                    .chain(&guard)
                    .map(|&block| Origin::Absorbed(block)),
            )
            .collect();
        let stmt = self.stmt(
            Stmt::VaStart {
                list: Place::Var(list),
            },
            &origins,
        );
        out.push(stmt);
        // What the function reads its unnamed arguments through itself:
        // the list's two pointers, as they are now.
        let pointer = self.lw.pointer;
        for (var, field) in [(self.va_stack, 8), (self.va_save, 16)] {
            let Some(var) = var else {
                continue;
            };
            let Some(ty) = self.ast.var(var).map(|variable| variable.ty) else {
                continue;
            };
            let base = self.add(Expr::AddressOf(list), pointer);
            let address = self.moved(base, field);
            let value = self.add(Expr::Load { address, ty }, pointer);
            let stmt = self.stmt(
                Stmt::Assign {
                    place: Place::Var(var),
                    value,
                },
                &[at],
            );
            out.push(stmt);
        }
    }

    /// What the unwinder hands a landing pad (`results`, after the
    /// memory): each value with a variable assigned what the runtime gave
    /// the handler ([`Expr::Exception`]).
    fn landing(&mut self, results: &[Value], at: Origin, out: &mut Vec<StmtId>) {
        for (index, &result) in results.iter().skip(1).enumerate() {
            let (Some(value), Some(var)) = (exception_value(index), self.class_var(result)) else {
                continue;
            };
            let width = self.lw.width(result);
            let expr = self.add(Expr::Exception { value, width }, width);
            let stmt = self.stmt(
                Stmt::Assign {
                    place: Place::Var(var),
                    value: expr,
                },
                &[Origin::Value(result), at],
            );
            out.push(stmt);
        }
    }

    /// The statements of call `inst` of `target` in a state of
    /// `registers`: the call, after a `StackTrick` escape of the stack
    /// pointer if it is made on a stack other than the frame
    /// (the frame's `tricks`).
    fn call_instruction(
        &mut self,
        inst: InstId,
        target: Value,
        registers: &[Value],
        at: Origin,
        out: &mut Vec<StmtId>,
    ) {
        let lw = self.lw;
        let site = Site::Call(inst);
        if lw.frame.tricks.contains(&site) {
            let sp = registers.get(usize::from(lw.cx.stack_pointer.0));
            let operands = sp.map(|&sp| self.expr(sp)).into_iter().collect();
            let stmt = self.stmt(
                Stmt::Escape {
                    kind: Escape::StackTrick,
                    operands,
                    results: Vec::new(),
                },
                &[at],
            );
            out.push(stmt);
        }
        let results = self.call_results(inst);
        out.extend(self.call(site, target, registers, results, at));
    }

    /// The assignment of pure value or load `result` to its variable, or
    /// the load evaluated for its fault (one nothing uses, or one folded
    /// under a select's arm, which C evaluates only if chosen:
    /// [`Lowering::selected_load`]); none if it is folded or inline.
    fn assignment(&mut self, result: Value) -> Option<Stmt> {
        match self.lw.role(result) {
            Role::Var => {
                let var = self.class_var(result)?;
                let value = self.definition(result);
                let value = self.fitted(value, self.lw.var_width(self.lw.canonical(result)));
                Some(Stmt::Assign {
                    place: Place::Var(var),
                    value,
                })
            }
            Role::Drop => Some(Stmt::Expr(self.definition(result))),
            Role::Fold(_) if self.lw.selected_load(result) => {
                Some(Stmt::Expr(self.definition(result)))
            }
            Role::None | Role::Inline | Role::Parameter(_) | Role::Fold(_) => None,
        }
    }

    /// The places of `results` (but the memory): each one's variable;
    /// with `all`, a new variable for one that has none, else none.
    fn outputs(&mut self, results: &[Value], all: bool) -> Vec<Place> {
        let lw = self.lw;
        let mut places = Vec::new();
        for &result in results {
            if lw.width(result) == 0 {
                continue;
            }
            if all {
                places.push(self.place_of(result));
            } else if let Some(var) = self.class_var(result) {
                places.push(Place::Var(var));
            }
        }
        places
    }

    /// The assignment of store `inst` of `value` at `address`, if it is
    /// lowered; an `Atomic` escape for an `atomic` one.
    fn store(&mut self, inst: InstId, address: Value, value: Value, atomic: bool) -> Option<Stmt> {
        let lw = self.lw;
        if atomic {
            let bytes = lw.width(value) / 8;
            let expr = self.expr(address);
            let address = self.data_address(expr, address, bytes, true);
            let stored = self.expr(value);
            let operands = vec![address, self.passed(stored, value)];
            return Some(Stmt::Escape {
                kind: Escape::Atomic,
                operands,
                results: Vec::new(),
            });
        }
        if !lw.store_lowered(inst) {
            return None;
        }
        let stored = self.expr(value);
        let value = self.passed(stored, value);
        let width = self.width_of(value);
        let place = if let (Some(&slot), Some(offset)) =
            (lw.frame.accesses.get(&inst), lw.address(address))
        {
            match lw.home(slot) {
                Home::Local => Place::Var(*self.slots.get(&slot)?),
                Home::Parameter | Home::Frame => {
                    if let Some(var) = self.whole_region(offset, u64::from(width / 8)) {
                        Place::Var(var)
                    } else {
                        let address = self.address(offset);
                        let ty = match self.field_at(offset, width) {
                            Some(ty) => ty,
                            None => self.access_type(inst, width),
                        };
                        Place::Memory { address, ty }
                    }
                }
            }
        } else {
            let value = address;
            let address = self.expr(value);
            if let Some(place) = self.data_store(address, value, width / 8) {
                place
            } else {
                let ty = self.access_type(inst, width);
                Place::Memory { address, ty }
            }
        };
        Some(Stmt::Assign { place, value })
    }

    /// The places of call `inst`'s return value: each piece's register
    /// after the call where it is used (else a new variable); none if no
    /// piece is used.
    fn call_results(&mut self, inst: InstId) -> Vec<Place> {
        let lw = self.lw;
        let Some(callee) = lw.callees.get(&Site::Call(inst)) else {
            return Vec::new();
        };
        let Some(i) = lw.l1.inst(inst) else {
            return Vec::new();
        };
        let values: Vec<Option<Value>> = callee
            .results
            .iter()
            .map(|piece| {
                i.results
                    .iter()
                    .skip(1)
                    .copied()
                    .find(|&r| lw.call_register(inst, r) == Some(piece.register))
                    .filter(|&r| self.class_var(r).is_some())
            })
            .collect();
        if values.iter().all(Option::is_none) {
            return Vec::new();
        }
        callee
            .results
            .iter()
            .zip(values)
            .map(|(piece, value)| match value {
                Some(value) => self.place_of(value),
                None => Place::Var(self.temporary(piece.width)),
            })
            .collect()
    }

    /// A call at `site` of `target` (its L1 value) in a state of
    /// `registers`, its result to `results`.
    fn call(
        &mut self,
        site: Site,
        target: Value,
        registers: &[Value],
        results: Vec<Place>,
        at: Origin,
    ) -> Option<StmtId> {
        let lw = self.lw;
        let callee: &Callee = lw.callees.get(&site)?;
        let ast_callee = match (callee.target, callee.import) {
            (Some(address), _) => AstCallee::Address(address),
            (None, Some(slot)) => AstCallee::Import(slot),
            (None, None) => AstCallee::Expr(self.expr(target)),
        };
        let sp = registers.get(usize::from(lw.cx.stack_pointer.0)).copied();
        // The callee's signature, typed by its scheme's instances.
        let signature = callee
            .target
            .filter(|_| callee.interfaced)
            .and_then(|address| lw.typed.as_ref()?.signatures.get(&address).copied())
            .unwrap_or(callee.signature);
        let signature = if callee.interfaced {
            classed(
                &mut self.ast.types,
                lw.cx.convention,
                signature,
                &callee.arguments,
                &callee.results,
            )
        } else {
            signature
        };
        let mut parameters = self
            .ast
            .types
            .signature(signature)
            .map(|signature| signature.parameters.clone())
            .unwrap_or_default();
        parameters.extend(callee.variadic.iter().copied());
        let mut arguments = Vec::new();
        for (index, source) in callee.arguments.iter().enumerate() {
            let (argument, value) = match *source {
                Source::Register(Piece {
                    register,
                    offset,
                    width,
                }) => match registers.get(usize::from(register.0)) {
                    Some(&value) => {
                        let expr = self.expr(value);
                        (self.extract(expr, offset, width), Some(value))
                    }
                    None => (self.undefined(width, Unknown::Lowering), None),
                },
                Source::Stack { offset, bytes } => {
                    (self.stack_argument(site, index, sp, offset, bytes), None)
                }
            };
            arguments.push(self.argument(argument, value, parameters.get(index).copied()));
        }
        self.mapping.calls.insert(
            target,
            CallSite {
                arguments: callee.arguments.clone(),
                results: callee.results.clone(),
            },
        );
        let call = Call {
            callee: ast_callee,
            arguments,
            signature,
            variadic: callee.variadic.clone(),
        };
        Some(self.stmt(Stmt::Call { results, call }, &[Origin::Value(target), at]))
    }

    /// Stack argument `index` of the call at `site` (`bytes` bytes at
    /// `offset` from the stack pointer `sp` at the call): its slot's
    /// variable or bytes, else a load.
    fn stack_argument(
        &mut self,
        site: Site,
        index: usize,
        sp: Option<Value>,
        offset: i64,
        bytes: u16,
    ) -> ExprId {
        let lw = self.lw;
        let base = sp.and_then(|sp| lw.address(sp));
        if let (Some(&slot), Some(base)) = (lw.frame.arguments.get(&(site, index)), base) {
            return self.slot_read(slot, base + offset, bytes, None);
        }
        let width = bytes.saturating_mul(8);
        let Some(sp) = sp else {
            return self.undefined(width, Unknown::Lowering);
        };
        let sp = self.expr(sp);
        let pointer = lw.pointer;
        let delta = self.constant(Bits::from_u64(pointer, offset.cast_unsigned()));
        let address = self.add(Expr::Binary(Binary::Add, sp, delta), pointer);
        let ty = self.bits(width);
        self.add(Expr::Load { address, ty }, width)
    }

    /// The statements of block `id`'s terminator. For an invoke, the
    /// statements of its call (from `call` in `out`) become the body of a
    /// `Try` whose one handler, a `Landing` at the landing pad, takes the
    /// unwind edge; the normal edge follows the `Try`.
    fn terminator(
        &mut self,
        id: BlockId,
        terminator: &Terminator,
        call: usize,
        out: &mut Vec<StmtId>,
    ) -> Result<(), LowerError> {
        let lw = self.lw;
        // The instruction leaving the block (a branch, a jump, a return).
        let address = lw.l1.block(id).map_or(0, |b| b.end);
        let at = Origin::Instruction(address);
        self.seen.clear();
        if self.absorbed_branch(id, terminator, out) {
            return Ok(());
        }
        match terminator {
            Terminator::Jump(target) => {
                let block = self.edge(target);
                out.extend(block);
            }
            Terminator::Branch {
                condition,
                then,
                otherwise,
            } => {
                let condition = self.expr(*condition);
                let then = self.edge(then);
                let otherwise = self.edge(otherwise);
                let stmt = self.stmt(
                    Stmt::If {
                        condition,
                        then,
                        otherwise,
                    },
                    &[at],
                );
                out.push(stmt);
            }
            Terminator::Invoke { normal, unwind } => {
                let body = out.split_off(call.min(out.len()));
                for &stmt in &body {
                    self.ast.provenance.add_stmt_origin(stmt, Origin::Block(id));
                }
                let pad = lw.l1.block(unwind.block).map_or(0, |b| b.address);
                let handler = Handler {
                    kind: HandlerKind::Landing(pad),
                    body: self.edge(unwind),
                };
                let stmt = self.stmt(
                    Stmt::Try {
                        body,
                        handlers: vec![handler],
                    },
                    &[at],
                );
                out.push(stmt);
                let normal = self.edge(normal);
                out.extend(normal);
            }
            Terminator::IndirectJump { address, targets } => {
                let stmt = self.switch(id, *address, targets, at)?;
                out.push(stmt);
            }
            Terminator::Return { address, state } => {
                if !lw.caller_return(*address) {
                    let operand = self.expr(*address);
                    let stmt = self.stmt(
                        Stmt::Escape {
                            kind: Escape::StackTrick,
                            operands: vec![operand],
                            results: Vec::new(),
                        },
                        &[at],
                    );
                    out.push(stmt);
                }
                let pieces = lw.returns.pieces.clone();
                let value = self.return_value(&pieces, |emit, piece| {
                    let value = *state.registers.get(usize::from(piece.register.0))?;
                    let expr = emit.expr(value);
                    let expr = emit.extract(expr, piece.offset, piece.width);
                    Some(emit.passed(expr, value))
                });
                let stmt = self.stmt(Stmt::Return(value), &[at]);
                out.push(stmt);
            }
            Terminator::Leave {
                address,
                state,
                returns,
            } => {
                self.leave(id, *address, &state.registers, *returns, at, out)?;
            }
            Terminator::Trap(trap) => {
                let stmt = self.stmt(Stmt::Trap(*trap), &[at]);
                out.push(stmt);
            }
            Terminator::Stop => {
                let stmt = self.stmt(Stmt::Unreachable, &[at]);
                out.push(stmt);
            }
            Terminator::Open => {
                return Err(LowerError::Malformed(format!("block {} is open", id.0)));
            }
        }
        Ok(())
    }

    /// Whether block `id`'s `terminator` is the branch on the count
    /// register a `va_start` absorbed: then its edge to the join, in
    /// `out`.
    fn absorbed_branch(
        &mut self,
        id: BlockId,
        terminator: &Terminator,
        out: &mut Vec<StmtId>,
    ) -> bool {
        let Some((guard, join)) = self.lw.va.as_ref().and_then(|va| va.guard) else {
            return false;
        };
        let Terminator::Branch {
            then, otherwise, ..
        } = terminator
        else {
            return false;
        };
        if guard != id {
            return false;
        }
        let target = if then.block == join { then } else { otherwise };
        let block = self.edge(target);
        out.extend(block);
        true
    }

    /// The return value of `pieces` (low first), each from `part` (else
    /// undefined); `None` for none.
    fn return_value(
        &mut self,
        pieces: &[Piece],
        mut part: impl FnMut(&mut Self, &Piece) -> Option<ExprId>,
    ) -> Option<ExprId> {
        let mut value: Option<ExprId> = None;
        for piece in pieces {
            let expr = match part(self, piece) {
                Some(expr) => expr,
                None => self.undefined(piece.width, Unknown::Lowering),
            };
            value = Some(match value {
                Some(low) => self.concat(expr, low),
                None => expr,
            });
        }
        value
    }

    /// A switch over computed address `address` of block `id` to
    /// `targets` (by their blocks' addresses), its default an
    /// `UnresolvedJump` escape; that escape alone where none is known.
    fn switch(
        &mut self,
        id: BlockId,
        address: Value,
        targets: &[Target],
        at: Origin,
    ) -> Result<StmtId, LowerError> {
        let lw = self.lw;
        let scrutinee = self.expr(address);
        let escape = self.stmt(
            Stmt::Escape {
                kind: Escape::UnresolvedJump,
                operands: vec![scrutinee],
                results: Vec::new(),
            },
            &[at],
        );
        if targets.is_empty() {
            return Ok(escape);
        }
        let mut arms = Vec::new();
        let mut seen = BTreeSet::new();
        let width = self.width_of(scrutinee);
        for target in targets {
            let to = lw.l1.block(target.block).map_or(0, |b| b.address);
            if !seen.insert(to) {
                return Err(LowerError::Malformed(format!(
                    "block {}: two targets of its computed jump at {to:#x}",
                    id.0
                )));
            }
            let body = self.edge(target);
            arms.push(Arm {
                values: vec![Bits::from_u64(width, to)],
                default: false,
                body,
                fallthrough: false,
            });
        }
        arms.push(Arm {
            values: Vec::new(),
            default: true,
            body: vec![escape],
            fallthrough: false,
        });
        Ok(self.stmt(Stmt::Switch { scrutinee, arms }, &[at]))
    }

    /// Block `id` leaving to `address` with `registers`: a tail call (the
    /// call, then a return of what it returns; unless it never `returns`:
    /// the call, then unreachable) or a `ForeignJump` escape.
    fn leave(
        &mut self,
        id: BlockId,
        address: Value,
        registers: &[Value],
        returns: bool,
        at: Origin,
        out: &mut Vec<StmtId>,
    ) -> Result<(), LowerError> {
        let lw = self.lw;
        let site = Site::Tail(id);
        let Some(callee) = lw.callees.get(&site) else {
            return Err(LowerError::Malformed(format!("block {}: no callee", id.0)));
        };
        if callee.foreign {
            let operand = self.expr(address);
            let stmt = self.stmt(
                Stmt::Escape {
                    kind: Escape::ForeignJump,
                    operands: vec![operand],
                    results: Vec::new(),
                },
                &[at],
            );
            out.push(stmt);
            return Ok(());
        }
        if !returns {
            // As a call that does not return.
            out.extend(self.call(site, address, registers, Vec::new(), at));
            let stmt = self.stmt(Stmt::Unreachable, &[at]);
            out.push(stmt);
            return Ok(());
        }
        let width: u16 = callee.results.iter().map(|p| p.width).sum();
        let given = &callee.results;
        let result = (width > 0 && !lw.returns.pieces.is_empty()).then(|| self.temporary(width));
        let results = result.map(Place::Var).into_iter().collect();
        out.extend(self.call(site, address, registers, results, at));
        // What the callee leaves in a piece's register beyond its result:
        // unknown after the jump.
        let jump = lw.l1.block(id).map_or(lw.l1.entry, |block| block.end);
        let value = self.return_value(&lw.returns.pieces, |emit, piece| {
            let after = Unknown::Call {
                address: jump,
                register: piece.register,
            };
            let mut start = 0u16;
            for given in given {
                let end = given.offset + given.width;
                if let Some(var) = result
                    && given.register == piece.register
                    && (given.offset..end).contains(&piece.offset)
                {
                    let value = emit.read(var);
                    let offset = start + piece.offset - given.offset;
                    let width = piece.width.min(end - piece.offset);
                    let low = emit.extract(value, offset, width);
                    if width == piece.width {
                        return Some(low);
                    }
                    let high = emit.undefined(piece.width - width, after);
                    return Some(emit.concat(high, low));
                }
                start += given.width;
            }
            Some(emit.undefined(piece.width, after))
        });
        let stmt = self.stmt(Stmt::Return(value), &[at]);
        out.push(stmt);
        Ok(())
    }

    /// An edge to `target`: the copies to the target's parameters, then a
    /// goto. An argument proved zero there ([`Lowering::nulls`]) is copied
    /// as 0: the parameter's variable is not the argument's.
    fn edge(&mut self, target: &Target) -> Vec<StmtId> {
        let lw = self.lw;
        // What the edge's copies read is theirs; what was seen before is
        // the statement's after the edge.
        let before = core::mem::take(&mut self.seen);
        let mut out = Vec::new();
        let parameters = lw
            .l1
            .block(target.block)
            .map_or(&[][..], |b| b.parameters.as_slice());
        // (destination class, argument, classes it reads; none if it is
        // copied as 0)
        let mut pending: Vec<(usize, Value, Option<Vec<usize>>)> = Vec::new();
        let mut leaves = Vec::new();
        for (&parameter, &argument) in parameters.iter().zip(&target.arguments) {
            if lw.canonical(parameter) != parameter || lw.role(parameter) != Role::Var {
                continue;
            }
            let Some(dest) = lw.classes.of(parameter) else {
                continue;
            };
            if lw.nulls.contains(&(parameter, argument)) {
                pending.push((dest, argument, None));
                continue;
            }
            if lw.classes.of(lw.canonical(argument)) == Some(dest) {
                continue;
            }
            leaves.clear();
            lw.leaves(Use::Value(argument, lw.width(argument)), &mut leaves);
            let reads = leaves.iter().filter_map(|&v| lw.classes.of(v)).collect();
            pending.push((dest, argument, Some(reads)));
        }
        let mut renamed: BTreeMap<VarId, VarId> = BTreeMap::new();
        let mut renamed_classes: Vec<usize> = Vec::new();
        while !pending.is_empty() {
            let ready = (0..pending.len()).find(|&i| {
                let dest = pending.get(i).map_or(usize::MAX, |p| p.0);
                pending.iter().enumerate().all(|(j, (_, _, sources))| {
                    j == i
                        || renamed_classes.contains(&dest)
                        || sources
                            .as_ref()
                            .is_none_or(|sources| !sources.contains(&dest))
                })
            });
            if let Some(i) = ready {
                let (dest, argument, sources) = pending.remove(i);
                let Some(var) = self.classes.get(dest).copied().flatten() else {
                    continue;
                };
                let value = self.copied(argument, sources.is_none(), &renamed);
                let width = lw.classes.sets.get(dest).map_or(0, |class| class.width);
                let value = self.fitted(value, width);
                let stmt = self.stmt(
                    Stmt::Assign {
                        place: Place::Var(var),
                        value,
                    },
                    &[Origin::Value(argument)],
                );
                out.push(stmt);
                self.copies += 1;
                continue;
            }
            // A cycle: keep the first destination's value aside.
            let Some(&(dest, _, _)) = pending.first() else {
                break;
            };
            let Some(var) = self.classes.get(dest).copied().flatten() else {
                break;
            };
            let width = lw.classes.sets.get(dest).map_or(0, |c| c.width);
            let temporary = self.temporary(width);
            let value = self.read(var);
            let stmt = self.stmt(
                Stmt::Assign {
                    place: Place::Var(temporary),
                    value,
                },
                &[],
            );
            out.push(stmt);
            self.copies += 1;
            renamed.insert(var, temporary);
            renamed_classes.push(dest);
        }
        let label = self.label(target.block);
        let goto = self.stmt(Stmt::Goto(label), &[]);
        out.push(goto);
        self.seen = before;
        out
    }

    /// What an edge copies of `argument`: 0 where it is proved zero there
    /// (`zero`); else its value, with the variables `renamed` read from
    /// their new names. An argument no run reads (on an edge where the
    /// parameter is used only where the edge was not taken) is a
    /// register's entry value, as such.
    fn copied(&mut self, argument: Value, zero: bool, renamed: &BTreeMap<VarId, VarId>) -> ExprId {
        let lw = self.lw;
        if zero {
            return self.constant(Bits::zero(lw.width(argument)));
        }
        let value = match lw.kind(lw.canonical(argument)) {
            Kind::Entry(register) if lw.role(argument) == Role::None => self.undefined(
                lw.width(argument),
                Unknown::Entry {
                    register: Some(register),
                },
            ),
            Kind::None
            | Kind::Const(_)
            | Kind::Undefined(..)
            | Kind::Address(_)
            | Kind::Entry(_)
            | Kind::Phi
            | Kind::Pure(_)
            | Kind::Load(_)
            | Kind::Result(_)
            | Kind::CallView { .. } => self.expr(argument),
        };
        let value = self.passed(value, argument);
        self.substitute(value, renamed)
    }

    /// `expr` with the variables `renamed` read from their new names.
    fn substitute(&mut self, expr: ExprId, renamed: &BTreeMap<VarId, VarId>) -> ExprId {
        if renamed.is_empty() {
            return expr;
        }
        let mut done: BTreeMap<ExprId, ExprId> = BTreeMap::new();
        let mut work = vec![(expr, false)];
        while let Some((at, ready)) = work.pop() {
            if done.contains_key(&at) {
                continue;
            }
            let Some(node) = self.ast.expr(at).copied() else {
                done.insert(at, at);
                continue;
            };
            if !ready {
                work.push((at, true));
                for operand in node.operands(&self.ast) {
                    work.push((operand, false));
                }
                continue;
            }
            let new = if let Expr::Var(var) = node {
                match renamed.get(&var) {
                    Some(&new) => self.read(new),
                    None => at,
                }
            } else if node
                .operands(&self.ast)
                .any(|operand| done.get(&operand).is_some_and(|&new| new != operand))
            {
                let width = self.width_of(at);
                let rebuilt = self.ast.map_operands(node, &mut |operand| {
                    done.get(&operand).copied().unwrap_or(operand)
                });
                self.add(rebuilt, width)
            } else {
                at
            };
            done.insert(at, new);
        }
        done.get(&expr).copied().unwrap_or(expr)
    }
}

/// The evidence of a type the solver gave where lowering had `evidence`:
/// deduced, but a declaration's stays (one declared only a pointer takes
/// the pointer the solver gives it and keeps its evidence).
const fn deduced(evidence: Evidence) -> Evidence {
    match evidence {
        Evidence::Declared | Evidence::DeclaredPointer => evidence,
        Evidence::Default | Evidence::Deduced => Evidence::Deduced,
    }
}

/// A stack offset from the entry stack pointer as a name's part: `m28`
/// for −0x28, `p8` for +8.
fn entry_offset(offset: i64) -> String {
    if offset < 0 {
        format!("m{:x}", offset.unsigned_abs())
    } else {
        format!("p{offset:x}")
    }
}

/// Which of debug information's types a variable of the frame takes
/// ([`Emit::debug_variable`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Typing {
    /// None: its type is a declaration's already (a promoted object).
    Kept,
    /// A scalar or pointer: it holds a value.
    Value,
    /// Any: it is memory.
    Memory,
}

/// Whether `ty` is a type a value has: a scalar or a pointer (not an
/// aggregate, an array or a vector, which a C variable holding a value
/// is not).
const fn scalar(ty: Option<&Type>) -> bool {
    match ty {
        Some(
            Type::Bits(_)
            | Type::Int(_)
            | Type::UInt(_)
            | Type::Char { .. }
            | Type::Bool(_)
            | Type::Float(_)
            | Type::Pointer(_)
            | Type::Code(_)
            | Type::Enum(_),
        ) => true,
        Some(Type::Struct(_) | Type::Union(_) | Type::Array { .. } | Type::Vector { .. })
        | None => false,
    }
}

/// The origins of the local of a class of `members`, values of `l1`: each
/// value, and the register the first held in one was held in, to name it
/// by.
fn origins(l1: &binbun_ssa::ir::Function, members: &[Value]) -> Vec<Origin> {
    let mut origins: Vec<Origin> = members.iter().map(|&v| Origin::Value(v)).collect();
    origins.extend(
        members
            .iter()
            .find_map(|value| l1.held.get(value))
            .map(|&register| Origin::Held(register)),
    );
    origins
}

/// The natural alignment in bytes of type `id` of `types` as C lays it
/// out on the printer's targets: a scalar's width rounded up to a power of
/// two (at most 16), an array's element's, an aggregate's largest field's
/// (1 for a vector or a type leading back to itself).
fn alignment(types: &Types, id: TypeId) -> u64 {
    alignment_within(types, id, types.len())
}

/// [`alignment`], `depth` types deep at most.
fn alignment_within(types: &Types, id: TypeId, depth: usize) -> u64 {
    let Some(depth) = depth.checked_sub(1) else {
        return 1;
    };
    match types.get(id) {
        Some(&Type::Array { element, .. }) => alignment_within(types, element, depth),
        Some(Type::Struct(aggregate) | Type::Union(aggregate)) => aggregate
            .fields
            .iter()
            .map(|field| alignment_within(types, field.ty, depth))
            .max()
            .unwrap_or(1),
        ty if scalar(ty) => types.width(id).map_or(1, |width| {
            width.div_ceil(8).max(1).next_power_of_two().min(16)
        }),
        Some(_) | None => 1,
    }
}
