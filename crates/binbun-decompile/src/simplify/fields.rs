//! The fields of the thread's declared structure: [`DeclaredFields`].

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

use binbun_ast::ir::{Expr, ExprId, Function, Place, Stmt, VarId, VarKind};
use binbun_ast::types::{Evidence, Type, TypeId, Types};
use binbun_semantics::core::pass::{Changed, Cx, Pass, Refusal};
use binbun_semantics::ir::Binary;

use crate::pass::{L2Env, size};

/// How deep an address's base is followed through loads.
const DEPTH: u8 = 16;

/// The pass `declared-fields`, after the others but [`Signs`](super::signs::Signs):
/// the types of what is read and written through the thread pointer,
/// where its environment variable has the type its platform declares
/// ([`Prototypes::thread_pointer`](crate::prototype::Prototypes::thread_pointer):
/// a pointer to Windows x64's TEB, to x86-64 glibc's `tcbhead_t`).
///
/// A load or store of `w` bits at `p + k` (or `p`), where `p` is such a
/// pointer to a structure with a field (in nested structures and unions
/// too; not in an array) starting at `k` of `w` bits, an integer, a
/// character, a boolean, a pointer or code, may take the field's type,
/// which is one of those too (never a float's place):
///
/// - an integer type, where it has an integer type (or only a width):
///   the declaration's signedness;
/// - a pointer to a structure, where the value is the base of accesses
///   and each is at a field of that structure (otherwise the code reads
///   it as something else: TEB's `NtTib.Self` is the TEB itself, a
///   `struct _NT_TIB *` read past its end).
///
/// Other pointers and code keep their types (a `void *` field the code
/// reads as an integer or indexes would only gain casts).
///
/// The pointer `p` is the environment variable, a load that took a
/// pointer to a structure this way (`teb->ProcessEnvironmentBlock->Ldr`),
/// or a local that takes one, declared: every assignment of it assigns
/// such a load or a value of that type, and the accesses through the
/// local are at its fields (a list's `entry = entry->Flink`). The bits
/// are the same; only how C reads them changes.
/// A local assigned once a field's address (`&peb->Ldr`), the field a
/// structure or a pointer to one, whose accesses are all within the
/// field, takes a pointer to its type, declared, and is such a `p` too.
///
/// Types are changed in place (an expression's users all read the same
/// load); nothing else is. Preserves everything. Fuel: a unit per
/// statement and expression.
#[derive(Clone, Copy, Debug, Default)]
pub struct DeclaredFields;

impl<'e> Pass<Function, L2Env<'e>> for DeclaredFields {
    fn name(&self) -> &'static str {
        "declared-fields"
    }

    fn run(
        &mut self,
        function: &mut Function,
        cx: &mut Cx<'_, Function, L2Env<'e>>,
    ) -> Result<Changed, Refusal> {
        let rooted = function.variables.iter().any(|variable| {
            matches!(variable.kind, VarKind::Environment(_))
                && structure(&function.types, variable.ty).is_some()
        });
        if !rooted {
            return Ok(Changed::No);
        }
        cx.fuel.spend(size(function))?;
        let declared = declared(function);
        let uses = Uses::new(function);
        let (mut addresses, mut locals) = (BTreeMap::new(), BTreeMap::new());
        for _ in 0..4 {
            let grown = grow_addresses(function, &uses, &declared, &locals, &mut addresses);
            let supposed = suppose(function, &uses, &declared, &addresses);
            if !grown && supposed == locals {
                break;
            }
            locals = supposed;
        }
        let mut changed = false;
        let mut retyped: Vec<(VarId, TypeId)> = locals.into_iter().collect();
        for (&var, &target) in &addresses {
            retyped.push((var, function.types.intern(Type::Pointer(Some(target)))));
        }
        for (var, ty) in retyped {
            if let Some(variable) = function.variables.get_mut(var.0 as usize)
                && variable.ty != ty
            {
                variable.ty = ty;
                variable.evidence = Evidence::Declared;
                changed = true;
            }
        }
        let typing = Typing {
            function,
            uses: &uses,
            declared: &declared,
            addresses: &addresses,
            locals: &BTreeMap::new(),
        };
        let mut loads = Vec::new();
        for (index, expr) in function.exprs.iter().enumerate() {
            let id = ExprId(u32::try_from(index).unwrap_or(u32::MAX));
            if let &Expr::Load { ty, .. } = expr
                && let Some(field) = typing.ty(id, 0)
                && field != ty
            {
                loads.push((index, field));
            }
        }
        let mut stores = Vec::new();
        for (index, stmt) in function.stmts.iter().enumerate() {
            if let Stmt::Assign {
                place: Place::Memory { address, ty },
                ..
            } = *stmt
                && let Some(field) = typing.field(address, ty, 0)
                && field != ty
                && typing.takes(field, ty, None)
            {
                stores.push((index, field));
            }
        }
        for (index, field) in loads {
            if let Some(Expr::Load { ty, .. }) = function.exprs.get_mut(index) {
                *ty = field;
                changed = true;
            }
        }
        for (index, field) in stores {
            if let Some(Stmt::Assign {
                place: Place::Memory { ty, .. },
                ..
            }) = function.stmts.get_mut(index)
            {
                *ty = field;
                changed = true;
            }
        }
        Ok(if changed { Changed::Yes } else { Changed::No })
    }
}

/// The structure or union a pointer type points to.
fn structure(types: &Types, ty: TypeId) -> Option<TypeId> {
    let &Type::Pointer(Some(target)) = types.get(ty)? else {
        return None;
    };
    matches!(types.get(target)?, Type::Struct(_) | Type::Union(_)).then_some(target)
}

/// The structures and unions the thread pointer's declared type reaches:
/// its target, and what their fields hold or point to.
fn declared(function: &Function) -> BTreeSet<TypeId> {
    let types = &function.types;
    let mut pending: Vec<TypeId> = function
        .variables
        .iter()
        .filter(|variable| matches!(variable.kind, VarKind::Environment(_)))
        .filter_map(|variable| structure(types, variable.ty))
        .collect();
    let mut seen = BTreeSet::new();
    while let Some(ty) = pending.pop() {
        if let Some(Type::Struct(aggregate) | Type::Union(aggregate)) = types.get(ty) {
            if seen.insert(ty) {
                pending.extend(aggregate.fields.iter().map(|field| field.ty));
            }
        } else if let Some(
            &(Type::Pointer(Some(target))
            | Type::Array {
                element: target, ..
            }),
        ) = types.get(ty)
        {
            pending.push(target);
        }
    }
    seen
}

/// Whether an access of `bits` bits at `offset` into a `ty` is at a field
/// of it (a structure's, a union's), or is the whole `ty` (a scalar).
fn within(types: &Types, ty: TypeId, offset: u64, bits: u16) -> bool {
    if matches!(types.get(ty), Some(Type::Struct(_) | Type::Union(_))) {
        field_at(types, ty, offset, bits, 0).is_some()
    } else {
        offset == 0 && types.value_width(ty) == Some(bits) && scalar(types, ty)
    }
}

/// Grows `addresses`, the locals assigned once a field's address
/// (`&p->field`: `p + k`, `p` a pointer to a declared structure with a
/// field, not an array, starting at `k`) whose every access is within
/// that field, with the field's type; whether any was added.
fn grow_addresses(
    function: &Function,
    uses: &Uses,
    declared: &BTreeSet<TypeId>,
    locals: &BTreeMap<VarId, TypeId>,
    addresses: &mut BTreeMap<VarId, TypeId>,
) -> bool {
    let types = &function.types;
    let mut grown = false;
    loop {
        let mut found = Vec::new();
        let typing = Typing {
            function,
            uses,
            declared,
            addresses,
            locals,
        };
        for (&var, &(base, offset)) in &uses.addresses {
            if addresses.contains_key(&var) {
                continue;
            }
            let Some(target) = typing
                .target(base, 0)
                .filter(|target| declared.contains(target))
            else {
                continue;
            };
            let Some(Type::Struct(aggregate) | Type::Union(aggregate)) = types.get(target) else {
                continue;
            };
            let Some(field) = aggregate.fields.iter().find_map(|field| {
                (field.offset == offset && !matches!(types.get(field.ty), Some(Type::Array { .. })))
                    .then_some(field.ty)
            }) else {
                continue;
            };
            let vague = function.var(var).is_some_and(|variable| {
                matches!(
                    types.get(variable.ty),
                    Some(Type::Bits(_) | Type::Pointer(_))
                )
            });
            let leads = matches!(types.get(field), Some(Type::Struct(_) | Type::Union(_)))
                || structure(types, field).is_some_and(|target| declared.contains(&target));
            let through = uses.vars.get(&var).map_or(&[][..], Vec::as_slice);
            if vague
                && leads
                && !through.is_empty()
                && through
                    .iter()
                    .all(|&(at, bits)| within(types, field, at, bits))
            {
                found.push((var, field));
            }
        }
        if found.is_empty() {
            return grown;
        }
        addresses.extend(found);
        grown = true;
    }
}

/// Whether a value of type `ty` may take a field's type (and a field of
/// type `ty` be taken): an integer, character, boolean, pointer or code.
fn scalar(types: &Types, ty: TypeId) -> bool {
    matches!(
        types.get(ty),
        Some(
            Type::Int(_)
                | Type::UInt(_)
                | Type::Bits(_)
                | Type::Char { .. }
                | Type::Bool(_)
                | Type::Pointer(_)
                | Type::Code(_)
        )
    )
}

/// Whether `ty` is an integer, a character or a boolean.
fn integer(types: &Types, ty: TypeId) -> bool {
    matches!(
        types.get(ty),
        Some(Type::Int(_) | Type::UInt(_) | Type::Char { .. } | Type::Bool(_))
    )
}

/// The type of the field of `bits` bits starting at byte `offset` of
/// aggregate `aggregate`, looking into nested structures and unions (the
/// first such field, in a union).
fn field_at(types: &Types, aggregate: TypeId, offset: u64, bits: u16, depth: u8) -> Option<TypeId> {
    let (Type::Struct(aggregate) | Type::Union(aggregate)) = types.get(aggregate)? else {
        return None;
    };
    let depth = depth.checked_add(1).filter(|&depth| depth < DEPTH)?;
    aggregate.fields.iter().find_map(|field| {
        let within = offset.checked_sub(field.offset)?;
        let bytes = types.width(field.ty)? / 8;
        if within >= bytes {
            return None;
        }
        if matches!(types.get(field.ty)?, Type::Struct(_) | Type::Union(_)) {
            field_at(types, field.ty, within, bits, depth)
        } else {
            (within == 0
                && types.value_width(field.ty) == Some(bits)
                && scalar(types, field.ty)
                && !matches!(types.get(field.ty), Some(Type::Bits(_))))
            .then_some(field.ty)
        }
    })
}

/// An address as a base plus a constant (`p + k`, `k + p`, `p`).
fn split(function: &Function, address: ExprId) -> Option<(ExprId, u64)> {
    let &Expr::Binary(Binary::Add, left, right) = function.expr(address)? else {
        return Some((address, 0));
    };
    if let Expr::Const(constant) = function.expr(right)? {
        return Some((left, u64::try_from(constant.low_u128()).ok()?));
    }
    if let Expr::Const(constant) = function.expr(left)? {
        return Some((right, u64::try_from(constant.low_u128()).ok()?));
    }
    None
}

/// Each local's assigned values, and the variables a call or intrinsic
/// writes.
fn assignments(function: &Function) -> (BTreeMap<VarId, Vec<ExprId>>, BTreeSet<VarId>) {
    let mut assigned: BTreeMap<VarId, Vec<ExprId>> = BTreeMap::new();
    let mut excluded = BTreeSet::new();
    for stmt in &function.stmts {
        if let Stmt::Assign {
            place: Place::Var(var),
            value,
        } = *stmt
        {
            assigned.entry(var).or_default().push(value);
        } else if let Stmt::Call { results, .. } | Stmt::Intrinsic { results, .. } = stmt {
            excluded.extend(results.iter().filter_map(|place| match *place {
                Place::Var(var) => Some(var),
                Place::Memory { .. } => None,
            }));
        }
    }
    (assigned, excluded)
}

/// The accesses through each value (a load's, or one assigned to a
/// local) and each variable: their offsets and widths; an access through
/// a local assigned once an address `p + k` counts as one through `p` too.
struct Uses {
    exprs: BTreeMap<ExprId, Vec<(u64, u16)>>,
    vars: BTreeMap<VarId, Vec<(u64, u16)>>,
    /// The locals assigned once `p + k` (and nothing else), with `p` and `k`.
    addresses: BTreeMap<VarId, (ExprId, u64)>,
}

impl Uses {
    fn new(function: &Function) -> Self {
        let (assignments, excluded) = assignments(function);
        let addresses = assignments
            .iter()
            .filter(|(var, _)| {
                !excluded.contains(*var)
                    && function
                        .var(**var)
                        .is_some_and(|variable| variable.kind == VarKind::Local)
            })
            .filter_map(|(&var, values)| {
                let [value] = values.as_slice() else {
                    return None;
                };
                matches!(function.expr(*value)?, Expr::Binary(Binary::Add, ..)).then_some(())?;
                Some((var, split(function, *value)?))
            })
            .collect();
        let mut accesses = Vec::new();
        for expr in &function.exprs {
            if let &Expr::Load { address, ty } = expr {
                accesses.push((address, ty));
            }
        }
        for stmt in &function.stmts {
            if let Stmt::Assign {
                place: Place::Memory { address, ty },
                ..
            } = *stmt
            {
                accesses.push((address, ty));
            }
        }
        let mut uses = Self {
            exprs: BTreeMap::new(),
            vars: BTreeMap::new(),
            addresses,
        };
        for (address, ty) in accesses {
            let (Some((base, offset)), Some(bits)) =
                (split(function, address), function.types.value_width(ty))
            else {
                continue;
            };
            let (mut base, mut offset) = (base, offset);
            for _ in 0..DEPTH {
                match function.expr(base) {
                    Some(&Expr::Var(var)) => {
                        uses.vars.entry(var).or_default().push((offset, bits));
                        let Some(&(next, k)) = uses.addresses.get(&var) else {
                            break;
                        };
                        let Some(sum) = offset.checked_add(k) else {
                            break;
                        };
                        (base, offset) = (next, sum);
                    }
                    Some(_) => {
                        uses.exprs.entry(base).or_default().push((offset, bits));
                        break;
                    }
                    None => break,
                }
            }
        }
        // A load assigned to a local is used as the local is.
        for stmt in &function.stmts {
            if let Stmt::Assign {
                place: Place::Var(var),
                value,
            } = *stmt
                && let Some(through) = uses.vars.get(&var).cloned()
            {
                uses.exprs.entry(value).or_default().extend(through);
            }
        }
        uses
    }
}

/// The types of a function's values as the fields say, with some locals'
/// types supposed.
struct Typing<'f> {
    function: &'f Function,
    uses: &'f Uses,
    /// The structures the thread pointer's type reaches ([`declared`]).
    declared: &'f BTreeSet<TypeId>,
    /// The locals holding a field's address, with the field's type.
    addresses: &'f BTreeMap<VarId, TypeId>,
    locals: &'f BTreeMap<VarId, TypeId>,
}

impl Typing<'_> {
    /// The declared structure a pointer type points to.
    fn structure(&self, ty: TypeId) -> Option<TypeId> {
        structure(&self.function.types, ty).filter(|target| self.declared.contains(target))
    }

    /// What the pointer `id` points to: a field's type for a local
    /// holding its address, else its type's target.
    fn target(&self, id: ExprId, depth: u8) -> Option<TypeId> {
        if let Some(&Expr::Var(var)) = self.function.expr(id)
            && let Some(&field) = self.addresses.get(&var)
        {
            return Some(field);
        }
        let &Type::Pointer(target) = self.function.types.get(self.ty(id, depth)?)? else {
            return None;
        };
        target
    }

    /// The type of `id`'s value, if it is a variable's, a load's or a
    /// cast's: a load's as the fields say, where it takes it.
    fn ty(&self, id: ExprId, depth: u8) -> Option<TypeId> {
        let expr = self.function.expr(id)?;
        if let &Expr::Var(var) = expr {
            return self
                .locals
                .get(&var)
                .copied()
                .or_else(|| Some(self.function.var(var)?.ty));
        }
        if let &Expr::Load { address, ty } = expr {
            return Some(
                self.field(address, ty, depth)
                    .filter(|&field| {
                        let uses = self.uses.exprs.get(&id).map_or(&[][..], Vec::as_slice);
                        self.takes(field, ty, Some(uses))
                    })
                    .unwrap_or(ty),
            );
        }
        if let &Expr::Cast { ty, .. } = expr {
            return Some(ty);
        }
        None
    }

    /// The type of the field an access of type `ty` at `address` reads or
    /// writes, if `address` is a pointer to a structure plus a constant
    /// and the structure has such a field.
    fn field(&self, address: ExprId, ty: TypeId, depth: u8) -> Option<TypeId> {
        let depth = depth.checked_add(1).filter(|&depth| depth < DEPTH)?;
        let types = &self.function.types;
        if !scalar(types, ty) {
            return None;
        }
        let bits = types.value_width(ty)?;
        let (base, offset) = split(self.function, address)?;
        let target = self.target(base, depth)?;
        if self.declared.contains(&target) {
            return field_at(types, target, offset, bits, 0);
        }
        // Through a field's address: the field itself.
        let address_local = matches!(
            self.function.expr(base),
            Some(Expr::Var(var)) if self.addresses.contains_key(var)
        );
        (address_local
            && offset == 0
            && types.value_width(target) == Some(bits)
            && scalar(types, target)
            && !matches!(types.get(target), Some(Type::Bits(_))))
        .then_some(target)
    }

    /// Whether a value of type `ty` accessed at `uses` (none: a store's)
    /// takes field type `field` (the rules of [`DeclaredFields`]).
    fn takes(&self, field: TypeId, ty: TypeId, uses: Option<&[(u64, u16)]>) -> bool {
        let types = &self.function.types;
        if integer(types, field) {
            return integer(types, ty) || matches!(types.get(ty), Some(Type::Bits(_)));
        }
        let (Some(aggregate), Some(uses)) = (self.structure(field), uses) else {
            return false;
        };
        !uses.is_empty()
            && uses
                .iter()
                .all(|&(offset, bits)| field_at(types, aggregate, offset, bits, 0).is_some())
    }
}

/// The locals that take a pointer to a structure from the fields: every
/// assignment of each assigns a value of that type, one of them a load
/// that takes it, and the accesses through it are at its fields;
/// supposed together, each checked again until all hold.
fn suppose(
    function: &Function,
    uses: &Uses,
    declared: &BTreeSet<TypeId>,
    addresses: &BTreeMap<VarId, TypeId>,
) -> BTreeMap<VarId, TypeId> {
    let (mut assigned, excluded) = assignments(function);
    assigned.retain(|var, _| {
        !excluded.contains(var)
            && !addresses.contains_key(var)
            && function.var(*var).is_some_and(|variable| {
                variable.kind == VarKind::Local && variable.evidence != Evidence::Declared
            })
    });
    let mut supposed: BTreeMap<VarId, TypeId> = BTreeMap::new();
    loop {
        let mut grown = false;
        for (&var, values) in &assigned {
            if supposed.contains_key(&var) {
                continue;
            }
            let typing = Typing {
                function,
                uses,
                declared,
                addresses,
                locals: &supposed,
            };
            let candidate = values.iter().find_map(|&value| {
                let &Expr::Load { address, ty } = function.expr(value)? else {
                    return None;
                };
                let field = typing.field(address, ty, 0)?;
                typing.structure(field)?;
                typing
                    .takes(field, ty, Some(uses.vars.get(&var)?.as_slice()))
                    .then_some(field)
            });
            if let Some(ty) = candidate {
                supposed.insert(var, ty);
                grown = true;
            }
        }
        // Drop the suppositions an assignment contradicts, until none does.
        loop {
            let typing = Typing {
                function,
                uses,
                declared,
                addresses,
                locals: &supposed,
            };
            let wrong: Vec<VarId> = supposed
                .iter()
                .filter(|&(var, &ty)| {
                    assigned.get(var).is_none_or(|values| {
                        values.iter().any(|&value| typing.ty(value, 0) != Some(ty))
                    })
                })
                .map(|(&var, _)| var)
                .collect();
            if wrong.is_empty() {
                break;
            }
            for var in &wrong {
                supposed.remove(var);
                assigned.remove(var);
            }
        }
        if !grown {
            return supposed;
        }
    }
}
