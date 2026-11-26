//! Declared structs as the table's identities (debug information is the
//! strongest name): where a function's debug information declares a root
//! a pointer to a named struct or union (a parameter, the return value,
//! an argument to a function of the program the debug information
//! declares, a frame variable, a global) or a global object of one, the
//! table struct that root's family is takes that declared type as its
//! identity ([`Structs`](super::Structs)).
//!
//! - **Roots** ([`Declared`]): a value of a declared pointer type (the
//!   struct is the family's at offset 0 in its struct), the values stored
//!   to and loaded from a frame slot or a global declared a pointer, a
//!   global object declared a struct (its family's struct is it), and a
//!   region of the stack frame passed as a declared pointer (the struct
//!   callees' roots claim it at its start is it:
//!   [`Contribution::regions`]).
//! - **Portable**: the declared type travels in a [`Types`] of its own
//!   ([`copy`]); a named struct or union a table already holds of that
//!   name, kind and size is that one (C has one type per tag), so the
//!   table's struct interned into a function whose debug information
//!   declares the type is the very type its declarations use.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use binbun_ast::types::{Aggregate, Field, Signature, Type, TypeId, Types};
use binbun_ssa::ir::{InstId, Value};
use binbun_typeinfer::Var;

use super::generate::Generated;
use super::structs::{Contribution, StructId, place};
use crate::prototype::Prototypes;

/// A root the debug information declares the type of.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Declared {
    /// A value of the type (a parameter's entry value, a value returned,
    /// an argument to a declared parameter).
    Value(Value, TypeId),
    /// The values stored to and loaded from the frame slot (by index) of
    /// the type.
    Slot(usize, TypeId),
    /// The region of the stack frame starting at this offset from the
    /// entry stack pointer, passed as a value of the type.
    Region(i64, TypeId),
}

/// Records in `contribution` the declared struct each of `roots` (types in
/// `types`) and of each global the function reaches points to (its type
/// [`Prototypes::global`], interned in `types`: an object of a struct type
/// is that struct, one of a pointer type holds pointers to it), by the
/// struct its family is in `contribution` ([`Contribution::accesses`])
/// where the root is at the struct's start.
pub(crate) fn declare(
    generated: &Generated,
    roots: &[Declared],
    prototypes: &dyn Prototypes,
    types: &mut Types,
    contribution: &mut Contribution,
) {
    let mut vars: Vec<(Var, TypeId)> = Vec::new();
    let mut regions: Vec<(StructId, TypeId)> = Vec::new();
    let cells = |var: Var| generated.cells.get(&var).into_iter().flatten().copied();
    for &root in roots {
        match root {
            Declared::Value(value, ty) => {
                if let (Some(var), Some(target)) = (generated.var(value), pointee(types, ty)) {
                    vars.push((var, target));
                }
            }
            Declared::Slot(slot, ty) => {
                if let (Some(&Some(var)), Some(target)) =
                    (generated.slots.get(slot), pointee(types, ty))
                {
                    vars.extend(cells(var).map(|cell| (cell, target)));
                }
            }
            Declared::Region(at, ty) => {
                if let (Some(&id), Some(target)) =
                    (contribution.regions.get(&at), pointee(types, ty))
                {
                    regions.push((id, target));
                }
            }
        }
    }
    for (&start, &var) in &generated.objects {
        if let Some(ty) = prototypes.global(start, types)
            && named(types, ty)
        {
            vars.push((var, ty));
        }
    }
    for (&start, &(var, _)) in &generated.globals {
        if let Some(ty) = prototypes.global(start, types)
            && let Some(target) = pointee(types, ty)
        {
            vars.extend(cells(var).map(|cell| (cell, target)));
        }
    }
    if vars.is_empty() && regions.is_empty() {
        return;
    }
    let accesses: BTreeMap<InstId, (StructId, i64)> = contribution
        .accesses
        .iter()
        .map(|&(inst, id, base)| (inst, (id, base)))
        .collect();
    let mut map = BTreeMap::new();
    let mut declare = |id: StructId, target: TypeId, contribution: &mut Contribution| {
        let into = contribution
            .declared_types
            .get_or_insert_with(|| Types::new(types.pointer_width()));
        if let Some(ty) = copy(&*types, target, into, &mut map)
            && !contribution.declared.contains(&(id, ty))
        {
            contribution.declared.push((id, ty));
        }
    };
    for (id, target) in regions {
        declare(id, target, contribution);
    }
    for (var, target) in vars {
        let Some((index, offset, 0)) = generated.families.of(var) else {
            continue;
        };
        let Some(family) = generated.families.get(index) else {
            continue;
        };
        let Some(&(id, base)) = family
            .accesses
            .iter()
            .find_map(|access| accesses.get(&access.inst))
        else {
            continue;
        };
        if place(offset, base, family.stride) != 0 {
            continue;
        }
        declare(id, target, contribution);
    }
}

/// The named struct or union type `ty` points to, if it does.
fn pointee(types: &Types, ty: TypeId) -> Option<TypeId> {
    let &Type::Pointer(Some(target)) = types.get(ty)? else {
        return None;
    };
    named(types, target).then_some(target)
}

/// Whether `ty` is a struct or union with a name.
fn named(types: &Types, ty: TypeId) -> bool {
    matches!(
        types.get(ty),
        Some(
            Type::Struct(Aggregate { name: Some(_), .. })
                | Type::Union(Aggregate { name: Some(_), .. })
        )
    )
}

/// Type `id` of `from` in `into` (each type of `from` once, by `map`): a
/// named struct or union `into` already holds of its name, kind and size
/// is that one, else it is copied with what it holds.
pub(crate) fn copy(
    from: &Types,
    id: TypeId,
    into: &mut Types,
    map: &mut BTreeMap<TypeId, TypeId>,
) -> Option<TypeId> {
    if let Some(&done) = map.get(&id) {
        return Some(done);
    }
    let ty = match from.get(id)?.clone() {
        Type::Struct(aggregate) => return Some(record(from, id, &aggregate, false, into, map)),
        Type::Union(aggregate) => return Some(record(from, id, &aggregate, true, into, map)),
        Type::Pointer(Some(target)) => Type::Pointer(Some(copy(from, target, into, map)?)),
        Type::Array { element, length } => Type::Array {
            element: copy(from, element, into, map)?,
            length,
        },
        Type::Vector { lanes, element } => Type::Vector {
            lanes,
            element: copy(from, element, into, map)?,
        },
        Type::Code(signature) => {
            let mut parameters = Vec::with_capacity(signature.parameters.len());
            for &parameter in &signature.parameters {
                parameters.push(copy(from, parameter, into, map)?);
            }
            let returns = match signature.returns {
                Some(returns) => Some(copy(from, returns, into, map)?),
                None => None,
            };
            Type::Code(Signature {
                parameters,
                returns,
                variadic: signature.variadic,
            })
        }
        scalar @ (Type::Bits(_)
        | Type::Int(_)
        | Type::UInt(_)
        | Type::Char { .. }
        | Type::Bool(_)
        | Type::Float(_)
        | Type::Pointer(None)
        | Type::Enum(_)) => scalar,
    };
    let copied = into.intern(ty);
    map.insert(id, copied);
    Some(copied)
}

/// [`copy`] of struct or union `id` (`aggregate`).
fn record(
    from: &Types,
    id: TypeId,
    aggregate: &Aggregate,
    union: bool,
    into: &mut Types,
    map: &mut BTreeMap<TypeId, TypeId>,
) -> TypeId {
    let existing = aggregate.name.as_ref().and_then(|name| {
        into.iter().find_map(|(existing, ty)| {
            let (Type::Struct(held) | Type::Union(held)) = ty else {
                return None;
            };
            let same = held.name.as_ref() == Some(name)
                && held.size == aggregate.size
                && matches!(ty, Type::Union(_)) == union;
            same.then_some(existing)
        })
    });
    if let Some(existing) = existing {
        map.insert(id, existing);
        return existing;
    }
    let shell = Aggregate {
        name: aggregate.name.clone(),
        size: aggregate.size,
        fields: Vec::new(),
    };
    let copied = into.intern(if union {
        Type::Union(shell)
    } else {
        Type::Struct(shell)
    });
    map.insert(id, copied);
    let fields: Vec<Field> = aggregate
        .fields
        .iter()
        .filter_map(|field| {
            Some(Field {
                offset: field.offset,
                ty: copy(from, field.ty, into, map)?,
                name: field.name.clone(),
            })
        })
        .collect();
    if let Some(held) = into.aggregate_mut(copied) {
        held.fields = fields;
    }
    copied
}
