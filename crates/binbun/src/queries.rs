//! What the reading view shows beside a decompiled function's C, each a
//! query on the [`Database`] for one function: synchronous, framework
//! free and cancel-safe (each returns owned data and keeps nothing but
//! what the database caches), so a session can run them on its worker.
//!
//! - [`verify`]: the function checked against its L1 on demand, in a
//!   view: the structure check and the differential from random states,
//!   with a counterexample where they differ.
//! - [`evidence`]: why each variable, parameter, global and the return
//!   value has its printed type and name.
//! - [`origin`]: where a value comes from (backward through L1's
//!   dataflow, trivial steps folded) and where it goes.
//! - [`compare`]: whether the function behaves differently on different
//!   processors (their profiles), and which site decides.
//!
//! All start from the function as decompilation makes it in the view
//! asked for ([`lower`]; the comparison, the exact view's): the same L1,
//! lowering and L2 passes, so what they say is about the C the user
//! reads.

pub mod compare;
pub mod evidence;
pub mod origin;
pub mod verify;

use binbun_ast::ir::{Function as Ast, Origin, VarKind};
use binbun_decompile::mapping::Mapping;
use binbun_decompile::names;
use binbun_decompile::pass::{Feeds, L2Env};
use binbun_ssa::ir::{Definition, Function, Op, Terminator, Value};

use crate::Database;
use crate::cfg::FunctionId;
use crate::decompile::{
    Interfaces, Prepared, View, l2_passes, lower_function, reading_l1, stream_parallel,
};

/// A function lowered and through the L2 passes as decompilation makes
/// it in a view ([`lower`]).
#[derive(Debug)]
pub struct Lowered {
    /// Its entry.
    pub entry: u64,
    /// The L1 it is lowered from: in the reading view, the assumed L1
    /// ([`reading_l1`]).
    pub prepared: Prepared,
    /// Its L2, after the L2 passes, named as decompilation names it.
    pub l2: Ast,
    /// Where its parameters, return value and calls are in L1's state.
    pub mapping: Mapping,
}

/// Function `id` of `database` as decompilation makes it in `view`
/// ([`Database::decompile`]: the same preparation, lowering and passes,
/// those `disabled` not run), with the interfaces of its callees.
///
/// # Errors
///
/// The function is not lifted, lowering fails, or a pass leaves L2
/// failing its verifier.
pub fn lower(
    database: &Database<'_>,
    id: FunctionId,
    view: View,
    disabled: &[String],
) -> Result<(Lowered, Interfaces), String> {
    let (prepared, interfaces) = database.prepare_in(id, view, disabled);
    let lowered = lower_prepared(database, prepared?, &interfaces, view, disabled)?;
    Ok((lowered, interfaces))
}

/// [`lower`] of a function `prepared` (by [`Database::prepare`] or the
/// stream) with its callees' `interfaces`.
///
/// # Errors
///
/// As for [`lower`].
pub fn lower_prepared(
    database: &Database<'_>,
    prepared: Prepared,
    interfaces: &Interfaces,
    view: View,
    disabled: &[String],
) -> Result<Lowered, String> {
    let image = database.image();
    let declarations = database
        .declarations()
        .ok_or_else(|| "the image's code is not lifted".to_owned())?;
    let prepared = match view {
        View::Exact => prepared,
        View::Reading => reading_l1(image, &prepared, disabled)?.0,
    };
    let entry = prepared.l1.entry;
    let prototypes = database.prototypes();
    let (mut l2, mapping, _) =
        lower_function(image, &prepared, interfaces, &prototypes, database.data())?;
    l2.name = database.data_name(entry);
    let feeds = Feeds::new(&prepared.l1);
    let env = L2Env {
        declarations,
        exceptions: database.exceptions(),
        feeds: Some(&feeds),
    };
    l2_passes(&mut l2, &env, disabled)?;
    names::name(&mut l2, &prototypes);
    Ok(Lowered {
        entry,
        prepared,
        l2,
        mapping,
    })
}

/// Every function of `database` as decompilation makes it in `view` (the
/// passes `disabled`), with its callees' interfaces, given to `work` on
/// `threads` threads, what it makes of each handed to `ready` callees
/// first as the stream hands them over ([`stream_parallel`]): each is
/// lifted once, and the results and their order are the same whatever
/// the threads.
pub fn each<T: Send>(
    database: &Database<'_>,
    view: View,
    disabled: &[String],
    threads: usize,
    work: impl Fn(FunctionId, Result<Lowered, String>, &Interfaces) -> T + Sync,
    ready: impl FnMut(T),
) {
    let callers = database.callers_in(view, disabled);
    stream_parallel(
        database.image(),
        database.program(),
        database.summaries(),
        &callers,
        disabled,
        threads,
        |id, prepared, interfaces| {
            let lowered = prepared.and_then(|prepared| {
                lower_prepared(database, prepared, interfaces, view, disabled)
            });
            work(id, lowered, interfaces)
        },
        ready,
    );
}

/// The address of the machine instruction that defines `value` of `l1`
/// (a block parameter: its block's first).
pub(crate) fn defined_at(l1: &Function, value: Value) -> Option<u64> {
    match l1.value(value)?.definition {
        Definition::Result { inst, .. } => l1.inst(inst).map(|inst| inst.address),
        Definition::Parameter { block, .. } => l1.block(block).map(|block| block.address),
    }
}

/// The constant `value` of `l1` is, if one (as a 64-bit address).
pub(crate) fn constant(l1: &Function, value: Value) -> Option<u64> {
    let Definition::Result { inst, .. } = l1.value(value)?.definition else {
        return None;
    };
    if let Op::Const(bits) = &l1.inst(inst)?.op {
        Some(bits.low_u64())
    } else {
        None
    }
}

/// The addresses of the calls of `l1` through `target` (the value, or
/// the same constant), and of its jumps out of the function to it (tail
/// calls: their block's address).
pub(crate) fn calls_through(l1: &Function, target: Value) -> Vec<u64> {
    let wanted = constant(l1, target);
    let same =
        |value: Value| value == target || (wanted.is_some() && constant(l1, value) == wanted);
    let mut out: Vec<u64> = l1
        .insts
        .iter()
        .filter_map(|inst| {
            if let Op::Call { target, .. } = inst.op
                && same(target)
            {
                Some(inst.address)
            } else {
                None
            }
        })
        .collect();
    out.extend(l1.blocks.iter().filter_map(|block| {
        if let Terminator::Leave { address, .. } = block.terminator
            && same(address)
        {
            Some(block.address)
        } else {
            None
        }
    }));
    out.sort_unstable();
    out.dedup();
    out
}

/// The L1 values of `l1` a variable of `kind` made from `origins` stands
/// for: its values, a register parameter's or environment register's
/// entry value and the low parts of it the code takes (a 32-bit
/// parameter is the low half of its register's entry value).
pub fn values_of(l1: &Function, kind: VarKind, origins: &[Origin]) -> Vec<Value> {
    let entry = l1.blocks.first().map_or(&[][..], |block| &block.parameters);
    let mut values: Vec<Value> = origins
        .iter()
        .filter_map(|origin| match (origin, kind) {
            (Origin::Value(value), _) => Some(*value),
            (Origin::Register(register), VarKind::Parameter | VarKind::Environment(_)) => {
                entry.get(usize::from(register.0)).copied()
            }
            (Origin::Register(_), VarKind::Local | VarKind::Frame(_) | VarKind::Global(_))
            | (
                Origin::Instruction(_)
                | Origin::Held(_)
                | Origin::Slot(_)
                | Origin::Block(_)
                | Origin::Absorbed(_)
                | Origin::Proved,
                _,
            ) => None,
        })
        .collect();
    if matches!(kind, VarKind::Parameter | VarKind::Environment(_)) {
        let low: Vec<Value> = l1
            .insts
            .iter()
            .filter_map(|inst| {
                if let Op::Extract {
                    value, offset: 0, ..
                } = inst.op
                    && values.contains(&value)
                {
                    inst.results.first().copied()
                } else {
                    None
                }
            })
            .collect();
        values.extend(low);
    }
    values
}
