//! The function's frame code, which makes no statement: the prologue's
//! saves of callee-saved registers (and of the link register), the stack
//! pointer lowered and the frame pointer set; the epilogue's restores and
//! the stack pointer raised. Its instructions go to the function's
//! signature (the prologue) and closing brace (the epilogue), or, where
//! the function has an epilogue before each of several returns, each
//! epilogue to its return's statement ([`Emit::frame_code`]).

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

use binbun_ssa::ir::{BlockId, InstId, Op, Terminator, Type, Value};

use super::Emit;
use crate::lower::facts::Kind;
use crate::lower::needed::Role;

/// How many jumps [`Emit::returning`] follows to a return.
const JUMPS: usize = 4;

/// Which end of the function an instruction's frame code is at.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum End {
    /// The prologue.
    Entry,
    /// The epilogue.
    Exit,
}

/// The frame code of a function, by machine instruction.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct FrameCode {
    /// The prologue's instructions.
    pub(super) entry: Vec<u64>,
    /// The epilogue's instructions, by the block whose return (or exit)
    /// they come before (`None`: none found).
    pub(super) exits: BTreeMap<Option<BlockId>, Vec<u64>>,
}

impl Emit<'_, '_, '_> {
    /// The function's frame code (see the module documentation): each
    /// machine instruction all of whose L1 instructions are saves (a
    /// store to the frame of a callee-saved register's or the link
    /// register's entry value), restores (a load of a save's slot nothing
    /// needs), stack addresses computed, or values nothing needs, and one
    /// of the first three. A save is the prologue's, a restore the
    /// epilogue's; stack arithmetic alone is the prologue's in the entry's
    /// block and the epilogue's in a block that returns or exits (in one
    /// that does both, by whether it lowers the stack pointer), and none
    /// elsewhere (an adjustment around a call).
    pub(super) fn frame_code(&self) -> FrameCode {
        let lw = self.lw;
        let saves = self.save_slots();
        let mut out = FrameCode::default();
        for (id, block) in lw.blocks() {
            let first = block.address == lw.l1.entry;
            let returning = self.returning(id);
            let mut at = 0;
            while at < block.insts.len() {
                let rest = block.insts.get(at..).unwrap_or_default();
                let address_of = |inst: &InstId| lw.l1.inst(*inst).map_or(0, |i| i.address);
                let address = rest.first().map_or(0, address_of);
                let length = rest
                    .iter()
                    .position(|inst| address_of(inst) != address)
                    .unwrap_or(rest.len());
                let group = rest.get(..length).unwrap_or_default();
                at += length.max(1);
                let Some((save, restore, lowered)) = self.frame_group(group, &saves) else {
                    continue;
                };
                let end = if save && !restore {
                    End::Entry
                } else if restore && !save {
                    End::Exit
                } else if save || restore {
                    continue;
                } else if first && returning.is_some() {
                    if lowered == Some(true) {
                        End::Entry
                    } else {
                        End::Exit
                    }
                } else if first {
                    End::Entry
                } else if returning.is_some() {
                    End::Exit
                } else {
                    continue;
                };
                match end {
                    End::Entry => out.entry.push(address),
                    End::Exit => out.exits.entry(returning).or_default().push(address),
                }
            }
        }
        out
    }

    /// Whether the L1 instructions `group` of one machine instruction are
    /// frame code (`None`: not), and what of it: a save, a restore, and
    /// whether stack arithmetic lowered the stack pointer (`None`: none).
    fn frame_group(
        &self,
        group: &[InstId],
        saves: &BTreeSet<usize>,
    ) -> Option<(bool, bool, Option<bool>)> {
        let lw = self.lw;
        let (mut save, mut restore, mut lowered) = (false, false, None);
        let unneeded =
            |v: &Value| !matches!(lw.l1.ty(*v), Some(Type::Bits(_))) || lw.role(*v) == Role::None;
        for &inst in group {
            let i = lw.l1.inst(inst)?;
            match &i.op {
                &Op::Store { value, .. } => {
                    let slot = lw.frame.accesses.get(&inst)?;
                    if !saves.contains(slot) || !self.is_save(value) {
                        return None;
                    }
                    save = true;
                }
                Op::Load { .. } => {
                    let slot = lw.frame.accesses.get(&inst)?;
                    if !saves.contains(slot) || !i.results.iter().all(unneeded) {
                        return None;
                    }
                    restore = true;
                }
                op @ (Op::Const(_)
                | Op::Undefined(..)
                | Op::Unary(..)
                | Op::Binary(..)
                | Op::Flag(..)
                | Op::Extract { .. }
                | Op::Concat { .. }
                | Op::Extend { .. }
                | Op::Select { .. }
                | Op::Lanes { .. }
                | Op::Float { .. }
                | Op::Intrinsic { .. }
                | Op::Call { .. }
                | Op::SystemCall { .. }
                | Op::Landing { .. }) => {
                    for result in &i.results {
                        if let Kind::Address(offset) = lw.kind(*result) {
                            let from = op.operands().into_iter().find_map(|o| {
                                if let Kind::Address(from) = lw.kind(o) {
                                    Some(from)
                                } else {
                                    None
                                }
                            })?;
                            lowered = Some(offset < from);
                        } else if !unneeded(result) {
                            return None;
                        }
                    }
                }
            }
        }
        (save || restore || lowered.is_some()).then_some((save, restore, lowered))
    }

    /// Whether `value` is a callee-saved register's or the link register's
    /// entry value, or its low part ([`Lowering::saved_entry`]).
    fn is_save(&self, value: Value) -> bool {
        self.lw.saved_entry(value).is_some()
    }

    /// The frame slots a save writes.
    fn save_slots(&self) -> BTreeSet<usize> {
        let lw = self.lw;
        lw.l1
            .insts
            .iter()
            .zip(0u32..)
            .filter_map(|(i, id)| match i.op {
                Op::Store { value, .. } if self.is_save(value) => {
                    lw.frame.accesses.get(&InstId(id)).copied()
                }
                Op::Store { .. }
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
                | Op::Float { .. }
                | Op::Load { .. }
                | Op::Intrinsic { .. }
                | Op::Call { .. }
                | Op::SystemCall { .. }
                | Op::Landing { .. } => None,
            })
            .collect()
    }

    /// The block whose return or exit block `id` comes before: itself, or
    /// the one a few jumps take it to; `None` if none.
    fn returning(&self, id: BlockId) -> Option<BlockId> {
        let l1 = self.lw.l1;
        let mut at = id;
        for _ in 0..=JUMPS {
            match &l1.block(at)?.terminator {
                Terminator::Return { .. } | Terminator::Leave { .. } => return Some(at),
                Terminator::Jump(target) => at = target.block,
                Terminator::Branch { .. }
                | Terminator::IndirectJump { .. }
                | Terminator::Trap(_)
                | Terminator::Stop
                | Terminator::Invoke { .. }
                | Terminator::Open => return None,
            }
        }
        None
    }
}
