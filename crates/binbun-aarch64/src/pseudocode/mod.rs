//! Helper functions of Arm's pseudocode that alias conditions and operand
//! values use, in plain Rust, one file per slice of the instruction set.
//! Arguments are field values, least significant bit first, in the
//! pseudocode's order. Names are the pseudocode's in snake case
//! (`MoveWidePreferred` → [`move_wide_preferred`]); the generated code calls
//! them by that name, as `pseudocode::move_wide_preferred`.

mod integer;
mod simd;
mod sve;
mod system;

pub use integer::{bfx_preferred, decode_bit_masks, move_wide_preferred};
pub use simd::{adv_simd_expand_imm, vfp_expand_imm};
pub use sve::sve_move_mask_preferred;
pub use system::{
    SYS_AT, SYS_BRB, SYS_DC, SYS_GIC, SYS_GSB, SYS_IC, SYS_PLBI, SYS_TLBI, SYS_TLBIP, SYSL_GICR,
    SystemOp, svcr_field, sys_l_op, sys_op, sys_op128, sys_register_allowed,
};
