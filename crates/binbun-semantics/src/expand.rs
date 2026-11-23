//! Flag computations ([`Flag`]) written with plain operations: their
//! definition for consumers that do not know them (SMT export, analyses
//! that only understand arithmetic). The interpreter evaluates flags
//! directly; tests check both agree.

use crate::build::Builder;
use crate::ir::{Binary, ExprId, Flag};

/// Builds `op(a, b, c)` from plain operations (no widening, so it works at
/// every width).
pub fn expand(builder: &mut Builder, op: Flag, a: ExprId, b: ExprId, c: ExprId) -> ExprId {
    let width = builder.width(a);
    let top = width.saturating_sub(1);
    match op {
        Flag::AddCarry => {
            // A carry out of either addition: the sum wraps below an addend.
            let partial = builder.binary(Binary::Add, a, b);
            let first = builder.binary(Binary::ULt, partial, a);
            let sum = builder.binary(Binary::Add, partial, c);
            let second = builder.binary(Binary::ULt, sum, partial);
            builder.binary(Binary::Or, first, second)
        }
        Flag::SubBorrow => {
            let first = builder.binary(Binary::ULt, a, b);
            let partial = builder.binary(Binary::Sub, a, b);
            let second = builder.binary(Binary::ULt, partial, c);
            builder.binary(Binary::Or, first, second)
        }
        Flag::AddOverflow => {
            // The result's sign differs from both addends' (equal) signs.
            let sum = builder.binary(Binary::Add, a, b);
            let result = builder.binary(Binary::Add, sum, c);
            let from_a = builder.binary(Binary::Xor, a, result);
            let from_b = builder.binary(Binary::Xor, b, result);
            let both = builder.binary(Binary::And, from_a, from_b);
            builder.extract(both, top, 1)
        }
        Flag::SubOverflow => {
            // The operands' signs differ and the result's differs from a's.
            let difference = builder.binary(Binary::Sub, a, b);
            let result = builder.binary(Binary::Sub, difference, c);
            let operands = builder.binary(Binary::Xor, a, b);
            let from_a = builder.binary(Binary::Xor, a, result);
            let both = builder.binary(Binary::And, operands, from_a);
            builder.extract(both, top, 1)
        }
        Flag::NibbleCarry => {
            if width <= 4 {
                return builder.constant(1, 0);
            }
            let partial = builder.binary(Binary::Xor, a, b);
            let all = builder.binary(Binary::Xor, partial, c);
            builder.extract(all, 4, 1)
        }
    }
}
