//! The instructions an expression built for a value stands for: the
//! value's own, and those folded into it at lowering that no other node
//! stands for (a copy seen through, a constant's, the flag computations
//! a comparison is read back from).

use alloc::vec::Vec;

use binbun_ast::ir::{ExprId, Origin};
use binbun_ssa::ir::{Definition, Value};

use super::Emit;
use crate::lower::facts::Kind;
use crate::lower::needed::Role;

/// How deep [`Emit::copies`] follows what a value is made of.
const DEPTH: u8 = 4;

impl Emit<'_, '_, '_> {
    /// Notes that value `v` is used where its expression is built: the
    /// instructions it came through that no node stands for
    /// ([`Self::copies`]), for the next statement ([`Emit::seen`]).
    pub(super) fn see(&mut self, v: Value) {
        let mut out = Vec::new();
        self.copies(v, &mut out);
        self.seen.append(&mut out);
    }

    /// The instructions value `u`, read where the node of its canonical
    /// value is used, came through that no node stands for, into `out`:
    /// a constant's and the constants it is computed from (its expression
    /// is shared by its uses: `xor ebx, ebx` then `mov eax, ebx`; `adrp`
    /// then `add`; not values it does not depend on: `xor eax, eax` after
    /// a call), and a copy's seen
    /// through, with the values it is made of that nothing
    /// else needs (`mov eax, r12d` then `sub eax, edx`: the low half of
    /// the copy's register, the copy and its extension); or `u` itself
    /// and what it is made of, where nothing else needs it (the flags a
    /// comparison is read back from, and the subtraction they are of).
    fn copies(&self, u: Value, out: &mut Vec<u64>) {
        let lw = self.lw;
        let mut work = Vec::from([(u, 0u8)]);
        while let Some((w, depth)) = work.pop() {
            // Memory is no value an expression reads.
            if lw.width(w) == 0 {
                continue;
            }
            let root = lw.canonical(w);
            if w == root && matches!(lw.kind(root), Kind::Const(_)) {
                out.extend(self.defined_at(w));
                if depth < DEPTH
                    && let Some((_, op)) = lw.defining(w)
                {
                    work.extend(
                        op.operands()
                            .into_iter()
                            .filter(|&o| matches!(lw.kind(o), Kind::Const(_)))
                            .map(|o| (o, depth + 1)),
                    );
                }
                continue;
            }
            let unbuilt = root != w || lw.role(root) == Role::None;
            if !unbuilt || depth >= DEPTH {
                continue;
            }
            out.extend(self.defined_at(w));
            if let Some((_, op)) = lw.defining(w) {
                work.extend(op.operands().into_iter().map(|o| (o, depth + 1)));
            }
        }
    }

    /// The address of the instruction defining `v`, if one does.
    fn defined_at(&self, v: Value) -> Option<u64> {
        let l1 = self.lw.l1;
        match l1.value(v)?.definition {
            Definition::Result { inst, .. } => l1.inst(inst).map(|i| i.address),
            Definition::Parameter { .. } => None,
        }
    }

    /// Gives `e`, built for value `x`, the instructions it stands for:
    /// `x`'s and those folded into it ([`Self::folded`]); nothing if `e`
    /// is an expression built before (`e` below `fresh`: another value's,
    /// which `x` turned out to be).
    pub(super) fn tag(&mut self, x: Value, e: ExprId, fresh: usize) {
        if (e.0 as usize) < fresh {
            return;
        }
        let mut addresses: Vec<u64> = self.defined_at(x).into_iter().collect();
        self.folded(x, &mut addresses);
        addresses.sort_unstable();
        addresses.dedup();
        let origins: Vec<Origin> = addresses.into_iter().map(Origin::Instruction).collect();
        if !origins.is_empty() {
            self.ast.provenance.set_expr(e, &origins);
        }
    }

    /// The instructions folded into the expression of value `x` (as its
    /// definition reads its operands) that no other node stands for, into
    /// `out`: those its operands came through ([`Self::copies`]).
    fn folded(&self, x: Value, out: &mut Vec<u64>) {
        let Some((_, op)) = self.lw.defining(x) else {
            return;
        };
        for u in op.operands() {
            self.copies(u, out);
        }
    }
}
