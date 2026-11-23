//! Pointer families: values related by pointer arithmetic, kept beside the
//! constraint system rather than in it (`q = p + 8` as a subtyping edge
//! would mix `p`'s fields with `q`'s, and `p = p + 8` around a loop would
//! make an unbounded chain).
//!
//! A family is a set of pointer-wide values that are addresses into one
//! object, each at an offset in bytes from the family's root: `q = p ± k`
//! puts `q` at `p`'s offset `± k`; `q = p + i·s` (an index scaled by a
//! constant, `s` times what the index is known a multiple of: `p + (n·8 −
//! 8)·1` steps by 8) puts `q` at `p`'s offset modulo `s` (`q`'s
//! [modulus](Families::of): the index scales between it and the root,
//! their greatest common divisor; 0: exact); a block parameter and its
//! arguments (but one proved null where it arrives: no object), and a
//! select and its arms, are at one offset; so are the value stored to a
//! pointer-wide frame slot no address reaches, stored once before every
//! load of it, and those loads (`-O0` code's local, loaded at each use); a
//! canonical-form check of an address (`sext(extract(x, 0, 48))`, low bits
//! wider than 32: narrower ones are an integer's sign extension) is the
//! address. A block parameter that is a scalar evolution
//! (`super::evolution`: `p = phi(p0, p + s)`) is related to its start
//! only, and its step is a period of the family: its offsets are known
//! modulo the step. Where two other relations give a value two offsets (a
//! cycle no evolution explains: back edges stepping differently, a step
//! by an index), offsets are known modulo their difference. The family's
//! [`stride`](Family::stride) is the greatest common divisor of the
//! steps, of such differences and of the indices' scales on such cycles
//! (0: every offset is exact up to its member's modulus). Constants are never
//! members (zero is every type, and one constant value may be used
//! anywhere), nor are integer computations (a
//! product, a quotient, a shift, an extension other than a canonical-form
//! check, a comparison, a unary operation, an extraction, a difference of
//! two values, and sums and selects of integer computations): a block
//! parameter or select joining one with an address does not make it part
//! of the address's object.
//!
//! Each family also keeps the accesses through its members, with offsets
//! from the root: with the members' offsets and the stride, this is the
//! object's layout as far as the function's own code shows it (where
//! struct and array recovery start). Rounding treats a family as
//! one object (see `round`). An access through a member with a modulus
//! says where in the object it is only where the modulus is a multiple of
//! its width ([`counts`]: an array walk, `p + i·8` read 8 bytes at a
//! time); `p + i` read 16 bytes at a time is at no known element.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use binbun_ssa::ir::InstId;
use binbun_typeinfer::Var;

/// An access through a member of a family.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Access {
    /// The load or store.
    pub(crate) inst: InstId,
    /// The member it is through.
    pub(crate) through: Var,
    /// Its offset in bytes from the family's root (modulo the stride, and
    /// modulo the index's scale where indexed).
    pub(crate) offset: i64,
    /// Its width in bits.
    pub(crate) bits: u16,
    /// The variable of the value loaded or stored.
    pub(crate) value: Option<Var>,
    /// Whether an index is added (`p[i]`).
    pub(crate) indexed: bool,
    /// The scale of the index added, where one is (the greatest common
    /// divisor of several, 1 where unknown): its offset is known modulo
    /// it.
    pub(crate) scale: u64,
    /// The modulus of the member it is through (see [`Families::of`]).
    pub(crate) modulus: u64,
}

/// Values that are addresses into one object.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Family {
    /// Its members' variables, each with its offset in bytes from the
    /// root and its modulus (see [`Families::of`]).
    pub(crate) members: Vec<(Var, i64, u64)>,
    /// Offsets are known modulo this (0: exactly, up to each member's
    /// modulus).
    pub(crate) stride: u64,
    /// The accesses through its members.
    pub(crate) accesses: Vec<Access>,
}

/// One function's pointer families.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Families {
    /// The families (one per member value's root; most have one member).
    pub(crate) families: Vec<Family>,
    /// Each member's family, offset and modulus.
    member: BTreeMap<Var, (usize, i64, u64)>,
}

impl Families {
    /// The family of `var` (its index), `var`'s offset in it and its
    /// modulus: the offset is known modulo the greatest common divisor of
    /// the index scales between `var` and the root (0: none, exactly).
    pub(crate) fn of(&self, var: Var) -> Option<(usize, i64, u64)> {
        self.member.get(&var).copied()
    }

    /// Family `index`.
    pub(crate) fn get(&self, index: usize) -> Option<&Family> {
        self.families.get(index)
    }

    /// Records the access `inst` through `base` at `offset` bytes from it,
    /// an index scaled by `scale` added (0: none).
    pub(crate) fn access(
        &mut self,
        inst: InstId,
        base: Var,
        offset: i64,
        bits: u16,
        value: Option<Var>,
        scale: u64,
    ) {
        let Some((index, at, modulus)) = self.of(base) else {
            return;
        };
        if let Some(family) = self.families.get_mut(index) {
            family.accesses.push(Access {
                inst,
                through: base,
                offset: at.wrapping_add(offset),
                bits,
                value,
                indexed: scale != 0,
                scale,
                modulus,
            });
        }
    }
}

/// Whether an access of `bits` bits through a member of modulus `modulus`
/// says where in its object it is: exactly, or by an index scaled by a
/// multiple of its width (an array walk).
pub(crate) const fn counts(modulus: u64, bits: u16) -> bool {
    let bytes = bits / 8;
    modulus == 0 || (bits.is_multiple_of(8) && bytes > 0 && modulus.is_multiple_of(bytes as u64))
}

/// What says where in its object access `access` of `family` is: its
/// offset is known modulo this (0: exactly), the greatest common divisor
/// of its index's scale, its member's modulus and the family's stride.
pub(crate) const fn period(family: &Family, access: &Access) -> u64 {
    gcd(gcd(access.scale, access.modulus), family.stride)
}

/// Union-find over values with offsets relative to their parents.
#[derive(Clone, Debug, Default)]
pub(crate) struct Builder {
    /// Per value: its parent, its offset from it and the index scales
    /// between them (their greatest common divisor; 0: none).
    links: Vec<(u32, i64, u64)>,
    /// Per root: its family's stride.
    strides: Vec<u64>,
}

impl Builder {
    /// `count` values, each its own family.
    pub(crate) fn new(count: usize) -> Self {
        let links = (0..count)
            .map(|index| (u32::try_from(index).unwrap_or(u32::MAX), 0, 0))
            .collect();
        Self {
            links,
            strides: alloc::vec![0; count],
        }
    }

    /// `v`'s root, its offset from it and its modulus.
    fn find(&mut self, v: u32) -> (u32, i64, u64) {
        let mut path = Vec::new();
        let mut at = v;
        while let Some(&(parent, _, _)) = self.links.get(at as usize) {
            if parent == at {
                break;
            }
            path.push(at);
            at = parent;
        }
        let root = at;
        let mut offset = 0i64;
        let mut modulus = 0u64;
        for &node in path.iter().rev() {
            if let Some(link) = self.links.get_mut(node as usize) {
                offset = offset.wrapping_add(link.1);
                modulus = gcd(modulus, link.2);
                *link = (root, offset, modulus);
            }
        }
        let own = if v == root {
            (0, 0)
        } else {
            self.links
                .get(v as usize)
                .map_or((0, 0), |&(_, offset, modulus)| (offset, modulus))
        };
        (root, own.0, own.1)
    }

    /// One more value, its own family; its index.
    pub(crate) fn add(&mut self) -> u32 {
        let index = u32::try_from(self.links.len()).unwrap_or(u32::MAX);
        self.links.push((index, 0, 0));
        self.strides.push(0);
        index
    }

    /// `b` is `a + delta` plus a multiple of `scale` (0: exactly). Joining
    /// two families, `b`'s goes under `a`'s root with the modulus of the
    /// scales between them; within one family (a cycle), its offsets
    /// repeat by the cycle's shift, known modulo those scales.
    pub(crate) fn relate(&mut self, a: u32, b: u32, delta: i64, scale: u64) {
        let (ra, oa, ma) = self.find(a);
        let (rb, ob, mb) = self.find(b);
        let rb_stride = self.stride(rb);
        let shift = oa.wrapping_add(delta).wrapping_sub(ob);
        let modulus = gcd(gcd(ma, mb), scale);
        let stride = if ra == rb {
            gcd(gcd(self.stride(ra), shift.unsigned_abs()), modulus)
        } else {
            if let Some(link) = self.links.get_mut(rb as usize) {
                *link = (ra, shift, modulus);
            }
            gcd(self.stride(ra), rb_stride)
        };
        if let Some(slot) = self.strides.get_mut(ra as usize) {
            *slot = stride;
        }
    }

    /// Root `root`'s stride.
    fn stride(&self, root: u32) -> u64 {
        self.strides.get(root as usize).copied().unwrap_or(0)
    }

    /// `v` steps by `step` per iteration of a loop (a scalar evolution's
    /// step, `super::evolution`): its family's offsets repeat by it, known
    /// modulo `v`'s modulus too (what closing the loop's cycle by
    /// [`Self::relate`] would give).
    pub(crate) fn period(&mut self, v: u32, step: u64) {
        let (root, _, modulus) = self.find(v);
        let stride = gcd(gcd(self.stride(root), step), modulus);
        if let Some(slot) = self.strides.get_mut(root as usize) {
            *slot = stride;
        }
    }

    /// The families of the values `vars` gives a variable (by value
    /// index; `None`: not a member).
    pub(crate) fn finish(mut self, vars: &[Option<Var>]) -> Families {
        let mut by_root: BTreeMap<u32, Vec<(Var, i64, u64)>> = BTreeMap::new();
        for (index, var) in vars.iter().enumerate() {
            let (Some(var), Ok(index)) = (var, u32::try_from(index)) else {
                continue;
            };
            let (root, offset, modulus) = self.find(index);
            by_root
                .entry(root)
                .or_default()
                .push((*var, offset, modulus));
        }
        let mut families = Families::default();
        for (root, members) in by_root {
            let index = families.families.len();
            for &(var, offset, modulus) in &members {
                families.member.insert(var, (index, offset, modulus));
            }
            families.families.push(Family {
                members,
                stride: self.stride(root),
                accesses: Vec::new(),
            });
        }
        families
    }
}

/// The greatest common divisor (`gcd(0, x)` is `x`).
pub(crate) const fn gcd(mut a: u64, mut b: u64) -> u64 {
    while b != 0 {
        let r = a % b;
        a = b;
        b = r;
    }
    a
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vars(count: u32) -> Vec<Option<Var>> {
        let mut system = binbun_typeinfer::System::default();
        (0..count).map(|_| Some(system.var())).collect()
    }

    #[test]
    fn a_loop_pointer_is_one_family_with_its_step_as_stride() {
        // v0 = phi(v3, v1); v1 = v0 + 8; v2 = v1 + 4; v3 is the entry.
        let mut builder = Builder::new(4);
        builder.relate(0, 1, 8, 0);
        builder.relate(1, 2, 4, 0);
        builder.relate(3, 0, 0, 0);
        builder.relate(1, 0, 0, 0);
        let vars = vars(4);
        let families = builder.finish(&vars);
        let found: Vec<(usize, i64, u64)> = vars
            .iter()
            .map(|var| families.of(var.unwrap()).unwrap())
            .collect();
        let family = families.get(found[0].0).unwrap();
        assert_eq!(family.members.len(), 4);
        assert_eq!(family.stride, 8);
        assert!(found.iter().all(|&(index, _, _)| index == found[0].0));
        assert!(found.iter().all(|&(_, _, modulus)| modulus == 0));
        let relative: Vec<i64> = found.iter().map(|&(_, o, _)| o - found[0].1).collect();
        assert_eq!(relative, [0, 8, 12, 0]);
    }

    #[test]
    fn an_index_makes_its_sums_offsets_modular_and_unrelated_values_stay_apart() {
        // v1 = v0 + i * 4 - 2; v3 = v1 + 6; v2 is unrelated.
        let mut builder = Builder::new(4);
        builder.relate(0, 1, -2, 4);
        builder.relate(1, 3, 6, 0);
        let vars = vars(4);
        let families = builder.finish(&vars);
        let of = |index: usize| families.of(vars[index].unwrap()).unwrap();
        assert_eq!(of(0).0, of(1).0);
        assert_eq!(of(1).1 - of(0).1, -2);
        assert_ne!(of(0).0, of(2).0);
        // The root's offset stays exact; the sum's (and what is related to
        // it) are known modulo the scale; no cycle, so no stride.
        assert_eq!(of(3).0, of(0).0);
        assert_eq!(of(3).1 - of(0).1, 4);
        assert_eq!((of(0).2, of(1).2, of(3).2), (0, 4, 4));
        assert_eq!(families.get(of(0).0).unwrap().stride, 0);
    }

    #[test]
    fn an_evolutions_step_is_the_period_its_closed_cycle_gives() {
        // v0 = phi(v3, v1); v1 = v0 + 24; v2 = v1 + 8; v3 is the entry.
        // Closing the back edge and taking the evolution's step agree,
        // and a later join keeps the period.
        let closed = |close: bool| {
            let mut builder = Builder::new(5);
            builder.relate(3, 0, 0, 0);
            builder.relate(0, 1, 24, 0);
            builder.relate(1, 2, 8, 0);
            if close {
                builder.relate(1, 0, 0, 0);
            } else {
                builder.period(0, 24);
            }
            builder.relate(4, 3, 0, 0);
            let vars = vars(5);
            let families = builder.finish(&vars);
            let (index, _, _) = families.of(vars[2].unwrap()).unwrap();
            families.get(index).unwrap().stride
        };
        assert_eq!(closed(true), 24);
        assert_eq!(closed(false), 24);
    }

    #[test]
    fn a_cycle_through_an_index_makes_the_family_periodic() {
        // v0 = phi(v2, v1); v1 = v0 + i * 8; v2 is the entry.
        let mut builder = Builder::new(3);
        builder.relate(2, 0, 0, 0);
        builder.relate(0, 1, 0, 8);
        builder.relate(1, 0, 0, 0);
        let vars = vars(3);
        let families = builder.finish(&vars);
        let (index, _, _) = families.of(vars[0].unwrap()).unwrap();
        assert_eq!(families.get(index).unwrap().stride, 8);
    }

    #[test]
    fn an_access_counts_where_its_index_walks_whole_elements() {
        assert!(counts(0, 128));
        assert!(counts(16, 128));
        assert!(!counts(4, 64));
        assert!(!counts(8, 4));
    }
}
