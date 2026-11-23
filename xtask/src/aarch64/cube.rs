//! Sets of instruction words as unions of cubes (`word & mask == value`).

/// The words `w` with `w & mask == value`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Cube {
    pub mask: u32,
    pub value: u32,
}

/// Largest number of free bits a predicate may be enumerated over.
const MAX_ENUMERATED_BITS: u32 = 24;

impl Cube {
    pub const fn new(mask: u32, value: u32) -> Self {
        Self {
            mask,
            value: value & mask,
        }
    }

    pub const fn contains(self, word: u32) -> bool {
        word & self.mask == self.value
    }

    pub const fn intersects(self, other: Self) -> bool {
        (self.value ^ other.value) & self.mask & other.mask == 0
    }

    pub const fn intersection(self, other: Self) -> Self {
        Self::new(self.mask | other.mask, self.value | other.value)
    }

    /// Whether every word of `self` is in `other`.
    pub const fn within(self, other: Self) -> bool {
        other.mask & !self.mask == 0 && (self.value ^ other.value) & other.mask == 0
    }

    /// Whether some word of `self` is in none of `holes`.
    pub fn exceeds(self, holes: &[Self]) -> bool {
        let Some((first, rest)) = holes.split_first() else {
            return true;
        };
        if !self.intersects(*first) {
            return self.exceeds(rest);
        }
        if self.within(*first) {
            return false;
        }
        // Split on a bit `first` fixes and `self` does not: the half that
        // disagrees with `first` escapes it.
        let bit = 1 << (first.mask & !self.mask).trailing_zeros();
        let escaping = Self::new(self.mask | bit, self.value | (!first.value & bit));
        let inside = Self::new(self.mask | bit, self.value | (first.value & bit));
        escaping.exceeds(rest) || inside.exceeds(holes)
    }
}

/// The words in `space` for which `member` holds, as disjoint cubes.
///
/// `member` is evaluated on every assignment of the bits in `bits` that
/// `space` leaves free (other free bits zero), so it must depend only on
/// those bits. The cubes fix only `bits` (the bits `space` fixes are left
/// out), and cubes that differ in one bit are merged.
pub fn cubes(space: Cube, bits: u32, member: impl Fn(u32) -> bool) -> Result<Vec<Cube>, String> {
    let free = bits & !space.mask;
    let count = free.count_ones();
    if count > MAX_ENUMERATED_BITS {
        return Err(format!("{count} bits are too many to enumerate"));
    }
    // positions[i] is the bit that index bit `count - 1 - i` stands for, so
    // a prefix of positions is a contiguous range of indices.
    let positions: Vec<u32> = (0..32).rev().filter(|bit| free & (1 << bit) != 0).collect();
    let scatter = |index: u32| {
        positions
            .iter()
            .enumerate()
            .filter(|&(i, _)| index & (1 << (count as usize - 1 - i)) != 0)
            .fold(space.value, |word, (_, bit)| word | (1 << bit))
    };
    let size = 1usize << count;
    // prefix[i] = members among indices below i.
    let mut prefix = Vec::with_capacity(size + 1);
    prefix.push(0usize);
    for index in 0..1u32 << count {
        let member = member(scatter(index));
        prefix.push(prefix[index as usize] + usize::from(member));
    }
    let mut out = Vec::new();
    split(&prefix, &positions, 0, 0, 0, &mut out);
    Ok(merge(out))
}

/// Disjoint `cubes` with pairs that differ in exactly one fixed bit merged
/// into one cube, repeatedly; the result is disjoint too.
fn merge(mut cubes: Vec<Cube>) -> Vec<Cube> {
    loop {
        cubes.sort_unstable();
        let mut merged = Vec::with_capacity(cubes.len());
        let mut used = vec![false; cubes.len()];
        for i in 0..cubes.len() {
            if used[i] {
                continue;
            }
            let cube = cubes[i];
            let partner = (i + 1..cubes.len()).find(|&j| {
                let other = cubes[j];
                !used[j] && other.mask == cube.mask && (other.value ^ cube.value).is_power_of_two()
            });
            match partner {
                Some(j) => {
                    used[j] = true;
                    let bit = cube.value ^ cubes[j].value;
                    merged.push(Cube::new(cube.mask & !bit, cube.value));
                }
                None => merged.push(cube),
            }
        }
        if merged.len() == cubes.len() {
            return merged;
        }
        cubes = merged;
    }
}

/// Emits the cubes covering the members among the indices whose top `depth`
/// bits are `base`'s, fixing `mask`/`value` so far.
fn split(
    prefix: &[usize],
    positions: &[u32],
    depth: usize,
    base: usize,
    fixed: u32,
    out: &mut Vec<Cube>,
) {
    let width = positions.len() - depth;
    let start = base << width;
    let end = start + (1 << width);
    let members = prefix[end] - prefix[start];
    if members == 0 {
        return;
    }
    let mask = positions[..depth]
        .iter()
        .fold(0, |mask, bit| mask | (1 << bit));
    if members == end - start {
        out.push(Cube::new(mask, fixed));
        return;
    }
    let bit = 1 << positions[depth];
    split(prefix, positions, depth + 1, base << 1, fixed, out);
    split(
        prefix,
        positions,
        depth + 1,
        (base << 1) | 1,
        fixed | bit,
        out,
    );
}

#[cfg(test)]
mod tests {
    use super::{Cube, cubes};

    #[test]
    fn enumerates_members_as_disjoint_cubes() {
        // Bits 4:0 equal to 11111, within a space fixing bit 31.
        let space = Cube::new(1 << 31, 1 << 31);
        let all_ones = cubes(space, 0x1f, |word| word & 0x1f == 0x1f).unwrap();
        assert_eq!(all_ones, [Cube::new(0x1f, 0x1f)]);
        // The complement takes one cube per leading bit.
        let not_all_ones = cubes(space, 0x1f, |word| word & 0x1f != 0x1f).unwrap();
        assert_eq!(not_all_ones.len(), 5);
        assert!((0..32).all(|w| not_all_ones.iter().any(|c| c.contains(w)) == (w != 0x1f)));
        // An odd register number is one cube, not sixteen.
        assert_eq!(
            cubes(space, 0x1f, |word| word & 1 == 1).unwrap(),
            [Cube::new(1, 1)]
        );
        // Bits the space fixes are not enumerated.
        let fixed = cubes(Cube::new(1, 1), 0b11, |word| word & 0b11 == 0b11).unwrap();
        assert_eq!(fixed, [Cube::new(0b10, 0b10)]);
    }

    #[test]
    fn finds_words_outside_holes() {
        let space = Cube::new(0xf0, 0x10);
        assert!(!space.exceeds(&[Cube::new(0x30, 0x10)]));
        let halves = [Cube::new(0x01, 0x00), Cube::new(0x01, 0x01)];
        assert!(!space.exceeds(&halves));
        assert!(space.exceeds(&halves[..1]));
        assert!(space.exceeds(&[Cube::new(0xf0, 0x20)]));
    }
}
