//! Back/forward trails: one the linked panes share (a jump in any of them
//! pushes where they were), one for each pane on its own ([`Trails`]); Esc
//! goes back, Ctrl+Enter forward, in the focused pane's trail.

use std::collections::HashMap;

use binbun_ast::ir::Node;

use crate::layout::PaneId;

/// A place to come back to: the address, and in a C view the node under
/// the cursor (by identity, so it survives a re-print).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Location {
    /// The cursor's address.
    pub address: u64,
    /// The node under a C view's cursor, if the jump was made there.
    pub node: Option<Node>,
}

impl Location {
    /// The location of `address`, no node.
    pub fn at(address: u64) -> Self {
        Self {
            address,
            node: None,
        }
    }
}

/// Back and forward stacks around the current location.
#[derive(Clone, Debug, Default)]
pub struct History {
    back: Vec<Location>,
    forward: Vec<Location>,
}

/// The most locations kept each way.
const DEPTH: usize = 512;

impl History {
    /// A jump from `from`: it goes on the back stack (unless it is the top
    /// already), forward is cleared.
    pub fn push(&mut self, from: Location) {
        if self.back.last() != Some(&from) {
            self.back.push(from);
            if self.back.len() > DEPTH {
                self.back.remove(0);
            }
        }
        self.forward.clear();
    }

    /// Back from `current`, if there is anywhere to go.
    pub fn back(&mut self, current: Location) -> Option<Location> {
        let to = self.back.pop()?;
        self.forward.push(current);
        Some(to)
    }

    /// Forward from `current`, if a back was taken.
    pub fn forward(&mut self, current: Location) -> Option<Location> {
        let to = self.forward.pop()?;
        self.back.push(current);
        Some(to)
    }

    /// Whether back goes anywhere.
    pub fn can_back(&self) -> bool {
        !self.back.is_empty()
    }

    /// Whether forward goes anywhere.
    pub fn can_forward(&self) -> bool {
        !self.forward.is_empty()
    }
}

/// The trail the linked panes share, and each pane on its own's.
#[derive(Clone, Debug, Default)]
pub struct Trails {
    linked: History,
    own: HashMap<PaneId, History>,
}

impl Trails {
    /// Pane `pane`'s trail: the linked panes' if it is `linked`, else its
    /// own (empty at first: a pane opened on its own starts its trail
    /// there).
    pub fn of(&mut self, pane: PaneId, linked: bool) -> &mut History {
        if linked {
            &mut self.linked
        } else {
            self.own.entry(pane).or_default()
        }
    }

    /// Pane `pane`'s trail, to read: `None` for a pane on its own that has
    /// none yet.
    pub fn get(&self, pane: PaneId, linked: bool) -> Option<&History> {
        if linked {
            Some(&self.linked)
        } else {
            self.own.get(&pane)
        }
    }

    /// Forgets the trails of the panes `live` says are gone, and of those
    /// linked again (linked, a pane follows the linked panes' trail; on its
    /// own again, it starts anew).
    pub fn retain(&mut self, own: impl Fn(PaneId) -> bool) {
        self.own.retain(|&pane, _| own(pane));
    }
}

#[cfg(test)]
mod tests {
    use super::{DEPTH, History, Location, PaneId, Trails};

    #[test]
    fn linked_panes_share_a_trail_and_a_pane_on_its_own_keeps_one() {
        let at = Location::at;
        let (left, right, reference) = (PaneId(0), PaneId(1), PaneId(2));
        let mut trails = Trails::default();
        // A double click in the right (linked) pane: back in the left one
        // returns both to where they were.
        trails.of(right, true).push(at(0x11d0));
        assert_eq!(trails.of(left, true).back(at(0x2d80)), Some(at(0x11d0)));
        // The reference's own moves are on its own trail only.
        trails.of(reference, false).push(at(0x2b50));
        assert!(!trails.of(left, true).can_back());
        assert_eq!(
            trails.of(reference, false).back(at(0x2c00)),
            Some(at(0x2b50))
        );
        assert!(trails.get(right, false).is_none());
        // Closed (or linked again), its trail is forgotten.
        trails.of(reference, false).push(at(0x3000));
        trails.retain(|pane| pane != reference);
        assert!(trails.get(reference, false).is_none());
        assert!(trails.of(left, true).can_forward());
    }

    #[test]
    fn back_forward_and_a_new_jump_drops_forward() {
        let at = Location::at;
        let mut h = History::default();
        h.push(at(1));
        h.push(at(2));
        assert_eq!(h.back(at(3)), Some(at(2)));
        assert_eq!(h.back(at(2)), Some(at(1)));
        assert_eq!(h.back(at(1)), None);
        assert_eq!(h.forward(at(1)), Some(at(2)));
        h.push(at(2));
        assert!(!h.can_forward());
        assert_eq!(h.forward(at(9)), None);
        // The same place twice in a row is kept once.
        h.push(at(2));
        assert_eq!(h.back(at(5)), Some(at(2)));
        assert_eq!(h.back(at(2)), Some(at(1)));
    }

    #[test]
    fn depth_is_bounded_dropping_the_oldest() {
        let mut h = History::default();
        for a in 0..(DEPTH as u64 + 10) {
            h.push(Location::at(a));
        }
        let mut last = None;
        while let Some(to) = h.back(Location::at(0)) {
            last = Some(to);
        }
        assert_eq!(last, Some(Location::at(10)));
    }
}
