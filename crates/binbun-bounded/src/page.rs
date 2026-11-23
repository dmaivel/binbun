//! Replies that can grow, filled by encoded size.

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::{Bounded, Bounds, size, varint_len};

/// A page of a reply that can grow: at most `N` items, in the order of
/// their keys, and whether more come after them. The asker states where
/// the next page starts (the key of the last item it was given); the
/// responder keeps nothing between pages.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Page<T, const N: usize> {
    /// The items.
    pub items: Bounded<T, N>,
    /// Whether items past these were left out.
    pub more: bool,
}

impl<T, const N: usize> Default for Page<T, N> {
    fn default() -> Self {
        Self {
            items: Bounded::new(),
            more: false,
        }
    }
}

impl<T: DeserializeOwned, const N: usize> Bounds for Page<T, N> {}

/// Fills a [`Page`] while its encoding, the list's length and `more`
/// included, stays within the room given.
#[derive(Debug)]
pub struct PageBuilder<T, const N: usize> {
    /// The items taken.
    items: Vec<T>,
    /// The most bytes the page's encoding may take.
    room: usize,
    /// The bytes it takes now.
    used: usize,
    /// Whether an item was left out.
    more: bool,
}

impl<T: Serialize, const N: usize> PageBuilder<T, N> {
    /// A page whose encoding takes at most `room` bytes: what is left of
    /// a frame's limit once the rest of the message around the page is
    /// counted. An empty page takes 2.
    pub fn new(room: usize) -> Self {
        Self {
            items: Vec::new(),
            room,
            used: 2,
            more: false,
        }
    }

    /// Adds `item` if it fits, by count and by bytes; else the page is
    /// full, says more come, and gives `item` back (as it does every one
    /// after).
    ///
    /// # Errors
    ///
    /// It does not fit, or one before it did not.
    pub fn push(&mut self, item: T) -> Result<(), T> {
        if self.more || self.items.len() >= N {
            self.more = true;
            return Err(item);
        }
        let length = self.items.len();
        let grows = varint_len(length + 1) - varint_len(length);
        let left = self.room.saturating_sub(self.used.saturating_add(grows));
        if let Ok(bytes) = size(&item, left) {
            self.used += grows + bytes;
            self.items.push(item);
            Ok(())
        } else {
            self.more = true;
            Err(item)
        }
    }

    /// Whether an item was left out: nothing more is taken.
    pub fn is_full(&self) -> bool {
        self.more
    }

    /// The bytes the page's encoding takes now.
    pub fn used(&self) -> usize {
        self.used
    }

    /// The page.
    pub fn finish(self) -> Page<T, N> {
        Page {
            items: Bounded::truncated(self.items),
            more: self.more,
        }
    }
}
