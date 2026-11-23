//! Searching what the views show: the session runs the searches
//! ([`binbun_session::search`]: matchers, byte patterns, immediates,
//! streamed searches through the listing, the C and the bytes); a pane
//! keeps its matches as they come ([`Found`]), the current one, and the
//! first after the cursor as soon as no earlier one can still come.

pub use binbun_session::search::{
    Batch, ByteHit, ByteMode, BytePattern, CONTEXT, Hit, Matcher, Plan, Query, Search, Source,
    TextHit, TextRows, immediate, is_immediate, listing_text,
};

/// A pane's matches as they come, in order, and the current one.
#[derive(Clone, Debug)]
pub struct Found {
    plan: Plan,
    hits: Vec<Hit>,
    done: Vec<bool>,
    current: Option<Hit>,
    /// The first match from the origin on is still to be revealed.
    pending: bool,
}

impl Found {
    /// None yet, searched as `plan` says.
    pub fn new(plan: Plan) -> Self {
        Self {
            plan,
            hits: Vec::new(),
            done: vec![false; plan.segments()],
            current: None,
            pending: true,
        }
    }

    /// Takes segment `segment`'s `hits`; the match to reveal, once: the
    /// first from the origin on (wrapping) as soon as every segment that
    /// could hold an earlier one has come.
    pub fn add(&mut self, segment: usize, hits: Vec<Hit>) -> Option<Hit> {
        if let Some(done) = self.done.get_mut(segment) {
            *done = true;
        }
        if !hits.is_empty() {
            self.hits.extend(hits);
            self.hits.sort_unstable();
            self.hits.dedup();
        }
        if !self.pending {
            return None;
        }
        let origin = self.plan.origin();
        let i = self.hits.partition_point(|h| h.line < origin);
        let candidate = self.hits.get(i).or_else(|| self.hits.first())?.clone();
        let needed = self.plan.needed(candidate.line);
        let known = self.done.iter().take(needed.saturating_add(1)).all(|&d| d);
        if !known {
            return None;
        }
        self.pending = false;
        self.current = Some(candidate.clone());
        Some(candidate)
    }

    /// Whether every segment came.
    pub fn is_complete(&self) -> bool {
        self.done.iter().all(|&d| d)
    }

    /// The matches so far, in order.
    pub fn hits(&self) -> &[Hit] {
        &self.hits
    }

    /// How many there are so far.
    pub fn len(&self) -> usize {
        self.hits.len()
    }

    /// Whether there are none so far.
    pub fn is_empty(&self) -> bool {
        self.hits.is_empty()
    }

    /// The current match and its place among them.
    pub fn current(&self) -> Option<(usize, &Hit)> {
        let hit = self.current.as_ref()?;
        let i = self.hits.binary_search(hit).ok()?;
        Some((i, hit))
    }

    /// The matches on `line`.
    pub fn on_line(&self, line: u64) -> &[Hit] {
        let from = self.hits.partition_point(|h| h.line < line);
        let to = self.hits.partition_point(|h| h.line <= line);
        self.hits.get(from..to).unwrap_or(&[])
    }

    /// The match covering position `at` of a hex view (its line the
    /// match's first position, its end its length), if one does.
    pub fn covering(&self, at: u64) -> Option<&Hit> {
        let i = self.hits.partition_point(|h| h.line <= at);
        let hit = self.hits.get(i.checked_sub(1)?)?;
        (at < hit.line + hit.end as u64).then_some(hit)
    }

    /// Makes the match after (`forward`) or before position `at` (a line
    /// and a byte on it) current, wrapping; it, if there is one.
    pub fn step(&mut self, at: (u64, usize), forward: bool) -> Option<Hit> {
        let here = |h: &Hit| (h.line, h.start);
        let next = if forward {
            let i = self.hits.partition_point(|h| here(h) <= at);
            self.hits.get(i).or_else(|| self.hits.first())
        } else {
            let i = self.hits.partition_point(|h| here(h) < at);
            i.checked_sub(1)
                .and_then(|i| self.hits.get(i))
                .or_else(|| self.hits.last())
        }?
        .clone();
        self.pending = false;
        self.current = Some(next.clone());
        Some(next)
    }
}

#[cfg(test)]
mod tests {
    use super::{Found, Hit, Plan};

    fn hit(line: u64) -> Hit {
        Hit {
            line,
            start: 0,
            end: 3,
        }
    }

    #[test]
    fn the_first_match_after_the_cursor_is_revealed_once_nothing_earlier_can_come() {
        // 100 lines in chunks of 10, the cursor on line 45: chunks 4..9,
        // then 0..3.
        let plan = Plan::new(100, 10, 45);
        assert_eq!(plan.segments(), 10);
        assert_eq!(plan.lines_of(0), 40..50);
        assert_eq!(plan.lines_of(6), 0..10);
        let mut found = Found::new(plan);
        // Chunk 6 (segment 2) first: a match, but chunk 5 may hold one.
        assert_eq!(found.add(2, vec![hit(61)]), None);
        // The cursor's chunk: only a match before the cursor.
        assert_eq!(found.add(0, vec![hit(41)]), None);
        assert_eq!(found.add(1, Vec::new()), Some(hit(61)));
        assert_eq!(found.current().map(|(i, h)| (i, h.line)), Some((1, 61)));
        // Once only.
        assert_eq!(found.add(3, vec![hit(55)]), None);
        assert_eq!(found.len(), 3);
        assert_eq!(found.current().map(|(i, _)| i), Some(2));
        assert!(!found.is_complete());
    }

    #[test]
    fn a_match_only_before_the_cursor_waits_for_every_segment() {
        let plan = Plan::new(30, 10, 25);
        let mut found = Found::new(plan);
        // Before the cursor in its own chunk: the last thing searched.
        assert_eq!(found.add(0, vec![hit(21)]), None);
        assert_eq!(found.add(2, vec![hit(15)]), None);
        assert_eq!(found.add(1, Vec::new()), Some(hit(15)));
        assert!(found.is_complete());
    }

    #[test]
    fn steps_wrap_both_ways_from_any_position() {
        let mut found = Found::new(Plan::new(10, 10, 0));
        found.add(
            0,
            vec![
                hit(2),
                Hit {
                    line: 2,
                    start: 7,
                    end: 9,
                },
                hit(8),
            ],
        );
        assert_eq!(
            found.step((2, 0), true).map(|h| (h.line, h.start)),
            Some((2, 7))
        );
        assert_eq!(found.step((2, 7), true).map(|h| h.line), Some(8));
        assert_eq!(found.step((8, 0), true).map(|h| h.line), Some(2));
        assert_eq!(found.step((2, 0), false).map(|h| h.line), Some(8));
        assert_eq!(
            found.step((5, 0), false).map(|h| (h.line, h.start)),
            Some((2, 7))
        );
        assert_eq!(found.on_line(2).len(), 2);
        assert_eq!(found.on_line(3), &[] as &[Hit]);
        assert_eq!(found.covering(9).map(|h| h.line), Some(8));
        assert_eq!(found.covering(11), None);
    }
}
