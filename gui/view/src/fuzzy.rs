//! Fuzzy matching for go-anywhere (names and addresses), the command palette and the
//! sidebars' filterable lists.
//!
//! A [`Query`] matches a candidate when the query's characters occur in order in the
//! candidate. Matching is smart-case: case-insensitive unless the query has an uppercase
//! letter.
//!
//! Scoring (higher is better):
//! - the kind of match ranks first: exact (the whole candidate) > prefix > contiguous
//!   substring starting at a word start > other contiguous substring > scattered
//!   subsequence;
//! - within a kind, each matched char scores, a matched char at a word start (index 0,
//!   after one of `_ . : @ - space /`, a lowercase→uppercase step, or a letter↔digit
//!   step) gets a bonus, consecutive matched chars get a bonus, and gaps between matched
//!   chars cost a penalty (opening a gap costs more than extending it);
//! - each candidate char beyond the query's length costs a small penalty, so shorter
//!   candidates win ties.
//!
//! [`parse_address`] reads an address in C's or the `h`-suffixed hex notation.

use std::cmp::Ordering;
use std::collections::BinaryHeap;

/// Weight of one match kind; larger than any within-kind score.
const TIER: i64 = 1 << 32;
/// Match kind: the query is a scattered subsequence.
const SCATTERED: i64 = 0;
/// Match kind: contiguous substring not starting at a word start.
const SUBSTRING: i64 = 1;
/// Match kind: contiguous substring starting at a word start.
const WORD_SUBSTRING: i64 = 2;
/// Match kind: the candidate starts with the query.
const PREFIX: i64 = 3;
/// Match kind: the candidate is the query.
const EXACT: i64 = 4;
/// Score of each matched char.
const MATCHED: i64 = 16;
/// Bonus of a matched char at a word start.
const WORD_START: i64 = 10;
/// Bonus of a matched char directly after the previous matched char.
const CONSECUTIVE: i64 = 8;
/// Penalty for the first skipped char between two matched chars.
const GAP_OPEN: i64 = 3;
/// Penalty for each further skipped char between two matched chars.
const GAP_EXTEND: i64 = 1;
/// Penalty for each candidate char beyond the query's length.
const EXTRA_CHAR: i64 = 1;
/// Predecessor marker for the first query char.
const NO_PREDECESSOR: usize = usize::MAX;

/// A successful match of a [`Query`] against a candidate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Match {
    /// How well the candidate matches; higher is better.
    pub score: i64,
    /// Byte offsets in the candidate of the matched chars, ascending.
    pub positions: Vec<usize>,
}

/// A parsed fuzzy query, reusable across candidates.
#[derive(Clone, Debug)]
pub struct Query {
    /// The trimmed query's chars, lowercased when matching case-insensitively.
    chars: Vec<char>,
    /// Whether the query has an uppercase letter, so case must match.
    case_sensitive: bool,
}

/// One candidate char prepared for alignment.
#[derive(Clone, Copy, Debug)]
struct Cell {
    /// Byte offset in the candidate.
    offset: usize,
    /// The char, lowercased when matching case-insensitively.
    ch: char,
    /// Whether the char starts a word.
    word_start: bool,
}

impl Query {
    /// Smart case: case-insensitive unless `text` has an uppercase letter. Leading/trailing
    /// whitespace trimmed. Empty query matches everything with score 0 and no positions.
    pub fn new(text: &str) -> Self {
        let text = text.trim();
        let case_sensitive = text.chars().any(char::is_uppercase);
        let chars = text
            .chars()
            .map(|c| if case_sensitive { c } else { fold(c) })
            .collect();
        Self {
            chars,
            case_sensitive,
        }
    }

    /// Whether the query is empty after trimming, so it matches everything.
    pub fn is_empty(&self) -> bool {
        self.chars.is_empty()
    }

    /// The query's chars as a subsequence of `candidate`, best-scoring alignment (see the
    /// module docs for the scoring): a contiguous occurrence is preferred over a scattered
    /// one, and among alignments of the same kind word-start matches win. None if the query
    /// is not a subsequence of `candidate`. Allocates nothing when it returns None.
    pub fn score(&self, candidate: &str) -> Option<Match> {
        if self.chars.is_empty() {
            return Some(Match {
                score: 0,
                positions: Vec::new(),
            });
        }
        if !self.is_subsequence(candidate) {
            return None;
        }
        let cells = self.cells(candidate);
        let (score, positions) = self
            .best_substring(&cells)
            .or_else(|| self.best_scattered(&cells))?;
        let extra = cells.len().saturating_sub(self.chars.len());
        let penalty = i64::try_from(extra)
            .unwrap_or(i64::MAX)
            .saturating_mul(EXTRA_CHAR);
        Some(Match {
            score: score.saturating_sub(penalty),
            positions,
        })
    }

    /// Whether the query's chars occur in order in `candidate`.
    fn is_subsequence(&self, candidate: &str) -> bool {
        let mut rest = self.chars.as_slice();
        for c in candidate.chars() {
            let Some((&wanted, tail)) = rest.split_first() else {
                return true;
            };
            let c = if self.case_sensitive { c } else { fold(c) };
            if c == wanted {
                rest = tail;
            }
        }
        rest.is_empty()
    }

    /// `candidate`'s chars with offsets, folded case and word starts.
    fn cells(&self, candidate: &str) -> Vec<Cell> {
        let mut previous = None;
        candidate
            .char_indices()
            .map(|(offset, raw)| {
                let word_start = is_word_start(previous, raw);
                previous = Some(raw);
                let ch = if self.case_sensitive { raw } else { fold(raw) };
                Cell {
                    offset,
                    ch,
                    word_start,
                }
            })
            .collect()
    }

    /// The best contiguous occurrence of the query in `cells`: its tiered score and
    /// positions. Ties go to the earliest occurrence.
    fn best_substring(&self, cells: &[Cell]) -> Option<(i64, Vec<usize>)> {
        let len = self.chars.len();
        if len == 0 {
            return None;
        }
        let mut best: Option<(i64, usize)> = None;
        for (start, window) in cells.windows(len).enumerate() {
            if !window
                .iter()
                .zip(&self.chars)
                .all(|(cell, &q)| cell.ch == q)
            {
                continue;
            }
            let kind = if start == 0 && window.len() == cells.len() {
                EXACT
            } else if start == 0 {
                PREFIX
            } else if window.first().is_some_and(|cell| cell.word_start) {
                WORD_SUBSTRING
            } else {
                SUBSTRING
            };
            let total = kind * TIER + run_score(window);
            if best.is_none_or(|(score, _)| total > score) {
                best = Some((total, start));
            }
        }
        let (total, start) = best?;
        let positions = cells
            .iter()
            .skip(start)
            .take(len)
            .map(|cell| cell.offset)
            .collect();
        Some((total, positions))
    }

    /// The best scattered alignment of the query over `cells` (dynamic programming over
    /// query chars × candidate chars with affine gap penalties): its score and positions.
    fn best_scattered(&self, cells: &[Cell]) -> Option<(i64, Vec<usize>)> {
        let width = cells.len();
        let mut predecessors = Vec::with_capacity(width.saturating_mul(self.chars.len()));
        let mut row: Vec<Option<i64>> = Vec::with_capacity(width);
        let mut previous_row: Vec<Option<i64>> = Vec::with_capacity(width);
        for (j, &q) in self.chars.iter().enumerate() {
            std::mem::swap(&mut row, &mut previous_row);
            row.clear();
            if j == 0 {
                for cell in cells {
                    row.push((cell.ch == q).then(|| MATCHED + bonus(cell)));
                    predecessors.push(NO_PREDECESSOR);
                }
            } else {
                fill_row(q, cells, &previous_row, &mut row, &mut predecessors);
            }
        }
        let (end, total) = row
            .iter()
            .enumerate()
            .filter_map(|(i, score)| score.map(|score| (i, score)))
            .fold(None, |best: Option<(usize, i64)>, (i, score)| {
                if best.is_none_or(|(_, top)| score > top) {
                    Some((i, score))
                } else {
                    best
                }
            })?;
        let mut positions = Vec::with_capacity(self.chars.len());
        let mut at = end;
        for j in (0..self.chars.len()).rev() {
            positions.push(cells.get(at)?.offset);
            at = *predecessors.get(j * width + at)?;
        }
        positions.reverse();
        Some((SCATTERED * TIER + total, positions))
    }
}

/// Fills one row (query char `q`, not the first) of the alignment table: for each
/// candidate char, the best score with `q` matched there, and where the previous query
/// char was matched.
fn fill_row(
    q: char,
    cells: &[Cell],
    previous_row: &[Option<i64>],
    row: &mut Vec<Option<i64>>,
    predecessors: &mut Vec<usize>,
) {
    // Best score of a previous match at least one char back, net of its gap penalty.
    let mut gap: Option<(i64, usize)> = None;
    for (i, cell) in cells.iter().enumerate() {
        gap = gap.map(|(score, k)| (score - GAP_EXTEND, k));
        if let Some(k) = i.checked_sub(2)
            && let Some(score) = previous_row.get(k).copied().flatten()
        {
            let opened = score - GAP_OPEN;
            if gap.is_none_or(|(best, _)| opened > best) {
                gap = Some((opened, k));
            }
        }
        let consecutive = i.checked_sub(1).and_then(|k| {
            let score = previous_row.get(k).copied().flatten()?;
            Some((score + CONSECUTIVE, k))
        });
        let reach = if cell.ch == q {
            better(consecutive, gap)
        } else {
            None
        };
        if let Some((score, k)) = reach {
            row.push(Some(score + MATCHED + bonus(cell)));
            predecessors.push(k);
        } else {
            row.push(None);
            predecessors.push(NO_PREDECESSOR);
        }
    }
}

/// The higher-scoring of two optional predecessors; `a` on ties.
fn better(a: Option<(i64, usize)>, b: Option<(i64, usize)>) -> Option<(i64, usize)> {
    match (a, b) {
        (Some(x), Some(y)) => Some(if y.0 > x.0 { y } else { x }),
        (Some(x), None) => Some(x),
        (None, y) => y,
    }
}

/// Within-kind score of a contiguous run of matched cells.
fn run_score(run: &[Cell]) -> i64 {
    let chars: i64 = run.iter().map(|cell| MATCHED + bonus(cell)).sum();
    let pairs = i64::try_from(run.len().saturating_sub(1)).unwrap_or(i64::MAX / TIER);
    chars + pairs * CONSECUTIVE
}

/// Word-start bonus of a matched cell.
fn bonus(cell: &Cell) -> i64 {
    if cell.word_start { WORD_START } else { 0 }
}

/// Whether `current` starts a word, given the char before it.
fn is_word_start(previous: Option<char>, current: char) -> bool {
    let Some(previous) = previous else {
        return true;
    };
    if is_separator(current) {
        return false;
    }
    is_separator(previous)
        || (previous.is_lowercase() && current.is_uppercase())
        || (previous.is_alphabetic() && current.is_numeric())
        || (previous.is_numeric() && current.is_alphabetic())
}

/// Whether `c` separates words.
fn is_separator(c: char) -> bool {
    matches!(c, '_' | '.' | ':' | '@' | '-' | ' ' | '/')
}

/// `c` lowercased when that is a single char, else `c` unchanged.
fn fold(c: char) -> char {
    if c.is_ascii() {
        return c.to_ascii_lowercase();
    }
    let mut lower = c.to_lowercase();
    if let (Some(single), None) = (lower.next(), lower.next()) {
        single
    } else {
        c
    }
}

/// A match in the bounded selection; orders worse matches greater, so a max-heap keeps
/// the worst kept match on top.
#[derive(Debug)]
struct Ranked {
    /// The candidate's index in the input.
    index: usize,
    /// The candidate's match.
    matched: Match,
}

impl Ord for Ranked {
    fn cmp(&self, other: &Self) -> Ordering {
        other
            .matched
            .score
            .cmp(&self.matched.score)
            .then(self.index.cmp(&other.index))
    }
}

impl PartialOrd for Ranked {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for Ranked {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for Ranked {}

/// The candidates `query` matches, best first; ties by original index (stable). With an
/// empty query: every index in order, score 0. At most `limit` results, kept in a bounded
/// heap so a small limit never sorts every match.
pub fn filter<'a>(
    query: &Query,
    candidates: impl IntoIterator<Item = &'a str>,
    limit: usize,
) -> Vec<(usize, Match)> {
    if limit == 0 {
        return Vec::new();
    }
    if query.is_empty() {
        return candidates
            .into_iter()
            .take(limit)
            .enumerate()
            .map(|(index, _)| {
                (
                    index,
                    Match {
                        score: 0,
                        positions: Vec::new(),
                    },
                )
            })
            .collect();
    }
    let mut kept: BinaryHeap<Ranked> = BinaryHeap::with_capacity(limit.min(4096));
    for (index, candidate) in candidates.into_iter().enumerate() {
        let Some(matched) = query.score(candidate) else {
            continue;
        };
        let ranked = Ranked { index, matched };
        if kept.len() < limit {
            kept.push(ranked);
        } else if let Some(mut worst) = kept.peek_mut()
            && ranked < *worst
        {
            *worst = ranked;
        }
    }
    kept.into_sorted_vec()
        .into_iter()
        .map(|ranked| (ranked.index, ranked.matched))
        .collect()
}

/// An address typed by hand: hex with an optional `0x` prefix or `h` suffix
/// (not both), surrounding whitespace ignored, underscores and backticks between digits
/// ignored (`0x1_c6c0`, `1C6C0h`, `0x00000001`). None if there are no hex digits, a char
/// is not a hex digit, or the value overflows `u64`.
pub fn parse_address(text: &str) -> Option<u64> {
    let text = text.trim();
    let digits = if let Some(rest) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        rest
    } else if let Some(rest) = text.strip_suffix(['h', 'H']) {
        rest
    } else {
        text
    };
    let mut value: u64 = 0;
    let mut any = false;
    for c in digits.chars() {
        if c == '_' || c == '`' {
            continue;
        }
        let digit = c.to_digit(16)?;
        value = value.checked_mul(16)?.checked_add(u64::from(digit))?;
        any = true;
    }
    any.then_some(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ranked(query: &str, candidates: &[&str]) -> Vec<usize> {
        filter(&Query::new(query), candidates.iter().copied(), usize::MAX)
            .into_iter()
            .map(|(index, _)| index)
            .collect()
    }

    fn positions(query: &str, candidate: &str) -> Vec<usize> {
        Query::new(query).score(candidate).unwrap().positions
    }

    #[test]
    fn ranks_exact_prefix_substring_scattered() {
        // main (exact), main_loop (prefix), xmain and domain_name (in-word substrings,
        // shorter first), m_a_i_n (scattered).
        let candidates = ["domain_name", "main_loop", "main", "m_a_i_n", "xmain"];
        assert_eq!(ranked("main", &candidates), [2, 1, 4, 0, 3]);
    }

    #[test]
    fn word_start_substring_beats_in_word_substring() {
        assert_eq!(ranked("loop", &["xloop", "main_loop"]), [1, 0]);
        assert_eq!(ranked("value", &["xvalue", "getValue"]), [1, 0]);
        // Letter→digit and digit→letter steps start words; digit→digit does not.
        assert_eq!(ranked("64", &["r164", "rx64"]), [1, 0]);
        assert_eq!(ranked("c", &["abxc", "ab1c"]), [1, 0]);
    }

    #[test]
    fn exact_ignores_case_when_query_is_lowercase() {
        assert_eq!(ranked("main", &["main_x", "MAIN"]), [1, 0]);
    }

    #[test]
    fn smart_case() {
        assert!(Query::new("Main").score("main").is_none());
        assert!(Query::new("Main").score("Main").is_some());
        assert!(Query::new("main").score("MAIN").is_some());
        assert!(Query::new("main").score("MaIn").is_some());
    }

    #[test]
    fn non_subsequence_does_not_match() {
        assert!(Query::new("mian").score("main").is_none());
        assert!(Query::new("mainx").score("main").is_none());
    }

    #[test]
    fn empty_and_whitespace_query_match_everything() {
        let empty = Match {
            score: 0,
            positions: Vec::new(),
        };
        assert!(Query::new("   ").is_empty());
        assert_eq!(Query::new("  ").score("anything"), Some(empty.clone()));
        assert_eq!(Query::new("").score(""), Some(empty));
    }

    #[test]
    fn query_is_trimmed() {
        assert_eq!(
            Query::new("  main\t").score("main"),
            Query::new("main").score("main")
        );
    }

    #[test]
    fn positions_prefer_word_starts() {
        assert_eq!(positions("sv", "set_value"), [0, 4]);
        // `g` in `log` is skipped for the word-start `g` of `get`.
        assert_eq!(positions("gv", "log_get_value"), [4, 8]);
        // camelCase steps start words.
        assert_eq!(positions("gv", "logGetValue"), [3, 6]);
    }

    #[test]
    fn positions_prefer_contiguous_then_word_start_occurrence() {
        assert_eq!(positions("abc", "a_b_c_abc"), [6, 7, 8]);
        assert_eq!(positions("val", "interval_value"), [9, 10, 11]);
        assert_eq!(positions("val", "intervalx"), [5, 6, 7]);
    }

    #[test]
    fn positions_are_byte_offsets() {
        // `ï` is two bytes.
        assert_eq!(positions("main", "naïve_main"), [7, 8, 9, 10]);
        // `É` folds to `é`, both two bytes.
        assert_eq!(positions("école", "ÉCOLE_x"), [0, 2, 3, 4, 5]);
        assert_eq!(positions("ïm", "naïve_main"), [2, 7]);
    }

    #[test]
    fn scattered_scores_below_contiguous() {
        let query = Query::new("ab");
        let contiguous = query.score("xxxxxxxxab").unwrap().score;
        let scattered = query.score("a_b").unwrap().score;
        assert!(contiguous > scattered);
    }

    #[test]
    fn gaps_cost() {
        // Same length, so only the gap differs.
        let query = Query::new("ab");
        let near = query.score("axbxxx").unwrap().score;
        let far = query.score("axxxxb").unwrap().score;
        assert!(near > far);
    }

    #[test]
    fn filter_empty_query_keeps_order_and_limit() {
        let got = filter(&Query::new(""), ["c", "a", "b"], 2);
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].0, 0);
        assert_eq!(got[1].0, 1);
        assert!(
            got.iter()
                .all(|(_, m)| m.score == 0 && m.positions.is_empty())
        );
    }

    #[test]
    fn filter_drops_non_matches_and_respects_limit() {
        let candidates = ["foo", "bar", "foo", "foo"];
        assert_eq!(ranked("foo", &candidates), [0, 2, 3]);
        let limited: Vec<usize> = filter(&Query::new("foo"), candidates, 2)
            .into_iter()
            .map(|(index, _)| index)
            .collect();
        assert_eq!(limited, [0, 2]);
        assert_eq!(filter(&Query::new("foo"), candidates, 0), Vec::new());
    }

    #[test]
    fn bounded_selection_matches_full_sort() {
        let owned: Vec<String> = (0..500)
            .map(|i| format!("{}fo{}o_{i}", "x".repeat(i % 5), "y".repeat(i % 3)))
            .collect();
        let query = Query::new("foo");
        let full = filter(&query, owned.iter().map(String::as_str), usize::MAX);
        assert_eq!(full.len(), 500);
        for pair in full.windows(2) {
            let (a, b) = (&pair[0], &pair[1]);
            assert!(a.1.score > b.1.score || (a.1.score == b.1.score && a.0 < b.0));
        }
        for limit in [1, 7, 64] {
            let bounded = filter(&query, owned.iter().map(String::as_str), limit);
            assert_eq!(bounded, full[..limit]);
        }
    }

    #[test]
    fn parse_address_accepts_ida_spellings() {
        assert_eq!(parse_address("0x1_c6c0"), Some(0x1_c6c0));
        assert_eq!(parse_address("0X1C6C0"), Some(0x1_c6c0));
        assert_eq!(parse_address("1C6C0h"), Some(0x1_c6c0));
        assert_eq!(parse_address("1c6c0H"), Some(0x1_c6c0));
        assert_eq!(parse_address("1c6c0"), Some(0x1_c6c0));
        assert_eq!(parse_address("0x00000001"), Some(1));
        assert_eq!(parse_address("0x0000`0001"), Some(0x1));
        assert_eq!(parse_address("  0x10 "), Some(0x10));
        assert_eq!(parse_address("ffffffffffffffff"), Some(u64::MAX));
    }

    #[test]
    fn parse_address_rejects() {
        for text in [
            "",
            "zz",
            "0x",
            "h",
            "0x_",
            "0x10h",
            "-1",
            "+1",
            "1 2",
            "main",
            "10000000000000000",
        ] {
            assert_eq!(parse_address(text), None, "{text:?}");
        }
    }
}
