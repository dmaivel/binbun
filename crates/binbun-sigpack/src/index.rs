//! The candidate index: a query's fingerprint against the packs' entries,
//! at most [`CANDIDATES`] returned, by weighted Jaccard similarity over
//! the features.
//!
//! Entries are found through their rarer tokens (constants, strings,
//! callee names, and the rarer shape tokens: those in fewer than
//! [`RARE`] entries); a query with no rare token is scored against the
//! entries of its shape bucket (arguments read, a loop or not, size
//! class).

use std::collections::{BTreeMap, BTreeSet, HashMap};

use crate::Fingerprint;

/// The most candidates a query returns.
pub const CANDIDATES: usize = 8;

/// A token in fewer entries than this is rare.
pub const RARE: usize = 200;

/// A weighted feature of a fingerprint.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum Token {
    Constant(u64),
    String(String),
    Callee(String),
    Arguments(u32),
    Results(Vec<u16>),
    Blocks(u32),
    Loops(u32),
    Returns(u32),
    Calls(u32),
    SystemCalls(u32),
    Traps(u32),
    Size(u32),
    Op(String),
}

impl Token {
    /// Whether it is distinctive enough to find candidates by.
    const fn distinctive(&self) -> bool {
        matches!(self, Self::Constant(_) | Self::String(_) | Self::Callee(_))
    }
}

/// The size class of `n`: classes of √2.
fn class(n: u32) -> u32 {
    if n == 0 {
        return 0;
    }
    // ⌊2·log₂ n⌋ + 1: the bit length of n², or one less where n² is below
    // the next power of two's half; exact in integers.
    let square = u64::from(n) * u64::from(n);
    64 - square.leading_zeros()
}

/// The weighted tokens of `fingerprint`; callee names only if `callees`.
fn tokens(fingerprint: &Fingerprint, callees: bool) -> BTreeMap<Token, u32> {
    let mut tokens = BTreeMap::new();
    for &constant in &fingerprint.constants {
        tokens.insert(Token::Constant(constant), 3);
    }
    for string in &fingerprint.strings {
        tokens.insert(Token::String(string.clone()), 4);
    }
    if callees {
        for callee in &fingerprint.callees {
            tokens.insert(Token::Callee(callee.clone()), 2);
        }
    }
    tokens.insert(Token::Arguments(fingerprint.arguments), 3);
    tokens.insert(
        Token::Results(fingerprint.results.iter().copied().collect()),
        2,
    );
    tokens.insert(Token::Blocks(class(fingerprint.blocks)), 1);
    tokens.insert(Token::Loops(fingerprint.loops.min(4)), 2);
    tokens.insert(Token::Returns(fingerprint.returns.min(4)), 1);
    tokens.insert(Token::Calls(fingerprint.calls.min(8)), 2);
    tokens.insert(Token::SystemCalls(fingerprint.system_calls.min(4)), 3);
    tokens.insert(Token::Traps(fingerprint.traps.min(4)), 1);
    tokens.insert(Token::Size(class(fingerprint.size)), 2);
    for (op, &count) in &fingerprint.ops {
        tokens.insert(Token::Op(op.clone()), count);
    }
    tokens
}

/// Weighted Jaccard similarity of two token bags.
fn similarity(a: &BTreeMap<Token, u32>, b: &BTreeMap<Token, u32>) -> f64 {
    let mut low = 0u64;
    let mut high = 0u64;
    let keys: BTreeSet<&Token> = a.keys().chain(b.keys()).collect();
    for key in keys {
        let (x, y) = (
            a.get(key).copied().unwrap_or(0),
            b.get(key).copied().unwrap_or(0),
        );
        low += u64::from(x.min(y));
        high += u64::from(x.max(y));
    }
    if high == 0 {
        0.0
    } else {
        #[expect(clippy::cast_precision_loss, reason = "a score: weights are small")]
        let ratio = low as f64 / high as f64;
        ratio
    }
}

/// A shape bucket: arguments read, a loop or not, size class.
type Bucket = (u32, bool, u32);

/// A shape bucket of `fingerprint` ([`Bucket`]).
fn bucket(fingerprint: &Fingerprint) -> (u32, bool, u32) {
    (
        fingerprint.arguments,
        fingerprint.loops != 0,
        class(fingerprint.size),
    )
}

/// An index of fingerprints, each with a value `T` (an entry).
#[derive(Clone, Debug)]
pub struct Index<T> {
    items: Vec<(T, BTreeMap<Token, u32>, Bucket)>,
    by_token: HashMap<Token, Vec<usize>>,
    by_bucket: HashMap<(u32, bool, u32), Vec<usize>>,
}

impl<T: Clone> Index<T> {
    /// The index of `items`.
    pub fn new(items: impl IntoIterator<Item = (T, Fingerprint)>) -> Self {
        let mut index = Self {
            items: Vec::new(),
            by_token: HashMap::new(),
            by_bucket: HashMap::new(),
        };
        for (value, fingerprint) in items {
            let position = index.items.len();
            let tokens = tokens(&fingerprint, true);
            for token in tokens.keys() {
                index
                    .by_token
                    .entry(token.clone())
                    .or_default()
                    .push(position);
            }
            let bucket = bucket(&fingerprint);
            index.by_bucket.entry(bucket).or_default().push(position);
            index.items.push((value, tokens, bucket));
        }
        index
    }

    /// The candidates for `fingerprint`, best first: at most
    /// [`CANDIDATES`], each scoring at least half the best, with their
    /// scores; callee names count only if `callees` (the query knows
    /// them).
    pub fn query(&self, fingerprint: &Fingerprint, callees: bool) -> Vec<(T, f64)> {
        let query = tokens(fingerprint, callees);
        let mut found: BTreeSet<usize> = BTreeSet::new();
        for token in query.keys() {
            let Some(list) = self.by_token.get(token) else {
                continue;
            };
            if list.len() < RARE && (token.distinctive() || list.len() < RARE / 4) {
                found.extend(list.iter().copied());
            }
        }
        if let Some(list) = self.by_bucket.get(&bucket(fingerprint)) {
            found.extend(list.iter().copied());
        }
        let mut scored: Vec<(usize, f64)> = found
            .into_iter()
            .filter_map(|position| {
                let (_, tokens, _) = self.items.get(position)?;
                let tokens = if callees {
                    tokens.clone()
                } else {
                    tokens
                        .iter()
                        .filter(|(t, _)| !matches!(t, Token::Callee(_)))
                        .map(|(t, &w)| (t.clone(), w))
                        .collect()
                };
                Some((position, similarity(&query, &tokens)))
            })
            .collect();
        scored.sort_by(|a, b| b.1.total_cmp(&a.1).then(a.0.cmp(&b.0)));
        let best = scored.first().map_or(0.0, |&(_, score)| score);
        scored
            .into_iter()
            .take_while(|&(_, score)| score >= best / 2.0 && score > 0.0)
            .take(CANDIDATES)
            .filter_map(|(position, score)| Some((self.items.get(position)?.0.clone(), score)))
            .collect()
    }

    /// How many fingerprints it holds.
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Whether it holds none.
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}
