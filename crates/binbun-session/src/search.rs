//! Searching what the front ends show, framework-free: in one listing
//! (Zed's buffer search, `Ctrl+F`), through the whole listing and every
//! function's C (Zed's project search, the GUI's `Alt+T`), for bytes
//! (`Alt+B`) and for immediates (`Alt+I`). The session runs them on
//! threads of their own ([`Session::find_in_listing`],
//! [`Session::search_text`], [`Session::search_immediate`],
//! [`Session::search_bytes`]), the listing as shown (the user's names and
//! comments laid over it) and the C as the session prints it; this
//! module holds what they are made of.
//!
//! - [`Matcher`]: a query as typed or as a regular expression, its case
//!   matched or not.
//! - [`BytePattern`]: hex with wildcard bytes and nibbles (`48 8B ?? 0?`),
//!   or a string as ASCII or UTF-16LE.
//! - [`immediate`]: a value as typed (`-1`, `0FFFFFFFFh`, `0x1000`),
//!   matched across widths as [`same`] matches the listing's numbers and
//!   the C's.
//! - [`Search`]: work cut into segments that threads of their own take in
//!   order, each segment's results sent as it ends; dropping it cancels.
//! - [`Plan`]: a listing's lines cut into chunks, searched from the
//!   cursor's chunk on; [`Hit`]: a match on a line.
//! - [`TextHit`]: a line found by a search through everything;
//!   [`TextRows`]: those found so far, in order, each line of the C's
//!   preamble (a global's `extern` declaration, which every function
//!   using the global prints) once.

use std::collections::HashMap;
use std::fmt;
use std::ops::Range;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, TryRecvError};
use std::thread;
use std::time::Duration;

use binbun::cfg::FunctionId;
use binbun::listing::{LineKind, Rendered, Role};
use binbun_ast::ir::{Node, VarKind};
use regex::{Regex, RegexBuilder};

use crate::listing::Listing;
use crate::number::{parse, same};
use crate::{Document, Session, View, Wake};

/// What a search looks for, as typed.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Query {
    /// The text.
    pub text: String,
    /// Whether case matters.
    pub case: bool,
    /// Whether the text is a regular expression.
    pub regex: bool,
}

/// A query made ready to match.
#[derive(Clone, Debug)]
pub struct Matcher(Regex);

impl Matcher {
    /// `query` ready to match; `None` for an empty one.
    ///
    /// # Errors
    ///
    /// The regular expression does not parse (why).
    pub fn new(query: &Query) -> Result<Option<Self>, String> {
        if query.text.is_empty() {
            return Ok(None);
        }
        let pattern = if query.regex {
            query.text.clone()
        } else {
            regex::escape(&query.text)
        };
        RegexBuilder::new(&pattern)
            .case_insensitive(!query.case)
            .build()
            .map(|regex| Some(Self(regex)))
            .map_err(|error| error.to_string())
    }

    /// Where it matches in `text`: byte ranges, in order, none empty.
    pub fn find(&self, text: &str) -> Vec<Range<usize>> {
        self.0
            .find_iter(text)
            .map(|found| found.range())
            .filter(|range| !range.is_empty())
            .collect()
    }
}

/// How a byte search reads its text.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum ByteMode {
    /// Hexadecimal bytes, `?` for a nibble that may be anything.
    #[default]
    Hex,
    /// A string, its bytes as typed (UTF-8, ASCII for ASCII).
    Text,
    /// A string as UTF-16LE.
    Utf16,
}

/// Bytes to look for: each with a mask of the bits that must match.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BytePattern {
    bytes: Vec<u8>,
    mask: Vec<u8>,
    /// ASCII letters match in either case.
    fold: bool,
}

impl BytePattern {
    /// The pattern `text` writes in `mode`; a string's ASCII letters match
    /// in either case unless `case`.
    ///
    /// # Errors
    ///
    /// It is empty, a hex digit pair is incomplete or not hexadecimal, or
    /// every byte may be anything.
    pub fn parse(text: &str, mode: ByteMode, case: bool) -> Result<Self, String> {
        let pattern = match mode {
            ByteMode::Hex => hex(text)?,
            ByteMode::Text => Self::exact(text.as_bytes().to_vec(), !case),
            ByteMode::Utf16 => Self::exact(
                text.encode_utf16().flat_map(u16::to_le_bytes).collect(),
                !case,
            ),
        };
        if pattern.bytes.is_empty() {
            return Err("nothing to look for".to_owned());
        }
        if pattern.mask.iter().all(|&m| m == 0) {
            return Err("every byte may be anything".to_owned());
        }
        Ok(pattern)
    }

    fn exact(bytes: Vec<u8>, fold: bool) -> Self {
        let mask = vec![0xff; bytes.len()];
        Self { bytes, mask, fold }
    }

    /// How many bytes it spans.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Whether it spans none (never, once parsed).
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Whether it matches `hay` at `at`.
    pub fn matches_at(&self, hay: &[u8], at: usize) -> bool {
        let Some(there) = at.checked_add(self.len()).and_then(|end| hay.get(at..end)) else {
            return false;
        };
        there
            .iter()
            .zip(&self.bytes)
            .zip(&self.mask)
            .all(|((&have, &want), &mask)| {
                if self.fold {
                    have.to_ascii_lowercase() & mask == want.to_ascii_lowercase() & mask
                } else {
                    have & mask == want & mask
                }
            })
    }

    /// Every place it matches in `hay`, overlapping ones too, in order.
    pub fn find_all(&self, hay: &[u8]) -> Vec<usize> {
        let Some(last) = hay.len().checked_sub(self.len()) else {
            return Vec::new();
        };
        (0..=last).filter(|&at| self.matches_at(hay, at)).collect()
    }
}

/// The pattern hexadecimal `text` writes: digit pairs, spaces between
/// bytes optional, `?` for a nibble that may be anything.
fn hex(text: &str) -> Result<BytePattern, String> {
    let mut bytes = Vec::new();
    let mut mask = Vec::new();
    for word in text.split_whitespace() {
        let digits: Vec<char> = word.chars().collect();
        if !digits.len().is_multiple_of(2) {
            return Err(format!("{word:?} is not whole bytes"));
        }
        for pair in digits.chunks(2) {
            let mut byte = 0u8;
            let mut bits = 0u8;
            for &digit in pair {
                byte <<= 4;
                bits <<= 4;
                if digit != '?' {
                    let value = digit
                        .to_digit(16)
                        .and_then(|d| u8::try_from(d).ok())
                        .ok_or_else(|| format!("{digit:?} is not a hex digit"))?;
                    byte |= value;
                    bits |= 0xf;
                }
            }
            bytes.push(byte);
            mask.push(bits);
        }
    }
    Ok(BytePattern {
        bytes,
        mask,
        fold: false,
    })
}

/// The value `text` writes as the GUI's `Alt+I` takes it: decimal, `0x88`,
/// `88h`, a character constant, a minus sign before any (its bits; a
/// width is never needed: [`is_immediate`] matches across widths).
///
/// # Errors
///
/// It is no number.
pub fn immediate(text: &str) -> Result<u64, String> {
    parse(text.trim())
        .map(|written| written.bits)
        .ok_or_else(|| format!("{:?} is not a number", text.trim()))
}

/// Whether a number written with bits `written` is `value`, at its width
/// or another (`0FFFFFFFFh` of a 32-bit operand is `-1`).
pub fn is_immediate(written: u64, value: u64) -> bool {
    same(written, value)
}

/// A listing line as one string, and where it starts after its prefix
/// (`.text:0001C6C0`): a search matches what follows the prefix.
pub fn listing_text(rendered: &Rendered) -> (String, usize) {
    let mut text = String::new();
    let mut start = 0;
    for token in &rendered.tokens {
        text.push_str(&token.text);
        if token.role == Role::Prefix {
            start = text.len();
        }
    }
    (text, start)
}

/// The byte ranges of `text` (a listing line as [`listing_text`] makes
/// it, its prefix ending at `start`) that `matcher` matches.
pub fn find_after(matcher: &Matcher, text: &str, start: usize) -> Vec<Range<usize>> {
    text.get(start..)
        .map(|rest| {
            matcher
                .find(rest)
                .into_iter()
                .map(|r| r.start + start..r.end + start)
                .collect()
        })
        .unwrap_or_default()
}

/// The ranges of `rendered`'s numbers (an instruction's operands) that are
/// `value` ([`is_immediate`]), in [`listing_text`]'s string.
pub fn listing_immediates(rendered: &Rendered, value: u64) -> Vec<Range<usize>> {
    let mut at = 0;
    let mut out = Vec::new();
    for token in &rendered.tokens {
        let end = at + token.text.len();
        if token.role == Role::Number
            && parse(&token.text).is_some_and(|written| is_immediate(written.bits, value))
        {
            out.push(at..end);
        }
        at = end;
    }
    out
}

/// Where a hit of a search through everything was found.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Source {
    /// The listing.
    Listing,
    /// A function's C.
    C,
    /// A line of a function's C before its definition
    /// ([`Document::definition`]): its header, or a struct, global or
    /// callee it uses declared, which every function using it prints
    /// again. Listed once ([`TextRows`]): at the global it declares, else
    /// at the first function printing it.
    Declaration,
}

/// A line found by a search through everything: where it is, and its text
/// with the matches.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TextHit {
    /// Its address (a C line's first instruction, else its function's
    /// entry; a declaration's global).
    pub address: u64,
    /// The entry of the function holding it (none for a declaration,
    /// which is every function's using what it declares).
    pub function: Option<u64>,
    /// The listing, the C, or the C's preamble.
    pub source: Source,
    /// The line, without its indentation (and a listing line without its
    /// prefix).
    pub text: String,
    /// The matches, byte ranges of [`Self::text`].
    pub ranges: Vec<Range<usize>>,
}

impl TextHit {
    /// A hit on `line` at `ranges` (of `line`), shown from byte `from`
    /// with its leading blanks trimmed.
    pub fn new(
        address: u64,
        function: Option<u64>,
        source: Source,
        line: &str,
        from: usize,
        ranges: &[Range<usize>],
    ) -> Self {
        let rest = line.get(from..).unwrap_or("");
        let trimmed = rest.trim_start();
        let skip = from + (rest.len() - trimmed.len());
        Self {
            address,
            function,
            source,
            text: trimmed.to_owned(),
            ranges: ranges
                .iter()
                .filter(|r| r.start >= skip)
                .map(|r| r.start - skip..r.end - skip)
                .collect(),
        }
    }

    /// What orders hits in a list: address, then the listing before the
    /// C, then the text.
    pub fn key(&self) -> (u64, Source, &str) {
        (self.address, self.source, &self.text)
    }
}

/// The lines of `document` that `matcher` matches, as hits.
pub fn c_hits(document: &Document, matcher: &Matcher) -> Vec<TextHit> {
    (0..document.lines().len())
        .filter_map(|n| {
            let text = document.line_text(n);
            let ranges = matcher.find(text);
            (!ranges.is_empty()).then(|| c_hit(document, n, text, &ranges))
        })
        .collect()
}

/// The literals of `document`'s definition that are `value`
/// ([`is_immediate`]; a `-` right before one is its sign), as hits, one
/// per line. Not the preamble's: a search for a value is about code, and
/// an array's length in a declaration is none.
pub fn c_immediates(document: &Document, value: u64) -> Vec<TextHit> {
    let mut out: Vec<TextHit> = Vec::new();
    for (n, line) in document
        .lines()
        .iter()
        .enumerate()
        .skip(document.definition)
    {
        let mut ranges = Vec::new();
        for s in line.spans.clone() {
            let Some((literal, written)) = document.number(s) else {
                continue;
            };
            // Each number once: from its literal, its sign included.
            if literal != s || !is_immediate(written.bits, value) {
                continue;
            }
            let signed = written.negative && s > line.spans.start;
            let first = if signed { s - 1 } else { s };
            let (Some(from), Some(to)) = (document.spans.get(first), document.spans.get(s)) else {
                continue;
            };
            ranges.push(from.range.start - line.range.start..to.range.end - line.range.start);
        }
        if !ranges.is_empty() {
            out.push(c_hit(document, n, document.line_text(n), &ranges));
        }
    }
    out
}

/// Line `n` of `document` (its `text`) as a hit at `ranges`: a line of
/// the preamble as a declaration ([`Source::Declaration`]).
fn c_hit(document: &Document, n: usize, text: &str, ranges: &[Range<usize>]) -> TextHit {
    if n < document.definition {
        let address = declared(document, n).unwrap_or(document.entry);
        return TextHit::new(address, None, Source::Declaration, text, 0, ranges);
    }
    let address = document
        .lines()
        .get(n)
        .and_then(|l| l.addresses.first().copied())
        .unwrap_or(document.entry);
    TextHit::new(address, Some(document.entry), Source::C, text, 0, ranges)
}

/// The address of the global line `n` of `document` declares
/// (`extern int32_t name;`): its first token standing for a global.
fn declared(document: &Document, n: usize) -> Option<u64> {
    let line = document.lines().get(n)?;
    let l2 = &document.decompiled.l2;
    document
        .spans
        .get(line.spans.clone())?
        .iter()
        .find_map(|span| {
            if let Some(Node::Var(var)) = span.node
                && let VarKind::Global(address) = l2.var(var)?.kind
            {
                return Some(address);
            }
            None
        })
}

/// The lines a search through everything found so far, in order
/// ([`TextHit::key`]), as its batches come in any order: a line of the
/// C's preamble ([`Source::Declaration`]) once, whichever functions print
/// it, at the lowest address it comes with (the same in every run).
#[derive(Clone, Debug, Default)]
pub struct TextRows {
    rows: Vec<TextHit>,
    /// The declarations listed, by text, with the address each is listed
    /// at.
    declared: HashMap<String, u64>,
}

impl TextRows {
    /// The lines, in order.
    pub fn rows(&self) -> &[TextHit] {
        &self.rows
    }

    /// Takes `new` lines in: each in its place, a declaration listed
    /// already only moving to a lower address.
    pub fn add(&mut self, mut new: Vec<TextHit>) {
        new.sort_by(|a, b| a.key().cmp(&b.key()));
        // In order, so of one declaration's lines the lowest comes first.
        new.retain(|hit| {
            if hit.source != Source::Declaration {
                return true;
            }
            match self.declared.get(&hit.text) {
                Some(&at) if at <= hit.address => false,
                Some(&at) => {
                    let key = (at, Source::Declaration, hit.text.as_str());
                    if let Ok(old) = self.rows.binary_search_by(|row| row.key().cmp(&key)) {
                        self.rows.remove(old);
                    }
                    self.declared.insert(hit.text.clone(), hit.address);
                    true
                }
                None => {
                    self.declared.insert(hit.text.clone(), hit.address);
                    true
                }
            }
        });
        if new.is_empty() {
            return;
        }
        let old = std::mem::take(&mut self.rows);
        self.rows.reserve(old.len() + new.len());
        let mut old = old.into_iter().peekable();
        let mut new = new.into_iter().peekable();
        loop {
            let next = match (old.peek(), new.peek()) {
                (Some(a), Some(b)) if a.key() <= b.key() => old.next(),
                (Some(_), Some(_)) | (None, _) => new.next(),
                (Some(_), None) => old.next(),
            };
            match next {
                Some(hit) => self.rows.push(hit),
                None => break,
            }
        }
    }
}

/// Bytes found by a byte search: where, and the bytes around them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ByteHit {
    /// Its position: an address, or a file offset when the search was over
    /// the file.
    pub at: u64,
    /// Up to [`CONTEXT`] bytes before it.
    pub before: Vec<u8>,
    /// The bytes matched.
    pub bytes: Vec<u8>,
    /// Up to [`CONTEXT`] bytes after it.
    pub after: Vec<u8>,
}

/// How many bytes a byte hit shows on each side.
pub const CONTEXT: usize = 6;

/// The hits of `pattern` in the region of `hay` starting at position
/// `base`, of those starting in `window` (offsets of `hay`).
pub fn byte_hits(
    pattern: &BytePattern,
    hay: &[u8],
    base: u64,
    window: Range<usize>,
) -> Vec<ByteHit> {
    let end = window.end.saturating_add(pattern.len()).min(hay.len());
    let Some(slice) = hay.get(window.start..end) else {
        return Vec::new();
    };
    pattern
        .find_all(slice)
        .into_iter()
        .map(|found| window.start + found)
        .filter(|&at| at < window.end)
        .map(|at| {
            let past = at + pattern.len();
            let get = |range: Range<usize>| hay.get(range).map(<[u8]>::to_vec).unwrap_or_default();
            ByteHit {
                at: base + at as u64,
                before: get(at.saturating_sub(CONTEXT)..at),
                bytes: get(at..past),
                after: get(past..past.saturating_add(CONTEXT).min(hay.len())),
            }
        })
        .collect()
}

/// One segment's results.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Batch<T> {
    /// The segment.
    pub segment: usize,
    /// What it found.
    pub items: Vec<T>,
}

/// A search running on threads of its own: its segments taken in order
/// (segment 0 first), each one's results sent when it ends. Dropping it
/// cancels it: no thread takes another segment, and one searching stops
/// where the work looks at the flag.
pub struct Search<T> {
    receiver: Receiver<Batch<T>>,
    cancelled: Arc<AtomicBool>,
    segments: usize,
    received: usize,
    stopped: bool,
}

impl<T> fmt::Debug for Search<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Search")
            .field("segments", &self.segments)
            .field("received", &self.received)
            .field("cancelled", &self.cancelled.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

/// How many threads a search takes: half the machine's, at most 8.
pub fn threads() -> usize {
    thread::available_parallelism()
        .map_or(2, |n| n.get() / 2)
        .clamp(1, 8)
}

impl<T: Send + 'static> Search<T> {
    /// Runs `work` on each of `segments` on up to `threads` threads, taking
    /// them in order; `wake` after each segment's results are sent. `work`
    /// gets the segment and the cancellation flag, to stop early (what it
    /// returns then is dropped).
    pub fn spawn(
        segments: usize,
        threads: usize,
        wake: &Wake,
        work: impl Fn(usize, &AtomicBool) -> Vec<T> + Send + Sync + 'static,
    ) -> Self {
        let (sender, receiver) = mpsc::channel();
        let cancelled = Arc::new(AtomicBool::new(false));
        let next = Arc::new(AtomicUsize::new(0));
        let work = Arc::new(work);
        for n in 0..threads.clamp(1, segments.max(1)) {
            let sender = sender.clone();
            let cancelled = Arc::clone(&cancelled);
            let next = Arc::clone(&next);
            let work = Arc::clone(&work);
            let wake = Arc::clone(wake);
            let spawned = thread::Builder::new()
                .name(format!("binbun-search-{n}"))
                .spawn(move || {
                    loop {
                        let segment = next.fetch_add(1, Ordering::Relaxed);
                        if segment >= segments || cancelled.load(Ordering::Relaxed) {
                            break;
                        }
                        let items = work(segment, &cancelled);
                        if cancelled.load(Ordering::Relaxed)
                            || sender.send(Batch { segment, items }).is_err()
                        {
                            break;
                        }
                        wake();
                    }
                });
            // No thread: the segments it would have taken are left to the
            // others (none at all: the search never ends, as cancelled).
            drop(spawned);
        }
        Self {
            receiver,
            cancelled,
            segments,
            received: 0,
            stopped: false,
        }
    }

    /// The batches sent since last asked, without waiting.
    pub fn poll(&mut self) -> Vec<Batch<T>> {
        let mut out = Vec::new();
        loop {
            match self.receiver.try_recv() {
                Ok(batch) => {
                    self.received += 1;
                    out.push(batch);
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    self.stopped = true;
                    break;
                }
            }
        }
        out
    }

    /// The next batch, waiting for it up to `timeout`: `None` once every
    /// segment's results came (or the search stopped), or when none came
    /// in time ([`Self::is_done`] tells which).
    pub fn wait(&mut self, timeout: Duration) -> Option<Batch<T>> {
        if self.is_done() || self.stopped {
            return None;
        }
        match self.receiver.recv_timeout(timeout) {
            Ok(batch) => {
                self.received += 1;
                Some(batch)
            }
            Err(RecvTimeoutError::Timeout) => None,
            Err(RecvTimeoutError::Disconnected) => {
                self.stopped = true;
                None
            }
        }
    }
}

impl<T> Search<T> {
    /// How many segments it has.
    pub fn segments(&self) -> usize {
        self.segments
    }

    /// Whether every segment's results came.
    pub fn is_done(&self) -> bool {
        self.received >= self.segments
    }

    /// Whether it still runs: not done, not cancelled, its threads alive.
    pub fn is_running(&self) -> bool {
        !self.is_done() && !self.stopped && !self.cancelled.load(Ordering::Relaxed)
    }

    /// Cancels it.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Relaxed);
    }
}

impl<T> Drop for Search<T> {
    fn drop(&mut self) {
        self.cancel();
    }
}

/// A match in a pane: its line (a listing line, a C line, a hex view's
/// position) and its bytes there (a hex match: `0..len`).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Hit {
    /// The line (or position).
    pub line: u64,
    /// Its first byte on the line.
    pub start: usize,
    /// Past its last.
    pub end: usize,
}

impl Hit {
    /// Its bytes on its line.
    pub fn range(&self) -> Range<usize> {
        self.start..self.end
    }
}

/// How a pane's lines are cut into chunks and the order they are searched
/// in: from the chunk holding the origin (the cursor's line) to the last,
/// then from the first.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Plan {
    lines: u64,
    chunk: u64,
    origin: u64,
}

impl Plan {
    /// `lines` lines in chunks of `chunk`, searched from `origin`'s.
    pub fn new(lines: u64, chunk: u64, origin: u64) -> Self {
        Self {
            lines,
            chunk: chunk.max(1),
            origin: origin.min(lines.saturating_sub(1)),
        }
    }

    /// How many segments (chunks) there are.
    pub fn segments(&self) -> usize {
        usize::try_from(self.lines.div_ceil(self.chunk)).unwrap_or(usize::MAX)
    }

    /// The origin.
    pub fn origin(&self) -> u64 {
        self.origin
    }

    /// The chunk searched `segment`-th.
    fn chunk_of(&self, segment: usize) -> u64 {
        let n = self.lines.div_ceil(self.chunk).max(1);
        (self.origin / self.chunk + segment as u64) % n
    }

    /// The lines of the segment searched `segment`-th.
    pub fn lines_of(&self, segment: usize) -> Range<u64> {
        let chunk = self.chunk_of(segment);
        let start = chunk * self.chunk;
        start..(start + self.chunk).min(self.lines)
    }

    /// The last segment that must be searched before `line` is known to be
    /// the first match from the origin on (wrapping): its own; the very
    /// last for a line before the origin in the origin's own chunk.
    pub fn needed(&self, line: u64) -> usize {
        let n = self.lines.div_ceil(self.chunk).max(1);
        let first = self.origin / self.chunk;
        let chunk = line / self.chunk;
        if line < self.origin && chunk == first {
            return usize::try_from(n - 1).unwrap_or(usize::MAX);
        }
        usize::try_from((chunk + n - first) % n).unwrap_or(usize::MAX)
    }
}

/// How many listing lines a search takes at a time.
const LISTING_CHUNK: u64 = 4096;

/// How many functions' C a search takes at a time.
const FUNCTION_CHUNK: usize = 4;

/// How many bytes a byte search takes at a time.
const BYTE_WINDOW: usize = 1 << 20;

impl Session {
    /// Finds `matcher` in `listing`'s lines as shown (the user's names and
    /// comments laid over them, the prefix not searched) on threads of
    /// their own, chunk by chunk as `plan` orders them: each chunk's
    /// matches as it is searched, `wake` called after each.
    pub fn find_in_listing(
        self: &Arc<Self>,
        listing: &Arc<Listing>,
        matcher: &Arc<Matcher>,
        plan: Plan,
        wake: &Wake,
    ) -> Search<Hit> {
        let session = Arc::downgrade(self);
        let listing = Arc::clone(listing);
        let matcher = Arc::clone(matcher);
        let overlay = self.overlay();
        Search::spawn(
            plan.segments(),
            threads(),
            wake,
            move |segment, cancelled| {
                let Some(session) = session.upgrade() else {
                    return Vec::new();
                };
                let Some(db) = session.database() else {
                    return Vec::new();
                };
                let mut hits = Vec::new();
                for line in plan.lines_of(segment) {
                    if cancelled.load(Ordering::Relaxed) {
                        break;
                    }
                    let (text, start) = listing_text(&listing.render(db, line, &overlay));
                    hits.extend(find_after(&matcher, &text, start).into_iter().map(|r| Hit {
                        line,
                        start: r.start,
                        end: r.end,
                    }));
                }
                hits
            },
        )
    }

    /// Searches the whole `listing` (if given) and every function's C in
    /// `view` (if given) for `matcher` on threads of their own (the GUI's
    /// `Alt+T`, Zed's project search): the listing first, then the
    /// functions, each decompiled as it is reached if it is not yet;
    /// `wake` called after each chunk.
    pub fn search_text(
        self: &Arc<Self>,
        listing: Option<&Arc<Listing>>,
        view: Option<View>,
        matcher: &Arc<Matcher>,
        wake: &Wake,
    ) -> Search<TextHit> {
        let in_line = Arc::clone(matcher);
        let in_c = Arc::clone(matcher);
        self.everywhere(
            listing,
            view,
            wake,
            move |rendered| {
                let (text, start) = listing_text(rendered);
                let ranges = find_after(&in_line, &text, start);
                (text, start, ranges)
            },
            move |document| c_hits(document, &in_c),
        )
    }

    /// Searches the listing's instructions (if given) for an operand that
    /// is `value` and every function's C in `view` (if given) for a
    /// literal that is (across widths: [`is_immediate`]; the GUI's `Alt+I`),
    /// as [`Self::search_text`] searches.
    pub fn search_immediate(
        self: &Arc<Self>,
        listing: Option<&Arc<Listing>>,
        view: Option<View>,
        value: u64,
        wake: &Wake,
    ) -> Search<TextHit> {
        self.everywhere(
            listing,
            view,
            wake,
            move |rendered| {
                let (text, start) = listing_text(rendered);
                (text, start, listing_immediates(rendered, value))
            },
            move |document| c_immediates(document, value),
        )
    }

    /// The listing's lines (instructions and data; `line` gives a line's
    /// text, where it starts after the prefix, and its matches) and every
    /// function's C in `view` (`c` gives a document's hits), searched on
    /// threads of their own.
    fn everywhere(
        self: &Arc<Self>,
        listing: Option<&Arc<Listing>>,
        view: Option<View>,
        wake: &Wake,
        line: impl Fn(&Rendered) -> (String, usize, Vec<Range<usize>>) + Send + Sync + 'static,
        c: impl Fn(&Document) -> Vec<TextHit> + Send + Sync + 'static,
    ) -> Search<TextHit> {
        let session = Arc::downgrade(self);
        let listing = listing.cloned();
        let lines = listing.as_ref().map_or(0, |l| l.len());
        let plan = Plan::new(lines, LISTING_CHUNK, 0);
        let listed = if lines == 0 { 0 } else { plan.segments() };
        let mut functions: Vec<FunctionId> = self
            .database()
            .filter(|_| view.is_some())
            .map(|db| db.functions().map(|(id, _)| id).collect())
            .unwrap_or_default();
        functions.sort_unstable();
        let functions = Arc::new(functions);
        let decompiled = functions.len().div_ceil(FUNCTION_CHUNK);
        let overlay = self.overlay();
        Search::spawn(
            listed + decompiled,
            threads(),
            wake,
            move |segment, cancelled: &AtomicBool| {
                let Some(session) = session.upgrade() else {
                    return Vec::new();
                };
                let Some(db) = session.database() else {
                    return Vec::new();
                };
                let mut hits = Vec::new();
                if let Some(listing) = listing.as_ref().filter(|_| segment < listed) {
                    for n in plan.lines_of(segment) {
                        if cancelled.load(Ordering::Relaxed) {
                            break;
                        }
                        let Some(at) = listing.line(n) else {
                            continue;
                        };
                        if !matches!(at.kind, LineKind::Instruction | LineKind::Data) {
                            continue;
                        }
                        let rendered = listing.render(db, n, &overlay);
                        let (text, start, ranges) = line(&rendered);
                        if !ranges.is_empty() {
                            let function = listing.function_of(at.address).map(|(_, e)| e);
                            // The line's own address, as its prefix shows
                            // it (a further line of a data item has its
                            // own), else its item's.
                            let address = rendered
                                .tokens
                                .first()
                                .filter(|t| t.role == Role::Prefix)
                                .and_then(|t| t.target)
                                .unwrap_or(at.address);
                            hits.push(TextHit::new(
                                address,
                                function,
                                Source::Listing,
                                &text,
                                start,
                                &ranges,
                            ));
                        }
                    }
                    return hits;
                }
                let first = (segment - listed) * FUNCTION_CHUNK;
                let Some(view) = view else {
                    return hits;
                };
                for &function in functions.iter().skip(first).take(FUNCTION_CHUNK) {
                    if cancelled.load(Ordering::Relaxed) {
                        break;
                    }
                    if let Ok(document) = session.document_here(function, view) {
                        hits.extend(c(&document));
                    }
                }
                hits
            },
        )
    }

    /// Searches the image's segments (or, `file`, the whole file) for
    /// `pattern` on threads of their own (the GUI's `Alt+B`): each hit at its
    /// address (or file offset), with the bytes around it; `wake` called
    /// after each window. `None` before the image is parsed.
    pub fn search_bytes(
        self: &Arc<Self>,
        pattern: &Arc<BytePattern>,
        file: bool,
        wake: &Wake,
    ) -> Option<Search<ByteHit>> {
        let (bytes, image) = (self.bytes()?, self.image()?);
        // Each region (`None`: the file; else a segment, by its index) with
        // its first position and length, cut into windows.
        let regions: Vec<(Option<usize>, u64, usize)> = if file {
            vec![(None, 0, bytes.len())]
        } else {
            image
                .segments
                .iter()
                .enumerate()
                .map(|(i, s)| (Some(i), s.start, s.bytes.len()))
                .collect()
        };
        let windows: Vec<(Option<usize>, u64, Range<usize>)> = regions
            .into_iter()
            .flat_map(|(region, base, len)| {
                (0..len)
                    .step_by(BYTE_WINDOW)
                    .map(move |at| (region, base, at..(at + BYTE_WINDOW).min(len)))
            })
            .collect();
        let session = Arc::downgrade(self);
        let pattern = Arc::clone(pattern);
        Some(Search::spawn(
            windows.len(),
            threads(),
            wake,
            move |segment, _| {
                let (Some(session), Some((region, base, window))) =
                    (session.upgrade(), windows.get(segment))
                else {
                    return Vec::new();
                };
                let hay = match region {
                    None => session.bytes(),
                    Some(i) => session
                        .image()
                        .and_then(|image| image.segments.get(*i))
                        .map(|s| s.bytes),
                };
                let Some(hay) = hay else {
                    return Vec::new();
                };
                byte_hits(&pattern, hay, *base, window.clone())
            },
        ))
    }
}

#[cfg(test)]
mod tests {
    use std::ops::Range;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::time::{Duration, Instant};

    use super::{ByteMode, BytePattern, Matcher, Query, Search, byte_hits};
    use super::{immediate, is_immediate};
    use crate::Wake;

    fn query(text: &str, case: bool, regex: bool) -> Matcher {
        Matcher::new(&Query {
            text: text.to_owned(),
            case,
            regex,
        })
        .unwrap()
        .unwrap()
    }

    #[test]
    fn a_query_matches_as_typed_or_as_a_regex_its_case_as_asked() {
        let line = "call    Sub_1C6C0 ; sub_1c6c0(x+1)";
        // As typed: `+` and `(` are themselves.
        assert_eq!(query("(x+1)", true, false).find(line), vec![29..34]);
        // Case blind by default, every occurrence.
        assert_eq!(
            query("sub_1c6c0", false, false).find(line),
            vec![8..17, 20..29]
        );
        assert_eq!(query("sub_1c6c0", true, false).find(line), vec![20..29]);
        // A regex; empty matches are no matches.
        assert_eq!(query(r"[0-9a-f]{5}", true, true).find(line), vec![24..29]);
        assert_eq!(
            query("z*", true, true).find(line),
            Vec::<Range<usize>>::new()
        );
        assert!(Matcher::new(&Query::default()).unwrap().is_none());
        let bad = Query {
            text: "(".to_owned(),
            case: false,
            regex: true,
        };
        assert!(Matcher::new(&bad).is_err());
    }

    #[test]
    fn hex_patterns_take_wildcard_bytes_and_nibbles() {
        let hay = [0x48, 0x8b, 0x05, 0x10, 0x48, 0x8b, 0x0d, 0x10, 0x48, 0x89];
        let p = BytePattern::parse("48 8B ?? 10", ByteMode::Hex, false).unwrap();
        assert_eq!(p.len(), 4);
        assert_eq!(p.find_all(&hay), vec![0, 4]);
        // A nibble: `0?` is 00..0F.
        let p = BytePattern::parse("8b0?", ByteMode::Hex, false).unwrap();
        assert_eq!(p.find_all(&hay), vec![1, 5]);
        let p = BytePattern::parse("?9", ByteMode::Hex, false).unwrap();
        assert_eq!(p.find_all(&hay), vec![9]);
        // Past the end: no match.
        let p = BytePattern::parse("89 00", ByteMode::Hex, false).unwrap();
        assert_eq!(p.find_all(&hay), Vec::<usize>::new());
        assert!(BytePattern::parse("4", ByteMode::Hex, false).is_err());
        assert!(BytePattern::parse("4g", ByteMode::Hex, false).is_err());
        assert!(BytePattern::parse("?? ??", ByteMode::Hex, false).is_err());
        assert!(BytePattern::parse("  ", ByteMode::Hex, false).is_err());
    }

    #[test]
    fn strings_match_as_ascii_or_utf16_their_case_as_asked() {
        let hay = b"xUsage\0U\0s\0A\0g\0e\0";
        let ascii = BytePattern::parse("usage", ByteMode::Text, false).unwrap();
        assert_eq!(ascii.find_all(hay), vec![1]);
        let exact = BytePattern::parse("usage", ByteMode::Text, true).unwrap();
        assert_eq!(exact.find_all(hay), Vec::<usize>::new());
        let wide = BytePattern::parse("Usage", ByteMode::Utf16, false).unwrap();
        assert_eq!(wide.len(), 10);
        assert_eq!(wide.find_all(hay), vec![7]);
        let wide_exact = BytePattern::parse("Usage", ByteMode::Utf16, true).unwrap();
        assert_eq!(wide_exact.find_all(hay), Vec::<usize>::new());
    }

    #[test]
    fn byte_hits_split_into_windows_find_each_match_once_with_context() {
        let mut hay = vec![0u8; 40];
        hay[9] = 0xaa;
        hay[10] = 0xbb;
        hay[30] = 0xaa;
        hay[31] = 0xbb;
        let p = BytePattern::parse("aa bb", ByteMode::Hex, false).unwrap();
        // The first window ends inside the first match: it is that
        // window's, found once.
        let first = byte_hits(&p, &hay, 0x1000, 0..10);
        let second = byte_hits(&p, &hay, 0x1000, 10..40);
        let at: Vec<u64> = first.iter().chain(&second).map(|h| h.at).collect();
        assert_eq!(at, vec![0x1009, 0x101e]);
        let hit = &first[0];
        assert_eq!(hit.before, vec![0; 6]);
        assert_eq!(hit.bytes, vec![0xaa, 0xbb]);
        assert_eq!(hit.after, vec![0; 6]);
        // At the end, as many bytes after as there are.
        assert_eq!(second[0].after, vec![0; 6]);
        let end = byte_hits(&p, &hay[..32], 0, 20..32);
        assert_eq!(end[0].after, Vec::<u8>::new());
    }

    #[test]
    fn immediates_match_across_widths_signed_or_not() {
        let minus_one = immediate("-1").unwrap();
        // The listing's 32-bit operand, the C's -1, a 64-bit operand.
        assert!(is_immediate(0xffff_ffff, minus_one));
        assert!(is_immediate(u64::MAX, minus_one));
        assert!(is_immediate(0xff, minus_one));
        let typed = immediate("0FFFFFFFFh").unwrap();
        assert!(is_immediate(u64::MAX, typed));
        assert!(!is_immediate(0xffff, typed));
        assert_eq!(immediate(" 0x1000 ").unwrap(), 4096);
        assert!(is_immediate(4096, immediate("1000h").unwrap()));
        assert!(!is_immediate(4097, immediate("4096").unwrap()));
        assert!(immediate("rax").is_err());
    }

    #[test]
    fn a_search_streams_every_segment_once_and_stops_when_cancelled() {
        let wakes = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&wakes);
        let mut search = Search::spawn(
            50,
            4,
            &(Arc::new(move || {
                counted.fetch_add(1, Ordering::Relaxed);
            }) as Wake),
            |segment, _: &AtomicBool| vec![segment * 2],
        );
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut seen = Vec::new();
        while !search.is_done() && Instant::now() < deadline {
            seen.extend(search.poll().into_iter().flat_map(|b| b.items));
            std::thread::sleep(Duration::from_millis(1));
        }
        seen.sort_unstable();
        assert_eq!(seen, (0..50).map(|s| s * 2).collect::<Vec<_>>());
        assert_eq!(wakes.load(Ordering::Relaxed), 50);
        assert!(!search.is_running());

        // Slow segments, cancelled after the first: the rest never come.
        let ran = Arc::new(AtomicUsize::new(0));
        let slow_ran = Arc::clone(&ran);
        let quiet: Wake = Arc::new(|| {});
        let mut slow = Search::spawn(1000, 2, &quiet, move |_, cancelled| {
            slow_ran.fetch_add(1, Ordering::Relaxed);
            for _ in 0..20 {
                if cancelled.load(Ordering::Relaxed) {
                    break;
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            vec![()]
        });
        while slow.poll().is_empty() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(slow.is_running());
        // Dropped, it is cancelled: each of the two threads may still begin
        // the segment it had taken, and takes none after, however late it
        // gets to run.
        drop(slow);
        let before = ran.load(Ordering::Relaxed);
        std::thread::sleep(Duration::from_millis(200));
        let after = ran.load(Ordering::Relaxed);
        assert!(after <= before + 2, "{before} segments ran, then {after}");
    }
}
