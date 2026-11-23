//! The continuous listing as every front end shows it
//! ([`crate::Session::listing`]): `binbun::listing`'s lines of the whole
//! image in the usual disassembler layout, with the user's edits laid over
//! them when a line is drawn ([`Overlay`]): a name the user gave replaces
//! the listing's wherever a token names that address, a number an
//! instruction uses is written in the form the user chose (the GUI's `H`,
//! `R`), and a comment goes at the end of its address's first content
//! line, each further line of it on a line of its own
//! below, at the same column ([`Listing::set_comments`]). A stack
//! variable (`var_54`) takes the name the user gave its frame slot, or the
//! C variable that is that slot.

use std::collections::BTreeMap;

use binbun::Database;
use binbun::cfg::FunctionId;
pub use binbun::listing::{Arrow, Item, Line, LineKind, Numbers, Options, Rendered, Role, Token};
use binbun_ast::types::Enumeration;

use crate::edits::{Edit, Edits, NumberForm};
use crate::number::{Radix, Written, by_name, canonical, parse};

/// The listing of one image under one set of [`Options`].
#[derive(Clone, Debug)]
pub struct Listing {
    lines: binbun::listing::Listing,
}

/// The user's names, comments, bookmarks and numbers' forms, by address.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Overlay {
    /// Names of functions and globals.
    pub names: BTreeMap<u64, String>,
    /// Comments.
    pub comments: BTreeMap<u64, String>,
    /// Bookmarks' names (a mark in the gutters, not the text).
    pub bookmarks: BTreeMap<u64, String>,
    /// Numbers' forms, by instruction and value.
    pub numbers: BTreeMap<(u64, u64), NumberForm>,
    /// The enumerations numbers' forms name ([`NumberForm::Enum`]), by that
    /// name: those the image's types or the user's define.
    pub enums: BTreeMap<String, Enumeration>,
    /// Frame slots' names, by function entry and offset from the stack
    /// pointer on entry.
    pub slots: BTreeMap<(u64, i64), String>,
}

/// Where a comment starts on its line (the usual comment column, 40).
const COMMENT_COLUMN: usize = 40;

/// The column a comment starts at on a line `width` characters wide: the
/// comment column, or one space after the text.
fn comment_column(width: usize) -> usize {
    width + COMMENT_COLUMN.saturating_sub(width).max(1)
}

impl Overlay {
    /// The user's names, comments, bookmarks and numbers' forms in
    /// `edits`, and the names of frame slots: a variable's that is one
    /// slot (the first of the same origins before a later one, whom the C
    /// may print instead), else the slot's.
    pub fn of(edits: &Edits) -> Self {
        let mut overlay = Self::default();
        // Each slot's name with its rank: a variable's by its ordinal, the
        // slot's own last.
        let mut slots: BTreeMap<(u64, i64), (usize, String)> = BTreeMap::new();
        let mut name_slot = |key, rank, name| match slots.get(&key) {
            Some(&(held, _)) if held <= rank => {}
            Some(_) | None => {
                slots.insert(key, (rank, name));
            }
        };
        for edit in edits.all() {
            match edit {
                Edit::Function { entry, name } => {
                    overlay.names.insert(entry, name);
                }
                Edit::Global { address, name } => {
                    overlay.names.insert(address, name);
                }
                Edit::Comment { address, text } => {
                    overlay.comments.insert(address, text);
                }
                Edit::Bookmark { address, name } => {
                    overlay.bookmarks.insert(address, name);
                }
                Edit::Variable { variable, name } => {
                    if let Some(slot) = variable.slot() {
                        name_slot((variable.function, slot), variable.ordinal, name);
                    }
                }
                Edit::Slot {
                    function,
                    offset,
                    name,
                } => {
                    name_slot((function, offset), usize::MAX, name);
                }
                Edit::Number {
                    address,
                    value,
                    form,
                } => {
                    overlay.numbers.insert((address, value), form);
                }
                Edit::Type { .. }
                | Edit::Definition { .. }
                | Edit::Item { .. }
                | Edit::Bounds { .. } => {}
            }
        }
        overlay.slots = slots
            .into_iter()
            .map(|(key, (_, name))| (key, name))
            .collect();
        overlay
    }

    /// The form the user chose for the number `value` the instruction at
    /// `address` uses, at its width or another (one [`canonical`] number).
    pub fn number(&self, address: u64, value: u64) -> Option<NumberForm> {
        let canon = canonical(value);
        self.numbers
            .range((address, 0)..=(address, u64::MAX))
            .find(|((_, stated), _)| canonical(*stated) == canon)
            .map(|(_, form)| form.clone())
    }

    /// `written` in `form` ([`NumberForm::spell`]), an enumeration's by its
    /// constants ([`by_name`]; none where it is not defined).
    pub fn spell(&self, form: &NumberForm, written: Written, radix: Radix) -> Option<String> {
        match form {
            NumberForm::Enum(name) => by_name(self.enums.get(name)?, written, radix),
            NumberForm::Hex | NumberForm::Decimal | NumberForm::Char => form.spell(written, radix),
        }
    }
}

impl Listing {
    /// The listing of `db`'s image (its cross-references built if they are
    /// not yet).
    pub fn build(db: &Database<'_>, options: &Options) -> Self {
        Self {
            lines: binbun::listing::Listing::build(db, options),
        }
    }

    /// Its settings.
    pub fn options(&self) -> &Options {
        self.lines.options()
    }

    /// The listing without the user's edits.
    pub fn lines(&self) -> &binbun::listing::Listing {
        &self.lines
    }

    /// How many lines there are.
    pub fn len(&self) -> u64 {
        self.lines.len()
    }

    /// Whether there are none.
    pub fn is_empty(&self) -> bool {
        self.lines.is_empty()
    }

    /// Line `n`: its item's address and kind.
    pub fn line(&self, n: u64) -> Option<Line> {
        self.lines.line(n)
    }

    /// Lays a line under each comment of `comments` for each of its lines
    /// after the first, at its address's first content line (the lines
    /// below are numbered anew); whether any line changed.
    pub fn set_comments(&mut self, comments: &BTreeMap<u64, String>) -> bool {
        let counts: BTreeMap<u64, usize> = comments
            .iter()
            .map(|(&address, text)| (address, text.split('\n').count()))
            .collect();
        self.lines.set_comments(&counts)
    }

    /// Where line `n`'s comment is: the address of its item and the line
    /// its comment starts on (its item's first content line), with the
    /// column the comment starts at there (after the line's text, at the
    /// comment column at the least), whether there is one yet or not.
    /// `None` on a line of no item with content (a section's banner).
    pub fn comment_place(
        &self,
        db: &Database<'_>,
        n: u64,
        overlay: &Overlay,
    ) -> Option<(u64, u64, usize)> {
        let address = self.lines.line(n)?.address;
        let first = self.first_content_line(address)?;
        let width: usize = self
            .render_bare(db, first, overlay)
            .tokens
            .iter()
            .map(|t| t.text.chars().count())
            .sum();
        Some((address, first, comment_column(width)))
    }

    /// Line `n` as tokens, with `overlay` laid over it.
    pub fn render(&self, db: &Database<'_>, n: u64, overlay: &Overlay) -> Rendered {
        let mut rendered = self.render_bare(db, n, overlay);
        if let Some(line) = self.lines.line(n)
            && let Some(comment) = overlay.comments.get(&line.address)
        {
            // The first line after the item's first content line, each
            // further one on a comment line of its own, under it.
            let first = self.first_content_line(line.address);
            let further = line.kind == LineKind::Comment;
            let piece = if further {
                first
                    .and_then(|first| usize::try_from(n.checked_sub(first)?).ok())
                    .and_then(|k| comment.split('\n').nth(k))
            } else if first == Some(n) {
                comment.split('\n').next()
            } else {
                None
            };
            if let Some(piece) = piece {
                let width: usize = rendered.tokens.iter().map(|t| t.text.chars().count()).sum();
                let column = if further {
                    self.comment_place(db, n, overlay)
                        .map_or(COMMENT_COLUMN, |(_, _, column)| column)
                } else {
                    comment_column(width)
                };
                rendered.tokens.push(Token {
                    text: " ".repeat(column.saturating_sub(width).max(1)),
                    role: Role::Space,
                    target: None,
                    automatic: false,
                });
                rendered.tokens.push(Token {
                    text: format!("; {piece}"),
                    role: Role::Comment,
                    target: None,
                    automatic: false,
                });
            }
        }
        rendered
    }

    /// Line `n` as tokens, with `overlay`'s names and numbers' forms laid
    /// over it (not its comments); a name the user gives is not
    /// [`Token::automatic`].
    fn render_bare(&self, db: &Database<'_>, n: u64, overlay: &Overlay) -> Rendered {
        let mut rendered = self.lines.render(db, n);
        if overlay.names.is_empty() && overlay.numbers.is_empty() && overlay.slots.is_empty() {
            return rendered;
        }
        let address = self.lines.line(n).map(|l| l.address);
        let radix = match self.options().numbers {
            Numbers::Masm => Radix::Masm,
            Numbers::C => Radix::C,
        };
        let mut pad: Option<isize> = None;
        for token in &mut rendered.tokens {
            // A frame line's `=` keeps its column under a longer or
            // shorter name.
            if let Some(by) = pad.take()
                && token.role == Role::Space
            {
                let len = token.text.len().cast_signed().saturating_sub(by).max(1);
                token.text = " ".repeat(len.cast_unsigned());
                continue;
            }
            if token.role == Role::LocalName
                && let Some(at) = address
                && let Some(slot) = self.lines.local(at, &token.text)
                && let Some(name) = overlay.slots.get(&slot)
            {
                let by = name.len().cast_signed() - token.text.len().cast_signed();
                pad = self
                    .lines
                    .line(n)
                    .filter(|line| line.kind == LineKind::Frame)
                    .map(|_| by);
                token.text.clone_from(name);
                token.automatic = false;
                continue;
            }
            if token.role == Role::Number
                && let Some(at) = address
                && let Some(written) = parse(&token.text)
                && let Some(form) = overlay.number(at, written.bits)
                && let Some(text) = overlay.spell(&form, written, radix)
            {
                token.text = text;
                continue;
            }
            if token.role == Role::Prefix {
                continue;
            }
            let Some(target) = token.target else {
                continue;
            };
            // The target's own name, else (`main+58`) its function's, else
            // (`record+4`) its data item's.
            let named = std::iter::once(target)
                .chain(self.lines.function_of(target).map(|(_, entry)| entry))
                .chain(self.lines.data_of(target))
                .find_map(|at| {
                    let user = overlay.names.get(&at)?;
                    let own = self.lines.name(at)?;
                    let rest = token.text.strip_prefix(own)?;
                    let whole =
                        at == target || rest.starts_with(['+', '-', ':']) || rest.is_empty();
                    whole.then(|| format!("{user}{rest}"))
                });
            if let Some(text) = named {
                token.text = text;
                token.automatic = false;
            }
        }
        rendered
    }

    /// The first instruction or data line of the item at `address`.
    fn first_content_line(&self, address: u64) -> Option<u64> {
        let n = self.lines.line_of(address);
        let line = self.lines.line(n)?;
        (line.address == address && matches!(line.kind, LineKind::Instruction | LineKind::Data))
            .then_some(n)
    }

    /// The comment lines of the item whose comment starts on line `first`
    /// (its first content line): it and the [`LineKind::Comment`] lines
    /// under it.
    pub fn comment_lines(&self, first: u64) -> std::ops::Range<u64> {
        let mut end = first + 1;
        while self
            .lines
            .line(end)
            .is_some_and(|line| line.kind == LineKind::Comment)
        {
            end += 1;
        }
        first..end
    }

    /// The content line of the item holding `address`, else the nearest
    /// line after it.
    pub fn line_of(&self, address: u64) -> u64 {
        self.lines.line_of(address)
    }

    /// The name the listing gives `address` (the user's aside).
    pub fn name(&self, address: u64) -> Option<&str> {
        self.lines.name(address)
    }

    /// The name of `address` as shown: the user's, else the listing's.
    pub fn shown_name<'a>(&'a self, address: u64, overlay: &'a Overlay) -> Option<&'a str> {
        overlay
            .names
            .get(&address)
            .map(String::as_str)
            .or_else(|| self.name(address))
    }

    /// The address `wanted` names: a name the user gave, a name (dummy
    /// names included), else a mapped hexadecimal address.
    pub fn find(&self, wanted: &str, overlay: &Overlay) -> Option<u64> {
        let wanted = wanted.trim();
        overlay
            .names
            .iter()
            .find(|(_, name)| name.as_str() == wanted)
            .map(|(&address, _)| address)
            .or_else(|| self.lines.find(wanted))
    }

    /// Where `address` is, as cross-references say it (`main+58`).
    pub fn describe(&self, address: u64) -> String {
        self.lines.describe(address)
    }

    /// The function whose block holds `address`, and its entry.
    pub fn function_of(&self, address: u64) -> Option<(FunctionId, u64)> {
        self.lines.function_of(address)
    }

    /// The jumps within a function with an end in `lines`.
    pub fn arrows(&self, lines: std::ops::Range<u64>) -> Vec<Arrow> {
        self.lines.arrows(lines)
    }

    /// The lines of the function at `entry`, from its first header line
    /// to its `endp`: the lit area.
    pub fn function_lines(&self, entry: u64) -> Option<std::ops::Range<u64>> {
        let content = self.lines.line_of(entry);
        let mut first = content;
        while let Some(previous) = first.checked_sub(1)
            && self
                .lines
                .line(previous)
                .is_some_and(|l| l.address == entry && l.kind != LineKind::Blank)
        {
            first = previous;
        }
        let mut end = content;
        while let Some(line) = self.lines.line(end) {
            let inside = line.kind == LineKind::End
                || self
                    .lines
                    .function_of(line.address)
                    .is_some_and(|(_, e)| e == entry);
            if !inside && line.kind != LineKind::Blank {
                break;
            }
            end += 1;
            if line.kind == LineKind::End {
                break;
            }
        }
        // Trailing blank lines are outside.
        while end > content
            && self
                .lines
                .line(end - 1)
                .is_some_and(|l| l.kind == LineKind::Blank)
        {
            end -= 1;
        }
        (end > first).then_some(first..end)
    }

    /// The section name of `address` (from its line's prefix, `.text`).
    pub fn section(&self, db: &Database<'_>, address: u64) -> Option<String> {
        let rendered = self.lines.render(db, self.lines.line_of(address));
        let prefix = rendered.tokens.first()?;
        let (name, _) = prefix.text.split_once(':')?;
        Some(name.to_owned())
    }

    /// The entry of the function after (`forward`) or before the one
    /// holding `address` (or after/before `address` if none holds it),
    /// among `entries` (sorted).
    pub fn neighbour_function(&self, entries: &[u64], address: u64, forward: bool) -> Option<u64> {
        let here = self
            .function_of(address)
            .map_or(address, |(_, entry)| entry);
        if forward {
            let i = entries.partition_point(|&e| e <= here);
            entries.get(i).copied()
        } else {
            let i = entries.partition_point(|&e| e < here);
            entries.get(i.checked_sub(1)?).copied()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Overlay;
    use crate::edits::{Edits, NumberForm, Variable};

    fn variable(origins: &[&str], ordinal: usize) -> Variable {
        Variable {
            function: 0x1000,
            origins: origins.iter().map(|&o| o.to_owned()).collect(),
            ordinal,
        }
    }

    #[test]
    fn a_slot_is_named_by_its_one_variable_before_its_own_name() {
        let mut edits = Edits::default();
        edits.set_slot(0x1000, -24, Some("spill".to_owned()));
        edits.set_slot(0x1000, -40, Some("saved".to_owned()));
        edits.set_variable(
            variable(&["slot -24", "value 7"], 0),
            Some("count".to_owned()),
        );
        // Two slots: no one slot's.
        edits.set_variable(
            variable(&["slot -40", "slot -48"], 0),
            Some("pair".to_owned()),
        );
        edits.set_variable(variable(&["frame -56"], 0), Some("buffer".to_owned()));
        // A second variable of the same (the C printing it, not the
        // first): its slot's, before the slot's own name; the first's
        // before it.
        edits.set_variable(variable(&["slot -64"], 1), Some("later".to_owned()));
        edits.set_slot(0x1000, -64, Some("own".to_owned()));
        edits.set_variable(variable(&["slot -72"], 1), Some("second".to_owned()));
        edits.set_variable(variable(&["slot -72"], 0), Some("first".to_owned()));
        let slots = Overlay::of(&edits).slots;
        let named = |offset: i64| slots.get(&(0x1000, offset)).map(String::as_str);
        assert_eq!(named(-24), Some("count"));
        assert_eq!(named(-40), Some("saved"));
        assert_eq!(named(-48), None);
        assert_eq!(named(-56), Some("buffer"));
        assert_eq!(named(-64), Some("later"));
        assert_eq!(named(-72), Some("first"));
    }

    #[test]
    fn a_number_form_spans_the_operands_width_and_the_cs() {
        let mut edits = Edits::default();
        // H on the listing's `0FFFFFFFFh` of a 32-bit compare.
        edits.set_number(0x10, 0xffff_ffff, Some(NumberForm::Decimal));
        let shown = Overlay::of(&edits);
        assert_eq!(shown.number(0x10, u64::MAX), Some(NumberForm::Decimal));
        assert_eq!(edits.number(0x10, u64::MAX), Some(NumberForm::Decimal));
        // One number at every width: `0xffff` too (one key per number).
        assert_eq!(shown.number(0x10, 0xffff), Some(NumberForm::Decimal));
        assert_eq!(shown.number(0x10, 0x7fff), None);
        assert_eq!(shown.number(0x11, u64::MAX), None);
    }
}
