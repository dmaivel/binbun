//! One function's C as a session shows it ([`Document`]): its decompiled
//! L1 and L2 (the provenance of every token), printed with the user's
//! names and numbers in the forms the user chose for their instructions
//! ([`NumberForm`]). Printing is presentation: an edit prints the kept L2 again,
//! never decompiles. Each variable's default name (what the printer calls
//! it without the user's name: what an empty rename field shows) comes
//! with it ([`Document::default_name`]).
//! Each member's name, in a struct's definition and where it is used
//! (`p->name`), is known by the struct or union it is a member of
//! ([`Document::members`]).
//! The user's comments are printed at the end of the lines made from
//! their instructions ([`Document::comments`]).
//! Which instructions each line and token came from is its
//! [`Provenance`] ([`Document::provenance`]).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use binbun::Database;
use binbun::cfg::FunctionId;
use binbun::data::ImageData;
use binbun::decompile::{Assumed, Decompiled, View, reading_comment};
use binbun_ast::ir::{Function as Ast, Name, NameOrigin, Node, VarId, VarKind};
use binbun_ast::types::{Enumeration, TypeId};
use binbun_print::c::{self, Counts, Image as Printing, Opaque, ThreadPointer, Unlifted, comment};
use binbun_print::document::TokenKind;
use binbun_print::layout::{Span, render_items, render_spans};
use binbun_print::style::Style;
use binbun_semantics::Declarations;
use binbun_semantics::ir::RegisterId;
use binbun_ssa::ir::Function as L1;

use crate::edits::{Edit, Edits, NumberForm, Unresolved};
use crate::number::{Radix, Written, by_name, parse};
use crate::provenance::{Line, Provenance};
use crate::types;

/// One function's C, with what it was printed from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Document {
    /// The function.
    pub function: FunctionId,
    /// The view it is decompiled in.
    pub view: View,
    /// Its entry.
    pub entry: u64,
    /// The C file, as `binbun decompile` prints the function when the
    /// user has named nothing it prints.
    pub text: String,
    /// The line the function's definition starts on. The lines before it
    /// are the file's preamble: its header, and the structs, globals and
    /// callees it uses declared, which every function using them prints
    /// again.
    pub definition: usize,
    /// Every token's span in `text`, with its kind and the L2 node it
    /// stands for ([`render_spans`]).
    pub spans: Vec<Span>,
    /// What the C contains.
    pub counts: Counts,
    /// The function decompiled (L1 and L2 as the pipeline left them,
    /// before the user's names), which the spans' nodes are of.
    pub decompiled: Arc<Decompiled>,
    /// The user's names of its variables that name none of them now.
    pub unresolved: Vec<Unresolved>,
    /// Each variable's name as the printer chooses it without the user's
    /// variable names (with the function's and other globals' names as
    /// the user set them; a global's without the user's name of it): what
    /// renaming it to nothing prints.
    pub defaults: BTreeMap<VarId, String>,
    /// Each member name's span (on its line of a struct's definition, or
    /// where it is used: `p->name`, `v.name`) with the struct or union
    /// (of the L2's types) it is a member of. A use's span stands for
    /// the access, as the `->` or `.` before it.
    pub members: BTreeMap<usize, TypeId>,
    /// The user's comments printed, one span (a `/* … */` comment) per
    /// line of a comment, each with the address the comment is at and
    /// that line's text as the user wrote it. A comment is printed once,
    /// at the end of the first line made from its instruction (as the
    /// provenance of the line's expressions and statements says, as the
    /// front end links C lines to instructions), the comments of a line
    /// in address order; its first line after the line's text, each
    /// further line on a line of its own below, at the same column.
    pub comments: BTreeMap<usize, (u64, String)>,
    /// Which instructions each line and token of `text` came from.
    pub provenance: Arc<Provenance>,
}

impl Document {
    /// Variable `var`'s default name ([`Self::defaults`]).
    pub fn default_name(&self, var: VarId) -> Option<&str> {
        self.defaults.get(&var).map(String::as_str)
    }

    /// The lines, each with the instructions it came from
    /// ([`Provenance::lines`]).
    pub fn lines(&self) -> &[Line] {
        self.provenance.lines()
    }

    /// The text of line `n` (empty past the last).
    pub fn line_text(&self, n: usize) -> &str {
        self.lines()
            .get(n)
            .and_then(|line| self.text.get(line.range.clone()))
            .unwrap_or("")
    }

    /// The lines made from the instruction at `address`, in order.
    pub fn lines_of(&self, address: u64) -> impl Iterator<Item = usize> + '_ {
        self.provenance.lines_of(address)
    }

    /// The instructions token `s` stands for ([`Provenance::span_addresses`]).
    pub fn span_addresses(&self, s: usize) -> &[u64] {
        self.provenance.span_addresses(s)
    }

    /// The number token `s` writes, with its literal's token: of a
    /// literal, or of the `-` right before one ([`number`]).
    pub fn number(&self, s: usize) -> Option<(usize, Written)> {
        number(&self.text, &self.spans, s)
    }
}

/// The number token `s` of `spans` (of `text`) writes, with its literal's
/// token: of a literal, or of the `-` right before one. The printer
/// writes a negative number as the operator `-` and a literal (`-1`): a
/// `-` ending where a literal starts is its sign, so either token is the
/// whole number (the listing's `0FFFFFFFFh`, not `1`).
fn number(text: &str, spans: &[Span], s: usize) -> Option<(usize, Written)> {
    let token = |s: usize| text.get(spans.get(s)?.range.clone());
    let is_sign = |s: usize| {
        let (Some(minus), Some(next)) = (spans.get(s), spans.get(s + 1)) else {
            return false;
        };
        minus.kind == TokenKind::Operator
            && next.kind == TokenKind::Number
            && minus.range.end == next.range.start
            && token(s) == Some("-")
    };
    let literal = if is_sign(s) { s + 1 } else { s };
    if spans.get(literal)?.kind != TokenKind::Number {
        return None;
    }
    let written = parse(token(literal)?)?;
    let signed = literal.checked_sub(1).is_some_and(is_sign);
    Some((literal, if signed { written.negated() } else { written }))
}

/// Function `function` of `database`, `decompiled`, printed under `style`
/// with the user's `edits`: its name, its variables', and those of the
/// functions and globals it refers to.
///
/// # Errors
///
/// The image's code is not lifted, or the printer refuses the function
/// (the message `binbun decompile` gives).
pub(crate) fn print(
    database: &Database<'_>,
    function: FunctionId,
    view: View,
    decompiled: &Arc<Decompiled>,
    edits: &Edits,
    style: &Style,
) -> Result<Document, String> {
    let declarations = database
        .declarations()
        .ok_or_else(|| "the image's code is not lifted".to_owned())?;
    let entry = database.function(function).map_or(0, |f| f.entry);
    let mut l2 = decompiled.l2.clone();
    if let Some(name) = edits.function(entry) {
        l2.name = Some(name.to_owned());
    }
    let unnamed = (edits.variables_of(entry).next().is_some()).then(|| l2.clone());
    let mut unresolved = Vec::new();
    for (variable, name) in edits.variables_of(entry) {
        match variable.resolve(&decompiled.l2, declarations) {
            Ok(var) => {
                if let Some(slot) = usize::try_from(var.0)
                    .ok()
                    .and_then(|var| l2.variables.get_mut(var))
                {
                    slot.name = Some(Name::new(name, NameOrigin::User));
                }
            }
            Err(why) => unresolved.push(Unresolved {
                edit: Edit::Variable {
                    variable: variable.clone(),
                    name: name.to_owned(),
                },
                why,
            }),
        }
    }
    let names = Named {
        data: database.data(),
        edits,
        own: &BTreeSet::new(),
    };
    let printed = c::function(&l2, declarations, style, &names, view.opaque())
        .map_err(|error| format!("cannot print: {error}"))?;
    let (text, spans, items) = render_items(&printed.document, style);
    // The definition is the printer's last item.
    let mut definition = items
        .last()
        .and_then(|&start| text.get(..start))
        .map_or(0, |before| before.matches('\n').count());
    let mut defaults = match &unnamed {
        None => variable_names(&text, &spans),
        Some(unnamed) => printed_names(unnamed, declarations, style, &names, view.opaque())?,
    };
    // Renamed to nothing, a global the user named prints its own name.
    let renamed: BTreeSet<u64> = l2
        .variables
        .iter()
        .filter_map(|v| match v.kind {
            VarKind::Global(address) => edits.name(address).map(|_| address),
            VarKind::Parameter | VarKind::Local | VarKind::Frame(_) | VarKind::Environment(_) => {
                None
            }
        })
        .collect();
    if !renamed.is_empty() {
        let own = Named {
            own: &renamed,
            ..names
        };
        let unnamed = unnamed.as_ref().unwrap_or(&l2);
        for (var, name) in printed_names(unnamed, declarations, style, &own, view.opaque())? {
            if matches!(unnamed.var(var).map(|v| v.kind), Some(VarKind::Global(_))) {
                defaults.insert(var, name);
            }
        }
    }
    let unheaded = text.len();
    let (text, spans) = with_header(text, spans, view, &decompiled.stats.assumed);
    definition += text
        .get(..text.len() - unheaded)
        .map_or(0, |header| header.matches('\n').count());
    let (l2, l1) = (&decompiled.l2, &decompiled.l1);
    let enums = types::enumerations(database, edits);
    let (text, spans) = with_numbers(text, spans, (edits, &enums), (l2, l1), definition);
    let (text, mut spans, comments) = with_comments(text, spans, edits, (l2, l1), definition);
    let members = members(&text, &mut spans);
    let provenance = Arc::new(provenance(&text, &spans, (l2, l1), definition));
    Ok(Document {
        function,
        view,
        entry,
        text,
        definition,
        spans,
        counts: printed.counts,
        decompiled: Arc::clone(decompiled),
        unresolved,
        defaults,
        members,
        comments,
        provenance,
    })
}

/// The provenance of `text` and its `spans`, of `l2` lowered from `l1`,
/// the definition starting at line `definition`.
fn provenance(text: &str, spans: &[Span], (l2, l1): (&Ast, &L1), definition: usize) -> Provenance {
    let spans = spans.iter().map(|span| (span.range.clone(), span.node));
    Provenance::new(text, spans, l2, l1, Some(definition))
}

/// The member names among `spans` of `text` (the printer gives a
/// member's name the struct it is a member of as its node), each with
/// that struct; a use's span (after `->` or `.`) is given the access's
/// node back, the operator's.
fn members(text: &str, spans: &mut [Span]) -> BTreeMap<usize, TypeId> {
    let mut members = BTreeMap::new();
    for at in 0..spans.len() {
        let Some(span) = spans.get(at) else {
            continue;
        };
        let (TokenKind::Field, Some(Node::Type(of))) = (span.kind, span.node) else {
            continue;
        };
        members.insert(at, of);
        let access = at
            .checked_sub(1)
            .and_then(|before| spans.get(before))
            .filter(|before| {
                before.kind == TokenKind::Operator
                    && matches!(text.get(before.range.clone()), Some("->" | "."))
            })
            .map(|before| before.node);
        if let (Some(node), Some(span)) = (access, spans.get_mut(at)) {
            span.node = node;
        }
    }
    members
}

/// Each variable's name in `text`: the first identifier standing for it.
fn variable_names(text: &str, spans: &[Span]) -> BTreeMap<VarId, String> {
    let mut names = BTreeMap::new();
    for span in spans {
        if let Some(Node::Var(var)) = span.node
            && span.kind.is_variable()
            && let Some(name) = text.get(span.range.clone())
        {
            names.entry(var).or_insert_with(|| name.to_owned());
        }
    }
    names
}

/// Each variable's name as function `l2` prints (registers named by
/// `declarations`) under `style`, the image read through `names`.
fn printed_names(
    l2: &Ast,
    declarations: &Declarations,
    style: &Style,
    names: &Named<'_>,
    opaque: Opaque,
) -> Result<BTreeMap<VarId, String>, String> {
    let printed = c::function(l2, declarations, style, names, opaque)
        .map_err(|error| format!("cannot print: {error}"))?;
    let (text, spans) = render_spans(&printed.document, style);
    Ok(variable_names(&text, &spans))
}

/// `text` and its `spans` with the reading view's header line in front,
/// as `binbun decompile --view reading` prints it, when the view assumed
/// the checks `assumed` away.
fn with_header(
    text: String,
    spans: Vec<Span>,
    view: View,
    assumed: &Assumed,
) -> (String, Vec<Span>) {
    if view != View::Reading || assumed.is_empty() {
        return (text, spans);
    }
    let header = reading_comment(assumed);
    let shift = header.len();
    let spans = spans
        .into_iter()
        .map(|span| Span {
            range: span.range.start + shift..span.range.end + shift,
            ..span
        })
        .collect();
    (header + &text, spans)
}

/// `text` and its `spans` with each number written in the form the user
/// chose for it at an instruction its line came from ([`Edits::number`]):
/// literals carry no provenance of their own, so a literal goes by the
/// instructions of its line's expressions and statements (`l2`'s
/// provenance, through `l1`'s values), as the front end links C lines to
/// instructions.
///
/// The printer writes a negative number as the operator `-` and a
/// literal (`-1`): a `-` ending where a literal starts is its sign, so
/// the form is the whole number's (the listing's `0FFFFFFFFh` is that
/// `-1`), and the form's spelling of it goes in the two tokens, its sign
/// in the `-` (`-0x1`, never `--0x1`).
///
/// An enumeration's form ([`NumberForm::Enum`], of `enums`) writes the
/// whole number, its sign too, as its constants' names ([`by_name`]):
/// tokens drawn as macros, the `-` gone.
fn with_numbers(
    text: String,
    spans: Vec<Span>,
    (edits, enums): (&Edits, &BTreeMap<String, Enumeration>),
    code: (&Ast, &L1),
    definition: usize,
) -> (String, Vec<Span>) {
    if edits.numbers().is_empty() {
        return (text, spans);
    }
    let provenance = provenance(&text, &spans, code, definition);
    let form_of = |line: usize, written: u64| -> Option<NumberForm> {
        provenance
            .addresses_of(line)
            .iter()
            .find_map(|&address| edits.number(address, written))
    };
    // The spelling, and whether it is an enumeration's names.
    let respell = |i: usize| -> Option<(String, bool)> {
        let (literal, written) = number(&text, &spans, i)?;
        let line = provenance.line_of_span(literal)?;
        let form = form_of(line, written.bits)?;
        if let NumberForm::Enum(name) = &form {
            let spelled = by_name(enums.get(name)?, written, Radix::C)?;
            // The sign is in the names.
            return Some(if literal == i {
                (spelled, true)
            } else {
                (String::new(), false)
            });
        }
        if literal != i {
            return None;
        }
        let spelled = form.spell(written, Radix::C)?;
        if written.negative {
            spelled.strip_prefix('-').map(|s| (s.to_owned(), false))
        } else {
            Some((spelled, false))
        }
    };
    let respelled: Vec<Option<(String, bool)>> = (0..spans.len()).map(respell).collect();
    let mut out = String::with_capacity(text.len());
    let mut shifted = Vec::with_capacity(spans.len());
    let mut at = 0;
    for (span, respelled) in spans.into_iter().zip(respelled) {
        let original = text.get(span.range.clone()).unwrap_or("");
        out.push_str(text.get(at..span.range.start).unwrap_or(""));
        let start = out.len();
        let named = respelled.as_ref().is_some_and(|&(_, named)| named);
        out.push_str(
            respelled
                .as_ref()
                .map_or(original, |(text, _)| text.as_str()),
        );
        at = span.range.end;
        shifted.push(Span {
            range: start..out.len(),
            kind: if named { TokenKind::Macro } else { span.kind },
            ..span
        });
    }
    out.push_str(text.get(at..).unwrap_or(""));
    (out, shifted)
}

/// `text` and its `spans` with the user's comments ([`Edits::comment`])
/// at the end of the lines made from their instructions, as
/// [`Document::comments`] says, and those comments by span. Without
/// comments, `text` as it is.
fn with_comments(
    text: String,
    spans: Vec<Span>,
    edits: &Edits,
    code: (&Ast, &L1),
    definition: usize,
) -> (String, Vec<Span>, BTreeMap<usize, (u64, String)>) {
    if edits.comments().is_empty() {
        return (text, spans, BTreeMap::new());
    }
    // Each line's comments, each on the first line made from its
    // instruction.
    let provenance = provenance(&text, &spans, code, definition);
    let mut placed = BTreeSet::new();
    let per_line: Vec<Vec<(u64, &str)>> = provenance
        .lines()
        .iter()
        .map(|line| {
            line.addresses
                .iter()
                .copied()
                .filter_map(|address| Some((address, edits.comment(address)?)))
                .filter(|&(address, _)| placed.insert(address))
                .collect()
        })
        .collect();
    if placed.is_empty() {
        return (text, spans, BTreeMap::new());
    }
    let mut out = String::with_capacity(text.len() + 64 * placed.len());
    let mut shifted = Vec::with_capacity(spans.len() + placed.len());
    let mut comments = BTreeMap::new();
    let mut spans = spans.into_iter().peekable();
    let mut start = 0;
    for (n, line) in text.split('\n').enumerate() {
        if n > 0 {
            out.push('\n');
        }
        let from = out.len();
        out.push_str(line);
        let end = start + line.len();
        while let Some(span) = spans.next_if(|span| span.range.start <= end) {
            shifted.push(Span {
                range: span.range.start - start + from..span.range.end - start + from,
                ..span
            });
        }
        let column = line.chars().count() + 1;
        let pieces = per_line
            .get(n)
            .into_iter()
            .flatten()
            .flat_map(|&(address, text)| {
                text.split('\n')
                    .map(move |piece| (address, piece.trim_end_matches('\r')))
            });
        for (k, (address, piece)) in pieces.enumerate() {
            if k == 0 {
                out.push(' ');
            } else {
                out.push('\n');
                out.extend(std::iter::repeat_n(' ', column));
            }
            let at = out.len();
            out.push_str(&comment(piece));
            comments.insert(shifted.len(), (address, piece.to_owned()));
            shifted.push(Span {
                range: at..out.len(),
                kind: TokenKind::Comment,
                node: None,
                automatic: false,
                cast: false,
            });
        }
        start = end + 1;
    }
    (out, shifted, comments)
}

/// The image as the printer reads it, functions and globals named as the
/// user named them (but those at [`Self::own`], by their own names).
struct Named<'d> {
    data: &'d ImageData<'d>,
    edits: &'d Edits,
    /// The addresses printed by their own names, not the user's.
    own: &'d BTreeSet<u64>,
}

impl Named<'_> {
    /// The user's name of the function or global at `address`, if it is
    /// printed.
    fn user(&self, address: u64) -> Option<String> {
        if self.own.contains(&address) {
            return None;
        }
        self.edits.name(address).map(str::to_owned)
    }
}

impl Printing for Named<'_> {
    fn symbol(&self, address: u64) -> Option<String> {
        self.user(address).or_else(|| self.data.symbol(address))
    }

    fn import(&self, slot: u64) -> Option<String> {
        self.user(slot)
            .or_else(|| Printing::import(self.data, slot))
    }

    fn read_only(&self, address: u64, bytes: u64) -> bool {
        self.data.read_only(address, bytes)
    }

    fn constant(&self, address: u64, bytes: u64) -> Option<Vec<u8>> {
        Printing::constant(self.data, address, bytes)
    }

    fn string(&self, address: u64) -> Option<Vec<u8>> {
        Printing::string(self.data, address)
    }

    fn thread_pointer(&self) -> ThreadPointer {
        self.data.thread_pointer()
    }

    fn long_width(&self) -> u16 {
        self.data.long_width()
    }

    fn is_thread_pointer(&self, register: RegisterId) -> bool {
        self.data.is_thread_pointer(register)
    }

    fn unlifted(&self, address: u64) -> Option<Unlifted> {
        Printing::unlifted(self.data, address)
    }

    fn instruction(&self, address: u64) -> Option<String> {
        Printing::instruction(self.data, address)
    }
}
