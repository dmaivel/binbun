//! Rendering a [`Document`] under a [`Style`]: to text ([`render`]), or
//! to text and the span of every token with its kind and node
//! ([`render_spans`]), for a UI, and where each top-level item starts
//! ([`render_items`]).
//!
//! The engine is Wadler's: a stack of pieces still to lay out, each with
//! its indentation and mode (flat or broken); a [`Doc::Group`] is flat if
//! it and what follows it up to the next possible break fit before the
//! column limit. [`Doc::Block`]s are always broken, their braces placed as
//! the [`BraceStyle`] says. Lines never end in whitespace.

use alloc::string::String;
use alloc::vec::Vec;
use core::ops::Range;

use binbun_ast::ir::Node;

use crate::document::{BlockKind, Braces, Doc, Document, Token, TokenKind};
use crate::style::{BraceStyle, Indent, SingleStatementBraces, Spacing, Style};

/// Where a token was rendered.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Span {
    /// Its bytes in the text.
    pub range: Range<usize>,
    /// What it is.
    pub kind: TokenKind,
    /// The L2 node it stands for, if any.
    pub node: Option<Node>,
    /// Whether it is a name binbun made up ([`Token::automatic`]).
    pub automatic: bool,
    /// Whether it is part of a cast ([`Token::cast`]).
    pub cast: bool,
}

/// The text of `document` under `style`.
pub fn render(document: &Document, style: &Style) -> String {
    render_spans(document, style).0
}

/// The text of `document` under `style`, and every token's span in it
/// (braces included), in order.
pub fn render_spans(document: &Document, style: &Style) -> (String, Vec<Span>) {
    let (text, spans, _) = render_items(document, style);
    (text, spans)
}

/// The text of `document` under `style`, every token's span in it
/// ([`render_spans`]), and where each of its top-level items starts in it
/// (a byte offset, the start of its first line, one per item).
pub fn render_items(document: &Document, style: &Style) -> (String, Vec<Span>, Vec<usize>) {
    let mut engine = Engine {
        style,
        text: String::new(),
        spans: Vec::new(),
        column: 0,
        pending: Some(0),
        omitted: false,
    };
    let mut stack = Vec::new();
    let mut starts = Vec::with_capacity(document.items.len());
    // Item by item: a group's fit looks no further than the next line
    // break, so laying each out alone is laying out the whole.
    for (index, item) in document.items.iter().enumerate() {
        if index > 0 {
            engine.step(Cmd::Newline { indent: 0 }, &mut stack);
        }
        starts.push(engine.text.len());
        stack.push(Cmd::Doc {
            indent: 0,
            mode: Mode::Break,
            doc: item,
        });
        while let Some(cmd) = stack.pop() {
            engine.step(cmd, &mut stack);
        }
    }
    if !engine.text.is_empty() {
        engine.text.push('\n');
    }
    (engine.text, engine.spans, starts)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Flat,
    Break,
}

#[derive(Clone, Copy, Debug)]
enum Cmd<'a> {
    Doc {
        indent: usize,
        mode: Mode,
        doc: &'a Doc,
    },
    Newline {
        indent: usize,
    },
    /// The end of a block: its closing brace at `column`, or nothing if
    /// its braces were left out.
    Close {
        column: usize,
        omitted: bool,
        node: Option<Node>,
    },
}

struct Engine<'a> {
    style: &'a Style,
    text: String,
    spans: Vec<Span>,
    column: usize,
    /// The indentation of the line just started, not yet written (lines
    /// that stay empty get none).
    pending: Option<usize>,
    /// Whether the last block closed had its braces left out.
    omitted: bool,
}

impl<'a> Engine<'a> {
    fn width(&self) -> usize {
        usize::from(self.style.indent_width)
    }

    fn step(&mut self, cmd: Cmd<'a>, stack: &mut Vec<Cmd<'a>>) {
        match cmd {
            Cmd::Doc { indent, mode, doc } => self.doc(indent, mode, doc, stack),
            Cmd::Newline { indent } => self.newline(indent),
            Cmd::Close {
                column,
                omitted,
                node,
            } => {
                if !omitted {
                    self.newline(column);
                    self.brace("}", node);
                }
                self.omitted = omitted;
            }
        }
    }

    fn doc(&mut self, indent: usize, mode: Mode, doc: &'a Doc, stack: &mut Vec<Cmd<'a>>) {
        let children = |stack: &mut Vec<Cmd<'a>>, items: &'a [Doc], indent, mode| {
            stack.extend(items.iter().rev().map(|doc| Cmd::Doc { indent, mode, doc }));
        };
        match doc {
            Doc::Token(token) => self.token(token),
            Doc::Space => self.space(),
            Doc::Line => match mode {
                Mode::Flat => self.space(),
                Mode::Break => self.newline(indent),
            },
            Doc::SoftLine => {
                if mode == Mode::Break {
                    self.newline(indent);
                }
            }
            Doc::HardLine => self.newline(indent),
            Doc::BlankLine => {
                self.newline(indent);
                self.newline(indent);
            }
            // A block's gaps are its body's lines ([`Self::block`]).
            Doc::Gap => {}
            Doc::Group(items) => {
                let flat = mode == Mode::Flat || self.fits(doc, stack);
                let mode = if flat { Mode::Flat } else { Mode::Break };
                children(stack, items, indent, mode);
            }
            Doc::Nest(items) => children(stack, items, indent + self.width(), mode),
            Doc::Outdent(items) => {
                let indent = indent.saturating_sub(self.width());
                if self.pending.is_some() {
                    self.pending = Some(indent);
                }
                children(stack, items, indent, mode);
            }
            Doc::Block {
                kind,
                braces,
                body,
                node,
            } => self.block(indent, *kind, *braces, body, *node, stack),
            Doc::AfterBlock => {
                let own_line = self.omitted
                    || matches!(self.style.braces, BraceStyle::Allman | BraceStyle::Gnu);
                if own_line {
                    self.newline(indent);
                } else {
                    self.space();
                }
            }
        }
    }

    fn block(
        &mut self,
        indent: usize,
        kind: BlockKind,
        braces: Braces,
        body: &'a [Doc],
        node: Option<Node>,
        stack: &mut Vec<Cmd<'a>>,
    ) {
        let width = self.width();
        if braces == Braces::Optional
            && self.style.single_statement_braces == SingleStatementBraces::WhenNeeded
            && let [only] = body
        {
            stack.push(Cmd::Close {
                column: indent,
                omitted: true,
                node,
            });
            stack.push(Cmd::Doc {
                indent: indent + width,
                mode: Mode::Break,
                doc: only,
            });
            stack.push(Cmd::Newline {
                indent: indent + width,
            });
            return;
        }
        let (column, own_line) = match (self.style.braces, kind) {
            (BraceStyle::Attach, _)
            | (
                BraceStyle::KernighanRitchie | BraceStyle::Linux,
                BlockKind::Statement | BlockKind::Aggregate,
            ) => (indent, false),
            (BraceStyle::KernighanRitchie | BraceStyle::Linux, BlockKind::Function)
            | (BraceStyle::Allman, _)
            | (BraceStyle::Gnu, BlockKind::Function | BlockKind::Aggregate) => (indent, true),
            (BraceStyle::Gnu, BlockKind::Statement) => (indent + width, true),
        };
        if own_line {
            self.newline(column);
        } else {
            self.space();
        }
        self.brace("{", node);
        stack.push(Cmd::Close {
            column,
            omitted: false,
            node,
        });
        for item in body.iter().rev() {
            // A gap is an empty line under paragraph spacing, else nothing.
            if matches!(item, Doc::Gap) {
                if self.style.spacing == Spacing::Paragraphs {
                    stack.push(Cmd::Newline {
                        indent: column + width,
                    });
                }
                continue;
            }
            stack.push(Cmd::Doc {
                indent: column + width,
                mode: Mode::Break,
                doc: item,
            });
            stack.push(Cmd::Newline {
                indent: column + width,
            });
        }
    }

    /// Whether `group`, flat, and what follows it up to the next break fit
    /// before the column limit.
    fn fits(&self, group: &Doc, rest: &[Cmd<'_>]) -> bool {
        let limit = usize::from(self.style.column_limit);
        let start = self.pending.unwrap_or(self.column);
        let Some(mut room) = limit.checked_sub(start) else {
            return false;
        };
        // Pieces of the group itself (true) or of what follows (false).
        let mut local: Vec<(bool, Mode, &Doc)> = alloc::vec![(true, Mode::Flat, group)];
        let mut rest = rest.iter().rev();
        loop {
            let (inside, mode, doc) = match local.pop() {
                Some(piece) => piece,
                None => match rest.next() {
                    Some(&Cmd::Doc { mode, doc, .. }) => (false, mode, doc),
                    Some(Cmd::Newline { .. } | Cmd::Close { .. }) | None => return true,
                },
            };
            let used = match doc {
                Doc::Token(token) => token.text.chars().count(),
                Doc::Space => 1,
                Doc::Line => match mode {
                    Mode::Flat => 1,
                    Mode::Break => return true,
                },
                Doc::SoftLine => match mode {
                    Mode::Flat => 0,
                    Mode::Break => return true,
                },
                Doc::HardLine | Doc::BlankLine | Doc::Gap | Doc::Block { .. } | Doc::AfterBlock => {
                    return !inside;
                }
                Doc::Group(items) | Doc::Nest(items) | Doc::Outdent(items) => {
                    let mode = if inside { Mode::Flat } else { mode };
                    local.extend(items.iter().rev().map(|doc| (inside, mode, doc)));
                    0
                }
            };
            match room.checked_sub(used) {
                Some(left) => room = left,
                None => return false,
            }
        }
    }

    fn newline(&mut self, indent: usize) {
        while self.text.ends_with(' ') || self.text.ends_with('\t') {
            self.text.pop();
        }
        self.text.push('\n');
        self.column = 0;
        self.pending = Some(indent);
    }

    fn space(&mut self) {
        if self.pending.is_none() {
            self.text.push(' ');
            self.column += 1;
        }
    }

    fn token(&mut self, token: &Token) {
        self.span(
            &token.text,
            token.kind,
            token.node,
            (token.automatic, token.cast),
        );
    }

    fn brace(&mut self, text: &str, node: Option<Node>) {
        self.span(text, TokenKind::Punctuation, node, (false, false));
    }

    /// A token of `text`, `kind` and `node`, `(automatic, cast)` as `flags`.
    fn span(&mut self, text: &str, kind: TokenKind, node: Option<Node>, flags: (bool, bool)) {
        if let Some(indent) = self.pending.take() {
            match self.style.indent {
                Indent::Spaces => {
                    self.text.extend(core::iter::repeat_n(' ', indent));
                }
                Indent::Tabs => {
                    let tab = usize::from(self.style.tab_width.max(1));
                    self.text.extend(core::iter::repeat_n('\t', indent / tab));
                    self.text.extend(core::iter::repeat_n(' ', indent % tab));
                }
            }
            self.column = indent;
        }
        let start = self.text.len();
        self.text.push_str(text);
        self.column += text.chars().count();
        self.spans.push(Span {
            range: start..self.text.len(),
            kind,
            node,
            automatic: flags.0,
            cast: flags.1,
        });
    }
}
