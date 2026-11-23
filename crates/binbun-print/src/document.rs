//! Tokens with kinds and provenance, in layout groups.
//!
//! - A [`Document`] is a list of [`Doc`]s: [`Token`]s (text, a
//!   [`TokenKind`] and the L2 node it stands for) and layout instructions
//!   in the style of Wadler's and Oppen's pretty printers: a
//!   [`Doc::Group`] is laid out on one line if it fits and broken at its
//!   [`Doc::Line`]s and [`Doc::SoftLine`]s if not, a [`Doc::Nest`] indents
//!   the lines it breaks onto.
//! - Braces are not tokens of the document but [`Doc::Block`]s, so the
//!   layout places them as the brace style says (and may leave out the
//!   braces of a block the printer marks [`Braces::Optional`]).
//! - Whitespace is never a token: rendering a document under any style and
//!   dropping the whitespace gives the same characters (but for optional
//!   braces), which the tests check.
//! - Provenance is the L2 node ([`Node`]); the node carries the addresses
//!   and L1 values it stands for (`binbun_ast::ir::Provenance`).

use alloc::string::String;
use alloc::vec::Vec;

use binbun_ast::ir::Node;

/// What a token is, for highlighting: the classes an editor's C
/// highlighting tells apart, decided from the L2 node and declaration a
/// token comes from (never from its text).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TokenKind {
    /// A keyword of control flow: `if`, `else`, `for`, `while`, `do`,
    /// `switch`, `case`, `default`, `return`, `goto`, `break`, `continue`.
    ControlKeyword,
    /// Any other keyword (`struct`, `union`, `extern`, `const`,
    /// `volatile`) or a preprocessor directive (`#include`).
    Keyword,
    /// A named type: a struct's, union's or typedef's name (`struct s_5`'s
    /// `s_5`, `va_list`).
    Type,
    /// A type C or its standard headers name: `int`, `char`, `void`,
    /// `bool`, `float`, `unsigned int`, `__int128`, and the fixed-width
    /// `int8_t`…`uint64_t` (typedefs, but drawn as editors draw the
    /// builtins).
    BuiltinType,
    /// A function: the one defined, a callee, an intrinsic, a compiler
    /// builtin (`__builtin_sqrt`); in calls and declarations.
    Function,
    /// A local variable, frame variable or temporary.
    Local,
    /// A parameter of the function.
    Parameter,
    /// A global variable.
    Global,
    /// A struct or union member: in its definition, after `.` or `->`, and
    /// in an `offsetof` designator.
    Field,
    /// A macro or other preprocessor-ish name: `binbun_defs.h`'s helpers and
    /// constants (`binbun_trap`, `rotl`, `BINBUN_TRAP_DIVIDE`,
    /// `BINBUN_SYMBOL`), the standard ones (`va_start`, `offsetof`,
    /// `INT64_MIN`), and `__attribute__((…))`.
    Macro,
    /// A number.
    Number,
    /// A string or character literal, quotes included.
    String,
    /// An operator (`+`, `<<=`, `*` as dereference, a cast's parentheses).
    Operator,
    /// Punctuation (`(`, `;`, `,`, braces).
    Punctuation,
    /// A comment, delimiters included.
    Comment,
    /// A label (`label_3`, `case 5`'s value is a literal).
    Label,
}

impl TokenKind {
    /// Whether it is a name a reader may rename or follow: a function,
    /// variable, field or macro.
    pub const fn is_name(self) -> bool {
        matches!(
            self,
            Self::Function
                | Self::Local
                | Self::Parameter
                | Self::Global
                | Self::Field
                | Self::Macro
        )
    }

    /// Whether it is a variable: a local, parameter or global.
    pub const fn is_variable(self) -> bool {
        matches!(self, Self::Local | Self::Parameter | Self::Global)
    }

    /// Whether it is a keyword, of control flow or not.
    pub const fn is_keyword(self) -> bool {
        matches!(self, Self::ControlKeyword | Self::Keyword)
    }

    /// Whether it is a type, named or builtin.
    pub const fn is_type(self) -> bool {
        matches!(self, Self::Type | Self::BuiltinType)
    }

    /// Whether it is a literal: a number or a string.
    pub const fn is_literal(self) -> bool {
        matches!(self, Self::Number | Self::String)
    }
}

/// One token.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Token {
    /// Its text (no whitespace but inside comments and literals).
    pub text: String,
    /// What it is.
    pub kind: TokenKind,
    /// The L2 node it stands for, if any (boilerplate has none).
    pub node: Option<Node>,
    /// Whether it is a name binbun made up (`v17`, `a1`, `sub_401000`,
    /// `g_404010`, `f_8`, `s_5`, `label_3`, `t0`): nothing (the user,
    /// debug information, a symbol, a declaration, an inference) named
    /// what it stands for.
    pub automatic: bool,
    /// Whether it is part of a cast: its parentheses or its type name.
    pub cast: bool,
}

/// The kind of a braced block: brace styles treat them differently.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BlockKind {
    /// A function body.
    Function,
    /// The body of `if`, a loop or `switch`.
    Statement,
    /// The members of a `struct` or `union`.
    Aggregate,
}

/// Whether a block's braces may be left out.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Braces {
    /// Always printed.
    Required,
    /// The block is one simple statement: the braces may go.
    Optional,
}

/// A piece of a document.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Doc {
    /// A token.
    Token(Token),
    /// One space, never broken.
    Space,
    /// A space, or a line break if the enclosing group does not fit.
    Line,
    /// Nothing, or a line break if the enclosing group does not fit.
    SoftLine,
    /// A line break.
    HardLine,
    /// An empty line (between top-level declarations).
    BlankLine,
    /// Laid out on one line if it fits, else with its lines broken.
    Group(Vec<Self>),
    /// Lines broken inside are indented one more level.
    Nest(Vec<Self>),
    /// A braced block: each item of `body` on its own line, indented, the
    /// braces where the brace style puts them.
    Block {
        /// What it is the body of.
        kind: BlockKind,
        /// Whether the braces may be left out.
        braces: Braces,
        /// The items, one per line.
        body: Vec<Self>,
        /// The node the braces stand for.
        node: Option<Node>,
    },
    /// Between a block's closing brace and what continues the statement
    /// (`else`, `while`): a space or a line break, as the brace style says.
    AfterBlock,
    /// A line one indentation level left of its block's items (`case`
    /// and goto labels).
    Outdent(Vec<Self>),
}

impl Doc {
    /// A token of `kind` for `node`.
    pub fn token(kind: TokenKind, text: impl Into<String>, node: Option<Node>) -> Self {
        Self::Token(Token {
            text: text.into(),
            kind,
            node,
            automatic: false,
            cast: false,
        })
    }

    /// A name of `kind` for `node`, made up by binbun if `automatic`.
    pub fn name(
        kind: TokenKind,
        text: impl Into<String>,
        automatic: bool,
        node: Option<Node>,
    ) -> Self {
        Self::Token(Token {
            text: text.into(),
            kind,
            node,
            automatic,
            cast: false,
        })
    }

    /// A keyword (not of control flow).
    pub fn keyword(text: &str, node: Option<Node>) -> Self {
        Self::token(TokenKind::Keyword, text, node)
    }

    /// A keyword of control flow.
    pub fn control(text: &str, node: Option<Node>) -> Self {
        Self::token(TokenKind::ControlKeyword, text, node)
    }

    /// A macro's name.
    pub fn macro_name(text: impl Into<String>, node: Option<Node>) -> Self {
        Self::token(TokenKind::Macro, text, node)
    }

    /// Punctuation.
    pub fn punct(text: &str, node: Option<Node>) -> Self {
        Self::token(TokenKind::Punctuation, text, node)
    }

    /// An operator.
    pub fn op(text: &str, node: Option<Node>) -> Self {
        Self::token(TokenKind::Operator, text, node)
    }

    /// A number.
    pub fn number(text: impl Into<String>, node: Option<Node>) -> Self {
        Self::token(TokenKind::Number, text, node)
    }

    /// A string or character literal (`text` includes the quotes).
    pub fn string(text: impl Into<String>, node: Option<Node>) -> Self {
        Self::token(TokenKind::String, text, node)
    }

    /// A comment (`text` includes the delimiters).
    pub fn comment(text: impl Into<String>, node: Option<Node>) -> Self {
        Self::token(TokenKind::Comment, text, node)
    }

    /// Marks every token in it part of a cast.
    pub fn mark_cast(&mut self) {
        match self {
            Self::Token(token) => token.cast = true,
            Self::Group(items)
            | Self::Nest(items)
            | Self::Outdent(items)
            | Self::Block { body: items, .. } => {
                for item in items {
                    item.mark_cast();
                }
            }
            Self::Space
            | Self::Line
            | Self::SoftLine
            | Self::HardLine
            | Self::BlankLine
            | Self::AfterBlock => {}
        }
    }
}

/// A document: what the printer emits, and the layout renders
/// ([`crate::layout`]).
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct Document {
    /// The top-level items, each starting on a new line.
    pub items: Vec<Doc>,
}

impl Document {
    /// The tokens in order (what any style renders, but for braces, which
    /// the layout adds).
    pub fn tokens(&self) -> Vec<&Token> {
        let mut out = Vec::new();
        for item in &self.items {
            collect(item, &mut out);
        }
        out
    }
}

fn collect<'a>(doc: &'a Doc, out: &mut Vec<&'a Token>) {
    match doc {
        Doc::Token(token) => out.push(token),
        Doc::Group(items)
        | Doc::Nest(items)
        | Doc::Outdent(items)
        | Doc::Block { body: items, .. } => {
            for item in items {
                collect(item, out);
            }
        }
        Doc::Space
        | Doc::Line
        | Doc::SoftLine
        | Doc::HardLine
        | Doc::BlankLine
        | Doc::AfterBlock => {}
    }
}
