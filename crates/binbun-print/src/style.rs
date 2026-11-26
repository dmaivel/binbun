//! Layout and presentation options.
//!
//! - **Layout** options change only whitespace and line breaks: the
//!   indentation ([`Indent`], width, tab width), the [`BraceStyle`], the
//!   column limit and the empty lines between a block's statements
//!   ([`Spacing`]). Rendering one document under any two layouts and
//!   dropping the whitespace gives the same text (tested).
//! - **Presentation** options change tokens but never meaning: how
//!   integer types are spelled ([`IntSpelling`]), from what magnitude
//!   constants are hexadecimal, and whether a single simple statement
//!   under `if` or a loop keeps its braces ([`SingleStatementBraces`]:
//!   presentation, not layout, since braces are tokens), and where locals
//!   are declared ([`Placement`]), and how variables with no name of their
//!   own are named ([`Naming`]).
//!
//! [`Style`] has a [`Default`] (the [`kr`](Style::kr) preset), presets by
//! name ([`Style::preset`]) and builder methods.

/// What indentation is made of.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Indent {
    /// Spaces.
    Spaces,
    /// Tabs (each [`Style::tab_width`] columns), then spaces for a
    /// remainder.
    Tabs,
}

/// Where braces go.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BraceStyle {
    /// Every opening brace at the end of its line (`clang-format`'s
    /// `Attach`, LLVM's style).
    Attach,
    /// Kernighan and Ritchie: a function's opening brace on a line of its
    /// own, the others attached; `} else {`.
    KernighanRitchie,
    /// The Linux kernel's: as [`KernighanRitchie`](Self::KernighanRitchie)
    /// for C.
    Linux,
    /// Every brace on a line of its own, at the statement's indentation.
    Allman,
    /// Every brace on a line of its own; a statement's braces indented one
    /// level, its body another.
    Gnu,
}

/// Whether a single simple statement keeps its braces.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SingleStatementBraces {
    /// Always braces.
    Always,
    /// Braces only where needed: a body of one simple statement (not a
    /// compound statement, nor a `do` loop's) has none.
    WhenNeeded,
}

/// Whether empty lines part a block's statements into paragraphs.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Spacing {
    /// An empty line after a run of declarations, after a compound
    /// statement (`if`, a loop, `switch`) that another statement follows,
    /// and before a label (not right after another): where the code's
    /// structure parts it, as the kernel's `checkpatch` asks after
    /// declarations. Every preset's.
    #[default]
    Paragraphs,
    /// No empty line between a block's statements (only after the
    /// locals declared at the top of a function).
    Compact,
}

/// How integer types are spelled.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum IntSpelling {
    /// `int32_t`, `uint64_t`, `uint8_t`: exact under every data model, and
    /// saying what is known of an inferred integer (its width and
    /// signedness) and no more. Every preset's spelling.
    #[default]
    Fixed,
    /// `int`, `unsigned short`, `long`: C's own names as C programmers
    /// write them for the image's data model
    /// ([`Image::long_width`](crate::c::Image::long_width)): 8 bits
    /// `signed char` and `unsigned char` (never plain `char`, whose
    /// signedness differs by platform), 16 `short`, 32 `int`, 64 `long`
    /// under LP64 (Linux, macOS) and `long long` under LLP64 (64-bit
    /// Windows) and ILP32.
    Plain,
}

/// Where locals are declared.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Placement {
    /// Where the function places them
    /// ([`Function::declared`](binbun_ast::ir::Function::declared)): in
    /// the innermost block using each, at its first assignment, a `for`'s
    /// counter in its header. Every preset's.
    #[default]
    Scoped,
    /// All at the top of the body.
    Top,
}

/// How a variable with no name of its own (none from debug information,
/// the user, a symbol or a callee's declaration) is named.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Naming {
    /// By kind and number: parameters `a1`, `a2`, …, locals `v7`. Every
    /// preset's.
    #[default]
    Numbered,
    /// By where the machine code kept it: parameters `arg1`, `arg2`, …; a
    /// local by the register it held its first value in (`rax`; where
    /// several were, `rax_1`, `rax_2`, …); a local in the stack frame by
    /// its offset from the stack pointer at entry (`var_58` below it,
    /// `arg_8` above); any other local `v7`.
    Registers,
}

/// Layout and presentation options.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Style {
    /// What indentation is made of.
    pub indent: Indent,
    /// Columns per indentation level.
    pub indent_width: u16,
    /// Columns per tab.
    pub tab_width: u16,
    /// Where braces go.
    pub braces: BraceStyle,
    /// The column a line should not pass (where breaks allow).
    pub column_limit: u16,
    /// Whether empty lines part a block's statements.
    pub spacing: Spacing,
    /// Whether single simple statements keep their braces (presentation).
    pub single_statement_braces: SingleStatementBraces,
    /// How integer types are spelled (presentation).
    pub int_spelling: IntSpelling,
    /// Where locals are declared (presentation).
    pub declarations: Placement,
    /// How variables with no name of their own are named (presentation).
    pub naming: Naming,
    /// Constants whose magnitude is at least this print in hexadecimal,
    /// smaller ones in decimal (presentation; masks and other operands of
    /// bitwise operations are hexadecimal from 10).
    pub hex_threshold: u64,
}

impl Default for Style {
    fn default() -> Self {
        Self::kr()
    }
}

impl Style {
    /// Kernighan and Ritchie: four spaces, function braces on their own
    /// line, braces only where needed.
    pub const fn kr() -> Self {
        Self {
            indent: Indent::Spaces,
            indent_width: 4,
            tab_width: 8,
            braces: BraceStyle::KernighanRitchie,
            column_limit: 80,
            spacing: Spacing::Paragraphs,
            single_statement_braces: SingleStatementBraces::WhenNeeded,
            int_spelling: IntSpelling::Fixed,
            declarations: Placement::Scoped,
            naming: Naming::Numbered,
            hex_threshold: 256,
        }
    }

    /// LLVM's: two spaces, attached braces, braces only where needed.
    pub const fn llvm() -> Self {
        Self {
            indent: Indent::Spaces,
            indent_width: 2,
            tab_width: 8,
            braces: BraceStyle::Attach,
            column_limit: 80,
            spacing: Spacing::Paragraphs,
            single_statement_braces: SingleStatementBraces::WhenNeeded,
            int_spelling: IntSpelling::Fixed,
            declarations: Placement::Scoped,
            naming: Naming::Numbered,
            hex_threshold: 256,
        }
    }

    /// The Linux kernel's: tabs of eight, K&R braces, braces only where
    /// needed.
    pub const fn linux() -> Self {
        Self {
            indent: Indent::Tabs,
            indent_width: 8,
            tab_width: 8,
            braces: BraceStyle::Linux,
            column_limit: 80,
            spacing: Spacing::Paragraphs,
            single_statement_braces: SingleStatementBraces::WhenNeeded,
            int_spelling: IntSpelling::Fixed,
            declarations: Placement::Scoped,
            naming: Naming::Numbered,
            hex_threshold: 256,
        }
    }

    /// Allman: four spaces, every brace on its own line, always braces.
    pub const fn allman() -> Self {
        Self {
            indent: Indent::Spaces,
            indent_width: 4,
            tab_width: 8,
            braces: BraceStyle::Allman,
            column_limit: 100,
            spacing: Spacing::Paragraphs,
            single_statement_braces: SingleStatementBraces::Always,
            int_spelling: IntSpelling::Fixed,
            declarations: Placement::Scoped,
            naming: Naming::Numbered,
            hex_threshold: 256,
        }
    }

    /// The preset named `name`: `kr`, `llvm`, `linux` or `allman`.
    pub fn preset(name: &str) -> Option<Self> {
        match name {
            "kr" => Some(Self::kr()),
            "llvm" => Some(Self::llvm()),
            "linux" => Some(Self::linux()),
            "allman" => Some(Self::allman()),
            _ => None,
        }
    }

    /// With indentation made of `indent`.
    #[must_use]
    pub const fn with_indent(mut self, indent: Indent) -> Self {
        self.indent = indent;
        self
    }

    /// With `width` columns per indentation level.
    #[must_use]
    pub const fn with_indent_width(mut self, width: u16) -> Self {
        self.indent_width = width;
        self
    }

    /// With `width` columns per tab.
    #[must_use]
    pub const fn with_tab_width(mut self, width: u16) -> Self {
        self.tab_width = width;
        self
    }

    /// With braces where `braces` puts them.
    #[must_use]
    pub const fn with_braces(mut self, braces: BraceStyle) -> Self {
        self.braces = braces;
        self
    }

    /// With lines broken (where they may be) before column `limit`.
    #[must_use]
    pub const fn with_column_limit(mut self, limit: u16) -> Self {
        self.column_limit = limit;
        self
    }

    /// With a block's statements parted by empty lines as `spacing` says.
    #[must_use]
    pub const fn with_spacing(mut self, spacing: Spacing) -> Self {
        self.spacing = spacing;
        self
    }

    /// With single simple statements braced as `braces` says.
    #[must_use]
    pub const fn with_single_statement_braces(mut self, braces: SingleStatementBraces) -> Self {
        self.single_statement_braces = braces;
        self
    }

    /// With integer types spelled as `spelling` says.
    #[must_use]
    pub const fn with_int_spelling(mut self, spelling: IntSpelling) -> Self {
        self.int_spelling = spelling;
        self
    }

    /// With constants of magnitude `threshold` and more in hexadecimal.
    #[must_use]
    pub const fn with_hex_threshold(mut self, threshold: u64) -> Self {
        self.hex_threshold = threshold;
        self
    }

    /// With locals declared where `declarations` says.
    #[must_use]
    pub const fn with_declarations(mut self, declarations: Placement) -> Self {
        self.declarations = declarations;
        self
    }

    /// With variables that have no name of their own named as `naming`
    /// says.
    #[must_use]
    pub const fn with_naming(mut self, naming: Naming) -> Self {
        self.naming = naming;
        self
    }
}
