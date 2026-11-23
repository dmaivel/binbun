//! The sites of x86's undefined values: each output an entry of the
//! semantics leaves undefined (`shrd.of`), as `cargo xtask codegen` lists
//! them in [`crate::sites`] from the semantics' `undefined()`s and the
//! flags XED says an entry's forms leave undefined. For L0 a site is a
//! name and named inputs ([`X86`](crate::X86)'s `sites`); here is what the
//! lifter needs to find the inputs' values and where the value goes.

use binbun_x86::{Flag, Form, Register};

/// What a site's input is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Input {
    /// Parameter `n` of the entry: its operand's value as the instruction
    /// reads it.
    Operand(u8),
    /// A flag, as the instruction reads it.
    Flag(Flag),
    /// The output's value before the instruction (`old`).
    Old,
    /// Parameter `n`: the value the entry writes to its operand, or its
    /// value as read where the entry writes none (`defined.<name>`).
    Defined(u8),
    /// The value the entry writes to a flag (`defined.<flag>`).
    DefinedFlag(Flag),
}

/// Where a site's value goes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Output {
    /// A flag (the x87 condition codes included).
    Flag(Flag),
    /// Parameter `n` of the entry: its operand.
    Operand(u8),
    /// Bits of a register the entry names.
    Register(Register),
    /// A part of a memory operand (a field of an x87 environment image).
    Memory,
}

/// One site: where its value goes, its inputs (named as in
/// [`X86`](crate::X86)'s site of the same number), and the forms whose
/// semantics have it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Site {
    /// Where the value goes.
    pub output: Output,
    /// The inputs.
    pub inputs: &'static [Input],
    /// The forms.
    pub forms: &'static [Form],
}
