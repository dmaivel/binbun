//! Character constants: a constant compared with, stored to or switched
//! on a value of L2 type `char` is written as C writes a character
//! (`c == '/'`, `*p = '\n'`, `case 'a':`), where that is the same
//! constant: a character constant is an `int` whose value is the
//! character's code (C11 6.4.4.4), so it stands for an `int` literal of a
//! code of the basic character set or of a simple escape, and for no
//! other (a byte of 0x80 or more is negative as a signed `char` and is
//! left a number).

use alloc::format;
use alloc::string::String;
use alloc::vec;

use binbun_ast::ir::{Expr, ExprId};
use binbun_ast::types::{Type, TypeId};
use binbun_semantics::ir::Binary;

use super::Printer;
use super::types::CTy;
use super::value::{Op, Value};
use crate::document::Doc;

/// How many extensions and truncations [`Printer::character`] looks
/// through.
const DEPTH: usize = 4;

/// How a constant compared with a value is written, by the value's L2
/// type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Spelling {
    /// A number.
    Number,
    /// By the names of this enumeration's constants
    /// ([`Printer::by_name`]).
    Enumeration(TypeId),
    /// As a character ([`Printer::by_character`]).
    Character,
}

/// C's spelling of the character whose code is `code`, if it is a
/// printing character of ASCII or has a simple escape.
fn spelled(code: u64) -> Option<String> {
    Some(match u8::try_from(code).ok()? {
        0 => String::from("'\\0'"),
        7 => String::from("'\\a'"),
        8 => String::from("'\\b'"),
        b'\t' => String::from("'\\t'"),
        b'\n' => String::from("'\\n'"),
        11 => String::from("'\\v'"),
        12 => String::from("'\\f'"),
        b'\r' => String::from("'\\r'"),
        b'\'' => String::from("'\\''"),
        b'\\' => String::from("'\\\\'"),
        byte @ 0x20..=0x7e => format!("'{}'", char::from(byte)),
        _ => return None,
    })
}

impl Printer<'_> {
    /// How a constant compared with `x` or `y` is written: by an
    /// enumeration's names where one is of its type, as a character
    /// where one is a `char`.
    pub(super) fn spelling(&self, x: ExprId, y: ExprId) -> Spelling {
        if let Some(ty) = self.enum_type(x).or_else(|| self.enum_type(y)) {
            Spelling::Enumeration(ty)
        } else if self.character(x) || self.character(y) {
            Spelling::Character
        } else {
            Spelling::Number
        }
    }

    /// Whether L2 type `ty` is `char`.
    pub(super) fn is_char(&self, ty: TypeId) -> bool {
        matches!(self.types.get(ty), Some(Type::Char { .. }))
    }

    /// Whether expression `id` is a character: its L2 type is `char` (a
    /// variable's, a load's, a cast's, an assignment's variable's or
    /// value's), it is a byte loaded through a pointer to `char`
    /// ([`Self::text_pointer`]: the second character of a string whose
    /// first one said it is text), or it is one extended, or the low
    /// byte of one (a character promoted, as `movsx` and `movzx` leave
    /// it for a comparison).
    pub(super) fn character(&self, id: ExprId) -> bool {
        let mut id = id;
        for _ in 0..DEPTH {
            let Some(&expr) = self.f.expr(id) else {
                return false;
            };
            if let Expr::Var(var) = expr {
                return self.f.var(var).is_some_and(|v| self.is_char(v.ty));
            }
            if let Expr::Assign { var, value } = expr {
                if self.f.var(var).is_some_and(|v| self.is_char(v.ty)) {
                    return true;
                }
                id = value;
                continue;
            }
            if let Expr::Load { address, ty } = expr {
                return self.is_char(ty)
                    || (self.width(id) == 8 && self.text_pointer(address, DEPTH));
            }
            if let Expr::Cast { ty, .. } = expr {
                return self.is_char(ty);
            }
            if let Expr::Extend { value, .. }
            | Expr::Extract {
                value,
                offset: 0,
                width: 8,
            } = expr
            {
                id = value;
                continue;
            }
            return false;
        }
        false
    }

    /// Whether address `id` is a pointer to `char`, or one moved on: a
    /// variable of that type, or a sum with one (`p + 1`, `p + i`),
    /// `depth` sums deep.
    fn text_pointer(&self, id: ExprId, depth: usize) -> bool {
        match self.f.expr(id) {
            Some(&Expr::Var(var)) => self.f.var(var).is_some_and(|variable| {
                matches!(
                    self.types.get(variable.ty),
                    Some(&Type::Pointer(Some(target))) if self.is_char(target)
                )
            }),
            Some(&Expr::Binary(Binary::Add, x, y)) if depth > 0 => {
                self.text_pointer(x, depth - 1) || self.text_pointer(y, depth - 1)
            }
            Some(_) | None => false,
        }
    }

    /// `value` as a character constant where it is an `int` literal of a
    /// character C can write ([`spelled`]): the same constant, of the
    /// same type; else `value` itself.
    pub(super) fn by_character(&self, value: Value) -> Value {
        let (Some(bits), Some((true, 32))) = (value.constant, value.form().promoted()) else {
            return value;
        };
        if bits.width() > 64 || bits.leading_zeros() + 7 < u32::from(bits.width()) {
            return value;
        }
        let Some(text) = spelled(bits.low_u64()) else {
            return value;
        };
        let mut character = value;
        character.doc = vec![Doc::number(text, self.node)];
        character.op = Op::Postfix;
        character.ty = CTy::Int {
            signed: true,
            bits: 32,
        };
        character
    }
}
