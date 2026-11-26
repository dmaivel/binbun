//! Enumerations' constants by name ([`Type::Enum`]): a constant of an
//! enumeration's type prints as the constant that is its value
//! (`GENERIC_READ`), or for a set of flags as those it holds
//! (`FILE_SHARE_READ | FILE_SHARE_WRITE`, bits no flag names after them in
//! hexadecimal), where its type says it is one: converted to an
//! enumeration's type (an argument, a store to a slot of one, a returned
//! value), compared with a value of one, and a case of a switch on one.
//! Only where C gives the name the value the number had, in that place:
//! the value converted to the slot's type the same, a comparison's
//! operands converted to the same type, a case converted to the switch's
//! promoted type the same. Anywhere else the number stays.
//!
//! An enumeration whose constants are macros in C's headers
//! ([`Enumeration::macros`]: `O_RDWR`, `PROT_READ`) has no tag: a value of
//! it is its integer type, as the headers give it, and each constant the
//! function names is defined as the macro it is, where no header has
//! defined it (`#ifndef O_RDWR` / `#define O_RDWR 2` / `#endif`), so the C
//! compiles after the system's headers too. Such a constant has its
//! literal's type (`int`, or `unsigned int` past `INT_MAX`); one of no
//! such type, or negative, leaves the number.
//!
//! Each name stays as declared, never suffixed: one another name has
//! (a variable, a function, another enumeration's constant), one a header
//! `binbun_defs.h` includes may define as a macro, or one C reserves leaves the
//! number. The enumerations named are defined before the function with
//! C23's fixed underlying type and only the constants the function uses
//! (`enum ACCESS_MASK : uint32_t { GENERIC_READ = 0x80000000 };`), which
//! GCC and Clang accept in C11 too.
//!
//! A value of an enumeration's type (a variable, a parameter, a field, a
//! function's return value) is declared with it (`enum ACCESS_MASK
//! access;`) where it has a tag no other name has ([`Printer::enum_tag`]):
//! with its fixed underlying type it is that integer type to C, the same
//! values and conversions. One whose constants the function does not
//! name is declared without them (`enum ACCESS_MASK : uint32_t;`). A
//! switch on one with a case its constants do not name, or no default,
//! is on the value as its integer type (`switch ((uint32_t)access)`):
//! GCC and Clang warn of such cases of an enumeration.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use binbun_ast::ir::{Expr, ExprId, Node};
use binbun_ast::types::{Enumeration, Type, TypeId};

use super::convert::{Class, IntTy, common, constant_value, promote};
use super::types::CTy;
use super::value::{Op, Value};
use super::{PrintError, Printer, number};
use crate::document::{BlockKind, Braces, Doc, TokenKind};

/// Where a constant is printed, which says when its name means the same.
#[derive(Clone, Copy, Debug)]
pub(super) enum Context {
    /// Converted to the enumeration's type (an argument, a stored or
    /// returned value): the same bits of its width.
    Converted,
    /// Compared with a value of C type `other` (promoted): the same value,
    /// and the same type for the comparison.
    Compared(IntTy),
    /// A case of a switch whose controlling expression is of C type
    /// `control` (promoted): the same value of that type.
    Case(IntTy),
}

/// A constant of an enumeration by name.
struct Spelled {
    doc: Vec<Doc>,
    op: Op,
    /// Its value, as C reads the constants.
    value: i128,
    /// Its C type (promoted).
    ty: IntTy,
}

/// Whether `name` may be a macro of the headers `binbun_defs.h` includes
/// (`<stdint.h>`'s limits and constant macros, `<stdarg.h>`'s, `<stddef.h>`'s,
/// `<stdbool.h>`'s), or one C reserves for the implementation (`__x`,
/// `_X`): a constant so named is not defined.
fn macro_like(name: &str) -> bool {
    const HEADERS: &[&str] = &[
        "SIZE_MAX",
        "PTRDIFF_MIN",
        "PTRDIFF_MAX",
        "WCHAR_MIN",
        "WCHAR_MAX",
        "WINT_MIN",
        "WINT_MAX",
        "SIG_ATOMIC_MIN",
        "SIG_ATOMIC_MAX",
        "offsetof",
        "va_arg",
        "va_end",
        "va_copy",
        "unreachable",
    ];
    if HEADERS.contains(&name) || name.starts_with("__") {
        return true;
    }
    let mut bytes = name.bytes();
    if bytes.next() == Some(b'_') && bytes.next().is_some_and(|b| b.is_ascii_uppercase()) {
        return true;
    }
    // `INT8_MIN`, `UINT_LEAST16_MAX`, `INTMAX_C`, `UINTPTR_WIDTH`.
    let rest = name.strip_prefix('U').unwrap_or(name);
    rest.starts_with("INT")
        && ["_MIN", "_MAX", "_C", "_WIDTH"]
            .iter()
            .any(|suffix| rest.ends_with(suffix))
}

/// The C type of the literal a macro of constant `value` is, as
/// [`Printer::enum_definitions`] writes it (in hexadecimal past
/// `INT_MAX`): `int`, or `unsigned int` up to `UINT_MAX`; `None` past it.
fn macro_literal(value: u128) -> Option<IntTy> {
    if value <= 0x7fff_ffff {
        Some((true, 32))
    } else if value <= 0xffff_ffff {
        Some((false, 32))
    } else {
        None
    }
}

impl Printer<'_> {
    /// The enumeration type `ty` is, if it is one.
    fn enumeration(&self, ty: TypeId) -> Option<&Enumeration> {
        let Type::Enum(enumeration) = self.types.get(ty)? else {
            return None;
        };
        Some(enumeration)
    }

    /// The tag enumeration `ty` is declared with (`enum ACCESS_MASK`),
    /// taken the first time it is asked for: `None` (an integer of its
    /// width instead) where it has none, or where its tag is another
    /// name's or one a header may define.
    pub(super) fn enum_tag(&mut self, ty: TypeId) -> Option<String> {
        if let Some(tag) = self.enum_tags.get(&ty) {
            return tag.clone();
        }
        let tag = self
            .enumeration(ty)
            .filter(|enumeration| !enumeration.macros)
            .and_then(|enumeration| enumeration.name.clone())
            .filter(|tag| !macro_like(tag) && self.names.claim(tag));
        self.enum_tags.insert(ty, tag.clone());
        tag
    }

    /// The enumeration type of expression `id`, where its L2 type is one:
    /// a variable's, a load's, a cast's, a call's return value's, an
    /// assignment's variable's.
    pub(super) fn enum_type(&self, id: ExprId) -> Option<TypeId> {
        let expr = *self.f.expr(id)?;
        let ty = if let Expr::Var(var) | Expr::Assign { var, .. } = expr {
            self.f.var(var)?.ty
        } else if let Expr::Load { ty, .. } | Expr::Cast { ty, .. } = expr {
            ty
        } else if let Expr::Call(call) = expr {
            let signature = self.f.call(call)?.signature;
            self.types.signature(signature)?.returns?
        } else {
            return None;
        };
        self.enumeration(ty).map(|_| ty)
    }

    /// Takes the name of constant `name` of enumeration `ty`: `false` if
    /// it is some other name's or cannot be declared as it is.
    fn claim_constant(&mut self, ty: TypeId, name: &str) -> bool {
        if let Some(&owner) = self.enum_constants.get(name) {
            return owner == ty;
        }
        if macro_like(name) || !self.names.claim(name) {
            return false;
        }
        self.enum_constants.insert(String::from(name), ty);
        true
    }

    /// The constant `bits` of enumeration `ty` by name, if its names say
    /// it and each can be declared.
    fn spelled(&mut self, bits: u128, width: u16, ty: TypeId) -> Option<Spelled> {
        let enumeration = self.enumeration(ty)?;
        if width != enumeration.width {
            return None;
        }
        let (signed, bits_of) = (enumeration.signed, enumeration.width);
        let held = enumeration.named(bits)?;
        let rest = held.rest;
        // A signed set of flags with its sign bit left over: the
        // hexadecimal would be unsigned, and the `|` too.
        if signed && rest >> (bits_of - 1) & 1 != 0 {
            return None;
        }
        let macros = enumeration.macros;
        // As C reads it: a macro's literal is never negative.
        let value = if macros {
            i128::try_from(bits).ok()?
        } else {
            enumeration.number(bits)
        };
        let names: Vec<String> = held.names.into_iter().map(String::from).collect();
        // A macro is its literal: `int`, or `unsigned int` past `INT_MAX`;
        // `|` of such, the wider. Else the number stays.
        let literal = if macros {
            let mut parts: Vec<u128> = names
                .iter()
                .filter_map(|name| {
                    let (_, bits) = enumeration.constants.iter().find(|(n, _)| n == name)?;
                    Some(*bits)
                })
                .collect();
            if rest != 0 {
                parts.push(rest);
            }
            let mut literal = (true, 32);
            for part in parts {
                // A negative constant is no unsuffixed literal.
                if enumeration.number(part) < 0 {
                    return None;
                }
                match macro_literal(part) {
                    Some((false, _)) => literal = (false, 32),
                    Some((true, _)) => {}
                    None => return None,
                }
            }
            literal
        } else {
            promote((signed, bits_of))
        };
        if !names.iter().all(|name| self.claim_constant(ty, name)) {
            return None;
        }
        let node = self.node;
        let mut doc = Vec::new();
        for (index, name) in names.into_iter().enumerate() {
            if index > 0 {
                doc.extend([Doc::Space, Doc::op("|", node), Doc::Space]);
            }
            doc.push(Doc::name(TokenKind::Macro, name, false, node));
        }
        if rest != 0 {
            doc.extend([Doc::Space, Doc::op("|", node), Doc::Space]);
            doc.push(Doc::number(number(rest, true), node));
        }
        let single = doc.len() == 1;
        Some(Spelled {
            doc,
            op: if single { Op::Postfix } else { Op::BitOr },
            value,
            ty: literal,
        })
    }

    /// `value` by the names of enumeration `ty`'s constants where it is a
    /// literal whose value they say with the same meaning in `context`;
    /// else `value` itself.
    pub(super) fn by_name(&mut self, value: Value, ty: TypeId, context: Context) -> Value {
        let (Some(bits), Some(literal)) = (value.constant, value.form().promoted()) else {
            return value;
        };
        if bits.width() > 64 || self.enumeration(ty).is_none() {
            return value;
        }
        let (negative, magnitude) = constant_value(bits, value.class);
        let Ok(magnitude) = i128::try_from(magnitude) else {
            return value;
        };
        let number = if negative { -magnitude } else { magnitude };
        let Some(spelled) = self.spelled(bits.low_u128(), bits.width(), ty) else {
            return value;
        };
        let modulo = |a: i128, b: i128, bits: u16| {
            let mask = (1i128 << bits) - 1;
            a & mask == b & mask
        };
        let same = match context {
            Context::Converted => modulo(spelled.value, number, bits.width()),
            Context::Compared(other) => {
                spelled.value == number && common(other, literal) == common(other, spelled.ty)
            }
            Context::Case(control) => modulo(spelled.value, number, control.1),
        };
        if !same {
            return value;
        }
        let mut named = value;
        named.doc = spelled.doc;
        named.op = spelled.op;
        named.ty = CTy::Int {
            signed: spelled.ty.0,
            bits: spelled.ty.1,
        };
        named.class = if spelled.value < 0 {
            Class::Sign
        } else {
            Class::Zero
        };
        named
    }

    /// The constants `names` of `enumeration`, whose constants are macros
    /// ([`Enumeration::macros`]), each defined where no header has:
    /// `#ifndef O_RDWR`, `#define O_RDWR 2`, `#endif`; past `INT_MAX` in
    /// hexadecimal, an `unsigned int` ([`macro_literal`]).
    fn macro_definitions(&self, enumeration: &Enumeration, names: &BTreeSet<&str>) -> Vec<Doc> {
        let mut out = Vec::new();
        for (name, bits) in &enumeration.constants {
            if !names.contains(name.as_str()) {
                continue;
            }
            let hex = *bits > 0x7fff_ffff || *bits >= u128::from(self.style.hex_threshold);
            let macro_name = || Doc::name(TokenKind::Macro, name.clone(), false, None);
            out.push(Doc::Group(vec![
                Doc::keyword("#ifndef", None),
                Doc::Space,
                macro_name(),
            ]));
            out.push(Doc::Group(vec![
                Doc::keyword("#define", None),
                Doc::Space,
                macro_name(),
                Doc::Space,
                Doc::number(number(*bits, hex), None),
            ]));
            out.push(Doc::Group(vec![Doc::keyword("#endif", None)]));
        }
        out
    }

    /// The definitions of the enumerations whose constants `used` names
    /// (the tokens of the output), each with those constants only and
    /// its underlying type: `enum ACCESS_MASK : uint32_t { GENERIC_READ =
    /// 0x80000000 };`; without its tag where that is another name. Those
    /// whose tags `tags` names (the output declares a value with one) and
    /// none of whose constants it names are declared with their tag and
    /// underlying type alone (`enum ACCESS_MASK : uint32_t;`).
    pub(super) fn enum_definitions(
        &mut self,
        used: &BTreeSet<&str>,
        tags: &BTreeSet<&str>,
    ) -> Result<Vec<Doc>, PrintError> {
        let mut constants: BTreeMap<TypeId, BTreeSet<&str>> = BTreeMap::new();
        for (name, &ty) in &self.enum_constants {
            if let Some(&name) = used.get(name.as_str()) {
                constants.entry(ty).or_default().insert(name);
            }
        }
        for (&ty, tag) in &self.enum_tags {
            if tag.as_deref().is_some_and(|tag| tags.contains(tag)) {
                constants.entry(ty).or_default();
            }
        }
        let mut out = Vec::new();
        for (ty, names) in constants {
            let Some(enumeration) = self.enumeration(ty).cloned() else {
                continue;
            };
            if enumeration.macros {
                if !out.is_empty() {
                    out.push(Doc::Group(Vec::new()));
                }
                out.extend(self.macro_definitions(&enumeration, &names));
                continue;
            }
            let node = Some(Node::Type(ty));
            let mut line = vec![Doc::keyword("enum", node), Doc::Space];
            if let Some(tag) = self.enum_tag(ty) {
                line.extend([Doc::name(TokenKind::Type, tag, false, None), Doc::Space]);
            }
            line.extend([Doc::punct(":", None), Doc::Space]);
            line.extend(self.declare_c(
                CTy::Int {
                    signed: enumeration.signed,
                    bits: enumeration.width,
                },
                Vec::new(),
            )?);
            let mut members = Vec::new();
            for (name, bits) in &enumeration.constants {
                if !names.contains(name.as_str()) {
                    continue;
                }
                let value = enumeration.number(*bits);
                let mut member = vec![
                    Doc::name(TokenKind::Macro, name.clone(), false, node),
                    Doc::Space,
                    Doc::op("=", None),
                    Doc::Space,
                ];
                if value == i128::from(i64::MIN) {
                    member.push(Doc::macro_name("INT64_MIN", None));
                } else if value < 0 {
                    member.push(Doc::op("-", None));
                    member.push(Doc::number(number(value.unsigned_abs(), false), None));
                } else {
                    let hex = value.unsigned_abs() >= u128::from(self.style.hex_threshold);
                    member.push(Doc::number(number(value.unsigned_abs(), hex), None));
                }
                member.push(Doc::punct(",", None));
                members.push(Doc::Group(member));
            }
            if !members.is_empty() {
                line.push(Doc::Block {
                    kind: BlockKind::Aggregate,
                    braces: Braces::Required,
                    body: members,
                    node,
                });
            }
            line.push(Doc::punct(";", None));
            if !out.is_empty() {
                out.push(Doc::Group(Vec::new()));
            }
            out.push(Doc::Group(line));
        }
        Ok(out)
    }
}
