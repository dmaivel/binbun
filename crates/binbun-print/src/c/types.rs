//! L2 types as C types: spelling, declarators, struct definitions.

use alloc::collections::BTreeSet;
use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use binbun_ast::ir::Node;
use binbun_ast::types::{Aggregate, Enumeration, Type, TypeId};
use binbun_semantics::ir::Format;

use super::{PrintError, Printer, RESERVED, error, sanitize};
use crate::document::{BlockKind, Braces, Doc, Document, TokenKind};
use crate::style::IntSpelling;

/// The C type of an expression the printer builds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum CTy {
    /// An integer type: signedness and width (8, 16, 32, 64 or 128).
    Int {
        /// Whether it is signed.
        signed: bool,
        /// Its width.
        bits: u16,
    },
    /// `bool`.
    Bool,
    /// `float` or `double`.
    Float(Format),
    /// `char *` (`uint8_t *`): for arithmetic in bytes.
    Bytes,
    /// An L2 pointer type.
    Pointer(TypeId),
    /// An L2 code pointer type.
    Code(TypeId),
    /// An L2 struct, union, array or vector type.
    Other(TypeId),
    /// One of `binbun_defs.h`'s vector types ([`VectorTy`]).
    Vector(VectorTy),
}

impl CTy {
    /// Whether it is a data pointer.
    pub(super) const fn is_pointer(self) -> bool {
        matches!(self, Self::Pointer(_) | Self::Bytes)
    }
}

/// What a vector's lanes are.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum LaneKind {
    /// Unsigned integers (`u8x16`).
    Unsigned,
    /// Signed integers (`i8x16`).
    Signed,
    /// IEEE floats (`f32x4`).
    Float,
}

/// A vector type of `binbun_defs.h` (GCC's and Clang's vector extension, each
/// `aligned(1)`): `lanes` lanes of `bits` bits, lane 0 the lowest. Only
/// those `binbun_defs.h` defines exist ([`VectorTy::new`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct VectorTy {
    /// What the lanes are.
    pub kind: LaneKind,
    /// The width of a lane.
    pub bits: u16,
    /// How many lanes.
    pub lanes: u16,
}

impl VectorTy {
    /// The type of `lanes` lanes of `bits` bits, if `binbun_defs.h` has it:
    /// at least two lanes, of 8 to 128 bits (integers) or 32 or 64 (floats),
    /// 4, 8, 16, 32 or 64 bytes in all.
    pub(super) fn new(kind: LaneKind, bits: u16, lanes: u16) -> Option<Self> {
        let lane = match kind {
            LaneKind::Unsigned | LaneKind::Signed => matches!(bits, 8 | 16 | 32 | 64 | 128),
            LaneKind::Float => matches!(bits, 32 | 64),
        };
        let size = u32::from(bits) * u32::from(lanes);
        (lane && lanes >= 2 && matches!(size, 32 | 64 | 128 | 256 | 512)).then_some(Self {
            kind,
            bits,
            lanes,
        })
    }

    /// The vector of a value of `width` bits (256 or 512) with no lanes
    /// known: `u64x4`, `u64x8`.
    pub(super) fn bits(width: u16) -> Option<Self> {
        if width <= 128 || !width.is_multiple_of(64) {
            return None;
        }
        Self::new(LaneKind::Unsigned, 64, width / 64)
    }

    /// Its width in bits.
    pub(super) const fn width(self) -> u16 {
        self.bits * self.lanes
    }

    /// The same lanes as `kind`.
    pub(super) fn of(self, kind: LaneKind) -> Self {
        Self { kind, ..self }
    }

    /// Its name in `binbun_defs.h`: `u8x16`, `i32x8`, `f64x4`.
    pub(super) fn name(self) -> String {
        let kind = match self.kind {
            LaneKind::Unsigned => 'u',
            LaneKind::Signed => 'i',
            LaneKind::Float => 'f',
        };
        format!("{kind}{}x{}", self.bits, self.lanes)
    }
}

/// Whether `name` is one of `binbun_defs.h`'s vector types' names (`u8x16`).
pub(super) fn vector_name(name: &str) -> bool {
    let kind = match name.as_bytes().first() {
        Some(b'u') => LaneKind::Unsigned,
        Some(b'i') => LaneKind::Signed,
        Some(b'f') => LaneKind::Float,
        Some(_) | None => return false,
    };
    let Some((bits, lanes)) = name.get(1..).and_then(|rest| rest.split_once('x')) else {
        return false;
    };
    let number = |text: &str| {
        text.bytes()
            .all(|b| b.is_ascii_digit())
            .then(|| text.parse::<u16>().ok())
            .flatten()
    };
    match (number(bits), number(lanes)) {
        (Some(bits), Some(lanes)) => {
            VectorTy::new(kind, bits, lanes).is_some_and(|vector| vector.name() == name)
        }
        _ => false,
    }
}

/// The type of `a op b` for promoted integer types (C's usual arithmetic
/// conversions).
pub(super) fn common(a: (bool, u16), b: (bool, u16)) -> (bool, u16) {
    let ((a_signed, a_bits), (b_signed, b_bits)) = (a, b);
    if a_signed == b_signed {
        return (a_signed, a_bits.max(b_bits));
    }
    let (unsigned, signed) = if a_signed {
        (b_bits, a_bits)
    } else {
        (a_bits, b_bits)
    };
    if unsigned >= signed {
        (false, unsigned)
    } else {
        (true, signed)
    }
}

/// Whether C has an integer type of exactly `width` bits.
pub(super) const fn native(width: u16) -> bool {
    matches!(width, 8 | 16 | 32 | 64 | 128)
}

/// The narrowest C integer width that holds `width` bits.
pub(super) fn container(width: u16) -> Option<u16> {
    [8, 16, 32, 64, 128].into_iter().find(|&bits| bits >= width)
}

/// How a value of an integer L2 type is held in C.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct IntRep {
    /// Whether the C type is signed.
    pub signed: bool,
    /// The C type's width.
    pub bits: u16,
    /// The L2 width (at most `bits`; a narrower value is kept zero- or
    /// sign-extended as the type is signed).
    pub width: u16,
    /// Whether the C type is `bool`.
    pub boolean: bool,
}

/// `specifier` then `declarator` (if any), with a space between.
pub(super) fn with_specifier(mut specifier: Vec<Doc>, declarator: Vec<Doc>) -> Vec<Doc> {
    if !declarator.is_empty() {
        specifier.push(Doc::Space);
        specifier.extend(declarator);
    }
    specifier
}

fn parenthesized(inner: Vec<Doc>) -> Vec<Doc> {
    let mut out = vec![Doc::punct("(", None)];
    out.extend(inner);
    out.push(Doc::punct(")", None));
    out
}

/// A builtin type's token (C's, or a fixed-width integer typedef of
/// `<stdint.h>`, drawn as editors draw the builtins).
fn ty(text: impl Into<String>) -> Doc {
    Doc::token(TokenKind::BuiltinType, text, None)
}

/// A field's C name ([`field_names`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct FieldName {
    /// The name.
    pub text: String,
    /// Whether binbun made it up (`f_8`: the field has no name).
    pub automatic: bool,
}

impl FieldName {
    /// Its token, a member of the struct or union `of`: its node is `node`.
    pub(super) fn doc(self, node: Option<Node>) -> Doc {
        Doc::name(TokenKind::Field, self.text, self.automatic, node)
    }
}

impl Printer<'_> {
    /// An error for what the printer does not support, at `node` (or the
    /// node being printed).
    pub(super) fn unsupported(&self, node: Option<Node>, what: &str) -> PrintError {
        error(
            node.or(self.node),
            format!("not printable as C yet: {what}"),
        )
    }

    /// How a value of integer type `id` is held, if it is an integer
    /// type C can hold.
    pub(super) fn int_rep(&self, id: TypeId) -> Option<IntRep> {
        let (signed, width, boolean) = match *self.types.get(id)? {
            Type::Bool(width @ (1 | 8)) | Type::Bits(width @ 1) | Type::UInt(width @ 1) => {
                (false, width, true)
            }
            Type::Bits(width) => (matches!(width, 32 | 64), width, false),
            Type::Int(width) => (true, width, false),
            Type::Char { signed } => (signed, 8, false),
            Type::UInt(width) | Type::Bool(width) => (false, width, false),
            Type::Enum(Enumeration { width, signed, .. }) => (signed, width, false),
            Type::Float(_)
            | Type::Pointer(_)
            | Type::Code(_)
            | Type::Struct(_)
            | Type::Union(_)
            | Type::Array { .. }
            | Type::Vector { .. } => return None,
        };
        Some(IntRep {
            signed,
            bits: if boolean { 8 } else { container(width)? },
            width,
            boolean,
        })
    }

    /// The C type of a value of L2 type `id`.
    pub(super) fn cty(&self, id: TypeId) -> Result<CTy, PrintError> {
        let missing = || error(Some(Node::Type(id)), "no such type");
        Ok(match self.types.get(id).ok_or_else(missing)? {
            &(Type::Bits(width) | Type::Int(width) | Type::UInt(width))
                if let Some(vector) = VectorTy::bits(width) =>
            {
                CTy::Vector(vector)
            }
            Type::Bits(_)
            | Type::Int(_)
            | Type::UInt(_)
            | Type::Char { .. }
            | Type::Bool(_)
            | Type::Enum(_) => {
                let rep = self.int_rep(id).ok_or_else(|| {
                    self.unsupported(Some(Node::Type(id)), "integers over 128 bits")
                })?;
                if rep.boolean {
                    CTy::Bool
                } else {
                    CTy::Int {
                        signed: rep.signed,
                        bits: rep.bits,
                    }
                }
            }
            Type::Float(format) => CTy::Float(*format),
            Type::Pointer(_) => CTy::Pointer(id),
            Type::Code(_) => CTy::Code(id),
            &Type::Vector { lanes, element } => {
                let lane = match self.types.get(element) {
                    Some(&Type::Int(bits)) => Some((LaneKind::Signed, bits)),
                    Some(&(Type::Bits(bits) | Type::UInt(bits))) => {
                        Some((LaneKind::Unsigned, bits))
                    }
                    Some(&Type::Float(format)) => Some((LaneKind::Float, format.width())),
                    Some(_) | None => None,
                };
                let vector = lane
                    .and_then(|(kind, bits)| VectorTy::new(kind, bits, lanes))
                    .ok_or_else(|| self.unsupported(Some(Node::Type(id)), "vector types"))?;
                CTy::Vector(vector)
            }
            Type::Struct(_) | Type::Union(_) | Type::Array { .. } => CTy::Other(id),
        })
    }

    /// The name of an integer type: [`IntSpelling::Plain`]'s 64 bits as
    /// the image's `long` allows ([`Image::long_width`](super::Image::long_width)).
    pub(super) fn int_name(&self, signed: bool, bits: u16) -> &'static str {
        match (self.style.int_spelling, signed, bits) {
            (_, true, 128) => "__int128",
            (_, false, 128) => "unsigned __int128",
            // Never plain `char`: signed on x86, unsigned on Arm.
            (IntSpelling::Plain, true, 8) => "signed char",
            (IntSpelling::Plain, false, 8) => "unsigned char",
            (IntSpelling::Plain, true, 16) => "short",
            (IntSpelling::Plain, false, 16) => "unsigned short",
            (IntSpelling::Plain, true, 32) => "int",
            (IntSpelling::Plain, false, 32) => "unsigned int",
            (IntSpelling::Plain, signed, _) => match (self.image.long_width() == 64, signed) {
                (true, true) => "long",
                (true, false) => "unsigned long",
                (false, true) => "long long",
                (false, false) => "unsigned long long",
            },
            (IntSpelling::Fixed, true, 8) => "int8_t",
            (IntSpelling::Fixed, false, 8) => "uint8_t",
            (IntSpelling::Fixed, true, 16) => "int16_t",
            (IntSpelling::Fixed, false, 16) => "uint16_t",
            (IntSpelling::Fixed, true, 32) => "int32_t",
            (IntSpelling::Fixed, false, 32) => "uint32_t",
            (IntSpelling::Fixed, true, _) => "int64_t",
            (IntSpelling::Fixed, false, _) => "uint64_t",
        }
    }

    /// The suffix of a 64-bit literal, `signed` or not: `L`/`UL` where
    /// the image's `long` is 64 bits (LP64), `LL`/`ULL` where it is 32
    /// (LLP64, ILP32), so the literal is 64 bits under the image's own
    /// data model ([`Image::long_width`](super::Image::long_width)).
    pub(super) fn long_suffix(&self, signed: bool) -> &'static str {
        match (self.image.long_width() == 64, signed) {
            (true, true) => "L",
            (true, false) => "UL",
            (false, true) => "LL",
            (false, false) => "ULL",
        }
    }

    /// `ty` declaring `name` (empty: an abstract declarator, as in a
    /// cast).
    pub(super) fn declare(&mut self, id: TypeId, name: Vec<Doc>) -> Result<Vec<Doc>, PrintError> {
        let node = Some(Node::Type(id));
        let Some(ty) = self.types.get(id).cloned() else {
            return Err(error(node, "no such type"));
        };
        match ty {
            Type::Enum(_) if let Some(tag) = self.enum_tag(id) => Ok(with_specifier(
                vec![
                    Doc::keyword("enum", node),
                    Doc::Space,
                    Doc::name(TokenKind::Type, tag, false, None),
                ],
                name,
            )),
            Type::Bits(_)
            | Type::Int(_)
            | Type::UInt(_)
            | Type::Bool(_)
            | Type::Vector { .. }
            | Type::Enum(_) => {
                let cty = self.cty(id)?;
                self.declare_c(cty, name)
            }
            Type::Char { .. } => Ok(with_specifier(
                vec![Doc::token(TokenKind::BuiltinType, "char", None)],
                name,
            )),
            Type::Float(format) => Ok(with_specifier(vec![self.float_name(format, node)?], name)),
            Type::Pointer(None) => {
                let mut inner = vec![Doc::op("*", None)];
                inner.extend(name);
                Ok(with_specifier(vec![ty_void()], inner))
            }
            Type::Pointer(Some(target)) => {
                let mut inner = vec![Doc::op("*", None)];
                inner.extend(name);
                let wrap = match self.types.get(target) {
                    Some(Type::Array { .. }) => true,
                    // Named by its typedef where unaligned.
                    Some(Type::Code(_)) => !self.unaligned,
                    Some(_) | None => false,
                };
                self.declare_target(target, if wrap { parenthesized(inner) } else { inner })
            }
            Type::Code(signature) => {
                let mut inner = vec![Doc::op("*", None)];
                inner.extend(name);
                let mut inner = parenthesized(inner);
                inner.extend(self.parameters(&signature.parameters, signature.variadic)?);
                match signature.returns {
                    Some(returns) => self.declare(returns, inner),
                    None => Ok(with_specifier(vec![ty_void()], inner)),
                }
            }
            Type::Array { element, length } => {
                let mut inner = name;
                inner.push(Doc::punct("[", None));
                if let Some(length) = length {
                    inner.push(Doc::number(format!("{length}"), None));
                }
                inner.push(Doc::punct("]", None));
                self.declare(element, inner)
            }
            Type::Struct(_) | Type::Union(_) => {
                let specifier = self.aggregate_specifier(id)?;
                Ok(with_specifier(specifier, name))
            }
        }
    }

    /// `target`, the type a pointer points to, declaring `inner` (the
    /// `*` and what it declares). In the exact output
    /// ([`Printer::unaligned`](super::Printer)) it is a type of alignment
    /// 1: the program's accesses are the machine's, which ask no
    /// alignment, and a compiler given two `int32_t *` takes what they
    /// point to to overlap wholly or not at all (GCC then answers a load
    /// after two stores of one value without reading). A scalar is
    /// `binbun_defs.h`'s (`binbun_i32_u`), a pointer or an enumeration a
    /// typedef the output defines ([`Self::unaligned_typedef`]); structs
    /// and unions are packed ([`Self::members`]); bytes and vectors are
    /// of alignment 1 as they are.
    fn declare_target(&mut self, target: TypeId, inner: Vec<Doc>) -> Result<Vec<Doc>, PrintError> {
        if !self.unaligned {
            return self.declare(target, inner);
        }
        match self.types.get(target).cloned() {
            Some(Type::Array { element, length }) => {
                let mut inner = inner;
                inner.push(Doc::punct("[", None));
                if let Some(length) = length {
                    inner.push(Doc::number(format!("{length}"), None));
                }
                inner.push(Doc::punct("]", None));
                self.declare_target(element, inner)
            }
            Some(Type::Pointer(_) | Type::Code(_)) => {
                let name = self.unaligned_typedef(target)?;
                Ok(with_specifier(
                    vec![Doc::token(TokenKind::Type, name, None)],
                    inner,
                ))
            }
            Some(Type::Enum(_)) if self.enum_tag(target).is_some() => {
                let name = self.unaligned_typedef(target)?;
                Ok(with_specifier(
                    vec![Doc::token(TokenKind::Type, name, None)],
                    inner,
                ))
            }
            Some(
                Type::Bits(_)
                | Type::Int(_)
                | Type::UInt(_)
                | Type::Bool(_)
                | Type::Enum(_)
                | Type::Float(_),
            ) => {
                let cty = self.cty(target)?;
                self.declare_target_c(cty, inner)
            }
            Some(Type::Char { .. } | Type::Struct(_) | Type::Union(_) | Type::Vector { .. })
            | None => self.declare(target, inner),
        }
    }

    /// [`Self::declare_target`] for C type `cty`.
    fn declare_target_c(&mut self, cty: CTy, inner: Vec<Doc>) -> Result<Vec<Doc>, PrintError> {
        let scalar = match cty {
            CTy::Int { signed, bits } if self.unaligned => unaligned_int(signed, bits),
            CTy::Float(format) if self.unaligned => unaligned_float(format),
            CTy::Pointer(id) | CTy::Code(id) | CTy::Other(id) => {
                return self.declare_target(id, inner);
            }
            CTy::Int { .. } | CTy::Float(_) | CTy::Bool | CTy::Bytes | CTy::Vector(_) => None,
        };
        match scalar {
            Some(name) => Ok(with_specifier(
                vec![Doc::token(TokenKind::Type, name, None)],
                inner,
            )),
            None => self.declare_c(cty, inner),
        }
    }

    /// The name of the typedef of alignment 1 for the pointer or
    /// enumeration type `id`, made at its first use and named after the
    /// type's own spelling: `typedef struct node *struct_node_p_u
    /// __attribute__((aligned(1)));` for what a `struct node **` points
    /// to. (Clang takes a lower alignment from a typedef only, not from
    /// an attribute in a declarator.)
    fn unaligned_typedef(&mut self, id: TypeId) -> Result<String, PrintError> {
        if let Some((_, name, _)) = self.unaligned_types.iter().find(|(ty, ..)| *ty == id) {
            return Ok(name.clone());
        }
        self.unaligned = false;
        let natural = self.declare(id, Vec::new());
        self.unaligned = true;
        let mut base = String::new();
        let mut star = false;
        for doc in natural? {
            let Doc::Token(token) = doc else {
                continue;
            };
            if token.text == "*" {
                base.push_str(if star { "p" } else { "_p" });
                star = true;
                continue;
            }
            let word: String = token
                .text
                .chars()
                .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            if word.is_empty() {
                continue;
            }
            if !base.is_empty() {
                base.push('_');
            }
            base.push_str(&word);
            star = false;
        }
        base.push_str("_u");
        let name = self.names.fresh(&base);
        let mut line = vec![Doc::keyword("typedef", None), Doc::Space];
        line.extend(self.declare(id, vec![Doc::token(TokenKind::Type, name.clone(), None)])?);
        line.extend([
            Doc::Space,
            Doc::macro_name("__attribute__((aligned(1)))", None),
            Doc::punct(";", None),
        ]);
        self.unaligned_types.push((id, name.clone(), line));
        Ok(name)
    }

    /// The typedefs of alignment 1 that `sections` name, and those these
    /// name in turn, each after those it names.
    pub(super) fn unaligned_definitions(&self, sections: &[&Vec<Doc>]) -> Vec<Doc> {
        let texts = |docs: &[Doc]| -> Vec<String> {
            let document = Document {
                items: docs.to_vec(),
            };
            document
                .tokens()
                .iter()
                .filter(|token| token.kind == TokenKind::Type)
                .map(|token| token.text.clone())
                .collect()
        };
        let mut named: BTreeSet<String> = sections
            .iter()
            .flat_map(|section| texts(section.as_slice()))
            .collect();
        let mut kept = Vec::new();
        for (_, name, line) in self.unaligned_types.iter().rev() {
            if named.contains(name) {
                // Past its own name: what the definition names.
                named.extend(texts(line).into_iter().filter(|text| text != name));
                kept.push(Doc::Group(line.clone()));
            }
        }
        kept.reverse();
        kept
    }

    /// `ty` declaring `name`, an object the program cannot change where
    /// `constant`: `const int x`, `const char s[4]`, but `char *const p`
    /// and `int (*const f)(int)` where it (or its elements) is a pointer
    /// (in front, `const` would qualify what the pointer points to, or a
    /// function's return type).
    pub(super) fn declare_const(
        &mut self,
        id: TypeId,
        name: Vec<Doc>,
        constant: bool,
    ) -> Result<Vec<Doc>, PrintError> {
        if !constant {
            return self.declare(id, name);
        }
        let mut element = id;
        for _ in 0..=self.types.len() {
            match self.types.get(element) {
                Some(&Type::Array { element: inner, .. }) => element = inner,
                Some(_) | None => break,
            }
        }
        let keyword = [Doc::keyword("const", None), Doc::Space];
        if matches!(
            self.types.get(element),
            Some(Type::Pointer(_) | Type::Code(_))
        ) {
            let name = keyword.into_iter().chain(name).collect();
            return self.declare(id, name);
        }
        let mut out: Vec<Doc> = keyword.into();
        out.extend(self.declare(id, name)?);
        Ok(out)
    }

    /// A parameter list: `(int, long)`, `(void)`, `(int, ...)`, and `()`
    /// for variadic with no named parameter (C11 has no `(...)`: an
    /// unprototyped declaration takes any arguments).
    pub(super) fn parameters(
        &mut self,
        parameters: &[TypeId],
        variadic: bool,
    ) -> Result<Vec<Doc>, PrintError> {
        let mut out = vec![Doc::punct("(", None)];
        for (position, &parameter) in parameters.iter().enumerate() {
            if position > 0 {
                out.push(Doc::punct(",", None));
                out.push(Doc::Space);
            }
            out.extend(self.declare_parameter(parameter, Vec::new())?);
        }
        if variadic {
            if !parameters.is_empty() {
                out.push(Doc::punct(",", None));
                out.push(Doc::Space);
                out.push(Doc::punct("...", None));
            }
        } else if parameters.is_empty() {
            out.push(ty_void());
        }
        out.push(Doc::punct(")", None));
        Ok(out)
    }

    /// `ty` declaring parameter `name` (empty: abstract): a pointer to
    /// System V's `va_list` element ([`Self::is_va_tag`]) is `va_list`,
    /// which a parameter of that array type is adjusted to.
    pub(super) fn declare_parameter(
        &mut self,
        id: TypeId,
        name: Vec<Doc>,
    ) -> Result<Vec<Doc>, PrintError> {
        if let Some(&Type::Pointer(Some(target))) = self.types.get(id)
            && self.is_va_tag(target)
        {
            let va_list = Doc::token(TokenKind::Type, "va_list", None);
            return Ok(with_specifier(vec![va_list], name));
        }
        self.declare(id, name)
    }

    /// Whether `id` is System V x86-64's `struct __va_list_tag` (24 bytes),
    /// whose array of one is its `va_list`: the compiler's own type, which
    /// C cannot name (a struct declared with that tag is another type), so
    /// spelled `binbun_va_tag` (`binbun_defs.h` names the compiler's) and never
    /// defined.
    pub(super) fn is_va_tag(&self, id: TypeId) -> bool {
        matches!(
            self.types.get(id),
            Some(Type::Struct(aggregate))
                if aggregate.name.as_deref() == Some("__va_list_tag") && aggregate.size == 24
        )
    }

    fn float_name(&self, format: Format, node: Option<Node>) -> Result<Doc, PrintError> {
        match format {
            Format::Single => Ok(ty("float")),
            Format::Double => Ok(ty("double")),
            Format::Half => Ok(ty("_Float16")),
            Format::Extended => Err(self.unsupported(node, "the x87 extended format")),
        }
    }

    /// `cty` declaring `name`.
    pub(super) fn declare_c(&mut self, cty: CTy, name: Vec<Doc>) -> Result<Vec<Doc>, PrintError> {
        match cty {
            CTy::Int { signed, bits } => {
                Ok(with_specifier(vec![ty(self.int_name(signed, bits))], name))
            }
            CTy::Bool => Ok(with_specifier(vec![ty("bool")], name)),
            CTy::Float(format) => Ok(with_specifier(vec![self.float_name(format, None)?], name)),
            CTy::Bytes => {
                let byte = self.int_name(false, 8);
                let mut inner = vec![Doc::op("*", None)];
                inner.extend(name);
                Ok(with_specifier(vec![ty(byte)], inner))
            }
            CTy::Pointer(id) | CTy::Code(id) | CTy::Other(id) => self.declare(id, name),
            CTy::Vector(vector) => Ok(with_specifier(
                vec![Doc::token(TokenKind::Type, vector.name(), None)],
                name,
            )),
        }
    }

    /// A pointer to values of C type `cty`, as a type name: `int *`,
    /// `int (**)(int)`; `volatile` qualifies the pointee, the object the
    /// pointer reaches: `volatile int *`, but `void *volatile *` and
    /// `int (*volatile *)(int)` where that object is itself a pointer (a
    /// qualifier follows the `*` it applies to; in front it would qualify
    /// what that pointer points to, or a function's return type).
    pub(super) fn pointer_to(&mut self, cty: CTy, volatile: bool) -> Result<Vec<Doc>, PrintError> {
        let pointer = vec![Doc::op("*", None)];
        if self.unaligned {
            // A pointer pointed to is named by its typedef, which a
            // qualifier in front qualifies.
            let array = matches!(
                cty,
                CTy::Other(id) if matches!(self.types.get(id), Some(Type::Array { .. }))
            );
            let inner = if array {
                parenthesized(pointer)
            } else {
                pointer
            };
            let mut spelled = self.declare_target_c(cty, inner)?;
            if volatile {
                spelled.splice(0..0, [Doc::keyword("volatile", None), Doc::Space]);
            }
            return Ok(spelled);
        }
        let mut spelled = match cty {
            CTy::Pointer(id) | CTy::Code(id)
                if volatile
                    && matches!(self.types.get(id), Some(Type::Pointer(_) | Type::Code(_))) =>
            {
                let qualified = vec![
                    Doc::keyword("volatile", None),
                    Doc::Space,
                    Doc::op("*", None),
                ];
                return self.declare(id, qualified);
            }
            CTy::Pointer(id) | CTy::Code(id) | CTy::Other(id) => {
                let wrap = matches!(self.types.get(id), Some(Type::Array { .. } | Type::Code(_)));
                let inner = if wrap {
                    parenthesized(pointer)
                } else {
                    pointer
                };
                self.declare(id, inner)?
            }
            CTy::Int { .. } | CTy::Bool | CTy::Float(_) | CTy::Bytes | CTy::Vector(_) => {
                self.declare_c(cty, pointer)?
            }
        };
        if volatile {
            spelled.splice(0..0, [Doc::keyword("volatile", None), Doc::Space]);
        }
        Ok(spelled)
    }

    /// The text of C type `cty`, for comparing types.
    pub(super) fn key(&mut self, cty: CTy) -> Result<String, PrintError> {
        let tokens = self.declare_c(cty, Vec::new())?;
        let mut out = String::new();
        for doc in tokens {
            if let Doc::Token(token) = doc {
                out.push_str(&token.text);
                out.push(' ');
            }
        }
        Ok(out)
    }

    /// The C type the pointer type `pointer` points to, and its size in
    /// bytes (if it has one, for scaling).
    pub(super) fn pointee(&self, pointer: CTy) -> Option<(Option<TypeId>, Option<u64>)> {
        match pointer {
            CTy::Bytes => Some((None, Some(1))),
            CTy::Pointer(id) => match self.types.get(id)? {
                Type::Pointer(Some(target)) => {
                    let size = self
                        .types
                        .width(*target)
                        .filter(|width| *width > 0 && width % 8 == 0)
                        .map(|width| width / 8);
                    Some((Some(*target), size))
                }
                Type::Pointer(None) => Some((None, None)),
                Type::Bits(_)
                | Type::Int(_)
                | Type::UInt(_)
                | Type::Char { .. }
                | Type::Bool(_)
                | Type::Float(_)
                | Type::Code(_)
                | Type::Struct(_)
                | Type::Union(_)
                | Type::Array { .. }
                | Type::Vector { .. }
                | Type::Enum(_) => None,
            },
            CTy::Int { .. }
            | CTy::Bool
            | CTy::Float(_)
            | CTy::Code(_)
            | CTy::Other(_)
            | CTy::Vector(_) => None,
        }
    }

    /// The L2 type of a pointer to `target`.
    pub(super) fn pointer_type(&mut self, target: TypeId) -> TypeId {
        self.types.intern(Type::Pointer(Some(target)))
    }

    /// `struct name` or `union name`, recording that it is used; a frame
    /// struct's name is `frame_<function>`; System V's `va_list` element
    /// is `binbun_va_tag` ([`Self::is_va_tag`]), not recorded.
    pub(super) fn aggregate_specifier(&mut self, id: TypeId) -> Result<Vec<Doc>, PrintError> {
        if self.is_va_tag(id) {
            return Ok(vec![Doc::token(
                TokenKind::Type,
                "binbun_va_tag",
                Some(Node::Type(id)),
            )]);
        }
        let (keyword, aggregate_name, prefix) = match self.types.get(id) {
            Some(Type::Struct(aggregate)) => ("struct", aggregate.name.clone(), "s"),
            Some(Type::Union(aggregate)) => ("union", aggregate.name.clone(), "u"),
            Some(_) | None => return Err(error(Some(Node::Type(id)), "not a struct or union")),
        };
        self.structs.insert(id);
        // Automatic unless the type has its own name (a frame's is made
        // up too, and so is type synthesis's).
        let automatic = self.frame_types.contains(&id)
            || aggregate_name.as_deref().is_none_or(synthesised_struct);
        let name = if let Some(name) = self.struct_names.get(&id) {
            name.clone()
        } else {
            let base = if self.frame_types.contains(&id) {
                format!("frame_{}", self.function_name)
            } else {
                aggregate_name.unwrap_or_else(|| format!("{prefix}_{}", id.0))
            };
            let name = self.names.fresh(&base);
            self.struct_names.insert(id, name.clone());
            name
        };
        Ok(vec![
            Doc::keyword(keyword, Some(Node::Type(id))),
            Doc::Space,
            Doc::name(TokenKind::Type, name, automatic, None),
        ])
    }

    /// Forward declarations and definitions of the structs and unions
    /// used (and those they use), each after those it holds by value; not
    /// the `va_list`'s element, the compiler's ([`Self::is_va_tag`]).
    pub(super) fn struct_definitions(&mut self) -> Result<Vec<Doc>, PrintError> {
        let mut done = BTreeSet::new();
        let mut order = Vec::new();
        let mut definitions = Vec::new();
        while let Some(&next) = self.structs.iter().find(|id| !done.contains(*id)) {
            self.define(next, &mut done, &mut order, &mut definitions, 0)?;
        }
        let mut out = Vec::new();
        for &id in &order {
            let mut line = self.aggregate_specifier(id)?;
            line.push(Doc::punct(";", None));
            out.push(Doc::Group(line));
        }
        out.extend(definitions);
        Ok(out)
    }

    fn define(
        &mut self,
        id: TypeId,
        done: &mut BTreeSet<TypeId>,
        order: &mut Vec<TypeId>,
        definitions: &mut Vec<Doc>,
        depth: usize,
    ) -> Result<(), PrintError> {
        if !done.insert(id) {
            return Ok(());
        }
        if depth > self.types.len() {
            return Err(error(Some(Node::Type(id)), "a struct holds itself"));
        }
        order.push(id);
        let (union, aggregate) = match self.types.get(id).cloned() {
            Some(Type::Struct(aggregate)) => (false, aggregate),
            Some(Type::Union(aggregate)) => (true, aggregate),
            Some(_) | None => return Err(error(Some(Node::Type(id)), "not a struct or union")),
        };
        // What it holds by value first.
        for field in &aggregate.fields {
            let mut inner = field.ty;
            while let Some(Type::Array { element, .. }) = self.types.get(inner) {
                inner = *element;
            }
            if matches!(
                self.types.get(inner),
                Some(Type::Struct(_) | Type::Union(_))
            ) && !self.is_va_tag(inner)
            {
                self.aggregate_specifier(inner)?;
                self.define(inner, done, order, definitions, depth + 1)?;
            }
        }
        let (members, packed) = self.members(id, &aggregate, union)?;
        let mut line = self.aggregate_specifier(id)?;
        line.push(Doc::Block {
            kind: BlockKind::Aggregate,
            braces: Braces::Required,
            body: members,
            node: Some(Node::Type(id)),
        });
        if packed {
            line.push(Doc::Space);
            line.push(Doc::macro_name("__attribute__((packed))", None));
        }
        line.push(Doc::punct(";", None));
        definitions.push(Doc::Group(Vec::new()));
        definitions.push(Doc::Group(line));
        Ok(())
    }

    /// The members of a struct or union, with byte arrays for padding, and
    /// whether it must be packed to have its layout (a frame struct only
    /// where a field is misaligned: its size is the frame's bytes, and C's
    /// tail padding past them is no byte the program uses).
    fn members(
        &mut self,
        id: TypeId,
        aggregate: &Aggregate,
        union: bool,
    ) -> Result<(Vec<Doc>, bool), PrintError> {
        let node = Some(Node::Type(id));
        let mut members = Vec::new();
        let mut at = 0u64;
        let mut packed = false;
        let mut align = 1u64;
        for (offset, ty, name) in field_names(aggregate) {
            let size = self
                .types
                .width(ty)
                .map(|width| width.div_ceil(8))
                .ok_or_else(|| self.unsupported(node, "a field without a size"))?;
            if !union && offset < at {
                return Err(self.unsupported(node, "overlapping struct fields"));
            }
            if !union && offset > at {
                members.push(self.padding(at, offset - at));
            }
            let field_align = self.alignment(ty);
            align = align.max(field_align);
            packed |= offset % field_align != 0;
            let mut line = self.declare(ty, vec![name.doc(node)])?;
            line.push(Doc::punct(";", None));
            members.push(Doc::Group(line));
            at = if union { at.max(size) } else { offset + size };
        }
        let frame = self.frame_types.contains(&id);
        packed |= !frame && !aggregate.size.is_multiple_of(align);
        // Reached through pointers, of which no alignment is known.
        packed |= !frame && self.unaligned;
        // Trailing bytes shorter than the alignment, in a struct of a
        // multiple of it, are the padding C adds itself: not spelled out.
        let natural_tail = !union && !packed && (frame || aggregate.size - at < align);
        if aggregate.size > at && !natural_tail {
            members.push(self.padding(if union { 0 } else { at }, aggregate.size - at));
        }
        Ok((members, packed))
    }

    fn padding(&self, offset: u64, bytes: u64) -> Doc {
        let byte = self.int_name(false, 8);
        Doc::Group(vec![
            ty(byte),
            Doc::Space,
            Doc::name(TokenKind::Field, format!("pad_{offset:x}"), true, None),
            Doc::punct("[", None),
            Doc::number(format!("{bytes}"), None),
            Doc::punct("]", None),
            Doc::punct(";", None),
        ])
    }

    /// Whether `&s.f` may be written for a field of type `field` of the
    /// struct `aggregate`: in a packed struct the field may lie where its
    /// type cannot, and C warns on its address becoming a pointer to that
    /// type; not on its becoming one to a type of alignment 1, which the
    /// exact output's all are ([`Self::declare_target`]).
    pub(super) fn field_addressable(&self, field: TypeId, aggregate: TypeId) -> bool {
        self.unaligned || self.alignment(field) <= self.alignment(aggregate)
    }

    /// The natural alignment of type `id` in bytes (1 for a packed
    /// struct; a frame struct is packed only for a misaligned field).
    pub(super) fn alignment(&self, id: TypeId) -> u64 {
        self.alignment_within(id, self.types.len())
    }

    fn alignment_within(&self, id: TypeId, depth: usize) -> u64 {
        let Some(depth) = depth.checked_sub(1) else {
            return 1;
        };
        match self.types.get(id) {
            Some(
                Type::Bits(_)
                | Type::Int(_)
                | Type::UInt(_)
                | Type::Char { .. }
                | Type::Bool(_)
                | Type::Enum(_),
            ) => self.int_rep(id).map_or(1, |rep| u64::from(rep.bits / 8)),
            Some(Type::Float(format)) => u64::from(format.width() / 8),
            Some(Type::Pointer(_) | Type::Code(_)) => u64::from(self.pointer_width() / 8),
            Some(Type::Array { element, .. }) => self.alignment_within(*element, depth),
            Some(Type::Struct(aggregate) | Type::Union(aggregate)) => {
                let align = aggregate
                    .fields
                    .iter()
                    .map(|field| self.alignment_within(field.ty, depth))
                    .max()
                    .unwrap_or(1);
                let natural = (self.frame_types.contains(&id) || aggregate.size % align == 0)
                    && aggregate
                        .fields
                        .iter()
                        .all(|field| field.offset % self.alignment_within(field.ty, depth) == 0);
                let unaligned = self.unaligned && !self.frame_types.contains(&id);
                if natural && !unaligned { align } else { 1 }
            }
            Some(Type::Vector { .. }) | None => 1,
        }
    }
}

fn ty_void() -> Doc {
    ty("void")
}

/// `binbun_defs.h`'s integer type of `bits` bits and alignment 1, where the
/// plain one's is more.
fn unaligned_int(signed: bool, bits: u16) -> Option<&'static str> {
    Some(match (signed, bits) {
        (true, 16) => "binbun_i16_u",
        (false, 16) => "binbun_u16_u",
        (true, 32) => "binbun_i32_u",
        (false, 32) => "binbun_u32_u",
        (true, 64) => "binbun_i64_u",
        (false, 64) => "binbun_u64_u",
        (true, 128) => "binbun_i128_u",
        (false, 128) => "binbun_u128_u",
        _ => return None,
    })
}

/// `binbun_defs.h`'s floating-point type of `format` and alignment 1.
fn unaligned_float(format: Format) -> Option<&'static str> {
    match format {
        Format::Half => Some("binbun_f16_u"),
        Format::Single => Some("binbun_f32_u"),
        Format::Double => Some("binbun_f64_u"),
        Format::Extended => None,
    }
}

/// The fields of an aggregate by offset (a stable order), with their C
/// names: sanitized, never a keyword or a padding member's name, unique.
pub(super) fn field_names(aggregate: &Aggregate) -> Vec<(u64, TypeId, FieldName)> {
    let mut fields: Vec<_> = aggregate.fields.iter().collect();
    fields.sort_by_key(|field| field.offset);
    let mut names = BTreeSet::new();
    let mut out = Vec::with_capacity(fields.len());
    for field in fields {
        let automatic = field
            .name
            .as_deref()
            .is_none_or(|name| synthesised_field(name, field.offset));
        let mut name = field
            .name
            .clone()
            .unwrap_or_else(|| format!("f_{:x}", field.offset));
        name = sanitize(&name);
        if RESERVED.contains(&name.as_str()) || name.starts_with("pad_") {
            name.push('_');
        }
        while !names.insert(name.clone()) {
            name.push('_');
        }
        out.push((
            field.offset,
            field.ty,
            FieldName {
                text: name,
                automatic,
            },
        ));
    }
    out
}

// L2's types keep a struct's and a field's name, not who gave it: the
// names type synthesis makes up (binbun-decompile's `typing::structs`
// and lowering's frame gaps) are known by their spelling.

/// Whether `name` is the name type synthesis gives a struct it lays out:
/// `struct_<function>_<k>`.
fn synthesised_struct(name: &str) -> bool {
    name.strip_prefix("struct_")
        .and_then(|rest| rest.rsplit_once('_'))
        .is_some_and(|(function, k)| {
            !function.is_empty() && !k.is_empty() && k.bytes().all(|b| b.is_ascii_digit())
        })
}

/// Whether `name` is the name type synthesis gives the field at `offset`
/// of a struct it lays out (`field_<offset>`, hexadecimal) or the bytes
/// between two fields (`unknown_<offset>`).
fn synthesised_field(name: &str, offset: u64) -> bool {
    name.starts_with("unknown_")
        || name
            .strip_prefix("field_")
            .and_then(|hex| u64::from_str_radix(hex, 16).ok())
            == Some(offset)
}
