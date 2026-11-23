//! The parser: one function per production, numbering substitution
//! candidates as the ABI does (§5.1.8): every prefix of a name before its
//! last component (a scope, a template's name before its arguments), an
//! unscoped template's name, and every type but a builtin one or one
//! itself written as a substitution.

use alloc::string::String;
use alloc::vec::Vec;

use super::{
    Abbreviation, Builtin, Component, CvQualifiers, Encoding, Error, FunctionType, Name, NameKind,
    Prefix, PrefixId, RefQualifier, Special, Substitutable, Symbol, TemplateArg, Type, TypeId,
    UnqualifiedName,
};

/// The operator names (`<operator-name>`) parsed, with their C++
/// spelling.
const OPERATORS: [(&[u8; 2], &str); 49] = [
    (b"nw", " new"),
    (b"na", " new[]"),
    (b"dl", " delete"),
    (b"da", " delete[]"),
    (b"aw", " co_await"),
    (b"ps", "+"),
    (b"ng", "-"),
    (b"ad", "&"),
    (b"de", "*"),
    (b"co", "~"),
    (b"pl", "+"),
    (b"mi", "-"),
    (b"ml", "*"),
    (b"dv", "/"),
    (b"rm", "%"),
    (b"an", "&"),
    (b"or", "|"),
    (b"eo", "^"),
    (b"aS", "="),
    (b"pL", "+="),
    (b"mI", "-="),
    (b"mL", "*="),
    (b"dV", "/="),
    (b"rM", "%="),
    (b"aN", "&="),
    (b"oR", "|="),
    (b"eO", "^="),
    (b"ls", "<<"),
    (b"rs", ">>"),
    (b"lS", "<<="),
    (b"rS", ">>="),
    (b"eq", "=="),
    (b"ne", "!="),
    (b"lt", "<"),
    (b"gt", ">"),
    (b"le", "<="),
    (b"ge", ">="),
    (b"ss", "<=>"),
    (b"nt", "!"),
    (b"aa", "&&"),
    (b"oo", "||"),
    (b"pp", "++"),
    (b"mm", "--"),
    (b"cm", ","),
    (b"pm", "->*"),
    (b"pt", "->"),
    (b"cl", "()"),
    (b"ix", "[]"),
    (b"qu", "?"),
];

/// Parses `mangled`, a whole `_Z…` symbol.
///
/// # Errors
///
/// If it is not an Itanium mangling, or uses a production not parsed yet
/// (the error names it).
pub fn parse(mangled: &str) -> Result<Symbol, Error> {
    let mut parser = Parser {
        input: mangled.as_bytes(),
        position: 0,
        prefixes: Vec::new(),
        types: Vec::new(),
        substitutions: Vec::new(),
    };
    if !parser.eat(b"_Z") {
        return Err(parser.error("<mangled-name>"));
    }
    let encoding = parser.encoding()?;
    let suffix = match parser.peek() {
        None => None,
        Some(b'.') => {
            let rest = mangled.get(parser.position + 1..).unwrap_or_default();
            Some(String::from(rest))
        }
        Some(_) => return Err(parser.error("<encoding> (trailing input)")),
    };
    Ok(Symbol {
        encoding,
        suffix,
        prefixes: parser.prefixes,
        types: parser.types,
        substitutions: parser.substitutions,
    })
}

/// The parse state: the input, where it is, and the tree's tables.
struct Parser<'a> {
    input: &'a [u8],
    position: usize,
    prefixes: Vec<Prefix>,
    types: Vec<Type>,
    substitutions: Vec<Substitutable>,
}

impl Parser<'_> {
    fn error(&self, production: &'static str) -> Error {
        Error {
            production,
            offset: self.position,
        }
    }

    fn peek(&self) -> Option<u8> {
        self.input.get(self.position).copied()
    }

    fn peek_at(&self, ahead: usize) -> Option<u8> {
        self.input.get(self.position + ahead).copied()
    }

    /// Consumes `bytes` if the input continues with them.
    fn eat(&mut self, bytes: &[u8]) -> bool {
        let found = self
            .input
            .get(self.position..)
            .is_some_and(|rest| rest.starts_with(bytes));
        if found {
            self.position += bytes.len();
        }
        found
    }

    /// Whether the encoding's parameters end here: the input's end or a
    /// vendor suffix.
    fn at_end(&self) -> bool {
        matches!(self.peek(), None | Some(b'.'))
    }

    fn push_prefix(&mut self, parent: Option<PrefixId>, component: Component) -> PrefixId {
        let id = PrefixId(u32::try_from(self.prefixes.len()).unwrap_or(u32::MAX));
        self.prefixes.push(Prefix { parent, component });
        id
    }

    fn push_type(&mut self, ty: Type) -> TypeId {
        let id = TypeId(u32::try_from(self.types.len()).unwrap_or(u32::MAX));
        self.types.push(ty);
        id
    }

    /// Pushes `ty` and makes it a substitution candidate.
    fn candidate(&mut self, ty: Type) -> TypeId {
        let id = self.push_type(ty);
        self.substitutions.push(Substitutable::Type(id));
        id
    }

    /// `<encoding> ::= <name> <bare-function-type> | <name> |
    /// <special-name>`.
    fn encoding(&mut self) -> Result<Encoding, Error> {
        if matches!(self.peek(), Some(b'T' | b'G')) {
            return self.special_name();
        }
        let name = self.name()?;
        if self.at_end() {
            return Ok(Encoding::Data(name));
        }
        let template = matches!(
            self.prefixes
                .get(name.path.0 as usize)
                .map(|node| &node.component),
            Some(Component::Arguments(_))
        );
        let structor = matches!(
            self.last_name(name.path),
            Some(NameKind::Constructor(_) | NameKind::Destructor(_))
        );
        let returns = if template && !structor {
            Some(self.ty()?)
        } else {
            None
        };
        let mut parameters = Vec::new();
        while !self.at_end() {
            parameters.push(self.ty()?);
        }
        let function = self.bare_function_type(returns, parameters)?;
        Ok(Encoding::Function(name, function))
    }

    /// `<special-name> ::= TV <type> | TT <type> | TI <type> | TS <type>`
    /// (the others are refused).
    fn special_name(&mut self) -> Result<Encoding, Error> {
        let make: fn(TypeId) -> Special = match (self.peek(), self.peek_at(1)) {
            (Some(b'T'), Some(b'V')) => Special::VirtualTable,
            (Some(b'T'), Some(b'T')) => Special::Vtt,
            (Some(b'T'), Some(b'I')) => Special::TypeInfo,
            (Some(b'T'), Some(b'S')) => Special::TypeInfoName,
            _ => return Err(self.error("<special-name>")),
        };
        self.position += 2;
        let ty = self.ty()?;
        if !self.at_end() {
            return Err(self.error("<special-name> (trailing input)"));
        }
        Ok(Encoding::Special(make(ty)))
    }

    /// A `<bare-function-type>` of these types: a lone `void` is no
    /// parameter.
    fn bare_function_type(
        &self,
        returns: Option<TypeId>,
        mut parameters: Vec<TypeId>,
    ) -> Result<FunctionType, Error> {
        if parameters.is_empty() {
            return Err(self.error("<bare-function-type>"));
        }
        if let [only] = parameters.as_slice()
            && self.types.get(only.0 as usize) == Some(&Type::Builtin(Builtin::Void))
        {
            parameters.clear();
        }
        Ok(FunctionType {
            returns,
            parameters,
        })
    }

    /// The kind of the last unqualified name of the chain ending at
    /// `path` (the template's, for a template).
    fn last_name(&self, path: PrefixId) -> Option<&NameKind> {
        let mut node = self.prefixes.get(path.0 as usize)?;
        loop {
            match &node.component {
                Component::Name(name) => return Some(&name.kind),
                Component::Arguments(_) => node = self.prefixes.get(node.parent?.0 as usize)?,
                Component::Std | Component::Abbreviation(_) => return None,
            }
        }
    }

    /// `<name>`: a nested name, an unscoped name or an unscoped template
    /// with its arguments. Its last node is no substitution candidate:
    /// a type's caller makes the type one.
    fn name(&mut self) -> Result<Name, Error> {
        let path = match self.peek() {
            Some(b'N') => return self.nested_name(),
            Some(b'Z') => return Err(self.error("<local-name>")),
            Some(b'S') if self.peek_at(1) == Some(b't') => {
                self.position += 2;
                let std = self.push_prefix(None, Component::Std);
                let name = self.unqualified_name()?;
                let node = self.push_prefix(Some(std), Component::Name(name));
                self.maybe_template(node)?
            }
            Some(b'S') => {
                let template = self.substitution_prefix()?;
                if self.peek() != Some(b'I') {
                    return Err(self.error("<unscoped-template-name>"));
                }
                self.template_args_of(template)?
            }
            _ => {
                let name = self.unqualified_name()?;
                let node = self.push_prefix(None, Component::Name(name));
                self.maybe_template(node)?
            }
        };
        Ok(Name {
            path,
            nested: false,
            cv: CvQualifiers::default(),
            reference: None,
        })
    }

    /// `<unscoped-template-name> <template-args>` if arguments follow
    /// unscoped name `node` (the name is then a candidate), else `node`.
    fn maybe_template(&mut self, node: PrefixId) -> Result<PrefixId, Error> {
        if self.peek() != Some(b'I') {
            return Ok(node);
        }
        self.substitutions.push(Substitutable::Prefix(node));
        self.template_args_of(node)
    }

    /// `<template-args>` of template `template`: the node they make.
    fn template_args_of(&mut self, template: PrefixId) -> Result<PrefixId, Error> {
        let arguments = self.template_args()?;
        Ok(self.push_prefix(Some(template), Component::Arguments(arguments)))
    }

    /// `<nested-name> ::= N [<CV-qualifiers>] [<ref-qualifier>] <prefix>
    /// <unqualified-name> E | N [<CV-qualifiers>] [<ref-qualifier>]
    /// <template-prefix> <template-args> E`.
    fn nested_name(&mut self) -> Result<Name, Error> {
        self.position += 1;
        let cv = self.cv_qualifiers();
        let reference = if self.eat(b"R") {
            Some(RefQualifier::Lvalue)
        } else if self.eat(b"O") {
            Some(RefQualifier::Rvalue)
        } else {
            None
        };
        // The chain so far, and whether its last node is new (a
        // substitution's or `std` is not a candidate again).
        let mut current: Option<PrefixId> = None;
        let mut fresh = false;
        loop {
            match (self.peek(), self.peek_at(1)) {
                (Some(b'E'), _) => {
                    self.position += 1;
                    break;
                }
                (Some(b'S'), Some(b't')) if current.is_none() => {
                    self.position += 2;
                    current = Some(self.push_prefix(None, Component::Std));
                    fresh = false;
                }
                (Some(b'S'), _) if current.is_none() => {
                    current = Some(self.substitution_prefix()?);
                    fresh = false;
                }
                (Some(b'I'), _) => {
                    let Some(template) = current else {
                        return Err(self.error("<template-prefix>"));
                    };
                    if fresh {
                        self.substitutions.push(Substitutable::Prefix(template));
                    }
                    current = Some(self.template_args_of(template)?);
                    fresh = true;
                }
                (Some(b'T'), _) => return Err(self.error("<template-param> (prefix)")),
                (Some(b'D'), Some(b't' | b'T')) => return Err(self.error("<decltype>")),
                (Some(b'M'), _) => return Err(self.error("<data-member-prefix>")),
                (Some(_), _) => {
                    let name = self.unqualified_name()?;
                    if let Some(scope) = current
                        && fresh
                    {
                        self.substitutions.push(Substitutable::Prefix(scope));
                    }
                    current = Some(self.push_prefix(current, Component::Name(name)));
                    fresh = true;
                }
                (None, _) => return Err(self.error("<nested-name> (no E)")),
            }
        }
        let path = current.ok_or_else(|| self.error("<nested-name> (empty)"))?;
        Ok(Name {
            path,
            nested: true,
            cv,
            reference,
        })
    }

    /// `<CV-qualifiers> ::= [r] [V] [K]`.
    fn cv_qualifiers(&mut self) -> CvQualifiers {
        CvQualifiers {
            restrict: self.eat(b"r"),
            volatile: self.eat(b"V"),
            constant: self.eat(b"K"),
        }
    }

    /// `<unqualified-name>` with its ABI tags.
    fn unqualified_name(&mut self) -> Result<UnqualifiedName, Error> {
        let kind = match (self.peek(), self.peek_at(1)) {
            (Some(b'0'..=b'9'), _) => NameKind::Source(self.source_name()?),
            (Some(b'L'), Some(b'0'..=b'9')) => {
                self.position += 1;
                NameKind::Source(self.source_name()?)
            }
            (Some(b'C'), Some(kind @ b'1'..=b'5')) => {
                self.position += 2;
                NameKind::Constructor(kind - b'0')
            }
            (Some(b'D'), Some(kind @ b'0'..=b'5')) => {
                self.position += 2;
                NameKind::Destructor(kind - b'0')
            }
            (Some(b'C'), _) => return Err(self.error("<ctor-dtor-name> (inheriting)")),
            (Some(b'U'), _) => return Err(self.error("<unnamed-type-name>")),
            (Some(b'D'), Some(b'C')) => return Err(self.error("<unqualified-name> (DC)")),
            (Some(b'c'), Some(b'v')) => return Err(self.error("<operator-name> (cv)")),
            (Some(b'l'), Some(b'i')) => return Err(self.error("<operator-name> (li)")),
            (Some(first @ b'a'..=b'z'), Some(second)) => {
                let spelling = OPERATORS
                    .iter()
                    .find(|(code, _)| **code == [first, second])
                    .map(|&(_, spelling)| spelling)
                    .ok_or_else(|| self.error("<operator-name>"))?;
                self.position += 2;
                NameKind::Operator(spelling)
            }
            _ => return Err(self.error("<unqualified-name>")),
        };
        let mut abi_tags = Vec::new();
        while self.eat(b"B") {
            abi_tags.push(self.source_name()?);
        }
        Ok(UnqualifiedName { kind, abi_tags })
    }

    /// A decimal number.
    fn number(&mut self) -> Option<usize> {
        let start = self.position;
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.position += 1;
        }
        let digits = self.input.get(start..self.position)?;
        if digits.is_empty() {
            return None;
        }
        digits.iter().try_fold(0usize, |value, &digit| {
            value
                .checked_mul(10)?
                .checked_add(usize::from(digit - b'0'))
        })
    }

    /// `<source-name> ::= <positive length number> <identifier>`.
    fn source_name(&mut self) -> Result<String, Error> {
        let length = self
            .number()
            .filter(|&length| length > 0)
            .ok_or_else(|| self.error("<source-name>"))?;
        let end = self
            .position
            .checked_add(length)
            .ok_or_else(|| self.error("<source-name>"))?;
        let bytes = self
            .input
            .get(self.position..end)
            .ok_or_else(|| self.error("<source-name> (too long)"))?;
        let identifier =
            core::str::from_utf8(bytes).map_err(|_| self.error("<identifier> (not UTF-8)"))?;
        self.position = end;
        Ok(String::from(identifier))
    }

    /// `<seq-id>` and `_`: the index `S…_`/`T…_` refer to (`_` is 0).
    fn sequence(&mut self, production: &'static str) -> Result<usize, Error> {
        let mut value: Option<usize> = None;
        loop {
            let digit = match self.peek() {
                Some(b'_') => {
                    self.position += 1;
                    return value
                        .map_or(Some(0), |value| value.checked_add(1))
                        .ok_or_else(|| self.error(production));
                }
                Some(digit @ b'0'..=b'9') => digit - b'0',
                Some(digit @ b'A'..=b'Z') => digit - b'A' + 10,
                _ => return Err(self.error(production)),
            };
            self.position += 1;
            value = value
                .unwrap_or(0)
                .checked_mul(36)
                .and_then(|value| value.checked_add(usize::from(digit)));
            if value.is_none() {
                return Err(self.error(production));
            }
        }
    }

    /// `<substitution>` (not `St`): an abbreviation or an entry of the
    /// table.
    fn substitution(&mut self) -> Result<Substitutable, Error> {
        self.position += 1;
        let abbreviation = match self.peek() {
            Some(b'a') => Abbreviation::Allocator,
            Some(b'b') => Abbreviation::BasicString,
            Some(b's') => Abbreviation::String,
            Some(b'i') => Abbreviation::Istream,
            Some(b'o') => Abbreviation::Ostream,
            Some(b'd') => Abbreviation::Iostream,
            _ => {
                let index = self.sequence("<substitution>")?;
                return self
                    .substitutions
                    .get(index)
                    .copied()
                    .ok_or_else(|| self.error("<substitution> (out of range)"));
            }
        };
        self.position += 1;
        Ok(Substitutable::Prefix(
            self.push_prefix(None, Component::Abbreviation(abbreviation)),
        ))
    }

    /// A `<substitution>` standing for a name node.
    fn substitution_prefix(&mut self) -> Result<PrefixId, Error> {
        match self.substitution()? {
            Substitutable::Prefix(prefix) => Ok(prefix),
            Substitutable::Type(ty) => match self.types.get(ty.0 as usize) {
                Some(&Type::Named { path, .. }) => Ok(path),
                _ => Err(self.error("<substitution> (a type, not a name)")),
            },
        }
    }

    /// `<template-args> ::= I <template-arg>+ E`.
    fn template_args(&mut self) -> Result<Vec<TemplateArg>, Error> {
        self.position += 1;
        let mut arguments = Vec::new();
        while !self.eat(b"E") {
            arguments.push(self.template_arg()?);
        }
        if arguments.is_empty() {
            return Err(self.error("<template-args> (empty)"));
        }
        Ok(arguments)
    }

    /// `<template-arg> ::= <type> | L … E | J <template-arg>* E` (an
    /// expression is refused).
    fn template_arg(&mut self) -> Result<TemplateArg, Error> {
        match self.peek() {
            Some(b'L') => self.literal(),
            Some(b'J') => {
                self.position += 1;
                let mut pack = Vec::new();
                while !self.eat(b"E") {
                    if self.peek().is_none() {
                        return Err(self.error("<template-arg> (pack)"));
                    }
                    pack.push(self.template_arg()?);
                }
                Ok(TemplateArg::Pack(pack))
            }
            Some(b'X') => Err(self.error("<expression>")),
            _ => Ok(TemplateArg::Type(self.ty()?)),
        }
    }

    /// `<expr-primary> ::= L <type> <value number> E` of an integral
    /// builtin type.
    fn literal(&mut self) -> Result<TemplateArg, Error> {
        self.position += 1;
        let Some(
            ty @ (Builtin::Bool
            | Builtin::Char
            | Builtin::SignedChar
            | Builtin::UnsignedChar
            | Builtin::Short
            | Builtin::UnsignedShort
            | Builtin::Int
            | Builtin::UnsignedInt
            | Builtin::Long
            | Builtin::UnsignedLong
            | Builtin::LongLong
            | Builtin::UnsignedLongLong
            | Builtin::Wchar
            | Builtin::Char8
            | Builtin::Char16
            | Builtin::Char32),
        ) = self.builtin()
        else {
            return Err(self.error("<expr-primary>"));
        };
        let start = self.position;
        self.eat(b"n");
        if self.number().is_none() {
            return Err(self.error("<expr-primary> (value)"));
        }
        let value = self
            .input
            .get(start..self.position)
            .and_then(|bytes| core::str::from_utf8(bytes).ok())
            .map(String::from)
            .ok_or_else(|| self.error("<expr-primary> (value)"))?;
        if !self.eat(b"E") {
            return Err(self.error("<expr-primary> (no E)"));
        }
        Ok(TemplateArg::Literal { ty, value })
    }

    /// `<builtin-type>`, consumed if the input continues with one parsed.
    fn builtin(&mut self) -> Option<Builtin> {
        let (ty, length) = match (self.peek()?, self.peek_at(1)) {
            (b'v', _) => (Builtin::Void, 1),
            (b'w', _) => (Builtin::Wchar, 1),
            (b'b', _) => (Builtin::Bool, 1),
            (b'c', _) => (Builtin::Char, 1),
            (b'a', _) => (Builtin::SignedChar, 1),
            (b'h', _) => (Builtin::UnsignedChar, 1),
            (b's', _) => (Builtin::Short, 1),
            (b't', _) => (Builtin::UnsignedShort, 1),
            (b'i', _) => (Builtin::Int, 1),
            (b'j', _) => (Builtin::UnsignedInt, 1),
            (b'l', _) => (Builtin::Long, 1),
            (b'm', _) => (Builtin::UnsignedLong, 1),
            (b'x', _) => (Builtin::LongLong, 1),
            (b'y', _) => (Builtin::UnsignedLongLong, 1),
            (b'n', _) => (Builtin::Int128, 1),
            (b'o', _) => (Builtin::UnsignedInt128, 1),
            (b'f', _) => (Builtin::Float, 1),
            (b'd', _) => (Builtin::Double, 1),
            (b'e', _) => (Builtin::LongDouble, 1),
            (b'g', _) => (Builtin::Float128, 1),
            (b'z', _) => (Builtin::Ellipsis, 1),
            (b'D', Some(b'i')) => (Builtin::Char32, 2),
            (b'D', Some(b's')) => (Builtin::Char16, 2),
            (b'D', Some(b'u')) => (Builtin::Char8, 2),
            (b'D', Some(b'n')) => (Builtin::Nullptr, 2),
            _ => return None,
        };
        self.position += length;
        Some(ty)
    }

    /// `<type>`, as far as parsed.
    fn ty(&mut self) -> Result<TypeId, Error> {
        if let Some(builtin) = self.builtin() {
            return Ok(self.push_type(Type::Builtin(builtin)));
        }
        match (self.peek(), self.peek_at(1)) {
            (Some(b'r' | b'V' | b'K'), _) => {
                let cv = self.cv_qualifiers();
                let ty = self.ty()?;
                Ok(self.candidate(Type::Qualified(cv, ty)))
            }
            (Some(b'P'), _) => self.wrapped(Type::Pointer),
            (Some(b'R'), _) => self.wrapped(Type::LvalueReference),
            (Some(b'O'), _) => self.wrapped(Type::RvalueReference),
            (Some(b'F'), _) => self.function_type(),
            (Some(b'T'), _) => {
                self.position += 1;
                let index = self.sequence("<template-param>")?;
                if self.peek() == Some(b'I') {
                    return Err(self.error("<template-template-param> <template-args>"));
                }
                let index = u32::try_from(index).map_err(|_| self.error("<template-param>"))?;
                Ok(self.candidate(Type::TemplateParam(index)))
            }
            (Some(b'S'), Some(b't')) | (Some(b'N' | b'0'..=b'9'), _) => {
                let name = self.name()?;
                Ok(self.candidate(Type::Named {
                    path: name.path,
                    nested: name.nested,
                }))
            }
            (Some(b'S'), _) => {
                let substitution = self.substitution()?;
                if self.peek() == Some(b'I') {
                    let template = match substitution {
                        Substitutable::Prefix(prefix) => prefix,
                        Substitutable::Type(ty) => match self.types.get(ty.0 as usize) {
                            Some(&Type::Named { path, .. }) => path,
                            _ => {
                                return Err(self.error("<template-template-param> <template-args>"));
                            }
                        },
                    };
                    let node = self.template_args_of(template)?;
                    return Ok(self.candidate(Type::Named {
                        path: node,
                        nested: false,
                    }));
                }
                Ok(match substitution {
                    Substitutable::Type(ty) => ty,
                    Substitutable::Prefix(prefix) => self.push_type(Type::Named {
                        path: prefix,
                        nested: false,
                    }),
                })
            }
            (Some(b'D'), Some(b'p')) => Err(self.error("<type> (pack expansion Dp)")),
            (Some(b'D'), Some(b't' | b'T')) => Err(self.error("<decltype>")),
            (Some(b'D'), _) => Err(self.error("<type> (D…)")),
            (Some(b'A'), _) => Err(self.error("<array-type>")),
            (Some(b'M'), _) => Err(self.error("<pointer-to-member-type>")),
            (Some(b'U' | b'u'), _) => Err(self.error("<type> (vendor extension)")),
            (Some(b'Z'), _) => Err(self.error("<local-name>")),
            _ => Err(self.error("<type>")),
        }
    }

    /// `P`, `R` or `O` and the type it applies to, a candidate.
    fn wrapped(&mut self, make: fn(TypeId) -> Type) -> Result<TypeId, Error> {
        self.position += 1;
        let ty = self.ty()?;
        Ok(self.candidate(make(ty)))
    }

    /// `<function-type> ::= F [Y] <bare-function-type> [<ref-qualifier>]
    /// E` (a ref-qualified one, a member function's type, is refused).
    fn function_type(&mut self) -> Result<TypeId, Error> {
        self.position += 1;
        self.eat(b"Y");
        let returns = self.ty()?;
        let mut parameters = Vec::new();
        loop {
            match (self.peek(), self.peek_at(1)) {
                (Some(b'E'), _) => {
                    self.position += 1;
                    break;
                }
                (Some(b'R' | b'O'), Some(b'E')) => {
                    return Err(self.error("<function-type> (ref-qualifier)"));
                }
                (Some(_), _) => parameters.push(self.ty()?),
                (None, _) => return Err(self.error("<function-type> (no E)")),
            }
        }
        let function = self.bare_function_type(Some(returns), parameters)?;
        Ok(self.candidate(Type::Function(function)))
    }
}
