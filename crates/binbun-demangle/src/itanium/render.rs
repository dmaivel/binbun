//! C++ text of a parsed mangling's parts, as demanglers print it
//! (`char const*`, `std::vector<int, std::allocator<int> >`).

use alloc::string::String;
use alloc::vec::Vec;

use super::{
    Abbreviation, Builtin, Component, CvQualifiers, FunctionType, NameKind, PrefixId, RefQualifier,
    Symbol, TemplateArg, Type, TypeId,
};

/// How deep types and names may nest before rendering gives up.
const DEPTH: usize = 256;

impl Symbol {
    /// Its function's parameter list as C++ text, without parentheses
    /// (`int, char const*`; empty for `(void)`), its template
    /// parameters replaced by their arguments; `None` if it is no
    /// function, or a template parameter stands for no argument.
    pub fn parameters_text(&self) -> Option<String> {
        let function = self.function()?;
        self.list_text(&function.parameters, 0)
    }

    /// The qualifiers its member function's text ends in, after the
    /// parameter list: ` const`, ` volatile`, ` restrict`, then ` &` or
    /// ` &&` (none if it names no function or data object).
    pub fn qualifiers_text(&self) -> String {
        let Some(name) = self.name() else {
            return String::new();
        };
        let mut text = cv_text(name.cv);
        text.push_str(match name.reference {
            None => "",
            Some(RefQualifier::Lvalue) => " &",
            Some(RefQualifier::Rvalue) => " &&",
        });
        text
    }

    /// Type `id` as C++ text.
    pub fn type_text(&self, id: TypeId) -> Option<String> {
        let mut out = String::new();
        self.write_type(id, "", &mut out, 0)?;
        Some(out)
    }

    /// Name node `id` (with its parents) as C++ text.
    pub fn prefix_text(&self, id: PrefixId) -> Option<String> {
        let mut out = String::new();
        self.write_prefix(id, &mut out, 0)?;
        Some(out)
    }

    fn list_text(&self, types: &[TypeId], depth: usize) -> Option<String> {
        let mut out = String::new();
        for (index, &ty) in types.iter().enumerate() {
            if index > 0 {
                out.push_str(", ");
            }
            self.write_type(ty, "", &mut out, depth + 1)?;
        }
        Some(out)
    }

    /// Writes type `id` around declarator `inner` (what applies to it:
    /// `*`, `&`, ` const`, a function pointer's `(*)`).
    fn write_type(&self, id: TypeId, inner: &str, out: &mut String, depth: usize) -> Option<()> {
        if depth > DEPTH {
            return None;
        }
        match self.ty(id)? {
            &Type::Builtin(builtin) => {
                out.push_str(builtin_text(builtin));
                out.push_str(inner);
            }
            &Type::Named { path, .. } => {
                self.write_prefix(path, out, depth + 1)?;
                out.push_str(inner);
            }
            &Type::Qualified(cv, ty) => {
                if matches!(self.ty(self.resolve(ty)?), Some(Type::Function(_))) {
                    return None;
                }
                let mut wrapped = cv_text(cv);
                wrapped.push_str(inner);
                self.write_type(ty, &wrapped, out, depth + 1)?;
            }
            &Type::Pointer(ty) => self.write_indirect(ty, "*", inner, out, depth)?,
            &Type::LvalueReference(ty) => self.write_indirect(ty, "&", inner, out, depth)?,
            &Type::RvalueReference(ty) => self.write_indirect(ty, "&&", inner, out, depth)?,
            Type::Function(function) => self.write_function(function, inner, out, depth)?,
            &Type::TemplateParam(index) => match self.template_args()?.get(index as usize)? {
                &TemplateArg::Type(ty) => self.write_type(ty, inner, out, depth + 1)?,
                argument @ (TemplateArg::Literal { .. } | TemplateArg::Pack(_)) => {
                    self.write_argument(argument, out, depth + 1)?;
                    out.push_str(inner);
                }
            },
        }
        Some(())
    }

    /// Writes `ty` under pointer or reference `operator`, parenthesized
    /// around a function type.
    fn write_indirect(
        &self,
        ty: TypeId,
        operator: &str,
        inner: &str,
        out: &mut String,
        depth: usize,
    ) -> Option<()> {
        let resolved = self.resolve(ty)?;
        // A reference to a reference (through a template parameter)
        // collapses: `&&` to `&&` stays `&&`, any other pair is `&`.
        if operator != "*" {
            match self.ty(resolved)? {
                &Type::LvalueReference(referent) => {
                    return self.write_indirect(referent, "&", inner, out, depth + 1);
                }
                &Type::RvalueReference(referent) => {
                    return self.write_indirect(referent, operator, inner, out, depth + 1);
                }
                Type::Builtin(_)
                | Type::Qualified(..)
                | Type::Pointer(_)
                | Type::Named { .. }
                | Type::Function(_)
                | Type::TemplateParam(_) => {}
            }
        }
        let mut wrapped = String::new();
        let function = matches!(self.ty(resolved), Some(Type::Function(_)));
        if function {
            wrapped.push('(');
        }
        wrapped.push_str(operator);
        wrapped.push_str(inner);
        if function {
            wrapped.push(')');
        }
        self.write_type(ty, &wrapped, out, depth + 1)
    }

    fn write_function(
        &self,
        function: &FunctionType,
        inner: &str,
        out: &mut String,
        depth: usize,
    ) -> Option<()> {
        let returns = function.returns?;
        self.write_type(returns, "", out, depth + 1)?;
        // A function type with no declarator around it follows a nested
        // name directly (`llvm::APInt(int)`), anything else after a space
        // (`bool (int)`, `std::optional<int> (int)`, `void (*)(int)`).
        let nested = matches!(
            self.ty(self.resolve(returns)?),
            Some(Type::Named { nested: true, .. })
        );
        if !(inner.is_empty() && nested) {
            out.push(' ');
        }
        out.push_str(inner);
        out.push('(');
        out.push_str(&self.list_text(&function.parameters, depth + 1)?);
        out.push(')');
        Some(())
    }

    fn write_prefix(&self, id: PrefixId, out: &mut String, depth: usize) -> Option<()> {
        if depth > DEPTH {
            return None;
        }
        let node = self.prefix(id)?;
        match &node.component {
            Component::Std => out.push_str("std"),
            &Component::Abbreviation(abbreviation) => {
                out.push_str(abbreviation_text(abbreviation));
            }
            Component::Name(name) => {
                if let Some(parent) = node.parent {
                    self.write_prefix(parent, out, depth + 1)?;
                    out.push_str("::");
                }
                match &name.kind {
                    NameKind::Source(source) => out.push_str(source_text(source)),
                    NameKind::Operator(spelling) => {
                        out.push_str("operator");
                        out.push_str(spelling);
                    }
                    NameKind::Constructor(_) => out.push_str(&self.class_name(node.parent?)?),
                    NameKind::Destructor(_) => {
                        out.push('~');
                        out.push_str(&self.class_name(node.parent?)?);
                    }
                }
                for tag in &name.abi_tags {
                    out.push_str("[abi:");
                    out.push_str(tag);
                    out.push(']');
                }
            }
            Component::Arguments(arguments) => {
                self.write_prefix(node.parent?, out, depth + 1)?;
                out.push('<');
                let mut text = String::new();
                self.write_arguments(arguments, &mut text, depth + 1)?;
                out.push_str(&text);
                if text.ends_with('>') {
                    out.push(' ');
                }
                out.push('>');
            }
        }
        Some(())
    }

    /// The name a constructor or destructor of class `id` has: the
    /// class's last name, without its template arguments.
    fn class_name(&self, id: PrefixId) -> Option<String> {
        let mut node = self.prefix(id)?;
        loop {
            match &node.component {
                Component::Arguments(_) => node = self.prefix(node.parent?)?,
                Component::Name(name) => {
                    return match &name.kind {
                        NameKind::Source(source) => Some(String::from(source_text(source))),
                        NameKind::Operator(_)
                        | NameKind::Constructor(_)
                        | NameKind::Destructor(_) => None,
                    };
                }
                &Component::Abbreviation(abbreviation) => {
                    let text = abbreviation_text(abbreviation);
                    return text.rsplit("::").next().map(String::from);
                }
                Component::Std => return None,
            }
        }
    }

    fn write_arguments(
        &self,
        arguments: &[TemplateArg],
        out: &mut String,
        depth: usize,
    ) -> Option<()> {
        for (index, argument) in arguments.iter().enumerate() {
            if index > 0 {
                out.push_str(", ");
            }
            self.write_argument(argument, out, depth + 1)?;
        }
        Some(())
    }

    fn write_argument(&self, argument: &TemplateArg, out: &mut String, depth: usize) -> Option<()> {
        if depth > DEPTH {
            return None;
        }
        match argument {
            &TemplateArg::Type(ty) => self.write_type(ty, "", out, depth + 1)?,
            TemplateArg::Literal { ty, value } => {
                let digits = value.strip_prefix('n');
                match (ty, value.as_str()) {
                    (Builtin::Bool, "0") => out.push_str("false"),
                    (Builtin::Bool, "1") => out.push_str("true"),
                    (Builtin::Int, _) => {}
                    _ => {
                        out.push('(');
                        out.push_str(builtin_text(*ty));
                        out.push(')');
                    }
                }
                if !matches!((ty, value.as_str()), (Builtin::Bool, "0" | "1")) {
                    if let Some(digits) = digits {
                        out.push('-');
                        out.push_str(digits);
                    } else {
                        out.push_str(value);
                    }
                }
            }
            TemplateArg::Pack(pack) => self.write_arguments(pack, out, depth + 1)?,
        }
        Some(())
    }
}

/// What a source name prints as: GCC's anonymous namespace
/// (`_GLOBAL__N_1`) as `(anonymous namespace)`.
fn source_text(source: &str) -> &str {
    let anonymous = source.strip_prefix("_GLOBAL_").is_some_and(|rest| {
        let mut bytes = rest.bytes();
        matches!(bytes.next(), Some(b'.' | b'_' | b'$')) && bytes.next() == Some(b'N')
    });
    if anonymous {
        "(anonymous namespace)"
    } else {
        source
    }
}

/// ` const`, ` volatile`, ` restrict`, those `cv` has.
fn cv_text(cv: CvQualifiers) -> String {
    let parts: Vec<&str> = [
        (cv.constant, " const"),
        (cv.volatile, " volatile"),
        (cv.restrict, " restrict"),
    ]
    .into_iter()
    .filter_map(|(has, text)| has.then_some(text))
    .collect();
    parts.concat()
}

fn abbreviation_text(abbreviation: Abbreviation) -> &'static str {
    match abbreviation {
        Abbreviation::Allocator => "std::allocator",
        Abbreviation::BasicString => "std::basic_string",
        Abbreviation::String => "std::string",
        Abbreviation::Istream => "std::basic_istream<char, std::char_traits<char> >",
        Abbreviation::Ostream => "std::ostream",
        Abbreviation::Iostream => "std::basic_iostream<char, std::char_traits<char> >",
    }
}

fn builtin_text(builtin: Builtin) -> &'static str {
    match builtin {
        Builtin::Void => "void",
        Builtin::Wchar => "wchar_t",
        Builtin::Bool => "bool",
        Builtin::Char => "char",
        Builtin::SignedChar => "signed char",
        Builtin::UnsignedChar => "unsigned char",
        Builtin::Short => "short",
        Builtin::UnsignedShort => "unsigned short",
        Builtin::Int => "int",
        Builtin::UnsignedInt => "unsigned int",
        Builtin::Long => "long",
        Builtin::UnsignedLong => "unsigned long",
        Builtin::LongLong => "long long",
        Builtin::UnsignedLongLong => "unsigned long long",
        Builtin::Int128 => "__int128",
        Builtin::UnsignedInt128 => "unsigned __int128",
        Builtin::Float => "float",
        Builtin::Double => "double",
        Builtin::LongDouble => "long double",
        Builtin::Float128 => "__float128",
        Builtin::Ellipsis => "...",
        Builtin::Char32 => "char32_t",
        Builtin::Char16 => "char16_t",
        Builtin::Char8 => "char8_t",
        Builtin::Nullptr => "std::nullptr_t",
    }
}
