//! Microsoft manglings (`?…`, parsed by `msvc-demangler`) on Windows
//! x64, whose placement every mangled function fixes:
//!
//! - Each parameter takes one slot (`rcx`, `rdx`, `r8`, `r9`, or `xmm0`–
//!   `xmm3` by position, then the stack), whatever its type: a class,
//!   structure or union passed by value is in its slot itself if it is 1,
//!   2, 4 or 8 bytes, else by the address of a copy, so it is placed,
//!   untyped ([`Bits`](Type::Bits)). The calling convention keywords
//!   (`__cdecl`, `__thiscall`, …) all mean the one x64 convention.
//! - A non-static member function takes `this` first, and returns a
//!   class, structure or union through a buffer whose address is its
//!   second argument (after `this`) and is returned in `rax`; a free or
//!   static member function returning one by value is not placed (that
//!   depends on its size and triviality, which the mangling does not
//!   state).
//! - A constructor returns `this`; a destructor nothing.
//! - Builtin types as on LLP64 Windows (`long` is 32 bits, `wchar_t` an
//!   unsigned 16-bit integer, `long double` a `double`); an enumeration
//!   is untyped (the parsed mangling loses its underlying type); pointers
//!   and references as pointers (only pointers, as an Itanium mangling's,
//!   where what they point to is not `void`, a builtin type or such a
//!   pointer; so are `this` and the result buffer); `...` as variadic.
//!   `__int128`, member
//!   function pointers, template parameters and the other types refuse
//!   the function, as do thunks.

use binbun_ast::types::{Signature, Type, TypeId, Types};
use binbun_decompile::prototype::Open;
use binbun_semantics::ir::Format as FloatFormat;
use msvc_demangler::{FuncClass, Name, Operator, Type as Mangled};

use super::Given;

/// The signature mangled `name` gives a function on Windows x64, if its
/// arguments' placement is fixed.
#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "msvc-demangler's types: any not named is refused, as one it adds would be"
)]
pub(super) fn signature(name: &str, types: &mut Types) -> Option<Given> {
    let parsed = msvc_demangler::parse(name).ok()?;
    let (member, params, returns) = match parsed.symbol_type {
        Mangled::MemberFunction(class, _, params, _, returns) => {
            if class.contains(FuncClass::THUNK) {
                return None;
            }
            (!class.contains(FuncClass::STATIC), params, returns)
        }
        Mangled::NonMemberFunction(_, params, _, returns) => (false, params, returns),
        _ => return None,
    };
    let mut parameters = Vec::new();
    let mut open = Open::default();
    if member {
        open.parameters.push(parameters.len());
        parameters.push(types.intern(Type::Pointer(None)));
    }
    let (returns, stated) = match *returns {
        Mangled::None => match parsed.symbol.name {
            Name::Operator(Operator::Ctor) if member => {
                open.returns = true;
                (Some(parameters.first().copied()?), true)
            }
            Name::Operator(Operator::Dtor) if member => (None, true),
            _ => return None,
        },
        Mangled::Void(_) => (None, true),
        Mangled::Class(..) | Mangled::Struct(..) | Mangled::Union(..) => {
            if !member {
                return None;
            }
            let buffer = types.intern(Type::Pointer(None));
            open.parameters.push(parameters.len());
            open.returns = true;
            parameters.push(buffer);
            (Some(buffer), true)
        }
        Mangled::Enum(..) => (Some(types.intern(Type::Bits(64))), false),
        other => {
            let (ty, pointer) = value(&other, types)?;
            open.returns = pointer;
            (Some(ty), true)
        }
    };
    let mut variadic = false;
    let count = params.types.len();
    for (index, param) in params.types.iter().enumerate() {
        match param {
            Mangled::Void(_) if count == 1 => {}
            Mangled::VarArgs if index + 1 == count => variadic = true,
            other => {
                let (ty, pointer) = value(other, types)?;
                if pointer {
                    open.parameters.push(parameters.len());
                }
                parameters.push(ty);
            }
        }
    }
    Some(Given {
        signature: Signature {
            parameters,
            returns,
            variadic,
        },
        returns_stated: stated,
        open,
    })
}

/// Mangled type `ty` as an argument slot's value, and whether it is only
/// a pointer (`void *` in the signature).
#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "msvc-demangler's types: the others are scalars or refused"
)]
fn value(ty: &Mangled<'_>, types: &mut Types) -> Option<(TypeId, bool)> {
    let (ty, pointer) = match ty {
        Mangled::Class(..) | Mangled::Struct(..) | Mangled::Union(..) | Mangled::Enum(..) => {
            (Type::Bits(64), false)
        }
        Mangled::Ptr(target, _) | Mangled::Ref(target, _) | Mangled::RValueRef(target, _) => {
            match pointer_to(target, types, 0) {
                Some(pointer) => return Some((pointer, false)),
                None => (Type::Pointer(None), true),
            }
        }
        other => (scalar(other)?, false),
    };
    Some((types.intern(ty), pointer))
}

/// A pointer to `ty`, if the mangling describes it: `void`, a builtin
/// scalar, or a pointer to one of these; none for anything else.
#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "msvc-demangler's types: the others are scalars or not described"
)]
fn pointer_to(ty: &Mangled<'_>, types: &mut Types, depth: usize) -> Option<TypeId> {
    if depth > 16 {
        return None;
    }
    let target = match ty {
        Mangled::Void(_) => None,
        Mangled::Ptr(target, _) => Some(pointer_to(target, types, depth + 1)?),
        other => Some(types.intern(scalar(other)?)),
    };
    Some(types.intern(Type::Pointer(target)))
}

/// Builtin type `ty` on LLP64 Windows, if a register holds it whole.
#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "msvc-demangler's types: any not named is refused, as one it adds would be"
)]
fn scalar(ty: &Mangled<'_>) -> Option<Type> {
    Some(match ty {
        Mangled::Bool(_) => Type::Bool(8),
        Mangled::Char(_) => Type::Char { signed: true },
        Mangled::Schar(_) => Type::Int(8),
        Mangled::Uchar(_) | Mangled::Char8(_) => Type::UInt(8),
        Mangled::Short(_) => Type::Int(16),
        Mangled::Ushort(_) | Mangled::Wchar(_) | Mangled::Char16(_) => Type::UInt(16),
        Mangled::Int(_) | Mangled::Long(_) => Type::Int(32),
        Mangled::Uint(_) | Mangled::Ulong(_) | Mangled::Char32(_) => Type::UInt(32),
        Mangled::Int64(_) => Type::Int(64),
        Mangled::Uint64(_) => Type::UInt(64),
        Mangled::Float(_) => Type::Float(FloatFormat::Single),
        Mangled::Double(_) | Mangled::Ldouble(_) => Type::Float(FloatFormat::Double),
        Mangled::Nullptr => Type::Pointer(None),
        _ => return None,
    })
}

/// What template code a Microsoft mangling is an instance of: the
/// demangled name with each template argument list as `<_>`
/// (`std::_Tree_val<_>::_Rrotate`), and the classes, structures, unions
/// and enumerations among its template arguments (at any depth), by
/// their own names without scope or arguments (`pair`,
/// `_Mutex_count_pair`). Another instance, for types of the same layout,
/// runs alike, and a program's own types make instances no pack holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Instance {
    pub generic: String,
    pub types: Vec<String>,
}

/// The template code a mangled function's name is an instance of, if its
/// name or a scope of it has template arguments; `None` for other names
/// and what does not parse.
pub(crate) fn instance(name: &str) -> Option<Instance> {
    let parsed = msvc_demangler::parse(name).ok()?;
    let mut found = Found::default();
    found.symbol(&parsed.symbol);
    if !found.template {
        return None;
    }
    let mut types = found.types;
    types.sort_unstable();
    types.dedup();
    let text = msvc_demangler::serialize(&parsed, msvc_demangler::DemangleFlags::NAME_ONLY);
    let mut generic = String::with_capacity(text.len());
    let mut depth = 0usize;
    for c in text.chars() {
        match c {
            '<' => {
                if depth == 0 {
                    generic.push_str("<_>");
                }
                depth += 1;
            }
            '>' => depth = depth.saturating_sub(1),
            _ if depth == 0 => generic.push(c),
            _ => {}
        }
    }
    Some(Instance { generic, types })
}

/// The names a mangled function's name is made of: its own, its scopes'
/// and those of the types in their template arguments (at any depth),
/// each without scope or arguments; empty if it does not parse.
pub(crate) fn names(name: &str) -> Vec<String> {
    let Ok(parsed) = msvc_demangler::parse(name) else {
        return Vec::new();
    };
    let mut found = Found::default();
    found.symbol(&parsed.symbol);
    found.names
}

/// What [`instance`] and [`names`] collect from a parsed mangling.
#[derive(Default)]
struct Found {
    /// Whether a template argument list was met.
    template: bool,
    /// The types in template arguments.
    types: Vec<String>,
    /// Every name.
    names: Vec<String>,
}

impl Found {
    fn symbol(&mut self, symbol: &msvc_demangler::Symbol<'_>) {
        self.name(&symbol.name);
        for scope in &symbol.scope.names {
            self.name(scope);
        }
    }

    /// `name`'s own name, without its template arguments, if it has one.
    fn name(&mut self, name: &Name<'_>) -> Option<String> {
        match name {
            Name::NonTemplate(text) | Name::AsInterface(text) => {
                let text = String::from_utf8_lossy(text).into_owned();
                self.names.push(text.clone());
                Some(text)
            }
            Name::Template(base, params) => {
                self.template = true;
                for ty in &params.types {
                    self.argument(ty);
                }
                self.name(base)
            }
            Name::ParsedName(parsed) => {
                self.symbol(&parsed.symbol);
                None
            }
            Name::Md5(_)
            | Name::Operator(_)
            | Name::Discriminator(_)
            | Name::AnonymousNamespace(_) => None,
        }
    }

    /// The named types of template argument `ty`.
    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "msvc-demangler's types: only those that hold named types matter"
    )]
    fn argument(&mut self, ty: &Mangled<'_>) {
        match ty {
            Mangled::Struct(symbol, _)
            | Mangled::Union(symbol, _)
            | Mangled::Class(symbol, _)
            | Mangled::Enum(symbol, _) => {
                if let Some(own) = self.name(&symbol.name) {
                    self.types.push(own);
                }
            }
            Mangled::Ptr(inner, _)
            | Mangled::Ref(inner, _)
            | Mangled::RValueRef(inner, _)
            | Mangled::Array(_, inner, _)
            | Mangled::Var(inner, ..) => self.argument(inner),
            Mangled::NonMemberFunction(_, params, _, returns)
            | Mangled::MemberFunctionPointer(_, _, _, params, _, returns) => {
                for param in &params.types {
                    self.argument(param);
                }
                self.argument(returns);
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test helpers fail loudly")]

    use binbun_ast::types::{Type, Types};
    use binbun_decompile::prototype::Open;

    /// The parameters and return value mangled `name` gives, as types,
    /// whether it states the return value, and its open pointers.
    fn placed(name: &str) -> Option<(Vec<Type>, Option<Type>, bool, Open)> {
        let mut types = Types::new(64);
        let stated = super::signature(name, &mut types)?;
        let ty = |id| types.get(id).cloned().unwrap();
        Some((
            stated
                .signature
                .parameters
                .iter()
                .map(|&id| ty(id))
                .collect(),
            stated.signature.returns.map(ty),
            stated.returns_stated,
            stated.open,
        ))
    }

    /// Open pointers: `parameters` and, if `returns`, the return value.
    fn open(parameters: &[usize], returns: bool) -> Open {
        Open {
            parameters: parameters.to_vec(),
            returns,
        }
    }

    #[test]
    fn members_take_this_and_return_classes_through_the_second_argument() {
        // std::ostream &std::ostream::put(char): `this` and the result
        // point to a class, only pointers.
        assert_eq!(
            placed("?put@?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAAEAV12@D@Z"),
            Some((
                vec![Type::Pointer(None), Type::Char { signed: true }],
                Some(Type::Pointer(None)),
                true,
                open(&[0], true)
            ))
        );
        // std::string std::stringstream::str(void) const: the buffer
        // after `this`, returned.
        let str = "?str@?$basic_stringstream@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@\
                   QEBA?AV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@2@XZ";
        assert_eq!(
            placed(str),
            Some((
                vec![Type::Pointer(None), Type::Pointer(None)],
                Some(Type::Pointer(None)),
                true,
                open(&[0, 1], true)
            ))
        );
        // std::_Lockit::_Lockit(int): returns `this`.
        assert_eq!(
            placed("??0_Lockit@std@@QEAA@H@Z"),
            Some((
                vec![Type::Pointer(None), Type::Int(32)],
                Some(Type::Pointer(None)),
                true,
                open(&[0], true)
            ))
        );
    }

    #[test]
    fn static_members_take_no_this_and_free_functions_returning_classes_are_refused() {
        // static size_t std::ctype<char>::_Getcat(const locale::facet **,
        // const locale *): no `this`; pointers (also to a pointer) to
        // classes are only pointers.
        assert_eq!(
            placed("?_Getcat@?$ctype@D@std@@SA_KPEAPEBVfacet@locale@2@PEBV42@@Z"),
            Some((
                vec![Type::Pointer(None), Type::Pointer(None)],
                Some(Type::UInt(64)),
                true,
                open(&[0, 1], false)
            ))
        );
        // struct bar foo(void): in rax or through rcx, by its size.
        assert_eq!(placed("?foo@@YA?AUbar@@XZ"), None);
        // long f(long, ...): LLP64 `long`, variadic.
        let mut types = Types::new(64);
        let signature = super::signature("?f@@YAJJZZ", &mut types)
            .unwrap()
            .signature;
        assert!(signature.variadic);
        assert_eq!(
            signature
                .parameters
                .iter()
                .map(|&id| types.get(id).cloned())
                .collect::<Vec<_>>(),
            vec![Some(Type::Int(32))]
        );
    }

    #[test]
    fn template_instances_and_their_types() {
        // A member of a class template instance: the STL tree of the
        // runtime's own map, for a pair holding a type of its own.
        let rotate = "?_Rrotate@?$_Tree_val@U?$_Tree_simple_types@U?$pair@QEAXU_Mutex_count_pair@?A0xc73d6b27@@@std@@@std@@@std@@QEAAXPEAU?$_Tree_node@U?$pair@QEAXU_Mutex_count_pair@?A0xc73d6b27@@@std@@PEAX@2@@Z";
        let found = super::instance(rotate).unwrap();
        assert_eq!(found.generic, "std::_Tree_val<_>::_Rrotate");
        assert_eq!(
            found.types,
            ["_Mutex_count_pair", "_Tree_simple_types", "pair"]
        );
        // A function template for a builtin type: an instance of no named
        // type.
        let gmtime = "??$common_gmtime_s@_J@@YAHQEAUtm@@QEB_J@Z";
        let found = super::instance(gmtime).unwrap();
        assert_eq!(found.generic, "common_gmtime_s<_>");
        assert_eq!(found.types, Vec::<String>::new());
        // No template: no instance, whatever its parameters' types.
        assert_eq!(super::instance("?f@@YAXPEAUtm@@@Z"), None);
        assert_eq!(super::instance("strlen"), None);
        // A callee's names: its own, its scopes', its scopes' arguments'
        // (their own names, without their scopes).
        let append = "?append@?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QEAAAEAV12@QEBD_K@Z";
        let mut names = super::names(append);
        names.sort_unstable();
        assert_eq!(
            names,
            ["allocator", "append", "basic_string", "char_traits", "std"]
        );
    }
}
