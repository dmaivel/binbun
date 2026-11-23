//! Prototypes from mangled names, below every database declaration: only
//! where the mangling fixes where each argument is.
//!
//! An Itanium mangling (`_Z…`, [`binbun_demangle::itanium`]) states a
//! function's parameter types, but neither whether a member function is
//! static nor, outside templates, its return type. Its parameters are
//! placed only where that is enough:
//!
//! - **Which ABI.** ELF images only: AArch64 (AAPCS64) and x86-64
//!   (System V). On AArch64 a result returned in memory goes through
//!   `x8`, never shifting an argument, so any mangling can be placed. On
//!   x86-64 its address is a hidden first argument (`rdi`), shifting every
//!   other: only a constructor or destructor (which return nothing) and a
//!   template whose stated return type is a builtin type, a pointer or a
//!   reference are placed.
//! - **`this`.** Only what holds whether a member is static or not: a
//!   constructor, a destructor and a cv- or ref-qualified member function
//!   are non-static members (`this` first); an unscoped name, or one
//!   directly in `std`, is a free function; `operator new` and `operator
//!   delete` (and their array forms) are static in any scope. Any other
//!   nested name is not placed: its scope may be a namespace or a class,
//!   and a member of a class may be static (knowing the scope is a class,
//!   from its constructors, virtual table or `type_info`, is not enough:
//!   libstdc++'s many `_S_` functions, `std::string::_S_construct` among
//!   them, are static members of such classes).
//! - **Constructors and destructors.** The complete-object constructor
//!   and destructor and the deleting destructor (`C1`, `D1`, `D0`). The
//!   base-object ones (`C2`, `D2`) take a VTT after `this` when the class
//!   has virtual bases, which the mangling does not say: they are placed
//!   only for a function the image defines that is also its class's `C1`
//!   or `D1` (the compiler aliases them only when they are the same code).
//! - **Types.** Builtin types exactly (`char`, `wchar_t` with the target's
//!   signedness; LP64 `long`), pointers and references as pointers, `...`
//!   as variadic. A pointer to `void`, to a builtin type or to such a
//!   pointer is that type; any other (to a class, an enumeration, a
//!   function), and `this`, is only a pointer
//!   ([`open`](binbun_decompile::prototype::Prototype::open)): the
//!   mangling names what it points to but does not describe it, so the
//!   accesses through it decide its target.
//!   A class or enumeration passed by value (the mangling does not say
//!   which, nor whether a class is trivially copyable, which decides how
//!   it is passed), `__int128`, `long double`, `__float128`, a function
//!   type or a template parameter that stands for no type: the function
//!   is not placed at all (it keeps the rule for undeclared functions).
//! - **Return value.** A constructor or destructor returns nothing; a
//!   template returns its stated type. Where the mangling states none (or
//!   on AArch64 a class or enumeration), the convention's first result
//!   register is returned untyped
//!   ([`returns_stated`](binbun_decompile::prototype::Prototype::returns_stated)
//!   false), as for an undeclared function.
//! - **Which names.** An import's name, and the symbols of a function the
//!   image defines: the compiler's own statement of that code's interface
//!   (not a library function's name taken as evidence). Every symbol at
//!   its entry must be a mangling giving the same signature. A vendor
//!   suffix (`.cold`, `.isra.0`, `.constprop.0`) is a part or a clone
//!   with its own interface: never placed.
//!
//! A Microsoft mangling (`?…`) on Windows x64 states the return type and
//! the calling convention: every function it parses is placed (see the
//! `msvc` submodule for how).

pub(crate) mod msvc;

use std::collections::{BTreeMap, BTreeSet};

use binbun_ast::types::{Signature, Type, TypeId, Types};
use binbun_decompile::prototype::{Open, Prototype};
use binbun_demangle::itanium::{
    self, Builtin, Component, NameKind, PrefixId, Symbol, Type as Mangled, TypeId as MangledId,
};
use binbun_loader::{Format, Image, Machine, SymbolKind};
use binbun_semantics::ir::Format as FloatFormat;

/// The calling conventions whose placement of a mangled function's
/// arguments is known.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Abi {
    /// AAPCS64 (Linux): an indirect result in `x8`.
    Aapcs64,
    /// The System V x86-64 psABI: an indirect result's address in `rdi`.
    SysV,
    /// Windows x64, with Microsoft manglings.
    MicrosoftX64,
}

/// What an image's manglings say about its functions' prototypes.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Manglings {
    /// The image's convention, if one whose placement is known.
    abi: Option<Abi>,
    /// The names of the symbols at each defined function's entry.
    defined: BTreeMap<u64, BTreeSet<String>>,
}

impl Manglings {
    /// The manglings of `image`'s symbols.
    pub fn new(image: &Image<'_>) -> Self {
        let abi = match (image.format, image.machine) {
            (Format::Elf | Format::MachO, Machine::Aarch64) => Some(Abi::Aapcs64),
            (Format::Elf | Format::MachO, Machine::X86_64) => Some(Abi::SysV),
            (Format::Pe, Machine::X86_64) => Some(Abi::MicrosoftX64),
            (Format::Elf | Format::MachO, Machine::X86 | Machine::Arm | Machine::Other)
            | (Format::Pe, Machine::X86 | Machine::Aarch64 | Machine::Arm | Machine::Other) => None,
        };
        let mut defined: BTreeMap<u64, BTreeSet<String>> = BTreeMap::new();
        for symbol in &image.symbols {
            if symbol.kind == SymbolKind::Function {
                defined
                    .entry(symbol.address)
                    .or_default()
                    .insert(symbol.name.clone());
            }
        }
        Self { abi, defined }
    }

    /// The prototype mangled `name` gives a function (an import's), its
    /// types interned into `types`, where the mangling fixes the
    /// placement of its arguments.
    pub fn import(&self, name: &str, types: &mut Types) -> Option<Prototype> {
        self.prototype(name, false, types)
    }

    /// The prototype the symbols at `entry` give the function the image
    /// defines there: every one a mangling giving the same one.
    pub fn defined(&self, entry: u64, types: &mut Types) -> Option<Prototype> {
        let names = self.defined.get(&entry)?;
        let aliased = |kind: NameKind| {
            names.iter().any(|name| {
                itanium::parse(name)
                    .ok()
                    .and_then(|symbol| symbol.last_name().map(|last| last.kind.clone()))
                    == Some(kind.clone())
            })
        };
        let complete = aliased(NameKind::Constructor(1)) || aliased(NameKind::Destructor(1));
        let mut found: Option<Prototype> = None;
        for name in names {
            let prototype = self.prototype(name, complete, types)?;
            match &found {
                Some(first)
                    if first.signature != prototype.signature
                        || first.returns_stated != prototype.returns_stated
                        || first.open != prototype.open =>
                {
                    return None;
                }
                Some(_) => {}
                None => found = Some(prototype),
            }
        }
        found
    }

    /// The prototype mangled `name` gives; `complete`: the function is
    /// also its class's complete-object constructor or destructor (so a
    /// base-object one takes no VTT).
    fn prototype(&self, name: &str, complete: bool, types: &mut Types) -> Option<Prototype> {
        let given = match self.abi? {
            Abi::MicrosoftX64 if name.starts_with('?') => msvc::signature(name, types)?,
            abi @ (Abi::Aapcs64 | Abi::SysV) if name.starts_with("_Z") => {
                let symbol = itanium::parse(name).ok()?;
                if symbol.suffix.is_some() {
                    return None;
                }
                let mut convert = Convert {
                    symbol: &symbol,
                    abi,
                    types,
                };
                convert.signature(complete)?
            }
            Abi::MicrosoftX64 | Abi::Aapcs64 | Abi::SysV => return None,
        };
        Some(Prototype {
            name: Some(name.to_owned()),
            signature: types.intern(Type::Code(given.signature)),
            returns_stated: given.returns_stated,
            own: false,
            open: given.open,
            noreturn: false,
            format: None,
            format_arg: Vec::new(),
            alloc_size: None,
            wide_result: None,
        })
    }
}

/// The signature a mangling gives, with what it states of it.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Given {
    signature: Signature,
    /// Whether it states the return value.
    returns_stated: bool,
    /// The pointers it states only to be pointers.
    open: Open,
}

/// The scope of the function or object a symbol names: the node before
/// its last unqualified name (before a template's arguments).
pub(crate) fn scope(symbol: &Symbol) -> Option<PrefixId> {
    let mut node = symbol.prefix(symbol.name()?.path)?;
    loop {
        match &node.component {
            Component::Arguments(_) => node = symbol.prefix(node.parent?)?,
            Component::Name(_) => return node.parent,
            Component::Std | Component::Abbreviation(_) => return None,
        }
    }
}

/// A conversion of one mangling's types into a function's [`Types`].
struct Convert<'s, 't> {
    symbol: &'s Symbol,
    abi: Abi,
    types: &'t mut Types,
}

impl Convert<'_, '_> {
    /// The signature, if the mangling fixes the placement (see the module
    /// documentation); `complete`: a base-object constructor or destructor
    /// is known to take no VTT.
    fn signature(&mut self, complete: bool) -> Option<Given> {
        let symbol = self.symbol;
        let name = symbol.name()?;
        let function = symbol.function()?;
        let kind = &symbol.last_name()?.kind;
        let structor = match kind {
            NameKind::Constructor(1) | NameKind::Destructor(0 | 1) => true,
            NameKind::Constructor(2) | NameKind::Destructor(2) => {
                if !complete {
                    return None;
                }
                true
            }
            NameKind::Constructor(_) | NameKind::Destructor(_) => return None,
            NameKind::Source(_) | NameKind::Operator(_) => false,
        };
        let scope = scope(symbol);
        let in_std = scope
            .and_then(|scope| symbol.prefix(scope))
            .is_some_and(|node| node.component == Component::Std);
        // A class's `operator new` and `operator delete` (and their array
        // forms) are static members, whatever their scope.
        let allocation = matches!(
            kind,
            NameKind::Operator(" new" | " new[]" | " delete" | " delete[]")
        );
        let member = !allocation && (structor || !name.cv.is_empty() || name.reference.is_some());
        if !member && !allocation && scope.is_some() && !in_std {
            return None;
        }
        let (returns, returns_stated, open_returns) = if structor {
            (None, true, false)
        } else {
            self.returns(function.returns)?
        };
        let mut parameters = Vec::new();
        let mut open = Open {
            parameters: Vec::new(),
            returns: open_returns,
        };
        if member {
            open.parameters.push(parameters.len());
            parameters.push(self.types.intern(Type::Pointer(None)));
        }
        let mut variadic = false;
        for (index, &parameter) in function.parameters.iter().enumerate() {
            let resolved = symbol.resolve(parameter)?;
            if symbol.ty(resolved)? == &Mangled::Builtin(Builtin::Ellipsis) {
                if index + 1 != function.parameters.len() {
                    return None;
                }
                variadic = true;
            } else {
                let (ty, pointer) = self.value(parameter)?;
                if pointer {
                    open.parameters.push(parameters.len());
                }
                parameters.push(ty);
            }
        }
        Some(Given {
            signature: Signature {
                parameters,
                returns,
                variadic,
            },
            returns_stated,
            open,
        })
    }

    /// The return value of a function whose mangling states `stated`,
    /// whether it is stated and whether it is only a pointer, if the
    /// convention's placement of the arguments does not depend on it.
    fn returns(&mut self, stated: Option<MangledId>) -> Option<(Option<TypeId>, bool, bool)> {
        let unstated = |convert: &mut Self| match convert.abi {
            Abi::Aapcs64 => Some((Some(convert.types.intern(Type::Bits(64))), false, false)),
            Abi::SysV | Abi::MicrosoftX64 => None,
        };
        let Some(stated) = stated else {
            return unstated(self);
        };
        let resolved = self.symbol.resolve(stated)?;
        match self.symbol.ty(resolved)? {
            Mangled::Builtin(Builtin::Void) => Some((None, true, false)),
            Mangled::Qualified(_, inner)
                if self.symbol.ty(self.symbol.resolve(*inner)?)?
                    == &Mangled::Builtin(Builtin::Void) =>
            {
                Some((None, true, false))
            }
            Mangled::Named { .. } => unstated(self),
            Mangled::Builtin(_)
            | Mangled::Qualified(..)
            | Mangled::Pointer(_)
            | Mangled::LvalueReference(_)
            | Mangled::RvalueReference(_)
            | Mangled::Function(_)
            | Mangled::TemplateParam(_) => {
                let (ty, pointer) = self.value(stated)?;
                Some((Some(ty), true, pointer))
            }
        }
    }

    /// Mangled type `id` as a value an argument register holds (a builtin
    /// scalar or a pointer), and whether it is only a pointer (to what
    /// the mangling does not describe: `void *` in the signature).
    fn value(&mut self, id: MangledId) -> Option<(TypeId, bool)> {
        let symbol = self.symbol;
        let resolved = symbol.resolve(id)?;
        match symbol.ty(resolved)? {
            &Mangled::Builtin(builtin) => {
                let ty = self.builtin(builtin)?;
                Some((self.types.intern(ty), false))
            }
            &Mangled::Qualified(_, inner) => self.value(inner),
            &(Mangled::Pointer(target)
            | Mangled::LvalueReference(target)
            | Mangled::RvalueReference(target)) => Some(match self.pointer_to(target, 0) {
                Some(pointer) => (pointer, false),
                None => (self.types.intern(Type::Pointer(None)), true),
            }),
            Mangled::Named { .. } | Mangled::Function(_) | Mangled::TemplateParam(_) => None,
        }
    }

    /// A pointer to mangled type `id`, if the mangling describes what it
    /// points to: `void`, a builtin scalar, or a pointer to one of these.
    /// Anything else (a class, an enumeration, a function) it names
    /// without describing: none.
    fn pointer_to(&mut self, id: MangledId, depth: usize) -> Option<TypeId> {
        let symbol = self.symbol;
        if depth > symbol.types.len() {
            return None;
        }
        let target = match symbol.ty(symbol.resolve(id)?)? {
            Mangled::Builtin(Builtin::Void) => None,
            &Mangled::Builtin(builtin) => {
                let ty = self.builtin(builtin)?;
                Some(self.types.intern(ty))
            }
            &Mangled::Qualified(_, inner) => return self.pointer_to(inner, depth + 1),
            &(Mangled::Pointer(target)
            | Mangled::LvalueReference(target)
            | Mangled::RvalueReference(target)) => Some(self.pointer_to(target, depth + 1)?),
            Mangled::Named { .. } | Mangled::Function(_) | Mangled::TemplateParam(_) => {
                return None;
            }
        };
        Some(self.types.intern(Type::Pointer(target)))
    }

    /// Builtin type `builtin` on the target (LP64), if a register holds it
    /// whole and L2 describes it (not `void`, which no value has).
    fn builtin(&self, builtin: Builtin) -> Option<Type> {
        let aarch64 = self.abi == Abi::Aapcs64;
        Some(match builtin {
            Builtin::Bool => Type::Bool(8),
            Builtin::Char => Type::Char { signed: !aarch64 },
            Builtin::SignedChar => Type::Int(8),
            Builtin::UnsignedChar | Builtin::Char8 => Type::UInt(8),
            Builtin::Short => Type::Int(16),
            Builtin::UnsignedShort | Builtin::Char16 => Type::UInt(16),
            Builtin::Int => Type::Int(32),
            Builtin::Wchar if !aarch64 => Type::Int(32),
            Builtin::UnsignedInt | Builtin::Char32 | Builtin::Wchar => Type::UInt(32),
            Builtin::Long | Builtin::LongLong => Type::Int(64),
            Builtin::UnsignedLong | Builtin::UnsignedLongLong => Type::UInt(64),
            Builtin::Float => Type::Float(FloatFormat::Single),
            Builtin::Double => Type::Float(FloatFormat::Double),
            Builtin::Nullptr => Type::Pointer(None),
            Builtin::Void
            | Builtin::Ellipsis
            | Builtin::Int128
            | Builtin::UnsignedInt128
            | Builtin::LongDouble
            | Builtin::Float128 => return None,
        })
    }
}
