//! Declared prototypes: what lowering and the type passes know about a
//! function from a declaration (the type library, debug information, the
//! user) rather than from its code.
//!
//! Prototypes come through the [`Prototypes`] trait, so this crate does not
//! depend on where they come from: the CLI's glue maps an address to a
//! symbol and converts the type library's declaration into the function's
//! [`Types`] table.

use alloc::string::String;
use alloc::vec::Vec;

use binbun_ast::types::{TypeId, Types};

use crate::format::Family;
use crate::typing::StructId;

/// A function's declared prototype.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Prototype {
    /// Its name, if the declaration has one.
    pub name: Option<String>,
    /// Its type: a [`Type::Code`](binbun_ast::types::Type::Code) in the
    /// table it was asked for with.
    pub signature: TypeId,
    /// Whether the declaration states the return value. A mangling may
    /// not (a non-template C++ function's states only its parameters):
    /// its signature then returns the convention's first result register
    /// untyped ([`Bits`](binbun_ast::types::Type::Bits)), as a call to an
    /// undeclared function does, and the function itself returns what
    /// every exit writes there, as without a declaration.
    pub returns_stated: bool,
    /// Whether the declaration is the function's own, its definition's
    /// (debug information's, or the user's): its parameters are all the
    /// function takes, so lowering takes the convention's other argument
    /// registers' entry values as undefined, and passing one on to a
    /// callee makes it no parameter. A library's declaration matched by
    /// name may say less than the definition reads (`main`'s `envp`).
    pub own: bool,
    /// The pointers the declaration states only to be pointers: what they
    /// point to it names but does not describe (a mangling's pointer to a
    /// class, whose layout it does not give). Their type in the signature
    /// is `void *`, which a call's argument takes as a pointer to
    /// anything; the function's own such parameters and return value are
    /// pointers whose target its accesses decide
    /// ([`Evidence::DeclaredPointer`](binbun_ast::types::Evidence::DeclaredPointer)).
    pub open: Open,
    /// Whether the declaration says it never returns (only a declaration
    /// says so; it is never guessed from a name).
    pub noreturn: bool,
    /// The format string the declaration says its variadic arguments
    /// follow, if it says one does.
    pub format: Option<Format>,
    /// The parameters (counted from 0) whose format string the declaration
    /// says its result is, translated (`__attribute__((format_arg(n)))`,
    /// as `dcgettext`'s; `ngettext` has two): on GNU gettext's documented
    /// contract that a translation keeps its message's conversions, a
    /// format string that is such a call's result has the conversions of
    /// these arguments' strings. Empty where it says none.
    pub format_arg: Vec<usize>,
    /// The parameters the declaration says give the size of the object it
    /// returns (`__attribute__((alloc_size(…)))`), if it says.
    pub alloc_size: Option<AllocSize>,
    /// The struct or union it returns by value where that is wider than
    /// any value (`struct mallinfo2`, of 80 bytes): its signature then
    /// returns none, as no code type states such a result. Lowering
    /// takes the declaration only where the convention returns the
    /// struct in memory: as a pointer to it, which the caller passes
    /// first and the function returns.
    pub wide_result: Option<TypeId>,
}

/// The parameters whose values give the size in bytes of the object a
/// function returns (`alloc_size`): one, or a count and a size whose
/// product it is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct AllocSize {
    /// The size's parameter, counted from 0.
    pub size: usize,
    /// The count's parameter, counted from 0, if the size is per element.
    pub count: Option<usize>,
}

/// The pointers a declaration states only to be pointers
/// ([`Prototype::open`]).
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct Open {
    /// Its parameters', by position.
    pub parameters: Vec<usize>,
    /// Whether its return value.
    pub returns: bool,
}

/// A declared format string (`__attribute__((format(archetype, string, first)))`)
/// whose conversions describe the arguments after the declared
/// parameters, or (`list`) those of the `va_list` parameter right after
/// it (`first` 0, as for `vprintf` and C's other `v` functions, whose
/// `va_list` follows the format: ISO/IEC 9899:2018 §7.21.6.8–14).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Format {
    /// Its conversions' family.
    pub family: Family,
    /// The format string's parameter, counted from 0.
    pub string: usize,
    /// Whether the arguments are a `va_list`, the parameter after the
    /// string (the function is not variadic), rather than the variadic
    /// arguments.
    pub list: bool,
}

/// A declared system call: what a system call instruction whose number is
/// a known constant does.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SystemCall {
    /// Its name (`read`).
    pub name: String,
    /// How many arguments it reads: the first so many of the
    /// convention's system call argument registers.
    pub arguments: usize,
}

/// Where declared prototypes come from.
pub trait Prototypes {
    /// The prototype of the function at `address`, its types interned into
    /// `types` (the table of the function asking), if one is known.
    fn of(&self, address: u64, types: &mut Types) -> Option<Prototype>;

    /// The prototype of the function a call through the pointer at `slot`
    /// reaches, if one is known: an import's slot, which the dynamic
    /// loader fills with the import's address (a call through the global
    /// offset table, `-fno-plt`; through a PE import address table). None
    /// by default.
    fn through(&self, slot: u64, types: &mut Types) -> Option<Prototype> {
        let _ = (slot, types);
        None
    }

    /// The names the declaration of the prototype of the function at
    /// `address` ([`of`](Self::of)) gives its parameters, in order
    /// (`None`: unnamed), as declared (`__fd`). Empty by default, and
    /// where no declaration names them.
    fn parameter_names(&self, address: u64) -> Vec<Option<String>> {
        let _ = address;
        Vec::new()
    }

    /// [`parameter_names`](Self::parameter_names) of the function a call
    /// through the pointer at `slot` reaches ([`through`](Self::through)).
    fn parameter_names_through(&self, slot: u64) -> Vec<Option<String>> {
        let _ = slot;
        Vec::new()
    }

    /// System call `number` of the target, if a declaration knows it.
    /// None by default: a system call then reads every argument register.
    fn system_call(&self, number: u64) -> Option<SystemCall> {
        let _ = number;
        None
    }

    /// What debug information states about the body of the function at
    /// `address` (its parameters' names, its variables in the frame), its
    /// types interned into `types`, if it states anything. None by
    /// default.
    fn debug(&self, address: u64, types: &mut Types) -> Option<DebugStated> {
        let _ = (address, types);
        None
    }

    /// The type debug information states for the global variable at
    /// `address`, interned into `types`, if it states one L2 can say.
    /// None by default.
    fn global(&self, address: u64, types: &mut Types) -> Option<TypeId> {
        let _ = (address, types);
        None
    }
    /// The type the platform declares its thread pointer to have, a
    /// pointer to its thread's structure (Windows x64's TEB, x86-64
    /// glibc's `tcbhead_t`), interned into `types`, if one is known:
    /// the type of the thread pointer's environment variable
    /// ([`Convention::thread_pointer`](crate::lower::Convention::thread_pointer)),
    /// asserted. None by default.
    fn thread_pointer(&self, types: &mut Types) -> Option<TypeId> {
        let _ = types;
        None
    }

    /// The types the user states for the variables of the function at
    /// `address` (its prototype's are [`of`](Self::of)'s, a global's
    /// [`global`](Self::global)'s), interned into `types`: the strongest
    /// evidence, above debug information. None by default.
    fn user(&self, address: u64, types: &mut Types) -> UserStated {
        let _ = (address, types);
        UserStated::default()
    }

    /// Whether the user states the prototype of the function at
    /// `address` ([`of`](Self::of) gives it then), or the type of the
    /// global at `address` ([`global`](Self::global)). False by default.
    fn stated_by_user(&self, address: u64) -> bool {
        let _ = address;
        false
    }

    /// The user's versions of the program's synthesised structs, each by
    /// its identity with its type (a struct or union) in the table given
    /// with them: they replace the table's layouts and names, over debug
    /// information's ([`Structs::state`](crate::typing::Structs::state)).
    /// None by default.
    fn user_structs(&self) -> Option<(Types, Vec<(StructId, TypeId)>)> {
        None
    }
}

/// The types the user states for one function's variables
/// ([`Prototypes::user`]): each type is a declared bound on the variable
/// (the solver takes it as one, with [`Reason::User`](crate::typing::Reason::User))
/// and the variable's type where it is as wide.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct UserStated {
    /// A register variable's: its L1 values (by number) and the type.
    pub values: Vec<(u32, TypeId)>,
    /// A frame variable's: its first byte from the entry stack pointer and
    /// the type.
    pub frame: Vec<(i64, TypeId)>,
}

impl UserStated {
    /// Whether the user states nothing.
    pub fn is_empty(&self) -> bool {
        self.values.is_empty() && self.frame.is_empty()
    }

    /// The user's type of the frame variable at `offset`, if stated.
    pub fn at(&self, offset: i64) -> Option<TypeId> {
        self.frame
            .iter()
            .find_map(|&(at, ty)| (at == offset).then_some(ty))
    }

    /// The user's type of a variable made of L1 `values`, if stated for
    /// one of them.
    pub fn of_values(&self, values: impl IntoIterator<Item = u32>) -> Option<TypeId> {
        values.into_iter().find_map(|value| {
            self.values
                .iter()
                .find_map(|&(stated, ty)| (stated == value).then_some(ty))
        })
    }
}

/// What debug information states about a function's own body
/// ([`Prototypes::debug`]).
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct DebugStated {
    /// Its declared parameters' names, in order, where its prototype
    /// ([`Prototypes::of`]) is the debug information's.
    pub parameters: Vec<Option<String>>,
    /// Why the debug information's prototype is not its prototype, if it
    /// is not.
    pub unplaced: Option<Unplaced>,
    /// Its variables that live in one place of the frame for all their
    /// stated ranges, by that place.
    pub locals: Vec<Local>,
    /// Its variables stated only in registers (named in no L2 variable:
    /// L2's variables carry no address ranges to match).
    pub registers: usize,
}

/// A variable in the frame ([`DebugStated::locals`]).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Local {
    /// Its first byte, from the entry stack pointer.
    pub offset: i64,
    /// Its size in bytes.
    pub bytes: u64,
    /// Its name.
    pub name: String,
    /// Its type, where L2 can say it (with a width).
    pub ty: Option<TypeId>,
}

/// Why debug information's prototype of a function is not taken: the
/// convention would not place its parameters where the code has them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Unplaced {
    /// A parameter or the return value is of a type L2 holds in no
    /// register (a structure or `long double` by value).
    Type,
    /// A parameter's stated place at the entry is not where the
    /// convention puts it (a clone whose parameters the compiler
    /// removed or changed: GCC's `.isra`, `.constprop`).
    Location,
    /// Its type states other parameters than its variables (PDB: a
    /// parameter without a symbol).
    Arity,
}

impl Unplaced {
    /// The name in reports.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Type => "type",
            Self::Location => "location",
            Self::Arity => "arity",
        }
    }
}

/// No prototypes at all: every function is known only from its code.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct NoPrototypes;

impl Prototypes for NoPrototypes {
    fn of(&self, _: u64, _: &mut Types) -> Option<Prototype> {
        None
    }
}
