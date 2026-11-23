//! Declared prototypes from the type library: the [`Prototypes`] lowering
//! and the type passes ask, answered for the functions an image imports
//! and those it defines in their place.
//!
//! A call target is known by name only where it is an import thunk (a
//! function whose only block jumps to an import and passes the call on
//! untouched, [`pure_thunk`]: a PLT stub, a PE import thunk), or the
//! pointer it calls through is an import's slot (a call
//! through the global offset table): the import names the function and,
//! for PE, its module. Code that changes an argument before it jumps (an
//! adapter: `mov rcx, rdx; jmp [__imp_free]`) is no thunk: it has its
//! own interface, and its jump is a tail call to the import. A function
//! the image defines is not looked up in the type library by a local
//! symbol's name: analyses never take a name as evidence of what code is
//! (a local function may be called `read` and be nothing like libc's).
//! An ELF function that interposes its name, exported in `.dynsym` under
//! the name's default version (`malloc@@GLIBC_2.2.5`) or unversioned,
//! global or weak, not hidden ([`binbun_loader::Symbol::interposes`]),
//! is the exception: the dynamic linker binds every module's references
//! to the name to it (an allocator linked into a program with
//! `-rdynamic` replaces libc's `malloc` for libc itself), so it has the
//! interface the name declares, and takes that declaration. Not under a
//! non-default version (`memcpy@GLIBC_2.2.5`: an older interface may
//! differ), and not a PE export (PE binds each import to a named module:
//! nothing is interposed).
//! A mangled name is evidence too: the compiler's statement of that
//! code's own parameters ([`Manglings`], below every declaration, which
//! also gives an import without one a prototype).
//! Debug information, where the image has it ([`DebugInfo`]), is above
//! them all: the compiler's statement of the function's own prototype,
//! taken where the convention places it as stated.
//! A Windows driver's entry point is what the system calls as the
//! driver's `DriverEntry`, of the prototype the WDK declares it with
//! (`DRIVER_INITIALIZE`, from the kernel database), below debug
//! information only; so is the function the entry tail-calls with its
//! parameters unchanged (MSVC's `GsDriverEntry` sets the stack cookie up,
//! then jumps to the driver's own `DriverEntry`): the system's arguments
//! reach it, and its result the system ([`driver_entries`]).
//!
//! A declaration converts to L2's types ([`binbun_ast::types`]) as far as
//! L2 can say it: typedefs become the type they stand for, enumerations
//! L2's ([`enumeration`]: their integer, with the constants whose values
//! the declaration gives), plain `char` stays `char` (C's third character type, with
//! the target's signedness), structures and unions keep their
//! byte-aligned fields (not bit-fields, nor a flexible array member: no
//! width), and a pointer to anything L2
//! cannot describe is `void *`.
//! A parameter of array type is a pointer to its element, as C adjusts it
//! (C11 6.7.6.3p7): `pipe(int[2])` takes an `int *`, and System V
//! x86-64's `va_list`, `struct __va_list_tag[1]`, is passed as a pointer
//! to its one `__va_list_tag` (the type a variadic definition's `va_list`
//! is an array of: passing it on needs no cast).
//! A prototype whose parameters or return value L2 cannot hold as values
//! (a structure passed by value, `long double` on AArch64, AArch64's
//! `va_list`, a structure too) or that states a calling convention other
//! than the target's is not given at all: lowering would place its
//! arguments wrongly.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use binbun_ast::types::{Aggregate, Enumeration, Field, Signature, Type, TypeId, Types};
use binbun_decompile::format::Family;
use binbun_decompile::prototype::{
    AllocSize, DebugStated, Format as FormatString, Open, Prototype, Prototypes, SystemCall,
};
use binbun_loader::{Image, SymbolKind};
use binbun_semantics::Declarations;
use binbun_semantics::ir::Format;
use binbun_ssa::Terminator;
use binbun_ssa::ir::{Definition, Function, Op, Value};
use binbun_typedb::database::Format as LibFormat;
use binbun_typedb::types::{Enum as LibEnum, FloatFormat, Signature as LibSignature};
use binbun_typedb::{Type as LibType, TypeId as LibId, TypeLibrary};

use crate::cfg::{Destination, Exit, FunctionId, Program};
use crate::debug::DebugInfo;
use crate::lift::{ImageEnvironment, lift_function, lift_function_leaving};
use crate::manglings::Manglings;
use crate::summary::Summaries;
use crate::target::{convention, handed_on};
use crate::user::UserTypes;

/// The key of the type the WDK declares a driver's entry with
/// (`DRIVER_INITIALIZE DriverEntry;`), a pointer to its function type, in
/// the kernel database (the WDK's metadata's).
const DRIVER_INITIALIZE: &str = "Windows.Wdk.Foundation.DRIVER_INITIALIZE";

/// The functions an image's import thunks and import slots stand for, and
/// the names its interposing definitions are exported under; a driver's
/// entry points.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Imports {
    /// The function each import thunk stands for: its module, if the file
    /// says, and its name.
    thunks: BTreeMap<u64, (Option<String>, String)>,
    /// The function each import slot holds the address of, likewise; and
    /// each slot an `IRELATIVE` relocation fills with what the resolver of
    /// an exported indirect function returns ([`binbun_loader::Resolved`]),
    /// by that function's name: the one the name declares, as an import's
    /// slot holds the import's.
    slots: BTreeMap<u64, (Option<String>, String)>,
    /// The function of the image each of its other thunks jumps to, by
    /// their entries: a PLT stub of a function the image itself defines
    /// (an ELF shared object calls its own exported functions through
    /// one, so that another module may define them first), an
    /// incremental linker's jump thunk. Only a function no symbol names
    /// that is nothing but the jump ([`STUB`]): one with a name, or that
    /// does anything else, is a function of its own that ends in a tail
    /// call (`int f(int a) { return g(a); }`), whatever it is declared.
    own: BTreeMap<u64, u64>,
    /// The names each function the image defines is exported under where
    /// that interposes the name ([`binbun_loader::Symbol::interposes`]:
    /// ELF dynamic symbols under their default version).
    exports: BTreeMap<u64, BTreeSet<String>>,
    /// The functions the system calls as a kernel driver's entry
    /// ([`driver_entries`]).
    driver_entries: BTreeSet<u64>,
}

impl Imports {
    /// The import thunks of `program` (recovered from `image`), the
    /// image's import slots and its interposing exports, and its driver
    /// entries.
    pub fn new(image: &Image<'_>, program: &Program) -> Self {
        let mut slots: BTreeMap<u64, (Option<String>, String)> = image
            .imports
            .iter()
            .map(|import| (import.slot, (import.library.clone(), import.name.clone())))
            .collect();
        for resolved in &image.resolved {
            // A public name before an internal alias of the same function.
            let name = resolved
                .names
                .iter()
                .find(|name| !name.starts_with('_'))
                .or_else(|| resolved.names.first());
            if let Some(name) = name {
                slots
                    .entry(resolved.at)
                    .or_insert_with(|| (None, name.clone()));
            }
        }
        let thunks = program
            .functions
            .iter()
            .filter_map(|(id, function)| {
                let [only] = function.blocks.as_slice() else {
                    return None;
                };
                let Exit::Jump(Destination::Import(slot) | Destination::Pointer(slot)) =
                    program.blocks.get(*only)?.exit
                else {
                    return None;
                };
                let import = slots.get(&slot)?.clone();
                pure_thunk(image, program, id).then_some((function.entry, import))
            })
            .collect();
        let named: BTreeSet<u64> = image
            .symbols
            .iter()
            .filter(|symbol| symbol.kind == SymbolKind::Function)
            .map(|symbol| symbol.address)
            .collect();
        let own = program
            .functions
            .iter()
            .filter_map(|(id, function)| {
                let [only] = function.blocks.as_slice() else {
                    return None;
                };
                let block = program.blocks.get(*only)?;
                let Exit::Jump(Destination::Address(target)) = block.exit else {
                    return None;
                };
                (target != function.entry
                    && block.instructions <= STUB
                    && !named.contains(&function.entry)
                    && program.function_at(target).is_some()
                    && pure_thunk(image, program, id))
                .then_some((function.entry, target))
            })
            .collect();
        let mut exports: BTreeMap<u64, BTreeSet<String>> = BTreeMap::new();
        for symbol in &image.symbols {
            if symbol.interposes && symbol.kind == SymbolKind::Function {
                exports
                    .entry(symbol.address)
                    .or_default()
                    .insert(symbol.name.clone());
            }
        }
        Self {
            thunks,
            slots,
            own,
            exports,
            driver_entries: driver_entries(image, program),
        }
    }

    /// Whether the system calls the function at `address` as a kernel
    /// driver's entry ([`driver_entries`]).
    pub fn is_driver_entry(&self, address: u64) -> bool {
        self.driver_entries.contains(&address)
    }

    /// The name of each import thunk: the import it jumps to (a PLT stub
    /// has no symbol of its own).
    pub fn thunk_names(&self) -> impl Iterator<Item = (u64, &str)> {
        self.thunks
            .iter()
            .map(|(&entry, (_, name))| (entry, name.as_str()))
    }

    /// The thunks of the image's own functions, each with the function it
    /// jumps to.
    pub fn own_thunks(&self) -> impl Iterator<Item = (u64, u64)> {
        self.own.iter().map(|(&entry, &target)| (entry, target))
    }

    /// The function a call of the function at `address` reaches: through
    /// the thunks of the image's own functions (at most [`THUNKS`] in a
    /// row), `address` itself where it is none.
    pub fn stands_for(&self, address: u64) -> u64 {
        let mut at = address;
        for _ in 0..THUNKS {
            match self.own.get(&at) {
                Some(&target) => at = target,
                None => break,
            }
        }
        at
    }

    /// Their prototypes, from `library`, else from their `manglings`
    /// (which also give those of the functions the image defines); the
    /// image's own functions' from its `debug` information first.
    pub fn prototypes<'a>(
        &'a self,
        library: &'a TypeLibrary,
        manglings: &'a Manglings,
        debug: Option<&'a DebugInfo>,
    ) -> LibraryPrototypes<'a> {
        LibraryPrototypes {
            library,
            imports: self,
            manglings,
            debug,
            user: None,
        }
    }

    /// The entries of the import thunks of functions `library` declares
    /// never to throw (C++ `throw()` or `noexcept`,
    /// `__attribute__((nothrow))`).
    pub fn nothrow<'a>(&'a self, library: &'a TypeLibrary) -> impl Iterator<Item = u64> + 'a {
        self.thunks
            .iter()
            .filter(|(_, (module, name))| {
                library
                    .function(module.as_deref(), name)
                    .and_then(|declaration| declaration.no_throw)
                    .is_some_and(|fact| fact.value)
            })
            .map(|(&entry, _)| entry)
    }
}

/// Prototypes of an image's imports, from a [`TypeLibrary`], else from
/// their [`Manglings`]; of the functions it defines, from its debug
/// information, else as interposing exports, else from their manglings.
/// The user's definitions of structs and unions, where given
/// ([`Self::defined_by`]), replace the library's records of their keys.
#[derive(Clone, Debug)]
pub struct LibraryPrototypes<'a> {
    library: &'a TypeLibrary,
    imports: &'a Imports,
    manglings: &'a Manglings,
    debug: Option<&'a DebugInfo>,
    /// The user's types whose struct and union definitions replace the
    /// library's ([`UserTypes::record`]).
    user: Option<Arc<UserTypes>>,
}

/// The most thunks in a row [`Imports::stands_for`] follows.
const THUNKS: usize = 4;

/// The most instructions a thunk of one of the image's own functions is:
/// its jump, after an instruction that marks where an indirect branch
/// may land (`endbr64`, `bti`) where the image has those.
const STUB: u32 = 2;

/// Whether function `id` of `program` (recovered from `image`) only
/// passes the call on: at every jump out of it, its L1 state still holds
/// what it found in the registers the jump hands on
/// ([`handed_on`]: the argument registers and those calls keep), and it
/// wrote no memory (an intrinsic whose inputs do not escape, a keyed hash
/// such as `compute_pac`, writes none). A PLT stub qualifies (AArch64's
/// loads its target into the scratch `x16`/`x17`; arm64e's authenticates
/// it with `braa x16, x17`); an adapter that moves an argument does not.
pub fn pure_thunk(image: &Image<'_>, program: &Program, id: FunctionId) -> bool {
    let (Ok(l1), Ok(handed), Ok(environment)) = (
        lift_function_leaving(image, program, id, &Summaries::new()),
        handed_on(image),
        ImageEnvironment::new(image, &[]),
    ) else {
        return false;
    };
    let declarations = environment.declarations();
    let Some(entry) = l1.blocks.first() else {
        return false;
    };
    let memory = entry.parameters.last().copied();
    let leaves: Vec<_> = l1
        .blocks
        .iter()
        .filter_map(|block| match &block.terminator {
            Terminator::Leave { state, .. } => Some(state),
            Terminator::IndirectJump { .. }
            | Terminator::Jump(_)
            | Terminator::Branch { .. }
            | Terminator::Invoke { .. }
            | Terminator::Return { .. }
            | Terminator::Trap(_)
            | Terminator::Stop
            | Terminator::Open => None,
        })
        .collect();
    !leaves.is_empty()
        && leaves.iter().all(|state| {
            Some(before_hashes(&l1, declarations, state.memory)) == memory
                && handed.iter().all(|register| {
                    let index = usize::from(register.0);
                    state.registers.get(index) == entry.parameters.get(index)
                })
        })
}

/// The functions the system calls as `image`'s `DriverEntry`, where it is
/// kernel-mode code ([`Image::kernel`]): its entry point, and the
/// functions the entry passes the two arguments of `DRIVER_INITIALIZE`
/// (the convention's first two argument registers) on to as it found
/// them, whose result is the entry's: a tail call (a jump to a function's
/// start), or a call whose result every return of the entry returns
/// (MSVC's `GsDriverEntry`, which sets the stack cookie up first, does
/// either). Each receives what the system passed and returns to the
/// system. None for any other image.
fn driver_entries(image: &Image<'_>, program: &Program) -> BTreeSet<u64> {
    let mut entries = BTreeSet::new();
    let Some((entry, id)) = image
        .entry
        .filter(|_| image.kernel)
        .and_then(|entry| Some((entry, program.function_at(entry)?)))
    else {
        return entries;
    };
    entries.insert(entry);
    let (Ok(l1), Ok(environment)) = (
        lift_function(image, program, id, &Summaries::new()),
        ImageEnvironment::new(image, &[]),
    ) else {
        return entries;
    };
    let convention = convention(image, environment.declarations());
    let (Some(arguments), Some(&result), Some(parameters)) = (
        convention.arguments.get(..2),
        convention.results.first(),
        l1.blocks.first().map(|block| &block.parameters),
    ) else {
        return entries;
    };
    // Whether `registers` (in register order) hold the entry's arguments.
    let handed = |registers: &[Value]| {
        arguments.iter().all(|register| {
            let index = usize::from(register.0);
            registers.get(index) == parameters.get(index)
        })
    };
    // The function at the end of the recovered block holding `address`,
    // if it is a call or jump to one's start.
    let callee = |address: u64| {
        let exit = program.blocks.get(program.block_containing(address)?)?.exit;
        let (Exit::Jump(Destination::Address(target))
        | Exit::Call {
            callee: Destination::Address(target),
            ..
        }) = exit
        else {
            return None;
        };
        program.function_at(target).map(|_| target)
    };
    // What every return returns, if one value.
    let mut returned = l1.blocks.iter().filter_map(|block| {
        let Terminator::Return { state, .. } = &block.terminator else {
            return None;
        };
        Some(state.registers.get(usize::from(result.0)))
    });
    let returned = returned
        .next()
        .flatten()
        .filter(|&first| returned.all(|other| other == Some(first)));
    for block in &l1.blocks {
        if let Terminator::Leave { state, .. } = &block.terminator
            && handed(&state.registers)
            && let Some(target) = callee(block.end)
        {
            entries.insert(target);
        }
        for inst in block.insts.iter().filter_map(|&id| l1.inst(id)) {
            let Op::Call {
                registers, changes, ..
            } = &inst.op
            else {
                continue;
            };
            // Results: the memory, then each register the call changes.
            let value = changes
                .iter()
                .position(|&register| register == result)
                .and_then(|position| inst.results.get(position + 1));
            if value.is_some()
                && value == returned
                && handed(registers)
                && let Some(target) = callee(inst.address)
            {
                entries.insert(target);
            }
        }
    }
    entries
}

/// `memory` of `l1` seen back through the intrinsics whose inputs do not
/// escape ([`IntrinsicInfo::escapes`](binbun_semantics::ir::IntrinsicInfo::escapes):
/// keyed hashes, which read no memory and write none, though L1 threads
/// memory through every intrinsic): the memory before the first of them.
fn before_hashes(l1: &Function, declarations: &Declarations, mut memory: Value) -> Value {
    while let Some(Definition::Result { inst, .. }) = l1.value(memory).map(|v| v.definition)
        && let Some(&Op::Intrinsic {
            intrinsic,
            memory: before,
            ..
        }) = l1.inst(inst).map(|i| &i.op)
        && declarations
            .intrinsic(intrinsic)
            .is_some_and(|info| !info.escapes)
    {
        memory = before;
    }
    memory
}

impl LibraryPrototypes<'_> {
    /// The function a call of the function at `address` reaches
    /// ([`Imports::stands_for`]).
    pub(crate) fn stands_for(&self, address: u64) -> u64 {
        self.imports.stands_for(address)
    }

    /// These prototypes with the user's definitions of structs and unions
    /// in `user` ([`UserTypes::set_record`]) for the library's records of
    /// their keys, wherever a declaration refers to one.
    #[must_use]
    pub fn defined_by(self, user: Arc<UserTypes>) -> Self {
        Self {
            user: Some(user),
            ..self
        }
    }

    /// A conversion of the library's types into `types`, with the user's
    /// definitions for the records they replace.
    fn convert<'s, 't>(&'s self, types: &'t mut Types) -> Convert<'s, 't> {
        Convert::new(self.library, types).replacing(self.user.as_deref())
    }

    /// The function type the WDK declares a driver's entry with
    /// (`DRIVER_INITIALIZE`), if the library has it (the kernel database
    /// does).
    fn driver_initialize(&self) -> Option<&LibSignature<LibId>> {
        let LibType::Typedef(typedef) =
            self.library.ty(self.library.named(DRIVER_INITIALIZE)?)?
        else {
            return None;
        };
        let &LibType::Pointer(target) = self.library.ty(typedef.target)? else {
            return None;
        };
        let LibType::Function(signature) = self.library.ty(target)? else {
            return None;
        };
        Some(signature)
    }

    /// The prototype of a driver's entry ([`driver_entries`]):
    /// `NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING
    /// RegistryPath)`, `DRIVER_INITIALIZE`'s.
    fn driver_entry(&self, types: &mut Types) -> Option<Prototype> {
        let signature = self.convert(types).signature(self.driver_initialize()?)?;
        Some(Prototype {
            name: None,
            signature: types.intern(Type::Code(signature)),
            returns_stated: true,
            own: false,
            open: Open::default(),
            noreturn: false,
            format: None,
            format_arg: Vec::new(),
            alloc_size: None,
            wide_result: None,
        })
    }

    /// The parameter names the library's declaration of import `name` (of
    /// `module`, if the file says) gives, where its prototype is that
    /// declaration's ([`import`](Self::import)); else none.
    fn declared_names(&self, module: Option<&str>, name: &str) -> Vec<Option<String>> {
        let mut types = Types::new(64);
        let Some(prototype) = self.import(module, name, &mut types) else {
            return Vec::new();
        };
        // A struct or union by value is passed in parts or through a
        // pointer the declaration does not name: the parameters lowering
        // gives are not the declared ones, one for one.
        let by_value = prototype.wide_result.is_some()
            || types
                .signature(prototype.signature)
                .is_some_and(|signature| {
                    signature
                        .parameters
                        .iter()
                        .any(|&ty| matches!(types.get(ty), Some(Type::Struct(_) | Type::Union(_))))
                });
        if by_value {
            return Vec::new();
        }
        let Some(declared) = self
            .library
            .function(module, name)
            .and_then(|declaration| declaration.prototype.as_ref())
        else {
            return Vec::new();
        };
        let names: Vec<Option<String>> = declared
            .value
            .params
            .iter()
            .map(|param| param.name.clone())
            .collect();
        let arity = types
            .signature(prototype.signature)
            .map(|signature| signature.parameters.len());
        if arity == Some(names.len()) {
            names
        } else {
            Vec::new()
        }
    }

    /// The prototype of import `name` (of `module`, if the file says):
    /// its declaration's, else its mangling's.
    fn import(&self, module: Option<&str>, name: &str, types: &mut Types) -> Option<Prototype> {
        let declaration = self.library.function(module, name);
        let noreturn = declaration
            .and_then(|declaration| declaration.no_return)
            .is_some_and(|fact| fact.value);
        let Some((declaration, prototype)) = declaration.and_then(|declaration| {
            let prototype = &declaration.prototype.as_ref()?.value;
            Some((declaration, prototype))
        }) else {
            let prototype = self.manglings.import(name, types)?;
            return Some(Prototype {
                noreturn,
                ..prototype
            });
        };
        let mut convert = self.convert(types);
        let (signature, wide_result) = convert.declared(prototype)?;
        let format = declaration
            .format
            .as_ref()
            .and_then(|fact| format(&fact.value, &signature));
        let format_arg = declaration
            .format_arg
            .as_ref()
            .map(|fact| format_arg(&fact.value, &signature))
            .unwrap_or_default();
        let alloc_size = declaration
            .alloc_size
            .as_ref()
            .and_then(|fact| alloc_size(&fact.value, &signature));
        Some(Prototype {
            name: Some(name.to_owned()),
            signature: types.intern(Type::Code(signature)),
            returns_stated: true,
            own: false,
            open: Open::default(),
            noreturn,
            format,
            format_arg,
            alloc_size,
            wide_result,
        })
    }
}

/// The parameters `indices` (counted from 1) of a declared `format_arg`,
/// counted from 0, where `signature` has them all; else none.
fn format_arg(indices: &[u32], signature: &Signature) -> Vec<usize> {
    let parameters: Option<Vec<usize>> = indices
        .iter()
        .map(|&index| {
            let index = usize::try_from(index.checked_sub(1)?).ok()?;
            (index < signature.parameters.len()).then_some(index)
        })
        .collect();
    parameters.unwrap_or_default()
}

/// The parameters `indices` (counted from 1: the size, or the count and
/// the size) of a declared `alloc_size`, where `signature` has them.
fn alloc_size(indices: &[u32], signature: &Signature) -> Option<AllocSize> {
    let parameter = |index: u32| {
        let index = usize::try_from(index.checked_sub(1)?).ok()?;
        (index < signature.parameters.len()).then_some(index)
    };
    match *indices {
        [size] => Some(AllocSize {
            size: parameter(size)?,
            count: None,
        }),
        [count, size] => Some(AllocSize {
            size: parameter(size)?,
            count: Some(parameter(count)?),
        }),
        _ => None,
    }
}

impl Prototypes for LibraryPrototypes<'_> {
    fn of(&self, address: u64, types: &mut Types) -> Option<Prototype> {
        // A thunk of one of the image's own functions is declared as that
        // function is.
        let address = self.imports.stands_for(address);
        if let Some((module, name)) = self.imports.thunks.get(&address) {
            return self.import(module.as_deref(), name, types);
        }
        if let Some(mut prototype) = self.debug.and_then(|debug| debug.prototype(address, types)) {
            // What debug information does not state (`noreturn`, a format
            // string, `alloc_size`) the declaration of its interposing
            // name says, where it has as many parameters.
            let arity = |types: &Types, prototype: &Prototype| {
                types
                    .signature(prototype.signature)
                    .map(|signature| signature.parameters.len())
            };
            if let Some(declared) = self.interposed(address, types)
                && arity(types, &declared) == arity(types, &prototype)
            {
                prototype.noreturn |= declared.noreturn;
                prototype.format = declared.format;
                prototype.format_arg = declared.format_arg;
                prototype.alloc_size = declared.alloc_size;
            }
            return Some(prototype);
        }
        if self.imports.is_driver_entry(address) {
            return self.driver_entry(types);
        }
        self.interposed(address, types)
            .or_else(|| self.manglings.defined(address, types))
    }

    fn through(&self, slot: u64, types: &mut Types) -> Option<Prototype> {
        let (module, name) = self.imports.slots.get(&slot)?;
        self.import(module.as_deref(), name, types)
    }

    fn parameter_names(&self, address: u64) -> Vec<Option<String>> {
        let address = self.imports.stands_for(address);
        if let Some((module, name)) = self.imports.thunks.get(&address) {
            return self.declared_names(module.as_deref(), name);
        }
        if let Some(debug) = self.debug {
            let mut types = Types::new(64);
            if debug.prototype(address, &mut types).is_some() {
                return debug
                    .facts(address, &mut types)
                    .map(|facts| facts.parameters)
                    .unwrap_or_default();
            }
        }
        if self.imports.is_driver_entry(address) {
            return self
                .driver_initialize()
                .map(|signature| {
                    signature
                        .params
                        .iter()
                        .map(|param| param.name.clone())
                        .collect()
                })
                .unwrap_or_default();
        }
        self.imports
            .exports
            .get(&address)
            .and_then(|names| {
                names
                    .iter()
                    .map(|name| self.declared_names(None, name))
                    .find(|names| !names.is_empty())
            })
            .unwrap_or_default()
    }

    fn parameter_names_through(&self, slot: u64) -> Vec<Option<String>> {
        self.imports
            .slots
            .get(&slot)
            .map(|(module, name)| self.declared_names(module.as_deref(), name))
            .unwrap_or_default()
    }

    fn system_call(&self, number: u64) -> Option<SystemCall> {
        let (name, declaration) = self.library.syscall_number(number)?;
        Some(SystemCall {
            name: name.to_owned(),
            arguments: declaration.prototype.as_ref()?.value.params.len(),
        })
    }

    fn debug(&self, address: u64, types: &mut Types) -> Option<DebugStated> {
        self.debug?.facts(address, types)
    }

    fn global(&self, address: u64, types: &mut Types) -> Option<TypeId> {
        self.debug?.global(address, types)
    }

    /// Windows x64's and ARM64's `struct _TEB *` (the native database's,
    /// phnt's), x86-64 glibc's `tcbhead_t *` ([`glibc_tcb`]); none
    /// elsewhere (ELF AArch64's thread control block is two words the ABI
    /// keeps private; kernel-mode code's library has no native database,
    /// and no metadata describes the KPCR its `gs` or `x18` holds).
    fn thread_pointer(&self, types: &mut Types) -> Option<TypeId> {
        let target = self.library.target()?;
        let structure = match (target.arch.as_str(), target.os.as_str()) {
            ("x86_64" | "aarch64", "windows") => {
                let teb = self.library.types().find_map(|(id, ty)| {
                    let LibType::Record(record) = ty else {
                        return None;
                    };
                    (record.key == "struct _TEB" && record.fields.is_some()).then_some(id)
                })?;
                self.convert(types).record(teb)?
            }
            ("x86_64", "linux") => glibc_tcb(types),
            _ => return None,
        };
        Some(types.intern(Type::Pointer(Some(structure))))
    }
}

/// x86-64 glibc's thread control block, `tcbhead_t`, the start of each
/// thread's `struct pthread`, at the thread pointer (glibc's
/// `sysdeps/x86_64/nptl/tls.h`), interned into `types`: only the fields
/// whose offsets code compiled apart from libc.so depends on, so that no
/// glibc release moves them:
///
/// - `tcb` (0): the TCB's own address, which the x86-64 TLS ABI requires
///   at `%fs:0` (TLS variant II; what `__builtin_thread_pointer()` reads);
/// - `self` (0x10): the thread's `struct pthread`, the same address
///   (glibc's `THREAD_SELF`, inlined into every glibc-built library);
/// - `stack_guard` (0x28): the stack protector's canary, at the offset
///   GCC and Clang compile into every protected function
///   (`-mstack-protector-guard-offset`'s default).
///
/// It is 0x30 bytes here, up to `stack_guard`; what follows is glibc's
/// own: `pointer_guard`, which older glibc kept at 0x30, is `__unused` in
/// the libc pair's glibc (its debug information says so; a test checks
/// the three fields against it).
pub fn glibc_tcb(types: &mut Types) -> TypeId {
    let pointer = types.intern(Type::Pointer(None));
    let word = types.intern(Type::UInt(64));
    let field = |offset: u64, ty: TypeId, name: &str| Field {
        offset,
        ty,
        name: Some(name.to_owned()),
    };
    types.intern(Type::Struct(Aggregate {
        name: Some("tcbhead_t".to_owned()),
        size: 0x30,
        fields: vec![
            field(0, pointer, "tcb"),
            field(0x10, pointer, "self"),
            field(0x28, word, "stack_guard"),
        ],
    }))
}

impl LibraryPrototypes<'_> {
    /// The declared interface of the function at `address` as an
    /// interposing definition: that of its name (the first of its names
    /// declared as L2 can hold).
    fn interposed(&self, address: u64, types: &mut Types) -> Option<Prototype> {
        self.imports.exports.get(&address).and_then(|names| {
            names
                .iter()
                .filter(|name| {
                    self.library
                        .function(None, name)
                        .is_some_and(|declaration| declaration.prototype.is_some())
                })
                .find_map(|name| self.import(None, name, types))
        })
    }
}

/// A conversion of library types into one function's [`Types`].
pub(crate) struct Convert<'l, 't> {
    library: &'l TypeLibrary,
    types: &'t mut Types,
    /// Structures and unions converted so far (a recursive one refers to
    /// itself through a pointer).
    seen: BTreeMap<LibId, TypeId>,
    /// Whether a pointer to a structure or union declared but not defined
    /// points to it by name (an empty one of size 0), not to nothing
    /// known ([`Self::naming_incomplete`]).
    incomplete: bool,
    /// The user's definitions that replace the library's records of
    /// their keys ([`Self::replacing`]).
    user: Option<&'l UserTypes>,
}

impl<'l> Convert<'l, '_> {
    /// A conversion of `library`'s types into `types`.
    pub(crate) fn new<'a, 't>(library: &'a TypeLibrary, types: &'t mut Types) -> Convert<'a, 't> {
        Convert {
            library,
            types,
            seen: BTreeMap::new(),
            incomplete: false,
            user: None,
        }
    }

    /// The conversion pointing to a structure or union declared but not
    /// defined by its name (an empty one of size 0): the user's structs
    /// name the table's synthesised ones so
    /// ([`Structs::state`](binbun_decompile::typing::Structs::state)).
    pub(crate) const fn naming_incomplete(mut self) -> Self {
        self.incomplete = true;
        self
    }

    /// The conversion taking the user's definition of a struct or union
    /// ([`UserTypes::record`]) for the library's record of its key,
    /// wherever a library type refers to it.
    pub(crate) const fn replacing(mut self, user: Option<&'l UserTypes>) -> Self {
        self.user = user;
        self
    }

    /// A function type, if L2 can state its parameters' and return
    /// value's types and it has the target's convention: scalars,
    /// pointers, and complete structs and unions passed by value (whose
    /// places lowering finds by the convention's rule, or does not take
    /// the declaration: [`Self::passed`]). A parameter of array
    /// type is a pointer to its element (C11 6.7.6.3p7): System V's
    /// `va_list`, `struct __va_list_tag[1]`, is passed as a pointer to its
    /// one `__va_list_tag`.
    pub(crate) fn signature(&mut self, signature: &LibSignature<LibId>) -> Option<Signature> {
        self.declared(signature)
            .and_then(|(signature, wide)| wide.is_none().then_some(signature))
    }

    /// [`Self::signature`] of a function declared, with the struct or
    /// union it returns by value where no value holds one so wide
    /// ([`Prototype::wide_result`]): the signature then returns none.
    pub(crate) fn declared(
        &mut self,
        signature: &LibSignature<LibId>,
    ) -> Option<(Signature, Option<TypeId>)> {
        if signature.convention.is_some() {
            return None;
        }
        let (returns, wide) = if self.void(signature.ret)? {
            (None, None)
        } else {
            let ty = self.passed(signature.ret)?;
            if self.types.value_width(ty).is_some() {
                (Some(ty), None)
            } else {
                (None, Some(ty))
            }
        };
        let parameters = signature
            .params
            .iter()
            .map(|param| self.parameter(param.ty))
            .collect::<Option<Vec<_>>>()?;
        // A parameter no value holds is in no code type.
        if parameters
            .iter()
            .any(|&ty| self.types.value_width(ty).is_none())
        {
            return None;
        }
        Some((
            Signature {
                parameters,
                returns,
                variadic: signature.variadic,
            },
            wide,
        ))
    }

    /// Whether `id` is `void`, through typedefs (Win32's `VOID`).
    fn void(&self, id: LibId) -> Option<bool> {
        match self.library.ty(id)? {
            LibType::Void => Some(true),
            LibType::Typedef(typedef) => self.void(typedef.target),
            LibType::Bool
            | LibType::Char { .. }
            | LibType::Int { .. }
            | LibType::Float(_)
            | LibType::Pointer(_)
            | LibType::Array { .. }
            | LibType::Function(_)
            | LibType::Record(_)
            | LibType::Enum(_)
            | LibType::Opaque(_) => Some(false),
        }
    }

    /// `id` as a type a value can have: a scalar or a pointer.
    pub(crate) fn value(&mut self, id: LibId) -> Option<TypeId> {
        match self.library.ty(id)? {
            LibType::Typedef(typedef) => self.value(typedef.target),
            LibType::Void
            | LibType::Record(_)
            | LibType::Array { .. }
            | LibType::Function(_)
            | LibType::Opaque(_) => None,
            LibType::Bool
            | LibType::Char { .. }
            | LibType::Int { .. }
            | LibType::Float(_)
            | LibType::Pointer(_)
            | LibType::Enum(_) => self.any(id),
        }
    }

    /// `id` as the type of a parameter or a return value: a value
    /// ([`Self::value`]), or a complete struct or union, passed by value.
    fn passed(&mut self, id: LibId) -> Option<TypeId> {
        match self.library.ty(id)? {
            LibType::Typedef(typedef) => self.passed(typedef.target),
            LibType::Record(_) => self.record(id),
            LibType::Void
            | LibType::Bool
            | LibType::Char { .. }
            | LibType::Int { .. }
            | LibType::Float(_)
            | LibType::Pointer(_)
            | LibType::Array { .. }
            | LibType::Function(_)
            | LibType::Enum(_)
            | LibType::Opaque(_) => self.value(id),
        }
    }

    /// Parameter type `id` as the type its argument has: an array, through
    /// typedefs, is a pointer to its element; any other, what is passed
    /// ([`Self::passed`]).
    fn parameter(&mut self, id: LibId) -> Option<TypeId> {
        match self.library.ty(id)? {
            LibType::Typedef(typedef) => self.parameter(typedef.target),
            &LibType::Array { element, .. } => {
                let pointer = self.pointer(element);
                Some(self.types.intern(pointer))
            }
            LibType::Void
            | LibType::Bool
            | LibType::Char { .. }
            | LibType::Int { .. }
            | LibType::Float(_)
            | LibType::Pointer(_)
            | LibType::Function(_)
            | LibType::Record(_)
            | LibType::Enum(_)
            | LibType::Opaque(_) => self.passed(id),
        }
    }

    /// `id` as any L2 type (what a pointer may point to).
    pub(crate) fn any(&mut self, id: LibId) -> Option<TypeId> {
        let ty = match self.library.ty(id)? {
            LibType::Bool => Type::Bool(8),
            &LibType::Char { signed } => Type::Char { signed },
            &LibType::Int { signed, size } => integer(signed, u16::from(size) * 8),
            LibType::Enum(definition) => enumeration(definition).map_or_else(
                || Type::Int(u16::from(definition.size.unwrap_or(4)) * 8),
                |enumeration| {
                    Type::Enum(Enumeration {
                        macros: self.library.macro_constants(id),
                        ..enumeration
                    })
                },
            ),
            &LibType::Float(format) => Type::Float(float(format)?),
            &LibType::Pointer(target) => self.pointer(target),
            &LibType::Array { element, count } => Type::Array {
                element: self.any(element)?,
                length: count,
            },
            LibType::Typedef(typedef) => return self.any(typedef.target),
            LibType::Record(_) => return self.record(id),
            LibType::Void | LibType::Function(_) | LibType::Opaque(_) => return None,
        };
        Some(self.types.intern(ty))
    }

    /// A pointer to `target`: to code with its signature, to a type L2 can
    /// describe, else `void *`.
    fn pointer(&mut self, target: LibId) -> Type {
        match self.library.ty(target) {
            Some(LibType::Function(signature)) => {
                let signature = signature.clone();
                self.signature(&signature)
                    .map_or(Type::Pointer(None), Type::Code)
            }
            _ => Type::Pointer(self.any(target).or_else(|| self.named(target))),
        }
    }

    /// Record `id`, declared but not defined, as an empty one of size 0
    /// with its name, where the conversion names them
    /// ([`Self::naming_incomplete`]).
    fn named(&mut self, id: LibId) -> Option<TypeId> {
        if !self.incomplete {
            return None;
        }
        let Some(LibType::Record(record)) = self.library.ty(id) else {
            return None;
        };
        if record.fields.is_some() {
            return None;
        }
        let shell = Aggregate {
            name: Some(record.name.clone()?),
            size: 0,
            fields: Vec::new(),
        };
        Some(self.types.intern(if record.union {
            Type::Union(shell)
        } else {
            Type::Struct(shell)
        }))
    }

    /// A structure or union with its byte-aligned fields, if its size is
    /// known. A named one the function's types already hold (converted
    /// for another prototype, or another call's) is that one: C has one
    /// type per tag.
    fn record(&mut self, id: LibId) -> Option<TypeId> {
        if let Some(&seen) = self.seen.get(&id) {
            return Some(seen);
        }
        let Some(LibType::Record(record)) = self.library.ty(id) else {
            return None;
        };
        if let Some(user) = self.user
            && let Some(replaced) = user.record(&record.key)
        {
            // The user's table is whole: its records refer to the
            // user's definitions already.
            let mut convert = Convert::new(user.types(), self.types);
            convert.incomplete = self.incomplete;
            let converted = convert.record(replaced)?;
            self.seen.insert(id, converted);
            return Some(converted);
        }
        let (size, fields) = (record.size?, record.fields.as_ref()?);
        let union = record.union;
        if let Some(name) = &record.name
            && let Some(existing) = self.types.iter().find_map(|(existing, ty)| {
                let (Type::Struct(aggregate) | Type::Union(aggregate)) = ty else {
                    return None;
                };
                let same = aggregate.name.as_ref() == Some(name)
                    && aggregate.size == size
                    && matches!(ty, Type::Union(_)) == union;
                same.then_some(existing)
            })
        {
            self.seen.insert(id, existing);
            return Some(existing);
        }
        let shell = Aggregate {
            name: record.name.clone(),
            size,
            fields: Vec::new(),
        };
        let converted = self.types.intern(if union {
            Type::Union(shell)
        } else {
            Type::Struct(shell)
        });
        self.seen.insert(id, converted);
        let declared = fields;
        let fields: Vec<Field> = declared
            .clone()
            .into_iter()
            .filter(|field| field.bit_width.is_none())
            .filter_map(|field| {
                let bits = field.bit_offset?;
                (bits % 8 == 0).then_some(())?;
                let ty = self.any(field.ty)?;
                // A flexible array member (`char data[]`) has no width:
                // no field of L2's.
                let width = self.types.width(ty)?;
                // A member of a type the user defined at another size
                // would run into the next: no field of L2's.
                if self.replaced(field.ty) {
                    let next = declared
                        .iter()
                        .filter_map(|field| field.bit_offset)
                        .filter(|&offset| !union && offset > bits)
                        .min()
                        .unwrap_or(size * 8);
                    (bits + width <= next).then_some(())?;
                }
                Some(Field {
                    offset: bits / 8,
                    ty,
                    name: field.name,
                })
            })
            .collect();
        if let Some(aggregate) = self.types.aggregate_mut(converted) {
            aggregate.fields = fields;
        }
        Some(converted)
    }

    /// Whether library type `id` is (through typedefs and arrays) a record
    /// the user's definition replaces ([`Self::replacing`]).
    fn replaced(&self, id: LibId) -> bool {
        let Some(user) = self.user else {
            return false;
        };
        let mut id = id;
        for _ in 0..64 {
            match self.library.ty(id) {
                Some(LibType::Typedef(typedef)) => id = typedef.target,
                Some(&LibType::Array { element, .. }) => id = element,
                Some(LibType::Record(record)) => return user.record(&record.key).is_some(),
                Some(
                    LibType::Void
                    | LibType::Bool
                    | LibType::Char { .. }
                    | LibType::Int { .. }
                    | LibType::Float(_)
                    | LibType::Pointer(_)
                    | LibType::Function(_)
                    | LibType::Enum(_)
                    | LibType::Opaque(_),
                )
                | None => return false,
            }
        }
        false
    }
}

/// L2's enumeration of `definition`: its integer (4 bytes where the
/// declaration states no size), signed unless no constant is negative and
/// one needs the top bit, with each constant whose value is known and
/// fits (the first of a name given twice); `None` for a size no C integer
/// has (only 1, 2, 4 and 8 bytes are an enumeration's underlying type).
/// Its constants are enumeration constants; the library says where they
/// are macros (`TypeLibrary::macro_constants`), which a caller sets.
pub fn enumeration(definition: &LibEnum) -> Option<Enumeration> {
    let width = u16::from(definition.size.unwrap_or(4)) * 8;
    if !matches!(width, 8 | 16 | 32 | 64) {
        return None;
    }
    let values = || definition.variants.iter().filter_map(|v| v.value);
    let top = 1i128 << (width - 1);
    let signed = values().any(|v| v < 0) || values().all(|v| v < top);
    let (low, high) = if signed { (-top, top) } else { (0, top * 2) };
    let mask = u128::MAX >> (128 - u32::from(width));
    let mut constants: Vec<(String, u128)> = Vec::new();
    for variant in &definition.variants {
        let Some(value) = variant.value.filter(|v| (low..high).contains(v)) else {
            continue;
        };
        if constants.iter().all(|(name, _)| *name != variant.name) {
            constants.push((variant.name.clone(), value.cast_unsigned() & mask));
        }
    }
    Some(Enumeration {
        name: definition.name.clone(),
        width,
        signed,
        flags: definition.flags,
        macros: false,
        constants,
    })
}

/// A signed or unsigned integer of `bits`.
fn integer(signed: bool, bits: u16) -> Type {
    if signed {
        Type::Int(bits)
    } else {
        Type::UInt(bits)
    }
}

/// L2's format for `format`, if it has one.
fn float(format: FloatFormat) -> Option<Format> {
    match format {
        FloatFormat::Half => Some(Format::Half),
        FloatFormat::Single => Some(Format::Single),
        FloatFormat::Double => Some(Format::Double),
        FloatFormat::X87 => Some(Format::Extended),
        FloatFormat::Quad => None,
    }
}

/// The format string `format` (a declared attribute) gives a function of
/// `signature`: one of the `printf` or `scanf` archetypes (GCC's names,
/// `gnu_` ones included), a declared parameter, describing the variadic
/// arguments right after the declared ones, or (`first` 0) the `va_list`
/// a function that is not variadic takes as its last parameter, right
/// after the string (C's `v` functions); `None` for any other
/// (`strftime`'s).
fn format(format: &LibFormat, signature: &Signature) -> Option<FormatString> {
    let family = match format.archetype.as_str() {
        "printf" | "gnu_printf" => Family::Printf,
        "scanf" | "gnu_scanf" => Family::Scanf,
        _ => return None,
    };
    let string = usize::try_from(format.string).ok()?.checked_sub(1)?;
    let first = usize::try_from(format.first).ok()?;
    let count = signature.parameters.len();
    let list = first == 0 && !signature.variadic && string.checked_add(2) == Some(count);
    let variadic = signature.variadic && string < count && first == count + 1;
    (list || variadic).then_some(FormatString {
        family,
        string,
        list,
    })
}
