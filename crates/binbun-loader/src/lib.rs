//! Loading executables: an ELF, PE or Mach-O file becomes an [`Image`], an address
//! space ([`Memory`]) of its segments with what the file says about the code
//! in it: where its code is (its executable sections), entry point,
//! symbols, imports (by the pointer slot calls go through), the function
//! ranges of its unwind tables, pointers to code stored in its data (from
//! relocations), the pointers to its own addresses that relocations store,
//! its exception tables (Itanium call sites, landing pads, catch clauses;
//! Microsoft x64 scope tables and C++ `FuncInfo`, with their funclets), and
//! what the dynamic loader writes into it (relocated slots, import slots) and
//! makes read-only afterwards (ELF RELRO).
//!
//! A universal ("fat") Mach-O file holds one image per architecture, its
//! slices ([`slices`]); one is opened ([`Image::parse_arch`], [`select`]):
//! the one asked for by name (`x86_64`, `arm64e`), else the first for the
//! host's instruction set, else the first.
//!
//! Memory is what the dynamic loader maps: segments with their
//! permissions. Code is narrower: an ELF file linked without
//! `-z separate-code` maps `.rodata` and `.eh_frame` executable together
//! with `.text`. What is code is answered by [`Image::is_code`] (the
//! executable sections), and [`Image::code_view`] is the memory as code
//! recovery reads it.
//!
//! The image records what the file states, not guesses: whatever is inferred
//! later (the OS from an ELF OS-ABI of 0, which imports never return) is the
//! analyses' business.
//!
//! Parsing is done by the `object` crate (and `gimli` for `.eh_frame`;
//! `cpp_demangle` and `msvc-demangler` name the C++ types of catch clauses).
//! Mach-O's compact unwind tables (`__unwind_info`) are read here
//! ([`compact`]).
//! Relocatable objects (`.o`, and the members of `.a` and `.rlib`
//! archives), which [`Image::parse`] refuses as they map nothing, are
//! laid out at synthetic addresses and relocated as one image by
//! [`relocatable::Linked`].
//! Damaged optional parts (unwind tables, import tables) do not fail the
//! load; they are reported in [`Image::warnings`].

mod compact;
mod elf;
mod lsda;
mod macho;
mod msvc;
mod pe;
pub mod relocatable;

use core::fmt;
use core::ops::Range;
use std::collections::{BTreeMap, BTreeSet};

use binbun_semantics::core::memory::{Memory, Permissions, ReadError, Region};
use object::{
    Object, ObjectSection, ObjectSegment, ObjectSymbol, SectionFlags, SegmentFlags,
    SymbolKind as ObjectSymbolKind,
};

pub use macho::{Slice, preferred, select, slices};

/// The file format.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Format {
    /// ELF.
    Elf,
    /// PE (Windows executables and DLLs).
    Pe,
    /// Mach-O (macOS executables and libraries; one slice of a universal
    /// file).
    MachO,
}

/// The instruction set the file says its code is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Machine {
    /// 32-bit x86.
    X86,
    /// x86-64.
    X86_64,
    /// 64-bit Arm.
    Aarch64,
    /// 32-bit Arm.
    Arm,
    /// Anything else.
    Other,
}

/// A mapped range of the image.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Segment<'data> {
    /// Its first address.
    pub start: u64,
    /// Its size in memory; bytes past the file's are zero.
    pub size: u64,
    /// Its permissions.
    pub permissions: Permissions,
    /// The bytes the file supplies, from `start`.
    pub bytes: &'data [u8],
}

impl Segment<'_> {
    /// The address after its last byte.
    pub const fn end(&self) -> u64 {
        self.start.saturating_add(self.size)
    }
}

/// A named section.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Section {
    /// Its name (`.text`; a Mach-O section's with its segment's,
    /// `__TEXT,__text`, as section names repeat across segments).
    pub name: String,
    /// Its first address.
    pub start: u64,
    /// Its size in memory.
    pub size: u64,
}

/// What a symbol names.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SymbolKind {
    /// Code: a function, or a PE export in an executable section.
    Function,
    /// Data.
    Data,
    /// Unspecified.
    Other,
}

/// Which table a symbol comes from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SymbolSource {
    /// ELF `.symtab`, the COFF symbol table, or Mach-O `LC_SYMTAB`.
    Static,
    /// ELF `.dynsym`.
    Dynamic,
    /// The PE export table, or the Mach-O exports trie.
    Export,
}

/// A symbol defined in the image.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Symbol {
    /// Its name, as stored (mangled names stay mangled), but a Mach-O
    /// name's leading `_`, which C compilers for Apple's platforms
    /// prefix to every C name, dropped (`_main` is `main`, `__ZN3fooEv`
    /// the Itanium mangling `_ZN3fooEv`, `_$s…` the Swift mangling `$s…`);
    /// a name without one (an Objective-C method's `-[C m]`) is as stored.
    pub name: String,
    /// Its address.
    pub address: u64,
    /// Its size, if the file gives one.
    pub size: Option<u64>,
    /// What it names.
    pub kind: SymbolKind,
    /// Where it comes from.
    pub source: SymbolSource,
    /// Whether other modules' references to its name bind to it, so that
    /// it interposes any other definition of the name (ELF): a function in
    /// `.dynsym`, global or weak, of default or protected visibility,
    /// defined under its name's default version (`name@@VERSION`) or
    /// unversioned. Not a non-default version (`name@VERSION`: an older
    /// interface kept for programs linked against it), and never a PE
    /// export or a Mach-O symbol (PE binds each import to a named module,
    /// as Mach-O's two-level namespace binds it to a named library).
    pub interposes: bool,
}

/// A symbol imported from another module, reached through a pointer slot
/// that the dynamic loader fills (an ELF GOT entry, a PE IAT entry, a
/// Mach-O bind's slot: `__got`, `__auth_got`, `__la_symbol_ptr`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Import {
    /// Its name, or `#ordinal` for a PE import by ordinal (a Mach-O name
    /// without its leading `_`, as [`Symbol::name`]).
    pub name: String,
    /// The module it comes from, if the file says: PE's import descriptor's
    /// DLL; ELF's symbol version's library (`DT_VERNEED`'s `vn_file`),
    /// none for an unversioned symbol (whichever module the dynamic loader
    /// finds defining it first); Mach-O's library by its bind's ordinal,
    /// as its install name (`/usr/lib/libSystem.B.dylib`), none for a
    /// flat-namespace or weak lookup, or one in the main executable.
    pub library: Option<String>,
    /// The address of the slot.
    pub slot: u64,
    /// The slot's size in bytes.
    pub size: u8,
    /// Whether the slot holds the import's address from the moment the
    /// program starts and never changes: the dynamic loader fills it
    /// before the program runs and the image makes it read-only after.
    /// ELF: the image asks for every symbol to be bound at load time
    /// (`DF_BIND_NOW` in `DT_FLAGS`, `DF_1_NOW` in `DT_FLAGS_1`, or
    /// `DT_BIND_NOW`), the slot lies in `PT_GNU_RELRO` ([`Image::relro`]),
    /// and the symbol is not weak (an undefined weak symbol may be bound to
    /// 0). PE: the slot (an IAT entry, which the loader overwrites with the
    /// symbol's address during binding: PE/COFF specification, "Import
    /// Address Table") lies in a section without `IMAGE_SCN_MEM_WRITE`
    /// ("the section can be written to"), so the program cannot change it
    /// once bound; delay-load slots, which the helper writes at the first
    /// call, are no imports here.
    /// Mach-O: a bind the dynamic loader makes before the program runs (a
    /// chained fixup, or a non-lazy bind of `LC_DYLD_INFO`; not a lazy
    /// bind's `__la_symbol_ptr` slot, which the stub helper fills at the
    /// first call) in a segment it makes read-only after its fixups
    /// (`SG_READ_ONLY`: `__DATA_CONST`, `__AUTH_CONST`), of a symbol not
    /// weakly imported.
    pub fixed: bool,
}

/// Which unwind table an entry comes from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum UnwindSource {
    /// An ELF `.eh_frame` (Mach-O `__eh_frame`) frame description entry.
    EhFrame,
    /// A PE `.pdata` runtime function entry.
    Pdata,
    /// A Mach-O compact unwind entry (`__unwind_info`), split at the
    /// function starts within it (`LC_FUNCTION_STARTS`): the linker folds
    /// adjacent functions of one encoding into one entry, so an entry's
    /// range alone may hold several.
    UnwindInfo,
}

/// The code range one unwind table entry covers: usually a whole function.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct UnwindEntry {
    /// The first address.
    pub start: u64,
    /// The address after the last.
    pub end: u64,
    /// Where it comes from.
    pub source: UnwindSource,
    /// Whether it covers only part of a function (a PE entry with chained
    /// unwind information, for code split off from its function).
    pub fragment: bool,
    /// Of a fragment, the start of the function it was split off, where
    /// its unwind information says (an x64 `.pdata` entry's chain ends at
    /// that function's own entry).
    pub split_from: Option<u64>,
    /// How the unwind rules at its first address say its code is entered.
    pub frame: EntryFrame,
}

/// How the unwind rules at the start of an [`UnwindEntry`] say its code is
/// entered.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum EntryFrame {
    /// As a function is, by a call: the rules are the initial ones.
    Call,
    /// Inside a frame: the rules are not a function entry's (an ELF FDE
    /// whose own instructions change its CIE's initial rules before its
    /// first row advances: the stack pointer already moved, registers
    /// already saved), or it is a [`fragment`](UnwindEntry::fragment). Code
    /// a compiler split off a function (a cold part), which the function
    /// jumps to with its frame set up; no caller's `call` enters it.
    Inside,
    /// As the outermost frame: the return address is undefined at its
    /// first address, so unwinding stops there. Code that starts a stack
    /// of its own: a process's or thread's start (a `clone` child's).
    Outermost,
}

/// Why a stored value is known to point to code.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PointerSource {
    /// A relocation targets it: the dynamic loader adjusts it as an
    /// address (ELF `R_*_RELATIVE` and absolute relocations, PE base
    /// relocations, Mach-O rebases). Vtables, callback tables, and in non-position-independent
    /// code also jump tables.
    Relocation,
    /// An entry of `.init_array`, `.fini_array` or `.preinit_array`, or of
    /// Mach-O `__init_offsets` (offsets from the image's start).
    InitArray,
    /// An ELF dynamic section entry naming code (`DT_INIT`, `DT_FINI`).
    DynamicTag,
    /// The exception handler of a PE unwind information record.
    UnwindHandler,
}

/// A pointer to executable code stored in the image.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CodePointer {
    /// Where it is stored.
    pub at: u64,
    /// Where it points.
    pub target: u64,
    /// Why it is known to be a pointer.
    pub source: PointerSource,
}

/// The relocation that makes a stored word a pointer ([`Pointer`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Relocation {
    /// An ELF relative relocation (`R_*_RELATIVE`, packed `.relr.dyn`
    /// entries): the load address plus an addend.
    Relative,
    /// An ELF absolute word against a symbol the image defines
    /// (`R_X86_64_64`, `R_AARCH64_ABS64`, `R_386_32`, `R_ARM_ABS32`).
    Absolute,
    /// An ELF GOT slot of a symbol the image defines (`GLOB_DAT`).
    GlobDat,
    /// An ELF PLT slot of a function the image defines (`JUMP_SLOT`).
    JumpSlot,
    /// A PE base relocation of a whole pointer (`DIR64`, `HIGHLOW`).
    Base,
    /// A Mach-O rebase of a whole pointer: a rebase opcode's
    /// (`LC_DYLD_INFO`), whose slot holds the address, or a chained
    /// fixup's (`LC_DYLD_CHAINED_FIXUPS`), whose slot holds the link to the
    /// next fixup and the address as an offset from the image's start.
    Rebase,
}

/// A word the dynamic loader makes one of the image's own addresses: a
/// relocation's slot and the address it holds once the image is loaded
/// at [`Image::base`], the binding the symbol has in the image (an
/// executable or a preloaded library may interpose a default-visibility
/// symbol at run time). Relocations against other modules' symbols,
/// thread-local storage, copy relocations and `IRELATIVE` slots (which
/// hold what a resolver returns) are none.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Pointer {
    /// Where it is stored.
    pub at: u64,
    /// The address it holds.
    pub target: u64,
    /// The relocation that says so.
    pub relocation: Relocation,
}

/// A slot the dynamic loader fills with what a resolver function of the
/// image returns (ELF `IRELATIVE`: a call of the resolver when the image
/// is loaded), with the names that resolve to the same: the interposing
/// `STT_GNU_IFUNC` symbols (default version, global or weak, default or
/// protected visibility) whose value is the resolver, to which other
/// modules' references to those names bind. Its value is the run's, so
/// it is no [`Pointer`].
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Resolved {
    /// Where it is stored.
    pub at: u64,
    /// The resolver's address.
    pub resolver: u64,
    /// The names that resolve to the same, sorted (none where no symbol
    /// names the resolver so).
    pub names: Vec<String>,
}

/// A range the dynamic loader writes when it loads the image: a slot a
/// relocation adjusts (ELF dynamic relocations, PE base relocations,
/// Mach-O rebases), a pointer slot it fills with an import's address (an
/// ELF GOT entry, a PE IAT entry, a Mach-O bind's slot), or data it keeps
/// for itself (the ELF dynamic section, whose
/// `DT_DEBUG` entry it sets). Its bytes in the file are not what the
/// program reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Fixup {
    /// Its first address.
    pub start: u64,
    /// Its size in bytes (an upper bound where the file does not say).
    pub size: u64,
    /// The value it holds once the image is loaded at the addresses it is
    /// linked for (at [`Image::base`]), when that depends on nothing else
    /// (other modules, the run): an ELF relative relocation's target, the
    /// pointer a PE base relocation adjusts (unchanged at the preferred
    /// base), a Mach-O rebase's target, and the address of a function the image defines in its GOT
    /// or PLT slot (ELF `GLOB_DAT`, `JUMP_SLOT`) or in an absolute word
    /// against its symbol (`R_X86_64_64`, `R_AARCH64_ABS64`: pointer
    /// tables), plus the addend: the binding when nothing interposes the
    /// symbol (an executable or preloaded library can, for
    /// default-visibility symbols; protected and hidden ones cannot be).
    /// `None` otherwise.
    pub value: Option<u64>,
}

impl Fixup {
    /// The address after its last byte.
    pub const fn end(&self) -> u64 {
        self.start.saturating_add(self.size)
    }
}

/// Code of a function that only the unwinder jumps to: a `catch` block or
/// a cleanup.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct LandingPad {
    /// The start of the function it belongs to.
    pub function: u64,
    /// Its address.
    pub address: u64,
}

/// The exception table of one function (or cold part of one, which has its
/// own): an Itanium C++ ABI language-specific data area (LSDA, in ELF
/// `.gcc_except_table`), which the function's `.eh_frame` entry points to,
/// and the personality routine that interprets it when an exception
/// unwinds through the function. GCC and Clang emit the same layout for
/// every architecture but 32-bit Arm.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExceptionTable {
    /// The start of the function (of its unwind entry, as
    /// [`LandingPad::function`]).
    pub function: u64,
    /// Where the table is.
    pub lsda: u64,
    /// The personality routine (`__gxx_personality_v0` for C++,
    /// `__gcc_personality_v0` for C cleanups), named by the entry's CIE.
    pub personality: Option<Referent>,
    /// The call-site table, in table order: by address, as the personality
    /// routine searches it. An instruction that may throw outside every
    /// range terminates the program (`std::terminate`).
    pub call_sites: Vec<CallSite>,
}

/// A range of a function's instructions in its exception table: where the
/// unwinder continues when an exception unwinds through a call in it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CallSite {
    /// The first byte of the range.
    pub start: u64,
    /// The byte after it.
    pub end: u64,
    /// The landing pad, or none: the exception unwinds through the
    /// function without running any of its code.
    pub landing_pad: Option<u64>,
    /// What the landing pad is entered for, in the order the personality
    /// routine tries them (its action chain); the landing pad tells them
    /// apart by the selector register. A landing pad without actions is a
    /// [`Clause::Cleanup`]. Empty without a landing pad (or when the
    /// action table is damaged).
    pub clauses: Vec<Clause>,
    /// The selector the personality routine gives the landing pad for each
    /// of [`clauses`](Self::clauses), in the same order: its action's
    /// filter (a catch's type table index, above 0; 0 for a cleanup; below
    /// 0 for an exception specification). The landing pad's code compares
    /// the selector register against these to tell the clauses apart.
    pub selectors: Vec<i64>,
}

/// What a landing pad is entered for (an action of the exception table).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Clause {
    /// `catch (T)`: an exception of type `T` (or derived from it).
    Catch(TypeInfo),
    /// `catch (...)`: any exception.
    CatchAll,
    /// Cleanup only (destructors of locals): entered for every exception,
    /// which the landing pad resumes unwinding (`_Unwind_Resume`) when done.
    Cleanup,
    /// A dynamic exception specification (`throw(A, B)`; `throw()` when
    /// empty): entered for an exception of none of these types, to call
    /// `std::unexpected`.
    Filter(Vec<TypeInfo>),
}

/// A C++ type an exception table names: its `std::type_info` object (an
/// MSVC `TypeDescriptor`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TypeInfo {
    /// The `type_info` object (`_ZTI…`, `??_R0…@8`).
    pub object: Referent,
    /// The type, demangled (`std::exception`), if the object's symbol or
    /// the name it stores is known.
    pub name: Option<String>,
}

/// A function's Microsoft x64 exception handling data: the language-specific
/// data that follows the exception handler's RVA in its unwind information
/// (`.xdata`), as the handler reads it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrameHandler {
    /// The start of the function (of its `.pdata` entry).
    pub function: u64,
    /// The handler (`__C_specific_handler`, `__CxxFrameHandler4`, ...):
    /// its address, the import slot its thunk jumps through, its name.
    pub handler: Referent,
    /// Where the data is.
    pub data: u64,
    /// How far the function's establisher frame (what the runtime hands
    /// its funclets in `rdx`) is below its stack pointer at entry: what its
    /// prologue pushes and allocates before it sets the frame register
    /// (the frame register minus 16 × its offset is then the establisher
    /// frame), or all of it without one (the stack pointer after the
    /// prologue), as its `UNWIND_INFO` codes say; `None` if they are
    /// damaged.
    pub establisher: Option<u64>,
    /// What it says.
    pub table: HandlerTable,
}

/// The language-specific data of a [`FrameHandler`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HandlerTable {
    /// Structured exception handling (`__C_specific_handler`): the scope
    /// table, innermost scopes first, as the handler searches it.
    Scopes(Vec<Scope>),
    /// C++ (`__CxxFrameHandler3`, `__CxxFrameHandler4`): its `FuncInfo`.
    Cxx(CxxTable),
}

/// A guarded range of a scope table (`__try`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Scope {
    /// Its first byte.
    pub start: u64,
    /// The byte after it.
    pub end: u64,
    /// What guards it.
    pub action: ScopeAction,
}

/// What guards a [`Scope`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScopeAction {
    /// `__except (filter)`: when the filter says to handle an exception
    /// (`EXCEPTION_EXECUTE_HANDLER`, 1), the runtime unwinds to the
    /// `__except` block at `target` (code of the function, entered with
    /// the function's frame and the exception code in the return
    /// register).
    Except {
        /// The filter.
        filter: SehFilter,
        /// The `__except` block.
        target: u64,
    },
    /// `__finally`: the termination handler (a funclet), which the runtime
    /// calls when an exception unwinds out of the scope (the function's own
    /// code calls or inlines it on the normal way out).
    Finally(u64),
}

/// The filter of an `__except`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SehFilter {
    /// A constant filter expression (not an address of code):
    /// `EXCEPTION_EXECUTE_HANDLER` is 1.
    Constant(i32),
    /// A filter funclet: it returns what the filter expression says
    /// (`EXCEPTION_EXECUTE_HANDLER`, `EXCEPTION_CONTINUE_SEARCH` 0,
    /// `EXCEPTION_CONTINUE_EXECUTION` -1).
    Funclet(u64),
}

/// The version of a C++ `FuncInfo`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CxxVersion {
    /// `__CxxFrameHandler3`'s fixed-size records.
    V3,
    /// `__CxxFrameHandler4`'s compressed encoding (Visual Studio 2019's
    /// default).
    V4,
}

/// A C++ `FuncInfo`: the states of a function's code (each instruction
/// range has one), what unwinding out of each runs, and the try blocks,
/// which cover ranges of states.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CxxTable {
    /// The encoding.
    pub version: CxxVersion,
    /// Where the `FuncInfo` is.
    pub info: u64,
    /// Per state (its index): the state unwinding goes to next, and what
    /// it runs.
    pub unwind: Vec<UnwindState>,
    /// The try blocks, innermost first.
    pub tries: Vec<TryBlock>,
    /// The IP-to-state map, of the function and its funclets (`FuncInfo`
    /// v3 maps them together; v4 a map per part, merged): from each address
    /// on (to the next's), the state (-1: none), sorted.
    pub states: Vec<StateRange>,
}

/// A state's entry of a [`CxxTable`]'s unwind map.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnwindState {
    /// The state unwinding goes to after it (-1: out of the function).
    pub next: i32,
    /// The unwind funclet it runs (destructors of the locals that this
    /// state constructed), if one. A destructor that `__CxxFrameHandler4`
    /// calls directly with the object's frame offset is no funclet
    /// ([`destructor`](Self::destructor)).
    pub action: Option<u64>,
    /// The destructor `__CxxFrameHandler4` calls directly, if it does.
    pub destructor: Option<Destructor>,
}

/// A destructor an unwind map entry of `__CxxFrameHandler4` calls itself,
/// without a funclet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Destructor {
    /// The destructor (a function, called with the object's address).
    pub function: u64,
    /// The object's offset from the establisher frame.
    pub object: i32,
    /// Whether the frame holds a pointer to the object rather than the
    /// object.
    pub indirect: bool,
}

/// A try block of a [`CxxTable`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TryBlock {
    /// The lowest state of its body.
    pub low: i32,
    /// The highest state of its body.
    pub high: i32,
    /// The highest state of its catch blocks.
    pub catch_high: i32,
    /// Its catch blocks, in the order they are tried.
    pub catches: Vec<Catch>,
}

/// A catch block of a [`TryBlock`] (a `HandlerType`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Catch {
    /// Its adjectives (`const` 1, `volatile` 2, by reference 8, `catch
    /// (...)` 0x40).
    pub adjectives: u32,
    /// The type caught, by its `TypeDescriptor`; none for `catch (...)`.
    pub ty: Option<TypeInfo>,
    /// The frame offset of the catch object (from the function's
    /// establisher frame), if the catch names one.
    pub object: Option<i32>,
    /// The catch funclet: called with the establisher frame, it returns
    /// where the function goes on.
    pub funclet: u64,
    /// Where the function goes on after it, when the table says
    /// (`__CxxFrameHandler4`).
    pub continuations: Vec<u64>,
}

/// An entry of a [`CxxTable`]'s IP-to-state map.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StateRange {
    /// The first address of the range.
    pub start: u64,
    /// Its state (-1: none).
    pub state: i32,
}

/// Code of a function that its exception handler calls (with the
/// function's frame, as its establisher frame): a separate function in the
/// binary, but a part of the function in the source.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Funclet {
    /// The function it belongs to (its outermost: a funclet's own
    /// funclets belong to its function).
    pub function: u64,
    /// Its address.
    pub address: u64,
    /// What it is.
    pub kind: FuncletKind,
}

/// What a [`Funclet`] is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FuncletKind {
    /// An `__except` filter expression.
    Filter,
    /// A `__finally` block.
    Finally,
    /// A C++ catch block.
    Catch,
    /// A C++ unwind action (destructors of locals).
    Unwind,
}

/// What a pointer in an exception table refers to: an address, read
/// directly or through a slot (an indirect pointer, such as a GOT entry),
/// and the symbol there.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Referent {
    /// The address, if known: an imported symbol's is not until the
    /// dynamic loader fills its slot.
    pub address: Option<u64>,
    /// The slot the pointer is read from, if indirect.
    pub slot: Option<u64>,
    /// The symbol at the address, or imported through the slot, as stored
    /// (mangled).
    pub symbol: Option<String>,
}

/// The parts of a file that can be damaged without failing the load.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Part {
    /// Symbol tables.
    Symbols,
    /// The import table or dynamic relocations.
    Imports,
    /// The PE export table, or the Mach-O exports trie.
    Exports,
    /// `.eh_frame` (Mach-O `__eh_frame`).
    EhFrame,
    /// `.pdata`.
    Pdata,
    /// Mach-O `__unwind_info`.
    UnwindInfo,
    /// Mach-O `LC_FUNCTION_STARTS`.
    FunctionStarts,
    /// Relocations.
    Relocations,
    /// An exception table (ELF `.gcc_except_table`).
    ExceptionTable,
}

/// A damaged part, skipped (wholly or from where the damage starts).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Warning {
    /// Which part.
    pub part: Part,
    /// What is wrong.
    pub message: String,
}

/// Why a file does not load.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LoadError {
    /// The file is no object file the parser understands, or its headers
    /// are damaged.
    Parse(String),
    /// An object file of another format (COFF objects, 32-bit Mach-O,
    /// ...).
    UnsupportedFormat,
    /// An object file without a loaded image (an ELF relocatable object, a
    /// Mach-O object file).
    NoSegments,
    /// A universal Mach-O file without a slice of the architecture asked
    /// for.
    NoSlice {
        /// The architecture asked for.
        arch: String,
        /// The file's slices' architectures.
        available: Vec<String>,
    },
}

impl fmt::Display for LoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Parse(message) => write!(f, "cannot parse the file: {message}"),
            Self::UnsupportedFormat => f.write_str("not an ELF, PE or 64-bit Mach-O file"),
            Self::NoSegments => f.write_str("the file maps nothing into memory"),
            Self::NoSlice { arch, available } => write!(
                f,
                "the universal file has no {arch} slice (it has {})",
                available.join(", ")
            ),
        }
    }
}

impl std::error::Error for LoadError {}

/// A loaded executable or shared library.
#[derive(Clone, Debug)]
pub struct Image<'data> {
    /// The file format.
    pub format: Format,
    /// The instruction set.
    pub machine: Machine,
    /// The slice of a universal Mach-O file the image is, if it is one.
    pub slice: Option<Slice>,
    /// The address the file is linked to load at: a PE file's image base,
    /// an ELF file's lowest segment page (0 if position-independent), a
    /// Mach-O file's header's (its `__TEXT` segment's start).
    /// Other tools may load it elsewhere; addresses here count from this.
    pub base: u64,
    /// Whether its code is position independent, so that no immediate
    /// operand is one of its addresses (it computes them from the program
    /// counter): an ELF file linked at 0 (a shared library or a PIE), a
    /// Mach-O file but an executable without `MH_PIE`; never a PE file.
    pub position_independent: bool,
    /// Whether it is Windows kernel-mode code (a driver, the kernel's own
    /// modules): a PE file for the native subsystem
    /// (`IMAGE_SUBSYSTEM_NATIVE`, which user-mode programs that run before
    /// Win32 does, such as smss.exe, share) that imports from the kernel
    /// (`ntoskrnl.exe`), the HAL (`hal.dll`) or a driver (a `.sys` module:
    /// `fltmgr.sys`, `ndis.sys`). Its imports are the kernel's, its thread
    /// pointer (`gs`) the processor's control region (KPCR), not a TEB.
    pub kernel: bool,
    /// The entry point, if the file has one (Mach-O: `LC_MAIN`'s, or
    /// `LC_UNIXTHREAD`'s program counter).
    pub entry: Option<u64>,
    /// The mapped ranges, sorted by address, not overlapping (not a
    /// Mach-O segment without access, `__PAGEZERO`).
    pub segments: Vec<Segment<'data>>,
    /// The sections.
    pub sections: Vec<Section>,
    /// The code: the parts of executable segments that executable sections
    /// (ELF `SHF_EXECINSTR`, PE `IMAGE_SCN_MEM_EXECUTE`, Mach-O
    /// `S_ATTR_PURE_INSTRUCTIONS` or `S_ATTR_SOME_INSTRUCTIONS`) cover; the
    /// executable segments whole if no executable section lies in one (an
    /// ELF file without section headers). Sorted, not overlapping, each
    /// within one segment.
    pub code: Vec<Range<u64>>,
    /// The symbols the image defines.
    pub symbols: Vec<Symbol>,
    /// The symbols it imports.
    pub imports: Vec<Import>,
    /// The starts of its functions that the linker lists (Mach-O
    /// `LC_FUNCTION_STARTS`, those in [`Image::code`]), sorted.
    pub function_starts: Vec<u64>,
    /// Its unwind table entries, sorted by address.
    pub unwind: Vec<UnwindEntry>,
    /// Pointers to code stored in it, sorted by where they are stored.
    pub code_pointers: Vec<CodePointer>,
    /// The pointers to its own addresses that relocations store (to code
    /// or data), sorted by where they are stored.
    pub pointers: Vec<Pointer>,
    /// The slots the dynamic loader fills with what a resolver of the
    /// image returns, sorted by where they are stored.
    pub resolved: Vec<Resolved>,
    /// Landing pads, sorted by address.
    pub landing_pads: Vec<LandingPad>,
    /// Exception tables, sorted by function: those of `.eh_frame` entries
    /// (ELF), with the landing pads of [`Image::landing_pads`].
    pub exception_tables: Vec<ExceptionTable>,
    /// Microsoft x64 exception handling data, by function (PE `.pdata`),
    /// in `.pdata` order.
    pub frame_handlers: Vec<FrameHandler>,
    /// The funclets [`Image::frame_handlers`] name, sorted by address.
    pub funclets: Vec<Funclet>,
    /// What the dynamic loader writes when it loads the image, sorted by
    /// start. Without ELF section headers the dynamic relocations are not
    /// found; then fixups of unknown value cover every segment.
    pub fixups: Vec<Fixup>,
    /// The ranges of writable segments the dynamic loader makes read-only
    /// once it has relocated the image (ELF `PT_GNU_RELRO`, its end rounded
    /// down to a page as loaders do; Mach-O segments flagged
    /// `SG_READ_ONLY`), sorted by start.
    pub relro: Vec<Range<u64>>,
    /// Damaged parts that were skipped.
    pub warnings: Vec<Warning>,
}

impl<'data> Image<'data> {
    /// Loads the ELF, PE or Mach-O file `data`; of a universal Mach-O
    /// file, the slice for the host's instruction set, else the first
    /// ([`Image::parse_arch`]).
    ///
    /// # Errors
    ///
    /// When `data` is not an ELF, PE or 64-bit Mach-O file, its headers
    /// are damaged, or it maps nothing.
    pub fn parse(data: &'data [u8]) -> Result<Self, LoadError> {
        Self::parse_arch(data, None)
    }

    /// Loads the ELF, PE or Mach-O file `data`; of a universal Mach-O
    /// file, the slice of architecture `arch` (`x86_64`, `x86_64h`,
    /// `arm64`, `arm64e`: [`Slice::arch`]), or without one the slice for
    /// the host's instruction set, else the first ([`select`]). Any other
    /// file is its one image, whatever `arch` says.
    ///
    /// # Errors
    ///
    /// When `data` is not an ELF, PE or 64-bit Mach-O file, its headers
    /// are damaged, it maps nothing, or a universal file has no slice of
    /// `arch`.
    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "object's format enums are non-exhaustive; every other format is unsupported"
    )]
    pub fn parse_arch(data: &'data [u8], arch: Option<&str>) -> Result<Self, LoadError> {
        let (data, slice) = select(data, arch)?;
        let file = object::File::parse(data).map_err(|e| LoadError::Parse(e.to_string()))?;
        let format = match file.format() {
            object::BinaryFormat::Elf => Format::Elf,
            object::BinaryFormat::Pe => Format::Pe,
            object::BinaryFormat::MachO if matches!(file, object::File::MachO64(_)) => {
                Format::MachO
            }
            _ => return Err(LoadError::UnsupportedFormat),
        };
        if let object::File::MachO64(macho) = &file
            && macho::is_object(macho)
        {
            return Err(LoadError::NoSegments);
        }
        let mut image = Self {
            format,
            machine: machine(file.architecture()),
            slice,
            base: 0,
            position_independent: false,
            kernel: false,
            entry: None,
            segments: segments(&file)?,
            sections: Vec::new(),
            code: Vec::new(),
            symbols: Vec::new(),
            imports: Vec::new(),
            function_starts: Vec::new(),
            unwind: Vec::new(),
            code_pointers: Vec::new(),
            pointers: Vec::new(),
            resolved: Vec::new(),
            landing_pads: Vec::new(),
            exception_tables: Vec::new(),
            frame_handlers: Vec::new(),
            funclets: Vec::new(),
            fixups: Vec::new(),
            relro: Vec::new(),
            warnings: Vec::new(),
        };
        if image.segments.is_empty() {
            return Err(LoadError::NoSegments);
        }
        image.base = match format {
            Format::Pe => file.relative_address_base(),
            Format::Elf => image.segments.first().map_or(0, |s| s.start & !0xfff),
            // The segment that maps the header, at the file's start.
            Format::MachO => file
                .segments()
                .find(|s| matches!(s.file_range(), (0, size) if size != 0))
                .map_or(0, |s| s.address()),
        };
        image.position_independent = format == Format::Elf && image.base == 0;
        image.sections = sections(&file);
        image.code = code(&file, &image.segments);
        // An entry point of 0 (shared libraries, DLLs without one) is none.
        // Mach-O's is set by its specifics (`object` gives `LC_MAIN`'s as
        // a file offset).
        image.entry = Some(file.entry()).filter(|&entry| entry != 0 && image.is_mapped(entry));
        let interposing = match &file {
            object::File::Elf32(elf_file) => elf::interposing(elf_file),
            object::File::Elf64(elf_file) => elf::interposing(elf_file),
            _ => BTreeSet::new(),
        };
        let resolvers = match &file {
            object::File::Elf32(elf_file) => elf::resolver_names(elf_file),
            object::File::Elf64(elf_file) => elf::resolver_names(elf_file),
            _ => BTreeMap::new(),
        };
        image.symbols = symbols(&file, &interposing);
        match &file {
            object::File::Elf32(elf_file) => {
                let headers = elf::program_headers(elf_file);
                elf::load(&file, &headers, &elf::libraries(elf_file), &mut image);
            }
            object::File::Elf64(elf_file) => {
                let headers = elf::program_headers(elf_file);
                elf::load(&file, &headers, &elf::libraries(elf_file), &mut image);
            }
            object::File::Pe32(pe) => pe::load(pe, &mut image),
            object::File::Pe64(pe) => pe::load(pe, &mut image),
            object::File::MachO64(macho) => {
                macho::load(macho, &mut image);
                elf::eh_frame(&file, &mut image);
            }
            _ => return Err(LoadError::UnsupportedFormat),
        }
        for slot in &mut image.resolved {
            slot.names = resolvers.get(&slot.resolver).cloned().unwrap_or_default();
        }
        image.order(&file);
        Ok(image)
    }

    /// Sorts what the format's loader found into address order, without
    /// duplicates, and names the exception tables' LSDAs (`file`'s).
    fn order(&mut self, file: &object::File<'_>) {
        self.unwind
            .sort_unstable_by_key(|entry| (entry.start, entry.end));
        self.function_starts.sort_unstable();
        self.function_starts.dedup();
        self.code_pointers
            .sort_unstable_by_key(|p| (p.at, p.target));
        self.code_pointers.dedup_by_key(|p| (p.at, p.target));
        self.pointers.sort_unstable_by_key(|p| (p.at, p.target));
        self.pointers.dedup_by_key(|p| (p.at, p.target));
        self.resolved.sort_unstable_by_key(|slot| slot.at);
        self.resolved.dedup_by_key(|slot| slot.at);
        self.landing_pads
            .sort_unstable_by_key(|p| (p.address, p.function));
        self.landing_pads.dedup();
        self.exception_tables
            .sort_by_key(|table| (table.function, table.lsda));
        // After sorting the pointers, which it searches.
        let word = if file.is_64() { 8 } else { 4 };
        lsda::name(self, word, file.is_little_endian());
        self.fixups
            .sort_unstable_by_key(|fixup| (fixup.start, fixup.size));
        self.fixups.dedup();
        self.relro.sort_unstable_by_key(|range| range.start);
    }

    /// The segment `address` is in.
    pub fn segment(&self, address: u64) -> Option<&Segment<'data>> {
        let index = self
            .segments
            .partition_point(|s| s.start <= address)
            .checked_sub(1)?;
        self.segments.get(index).filter(|s| address < s.end())
    }

    /// Whether `address` is mapped.
    pub fn is_mapped(&self, address: u64) -> bool {
        self.segment(address).is_some()
    }

    /// Whether `address` is code: in [`Image::code`]. Mapped executable is
    /// not enough: an executable segment may hold read-only data.
    pub fn is_code(&self, address: u64) -> bool {
        self.code_range(address).is_some()
    }

    /// The range of [`Image::code`] that `address` is in.
    fn code_range(&self, address: u64) -> Option<&Range<u64>> {
        let index = self
            .code
            .partition_point(|range| range.start <= address)
            .checked_sub(1)?;
        self.code.get(index).filter(|range| address < range.end)
    }

    /// The image's memory as code recovery reads it: executable only where
    /// it holds code ([`Image::is_code`]).
    pub const fn code_view(&self) -> CodeView<'_, 'data> {
        CodeView { image: self }
    }

    /// Records that `part` is damaged.
    fn warn(&mut self, part: Part, message: impl fmt::Display) {
        self.warnings.push(Warning {
            part,
            message: message.to_string(),
        });
    }

    /// The `size`-byte little- or big-endian value at `address`.
    fn read_word(&self, address: u64, size: usize, little: bool) -> Option<u64> {
        let mut bytes = [0u8; 8];
        let buffer = bytes.get_mut(..size)?;
        if self.read(address, buffer) != Ok(size) {
            return None;
        }
        if !little {
            buffer.reverse();
        }
        Some(u64::from_le_bytes(bytes))
    }

    /// Records `target`, stored at `at`, if it points to code.
    fn code_pointer(&mut self, at: u64, target: u64, source: PointerSource) {
        if self.is_code(target) {
            self.code_pointers.push(CodePointer { at, target, source });
        }
    }
}

/// An image's memory as code recovery reads it ([`Image::code_view`]): the
/// same bytes, but executable only in [`Image::code`], so that read-only
/// data mapped executable along with the code is not decoded.
#[derive(Clone, Copy, Debug)]
pub struct CodeView<'a, 'data> {
    image: &'a Image<'data>,
}

impl Memory for CodeView<'_, '_> {
    fn read(&self, address: u64, buffer: &mut [u8]) -> Result<usize, ReadError> {
        self.image.read(address, buffer)
    }

    /// The range of code `address` is in, or the part of its segment
    /// between two ranges of code, not executable.
    fn region(&self, address: u64) -> Option<Region> {
        let segment = self.image.segment(address)?;
        if let Some(range) = self.image.code_range(address) {
            return Some(Region {
                start: range.start,
                end: range.end,
                permissions: segment.permissions,
            });
        }
        let code = &self.image.code;
        let next = code.partition_point(|range| range.start <= address);
        let after_previous = next
            .checked_sub(1)
            .and_then(|index| code.get(index))
            .map_or(segment.start, |range| range.end.max(segment.start));
        let before_next = code
            .get(next)
            .map_or(segment.end(), |range| range.start.min(segment.end()));
        Some(Region {
            start: after_previous,
            end: before_next,
            permissions: Permissions {
                execute: false,
                ..segment.permissions
            },
        })
    }
}

/// The defined symbols of the static and dynamic symbol tables; those of
/// the dynamic table at `interposing` (indices) interpose. Not a local
/// symbol named as a section is: a COFF section's own symbol (`.text`)
/// stands at the start of each object's part of it, where that object's
/// first function is, and names none.
#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "object's symbol kinds are non-exhaustive; the rest are neither code nor data"
)]
fn symbols(file: &object::File<'_>, interposing: &BTreeSet<usize>) -> Vec<Symbol> {
    let sections: BTreeSet<&str> = file
        .sections()
        .filter_map(|section| section.name().ok())
        .collect();
    let tables = [
        (file.symbols(), SymbolSource::Static),
        (file.dynamic_symbols(), SymbolSource::Dynamic),
    ];
    tables
        .into_iter()
        .flat_map(|(symbols, source)| symbols.map(move |symbol| (symbol, source)))
        .filter(|(symbol, _)| symbol.is_definition() && symbol.address() != 0)
        .filter(|(symbol, _)| {
            symbol.is_global() || !symbol.name().is_ok_and(|name| sections.contains(name))
        })
        .filter_map(|(symbol, source)| {
            let kind = match symbol.kind() {
                ObjectSymbolKind::Text => SymbolKind::Function,
                ObjectSymbolKind::Data | ObjectSymbolKind::Tls => SymbolKind::Data,
                _ => SymbolKind::Other,
            };
            Some(Symbol {
                name: symbol.name().ok()?.to_owned(),
                address: symbol.address(),
                size: Some(symbol.size()).filter(|&size| size != 0),
                kind,
                source,
                interposes: source == SymbolSource::Dynamic
                    && interposing.contains(&symbol.index().0),
            })
        })
        .collect()
}

/// The machine of `architecture`.
#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "object's architectures are non-exhaustive; binbun decodes only these"
)]
fn machine(architecture: object::Architecture) -> Machine {
    match architecture {
        object::Architecture::I386 => Machine::X86,
        object::Architecture::X86_64 | object::Architecture::X86_64_X32 => Machine::X86_64,
        object::Architecture::Aarch64 | object::Architecture::Aarch64_Ilp32 => Machine::Aarch64,
        object::Architecture::Arm => Machine::Arm,
        _ => Machine::Other,
    }
}

/// The loadable segments of `file`, sorted, with overlapping ones dropped.
fn segments<'data>(file: &object::File<'data>) -> Result<Vec<Segment<'data>>, LoadError> {
    let mut segments = Vec::new();
    for segment in file.segments() {
        let bytes = segment
            .data()
            .map_err(|e| LoadError::Parse(e.to_string()))?;
        let size = segment.size();
        // A Mach-O segment without access (`__PAGEZERO`) maps nothing the
        // program can read.
        let inaccessible =
            matches!(segment.flags(), SegmentFlags::MachO { initprot, .. } if initprot.0 == 0);
        if size == 0 || inaccessible {
            continue;
        }
        segments.push(Segment {
            start: segment.address(),
            size,
            permissions: permissions(segment.flags()),
            bytes: bytes
                .get(..usize::try_from(size).unwrap_or(usize::MAX).min(bytes.len()))
                .unwrap_or(bytes),
        });
    }
    segments.sort_unstable_by_key(|s| s.start);
    // A later segment overlapping an earlier one is dropped, so that every
    // address has one segment (ELF segments may share a page, never an
    // address).
    let mut end = 0;
    segments.retain(|s| {
        let keep = s.start >= end;
        if keep {
            end = s.end();
        }
        keep
    });
    Ok(segments)
}

/// The permissions of segment flags.
#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "object's segment flags are non-exhaustive; other formats are not loaded"
)]
fn permissions(flags: SegmentFlags) -> Permissions {
    match flags {
        SegmentFlags::Elf { p_flags, .. } => Permissions {
            read: p_flags.contains(object::elf::PF_R),
            write: p_flags.contains(object::elf::PF_W),
            execute: p_flags.contains(object::elf::PF_X),
        },
        SegmentFlags::Coff { characteristics } => Permissions {
            read: characteristics.contains(object::pe::IMAGE_SCN_MEM_READ),
            write: characteristics.contains(object::pe::IMAGE_SCN_MEM_WRITE),
            execute: characteristics.contains(object::pe::IMAGE_SCN_MEM_EXECUTE),
        },
        SegmentFlags::MachO { initprot, .. } => Permissions {
            read: initprot.contains(object::macho::VM_PROT_READ),
            write: initprot.contains(object::macho::VM_PROT_WRITE),
            execute: initprot.contains(object::macho::VM_PROT_EXECUTE),
        },
        _ => Permissions::default(),
    }
}

/// The sections of `file` with a name and an address; a Mach-O section's
/// name after its segment's (`__TEXT,__text`).
fn sections(file: &object::File<'_>) -> Vec<Section> {
    file.sections()
        .filter(|section| section.address() != 0)
        .filter_map(|section| {
            let name = section.name().ok()?;
            Some(Section {
                name: match section.segment_name() {
                    Ok(Some(segment)) => format!("{segment},{name}"),
                    Ok(None) | Err(_) => name.to_owned(),
                },
                start: section.address(),
                size: section.size(),
            })
        })
        .collect()
}

/// The code of `file`, whose segments are `segments` ([`Image::code`]).
fn code(file: &object::File<'_>, segments: &[Segment<'_>]) -> Vec<Range<u64>> {
    let executable = || segments.iter().filter(|s| s.permissions.execute);
    // Each executable section's parts in executable segments.
    let mut parts: Vec<Range<u64>> = file
        .sections()
        .filter(|section| is_executable_section(section.flags()))
        .map(|section| section.address()..section.address().saturating_add(section.size()))
        .flat_map(|section| {
            executable().map(move |segment| {
                section.start.max(segment.start)..section.end.min(segment.end())
            })
        })
        .filter(|range| !range.is_empty())
        .collect();
    if parts.is_empty() {
        return executable().map(|s| s.start..s.end()).collect();
    }
    parts.sort_unstable_by_key(|range| range.start);
    // Overlapping sections (which linkers do not write) are merged; parts
    // that overlap lie in the same segment, as segments do not overlap.
    let mut code: Vec<Range<u64>> = Vec::with_capacity(parts.len());
    for range in parts {
        match code.last_mut() {
            Some(last) if range.start < last.end => last.end = last.end.max(range.end),
            Some(_) | None => code.push(range),
        }
    }
    code
}

/// Whether section flags `flags` mark code that is loaded.
#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "object's section flags are non-exhaustive; other formats are not loaded"
)]
fn is_executable_section(flags: SectionFlags) -> bool {
    match flags {
        SectionFlags::Elf { sh_flags, .. } => {
            sh_flags.contains(object::elf::SHF_ALLOC)
                && sh_flags.contains(object::elf::SHF_EXECINSTR)
        }
        SectionFlags::Coff { characteristics } => {
            characteristics.contains(object::pe::IMAGE_SCN_MEM_EXECUTE)
        }
        SectionFlags::MachO { flags, .. } => flags.intersects(
            object::macho::S_ATTR_PURE_INSTRUCTIONS.with(object::macho::S_ATTR_SOME_INSTRUCTIONS),
        ),
        _ => false,
    }
}

impl Memory for Image<'_> {
    fn read(&self, address: u64, buffer: &mut [u8]) -> Result<usize, ReadError> {
        let mut done = 0;
        let mut at = address;
        while done < buffer.len() {
            let Some(segment) = self.segment(at) else {
                break;
            };
            // Within the segment: file bytes, then zeros.
            let offset = at - segment.start;
            let available = usize::try_from(segment.end() - at).unwrap_or(usize::MAX);
            let Some(rest) = buffer.get_mut(done..) else {
                break;
            };
            let count = rest.len().min(available);
            let Some(out) = rest.get_mut(..count) else {
                break;
            };
            let file = usize::try_from(offset)
                .ok()
                .and_then(|offset| segment.bytes.get(offset..))
                .unwrap_or_default();
            let copied = file.len().min(count);
            if let (Some(dest), Some(source)) = (out.get_mut(..copied), file.get(..copied)) {
                dest.copy_from_slice(source);
            }
            if let Some(zeros) = out.get_mut(copied..) {
                zeros.fill(0);
            }
            done += count;
            at = segment.end();
        }
        Ok(done)
    }

    fn region(&self, address: u64) -> Option<Region> {
        self.segment(address).map(|segment| Region {
            start: segment.start,
            end: segment.end(),
            permissions: segment.permissions,
        })
    }
}
