//! One L1 function to goto-only L2.
//!
//! [`lower`] turns an L1 function ([`binbun_ssa`]) into an L2 function
//! ([`binbun_ast`]) that says the same thing with variables, expressions,
//! labels and gotos, and the [`Mapping`] of where its parameters, return
//! value and calls are in L1's state. In order:
//!
//! 1. **Facts.** The L1 analyses lowering reads ([`Facts`]: constant
//!    propagation over the read-only memory, the stack analysis
//!    ([`Stack`]), dominators) are the caller's, taken from the pass
//!    manager that ran the L1 passes before lowering
//!    ([`Facts::of`]), so one computation serves both: lowering computes
//!    none itself. Copies are seen through: a block parameter whose
//!    arguments are all one value, a whole-width extraction, the low or
//!    high half of a concatenation, the low part of an extension, are that
//!    value; so are `a & a`, `a | a`, and a pure operation repeating an
//!    earlier one of its block on the same operands (`test eax, eax`
//!    extracts `eax` twice). `a ^ a` and `a - a` are 0.
//! 2. **Calls.** Each call's arguments and result come from the callee's
//!    declared prototype (scalar parameters in the convention's integer and
//!    vector registers, then the stack), else its [`Interface`] (what
//!    lowering found it reads and returns), else the convention's whole
//!    integer argument set, each argument and the result untyped (`bits`:
//!    no evidence for the type passes), in a signature that lists exactly
//!    the arguments passed (so C declares it with a prototype). The
//!    arguments a variadic prototype does not declare come from its
//!    declared format string where that is a constant string in read-only
//!    data the parser takes ([`format`](crate::format): exactly the
//!    arguments, with their types, as declared evidence). Otherwise, and
//!    for a callee known only by its address or by a variadic
//!    [`Interface`], they are the convention's
//!    remaining integer argument registers up to the last one whose value
//!    at the call is not undefined on every path: a register another call
//!    clobbered passes nothing, but the caller's own entry value untouched
//!    stays an argument, since passing a parameter on in place looks the
//!    same; only the caller's callers could tell (a later, caller-informed
//!    pass could drop a parameter no caller sets). A jump out of the
//!    function to a known address that is no function's entry
//!    ([`Context::functions`]) and has no prototype is a `ForeignJump`;
//!    any other is a tail call.
//!    A system call reads its number register and, where the number is a
//!    constant the declarations know ([`Prototypes::system_call`]), only
//!    that call's arguments (`read`: three); else every system call
//!    argument register ([`Convention::system_call`]).
//! 3. **The frame.** Every load, store and stack argument at a known offset
//!    from the entry stack pointer is an access; overlapping accesses form
//!    a slot (a call's push of its return address is none: it is not
//!    lowered). A stack address used as a value (stored, passed,
//!    returned, aligned, indexed: used by an operation as wide as an
//!    address other than offset arithmetic) may reach any byte above it;
//!    one passed only at declared parameters, as far as their largest
//!    type; once a variadic definition is recognised, one in its save area
//!    or its `va_list`, only that object's bytes (nothing else uses an
//!    address in them as a value). A stack address escaping where none of
//!    these is seen may reach any byte; so may one below the entry stack
//!    pointer reaching any byte above it, since code may step back from it
//!    (an enclosing object's `container_of`), but where the function's own
//!    code does not (what it computes from such an address and accesses,
//!    stores, passes or joins in a block parameter adds only constants
//!    that are not negative to it) and the reading view assumes that no
//!    code it is passed or stored to does
//!    ([`Context::assume_forward_reach`]): there it reaches only the bytes
//!    above it. A slot no such address reaches is
//!    as in a frame where none escapes: read only, at or above the stack
//!    arguments, with one shape, a stack parameter; written, of one shape,
//!    below the entry stack pointer, a local variable, as is one written
//!    whole only and read in parts only as calls' stack arguments (pushed
//!    as 8 bytes and passed as 4: the arguments are the variable's bits);
//!    else a
//!    `Frame(offset)` variable of its own. Where such a slot in the
//!    function's own bytes is accessed in several shapes, and each reuse
//!    of its bytes (a read joined with every store that may have written
//!    one of its bytes last on some path from the entry, transitively: a
//!    compiler shares a spill slot among values of different types) is
//!    one value's (written, and every access all of it), each reuse is a
//!    slot of its own, a local variable.
//!    The slots reached are memory:
//!    one `Frame` variable from the lowest address that may reach any byte
//!    above it, spanning every accessed and address-taken byte above it
//!    below the entry stack pointer, and one per other reach with the
//!    slots it overlaps, cut around the local variables of slots that only save a
//!    callee-saved register or the link register (store its entry value,
//!    or what was loaded back from the slot: saved again after a
//!    restore), so neither is a parameter, and one per slot
//!    above it. The return
//!    address's bytes, and slots of more than 64 bytes, are always memory.
//!    Before that cut, an address whose every use is as a call's argument
//!    at a declared parameter pointing to one complete type `T` (not a
//!    character type: `stat(path, &st)`, `time(&t)`, `scanf`'s `%d`) is
//!    promoted: its `sizeof(T)` bytes, below the entry stack pointer, are
//!    a `Frame` variable of type `T` of their own (the frame is cut around
//!    them too), where no other address is taken among them, every slot
//!    they overlap lies inside them, and no address below them may reach
//!    them (one used otherwise, or passed where no declaration bounds it,
//!    may reach any byte above it).
//!    Each piece of the memory below the entry stack pointer that is not
//!    one value (nor a promoted object, nor the `va_list`) is a frame
//!    struct (`Function::frames`): a field per slot inside it, at its
//!    offset, named by its offset from the entry stack pointer (`at_m28`:
//!    entry−0x28; `at_p8`: entry+8), of the slot's solved type where it
//!    has one shape C holds in exactly its bytes; where it (at most 8
//!    bytes) is accessed in several widths, all at its first byte, a union
//!    of a member per width (`w32`, `w64`: the same bytes, so each access
//!    names its own member, `frame.at_m28.w32`, not a cast of the field's
//!    address); of the type most of its accesses of the whole slot have
//!    where it is also accessed in other parts; else bytes; the bytes no
//!    slot holds are `unknown_m<hex>[n]`. Its size is the piece's; it
//!    starts on the ABI's 16-byte grid (taking the padding below it, no
//!    slot's and above every call's stack pointer) so its fields are at
//!    their natural alignment, as in the stack. A piece that is one value
//!    has its slot's solved type; one that is exactly one slot accessed
//!    in parts, the type its field of a frame struct would have.
//!    A stack address is the address of the `Frame` variable holding it
//!    plus an offset, else of one at the entry stack pointer (the return
//!    address's bytes, where the call leaves it on the stack).
//!    The frame's stores then say whether the function is a variadic
//!    definition by the convention's `va_list` rule ([`VaList`]: the
//!    prologue's spill of the unnamed argument registers and `va_start`'s
//!    stores, [`Counts::variadic`]). Where the code says nothing C's
//!    `va_start` cannot (`lower::variadic` says when), the function is
//!    C's variadic one (`Function::variadic`): one `Stmt::VaStart` stands
//!    for the saves and the stores (with the branch on the vector count
//!    and the blocks of the vector saves, which it absorbs), the save area
//!    and the unnamed arguments' home slots are no variable, System V's
//!    `va_list` is a `Frame` variable of its own, and the unnamed
//!    registers' entry values are undefined ([`Mapping::unnamed`]); its
//!    parameters are the named ones, and its [`Interface`] is variadic.
//! 4. **Signature.** The return value is the convention's first result
//!    register where every exit writes it (a return: not its entry value;
//!    a tail call: the callee returns there), and callers read it when
//!    that is known; 32 bits where every return zero-extends 32 bits or
//!    less, else the whole register. Then only what is needed is kept: the
//!    values stores to memory, calls, intrinsics, escapes, conditions,
//!    jumps and the return value use, transitively (a load of memory that
//!    is not the frame stays, for its fault), each as far as its low bits
//!    are used (to a fixed point): a concatenation's high part, an
//!    extension's and an extraction's source past the used bits, a
//!    block's arguments past its parameter's used bits, and the high part
//!    of a concatenation that is an `and`'s operand where the other
//!    operand is 0 there (`sete dl`, then `and eax, edx` with a one-bit
//!    `eax`) are not used, so
//!    the bits a register keeps through a narrower write (SSE's `movsd`
//!    keeps the rest of `zmm0`) are no parameter unless something reads
//!    them, on any path. The parameters are the
//!    convention's integer argument registers whose entry value is needed,
//!    up to the last one (all of them if there are stack parameters), then
//!    its vector argument registers up to the last one needed, then any
//!    other register whose entry value is needed (a non-standard input:
//!    a register a fragment of a function receives, say), then the stack
//!    parameters by offset, with a pointer-sized one for each slot before
//!    them that is not read (C passes arguments by position: the
//!    argument read at `[entry + 0x20]` is the tenth only after a seventh
//!    to ninth); each as wide as its widest use (a register only
//!    read as its low 32 bits is a 32-bit parameter). A declared prototype
//!    gives the parameters and return value first. The convention's
//!    thread pointer ([`Convention::thread_pointer`]) is no parameter: its
//!    entry value is an environment variable (`VarKind::Environment`),
//!    which callers do not pass, where the function leaves it unchanged
//!    (it holds its entry value at every call and exit). Nor is a
//!    floating-point control register ([`Convention::float_control`])
//!    where the function keeps its controls (it holds its entry value at
//!    every call and exit but for status flags raised, or what a call
//!    left, which keeps them too). Callee-saved registers
//!    and the stack pointer are no variables: their saves and restores are
//!    not needed, so they disappear.
//! 5. **Expressions.** A value used once, in its own block, by a later
//!    statement, with nothing in between writing what it reads (memory for
//!    a load, the local for a local's read), is folded into its use. Branch
//!    and select conditions are read back as comparisons
//!    ([`condition::comparison`](binbun_ssa::condition::comparison)), so
//!    flags consumed only by a branch never become variables. Constants
//!    come from propagation. Constant addresses in the image
//!    ([`Context::data`]) are its objects' `Global` variables, strings and
//!    functions where the evidence allows (`emit::data` says which); a
//!    call through an import's slot takes the import's prototype
//!    ([`Prototypes::through`]).
//!    The type solver's constraints are generated from what is kept and
//!    solved here ([`crate::typing`]), and rounded after step 6 to the
//!    types of
//!    variables, loads, stores, parameters and the return value (declared
//!    ones unchanged); a refusal leaves them `bits`
//!    ([`Outcome::refused`]). There a call taking its callee's interface
//!    (no prototype) is typed by the callee's scheme where
//!    [`Context::schemes`] has one from before this function
//!    ([`summarise`] computes a function's).
//! 6. **Variables out of SSA.** Each remaining value is a variable, then
//!    block parameters are coalesced with their arguments where their live
//!    ranges do not interfere (Budimlić et al., "Fast Copy Coalescing and
//!    Live-Range Identification", 2002: in strict SSA two values interfere
//!    if one is live where the other, which it dominates, is defined;
//!    liveness counts a folded value's operands at the statement it is
//!    folded into, and a block argument at the end of its predecessor). A
//!    register through a loop is one variable; two values of one register
//!    live at once stay two. Types inform coalescing: a class holding a
//!    pointer is not coalesced with one holding an integer (what the
//!    solution rounds each pointer-wide value
//!    to alone; an integer computation is an integer whatever it rounds
//!    to), so a register reused for both is two variables. The arguments
//!    not coalesced are parallel
//!    copies on their edge (inside the arm of the branch that takes it, so
//!    no edge is split), sequentialized with a temporary for each cycle.
//!    Past the [`Context::budget`], coalescing stops: every value keeps its
//!    own variable, which is always correct.
//! 7. **Control.** Every L1 block but the entry is a label; the entry's
//!    code starts the body, unlabelled. A block's statements and its
//!    terminator (not what is inside the terminator's arms) have the
//!    block as an `Origin::Block`: that, not the label, is how the
//!    structure check knows the block, so passes may move or drop labels.
//!    Each block ends in exactly one explicit terminator (no fall
//!    through, even to the next label): a `goto`, an
//!    `if (c) { copies; goto a } else { copies; goto b }`, a `switch` over
//!    the computed address for a resolved jump table (its default an
//!    `UnresolvedJump` escape), a return, a tail call (call and return), a
//!    trap, `unreachable` (after a call that does not return) or an
//!    escape: an unresolved computed jump, a jump into another function
//!    (`ForeignJump`); a return to an address other than the one the
//!    caller left is a `StackTrick` escape, then the return. A call made
//!    on a stack other than the frame is a `StackTrick` escape of the
//!    stack pointer, then the call: the stack pointer at the call (after
//!    the push of its return address) is a stack address whose pushed
//!    return address is not below the entry stack pointer (`pop; pop;
//!    call` writes the caller's frame), or is not computed from the entry
//!    stack pointer at all (loaded, another register's: a stack switched
//!    to); one computed from it at an unknown offset (`alloca`,
//!    alignment) is the frame's. Pushes and pops at such a stack pointer
//!    need no escape: they are loads and stores at the address it holds,
//!    lowered as such. System calls
//!    and atomic accesses are escapes in the block. Blocks are in L1's
//!    order. Every call statement has the L1 value of its target in its
//!    provenance.
//!
//! Precondition: the L1 function passes its verifier. Postcondition: the
//! L2 function passes binbun-ast's verifier (both checked: a failure is a
//! [`LowerError`]). Only L1 blocks the entry reaches are lowered.

mod atomic;
mod calls;
mod coalesce;
mod emit;
mod facts;
mod frame;
mod needed;
mod typed;
mod variadic;

pub(crate) use calls::{MAX_SCALAR, scalar_code, stated_code_type};

use alloc::boxed::Box;
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::rc::Rc;
use alloc::string::String;
use alloc::vec::Vec;
use core::cell::OnceCell;
use core::fmt;

use binbun_ast::ir::Function as Ast;
use binbun_ast::types::{Signature, Types};
use binbun_semantics::Declarations;
use binbun_semantics::core::pass::Manager;
use binbun_semantics::ir::RegisterId;
use binbun_ssa::constant::Constants;
use binbun_ssa::graph::Dominators;
use binbun_ssa::ir::{Function, Value};
use binbun_ssa::pass::L1Env;
use binbun_ssa::stack::Stack;

use crate::data::{Data, NoData};
use crate::format::Refusal;
use crate::mapping::{Mapping, Piece, Source};
use crate::prototype::{Format, NoPrototypes, Prototypes, Unplaced};
use crate::typing::{Arguments, Class, Contribution, Explained, Outcome, Schemes, Summary};
use crate::validate::Link;

/// The registers of a calling convention, as lowering uses them.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Convention {
    /// The integer (and pointer) argument registers, in order.
    pub arguments: Vec<RegisterId>,
    /// The vector (floating-point) argument registers, in order.
    pub float_arguments: Vec<RegisterId>,
    /// How many low bits of a vector argument register an argument
    /// occupies at most (0: the whole register); the bits above carry
    /// nothing a callee may depend on.
    pub float_bits: u16,
    /// Whether arguments take registers by position: the nth argument goes
    /// in the nth integer or the nth vector register, by its type, and
    /// the others of that position go unused (Microsoft x64). Otherwise
    /// each class takes its next free register.
    pub positional: bool,
    /// The bytes the caller reserves just above the return address for
    /// the callee to use as it likes (Microsoft x64's home space for the
    /// four register arguments); the stack arguments follow them.
    pub shadow: u16,
    /// The integer result registers, low part first.
    pub results: Vec<RegisterId>,
    /// The vector result registers.
    pub float_results: Vec<RegisterId>,
    /// The registers a callee keeps.
    pub callee_saved: Vec<RegisterId>,
    /// The registers a system call takes: its number, then its arguments.
    pub system_call: Vec<RegisterId>,
    /// The width of C's `long` in bits (the data model: 64 under LP64, 32
    /// under LLP64), which a format string's `%ld` passes; 0 if unknown
    /// (a format with an `l` conversion is then not used).
    pub long: u16,
    /// The register the platform keeps the thread pointer in: an input of
    /// every function that no caller passes, lowered to an environment
    /// variable ([`VarKind::Environment`](binbun_ast::ir::VarKind)), never
    /// a parameter.
    pub thread_pointer: Option<RegisterId>,
    /// The registers of the floating-point environment whose control bits
    /// (rounding, exception masks, flush-to-zero, denormals-are-zero) a
    /// callee keeps and so sees as its caller left them, while it may
    /// raise their status bits (exception flags) if they have any: inputs
    /// of every function that no caller passes, environment variables
    /// like the thread pointer where the function keeps their controls.
    pub float_control: Vec<FloatControl>,
    /// How a variadic function receives its unnamed arguments (the
    /// ABI's `va_list`), which [`Counts::variadic`] recognises.
    pub va_list: VaList,
    /// Whether the arguments a variadic prototype does not declare go on
    /// the stack, each in its own 8-byte slot after the named ones, never
    /// in registers (Apple's arm64: "Writing ARM64 code for Apple
    /// platforms", variadic functions). A call's unnamed arguments are
    /// then only what its format string says.
    pub variadic_on_stack: bool,
    /// How a struct or a union is passed and returned by value.
    pub aggregates: Aggregates,
    /// The x87 unit, where the architecture has one: no argument is passed
    /// in it (System V x86-64 §3.2.3 passes the X87 classes in memory;
    /// Microsoft x64: "The x87 register stack is unused"), so the reading
    /// view takes its stack as empty at entry with TOP 0
    /// ([`AssumeEmptyX87`](binbun_ssa::float::AssumeEmptyX87)) and none of
    /// its registers as a parameter.
    pub x87: Option<X87>,
}

/// The x87 unit's state, in which no convention passes an argument
/// ([`Convention::x87`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X87 {
    /// The eight physical registers.
    pub registers: Vec<RegisterId>,
    /// The abridged tag word (bit *i*: register *i* in use).
    pub tags: RegisterId,
    /// TOP.
    pub top: RegisterId,
    /// The control word, the status word and the condition codes.
    pub words: Vec<RegisterId>,
}

impl X87 {
    /// The x87 unit as `declarations` names it, if it declares it.
    fn of(declarations: &Declarations) -> Option<Self> {
        let registers = (0..8)
            .map(|i| declarations.find(&alloc::format!("fpr{i}")))
            .collect::<Option<Vec<_>>>()?;
        let words = ["fcw", "fsw", "c0", "c1", "c2", "c3"]
            .into_iter()
            .map(|name| declarations.find(name))
            .collect::<Option<Vec<_>>>()?;
        Some(Self {
            registers,
            tags: declarations.find("ftw")?,
            top: declarations.find("ftop")?,
            words,
        })
    }

    /// Every register of its state: the eight, the tag word, TOP, the
    /// control and status words and the condition codes.
    pub fn state(&self) -> impl Iterator<Item = RegisterId> + '_ {
        self.registers
            .iter()
            .copied()
            .chain([self.tags, self.top])
            .chain(self.words.iter().copied())
    }
}

/// A calling convention's rule for structs and unions passed and
/// returned by value.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Aggregates {
    /// None known: a declaration that passes or returns one is not
    /// placed, so it is not taken.
    #[default]
    Unknown,
    /// x86-64 System V (psABI §3.2.3): one of at most 16 bytes whose
    /// fields are aligned is passed and returned in a register per
    /// eightbyte (a vector one where every field in it is `float` or
    /// `double`, else an integer one), where registers are left for all
    /// of it; any other in memory: a parameter on the stack, a result in
    /// storage whose address the caller passes as a hidden first argument
    /// and the callee returns.
    SystemV,
    /// Microsoft x64 ("x64 calling convention": parameter passing, return
    /// values): one of 1, 2, 4 or 8 bytes is passed and returned as the
    /// integer of its size (whatever its fields: in an integer register
    /// or a stack slot by its position, in `rax`); any other is passed as
    /// a pointer to a copy the caller makes, and returned in storage
    /// whose address the caller passes as a hidden first argument and the
    /// callee returns. (C's types: a C++ class with a constructor, a
    /// destructor or a base is returned in memory whatever its size.)
    Microsoft,
    /// AAPCS64 ("Parameter passing rules", B.4): one larger than 16 bytes
    /// is passed as a pointer to a copy the caller makes (as `va_list`,
    /// 32 bytes, is to `vfprintf`). Others, passed in registers by rules
    /// not modelled here (homogeneous floating-point aggregates in vector
    /// registers, the rest in integer ones), and any returned (one larger
    /// than 16 bytes in storage whose address is in `x8`, the indirect
    /// result register, not an argument's) are not placed, as for
    /// [`Self::Unknown`].
    Aapcs64,
}

/// A calling convention's `va_list`: how a variadic function's prologue
/// and `va_start` make its unnamed arguments a list, by the ABI's rule.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum VaList {
    /// None known: no variadic definition is recognised.
    #[default]
    Unknown,
    /// x86-64 System V (psABI §3.5.7): `struct __va_list_tag { unsigned
    /// gp_offset; unsigned fp_offset; void *overflow_arg_area; void
    /// *reg_save_area; }`. The prologue spills the integer argument
    /// registers after the named ones to the 176-byte register save area
    /// (at 8·k), and, where the low byte of `count` (`al`: an upper bound
    /// on the vector registers the caller used) is not 0, the vector ones
    /// (at 48 + 16·k); `va_start` stores `gp_offset` = 8·(named integer),
    /// `fp_offset` = 48 + 16·(named vector), the caller's stack arguments
    /// after the named ones, and the save area.
    SystemV {
        /// The register whose low byte counts the vector arguments.
        count: RegisterId,
    },
    /// Microsoft x64 ("Variable argument lists"): `va_list` is `char *`;
    /// the callee spills the integer argument registers after the named
    /// ones to their home slots, and `va_start` is the address of the
    /// home slot after the last named parameter.
    Pointer,
    /// AAPCS64 ("Variable argument lists": `struct __va_list { void
    /// *__stack; void *__gr_top; void *__vr_top; int __gr_offs; int
    /// __vr_offs; }`, 32 bytes). The prologue saves the integer argument
    /// registers after the named ones below `__gr_top` (`x`*k* at
    /// `__gr_top` − 8·(8 − *k*)) and the vector ones below `__vr_top`
    /// (`q`*k* at `__vr_top` − 16·(8 − *k*)), with no count register;
    /// `va_start` stores the caller's stack arguments after the named
    /// ones, the two tops and the negative offsets
    /// `__gr_offs` = −8·(8 − named integer), `__vr_offs` = −16·(8 −
    /// named vector).
    Aapcs64,
}

/// A floating-point control register, whose low bits may be status flags
/// ([`Convention::float_control`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FloatControl {
    /// The register.
    pub register: RegisterId,
    /// How many of its low bits are status flags, which floating-point
    /// operations set; the bits above are its controls.
    pub status_bits: u16,
    /// Its value when a process starts: what the reading view takes its
    /// controls to be at a function's entry
    /// ([`AssumeFloatControls`](binbun_ssa::float::AssumeFloatControls)).
    pub default: u64,
}

impl Convention {
    /// The convention named by register names of `declarations` (names it
    /// does not declare are left out), with `long` `long` bits wide.
    fn named(
        declarations: &Declarations,
        [
            arguments,
            float_arguments,
            results,
            float_results,
            callee_saved,
            system_call,
        ]: [&[&str]; 6],
        long: u16,
    ) -> Self {
        let ids = |names: &[&str]| -> Vec<RegisterId> {
            names
                .iter()
                .filter_map(|name| declarations.find(name))
                .collect()
        };
        Self {
            arguments: ids(arguments),
            float_arguments: ids(float_arguments),
            float_bits: 0,
            positional: false,
            shadow: 0,
            results: ids(results),
            float_results: ids(float_results),
            callee_saved: ids(callee_saved),
            system_call: ids(system_call),
            long,
            thread_pointer: None,
            float_control: Vec::new(),
            va_list: VaList::Unknown,
            variadic_on_stack: false,
            aggregates: Aggregates::Unknown,
            x87: None,
        }
    }

    /// x86-64 System V (ELF), with Linux system calls. A vector argument
    /// may fill its whole register (`__m512` in `zmm0` under AVX-512).
    /// The thread pointer is `fs_base` (the psABI's TLS: `%fs` holds the
    /// thread's TCB). "The control bits of the MXCSR register and the x87
    /// FPU control word are callee-saved, while the status bits are
    /// caller-saved" (psABI §3.2.1, "Registers and the Stack Frame").
    pub fn system_v(declarations: &Declarations) -> Self {
        let named = Self::named(
            declarations,
            [
                &["rdi", "rsi", "rdx", "rcx", "r8", "r9"],
                &[
                    "zmm0", "zmm1", "zmm2", "zmm3", "zmm4", "zmm5", "zmm6", "zmm7",
                ],
                &["rax", "rdx"],
                &["zmm0", "zmm1"],
                &["rbx", "rbp", "r12", "r13", "r14", "r15"],
                &["rax", "rdi", "rsi", "rdx", "r10", "r8", "r9"],
            ],
            64,
        );
        Self {
            thread_pointer: declarations.find("fs_base"),
            float_control: x86_float_control(declarations),
            va_list: declarations
                .find("rax")
                .map_or(VaList::Unknown, |count| VaList::SystemV { count }),
            aggregates: Aggregates::SystemV,
            x87: X87::of(declarations),
            ..named
        }
    }

    /// x86-64 System V as macOS has it ([`Self::system_v`]): its thread
    /// pointer is `gs_base` (`%gs` holds the thread's TSD).
    pub fn darwin_x86_64(declarations: &Declarations) -> Self {
        Self {
            thread_pointer: declarations.find("gs_base"),
            ..Self::system_v(declarations)
        }
    }

    /// Microsoft x64 (PE), as Microsoft's "x64 calling convention" states
    /// it: the first four arguments by position in `rcx`, `rdx`, `r8`,
    /// `r9` or, for floating-point ones, the low 64 bits of `xmm0`–`xmm3`
    /// (`__m128` and larger are passed by reference; `__vectorcall`
    /// a 32-byte home space above the return address, then the
    /// fifth argument on; `rbx`, `rbp`, `rdi`, `rsi`, `r12`–`r15` and
    /// `xmm6`–`xmm15` kept ("Nonvolatile (XMM), Volatile (upper half of
    /// YMM)": the whole register is taken as kept, as code compiled to the
    /// convention reads no upper half a call may change).
    /// The thread pointer is `gs_base` (`gs` holds the thread's TEB).
    /// MXCSR's bits 6–15 (its controls) are nonvolatile, bits 0–5 (its
    /// status flags) volatile, and the x87 control word is nonvolatile
    /// ("x64 ABI conventions": register volatility, MXCSR, x87 FPU).
    pub fn microsoft_x64(declarations: &Declarations) -> Self {
        let named = Self::named(
            declarations,
            [
                &["rcx", "rdx", "r8", "r9"],
                &["zmm0", "zmm1", "zmm2", "zmm3"],
                &["rax"],
                &["zmm0"],
                &[
                    "rbx", "rbp", "rdi", "rsi", "r12", "r13", "r14", "r15", "zmm6", "zmm7", "zmm8",
                    "zmm9", "zmm10", "zmm11", "zmm12", "zmm13", "zmm14", "zmm15",
                ],
                &["rax", "r10", "rdx", "r8", "r9"],
            ],
            32,
        );
        Self {
            float_bits: 64,
            positional: true,
            shadow: 32,
            thread_pointer: declarations.find("gs_base"),
            float_control: x86_float_control(declarations),
            va_list: VaList::Pointer,
            aggregates: Aggregates::Microsoft,
            x87: X87::of(declarations),
            ..named
        }
    }

    /// AArch64's procedure call standard (AAPCS64), with Linux system
    /// calls. A vector argument fills its 128-bit register (SVE aside).
    /// `x19`–`x29` and `v8`–`v15` are kept ("Use of the SIMD and
    /// Floating-Point registers": only the low 64 bits of `v8`–`v15` need
    /// be preserved; the whole register is taken as kept, as code compiled
    /// to the convention reads no upper half a call may change, as
    /// Microsoft x64's `xmm6`–`xmm15`).
    /// The thread pointer is `tpidr_el0` (the AArch64 ELF ABI's TLS).
    /// FPCR's controls (rounding, flush-to-zero, default NaN, trap
    /// enables) are preserved across calls; the cumulative flags are in
    /// FPSR, which is not (AAPCS64, "The Floating-point Control and Status
    /// Registers").
    pub fn aapcs64(declarations: &Declarations) -> Self {
        let named = Self::named(
            declarations,
            [
                &["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"],
                &["v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7"],
                &["x0", "x1"],
                &["v0", "v1"],
                &[
                    "x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27", "x28", "x29",
                    "v8", "v9", "v10", "v11", "v12", "v13", "v14", "v15",
                ],
                &["x8", "x0", "x1", "x2", "x3", "x4", "x5"],
            ],
            64,
        );
        Self {
            thread_pointer: declarations.find("tpidr_el0"),
            float_control: declarations
                .find("fpcr")
                .map(|register| FloatControl {
                    register,
                    status_bits: 0,
                    default: 0,
                })
                .into_iter()
                .collect(),
            va_list: VaList::Aapcs64,
            aggregates: Aggregates::Aapcs64,
            ..named
        }
    }

    /// AAPCS64 as Apple's platforms change it ("Writing ARM64 code for
    /// Apple platforms"): a variadic function's unnamed arguments on the
    /// stack, in 8-byte slots ([`Self::variadic_on_stack`]); the thread
    /// pointer `tpidrro_el0`; a system call's number in `x16`
    /// (`svc #0x80`), its arguments in `x0`–`x5`. Its `va_list` is a
    /// `char *` binbun does not recognise yet.
    pub fn darwin_arm64(declarations: &Declarations) -> Self {
        let aapcs64 = Self::aapcs64(declarations);
        Self {
            thread_pointer: declarations.find("tpidrro_el0"),
            system_call: ["x16", "x0", "x1", "x2", "x3", "x4", "x5"]
                .iter()
                .filter_map(|name| declarations.find(name))
                .collect(),
            variadic_on_stack: true,
            va_list: VaList::Unknown,
            ..aapcs64
        }
    }

    /// AAPCS64 as Windows changes it ("Overview of ARM64 ABI
    /// conventions"): `x18` is the platform register, which "in user
    /// mode points to TEB" (in kernel mode to the processor's KPCR) and
    /// code never changes: the thread pointer, as `gs_base` is on x64; C's
    /// `long` is 32 bits (LLP64). Its `va_list` is a `char *` binbun does
    /// not recognise yet.
    pub fn windows_arm64(declarations: &Declarations) -> Self {
        Self {
            thread_pointer: declarations.find("x18"),
            long: 32,
            va_list: VaList::Unknown,
            ..Self::aapcs64(declarations)
        }
    }
}

/// x86-64's floating-point control registers: MXCSR, whose status flags
/// are bits 0–5 and controls bits 6–15, and the x87 control word (its
/// status word is another register). A process starts with every
/// exception masked and rounding to nearest in both (`0x1f80`; `0x37f`,
/// the x87's precision extended: System V x86-64 3.4.1, as `FNINIT` and
/// a reset leave them).
fn x86_float_control(declarations: &Declarations) -> Vec<FloatControl> {
    [("mxcsr", 6, 0x1f80), ("fcw", 0, 0x37f)]
        .into_iter()
        .filter_map(|(name, status_bits, default)| {
            let register = declarations.find(name)?;
            Some(FloatControl {
                register,
                status_bits,
                default,
            })
        })
        .collect()
}

/// What lowering found a function takes and gives ([`interface`]): how
/// its callers' calls pass arguments and get its result.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Interface {
    /// Its parameters, in the state at its entry (a call's state).
    pub parameters: Vec<Source>,
    /// Where its return value is after it returns, low bits first.
    pub returns: Vec<Piece>,
    /// Whether it takes more arguments than its parameters (a variadic
    /// definition recognised, [`Counts::variadic`], printed as C's or
    /// not: then these are its named parameters only): its callers pass
    /// the convention's integer argument registers after them that they
    /// set (rule 1 of call arguments, as for a declared variadic
    /// prototype) and the vector ones the convention's count register
    /// covers.
    pub variadic: bool,
    /// The format string its variadic arguments follow, where it passes
    /// one of its parameters as the format of a `v` function (declared
    /// with a format describing its `va_list`, as `vfprintf`) together
    /// with the `va_list` of its own variadic arguments, untouched
    /// (GCC's `-Wsuggest-attribute=format` case): `string` counts in
    /// [`parameters`](Self::parameters), its callers' arguments are
    /// counted from their format strings.
    pub format: Option<Format>,
}

/// No interfaces.
static NO_INTERFACES: BTreeMap<u64, Interface> = BTreeMap::new();

/// No function entries.
static NO_FUNCTIONS: BTreeSet<u64> = BTreeSet::new();

/// No schemes.
static NO_SCHEMES: Schemes = Schemes::new();

/// No specialisations.
static NO_SPECIALISATIONS: BTreeMap<u64, Vec<(Source, Class)>> = BTreeMap::new();

/// What lowering knows about the code around the function.
#[derive(Clone, Copy)]
pub struct Context<'a> {
    /// The architecture's registers and intrinsics.
    pub declarations: &'a Declarations,
    /// The stack pointer.
    pub stack_pointer: RegisterId,
    /// Where a call leaves the return address.
    pub link: Link,
    /// The program counter, whose entry value is the function's entry.
    pub program_counter: Option<RegisterId>,
    /// Registers the convention gives a fixed value at entry (x86-64: the
    /// direction flag clear).
    pub fixed: &'a [(RegisterId, u64)],
    /// The calling convention.
    pub convention: &'a Convention,
    /// Declared prototypes.
    pub prototypes: &'a dyn Prototypes,
    /// The image's data: accesses at constant addresses in it are its
    /// objects' variables, strings passed as `char *` its strings.
    pub data: &'a dyn Data,
    /// The interfaces of the functions it may call, by entry (a callee
    /// without one, and without a prototype, takes the convention's whole
    /// argument set, unprototyped).
    pub interfaces: &'a BTreeMap<u64, Interface>,
    /// The entries of the program's functions. Where it is not empty, a
    /// jump out of the function to a known address that is none of them
    /// and has no prototype is a `ForeignJump`, not a tail call.
    pub functions: &'a BTreeSet<u64>,
    /// The result registers callers read after calls to the function, if
    /// known (over all recovered callers).
    pub read_results: Option<&'a [RegisterId]>,
    /// The vector result register, where callers of the function read it
    /// after their calls and none reads the integer one
    /// ([`Found::strays`]): if every exit writes a scalar there, that is
    /// the return value, whatever the integer register holds.
    pub preferred_result: Option<RegisterId>,
    /// The registers dropped from the function's interface (the whole
    /// program's fact: its body reads them only to pass them to callees
    /// that do not read them, or every caller leaves garbage in them):
    /// lowering takes their entry values as undefined, so they are no
    /// parameters.
    pub dropped: &'a [RegisterId],
    /// The most steps liveness and coalescing take; past it, values are
    /// not coalesced (each keeps its own variable).
    pub budget: u64,
    /// The schemes of the program's functions: a call to a function with
    /// no prototype whose scheme came before this function's instantiates
    /// it ([`crate::typing`]).
    pub schemes: &'a Schemes,
    /// The class every caller passes at each parameter of the function,
    /// where they all agree (the top-down specialisation): a lower bound
    /// on the parameter below its body's own evidence ([`crate::typing`]).
    pub specialised: &'a [(Source, Class)],
    /// Every function's [`specialised`](Self::specialised) classes, by
    /// entry: a call to one takes them as lower bounds on its scheme's
    /// parameters (at the same strength as the callee's own solve), so
    /// the call passes the parameter as the callee's C declares it.
    pub specialisations: &'a BTreeMap<u64, Vec<(Source, Class)>>,
    /// The reading view's assumption that a `futex` operation made of a
    /// constant and another value has the constant's command, the other
    /// value giving only its private and clock flags (Linux defines the
    /// operation as a command with flags or-ed in): taken where the
    /// constant gives a command other than `FUTEX_WAIT`, or turns the
    /// other value's private flag over (`x ^ 0x80`); not for a value with
    /// a flag or-ed in alone (`x | 0x80`, maybe an operation passed in).
    pub assume_futex: bool,
    /// The reading view's assumption that no code steps back from a stack
    /// address the function passes to a call or stores to the bytes below
    /// it (an enclosing object's `container_of`): such an address reaches
    /// only bytes at or above it, so where the function's own code does
    /// not step back either and nothing else makes the stack escape, the
    /// slots below every such address are variables of their own, not
    /// memory ([`Found::steps_back`]; step 3 of the [module](self)).
    pub assume_forward_reach: bool,
}

impl fmt::Debug for Context<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Context")
            .field("stack_pointer", &self.stack_pointer)
            .field("link", &self.link)
            .field("program_counter", &self.program_counter)
            .field("fixed", &self.fixed)
            .field("convention", &self.convention)
            .field("interfaces", &self.interfaces.len())
            .field("functions", &self.functions.len())
            .field("read_results", &self.read_results)
            .field("dropped", &self.dropped)
            .field("budget", &self.budget)
            .field("schemes", &self.schemes.len())
            .field("specialised", &self.specialised)
            .field("specialisations", &self.specialisations.len())
            .finish_non_exhaustive()
    }
}

impl<'a> Context<'a> {
    /// The default [`budget`](Self::budget).
    pub const BUDGET: u64 = 1 << 26;

    /// A context of `declarations` and `convention`, with no fixed
    /// registers, prototypes, data, interfaces or function entries, and
    /// the default budget and type inference.
    pub fn new(
        declarations: &'a Declarations,
        stack_pointer: RegisterId,
        link: Link,
        convention: &'a Convention,
    ) -> Self {
        Self {
            declarations,
            stack_pointer,
            link,
            program_counter: None,
            fixed: &[],
            convention,
            prototypes: &NoPrototypes,
            data: &NoData,
            interfaces: &NO_INTERFACES,
            functions: &NO_FUNCTIONS,
            read_results: None,
            preferred_result: None,
            dropped: &[],
            budget: Self::BUDGET,
            schemes: &NO_SCHEMES,
            specialised: &[],
            specialisations: &NO_SPECIALISATIONS,
            assume_futex: false,
            assume_forward_reach: false,
        }
    }

    /// The bytes of the return address at the entry stack pointer.
    fn link_bytes(&self) -> u16 {
        match self.link {
            Link::Stack { bytes } => bytes,
            Link::Register(_) => 0,
        }
    }
}

/// Why a function cannot be lowered.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LowerError {
    /// The L1 function is malformed (its verifier, or a shape lowering
    /// needs).
    Malformed(String),
    /// The L2 function fails binbun-ast's verifier (a lowering bug).
    Invalid(String),
}

impl fmt::Display for LowerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(message) => write!(f, "malformed L1: {message}"),
            Self::Invalid(message) => write!(f, "lowered L2 does not verify: {message}"),
        }
    }
}

impl core::error::Error for LowerError {}

/// The L1 analyses lowering reads, of the function it lowers. They must
/// be computed in an [`L1Env`] whose declarations and stack pointer are
/// the [`Context`]'s and whose arguments are its convention's
/// ([`Convention::arguments`]); the memory is what the caller's constant
/// propagation may fold loads from.
#[derive(Clone, Debug)]
pub struct Facts {
    /// Constant propagation, and which blocks can run.
    pub constants: Rc<Constants>,
    /// The stack: addresses at known offsets, escape, forwarding.
    pub stack: Rc<Stack>,
    /// The dominator tree.
    pub dominators: Rc<Dominators>,
    /// Whether the L1 these are the analyses of is well formed (passes
    /// its verifier), once lowering has checked it (it checks first): a
    /// function lowered again (each round of finding its interface, then
    /// its C) is not checked again.
    well_formed: OnceCell<Result<(), String>>,
    /// What lowering found of the function before reading its context,
    /// once found: each later lowering of it starts from there.
    start: OnceCell<facts::Start>,
}

impl Facts {
    /// The facts made of these analyses, the L1 not checked yet.
    pub fn new(constants: Rc<Constants>, stack: Rc<Stack>, dominators: Rc<Dominators>) -> Self {
        Self {
            constants,
            stack,
            dominators,
            well_formed: OnceCell::new(),
            start: OnceCell::new(),
        }
    }

    /// The facts of `function` in `env` from `manager`'s analyses: those
    /// its passes left valid, the others computed now (and kept there).
    pub fn of<'e>(
        manager: &mut Manager<Function, L1Env<'e>>,
        function: &Function,
        env: &L1Env<'e>,
    ) -> Self {
        Self::new(
            manager.analysis(function, env),
            manager.analysis(function, env),
            manager.analysis(function, env),
        )
    }

    /// Whether `l1`, the function these are the analyses of, is well
    /// formed under `declarations` (passes [`binbun_ssa::verify::verify`]);
    /// checked once.
    pub(crate) fn well_formed(
        &self,
        l1: &Function,
        declarations: &Declarations,
    ) -> Result<(), String> {
        self.well_formed
            .get_or_init(|| {
                binbun_ssa::verify::verify(l1, declarations)
                    .map_err(|error| alloc::format!("{error}"))
            })
            .clone()
    }
}

/// `function` lowered to goto-only L2 under `context`, with its
/// [`Mapping`] (the [module](self) describes how); `facts` are its
/// analyses.
///
/// # Errors
///
/// The L1 function does not verify or has a block still open, a computed
/// jump's targets share an address, or the result does not verify.
pub fn lower(
    function: &Function,
    facts: &Facts,
    context: &Context<'_>,
) -> Result<(Ast, Mapping), LowerError> {
    lower_counted(function, facts, context).map(|(ast, mapping, _)| (ast, mapping))
}

/// Where a convention places a declared signature's parameters
/// ([`places`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Places {
    /// Each declared parameter's places, in order: several where it is a
    /// struct or union the convention passes in parts.
    pub parameters: Vec<Vec<Source>>,
}

/// Where `convention` (its registers of `declarations`) places the
/// parameters of a function declared with `signature` (of `types`,
/// which takes the types of its lowered form), as lowering places a
/// declaration's: for checking one against where its parameters are
/// stated to be. `pointer`: a pointer's bits; `link`: the bytes of the
/// return address on the stack at the function's entry. `None` where the
/// convention's rules do not say.
pub fn places(
    types: &mut Types,
    convention: &Convention,
    declarations: &Declarations,
    pointer: u16,
    link: u16,
    signature: &Signature,
) -> Option<Places> {
    calls::Placer {
        types,
        convention,
        declarations,
        pointer,
        link,
    }
    .place(signature)
    .map(|placed| Places {
        parameters: placed.declared,
    })
}

/// What [`interface`] finds about a function.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Found {
    /// What it takes and gives as [`lower`] finds it: its parameters and
    /// return value, for its callers' calls; `None` where it leaves for
    /// code it does not know (an unresolved computed jump, a jump into
    /// another function), which may read and return anything (a stub
    /// jumping to an import): its callers take the convention.
    pub interface: Option<Interface>,
    /// The constant addresses it calls or jumps out of the function to:
    /// every address whose [`Context::interfaces`] entry its lowering may
    /// read, so it lowers the same once theirs are final.
    pub callees: BTreeSet<u64>,
    /// How it reads the return value of each function it calls or jumps
    /// to at a constant address, over all its calls to it.
    pub results: BTreeMap<u64, Read>,
    /// Where its return value is in an integer register and every exit
    /// also writes a scalar to the vector result register: that one (a
    /// function returning a `float` leaves what it computed with in
    /// `rax`, one returning an `int` what it computed with in `xmm0`, and
    /// its body says no more). Its callers tell
    /// ([`Self::strays`], [`Context::preferred_result`]).
    pub alternative: Option<Piece>,
    /// The functions it calls at a constant address and reads the vector
    /// result register after, though their interfaces return nothing
    /// there: no compiler reads a register a call may change unless the
    /// callee returns in it.
    pub strays: BTreeSet<u64>,
    /// What it passes each function it calls or jumps to at a constant
    /// address, over all its calls to it: per register the callee may
    /// take an argument in (the convention's argument registers and the
    /// call's arguments), what that register holds at the calls.
    pub passes: BTreeMap<u64, BTreeMap<RegisterId, Passed>>,
    /// The registers whose entry value it reads other than as an argument
    /// register of a call (every parameter register of a declared
    /// prototype): those it needs whatever its calls' callees take.
    pub reads: BTreeSet<RegisterId>,
    /// The registers whose entry value it may pass as a register argument
    /// of a call not to one of [`Self::undeclared`] (a declared
    /// prototype's parameters, a call through a pointer, to an address no
    /// function of the program starts at), or computes a call's argument
    /// from: those callees may read them.
    pub opaque: BTreeSet<RegisterId>,
    /// Of [`Self::opaque`], the registers whose entry value it only
    /// passes on as it found it, in the same register, where nothing
    /// says the callee reads it: past the parameters a variadic prototype
    /// names, with no format string that counts the arguments, or to a
    /// callee with no declaration and no code in the program (an import
    /// the type library does not know), or after the last argument a call
    /// through a pointer sets (`ops->read(cookie, buf, size)` with `r8`
    /// and `r9` untouched). `open(path, O_RDONLY)` with `rdx`
    /// untouched and a wrapper passing its own third argument on are the
    /// same code there. Sound lowering keeps them parameters; the reading
    /// view assumes they hold no argument unless a caller sets one
    /// (`callers` in `binbun::decompile`). Not what goes to a call
    /// through a pointer that sets no argument: a callback's caller passes
    /// its arguments on so.
    pub forwarded: BTreeSet<RegisterId>,
    /// The registers whose entry value it only passes on as it found it,
    /// in the same register, to callees no declaration states the
    /// parameters of: those of [`Self::forwarded`], and those so passed
    /// to a function of the program with no prototype or through a
    /// pointer. Its code does nothing else with them, so whether they
    /// hold arguments is for its callers to show: where a call of the
    /// program leaves one undefined ([`Passed::undefined`]), the reading
    /// view assumes it is none.
    pub passed_on: BTreeSet<RegisterId>,
    /// The functions of the program it calls or jumps to with no
    /// prototype (by their interfaces, or the convention's registers where
    /// none was known): what it passes them ([`Self::passes`]) is read
    /// where their interfaces read it.
    pub undeclared: BTreeSet<u64>,
    /// Where its prototype is its own, its definition's
    /// ([`Prototype::own`](crate::prototype::Prototype::own): debug
    /// information's, the user's; placed, not variadic): the registers
    /// whose entry value it reads or computes a call's argument from, its
    /// declared parameters' among them. The others of its interface it
    /// only passes on in place to calls, which the declaration says it
    /// takes nothing in: they are dropped from it, whatever its callees
    /// read.
    pub own_reads: Option<BTreeSet<RegisterId>>,
    /// Where its prototype is a declaration that is not its own (the
    /// type library's for the name it is exported under, its mangling's;
    /// placed, not variadic): the registers the declaration places
    /// parameters in and those whose entry value it reads, computes a
    /// call's argument from or passes to a call in another register. The
    /// others of its interface it only passes on as it found them: sound
    /// lowering keeps them (such a declaration may say less than the
    /// definition takes, as `main`'s of `envp`), the reading view assumes
    /// the declaration says all the function takes there (`callers` in
    /// `binbun::decompile`).
    pub declared_reads: Option<BTreeSet<RegisterId>>,
    /// What its calls pass each function of the program they type by its
    /// interface, per parameter, by its solved types (from [`summarise`]
    /// only; empty where solving refused): the evidence of the top-down
    /// specialisation.
    pub arguments: Arguments,
    /// What it adds to the program's synthesised structs, by its solved
    /// types (from [`summarise`] only; empty where solving refused).
    pub structs: Contribution,
    /// Its signature as its solved types round it (from [`summarise`]
    /// only; empty where solving refused): the evidence of the program's
    /// one signature per function, which types the calls to it no
    /// instance of its scheme reaches
    /// ([`Schemes::settle_signatures`](crate::typing::Schemes::settle_signatures)).
    pub signature: crate::typing::FunctionTypes,
    /// Whether it makes a `futex` call whose operation's command its code
    /// does not settle ([`Context::assume_futex`]).
    pub unsettled_futex: bool,
    /// Whether its frame is all memory only because a stack address below
    /// the entry stack pointer may step back from where it points
    /// ([`Context::assume_forward_reach`]).
    pub steps_back: bool,
    /// What [`interface`] finds of it with [`Context::assume_futex`] and
    /// [`Context::assume_forward_reach`], where that may differ
    /// ([`Self::unsettled_futex`] or [`Self::steps_back`] without them):
    /// the reading view's.
    pub assumed: Option<Box<Found>>,
    /// The callee-saved registers it keeps as its convention says: each
    /// saved in a stack slot that holds nothing else, and holding its
    /// entry value (as found, or loaded back) wherever it returns. The
    /// reading view assumes these hold no argument (`callers` in
    /// `binbun::decompile`): what else the function reads of their entry
    /// value is its own variable before a path assigns it.
    pub kept: BTreeSet<RegisterId>,
}

impl Found {
    /// Its padding parameters: the register parameters of its interface
    /// whose entry value it does not read ([`Self::reads`]) and passes to
    /// no call in another register, so only passes on to calls in the
    /// same register (rule 1 of call arguments): what they hold is what
    /// its callers leave there, often garbage, so the top-down
    /// specialisation does not type them by its callers.
    pub fn padding(&self) -> BTreeSet<RegisterId> {
        let Some(interface) = &self.interface else {
            return BTreeSet::new();
        };
        interface
            .parameters
            .iter()
            .filter_map(|source| match source {
                Source::Register(piece) => Some(piece.register),
                Source::Stack { .. } => None,
            })
            .filter(|register| {
                !self.reads.contains(register)
                    && self
                        .passes
                        .values()
                        .flatten()
                        .all(|(at, passed)| at == register || !passed.entries.contains(register))
            })
            .collect()
    }
}

/// What a function's calls to a callee hold in one register
/// ([`Found::passes`]), over all of them and every path to them.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Passed {
    /// A value other than an undefined one or the caller's own entry
    /// value of a register.
    pub value: bool,
    /// The registers whose entry value (untouched) it may hold.
    pub entries: BTreeSet<RegisterId>,
    /// An undefined value, at some call on some path: what an earlier
    /// call left there, or nothing the function put there. C gives a
    /// function one prototype, so a call that leaves a register so shows
    /// the callee takes no argument in it.
    pub undefined: bool,
}

impl Passed {
    /// Adds what `other` holds.
    pub fn add(&mut self, other: &Self) {
        self.value |= other.value;
        self.entries.extend(other.entries.iter().copied());
        self.undefined |= other.undefined;
    }

    /// Whether it holds only undefined values (garbage).
    pub fn garbage(&self) -> bool {
        !self.value && self.entries.is_empty()
    }
}

/// How a function reads what a callee returns, over its calls to it
/// (ordered: a later kind includes the earlier ones' reads).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub enum Read {
    /// Never: no call's result is used before it is overwritten.
    #[default]
    No,
    /// Only as its own return value (a tail call, or a call whose result
    /// only reaches a return): read exactly where its own callers read
    /// its result.
    Returned,
    /// Used otherwise.
    Yes,
}

/// `function`'s interface and callees ([`Found`]), with the [`Context`]'s
/// interfaces of its callees known so far.
///
/// # Errors
///
/// As for [`lower`], before its result is built.
pub fn interface(
    function: &Function,
    facts: &Facts,
    context: &Context<'_>,
) -> Result<Found, LowerError> {
    let mut lowering = facts::Lowering::new(function, facts, context)?;
    lowering.signature();
    let results = lowering.result_reads();
    let strays = lowering.stray_reads();
    let passes = lowering.passes();
    let reads = lowering.entry_reads();
    let own_reads = lowering.own_reads();
    let declared_reads = lowering.declared_reads();
    Ok(Found {
        interface: lowering.interface(),
        callees: lowering.callee_addresses(),
        results,
        alternative: lowering.alternative_result(),
        strays,
        passes,
        reads,
        opaque: lowering.opaque_reads(),
        forwarded: lowering.forwarded_reads(),
        passed_on: lowering.passed_on_reads(),
        undeclared: lowering.undeclared_callees(),
        own_reads,
        declared_reads,
        arguments: Arguments::new(),
        structs: Contribution::default(),
        signature: crate::typing::FunctionTypes::default(),
        unsettled_futex: lowering.unsettled_futex,
        steps_back: lowering.frame.steps_back,
        assumed: None,
        kept: lowering.kept_registers(),
    })
}

/// [`interface`], and the function's scheme ([`Summary`]): lowered up to
/// solving its types, with the [`Context`]'s schemes of its callees;
/// `None` where solving refused.
///
/// # Errors
///
/// As for [`lower`], before its result is built.
pub fn summarise(
    function: &Function,
    facts: &Facts,
    context: &Context<'_>,
) -> Result<(Found, Option<Summary>), LowerError> {
    let mut lowering = facts::Lowering::new(function, facts, context)?;
    lowering.signature();
    let own_reads = lowering.own_reads();
    let declared_reads = lowering.declared_reads();
    let strays = lowering.stray_reads();
    let found = Found {
        interface: lowering.interface(),
        callees: lowering.callee_addresses(),
        results: lowering.result_reads(),
        alternative: lowering.alternative_result(),
        strays,
        passes: lowering.passes(),
        reads: lowering.entry_reads(),
        opaque: lowering.opaque_reads(),
        forwarded: lowering.forwarded_reads(),
        passed_on: lowering.passed_on_reads(),
        undeclared: lowering.undeclared_callees(),
        own_reads,
        declared_reads,
        arguments: Arguments::new(),
        structs: Contribution::default(),
        signature: crate::typing::FunctionTypes::default(),
        unsettled_futex: lowering.unsettled_futex,
        steps_back: lowering.frame.steps_back,
        assumed: None,
        kept: lowering.kept_registers(),
    };
    lowering.fold();
    lowering.solve_types();
    let summary = lowering.summary();
    let arguments = lowering.arguments();
    let structs = lowering.structs();
    let signature = lowering.signature_types();
    Ok((
        Found {
            arguments,
            structs,
            signature,
            ..found
        },
        summary,
    ))
}

/// Why the type solver types `values` of `function` as it does
/// ([`Explained`]): lowered up to solving its
/// types, as [`lower`] lowers it, and the solve read, never fed back;
/// `None` where solving refused (every type is lowering's default).
///
/// # Errors
///
/// As for [`lower`], before its result is built.
pub fn explain(
    function: &Function,
    facts: &Facts,
    context: &Context<'_>,
    values: &[Value],
) -> Result<Option<Explained>, LowerError> {
    let mut lowering = facts::Lowering::new(function, facts, context)?;
    lowering.signature();
    lowering.fold();
    lowering.solve_types();
    Ok(lowering.explained(values))
}

/// Counts of one lowering, for corpus metrics.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counts {
    /// Values that needed a variable before coalescing.
    pub values: usize,
    /// Variables of those values after coalescing.
    pub variables: usize,
    /// Copies left on edges.
    pub copies: usize,
    /// Whether the budget stopped coalescing.
    pub over_budget: bool,
    /// What became of its calls' declared format strings.
    pub formats: Formats,
    /// What the type solver did ([`crate::typing`]).
    pub typing: Outcome,
    /// Whether it is a variadic definition, recognised and declared.
    pub variadic: Variadic,
    /// What became of the frame's memory.
    pub frames: Frames,
    /// What became of what debug information states about it.
    pub debug: DebugCounts,
}

/// What became of what debug information states about a function
/// ([`Prototypes::debug`]).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DebugCounts {
    /// Whether debug information states anything about it.
    pub stated: bool,
    /// Why its debug prototype is not its prototype, if it is not.
    pub unplaced: Option<Unplaced>,
    /// Its L2 parameters.
    pub parameters: usize,
    /// Of them, named by debug information.
    pub parameters_named: usize,
    /// Its variables debug information places in the frame.
    pub locals: usize,
    /// Of them, naming an L2 variable or a frame struct's field.
    pub locals_named: usize,
    /// Of those, typing it too (a type L2 can say, of its width).
    pub locals_typed: usize,
    /// Its variables debug information places only in registers, not
    /// named.
    pub registers: usize,
}

impl DebugCounts {
    /// Adds `other`'s counts (`stated` and `unplaced` as counts of
    /// functions are the caller's).
    pub const fn add(&mut self, other: &Self) {
        self.parameters += other.parameters;
        self.parameters_named += other.parameters_named;
        self.locals += other.locals;
        self.locals_named += other.locals_named;
        self.locals_typed += other.locals_typed;
        self.registers += other.registers;
    }
}

impl fmt::Display for DebugCounts {
    /// `debug (parameters named N/M, locals named N/M (typed K), register
    /// locals R)`, with `, prototype unplaced (reason)` where it is; empty
    /// if nothing is stated.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if !self.stated {
            return Ok(());
        }
        write!(
            f,
            "debug (parameters named {}/{}, locals named {}/{} (typed {}), register locals {}",
            self.parameters_named,
            self.parameters,
            self.locals_named,
            self.locals,
            self.locals_typed,
            self.registers
        )?;
        if let Some(unplaced) = self.unplaced {
            write!(f, ", prototype unplaced ({})", unplaced.name())?;
        }
        f.write_str(")")
    }
}

/// What became of the frame's memory: how many slots each rule takes
/// (step 3).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Frames {
    /// Slots that are fields of a frame struct.
    pub struct_slots: usize,
    /// Objects promoted to variables of their declared type.
    pub promoted: usize,
    /// Slots inside those objects.
    pub promoted_slots: usize,
}

impl Frames {
    /// Adds `other`'s counts.
    pub const fn add(&mut self, other: &Self) {
        self.struct_slots += other.struct_slots;
        self.promoted += other.promoted;
        self.promoted_slots += other.promoted_slots;
    }
}

impl fmt::Display for Frames {
    /// `frame struct slots N, promoted M (slots K)`; empty if all are 0.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if *self == Self::default() {
            return Ok(());
        }
        write!(
            f,
            "frame struct slots {}, promoted {} (slots {})",
            self.struct_slots, self.promoted, self.promoted_slots
        )
    }
}

/// Whether a function is a variadic definition: recognised from its
/// prologue and `va_start` by its convention's rule ([`VaList`]), and
/// what its declared prototype says.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Variadic {
    /// Recognised: its named arguments, the rest of the argument
    /// registers being the list's.
    pub recognised: Option<Named>,
    /// Its declared prototype's `...`: `Some(true)` variadic,
    /// `Some(false)` not, `None` no prototype.
    pub declared: Option<bool>,
    /// Whether it is printed as C's variadic function (`, ...` and
    /// `va_start`: `lower::variadic` says when).
    pub printed: bool,
}

/// The named arguments of a recognised variadic definition.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Named {
    /// In integer argument registers.
    pub integer: u8,
    /// In vector argument registers (System V's `fp_offset`; 0 where the
    /// convention passes unnamed floating-point arguments in integer
    /// registers).
    pub vector: u8,
    /// On the stack, in 8-byte slots (System V's `overflow_arg_area`).
    pub stack: u8,
}

impl fmt::Display for Variadic {
    /// `variadic (named integer/vector/stack N/N/N, declared variadic)`
    /// (`, printed` where it is printed as C's), or `declared variadic,
    /// not recognised`; empty if neither.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let declared = match self.declared {
            Some(true) => "declared variadic",
            Some(false) => "declared fixed",
            None => "undeclared",
        };
        let printed = if self.printed { ", printed" } else { "" };
        match self.recognised {
            Some(named) => write!(
                f,
                "variadic (named integer/vector/stack {}/{}/{}, {declared}{printed})",
                named.integer, named.vector, named.stack
            ),
            None if self.declared == Some(true) => f.write_str("declared variadic, not recognised"),
            None => Ok(()),
        }
    }
}

/// What became of the declared format strings of a function's calls
/// (calls to a `printf`- or `scanf`-like function).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Formats {
    /// Parsed: they give the arguments and their types.
    pub parsed: usize,
    /// Not a constant string in read-only data.
    pub not_constant: usize,
    /// Parsed, but an argument's type has no place (a `long` of unknown
    /// width, one the convention cannot pass).
    pub unplaced: usize,
    /// Refused by the parser, by [`Refusal::index`].
    pub refused: [usize; Refusal::ALL.len()],
}

impl Formats {
    /// Adds `other`'s counts.
    pub fn add(&mut self, other: &Self) {
        self.parsed += other.parsed;
        self.not_constant += other.not_constant;
        self.unplaced += other.unplaced;
        for (slot, count) in self.refused.iter_mut().zip(other.refused) {
            *slot += count;
        }
    }

    /// How many calls had a declared format string.
    pub fn calls(&self) -> usize {
        self.parsed + self.not_constant + self.unplaced + self.refused.iter().sum::<usize>()
    }
}

impl fmt::Display for Formats {
    /// `parsed N`, then each other outcome that happened.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "parsed {}", self.parsed)?;
        let others = [
            ("not constant", self.not_constant),
            ("unplaced", self.unplaced),
        ];
        let refused = Refusal::ALL
            .iter()
            .zip(self.refused)
            .map(|(refusal, count)| (refusal.name(), count));
        for (name, count) in others.into_iter().chain(refused) {
            if count > 0 {
                write!(f, " {name} {count}")?;
            }
        }
        Ok(())
    }
}

/// [`lower`], with its [`Counts`].
///
/// # Errors
///
/// As for [`lower`].
pub fn lower_counted(
    function: &Function,
    facts: &Facts,
    context: &Context<'_>,
) -> Result<(Ast, Mapping, Counts), LowerError> {
    let mut lowering = facts::Lowering::new(function, facts, context)?;
    lowering.prepare();
    let (ast, mapping) = lowering.emit()?;
    binbun_ast::verify::verify(&ast, context.declarations)
        .map_err(|error| LowerError::Invalid(alloc::format!("{error}")))?;
    Ok((ast, mapping, lowering.counts()))
}
