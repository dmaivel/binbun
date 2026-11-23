//! Control-flow recovery for any instruction set: basic blocks, functions,
//! and which calls return, from a [`Memory`] and a few starting points.
//!
//! The recovery sees instructions only through [`binbun_isa`]'s traits, and
//! memory only through [`Memory`], so the same code serves x86 and AArch64,
//! a loaded file and a live target.
//!
//! Recursive descent: from each seed (an entry point, a symbol, an unwind
//! table entry) code is decoded and followed along jumps and branches;
//! call targets become functions. A call's fallthrough is followed only once
//! the callee is known to return, so that bytes after a call to a function
//! that never returns (`exit`, `abort`, a `noreturn` helper) are not taken
//! for code. Computed jumps (through a register or a computed memory
//! operand) are asked about through a [`Resolver`] once the rest of their
//! function is recovered, computed calls once reached. One that always
//! goes through the same pointer slot (a GOT or IAT entry the code
//! addresses in a register: an AArch64 PLT stub) becomes a jump or call
//! through that slot, as if the instruction named it: its block's exit
//! says so from then on. Otherwise a jump's table (a switch) is asked for:
//! the targets it knows
//! become the jump's table, and the function's code. Those it does not
//! know, and other jumps and calls it cannot follow (virtual calls, tail
//! calls through a pointer), are recorded as unresolved.
//!
//! A function whose only block jumps to an import (a PLT stub, a PE import
//! thunk) is an import thunk: an ordinary function, which returns if the
//! import does, so calls to `exit@plt` do not return either.
//!
//! What recovery cannot see, imports above all, it asks about through
//! [`Callees`]; it holds no knowledge of library functions itself.
//!
//! A compiler may split a function into parts placed apart (GCC's
//! `-freorder-blocks-and-partition` moves cold blocks to
//! `.text.unlikely` as `foo.cold`; Clang's `-fsplit-machine-functions`
//! likewise), each with its own unwind table entry, so recovery first finds
//! such a part as a function of its own. Afterwards a function `p` is
//! joined into the function `f` it is a part of (its blocks become `f`'s,
//! [`Function::parts`] lists it) when:
//!
//! 1. only `f`'s code enters it, and only by jumps or branches (at least
//!    one, or an exception unwinding to a landing pad; none from another
//!    function; no call to it), and nothing else
//!    says it is a function: it is not the entry point, not exported, no
//!    pointer stored in data nor an address code computes, and its unwind
//!    table entry does not start an outermost frame (code that starts a
//!    stack of its own, as a `clone` child does, is another thread's, not
//!    a part of the function that made the thread); and
//! 2. something says it is not a function of its own: it jumps back into
//!    `f` (into `f`'s unwind extent or code, not to its entry; a function
//!    never jumps into the middle of another), or its unwind table entry
//!    starts inside a frame (no call could have entered it), or `f` enters
//!    it by a conditional branch (compilers' tail calls are unconditional
//!    jumps; a conditional jump out of a function is how they reach a
//!    part split off it).
//!
//! A part entered from several functions, or called, stays a function;
//! so does a function only tail-called by one other (an unconditional
//! jump and no other evidence). Symbols are not evidence: stripped
//! binaries have none, and the rule finds the parts their names show
//! without them. Joining repeats until nothing changes (a part may enter
//! another).
//!
//! Exceptions: a call through which an exception unwinds to a landing
//! pad ([`Seed::Unwind`], from the exception tables) has an
//! [`EdgeKind::Unwind`] edge there, so a function's landing pads, and
//! the parts only they lead to, are reached from its entry like the rest
//! of its code. A part only landing pads that no recovered call unwinds
//! to reach (code the unwinder enters, through call sites recovery did
//! not find) stays a function of its own, marked [`Function::part_of`],
//! since its function's decompilation would not show its code.
//!
//! Funclets: code that a function's exception handler calls, with the
//! function's frame (Microsoft x64: `__except` filters, `__finally`
//! blocks, C++ catch blocks and unwind actions), is a function in the
//! binary but a part of the function in the source. The exception tables
//! say whose ([`Seed::Funclet`]); recovered as a function of its own (its
//! own frame and unwind entry), it is joined to its function: listed in
//! its [`Function::funclets`] and marked [`Function::part_of`] (a
//! function's funclets are its root's: joined parts' funclets too).

mod parts;
mod recover;

use std::collections::BTreeMap;

use binbun_isa::Target;
use binbun_semantics::core::{Arena, Id, Memory};

pub use recover::{Options, recover};

/// A basic block's id.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Id)]
pub struct BlockId(u32);

/// A function's id.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Id)]
pub struct FunctionId(u32);

/// Whether a function returns to its caller.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Returns {
    /// It can return.
    Yes,
    /// It never returns.
    No,
    /// Not known: assumed to return.
    Unknown,
}

/// Code a call or jump reaches, as recovery asks [`Callees`] about it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Callee {
    /// The function whose address is in the pointer slot at this address
    /// (an import).
    Import(u64),
    /// The function at this address.
    Address(u64),
}

/// What the caller of recovery knows about code it reaches but cannot
/// recover itself (imports) or knows better (functions identified as
/// library code).
pub trait Callees {
    /// Whether the pointer slot at `slot` holds an import's address.
    fn is_import(&self, slot: u64) -> bool;

    /// The code address the pointer slot at `slot` (of `size` bytes)
    /// always holds while the program runs: one the dynamic loader writes
    /// (a relative relocation) or the file holds, where the program
    /// cannot change it. `None` if not known.
    fn slot(&self, slot: u64, size: u8) -> Option<u64> {
        let _ = (slot, size);
        None
    }

    /// Whether `callee` returns, if known. For an address, a known answer
    /// overrides what recovery infers from the code.
    fn returns(&self, callee: Callee) -> Returns;
}

/// Nothing known: no imports, every callee's return found from its code
/// (or assumed).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NothingKnown;

impl Callees for NothingKnown {
    fn is_import(&self, _: u64) -> bool {
        false
    }

    fn returns(&self, _: Callee) -> Returns {
        Returns::Unknown
    }
}

/// Where a computed jump goes, as a [`Resolver`] found it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Table {
    /// The addresses it can go to, sorted.
    pub targets: Vec<u64>,
    /// Whether where the table ends was inferred (its index bounded only
    /// by its width, the entries cut where they stop looking like the
    /// function's code) rather than proven.
    pub inferred: bool,
}

/// What recovery asks about computed jumps and calls it cannot follow:
/// where one goes when it always goes to one place (a pointer slot), and
/// where a jump can go when it reads a table (a switch).
pub trait Resolver {
    /// Where the computed jump or call ending block `jump` (a block of the
    /// function at `entry`, whose blocks so far are `blocks`) always goes:
    /// [`Target::Pointer`] if its address is read from a pointer slot at a
    /// fixed address (a GOT or IAT entry: `adrp x16, slot; ldr x17, [x16,
    /// :lo12:slot]; br x17`, x86 `mov rax, [rip+slot]; jmp rax`), which
    /// recovery then treats as it treats `jmp [rip+slot]` (an import, the
    /// slot's fixed value, or unresolved); [`Target::Address`] if the
    /// address is a constant. `None` (the default) if not known: a jump is
    /// then asked about its [`table`](Self::table).
    ///
    /// A call is asked about as soon as recovery reaches it, with its
    /// block alone as the function (`entry` its start, `blocks` just
    /// `jump`), so that its fallthrough need not wait for the rest of the
    /// function.
    fn target(&mut self, entry: u64, blocks: &[Block], jump: Block) -> Option<Target> {
        let _ = (entry, blocks, jump);
        None
    }

    /// Where the computed jump ending block `jump` (a block of the function
    /// at `entry`, whose blocks so far are `blocks`) can go; `None` if not
    /// known.
    fn table(&mut self, entry: u64, blocks: &[Block], jump: Block) -> Option<Table>;

    /// The end of the data the bytes at `address` are, if they are known
    /// to be data rather than code whatever decodes there (text: a string
    /// and its terminator, as a compiler places in a code section). A
    /// computed address ([`SeedKind::Reference`]) or a pointer stored in
    /// data ([`SeedKind::Pointer`]) there, the only evidence of code
    /// there, then makes no function ([`Program::data`]); stronger seeds
    /// (an entry, a symbol, an unwind table entry, a call) still do.
    /// `None` (the default): they may be code.
    fn data(&mut self, address: u64) -> Option<u64> {
        let _ = address;
        None
    }
}

/// Knows nothing: every computed jump stays unresolved.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NoResolver;

impl Resolver for NoResolver {
    fn table(&mut self, _: u64, _: &[Block], _: Block) -> Option<Table> {
        None
    }
}

/// Why an address is a function's start.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SeedKind {
    /// The program's entry point.
    Entry,
    /// A function symbol the image does not export.
    Symbol,
    /// A symbol the image exports (a dynamic symbol, a PE export): code
    /// outside the image may call it.
    Export,
    /// The start of an unwind table entry.
    Unwind,
    /// The target of a call found during recovery.
    Call,
    /// A pointer to code stored in data (a relocation's target): only a
    /// function if no code recovered from the other seeds contains it.
    Pointer,
    /// An address code computes (an x86 RIP-relative `lea`), found while
    /// recovering: only a function if no other recovered code contains it.
    Reference,
    /// The user's word ([`Seed::Function`] of a correction): a function's
    /// start, never joined into another as a part.
    User,
}

impl SeedKind {
    const fn bit(self) -> u8 {
        match self {
            Self::Entry => 1,
            Self::Symbol => 2,
            Self::Unwind => 4,
            Self::Call => 8,
            Self::Pointer => 16,
            Self::Reference => 32,
            Self::Export => 64,
            Self::User => 128,
        }
    }
}

/// Where recovery starts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Seed {
    /// A function's start.
    Function(u64, SeedKind),
    /// Code of the function at `function` that its blocks do not reach, such
    /// as a landing pad, which only the unwinder jumps to.
    Code {
        /// The function's start.
        function: u64,
        /// The code's address.
        address: u64,
    },
    /// The function at `function` occupies `function..end` (an unwind
    /// table entry says so). A jump out of it is a tail call: into a new
    /// function, unless the target lies within another known extent (code
    /// of that function, as when a cold part jumps back).
    Extent {
        /// The function's start.
        function: u64,
        /// The address after its last byte.
        end: u64,
        /// How the unwind table entry says its code is entered.
        frame: Frame,
    },
    /// `start..end` is code split off a function (an x64 `.pdata` entry
    /// whose unwind information chains to another's: MSVC's
    /// profile-guided hot and cold splitting), which its function may
    /// enter anywhere: what is recovered there is a part of `owner` (the
    /// function the chain ends at) where known, else of the one function
    /// that enters it, not a function of its own.
    Split {
        /// The first byte.
        start: u64,
        /// The byte after the last.
        end: u64,
        /// The function it was split off, where known.
        owner: Option<u64>,
    },
    /// An exception that unwinds through a call in `start..end` (the
    /// call's return address minus one in it, as the unwinder looks it
    /// up) continues at the landing pad `pad` (an exception table's call
    /// site): the call's block has an [`EdgeKind::Unwind`] edge there.
    Unwind {
        /// The first byte of the range.
        start: u64,
        /// The byte after it.
        end: u64,
        /// The landing pad.
        pad: u64,
    },
    /// The code at `address`, recovered as a function, is a funclet of the
    /// function at `function`: code its exception handler calls with its
    /// frame (from the exception tables).
    Funclet {
        /// The function's start.
        function: u64,
        /// The funclet's start.
        address: u64,
    },
    /// The user's correction: the code at the address is code, of no
    /// function unless one reaches it (`C`): decoded and followed
    /// from there (its calls' targets become functions).
    Flow(u64),
    /// The user's correction: no instruction overlaps `start..end` (bytes
    /// the user undefined or typed as data); code that reaches them ends
    /// there ([`Exit::Invalid`]).
    NotCode {
        /// The first byte.
        start: u64,
        /// The byte after the last.
        end: u64,
    },
    /// The user's correction: the function at `function` ends at `end`
    /// (Edit Function). `end` is a block boundary; control leaving
    /// `function..end` (a jump, or falling through) is a tail call into
    /// the function there; the extent replaces an unwind table's
    /// ([`Seed::Extent`]), and no part is joined into the function.
    End {
        /// The function's start.
        function: u64,
        /// The address after its last byte.
        end: u64,
    },
    /// The user's correction: no function starts at the address (a
    /// deleted function): seeds there make none, and a call there is a
    /// call to code of no function, assumed to return.
    NoFunction(u64),
}

impl Seed {
    /// The address of a pointer's target ([`SeedKind::Pointer`]).
    const fn pointer(&self) -> Option<u64> {
        match *self {
            Self::Function(address, SeedKind::Pointer) => Some(address),
            Self::Function(..)
            | Self::Code { .. }
            | Self::Extent { .. }
            | Self::Split { .. }
            | Self::Unwind { .. }
            | Self::Funclet { .. }
            | Self::Flow(_)
            | Self::NotCode { .. }
            | Self::End { .. }
            | Self::NoFunction(_) => None,
        }
    }

    /// The address it is about, as seeds are sorted by.
    pub const fn address(&self) -> u64 {
        match *self {
            Self::Function(address, _)
            | Self::Code { address, .. }
            | Self::Extent {
                function: address, ..
            }
            | Self::Split { start: address, .. }
            | Self::Unwind { start: address, .. }
            | Self::Funclet { address, .. }
            | Self::Flow(address)
            | Self::NotCode { start: address, .. }
            | Self::End {
                function: address, ..
            }
            | Self::NoFunction(address) => address,
        }
    }
}

/// How an unwind table entry says its code is entered.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Frame {
    /// As a function is, by a call.
    Call,
    /// Inside a frame (code split off a function, which no call enters):
    /// evidence that it is a part of the function that jumps to it.
    Inside,
    /// As the outermost frame (where a process or thread starts its own
    /// stack): a function's start, never a part of another.
    Outermost,
}

/// A set of [`SeedKind`]s.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct SeedKinds(u8);

impl SeedKinds {
    /// Whether `kind` is in the set.
    pub const fn contains(self, kind: SeedKind) -> bool {
        self.0 & kind.bit() != 0
    }

    /// Adds `kind`.
    pub const fn insert(&mut self, kind: SeedKind) {
        self.0 |= kind.bit();
    }
}

/// Where a jump or call goes, as recovery resolved it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Destination {
    /// Code at an address.
    Address(u64),
    /// An import, by the address of its pointer slot.
    Import(u64),
    /// The address stored at an address that is no import (unresolved).
    Pointer(u64),
    /// A register or computed memory operand (unresolved).
    Indirect,
    /// A segmented address (unresolved).
    Far,
}

impl Destination {
    /// Whether recovery could not tell where it goes.
    pub const fn is_unresolved(self) -> bool {
        matches!(self, Self::Pointer(_) | Self::Indirect | Self::Far)
    }
}

/// How control leaves a block.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Exit {
    /// It continues at the block's end, where another block starts.
    Next,
    /// An unconditional jump.
    Jump(Destination),
    /// A conditional jump; otherwise it continues at the block's end.
    Branch(Destination),
    /// A call; it continues at the block's end if the callee returns.
    Call {
        /// The callee.
        callee: Destination,
        /// Whether the callee returns.
        returns: Returns,
    },
    /// A return from the function.
    Return,
    /// A trap, a halt or an exception return: execution does not go on.
    Stop,
    /// The instruction at the block's end does not decode, is not mapped,
    /// or is not executable.
    Invalid,
    /// The block hit [`Options::max_block_instructions`].
    Limit,
}

/// A basic block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Block {
    /// Its first instruction's address.
    pub start: u64,
    /// The address after its last instruction.
    pub end: u64,
    /// Number of instructions.
    pub instructions: u32,
    /// How control leaves it.
    pub exit: Exit,
}

/// Why control goes from one block to another.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum EdgeKind {
    /// Falling into the next block.
    Next,
    /// An unconditional jump.
    Jump,
    /// A conditional jump, taken.
    Taken,
    /// A conditional jump, not taken.
    NotTaken,
    /// Returning from a call to the instruction after it.
    CallReturn,
    /// A computed jump, to one of the targets resolved for it.
    Table,
    /// An exception unwinding through a call, to the landing pad the
    /// exception table names for it ([`Seed::Unwind`]).
    Unwind,
}

/// The addresses control can go to next from `block` within the program,
/// as its exit states them: a computed jump's table is not included, and
/// calls' callees are not successors (their return is).
fn static_successors(block: Block) -> impl Iterator<Item = (EdgeKind, u64)> {
    let (first, second) = match block.exit {
        Exit::Next => (Some((EdgeKind::Next, block.end)), None),
        Exit::Jump(Destination::Address(target)) => (Some((EdgeKind::Jump, target)), None),
        Exit::Branch(Destination::Address(target)) => (
            Some((EdgeKind::Taken, target)),
            Some((EdgeKind::NotTaken, block.end)),
        ),
        Exit::Branch(_) => (Some((EdgeKind::NotTaken, block.end)), None),
        Exit::Call {
            returns: Returns::Yes | Returns::Unknown,
            ..
        } => (Some((EdgeKind::CallReturn, block.end)), None),
        Exit::Jump(_)
        | Exit::Call {
            returns: Returns::No,
            ..
        }
        | Exit::Return
        | Exit::Stop
        | Exit::Invalid
        | Exit::Limit => (None, None),
    };
    first.into_iter().chain(second)
}

/// The call-site ranges of exception tables with a landing pad
/// ([`Seed::Unwind`]): start to end and landing pad.
pub(crate) type Unwind = BTreeMap<u64, (u64, u64)>;

/// The landing pad an exception unwinding through a call that returns to
/// `return_address` goes to, from `unwind`: the range holding the address
/// before it, as the unwinder looks it up.
fn landing_pad(unwind: &Unwind, return_address: u64) -> Option<u64> {
    let at = return_address.checked_sub(1)?;
    let (_, &(end, pad)) = unwind.range(..=at).next_back()?;
    (at < end).then_some(pad)
}

/// `block`'s [`EdgeKind::Unwind`] edge, if it ends in a call through which
/// an exception unwinds to a landing pad.
fn unwind_successor(unwind: &Unwind, block: Block) -> Option<(EdgeKind, u64)> {
    match block.exit {
        Exit::Call { .. } => landing_pad(unwind, block.end).map(|pad| (EdgeKind::Unwind, pad)),
        Exit::Next
        | Exit::Jump(_)
        | Exit::Branch(_)
        | Exit::Return
        | Exit::Stop
        | Exit::Invalid
        | Exit::Limit => None,
    }
}

/// A function.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Function {
    /// Its entry point.
    pub entry: u64,
    /// Why it is one.
    pub seeds: SeedKinds,
    /// Its blocks, by address: those reachable from the entry without
    /// passing into another function's entry, from its landing pads, and
    /// those of its [`parts`](Self::parts).
    pub blocks: Vec<BlockId>,
    /// Whether it can return to its caller.
    pub returns: bool,
    /// The entries of the parts of it that recovery first found as
    /// functions of their own and joined into it (cold parts: the
    /// [crate]'s rule), by address. Their blocks are among
    /// [`blocks`](Self::blocks); each part's entry is a block start.
    pub parts: Vec<u64>,
    /// Its landing pads, and those of its parts, by address: code only
    /// the unwinder enters (from its exception tables).
    pub landing_pads: Vec<u64>,
    /// For a part of another function that only that function's landing
    /// pads lead to, or a funclet of another function: that function's
    /// entry. Such a part is kept a function of its own (the [crate]'s
    /// rule).
    pub part_of: Option<u64>,
    /// The entries of its funclets ([`Seed::Funclet`]), by address: each is
    /// a function [`part_of`](Self::part_of) it.
    pub funclets: Vec<u64>,
}

/// Bytes decoded as two different instructions: an instruction that
/// overlaps another block's start.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Conflict {
    /// The instruction's address.
    pub instruction: u64,
    /// The start of the block it overlaps.
    pub block: u64,
}

/// The recovered control flow of a program.
#[derive(Clone, Debug, Default)]
pub struct Program {
    /// Every block decoded (including any after calls later found not to
    /// return, which belong to no function).
    pub blocks: Arena<BlockId, Block>,
    /// The functions.
    pub functions: Arena<FunctionId, Function>,
    /// Overlapping instructions.
    pub conflicts: Vec<Conflict>,
    by_start: BTreeMap<u64, BlockId>,
    by_entry: BTreeMap<u64, FunctionId>,
    /// The resolved targets of computed jumps, by the block they end.
    tables: BTreeMap<BlockId, Table>,
    /// The call-site ranges with a landing pad, by start.
    unwind: Unwind,
    /// The data in code that computed addresses and pointers in data point
    /// to and that made no function ([`Resolver::data`]): start to end.
    data: BTreeMap<u64, u64>,
}

impl Program {
    /// The data in code that computed addresses and pointers in data point
    /// to, which is no function: its bytes are data ([`Resolver::data`]),
    /// and no stronger seed made a function there nor does a block hold
    /// it. Start to end, not overlapping.
    pub fn data(&self) -> &BTreeMap<u64, u64> {
        &self.data
    }

    /// The block that starts at `address`.
    pub fn block_at(&self, address: u64) -> Option<BlockId> {
        self.by_start.get(&address).copied()
    }

    /// The block that contains `address`: the one starting nearest before
    /// it, if it reaches it. (Where code overlaps, an address can also be
    /// in a block that starts earlier.)
    pub fn block_containing(&self, address: u64) -> Option<BlockId> {
        let (_, &id) = self.by_start.range(..=address).next_back()?;
        self.blocks.get(id).filter(|b| address < b.end).map(|_| id)
    }

    /// The function that starts at `address`.
    pub fn function_at(&self, address: u64) -> Option<FunctionId> {
        self.by_entry.get(&address).copied()
    }

    /// Blocks, sorted by start.
    pub fn blocks_by_address(&self) -> impl Iterator<Item = (u64, BlockId)> + '_ {
        self.by_start.iter().map(|(&start, &id)| (start, id))
    }

    /// Where the computed jump ending `block` goes, when the [`Resolver`]
    /// knew (a switch table's cases).
    pub fn table(&self, block: BlockId) -> Option<&Table> {
        self.tables.get(&block)
    }

    /// The addresses control can go to next from `block` within the
    /// program: those its exit states, and its computed jump's
    /// [`table`](Self::table), and a call's landing pad (calls' callees are
    /// not successors; their return is).
    pub fn successors(&self, block: BlockId) -> impl Iterator<Item = (EdgeKind, u64)> + '_ {
        let table = self
            .table(block)
            .into_iter()
            .flat_map(|table| &table.targets)
            .map(|&target| (EdgeKind::Table, target));
        let block = self.blocks.get(block).copied();
        let unwind = block.and_then(|block| unwind_successor(&self.unwind, block));
        block
            .into_iter()
            .flat_map(static_successors)
            .chain(table)
            .chain(unwind)
    }

    /// The landing pad an exception unwinding through the call that
    /// returns to `return_address` goes to ([`Seed::Unwind`]), if one.
    pub fn landing_pad(&self, return_address: u64) -> Option<u64> {
        landing_pad(&self.unwind, return_address)
    }

    /// The jumps and calls whose destination recovery could not tell, with
    /// their block (switch tables the [`Resolver`] did not know, virtual and
    /// function-pointer calls).
    pub fn unresolved(&self) -> impl Iterator<Item = (BlockId, Destination)> + '_ {
        self.blocks
            .iter()
            .filter_map(|(id, block)| match block.exit {
                Exit::Jump(destination)
                | Exit::Branch(destination)
                | Exit::Call {
                    callee: destination,
                    ..
                } if destination.is_unresolved() && !self.tables.contains_key(&id) => {
                    Some((id, destination))
                }
                Exit::Jump(_)
                | Exit::Branch(_)
                | Exit::Call { .. }
                | Exit::Next
                | Exit::Return
                | Exit::Stop
                | Exit::Invalid
                | Exit::Limit => None,
            })
    }
}

/// Builds the result from recovery's tables.
fn program(
    blocks: Arena<BlockId, Block>,
    by_start: BTreeMap<u64, BlockId>,
    functions: Arena<FunctionId, Function>,
    conflicts: Vec<Conflict>,
    tables: BTreeMap<BlockId, Table>,
    unwind: Unwind,
    data: BTreeMap<u64, u64>,
) -> Program {
    let by_entry = functions.iter().map(|(id, f)| (f.entry, id)).collect();
    Program {
        blocks,
        functions,
        conflicts,
        by_start,
        by_entry,
        tables,
        unwind,
        data,
    }
}

/// Recovers the one function at `entry`, without recovering its callees:
/// calls are assumed to return unless they go to an import known not to
/// (for debuggers, which want one function's graph from a live target).
/// `resolver` tells where its computed jumps go.
pub fn recover_function<A: binbun_isa::Architecture, M: Memory>(
    architecture: &A,
    mode: A::Mode,
    memory: &M,
    entry: u64,
    callees: &impl Callees,
    resolver: &mut dyn Resolver,
) -> Program {
    let options = Options {
        follow_calls: false,
        ..Options::default()
    };
    recover(
        architecture,
        mode,
        memory,
        &[Seed::Function(entry, SeedKind::Symbol)],
        callees,
        resolver,
        &options,
    )
}
