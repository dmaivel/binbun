//! Funclets built into their functions (Microsoft x64): the code a
//! function's exception handler calls with the function's frame
//! (`__finally` blocks, C++ catch blocks and unwind funclets) becomes L1
//! code of the function
//! ([`Funclets`]), reached from the calls an exception unwinds through as
//! landing pads are, so lowering gives it the function's frame and
//! variables. Filters are not: the runtime runs them before anything
//! unwinds, and their expressions join the `__except` in L2
//! ([`crate::decompile`]).
//!
//! - **The frame**: the runtime hands a funclet the function's establisher
//!   frame in `rdx`. Its distance below the function's entry stack pointer
//!   is what the prologue pushes and allocates up to the frame register (or
//!   all of it), as the function's `UNWIND_INFO` codes say
//!   ([`FrameHandler::establisher`]): the runtime computes the establisher
//!   frame from the same codes (by unwinding the prologue), so L1's landing
//!   gives `rdx` the entry stack pointer minus that distance
//!   ([`Unwind::frames`]), and a funclet's `[rdx + k]` is the function's
//!   frame at entry + k − distance.
//! - **Its own frame**: a funclet's stack pointer at entry is the
//!   function's at the call, less the return address the call pushed: what
//!   it pushes and allocates is below the function's frame, the handler's
//!   own.
//! - **Unwinding as a chain**: the handlers an exception unwinding through
//!   a call meets, innermost first. Structured exception handling: the
//!   scopes whose range holds the call, in the table's order (an `__except`
//!   block, code of the function the runtime unwinds to with the code in
//!   `rax`; a `__finally` funclet). C++: from the call's state (the
//!   IP-to-state map, at the return address minus one as the runtime looks
//!   it up), each state, then the state it unwinds to: a try block whose
//!   lowest state it is, and whose body holds the call's state, offers its
//!   catch blocks first; then the state's unwind funclet runs.
//! - **Pads** ([`Unwind`]), one per chain from a handler on: an `__except`
//!   block; an unwind funclet or `__finally` block, entered with `rcx` (a
//!   termination handler's `AbnormalTermination()`); a try block's catch
//!   blocks, which the runtime chooses among (L1's selector, the second
//!   value the pad receives: catch block *i* is *i*), else the state's
//!   unwind funclet, else unwinding goes on ([`Resume`], to the rest of
//!   the chain: a call that does not return to the address of the
//!   function's exception handling data, which no code calls, where the
//!   handler itself may be a function code calls).
//! - **Returns** ([`FuncletReturn`]): an unwind funclet's or `__finally`
//!   block's return (or tail call) goes on unwinding, to the rest of its
//!   chain; a catch block's goes to the continuation it returns in `rax`,
//!   which `__CxxFrameHandler4`'s table lists, and which for
//!   `__CxxFrameHandler3` constant propagation finds in the catch block's
//!   own L1 (the constant each of its returns hands back). At every
//!   return the registers the convention has a function keep hold their
//!   values at the funclet's entry (the funclet is a function the runtime
//!   calls), and a catch block's continuation has the establisher frame as
//!   its stack pointer (where the runtime unwinds to).
//! - **Catch-alls**: a try's `catch (...)` takes every exception, so the
//!   runtime's choice ends there (no cleanup, no resume after it).
//!
//! A function whose funclets cannot all be built in (its establisher frame
//! not known, a funclet no function of the program, one funclet in two
//! roles or sharing code with another, a continuation not found) is built
//! without them, its funclets left functions of their own.

use std::collections::{BTreeMap, BTreeSet};

use crate::cfg::{Block, FunctionId, Program};
use binbun_loader::{
    Catch, CxxTable, FrameHandler, FuncletKind, HandlerTable, Image, Machine, Scope, ScopeAction,
    SehFilter,
};
use binbun_semantics::RegisterId;
use binbun_semantics::ir::Binary;
use binbun_ssa::ir::Definition;
use binbun_ssa::{FuncletReturn, Op, Resume, Terminator, Unwind, Value};
use binbun_x86_lift::X86;

use crate::lift::lift_function;
use crate::summary::Summaries;
use crate::target::Abi;

/// How far below a call's stack pointer (after it pushed the return
/// address) a funclet's starts: the 32 bytes of home space the x64
/// convention has a caller reserve, the runtime's frame below the
/// function's. What the funclet stores there and below is its own.
const HOME: i64 = 32;

/// Where a funclet's stack pointer is once it returned (its return address
/// popped), from a call's.
const RETURNED: i64 = 8 - HOME;

/// A handler an exception unwinding through a call meets.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Step {
    /// An `__except` block (code of the function).
    Except(u64),
    /// An unwind funclet or a `__finally` block.
    Cleanup(u64),
    /// A try block's catch blocks, in the order the runtime tries them,
    /// then its `catch (...)` (which takes every exception: nothing after
    /// it runs), or else the unwind funclet of the try's lowest state, if
    /// it has one.
    Dispatch {
        catches: Vec<u64>,
        all: Option<u64>,
        cleanup: Option<u64>,
    },
}

/// The registers the model names.
#[derive(Clone, Debug)]
struct Registers {
    rsp: RegisterId,
    rax: RegisterId,
    rcx: RegisterId,
    rdx: RegisterId,
    /// Those a call keeps (the unwinder restores them).
    kept: Vec<RegisterId>,
}

/// The funclets of a function built into its L1 (see the module
/// documentation).
#[derive(Clone, Debug)]
pub struct Funclets {
    /// Where the function's exception handling data is
    /// ([`FrameHandler::data`]): a call there, which no code makes (the
    /// handler itself is a function other code may call: a statically
    /// linked `__CxxFrameHandler3` is), stands for the runtime going on
    /// unwinding.
    runtime: u64,
    /// How far the establisher frame is below the entry stack pointer.
    establisher: u64,
    /// The function's exception handling data.
    table: HandlerTable,
    /// The C++ tables of funclets with exception handling data of their
    /// own (`__CxxFrameHandler4`'s catch blocks), by the funclet's start:
    /// the states of their code.
    own: BTreeMap<u64, CxxTable>,
    /// The starts of the function and of the funclets built in, sorted:
    /// an IP-to-state map's entries count only within the code they map.
    starts: Vec<u64>,
    registers: Registers,
    /// What the return of each funclet built in does, by the blocks of its
    /// code (start, end), with the funclet's entry.
    returns: Vec<(u64, u64, u64, FuncletReturn)>,
    /// The catch blocks' continuations.
    continuations: Vec<u64>,
    /// The functions of the program whose code is built in: the funclets,
    /// and continuations recovered as functions of their own.
    parts: Vec<FunctionId>,
    /// The blocks of `parts` (those the function's own do not hold).
    blocks: Vec<Block>,
}

impl Funclets {
    /// The funclets of `function` of `program` (recovered from `image`),
    /// if its handler's are all built in (see the module documentation).
    pub fn of(image: &Image<'_>, program: &Program, function: FunctionId) -> Option<Self> {
        if image.machine != Machine::X86_64 {
            return None;
        }
        let f = program.functions.get(function)?;
        let handler = image
            .frame_handlers
            .iter()
            .find(|handler| handler.function == f.entry)?;
        let runtime = handler.data;
        let establisher = handler.establisher?;
        let abi = Abi::of(image).ok()?;
        let find = |name| X86.find(name);
        let kept = (0..abi.declarations.registers.len())
            .filter_map(|index| u16::try_from(index).ok().map(RegisterId))
            .filter(|&register| {
                register != abi.stack_pointer && !abi.call.changes.contains(&register)
            })
            .collect();
        let mut model = Self {
            runtime,
            establisher,
            table: handler.table.clone(),
            own: BTreeMap::new(),
            starts: vec![f.entry],
            registers: Registers {
                rsp: abi.stack_pointer,
                rax: find("rax")?,
                rcx: find("rcx")?,
                rdx: find("rdx")?,
                kept,
            },
            returns: Vec::new(),
            continuations: Vec::new(),
            parts: Vec::new(),
            blocks: Vec::new(),
        };
        let roles = model.roles(image, program, handler)?;
        for &address in roles.keys() {
            model.starts.push(address);
            if let Some(HandlerTable::Cxx(cxx)) = image
                .frame_handlers
                .iter()
                .find(|handler| handler.function == address)
                .map(|handler| &handler.table)
            {
                model.own.insert(address, cxx.clone());
            }
        }
        model.starts.sort_unstable();
        // The function's own blocks, then each part's, none shared.
        let mut covered: Vec<(u64, u64)> = Vec::new();
        let own = blocks(program, function)?;
        covered.extend(own.iter().map(|block| (block.start, block.end)));
        let overlaps = |covered: &[(u64, u64)], block: &Block| {
            covered
                .iter()
                .any(|&(start, end)| start < block.end && block.start < end)
        };
        for (address, resumed) in roles {
            let part = program.function_at(address)?;
            let code = blocks(program, part)?;
            if code.iter().any(|block| overlaps(&covered, block)) {
                return None;
            }
            for block in &code {
                covered.push((block.start, block.end));
                model
                    .returns
                    .push((block.start, block.end, address, resumed.clone()));
            }
            model.parts.push(part);
            model.blocks.extend(code);
        }
        // A continuation is code of the function, or recovered as a
        // function of its own (no code of the function reaches it).
        for &continuation in &model.continuations.clone() {
            if covered
                .iter()
                .any(|&(start, end)| (start..end).contains(&continuation))
            {
                continue;
            }
            let part = program.function_at(continuation)?;
            let code = blocks(program, part)?;
            let code: Vec<Block> = code
                .into_iter()
                .filter(|block| !overlaps(&covered, block))
                .collect();
            if !code
                .iter()
                .any(|block| (block.start..block.end).contains(&continuation))
            {
                return None;
            }
            covered.extend(code.iter().map(|block| (block.start, block.end)));
            model.parts.push(part);
            model.blocks.extend(code);
        }
        Some(model)
    }

    /// Each funclet built in, with what its return does: `None` if one is
    /// not known (a catch block's continuation), or one funclet has two
    /// roles. Collects the continuations.
    fn roles(
        &mut self,
        image: &Image<'_>,
        program: &Program,
        handler: &FrameHandler,
    ) -> Option<BTreeMap<u64, FuncletReturn>> {
        let mut roles: BTreeMap<u64, FuncletReturn> = BTreeMap::new();
        let add = |roles: &mut BTreeMap<u64, FuncletReturn>, address, resumed| {
            if let Some(known) = roles.get(&address) {
                return *known == resumed;
            }
            roles.insert(address, resumed);
            true
        };
        match &handler.table {
            HandlerTable::Scopes(scopes) => {
                for (index, scope) in scopes.iter().enumerate() {
                    let ScopeAction::Finally(funclet) = scope.action else {
                        continue;
                    };
                    let rest = Self::scope_chain(scopes.get(index + 1..)?, |other| {
                        other.start <= scope.start && scope.end <= other.end
                    });
                    let resumed = FuncletReturn::Resume(self.resume(&rest, RETURNED));
                    if !add(&mut roles, funclet, resumed) {
                        return None;
                    }
                }
            }
            HandlerTable::Cxx(cxx) => {
                for (state, entry) in cxx.unwind.iter().enumerate() {
                    let Some(funclet) = entry.action else {
                        continue;
                    };
                    let state = i32::try_from(state).ok()?;
                    let rest = Self::cxx_chain(cxx, entry.next, state);
                    let resumed = FuncletReturn::Resume(self.resume(&rest, RETURNED));
                    if !add(&mut roles, funclet, resumed) {
                        return None;
                    }
                }
                for catch in cxx.tries.iter().flat_map(|block| &block.catches) {
                    let targets = if catch.continuations.is_empty() {
                        continuations(image, program, catch.funclet, self.registers.rax)?
                    } else {
                        catch.continuations.clone()
                    };
                    self.continuations.extend(&targets);
                    let resumed = FuncletReturn::Continue {
                        register: self.registers.rax,
                        targets,
                        frames: vec![(
                            self.registers.rsp,
                            self.registers.rsp,
                            0i64.checked_sub_unsigned(self.establisher)?,
                        )],
                    };
                    if !add(&mut roles, catch.funclet, resumed) {
                        return None;
                    }
                }
            }
        }
        self.continuations.sort_unstable();
        self.continuations.dedup();
        // Every funclet of the function's table (but filters) is built in.
        let all = handler
            .funclets()
            .filter(|&(_, kind)| kind != FuncletKind::Filter)
            .all(|(address, _)| roles.contains_key(&address));
        all.then_some(roles)
    }

    /// The steps of `scopes` (in the table's order) that `holds` says
    /// hold the code.
    fn scope_chain(scopes: &[Scope], holds: impl Fn(&Scope) -> bool) -> Vec<Step> {
        scopes
            .iter()
            .filter(|scope| holds(scope))
            .map(|scope| match scope.action {
                ScopeAction::Except { target, .. } => Step::Except(target),
                ScopeAction::Finally(funclet) => Step::Cleanup(funclet),
            })
            .collect()
    }

    /// The steps from C++ state `state` on, for code in state `origin` (a
    /// try block offers its catch blocks at its lowest state only to code
    /// of its body).
    fn cxx_chain(cxx: &CxxTable, mut state: i32, origin: i32) -> Vec<Step> {
        let mut steps = Vec::new();
        for _ in 0..=cxx.unwind.len() {
            let Some(entry) = usize::try_from(state)
                .ok()
                .and_then(|index| cxx.unwind.get(index))
            else {
                break;
            };
            let mut catches: Vec<u64> = Vec::new();
            let mut all = None;
            for catch in cxx
                .tries
                .iter()
                .filter(|block| block.low == state && block.low <= origin && origin <= block.high)
                .flat_map(|block| &block.catches)
            {
                if catch_all(catch) {
                    all = Some(catch.funclet);
                    break;
                }
                catches.push(catch.funclet);
            }
            if all.is_some() {
                steps.push(Step::Dispatch {
                    catches,
                    all,
                    cleanup: None,
                });
                break;
            }
            if !catches.is_empty() {
                steps.push(Step::Dispatch {
                    catches,
                    all: None,
                    cleanup: entry.action,
                });
            } else if let Some(funclet) = entry.action {
                steps.push(Step::Cleanup(funclet));
            }
            state = entry.next;
        }
        steps
    }

    /// The chain of handlers an exception unwinding through the call at
    /// `ip` meets.
    fn chain(&self, ip: u64) -> Vec<Step> {
        match &self.table {
            HandlerTable::Scopes(scopes) => {
                Self::scope_chain(scopes, |scope| scope.start <= ip && ip < scope.end)
            }
            HandlerTable::Cxx(cxx) => {
                // The code's part (the function, or a funclet), and the
                // table mapping it: the funclet's own, else the function's.
                let part = self
                    .starts
                    .partition_point(|&start| start <= ip)
                    .checked_sub(1)
                    .and_then(|at| self.starts.get(at))
                    .copied()
                    .unwrap_or(0);
                let cxx = self.own.get(&part).unwrap_or(cxx);
                let at = cxx.states.partition_point(|range| range.start <= ip);
                let state = at
                    .checked_sub(1)
                    .and_then(|at| cxx.states.get(at))
                    .filter(|range| range.start >= part)
                    .map_or(-1, |range| range.state);
                Self::cxx_chain(cxx, state, state)
            }
        }
    }

    /// Unwinding going on to `chain`, from code whose stack pointer is
    /// `from` from a call's ([`Self::pad`]).
    fn resume(&self, chain: &[Step], from: i64) -> Resume {
        Resume {
            runtime: self.runtime,
            unwind: self.pad(chain, from).map(Box::new),
        }
    }

    /// The landing pad of `chain`, entered from code whose stack pointer is
    /// `from` from a call's (after it pushed the return address): an
    /// `__except` block gets the function's stack pointer (the call's
    /// before it pushed), a funclet the call's less the home space the
    /// runtime's frame below the function's gives it ([`HOME`]).
    fn pad(&self, chain: &[Step], from: i64) -> Option<Unwind> {
        let (first, rest) = chain.split_first()?;
        let r = &self.registers;
        let frames = vec![(r.rdx, r.rsp, 0i64.checked_sub_unsigned(self.establisher)?)];
        let entry = -HOME - from;
        Some(match first {
            &Step::Except(target) => Unwind {
                pad: target,
                kept: r.kept.clone(),
                stack: Some((r.rsp, 8 - from)),
                receives: vec![r.rax],
                ..Unwind::default()
            },
            &Step::Cleanup(funclet) => Unwind {
                pad: funclet,
                kept: r.kept.clone(),
                stack: Some((r.rsp, entry)),
                receives: vec![r.rcx],
                frames,
                ..Unwind::default()
            },
            Step::Dispatch {
                catches,
                all,
                cleanup,
            } => Unwind {
                pad: all.or(*cleanup).or_else(|| catches.first().copied())?,
                kept: r.kept.clone(),
                stack: Some((r.rsp, entry)),
                receives: vec![r.rcx, r.rax],
                frames,
                choices: (1..)
                    .zip(catches)
                    .map(|(selector, &funclet)| (selector, funclet))
                    .collect(),
                resume: (all.is_none() && cleanup.is_none()).then(|| self.resume(rest, -HOME)),
            },
        })
    }

    /// The landing pad an exception unwinding through the call returning to
    /// `return_address` goes to, if any.
    pub fn unwind(&self, return_address: u64) -> Option<Unwind> {
        self.pad(&self.chain(return_address.checked_sub(1)?), 0)
    }

    /// What the return at `site` does, with the entry of its funclet, if
    /// `site` is in a funclet built in.
    pub fn funclet_return(&self, site: u64) -> Option<(u64, FuncletReturn)> {
        self.returns
            .iter()
            .find(|&&(start, end, _, _)| (start..end).contains(&site))
            .map(|(_, _, entry, resumed)| (*entry, resumed.clone()))
    }

    /// The funclets built in, by entry, with the registers the convention
    /// has them keep.
    pub fn entries(&self) -> Vec<(u64, Vec<RegisterId>)> {
        let mut entries: Vec<u64> = self.returns.iter().map(|&(_, _, entry, _)| entry).collect();
        entries.dedup();
        entries
            .into_iter()
            .map(|entry| (entry, self.registers.kept.clone()))
            .collect()
    }

    /// The catch blocks' continuations.
    pub fn continuations(&self) -> &[u64] {
        &self.continuations
    }

    /// The functions of the program whose code is built in.
    pub fn parts(&self) -> &[FunctionId] {
        &self.parts
    }

    /// The blocks of [`parts`](Self::parts) built in.
    pub fn blocks(&self) -> &[Block] {
        &self.blocks
    }
}

/// The entries of the functions of `program` (recovered from `image`)
/// built into another ([`Funclets::parts`]): not decompiled on their own.
pub fn built_in(image: &Image<'_>, program: &Program) -> BTreeSet<u64> {
    let mut entries = BTreeSet::new();
    for handler in &image.frame_handlers {
        let Some(function) = program.function_at(handler.function) else {
            continue;
        };
        let Some(model) = Funclets::of(image, program, function) else {
            continue;
        };
        entries.extend(
            model
                .parts()
                .iter()
                .filter_map(|&part| program.functions.get(part))
                .map(|part| part.entry),
        );
    }
    entries
}

/// The funclets `image`'s exception handling data names, built in or not:
/// the termination handlers and filter funclets of `__try` scopes, and C++
/// catch blocks and unwind funclets. Each is part of its function.
pub fn named(image: &Image<'_>) -> BTreeSet<u64> {
    let mut entries = BTreeSet::new();
    for handler in &image.frame_handlers {
        match &handler.table {
            HandlerTable::Scopes(scopes) => {
                entries.extend(scopes.iter().filter_map(|scope| match scope.action {
                    ScopeAction::Finally(funclet)
                    | ScopeAction::Except {
                        filter: SehFilter::Funclet(funclet),
                        ..
                    } => Some(funclet),
                    ScopeAction::Except {
                        filter: SehFilter::Constant(_),
                        ..
                    } => None,
                }));
            }
            HandlerTable::Cxx(cxx) => {
                entries.extend(cxx.unwind.iter().filter_map(|state| state.action));
                entries.extend(
                    cxx.tries
                        .iter()
                        .flat_map(|t| &t.catches)
                        .map(|catch| catch.funclet),
                );
            }
        }
    }
    entries
}

/// Whether `catch` is `catch (...)`: its adjective says so, or it names no
/// type.
pub fn catch_all(catch: &Catch) -> bool {
    catch.adjectives & 0x40 != 0 || catch.ty.is_none()
}

/// The blocks of `function` of `program`.
fn blocks(program: &Program, function: FunctionId) -> Option<Vec<Block>> {
    let function = program.functions.get(function)?;
    function
        .blocks
        .iter()
        .map(|&id| program.blocks.get(id).copied())
        .collect()
}

/// Where the catch block at `funclet` (a function of `program`) goes on:
/// the constant each of its returns hands back in `rax`, by constant
/// folding its own L1 (none if it never returns: it throws on); `None` if
/// one is not constant.
fn continuations(
    image: &Image<'_>,
    program: &Program,
    funclet: u64,
    rax: RegisterId,
) -> Option<Vec<u64>> {
    let id = program.function_at(funclet)?;
    let l1 = lift_function(image, program, id, &Summaries::new()).ok()?;
    let mut targets = Vec::new();
    for block in &l1.blocks {
        if let Terminator::Return { state, .. } = &block.terminator {
            let &value = state.registers.get(usize::from(rax.0))?;
            targets.push(constant(&l1, value, 8)?);
        }
    }
    targets.sort_unstable();
    targets.dedup();
    Some(targets)
}

/// The constant `value` of `function` is, through constants, sums and
/// differences (at most `depth` deep).
fn constant(function: &binbun_ssa::Function, value: Value, depth: u32) -> Option<u64> {
    let depth = depth.checked_sub(1)?;
    let Definition::Result { inst, .. } = function.value(value)?.definition else {
        return None;
    };
    let op = &function.inst(inst)?.op;
    if let Op::Const(bits) = op {
        return Some(bits.low_u64());
    }
    let &Op::Binary(binary, a, b) = op else {
        return None;
    };
    let (a, b) = (constant(function, a, depth)?, constant(function, b, depth)?);
    match binary {
        Binary::Add => Some(a.wrapping_add(b)),
        Binary::Sub => Some(a.wrapping_sub(b)),
        Binary::Mul
        | Binary::UDiv
        | Binary::URem
        | Binary::SDiv
        | Binary::SRem
        | Binary::And
        | Binary::Or
        | Binary::Xor
        | Binary::Shl
        | Binary::LShr
        | Binary::AShr
        | Binary::Rol
        | Binary::Ror
        | Binary::Eq
        | Binary::Ne
        | Binary::ULt
        | Binary::ULe
        | Binary::SLt
        | Binary::SLe => None,
    }
}
