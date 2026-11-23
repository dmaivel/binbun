//! L1 for recovered functions: each block of a function decoded and lifted
//! to L0, and what calls do from the image's calling convention, built in
//! SSA form ([`binbun_ssa`]). x86-64 and AArch64 images (the architecture
//! is the image's). An instruction without semantics that continues with
//! the next one is lifted as its architecture's over-approximation
//! (`lift_opaque`); a control transfer without semantics fails its function.

use std::error::Error;
use std::fmt;

use std::collections::BTreeMap;

use crate::cfg::{Block, Destination, Exit, FunctionId, Program, Returns};
use binbun_aarch64_lift::LiftError as A64LiftError;
use binbun_aarch64_lift::registers as a64;
use binbun_isa::Flow;
use binbun_loader::Image;
use binbun_print::c::Unlifted;
use binbun_semantics::core::Memory as _;
use binbun_semantics::ir::{Stmt, Trap};
use binbun_semantics::{Declarations, RegisterId, Semantics};
use binbun_ssa::{
    CallEffect, Code, Environment, FuncletReturn, Function, Instruction, Unwind, build,
};
use binbun_x86::{MAX_LENGTH, Mode, decode};
use binbun_x86_lift::registers::names;
use binbun_x86_lift::{LiftError, lift, lift_opaque, opaque_outputs};

use crate::funclets::Funclets;
use crate::summary::Summaries;
use crate::target::{Abi, Isa};

/// Why a function cannot be put in SSA form.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SsaError(pub String);

impl fmt::Display for SsaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Error for SsaError {}

/// How an instruction's L0 came about.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// It is the instruction's semantics.
    Semantics,
    /// The instruction has no semantics yet: it is the over-approximation
    /// of its architecture's `lift_opaque`.
    Opaque,
}

/// An instruction decoded and lifted ([`decode_and_lift`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Lifted {
    /// The address of the instruction after it.
    pub next: u64,
    /// Its L0 and how it came about, or why it cannot be lifted (a control
    /// transfer without semantics, or a problem lifting it).
    pub semantics: Result<(Semantics, Kind), SsaError>,
}

/// The instruction of `image` at `address`, decoded and lifted (x86-64 or
/// AArch64, as the image is): its semantics, or, for an instruction that
/// has none yet and continues with the next one, the over-approximation of
/// its architecture's `lift_opaque`.
///
/// # Errors
///
/// The image's code is not lifted, the address is not readable or does not
/// decode, or the instruction cannot be lifted (a control transfer without
/// semantics, or a problem lifting it).
pub fn lift_instruction(image: &Image<'_>, address: u64) -> Result<Instruction, SsaError> {
    let lifted = decode_and_lift(image, address)?;
    let (semantics, _) = lifted.semantics?;
    Ok(Instruction {
        address,
        next: lifted.next,
        semantics,
    })
}

/// The instruction of `image` at `address` decoded, and lifted as
/// [`lift_instruction`] does, saying how ([`Kind`]); its end is known even
/// where lifting fails.
///
/// # Errors
///
/// The image's code is not lifted, or the address is not readable or does
/// not decode.
pub fn decode_and_lift(image: &Image<'_>, address: u64) -> Result<Lifted, SsaError> {
    match Isa::of(image)? {
        Isa::X86_64 => lift_x86(image, address),
        Isa::A64 => lift_a64(image, address),
    }
}

/// [`decode_and_lift`] for x86-64.
fn lift_x86(image: &Image<'_>, address: u64) -> Result<Lifted, SsaError> {
    let mode = Mode::Bits64;
    let mut buffer = [0u8; MAX_LENGTH];
    let read = image
        .read(address, &mut buffer)
        .map_err(|error| SsaError(format!("{address:#x}: {error}")))?;
    let bytes = buffer.get(..read).unwrap_or_default();
    let instruction =
        decode(bytes, mode).map_err(|error| SsaError(format!("{address:#x}: {error}")))?;
    let semantics = match lift(&instruction, mode, address) {
        Ok(semantics) if !interrupts_known(image, &semantics) => Err(SsaError(format!(
            "{address:#x} `{}`: an interrupt whose handler the platform does not define",
            instruction.intel(address)
        ))),
        Ok(semantics) => Ok((semantics, Kind::Semantics)),
        Err(LiftError::Unsupported) if instruction.flow(address) == Flow::Next => {
            Ok((lift_opaque(&instruction, mode, address), Kind::Opaque))
        }
        Err(error) => {
            let problem = match error {
                LiftError::Unsupported => "a control transfer without semantics".to_owned(),
                LiftError::Mode(other) => format!("{other:?} code is not lifted"),
                LiftError::Problem(problem) => problem,
            };
            Err(SsaError(format!(
                "{address:#x} `{}`: {problem}",
                instruction.intel(address)
            )))
        }
    };
    Ok(Lifted {
        next: address.wrapping_add(instruction.len() as u64),
        semantics,
    })
}

/// Whether every software interrupt `semantics` traps to is one `image`'s
/// platform defines as ending there, as the CFG takes every `INT n`
/// ([`Flow::Trap`]): Windows' `__fastfail` (vector `0x29`) ends the
/// process. Another's handler may return, with what it changed unknown,
/// which L1 cannot say: its function is not lifted, as before `INT n`
/// had semantics.
fn interrupts_known(image: &Image<'_>, semantics: &Semantics) -> bool {
    let windows = image.format == binbun_loader::Format::Pe;
    !semantics.body.iter().any(|stmt| {
        matches!(stmt, Stmt::Trap(Trap::Interrupt(vector)) if !(windows && *vector == FASTFAIL))
    })
}

/// Windows' `__fastfail` interrupt vector.
const FASTFAIL: u8 = 0x29;

/// The instruction of `image` at `address` as its decoder's text (x86-64:
/// Intel syntax as XED prints it; AArch64: LLVM's), with the address of
/// the instruction after it.
///
/// # Errors
///
/// The image's code is not lifted, or the address is not readable or does
/// not decode.
pub fn disassemble(image: &Image<'_>, address: u64) -> Result<(String, u64), SsaError> {
    let unreadable = |error: &dyn fmt::Display| SsaError(format!("{address:#x}: {error}"));
    match Isa::of(image)? {
        Isa::X86_64 => {
            let mut buffer = [0u8; MAX_LENGTH];
            let read = image
                .read(address, &mut buffer)
                .map_err(|error| unreadable(&error))?;
            let instruction = decode(buffer.get(..read).unwrap_or_default(), Mode::Bits64)
                .map_err(|error| unreadable(&error))?;
            let next = address.wrapping_add(instruction.len() as u64);
            Ok((instruction.intel(address).to_string(), next))
        }
        Isa::A64 => {
            let mut buffer = [0u8; 4];
            let read = image
                .read(address, &mut buffer)
                .map_err(|error| unreadable(&error))?;
            let instruction = binbun_aarch64::decode_bytes(buffer.get(..read).unwrap_or_default())
                .map_err(|error| unreadable(&error))?;
            Ok((
                instruction.display(address).to_string(),
                address.wrapping_add(4),
            ))
        }
    }
}

/// The instruction of `image` at `address`, lifted without semantics
/// (its architecture's `lift_opaque`), as the printer shows it: its text
/// ([`disassemble`]) and what each output of its intrinsic is called
/// (the register it writes, by the width read of it: x86's
/// [`names`](binbun_x86_lift::registers::names), AArch64's
/// [`names`](binbun_aarch64_lift::registers::names); none for a value it
/// stores).
///
/// # Errors
///
/// As for [`disassemble`], or AArch64's `lift_opaque` refuses it.
pub fn unlifted(image: &Image<'_>, address: u64) -> Result<Unlifted, SsaError> {
    let (text, _) = disassemble(image, address)?;
    // XED leaves a space after a mnemonic without operands (`rdpkru `).
    let text = text.trim_end().to_owned();
    let unreadable = |error: &dyn fmt::Display| SsaError(format!("{address:#x}: {error}"));
    let outputs = match Isa::of(image)? {
        Isa::X86_64 => {
            let mut buffer = [0u8; MAX_LENGTH];
            let read = image
                .read(address, &mut buffer)
                .map_err(|error| unreadable(&error))?;
            let instruction = decode(buffer.get(..read).unwrap_or_default(), Mode::Bits64)
                .map_err(|error| unreadable(&error))?;
            opaque_outputs(&instruction, Mode::Bits64)
                .into_iter()
                .map(names)
                .collect()
        }
        Isa::A64 => {
            let mut buffer = [0u8; 4];
            let read = image
                .read(address, &mut buffer)
                .map_err(|error| unreadable(&error))?;
            let instruction = binbun_aarch64::decode_bytes(buffer.get(..read).unwrap_or_default())
                .map_err(|error| unreadable(&error))?;
            binbun_aarch64_lift::opaque_outputs(&instruction, address)
                .map_err(|error| unreadable(&format_args!("{error:?}")))?
                .into_iter()
                .map(|view| view.map(a64::names).unwrap_or_default())
                .collect()
        }
    };
    Ok(Unlifted { text, outputs })
}

/// [`decode_and_lift`] for AArch64.
fn lift_a64(image: &Image<'_>, address: u64) -> Result<Lifted, SsaError> {
    let mut buffer = [0u8; 4];
    let read = image
        .read(address, &mut buffer)
        .map_err(|error| SsaError(format!("{address:#x}: {error}")))?;
    let instruction = binbun_aarch64::decode_bytes(buffer.get(..read).unwrap_or_default())
        .map_err(|error| SsaError(format!("{address:#x}: {error}")))?;
    let semantics = match binbun_aarch64_lift::lift(&instruction, address) {
        Ok(semantics) => Ok((semantics, Kind::Semantics)),
        Err(A64LiftError::Unsupported) if instruction.flow(address) == Flow::Next => {
            binbun_aarch64_lift::lift_opaque(&instruction, address)
                .map(|semantics| (semantics, Kind::Opaque))
        }
        Err(error) => Err(error),
    }
    .map_err(|error| {
        let problem = match error {
            A64LiftError::Unsupported => "a control transfer without semantics".to_owned(),
            A64LiftError::Problem(problem) => problem,
        };
        SsaError(format!(
            "{address:#x} `{}`: {problem}",
            instruction.display(address)
        ))
    });
    Ok(Lifted {
        next: address.wrapping_add(4),
        semantics,
    })
}

/// The blocks of `function` of `program`.
///
/// # Errors
///
/// The function or one of its blocks is not in `program`.
fn blocks_of(program: &Program, function: FunctionId) -> Result<(u64, Vec<Block>), SsaError> {
    let function = program
        .functions
        .get(function)
        .ok_or_else(|| SsaError("no such function".to_owned()))?;
    let blocks = function
        .blocks
        .iter()
        .map(|&id| {
            program
                .blocks
                .get(id)
                .copied()
                .ok_or_else(|| SsaError(format!("{:#x}: a block is missing", function.entry)))
        })
        .collect::<Result<_, _>>()?;
    Ok((function.entry, blocks))
}

/// The code of `function` of `program` (recovered from `image`): [`code`]
/// of its blocks.
///
/// # Errors
///
/// The function or a block is not in `program`, or as for [`code`].
pub fn function_code(
    image: &Image<'_>,
    program: &Program,
    function: FunctionId,
) -> Result<Code, SsaError> {
    let (entry, blocks) = blocks_of(program, function)?;
    code(image, entry, &blocks)
}

/// The code of the function at `entry` made of `blocks` (of `image`): each
/// block's instructions decoded and lifted ([`lift_instruction`]). Blocks
/// without instructions (an undecodable start) are left out: control
/// reaching them leaves the function.
///
/// # Errors
///
/// The image's code is not lifted, an instruction cannot be lifted, or a
/// block's instructions do not end where the block does.
pub fn code(image: &Image<'_>, entry: u64, blocks: &[Block]) -> Result<Code, SsaError> {
    Isa::of(image)?;
    code_with(entry, blocks, &mut |address| {
        lift_instruction(image, address)
    })
}

/// [`code`], each instruction lifted by `lift` (from its address).
///
/// # Errors
///
/// `lift` fails, or a block's instructions do not end where it does.
pub fn code_with(
    entry: u64,
    blocks: &[Block],
    lift: &mut dyn FnMut(u64) -> Result<Instruction, SsaError>,
) -> Result<Code, SsaError> {
    let mut code_blocks = Vec::with_capacity(blocks.len());
    for block in blocks {
        if block.instructions == 0 {
            continue;
        }
        let mut instructions = Vec::with_capacity(block.instructions as usize);
        let mut address = block.start;
        for _ in 0..block.instructions {
            let instruction = lift(address)?;
            address = instruction.next;
            instructions.push(instruction);
        }
        if address != block.end {
            return Err(SsaError(format!(
                "block {:#x}..{:#x}: its instructions end at {address:#x}",
                block.start, block.end
            )));
        }
        code_blocks.push(instructions);
    }
    Ok(Code {
        entry,
        blocks: code_blocks,
    })
}

/// What calls and system calls do in an image, by its calling convention
/// (x86-64: System V for ELF, Microsoft x64 for PE; AArch64: AAPCS64) or by
/// the callee's [`Summary`](binbun_ssa::summary::Summary) where there is
/// one; whether each call returns, as recovery found; and where computed
/// jumps go, as recovery resolved; which code jumps out of the function go
/// to never returns, as recovery found; which computed jumps leave for an
/// import through its slot (a tail call to the import); and where an
/// exception unwinding through a call goes (the landing pads of the
/// exception tables, ELF).
#[derive(Clone, Debug)]
pub struct ImageEnvironment {
    /// The calls that do not return (each block ending in one: start, end).
    no_return: Vec<(u64, u64)>,
    /// The functions that jumps out of the function go to and that never
    /// return, by entry.
    no_return_jumps: Vec<u64>,
    /// The jumps through an import's slot (each block ending in one:
    /// start, end), and whether the imports they go to may return.
    import_jumps: (Vec<(u64, u64)>, bool),
    /// The computed jumps recovery found no table for (each block ending
    /// in one: start, end), which leave the function (a
    /// [`Terminator::Leave`](binbun_ssa::ir::Terminator::Leave) to the
    /// address, which may return as the import jumps may) rather than go
    /// to code not known
    /// ([`with_unresolved_leaves`](Self::with_unresolved_leaves)); and
    /// those recovery resolved to code outside the function, where
    /// [`with_slot_leaves`](Self::with_slot_leaves).
    unresolved_leaves: Vec<(u64, u64)>,
    /// The resolved computed jumps (each block ending in one: start, end)
    /// and their targets.
    tables: Vec<(u64, u64, Vec<u64>)>,
    /// The callees' effects, by entry.
    summaries: BTreeMap<u64, CallEffect>,
    /// The landing pad of each call through which an exception unwinds to
    /// one, by the call's return address.
    landing_pads: BTreeMap<u64, u64>,
    /// The funclets built into the function (Microsoft x64), which say
    /// where exceptions unwind instead of `landing_pads`.
    funclets: Option<Funclets>,
    convention: Abi,
}

impl ImageEnvironment {
    /// The environment of a function of `image` made of `blocks` (which
    /// tell whether each call returns).
    ///
    /// # Errors
    ///
    /// The image's code is not lifted.
    pub fn new(image: &Image<'_>, blocks: &[Block]) -> Result<Self, SsaError> {
        let convention = Abi::of(image)?;
        let no_return = blocks
            .iter()
            .filter(|block| {
                matches!(
                    block.exit,
                    Exit::Call {
                        returns: Returns::No,
                        ..
                    }
                )
            })
            .map(|block| (block.start, block.end))
            .collect();
        Ok(Self {
            no_return,
            no_return_jumps: Vec::new(),
            import_jumps: (Vec::new(), true),
            unresolved_leaves: Vec::new(),
            tables: Vec::new(),
            summaries: BTreeMap::new(),
            landing_pads: BTreeMap::new(),
            funclets: None,
            convention,
        })
    }

    /// With `funclets` built into the function: they say where exceptions
    /// unwind through its calls, where its funclets return to, and its
    /// catch blocks' continuations.
    #[must_use]
    pub fn with_funclets(mut self, funclets: Option<Funclets>) -> Self {
        self.funclets = funclets;
        self
    }

    /// With every computed jump among `blocks` that `program` has no table
    /// for (not even an inferred one) leaving the function to its address
    /// (with the state there), as a tail call would: decompilation then
    /// keeps it a tail call where the ABI's conditions for one hold, and
    /// an unresolved jump elsewhere
    /// ([`TailJumps`](binbun_ssa::stack::TailJumps)).
    #[must_use]
    pub fn with_unresolved_leaves(mut self, program: &Program, blocks: &[Block]) -> Self {
        self.unresolved_leaves = blocks
            .iter()
            .filter(|block| {
                matches!(
                    block.exit,
                    Exit::Jump(Destination::Pointer(_) | Destination::Indirect)
                ) && program
                    .block_at(block.start)
                    .is_none_or(|id| program.table(id).is_none())
            })
            .map(|block| (block.start, block.end))
            .collect();
        self
    }

    /// With every computed jump among `blocks` that recovery resolved to
    /// code none of `blocks` starts (`jmp [rip+GOT]` through a slot
    /// holding a fixed code pointer: a tail call of that code, as a PLT
    /// stub of a function the image defines is) leaving the function to
    /// its address as well.
    #[must_use]
    pub fn with_slot_leaves(mut self, blocks: &[Block]) -> Self {
        self.unresolved_leaves.extend(
            blocks
                .iter()
                .filter(|block| {
                    matches!(block.exit, Exit::Jump(Destination::Address(target))
                        if !blocks.iter().any(|other| other.start == target))
                })
                .map(|block| (block.start, block.end)),
        );
        self
    }

    /// With the landing pads of the calls among `blocks`, as `program`
    /// knows them from the exception tables ([`Program::landing_pad`]).
    #[must_use]
    pub fn with_landing_pads(mut self, program: &Program, blocks: &[Block]) -> Self {
        self.landing_pads = blocks
            .iter()
            .filter(|block| matches!(block.exit, Exit::Call { .. }))
            .filter_map(|block| Some((block.end, program.landing_pad(block.end)?)))
            .collect();
        self
    }

    /// With the computed jumps of `program` among `blocks` as recovery
    /// resolved them, where the targets are proven (an inferred table's end
    /// may cut off cases, which L1 would then take as impossible).
    #[must_use]
    pub fn with_tables(mut self, program: &Program, blocks: &[Block]) -> Self {
        self.tables = blocks
            .iter()
            .filter_map(|block| {
                let id = program.block_at(block.start)?;
                let table = program.table(id).filter(|table| !table.inferred)?;
                Some((block.start, block.end, table.targets.clone()))
            })
            .collect();
        self
    }

    /// With the jumps among `blocks` (and their falling off into the next
    /// function) that go to a function of `program` recovery found never to
    /// return: those tail calls do not return either.
    #[must_use]
    pub fn with_jumps(mut self, program: &Program, blocks: &[Block]) -> Self {
        let mut targets: Vec<u64> = blocks
            .iter()
            .filter_map(|block| program.block_at(block.start))
            .flat_map(|id| program.successors(id))
            .map(|(_, target)| target)
            .filter(|&target| {
                program
                    .function_at(target)
                    .and_then(|id| program.functions.get(id))
                    .is_some_and(|function| !function.returns)
            })
            .collect();
        targets.sort_unstable();
        targets.dedup();
        self.no_return_jumps = targets;
        self
    }

    /// With the jumps among `blocks` through an import's slot (`jmp
    /// [__imp_X]`, a PLT stub's `jmp [GOT]`): each leaves the function for
    /// the import, a tail call. They may return unless the function they
    /// end never does (`returns`): recovery took every way out of it, these
    /// among them, never to return.
    #[must_use]
    pub fn with_import_jumps(mut self, blocks: &[Block], returns: bool) -> Self {
        let jumps = blocks
            .iter()
            .filter(|block| matches!(block.exit, Exit::Jump(Destination::Import(_))))
            .map(|block| (block.start, block.end))
            .collect();
        self.import_jumps = (jumps, returns);
        self
    }

    /// With the direct calls among `blocks` to the functions of
    /// `summaries` taking the effect each summary states, the calling
    /// convention's where it cannot tell (only the callees `blocks` call
    /// directly: a call's target is constant only where recovery found it).
    #[must_use]
    pub fn with_summaries(mut self, summaries: &Summaries, blocks: &[Block]) -> Self {
        let (stack_pointer, call) = (self.convention.stack_pointer, &self.convention.call);
        self.summaries = blocks
            .iter()
            .filter_map(|block| match block.exit {
                Exit::Call {
                    callee: Destination::Address(target),
                    ..
                } => Some(target),
                Exit::Call { .. }
                | Exit::Next
                | Exit::Jump(_)
                | Exit::Branch(_)
                | Exit::Return
                | Exit::Stop
                | Exit::Invalid
                | Exit::Limit => None,
            })
            .filter_map(|target| {
                let summary = summaries.get(&target)?;
                Some((target, summary.effect(stack_pointer, call)))
            })
            .collect();
        self
    }

    /// The registers calls take arguments in, by the calling convention.
    pub fn arguments(&self) -> Vec<RegisterId> {
        self.convention.arguments.clone()
    }

    /// The architecture's registers and intrinsics.
    pub fn declarations(&self) -> &'static Declarations {
        self.convention.declarations
    }

    /// The architecture's stack pointer.
    pub fn stack_pointer(&self) -> RegisterId {
        self.convention.stack_pointer
    }
}

impl Environment for ImageEnvironment {
    /// The callee's summary, else the calling convention's effect; it
    /// returns unless recovery found that the call at `site` (ending its
    /// block) does not.
    fn call(&self, site: u64, target: Option<u64>) -> CallEffect {
        let returns = !self
            .no_return
            .iter()
            .any(|&(start, end)| (start..end).contains(&site));
        let effect = target
            .and_then(|target| self.summaries.get(&target))
            .unwrap_or(&self.convention.call);
        CallEffect {
            returns,
            ..effect.clone()
        }
    }

    fn system_call(&self, _site: u64) -> CallEffect {
        self.convention.system_call.clone()
    }

    /// The targets recovery resolved for the computed jump at `site`.
    fn jump_targets(&self, site: u64) -> Vec<u64> {
        self.tables
            .iter()
            .find(|(start, end, _)| (*start..*end).contains(&site))
            .map(|(_, _, targets)| targets.clone())
            .unwrap_or_default()
    }

    /// Whether recovery found that the function at `target` returns (code
    /// at no function's entry: it may).
    fn jump_returns(&self, target: u64) -> bool {
        self.no_return_jumps.binary_search(&target).is_err()
    }

    /// A jump through an import's slot leaves for the import
    /// ([`ImageEnvironment::with_import_jumps`]); so does one no table
    /// resolves, to its address, where
    /// [`with_unresolved_leaves`](ImageEnvironment::with_unresolved_leaves).
    fn jump_leaves(&self, site: u64) -> Option<bool> {
        let (jumps, returns) = &self.import_jumps;
        if jumps
            .iter()
            .any(|&(start, end)| (start..end).contains(&site))
        {
            return Some(*returns);
        }
        self.unresolved_leaves
            .iter()
            .any(|&(start, end)| (start..end).contains(&site))
            .then_some(*returns)
    }

    /// The landing pad of the call returning to `return_address`, with
    /// what the convention's unwinder hands it.
    fn unwind(&self, return_address: u64) -> Option<Unwind> {
        if let Some(funclets) = &self.funclets {
            return funclets.unwind(return_address);
        }
        let &pad = self.landing_pads.get(&return_address)?;
        self.convention.unwind(pad)
    }

    /// The continuations of the catch blocks built in.
    fn labels(&self) -> Vec<u64> {
        self.funclets
            .as_ref()
            .map(|funclets| funclets.continuations().to_vec())
            .unwrap_or_default()
    }

    /// What the return of a funclet built in does.
    fn funclet_return(&self, site: u64) -> Option<(u64, FuncletReturn)> {
        self.funclets.as_ref()?.funclet_return(site)
    }

    /// The funclets built in, and the registers the convention has them
    /// keep.
    fn funclets(&self) -> Vec<(u64, Vec<RegisterId>)> {
        self.funclets
            .as_ref()
            .map(Funclets::entries)
            .unwrap_or_default()
    }
}

/// `function` of `program` (recovered from `image`) in SSA form: its calls
/// as `summaries` or else the image's calling convention say, its computed
/// jumps as recovery resolved them ([`ImageEnvironment`]).
///
/// # Errors
///
/// As for [`function_code`], or construction fails.
pub fn lift_function(
    image: &Image<'_>,
    program: &Program,
    function: FunctionId,
    summaries: &Summaries,
) -> Result<Function, SsaError> {
    lift_with(image, program, function, summaries, false)
}

/// [`lift_function`], but every computed jump recovery did not resolve,
/// or resolved to code outside the function (a jump through a slot
/// holding a fixed code pointer), leaves the function to its address
/// ([`ImageEnvironment::with_unresolved_leaves`],
/// [`ImageEnvironment::with_slot_leaves`]): decompilation's and the
/// signatures' L1, whose pass [`TailJumps`](binbun_ssa::stack::TailJumps)
/// keeps those leaves only where the ABI's conditions for a tail call
/// hold.
///
/// # Errors
///
/// As for [`lift_function`].
pub fn lift_function_leaving(
    image: &Image<'_>,
    program: &Program,
    function: FunctionId,
    summaries: &Summaries,
) -> Result<Function, SsaError> {
    lift_with(image, program, function, summaries, true)
}

/// [`lift_function`]; where `leaving`, the computed jumps recovery did
/// not resolve, or resolved to code outside the function, leave it.
fn lift_with(
    image: &Image<'_>,
    program: &Program,
    function: FunctionId,
    summaries: &Summaries,
    leaving: bool,
) -> Result<Function, SsaError> {
    let (entry, mut blocks) = blocks_of(program, function)?;
    let returns = program.functions.get(function).is_none_or(|f| f.returns);
    let funclets = Funclets::of(image, program, function);
    if let Some(funclets) = &funclets {
        blocks.extend_from_slice(funclets.blocks());
    }
    let code = code(image, entry, &blocks)?;
    let mut environment = ImageEnvironment::new(image, &blocks)?
        .with_tables(program, &blocks)
        .with_jumps(program, &blocks)
        .with_import_jumps(&blocks, returns)
        .with_landing_pads(program, &blocks)
        .with_summaries(summaries, &blocks)
        .with_funclets(funclets);
    if leaving {
        environment = environment
            .with_unresolved_leaves(program, &blocks)
            .with_slot_leaves(&blocks);
    }
    build(&code, environment.declarations(), &environment)
        .map_err(|error| SsaError(format!("{:#x}: {error}", code.entry)))
}
