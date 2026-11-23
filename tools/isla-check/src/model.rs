//! sail-arm's model (the `armv9p4.ir` Jib snapshot) in isla, under
//! binbun's execution context ([`CONFIG`]) with the memory boundary
//! replaced ([`OVERRIDES`]), run symbolically on one opcode at a time.

use std::collections::HashMap;
use std::sync::Arc;

use crossbeam::queue::SegQueue;
use isla_lib::bitvector::BV;
use isla_lib::bitvector::b129::B129;
use isla_lib::config::ISAConfig;
use isla_lib::executor::{self, LocalFrame, TaskId, TaskState, TraceQueue};
use isla_lib::init::{Initialized, initialize_architecture};
use isla_lib::ir::{AssertionMode, Def, Exp, IRTypeInfo, Instr, Loc, Name, Reset, Symtab, Val};
use isla_lib::ir_lexer::new_ir_lexer;
use isla_lib::ir_parser::IrParser;
use isla_lib::memory::Memory;
use isla_lib::smt::{Checkpoint, Event};
use isla_lib::zencode;

/// isla's configuration: the execution context (EL0, AArch64,
/// little-endian; `SCTLR_EL1.SA0` = 1, `TCR_EL1.TBI0` = `TBI1` = `TBID1` = 1
/// as Linux sets them; BTI and LSE2 implemented, GCS, MTE, SPE and BRBE
/// not).
pub const CONFIG: &str = include_str!("../armv9p4-el0.toml");

/// Jib replacements for the memory boundary: `Mem_read__2` and
/// `Mem_set__2` (every data access of sail-arm funnels through them) read
/// and write isla's memory at the virtual address directly. Translation,
/// tag checks, watchpoints, the emulator's devices and the alignment
/// faults of Device memory go; what is left is flat Normal memory, which is
/// what a user process sees, indexed by the virtual address as computed
/// (top-byte-ignore is the memory system's, as in binbun's L0). The
/// alignment faults of Normal memory (exclusives, atomics,
/// acquire/release: `AArch64.UnalignedAccessFaults`) are kept. `MemAtomic`
/// (the LSE atomics), `AArch64.SetExclusiveMonitors` and
/// `AArch64.ExclusiveMonitorsPass`, which translate the address
/// themselves, get the same treatment; the last gives the monitors'
/// verdict as binbun's `exclusive_store`.
///
/// They also fix binbun's choices for CONSTRAINED UNPREDICTABLE behaviour,
/// which sail-arm leaves open (`ConstrainUnpredictable` returns an unknown
/// constraint, so isla explores every permitted behaviour as a path, and
/// L0 would have to match them all); the file states each: a store with
/// writeback whose base is its data register (`str x1, [x1], #8`,
/// `WBOVERLAPST`) stores the register's original value (`Constraint_NONE`),
/// as binbun's L0 does. The other cases stay open: a word that reaches one
/// is reported until a choice is made here. Lines starting with `//` are
/// comments (Jib has none).
///
/// And `isla_footprint_common`, isla's harness around `__DecodeA64`, which
/// catches every exception the decode or execute code throws and returns:
/// an UNDEFINED one (`Error_Undefined`, an encoding whose feature is not
/// implemented) is now taken as the processor takes it
/// (`AArch64_UndefinedFault`, `ESR_EL1` with EC 0), so the path is an
/// exception path, not a completion without effects.
/// A `SEE` one (the generic HINT clause, tried first, sends PACIASP and
/// the other pointer authentication hints to their own encodings) decodes
/// again, as sail-arm's `__DecodeExecute` does: `SEE` keeps the clause
/// that sent it, so the retry reaches the encoding it names.
pub const OVERRIDES: &str = include_str!("../overrides.jib");

/// `text` with its `//` comment lines blanked (line numbers kept).
fn uncommented(text: &str) -> String {
    text.lines()
        .map(|line| {
            if line.trim_start().starts_with("//") {
                ""
            } else {
                line
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The events of one execution path, in order.
pub type Path = Vec<Event<B129>>;

/// The paths of one opcode, and the errors of paths isla could not finish.
#[derive(Debug, Default)]
pub struct Run {
    /// Finished paths.
    pub paths: Vec<Path>,
    /// Why other paths did not finish.
    pub errors: Vec<String>,
}

/// The model, ready to run opcodes.
pub struct Model<'ir> {
    iarch: Initialized<'ir, B129>,
    pc: Name,
    threads: usize,
    timeout: Option<u64>,
}

fn parse<'input>(
    text: &'input str,
    symtab: &mut Symtab<'input>,
    what: &str,
) -> Result<Vec<Def<Name, B129>>, String> {
    IrParser::new()
        .parse(symtab, new_ir_lexer(text))
        .map_err(|error| format!("{what}: {error}"))
}

/// Replaces the functions of `arch` that `overrides` defines, and adds the
/// abstract functions it declares (uninterpreted: each call is an event
/// with a fresh result, which the checker ties to binbun's intrinsic of
/// the same name, `binbun_<intrinsic>`).
fn replace(arch: &mut Vec<Def<Name, B129>>, overrides: Vec<Def<Name, B129>>) -> Result<(), String> {
    for replacement in overrides {
        if let Def::Extern(name, true, ..) = &replacement {
            if arch
                .iter()
                .any(|def| matches!(def, Def::Extern(other, ..) if other == name))
            {
                return Err("an abstract override is declared twice".into());
            }
            arch.push(replacement);
            continue;
        }
        let Def::Fn(name, ..) = &replacement else {
            return Err("overrides may only define functions and abstract functions".into());
        };
        let slot = arch
            .iter_mut()
            .find(|def| matches!(def, Def::Fn(other, ..) if other == name))
            .ok_or("an override replaces no function")?;
        *slot = replacement;
    }
    Ok(())
}

/// Makes the integers sail-arm's decode functions leave UNKNOWN 0, as
/// Sail's own emulators do. ASL leaves a register number the encoding does
/// not use unassigned (PACIASP's `n`: its modifier is SP), Sail asserts
/// that it is a register number anyway (0 to 31), and isla, which makes
/// UNKNOWN values symbolic, finds paths where the assertion fails. The
/// value is never used, so any one in range is Arm's behaviour.
fn known_unknowns(arch: &mut [Def<Name, B129>], symtab: &Symtab<'_>) -> Result<(), String> {
    let name = |text: &str| {
        symtab
            .get(&zencode::encode(text))
            .ok_or_else(|| format!("the snapshot has no {text}"))
    };
    let undefined_int = name("undefined_int")?;
    // Sail's conversion of a 64-bit integer to an unbounded one.
    let from_i64 = symtab
        .get("zz5i64zDzKz5i")
        .ok_or("the snapshot has no 64-bit integer conversion")?;
    for def in arch {
        let Def::Fn(function, _, body) = def else {
            continue;
        };
        if !symtab.to_str(*function).starts_with("zdecode_") {
            continue;
        }
        for instruction in body {
            if let Instr::Call(loc, false, callee, _, info) = instruction
                && *callee == undefined_int
            {
                *instruction = Instr::Call(loc.clone(), false, from_i64, vec![Exp::I64(0)], *info);
            }
        }
    }
    Ok(())
}

/// Loads the Jib snapshot `ir` (the text of `armv9p4.ir`), applies the
/// overrides and the configuration, and runs `body` with the model.
/// `threads` workers explore paths, each opcode for at most `timeout`
/// seconds.
///
/// # Errors
///
/// If the snapshot, the overrides or the configuration do not parse, or
/// the snapshot lacks what they name.
pub fn with_model<R>(
    ir: &str,
    threads: usize,
    timeout: Option<u64>,
    body: impl FnOnce(&Model<'_>) -> R,
) -> Result<R, String> {
    let text = uncommented(OVERRIDES);
    let mut symtab = Symtab::new();
    let mut arch = parse(ir, &mut symtab, "armv9p4.ir")?;
    let overrides = parse(&text, &mut symtab, "overrides")?;
    replace(&mut arch, overrides)?;
    known_unknowns(&mut arch, &symtab)?;
    let type_info = IRTypeInfo::new(&arch);
    let config = ISAConfig::parse(CONFIG, None, &symtab, &type_info)?;
    let pc = symtab
        .get(&zencode::encode("_PC"))
        .ok_or("the snapshot has no _PC")?;
    let iarch = initialize_architecture(
        &mut arch,
        symtab,
        type_info,
        &config,
        AssertionMode::Optimistic,
        true,
    );
    let model = Model {
        iarch,
        pc,
        threads: threads.max(1),
        timeout,
    };
    Ok(body(&model))
}

impl Model<'_> {
    /// The name of identifier `name` (as Sail writes it, `R0`, `PSTATE`).
    pub fn name(&self, name: &str) -> Option<Name> {
        self.iarch.shared_state.symtab.get(&zencode::encode(name))
    }

    /// The Sail identifier `name` stands for.
    pub fn identifier(&self, name: Name) -> String {
        zencode::decode(self.iarch.shared_state.symtab.to_str(name))
    }

    /// Runs `word` (an A64 instruction) at address `pc` from the reset
    /// state, every register isla does not fix symbolic.
    pub fn run(&self, word: u32, pc: u64) -> Run {
        let shared_state = &self.iarch.shared_state;
        let Some(function) = shared_state.symtab.get(&zencode::encode("isla_footprint")) else {
            return Run {
                errors: vec!["the snapshot has no isla_footprint".into()],
                ..Run::default()
            };
        };
        let Some((arguments, result, body)) = shared_state.functions.get(&function) else {
            return Run {
                errors: vec!["isla_footprint has no body".into()],
                ..Run::default()
            };
        };
        let mut resets: HashMap<Loc<Name>, Reset<B129>> = HashMap::new();
        let at: Reset<B129> = Arc::new(move |_, _, _| Ok(Val::Bits(B129::from_u64(pc))));
        resets.insert(Loc::Id(self.pc), at);
        let task_state = TaskState::new().with_reset_registers(resets);
        let opcode = [Val::Bits(B129::from_u32(word))];
        let task = LocalFrame::new(function, arguments, result, Some(&opcode), body)
            .add_lets(&self.iarch.lets)
            .add_regs(&self.iarch.regs)
            .set_memory(Memory::new())
            .task_with_checkpoint(TaskId::fresh(), &task_state, Checkpoint::new());
        let queue: Arc<TraceQueue<B129>> = Arc::new(SegQueue::new());
        executor::start_multi(
            self.threads,
            self.timeout,
            vec![task],
            shared_state,
            Arc::clone(&queue),
            &executor::trace_collector,
        );
        let mut run = Run::default();
        while let Some(result) = queue.pop() {
            match result {
                Ok((_, mut events)) => {
                    events.reverse();
                    run.paths.push(events);
                }
                Err(error) => run.errors.push(format!("{error}")),
            }
        }
        run
    }
}
