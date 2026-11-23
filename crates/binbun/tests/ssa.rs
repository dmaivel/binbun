//! Recovered functions in SSA form: every function of the x86-64 fixtures
//! (and of the system's libc, where there is one) builds and verifies, and
//! leaf functions run as L1 end as their instructions, run one by one as
//! L0, do. The image's read-only memory gives only bytes that cannot change
//! at run time.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers fail loudly"
)]

use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use binbun::analysis::{Seeds, analyse, type_library};
use binbun::cfg::Program;
use binbun::lift::{function_code, lift_function, lift_instruction};
use binbun::memory::ImageMemory;
use binbun::summary::{Summaries, summaries};
use binbun_loader::Image;
use binbun_semantics::Bits;
use binbun_semantics::core::Memory as _;
use binbun_semantics::interpret::{self as l0, Fault, Machine, Value};
use binbun_semantics::ir::{IntrinsicId, RegisterId, Stmt, Trap};
use binbun_ssa::constant::{ReadOnly, propagate};
use binbun_ssa::interpret as l1;
use binbun_ssa::stack::Stack;
use binbun_ssa::summary::{Kept, Summary, summarize};
use binbun_ssa::verify::verify;
use binbun_ssa::{Function, Instruction, Op, Terminator};

use binbun_x86_lift::X86;
use binbun_x86_lift::registers::{RIP, RSP};

const FIXTURES: [&str; 3] = [
    "program-x86_64.elf",
    "exceptions-x86_64.elf",
    "program-x86_64.exe",
];

const LIBC: &str = "/usr/lib/libc.so.6";

fn fixture(name: &str) -> String {
    format!("{}/../../tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"))
}

fn read(path: &str) -> Vec<u8> {
    fs::read(path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

/// Builds and verifies every function of the image in `data`: how many
/// passed; failures go to `failures`.
fn check_functions(path: &str, data: &[u8], failures: &mut Vec<String>) -> usize {
    let image = Image::parse(data).unwrap();
    let program = analyse(&image, Seeds::ALL, &type_library(&image).unwrap()).unwrap();
    let summaries = summaries(&image, &program);
    let mut passed = 0;
    for (id, function) in &program.functions {
        let entry = function.entry;
        match lift_function(&image, &program, id, &summaries) {
            Ok(built) => match verify(&built, &X86) {
                Ok(()) => passed += 1,
                Err(error) => failures.push(format!("{path} {entry:#x}: does not verify: {error}")),
            },
            Err(error) => failures.push(format!("{path} {entry:#x}: does not build: {error}")),
        }
    }
    passed
}

fn assert_none(failures: &[String]) {
    assert!(
        failures.is_empty(),
        "{} failures:\n{}",
        failures.len(),
        failures
            .iter()
            .take(30)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn every_fixture_function_builds_and_verifies() {
    let mut failures = Vec::new();
    let mut passed = 0;
    for name in FIXTURES {
        let path = fixture(name);
        passed += check_functions(&path, &read(&path), &mut failures);
    }
    assert_none(&failures);
    assert!(passed >= 40, "only {passed} functions checked");
}

#[test]
fn every_libc_function_builds_and_verifies() {
    if !Path::new(LIBC).exists() {
        return;
    }
    let mut failures = Vec::new();
    let passed = check_functions(LIBC, &read(LIBC), &mut failures);
    assert_none(&failures);
    assert!(passed >= 1000, "only {passed} functions checked");
}

/// A deterministic xorshift generator.
struct Rng(u64);

impl Rng {
    fn draw(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
}

/// A byte of memory nothing wrote: a hash of its address.
fn initial(address: u64) -> u8 {
    let mut x = (address ^ 0x9e37_79b9_7f4a_7c15).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x ^= x >> 31;
    x.to_le_bytes()[0]
}

/// Where functions return to: an address no function has, and canonical,
/// so that a return completes instead of trapping.
const RETURN: u64 = 0x7fff_0000_1000;

/// Registers, and memory where every byte below 0x1000 faults, the 8 bytes
/// at the entry stack pointer hold [`RETURN`], every other unwritten byte
/// is [`initial`], and writes are kept (with their undefined bits).
struct TestMachine {
    registers: Vec<Value>,
    /// The stack pointer at entry (the return address's slot).
    entry_sp: u64,
    /// Bytes written: value and undefined bits.
    written: BTreeMap<u64, (u8, u8)>,
    unlifted_id: IntrinsicId,
    /// Whether an instruction without semantics ran.
    unlifted: bool,
}

impl TestMachine {
    fn new(registers: Vec<Value>) -> Self {
        let entry_sp = registers[RSP.0 as usize].bits.low_u64();
        Self {
            registers,
            entry_sp,
            written: BTreeMap::new(),
            unlifted_id: X86.find_intrinsic("unlifted").unwrap(),
            unlifted: false,
        }
    }

    fn byte(&self, address: u64) -> (u8, u8) {
        if let Some(&written) = self.written.get(&address) {
            return written;
        }
        match address.checked_sub(self.entry_sp) {
            Some(offset @ 0..8) => (RETURN.to_le_bytes()[usize::try_from(offset).unwrap()], 0),
            Some(_) | None => (initial(address), 0),
        }
    }

    fn check(address: u64, bytes: u16, write: bool) -> Result<(), Fault> {
        if address < 0x1000 || address.checked_add(u64::from(bytes)).is_none() {
            Err(Fault { address, write })
        } else {
            Ok(())
        }
    }
}

impl Machine for TestMachine {
    fn read(&mut self, register: RegisterId) -> Value {
        self.registers[usize::from(register.0)]
    }

    fn write(&mut self, register: RegisterId, value: Value) {
        self.registers[usize::from(register.0)] = value;
    }

    fn load(&mut self, address: u64, bytes: u16) -> Result<Value, Fault> {
        Self::check(address, bytes, false)?;
        let (values, undefined): (Vec<u8>, Vec<u8>) = (0..u64::from(bytes))
            .map(|i| self.byte(address + i))
            .unzip();
        let width = bytes * 8;
        Ok(Value {
            bits: Bits::from_le_bytes(width, &values),
            undefined: Bits::from_le_bytes(width, &undefined),
        })
    }

    fn store(&mut self, address: u64, value: Value) -> Result<(), Fault> {
        let bytes = value.width() / 8;
        Self::check(address, bytes, true)?;
        let pairs = value.bits.to_le_bytes().zip(value.undefined.to_le_bytes());
        for (i, (bits, undefined)) in pairs.take(usize::from(bytes)).enumerate() {
            self.written
                .insert(address + i as u64, (bits & !undefined, undefined));
        }
        Ok(())
    }

    fn intrinsic(
        &mut self,
        intrinsic: IntrinsicId,
        _inputs: &[Value],
        outputs: &[u16],
    ) -> Vec<Value> {
        if intrinsic == self.unlifted_id {
            self.unlifted = true;
        }
        outputs.iter().map(|&width| Value::unknown(width)).collect()
    }
}

/// Every register at the entry of the function at `entry`: values small,
/// pointer-like or anything, flags random but the direction flag clear, the
/// stack pointer in a stack-like place, the instruction pointer `entry`.
fn random_registers(rng: &mut Rng, entry: u64) -> Vec<Value> {
    X86.registers
        .iter()
        .enumerate()
        .map(|(index, info)| {
            let id = RegisterId(u16::try_from(index).unwrap());
            let value = if id == RSP {
                0x7ffe_0000_0000 + (rng.draw() % 0x10_0000) * 16 + 8
            } else if id == RIP {
                entry
            } else if info.name == "df" {
                0
            } else if info.width == 1 {
                rng.draw() & 1
            } else {
                match rng.draw() % 4 {
                    0 => rng.draw() % 16,
                    1 => rng.draw() % 0x1_0000,
                    2 => 0x5555_0000_0000 + (rng.draw() % 0x1_0000_0000) * 8,
                    _ => rng.draw(),
                }
            };
            Value::defined(Bits::from_u64(info.width, value))
        })
        .collect()
}

/// Whether `statements` return from a call.
fn returns(statements: &[Stmt]) -> bool {
    statements.iter().any(|statement| match statement {
        Stmt::Return { .. } => true,
        Stmt::If {
            then, otherwise, ..
        } => returns(then) || returns(otherwise),
        Stmt::Loop(body) | Stmt::Atomic(body) => returns(body),
        Stmt::Read { .. }
        | Stmt::Write { .. }
        | Stmt::Load { .. }
        | Stmt::Store { .. }
        | Stmt::Break
        | Stmt::Trap(_)
        | Stmt::Jump { .. }
        | Stmt::Call { .. }
        | Stmt::SystemCall
        | Stmt::Intrinsic { .. } => false,
    })
}

/// Whether the function makes no calls or system calls and has no computed
/// jumps: L1 can run all of it.
fn is_leaf(function: &Function) -> bool {
    function
        .insts
        .iter()
        .all(|inst| !matches!(inst.op, Op::Call { .. } | Op::SystemCall { .. }))
        && function
            .blocks
            .iter()
            .all(|block| !matches!(block.terminator, Terminator::IndirectJump { .. }))
}

/// How a run ended, comparably.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum End {
    Exit {
        returned: bool,
        address: u64,
    },
    Trap(Trap),
    Fault(Fault),
    /// Not comparable (undefined bits decided something, or too long).
    Skip,
}

/// Instructions run before giving up.
const STEPS: u64 = 20_000;

/// Runs the function's instructions one at a time (each decoded and lifted
/// at the program counter) from `entry` until control leaves its
/// instructions (`code`) or a return runs.
fn run_instructions(
    image: &Image<'_>,
    code: &BTreeSet<u64>,
    entry: u64,
    machine: &mut TestMachine,
    lifted: &mut BTreeMap<u64, Instruction>,
) -> Result<End, String> {
    let mut pc = entry;
    for _ in 0..STEPS {
        let instruction = match lifted.entry(pc) {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => entry.insert(lift_instruction(image, pc).map_err(|e| e.0)?),
        };
        let (next, returned) = match l0::run(&instruction.semantics, machine) {
            l0::Outcome::Next => (instruction.next, false),
            l0::Outcome::Transfer(target) => (target, returns(&instruction.semantics.body)),
            l0::Outcome::Trap(trap) => return Ok(End::Trap(trap)),
            l0::Outcome::Fault(fault) => return Ok(End::Fault(fault)),
            l0::Outcome::Undetermined | l0::Outcome::OutOfFuel | l0::Outcome::SystemCall => {
                return Ok(End::Skip);
            }
            l0::Outcome::Malformed => return Err(format!("{pc:#x}: malformed semantics")),
        };
        if returned || !code.contains(&next) {
            return Ok(End::Exit {
                returned,
                address: next,
            });
        }
        pc = next;
    }
    Ok(End::Skip)
}

/// Whether two values agree on the bits both define.
fn agree(a: &Value, b: &Value) -> bool {
    a.width() == b.width() && {
        let defined = a.undefined.or(&b.undefined).invert();
        a.bits.and(&defined) == b.bits.and(&defined)
    }
}

/// Counts of a differential run.
#[derive(Default)]
struct Tally {
    compared: usize,
    exits: usize,
    /// Returns where a summary's claims were checked.
    summarized: usize,
    mismatches: Vec<String>,
}

/// Compares, for one function and one register state, L1's run with the
/// instructions' run.
fn compare(
    image: &Image<'_>,
    function: &Function,
    summary: Option<&Summary>,
    code: &BTreeSet<u64>,
    registers: &[Value],
    lifted: &mut BTreeMap<u64, Instruction>,
    tally: &mut Tally,
) -> Result<(), String> {
    let entry = registers;
    let mut whole = TestMachine::new(registers.to_vec());
    let outcome = l1::run(function, &X86, registers, &mut whole, 4 * STEPS);
    let mut stepped = TestMachine::new(registers.to_vec());
    let end = run_instructions(image, code, function.entry, &mut stepped, lifted)?;
    if whole.unlifted || stepped.unlifted || end == End::Skip {
        return Ok(());
    }
    let mismatch = match &outcome {
        l1::Outcome::Undetermined | l1::Outcome::OutOfFuel => return Ok(()),
        l1::Outcome::Exit {
            returned,
            address,
            registers,
        } => match end {
            End::Exit {
                returned: r,
                address: a,
            } if r == *returned && a == *address => {
                tally.exits += 1;

                let summary = summary.filter(|_| *returned);
                tally.summarized += usize::from(summary.is_some());
                exit_mismatch(registers, &whole, &stepped).or_else(|| {
                    summary.and_then(|s| summary_mismatch(s, entry, &stepped.registers))
                })
            }
            End::Exit { .. } | End::Trap(_) | End::Fault(_) | End::Skip => Some(format!(
                "L1 exits (returned {returned}) to {address:#x}, the instructions end {end:?}"
            )),
        },
        l1::Outcome::Trap(trap) if end == End::Trap(*trap) => None,
        l1::Outcome::Fault(fault) if end == End::Fault(*fault) => None,
        l1::Outcome::Trap(_)
        | l1::Outcome::Fault(_)
        | l1::Outcome::Stop
        | l1::Outcome::Call(_)
        | l1::Outcome::Unresolved(_)
        | l1::Outcome::Malformed => Some(format!("L1 ends {outcome:?}, the instructions {end:?}")),
    };
    tally.compared += 1;
    if let Some(mismatch) = mismatch {
        return Err(mismatch);
    }
    Ok(())
}

/// A claim of `summary` that the instructions' run broke: a register it
/// says is preserved changed from `entry` to `exit`, or the stack pointer
/// moved otherwise.
fn summary_mismatch(summary: &Summary, entry: &[Value], exit: &[Value]) -> Option<String> {
    for (index, &kept) in summary.kept.iter().enumerate() {
        if kept == Kept::Yes && !agree(&entry[index], &exit[index]) {
            let name = X86.registers[index].name;
            return Some(format!("the summary keeps {name}, the run changes it"));
        }
    }
    let sp = RSP.0 as usize;
    let moved = exit[sp]
        .known()
        .zip(entry[sp].known())
        .map(|(after, before)| after.low_u64().wrapping_sub(before.low_u64()));
    match moved {
        Some(moved) if moved != summary.stack.cast_unsigned() => Some(format!(
            "the summary moves rsp by {}, the run by {}",
            summary.stack,
            moved.cast_signed()
        )),
        Some(_) | None => None,
    }
}

/// What differs between L1's final registers (and memory, `whole`) and the
/// instructions' (`stepped`).
fn exit_mismatch(
    registers: &[Value],
    whole: &TestMachine,
    stepped: &TestMachine,
) -> Option<String> {
    if registers.len() != stepped.registers.len() {
        return Some(format!("L1 exits with {} registers", registers.len()));
    }
    for (index, (a, b)) in registers.iter().zip(&stepped.registers).enumerate() {
        if !agree(a, b) {
            let name = X86.registers[index].name;
            return Some(format!("{name}: L1 {a:?}, the instructions {b:?}"));
        }
    }
    for &address in whole.written.keys().chain(stepped.written.keys()) {
        let ((a, a_undefined), (b, b_undefined)) = (whole.byte(address), stepped.byte(address));
        let defined = !(a_undefined | b_undefined);
        if a & defined != b & defined {
            return Some(format!(
                "memory at {address:#x}: L1 {a:#04x}, the instructions {b:#04x}"
            ));
        }
    }
    None
}

/// Runs every leaf function of the image in `data` from `states` random
/// register states, as L1 and instruction by instruction.
fn differential(path: &str, data: &[u8], states: usize, tally: &mut Tally) {
    let image = Image::parse(data).unwrap();
    let program: Program = analyse(&image, Seeds::ALL, &type_library(&image).unwrap()).unwrap();
    let memory = ImageMemory::new(&image);
    let mut rng = Rng(0x2545_f491_4f6c_dd1d);
    let mut lifted = BTreeMap::new();
    for (id, function) in &program.functions {
        let Ok(built) = lift_function(&image, &program, id, &Summaries::new()) else {
            continue;
        };
        if !is_leaf(&built) {
            continue;
        }
        let constants = propagate(&built, &memory);
        let stack = Stack::new(&built, &X86, &constants, RSP, &[]);
        let summary = summarize(&built, &X86, &constants, &stack, RSP);

        let code: BTreeSet<u64> = function_code(&image, &program, id)
            .unwrap()
            .blocks
            .iter()
            .flatten()
            .map(|instruction| instruction.address)
            .collect();
        for state in 0..states {
            let registers = random_registers(&mut rng, function.entry);
            let checked = compare(
                &image,
                &built,
                summary.as_ref(),
                &code,
                &registers,
                &mut lifted,
                tally,
            );
            if let Err(mismatch) = checked {
                tally.mismatches.push(format!(
                    "{path} {:#x} state {state}: {mismatch}",
                    function.entry
                ));
            }
        }
    }
}

#[test]
fn fixture_leaf_functions_run_as_their_instructions() {
    let mut tally = Tally::default();
    for name in FIXTURES {
        let path = fixture(name);
        differential(&path, &read(&path), 16, &mut tally);
    }
    assert_none(&tally.mismatches);
    assert!(
        tally.summarized >= 50,
        "only {} returns checked a summary",
        tally.summarized
    );
    assert!(
        tally.compared >= 40,
        "only {} runs compared",
        tally.compared
    );
    assert!(
        tally.exits >= 10,
        "only {} runs reached an exit",
        tally.exits
    );
}

#[test]
fn libc_leaf_functions_run_as_their_instructions() {
    if !Path::new(LIBC).exists() {
        return;
    }
    let mut tally = Tally::default();
    differential(LIBC, &read(LIBC), 4, &mut tally);
    assert_none(&tally.mismatches);
    assert!(
        tally.summarized >= 500,
        "only {} returns checked a summary",
        tally.summarized
    );
    assert!(
        tally.compared >= 200,
        "only {} runs compared",
        tally.compared
    );
    assert!(
        tally.exits >= 50,
        "only {} runs reached an exit",
        tally.exits
    );
}

/// libc follows the System V convention: a summary never finds a
/// callee-saved register changed (a reload it cannot follow is unknown,
/// not changed), and every return pops just the return address; most
/// summaries prove every callee-saved register kept.
#[test]
fn libc_summaries_agree_with_the_calling_convention() {
    if !Path::new(LIBC).exists() {
        return;
    }
    let data = read(LIBC);
    let image = Image::parse(&data).unwrap();
    let program = analyse(&image, Seeds::ALL, &type_library(&image).unwrap()).unwrap();
    let summaries = summaries(&image, &program);
    let saved = ["rbx", "rbp", "r12", "r13", "r14", "r15"].map(|name| X86.find(name).unwrap());
    let mut wrong = Vec::new();
    let mut proven = 0;
    for (entry, summary) in &summaries {
        let kept = saved.map(|register| summary.kept[usize::from(register.0)]);
        if kept.contains(&Kept::No) || summary.stack != 8 {
            wrong.push(format!("{entry:#x}: {kept:?}, stack {}", summary.stack));
        }
        proven += usize::from(kept.iter().all(|&k| k == Kept::Yes));
    }
    assert_none(&wrong);
    assert!(
        proven * 2 > summaries.len() && summaries.len() >= 1000,
        "{proven} of {} summaries prove the callee-saved registers kept",
        summaries.len()
    );
}

/// What [`ImageMemory`] knows of `image`: the file's bytes of code; nothing
/// of writable data, nor of slots the dynamic loader fills with symbols'
/// addresses (even in RELRO); a relative relocation's target for its slot
/// in RELRO, read whole, and nothing for part of it.
fn check_image_memory(image: &Image<'_>) {
    let memory = ImageMemory::new(image);
    let section = |name: &str| image.sections.iter().find(|s| s.name == name).unwrap();
    let in_relro = |at: u64| {
        image
            .relro
            .iter()
            .any(|range| range.start <= at && at + 8 <= range.end)
    };

    let text = section(".text").start;
    let mut bytes = [0u8; 8];
    assert_eq!(image.read(text, &mut bytes).unwrap(), 8);
    assert_eq!(memory.read(text, 8), Some(Bits::from_le_bytes(64, &bytes)));

    for name in [".data", ".bss"] {
        let start = section(name).start;
        assert!(image.is_mapped(start), "{name}");
        assert_eq!(memory.read(start, 1), None, "{name}");
    }

    assert!(
        image.imports.iter().any(|import| in_relro(import.slot)),
        "no import slot in RELRO"
    );
    for import in &image.imports {
        assert_eq!(memory.read(import.slot, 8), None, "{}", import.name);
    }
    let symbolic: Vec<u64> = image
        .fixups
        .iter()
        .filter(|fixup| fixup.value.is_none() && fixup.size == 8 && in_relro(fixup.start))
        .map(|fixup| fixup.start)
        .collect();
    assert!(!symbolic.is_empty(), "no symbol-dependent slot in RELRO");
    for slot in symbolic {
        assert_eq!(memory.read(slot, 8), None, "{slot:#x}");
    }

    let alone = |slot: u64| {
        image
            .fixups
            .iter()
            .filter(|fixup| fixup.start < slot + 8 && fixup.end() > slot)
            .count()
            == 1
    };
    let relative: Vec<(u64, u64)> = image
        .fixups
        .iter()
        .filter(|fixup| fixup.size == 8 && in_relro(fixup.start) && alone(fixup.start))
        .filter_map(|fixup| Some((fixup.start, fixup.value?)))
        .collect();
    assert!(!relative.is_empty(), "no relative relocation in RELRO");
    for (slot, value) in relative {
        assert_eq!(
            memory.read(slot, 8),
            Some(Bits::from_u64(64, value)),
            "{slot:#x}"
        );
        assert_eq!(memory.read(slot, 4), None, "{slot:#x}");
        assert_eq!(memory.read(slot + 4, 8), None, "{slot:#x}");
    }
}

#[test]
fn image_memory_gives_only_what_cannot_change() {
    let data = read(&fixture("program-x86_64.elf"));
    let image = Image::parse(&data).unwrap();
    check_image_memory(&image);
    let memory = ImageMemory::new(&image);
    // `.init_array`'s entry, in RELRO: R_X86_64_RELATIVE, addend 0x1180.
    assert_eq!(memory.read(0x3dd0, 8), Some(Bits::from_u64(64, 0x1180)));
    // `__libc_start_main`'s GOT entry, in RELRO: R_X86_64_GLOB_DAT.
    assert_eq!(memory.read(0x3fc0, 8), None);
    // A PLT call's GOT entry, writable: R_X86_64_JUMP_SLOT.
    assert_eq!(memory.read(0x4000, 8), None);

    if Path::new(LIBC).exists() {
        let data = read(LIBC);
        check_image_memory(&Image::parse(&data).unwrap());
    }
}
