//! Where computed jumps and calls go, for control-flow recovery: the
//! function's code so far lifted to L1, constants and stack slots found;
//! then the pointer slot the address is loaded from, or the jump's table
//! read from the image ([`binbun_ssa::jump`]). The same for x86-64 and
//! AArch64: only the sweep for the addresses code computes, which cuts
//! tables bounded by their index's width, decodes each architecture's
//! instructions.

use std::collections::HashMap;

use binbun_aarch64::operand::{Register, RegisterClass, Writeback};
use binbun_aarch64::{Encoding, Operand, decode};
use binbun_isa::{Architecture as _, Flow, Instruction as _, Target};
use binbun_loader::{Image, Machine};
use binbun_semantics::core::Memory as _;
use binbun_semantics::ir::Binary;
use binbun_ssa::condition::defining;
use binbun_ssa::constant::{Constants, propagate};
use binbun_ssa::jump::{self, Bound, Entry, Facts};
use binbun_ssa::stack::Stack;
use binbun_ssa::{BlockId, Code, Function, Instruction, Op, Terminator, Value, build};
use binbun_x86::{Mode, X86 as Decoder};

use crate::cfg::{Block, Resolver, Table};
use crate::lift::{ImageEnvironment, code_with, lift_instruction};
use crate::memory::ImageMemory;
use crate::strings;

/// The most cases a table may have.
const LIMIT: u64 = 4096;

/// How many views of a loaded value [`slot`] looks through.
const VIEWS: u32 = 8;

/// A function's L1 and what the analyses found in it.
#[derive(Debug)]
struct Analysis {
    function: Function,
    constants: Constants,
    stack: Stack,
}

/// Resolves the computed jumps and calls of an x86-64 or AArch64 image.
#[derive(Debug)]
pub struct TableResolver<'a> {
    image: &'a Image<'a>,
    memory: ImageMemory<'a>,
    /// Instructions lifted so far (the same blocks come back as recovery
    /// asks again).
    lifted: HashMap<u64, Instruction>,
    /// The last function analysed, by its entry and blocks (recovery asks
    /// about its jumps one after another).
    last: Option<(u64, Vec<Block>, Option<Analysis>)>,
    /// The addresses the code computes ([`Self::references`]), once needed.
    references: Option<Vec<u64>>,
}

impl<'a> TableResolver<'a> {
    /// The resolver for the code of `image` (its machine's).
    pub fn new(image: &'a Image<'a>) -> Self {
        Self {
            image,
            memory: ImageMemory::new(image),
            lifted: HashMap::new(),
            last: None,
            references: None,
        }
    }

    /// Analyses the function at `entry` made of `blocks` unless it was the
    /// last one.
    fn prepare(&mut self, entry: u64, blocks: &[Block]) {
        let fresh = !matches!(&self.last, Some((e, b, _)) if *e == entry && b == blocks);
        if fresh {
            let analysis = self.analyse(entry, blocks);
            self.last = Some((entry, blocks.to_vec(), analysis));
        }
    }

    /// The last function's analysis (`None` if its code does not lift or
    /// build).
    fn analysis(&self) -> Option<&Analysis> {
        self.last.as_ref()?.2.as_ref()
    }

    fn analyse(&mut self, entry: u64, blocks: &[Block]) -> Option<Analysis> {
        let (image, lifted) = (self.image, &mut self.lifted);
        // Lifted instructions are lent to the code and put back after.
        let code = code_with(entry, blocks, &mut |address| {
            lifted
                .remove(&address)
                .map_or_else(|| lift_instruction(image, address), Ok)
        })
        .ok()?;
        let analysis = self.analyse_code(&code, blocks);
        let instructions = code.blocks.into_iter().flatten();
        self.lifted
            .extend(instructions.map(|instruction| (instruction.address, instruction)));
        analysis
    }

    /// L1 of `code` (made of `blocks`), its constants and stack slots.
    fn analyse_code(&self, code: &Code, blocks: &[Block]) -> Option<Analysis> {
        let environment = ImageEnvironment::new(self.image, blocks).ok()?;
        let function = build(code, environment.declarations(), &environment).ok()?;
        let constants = propagate(&function, &self.memory);
        let stack = Stack::new(
            &function,
            environment.declarations(),
            &constants,
            environment.stack_pointer(),
            &environment.arguments(),
        );
        Some(Analysis {
            function,
            constants,
            stack,
        })
    }
}

/// The L1 block that ends in the computed jump of `jump`.
fn jump_block(function: &Function, jump: Block) -> Option<BlockId> {
    function.blocks.iter().enumerate().find_map(|(index, b)| {
        (matches!(b.terminator, Terminator::IndirectJump { .. })
            && (jump.start..jump.end).contains(&b.address))
        .then(|| BlockId(u32::try_from(index).unwrap_or(u32::MAX)))
    })
}

/// The address the computed jump or call ending `jump` goes to: the
/// jump's, or that of the last call made in the block.
fn transfer_address(function: &Function, jump: Block) -> Option<Value> {
    if let Some(block) = jump_block(function, jump)
        && let Some(Terminator::IndirectJump { address, .. }) =
            function.block(block).map(|b| &b.terminator)
    {
        return Some(*address);
    }
    function
        .insts
        .iter()
        .rev()
        .filter(|inst| (jump.start..jump.end).contains(&inst.address))
        .find_map(|inst| {
            if let Op::Call { target, .. } = inst.op {
                Some(target)
            } else {
                None
            }
        })
}

/// The pointer slot `value` is read from, and its size: a load of at
/// least 4 bytes from a constant address, seen through stack slots and
/// through views that keep every address the slot can hold (zero
/// extension, the low 48 bits or more, and a choice between such views:
/// AArch64 clears a branch target's top byte unless bit 55 is set; an
/// exclusive or with bits above the low 48 only: pointer authentication's
/// code taken out of an authenticated pointer, `braa x16, x17` of an
/// arm64e stub).
fn slot(facts: Facts<'_>, value: Value, depth: u32) -> Option<(u64, u16)> {
    let function = facts.function;
    if depth > VIEWS {
        return None;
    }
    let value = facts.stack.resolve(function, value);
    let op = defining(function, value)?;
    if let Op::Load { address, bytes, .. } = *op {
        let address = facts.constants.constant(address).filter(|_| bytes >= 4)?;
        return Some((address.low_u64(), bytes));
    }
    if let Op::Extend {
        signed: false,
        value,
        ..
    }
    | Op::Extract {
        value,
        offset: 0,
        width: 48..,
    } = *op
    {
        return slot(facts, value, depth + 1);
    }
    if let Op::Select {
        then, otherwise, ..
    } = *op
    {
        let found = slot(facts, then, depth + 1)?;
        return (slot(facts, otherwise, depth + 1)? == found).then_some(found);
    }
    if let Op::Binary(Binary::Xor, left, right) = *op {
        if above_address(facts, right) {
            return slot(facts, left, depth + 1);
        }
        if above_address(facts, left) {
            return slot(facts, right, depth + 1);
        }
    }
    None
}

/// Whether `value` has no bit set in the low 48 (an address's): it is
/// masked by a constant without them.
fn above_address(facts: Facts<'_>, value: Value) -> bool {
    let Some(&Op::Binary(Binary::And, left, right)) = defining(facts.function, value) else {
        return false;
    };
    [left, right].into_iter().any(|operand| {
        facts
            .constants
            .constant(operand)
            .is_some_and(|mask| mask.low_u64().trailing_zeros() >= 48)
    })
}

impl Resolver for TableResolver<'_> {
    /// A load from a pointer slot at a constant address (a GOT or IAT
    /// entry: an AArch64 PLT stub, x86 `mov rax, [rip+slot]; jmp rax`), or
    /// a constant address of code.
    fn target(&mut self, entry: u64, blocks: &[Block], jump: Block) -> Option<Target> {
        self.prepare(entry, blocks);
        let analysis = self.analysis()?;
        let facts = Facts {
            function: &analysis.function,
            constants: &analysis.constants,
            stack: &analysis.stack,
        };
        let address = transfer_address(&analysis.function, jump)?;
        if let Some((slot, bytes)) = slot(facts, address, 0) {
            return Some(Target::Pointer {
                address: slot,
                size: u8::try_from(bytes).ok()?,
            });
        }
        let constant = analysis.constants.constant(address)?.low_u64();
        self.image
            .is_code(constant)
            .then_some(Target::Address(constant))
    }

    fn table(&mut self, entry: u64, blocks: &[Block], jump: Block) -> Option<Table> {
        self.prepare(entry, blocks);
        let image = self.image;
        let analysis = self.analysis()?;
        let facts = Facts {
            function: &analysis.function,
            constants: &analysis.constants,
            stack: &analysis.stack,
        };
        let block = jump_block(&analysis.function, jump)?;
        let table = jump::targets(facts, &self.memory, block, LIMIT)?;
        let mut targets: Vec<u64> = match table.bound {
            // Only code can be jumped to.
            Bound::Guard => table
                .entries
                .iter()
                .map(|entry| entry.target)
                .all(|address| image.is_code(address))
                .then(|| table.entries.iter().map(|entry| entry.target).collect())?,
            Bound::Width => self.table_end(jump.start, &table.entries),
        };
        targets.sort_unstable();
        targets.dedup();
        (!targets.is_empty()).then_some(Table {
            targets,
            inferred: table.bound == Bound::Width,
        })
    }

    /// Text in code ([`strings::code_text`]): a string and its NUL that
    /// end in the same code range.
    fn data(&mut self, address: u64) -> Option<u64> {
        let code = &self.image.code;
        let index = code
            .partition_point(|range| range.start <= address)
            .checked_sub(1)?;
        let end = code.get(index).filter(|range| address < range.end)?.end;
        let size = usize::try_from(end - address).unwrap_or(usize::MAX);
        let mut bytes = vec![0; strings::MAX_CODE_TEXT.min(size)];
        let read = self.image.read(address, &mut bytes).unwrap_or(0);
        bytes.truncate(read);
        let (encoding, length) = strings::code_text(address, &bytes)?;
        Some(address + length + encoding.unit())
    }
}

impl TableResolver<'_> {
    /// The targets of a table whose index only its width bounds, up to
    /// where the table seems to end: before the first entry that leaves
    /// the unwind table range of the function the jump at `jump` is in
    /// (every case of a switch is code of its function), or that is read
    /// past an address the code computes (the start of the next object in
    /// memory, often the next table). None without such a range.
    fn table_end(&mut self, jump: u64, entries: &[Entry]) -> Vec<u64> {
        let Some(range) = self
            .image
            .unwind
            .iter()
            .filter(|entry| (entry.start..entry.end).contains(&jump))
            .min_by_key(|entry| entry.end - entry.start)
            .map(|entry| entry.start..entry.end)
        else {
            return Vec::new();
        };
        let computed = self.references();
        // Whether some referenced address lies in `after..=at`.
        let referenced = |after: u64, at: u64| {
            let first = computed.partition_point(|&r| r <= after);
            computed.get(first).is_some_and(|&r| r <= at)
        };
        let mut targets = Vec::new();
        let mut previous: Option<&Entry> = None;
        for entry in entries {
            let crossed = previous.is_some_and(|previous| {
                previous
                    .reads
                    .iter()
                    .zip(&entry.reads)
                    .any(|(&before, &at)| before < at && referenced(before, at))
            });
            if crossed || !range.contains(&entry.target) {
                break;
            }
            targets.push(entry.target);
            previous = Some(entry);
        }
        targets
    }

    /// The addresses the image's code computes, sorted: found by decoding
    /// its code ([`Image::code`]) from start to end, once (x86:
    /// RIP-relative `lea`; AArch64: `adr`, and `adrp` with the `add` that
    /// completes its address). Decoding out of step with the real
    /// instructions (x86) or a register's page carried past a branch
    /// target (AArch64) adds addresses that are none; they only cut
    /// inferred tables shorter.
    fn references(&mut self) -> &[u64] {
        let image = self.image;
        self.references.get_or_insert_with(|| {
            let mut found = Vec::new();
            for range in &image.code {
                // Each range of code lies within one segment.
                let bytes = image
                    .segment(range.start)
                    .and_then(|segment| {
                        let start = usize::try_from(range.start - segment.start).ok()?;
                        let end = usize::try_from(range.end - segment.start).ok()?;
                        segment.bytes.get(start..end.min(segment.bytes.len()))
                    })
                    .unwrap_or_default();
                match image.machine {
                    Machine::X86 => x86_references(Mode::Bits32, range.start, bytes, &mut found),
                    Machine::X86_64 => {
                        x86_references(Mode::Bits64, range.start, bytes, &mut found);
                    }
                    Machine::Aarch64 => aarch64_references(range.start, bytes, &mut found),
                    Machine::Arm | Machine::Other => {}
                }
            }
            found.sort_unstable();
            found.dedup();
            found
        })
    }
}

/// The addresses x86 code at `start` computes (RIP-relative `lea`), added
/// to `found`.
fn x86_references(mode: Mode, start: u64, bytes: &[u8], found: &mut Vec<u64>) {
    let mut offset = 0;
    while let Some(rest) = bytes.get(offset..) {
        if rest.is_empty() {
            break;
        }
        let address = start + offset as u64;
        match Decoder.decode_flow(rest, mode, address) {
            Ok(step) => {
                found.extend(step.computed_address);
                offset += step.len;
            }
            Err(_) => offset += 1,
        }
    }
}

/// The addresses AArch64 code at `start` computes, added to `found`: `adr`
/// targets, and a page an `adrp` put in a register plus the immediate of
/// an `add` from that register further on. A register's page is forgotten
/// when an instruction writes the register, when a call may change it
/// (`x0`–`x18`, `x30`), and after a jump or return (the next instruction
/// is reached from elsewhere).
fn aarch64_references(start: u64, bytes: &[u8], found: &mut Vec<u64>) {
    let mut pages = [None::<u64>; 31];
    // A general register's number (31 is the zero register or the stack
    // pointer, neither of which holds a page).
    let general = |register: &Register| {
        matches!(
            register.class,
            RegisterClass::W | RegisterClass::X | RegisterClass::Wsp | RegisterClass::Xsp
        )
        .then_some(usize::from(register.number))
        .filter(|&number| number < 31)
    };
    let (words, _) = bytes.as_chunks::<4>();
    for (address, word) in (start..).step_by(4).zip(words) {
        let Ok(instruction) = decode(u32::from_le_bytes(*word)) else {
            pages = [None; 31];
            continue;
        };
        found.extend(instruction.computed_address(address));
        let operands = instruction.encoding_operands();
        // The page `adrp` writes to its register.
        let mut page = None;
        if let (Encoding::ADRP_only_pcreladdr, [Operand::Register(_), Operand::Label(label)]) =
            (instruction.encoding(), operands.as_slice())
        {
            page = Some(label.target(address));
        }
        if let (
            Encoding::ADD_64_addsub_imm,
            [
                Operand::Register(_),
                Operand::Register(base),
                Operand::Immediate(immediate),
                rest @ ..,
            ],
        ) = (instruction.encoding(), operands.as_slice())
            && let Some(Some(base)) = general(base).and_then(|n| pages.get(n))
        {
            let shift = if let [Operand::Shift(shift)] = rest {
                u32::from(shift.amount)
            } else {
                0
            };
            found.push(base.wrapping_add(immediate.value << shift));
        }
        let accesses = instruction.encoding_access();
        let written = operands
            .iter()
            .zip(accesses.iter())
            .filter_map(|(operand, access)| {
                if let Operand::Register(register) = operand
                    && access.writes()
                {
                    general(register)
                } else if let Operand::Memory(memory) = operand
                    && memory.writeback != Writeback::None
                {
                    general(&memory.base)
                } else {
                    None
                }
            });
        for number in written {
            if let Some(slot) = pages.get_mut(number) {
                *slot = page;
            }
        }
        match instruction.flow(address) {
            Flow::Next | Flow::Branch(_) | Flow::Trap { conditional: true } | Flow::SystemCall => {}
            Flow::Call(_) => {
                for (number, slot) in pages.iter_mut().enumerate() {
                    if number <= 18 || number == 30 {
                        *slot = None;
                    }
                }
            }
            Flow::Jump(_)
            | Flow::Return
            | Flow::Trap { conditional: false }
            | Flow::ExceptionReturn
            | Flow::Halt => pages = [None; 31],
        }
    }
}
