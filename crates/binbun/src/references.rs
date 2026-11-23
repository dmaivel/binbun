//! Cross-references: every place the program refers to an address, from
//! code and from data, as one index built for the whole program
//! ([`References`]).
//!
//! From code, each recovered function's references, by the instruction
//! that makes them:
//!
//! - **Calls and jumps** are recovery's: a block's exit to a known address
//!   (a call, a jump or branch, a tail call: a jump to another function),
//!   and each case of a resolved computed jump, from the instruction
//!   ending the block.
//! - **Reads, writes and addresses taken** come from L1 after constant
//!   propagation over the image's read-only memory, as lowering's data
//!   references read them, so that an address formed in two instructions
//!   (AArch64's `adrp` and `add` or `ldr`) and in one (x86's rip-relative
//!   operands) are alike. A pointer-wide value that is one constant on
//!   every path and one of the image's addresses (in a section) is a
//!   reference from the instruction computing it, where it may be an
//!   address: anywhere in an image at a fixed address, but in a
//!   position-independent one only computed (the program counter plus an
//!   offset; not an immediate, which is never an address there) or loaded
//!   from a slot a relocation fills. What it is then is how it is used,
//!   through jumps' arguments and copies (the same constant computed from
//!   it, as plus 0): as the address of a load (a **read**) or a store (a
//!   **write**), directly or plus a computed index; passed in a call's
//!   argument register, returned (in the first result register: a second,
//!   `rdx` or `x1`, mostly holds what is left there), stored, given to an
//!   intrinsic, packed into a vector, used in a computation that is not
//!   constant, or (unless an immediate) computed into another constant by
//!   a later instruction (an **address** taken: compared, offset by a
//!   computed amount, the base of a field the next instruction reads). A
//!   value computed into another constant within its own instruction
//!   (rip plus the displacement, an address plus the access's
//!   displacement, L0's check that an address is canonical), or an
//!   immediate computed into another (`adrp`'s page into its `add`), is no
//!   reference of its own: the address computed is. Nor is the return
//!   address a call pushes. Only blocks constant propagation finds may run
//!   are read. A function that does not lift has its calls and jumps only,
//!   and reads of the pointer slots it calls or jumps through.
//!
//! From data, **pointers**: the words relocations make the image's own
//! addresses ([`Image::pointers`]: ELF `RELATIVE`, `ABS64`, `GLOB_DAT`,
//! `JUMP_SLOT`, PE base relocations); and only where an image at a fixed
//! address has no such relocations (an ELF executable that is not
//! position-independent, a PE file without base relocations), every
//! aligned pointer-sized word of its program data
//! ([`program_data`]) that the dynamic loader
//! does not write and that holds one of its addresses, marked as found by
//! scanning.

use std::collections::BTreeSet;
use std::ops::Range;

use binbun_loader::{Image, Machine, Relocation};
use binbun_semantics::RegisterId;
use binbun_semantics::core::{Id as _, Memory as _};
use binbun_ssa::constant::Constants;
use binbun_ssa::ir::Definition;
use binbun_ssa::{BlockId, Function, Inst, Op, Terminator, Value};
use binbun_x86::{MAX_LENGTH, decode};

use crate::analysis::x86_mode;
use crate::cfg::{Block, BlockId as RecoveredBlock, Destination, Exit, FunctionId, Program};
use crate::data::program_data;
use crate::lift::ImageEnvironment;
use crate::progress::Progress;
use crate::summary::{Summaries, summarize_all};
use crate::target::convention;

/// How a reference refers to its target.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Kind {
    /// A call to it.
    Call,
    /// A jump or conditional branch to it (a tail call, if it is another
    /// function's entry; a case, from a computed jump).
    Jump,
    /// A load from it.
    Read,
    /// A store to it.
    Write,
    /// Its address computed and used otherwise: passed, stored, returned,
    /// compared, offset by a computed amount.
    Address,
    /// A pointer to it stored in data.
    Pointer(Origin),
}

/// How a pointer in data is known.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Origin {
    /// A relocation stores it.
    Relocation(Relocation),
    /// An aligned word holds it, in an image without relocations.
    Scan,
}

/// One reference to an address.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Reference {
    /// The address referred to.
    pub target: u64,
    /// Where it is made: the instruction, or where the pointer is stored.
    pub from: u64,
    /// How.
    pub kind: Kind,
    /// The function whose instruction makes it (`None`: a pointer in data).
    pub function: Option<FunctionId>,
}

/// Every reference of a program, by target and by function.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct References {
    /// The references, sorted by target (then where they are made, how,
    /// and by which function).
    by_target: Vec<Reference>,
    /// The code references' indices in `by_target`, sorted by function,
    /// then where they are made and their target.
    by_function: Vec<u32>,
    /// The functions that do not lift: only their calls and jumps are
    /// known.
    unlifted: Vec<FunctionId>,
    /// Whether pointers in data were found by scanning.
    scanned: bool,
}

impl References {
    /// The references of `program` (recovered from `image`), with the
    /// functions' summaries, which building them computes on the way: each
    /// function is lifted once, callees first, as for
    /// [`summaries`](crate::summary::summaries), on `threads` threads
    /// ([`summarize_all`]: the same whatever the threads), each one a step
    /// of `progress`.
    pub fn build(
        image: &Image<'_>,
        program: &Program,
        threads: usize,
        progress: &Progress,
    ) -> (Self, Summaries) {
        let mut references = Vec::new();
        let mut lifted = vec![false; program.functions.len()];
        let context = Context::new(image);
        progress.start(program.functions.len());
        let summaries = summarize_all(
            image,
            program,
            threads,
            |id, built| {
                let (Ok((function, constants)), Some(context)) = (built, &context) else {
                    return None;
                };
                let mut found = Vec::new();
                context.function(id, function, constants, &mut found);
                Some(found)
            },
            |id, found| {
                progress.step();
                if let Some(mut found) = found {
                    references.append(&mut found);
                    if let Some(flag) = lifted.get_mut(id.index()) {
                        *flag = true;
                    }
                }
            },
        );
        let mut unlifted = Vec::new();
        for (id, function) in program.functions.iter() {
            let lifts = lifted.get(id.index()).copied().unwrap_or(false);
            if !lifts {
                unlifted.push(id);
            }
            control(image, program, id, &function.blocks, lifts, &mut references);
        }
        let scanned = pointers(image, &mut references);
        (Self::new(references, unlifted, scanned), summaries)
    }

    /// The index of `references`.
    fn new(mut references: Vec<Reference>, unlifted: Vec<FunctionId>, scanned: bool) -> Self {
        references.sort_unstable();
        references.dedup();
        let mut by_function: Vec<u32> = references
            .iter()
            .enumerate()
            .filter(|(_, reference)| reference.function.is_some())
            .filter_map(|(index, _)| u32::try_from(index).ok())
            .collect();
        let key = |index: &u32| {
            references
                .get(*index as usize)
                .map(|r| (r.function, r.from, r.target, r.kind))
        };
        by_function.sort_unstable_by_key(key);
        Self {
            by_target: references,
            by_function,
            unlifted,
            scanned,
        }
    }

    /// Every reference, by target.
    pub fn all(&self) -> &[Reference] {
        &self.by_target
    }

    /// The references to `address`.
    pub fn to(&self, address: u64) -> &[Reference] {
        self.within(address..address.saturating_add(1))
    }

    /// The references to any address of `range` (an object's bytes), by
    /// target.
    pub fn within(&self, range: Range<u64>) -> &[Reference] {
        let first = self.by_target.partition_point(|r| r.target < range.start);
        let last = self.by_target.partition_point(|r| r.target < range.end);
        self.by_target.get(first..last).unwrap_or_default()
    }

    /// The references function `id` makes, by the instruction making them.
    pub fn from_function(&self, id: FunctionId) -> impl Iterator<Item = &Reference> {
        let function = |index: &u32| {
            self.by_target
                .get(*index as usize)
                .and_then(|reference| reference.function)
        };
        let first = self
            .by_function
            .partition_point(|index| function(index) < Some(id));
        let last = self
            .by_function
            .partition_point(|index| function(index) <= Some(id));
        self.by_function
            .get(first..last)
            .unwrap_or_default()
            .iter()
            .filter_map(|&index| self.by_target.get(index as usize))
    }

    /// The functions that do not lift, whose reads, writes and addresses
    /// taken are not known.
    pub fn unlifted(&self) -> &[FunctionId] {
        &self.unlifted
    }

    /// Whether pointers in data were found by scanning (the image has no
    /// relocations of its own addresses).
    pub fn scanned(&self) -> bool {
        self.scanned
    }
}

/// The calls and jumps of the function `id` of `program` made of `blocks`
/// (of `image`): each block's exit and resolved table, from the
/// instruction ending it; and, if the function does not `lift`, reads of
/// the pointer slots it calls or jumps through.
fn control(
    image: &Image<'_>,
    program: &Program,
    id: FunctionId,
    blocks: &[RecoveredBlock],
    lifts: bool,
    out: &mut Vec<Reference>,
) {
    for &block_id in blocks {
        let Some(block) = program.blocks.get(block_id) else {
            continue;
        };
        let Some(from) = last_instruction(image, block) else {
            continue;
        };
        let mut push = |target, kind| {
            out.push(Reference {
                target,
                from,
                kind,
                function: Some(id),
            });
        };
        let exit = match block.exit {
            Exit::Call { callee, .. } => Some((callee, Kind::Call)),
            Exit::Jump(destination) | Exit::Branch(destination) => Some((destination, Kind::Jump)),
            Exit::Next | Exit::Return | Exit::Stop | Exit::Invalid | Exit::Limit => None,
        };
        if let Some((destination, kind)) = exit {
            match destination {
                Destination::Address(target) => push(target, kind),
                Destination::Import(slot) | Destination::Pointer(slot) if !lifts => {
                    push(slot, Kind::Read);
                }
                Destination::Import(_)
                | Destination::Pointer(_)
                | Destination::Indirect
                | Destination::Far => {}
            }
        }
        for &target in program.table(block_id).map_or(&[][..], |t| &t.targets) {
            push(target, Kind::Jump);
        }
    }
}

/// The address of the last instruction of `block` (of `image`).
pub(crate) fn last_instruction(image: &Image<'_>, block: &Block) -> Option<u64> {
    if block.instructions == 0 {
        return None;
    }
    if image.machine == Machine::Aarch64 {
        return block.end.checked_sub(4);
    }
    let mode = x86_mode(image.machine).ok()?;
    let mut address = block.start;
    for _ in 1..block.instructions {
        let mut buffer = [0u8; MAX_LENGTH];
        let read = image.read(address, &mut buffer).ok()?;
        let instruction = decode(buffer.get(..read)?, mode).ok()?;
        address = address.checked_add(instruction.len() as u64)?;
    }
    Some(address)
}

/// The pointers in the data of `image`: its relocations', and if it is at
/// a fixed address without relocations of its own addresses, those found
/// by scanning; whether it was scanned.
fn pointers(image: &Image<'_>, out: &mut Vec<Reference>) -> bool {
    out.extend(image.pointers.iter().map(|pointer| Reference {
        target: pointer.target,
        from: pointer.at,
        kind: Kind::Pointer(Origin::Relocation(pointer.relocation)),
        function: None,
    }));
    let relocated = image.pointers.iter().any(|pointer| {
        matches!(
            pointer.relocation,
            Relocation::Relative | Relocation::Base | Relocation::Rebase
        )
    });
    if relocated || image.position_independent {
        return false;
    }
    scan(image, out);
    true
}

/// Every aligned pointer-sized word of the program data of `image` that
/// no relocation and no other write of the dynamic loader covers and that
/// holds one of its addresses.
fn scan(image: &Image<'_>, out: &mut Vec<Reference>) {
    let size: usize = match image.machine {
        Machine::X86_64 | Machine::Aarch64 => 8,
        Machine::X86 | Machine::Arm | Machine::Other => 4,
    };
    let step = size as u64;
    let addresses = Addresses::new(image);
    // Fixups are sorted by start; `reach` is the furthest end so far.
    let fixups = &image.fixups;
    let (mut next, mut reach) = (0, 0);
    for section in program_data(image) {
        let end = section.start.saturating_add(section.size);
        let mut at = section.start.next_multiple_of(step);
        while at.saturating_add(step) <= end {
            while let Some(fixup) = fixups.get(next).filter(|f| f.start < at + step) {
                reach = reach.max(fixup.end());
                next += 1;
            }
            let mut word = [0u8; 8];
            let written = reach > at;
            let bytes = word.get_mut(..size).unwrap_or_default();
            if !written && image.read(at, bytes) == Ok(bytes.len()) {
                let target = u64::from_le_bytes(word);
                if addresses.contains(target) {
                    out.push(Reference {
                        target,
                        from: at,
                        kind: Kind::Pointer(Origin::Scan),
                        function: None,
                    });
                }
            }
            at += step;
        }
    }
}

/// The image's addresses: what its sections cover (not the headers a
/// position-independent image maps at address 0), or its segments if it
/// has no sections.
#[derive(Clone, Debug)]
struct Addresses {
    /// Sorted, not overlapping.
    ranges: Vec<Range<u64>>,
}

impl Addresses {
    /// The addresses of `image`.
    fn new(image: &Image<'_>) -> Self {
        let mut ranges: Vec<Range<u64>> = image
            .sections
            .iter()
            .filter(|section| section.start != 0 && section.size != 0)
            .map(|section| section.start..section.start.saturating_add(section.size))
            .collect();
        if ranges.is_empty() {
            ranges = image
                .segments
                .iter()
                .map(|segment| segment.start..segment.end())
                .collect();
        }
        ranges.sort_by_key(|range| range.start);
        let mut merged: Vec<Range<u64>> = Vec::with_capacity(ranges.len());
        for range in ranges {
            match merged.last_mut() {
                Some(last) if range.start <= last.end => last.end = last.end.max(range.end),
                Some(_) | None => merged.push(range),
            }
        }
        Self { ranges: merged }
    }

    /// Whether `address` is one of them.
    fn contains(&self, address: u64) -> bool {
        let after = self.ranges.partition_point(|range| range.start <= address);
        after
            .checked_sub(1)
            .and_then(|index| self.ranges.get(index))
            .is_some_and(|range| address < range.end)
    }
}

/// How a value is used, for what a constant address is taken as.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Use {
    /// An operand of a pure operation with this result.
    Pure(Value),
    /// The address of a load.
    Load,
    /// The address of a store.
    Store,
    /// Passed, returned, stored or given to an intrinsic.
    Escape,
    /// A jump's argument for this block parameter.
    Parameter(Value),
}

/// What reading references in L1 needs of an image.
#[derive(Clone, Debug)]
struct Context<'a> {
    image: &'a Image<'a>,
    addresses: Addresses,
    /// Whether an immediate can be one of its addresses (it is at a fixed
    /// address).
    fixed: bool,
    /// The registers of the calling convention's arguments, first result
    /// and system call arguments, by index.
    arguments: Vec<usize>,
    results: Vec<usize>,
    system_call: Vec<usize>,
}

impl<'a> Context<'a> {
    /// The context of `image`, if its code is lifted.
    fn new(image: &'a Image<'a>) -> Option<Self> {
        let declarations = ImageEnvironment::new(image, &[]).ok()?.declarations();
        let convention = convention(image, declarations);
        let indices = |registers: &[RegisterId]| {
            registers
                .iter()
                .map(|register| usize::from(register.0))
                .collect()
        };
        Some(Self {
            image,
            addresses: Addresses::new(image),
            fixed: !image.position_independent,
            arguments: indices(&convention.arguments),
            results: indices(convention.results.get(..1).unwrap_or_default()),
            system_call: indices(convention.system_call.get(1..).unwrap_or_default()),
        })
    }

    /// The reads, writes and addresses taken of function `id`, lifted to
    /// `function` with its `constants`.
    fn function(
        &self,
        id: FunctionId,
        function: &Function,
        constants: &Constants,
        out: &mut Vec<Reference>,
    ) {
        let uses = self.uses(function, constants);
        let address = |value: Value| {
            constants
                .constant(value)
                .filter(|bits| bits.width() == 64 && self.addresses.contains(bits.low_u64()))
                .map(|bits| bits.low_u64())
        };
        for inst in &function.insts {
            for &value in &inst.results {
                let Some(target) = address(value) else {
                    continue;
                };
                // A copy (an address plus 0) is its source's reference, if
                // that may be one (`adrp`'s page plus 0 is the first).
                let copy = operands(&inst.op).into_iter().any(|operand| {
                    constants.constant(operand) == constants.constant(value)
                        && self.may_be_address(source(function, constants, operand))
                });
                let source = source(function, constants, value);
                if copy || !self.may_be_address(source) {
                    continue;
                }
                let formed = !matches!(source, Source::Immediate);
                for kind in uses.kinds(function, constants, (value, inst.address), formed) {
                    out.push(Reference {
                        target,
                        from: inst.address,
                        kind,
                        function: Some(id),
                    });
                }
            }
        }
    }

    /// Whether a constant from `source` may be one of the image's
    /// addresses: anything in an image at a fixed address; else computed,
    /// or loaded from a slot a relocation fills.
    fn may_be_address(&self, source: Source) -> bool {
        if self.fixed {
            return true;
        }
        match source {
            Source::Computed => true,
            Source::Immediate => false,
            Source::Loaded(slot) => {
                let pointers = &self.image.pointers;
                let index = pointers.partition_point(|pointer| pointer.at < slot);
                pointers
                    .get(index)
                    .is_some_and(|pointer| pointer.at == slot)
            }
        }
    }

    /// The uses of the values of `function`'s blocks that can run (by
    /// `constants`).
    fn uses(&self, function: &Function, constants: &Constants) -> Uses {
        let returns: Vec<(u64, u64)> = function
            .insts
            .iter()
            .filter_map(|inst| match inst.op {
                Op::Call { return_address, .. } => constants
                    .constant(return_address)
                    .map(|bits| (inst.address, bits.low_u64())),
                Op::Const(_)
                | Op::Undefined(..)
                | Op::Unary(..)
                | Op::Binary(..)
                | Op::Flag(..)
                | Op::Extract { .. }
                | Op::Concat { .. }
                | Op::Extend { .. }
                | Op::Select { .. }
                | Op::Lanes { .. }
                | Op::Float { .. }
                | Op::Load { .. }
                | Op::Store { .. }
                | Op::Intrinsic { .. }
                | Op::SystemCall { .. }
                | Op::Landing { .. } => None,
            })
            .collect();
        let mut uses = Vec::new();
        for (index, block) in function.blocks.iter().enumerate() {
            let id = BlockId(u32::try_from(index).unwrap_or(u32::MAX));
            if !constants.reachable(id) {
                continue;
            }
            for &inst in &block.insts {
                if let Some(inst) = function.inst(inst) {
                    self.inst_uses(inst, constants, &returns, &mut uses);
                }
            }
            self.terminator_uses(function, &block.terminator, &mut uses);
        }
        uses.sort_by_key(|&(value, _)| value);
        Uses(uses)
    }

    /// The uses `inst` makes; a store of the return address a call at the
    /// same instruction pushes (one of `returns`: instruction, return
    /// address) is none.
    fn inst_uses(
        &self,
        inst: &Inst,
        constants: &Constants,
        returns: &[(u64, u64)],
        uses: &mut Vec<(Value, Use)>,
    ) {
        let pure = inst.results.first().copied().map(Use::Pure);
        let mut push = |value: Value, kind: Option<Use>| {
            if let Some(kind) = kind {
                uses.push((value, kind));
            }
        };
        match &inst.op {
            Op::Const(_) | Op::Undefined(..) | Op::Landing { .. } => {}
            &(Op::Unary(_, a) | Op::Extract { value: a, .. } | Op::Extend { value: a, .. }) => {
                push(a, pure);
            }
            &(Op::Binary(_, a, b) | Op::Concat { high: a, low: b }) => {
                push(a, pure);
                push(b, pure);
            }
            &(Op::Flag(_, a, b, c)
            | Op::Select {
                condition: a,
                then: b,
                otherwise: c,
            }
            | Op::Lanes {
                operands: [a, b, c],
                ..
            }
            | Op::Float {
                operands: [a, b, c],
                ..
            }) => {
                push(a, pure);
                push(b, pure);
                push(c, pure);
            }
            &Op::Load { address, .. } => push(address, Some(Use::Load)),
            &Op::Store { address, value, .. } => {
                push(address, Some(Use::Store));
                let pushed = constants
                    .constant(value)
                    .is_some_and(|bits| returns.contains(&(inst.address, bits.low_u64())));
                if !pushed {
                    push(value, Some(Use::Escape));
                }
            }
            Op::Intrinsic { inputs, .. } => {
                for &input in inputs {
                    push(input, Some(Use::Escape));
                }
            }
            Op::Call { registers, .. } => {
                for value in self.arguments.iter().filter_map(|&r| registers.get(r)) {
                    push(*value, Some(Use::Escape));
                }
            }
            Op::SystemCall { registers, .. } => {
                for value in self.system_call.iter().filter_map(|&r| registers.get(r)) {
                    push(*value, Some(Use::Escape));
                }
            }
        }
    }

    /// The uses `terminator` (of `function`) makes: jump arguments for
    /// their parameters, results returned, arguments of a tail call.
    fn terminator_uses(
        &self,
        function: &Function,
        terminator: &Terminator,
        uses: &mut Vec<(Value, Use)>,
    ) {
        for target in terminator.targets() {
            let Some(block) = function.block(target.block) else {
                continue;
            };
            for (&argument, &parameter) in target.arguments.iter().zip(&block.parameters) {
                uses.push((argument, Use::Parameter(parameter)));
            }
        }
        let escaping = match terminator {
            Terminator::Return { state, .. } => Some((state, &self.results)),
            Terminator::Leave { state, .. } => Some((state, &self.arguments)),
            Terminator::Jump(_)
            | Terminator::Branch { .. }
            | Terminator::IndirectJump { .. }
            | Terminator::Trap(_)
            | Terminator::Stop
            | Terminator::Open
            | Terminator::Invoke { .. } => None,
        };
        if let Some((state, registers)) = escaping {
            for value in registers.iter().filter_map(|&r| state.registers.get(r)) {
                uses.push((*value, Use::Escape));
            }
        }
    }
}

/// The uses of a function's values, sorted by value.
struct Uses(Vec<(Value, Use)>);

/// Where a constant value comes from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Source {
    /// An instruction's immediate (or a function's input).
    Immediate,
    /// A computation.
    Computed,
    /// A load from this address.
    Loaded(u64),
}

/// Where constant `value` of `function` comes from (by `constants`), seen
/// through extensions, extractions and copies (the same constant computed
/// from another, as plus 0); a copy of an immediate is computed
/// (`adrp`'s page plus 0).
fn source(function: &Function, constants: &Constants, value: Value) -> Source {
    let constant = constants.constant(value);
    let mut value = value;
    let mut copied = false;
    let immediate = |copied| {
        if copied {
            Source::Computed
        } else {
            Source::Immediate
        }
    };
    // Each step goes to an earlier definition; this bounds odd chains.
    for _ in 0..16 {
        let Some(inst) = defining(function, value) else {
            return immediate(copied);
        };
        if let Some(operand) = operands(&inst.op)
            .into_iter()
            .find(|&operand| constants.constant(operand) == constant)
        {
            (value, copied) = (operand, true);
            continue;
        }
        match inst.op {
            Op::Extend { value: source, .. } | Op::Extract { value: source, .. } => {
                value = source;
            }
            Op::Const(_) | Op::Undefined(..) => return immediate(copied),
            Op::Load { address, .. } => {
                return constants
                    .constant(address)
                    .map_or(Source::Computed, |slot| Source::Loaded(slot.low_u64()));
            }
            Op::Unary(..)
            | Op::Binary(..)
            | Op::Flag(..)
            | Op::Concat { .. }
            | Op::Select { .. }
            | Op::Lanes { .. }
            | Op::Float { .. }
            | Op::Store { .. }
            | Op::Intrinsic { .. }
            | Op::Call { .. }
            | Op::SystemCall { .. }
            | Op::Landing { .. } => return Source::Computed,
        }
    }
    Source::Immediate
}

/// The instruction of `function` defining `value`, if one does.
fn defining(function: &Function, value: Value) -> Option<&Inst> {
    match function.value(value)?.definition {
        Definition::Result { inst, .. } => function.inst(inst),
        Definition::Parameter { .. } => None,
    }
}

/// The operands of `op` if it is a pure operation of whole values (what
/// can copy one).
fn operands(op: &Op) -> Vec<Value> {
    match *op {
        Op::Unary(_, a) | Op::Extract { value: a, .. } | Op::Extend { value: a, .. } => vec![a],
        Op::Binary(_, a, b) | Op::Concat { high: a, low: b } => vec![a, b],
        Op::Select {
            then, otherwise, ..
        } => vec![then, otherwise],
        Op::Const(_)
        | Op::Undefined(..)
        | Op::Flag(..)
        | Op::Lanes { .. }
        | Op::Float { .. }
        | Op::Load { .. }
        | Op::Store { .. }
        | Op::Intrinsic { .. }
        | Op::Call { .. }
        | Op::SystemCall { .. }
        | Op::Landing { .. } => Vec::new(),
    }
}

impl Uses {
    /// The uses of `value`.
    fn of(&self, value: Value) -> &[(Value, Use)] {
        let first = self.0.partition_point(|&(v, _)| v < value);
        let last = self.0.partition_point(|&(v, _)| v <= value);
        self.0.get(first..last).unwrap_or_default()
    }

    /// What constant address `value` of `function`, made by the
    /// instruction at `from`, is taken as, by its uses and those of the
    /// block parameters and copies (the same constant computed from it, as
    /// plus 0) it is passed to (by `constants`): read, written, address
    /// taken. A value computed into another constant within its
    /// instruction is not a use: the other is the reference if it is an
    /// address (and the checks L0 makes of an address, whether it is
    /// canonical, are none). One `formed` (not an immediate: `adrp`'s page
    /// is one) and computed into another constant by a later instruction
    /// (an offset to a field, a comparison) is an address taken, as is one
    /// packed into a vector.
    fn kinds(
        &self,
        function: &Function,
        constants: &Constants,
        (value, from): (Value, u64),
        formed: bool,
    ) -> Vec<Kind> {
        let constant = constants.constant(value);
        let (mut read, mut write, mut address) = (false, false, false);
        let mut seen = BTreeSet::new();
        let mut pending = vec![(value, from)];
        while let Some((value, at)) = pending.pop() {
            for &(_, kind) in self.of(value) {
                match kind {
                    Use::Pure(result) if constants.constant(result).is_none() => {
                        // Offset by a computed amount: an access there, or
                        // an address.
                        let (mut accessed, mut used) = (false, false);
                        for &(_, kind) in self.of(result) {
                            used = true;
                            match kind {
                                Use::Load => (read, accessed) = (true, true),
                                Use::Store => (write, accessed) = (true, true),
                                Use::Pure(_) | Use::Escape | Use::Parameter(_) => {}
                            }
                        }
                        address |= used && !accessed;
                    }
                    Use::Pure(result) => {
                        let computed = constants.constant(result);
                        let here = defining(function, result).map_or(at, |inst| inst.address);
                        if computed == constant {
                            if seen.insert(result) {
                                pending.push((result, here));
                            }
                        } else if computed.is_some_and(|bits| bits.width() > 64)
                            || (formed && here != at)
                        {
                            // Packed into a vector, to be stored with others;
                            // or formed here and offset or compared later.
                            address = true;
                        }
                    }
                    Use::Load => read = true,
                    Use::Store => write = true,
                    Use::Escape => address = true,
                    Use::Parameter(parameter) => {
                        if seen.insert(parameter) {
                            pending.push((parameter, at));
                        }
                    }
                }
            }
        }
        [
            (read, Kind::Read),
            (write, Kind::Write),
            (address, Kind::Address),
        ]
        .into_iter()
        .filter_map(|(found, kind)| found.then_some(kind))
        .collect()
    }
}
