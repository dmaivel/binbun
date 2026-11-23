//! Checking a [`Function`] against L1's rules:
//!
//! - Block 0 is the entry: a parameter per register (of its width) and then
//!   the memory, only constants and undefined values among its
//!   instructions, and nothing jumps to it.
//! - Every value is defined exactly once, where its
//!   [`ValueInfo`](crate::ir::ValueInfo) says, with a width L0 allows.
//! - Every use is of a value whose definition dominates it: a block
//!   parameter is defined at the block's start, an instruction's results
//!   after it, and jump arguments are used at the end of the block jumping.
//!   Uses in blocks the entry does not reach are not checked for
//!   dominance.
//! - A [`Terminator::Invoke`] ends a block whose last instruction is a
//!   call; the block it unwinds to starts with an [`Op::Landing`], and
//!   only invokes' unwind edges go to a block starting with one. The
//!   call's results exist only on the way it returns: they are used only
//!   where its `normal` target dominates, never on the unwind edge.
//! - Operands, results, branch conditions, jump arguments and exit states
//!   have the types their operations and targets call for (L0's rules for
//!   the pure operations).
//! - No block is still [`Terminator::Open`].
//!
//! Errors name the block (`b3 @0x401000`, its number and address) and, for
//! an instruction, the instruction's address (`b3 0x401004`).

use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt;

use binbun_semantics::bits::MAX_WIDTH;
use binbun_semantics::ir::{Binary, Declarations, IntrinsicId, RegisterId, Unary};
use binbun_semantics::verify::{float_width, lanes_width};

use crate::graph::Dominators;
use crate::ir::{Block, BlockId, Definition, Function, Inst, Op, Target, Terminator, Type, Value};

/// A broken rule, with where it is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifyError(pub String);

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Checks `function` against L1's rules, with the registers and intrinsics
/// of `declarations`.
///
/// # Errors
///
/// The first broken rule found, with its block and, for an instruction,
/// the instruction's address.
pub fn verify(function: &Function, declarations: &Declarations) -> Result<(), VerifyError> {
    let sites = definitions(function)?;
    entry(function, declarations)?;
    let checker = Checker {
        function,
        declarations,
        sites,
        dominators: Dominators::new(function),
    };
    function
        .blocks
        .iter()
        .enumerate()
        .try_for_each(|(index, block)| checker.block(index, block))
}

/// Where a value is defined or used: a block, and a position in it (0 for
/// its parameters, `k + 1` for its instruction `k`, one past the last
/// instruction for its terminator).
#[derive(Clone, Copy, Debug)]
struct Site {
    block: usize,
    position: usize,
}

/// `index` as a `u32` id.
fn number(index: usize) -> u32 {
    u32::try_from(index).unwrap_or(u32::MAX)
}

/// A type, for messages.
fn kind(ty: Type) -> String {
    match ty {
        Type::Bits(width) => format!("{width} bits"),
        Type::Memory => String::from("memory"),
    }
}

/// A list of types, for messages.
fn kinds(types: &[Type]) -> String {
    let list: Vec<String> = types.iter().map(|&ty| kind(ty)).collect();
    format!("({})", list.join(", "))
}

/// A definition, for messages.
fn describe(definition: Definition) -> String {
    match definition {
        Definition::Parameter { block, index } => format!("parameter {index} of b{}", block.0),
        Definition::Result { inst, index } => format!("result {index} of i{}", inst.0),
    }
}

/// Where each value is defined, checking that each is defined exactly
/// once, where its `ValueInfo` says, with a width L0 allows.
fn definitions(function: &Function) -> Result<Vec<Option<Site>>, VerifyError> {
    let mut sites = vec![None; function.values.len()];
    for (index, block) in function.blocks.iter().enumerate() {
        let at = |e: String| VerifyError(format!("b{index} @{:#x}: {e}", block.address));
        let id = BlockId(number(index));
        for (position, &parameter) in block.parameters.iter().enumerate() {
            let definition = Definition::Parameter {
                block: id,
                index: number(position),
            };
            let site = Site {
                block: index,
                position: 0,
            };
            define(function, &mut sites, parameter, definition, site).map_err(at)?;
        }
        for (position, &inst) in block.insts.iter().enumerate() {
            let Some(instruction) = function.inst(inst) else {
                return Err(at(format!("no instruction i{}", inst.0)));
            };
            let site = Site {
                block: index,
                position: position + 1,
            };
            for (result, &value) in instruction.results.iter().enumerate() {
                let definition = Definition::Result {
                    inst,
                    index: number(result),
                };
                define(function, &mut sites, value, definition, site).map_err(|e| {
                    VerifyError(format!("b{index} {:#x}: {e}", instruction.address))
                })?;
            }
        }
    }
    match sites.iter().position(Option::is_none) {
        Some(value) => Err(VerifyError(format!("v{value} is never defined"))),
        None => Ok(sites),
    }
}

/// Records that `value` is defined at `site`, by `definition`.
fn define(
    function: &Function,
    sites: &mut [Option<Site>],
    value: Value,
    definition: Definition,
    site: Site,
) -> Result<(), String> {
    let info = function
        .value(value)
        .ok_or_else(|| format!("v{} does not exist", value.0))?;
    if info.definition != definition {
        return Err(format!(
            "v{} is {}, but recorded as {}",
            value.0,
            describe(definition),
            describe(info.definition)
        ));
    }
    if let Type::Bits(width) = info.ty
        && (width == 0 || width > MAX_WIDTH)
    {
        return Err(format!("v{} has width {width}", value.0));
    }
    let slot = sites
        .get_mut(value.0 as usize)
        .ok_or_else(|| format!("v{} does not exist", value.0))?;
    if slot.is_some() {
        return Err(format!("v{} is defined twice", value.0));
    }
    *slot = Some(site);
    Ok(())
}

/// Checks the entry block's parameters and instructions, and that nothing
/// jumps to it.
fn entry(function: &Function, declarations: &Declarations) -> Result<(), VerifyError> {
    let Some(block) = function.blocks.first() else {
        return Err(VerifyError("no entry block".into()));
    };
    let at = |e: String| VerifyError(format!("b0 @{:#x}: {e}", block.address));
    let registers = declarations.registers;
    if block.parameters.len() != registers.len() + 1 {
        return Err(at(format!(
            "{} parameters, not one per register and the memory ({})",
            block.parameters.len(),
            registers.len() + 1
        )));
    }
    let expected = registers
        .iter()
        .map(|register| Type::Bits(register.width))
        .chain([Type::Memory]);
    for ((position, &parameter), ty) in block.parameters.iter().enumerate().zip(expected) {
        let actual = function.ty(parameter);
        if actual != Some(ty) {
            return Err(at(format!(
                "parameter {position} (v{}) is {}, not {}",
                parameter.0,
                actual.map_or_else(|| String::from("nothing"), kind),
                kind(ty)
            )));
        }
    }
    for &inst in &block.insts {
        let Some(instruction) = function.inst(inst) else {
            return Err(at(format!("no instruction i{}", inst.0)));
        };
        match &instruction.op {
            Op::Const(_) | Op::Undefined(..) => {}
            Op::Unary(..)
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
            | Op::Call { .. }
            | Op::SystemCall { .. }
            | Op::Landing { .. } => {
                return Err(VerifyError(format!(
                    "b0 {:#x}: the entry block holds an instruction other than a constant or an undefined value",
                    instruction.address
                )));
            }
        }
    }
    for (index, other) in function.blocks.iter().enumerate() {
        if other
            .terminator
            .targets()
            .any(|target| target.block == BlockId(0))
        {
            return Err(VerifyError(format!(
                "b{index} @{:#x}: jumps to the entry block",
                other.address
            )));
        }
    }
    landings(function)?;
    Ok(())
}

/// Checks that every block an invoke unwinds to starts with a landing,
/// that only invokes' unwind edges go to such a block, and that a landing
/// is only ever the first instruction of its block.
fn landings(function: &Function) -> Result<(), VerifyError> {
    let starts_landing = |block: BlockId| {
        function
            .block(block)
            .and_then(|b| b.insts.first())
            .and_then(|&inst| function.inst(inst))
            .is_some_and(|i| matches!(i.op, Op::Landing { .. }))
    };
    for (index, block) in function.blocks.iter().enumerate() {
        let at = |e: &str| VerifyError(format!("b{index} @{:#x}: {e}", block.address));
        for (position, &inst) in block.insts.iter().enumerate() {
            let landing = function
                .inst(inst)
                .is_some_and(|i| matches!(i.op, Op::Landing { .. }));
            if landing && position > 0 {
                return Err(at("a landing is not the block's first instruction"));
            }
        }
        if let Terminator::Invoke { normal, unwind } = &block.terminator {
            let call = block
                .insts
                .last()
                .and_then(|&inst| function.inst(inst))
                .is_some_and(|i| matches!(i.op, Op::Call { .. }));
            if !call {
                return Err(at("an invoke whose block does not end in a call"));
            }
            if !starts_landing(unwind.block) {
                return Err(at("an invoke unwinds to a block without a landing"));
            }
            if starts_landing(normal.block) {
                return Err(at("an invoke returns to a landing"));
            }
        } else if block
            .terminator
            .targets()
            .any(|target| starts_landing(target.block))
        {
            return Err(at("a jump to a landing other than an invoke's unwind edge"));
        }
    }
    Ok(())
}

/// The width of `op` applied to an `a`-bit operand (L0's rule).
fn unary_width(op: Unary, a: u16) -> Result<u16, String> {
    match op {
        Unary::EvenParity8 => Ok(1),
        Unary::ByteSwap if !a.is_multiple_of(8) => Err(format!("byte swap of {a} bits")),
        Unary::ByteSwap
        | Unary::Not
        | Unary::Neg
        | Unary::Popcount
        | Unary::LeadingZeros
        | Unary::TrailingZeros => Ok(a),
    }
}

/// The width of `op` applied to `a`- and `b`-bit operands (L0's rule).
fn binary_width(op: Binary, a: u16, b: u16) -> Result<u16, String> {
    if a != b {
        return Err(format!("{op:?} of {a}- and {b}-bit operands"));
    }
    match op {
        Binary::Eq | Binary::Ne | Binary::ULt | Binary::ULe | Binary::SLt | Binary::SLe => Ok(1),
        Binary::Mul | Binary::UDiv | Binary::URem | Binary::SDiv | Binary::SRem if a > 128 => {
            Err(format!("{op:?} of {a}-bit operands (at most 128)"))
        }
        Binary::Mul
        | Binary::UDiv
        | Binary::URem
        | Binary::SDiv
        | Binary::SRem
        | Binary::Add
        | Binary::Sub
        | Binary::And
        | Binary::Or
        | Binary::Xor
        | Binary::Shl
        | Binary::LShr
        | Binary::AShr
        | Binary::Rol
        | Binary::Ror => Ok(a),
    }
}

/// Checks uses and types, once definitions and the entry are known good.
struct Checker<'a> {
    function: &'a Function,
    declarations: &'a Declarations,
    /// Where each value is defined.
    sites: Vec<Option<Site>>,
    dominators: Dominators,
}

impl Checker<'_> {
    fn block(&self, index: usize, block: &Block) -> Result<(), VerifyError> {
        for (position, &inst) in block.insts.iter().enumerate() {
            let Some(instruction) = self.function.inst(inst) else {
                return Err(VerifyError(format!(
                    "b{index} @{:#x}: no instruction i{}",
                    block.address, inst.0
                )));
            };
            let site = Site {
                block: index,
                position: position + 1,
            };
            self.inst(instruction, site)
                .map_err(|e| VerifyError(format!("b{index} {:#x}: {e}", instruction.address)))?;
        }
        let site = Site {
            block: index,
            position: block.insts.len() + 1,
        };
        self.terminator(&block.terminator, site)
            .map_err(|e| VerifyError(format!("b{index} @{:#x}: {e}", block.address)))
    }

    fn inst(&self, inst: &Inst, site: Site) -> Result<(), String> {
        let actual = inst
            .results
            .iter()
            .map(|&result| self.ty(result))
            .collect::<Result<Vec<Type>, String>>()?;
        let expected = self.op(&inst.op, &actual, site)?;
        if actual == expected {
            Ok(())
        } else {
            Err(format!(
                "results {}, but the operation gives {}",
                kinds(&actual),
                kinds(&expected)
            ))
        }
    }

    /// `value`'s type.
    fn ty(&self, value: Value) -> Result<Type, String> {
        self.function
            .ty(value)
            .ok_or_else(|| format!("v{} does not exist", value.0))
    }

    /// Checks that `value`'s definition dominates its use at `site` (in a
    /// block the entry reaches); returns its type.
    fn operand(&self, value: Value, site: Site) -> Result<Type, String> {
        let ty = self.ty(value)?;
        if !self.dominators.reachable(BlockId(number(site.block))) {
            return Ok(ty);
        }
        let definition = self
            .sites
            .get(value.0 as usize)
            .copied()
            .flatten()
            .ok_or_else(|| format!("v{} is never defined", value.0))?;
        let dominates = if definition.block == site.block {
            definition.position < site.position
        } else {
            self.dominators.dominates(
                BlockId(number(definition.block)),
                BlockId(number(site.block)),
            ) && self.returned(definition, site)
        };
        if dominates {
            Ok(ty)
        } else {
            Err(format!(
                "v{} is used where its definition (in b{}) does not dominate",
                value.0, definition.block
            ))
        }
    }

    /// Whether a use at `site`, in another block than `definition`, sees
    /// the value on every path: a result of the call ending an invoke's
    /// block exists only where the invoke's `normal` target dominates.
    fn returned(&self, definition: Site, site: Site) -> bool {
        let Some(block) = self.function.blocks.get(definition.block) else {
            return true;
        };
        match &block.terminator {
            Terminator::Invoke { normal, .. } if definition.position == block.insts.len() => self
                .dominators
                .dominates(normal.block, BlockId(number(site.block))),
            Terminator::Jump(_)
            | Terminator::Branch { .. }
            | Terminator::Invoke { .. }
            | Terminator::IndirectJump { .. }
            | Terminator::Return { .. }
            | Terminator::Leave { .. }
            | Terminator::Trap(_)
            | Terminator::Stop
            | Terminator::Open => true,
        }
    }

    /// The width of bit vector `value`, used at `site`.
    fn bits(&self, value: Value, site: Site) -> Result<u16, String> {
        match self.operand(value, site)? {
            Type::Bits(width) => Ok(width),
            Type::Memory => Err(format!("v{} is memory, not a bit vector", value.0)),
        }
    }

    /// Checks that `value`, used at `site`, is memory.
    fn memory(&self, value: Value, site: Site) -> Result<(), String> {
        match self.operand(value, site)? {
            Type::Memory => Ok(()),
            Type::Bits(width) => Err(format!("v{} is {width} bits, not memory", value.0)),
        }
    }

    /// The result types of `op` at `site` (`results`, the instruction's
    /// own, for the width of an undefined value).
    fn op(&self, op: &Op, results: &[Type], site: Site) -> Result<Vec<Type>, String> {
        let width = match op {
            Op::Const(constant) => constant.width(),
            Op::Undefined(_, inputs) => {
                for &input in inputs {
                    self.bits(input, site)?;
                }
                let [Type::Bits(width)] = results else {
                    return Err("an undefined value is one bit vector".into());
                };
                *width
            }
            Op::Unary(..)
            | Op::Binary(..)
            | Op::Flag(..)
            | Op::Extract { .. }
            | Op::Concat { .. }
            | Op::Extend { .. }
            | Op::Select { .. }
            | Op::Lanes { .. }
            | Op::Float { .. } => self.pure(op, site)?,
            Op::Load {
                memory,
                address,
                bytes,
                ..
            } => {
                self.memory(*memory, site)?;
                self.bits(*address, site)?;
                if *bytes == 0 {
                    return Err("load of 0 bytes".into());
                }
                bytes
                    .checked_mul(8)
                    .ok_or_else(|| format!("load of {bytes} bytes"))?
            }
            Op::Store {
                memory,
                address,
                value,
                ..
            } => {
                self.memory(*memory, site)?;
                self.bits(*address, site)?;
                let width = self.bits(*value, site)?;
                if !width.is_multiple_of(8) {
                    return Err(format!("store of {width} bits, not whole bytes"));
                }
                return Ok(vec![Type::Memory]);
            }
            Op::Intrinsic {
                intrinsic,
                memory,
                inputs,
            } => return self.intrinsic(*intrinsic, *memory, inputs, results, site),
            Op::Call {
                target,
                return_address,
                memory,
                registers,
                changes,
            } => {
                self.bits(*target, site)?;
                self.bits(*return_address, site)?;
                return self.call(*memory, registers, changes, site);
            }
            Op::SystemCall {
                memory,
                registers,
                changes,
            } => return self.call(*memory, registers, changes, site),
            Op::Landing { memory, receives } => {
                self.memory(*memory, site)?;
                let mut types = vec![Type::Memory];
                for &register in receives {
                    let info = self
                        .declarations
                        .info(register)
                        .ok_or_else(|| format!("no register {}", register.0))?;
                    types.push(Type::Bits(info.width));
                }
                return Ok(types);
            }
        };
        Ok(vec![Type::Bits(width)])
    }

    /// The result width of pure operation `op` at `site`.
    fn pure(&self, op: &Op, site: Site) -> Result<u16, String> {
        let bits = |value: Value| self.bits(value, site);
        match op {
            Op::Unary(operation, a) => unary_width(*operation, bits(*a)?),
            Op::Binary(operation, a, b) => binary_width(*operation, bits(*a)?, bits(*b)?),
            Op::Flag(operation, a, b, c) => {
                let (a, b, c) = (bits(*a)?, bits(*b)?, bits(*c)?);
                if a == b && a == c {
                    Ok(1)
                } else {
                    Err(format!("{operation:?} of {a}-, {b}- and {c}-bit operands"))
                }
            }
            Op::Extract {
                value,
                offset,
                width,
            } => {
                let source = bits(*value)?;
                if *width == 0 || u32::from(*offset) + u32::from(*width) > u32::from(source) {
                    return Err(format!(
                        "bits {offset}..{} of a {source}-bit value",
                        u32::from(*offset) + u32::from(*width)
                    ));
                }
                Ok(*width)
            }
            Op::Concat { high, low } => {
                let sum = u32::from(bits(*high)?) + u32::from(bits(*low)?);
                u16::try_from(sum).map_err(|_| String::from("concatenation too wide"))
            }
            Op::Extend { value, width, .. } => {
                let source = bits(*value)?;
                if *width < source {
                    return Err(format!("extension of {source} bits to {width}"));
                }
                Ok(*width)
            }
            Op::Select {
                condition,
                then,
                otherwise,
            } => {
                if bits(*condition)? != 1 {
                    return Err(format!("select condition v{} is not 1 bit", condition.0));
                }
                let (then, otherwise) = (bits(*then)?, bits(*otherwise)?);
                if then == otherwise {
                    Ok(then)
                } else {
                    Err(format!("select of {then}- and {otherwise}-bit values"))
                }
            }
            Op::Lanes {
                lanes,
                op,
                operands,
            } => {
                let widths = operands
                    .iter()
                    .take(op.arity())
                    .map(|&a| bits(a))
                    .collect::<Result<Vec<u16>, String>>()?;
                lanes_width(*op, *lanes, &widths)
            }
            Op::Float {
                op,
                format,
                lanes,
                output,
                rounding,
                operands,
            } => {
                let widths = operands
                    .iter()
                    .take(op.arity())
                    .map(|&a| bits(a))
                    .collect::<Result<Vec<u16>, String>>()?;
                float_width(*op, *format, *lanes, *output, bits(*rounding)?, &widths)
            }
            Op::Const(_)
            | Op::Undefined(..)
            | Op::Load { .. }
            | Op::Store { .. }
            | Op::Intrinsic { .. }
            | Op::Call { .. }
            | Op::SystemCall { .. }
            | Op::Landing { .. } => Err("not a pure operation".into()),
        }
    }

    /// The result types of intrinsic `intrinsic` of `memory` and `inputs`
    /// at `site`: its outputs, then the memory. An opaque one's are its own
    /// (`results`): bit vectors, then the memory.
    fn intrinsic(
        &self,
        intrinsic: IntrinsicId,
        memory: Value,
        inputs: &[Value],
        results: &[Type],
        site: Site,
    ) -> Result<Vec<Type>, String> {
        let info = self
            .declarations
            .intrinsic(intrinsic)
            .ok_or_else(|| format!("no intrinsic {}", intrinsic.0))?;
        self.memory(memory, site)?;
        if info.opaque {
            for &input in inputs {
                self.bits(input, site)?;
            }
            let Some((Type::Memory, outputs)) = results.split_last() else {
                return Err(format!("{} does not give the memory last", info.name));
            };
            if let Some(memory) = outputs.iter().position(|ty| *ty == Type::Memory) {
                return Err(format!("{} output {memory} is memory", info.name));
            }
            return Ok(results.to_vec());
        }
        if inputs.len() != info.inputs.len() {
            return Err(format!(
                "{} inputs to {}, which takes {}",
                inputs.len(),
                info.name,
                info.inputs.len()
            ));
        }
        for (&input, &width) in inputs.iter().zip(info.inputs) {
            let actual = self.bits(input, site)?;
            if actual != width {
                return Err(format!(
                    "{} input v{} is {actual} bits, not {width}",
                    info.name, input.0
                ));
            }
        }
        Ok(info
            .outputs
            .iter()
            .map(|&width| Type::Bits(width))
            .chain([Type::Memory])
            .collect())
    }

    /// The result types of a call or system call at `site`: the memory,
    /// then each register of `changes`.
    fn call(
        &self,
        memory: Value,
        registers: &[Value],
        changes: &[RegisterId],
        site: Site,
    ) -> Result<Vec<Type>, String> {
        self.memory(memory, site)?;
        self.registers(registers, site)?;
        let mut results = vec![Type::Memory];
        for &register in changes {
            let info = self
                .declarations
                .info(register)
                .ok_or_else(|| format!("no register {}", register.0))?;
            results.push(Type::Bits(info.width));
        }
        Ok(results)
    }

    /// Checks that `values`, used at `site`, are one per register, of its
    /// width.
    fn registers(&self, values: &[Value], site: Site) -> Result<(), String> {
        let registers = self.declarations.registers;
        if values.len() != registers.len() {
            return Err(format!(
                "{} register values for {} registers",
                values.len(),
                registers.len()
            ));
        }
        for (&value, register) in values.iter().zip(registers) {
            let width = self.bits(value, site)?;
            if width != register.width {
                return Err(format!(
                    "{} is {} bits, but v{} is {width}",
                    register.name, register.width, value.0
                ));
            }
        }
        Ok(())
    }

    fn terminator(&self, terminator: &Terminator, site: Site) -> Result<(), String> {
        match terminator {
            Terminator::Jump(target) => self.target(target, site),
            Terminator::Branch {
                condition,
                then,
                otherwise,
            } => {
                let width = self.bits(*condition, site)?;
                if width != 1 {
                    return Err(format!(
                        "branch condition v{} is {width} bits, not 1",
                        condition.0
                    ));
                }
                self.target(then, site)?;
                self.target(otherwise, site)
            }
            Terminator::Invoke { normal, unwind } => {
                self.target(normal, site)?;
                self.target(unwind, site)?;
                // The call's results: its last instruction's.
                let results = self
                    .function
                    .blocks
                    .get(site.block)
                    .and_then(|block| block.insts.last())
                    .and_then(|&inst| self.function.inst(inst))
                    .map_or(&[][..], |inst| inst.results.as_slice());
                match unwind.arguments.iter().find(|a| results.contains(a)) {
                    Some(argument) => Err(format!(
                        "the unwind edge passes v{}, a result of the call",
                        argument.0
                    )),
                    None => Ok(()),
                }
            }
            Terminator::IndirectJump { address, targets } => {
                self.bits(*address, site)?;
                targets
                    .iter()
                    .try_for_each(|target| self.target(target, site))
            }
            Terminator::Return { address, state } | Terminator::Leave { address, state, .. } => {
                self.bits(*address, site)?;
                self.registers(&state.registers, site)?;
                self.memory(state.memory, site)
            }
            Terminator::Trap(_) | Terminator::Stop => Ok(()),
            Terminator::Open => Err("the block is open (not built)".into()),
        }
    }

    /// Checks that `target`'s arguments, used at `site`, match its block's
    /// parameters.
    fn target(&self, target: &Target, site: Site) -> Result<(), String> {
        let block = self
            .function
            .block(target.block)
            .ok_or_else(|| format!("jump to b{}, which does not exist", target.block.0))?;
        if target.arguments.len() != block.parameters.len() {
            return Err(format!(
                "{} arguments to b{}, which has {} parameters",
                target.arguments.len(),
                target.block.0,
                block.parameters.len()
            ));
        }
        for (position, (&argument, &parameter)) in
            target.arguments.iter().zip(&block.parameters).enumerate()
        {
            let actual = self.operand(argument, site)?;
            let expected = self.ty(parameter)?;
            if actual != expected {
                return Err(format!(
                    "argument {position} to b{} (v{}) is {}, but the parameter is {}",
                    target.block.0,
                    argument.0,
                    kind(actual),
                    kind(expected)
                ));
            }
        }
        Ok(())
    }
}
