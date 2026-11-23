//! L1's text form, for reading: [`print`].
//!
//! ```text
//! function 0x401000
//! b0 @0x401000 (v0:64 rax, v1:64 rcx, ..., v25:64 gs_base, v26:mem):
//!   0x401000  v40:8 = undefined
//!   jump b1(v0, v26)
//! b1 @0x401000 (v27:64, v28:mem):
//!   0x401000  v29:64 = const 0x8:64
//!   0x401004  v30:64 = add v27, v29
//!   0x401004  v31:8 = load v28, v30, 1
//!   0x401008  v32:1 = eq v31, v40
//!   branch v32, b2(v30), b3()
//! b2 @0x40100a (v33:64):
//!   0x40100a  v34:mem, v35:64 = call v33, v30, v28 (v0, ..., v25) -> (rax)
//!   return v27 (v35, v1, ..., v25) v34
//! ```
//!
//! - A block's header gives its number, the address it starts at and its
//!   parameters; the entry block's are named after their registers.
//! - A value is `v` and its number; where defined, its type follows: a
//!   width in bits, or `mem` for the memory.
//! - An instruction line gives its machine instruction's address, its
//!   results and its operation; a block's last line is its terminator.
//! - Constants are hexadecimal with their width (`0x8:64`).
//! - An undefined value of a site names it and its inputs:
//!   `undefined @shrd.of(v3, v4, v5, ...)`.
//! - Operations: L0's names for the pure ones (`add`, `add-carry`, `zext`,
//!   ...), `extract value, offset, width`, `load memory, address, bytes`,
//!   `store memory, address, value` (either with `atomic n` after it),
//!   `intrinsic name memory (inputs)`, `call target, return address,
//!   memory (registers) -> (changed registers)`, `syscall memory
//!   (registers) -> (changed registers)`.
//! - Terminators: `jump b(arguments)`, `branch condition, b(...), b(...)`,
//!   `indirect-jump address [b(...), ...]`, `return address (registers)
//!   memory`, `leave address (registers) memory`, `trap kind`, `stop`,
//!   `open`.
//! - Register lists are in register order.

use alloc::string::String;
use core::fmt::{self, Write};

use binbun_semantics::ir::{
    Binary, Declarations, Flag, FloatOp, FloatOutput, Format, LaneOp, RegisterId, Unary,
};
use binbun_semantics::text::trap_name;

use crate::ir::{Block, Function, Inst, Op, State, Target, Terminator, Type, Unknown, Value};

/// The text of `function`, with register and intrinsic names from
/// `declarations`.
pub fn print(function: &Function, declarations: &Declarations) -> String {
    let mut out = String::new();
    // Writing to a `String` cannot fail.
    let _ = Printer {
        out: &mut out,
        function,
        declarations,
    }
    .function();
    out
}

fn unary(op: Unary) -> &'static str {
    match op {
        Unary::Not => "not",
        Unary::Neg => "neg",
        Unary::Popcount => "popcount",
        Unary::LeadingZeros => "leading-zeros",
        Unary::TrailingZeros => "trailing-zeros",
        Unary::ByteSwap => "byte-swap",
        Unary::EvenParity8 => "even-parity8",
    }
}

fn binary(op: Binary) -> &'static str {
    match op {
        Binary::Add => "add",
        Binary::Sub => "sub",
        Binary::Mul => "mul",
        Binary::UDiv => "udiv",
        Binary::URem => "urem",
        Binary::SDiv => "sdiv",
        Binary::SRem => "srem",
        Binary::And => "and",
        Binary::Or => "or",
        Binary::Xor => "xor",
        Binary::Shl => "shl",
        Binary::LShr => "lshr",
        Binary::AShr => "ashr",
        Binary::Rol => "rol",
        Binary::Ror => "ror",
        Binary::Eq => "eq",
        Binary::Ne => "ne",
        Binary::ULt => "ult",
        Binary::ULe => "ule",
        Binary::SLt => "slt",
        Binary::SLe => "sle",
    }
}

fn flag(op: Flag) -> &'static str {
    match op {
        Flag::AddCarry => "add-carry",
        Flag::AddOverflow => "add-overflow",
        Flag::SubBorrow => "sub-borrow",
        Flag::SubOverflow => "sub-overflow",
        Flag::NibbleCarry => "nibble-carry",
    }
}

fn format(format: Format) -> &'static str {
    match format {
        Format::Half => "half",
        Format::Single => "single",
        Format::Double => "double",
        Format::Extended => "extended",
    }
}

/// `add`, `convert-double`, `to-sint-32`, ...
fn float(op: FloatOp) -> String {
    match op {
        FloatOp::Add => "add".into(),
        FloatOp::Sub => "sub".into(),
        FloatOp::Mul => "mul".into(),
        FloatOp::Div => "div".into(),
        FloatOp::Sqrt => "sqrt".into(),
        FloatOp::MulAdd => "mul-add".into(),
        FloatOp::RoundToIntegral => "round-to-integral".into(),
        FloatOp::Compare { signaling: false } => "compare-quiet".into(),
        FloatOp::Compare { signaling: true } => "compare-signaling".into(),
        FloatOp::Convert(target) => alloc::format!("convert-{}", format(target)),
        FloatOp::FromInt { signed } => {
            alloc::format!("from-{}int", if signed { "s" } else { "u" })
        }
        FloatOp::ToInt { signed, width } => {
            alloc::format!("to-{}int-{width}", if signed { "s" } else { "u" })
        }
    }
}

/// Values, separated by commas.
struct Values<'a>(&'a [Value]);

impl fmt::Display for Values<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (position, value) in self.0.iter().enumerate() {
            if position > 0 {
                f.write_str(", ")?;
            }
            write!(f, "v{}", value.0)?;
        }
        Ok(())
    }
}

/// A value and its type (`?` for a value the function does not have).
struct Typed<'a>(&'a Function, Value);

impl fmt::Display for Typed<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "v{}:", self.1.0)?;
        match self.0.ty(self.1) {
            Some(Type::Bits(width)) => write!(f, "{width}"),
            Some(Type::Memory) => f.write_str("mem"),
            None => f.write_str("?"),
        }
    }
}

/// Register names, separated by commas (`?` for one not declared).
struct Registers<'a>(&'a Declarations, &'a [RegisterId]);

impl fmt::Display for Registers<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (position, &register) in self.1.iter().enumerate() {
            if position > 0 {
                f.write_str(", ")?;
            }
            f.write_str(self.0.info(register).map_or("?", |info| info.name))?;
        }
        Ok(())
    }
}

/// A jump to a block: `b1(v2, v3)`.
struct Jump<'a>(&'a Target);

impl fmt::Display for Jump<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "b{}({})", self.0.block.0, Values(&self.0.arguments))
    }
}

/// An exit state: `(registers) memory`.
struct Exit<'a>(&'a State);

impl fmt::Display for Exit<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "({}) v{}", Values(&self.0.registers), self.0.memory.0)
    }
}

/// ` atomic n` for an access in atomic group `n`.
struct Atomic(Option<u32>);

impl fmt::Display for Atomic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Some(group) => write!(f, " atomic {group}"),
            None => Ok(()),
        }
    }
}

struct Printer<'a> {
    out: &'a mut String,
    function: &'a Function,
    declarations: &'a Declarations,
}

impl Printer<'_> {
    fn function(&mut self) -> fmt::Result {
        let function = self.function;
        writeln!(self.out, "function {:#x}", function.entry)?;
        for (index, block) in function.blocks.iter().enumerate() {
            self.block(index, block)?;
        }
        Ok(())
    }

    fn block(&mut self, index: usize, block: &Block) -> fmt::Result {
        let function = self.function;
        write!(self.out, "b{index} @{:#x} (", block.address)?;
        for (position, &parameter) in block.parameters.iter().enumerate() {
            if position > 0 {
                self.out.push_str(", ");
            }
            write!(self.out, "{}", Typed(function, parameter))?;
            if index == 0
                && let Some(register) = self.declarations.registers.get(position)
            {
                write!(self.out, " {}", register.name)?;
            }
        }
        self.out.push_str("):\n");
        for &inst in &block.insts {
            match function.inst(inst) {
                Some(instruction) => self.inst(instruction)?,
                None => writeln!(self.out, "  i{} ?", inst.0)?,
            }
        }
        self.out.push_str("  ");
        self.terminator(&block.terminator)?;
        self.out.push('\n');
        Ok(())
    }

    fn inst(&mut self, inst: &Inst) -> fmt::Result {
        write!(self.out, "  {:#x}  ", inst.address)?;
        for (position, &result) in inst.results.iter().enumerate() {
            if position > 0 {
                self.out.push_str(", ");
            }
            write!(self.out, "{}", Typed(self.function, result))?;
        }
        if !inst.results.is_empty() {
            self.out.push_str(" = ");
        }
        self.op(&inst.op)?;
        self.out.push('\n');
        Ok(())
    }

    fn op(&mut self, op: &Op) -> fmt::Result {
        let declarations = self.declarations;
        let out = &mut *self.out;
        match op {
            Op::Const(bits) => write!(out, "const {bits}:{}", bits.width()),
            Op::Undefined(unknown, inputs) => {
                out.write_str("undefined")?;
                if let Unknown::Architecture {
                    site: Some(site), ..
                } = unknown
                {
                    match declarations.site(*site) {
                        Some(info) => write!(out, " @{}(", info.name)?,
                        None => write!(out, " @{}(", site.0)?,
                    }
                    for (i, input) in inputs.iter().enumerate() {
                        let comma = if i == 0 { "" } else { ", " };
                        write!(out, "{comma}v{}", input.0)?;
                    }
                    out.write_str(")")?;
                }
                Ok(())
            }
            Op::Unary(operation, a) => write!(out, "{} v{}", unary(*operation), a.0),
            Op::Binary(operation, a, b) => {
                write!(out, "{} v{}, v{}", binary(*operation), a.0, b.0)
            }
            Op::Flag(operation, a, b, c) => {
                write!(out, "{} v{}, v{}, v{}", flag(*operation), a.0, b.0, c.0)
            }
            Op::Extract {
                value,
                offset,
                width,
            } => write!(out, "extract v{}, {offset}, {width}", value.0),
            Op::Concat { high, low } => write!(out, "concat v{}, v{}", high.0, low.0),
            Op::Extend { signed, value, .. } => {
                let name = if *signed { "sext" } else { "zext" };
                write!(out, "{name} v{}", value.0)
            }
            Op::Select {
                condition,
                then,
                otherwise,
            } => write!(
                out,
                "select v{}, v{}, v{}",
                condition.0, then.0, otherwise.0
            ),
            Op::Lanes { .. } | Op::Float { .. } => self.vector(op),
            Op::Load {
                memory,
                address,
                bytes,
                atomic,
            } => write!(
                out,
                "load v{}, v{}, {bytes}{}",
                memory.0,
                address.0,
                Atomic(*atomic)
            ),
            Op::Store {
                memory,
                address,
                value,
                atomic,
            } => write!(
                out,
                "store v{}, v{}, v{}{}",
                memory.0,
                address.0,
                value.0,
                Atomic(*atomic)
            ),
            Op::Intrinsic { .. } | Op::Call { .. } | Op::SystemCall { .. } | Op::Landing { .. } => {
                self.effect(op)
            }
        }
    }

    /// A lane-wise or floating-point operation.
    fn vector(&mut self, op: &Op) -> fmt::Result {
        let out = &mut *self.out;
        match op {
            Op::Lanes {
                lanes,
                op,
                operands: [a, b, c],
            } => match op {
                LaneOp::Unary(operation) => {
                    write!(out, "lanes.{lanes} {} v{}", unary(*operation), a.0)
                }
                LaneOp::Binary(operation) => {
                    write!(
                        out,
                        "lanes.{lanes} {} v{}, v{}",
                        binary(*operation),
                        a.0,
                        b.0
                    )
                }
                LaneOp::Extract { offset, width } => {
                    write!(out, "lanes.{lanes} extract v{}, {offset}, {width}", a.0)
                }
                LaneOp::Extend { signed, .. } => {
                    let name = if *signed { "sext" } else { "zext" };
                    write!(out, "lanes.{lanes} {name} v{}", a.0)
                }
                LaneOp::Select => {
                    write!(out, "lanes.{lanes} select v{}, v{}, v{}", a.0, b.0, c.0)
                }
            },
            Op::Float {
                op,
                format: kind,
                lanes,
                output,
                rounding,
                operands,
            } => {
                let what = match output {
                    FloatOutput::Value => "float",
                    FloatOutput::Status => "float-status",
                };
                write!(
                    out,
                    "{what}.{lanes} {} {} v{}",
                    float(*op),
                    format(*kind),
                    rounding.0
                )?;
                for operand in operands.iter().take(op.arity()) {
                    write!(out, ", v{}", operand.0)?;
                }
                Ok(())
            }
            Op::Const(_)
            | Op::Undefined(..)
            | Op::Unary(..)
            | Op::Binary(..)
            | Op::Flag(..)
            | Op::Extract { .. }
            | Op::Concat { .. }
            | Op::Extend { .. }
            | Op::Select { .. }
            | Op::Load { .. }
            | Op::Store { .. }
            | Op::Intrinsic { .. }
            | Op::Call { .. }
            | Op::SystemCall { .. }
            | Op::Landing { .. } => out.write_str("?"),
        }
    }

    /// An intrinsic, call, system call or landing.
    fn effect(&mut self, op: &Op) -> fmt::Result {
        let declarations = self.declarations;
        let out = &mut *self.out;
        match op {
            Op::Intrinsic {
                intrinsic,
                memory,
                inputs,
            } => {
                let name = declarations
                    .intrinsic(*intrinsic)
                    .map_or("?", |info| info.name);
                write!(out, "intrinsic {name} v{} ({})", memory.0, Values(inputs))
            }
            Op::Call {
                target,
                return_address,
                memory,
                registers,
                changes,
            } => write!(
                out,
                "call v{}, v{}, v{} ({}) -> ({})",
                target.0,
                return_address.0,
                memory.0,
                Values(registers),
                Registers(declarations, changes)
            ),
            Op::SystemCall {
                memory,
                registers,
                changes,
            } => write!(
                out,
                "syscall v{} ({}) -> ({})",
                memory.0,
                Values(registers),
                Registers(declarations, changes)
            ),
            Op::Landing { memory, receives } => write!(
                out,
                "landing v{} -> ({})",
                memory.0,
                Registers(declarations, receives)
            ),
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
            | Op::Store { .. } => self.op(op),
        }
    }

    fn terminator(&mut self, terminator: &Terminator) -> fmt::Result {
        let out = &mut *self.out;
        match terminator {
            Terminator::Jump(target) => write!(out, "jump {}", Jump(target)),
            Terminator::Branch {
                condition,
                then,
                otherwise,
            } => write!(
                out,
                "branch v{}, {}, {}",
                condition.0,
                Jump(then),
                Jump(otherwise)
            ),
            Terminator::Invoke { normal, unwind } => {
                write!(out, "invoke {}, unwind {}", Jump(normal), Jump(unwind))
            }
            Terminator::IndirectJump { address, targets } => {
                write!(out, "indirect-jump v{} [", address.0)?;
                for (position, target) in targets.iter().enumerate() {
                    if position > 0 {
                        out.push_str(", ");
                    }
                    write!(out, "{}", Jump(target))?;
                }
                out.write_str("]")
            }
            Terminator::Return { address, state } => {
                write!(out, "return v{} {}", address.0, Exit(state))
            }
            Terminator::Leave {
                address,
                state,
                returns,
            } => {
                let never = if *returns { "" } else { " noreturn" };
                write!(out, "leave{never} v{} {}", address.0, Exit(state))
            }
            Terminator::Trap(kind) => write!(out, "trap {}", trap_name(*kind)),
            Terminator::Stop => out.write_str("stop"),
            Terminator::Open => out.write_str("open"),
        }
    }
}
