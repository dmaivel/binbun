//! The decoders being compared: the x86-64 ones here, the AArch64 ones in
//! [`aarch64`]; Capstone and LLVM serve both.

mod aarch64;

use std::hint::black_box;

use crate::{Arch, Sweep, Task};

/// A decoder under test.
pub trait Contender {
    fn name(&self) -> &'static str;

    /// How the contender performs `task`, or `None` if it cannot.
    fn supports(&self, task: Task) -> Option<&'static str>;

    /// Linearly sweeps `code` mapped at `address`, skipping one byte
    /// (x86-64) or one 4-byte word (AArch64) at a time where nothing
    /// decodes.
    fn sweep(&mut self, task: Task, code: &[u8], address: u64) -> Sweep;
}

/// Every contender for `arch`.
pub fn all(arch: Arch) -> Vec<Box<dyn Contender>> {
    match arch {
        Arch::X86_64 => x86_64(),
        Arch::Aarch64 => aarch64::all(),
    }
}

fn x86_64() -> Vec<Box<dyn Contender>> {
    #[cfg_attr(
        not(any(xed, llvm)),
        expect(unused_mut, reason = "pushed to only when linked")
    )]
    let mut all: Vec<Box<dyn Contender>> = vec![
        Box::new(Binbun::default()),
        Box::new(Iced::new()),
        Box::new(Yaxpeax::new()),
        Box::new(Zydis::new()),
        Box::new(Bddisasm::new()),
        Box::new(Capstone::x86_64()),
    ];
    #[cfg(xed)]
    all.push(Box::new(xed::Xed::new()));
    #[cfg(llvm)]
    if let Some(llvm) = llvm::Llvm::x86_64() {
        all.push(Box::new(llvm));
    }
    all
}

/// binbun's decoder (`binbun-x86`).
#[derive(Default)]
struct Binbun {
    text: String,
}

impl Contender for Binbun {
    fn name(&self) -> &'static str {
        "binbun"
    }

    fn supports(&self, task: Task) -> Option<&'static str> {
        match task {
            Task::Length => Some("decode_length"),
            Task::Flow => Some("decode_flow (length, flow, target, RIP-relative address)"),
            Task::Decode => {
                Some("decode (operand values decoded; `Operand` structs built on demand)")
            }
            Task::Format => Some("decode + intel (XED's Intel syntax)"),
            Task::Valid => None,
        }
    }

    fn sweep(&mut self, task: Task, code: &[u8], address: u64) -> Sweep {
        use std::fmt::Write as _;

        use binbun_x86::{Mode, decode, decode_flow, decode_length};
        match task {
            Task::Length | Task::Valid => sweep_with(code, |rest, _| {
                decode_length(black_box(rest), Mode::Bits64).ok()
            }),
            Task::Flow => sweep_with(code, |rest, offset| {
                decode_flow(black_box(rest), Mode::Bits64, address + offset as u64)
                    .ok()
                    .map(|step| black_box(step).len)
            }),
            Task::Decode => sweep_with(code, |rest, _| {
                decode(black_box(rest), Mode::Bits64)
                    .ok()
                    .map(|i| black_box(i).len())
            }),
            Task::Format => {
                let text = &mut self.text;
                sweep_with(code, |rest, offset| {
                    let instruction = decode(black_box(rest), Mode::Bits64).ok()?;
                    text.clear();
                    write!(text, "{}", instruction.intel(address + offset as u64)).ok()?;
                    black_box(&*text);
                    Some(instruction.len())
                })
            }
        }
    }
}

/// iced-x86: pure Rust.
struct Iced {
    formatter: iced_x86::IntelFormatter,
    text: String,
}

impl Iced {
    fn new() -> Self {
        Self {
            formatter: iced_x86::IntelFormatter::new(),
            text: String::with_capacity(128),
        }
    }
}

impl Contender for Iced {
    fn name(&self) -> &'static str {
        "iced-x86 1.21"
    }

    fn supports(&self, task: Task) -> Option<&'static str> {
        match task {
            Task::Length | Task::Valid => None,
            Task::Flow => Some("decode_out + flow_control + near_branch_target"),
            Task::Decode => Some("Decoder::decode_out"),
            Task::Format => Some("decode_out + IntelFormatter"),
        }
    }

    fn sweep(&mut self, task: Task, code: &[u8], address: u64) -> Sweep {
        use iced_x86::{Decoder, DecoderOptions, Formatter, Instruction};
        let mut decoder = Decoder::with_ip(64, code, address, DecoderOptions::NONE);
        let mut instruction = Instruction::default();
        let mut sweep = Sweep::default();
        while decoder.can_decode() {
            let position = decoder.position();
            decoder.decode_out(&mut instruction);
            if instruction.is_invalid() {
                sweep.invalid += 1;
                decoder.set_position(position + 1).expect("in bounds");
                decoder.set_ip(address + position as u64 + 1);
                continue;
            }
            sweep.instructions += 1;
            match task {
                Task::Format => {
                    self.text.clear();
                    self.formatter.format(&instruction, &mut self.text);
                    black_box(&self.text);
                }
                Task::Flow => {
                    black_box((instruction.flow_control(), instruction.near_branch_target()));
                }
                Task::Length | Task::Valid | Task::Decode => {
                    black_box(&instruction);
                }
            }
        }
        sweep
    }
}

/// Zydis 4 through the `zydis` crate (C, statically linked).
struct Zydis {
    minimal: zydis::Decoder,
    full: zydis::Decoder,
    formatter: zydis::Formatter,
    buffer: [u8; 256],
}

/// Sweeps `code`, asking `decode` for the length of the instruction at each
/// offset (`None` when nothing decodes there).
fn sweep_with(code: &[u8], mut decode: impl FnMut(&[u8], usize) -> Option<usize>) -> Sweep {
    let mut sweep = Sweep::default();
    let mut offset = 0;
    while let Some(rest) = code.get(offset..).filter(|rest| !rest.is_empty()) {
        if let Some(length) = decode(rest, offset) {
            sweep.instructions += 1;
            offset += length;
        } else {
            sweep.invalid += 1;
            offset += 1;
        }
    }
    sweep
}

/// yaxpeax-x86: pure Rust.
struct Yaxpeax {
    decoder: yaxpeax_x86::amd64::InstDecoder,
    text: String,
}

impl Yaxpeax {
    fn new() -> Self {
        Self {
            decoder: yaxpeax_x86::amd64::InstDecoder::default(),
            text: String::with_capacity(128),
        }
    }
}

impl Contender for Yaxpeax {
    fn name(&self) -> &'static str {
        "yaxpeax-x86 2.2"
    }

    fn supports(&self, task: Task) -> Option<&'static str> {
        match task {
            Task::Length | Task::Valid => None,
            Task::Flow => Some("decode_into + flow class of the opcode + relative target"),
            Task::Decode => Some("InstDecoder::decode_into"),
            Task::Format => Some("decode_into + Intel display"),
        }
    }

    fn sweep(&mut self, task: Task, code: &[u8], address: u64) -> Sweep {
        use std::fmt::Write as _;
        use yaxpeax_arch::{Decoder, LengthedInstruction, U8Reader};
        use yaxpeax_x86::amd64::{DisplayStyle, Instruction};
        let mut instruction = Instruction::default();
        sweep_with(code, |rest, offset| {
            let mut reader = U8Reader::new(rest);
            self.decoder
                .decode_into(&mut instruction, &mut reader)
                .ok()?;
            let length = usize::try_from(instruction.len().to_const()).ok()?;
            match task {
                Task::Format => {
                    self.text.clear();
                    write!(
                        self.text,
                        "{}",
                        instruction.display_with(DisplayStyle::Intel)
                    )
                    .ok()?;
                    black_box(&self.text);
                }
                Task::Flow => {
                    let next = address + (offset + length) as u64;
                    black_box(yaxpeax_flow(&instruction, next));
                }
                Task::Length | Task::Valid | Task::Decode => {
                    black_box(&instruction);
                }
            }
            Some(length)
        })
    }
}

/// yaxpeax-x86 has no control-flow classification: the kind of transfer
/// (0 none, 1 jump, 2 conditional, 3 call, 4 return) from the opcode, and
/// the target of a relative one ending at `next`.
fn yaxpeax_flow(instruction: &yaxpeax_x86::amd64::Instruction, next: u64) -> (u8, Option<u64>) {
    use yaxpeax_x86::amd64::{Opcode, Operand};
    let kind = match instruction.opcode() {
        Opcode::JMP => 1,
        Opcode::JO
        | Opcode::JNO
        | Opcode::JB
        | Opcode::JNB
        | Opcode::JZ
        | Opcode::JNZ
        | Opcode::JA
        | Opcode::JNA
        | Opcode::JS
        | Opcode::JNS
        | Opcode::JP
        | Opcode::JNP
        | Opcode::JL
        | Opcode::JGE
        | Opcode::JLE
        | Opcode::JG
        | Opcode::JRCXZ
        | Opcode::LOOP
        | Opcode::LOOPZ
        | Opcode::LOOPNZ => 2,
        Opcode::CALL => 3,
        Opcode::RETURN => 4,
        _ => return (0, None),
    };
    let target = match instruction.operand(0) {
        Operand::ImmediateI8 { imm } => Some(next.wrapping_add_signed(i64::from(imm))),
        Operand::ImmediateI32 { imm } => Some(next.wrapping_add_signed(i64::from(imm))),
        _ => None,
    };
    (kind, target)
}

/// bddisasm (Bitdefender) through the `bddisasm` crate (C, statically
/// linked).
struct Bddisasm {
    text: String,
}

impl Bddisasm {
    fn new() -> Self {
        Self {
            text: String::with_capacity(128),
        }
    }
}

impl Contender for Bddisasm {
    fn name(&self) -> &'static str {
        "bddisasm 0.4"
    }

    fn supports(&self, task: Task) -> Option<&'static str> {
        match task {
            Task::Length | Task::Valid => None,
            Task::Decode => Some("DecodedInstruction::decode_with_ip"),
            Task::Format => Some("decode + NdToText (Display)"),
            Task::Flow => None,
        }
    }

    fn sweep(&mut self, task: Task, code: &[u8], address: u64) -> Sweep {
        use bddisasm::{DecodeMode, DecodedInstruction};
        use std::fmt::Write as _;
        sweep_with(code, |rest, offset| {
            let instruction = DecodedInstruction::decode_with_ip(
                rest,
                DecodeMode::Bits64,
                address + offset as u64,
            )
            .ok()?;
            if task == Task::Format {
                self.text.clear();
                write!(self.text, "{instruction}").ok()?;
                black_box(&self.text);
            }
            Some(black_box(instruction).length())
        })
    }
}

impl Zydis {
    fn new() -> Self {
        let mut minimal = zydis::Decoder::new64();
        minimal
            .enable_mode(zydis::DecoderMode::MINIMAL, true)
            .expect("minimal mode");
        Self {
            minimal,
            full: zydis::Decoder::new64(),
            formatter: zydis::Formatter::intel(),
            buffer: [0; 256],
        }
    }
}

impl Contender for Zydis {
    fn name(&self) -> &'static str {
        "Zydis 4"
    }

    fn supports(&self, task: Task) -> Option<&'static str> {
        match task {
            Task::Length => Some("minimal mode, no operands"),
            Task::Flow => Some("minimal mode + branch type, category, relative target"),
            Task::Decode => Some("all operands"),
            Task::Format => Some("visible operands + Intel formatter"),
            Task::Valid => None,
        }
    }

    fn sweep(&mut self, task: Task, code: &[u8], address: u64) -> Sweep {
        use zydis::{AllOperands, NoOperands, OutputBuffer, VisibleOperands};
        sweep_with(code, |rest, offset| {
            let length = match task {
                Task::Length | Task::Valid => {
                    self.minimal.decode_first::<NoOperands>(rest).ok()??.length
                }
                Task::Flow => {
                    let instruction = self.minimal.decode_first::<NoOperands>(rest).ok()??;
                    let next = address + offset as u64 + u64::from(instruction.length);
                    let relative = instruction.raw.imm[0].is_relative;
                    let target = relative.then(|| next.wrapping_add(instruction.raw.imm[0].value));
                    black_box((
                        instruction.meta.branch_type,
                        instruction.meta.category,
                        target,
                    ));
                    instruction.length
                }
                Task::Decode => {
                    black_box(self.full.decode_first::<AllOperands>(rest).ok()??).length
                }
                Task::Format => {
                    let instruction = self.full.decode_first::<VisibleOperands>(rest).ok()??;
                    let mut buffer = OutputBuffer::new(&mut self.buffer);
                    let ip = address + offset as u64;
                    self.formatter
                        .format_ex(Some(ip), &instruction, &mut buffer, None)
                        .ok()?;
                    black_box(buffer.as_str().ok());
                    instruction.length
                }
            };
            Some(usize::from(length))
        })
    }
}

/// Capstone 5 through the `capstone` crate (C, statically linked), for
/// either architecture. It always produces text, so its decode task formats
/// too.
struct Capstone {
    detail: capstone::Capstone,
    plain: capstone::Capstone,
    /// Bytes skipped where nothing decodes.
    step: usize,
}

impl Capstone {
    fn x86_64() -> Self {
        use capstone::arch::{self, BuildsCapstone, BuildsCapstoneSyntax};
        let build = |detail| {
            capstone::Capstone::new()
                .x86()
                .mode(arch::x86::ArchMode::Mode64)
                .syntax(arch::x86::ArchSyntax::Intel)
                .detail(detail)
                .build()
                .expect("capstone")
        };
        Self {
            detail: build(true),
            plain: build(false),
            step: 1,
        }
    }

    fn aarch64() -> Self {
        use capstone::arch::{self, BuildsCapstone};
        let build = |detail| {
            capstone::Capstone::new()
                .arm64()
                .mode(arch::arm64::ArchMode::Arm)
                .detail(detail)
                .build()
                .expect("capstone")
        };
        Self {
            detail: build(true),
            plain: build(false),
            step: 4,
        }
    }
}

impl Contender for Capstone {
    fn name(&self) -> &'static str {
        "Capstone 5"
    }

    fn supports(&self, task: Task) -> Option<&'static str> {
        match task {
            Task::Length | Task::Valid | Task::Flow => None,
            Task::Decode => Some("detail on (formats text too)"),
            Task::Format => Some("detail off"),
        }
    }

    fn sweep(&mut self, task: Task, code: &[u8], address: u64) -> Sweep {
        let cs = if task == Task::Decode {
            &self.detail
        } else {
            &self.plain
        };
        let mut sweep = Sweep::default();
        let mut iter = cs.disasm_iter(code, address).expect("allocates");
        loop {
            if let Some(instruction) = iter.next() {
                sweep.instructions += 1;
                black_box(instruction.len());
                continue;
            }
            let left = iter.code().len();
            if left < self.step {
                break;
            }
            sweep.invalid += 1;
            let offset = code.len() - left + self.step;
            iter.reset(&code[offset..], address + offset as u64);
        }
        sweep
    }
}

#[cfg(xed)]
mod xed {
    #![allow(unsafe_code)]

    use crate::{Sweep, Task};

    unsafe extern "C" {
        fn binbun_bench_xed_init();
        fn binbun_bench_xed_sweep(
            code: *const u8,
            len: usize,
            ip: u64,
            task: i32,
            invalid: *mut u64,
        ) -> u64;
    }

    /// Intel XED, swept in C (see `xed.c`).
    pub struct Xed;

    impl Xed {
        pub fn new() -> Self {
            // SAFETY: initialises XED's static tables; no preconditions.
            unsafe { binbun_bench_xed_init() };
            Self
        }
    }

    impl super::Contender for Xed {
        fn name(&self) -> &'static str {
            "XED 2026.08"
        }

        fn supports(&self, task: Task) -> Option<&'static str> {
            match task {
                Task::Length => Some("xed_ild_decode"),
                Task::Flow => Some("xed_decode + category + branch displacement"),
                Task::Decode => Some("xed_decode"),
                Task::Format => Some("xed_decode + xed_format_context"),
                Task::Valid => None,
            }
        }

        fn sweep(&mut self, task: Task, code: &[u8], address: u64) -> Sweep {
            let task = match task {
                Task::Length | Task::Valid => 0,
                Task::Decode => 1,
                Task::Format => 2,
                Task::Flow => 3,
            };
            let mut invalid = 0;
            // SAFETY: `code` is valid for `code.len()` bytes and `invalid`
            // for one write; the C side reads within those bounds only.
            let instructions = unsafe {
                binbun_bench_xed_sweep(code.as_ptr(), code.len(), address, task, &raw mut invalid)
            };
            Sweep {
                instructions,
                invalid,
            }
        }
    }
}

#[cfg(llvm)]
mod llvm {
    #![allow(unsafe_code)]

    use crate::{Sweep, Task};

    unsafe extern "C" {
        fn binbun_bench_llvm_init() -> i32;
        fn binbun_bench_llvm_sweep(code: *const u8, len: usize, ip: u64, invalid: *mut u64) -> u64;
        fn binbun_bench_llvm_a64_init() -> i32;
        fn binbun_bench_llvm_a64_sweep(
            code: *const u8,
            len: usize,
            ip: u64,
            invalid: *mut u64,
        ) -> u64;
    }

    /// A sweep in C: instructions decoded in `len` bytes at `code`, mapped
    /// at `ip`, with the units skipped written to `invalid`.
    type SweepFn =
        unsafe extern "C" fn(code: *const u8, len: usize, ip: u64, invalid: *mut u64) -> u64;

    /// LLVM's MC disassembler through its C API, swept in C (see `llvm.c`
    /// and `llvm_a64.c`).
    pub struct Llvm {
        sweep: SweepFn,
    }

    impl Llvm {
        pub fn x86_64() -> Option<Self> {
            // SAFETY: initialises LLVM's X86 target and one disassembler
            // context; no preconditions.
            (unsafe { binbun_bench_llvm_init() } != 0).then_some(Self {
                sweep: binbun_bench_llvm_sweep,
            })
        }

        pub fn aarch64() -> Option<Self> {
            // SAFETY: initialises LLVM's AArch64 target and one disassembler
            // context; no preconditions.
            (unsafe { binbun_bench_llvm_a64_init() } != 0).then_some(Self {
                sweep: binbun_bench_llvm_a64_sweep,
            })
        }
    }

    impl super::Contender for Llvm {
        fn name(&self) -> &'static str {
            env!("BINBUN_BENCH_LLVM_NAME")
        }

        fn supports(&self, task: Task) -> Option<&'static str> {
            (task == Task::Format).then_some("LLVMDisasmInstruction (C API always prints)")
        }

        fn sweep(&mut self, _task: Task, code: &[u8], address: u64) -> Sweep {
            let mut invalid = 0;
            // SAFETY: `code` is valid for `code.len()` bytes and `invalid`
            // for one write; the C side reads within those bounds only.
            let instructions =
                unsafe { (self.sweep)(code.as_ptr(), code.len(), address, &raw mut invalid) };
            Sweep {
                instructions,
                invalid,
            }
        }
    }
}
