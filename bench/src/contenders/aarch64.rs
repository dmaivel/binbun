//! The AArch64 decoders. Every instruction is one little-endian 32-bit word,
//! so a sweep goes word by word and skips a word that does not decode.
//!
//! The valid task asks whether a word is an instruction. None of these
//! crates has a call that answers only that, so each answers it with its
//! decode call, keeping only whether it succeeded; Capstone and LLVM, which
//! always print, take no part.

use std::fmt::Write as _;
use std::hint::black_box;

use binbun_aarch64::decode;

use super::{Capstone, Contender};
use crate::{Sweep, Task};

pub fn all() -> Vec<Box<dyn Contender>> {
    #[cfg_attr(
        not(any(llvm, capstone6)),
        expect(unused_mut, reason = "pushed to only when linked")
    )]
    let mut all: Vec<Box<dyn Contender>> = vec![
        Box::new(Binbun::default()),
        Box::new(Exarmo::default()),
        Box::new(Bad64::default()),
        Box::new(Disarm64::default()),
        Box::new(Farm64::default()),
        Box::new(Yaxpeax::default()),
        Box::new(Capstone::aarch64()),
    ];
    #[cfg(capstone6)]
    if let Some(capstone6) = capstone6::Capstone6::new() {
        all.push(Box::new(capstone6));
    }
    #[cfg(llvm)]
    if let Some(llvm) = super::llvm::Llvm::aarch64() {
        all.push(Box::new(llvm));
    }
    all
}

/// Sweeps `code` mapped at `address` word by word, asking `decode` whether
/// the word at each address is an instruction.
fn sweep_words(code: &[u8], address: u64, mut decode: impl FnMut(u32, u64) -> bool) -> Sweep {
    let mut sweep = Sweep::default();
    let (words, _) = code.as_chunks::<4>();
    for (index, &word) in words.iter().enumerate() {
        if decode(u32::from_le_bytes(word), address + 4 * index as u64) {
            sweep.instructions += 1;
        } else {
            sweep.invalid += 1;
        }
    }
    sweep
}

/// binbun's decoder (`binbun-aarch64`).
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
            Task::Valid => Some("decode(..).is_ok()"),
            Task::Decode => Some(
                "decode (the encoding, with every UNDEFINED check; `operands()` built on demand)",
            ),
            Task::Format => Some("decode + Display of display(address)"),
            Task::Length | Task::Flow => None,
        }
    }

    fn sweep(&mut self, task: Task, code: &[u8], address: u64) -> Sweep {
        match task {
            Task::Format => {
                let text = &mut self.text;
                sweep_words(code, address, |word, address| {
                    let Ok(instruction) = decode(word) else {
                        return false;
                    };
                    text.clear();
                    let _ = write!(text, "{}", instruction.display(address));
                    black_box(&*text);
                    true
                })
            }
            Task::Decode => {
                sweep_words(code, address, |word, _| decode(word).map(black_box).is_ok())
            }
            Task::Valid | Task::Length | Task::Flow => {
                sweep_words(code, address, |word, _| decode(word).is_ok())
            }
        }
    }
}

/// exarmo (Vector 35; Binary Ninja's decoder since 2026-10): pure Rust,
/// generated from Arm's ISA XML.
#[derive(Default)]
struct Exarmo {
    text: String,
}

impl Contender for Exarmo {
    fn name(&self) -> &'static str {
        "exarmo-aarch64 0.4"
    }

    fn supports(&self, task: Task) -> Option<&'static str> {
        match task {
            Task::Valid => Some("decode_word(..).is_ok()"),
            Task::Decode => Some(
                "decode_word (an enum of encodings holding their fields; `operands()` built on demand)",
            ),
            Task::Format => Some("decode_word + Display of at(address)"),
            Task::Length | Task::Flow => None,
        }
    }

    fn sweep(&mut self, task: Task, code: &[u8], address: u64) -> Sweep {
        use exarmo_aarch64::decode_word;
        match task {
            Task::Format => {
                let text = &mut self.text;
                sweep_words(code, address, |word, address| {
                    let Ok(instruction) = decode_word(word) else {
                        return false;
                    };
                    text.clear();
                    let _ = write!(text, "{}", instruction.at(address));
                    black_box(&*text);
                    true
                })
            }
            Task::Decode => sweep_words(code, address, |word, _| {
                decode_word(word).map(black_box).is_ok()
            }),
            Task::Length | Task::Valid | Task::Flow => {
                sweep_words(code, address, |word, _| decode_word(word).is_ok())
            }
        }
    }
}

/// bad64: Binary Ninja's previous decoder (C, statically linked, through
/// bindgen); archived in 2026-10 in favour of exarmo.
#[derive(Default)]
struct Bad64 {
    text: String,
}

impl Contender for Bad64 {
    fn name(&self) -> &'static str {
        "bad64 0.13"
    }

    fn supports(&self, task: Task) -> Option<&'static str> {
        match task {
            Task::Valid => Some("decode(..).is_ok()"),
            Task::Decode => Some("decode (the C decoder fills in every operand)"),
            Task::Format => Some("decode + Display"),
            Task::Length | Task::Flow => None,
        }
    }

    fn sweep(&mut self, task: Task, code: &[u8], address: u64) -> Sweep {
        match task {
            Task::Format => {
                let text = &mut self.text;
                sweep_words(code, address, |word, address| {
                    let Ok(instruction) = bad64::decode(word, address) else {
                        return false;
                    };
                    text.clear();
                    let _ = write!(text, "{instruction}");
                    black_box(&*text);
                    true
                })
            }
            Task::Decode => sweep_words(code, address, |word, address| {
                bad64::decode(word, address).map(black_box).is_ok()
            }),
            Task::Length | Task::Valid | Task::Flow => {
                sweep_words(code, address, |word, address| {
                    bad64::decode(word, address).is_ok()
                })
            }
        }
    }
}

/// disarm64: pure Rust, generated from a JSON description of the ISA.
#[derive(Default)]
struct Disarm64 {
    text: String,
}

impl Contender for Disarm64 {
    fn name(&self) -> &'static str {
        "disarm64 0.2"
    }

    fn supports(&self, task: Task) -> Option<&'static str> {
        match task {
            Task::Valid => Some("decoder::decode(..).is_some()"),
            Task::Decode => Some(
                "decoder::decode (identifies the opcode only; operand fields extracted when formatting)",
            ),
            Task::Format => Some("decode + display_at(address) (no aliases)"),
            Task::Length | Task::Flow => None,
        }
    }

    fn sweep(&mut self, task: Task, code: &[u8], address: u64) -> Sweep {
        use disarm64::InsnDisplay;
        use disarm64::decoder::decode;
        match task {
            Task::Format => {
                let text = &mut self.text;
                sweep_words(code, address, |word, address| {
                    let Some(opcode) = decode(word) else {
                        return false;
                    };
                    text.clear();
                    let _ = write!(text, "{}", opcode.display_at(address));
                    black_box(&*text);
                    true
                })
            }
            Task::Decode => sweep_words(code, address, |word, _| {
                decode(word).map(black_box).is_some()
            }),
            Task::Length | Task::Valid | Task::Flow => {
                sweep_words(code, address, |word, _| decode(word).is_some())
            }
        }
    }
}

/// fARM64: pure Rust, hand-written, shaped like iced-x86 (a streaming
/// decoder filling a reused `Instruction`; a formatter writing to a
/// buffer).
struct Farm64 {
    formatter: farm64::format::FmtFormatter,
    buffer: [u8; 256],
}

impl Default for Farm64 {
    fn default() -> Self {
        Self {
            formatter: farm64::format::FmtFormatter::new(),
            buffer: [0; 256],
        }
    }
}

impl Contender for Farm64 {
    fn name(&self) -> &'static str {
        "fARM64 0.1"
    }

    fn supports(&self, task: Task) -> Option<&'static str> {
        match task {
            Task::Valid => Some("Decoder::decode_into, !is_invalid()"),
            Task::Decode => Some("Decoder::decode_into (all operands)"),
            Task::Format => Some("decode_into + FmtFormatter into a buffer"),
            Task::Length | Task::Flow => None,
        }
    }

    fn sweep(&mut self, task: Task, code: &[u8], address: u64) -> Sweep {
        use farm64::format::{BufSink, Formatter};
        use farm64::{Decoder, DecoderOptions, Instruction};
        let mut decoder = Decoder::new(code, address, DecoderOptions::default());
        let mut instruction = Instruction::default();
        let mut sweep = Sweep::default();
        // The corpus holds whole words only, so every call advances.
        while decoder.can_decode() {
            decoder.decode_into(&mut instruction);
            if instruction.is_invalid() {
                sweep.invalid += 1;
                continue;
            }
            sweep.instructions += 1;
            match task {
                Task::Format => {
                    let mut sink = BufSink::new(&mut self.buffer);
                    self.formatter.format(&instruction, &mut sink);
                    black_box(sink.as_str());
                }
                Task::Decode => {
                    black_box(&instruction);
                }
                Task::Length | Task::Valid | Task::Flow => {}
            }
        }
        sweep
    }
}

/// yaxpeax-arm's A64 decoder: pure Rust. It has no SVE or SME.
#[derive(Default)]
struct Yaxpeax {
    decoder: yaxpeax_arm::armv8::a64::InstDecoder,
    instruction: yaxpeax_arm::armv8::a64::Instruction,
    text: String,
}

impl Contender for Yaxpeax {
    fn name(&self) -> &'static str {
        "yaxpeax-arm 0.5"
    }

    fn supports(&self, task: Task) -> Option<&'static str> {
        match task {
            Task::Valid => Some("InstDecoder::decode_into(..).is_ok()"),
            Task::Decode => Some("InstDecoder::decode_into (no SVE/SME)"),
            Task::Format => Some("decode_into + Display (PC-relative targets)"),
            Task::Length | Task::Flow => None,
        }
    }

    fn sweep(&mut self, task: Task, code: &[u8], address: u64) -> Sweep {
        use yaxpeax_arch::{Decoder, U8Reader};
        let Self {
            decoder,
            instruction,
            text,
        } = self;
        sweep_words(code, address, |word, _| {
            let bytes = word.to_le_bytes();
            if decoder
                .decode_into(instruction, &mut U8Reader::new(&bytes))
                .is_err()
            {
                return false;
            }
            match task {
                Task::Format => {
                    text.clear();
                    let _ = write!(text, "{instruction}");
                    black_box(&*text);
                }
                Task::Decode => {
                    black_box(&*instruction);
                }
                Task::Length | Task::Valid | Task::Flow => {}
            }
            true
        })
    }
}

#[cfg(capstone6)]
mod capstone6 {
    #![allow(unsafe_code)]

    use crate::{Sweep, Task};

    unsafe extern "C" {
        fn binbun_bench_cs6_init() -> i32;
        fn binbun_bench_cs6_sweep(
            code: *const u8,
            len: usize,
            ip: u64,
            detail: i32,
            invalid: *mut u64,
        ) -> u64;
    }

    /// Capstone 6 ("next", its AArch64 module generated from LLVM 18),
    /// swept in C (see `capstone6.c`). It always produces text, so its
    /// decode task formats too.
    pub struct Capstone6;

    impl Capstone6 {
        pub fn new() -> Option<Self> {
            // SAFETY: opens two Capstone handles; no preconditions.
            (unsafe { binbun_bench_cs6_init() } != 0).then_some(Self)
        }
    }

    impl super::Contender for Capstone6 {
        fn name(&self) -> &'static str {
            "Capstone 6.0.0-Alpha11"
        }

        fn supports(&self, task: Task) -> Option<&'static str> {
            match task {
                Task::Length | Task::Valid | Task::Flow => None,
                Task::Decode => Some("cs_disasm_iter, detail on (formats text too)"),
                Task::Format => Some("cs_disasm_iter, detail off"),
            }
        }

        fn sweep(&mut self, task: Task, code: &[u8], address: u64) -> Sweep {
            let detail = i32::from(task == Task::Decode);
            let mut invalid = 0;
            // SAFETY: `code` is valid for `code.len()` bytes and `invalid`
            // for one write; the C side reads within those bounds only.
            let instructions = unsafe {
                binbun_bench_cs6_sweep(code.as_ptr(), code.len(), address, detail, &raw mut invalid)
            };
            Sweep {
                instructions,
                invalid,
            }
        }
    }
}
