//! The CPU this runs on as a test oracle (`tools/cpu-oracle`), shared by the
//! hardware test (`tests/hardware.rs`) and the profile measurement
//! (`tests/profile.rs`): states, the oracle's protocol, the interpreter's
//! machine, the instructions to run and the CPUs allowed.
//!
//! States are random with a bias to edge values; registers used as a memory
//! base point into a mappable window and the stack pointer at a stack page,
//! so memory operands land where the oracle can map them. The interpreter
//! runs first on lazily invented memory; the bytes it touches become the
//! oracle's memory regions, with the same contents.
//!
//! Instructions that use vector, MXCSR or x87 state also get random
//! floating-point state (float edge values per lane, random rounding, DAZ,
//! FTZ, sticky flags and now and then unmasked exceptions; a random x87
//! stack), sent to the oracle and compared afterwards; the others run
//! with the process's floating-point state, which is not compared.
//!
//! The interpreter's machine records each site's undefined value it
//! evaluates, with its inputs, and gives the value a profile's rule gives
//! where it runs with one.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt::Write as _;
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::Arc;

use binbun_semantics::bits::Bits;
use binbun_semantics::interpret::{Fault, Machine, Outcome, Value};
use binbun_semantics::ir::{RegisterId, SiteId, Trap};
use binbun_semantics::profile::Profile;
use binbun_x86::{
    Form, Instruction, Mode, OperandName, Register, RegisterClass, Value as OperandValue, decode,
};
use binbun_x86_lift::registers::{self, C0, FCW, FPR0, FSW, FTOP, FTW, MXCSR, RAX, ZMM0};
use binbun_x86_lift::{X86, lift};

use crate::support;

/// Where memory operands point (a page-aligned base plus up to 16 pages).
pub const WINDOW: u64 = 0x3c3c_0000_0000;
/// The same for 32-bit addresses.
pub const WINDOW_32: u64 = 0x4000_0000;
/// The stack pointer's page.
pub const STACK: u64 = 0x2b2b_0000_8000;
/// Where code goes.
pub const CODE: u64 = 0x5a5a_0000_0000;
pub const PAGE: u64 = 4096;

/// The status flags L0 models, with their `RFLAGS` bit.
pub const FLAGS: [(&str, u32); 7] = [
    ("cf", 0),
    ("pf", 2),
    ("af", 4),
    ("zf", 6),
    ("sf", 7),
    ("df", 10),
    ("of", 11),
];

pub const GPRS: [&str; 16] = [
    "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13",
    "r14", "r15",
];

/// The x87 status word bits of C0, C1, C2 and C3 (TOP is bits 11 to 13).
pub const CONDITION_BITS: [u32; 4] = [8, 9, 10, 14];

/// Extension and category names (substrings) whose instructions use
/// floating-point state, beyond what their register operands show.
const FP_NAMES: [&str; 19] = [
    "SSE",
    "AVX",
    "FMA",
    "F16C",
    "FP16",
    "X87",
    "FCMOV",
    "MMX",
    "3DNOW",
    "AES",
    "PCLMUL",
    "SHA",
    "GFNI",
    "SM3",
    "SM4",
    "XSAVE",
    "KEYLOCKER",
    "LOGICAL_FP",
    "STTNI",
];

/// A xorshift generator.
pub struct Random(pub u64);

impl Random {
    pub fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    pub fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }

    /// A register value, often an edge case.
    pub fn value(&mut self) -> u64 {
        match self.below(10) {
            0 => 0,
            1 => u64::MAX,
            2 => 1,
            3 => 1 << self.below(64),
            4 => (1 << self.below(64)) - 1,
            5 => self.below(64),
            6 => 0x7f | (self.next() & !0xff),
            7 => 0x8000_0000 | (self.next() & !0xffff_ffff),
            _ => self.next(),
        }
    }

    /// The bits of an IEEE binary float with `exponent` and `fraction` bit
    /// fields, often an edge case: zero, the smallest and largest
    /// denormals, the smallest normal, the largest finite value, infinity,
    /// quiet and signalling NaNs with random payloads, 1 and its
    /// neighbours; either sign.
    fn float(&mut self, exponent: u32, fraction: u32) -> u64 {
        let infinity = ((1u64 << exponent) - 1) << fraction;
        let quiet = 1u64 << (fraction - 1);
        let payload = self.next() & (quiet - 1);
        let one = ((1u64 << (exponent - 1)) - 1) << fraction;
        let magnitude = match self.below(13) {
            0 => 0,
            1 => 1,
            2 => (1 << fraction) - 1,
            3 => 1 << fraction,
            4 => infinity - 1,
            5 => infinity,
            6 => infinity | quiet | payload,
            7 => infinity | payload.max(1),
            8 => one,
            9 => one + 1,
            10 => one - 1,
            _ => self.next() & ((1 << (exponent + fraction)) - 1),
        };
        (u64::from(self.below(2) == 1) << (exponent + fraction)) | magnitude
    }

    /// 64 bits of a vector register: often a double, two singles or four
    /// halves that are float edge cases, else a register value.
    fn vector_word(&mut self) -> u64 {
        match self.below(4) {
            0 => self.float(11, 52),
            1 => self.float(8, 23) | (self.float(8, 23) << 32),
            2 => (0..4).fold(0, |word, lane| word | (self.float(5, 10) << (16 * lane))),
            _ => self.value(),
        }
    }

    /// An x87 80-bit value, often an edge case: zero, a denormal, the
    /// smallest and largest normals, a random normal, 1 and its neighbours,
    /// infinity, quiet and signalling NaNs with random payloads; else
    /// random bits (unnormals included); either sign.
    fn extended(&mut self) -> u128 {
        const INTEGER: u64 = 1 << 63;
        let (exponent, significand): (u64, u64) = match self.below(12) {
            0 => (0, 0),
            1 => (0, (self.next() >> 1).max(1)),
            2 => (1, INTEGER),
            3 => (0x7ffe, u64::MAX),
            4 => (1 + self.below(0x7ffe), INTEGER | self.next()),
            5 => (0x3fff, INTEGER),
            6 => (0x3fff, INTEGER | 1),
            7 => (0x3ffe, u64::MAX),
            8 => (0x7fff, INTEGER),
            9 => (0x7fff, INTEGER | (1 << 62) | (self.next() >> 2)),
            10 => (0x7fff, INTEGER | (self.next() >> 2).max(1)),
            _ => (self.below(0x8000), self.next()),
        };
        (u128::from(self.below(2) == 1) << 79)
            | (u128::from(exponent) << 64)
            | u128::from(significand)
    }

    /// An MXCSR value: random rounding, DAZ, FTZ and sticky flags; the
    /// exceptions masked but now and then for a random few.
    fn mxcsr(&mut self) -> u32 {
        let masks = if self.below(8) == 0 {
            (self.next() & 0x3f) << 7
        } else {
            0x1f80
        };
        let flags = if self.below(2) == 0 {
            0
        } else {
            self.next() & 0x3f
        };
        let daz = u64::from(self.below(4) == 0) << 6;
        let ftz = u64::from(self.below(4) == 0) << 15;
        let rounding = self.below(4) << 13;
        u32::try_from(masks | flags | daz | ftz | rounding).unwrap()
    }

    /// An x87 control word: `37f` with random rounding, now and then with
    /// another precision and some exceptions unmasked.
    fn fcw(&mut self) -> u16 {
        let rest = if self.below(8) == 0 {
            (self.below(4) << 8) | (self.next() & 0x3f)
        } else {
            0x33f
        };
        u16::try_from(0x40 | rest | (self.below(4) << 10)).unwrap()
    }

    /// An x87 status word with TOP `top`: random condition codes, and
    /// sometimes exception flags, only for exceptions `fcw` masks, so that
    /// none is pending (ES clear) before the instruction.
    fn fsw(&mut self, fcw: u16, top: u16) -> u16 {
        let flags = if self.below(2) == 0 {
            0
        } else {
            u16::try_from(self.next() & 0x3f).unwrap() & fcw & 0x3f
        };
        let stack_fault = if flags & 1 == 1 && self.below(2) == 0 {
            0x40
        } else {
            0
        };
        let conditions = u16::try_from(self.next() & 0x4700).unwrap();
        flags | stack_fault | conditions | (top << 11)
    }
}

/// The CPU oracle, running.
pub struct Oracle {
    child: Child,
    input: ChildStdin,
    output: BufReader<ChildStdout>,
}

impl Oracle {
    pub fn start(path: &str) -> Self {
        let mut child = Command::new(path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap_or_else(|e| panic!("{path}: {e}"));
        let input = child.stdin.take().unwrap();
        let output = BufReader::new(child.stdout.take().unwrap());
        Self {
            child,
            input,
            output,
        }
    }

    pub fn ask(&mut self, line: &str) -> String {
        writeln!(self.input, "{line}").unwrap();
        self.input.flush().unwrap();
        let mut answer = String::new();
        self.output.read_line(&mut answer).unwrap();
        answer.trim_end().to_owned()
    }
}

impl Drop for Oracle {
    fn drop(&mut self) {
        let _ = self.child.kill();
    }
}

/// The interpreter's machine: registers, and memory invented on first
/// touch (remembered, so the oracle gets the same contents); the sites'
/// undefined values evaluated, and a profile's rules if it has one.
pub struct Test {
    pub registers: HashMap<RegisterId, Value>,
    pub memory: BTreeMap<u64, u8>,
    /// The undefined bits of stored bytes (absent: all defined).
    pub undefined: BTreeMap<u64, u8>,
    pub initial: BTreeMap<u64, u8>,
    /// The code page(s): their contents are the code, not invented.
    code: (u64, Vec<u8>),
    random: Random,
    /// Each site's undefined value evaluated, with its inputs' values.
    pub sites: Vec<(SiteId, Vec<Value>)>,
    /// The processor's rules, if the run follows a profile.
    pub profile: Option<Arc<Profile>>,
}

impl Test {
    fn byte(&mut self, address: u64) -> u8 {
        if let Some(&byte) = self.memory.get(&address) {
            return byte;
        }
        let (start, ref bytes) = self.code;
        let page = start & !(PAGE - 1);
        let end = (start + bytes.len() as u64 + PAGE - 1) & !(PAGE - 1);
        let byte = if (page..end).contains(&address) {
            address
                .checked_sub(start)
                .and_then(|offset| bytes.get(usize::try_from(offset).ok()?))
                .copied()
                .unwrap_or(0)
        } else {
            #[expect(clippy::cast_possible_truncation, reason = "a random byte")]
            let byte = self.random.next() as u8;
            self.initial.insert(address, byte);
            byte
        };
        self.memory.insert(address, byte);
        byte
    }
}

impl Machine for Test {
    fn read(&mut self, register: RegisterId) -> Value {
        let width = X86.info(register).map_or(64, |info| info.width);
        self.registers
            .get(&register)
            .copied()
            .unwrap_or_else(|| Value::unknown(width))
    }

    fn write(&mut self, register: RegisterId, value: Value) {
        self.registers.insert(register, value);
    }

    fn load(&mut self, address: u64, bytes: u16) -> Result<Value, Fault> {
        let addresses = (0..u64::from(bytes)).map(|i| address.wrapping_add(i));
        let data: Vec<u8> = addresses.clone().map(|at| self.byte(at)).collect();
        let undefined: Vec<u8> = addresses
            .map(|at| self.undefined.get(&at).copied().unwrap_or(0))
            .collect();
        Ok(Value {
            bits: Bits::from_le_bytes(bytes * 8, &data),
            undefined: Bits::from_le_bytes(bytes * 8, &undefined),
        })
    }

    fn store(&mut self, address: u64, value: Value) -> Result<(), Fault> {
        let bytes = value.bits.to_le_bytes().zip(value.undefined.to_le_bytes());
        for (i, (byte, undefined)) in bytes.enumerate() {
            let at = address.wrapping_add(i as u64);
            self.byte(at);
            self.memory.insert(at, byte);
            self.undefined.insert(at, undefined);
        }
        Ok(())
    }

    fn undefined(&mut self, site: SiteId, inputs: &[Value], width: u16) -> Value {
        self.sites.push((site, inputs.to_vec()));
        self.profile.as_ref().map_or_else(
            || Value::unknown(width),
            |profile| profile.value(site, inputs, width),
        )
    }
}

/// Initial registers for `instruction`: random, with memory bases and the
/// stack pointer aimed at mappable addresses. In a quarter of the states,
/// rax and rdx hold one 32-bit value twice and so do 16 bytes at each
/// memory operand (the returned bytes), so comparisons of every width
/// (`cmpxchg`, `cmpxchg16b`, `repe cmps`) also see equal values.
pub fn state(instruction: &Instruction, random: &mut Random) -> ([u64; 16], BTreeMap<u64, u8>) {
    let mut registers: [u64; 16] = std::array::from_fn(|_| random.value());
    registers[4] = STACK + random.below(64) * 8;
    let equal = (random.below(4) == 0).then(|| {
        let half = random.value() & 0xffff_ffff;
        let value = half | half << 32;
        registers[0] = value;
        registers[2] = value;
        let bytes = value.to_le_bytes();
        std::array::from_fn::<u8, 16, _>(|i| bytes[i % 8])
    });
    let mut seeds = BTreeMap::new();
    let index_of = |register: Register| {
        registers::gpr(register).map(|view| usize::from(view.register.0 - RAX.0))
    };
    for operand in instruction.operands() {
        let OperandValue::Memory(memory) = operand.value else {
            continue;
        };
        if operand.name == OperandName::Agen {
            continue;
        }
        let window = if instruction.address_width() == 32 {
            WINDOW_32
        } else {
            WINDOW
        };
        let mut offset = 0u64;
        if let Some(index) = memory.index.and_then(index_of) {
            let value = random.below(64);
            registers[index] = value;
            offset = value * u64::from(memory.scale.max(1));
        }
        if let Some(base) = memory.base.and_then(index_of)
            && base != 4
        {
            // Now and then a non-canonical address, which must fault.
            let target = if random.below(16) == 0 {
                0x8000_0000_0000_0000 | random.next() >> 2
            } else {
                // Half aligned to 64 bytes, for instructions that require
                // alignment.
                let mut target = window + random.below(16) * PAGE + random.below(PAGE);
                if random.below(2) == 0 {
                    target &= !63;
                }
                if let Some(bytes) = equal {
                    seeds.extend((target..).zip(bytes));
                }
                target
            };
            registers[base] = target
                .wrapping_sub(memory.displacement.cast_unsigned())
                .wrapping_sub(offset);
        }
    }
    (registers, seeds)
}

pub fn hex(bytes: impl IntoIterator<Item = u8>) -> String {
    bytes.into_iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// Whether `instruction` uses vector, MXCSR or x87 state: a register
/// operand of such a class, or an extension or category that implies it.
pub fn uses_fp(instruction: &Instruction) -> bool {
    let operand = instruction.operands().any(|operand| {
        let OperandValue::Register(Some(register)) = operand.value else {
            return false;
        };
        matches!(
            register.class(),
            RegisterClass::Xmm
                | RegisterClass::Ymm
                | RegisterClass::Zmm
                | RegisterClass::X87
                | RegisterClass::Pseudox87
                | RegisterClass::Mxcsr
                | RegisterClass::Mmx
        )
    });
    let names = [
        instruction.extension().as_str(),
        instruction.category().as_str(),
    ];
    operand
        || names
            .iter()
            .any(|name| FP_NAMES.iter().any(|fp| name.contains(fp)))
}

/// Floating-point state as the oracle takes it: `ymm` registers as 64-bit
/// words, low first; the whole x87 status word (TOP and the condition
/// codes included); the abridged tag word; the physical x87 registers.
#[derive(Clone)]
pub struct FpState {
    pub ymm: [[u64; 4]; 16],
    pub mxcsr: u32,
    pub fcw: u16,
    pub fsw: u16,
    pub ftw: u8,
    pub fpr: [u128; 8],
}

impl FpState {
    /// Random state: float edge values in the vector lanes, a random x87
    /// stack (registers tagged empty are 0).
    pub fn random(random: &mut Random) -> Self {
        let ymm = std::array::from_fn(|_| std::array::from_fn(|_| random.vector_word()));
        let mxcsr = random.mxcsr();
        let fcw = random.fcw();
        let top = u16::try_from(random.below(8)).unwrap();
        let fsw = random.fsw(fcw, top);
        let ftw = u8::try_from(random.value() & 0xff).unwrap();
        let fpr = std::array::from_fn(|i| {
            if ftw >> i & 1 == 1 {
                random.extended()
            } else {
                0
            }
        });
        Self {
            ymm,
            mxcsr,
            fcw,
            fsw,
            ftw,
            fpr,
        }
    }

    /// Sets the interpreter's registers: `zmm` bits 256..512 are 0; the
    /// status word is split into `fsw`, `ftop` and `c0`–`c3`.
    fn write_to(&self, machine: &mut Test) {
        for (i, words) in (0u16..).zip(&self.ymm) {
            let bytes: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
            let value = Value::defined(Bits::from_le_bytes(512, &bytes));
            machine.write(RegisterId(ZMM0.0 + i), value);
        }
        let fsw = u64::from(self.fsw);
        let scalars = [
            (MXCSR, 32, u64::from(self.mxcsr)),
            (FCW, 16, u64::from(self.fcw)),
            (FSW, 16, fsw & 0x80ff),
            (FTOP, 3, fsw >> 11 & 7),
            (FTW, 8, u64::from(self.ftw)),
        ];
        for (id, width, value) in scalars {
            machine.write(id, Value::defined(Bits::from_u64(width, value)));
        }
        for (i, bit) in (0u16..).zip(CONDITION_BITS) {
            let value = Value::defined(Bits::from_bool(fsw >> bit & 1 == 1));
            machine.write(RegisterId(C0.0 + i), value);
        }
        for (i, &value) in (0u16..).zip(&self.fpr) {
            machine.write(
                RegisterId(FPR0.0 + i),
                Value::defined(Bits::from_u128(80, value)),
            );
        }
    }

    /// The oracle's input fields.
    fn append_to(&self, line: &mut String) {
        for (i, words) in self.ymm.iter().enumerate() {
            let _ = write!(line, " ymm{i}={}", wide_hex(words));
        }
        let _ = write!(
            line,
            " mxcsr={:x} fcw={:x} fsw={:x} ftw={:x}",
            self.mxcsr, self.fcw, self.fsw, self.ftw
        );
        for (i, value) in self.fpr.iter().enumerate() {
            let _ = write!(line, " fpr{i}={value:x}");
        }
    }
}

/// A number given as 64-bit words, low first, in hex without leading zeros.
fn wide_hex(words: &[u64]) -> String {
    let top = words.iter().rposition(|&word| word != 0).unwrap_or(0);
    let mut s = format!("{:x}", words[top]);
    for word in words[..top].iter().rev() {
        let _ = write!(s, "{word:016x}");
    }
    s
}

/// A hex number of up to 512 bits.
fn wide_number(hex: &str) -> Bits {
    let digits: Vec<u8> = hex
        .bytes()
        .rev()
        .map(|digit| u8::try_from(char::from(digit).to_digit(16).unwrap()).unwrap())
        .collect();
    let bytes: Vec<u8> = digits
        .chunks(2)
        .map(|pair| pair[0] | (pair.get(1).copied().unwrap_or(0) << 4))
        .collect();
    Bits::from_le_bytes(512, &bytes)
}

/// Contiguous runs of `bytes`.
fn runs(bytes: &BTreeMap<u64, u8>) -> Vec<(u64, Vec<u8>)> {
    let mut runs: Vec<(u64, Vec<u8>)> = Vec::new();
    for (&address, &byte) in bytes {
        match runs.last_mut() {
            Some((start, data)) if *start + data.len() as u64 == address => data.push(byte),
            _ => runs.push((address, vec![byte])),
        }
    }
    runs
}

/// The oracle's answer, parsed: kind, values, memory regions; `ymm` and
/// `fpr` registers, which may not fit 64 bits, in `wide`.
pub struct Answer {
    pub kind: String,
    pub values: HashMap<String, u64>,
    pub wide: HashMap<String, Bits>,
    pub memory: BTreeMap<u64, u8>,
}

/// Reads an answer of the oracle.
pub fn parse(answer: &str) -> Answer {
    let mut words = answer.split_whitespace();
    let kind = words.next().unwrap_or_default().to_owned();
    let mut values = HashMap::new();
    let mut wide = HashMap::new();
    let mut memory = BTreeMap::new();
    for word in words {
        let Some((name, value)) = word.split_once('=') else {
            values.insert(word.to_owned(), 0);
            continue;
        };
        if name == "mem" {
            let (address, bytes) = value.split_once(':').unwrap();
            let address = u64::from_str_radix(address, 16).unwrap();
            for (i, pair) in bytes.as_bytes().chunks(2).enumerate() {
                let byte = u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap();
                memory.insert(address + i as u64, byte);
            }
        } else if name.starts_with("ymm") || name.starts_with("fpr") {
            wide.insert(name.to_owned(), wide_number(value));
        } else if let Ok(number) = u64::from_str_radix(value.trim_start_matches('-'), 16) {
            values.insert(name.to_owned(), number);
        }
    }
    Answer {
        kind,
        values,
        wide,
        memory,
    }
}

/// Where execution continues if the processor agrees with `outcome`: after
/// a fault, at the instruction (`code`); after a trap (#BP), at the next
/// one (`next`). `None` if they disagree. `SIGFPE` is a divide error with
/// `FPE_INTDIV` or `FPE_INTOVF` (1, 2), a floating-point exception with
/// `FPE_FLTDIV` to `FPE_FLTSUB` (3 to 8).
pub fn resumes_at(outcome: Outcome, answer: &Answer, code: u64, next: u64) -> Option<u64> {
    let signal = |name: &str| answer.values.contains_key(name);
    let si_code = answer.values.get("code").copied().unwrap_or(0);
    match (outcome, answer.kind.as_str()) {
        (Outcome::Next, "ok") => Some(next),
        (Outcome::Transfer(target), "ok") => Some(target),
        (Outcome::Trap(Trap::Divide), "fault")
            if signal("SIGFPE") && (1..=2).contains(&si_code) =>
        {
            Some(code)
        }
        (Outcome::Trap(Trap::FloatingPoint), "fault")
            if signal("SIGFPE") && (3..=8).contains(&si_code) =>
        {
            Some(code)
        }
        (Outcome::Trap(Trap::InvalidInstruction), "fault") if signal("SIGILL") => Some(code),
        (Outcome::Trap(Trap::Breakpoint), "fault") if signal("SIGTRAP") => Some(next),
        (Outcome::Trap(Trap::Protection | Trap::Stack), "fault")
            if signal("SIGSEGV") || signal("SIGBUS") =>
        {
            Some(code)
        }
        _ => None,
    }
}

/// Differences between the interpreter's state and the processor's.
pub fn compare(machine: &mut Test, answer: &Answer, rip: u64, wrong: &mut Vec<String>) {
    let cpu_rip = answer.values.get("rip").copied().unwrap_or(0);
    if cpu_rip != rip {
        wrong.push(format!("rip: L0 {rip:x}, CPU {cpu_rip:x}"));
    }
    for (i, name) in GPRS.iter().enumerate() {
        let value = machine.read(RegisterId(RAX.0 + u16::try_from(i).unwrap()));
        let mask = !value.undefined.low_u64();
        let cpu = answer.values.get(*name).copied().unwrap_or(0);
        if (value.bits.low_u64() ^ cpu) & mask != 0 {
            wrong.push(format!(
                "{name}: L0 {:x}, CPU {cpu:x}",
                value.bits.low_u64()
            ));
        }
    }
    let flags = answer.values.get("rflags").copied().unwrap_or(0);
    for (name, bit) in FLAGS {
        let value = machine.read(X86.find(name).unwrap());
        let cpu = flags >> bit & 1;
        if value.is_defined() && value.bits.low_u64() != cpu {
            wrong.push(format!("{name}: L0 {}, CPU {cpu}", value.bits.low_u64()));
        }
    }
    for (address, &byte) in &answer.memory {
        let ours = machine.memory.get(address).copied().unwrap_or(0);
        let defined = !machine.undefined.get(address).copied().unwrap_or(0);
        if (ours ^ byte) & defined != 0 {
            wrong.push(format!("[{address:x}]: L0 {ours:02x}, CPU {byte:02x}"));
        }
    }
}

/// Differences in the floating-point state: `zmm` (all 512 bits; the
/// processor's are 0 from 256), `mxcsr`, `fcw`, the status word composed
/// of `fsw`, `ftop` and `c0`–`c3`, `ftw`, `fpr0`–`fpr7`.
/// Compares the vector, MXCSR and x87 state. At a SIMD floating-point
/// fault (`fault`) the processor has set MXCSR's flags for the exceptions
/// it found before delivering it; L0's precise exception leaves MXCSR
/// unchanged, so its flags are not compared then.
pub fn compare_fp(machine: &mut Test, answer: &Answer, fault: bool, wrong: &mut Vec<String>) {
    let wide = |name: &str| answer.wide.get(name).copied().unwrap_or(Bits::zero(512));
    let scalar = |name: &str| Bits::from_u64(64, answer.values.get(name).copied().unwrap_or(0));
    for i in 0..16u16 {
        let value = machine.read(RegisterId(ZMM0.0 + i));
        differ(value, wide(&format!("ymm{i}")), &format!("zmm{i}"), wrong);
    }
    let mut mxcsr = machine.read(MXCSR);
    if fault {
        mxcsr.undefined = mxcsr.undefined.or(&Bits::from_u64(32, 0x3f));
    }
    differ(mxcsr, scalar("mxcsr"), "mxcsr", wrong);
    for (id, name) in [(FCW, "fcw"), (FTW, "ftw")] {
        differ(machine.read(id), scalar(name), name, wrong);
    }
    differ(status_word(machine), scalar("fsw"), "status word", wrong);
    for i in 0..8u16 {
        let value = machine.read(RegisterId(FPR0.0 + i));
        differ(value, wide(&format!("fpr{i}")), &format!("fpr{i}"), wrong);
    }
}

/// The x87 status word as the processor has it, from L0's parts.
fn status_word(machine: &mut Test) -> Value {
    let conditions = (0u16..)
        .zip(CONDITION_BITS)
        .map(|(i, bit)| (RegisterId(C0.0 + i), bit));
    let (mut bits, mut undefined) = (0u64, 0u64);
    for (id, shift) in [(FSW, 0), (FTOP, 11)].into_iter().chain(conditions) {
        let value = machine.read(id);
        bits |= value.bits.low_u64() << shift;
        undefined |= value.undefined.low_u64() << shift;
    }
    Value {
        bits: Bits::from_u64(16, bits),
        undefined: Bits::from_u64(16, undefined),
    }
}

/// Records a difference between `value` and the processor's `cpu` (cut to
/// the register's width) in the bits L0 defines.
fn differ(value: Value, cpu: Bits, name: &str, wrong: &mut Vec<String>) {
    let cpu = cpu.extract(0, value.bits.width());
    if !value
        .bits
        .xor(&cpu)
        .and(&value.undefined.invert())
        .is_zero()
    {
        wrong.push(format!("{name}: L0 {}, CPU {cpu}", value.bits));
    }
}

/// Whether `bytes` has a REX2 prefix (APX) after its legacy prefixes.
pub fn rex2(bytes: &[u8]) -> bool {
    const LEGACY: [u8; 11] = [
        0x26, 0x2e, 0x36, 0x3e, 0x64, 0x65, 0x66, 0x67, 0xf0, 0xf2, 0xf3,
    ];
    // A REX prefix followed by another prefix is ignored, so a REX2 prefix
    // may come after one (`41 2e d5 ...`).
    bytes
        .iter()
        .find(|b| !LEGACY.contains(b) && !(0x40..=0x4f).contains(*b))
        == Some(&0xd5)
}

/// The registers a case starts from, and where its code is.
#[derive(Clone)]
pub struct Start {
    pub code: u64,
    pub gprs: [u64; 16],
    pub rflags: u64,
    /// For instructions that use floating-point state.
    pub fp: Option<FpState>,
}

impl Start {
    /// The interpreter's machine in this state, with `seeds` in memory and
    /// the rest invented from `random`.
    pub fn machine(&self, bytes: &[u8], seeds: &BTreeMap<u64, u8>, random: &mut Random) -> Test {
        let mut machine = Test {
            registers: HashMap::new(),
            memory: BTreeMap::new(),
            undefined: BTreeMap::new(),
            initial: BTreeMap::new(),
            code: (self.code, bytes.to_vec()),
            random: Random(random.next() | 1),
            sites: Vec::new(),
            profile: None,
        };
        for (&at, &byte) in seeds {
            machine.memory.insert(at, byte);
            machine.initial.insert(at, byte);
        }
        for (i, &value) in self.gprs.iter().enumerate() {
            let id = RegisterId(RAX.0 + u16::try_from(i).unwrap());
            machine.write(id, Value::defined(Bits::from_u64(64, value)));
        }
        for (name, bit) in FLAGS {
            let id = X86.find(name).unwrap();
            machine.write(
                id,
                Value::defined(Bits::from_bool(self.rflags >> bit & 1 == 1)),
            );
        }
        if let Some(fp) = &self.fp {
            fp.write_to(&mut machine);
        }
        machine
    }

    /// The oracle's `case` line for `bytes`, with `initial` (the memory the
    /// interpreter read) as memory regions.
    pub fn line(&self, bytes: &[u8], initial: &BTreeMap<u64, u8>) -> String {
        let mut line = format!("case {:x} {}", self.code, hex(bytes.iter().copied()));
        for (name, value) in GPRS.iter().zip(self.gprs) {
            let _ = write!(line, " {name}={value:x}");
        }
        let _ = write!(line, " rflags={:x}", self.rflags);
        if let Some(fp) = &self.fp {
            fp.append_to(&mut line);
        }
        for (address, data) in runs(initial) {
            let _ = write!(line, " mem={address:x}:{}", hex(data));
        }
        line
    }
}

/// Random instruction bytes: a third plain (a legacy prefix now and then,
/// or 66, F2 or F3 before 0F),
/// a third in the `0F 38` and `0F 3A` maps (with a mandatory prefix or
/// none), a third VEX-encoded (two- and three-byte, maps 1 to 3), so that
/// SSE4, SSSE3, AVX, FMA and the crypto extensions are reached.
fn random_encoding(random: &mut Random) -> [u8; 15] {
    let mut bytes = [0u8; 15];
    for chunk in bytes.chunks_mut(8) {
        let word = random.next().to_le_bytes();
        chunk.copy_from_slice(&word[..chunk.len()]);
    }
    let pick = |random: &mut Random, list: &[u8]| {
        list[usize::try_from(random.below(list.len() as u64)).unwrap()]
    };
    match random.below(3) {
        0 => {
            // A legacy prefix a quarter of the time, 66, F2 or F3 before
            // 0F (the mandatory-prefix SSE forms) another quarter.
            match random.below(4) {
                0 => bytes[0] = pick(random, &[0x66, 0x67, 0x48, 0x41, 0x4c, 0x66]),
                1 => {
                    bytes[0] = pick(random, &[0x66, 0xf2, 0xf3]);
                    bytes[1] = 0x0f;
                }
                _ => {}
            }
        }
        1 => {
            let prefix = pick(random, &[0x66, 0xf2, 0xf3, 0x66, 0x48]);
            let map = pick(random, &[0x38, 0x3a]);
            bytes[0] = prefix;
            bytes[1] = 0x0f;
            bytes[2] = map;
        }
        _ => {
            if random.below(2) == 0 {
                bytes[0] = 0xc5;
            } else {
                bytes[0] = 0xc4;
                // R, X, B random; map 1 (0F), 2 (0F 38) or 3 (0F 3A).
                bytes[1] = (bytes[1] & 0xe0) | pick(random, &[1, 2, 3]);
            }
        }
    }
    bytes
}

/// Every opcode slot, systematically: each opcode of the one-byte, `0F`,
/// `0F 38` and `0F 3A` maps under no prefix, 66, F2, F3, `lock`, each of
/// them with REX.W, and 66 with F2 or F3 (16-bit `rep` string forms), and
/// of the three VEX maps under every `pp`, `L` and
/// `W`, each with every `reg` field of a register `ModRM` byte and of two
/// memory ones (the rest of the bytes random); every `ModRM` byte of the
/// `0F` map under no prefix, 66, F2 and F3, and of the x87 escapes D8 to
/// DF. So every form the decoder knows is reached, whatever the corpus.
fn systematic_encodings(random: &mut Random) -> Vec<[u8; 15]> {
    let mut encodings = Vec::new();
    let mut push = |random: &mut Random, prefix: &[u8], opcode: u8, modrm: Option<u8>| {
        let mut bytes = random_encoding(random);
        let mut at = 0;
        for &byte in prefix {
            bytes[at] = byte;
            at += 1;
        }
        bytes[at] = opcode;
        if let Some(modrm) = modrm {
            bytes[at + 1] = modrm;
        }
        encodings.push(bytes);
    };
    // For each `reg` field: a register `ModRM` byte, and two memory ones
    // (with SIB and disp8, and without SIB with disp32), the other fields
    // random.
    let shapes = |random: &mut Random| {
        let mut shapes = Vec::with_capacity(24);
        for reg in 0..8u8 {
            let rm = u8::try_from(random.below(8)).unwrap();
            shapes.push(0xc0 | reg << 3 | rm);
            shapes.push(0x44 | reg << 3);
            shapes.push(0x80 | reg << 3 | (rm & 3));
        }
        shapes
    };
    for map in [&[][..], &[0x0f][..], &[0x0f, 0x38][..], &[0x0f, 0x3a][..]] {
        for prefix in [
            &[][..],
            &[0x66][..],
            &[0xf2][..],
            &[0xf3][..],
            &[0x48][..],
            &[0xf0][..],
            &[0x66, 0x48][..],
            &[0xf2, 0x48][..],
            &[0xf3, 0x48][..],
            &[0xf0, 0x48][..],
            &[0x66, 0xf2][..],
            &[0x66, 0xf3][..],
        ] {
            let lead: Vec<u8> = prefix.iter().chain(map).copied().collect();
            // The `0F` map holds forms told apart by their whole `ModRM`
            // byte (fences, ENDBR, XGETBV): every one, under the mandatory
            // prefixes.
            let every = map == [0x0f] && prefix.len() <= 1 && prefix != [0x48] && prefix != [0xf0];
            for opcode in 0..=255u8 {
                let modrms: Vec<u8> = if every {
                    (0..=255).collect()
                } else {
                    shapes(random)
                };
                for modrm in modrms {
                    push(random, &lead, opcode, Some(modrm));
                }
            }
        }
    }
    for map in 1..=3u8 {
        for l_pp in 0..8u8 {
            for w in [0x00, 0x80] {
                // C4, inverted R X B (all set: no extension), the map; W,
                // vvvv 1111, L and pp.
                let byte2 = w | 0x78 | l_pp;
                let lead = [0xc4, 0xe0 | map, byte2];
                for opcode in 0..=255u8 {
                    for modrm in shapes(random) {
                        push(random, &lead, opcode, Some(modrm));
                    }
                }
            }
        }
    }
    for escape in 0xd8..=0xdfu8 {
        for modrm in 0..=255u8 {
            push(random, &[], escape, Some(modrm));
        }
    }
    encodings
}

/// Instructions whose forms have semantics: from the corpus, then from
/// systematic bytes and `random` random ones (for the operand sizes and
/// prefixes compilers rarely emit), up to `per_form` distinct encodings of
/// each form `wanted` accepts.
pub fn instructions(
    per_form: usize,
    corpus: &[String],
    wanted: &dyn Fn(Form) -> bool,
    random: usize,
) -> Vec<(Form, Vec<u8>, Instruction)> {
    let mut by_form: BTreeMap<Form, Vec<(Vec<u8>, Instruction)>> = BTreeMap::new();
    for path in corpus {
        for found in support::sweep(path) {
            let form = found.instruction.form();
            if !wanted(form) {
                continue;
            }
            let list = by_form.entry(form).or_default();
            if list.len() >= per_form || list.iter().any(|(bytes, _)| *bytes == found.bytes) {
                continue;
            }
            if lift(&found.instruction, Mode::Bits64, CODE).is_ok() {
                list.push((found.bytes, found.instruction));
            }
        }
    }
    let mut generator = Random(0x0123_4567_89ab_cdef);
    let systematic = systematic_encodings(&mut generator);
    let random_ones = (0..random).map(|_| random_encoding(&mut generator));
    let all: Vec<[u8; 15]> = systematic.into_iter().chain(random_ones).collect();
    for bytes in all {
        let Ok(instruction) = decode(&bytes, Mode::Bits64) else {
            continue;
        };
        if !wanted(instruction.form()) {
            continue;
        }
        let bytes = bytes[..instruction.len()].to_vec();
        let list = by_form.entry(instruction.form()).or_default();
        if list.len() < per_form
            && !list.iter().any(|(b, _)| *b == bytes)
            && !rex2(&bytes)
            && lift(&instruction, Mode::Bits64, CODE).is_ok()
        {
            list.push((bytes, instruction));
        }
    }
    by_form
        .into_iter()
        .flat_map(|(form, list)| list.into_iter().map(move |(b, i)| (form, b, i)))
        .collect()
}

/// The CPUs this process (and so the oracle) may run on, as Linux lists
/// them (`0-15`).
pub fn allowed_cpus() -> String {
    let status = std::fs::read_to_string("/proc/self/status").unwrap();
    status
        .lines()
        .find_map(|line| line.strip_prefix("Cpus_allowed_list:"))
        .unwrap()
        .trim()
        .to_owned()
}

/// A core type of a hybrid processor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Core {
    /// A performance core (`/sys/devices/cpu_core/cpus`).
    Performance,
    /// An efficiency core (`/sys/devices/cpu_atom/cpus`).
    Efficiency,
}

/// The core type every CPU of `cpus` is, on a hybrid processor; `None` if
/// they mix types or the processor is not hybrid.
pub fn core_type(cpus: &str) -> Option<Core> {
    let allowed = cpu_list(cpus);
    let of = |path: &str| {
        std::fs::read_to_string(path).is_ok_and(|list| allowed.is_subset(&cpu_list(list.trim())))
    };
    if of("/sys/devices/cpu_core/cpus") {
        Some(Core::Performance)
    } else if of("/sys/devices/cpu_atom/cpus") {
        Some(Core::Efficiency)
    } else {
        None
    }
}

/// The CPUs of a Linux CPU list (`0-15,20`).
pub fn cpu_list(text: &str) -> BTreeSet<u32> {
    text.split(',')
        .filter(|range| !range.is_empty())
        .flat_map(|range| {
            let (first, last) = range.split_once('-').unwrap_or((range, range));
            first.parse().unwrap()..=last.parse().unwrap()
        })
        .collect()
}
