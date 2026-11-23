//! L0 against an AArch64 processor: each encoding with semantics, in words
//! from a sweep of its fields, runs once in the L0 interpreter and once on
//! the processor (`tools/cpu-oracle-aarch64`) from the same state, and the
//! results must agree on every bit L0 defines.
//!
//! ```sh
//! sh scripts/cpu-oracle-aarch64.sh
//! # natively on AArch64 Linux:
//! BINBUN_CPU_ORACLE_AARCH64=target/cpu-oracle-aarch64 \
//!   cargo test --release -p binbun-aarch64-lift --test hardware -- --ignored --nocapture
//! # elsewhere, under qemu:
//! BINBUN_CPU_ORACLE_AARCH64="qemu-aarch64 -cpu max target/cpu-oracle-aarch64" \
//!   cargo test --release -p binbun-aarch64-lift --test hardware -- --ignored --nocapture
//! ```
//!
//! `BINBUN_CPU_ORACLE_AARCH64` is a command: words separated by spaces.
//!
//! - `BINBUN_LIFT_PER_FORM`: distinct words per encoding (default 40).
//! - `BINBUN_LIFT_STATES`: states per word (default 8).
//! - `BINBUN_LIFT_SEED`: the random seed.
//! - `BINBUN_LIFT_REPORT`: a file to write every mismatch to.
//! - `BINBUN_LIFT_FORMS`: comma-separated beginnings of encoding names (as
//!   `ADD_64`, `LDP`); only encodings whose name starts with one are run.
//!
//! Words come from Arm's specification (AARCHMRS): for every encoding, each
//! value of each field of up to 5 free bits and the edge values of longer
//! fields, other bits random, and random words, the fixed bits held; those
//! that decode, lift, and are not CONSTRAINED UNPREDICTABLE (writeback to a
//! transferred register, a load pair into one register) are kept.
//! Crafted cases ([`CRAFTED`]: edge values random states almost never
//! reach) run too, in every run that covers their encoding.
//!
//! States are random with a bias to edge values; a memory operand's base
//! register points into a mappable window (in a sixteenth of the states
//! into an unmapped one, through a tagged pointer, or outside the user
//! address range) and the stack pointer at a stack page, 16-aligned except
//! in an eighth of the states. The interpreter runs first on lazily
//! invented memory; the bytes it touches become the oracle's memory
//! regions, with the same contents. L0's load and store addresses are
//! virtual, tag byte included; the interpreter's machine translates them
//! as Linux EL0 does (bit 55 clear: the tag byte is ignored; set: the
//! kernel half, which faults), and addresses outside the user range (48
//! bits) or in the unmapped window fault, as on the processor.
//!
//! The processor's traits are probed first: whether it checks SP
//! alignment (Linux sets `SCTLR_EL1.SA0`; qemu does not check), whether it
//! keeps BTYPE (`FEAT_BTI`), whether SB leaves BTYPE alone (qemu's does;
//! Arm's clears it: BTYPE is then not compared after SB), whether TCO
//! sticks (`FEAT_MTE`; else states keep it 0), whether failed
//! authentications fault (`FEAT_FPAC`, and `FEAT_FPACCOMBINE` for the
//! branches), whether a data pointer with bit 55 set keeps its top byte
//! (`TCR_EL1.TBI1`), whether a failing store exclusive raises alignment
//! and translation faults, and which FPCR and FPSR bits it implements.
//! Features some processors lack ([`FEATURE_PROBES`]: qemu has no
//! `FEAT_LRCPC3`, the Apple M3 no `FEAT_CSSC`, `FEAT_CMPBR`, `FEAT_HBC`,
//! `FEAT_MTE`, `FEAT_XS`) are probed with a word that needs them; cases of
//! an encoding (or word: MSR and MRS of TCO need `FEAT_MTE`) that needs a
//! lacking feature are counted, not run, and listed.
//! Where it does not check SP alignment, an L0 SP alignment trap is
//! counted, not run; without BTI, BTYPE is not compared. Where a probe
//! found the processor differs from L0's context in a way Arm permits, the
//! cases it shows in are counted, not compared ([`Tally::excused`]): an L0
//! authentication trap the processor does not take, leaving the pointer
//! corrupted; with `TBI1` = 0, data-key PAC instructions on a pointer with
//! bit 55 set (not run); an L0 alignment trap of a failing store exclusive
//! the processor completes with status 1; a failing store exclusive the
//! processor faults on translation where L0's fails. A branch to itself
//! (which the oracle cannot run to an end) agrees if L0 also branches to
//! the instruction.
//! Where the kernel rewrites SSBS at context switches (it keeps SSBS but
//! its `ID_AA64PFR1_EL1` shows none), a case ending with SSBS 1 where L0's
//! is 0 is run once more.
//!
//! Instructions with SIMD&FP register operands also get random vector and
//! FPCR/FPSR state, sent to the oracle and compared afterwards; the others
//! run with the process's floating-point state, which is not compared.
//!
//! Every case also sends a random thread pointer (`tpidr_el0`) and `DIT`,
//! `SSBS`, `TCO`, compared afterwards with `tpidrro_el0`. Intrinsics the
//! oracle can answer are answered by it: `system_register` by running MRS
//! of the register (but the counters, which move), `compute_pac` by running
//! the PAC instruction of the key on the extended pointer (the keys are
//! the oracle's process's: every case forks from it), which gives the bits
//! of the code that `AddPAC` and `Auth` use. Half the cases of an instruction
//! that authenticates a pointer start with it signed by the matching PAC
//! instruction on the oracle, so authentication succeeds as often as it
//! fails. A store exclusive fails (each case starts with the local monitor
//! clear); the bytes it would store are mapped all the same. Encodings that
//! always enter the system (SVC) are never sent.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers fail loudly"
)]

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt::Write as _;
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use binbun_aarch64::operand::{Memory, Offset, Register, RegisterClass, Writeback};
use binbun_aarch64::{Encoding, Feature, Instruction, MemoryKind, Operand, decode};
use binbun_aarch64_lift::registers::{
    self, BTYPE, C, DIT, FPCR, FPSR, N, SP, SSBS, TCO, TPIDR_EL0, TPIDRRO_EL0, V, Z,
};
use binbun_aarch64_lift::{AARCH64, ENCODINGS, lift};
use binbun_semantics::bits::Bits;
use binbun_semantics::interpret::{self, Fault, Machine, Outcome, Value};
use binbun_semantics::ir::{IntrinsicId, RegisterId, Trap};
use xtask::aarchmrs::Package;

/// Where code goes (plus up to 2^20 pages). Every address here is below
/// 2^39, so that kernels with 39-bit user address spaces can map it.
const CODE: u64 = 0x55_0000_0000;
/// Where memory operands point (a page-aligned base plus up to 16 pages).
const WINDOW: u64 = 0x3c_3c00_0000;
/// Never mapped: accesses here fault.
const UNMAPPED: u64 = 0x4d_4d00_0000;
/// The stack pointer's page.
const STACK: u64 = 0x2b_2b00_8000;
/// The smallest page size; larger pages only map more of the same.
const PAGE: u64 = 4096;
const WINDOW_SIZE: u64 = 16 * PAGE;
/// User addresses (after the tag byte is dropped) are below this.
const USER_END: u64 = 1 << 48;

/// `ldr x0, [sp]`, `br x16`, `orr x0, xzr, x0` (`mov x0, x0`).
const LDR_SP: u32 = 0xf940_03e0;
const BR_X16: u32 = 0xd61f_0200;
const MOV_X0: u32 = 0xaa00_03e0;
/// `sb`.
const SB: u32 = 0xd503_30ff;
/// `pacia x1, x2`.
const PACIA_X1_X2: u32 = 0xdac1_0041;
/// `autia x1, x2`, `braa x1, x2`, `xpacd x1`.
const AUTIA_X1_X2: u32 = 0xdac1_1041;
const BRAA_X1_X2: u32 = 0xd71f_0822;
const XPACD_X1: u32 = 0xdac1_47e1;
/// `stxr w0, x2, [x1]`.
const STXR_W0_X2_X1: u32 = 0xc800_7c22;
/// `mrs x0, ID_AA64PFR1_EL1`.
const MRS_ID_AA64PFR1: u32 = 0xd538_0420;

const PACKAGE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../third_party/aarchmrs/AARCHMRS_OPENSOURCE_A_profile_FAT-2026-09.tar.gz"
);

struct Random(u64);

impl Random {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }

    /// A register value, often an edge case of 64 or 32 bits.
    fn value(&mut self) -> u64 {
        match self.below(14) {
            0 => 0,
            1 => u64::MAX,
            2 => 1,
            3 => 1 << self.below(64),
            4 => (1 << self.below(64)) - 1,
            5 => self.below(64),
            6 => 0x7fff_ffff_ffff_ffff,
            7 => 0x8000_0000_0000_0000,
            8 => 0xffff_ffff,
            9 => 0x8000_0000 | (self.next() & !0xffff_ffff),
            10 => 0x7fff_ffff | (self.next() & !0xffff_ffff),
            11 => self.next() & 0xffff_ffff,
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

    /// An address in the mappable window, half of them 16-aligned.
    fn window(&mut self) -> u64 {
        let target = WINDOW + self.below(16) * PAGE + self.below(PAGE);
        if self.below(2) == 0 {
            target & !15
        } else {
            target
        }
    }
}

struct Oracle {
    child: Child,
    input: ChildStdin,
    output: BufReader<ChildStdout>,
}

impl Oracle {
    /// Starts `command` (words separated by spaces).
    fn start(command: &str) -> Self {
        let mut words = command.split_whitespace();
        let program = words.next().expect("an oracle command");
        let mut child = Command::new(program)
            .args(words)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap_or_else(|e| panic!("{command}: {e}"));
        let input = child.stdin.take().unwrap();
        let output = BufReader::new(child.stdout.take().unwrap());
        Self {
            child,
            input,
            output,
        }
    }

    fn ask(&mut self, line: &str) -> String {
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

/// What the processor behind the oracle does where processors may differ.
#[expect(
    clippy::struct_excessive_bools,
    reason = "independent traits of the processor"
)]
struct Platform {
    /// A load or store with a misaligned SP base faults (`SCTLR_EL1.SA0`).
    sp_alignment: bool,
    /// BTYPE is kept (`FEAT_BTI`).
    bti: bool,
    /// SB leaves BTYPE as it was (qemu 11.1's SB ends its translation block
    /// before BTYPE is reset; Arm's SB, as every instruction that is not a
    /// branch, sets it to 0). Then BTYPE is not compared after SB.
    sb_keeps_btype: bool,
    /// `AddPAC` takes the upper-half pointer's extension from bit 63 rather
    /// than bit 55 (qemu 11.1 picks `ptr<63>` when the selected range has
    /// no top-byte-ignore; Arm's `AddPAC` uses `ptr<55>` whenever either
    /// range has it, as `TCR_EL1.TBI0` here). PAC instructions on a pointer
    /// with bit 55 set and bit 63 clear are then not compared.
    pac_extends_bit63: bool,
    /// `PSTATE.TCO` is implemented (`FEAT_MTE`; without it TCO is RAZ/WI and
    /// states keep it 0).
    tco: bool,
    /// A failed AUT* faults (`FEAT_FPAC`).
    fpac: bool,
    /// A failed BRAA, BLRAA, RETAA (and their forms) faults
    /// (`FEAT_FPACCOMBINE`; the Apple M3 branches to the corrupted pointer).
    fpac_combined: bool,
    /// A data pointer with bit 55 set keeps its top byte in PAC
    /// instructions (`TCR_EL1.TBI1` = `TBID1` = 1, as Linux sets them with
    /// `CONFIG_ARM64_MTE`; qemu-user sets `TBI0` only). Data-key PAC
    /// instructions on such a pointer are otherwise not compared.
    tbi1: bool,
    /// A misaligned store exclusive faults although the monitors fail
    /// (Arm's order; qemu 11.1 checks the monitor first). A store exclusive
    /// L0 traps there is otherwise not compared.
    exclusive_alignment: bool,
    /// A failing store exclusive takes translation faults (IMPLEMENTATION
    /// DEFINED: the Apple M3 does; Arm's pseudocode, qemu and L0 check the
    /// monitor first). Such faults are then counted, not compared.
    exclusive_aborts: bool,
    /// The kernel rewrites `PSTATE.SSBS` when it switches to the process:
    /// the processor keeps SSBS, but the kernel did not find `FEAT_SSBS`
    /// (`ID_AA64PFR1_EL1.SSBS` = 0 as it shows EL0; Apple M3 under
    /// Hypervisor.framework), so it sets SSBS from its Spectre-v4 policy
    /// at every context switch (`ssbs_thread_switch`), 1 for a process that
    /// has not asked for the mitigation. A case preempted mid-way then ends
    /// with SSBS 1: a case where only that differs is run again.
    ssbs_switched: bool,
    /// The FPCR and FPSR bits it implements.
    fpcr: u32,
    fpsr: u32,
    /// The features of [`FEATURE_PROBES`] it lacks.
    lacking: Vec<Feature>,
}

/// Features a processor may lack, each with a probe word that needs it
/// (run with x1 at 16 zero bytes of the stack page): the processor lacks
/// the feature if it answers SIGILL. Encodings that need a lacking feature
/// are counted, not compared.
const FEATURE_PROBES: [(Feature, u32); 6] = [
    // ldapr w0, [x1], #4 (qemu 11.1 has no FEAT_LRCPC3).
    (Feature::LRCPC3, 0x99c0_0820),
    // abs x0, x0; cbeq x0, #0, .+4; bc.eq .+4; addg x0, x1, #0, #0; dsb
    // oshnxs (the Apple M3 has none of these).
    (Feature::CSSC, 0xdac0_2000),
    (Feature::CMPBR, 0xf5c0_0020),
    (Feature::HBC, 0x5400_0030),
    (Feature::MTE, 0x9180_0020),
    (Feature::XS, 0xd503_323f),
];

/// Asks the oracle `line`, a probe that must run (or fault).
fn probe(oracle: &mut Oracle, line: &str) -> Answer {
    let answer = parse(&oracle.ask(line));
    assert!(
        matches!(answer.kind.as_str(), "ok" | "fault"),
        "the oracle answers `{line}` with {}",
        answer.raw
    );
    answer
}

fn sigill(answer: &Answer) -> bool {
    answer.kind == "fault" && answer.values.contains_key("SIGILL")
}

impl Platform {
    fn probe(oracle: &mut Oracle) -> Self {
        let mut ask = |line: String| probe(oracle, &line);
        let sp = ask(format!(
            "case {CODE:x} {LDR_SP:08x} sp={:x} mem={STACK:x}:{}",
            STACK + 8,
            "00".repeat(16)
        ));
        let br = ask(format!("case {CODE:x} {BR_X16:08x} x16={UNMAPPED:x}"));
        let sb = ask(format!("case {CODE:x} {SB:08x} btype=3"));
        let tco = ask(format!("case {CODE:x} {MOV_X0:08x} tco=1"));
        let ssbs = ask(format!("case {CODE:x} {MOV_X0:08x} ssbs=1"));
        let pfr1 = ask(format!("case {CODE:x} {MRS_ID_AA64PFR1:08x}"));
        let xpacd = ask(format!("case {CODE:x} {XPACD_X1:08x} x1=2b80000012345000"));
        // PACIA x1, x2 on two pointers with bit 55 set, bit 63 clear and
        // set: with Arm's extension both are signed as 0xffff..., so their
        // codes in bits 54:48 agree; with bit 63's they differ (but by a
        // 1 in 128 chance, twice over).
        let codes: Vec<u64> = [0x0080, 0xff80, 0x0081, 0xff81]
            .iter()
            .map(|top: &u64| {
                let pointer = top << 48 | 0x1234_5000;
                let answer = ask(format!("case {CODE:x} {PACIA_X1_X2:08x} x1={pointer:x}"));
                (answer.values["x1"] ^ pointer) >> 48 & 0x7f
            })
            .collect();
        let fp = ask(format!(
            "case {CODE:x} {MOV_X0:08x} fpcr=ffffffff fpsr=ffffffff"
        ));
        let word = |name: &str| u32::try_from(fp.values[name]).unwrap();
        let lacking = FEATURE_PROBES
            .iter()
            .filter(|&&(_, probe)| {
                sigill(&ask(format!(
                    "case {CODE:x} {probe:08x} x1={STACK:x} mem={STACK:x}:{}",
                    "00".repeat(16)
                )))
            })
            .map(|&(feature, _)| feature)
            .collect();
        let (fpac, fpac_combined) = Self::probe_authentication(oracle);
        let (exclusive_alignment, exclusive_aborts) = Self::probe_exclusive(oracle);
        let platform = Self {
            sp_alignment: sp.kind == "fault",
            bti: br.values.get("btype") == Some(&1),
            sb_keeps_btype: sb.values.get("btype") == Some(&3),
            pac_extends_bit63: codes[0] != codes[1] && codes[2] != codes[3],
            tco: tco.values.get("tco") == Some(&1),
            ssbs_switched: ssbs.values.get("ssbs") == Some(&1)
                && pfr1.values.get("x0").is_some_and(|value| value & 0xf0 == 0),
            fpac,
            fpac_combined,
            tbi1: xpacd.values.get("x1") == Some(&0x2bff_0000_1234_5000),
            exclusive_alignment,
            exclusive_aborts,
            fpcr: word("fpcr"),
            fpsr: word("fpsr"),
            lacking,
        };
        platform.describe();
        platform
    }

    /// Whether a failed AUTIA and a failed BRAA fault (`FEAT_FPAC`,
    /// `FEAT_FPACCOMBINE`): both on a pointer signed by PACIA with one bit
    /// of its code flipped, which never authenticates.
    fn probe_authentication(oracle: &mut Oracle) -> (bool, bool) {
        let signed = probe(
            oracle,
            &format!("case {CODE:x} {PACIA_X1_X2:08x} x1=12345000 x2=0"),
        );
        assert_eq!(signed.kind, "ok", "pacia: {}", signed.raw);
        let corrupted = signed.values["x1"] ^ 1 << 50;
        let [autia, braa] = [AUTIA_X1_X2, BRAA_X1_X2].map(|word| {
            sigill(&probe(
                oracle,
                &format!("case {CODE:x} {word:08x} x1={corrupted:x} x2=0"),
            ))
        });
        (autia, braa)
    }

    /// Whether a store exclusive that fails (the monitors are clear when a
    /// case starts) faults when it crosses an aligned 16-byte block, and
    /// when its address is unmapped.
    fn probe_exclusive(oracle: &mut Oracle) -> (bool, bool) {
        let misaligned = probe(
            oracle,
            &format!(
                "case {CODE:x} {STXR_W0_X2_X1:08x} x1={:x} mem={STACK:x}:{}",
                STACK + 12,
                "00".repeat(32)
            ),
        );
        let unmapped = probe(
            oracle,
            &format!("case {CODE:x} {STXR_W0_X2_X1:08x} x1={UNMAPPED:x}"),
        );
        (
            misaligned.kind == "fault" && misaligned.values.contains_key("SIGBUS"),
            unmapped.kind == "fault",
        )
    }

    fn describe(&self) {
        println!(
            "processor: SP alignment checked {}, BTI {}, SB keeps BTYPE {}, AddPAC extends bit \
             63 {}, TCO {}, FPAC {}, FPACCOMBINE {}, TBI1 {}, failing store exclusives check \
             alignment {} and translation {}, SSBS rewritten at context switches {}, FPCR bits \
             {:x}, FPSR bits {:x}, lacking {:?}",
            self.sp_alignment,
            self.bti,
            self.sb_keeps_btype,
            self.pac_extends_bit63,
            self.tco,
            self.fpac,
            self.fpac_combined,
            self.tbi1,
            self.exclusive_alignment,
            self.exclusive_aborts,
            self.ssbs_switched,
            self.fpcr,
            self.fpsr,
            self.lacking.iter().map(|f| f.name()).collect::<Vec<_>>()
        );
    }
}

/// The interpreter's machine: registers, and memory invented on first
/// touch (remembered, so the oracle gets the same contents); intrinsics the
/// oracle can answer, while it lends itself.
struct Test<'o> {
    registers: HashMap<RegisterId, Value>,
    memory: BTreeMap<u64, u8>,
    /// The undefined bits of stored bytes (absent: all defined).
    undefined: BTreeMap<u64, u8>,
    initial: BTreeMap<u64, u8>,
    /// The code's address and word: its page holds the word, else zeros.
    code: (u64, u32),
    /// A store exclusive's address and size.
    exclusive: Option<(u64, u64)>,
    random: Random,
    oracle: Option<&'o mut Oracle>,
}

/// Whether an access to `address` faults: outside the user range, or in
/// the unmapped window.
fn faults(address: u64) -> bool {
    address >= USER_END || (UNMAPPED..UNMAPPED + WINDOW_SIZE + PAGE).contains(&address)
}

impl Test<'_> {
    fn byte(&mut self, address: u64) -> u8 {
        if let Some(&byte) = self.memory.get(&address) {
            return byte;
        }
        let (start, word) = self.code;
        let page = start & !(PAGE - 1);
        let byte = if (page..page + PAGE).contains(&address) {
            address
                .checked_sub(start)
                .and_then(|offset| {
                    word.to_le_bytes()
                        .get(usize::try_from(offset).ok()?)
                        .copied()
                })
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

    /// Where an access of `bytes` bytes at virtual address `address` (as
    /// L0 computes it, tag included) lands, translated as Linux EL0 does:
    /// with bit 55 clear the tag byte is ignored (`TCR_EL1.TBI0`); with it
    /// set the address is in the kernel half and faults. The fault, if
    /// any, names the virtual address.
    fn translate(address: u64, bytes: u64, write: bool) -> Result<u64, Fault> {
        let physical = if address >> 55 & 1 == 0 {
            address & 0x00ff_ffff_ffff_ffff
        } else {
            address
        };
        if (0..bytes).any(|i| faults(physical.wrapping_add(i))) {
            return Err(Fault { address, write });
        }
        Ok(physical)
    }

    /// What register `name` holds after `word` runs on the oracle from
    /// `registers` (name and value), if the oracle runs it.
    fn run_on_oracle(&mut self, word: u32, registers: &str, name: &str) -> Option<u64> {
        let oracle = self.oracle.as_mut()?;
        let answer = parse(&oracle.ask(&format!("case {CODE:x} {word:08x} {registers}")));
        (answer.kind == "ok").then(|| answer.values.get(name).copied())?
    }

    /// `compute_pac(data, modifier, key)` as far as the oracle tells: the
    /// code's bits that the PAC instruction of the key XORs into an
    /// extended pointer (54:48, and 63:56 for an instruction key in the
    /// upper half, whose top byte a data pointer's keeps; PACGA gives
    /// 63:32), the others unknown.
    fn compute_pac(&mut self, inputs: &[Value]) -> Value {
        let unknown = Value::unknown(64);
        let [data, modifier, key] = inputs else {
            return unknown;
        };
        if [data, modifier, key].iter().any(|v| !v.undefined.is_zero()) {
            return unknown;
        }
        let (data, modifier) = (data.bits.low_u64(), modifier.bits.low_u64());
        let registers = format!("x1={data:x} x2={modifier:x}");
        let code = match key.bits.low_u64() {
            // PACGA x0, x1, x2: the code's top half.
            4 => self
                .run_on_oracle(0x9ac2_3020, &registers, "x0")
                .map(|result| (result, 0xffff_ffff_0000_0000)),
            // PACIA, PACIB, PACDA, PACDB x1, x2: the PAC field XORed in.
            key @ 0..4 => {
                let word = 0xdac1_0041 | u32::try_from(key).unwrap() << 10;
                let field = if data >> 55 & 1 == 1 && key < 2 {
                    0xff7f_0000_0000_0000
                } else {
                    0x007f_0000_0000_0000
                };
                self.run_on_oracle(word, &registers, "x1")
                    .map(|result| (result ^ data, field))
            }
            _ => None,
        };
        let Some((code, known)) = code else {
            return unknown;
        };
        Value {
            bits: Bits::from_u64(64, code & known),
            undefined: Bits::from_u64(64, !known),
        }
    }

    /// `exclusive_store(address, bytes)`: the access remembered, and its
    /// bytes, unless it faults, invented as a load's are, so that the
    /// oracle maps them (a processor that checks the access whether or not
    /// the monitors pass, as the Apple M3 does, faults on unmapped memory).
    fn exclusive_store(&mut self, inputs: &[Value]) {
        let [address, bytes] = inputs else {
            return;
        };
        if !address.undefined.is_zero() || !bytes.undefined.is_zero() {
            return;
        }
        let (address, bytes) = (address.bits.low_u64(), bytes.bits.low_u64());
        self.exclusive = Some((address, bytes));
        if let Ok(physical) = Self::translate(address, bytes, true) {
            for i in 0..bytes {
                self.byte(physical.wrapping_add(i));
            }
        }
    }

    /// `system_register(encoding)`: MRS of it on the oracle, but for the
    /// counters (`CNTVCT_EL0`, `CNTVCTSS_EL0`), which move.
    fn system_register(&mut self, inputs: &[Value]) -> Value {
        let unknown = Value::unknown(64);
        let [encoding] = inputs else {
            return unknown;
        };
        let encoding = u32::try_from(encoding.bits.low_u64()).unwrap_or(u32::MAX);
        if !encoding_known(encoding) || matches!(encoding, 0xdf02 | 0xdf06) {
            return unknown;
        }
        // MRS x0, <encoding>.
        let word = 0xd520_0000 | encoding << 5;
        self.run_on_oracle(word, "", "x0")
            .map_or(unknown, |value| Value::defined(Bits::from_u64(64, value)))
    }
}

/// Whether a `system_register` input is a 16-bit encoding with op0 = 3 (as
/// MRS's are).
fn encoding_known(encoding: u32) -> bool {
    encoding >> 14 == 3
}

impl Machine for Test<'_> {
    fn read(&mut self, register: RegisterId) -> Value {
        let width = AARCH64.info(register).map_or(64, |info| info.width);
        self.registers
            .get(&register)
            .copied()
            .unwrap_or_else(|| Value::unknown(width))
    }

    fn write(&mut self, register: RegisterId, value: Value) {
        self.registers.insert(register, value);
    }

    fn load(&mut self, address: u64, bytes: u16) -> Result<Value, Fault> {
        let address = Self::translate(address, u64::from(bytes), false)?;
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
        let address = Self::translate(address, u64::from(value.width() / 8), true)?;
        let bytes = value.bits.to_le_bytes().zip(value.undefined.to_le_bytes());
        for (i, (byte, undefined)) in bytes.enumerate() {
            let at = address.wrapping_add(i as u64);
            self.byte(at);
            self.memory.insert(at, byte);
            self.undefined.insert(at, undefined);
        }
        Ok(())
    }

    /// `compute_pac` and `system_register` are answered by the processor;
    /// a store exclusive fails: each case starts with the local monitor
    /// open (the oracle enters it by an exception return, sigreturn, and
    /// Arm's `AArch64.ExceptionReturn` clears the local monitor). Other
    /// intrinsics have no outputs.
    fn intrinsic(
        &mut self,
        intrinsic: IntrinsicId,
        inputs: &[Value],
        outputs: &[u16],
    ) -> Vec<Value> {
        match AARCH64.intrinsic(intrinsic).map(|info| info.name) {
            Some("compute_pac") => vec![self.compute_pac(inputs)],
            Some("system_register") => vec![self.system_register(inputs)],
            Some("exclusive_store") => {
                self.exclusive_store(inputs);
                outputs
                    .iter()
                    .map(|&width| Value::defined(Bits::from_u64(width, 1)))
                    .collect()
            }
            _ => outputs.iter().map(|&width| Value::unknown(width)).collect(),
        }
    }
}

/// Whether `register` is a general register (the zero register or SP
/// included).
const fn general(register: Register) -> bool {
    matches!(
        register.class,
        RegisterClass::W | RegisterClass::X | RegisterClass::Wsp | RegisterClass::Xsp
    )
}

/// Whether the word is CONSTRAINED UNPREDICTABLE in a way the decoder
/// accepts: a load or store writing back to a register it transfers, or a
/// load into the same register twice. Processors differ there.
fn unpredictable(instruction: Instruction) -> bool {
    let operands = instruction.operands();
    let Some(memory) = operands.iter().find_map(|operand| {
        let Operand::Memory(memory) = operand else {
            return None;
        };
        Some(*memory)
    }) else {
        return false;
    };
    let transfers: Vec<u8> = operands
        .iter()
        .filter_map(|operand| {
            let Operand::Register(register) = operand else {
                return None;
            };
            (general(*register) && register.number != 31).then_some(register.number)
        })
        .collect();
    let writeback = memory.writeback != Writeback::None
        && memory.base.number != 31
        && transfers.contains(&memory.base.number);
    let load = instruction
        .memory()
        .is_some_and(|access| access.kind == MemoryKind::Load);
    let twice = load && transfers.len() == 2 && transfers[0] == transfers[1];
    writeback || twice
}

/// Whether `instruction` has a SIMD&FP register operand.
fn uses_fp(instruction: Instruction) -> bool {
    let vector = |register: &Register| {
        matches!(
            register.class,
            RegisterClass::B
                | RegisterClass::H
                | RegisterClass::S
                | RegisterClass::D
                | RegisterClass::Q
                | RegisterClass::V
                | RegisterClass::Z
        )
    };
    instruction.operands().iter().any(|operand| {
        if let Operand::Register(register) = operand {
            vector(register)
        } else if let Operand::List(list) = operand {
            vector(&list.first)
        } else {
            false
        }
    })
}

/// Vector and floating-point control state: `v` registers as two 64-bit
/// words, low first.
struct FpState {
    v: [[u64; 2]; 32],
    fpcr: u32,
    fpsr: u32,
}

impl FpState {
    /// Random state: float edge values in the lanes; random rounding,
    /// flush-to-zero, default NaN, alternative half precision and
    /// alternative handling, and cumulative flags, where implemented.
    fn random(random: &mut Random, platform: &Platform) -> Self {
        // FIZ, AH, NEP; FZ16; RMode, FZ, DN, AHP.
        const CONTROL: u64 = 0x7 | 1 << 19 | 0x1f << 22;
        // IOC DZC OFC UFC IXC IDC, QC.
        const STATUS: u64 = 0x9f | 1 << 27;
        let v = std::array::from_fn(|_| [random.vector_word(), random.vector_word()]);
        let control = u32::try_from(random.next() & CONTROL).unwrap() & platform.fpcr;
        let status = if random.below(2) == 0 {
            0
        } else {
            u32::try_from(random.next() & STATUS).unwrap() & platform.fpsr
        };
        Self {
            v,
            fpcr: control,
            fpsr: status,
        }
    }

    fn write_to(&self, machine: &mut Test) {
        for (i, words) in (0u8..).zip(&self.v) {
            let value = u128::from(words[0]) | u128::from(words[1]) << 64;
            machine.write(registers::v(i), Value::defined(Bits::from_u128(128, value)));
        }
        machine.write(FPCR, Value::defined(Bits::from_u64(32, self.fpcr.into())));
        machine.write(FPSR, Value::defined(Bits::from_u64(32, self.fpsr.into())));
    }

    /// The oracle's input fields.
    fn append_to(&self, line: &mut String) {
        for (i, words) in self.v.iter().enumerate() {
            let value = u128::from(words[0]) | u128::from(words[1]) << 64;
            let _ = write!(line, " v{i}={value:x}");
        }
        let _ = write!(line, " fpcr={:x} fpsr={:x}", self.fpcr, self.fpsr);
    }
}

fn hex(bytes: impl IntoIterator<Item = u8>) -> String {
    bytes.into_iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
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

/// The registers a case starts from, and where its code is.
struct Start {
    code: u64,
    x: [u64; 31],
    sp: u64,
    nzcv: u8,
    btype: u8,
    tpidr: u64,
    /// DIT, SSBS, TCO.
    pstate: [bool; 3],
    /// For instructions with SIMD&FP operands.
    fp: Option<FpState>,
}

impl Start {
    /// Replaces the registers by those `word` (a PAC instruction) leaves on
    /// the oracle, if it runs: the pointer an authenticating instruction
    /// takes is then signed.
    fn sign(&mut self, word: u32, oracle: &mut Oracle) {
        let answer = parse(&oracle.ask(&self.line(word, &BTreeMap::new())));
        if answer.kind != "ok" {
            return;
        }
        for (i, x) in self.x.iter_mut().enumerate() {
            *x = answer.values[&format!("x{i}")];
        }
    }

    /// Random registers, with memory bases and the stack pointer aimed at
    /// mappable addresses. In a quarter of the states the general
    /// registers take values from a pool of three, so that compared and
    /// subtracted registers are now and then equal. TCO stays 0 on a
    /// processor without it.
    fn random(instruction: Instruction, platform: &Platform, random: &mut Random) -> Self {
        let pool = [random.value(), random.value(), random.value()];
        let equal = random.below(4) == 0;
        let mut x: [u64; 31] = std::array::from_fn(|_| {
            if equal {
                pool[usize::try_from(random.below(3)).unwrap()]
            } else {
                random.value()
            }
        });
        let mut sp = STACK + random.below(64) * 16;
        if random.below(8) == 0 {
            sp += 1 + random.below(15);
        }
        for operand in &instruction.operands() {
            if let Operand::Memory(memory) = operand {
                aim(memory, &mut x, random);
            }
        }
        let code = CODE + random.below(1 << 20) * PAGE + random.below(PAGE / 4) * 4;
        Self {
            code,
            x,
            sp,
            nzcv: u8::try_from(random.below(16)).unwrap(),
            btype: u8::try_from(random.below(4)).unwrap(),
            tpidr: random.value(),
            pstate: [
                random.below(2) == 1,
                random.below(2) == 1,
                random.below(2) == 1 && platform.tco,
            ],
            fp: uses_fp(instruction).then(|| FpState::random(random, platform)),
        }
    }

    /// The interpreter's machine in this state for `word`, the rest of
    /// memory invented from `random`.
    fn machine<'o>(&self, word: u32, random: &mut Random) -> Test<'o> {
        let mut machine = Test {
            registers: HashMap::new(),
            memory: BTreeMap::new(),
            undefined: BTreeMap::new(),
            initial: BTreeMap::new(),
            code: (self.code, word),
            exclusive: None,
            random: Random(random.next() | 1),
            oracle: None,
        };
        for (i, &value) in (0u8..).zip(&self.x) {
            machine.write(registers::x(i), Value::defined(Bits::from_u64(64, value)));
        }
        machine.write(SP, Value::defined(Bits::from_u64(64, self.sp)));
        for (id, bit) in [(N, 3), (Z, 2), (C, 1), (V, 0)] {
            let value = Bits::from_bool(self.nzcv >> bit & 1 == 1);
            machine.write(id, Value::defined(value));
        }
        machine.write(BTYPE, Value::defined(Bits::from_u64(2, self.btype.into())));
        machine.write(TPIDR_EL0, Value::defined(Bits::from_u64(64, self.tpidr)));
        for (id, &bit) in [DIT, SSBS, TCO].iter().zip(&self.pstate) {
            machine.write(*id, Value::defined(Bits::from_bool(bit)));
        }
        if let Some(fp) = &self.fp {
            fp.write_to(&mut machine);
        }
        machine
    }

    /// The oracle's `case` line for `word`, with `initial` (the memory the
    /// interpreter read) as memory regions.
    fn line(&self, word: u32, initial: &BTreeMap<u64, u8>) -> String {
        let mut line = format!("case {:x} {word:08x}", self.code);
        for (i, value) in self.x.iter().enumerate() {
            let _ = write!(line, " x{i}={value:x}");
        }
        let _ = write!(
            line,
            " sp={:x} nzcv={:x} btype={:x}",
            self.sp, self.nzcv, self.btype
        );
        let [dit, ssbs, tco] = self.pstate.map(u8::from);
        let _ = write!(
            line,
            " tpidr_el0={:x} dit={dit} ssbs={ssbs} tco={tco}",
            self.tpidr
        );
        if let Some(fp) = &self.fp {
            fp.append_to(&mut line);
        }
        for (address, data) in runs(initial) {
            let _ = write!(line, " mem={address:x}:{}", hex(data));
        }
        line
    }
}

/// The general register an `AddPAC` instruction (PACIA, ..., PACIASP,
/// PACIA1716, ...) signs, if `instruction` is one (not the zero register).
fn signed(instruction: Instruction) -> Option<u8> {
    let name = instruction.encoding().name();
    let register = match name {
        _ if !name.starts_with("PAC") || name.starts_with("PACGA") || name.starts_with("PACM") => {
            return None;
        }
        _ if name.ends_with("_dp_1src") => u8::try_from(instruction.word() & 31).unwrap(),
        _ if name.contains("1716") => 17,
        _ => 30,
    };
    (register < 31).then_some(register)
}

/// The PAC instruction that signs what `instruction` authenticates, with
/// the same key, register and modifier, if it authenticates a pointer.
fn signer(instruction: Instruction) -> Option<u32> {
    let word = instruction.word();
    let name = instruction.encoding().name();
    let n = word >> 5 & 31;
    // BRAx, BLRAx (and their Z forms): M (bit 10) is the key.
    let key = word >> 10 & 1;
    Some(match name {
        // AUTxx (dp_1src): PACxx is the same word with bit 12 clear.
        _ if name.starts_with("AUT") && name.ends_with("_dp_1src") => word & !0x1000,
        // AUTIxSP, AUTIxZ, AUTIx1716: PACIx... with bit 7 clear.
        _ if name.starts_with("AUT") && name.ends_with("_HI_hints") => word & !0x80,
        // BRAx Xn, Xm and BLRAx Xn, Xm: PACIx Xn, Xm.
        "BRAA_64P_branch_reg"
        | "BRAB_64P_branch_reg"
        | "BLRAA_64P_branch_reg"
        | "BLRAB_64P_branch_reg" => 0xdac1_0000 | key << 10 | (word & 31) << 5 | n,
        // BRAxZ Xn and BLRAxZ Xn: PACIZx Xn.
        "BRAAZ_64_branch_reg"
        | "BRABZ_64_branch_reg"
        | "BLRAAZ_64_branch_reg"
        | "BLRABZ_64_branch_reg" => 0xdac1_23e0 | key << 10 | n,
        // RETAx: PACIxSP.
        "RETAA_64E_branch_reg" | "RETAB_64E_branch_reg" => 0xd503_233f | key << 6,
        _ => return None,
    })
}

/// The features `instruction` needs: its encoding's, and `FEAT_MTE` for
/// `PSTATE.TCO` (MSR TCO, #imm: op1 = 3, op2 = 4; MRS and MSR of TCO,
/// `S3_3_C4_C2_7`), which the encodings' conditions do not name.
fn features(instruction: Instruction) -> Vec<Feature> {
    let word = instruction.word();
    let encoding = instruction.encoding();
    let tco = (encoding == Encoding::MSR_SI_pstate && word >> 16 & 7 == 3 && word >> 5 & 7 == 4)
        || (matches!(
            encoding,
            Encoding::MRS_RS_systemmove | Encoding::MSR_SR_systemmove
        ) && word >> 5 & 0x7fff == 0x5a17);
    let mut features = instruction.features().to_vec();
    if tco {
        features.push(Feature::MTE);
    }
    features
}

/// The register holding the data pointer `instruction` signs,
/// authenticates or strips (PACDA, AUTDA, XPACD and their B and Z forms),
/// if it is one (not the zero register).
fn data_pointer(instruction: Instruction) -> Option<u8> {
    let name = instruction.encoding().name();
    let register = u8::try_from(instruction.word() & 31).unwrap();
    let data = ["PACD", "AUTD", "XPACD"]
        .iter()
        .any(|prefix| name.starts_with(prefix));
    (data && register < 31).then_some(register)
}

/// The status register of a store exclusive (STXR, STLXR and their B, H
/// and pair forms), if `instruction` is one.
fn store_exclusive(instruction: Instruction) -> Option<u8> {
    let name = instruction.encoding().name();
    ["STXR", "STLXR", "STXP", "STLXP"]
        .iter()
        .any(|prefix| name.starts_with(prefix))
        .then(|| u8::try_from(instruction.word() >> 16 & 31).unwrap())
}

/// Whether a failed authentication by `instruction` (one [`signer`] knows)
/// went unfaulted on the processor and left the pointer corrupted, as
/// `FEAT_PAuth2` does without `FEAT_FPAC` (AUT*) or `FEAT_FPACCOMBINE` (BRAA,
/// BLRAA, RETAA and their forms, which branch to it): its PAC field not
/// all copies of bit 55.
fn unfaulted_authentication(
    instruction: Instruction,
    answer: &Answer,
    platform: &Platform,
) -> bool {
    let name = instruction.encoding().name();
    let word = instruction.word();
    let (faults, pointer, top_byte_ignored) = if name.starts_with("AUT") {
        let register = if name.ends_with("_dp_1src") {
            word & 31
        } else if name.contains("1716") {
            17
        } else {
            30
        };
        let pointer = answer.values.get(&format!("x{register}")).copied();
        (
            platform.fpac,
            pointer,
            name.starts_with("AUTD") && platform.tbi1,
        )
    } else {
        (
            platform.fpac_combined,
            answer.values.get("pc").copied(),
            false,
        )
    };
    let corrupted = |pointer: u64| {
        let upper = pointer >> 55 & 1 == 1;
        let mask = if upper && !top_byte_ignored {
            0xff7f
        } else {
            0x7f
        };
        pointer >> 48 & mask != if upper { mask } else { 0 }
    };
    !faults
        && signer(instruction).is_some()
        && answer.kind == "ok"
        && pointer.is_some_and(corrupted)
}

/// Aims the base register of `memory` (unless it is SP, which points at
/// the stack already) so that the access lands in the window; in a
/// sixteenth of the states each in the unmapped window, through a tagged
/// pointer, or outside the user address range (bit 55 set). A register
/// offset gets a small value.
fn aim(memory: &Memory, x: &mut [u64; 31], random: &mut Random) {
    let mut displacement = 0u64;
    if let Offset::Immediate(immediate) = memory.offset
        && memory.writeback != Writeback::Post
    {
        displacement = immediate.value;
    }
    if let Offset::Register { index, .. } = memory.offset
        && general(index)
        && index.number != 31
    {
        x[usize::from(index.number)] = random.below(64);
    }
    if !general(memory.base) || memory.base.number == 31 {
        return;
    }
    let tag = random.next() & 0xff00_0000_0000_0000;
    let target = match random.below(16) {
        0 => UNMAPPED + random.below(WINDOW_SIZE),
        1 => tag | random.window(),
        2 => tag | 1 << 55 | random.window(),
        _ => random.window(),
    };
    x[usize::from(memory.base.number)] = target.wrapping_sub(displacement);
}

/// The oracle's answer, parsed: kind, values, memory regions; `v`
/// registers, which may not fit 64 bits, in `wide`.
struct Answer {
    raw: String,
    kind: String,
    values: HashMap<String, u64>,
    wide: HashMap<String, Bits>,
    memory: BTreeMap<u64, u8>,
}

fn parse(answer: &str) -> Answer {
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
        } else if name.starts_with('v') {
            let number = u128::from_str_radix(value, 16).unwrap();
            wide.insert(name.to_owned(), Bits::from_u128(128, number));
        } else if let Ok(number) = u64::from_str_radix(value.trim_start_matches('-'), 16) {
            values.insert(name.to_owned(), number);
        }
    }
    Answer {
        raw: answer.to_owned(),
        kind,
        values,
        wide,
        memory,
    }
}

/// Whether the processor's fault address `cpu` fits L0's fault at
/// `address`: within the 16 bytes from it (an access crossing into an
/// unmapped page reports the page), the tag byte ignored; or 0, which qemu
/// reports for addresses outside the address range.
fn fault_address_fits(cpu: u64, address: u64) -> bool {
    const LOW: u64 = 0x00ff_ffff_ffff_ffff;
    cpu == 0 || (cpu & LOW).wrapping_sub(address & LOW) & LOW < 16
}

/// Where execution continues if the processor agrees with `outcome`: after
/// a fault, at the instruction (`code`, exceptions being precise); else at
/// the next one or the target. `None` if they disagree.
fn resumes_at(outcome: Outcome, answer: &Answer, code: u64) -> Option<u64> {
    let signal = |name: &str| answer.values.contains_key(name);
    let address = answer.values.get("addr").copied().unwrap_or(0);
    match (outcome, answer.kind.as_str()) {
        (Outcome::Next, "ok") => Some(code.wrapping_add(4)),
        (Outcome::Transfer(target), "ok") => Some(target),
        (Outcome::Fault(fault), "fault")
            if (signal("SIGSEGV") || signal("SIGBUS"))
                && fault_address_fits(address, fault.address) =>
        {
            Some(code)
        }
        (Outcome::Trap(Trap::Stack | Trap::Alignment), "fault") if signal("SIGBUS") => Some(code),
        (Outcome::Trap(Trap::Protection), "fault") if signal("SIGSEGV") || signal("SIGBUS") => {
            Some(code)
        }
        (Outcome::Trap(Trap::InvalidInstruction | Trap::Authentication), "fault")
            if signal("SIGILL") =>
        {
            Some(code)
        }
        (Outcome::Trap(Trap::Breakpoint), "fault") if signal("SIGTRAP") => Some(code),
        (Outcome::Trap(Trap::FloatingPoint), "fault") if signal("SIGFPE") => Some(code),
        _ => None,
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

/// Differences between the interpreter's state and the processor's: pc,
/// the general registers, SP, the flags, BTYPE (if `btype`: the processor
/// keeps it, as the instruction should), the thread pointers, DIT, SSBS,
/// TCO, and after an instruction that completed, memory. After a fault the
/// processor may have written part of a store; L0's precise exception
/// writes none, so memory is not compared then.
fn compare(machine: &mut Test, answer: &Answer, pc: u64, btype: bool, wrong: &mut Vec<String>) {
    let cpu = |name: &str| Bits::from_u64(64, answer.values.get(name).copied().unwrap_or(0));
    let cpu_pc = cpu("pc").low_u64();
    if cpu_pc != pc {
        wrong.push(format!("pc: L0 {pc:x}, CPU {cpu_pc:x}"));
    }
    for i in 0..31u8 {
        let name = format!("x{i}");
        differ(machine.read(registers::x(i)), cpu(&name), &name, wrong);
    }
    differ(machine.read(SP), cpu("sp"), "sp", wrong);
    let nzcv = cpu("nzcv").low_u64();
    for (id, name, bit) in [(N, "n", 3), (Z, "z", 2), (C, "c", 1), (V, "v", 0)] {
        differ(
            machine.read(id),
            Bits::from_bool(nzcv >> bit & 1 == 1),
            name,
            wrong,
        );
    }
    if btype {
        differ(machine.read(BTYPE), cpu("btype"), "btype", wrong);
    }
    for (id, name) in [
        (TPIDR_EL0, "tpidr_el0"),
        (TPIDRRO_EL0, "tpidrro_el0"),
        (DIT, "dit"),
        (SSBS, "ssbs"),
        (TCO, "tco"),
    ] {
        differ(machine.read(id), cpu(name), name, wrong);
    }
    if answer.kind != "ok" {
        return;
    }
    for (address, &byte) in &answer.memory {
        let ours = machine.memory.get(address).copied().unwrap_or(0);
        let defined = !machine.undefined.get(address).copied().unwrap_or(0);
        if (ours ^ byte) & defined != 0 {
            wrong.push(format!("[{address:x}]: L0 {ours:02x}, CPU {byte:02x}"));
        }
    }
}

/// Differences in the vector registers, FPCR and FPSR.
fn compare_fp(machine: &mut Test, answer: &Answer, wrong: &mut Vec<String>) {
    for i in 0..32u8 {
        let name = format!("v{i}");
        let cpu = answer.wide.get(&name).copied().unwrap_or(Bits::zero(128));
        differ(machine.read(registers::v(i)), cpu, &name, wrong);
    }
    for (id, name) in [(FPCR, "fpcr"), (FPSR, "fpsr")] {
        let cpu = Bits::from_u64(64, answer.values.get(name).copied().unwrap_or(0));
        differ(machine.read(id), cpu, name, wrong);
    }
}

/// The low bits of `value` scattered to the set bits of `mask`.
fn deposit(value: u32, mask: u32) -> u32 {
    let mut out = 0;
    let mut rest = mask;
    let mut index = 0;
    while rest != 0 {
        let bit = rest.isolate_lowest_one();
        if value & (1 << index) != 0 {
            out |= bit;
        }
        rest &= rest - 1;
        index += 1;
    }
    out
}

/// Words of an AARCHMRS encoding: each value of every free field of up to
/// 5 bits and the edge values (0, 1, all ones and all ones but the lowest
/// bit) of longer fields, twice each with the other free bits random, and
/// 64 random words; fixed bits held. Should-be bits are held at their
/// specified values if `should_be`, else free (other values are
/// CONSTRAINED UNPREDICTABLE, and most such words do not decode as the
/// encoding: an encoding with should-be register fields gets words only
/// with them held).
fn encoding_words(
    instruction: &xtask::aarchmrs::Instruction,
    should_be: bool,
    random: &mut Random,
) -> Vec<u32> {
    let mut fixed_mask = 0u32;
    let mut fixed_value = 0u32;
    let mut fields = Vec::new();
    for field in &instruction.encoding.fields {
        let soft = if should_be {
            0
        } else {
            field.should_be_mask.value()
        };
        let mask = u32::try_from((field.value.mask() & !soft) << field.start).unwrap();
        fixed_mask |= mask;
        fixed_value |= u32::try_from((field.value.value() & !soft) << field.start).unwrap();
        let free =
            u32::try_from((((1u64 << field.width) - 1) << field.start) & !u64::from(mask)).unwrap();
        if free != 0 {
            fields.push(free);
        }
    }
    let word = |random: &mut Random| {
        let bits = u32::try_from(random.next() >> 32).unwrap();
        (bits & !fixed_mask) | fixed_value
    };
    let mut words = Vec::new();
    for &free in &fields {
        let width = free.count_ones();
        let values: Vec<u32> = if width > 5 {
            let ones = (1u32 << width) - 1;
            vec![0, 1, ones, ones - 1]
        } else {
            (0..1u32 << width).collect()
        };
        for value in values {
            for _ in 0..2 {
                words.push((word(random) & !free) | deposit(value, free));
            }
        }
    }
    words.extend((0..64).map(|_| word(random)));
    words
}

/// Instructions with semantics: up to `per_form` distinct words of each
/// encoding the lifter supports, chosen at random from its sweep words.
fn instructions(per_form: usize, random: &mut Random) -> Vec<Instruction> {
    let package = Package::read(PACKAGE).unwrap();
    let only = std::env::var("BINBUN_LIFT_FORMS").unwrap_or_default();
    let wanted = |encoding: Encoding| {
        only.is_empty()
            || only
                .split(',')
                .any(|prefix| encoding.name().starts_with(prefix.trim()))
    };
    let mut by_encoding: BTreeMap<Encoding, Vec<Instruction>> = BTreeMap::new();
    for (_, encoding) in package.a64.encodings() {
        let mut words = encoding_words(encoding, true, random);
        words.extend(encoding_words(encoding, false, random));
        for word in words {
            let Ok(instruction) = decode(word) else {
                continue;
            };
            if !wanted(instruction.encoding())
                || unpredictable(instruction)
                || lift(&instruction, CODE).is_err()
            {
                continue;
            }
            let list = by_encoding.entry(instruction.encoding()).or_default();
            if !list.contains(&instruction) {
                list.push(instruction);
            }
        }
    }
    let mut chosen = Vec::new();
    for mut list in by_encoding.into_values() {
        for i in (1..list.len()).rev() {
            let j = usize::try_from(random.below(i as u64 + 1)).unwrap();
            list.swap(i, j);
        }
        list.truncate(per_form);
        chosen.extend(list);
    }
    chosen
}

/// Counts and mismatches over a run.
#[derive(Default)]
struct Tally {
    checked: BTreeMap<Encoding, u32>,
    /// Encodings with cases that entered the system (never sent).
    system_calls: BTreeSet<Encoding>,
    /// Compared cases where the processor faulted.
    faults: u32,
    skipped: u32,
    undetermined: u32,
    /// Branches to themselves, where L0 agrees.
    to_itself: u32,
    /// L0 SP alignment traps not run, the processor not checking.
    sp_unchecked: u32,
    /// SB cases whose BTYPE is not compared ([`Platform::sb_keeps_btype`]).
    sb_btype_unchecked: u32,
    /// PAC cases not run ([`Platform::pac_extends_bit63`]).
    pac_unchecked: u32,
    /// Data-key PAC cases of upper-half pointers not run ([`Platform::tbi1`]).
    tbi1_unchecked: u32,
    /// L0 authentication traps the processor does not take, the pointer
    /// corrupted instead ([`Platform::fpac`], [`Platform::fpac_combined`]).
    fpac_unchecked: u32,
    /// L0 alignment traps of failing store exclusives the processor does
    /// not take, the status 1 ([`Platform::exclusive_alignment`]).
    exclusive_alignment_unchecked: u32,
    /// Failing store exclusives the processor faults on translation
    /// ([`Platform::exclusive_aborts`]).
    exclusive_aborts_unchecked: u32,
    /// Cases run again, their SSBS rewritten by a context switch
    /// ([`Platform::ssbs_switched`]).
    ssbs_reruns: u32,
    /// Cases not run, by encoding, its feature lacking on the processor.
    unimplemented: BTreeMap<Encoding, (u32, &'static str)>,
    mismatches: Vec<String>,
}

impl Tally {
    /// Whether the processor's `answer` differs from L0's `outcome` only by
    /// a platform difference the probes found, counting it if so.
    fn excused(
        &mut self,
        platform: &Platform,
        instruction: Instruction,
        outcome: Outcome,
        answer: &Answer,
        exclusive: Option<(u64, u64)>,
    ) -> bool {
        let status = store_exclusive(instruction);
        let failed = |s: u8| s == 31 || answer.values.get(&format!("x{s}")) == Some(&1);
        // The processor's fault fits the access L0 checked the monitor of.
        let aborted = |(address, bytes): (u64, u64)| {
            Test::translate(address, bytes, true)
                .is_err_and(|fault| resumes_at(Outcome::Fault(fault), answer, 0).is_some())
        };
        let counter = if outcome == Outcome::Trap(Trap::Authentication)
            && unfaulted_authentication(instruction, answer, platform)
        {
            &mut self.fpac_unchecked
        } else if outcome == Outcome::Trap(Trap::Alignment)
            && !platform.exclusive_alignment
            && answer.kind == "ok"
            && status.is_some_and(failed)
        {
            &mut self.exclusive_alignment_unchecked
        } else if outcome == Outcome::Next
            && platform.exclusive_aborts
            && status.is_some()
            && exclusive.is_some_and(aborted)
        {
            &mut self.exclusive_aborts_unchecked
        } else {
            return false;
        };
        *counter += 1;
        true
    }

    /// The processor's answer to `line`. Where the kernel rewrites SSBS at
    /// context switches ([`Platform::ssbs_switched`]), a case ending with
    /// SSBS 1 where L0's (`machine`'s) is 0 is run once more.
    fn ask(
        &mut self,
        oracle: &mut Oracle,
        platform: &Platform,
        line: &str,
        machine: &mut Test,
    ) -> Answer {
        let answer = parse(&oracle.ask(line));
        let zero = |value: Value| value.known().is_some_and(|bits| bits.is_zero());
        if platform.ssbs_switched
            && answer.values.get("ssbs") == Some(&1)
            && zero(machine.read(SSBS))
        {
            self.ssbs_reruns += 1;
            return parse(&oracle.ask(line));
        }
        answer
    }

    /// Runs `instruction` from a random state on both and compares.
    fn case(
        &mut self,
        oracle: &mut Oracle,
        platform: &Platform,
        instruction: Instruction,
        random: &mut Random,
    ) {
        self.case_from(oracle, platform, instruction, random, |_| {});
    }

    /// Runs `instruction` on both from a random state that `craft` changes,
    /// and compares.
    fn case_from(
        &mut self,
        oracle: &mut Oracle,
        platform: &Platform,
        instruction: Instruction,
        random: &mut Random,
        craft: impl FnOnce(&mut Start),
    ) {
        // A processor without the encoding's feature cannot run it.
        if let Some(feature) = features(instruction)
            .into_iter()
            .find(|feature| platform.lacking.contains(feature))
        {
            let entry = self
                .unimplemented
                .entry(instruction.encoding())
                .or_insert((0, feature.name()));
            entry.0 += 1;
            return;
        }
        let mut start = Start::random(instruction, platform, random);
        craft(&mut start);
        if let Some(word) = signer(instruction)
            && random.below(2) == 0
        {
            start.sign(word, oracle);
        }
        let code = start.code;
        let semantics = lift(&instruction, code).unwrap();
        let mut machine = start.machine(instruction.word(), random);
        machine.oracle = Some(oracle);
        let outcome = interpret::run(&semantics, &mut machine);
        let oracle = machine.oracle.take().unwrap();
        // Never run a system call on the processor: with random registers
        // it could do anything the user can.
        if outcome == Outcome::SystemCall {
            self.system_calls.insert(instruction.encoding());
        }
        if matches!(outcome, Outcome::Undetermined | Outcome::SystemCall) {
            self.undetermined += 1;
            return;
        }
        // A processor that does not check SP alignment cannot vouch for an
        // SP alignment trap (and L0 touched no memory to map for it).
        if outcome == Outcome::Trap(Trap::Stack) && !platform.sp_alignment {
            self.sp_unchecked += 1;
            return;
        }
        if platform.pac_extends_bit63
            && let Some(register) = signed(instruction)
            && start.x[usize::from(register)] >> 55 & 0x101 == 1
        {
            self.pac_unchecked += 1;
            return;
        }
        if !platform.tbi1
            && let Some(register) = data_pointer(instruction)
            && start.x[usize::from(register)] >> 55 & 1 == 1
        {
            self.tbi1_unchecked += 1;
            return;
        }
        let line = start.line(instruction.word(), &machine.initial);
        let answer = self.ask(oracle, platform, &line, &mut machine);
        if answer.kind == "skip" {
            if outcome == Outcome::Transfer(code) && answer.raw.contains("branches to itself") {
                self.to_itself += 1;
            } else {
                self.skipped += 1;
            }
            return;
        }
        if self.excused(platform, instruction, outcome, &answer, machine.exclusive) {
            return;
        }
        let mut wrong = Vec::new();
        if answer.kind == "fault" {
            self.faults += 1;
        }
        if let Some(pc) = resumes_at(outcome, &answer, code) {
            let quirk =
                platform.sb_keeps_btype && instruction.encoding() == Encoding::SB_only_barriers;
            self.sb_btype_unchecked += u32::from(quirk);
            compare(
                &mut machine,
                &answer,
                pc,
                platform.bti && !quirk,
                &mut wrong,
            );
            if start.fp.is_some() {
                compare_fp(&mut machine, &answer, &mut wrong);
            }
        } else {
            wrong.push(format!("L0 {outcome:?}, CPU {}", answer.raw));
        }
        *self.checked.entry(instruction.encoding()).or_default() += 1;
        if !wrong.is_empty() {
            self.mismatches.push(format!(
                "{} `{}`\n  {line}\n  {}",
                instruction.encoding(),
                instruction.display(code),
                wrong.join("\n  ")
            ));
        }
    }

    /// Prints the counts, writes the report and fails on any mismatch or
    /// an encoding of `encodings` no case could compare (but those whose
    /// cases all entered the system or need a feature the processor lacks).
    fn finish(self, encodings: &[Encoding]) {
        let cases: u32 = self.checked.values().sum();
        println!(
            "{cases} cases over {} encodings ({} faulting); {} skipped by the oracle, {} undetermined, \
             {} branches to themselves, {} SP alignment traps not checked by the processor, {} SB \
             cases without BTYPE compared, {} PAC cases of pointers the processor extends from \
             bit 63 not run; {} mismatches",
            self.checked.len(),
            self.faults,
            self.skipped,
            self.undetermined,
            self.to_itself,
            self.sp_unchecked,
            self.sb_btype_unchecked,
            self.pac_unchecked,
            self.mismatches.len()
        );
        println!(
            "excused: {} data-key PAC cases of upper-half pointers not run (the processor has \
             TBI1 = 0), {} failed authentications the processor does not fault (no FPAC or \
             FPACCOMBINE: it leaves the pointer corrupted), {} misaligned failing store \
             exclusives the processor does not fault (status 1), {} failing store exclusives \
             the processor faults on translation; {} cases run again, their SSBS set by a \
             context switch",
            self.tbi1_unchecked,
            self.fpac_unchecked,
            self.exclusive_alignment_unchecked,
            self.exclusive_aborts_unchecked,
            self.ssbs_reruns
        );
        for (encoding, (cases, feature)) in &self.unimplemented {
            println!(
                "{cases} cases of {} not run: the processor lacks {feature}",
                encoding.name()
            );
        }
        if let Ok(path) = std::env::var("BINBUN_LIFT_REPORT") {
            std::fs::write(&path, self.mismatches.join("\n")).unwrap();
        }
        assert!(
            self.mismatches.is_empty(),
            "{}",
            self.mismatches
                .iter()
                .take(25)
                .cloned()
                .collect::<Vec<_>>()
                .join("\n")
        );
        let unchecked: Vec<&str> = encodings
            .iter()
            .filter(|encoding| {
                !self.checked.contains_key(encoding)
                    && !self.system_calls.contains(encoding)
                    && !self.unimplemented.contains_key(encoding)
            })
            .map(|encoding| encoding.name())
            .collect();
        assert!(!encodings.is_empty(), "no encoding has semantics");
        assert!(unchecked.is_empty(), "no case compared for {unchecked:?}");
    }
}

#[test]
#[ignore = "needs the AArch64 CPU oracle: BINBUN_CPU_ORACLE_AARCH64=target/cpu-oracle-aarch64"]
fn semantics_match_the_processor() {
    let command = std::env::var("BINBUN_CPU_ORACLE_AARCH64").expect("BINBUN_CPU_ORACLE_AARCH64");
    let per_form = std::env::var("BINBUN_LIFT_PER_FORM").map_or(40, |v| v.parse().unwrap());
    let states = std::env::var("BINBUN_LIFT_STATES").map_or(8, |v| v.parse().unwrap());
    let seed =
        std::env::var("BINBUN_LIFT_SEED").map_or(0x5eed_1234_abcd_ef01, |v| v.parse().unwrap());
    let mut random = Random(seed);
    let mut oracle = Oracle::start(&command);
    let platform = Platform::probe(&mut oracle);

    let instructions = instructions(per_form, &mut random);
    // Every encoding with semantics must get cases, unless the run is
    // narrowed to some.
    let encodings: Vec<Encoding> = if std::env::var("BINBUN_LIFT_FORMS").is_ok() {
        let mut encodings: Vec<Encoding> = instructions.iter().map(|i| i.encoding()).collect();
        encodings.dedup();
        encodings
    } else {
        ENCODINGS.to_vec()
    };
    let mut tally = Tally::default();
    for &instruction in &instructions {
        for _ in 0..states {
            tally.case(&mut oracle, &platform, instruction, &mut random);
        }
    }
    for &(word, register, value, fpcr) in &CRAFTED {
        let instruction = decode(word).unwrap();
        if !encodings.contains(&instruction.encoding()) {
            continue;
        }
        tally.case_from(&mut oracle, &platform, instruction, &mut random, |start| {
            start.x[usize::from(register)] = value;
            let fp = start.fp.as_mut().unwrap();
            fp.fpcr = fpcr & platform.fpcr;
            fp.fpsr = 0;
        });
    }
    tally.finish(&encodings);
}

/// `scvtf h0, x1, #40` and `ucvtf h0, x1, #40`.
const SCVTF_H0_X1_40: u32 = 0x9ec2_6020;
const UCVTF_H0_X1_40: u32 = 0x9ec3_6020;

/// Cases run in every run that covers their encoding: a word, a general
/// register's value and FPCR (the rest of the state random, FPSR clear).
///
/// Half-precision conversions from fixed-point of integers with more than
/// 24 significant bits, whose value rounded once to single precision is a
/// tie at half precision's 11 bits while the exact value is not: 2^40 +
/// 2^29 + 1 (just above the tie between 1.0 and 1 + 2^-10, which rounds
/// up to nearest) and 2^40 + 3 * 2^29 - 1 (just below the tie between 1 +
/// 2^-10 and 1 + 2^-9, which rounds down), of both signs; rounding to
/// nearest and toward -infinity.
const CRAFTED: [(u32, u8, u64, u32); 12] = [
    (SCVTF_H0_X1_40, 1, 0x100_2000_0001, 0),
    (SCVTF_H0_X1_40, 1, 0x100_5fff_ffff, 0),
    (SCVTF_H0_X1_40, 1, 0xffff_feff_dfff_ffff, 0),
    (SCVTF_H0_X1_40, 1, 0xffff_feff_a000_0001, 0),
    (SCVTF_H0_X1_40, 1, 0x100_2000_0001, 2 << 22),
    (SCVTF_H0_X1_40, 1, 0x100_5fff_ffff, 2 << 22),
    (SCVTF_H0_X1_40, 1, 0xffff_feff_dfff_ffff, 2 << 22),
    (SCVTF_H0_X1_40, 1, 0xffff_feff_a000_0001, 2 << 22),
    (UCVTF_H0_X1_40, 1, 0x100_2000_0001, 0),
    (UCVTF_H0_X1_40, 1, 0x100_5fff_ffff, 0),
    (UCVTF_H0_X1_40, 1, 0x100_2000_0001, 2 << 22),
    (UCVTF_H0_X1_40, 1, 0x100_5fff_ffff, 2 << 22),
];
