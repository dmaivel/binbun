//! Differential validity tests against LLVM's disassembler
//! (`tools/llvm-oracle`, LLVM 22 with every feature).
//!
//! ```sh
//! scripts/llvm-oracle.sh                       # writes target/llvm-oracle
//! BINBUN_LLVM_ORACLE=target/llvm-oracle cargo test --release \
//!     -p binbun-aarch64 --test oracle -- --ignored
//! ```
//!
//! `BINBUN_ORACLE_CASES` sets how many random words to try (default
//! 1 000 000) and `BINBUN_ORACLE_SEED` the seed. `corpus_matches_llvm`
//! sweeps every ELF and PE file under `BINBUN_ARM64_CORPUS` (default
//! `~/.cache/binbun-arm64/corpus`). `whole_space_matches_llvm` compares all
//! 2^32 words on `BINBUN_ORACLE_THREADS` threads (default 16).
//! `BINBUN_ORACLE_GROUPS` (comma-separated group path prefixes such as
//! `ldst` or `control/hints`) limits the per-encoding sweep and every text
//! comparison to those groups.
//!
//! A word may decode here and not in LLVM only if its encoding needs a
//! feature in [`NEWER_THAN_LLVM`] or LLVM wrongly rejects it
//! ([`llvm_rejects_valid`]); a word may decode in LLVM and not here only if
//! LLVM decodes it as a move of an unallocated system register
//! ([`llvm_accepts_unallocated`]). Every other difference fails the test.
//! So that the lists shrink when LLVM catches up, the full per-encoding
//! sweep (no `BINBUN_ORACLE_GROUPS`) also fails if a [`NEWER_THAN_LLVM`] or
//! [`TEXT_NEWER_THAN_LLVM`] feature, an [`LLVM_REJECTS_VALID`] encoding or
//! [`deliberate`] excuses no word, and the whole-space sweep if a validity
//! allowance does (including [`llvm_accepts_unallocated`]).
//!
//! LLVM cannot vouch for the words of [`NEWER_THAN_LLVM`] features and
//! [`LLVM_REJECTS_VALID`] encodings, so
//! `exarmo_agrees_where_llvm_cannot` checks them against a second oracle:
//! exarmo-aarch64 (`tools/exarmo-oracle`, generated from the same 2026-09
//! specification).
//!
//! ```sh
//! scripts/exarmo-oracle.sh                     # writes target/exarmo-oracle
//! BINBUN_EXARMO_ORACLE=target/exarmo-oracle cargo test --release \
//!     -p binbun-aarch64 --test oracle -- --ignored exarmo
//! ```
//!
//! The exarmo tests also compare control flow ([`Instruction::flow`]) with
//! exarmo's branch information (`tools/exarmo-oracle --flow`, from Arm's
//! pseudocode) on the per-encoding words and the corpus.
//!
//! Text is compared as LLVM's C API writes it, labels as offsets
//! ([`LabelStyle::Relative`]). A sample of LLVM's answers is checked in
//! (`tests/data/llvm-answers.txt`, three per-encoding words of every
//! encoding), so the comparison also runs without LLVM;
//! `BINBUN_WRITE_FIXTURE=1` with the full `encodings_match_llvm` rewrites
//! it.
//!
//! The access metadata (`Instruction::access`, `memory`, `implicit`,
//! `flags`) is checked on the per-encoding sweep without an oracle
//! (`access_matches_operands`, `access_is_consistent`) and against exarmo's
//! flag effects, ACLE intrinsic bindings and system-operation register
//! access (`access_matches_exarmo`, `tools/exarmo-oracle --analysis`, also
//! on the corpus when `BINBUN_ARM64_CORPUS` is set).

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers fail loudly"
)]

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fmt::Write as _;
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::LazyLock;

use binbun_aarch64::operand::{NameKind, Predication, Register, RegisterClass};
use binbun_aarch64::{
    Access, Encoding, Error, FlagSet, Instruction, LabelStyle, MemoryKind, Operand, decode,
};
use binbun_isa::{Flow, Target};
use xtask::aarchmrs::{BinaryOp, Expr, Package};

/// Features LLVM 22 does not decode (or decodes only partly), so words of
/// encodings that need them may be valid here and invalid in LLVM.
///
/// Established by listing the features of every encoding with words LLVM
/// rejects but this decoder accepts. `exarmo_agrees_where_llvm_cannot`
/// checks the validity of these encodings against exarmo-aarch64 0.4.0
/// (generated from Arm's 2026-09 XML) instead, and the per-encoding and
/// whole-space sweeps fail if a feature here excuses no word.
const NEWER_THAN_LLVM: &[&str] = &[
    "FEAT_CFLT",
    "FEAT_FPv2",
    "FEAT_LSC64B",
    "FEAT_SME_F16F8F16",
    "FEAT_SVE_LRCPC",
];

/// Encodings with words the specification defines and LLVM 22 rejects
/// ([`llvm_rejects_valid`]).
const LLVM_REJECTS_VALID: &[Encoding] = &[
    Encoding::LDTR_32_ldst_unpriv,
    Encoding::LDTR_64_ldst_unpriv,
    Encoding::LDTRB_32_ldst_unpriv,
    Encoding::LDTRH_32_ldst_unpriv,
    Encoding::LDTRSB_32_ldst_unpriv,
    Encoding::LDTRSH_32_ldst_unpriv,
];

/// Words the specification defines and LLVM 22 rejects: the unprivileged
/// loads `LDTR`, `LDTRB`, `LDTRH`, `LDTRSB`/`LDTRSH` (32-bit) with
/// `Rt == Rn != 31`. They have no writeback, so their pseudocode has no
/// overlap check, but LLVM applies the writeback-overlap check of the
/// pre/post-indexed loads to them. exarmo decodes them.
fn llvm_rejects_valid(encoding: Encoding, word: u32) -> bool {
    let (rt, rn) = (word & 0x1f, (word >> 5) & 0x1f);
    LLVM_REJECTS_VALID.contains(&encoding) && rt == rn && rn != 31
}

/// Whether `word` is in the `op0 = 0b00` and `0b01` halves of the
/// `MRS`/`MSR` (register) and `MRRS`/`MSRR` spaces (`1101010100 L 0 …` and
/// `1101010101 L 0 …`).
const fn generic_system_move_space(word: u32) -> bool {
    word & 0xff90_0000 == 0xd500_0000
}

/// Words the specification leaves unallocated and LLVM 22 decodes: words
/// of [`generic_system_move_space`], which LLVM prints as moves of generic
/// system registers `S0_…` and `S1_…`. In the architecture `op0` of these
/// instructions is `1:o0`; the allocated words of those halves are other
/// instructions (hints, barriers, `PSTATE` moves, `SYS`, `SYSL`, `SYSP`),
/// which both decoders decode, so LLVM's text must be such a move: a word
/// rejected here that LLVM decodes as one of those instructions is a
/// mismatch.
fn llvm_accepts_unallocated(word: u32, ours: Result<Encoding, Error>, llvm: &str) -> bool {
    ours == Err(Error::Unallocated) && generic_system_move_space(word) && generic_move(llvm)
}

/// Whether LLVM's text moves a generic system register with `op0` 0 or 1:
/// `msr\tS0_0_C0_C0_0, x0`, `mrrs\tx0, x1, S1_2_C3_C4_5`.
fn generic_move(llvm: &str) -> bool {
    let number = |text: &str| !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit());
    let generic = |operand: &str| {
        let Some(rest) = operand
            .strip_prefix("S0_")
            .or_else(|| operand.strip_prefix("S1_"))
        else {
            return false;
        };
        let parts: Vec<&str> = rest.split('_').collect();
        matches!(parts.as_slice(), [op1, crn, crm, op2]
            if number(op1)
                && crn.strip_prefix('C').is_some_and(number)
                && crm.strip_prefix('C').is_some_and(number)
                && number(op2))
    };
    llvm.split_once('\t').is_some_and(|(mnemonic, operands)| {
        matches!(mnemonic, "msr" | "mrs" | "msrr" | "mrrs") && operands.split(", ").any(generic)
    })
}

const PACKAGE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../third_party/aarchmrs/AARCHMRS_OPENSOURCE_A_profile_FAT-2026-09.tar.gz"
);

fn env_number(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

/// The oracle binary named by the environment variable `variable`.
fn oracle(variable: &str) -> String {
    std::env::var(variable).unwrap_or_else(|_| panic!("{variable} names the oracle binary"))
}

const LLVM: &str = "BINBUN_LLVM_ORACLE";
const EXARMO: &str = "BINBUN_EXARMO_ORACLE";

/// The address the words are disassembled at; LLVM's C API writes labels
/// as offsets ([`LabelStyle::Relative`]), so the text does not depend on it.
const ADDRESS: u64 = 0x0040_1000;

/// The text of `instruction` as LLVM's C API writes it.
fn llvm_style(instruction: Instruction) -> String {
    instruction
        .display_with(ADDRESS, LabelStyle::Relative)
        .to_string()
}

/// Features of encodings LLVM 22 decodes as an older, more general
/// instruction, so validity agrees but the text cannot: `hinte` (LLVM:
/// `msr`/`mrs` of a generic register), `srls` and `slbnd` (LLVM: `stshh #6`,
/// `hint #0x38`). Established as [`NEWER_THAN_LLVM`] was.
const TEXT_NEWER_THAN_LLVM: &[&str] = &["FEAT_HINTE", "FEAT_RLCS"];

/// Deliberate differences from LLVM's text, each with its reason.
fn deliberate(instruction: Instruction, llvm: &str) -> bool {
    // `dsb #12`: LLVM 22 writes `dfb`, an instruction Arm's specification
    // (2026-09) does not have; binbun writes the DSB it is.
    if instruction.encoding() == Encoding::DSB_BO_barriers && llvm == "dfb" {
        return true;
    }
    // `mlbi`: MLBI was withdrawn from the architecture (Arm's 2026-09
    // specification has no MLBI); LLVM 22 still writes it for
    // `sys #4, c7, c0, #4..7`, binbun writes the SYS it is.
    if instruction.encoding() == Encoding::SYS_CR_systeminstrs && llvm.starts_with("mlbi\t") {
        return true;
    }
    // `tlbip …nxs`: LLVM 22 writes this alias of SYSP (CRn 9) only with
    // FeatureXS, which `+all` does not enable, and writes `sysp`;
    // binbun writes Arm's syntax.
    if instruction.encoding() == Encoding::SYSP_CR_syspairinstrs
        && instruction.mnemonic() == "tlbip"
        && llvm.starts_with("sysp\t")
    {
        return true;
    }
    // `*MLALL`/`*MLSLL` by single: an extra space in LLVM's asm strings.
    if wide_group_spacing(instruction, llvm) {
        return true;
    }
    let ours = llvm_style(instruction);
    // LLVM annotates acquiring atomics to the zero register with a comment;
    // it is not part of the instruction's syntax.
    if llvm.strip_suffix(" // acquire semantics dropped since destination is zero")
        == Some(ours.as_str())
    {
        return true;
    }
    // FEAT_LSFE stores (`STFADD`, `STBFMAX`…): LLVM's asm strings have a
    // typo, two spaces before the address; Arm writes `STFADD <Hs>, [<Xn|SP>]`.
    instruction
        .features()
        .iter()
        .any(|feature| feature.name() == "FEAT_LSFE")
        && ours.starts_with("st")
        && llvm == ours.replacen(", [", ",  [", 1)
}

/// The multi-vector-by-single `*MLALL`/`*MLSLL` forms: LLVM 22's asm
/// strings put two spaces before the vector group (`za.s[w8, 0x0:0x3,
/// vgx2]` with `,  vgx2`); Arm's syntax has one, which binbun writes.
fn wide_group_spacing(instruction: Instruction, llvm: &str) -> bool {
    const ENCODINGS: &[Encoding] = &[
        Encoding::smlall_za_zzv_2x1,
        Encoding::smlall_za_zzv_4x1,
        Encoding::smlsll_za_zzv_2x1,
        Encoding::smlsll_za_zzv_4x1,
        Encoding::umlall_za_zzv_2x1,
        Encoding::umlall_za_zzv_4x1,
        Encoding::umlsll_za_zzv_2x1,
        Encoding::umlsll_za_zzv_4x1,
        Encoding::sumlall_za_zzv_s2x1,
        Encoding::sumlall_za_zzv_s4x1,
        Encoding::usmlall_za_zzv_s2x1,
        Encoding::usmlall_za_zzv_s4x1,
        Encoding::fmlall_za32_z8z8v_2x1,
        Encoding::fmlall_za32_z8z8v_4x1,
    ];
    ENCODINGS.contains(&instruction.encoding())
        && llvm_style(instruction) == llvm.replacen(",  vgx", ", vgx", 1)
}

/// Whether the group path `path` (`dpimm/addsub_imm`) is in
/// `BINBUN_ORACLE_GROUPS`, or no groups are given.
fn selected(path: &str) -> bool {
    static GROUPS: LazyLock<Vec<String>> = LazyLock::new(|| {
        std::env::var("BINBUN_ORACLE_GROUPS")
            .map(|groups| groups.split(',').map(str::to_owned).collect())
            .unwrap_or_default()
    });
    GROUPS.is_empty()
        || GROUPS.iter().any(|group| {
            path == group
                || path
                    .strip_prefix(group.as_str())
                    .is_some_and(|rest| rest.starts_with('/'))
        })
}

/// The answer of the oracle named by the environment variable `variable`
/// for each word: `None` if it does not decode it, else its text.
fn ask(variable: &str, words: &[u32]) -> Vec<Option<String>> {
    ask_with(variable, &[], words)
}

/// [`ask`] with the oracle's arguments `args`.
fn ask_with(variable: &str, args: &[&str], words: &[u32]) -> Vec<Option<String>> {
    let mut child = Command::new(oracle(variable))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("the oracle runs");
    let mut stdin = child.stdin.take().unwrap();
    let text = words.iter().fold(String::new(), |mut text, word| {
        writeln!(text, "{word:08x} {ADDRESS:x}").unwrap();
        text
    });
    let writer = std::thread::spawn(move || stdin.write_all(text.as_bytes()).unwrap());
    let output = child.wait_with_output().unwrap();
    writer.join().unwrap();
    assert!(output.status.success(), "the oracle failed");
    let answers: Vec<Option<String>> = String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(|line| (line != "invalid").then(|| line.to_owned()))
        .collect();
    assert_eq!(answers.len(), words.len(), "the oracle answered every word");
    answers
}

/// The `SplitMix64` generator.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn word(&mut self) -> u32 {
        (self.next() >> 32) as u32
    }
}

/// Whether a word that decodes here as `encoding` may be invalid in LLVM.
fn newer_than_llvm(encoding: Encoding) -> bool {
    encoding
        .features()
        .iter()
        .any(|feature| NEWER_THAN_LLVM.contains(&feature.name()))
}

/// Counts of a comparison, and the differences grouped by kind.
#[derive(Default)]
struct Comparison {
    words: usize,
    both_valid: usize,
    both_invalid: usize,
    newer: usize,
    llvm_wrong: usize,
    llvm_loose: usize,
    mismatches: BTreeMap<String, (usize, Vec<String>)>,
    /// Words of done syntax whose text was compared.
    texts: usize,
    /// Text differences, by encoding and mnemonic.
    text_mismatches: BTreeMap<String, (usize, Vec<String>)>,
    /// The allowances that excused a difference: [`NEWER_THAN_LLVM`] and
    /// [`TEXT_NEWER_THAN_LLVM`] features, [`LLVM_REJECTS_VALID`] encodings
    /// (by name), [`deliberate`] and [`llvm_accepts_unallocated`].
    used: BTreeSet<&'static str>,
}

impl Comparison {
    /// Compares the text of a word both decoders decode, when LLVM knows its
    /// features.
    fn add_text(&mut self, word: u32, instruction: Instruction, llvm: &str) {
        if !selected(&instruction.encoding().groups().join("/"))
            || newer_than_llvm(instruction.encoding())
        {
            return;
        }
        let ours = llvm_style(instruction);
        let text_newer = instruction
            .features()
            .iter()
            .map(|feature| feature.name())
            .filter(|name| TEXT_NEWER_THAN_LLVM.contains(name));
        if text_newer.clone().next().is_some() {
            if ours != llvm {
                self.used.extend(text_newer);
            }
            return;
        }
        self.texts += 1;
        if ours == llvm {
            return;
        }
        if deliberate(instruction, llvm) {
            self.used.insert("deliberate");
            return;
        }
        let kind = format!("{} ({})", instruction.encoding(), instruction.mnemonic());
        let entry = self.text_mismatches.entry(kind).or_default();
        entry.0 += 1;
        if entry.1.len() < 3 {
            entry.1.push(format!("{word:08x} {ours:?} llvm {llvm:?}"));
        }
    }

    fn add(&mut self, word: u32, ours: Result<Encoding, Error>, llvm: Option<&str>) {
        self.words += 1;
        let kind = match (ours, llvm) {
            (Ok(_), Some(_)) => {
                self.both_valid += 1;
                return;
            }
            (Err(_), None) => {
                self.both_invalid += 1;
                return;
            }
            (Ok(encoding), None) if newer_than_llvm(encoding) => {
                self.newer += 1;
                self.used.extend(
                    encoding
                        .features()
                        .iter()
                        .map(|feature| feature.name())
                        .filter(|name| NEWER_THAN_LLVM.contains(name)),
                );
                return;
            }
            (Ok(encoding), None) if llvm_rejects_valid(encoding, word) => {
                self.llvm_wrong += 1;
                self.used.insert(encoding.name());
                return;
            }
            (Err(_), Some(text)) if llvm_accepts_unallocated(word, ours, text) => {
                self.llvm_loose += 1;
                self.used.insert("llvm_accepts_unallocated");
                return;
            }
            (Ok(encoding), None) => format!("only here: {encoding}"),
            (Err(error), Some(text)) => {
                let mnemonic = text.split_whitespace().next().unwrap_or_default();
                format!("only in LLVM: {mnemonic} ({error})")
            }
        };
        let entry = self.mismatches.entry(kind).or_default();
        entry.0 += 1;
        if entry.1.len() < 4 {
            entry
                .1
                .push(format!("{word:08x} {}", llvm.unwrap_or("invalid")));
        }
    }

    fn compare(&mut self, words: &[u32]) {
        for words in words.chunks(1 << 20) {
            self.compare_answers(words, &ask(LLVM, words));
        }
    }

    /// Compares with LLVM's `answers` for `words`.
    fn compare_answers(&mut self, words: &[u32], answers: &[Option<String>]) {
        for (&word, answer) in words.iter().zip(answers) {
            let ours = decode(word);
            if let (Ok(instruction), Some(text)) = (ours, answer.as_deref()) {
                self.add_text(word, instruction, text);
            }
            self.add(word, ours.map(Instruction::encoding), answer.as_deref());
        }
    }

    /// Fails if one of the allowances `names` excused no word: LLVM may have
    /// learnt the feature or fixed the quirk, and the allowance should go.
    fn assert_allowances_used<'a>(&self, names: impl IntoIterator<Item = &'a str>) {
        let unused: Vec<&str> = names
            .into_iter()
            .filter(|name| !self.used.contains(name))
            .collect();
        assert!(
            unused.is_empty(),
            "allowances that excused no word (remove them if LLVM no longer needs them): {}",
            unused.join(", ")
        );
    }

    /// Prints the counts and fails on any validity or text mismatch.
    fn assert_agrees(&self, what: &str) {
        let total: usize = self.mismatches.values().map(|(n, _)| n).sum();
        let text_total: usize = self.text_mismatches.values().map(|(n, _)| n).sum();
        eprintln!(
            "{what}: {} words, {} valid in both, {} invalid in both, {} newer than LLVM, \
             {} wrongly rejected by LLVM, {} unallocated decoded by LLVM, {total} mismatches; \
             text of {} words compared, {text_total} differ",
            self.words,
            self.both_valid,
            self.both_invalid,
            self.newer,
            self.llvm_wrong,
            self.llvm_loose,
            self.texts,
        );
        let report = |mismatches: &BTreeMap<String, (usize, Vec<String>)>| {
            let mut by_count: Vec<_> = mismatches.iter().collect();
            by_count.sort_by_key(|(_, (n, _))| std::cmp::Reverse(*n));
            by_count
                .iter()
                .fold(String::new(), |mut report, (kind, (n, examples))| {
                    writeln!(report, "{n:7} {kind}: {}", examples.join(" | ")).unwrap();
                    report
                })
        };
        assert!(
            self.mismatches.is_empty() && self.text_mismatches.is_empty(),
            "{total} of {} words differ in validity ({} kinds):\n{}\
             {text_total} of {} texts differ ({} kinds):\n{}",
            self.words,
            self.mismatches.len(),
            report(&self.mismatches),
            self.texts,
            self.text_mismatches.len(),
            report(&self.text_mismatches),
        );
    }
}

/// Words for every encoding `keep` accepts (given its group path, such as
/// `dpimm/addsub_imm`, and its name): each value of every field of up to 5 free
/// bits and the edge values (0, 1, all ones and all ones but the lowest
/// bit) of longer fields (twice each, other fields random), words with the
/// field equalities of each alias's condition and preferred expression set
/// (so narrow aliases such as `MOV` for `ADD #0` occur), words with the
/// should-be bits as specified, and random words; fixed bits held.
fn encoding_words(package: &Package, rng: &mut Rng, keep: impl Fn(&str, &str) -> bool) -> Vec<u32> {
    encoding_word_sets(package, rng, keep)
        .into_iter()
        .flat_map(|(_, words)| words)
        .collect()
}

/// The words of [`encoding_words`], by encoding name.
fn encoding_word_sets(
    package: &Package,
    rng: &mut Rng,
    keep: impl Fn(&str, &str) -> bool,
) -> Vec<(String, Vec<u32>)> {
    const PER_VALUE: usize = 2;
    const PER_ALIAS: usize = 16;
    const SPECIFIED: usize = 8;
    const RANDOM: usize = 64;
    let mut sets = Vec::new();
    for (groups, instruction) in package.a64.encodings() {
        let path: Vec<&str> = groups.iter().map(|group| group.name.as_str()).collect();
        if !keep(&path.join("/"), &instruction.name) {
            continue;
        }
        let mut words = Vec::new();
        let mut fixed_mask = 0u32;
        let mut fixed_value = 0u32;
        let mut soft_mask = 0u32;
        let mut soft_value = 0u32;
        let mut fields = Vec::new();
        for field in &instruction.encoding.fields {
            let soft = field.should_be_mask.value();
            let mask = u32::try_from((field.value.mask() & !soft) << field.start).unwrap();
            fixed_mask |= mask;
            fixed_value |= u32::try_from((field.value.value() & !soft) << field.start).unwrap();
            soft_mask |= u32::try_from(soft << field.start).unwrap();
            soft_value |= u32::try_from((field.value.value() & soft) << field.start).unwrap();
            let free =
                u32::try_from((((1u64 << field.width) - 1) << field.start) & !u64::from(mask))
                    .unwrap();
            if free != 0 {
                fields.push(free);
            }
        }
        let random = |rng: &mut Rng| (rng.word() & !fixed_mask) | fixed_value;
        for &free in &fields {
            let width = free.count_ones();
            let values: Vec<u32> = if width > 5 {
                let ones = (1u32 << width) - 1;
                vec![0, 1, ones, ones - 1]
            } else {
                (0..1u32 << width).collect()
            };
            for value in values {
                let bits = deposit(value, free);
                for _ in 0..PER_VALUE {
                    words.push((random(rng) & !free) | bits);
                }
            }
        }
        for alias in &instruction.aliases {
            let mut equalities = Vec::new();
            alias
                .condition
                .walk(&mut |expr| equalities.extend(equality(expr, instruction)));
            alias
                .preferred
                .walk(&mut |expr| equalities.extend(equality(expr, instruction)));
            let (mask, value) = equalities.iter().fold((0, 0), |(mask, value), &(m, v)| {
                (mask | m, (value & !m) | v)
            });
            for _ in 0..PER_ALIAS {
                words.push((random(rng) & !(mask & !fixed_mask)) | (value & !fixed_mask));
            }
        }
        // Should-be bits as specified: with several should-be fields
        // (`Rs` and `Rt2` of LDAR), the words above rarely have them all.
        words.extend((0..SPECIFIED).map(|_| (random(rng) & !soft_mask) | soft_value));
        words.extend((0..RANDOM).map(|_| random(rng)));
        sets.push((instruction.name.clone(), words));
    }
    sets
}

/// The word mask and value an equality `field == 'pattern'` sets.
fn equality(expr: &Expr, instruction: &xtask::aarchmrs::Instruction) -> Option<(u32, u32)> {
    let Expr::Binary {
        op: BinaryOp::Eq,
        left,
        right,
    } = expr
    else {
        return None;
    };
    let (Expr::Identifier(name), Expr::Bits(pattern)) = (left.as_ref(), right.as_ref()) else {
        return None;
    };
    let field = instruction
        .encoding
        .fields
        .iter()
        .find(|field| field.name.as_deref() == Some(name.as_str()))?;
    let mask = u32::try_from(pattern.mask() << field.start).ok()?;
    let value = u32::try_from(pattern.value() << field.start).ok()?;
    Some((mask, value))
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

#[test]
#[ignore = "needs BINBUN_LLVM_ORACLE"]
fn encodings_match_llvm() {
    let package = Package::read(PACKAGE).unwrap();
    let mut rng = Rng(env_number("BINBUN_ORACLE_SEED", 0x5eed));
    let sets = encoding_word_sets(&package, &mut rng, |path, _| selected(path));
    let words: Vec<u32> = sets.iter().flat_map(|(_, words)| words.clone()).collect();
    let answers: Vec<Option<String>> = words
        .chunks(1 << 20)
        .flat_map(|words| ask(LLVM, words))
        .collect();
    let mut comparison = Comparison::default();
    comparison.compare_answers(&words, &answers);
    comparison.assert_agrees("per-encoding sweep");
    if std::env::var_os("BINBUN_ORACLE_GROUPS").is_some() {
        return;
    }
    // Every allowance tied to encodings fires on their words.
    comparison.assert_allowances_used(
        NEWER_THAN_LLVM
            .iter()
            .chain(TEXT_NEWER_THAN_LLVM)
            .copied()
            .chain(LLVM_REJECTS_VALID.iter().map(|encoding| encoding.name()))
            .chain(["deliberate"]),
    );
    if std::env::var_os("BINBUN_WRITE_FIXTURE").is_some() {
        write_fixture(&sets, &answers);
    }
}

/// The checked-in sample of LLVM's answers: oracle lines `WORD ANSWER`
/// (`invalid`, or the text as LLVM's C API writes it at [`ADDRESS`]).
const FIXTURE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/llvm-answers.txt");

/// Words per encoding in the fixture.
const FIXTURE_WORDS: usize = 3;

/// Writes [`FIXTURE`] from the per-encoding sweep's `sets` of words and
/// LLVM's `answers` to them (in order): for each encoding, the first word
/// that decodes as it and words spread over the rest of its set.
fn write_fixture(sets: &[(String, Vec<u32>)], answers: &[Option<String>]) {
    let mut text = String::new();
    let mut start = 0;
    for (name, words) in sets {
        let answers = &answers[start..start + words.len()];
        start += words.len();
        let first = words
            .iter()
            .position(|&word| decode(word).is_ok_and(|i| i.encoding().name() == name))
            .unwrap_or(0);
        let step = words.len() / FIXTURE_WORDS;
        let picks = std::iter::once(first).chain((1..FIXTURE_WORDS).map(|k| k * step));
        for index in picks {
            let answer = answers[index].as_deref().unwrap_or("invalid");
            writeln!(text, "{:08x} {answer}", words[index]).unwrap();
        }
    }
    std::fs::write(FIXTURE, text).unwrap();
}

/// The checked-in sample of LLVM's answers ([`FIXTURE`]) agrees, as the
/// sweeps do; every encoding decodes from one of its words.
#[test]
fn matches_recorded_llvm_answers() {
    let text = std::fs::read_to_string(FIXTURE).expect("tests/data/llvm-answers.txt exists");
    let (words, answers): (Vec<u32>, Vec<Option<String>>) = text
        .lines()
        .map(|line| {
            let (word, answer) = line.split_once(' ').unwrap();
            let word = u32::from_str_radix(word, 16).unwrap();
            (word, (answer != "invalid").then(|| answer.to_owned()))
        })
        .unzip();
    let mut comparison = Comparison::default();
    comparison.compare_answers(&words, &answers);
    comparison.assert_agrees("recorded LLVM answers");
    let decoded: BTreeSet<Encoding> = words
        .iter()
        .filter_map(|&word| decode(word).ok())
        .map(Instruction::encoding)
        .collect();
    let missing: Vec<Encoding> = Encoding::ALL
        .into_iter()
        .filter(|encoding| !decoded.contains(encoding))
        .collect();
    assert!(missing.is_empty(), "encodings without a word: {missing:?}");
}

/// What `tools/exarmo-oracle` appends to the text of a word exarmo marks
/// CONSTRAINED UNPREDICTABLE.
const UNPREDICTABLE_NOTE: &str = "\t// CONSTRAINED UNPREDICTABLE";

/// The words LLVM cannot vouch for agree with exarmo: the per-encoding words
/// of every encoding that needs a [`NEWER_THAN_LLVM`] feature and of the
/// [`LLVM_REJECTS_VALID`] encodings. A word decodes here if exarmo decodes
/// it, is [`Error::Unpredictable`] if exarmo marks it CONSTRAINED
/// UNPREDICTABLE (binbun rejects those for every encoding LLVM does not
/// know), and is otherwise rejected.
#[test]
#[ignore = "needs BINBUN_EXARMO_ORACLE"]
fn exarmo_agrees_where_llvm_cannot() {
    let package = Package::read(PACKAGE).unwrap();
    let mut rng = Rng(env_number("BINBUN_ORACLE_SEED", 0x5eed));
    let vouched =
        |encoding: Encoding| newer_than_llvm(encoding) || LLVM_REJECTS_VALID.contains(&encoding);
    let words = encoding_words(&package, &mut rng, |_, name| {
        name.parse().is_ok_and(vouched)
    });
    let mut mismatches: BTreeMap<String, (usize, Vec<String>)> = BTreeMap::new();
    let mut confirmed = BTreeSet::new();
    let mut agreed = 0;
    for (&word, answer) in words.iter().zip(ask(EXARMO, &words)) {
        let ours = decode(word).map(Instruction::encoding);
        let theirs = answer
            .as_deref()
            .map(|text| text.ends_with(UNPREDICTABLE_NOTE));
        match (ours, theirs) {
            (Ok(encoding), Some(false)) => {
                if vouched(encoding) {
                    confirmed.insert(encoding);
                }
            }
            (Err(Error::Unpredictable), Some(true))
            | (Err(Error::Undefined | Error::Unallocated), None) => {}
            _ => {
                let kind = format!(
                    "binbun {ours:?}, exarmo {}",
                    match theirs {
                        None => "invalid",
                        Some(false) => "valid",
                        Some(true) => "CONSTRAINED UNPREDICTABLE",
                    }
                );
                let entry = mismatches.entry(kind).or_default();
                entry.0 += 1;
                if entry.1.len() < 4 {
                    entry.1.push(format!(
                        "{word:08x} {}",
                        answer.as_deref().unwrap_or("invalid")
                    ));
                }
                continue;
            }
        }
        agreed += 1;
    }
    eprintln!(
        "exarmo: {} words, {agreed} agree; {} of the encodings LLVM cannot vouch for decoded",
        words.len(),
        confirmed.len(),
    );
    let report = mismatches
        .iter()
        .fold(String::new(), |mut report, (kind, (n, examples))| {
            writeln!(report, "{n:7} {kind}: {}", examples.join(" | ")).unwrap();
            report
        });
    assert!(
        mismatches.is_empty(),
        "validity differs from exarmo:\n{report}"
    );
    let unconfirmed: Vec<Encoding> = Encoding::ALL
        .into_iter()
        .filter(|&encoding| vouched(encoding) && !confirmed.contains(&encoding))
        .collect();
    assert!(
        unconfirmed.is_empty(),
        "no word of these encodings decoded in both: {unconfirmed:?}"
    );
}

#[test]
#[ignore = "needs BINBUN_LLVM_ORACLE"]
fn random_words_match_llvm() {
    let cases = env_number("BINBUN_ORACLE_CASES", 1_000_000);
    let mut rng = Rng(env_number("BINBUN_ORACLE_SEED", 0x5eed));
    let words: Vec<u32> = (0..cases).map(|_| rng.word()).collect();
    let mut comparison = Comparison::default();
    comparison.compare(&words);
    comparison.assert_agrees("random words");
}

fn corpus_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            corpus_files(&path, out);
        } else {
            out.push(path);
        }
    }
}

/// The distinct words of the code sections of every AArch64 ELF and PE file
/// under `BINBUN_ARM64_CORPUS`, sorted, and the number of those files.
fn corpus_words() -> (Vec<u32>, usize) {
    use object::{Architecture, Object as _, ObjectSection as _, SectionKind};

    let dir = std::env::var_os("BINBUN_ARM64_CORPUS").map_or_else(
        || {
            std::env::home_dir()
                .unwrap()
                .join(".cache/binbun-arm64/corpus")
        },
        PathBuf::from,
    );
    let mut files = Vec::new();
    corpus_files(&dir, &mut files);
    files.sort();
    let mut words = HashSet::new();
    let mut binaries = 0;
    for path in &files {
        let data = std::fs::read(path).unwrap();
        let Ok(file) = object::File::parse(&*data) else {
            continue;
        };
        if file.architecture() != Architecture::Aarch64 {
            continue;
        }
        binaries += 1;
        for section in file.sections() {
            if section.kind() != SectionKind::Text {
                continue;
            }
            let bytes = section.data().unwrap();
            words.extend(
                bytes
                    .as_chunks::<4>()
                    .0
                    .iter()
                    .map(|chunk| u32::from_le_bytes(*chunk)),
            );
        }
    }
    assert!(binaries > 0, "no AArch64 binaries under {}", dir.display());
    let mut words: Vec<u32> = words.into_iter().collect();
    words.sort_unstable();
    (words, binaries)
}

#[test]
#[ignore = "needs BINBUN_LLVM_ORACLE and the AArch64 corpus"]
fn corpus_matches_llvm() {
    let (words, binaries) = corpus_words();
    let mut comparison = Comparison::default();
    comparison.compare(&words);
    comparison.assert_agrees(&format!("corpus ({binaries} binaries, distinct words)"));
}

#[test]
#[ignore = "needs BINBUN_LLVM_ORACLE; minutes on 16 threads"]
fn whole_space_matches_llvm() {
    let threads = env_number("BINBUN_ORACLE_THREADS", 16);
    let chunk = (1u64 << 32) / threads;
    assert_eq!(chunk * threads, 1 << 32, "the thread count divides 2^32");
    let workers: Vec<_> = (0..threads)
        .map(|index| {
            std::thread::spawn(move || {
                let start = index * chunk;
                let mut child = Command::new(oracle(LLVM))
                    .args(["--bitmap", &format!("{start:x}"), &chunk.to_string()])
                    .stdout(Stdio::piped())
                    .spawn()
                    .expect("the oracle runs");
                let mut stdout = child.stdout.take().unwrap();
                let mut comparison = Comparison::default();
                // Words only LLVM decodes that may be generic system
                // register moves: asked again in line mode, for the text.
                let mut moves = Vec::new();
                let mut buffer = vec![0u8; 1 << 16];
                let mut word = start;
                loop {
                    let read = stdout.read(&mut buffer).unwrap();
                    if read == 0 {
                        break;
                    }
                    for &byte in &buffer[..read] {
                        for bit in 0..8 {
                            let w = u32::try_from(word).unwrap();
                            let valid = byte & (1 << bit) != 0;
                            let ours = decode(w).map(Instruction::encoding);
                            if valid
                                && ours == Err(Error::Unallocated)
                                && generic_system_move_space(w)
                            {
                                moves.push(w);
                            } else {
                                comparison.add(w, ours, valid.then_some("valid"));
                            }
                            word += 1;
                        }
                    }
                }
                assert!(child.wait().unwrap().success(), "the oracle failed");
                assert_eq!(word, start + chunk, "the oracle answered every word");
                comparison.compare(&moves);
                comparison
            })
        })
        .collect();
    let mut total = Comparison::default();
    for worker in workers {
        let part = worker.join().unwrap();
        total.words += part.words;
        total.both_valid += part.both_valid;
        total.both_invalid += part.both_invalid;
        total.newer += part.newer;
        total.llvm_wrong += part.llvm_wrong;
        total.llvm_loose += part.llvm_loose;
        total.used.extend(part.used);
        for (kind, (n, examples)) in part.mismatches {
            let entry = total.mismatches.entry(kind).or_default();
            entry.0 += n;
            for example in examples {
                if entry.1.len() < 4 {
                    entry.1.push(example);
                }
            }
        }
    }
    total.assert_agrees("whole space");
    // Every validity allowance fires somewhere in the word space.
    total.assert_allowances_used(
        NEWER_THAN_LLVM
            .iter()
            .copied()
            .chain(LLVM_REJECTS_VALID.iter().map(|encoding| encoding.name()))
            .chain(["llvm_accepts_unallocated"]),
    );
}

/// `flow` as `tools/exarmo-oracle --flow` writes exarmo's branch
/// information: `KIND CONDITIONAL TARGET`.
fn exarmo_flow(flow: Flow) -> String {
    let (kind, conditional, target) = match flow {
        Flow::Next => ("None", false, None),
        Flow::Jump(Target::Address(target)) => ("Direct", false, Some(target)),
        Flow::Branch(Target::Address(target)) => ("Direct", true, Some(target)),
        Flow::Jump(_) => ("Indirect", false, None),
        Flow::Branch(_) => ("Indirect", true, None),
        Flow::Call(Target::Address(target)) => ("DirectCall", false, Some(target)),
        Flow::Call(_) => ("IndirectCall", false, None),
        Flow::Return => ("Return", false, None),
        Flow::ExceptionReturn => ("ExceptionReturn", false, None),
        Flow::SystemCall => ("SystemCall", false, None),
        Flow::Trap { conditional } => ("Exception", conditional, None),
        Flow::Halt => ("Halt", false, None),
    };
    let target = target.map_or_else(|| "-".to_owned(), |target| format!("{target:x}"));
    format!("{kind} {} {target}", u8::from(conditional))
}

/// Where binbun's flow deliberately differs from exarmo's, each with its
/// reason: the allowance's name, if one excuses `instruction` with
/// exarmo's answer `exarmo`.
fn flow_difference(instruction: Instruction, exarmo: &str) -> Option<&'static str> {
    let ours = exarmo_flow(instruction.flow(ADDRESS));
    // HLT: exarmo's `Halt` (halting into debug state). binbun_isa's
    // `Flow::Halt` is a wait for an interrupt (x86 `HLT`), so the debug
    // halt is a trap: the instruction does not complete.
    if instruction.encoding() == Encoding::HLT_EX_exception
        && ours == "Exception 0 -"
        && exarmo == "Halt 0 -"
    {
        return Some("hlt");
    }
    // FEAT_CFLT (`flt.<cond>`, `cflt<cc>`, `tfltz`, `tfltnz`): exarmo 0.4
    // gives no branch kind for these; their pseudocode raises a fault
    // exception when the test passes, so binbun makes them conditional
    // traps (unconditional for `flt.al` and `flt.nv`).
    if instruction
        .features()
        .iter()
        .any(|feature| feature.name() == "FEAT_CFLT")
        && ours.starts_with("Exception ")
        && exarmo == "None 0 -"
    {
        return Some("FEAT_CFLT");
    }
    None
}

/// Compares binbun's flow of `words` at [`ADDRESS`] with exarmo's where
/// both decode; prints the counts and fails on any difference that
/// [`flow_difference`] does not excuse. Returns the words each allowance
/// excused.
fn flow_agrees(what: &str, words: &[u32]) -> BTreeMap<&'static str, usize> {
    let mut mismatches: BTreeMap<String, (usize, Vec<String>)> = BTreeMap::new();
    let mut used = BTreeMap::new();
    let (mut compared, mut transfers) = (0, 0);
    for words in words.chunks(1 << 20) {
        for (&word, answer) in words.iter().zip(ask_with(EXARMO, &["--flow"], words)) {
            let (Ok(instruction), Some(exarmo)) = (decode(word), answer) else {
                continue;
            };
            compared += 1;
            let flow = instruction.flow(ADDRESS);
            transfers += usize::from(flow != Flow::Next);
            let ours = exarmo_flow(flow);
            if ours == exarmo {
                continue;
            }
            if let Some(name) = flow_difference(instruction, &exarmo) {
                *used.entry(name).or_default() += 1;
                continue;
            }
            let kind = format!("{} binbun {ours}", instruction.encoding());
            let entry = mismatches.entry(kind).or_default();
            entry.0 += 1;
            if entry.1.len() < 3 {
                entry.1.push(format!("{word:08x} exarmo {exarmo}"));
            }
        }
    }
    let total: usize = mismatches.values().map(|(n, _)| n).sum();
    eprintln!(
        "{what}: flow of {compared} words compared ({transfers} transfer control), \
         differences by allowance {used:?}, {total} other differences"
    );
    let report = mismatches
        .iter()
        .fold(String::new(), |mut report, (kind, (n, examples))| {
            writeln!(report, "{n:7} {kind}: {}", examples.join(" | ")).unwrap();
            report
        });
    assert!(mismatches.is_empty(), "flow differs from exarmo:\n{report}");
    used
}

/// Flow agrees with exarmo's branch information (from Arm's pseudocode) on
/// the per-encoding words of every encoding, apart from the documented
/// [`flow_difference`]s, each of which must excuse a word.
#[test]
#[ignore = "needs BINBUN_EXARMO_ORACLE"]
fn flow_matches_exarmo() {
    let package = Package::read(PACKAGE).unwrap();
    let mut rng = Rng(env_number("BINBUN_ORACLE_SEED", 0x5eed));
    let words = encoding_words(&package, &mut rng, |path, _| selected(path));
    let used = flow_agrees("per-encoding sweep", &words);
    if std::env::var_os("BINBUN_ORACLE_GROUPS").is_none() {
        let unused: Vec<&str> = ["hlt", "FEAT_CFLT"]
            .into_iter()
            .filter(|name| !used.contains_key(name))
            .collect();
        assert!(
            unused.is_empty(),
            "flow allowances that excused no word: {unused:?}"
        );
    }
}

#[test]
#[ignore = "needs BINBUN_EXARMO_ORACLE and the AArch64 corpus"]
fn corpus_flow_matches_exarmo() {
    let (words, binaries) = corpus_words();
    flow_agrees(
        &format!("corpus ({binaries} binaries, distinct words)"),
        &words,
    );
}

/// The instructions of the per-encoding sweep words of every encoding.
fn sweep_instructions() -> Vec<Instruction> {
    let package = Package::read(PACKAGE).unwrap();
    let mut rng = Rng(env_number("BINBUN_ORACLE_SEED", 0x5eed));
    encoding_words(&package, &mut rng, |_, _| true)
        .into_iter()
        .filter_map(|word| decode(word).ok())
        .collect()
}

/// Violations of a check, by kind, with a few examples each.
#[derive(Default)]
struct Violations(BTreeMap<String, (usize, Vec<String>)>);

impl Violations {
    fn add(&mut self, instruction: Instruction, check: &str) {
        let kind = format!(
            "{} ({}): {check}",
            instruction.encoding(),
            instruction.mnemonic()
        );
        let entry = self.0.entry(kind).or_default();
        entry.0 += 1;
        if entry.1.len() < 2 {
            entry.1.push(format!(
                "{:08x} {} {:?}",
                instruction.word(),
                instruction.display(0),
                instruction.access().as_slice()
            ));
        }
    }

    fn assert_none(&self, what: &str) {
        let report = self
            .0
            .iter()
            .fold(String::new(), |mut report, (kind, (n, examples))| {
                writeln!(report, "{n:7} {kind}: {}", examples.join(" | ")).unwrap();
                report
            });
        assert!(
            self.0.is_empty(),
            "{what}: {} kinds\n{report}",
            self.0.len()
        );
    }
}

/// `access` has one entry per operand of `operands`, for every per-encoding
/// sweep word: the generator rewrites each slot's operand pushes into
/// access pushes, so optional slots (0 or 1 operands) and slots of several
/// operands stay aligned.
#[test]
fn access_matches_operands() {
    let instructions = sweep_instructions();
    let mut violations = Violations::default();
    for &instruction in &instructions {
        let (operands, access) = (instruction.operands(), instruction.access());
        if operands.len() != access.len() {
            violations.add(
                instruction,
                &format!("{} operands, {} accesses", operands.len(), access.len()),
            );
        }
    }
    eprintln!("{} words", instructions.len());
    violations.assert_none("access and operands differ in length");
}

/// Whether `operand` is a governing predicate (`p0/m`, `pn8/z`).
const fn is_predicate(operand: &Operand) -> bool {
    matches!(
        operand,
        Operand::Register(Register {
            class: RegisterClass::P | RegisterClass::Pn,
            predication: Some(_),
            ..
        })
    )
}

/// Whether `operand` names storage a load or store transfers.
const fn is_transfer(operand: &Operand) -> bool {
    matches!(
        operand,
        Operand::Register(_)
            | Operand::List(_)
            | Operand::Za(_)
            | Operand::ZaList(_)
            | Operand::TableSlice(_)
    ) && !is_predicate(operand)
}

/// The access a memory operand of `kind` must have.
const fn memory_access(kind: MemoryKind) -> Option<Access> {
    match kind {
        MemoryKind::Load
        | MemoryKind::LoadExclusive
        | MemoryKind::LoadTag
        | MemoryKind::Prefetch => Some(Access::Read),
        MemoryKind::Store | MemoryKind::StoreExclusive | MemoryKind::StoreTag => {
            Some(Access::Write)
        }
        MemoryKind::Atomic => Some(Access::ReadWrite),
        MemoryKind::Copy => None,
    }
}

/// Operands that are values are read; system registers are written by
/// `msr`/`msrr` and read by `mrs`/`mrrs`; PSTATE fields are written;
/// governing predicates are read.
fn check_values(instruction: Instruction, violations: &mut Violations) {
    let mnemonic = instruction.mnemonic();
    for (operand, &access) in instruction
        .operands()
        .iter()
        .zip(instruction.access().iter())
    {
        let expected = match operand {
            Operand::Named(named) if named.kind == NameKind::PstateField => Access::Write,
            Operand::SystemRegister(_) if mnemonic.starts_with("msr") => Access::Write,
            Operand::Immediate(_)
            | Operand::Float(_)
            | Operand::Shift(_)
            | Operand::Extend(_)
            | Operand::Label(_)
            | Operand::Condition(_)
            | Operand::Named(_)
            | Operand::SystemRegister(_) => Access::Read,
            operand if is_predicate(operand) => Access::Read,
            Operand::Register(_)
            | Operand::List(_)
            | Operand::Memory(_)
            | Operand::Writeback(_)
            | Operand::Za(_)
            | Operand::ZaList(_)
            | Operand::TableSlice(_)
            | Operand::IndexedRegister(_) => continue,
        };
        if access != expected {
            violations.add(instruction, &format!("{operand:?} is {access:?}"));
        }
    }
}

/// A memory access exactly where there is a memory operand or a literal
/// load, for every word of the load/store groups; the memory operand's
/// access is the memory access; loads write their transfer registers and
/// stores read them.
fn check_memory(instruction: Instruction, violations: &mut Violations) {
    let operands = instruction.operands();
    let access = instruction.access();
    let memory = instruction.memory();
    let mnemonic = instruction.mnemonic();
    let has_memory = operands.iter().any(|o| matches!(o, Operand::Memory(_)));
    let literal = operands.iter().any(|o| matches!(o, Operand::Label(_)))
        && instruction.encoding().groups().first() == Some(&"ldst");
    // SVE ADR only computes addresses.
    let adr = mnemonic == "adr" && has_memory;
    if (has_memory && !adr || literal) != memory.is_some() {
        violations.add(
            instruction,
            &format!("memory operand {has_memory}, memory {memory:?}"),
        );
    }
    if instruction.encoding().groups().first() == Some(&"ldst") && memory.is_none() {
        violations.add(instruction, "load/store group without memory");
    }
    let Some(memory) = memory else { return };
    let mut memories = operands
        .iter()
        .zip(access.iter())
        .filter(|(o, _)| matches!(o, Operand::Memory(_)))
        .map(|(_, &a)| a);
    let expected: Vec<Access> = match memory_access(memory.kind) {
        Some(access) => vec![access],
        None => vec![Access::Write, Access::Read],
    };
    if !literal && memories.by_ref().take(2).collect::<Vec<_>>() != expected {
        violations.add(instruction, "memory operand access");
    }
    let first = operands
        .iter()
        .position(|o| matches!(o, Operand::Memory(_) | Operand::Label(_)))
        .unwrap_or(0);
    for (index, (operand, &access)) in operands.iter().zip(access.iter()).enumerate().take(first) {
        if !is_transfer(operand) {
            continue;
        }
        let ok = match memory.kind {
            MemoryKind::Load | MemoryKind::LoadExclusive | MemoryKind::LoadTag => access.writes(),
            MemoryKind::StoreExclusive if index == 0 => access == Access::Write,
            MemoryKind::Store if index == 0 && mnemonic.starts_with("st64bv") => {
                access == Access::Write
            }
            MemoryKind::Store | MemoryKind::StoreExclusive | MemoryKind::StoreTag => {
                access == Access::Read
            }
            MemoryKind::Atomic | MemoryKind::Prefetch | MemoryKind::Copy => true,
        };
        if !ok {
            violations.add(
                instruction,
                &format!("{:?} transfer is {access:?}", memory.kind),
            );
        }
    }
}

/// A destination governed by a merging predicate (`/m`) is read and
/// written; by a zeroing one (`/z`) only written.
fn check_predication(instruction: Instruction, violations: &mut Violations) {
    let operands = instruction.operands();
    let predication = operands.iter().find_map(|operand| {
        if let Operand::Register(Register {
            class: RegisterClass::P | RegisterClass::Pn,
            predication,
            ..
        }) = operand
        {
            *predication
        } else {
            None
        }
    });
    let (Some(predication), Some(first), Some(&access)) = (
        predication,
        operands.iter().next(),
        instruction.access().iter().next(),
    ) else {
        return;
    };
    let destination = matches!(
        first,
        Operand::Register(Register {
            class: RegisterClass::Z | RegisterClass::P,
            predication: None,
            ..
        })
    ) || matches!(first, Operand::List(list) if list.first.class == RegisterClass::Z);
    if !destination || instruction.memory().is_some() {
        return;
    }
    let ok = match predication {
        Predication::Merging => access == Access::ReadWrite,
        Predication::Zeroing => access.writes(),
    };
    if !ok {
        violations.add(
            instruction,
            &format!("{predication:?} destination is {access:?}"),
        );
    }
}

/// Flags: a condition operand's flags are read; flags are read without a
/// condition operand only by conditional branches (the condition is in the
/// mnemonic) and the documented carry and flag readers; the flag-setting
/// integer and floating-point instructions write all four.
fn check_flags(instruction: Instruction, violations: &mut Violations) {
    const READERS: &[&str] = &[
        "adc", "adcs", "sbc", "sbcs", "ngc", "ngcs", "cfinv", "axflag", "xaflag", "mrs", "ctermeq",
        "ctermne",
    ];
    const CONDITIONS: &[&str] = &[
        "eq", "ne", "hs", "lo", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt", "le", "al",
        "nv",
    ];
    const WRITERS: &[&str] = &[
        "adds", "subs", "ands", "bics", "adcs", "sbcs", "negs", "ngcs", "cmp", "cmn", "tst",
        "ccmp", "ccmn", "fcmp", "fcmpe", "fccmp", "fccmpe",
    ];
    let flags = instruction.flags();
    let mnemonic = instruction.mnemonic();
    // `b.eq`, `bc.eq`, `flt.eq`: the condition is part of the mnemonic.
    if let Some((_, suffix)) = mnemonic.split_once('.') {
        let index = CONDITIONS.iter().position(|c| *c == suffix).unwrap();
        let expected = FlagSet::tested_by(u8::try_from(index).unwrap());
        if flags.read != expected {
            violations.add(instruction, &format!("reads {:?}", flags.read));
        }
        return;
    }
    let condition = instruction.operands().iter().find_map(|operand| {
        if let Operand::Condition(condition) = operand {
            Some(*condition)
        } else {
            None
        }
    });
    match condition {
        Some(condition) if !flags.read.contains(condition.flags()) => {
            violations.add(
                instruction,
                &format!("reads {:?} for {condition:?}", flags.read),
            );
        }
        None if !flags.read.is_empty()
            && !READERS.contains(&mnemonic)
            && !mnemonic.starts_with("cpy")
            && !mnemonic.starts_with("set") =>
        {
            violations.add(
                instruction,
                &format!("reads {:?} without a condition", flags.read),
            );
        }
        _ => {}
    }
    if WRITERS.contains(&mnemonic)
        && instruction.encoding().groups().first() != Some(&"sve")
        && flags.written != FlagSet::NZCV
    {
        violations.add(instruction, &format!("writes {:?}", flags.written));
    }
}

/// Branches with link write x30; first-fault and non-fault loads update
/// FFR.
fn check_implicit(instruction: Instruction, violations: &mut Violations) {
    let implicit = instruction.implicit();
    let mnemonic = instruction.mnemonic();
    let x30 = Register::new(RegisterClass::X, 30);
    let ffr = Register::new(RegisterClass::Ffr, 0);
    if matches!(
        mnemonic,
        "bl" | "blr" | "blraa" | "blraaz" | "blrab" | "blrabz"
    ) && !implicit.writes.contains(&x30)
    {
        violations.add(instruction, "branch with link does not write x30");
    }
    if (mnemonic.starts_with("ldff1") || mnemonic.starts_with("ldnf1"))
        && !(implicit.reads.contains(&ffr) && implicit.writes.contains(&ffr))
    {
        violations.add(instruction, "first-fault load does not update FFR");
    }
}

/// Invariants of the access metadata over every per-encoding sweep word.
#[test]
fn access_is_consistent() {
    let instructions = sweep_instructions();
    let mut violations = Violations::default();
    for &instruction in &instructions {
        check_values(instruction, &mut violations);
        check_memory(instruction, &mut violations);
        check_predication(instruction, &mut violations);
        check_flags(instruction, &mut violations);
        check_implicit(instruction, &mut violations);
    }
    eprintln!("{} words checked", instructions.len());
    violations.assert_none("access metadata inconsistent");
}

/// What `tools/exarmo-oracle --analysis` says of one word.
struct ExarmoAnalysis {
    /// Flags read and written (N = 8, Z = 4, C = 2, V = 1).
    read: u8,
    written: u8,
    /// The number of operands of exarmo's operand view.
    operands: usize,
    /// `R`/`W` if a system operation reads or writes its register.
    sysop: char,
    /// Operands the ACLE intrinsics take as arguments and give as results.
    arguments: Vec<usize>,
    results: Vec<usize>,
    /// `L`/`S` for an intrinsic's read-only/writable pointer.
    pointer: char,
}

impl ExarmoAnalysis {
    fn parse(line: &str) -> Self {
        let field = |prefix: char| -> &str {
            line.split(' ')
                .find_map(|part| part.strip_prefix(prefix))
                .unwrap()
        };
        let flags = u8::from_str_radix(field('F'), 16).unwrap();
        let indices = |text: &str| -> Vec<usize> {
            if text == "-" {
                return Vec::new();
            }
            text.split(',').map(|i| i.parse().unwrap()).collect()
        };
        Self {
            read: flags >> 4,
            written: flags & 15,
            operands: field('K').len(),
            sysop: field('S').chars().next().unwrap(),
            arguments: indices(field('R')),
            results: indices(field('W')),
            pointer: field('P').chars().next().unwrap(),
        }
    }
}

/// Counts of the exarmo comparison.
#[derive(Default)]
struct ExarmoComparison {
    words: usize,
    flags_agree: usize,
    /// exarmo reads all four flags for any condition but `al`/`nv`; binbun
    /// the ones the condition tests.
    condition_precision: usize,
    /// Differences the pseudocode settles in binbun's favour (see
    /// `exarmo_differs`).
    justified: BTreeMap<&'static str, usize>,
    bindings: usize,
    bindings_agree: usize,
    /// Words whose operand views differ in length, so intrinsic bindings
    /// cannot be mapped.
    unmapped: usize,
    sysops: usize,
    pointers: usize,
    disagreements: Violations,
}

/// Why binbun's flags differ from exarmo's for `instruction`, when the
/// difference is known and the pseudocode is on binbun's side.
fn exarmo_differs(instruction: Instruction, theirs: &ExarmoAnalysis) -> Option<&'static str> {
    let mnemonic = instruction.mnemonic();
    let flags = instruction.flags();
    if mnemonic.starts_with("cpy") || mnemonic.starts_with("set") {
        // exarmo: every stage reads and writes NZCV. The pseudocode reads
        // PSTATE into `nzcv` first in every stage, but the prologue
        // overwrites it before use and is the only stage that writes
        // PSTATE back; the main and epilogue stages test only C (and N,
        // the direction of a CPY under option B).
        return Some("memory copy and set stages");
    }
    let mask = u8::try_from(instruction.word() & 15).unwrap();
    if mnemonic == "rmif" && theirs.written == 15 && flags.written == FlagSet::from_bits(mask) {
        // exarmo: RMIF writes all four. The pseudocode writes only the
        // flags whose `mask` bit is set.
        return Some("rmif mask");
    }
    if matches!(mnemonic, "mrs" | "msr") && theirs.read == 0 && theirs.written == 0 {
        // exarmo has no flags for system register moves; MRS and MSR of
        // NZCV read and write them.
        return Some("mrs/msr nzcv");
    }
    None
}

impl ExarmoComparison {
    fn flags(&mut self, instruction: Instruction, theirs: &ExarmoAnalysis) {
        let ours = instruction.flags();
        let read = FlagSet::from_bits(theirs.read);
        let written = FlagSet::from_bits(theirs.written);
        if ours.read == read && ours.written == written {
            self.flags_agree += 1;
        } else if ours.written == written
            && theirs.read == 15
            && !ours.read.is_empty()
            && read.contains(ours.read)
        {
            self.condition_precision += 1;
        } else if let Some(reason) = exarmo_differs(instruction, theirs) {
            *self.justified.entry(reason).or_default() += 1;
        } else {
            self.disagreements.add(
                instruction,
                &format!(
                    "flags read {:x} written {:x}, exarmo {:x} {:x}",
                    ours.read.bits(),
                    ours.written.bits(),
                    theirs.read,
                    theirs.written
                ),
            );
        }
    }

    fn operands(&mut self, instruction: Instruction, theirs: &ExarmoAnalysis) {
        let operands = instruction.operands();
        let access = instruction.access();
        if theirs.sysop != '-' {
            self.sysops += 1;
            let register = operands
                .iter()
                .zip(access.iter())
                .filter(|(o, _)| matches!(o, Operand::Register(r) if r.class == RegisterClass::X))
                .map(|(_, &a)| a)
                .next_back();
            let expected = if theirs.sysop == 'R' {
                Access::Read
            } else {
                Access::Write
            };
            if register.is_some_and(|a| a != expected) {
                self.disagreements.add(
                    instruction,
                    &format!("system operation register, exarmo {}", theirs.sysop),
                );
            }
        }
        if theirs.arguments.is_empty() && theirs.results.is_empty() {
            return;
        }
        if theirs.operands != operands.len() {
            self.unmapped += 1;
            return;
        }
        for (index, &access) in access.iter().enumerate() {
            let argument = theirs.arguments.contains(&index);
            let result = theirs.results.contains(&index);
            if !argument && !result {
                continue;
            }
            self.bindings += 1;
            let memory = matches!(operands.as_slice()[index], Operand::Memory(_));
            // A pointer argument is the memory operand: its access is the
            // memory access.
            let ok = if memory {
                match theirs.pointer {
                    'L' => access == Access::Read,
                    _ => access == Access::Write,
                }
            } else {
                (!argument || access.reads()) && (!result || access.writes())
            };
            if ok {
                self.bindings_agree += 1;
            } else {
                self.disagreements.add(
                    instruction,
                    &format!("operand {index}: argument {argument}, result {result}"),
                );
            }
        }
        if theirs.pointer != '-' {
            self.pointers += 1;
            let kind = instruction.memory().map(|m| m.kind);
            let expected = if theirs.pointer == 'L' {
                MemoryKind::Load
            } else {
                MemoryKind::Store
            };
            if kind != Some(expected) {
                self.disagreements.add(
                    instruction,
                    &format!("memory {kind:?}, exarmo pointer {}", theirs.pointer),
                );
            }
        }
    }

    fn compare(&mut self, words: &[u32]) {
        for words in words.chunks(1 << 20) {
            for (&word, answer) in words.iter().zip(ask_with(EXARMO, &["--analysis"], words)) {
                let (Ok(instruction), Some(answer)) = (decode(word), answer) else {
                    continue;
                };
                let theirs = ExarmoAnalysis::parse(&answer);
                self.words += 1;
                self.flags(instruction, &theirs);
                self.operands(instruction, &theirs);
            }
        }
    }

    fn report(&self, what: &str) {
        eprintln!(
            "{what}: {} words decoded by both; flags: {} agree, {} differ only in exarmo \
             reading all four flags for a condition, justified {:?}; intrinsic bindings: {} of \
             {} agree ({} words with differently split operands); {} system operation \
             registers and {} intrinsic pointers compared",
            self.words,
            self.flags_agree,
            self.condition_precision,
            self.justified,
            self.bindings_agree,
            self.bindings,
            self.unmapped,
            self.sysops,
            self.pointers,
        );
        self.disagreements.assert_none(what);
    }
}

/// Access metadata agrees with what exarmo-aarch64 0.4 knows of the same
/// words: its condition flags (read from the Execute pseudocode; it reads
/// all four flags for any condition), the ACLE intrinsic bindings of the
/// Advanced SIMD operands (an argument is read, a result written, a
/// read-only pointer is a load), and the register access of system
/// operations, on every per-encoding sweep word and, with
/// `BINBUN_ARM64_CORPUS`, the corpus.
#[test]
#[ignore = "needs BINBUN_EXARMO_ORACLE (built with --analysis support)"]
fn access_matches_exarmo() {
    let package = Package::read(PACKAGE).unwrap();
    let mut rng = Rng(env_number("BINBUN_ORACLE_SEED", 0x5eed));
    let words = encoding_words(&package, &mut rng, |path, _| selected(path));
    let mut comparison = ExarmoComparison::default();
    comparison.compare(&words);
    comparison.report("per-encoding sweep");
    if std::env::var_os("BINBUN_ARM64_CORPUS").is_some() {
        let (words, binaries) = corpus_words();
        let mut comparison = ExarmoComparison::default();
        comparison.compare(&words);
        comparison.report(&format!("corpus ({binaries} binaries)"));
    }
}
