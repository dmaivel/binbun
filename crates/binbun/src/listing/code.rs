//! Code: instructions in recovered blocks, the bytes between them, the
//! lines around functions and labels; instructions' text in the usual
//! disassembler conventions.

use binbun_aarch64::{Encoding, Sink, TokenKind, decode_bytes};
use binbun_isa::{Flow, Target};
use binbun_x86::{Category, Instruction, Mnemonic, decode, decode_length};

use crate::Database;
use crate::cfg::{Destination, Exit, Returns};
use crate::listing::build::Builder;
use crate::listing::data::{alignment, lay_out as lay_out_data};
use crate::listing::render::{bytes, slot_name};
use crate::listing::text::{COMMENTS, MNEMONIC, OPERANDS, PREVIEW, gpr_size, number, preview};
use crate::listing::{
    DataItem, DataKind, Decoder, Function, Item, Jump, LineKind, Listing, Rendered, Role, Section,
};
use crate::references::Kind;

/// The length of the instruction at the start of `bytes`.
pub(crate) fn length(decoder: Option<Decoder>, bytes: &[u8]) -> Option<u64> {
    match decoder? {
        Decoder::X86(mode) => decode_length(bytes, mode).ok().map(|n| n as u64),
        Decoder::Aarch64 => decode_bytes(bytes).ok().map(|_| 4),
    }
}

/// The width an AArch64 load or store accesses memory at, from its
/// mnemonic and data register (`ldrb` 1, `ldrh` 2, `ldr w0` 4, `ldr x0`
/// 8, `ldr q0` 16); 0 if not one.
pub(crate) fn arm_access_width(bytes: &[u8]) -> u8 {
    let Ok(i) = decode_bytes(bytes) else {
        return 0;
    };
    let mut tokens = Tokens::default();
    if i.format(0, &mut tokens).is_err() {
        return 0;
    }
    let mnemonic = tokens.0.first().map_or("", |(_, t)| t.as_str());
    if !(mnemonic.starts_with("ld") || mnemonic.starts_with("st")) {
        return 0;
    }
    if mnemonic.ends_with('b') {
        return 1;
    }
    if mnemonic.ends_with('h') {
        return 2;
    }
    if mnemonic.ends_with("sw") {
        return 4;
    }
    let register = tokens
        .0
        .iter()
        .find(|(k, _)| *k == TokenKind::Register)
        .map_or("", |(_, t)| t.as_str());
    match register.chars().next() {
        Some('w' | 's') => 4,
        Some('x' | 'd') => 8,
        Some('q') => 16,
        Some('h') => 2,
        Some('b') => 1,
        _ => 0,
    }
}

/// An AArch64 instruction's text as tokens.
#[derive(Default)]
struct Tokens(Vec<(TokenKind, String)>);

impl Sink for Tokens {
    fn token(&mut self, kind: TokenKind, text: &str) -> std::fmt::Result {
        self.0.push((kind, text.to_owned()));
        Ok(())
    }
}

/// Lays out code section `section`: the recovered blocks' instructions,
/// what lies between them.
pub(crate) fn lay_out(b: &mut Builder<'_, '_>, section: &Section) {
    let mut pc = section.start;
    for (start, end, exit) in blocks(b, section) {
        if start < pc {
            continue;
        }
        gap(b, pc, start);
        pc = start;
        let end = end.min(section.end);
        while pc < end {
            let Some(len) = length(b.l.decoder, b.bytes(pc, 15)).filter(|&n| pc + n <= end) else {
                lay_out_data(b, pc, end, end);
                pc = end;
                break;
            };
            let last = pc + len >= end;
            instruction(b, pc, len, last.then_some(exit));
            pc += len;
        }
    }
    gap(b, pc, section.end);
}

/// The bytes `start..end` between blocks: data if code reads them or a
/// table is there, `align` if padding, else instructions swept linearly;
/// the user's items (bytes undefined, data) as data.
fn gap(b: &mut Builder<'_, '_>, start: u64, end: u64) {
    let mut pc = start;
    for (at, item_end) in b.user_items(start, end) {
        let (at, item_end) = (at.max(start), item_end.min(end));
        unclaimed_gap(b, pc, at);
        lay_out_data(b, at, item_end, item_end);
        pc = item_end;
    }
    unclaimed_gap(b, pc, end);
}

/// The bytes `start..end` between blocks, none the user's: data if code
/// reads them or a table is there, `align` if padding, else instructions
/// swept linearly.
fn unclaimed_gap(b: &mut Builder<'_, '_>, start: u64, end: u64) {
    if start >= end {
        return;
    }
    match classify_gap(b, start, end) {
        Gap::Data => {
            lay_out_data(b, start, end, end);
            return;
        }
        Gap::Align(to) => {
            b.push(start, LineKind::Data, 0, Item::Data);
            b.l.items.push(DataItem {
                start,
                size: end - start,
                kind: DataKind::Align { to },
            });
            return;
        }
        Gap::Code => {}
    }
    let mut pc = start;
    while pc < end {
        if let Some(len) = length(b.l.decoder, b.bytes(pc, 15)).filter(|&n| pc + n <= end) {
            instruction(b, pc, len, None);
            pc += len;
        } else {
            lay_out_data(b, pc, pc + 1, end);
            pc += 1;
        }
    }
}

/// What the bytes between recovered blocks are.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Gap {
    /// Data: code reads them, or a jump table is there.
    Data,
    /// Padding to this alignment.
    Align(u64),
    /// Code no recovered function reaches, swept linearly.
    Code,
}

fn classify_gap(b: &Builder<'_, '_>, start: u64, end: u64) -> Gap {
    let read = b
        .refs
        .within(start..end)
        .iter()
        .any(|r| !matches!(r.kind, Kind::Call | Kind::Jump));
    if read || b.tables.range(start..end).next().is_some() {
        return Gap::Data;
    }
    match alignment(start, end) {
        Some(to) if padding(b, start, end) => Gap::Align(to),
        Some(_) | None => Gap::Code,
    }
}

/// The recovered blocks of code section `section`, by address, as `(start,
/// end, exit)`.
fn blocks(b: &Builder<'_, '_>, section: &Section) -> Vec<(u64, u64, Exit)> {
    let program = b.db.program();
    program
        .blocks_by_address()
        .filter(|&(start, _)| start >= section.start && start < section.end)
        .filter_map(|(start, id)| {
            program
                .blocks
                .get(id)
                .map(|block| (start, block.end, block.exit))
        })
        .collect()
}

/// The direct calls' and jumps' targets of the code between recovered
/// blocks (swept linearly, as it is laid out), and whether each is
/// called.
pub(crate) fn swept_targets(b: &Builder<'_, '_>, section: &Section) -> Vec<(u64, bool)> {
    let mut targets = Vec::new();
    let sweep_unclaimed = |start: u64, end: u64, targets: &mut Vec<(u64, bool)>| {
        if start >= end || classify_gap(b, start, end) != Gap::Code {
            return;
        }
        let mut at = start;
        while at < end {
            let Some((len, flow)) = flow(b.l.decoder, b.bytes(at, 15), at) else {
                at += 1;
                continue;
            };
            match flow {
                Flow::Jump(Target::Address(to)) | Flow::Branch(Target::Address(to)) => {
                    targets.push((to, false));
                }
                Flow::Call(Target::Address(to)) => targets.push((to, true)),
                Flow::Next
                | Flow::Jump(_)
                | Flow::Branch(_)
                | Flow::Call(_)
                | Flow::Return
                | Flow::Trap { .. }
                | Flow::SystemCall
                | Flow::ExceptionReturn
                | Flow::Halt => {}
            }
            at += len;
        }
    };
    // The user's items are no code.
    let sweep = |start: u64, end: u64, targets: &mut Vec<(u64, bool)>| {
        let mut pc = start;
        for (at, item_end) in b.user_items(start, end) {
            sweep_unclaimed(pc, at.max(start), targets);
            pc = item_end.min(end);
        }
        sweep_unclaimed(pc, end, targets);
    };
    let mut pc = section.start;
    for (start, end, _) in blocks(b, section) {
        if start < pc {
            continue;
        }
        sweep(pc, start, &mut targets);
        pc = end.min(section.end);
    }
    sweep(pc, section.end, &mut targets);
    targets.retain(|&(to, _)| section.start <= to && to < section.end);
    targets
}

/// The length of the instruction at the start of `bytes` (at `pc`) and
/// how it transfers control.
pub(crate) fn flow(decoder: Option<Decoder>, bytes: &[u8], pc: u64) -> Option<(u64, Flow)> {
    match decoder? {
        Decoder::X86(mode) => decode(bytes, mode)
            .ok()
            .map(|i| (i.len() as u64, i.flow(pc))),
        Decoder::Aarch64 => decode_bytes(bytes).ok().map(|i| (4, i.flow(pc))),
    }
}

/// What an instruction that pads is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fill {
    /// A `nop` of any length (x86's multi-byte `nop word ptr cs:[…]`).
    Nop,
    /// A trap toolchains fill with: x86's `int3`, AArch64's zero word
    /// (`udf #0`).
    Trap,
}

/// CET's `endbr64`/`endbr32`, which the decoder reads as the reserved-NOP
/// form they reuse: code, not padding.
fn endbr(bytes: &[u8]) -> Option<&'static str> {
    match bytes {
        [0xf3, 0x0f, 0x1e, 0xfa] => Some("endbr64"),
        [0xf3, 0x0f, 0x1e, 0xfb] => Some("endbr32"),
        _ => None,
    }
}

/// What the x86 instruction `i` of bytes `data` pads with, if it is a
/// padding instruction: by the decoder's class (`NOP`, `WIDENOP`), and
/// `int3`.
fn x86_fill(i: &Instruction, data: &[u8]) -> Option<Fill> {
    if matches!(i.category(), Category::Nop | Category::Widenop) && endbr(data).is_none() {
        Some(Fill::Nop)
    } else if i.mnemonic() == Mnemonic::Int3 {
        Some(Fill::Trap)
    } else {
        None
    }
}

/// What the AArch64 instruction `i` pads with, if it is a padding
/// instruction: `nop` by its encoding, the zero word (`udf #0`).
fn arm_fill(i: binbun_aarch64::Instruction) -> Option<Fill> {
    if i.word() == 0 {
        Some(Fill::Trap)
    } else if i.encoding() == Encoding::NOP_HI_hints {
        Some(Fill::Nop)
    } else {
        None
    }
}

/// The length of the instruction at the start of `bytes` and what it pads
/// with, if it is a padding instruction.
fn fill(decoder: Option<Decoder>, bytes: &[u8]) -> Option<(u64, Fill)> {
    match decoder? {
        Decoder::X86(mode) => {
            let i = decode(bytes, mode).ok()?;
            let fill = x86_fill(&i, bytes.get(..i.len())?)?;
            Some((i.len() as u64, fill))
        }
        Decoder::Aarch64 => arm_fill(decode_bytes(bytes).ok()?).map(|fill| (4, fill)),
    }
}

/// The role of an instruction's mnemonic, by how it transfers control:
/// jumps' and branches', calls', returns' (from exceptions too); a
/// `nop`'s is padding's, and a trap's that pads ([`Fill::Trap`]) where
/// no recovered block holds it (`reached` says whether one does: code
/// reaching an `int3` breaks there).
fn mnemonic_role(flow: Flow, fill: Option<Fill>, reached: impl FnOnce() -> bool) -> Role {
    match flow {
        Flow::Jump(_) | Flow::Branch(_) => Role::JumpMnemonic,
        Flow::Call(_) => Role::CallMnemonic,
        Flow::Return | Flow::ExceptionReturn => Role::ReturnMnemonic,
        Flow::Next if fill == Some(Fill::Nop) => Role::PaddingMnemonic,
        Flow::Trap { conditional: false } if fill == Some(Fill::Trap) && !reached() => {
            Role::PaddingMnemonic
        }
        Flow::Next | Flow::Trap { .. } | Flow::SystemCall | Flow::Halt => Role::Mnemonic,
    }
}

/// Whether `start..end` is all padding: `nop`s and `int3`s (x86), `nop`s
/// and zero words (AArch64).
fn padding(b: &Builder<'_, '_>, start: u64, end: u64) -> bool {
    let mut pc = start;
    while pc < end {
        let Some((len, _)) = fill(b.l.decoder, b.bytes(pc, (end - pc).min(15))) else {
            return false;
        };
        pc += len;
    }
    pc == end
}

/// The instruction at `pc` and the lines before and after it.
fn instruction(b: &mut Builder<'_, '_>, pc: u64, len: u64, exit: Option<Exit>) {
    let owner = b.l.function_of(pc).map(|(_, entry)| entry);
    let item = if owner.is_some() {
        Item::Function
    } else {
        Item::Code
    };
    if b.l.functions.contains_key(&pc) {
        header(b, pc);
    } else if b.l.names.contains_key(&pc) {
        b.push(pc, LineKind::Blank, 0, item);
        b.push(pc, LineKind::Label, 0, item);
        for k in 1..b.xref_count(pc, pc + 1) {
            b.push(pc, LineKind::Xref, k, item);
        }
    }
    b.push(
        pc,
        LineKind::Instruction,
        u32::try_from(len).unwrap_or(u32::MAX),
        item,
    );
    b.l.stats.instructions += 1;
    let falls = match exit {
        Some(Exit::Jump(Destination::Address(to))) => {
            jump(b, pc, to, owner, false);
            false
        }
        Some(Exit::Branch(destination)) => {
            if let Destination::Address(to) = destination {
                jump(b, pc, to, owner, true);
            }
            true
        }
        Some(Exit::Jump(_) | Exit::Return | Exit::Stop | Exit::Invalid) => false,
        Some(Exit::Call { returns, .. }) => returns != Returns::No,
        Some(Exit::Next | Exit::Limit) | None => true,
    };
    let ends =
        owner.is_some_and(|entry| b.l.functions.get(&entry).is_some_and(|f| f.end == pc + len));
    if ends {
        b.push(pc, LineKind::End, 0, item);
        b.push(pc, LineKind::Blank, 0, item);
    }
    if !falls {
        // The separator heads what follows, except after a function's end.
        b.push(
            if ends { pc } else { pc + len },
            LineKind::Separator,
            0,
            item,
        );
    }
    if b.l.decoder == Some(Decoder::Aarch64) {
        pair_pages(b, pc);
    }
}

/// Records a jump within one function, for the arrows.
fn jump(b: &mut Builder<'_, '_>, from: u64, to: u64, owner: Option<u64>, conditional: bool) {
    if owner.is_some() && b.l.function_of(to).map(|(_, e)| e) == owner {
        b.l.jumps.push(Jump {
            from,
            to,
            conditional,
            crosses: false,
            lane: 0,
        });
    }
}

/// The header of the function at `entry`: banner, attributes, prototype,
/// `public`, `proc near` with its cross-references, the frame block.
fn header(b: &mut Builder<'_, '_>, entry: u64) {
    let Some(f) = b.l.functions.get(&entry).cloned() else {
        return;
    };
    let item = Item::Function;
    for kind in [LineKind::Blank, LineKind::Banner, LineKind::Blank] {
        b.push(entry, kind, 0, item);
    }
    if f.noreturn || f.bp_frame {
        b.push(entry, LineKind::Attributes, 0, item);
        b.push(entry, LineKind::Blank, 0, item);
    }
    if f.prototype.is_some() {
        b.push(entry, LineKind::Prototype, 0, item);
    }
    if f.public {
        b.push(entry, LineKind::Public, 0, item);
    }
    b.push(entry, LineKind::Proc, 0, item);
    for k in 1..b.xref_count(entry, entry + 1) {
        b.push(entry, LineKind::Xref, k, item);
    }
    if !f.frame.is_empty() {
        b.push(entry, LineKind::Blank, 0, item);
        for k in 0..f.frame.len() {
            b.push(
                entry,
                LineKind::Frame,
                u32::try_from(k).unwrap_or(u32::MAX),
                item,
            );
        }
        b.push(entry, LineKind::Blank, 0, item);
    }
}

/// The most instructions after an `adrp` searched for its uses.
const PAGE_USES: u64 = 32;

/// Pairs the AArch64 `adrp xN, page` at `pc` with the instructions after
/// it that add the low 12 bits of an address to `xN` (`add xM, xN,
/// #lo`, a load or store `[xN, #lo]`), until `xN` is written again or
/// control leaves (`b`, `br`, `ret`; `bl` and `blr`, which may change the
/// caller-saved `x0`–`x18`): both are then written with the address's
/// name (`name@PAGE`, `#name@PAGEOFF`), the `adrp` with the first's.
fn pair_pages(b: &mut Builder<'_, '_>, pc: u64) {
    let adrp = arm_tokens(b.bytes(pc, 4), pc);
    if adrp.0.first().is_none_or(|(_, m)| m != "adrp") {
        return;
    }
    let Some(register) = registers(&adrp).first().cloned() else {
        return;
    };
    let Some(page) = adrp
        .0
        .iter()
        .find(|(k, _)| *k == TokenKind::Address)
        .and_then(|(_, t)| parse_hex(t))
    else {
        return;
    };
    let caller_saved = register
        .get(1..)
        .and_then(|n| n.parse::<u8>().ok())
        .is_some_and(|n| n <= 18);
    for at in (1..=PAGE_USES).map(|k| pc + 4 * k) {
        let i = arm_tokens(b.bytes(at, 4), at);
        let Some(mnemonic) = i.0.first().map(|(_, m)| m.as_str()) else {
            break;
        };
        let regs = registers(&i);
        let base = if mnemonic == "add" {
            regs.get(1)
        } else if mnemonic.starts_with("ld")
            || mnemonic.starts_with("st")
            || mnemonic.starts_with("prfm")
        {
            memory_base(&i)
        } else {
            None
        };
        let low =
            i.0.iter()
                .rev()
                .find(|(k, _)| *k == TokenKind::Immediate)
                .and_then(|(_, t)| parse_hex(t));
        if base == Some(&register)
            && let Some(low) = low.filter(|&low| low < 0x1000)
        {
            let target = page + low;
            b.l.pages.entry(pc).or_insert(target);
            b.l.pages.insert(at, target);
        }
        let writes = regs.first() == Some(&register) && !mnemonic.starts_with("st");
        let leaves = matches!(
            mnemonic,
            "b" | "br" | "ret" | "braa" | "brab" | "retaa" | "retab"
        ) || (caller_saved && matches!(mnemonic, "bl" | "blr" | "blraa" | "blrab"));
        if writes || leaves {
            break;
        }
    }
}

/// The text tokens of the AArch64 instruction in `bytes` at `pc`.
fn arm_tokens(bytes: &[u8], pc: u64) -> Tokens {
    let mut tokens = Tokens::default();
    if let Ok(i) = decode_bytes(bytes)
        && i.format(pc, &mut tokens).is_err()
    {
        tokens.0.clear();
    }
    tokens
}

/// The registers of an instruction's text, in order.
fn registers(tokens: &Tokens) -> Vec<String> {
    tokens
        .0
        .iter()
        .filter(|(k, _)| *k == TokenKind::Register)
        .map(|(_, t)| t.clone())
        .collect()
}

/// The base register of a memory operand (the register after `[`).
fn memory_base(tokens: &Tokens) -> Option<&String> {
    let open = tokens
        .0
        .iter()
        .position(|(k, t)| *k == TokenKind::Punctuation && t.contains('['))?;
    tokens
        .0
        .get(open + 1..)?
        .iter()
        .find(|(k, _)| *k == TokenKind::Register)
        .map(|(_, t)| t)
}

fn parse_hex(text: &str) -> Option<u64> {
    let t = text.trim_start_matches('#');
    t.strip_prefix("0x")
        .map_or_else(|| t.parse().ok(), |h| u64::from_str_radix(h, 16).ok())
}

/// The mnemonic (with its prefixes) and the operands of a disassembly.
fn split_mnemonic(text: &str) -> (&str, &str) {
    const PREFIXES: [&str; 9] = [
        "rep", "repe", "repz", "repne", "repnz", "lock", "bnd", "notrack", "data16",
    ];
    let mut end;
    let mut rest = text;
    loop {
        let word_end = rest.find(' ').unwrap_or(rest.len());
        let word = rest.get(..word_end).unwrap_or("");
        end = text.len() - rest.len() + word_end;
        rest = rest.get(word_end..).unwrap_or("").trim_start_matches(' ');
        if !PREFIXES.contains(&word) || rest.is_empty() {
            break;
        }
    }
    let (m, o) = text.split_at(end.min(text.len()));
    (m, o.trim())
}

/// The listing's spelling of an x86 mnemonic: `ja`, `jg`, `jge` (and
/// their `cmov` forms) for XED's `jnbe`, `jnle`, `jnl`; `retn`; `int 3`.
fn listing_mnemonic(mnemonic: &str) -> String {
    let (prefixes, last) = mnemonic
        .rsplit_once(' ')
        .map_or(("", mnemonic), |(p, l)| (p, l));
    let renamed = match last {
        "ret" => "retn".to_owned(),
        "int3" => "int 3".to_owned(),
        // Jumps' and `cmov`s' conditions are renamed, not `set`s'.
        _ => ["j", "cmov"]
            .into_iter()
            .find_map(|stem| {
                let condition = last.strip_prefix(stem)?;
                let renamed = match condition {
                    "nbe" => "a",
                    "nle" => "g",
                    "nl" => "ge",
                    _ => return None,
                };
                Some(format!("{stem}{renamed}"))
            })
            .unwrap_or_else(|| last.to_owned()),
    };
    if prefixes.is_empty() {
        renamed
    } else {
        format!("{prefixes} {renamed}")
    }
}

/// A memory operand of XED's text: `qword ptr fs:[rax+rbx*4-0x10]{1to8}`.
#[derive(Debug, Default, PartialEq, Eq)]
struct MemoryText<'a> {
    size: Option<&'a str>,
    segment: Option<&'a str>,
    base: Option<&'a str>,
    index: Option<&'a str>,
    scale: u64,
    displacement: i64,
    suffix: &'a str,
}

fn parse_memory(operand: &str) -> Option<MemoryText<'_>> {
    let open = operand.find('[')?;
    let close = operand.rfind(']')?;
    let head = operand.get(..open)?;
    let inner = operand.get(open + 1..close)?;
    let mut m = MemoryText {
        suffix: operand.get(close + 1..)?,
        scale: 1,
        ..MemoryText::default()
    };
    for word in head.split_whitespace() {
        if let Some(segment) = word.strip_suffix(':') {
            m.segment = Some(segment);
        } else if word != "ptr" {
            m.size = Some(word);
        }
    }
    let mut sign = 1i64;
    let mut term = String::new();
    let mut terms = Vec::new();
    for c in inner.chars().chain(std::iter::once('+')) {
        if c == '+' || c == '-' {
            if !term.is_empty() {
                terms.push((sign, std::mem::take(&mut term)));
            }
            sign = if c == '-' { -1 } else { 1 };
        } else {
            term.push(c);
        }
    }
    for (sign, term) in terms {
        let start = inner.find(term.as_str())?;
        let word = inner.get(start..start + term.len())?;
        if let Some(hex) = word.strip_prefix("0x") {
            let value = u64::from_str_radix(hex, 16).ok()?;
            m.displacement = m
                .displacement
                .wrapping_add(sign.wrapping_mul(value.cast_signed()));
        } else if let Some((register, scale)) = word.split_once('*') {
            m.index = Some(register);
            m.scale = scale.parse().ok()?;
        } else if m.base.is_none() {
            m.base = Some(word);
        } else {
            m.index = Some(word);
        }
    }
    Some(m)
}

fn size_bytes(word: &str) -> u32 {
    match word {
        "byte" => 1,
        "word" => 2,
        "dword" => 4,
        "fword" => 6,
        "qword" => 8,
        "tbyte" => 10,
        "xmmword" | "oword" => 16,
        "ymmword" => 32,
        "zmmword" => 64,
        _ => 0,
    }
}

/// What an x86 operand's rewriting needs to know.
struct Context<'a> {
    pc: u64,
    next: u64,
    len: u64,
    mnemonic: &'a str,
    /// The sizes of the general-purpose registers among its operands.
    registers: Vec<u32>,
    /// Whether it sign- or zero-extends its source (`movsx`, `movzx`,
    /// `movsxd`).
    extends: bool,
}

impl Listing {
    /// Instruction line of `len` bytes at `pc`.
    pub(crate) fn render_instruction(
        &self,
        db: &Database<'_>,
        r: &mut Rendered,
        pc: u64,
        len: u32,
        base: usize,
    ) {
        let data = bytes(db.image(), pc, u64::from(len));
        let comment = match self.decoder {
            Some(Decoder::X86(mode)) => match decode(data, mode) {
                Ok(i) => self.render_x86(db, r, pc, &i, data, base),
                Err(_) => None,
            },
            Some(Decoder::Aarch64) => self.render_arm(db, r, pc, data, base),
            None => None,
        };
        // A call that never returns ends its block with nothing after it:
        // said, so the block does not read as the function's end.
        let program = db.program();
        let noreturn = program
            .block_containing(pc)
            .and_then(|b| program.blocks.get(b))
            .is_some_and(|b| {
                b.end == pc + u64::from(len)
                    && matches!(
                        b.exit,
                        Exit::Call {
                            returns: Returns::No,
                            ..
                        }
                    )
            });
        let comment = match (comment, noreturn) {
            (Some(text), true) => Some(format!("{text}; noreturn")),
            (None, true) => Some("noreturn".to_owned()),
            (comment, false) => comment,
        };
        if let Some(text) = comment {
            r.pad_to(base + COMMENTS, true);
            r.push(Role::AutoComment, format!("; {text}"));
        }
    }

    /// The `rbp`-based function whose frame the instruction at `pc` uses:
    /// the function whose block holds it (a cold part's is its owner's),
    /// else the function it follows (code recovery did not reach).
    fn frame_owner(&self, pc: u64) -> Option<&Function> {
        let owner = self
            .function_of(pc)
            .and_then(|(_, entry)| self.functions.get(&entry))
            .or_else(|| {
                self.functions
                    .range(..=pc)
                    .next_back()
                    .map(|(_, f)| f)
                    .filter(|f| pc < f.limit)
            })?;
        owner.bp_frame.then_some(owner)
    }

    /// An x86 instruction; the comment it takes, if any.
    fn render_x86(
        &self,
        db: &Database<'_>,
        r: &mut Rendered,
        pc: u64,
        instruction: &Instruction,
        data: &[u8],
        base: usize,
    ) -> Option<String> {
        r.pad_to(base + MNEMONIC, false);
        if let Some(mnemonic) = endbr(data) {
            r.push(Role::Mnemonic, mnemonic);
            return None;
        }
        let text = instruction.intel(pc).to_string();
        let (mnemonic, operands) = split_mnemonic(&text);
        let shown = listing_mnemonic(mnemonic);
        let role = mnemonic_role(instruction.flow(pc), x86_fill(instruction, data), || {
            reached(db, pc)
        });
        r.push(role, shown.clone());
        // String instructions' implied operands are not written (`rep
        // stosq`).
        if operands.is_empty() || instruction.category() == Category::Stringop {
            return None;
        }
        r.pad_to(base + OPERANDS, true);
        let ops: Vec<&str> = operands.split(", ").collect();
        let cx = Context {
            pc,
            next: pc + data.len() as u64,
            len: data.len() as u64,
            mnemonic: shown.rsplit(' ').next().unwrap_or(""),
            registers: ops.iter().filter_map(|o| gpr_size(o)).collect(),
            extends: matches!(shown.as_str(), "movsx" | "movzx" | "movsxd"),
        };
        let mut comment = None;
        for (i, op) in ops.iter().enumerate() {
            if i > 0 {
                r.push(Role::Punctuation, ",");
                r.push(Role::Space, " ");
            }
            if let Some(c) = self.x86_operand(db, r, op, &cx) {
                comment = Some(c);
            }
        }
        comment
    }

    /// One x86 operand; a comment it calls for.
    fn x86_operand(
        &self,
        db: &Database<'_>,
        r: &mut Rendered,
        op: &str,
        cx: &Context<'_>,
    ) -> Option<String> {
        if let Some(m) = parse_memory(op) {
            return self.x86_memory(r, &m, cx);
        }
        if let Some(hex) = op.strip_prefix("0x") {
            let value = u64::from_str_radix(hex, 16).unwrap_or(0);
            let branch = cx.mnemonic.starts_with('j')
                || cx.mnemonic == "call"
                || cx.mnemonic.starts_with("loop");
            if branch && self.options.symbolic && self.section_of(value).is_some() {
                if cx.mnemonic.starts_with('j') && cx.len <= 3 {
                    r.push(Role::OperandKeyword, "short ");
                }
                self.push_expr(r, value);
                return None;
            }
            let referenced = !self.relocatable
                && self.options.symbolic
                && self.section_of(value).is_some()
                && db.references().to(value).iter().any(|x| x.from == cx.pc);
            if referenced {
                r.push(Role::OperandKeyword, "offset ");
                self.push_expr(r, value);
                return self.preview_of(value);
            }
            r.push(Role::Number, number(value, self.options.numbers));
            return None;
        }
        push_words(r, op);
        None
    }

    /// A memory operand: names for rip-relative and absolute addresses,
    /// frame variables for `rbp`-relative slots, numbers as the options
    /// write them.
    fn x86_memory(&self, r: &mut Rendered, m: &MemoryText<'_>, cx: &Context<'_>) -> Option<String> {
        let size = m.size.map_or(0, size_bytes);
        let agen = cx.mnemonic == "lea";
        let style = self.options.numbers;
        // Elsewhere a register operand of the same size gives it.
        let implied = agen || size == 0 || cx.registers.contains(&size);
        let push_size = |r: &mut Rendered, implied: bool| {
            if !implied && let Some(word) = m.size {
                r.push(Role::OperandKeyword, format!("{word} ptr "));
            }
        };
        let rip = m.base == Some("rip") && m.index.is_none();
        let absolute = m.base.is_none() && m.index.is_none() && !self.relocatable;
        let ea = if rip {
            cx.next.wrapping_add_signed(m.displacement)
        } else {
            m.displacement.cast_unsigned()
        };
        if (rip || absolute) && self.section_of(ea).is_some() {
            if !self.options.symbolic {
                push_size(r, false);
                self.raw_memory(r, m);
                return Some(self.expr(ea).text);
            }
            // A name gives the size where an item of that width starts
            // there; in an aggregate or inside an item the access's size
            // is written.
            push_size(
                r,
                agen || size == 0 || self.item_width(ea) == Some(u64::from(size)),
            );
            if !agen {
                push_segment(r, m.segment.unwrap_or(if rip { "cs" } else { "ds" }));
            }
            self.push_expr(r, ea);
            return self.preview_of(ea);
        }
        let slot = (self.options.symbolic && m.base == Some("rbp") && m.index.is_none())
            .then(|| self.frame_owner(cx.pc))
            .flatten()
            .and_then(|f| f.frame.iter().find(|s| s.offset == m.displacement));
        if let Some(slot) = slot {
            // The variable's size gives the access's.
            push_size(r, agen || size == 0 || slot.size == size);
            r.push(Role::Punctuation, "[");
            r.push(Role::Register, "rbp");
            r.push(Role::Punctuation, "+");
            r.push_local(slot_name(slot.offset));
            r.push(Role::Punctuation, "]");
            return None;
        }
        if m.base.is_none() && m.index.is_none() {
            // An absolute address that names nothing: `qword ptr ds:8`.
            push_size(r, implied);
            push_segment(r, m.segment.unwrap_or("ds"));
            r.push(Role::Number, number(ea, style));
            return None;
        }
        // An extension's source in registers' memory has its size written.
        push_size(r, implied && !cx.extends);
        if let Some(segment) = m.segment {
            push_segment(r, segment);
        }
        let table = !self.relocatable
            && self.options.symbolic
            && m.displacement > 0
            && self.section_of(ea).is_some();
        if table {
            self.push_expr(r, ea);
        }
        r.push(Role::Punctuation, "[");
        let mut started = false;
        for register in [m.base, m.index].into_iter().flatten() {
            if started {
                r.push(Role::Punctuation, "+");
            }
            r.push(Role::Register, register);
            if Some(register) == m.index && m.scale > 1 {
                r.push(Role::Punctuation, "*");
                r.push(Role::Number, m.scale.to_string());
            }
            started = true;
        }
        if !table && (m.displacement != 0 || !started) {
            if started {
                r.push(
                    Role::Punctuation,
                    if m.displacement < 0 { "-" } else { "+" },
                );
                r.push(Role::Number, number(m.displacement.unsigned_abs(), style));
            } else {
                r.push(Role::Number, number(m.displacement.cast_unsigned(), style));
            }
        }
        r.push(Role::Punctuation, "]");
        if !m.suffix.is_empty() {
            push_words(r, m.suffix);
        }
        None
    }

    /// The decoder's memory operand in `88h` numbers: `[rip+10E4DEh]`.
    fn raw_memory(&self, r: &mut Rendered, m: &MemoryText<'_>) {
        if let Some(segment) = m.segment {
            push_segment(r, segment);
        }
        r.push(Role::Punctuation, "[");
        if let Some(base) = m.base {
            r.push(Role::Register, base);
            r.push(
                Role::Punctuation,
                if m.displacement < 0 { "-" } else { "+" },
            );
        }
        r.push(
            Role::Number,
            number(m.displacement.unsigned_abs(), self.options.numbers),
        );
        r.push(Role::Punctuation, "]");
    }

    /// The width of the value the item at `address` is, if one starts
    /// there and has one.
    fn item_width(&self, address: u64) -> Option<u64> {
        let item = self.item(address)?;
        match item.kind {
            DataKind::Scalar { width } | DataKind::Uninitialised { width } if width > 0 => {
                Some(u64::from(width))
            }
            DataKind::Pointer { .. } | DataKind::Import { .. } => Some(item.size),
            DataKind::Scalar { .. }
            | DataKind::Uninitialised { .. }
            | DataKind::String { .. }
            | DataKind::Values { .. }
            | DataKind::Fill { .. }
            | DataKind::Align { .. }
            | DataKind::Table { .. }
            | DataKind::Unexplored => None,
        }
    }

    /// The preview of the string at `address`, if one starts there.
    fn preview_of(&self, address: u64) -> Option<String> {
        self.strings
            .get(&address)
            .map(|text| preview(text, PREVIEW + 24))
    }

    /// An AArch64 instruction in LLVM's syntax with names: labels, and
    /// `name@PAGE` / `#name@PAGEOFF` for the `adrp` pairs that form an
    /// address; the comment it takes, if any.
    fn render_arm(
        &self,
        db: &Database<'_>,
        r: &mut Rendered,
        pc: u64,
        data: &[u8],
        base: usize,
    ) -> Option<String> {
        r.pad_to(base + MNEMONIC, false);
        let i = decode_bytes(data).ok()?;
        let mut tokens = Tokens::default();
        i.format(pc, &mut tokens).ok()?;
        let role = mnemonic_role(i.flow(pc), arm_fill(i), || reached(db, pc));
        let paired = self.pages.get(&pc).copied();
        let mut comment = None;
        let mut first = true;
        let mut mnemonic = String::new();
        for (kind, text) in &tokens.0 {
            match kind {
                TokenKind::Mnemonic => {
                    mnemonic.clone_from(text);
                    r.push(role, text.clone());
                }
                TokenKind::Whitespace if first => {
                    first = false;
                    r.pad_to(base + OPERANDS, true);
                }
                TokenKind::Whitespace => r.push(Role::Space, text.clone()),
                TokenKind::Register => r.push(Role::Register, text.clone()),
                TokenKind::Punctuation => r.push(Role::Punctuation, text.clone()),
                TokenKind::Text => r.push(Role::Keyword, text.clone()),
                TokenKind::Address => {
                    let value = parse_hex(text).unwrap_or(0);
                    match paired.filter(|_| mnemonic == "adrp" && self.options.symbolic) {
                        Some(target) => {
                            let mut name = self.expr(target);
                            name.text.push_str("@PAGE");
                            r.tokens.push(name);
                        }
                        None if self.options.symbolic
                            && self.section_of(value).is_some()
                            && mnemonic != "adrp" =>
                        {
                            self.push_expr(r, value);
                            comment = comment.or_else(|| self.preview_of(value));
                        }
                        None => r.push(Role::Number, text.clone()),
                    }
                }
                TokenKind::Immediate => match paired.filter(|&t| {
                    self.options.symbolic
                        && mnemonic != "adrp"
                        && parse_hex(text) == Some(t & 0xfff)
                }) {
                    Some(target) => {
                        let mut name = self.expr(target);
                        name.text = format!("#{}@PAGEOFF", name.text);
                        r.tokens.push(name);
                        comment = comment.or_else(|| self.preview_of(target));
                    }
                    None => r.push(Role::Number, text.clone()),
                },
            }
        }
        comment
    }
}

/// Whether a recovered block holds the instruction at `pc`.
fn reached(db: &Database<'_>, pc: u64) -> bool {
    db.program().block_containing(pc).is_some()
}

/// A memory operand's segment and its colon (`cs:`, `fs:`).
fn push_segment(r: &mut Rendered, segment: &str) {
    r.push(Role::OperandKeyword, format!("{segment}:"));
}

/// Registers, keywords and punctuation of an operand that is neither
/// memory nor a number (`xmm0`, `st(1)`, `{k1}{z}`).
fn push_words(r: &mut Rendered, text: &str) {
    let mut word = String::new();
    let flush = |r: &mut Rendered, word: &mut String| {
        if !word.is_empty() {
            let role = if word.starts_with("0x") || word.starts_with(|c: char| c.is_ascii_digit()) {
                Role::Number
            } else {
                Role::Register
            };
            r.push(role, std::mem::take(word));
        }
    };
    for c in text.chars() {
        if c.is_ascii_alphanumeric() || c == '_' {
            word.push(c);
        } else {
            flush(r, &mut word);
            r.push(Role::Punctuation, c.to_string());
        }
    }
    flush(r, &mut word);
}

#[cfg(test)]
mod tests {
    use binbun_isa::{Flow, Target};
    use binbun_x86::Mode;

    use super::{
        Fill, MemoryText, fill, listing_mnemonic, mnemonic_role, parse_memory, split_mnemonic,
    };
    use crate::listing::{Decoder, Role};

    #[test]
    fn padding_instructions_are_nops_of_any_length_and_fill_traps() {
        let x86 = Some(Decoder::X86(Mode::Bits64));
        // `cs nop word ptr [rax+rax+0]`, ten bytes.
        let long = [0x2e, 0x66, 0x0f, 0x1f, 0x84, 0, 0, 0, 0, 0];
        assert_eq!(fill(x86, &long), Some((10, Fill::Nop)));
        assert_eq!(fill(x86, &[0x90]), Some((1, Fill::Nop)));
        assert_eq!(fill(x86, &[0xcc]), Some((1, Fill::Trap)));
        // `endbr64` reuses a reserved NOP's encoding but starts code;
        // `int 29h` and `ud2` trap but toolchains do not pad with them.
        assert_eq!(fill(x86, &[0xf3, 0x0f, 0x1e, 0xfa]), None);
        assert_eq!(fill(x86, &[0xcd, 0x29]), None);
        assert_eq!(fill(x86, &[0x0f, 0x0b]), None);
        let arm = Some(Decoder::Aarch64);
        assert_eq!(fill(arm, &[0x1f, 0x20, 0x03, 0xd5]), Some((4, Fill::Nop)));
        assert_eq!(fill(arm, &[0, 0, 0, 0]), Some((4, Fill::Trap)));
        // `brk #0x3e8`, `yield` (a hint beside `nop`'s).
        assert_eq!(fill(arm, &[0x00, 0x7d, 0x20, 0xd4]), None);
        assert_eq!(fill(arm, &[0x3f, 0x20, 0x03, 0xd5]), None);
    }

    #[test]
    fn a_padding_trap_is_code_where_a_recovered_block_holds_it() {
        let trap = Flow::Trap { conditional: false };
        let role = |flow, fill, reached| mnemonic_role(flow, fill, || reached);
        assert_eq!(role(trap, Some(Fill::Trap), false), Role::PaddingMnemonic);
        assert_eq!(role(trap, Some(Fill::Trap), true), Role::Mnemonic);
        assert_eq!(role(trap, None, false), Role::Mnemonic);
        // A `nop` pads wherever it is.
        assert_eq!(
            role(Flow::Next, Some(Fill::Nop), true),
            Role::PaddingMnemonic
        );
        assert_eq!(
            role(Flow::Branch(Target::Indirect), None, true),
            Role::JumpMnemonic
        );
        assert_eq!(
            role(Flow::ExceptionReturn, None, true),
            Role::ReturnMnemonic
        );
    }

    #[test]
    fn memory_operands_parse_into_their_parts() {
        assert_eq!(
            parse_memory("qword ptr fs:[rax+rbx*4-0x10]"),
            Some(MemoryText {
                size: Some("qword"),
                segment: Some("fs"),
                base: Some("rax"),
                index: Some("rbx"),
                scale: 4,
                displacement: -0x10,
                suffix: "",
            })
        );
        let rip = parse_memory("ptr [rip+0x10e4de]").unwrap();
        assert_eq!(
            (rip.size, rip.base, rip.displacement),
            (None, Some("rip"), 0x0010_e4de)
        );
        let two = parse_memory("word ptr cs:[rax+rax*1]").unwrap();
        assert_eq!(
            (two.base, two.index, two.scale),
            (Some("rax"), Some("rax"), 1)
        );
    }

    #[test]
    fn mnemonics_take_listing_spellings_and_keep_prefixes() {
        assert_eq!(listing_mnemonic("jnbe"), "ja");
        assert_eq!(listing_mnemonic("jnle"), "jg");
        // `set`'s conditions stay as the decoder spells them.
        assert_eq!(listing_mnemonic("setnl"), "setnl");
        assert_eq!(listing_mnemonic("cmovnbe"), "cmova");
        assert_eq!(listing_mnemonic("jnb"), "jnb");
        assert_eq!(listing_mnemonic("notrack jmp"), "notrack jmp");
        assert_eq!(listing_mnemonic("ret"), "retn");
        assert_eq!(
            split_mnemonic("rep stosq qword ptr [rdi]"),
            ("rep stosq", "qword ptr [rdi]")
        );
        assert_eq!(split_mnemonic("notrack jmp rax"), ("notrack jmp", "rax"));
        assert_eq!(split_mnemonic("ret"), ("ret", ""));
    }
}
