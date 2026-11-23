//! How much of a function's machine code its C says it came from
//! ([`coverage`]): the share of its instructions that some line's
//! provenance names ([`binbun_session::Provenance`], what the GUI tints
//! and the Python API's `addresses` give), leaving out only the
//! instructions that make no C at all ([`Class::NoC`]: nops, padding,
//! branch-target and pointer-authentication hints). The frame's code
//! ([`Class::Frame`]: callee-saved registers saved and restored, the
//! stack pointer adjusted, the frame pointer set) is counted, and its
//! unmapped instructions are reported apart.

use std::collections::BTreeMap;
use std::fmt;

use binbun::Database;
use binbun::analysis::x86_mode;
use binbun::cfg::FunctionId;
use binbun::decompile::Decompiled;
use binbun_aarch64::decode_bytes;
use binbun_loader::{Format, Image, Machine};
use binbun_print::c::function as print_c;
use binbun_print::layout::render_items;
use binbun_print::style::Style;
use binbun_semantics::core::Memory;
use binbun_session::Provenance;
use binbun_x86::decode;

/// A function's instructions against the lines of its C.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Coverage {
    /// The counted instructions some line came from.
    pub covered: usize,
    /// The instructions counted: all but those making no C
    /// ([`Class::NoC`]).
    pub counted: usize,
    /// The instructions left out ([`Class::NoC`]).
    pub excluded: usize,
    /// The counted instructions of the frame's code ([`Class::Frame`]) no
    /// line came from.
    pub frame: usize,
    /// The counted instructions no line came from, by mnemonic.
    pub unmapped: BTreeMap<String, usize>,
}

impl Coverage {
    /// The share of the counted instructions some line came from (none if
    /// none is counted).
    pub fn share(&self) -> Option<f64> {
        #[expect(clippy::cast_precision_loss, reason = "counts are far below 2^52")]
        (self.counted > 0).then(|| self.covered as f64 / self.counted as f64)
    }
}

impl fmt::Display for Coverage {
    /// `provenance 45/50 (no C 6, frame unmapped 1; unmapped jmp 3, mov 2)`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "provenance {}/{} (no C {}, frame unmapped {}",
            self.covered, self.counted, self.excluded, self.frame
        )?;
        for (n, (mnemonic, count)) in self.unmapped.iter().enumerate() {
            let lead = if n == 0 { "; unmapped" } else { "," };
            write!(f, "{lead} {mnemonic} {count}")?;
        }
        f.write_str(")")
    }
}

/// The instructions of function `id` of `database` (its blocks') against
/// the lines of `decompiled`'s C printed in `style`: which a line's
/// provenance names (its instructions without semantics as `opaque`
/// says).
///
/// # Errors
///
/// The image's code is not lifted, or the printer refuses the function.
pub fn coverage(
    database: &Database<'_>,
    id: FunctionId,
    decompiled: &Decompiled,
    style: &Style,
    opaque: binbun_print::c::Opaque,
) -> Result<Coverage, String> {
    let declarations = database
        .declarations()
        .ok_or_else(|| "the image's code is not lifted".to_owned())?;
    let printed = print_c(&decompiled.l2, declarations, style, database.data(), opaque)
        .map_err(|error| format!("cannot print: {error}"))?;
    let (text, spans, items) = render_items(&printed.document, style);
    // The definition is the printer's last item.
    let definition = items
        .last()
        .and_then(|&start| text.get(..start))
        .map(|before| before.matches('\n').count());
    let provenance = Provenance::new(
        &text,
        spans.into_iter().map(|span| (span.range, span.node)),
        &decompiled.l2,
        &decompiled.l1,
        definition,
    );
    let mut made: Vec<u64> = provenance
        .lines()
        .iter()
        .flat_map(|line| line.addresses.iter().copied())
        .collect();
    made.sort_unstable();
    made.dedup();
    let image = database.image();
    let program = database.program();
    let mut out = Coverage::default();
    let blocks = database
        .function(id)
        .map_or(&[][..], |function| function.blocks.as_slice());
    for block in blocks.iter().filter_map(|&block| program.blocks.get(block)) {
        let mut pc = block.start;
        while pc < block.end {
            let Some((length, text)) = instruction(image, pc) else {
                break;
            };
            let class = classify(&text, image.machine, image.format == Format::Pe);
            if class == Class::NoC {
                out.excluded += 1;
            } else if made.binary_search(&pc).is_ok() {
                out.counted += 1;
                out.covered += 1;
            } else {
                out.counted += 1;
                out.frame += usize::from(class == Class::Frame);
                let mnemonic = text.split_whitespace().next().unwrap_or_default();
                *out.unmapped.entry(mnemonic.to_owned()).or_default() += 1;
            }
            pc += length;
        }
    }
    Ok(out)
}

/// The length and text (x86 in Intel syntax) of the instruction at
/// `address` of `image`, if it decodes.
fn instruction(image: &Image<'_>, address: u64) -> Option<(u64, String)> {
    let mut bytes = [0u8; 15];
    let read = image.read(address, &mut bytes).unwrap_or(0);
    let bytes = bytes.get(..read)?;
    if image.machine == Machine::Aarch64 {
        let instruction = decode_bytes(bytes).ok()?;
        return Some((4, instruction.display(address).to_string()));
    }
    let mode = x86_mode(image.machine).ok()?;
    let instruction = decode(bytes, mode).ok()?;
    Some((
        instruction.len() as u64,
        instruction.intel(address).to_string(),
    ))
}

/// What an instruction is to the C.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Class {
    /// It makes no C at all: a nop, padding (`data16`, `int3`), a hint
    /// (`endbr64`, `bti`, `paciasp`).
    NoC,
    /// The frame's code: a save or restore of a callee-saved register
    /// (`push rbx`, `mov qword ptr [rsp+0x8], rbp`, `ldp x19, x20, [sp,
    /// #0x10]`), a stack adjustment (`sub rsp, 0x18`, `leave`), the frame
    /// pointer set (`mov x29, sp`).
    Frame,
    /// Anything else.
    Code,
}

/// What the instruction `text` (of `machine`; `windows`: under the
/// Windows calling convention, where `rsi`, `rdi` and `xmm6`–`xmm15` are
/// callee-saved) is to the C.
pub fn classify(text: &str, machine: Machine, windows: bool) -> Class {
    let text = text.trim();
    let (mnemonic, rest) = text.split_once(char::is_whitespace).unwrap_or((text, ""));
    let operands = operands(rest);
    match machine {
        Machine::Aarch64 => arm(mnemonic, &operands),
        Machine::X86 | Machine::X86_64 => x86(mnemonic, &operands, windows),
        Machine::Arm | Machine::Other => Class::Code,
    }
}

/// The operands of `text`, split at the commas outside brackets.
fn operands(text: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let (mut depth, mut start) = (0usize, 0);
    for (at, c) in text.char_indices() {
        match c {
            '[' | '{' => depth += 1,
            ']' | '}' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                out.push(text.get(start..at).unwrap_or_default().trim());
                start = at + 1;
            }
            _ => {}
        }
    }
    let last = text.get(start..).unwrap_or_default().trim();
    if !last.is_empty() {
        out.push(last);
    }
    out
}

/// The register a memory operand `[base…]` is based on (`[rsp+0x8]`:
/// `rsp`; `[sp, #0x10]!`: `sp`), if it is one.
fn base(operand: &str) -> Option<&str> {
    let inside = operand.split_once('[')?.1;
    inside
        .split(['+', '-', ',', ']', '*'])
        .next()
        .map(str::trim)
}

fn x86(mnemonic: &str, operands: &[&str], windows: bool) -> Class {
    let saved = |register: &str| {
        matches!(
            register,
            "rbx" | "rbp" | "r12" | "r13" | "r14" | "r15" | "ebx" | "ebp"
        ) || (windows
            && (matches!(register, "rsi" | "rdi" | "esi" | "edi")
                || register
                    .strip_prefix("xmm")
                    .is_some_and(|n| n.parse::<u8>().is_ok_and(|n| (6..=15).contains(&n)))))
    };
    let stack = |operand: &str| {
        operand.contains('[') && matches!(base(operand), Some("rsp" | "rbp" | "esp" | "r11"))
    };
    match (mnemonic, operands) {
        // `data16` alone: a prefix padding a nop.
        ("nop" | "data16" | "endbr64" | "endbr32" | "int3" | "fnop", _)
        | ("xchg", ["ax", "ax"]) => Class::NoC,
        ("leave", _)
        | ("sub" | "add" | "lea" | "and" | "mov", ["rsp" | "esp", _])
        | ("mov", ["rbp", "rsp"] | ["ebp", "esp"]) => Class::Frame,
        ("push" | "pop", [register]) if !register.contains('[') && !register.starts_with("0x") => {
            Class::Frame
        }
        ("mov" | "movaps" | "movups" | "movdqa" | "movdqu" | "movapd", [destination, source])
            if (stack(destination) && saved(source)) || (saved(destination) && stack(source)) =>
        {
            Class::Frame
        }
        _ => Class::Code,
    }
}

fn arm(mnemonic: &str, operands: &[&str]) -> Class {
    let saved = |register: &str| {
        let numbered = |prefix: char, range: core::ops::RangeInclusive<u8>| {
            register
                .strip_prefix(prefix)
                .and_then(|n| n.parse::<u8>().ok())
                .is_some_and(|n| range.contains(&n))
        };
        numbered('x', 19..=30) || numbered('d', 8..=15) || matches!(register, "fp" | "lr")
    };
    let stack = |operand: &str| matches!(base(operand), Some("sp" | "x29" | "fp"));
    match (mnemonic, operands) {
        ("nop" | "bti" | "paciasp" | "autiasp" | "pacibsp" | "autibsp" | "hint" | "xpaclri", _) => {
            Class::NoC
        }
        ("sub" | "add", ["sp", "sp", ..])
        | ("mov", ["sp", "x29" | "fp"] | ["x29" | "fp", "sp"])
        | ("add", ["x29" | "fp", "sp", ..]) => Class::Frame,
        ("stp" | "ldp" | "str" | "ldr" | "stur" | "ldur", [registers @ .., _]) => {
            let memory = operands.iter().find(|o| o.contains('['));
            let frame = !registers.is_empty()
                && memory.is_some_and(|m| stack(m))
                && registers
                    .iter()
                    .filter(|r| !r.contains('[') && !r.starts_with('#'))
                    .all(|r| saved(r));
            if frame { Class::Frame } else { Class::Code }
        }
        _ => Class::Code,
    }
}

#[cfg(test)]
mod tests {
    use binbun_loader::Machine;

    use super::{Class, classify};

    #[test]
    fn nops_and_hints_make_no_c_and_the_frames_code_is_apart() {
        let x86 = |text| classify(text, Machine::X86_64, false);
        let windows = |text| classify(text, Machine::X86_64, true);
        let arm = |text| classify(text, Machine::Aarch64, false);
        for text in ["nop dword ptr [rax]", "endbr64", "data16", "int3"] {
            assert_eq!(x86(text), Class::NoC, "{text}");
        }
        for text in [
            "sub rsp, 0x18",
            "mov qword ptr [rsp], rbx",
            "mov rbp, qword ptr [rsp+0x8]",
            "push r12",
            "pop rbx",
            "leave",
        ] {
            assert_eq!(x86(text), Class::Frame, "{text}");
        }
        assert_eq!(windows("movaps xmmword ptr [rsp+0x20], xmm6"), Class::Frame);
        assert_eq!(windows("mov qword ptr [rsp+0x10], rsi"), Class::Frame);
        for text in [
            "mov qword ptr [rsp+0x10], rsi",
            "mov edx, r12d",
            "add r12d, 0x1",
            "push 0x10",
            "mov qword ptr [rax], rbx",
            "ret",
            "jmp 0x1210",
        ] {
            assert_eq!(x86(text), Class::Code, "{text}");
        }
        for text in ["paciasp", "bti\tj", "nop"] {
            assert_eq!(arm(text), Class::NoC, "{text}");
        }
        for text in [
            "sub\tsp, sp, #0x180",
            "stp\tx29, x30, [sp, #0x120]",
            "stp\tx29, x30, [sp, #-0x30]!",
            "add\tx29, sp, #0x120",
            "ldp\tx19, x20, [sp], #0x10",
            "ldr\td8, [sp, #0x8]",
        ] {
            assert_eq!(arm(text), Class::Frame, "{text}");
        }
        for text in [
            "str\tx1, [sp, #0x8]",
            "ldr\tx0, [x0, #0xb38]",
            "mov\tw4, w0",
            "stp\tx19, x1, [sp, #0x10]",
        ] {
            assert_eq!(arm(text), Class::Code, "{text}");
        }
    }
}
