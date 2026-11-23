//! The reference answers: the function starts an unstripped original
//! states, read with binutils, independently of binbun's loader (whose
//! mistakes would otherwise count for binbun and against everyone else).
//!
//! - ELF: defined `FUNC` and `IFUNC` symbols (`readelf -sW`, `.symtab` and
//!   `.dynsym`), and the start of every FDE (`readelf -wf`, `.eh_frame` and
//!   `.debug_frame` in the file itself).
//! - PE: COFF function symbols (`objdump -t`, type 0x20, section-relative),
//!   exports (`objdump -p`), and `.pdata` entries (`objdump -x`) other than
//!   chained ones, which continue a function begun elsewhere.

use std::collections::{BTreeSet, HashSet};
use std::path::Path;
use std::process::Command;

use binbun_loader::Format;

/// Function starts `file` states (unfiltered: callers keep those in code).
pub fn functions(file: &Path, format: Format) -> Result<BTreeSet<u64>, String> {
    match format {
        Format::Elf => elf(file),
        Format::Pe => pe(file),
        Format::MachO => Err("no reference function starts for Mach-O files".to_owned()),
    }
}

fn elf(file: &Path) -> Result<BTreeSet<u64>, String> {
    let mut starts = BTreeSet::new();
    // `Num: Value Size Type Bind Vis Ndx Name`
    for line in run("readelf", &["-sW"], file)?.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if let [_, value, _, kind, _, _, section, ..] = fields[..]
            && matches!(kind, "FUNC" | "IFUNC")
            && section != "UND"
            && let Some(address) = hex(value)
        {
            starts.insert(address);
        }
    }
    // `... FDE cie=... pc=BEGIN..END`. Without following `.gnu_debuglink`
    // (`-wN`): readelf fails if the separate debug file is not installed.
    for line in run("readelf", &["-wN", "-wf"], file)?.lines() {
        if line.contains(" FDE ")
            && let Some(range) = line.split_whitespace().find_map(|f| f.strip_prefix("pc="))
            && let Some(address) = range.split("..").next().and_then(hex)
        {
            starts.insert(address);
        }
    }
    Ok(starts)
}

fn pe(file: &Path) -> Result<BTreeSet<u64>, String> {
    let mut starts = BTreeSet::new();

    // Section addresses, for section-relative symbols: `Idx Name Size VMA ...`.
    let mut sections = Vec::new();
    for line in run("objdump", &["-h"], file)?.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if let [index, _, _, vma, ..] = fields[..]
            && index.parse::<usize>().is_ok()
            && let Some(vma) = hex(vma)
        {
            sections.push(vma);
        }
    }
    // `[  4](sec  1)(fl 0x00)(ty   20)(scl   3) (nx 1) 0x0000000000000010 name`
    for line in run("objdump", &["-t"], file)?.lines() {
        let Some(rest) = line.split_once("(sec").map(|(_, rest)| rest) else {
            continue;
        };
        let section = rest
            .split(')')
            .next()
            .and_then(|n| n.trim().parse::<usize>().ok());
        let function = rest
            .split_once("(ty")
            .and_then(|(_, t)| t.split(')').next())
            .map(str::trim)
            == Some("20");
        let value = rest
            .split_once("(nx")
            .and_then(|(_, t)| t.split_once(')'))
            .and_then(|(_, t)| t.split_whitespace().next())
            .and_then(hex);
        if function
            && let (Some(section), Some(value)) = (section, value)
            && let Some(base) = section.checked_sub(1).and_then(|i| sections.get(i))
        {
            starts.insert(base + value);
        }
    }

    // Exports: `[   0] +base[   1] 00013660 Export RVA` (forwarders are not code).
    let private = run("objdump", &["-p"], file)?;
    let image_base = private
        .lines()
        .find_map(|line| line.strip_prefix("ImageBase"))
        .and_then(|value| hex(value.trim()))
        .ok_or("objdump -p: no ImageBase")?;
    for line in private.lines() {
        if let Some(fields) = line.strip_suffix("Export RVA")
            && let Some(rva) = fields.split_whitespace().last().and_then(hex)
        {
            starts.insert(image_base + rva);
        }
    }

    // `.pdata`: the function table (` VMA:\tBEGIN END UNWIND`), then the
    // unwind data, whose flags say which entries are chained
    // (` XDATA (rva: ...): BEGIN - END`, then `\tVersion: 1, Flags: ...`).
    let headers = run("objdump", &["-x"], file)?;
    let mut chained = HashSet::new();
    let mut lines = headers.lines().peekable();
    while let Some(line) = lines.next() {
        if line.contains("(rva:")
            && let Some(xdata) = line.split_whitespace().next().and_then(hex)
            && lines
                .peek()
                .is_some_and(|next| next.contains("UNW_FLAG_CHAININFO"))
        {
            chained.insert(xdata);
        }
    }
    let mut table = false;
    for line in headers.lines() {
        if line.starts_with("The Function Table") {
            table = true;
            continue;
        }
        if table {
            let Some((_, entry)) = line.split_once(":\t") else {
                if line.trim().is_empty() {
                    table = false;
                }
                continue;
            };
            let fields: Vec<Option<u64>> = entry.split_whitespace().map(hex).collect();
            if let [Some(begin), Some(_), Some(unwind)] = fields[..]
                && !chained.contains(&unwind)
            {
                starts.insert(begin);
            }
        }
    }
    Ok(starts)
}

/// The standard output of `program ARGS FILE`.
fn run(program: &str, args: &[&str], file: &Path) -> Result<String, String> {
    let output = Command::new(program)
        .args(args)
        .arg(file)
        .output()
        .map_err(|e| format!("{program}: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "{program} {} failed on {}",
            args.join(" "),
            file.display()
        ));
    }
    String::from_utf8(output.stdout).map_err(|e| format!("{program}: {e}"))
}

fn hex(text: &str) -> Option<u64> {
    u64::from_str_radix(text.trim_start_matches("0x"), 16).ok()
}
