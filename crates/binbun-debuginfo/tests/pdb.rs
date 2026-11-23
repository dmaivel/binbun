#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers fail loudly"
)]
//! The PDB reader against `llvm-pdbutil dump --types --symbols` on the MSVC
//! fixture: a few functions' parameters (names, types, entry registers) and
//! return types, and the fields of every struct both state (names,
//! offsets, primitive types, bit-fields); and the frame-relative offsets'
//! conversion to canonical-frame-address-relative ones.
//!
//! Windows on ARM64 against the Python 3.15.2 build for ARM64 and its PDB,
//! and ntdll.dll 10.0.26100.9711's public PDB (as `llvm-pdbutil dump
//! --symbols --types --publics` and `llvm-readobj --unwind` state them),
//! skipped where the data is absent: `python315.dll` from the ARM64 corpus
//! (`$BINBUN_ARM64_CORPUS`, else `~/.cache/binbun-arm64/corpus`:
//! `scripts/aarch64-corpus.sh`), its PDB from python.org's
//! `3.15.2/arm64/core_pdb.msi`; ntdll.dll (`scripts/typedb.sh` pins it) and
//! its PDB from Microsoft's symbol server; both under
//! `~/.cache/binbun-truth-data/pdb` (`python-3.15.2-arm64/python315.pdb`,
//! `ntdll-arm64/ntdll.dll`, `ntdll-arm64.pdb`).

use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Command;
use std::sync::LazyLock;

use binbun_debuginfo::info::DebugModel;
use binbun_debuginfo::info::model::{Encoding, Function, Place, Type};
use binbun_debuginfo::info::pdb::Frame;
use object::{Object, ObjectSection};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(name)
}

fn model() -> DebugModel {
    let pdb = std::fs::read(fixture("msvc-x86_64.pdb")).unwrap();
    let image = std::fs::read(fixture("msvc-x86_64.exe")).unwrap();
    let model = binbun_debuginfo::info::pdb::read(&pdb, &image).unwrap();
    assert!(model.damage.is_empty(), "{:?}", model.damage);
    model
}

/// `llvm-pdbutil dump ARGS` on the fixture's PDB, or `None` if the tool is
/// not installed.
fn pdbutil(args: &[&str]) -> Option<String> {
    let output = Command::new("llvm-pdbutil")
        .arg("dump")
        .args(args)
        .arg(fixture("msvc-x86_64.pdb"))
        .output()
        .ok()?;
    assert!(output.status.success());
    Some(String::from_utf8(output.stdout).unwrap())
}

/// The text between the first `` ` `` and the last.
fn quoted(line: &str) -> &str {
    let start = line.find('`').unwrap();
    let end = line.rfind('`').unwrap();
    &line[start + 1..end]
}

/// The value after `key = ` up to the next `,` or `]`.
fn value<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let start = line.find(&format!("{key} = "))? + key.len() + 3;
    let rest = &line[start..];
    let end = rest.find([',', ']']).unwrap_or(rest.len());
    Some(rest[..end].trim())
}

/// A type as text without qualifiers and spaces: `const char* const` and
/// `char *` are both `char*`.
fn normal(text: &str) -> String {
    text.replace("const", "")
        .replace("volatile", "")
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect()
}

/// A `CodeView` register name as the reader names it: the 64-bit register.
/// `llvm-pdbutil` has no names for the float lanes of `xmm0`..`xmm7`
/// (`xmm0_0`..`xmm7_3`, numbers 162..193; `xmm0l`..`xmm7l`, 194..201):
/// `unknown (195)`.
fn register(name: &str) -> String {
    if let Some(number) = name.strip_prefix("unknown (") {
        let number: u16 = number.trim_end_matches(')').parse().unwrap();
        return match number {
            162..=193 => format!("xmm{}", (number - 162) / 4),
            194..=201 => format!("xmm{}", number - 194),
            _ => panic!("{name}"),
        };
    }
    let name = name.to_lowercase();
    match name.as_str() {
        "eax" | "ecx" | "edx" | "ebx" | "esi" | "edi" => format!("r{}", &name[1..]),
        _ => name.trim_end_matches(['d', 'w', 'b']).to_owned(),
    }
}

/// One procedure of the symbol dump: its section offset, type text and
/// parameters (name, type text, entry register).
#[derive(Debug, Default)]
struct Procedure {
    offset: u64,
    ty: String,
    parameters: Vec<(String, String, Option<String>)>,
}

fn procedures(text: &str) -> HashMap<String, Procedure> {
    let mut out: HashMap<String, Procedure> = HashMap::new();
    let mut current: Option<(String, String)> = None;
    let mut lines = text.lines().peekable();
    // Whether the last S_LOCAL was a parameter.
    let mut in_parameter = false;
    while let Some(line) = lines.next() {
        if line.contains("| S_GPROC32 ") || line.contains("| S_LPROC32 ") {
            let name = quoted(line).to_owned();
            let next = lines.next().unwrap();
            let address = value(next, "addr").unwrap();
            let (_, offset) = address.split_once(':').unwrap();
            let ty = lines.next().unwrap();
            let ty = quoted(ty);
            // `0x1237 (int (int))`, or `<no type>`.
            let ty = ty
                .find('(')
                .map_or_else(String::new, |start| ty[start + 1..ty.len() - 1].to_owned());
            out.entry(name.clone()).or_insert(Procedure {
                offset: offset.parse().unwrap(),
                ty,
                parameters: Vec::new(),
            });
            current = Some((name, address.to_owned()));
            in_parameter = false;
        } else if line.contains("| S_LOCAL ") {
            let name = quoted(line).to_owned();
            let next = lines.next().unwrap();
            in_parameter = next.ends_with("flags = param");
            if in_parameter && let Some((procedure, _)) = &current {
                let start = next.find('(').unwrap();
                let end = next.rfind(')').unwrap();
                let ty = next[start + 1..end].to_owned();
                out.get_mut(procedure)
                    .unwrap()
                    .parameters
                    .push((name, ty, None));
            }
        } else if line.contains("| S_DEFRANGE_REGISTER ") {
            let next = lines.next().unwrap();
            if in_parameter
                && let Some((procedure, address)) = &current
                && value(next, "range start") == Some(address.as_str())
            {
                let parameter = out
                    .get_mut(procedure)
                    .unwrap()
                    .parameters
                    .last_mut()
                    .unwrap();
                parameter
                    .2
                    .get_or_insert_with(|| register(value(next, "register").unwrap()));
            }
        } else if line.contains("| S_END ") {
            current = None;
        }
    }
    out
}

#[test]
fn parameters_equal_pdbutil() {
    let Some(text) = pdbutil(&["--symbols"]) else {
        return;
    };
    let procedures = procedures(&text);
    let model = model();
    let image = std::fs::read(fixture("msvc-x86_64.exe")).unwrap();
    let file = object::File::parse(&*image).unwrap();
    let text_start = file.section_by_name(".text").unwrap().address();
    let mut registers = 0;
    for name in [
        "one",
        "two",
        "three",
        "four",
        "five",
        "six",
        "mixed",
        "report",
        "apply",
        "release_second",
        "measure",
    ] {
        let procedure = &procedures[name];
        let entry = text_start + procedure.offset;
        let function = &model.functions[&entry];
        assert_eq!(function.name.as_deref(), Some(name));
        // `int (int, int, int)`: the return type is before the arguments.
        let returns = &procedure.ty[..procedure.ty.find(" (").unwrap()];
        assert_eq!(
            normal(&model.display(function.returns)),
            normal(returns),
            "{name}"
        );
        assert_eq!(
            function.parameters.len(),
            procedure.parameters.len(),
            "{name}"
        );
        for (parameter, (expected, ty, at_entry)) in
            function.parameters.iter().zip(&procedure.parameters)
        {
            assert_eq!(parameter.name.as_deref(), Some(expected.as_str()));
            if !ty.contains('(') {
                assert_eq!(
                    normal(&model.display(parameter.ty)),
                    normal(ty),
                    "{name} {expected}"
                );
            }
            if let Some(at_entry) = at_entry {
                let stated = match parameter.place_at(entry) {
                    Some(Place::Register(register)) => Some(*register),
                    _ => None,
                };
                assert_eq!(stated, Some(at_entry.as_str()), "{name} {expected}");
                registers += 1;
            }
        }
    }
    assert!(registers >= 25, "{registers} entry registers compared");
}

/// The struct definitions of the type dump, by name and size: their
/// `LF_MEMBER`s (name, offset, type text, bit-field (position, width)).
type Members = Vec<(String, u64, String, Option<(u64, u64)>)>;

fn structs(text: &str) -> HashMap<(String, u64), Vec<Members>> {
    // Records: index → (kind line, the lines after it).
    let mut records: HashMap<String, (String, Vec<String>)> = HashMap::new();
    let mut order = Vec::new();
    let mut current: Option<String> = None;
    for line in text.lines() {
        if let Some((index, rest)) = line.trim_start().split_once(" | LF_")
            && index.starts_with("0x")
        {
            records.insert(index.to_owned(), (rest.to_owned(), Vec::new()));
            order.push(index.to_owned());
            current = Some(index.to_owned());
        } else if let Some(index) = &current {
            records
                .get_mut(index)
                .unwrap()
                .1
                .push(line.trim().to_owned());
        }
    }
    let mut out: HashMap<(String, u64), Vec<Members>> = HashMap::new();
    for index in &order {
        let (head, lines) = &records[index];
        if !head.starts_with("STRUCTURE ") {
            continue;
        }
        let options = lines
            .iter()
            .find(|line| line.starts_with("options:"))
            .unwrap();
        if options.contains("forward ref") {
            continue;
        }
        let size: u64 = options.rsplit("sizeof ").next().unwrap().parse().unwrap();
        let list = lines
            .iter()
            .find_map(|line| line.split_once("field list: ").map(|(_, list)| list))
            .unwrap();
        let mut members = Vec::new();
        for line in &records[list].1 {
            let Some(member) = line.strip_prefix("- LF_MEMBER ") else {
                continue;
            };
            let ty = value(member, "Type").unwrap();
            let (ty_index, ty_text) = ty.split_once(' ').unwrap_or((ty, ""));
            let mut ty_text = ty_text.trim_matches(['(', ')']).to_owned();
            let mut bits = None;
            if let Some((head, lines)) = records.get(ty_index)
                && head.starts_with("BITFIELD")
            {
                let line = &lines[0];
                let underlying = value(line, "type").unwrap();
                underlying[underlying.find('(').unwrap() + 1..underlying.len() - 1]
                    .clone_into(&mut ty_text);
                bits = Some((
                    value(line, "bit offset").unwrap().parse().unwrap(),
                    value(line, "# bits").unwrap().parse().unwrap(),
                ));
            }
            members.push((
                quoted(member).to_owned(),
                value(member, "offset").unwrap().parse().unwrap(),
                ty_text,
                bits,
            ));
        }
        out.entry((quoted(head).to_owned(), size))
            .or_default()
            .push(members);
    }
    out
}

#[test]
fn struct_fields_equal_pdbutil() {
    let Some(text) = pdbutil(&["--types"]) else {
        return;
    };
    let structs = structs(&text);
    let model = model();
    let mut compared = 0;
    for ty in &model.types {
        let Type::Composite(composite) = ty else {
            continue;
        };
        let (Some(name), Some(size)) = (&composite.name, composite.size) else {
            continue;
        };
        let Some(definitions) = structs.get(&(name.clone(), size)) else {
            continue;
        };
        let fields: Vec<_> = composite
            .fields
            .iter()
            .map(|field| {
                (
                    field.name.clone().unwrap(),
                    field.offset,
                    model.display(field.ty),
                    field.bits,
                )
            })
            .collect();
        // Same-named definitions (`<unnamed-tag>`): one of them.
        let matching = definitions.iter().find(|members| {
            members.len() == fields.len()
                && members.iter().zip(&fields).all(|(member, field)| {
                    member.0 == field.0 && member.1 == field.1 && member.3 == field.3
                })
        });
        let members = matching.unwrap_or_else(|| panic!("{name}: {fields:?} vs {definitions:?}"));
        for (member, field) in members.iter().zip(&fields) {
            // Primitive member types print their name.
            if !member.2.is_empty() && !member.2.contains(['*', '[', '(']) {
                assert_eq!(normal(&member.2), normal(&field.2), "{name}.{}", member.0);
            }
        }
        compared += 1;
    }
    assert!(compared >= 5, "{compared} structs compared");
}

/// `five`'s fifth parameter is at the frame pointer (`rsp`, `five` is a
/// leaf: CFA − `rsp` = 8) + 40: CFA + 32. `__scrt_get_show_window_mode`'s
/// `startup_info` is at `rsp` + 32 after `sub rsp, 152` (`ALLOC_LARGE
/// 152`): CFA − (8 + 152) + 32 = CFA − 128.
#[test]
fn frame_offsets_are_cfa_relative() {
    let model = model();
    let function = |name: &str| {
        model
            .functions
            .values()
            .find(|function| function.name.as_deref() == Some(name))
            .unwrap()
    };
    let five = function("five");
    assert_eq!(five.parameters[4].stack_slot(), Some(32));
    let show = function("__scrt_get_show_window_mode");
    let startup = show
        .locals
        .iter()
        .find(|local| local.name.as_deref() == Some("startup_info"))
        .unwrap();
    assert_eq!(startup.stack_slot(), Some(-128));
}

#[test]
fn unwind_info_frames() {
    // push rbx; sub rsp, 0x20: codes last-executed first.
    let pushed = [1, 6, 2, 0, 0x06, 0x32, 0x02, 0x30];
    let frame = Frame::from_unwind_info(&pushed).unwrap();
    assert_eq!(
        frame,
        Frame {
            stack: ("rsp", 8 + 8 + 0x20),
            frame: None,
            prologue: vec![(2, 8), (6, 0x20)],
        }
    );
    // The fifth argument (CFA + 0x20) is `rsp + 0x28` at the entry,
    // `rsp + 0x30` after the push, `rsp + 0x50` after the allocation.
    assert_eq!(frame.stack("rsp", 0x28, 0), Some(0x20));
    assert_eq!(frame.stack("rsp", 0x30, 2), Some(0x20));
    assert_eq!(frame.stack("rsp", 0x50, 6), Some(0x20));
    assert_eq!(frame.stack("rsp", 0x50, u64::MAX), Some(0x20));
    // push rbp; sub rsp, 0x40; lea rbp, [rsp + 0x20] (frame register rbp,
    // offset 2 × 16): rbp is 8 + 8 + 0x40 − 0x20 below the CFA.
    let framed = [1, 12, 3, 0x25, 0x0c, 0x03, 0x08, 0x72, 0x01, 0x50];
    assert_eq!(
        Frame::from_unwind_info(&framed),
        Some(Frame {
            stack: ("rsp", 8 + 8 + 0x40),
            frame: Some(("rbp", 8 + 8 + 0x40 - 0x20)),
            prologue: vec![(1, 8), (8, 0x40)],
        })
    );
    // Truncated codes.
    assert_eq!(Frame::from_unwind_info(&[1, 0, 2, 0, 0, 0x01]), None);
}

/// ARM64 packed unwind data states the whole frame: `FrameSize` × 16
/// below the CFA, `x29` there too where `CR` chains it (2, 3); a link
/// record (flag 3) is none.
#[test]
fn arm64_packed_frames() {
    // Flag 1, length 20, RegI 3, CR 3, FrameSize 3: `getpath_basename`'s.
    let chained = 1 | (20 << 2) | (3 << 16) | (3 << 21) | (3 << 23);
    assert_eq!(
        Frame::from_arm64_packed(chained),
        Some(Frame {
            stack: ("sp", 48),
            frame: Some(("x29", 48)),
            prologue: Vec::new(),
        })
    );
    // Flag 2 (a fragment), CR 0, FrameSize 1: `sub sp, sp, #16` alone.
    let unchained = 2 | (21 << 2) | (1 << 23);
    assert_eq!(
        Frame::from_arm64_packed(unchained),
        Some(Frame {
            stack: ("sp", 16),
            frame: None,
            prologue: Vec::new(),
        })
    );
    assert_eq!(Frame::from_arm64_packed(0x0077_48b3), None);
}

/// ARM64 `.xdata` unwind codes, listed last-executed first: `sp` moves by
/// each allocation and pre-indexed save, `x29` is set from `sp` as it
/// stood before the codes listed ahead of `set_fp`/`add_fp` ran.
#[test]
fn arm64_unwind_code_frames() {
    let frame = |stack, x29: Option<i64>| Frame {
        stack: ("sp", stack),
        frame: x29.map(|x29| ("x29", x29)),
        prologue: Vec::new(),
    };
    // `_safe_PyBytes_Find`: str x19, [sp, #-16]!; stp x29, lr, [sp,
    // #-176]!; mov x29, sp.
    assert_eq!(
        Frame::from_arm64_codes(&[0xe1, 0x95, 0xd4, 0x01, 0xe4]),
        Some(frame(192, Some(192)))
    );
    // stp x29, lr, [sp, #-16]!; mov x29, sp; sub sp, sp, #32: x29 is 16
    // below the CFA, sp 48. Epilogue codes after `end` do not count.
    assert_eq!(
        Frame::from_arm64_codes(&[0x02, 0xe1, 0x81, 0xe4, 0x02, 0xe4]),
        Some(frame(48, Some(16)))
    );
    // sub sp, sp, #64; stp x29, lr, [sp, #48]; add x29, sp, #48.
    assert_eq!(
        Frame::from_arm64_codes(&[0xe2, 0x06, 0x46, 0x04, 0xe4]),
        Some(frame(64, Some(16)))
    );
    // stp x19, x20, [sp, #-32]!; stp x21, x22, [sp, #16] (save_next);
    // stp d8, d9, [sp, #-16]! (save_fregp_x); str d10, [sp, #-16]!
    // (save_freg_x); stp d12, d13, [sp, #-32]! (save_any_reg, pre-indexed
    // pair); sub sp, sp, #1024 (alloc_m); sub sp, sp, #0x10000 (alloc_l);
    // pacibsp; nop.
    assert_eq!(
        Frame::from_arm64_codes(&[
            0xe3, 0xfc, 0xe0, 0x00, 0x10, 0x00, 0xc0, 0x40, 0xe7, 0x6c, 0x41, 0xde, 0x41, 0xda,
            0x01, 0xe6, 0xcc, 0x03, 0xe4,
        ]),
        Some(frame(32 + 16 + 16 + 32 + 1024 + 0x10000, None))
    );
    // save_r19r20_x: stp x19, x20, [sp, #-24]!; save_reg_x x20 at [sp,
    // #-(1 + 1) × 8]!; end_c then the parent's alloc_s.
    assert_eq!(
        Frame::from_arm64_codes(&[0x23, 0xd4, 0x21, 0xe5, 0x01, 0xe4]),
        Some(frame(24 + 16 + 16, None))
    );
    // Codes that end early; an SVE allocation; a trap frame.
    assert_eq!(Frame::from_arm64_codes(&[0x02, 0xe1]), None);
    assert_eq!(Frame::from_arm64_codes(&[0xc0]), None);
    assert_eq!(Frame::from_arm64_codes(&[0xdf, 0x02, 0xe4]), None);
    assert_eq!(Frame::from_arm64_codes(&[0xe8, 0xe4]), None);
}

/// An `.xdata` record's prologue codes follow its header (and the
/// extension word where both counts are 0) and its epilogue scopes, which
/// a record with the `E` bit has none of.
#[test]
fn arm64_xdata_frames() {
    let codes = [0xe1, 0x95, 0xd4, 0x01, 0xe4, 0x95, 0xd4, 0x01];
    let expected = Some(Frame {
        stack: ("sp", 192),
        frame: Some(("x29", 192)),
        prologue: Vec::new(),
    });
    let record = |words: &[u32]| -> Vec<u8> {
        let mut bytes: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
        bytes.extend(codes);
        bytes
    };
    // The function's length in instructions; two code words, one epilogue
    // scope (starting 33 instructions in, at code index 1).
    let length: u32 = 38;
    let start: u32 = 33;
    let scope = start | (1 << 22);
    assert_eq!(
        Frame::from_arm64_xdata(&record(&[length | (1 << 22) | (2 << 27), scope])),
        expected
    );
    // The counts in the extension word.
    assert_eq!(
        Frame::from_arm64_xdata(&record(&[length, 1 | (2 << 16), scope])),
        expected
    );
    // `E`: the epilogue's codes start at index 1, no scopes.
    assert_eq!(
        Frame::from_arm64_xdata(&record(&[length | (1 << 21) | (1 << 22) | (2 << 27)])),
        expected
    );
    // Fewer code bytes than the header counts.
    let short = record(&[length | (1 << 21) | (3 << 27)]);
    assert_eq!(Frame::from_arm64_xdata(&short), None);
}

/// The ARM64 oracle data's `file`: `$BINBUN_ARM64_CORPUS` (else
/// `~/.cache/binbun-arm64/corpus`) for an image of the corpus, else
/// `~/.cache/binbun-truth-data/pdb`; `None` where it is absent.
fn arm64_data(corpus: bool, file: &str) -> Option<Vec<u8>> {
    let home = std::env::home_dir()?;
    let path = if corpus {
        std::env::var_os("BINBUN_ARM64_CORPUS")
            .map_or_else(|| home.join(".cache/binbun-arm64/corpus"), PathBuf::from)
    } else {
        home.join(".cache/binbun-truth-data/pdb")
    }
    .join(file);
    let data = std::fs::read(&path).ok();
    if data.is_none() {
        eprintln!("skipped: no {}", path.display());
    }
    data
}

/// python315.dll's PDB, read once (`None` where absent).
static PYTHON: LazyLock<Option<DebugModel>> = LazyLock::new(|| {
    let image = arm64_data(true, "pe/python/python315.dll")?;
    let pdb = arm64_data(false, "python-3.15.2-arm64/python315.pdb")?;
    let model = binbun_debuginfo::info::pdb::read(&pdb, &image).unwrap();
    assert!(model.damage.is_empty(), "{:?}", model.damage);
    Some(model)
});

fn named<'m>(model: &'m DebugModel, name: &str) -> &'m Function {
    model
        .functions
        .values()
        .find(|function| function.name.as_deref() == Some(name))
        .unwrap_or_else(|| panic!("no {name}"))
}

/// `double PyFloat_Unpack8(const char *data, int le)` (section 1, offset
/// 1734096: 0x1801a85d0): its prototype, and its parameters in `x0` and
/// `w1` (`x1`) at the entry. `_safe_PyBytes_Find`'s `self` points to
/// `mmap_object` (96 bytes: `data` at 16, `size` at 24, `trackfd`, a
/// `bool`, at 92).
#[test]
fn arm64_prototypes_registers_and_structs() {
    let Some(model) = PYTHON.as_ref() else { return };
    let unpack = named(model, "PyFloat_Unpack8");
    assert_eq!(unpack.entry, 0x1_801a_85d0);
    assert_eq!(model.display(unpack.returns), "double");
    let parameters: Vec<_> = unpack
        .parameters
        .iter()
        .map(|parameter| {
            (
                parameter.name.as_deref().unwrap(),
                model.display(parameter.ty),
                parameter.place_at(unpack.entry),
            )
        })
        .collect();
    assert_eq!(
        parameters,
        [
            ("data", "char *".to_owned(), Some(&Place::Register("x0"))),
            ("le", "int".to_owned(), Some(&Place::Register("x1"))),
        ]
    );

    let find = named(model, "_safe_PyBytes_Find");
    let this = &find.parameters[1];
    assert_eq!(this.name.as_deref(), Some("self"));
    let &Type::Pointer { target, bytes: 8 } = model.ty(model.resolve(this.ty)) else {
        panic!("{:?}", model.ty(this.ty));
    };
    let Type::Composite(object) = model.ty(model.resolve(target)) else {
        panic!("{:?}", model.ty(target));
    };
    assert_eq!(object.name.as_deref(), Some("mmap_object"));
    assert_eq!(object.size, Some(96));
    let field = |name: &str| {
        let field = object
            .fields
            .iter()
            .find(|field| field.name.as_deref() == Some(name))
            .unwrap();
        (field.offset, model.ty(field.ty).clone())
    };
    assert_eq!(field("data").0, 16);
    assert_eq!(field("size").0, 24);
    assert_eq!(
        field("trackfd"),
        (
            92,
            Type::Base {
                name: "bool".to_owned(),
                bytes: 1,
                encoding: Encoding::Bool
            }
        )
    );
}

/// Stack places against ARM64 frames (the CFA is the entry `sp`):
///
/// - `PyFloat_Unpack8` (packed: `FrameSize` 1, `sub sp, sp, #16`) keeps
///   `x` at `sp` + 0 (`S_DEFRANGE_REGISTER_REL`): CFA − 16.
/// - `_safe_PyBytes_Find` (`.xdata`: `str x19, [sp, #-16]!; stp x29, lr,
///   [sp, #-176]!; mov x29, sp`) spills `self` at `x29` + 16: CFA − 192 +
///   16 = CFA − 176.
/// - `PyLong_AsLong` (`.xdata`: `stp x29, lr, [sp, #-32]!; mov x29, sp`)
///   keeps `overflow` at its frame pointer (`S_FRAMEPROC`'s 1, `sp`) + 16
///   (`S_DEFRANGE_FRAMEPOINTER_REL`): CFA − 16.
#[test]
fn arm64_frame_offsets_are_cfa_relative() {
    let Some(model) = PYTHON.as_ref() else { return };
    let local = |function: &str, name: &str| {
        let function = named(model, function);
        function
            .parameters
            .iter()
            .chain(&function.locals)
            .find(|variable| variable.name.as_deref() == Some(name))
            .unwrap()
            .clone()
    };
    assert_eq!(local("PyFloat_Unpack8", "x").stack_slot(), Some(-16));
    let this = local("_safe_PyBytes_Find", "self");
    let stack: Vec<_> = this
        .location
        .iter()
        .filter_map(|span| match span.place {
            Place::Stack(offset) => Some(offset),
            Place::Register(_) | Place::Relative { .. } | Place::Other => None,
        })
        .collect();
    assert_eq!(stack, [-176]);
    let overflow = local("PyLong_AsLong", "overflow");
    assert!(
        overflow
            .location
            .iter()
            .any(|span| span.place == Place::Stack(-16)),
        "{overflow:?}"
    );
    // No stated stack place is left relative to `sp` or `x29`, but in the
    // funclets of exception handling (`f$filt$0`, `` `f'::`1'::fin$0 ``),
    // where `x29` is their parent's and their own unwind codes set none.
    let relative = model
        .functions
        .values()
        .filter(|function| !function.name.as_deref().unwrap_or_default().contains('$'))
        .flat_map(|function| {
            function
                .parameters
                .iter()
                .chain(&function.locals)
                .flat_map(|variable| &variable.location)
                .filter(|span| {
                    matches!(span.place, Place::Relative { register, .. } if register == "sp" || register == "x29")
                })
                .map(|span| (function.name.clone(), function.entry, span.place.clone()))
        })
        .collect::<Vec<_>>();
    assert_eq!(relative, [], "{relative:x?}");
}

/// ntdll.dll's public PDB (an ARM64X image's, whose code the PDB's OMAP
/// moves): its public symbols name the ARM64 exports' code where the
/// export table has it, its procedures name their code, and its types lay
/// out ARM64's structures (`_PEB`'s
/// `Ldr` at 0x18, a pointer of 8 bytes).
#[test]
fn arm64_ntdll_names_and_types() {
    let (Some(image), Some(pdb)) = (
        arm64_data(false, "ntdll-arm64/ntdll.dll"),
        arm64_data(false, "ntdll-arm64.pdb"),
    ) else {
        return;
    };
    let model = binbun_debuginfo::info::pdb::read(&pdb, &image).unwrap();
    assert!(model.damage.is_empty(), "{:?}", model.damage);
    let file = object::File::parse(&*image).unwrap();
    let base = file.relative_address_base();
    // The exports of code: name and address.
    let exports: Vec<(String, u64)> = file
        .exports()
        .unwrap()
        .filter_map(|export| {
            let export = export.unwrap();
            let (object::NameOrOrdinal::Name(name), object::ExportTarget::Address { address }) =
                (export.name(), export.target())
            else {
                return None;
            };
            Some((String::from_utf8(name.to_vec()).unwrap(), address))
        })
        .collect();
    let close = exports
        .iter()
        .find(|(name, _)| name == "NtClose")
        .unwrap()
        .1;
    assert_eq!(close, base + 0x10f0);
    assert_eq!(
        model.publics.get(&close).map(String::as_str),
        Some("NtClose")
    );
    // The public at each export's address is one of the names exported
    // there (`NtClose` and `ZwClose` share one), as ARM64X images name
    // the native code of functions ARM64EC code calls too (`#islower`):
    // all but 40 of 1937: data exports (no public of code), other aliases
    // (`RtlGuardRestoreContext` is `RtlRestoreContext`) and thunks
    // (`memcpy`).
    let mut names: HashMap<u64, Vec<&str>> = HashMap::new();
    for (name, address) in &exports {
        names.entry(*address).or_default().push(name);
    }
    let unnamed: Vec<_> = names
        .iter()
        .filter(|(address, names)| {
            !model
                .publics
                .get(address)
                .is_some_and(|public| names.contains(&public.trim_start_matches('#')))
        })
        .collect();
    assert!(
        unnamed.len() * 25 < names.len(),
        "{} of {}: {unnamed:x?}",
        unnamed.len(),
        names.len()
    );

    // 880 procedures at 783 addresses (a static helper is stated by each
    // module that has it).
    assert_eq!(model.functions.len(), 783);
    // The C runtime's `xtoa(val, buf, radix, is_neg)`, a leaf (no
    // `.pdata`): section 1 offset 2280544 before the OMAP, RVA 0xe7380
    // after, where `cbz w3, ...` tests `is_neg` past the padding that ends
    // `_ultoa`.
    assert_eq!(named(&model, "xtoa").entry, base + 0xe_7380);

    let (types, ids) = binbun_debuginfo::info::pdb::named(&pdb, &["_PEB"]).unwrap();
    let Type::Composite(peb) = types.ty(types.resolve(ids[0].unwrap())) else {
        panic!("_PEB");
    };
    let ldr = peb
        .fields
        .iter()
        .find(|field| field.name.as_deref() == Some("Ldr"))
        .unwrap();
    assert_eq!(ldr.offset, 0x18);
    assert_eq!(types.size(ldr.ty), Some(8));
}

/// Public symbols of code name their addresses as `llvm-pdbutil dump
/// --publics` states them (`report` at 0001:0848, `_vfprintf_l` at
/// 0001:0032); data publics (`_fltused`, guard data, import slots) name
/// nothing; C++ names stay decorated.
#[test]
fn public_symbols_of_code_name_their_addresses() {
    let model = model();
    let entry = model
        .functions
        .iter()
        .find(|(_, function)| function.name.as_deref() == Some("report"))
        .map(|(&entry, _)| entry)
        .unwrap();
    let at = |name: &str| {
        model
            .publics
            .iter()
            .find(|(_, public)| public.as_str() == name)
            .map(|(&address, _)| address)
    };
    assert_eq!(at("report"), Some(entry));
    assert_eq!(at("_vfprintf_l"), Some(entry - (848 - 32)));
    for data in ["_fltused", "__guard_flags", "__imp_GetCurrentThreadId"] {
        assert_eq!(at(data), None, "{data}");
    }
    assert!(at("?__scrt_initialize_type_info@@YAXXZ").is_some());
}

/// Each function keeps its module: a build without its build
/// information's paths (`/Brepro`) names the module by its object file,
/// the program's own (`msvc.obj`) apart from the C runtime's startup
/// objects.
#[test]
fn functions_keep_their_module() {
    let model = model();
    let unit = |name: &str| {
        let function = model
            .functions
            .values()
            .find(|function| function.name.as_deref() == Some(name))
            .unwrap();
        model.unit(function.unit.unwrap()).unwrap()
    };
    assert!(
        unit("main").name.ends_with(r"\msvc.obj"),
        "{:?}",
        unit("main")
    );
    assert_eq!(unit("five"), unit("main"));
    let startup = unit("__scrt_get_show_window_mode");
    assert_ne!(startup, unit("main"));
    assert!(startup.directory.is_none(), "{startup:?}");
    assert!(
        model
            .functions
            .values()
            .all(|function| function.unit.is_some())
    );
}
