//! A PE file importing Win32 functions (user32.dll's `MessageBoxA` and
//! `CreateWindowExW`, kernel32.dll's `CreateFileW`) decompiles with their
//! prototypes from the Win32 database binbun embeds, with no database
//! directory (`BINBUN_TYPEDB` unset, a home without one).

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers fail loudly"
)]

use std::path::Path;
use std::process::Command;

/// Where the image is loaded, and its sections' addresses.
const IMAGE_BASE: u64 = 0x1_4000_0000;
const TEXT: u32 = 0x1000;
const IDATA: u32 = 0x2000;

/// The imports: library, then its functions.
const IMPORTS: [(&str, &[&str]); 2] = [
    ("KERNEL32.dll", &["CreateFileW"]),
    ("USER32.dll", &["MessageBoxA", "CreateWindowExW"]),
];

/// `.idata`: the import descriptors, each library's lookup and address
/// tables, hint/name entries and names, then a string the code passes
/// (wide, so for both the ANSI and the wide functions); the address
/// table slot of each function by name, and the string's address.
fn idata() -> (Vec<u8>, Vec<(&'static str, u32)>, u32) {
    let descriptors = 20 * (IMPORTS.len() + 1);
    let mut tables = Vec::new();
    let mut strings: Vec<u8> = Vec::new();
    let mut names = Vec::new();
    // Each library's table of 8-byte entries, null-terminated; one copy
    // for the lookup table and one for the address table.
    let table_bytes: usize = IMPORTS
        .iter()
        .map(|(_, functions)| 8 * (functions.len() + 1))
        .sum();
    let strings_at = descriptors + 2 * table_bytes;
    let rva = |offset: usize| IDATA + u32::try_from(offset).unwrap();
    let mut library_names = Vec::new();
    let mut hints = Vec::new();
    for (library, functions) in IMPORTS {
        let mut entries = Vec::new();
        for function in functions {
            entries.push(rva(strings_at + strings.len()));
            strings.extend([0, 0]);
            strings.extend(function.as_bytes());
            strings.push(0);
            if strings.len() % 2 == 1 {
                strings.push(0);
            }
        }
        hints.push(entries);
        library_names.push(rva(strings_at + strings.len()));
        strings.extend(library.as_bytes());
        strings.push(0);
        if strings.len() % 2 == 1 {
            strings.push(0);
        }
    }
    let text = rva(strings_at + strings.len());
    for unit in "binbun".encode_utf16().chain([0]) {
        strings.extend(unit.to_le_bytes());
    }
    let mut out = vec![0; descriptors];
    let mut lookup = descriptors;
    let mut address = descriptors + table_bytes;
    for (index, (_, functions)) in IMPORTS.iter().enumerate() {
        let descriptor = &mut out[20 * index..20 * index + 20];
        descriptor[0..4].copy_from_slice(&rva(lookup).to_le_bytes());
        descriptor[12..16].copy_from_slice(&library_names[index].to_le_bytes());
        descriptor[16..20].copy_from_slice(&rva(address).to_le_bytes());
        for (function, hint) in functions.iter().zip(&hints[index]) {
            names.push((*function, rva(address)));
            tables.push((lookup, *hint));
            tables.push((address, *hint));
            lookup += 8;
            address += 8;
        }
        lookup += 8;
        address += 8;
    }
    out.resize(strings_at, 0);
    for (offset, hint) in tables {
        out[offset..offset + 8].copy_from_slice(&u64::from(hint).to_le_bytes());
    }
    out.extend(strings);
    (out, names, text)
}

/// The entry point's code: `MessageBoxA(NULL, s, s, 0)`,
/// `CreateFileW(s, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL)`,
/// `CreateWindowExW(0, s, s, 0, 0, 0, 0, 0, NULL, NULL, NULL, NULL)`.
fn text(slots: &[(&str, u32)], string: u32) -> Vec<u8> {
    let slot = |name: &str| slots.iter().find(|(n, _)| *n == name).unwrap().1;
    let mut code: Vec<u8> = Vec::new();
    // An instruction `prefix disp32` addressing `target` relative to its
    // end.
    let rip = |code: &mut Vec<u8>, prefix: &[u8], target: u32| {
        code.extend(prefix);
        let end = TEXT + u32::try_from(code.len()).unwrap() + 4;
        code.extend(target.wrapping_sub(end).to_le_bytes());
    };
    // `mov qword [rsp + offset], value`.
    let store = |code: &mut Vec<u8>, offset: u8, value: u32| {
        code.extend([0x48, 0xc7, 0x44, 0x24, offset]);
        code.extend(value.to_le_bytes());
    };
    code.extend([0x48, 0x83, 0xec, 0x68]); // sub rsp, 0x68
    code.extend([0x31, 0xc9]); // xor ecx, ecx
    rip(&mut code, &[0x48, 0x8d, 0x15], string); // lea rdx, [s]
    rip(&mut code, &[0x4c, 0x8d, 0x05], string); // lea r8, [s]
    code.extend([0x45, 0x31, 0xc9]); // xor r9d, r9d
    rip(&mut code, &[0xff, 0x15], slot("MessageBoxA"));
    rip(&mut code, &[0x48, 0x8d, 0x0d], string); // lea rcx, [s]
    code.extend([0xba, 0x00, 0x00, 0x00, 0x80]); // mov edx, GENERIC_READ
    code.extend([0x45, 0x31, 0xc0]); // xor r8d, r8d
    code.extend([0x45, 0x31, 0xc9]); // xor r9d, r9d
    store(&mut code, 0x20, 3); // OPEN_EXISTING
    store(&mut code, 0x28, 0);
    store(&mut code, 0x30, 0);
    rip(&mut code, &[0xff, 0x15], slot("CreateFileW"));
    code.extend([0x31, 0xc9]); // xor ecx, ecx
    rip(&mut code, &[0x48, 0x8d, 0x15], string); // lea rdx, [s]
    rip(&mut code, &[0x4c, 0x8d, 0x05], string); // lea r8, [s]
    code.extend([0x45, 0x31, 0xc9]); // xor r9d, r9d
    for offset in (0x20..=0x58).step_by(8) {
        store(&mut code, offset, 0);
    }
    rip(&mut code, &[0xff, 0x15], slot("CreateWindowExW"));
    code.extend([0x48, 0x83, 0xc4, 0x68]); // add rsp, 0x68
    code.push(0xc3); // ret
    code
}

/// A PE32+ executable of [`text`] and [`idata`].
fn image() -> Vec<u8> {
    let (idata, slots, string) = idata();
    let text = text(&slots, string);
    let put = |file: &mut Vec<u8>, at: usize, bytes: &[u8]| {
        file[at..at + bytes.len()].copy_from_slice(bytes);
    };
    let len = |bytes: &[u8]| u32::try_from(bytes.len()).unwrap();
    let mut file = vec![0; 0x200];
    put(&mut file, 0, b"MZ");
    put(&mut file, 0x3c, &0x40u32.to_le_bytes());
    put(&mut file, 0x40, b"PE\0\0");
    // The COFF header: x86-64, two sections, the optional header's size,
    // an executable image with large addresses.
    put(&mut file, 0x44, &0x8664u16.to_le_bytes());
    put(&mut file, 0x46, &2u16.to_le_bytes());
    put(&mut file, 0x54, &240u16.to_le_bytes());
    put(&mut file, 0x56, &0x22u16.to_le_bytes());
    // The optional header (PE32+).
    let optional = 0x58;
    put(&mut file, optional, &0x20bu16.to_le_bytes());
    put(&mut file, optional + 4, &0x200u32.to_le_bytes());
    put(&mut file, optional + 8, &0x200u32.to_le_bytes());
    put(&mut file, optional + 16, &TEXT.to_le_bytes());
    put(&mut file, optional + 20, &TEXT.to_le_bytes());
    put(&mut file, optional + 24, &IMAGE_BASE.to_le_bytes());
    put(&mut file, optional + 32, &0x1000u32.to_le_bytes());
    put(&mut file, optional + 36, &0x200u32.to_le_bytes());
    put(&mut file, optional + 40, &6u16.to_le_bytes());
    put(&mut file, optional + 48, &6u16.to_le_bytes());
    put(&mut file, optional + 56, &0x3000u32.to_le_bytes());
    put(&mut file, optional + 60, &0x200u32.to_le_bytes());
    put(&mut file, optional + 68, &3u16.to_le_bytes());
    put(&mut file, optional + 72, &0x10_0000u64.to_le_bytes());
    put(&mut file, optional + 80, &0x1000u64.to_le_bytes());
    put(&mut file, optional + 88, &0x10_0000u64.to_le_bytes());
    put(&mut file, optional + 96, &0x1000u64.to_le_bytes());
    put(&mut file, optional + 108, &16u32.to_le_bytes());
    // The import directory: the descriptors at the start of .idata.
    let descriptors = 20 * (u32::try_from(IMPORTS.len()).unwrap() + 1);
    put(&mut file, optional + 112 + 8, &IDATA.to_le_bytes());
    put(&mut file, optional + 112 + 12, &descriptors.to_le_bytes());
    // The section headers; the import tables read-only, as MSVC links
    // them (in .rdata): the slots hold the imports, never rewritten.
    let sections = optional + 240;
    for (index, (name, rva, bytes, characteristics)) in [
        (b".text\0\0\0", TEXT, &text, 0x6000_0020u32),
        (b".idata\0\0", IDATA, &idata, 0x4000_0040),
    ]
    .into_iter()
    .enumerate()
    {
        let header = sections + 40 * index;
        let raw = 0x200 * (u32::try_from(index).unwrap() + 1);
        put(&mut file, header, name);
        put(&mut file, header + 8, &len(bytes).to_le_bytes());
        put(&mut file, header + 12, &rva.to_le_bytes());
        put(&mut file, header + 16, &0x200u32.to_le_bytes());
        put(&mut file, header + 20, &raw.to_le_bytes());
        put(&mut file, header + 36, &characteristics.to_le_bytes());
    }
    for bytes in [&text, &idata] {
        assert!(bytes.len() <= 0x200);
        let at = file.len();
        file.resize(at + 0x200, 0);
        put(&mut file, at, bytes);
    }
    file
}

/// The number of parameters of the declaration of import `name` in `c`.
fn parameters(c: &str, name: &str) -> usize {
    let declaration = c
        .lines()
        .find(|line| {
            line.contains("/* import")
                && line
                    .split(|c: char| !(c.is_alphanumeric() || c == '_'))
                    .any(|word| word == name)
        })
        .unwrap_or_else(|| panic!("no declaration of {name} in\n{c}"));
    let start = declaration.find(&format!("{name}(")).unwrap() + name.len() + 1;
    let end = declaration[start..].find(')').unwrap() + start;
    let list = &declaration[start..end];
    assert!(!list.is_empty() && list != "void", "{declaration}");
    list.split(',').count()
}

#[test]
fn win32_imports_have_the_embedded_prototypes() {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("win32-imports");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let exe = dir.join("imports.exe");
    std::fs::write(&exe, image()).unwrap();
    let home = dir.join("home");
    let output = Command::new(env!("CARGO_BIN_EXE_binbun"))
        .args(["decompile", exe.to_str().unwrap()])
        .env("HOME", &home)
        .env("XDG_CACHE_HOME", home.join("cache"))
        .env_remove("BINBUN_TYPEDB")
        .env_remove("BINBUN_HOME")
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let c = String::from_utf8(output.stdout).unwrap();
    assert_eq!(parameters(&c, "MessageBoxA"), 4, "{c}");
    // Its four are the guess without a prototype; its type is not. Its
    // style is a set of flags, macros in the SDK's headers (`MB_OK`): an
    // integer, no tag.
    assert!(
        c.contains("enum MESSAGEBOX_RESULT MessageBoxA(void *, uint8_t *, uint8_t *, int32_t);"),
        "{c}"
    );
    assert!(c.contains("#ifndef MB_OK\n#define MB_OK 0\n#endif"), "{c}");
    assert_eq!(parameters(&c, "CreateFileW"), 7, "{c}");
    assert_eq!(parameters(&c, "CreateWindowExW"), 12, "{c}");
    // No database directory was made.
    assert!(!home.exists());
}
