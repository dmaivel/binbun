//! Strings among the code are data, not functions: their addresses, which
//! code takes with `lea`, start no function; they are program data
//! (`Program::data`) and string literals (`Database::strings`).
//! `tests/fixtures/textstrings-x86_64.s` (an ELF file: a narrow and a wide
//! string after the code, and a callback reached only by `lea`) and
//! `tests/fixtures/driver-x86_64.sys` (MSVC's WDK build of `driver.c`,
//! whose literals the WDK's `-cbstring` puts at the end of `.text`).

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers fail loudly"
)]

use binbun::Database;
use binbun::analysis::Seeds;
use binbun::strings::Encoding;
use binbun_loader::Image;

fn fixture(name: &str) -> Vec<u8> {
    let path = format!("{}/../../tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

/// The entries of `database`'s functions, sorted.
fn entries(database: &Database<'_>) -> Vec<u64> {
    let mut entries: Vec<u64> = database.functions().map(|(_, f)| f.entry).collect();
    entries.sort_unstable();
    entries
}

/// The strings `database` finds in `range`: address, encoding, text.
fn strings(database: &Database<'_>, range: std::ops::Range<u64>) -> Vec<(u64, Encoding, String)> {
    database
        .strings(4)
        .into_iter()
        .filter(|literal| range.contains(&literal.address))
        .map(|literal| (literal.address, literal.encoding, literal.text))
        .collect()
}

/// The narrow and wide strings after the ELF file's code are data; the
/// callback whose address `lea` takes the same way is still a function.
#[test]
fn strings_after_the_code_are_data_and_a_callback_is_a_function() {
    let data = fixture("textstrings-x86_64.elf");
    let image = Image::parse(&data).unwrap();
    let database = Database::new(&image, Seeds::ALL).unwrap();
    // _start, show, the callback.
    assert_eq!(entries(&database), [0x20_1120, 0x20_113c, 0x20_1140]);
    let data: Vec<(u64, u64)> = database
        .program()
        .data()
        .iter()
        .map(|(&start, &end)| (start, end))
        .collect();
    // "narrow text in .text" and its NUL; u"wide text" and its zero unit.
    assert_eq!(data, [(0x20_114a, 0x20_115f), (0x20_1160, 0x20_1174)]);
    assert_eq!(
        strings(&database, 0x20_1000..0x20_2000),
        [
            (0x20_114a, Encoding::Utf8, "narrow text in .text".to_owned()),
            (0x20_1160, Encoding::Utf16, "wide text".to_owned()),
        ]
    );
}

/// The driver's four literals at the end of `.text` (two device names,
/// two `DbgPrint` formats) are data; its functions are its code's.
#[test]
fn a_driver_s_literals_in_text_are_data() {
    let data = fixture("driver-x86_64.sys");
    let image = Image::parse(&data).unwrap();
    let database = Database::new(&image, Seeds::ALL).unwrap();
    assert_eq!(
        entries(&database),
        [
            0x1_4000_1000, // DriverEntry
            0x1_4000_1120, // DrvCreateClose
            0x1_4000_1160, // DrvThreadTag
            0x1_4000_1190, // DrvUnload
            0x1_4000_11e0, // KeGetCurrentThread
            0x1_4000_11ea, // DbgPrint's import thunk
            0x1_4000_11f0, // _guard_check_icall_nop
            0x1_4000_1210, // jmp rax (control flow guard's dispatch)
            0x1_4000_1230, // an import thunk
            0x1_4000_5000, // GsDriverEntry
            0x1_4000_502c, // __security_init_cookie
        ]
    );
    assert_eq!(
        strings(&database, 0x1_4000_1000..0x1_4000_2000),
        [
            (
                0x1_4000_1240,
                Encoding::Utf16,
                "\\DosDevices\\BinbunDrv".to_owned()
            ),
            (
                0x1_4000_1270,
                Encoding::Utf8,
                "BinbunDrv: unloaded\n".to_owned()
            ),
            (
                0x1_4000_1290,
                Encoding::Utf8,
                "BinbunDrv: thread tag %p\n".to_owned()
            ),
            (
                0x1_4000_12b0,
                Encoding::Utf16,
                "\\Device\\BinbunDrv".to_owned()
            ),
        ]
    );
}
