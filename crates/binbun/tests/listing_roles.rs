//! The roles of the checked-in fixtures' tokens: mnemonics by how their
//! instructions transfer control, x86 operands' qualifiers apart from data
//! directives, and which names binbun made.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers fail loudly"
)]

use binbun::Database;
use binbun::analysis::Seeds;
use binbun::listing::{Listing, Options, Role};
use binbun_loader::Image;

fn fixture(name: &str) -> Vec<u8> {
    let path = format!("{}/../../tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

/// Calls `f` with the database and default listing of fixture `name`.
fn with(name: &str, f: impl FnOnce(&Database<'_>, &Listing)) {
    let data = fixture(name);
    let image = Image::parse(&data).unwrap();
    let db = Database::new(&image, Seeds::ALL).unwrap();
    let listing = Listing::build(&db, &Options::default());
    f(&db, &listing);
}

/// The tokens of the content line of the item at `address` (prefix,
/// padding and comments left out): text, role, whether automatic.
fn tokens(db: &Database<'_>, listing: &Listing, address: u64) -> Vec<(String, Role, bool)> {
    let n = listing.line_of(address);
    assert_eq!(listing.line(n).unwrap().address, address, "{address:#x}");
    listing
        .render(db, n)
        .tokens
        .into_iter()
        .filter(|t| {
            !matches!(
                t.role,
                Role::Prefix | Role::Space | Role::CodeXref | Role::DataXref | Role::AutoComment
            )
        })
        .map(|t| (t.text, t.role, t.automatic))
        .collect()
}

/// The first token of the line at `address` (its mnemonic) and its role.
fn mnemonic(db: &Database<'_>, listing: &Listing, address: u64) -> (String, Role) {
    let (text, role, _) = tokens(db, listing, address).swap_remove(0);
    (text, role)
}

fn owned(rows: &[(&str, Role, bool)]) -> Vec<(String, Role, bool)> {
    rows.iter()
        .map(|&(text, role, automatic)| (text.to_owned(), role, automatic))
        .collect()
}

#[test]
fn x86_mnemonics_are_classed_by_how_their_instructions_transfer_control() {
    with("program-x86_64.elf", |db, listing| {
        for (address, text, role) in [
            (0x11D0, "sub", Role::Mnemonic),
            (0x11D6, "js", Role::JumpMnemonic),
            (0x11D8, "call", Role::CallMnemonic),
            (0x11E3, "retn", Role::ReturnMnemonic),
            // The PLT's jump through its slot.
            (0x1050, "jmp", Role::JumpMnemonic),
            // A `nop` inside a function pads to a loop's alignment.
            (0x120D, "nop", Role::PaddingMnemonic),
            (0x10B5, "hlt", Role::Mnemonic),
        ] {
            assert_eq!(
                mnemonic(db, listing, address),
                (text.to_owned(), role),
                "{address:#x}"
            );
        }
        // Padding between functions is `align`, padding's too.
        assert_eq!(
            mnemonic(db, listing, 0x125D),
            ("align ".to_owned(), Role::PaddingMnemonic)
        );
    });
    with("teb-x86_64.exe", |db, listing| {
        // A multi-byte `nop` (`66 0F 1F 44 00 00`).
        assert_eq!(
            mnemonic(db, listing, 0x1_4000_10AA),
            ("nop".to_owned(), Role::PaddingMnemonic)
        );
        // MSVC's `int3`s after a function's `retn`, which no recovered
        // block holds, pad; the one a call falls into is code.
        assert_eq!(
            mnemonic(db, listing, 0x1_4000_17A5),
            ("int 3".to_owned(), Role::PaddingMnemonic)
        );
        assert_eq!(
            mnemonic(db, listing, 0x1_4000_188A),
            ("int 3".to_owned(), Role::Mnemonic)
        );
        // `__fastfail`'s `int 29h` is a trap, not padding.
        assert_eq!(
            mnemonic(db, listing, 0x1_4000_17A2),
            ("int".to_owned(), Role::Mnemonic)
        );
    });
}

#[test]
fn aarch64_mnemonics_are_classed_by_how_their_instructions_transfer_control() {
    with("dozen-aarch64.elf", |db, listing| {
        for (address, text, role) in [
            (0x21_0130, "bl", Role::CallMnemonic),
            (0x21_013C, "b", Role::JumpMnemonic),
            (0x21_0140, "add", Role::Mnemonic),
            (0x21_0144, "ret", Role::ReturnMnemonic),
            (0x21_016C, "cbz", Role::JumpMnemonic),
            (0x21_0178, "b.ne", Role::JumpMnemonic),
        ] {
            assert_eq!(
                mnemonic(db, listing, address),
                (text.to_owned(), role),
                "{address:#x}"
            );
        }
    });
    with("resolve-aarch64.elf", |db, listing| {
        for (address, text, role) in [
            (0x21_03B4, "cbnz", Role::JumpMnemonic),
            (0x21_03D4, "b.hi", Role::JumpMnemonic),
            (0x21_03D8, "nop", Role::PaddingMnemonic),
            (0x21_03EC, "br", Role::JumpMnemonic),
            // The `udf #0` after a call to `exit` pads to the next
            // function.
            (0x21_03CC, "ALIGN ", Role::PaddingMnemonic),
        ] {
            assert_eq!(
                mnemonic(db, listing, address),
                (text.to_owned(), role),
                "{address:#x}"
            );
        }
    });
}

#[test]
fn operand_qualifiers_are_apart_from_data_directives() {
    with("program-x86_64.elf", |db, listing| {
        assert_eq!(
            tokens(db, listing, 0x1050),
            owned(&[
                ("jmp", Role::JumpMnemonic, false),
                ("cs:", Role::OperandKeyword, false),
                ("exit_ptr", Role::DataName, false),
            ])
        );
        assert_eq!(
            tokens(db, listing, 0x11D6),
            owned(&[
                ("js", Role::JumpMnemonic, false),
                ("short ", Role::OperandKeyword, false),
                ("loc_11E4", Role::CodeName, true),
            ])
        );
        assert_eq!(
            tokens(db, listing, 0x120D)[1],
            ("dword ptr ".to_owned(), Role::OperandKeyword, false)
        );
        // The import's slot: a directive, then the operand's `offset`.
        assert_eq!(
            tokens(db, listing, 0x4010),
            owned(&[
                ("exit_ptr", Role::DataName, false),
                ("dq", Role::Keyword, false),
                ("offset ", Role::OperandKeyword, false),
                ("exit", Role::ImportName, false),
            ])
        );
    });
}

#[test]
fn names_binbun_makes_are_automatic_and_symbols_are_not() {
    with("program-x86_64.elf", |db, listing| {
        // A function's symbol, at its header.
        let header = listing.line_of(0x11D0) - 1;
        let proc_line = listing.render(db, header);
        let name = &proc_line.tokens[2];
        assert_eq!((name.text.as_str(), name.automatic), ("checked", false));
        assert_eq!(
            tokens(db, listing, 0x11D8)[1..],
            owned(&[("classify", Role::CodeName, false)])
        );
        // A string's name made from its text.
        assert_eq!(
            tokens(db, listing, 0x11E4)[3..],
            owned(&[("aNegative", Role::DataName, true)])
        );
        // A label's line.
        let label = listing.render(db, listing.line_of(0x11E4) - 1);
        let name = &label.tokens[2];
        assert_eq!((name.text.as_str(), name.automatic), ("loc_11E4", true));
    });
    with("teb-x86_64.exe", |db, listing| {
        // A function no symbol names, called: `sub_`.
        assert_eq!(
            tokens(db, listing, 0x1_4000_1048),
            owned(&[
                ("call", Role::CallMnemonic, false),
                ("sub_140001090", Role::CodeName, true),
            ])
        );
        // A pointer no symbol names: `off_`.
        assert_eq!(
            tokens(db, listing, 0x1_4000_12C5),
            owned(&[
                ("call", Role::CallMnemonic, false),
                ("cs:", Role::OperandKeyword, false),
                ("off_140002158", Role::DataName, true),
            ])
        );
    });
}
