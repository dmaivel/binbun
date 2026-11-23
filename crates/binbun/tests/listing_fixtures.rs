//! The listing of the checked-in fixtures, line for line where the usual
//! disassembler conventions fix the text, and the invariants of its line
//! space on whole images.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers fail loudly"
)]

use std::collections::BTreeMap;

use binbun::Database;
use binbun::analysis::Seeds;
use binbun::listing::{LineKind, Listing, Numbers, Options, Role};
use binbun::listing::{Span, SpanKind};
use binbun_loader::Image;

fn fixture(name: &str) -> Vec<u8> {
    let path = format!("{}/../../tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

/// Calls `f` with the database and listing (under `options`) of fixture
/// `name`.
fn with(name: &str, options: &Options, f: impl FnOnce(&Database<'_>, &Listing)) {
    let data = fixture(name);
    let image = Image::parse(&data).unwrap();
    let db = Database::new(&image, Seeds::ALL).unwrap();
    let listing = Listing::build(&db, options);
    f(&db, &listing);
}

/// `count` lines from the first line of the item at `address`.
fn lines(db: &Database<'_>, listing: &Listing, address: u64, count: u64) -> Vec<String> {
    let mut n = listing.line_of(address);
    let head = listing.line(n).unwrap().address;
    while n > 0 && listing.line(n - 1).unwrap().address == head {
        n -= 1;
    }
    (n..(n + count).min(listing.len()))
        .map(|n| listing.render(db, n).text())
        .collect()
}

#[test]
fn a_function_header_has_its_banner_attributes_prototype_and_end() {
    with("program-x86_64.elf", &Options::default(), |db, listing| {
        // The PLT stub of the imported `exit`: noreturn, declared.
        assert_eq!(
            lines(db, listing, 0x1050, 11),
            [
                ".plt:1050",
                ".plt:1050 ; =============== S U B R O U T I N E =======================================",
                ".plt:1050",
                ".plt:1050 ; Attributes: noreturn",
                ".plt:1050",
                ".plt:1050 ; void exit(int __status)",
                ".plt:1050 exit            proc near               ; CODE XREF: fail+E↓p",
                ".plt:1050                 jmp     cs:exit_ptr",
                ".plt:1050 exit            endp",
                ".plt:1050",
                ".plt:1050 ; ---------------------------------------------------------------------------",
            ]
        );
    });
}

#[test]
fn a_branch_target_is_a_labelled_line_and_a_string_is_named_at_its_use() {
    with("program-x86_64.elf", &Options::default(), |db, listing| {
        assert_eq!(
            lines(db, listing, 0x11D0, 19),
            [
                ".text:11D0",
                ".text:11D0 ; =============== S U B R O U T I N E =======================================",
                ".text:11D0",
                ".text:11D0 checked         proc near               ; CODE XREF: loop_sum+4C↓p",
                ".text:11D0                 sub     rsp, 8",
                ".text:11D4                 test    edi, edi",
                ".text:11D6                 js      short loc_11E4",
                ".text:11D8                 call    classify",
                ".text:11DD                 add     rsp, 8",
                ".text:11E1                 add     eax, eax",
                ".text:11E3                 retn",
                ".text:11E4 ; ---------------------------------------------------------------------------",
                ".text:11E4",
                ".text:11E4 loc_11E4:                               ; CODE XREF: checked+6↑j",
                ".text:11E4                 lea     rdi, aNegative  ; \"negative\"",
                // `fail` never returns: the function ends at its call.
                ".text:11EB                 call    fail            ; noreturn",
                ".text:11EB checked         endp",
                ".text:11EB",
                ".text:11EB ; ---------------------------------------------------------------------------",
            ]
        );
        // A label's name is found, and its line is the instruction's.
        let target = listing.find("loc_11E4").unwrap();
        assert_eq!(target, 0x11E4);
        let line = listing.line(listing.line_of(target)).unwrap();
        assert_eq!((line.address, line.kind), (0x11E4, LineKind::Instruction));
    });
}

#[test]
fn comment_lines_go_under_their_items_first_content_line_and_go_again() {
    with("program-x86_64.elf", &Options::default(), |db, built| {
        let mut listing = built.clone();
        let text = |listing: &Listing| -> Vec<String> {
            (0..listing.len())
                .map(|n| listing.render(db, n).text())
                .collect()
        };
        let before = text(&listing);
        let label = listing.line_of(0x11E4);
        // Three lines at `test` (two more), two at the labelled `lea`
        // (one more, after its label), one at `retn` (none more), and
        // an address inside an instruction (none: no item starts there).
        let comments = [(0x11D4, 3), (0x11E4, 2), (0x11E3, 1), (0x11D5, 4)].into();
        assert!(listing.set_comments(&comments));
        assert!(!listing.set_comments(&comments));
        assert_eq!(listing.len(), built.len() + 3);
        assert_eq!(
            lines(db, &listing, 0x11D4, 4),
            [
                ".text:11D4                 test    edi, edi",
                ".text:11D4",
                ".text:11D4",
                ".text:11D6                 js      short loc_11E4",
            ]
        );
        let kinds: Vec<(u64, LineKind)> = (listing.line_of(0x11D4)..listing.line_of(0x11D6))
            .map(|n| listing.line(n).unwrap())
            .map(|line| (line.address, line.kind))
            .collect();
        assert_eq!(
            kinds,
            [
                (0x11D4, LineKind::Instruction),
                (0x11D4, LineKind::Comment),
                (0x11D4, LineKind::Comment),
            ]
        );
        // Lines below are numbered anew; addresses find their lines.
        assert_eq!(listing.line_of(0x11E4), label + 2);
        let more = listing.line_of(0x11E4) + 1;
        assert_eq!(
            listing.line(more).map(|l| (l.address, l.kind)),
            Some((0x11E4, LineKind::Comment))
        );
        assert_eq!(
            listing.line(more + 1).map(|l| (l.address, l.kind)),
            Some((0x11EB, LineKind::Instruction))
        );
        // Fewer, then none: the listing as built.
        assert!(listing.set_comments(&[(0x11E4, 2)].into()));
        assert_eq!(listing.len(), built.len() + 1);
        assert!(listing.set_comments(&[].into()));
        assert_eq!(text(&listing), before);
    });
}

#[test]
fn a_jump_table_is_named_after_its_jump_with_offsets_to_its_cases() {
    with("program-x86_64.exe", &Options::default(), |db, listing| {
        assert_eq!(
            lines(db, listing, 0x1_4000_1826, 6),
            [
                ".text:140001826                 cmp     dword ptr [rcx], 6",
                // The guard's branch goes to the default case.
                ".text:140001829                 ja      def_14000183F",
                ".text:14000182F                 mov     eax, [rcx]",
                ".text:140001831                 lea     rdx, jpt_14000183F",
                ".text:140001838                 movsxd  rax, dword ptr [rdx+rax*4]",
                ".text:14000183C                 add     rax, rdx",
            ]
        );
        // Its entries, one a line with its own address; the comment on
        // a line of its own since the entry reaches the comment column.
        assert_eq!(
            lines(db, listing, 0x1_4000_41E4, 4),
            [
                ".rdata:1400041E4 jpt_14000183F   dd offset def_14000183F - 1400041E4h",
                ".rdata:1400041E4                                         ; DATA XREF: _matherr+21↑o",
                ".rdata:1400041E8                 dd offset loc_1400018B0 - 1400041E4h",
                ".rdata:1400041EC                 dd offset loc_140001848 - 1400041E4h",
            ]
        );
    });
}

#[test]
fn data_is_typed_strings_named_from_their_text_and_pointers_written_as_offsets() {
    with("program-x86_64.elf", &Options::default(), |db, listing| {
        assert_eq!(
            lines(db, listing, 0x2000, 8),
            [
                ".rodata:2000 ; ===========================================================================",
                ".rodata:2000",
                ".rodata:2000 ; Segment type: Pure data",
                ".rodata:2000 ; Segment permissions: Read",
                ".rodata:2000",
                // A data symbol of 4 bytes is one value.
                ".rodata:2000 _IO_stdin_used  dd 20001h",
                ".rodata:2004 aNegative       db 'negative',0         ; DATA XREF: checked:loc_11E4↑o",
                ".rodata:200D aD              db '%d',0Ah,0           ; DATA XREF: main+C↑o",
            ]
        );
        assert_eq!(
            lines(db, listing, 0x3DD0, 6)[5],
            ".init_array:3DD0 __frame_dummy_init_array_entry dq offset frame_dummy"
        );
    });
}

#[test]
fn strings_in_text_after_the_code_are_strings_not_code() {
    with(
        "textstrings-x86_64.elf",
        &Options::default(),
        |db, listing| {
            // Named from their text (not `loc_`), as strings, the `nop` the
            // assembler aligned the wide one with a byte between them.
            let text = lines(db, listing, 0x20_114a, 5);
            assert_eq!(
                text,
                [
                    ".text:20114A aNarrowTextInTe db 'narrow text in .text',0",
                    ".text:20114A                                         ; DATA XREF: _start↑o",
                    ".text:20115F                 db  90h",
                    ".text:201160 aWideText       text \"UTF-16LE\", 'wide text',0",
                    ".text:201160                                         ; DATA XREF: _start+7↑o",
                ]
            );
        },
    );
}

#[test]
fn aarch64_names_the_addresses_adrp_pairs_form() {
    with("resolve-aarch64.elf", &Options::default(), |db, listing| {
        let text: Vec<String> = (0..listing.len())
            .map(|n| listing.render(db, n).text())
            .collect();
        let at = text
            .iter()
            .position(|l| l.ends_with("adrp    x16, abort_ptr@PAGE"))
            .unwrap();
        assert!(
            text[at + 1].ends_with("ldr     x16, [x16, #abort_ptr@PAGEOFF]"),
            "{}",
            text[at + 1]
        );
    });
}

#[test]
fn settings_change_numbers_bytes_and_operands() {
    let options = Options {
        opcode_bytes: 8,
        numbers: Numbers::C,
        symbolic: false,
        xrefs: 0,
    };
    with("program-x86_64.elf", &options, |db, listing| {
        let lines = lines(db, listing, 0x11E4, 4);
        assert_eq!(
            lines,
            [
                // The bytes' field pushes every line's text right.
                ".text:11E4                          ; ---------------------------------------------------------------------------",
                ".text:11E4",
                // No cross-references.
                ".text:11E4                          loc_11E4:",
                // Raw operand, the name in a comment.
                ".text:11E4 48 8D 3D 19 0E 00 00                     lea     rdi, [rip+0xe19] ; aNegative",
            ]
        );
    });
    let options = Options {
        numbers: Numbers::C,
        ..Options::default()
    };
    with("program-x86_64.elf", &options, |db, listing| {
        assert_eq!(
            lines(db, listing, 0x11F0, 5)[4],
            ".text:11F0                 sub     rsp, 0x18"
        );
    });
}

/// Whole fixtures: lines are in address order; every instruction's
/// address finds its line; a name plus an offset only ever names a byte
/// of the item the name starts; every arrow joins two instruction lines.
#[test]
fn the_line_space_holds_its_invariants_on_whole_images() {
    for name in [
        "program-x86_64.elf",
        "program-x86_64.exe",
        "exceptions-x86_64.elf",
        "resolve-aarch64.elf",
        "rodata-x86_64.elf",
    ] {
        with(name, &Options::default(), |db, listing| {
            let mut previous = 0;
            for n in 0..listing.len() {
                let line = listing.line(n).unwrap();
                assert!(line.address >= previous, "{name}: line {n} goes back");
                previous = line.address;
                if line.kind == LineKind::Instruction {
                    let found = listing.line(listing.line_of(line.address)).unwrap();
                    assert_eq!(found.address, line.address, "{name}: line {n}");
                }
                for token in listing.render(db, n).tokens {
                    let named = matches!(
                        token.role,
                        Role::CodeName | Role::DataName | Role::ImportName
                    );
                    let Some((base, _)) = token.text.split_once('+').filter(|_| named) else {
                        continue;
                    };
                    let target = token.target.unwrap();
                    let start = listing.find(base.trim_start_matches('#')).unwrap();
                    let holder = listing.line(listing.line_of(target)).unwrap();
                    assert_eq!(
                        holder.address, start,
                        "{name}: {} goes past {base}",
                        token.text
                    );
                }
            }
            for arrow in listing.arrows(0..listing.len()) {
                for end in [arrow.from, arrow.to] {
                    assert_eq!(
                        listing.line(end).unwrap().kind,
                        LineKind::Instruction,
                        "{name}"
                    );
                }
            }
        });
    }
}

/// Whole fixtures: an arrow's lane is the same whatever lines are asked
/// for (the gutter never re-packs while scrolling), and two arrows of one
/// function whose spans overlap never share a lane; arrows of two
/// functions overlap only where one crosses the other function.
#[test]
fn arrow_lanes_are_fixed_per_function_and_overlapping_arrows_differ() {
    for name in [
        "program-x86_64.elf",
        "exceptions-x86_64.elf",
        "resolve-aarch64.elf",
    ] {
        with(name, &Options::default(), |_, listing| {
            let all = listing.arrows(0..listing.len());
            assert!(all.iter().any(|a| a.lane > 0), "{name}: no nesting");
            for start in (0..listing.len()).step_by(7) {
                for arrow in listing.arrows(start..(start + 40).min(listing.len())) {
                    let whole = all
                        .iter()
                        .find(|a| a.from == arrow.from && a.to == arrow.to)
                        .unwrap();
                    assert_eq!(whole.lane, arrow.lane, "{name}: line {start}");
                }
            }
            let function = |line: u64| listing.function_of(listing.line(line).unwrap().address);
            for (i, a) in all.iter().enumerate() {
                for b in &all[i + 1..] {
                    let overlap = a.from.min(a.to) <= b.from.max(b.to)
                        && b.from.min(b.to) <= a.from.max(a.to);
                    if overlap && function(a.from) == function(b.from) {
                        assert_ne!(a.lane, b.lane, "{name}: {a:?} {b:?}");
                    } else if overlap {
                        // Lanes restart per function: overlapping arrows
                        // of two functions are crossing ones (stubs).
                        assert!(a.crosses || b.crosses, "{name}: {a:?} {b:?}");
                    }
                }
            }
        });
    }
}

/// Whole fixtures: a window's arrows are the same whether asked first or
/// after every line's ends were found, and after comment lines number
/// the lines anew.
#[test]
fn a_windows_arrows_are_the_same_asked_first_or_after_the_whole() {
    for name in ["program-x86_64.elf", "resolve-aarch64.elf"] {
        let data = fixture(name);
        let image = Image::parse(&data).unwrap();
        let db = Database::new(&image, Seeds::ALL).unwrap();
        let fresh = Listing::build(&db, &Options::default());
        let warmed = Listing::build(&db, &Options::default());
        // The lines of the ends `warmed` keeps once found are the ones
        // `fresh` finds for each window first.
        let _ = warmed.arrows(0..warmed.len());
        for start in (0..fresh.len()).step_by(11) {
            let window = start..(start + 40).min(fresh.len());
            assert_eq!(
                fresh.arrows(window.clone()),
                warmed.arrows(window),
                "{name}: line {start}"
            );
        }
        // A comment line under every tenth instruction: `warmed`'s known
        // ends move with their lines.
        let comments: BTreeMap<u64, usize> = (0..fresh.len())
            .filter_map(|n| fresh.line(n))
            .filter(|line| line.kind == LineKind::Instruction)
            .step_by(10)
            .map(|line| (line.address, 2))
            .collect();
        let mut warmed = warmed;
        assert!(warmed.set_comments(&comments));
        let mut fresh = Listing::build(&db, &Options::default());
        assert!(fresh.set_comments(&comments));
        for start in (0..fresh.len()).step_by(11) {
            let window = start..(start + 40).min(fresh.len());
            assert_eq!(
                fresh.arrows(window.clone()),
                warmed.arrows(window),
                "{name}, commented: line {start}"
            );
        }
    }
}

/// Whole fixtures: the spans of each mapped range are in order and never
/// overlap; every instruction line starts one; a window's spans are the
/// whole range's that touch it (runs of unexplored bytes aside, which a
/// window cuts).
#[test]
fn spans_partition_the_items_and_a_window_sees_the_same_ones() {
    for name in [
        "program-x86_64.elf",
        "program-x86_64.exe",
        "resolve-aarch64.elf",
        "rodata-x86_64.elf",
    ] {
        let data = fixture(name);
        let image = Image::parse(&data).unwrap();
        let db = Database::new(&image, Seeds::ALL).unwrap();
        let listing = Listing::build(&db, &Options::default());
        for segment in &image.segments {
            let all = listing.spans(segment.start..segment.end());
            for pair in all.windows(2) {
                assert!(pair[0].start < pair[0].end, "{name}: {:?}", pair[0]);
                assert!(pair[0].end <= pair[1].start, "{name}: {pair:?}");
            }
            let starts: Vec<u64> = all.iter().map(|s| s.start).collect();
            for n in 0..listing.len() {
                let line = listing.line(n).unwrap();
                if line.kind == LineKind::Instruction
                    && (segment.start..segment.end()).contains(&line.address)
                {
                    assert!(starts.binary_search(&line.address).is_ok(), "{name}: {n}");
                }
            }
            let typed = |spans: &[Span]| -> Vec<Span> {
                spans
                    .iter()
                    .copied()
                    .filter(|s| s.kind != SpanKind::Unexplored)
                    .collect()
            };
            let mut at = segment.start;
            while at < segment.end() {
                let window = at..(at + 0x130).min(segment.end());
                let expected: Vec<Span> = typed(&all)
                    .into_iter()
                    .filter(|s| s.start < window.end && s.end > window.start)
                    .collect();
                assert_eq!(
                    typed(&listing.spans(window.clone())),
                    expected,
                    "{name}: {window:X?}"
                );
                at += 0x130;
            }
        }
    }
}
