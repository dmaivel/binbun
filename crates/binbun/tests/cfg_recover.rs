//! Control-flow recovery on small hand-assembled x86-64 programs.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers fail loudly"
)]

use binbun::cfg::{
    Block, Callee, Callees, Destination, EdgeKind, Exit, Frame, NoResolver, NothingKnown, Options,
    Program, Resolver, Returns, Seed, SeedKind, Table, recover, recover_function,
};
use binbun_isa::Target;
use binbun_semantics::core::memory::Flat;
use binbun_x86::{Mode, X86};

const BASE: u64 = 0x1000;

/// One import, in the slot at 0x2000, that never returns; and functions at
/// the given addresses known never to return.
struct Known {
    no_return: Vec<u64>,
}

impl Callees for Known {
    fn is_import(&self, slot: u64) -> bool {
        slot == 0x2000
    }

    fn returns(&self, callee: Callee) -> Returns {
        match callee {
            Callee::Import(0x2000) => Returns::No,
            Callee::Address(address) if self.no_return.contains(&address) => Returns::No,
            Callee::Import(_) | Callee::Address(_) => Returns::Unknown,
        }
    }
}

/// Pointer slots holding known code addresses: (slot, address).
struct Slots(Vec<(u64, u64)>);

impl Callees for Slots {
    fn is_import(&self, _: u64) -> bool {
        false
    }

    fn slot(&self, slot: u64, size: u8) -> Option<u64> {
        assert_eq!(size, 8);
        self.0.iter().find(|&&(s, _)| s == slot).map(|&(_, a)| a)
    }

    fn returns(&self, _: Callee) -> Returns {
        Returns::Unknown
    }
}

/// Answers `targets` for the computed jump whose block ends at `end`,
/// nothing for any other, and records each question: the function's entry,
/// the jump block's start, and the starts of the blocks it was given.
struct Answers {
    end: u64,
    targets: Vec<u64>,
    asked: Vec<(u64, u64, Vec<u64>)>,
}

impl Answers {
    fn new(end: u64, targets: &[u64]) -> Self {
        Self {
            end,
            targets: targets.to_vec(),
            asked: Vec::new(),
        }
    }
}

impl Resolver for Answers {
    fn table(&mut self, entry: u64, blocks: &[Block], jump: Block) -> Option<Table> {
        let starts = blocks.iter().map(|b| b.start).collect();
        self.asked.push((entry, jump.start, starts));
        (jump.end == self.end).then(|| Table {
            targets: self.targets.clone(),
            inferred: false,
        })
    }
}

/// Recovers `code` at `BASE` from the given function entries.
fn run(code: &[u8], entries: &[u64], callees: &impl Callees) -> Program {
    resolved(code, entries, callees, &mut NoResolver)
}

/// Recovers `code` at `BASE` from the given function entries, asking
/// `resolver` about computed jumps.
fn resolved(
    code: &[u8],
    entries: &[u64],
    callees: &impl Callees,
    resolver: &mut dyn Resolver,
) -> Program {
    let seeds: Vec<Seed> = entries
        .iter()
        .map(|&e| Seed::Function(e, SeedKind::Symbol))
        .collect();
    recover(
        &X86,
        Mode::Bits64,
        &Flat::new(BASE, code),
        &seeds,
        callees,
        resolver,
        &Options::default(),
    )
}

/// `code` padded with `int3` to `size` bytes, then `tail` (for placing
/// functions at fixed offsets).
fn at(mut code: Vec<u8>, offset: usize, tail: &[u8]) -> Vec<u8> {
    code.resize(offset, 0xcc);
    code.extend_from_slice(tail);
    code
}

fn block(program: &Program, start: u64) -> Block {
    program.blocks[program
        .block_at(start)
        .unwrap_or_else(|| panic!("no block at {start:#x}"))]
}

fn returns(program: &Program, entry: u64) -> bool {
    program.functions[program.function_at(entry).unwrap()].returns
}

fn body(program: &Program, entry: u64) -> Vec<u64> {
    let function = &program.functions[program.function_at(entry).unwrap()];
    function
        .blocks
        .iter()
        .map(|&id| program.blocks[id].start)
        .collect()
}

#[test]
fn splits_blocks_at_jump_targets() {
    let code = [
        0x85, 0xff, // 1000 test edi, edi
        0x74, 0x03, // 1002 jz 1007
        0x31, 0xc0, // 1004 xor eax, eax
        0xc3, //       1006 ret
        0xb8, 1, 0, 0, 0, // 1007 mov eax, 1
        0xeb, 0xf8, // 100c jmp 1006 (inside the block 1004..1007)
    ];
    let program = run(&code, &[BASE], &NothingKnown);
    assert_eq!(
        block(&program, 0x1000).exit,
        Exit::Branch(Destination::Address(0x1007))
    );
    assert_eq!(
        (block(&program, 0x1004).end, block(&program, 0x1004).exit),
        (0x1006, Exit::Next)
    );
    assert_eq!(block(&program, 0x1006).exit, Exit::Return);
    assert_eq!(block(&program, 0x1006).instructions, 1);
    assert_eq!(
        block(&program, 0x1007).exit,
        Exit::Jump(Destination::Address(0x1006))
    );
    assert_eq!(body(&program, BASE), [0x1000, 0x1004, 0x1006, 0x1007]);
    assert!(returns(&program, BASE));
    assert_eq!(program.conflicts, []);
}

#[test]
fn calls_to_functions_that_never_return_have_no_fallthrough() {
    // f: call g; then bytes that are no code. g: call [rip -> exit's slot].
    let f = vec![0xe8, 0x0b, 0, 0, 0, 0x06, 0x06]; // call 1010; (push es)x2
    let g = [0xff, 0x15, 0xea, 0x0f, 0, 0]; // 1010: call [rip+0xfea] = [2000]
    let program = run(&at(f, 0x10, &g), &[BASE], &Known { no_return: vec![] });
    assert_eq!(
        block(&program, 0x1010).exit,
        Exit::Call {
            callee: Destination::Import(0x2000),
            returns: Returns::No
        }
    );
    assert!(!returns(&program, 0x1010), "g ends in exit");
    assert!(!returns(&program, BASE), "f only calls g");
    assert_eq!(
        block(&program, BASE).exit,
        Exit::Call {
            callee: Destination::Address(0x1010),
            returns: Returns::No
        }
    );
    assert!(
        program.block_at(0x1005).is_none(),
        "the bytes after the call were decoded"
    );
    assert!(
        program.function_at(0x1010).is_some(),
        "the call target is a function"
    );
}

#[test]
fn tail_calls_end_the_function_and_pass_on_returning() {
    // f: jmp g (another function); g: ret.
    let code = at(vec![0xeb, 0x0e], 0x10, &[0xc3]);
    let program = run(&code, &[BASE, 0x1010], &NothingKnown);
    assert_eq!(body(&program, BASE), [BASE]);
    assert_eq!(body(&program, 0x1010), [0x1010]);
    assert!(returns(&program, BASE), "f returns through g");
}

#[test]
fn mutually_recursive_functions_are_released_as_returning() {
    // f: call g; ret.   g: test edi, edi; jz done; call f; done: ret.
    let f = vec![0xe8, 0x0b, 0, 0, 0, 0xc3]; // call 1010; ret
    let g = [
        0x85, 0xff, // 1010 test edi, edi
        0x74, 0x05, // 1012 jz 1019
        0xe8, 0xe7, 0xef, 0xff, 0xff, // 1014 call 1000
        0xc3, // 1019 ret
    ];
    let program = run(&at(f, 0x10, &g), &[BASE], &NothingKnown);
    assert!(returns(&program, BASE));
    assert!(returns(&program, 0x1010));
    assert!(
        program.block_at(0x1005).is_some(),
        "f's code after the call"
    );
    assert!(
        program.block_at(0x1019).is_some(),
        "g's code after the call"
    );
}

#[test]
fn functions_that_only_call_each_other_never_return() {
    // f: call g; ret.   g: call h; ret.   h: call g; ret. g and h only
    // return if the other does: neither does, so no `ret` after their calls
    // is code, and f does not return either.
    let f = vec![0xe8, 0x0b, 0, 0, 0, 0xc3]; // 1000 call 1010; ret
    let g = at(f, 0x10, &[0xe8, 0x0b, 0, 0, 0, 0xc3]); // 1010 call 1020; ret
    let h = [0xe8, 0xeb, 0xff, 0xff, 0xff, 0xc3]; // 1020 call 1010; ret
    let program = run(&at(g, 0x20, &h), &[BASE], &NothingKnown);
    for entry in [BASE, 0x1010, 0x1020] {
        assert!(!returns(&program, entry), "{entry:#x}");
    }
    for after in [0x1005, 0x1015, 0x1025] {
        assert!(program.block_at(after).is_none(), "{after:#x} was decoded");
    }
}

#[test]
fn falling_into_another_function_is_like_a_tail_call() {
    // f: nop; then g's entry. g: call exit's import. f does not return, and
    // its blocks stop at g.
    let code = [
        0x90, // 1000 nop
        0xff, 0x15, 0xf9, 0x0f, 0, 0, // 1001 call [rip+0xff9] = [2000]
    ];
    let program = run(&code, &[BASE, 0x1001], &Known { no_return: vec![] });
    assert_eq!(block(&program, BASE).exit, Exit::Next);
    assert_eq!(body(&program, BASE), [BASE]);
    assert!(!returns(&program, 0x1001));
    assert!(
        !returns(&program, BASE),
        "f falls into g, which never returns"
    );
    // The same with a returning g.
    let code = [0x90, 0xc3];
    let program = run(&code, &[BASE, 0x1001], &NothingKnown);
    assert!(returns(&program, BASE));
}

#[test]
fn overlapping_instructions_are_conflicts() {
    // jz into the middle of the following mov, whose immediate's first
    // byte is a ret.
    let code = [
        0x74, 0x01, // 1000 jz 1003
        0xb8, 0xc3, 0x90, 0x90, 0x90, // 1002 mov eax, 0x909090c3 (1003: ret)
        0xc3, // 1007 ret
    ];
    let program = run(&code, &[BASE], &NothingKnown);
    assert_eq!(block(&program, 0x1003).exit, Exit::Return);
    assert_eq!(block(&program, 0x1002).end, 0x1008);
    assert!(
        !program.conflicts.is_empty(),
        "the mov at 1002 and the ret at 1003 share a byte"
    );
}

#[test]
fn jumps_out_of_code_and_unresolved_jumps_are_recorded() {
    // je 0x9000 (unmapped); jmp rax.
    let code = [0x0f, 0x84, 0xfa, 0x7f, 0, 0, 0xff, 0xe0];
    let program = run(&code, &[BASE], &NothingKnown);
    assert_eq!(block(&program, 0x9000).exit, Exit::Invalid);
    assert_eq!(block(&program, 0x9000).instructions, 0);
    assert_eq!(
        block(&program, 0x1006).exit,
        Exit::Jump(Destination::Indirect)
    );
    let unresolved: Vec<_> = program.unresolved().map(|(_, d)| d).collect();
    assert_eq!(unresolved, [Destination::Indirect]);
    assert!(returns(&program, BASE), "an unresolved jump may return");
}

#[test]
fn calls_to_no_code_make_no_function() {
    // call 0 (a weak symbol left undefined); ret.
    let code = [0xe8, 0xfb, 0xef, 0xff, 0xff, 0xc3];
    let program = run(&code, &[BASE], &NothingKnown);
    assert_eq!(program.functions.len(), 1);
    assert!(program.function_at(0).is_none());
    assert_eq!(body(&program, BASE), [BASE, 0x1005]);
    assert!(returns(&program, BASE));
}

#[test]
fn one_function_alone_assumes_its_calls_return() {
    // f: call g; ret.  g: (never decoded) hlt.
    let code = at(vec![0xe8, 0x0b, 0, 0, 0, 0xc3], 0x10, &[0xf4]);
    let program = recover_function(
        &X86,
        Mode::Bits64,
        &Flat::new(BASE, &code),
        BASE,
        &NothingKnown,
        &mut NoResolver,
    );
    assert_eq!(program.functions.len(), 1);
    assert!(
        program.block_at(0x1010).is_none(),
        "the callee was recovered"
    );
    assert_eq!(
        block(&program, BASE).exit,
        Exit::Call {
            callee: Destination::Address(0x1010),
            returns: Returns::Unknown
        }
    );
    assert_eq!(body(&program, BASE), [BASE, 0x1005]);
}

#[test]
fn pointer_seeds_become_functions_only_outside_known_code() {
    // f: xor eax, eax; ret (1000-1003). Pointers to 1002 (inside f: a
    // jump-table-like target) and to g at 1010.
    let code = at(vec![0x31, 0xc0, 0x90, 0xc3], 0x10, &[0xc3]);
    let seeds = [
        Seed::Function(BASE, SeedKind::Symbol),
        Seed::Function(0x1002, SeedKind::Pointer),
        Seed::Function(0x1010, SeedKind::Pointer),
    ];
    let memory = Flat::new(BASE, &code);
    let program = recover(
        &X86,
        Mode::Bits64,
        &memory,
        &seeds,
        &NothingKnown,
        &mut NoResolver,
        &Options::default(),
    );
    assert!(
        program.function_at(0x1002).is_none(),
        "a pointer into f became a function"
    );
    let g = &program.functions[program.function_at(0x1010).unwrap()];
    assert!(g.seeds.contains(SeedKind::Pointer));
    assert_eq!(body(&program, BASE), [BASE]);
}

#[test]
fn addresses_code_computes_become_functions_only_outside_known_code() {
    // 1000: lea rdi, [rip+0xa]  (0x1011: code nothing else reaches)
    // 1007: lea rsi, [rip+0]    (0x100e: inside this function)
    // 100e: ret
    // 1011: ret
    let code = at(
        vec![
            0x48, 0x8d, 0x3d, 0x0a, 0, 0, 0, 0x48, 0x8d, 0x35, 0, 0, 0, 0, 0xc3,
        ],
        0x11,
        &[0xc3],
    );
    let p = run(&code, &[BASE], &NothingKnown);
    let mut entries: Vec<u64> = p.functions.values().map(|f| f.entry).collect();
    entries.sort_unstable();
    assert_eq!(entries, [BASE, 0x1011]);
    let referenced = &p.functions[p.function_at(0x1011).unwrap()];
    assert!(referenced.seeds.contains(SeedKind::Reference));
}

/// Says strings are at 0x1010..0x1015, 0x1016..0x101b and 0x1020..0x1021.
struct Strings;

impl Resolver for Strings {
    fn table(&mut self, _: u64, _: &[Block], _: Block) -> Option<Table> {
        None
    }

    fn data(&mut self, address: u64) -> Option<u64> {
        match address {
            0x1010 => Some(0x1015),
            0x1016 => Some(0x101b),
            0x1020 => Some(0x1021),
            _ => None,
        }
    }
}

#[test]
fn computed_addresses_and_pointers_to_data_make_no_function() {
    // 1000: lea rdx, [rip+0x9]  (0x1010: "ABCD\0", which decodes as
    //       `rex.B push r12; rex.B push r12` and more)
    // 1007: lea rcx, [rip+0x8]  (0x1016: "EFGH\0")
    // 100e: ret
    // A pointer in data to 0x1016 too, and a call target at 0x1020 that
    // the resolver would call data: a call is code's evidence.
    let code = at(
        at(
            vec![
                0x48, 0x8d, 0x15, 0x09, 0, 0, 0, 0x48, 0x8d, 0x0d, 0x08, 0, 0, 0, 0xc3,
            ],
            0x10,
            b"ABCD\0\0EFGH\0",
        ),
        0x20,
        &[0xc3],
    );
    let memory = Flat::new(BASE, &code);
    let seeds = [
        Seed::Function(BASE, SeedKind::Symbol),
        Seed::Function(0x1016, SeedKind::Pointer),
        Seed::Function(0x1020, SeedKind::Call),
    ];
    let program = recover(
        &X86,
        Mode::Bits64,
        &memory,
        &seeds,
        &NothingKnown,
        &mut Strings,
        &Options::default(),
    );
    let mut entries: Vec<u64> = program.functions.values().map(|f| f.entry).collect();
    entries.sort_unstable();
    assert_eq!(
        entries,
        [BASE, 0x1020],
        "only code's evidence makes functions"
    );
    assert!(program.block_containing(0x1010).is_none());
    assert_eq!(
        program
            .data()
            .iter()
            .map(|(&s, &e)| (s, e))
            .collect::<Vec<_>>(),
        [(0x1010, 0x1015), (0x1016, 0x101b)]
    );
    // Without the resolver's word, both are functions.
    let p = recover(
        &X86,
        Mode::Bits64,
        &memory,
        &seeds,
        &NothingKnown,
        &mut NoResolver,
        &Options::default(),
    );
    assert!(p.function_at(0x1010).is_some() && p.function_at(0x1016).is_some());
    assert!(p.data().is_empty());
}

#[test]
fn jumps_out_of_a_known_extent_are_tail_calls() {
    // f (1000-1002, extent known): jmp 1010. At 1010, code no seed names:
    // ret. h (1020-1030, extent known): ret; its cold part c (1040,
    // extent known) jumps back into h at 1021.
    let f = vec![0xeb, 0x0e]; // 1000 jmp 1010
    let code = at(
        at(at(f, 0x10, &[0xc3]), 0x20, &[0xc3, 0xc3]),
        0x40,
        &[0xeb, 0xdf],
    ); // 1040 jmp 1021
    let seeds = [
        Seed::Function(BASE, SeedKind::Unwind),
        Seed::Extent {
            function: BASE,
            end: 0x1002,
            frame: Frame::Call,
        },
        Seed::Function(0x1020, SeedKind::Unwind),
        Seed::Extent {
            function: 0x1020,
            end: 0x1030,
            frame: Frame::Call,
        },
        Seed::Function(0x1040, SeedKind::Unwind),
        Seed::Extent {
            function: 0x1040,
            end: 0x1042,
            frame: Frame::Call,
        },
    ];
    let memory = Flat::new(BASE, &code);
    let program = recover(
        &X86,
        Mode::Bits64,
        &memory,
        &seeds,
        &NothingKnown,
        &mut NoResolver,
        &Options::default(),
    );
    // The target outside f's extent is a new function, f's tail call.
    let g = &program.functions[program.function_at(0x1010).unwrap()];
    assert!(g.seeds.contains(SeedKind::Call));
    assert_eq!(body(&program, BASE), [BASE]);
    assert!(returns(&program, BASE));
    // Into h's extent: h's code, not a new function.
    assert!(program.function_at(0x1021).is_none());
    assert_eq!(body(&program, 0x1040), [0x1040]);
}

#[test]
fn code_seeds_join_their_function() {
    // f: ret. A landing pad of f at 1008: mov eax, 1; ret.
    let code = at(vec![0xc3], 8, &[0xb8, 1, 0, 0, 0, 0xc3]);
    let seeds = [
        Seed::Function(BASE, SeedKind::Unwind),
        Seed::Code {
            function: BASE,
            address: 0x1008,
        },
    ];
    let memory = Flat::new(BASE, &code);
    let program = recover(
        &X86,
        Mode::Bits64,
        &memory,
        &seeds,
        &NothingKnown,
        &mut NoResolver,
        &Options::default(),
    );
    assert_eq!(body(&program, BASE), [BASE, 0x1008]);
    assert!(program.function_at(0x1008).is_none());
}

/// Recovers `code` at `BASE` from functions with unwind table entries:
/// (start, end, how entered); and landing pads: (function, address).
fn unwound(code: &[u8], extents: &[(u64, u64, Frame)], pads: &[(u64, u64)]) -> Program {
    let mut seeds = Vec::new();
    for &(function, end, frame) in extents {
        seeds.push(Seed::Function(function, SeedKind::Unwind));
        seeds.push(Seed::Extent {
            function,
            end,
            frame,
        });
    }
    for &(function, address) in pads {
        seeds.push(Seed::Code { function, address });
    }
    recover(
        &X86,
        Mode::Bits64,
        &Flat::new(BASE, code),
        &seeds,
        &NothingKnown,
        &mut NoResolver,
        &Options::default(),
    )
}

fn parts(program: &Program, entry: u64) -> Vec<u64> {
    program.functions[program.function_at(entry).unwrap()]
        .parts
        .clone()
}

#[test]
fn parts_join_the_function_they_are_split_from() {
    // f1: jg c1; ret. c1: ud2 (entered by a conditional branch).
    // f2: jmp c2. c2: ret (its unwind entry starts inside a frame).
    // f3: jmp c3; ret. c3: jmp 1032 (back into f3).
    let code = at(vec![0x7f, 0x1e, 0xc3], 0x10, &[0xeb, 0x3e]);
    let code = at(at(code, 0x20, &[0x0f, 0x0b]), 0x30, &[0xeb, 0x2e, 0xc3]);
    let code = at(at(code, 0x50, &[0xc3]), 0x60, &[0xeb, 0xd0]);
    let program = unwound(
        &code,
        &[
            (BASE, 0x1003, Frame::Call),
            (0x1010, 0x1012, Frame::Call),
            (0x1020, 0x1022, Frame::Call),
            (0x1030, 0x1033, Frame::Call),
            (0x1050, 0x1051, Frame::Inside),
            (0x1060, 0x1062, Frame::Call),
        ],
        &[],
    );
    for (owner, part) in [(BASE, 0x1020), (0x1010, 0x1050), (0x1030, 0x1060)] {
        assert!(program.function_at(part).is_none(), "{part:#x} stayed");
        assert_eq!(parts(&program, owner), [part]);
    }
    assert_eq!(body(&program, BASE), [BASE, 0x1002, 0x1020]);
    assert_eq!(body(&program, 0x1030), [0x1030, 0x1032, 0x1060]);
    assert!(returns(&program, 0x1010));
    assert_eq!(program.functions.len(), 3);
}

/// MSVC's split-off code (profile-guided hot and cold splitting) is one
/// `.pdata` entry chained to its function's, which the function may jump
/// into at several places, not only its start. A place inside it entered
/// by an unconditional jump, that never jumps back, is a part all the same.
#[test]
fn a_jump_into_the_middle_of_split_off_code_is_into_a_part() {
    // f: jg 1050; jmp 1054. The split-off code 1050..1055 (never seeded
    // as a function): ret; ud2; nop; ret at 1054.
    let code = at(
        vec![0x7f, 0x4e, 0xeb, 0x50],
        0x50,
        &[0xc3, 0x0f, 0x0b, 0x90, 0xc3],
    );
    let seeds = [
        Seed::Function(BASE, SeedKind::Unwind),
        Seed::Extent {
            function: BASE,
            end: 0x1004,
            frame: Frame::Call,
        },
        Seed::Split {
            start: 0x1050,
            end: 0x1055,
            owner: None,
        },
    ];
    let program = recover(
        &X86,
        Mode::Bits64,
        &Flat::new(BASE, &code),
        &seeds,
        &NothingKnown,
        &mut NoResolver,
        &Options::default(),
    );
    assert!(
        program.function_at(0x1054).is_none(),
        "1054 stayed a function"
    );
    assert_eq!(parts(&program, BASE), [0x1050, 0x1054]);
    assert_eq!(program.functions.len(), 1);
}

/// Split-off code jumps back into its function. Its range is the piece's
/// extent: the jump back is the function's code, not the piece's, so the
/// piece does not take in the block that enters it (which would hide that
/// entry, and the piece would stay a function holding its owner's code).
#[test]
fn split_off_code_jumping_back_leaves_its_owners_code_alone() {
    // f: nop; jg 1050; ret. Split-off 1050..1052: jmp 1001 (back to the
    // branch that enters it, inside f).
    let code = at(vec![0x90, 0x7f, 0x4d, 0xc3], 0x50, &[0xeb, 0xaf]);
    let seeds = [
        Seed::Function(BASE, SeedKind::Unwind),
        Seed::Extent {
            function: BASE,
            end: 0x1004,
            frame: Frame::Call,
        },
        Seed::Split {
            start: 0x1050,
            end: 0x1052,
            owner: None,
        },
    ];
    let program = recover(
        &X86,
        Mode::Bits64,
        &Flat::new(BASE, &code),
        &seeds,
        &NothingKnown,
        &mut NoResolver,
        &Options::default(),
    );
    assert_eq!(parts(&program, BASE), [0x1050]);
    assert_eq!(program.functions.len(), 1);
    assert_eq!(body(&program, BASE), [BASE, 0x1001, 0x1003, 0x1050]);
}

/// Pieces of split-off code may enter each other, so neither is entered
/// from one function alone until the other is joined. Where its unwind
/// information names the function it was split off, each is a part of
/// that function all the same.
#[test]
fn split_off_code_joins_the_function_its_unwind_information_names() {
    // f: jg b; jmp a. Split-off 1050..1056 of f: a: jmp b; b: jmp a.
    let code = at(
        vec![0x7f, 0x52, 0xeb, 0x4c],
        0x50,
        &[0xeb, 0x02, 0x90, 0x90, 0xeb, 0xfa],
    );
    let program = |owner| {
        recover(
            &X86,
            Mode::Bits64,
            &Flat::new(BASE, &code),
            &[
                Seed::Function(BASE, SeedKind::Unwind),
                Seed::Extent {
                    function: BASE,
                    end: 0x1004,
                    frame: Frame::Call,
                },
                Seed::Split {
                    start: 0x1050,
                    end: 0x1056,
                    owner,
                },
            ],
            &NothingKnown,
            &mut NoResolver,
            &Options::default(),
        )
    };
    let named = program(Some(BASE));
    assert_eq!(parts(&named, BASE), [0x1050, 0x1054]);
    assert_eq!(named.functions.len(), 1);
    // Unnamed, each is entered from two functions: they stay functions.
    assert_eq!(program(None).functions.len(), 3);
}

#[test]
fn functions_entered_otherwise_stay_functions() {
    // g1: jg s; ret. g2: jg s; ret. s: ud2 (entered from two functions).
    // g3: call t; jg t; ret. t: ret (called). g4: jmp u. u: ret (a tail
    // call, nothing saying otherwise). g5: jg v; ret. v: ret (an outermost
    // frame: a thread's start).
    let code = at(vec![0x7f, 0x1e, 0xc3], 0x10, &[0x7f, 0x0e, 0xc3]);
    let code = at(code, 0x20, &[0x0f, 0x0b]);
    let code = at(code, 0x30, &[0xe8, 0x1b, 0, 0, 0, 0x7f, 0x19, 0xc3]);
    let code = at(at(code, 0x40, &[0xeb, 0x1e]), 0x50, &[0xc3]);
    let code = at(code, 0x60, &[0xc3]);
    let code = at(at(code, 0x70, &[0x7f, 0x0e, 0xc3]), 0x80, &[0xc3]);
    let program = unwound(
        &code,
        &[
            (BASE, 0x1003, Frame::Call),
            (0x1010, 0x1013, Frame::Call),
            (0x1020, 0x1022, Frame::Call),
            (0x1030, 0x1038, Frame::Call),
            (0x1040, 0x1042, Frame::Call),
            (0x1050, 0x1051, Frame::Call),
            (0x1060, 0x1061, Frame::Call),
            (0x1070, 0x1073, Frame::Call),
            (0x1080, 0x1081, Frame::Outermost),
        ],
        &[],
    );
    assert_eq!(program.functions.len(), 9);
    assert!(program.functions.values().all(|f| f.parts.is_empty()));
}

#[test]
fn parts_only_landing_pads_reach_stay_functions() {
    // f: nop; ret; a landing pad at 1002: jmp p. p (inside a frame): jmp
    // 1001, back into f.
    let code = at(vec![0x90, 0xc3, 0xeb, 0x1c], 0x20, &[0xeb, 0xdf]);
    let program = unwound(
        &code,
        &[(BASE, 0x1010, Frame::Call), (0x1020, 0x1022, Frame::Inside)],
        &[(BASE, 0x1002)],
    );
    let f = &program.functions[program.function_at(BASE).unwrap()];
    assert_eq!(f.parts, [0u64; 0]);
    assert_eq!(f.landing_pads, [0x1002]);
    let p = &program.functions[program.function_at(0x1020).unwrap()];
    assert_eq!(p.part_of, Some(BASE));
}

#[test]
fn what_the_caller_knows_about_a_function_wins_over_its_code() {
    // f: call g; ret.  g: ret, but known (say, by a signature) not to
    // return.
    let code = at(vec![0xe8, 0x0b, 0, 0, 0, 0xc3], 0x10, &[0xc3]);
    let program = run(
        &code,
        &[BASE],
        &Known {
            no_return: vec![0x1010],
        },
    );
    assert!(!returns(&program, 0x1010));
    assert!(!returns(&program, BASE));
    assert!(program.block_at(0x1005).is_none());
}

#[test]
fn resolved_computed_jumps_become_tables_of_their_function() {
    // 1000 cmp edi, 2; ja 1010; 1005 jmp rax (cases at 1008 and 100c).
    // 1008 xor eax, eax; ret.  100c ret.  1010 ret (the default).
    let switch = vec![0x83, 0xff, 0x02, 0x77, 0x0b, 0xff, 0xe0];
    let code = at(
        at(at(switch, 8, &[0x31, 0xc0, 0xc3]), 0xc, &[0xc3]),
        0x10,
        &[0xc3],
    );

    let mut table = Answers::new(0x1007, &[0x100c, 0x1008]);
    let program = resolved(&code, &[BASE], &NothingKnown, &mut table);
    assert_eq!(
        table.asked,
        [(BASE, 0x1005, vec![BASE, 0x1005, 0x1010])],
        "asked once, with the blocks found before"
    );
    let jump = program.block_at(0x1005).unwrap();
    assert_eq!(
        program.table(jump),
        Some(&Table {
            targets: vec![0x1008, 0x100c],
            inferred: false
        })
    );
    let successors: Vec<_> = program.successors(jump).collect();
    assert_eq!(
        successors,
        [(EdgeKind::Table, 0x1008), (EdgeKind::Table, 0x100c)]
    );
    assert_eq!(body(&program, BASE), [BASE, 0x1005, 0x1008, 0x100c, 0x1010]);
    assert!(program.function_at(0x1008).is_none());
    assert_eq!(program.unresolved().count(), 0);
    assert!(returns(&program, BASE));

    // Knowing nothing: as before, the jump is unresolved and may return.
    let program = run(&code, &[BASE], &NothingKnown);
    let jump = program.block_at(0x1005).unwrap();
    assert_eq!(program.table(jump), None);
    assert_eq!(program.successors(jump).count(), 0);
    assert_eq!(body(&program, BASE), [BASE, 0x1005, 0x1010]);
    assert!(program.block_at(0x1008).is_none());
    let unresolved: Vec<_> = program.unresolved().collect();
    assert_eq!(unresolved, [(jump, Destination::Indirect)]);
    assert!(returns(&program, BASE));
}

/// A call or jump through a slot the caller knows the content of goes to
/// that address, like a direct one; through any other slot it stays
/// unresolved.
#[test]
fn calls_and_jumps_through_known_slots_go_where_the_slot_points() {
    let f = vec![
        0xff, 0x15, 0xfa, 0x1f, 0, 0, // 1000 call [rip+0x1ffa] (slot 3000: g)
        0xff, 0x25, 0xfc, 0x1f, 0, 0, // 1006 jmp [rip+0x1ffc] (slot 3008: h)
    ];
    let k = [0xff, 0x25, 0xca, 0x1f, 0, 0]; // 1040 jmp [rip+0x1fca] (slot 3010)
    let code = at(at(at(f, 0x20, &[0xc3]), 0x30, &[0xc3]), 0x40, &k);
    let program = run(
        &code,
        &[BASE, 0x1040],
        &Slots(vec![(0x3000, 0x1020), (0x3008, 0x1030)]),
    );
    assert_eq!(
        block(&program, BASE).exit,
        Exit::Call {
            callee: Destination::Address(0x1020),
            returns: Returns::Yes
        }
    );
    assert!(program.function_at(0x1020).is_some(), "g is a function");
    assert_eq!(
        block(&program, 0x1006).exit,
        Exit::Jump(Destination::Address(0x1030))
    );
    assert_eq!(
        block(&program, 0x1040).exit,
        Exit::Jump(Destination::Pointer(0x3010))
    );
}

#[test]
fn whether_a_switch_returns_waits_for_the_resolver() {
    // f: 1000 jmp rax, its only way out; 1008 ud2; 1010 ret.
    // g: 1020 call f; 1025 ret.
    let code = at(
        at(at(vec![0xff, 0xe0], 8, &[0x0f, 0x0b]), 0x10, &[0xc3]),
        0x20,
        &[0xe8, 0xdb, 0xff, 0xff, 0xff, 0xc3],
    );
    let (f, g) = (BASE, 0x1020);

    // Knowing nothing: the unresolved jump may return.
    let program = run(&code, &[g], &NothingKnown);
    assert!(returns(&program, f));
    assert!(returns(&program, g));
    assert_eq!(body(&program, g), [g, 0x1025]);

    // Its only case traps: f never returns, so g does not go on after the
    // call.
    let mut table = Answers::new(0x1002, &[0x1008]);
    let program = resolved(&code, &[g], &NothingKnown, &mut table);
    assert_eq!(table.asked, [(f, f, vec![f])]);
    assert_eq!(body(&program, f), [f, 0x1008]);
    assert_eq!(block(&program, 0x1008).exit, Exit::Stop);
    assert!(!returns(&program, f));
    assert!(!returns(&program, g));
    assert!(program.block_at(0x1025).is_none());
    assert_eq!(program.unresolved().count(), 0);

    // Its only case returns: so does f, and g goes on after the call.
    let mut table = Answers::new(0x1002, &[0x1010]);
    let program = resolved(&code, &[g], &NothingKnown, &mut table);
    assert_eq!(table.asked.len(), 1);
    assert_eq!(body(&program, f), [f, 0x1010]);
    assert!(returns(&program, f));
    assert!(returns(&program, g));
    assert_eq!(body(&program, g), [g, 0x1025]);
}

/// Answers the single target of the computed jumps and calls whose blocks
/// end at the given addresses, and no table; records the ends asked about.
struct Targets {
    answers: Vec<(u64, Target)>,
    asked: Vec<u64>,
}

impl Resolver for Targets {
    fn target(&mut self, _: u64, _: &[Block], jump: Block) -> Option<Target> {
        self.asked.push(jump.end);
        self.answers
            .iter()
            .find(|&&(end, _)| end == jump.end)
            .map(|&(_, target)| target)
    }

    fn table(&mut self, _: u64, _: &[Block], _: Block) -> Option<Table> {
        None
    }
}

#[test]
fn jumps_and_calls_through_an_import_s_slot_are_the_import() {
    // f: 1000 call stub; 1005 ret.  stub: 1010 jmp rax (rax loaded from
    // exit's slot).  g: 1020 call rax (the same); 1022 ret.  h: 1030 call
    // rcx (unknown); 1032 ret.
    let code = at(
        at(
            at(vec![0xe8, 0x0b, 0, 0, 0, 0xc3], 0x10, &[0xff, 0xe0]),
            0x20,
            &[0xff, 0xd0, 0xc3],
        ),
        0x30,
        &[0xff, 0xd1, 0xc3],
    );
    let (f, stub, g, h) = (BASE, 0x1010, 0x1020, 0x1030);
    let slot = Target::Pointer {
        address: 0x2000,
        size: 8,
    };
    let mut resolver = Targets {
        answers: vec![(0x1012, slot), (0x1022, slot)],
        asked: Vec::new(),
    };
    let known = Known { no_return: vec![] };
    let program = resolved(&code, &[f, g, h], &known, &mut resolver);
    resolver.asked.sort_unstable();
    assert_eq!(resolver.asked, [0x1012, 0x1022, 0x1032]);

    // The stub is a thunk to exit: it never returns, nor does its caller.
    assert_eq!(body(&program, stub), [stub]);
    assert_eq!(
        block(&program, stub).exit,
        Exit::Jump(Destination::Import(0x2000))
    );
    assert!(!returns(&program, stub));
    assert_eq!(
        block(&program, f).exit,
        Exit::Call {
            callee: Destination::Address(stub),
            returns: Returns::No
        }
    );
    assert!(!returns(&program, f));
    assert!(program.block_at(0x1005).is_none(), "f falls through exit");

    // A call through the slot is a call to exit: no fallthrough.
    assert_eq!(
        block(&program, g).exit,
        Exit::Call {
            callee: Destination::Import(0x2000),
            returns: Returns::No
        }
    );
    assert!(!returns(&program, g));
    assert!(program.block_at(0x1022).is_none(), "g falls through exit");

    // A call the resolver does not know goes on, unresolved.
    assert_eq!(body(&program, h), [h, 0x1032]);
    assert!(returns(&program, h));
    let unresolved: Vec<_> = program
        .unresolved()
        .map(|(id, d)| (program.blocks[id].start, d))
        .collect();
    assert_eq!(unresolved, [(h, Destination::Indirect)]);
}

#[test]
fn a_single_target_that_is_a_slot_with_a_known_value_or_an_address_is_followed() {
    // f: 1000 call rax (its slot holds 1020); 1002 jmp rcx (to 1030).
    // g: 1020 ret.  1030: ret.
    let code = at(
        at(vec![0xff, 0xd0, 0xff, 0xe1], 0x20, &[0xc3]),
        0x30,
        &[0xc3],
    );
    let mut resolver = Targets {
        answers: vec![
            (
                0x1002,
                Target::Pointer {
                    address: 0x3000,
                    size: 8,
                },
            ),
            (0x1004, Target::Address(0x1030)),
        ],
        asked: Vec::new(),
    };
    let program = resolved(
        &code,
        &[BASE],
        &Slots(vec![(0x3000, 0x1020)]),
        &mut resolver,
    );
    assert_eq!(
        block(&program, BASE).exit,
        Exit::Call {
            callee: Destination::Address(0x1020),
            returns: Returns::Yes
        }
    );
    assert!(program.function_at(0x1020).is_some(), "g is a function");
    assert_eq!(
        block(&program, 0x1002).exit,
        Exit::Jump(Destination::Address(0x1030))
    );
    assert_eq!(body(&program, BASE), [BASE, 0x1002, 0x1030]);
    assert!(returns(&program, BASE));
    assert_eq!(program.unresolved().count(), 0);
}

#[test]
fn nested_loops_have_their_headers_dominators_and_bodies() {
    let code = [
        0x31, 0xc0, // 1000 xor eax, eax
        0x31, 0xc9, // 1002 xor ecx, ecx       (the outer loop's head)
        0xff, 0xc0, // 1004 inc eax            (the inner loop's head)
        0x39, 0xf8, // 1006 cmp eax, edi
        0x7c, 0xfa, // 1008 jl 1004
        0xff, 0xc1, // 100a inc ecx
        0x39, 0xf1, // 100c cmp ecx, esi
        0x7c, 0xf2, // 100e jl 1002
        0xc3, //       1010 ret
    ];
    let program = run(&code, &[BASE], &NothingKnown);
    let function = program.function_at(BASE).unwrap();
    let start = |id| program.blocks[id].start;
    let mut dominators: Vec<(u64, u64)> = program
        .dominators(function)
        .into_iter()
        .map(|(block, dominator)| (start(block), start(dominator)))
        .collect();
    dominators.sort_unstable();
    assert_eq!(
        dominators,
        [
            (0x1002, 0x1000),
            (0x1004, 0x1002),
            (0x100a, 0x1004),
            (0x1010, 0x100a)
        ]
    );
    let loops: Vec<(u64, Vec<u64>)> = program
        .loops(function)
        .into_iter()
        .map(|l| (start(l.header), l.blocks.into_iter().map(start).collect()))
        .collect();
    assert_eq!(
        loops,
        [
            (0x1002, vec![0x1002, 0x1004, 0x100a]),
            (0x1004, vec![0x1004])
        ]
    );
}
