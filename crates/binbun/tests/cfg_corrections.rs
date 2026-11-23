//! The user's corrections as seeds of recovery ([`Seed::Flow`],
//! [`Seed::NotCode`], [`Seed::End`], [`Seed::NoFunction`],
//! [`SeedKind::User`]) on a small hand-assembled x86-64 program.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers fail loudly"
)]

use binbun::cfg::{
    Exit, NoResolver, NothingKnown, Options, Program, Returns, Seed, SeedKind, recover,
};
use binbun_semantics::core::memory::Flat;
use binbun_x86::{Mode, X86};

const BASE: u64 = 0x1000;

/// `0x1000: call 0x100a; ret; nop×4`, `0x100a: mov eax, 1; nop; ret`, and
/// `0x1011: mov eax, 2; ret`, which nothing reaches.
const CODE: &[u8] = &[
    0xe8, 0x05, 0x00, 0x00, 0x00, // call 0x100a
    0xc3, // ret
    0x90, 0x90, 0x90, 0x90, // nop ×4
    0xb8, 0x01, 0x00, 0x00, 0x00, // 0x100a: mov eax, 1
    0x90, // 0x100f: nop
    0xc3, // 0x1010: ret
    0xb8, 0x02, 0x00, 0x00, 0x00, // 0x1011: mov eax, 2
    0xc3, // 0x1016: ret
];

/// Recovers [`CODE`] from its entry and `corrections`.
fn recovered(corrections: &[Seed]) -> Program {
    let mut seeds = vec![Seed::Function(BASE, SeedKind::Symbol)];
    seeds.extend_from_slice(corrections);
    seeds.sort_by_key(Seed::address);
    recover(
        &X86,
        Mode::Bits64,
        &Flat::new(BASE, CODE),
        &seeds,
        &NothingKnown,
        &mut NoResolver,
        &Options::default(),
    )
}

/// The function at `entry`'s blocks as `(start, end)`.
fn blocks(p: &Program, entry: u64) -> Vec<(u64, u64)> {
    let f = &p.functions[p.function_at(entry).unwrap()];
    f.blocks
        .iter()
        .map(|&b| (p.blocks[b].start, p.blocks[b].end))
        .collect()
}

fn entries(p: &Program) -> Vec<u64> {
    p.functions.values().map(|f| f.entry).collect()
}

#[test]
fn without_corrections_the_called_function_is_recovered() {
    let p = recovered(&[]);
    assert_eq!(entries(&p), [0x1000, 0x100a]);
    assert_eq!(blocks(&p, 0x100a), [(0x100a, 0x1011)]);
    assert!(p.block_at(0x1011).is_none());
}

#[test]
fn code_is_decoded_and_followed_without_making_a_function() {
    let p = recovered(&[Seed::Flow(0x1011)]);
    assert_eq!(entries(&p), [0x1000, 0x100a]);
    let block = p.blocks[p.block_at(0x1011).unwrap()];
    assert_eq!((block.end, block.exit), (0x1017, Exit::Return));
}

#[test]
fn code_already_a_function_changes_nothing() {
    let p = recovered(&[Seed::Flow(0x100a)]);
    assert_eq!(entries(&p), [0x1000, 0x100a]);
    assert_eq!(blocks(&p, 0x100a), [(0x100a, 0x1011)]);
}

#[test]
fn bytes_that_are_no_code_end_the_code_that_reaches_them() {
    let p = recovered(&[Seed::NotCode {
        start: 0x100f,
        end: 0x1010,
    }]);
    let f = &p.functions[p.function_at(0x100a).unwrap()];
    let block = p.blocks[f.blocks[0]];
    assert_eq!((block.start, block.end), (0x100a, 0x100f));
    assert_eq!(block.exit, Exit::Invalid);
    // What only that code led to is gone: the `ret` after it.
    assert!(p.block_at(0x1010).is_none());
    // The function no longer returns, so its caller's fallthrough is not
    // its code.
    assert!(!f.returns);
    assert_eq!(blocks(&p, 0x1000), [(0x1000, 0x1005)]);
}

#[test]
fn a_function_the_user_states_is_made_and_kept() {
    let p = recovered(&[Seed::Function(0x1011, SeedKind::User)]);
    assert_eq!(entries(&p), [0x1000, 0x100a, 0x1011]);
    let f = &p.functions[p.function_at(0x1011).unwrap()];
    assert!(f.seeds.contains(SeedKind::User));
    assert!(f.returns);
}

#[test]
fn a_functions_end_makes_what_follows_a_tail_call() {
    let p = recovered(&[
        Seed::Function(0x100a, SeedKind::User),
        Seed::End {
            function: 0x100a,
            end: 0x100f,
        },
    ]);
    assert_eq!(blocks(&p, 0x100a), [(0x100a, 0x100f)]);
    // Falling out of the range goes into a function of its own, which
    // returns: so does the one ended.
    assert_eq!(entries(&p), [0x1000, 0x100a, 0x100f]);
    assert!(p.functions[p.function_at(0x100a).unwrap()].returns);
    assert_eq!(blocks(&p, 0x100f), [(0x100f, 0x1011)]);
}

#[test]
fn a_deleted_function_is_not_made_and_its_call_falls_through() {
    let p = recovered(&[Seed::NoFunction(0x100a), Seed::Flow(0x100a)]);
    assert_eq!(entries(&p), [0x1000]);
    // Its instructions stay code.
    let kept = p.blocks[p.block_at(0x100a).unwrap()];
    assert_eq!((kept.end, kept.exit), (0x1011, Exit::Return));
    let call = p.blocks[p.block_at(0x1000).unwrap()];
    assert!(matches!(
        call.exit,
        Exit::Call {
            returns: Returns::Unknown,
            ..
        }
    ));
    assert_eq!(blocks(&p, 0x1000), [(0x1000, 0x1005), (0x1005, 0x1006)]);
}
