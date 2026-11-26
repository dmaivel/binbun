//! Instructions without semantics in L1: a pointer into the frame passed
//! through them (into a register, or into state L0 does not declare and
//! back) is seen to escape, so a store through the copy is not passed when
//! a load of the slot looks for its value (`tests/fixtures/opaque-*.s`).
//! In C, a branch on what they leave in a register reads it, in both views.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers fail loudly"
)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use binbun::Database;
use binbun::analysis::{Seeds, analyse, type_library};
use binbun::decompile::{Decompiled, Options, View};
use binbun::lift::{ImageEnvironment, Kind, decode_and_lift, lift_function};
use binbun::memory::ImageMemory;
use binbun::summary::summaries;
use binbun_ast::ir::{Expr, Origin, Stmt};
use binbun_loader::Image;
use binbun_ssa::Op;
use binbun_ssa::constant::propagate;
use binbun_ssa::ir::{BlockId, Definition, Terminator, Type, Value};
use binbun_ssa::stack::Stack;
use binbun_ssa::text::print;

fn fixture(name: &str) -> Vec<u8> {
    let path = format!("{}/../../tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

/// Function `name` of fixture `file`, as the CLI builds and analyses it
/// (summaries, L1, constants, the stack): the slot at -16 from the entry
/// stack pointer is stored, overwritten through a copy of its address made
/// by instructions without semantics, and loaded. The load must not be
/// taken as reading the first store, and the frame must escape.
fn check(file: &str, name: &str) {
    let data = fixture(file);
    let image = Image::parse(&data).unwrap();
    let program = analyse(&image, Seeds::ALL, &type_library(&image).unwrap()).unwrap();
    let summaries = summaries(&image, &program);
    let entry = image
        .symbols
        .iter()
        .find(|symbol| symbol.name == name)
        .unwrap()
        .address;
    let id = program.function_at(entry).unwrap();
    let function = lift_function(&image, &program, id, &summaries).unwrap();
    let environment = ImageEnvironment::new(&image, &[]).unwrap();
    let constants = propagate(&function, &ImageMemory::new(&image));
    let stack = Stack::new(
        &function,
        environment.declarations(),
        &constants,
        environment.stack_pointer(),
        &environment.arguments(),
    );
    let text = print(&function, environment.declarations());
    let loads: Vec<_> = function
        .insts
        .iter()
        .filter(|inst| {
            matches!(inst.op, Op::Load { address, bytes: 8, .. } if stack.offset(address) == Some(-16))
        })
        .collect();
    assert_eq!(loads.len(), 1, "{file} {name}:\n{text}");
    let loaded = loads[0].results[0];
    assert_eq!(
        stack.resolve(&function, loaded),
        loaded,
        "{file} {name}: the load is taken as reading the earlier store:\n{text}"
    );
    assert!(
        stack.escaped(),
        "{file} {name}: the frame does not escape:\n{text}"
    );
}

#[test]
fn a_frame_pointer_through_a_vector_register_escapes() {
    check("opaque-x86_64.elf", "through_vector");
    check("opaque-aarch64.elf", "through_fp");
}

#[test]
fn a_frame_pointer_through_undeclared_state_escapes() {
    check("opaque-x86_64.elf", "through_mask");
    check("opaque-aarch64.elf", "through_sysreg");
}

/// The link register an escaping frame saves (`stp x29, x30, [sp,
/// #-32]!`) holds where to return, no input: `through_fp` and
/// `through_sysreg` take `x0`..`x2` (they read `x1` and `x2`, `x0` comes
/// before them), not `x30` too, and `_start` passes them no return
/// address.
#[test]
fn a_saved_link_register_is_no_parameter() {
    let data = fixture("opaque-aarch64.elf");
    let image = Image::parse(&data).unwrap();
    let database = Database::new(&image, Seeds::ALL).unwrap();
    let options = Options {
        style: None,
        ..Options::default()
    };
    for name in ["through_fp", "through_sysreg"] {
        let id = database.find_function(name).unwrap();
        let decompiled = database.decompile(id, &options).result.unwrap();
        assert_eq!(decompiled.l2.parameters.len(), 3, "{name}");
    }
}

/// The C of function `name` of fixture `file` in `view`, and its count of
/// `__asm` blocks.
fn c(file: &str, name: &str, view: View) -> (String, usize) {
    let data = fixture(file);
    let image = Image::parse(&data).unwrap();
    let database = Database::new(&image, Seeds::ALL).unwrap();
    let id = database.find_function(name).unwrap();
    let options = Options {
        style: Some("kr".to_owned()),
        view,
        ..Options::default()
    };
    let c = database.decompile(id, &options).result.unwrap().c.unwrap();
    (c.text, c.asm)
}

/// glibc's `__memcmp_evex_movbe`: `vpcmpnequb` sets k1, `kmovd eax, k1`
/// copies it, `test eax, eax; jne` branches on it. The branch must test
/// what `kmovd` left (it printed as `if (0 == 0)` when AVX-512's state was
/// not L0's): in the exact view a variable `unlifted_u32` gives, in the
/// reading view `_EAX` after the three instructions' `__asm` block.
#[test]
fn a_branch_reads_what_an_instruction_without_semantics_leaves() {
    let (exact, asm) = c("opaque-x86_64.elf", "first_difference", View::Exact);
    assert_eq!(asm, 0, "{exact}");
    let lines: Vec<&str> = exact.lines().map(str::trim).collect();
    let kmovd = lines
        .iter()
        .position(|line| line.ends_with(" = unlifted_u32(\"kmovd eax, k1\");"))
        .unwrap_or_else(|| panic!("{exact}"));
    // `v5 = …`, or `int32_t v5 = …` where it declares the mask.
    let mask = lines[kmovd]
        .split(" = ")
        .next()
        .and_then(|target| target.rsplit(' ').next())
        .unwrap();
    assert_eq!(
        lines[kmovd - 2..kmovd],
        [
            "unlifted(\"vmovdqu64 ymm17, ymmword ptr [rsi]\");",
            "unlifted(\"vpcmpub k1, ymm17, ymmword ptr [rdi], 0x4\");",
        ][..],
        "{exact}"
    );
    assert!(
        lines[kmovd + 1].starts_with(&format!("if ({mask} ")),
        "{exact}"
    );

    let (reading, asm) = c("opaque-x86_64.elf", "first_difference", View::Reading);
    assert_eq!(asm, 1, "{reading}");
    let lines: Vec<&str> = reading
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect();
    let block = lines
        .iter()
        .position(|&line| line == "__asm {")
        .unwrap_or_else(|| panic!("{reading}"));
    assert_eq!(
        lines[block + 1..block + 6],
        [
            "vmovdqu64 ymm17, ymmword ptr [rsi]",
            "vpcmpub k1, ymm17, ymmword ptr [rdi], 0x4",
            "kmovd eax, k1",
            "}",
            "if (_EAX == 0)",
        ][..],
        "{reading}"
    );
}

/// Whether the instruction of `image` at `address` has no semantics (its
/// L0 is `lift_opaque`'s), remembered in `known`.
fn opaque_at(image: &Image<'_>, address: u64, known: &mut BTreeMap<u64, bool>) -> bool {
    *known.entry(address).or_insert_with(|| {
        decode_and_lift(image, address)
            .is_ok_and(|lifted| matches!(lifted.semantics, Ok((_, Kind::Opaque))))
    })
}

/// Whether L1 `value` of `decompiled` is computed (through instructions,
/// not memory or block parameters) from one of `values`.
fn computed_from(decompiled: &Decompiled, value: Value, values: &BTreeSet<Value>) -> bool {
    let l1 = &decompiled.l1;
    let mut work = vec![value];
    let mut seen = BTreeSet::new();
    while let Some(value) = work.pop() {
        if values.contains(&value) {
            return true;
        }
        if !seen.insert(value) {
            continue;
        }
        let Some(info) = l1.value(value) else {
            continue;
        };
        let Definition::Result { inst, .. } = info.definition else {
            continue;
        };
        let Some(inst) = l1.inst(inst) else { continue };
        work.extend(
            inst.op
                .operands()
                .into_iter()
                .filter(|&operand| l1.ty(operand) != Some(Type::Memory)),
        );
    }
    false
}

/// Whether L2 expression `id` of `decompiled` is a constant or has an
/// undefined value in it.
fn constant_or_undefined(decompiled: &Decompiled, id: binbun_ast::ir::ExprId) -> bool {
    let l2 = &decompiled.l2;
    if matches!(l2.expr(id), Some(Expr::Const(_))) {
        return true;
    }
    let mut work = vec![id];
    while let Some(id) = work.pop() {
        match l2.expr(id) {
            Some(Expr::Undefined(..)) => return true,
            Some(expr) => work.extend(expr.operands(l2)),
            None => {}
        }
    }
    false
}

/// What of `decompiled` (a function of the x86-64 `image`) folds a value
/// an instruction without semantics defines: in L1, an instruction of it
/// that is a constant or undefined, or an output of its intrinsic that
/// constant propagation finds constant; in L2, a decision whose L1 branch
/// tests a value computed from such outputs, made on a constant or an
/// undefined value.
fn folded(
    image: &Image<'_>,
    decompiled: &Decompiled,
    known: &mut BTreeMap<u64, bool>,
) -> Vec<String> {
    let l1 = &decompiled.l1;
    let constants = propagate(l1, &ImageMemory::new(image));
    let mut failures = Vec::new();
    let mut defined = BTreeSet::new();
    for inst in &l1.insts {
        if !opaque_at(image, inst.address, known) {
            continue;
        }
        if matches!(inst.op, Op::Const(_) | Op::Undefined(..)) {
            failures.push(format!("{:#x}: L1 {:?}", inst.address, inst.op));
        }
        for &result in &inst.results {
            if l1.ty(result) == Some(Type::Memory) {
                continue;
            }
            if constants.constant(result).is_some() {
                failures.push(format!("{:#x}: {result:?} is constant", inst.address));
            }
            defined.insert(result);
        }
    }
    let tested: BTreeSet<BlockId> = (0u32..)
        .zip(&l1.blocks)
        .filter(|(_, block)| {
            matches!(block.terminator, Terminator::Branch { condition, .. }
                if computed_from(decompiled, condition, &defined))
        })
        .map(|(index, _)| BlockId(index))
        .collect();
    let l2 = &decompiled.l2;
    for (index, stmt) in (0u32..).zip(&l2.stmts) {
        let condition = match *stmt {
            Stmt::If { condition, .. }
            | Stmt::While { condition, .. }
            | Stmt::DoWhile { condition, .. }
            | Stmt::For { condition, .. } => condition,
            Stmt::Switch { scrutinee, .. } => scrutinee,
            Stmt::Assign { .. }
            | Stmt::Call { .. }
            | Stmt::Intrinsic { .. }
            | Stmt::Expr(_)
            | Stmt::Break(_)
            | Stmt::Continue(_)
            | Stmt::Label(_)
            | Stmt::Goto(_)
            | Stmt::Return(_)
            | Stmt::Trap(_)
            | Stmt::Unreachable
            | Stmt::Escape { .. }
            | Stmt::Try { .. }
            | Stmt::VaStart { .. } => continue,
        };
        let branch = l2
            .provenance
            .stmt(binbun_ast::ir::StmtId(index))
            .iter()
            .any(|origin| matches!(origin, Origin::Block(block) if tested.contains(block)));
        if branch && constant_or_undefined(decompiled, condition) {
            failures.push(format!("L2 s{index} decides on a constant"));
        }
    }
    failures
}

/// No value an instruction without semantics defines is folded to a
/// constant, in L1 or in L2's decisions, in either view, in any function
/// of the system's libc and bash (their AVX-512 string functions
/// included: `__memcmp_evex_movbe` decided on `0 == 0` when AVX-512's
/// state was not L0's).
#[test]
#[ignore = "decompiles all of libc and bash in both views"]
fn values_of_instructions_without_semantics_are_never_folded() {
    for path in ["/usr/lib/libc.so.6", "/usr/bin/bash"] {
        if !Path::new(path).exists() {
            continue;
        }
        let data = fs::read(path).unwrap();
        let image = Image::parse(&data).unwrap();
        let database = Database::new(&image, Seeds::ALL).unwrap();
        for view in [View::Exact, View::Reading] {
            let options = Options {
                view,
                ..Options::default()
            };
            let mut failures = Vec::new();
            let mut checked = 0;
            database.decompile_all(
                &options,
                |output| {
                    let Ok(decompiled) = &output.result else {
                        return (false, Vec::new());
                    };
                    let found = folded(&image, decompiled, &mut BTreeMap::new());
                    let found = found
                        .into_iter()
                        .map(|failure| format!("{:#x}: {failure}", output.entry))
                        .collect();
                    (true, found)
                },
                |(decompiled, found)| {
                    checked += usize::from(decompiled);
                    failures.extend(found);
                },
            );
            assert!(
                failures.is_empty(),
                "{path} {view:?}:\n{}",
                failures.join("\n")
            );
            assert!(checked > 1000, "{path} {view:?}: {checked} decompiled");
        }
    }
}
