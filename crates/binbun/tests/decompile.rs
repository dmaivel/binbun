#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers fail loudly"
)]

//! Decompilation's glue: the goto and escape counts, the differential
//! check's setup per architecture, finding a function by name or address,
//! and one function decompiled alone as in the whole program.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use binbun::Database;
use binbun::analysis::Seeds;
use binbun::cfg::FunctionId;
use binbun::decompile::{Options, Output, View, callers, callers_for, count, stream, threads};
use binbun::progress::Progress;
use binbun::references::References;
use binbun::summary::{self, callees_first, calls};
use binbun::target::setup;
use binbun::user::{UserTypes, data_model};
use binbun_aarch64_lift::registers::{self as a64};
use binbun_ast::ir::{Arm, Call, Callee, Escape, Expr, Function as Ast, Stmt};
use binbun_ast::types::{Type, Types};
use binbun_decompile::lower::Named;
use binbun_decompile::mapping::{Piece, Source};
use binbun_decompile::prototype::Prototypes;
use binbun_decompile::validate::{Link, RETURN_ADDRESS, random_states};
use binbun_loader::Image;
use binbun_semantics::bits::Bits;
use binbun_typedb::c::Scope;
use binbun_x86_lift::registers::{RAX, RIP, RSP, X86, ZMM0};

fn fixture(name: &str) -> Vec<u8> {
    let path = format!("{}/../../tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

/// `while (1) { switch (x) { case: continue; break; } if (1) break outer; }`
/// with a goto and an escape around it.
#[test]
fn counts_say_which_jumps_need_a_goto_in_c() {
    let mut f = Ast::new(0x1000, Types::new(64));
    let label = f.add_label();
    let one = f.add_expr(Expr::Const(Bits::from_u64(1, 1)));
    let outer = f.add_stmt(Stmt::Unreachable);
    let inner = f.add_stmt(Stmt::Unreachable);
    let switch = f.add_stmt(Stmt::Unreachable);
    // Inside the switch: `continue inner` is C's continue (a switch does
    // not catch it), `break switch` C's break, `break inner` a goto.
    let continue_inner = f.add_stmt(Stmt::Continue(inner));
    let break_switch = f.add_stmt(Stmt::Break(switch));
    let break_inner = f.add_stmt(Stmt::Break(inner));
    f.stmts[switch.0 as usize] = Stmt::Switch {
        scrutinee: f.add_expr(Expr::Const(Bits::from_u64(8, 0))),
        arms: vec![Arm {
            values: Vec::new(),
            default: true,
            body: vec![continue_inner, break_switch, break_inner],
            fallthrough: false,
        }],
    };
    // In the inner loop: `break outer` and `continue outer` are gotos.
    let break_outer = f.add_stmt(Stmt::Break(outer));
    let continue_outer = f.add_stmt(Stmt::Continue(outer));
    let guarded = f.add_stmt(Stmt::If {
        condition: one,
        then: vec![break_outer],
        otherwise: vec![continue_outer],
    });
    f.stmts[inner.0 as usize] = Stmt::While {
        condition: one,
        body: vec![switch, guarded],
    };
    let break_own = f.add_stmt(Stmt::Break(outer));
    f.stmts[outer.0 as usize] = Stmt::DoWhile {
        body: vec![inner, break_own],
        condition: one,
    };
    let to = f.add_stmt(Stmt::Goto(label));
    let at = f.add_stmt(Stmt::Label(label));
    let escape = f.add_stmt(Stmt::Escape {
        kind: Escape::StackTrick,
        operands: Vec::new(),
        results: Vec::new(),
    });
    f.body = vec![to, at, outer, escape];
    let counts = count(&f);
    assert_eq!((counts.gotos, counts.escapes), (4, 1));
}

#[test]
fn setup_follows_the_architecture() {
    let data = fixture("program-x86_64.elf");
    let image = Image::parse(&data).unwrap();
    let x86 = setup(&image, 0x40_1000).unwrap();
    assert_eq!(x86.link, Link::Stack { bytes: 8 });
    for state in random_states(&x86, 32, 1) {
        let rsp = state.registers[RSP.0 as usize].known().unwrap().low_u64();
        // As after a call from 16-byte aligned code.
        assert_eq!(rsp % 16, 8);
        assert_eq!(state.registers[RIP.0 as usize].bits.low_u64(), 0x40_1000);
        let df = x86.declarations.find("df").unwrap();
        assert!(state.registers[usize::from(df.0)].bits.is_zero());
    }
    let data = fixture("dozen-aarch64.elf");
    let image = Image::parse(&data).unwrap();
    let arm = setup(&image, 0x40_0000).unwrap();
    assert_eq!(arm.link, Link::Register(a64::x(30)));
    for state in random_states(&arm, 32, 1) {
        let sp = state.registers[a64::SP.0 as usize].bits.low_u64();
        assert_eq!(sp % 16, 0);
        let link = state.registers[a64::x(30).0 as usize].bits.low_u64();
        assert_eq!(link, RETURN_ADDRESS);
        assert_eq!(
            state.registers[a64::PC.0 as usize].bits.low_u64(),
            0x40_0000
        );
    }
}

#[test]
fn functions_are_found_by_name_or_address() {
    let data = fixture("program-x86_64.elf");
    let image = Image::parse(&data).unwrap();
    let database = Database::new(&image, Seeds::ALL).unwrap();
    let main = database.find_function("main").unwrap();
    let entry = database.function(main).unwrap().entry;
    assert_eq!(database.find_function(&format!("{entry:#x}")), Ok(main));
    assert_eq!(database.find_function(&format!("{entry:x}")), Ok(main));
    assert!(
        database
            .find_function(&format!("{:#x}", entry + 1))
            .is_err()
    );
    assert!(database.find_function("no_such_function").is_err());
}

/// Every function of the fixtures decompiled alone (only what it reads
/// computed) is what the whole program's stream gives for it: the same
/// L1, L2, C and counts, or the same reason it is not decompiled.
#[test]
fn one_function_decompiles_as_in_the_whole_program() {
    for name in PROGRAMS {
        let path = format!("{}/../../tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
        let alone = alone_as_in_the_whole_program(&path, usize::MAX);
        assert!(alone.decompiled > 0, "{name}: nothing decompiled");
        assert_eq!(alone.differ, Vec::<u64>::new(), "{name}");
    }
}

/// The fixtures whole programs are decompiled from.
const PROGRAMS: [&str; 14] = [
    "program-x86_64.elf",
    "program-x86_64.exe",
    "exceptions-x86_64.elf",
    "handlers-gcc-x86_64.elf",
    "handlers-clang-x86_64.elf",
    "classes-gcc-x86_64.elf",
    "classes-clang-x86_64.elf",
    "rodata-x86_64.elf",
    "dozen-aarch64.elf",
    "resolve-aarch64.elf",
    "opaque-x86_64.elf",
    "opaque-aarch64.elf",
    "mangled-aarch64.elf",
    "globals-x86_64.elf",
];

/// The whole program decompiled on several threads is the whole program
/// decompiled on one: every function's output (L1, L2, C and counts, or
/// why it is not decompiled), in the same order, though the threads
/// finish them in any order and the stream finds more interfaces while
/// they work.
#[test]
fn the_whole_program_decompiles_the_same_on_any_number_of_threads() {
    let options = Options {
        style: Some("kr".to_owned()),
        ..Options::default()
    };
    for name in PROGRAMS {
        let data = fixture(name);
        let image = Image::parse(&data).unwrap();
        let database = Database::new(&image, Seeds::ALL).unwrap();
        let on = |threads| {
            let mut outputs = Vec::new();
            database.decompile_all_on(
                &options,
                threads,
                |output| output,
                |output| {
                    outputs.push(output);
                },
            );
            outputs
        };
        let one = on(1);
        assert_eq!(one.len(), database.functions().count(), "{name}");
        assert!(
            one.iter().any(|output| output.result.is_ok()),
            "{name}: nothing decompiled"
        );
        for threads in [2, 7] {
            assert!(on(threads) == one, "{name}: {threads} threads differ");
        }
    }
}

/// The whole-program analyses before the stream are the same on any
/// number of threads: the summaries (each function lifted once its
/// earlier callees' effects are known, with those alone) are those of
/// the one-thread sweep, the references are collected in the same order,
/// and what callers read of each function is the same with every L1
/// lifted ahead of the sweep on other threads.
#[test]
fn the_whole_program_analyses_are_the_same_on_any_number_of_threads() {
    for name in PROGRAMS {
        let data = fixture(name);
        let image = Image::parse(&data).unwrap();
        let database = Database::new(&image, Seeds::ALL).unwrap();
        let program = database.program();
        let (references, summaries) = References::build(&image, program, 1, &Progress::default());
        assert_eq!(summaries, summary::summaries(&image, program), "{name}");
        let prototypes = database.prototypes();
        let read = |threads| {
            callers(
                &image,
                program,
                &summaries,
                &references,
                &prototypes,
                database.data(),
                &[],
                threads,
                false,
            )
        };
        let one = read(1);
        for threads in [2, 7] {
            let (more, effects) = References::build(&image, program, threads, &Progress::default());
            assert!(
                more == references && effects == summaries,
                "{name}: {threads} threads differ"
            );
            assert!(read(threads) == one, "{name}: {threads} threads differ");
        }
    }
}

/// Both views' callers found in one pass (the sweeps once, each settle
/// round lifting a function once for both) are each what that view's
/// pass alone finds; on `forwarded-x86_64`, where the reading view's
/// assumption drops a parameter, the two differ.
#[test]
fn both_views_found_together_are_each_as_found_alone() {
    for name in PROGRAMS.iter().copied().chain(["forwarded-x86_64.elf"]) {
        let data = fixture(name);
        let image = Image::parse(&data).unwrap();
        let database = Database::new(&image, Seeds::ALL).unwrap();
        let program = database.program();
        let (references, summaries) = References::build(&image, program, 1, &Progress::default());
        let prototypes = database.prototypes();
        let alone = |assume| {
            callers(
                &image,
                program,
                &summaries,
                &references,
                &prototypes,
                database.data(),
                &[],
                2,
                assume,
            )
        };
        let together = callers_for(
            &image,
            program,
            &summaries,
            &references,
            &prototypes,
            database.data(),
            &[],
            2,
            &[false, true],
            &Progress::default(),
        );
        let [exact, reading] = [alone(false), alone(true)];
        assert!(together.len() == 2, "{name}");
        assert!(together[0] == exact, "{name}: the exact view differs");
        assert!(together[1] == reading, "{name}: the reading view differs");
        if name == "forwarded-x86_64.elf" {
            assert!(exact != reading, "{name}: the views agree");
        }
    }
}

/// Whether one block dominates another, as the dominator tree answers it
/// at once, is what walking up from the other through each immediate
/// dominator finds: for every pair of blocks, reached or not, of every
/// function of a few binaries.
#[test]
fn dominance_is_the_walk_up_the_dominator_tree() {
    use binbun_ssa::ir::BlockId;
    for name in [
        "program-x86_64.elf",
        "classes-gcc-x86_64.elf",
        "dozen-aarch64.elf",
        "handlers-clang-x86_64.elf",
    ] {
        let data = fixture(name);
        let image = Image::parse(&data).unwrap();
        let database = Database::new(&image, Seeds::ALL).unwrap();
        for (id, _) in database.functions() {
            let (Ok(prepared), _) = database.prepare(id, &[]) else {
                continue;
            };
            let tree = &prepared.facts.dominators;
            let blocks = u32::try_from(prepared.l1.blocks.len()).unwrap();
            let walked = |a: BlockId, b: BlockId| {
                let mut at = b;
                loop {
                    if at == a {
                        return true;
                    }
                    match tree.parent(at) {
                        Some(parent) => at = parent,
                        None => return false,
                    }
                }
            };
            for a in (0..blocks).map(BlockId) {
                for b in (0..blocks).map(BlockId) {
                    assert_eq!(tree.dominates(a, b), walked(a, b), "{name}: {a:?} {b:?}");
                }
            }
        }
    }
}

/// A database's progress counts each whole-program pass through: the
/// references end with every function done, and finding what callers
/// read ends with its last pass done.
#[test]
fn whole_program_passes_count_every_function_through() {
    let data = fixture("program-x86_64.elf");
    let image = Image::parse(&data).unwrap();
    let database = Database::new(&image, Seeds::ALL).unwrap();
    assert_eq!(database.progress().get(), None);
    let _ = database.references();
    let functions = database.program().functions.len();
    assert_eq!(database.progress().get(), Some((functions, functions)));
    let _ = database.callers_both(&[]);
    let (done, total) = database.progress().get().unwrap();
    assert!(total > 0 && done == total, "{done} of {total}");
}

/// `risky` (`exceptions.cpp`) throws on one path, through its cold part,
/// and returns `2 * x` on the other: the path that never returns says
/// nothing about its result, so it returns an `int` in `eax`, and so does
/// `guarded`, which returns what `risky` returns.
#[test]
fn paths_that_never_return_leave_the_result_alone() {
    let data = fixture("exceptions-x86_64.elf");
    let image = Image::parse(&data).unwrap();
    let database = Database::new(&image, Seeds::ALL).unwrap();
    let risky = database.find_function("_Z5riskyi").unwrap();
    let cold = database.find_function("_Z5riskyi.cold").unwrap();
    assert_eq!(cold, risky, "the cold part is risky's");
    let int = [Piece {
        register: RAX,
        offset: 0,
        width: 32,
    }];
    let mut returns = BTreeMap::new();
    stream(
        &image,
        database.program(),
        database.summaries(),
        &database.callers(&[]),
        &[],
        |id, _, interfaces| {
            let entry = database.function(id).unwrap().entry;
            let pieces = interfaces.interfaces.get(&entry).map(|i| i.returns.clone());
            returns.insert(database.name(entry).unwrap_or("").to_owned(), pieces);
        },
    );
    for name in ["_Z5riskyi", "_Z7guardedi"] {
        assert_eq!(returns[name].as_deref(), Some(&int[..]), "{name}");
    }
}

/// `deregister_tm_clones` (the C runtime's, in the fixture) leaves a
/// constant in `eax` at every exit, which its only caller never reads: it
/// returns nothing. `main` is passed to `__libc_start_main` by address,
/// a caller we cannot see, so it keeps the `int` its body returns.
#[test]
fn results_no_caller_reads_are_dropped() {
    let data = fixture("program-x86_64.elf");
    let image = Image::parse(&data).unwrap();
    let database = Database::new(&image, Seeds::ALL).unwrap();
    // The width of the return value, if any.
    let returns = |name: &str| {
        let id = database.find_function(name).unwrap();
        let l2 = database
            .decompile(id, &Options::default())
            .result
            .unwrap()
            .l2;
        l2.returns.map(|ty| l2.types.width(ty))
    };
    assert_eq!(returns("deregister_tm_clones"), None);
    assert_eq!(returns("main"), Some(Some(32)));
}

/// `both` (`tests/fixtures/interfaces-x86_64.s`) writes `dl` and then
/// reads `edx` only in an `and` with a value that is 0 or 1: no bit of
/// the entry value of `rdx` reaches its result, so it has two parameters,
/// and `forwards`, which sets both and jumps to it, none. `kept` returns
/// all of `edx` after the same write: the bits `dl` leaves are read, a
/// third parameter.
#[test]
fn bits_an_and_masks_off_make_no_parameter() {
    let data = fixture("interfaces-x86_64.elf");
    let image = Image::parse(&data).unwrap();
    let database = Database::new(&image, Seeds::ALL).unwrap();
    let parameters = |name: &str| {
        let id = database.find_function(name).unwrap();
        let decompiled = database.decompile(id, &Options::default()).result.unwrap();
        decompiled.mapping.parameters.len()
    };
    assert_eq!(parameters("both"), 2);
    assert_eq!(parameters("forwards"), 0);
    assert_eq!(parameters("kept"), 3);
}

/// glibc's `open` declares its flags a plain `int`; the system call
/// `open`'s are the set `open_flags`, which the C library's wrapper
/// takes too. So `check_tty`'s (`tests/fixtures/forwarded.c`) are
/// named, with the target's values, defined as the macros they are in
/// C's headers where none has defined them (an `enum` of `O_RDWR` broke C
/// compiled after `<fcntl.h>`).
#[test]
fn a_c_library_function_takes_its_system_calls_flag_names() {
    let data = fixture("forwarded-x86_64.elf");
    let c = bare_c(&data, "check_tty");
    assert!(c.contains("open(\"/dev/tty\",O_RDWR|O_NONBLOCK"), "{c}");
    assert!(c.contains("#ifndefO_RDWR#defineO_RDWR2#endif"), "{c}");
    assert!(c.contains("#defineO_NONBLOCK0x800"), "{c}");
    assert!(!c.contains("enum"), "{c}");
}

/// `chosen` (`tests/fixtures/interfaces-x86_64.s`) is `cmovne eax,
/// [rdi]`: the machine reads `[rdi]` whichever value it keeps, and C's
/// `?:` reads it only if it is chosen. So the C reads it first, for its
/// fault (an unreadable `a1` faults with `a2` 0 too), in both views
/// (the exact one's pointee is its type of alignment 1).
#[test]
fn a_load_a_conditional_move_makes_is_read_whichever_value_is_kept() {
    let data = fixture("interfaces-x86_64.elf");
    for (view, pointee) in [(View::Exact, "binbun_i32_u"), (View::Reading, "int32_t")] {
        let c = bare_c_in(&data, "chosen", view);
        let read = c.find(&format!("(void)*(volatile{pointee}*)a1;"));
        let select = c.find("a2!=0?*a1:41");
        assert!(read.is_some() && read < select, "{view:?}: {c}");
    }
}

/// The same code in the exact view is the machine's: MXCSR read at
/// entry, each operation under the rounding it holds
/// (`float_mul(a, b, rounding)`), the exceptions the operation raises
/// (`float_mul_status`) tested against the masks for the trap, and a
/// comparison `ucomisd` made written as C's quiet one, not `>`, which
/// is the signalling comparison.
#[test]
fn scalar_floats_are_the_machines_operations_in_the_exact_view() {
    let data = fixture("floats-x86_64.elf");
    let c = bare_c(&data, "product");
    for expected in [
        "doubleproduct(doublea1,doublea2)",
        "mxcsr_entry=binbun_read_mxcsr();",
        "float_mul_status(",
        "=float_mul(",
        "binbun_trap(BINBUN_TRAP_FLOATING_POINT);",
    ] {
        assert!(c.contains(expected), "{expected}: {c}");
    }
    let c = bare_c(&data, "narrowed");
    assert!(c.contains("float_convert_status("), "{c}");
    let c = bare_c(&data, "truncated");
    assert!(c.contains("float_to_sint32_status("), "{c}");
    let c = bare_c(&data, "below");
    assert!(c.contains("float_compare_signaling_status("), "{c}");
    assert!(c.contains("return__builtin_isgreater("), "{c}");
    // The others have their C too (`bare_c` fails where one has none).
    for function in [
        "total",
        "halved",
        "nearest",
        "differs",
        "same",
        "unordered",
        "root",
        "polynomial",
        "smaller",
        "summed",
    ] {
        assert!(bare_c(&data, function).contains(&format!("{function}(")));
    }
}

/// Scalar floating point (`tests/fixtures/floats.c`) in the reading
/// view, which takes the floating-point controls for what a process
/// starts with, a NaN for any NaN and a converted float for one in
/// range: each SSE instruction is then C's operation (`mulsd` is `*`,
/// not the rounding, the modes, the masks and the trap MXCSR adds to
/// it); a condition on `ucomisd`'s flags is the comparison C writes,
/// whichever condition codes made it (`setp` and `cmovne` for `!=`); a
/// sign mask is a negation or `fabs`; and a function that leaves its
/// first argument where it found it on one path still returns a
/// `double`. The C says how many instructions it assumed this of.
#[test]
fn scalar_floats_are_cs_operations_in_the_reading_view() {
    let data = fixture("floats-x86_64.elf");
    let cases = [
        ("product", "doubleproduct(doublea1,doublea2){returna1*a2;}"),
        ("total", "floattotal(floata1,floata2){returna1+a2;}"),
        ("halved", "doublehalved(int32_ta1){return(double)a1*0.5;}"),
        ("truncated", "(doublea1){return(int32_t)a1;}"),
        ("narrowed", "floatnarrowed(doublea1){return(float)a1;}"),
        ("below", "(doublea1,doublea2){returna2>a1;}"),
        ("differs", "(doublea1,doublea2){returna1!=a2;}"),
        ("same", "(floata1,floata2){returna1==a2;}"),
        ("unordered", "{return__builtin_isunordered(a1,a2);}"),
        ("negated", "doublenegated(doublea1){return-a1;}"),
        (
            "magnitude",
            "floatmagnitude(floata1){return__builtin_fabsf(a1);}",
        ),
        ("root", "if(0.0>x)returnsqrt(x);return__builtin_sqrt(x);"),
        ("polynomial", "{return3.0*a1*a1-a1*2.5+0.125;}"),
        ("smaller", "doublesmaller(doublea1,doublea2){"),
    ];
    for (function, expected) in cases {
        let c = bare_c_in(&data, function, View::Reading);
        assert!(c.contains(expected), "{function}: {c}");
    }
    let c = bare_c_in(&data, "product", View::Reading);
    assert!(
        c.contains(
            "1instruction'sfloating-pointcontrols,1instruction'sfloating-pointresultassumed."
        ),
        "{c}"
    );
    // A sign mask assumes nothing: it is exact.
    let c = bare_c_in(&data, "negated", View::Exact);
    assert!(c.contains("doublenegated(doublea1){return-a1;}"), "{c}");
}

/// What a function leaves in the vector result register is its return
/// value where it is a scalar that goes nowhere else
/// (`tests/fixtures/floats.c`), in both views: a `double` loaded and
/// returned (`loaded`), a sum a loop keeps there (`summed`: each
/// addition's operand in the exact L1 is tested for the next one's
/// exceptions, which makes it no less a result) and the largest of an
/// array. One stored to memory is a copy that went through the
/// register, and no result (`copied`, `scaled`). The sum is a `double`
/// variable, not the 512 bits of `zmm0` L1 carries round the loop, and
/// the largest is chosen as a `double` (`a > b ? a : b`), not by the
/// bits of a comparison's outcome.
#[test]
fn a_scalar_left_in_the_vector_register_is_the_result_unless_it_was_stored() {
    let data = fixture("floats-x86_64.elf");
    for view in [View::Exact, View::Reading] {
        for (function, expected) in [
            ("loaded", "doubleloaded("),
            ("summed", "doublesummed("),
            ("largest", "doublelargest("),
            ("copied", "voidcopied("),
            ("scaled", "voidscaled("),
        ] {
            let c = bare_c_in(&data, function, view);
            assert!(c.contains(expected), "{view:?} {function}: {c}");
        }
    }
    let c = bare_c_in(&data, "summed", View::Reading);
    for expected in [
        "doublesummed(double*a1,int32_ta2)",
        "if(a2<=0)return0.0;doubleresult=0.0;",
        "result=result+*a1;",
        "returnresult;",
    ] {
        assert!(c.contains(expected), "{expected}: {c}");
    }
    assert!(
        !c.contains("u64x8") && !c.contains("binbun_undefined"),
        "{c}"
    );
    // `maxsd`'s choice is one between two doubles by their comparison.
    let c = bare_c_in(&data, "largest", View::Reading);
    assert!(c.contains("result=v7>result?v7:result;"), "{c}");
    // The caller reads each.
    let c = bare_c_in(&data, "main", View::Reading);
    for call in ["=summed(", "=f64_bits(loaded(", "=f64_bits(largest("] {
        assert!(c.contains(call), "{call}: {c}");
    }
}

/// `shifted` (`tests/fixtures/floats.c`, glibc's `scalbnf` in small)
/// returns a `float` it makes of an exponent it keeps in `eax` on every
/// path, so every exit leaves a value in both result registers and its
/// body cannot say which it returns. Its caller reads `xmm0` after the
/// call and nothing reads `eax`: it returns the `float`, in both views,
/// and the caller's call has it. Its exponent, which goes into the
/// float's bits, is still the integer its register passes: a
/// floating-point type there would pass it in a vector register.
#[test]
fn a_result_in_the_vector_register_is_told_from_one_in_the_integer_register_by_callers() {
    let data = fixture("floats-x86_64.elf");
    for view in [View::Exact, View::Reading] {
        let c = bare_c_in(&data, "shifted", view);
        assert!(
            c.contains("floatshifted(int32_ta1,floata2)"),
            "{view:?}: {c}"
        );
        let c = bare_c_in(&data, "main", view);
        assert!(c.contains("floatshifted(int32_t,float);"), "{view:?}: {c}");
        assert!(c.contains("=shifted("), "{view:?}: {c}");
    }
}

/// A function returns what its callee returns in the vector register
/// (`tests/fixtures/floats.c`): `forwarded` leaves for `root` (a jump,
/// which the sweep that finds interfaces follows as it does a call, so
/// `root`'s is known when `forwarded`'s callers are read), and `wrapped`
/// returns `product`'s `double` after a store, the callee's lane and not
/// the 512 bits of the register after the call. `main` has both.
#[test]
fn a_callees_vector_result_returned_on_is_the_functions_own() {
    let data = fixture("floats-x86_64.elf");
    for view in [View::Exact, View::Reading] {
        let c = bare_c_in(&data, "forwarded", view);
        assert!(c.contains("doubleforwarded(doublea1)"), "{view:?}: {c}");
        let c = bare_c_in(&data, "wrapped", view);
        assert!(c.contains("doublewrapped("), "{view:?}: {c}");
        let c = bare_c_in(&data, "main", view);
        for expected in ["doubleforwarded(double);", "=wrapped(", "forwarded("] {
            assert!(c.contains(expected), "{view:?} {expected}: {c}");
        }
        assert!(!c.contains("wrapped called"), "{view:?}: {c}");
    }
}

/// `tenth` and `weighted` (`tests/fixtures/interfaces-x86_64.s`) read
/// the stack argument at `[rsp + 0x20]` and not all of those before it:
/// each has the four stack parameters up to it, so that C's tenth
/// parameter is where the code reads it, and `tenth` returns that one.
#[test]
fn a_stack_parameter_keeps_its_place_after_ones_not_read() {
    let data = fixture("interfaces-x86_64.elf");
    let image = Image::parse(&data).unwrap();
    let database = Database::new(&image, Seeds::ALL).unwrap();
    for name in ["tenth", "weighted"] {
        let id = database.find_function(name).unwrap();
        let decompiled = database.decompile(id, &Options::default()).result.unwrap();
        let stack: Vec<i64> = decompiled
            .mapping
            .parameters
            .iter()
            .filter_map(|source| match *source {
                Source::Stack { offset, .. } => Some(offset),
                Source::Register(_) => None,
            })
            .collect();
        assert_eq!(stack, [8, 16, 24, 32], "{name}");
        assert_eq!(decompiled.mapping.parameters.len(), 10, "{name}");
    }
    assert!(bare_c(&data, "tenth").contains("returna10;"));
}

/// `reused` reads its seventh argument and then stores to its slot;
/// `escaped` reads its seventh with a frame whose address is passed on
/// (`tests/fixtures/interfaces-x86_64.s`). In both the slot is a variable
/// in the frame's memory, which C gives no value: each has the stack
/// parameter, and the variable takes it at entry.
#[test]
fn a_stack_argument_in_the_frames_memory_is_a_parameter() {
    let data = fixture("interfaces-x86_64.elf");
    let image = Image::parse(&data).unwrap();
    let database = Database::new(&image, Seeds::ALL).unwrap();
    for name in ["reused", "escaped"] {
        let id = database.find_function(name).unwrap();
        let decompiled = database.decompile(id, &Options::default()).result.unwrap();
        let stack = Source::Stack {
            offset: 8,
            bytes: 8,
        };
        assert_eq!(decompiled.mapping.parameters.len(), 7, "{name}");
        assert_eq!(decompiled.mapping.parameters.last(), Some(&stack), "{name}");
        assert!(bare_c(&data, name).contains("frame_p8=a7;"), "{name}");
    }
}

/// A locked instruction (`tests/fixtures/atomics.c`) is one operation in
/// C, as it is one for the other threads: `lock xadd` an
/// `atomic_fetch_add` whose result is the value read, `xchg` an
/// exchange, `lock cmpxchg` a compare-and-exchange (the value read
/// compared again for the flags, not read again), `lock add`, `lock or`,
/// `lock sub` and `lock bts` fetch-and-updates whose result is dropped
/// or tested. No group is left as a load and a store, which two threads
/// could come between.
#[test]
fn a_locked_instruction_is_one_atomic_operation() {
    let data = fixture("atomics-x86_64.elf");
    let cases = [
        (
            "fetch_add",
            "result=binbun_atomic_fetch_add32(a1,a2);returnresult;",
        ),
        (
            "exchange",
            "result=binbun_atomic_exchange64(a1,a2);returnresult;",
        ),
        (
            "compare_exchange",
            "=binbun_atomic_compare_exchange32(a1,v13,a3);",
        ),
        ("increment", "binbun_atomic_fetch_add64(a1,3);return;"),
        ("set_bits", "binbun_atomic_fetch_or32(a1,a2);return;"),
        (
            "fetch_or",
            "=binbun_atomic_compare_exchange32(a1,v11,v11|a2);",
        ),
        ("try_lock", "v2=binbun_atomic_exchange32(a1,1);"),
        ("test_and_set", "v3=binbun_atomic_fetch_or64(a1,4);"),
        ("release", "v3=binbun_atomic_fetch_sub32(a1,1);"),
    ];
    for view in [View::Exact, View::Reading] {
        for (function, expected) in cases {
            let c = bare_c_in(&data, function, view);
            assert!(c.contains(expected), "{view:?} {function}: {c}");
            for split in ["binbun_atomic_load", "binbun_atomic_store"] {
                assert!(!c.contains(split), "{view:?} {function}: {c}");
            }
        }
    }
}

/// `guarded` (`tests/fixtures/interfaces-x86_64.s`) jumps over one store
/// from three tests with a load between them. Only once the load is in
/// the condition and the tests are one `&&` is the `goto` all of an
/// `if`'s arm beside the code it skips: the fold of forward `goto`s runs
/// after that too, and the store is under the `if` (in the reading view:
/// the exact one's checks of the addresses loaded from stand between
/// the tests).
#[test]
fn a_goto_over_code_from_merged_tests_is_an_if() {
    let data = fixture("interfaces-x86_64.elf");
    let c = bare_c_in(&data, "guarded", View::Reading);
    assert!(!c.contains("goto"), "{c}");
    assert!(c.contains("named[0]=1;named[1]=2;"), "{c}");
}

/// `escaped` (`tests/fixtures/interfaces-x86_64.s`) passes the address of
/// the bottom of its 24-byte frame to a callee and accesses none of it:
/// nothing says where the object there ends, and the callee may write
/// all of it, so the variable is the 24 bytes up to the return address,
/// not the one byte whose address is known.
#[test]
fn an_object_known_by_its_address_reaches_the_next_thing_in_the_frame() {
    let data = fixture("interfaces-x86_64.elf");
    let c = bare_c(&data, "escaped");
    assert!(c.contains("uint8_tunknown_m18[24];"), "{c}");
}

/// `as_double` (`tests/fixtures/interfaces-x86_64.s`) leaves the bits of
/// its argument in `xmm0` and nothing else uses them: it returns a
/// `double` there, and `read_bits`, which reads `xmm0` after calling it,
/// reads its result, not an unknown value. `through` copies eight bytes
/// through `xmm0` to memory: it returns nothing. `second` returns its
/// second vector argument, and its first, there for its position, is one
/// C passes in `xmm0`.
#[test]
fn a_value_left_in_the_vector_result_register_is_returned() {
    let data = fixture("interfaces-x86_64.elf");
    let image = Image::parse(&data).unwrap();
    let database = Database::new(&image, Seeds::ALL).unwrap();
    let returns = |name: &str| {
        let id = database.find_function(name).unwrap();
        let decompiled = database.decompile(id, &Options::default()).result.unwrap();
        decompiled.mapping.returns
    };
    let double = [Piece {
        register: ZMM0,
        offset: 0,
        width: 64,
    }];
    assert_eq!(returns("as_double"), double);
    assert_eq!(returns("through"), []);
    assert!(bare_c(&data, "as_double").contains("doubleas_double(int64_ta1)"));
    assert!(bare_c(&data, "read_bits").contains("returnf64_bits(as_double(a1))^1;"));
    assert!(bare_c(&data, "second").contains("u64x2second(doublea1,u64x2a2)"));
}

/// Calls of library functions that return a struct by value
/// (`tests/fixtures/aggregates.c`) take the declaration, placed by System
/// V's rule: `imaxdiv` takes its two arguments and returns the 16 bytes
/// of `imaxdiv_t` in `rax` and `rdx`, so the remainder is its result too,
/// not what the call leaves in `rdx`; `mallinfo2` returns its 80 bytes in
/// memory, whose address is its one argument and its result.
#[test]
fn a_struct_returned_by_value_is_placed_by_the_convention() {
    let data = fixture("aggregates-x86_64.elf");
    let image = Image::parse(&data).unwrap();
    let database = Database::new(&image, Seeds::ALL).unwrap();
    let calls = |name: &str| {
        let id = database.find_function(name).unwrap();
        let decompiled = database.decompile(id, &Options::default()).result.unwrap();
        decompiled.mapping.calls.into_values().collect::<Vec<_>>()
    };
    let whole = |register| Piece {
        register,
        offset: 0,
        width: 64,
    };
    let (rdi, rdx) = (X86.find("rdi").unwrap(), X86.find("rdx").unwrap());
    let divided = calls("quot_plus_rem");
    assert_eq!(divided.len(), 1);
    assert_eq!(divided[0].arguments.len(), 2);
    assert_eq!(divided[0].results, [whole(RAX), whole(rdx)]);
    assert!(!bare_c(&data, "quot_plus_rem").contains("clobbered"));
    let measured = calls("used");
    assert!(measured.iter().any(|call| {
        call.arguments == [Source::Register(whole(rdi))] && call.results == [whole(RAX)]
    }));
    assert!(bare_c(&data, "used").contains("*mallinfo2(structmallinfo2"));
}

/// Structs on the stack passed by address (`tests/fixtures/regions.c`):
/// `main` passes `before` to `gettimeofday`, declared `struct timeval *`,
/// and to `difference` as its third argument, `after` likewise as its
/// second; each region is the struct its callees' parameters claim, so
/// those parameters are `struct timeval *`. `spent`, passed to no
/// declared function, keeps the struct of the program's own.
#[test]
fn a_stack_struct_passed_to_a_declared_function_is_its_declared_type() {
    let data = fixture("regions-x86_64.elf");
    let difference = bare_c(&data, "difference");
    assert!(
        difference.contains("structtimeval*a2,structtimeval*a3)"),
        "{difference}"
    );
    assert!(!difference.contains("structtimeval*a1"), "{difference}");
}

/// Calls of functions that take or return a struct by value under the
/// Microsoft x64 convention (`tests/fixtures/aggregates-win.c`) take the
/// declaration, placed by its rule: `SetConsoleCursorPosition`'s `COORD`
/// (four bytes) is the 32-bit integer in `edx`, with nothing in `r8`;
/// `GetLargestConsoleWindowSize` returns one in `eax`; `lldiv` returns
/// its 16 bytes in memory, whose address is its first argument, before
/// the two declared ones (linked in from MinGW's library at the start of
/// its object's `.text`, whose section symbol does not name it).
#[test]
fn a_struct_by_value_is_placed_by_microsofts_convention() {
    let data = fixture("aggregates-x86_64.exe");
    let image = Image::parse(&data).unwrap();
    let database = Database::new(&image, Seeds::ALL).unwrap();
    let calls = |name: &str| {
        let id = database.find_function(name).unwrap();
        let decompiled = database.decompile(id, &Options::default()).result.unwrap();
        decompiled.mapping.calls.into_values().collect::<Vec<_>>()
    };
    let piece = |register, width| Piece {
        register,
        offset: 0,
        width,
    };
    let [rcx, rdx, r8] = ["rcx", "rdx", "r8"].map(|name| X86.find(name).unwrap());
    let placed = calls("place");
    assert_eq!(placed.len(), 1);
    assert_eq!(
        placed[0].arguments,
        [
            Source::Register(piece(rcx, 64)),
            Source::Register(piece(rdx, 32))
        ]
    );
    let sized = calls("widest");
    assert_eq!(sized.len(), 1);
    assert_eq!(sized[0].results, [piece(RAX, 32)]);
    let c = bare_c(&data, "widest");
    assert!(
        c.contains("structCOORDGetLargestConsoleWindowSize(void*)"),
        "{c}"
    );
    let divided = calls("both");
    assert_eq!(divided.len(), 1);
    assert_eq!(
        divided[0].arguments,
        [rcx, rdx, r8].map(|register| Source::Register(piece(register, 64)))
    );
    assert_eq!(divided[0].results, [piece(RAX, 64)]);
    let c = bare_c(&data, "both");
    assert!(c.contains("lldiv(&"), "{c}");
}

/// `check_tty` (`tests/fixtures/forwarded.c`) calls `open` with two
/// arguments and leaves `rdx` to `r9` as it found them: the exact view
/// keeps them its parameters, passed on (`open` may read them); the
/// reading view assumes they hold no argument, as no call sets them.
/// `wrap_open` passes its own third argument on the same way, but
/// `wrap_twice` passes it one that `main` sets: it keeps three
/// parameters in both views.
#[test]
fn the_reading_view_assumes_a_register_only_passed_on_is_no_argument() {
    let data = fixture("forwarded-x86_64.elf");
    let image = Image::parse(&data).unwrap();
    let database = Database::new(&image, Seeds::ALL).unwrap();
    let parameters = |name: &str, view: View| {
        let id = database.find_function(name).unwrap();
        let options = Options {
            view,
            ..Options::default()
        };
        let decompiled = database.decompile(id, &options).result.unwrap();
        decompiled.mapping.parameters.len()
    };
    assert_eq!(parameters("check_tty", View::Exact), 6);
    assert_eq!(parameters("check_tty", View::Reading), 0);
    for view in [View::Exact, View::Reading] {
        assert_eq!(parameters("wrap_open", view), 3, "{view:?}");
        assert_eq!(parameters("wrap_twice", view), 3, "{view:?}");
    }
    assert_eq!(parameters("main", View::Reading), 2);
}

/// The parameters of function `name` of `database` in `view`.
fn parameters_in(database: &Database<'_>, name: &str, view: View) -> usize {
    let id = database.find_function(name).unwrap();
    let options = Options {
        view,
        ..Options::default()
    };
    let decompiled = database.decompile(id, &options).result.unwrap();
    decompiled.mapping.parameters.len()
}

/// `forwarded-x86_64.so` is `tests/fixtures/forwarded.c` as a shared
/// object: it calls its own exported functions through their PLT stubs
/// (`wrap_twice` jumps to `wrap_open`'s, which nothing calls). A stub is
/// a function that tail-calls the one the image defines, named as it,
/// so the callers' calls read as calls of it and what they pass reaches
/// it: `wrap_open` keeps the third parameter `main` sets through
/// `wrap_twice` in the reading view too.
#[test]
fn a_shared_objects_calls_of_its_own_functions_reach_them() {
    let data = fixture("forwarded-x86_64.so");
    let image = Image::parse(&data).unwrap();
    let database = Database::new(&image, Seeds::ALL).unwrap();
    for view in [View::Exact, View::Reading] {
        assert_eq!(parameters_in(&database, "wrap_twice", view), 3, "{view:?}");
    }
    assert_eq!(parameters_in(&database, "wrap_open", View::Reading), 3);
    assert_eq!(parameters_in(&database, "check_tty", View::Reading), 0);
    let c = bare_c(&data, "wrap_twice");
    assert!(c.contains("returnwrap_open("), "{c}");
    let c = bare_c(&data, "main");
    assert!(c.contains("wrap_twice(*a2,65,0x1a4)"), "{c}");
    assert!(!c.contains("sub_"), "{c}");
}

/// `report` (`tests/fixtures/forwarded.c`) passes its two arguments on
/// through a pointer and leaves `rdx` to `r9` as it found them; `main`
/// calls it after other calls, with those registers undefined. Exported
/// from the shared object, it may have callers unseen: the exact view
/// keeps the six registers the callee may read, the reading view assumes
/// the four the call leaves undefined hold no argument.
#[test]
fn the_reading_view_assumes_a_register_a_call_leaves_undefined_is_no_argument() {
    let data = fixture("forwarded-x86_64.so");
    let image = Image::parse(&data).unwrap();
    let database = Database::new(&image, Seeds::ALL).unwrap();
    assert_eq!(parameters_in(&database, "report", View::Exact), 6);
    assert_eq!(parameters_in(&database, "report", View::Reading), 2);
}

/// `scan` (`tests/fixtures/cycles.c`) has a loop entered at two places,
/// so each join of it gets the thread pointer from the other as well as
/// from outside, and its stack protector reads the thread pointer at the
/// exit. Those joins only pass one value around: the thread pointer
/// holds its entry value at the exit and is no parameter, in both views.
/// Taken one join at a time, each got another's besides the entry value,
/// and the thread pointer was a third parameter.
#[test]
fn a_value_a_loop_carries_unchanged_is_its_entry_value() {
    let data = fixture("cycles-x86_64.elf");
    let image = Image::parse(&data).unwrap();
    let database = Database::new(&image, Seeds::ALL).unwrap();
    for view in [View::Exact, View::Reading] {
        assert_eq!(parameters_in(&database, "scan", view), 2, "{view:?}");
    }
}

/// `raised` (`tests/fixtures/x87.c`) stores the x87 environment, whose
/// tag word classifies each x87 register in use: the exact view reads
/// the eight registers, the tag word and TOP at entry, so takes them as
/// parameters after its flags. The reading view takes the x87 stack as
/// empty (no convention passes an argument there): its flags alone.
#[test]
fn the_reading_view_takes_no_argument_in_the_x87_stack() {
    let data = fixture("x87-x86_64.elf");
    let image = Image::parse(&data).unwrap();
    let database = Database::new(&image, Seeds::ALL).unwrap();
    assert!(parameters_in(&database, "raised", View::Exact) > 1);
    assert_eq!(parameters_in(&database, "raised", View::Reading), 1);
    // `main` only calls it: no instruction of its own reads the x87
    // state, so it assumes nothing of it.
    let id = database.find_function("main").unwrap();
    let options = Options {
        view: View::Reading,
        ..Options::default()
    };
    let decompiled = database.decompile(id, &options).result.unwrap();
    assert_eq!(decompiled.stats.assumed.kinds[5], 0);
}

/// `floor_pow2` (`tests/fixtures/bits.c`) tests its byte for zero, then
/// counts its bits with `bsr`, which keeps its destination (`rcx`) for a
/// zero source: a second branch on the same value, which the first
/// decides. Folded, `rcx` is never read and the function takes its byte
/// alone in both views; unfolded, `rcx` was a parameter, and `rsi` and
/// `rdx` with it for their positions.
#[test]
fn a_zero_test_an_earlier_one_decides_goes_its_way() {
    let data = fixture("bits-x86_64.elf");
    let image = Image::parse(&data).unwrap();
    let database = Database::new(&image, Seeds::ALL).unwrap();
    for view in [View::Exact, View::Reading] {
        assert_eq!(parameters_in(&database, "floor_pow2", view), 1, "{view:?}");
    }
}

/// `bit_width` (`tests/fixtures/bits.c`) counts its bits with `bsr` first,
/// whose destination (`rcx`) keeps its old value for a zero source, and
/// tests the source after it: a conditional move takes the count only
/// where the source is not zero, which is where the old value was not
/// kept. So `rcx` is never read: the function takes its source alone, in
/// both views (it took `rcx`, and `rsi`, `rdx` before it).
#[test]
fn a_value_kept_for_a_zero_source_is_unread_where_only_a_nonzero_one_is_used() {
    let data = fixture("bits-x86_64.elf");
    let image = Image::parse(&data).unwrap();
    let database = Database::new(&image, Seeds::ALL).unwrap();
    for view in [View::Exact, View::Reading] {
        assert_eq!(parameters_in(&database, "bit_width", view), 1, "{view:?}");
    }
}

/// `twice` (`tests/fixtures/ifunc.c`) calls `strlen`, which the image
/// defines as an indirect function and exports: the call goes through a
/// PLT stub and a slot an `IRELATIVE` relocation fills with what the
/// resolver returns, which is what the name binds to. So it is a call of
/// `strlen` as declared, with one argument, and `twice` takes its string
/// alone in both views. As a call through an unknown pointer, it took
/// every argument register `twice` left as it found it.
#[test]
fn a_call_through_an_indirect_functions_slot_is_a_call_of_it() {
    let data = fixture("ifunc-x86_64.elf");
    let image = Image::parse(&data).unwrap();
    let database = Database::new(&image, Seeds::ALL).unwrap();
    for view in [View::Exact, View::Reading] {
        assert_eq!(parameters_in(&database, "twice", view), 1, "{view:?}");
    }
    let c = bare_c(&data, "twice");
    assert!(c.contains("returnstrlen(s)*2;"), "{c}");
}

/// `wait_on` and `wake_one` (`tests/fixtures/futex.c`) call the kernel's
/// `futex` with the `syscall` instruction, setting the arguments their
/// operation reads (`FUTEX_WAIT` four, `FUTEX_WAKE` three) and leaving `r8`
/// and `r9` as their callers did; the kernel reads no more, so in both
/// views each takes its word alone, and so does `lock`, which calls
/// `wait_on`. Taken to read all six, they were six parameters each.
/// `wake_kind` computes its operation, `FUTEX_WAKE | (private &
/// FUTEX_PRIVATE_FLAG)`: its command is known though its flag is not, so
/// it takes its word and `private` (it took six).
/// `wake_shared` xors `private` into `FUTEX_WAKE_PRIVATE` (glibc's
/// `__lll_lock_wake`): its command depends on `private`, so the exact view
/// reads all six arguments; the reading view assumes `private` gives only
/// flags, and it takes its word and `private`.
#[test]
fn futex_reads_the_arguments_its_operation_takes() {
    let data = fixture("futex-x86_64.elf");
    let image = Image::parse(&data).unwrap();
    let database = Database::new(&image, Seeds::ALL).unwrap();
    for view in [View::Exact, View::Reading] {
        for function in ["wait_on", "wake_one", "lock"] {
            assert_eq!(
                parameters_in(&database, function, view),
                1,
                "{function} {view:?}"
            );
        }
        assert_eq!(parameters_in(&database, "wake_kind", view), 2, "{view:?}");
    }
    assert!(parameters_in(&database, "wake_shared", View::Exact) > 2);
    assert_eq!(parameters_in(&database, "wake_shared", View::Reading), 2);
    assert!(View::ASSUMPTIONS.contains("futex"));
}

/// `kept-x86_64.elf` is `tests/fixtures/kept-x86_64.s`. `root` saves and
/// restores `r15` and stores it on a path that did not assign it, which
/// reads its caller's `r15`: the exact view takes it as a parameter, and
/// so `caller`, which passes its own on; the reading view assumes a
/// register a function keeps holds no argument, and takes it in neither.
/// `thunk` reads `r15` without saving it: a parameter in both views.
#[test]
fn a_register_a_function_keeps_is_no_argument_in_the_reading_view() {
    let data = fixture("kept-x86_64.elf");
    let image = Image::parse(&data).unwrap();
    let database = Database::new(&image, Seeds::ALL).unwrap();
    for (function, exact, reading) in [("root", 2, 1), ("caller", 1, 0), ("thunk", 1, 1)] {
        assert_eq!(
            parameters_in(&database, function, View::Exact),
            exact,
            "{function}"
        );
        assert_eq!(
            parameters_in(&database, function, View::Reading),
            reading,
            "{function}"
        );
    }
    assert!(View::ASSUMPTIONS.contains("a register a function must keep, and saves and restores"));
}

/// `callbacks-x86_64.elf` is `tests/fixtures/callbacks.c`. `apply` calls
/// `f(x)` through a pointer, setting `rdi` and leaving `rdx`..`r9` as its
/// callers left them, and no call sets them: the reading view assumes
/// they hold no argument (two parameters; it took six), the exact view
/// keeps them. `relay`, with no call seen, hands its own arguments on
/// through a pointer, setting none, as a dispatch does: both views keep
/// the convention's six.
#[test]
fn a_call_through_a_pointer_takes_nothing_after_the_arguments_it_sets() {
    let data = fixture("callbacks-x86_64.elf");
    let image = Image::parse(&data).unwrap();
    let database = Database::new(&image, Seeds::ALL).unwrap();
    assert_eq!(parameters_in(&database, "apply", View::Reading), 2);
    assert_eq!(parameters_in(&database, "apply", View::Exact), 6);
    for view in [View::Exact, View::Reading] {
        assert_eq!(parameters_in(&database, "relay", view), 6, "{view:?}");
    }
    assert!(View::ASSUMPTIONS.contains("to a call through a pointer after the last argument"));
}

/// `saves-x86_64.exe` is `tests/fixtures/saves-win.c`: `scaled` keeps its
/// `double` in `xmm6` across a call, saving and restoring the caller's
/// `xmm6`, which the Microsoft x64 convention keeps: a save, not a
/// parameter (it took two).
#[test]
fn saving_xmm6_reads_no_parameter_under_microsofts_convention() {
    let data = fixture("saves-x86_64.exe");
    let image = Image::parse(&data).unwrap();
    let database = Database::new(&image, Seeds::ALL).unwrap();
    for view in [View::Exact, View::Reading] {
        assert_eq!(parameters_in(&database, "scaled", view), 1, "{view:?}");
    }
}

/// `tests/fixtures/kept-float.c`: `scaled` keeps its `double` across a call
/// of the import `strtod` in a register whose low bits the convention's
/// callee keeps: AAPCS64's `d8` (`v8`'s low 64 bits), Microsoft x64's
/// `xmm6` (`zmm6`'s low 128 bits). After the call it is still the
/// parameter, not a value the call may have changed (it was, and the
/// parameter was lost). `rescaled` keeps its own across a call to
/// `scaled`, whose summary gives back the low bits it saves and restores.
#[test]
fn the_low_bits_a_call_keeps_hold_a_value_across_it() {
    for name in ["kept-float-aarch64.elf", "kept-float-x86_64.exe"] {
        let data = fixture(name);
        let image = Image::parse(&data).unwrap();
        let database = Database::new(&image, Seeds::ALL).unwrap();
        for function in ["scaled", "rescaled"] {
            for view in [View::Exact, View::Reading] {
                let at = format!("{name} {function} {view:?}");
                assert_eq!(parameters_in(&database, function, view), 2, "{at}");
                let c = bare_c_in(&data, function, view);
                assert!(
                    !c.contains("V8_clobbered") && !c.contains("MM6_clobbered"),
                    "{at}: {c}"
                );
            }
        }
    }
}

/// Scalar floating point on AArch64 (`tests/fixtures/floats.c`): a
/// function's result left in `v0` is its return value where its caller
/// keeps it in `d8`–`d15` across later calls (AAPCS64 keeps their low 64
/// bits) before reading it, and the bits FPCR.NEP keeps above a scalar
/// result are no part of it. `main` saves and restores the `d`
/// registers it uses: saves, not parameters.
#[test]
fn aarch64_scalar_floats_return_what_callers_keep_across_calls() {
    let data = fixture("floats-aarch64.elf");
    for (function, expected) in [
        ("halved", "doublehalved(int32_ta1)"),
        ("negated", "doublenegated(doublea1)"),
        ("product", "doubleproduct(doublea1,doublea2)"),
        ("main", "int32_tmain_2(int32_ta1,int64_t*a2)"),
    ] {
        let c = bare_c_in(&data, function, View::Reading);
        assert!(c.contains(expected), "{function}: {c}");
    }
    // The exact view takes FPCR.NEP as it is at entry: `product` may read
    // `v0`'s upper half (merged above its result), but returns a double.
    let c = bare_c_in(&data, "product", View::Exact);
    assert!(c.contains("doubleproduct(u64x2a1,doublea2)"), "{c}");
}

/// Scalar floating point on AArch64 (`tests/fixtures/floats.c`) in the
/// reading view, as on x86: an operation's NaN is its own whichever NaN
/// AArch64's rule chooses (the first signalling NaN, else the first
/// NaN, quieted, else the default NaN; FMA's default NaN for a quiet NaN
/// addend and an infinity times a zero), a converted float is in range
/// (no NaN, no saturation), a narrowing conversion is C's cast (the
/// alternative half-precision format, which lifting decides it does not
/// convert to, gone), and a choice on a comparison's flags is the
/// comparison C writes.
#[test]
fn aarch64_scalar_floats_are_cs_operations_in_the_reading_view() {
    let data = fixture("floats-aarch64.elf");
    let cases = [
        ("product", "doubleproduct(doublea1,doublea2){returna1*a2;}"),
        ("total", "floattotal(floata1,floata2){returna1+a2;}"),
        (
            "truncated",
            "int32_ttruncated(doublea1){return(int32_t)a1;}",
        ),
        ("narrowed", "floatnarrowed(doublea1){return(float)a1;}"),
        (
            "root",
            "doublev1=__builtin_sqrt(x);if(!__builtin_isunordered(v1,v1))returnv1;",
        ),
        (
            "polynomial",
            "doublepolynomial(doublea1){return__builtin_fma(a1*3.0,a1,a1*-2.5)+0.125;}",
        ),
        (
            "smaller",
            "doublesmaller(doublea1,doublea2){returna1<a2?a1:(a2+1.0);}",
        ),
        ("largest", "result=v4>result?v4:result;"),
    ];
    for (function, expected) in cases {
        let c = bare_c_in(&data, function, View::Reading);
        assert!(c.contains(expected), "{function}: {c}");
        assert!(
            !c.contains("0x7ff8") && !c.contains("0x7fc0"),
            "{function}: {c}"
        );
    }
}

/// The C of function `function` of the image `data` (exact), without
/// white space.
fn bare_c(data: &[u8], function: &str) -> String {
    bare_c_in(data, function, View::Exact)
}

/// `apply` (`tests/fixtures/msvc.c`, 0x140001060) calls through its
/// pointer parameter (`call rax`): the exact C checks that the pointer is
/// canonical before the call; the reading view assumes every address it
/// calls is, though the call pushes its return address between the check
/// and the call.
#[test]
fn the_reading_view_assumes_a_called_pointer_canonical() {
    let data = fixture("msvc-x86_64.exe");
    assert!(bare_c_in(&data, "0x140001060", View::Exact).contains("binbun_check_canonical"));
    assert!(!bare_c_in(&data, "0x140001060", View::Reading).contains("binbun_check_canonical"));
}

/// The C of function `function` of the image `data` in `view`, without
/// white space.
fn bare_c_in(data: &[u8], function: &str, view: View) -> String {
    let image = Image::parse(data).unwrap();
    let database = Database::new(&image, Seeds::ALL).unwrap();
    let id = database.find_function(function).unwrap();
    let options = Options {
        style: Some("kr".to_owned()),
        view,
        ..Options::default()
    };
    let c = database.decompile(id, &options).result.unwrap().c.unwrap();
    c.text.split_whitespace().collect()
}

/// Loads and stores at addresses of no alignment
/// (`tests/fixtures/unaligned.c`: fixed-size `memcpy`, the machine's
/// plain `mov`s). The exact C asks none: what a pointer points to is a
/// type of alignment 1, so two stores through pointers that overlap in
/// part are both seen by the load after them. The reading view writes
/// C's types and says in its header that it takes addresses to be
/// aligned for them.
#[test]
fn what_a_pointer_points_to_asks_no_alignment_in_exact_c() {
    let data = fixture("unaligned-x86_64.elf");
    let c = bare_c(&data, "twice");
    for expected in [
        "twice(binbun_i32_u*a1,binbun_i32_u*a2)",
        "*a1=1;",
        "*a2=1;",
        "return*a1;",
    ] {
        assert!(c.contains(expected), "{expected}: {c}");
    }
    let c = bare_c(&data, "halves");
    assert!(
        c.contains("halves(binbun_i64_u*a1,binbun_u16_u*a2,uint16_ta3)"),
        "{c}"
    );
    let c = bare_c_in(&data, "twice", View::Reading);
    assert!(c.contains("twice(int32_t*a1,int32_t*a2)"), "{c}");
    assert!(View::ASSUMPTIONS.contains("aligned for the type"));
}

/// A byte tested only for being characters, two or more of them
/// (`tests/fixtures/chars.c`), is a `char`, what it is loaded through a
/// `char *`, and the constants it is compared with are written as
/// characters, a later byte of the same string's too; a NUL stored
/// through a `char *` a declaration gives is `'\0'`. A byte tested for
/// one value that happens to be a character's code (`64`), or for
/// values no character has, stays a number, in both views.
#[test]
fn bytes_tested_for_characters_are_text() {
    let data = fixture("chars-x86_64.elf");
    for view in [View::Exact, View::Reading] {
        let c = bare_c_in(&data, "absolute", view);
        for expected in ["absolute(char*a1)", "=*a1)=='/'", "=='.'"] {
            assert!(c.contains(expected), "{view:?}: {expected}: {c}");
        }
        // The second byte too, which is tested for one character only.
        assert_eq!(c.matches("=='/'").count(), 2, "{view:?}: {c}");
        let c = bare_c_in(&data, "separators", view);
        assert!(
            c.contains("==',')|(") && c.contains("==';')"),
            "{view:?}: {c}"
        );
        let c = bare_c_in(&data, "chomp", view);
        assert!(c.contains("*result='\\0';"), "{view:?}: {c}");
        let c = bare_c_in(&data, "flagged", view);
        assert!(
            c.contains("uint8_t*a1") && c.contains("*a1==64;"),
            "{view:?}: {c}"
        );
        let c = bare_c_in(&data, "marked", view);
        assert!(c.contains("==255)|(") && !c.contains('\''), "{view:?}: {c}");
    }
}

/// A value of an enumeration kept in a variable (`tests/fixtures/enums.c`,
/// its callees declared by the user to return `enum state` and `enum
/// fault`) keeps its type: the variable is declared with the tag, its
/// comparisons and a switch on it print the constants' names, in both
/// views. A variable holding values of both enumerations, or a status
/// or a product, is an integer: its comparisons print numbers.
#[test]
fn a_variable_of_one_enumerations_values_keeps_its_type() {
    let data = fixture("enums-x86_64.elf");
    let image = Image::parse(&data).unwrap();
    let database = Database::new(&image, Seeds::ALL).unwrap();
    let mut scope = Scope::new(data_model(&image), None);
    scope
        .define(
            "enum state { IDLE = 1, BUSY = 2, DONE = 3, GONE = 4, LOST = 5 };\n\
             enum fault { FAULT_THREE = 3, FAULT_FIVE = 5 };",
        )
        .unwrap();
    let prototypes = [
        ("status", "enum state status(void)"),
        ("other", "enum fault other(void)"),
    ]
    .map(|(name, c)| {
        let id = database.find_function(name).unwrap();
        let entry = database.function(id).unwrap().entry;
        (entry, scope.declaration(c).unwrap().ty)
    });
    let mut user = UserTypes::new(scope.into_types(), 64);
    for (entry, ty) in prototypes {
        user.set_prototype(entry, ty);
    }
    database.set_user(user);
    let bare = |text: &str| -> String { text.split_whitespace().collect() };
    for view in [View::Exact, View::Reading] {
        let c = |name: &str| {
            let id = database.find_function(name).unwrap();
            let options = Options {
                style: Some("kr".to_owned()),
                view,
                ..Options::default()
            };
            bare(
                &database
                    .decompile(id, &options)
                    .result
                    .unwrap()
                    .c
                    .unwrap()
                    .text,
            )
        };
        let compared = c("compared");
        for line in ["enum state v", "= status();", "!= DONE", "!= LOST"] {
            assert!(
                compared.contains(&bare(line)),
                "{view:?}: no {line} in\n{compared}"
            );
        }
        let switched = c("switched");
        for line in ["enum state v", "case IDLE:", "case BUSY:", "case GONE:"] {
            assert!(
                switched.contains(&bare(line)),
                "{view:?}: no {line} in\n{switched}"
            );
        }
        for name in ["mixed", "stepped"] {
            let mixed = c(name);
            // The variable compared is an integer, compared with numbers.
            let at = mixed
                .find("!=3)")
                .unwrap_or_else(|| panic!("{view:?}: {name}\n{mixed}"));
            let compared = &mixed[..at];
            let start = compared
                .rfind(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                .unwrap();
            let variable = &compared[start + 1..];
            // Declared alone or with its initializer (`int32_t v3 = f();`).
            let declared = mixed.contains(&format!("int32_t{variable};"))
                || mixed.contains(&format!("int32_t{variable}="));
            assert!(
                declared && mixed.contains("!=5"),
                "{view:?}: {name}\n{mixed}"
            );
            for constant in ["DONE", "LOST", "FAULT_"] {
                assert!(!mixed.contains(constant), "{view:?}: {name}\n{mixed}");
            }
        }
    }
}

/// A call's result narrower than its register (a 32-bit `int` in `rax`)
/// where the register's variable holds it takes the return type the
/// callee's prototype declares, as a whole register's result does: the
/// variable `switched` (`tests/fixtures/enums.c`) switches on, which
/// holds `status()`'s result, is a `uint32_t` where the user declares
/// `unsigned int status(void)` and an `int32_t` where `int status(void)`,
/// in both views (the switch says no sign).
#[test]
fn a_narrower_call_result_kept_takes_its_declared_type() {
    let data = fixture("enums-x86_64.elf");
    let image = Image::parse(&data).unwrap();
    let database = Database::new(&image, Seeds::ALL).unwrap();
    let id = database.find_function("switched").unwrap();
    let status = database.find_function("status").unwrap();
    let entry = database.function(status).unwrap().entry;
    for (prototype, declared) in [
        ("unsigned int status(void)", "uint32_t"),
        ("int status(void)", "int32_t"),
    ] {
        let mut scope = Scope::new(data_model(&image), None);
        let ty = scope.declaration(prototype).unwrap().ty;
        let mut user = UserTypes::new(scope.into_types(), 64);
        user.set_prototype(entry, ty);
        database.set_user(user);
        for view in [View::Exact, View::Reading] {
            let options = Options {
                style: Some("kr".to_owned()),
                view,
                ..Options::default()
            };
            let c: String = database
                .decompile(id, &options)
                .result
                .unwrap()
                .c
                .unwrap()
                .text
                .split_whitespace()
                .collect();
            let at = c
                .find("=status();")
                .unwrap_or_else(|| panic!("{prototype}, {view:?}:\n{c}"));
            let kept = &c[..at];
            let start = kept
                .rfind(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                .unwrap();
            let variable = &kept[start + 1..];
            // Declared with its initializer (`uint32_t v0 = status();`, no
            // spaces here): the type and the name before the `=`.
            let initialized = variable.len() > declared.len() && variable.starts_with(declared);
            assert!(
                c.contains(&format!(";{declared}{variable};"))
                    || c.contains(&format!("{{{declared}{variable};"))
                    || initialized,
                "{prototype}, {view:?}: {variable} not {declared} in\n{c}"
            );
        }
    }
}

/// A call through an import slot the loader fixes (MSVC's IAT in a
/// read-only `.rdata`) is a call of the import, with no load of the slot
/// and no check of what it holds; through a slot the program could
/// change (the same file with `.rdata` writable), or one bound lazily (an
/// ELF executable linked without `-z now`), it stays a call through the
/// slot's value.
#[test]
fn calls_through_import_slots_are_direct_only_where_the_loader_fixes_the_slot() {
    let mut data = fixture("msvc-x86_64.exe");
    let direct = bare_c(&data, "0x140001020");
    assert!(
        direct.contains("return__stdio_common_vfprintf(*v5,"),
        "{direct}"
    );
    assert!(!direct.contains("_ptr"), "{direct}");
    let headers = u32::from_le_bytes(data[0x3c..0x40].try_into().unwrap()) as usize;
    let sections = u16::from_le_bytes(data[headers + 6..headers + 8].try_into().unwrap());
    let optional = u16::from_le_bytes(data[headers + 20..headers + 22].try_into().unwrap());
    let table = headers + 24 + usize::from(optional);
    let rdata = (0..usize::from(sections))
        .map(|index| table + 40 * index)
        .find(|&at| &data[at..at + 8] == b".rdata\0\0")
        .unwrap();
    // IMAGE_SCN_MEM_WRITE.
    data[rdata + 39] |= 0x80;
    let through = bare_c(&data, "0x140001020");
    assert!(
        through.contains("=__stdio_common_vfprintf_ptr;"),
        "{through}"
    );
    let lazy = bare_c(&fixture("program-x86_64.elf"), "_start");
    assert!(lazy.contains("=__libc_start_main_ptr;"), "{lazy}");
    assert!(!lazy.contains("=__libc_start_main("), "{lazy}");
}

/// AArch64 branches to their target with its top byte ignored: a call
/// through an import's GOT slot (`adrp`, `ldr`, `blr`; Windows on ARM64
/// calls every DLL function so through the IAT) is a call through the
/// slot all the same, with the import's prototype: `abort(void)` passes
/// nothing, so `got_abort` takes nothing.
#[test]
fn an_aarch64_call_through_a_slot_has_the_imports_prototype() {
    let c = bare_c(&fixture("resolve-aarch64.elf"), "got_abort");
    assert!(c.contains("voidgot_abort(void)"), "{c}");
    assert!(c.contains("=abort_ptr;"), "{c}");
    assert!(c.contains(")))();"), "{c}");
}

/// The thread pointer has its platform's declared type: the stack
/// protector's canary reads as x86-64 glibc's `tcbhead_t` field, and a
/// walk from Windows x64's TEB to the loader's module list
/// (`tests/fixtures/teb.c`) reads its fields: the PEB by the binary's
/// single `gs`-relative read, at the TEB field's `offsetof`, then the
/// PEB's `Ldr` and the loader data's list by name (compared without
/// white space: the lines break). Windows ARM64's TEB is in `x18`, no
/// parameter: the same walk (`teb-aarch64.exe`, from the same source)
/// reads through `NtCurrentTeb()` by field, and its call of ntdll.dll's
/// `NtQueryInformationProcess` has the native API's prototype for ARM64.
#[test]
fn the_thread_pointer_reads_as_its_platforms_structure() {
    let cases = [
        (
            "variadic-gcc-x86_64.elf",
            "report",
            vec!["binbun_tcb()->stack_guard;", "uint64_t stack_guard;"],
        ),
        (
            "teb-x86_64.exe",
            "0x140001090",
            vec![
                "__readgsqword(offsetof(struct _TEB, ProcessEnvironmentBlock))",
                "))->Ldr;",
                "->InMemoryOrderModuleList;",
            ],
        ),
        (
            "teb-aarch64.exe",
            "0x1400011d0",
            vec![
                "int64_t sub_1400011d0(uint16_t a1)",
                "&NtCurrentTeb()->ProcessEnvironmentBlock->Ldr->InMemoryOrderModuleList;",
            ],
        ),
        (
            "teb-aarch64.exe",
            "0x140001250",
            vec![
                "int32_t NtQueryInformationProcess(void *, int32_t, void *, uint32_t, binbun_u32_u *);",
                "ProcessBasicInformation,",
            ],
        ),
    ];
    for (name, function, lines) in cases {
        let data = fixture(name);
        let image = Image::parse(&data).unwrap();
        let database = Database::new(&image, Seeds::ALL).unwrap();
        let id = database.find_function(function).unwrap();
        let options = Options {
            style: Some("kr".to_owned()),
            ..Options::default()
        };
        let decompiled = database.decompile(id, &options).result.unwrap();
        let bare = |text: &str| -> String { text.split_whitespace().collect() };
        let text = bare(&decompiled.c.unwrap().text);
        for line in lines {
            assert!(text.contains(&bare(line)), "{name}: no {line} in\n{text}");
        }
    }
}

/// A driver without its PDB (`tests/fixtures/driver.c`): its entry point
/// is `DriverEntry`, and the function it hands the system's arguments on
/// to (MSVC's `GsDriverEntry` jumps to the driver's own) has its
/// prototype and parameter names; the kernel's functions are the WDK's
/// (`IoCreateDevice`'s seven arguments, its device name a wide literal
/// through `RtlInitUnicodeString`'s `PCWSTR`); `gs` is the KPCR,
/// untyped (`KeGetCurrentThread`'s read of the current thread), no TEB.
/// `__security_init_cookie` ends in `__fastfail` (`int 0x29`), which a
/// Windows image's code lifts as the interrupt that does not return.
#[test]
fn a_driver_reads_as_kernel_mode_code() {
    let data = fixture("driver-x86_64.sys");
    let image = Image::parse(&data).unwrap();
    let database = Database::new(&image, Seeds::ALL).unwrap();
    let entry = image.entry.unwrap();
    assert_eq!(database.name(entry), Some("DriverEntry"));
    let options = Options {
        style: Some("kr".to_owned()),
        ..Options::default()
    };
    let c = |function: &str| -> String {
        let id = database.find_function(function).unwrap();
        let decompiled = database.decompile(id, &options).result.unwrap();
        decompiled.c.unwrap().text.split_whitespace().collect()
    };
    let bare = |text: &str| -> String { text.split_whitespace().collect() };
    let entry_c = c("DriverEntry");
    let own_c = c("0x140001000");
    let tag_c = c("0x1400011e0");
    let cookie_c = c("0x14000502c");
    for (text, expected) in [
        (
            &entry_c,
            "int32_t DriverEntry(struct DRIVER_OBJECT *DriverObject, struct UNICODE_STRING *RegistryPath)",
        ),
        (
            &entry_c,
            "return sub_140001000(DriverObject, RegistryPath);",
        ),
        (
            &own_c,
            "int32_t sub_140001000(struct DRIVER_OBJECT *DriverObject, struct UNICODE_STRING *RegistryPath)",
        ),
        (&own_c, "u\"\\\\Device\\\\BinbunDrv\")"),
        (
            &own_c,
            "int32_t IoCreateDevice(struct DRIVER_OBJECT *, uint32_t, struct UNICODE_STRING *, uint32_t, uint32_t, uint8_t, struct_DEVICE_OBJECT_p_u *);",
        ),
        (
            &own_c,
            "typedef struct DEVICE_OBJECT *struct_DEVICE_OBJECT_p_u __attribute__((aligned(1)));",
        ),
        (&tag_c, "__readgsqword(0x188)"),
        (
            &cookie_c,
            "g_140003008 = ~v0; return; } binbun_interrupt(0x29); }",
        ),
    ] {
        assert!(text.contains(&bare(expected)), "no {expected} in\n{text}");
    }
    for text in [&entry_c, &own_c, &tag_c] {
        assert!(!text.contains("_TEB") && !text.contains("tagMSG"), "{text}");
    }
}

/// The variadic definitions of the variadic fixture whose `va_list` is
/// in memory are recognised with their named arguments, by System V's
/// rule (GCC, Clang), Microsoft x64's (MinGW) and AAPCS64's (Clang); the
/// fixed function that stores its arguments to the stack and takes an
/// address is not.
/// `report`, which passes its `va_list` on, is printed as C's variadic
/// function (`, ...`, `va_list ap; va_start(ap, a2);`, the list passed
/// as `ap`), with no parameter for the unnamed registers; MinGW's `sum`,
/// which walks its list inline, is not; nor, yet, is any AAPCS64 one.
#[test]
fn variadic_definitions_are_recognised_by_the_abi() {
    let named = |integer| Named {
        integer,
        vector: 0,
        stack: 0,
    };
    let cases = [
        ("variadic-gcc-x86_64.elf", vec![("report", Some(named(2)))]),
        (
            "variadic-clang-x86_64.elf",
            vec![("report", Some(named(2)))],
        ),
        (
            "variadic-x86_64.exe",
            vec![("sum", Some(named(1))), ("report", Some(named(2)))],
        ),
        (
            "variadic-clang-aarch64.elf",
            vec![
                ("sum", Some(named(1))),
                ("report", Some(named(2))),
                ("many", Some(named(7))),
            ],
        ),
    ];
    for (name, expected) in cases {
        let data = fixture(name);
        let image = Image::parse(&data).unwrap();
        let database = Database::new(&image, Seeds::ALL).unwrap();
        let decompile = |function: &str| {
            let id = database.find_function(function).unwrap();
            let options = Options {
                style: Some("kr".to_owned()),
                ..Options::default()
            };
            database.decompile(id, &options).result.unwrap()
        };
        for (function, named) in expected.into_iter().chain([("fixed", None)]) {
            let decompiled = decompile(function);
            let variadic = decompiled.stats.variadic;
            assert_eq!(variadic.recognised, named, "{name}: {function}");
            let printed = function == "report" && !name.contains("aarch64");
            assert_eq!(variadic.printed, printed, "{name}: {function}");
            assert_eq!(decompiled.l2.variadic, printed, "{name}: {function}");
            if printed {
                assert_eq!(decompiled.l2.parameters.len(), 2, "{name}");
                let text = decompiled.c.unwrap().text;
                // The ELF fixtures' `vfprintf` is glibc's, whose declaration
                // names its parameters `__s` and `__format`; the PE
                // fixture's is its own (statically linked), named nothing.
                let (stream, format) = if name == "variadic-x86_64.exe" {
                    ("a1", "a2")
                } else {
                    ("s", "format")
                };
                for line in [
                    format!("{format}, ...)"),
                    "va_list ap;".to_owned(),
                    format!("va_start(ap, {format});"),
                    format!("({stream}, {format}, ap);"),
                ] {
                    assert!(text.contains(&line), "{name}: no {line} in\n{text}");
                }
                assert!(!text.contains("__va_list_tag"), "{name}:\n{text}");
            }
        }
    }
}

/// `report` (`tests/fixtures/variadic.c`, built for AArch64) passes its
/// list on to glibc's `vfprintf` with its format, so its unnamed
/// arguments are the ones that format takes. `vfprintf`'s `va_list` is a
/// 32-byte struct passed by value, which AAPCS64 passes as a pointer to a
/// copy; without that rule `vfprintf`'s declaration did not place and
/// had no format. So `main`'s call passes what `"%s %ld %f\n"` takes,
/// five arguments in all, not every argument register it left as it was.
#[test]
fn an_aapcs64_list_passed_on_takes_its_format() {
    let data = fixture("variadic-clang-aarch64.elf");
    for view in [View::Exact, View::Reading] {
        let c = bare_c_in(&data, "main", view);
        // The call, after the declaration of `report` before the function.
        let start = c.rfind("report(").expect("a call of report") + "report(".len();
        let mut depth = 0;
        let mut arguments = 1;
        for character in c[start..].chars() {
            match character {
                '(' => depth += 1,
                ')' if depth == 0 => break,
                ')' => depth -= 1,
                ',' if depth == 0 => arguments += 1,
                _ => {}
            }
        }
        assert_eq!(arguments, 5, "{view:?}: {c}");
    }
}

/// `lengths` (`tests/fixtures/variadic.c`) reads only pointers from its
/// list, as glibc's `__libc_message_impl`: GCC saves no vector register
/// and leaves `fp_offset` unset, and with the frame pointer it keeps the
/// callee-saved registers just above the integer registers' save area.
/// Those are no vector saves: it is recognised with its two named
/// arguments and takes no parameter for the unnamed registers. Taken
/// for vector saves, they made the save area run past the return
/// address, and the function six parameters.
#[test]
fn a_variadic_definition_saving_no_vector_register_is_recognised() {
    let data = fixture("variadic-gcc-x86_64.elf");
    let image = Image::parse(&data).unwrap();
    let database = Database::new(&image, Seeds::ALL).unwrap();
    let id = database.find_function("lengths").unwrap();
    let decompiled = database.decompile(id, &Options::default()).result.unwrap();
    assert_eq!(
        decompiled.stats.variadic.recognised,
        Some(Named {
            integer: 2,
            vector: 0,
            stack: 0,
        })
    );
    assert_eq!(decompiled.l2.parameters.len(), 2);
    assert!(decompiled.l2.variadic);
}

/// At -O0 (`variadic-gcc-O0-x86_64.elf`) every local lives in the frame
/// beside the register save area and the `va_list`, whose addresses
/// `va_start` stores. Once it is recognised, those reach only their own
/// bytes, so the locals are variables, not fields of a frame struct that
/// every address stored made the whole frame. `sum`'s loop, `while (1) {
/// if (n <= i) break; … }` once the counter's reload is coalesced away,
/// is a `for` (pass `loop-heads`), taking `i = 0` past the total's `= 0`
/// that sinking moved after it.
#[test]
fn locals_beside_a_va_list_are_variables() {
    let data = fixture("variadic-gcc-O0-x86_64.elf");
    for function in ["sum", "report"] {
        let c = bare_c(&data, function);
        assert!(c.contains("va_start(ap,"), "{function}: {c}");
        assert!(!c.contains("frame"), "{function}: {c}");
    }
    let c = bare_c(&data, "sum");
    for expected in ["result+=*", "for(int32_ti=0;i<a1;i++)"] {
        assert!(c.contains(expected), "{expected}: {c}");
    }
}

/// `tests/fixtures/objects.c`. At -O0 `make` keeps its new object's
/// pointer in a frame slot and loads it again for each field: the loads
/// of a slot stored once, before them, are that pointer, so the fields
/// are one struct's. At -O2 `resolve` returns `v->value` only where it
/// is null: that is no object it returns, so the field stays the
/// `char *` `find` compares, not a pointer to the struct.
/// `elements` reads `dims[i]` (`int dims[3]`) in a loop to `rank`, where
/// `rank <= 3` is checked first: the array is a field of three, and the
/// read subscripts it, `i` proved in `0..=2` (the exact view takes the
/// element's address, to check it). `unchecked` reads it to an unchecked
/// `rank`, maybe past the array: the read stays bytes.
/// `describe` reads two fields of the 40-byte `struct var` `made` passes
/// it from `make`: a partial view of that struct, so one type, with no
/// cast where `made` passes it.
#[test]
fn a_spilled_pointer_and_a_null_return_keep_their_objects() {
    let o0 = fixture("objects-gcc-O0-x86_64.elf");
    let c = bare_c_in(&o0, "make", View::Reading);
    for expected in ["result->field_8=s;", "result->field_20=a3;"] {
        assert!(c.contains(expected), "{expected}: {c}");
    }
    let c = bare_c_in(&fixture("objects-gcc-x86_64.elf"), "resolve", View::Reading);
    assert!(c.contains("char*field_8;"), "{c}");
    let c = bare_c_in(&o0, "elements", View::Reading);
    for expected in ["int32_tfield_4[3];", "a1->field_4[i]"] {
        assert!(c.contains(expected), "{expected}: {c}");
    }
    let c = bare_c_in(&o0, "elements", View::Exact);
    assert!(c.contains("=&a1->field_4[i];"), "{c}");
    let c = bare_c_in(&o0, "unchecked", View::Reading);
    assert!(!c.contains("field_4[i]"), "{c}");
    let c = bare_c_in(&o0, "made", View::Reading);
    assert!(c.contains("returndescribe(make(a1,a1,1));"), "{c}");
}

/// A variadic definition that walks its `va_list` in place (the
/// compiler's expansion of `va_arg`: a test of `gp_offset`, an address
/// in the register save area or among the stack arguments, the fields
/// stored again) is recognised by its `va_start` all the same, called
/// as one and printed as one: `sum(int32_t a1, ...)` with `va_start`,
/// then the walk through the list's own fields, which
/// `binbun_va_walk(ap)` makes the compiler fill. Clang reads the fields
/// back from the list; GCC, which never stores `fp_offset` here and
/// keeps the offsets in registers, takes the two pointers from it
/// (`ap_registers`, `ap_stack`). Clang's `main` passes `sum` its count
/// and integer registers but no vector register (`al` is 0 there),
/// `mean(2, 1.5, (double)argc)` the two vector registers `al` counts,
/// and `scaled(0.5, 2, argc, 4)`, whose named `double` takes no integer
/// register, `argc` in `rsi`. None gets the count register.
#[test]
fn a_variadic_definition_walking_its_list_is_called_as_one() {
    let data = fixture("variadic-clang-x86_64.elf");
    let image = Image::parse(&data).unwrap();
    let database = Database::new(&image, Seeds::ALL).unwrap();
    let decompile = |function: &str| {
        let id = database.find_function(function).unwrap();
        database.decompile(id, &Options::default()).result.unwrap()
    };
    let sum = decompile("sum").stats.variadic;
    let named = Named {
        integer: 1,
        vector: 0,
        stack: 0,
    };
    assert_eq!((sum.recognised, sum.printed), (Some(named), true));
    let c = bare_c(&data, "sum");
    for expected in [
        "sum(int32_ta1,...)",
        "va_start(ap,a1);binbun_va_walk(ap);",
        "=ap->gp_offset;",
        "ap->reg_save_area",
    ] {
        assert!(c.contains(expected), "{expected}: {c}");
    }
    let gcc = fixture("variadic-gcc-x86_64.elf");
    let c = bare_c(&gcc, "sum");
    for expected in [
        "sum(int32_ta1,...)",
        "va_start(ap,a1);binbun_va_walk(ap);",
        "ap_registers=(uint8_t*)ap->reg_save_area;",
        "=ap_registers+v6;",
        "+=*ap_stack;",
    ] {
        assert!(c.contains(expected), "{expected}: {c}");
    }
    let l2 = decompile("main").l2;
    let calls: Vec<&Call> = l2
        .stmts
        .iter()
        .filter_map(|stmt| {
            let Stmt::Call { call, .. } = stmt else {
                return None;
            };
            Some(call)
        })
        .chain(&l2.calls)
        .collect();
    // Each call's signature's parameters, and its arguments' widths.
    let call = |function: &str| -> (usize, Vec<u16>) {
        let id = database.find_function(function).unwrap();
        let (_, callee) = database.functions().find(|&(f, _)| f == id).unwrap();
        let call = calls
            .iter()
            .find(|call| call.callee == Callee::Address(callee.entry))
            .unwrap_or_else(|| panic!("main calls no {function}"));
        let signature = l2.types.signature(call.signature).unwrap();
        assert!(signature.variadic, "{function}");
        let widths = call
            .arguments
            .iter()
            .map(|&argument| l2.width(argument).unwrap())
            .collect();
        (signature.parameters.len(), widths)
    };
    let vectors = |widths: &[u16]| widths.iter().filter(|&&width| width == 128).count();
    let (parameters, widths) = call("sum");
    assert_eq!((parameters, vectors(&widths)), (1, 0), "{widths:?}");
    assert!(widths.len() <= 6 && !widths.contains(&8), "{widths:?}");
    let (parameters, widths) = call("mean");
    assert_eq!((parameters, vectors(&widths)), (1, 2), "{widths:?}");
    let (parameters, widths) = call("scaled");
    assert_eq!((parameters, vectors(&widths)), (2, 0), "{widths:?}");
    // The count, the scale, then `rsi` to `r9`: `argc` is not skipped.
    assert_eq!(widths.len(), 7, "{widths:?}");
}

/// A variadic definition that passes its own format parameter, untouched,
/// and its `va_list`, used once, to a `v` function (`report`, to
/// `vfprintf`: GCC's `-Wsuggest-attribute=format` case) takes that format:
/// at `main`'s call the arguments past it are typed by the format string
/// passed. One that changes the format first (`skipped` passes `format +
/// 1`) or passes its `va_list` to two calls (`twice`) takes none, so its
/// call's arguments are untyped; both are variadic definitions printed as
/// C's.
#[test]
fn a_variadic_wrapper_takes_the_format_it_passes_on_unchanged() {
    for name in ["variadic-gcc-x86_64.elf", "variadic-clang-x86_64.elf"] {
        let data = fixture(name);
        let image = Image::parse(&data).unwrap();
        let database = Database::new(&image, Seeds::ALL).unwrap();
        let main = database.find_function("main").unwrap();
        let l2 = database
            .decompile(main, &Options::default())
            .result
            .unwrap()
            .l2;
        let calls: Vec<&Call> = l2
            .stmts
            .iter()
            .filter_map(|stmt| {
                let Stmt::Call { call, .. } = stmt else {
                    return None;
                };
                Some(call)
            })
            .chain(&l2.calls)
            .collect();
        let variadic = |function: &str| -> Vec<&Type> {
            let id = database.find_function(function).unwrap();
            let (_, callee) = database.functions().find(|&(f, _)| f == id).unwrap();
            let call = calls
                .iter()
                .find(|call| call.callee == Callee::Address(callee.entry))
                .unwrap_or_else(|| panic!("{name}: main calls no {function}"));
            call.variadic
                .iter()
                .map(|&ty| l2.types.get(ty).unwrap())
                .collect()
        };
        // report(stdout, "%s %ld %f\n", argv[0], total + …, average)
        let report = variadic("report");
        assert!(
            matches!(
                report.as_slice(),
                [Type::Pointer(Some(_)), Type::Int(64), Type::Float(_)]
            ),
            "{name}: {report:?}"
        );
        for function in ["skipped", "twice"] {
            let id = database.find_function(function).unwrap();
            let decompiled = database.decompile(id, &Options::default()).result;
            assert!(decompiled.unwrap().l2.variadic, "{name}: {function}");
            assert_eq!(
                variadic(function),
                Vec::<&Type>::new(),
                "{name}: {function}"
            );
        }
    }
}

/// A declared parameter of array type is a pointer to its element (C11
/// 6.7.6.3p7): System V's `vfprintf` takes its `va_list` (through
/// typedefs, `struct __va_list_tag[1]`) as a pointer to the 24-byte tag,
/// which is the type `report`'s own `va_list` is an array of. So `report`
/// declares `vfprintf` with a `va_list` parameter, passes `ap` on with no
/// cast, and compiles with no error or warning under GCC and Clang.
#[test]
fn a_va_list_parameter_decays_to_the_tag_report_passes_on() {
    for name in ["variadic-gcc-x86_64.elf", "variadic-clang-x86_64.elf"] {
        let data = fixture(name);
        let image = Image::parse(&data).unwrap();
        let database = Database::new(&image, Seeds::ALL).unwrap();
        let slot = image
            .imports
            .iter()
            .find(|import| import.name == "vfprintf")
            .unwrap()
            .slot;
        let mut types = Types::new(64);
        let prototype = database.prototypes().through(slot, &mut types).unwrap();
        let signature = types.signature(prototype.signature).unwrap();
        let &Type::Pointer(Some(tag)) = types.get(signature.parameters[2]).unwrap() else {
            panic!("{name}: vfprintf's va_list is no pointer");
        };
        let Type::Struct(aggregate) = types.get(tag).unwrap() else {
            panic!("{name}: vfprintf's va_list points to no struct");
        };
        assert_eq!(
            (aggregate.name.as_deref(), aggregate.size),
            (Some("__va_list_tag"), 24),
            "{name}"
        );

        let id = database.find_function("report").unwrap();
        let options = Options {
            style: Some("kr".to_owned()),
            ..Options::default()
        };
        let decompiled = database.decompile(id, &options).result.unwrap();
        let text = decompiled.c.unwrap().text;
        for line in [
            "vfprintf(struct _IO_FILE *, char *, va_list);",
            "(s, format, ap);",
        ] {
            assert!(text.contains(line), "{name}: no {line} in\n{text}");
        }
        if cfg!(windows) {
            // Compiled on LP64 hosts (Linux, macOS): System V's va_list.
            continue;
        }
        let directory = std::env::home_dir()
            .unwrap()
            .join(".cache/binbun-print-check")
            .join(format!("va-list-{}-{name}", std::process::id()));
        fs::create_dir_all(&directory).unwrap();
        fs::write(directory.join("binbun_defs.h"), binbun_print::c::HEADER).unwrap();
        fs::write(directory.join("report.c"), &text).unwrap();
        for compiler in ["gcc", "clang"] {
            let output = Command::new(compiler)
                .current_dir(&directory)
                .args([
                    "-std=c11",
                    "-fwrapv",
                    "-fno-strict-aliasing",
                    "-Wall",
                    "-Wextra",
                ])
                .args(["-c", "report.c", "-o", "report.o"])
                .output();
            let Ok(output) = output else {
                continue;
            };
            let diagnostics = String::from_utf8_lossy(&output.stderr);
            assert!(
                output.status.success() && diagnostics.is_empty(),
                "{name}: {compiler}:\n{diagnostics}\n{text}"
            );
        }
        fs::remove_dir_all(&directory).unwrap();
    }
}

/// The same on an evenly spread sample of the functions of the system's
/// libc and bash: `BINBUN_SAMPLE` of each (300 by default; `all`).
/// Prints how many were compared, how many sit where the whole program
/// breaks a cycle of calls, and how long they took alone (`--nocapture`;
/// [`threads`] of them at once).
#[test]
#[ignore = "decompiles all of libc and bash, then a sample one by one"]
fn system_functions_decompile_as_in_the_whole_program() {
    let sample = match std::env::var("BINBUN_SAMPLE").as_deref() {
        Ok("all") => usize::MAX,
        Ok(count) => count.parse().unwrap(),
        Err(_) => 300,
    };
    for path in ["/usr/lib/libc.so.6", "/usr/bin/bash"] {
        if !Path::new(path).exists() {
            continue;
        }
        let alone = alone_as_in_the_whole_program(path, sample);
        let mut times = alone.times.clone();
        times.sort_unstable();
        let at = |share: usize| times[(times.len() - 1) * share / 100];
        eprintln!(
            "{path}: {} compared ({} decompiled, {} where a cycle is broken), {} differ; \
             alone: median {:?}, 90% {:?}, max {:?}, total {:?}",
            alone.compared,
            alone.decompiled,
            alone.cyclic,
            alone.differ.len(),
            at(50),
            at(90),
            at(100),
            times.iter().sum::<Duration>(),
        );
        assert_eq!(alone.differ, Vec::<u64>::new(), "{path}");
    }
}

/// What [`alone_as_in_the_whole_program`] found.
struct Alone {
    /// Functions compared.
    compared: usize,
    /// Of those, the ones that decompiled.
    decompiled: usize,
    /// Of those compared, the ones that call a function the whole
    /// program's order puts after them (or themselves): where it breaks a
    /// cycle of calls.
    cyclic: usize,
    /// The entries of those whose output alone differs.
    differ: Vec<u64>,
    /// How long each took alone ([`threads`] of them decompiled at once).
    times: Vec<Duration>,
}

/// Compares, for at most `sample` functions of the image at `path` (spread
/// evenly by address), each decompiled alone with what the whole
/// program's stream gives for it.
fn alone_as_in_the_whole_program(path: &str, sample: usize) -> Alone {
    let data = fs::read(path).unwrap();
    let image = Image::parse(&data).unwrap();
    let database = Database::new(&image, Seeds::ALL).unwrap();
    let options = Options {
        style: Some("kr".to_owned()),
        ..Options::default()
    };
    let mut functions: Vec<(u64, FunctionId)> = database
        .functions()
        .map(|(id, function)| (function.entry, id))
        .collect();
    functions.sort_unstable();
    let count = functions.len().min(sample);
    let sampled: BTreeSet<FunctionId> = (0..count)
        .map(|k| functions[k * functions.len() / count].1)
        .collect();
    let mut whole: BTreeMap<FunctionId, Output> = BTreeMap::new();
    database.decompile_all(
        &options,
        |output| sampled.contains(&output.id).then_some(output),
        |output| {
            if let Some(output) = output {
                whole.insert(output.id, output);
            }
        },
    );
    assert_eq!(whole.len(), sampled.len(), "{path}");
    let order = callees_first(database.program());
    let position: BTreeMap<FunctionId, usize> =
        order.iter().enumerate().map(|(at, &id)| (id, at)).collect();
    let mut alone = Alone {
        compared: whole.len(),
        decompiled: whole
            .values()
            .filter(|output| output.result.is_ok())
            .count(),
        cyclic: 0,
        differ: Vec::new(),
        times: Vec::new(),
    };
    for &id in whole.keys() {
        let at = position[&id];
        alone.cyclic += usize::from(
            calls(database.program(), id)
                .iter()
                .any(|callee| position[callee] >= at),
        );
    }
    // Each alone, on as many threads as the whole program.
    let whole: Vec<&Output> = whole.values().collect();
    let next = AtomicUsize::new(0);
    let mut timed: Vec<(usize, Duration, bool)> = thread::scope(|scope| {
        let workers: Vec<_> = (0..threads())
            .map(|_| {
                scope.spawn(|| {
                    let mut timed = Vec::new();
                    loop {
                        let at = next.fetch_add(1, Ordering::Relaxed);
                        let Some(&output) = whole.get(at) else {
                            return timed;
                        };
                        let start = Instant::now();
                        let one = database.decompile(output.id, &options);
                        timed.push((at, start.elapsed(), &one == output));
                    }
                })
            })
            .collect();
        workers
            .into_iter()
            .flat_map(|worker| worker.join().unwrap())
            .collect()
    });
    timed.sort_unstable_by_key(|&(at, ..)| at);
    for (at, time, same) in timed {
        alone.times.push(time);
        if !same {
            alone.differ.push(whole[at].entry);
        }
    }
    alone
}
