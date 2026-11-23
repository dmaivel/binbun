#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers fail loudly"
)]

//! C++ exception handling as the source has it: the fixtures' functions
//! (`tests/fixtures/handlers.cpp`, built by GCC and Clang, and
//! `exceptions.cpp`) decompile to `Try`s with the source's catch types in
//! order, cleanups and nesting, the same structure as L1, and C that
//! declares each callee and type once; and structured exception handling
//! (`seh.c`, built by MSVC) to `Try`s with the source's `__except`s.

use std::collections::BTreeSet;
use std::fmt::Write;

use binbun::Database;
use binbun::analysis::Seeds;
use binbun::decompile::{Decompiled, Options};
use binbun_ast::ir::{Block, CatchType, Function as Ast, HandlerKind, SehFilter, Stmt};
use binbun_ast::types::Type;
use binbun_loader::Image;

fn fixture(name: &str) -> Vec<u8> {
    let path = format!("{}/../../tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

/// Every function of fixture `name` named in `functions`, decompiled to C.
fn decompile(name: &str, functions: &[&str]) -> Vec<(String, Decompiled)> {
    let data = fixture(name);
    let image = Image::parse(&data).unwrap();
    let database = Database::new(&image, Seeds::ALL).unwrap();
    let options = Options {
        style: Some("kr".to_owned()),
        ..Options::default()
    };
    functions
        .iter()
        .map(|&function| {
            let id = database.find_function(function).unwrap();
            let output = database.decompile(id, &options);
            let decompiled = output
                .result
                .unwrap_or_else(|e| panic!("{name} {function}: {e}"));
            (function.to_owned(), decompiled)
        })
        .collect()
}

fn catch_type(ty: &CatchType) -> String {
    ty.name
        .clone()
        .or_else(|| ty.symbol.clone())
        .unwrap_or_else(|| "?".to_owned())
}

/// The `Try`s of `block` and the loops around them, the rest left out:
/// `try{body}catch(T){handler}...`, `loop{...}`.
fn shape(f: &Ast, block: &Block) -> String {
    let mut out = String::new();
    for stmt in block.iter().filter_map(|&id| f.stmt(id)) {
        match stmt {
            Stmt::Try { body, handlers } => {
                let _ = write!(out, "try{{{}}}", shape(f, body));
                for handler in handlers {
                    let head = match &handler.kind {
                        HandlerKind::Landing(_) => "landing".to_owned(),
                        HandlerKind::Catch(ty) => format!("catch({})", catch_type(ty)),
                        HandlerKind::CatchAll => "catch(...)".to_owned(),
                        HandlerKind::Cleanup => "cleanup".to_owned(),
                        HandlerKind::Unexpected(types) => {
                            let names: Vec<String> = types.iter().map(catch_type).collect();
                            format!("unexpected({})", names.join(","))
                        }
                        HandlerKind::Except(SehFilter::Constant(value)) => {
                            format!("except({value})")
                        }
                        HandlerKind::Except(SehFilter::Funclet(funclet)) => {
                            format!("except({funclet:#x})")
                        }
                        HandlerKind::Finally => "finally".to_owned(),
                    };
                    let _ = write!(out, "{head}{{{}}}", shape(f, &handler.body));
                }
            }
            Stmt::While { .. } | Stmt::DoWhile { .. } | Stmt::For { .. } => {
                let inner: String = stmt.blocks().map(|block| shape(f, block)).collect();
                if !inner.is_empty() {
                    let _ = write!(out, "loop{{{inner}}}");
                }
            }
            Stmt::If { .. }
            | Stmt::Switch { .. }
            | Stmt::VaStart { .. }
            | Stmt::Assign { .. }
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
            | Stmt::Escape { .. } => out.extend(stmt.blocks().map(|block| shape(f, block))),
        }
    }
    out
}

/// What the functions of `handlers.cpp` are in the source, by name, as
/// GCC and as Clang compile them (`None`: a gap, checked apart). A
/// handler's call that may throw runs while the handler holds the
/// exception: unwinding out of it ends the catch (`__cxa_end_catch`, a
/// cleanup) and goes on. Clang finds that `note` (which calls only the
/// `noexcept` `puts`) never throws, so its handlers call it unguarded.
const HANDLERS: [(&str, Option<&str>, Option<&str>); 7] = [
    (
        "by_type",
        Some("try{}catch(Error){}"),
        Some("try{}catch(Error){}"),
    ),
    (
        "several",
        Some("try{}catch(Error){}catch(std::exception){try{}cleanup{}}catch(int){}"),
        Some("try{}catch(Error){}catch(std::exception){}catch(int){}"),
    ),
    ("any", Some("try{}catch(...){}"), Some("try{}catch(...){}")),
    // Clang shares the resume of the pad's "no clause matched" path with
    // the rethrow's cleanup, and ends the catch there under a catch-all
    // that terminates (`__cxa_end_catch` must not throw while unwinding).
    (
        "rethrow",
        Some("try{}catch(Error){try{}cleanup{}}"),
        Some("try{}catch(Error){try{}cleanup{try{}catch(...){}}}"),
    ),
    // GCC leaves the inner handler's `__cxa_end_catch` unguarded (it
    // unwinds out of the function, not to the outer handler), so its inner
    // handler stays out of the outer try.
    (
        "nested",
        None,
        Some("try{try{}catch(Error){}}catch(std::exception){}"),
    ),
    // The guard's destructor.
    ("cleanup", Some("try{}cleanup{}"), Some("try{}cleanup{}")),
    (
        "loop",
        Some("loop{try{}catch(Error){}}"),
        Some("loop{try{}catch(Error){}}"),
    ),
];

/// Checks `decompiled` (of `function` in `fixture`): the structure check
/// passed, and it compiles.
fn check_clean(fixture: &str, function: &str, decompiled: &Decompiled) {
    assert_eq!(
        decompiled.stats.structure, None,
        "{fixture} {function}: structure"
    );
    let c = decompiled.c.as_ref().unwrap();
    assert!(
        !c.text.contains("binbun_foreign_jump"),
        "{fixture} {function}:\n{}",
        c.text
    );
}

#[test]
fn handlers_read_as_the_source() {
    let mut wrong = Vec::new();
    for (index, compiler) in ["gcc", "clang"].into_iter().enumerate() {
        let name = format!("handlers-{compiler}-x86_64.elf");
        let functions: Vec<&str> = HANDLERS.iter().map(|&(function, ..)| function).collect();
        for ((function, decompiled), &(_, gcc, clang)) in
            decompile(&name, &functions).into_iter().zip(&HANDLERS)
        {
            check_clean(&name, &function, &decompiled);
            let l2 = &decompiled.l2;
            let got = shape(l2, &l2.body);
            let Some(want) = [gcc, clang][index] else {
                continue;
            };
            if got != want {
                wrong.push(format!("{name} {function}: {got}, not {want}"));
            }
        }
    }
    assert!(wrong.is_empty(), "{wrong:#?}");
}

/// `seh.c`'s `__try`s (by address: the PDB's `filtered`, `nested`,
/// `main`, `finally`): `filtered`'s filter expression is its funclet
/// `filtered$filt$0`; `nested`'s `__finally` (its funclet built in, on
/// the exception's way out) resumes into its `__except`, which its own
/// call (`note`, outside every scope's range: it unwinds out of the
/// function) keeps from nesting inside it; `main`
/// prints the code its handlers take (`GetExceptionCode()`); `finally`'s
/// termination handler reads `AbnormalTermination()` and the frame's
/// `result`.
#[test]
fn excepts_read_as_the_source() {
    let name = "seh-x86_64.exe";
    let want = [
        ("0x140001080", "try{}except(0x1400026f0){}"),
        (
            "0x1400011f0",
            "try{}finally{try{}except(1){}}try{}except(1){}",
        ),
        ("0x1400010f0", "try{}except(1){}try{}except(1){}"),
        ("0x1400010b0", "try{}finally{}"),
    ];
    let functions: Vec<&str> = want.iter().map(|&(function, _)| function).collect();
    for ((function, decompiled), (_, want)) in decompile(name, &functions).into_iter().zip(want) {
        check_clean(name, &function, &decompiled);
        let l2 = &decompiled.l2;
        assert_eq!(shape(l2, &l2.body), want, "{function}");
        let c = &decompiled.c.as_ref().unwrap().text;
        assert!(c.contains("BINBUN_SEH_TRY"), "{c}");
        if function == "0x1400010f0" {
            assert_eq!(c.matches("binbun_exception_code()").count(), 2, "{c}");
        }
        if function == "0x1400010b0" {
            assert!(c.contains("BINBUN_FINALLY"), "{c}");
            assert!(c.contains("binbun_abnormal_termination()"), "{c}");
        }
    }
}

/// `eh.cpp`'s try blocks, as `__CxxFrameHandler4` (`eh-x86_64.exe`) and
/// `__CxxFrameHandler3` (`eh-fh3-x86_64.exe`) tables say (by address:
/// the PDBs' `by_type`, `several`, `any`, `rethrow`, `loop`, `cleanup`):
/// the catch blocks' funclets built in as the `Try`s' handlers, in the
/// source's order, the same both ways; `cleanup`'s guard destructor is an
/// unwind funclet under v3 only (v4 calls the destructor itself).
#[test]
fn catches_read_as_the_source() {
    let shapes = [
        "try{}catch(Error){}",
        "try{}catch(Error){}catch(std::exception){}catch(int){}",
        "try{}catch(...){}",
        "try{}catch(Error){}",
        "loop{try{}catch(Error){}}",
    ];
    for (name, functions, cleanup) in [
        (
            "eh-x86_64.exe",
            [
                "0x1400012a0",
                "0x140001550",
                "0x140001280",
                "0x140001540",
                "0x140001310",
            ],
            ("0x1400012c0", ""),
        ),
        (
            "eh-fh3-x86_64.exe",
            [
                "0x1400012f0",
                "0x1400015e0",
                "0x1400012d0",
                "0x1400015c0",
                "0x140001360",
            ],
            ("0x140001310", "try{}cleanup{}"),
        ),
    ] {
        let mut all: Vec<&str> = functions.to_vec();
        all.push(cleanup.0);
        let want = shapes.iter().copied().chain([cleanup.1]);
        for ((function, decompiled), want) in decompile(name, &all).into_iter().zip(want) {
            check_clean(name, &function, &decompiled);
            let l2 = &decompiled.l2;
            assert_eq!(shape(l2, &l2.body), want, "{name} {function}");
        }
    }
}

/// The funclets built into their functions are not decompiled on their
/// own (`seh.c`'s termination handlers, `eh.cpp`'s catch blocks), a
/// filter is (`filtered$filt$0`: its expression is not built in).
#[test]
fn built_in_funclets_are_not_functions_of_their_own() {
    for (name, built_in, apart) in [
        (
            "seh-x86_64.exe",
            &[0x1_4000_2720, 0x1_4000_2760][..],
            0x1_4000_26f0,
        ),
        (
            "eh-x86_64.exe",
            &[0x1_4000_2c90, 0x1_4000_2cc0, 0x1_4000_2d00][..],
            0x1_4000_1550,
        ),
    ] {
        let data = fixture(name);
        let image = Image::parse(&data).unwrap();
        let database = Database::new(&image, Seeds::ALL).unwrap();
        let options = Options {
            style: None,
            ..Options::default()
        };
        let mut entries = BTreeSet::new();
        database.decompile_all_on(
            &options,
            1,
            |output| output.entry,
            |entry| {
                entries.insert(entry);
            },
        );
        for &funclet in built_in {
            assert!(!entries.contains(&funclet), "{name} {funclet:#x}");
        }
        assert!(entries.contains(&apart), "{name} {apart:#x}");
    }
}

/// Funclets are joined to their functions (by the PDBs: `filtered$filt$0`,
/// `nested$fin$0`; `several$catch$0` to `$2`, `cleanup$dtor$0`'s v3 twin).
#[test]
fn funclets_are_joined_to_their_functions() {
    for (name, function, funclets) in [
        ("seh-x86_64.exe", 0x1_4000_1080, &[0x1_4000_26f0][..]),
        ("seh-x86_64.exe", 0x1_4000_11f0, &[0x1_4000_2760][..]),
        (
            "eh-x86_64.exe",
            0x1_4000_1550,
            &[0x1_4000_2c90, 0x1_4000_2cc0, 0x1_4000_2d00][..],
        ),
        ("eh-fh3-x86_64.exe", 0x1_4000_1310, &[0x1_4000_2ba0][..]),
    ] {
        let data = fixture(name);
        let image = Image::parse(&data).unwrap();
        let database = Database::new(&image, Seeds::ALL).unwrap();
        let owner = database
            .function(database.function_at(function).unwrap())
            .unwrap();
        assert_eq!(owner.funclets, funclets, "{name} {function:#x}");
        for &funclet in funclets {
            let part = database
                .function(database.function_at(funclet).unwrap())
                .unwrap();
            assert_eq!(part.part_of, Some(function), "{name} {funclet:#x}");
        }
    }
}

/// `exceptions.cpp`'s `guarded`: a catch of `std::exception` whose
/// handler's call is guarded by the end of the catch; C++ propagates
/// implicitly, so no `_Unwind_Resume` is left.
#[test]
fn guarded_catches_std_exception() {
    let name = "exceptions-x86_64.elf";
    for (function, decompiled) in decompile(name, &["_Z7guardedi"]) {
        check_clean(name, &function, &decompiled);
        let l2 = &decompiled.l2;
        assert_eq!(
            shape(l2, &l2.body),
            "try{}catch(std::exception){try{}cleanup{}}"
        );
        let text = &decompiled.c.as_ref().unwrap().text;
        assert!(text.contains("BINBUN_CATCH(std::exception)"), "{text}");
        assert!(!text.contains("_Unwind_Resume"), "{text}");
    }
}

/// Every callee is declared once (one prototype per address, whatever
/// its calls pass: a handler's call to `__cxa_end_catch` has fewer
/// argument registers set than the one after the `Try`) and every named
/// type is one type (the prototypes of two calls to `_Unwind_Resume`
/// share `struct _Unwind_Exception`).
#[test]
fn each_callee_and_type_is_declared_once() {
    let mut checked = 0;
    for (name, functions) in [
        ("exceptions-x86_64.elf", &["_Z7guardedi", "main"][..]),
        (
            "handlers-gcc-x86_64.elf",
            &["several", "rethrow", "nested", "cleanup", "loop"][..],
        ),
        (
            "handlers-clang-x86_64.elf",
            &["several", "rethrow", "nested", "cleanup", "loop"][..],
        ),
    ] {
        for (function, decompiled) in decompile(name, functions) {
            let text = &decompiled.c.as_ref().unwrap().text;
            let mut addresses = BTreeSet::new();
            for line in text.lines().filter(|line| line.contains("); /* 0x")) {
                let address = line.split("/* ").nth(1).unwrap().split(' ').next().unwrap();
                assert!(
                    addresses.insert(address.to_owned()),
                    "{name} {function}: {address} declared twice:\n{text}"
                );
                checked += 1;
            }
            let mut names = BTreeSet::new();
            for (_, ty) in decompiled.l2.types.iter() {
                if let Type::Struct(aggregate) | Type::Union(aggregate) = ty
                    && let Some(tag) = &aggregate.name
                {
                    assert!(names.insert(tag.clone()), "{name} {function}: two {tag}");
                }
            }
        }
    }
    assert!(checked > 20, "only {checked} declarations");
}
