//! Reading Microsoft x64 exception handling data from the MSVC fixtures
//! (`seh.c`, `eh.cpp`, built by `scripts/build-fixtures.sh`), checked
//! against their PDBs (functions and funclets by `llvm-pdbutil dump
//! --symbols --modi=0`) and the sources' handlers.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers fail loudly"
)]

use binbun_loader::{
    CxxTable, CxxVersion, Funclet, FuncletKind, HandlerTable, Image, Scope, ScopeAction, SehFilter,
};

fn fixture(name: &str) -> Vec<u8> {
    let path = format!("{}/../../tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

fn scopes<'a>(image: &'a Image<'_>, function: u64) -> &'a [Scope] {
    let table = image
        .frame_handlers
        .iter()
        .find(|table| table.function == function)
        .unwrap_or_else(|| panic!("no handler data at {function:#x}"));
    assert_eq!(
        table.handler.symbol.as_deref(),
        Some("__C_specific_handler")
    );
    match &table.table {
        HandlerTable::Scopes(scopes) => scopes,
        HandlerTable::Cxx(_) => panic!("{function:#x}: C++ data"),
    }
}

fn cxx<'a>(image: &'a Image<'_>, function: u64) -> &'a CxxTable {
    let table = image
        .frame_handlers
        .iter()
        .find(|table| table.function == function)
        .unwrap_or_else(|| panic!("no handler data at {function:#x}"));
    match &table.table {
        HandlerTable::Cxx(cxx) => cxx,
        HandlerTable::Scopes(_) => panic!("{function:#x}: scopes"),
    }
}

#[test]
fn reads_scope_tables_and_their_funclets() {
    let data = fixture("seh-x86_64.exe");
    let image = Image::parse(&data).unwrap();
    // The PDB's functions: any, filtered, finally, nested.
    let (any, filtered, finally, nested) =
        (0x1_4000_1050, 0x1_4000_1080, 0x1_4000_10b0, 0x1_4000_11f0);
    let except = |start, end, filter, target| Scope {
        start,
        end,
        action: ScopeAction::Except { filter, target },
    };
    // EXCEPTION_EXECUTE_HANDLER is the constant 1; the fault's write is
    // guarded, as is the call.
    assert_eq!(
        scopes(&image, any),
        [except(
            any,
            0x1_4000_106b,
            SehFilter::Constant(1),
            0x1_4000_1072
        )]
    );
    // The filter expression is the funclet `filtered$filt$0`.
    assert_eq!(
        scopes(&image, filtered),
        [except(
            0x1_4000_1084,
            0x1_4000_1093,
            SehFilter::Funclet(0x1_4000_26f0),
            0x1_4000_109e
        )]
    );
    // `finally$fin$0`.
    assert_eq!(
        scopes(&image, finally),
        [Scope {
            start: 0x1_4000_10bc,
            end: 0x1_4000_10c9,
            action: ScopeAction::Finally(0x1_4000_2720),
        }]
    );
    // Innermost first: the __finally (`nested$fin$0`) inside the __except.
    let nested_scopes = scopes(&image, nested);
    assert_eq!(nested_scopes.len(), 2);
    assert_eq!(nested_scopes[0].action, ScopeAction::Finally(0x1_4000_2760));
    assert_eq!(
        nested_scopes[1].action,
        ScopeAction::Except {
            filter: SehFilter::Constant(1),
            target: 0x1_4000_1212
        }
    );
    assert!(nested_scopes[1].start <= nested_scopes[0].start);
    assert!(nested_scopes[0].end <= nested_scopes[1].end);
    // The funclets belong to their functions.
    for funclet in [
        Funclet {
            function: filtered,
            address: 0x1_4000_26f0,
            kind: FuncletKind::Filter,
        },
        Funclet {
            function: finally,
            address: 0x1_4000_2720,
            kind: FuncletKind::Finally,
        },
        Funclet {
            function: nested,
            address: 0x1_4000_2760,
            kind: FuncletKind::Finally,
        },
    ] {
        assert!(image.funclets.contains(&funclet), "{funclet:x?}");
    }
    assert!(image.warnings.is_empty(), "{:?}", image.warnings);
}

/// The functions of `eh.cpp` in a build: `any`, `several`, `nested`,
/// `cleanup`, `Guard::~Guard` (by its PDB).
struct Build {
    name: &'static str,
    version: CxxVersion,
    any: u64,
    several: u64,
    nested: u64,
    cleanup: u64,
}

#[test]
fn reads_cxx_tables_of_both_encodings() {
    let builds = [
        Build {
            name: "eh-x86_64.exe",
            version: CxxVersion::V4,
            any: 0x1_4000_1280,
            several: 0x1_4000_1550,
            nested: 0x1_4000_14a0,
            cleanup: 0x1_4000_12c0,
        },
        Build {
            name: "eh-fh3-x86_64.exe",
            version: CxxVersion::V3,
            any: 0x1_4000_12d0,
            several: 0x1_4000_15e0,
            nested: 0x1_4000_1510,
            cleanup: 0x1_4000_1310,
        },
    ];
    for build in builds {
        let data = fixture(build.name);
        let image = Image::parse(&data).unwrap();
        assert!(
            image.warnings.is_empty(),
            "{}: {:?}",
            build.name,
            image.warnings
        );
        // catch (...): no type, adjective 0x40.
        let any = cxx(&image, build.any);
        assert_eq!(any.version, build.version);
        assert_eq!(any.tries.len(), 1);
        assert_eq!(any.tries[0].catches.len(), 1);
        assert_eq!(any.tries[0].catches[0].ty, None);
        assert_eq!(any.tries[0].catches[0].adjectives & 0x40, 0x40);
        // Three catches, in the source's order, by their types.
        let several = cxx(&image, build.several);
        let catches = &several.tries[0].catches;
        let names: Vec<_> = catches
            .iter()
            .map(|catch| catch.ty.as_ref().and_then(|ty| ty.name.as_deref()))
            .collect();
        assert_eq!(
            names,
            [Some("Error"), Some("std::exception"), Some("int")],
            "{}",
            build.name
        );
        assert_eq!(
            catches[0].ty.as_ref().unwrap().object.symbol.as_deref(),
            Some("??_R0?AUError@@@8")
        );
        for catch in catches {
            let funclet = Funclet {
                function: build.several,
                address: catch.funclet,
                kind: FuncletKind::Catch,
            };
            assert!(
                image.funclets.contains(&funclet),
                "{}: {funclet:x?}",
                build.name
            );
        }
        // The inner try (states 1..1) first, inside the outer (0..2): the
        // inner one's states unwind to the outer's.
        let nested = cxx(&image, build.nested);
        let ranges: Vec<_> = nested
            .tries
            .iter()
            .map(|block| (block.low, block.high, block.catch_high))
            .collect();
        assert_eq!(ranges, [(1, 1, 2), (0, 2, 3)], "{}", build.name);
        let next: Vec<_> = nested.unwind.iter().map(|state| state.next).collect();
        assert_eq!(next, [-1, 0, 0, -1], "{}", build.name);
        // The guard's destructor: an unwind funclet (v3), or `~Guard`
        // itself with the guard's frame offset (v4).
        let cleanup = cxx(&image, build.cleanup);
        assert_eq!(cleanup.unwind.len(), 1);
        match build.version {
            CxxVersion::V3 => {
                let action = cleanup.unwind[0].action.unwrap();
                assert!(image.funclets.contains(&Funclet {
                    function: build.cleanup,
                    address: action,
                    kind: FuncletKind::Unwind
                }));
            }
            CxxVersion::V4 => {
                let destructor = cleanup.unwind[0].destructor.unwrap();
                assert_eq!(destructor.function, 0x1_4000_1120, "Guard::~Guard");
                assert_eq!((destructor.object, destructor.indirect), (0x38, false));
            }
        }
    }
}

#[test]
fn catch_continuations_are_in_their_function() {
    // __CxxFrameHandler4 states where `several`'s catches return to.
    let data = fixture("eh-x86_64.exe");
    let image = Image::parse(&data).unwrap();
    let several = 0x1_4000_1550;
    let table = cxx(&image, several);
    let continuations: Vec<u64> = table.tries[0]
        .catches
        .iter()
        .flat_map(|catch| catch.continuations.iter().copied())
        .collect();
    assert_eq!(continuations.len(), 3);
    for address in continuations {
        // In `several`'s own code (40 bytes in the PDB).
        assert!((several..several + 40).contains(&address), "{address:#x}");
    }
}
