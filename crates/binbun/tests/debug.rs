#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers fail loudly"
)]

//! Debug information as input ([`binbun::debug`]): a function's
//! parameters, frame variables and the structs they reach take their
//! debug names and types; a debug prototype the convention would not
//! place as stated is ignored.

use std::fs;
use std::path::{Path, PathBuf};

use binbun::Database;
use binbun::analysis::Seeds;
use binbun::decompile::{Decompiled, Options};
use binbun_ast::ir::{Function as Ast, NameOrigin, VarKind};
use binbun_ast::types::{Evidence, Type};
use binbun_debuginfo::info::DebugModel;
use binbun_debuginfo::info::model::{
    Encoding, Function, Place, Span, Type as DebugType, TypeId, Variable,
};
use binbun_decompile::mapping::{Piece, Source};
use binbun_decompile::prototype::Unplaced;
use binbun_loader::Image;
use binbun_x86_lift::registers::X86;

fn fixture(name: &str) -> Vec<u8> {
    let path = format!("{}/../../tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

/// Function `name` of `database` decompiled (L2 only).
fn decompiled(database: &Database<'_>, name: &str) -> Decompiled {
    let id = database.find_function(name).unwrap();
    let options = Options {
        style: None,
        ..Options::default()
    };
    database.decompile(id, &options).result.unwrap()
}

/// The names and types of `l2`'s parameters.
fn parameters(l2: &Ast) -> Vec<(Option<String>, Option<Type>)> {
    l2.parameters
        .iter()
        .map(|&var| {
            let variable = l2.var(var).unwrap();
            let name = variable
                .name
                .as_ref()
                .filter(|name| name.origin == NameOrigin::Debug)
                .map(|name| name.text.clone());
            (name, l2.types.get(variable.ty).cloned())
        })
        .collect()
}

/// MSVC's `five(int a, int b, int c, int d, int e)`: four parameters in
/// registers and the fifth on the stack past the home space, as the PDB
/// states them; the PE has no symbols, so the function is found by its
/// debug name.
#[test]
fn a_pdb_prototype_names_and_types_the_parameters_in_registers_and_on_the_stack() {
    let data = fixture("msvc-x86_64.exe");
    let model = binbun_debuginfo::info::read(&fixture("msvc-x86_64.pdb"), &data).unwrap();
    let image = Image::parse(&data).unwrap();
    assert!(image.symbols.iter().all(|symbol| symbol.name != "five"));
    let database = Database::with_debug(&image, Seeds::ALL, Some(model)).unwrap();
    let five = decompiled(&database, "five");
    let int = Some(Type::Int(32));
    assert_eq!(
        parameters(&five.l2),
        ["a", "b", "c", "d", "e"]
            .map(|name| (Some(name.to_owned()), int.clone()))
            .to_vec()
    );
    assert_eq!(five.stats.debug.unplaced, None);
    assert_eq!(five.stats.debug.parameters_named, 5);
}

/// The image at `image` and its PDB at `pdb`; `None` where either is
/// absent.
fn with_pdb(image: &Path, pdb: &Path) -> Option<(Vec<u8>, Vec<u8>)> {
    if let (Ok(image), Ok(pdb)) = (fs::read(image), fs::read(pdb)) {
        Some((image, pdb))
    } else {
        eprintln!("skipped: no {} or {}", image.display(), pdb.display());
        None
    }
}

/// `~/.cache/binbun-truth-data/pdb`, where downloaded PDBs are kept.
fn pdbs() -> Option<PathBuf> {
    Some(std::env::home_dir()?.join(".cache/binbun-truth-data/pdb"))
}

/// Windows on ARM64: Python 3.15.2's `select.pyd` for ARM64 (from the
/// AArch64 corpus, `$BINBUN_ARM64_CORPUS`, else
/// `~/.cache/binbun-arm64/corpus`) with its PDB (python.org's
/// `3.15.2/arm64/lib_pdb.msi`, in [`pdbs`]`/python-3.15.2-arm64`).
fn arm64_select() -> Option<(Vec<u8>, Vec<u8>)> {
    let home = std::env::home_dir()?;
    let corpus = std::env::var_os("BINBUN_ARM64_CORPUS")
        .map_or_else(|| home.join(".cache/binbun-arm64/corpus"), Into::into);
    with_pdb(
        &corpus.join("pe/python/select.pyd"),
        &pdbs()?.join("python-3.15.2-arm64/select.pdb"),
    )
}

/// Python 3.13.1's `select.pyd` for x64 with its PDB (python.org's
/// `3.13.1/amd64/lib_pdb.msi`), both in [`pdbs`]`/python-3.13.1-amd64`.
fn x64_select() -> Option<(Vec<u8>, Vec<u8>)> {
    let dir = pdbs()?.join("python-3.13.1-amd64");
    with_pdb(&dir.join("select.pyd"), &dir.join("select.pdb"))
}

/// A PDB prototype is all its function takes: `_select_exec(PyObject
/// *m)` and `reap_obj(pylist fd2obj[])` take only those, though their
/// bodies pass the other argument registers on as they found them to
/// `PyModule_GetState` and `_Py_Dealloc` (imports whose prototype is
/// unknown); likewise `PyInit_select(void)`. A register the body reads is
/// still a parameter: MSVC's `__security_check_cookie`, assembly whose
/// PDB type is `void ()`, compares the cookie it is given (`rcx`, `x0`).
/// On ARM64 and x64 alike.
#[test]
fn a_pdb_prototype_keeps_exactly_its_parameters() {
    for (arch, select) in [("aarch64", arm64_select()), ("x86_64", x64_select())] {
        let Some((data, pdb)) = select else {
            continue;
        };
        let model = binbun_debuginfo::info::read(&pdb, &data).unwrap();
        let image = Image::parse(&data).unwrap();
        let database = Database::with_debug(&image, Seeds::ALL, Some(model)).unwrap();
        let names = |function: &str| -> Vec<Option<String>> {
            let decompiled = decompiled(&database, function);
            assert_eq!(decompiled.stats.debug.unplaced, None, "{arch} {function}");
            parameters(&decompiled.l2)
                .into_iter()
                .map(|(name, _)| name)
                .collect()
        };
        assert_eq!(names("_select_exec"), [Some("m".to_owned())], "{arch}");
        assert_eq!(names("reap_obj"), [Some("fd2obj".to_owned())], "{arch}");
        assert!(names("PyInit_select").is_empty(), "{arch}");
        assert_eq!(names("__security_check_cookie").len(), 1, "{arch}");
    }
}

/// DWARF's prototypes too: `rodata-x86_64.elf`'s `int main(int argc, char
/// **argv)` calls through `operations[argc & 1]`, code of unknown
/// prototype, which takes the System V argument registers as `main`
/// leaves them (`rcx`, `r8` and `r9` as it found them); `main` takes
/// `argc` and `argv` only.
#[test]
fn a_dwarf_prototype_keeps_exactly_its_parameters() {
    let data = fixture("rodata-x86_64.elf");
    let model = binbun_debuginfo::info::read(&fixture("rodata-x86_64.debug"), &data).unwrap();
    let image = Image::parse(&data).unwrap();
    let database = Database::with_debug(&image, Seeds::ALL, Some(model)).unwrap();
    let main = decompiled(&database, "main");
    assert_eq!(main.stats.debug.unplaced, None);
    let names: Vec<_> = parameters(&main.l2)
        .into_iter()
        .map(|(name, _)| name)
        .collect();
    assert_eq!(names, [Some("argc".to_owned()), Some("argv".to_owned())]);
}

/// An ARM64 PDB's prototypes name and type the parameters `x0`, `x1`
/// and `x2` hold at the entry: `_select_traverse(PyObject *module,
/// visitproc visit, void *arg)`, and `reap_obj(pylist fd2obj[])`'s
/// pointer to the PDB's `pylist` (`obj`, `fd`, `sentinel`). Their
/// functions are `static`: only the PDB names them.
#[test]
fn an_arm64_pdb_prototype_names_and_types_the_parameters_in_registers() {
    let Some((data, pdb)) = arm64_select() else {
        return;
    };
    let model = binbun_debuginfo::info::read(&pdb, &data).unwrap();
    let image = Image::parse(&data).unwrap();
    assert!(
        image
            .symbols
            .iter()
            .all(|symbol| symbol.name != "_select_traverse")
    );
    let database = Database::with_debug(&image, Seeds::ALL, Some(model)).unwrap();

    let traverse = decompiled(&database, "_select_traverse");
    assert_eq!(traverse.stats.debug.unplaced, None);
    let named: Vec<_> = parameters(&traverse.l2)
        .into_iter()
        .map_while(|(name, _)| name)
        .collect();
    assert_eq!(named, ["module", "visit", "arg"]);

    let reap = decompiled(&database, "reap_obj");
    let (name, ty) = parameters(&reap.l2).swap_remove(0);
    assert_eq!(name.as_deref(), Some("fd2obj"));
    let Some(Type::Pointer(Some(target))) = ty else {
        panic!("fd2obj is {ty:?}");
    };
    let Some(Type::Struct(pylist)) = reap.l2.types.get(target) else {
        panic!("fd2obj points to {:?}", reap.l2.types.get(target));
    };
    assert_eq!(pylist.name.as_deref(), Some("pylist"));
    let fields: Vec<(u64, &str)> = pylist
        .fields
        .iter()
        .filter_map(|field| Some((field.offset, field.name.as_deref()?)))
        .collect();
    assert_eq!(fields, [(0, "obj"), (8, "fd"), (16, "sentinel")]);
}

/// A public PDB (as symbol servers serve: no procedure or data records,
/// only public symbols) names the functions of a PE without symbols by
/// their public names; a decorated C++ name is no C identifier and names
/// nothing; no prototype comes with a name.
#[test]
fn a_public_pdb_names_functions() {
    let data = fixture("msvc-x86_64.exe");
    let mut model = binbun_debuginfo::info::read(&fixture("msvc-x86_64.pdb"), &data).unwrap();
    let five = *model
        .functions
        .iter()
        .find(|(_, function)| function.name.as_deref() == Some("five"))
        .unwrap()
        .0;
    model.functions.clear();
    model.globals.clear();
    let image = Image::parse(&data).unwrap();
    let without = Database::new(&image, Seeds::ALL).unwrap();
    assert_eq!(without.find_function("five").ok(), None);
    let database = Database::with_debug(&image, Seeds::ALL, Some(model)).unwrap();
    let id = database.find_function("five").unwrap();
    assert_eq!(database.function(id).unwrap().entry, five);
    assert!(database.find_function("_get_startup_commit_mode").is_ok());
    assert!(database.names().values().all(|name| !name.starts_with('?')));
    let decompiled = decompiled(&database, "five");
    assert_eq!(decompiled.stats.debug.parameters_named, 0);
}

/// MSVC's `__get_entropy` keeps `systime` (a `union FT` of 8 bytes, its
/// address passed to `GetSystemTimeAsFileTime`) in the frame: the frame
/// variable takes its name, and its scalar type only (a variable holding
/// a value is no union). `__scrt_get_show_window_mode`'s `startup_info`
/// (its address passed to `GetStartupInfoW`) is a variable of its own
/// with the PDB's name, of the 104-byte `STARTUPINFOW` with its fields'
/// names (the SDK's `typedef struct _STARTUPINFOW {…} STARTUPINFOW`: the
/// PDB's tag or the Win32 database's name).
#[test]
fn frame_variables_and_their_structs_take_their_debug_names_and_types() {
    let data = fixture("msvc-x86_64.exe");
    let model = binbun_debuginfo::info::read(&fixture("msvc-x86_64.pdb"), &data).unwrap();
    let image = Image::parse(&data).unwrap();
    let database = Database::with_debug(&image, Seeds::ALL, Some(model)).unwrap();

    let entropy = decompiled(&database, "__get_entropy");
    let systime = entropy
        .l2
        .variables
        .iter()
        .find(|variable| {
            variable
                .name
                .as_ref()
                .is_some_and(|name| name.text == "systime")
        })
        .unwrap();
    assert!(matches!(systime.kind, VarKind::Local | VarKind::Frame(_)));
    assert_ne!(systime.evidence, Evidence::Declared);

    let show = decompiled(&database, "__scrt_get_show_window_mode");
    let startup_info = show
        .l2
        .variables
        .iter()
        .find(|variable| {
            variable
                .name
                .as_ref()
                .is_some_and(|name| name.text == "startup_info")
        })
        .unwrap();
    let Some(Type::Struct(startup)) = show.l2.types.get(startup_info.ty) else {
        panic!("startup_info is no struct");
    };
    assert!(matches!(
        startup.name.as_deref(),
        Some("STARTUPINFOW" | "_STARTUPINFOW")
    ));
    assert_eq!(startup.size, 104);
    let names: Vec<(u64, &str)> = startup
        .fields
        .iter()
        .filter_map(|field| Some((field.offset, field.name.as_deref()?)))
        .take(3)
        .collect();
    assert_eq!(names, [(0, "cb"), (8, "lpReserved"), (16, "lpDesktop")]);
    assert_eq!(show.stats.debug.locals_named, 1);
}

/// Debug information stating `classify(int x)` of `program-x86_64.elf`
/// with `x` in `register` at the entry.
fn classify(image: &Image<'_>, register: &'static str) -> DebugModel {
    let database = Database::new(image, Seeds::ALL).unwrap();
    let id = database.find_function("classify").unwrap();
    let entry = database.function(id).unwrap().entry;
    let mut model = DebugModel::default();
    model.types.push(DebugType::Base {
        name: "int".to_owned(),
        bytes: 4,
        encoding: Encoding::Signed,
    });
    model.functions.insert(
        entry,
        Function {
            entry,
            name: Some("classify".to_owned()),
            parameters: vec![Variable {
                name: Some("x".to_owned()),
                ty: TypeId(0),
                location: vec![Span {
                    range: entry..entry + 1,
                    place: Place::Register(register),
                }],
            }],
            returns: TypeId(0),
            variadic: false,
            arity: None,
            locals: Vec::new(),
            unit: None,
        },
    );
    model
}

/// A C function's debug prototype that takes or returns a struct by
/// value (`tests/fixtures/records.c`) is taken, its parameters where
/// System V's rule puts them: `sum(struct pair p, long k)` in `rdi`,
/// `rsi` and `rdx`; `swap(struct pair)` in `rdi` and `rsi`;
/// `fill(long)`, which returns four words in memory, the address in
/// `rdi` and `x` in `rsi`; `weigh(struct mixed)` in `xmm0` and `rdi`;
/// `last(struct wide w, long k)` `k` in `rdi` and `w` in four stack
/// words, after the five integer registers nothing sets (C would pass
/// four scalars in them).
#[test]
fn a_dwarf_prototype_with_a_struct_by_value_is_placed_by_the_convention() {
    let data = fixture("records-x86_64.elf");
    let model = binbun_debuginfo::info::read(&fixture("records-x86_64.debug"), &data).unwrap();
    let image = Image::parse(&data).unwrap();
    let database = Database::with_debug(&image, Seeds::ALL, Some(model)).unwrap();
    let placed = |name: &str| {
        let function = decompiled(&database, name);
        assert_eq!(function.stats.debug.unplaced, None, "{name}");
        function.mapping.parameters
    };
    let register = |name: &str| {
        Source::Register(Piece {
            register: X86.find(name).unwrap(),
            offset: 0,
            width: 64,
        })
    };
    let stack = |offset: i64| Source::Stack { offset, bytes: 8 };
    let registers = |names: &[&str]| names.iter().map(|name| register(name)).collect::<Vec<_>>();
    assert_eq!(placed("sum"), registers(&["rdi", "rsi", "rdx"]));
    assert_eq!(placed("swap"), registers(&["rdi", "rsi"]));
    assert_eq!(placed("fill"), registers(&["rdi", "rsi"]));
    assert_eq!(placed("weigh"), registers(&["zmm0", "rdi"]));
    let mut last = registers(&["rdi", "rsi", "rdx", "rcx", "r8", "r9"]);
    last.extend([8, 16, 24, 32].map(stack));
    assert_eq!(placed("last"), last);
}

/// MSVC's code and PDB for the same (`tests/fixtures/records-win.c`,
/// whose compile flags say C): `sum(struct pair p, long long k)` takes a
/// pointer to its 16-byte struct in `rcx` and `k` in `rdx`;
/// `swap(struct pair)` the address of its result in `rcx` and the
/// pointer in `rdx`; `area(struct dims s, int k)` its 8-byte struct as
/// an integer in `rcx` and `k` in `edx`; `twice(struct dims)` likewise,
/// its result a `struct dims` in `rax`.
#[test]
fn a_pdb_prototype_with_a_struct_by_value_is_placed_by_the_convention() {
    let data = fixture("records-x86_64.exe");
    let model = binbun_debuginfo::info::read(&fixture("records-x86_64.pdb"), &data).unwrap();
    let image = Image::parse(&data).unwrap();
    let database = Database::with_debug(&image, Seeds::ALL, Some(model)).unwrap();
    let placed = |name: &str| {
        let function = decompiled(&database, name);
        assert_eq!(function.stats.debug.unplaced, None, "{name}");
        function
    };
    let register = |name: &str, width: u16| {
        Source::Register(Piece {
            register: X86.find(name).unwrap(),
            offset: 0,
            width,
        })
    };
    let both = [register("rcx", 64), register("rdx", 64)];
    assert_eq!(placed("sum").mapping.parameters, both);
    assert_eq!(placed("swap").mapping.parameters, both);
    assert_eq!(
        placed("area").mapping.parameters,
        [register("rcx", 64), register("rdx", 32)]
    );
    let twice = placed("twice");
    assert_eq!(twice.mapping.parameters, [register("rcx", 64)]);
    let returned = twice.l2.returns.and_then(|ty| twice.l2.types.get(ty));
    assert!(
        matches!(returned, Some(Type::Struct(dims)) if dims.name.as_deref() == Some("dims")),
        "{returned:?}"
    );
}

/// A debug prototype whose parameter the debug information states in
/// another register than the convention's (as GCC's `.isra` and
/// `.constprop` clones do, their parameters removed or reordered) is
/// ignored and counted; in the convention's register, it is taken.
#[test]
fn a_debug_prototype_the_convention_does_not_place_is_ignored() {
    let data = fixture("program-x86_64.elf");
    let image = Image::parse(&data).unwrap();

    let placed = Database::with_debug(&image, Seeds::ALL, Some(classify(&image, "rdi"))).unwrap();
    let taken = decompiled(&placed, "classify");
    assert_eq!(taken.stats.debug.unplaced, None);
    assert_eq!(
        parameters(&taken.l2),
        [(Some("x".to_owned()), Some(Type::Int(32)))]
    );

    let clone = Database::with_debug(&image, Seeds::ALL, Some(classify(&image, "rsi"))).unwrap();
    let ignored = decompiled(&clone, "classify");
    assert_eq!(ignored.stats.debug.unplaced, Some(Unplaced::Location));
    let plain = decompiled(&Database::new(&image, Seeds::ALL).unwrap(), "classify");
    assert_eq!(ignored.l2, plain.l2);
}
