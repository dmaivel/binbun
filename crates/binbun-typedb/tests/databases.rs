#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers fail loudly"
)]
//! The embedded databases against what the headers and the C compiler say,
//! and the precedence of origins.

// The compiler's layouts are asked for on x86-64 Linux only.
#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
use std::fmt::Write as _;
#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
use std::process::Command;

use binbun_typedb::database::{
    Database, Function, Header, SCHEMA_VERSION, Source, Target, TypeRef,
};
use binbun_typedb::jsonl::{self, ParseErrorKind};
use binbun_typedb::types::{Param, Signature};
use binbun_typedb::{Declaration, LoadError, Origin, Type, TypeId, TypeLibrary, embedded};

fn linux() -> TypeLibrary {
    TypeLibrary::for_target("x86_64", "linux").unwrap()
}

/// `ty` spelled compactly: `i4`/`u8` integers, `*T` pointers, typedefs,
/// records and enumerations by name or key.
fn spell(library: &TypeLibrary, ty: TypeId) -> String {
    match library.ty(ty).unwrap() {
        Type::Void => "void".to_owned(),
        Type::Bool => "bool".to_owned(),
        Type::Char { .. } => "char".to_owned(),
        &Type::Int { signed, size } => format!("{}{size}", if signed { 'i' } else { 'u' }),
        Type::Float(format) => format!("{format:?}"),
        &Type::Pointer(target) => format!("*{}", spell(library, target)),
        &Type::Array { element, count } => format!("{}[{count:?}]", spell(library, element)),
        Type::Function(_) => "fn".to_owned(),
        Type::Record(record) => record.key.clone(),
        Type::Enum(definition) => definition.key.clone(),
        Type::Typedef(typedef) => typedef.name.clone(),
        Type::Opaque(opaque) => opaque.key.clone(),
    }
}

/// A prototype spelled: `ret (type name, …, ...)`.
fn prototype(library: &TypeLibrary, declaration: &Declaration) -> String {
    let signature = &declaration.prototype.as_ref().unwrap().value;
    let mut params: Vec<String> = signature
        .params
        .iter()
        .map(|param| {
            format!(
                "{} {}",
                spell(library, param.ty),
                param.name.as_deref().unwrap_or("")
            )
        })
        .collect();
    if signature.variadic {
        params.push("...".to_owned());
    }
    format!("{} ({})", spell(library, signature.ret), params.join(", "))
}

#[test]
fn libc_prototypes_are_as_declared() {
    let library = linux();
    let function = |name| library.function(None, name).unwrap();
    let cases = [
        ("memcpy", "*void (*void __dest, *void __src, size_t __n)"),
        ("printf", "i4 (*char __format, ...)"),
        // The system call's flag sets, for the headers' `int`s.
        ("open", "i4 (*char __file, flags open_flags __oflag, ...)"),
        (
            "mmap",
            "*void (*void __addr, size_t __len, flags mmap_prot __prot, flags mmap_flags __flags, i4 __fd, __off_t __offset)",
        ),
        ("exit", "void (i4 __status)"),
        ("fstat", "i4 (i4 __fd, *struct stat __buf)"),
        // C23 headers redirect strtol to __isoc23_strtol: both names link.
        ("strtol", "i8 (*char __nptr, **char __endptr, i4 __base)"),
        (
            "__isoc23_strtol",
            "i8 (*char __nptr, **char __endptr, i4 __base)",
        ),
    ];
    for (name, expected) in cases {
        let declaration = function(name);
        assert_eq!(prototype(&library, declaration), expected, "{name}");
        assert_eq!(
            declaration.prototype.as_ref().unwrap().origin,
            Origin::Header
        );
    }
    // A typedef stays a named atom over its target.
    let size_t = function("memcpy").prototype.as_ref().unwrap().value.params[2].ty;
    let Type::Typedef(typedef) = library.ty(size_t).unwrap() else {
        panic!("size_t is not a typedef");
    };
    assert_eq!(spell(&library, typedef.target), "u8");

    for name in [
        "exit",
        "abort",
        "_exit",
        "longjmp",
        "__longjmp_chk",
        "err",
        "__assert_fail",
    ] {
        let no_return = function(name).no_return.unwrap();
        assert_eq!(
            (no_return.value, no_return.origin),
            (true, Origin::Header),
            "{name}"
        );
    }
    // A declaration without the attribute says nothing.
    for name in ["printf", "memcpy", "pthread_create"] {
        assert_eq!(function(name).no_return, None, "{name}");
    }
}

/// The checking functions `_FORTIFY_SOURCE` code calls that glibc's
/// headers call only as GCC builtins are declared as GCC's `builtins.def`
/// types them, for each target (`char` is unsigned on AArch64); a
/// function the headers declare keeps their prototype; the stack
/// protector's handler, which nothing declares, is the override's.
#[test]
fn fortified_functions_as_gcc_declares_them() {
    for (arch, char_signed) in [("x86_64", true), ("aarch64", false)] {
        let library = TypeLibrary::for_target(arch, "linux").unwrap();
        let function = |name| library.function(None, name).unwrap();
        for (name, expected) in [
            ("__memcpy_chk", "*void (*void , *void , size_t , size_t )"),
            ("__memset_chk", "*void (*void , i4 , size_t , size_t )"),
            ("__strcpy_chk", "*char (*char , *char , size_t )"),
            ("__strncpy_chk", "*char (*char , *char , size_t , size_t )"),
            ("__stpncpy_chk", "*char (*char , *char , size_t , size_t )"),
            // Declared by bits/stdio2-decl.h itself.
            (
                "__sprintf_chk",
                "i4 (*char __s, i4 __flag, size_t __slen, *char __format, ...)",
            ),
        ] {
            let declaration = function(name);
            assert_eq!(prototype(&library, declaration), expected, "{arch} {name}");
            assert_eq!(
                declaration.prototype.as_ref().unwrap().origin,
                Origin::Header
            );
            assert!(
                declaration.no_throw.is_some_and(|fact| fact.value),
                "{name}"
            );
        }
        let strcpy = &function("__strcpy_chk").prototype.as_ref().unwrap().value;
        let Type::Pointer(target) = library.ty(strcpy.ret).unwrap() else {
            panic!("__strcpy_chk does not return a pointer");
        };
        assert_eq!(
            library.ty(*target),
            Some(&Type::Char {
                signed: char_signed
            }),
            "{arch}"
        );
        let fail = function("__stack_chk_fail");
        assert_eq!(prototype(&library, fail), "void ()");
        assert_eq!(fail.prototype.as_ref().unwrap().origin, Origin::Override);
        assert!(fail.no_return.is_some_and(|fact| fact.value));
    }
}

#[test]
fn format_strings_from_headers_and_overrides() {
    let library = linux();
    let format_arg = |name| {
        let fact = library.function(None, name)?.format_arg.clone()?;
        Some((fact.value, fact.origin))
    };
    // glibc's <libintl.h>: `__attribute_format_arg__`, once or (ngettext)
    // twice; a function without it states none.
    assert_eq!(format_arg("dcgettext"), Some((vec![2], Origin::Header)));
    assert_eq!(format_arg("gettext"), Some((vec![1], Origin::Header)));
    assert_eq!(format_arg("ngettext"), Some((vec![1, 2], Origin::Header)));
    assert_eq!(format_arg("strdup"), None);
    let format = |name| {
        let fact = library.function(None, name)?.format.clone()?;
        Some((
            fact.value.archetype,
            fact.value.string,
            fact.value.first,
            fact.origin,
        ))
    };
    // glibc's headers state the attribute on these.
    assert_eq!(
        format("snprintf"),
        Some(("printf".to_owned(), 3, 4, Origin::Header))
    );
    assert_eq!(
        format("vsscanf"),
        Some(("scanf".to_owned(), 2, 0, Origin::Header))
    );
    // And not on these (the compilers know them as builtins): overrides.
    assert_eq!(
        format("printf"),
        Some(("printf".to_owned(), 1, 2, Origin::Override))
    );
    assert_eq!(
        format("__fprintf_chk"),
        Some(("printf".to_owned(), 3, 4, Origin::Override))
    );
    // Their `va_list` forms: the format describes the `va_list` (first 0).
    assert_eq!(
        format("__vfprintf_chk"),
        Some(("printf".to_owned(), 3, 0, Origin::Override))
    );
    assert_eq!(format("memcpy"), None);
    // An override with only a format says nothing about returning.
    assert_eq!(library.function(None, "printf").unwrap().no_return, None);
}

#[test]
fn syscall_numbers_name_the_call_and_its_arguments() {
    let library = linux();
    // x86-64's table: read is 0, ptrace 101 with its variants' four
    // arguments (its plain description gives two).
    let arity = |number| {
        let (name, declaration) = library.syscall_number(number).unwrap();
        (
            name,
            declaration.prototype.as_ref().unwrap().value.params.len(),
        )
    };
    assert_eq!(arity(0), ("read", 3));
    assert_eq!(arity(101), ("ptrace", 4));
    assert!(library.syscall_number(100_000).is_none());
}

/// Every x86-64 system call the kernel implements is declared, those
/// syzkaller leaves out too (`tools/typegen/syzlang/unfuzzed.txt`): a
/// call with no declaration is taken to read all six argument registers,
/// which makes parameters of whatever its caller leaves there. The
/// numbers not declared are those x86-64 never assigned (337 to 423,
/// below those every architecture shares) and the calls the kernel no
/// longer implements (`sys_ni_syscall`, which reads nothing).
#[test]
fn every_implemented_syscall_is_declared() {
    let library = linux();
    let retired = [
        156, // _sysctl
        174, // create_module
        177, // get_kernel_syms
        178, // query_module
        180, // nfsservctl
        181, // getpmsg
        182, // putpmsg
        183, // afs_syscall
        184, // tuxcall
        185, // security
        214, // epoll_ctl_old
        215, // epoll_wait_old
        236, // vserver
    ];
    let missing: Vec<u64> = (0..=471)
        .filter(|number| !(337..=423).contains(number) && !retired.contains(number))
        .filter(|&number| library.syscall_number(number).is_none())
        .collect();
    assert!(missing.is_empty(), "no declaration: {missing:?}");
    let futex = library.syscall_number(202).unwrap();
    assert_eq!(futex.0, "futex");
    assert_eq!(futex.1.prototype.as_ref().unwrap().value.params.len(), 6);
}

/// Every AArch64 system call the kernel implements is declared, numbered
/// from the arm64 table of the AArch64 databases' kernel headers (Debian
/// trixie's Linux 6.12, which ends at mseal, 462). The numbers not
/// declared are those arm64 does not assign (244 to 259, kept for
/// architecture-specific calls arm64 has none of; 295 to 423) and
/// nfsservctl (42, `sys_ni_syscall`). The numbers are arm64's, not
/// x86-64's; the calls only x86-64 has (`open`, `arch_prctl`, `iopl`) have
/// none; the flag values are AArch64's (`O_DIRECTORY` 040000, x86-64's
/// 0200000).
#[test]
fn every_implemented_aarch64_syscall_is_declared() {
    let library = TypeLibrary::for_target("aarch64", "linux").unwrap();
    let missing: Vec<u64> = (0..=462)
        .filter(|number| {
            !(244..=259).contains(number) && !(295..=423).contains(number) && *number != 42
        })
        .filter(|&number| library.syscall_number(number).is_none())
        .collect();
    assert!(missing.is_empty(), "no declaration: {missing:?}");
    let arity = |number| {
        let (name, declaration) = library.syscall_number(number).unwrap();
        (
            name,
            declaration.prototype.as_ref().unwrap().value.params.len(),
        )
    };
    assert_eq!(arity(63), ("read", 3));
    assert_eq!(arity(56), ("openat", 4));
    assert_eq!(arity(98), ("futex", 6));
    assert_eq!(arity(117), ("ptrace", 4));
    assert_eq!(arity(222), ("mmap", 6));
    assert_eq!(arity(2), ("io_submit", 3));
    let named: Vec<&str> = (0..=462)
        .filter_map(|number| Some(library.syscall_number(number)?.0))
        .collect();
    for name in ["open", "arch_prctl", "iopl", "stat", "fork"] {
        assert!(library.syscall(name).is_some(), "{name} is not declared");
        assert!(!named.contains(&name), "{name} has an AArch64 number");
    }

    for (arch, directory, no_follow) in [
        ("aarch64", 0o40_000, 0o100_000),
        ("x86_64", 0o200_000, 0o400_000),
    ] {
        let library = TypeLibrary::for_target(arch, "linux").unwrap();
        let openat = library.syscall("openat").unwrap();
        let flags = openat
            .prototype
            .as_ref()
            .unwrap()
            .value
            .params
            .iter()
            .find(|param| param.name.as_deref() == Some("flags"))
            .unwrap();
        let Type::Enum(flags) = library.ty(flags.ty).unwrap() else {
            panic!("{arch}: openat's flags are not a flag set");
        };
        let value = |name| {
            flags
                .variants
                .iter()
                .find(|variant| variant.name == name)
                .unwrap()
                .value
        };
        assert_eq!(
            (value("O_DIRECTORY"), value("O_NOFOLLOW")),
            (Some(directory), Some(no_follow)),
            "{arch}"
        );
    }
}

#[test]
fn syscall_parameters_have_flag_types() {
    let library = linux();
    let mmap = library.syscall("mmap").unwrap();
    let signature = &mmap.prototype.as_ref().unwrap().value;
    let prot = signature
        .params
        .iter()
        .find(|p| p.name.as_deref() == Some("prot"))
        .unwrap();
    let Type::Enum(flags) = library.ty(prot.ty).unwrap() else {
        panic!("mmap's prot is not a flag set");
    };
    assert!(flags.flags);
    let value = |name| {
        flags
            .variants
            .iter()
            .find(|v| v.name == name)
            .unwrap()
            .value
    };
    assert_eq!(
        (value("PROT_READ"), value("PROT_WRITE"), value("PROT_EXEC")),
        (Some(1), Some(2), Some(4))
    );
    // A resource stays a named type: `fd` over `int32`.
    let fd = signature
        .params
        .iter()
        .find(|p| p.name.as_deref() == Some("fd"))
        .unwrap();
    assert_eq!(spell(&library, fd.ty), "fd");
    // System calls are not library functions: libc's `mmap` is the libc one.
    assert_eq!(
        library
            .function(None, "mmap")
            .unwrap()
            .prototype
            .as_ref()
            .unwrap()
            .origin,
        Origin::Header
    );
}

/// What the C compiler says: `sizeof`/`_Alignof` of each type, `offsetof`
/// of each record's named fields as the library gives them; `None` if
/// `cc` cannot be run.
#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
fn compiler_layout(library: &TypeLibrary, records: &[&str], types: &[&str]) -> Option<String> {
    let mut source = String::from(
        "#define _GNU_SOURCE\n#include <stdio.h>\n#include <stddef.h>\n#include <signal.h>\n\
         #include <setjmp.h>\n#include <sys/stat.h>\n#include <sys/epoll.h>\n#include <time.h>\n\
         int main(void) {\n",
    );
    let record_types = library.types().filter_map(|(_, ty)| {
        if let Type::Record(record) = ty
            && records.contains(&record.key.as_str())
        {
            Some(record)
        } else {
            None
        }
    });
    for record in record_types {
        let key = &record.key;
        writeln!(
            source,
            "printf(\"{key} %zu %zu\\n\", sizeof({key}), _Alignof({key}));"
        )
        .unwrap();
        for field in record.fields.as_ref().unwrap() {
            if let Some(name) = &field.name {
                writeln!(
                    source,
                    "printf(\"{key}.{name} %zu\\n\", offsetof({key}, {name}));"
                )
                .unwrap();
            }
        }
    }
    for ty in types {
        writeln!(
            source,
            "printf(\"{ty} %zu %zu\\n\", sizeof({ty}), _Alignof({ty}));"
        )
        .unwrap();
    }
    source.push_str("return 0;\n}\n");
    let dir = std::env::temp_dir().join(format!("binbun-typedb-layout-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let (c_path, binary) = (dir.join("layout.c"), dir.join("layout"));
    std::fs::write(&c_path, source).unwrap();
    let compiled = Command::new("cc")
        .arg(&c_path)
        .arg("-o")
        .arg(&binary)
        .output();
    let output = match compiled {
        Ok(compiled) if compiled.status.success() => Command::new(&binary).output().unwrap(),
        Ok(compiled) => panic!(
            "the layout probe does not compile:\n{}",
            String::from_utf8_lossy(&compiled.stderr)
        ),
        Err(error) => {
            eprintln!("skipped: cannot run cc: {error}");
            return None;
        }
    };
    std::fs::remove_dir_all(&dir).unwrap();
    Some(String::from_utf8(output.stdout).unwrap())
}

#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
#[test]
fn layouts_match_the_compiler() {
    // The libc database alone: the syscall one has records of the same
    // names, with syzlang's fields.
    let mut library = TypeLibrary::new();
    let (_, libc) = embedded("x86_64", "linux")
        .into_iter()
        .find(|(_, database)| database.header.source == Source::Header)
        .unwrap();
    library.add(libc).unwrap();
    // `struct epoll_event` is packed on x86-64; `struct sigaction` has a
    // union; `jmp_buf` and `sigset_t` are arrays and anonymous structures.
    let records = [
        "struct stat",
        "struct sigaction",
        "struct epoll_event",
        "struct timespec",
    ];
    let types = [
        "size_t",
        "off_t",
        "pid_t",
        "sigset_t",
        "jmp_buf",
        "time_t",
        "struct stat",
    ];
    let Some(expected) = compiler_layout(&library, &records, &types) else {
        return;
    };
    let mut actual = String::new();
    for (id, ty) in library.types() {
        if let Type::Record(record) = ty
            && records.contains(&record.key.as_str())
        {
            let key = &record.key;
            let (size, align) = (library.size_of(id).unwrap(), library.align_of(id).unwrap());
            writeln!(actual, "{key} {size} {align}").unwrap();
            for field in record.fields.as_ref().unwrap() {
                if let Some(name) = &field.name {
                    writeln!(actual, "{key}.{name} {}", field.bit_offset.unwrap() / 8).unwrap();
                }
            }
        }
    }
    for name in types {
        let id = library
            .types()
            .find(|(_, ty)| ty.key() == Some(name))
            .unwrap()
            .0;
        let (size, align) = (library.size_of(id).unwrap(), library.align_of(id).unwrap());
        writeln!(actual, "{name} {size} {align}").unwrap();
    }
    assert_eq!(actual, expected);
    assert!(expected.contains("struct stat.st_mtim 88\n"), "{expected}");
}

fn database(source: Source, functions: Vec<Function>) -> Database {
    Database {
        header: Header {
            binbun_typedb: SCHEMA_VERSION,
            source,
            target: embedded("x86_64", "linux")[0].1.header.target.clone(),
            generator: "test".to_owned(),
            inputs: Vec::new(),
        },
        functions,
        types: Vec::new(),
    }
}

fn void_function(name: &str, no_return: bool) -> Function {
    Function {
        name: name.to_owned(),
        library: None,
        signature: Signature {
            ret: TypeRef::Void,
            params: vec![Param {
                name: None,
                ty: TypeRef::Int {
                    signed: true,
                    size: 4,
                },
            }],
            variadic: false,
            convention: None,
        },
        no_return,
        no_throw: false,
        format: None,
        format_arg: Vec::new(),
        alloc_size: None,
        number: None,
    }
}

#[test]
fn declarations_override_the_overrides_but_silence_does_not() {
    let fact = |library: &TypeLibrary, name| {
        library
            .function(None, name)
            .and_then(|d| d.no_return)
            .map(|f| (f.value, f.origin))
    };
    let mut library = TypeLibrary::builtin();
    assert_eq!(fact(&library, "exit"), Some((true, Origin::Override)));
    assert_eq!(fact(&library, "abort"), Some((true, Origin::Override)));
    // `exit` declared noreturn; `abort` declared without the attribute.
    let header = database(
        Source::Header,
        vec![void_function("exit", true), void_function("abort", false)],
    );
    library.add(&header).unwrap();
    assert_eq!(fact(&library, "exit"), Some((true, Origin::Header)));
    assert_eq!(fact(&library, "abort"), Some((true, Origin::Override)));
    assert_eq!(
        library
            .function(None, "abort")
            .unwrap()
            .prototype
            .as_ref()
            .unwrap()
            .origin,
        Origin::Header
    );
    // A weaker source does not replace a header's prototype.
    let mut syzlang_like = database(Source::Winmd, vec![void_function("exit", false)]);
    syzlang_like.functions[0].signature.params.clear();
    library.add(&syzlang_like).unwrap();
    let exit = library.function(None, "exit").unwrap();
    assert_eq!(exit.prototype.as_ref().unwrap().origin, Origin::Header);
    assert_eq!(exit.prototype.as_ref().unwrap().value.params.len(), 1);

    // On the real target the header's fact replaces the override.
    assert_eq!(fact(&linux(), "exit"), Some((true, Origin::Header)));
    // An override the libc headers do not state stays one.
    assert_eq!(
        fact(&linux(), "__stack_chk_fail"),
        Some((true, Origin::Override))
    );
}

#[test]
fn a_database_that_does_not_load_changes_nothing() {
    let mut library = linux();
    let before = library.clone();
    let mut broken = database(Source::Header, vec![void_function("broken", true)]);
    broken.functions[0].signature.ret =
        TypeRef::Pointer(Box::new(TypeRef::Named("struct missing".to_owned())));
    assert_eq!(
        library.add(&broken),
        Err(LoadError::UnknownType("struct missing".to_owned()))
    );
    assert_eq!(library, before);

    let mut windows = database(Source::Winmd, Vec::new());
    windows.header.target = Target {
        os: "windows".to_owned(),
        env: "msvc".to_owned(),
        ..windows.header.target
    };
    assert!(matches!(library.add(&windows), Err(LoadError::Target(_))));
    assert_eq!(library, before);
}

#[test]
fn embedded_files_are_written_as_they_read() {
    for (name, text) in [
        ("libc", include_str!("../data/linux-x86_64-libc.jsonl")),
        (
            "syscalls",
            include_str!("../data/linux-x86_64-syscalls.jsonl"),
        ),
    ] {
        let database = jsonl::parse(text).unwrap();
        assert_eq!(jsonl::write(&database).unwrap(), text, "{name}");
    }
}

#[test]
fn another_schema_version_is_refused() {
    let text = include_str!("../data/linux-x86_64-syscalls.jsonl");
    let other = text.replacen(
        &format!("{{\"binbun_typedb\":{SCHEMA_VERSION},"),
        &format!("{{\"binbun_typedb\":{},", SCHEMA_VERSION + 1),
        1,
    );
    let error = jsonl::parse(&other).unwrap_err();
    assert!(matches!(error.kind, ParseErrorKind::Version(v) if v == SCHEMA_VERSION + 1));
}

#[test]
fn every_data_file_is_embedded_and_parses() {
    let data = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("data");
    let mut files: Vec<String> = std::fs::read_dir(data)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "jsonl")
        })
        .map(|path| path.file_name().unwrap().to_str().unwrap().to_owned())
        .collect();
    files.sort();
    let targets = [
        ("x86_64", "linux"),
        ("aarch64", "linux"),
        ("x86_64", "windows"),
        ("aarch64", "windows"),
        ("x86_64", "macos"),
        ("aarch64", "macos"),
    ];
    let mut embedded: Vec<String> = Vec::new();
    for (arch, os) in targets {
        for (name, database) in binbun_typedb::embedded(arch, os) {
            assert_eq!(
                (
                    database.header.target.arch.as_str(),
                    database.header.target.os.as_str()
                ),
                (arch, os),
                "{name}"
            );
            embedded.push(name.to_owned());
        }
    }
    embedded.sort();
    assert_eq!(embedded, files);
}

#[test]
fn a_targets_databases_are_added_c_runtime_first() {
    let names = |arch, os| -> Vec<&str> {
        embedded(arch, os)
            .into_iter()
            .map(|(name, _)| name)
            .collect()
    };
    assert_eq!(
        names("x86_64", "linux"),
        [
            "linux-x86_64-libc.jsonl",
            "linux-x86_64-cxxabi.jsonl",
            "linux-x86_64-syscalls.jsonl"
        ]
    );
    assert_eq!(
        names("x86_64", "windows")[..4],
        [
            "windows-x86_64-ucrt.jsonl",
            "windows-x86_64-msvcrt.jsonl",
            "windows-x86_64-native.jsonl",
            "windows-x86_64-win32.jsonl"
        ]
    );
    assert_eq!(
        names("aarch64", "windows")[..4],
        [
            "windows-aarch64-ucrt.jsonl",
            "windows-aarch64-msvcrt.jsonl",
            "windows-aarch64-native.jsonl",
            "windows-aarch64-win32.jsonl"
        ]
    );
}

/// The native API (phnt's, for ntdll.dll) of each Windows architecture:
/// the functions its own ntdll.dll exports, with its TEB, the PEB at 0x60
/// on both.
#[test]
fn native_is_embedded_for_each_windows_architecture() {
    for (arch, only, not) in [
        ("x86_64", "RtlCaptureContext2", "RtlFillMemoryUlong"),
        ("aarch64", "RtlFillMemoryUlong", "RtlCaptureContext2"),
    ] {
        let file = format!("windows-{arch}-native.jsonl");
        let (_, native) = embedded(arch, "windows")
            .into_iter()
            .find(|(name, _)| *name == file)
            .unwrap_or_else(|| panic!("no {file}"));
        let declared = |name: &str| {
            native.functions.iter().any(|function| {
                function.name == name && function.library.as_deref() == Some("ntdll.dll")
            })
        };
        for name in ["NtClose", "NtQueryInformationProcess", "LdrLoadDll", only] {
            assert!(declared(name), "{arch}: no ntdll.dll!{name}");
        }
        assert!(!declared(not), "{arch}: ntdll.dll!{not}");
        let library = TypeLibrary::for_target(arch, "windows").unwrap();
        let Some(Type::Record(teb)) = library.ty(library.named("struct _TEB").unwrap()) else {
            panic!("{arch}: _TEB is no record");
        };
        let peb = teb
            .fields
            .iter()
            .flatten()
            .find(|field| field.name.as_deref() == Some("ProcessEnvironmentBlock"))
            .unwrap();
        assert_eq!(peb.bit_offset, Some(0x60 * 8), "{arch}");
    }
}

#[test]
fn win32_is_embedded() {
    for arch in ["x86_64", "aarch64"] {
        let file = format!("windows-{arch}-win32.jsonl");
        let (_, win32) = embedded(arch, "windows")
            .into_iter()
            .find(|(name, _)| *name == file)
            .unwrap();
        assert_eq!(win32.header.source, Source::Winmd);
        for (library, name, params) in [
            ("USER32.dll", "MessageBoxA", 4),
            ("KERNEL32.dll", "CreateFileW", 7),
            ("USER32.dll", "CreateWindowExW", 12),
        ] {
            let function = win32
                .functions
                .iter()
                .find(|function| {
                    function.name == name && function.library.as_deref() == Some(library)
                })
                .unwrap_or_else(|| panic!("{arch}: no {library}!{name}"));
            assert_eq!(function.signature.params.len(), params, "{arch}: {name}");
        }
    }
    let library = TypeLibrary::for_target("x86_64", "windows").unwrap();
    let exit = library
        .function(Some("KERNEL32.dll"), "ExitProcess")
        .unwrap();
    let no_return = exit.no_return.unwrap();
    assert_eq!((no_return.value, no_return.origin), (true, Origin::Winmd));
    let alloc = library
        .function(Some("kernel32.dll"), "VirtualAlloc")
        .unwrap();
    let signature = &alloc.prototype.as_ref().unwrap().value;
    let Type::Enum(flags) = library.ty(signature.params[2].ty).unwrap() else {
        panic!("flAllocationType is not an enumeration");
    };
    assert!(flags.flags);
    let commit = flags
        .variants
        .iter()
        .find(|v| v.name == "MEM_COMMIT")
        .unwrap();
    assert_eq!(commit.value, Some(0x1000));
    // Linux's facts are not loaded for Windows.
    assert!(library.function(None, "__longjmp_chk").is_none());
}
