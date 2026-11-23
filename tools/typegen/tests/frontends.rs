#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers fail loudly"
)]
//! The front ends on small inputs whose declarations say exactly what the
//! database must.

use std::path::PathBuf;

use binbun_typedb::database::{Definition, Function, Target, TypeRef};
use binbun_typedb::types::Record;
use binbun_typegen::{Declarations, syzlang};

fn target() -> Target {
    Target {
        arch: "x86_64".to_owned(),
        os: "linux".to_owned(),
        env: "gnu".to_owned(),
        pointer_size: 8,
    }
}

/// `text` written to a fresh file named `name`.
fn file(name: &str, text: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("binbun-typegen-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(name);
    std::fs::write(&path, text).unwrap();
    path
}

fn function<'a>(declarations: &'a Declarations, name: &str) -> &'a Function {
    declarations
        .functions
        .iter()
        .find(|function| function.name == name)
        .unwrap_or_else(|| panic!("{name} is not declared"))
}

fn record<'a>(declarations: &'a Declarations, key: &str) -> &'a Record<TypeRef> {
    let Definition::Record(record) = &declarations.types[key] else {
        panic!("{key} is {:?}", declarations.types[key]);
    };
    record
}

#[cfg(feature = "headers")]
mod headers {
    use binbun_typedb::database::TypeRef;
    use binbun_typegen::headers::{Options, parse};

    use super::{file, function, record, target};

    /// libclang allows one `Clang` per process at a time: the tests take
    /// turns.
    static CLANG: std::sync::Mutex<()> = std::sync::Mutex::new(());

    const HEADER: &str = "
typedef unsigned long size_t;
void plain(int);
_Noreturn void c11(int);
[[noreturn]] void c23(int);
__attribute__((noreturn)) void gnu_before(int);
void gnu_after(int) __attribute__((__noreturn__));
void redeclared(int);
void redeclared(int) __attribute__((noreturn));
void takes_noreturn_callback(void (*callback)(int) __attribute__((noreturn)));
int printf(const char *format, ...);
int logf_(int level, const char *format, ...) __attribute__((__format__(__printf__, 2, 3)));
int scanned(const char *format, ...) __attribute__((format(scanf, 1, 2), nonnull(1)));
int vlogf_(const char *format, __builtin_va_list) __attribute__((format(printf, 1, 0)));
void redeclared_format(const char *, ...);
void redeclared_format(const char *, ...) __attribute__((format(printf, 1, 2)));
int unprototyped();
long strtol(const char *, char **, int) __asm__(\"__isoc23_strtol\");
void *memcpy(void *dest, const void *src, size_t n);
struct flags { unsigned int a : 3; unsigned int b : 5; int c; };
struct outer { char tag; union { int i; double d; }; struct { short x; } named; };
#define INLINE_ATTRS extern __inline__ __attribute__((__always_inline__, __gnu_inline__))
#define NORETURN_ATTR __attribute__((__noreturn__))
#define C11_NORETURN _Noreturn
void NORETURN_ATTR fails(unsigned int);
INLINE_ATTRS void NORETURN_ATTR fails(unsigned int code) { __builtin_unreachable(); }
void prefetches(const void *);
INLINE_ATTRS void prefetches(const void *address) { (void)address; }
C11_NORETURN void c11_macro(int);
";

    #[test]
    fn prototypes_and_noreturn_as_declared() {
        let _clang = CLANG
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let path = file("test.h", HEADER);
        let target = target();
        let args = ["-std=gnu23".to_owned()];
        let options = Options {
            target: &target,
            args: &args,
            include_system: false,
            from: &[],
            extra: "",
        };
        let declarations = match parse(&[path.as_path()], &options) {
            Ok(declarations) => declarations,
            Err(error) if error.contains("libclang") => {
                eprintln!("skipped: {error}");
                return;
            }
            Err(error) => panic!("{error}"),
        };
        for (name, no_return) in [
            ("plain", false),
            ("c11", true),
            ("c23", true),
            ("gnu_before", true),
            ("gnu_after", true),
            ("redeclared", true),
            // A parameter's attribute is not the function's.
            ("takes_noreturn_callback", false),
            ("printf", false),
            // Through macros (mingw-w64's `__fastfail` and `__prefetch`):
            // an attribute's range runs from the macro's definition to
            // its use, over `NORETURN_ATTR`'s, which is not
            // `prefetches`'s.
            ("fails", true),
            ("prefetches", false),
            ("c11_macro", true),
        ] {
            assert_eq!(function(&declarations, name).no_return, no_return, "{name}");
        }
        let printf = &function(&declarations, "printf").signature;
        assert!(printf.variadic);
        assert_eq!(printf.params.len(), 1);
        assert_eq!(printf.params[0].name.as_deref(), Some("format"));
        // The format attribute as written, underscores dropped; none for
        // `printf`, whose attribute clang adds implicitly.
        let format = |name| {
            function(&declarations, name)
                .format
                .as_ref()
                .map(|format| (format.archetype.as_str(), format.string, format.first))
        };
        assert_eq!(format("printf"), None);
        assert_eq!(format("logf_"), Some(("printf", 2, 3)));
        assert_eq!(format("scanned"), Some(("scanf", 1, 2)));
        assert_eq!(format("vlogf_"), Some(("printf", 1, 0)));
        assert_eq!(format("redeclared_format"), Some(("printf", 1, 2)));
        // C23: `int f();` is `int f(void)`.
        assert!(!function(&declarations, "unprototyped").signature.variadic);
        assert!(!function(&declarations, "memcpy").signature.variadic);
        assert_eq!(
            function(&declarations, "memcpy").signature.params[2].ty,
            TypeRef::Named("size_t".to_owned())
        );
        // The label links; the C name is the same function elsewhere.
        assert_eq!(
            function(&declarations, "__isoc23_strtol").signature,
            function(&declarations, "strtol").signature
        );

        let flags = record(&declarations, "struct flags");
        let layout: Vec<_> = flags
            .fields
            .as_ref()
            .unwrap()
            .iter()
            .map(|field| {
                (
                    field.name.as_deref().unwrap(),
                    field.bit_offset,
                    field.bit_width,
                )
            })
            .collect();
        assert_eq!(
            layout,
            [
                ("a", Some(0), Some(3)),
                ("b", Some(3), Some(5)),
                ("c", Some(32), None)
            ]
        );

        // The anonymous union is a member at its offset, keyed by where it is.
        let outer = record(&declarations, "struct outer");
        let fields = outer.fields.as_ref().unwrap();
        assert_eq!(fields[1].name, None);
        assert_eq!(fields[1].bit_offset, Some(64));
        assert_eq!(
            fields[1].ty,
            TypeRef::Named("union (struct outer).#1".to_owned())
        );
        assert!(record(&declarations, "union (struct outer).#1").union);
        assert_eq!(fields[2].bit_offset, Some(128));
        assert_eq!(outer.size, Some(24));
    }

    /// A structure's anonymous members are each their own type (C gives
    /// them all the same USR), and keeping what the functions reach
    /// keeps them, not a type nothing refers to.
    #[test]
    fn anonymous_members_are_their_own_types() {
        let _clang = CLANG
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let path = file(
            "anonymous.h",
            "struct two { union { int a; char b; }; long gap; union { double c; short d; }; };\n\
             struct two *get(void);\n\
             struct unused { int x; };\n",
        );
        let target = target();
        let options = Options {
            target: &target,
            args: &[],
            include_system: false,
            from: &[],
            extra: "",
        };
        let mut declarations = match parse(&[path.as_path()], &options) {
            Ok(declarations) => declarations,
            Err(error) if error.contains("libclang") => {
                eprintln!("skipped: {error}");
                return;
            }
            Err(error) => panic!("{error}"),
        };
        declarations.keep(&[]).unwrap();
        assert!(!declarations.has_type("struct unused"));
        let names = |key: &str| -> Vec<String> {
            record(&declarations, key)
                .fields
                .iter()
                .flatten()
                .filter_map(|field| field.name.clone())
                .collect()
        };
        let members: Vec<String> = record(&declarations, "struct two")
            .fields
            .iter()
            .flatten()
            .filter(|field| field.name.is_none())
            .map(|field| {
                let TypeRef::Named(key) = &field.ty else {
                    panic!("{:?}", field.ty);
                };
                key.clone()
            })
            .collect();
        assert_eq!(members.len(), 2);
        assert_eq!(names(&members[0]), ["a", "b"]);
        assert_eq!(names(&members[1]), ["c", "d"]);
    }

    /// `nothrow` as glibc's `__THROW` states it in C (an attribute behind
    /// a macro) and as `cxxabi.h` does in C++ (an exception
    /// specification), where only the functions of C linkage are kept.
    #[test]
    fn nothrow_and_cplusplus() {
        let _clang = CLANG
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let c = file(
            "nothrow.h",
            "#define THROW __attribute__((__nothrow__, __leaf__))\n\
             void quiet(int) THROW;\n\
             void loud(int) __attribute__((nonnull(1)));\n\
             void later(int);\n\
             void later(int) THROW;\n",
        );
        let cxx = file(
            "abi.h",
            "namespace std { class type_info; }\n\
             namespace abi { extern \"C\" {\n\
             void *begin(void *) noexcept;\n\
             void *alloc(unsigned long) throw();\n\
             void end();\n\
             void maybe() noexcept(false);\n\
             void raise(void *, std::type_info *, void (*)(void *));\n\
             } void mangled(int) noexcept; }\n",
        );
        let target = target();
        let parse_with = |path: &std::path::Path, args: &[String]| {
            let options = Options {
                target: &target,
                args,
                include_system: false,
                from: &[],
                extra: "",
            };
            parse(&[path], &options)
        };
        let declarations = match parse_with(&c, &[]) {
            Ok(declarations) => declarations,
            Err(error) if error.contains("libclang") => {
                eprintln!("skipped: {error}");
                return;
            }
            Err(error) => panic!("{error}"),
        };
        for (name, no_throw) in [("quiet", true), ("loud", false), ("later", true)] {
            assert_eq!(function(&declarations, name).no_throw, no_throw, "{name}");
        }

        let args = ["-x".to_owned(), "c++".to_owned(), "-std=c++17".to_owned()];
        let declarations = parse_with(&cxx, &args).unwrap();
        for (name, no_throw) in [
            ("begin", true),
            ("alloc", true),
            ("end", false),
            ("maybe", false),
            ("raise", false),
        ] {
            assert_eq!(function(&declarations, name).no_throw, no_throw, "{name}");
        }
        assert!(
            declarations
                .functions
                .iter()
                .all(|function| function.name != "mangled" && !function.name.starts_with("_Z")),
            "a C++ function is not declared"
        );
        assert_eq!(
            function(&declarations, "raise").signature.params[1].ty,
            TypeRef::Pointer(Box::new(TypeRef::Named("struct type_info".to_owned())))
        );
    }

    /// Declarations read after the headers (GCC's checking builtins) are
    /// typed as the headers' own, for the target (`size_t` stays the
    /// headers' typedef; `char` is unsigned on AArch64), and a function the
    /// headers declare keeps their prototype and gains what the later one
    /// adds.
    #[test]
    fn extra_declarations_follow_the_headers() {
        let _clang = CLANG
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let path = file(
            "fortify.h",
            "typedef unsigned long size_t;\n\
             int __printf_chk(int flag, const char *format, ...);\n",
        );
        let extra = "extern char *__strcpy_chk(char *, const char *, size_t) __attribute__((__nothrow__));\n\
                     extern int __printf_chk(int, const char *, ...) __attribute__((__nothrow__));\n";
        let mut target = target();
        target.arch = "aarch64".to_owned();
        let options = Options {
            target: &target,
            args: &[],
            include_system: false,
            from: &[],
            extra,
        };
        let declarations = match parse(&[path.as_path()], &options) {
            Ok(declarations) => declarations,
            Err(error) if error.contains("libclang") => {
                eprintln!("skipped: {error}");
                return;
            }
            Err(error) => panic!("{error}"),
        };
        let strcpy = function(&declarations, "__strcpy_chk");
        let string = TypeRef::Pointer(Box::new(TypeRef::Char { signed: false }));
        assert_eq!(strcpy.signature.ret, string);
        assert_eq!(strcpy.signature.params[0].ty, string);
        assert_eq!(
            strcpy.signature.params[2].ty,
            TypeRef::Named("size_t".to_owned())
        );
        assert!(strcpy.no_throw);
        let printf = function(&declarations, "__printf_chk");
        assert_eq!(printf.signature.params[0].name.as_deref(), Some("flag"));
        assert!(printf.no_throw);
    }
}

const SYZLANG: &str = "
include <linux/mman.h>
resource fd[int32]: -1
resource sock[fd]
mmap_prot = PROT_READ, PROT_WRITE
more_prot = mmap_prot, 0x40
mmap(addr vma, len len[addr], prot flags[mmap_prot], fd fd) vma
openat$dir(fd fd, file ptr[in, filename]) fd
openat(fd fd, file ptr[in, filename], prot flags[more_prot]) fd
socket(domain int32) sock
ptrace(req int32, pid int32)
ptrace$peek(req int32, pid int32, addr int64, data int64)
fcntl_dupfd = F_DUPFD, F_DUPFD_CLOEXEC
fcntl_getflags = F_GETFD, F_GETFL
fcntl$dupfd(fd fd, cmd flags[fcntl_dupfd], arg fd) fd
fcntl$getflags(fd fd, cmd flags[fcntl_getflags])
fcntl$setflags(fd fd, cmd const[F_SETFD], flags int32)
mprotect$none(addr vma, len len[addr], prot const[0])
mprotect$any(addr vma, len len[addr], prot int32)
mprotect(addr vma, len len[addr], prot flags[mmap_prot])
pair {
\ta\tint32\t(out)
\tb\tint8:3
}
";

#[test]
fn syzlang_descriptions() {
    let path = file("test.txt", SYZLANG);
    let target = target();
    let numbers = syzlang::numbers(
        "#define __NR_mmap 9\n#define __NR_ptrace 101\n#define __NR_fcntl __NR3264_fcntl\n",
    )
    .unwrap();
    let options = syzlang::Options {
        target: &target,
        resolve: false,
        skip_includes: &[],
        probe_runner: None,
        numbers: &numbers,
    };
    let declarations = syzlang::parse(&[path.as_path()], &options).unwrap();
    // The plain form wins over a variant declared first.
    let openat = &function(&declarations, "openat").signature;
    assert_eq!(openat.params.len(), 3);
    assert_eq!(openat.ret, TypeRef::Named("fd".to_owned()));
    // A wider variant wins over the plain form: the call reads its
    // arguments. Numbers come from the table; a call it lacks has none.
    let ptrace = function(&declarations, "ptrace");
    assert_eq!(ptrace.signature.params.len(), 4);
    assert_eq!(ptrace.number, Some(101));
    assert_eq!(function(&declarations, "mmap").number, Some(9));
    assert_eq!(function(&declarations, "openat").number, None);
    assert!(!numbers.contains_key("fcntl"));
    let mmap = &function(&declarations, "mmap").signature;
    assert_eq!(
        mmap.params[2].ty,
        TypeRef::Named("flags mmap_prot".to_owned())
    );
    assert_eq!(mmap.ret, TypeRef::Pointer(Box::new(TypeRef::Void)));
    // A folded parameter keeps a set unless a form gives it another set
    // or kind of value: `fcntl`'s forms give `cmd` other sets, so no one
    // set holds all its commands. A constant or an integer (`mprotect$…`)
    // narrows the call and leaves the set.
    let fcntl = &function(&declarations, "fcntl").signature;
    assert_eq!(
        fcntl.params[1].ty,
        TypeRef::Int {
            signed: true,
            size: 8
        }
    );
    let mprotect = &function(&declarations, "mprotect").signature;
    assert_eq!(
        mprotect.params[2].ty,
        TypeRef::Named("flags mmap_prot".to_owned())
    );
    // A reference to another set is expanded; a number is its own value.
    let Definition::Enum(more) = &declarations.types["flags more_prot"] else {
        panic!("more_prot is not an enumeration");
    };
    let names: Vec<_> = more
        .variants
        .iter()
        .map(|v| (v.name.as_str(), v.value))
        .collect();
    assert_eq!(
        names,
        [
            ("PROT_READ", None),
            ("PROT_WRITE", None),
            ("0x40", Some(0x40))
        ]
    );
    // Resources are typedefs over their base: sock → fd → int32.
    let Definition::Typedef(sock) = &declarations.types["sock"] else {
        panic!("sock is not a typedef");
    };
    assert_eq!(sock.target, TypeRef::Named("fd".to_owned()));
    // Field attributes and bit-field widths are not part of the type.
    let pair = record(&declarations, "struct pair");
    let types: Vec<_> = pair
        .fields
        .as_ref()
        .unwrap()
        .iter()
        .map(|f| f.ty.clone())
        .collect();
    assert_eq!(
        types,
        [
            TypeRef::Int {
                signed: true,
                size: 4
            },
            TypeRef::Int {
                signed: true,
                size: 1
            }
        ]
    );
}

/// With a probe runner, the probe is run as `runner probe`, and the values
/// are what it prints: here a shell script that notes the program it was
/// given and runs it (`qemu-aarch64` runs a probe built for AArch64).
#[cfg(unix)]
#[test]
fn the_probe_runs_under_the_runner() {
    use std::os::unix::fs::PermissionsExt as _;

    let note = file("runner-ran", "");
    let runner = file(
        "runner.sh",
        &format!(
            "#!/bin/sh\necho \"$1\" > '{}'\nexec \"$1\"\n",
            note.display()
        ),
    );
    std::fs::set_permissions(&runner, std::fs::Permissions::from_mode(0o755)).unwrap();
    let path = file(
        "probe.txt",
        "include <linux/mman.h>\nmmap_prot = PROT_READ, PROT_WRITE\nmprotect(addr vma, len len[addr], prot flags[mmap_prot])\n",
    );
    let target = target();
    let options = syzlang::Options {
        target: &target,
        resolve: true,
        skip_includes: &[],
        probe_runner: runner.to_str(),
        numbers: &std::collections::BTreeMap::new(),
    };
    let declarations = syzlang::parse(&[path.as_path()], &options).unwrap();
    let Definition::Enum(prot) = &declarations.types["flags mmap_prot"] else {
        panic!("mmap_prot is not an enumeration");
    };
    let values: Vec<_> = prot
        .variants
        .iter()
        .map(|v| (v.name.as_str(), v.value))
        .collect();
    assert_eq!(values, [("PROT_READ", Some(1)), ("PROT_WRITE", Some(2))]);
    let ran = std::fs::read_to_string(&note).unwrap();
    assert!(ran.trim_end().ends_with("/probe"), "{ran}");
}

#[cfg(feature = "winmd")]
mod winmd {
    use binbun_typedb::database::TypeRef;
    use binbun_typegen::winmd::{Layouts, parse};
    use windows_metadata::writer::{
        self, AttributeType, HasAttribute, MemberRefParent, TypeDefOrRef,
    };
    use windows_metadata::{
        FieldAttributes, MethodAttributes, MethodCallAttributes, MethodImplAttributes,
        PInvokeAttributes, ParamAttributes, Signature, Type, TypeAttributes, TypeName, Value,
    };

    use super::{function, record, target};

    /// `SupportedArchitecture`'s bits: x64, ARM64.
    const X64: i32 = 2;
    const ARM64: i32 = 4;

    /// Metadata declaring a `CONTEXT` for x64 (`Rip`, after a `u64`) and
    /// one for ARM64 (`Pc`, after a `u32`), a structure for both, and a
    /// function of each architecture's: `RtlCaptureContext(CONTEXT *)`,
    /// both's, and `RtlCaptureContext2`, x64's only.
    fn metadata() -> std::path::PathBuf {
        let mut file = writer::File::new("Test");
        let value_type = TypeDefOrRef::TypeRef(file.TypeRef("System", "ValueType"));
        let object = TypeDefOrRef::TypeRef(file.TypeRef("System", "Object"));
        let supported = file.TypeRef(
            "Windows.Win32.Foundation.Metadata",
            "SupportedArchitectureAttribute",
        );
        let ctor = file.MemberRef(
            ".ctor",
            &Signature {
                types: vec![Type::I32],
                ..Signature::default()
            },
            MemberRefParent::TypeRef(supported),
        );
        let supported_on = |file: &mut writer::File, parent, arches| {
            file.Attribute(
                parent,
                AttributeType::MemberRef(ctor),
                &[(String::new(), Value::I32(arches))],
            );
        };
        let layout = TypeAttributes::Public | TypeAttributes::SequentialLayout;
        for (arches, first, field) in [(X64, Type::U64, "Rip"), (ARM64, Type::U32, "Pc")] {
            let context = file.TypeDef("Test", "CONTEXT", value_type, layout);
            file.Field("Flags", &first, FieldAttributes::Public);
            file.Field(field, &Type::U64, FieldAttributes::Public);
            supported_on(&mut file, HasAttribute::TypeDef(context), arches);
        }
        file.TypeDef("Test", "POINT", value_type, layout);
        file.Field("x", &Type::I32, FieldAttributes::Public);
        file.Field("y", &Type::I32, FieldAttributes::Public);
        file.TypeDef(
            "Test",
            "Apis",
            object,
            TypeAttributes::Public | TypeAttributes::Abstract | TypeAttributes::Sealed,
        );
        let context = Type::PtrMut(Box::new(Type::Name(TypeName::named("Test", "CONTEXT"))), 1);
        for (name, arches) in [("RtlCaptureContext", 0), ("RtlCaptureContext2", X64)] {
            let method = file.MethodDef(
                name,
                &Signature {
                    flags: MethodCallAttributes::default(),
                    return_type: Type::Void,
                    types: vec![context.clone()],
                },
                MethodAttributes::Public | MethodAttributes::Static | MethodAttributes::PInvokeImpl,
                MethodImplAttributes::PreserveSig,
            );
            file.Param("ContextRecord", 1, ParamAttributes::Out);
            file.ImplMap(method, PInvokeAttributes::NoMangle, name, "KERNEL32.dll");
            if arches != 0 {
                supported_on(&mut file, HasAttribute::MethodDef(method), arches);
            }
        }
        let dir = std::env::temp_dir().join(format!("binbun-typegen-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("Test.winmd");
        std::fs::write(&path, file.into_stream()).unwrap();
        path
    }

    /// Where the metadata declares a type or function per architecture,
    /// `--arch`'s is taken, and laid out; what it declares for all is
    /// taken for each.
    #[test]
    fn the_targets_architecture_is_taken() {
        let path = metadata();
        let mut target = target();
        target.os = "windows".to_owned();
        target.env = "msvc".to_owned();
        for (arch, field, offset, size, x64_only) in [
            ("x86_64", "Rip", 64, 16, true),
            ("aarch64", "Pc", 64, 16, false),
        ] {
            target.arch = arch.to_owned();
            let declarations = parse(&[path.as_path()], &target, Layouts::Computed).unwrap();
            let context = record(&declarations, "struct Test.CONTEXT");
            let fields = context.fields.as_ref().unwrap();
            assert_eq!(fields[1].name.as_deref(), Some(field), "{arch}");
            assert_eq!(fields[1].bit_offset, Some(offset), "{arch}");
            assert_eq!(context.size, Some(size), "{arch}");
            assert_eq!(record(&declarations, "struct Test.POINT").size, Some(8));
            let capture = &function(&declarations, "RtlCaptureContext").signature;
            assert_eq!(
                capture.params[0].ty,
                TypeRef::Pointer(Box::new(TypeRef::Named("struct Test.CONTEXT".to_owned())))
            );
            assert_eq!(
                declarations
                    .functions
                    .iter()
                    .any(|function| function.name == "RtlCaptureContext2"),
                x64_only,
                "{arch}"
            );
        }
        // An architecture the metadata does not distinguish is refused.
        target.arch = "riscv64".to_owned();
        assert!(parse(&[path.as_path()], &target, Layouts::Computed).is_err());
    }
}
