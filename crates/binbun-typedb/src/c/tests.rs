#![allow(clippy::unwrap_used, reason = "tests fail loudly")]

use super::*;

/// The structs whose layout GCC 15 gave (x86-64 and `-m32`, `offsetof`,
/// `sizeof`, `_Alignof`); the expectations below are its output.
const STRUCTS: &str = "
    struct a { char c; int i; short s; };
    struct __attribute__((packed)) b { char c; int i; short s; };
    union u { char c[5]; int i; };
    struct n { struct a inner[2]; long l; int (*f)(int, char **); unsigned flags; };
    struct bits { int a : 3; unsigned b : 7; char c; unsigned d : 30; unsigned e : 4; long long f : 33; };
    struct mixed { char tag; double d; long double ld; char *argv[3]; uint16_t w; };
    struct flex { int count; short items[]; };
    struct anon { int kind; union { int i; float f; }; char after; };
    struct zero { char a : 3; int : 0; char b; };
    struct packed_bits { char a; unsigned b : 12; } __attribute__((packed));
";

/// The size and alignment of `name` and the byte offset of its members.
fn layout(scope: &mut Scope<'_>, name: &str) -> (u64, u64, Vec<(String, u64)>) {
    let id = scope.lookup(name).unwrap();
    let Some(Type::Record(record)) = scope.types().ty(id) else {
        panic!("{name} is not a record");
    };
    let offsets = record
        .fields
        .iter()
        .flatten()
        .filter_map(|f| Some((f.name.clone()?, f.bit_offset? / 8)))
        .collect();
    (
        scope.size_of(id).unwrap(),
        scope.align_of(id).unwrap(),
        offsets,
    )
}

fn offset(fields: &[(String, u64)], name: &str) -> u64 {
    fields.iter().find(|(n, _)| n == name).unwrap().1
}

#[test]
fn records_are_laid_out_as_gcc_lays_them_out() {
    // (struct, member, LP64 offset, ILP32 offset), then sizes.
    let offsets = [
        ("struct a", "i", 4, 4),
        ("struct a", "s", 8, 8),
        ("struct b", "s", 5, 5),
        ("struct n", "l", 24, 24),
        ("struct n", "f", 32, 28),
        ("struct n", "flags", 40, 32),
        ("struct bits", "c", 2, 2),
        ("struct mixed", "d", 8, 4),
        ("struct mixed", "ld", 16, 12),
        ("struct mixed", "argv", 32, 24),
        ("struct mixed", "w", 56, 36),
        ("struct flex", "items", 4, 4),
        ("struct anon", "after", 8, 8),
        ("struct zero", "b", 4, 4),
    ];
    let sizes = [
        ("struct a", (12, 4), (12, 4)),
        ("struct b", (7, 1), (7, 1)),
        ("union u", (8, 4), (8, 4)),
        ("struct n", (48, 8), (36, 4)),
        ("struct bits", (16, 8), (16, 4)),
        ("struct mixed", (64, 16), (40, 4)),
        ("struct flex", (4, 4), (4, 4)),
        ("struct anon", (12, 4), (12, 4)),
        ("struct zero", (5, 1), (5, 1)),
        ("struct packed_bits", (3, 1), (3, 1)),
    ];
    for (model, wide) in [(DataModel::LP64, true), (DataModel::ILP32, false)] {
        let mut scope = Scope::new(model, None);
        scope.define(STRUCTS).unwrap();
        for (name, lp64, ilp32) in sizes {
            let (size, align, _) = layout(&mut scope, name);
            assert_eq!((size, align), if wide { lp64 } else { ilp32 }, "{name}");
        }
        for (name, member, lp64, ilp32) in offsets {
            let (_, _, fields) = layout(&mut scope, name);
            let expected = if wide { lp64 } else { ilp32 };
            assert_eq!(offset(&fields, member), expected, "{name}.{member}");
        }
    }
}

#[test]
fn bit_fields_take_bits_and_are_refused_by_microsoft_rules() {
    let mut scope = Scope::new(DataModel::LP64, None);
    scope.define(STRUCTS).unwrap();
    let id = scope.lookup("struct bits").unwrap();
    let Some(Type::Record(record)) = scope.types().ty(id) else {
        panic!("not a record");
    };
    let bits: Vec<(u64, Option<u32>)> = record
        .fields
        .iter()
        .flatten()
        .map(|f| (f.bit_offset.unwrap(), f.bit_width))
        .collect();
    assert_eq!(
        bits,
        [
            (0, Some(3)),
            (3, Some(7)),
            (16, None),
            (32, Some(30)),
            (64, Some(4)),
            (68, Some(33))
        ]
    );
    let mut windows = Scope::new(DataModel::LLP64, None);
    let error = windows.define("struct f { int a : 3; };").unwrap_err();
    assert_eq!(
        error.message,
        "bit-fields are laid out only for System V targets"
    );
    assert_eq!(error.span, 15..20);
    let error = scope.define("struct w { char a : 9; };").unwrap_err();
    assert_eq!(error.message, "a is wider than its type");
    let error = scope.define("struct w { float a : 2; };").unwrap_err();
    assert!(error.message.contains("not an integer"));
}

#[test]
fn declarators_read_as_c_reads_them() {
    let mut scope = Scope::new(DataModel::LP64, None);
    let spell = |scope: &mut Scope<'_>, c: &str| {
        let declared = scope.declaration(c).unwrap();
        scope.spell(declared.ty, declared.name.as_deref().unwrap_or(""))
    };
    assert_eq!(
        spell(&mut scope, "int (*)(int, char **)"),
        "int (*)(int, char **)"
    );
    // A parameter of array type is a pointer to its element.
    assert_eq!(
        spell(&mut scope, "int main(int argc, char *argv[])"),
        "int main(int argc, char **argv)"
    );
    assert_eq!(spell(&mut scope, "char *argv[]"), "char *argv[]");
    assert_eq!(
        spell(&mut scope, "int (*handlers[4])(int)"),
        "int (*handlers[4])(int)"
    );
    assert_eq!(
        spell(&mut scope, "char (*grid)[3][4]"),
        "char (*grid)[3][4]"
    );
    assert_eq!(
        spell(
            &mut scope,
            "void (*signal(int sig, void (*handler)(int)))(int)"
        ),
        "void (*signal(int sig, void (*handler)(int)))(int)"
    );
    assert_eq!(
        spell(&mut scope, "int printf(const char *format, ...);"),
        "int printf(char *format, ...)"
    );
    assert_eq!(spell(&mut scope, "unsigned long long"), "unsigned long");
    assert_eq!(spell(&mut scope, "long int x"), "long x");
    assert_eq!(spell(&mut scope, "int f(void)"), "int f(void)");
    assert_eq!(
        spell(&mut scope, "char buf[2 * (1 << 4) + 1]"),
        "char buf[33]"
    );
    let argv = scope.type_name("char **").unwrap();
    let Some(&Type::Pointer(inner)) = scope.types().ty(argv) else {
        panic!("not a pointer");
    };
    assert_eq!(scope.spell(inner, ""), "char *");
    assert_eq!(scope.size_of(argv), Some(8));
    let main = scope
        .declaration("int main(int argc, char **argv)")
        .unwrap();
    let Some(Type::Function(signature)) = scope.types().ty(main.ty) else {
        panic!("not a function");
    };
    let names: Vec<_> = signature.params.iter().map(|p| p.name.as_deref()).collect();
    assert_eq!(names, [Some("argc"), Some("argv")]);
    assert!(!signature.variadic);
}

#[test]
fn typedefs_enums_and_self_reference() {
    let mut scope = Scope::new(DataModel::LP64, None);
    let defined = scope
        .define(
            "typedef struct node node_t;
             struct node { node_t *next; int value; };
             enum color { RED, GREEN = 4, BLUE, LAST = BLUE * 2 };
             typedef struct { enum color c; char name[LAST]; } paint;
             typedef unsigned int u32, *pu32;",
        )
        .unwrap();
    assert_eq!(
        defined,
        [
            "node_t",
            "struct node",
            "enum color",
            "paint",
            "u32",
            "pu32"
        ]
    );
    let node = scope.lookup("node_t").unwrap();
    assert_eq!(scope.size_of(node), Some(16));
    let paint = scope.lookup("paint").unwrap();
    assert_eq!(scope.size_of(paint), Some(16));
    assert_eq!(scope.spell(paint, "p"), "paint p");
    let Some(Type::Record(record)) = scope.types().ty(scope.resolve(paint)) else {
        panic!("not a record");
    };
    assert_eq!(
        record.name.as_deref(),
        Some("paint"),
        "named by its typedef"
    );
    let color = scope.lookup("enum color").unwrap();
    let Some(Type::Enum(color)) = scope.types().ty(color) else {
        panic!("not an enum");
    };
    let values: Vec<_> = color.variants.iter().map(|v| v.value.unwrap()).collect();
    assert_eq!(values, [0, 4, 5, 10]);
    let pu32 = scope.lookup("pu32").unwrap();
    assert_eq!(scope.size_of(pu32), Some(8));
    assert!(scope.names().iter().any(|n| n == "struct node"));
    assert!(scope.names().iter().any(|n| n == "uint32_t"));
}

#[test]
fn enums_take_an_underlying_type_and_the_flag_enum_attribute() {
    let mut scope = Scope::new(DataModel::LP64, None);
    scope
        .define(
            "typedef uint16_t half;
             enum kind : half { NONE, EXEC = 2, DYN };
             enum __attribute__((flag_enum)) perm : uint32_t { X = 1, W = 2, R = 4 };
             struct h { enum kind k; enum kind : 3; enum perm p; };",
        )
        .unwrap();
    let kind = scope.lookup("enum kind").unwrap();
    assert_eq!(
        (scope.size_of(kind), scope.align_of(kind)),
        (Some(2), Some(2))
    );
    let perm = scope.lookup("enum perm").unwrap();
    let Some(Type::Enum(perm)) = scope.types().ty(perm) else {
        panic!("not an enum");
    };
    assert!(perm.flags);
    assert_eq!(perm.size, Some(4));
    let Some(Type::Enum(kind)) = scope.types().ty(kind) else {
        panic!("not an enum");
    };
    assert!(!kind.flags);
    // `enum kind : 3` in a record is an unnamed bit-field.
    let h = scope.lookup("struct h").unwrap();
    assert_eq!(scope.size_of(h), Some(8));
    // A floating underlying type is refused, and nothing is defined.
    assert!(scope.define("enum bad : double { A };").is_err());
    assert!(scope.lookup("enum bad").is_none());
}

#[test]
fn errors_name_where_and_define_nothing() {
    let mut scope = Scope::new(DataModel::LP64, None);
    let error = scope
        .define("struct ok { int a; }; struct bad { mystery_t x; };")
        .unwrap_err();
    assert_eq!(error.message, "mystery_t is not a type");
    assert_eq!(error.span, 35..44);
    assert!(scope.lookup("struct ok").is_none(), "nothing is defined");
    let cases: [(&str, &str, Range<usize>); 9] = [
        ("char *[2", "expected ']'", 8..8),
        ("int (*)(int", "expected ')'", 11..11),
        ("unsigned float", "unsigned float is not a type", 0..14),
        ("struct s { int a; int a; }", "a is declared twice", 22..23),
        ("struct s { struct t x; }", "x has no size", 20..21),
        ("int f(void x)", "a parameter cannot be void", 6..12),
        ("int x[-1]", "-1 is not an array's length", 6..8),
        ("int $", "unexpected '$'", 4..5),
        ("int a b", "expected the end of the declaration", 6..7),
    ];
    for (c, message, span) in cases {
        let error = scope.declaration(c).unwrap_err();
        assert_eq!((error.message.as_str(), error.span), (message, span), "{c}");
    }
    let error = scope.type_name("char *name").unwrap_err();
    assert_eq!(
        (error.message.as_str(), error.span),
        ("unexpected name name", 6..10)
    );
    // A pointer to an incomplete struct is a type.
    let p = scope.type_name("struct later *").unwrap();
    assert_eq!(scope.size_of(p), Some(8));
    assert!(scope.type_name("struct later").is_ok());
    let later = scope.lookup("struct later").unwrap();
    assert_eq!(scope.size_of(later), None);
}

#[test]
fn a_definition_printed_reads_back_to_the_same_layout() {
    let mut scope = Scope::new(DataModel::LP64, None);
    scope.define(STRUCTS).unwrap();
    for name in [
        "struct n",
        "struct bits",
        "struct anon",
        "struct flex",
        "union u",
    ] {
        let id = scope.lookup(name).unwrap();
        let text = scope.definition(id).unwrap();
        let mut again = Scope::new(DataModel::LP64, None);
        again
            .define("struct a { char c; int i; short s; };")
            .unwrap();
        again.define(&text).unwrap();
        assert_eq!(layout(&mut again, name), layout(&mut scope, name), "{text}");
    }
    let anon = scope.lookup("struct anon").unwrap();
    assert_eq!(
        scope.definition(anon).unwrap(),
        "struct anon {\n    int kind;\n    union {\n        int i;\n        float f;\n    };\n    char after;\n};"
    );
}

#[test]
fn an_enumeration_printed_reads_back_as_it_was() {
    let mut scope = Scope::new(DataModel::LP64, None);
    scope
        .define(
            "enum __attribute__((flag_enum)) perm : uint16_t { X = 1, W = 2, R = 4, U };
             typedef enum { BAD = -1, OK = 7 } status_t;
             enum big { HUGE = 0x80000000 };",
        )
        .unwrap();
    let text = |scope: &mut Scope<'_>, name: &str| {
        let id = scope.lookup(name).unwrap();
        scope.definition(id).unwrap()
    };
    let perm = text(&mut scope, "enum perm");
    // Its size is kept, not the signedness of the type it was written
    // with: signed, as no constant needs the top bit.
    assert_eq!(
        perm,
        "enum __attribute__((flag_enum)) perm : int16_t {\n    X = 0x1,\n    W = 0x2,\n    R = 0x4,\n    U = 0x5,\n};"
    );
    // Anonymous: the typedef naming it is what is defined.
    let status = text(&mut scope, "status_t");
    assert_eq!(
        status,
        "typedef enum : int32_t {\n    BAD = -1,\n    OK = 7,\n} status_t;"
    );
    // Unsigned where a constant needs the top bit.
    let big = text(&mut scope, "enum big");
    assert!(big.starts_with("enum big : uint32_t {"), "{big}");
    for (name, c) in [
        ("enum perm", &perm),
        ("status_t", &status),
        ("enum big", &big),
    ] {
        let mut again = Scope::new(DataModel::LP64, None);
        again.define(c).unwrap();
        let read = |scope: &mut Scope<'_>| {
            let id = scope.lookup(name).unwrap();
            let id = scope.resolve(id);
            let Some(Type::Enum(definition)) = scope.types().ty(id) else {
                panic!("{name} is no enumeration");
            };
            (
                definition.size,
                definition.flags,
                definition.variants.clone(),
            )
        };
        assert_eq!(read(&mut again), read(&mut scope), "{c}");
    }
}

#[test]
fn a_sixteen_byte_integer_reads_back_as_it_is_printed() {
    let mut scope = Scope::new(DataModel::LP64, None);
    scope
        .define("struct w { char c; unsigned __int128 x; __int128_t y; signed __int128 z; };")
        .unwrap();
    // GCC on x86-64: 16-byte integers are 16-byte aligned.
    let (size, align, fields) = layout(&mut scope, "struct w");
    assert_eq!((size, align), (64, 16));
    assert_eq!(offset(&fields, "x"), 16);
    assert_eq!(offset(&fields, "y"), 32);
    assert_eq!(offset(&fields, "z"), 48);
    let id = scope.lookup("struct w").unwrap();
    let text = scope.definition(id).unwrap();
    assert!(text.contains("unsigned __int128 x;"), "{text}");
    let mut again = Scope::new(DataModel::LP64, None);
    again.define(&text).unwrap();
    assert_eq!(
        layout(&mut again, "struct w"),
        layout(&mut scope, "struct w")
    );
    assert!(scope.define("struct bad { short __int128 v; };").is_err());
}

#[test]
fn data_models_follow_the_target() {
    let model = DataModel::of("x86_64", "linux");
    assert_eq!(model, DataModel::LP64);
    assert_eq!(DataModel::of("x86_64", "windows"), DataModel::LLP64);
    assert_eq!(DataModel::of("x86", "linux"), DataModel::ILP32);
    let arm = DataModel::of("aarch64", "linux");
    assert!(!arm.char_signed);
    assert_eq!(arm.long_double, FloatFormat::Quad);
    let mut windows = Scope::new(DataModel::LLP64, None);
    let long = windows.type_name("long").unwrap();
    assert_eq!(windows.size_of(long), Some(4));
    assert_eq!(windows.spell(long, ""), "int");
}

#[test]
fn library_types_are_named_and_copied() {
    let library = TypeLibrary::for_target("x86_64", "linux").unwrap();
    let mut scope = Scope::new(DataModel::LP64, Some(&library));
    let declared = scope
        .declaration("int fstat(int fd, struct stat *buf)")
        .unwrap();
    let Some(Type::Function(signature)) = scope.types().ty(declared.ty) else {
        panic!("not a function");
    };
    let buf = signature.params[1].ty;
    let Some(&Type::Pointer(stat)) = scope.types().ty(buf) else {
        panic!("not a pointer");
    };
    assert_eq!(scope.size_of(stat), Some(144), "glibc's x86-64 struct stat");
    let file = scope.type_name("FILE *").unwrap();
    assert_eq!(scope.spell(file, "stream"), "FILE *stream");
    assert!(scope.names().iter().any(|n| n == "struct stat"));
    // The scope's own definitions come first.
    scope.define("struct stat { int mine; };").unwrap();
    let mine = scope.lookup("struct stat").unwrap();
    assert_eq!(scope.size_of(mine), Some(4));
}
