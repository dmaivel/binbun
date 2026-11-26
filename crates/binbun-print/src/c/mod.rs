//! An L2 function as C: [`function`] gives a [`Document`] holding a whole
//! translation unit for it (the header comment with the compile flags,
//! `#include "binbun_defs.h"`, the structs, globals, callees and intrinsics it
//! uses, then the function), and [`Counts`] of what readers and the
//! recompile metric care about.
//!
//! # Exact lowering, minimal casts
//!
//! The output is compiled with `-fwrapv -fno-strict-aliasing` by GCC or
//! Clang, whose extensions it uses: `__int128`, vector types, and
//! arithmetic on a `void *` in bytes. Every C expression the printer
//! builds carries its C type and what is known of how its value relates
//! to the L2 value it stands for (of the L2 width `w`): whether the C
//! value *is* the unsigned value of those `w` bits ("zero"), the signed
//! value ("sign"), or only agrees in its low `w` bits.
//! Each operation asks its operands for what it needs, and a cast is
//! emitted only where that is not already so:
//!
//! - `+ - * & | ^ ~ <<` need only the low bits; the result is exact when
//!   C computes it at exactly `w` bits (after the integer promotions and
//!   the usual arithmetic conversions), and an operand is widened (a
//!   literal by a suffix, else a cast) where C would compute it narrower.
//! - Unsigned comparisons, division, `>>` and zero extension need zero
//!   values; signed ones need sign values. A value that is not is cast to
//!   the `w`-bit type of that signedness (`(uint8_t)(a + b) < a`), or
//!   masked or sign-extended by a helper at widths C lacks.
//!   A `+`, `-` or `*` of a literal computed in the signed type of
//!   exactly `w` bits (32 or 64: narrower operands are promoted to
//!   `int`) is made a zero value by printing the literal unsigned
//!   instead (`x - 14U <= 1`, not `(uint32_t)(x - 14) <= 1`): C then
//!   computes in the unsigned type of `w` bits.
//! - `==` and `!=` need nothing more where C compares at exactly `w` bits,
//!   else two zero or two sign values (whichever costs fewer casts). No
//!   comparison or `?:` mixes a signed operand C would convert to
//!   unsigned (`-Wsign-compare`): that operand is cast instead.
//! - Pointers: two of one type compare as they are (`==`, `!=`, and
//!   unsigned `<`, `<=`); a pointer compares with the constant 0 by `==`
//!   and `!=` as it is (C's null pointer comparison); other comparisons
//!   take the pointers' bits. `p - q` of two byte or `void` pointers of
//!   one type is their distance; `p + i * s` (no constant) with `p`
//!   surely a pointer to `s` bytes is `p + i`. A select of a pointer (or
//!   function pointer) and the constant 0 is the pointer's type, with 0
//!   as C's null pointer constant (`c ? p : 0`, not
//!   `(T *)(c ? (uint64_t)p : 0)`).
//! - Extensions emit nothing (C converts by value); truncations emit
//!   nothing until a clean value is needed; assignments truncate.
//! - Literals are printed in the signedness and type the use needs (`int`
//!   where it holds them, else the other operand's type, else the
//!   narrowest that does), constants folded through extractions and
//!   extensions; `x + -1` is `x - 1`, `x = x + 1` is `x++`.
//! - A 1-bit `and`/`or` is `&&`/`||` when its right operand reads no
//!   memory (evaluating it or not is then the same); a 1-bit sign
//!   extension is `-x`.
//! - Loads are `*(T *)(p + k)` (`*(T *)p` at `p` itself: any pointer
//!   converts to `T *`), or `p[i]`, `p->field` and `*p` when the pointer's
//!   type allows (at a union field, its member of the access's type:
//!   `v.field.w32`); pointer arithmetic is scaled to the pointee or done in
//!   bytes, a pointer plus or minus a byte index too: on a `void *` as it
//!   is (`p + i`, `*(int32_t *)(p - 32)`), on another pointer through a
//!   byte pointer (`(uint8_t *)p + i`), not `(uint64_t)p + i`; an index
//!   typed a pointer is added as its integer value.
//! - Shifts by counts not below the width, divisions that may trap,
//!   rotations, counts, byte swaps, flags and double-width products are
//!   `binbun_defs.h` helpers with L0's meaning.
//! - L0's canonical-address check of a 64-bit address `p`, `if
//!   (sext(extract(p, 0, 48)) != p) trap` (either operand order) with a
//!   `Protection` (#GP) or `Stack` (#SS) trap alone in the arm and no
//!   `else`, is one statement: `binbun_check_canonical(p);` or
//!   `binbun_check_canonical_stack(p);`, `binbun_defs.h`'s macros doing that
//!   test and trap on the 64 bits of `p` (an integer, a data or a code
//!   pointer, evaluated once). Any other shape (another width or trap, an
//!   `else`, more in the arm, a condition combined with others) keeps the
//!   explicit test.
//! - Values wider than 128 bits and lane-wise operations are GCC's and
//!   Clang's vector extensions with `binbun_defs.h`'s types (`u8x16`, `u64x4`,
//!   each `aligned(1)`; [`vector`]): `a == b` lane by lane, `(u8x16)x`
//!   to view a 128-bit integer's lanes, `((u32x8)v)[3]` for a lane,
//!   `(u128x2){low, high}` for halves, `mask_bits`, `blend`, `splat` and
//!   the lane-wise shifts for what C has no operator for.
//!
//! # Names
//!
//! Names from the binary are made C identifiers (`foo.cold` →
//! `foo_cold`, `printf@plt` → `printf`), never a keyword or a `binbun_defs.h`
//! helper, and unique in the translation unit: callees and globals are
//! named first, so a colliding local is the one renamed. A changed name
//! keeps the original in a comment, and a callee's declaration links to
//! its symbol (`BINBUN_SYMBOL("foo.cold")`); a second signature for one
//! callee is a second declaration of the same symbol.
//! An import called through a slot the loader fixes
//! ([`Callee::Import`](binbun_ast::ir::Callee::Import)) is a callee named
//! by its import ([`Image::import`]), declared as a function.
//!
//! # What the printer requires
//!
//! A function binbun-ast's verifier accepts. Refused ([`PrintError`]):
//! lane-wise divisions, rotations, counts and byte swaps, float lanes but
//! for arithmetic and conversions, values wider than 128 bits but for
//! 256- and 512-bit ones moved, built, taken apart, extended, compared
//! and combined bitwise (`vector`'s list), floating-point status,
//! roundings other than to nearest (but for rounding to integral and
//! conversion to integers), x87 extended and half-precision arithmetic,
//! memory accesses of 3, 5, 6 or 7 bytes, carries and overflows at widths
//! C has no type for, escape
//! operands wider than 64 bits, overlapping struct fields, statements
//! nested more than 100 deep, and expressions past the printing budgets
//! (shared operands printed at each use, deep right-nested operators).
//!
//! Two differences are accepted: a `Select` (C's `?:`) evaluates only the
//! chosen arm, so a load in the other arm that would fault does not (an
//! L2 pass should hoist such loads); and a float operation whose result
//! is a NaN gives the target's NaN, where L0 gives the default NaN.
//!
//! # Instructions without semantics
//!
//! An opaque intrinsic (an architecture's `lift_opaque`) prints as its
//! instruction's text, as [`Opaque`] says: a call of `binbun_defs.h`'s that
//! compiles, or `__asm { … }` blocks, which do not ([`Counts::asm`]). Its
//! inputs are not printed, and of its outputs only those the code after
//! it reads.
//!
//! # Unknown values
//!
//! A value the architecture leaves undefined (SHRD's OF), which
//! processors set differently, is never a constant: a `binbun_defs.h` helper
//! no compiler folds (`binbun_undefined_bool()`), or in the reading view
//! ([`Opaque::Asm`]) a register-style name declared from it
//! (`_OF_undefined`), with a comment naming the instruction
//! ([`Counts::unknowns`]). What a call leaves in a register, an entry
//! value no parameter holds and lowering's fallback are named in both
//! views (`_RDX_clobbered`, `_RCX_entry`, `_unknown`); the reading view
//! leaves a local merged from several paths unassigned on a path that
//! would give it one. Values at a landing pad or read before any write
//! print as `0`, counted.

mod chars;
mod enums;
mod expr;
mod float;
mod memory;
mod stmt;
mod thread;
mod types;
mod unknown;
mod unlifted;
mod value;
mod vector;

pub use memory::string_literal;
pub use thread::ThreadPointer;
pub use unknown::Unknowns;
pub use unlifted::{Opaque, Unlifted};

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use core::cell::Cell;
use core::fmt;

use binbun_ast::ir::{
    Block, Call, Callee as AstCallee, Expr, ExprId, Function, LabelId, Node, Origin, Place, Stmt,
    StmtId, VarId, VarKind, Variable,
};
use binbun_ast::types::{Type, TypeId, Types};
use binbun_ast::verify::expr_width;
use binbun_semantics::Declarations;
use binbun_semantics::ir::RegisterId;

use crate::document::{BlockKind, Braces, Doc, Document, TokenKind};
use crate::style::{Naming, Placement, Style};

/// What a printed function contains, for readers and the recompile
/// metric.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Counts {
    /// Casts emitted (each `(T)` in the output).
    pub casts: usize,
    /// `goto` statements, those standing for a `break` or `continue` that
    /// leaves a construct other than the innermost included.
    pub gotos: usize,
    /// Constructs C cannot say: escape helpers called.
    pub escapes: usize,
    /// Instructions without semantics printed (an `unlifted` call or an
    /// `__asm` block's line each).
    pub unlifted: usize,
    /// `__asm` blocks printed ([`Opaque::Asm`]): a function with one is no
    /// C a compiler takes.
    pub asm: usize,
    /// Unknown values printed, by where they come from; those the
    /// architecture leaves undefined are processor-dependent.
    pub unknowns: Unknowns,
}

/// A printed function.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Printed {
    /// The translation unit.
    pub document: Document,
    /// What it contains.
    pub counts: Counts,
}

/// Why a function could not be printed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrintError {
    /// The node (`None`: the function as a whole).
    pub node: Option<Node>,
    /// What is wrong or unsupported.
    pub message: String,
}

impl fmt::Display for PrintError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.node {
            Some(node) => write!(f, "{node}: {}", self.message),
            None => f.write_str(&self.message),
        }
    }
}

/// An error at `node`.
fn error(node: Option<Node>, message: impl Into<String>) -> PrintError {
    PrintError {
        node,
        message: message.into(),
    }
}

/// `binbun_defs.h`, to write next to the output.
pub const HEADER: &str = include_str!("../../include/binbun_defs.h");

/// What the printer knows about the image a function comes from: the
/// names of its functions and objects, and its read-only data (a global
/// in it is declared `const`; a `char` array in it holding a string is
/// that string's literal, as is a constant address of a string where a
/// `char *` is expected), how its platform's thread pointer is spelled,
/// and how wide its `long` is.
pub trait Image {
    /// The name of the function or object at `address`, if it has one.
    fn symbol(&self, address: u64) -> Option<String>;

    /// The name of the import whose slot is at `slot`, if one is (a call
    /// through it, [`Callee::Import`](binbun_ast::ir::Callee::Import), is a
    /// call of that import).
    fn import(&self, _slot: u64) -> Option<String> {
        None
    }

    /// Whether the program cannot change any of the `bytes` bytes at
    /// `address` once loaded.
    fn read_only(&self, address: u64, bytes: u64) -> bool;

    /// The `bytes` bytes at `address`, if the program cannot change them
    /// and the image says what they are.
    fn constant(&self, address: u64, bytes: u64) -> Option<Vec<u8>>;

    /// The bytes of the string at `address` (its NUL not included), if
    /// they and the NUL are in read-only data.
    fn string(&self, address: u64) -> Option<Vec<u8>>;

    /// How C reaches the thread pointer on the image's platform (by
    /// default the ELF TLS ABIs' `__builtin_thread_pointer()`).
    fn thread_pointer(&self) -> ThreadPointer {
        ThreadPointer::Builtin
    }

    /// The width of C's `long` on the image's platform, in bits, which
    /// says how [`IntSpelling::Plain`](crate::style::IntSpelling::Plain)
    /// spells 64 bits: `long` where it is 64 (LP64: 64-bit Linux and
    /// macOS, the default), else `long long` (LLP64: 64-bit Windows;
    /// ILP32).
    fn long_width(&self) -> u16 {
        64
    }

    /// Whether an environment variable of `register`
    /// ([`VarKind::Environment`]) holds the thread pointer (by default
    /// every one does); the others (floating-point control registers) are
    /// read at entry into a local ([`entry_reader`]).
    fn is_thread_pointer(&self, _register: RegisterId) -> bool {
        true
    }

    /// The instruction at `address`, which has no semantics, as the
    /// listing shows it: its text and what its outputs are called (by
    /// default none: the printer says only where it is).
    fn unlifted(&self, _address: u64) -> Option<Unlifted> {
        None
    }

    /// The text of the instruction at `address`, as the listing shows it
    /// (by default none: the printer says only where it is).
    fn instruction(&self, _address: u64) -> Option<String> {
        None
    }
}

/// The `binbun_defs.h` helper that reads register `name` (a floating-point
/// control register a convention makes the environment), if there is one.
/// Its value at entry is the caller's (the convention keeps it, or the
/// status flags the caller left), which a function that keeps its
/// controls reads as an environment variable; C reads it once, first
/// thing, into a local.
fn entry_reader(name: &str) -> Option<&'static str> {
    match name {
        "mxcsr" => Some("binbun_read_mxcsr"),
        "fcw" => Some("binbun_read_fcw"),
        "fpcr" => Some("binbun_read_fpcr"),
        _ => None,
    }
}

/// Names alone: nothing is read-only.
impl<F: Fn(u64) -> Option<String>> Image for F {
    fn symbol(&self, address: u64) -> Option<String> {
        self(address)
    }

    fn read_only(&self, _: u64, _: u64) -> bool {
        false
    }

    fn constant(&self, _: u64, _: u64) -> Option<Vec<u8>> {
        None
    }

    fn string(&self, _: u64) -> Option<Vec<u8>> {
        None
    }
}

/// An image whose `long` is `.0` bits wide, and nothing more: no names,
/// nothing read-only.
struct Unnamed(u16);

impl Image for Unnamed {
    fn symbol(&self, _: u64) -> Option<String> {
        None
    }

    fn read_only(&self, _: u64, _: u64) -> bool {
        false
    }

    fn constant(&self, _: u64, _: u64) -> Option<Vec<u8>> {
        None
    }

    fn string(&self, _: u64) -> Option<Vec<u8>> {
        None
    }

    fn long_width(&self) -> u16 {
        self.0
    }
}

/// `function` as a C translation unit, under `style`'s presentation
/// options, with intrinsic names from `declarations` and the names of
/// functions and globals at addresses, and the read-only data, from
/// `image`; its instructions without semantics as `opaque` says.
///
/// # Errors
///
/// A node the printer does not support (see the module documentation),
/// or one that breaks the verifier's rules.
pub fn function(
    function: &Function,
    declarations: &Declarations,
    style: &Style,
    image: &dyn Image,
    opaque: Opaque,
) -> Result<Printed, PrintError> {
    // The reading view leaves a merged local unassigned on the paths where
    // it would be given a named unknown value ([`unknown::unassigned`]).
    let shown;
    let function = match opaque {
        Opaque::Asm => {
            let hidden = unknown::unassigned(function, &held(function));
            if hidden.is_empty() {
                function
            } else {
                shown = unknown::without(function, &hidden);
                &shown
            }
        }
        Opaque::Calls => function,
    };
    let mut printer = Printer::new(function, declarations, style, image, opaque)?;
    printer.unaligned = opaque == Opaque::Calls;
    printer.prepass(&function.body, &mut Vec::new(), 0);
    let mut body = printer.block(&function.body)?;
    body.splice(0..0, printer.unused_parameters());
    body.splice(0..0, printer.unread_frames());
    let head = printer.signature()?;
    let locals = printer.locals()?;
    let mut items = opening(function, image, &printer.function_name);
    let declared = printer.declarations()?;
    let structs = printer.struct_definitions()?;
    let typedefs = printer.unaligned_definitions(&[&head, &body, &locals, &declared, &structs]);
    let mut function_body = locals;
    if !function_body.is_empty() && !body.is_empty() {
        function_body.push(Doc::Group(Vec::new()));
    }
    function_body.extend(body);
    let mut definition = vec![Doc::Group(head)];
    definition.push(Doc::Block {
        kind: BlockKind::Function,
        braces: Braces::Required,
        body: function_body,
        node: None,
    });
    // The enumerations' constants the output names and the tags it
    // declares values with (not those of attempts discarded), defined
    // first.
    let enums = {
        let named = Document {
            items: definition
                .iter()
                .chain(&declared)
                .chain(&structs)
                .chain(&typedefs)
                .cloned()
                .collect(),
        };
        let tokens = named.tokens();
        let used = tokens
            .iter()
            .filter(|token| token.kind == TokenKind::Macro)
            .map(|token| token.text.as_str())
            .collect();
        let tags = tokens
            .iter()
            .zip(tokens.iter().skip(1))
            .filter(|(keyword, _)| keyword.kind == TokenKind::Keyword && keyword.text == "enum")
            .filter(|(_, tag)| tag.kind == TokenKind::Type)
            .map(|(_, tag)| tag.text.as_str())
            .collect();
        printer.enum_definitions(&used, &tags)?
    };
    for section in [enums, typedefs, structs, declared] {
        if !section.is_empty() {
            items.push(Doc::Group(Vec::new()));
            items.extend(section);
        }
    }
    items.push(Doc::Group(Vec::new()));
    items.push(Doc::Group(definition));
    let document = Document { items };
    let mut counts = printer.counts;
    // Casts are the operator parentheses (those of discarded attempts are
    // not in the document).
    counts.casts = document
        .tokens()
        .iter()
        .filter(|token| token.kind == TokenKind::Operator && token.text == "(")
        .count();
    Ok(Printed { document, counts })
}

/// A translation unit's first lines: what `function` (printed as `name`)
/// is, how to compile it, the header.
fn opening(function: &Function, image: &dyn Image, name: &str) -> Vec<Doc> {
    let renamed = function
        .name
        .clone()
        .or_else(|| image.symbol(function.address))
        .filter(|original| original != name)
        .map(|original| format!(" ({original})"))
        .unwrap_or_default();
    vec![
        Doc::comment(
            comment(&format!(
                "{name}{renamed} at {:#x}, decompiled by binbun.",
                function.address
            )),
            None,
        ),
        Doc::comment(
            "/* Compile with -fwrapv -fno-strict-aliasing (see binbun_defs.h). */",
            None,
        ),
        Doc::Group(vec![
            Doc::keyword("#include", None),
            Doc::Space,
            Doc::string("\"binbun_defs.h\"", None),
        ]),
    ]
}

/// The structs and unions `ids` of `types` as C, as a function using them
/// prints them: the forward declarations, then the definitions (with
/// those of the structs they hold or point to), under `style`'s options
/// where `long` is `long_width` bits ([`Image::long_width`]), with
/// intrinsic names from `declarations`.
///
/// # Errors
///
/// An id is no struct or union, or one holds itself.
pub fn definitions(
    types: &Types,
    ids: &[TypeId],
    declarations: &Declarations,
    style: &Style,
    long_width: u16,
) -> Result<Document, PrintError> {
    let function = Function::new(0, types.clone());
    let image = Unnamed(long_width);
    let mut printer = Printer::new(&function, declarations, style, &image, Opaque::Calls)?;
    for &id in ids {
        printer.aggregate_specifier(id)?;
    }
    let items = printer.struct_definitions()?;
    Ok(Document { items })
}

/// The declaration `ty name;` (`ty` of `types`) as C, as a function
/// using a global of that type declares it (without `extern`), under
/// `style`'s options where `long` is `long_width` bits, with intrinsic
/// names from `declarations`.
///
/// # Errors
///
/// `ty` is no type of `types`, or not one C can declare.
pub fn declaration(
    types: &Types,
    ty: TypeId,
    name: &str,
    declarations: &Declarations,
    style: &Style,
    long_width: u16,
) -> Result<Document, PrintError> {
    let function = Function::new(0, types.clone());
    let image = Unnamed(long_width);
    let mut printer = Printer::new(&function, declarations, style, &image, Opaque::Calls)?;
    let mut line = printer.declare(ty, vec![Doc::name(TokenKind::Global, name, false, None)])?;
    line.push(Doc::punct(";", None));
    Ok(Document {
        items: vec![Doc::Group(line)],
    })
}

/// Every type of `types`, by id, as C names it in a cast (`uint32_t[4]`,
/// `struct pair *`, `void (*)(int32_t)`; `None` for one C cannot name),
/// under `style`'s options where `long` is `long_width` bits, with
/// intrinsic names from `declarations`.
///
/// # Errors
///
/// The printer cannot start (`declarations` lack a type it needs).
pub fn type_names(
    types: &Types,
    declarations: &Declarations,
    style: &Style,
    long_width: u16,
) -> Result<Vec<Option<Document>>, PrintError> {
    let function = Function::new(0, types.clone());
    let image = Unnamed(long_width);
    let mut printer = Printer::new(&function, declarations, style, &image, Opaque::Calls)?;
    Ok(types
        .iter()
        .map(|(id, _)| {
            let line = printer.declare(id, Vec::new()).ok()?;
            Some(Document {
                items: vec![Doc::Group(line)],
            })
        })
        .collect())
}

/// Names given out, unique in the translation unit.
#[derive(Debug, Default)]
struct Names {
    taken: BTreeSet<String>,
}

/// Words the output may not use as names: C's keywords, `binbun_defs.h`'s
/// helpers and the standard types and macros it uses.
const RESERVED: &[&str] = &[
    "auto",
    "break",
    "case",
    "char",
    "const",
    "continue",
    "default",
    "do",
    "double",
    "else",
    "enum",
    "extern",
    "float",
    "for",
    "goto",
    "if",
    "inline",
    "int",
    "long",
    "register",
    "restrict",
    "return",
    "short",
    "signed",
    "sizeof",
    "static",
    "struct",
    "switch",
    "typedef",
    "union",
    "unsigned",
    "void",
    "volatile",
    "while",
    "bool",
    "true",
    "false",
    "NULL",
    "main",
    "int8_t",
    "int16_t",
    "int32_t",
    "int64_t",
    "uint8_t",
    "uint16_t",
    "uint32_t",
    "uint64_t",
    "uintptr_t",
    "intptr_t",
    "size_t",
    "ptrdiff_t",
    "va_list",
    "va_start",
    "INT64_MIN",
    "popcount",
    "clz",
    "ctz",
    "clz_n",
    "ctz_n",
    "even_parity8",
    "bswap",
    "shl",
    "lshr",
    "ashr",
    "rotl",
    "rotr",
    "rotl_n",
    "rotr_n",
    "sext_n",
    "low8",
    "low16",
    "low32",
    "high8",
    "add_carry",
    "add_overflow",
    "sub_borrow",
    "sub_overflow",
    "nibble_carry",
    "umulh",
    "smulh",
    "udiv",
    "urem",
    "sdiv",
    "srem",
    "as_f32",
    "as_f64",
    "f32_bits",
    "f64_bits",
    "fcmp",
    "float_to_sint",
    "float_to_uint",
    "float_add",
    "float_sub",
    "float_mul",
    "float_div",
    "float_sqrt",
    "float_fma",
    "float_convert",
    "f32_from_sint",
    "f64_from_sint",
    "float_add_status",
    "float_sub_status",
    "float_mul_status",
    "float_div_status",
    "float_sqrt_status",
    "float_fma_status",
    "float_round_status",
    "float_convert_status",
    "f32_from_sint_status",
    "f64_from_sint_status",
    "float_to_sint32_status",
    "float_to_sint64_status",
    "float_compare_status",
    "float_compare_signaling_status",
    // Vectors (and their types: `vector_name`).
    "mask_bits",
    "lanes_from_bits",
    "splat",
    "blend",
    "shl_lanes",
    "lshr_lanes",
    "ashr_lanes",
    // Instructions without semantics.
    "unlifted",
    "unlifted_bool",
    "unlifted_u8",
    "unlifted_u16",
    "unlifted_u32",
    "unlifted_u64",
    "unlifted_u128",
    "unlifted_u256",
    "unlifted_u512",
    // The thread pointer's spellings `binbun_defs.h` defines (Microsoft's).
    "NtCurrentTeb",
    "KeGetPcr",
    "__readgsbyte",
    "__readgsword",
    "__readgsdword",
    "__readgsqword",
    "__writegsbyte",
    "__writegsword",
    "__writegsdword",
    "__writegsqword",
    "__readfsbyte",
    "__readfsword",
    "__readfsdword",
    "__readfsqword",
    "__writefsbyte",
    "__writefsword",
    "__writefsdword",
    "__writefsqword",
    // GNU C keywords and C11's, which no symbol may be named either.
    "__alignof__",
    "__asm",
    "__asm__",
    "__attribute__",
    "__complex__",
    "__const",
    "__extension__",
    "__func__",
    "__FUNCTION__",
    "__imag__",
    "__inline",
    "__inline__",
    "__int128",
    "__label__",
    "__PRETTY_FUNCTION__",
    "__real__",
    "__restrict",
    "__restrict__",
    "__signed__",
    "__thread",
    "__typeof",
    "__typeof__",
    "__volatile__",
    "_Alignas",
    "_Alignof",
    "_Atomic",
    "_Bool",
    "_Complex",
    "_Generic",
    "_Imaginary",
    "_Noreturn",
    "_Static_assert",
    "_Thread_local",
];

/// Prefixes no name may start with: `binbun_defs.h`'s, and the compilers'
/// builtins. A name with one gets an `x` in front (a suffix cannot fix it).
const RESERVED_PREFIXES: &[&str] = &["binbun_", "BINBUN_", "__builtin"];

/// A variable at `offset` from the stack pointer at entry, as
/// [`Naming::Registers`] names it: `var_58` below it, `arg_8` above.
fn stack_name(offset: i64) -> String {
    if offset < 0 {
        format!("var_{:x}", offset.unsigned_abs())
    } else {
        format!("arg_{offset:x}")
    }
}

impl Names {
    /// A name like `base` (made a C identifier), not given out before.
    fn fresh(&mut self, base: &str) -> String {
        let mut base = sanitize(base);
        if RESERVED_PREFIXES
            .iter()
            .any(|prefix| base.starts_with(prefix))
        {
            base.insert(0, 'x');
        }
        let mut name = base.clone();
        let mut counter = 2;
        while self.taken.contains(&name)
            || RESERVED.contains(&name.as_str())
            || types::vector_name(&name)
        {
            name = format!("{base}_{counter}");
            counter += 1;
        }
        self.taken.insert(name.clone());
        name
    }

    /// Takes `name` itself, if it is a C identifier no name has and no
    /// rule keeps (not suffixed: a name that must stay as declared, an
    /// enumeration's constant).
    fn claim(&mut self, name: &str) -> bool {
        let free = sanitize(name) == name
            && !RESERVED_PREFIXES
                .iter()
                .any(|prefix| name.starts_with(prefix))
            && !RESERVED.contains(&name)
            && !types::vector_name(name)
            && !self.taken.contains(name);
        if free {
            self.taken.insert(String::from(name));
        }
        free
    }
}

/// `name` as a C identifier: up to an `@` (symbol versions), other
/// characters replaced by `_`, never starting with a digit.
fn sanitize(name: &str) -> String {
    let name = name.split('@').next().unwrap_or_default();
    let mut out: String = name
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();
    if out.is_empty() || out.starts_with(|c: char| c.is_ascii_digit()) {
        out.insert_str(0, "n_");
    }
    out
}

/// A callee by address, as declared.
#[derive(Clone, Debug)]
struct Callee {
    name: String,
    signature: TypeId,
    /// Whether binbun made its name up (no symbol named it).
    automatic: bool,
    /// The symbol it was named from, if the name had to change.
    original: Option<String>,
    /// The symbol it links to, where that is not its C name (a
    /// `BINBUN_SYMBOL` label).
    symbol: Option<String>,
}

/// An intrinsic as declared: its C name.
#[derive(Clone, Debug)]
struct Intrinsic {
    name: String,
}

struct Printer<'a> {
    f: &'a Function,
    declarations: &'a Declarations,
    style: &'a Style,
    image: &'a dyn Image,
    /// How instructions without semantics print.
    opaque: Opaque,
    /// The variables the printed code reads (not only instructions
    /// without semantics: [`unlifted::printed_reads`]).
    printed_reads: BTreeSet<VarId>,
    /// The assignments not printed: their values feed only instructions
    /// without semantics ([`unlifted::Reads::unprinted`]).
    unprinted: BTreeSet<StmtId>,
    /// The locals declared in the body ([`scoped`]), by the statement
    /// each is declared before (or initialized by).
    scoped: BTreeMap<StmtId, Vec<VarId>>,
    /// The locals declared in the body so far (not at the top).
    declared_in_body: BTreeSet<VarId>,
    /// [`Opaque::Asm`]: the locals named after the register an
    /// instruction without semantics writes them in (`_EAX`).
    register_vars: BTreeMap<VarId, String>,
    /// The unknown values printed (to count each once).
    unknowns_printed: BTreeSet<ExprId>,
    /// The names of the unknown values printed as names, in the order
    /// first printed.
    unknown_names: Vec<unknown::UnknownName>,
    /// The function's types, and the pointer types the printer needs.
    types: Types,
    /// The width of every expression.
    widths: Vec<u16>,
    names: Names,
    function_name: String,
    /// Whether binbun made the function's name up.
    function_automatic: bool,
    var_names: Vec<String>,
    /// Whether binbun made each variable's name up.
    var_automatic: Vec<bool>,
    /// The variables the output uses (to declare).
    used: BTreeSet<VarId>,
    /// The structs and unions the output names.
    structs: BTreeSet<TypeId>,
    struct_names: BTreeMap<TypeId, String>,
    /// The enumerations' constants printed by name, by name: their
    /// enumeration ([`enums`]).
    enum_constants: BTreeMap<String, TypeId>,
    /// The enumerations' tags, by enumeration: `None` for one declared as
    /// an integer ([`Printer::enum_tag`]).
    enum_tags: BTreeMap<TypeId, Option<String>>,
    /// The types of the frame's structs ([`Function::frames`]): named
    /// `frame_<function>`, and laid out without C's tail padding counting.
    frame_types: BTreeSet<TypeId>,
    /// Whether what a pointer points to is spelled as a type of
    /// alignment 1 ([`Printer::declare_target`]): the exact output's
    /// accesses are the machine's, which ask no alignment.
    unaligned: bool,
    /// The typedefs of alignment 1 made for pointer and enumeration
    /// types pointed to, in the order made: the type, the name, the
    /// definition ([`Printer::unaligned_typedef`]).
    unaligned_types: Vec<(TypeId, String, Vec<Doc>)>,
    /// The variables in memory the output reads or takes the address of
    /// (not only stores to their fields).
    read_objects: BTreeSet<VarId>,
    /// Whether the place of a store is being printed (its base is no read).
    storing: bool,
    /// By address and signature.
    callees: BTreeMap<(u64, TypeId), Callee>,
    /// The imports called through their slots, by slot and signature.
    imports: BTreeMap<(u64, TypeId), Callee>,
    intrinsics: BTreeMap<u16, Intrinsic>,
    /// Temporaries: name and type.
    temps: Vec<(String, TypeId)>,
    /// Labels a `goto` uses, by label.
    labels: BTreeMap<LabelId, String>,
    /// Labels after loops and switches a `break` leaves by `goto`.
    break_labels: BTreeMap<StmtId, String>,
    /// Labels at the end of loop bodies a `continue` reaches by `goto`.
    continue_labels: BTreeMap<StmtId, String>,
    /// `for` loops whose step is not an expression list: printed after
    /// the body.
    late_steps: BTreeSet<StmtId>,
    /// The loops and switches around the statement being printed,
    /// innermost last.
    breakable: Vec<StmtId>,
    counts: Counts,
    /// The node the tokens being made stand for.
    node: Option<Node>,
    /// Expression nodes still allowed ([`expr::BUDGET`]).
    budget: usize,
    /// Expression pieces copied so far ([`expr::COPY_BUDGET`]).
    copied: Cell<usize>,
    /// How deep the block being printed is.
    nesting: usize,
}

impl<'a> Printer<'a> {
    fn new(
        f: &'a Function,
        declarations: &'a Declarations,
        style: &'a Style,
        image: &'a dyn Image,
        opaque: Opaque,
    ) -> Result<Self, PrintError> {
        let mut widths = Vec::with_capacity(f.exprs.len());
        for (index, expr) in (0..).zip(&f.exprs) {
            let width = expr_width(f, expr, &mut |operand| {
                widths
                    .get(operand.0 as usize)
                    .copied()
                    .ok_or_else(String::new)
            })
            .map_err(|message| error(Some(Node::Expr(ExprId(index))), message))?;
            widths.push(width);
        }
        let mut names = Names::default();
        let symbol = f.name.clone().or_else(|| image.symbol(f.address));
        let function_automatic = symbol.is_none();
        let function_name = names.fresh(&symbol.unwrap_or_else(|| format!("sub_{:x}", f.address)));
        let unlifted::Reads {
            vars: printed_reads,
            unprinted,
        } = unlifted::printed_reads(f, declarations);
        let register_vars = match opaque {
            Opaque::Asm => unlifted::register_names(f, declarations, image, &printed_reads),
            Opaque::Calls => BTreeMap::new(),
        };
        let scoped = match style.declarations {
            Placement::Scoped => scoped(f, declarations, &printed_reads, &unprinted),
            Placement::Top => BTreeMap::new(),
        };
        let mut printer = Self {
            f,
            declarations,
            style,
            image,
            opaque,
            printed_reads,
            unprinted,
            scoped,
            declared_in_body: BTreeSet::new(),
            register_vars,
            unknowns_printed: BTreeSet::new(),
            unknown_names: Vec::new(),
            types: f.types.clone(),
            widths,
            names,
            function_name,
            function_automatic,
            var_names: Vec::new(),
            var_automatic: Vec::new(),
            used: BTreeSet::new(),
            structs: BTreeSet::new(),
            struct_names: BTreeMap::new(),
            enum_constants: BTreeMap::new(),
            enum_tags: BTreeMap::new(),
            frame_types: f
                .frames
                .iter()
                .filter_map(|&id| f.var(id).map(|variable| variable.ty))
                .collect(),
            unaligned: false,
            unaligned_types: Vec::new(),
            read_objects: BTreeSet::new(),
            storing: false,
            callees: BTreeMap::new(),
            imports: BTreeMap::new(),
            intrinsics: BTreeMap::new(),
            temps: Vec::new(),
            labels: BTreeMap::new(),
            break_labels: BTreeMap::new(),
            continue_labels: BTreeMap::new(),
            late_steps: BTreeSet::new(),
            breakable: Vec::new(),
            counts: Counts::default(),
            node: None,
            budget: expr::BUDGET,
            copied: Cell::new(0),
            nesting: 0,
        };
        printer.name_callees();
        printer.name_variables();
        Ok(printer)
    }

    /// Names the functions called by address or referred to (a constant
    /// cast to a code type, [`Printer::function_ref`]), before any
    /// variable (so they keep the names readers know): each address under
    /// its symbol, a second signature for one address under a new name
    /// that links to the same symbol. Only what the body holds counts (a
    /// pass may leave statements no block holds).
    fn name_callees(&mut self) {
        let f = self.f;
        let own_symbol = f.name.clone().or_else(|| self.image.symbol(f.address));
        let (live_stmts, live_exprs) = held(f);
        let live = |index: usize, set: &[bool]| set.get(index).copied().unwrap_or(false);
        let statements = f
            .stmts
            .iter()
            .enumerate()
            .filter_map(|(index, stmt)| match stmt {
                Stmt::Call { .. } if !live(index, &live_stmts) => None,
                Stmt::Call { call, .. } => Some(call),
                Stmt::Assign { .. }
                | Stmt::Intrinsic { .. }
                | Stmt::Expr(_)
                | Stmt::If { .. }
                | Stmt::While { .. }
                | Stmt::DoWhile { .. }
                | Stmt::For { .. }
                | Stmt::Switch { .. }
                | Stmt::Break(_)
                | Stmt::Continue(_)
                | Stmt::Label(_)
                | Stmt::Goto(_)
                | Stmt::Return(_)
                | Stmt::Trap(_)
                | Stmt::Unreachable
                | Stmt::Escape { .. }
                | Stmt::Try { .. }
                | Stmt::VaStart { .. } => None,
            });
        // Called from call statements and from call expressions.
        let live_calls: BTreeSet<usize> = (0..f.exprs.len())
            .filter(|&index| live(index, &live_exprs))
            .filter_map(|index| match f.exprs.get(index) {
                Some(&Expr::Call(id)) => Some(id.0 as usize),
                Some(_) | None => None,
            })
            .collect();
        let expression_calls = (0..)
            .zip(&f.calls)
            .filter(|(index, _)| live_calls.contains(index))
            .map(|(_, call)| call);
        let calls: Vec<&Call> = statements.chain(expression_calls).collect();
        let called = calls.iter().filter_map(|call| {
            let AstCallee::Address(address) = call.callee else {
                return None;
            };
            Some((address, call.signature))
        });
        let imported: Vec<(u64, TypeId)> = calls
            .iter()
            .filter_map(|call| {
                let AstCallee::Import(slot) = call.callee else {
                    return None;
                };
                Some((slot, call.signature))
            })
            .collect();
        let referred = (0..f.exprs.len())
            .filter(|&index| live(index, &live_exprs))
            .filter_map(|index| self.function_constant(ExprId(u32::try_from(index).ok()?)));
        let functions: Vec<(u64, TypeId)> = called.chain(referred).collect();
        for (address, signature) in functions {
            if self.callees.contains_key(&(address, signature)) {
                continue;
            }
            if address == f.address && self.is_own_signature(signature) {
                continue;
            }
            let original = if address == f.address {
                own_symbol.clone()
            } else {
                self.image.symbol(address)
            };
            let automatic = original.is_none();
            let base = original
                .clone()
                .unwrap_or_else(|| format!("sub_{address:x}"));
            let name = self.names.fresh(&base);
            let linked = base.split('@').next().unwrap_or_default().to_string();
            let second =
                address == f.address || self.callees.keys().any(|&(other, _)| other == address);
            let symbol = (second || linked != name).then_some(linked);
            self.callees.insert(
                (address, signature),
                Callee {
                    name: name.clone(),
                    signature,
                    automatic,
                    original: original.filter(|original| *original != name),
                    symbol,
                },
            );
        }
        self.name_imports(imported);
    }

    /// Names the imports called through their slots (`imported`: slot and
    /// signature), after the functions: each under its import's name, a
    /// second signature for one slot under a new name that links to the
    /// same symbol.
    fn name_imports(&mut self, imported: Vec<(u64, TypeId)>) {
        for (slot, signature) in imported {
            if self.imports.contains_key(&(slot, signature)) {
                continue;
            }
            let import = self.image.import(slot);
            let automatic = import.is_none();
            let base = import.unwrap_or_else(|| format!("import_{slot:x}"));
            let name = self.names.fresh(&base);
            let second = self.imports.keys().any(|&(other, _)| other == slot);
            let symbol = (second || base != name).then(|| base.clone());
            self.imports.insert(
                (slot, signature),
                Callee {
                    name: name.clone(),
                    signature,
                    automatic,
                    original: Some(base).filter(|original| *original != name),
                    symbol,
                },
            );
        }
    }

    /// The function `id` refers to, if it is a constant cast to a code
    /// type (lowering's reference to a function by its entry): its
    /// address and type.
    fn function_constant(&self, id: ExprId) -> Option<(u64, TypeId)> {
        let f = self.f;
        let &Expr::Cast { value, ty } = f.expr(id)? else {
            return None;
        };
        let &Expr::Const(bits) = f.expr(value)? else {
            return None;
        };
        let code = matches!(f.types.get(ty), Some(Type::Code(_)));
        (code && bits.width() == self.pointer_width()).then(|| (bits.low_u64(), ty))
    }

    /// Whether code type `signature` is the function's own.
    fn is_own_signature(&self, signature: TypeId) -> bool {
        let f = self.f;
        let Some(Type::Code(signature)) = f.types.get(signature) else {
            return false;
        };
        signature.returns == f.returns
            && signature.variadic == f.variadic
            && signature.parameters.len() == f.parameters.len()
            && f.parameters
                .iter()
                .zip(&signature.parameters)
                .all(|(&parameter, &ty)| f.var(parameter).is_some_and(|v| v.ty == ty))
    }

    /// Names every variable: its own name, a symbol, or one from its kind
    /// and number; globals first. The thread pointer's environment
    /// variable has none: it is printed as the platform spells it. Another
    /// is its register's name with `_entry`. A frame struct is `frame`; a
    /// promoted object is named as a local. A name from its kind and
    /// number is automatic ([`Token::automatic`](crate::document::Token)).
    /// Under [`Naming::Registers`] a parameter is `arg1`, a local the
    /// register it was held in ([`Origin::Held`]) or its stack offset
    /// (`var_58`), and so is a variable of the frame other than its struct;
    /// locals sharing one are numbered from 1 (`rax_1`, `rax_2`), one alone
    /// keeps the bare name ([`Self::kept_names`]).
    fn name_variables(&mut self) {
        let f = self.f;
        let registers = self.style.naming == Naming::Registers;
        let kept = if registers {
            self.kept_names()
        } else {
            BTreeMap::new()
        };
        let mut names = vec![String::new(); f.variables.len()];
        let mut automatic = vec![true; f.variables.len()];
        let globals_first = (0u32..)
            .zip(&f.variables)
            .filter(|(_, v)| matches!(v.kind, VarKind::Global(_)))
            .chain(
                (0u32..)
                    .zip(&f.variables)
                    .filter(|(_, v)| !matches!(v.kind, VarKind::Global(_))),
            );
        for (index, variable) in globals_first {
            let position = f.parameters.iter().position(|&p| p.0 == index);
            let mut symbol = None;
            let base = match variable.kind {
                VarKind::Environment(register) => {
                    if self.image.is_thread_pointer(register) {
                        continue;
                    }
                    let name = self
                        .declarations
                        .info(register)
                        .map_or("register", |info| info.name);
                    format!("{name}_entry")
                }
                VarKind::Parameter if registers => format!("arg{}", position.unwrap_or(0) + 1),
                VarKind::Parameter => format!("a{}", position.unwrap_or(0) + 1),
                VarKind::Local => self
                    .register_vars
                    .get(&VarId(index))
                    .cloned()
                    .or_else(|| kept.get(&VarId(index)).cloned())
                    .unwrap_or_else(|| format!("v{index}")),
                VarKind::Global(address) => {
                    symbol = self.image.symbol(address);
                    symbol.clone().unwrap_or_else(|| format!("g_{address:x}"))
                }
                VarKind::Frame(_) if f.frames.contains(&VarId(index)) => String::from("frame"),
                VarKind::Frame(offset) if registers => stack_name(offset),
                VarKind::Frame(_) if f.promoted.contains(&VarId(index)) => format!("v{index}"),
                VarKind::Frame(offset) if offset < 0 => {
                    format!("frame_m{:x}", offset.unsigned_abs())
                }
                VarKind::Frame(offset) => format!("frame_p{offset:x}"),
            };
            let base = variable
                .name
                .as_ref()
                .map_or(base, |name| name.text.clone());
            let name = self.names.fresh(&base);
            if let Some(slot) = names.get_mut(index as usize) {
                *slot = name;
            }
            if let Some(slot) = automatic.get_mut(index as usize) {
                *slot = variable.name.is_none() && symbol.is_none();
            }
        }
        self.var_names = names;
        self.var_automatic = automatic;
    }

    /// The locals [`Naming::Registers`] names by where the machine code
    /// kept them ([`Self::kept_in`]), those of no name of their own or of
    /// the opaque instructions' registers: each its register or slot, and
    /// where several share one, numbered from 1 in their order (`rax_1`,
    /// `rax_2`, `rax_3`).
    fn kept_names(&self) -> BTreeMap<VarId, String> {
        let kept: Vec<(VarId, String)> = (0u32..)
            .zip(&self.f.variables)
            .filter(|&(index, variable)| {
                variable.kind == VarKind::Local
                    && variable.name.is_none()
                    && !self.register_vars.contains_key(&VarId(index))
            })
            .filter_map(|(index, variable)| Some((VarId(index), self.kept_in(variable)?)))
            .collect();
        let mut shared: BTreeMap<&str, usize> = BTreeMap::new();
        for (_, name) in &kept {
            *shared.entry(name.as_str()).or_default() += 1;
        }
        let mut next: BTreeMap<&str, usize> = BTreeMap::new();
        kept.iter()
            .map(|(var, name)| {
                if shared.get(name.as_str()).copied().unwrap_or(0) < 2 {
                    return (*var, name.clone());
                }
                let number = next.entry(name.as_str()).or_insert(0);
                *number += 1;
                (*var, format!("{name}_{number}"))
            })
            .collect()
    }

    /// Where the machine code kept local `variable`, as
    /// [`Naming::Registers`] names it: the register it was held in, else
    /// its stack slot's offset.
    fn kept_in(&self, variable: &Variable) -> Option<String> {
        let held = variable.origins.iter().find_map(|origin| {
            let &Origin::Held(register) = origin else {
                return None;
            };
            self.declarations.info(register).map(|info| info.name)
        });
        if let Some(name) = held {
            return Some(String::from(name));
        }
        variable.origins.iter().find_map(|origin| {
            let &Origin::Slot(offset) = origin else {
                return None;
            };
            Some(stack_name(offset))
        })
    }

    /// Finds the labels gotos use, the breaks and continues that need a
    /// label, and the `for` steps that are printed late.
    /// Stops below [`stmt::MAX_NESTING`] blocks (printing refuses those).
    fn prepass(&mut self, block: &Block, enclosing: &mut Vec<(StmtId, bool)>, depth: usize) {
        if depth > stmt::MAX_NESTING {
            return;
        }
        let f = self.f;
        for &id in block {
            let Some(stmt) = f.stmt(id) else { continue };
            match stmt {
                Stmt::Goto(label) => {
                    if !self.labels.contains_key(label) {
                        let name = self.names.fresh(&format!("label_{}", label.0));
                        self.labels.insert(*label, name);
                    }
                }
                Stmt::Break(target) => {
                    if enclosing.last().map(|&(id, _)| id) != Some(*target) {
                        self.need_label(*target, true);
                    }
                }
                Stmt::Continue(target) => {
                    let innermost = enclosing.iter().rev().find(|&&(_, looping)| looping);
                    if innermost.map(|&(id, _)| id) != Some(*target) {
                        self.need_label(*target, false);
                    }
                }
                Stmt::For { step, .. } => {
                    if !step.iter().all(|&s| self.expressible(s)) {
                        self.late_steps.insert(id);
                    }
                }
                Stmt::Assign { .. }
                | Stmt::Call { .. }
                | Stmt::Intrinsic { .. }
                | Stmt::Expr(_)
                | Stmt::If { .. }
                | Stmt::While { .. }
                | Stmt::DoWhile { .. }
                | Stmt::Switch { .. }
                | Stmt::Label(_)
                | Stmt::Return(_)
                | Stmt::Trap(_)
                | Stmt::Unreachable
                | Stmt::Escape { .. }
                | Stmt::Try { .. }
                | Stmt::VaStart { .. } => {}
            }
            let scope = stmt.is_loop() || matches!(stmt, Stmt::Switch { .. });
            if scope {
                enclosing.push((id, stmt.is_loop()));
            }
            for child in stmt.blocks() {
                self.prepass(child, enclosing, depth + 1);
            }
            if scope {
                enclosing.pop();
            }
        }
        // A continue to a `for` whose step comes after the body must reach
        // the step: by a label.
        for &id in &self.late_steps.clone() {
            if !self.continue_labels.contains_key(&id) {
                let name = self.names.fresh(&format!("continue_{}", id.0));
                self.continue_labels.insert(id, name);
            }
        }
    }

    fn need_label(&mut self, target: StmtId, exit: bool) {
        let (map, base) = if exit {
            (&mut self.break_labels, "break")
        } else {
            (&mut self.continue_labels, "continue")
        };
        let names = &mut self.names;
        map.entry(target)
            .or_insert_with(|| names.fresh(&format!("{base}_{}", target.0)));
    }

    /// The function's return type, name and parameters.
    fn signature(&mut self) -> Result<Vec<Doc>, PrintError> {
        let f = self.f;
        // The parameters nest, so a list too long for one line continues
        // indented under the name rather than at the left margin.
        let mut parameters = Vec::new();
        for (position, &parameter) in f.parameters.iter().enumerate() {
            if position > 0 {
                parameters.push(Doc::punct(",", None));
                parameters.push(Doc::Line);
            }
            let variable = f
                .var(parameter)
                .ok_or_else(|| error(None, "missing parameter"))?;
            let name = vec![self.var(parameter)];
            parameters.extend(self.declare_parameter(variable.ty, name)?);
        }
        // Variadic with no named parameter: C11's `()` (no `(...)`).
        if f.variadic && !f.parameters.is_empty() {
            parameters.extend([Doc::punct(",", None), Doc::Line, Doc::punct("...", None)]);
        } else if f.parameters.is_empty() && !f.variadic {
            parameters.push(Doc::token(TokenKind::BuiltinType, "void", None));
        }
        let inner = vec![
            Doc::name(
                TokenKind::Function,
                self.function_name.clone(),
                self.function_automatic,
                None,
            ),
            Doc::punct("(", None),
            Doc::Nest(parameters),
            Doc::punct(")", None),
        ];
        match f.returns {
            Some(ty) => self.declare(ty, inner),
            None => Ok(types::with_specifier(
                vec![Doc::token(TokenKind::BuiltinType, "void", None)],
                inner,
            )),
        }
    }

    /// Declarations of the locals, frame variables and temporaries used
    /// (but the locals declared in the body, [`scoped`]),
    /// and of the environment variables other than the thread pointer's,
    /// each initialised with its register's value at entry
    /// ([`entry_reader`]); the `va_list` [`Stmt::VaStart`] writes is
    /// `<stdarg.h>`'s `va_list`; a promoted object's says where in the
    /// frame it is (`/* [entry-0x98] */`).
    fn locals(&mut self) -> Result<Vec<Doc>, PrintError> {
        let f = self.f;
        let mut out = Vec::new();
        let va_list = f.va_list();
        for &id in &self.used.clone() {
            let Some(variable) = f.var(id) else { continue };
            if self.declared_in_body.contains(&id) {
                continue;
            }
            if va_list == Some(id) {
                out.push(Doc::Group(vec![
                    Doc::token(TokenKind::Type, "va_list", None),
                    Doc::Space,
                    self.var(id),
                    Doc::punct(";", None),
                ]));
                continue;
            }
            let reader = match variable.kind {
                VarKind::Local | VarKind::Frame(_) => {
                    out.push(self.local_declaration(id)?);
                    continue;
                }
                VarKind::Environment(register) => {
                    let name = self.declarations.info(register).map(|info| info.name);
                    name.and_then(entry_reader).ok_or_else(|| {
                        self.unsupported(Some(Node::Var(id)), "this environment register")
                    })?
                }
                VarKind::Parameter | VarKind::Global(_) => continue,
            };
            let name = vec![self.var(id)];
            let mut line = self.declare(variable.ty, name)?;
            line.extend([
                Doc::Space,
                Doc::punct("=", None),
                Doc::Space,
                Doc::macro_name(reader, None),
                Doc::punct("(", None),
                Doc::punct(")", None),
            ]);
            line.push(Doc::punct(";", None));
            out.push(Doc::Group(line));
        }
        for (name, ty) in self.temps.clone() {
            let mut line = self.declare(ty, vec![Doc::name(TokenKind::Local, name, true, None)])?;
            line.push(Doc::punct(";", None));
            out.push(Doc::Group(line));
        }
        out.extend(self.unknown_declarations()?);
        Ok(out)
    }

    /// `T v;` declaring local or frame variable `id`; a promoted object's
    /// says where in the frame it is (`/* [entry-0x98] */`).
    fn local_declaration(&mut self, id: VarId) -> Result<Doc, PrintError> {
        let variable = self
            .f
            .var(id)
            .ok_or_else(|| error(Some(Node::Var(id)), "no such variable"))?;
        let (kind, ty) = (variable.kind, variable.ty);
        let mut line = self.declare(ty, vec![self.var(id)])?;
        line.push(Doc::punct(";", None));
        if let VarKind::Frame(offset) = kind
            && self.f.promoted.contains(&id)
        {
            let sign = if offset < 0 { '-' } else { '+' };
            line.push(Doc::Space);
            line.push(Doc::comment(
                comment(&format!("[entry{sign}{:#x}]", offset.unsigned_abs())),
                None,
            ));
        }
        Ok(Doc::Group(line))
    }

    /// The declarations of the locals declared just before statement `id`
    /// ([`scoped`]), but the one it initializes ([`Self::initializes`])
    /// unless `all`.
    fn scoped_declarations(&mut self, id: StmtId, all: bool) -> Result<Vec<Doc>, PrintError> {
        let Some(vars) = self.scoped.get(&id).cloned() else {
            return Ok(Vec::new());
        };
        let initialized = if all { None } else { self.initializes(id) };
        let mut out = Vec::with_capacity(vars.len());
        for var in vars {
            if Some(var) != initialized && self.declared_in_body.insert(var) {
                self.used.insert(var);
                out.push(self.local_declaration(var)?);
            }
        }
        Ok(out)
    }

    /// The local statement `id` declares as it assigns it (`T v = e;`,
    /// `T v = f(a);`, `T v = unlifted_u32("…");`): one declared there
    /// ([`scoped`]) that an assignment, or a call or intrinsic of one
    /// result printed, writes whole, of a type C initializes from a value
    /// (not an aggregate). An instruction without semantics counts only
    /// as a call ([`Opaque::Calls`]), and with only that result read.
    fn initializes(&self, id: StmtId) -> Option<VarId> {
        let stmt = self.f.stmt(id)?;
        let var = match stmt {
            &Stmt::Assign {
                place: Place::Var(var),
                ..
            } => var,
            Stmt::Call { results, .. } => one_var(results)?,
            Stmt::Intrinsic {
                results, intrinsic, ..
            } => {
                let info = self.declarations.intrinsic(*intrinsic)?;
                if !info.opaque && info.outputs.len() == 1 {
                    one_var(results)?
                } else if info.opaque && self.opaque == Opaque::Calls {
                    let printed: Vec<Place> = results
                        .iter()
                        .copied()
                        .filter(|place| self.printed(place))
                        .collect();
                    one_var(&printed)?
                } else {
                    return None;
                }
            }
            Stmt::Assign { .. }
            | Stmt::Expr(_)
            | Stmt::If { .. }
            | Stmt::While { .. }
            | Stmt::DoWhile { .. }
            | Stmt::For { .. }
            | Stmt::Switch { .. }
            | Stmt::Break(_)
            | Stmt::Continue(_)
            | Stmt::Label(_)
            | Stmt::Goto(_)
            | Stmt::Return(_)
            | Stmt::Trap(_)
            | Stmt::Unreachable
            | Stmt::Escape { .. }
            | Stmt::Try { .. }
            | Stmt::VaStart { .. } => return None,
        };
        let ty = self.f.var(var)?.ty;
        let declared = self.scoped.get(&id)?.contains(&var);
        let value = !matches!(self.cty(ty), Ok(types::CTy::Other(_)) | Err(_));
        (declared && value && !self.unprinted.contains(&id)).then_some(var)
    }

    /// Declarations of the globals, callees and intrinsics used.
    fn declarations(&mut self) -> Result<Vec<Doc>, PrintError> {
        let f = self.f;
        let mut out = Vec::new();
        for &id in &self.used.clone() {
            let Some(variable) = f.var(id) else { continue };
            if let VarKind::Global(address) = variable.kind {
                let name = vec![self.var(id)];
                let mut line = vec![Doc::keyword("extern", None), Doc::Space];
                let bytes = self.types.width(variable.ty).map_or(0, |width| width / 8);
                let constant =
                    bytes > 0 && self.image.read_only(address, bytes) && !self.writes(id);
                line.extend(self.declare_const(variable.ty, name, constant)?);
                line.push(Doc::punct(";", None));
                line.push(Doc::Space);
                let original = variable
                    .name
                    .as_ref()
                    .map(|name| name.text.clone())
                    .or_else(|| self.image.symbol(address))
                    .filter(|original| *original != self.var_name(id))
                    .map(|original| format!(" {original}"))
                    .unwrap_or_default();
                line.push(Doc::comment(
                    comment(&format!("{address:#x}{original}")),
                    None,
                ));
                out.push(Doc::Group(line));
            }
        }
        for ((address, _), callee) in self.callees.clone() {
            let original = callee
                .original
                .as_ref()
                .map(|original| format!(" {original}"))
                .unwrap_or_default();
            out.push(self.callee_declaration(&callee, &format!("{address:#x}{original}"))?);
        }
        for ((slot, _), callee) in self.imports.clone() {
            let original = callee
                .original
                .as_ref()
                .map(|original| format!(" {original}"))
                .unwrap_or_default();
            let note = format!("import{original}, slot {slot:#x}");
            out.push(self.callee_declaration(&callee, &note)?);
        }
        for (id, intrinsic) in self.intrinsics.clone() {
            let mut line = self.intrinsic_prototype(id, &intrinsic.name)?;
            line.push(Doc::punct(";", None));
            out.push(Doc::Group(line));
        }
        Ok(out)
    }

    /// The declaration of `callee`, with the comment `note`.
    fn callee_declaration(&mut self, callee: &Callee, note: &str) -> Result<Doc, PrintError> {
        let name = Doc::name(
            TokenKind::Function,
            callee.name.clone(),
            callee.automatic,
            None,
        );
        let mut line = self.prototype(name, callee.signature)?;
        if let Some(symbol) = &callee.symbol {
            let escaped = symbol.replace('\\', "\\\\").replace('"', "\\\"");
            line.extend([
                Doc::Space,
                Doc::macro_name("BINBUN_SYMBOL", None),
                Doc::punct("(", None),
                Doc::string(format!("\"{escaped}\""), None),
                Doc::punct(")", None),
            ]);
        }
        line.push(Doc::punct(";", None));
        line.push(Doc::Space);
        line.push(Doc::comment(comment(note), None));
        Ok(Doc::Group(line))
    }

    fn var_name(&self, id: VarId) -> String {
        self.var_names
            .get(id.0 as usize)
            .cloned()
            .unwrap_or_else(|| format!("v{}", id.0))
    }

    /// Variable `id`'s name as a token: a parameter, global or local
    /// (frame and environment variables too), automatic as named.
    fn var(&self, id: VarId) -> Doc {
        let kind = match self.f.var(id).map(|variable| variable.kind) {
            Some(VarKind::Parameter) => TokenKind::Parameter,
            Some(VarKind::Global(_)) => TokenKind::Global,
            Some(VarKind::Local | VarKind::Frame(_) | VarKind::Environment(_)) | None => {
                TokenKind::Local
            }
        };
        let automatic = self
            .var_automatic
            .get(id.0 as usize)
            .copied()
            .unwrap_or(true);
        Doc::name(kind, self.var_name(id), automatic, Some(Node::Var(id)))
    }

    /// A temporary's name (`t0`) as a token.
    fn temp_name(&self, name: impl Into<String>) -> Doc {
        Doc::name(TokenKind::Local, name, true, self.node)
    }

    /// `(void)a;` for each parameter the body never reads (so `-Wextra`
    /// does not warn).
    fn unused_parameters(&self) -> Vec<Doc> {
        self.f
            .parameters
            .iter()
            .filter(|parameter| !self.used.contains(parameter))
            .map(|&parameter| {
                let mut line = value::cast_parentheses(
                    vec![Doc::token(TokenKind::BuiltinType, "void", None)],
                    None,
                );
                line.push(self.var(parameter));
                line.push(Doc::punct(";", None));
                Doc::Group(line)
            })
            .collect()
    }

    /// `(void)&frame;` for each `Frame` variable the body only stores to
    /// (but the `va_list`): `-Wall` would warn it is set but not used,
    /// where its bytes are the frame's all the same.
    fn unread_frames(&self) -> Vec<Doc> {
        let f = self.f;
        let va_list = f.va_list();
        self.used
            .iter()
            .filter(|&&id| {
                f.var(id)
                    .is_some_and(|variable| matches!(variable.kind, VarKind::Frame(_)))
                    && !self.read_objects.contains(&id)
                    && va_list != Some(id)
            })
            .map(|&frame| {
                let mut line = value::cast_parentheses(
                    vec![Doc::token(TokenKind::BuiltinType, "void", None)],
                    None,
                );
                line.push(Doc::op("&", None));
                line.push(self.var(frame));
                line.push(Doc::punct(";", None));
                Doc::Group(line)
            })
            .collect()
    }

    /// A new temporary of type `ty`.
    fn temp(&mut self, ty: TypeId) -> String {
        let name = self.names.fresh(&format!("t{}", self.temps.len()));
        self.temps.push((name.clone(), ty));
        name
    }

    /// The width of expression `id` (it was checked when the printer was
    /// made).
    fn width(&self, id: ExprId) -> u16 {
        self.widths.get(id.0 as usize).copied().unwrap_or(1)
    }

    fn pointer_width(&self) -> u16 {
        self.types.pointer_width()
    }
}

/// Text of a number in decimal or hexadecimal.
fn number(value: u128, hex: bool) -> String {
    if hex {
        format!("{value:#x}")
    } else {
        value.to_string()
    }
}

/// `/* text */`, the text unable to end the comment early: as the printer
/// writes its own comments, and a front end the user's.
///
/// ```
/// use binbun_print::c::comment;
///
/// assert_eq!(comment("argc"), "/* argc */");
/// assert_eq!(comment("a */ b*/"), "/* a * / b* / */");
/// ```
pub fn comment(text: &str) -> String {
    format!("/* {} */", text.replace("*/", "* /"))
}

/// Which statements and expressions of `f` its body holds, by index:
/// those reached from it through blocks, roots and operands.
fn held(f: &Function) -> (Vec<bool>, Vec<bool>) {
    let mut stmts = vec![false; f.stmts.len()];
    let mut exprs = vec![false; f.exprs.len()];
    let mut blocks = vec![&f.body];
    let mut work = Vec::new();
    while let Some(block) = blocks.pop() {
        for &id in block {
            let (Some(seen), Some(stmt)) = (stmts.get_mut(id.0 as usize), f.stmt(id)) else {
                continue;
            };
            if core::mem::replace(seen, true) {
                continue;
            }
            work.extend(stmt.roots());
            blocks.extend(stmt.blocks());
        }
    }
    while let Some(id) = work.pop() {
        let (Some(seen), Some(expr)) = (exprs.get_mut(id.0 as usize), f.expr(id)) else {
            continue;
        };
        if !core::mem::replace(seen, true) {
            work.extend(expr.operands(f));
        }
    }
    (stmts, exprs)
}

/// The variable `places` are, if they are one whole variable.
fn one_var(places: &[Place]) -> Option<VarId> {
    match *places {
        [Place::Var(var)] => Some(var),
        _ => None,
    }
}

/// The locals declared in the body of `f` ([`Placement::Scoped`]), by the
/// statement each is declared before: those [`Function::declared`] places
/// at statements the body holds that the printed code uses (`reads`
/// them, or a statement printed writes them: not one of the assignments
/// `unprinted`, nor an instruction without semantics, whose outputs
/// print where read). The others are declared at the top.
fn scoped(
    f: &Function,
    declarations: &Declarations,
    reads: &BTreeSet<VarId>,
    unprinted: &BTreeSet<StmtId>,
) -> BTreeMap<StmtId, Vec<VarId>> {
    if f.declared.is_empty() {
        return BTreeMap::new();
    }
    let (stmts, _) = held(f);
    let held = |id: StmtId| stmts.get(id.0 as usize).copied().unwrap_or(false);
    let mut written = BTreeSet::new();
    for (index, stmt) in (0u32..).zip(&f.stmts) {
        let id = StmtId(index);
        if !held(id) || unprinted.contains(&id) || unlifted::is_unlifted(stmt, declarations) {
            continue;
        }
        written.extend(stmt.places().iter().filter_map(|place| match *place {
            Place::Var(var) => Some(var),
            Place::Memory { .. } => None,
        }));
    }
    f.declared
        .iter()
        .filter(|&(&id, _)| held(id))
        .map(|(&id, vars)| {
            let printed = vars
                .iter()
                .copied()
                .filter(|var| reads.contains(var) || written.contains(var));
            (id, printed.collect::<Vec<VarId>>())
        })
        .filter(|(_, vars)| !vars.is_empty())
        .collect()
}
