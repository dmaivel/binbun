#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers fail loudly"
)]

//! What a local byte or `void` pointer points to, chosen on the
//! conversion plan: of the types its uses ask for, a byte and `void`, the
//! one that needs fewest casts; a declared pointer keeps its type.

mod common;

use binbun_ast::ir::{ExprId, VarKind};
use binbun_ast::types::{Evidence, Type};
use binbun_print::style::Style;
use binbun_semantics::ir::Binary;
use common::{Builder, print};

/// `int32_t` loads at `offsets` from local `v`, a copy of the parameter,
/// summed.
fn loads(evidence: Evidence, offsets: &[u64]) -> (String, usize) {
    let mut b = Builder::new(0x1000, "words");
    let void = b.ty(Type::Pointer(None));
    let int32 = b.int(32);
    b.f.returns = Some(int32);
    let parameter = b.var(VarKind::Parameter, void, Some("p"));
    b.f.parameters.push(parameter);
    let local = b.var(VarKind::Local, void, Some("v"));
    b.f.variables[local.0 as usize].evidence = evidence;
    let read = b.read(parameter);
    let set = b.assign(local, read);
    let mut total: Option<ExprId> = None;
    for &offset in offsets {
        let base = b.read(local);
        let value = b.load_at(base, offset, int32);
        total = Some(match total {
            Some(sum) => b.bin(Binary::Add, sum, value),
            None => value,
        });
    }
    let ret = b.ret(total.unwrap());
    let function = b.done(vec![set, ret]);
    let (c, counts) = print(&function, &Style::kr());
    (c, counts.casts)
}

#[test]
fn a_void_pointer_loaded_as_words_points_to_words() {
    let (c, casts) = loads(Evidence::Deduced, &[0, 4, 8]);
    // The exact view's words are of alignment 1 (`binbun_i32_u`).
    assert!(c.contains("binbun_i32_u *v;"), "{c}");
    assert!(c.contains("return *v + v[1] + v[2];"), "{c}");
    assert_eq!(casts, 0, "{c}");
}

#[test]
fn an_offset_not_of_whole_words_stays_in_bytes() {
    // Words at 4 and 8, one at 6: `v[1] + v[2]` and the third through a
    // byte pointer, rather than three casts of a `void *`.
    let (c, casts) = loads(Evidence::Deduced, &[4, 8, 6]);
    assert!(
        c.contains("return v[1] + v[2] + *(binbun_i32_u *)((uint8_t *)v + 6);"),
        "{c}"
    );
    assert_eq!(casts, 2, "{c}");
}

#[test]
fn a_declared_pointer_keeps_its_type() {
    let (c, casts) = loads(Evidence::Declared, &[0, 4, 8]);
    assert!(c.contains("void *v"), "{c}");
    assert_eq!(casts, 3, "{c}");
}
