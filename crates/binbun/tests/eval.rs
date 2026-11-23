//! How much of the recovered code lifts (`lifting`), on the checked-in
//! fixtures.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers fail loudly"
)]

use binbun::analysis::{Seeds, analyse, type_library};
use binbun::eval::{Lifting, evaluate, lifting};
use binbun_loader::Image;

fn path(name: &str) -> String {
    format!("{}/../../tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"))
}

fn measured(name: &str, sample: usize) -> (Option<Lifting>, u64) {
    let data = std::fs::read(path(name)).unwrap();
    let image = Image::parse(&data).unwrap();
    let program = analyse(&image, Seeds::ALL, &type_library(&image).unwrap()).unwrap();
    let instructions = evaluate(&image, &program).instructions;
    (lifting(&image, &program, sample), instructions)
}

/// Every instruction of the AArch64 fixture has semantics and all six
/// functions build; the instructions counted are those `evaluate` counts.
#[test]
fn the_dozen_fixture_lifts_whole() {
    let (lifting, instructions) = measured("dozen-aarch64.elf", 100);
    let lifting = lifting.unwrap();
    assert_eq!(
        lifting,
        Lifting {
            instructions,
            semantics: instructions,
            opaque: 0,
            functions: 6,
            tried: 6,
            built: 6,
        }
    );
    assert!((lifting.lifted() - 1.0).abs() < f64::EPSILON);
}

/// The opaque fixture's moves through a system register L0 does not
/// declare (`fpmr`) have no semantics: they count as opaque, not lifted,
/// and their functions still build (its floating-point moves are lifted).
#[test]
fn opaque_instructions_are_not_counted_as_lifted() {
    let (lifting, instructions) = measured("opaque-aarch64.elf", 100);
    let lifting = lifting.unwrap();
    assert_eq!(lifting.instructions, instructions);
    assert_eq!(lifting.semantics + lifting.opaque, instructions);
    // msr fpmr, x9; mrs x10, fpmr.
    assert!(lifting.opaque >= 2, "{lifting:?}");
    assert!(lifting.lifted() < 1.0);
    assert_eq!((lifting.tried, lifting.built), (3, 3));
}

/// Beyond the sample size, functions are sampled: as many as asked.
#[test]
fn l1_is_measured_on_a_sample() {
    let (lifting, _) = measured("program-x86_64.exe", 10);
    let lifting = lifting.unwrap();
    assert!(lifting.functions > 10);
    assert_eq!(lifting.tried, 10);
    assert!(lifting.built <= lifting.tried);
}

/// 32-bit x86 code is not lifted: no measurement.
#[test]
fn unlifted_machines_have_no_measurement() {
    assert_eq!(measured("program-i686.exe", 100).0, None);
}
