//! Reads the vendored package and checks the model against counts measured
//! independently on the extracted JSON.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers fail loudly"
)]

use xtask::aarchmrs::{AccessorValue, AssemblyRule, Expr, Package, Symbol};

const PACKAGE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../third_party/aarchmrs/AARCHMRS_OPENSOURCE_A_profile_FAT-2026-09.tar.gz"
);

#[test]
fn vendored_package_parses_into_the_model() {
    let started = std::time::Instant::now();
    let package = Package::read(PACKAGE).unwrap();
    eprintln!("parsed in {:?}", started.elapsed());
    assert_eq!(package.version.reference, "2026-09_rel");

    let encodings = package.a64.encodings();
    assert_eq!(encodings.len(), 4429);
    let aliases: usize = encodings.iter().map(|(_, e)| e.aliases.len()).sum();
    assert_eq!(aliases, 314);
    let should_be = encodings
        .iter()
        .filter(|(_, e)| {
            e.encoding
                .fields
                .iter()
                .any(|f| f.should_be_mask.value() != 0)
        })
        .count();
    assert_eq!(should_be, 77);

    let (groups, add) = encodings
        .iter()
        .find(|(_, e)| e.name == "ADD_32_addsub_imm")
        .unwrap();
    assert_eq!(
        groups.iter().map(|g| g.name.as_str()).collect::<Vec<_>>(),
        ["dpimm", "addsub_imm"]
    );
    assert_eq!(add.mnemonic(), Some("ADD"));
    assert_eq!(add.encoded_in["<imm>"], ["imm12"]);
    let fixed: u64 = add
        .encoding
        .fields
        .iter()
        .map(|f| f.value.mask() << f.start)
        .fold(0, |a, b| a | b);
    assert_eq!(fixed, 0xff80_0000);
    let mov = &add.aliases[0];
    assert_eq!(mov.assembly[0], Symbol::Literal("MOV".into()));
    assert_eq!(
        mov.preferred.to_string(),
        "((Rd == '11111') || (Rn == '11111'))"
    );

    let rules = &package.assembly_rules;
    assert_eq!(rules.len(), 3215);
    assert!(matches!(
        &rules["COMMA"],
        AssemblyRule::Token { default: Some(default), .. } if default == ", "
    ));

    let parameters = &package.features.parameters;
    assert_eq!(parameters.len(), 430);
    assert_eq!(
        package.features.versions("FEAT_TEV"),
        ["v9Ap4", "v9Ap5", "v9Ap6", "vFATAp0"]
    );
    assert!(package.features.versions("FEAT_SVE2").contains(&"v9Ap0"));

    assert_eq!(package.accessors.len(), 2015);
    let ttbr0 = package
        .accessors
        .iter()
        .find(|a| a.instruction == "A64.MRS" && a.register == "TTBR0_EL1")
        .unwrap();
    assert_eq!(ttbr0.condition, Expr::Bool(true));
    let encoding = &ttbr0.encodings[0];
    assert_eq!(encoding.asm_value.as_deref(), Some("TTBR0_EL1"));
    assert!(matches!(&encoding.fields["CRn"], AccessorValue::Bits(p) if p.as_str() == "0010"));
}
