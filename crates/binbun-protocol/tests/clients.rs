#![allow(clippy::unwrap_used, reason = "test helpers fail loudly")]
//! What clients send, as the host takes it: a write at an address no
//! segment holds is refused, nothing written; a thread anchored at a
//! plain address is about the instruction a recovered block holds there,
//! else about the data; a suggestion still sending a percentage is read.

use std::fs;
use std::path::Path;
use std::process;
use std::sync::Arc;

use binbun_protocol::talk::{self, Make, ThreadData, method};
use binbun_protocol::{FaultKind, Host, USER, Write};
use binbun_session::journal::Origin;
use binbun_session::{Lineage, Options, Stage};
use serde_json::json;

#[test]
fn an_unmapped_write_is_refused_and_a_plain_address_anchors_code_or_data() {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("clients-{}", process::id()));
    let _ = fs::remove_dir_all(&dir);
    let fixture =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/program-x86_64.elf");
    let options = Options {
        project: Some(dir.join("project")),
        identity: Some(dir.join("identity")),
        warm: false,
        ..Options::default()
    };
    let lineage = Arc::new(Lineage::open(fixture, options).unwrap());
    let session = lineage.session();
    session.wait(Stage::Callers, None);
    let host = Host::new(Arc::clone(&lineage), false);

    let unmapped = 0x10_0000;
    let comment = Write::Comment {
        address: unmapped,
        text: Some("nowhere".to_owned()),
    };
    let refused = host.apply(USER, &Origin::User, None, &comment).unwrap_err();
    assert_eq!(
        refused.kind,
        FaultKind::InvalidAddress,
        "{}",
        refused.message
    );
    assert_eq!(session.edits().comment(unmapped), None);
    assert_eq!(host.history(), Vec::new());
    // Mapped (`.data`): written.
    let mapped = Write::Comment {
        address: 0x4018,
        text: Some("table".to_owned()),
    };
    host.apply(USER, &Origin::User, None, &mapped).unwrap();
    assert_eq!(session.edits().comment(0x4018), Some("table"));

    // In `main`'s code, then in `.data`.
    let anchored = |address: &str| {
        let params = json!({ "anchor": { "kind": "address", "address": address } });
        let made = talk::answer(&host, USER, &Origin::User, None, method::CREATE, params).unwrap();
        let thread: Option<ThreadData> = serde_json::from_value(made).unwrap();
        serde_json::to_value(thread.unwrap().anchor).unwrap()
    };
    assert_eq!(
        anchored("0x1194"),
        json!({ "kind": "instruction", "address": "0x1194" })
    );
    assert_eq!(
        anchored("0x4018"),
        json!({ "kind": "data", "address": "0x4018" })
    );

    // A percentage older clients send is read past.
    let make: Make =
        serde_json::from_value(json!({ "label": "Name it", "edits": [], "confidence": 80 }))
            .unwrap();
    assert_eq!(make.label, "Name it");

    drop(host);
    drop(session);
    Arc::try_unwrap(lineage).unwrap().close();
    let _ = fs::remove_dir_all(&dir);
}
