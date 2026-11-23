//! A binbun built without the `collab` feature: its collaboration
//! commands fail, saying why, and touch nothing.

#![cfg(not(feature = "collab"))]
#![allow(clippy::unwrap_used, reason = "test helpers fail loudly")]

use std::process::Command;

#[test]
fn the_collaboration_commands_say_they_are_not_built_in() {
    let home = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("without-collab-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&home);
    for command in ["id", "share", "join", "edit"] {
        let output = Command::new(env!("CARGO_BIN_EXE_binbun"))
            .arg(command)
            .env("HOME", &home)
            .env("XDG_CONFIG_HOME", home.join("config"))
            .env("XDG_DATA_HOME", home.join("data"))
            .env_remove("BINBUN_HOME")
            .output()
            .unwrap();
        assert!(!output.status.success(), "{command}");
        let said = String::from_utf8(output.stderr).unwrap();
        assert!(
            said.contains("built without collaboration"),
            "{command}: {said}"
        );
    }
    // No identity was made.
    assert!(!home.exists());
}
