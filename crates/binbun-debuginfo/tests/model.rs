#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers fail loudly"
)]
//! A compilation unit's source path: the name joined to the directory
//! with the directory's separator, `..` resolved, never past the root; an
//! absolute name as stated.

use binbun_debuginfo::info::model::{Language, Unit};

fn path(name: &str, directory: Option<&str>) -> String {
    Unit {
        name: name.to_owned(),
        directory: directory.map(str::to_owned),
        language: Language::Other,
    }
    .path()
}

#[test]
fn a_relative_name_joins_its_directory() {
    assert_eq!(path("units-a.c", Some("/src")), "/src/units-a.c");
    assert_eq!(path("./lib/x.c", Some("/src/")), "/src/lib/x.c");
    assert_eq!(
        path(r"..\Modules\getpath.c", Some(r"D:\a\1\s\PCbuild")),
        r"D:\a\1\s\Modules\getpath.c"
    );
    assert_eq!(path("../../../x.c", Some("/src")), "/x.c");
    assert_eq!(path(r"..\..\x.c", Some(r"D:\a")), r"D:\x.c");
}

#[test]
fn an_absolute_name_or_none_directory_is_the_name() {
    assert_eq!(path("/usr/src/x.c", Some("/build")), "/usr/src/x.c");
    assert_eq!(path(r"C:\src\x.c", Some(r"D:\build")), r"C:\src\x.c");
    assert_eq!(path(r"D:\obj\x.obj", None), r"D:\obj\x.obj");
}
