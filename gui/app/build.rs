//! binbun.exe's icon: for Windows targets, `assets/windows/binbun.rc`
//! (`binbun.ico`) is compiled with the Windows SDK's rc.exe (windres when
//! cross-building) and linked into the `binbun` binary. Nothing for other
//! targets.

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    let dir = "assets/windows";
    println!("cargo:rerun-if-changed={dir}/binbun.rc");
    println!("cargo:rerun-if-changed={dir}/binbun.ico");
    // Required, as GPUI's manifest is: a binbun.exe without its icon is
    // an error, not a silent fallback.
    if let Err(err) = embed_resource::compile_for(
        format!("{dir}/binbun.rc"),
        ["binbun"],
        embed_resource::ParamsIncludeDirs([dir]),
    )
    .manifest_required()
    {
        panic!("binbun.exe's icon: {err}");
    }
}
