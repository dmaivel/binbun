//! The root workspace's `binbun`: the commands alone ([`binbun_cli::main`]),
//! for servers and CI, with no GPUI and none of the window system's
//! libraries. The GUI's workspace (`gui/`) builds the `binbun` that also
//! opens the GUI; asked for the GUI, this one says it was built without,
//! except on Windows as the release zip's `bin\binbun.exe`, which starts
//! the app in the folder above.

use std::process::ExitCode;

/// jemalloc: the analysis allocates and frees on many threads at once,
/// faster than with the system's allocator (none on MSVC, which jemalloc
/// does not build for).
#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static ALLOCATOR: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

fn main() -> ExitCode {
    binbun_cli::main(None)
}
