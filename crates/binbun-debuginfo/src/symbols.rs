//! Debug information from symbol servers (Microsoft's, debuginfod),
//! cached in the symstore layout, where anything reading
//! `_NT_SYMBOL_PATH` stores finds it.
//!
//! - [`identity`]: which file an image needs ([`Identity::of`]: a PE
//!   image's PDB by its `CodeView` record's name, GUID and age; an ELF
//!   image's debug file by build ID; nothing for Mach-O, which has no
//!   public server), where stores and servers file it, and whether a file
//!   is it ([`Identity::verify`]).
//! - [`config`]: where it is looked for and fetched from ([`Config`]):
//!   local stores (symstore layout, or flat), `_NT_SYMBOL_PATH`
//!   ([`SymbolPath`]), the store in `~/.ntoseye/symbols`, Microsoft's
//!   server by default for PDBs, debuginfod's `DEBUGINFOD_URLS` for ELF;
//!   binbun's own cache ([`config::cache`]: `symbols` in binbun's cache folder,
//!   [`binbun_paths::Place::Symbols`], tagged with `CACHEDIR.TAG`).
//! - [`fetch`]: fetching it ([`Config::fetch`]), cancellable
//!   ([`Cancel`]), with timeouts, a compressed PDB (`.pd_`, a cabinet)
//!   expanded, verified, stored atomically in symstore layout
//!   (`<cache>/<name>/<GUID><age>/<name>`, `<cache>/buildid/<hex>/debuginfo`).
//!
//! The module never decides whether to fetch: a request tells the server
//! which binary is analysed, so that is the caller's decision.
//! [`Config::locate`] reads only local stores and sends nothing.
//!
//! ```no_run
//! use binbun_debuginfo::symbols::{Cancel, Config, Identity};
//!
//! let image = std::fs::read("python313.dll")?;
//! let identity = Identity::of(&image).expect("a CodeView record");
//! let config = Config::from_environment();
//! let path = match config.locate(&identity) {
//!     Some(path) => path,
//!     // Only where the user agreed to tell the server.
//!     None => config.fetch(&identity, &Cancel::default())?.path,
//! };
//! println!("{}", path.display());
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

pub mod config;
pub mod fetch;
pub mod identity;

pub use config::{Config, MICROSOFT, Server, SymbolPath};
pub use fetch::{Cancel, Failure, Fetched};
pub use identity::{Guid, Identity, Mismatch, Pdb};
