//! Library signatures applied to a session's binary: after the cross-references
//! ([`Stage::Signatures`](crate::Stage::Signatures)) the functions whose
//! identity a pack holds exactly are named; checking the others by their
//! behaviour goes on in the background, its names one later change. Each
//! run is one change made by [`Origin::Signature`], undone as any:
//! per function the name, the library's prototype and what matched
//! ([`Key::Signature`]: [`Identified`]). A run never writes over a name or
//! prototype anything but a signature wrote, never applies a match the
//! user rejected ([`Session::reject_signature`]), and writes only what
//! differs from what the edits hold, so a project opened again, or by a
//! peer that received the change, writes nothing.
//!
//! The packs ([`folders`]): `BINBUN_SIGNATURES`, the user's own in
//! binbun's data folder ([`Place::Signatures`]), and those installed with
//! binbun (`share/binbun/signatures` beside the executable's `bin`, as
//! the Linux archives lay them out; `Resources/signatures` in a macOS
//! app; `signatures` beside the executable, as the Windows archive has it
//! beside the app, or, on Windows, in the folder above an executable in
//! `bin`, the archive's command).

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use binbun::Database;
use binbun::corrections::Bounds;
use binbun::signatures::{How, MatchOptions, match_image};
use binbun_loader::{Format, Machine};
use binbun_paths::Place;
use binbun_sigpack::pack::{self, Pack};

use crate::edits::{Edits, Identified, Matched, Typed};
use crate::journal::{Key, Origin, Value};
use crate::worker::{self, Shared};
use crate::{Change, Error, Event, Session};

/// How a session names library functions by their signatures.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Options {
    /// Whether it does.
    pub enabled: bool,
    /// Whether the behaviour pass runs in the background after the exact
    /// one (checking candidates by running them: slower, names most).
    pub behaviour: bool,
    /// Whether functions recovery did not find, found by looking in the
    /// code nothing reaches for what a pack names, are adopted (made
    /// functions, as a correction of recovery, and named). Off by default
    /// (a setting): its wrong names were measured at none (musl, every
    /// build, and Rust std), but the search makes the behaviour pass five
    /// to ten times as long on every x86-64 Linux binary, those without
    /// the library too (bash with the musl pack: 8.5 s to 87 s, all
    /// cores), and each function it adopts is a correction, so the binary
    /// is analysed anew and searched again: a whole musl program went
    /// through four analyses in 460 s (11 s without).
    pub sweep: bool,
    /// The packs' files; `None`: every pack in [`folders`].
    pub packs: Option<Vec<PathBuf>>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            enabled: true,
            behaviour: true,
            sweep: false,
            packs: None,
        }
    }
}

/// The folders packs are read from, in order: `BINBUN_SIGNATURES` if set,
/// the user's own ([`Place::Signatures`]), and those installed with
/// binbun beside the executable, as started and with links followed (an
/// install's command is a link to the executable in its folder;
/// `installed`).
pub fn folders() -> Vec<PathBuf> {
    let mut folders = Vec::new();
    if let Some(folder) = env::var_os("BINBUN_SIGNATURES").filter(|f| !f.is_empty()) {
        folders.push(PathBuf::from(folder));
    }
    folders.extend(Place::Signatures.path());
    let started = env::current_exe().ok();
    let linked = started.as_ref().and_then(|exe| fs::canonicalize(exe).ok());
    for exe in started
        .iter()
        .chain(linked.iter().filter(|l| Some(*l) != started.as_ref()))
    {
        folders.extend(installed(exe));
    }
    folders
}

/// Where packs installed with the executable `exe` are: `signatures`
/// beside it; `share/binbun/signatures` and `Resources/signatures` in the
/// folder above its own; on Windows also `signatures` there when its
/// folder is `bin` (the release zip's `bin\binbun.exe`, the packs beside
/// the app above it).
fn installed(exe: &Path) -> Vec<PathBuf> {
    let Some(bin) = exe.parent() else {
        return Vec::new();
    };
    let mut folders = vec![bin.join("signatures")];
    if let Some(prefix) = bin.parent() {
        folders.push(prefix.join("share").join("binbun").join("signatures"));
        folders.push(prefix.join("Resources").join("signatures"));
        if cfg!(windows)
            && bin
                .file_name()
                .is_some_and(|name| name.eq_ignore_ascii_case("bin"))
        {
            folders.push(prefix.join("signatures"));
        }
    }
    folders
}

/// The packs in `folders` (each folder's `.jsonl` and zstd-compressed
/// `.jsonl.zst` files, by name; a pack of a library, version and revision
/// read already is left out), and why each file that is not one was left
/// out.
pub fn read_folders(folders: &[PathBuf]) -> (Vec<Pack>, Vec<String>) {
    let mut files = Vec::new();
    for folder in folders {
        let Ok(entries) = fs::read_dir(folder) else {
            continue;
        };
        let mut found: Vec<PathBuf> = entries
            .filter_map(|entry| Some(entry.ok()?.path()))
            .filter(|path| {
                // `x.jsonl.zst` names a pack as `x.jsonl` does.
                let plain = if path.extension().is_some_and(|extension| extension == "zst") {
                    path.file_stem().map(Path::new)
                } else {
                    Some(path.as_path())
                };
                plain
                    .and_then(Path::extension)
                    .is_some_and(|extension| extension == "jsonl")
            })
            .collect();
        found.sort();
        files.extend(found);
    }
    read_packs(&files)
}

/// The packs in `files`, and why each file that is not one was left out;
/// one pack of each library, version and revision.
pub fn read_packs(files: &[PathBuf]) -> (Vec<Pack>, Vec<String>) {
    let mut packs: Vec<Pack> = Vec::new();
    let mut refused = Vec::new();
    for file in files {
        match fs::read(file)
            .map_err(|error| error.to_string())
            .and_then(pack::text)
            .and_then(|text| Pack::read(&text))
        {
            Ok(pack) => {
                if !packs.iter().any(|known| label(known) == label(&pack)) {
                    packs.push(pack);
                }
            }
            Err(error) => refused.push(format!("{}: {error}", file.display())),
        }
    }
    (packs, refused)
}

/// A pack's name in edits and changes: `library-version@revision`.
pub fn label(pack: &Pack) -> String {
    let header = &pack.header;
    format!("{}-{}@{}", header.library, header.version, header.revision)
}

/// The packs `shared`'s options name, for `database`'s target, read once
/// per analysis: none if matching is off, or no pack is of the binary's
/// architecture and system (an ELF file's is Linux, a PE file's
/// Windows, a Mach-O file's macOS: a Linux library's code says nothing
/// of a Windows program's, whose calling convention differs).
fn packs<'s>(shared: &'s Shared, database: &Database<'_>) -> &'s [Pack] {
    shared.signature_packs.get_or_init(|| {
        let options = &shared.signatures;
        if !options.enabled {
            return Vec::new();
        }
        let image = database.image();
        let arch = match image.machine {
            Machine::X86_64 => "x86_64",
            Machine::X86 | Machine::Aarch64 | Machine::Arm | Machine::Other => {
                return Vec::new();
            }
        };
        let os = match image.format {
            Format::Elf => "linux",
            Format::Pe => "windows",
            Format::MachO => "macos",
        };
        let (packs, _) = match &options.packs {
            Some(files) => read_packs(files),
            None => read_folders(&folders()),
        };
        packs
            .into_iter()
            .filter(|pack| pack.header.target.arch == arch && pack.header.target.os == os)
            .collect()
    })
}

/// What matching `database` against `packs` names: per entry, what
/// matched and whether the function is one recovery did not find (to be
/// adopted). Functions with a name of their own (a symbol, debug
/// information) are left as they are.
fn found(
    database: &Database<'_>,
    packs: &[Pack],
    options: MatchOptions,
) -> BTreeMap<u64, (Identified, bool)> {
    let Ok(matches) = match_image(database, packs, options) else {
        return BTreeMap::new();
    };
    let library = database.library();
    let mut found = BTreeMap::new();
    for m in matches {
        let Some(((p, e), how)) = &m.named else {
            continue;
        };
        if database.name(m.entry).is_some() {
            continue;
        }
        let (Some(pack), Some(entry)) = (
            packs.get(*p),
            packs.get(*p).and_then(|pack| pack.functions.get(*e)),
        ) else {
            continue;
        };
        let no_return = core::iter::once(&entry.name)
            .chain(&entry.aliases)
            .filter_map(|name| library.function(None, name)?.no_return)
            .any(|fact| fact.value);
        let how = match how {
            How::Exact => Matched::Exact,
            How::Behaviour { states, rivals } => Matched::Behaviour {
                states: u32::try_from(*states).unwrap_or(u32::MAX),
                ruled_out: u32::try_from(rivals.len()).unwrap_or(u32::MAX),
            },
        };
        let identified = Identified {
            pack: label(pack),
            library: pack.header.library.clone(),
            version: pack.header.version.clone(),
            name: entry.name.clone(),
            object: entry.object.clone(),
            how,
            prototype: entry.prototype.clone(),
            no_return,
            rejected: false,
        };
        found.insert(m.entry, (identified, m.found));
    }
    found
}

/// The exact pass, at [`Stage::Signatures`](crate::Stage::Signatures):
/// functions named by identity alone, applied as one change.
pub(crate) fn exact(shared: &Arc<Shared>, database: &Database<'_>) {
    let packs = packs(shared, database);
    if packs.is_empty() {
        return;
    }
    let options = MatchOptions {
        behaviour: false,
        sweep: false,
    };
    let found = found(database, packs, options);
    let session = Session::handle(Arc::clone(shared));
    if let Err(error) = session.apply_signatures(&found, packs, false) {
        shared.emit(&Event::Failed(error.to_string()));
    }
}

/// The behaviour pass, on a thread of its own once the stages are done:
/// every function checked, what differs from the edits applied as one
/// change.
pub(crate) fn behaviour(shared: &Arc<Shared>) {
    if !shared.signatures.behaviour {
        return;
    }
    let Some(database) = shared.database() else {
        return;
    };
    if packs(shared, database).is_empty() {
        return;
    }
    let shared = Arc::clone(shared);
    let _ = thread::Builder::new()
        .name("binbun-signatures".to_owned())
        .stack_size(STACK)
        .spawn(move || {
            let Some(database) = shared.database() else {
                return;
            };
            let packs = packs(&shared, database);
            let options = MatchOptions {
                behaviour: true,
                sweep: shared.signatures.sweep,
            };
            let found = found(database, packs, options);
            if shared.cancelled() {
                return;
            }
            let session = Session::handle(Arc::clone(&shared));
            if let Err(error) = session.apply_signatures(&found, packs, true) {
                shared.emit(&Event::Failed(error.to_string()));
            }
        });
}

/// The stack of the behaviour pass's thread (lifting and checking recurse).
const STACK: usize = 64 << 20;

/// Where the name of a function comes from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NameSource {
    /// An edit by this origin (the user, a script, a plugin, an import).
    Edit(Origin),
    /// A library signature ([`Session::signature`]).
    Signature,
    /// The binary's symbol.
    Symbol,
    /// Debug information.
    Debug,
}

impl NameSource {
    /// Its name in Python and the protocol: `"user"` (an edit by the
    /// user, an import, an accepted suggestion), `"script"`, `"plugin"`,
    /// `"agent"`, `"signature"`, `"symbol"`, `"debug"`.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Signature | Self::Edit(Origin::Signature(_)) => "signature",
            Self::Symbol => "symbol",
            Self::Debug => "debug",
            Self::Edit(Origin::Script(_)) => "script",
            Self::Edit(Origin::Plugin(_)) => "plugin",
            Self::Edit(Origin::Agent) => "agent",
            Self::Edit(
                Origin::User
                | Origin::Import(_)
                | Origin::Undo(_)
                | Origin::Redo(_)
                | Origin::Accept(_),
            ) => "user",
        }
    }
}

impl Session {
    /// What a library signature says of the function at `entry`: the
    /// match applied, or rejected.
    pub fn signature(&self, entry: u64) -> Option<Identified> {
        self.shared.state().edits.signature(entry).cloned()
    }

    /// What library signatures say, by entry.
    pub fn signatures(&self) -> BTreeMap<u64, Identified> {
        self.shared.state().edits.signatures().clone()
    }

    /// Where the name of the function at `entry` comes from: an edit, a
    /// signature's when a match not rejected gives the name it has (put
    /// back by an undo too), else the origin of the change that wrote it;
    /// else the binary's symbol (an import thunk's import's too) or its
    /// debug information; `None` for a name binbun made (`sub_…`).
    pub fn name_source(&self, entry: u64) -> Option<NameSource> {
        let edited = {
            let state = self.shared.state();
            state.edits.function(entry).map(|name| {
                let matched = state
                    .edits
                    .signature(entry)
                    .is_some_and(|s| !s.rejected && s.name == name);
                if matched {
                    NameSource::Signature
                } else {
                    let origin = state.journal.origin(&Key::FunctionName(entry));
                    NameSource::Edit(origin.cloned().unwrap_or(Origin::User))
                }
            })
        };
        if edited.is_some() {
            return edited;
        }
        let database = self.database()?;
        if database.name(entry).is_none() {
            // An import thunk's name is its import's: the binary's too.
            return database.data_name(entry).map(|_| NameSource::Symbol);
        }
        let symbol = database
            .image()
            .symbols
            .iter()
            .any(|symbol| symbol.address == entry && !symbol.name.is_empty());
        Some(if symbol {
            NameSource::Symbol
        } else {
            NameSource::Debug
        })
    }

    /// Rejects the signature match of the function at `entry`: one change
    /// by the user, its name and prototype as before the match (unless
    /// written since by anything but a signature), the match kept as
    /// rejected so no later run applies it again (another pack's entry
    /// still may); in the group open, if one is. Undone, the match is
    /// back. What changed.
    ///
    /// # Errors
    ///
    /// No match is applied there; the change cannot be made, or the share
    /// does not take it ([`Error::Refused`]).
    pub fn reject_signature(&self, entry: u64) -> Result<Arc<Change>, Error> {
        let Some(mut identified) = self.signature(entry).filter(|i| !i.rejected) else {
            return Err(Error::Transaction(format!(
                "no signature names the function at {entry:#x}"
            )));
        };
        identified.rejected = true;
        let (ops, change, retype) = self.unapplied(entry, &identified);
        let mut ops = ops;
        ops.push((
            Key::Signature(entry),
            Value::Signature(Some(Box::new(identified))),
        ));
        self.begin("Reject signature", Origin::User);
        let change = self.write("Reject signature", ops, change, false)?;
        if retype {
            self.take_types(&change.documents);
        }
        self.commit()?;
        Ok(change)
    }

    /// The ops clearing what a signature wrote at `entry` (`identified`'s
    /// name and prototype, where no other origin wrote since), what they
    /// change, and whether a prototype is among them.
    fn unapplied(&self, entry: u64, identified: &Identified) -> (Vec<(Key, Value)>, Change, bool) {
        let mut ops = Vec::new();
        let mut change = Change::default();
        let mut retype = false;
        let ours = |key: &Key| {
            let state = self.shared.state();
            matches!(state.journal.origin(key), Some(Origin::Signature(_)))
        };
        let name = Key::FunctionName(entry);
        if ours(&name) && self.shared.state().edits.function(entry) == Some(&identified.name) {
            ops.push((name, Value::Text(None)));
            change = self.printing(entry);
        }
        let typed = Typed::Prototype(entry);
        let prototype = Key::Type(typed.clone());
        if identified.prototype.is_some() && ours(&prototype) {
            ops.push((prototype, Value::Text(None)));
            merge(&mut change, self.reached(&[typed]));
            retype = true;
        }
        (ops, change, retype)
    }

    /// Applies what a run `found` (by entry: the match, and whether the
    /// function is to be adopted) as one change by [`Origin::Signature`],
    /// writing only what differs from the edits; with `complete` (a run
    /// over every function), the matches of `packs` it no longer finds
    /// are taken back. Waits for a group of edits open to close.
    fn apply_signatures(
        &self,
        found: &BTreeMap<u64, (Identified, bool)>,
        packs: &[Pack],
        complete: bool,
    ) -> Result<(), Error> {
        let labels: BTreeSet<String> = packs.iter().map(label).collect();
        let mut ops: Vec<(Key, Value)> = Vec::new();
        let mut change = Change::default();
        let mut retype = false;
        let (edits, origin_of) = self.origins(found.keys().copied());
        // A key a run may write: never written (a clearing is its
        // writer's too), or last by a signature.
        let free = |key: &Key| {
            matches!(
                origin_of.get(key),
                None | Some(None | Some(Origin::Signature(_)))
            )
        };
        for (&entry, (identified, adopt)) in found {
            let current = edits.signature(entry);
            if current.is_some_and(|c| {
                c.rejected && c.pack == identified.pack && c.name == identified.name
            }) || current == Some(identified)
            {
                continue;
            }
            ops.push((
                Key::Signature(entry),
                Value::Signature(Some(Box::new(identified.clone()))),
            ));
            let name = Key::FunctionName(entry);
            if free(&name) && edits.function(entry) != Some(&identified.name) {
                ops.push((name, Value::Text(Some(identified.name.clone()))));
                merge(&mut change, self.printing(entry));
            }
            let typed = Typed::Prototype(entry);
            let prototype = Key::Type(typed.clone());
            if let Some(c) = &identified.prototype
                && free(&prototype)
                && edits.types().get(&typed) != Some(c)
                && self.check_type(&typed, c).is_ok()
            {
                ops.push((prototype, Value::Text(Some(c.clone()))));
                merge(&mut change, self.reached(&[typed]));
                retype = true;
            }
            if *adopt && edits.corrections().bounds(entry).is_none() {
                ops.push((
                    Key::Bounds(entry),
                    Value::Bounds(Some(Bounds::Function { end: None })),
                ));
            }
        }
        if complete {
            for (&entry, identified) in edits.signatures() {
                if identified.rejected
                    || found.contains_key(&entry)
                    || !labels.contains(&identified.pack)
                {
                    continue;
                }
                let (undo, unchanged, typed) = self.unapplied(entry, identified);
                ops.extend(undo);
                merge(&mut change, unchanged);
                retype |= typed;
                ops.push((Key::Signature(entry), Value::Signature(None)));
            }
        }
        if ops.is_empty() {
            return Ok(());
        }
        let pack = labels.into_iter().collect::<Vec<_>>().join(", ");
        let named = ops
            .iter()
            .filter(|(key, value)| matches!(key, Key::Signature(_)) && value.is_some())
            .count();
        let label = format!("Apply signatures ({pack}): {named} functions");
        if !self.begin_alone(&label, Origin::Signature(pack)) {
            return Ok(());
        }
        let written = self.write(&label, ops, change, false)?;
        if retype {
            self.take_types(&written.documents);
        }
        self.commit()?;
        Ok(())
    }

    /// The edits, and who last wrote each key a run may write for the
    /// functions at `entries` and those signatures named before: their
    /// names and prototypes (`None`: never written).
    fn origins(
        &self,
        entries: impl Iterator<Item = u64>,
    ) -> (Edits, BTreeMap<Key, Option<Origin>>) {
        let state = self.shared.state();
        let keys = |entry: u64| [Key::FunctionName(entry), Key::Type(Typed::Prototype(entry))];
        let origins = entries
            .chain(state.edits.signatures().keys().copied())
            .flat_map(keys)
            .map(|key| {
                let origin = state.journal.origin(&key).cloned();
                (key, origin)
            })
            .collect();
        (state.edits.clone(), origins)
    }

    /// Opens a group labelled `label` made by `origin`, never inside
    /// another's: waits for one open to close; whether it opened (not if
    /// the session was cancelled meanwhile).
    fn begin_alone(&self, label: &str, origin: Origin) -> bool {
        loop {
            {
                let mut state = self.shared.state();
                if !state.journal.in_group() {
                    state.journal.begin(label, origin);
                    return true;
                }
            }
            if self.shared.cancelled() {
                return false;
            }
            thread::sleep(Duration::from_millis(50));
        }
    }
}

/// `other`'s documents and listing lines added to `change`'s.
fn merge(change: &mut Change, other: Change) {
    change.documents.extend(other.documents);
    change.documents.sort_unstable();
    change.documents.dedup();
    change.listing.extend(other.listing);
    change.listing = worker::merge(core::mem::take(&mut change.listing));
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use super::installed;

    #[test]
    fn packs_beside_an_executable_in_bin_are_above_it_on_windows_alone() {
        let root = Path::new("opt").join("binbun");
        let exe = root.join("bin").join("binbun.exe");
        let mut expected = vec![
            root.join("bin").join("signatures"),
            root.join("share").join("binbun").join("signatures"),
            root.join("Resources").join("signatures"),
        ];
        if cfg!(windows) {
            expected.push(root.join("signatures"));
        }
        assert_eq!(installed(&exe), expected);
        // An executable in another folder: the packs beside it, not above.
        let exe = root.join("binbun.exe");
        let above: PathBuf = Path::new("opt").join("signatures");
        let found = installed(&exe);
        assert_eq!(found.first(), Some(&root.join("signatures")));
        assert!(!found.contains(&above), "{found:?}");
    }
}
