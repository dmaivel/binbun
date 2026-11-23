//! Where binbun keeps its files, on every platform: the one resolver of
//! the CLI, the GUI, the Python package, the updater, discovery, the
//! symbol cache and the type databases. Every place ([`Place`]) is
//! decided here, nowhere else, in one of binbun's folders ([`Dir`]):
//!
//! | [`Dir`] | Linux and the rest | macOS | Windows |
//! |---|---|---|---|
//! | [`Config`](Dir::Config) | `~/.config/binbun` | `~/.config/binbun` | `%APPDATA%\binbun` |
//! | [`Data`](Dir::Data) | `~/.local/share/binbun` | `~/Library/Application Support/binbun` | `%LOCALAPPDATA%\binbun` |
//! | [`State`](Dir::State) | `~/.local/state/binbun` | `~/Library/Application Support/binbun/state` | `%LOCALAPPDATA%\binbun\state` |
//! | [`Cache`](Dir::Cache) | `~/.cache/binbun` | `~/Library/Caches/binbun` | `%LOCALAPPDATA%\binbun\cache` |
//! | [`Runtime`](Dir::Runtime) | `$XDG_RUNTIME_DIR/binbun` | `$TMPDIR/binbun` | `%LOCALAPPDATA%\binbun\run` |
//!
//! Overrides, first first (a value that is not an absolute path is
//! ignored, as the XDG specification says, and so is an empty one):
//!
//! - `BINBUN_HOME`: every folder but the runtime one under it, as
//!   `config`, `data`, `state` and `cache`, on every platform.
//! - Each folder's XDG variable (`XDG_CONFIG_HOME`, `XDG_DATA_HOME`,
//!   `XDG_STATE_HOME`, `XDG_CACHE_HOME`, `XDG_RUNTIME_DIR`) where set, on
//!   every platform: `<it>/binbun` (tests point them at their own).
//!
//! On Windows `HOME` is never read: Git Bash and MSYS2 set it, and the
//! same user would get two sets of projects and identities by which shell
//! started binbun. The Known Folders come from `APPDATA` (roaming: the
//! settings follow the user to another machine of their domain) and
//! `LOCALAPPDATA` (not roaming: projects, the identity's private key and
//! gigabytes of symbols stay on the machine), which Windows sets for every
//! process of the user; the user's home ([`home`]) from `USERPROFILE`.
//!
//! The cache is tagged with `CACHEDIR.TAG` when binbun makes it
//! ([`tag_cache`]); `binbun paths` and `binbun.paths()` list the folders
//! with their sizes ([`folders`]).

use std::env;
use std::ffi::OsString;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// Whose conventions place binbun's folders.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Platform {
    /// Linux and the rest: the XDG base directories under `HOME`.
    Xdg,
    /// macOS: the configuration as on Linux, the data and state under
    /// `~/Library/Application Support`, the cache under `~/Library/Caches`,
    /// the runtime folder in `TMPDIR` (the user's own, which launchd gives
    /// every process of the user's session).
    MacOs,
    /// Windows: the Known Folders `%APPDATA%` and `%LOCALAPPDATA%`.
    Windows,
}

impl Platform {
    /// The platform binbun is built for.
    pub const CURRENT: Self = if cfg!(windows) {
        Self::Windows
    } else if cfg!(target_os = "macos") {
        Self::MacOs
    } else {
        Self::Xdg
    };

    /// Every platform.
    pub const ALL: [Self; 3] = [Self::Xdg, Self::MacOs, Self::Windows];

    /// The separator of the paths it shows.
    const fn separator(self) -> &'static str {
        match self {
            Self::Xdg | Self::MacOs => "/",
            Self::Windows => "\\",
        }
    }

    /// The variable holding the user's home: `USERPROFILE` on Windows,
    /// `HOME` elsewhere.
    const fn home_variable(self) -> &'static str {
        match self {
            Self::Xdg | Self::MacOs => "HOME",
            Self::Windows => "USERPROFILE",
        }
    }
}

/// One of binbun's folders.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dir {
    /// What the user edits: settings, themes, `startup.py`.
    Config,
    /// What binbun keeps for the user: projects, the identity, signature
    /// packs.
    Data,
    /// What binbun remembers between runs: recent files, histories.
    State,
    /// What can be fetched or made again: symbols, type databases.
    Cache,
    /// What lives as long as a process: servers' sockets (on Windows
    /// their named pipes' names) and discovery files.
    Runtime,
}

impl Dir {
    /// Every folder, in the order they are listed.
    pub const ALL: [Self; 5] = [
        Self::Config,
        Self::Data,
        Self::State,
        Self::Cache,
        Self::Runtime,
    ];

    /// Its name: `config`, `data`, `state`, `cache`, `runtime` (and its
    /// folder's under `BINBUN_HOME`).
    pub const fn name(self) -> &'static str {
        match self {
            Self::Config => "config",
            Self::Data => "data",
            Self::State => "state",
            Self::Cache => "cache",
            Self::Runtime => "runtime",
        }
    }

    /// The folder named `name` ([`name`](Self::name)).
    pub fn named(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|dir| dir.name() == name)
    }

    /// The XDG variable whose value, where absolute, holds it on every
    /// platform (`<it>/binbun`) unless `BINBUN_HOME` is set.
    pub const fn variable(self) -> &'static str {
        match self {
            Self::Config => "XDG_CONFIG_HOME",
            Self::Data => "XDG_DATA_HOME",
            Self::State => "XDG_STATE_HOME",
            Self::Cache => "XDG_CACHE_HOME",
            Self::Runtime => "XDG_RUNTIME_DIR",
        }
    }

    /// Where it is on `platform` without an override: the variable naming
    /// the base and the path under it; none for the runtime folder on
    /// [`Platform::Xdg`] (`XDG_RUNTIME_DIR` alone).
    const fn fallback(self, platform: Platform) -> Option<(&'static str, &'static [&'static str])> {
        Some(match (self, platform) {
            (Self::Config, Platform::Xdg | Platform::MacOs) => ("HOME", &[".config", "binbun"]),
            (Self::Config, Platform::Windows) => ("APPDATA", &["binbun"]),
            (Self::Data, Platform::Xdg) => ("HOME", &[".local", "share", "binbun"]),
            (Self::Data, Platform::MacOs) => {
                ("HOME", &["Library", "Application Support", "binbun"])
            }
            (Self::Data, Platform::Windows) => ("LOCALAPPDATA", &["binbun"]),
            (Self::State, Platform::Xdg) => ("HOME", &[".local", "state", "binbun"]),
            (Self::State, Platform::MacOs) => (
                "HOME",
                &["Library", "Application Support", "binbun", "state"],
            ),
            (Self::State, Platform::Windows) => ("LOCALAPPDATA", &["binbun", "state"]),
            (Self::Cache, Platform::Xdg) => ("HOME", &[".cache", "binbun"]),
            (Self::Cache, Platform::MacOs) => ("HOME", &["Library", "Caches", "binbun"]),
            (Self::Cache, Platform::Windows) => ("LOCALAPPDATA", &["binbun", "cache"]),
            (Self::Runtime, Platform::Xdg) => return None,
            (Self::Runtime, Platform::MacOs) => ("TMPDIR", &["binbun"]),
            (Self::Runtime, Platform::Windows) => ("LOCALAPPDATA", &["binbun", "run"]),
        })
    }

    /// The folder on `platform` from the environment variables' values
    /// `var` gives (the module's table and overrides); `None` where no
    /// variable it is found by is an absolute path.
    ///
    /// ```
    /// use std::ffi::OsString;
    /// use std::path::Path;
    /// use binbun_paths::{Dir, Platform};
    ///
    /// // An absolute path on this host (macOS' table, read anywhere).
    /// let home = if cfg!(windows) { r"C:\Users\a" } else { "/home/a" };
    /// let var = |name: &str| (name == "HOME").then(|| OsString::from(home));
    /// assert_eq!(
    ///     Dir::Cache.path_in(Platform::MacOs, var),
    ///     Some(Path::new(home).join("Library").join("Caches").join("binbun"))
    /// );
    /// ```
    pub fn path_in(
        self,
        platform: Platform,
        var: impl Fn(&str) -> Option<OsString>,
    ) -> Option<PathBuf> {
        if self != Self::Runtime
            && let Some(home) = absolute(&var, "BINBUN_HOME")
        {
            return Some(home.join(self.name()));
        }
        if let Some(base) = absolute(&var, self.variable()) {
            return Some(base.join("binbun"));
        }
        self.default_in(platform, var)
    }

    /// The folder on `platform` without the overrides: the platform's own
    /// place.
    fn default_in(
        self,
        platform: Platform,
        var: impl Fn(&str) -> Option<OsString>,
    ) -> Option<PathBuf> {
        let (base, under) = self.fallback(platform)?;
        let base = if base == "HOME" {
            platform.home_variable()
        } else {
            base
        };
        let mut path = absolute(&var, base)?;
        path.extend(under);
        Some(path)
    }

    /// The folder as this process's environment says
    /// ([`path_in`](Self::path_in) on [`Platform::CURRENT`]).
    pub fn path(self) -> Option<PathBuf> {
        self.path_in(Platform::CURRENT, |name| env::var_os(name))
    }

    /// Where it is on `platform` without an override, as the user is
    /// shown it: `~/.config/binbun`, `%APPDATA%\binbun`; none where it has
    /// no such place.
    pub fn shown(self, platform: Platform) -> Option<String> {
        let (base, under) = self.fallback(platform)?;
        let base = match base {
            "HOME" => "~".to_owned(),
            _ if platform == Platform::Windows => format!("%{base}%"),
            _ => format!("${base}"),
        };
        Some(
            [base.as_str()]
                .into_iter()
                .chain(under.iter().copied())
                .collect::<Vec<_>>()
                .join(platform.separator()),
        )
    }

    /// Why there is no such folder on `platform`: `no data folder: neither
    /// BINBUN_HOME, XDG_DATA_HOME nor HOME is an absolute path`.
    pub fn missing_on(self, platform: Platform) -> String {
        let mut variables = Vec::new();
        if self != Self::Runtime {
            variables.push("BINBUN_HOME");
        }
        variables.push(self.variable());
        if let Some((base, _)) = self.fallback(platform) {
            variables.push(if base == "HOME" {
                platform.home_variable()
            } else {
                base
            });
        }
        let named = match variables.as_slice() {
            [only] => format!("{only} is not"),
            [first @ .., last] => format!("neither {} nor {last} is", first.join(", ")),
            [] => String::new(),
        };
        format!("no {} folder: {named} an absolute path", self.name())
    }

    /// [`missing_on`](Self::missing_on) [`Platform::CURRENT`].
    pub fn missing(self) -> String {
        self.missing_on(Platform::CURRENT)
    }
}

/// A file or folder binbun keeps.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Place {
    /// The settings file, `settings.toml` ([`Dir::Config`]).
    Settings,
    /// The script the console runs first, `startup.py` ([`Dir::Config`]).
    Startup,
    /// The user's themes' folder, `themes` ([`Dir::Config`]).
    Themes,
    /// The projects' folder, `projects` ([`Dir::Data`]).
    Projects,
    /// This install's identity's folder, `identity` ([`Dir::Data`]): its
    /// private key is data, never configuration (dotfile managers sync
    /// the configuration, and on Windows it roams).
    Identity,
    /// The recent files, `recent` ([`Dir::State`]).
    Recent,
    /// The slices chosen of universal files, `slices` ([`Dir::State`]).
    Slices,
    /// The console's history, `console_history` ([`Dir::State`]).
    ConsoleHistory,
    /// The update skipped, `skipped-update` ([`Dir::State`]).
    SkippedUpdate,
    /// binbun's own symbol cache, `symbols` ([`Dir::Cache`]): where its
    /// downloads go, the one folder binbun may clear.
    Symbols,
    /// The servers' sockets and discovery files: the [`Dir::Runtime`]
    /// itself.
    Servers,
    /// Type databases added to those binbun embeds (one of an embedded
    /// one's name replaces it): `BINBUN_TYPEDB` wherever it is set; else
    /// `typedb` in the [`Dir::Cache`] under `BINBUN_HOME` and on Windows,
    /// and elsewhere `~/.cache/binbun-typedb`.
    TypeDb,
    /// The user's own signature packs, `signatures` ([`Dir::Data`]):
    /// packs they made (`binbun sig make`), matched beside those installed
    /// with binbun.
    Signatures,
    /// Files fetched from peers while they come, `collab/fetches`
    /// ([`Dir::Cache`]): each blob's resume state, made and removed by
    /// the fetch alone.
    Fetches,
    /// Files fetched from peers once whole, `downloads` ([`Dir::Data`]):
    /// where one goes unless the user chose where, under a name binbun
    /// gives it. Never a project's folder.
    Downloads,
}

impl Place {
    /// Every place.
    pub const ALL: [Self; 15] = [
        Self::Settings,
        Self::Startup,
        Self::Themes,
        Self::Projects,
        Self::Identity,
        Self::Recent,
        Self::Slices,
        Self::ConsoleHistory,
        Self::SkippedUpdate,
        Self::Symbols,
        Self::Servers,
        Self::TypeDb,
        Self::Signatures,
        Self::Fetches,
        Self::Downloads,
    ];

    /// The folder it is in.
    pub const fn dir(self) -> Dir {
        match self {
            Self::Settings | Self::Startup | Self::Themes => Dir::Config,
            Self::Projects | Self::Identity | Self::Signatures | Self::Downloads => Dir::Data,
            Self::Recent | Self::Slices | Self::ConsoleHistory | Self::SkippedUpdate => Dir::State,
            Self::Symbols | Self::TypeDb | Self::Fetches => Dir::Cache,
            Self::Servers => Dir::Runtime,
        }
    }

    /// Its path in its [`dir`](Self::dir).
    const fn name(self) -> &'static [&'static str] {
        match self {
            Self::Settings => &["settings.toml"],
            Self::Startup => &["startup.py"],
            Self::Themes => &["themes"],
            Self::Projects => &["projects"],
            Self::Identity => &["identity"],
            Self::Recent => &["recent"],
            Self::Slices => &["slices"],
            Self::ConsoleHistory => &["console_history"],
            Self::SkippedUpdate => &["skipped-update"],
            Self::Symbols => &["symbols"],
            Self::Servers => &[],
            Self::TypeDb => &["typedb"],
            Self::Signatures => &["signatures"],
            Self::Fetches => &["collab", "fetches"],
            Self::Downloads => &["downloads"],
        }
    }

    /// The place on `platform` from the environment variables' values
    /// `var` gives ([`Dir::path_in`]); `None` without its folder.
    pub fn path_in(
        self,
        platform: Platform,
        var: impl Fn(&str) -> Option<OsString>,
    ) -> Option<PathBuf> {
        if self == Self::TypeDb {
            if let Some(dir) = var("BINBUN_TYPEDB").filter(|dir| !dir.is_empty()) {
                return Some(dir.into());
            }
            if platform != Platform::Windows && absolute(&var, "BINBUN_HOME").is_none() {
                let mut path = home_in(platform, &var)?;
                path.extend([".cache", "binbun-typedb"]);
                return Some(path);
            }
        }
        let mut path = self.dir().path_in(platform, var)?;
        path.extend(self.name());
        Some(path)
    }

    /// The place as this process's environment says
    /// ([`path_in`](Self::path_in) on [`Platform::CURRENT`]).
    pub fn path(self) -> Option<PathBuf> {
        self.path_in(Platform::CURRENT, |name| env::var_os(name))
    }

    /// [`path`](Self::path), else (no such folder) its place under the
    /// temporary directory, `binbun` there standing for its folder.
    pub fn path_or_temporary(self) -> PathBuf {
        self.path().unwrap_or_else(|| {
            let mut path = env::temp_dir().join("binbun");
            path.extend(self.name());
            path
        })
    }

    /// Why it has no place ([`Dir::missing`]).
    pub fn missing(self) -> String {
        self.dir().missing()
    }
}

/// The value of variable `name` that `var` gives, where an absolute path.
fn absolute(var: impl Fn(&str) -> Option<OsString>, name: &str) -> Option<PathBuf> {
    var(name)
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
}

/// The user's home folder on `platform` from the environment variables'
/// values `var` gives: `USERPROFILE` on Windows (never `HOME`, which Git
/// Bash and MSYS2 set), `HOME` elsewhere; `None` where it is not an
/// absolute path.
pub fn home_in(platform: Platform, var: impl Fn(&str) -> Option<OsString>) -> Option<PathBuf> {
    absolute(var, platform.home_variable())
}

/// The user's home folder as this process's environment says
/// ([`home_in`] on [`Platform::CURRENT`]).
pub fn home() -> Option<PathBuf> {
    home_in(Platform::CURRENT, |name| env::var_os(name))
}

/// `path` made absolute with its links followed, as a user writes it: on
/// Windows without the verbatim prefix `fs::canonicalize` gives a drive's
/// path (`\\?\C:\…` becomes `C:\…`), so what is shown, stored or
/// handed to another program reads as an ordinary path.
///
/// # Errors
///
/// `fs::canonicalize`'s: the path does not exist or cannot be read.
pub fn canonical(path: &Path) -> io::Result<PathBuf> {
    let real = fs::canonicalize(path)?;
    let mut components = real.components();
    if let Some(std::path::Component::Prefix(prefix)) = components.next()
        && let std::path::Prefix::VerbatimDisk(drive) = prefix.kind()
    {
        let mut plain = PathBuf::from(format!("{}:", char::from(drive)));
        plain.extend(components);
        return Ok(plain);
    }
    Ok(real)
}

/// The first line of a `CACHEDIR.TAG` (<https://bford.info/cachedir/>),
/// which backup tools and cleaners know a cache by.
const CACHEDIR_SIGNATURE: &str = "Signature: 8a477f597d28d172789f06886806bc55";

/// Tags binbun's cache ([`Dir::Cache`]) with `CACHEDIR.TAG` if `made` is
/// in it and the tag is not there yet: called by what makes a folder in
/// it. Nothing for a folder elsewhere (a store of `_NT_SYMBOL_PATH`'s).
///
/// # Errors
///
/// The tag cannot be written.
pub fn tag_cache(made: &Path) -> io::Result<()> {
    match Dir::Cache.path() {
        Some(cache) if made.starts_with(&cache) => tag(&cache),
        Some(_) | None => Ok(()),
    }
}

/// Writes `CACHEDIR.TAG` in `cache` (made if it is not) unless there.
fn tag(cache: &Path) -> io::Result<()> {
    let file = cache.join("CACHEDIR.TAG");
    if file.exists() {
        return Ok(());
    }
    fs::create_dir_all(cache)?;
    fs::write(
        file,
        format!(
            "{CACHEDIR_SIGNATURE}\n\
             # This file is a cache directory tag created by binbun.\n\
             # For information about cache directory tags, see:\n\
             #\thttps://bford.info/cachedir/\n"
        ),
    )
}

/// One of binbun's folders as `binbun paths` lists it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Folder {
    /// Which.
    pub dir: Dir,
    /// Where, if it has a place.
    pub path: Option<PathBuf>,
    /// The bytes of the files in it (0 if it does not exist), not
    /// counting another of the folders inside it (on Windows the cache
    /// is in the data folder); `None` where not counted.
    pub size: Option<u64>,
}

/// binbun's folders as this process's environment says, in [`Dir::ALL`]'s
/// order, with their sizes if `sizes` (which walks them).
pub fn folders(sizes: bool) -> Vec<Folder> {
    let paths: Vec<(Dir, Option<PathBuf>)> =
        Dir::ALL.into_iter().map(|dir| (dir, dir.path())).collect();
    paths
        .iter()
        .map(|(dir, path)| Folder {
            dir: *dir,
            path: path.clone(),
            size: sizes.then(|| {
                path.as_deref().map_or(0, |path| {
                    let others: Vec<&Path> = paths
                        .iter()
                        .filter_map(|(_, other)| other.as_deref())
                        .filter(|other| *other != path)
                        .collect();
                    size_without(path, &others)
                })
            }),
        })
        .collect()
}

/// The bytes of the files under `dir`, symbolic links counted as
/// themselves and not followed; 0 if it does not exist. What cannot be
/// read is not counted.
pub fn size(dir: &Path) -> u64 {
    size_without(dir, &[])
}

/// [`size`] of `dir`, the folders `skipped` under it not counted.
fn size_without(dir: &Path, skipped: &[&Path]) -> u64 {
    let mut total = 0;
    let mut dirs = vec![dir.to_owned()];
    while let Some(dir) = dirs.pop() {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let Ok(meta) = entry.metadata() else {
                continue;
            };
            let path = entry.path();
            if meta.is_dir() {
                if !skipped.contains(&path.as_path()) {
                    dirs.push(path);
                }
            } else {
                total += meta.len();
            }
        }
    }
    total
}

/// `bytes` as a size is read: `0 bytes`, `512 bytes`, then decimal units
/// with one decimal below ten (`1.2 KB`, `34 MB`, `1.5 GB`).
pub fn size_text(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["KB", "MB", "GB", "TB", "PB"];
    if bytes < 1000 {
        return format!("{bytes} bytes");
    }
    // Rounded in integers: the largest unit it reads below 1000 of.
    let bytes = u128::from(bytes);
    let rounded = |scale: u128| (bytes + scale / 2) / scale;
    let mut unit = 0;
    let mut scale = 1000;
    while unit + 1 < UNITS.len() && rounded(scale) >= 1000 {
        unit += 1;
        scale *= 1000;
    }
    let name = UNITS.get(unit).copied().unwrap_or_default();
    let tenths = rounded(scale / 10);
    if tenths < 100 {
        format!("{}.{} {name}", tenths / 10, tenths % 10)
    } else {
        format!("{} {name}", rounded(scale))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::ffi::OsString;
    use std::fs;
    use std::path::{Path, PathBuf};

    use super::{Dir, Place, Platform, home_in, size, size_text};

    /// `path` from the root, as this host writes an absolute path.
    fn absolute(path: &str) -> PathBuf {
        let root = if cfg!(windows) { r"C:\" } else { "/" };
        Path::new(root).join(path)
    }

    /// An environment of `vars`, the rest unset.
    fn env(vars: &[(&str, &Path)]) -> impl Fn(&str) -> Option<OsString> {
        let vars: BTreeMap<String, OsString> = vars
            .iter()
            .map(|(name, value)| ((*name).to_owned(), value.as_os_str().to_owned()))
            .collect();
        move |name| vars.get(name).cloned()
    }

    /// `base` joined with `parts`.
    fn under(base: &Path, parts: &[&str]) -> PathBuf {
        let mut path = base.to_owned();
        path.extend(parts);
        path
    }

    /// A fresh scratch folder of this test's.
    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("binbun-paths-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// A canonical path is the file's, absolute, with no verbatim prefix
    /// (`\\?\`), even when reached through `..`.
    #[test]
    fn canonical_paths_read_as_written() {
        let dir = scratch("canonical");
        fs::create_dir(dir.join("sub")).unwrap();
        fs::write(dir.join("file"), b"x").unwrap();
        let path = super::canonical(&dir.join("sub").join("..").join("file")).unwrap();
        assert!(path.is_absolute(), "{path:?}");
        assert!(!path.to_string_lossy().starts_with(r"\\?\"), "{path:?}");
        assert!(
            !path
                .components()
                .any(|c| c == std::path::Component::ParentDir)
        );
        assert_eq!(fs::read(&path).unwrap(), b"x");
        assert_eq!(
            fs::canonicalize(&path).unwrap(),
            fs::canonicalize(dir.join("file")).unwrap()
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    /// Every folder's place where only the platforms' own variables are
    /// set: the module's table, each platform's tested on every host.
    #[test]
    fn each_platform_places_each_folder() {
        let home = absolute("home/a");
        let profile = absolute("Users/a");
        let tmp = absolute("tmp/user");
        let roaming = absolute("Users/a/AppData/Roaming");
        let local = absolute("Users/a/AppData/Local");
        let vars = [
            ("HOME", home.as_path()),
            ("USERPROFILE", &profile),
            ("TMPDIR", &tmp),
            ("APPDATA", &roaming),
            ("LOCALAPPDATA", &local),
        ];
        let support = ["Library", "Application Support", "binbun"];
        let expected: [(Platform, [Option<PathBuf>; 5]); 3] = [
            (
                Platform::Xdg,
                [
                    Some(under(&home, &[".config", "binbun"])),
                    Some(under(&home, &[".local", "share", "binbun"])),
                    Some(under(&home, &[".local", "state", "binbun"])),
                    Some(under(&home, &[".cache", "binbun"])),
                    None,
                ],
            ),
            (
                Platform::MacOs,
                [
                    Some(under(&home, &[".config", "binbun"])),
                    Some(under(&home, &support)),
                    Some(under(&home, &support).join("state")),
                    Some(under(&home, &["Library", "Caches", "binbun"])),
                    Some(under(&tmp, &["binbun"])),
                ],
            ),
            (
                Platform::Windows,
                [
                    Some(under(&roaming, &["binbun"])),
                    Some(under(&local, &["binbun"])),
                    Some(under(&local, &["binbun", "state"])),
                    Some(under(&local, &["binbun", "cache"])),
                    Some(under(&local, &["binbun", "run"])),
                ],
            ),
        ];
        for (platform, paths) in expected {
            for (dir, path) in Dir::ALL.into_iter().zip(paths) {
                assert_eq!(
                    dir.path_in(platform, env(&vars)),
                    path,
                    "{dir:?} {platform:?}"
                );
            }
        }
    }

    /// `BINBUN_HOME` first, then an XDG variable, on every platform; the
    /// runtime folder is not under `BINBUN_HOME`; a relative or empty
    /// value is ignored.
    #[test]
    fn binbun_home_then_xdg_win_everywhere() {
        let home = absolute("home/a");
        let local = absolute("Users/a/AppData/Local");
        let one = absolute("scratch/one");
        let mine = absolute("scratch/mine");
        for platform in Platform::ALL {
            for dir in Dir::ALL {
                let base = [("HOME", home.as_path()), ("LOCALAPPDATA", &local)];
                let xdg = [base[0], base[1], (dir.variable(), mine.as_path())];
                let both = [xdg[0], xdg[1], xdg[2], ("BINBUN_HOME", one.as_path())];
                assert_eq!(
                    dir.path_in(platform, env(&xdg)),
                    Some(mine.join("binbun")),
                    "{dir:?} {platform:?}"
                );
                let expected = if dir == Dir::Runtime {
                    mine.join("binbun")
                } else {
                    one.join(dir.name())
                };
                assert_eq!(dir.path_in(platform, env(&both)), Some(expected));
                for ignored in ["", "relative/dir"] {
                    let ignored = Path::new(ignored);
                    let vars = [
                        base[0],
                        base[1],
                        (dir.variable(), ignored),
                        ("BINBUN_HOME", ignored),
                    ];
                    assert_eq!(
                        dir.path_in(platform, env(&vars)),
                        dir.path_in(platform, env(&base)),
                        "{dir:?} {platform:?} {ignored:?}"
                    );
                }
            }
        }
    }

    /// On Windows `HOME` (Git Bash's, MSYS2's) places nothing, and the
    /// home is `USERPROFILE`.
    #[test]
    fn windows_never_reads_home() {
        let home = absolute("home/a");
        let profile = absolute("Users/a");
        let vars = [
            ("HOME", home.as_path()),
            ("TMPDIR", &home),
            ("USERPROFILE", &profile),
        ];
        for place in Place::ALL {
            assert_eq!(
                place.path_in(Platform::Windows, env(&vars)),
                None,
                "{place:?}"
            );
        }
        assert_eq!(
            home_in(Platform::Windows, env(&vars)),
            Some(profile.clone())
        );
        assert_eq!(home_in(Platform::Xdg, env(&vars)), Some(home.clone()));
        assert_eq!(home_in(Platform::MacOs, env(&vars)), Some(home));
    }

    /// Each place is in its folder, an override of the folder moving it;
    /// the identity is data; the type databases are `BINBUN_TYPEDB`
    /// wherever set, else under the home off Windows, `BINBUN_HOME` aside.
    #[test]
    fn places_follow_their_folder() {
        let home = absolute("home/a");
        let local = absolute("Users/a/AppData/Local");
        let mine = absolute("scratch/mine");
        let one = absolute("scratch/one");
        let vars = [
            ("HOME", home.as_path()),
            ("LOCALAPPDATA", &local),
            ("XDG_STATE_HOME", &mine),
        ];
        assert_eq!(
            Place::Recent.path_in(Platform::Windows, env(&vars)),
            Some(under(&mine, &["binbun", "recent"]))
        );
        assert_eq!(
            Place::Identity.path_in(Platform::Windows, env(&vars)),
            Some(under(&local, &["binbun", "identity"]))
        );
        assert_eq!(
            Place::Identity.path_in(Platform::Xdg, env(&vars)),
            Some(under(&home, &[".local", "share", "binbun", "identity"]))
        );
        assert_eq!(
            Place::TypeDb.path_in(Platform::Xdg, env(&vars)),
            Some(under(&home, &[".cache", "binbun-typedb"]))
        );
        assert_eq!(
            Place::TypeDb.path_in(Platform::Windows, env(&vars)),
            Some(under(&local, &["binbun", "cache", "typedb"]))
        );
        let with_home = [vars[0], ("BINBUN_HOME", one.as_path())];
        assert_eq!(
            Place::TypeDb.path_in(Platform::Xdg, env(&with_home)),
            Some(under(&one, &["cache", "typedb"]))
        );
        let typedb = [vars[0], vars[1], ("BINBUN_TYPEDB", Path::new("dbs"))];
        for platform in Platform::ALL {
            assert_eq!(
                Place::TypeDb.path_in(platform, env(&typedb)),
                Some(PathBuf::from("dbs"))
            );
        }
    }

    /// The places as the user is shown them, and what is missing naming
    /// the variables each platform reads.
    #[test]
    fn shown_and_missing_as_the_user_reads_them() {
        assert_eq!(
            Dir::Config.shown(Platform::Xdg).as_deref(),
            Some("~/.config/binbun")
        );
        assert_eq!(
            Dir::State.shown(Platform::Windows).as_deref(),
            Some(r"%LOCALAPPDATA%\binbun\state")
        );
        assert_eq!(
            Dir::Data.shown(Platform::MacOs).as_deref(),
            Some("~/Library/Application Support/binbun")
        );
        assert_eq!(
            Dir::Runtime.shown(Platform::MacOs).as_deref(),
            Some("$TMPDIR/binbun")
        );
        assert_eq!(Dir::Runtime.shown(Platform::Xdg), None);
        assert_eq!(
            Dir::Data.missing_on(Platform::Windows),
            "no data folder: neither BINBUN_HOME, XDG_DATA_HOME nor LOCALAPPDATA is an absolute path"
        );
        assert_eq!(
            Dir::Runtime.missing_on(Platform::Xdg),
            "no runtime folder: XDG_RUNTIME_DIR is not an absolute path"
        );
        assert_eq!(
            Dir::Config.missing_on(Platform::Windows),
            "no config folder: neither BINBUN_HOME, XDG_CONFIG_HOME nor APPDATA is an absolute path"
        );
    }

    /// The tag starts with the signature backup tools look for.
    #[test]
    fn the_cache_is_tagged_once() {
        let root = scratch("tag");
        super::tag(&root).unwrap();
        let text = fs::read_to_string(root.join("CACHEDIR.TAG")).unwrap();
        // The specification's signature, alone on the first line.
        assert!(
            text.starts_with("Signature: 8a477f597d28d172789f06886806bc55\n"),
            "{text}"
        );
        // A tag there is left as it is.
        fs::write(root.join("CACHEDIR.TAG"), "kept").unwrap();
        super::tag(&root).unwrap();
        assert_eq!(
            fs::read_to_string(root.join("CACHEDIR.TAG")).unwrap(),
            "kept"
        );
        fs::remove_dir_all(&root).unwrap();
    }

    /// Sizes count every file, not the folders skipped.
    #[test]
    fn sizes_count_files_and_read_in_decimal_units() {
        let root = scratch("size");
        fs::create_dir_all(root.join("a/b")).unwrap();
        fs::create_dir_all(root.join("cache")).unwrap();
        fs::write(root.join("a/b/f"), [0; 7]).unwrap();
        fs::write(root.join("g"), [0; 5]).unwrap();
        fs::write(root.join("cache/h"), [0; 100]).unwrap();
        assert_eq!(size(&root), 112);
        assert_eq!(super::size_without(&root, &[&root.join("cache")]), 12);
        assert_eq!(size(&root.join("none")), 0);
        fs::remove_dir_all(&root).unwrap();
        assert_eq!(size_text(0), "0 bytes");
        assert_eq!(size_text(999), "999 bytes");
        assert_eq!(size_text(1000), "1.0 KB");
        assert_eq!(size_text(9_949), "9.9 KB");
        assert_eq!(size_text(9_950), "10 KB");
        assert_eq!(size_text(999_600), "1.0 MB");
        assert_eq!(size_text(1_500_000_000), "1.5 GB");
    }
}
