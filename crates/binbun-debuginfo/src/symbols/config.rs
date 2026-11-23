//! Where debug information is looked for and fetched from ([`Config`]):
//! local stores read first, symbol servers and the caches their downloads
//! go to, in Microsoft's `_NT_SYMBOL_PATH` syntax ([`SymbolPath`]) and
//! debuginfod's `DEBUGINFOD_URLS`.

use std::collections::HashSet;
use std::env;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::symbols::identity::Identity;

/// Microsoft's public symbol server.
pub const MICROSOFT: &str = "https://msdl.microsoft.com/download/symbols";

/// A symbol server, and the store its downloads are cached in.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Server {
    /// Its URL, without a trailing `/`.
    pub url: String,
    /// The store (symstore layout) files fetched from it are written to.
    pub cache: PathBuf,
}

impl Server {
    /// The server at `url` caching in `cache`.
    pub fn new(url: &str, cache: impl Into<PathBuf>) -> Self {
        Self {
            url: url.trim_end_matches('/').to_owned(),
            cache: cache.into(),
        }
    }

    /// Its host, as a user knows it (`msdl.microsoft.com`); the URL if it
    /// names none.
    pub fn host(&self) -> &str {
        self.url
            .split_once("://")
            .map_or(self.url.as_str(), |(_, rest)| rest)
            .split(['/', '?'])
            .next()
            .unwrap_or(&self.url)
    }
}

/// A symbol path in Microsoft's syntax (`_NT_SYMBOL_PATH`, `.sympath`), as
/// stores and servers.
///
/// Elements are separated by `;`:
/// - `srv*[store*…]*url` (also `symsrv*symsrv.dll*…`): the stores are
///   read, the URLs are servers whose downloads go to the first store
///   (the downstream store), else to the cache in force;
/// - `cache*dir` (or `cache*`, the default cache): read, and the cache
///   for servers after it that name none;
/// - a URL alone: a server, its downloads to the cache in force;
/// - anything else: a directory read (flat or in symstore layout).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SymbolPath {
    /// The stores read, in order.
    pub stores: Vec<PathBuf>,
    /// The servers, in order.
    pub servers: Vec<Server>,
}

impl SymbolPath {
    /// Parses `text`, the caches it leaves unnamed being `default_cache`.
    pub fn parse(text: &str, default_cache: &Path) -> Self {
        let mut path = Self::default();
        let mut cache = default_cache.to_owned();
        for element in text.split(';').map(str::trim).filter(|e| !e.is_empty()) {
            let lower = element.to_ascii_lowercase();
            if lower == "cache" || lower.starts_with("cache*") {
                let dir = element.get("cache*".len()..).unwrap_or_default();
                cache = if dir.is_empty() {
                    default_cache.to_owned()
                } else {
                    PathBuf::from(dir)
                };
                path.stores.push(cache.clone());
            } else if let Some(parts) = server_parts(element, &lower) {
                let mut downstream = None;
                for part in parts.split('*') {
                    if is_url(part) {
                        let to = downstream.clone().unwrap_or_else(|| cache.clone());
                        path.servers.push(Server::new(part, to));
                    } else if !part.is_empty() {
                        downstream.get_or_insert_with(|| PathBuf::from(part));
                        path.stores.push(PathBuf::from(part));
                    } else if downstream.is_none() {
                        // `srv**url`: the default downstream store.
                        downstream = Some(default_cache.to_owned());
                    }
                }
            } else if is_url(element) {
                path.servers.push(Server::new(element, cache.clone()));
            } else {
                path.stores.push(PathBuf::from(element));
            }
        }
        path
    }
}

/// The parts after `srv*` or `symsrv*<dll>*`, if `element` is such.
fn server_parts<'a>(element: &'a str, lower: &str) -> Option<&'a str> {
    if lower.starts_with("srv*") {
        return element.get("srv*".len()..);
    }
    if lower.starts_with("symsrv*") {
        let rest = element.get("symsrv*".len()..)?;
        return Some(rest.split_once('*').map_or("", |(_, parts)| parts));
    }
    None
}

/// Whether `text` is an HTTP(S) URL.
fn is_url(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    lower.starts_with("http://") || lower.starts_with("https://")
}

/// binbun's own symbol cache as the environment says
/// ([`binbun_paths::Place::Symbols`], under the temporary directory without
/// binbun's cache directory): where its downloads go, the one directory
/// binbun may clear.
pub fn cache() -> PathBuf {
    binbun_paths::Place::Symbols.path_or_temporary()
}

/// Where debug information is looked for and fetched from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    /// The stores read before any server, in order (each in symstore
    /// layout, `<name>/<key>/<name>` and `buildid/<key>/debuginfo`, or
    /// flat, `<name>`); the servers' caches are read too.
    pub stores: Vec<PathBuf>,
    /// The servers PDBs are fetched from, in order.
    pub pdb_servers: Vec<Server>,
    /// The debuginfod servers ELF debug files are fetched from, in order.
    pub debuginfod: Vec<Server>,
    /// How long connecting, and each wait for the server, may take.
    pub timeout: Duration,
}

impl Config {
    /// The default timeout: 20 seconds to connect, and for each wait for
    /// the server.
    pub const TIMEOUT: Duration = Duration::from_secs(20);

    /// Everything read from and written to `cache`, PDBs fetched from
    /// Microsoft's server, no debuginfod server.
    pub fn with_cache(cache: impl Into<PathBuf>) -> Self {
        let cache = cache.into();
        Self {
            stores: vec![cache.clone()],
            pdb_servers: vec![Server::new(MICROSOFT, cache)],
            debuginfod: Vec::new(),
            timeout: Self::TIMEOUT,
        }
    }

    /// As the environment says: binbun's cache ([`cache`]);
    /// `_NT_SYMBOL_PATH`'s stores and servers ([`SymbolPath`]) if it is
    /// set, else Microsoft's server; the store in `~/.ntoseye/symbols`
    /// read if it exists; the debuginfod servers of `DEBUGINFOD_URLS`
    /// (space-separated), none if unset.
    pub fn from_environment() -> Self {
        let cache = cache();
        let ntoseye = binbun_paths::home()
            .map(|home| home.join(".ntoseye").join("symbols"))
            .filter(|store| store.is_dir());
        Self::from_variables(
            &cache,
            env::var("_NT_SYMBOL_PATH").ok().as_deref(),
            env::var("DEBUGINFOD_URLS").ok().as_deref(),
            ntoseye.as_deref(),
        )
    }

    /// [`Self::from_environment`] from the variables' values: the cache
    /// `cache`, `_NT_SYMBOL_PATH` `symbol_path`, `DEBUGINFOD_URLS`
    /// `debuginfod`, and another store read last, `other`.
    pub fn from_variables(
        cache: &Path,
        symbol_path: Option<&str>,
        debuginfod: Option<&str>,
        other: Option<&Path>,
    ) -> Self {
        let mut config = Self::with_cache(cache);
        if let Some(symbol_path) = symbol_path.filter(|path| !path.trim().is_empty()) {
            let parsed = SymbolPath::parse(symbol_path, cache);
            config.stores = parsed.stores;
            config.stores.push(cache.to_owned());
            config.pdb_servers = parsed.servers;
        }
        config.stores.extend(other.map(Path::to_owned));
        config.debuginfod = debuginfod
            .unwrap_or_default()
            .split_ascii_whitespace()
            .filter(|url| is_url(url))
            .map(|url| Server::new(url, cache))
            .collect();
        config
    }

    /// The servers `identity` is fetched from.
    pub fn servers(&self, identity: &Identity) -> &[Server] {
        match identity {
            Identity::Pdb(_) => &self.pdb_servers,
            Identity::BuildId(_) => &self.debuginfod,
        }
    }

    /// The local files `identity` may be in, in the order they are tried:
    /// each store (then each server's cache) in symstore layout, then a
    /// PDB flat in it, by its name and by its name with the key before
    /// the extension (`ntdll.<key>.pdb`, as `~/.ntoseye/symbols` holds
    /// them).
    pub fn candidates(&self, identity: &Identity) -> Vec<PathBuf> {
        let mut seen = HashSet::new();
        let stores = self
            .stores
            .iter()
            .chain(self.servers(identity).iter().map(|server| &server.cache))
            .filter(|store| seen.insert(*store));
        let mut out = Vec::new();
        for store in stores {
            out.push(store.join(identity.store_path()));
            if let Identity::Pdb(pdb) = identity {
                out.push(store.join(&pdb.name));
                let keyed = match pdb.name.rsplit_once('.') {
                    Some((stem, extension)) => format!("{stem}.{}.{extension}", identity.key()),
                    None => format!("{}.{}", pdb.name, identity.key()),
                };
                out.push(store.join(keyed));
            }
        }
        out
    }

    /// The first of [`Self::candidates`] that is `identity`
    /// ([`Identity::verify`]): nothing is sent anywhere.
    pub fn locate(&self, identity: &Identity) -> Option<PathBuf> {
        self.candidates(identity)
            .into_iter()
            .find(|candidate| candidate.is_file() && identity.verify(candidate).is_ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::symbols::identity::{Guid, Pdb};

    #[test]
    fn symbol_paths_parse_in_nt_symbol_path_syntax() {
        let default = Path::new("/default");
        let parsed = SymbolPath::parse(
            "srv*/a*https://one.example/s/;cache*/c;HTTPS://two.example;/plain; ;\
             SRV*https://three.example;symsrv*symsrv.dll*/d*http://four.example;srv**https://five.example;cache*;https://six.example",
            default,
        );
        assert_eq!(
            parsed.stores,
            [
                Path::new("/a"),
                Path::new("/c"),
                Path::new("/plain"),
                Path::new("/d"),
                Path::new("/default"),
            ]
        );
        assert_eq!(
            parsed.servers,
            [
                Server::new("https://one.example/s", "/a"),
                Server::new("HTTPS://two.example", "/c"),
                Server::new("https://three.example", "/c"),
                Server::new("http://four.example", "/d"),
                Server::new("https://five.example", "/default"),
                Server::new("https://six.example", "/default"),
            ]
        );
    }

    #[test]
    fn the_environment_decides_stores_and_servers() {
        let cache = Path::new("/cache");
        let unset = Config::from_variables(cache, None, None, None);
        assert_eq!(unset, Config::with_cache(cache));
        assert_eq!(unset.pdb_servers, [Server::new(MICROSOFT, cache)]);
        assert_eq!(unset.debuginfod, []);

        let set = Config::from_variables(
            cache,
            Some("/local;srv*/sym*https://symbols.example"),
            Some("  https://a.example/  ftp://no.example https://b.example "),
            Some(Path::new("/ntoseye")),
        );
        assert_eq!(
            set.stores,
            [
                Path::new("/local"),
                Path::new("/sym"),
                cache,
                Path::new("/ntoseye")
            ]
        );
        assert_eq!(
            set.pdb_servers,
            [Server::new("https://symbols.example", "/sym")]
        );
        assert_eq!(
            set.debuginfod,
            [
                Server::new("https://a.example", cache),
                Server::new("https://b.example", cache)
            ]
        );
        // A path naming no server fetches nothing.
        let local = Config::from_variables(cache, Some("/only"), None, None);
        assert_eq!(local.pdb_servers, []);
    }

    #[test]
    fn candidates_cover_every_store_once_in_both_layouts() {
        let mut config = Config::with_cache("/cache");
        config.stores.insert(0, PathBuf::from("/flat"));
        let pdb = Identity::Pdb(Pdb {
            name: "a.pdb".to_owned(),
            guid: Guid([0; 16]),
            age: 11,
        });
        assert_eq!(
            config.candidates(&pdb),
            [
                Path::new("/flat/a.pdb/00000000000000000000000000000000B/a.pdb"),
                Path::new("/flat/a.pdb"),
                Path::new("/flat/a.00000000000000000000000000000000B.pdb"),
                Path::new("/cache/a.pdb/00000000000000000000000000000000B/a.pdb"),
                Path::new("/cache/a.pdb"),
                Path::new("/cache/a.00000000000000000000000000000000B.pdb"),
            ]
        );
        let elf = Identity::build_id("aabb").unwrap();
        assert_eq!(
            config.candidates(&elf),
            [
                Path::new("/flat/buildid/aabb/debuginfo"),
                Path::new("/cache/buildid/aabb/debuginfo")
            ]
        );
    }

    #[test]
    fn a_server_names_its_host() {
        assert_eq!(Server::new(MICROSOFT, "/c").host(), "msdl.microsoft.com");
        assert_eq!(
            Server::new("http://127.0.0.1:8000/x?y", "/c").host(),
            "127.0.0.1:8000"
        );
    }
}
