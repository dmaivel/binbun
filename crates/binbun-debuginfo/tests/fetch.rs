//! Identities of the fixtures, verification, and fetching from a local
//! server standing in for a symbol server (no test touches the network).

mod support;

use std::fs;
use std::io::{Cursor, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use binbun_debuginfo::symbols::fetch::expand;
use binbun_debuginfo::symbols::{Cancel, Config, Failure, Guid, Identity, Mismatch, Pdb, Server};
use cab::{CabinetBuilder, CompressionType};
use support::server::LocalServer;

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(name)
}

fn read(name: &str) -> Vec<u8> {
    fs::read(fixture(name)).expect("the fixture")
}

/// A fresh directory for one test.
fn scratch(name: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join("binbun-symbols")
        .join(name);
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("a scratch directory");
    dir
}

/// Fetching from `servers` only (PDBs and debuginfod alike), caching in
/// `cache`, with a short timeout.
fn config(cache: &Path, servers: &[&str]) -> Config {
    let servers: Vec<Server> = servers.iter().map(|url| Server::new(url, cache)).collect();
    Config {
        stores: vec![cache.to_owned()],
        pdb_servers: servers.clone(),
        debuginfod: servers,
        timeout: Duration::from_secs(5),
    }
}

fn msvc() -> Identity {
    Identity::of(&read("msvc-x86_64.exe")).expect("a CodeView record")
}

fn units() -> Identity {
    Identity::of(&read("units-x86_64.elf")).expect("a build ID")
}

/// The URL path `identity` is served at.
fn served(identity: &Identity, compressed: bool) -> String {
    let (url, _) = identity
        .urls("")
        .into_iter()
        .find(|&(_, c)| c == compressed)
        .expect("that form");
    url
}

/// `data` as a cabinet holding `name`, MSZIP-compressed (as `makecab`
/// writes a `.pd_`).
fn cabinet(name: &str, data: &[u8]) -> Vec<u8> {
    let mut builder = CabinetBuilder::new();
    builder.add_folder(CompressionType::MsZip).add_file(name);
    let mut writer = builder.build(Cursor::new(Vec::new())).expect("a cabinet");
    while let Some(mut file) = writer.next_file().expect("its file") {
        file.write_all(data).expect("written");
    }
    writer.finish().expect("finished").into_inner()
}

/// Files in `dir` and below, relative to it.
fn files(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut pending = vec![dir.to_owned()];
    while let Some(at) = pending.pop() {
        for entry in fs::read_dir(&at).into_iter().flatten().flatten() {
            let path = entry.path();
            if path.is_dir() {
                pending.push(path);
            } else {
                out.push(path.strip_prefix(dir).expect("below").to_owned());
            }
        }
    }
    out.sort();
    out
}

#[test]
fn identities_come_from_codeview_and_build_id() {
    let Identity::Pdb(pdb) = msvc() else {
        panic!("a PDB");
    };
    assert_eq!(pdb.name, "msvc-x86_64.pdb");
    assert_eq!(pdb.age, 1);
    assert_eq!(
        units(),
        Identity::build_id("f9f584098b5d8a8478e75c99cfb45d2387c6d91c").unwrap()
    );
    // A separate debug file states the build ID too; a PDB is no image.
    assert_eq!(Identity::of(&read("units-x86_64.debug")), Some(units()));
    assert_eq!(Identity::of(&read("msvc-x86_64.pdb")), None);
}

#[test]
fn verification_takes_the_matching_file_only() {
    assert_eq!(msvc().verify(&fixture("msvc-x86_64.pdb")), Ok(()));
    // Another PDB: its own GUID.
    let Err(Mismatch::Pdb { guid, .. }) = msvc().verify(&fixture("seh-x86_64.pdb")) else {
        panic!("a GUID mismatch");
    };
    let Identity::Pdb(seh) = Identity::of(&read("seh-x86_64.exe")).unwrap() else {
        panic!("a PDB");
    };
    assert_eq!(guid, seh.guid);
    // The right GUID at another age.
    let Identity::Pdb(pdb) = msvc() else {
        panic!("a PDB");
    };
    let older = Identity::Pdb(Pdb { age: 2, ..pdb });
    assert_eq!(
        older.verify(&fixture("msvc-x86_64.pdb")),
        Err(Mismatch::Pdb {
            guid: guid_of(&msvc()),
            age: Some(1)
        })
    );
    // An ELF file is no PDB, and a PDB no ELF file.
    assert!(matches!(
        msvc().verify(&fixture("units-x86_64.debug")),
        Err(Mismatch::Unreadable(_))
    ));
    assert!(matches!(
        units().verify(&fixture("msvc-x86_64.pdb")),
        Err(Mismatch::Unreadable(_))
    ));
    assert_eq!(units().verify(&fixture("units-x86_64.debug")), Ok(()));
    assert!(matches!(
        units().verify(&fixture("rodata-x86_64.debug")),
        Err(Mismatch::BuildId(Some(_)))
    ));
}

fn guid_of(identity: &Identity) -> Guid {
    match identity {
        Identity::Pdb(pdb) => pdb.guid,
        Identity::BuildId(_) => panic!("a PDB"),
    }
}

#[test]
fn a_pdb_is_fetched_verified_and_cached_and_then_found_without_a_request() {
    let cache = scratch("pdb");
    let pdb = read("msvc-x86_64.pdb");
    let server = LocalServer::serve(vec![(served(&msvc(), false), pdb.clone())]);
    let config = config(&cache, &[&server.url]);
    assert_eq!(config.locate(&msvc()), None);
    assert!(server.requests().is_empty(), "locating sends nothing");

    let fetched = config.fetch(&msvc(), &Cancel::default()).unwrap();
    assert_eq!(fetched.path, cache.join(msvc().store_path()));
    assert!(!fetched.compressed);
    assert_eq!(fs::read(&fetched.path).unwrap(), pdb);
    assert_eq!(server.requests(), [served(&msvc(), false)]);
    // Nothing but the file in the store (no partial file left).
    assert_eq!(files(&cache), [msvc().store_path()]);

    // Opened again: the cache has it, the server hears nothing.
    assert_eq!(config.locate(&msvc()), Some(fetched.path));
    assert_eq!(server.requests().len(), 1);
}

#[test]
fn a_compressed_pdb_is_fetched_when_the_plain_one_is_absent_and_expanded() {
    let cache = scratch("compressed");
    let pdb = read("msvc-x86_64.pdb");
    let server = LocalServer::serve(vec![(
        served(&msvc(), true),
        cabinet("msvc-x86_64.pdb", &pdb),
    )]);
    let fetched = config(&cache, &[&server.url])
        .fetch(&msvc(), &Cancel::default())
        .unwrap();
    assert!(fetched.compressed);
    assert_eq!(fs::read(&fetched.path).unwrap(), pdb);
    assert_eq!(
        server.requests(),
        [served(&msvc(), false), served(&msvc(), true)]
    );
    assert_eq!(files(&cache), [msvc().store_path()]);
}

#[test]
fn a_cabinet_expands_to_its_file() {
    let dir = scratch("expand");
    let data: Vec<u8> = (0..200_000u32).map(|i| (i * 7 % 251) as u8).collect();
    fs::write(dir.join("x.pd_"), cabinet("x.pdb", &data)).unwrap();
    expand(&dir.join("x.pd_"), &dir.join("x.pdb")).unwrap();
    assert_eq!(fs::read(dir.join("x.pdb")).unwrap(), data);
    fs::write(dir.join("bad.pd_"), b"MSCF but not really").unwrap();
    assert!(expand(&dir.join("bad.pd_"), &dir.join("bad.pdb")).is_err());
}

#[test]
fn a_mismatched_file_is_refused_and_never_stored() {
    let cache = scratch("mismatch");
    let server = LocalServer::serve(vec![(served(&msvc(), false), read("seh-x86_64.pdb"))]);
    let failure = config(&cache, &[&server.url])
        .fetch(&msvc(), &Cancel::default())
        .unwrap_err();
    assert!(
        matches!(
            &failure,
            Failure::Mismatch {
                why: Mismatch::Pdb { .. },
                ..
            }
        ),
        "{failure:?}"
    );
    assert_eq!(files(&cache), Vec::<PathBuf>::new());
}

#[test]
fn debuginfod_serves_by_build_id_and_a_later_server_is_tried() {
    let cache = scratch("debuginfod");
    let debug = read("units-x86_64.debug");
    let empty = LocalServer::serve(Vec::new());
    let server = LocalServer::serve(vec![(served(&units(), false), debug.clone())]);
    let config = config(&cache, &[&empty.url, &server.url]);
    let fetched = config.fetch(&units(), &Cancel::default()).unwrap();
    assert_eq!(fetched.server.url, server.url);
    assert_eq!(
        fetched.path,
        cache
            .join("buildid/f9f584098b5d8a8478e75c99cfb45d2387c6d91c")
            .join("debuginfo")
    );
    assert_eq!(fs::read(&fetched.path).unwrap(), debug);
    assert_eq!(empty.requests(), [served(&units(), false)]);
    assert_eq!(config.locate(&units()), Some(fetched.path));
}

#[test]
fn failures_say_why() {
    let cache = scratch("failures");
    let empty = LocalServer::serve(Vec::new());
    let host = empty.url.trim_start_matches("http://").to_owned();
    assert_eq!(
        config(&cache, &[&empty.url]).fetch(&units(), &Cancel::default()),
        Err(Failure::NotFound {
            servers: vec![host]
        })
    );
    // A mismatch says more than another server's absence.
    let wrong = LocalServer::serve(vec![(served(&units(), false), read("rodata-x86_64.debug"))]);
    assert!(matches!(
        config(&cache, &[&empty.url, &wrong.url]).fetch(&units(), &Cancel::default()),
        Err(Failure::Mismatch {
            why: Mismatch::BuildId(Some(_)),
            ..
        })
    ));
    // Nothing listens on a port just released.
    let closed = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        format!("http://{}", listener.local_addr().unwrap())
    };
    assert!(matches!(
        config(&cache, &[&closed]).fetch(&units(), &Cancel::default()),
        Err(Failure::Network { .. })
    ));
    assert_eq!(
        config(&cache, &[]).fetch(&units(), &Cancel::default()),
        Err(Failure::NoServer)
    );
    // Cancelled before it starts: no request.
    let asked = empty.requests().len();
    let cancel = Cancel::default();
    cancel.cancel();
    assert_eq!(
        config(&cache, &[&empty.url]).fetch(&msvc(), &cancel),
        Err(Failure::Cancelled)
    );
    assert_eq!(empty.requests().len(), asked);
    assert_eq!(files(&cache), Vec::<PathBuf>::new());
}
