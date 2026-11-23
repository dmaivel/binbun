//! `binbun share` and `binbun join` over the loopback interface, no relay,
//! driven by commands on standard input: the joiner added by the owner
//! from their card (`--add`) and let in with nothing asked, or approved
//! live (`--yes`), or asked about and refused; an edit made on each
//! side seen on the other, the members listed; a joiner with no binary
//! fetching the one the host sends (`--send-binary`), then joining with
//! it in a project of its own for the share; values of a private project
//! brought into the share. Each side keeps its identity and projects in a
//! directory of its own.
//! Each side quits as soon as its own script is done: quitting sends what
//! the other has not had yet first.

#![cfg(feature = "collab")]
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers fail loudly"
)]

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::Receiver;
use std::time::{Duration, Instant};

fn fixture() -> String {
    format!(
        "{}/../../tests/fixtures/program-x86_64.elf",
        env!("CARGO_MANIFEST_DIR")
    )
}

/// `binbun` with `args`, its files under `home`, standard input, output
/// and error piped.
fn binbun(home: &Path, args: &[&str]) -> Child {
    let mut command = Command::new(env!("CARGO_BIN_EXE_binbun"));
    command.args(args);
    let _ = std::fs::create_dir_all(home);
    command.current_dir(home);
    for (variable, dir) in [
        ("HOME", ""),
        ("XDG_CONFIG_HOME", "config"),
        ("XDG_DATA_HOME", "data"),
        ("XDG_STATE_HOME", "state"),
        ("XDG_CACHE_HOME", "cache"),
    ] {
        command.env(variable, home.join(dir));
    }
    // It would win over the XDG variables.
    command.env_remove("BINBUN_HOME");
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
}

/// Writes `lines` to `child`'s input.
fn say(child: &mut Child, lines: &[&str]) {
    let input = child.stdin.as_mut().unwrap();
    for line in lines {
        writeln!(input, "{line}").unwrap();
    }
}

/// What `child` printed, once it ended; all it said if it failed.
fn printed(child: Child) -> String {
    let output = child.wait_with_output().unwrap();
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(
        output.status.success(),
        "{}\n{text}\n--- stderr ---\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    text
}

/// The identity card of the install whose files are under `home`
/// (`binbun id`), named `name`.
fn card(home: &Path, name: &str) -> String {
    let output = binbun(home, &["id", "--name", name])
        .wait_with_output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .find_map(|line| line.strip_prefix("card"))
        .unwrap()
        .trim()
        .to_owned()
}

/// `child`'s output, a line at a time as it prints it, until it ends.
fn lines_of(child: &mut Child) -> Receiver<String> {
    let out = child.stdout.take().unwrap();
    let (sender, lines) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(out).lines().map_while(Result::ok) {
            if sender.send(line).is_err() {
                break;
            }
        }
    });
    lines
}

/// The lines of `lines` up to the first holding `text`, which must come
/// within a minute.
fn until(lines: &Receiver<String>, text: &str) -> Vec<String> {
    let start = Instant::now();
    let mut seen = Vec::new();
    loop {
        let left = Duration::from_secs(60).saturating_sub(start.elapsed());
        let Ok(line) = lines.recv_timeout(left) else {
            panic!("no {text:?} in {seen:#?}");
        };
        let found = line.contains(text);
        seen.push(line);
        if found {
            return seen;
        }
    }
}

/// Starts `binbun share` of `file` for Ann under `dir` with `extra`
/// flags: the process and its ticket.
fn share(dir: &Path, file: &str, extra: &[&str]) -> (Child, String) {
    let ticket_file = dir.join("ticket");
    let mut args = vec![
        "share",
        file,
        "--relay",
        "none",
        "--bind",
        "127.0.0.1",
        "--name",
        "ann",
        "--ticket-file",
        ticket_file.to_str().unwrap(),
    ];
    args.extend_from_slice(extra);
    let host = binbun(&dir.join("ann"), &args);
    let start = Instant::now();
    let ticket = loop {
        if let Ok(ticket) = std::fs::read_to_string(&ticket_file) {
            break ticket.trim().to_owned();
        }
        assert!(start.elapsed() < Duration::from_secs(60), "no ticket");
        std::thread::sleep(Duration::from_millis(50));
    };
    (host, ticket)
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one scenario, both sides' scripts and checks"
)]
fn a_joiner_without_the_binary_fetches_the_one_sent_and_joins_with_it() {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("collab-cli-fetch-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let fixture = fixture();
    // Bob holds the ticket and was not added: approved live.
    let (mut host, ticket) = share(&dir, &fixture, &["--send-binary", "--yes"]);
    // A directory named as fetches once named theirs, beside the file:
    // Bob's own.
    let theirs = dir.join("bob").join(".program-x86_64.elf.binbun-fetch");
    std::fs::create_dir_all(&theirs).unwrap();
    std::fs::write(theirs.join("keep"), b"Bob's").unwrap();
    // Bob has no file: `join TICKET` fetches it into binbun's downloads
    // folder, under a name binbun gives it.
    let mut guest = binbun(
        &dir.join("bob"),
        &[
            "join",
            &ticket,
            "--relay",
            "none",
            "--bind",
            "127.0.0.1",
            "--name",
            "bob",
        ],
    );
    // Bob asks what Ann offers before he renames; Ann quits only once he
    // has left, so his offers are never cut by her going.
    say(
        &mut guest,
        &["wait linked 60", "offers", "rename classify sort", "quit"],
    );
    say(
        &mut host,
        &["wait name classify sort 60", "wait unlinked 60", "quit"],
    );
    let (host, guest) = (printed(host), printed(guest));
    let downloads = dir
        .join("bob")
        .join("data")
        .join("binbun")
        .join("downloads");
    let files: Vec<PathBuf> = under(&downloads)
        .into_iter()
        .filter(|path| path.is_file())
        .collect();
    let [fetched] = <[PathBuf; 1]>::try_from(files).unwrap();
    // The share's project is named after the binary offered, not the name
    // the fetch was saved under.
    let projects = dir.join("bob").join("data").join("binbun").join("projects");
    let names: Vec<String> = std::fs::read_dir(&projects)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert!(
        names.len() == 1 && names[0].contains("-program-x86_64.elf@"),
        "{names:?}"
    );
    assert!(
        fetched
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("binary-"),
        "{fetched:?}"
    );
    assert_eq!(
        std::fs::read(&fetched).unwrap(),
        std::fs::read(&fixture).unwrap()
    );
    // Nothing by the name offered; the blob gone from the cache once
    // whole; Bob's directory as it was.
    assert!(!dir.join("bob").join("program-x86_64.elf").exists());
    let cache = dir
        .join("bob")
        .join("cache")
        .join("binbun")
        .join("collab")
        .join("fetches");
    let left: Vec<PathBuf> = under(&cache)
        .into_iter()
        .filter(|path| *path != cache)
        .collect();
    assert!(
        !left.is_empty()
            && left.iter().all(|path| path
                .extension()
                .is_some_and(|extension| extension == "lock")),
        "{left:?}"
    );
    assert_eq!(std::fs::read(theirs.join("keep")).unwrap(), b"Bob's");
    assert!(
        guest.contains("the host offers the binary program-x86_64.elf"),
        "{guest}"
    );
    assert!(
        guest.contains("] fetched the binary program-x86_64.elf"),
        "{guest}"
    );
    assert!(guest.contains("SHA-256 checked"), "{guest}");
    assert!(
        host.lines().any(
            |line| line.contains("] sending the binary program-x86_64.elf (16.2 kB")
                && line.contains("to members who ask: sealed in")
        ),
        "{host}"
    );
    assert!(
        host.contains("] sent the binary program-x86_64.elf to "),
        "{host}"
    );
    // Bob's rename, made in the binary fetched, is Ann's too.
    assert!(host.contains("ok: name classify sort"), "{host}");
    // Linked, Bob sees what Ann offers.
    assert!(guest.contains("offer binary program-x86_64.elf"), "{guest}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one scenario, both sides' scripts and checks"
)]
fn share_and_join_sync_edits_both_ways() {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("collab-cli-sync-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let ticket_file = dir.join("ticket");
    let fixture = fixture();
    // Ann adds Bob from his card: he is let in when he joins.
    let bob = card(&dir.join("bob"), "bob");
    let mut host = binbun(
        &dir.join("ann"),
        &[
            "share",
            &fixture,
            "--relay",
            "none",
            "--bind",
            "127.0.0.1",
            "--add",
            &bob,
            "--name",
            "ann",
            "--ticket-file",
            ticket_file.to_str().unwrap(),
        ],
    );
    let start = Instant::now();
    let ticket = loop {
        if let Ok(ticket) = std::fs::read_to_string(&ticket_file) {
            break ticket.trim().to_owned();
        }
        assert!(start.elapsed() < Duration::from_secs(60), "no ticket");
        std::thread::sleep(Duration::from_millis(50));
    };
    assert!(ticket.starts_with("binbun"));
    let mut guest = binbun(
        &dir.join("bob"),
        &[
            "join",
            &ticket,
            &fixture,
            "--relay",
            "none",
            "--bind",
            "127.0.0.1",
            "--name",
            "bob",
        ],
    );
    say(
        &mut host,
        &[
            "wait linked 60",
            "rename classify sort",
            "wait name checked guard 60",
            "members",
            "conflicts",
            "quit",
        ],
    );
    say(
        &mut guest,
        &[
            "wait name classify sort 60",
            "rename checked guard",
            "wait changes 2 60",
            "state",
            "quit",
        ],
    );
    let (host, guest) = (printed(host), printed(guest));
    assert!(host.contains("] added bob ("), "{host}");
    assert!(!host.contains("asks to join"), "{host}");
    assert!(host.contains("ok: name checked guard"), "{host}");
    assert!(guest.contains("ok: name classify sort"), "{guest}");
    for said in [&host, &guest] {
        assert!(said.contains("1 member(s) acknowledged"), "{said}");
    }
    let members: Vec<&str> = host
        .lines()
        .filter(|line| line.starts_with("member "))
        .collect();
    assert_eq!(members.len(), 2, "{host}");
    assert!(
        members.iter().any(|line| line.contains(" owner (me) ")),
        "{host}"
    );
    assert!(
        members.iter().any(|line| line.contains(" editor ")),
        "{host}"
    );
    assert!(host.contains("0 conflict(s)"), "{host}");
    assert!(
        guest.contains("changes 2, ")
            && guest.contains("conflicts 0, refused 0, epoch 0 (keys [0]), role editor"),
        "{guest}"
    );
    // Bob's share has a project of its own, beside nothing private.
    let projects = dir.join("bob").join("data").join("binbun").join("projects");
    let names: Vec<String> = std::fs::read_dir(&projects)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert!(
        names.len() == 1 && names[0].contains("-program-x86_64.elf@"),
        "{names:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_thread_and_a_suggestion_cross_and_the_host_accepts_it() {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("collab-cli-talk-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let fixture = fixture();
    let bob = card(&dir.join("bob"), "bob");
    let (mut host, ticket) = share(&dir, &fixture, &["--add", &bob]);
    let mut guest = binbun(
        &dir.join("bob"),
        &[
            "join",
            &ticket,
            &fixture,
            "--relay",
            "none",
            "--bind",
            "127.0.0.1",
            "--name",
            "bob",
        ],
    );
    say(
        &mut host,
        &[
            "wait linked 60",
            "thread 0x1190 Why does it start here?",
            "wait posts 2 60",
            "wait suggestions 1 60",
            "accept last 0",
            "threads",
            "suggestions",
            "wait unlinked 60",
            "quit",
        ],
    );
    say(
        &mut guest,
        &[
            "wait threads 1 60",
            "post last Because it is called.",
            "suggest classify sign_of it returns a sign",
            "wait name classify sign_of 60",
            "quit",
        ],
    );
    let (host, guest) = (printed(host), printed(guest));
    assert!(guest.contains("ok: name classify sign_of"), "{guest}");
    let posts: Vec<&str> = host
        .lines()
        .filter(|line| line.trim_start().starts_with("post "))
        .collect();
    assert_eq!(posts.len(), 2, "{host}");
    assert!(posts[0].ends_with(": Why does it start here?"), "{host}");
    assert!(posts[1].ends_with(": Because it is called."), "{host}");
    assert!(
        host.contains("thread ") && host.contains("Instruction(4496)"),
        "{host}"
    );
    assert!(host.contains("\"Name classify\" Accepted([0])"), "{host}");
    assert!(
        host.contains("  0 function 0x") && host.contains("\"sign_of\""),
        "{host}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_failed_edit_command_fails_saying_why_on_standard_error() {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("collab-cli-edit-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let fixture = fixture();
    let edit = |words: &[&str]| {
        let mut args = vec!["edit", fixture.as_str()];
        args.extend_from_slice(words);
        binbun(&dir, &args).wait_with_output().unwrap()
    };
    for (words, why) in [
        (
            &["rename", "no_such_function", "x"][..],
            "no function no_such_function",
        ),
        (&["links"][..], "needs a live session"),
        (&["frobnicate"][..], "unknown command"),
    ] {
        let output = edit(words);
        assert!(!output.status.success(), "{words:?}");
        assert!(output.stdout.is_empty(), "{words:?}");
        let said = String::from_utf8(output.stderr).unwrap();
        assert!(said.contains(why), "{words:?}: {said}");
    }
    // The same command on a function there succeeds.
    let output = edit(&["rename", "main", "entry_point"]);
    assert!(output.status.success(), "{output:?}");
    assert!(
        String::from_utf8(output.stdout)
            .unwrap()
            .contains("renamed")
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Every path under `dir`.
fn under(dir: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut todo = vec![dir.to_path_buf()];
    while let Some(path) = todo.pop() {
        if let Ok(entries) = std::fs::read_dir(&path) {
            todo.extend(entries.flatten().map(|entry| entry.path()));
        }
        found.push(path);
    }
    found
}

#[test]
fn a_join_with_another_binary_ends_and_leaves_its_project_alone() {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("collab-cli-other-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let bob = card(&dir.join("bob"), "bob");
    let (mut host, ticket) = share(&dir, &fixture(), &["--add", &bob]);

    // Bob joins Ann's share with another binary: the join ends, and that
    // binary's project is not made the shared one's.
    let other = format!(
        "{}/../../tests/fixtures/units-x86_64.elf",
        env!("CARGO_MANIFEST_DIR")
    );
    let mut guest = binbun(
        &dir.join("bob"),
        &[
            "join",
            &ticket,
            &other,
            "--relay",
            "none",
            "--bind",
            "127.0.0.1",
            "--name",
            "bob",
        ],
    );
    drop(guest.stdin.take());
    let output = guest.wait_with_output().unwrap();
    let said = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "{said}");
    assert!(
        said.contains("is not the binary the project shared annotates"),
        "{said}"
    );
    // The file is checked against the chain's binary before any project
    // is opened: none was made for it, shared or not.
    let projects: Vec<PathBuf> = under(&dir.join("bob"))
        .into_iter()
        .filter(|path| path.to_string_lossy().contains("-units-x86_64.elf"))
        .collect();
    assert_eq!(projects, Vec::<PathBuf>::new());
    say(&mut host, &["quit"]);
    printed(host);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_ticket_holder_the_owner_did_not_add_is_asked_about_and_refused_holds_nothing() {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("collab-cli-stranger-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let fixture = fixture();
    let (mut host, ticket) = share(&dir, &fixture, &[]);
    let asked = lines_of(&mut host);
    let guest = binbun(
        &dir.join("bob"),
        &[
            "join",
            &ticket,
            &fixture,
            "--relay",
            "none",
            "--bind",
            "127.0.0.1",
            "--name",
            "bob",
        ],
    );
    // Ann is asked about Bob, with an id to answer by; she refuses.
    let seen = until(&asked, ": admit as editor (e ");
    assert!(
        seen.iter()
            .any(|line| line.contains("bob (") && line.contains("asks to join")),
        "{seen:#?}"
    );
    let id = seen
        .last()
        .and_then(|line| line.split("request ").nth(1))
        .and_then(|rest| rest.split(':').next())
        .unwrap()
        .to_owned();
    say(&mut host, &[&format!("n {id}")]);
    // Refused, Bob's join ends with the reason.
    let output = guest.wait_with_output().unwrap();
    let said = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "{said}");
    assert!(said.contains("refused by the host"), "{said}");
    say(&mut host, &["members", "quit"]);
    let rest: Vec<String> = asked.iter().collect();
    assert!(host.wait().unwrap().success(), "{rest:#?}");
    // Ann admitted no one.
    let members = rest
        .iter()
        .filter(|line| line.starts_with("member "))
        .count();
    assert_eq!(members, 1, "{rest:#?}");
    // Bob holds nothing of the share: no project made for it.
    let shared: Vec<PathBuf> = under(&dir.join("bob"))
        .into_iter()
        .filter(|path| path.to_string_lossy().contains(".elf@"))
        .collect();
    assert_eq!(shared, Vec::<PathBuf>::new());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn values_of_a_private_project_brought_into_the_share_reach_the_owner() {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("collab-cli-bring-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let fixture = fixture();
    let home = dir.join("bob");
    // Bob's own analysis, before the share.
    let output = binbun(&home, &["edit", &fixture, "rename", "main", "bobs_main"])
        .wait_with_output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let bob = card(&home, "bob");
    let (mut host, ticket) = share(&dir, &fixture, &["--add", &bob]);
    let join = |script: &[&str]| {
        let mut guest = binbun(
            &home,
            &[
                "join",
                &ticket,
                &fixture,
                "--relay",
                "none",
                "--bind",
                "127.0.0.1",
                "--name",
                "bob",
            ],
        );
        say(&mut guest, script);
        printed(guest)
    };
    // Joined: his private name is not in the share.
    let first = join(&["wait linked 60", "quit"]);
    assert!(!first.contains("bobs_main"), "{first}");
    // Listed with who wrote it, then brought, as one change of his.
    let list = binbun(&home, &["bring", &fixture, "--list"])
        .wait_with_output()
        .unwrap();
    let listed = String::from_utf8(list.stdout).unwrap();
    assert!(
        listed.contains("\"bobs_main\" by you") && listed.contains("1 value(s) to bring"),
        "{listed}"
    );
    let brought = binbun(&home, &["bring", &fixture, "--all"])
        .wait_with_output()
        .unwrap();
    let said = String::from_utf8(brought.stdout).unwrap();
    assert!(said.starts_with("brought 1 value(s) into "), "{said}");
    // At the next join the share takes it, and Ann has it.
    say(&mut host, &["wait name main bobs_main 60", "quit"]);
    join(&["wait linked 60", "sleep 2000", "quit"]);
    let host = printed(host);
    assert!(host.contains("ok: name main bobs_main"), "{host}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_owner_sees_what_goes_with_a_share_and_chooses_it() {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("collab-cli-history-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let fixture = fixture();
    let home = dir.join("ann");
    let output = binbun(&home, &["edit", &fixture, "rename", "main", "anns_main"])
        .wait_with_output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    // Listed, numbered, hers marked as going by default; nothing shared.
    let listed = printed(binbun(&home, &["share", &fixture, "--history", "list"]));
    assert!(
        listed.contains("1 * chain ") && listed.contains(", yours, 2 change(s)"),
        "{listed}"
    );
    assert!(listed.contains("1 chain(s)"), "{listed}");
    // Shared with none of it: nothing said to go, and her earlier name is
    // kept apart, out of the share's project.
    let (mut host, _) = share(&dir, &fixture, &["--history", "none"]);
    say(&mut host, &["wait name main main 30", "quit"]);
    let host = printed(host);
    assert!(
        !host.contains("goes with the share") && host.contains("ok: name main main"),
        "{host}"
    );
    // Shared anew by default (another install): its chain is said to go.
    let output = binbun(
        &dir.join("cat"),
        &["edit", &fixture, "rename", "main", "cats_main"],
    )
    .wait_with_output()
    .unwrap();
    assert!(output.status.success(), "{output:?}");
    let ticket_file = dir.join("cat-ticket");
    let mut cat = binbun(
        &dir.join("cat"),
        &[
            "share",
            &fixture,
            "--relay",
            "none",
            "--bind",
            "127.0.0.1",
            "--ticket-file",
            ticket_file.to_str().unwrap(),
        ],
    );
    say(&mut cat, &["wait name cats_main cats_main 30", "quit"]);
    let cat = printed(cat);
    assert!(
        cat.contains("goes with the share: 1 * chain ")
            && cat.contains("ok: name cats_main cats_main"),
        "{cat}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
