//! `binbun id`, `share`, `join`, `edit` and `bring`: a project shared
//! between peers ([`binbun_collab`]).
//!
//! `share` and `join` keep running: what the peer tells is printed as it
//! happens, each line stamped with the seconds since the command
//! started, and each line of standard input is a command ([`driver`]),
//! so a script can drive a session. The owner adds members by their
//! identity cards (`share --add CARD`, or `add CARD` typed while sharing;
//! `binbun id` prints one's card, whose fingerprint the two check between
//! them): their key is let in when it joins, with nothing asked. Live
//! approval of whoever else holds the ticket is the default: a host asks on
//! standard input about each request (with `--yes` it admits everyone
//! holding the ticket), one request at a time,
//! the others waiting in the order they came, each shown with an id of
//! its own, numbered on from a start drawn at random. Every answer names
//! that id (`e 7f3a`, `v 7f3a`, `n 7f3a`). An answer naming another id,
//! or none, is refused with a message, and never answers another request
//! ([`Prompts::answer`]). What peers say is
//! printed with the characters that move or hide what a terminal shows
//! escaped ([`shown`]), field by field before a line is put together.
//! `edit` runs one command on the project with no peer, its edits synced
//! at the next `share` or `join`. A process at a time works on a project:
//! `share`, `join` and `edit` hold its lock.
//!
//! **Which project.** A binary may have a private project and one per
//! share it was joined in (`join` makes the share's own,
//! `<sha256>-<name>@<share>`; an owner's share is their project, shared
//! in place). `share` and `edit` open the one there is, else the one used
//! last and say which; `--share ID` or `--private` chooses. `bring`
//! publishes chosen values of the private project in a share's, as one
//! new change of this install's key.
//!
//! Files by hash: `share --send-binary` (and `--send-debug`) offers the
//! binary (the debug file the analysis read) to members who ask, sealed
//! once into the project's blob store; `join TICKET` with no file, or a
//! file that is not there, fetches the binary the host offers into it (by
//! default into binbun's downloads folder, under a name binbun gives it:
//! [`fetches`]), how far it is printed as it goes, going on where a fetch
//! cut short stopped (in binbun's cache); a joiner whose file is there
//! never fetches.
//! Either way the file is the binary the project shared annotates, as its
//! owner's membership chain names it: one of other bytes ends the join
//! before its project is made the shared one's.

mod driver;

use std::collections::{BTreeSet, VecDeque};
use std::fmt::Write as _;
use std::fs::{self, File};
use std::io::{self, BufRead};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use binbun_collab::blobs::{Fetched, Kind, Offer, OnProgress, Progress, Step, Visit};
use binbun_collab::fetches::{self, Fetches};
use binbun_collab::live::LiveEvent;
use binbun_collab::membership::{Binary, Role};
use binbun_collab::net::{IrohTransport, NetOptions, Relay};
use binbun_collab::ticket::{self, Card, JoinTicket, LAN_ONLY, fingerprint};
use binbun_collab::{
    Approver, Config, Listable, Notice, Notifier, Peer, Request, Transport, listable,
};
use binbun_paths::Place;
use binbun_session::identity::{self, Identity};
use binbun_session::journal::{Bringable, ChainId, EngineVersion, PublicKey};
use binbun_session::project::{self, Choice, Chosen};
use binbun_session::{Options, Session, Stage, Waited};
use tokio::sync::{mpsc, oneshot};

use driver::Driver;

use super::{USAGE, arch};

/// `binbun id`: this install's identity key, its fingerprint and its
/// identity card.
pub fn id(args: &[String]) -> Result<String, String> {
    let mut name = None;
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--name" => name = Some(args.next().ok_or("--name takes a name")?.clone()),
            other => return Err(format!("binbun id: unknown argument {other:?}")),
        }
    }
    let identity = identity()?;
    let card = Card::new(&identity, &name.unwrap_or_else(default_name));
    let engine = EngineVersion::this();
    Ok(format!(
        "key          {}\nfingerprint  {}\nname         {}\ncard         {card}\nbinbun       {} (build {})\n",
        identity.public(),
        fingerprint(identity.public()),
        card.name,
        engine.release,
        engine.build
    ))
}

/// This install's identity.
fn identity() -> Result<Identity, String> {
    let root = identity::root().ok_or_else(|| Place::Identity.missing())?;
    Identity::load_or_create(&root)
}

/// This install's identity for a peer, and the lock that keeps it one
/// peer's: an endpoint's key is to be used by one endpoint at a time.
fn peer_identity() -> Result<(Identity, File), String> {
    let identity = identity()?;
    let root = identity::root().ok_or_else(|| Place::Identity.missing())?;
    let path = root.join("collab.lock");
    let lock = File::create(&path).map_err(|error| format!("{}: {error}", path.display()))?;
    lock.try_lock()
        .map_err(|_| "another binbun shares or joins with this identity".to_owned())?;
    Ok((identity, lock))
}

/// The name on this install's card by default: the login.
fn default_name() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "someone".to_owned())
}

/// How `share` and `join` are told to reach peers.
#[derive(Default)]
struct Network {
    relay: Option<Relay>,
    mdns: bool,
    no_portmap: bool,
    lan_only: bool,
    bind: Option<SocketAddr>,
}

/// The address `text` gives to bind: an IP address (any port), or one
/// with a port.
fn parse_bind(text: &str) -> Result<SocketAddr, String> {
    text.parse::<SocketAddr>()
        .or_else(|_| text.parse::<IpAddr>().map(|ip| SocketAddr::new(ip, 0)))
        .map_err(|_| format!("not an address: {text}"))
}

/// How a host answers those holding its ticket who are not members (the
/// members its owner added are let in at once).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum Approval {
    /// Each request asked on standard input (the default).
    #[default]
    Ask,
    /// Everyone, as `--role` (`--yes`).
    Everyone,
}

/// What `share` and `join` are given.
#[derive(Default)]
struct Flags {
    network: Network,
    /// How those holding the ticket who are not members are answered.
    approval: Approval,
    role: Option<Role>,
    /// Identity cards to add as members (`role`) before the ticket is out.
    add: Vec<String>,
    /// Which of the binary's projects to open.
    choice: Choice,
    name: Option<String>,
    ticket_file: Option<String>,
    /// Offer the binary to members who ask.
    send_binary: bool,
    /// Offer the debug file the analysis read.
    send_debug: bool,
    /// What of the project from before the share a share made anew lists
    /// in its first record (`--history`).
    history: History,
}

/// What of the project from before the share goes with a share made
/// anew (`--history`).
#[derive(Default)]
enum History {
    /// This install's chains and its agents' (as [`binbun_collab::listable`]
    /// chooses).
    #[default]
    Own,
    /// The chains that could go, numbered; nothing shared.
    List,
    /// None of them.
    Nothing,
    /// Those numbered so in the list.
    Numbers(Vec<usize>),
}

impl History {
    /// `--history`'s value: `list`, `none`, or numbers of the list,
    /// comma-separated.
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "list" => Ok(Self::List),
            "none" => Ok(Self::Nothing),
            numbers => numbers
                .split(',')
                .map(|n| {
                    n.trim()
                        .parse::<usize>()
                        .ok()
                        .filter(|n| *n >= 1)
                        .ok_or_else(|| format!("--history: {n:?} is no number of the list"))
                })
                .collect::<Result<_, _>>()
                .map(Self::Numbers),
        }
    }
}

impl Flags {
    /// The flags in `args`, and the other arguments.
    fn parse(args: &[String]) -> Result<(Self, Vec<String>), String> {
        let mut flags = Self::default();
        let network = &mut flags.network;
        let mut rest = Vec::new();
        let mut args = args.iter();
        while let Some(arg) = args.next() {
            let mut value = || {
                args.next()
                    .cloned()
                    .ok_or_else(|| format!("{arg} takes a value"))
            };
            match arg.as_str() {
                "--lan-only" => {
                    network.relay = Some(Relay::Disabled);
                    network.mdns = true;
                    network.no_portmap = true;
                    network.lan_only = true;
                }
                "--relay" => {
                    network.relay = Some(Relay::parse(&value()?).map_err(|e| e.to_string())?);
                }
                "--bind" => {
                    network.bind = Some(parse_bind(&value()?)?);
                }
                "--mdns" => network.mdns = true,
                "--no-portmap" => network.no_portmap = true,
                "--yes" => flags.approval = Approval::Everyone,
                "--role" => flags.role = Some(Role::given(&value()?).map_err(|e| e.to_string())?),
                "--add" => flags.add.push(value()?),
                "--share" => flags.choice = Choice::Share(value()?),
                "--private" => flags.choice = Choice::Private,
                "--name" => flags.name = Some(value()?),
                "--ticket-file" => flags.ticket_file = Some(value()?),
                "--send-binary" => flags.send_binary = true,
                "--send-debug" => flags.send_debug = true,
                "--history" => flags.history = History::parse(&value()?)?,
                other if other.starts_with("--") => return Err(format!("unknown flag {other}")),
                other => rest.push(other.to_owned()),
            }
        }
        Ok((flags, rest))
    }
}

impl Network {
    /// The endpoint's options: binbun's relay unless given, or none, mDNS
    /// and no port mapping for a host on its LAN only (`lan`).
    fn options(&self, lan: bool) -> NetOptions {
        let relay = match &self.relay {
            Some(relay) => relay.clone(),
            None if lan => Relay::Disabled,
            None => Relay::Binbun,
        };
        NetOptions {
            relay,
            mdns: self.mdns || (lan && self.relay.is_none()),
            portmap: !(self.no_portmap || (lan && self.relay.is_none())),
            bind: self.bind,
        }
    }
}

/// What a running peer prints from: when it started.
#[derive(Clone, Copy)]
pub(crate) struct Clock(Instant);

impl Clock {
    /// Prints `line` stamped with the seconds since the start ([`shown`]).
    pub(crate) fn say(self, line: &str) {
        println!("[{:8.3}] {}", self.0.elapsed().as_secs_f64(), shown(line));
    }
}

/// `text` with each character that moves or hides what a terminal shows
/// (one [`ticket::plain`] refuses: control and format characters, line
/// breaks) escaped (`\u{1b}`): the one way text a peer wrote reaches the
/// terminal, a field at a time, so no field reads as another line.
pub(crate) fn shown(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if ticket::plain(c.encode_utf8(&mut [0; 4]), 1) {
            out.push(c);
        } else {
            let _ = write!(out, "{}", c.escape_unicode());
        }
    }
    out
}

/// A short form of `key`: its fingerprint's first two groups.
pub(crate) fn short(key: PublicKey) -> String {
    fingerprint(key).chars().take(9).collect()
}

/// Says what `notice` tells.
fn tell(clock: Clock, notice: &Notice) {
    let line = match notice {
        Notice::Linked {
            peer,
            role,
            path,
            view_only,
        } => format!(
            "linked {} ({}) via {path}{}",
            short(*peer),
            role.map_or_else(
                || "role not assigned yet".to_owned(),
                |role| role.to_string()
            ),
            view_only
                .as_ref()
                .map_or_else(String::new, |why| format!("; view-only: {why}"))
        ),
        Notice::ViewOnly(why) => format!("view-only in this session: {why}"),
        Notice::Unlinked { peer, why } => format!("unlinked {}: {why}", short(*peer)),
        Notice::Waiting => "waiting for the host's approval".to_owned(),
        Notice::Admitted { member, role } => format!("admitted {} as {role}", short(*member)),
        Notice::Turned { peer, why } => format!("turned away {}: {why}", short(*peer)),
        Notice::Membership { seq, epoch } => format!("membership record {seq}, epoch {epoch}"),
        Notice::Crowded { bytes } => format!(
            "the membership chain is {} MiB: past 32 MiB no member can be removed",
            bytes >> 20
        ),
        Notice::Denied(why) => format!("denied: {why}"),
        Notice::Kicked(why) => format!("put out: {why}"),
        Notice::Took {
            from,
            taken,
            conflicts,
        } => format!(
            "took {taken} change(s) from {} ({conflicts} conflict(s) now)",
            short(*from)
        ),
        Notice::Refused(refused) => format!(
            "refused {} by {}: {}",
            refused.change.map_or_else(
                || "a change".to_owned(),
                |id| format!("{}:{}", id.chain, id.seq)
            ),
            refused.author.map_or_else(|| "?".to_owned(), short),
            refused.why
        ),
        Notice::Failed(why) => format!("failed: {why}"),
        Notice::Sending { to, kind, name } => {
            format!("sending the {kind} {name} to {}", short(*to))
        }
        Notice::Sent {
            to,
            kind,
            name,
            error: None,
        } => format!("sent the {kind} {name} to {}", short(*to)),
        Notice::Sent {
            to,
            kind,
            name,
            error: Some(why),
        } => format!("stopped sending the {kind} {name} to {}: {why}", short(*to)),
    };
    clock.say(&line);
}

/// `bytes` in kilobytes, to the kilobyte.
fn kilobytes(bytes: u64) -> f64 {
    f64::from(u32::try_from(bytes / 1000).unwrap_or(u32::MAX))
}

/// `bytes` in megabytes (kilobytes under one), for people.
pub(crate) fn megabytes(bytes: u64) -> String {
    if bytes < 1_000_000 {
        format!(
            "{:.1} kB",
            f64::from(u32::try_from(bytes).unwrap_or(0)) / 1e3
        )
    } else {
        format!("{:.1} MB", kilobytes(bytes) / 1e3)
    }
}

/// Megabytes a second.
fn rate(bytes: u64, time: Duration) -> f64 {
    kilobytes(bytes) / 1e3 / time.as_secs_f64().max(1e-9)
}

/// Prints how far a fetch of a file of `kind` is, once a second.
pub(crate) fn progress_printer(clock: Clock, kind: Kind) -> OnProgress {
    let last: Mutex<Option<(Instant, u64)>> = Mutex::new(None);
    Arc::new(move |progress: &Progress| {
        let mut last = last.lock().unwrap_or_else(PoisonError::into_inner);
        let now = Instant::now();
        let (since, before) = *last.get_or_insert((now, progress.done));
        let elapsed = now.duration_since(since);
        let whole = progress.done == progress.total;
        if elapsed < Duration::from_secs(1) && !whole {
            return;
        }
        let doing = match progress.step {
            Step::Fetching => "fetching",
            Step::Opening => "opening",
        };
        clock.say(&format!(
            "{doing} the {kind}: {} / {} ({} %), {:.0} MB/s",
            megabytes(progress.done),
            megabytes(progress.total),
            progress.done * 100 / progress.total.max(1),
            rate(progress.done.saturating_sub(before), elapsed)
        ));
        *last = Some((now, progress.done));
    })
}

/// What a fetch of `offer` came to, for people.
pub(crate) fn fetched_line(offer: &Offer, fetched: &Fetched) -> String {
    format!(
        "fetched the {} {} ({}) into {}: {} of its {} blob here before, {} received in \
         {:.2} s ({:.0} MB/s); opened in {:.2} s (AEAD {:.2} s); SHA-256 checked",
        offer.kind,
        shown(&offer.name),
        megabytes(offer.length),
        fetched.path.display(),
        megabytes(fetched.had),
        megabytes(fetched.sealed),
        megabytes(fetched.received),
        fetched.fetching.as_secs_f64(),
        rate(fetched.received, fetched.fetching),
        fetched.opening.as_secs_f64(),
        fetched.crypto.as_secs_f64()
    )
}

/// Where a session's project is.
enum Where<'a> {
    /// The binary's project in binbun's data directory, as `choice` says:
    /// of several, the one used last unless chosen (what was chosen is
    /// said to `say`).
    Chosen(&'a Choice, &'a dyn Fn(&str)),
    /// This directory (a share's project for a joiner).
    Dir(PathBuf),
}

/// The directory of `file`'s project (`arch`'s slice) as `choice` says,
/// said to `say` when it was chosen of several; `None`: a new one, made
/// where the session makes it.
fn chosen(
    file: &str,
    arch: Option<&str>,
    choice: &Choice,
    say: &dyn Fn(&str),
) -> Result<Option<PathBuf>, String> {
    let root = project::root().ok_or_else(|| Place::Projects.missing())?;
    let key = project::Key::of_file_slice(Path::new(file), arch)
        .map_err(|error| format!("{file}: {error}"))?;
    let located = project::locate(&root, &key, choice)?;
    if located.chosen == Chosen::LastUsed {
        let others: Vec<String> = located
            .all
            .iter()
            .skip(1)
            .map(|other| project::file_name(other.dir()))
            .collect();
        say(&format!(
            "opened the project of {file} used last, {}; also here: {} (another with --share ID \
             or --private)",
            project::file_name(located.project.dir()),
            others.join(", ")
        ));
    }
    Ok((located.chosen != Chosen::New).then(|| located.project.dir().to_path_buf()))
}

/// Opens `file`'s session (its project `at`, this install's identity)
/// once its functions are recovered: its project held for writing for
/// the session's life (refused if it is open elsewhere).
fn open(file: &str, arch: Option<&str>, at: Where<'_>) -> Result<Arc<Session>, String> {
    let project = match at {
        Where::Chosen(choice, say) => chosen(file, arch, choice, say)?,
        Where::Dir(dir) => Some(dir),
    };
    let options = Options {
        project,
        warm: false,
        arch: arch.map(str::to_owned),
        ..Options::default()
    };
    let session = Session::open(file, options).map_err(|error| error.to_string())?;
    match session.wait(Stage::Analysed, None) {
        Waited::Reached(_) => {}
        Waited::Stopped { failure, .. } => {
            return Err(failure.unwrap_or_else(|| format!("{file}: stopped")));
        }
        Waited::TimedOut(_) => return Err(format!("{file}: timed out")),
    }
    session.project().ok_or("no project")?;
    Ok(Arc::new(session))
}

/// `binbun edit FILE [--share ID | --private] COMMAND...`: one command on
/// the project, no peer.
pub fn edit(args: &[String]) -> Result<String, String> {
    let [file, rest @ ..] = args else {
        return Err(USAGE.to_owned());
    };
    let (choice, command) = match rest {
        [flag, id, command @ ..] if flag == "--share" => (Choice::Share(id.clone()), command),
        [flag, command @ ..] if flag == "--private" => (Choice::Private, command),
        command => (Choice::Any, command),
    };
    let say = |line: &str| eprintln!("{}", shown(line));
    let session = open(file, arch(), Where::Chosen(&choice, &say))?;
    Driver::new(session, None, Clock(Instant::now())).run_offline(&command.join(" "))
}

/// What `bring` brings.
enum Picked {
    /// Nothing: the values are listed.
    List,
    /// Every value this install's key wrote (and others' too).
    All { others: bool },
    /// Those numbered as listed, from 1.
    Numbers(Vec<usize>),
}

/// What `bring` is given: the file, the share named, the label, what to
/// bring.
fn bring_args(args: &[String]) -> Result<(String, Option<String>, String, Picked), String> {
    let mut file = None;
    let mut share = None;
    let mut label = "Bring".to_owned();
    let (mut list, mut all) = (false, false);
    let mut others = false;
    let mut numbers = Vec::new();
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--share" => share = Some(args.next().ok_or("--share takes an id")?.clone()),
            "--label" => label.clone_from(args.next().ok_or("--label takes a text")?),
            "--list" => list = true,
            "--all" => all = true,
            "--others" => others = true,
            other if other.starts_with("--") => {
                return Err(format!("binbun bring: unknown flag {other}"));
            }
            other if file.is_none() => file = Some(other.to_owned()),
            other => numbers.push(
                other
                    .parse::<usize>()
                    .ok()
                    .filter(|n| *n > 0)
                    .ok_or_else(|| format!("binbun bring: not a number listed: {other}"))?,
            ),
        }
    }
    let file = file.ok_or_else(|| USAGE.to_owned())?;
    let picked = match (list, all, numbers.is_empty()) {
        (_, false, true) => Picked::List,
        (false, true, true) => Picked::All { others },
        (false, false, false) => Picked::Numbers(numbers),
        (true, true, _) | (_, _, false) => {
            return Err("binbun bring: numbers, or --all, or --list".to_owned());
        }
    };
    Ok((file, share, label, picked))
}

/// The values `values` listed, numbered from 1, each with who wrote it
/// (`me`: this install's key).
fn listing(values: &[Bringable], me: PublicKey) -> String {
    let mut out = String::new();
    for (n, brought) in values.iter().enumerate() {
        let by = if brought.writer == me {
            "you".to_owned()
        } else {
            format!("{} (another author or an agent)", short(brought.writer))
        };
        let _ = writeln!(
            out,
            "{} {} = {} by {by}",
            n + 1,
            driver::key(&brought.key),
            driver::value(&brought.value)
        );
    }
    let _ = writeln!(out, "{} value(s) to bring", values.len());
    out
}

/// Chain `chain`, `n`th (from 0) of a share's history list, for people:
/// its number, whose it is (`me`'s, an agent's, another's) and how far it
/// goes, marked if it goes by default.
fn chain_line(n: usize, chain: &Listable, me: PublicKey) -> String {
    let whose = match &chain.agent {
        _ if chain.author == me => "yours".to_owned(),
        Some(agent) => format!("agent {}", shown(agent)),
        None => format!("{} (another author)", short(chain.author)),
    };
    format!(
        "{} {} chain {}, {whose}, {} change(s)",
        n + 1,
        if chain.chosen { "*" } else { " " },
        chain.chain,
        chain.through
    )
}

/// The chains of the project from before a share that `share` could list
/// (`--history list`): numbered, those going by default marked `*`.
fn history(listable: &[Listable], me: PublicKey) -> String {
    let mut out = String::new();
    for (n, chain) in listable.iter().enumerate() {
        let _ = writeln!(out, "{}", chain_line(n, chain, me));
    }
    let _ = writeln!(
        out,
        "{} chain(s); * goes by default (--history N,N or none to choose)",
        listable.len()
    );
    out
}

/// The share's project to bring into, of those `all` of a file's: the
/// only one.
fn only_share(all: &[project::Project]) -> Result<project::Project, String> {
    let shares: Vec<&project::Project> = all
        .iter()
        .filter(|project| project::file_name(project.dir()).contains('@'))
        .collect();
    match shares.as_slice() {
        [only] => Ok((*only).clone()),
        [] => Err("no share's project of this binary to bring into".to_owned()),
        _ => Err("several shares' projects: name one with --share ID".to_owned()),
    }
}

/// `binbun bring FILE [--share ID] [--list | --all [--others] | N...]
/// [--label TEXT]`: values of FILE's private project brought into a
/// share's project (the one named, else the only one here) as one new
/// change of this install's key, labelled as brought; nothing of the
/// private project's history or ids goes with them. Listed with `--list`
/// (numbered, each with who wrote it); `--all` brings every value this
/// key wrote, `--others` also those of other authors and agents; else the
/// values numbered. The change is pending in the share's project until
/// the share takes it at the next `join` or `share` (a role that may not
/// write it refuses it then, and it is kept apart).
pub fn bring(args: &[String]) -> Result<String, String> {
    let (file, share, label, picked) = bring_args(args)?;
    let root = project::root().ok_or_else(|| Place::Projects.missing())?;
    let key = project::Key::of_file_slice(Path::new(&file), arch())
        .map_err(|error| format!("{file}: {error}"))?;
    let from = project::locate(&root, &key, &Choice::Private)?;
    if from.chosen == Chosen::New {
        return Err(format!("{file} has no private project to bring from"));
    }
    let into = if let Some(id) = share {
        project::locate(&root, &key, &Choice::Share(id))?.project
    } else {
        only_share(&from.all)?
    };
    let identity = identity()?;
    let values = from.project.bringable(&identity)?;
    let me = identity.public();
    let chosen: Vec<_> = match picked {
        Picked::List => return Ok(listing(&values, me)),
        Picked::All { others } => values
            .into_iter()
            .filter(|brought| others || brought.writer == me)
            .collect(),
        Picked::Numbers(numbers) => numbers
            .iter()
            .map(|n| {
                values
                    .get(n - 1)
                    .cloned()
                    .ok_or_else(|| format!("no value {n}: {} listed", values.len()))
            })
            .collect::<Result<_, _>>()?,
    };
    let session = open(&file, arch(), Where::Dir(into.dir().to_path_buf()))?;
    let brought = session
        .bring(&chosen, &label)
        .map_err(|error| error.to_string())?;
    session.save().map_err(|error| error.to_string())?;
    Ok(match brought {
        Some(_) => format!(
            "brought {} value(s) into {} as one change of yours ({}); the share takes it at the \
             next join or share\n",
            chosen.len(),
            into.dir().display(),
            shown(&label)
        ),
        None => "nothing to bring\n".to_owned(),
    })
}

/// `binbun share FILE ...`: the project shared, its ticket printed.
#[expect(clippy::too_many_lines, reason = "each step of sharing in turn")]
pub fn share(args: &[String]) -> Result<String, String> {
    let (flags, rest) = Flags::parse(args)?;
    let [file] = rest.as_slice() else {
        return Err(USAGE.to_owned());
    };
    let clock = Clock(Instant::now());
    let say = |line: &str| clock.say(line);
    let session = open(file, arch(), Where::Chosen(&flags.choice, &say))?;
    clock.say(&format!("analysed {file}"));
    let cards: Vec<Card> = flags
        .add
        .iter()
        .map(|card| {
            card.parse()
                .map_err(|e: binbun_collab::Error| e.to_string())
        })
        .collect::<Result<_, _>>()?;
    let (identity, _peer) = peer_identity()?;
    // Shared anew: what of the project from before goes with it is shown,
    // and chosen (`--history`).
    let anew = session.genesis().is_none();
    let listable = listable(&session, identity.public());
    if matches!(flags.history, History::List) {
        if !anew {
            return Err(
                "the project is shared already: its first record lists what goes".to_owned(),
            );
        }
        return Ok(history(&listable, identity.public()));
    }
    let listed: BTreeSet<ChainId> = match &flags.history {
        History::Own | History::List => listable
            .iter()
            .filter(|listable| listable.chosen)
            .map(|listable| listable.chain)
            .collect(),
        History::Nothing => BTreeSet::new(),
        History::Numbers(numbers) => numbers
            .iter()
            .map(|n| {
                listable
                    .get(n - 1)
                    .map(|listable| listable.chain)
                    .ok_or_else(|| format!("--history: no chain {n}: {} listed", listable.len()))
            })
            .collect::<Result<_, _>>()?,
    };
    if anew {
        for (n, chain) in listable.iter().enumerate() {
            if listed.contains(&chain.chain) {
                clock.say(&format!(
                    "goes with the share: {}",
                    chain_line(n, chain, identity.public())
                ));
            }
        }
    }
    let runtime = runtime()?;
    runtime
        .block_on(async move {
            let transport = bind(&identity, &flags.network.options(false), clock).await?;
            let lines = typed_lines();
            let asking = Asking::default();
            let approve = Some(approver(&flags, Arc::clone(&asking), clock));
            let config = config(identity, &flags, approve, clock);
            let (peer, mut ticket) = Peer::share_listing(session, transport, config, Some(listed))
                .await
                .map_err(|error| error.to_string())?;
            if flags.network.lan_only {
                ticket.flags |= LAN_ONLY;
            }
            // Added before the ticket is out: their first link is let in.
            let role = flags.role.unwrap_or(Role::Editor);
            for card in &cards {
                if peer.membership().role(card.key).is_some() {
                    clock.say(&format!("{} is a member already", short(card.key)));
                    continue;
                }
                peer.add(card, role).map_err(|error| error.to_string())?;
                clock.say(&format!(
                    "added {} ({}) as {role}",
                    shown(&card.name),
                    fingerprint(card.key)
                ));
            }
            // Offered before the ticket is out, so a joiner never finds it
            // missing while it is sealed.
            for (kind, wanted) in [
                (Kind::Binary, flags.send_binary),
                (Kind::DebugFile, flags.send_debug),
            ] {
                if wanted {
                    offer(&peer, kind, clock).await?;
                }
            }
            if let Some(path) = &flags.ticket_file {
                fs::write(path, format!("{ticket}\n"))
                    .map_err(|error| format!("{path}: {error}"))?;
            }
            clock.say(&format!(
                "sharing; addresses {:?}, relay {}",
                ticket.host.direct,
                ticket.host.relay.as_deref().unwrap_or("none")
            ));
            println!("{ticket}");
            serve(peer, lines, asking, clock).await
        })
        // An error may quote what a peer said.
        .map_err(|error| shown(&error))
}

/// Offers the session's file of `kind` to members who ask.
async fn offer(peer: &Peer, kind: Kind, clock: Clock) -> Result<(), String> {
    let prepared = peer.offer(kind).await.map_err(|error| error.to_string())?;
    let offer = &prepared.offer;
    let how = if prepared.kept {
        "its blob kept from before".to_owned()
    } else {
        format!(
            "sealed in {:.2} s ({:.0} MB/s; AEAD {:.2} s)",
            prepared.sealing.as_secs_f64(),
            rate(offer.length, prepared.sealing),
            prepared.crypto.as_secs_f64()
        )
    };
    clock.say(&format!(
        "sending the {kind} {} ({}, a blob of {}) to members who ask: {how}",
        offer.name,
        megabytes(offer.length),
        megabytes(offer.sealed())
    ));
    Ok(())
}

/// `binbun join TICKET [FILE] ...`: the project joined from its host,
/// once its owner added this install's card (or, if the host approves
/// live, once approved); the binary the host offers fetched first into
/// FILE (binbun's downloads folder by default) if it is not there. The
/// host is visited first (membership records only) for the share's
/// genesis and binary: the binary is the one the project shared
/// annotates, as its owner's membership chain names it
/// ([`Visit::binary`]): a FILE of other bytes ends the join, and an offer
/// of another binary is not fetched. The share is joined in a project
/// directory of its own (`<sha256>-<name>@<share>`), apart from any
/// private project of the binary. Of a universal file, the slice shared
/// is opened (the chain's), unless `--arch` says another.
pub fn join(args: &[String]) -> Result<String, String> {
    let (flags, rest) = Flags::parse(args)?;
    let (ticket, file) = match rest.as_slice() {
        [ticket] => (ticket, None),
        [ticket, file] => (ticket, Some(PathBuf::from(file))),
        _ => return Err(USAGE.to_owned()),
    };
    let ticket: JoinTicket = ticket
        .parse()
        .map_err(|error: binbun_collab::Error| error.to_string())?;
    let clock = Clock(Instant::now());
    let (identity, _peer) = peer_identity()?;
    // A host on its LAN only: no relay, mDNS, unless told otherwise.
    let lan = ticket.lan_only();
    let runtime = runtime()?;
    runtime
        .block_on(async move {
            let transport = bind(&identity, &flags.network.options(lan), clock).await?;
            let visiting = config(identity.clone(), &flags, None, clock);
            clock.say(&format!(
                "visiting {} for the share's membership chain",
                short(ticket.host.id)
            ));
            let visit = Visit::new(&transport, &visiting, &ticket)
                .await
                .map_err(|error| error.to_string())?;
            let Some(binary) = visit.binary().cloned() else {
                visit.close();
                return Err(unopened());
            };
            let genesis = visit.genesis();
            // A file fetched is saved under a name binbun gives it; its
            // project is named after the name its offer gives.
            let (file, offered) = match file {
                Some(file) if file.exists() => {
                    visit.close();
                    (file, None)
                }
                file => {
                    let (file, name) = fetch_shared(visit, &binary, file, clock).await?;
                    (file, Some(name))
                }
            };
            if whole_sha256(&file)? != binary.sha256 {
                return Err(not_shared(&file, &binary));
            }
            let arch = arch().or(binary.slice.as_deref());
            let root = project::root().ok_or_else(|| Place::Projects.missing())?;
            let key = project::Key::of_file_slice(&file, arch)
                .map_err(|error| format!("{}: {error}", file.display()))?;
            let key = match offered {
                Some(name) => key.renamed(shown(&name)),
                None => key,
            };
            let dir = root.join(key.share_dir_name(&genesis));
            clock.say(&format!(
                "the share {}'s project: {}",
                project::share_id(&genesis),
                dir.display()
            ));
            let session = tokio::task::block_in_place(|| {
                open(&file.to_string_lossy(), arch, Where::Dir(dir))
            })?;
            match session.slice() {
                Some(slice) => clock.say(&format!("analysed {} ({slice})", file.display())),
                None => clock.say(&format!("analysed {}", file.display())),
            }
            let lines = typed_lines();
            let config = config(identity, &flags, None, clock);
            clock.say(&format!("dialling {}", short(ticket.host.id)));
            let peer = Peer::join(session, transport, config, &ticket)
                .await
                .map_err(|error| error.to_string())?;
            serve(peer, lines, Asking::default(), clock).await
        })
        // An error may quote what the host said.
        .map_err(|error| shown(&error))
}

/// Why a join stops when the chain's binary does not open.
fn unopened() -> String {
    "the project shared names its binary so that its key does not open it".to_owned()
}

/// Why a join stops with the file at `file`, not `binary`.
fn not_shared(file: &Path, binary: &Binary) -> String {
    format!(
        "{} is not the binary the project shared annotates (sha256 {})",
        file.display(),
        driver::hex(&binary.sha256)
    )
}

/// The SHA-256 of the whole file at `file`.
fn whole_sha256(file: &Path) -> Result<[u8; 32], String> {
    let bytes = fs::read(file).map_err(|error| format!("{}: {error}", file.display()))?;
    Ok(*project::Key::new(&bytes, "").sha256())
}

/// Fetches `binary`, the binary the project shared annotates (as its
/// owner's membership chain names it), over `visit` if its host offers
/// it, into `file` (if none, binbun's downloads folder, under a name
/// binbun gives it), going on where a fetch cut short stopped (the blob is
/// kept in binbun's cache until whole). An offer of another binary is not
/// fetched. The visit ends. The file, and the name its offer gives.
async fn fetch_shared(
    visit: Visit,
    binary: &Binary,
    file: Option<PathBuf>,
    clock: Clock,
) -> Result<(PathBuf, String), String> {
    let offers = visit.offers().await.map_err(|error| error.to_string());
    let offered = offers.map(|offers| {
        offers
            .into_iter()
            .find(|offer| offer.kind == Kind::Binary && offer.sha256 == binary.sha256)
    });
    let Some(offer) = offered? else {
        visit.close();
        return Err(
            "the host does not send the binary the project shared annotates (it shares \
             without --send-binary): give the binary's file"
                .to_owned(),
        );
    };
    let places = match file {
        Some(file) => Fetches::new().map(|cache| (cache, file)),
        None => Fetches::new().and_then(|cache| {
            let to = fetches::downloads()?.join(fetches::local_name(&offer));
            Ok((cache, to))
        }),
    };
    let (cache, to) = match places {
        Ok(places) => places,
        Err(error) => {
            visit.close();
            return Err(error.to_string());
        }
    };
    clock.say(&format!(
        "the host offers the binary {} ({}, sha256 {}); fetching it into {}",
        shown(&offer.name),
        megabytes(offer.length),
        driver::hex(&offer.sha256),
        to.display()
    ));
    let fetched = visit
        .fetch(
            &offer,
            &cache,
            &to,
            Some(progress_printer(clock, Kind::Binary)),
        )
        .await;
    visit.close();
    let fetched = fetched.map_err(|error| error.to_string())?;
    clock.say(&fetched_line(&offer, &fetched));
    // Beside `to` under a numbered name if another file was there.
    Ok((fetched.path, offer.name.to_string()))
}

/// The runtime a peer runs on.
fn runtime() -> Result<tokio::runtime::Runtime, String> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|error| error.to_string())
}

/// An endpoint keyed by `identity` per `options`.
async fn bind(
    identity: &Identity,
    options: &NetOptions,
    clock: Clock,
) -> Result<Arc<dyn Transport>, String> {
    let transport = IrohTransport::bind(&identity.secret(), options)
        .await
        .map_err(|error| error.to_string())?;
    clock.say(&format!(
        "endpoint {} bound ({options:?})",
        short(identity.public())
    ));
    Ok(Arc::new(transport))
}

/// A peer's configuration: `identity`, the name given, `approve`, its
/// notices printed.
fn config(identity: Identity, flags: &Flags, approve: Option<Approver>, clock: Clock) -> Config {
    let notify: Notifier = Arc::new(move |notice: &Notice| tell(clock, notice));
    Config {
        identity,
        name: flags.name.clone().unwrap_or_else(default_name),
        approve,
        notify: Some(notify),
        engine: EngineVersion::this(),
    }
}

/// A request to join asked on standard input.
struct Prompt {
    /// Its id: shown with it, named by an answer that admits, and the one
    /// it is withdrawn by.
    id: String,
    /// Who asks, for people.
    who: String,
    /// What is said of the request.
    lines: Vec<String>,
    /// Where its answer goes.
    answer: oneshot::Sender<Option<Role>>,
    /// Whether it was asked.
    asked: bool,
}

/// The requests to join asked on standard input, one at a time: the first
/// is asked, the others wait in the order they came.
#[derive(Default)]
struct Prompts {
    queue: VecDeque<Prompt>,
    /// The ids given in this process, as a count from a start drawn at
    /// random (`None`: none given yet): each id is the next number, so
    /// none is given twice and an answer typed for a request gone never
    /// names another, with nothing kept of the ids given.
    next: Option<u64>,
}

/// The hexadecimal digits of a request's id, at least.
const ID_DIGITS: usize = 4;

/// What a line typed came to.
#[derive(Debug, PartialEq, Eq)]
enum Typed {
    /// Not an answer: a command, to run.
    Command(String),
    /// The request asked was answered.
    Answered,
    /// An answer applied to no request, and why.
    Refused(String),
}

impl Prompts {
    /// Asks the first request if it is not asked yet.
    fn ask(&mut self, clock: Clock) {
        let waiting = self.queue.len().saturating_sub(1);
        let Some(prompt) = self.queue.front_mut() else {
            return;
        };
        if prompt.asked {
            return;
        }
        for line in &prompt.lines {
            clock.say(line);
        }
        if waiting > 0 {
            clock.say(&format!("  {waiting} more waiting"));
        }
        let id = &prompt.id;
        println!("request {id}: admit as editor (e {id}), as viewer (v {id}), or not (n {id})?");
        prompt.asked = true;
    }

    /// An id no request of this process had: the next number of the
    /// count, in hexadecimal digits ([`ID_DIGITS`] at least).
    fn new_id(&mut self) -> Result<String, String> {
        let next = match self.next {
            Some(next) => next,
            None => u64::from(getrandom::u32().map_err(|error| error.to_string())? & 0xffff),
        };
        self.next = Some(next + 1);
        Ok(format!("{next:0ID_DIGITS$x}"))
    }

    /// Adds a request (`who`, `lines` said of it) answered to `answer`,
    /// asked once those before it are answered: its id.
    fn add(
        &mut self,
        who: String,
        mut lines: Vec<String>,
        answer: oneshot::Sender<Option<Role>>,
        clock: Clock,
    ) -> Result<String, String> {
        let id = self.new_id()?;
        if let Some(first) = lines.first_mut() {
            first.insert_str(0, &format!("request {id}: "));
        }
        self.queue.push_back(Prompt {
            id: id.clone(),
            who,
            lines,
            answer,
            asked: false,
        });
        self.ask(clock);
        Ok(id)
    }

    /// Takes `line` as an answer if it is one (`e ID`, `v ID`, `n ID`;
    /// `editor`, `viewer`, `no` too, and any of them without its id):
    /// applied to the request asked if it names that request's id, the
    /// next then asked; else (another id, or none) refused, applied to
    /// none. Any other line is a command.
    fn answer(&mut self, line: &str, clock: Clock) -> Typed {
        let words: Vec<&str> = line.split_whitespace().collect();
        let (role, named) = match words.as_slice() {
            [verb, named @ ..] if named.len() < 2 => {
                let role = match *verb {
                    "e" | "editor" => Some(Role::Editor),
                    "v" | "viewer" => Some(Role::Viewer),
                    "n" | "no" => None,
                    _ => return Typed::Command(line.to_owned()),
                };
                (role, named.first().copied())
            }
            _ => return Typed::Command(line.to_owned()),
        };
        let Some(asked) = self.queue.front().filter(|prompt| prompt.asked) else {
            return Typed::Refused(match named {
                Some(named) => format!("not applied: request {named} is not waiting"),
                None => "not applied: no request to join is waiting".to_owned(),
            });
        };
        match named {
            Some(named) if named == asked.id => {}
            Some(named) => {
                return Typed::Refused(format!(
                    "not applied: request {named} is not the one asked (request {}, of {})",
                    asked.id, asked.who
                ));
            }
            None => {
                return Typed::Refused(format!(
                    "not applied: an answer names the request (request {}, of {})",
                    asked.id, asked.who
                ));
            }
        }
        if let Some(prompt) = self.queue.pop_front() {
            let _ = prompt.answer.send(role);
        }
        self.ask(clock);
        Typed::Answered
    }

    /// Withdraws request `id`, if it is still here: the next one asked if
    /// it was.
    fn withdraw(&mut self, id: &str, clock: Clock) {
        let Some(at) = self.queue.iter().position(|prompt| prompt.id == id) else {
            return;
        };
        let prompt = self.queue.remove(at);
        if at == 0 {
            if let Some(prompt) = prompt {
                clock.say(&format!(
                    "request {} of {} was withdrawn",
                    prompt.id, prompt.who
                ));
            }
            self.ask(clock);
        }
    }
}

/// The requests to join asked on standard input.
type Asking = Arc<Mutex<Prompts>>;

/// Withdraws a request when dropped (answered, it is gone already).
struct Withdraw {
    asking: Asking,
    id: String,
    clock: Clock,
}

impl Drop for Withdraw {
    fn drop(&mut self) {
        self.asking
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .withdraw(&self.id, self.clock);
    }
}

/// The host's live approver: with `--yes` everyone holding the ticket is
/// admitted as `--role` (an editor by default); else each request is
/// asked on standard input ([`Prompts`]).
fn approver(flags: &Flags, asking: Asking, clock: Clock) -> Approver {
    let role = flags.role.unwrap_or(Role::Editor);
    let yes = flags.approval == Approval::Everyone;
    Arc::new(move |request: Request| {
        let name = shown(&request.card.name);
        let who = format!("{name} ({})", short(request.card.key));
        let lines = vec![format!(
            "{name} ({}) asks to join via {}, binbun {} {}",
            fingerprint(request.card.key),
            shown(&request.path),
            shown(&request.engine.release),
            shown(&request.engine.build)
        )];
        if yes {
            for line in &lines {
                clock.say(line);
            }
            return Box::pin(async move { Some(role) });
        }
        let (answer, answered) = oneshot::channel();
        let added = asking
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .add(who, lines, answer, clock);
        let id = match added {
            Ok(id) => id,
            Err(why) => {
                clock.say(&format!("a request to join refused: no id for it: {why}"));
                return Box::pin(async { None });
            }
        };
        let withdraw = Withdraw {
            asking: Arc::clone(&asking),
            id,
            clock,
        };
        Box::pin(async move {
            let _withdraw = withdraw;
            answered.await.ok().flatten()
        })
    })
}

/// Standard input's lines, read on a thread of their own.
fn typed_lines() -> mpsc::UnboundedReceiver<String> {
    let (send, lines) = mpsc::unbounded_channel();
    std::thread::spawn(move || {
        for line in io::stdin().lock().lines() {
            let Ok(line) = line else { break };
            if send.send(line).is_err() {
                break;
            }
        }
    });
    lines
}

/// How long quitting waits for the members linked to say they hold this
/// peer's changes.
const FLUSH: Duration = Duration::from_secs(5);

/// Runs `peer` until `quit`, the end of input or Ctrl+C: each line is an
/// answer to a request to join ([`Prompts::answer`]) or a command. Then
/// it waits for the members linked to say they hold this peer's changes
/// ([`Peer::flush`]), says who did, and closes.
async fn serve(
    peer: Peer,
    mut lines: mpsc::UnboundedReceiver<String>,
    asking: Asking,
    clock: Clock,
) -> Result<String, String> {
    let peer = Arc::new(peer);
    // The session's chat, as it comes (each message's id: what `unchat`
    // names).
    peer.on_live(Arc::new(move |event: &LiveEvent| {
        if let LiveEvent::Chat(message) = event {
            clock.say(&format!(
                "chat {} {}: {}",
                message.id,
                short(message.from),
                shown(&message.text)
            ));
        } else if let LiveEvent::ChatRemoved(id) = event {
            clock.say(&format!("chat {id} removed by the owner"));
        }
    }));
    let driver = Driver::new(peer.session(), Some(Arc::clone(&peer)), clock);
    let commands = async {
        while let Some(line) = lines.recv().await {
            let typed = asking
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .answer(&line, clock);
            let line = match typed {
                Typed::Command(line) => line,
                Typed::Answered => continue,
                Typed::Refused(why) => {
                    clock.say(&why);
                    continue;
                }
            };
            if line.trim() == "quit" {
                break;
            }
            match driver.run(&line).await {
                // What peers made (names, comments, posts) is escaped
                // field by field as the driver puts its lines together.
                Ok(said) => print!("{said}"),
                Err(error) => println!("error: {}", shown(&error)),
            }
        }
    };
    tokio::select! {
        () = commands => {}
        _ = tokio::signal::ctrl_c() => clock.say("interrupted"),
    }
    let start = Instant::now();
    let flushed = peer.flush(FLUSH).await;
    let elapsed = start.elapsed().as_secs_f64();
    let names = |keys: &[PublicKey]| -> String {
        keys.iter()
            .map(|key| short(*key))
            .collect::<Vec<_>>()
            .join(", ")
    };
    let mut said = format!(
        "flushed in {elapsed:.3} s: {} member(s) acknowledged",
        flushed.acknowledged.len()
    );
    if !flushed.unacknowledged.is_empty() {
        let _ = write!(
            said,
            "; unacknowledged after {} s by {}",
            FLUSH.as_secs(),
            names(&flushed.unacknowledged)
        );
    }
    if !flushed.disconnected.is_empty() {
        let _ = write!(
            said,
            "; disconnected before acknowledging: {}",
            names(&flushed.disconnected)
        );
    }
    clock.say(&said);
    drop(driver);
    if let Ok(peer) = Arc::try_unwrap(peer) {
        peer.close().await;
    }
    Ok(String::new())
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, PoisonError};
    use std::time::Instant;

    use binbun_collab::Request;
    use binbun_collab::membership::Role;
    use binbun_collab::ticket::Card;
    use binbun_session::identity::Identity;
    use binbun_session::journal::EngineVersion;

    use super::{Asking, Clock, Flags, Typed, approver, shown};

    /// A request to join from someone new named `name`.
    fn request(name: &str) -> Request {
        Request {
            card: Card::new(&Identity::ephemeral().unwrap(), name),
            path: "direct".to_owned(),
            engine: EngineVersion::this(),
        }
    }

    /// The ids of the requests waiting, the one asked first.
    fn waiting(asking: &Asking) -> Vec<String> {
        let prompts = asking.lock().unwrap_or_else(PoisonError::into_inner);
        prompts
            .queue
            .iter()
            .map(|prompt| prompt.id.clone())
            .collect()
    }

    #[tokio::test]
    async fn an_answer_typed_for_one_request_never_admits_another() {
        let clock = Clock(Instant::now());
        let asking = Asking::default();
        let approve = approver(&Flags::default(), Arc::clone(&asking), clock);
        let answer = |line: &str| {
            asking
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .answer(line, clock)
        };
        let refused = |typed: Typed| matches!(typed, Typed::Refused(_));

        // Ann asked, Bob waiting, each under an id of their own.
        let ann = approve(request("Ann"));
        let bob = approve(request("Bob"));
        let [ann_id, bob_id] = <[String; 2]>::try_from(waiting(&asking)).unwrap();
        assert_ne!(ann_id, bob_id);
        // Admitting Bob while Ann is asked, or admitting naming no one:
        // refused, applied to neither.
        assert!(refused(answer(&format!("e {bob_id}"))));
        assert!(refused(answer("e")));
        assert!(refused(answer("v")));
        assert_eq!(waiting(&asking), [ann_id.clone(), bob_id.clone()]);

        // Ann withdrawn as an answer for her is typed: Bob is asked, and
        // the answer naming Ann is refused, not his.
        drop(ann);
        assert!(refused(answer(&format!("e {ann_id}"))));
        assert!(refused(answer(&format!("n {ann_id}"))));
        assert_eq!(waiting(&asking), std::slice::from_ref(&bob_id));
        // His own id answers him.
        assert_eq!(answer(&format!("v {bob_id}")), Typed::Answered);
        assert_eq!(bob.await, Some(Role::Viewer));

        // `n` alone names no request: refused, as admitting naming none
        // is; `n` with its id refuses the request asked. Then nothing
        // waits, and an answer is refused, never a command.
        let cat = approve(request("Cat"));
        let [cat_id] = <[String; 1]>::try_from(waiting(&asking)).unwrap();
        assert!(refused(answer("n")));
        assert!(refused(answer("no")));
        assert_eq!(waiting(&asking), std::slice::from_ref(&cat_id));
        assert_eq!(answer(&format!("n {cat_id}")), Typed::Answered);
        assert_eq!(cat.await, None);
        assert!(refused(answer(&format!("e {bob_id}"))));
        assert_eq!(answer("people"), Typed::Command("people".to_owned()));
    }

    #[test]
    fn what_peers_say_reaches_the_terminal_without_control_characters() {
        let said = shown("hi\u{1b}[2J\n[ 1.000] admitted\u{202e}x\u{9b}");
        assert!(said.chars().all(|c| !c.is_control() && c != '\u{202e}'));
        assert!(said.starts_with("hi") && said.contains("admitted"));
    }
}
