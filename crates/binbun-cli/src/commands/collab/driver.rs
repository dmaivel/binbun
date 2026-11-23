//! The commands `share`, `join` and `edit` take, one a line:
//!
//! ```text
//! rename FUNCTION NAME        name a function (FUNCTION: 0x entry, or its name)
//! comment ADDRESS TEXT...     comment an address
//! resolve FUNCTION NAME       resolve the conflict on a function's name
//! begin LABEL...              open a group: the edits until `commit` are one change,
//!                             which peers see only once committed
//! commit                      commit the group open
//! conflicts                   the keys in conflict, each value and its author
//! state                       changes, chains, conflicts, refusals, epoch, role, links
//! refused                     the changes refused, and why
//! pending                     this install's edits not yet shared (made with no link
//!                             synced), each with its values
//! apart                       the edits not in this project (refused when judged, kept
//!                             apart), each with its author and values
//! members                     the membership chain: each member's role
//! links                       the members linked, and how
//! remove KEY                  remove a member (KEY: a prefix of their key or fingerprint)
//! role KEY editor|viewer      change a member's role
//! add CARD [--role] [editor|viewer|agent]
//!                             add a member by their identity card (`binbun id`; check
//!                             its fingerprint with them), or admit again one removed
//!                             (an editor by default): their key is let in when it
//!                             joins
//! transfer KEY                give the project to a member; this peer becomes an editor
//! chat TEXT...                say TEXT in the session's chat (others' messages print
//!                             as they come)
//! people                      who is in the session: name, binbun, cursor
//! thread ADDRESS TEXT...      open a thread on an instruction, TEXT its first post
//! post THREAD TEXT...         post in a thread (THREAD: its id, as `threads` lists it,
//!                             or `last`, the thread opened last)
//! edit POST TEXT...           edit one's own post
//! delete POST                 delete one's own post (the owner: anyone's)
//! threads                     each thread, its posts and the suggestions answering it
//! suggest FUNCTION NAME TEXT...  suggest a name for a function, TEXT why
//! suggestions                 each suggestion, its state and edits
//! accept SUGGESTION [N...]    accept a suggestion's edits N (all by default; SUGGESTION
//!                             `last`: the one made last)
//! unchat ID                   remove a chat message (the owner; ID as `chat` prints it)
//! offer binary|debug          send the binary, or the debug file the analysis read, to
//!                             members who ask (sealed once; nothing is sent unless offered)
//! withdraw binary|debug       offer it no longer
//! offers                      what each member linked offers
//! fetch debug [PATH]          fetch the debug file a member linked offers into PATH
//!                             (binbun's downloads folder by default), then analyse
//!                             again with it
//! fetch binary [PATH]         fetch the binary a member linked offers into PATH
//!                             (binbun's downloads folder by default)
//! sleep MS                    wait
//! wait WHAT [SECONDS]         wait (60 s at most by default) until WHAT holds:
//!                               changes N | conflicts N | name FUNCTION NAME |
//!                               linked | unlinked | refused N | epoch N | members N |
//!                               threads N | posts N | suggestions N
//! quit                        stop
//! ```
//!
//! `edit` runs the commands that need no peer (`rename`, `comment`,
//! `resolve`, `conflicts`, `state`).
//!
//! What a command prints of what others wrote (names, comments, posts,
//! labels, file names offered) is escaped a field at a time
//! ([`shown`]) before its line is put together, so no field reads as
//! another line, with or without a peer.

use std::fmt::Write as _;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use binbun_collab::Peer;
use binbun_collab::blobs::{Kind, Offer};
use binbun_collab::fetches::{self, Fetches};
use binbun_collab::membership::Role;
use binbun_collab::ticket::{Card, fingerprint};
use binbun_session::journal::talk::{Anchor, Thread};
use binbun_session::journal::{ChainId, ChangeId, Key, LocalEdit, OpId, Origin, PublicKey, Value};
use binbun_session::{Error, Say, Session, Stage, Suggesting, Waited};

use super::{Clock, fetched_line, megabytes, progress_printer, short, shown};

/// Runs commands on a session and, if live, its peer.
pub(crate) struct Driver {
    /// The session without a peer (else the peer's: a newer analysis
    /// takes the place of the one before).
    own: Arc<Session>,
    peer: Option<Arc<Peer>>,
    clock: Clock,
}

/// How long `wait` waits by default.
const WAIT: Duration = Duration::from_secs(60);

impl Driver {
    /// A driver of `session`, live through `peer` if given.
    pub(crate) fn new(session: Arc<Session>, peer: Option<Arc<Peer>>, clock: Clock) -> Self {
        Self {
            own: session,
            peer,
            clock,
        }
    }

    /// The session in use.
    fn session(&self) -> Arc<Session> {
        self.peer
            .as_ref()
            .map_or_else(|| Arc::clone(&self.own), |peer| peer.session())
    }

    /// Runs `line`, which needs no peer; what it says.
    pub(crate) fn run_offline(&self, line: &str) -> Result<String, String> {
        let words: Vec<&str> = line.split_whitespace().collect();
        self.command(&words)
    }

    /// Runs `line`; what it says.
    pub(crate) async fn run(&self, line: &str) -> Result<String, String> {
        let words: Vec<&str> = line.split_whitespace().collect();
        match words.as_slice() {
            [] => Ok(String::new()),
            ["sleep", ms] => {
                let ms: u64 = ms.parse().map_err(|_| format!("not milliseconds: {ms}"))?;
                tokio::time::sleep(Duration::from_millis(ms)).await;
                Ok(String::new())
            }
            ["wait", what @ ..] => self.wait(what).await,
            ["offer", kind] => {
                let kind = blob_kind(kind)?;
                let prepared = self.peer()?.offer(kind).await.map_err(|e| e.to_string())?;
                Ok(self.stamped(&format!(
                    "offering the {kind} {} ({}): {}",
                    shown(&prepared.offer.name),
                    megabytes(prepared.offer.length),
                    if prepared.kept {
                        "its blob kept from before".to_owned()
                    } else {
                        format!(
                            "sealed in {:.2} s (AEAD {:.2} s)",
                            prepared.sealing.as_secs_f64(),
                            prepared.crypto.as_secs_f64()
                        )
                    }
                )))
            }
            ["offers"] => self.offers().await,
            ["fetch", kind, path @ ..] => self.fetch(blob_kind(kind)?, path.first().copied()).await,
            _ => self.command(&words),
        }
    }

    /// What each member linked offers.
    async fn offers(&self) -> Result<String, String> {
        let peer = self.peer()?;
        let mut out = String::new();
        for member in peer.readers() {
            for offer in peer.offers(member).await.map_err(|e| e.to_string())? {
                let _ = writeln!(
                    out,
                    "offer {} {} {} sha256 {} from {}",
                    offer.kind,
                    shown(&offer.name),
                    megabytes(offer.length),
                    hex(&offer.sha256),
                    short(member)
                );
            }
        }
        Ok(out)
    }

    /// The first member linked offering a file of `kind`, and its offer.
    async fn offered(&self, kind: Kind) -> Result<(PublicKey, Offer), String> {
        let peer = self.peer()?;
        for member in peer.readers() {
            let offers = peer.offers(member).await.map_err(|e| e.to_string())?;
            if let Some(offer) = offers.into_iter().find(|offer| offer.kind == kind) {
                return Ok((member, offer));
            }
        }
        Err(format!("no member linked offers a {kind}"))
    }

    /// Fetches the file of `kind` a member offers into `path` (binbun's
    /// downloads folder by default, under a name binbun gives it; a debug
    /// file is then analysed again with).
    async fn fetch(&self, kind: Kind, path: Option<&str>) -> Result<String, String> {
        let (member, offer) = self.offered(kind).await?;
        let session = self.session();
        if kind == Kind::Binary
            && session
                .key()
                .is_some_and(|key| *key.sha256() == offer.sha256)
        {
            return Ok(self.stamped("this session's binary is the one offered: nothing to fetch"));
        }
        let failed = |error: binbun_collab::Error| error.to_string();
        let to = match path {
            Some(path) => PathBuf::from(path),
            None => fetches::downloads()
                .map_err(failed)?
                .join(fetches::local_name(&offer)),
        };
        let cache = Fetches::new().map_err(failed)?;
        self.clock.say(&format!(
            "fetching the {kind} {} ({}) from {}",
            shown(&offer.name),
            megabytes(offer.length),
            short(member)
        ));
        let fetched = self
            .peer()?
            .fetch(
                member,
                &offer,
                &cache,
                &to,
                Some(progress_printer(self.clock, kind)),
            )
            .await
            .map_err(failed)?;
        self.clock.say(&fetched_line(&offer, &fetched));
        if kind == Kind::Binary {
            return Ok(String::new());
        }
        // Beside `to` under a numbered name if another file was there.
        let again = session
            .with_debug(&fetched.path)
            .map_err(|e| e.to_string())?;
        let again = tokio::task::spawn_blocking(move || match again.wait(Stage::Analysed, None) {
            Waited::Reached(_) => Ok(again),
            Waited::Stopped { failure, .. } => {
                Err(failure.unwrap_or_else(|| "the analysis stopped".to_owned()))
            }
            Waited::TimedOut(_) => Err("the analysis timed out".to_owned()),
        })
        .await
        .map_err(|e| e.to_string())??;
        // Edits taken while it was analysed go on with it.
        again.take_edits(&session);
        self.peer()?.set_session(Arc::new(again));
        let fingerprint = self
            .session()
            .fingerprint()
            .map_or_else(|| "none".to_owned(), |print| hex(&print.analysis));
        Ok(self.stamped(&format!(
            "analysed again with {}: fingerprint {}",
            fetched.path.display(),
            fingerprint.get(..16).unwrap_or_default()
        )))
    }

    /// The peer, for the commands that need one.
    fn peer(&self) -> Result<&Peer, String> {
        self.peer
            .as_deref()
            .ok_or_else(|| "this command needs a live session (share or join)".to_owned())
    }

    /// Runs `words`, a command that does not wait.
    fn command(&self, words: &[&str]) -> Result<String, String> {
        match words {
            ["rename", function, name] => {
                self.writable()?;
                let entry = self.function(function)?;
                self.session()
                    .rename_function(entry, Some(name))
                    .map_err(|error| error.to_string())?;
                Ok(self.stamped(&format!("renamed {entry:#x} {name}")))
            }
            ["comment", address, text @ ..] => {
                self.writable()?;
                let address = number(address)?;
                self.session()
                    .comment(address, Some(&text.join(" ")))
                    .map_err(|error| error.to_string())?;
                Ok(self.stamped(&format!("commented {address:#x}")))
            }
            ["resolve", function, name] => {
                self.writable()?;
                let entry = self.function(function)?;
                self.session()
                    .resolve(
                        Key::FunctionName(entry),
                        Value::Text(Some((*name).to_owned())),
                    )
                    .map_err(|error| error.to_string())?;
                Ok(self.stamped(&format!("resolved {entry:#x} as {name}")))
            }
            ["begin", label @ ..] => {
                self.writable()?;
                self.session().begin(&label.join(" "), Origin::User);
                Ok(self.stamped("group open"))
            }
            ["commit"] => {
                let committed = self.session().commit().map_err(|error| error.to_string())?;
                Ok(self.stamped(&format!(
                    "committed {}",
                    committed.map_or_else(|| "nothing".to_owned(), |entry| entry.label)
                )))
            }
            ["conflicts"] => Ok(self.conflicts()),
            ["state"] => Ok(self.state()),
            ["refused"] => self.refused(),
            ["pending"] => Ok(local("pending", &self.session().pending())),
            ["apart"] => Ok(local("apart", &self.session().not_in_project())),
            ["members"] => self.members(),
            ["links"] => {
                let mut out = String::new();
                for (key, path) in self.peer()?.links() {
                    let _ = writeln!(out, "link {} via {path}", short(key));
                }
                Ok(out)
            }
            ["withdraw", kind] => {
                let kind = blob_kind(kind)?;
                self.peer()?.withdraw(kind);
                Ok(self.stamped(&format!("the {kind} is offered no longer")))
            }
            _ => self.manage(words),
        }
    }

    /// Runs `words`, a command on the members (the owner's).
    fn manage(&self, words: &[&str]) -> Result<String, String> {
        match words {
            ["remove", key] => {
                let member = self.member(key)?;
                let epoch = self.peer()?.remove(member).map_err(|e| e.to_string())?;
                Ok(self.stamped(&format!("removed {}; epoch {epoch}", short(member))))
            }
            ["role", key, role] => {
                let member = self.member(key)?;
                let role = Role::given(role).map_err(|e| e.to_string())?;
                self.peer()?
                    .set_role(member, role)
                    .map_err(|e| e.to_string())?;
                Ok(self.stamped(&format!("{} is a {role}", short(member))))
            }
            ["add", card, role @ ..] => {
                let card: Card = card
                    .parse()
                    .map_err(|e: binbun_collab::Error| e.to_string())?;
                let role = match role {
                    [] => Role::Editor,
                    [role] => Role::given(role).map_err(|e| e.to_string())?,
                    [flag, role] if *flag == "--role" => {
                        Role::given(role).map_err(|e| e.to_string())?
                    }
                    _ => return Err("add CARD [--role] [editor|viewer|agent]".to_owned()),
                };
                self.peer()?.add(&card, role).map_err(|e| e.to_string())?;
                Ok(self.stamped(&format!("added {} as {role}", short(card.key))))
            }
            ["transfer", key] => {
                let member = self.member(key)?;
                self.peer()?.transfer(member).map_err(|e| e.to_string())?;
                Ok(self.stamped(&format!("{} owns the project now", short(member))))
            }
            ["chat", text @ ..] => {
                self.peer()?
                    .chat(&text.join(" "), &[], &[])
                    .map_err(|e| e.to_string())?;
                Ok(String::new())
            }
            ["people"] => {
                let mut out = String::new();
                for person in self.peer()?.participants() {
                    let _ = writeln!(
                        out,
                        "{} {} binbun {} {}{}",
                        short(person.card.key),
                        shown(&person.card.name),
                        shown(&person.engine.release),
                        shown(&person.engine.build),
                        person
                            .cursor
                            .map(|c| format!(" at {:#x}", c.address))
                            .unwrap_or_default()
                    );
                }
                Ok(out)
            }
            _ => self.talk(words),
        }
    }

    /// Runs `words`, a command on the threads and suggestions.
    fn talk(&self, words: &[&str]) -> Result<String, String> {
        let session = self.session();
        let said = |text: &[&str]| Say {
            body: text.join(" "),
            ..Say::default()
        };
        let failed = |error: Error| error.to_string();
        match words {
            ["thread", address, text @ ..] => {
                let address = number(address)?;
                session.begin("Open thread", Origin::User);
                let opened = session
                    .open_thread(Anchor::Instruction(address), "")
                    .and_then(|id| session.post(id, said(text)).map(|_| id));
                if opened.is_err() {
                    session.rollback();
                }
                let id = opened.map_err(failed)?;
                session.commit().map_err(failed)?;
                Ok(self.stamped(&format!("thread {} at {address:#x}", talk_id(id))))
            }
            ["post", thread, text @ ..] => {
                let thread = if *thread == "last" {
                    session.threads().last().map(|t| t.id).ok_or("no thread")?
                } else {
                    parse_talk_id(thread)?
                };
                let id = session.post(thread, said(text)).map_err(failed)?;
                Ok(self.stamped(&format!("posted {}", talk_id(id))))
            }
            ["edit", post, text @ ..] => {
                session
                    .edit_post(parse_talk_id(post)?, &text.join(" "))
                    .map_err(failed)?;
                Ok(self.stamped(&format!("edited {post}")))
            }
            ["delete", post] => {
                session.delete_post(parse_talk_id(post)?).map_err(failed)?;
                Ok(self.stamped(&format!("deleted {post}")))
            }
            ["threads"] => Ok(session.threads().iter().map(thread_text).collect()),
            ["suggest", function, name, text @ ..] => {
                let entry = self.function(function)?;
                let id = session
                    .suggest(Suggesting {
                        label: format!("Name {function}"),
                        edits: vec![(
                            Key::FunctionName(entry),
                            Value::Text(Some((*name).to_owned())),
                        )],
                        rationale: text.join(" "),
                        ..Suggesting::default()
                    })
                    .map_err(failed)?;
                Ok(self.stamped(&format!("suggested {}", talk_id(id))))
            }
            ["suggestions"] => Ok(self.suggestions()),
            ["accept", suggestion, chosen @ ..] => {
                let chosen = chosen
                    .iter()
                    .map(|n| n.parse().map_err(|_| format!("not an edit's number: {n}")))
                    .collect::<Result<Vec<usize>, _>>()?;
                let id = if *suggestion == "last" {
                    session
                        .suggestions()
                        .last()
                        .map(|s| s.id)
                        .ok_or("no suggestion")?
                } else {
                    parse_talk_id(suggestion)?
                };
                session.accept(id, &chosen).map_err(failed)?;
                Ok(self.stamped(&format!("accepted {suggestion}")))
            }
            ["unchat", id] => {
                let id = id
                    .parse()
                    .map_err(|_| format!("not a chat message's id: {id}"))?;
                self.peer()?.remove_chat(id).map_err(|e| e.to_string())?;
                Ok(self.stamped(&format!("removed chat message {id}")))
            }
            _ => Err(format!("unknown command {:?}", words.join(" "))),
        }
    }

    /// Each suggestion, a line, then its edits.
    fn suggestions(&self) -> String {
        let mut out = String::new();
        for suggestion in self.session().suggestions() {
            let _ = writeln!(
                out,
                "suggestion {} by {} {}: {} {}",
                talk_id(suggestion.id),
                short(suggestion.author.key),
                shown(&suggestion.author.origin.to_string()),
                shown(&format!("{:?}", suggestion.label)),
                shown(&format!("{:?}", suggestion.state))
            );
            for (n, edit) in suggestion.edits.iter().enumerate() {
                let moved = if edit.moved { " (changed since)" } else { "" };
                let _ = writeln!(
                    out,
                    "  {n} {} {}{moved}",
                    key(&edit.key),
                    value(&edit.value)
                );
            }
        }
        out
    }

    /// Says `line`, stamped: nothing left to say.
    fn stamped(&self, line: &str) -> String {
        self.clock.say(line);
        String::new()
    }

    /// Refuses to edit as a viewer, or as a peer view-only in this session
    /// (another build than the host's): every peer refuses their edits.
    fn writable(&self) -> Result<(), String> {
        if let Some(why) = self.peer.as_ref().and_then(|peer| peer.view_only()) {
            return Err(format!("view-only in this session: {why}"));
        }
        match self.peer.as_ref().and_then(|peer| peer.role()) {
            Some(Role::Viewer) => Err("a viewer does not edit".to_owned()),
            Some(Role::Owner | Role::Editor | Role::Agent | Role::Store) | None => Ok(()),
        }
    }

    /// The entry of `word`: a number, or a function's name.
    fn function(&self, word: &str) -> Result<u64, String> {
        if word.starts_with("0x") {
            return number(word);
        }
        let session = self.session();
        let database = session
            .database()
            .ok_or("the functions are not recovered")?;
        database
            .functions()
            .find(|(_, f)| session.name(f.entry).as_deref() == Some(word))
            .map(|(_, f)| f.entry)
            .ok_or_else(|| format!("no function {word}"))
    }

    /// The member whose key or fingerprint starts with `prefix`.
    fn member(&self, prefix: &str) -> Result<PublicKey, String> {
        let prefix = prefix.replace(' ', "");
        let membership = self.peer()?.membership();
        let found: Vec<PublicKey> = membership
            .members()
            .keys()
            .copied()
            .filter(|key| {
                key.to_string().starts_with(&prefix)
                    || fingerprint(*key).replace(' ', "").starts_with(&prefix)
            })
            .collect();
        match found.as_slice() {
            [one] => Ok(*one),
            [] => Err(format!("no member {prefix}")),
            _ => Err(format!("{prefix} names more than one member")),
        }
    }

    /// The keys in conflict.
    fn conflicts(&self) -> String {
        let mut out = String::new();
        let conflicts = self.session().conflicts();
        for conflict in &conflicts {
            let leaves: Vec<String> = conflict
                .leaves
                .iter()
                .map(|leaf| {
                    let shown = if leaf.op == conflict.shown {
                        " (shown)"
                    } else {
                        ""
                    };
                    format!("{} by {}{shown}", value(&leaf.value), short(leaf.author))
                })
                .collect();
            let _ = writeln!(
                out,
                "conflict {}: {}",
                key(&conflict.key),
                leaves.join(", ")
            );
        }
        let _ = writeln!(out, "{} conflict(s)", conflicts.len());
        out
    }

    /// The session's and peer's state in one line.
    fn state(&self) -> String {
        let session = self.session();
        let mut out = format!(
            "changes {}, chains {}, conflicts {}",
            session.history().len(),
            session.chains().len(),
            session.conflicts().len()
        );
        match &self.peer {
            Some(peer) => {
                let membership = peer.membership();
                let _ = write!(
                    out,
                    ", refused {}, epoch {} (keys {:?}), role {}, links {}",
                    peer.refused().len(),
                    membership.epoch(),
                    peer.epochs(),
                    peer.role()
                        .map_or_else(|| "none".to_owned(), |role| role.to_string()),
                    peer.links().len()
                );
            }
            None => {
                let _ = write!(out, ", refused {}", session.refused().len());
            }
        }
        out.push('\n');
        out
    }

    /// The changes refused.
    fn refused(&self) -> Result<String, String> {
        let mut out = String::new();
        for refused in self.peer()?.refused() {
            let _ = writeln!(
                out,
                "refused {} by {}: {}",
                refused
                    .change
                    .map_or_else(|| "?".to_owned(), |id| format!("{}:{}", id.chain, id.seq)),
                refused.author.map_or_else(|| "?".to_owned(), short),
                shown(&refused.why)
            );
        }
        Ok(out)
    }

    /// The membership chain's members.
    fn members(&self) -> Result<String, String> {
        let peer = self.peer()?;
        let membership = peer.membership();
        let mut out = String::new();
        for (key, member) in membership.members() {
            let role = member
                .role()
                .map_or_else(|| "removed".to_owned(), |role| role.to_string());
            let me = if *key == peer.id() { " (me)" } else { "" };
            let _ = writeln!(out, "member {} {role}{me}  {key}", short(*key));
        }
        let _ = writeln!(
            out,
            "membership record {}, epoch {}, keys held {:?}",
            membership.seq(),
            membership.epoch(),
            peer.epochs()
        );
        Ok(out)
    }

    /// Waits until `what` holds (`[.., SECONDS]` at most).
    async fn wait(&self, what: &[&str]) -> Result<String, String> {
        // The words each condition takes after its name.
        let arity = match what.first() {
            Some(&("linked" | "unlinked")) => 0,
            Some(&"name") => 2,
            Some(_) | None => 1,
        };
        let (what, limit) = match what.split_last() {
            Some((seconds, rest)) if what.len() == arity + 2 => {
                let seconds: f64 = seconds
                    .parse()
                    .map_err(|_| format!("not seconds: {seconds}"))?;
                (rest, Duration::from_secs_f64(seconds))
            }
            Some(_) | None => (what, WAIT),
        };
        let holds = self.condition(what)?;
        let start = Instant::now();
        while !holds() {
            if start.elapsed() > limit {
                return Err(format!(
                    "timed out after {:.1} s waiting for {}",
                    limit.as_secs_f64(),
                    what.join(" ")
                ));
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        Ok(self.stamped(&format!(
            "ok: {} after {:.3} s",
            what.join(" "),
            start.elapsed().as_secs_f64()
        )))
    }

    /// Whether `what` holds now, as a test.
    fn condition(&self, what: &[&str]) -> Result<Box<dyn Fn() -> bool + '_>, String> {
        let count = |n: &str| n.parse::<usize>().map_err(|_| format!("not a count: {n}"));
        Ok(match what {
            ["changes", n] => {
                let n = count(n)?;
                Box::new(move || self.session().history().len() >= n)
            }
            ["conflicts", n] => {
                let n = count(n)?;
                Box::new(move || self.session().conflicts().len() == n)
            }
            ["name", function, name] => {
                let entry = self.function(function)?;
                let name = (*name).to_owned();
                Box::new(move || self.session().name(entry).as_deref() == Some(name.as_str()))
            }
            ["linked"] => {
                let peer = self.peer()?;
                // Linked and synced: a link serves files and changes only
                // once it is a reader's.
                Box::new(move || !peer.readers().is_empty())
            }
            ["unlinked"] => {
                let peer = self.peer()?;
                Box::new(move || peer.links().is_empty())
            }
            ["refused", n] => {
                let (peer, n) = (self.peer()?, count(n)?);
                Box::new(move || peer.refused().len() >= n)
            }
            ["epoch", n] => {
                let (peer, n) = (self.peer()?, n.parse::<u32>().map_err(|_| "not an epoch")?);
                Box::new(move || peer.membership().epoch() >= n)
            }
            ["members", n] => {
                let (peer, n) = (self.peer()?, count(n)?);
                Box::new(move || {
                    peer.membership()
                        .members()
                        .values()
                        .filter(|member| member.role().is_some())
                        .count()
                        == n
                })
            }
            ["threads", n] => {
                let n = count(n)?;
                Box::new(move || self.session().threads().len() >= n)
            }
            ["posts", n] => {
                let n = count(n)?;
                Box::new(move || {
                    let threads = self.session().threads();
                    threads
                        .iter()
                        .map(|thread| thread.posts.len())
                        .sum::<usize>()
                        >= n
                })
            }
            ["suggestions", n] => {
                let n = count(n)?;
                Box::new(move || self.session().suggestions().len() >= n)
            }
            _ => return Err(format!("cannot wait for {:?}", what.join(" "))),
        })
    }
}

/// `word` as a number: `0x` hexadecimal, else decimal.
fn number(word: &str) -> Result<u64, String> {
    match word.strip_prefix("0x") {
        Some(hex) => u64::from_str_radix(hex, 16),
        None => word.parse(),
    }
    .map_err(|_| format!("not an address: {word}"))
}

/// The kind of file `word` names: `binary` or `debug`.
fn blob_kind(word: &str) -> Result<Kind, String> {
    match word {
        "binary" => Ok(Kind::Binary),
        "debug" => Ok(Kind::DebugFile),
        other => Err(format!("not binary or debug: {other}")),
    }
}

/// `bytes` in lower-case hexadecimal.
pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}

/// A thread, post or suggestion's id: `<chain>:<seq>:<n>`.
fn talk_id(id: OpId) -> String {
    format!("{}:{}:{}", id.change.chain, id.change.seq, id.index)
}

/// The id `word` spells (`talk_id`).
fn parse_talk_id(word: &str) -> Result<OpId, String> {
    let bad = || format!("not a thread, post or suggestion: {word}");
    let [chain, seq, index] =
        <[&str; 3]>::try_from(word.split(':').collect::<Vec<_>>()).map_err(|_| bad())?;
    let mut bytes = [0; 16];
    if chain.len() != 32 {
        return Err(bad());
    }
    for (at, byte) in bytes.iter_mut().enumerate() {
        let pair = chain.get(at * 2..at * 2 + 2).ok_or_else(bad)?;
        *byte = u8::from_str_radix(pair, 16).map_err(|_| bad())?;
    }
    Ok(OpId {
        change: ChangeId {
            chain: ChainId(bytes),
            seq: seq.parse().map_err(|_| bad())?,
        },
        index: index.parse().map_err(|_| bad())?,
    })
}

/// `thread` for people: a line, then a line per post, what its author
/// wrote escaped ([`shown`]: a line break in a post is no line here).
fn thread_text(thread: &Thread) -> String {
    let mut out = format!(
        "thread {} at {}{}\n",
        talk_id(thread.id),
        shown(&format!("{:?}", thread.anchor)),
        if thread.resolved { " (resolved)" } else { "" }
    );
    for post in &thread.posts {
        let body = match &post.deleted {
            Some(deleted) if deleted.by_owner => "(removed by the owner)".to_owned(),
            Some(_) => "(deleted)".to_owned(),
            None => shown(&post.body),
        };
        let _ = writeln!(
            out,
            "  post {} by {}: {body}",
            talk_id(post.id),
            short(post.author.key)
        );
    }
    for suggestion in &thread.suggestions {
        let _ = writeln!(out, "  suggestion {}", talk_id(*suggestion));
    }
    out
}

/// `edits`, each a line `WORD CHAIN:SEQ by AUTHOR: KEY = VALUE, ...`, then
/// their count.
fn local(word: &str, edits: &[LocalEdit]) -> String {
    let mut out = String::new();
    for edit in edits {
        let values: Vec<String> = edit
            .values
            .iter()
            .map(|(k, v)| format!("{} = {}", key(k), value(v)))
            .collect();
        let _ = writeln!(
            out,
            "{word} {}:{} by {}: {}",
            edit.change.chain,
            edit.change.seq,
            short(edit.author),
            values.join(", ")
        );
    }
    let _ = writeln!(out, "{} {word} edit(s)", edits.len());
    out
}

/// `key` for people.
pub(crate) fn key(key: &Key) -> String {
    match key {
        Key::FunctionName(entry) => format!("function {entry:#x}"),
        Key::GlobalName(address) => format!("global {address:#x}"),
        Key::Comment(address) => format!("comment {address:#x}"),
        Key::Signature(entry) => format!("signature {entry:#x}"),
        other @ (Key::VariableName(_)
        | Key::Slot(..)
        | Key::Bookmark(..)
        | Key::Number(..)
        | Key::Type(_)
        | Key::Definition(_)
        | Key::Item(_)
        | Key::Bounds(_)
        | Key::DebugFile
        | Key::Thread(_)
        | Key::Post(_)
        | Key::Suggestion(_)) => shown(&format!("{other:?}")),
    }
}

/// `value` for people.
pub(crate) fn value(value: &Value) -> String {
    match value {
        Value::Text(Some(text)) => shown(&format!("{text:?}")),
        Value::Text(None) => "(none)".to_owned(),
        other @ (Value::Number(_)
        | Value::Item(_)
        | Value::Bounds(_)
        | Value::DebugFile(_)
        | Value::Thread(_)
        | Value::Post(_)
        | Value::Suggestion(_)
        | Value::Signature(_)) => shown(&format!("{other:?}")),
    }
}

#[cfg(test)]
mod tests {
    use binbun_session::journal::talk::{Anchor, Author, Post, Thread};
    use binbun_session::journal::{ChainId, ChangeId, Hlc, OpId, Origin, PublicKey};

    use super::thread_text;

    /// Op `index` of change 1 of a chain.
    fn op(index: u16) -> OpId {
        OpId {
            change: ChangeId {
                chain: ChainId([5; 16]),
                seq: 1,
            },
            index,
        }
    }

    #[test]
    fn a_post_prints_on_its_own_line_whatever_its_author_wrote() {
        let author = Author {
            key: PublicKey([7; 32]),
            origin: Origin::User,
        };
        // A post that clears the screen, then fakes a post and a refusal
        // on lines of their own.
        let body = "ok\u{1b}[2J\n  post 0:0:0 by 0000 0000: trust me\r\nrefused x\u{202e}";
        let thread = Thread {
            id: op(0),
            anchor: Anchor::Instruction(0x1000),
            quote: String::new(),
            opened_by: author.clone(),
            time: Hlc::new(1, 0),
            resolved: false,
            resolved_by: None,
            posts: vec![Post {
                id: op(1),
                thread: op(0),
                reply_to: None,
                author,
                time: Hlc::new(1, 0),
                body: body.to_owned(),
                edited: None,
                deleted: None,
                mentions: Vec::new(),
                evidence: None,
            }],
            suggestions: Vec::new(),
        };
        let printed = thread_text(&thread);
        let lines: Vec<&str> = printed.lines().collect();
        assert_eq!(lines.len(), 2, "{printed}");
        assert!(lines[0].starts_with("thread "), "{printed}");
        assert!(lines[1].starts_with("  post "), "{printed}");
        assert!(lines[1].contains("trust me"), "{printed}");
        assert!(
            printed
                .chars()
                .all(|c| c == '\n' || !(c.is_control() || c == '\u{202e}')),
            "{printed:?}"
        );
    }
}
