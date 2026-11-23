//! The sync properties of §10.5 over model peers and arbitrary schedules
//! (`proptest`): local changes, deliveries, duplicates, links dropped and
//! made again, membership records (add, role raised and lowered, remove,
//! readmit; viewers and editors), an author forking, held caches and
//! stops dropped, restarts. Random schedules show these on the schedules
//! tried; they prove nothing beyond them.
//!
//! Every schedule ends with every peer linked and time let pass, and
//! P1, P3, P7 are checked then, under the design's assumptions (one
//! membership chain everywhere, every change delivered, no local stop
//! the others lack). P2, P4, P6, P12, P13 and P14 are checked after every
//! step.

#![allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::wildcard_enum_match_arm,
    reason = "tests fail loudly"
)]

mod model;

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::time::Duration;

use binbun_bounded::Bounded;
use binbun_session::journal::{
    ChainId, ChainOrigin, ChangeHash, ChangeId, ForkProof, ProjectId, SignedHead, Signer, Tip,
    Under,
};
use binbun_sync::machine::Closed;
use binbun_sync::wire::ProofBytes;
use binbun_sync::{Admission, Envelope, Spent, Storage, Sync};
use model::{BINARY, Model, ModelBody, Net, Op, Role, prior, seal, seed, sign};
use proptest::prelude::*;
use proptest::test_runner::{Config, RngSeed};

/// Peers in a schedule: the owner, two members, one added later.
const PEERS: usize = 4;

/// Seconds let pass at the end of a schedule, every peer linked.
const SETTLE: u64 = 200;

/// One step of a schedule.
#[derive(Clone, Debug)]
enum Action {
    /// `peer` makes a change, naming the tip of `dep`'s chain it holds.
    Change { peer: usize, dep: Option<usize> },
    /// Delivers up to `n` messages from `from` to `to`.
    Deliver { from: usize, to: usize, n: usize },
    /// Delivers everything in flight and builds every page, until quiet.
    Drain,
    /// Delivers the next message from `from` to `to` twice, if it is
    /// unsolicited.
    Duplicate { from: usize, to: usize },
    /// `peer` builds its next page.
    Serve { peer: usize },
    /// Time passes.
    Tick { secs: u64 },
    /// A link is made.
    Link { a: usize, b: usize },
    /// A link is dropped.
    Unlink { a: usize, b: usize },
    /// The owner adds (or readmits) `peer`.
    Add { peer: usize, editor: bool },
    /// The owner raises or lowers `peer`'s role.
    Role { peer: usize, editor: bool },
    /// The owner removes `peer`.
    Remove { peer: usize },
    /// `author` forks its chain, the other branch reaching `target`.
    Fork { author: usize, target: usize },
    /// `peer`'s held cache is lost.
    DropHeld { peer: usize },
    /// `peer`'s stops are lost.
    DropStops { peer: usize },
    /// `peer` restarts.
    Restart { peer: usize },
    /// A valid proof of a chain no one knows is sent to `to`.
    Foreign { from: usize, to: usize },
}

impl Action {
    /// Whether it loses a cache (P5).
    fn drops(&self) -> bool {
        matches!(self, Self::DropHeld { .. } | Self::DropStops { .. })
    }
}

fn peer() -> impl Strategy<Value = usize> {
    0..PEERS
}

fn pair() -> impl Strategy<Value = (usize, usize)> {
    (peer(), 1..PEERS).prop_map(|(a, d)| (a, (a + d) % PEERS))
}

fn action() -> impl Strategy<Value = Action> {
    prop_oneof![
        8 => (peer(), proptest::option::of(peer())).prop_map(|(peer, dep)| Action::Change { peer, dep }),
        16 => (pair(), 1..20usize).prop_map(|((from, to), n)| Action::Deliver { from, to, n }),
        4 => Just(Action::Drain),
        2 => pair().prop_map(|(from, to)| Action::Duplicate { from, to }),
        8 => peer().prop_map(|peer| Action::Serve { peer }),
        4 => (1..40u64).prop_map(|secs| Action::Tick { secs }),
        4 => pair().prop_map(|(a, b)| Action::Link { a, b }),
        1 => pair().prop_map(|(a, b)| Action::Unlink { a, b }),
        2 => (1..PEERS, any::<bool>()).prop_map(|(peer, editor)| Action::Add { peer, editor }),
        2 => (1..PEERS, any::<bool>()).prop_map(|(peer, editor)| Action::Role { peer, editor }),
        2 => (1..PEERS).prop_map(|peer| Action::Remove { peer }),
        1 => pair().prop_map(|(author, target)| Action::Fork { author, target }),
        1 => peer().prop_map(|peer| Action::DropHeld { peer }),
        1 => peer().prop_map(|peer| Action::DropStops { peer }),
        1 => peer().prop_map(|peer| Action::Restart { peer }),
        1 => pair().prop_map(|(from, to)| Action::Foreign { from, to }),
    ]
}

fn schedule() -> impl Strategy<Value = Vec<Action>> {
    proptest::collection::vec(action(), 1..80)
}

/// A chain as kept: its changes' hashes, its freeze and its proof's place.
type Kept = (Vec<ChangeHash>, Option<u64>, Option<u64>);

/// What survives a restart of `model`: its records and chains as held.
fn durable(model: &Model) -> (Vec<Vec<u8>>, BTreeMap<ChainId, Kept>) {
    let chains = model
        .chains
        .iter()
        .map(|(chain, c)| {
            let hashes = c.changes.iter().map(|(h, _)| h.hash()).collect();
            (*chain, (hashes, c.frozen, c.proof.map(|p| p.place())))
        })
        .collect();
    (model.records.clone(), chains)
}

/// A valid fork proof of a chain of a key no one knows.
fn foreign_proof() -> ForkProof {
    let signer = Signer::from_seed(&[0x77; 32]);
    let origin = ChainOrigin {
        author: signer.public(),
        project: ProjectId([0x77; 16]),
        salt: [0x77; 16],
    };
    let a = prior(&signer, origin, 1, 1).remove(0).0;
    let b = prior(&signer, origin, 1, 2).remove(0).0;
    ForkProof::new(origin, a, b).unwrap()
}

/// Closes an honest peer never makes another honest peer make.
fn fault(why: Closed) -> bool {
    match why {
        Closed::Stalled | Closed::Revoked | Closed::NotServed => false,
        Closed::Malformed
        | Closed::Phase(_)
        | Closed::Reply(_)
        | Closed::Requests
        | Closed::Strays
        | Closed::Genesis
        | Closed::Membership
        | Closed::Records
        | Closed::TooManyChains
        | Closed::Claim
        | Closed::Invalid
        | Closed::Recovering => true,
    }
}

/// The items a message carries, for its work bound.
fn items(message: &Sync) -> usize {
    match message {
        Sync::Records { records, .. } => records.len(),
        Sync::TipsPage { tips, .. } => tips.len(),
        Sync::Tips { tips } => tips.len(),
        Sync::Changes { changes, .. } => changes.len(),
        Sync::Fresh { changes } => changes.len(),
        Sync::Probe { seqs, .. } => seqs.len(),
        Sync::Heads { heads, .. } => heads.len(),
        Sync::HeadsRun { heads, .. } => heads.len(),
        Sync::HeadsAsk { most, .. } | Sync::Want { most, .. } => usize::from(*most),
        Sync::Refused { changes } => changes.len(),
        Sync::MembershipHead { .. }
        | Sync::Ready { .. }
        | Sync::Summary { .. }
        | Sync::RecordsAsk { .. }
        | Sync::RecordsDiverged { .. }
        | Sync::TipsAsk { .. }
        | Sync::Diverged { .. }
        | Sync::ForkAsk { .. }
        | Sync::Fork { .. } => 1,
    }
}

/// P4: the work one message caused is within the cost table: at most one
/// request; at most a page of judgements; signature checks of at most a
/// probe's heads and a proof; reads, hashes and tasks in proportion to
/// what the message carries and the links (not to the history), never
/// the whole of a chain or of the known chains.
fn within(spent: &Spent, message: &Sync, links: usize) -> Result<(), String> {
    let k = items(message);
    let per = (k + 1) * (links + 1);
    let checks = [
        ("request", spent.request, 1),
        ("admit", spent.admit, 256),
        ("verify", spent.verify, 16 + 3),
        ("read", spent.read, 8 * per + 64),
        ("hash", spent.hash, 4096 + 256),
        ("task", spent.task, k + 2 * links + 2),
    ];
    for (what, got, most) in checks {
        if got > most {
            return Err(format!(
                "{} caused {got} {what}, past {most}",
                message.name()
            ));
        }
    }
    Ok(())
}

/// Runs `actions` on a fresh net, checking the step properties after
/// each; then links every peer, lets time pass, and returns the net.
fn run(actions: &[Action]) -> Result<Net, TestCaseError> {
    let mut net = Net::with(PEERS, PEERS - 1, Vec::new());
    net.keep = false;
    for p in 0..PEERS - 1 {
        net.start(p);
    }
    let foreign = foreign_proof();
    for action in actions {
        step(&mut net, action, &foreign)?;
        check_step(&net, &foreign)?;
    }
    finish(&mut net, Some(&foreign))?;
    Ok(net)
}

/// Links every pair and lets time pass, checking the step properties
/// each second if `foreign` is given.
fn finish(net: &mut Net, foreign: Option<&ForkProof>) -> Result<(), TestCaseError> {
    for _ in 0..3 {
        net.link_all();
        for _ in 0..SETTLE / 3 {
            net.drain(64);
            if let Some(foreign) = foreign {
                check_step(net, foreign)?;
            }
            net.tick(Duration::from_secs(1));
        }
        net.drain(64);
    }
    match foreign {
        Some(foreign) => check_step(net, foreign),
        None => Ok(()),
    }
}

#[expect(clippy::too_many_lines, reason = "one arm per action")]
fn step(net: &mut Net, action: &Action, foreign: &ForkProof) -> Result<(), TestCaseError> {
    match *action {
        Action::Change { peer, dep } => {
            let deps = dep
                .filter(|dep| *dep != peer)
                .and_then(|dep| {
                    let chain = net.peers[dep].chain();
                    let tip = net.peers[peer].model.tip(chain)?;
                    (tip.seq >= 1 && tip.fork == 0).then_some(ChangeId {
                        chain,
                        seq: tip.seq,
                    })
                })
                .into_iter()
                .collect();
            net.change(peer, deps);
        }
        Action::Deliver { from, to, n } => {
            for _ in 0..n {
                let Some(queued) = net.flight.get(&(from, to)).and_then(|q| q.front()).cloned()
                else {
                    break;
                };
                let links = net.wires.len();
                net.peers[to].budget.take();
                net.deliver(from, to);
                let spent = net.peers[to].budget.take();
                within(&spent, &queued.message, links).map_err(TestCaseError::fail)?;
            }
        }
        Action::Duplicate { from, to } => {
            let Some(queued) = net
                .flight
                .get_mut(&(from, to))
                .and_then(VecDeque::pop_front)
            else {
                return Ok(());
            };
            let unsolicited = match &queued.message {
                Sync::Records { id, .. } | Sync::Fork { id, .. } => id.is_none(),
                // Sent once by an honest side: a second is a violation.
                Sync::Ready { .. } => false,
                message => {
                    message.request().is_none()
                        && !matches!(
                            message,
                            Sync::RecordsDiverged { .. }
                                | Sync::TipsPage { .. }
                                | Sync::Changes { .. }
                                | Sync::Diverged { .. }
                                | Sync::Heads { .. }
                                | Sync::HeadsRun { .. }
                        )
                }
            };
            if !net.peers[from]
                .machine
                .is_current(queued.link, queued.generation)
            {
                return Ok(());
            }
            net.deliver_message(from, to, &queued.message);
            if unsolicited {
                // P6: a fact delivered twice leaves durable state as once.
                let once = durable(&net.peers[to].model);
                net.deliver_message(from, to, &queued.message);
                prop_assert_eq!(
                    durable(&net.peers[to].model),
                    once,
                    "{}",
                    queued.message.name()
                );
            }
        }
        Action::Serve { peer } => {
            net.serve(peer);
        }
        Action::Drain => {
            // Message by message, so each one's work is measured (P4).
            for _ in 0..64 {
                let mut any = false;
                for peer in 0..PEERS {
                    while net.serve(peer) {
                        any = true;
                    }
                }
                let pairs: Vec<(usize, usize)> = net.flight.keys().copied().collect();
                for (from, to) in pairs {
                    while let Some(queued) =
                        net.flight.get(&(from, to)).and_then(|q| q.front()).cloned()
                    {
                        any = true;
                        let links = net.wires.len();
                        net.peers[to].budget.take();
                        net.deliver(from, to);
                        let spent = net.peers[to].budget.take();
                        within(&spent, &queued.message, links).map_err(TestCaseError::fail)?;
                    }
                }
                if !any {
                    break;
                }
            }
        }
        Action::Tick { secs } => net.tick(Duration::from_secs(secs)),
        Action::Link { a, b } => net.link(a, b),
        Action::Unlink { a, b } => net.unlink(a, b),
        Action::Add { peer, editor } => {
            let key = net.peers[peer].key();
            if !net.peers[0].model.is_member(key) {
                net.record(Op::Add { key: key.0, editor });
            }
        }
        Action::Role { peer, editor } => {
            let key = net.peers[peer].key();
            if let Some(role) = net.peers[0].model.members().now.get(&key).copied() {
                // Only a lowering carries a cut.
                let lowers = !editor && role == Role::Editor;
                let cuts = if lowers { net.cuts(key) } else { Vec::new() };
                net.record(Op::Role {
                    key: key.0,
                    editor,
                    cuts,
                });
            }
        }
        Action::Remove { peer } => {
            let key = net.peers[peer].key();
            if net.peers[0].model.is_member(key) {
                let cuts = net.cuts(key);
                net.record(Op::Remove { key: key.0, cuts });
            }
        }
        Action::Fork { author, target } => {
            net.fork_into(author, target);
        }
        Action::DropHeld { peer } => net.peers[peer].model.drop_held(),
        Action::DropStops { peer } => net.peers[peer].machine.drop_stops(),
        Action::Restart { peer } => net.restart(peer),
        Action::Foreign { from, to } => {
            if net.reader(to, from) && net.reader(from, to) {
                net.deliver_message(
                    from,
                    to,
                    &Sync::Fork {
                        id: None,
                        chain: foreign.chain(),
                        proof: Some(ProofBytes::try_from(&*foreign.bytes()).unwrap()),
                    },
                );
            }
        }
    }
    Ok(())
}

/// The properties checked after every step.
fn check_step(net: &Net, foreign: &ForkProof) -> Result<(), TestCaseError> {
    // P14: nothing but Bootstrap's messages is sent before Reader, and no
    // honest peer closes another for a fault.
    prop_assert!(net.early.is_empty(), "sent early: {:?}", net.early);
    let faults: Vec<_> = net.closes.iter().filter(|(_, why)| fault(*why)).collect();
    prop_assert!(faults.is_empty(), "closed: {faults:?}");
    for (i, peer) in net.peers.iter().enumerate() {
        // P2: from the moment a replica takes a cut, nothing of that
        // author past it is admitted there, by arrival or release.
        prop_assert!(
            peer.model.violations.is_empty(),
            "peer {i} admitted past a cut: {:?}",
            peer.model.violations
        );
        // P13: a proof of a chain not known here leaves no state.
        prop_assert!(!peer.model.chains.contains_key(&foreign.chain()));
        // P12: what each link was told is what the other side held.
        for (j, other) in net.peers.iter().enumerate() {
            if i == j {
                continue;
            }
            let Some(link) = net.link_id(i, j) else {
                continue;
            };
            let Some(report) = peer.machine.report(link) else {
                continue;
            };
            for tip in report.tips.values() {
                prop_assert!(
                    net.history[j].contains(&(tip.chain, tip.seq, tip.hash, tip.fork)),
                    "peer {i} was told a tip peer {j} never held: {tip:?}"
                );
            }
            if let Some((seq, hash)) = report.membership {
                prop_assert_eq!(other.model.record_hash(seq), Some(hash));
            }
        }
    }
    Ok(())
}

/// The peers the owner's chain names now.
fn final_members(net: &Net) -> Vec<usize> {
    (0..PEERS)
        .filter(|p| net.peers[0].model.is_member(net.peers[*p].key()))
        .collect()
}

/// P1, P3 and P7 at the end of a schedule.
fn check_end(net: &Net) -> Result<(), TestCaseError> {
    let members = final_members(net);
    let owner = &net.peers[0].model;
    for &p in &members {
        let model = &net.peers[p].model;
        // One membership chain everywhere (the properties' assumption,
        // reached by sync).
        prop_assert_eq!(&model.records, &owner.records, "peer {}", p);
        // P1: the same admitted changes and tips.
        prop_assert_eq!(model.admitted(), owner.admitted(), "peer {}", p);
        prop_assert_eq!(
            model.tips_after(None, None, usize::MAX).0,
            owner.tips_after(None, None, usize::MAX).0,
            "peer {}",
            p
        );
        // P3, P7: a proof at the same lowest place, nothing kept from it.
        for (chain, c) in &model.chains {
            let place = owner.evidence(*chain).map(|proof| proof.place());
            prop_assert_eq!(c.proof.map(|proof| proof.place()), place, "peer {}", p);
            if let Some(place) = place {
                prop_assert!(model.tip(*chain).unwrap().seq < place);
            }
        }
    }
    Ok(())
}

/// The told tips of every link between final members.
fn acknowledgements(net: &Net) -> BTreeMap<(usize, usize), BTreeMap<ChainId, Tip>> {
    let members = final_members(net);
    let mut out = BTreeMap::new();
    for &a in &members {
        for &b in &members {
            if let Some(report) = net
                .link_id(a, b)
                .and_then(|l| net.peers[a].machine.report(l))
            {
                out.insert((a, b), report.tips);
            }
        }
    }
    out
}

/// `cases` cases from a fixed `seed`, so every run tries the same
/// schedules; `BINBUN_SYNC_CASES` multiplies the cases and
/// `BINBUN_SYNC_SEED` is added to the seed, for a deeper or another run.
fn config(cases: u32, seed: u64) -> Config {
    let number = |name: &str| std::env::var(name).ok().and_then(|v| v.parse::<u64>().ok());
    let scale = number("BINBUN_SYNC_CASES").map_or(1, |n| u32::try_from(n).unwrap_or(1));
    Config {
        cases: cases.saturating_mul(scale.max(1)),
        rng_seed: RngSeed::Fixed(seed.wrapping_add(number("BINBUN_SYNC_SEED").unwrap_or(0))),
        failure_persistence: None,
        ..Config::default()
    }
}

proptest! {
    #![proptest_config(config(96, 0x5ec0_0001))]

    /// P1, P2, P3, P4, P6, P7, P12, P13, P14 over arbitrary schedules.
    #[test]
    fn schedules_converge_and_keep_every_step_property(actions in schedule()) {
        let net = run(&actions)?;
        check_end(&net)?;
    }
}

proptest! {
    #![proptest_config(config(48, 0x5ec0_0005))]

    /// P5: losing the held cache or the stops at any step changes no final
    /// admitted state and no acknowledgement.
    #[test]
    fn dropping_the_caches_changes_no_outcome(actions in schedule()) {
        let with = run(&actions)?;
        let kept: Vec<Action> = actions.iter().filter(|a| !a.drops()).cloned().collect();
        let without = run(&kept)?;
        for p in final_members(&with) {
            prop_assert_eq!(with.peers[p].model.admitted(), without.peers[p].model.admitted());
        }
        prop_assert_eq!(acknowledgements(&with), acknowledgements(&without));
    }
}

/// A well-formed message from a peer that lies: any variant, with fields
/// drawn from small sets and the ends of `u64`.
fn lie(chains: Vec<ChainId>) -> impl Strategy<Value = Sync> {
    let chain = proptest::sample::select(chains);
    let seq = prop_oneof![0..8u64, Just(u64::MAX), Just(u64::MAX - 1), any::<u64>()];
    let hash = prop_oneof![Just(ChangeHash::ZERO), Just(ChangeHash([7; 32]))];
    let id = 0..12u32;
    let tip =
        (chain.clone(), seq.clone(), hash.clone(), 0..3u64).prop_map(|(chain, seq, hash, fork)| {
            Tip {
                chain,
                project: ProjectId([1; 16]),
                seq,
                hash,
                fork,
            }
        });
    prop_oneof![
        proptest::collection::vec(tip.clone(), 0..8).prop_map(|tips| Sync::Tips {
            tips: Bounded::truncated(tips)
        }),
        (
            id.clone(),
            proptest::collection::vec(tip, 0..8),
            proptest::option::of(chain.clone())
        )
            .prop_map(|(id, tips, next)| Sync::TipsPage {
                id,
                tips: Bounded::truncated(tips),
                next
            }),
        (
            id.clone(),
            chain.clone(),
            seq.clone(),
            hash.clone(),
            0..300u16
        )
            .prop_map(|(id, chain, after, at, most)| Sync::Want {
                id,
                chain,
                after,
                at,
                most
            }),
        (id.clone(), chain.clone(), any::<bool>()).prop_map(|(id, chain, more)| Sync::Changes {
            id,
            chain,
            changes: Bounded::new(),
            more
        }),
        (id.clone(), chain.clone()).prop_map(|(id, chain)| Sync::Diverged { id, chain }),
        (
            id.clone(),
            chain.clone(),
            proptest::collection::vec(seq.clone(), 0..17)
        )
            .prop_map(|(id, chain, seqs)| Sync::Probe {
                id,
                chain,
                seqs: Bounded::truncated(seqs)
            }),
        (id.clone(), chain.clone()).prop_map(|(id, chain)| Sync::Heads {
            id,
            chain,
            heads: Bounded::new()
        }),
        (id.clone(), chain.clone(), seq.clone(), 0..5000u16).prop_map(|(id, chain, upto, most)| {
            Sync::HeadsAsk {
                id,
                chain,
                upto,
                most,
            }
        }),
        (id.clone(), chain.clone()).prop_map(|(id, chain)| Sync::HeadsRun {
            id,
            chain,
            heads: Bounded::new()
        }),
        (id.clone(), chain.clone()).prop_map(|(id, chain)| Sync::ForkAsk { id, chain }),
        (proptest::option::of(id.clone()), chain).prop_map(|(id, chain)| Sync::Fork {
            id,
            chain,
            proof: None
        }),
        (seq.clone(), hash).prop_map(|(seq, hash)| Sync::Summary {
            membership: (seq, hash.0),
            tips: (3, [1; 32])
        }),
        (id, seq).prop_map(|(id, after)| Sync::RecordsAsk {
            id,
            after,
            at: [0; 32]
        }),
    ]
}

proptest! {
    #![proptest_config(config(256, 0x5ec0_0004))]

    /// P4: against a well-formed adversary, each message's work stays
    /// within the cost table, and nothing panics.
    #[test]
    fn an_adversarys_messages_cost_within_the_table(
        lies in proptest::collection::vec(lie(vec![
            ChainId([0; 16]),
            ChainOrigin { author: Signer::from_seed(&seed(0)).public(), project: ProjectId([0; 16]), salt: [7; 16] }.chain(),
            ChainOrigin { author: Signer::from_seed(&seed(1)).public(), project: ProjectId([1; 16]), salt: [7; 16] }.chain(),
        ]), 1..40),
    ) {
        let mut net = Net::with(2, 2, Vec::new());
        net.keep = false;
        net.start(0);
        net.start(1);
        for _ in 0..20 {
            net.change(0, Vec::new());
        }
        net.link_all();
        net.settle(3);
        for message in &lies {
            if !net.reader(0, 1) {
                break;
            }
            net.peers[0].budget.take();
            net.deliver_message(1, 0, message);
            let spent = net.peers[0].budget.take();
            within(&spent, message, 1).map_err(TestCaseError::fail)?;
            for _ in 0..4 {
                net.serve(0);
            }
            net.flight.clear();
            net.tick(Duration::from_secs(1));
        }
    }
}

// --- P21: grants ---

/// The owner's records: its first, then `ops`.
fn records(ops: Vec<Op>) -> Vec<Vec<u8>> {
    let owner = Signer::from_seed(&seed(0)).public();
    let first = model::Record {
        seq: 1,
        prev: [0; 32],
        op: Op::Create {
            owner: owner.0,
            before: Vec::new(),
        },
    };
    let mut out = vec![first.bytes()];
    for op in ops {
        let record = model::Record {
            seq: out.len() as u64 + 1,
            prev: model::record_hash(out.last().unwrap()),
            op,
        };
        out.push(record.bytes());
    }
    out
}

/// The envelopes of `n` changes of `signer`'s chain salted `salt`, begun
/// in the share of `records` under `grant`; and the chain.
fn granted(
    signer: &Signer,
    records: &[Vec<u8>],
    grant: u64,
    salt: u8,
    n: u64,
) -> (ChainId, Vec<Vec<u8>>) {
    let origin = ChainOrigin {
        author: signer.public(),
        project: ProjectId([0x21; 16]),
        salt: [salt; 16],
    };
    let genesis = model::record_hash(&records[0]);
    let mut prev = ChangeHash::ZERO;
    let mut out = Vec::new();
    for seq in 1..=n {
        let body = if seq == 1 {
            ModelBody::Start {
                share: Some(Under { genesis, grant }),
                binary: BINARY,
                blind: 0,
            }
        } else {
            ModelBody::Edit {
                deps: Vec::new(),
                never: false,
                blind: 0,
            }
        };
        let head = sign(signer, origin, seq, prev, &body);
        prev = head.hash();
        out.push(seal(head, &body));
    }
    (origin.chain(), out)
}

/// `envelope` given to `model`'s admission, by `from`.
fn admit(model: &mut Model, from: &Signer, envelope: &[u8]) -> Admission {
    model.admit(from.public(), &Envelope::parse(envelope).unwrap())
}

/// The hashes of `envelopes`' heads.
fn hashes(envelopes: &[Vec<u8>]) -> Vec<ChangeHash> {
    envelopes
        .iter()
        .map(|envelope| {
            let parsed = Envelope::parse(envelope).unwrap();
            SignedHead::parse(parsed.signed_head()).unwrap().hash()
        })
        .collect()
}

/// Every interleaving of sequences of `lens` items, each kept in order:
/// each a list of `(sequence, index)`.
fn interleavings(lens: &[usize]) -> Vec<Vec<(usize, usize)>> {
    fn go(
        next: &mut Vec<usize>,
        lens: &[usize],
        at: &mut Vec<(usize, usize)>,
        out: &mut Vec<Vec<(usize, usize)>>,
    ) {
        if next.iter().zip(lens).all(|(n, len)| n == len) {
            out.push(at.clone());
            return;
        }
        for s in 0..lens.len() {
            if next[s] < lens[s] {
                at.push((s, next[s]));
                next[s] += 1;
                go(next, lens, at, out);
                next[s] -= 1;
                at.pop();
            }
        }
    }
    let mut out = Vec::new();
    go(&mut vec![0; lens.len()], lens, &mut Vec::new(), &mut out);
    out
}

/// P21: an editor is removed and readmitted. Of a chain the owner never
/// saw, a replica that held it before the removal and one that first
/// sees it after the readmission admit the same, its start only, in
/// every order of records and changes; a chain the removal names stands
/// to the change named, on every replica.
#[test]
fn removal_and_readmission_decide_alike_in_every_order() {
    let editor = Signer::from_seed(&seed(1));
    let reader = Signer::from_seed(&seed(2)).public();
    let base = records(vec![Op::Add {
        key: editor.public().0,
        editor: true,
    }]);
    let (unseen, a) = granted(&editor, &base, 2, 1, 3);
    let (named, b) = granted(&editor, &base, 2, 2, 3);
    let all = records(vec![
        Op::Add {
            key: editor.public().0,
            editor: true,
        },
        Op::Remove {
            key: editor.public().0,
            cuts: vec![(named.0, 2)],
        },
        Op::Add {
            key: editor.public().0,
            editor: true,
        },
    ]);
    let orders = interleavings(&[2, a.len(), b.len()]);
    assert_eq!(orders.len(), 560);
    for order in orders {
        let mut model = Model::new(reader, base.clone());
        for (sequence, i) in &order {
            match sequence {
                0 => {
                    let after = model.records.len() as u64;
                    model.take_records(after, &[&all[2 + i][..]]).1.unwrap();
                }
                1 => {
                    admit(&mut model, &editor, &a[*i]);
                }
                _ => {
                    admit(&mut model, &editor, &b[*i]);
                }
            }
        }
        let admitted = model.admitted();
        assert_eq!(admitted[&unseen], hashes(&a[..1]), "{order:?}");
        assert_eq!(admitted[&named], hashes(&b[..2]), "{order:?}");
        assert_eq!(model.tip(unseen).unwrap().seq, 1, "{order:?}");
        assert!(model.violations.is_empty(), "{order:?}");
    }
}

/// P21: a raise leaves a chain of the earlier grant at the earlier role:
/// a viewer's edit on it is refused for good before and after the
/// raise; a chain of the new grant takes edits.
#[test]
fn a_raise_leaves_chains_of_the_earlier_grant_at_its_role() {
    let member = Signer::from_seed(&seed(1));
    let reader = Signer::from_seed(&seed(2)).public();
    let all = records(vec![
        Op::Add {
            key: member.public().0,
            editor: false,
        },
        Op::Role {
            key: member.public().0,
            editor: true,
            cuts: Vec::new(),
        },
    ]);
    let (earlier, c) = granted(&member, &all, 2, 3, 2);
    let (later, d) = granted(&member, &all, 3, 4, 2);
    for raised_first in [false, true] {
        let mut model = Model::new(reader, all[..2].to_vec());
        assert_eq!(admit(&mut model, &member, &c[0]), Admission::Applied);
        if raised_first {
            model.take_records(2, &[&all[2][..]]).1.unwrap();
        }
        assert!(matches!(
            admit(&mut model, &member, &c[1]),
            Admission::Never { .. }
        ));
        if !raised_first {
            model.take_records(2, &[&all[2][..]]).1.unwrap();
        }
        assert_eq!(model.admitted()[&earlier], hashes(&c[..1]));
        assert_eq!(model.frozen(earlier), Some(2));
        assert_eq!(admit(&mut model, &member, &d[0]), Admission::Applied);
        assert_eq!(admit(&mut model, &member, &d[1]), Admission::Applied);
        assert_eq!(model.admitted()[&later], hashes(&d));
    }
}

/// P21: a start naming a record that does not set its author's entry is
/// refused for good and kept as the chain's witness; one naming a record
/// not yet held is declined with no state, and taken once it arrives.
#[test]
fn a_start_is_judged_by_the_record_it_names() {
    let member = Signer::from_seed(&seed(1));
    let reader = Signer::from_seed(&seed(2)).public();
    let all = records(vec![Op::Add {
        key: member.public().0,
        editor: true,
    }]);
    // Record 1 sets the owner's entry, not the member's.
    let (foreign, wrong) = granted(&member, &all, 1, 5, 1);
    let mut model = Model::new(reader, all.clone());
    assert!(matches!(
        admit(&mut model, &member, &wrong[0]),
        Admission::Never { .. }
    ));
    assert_eq!(model.frozen(foreign), Some(1));
    assert_eq!(model.tip(foreign).unwrap().seq, 1);
    // Record 2 is not here yet.
    let (waiting, start) = granted(&member, &all, 2, 6, 1);
    let mut model = Model::new(reader, all[..1].to_vec());
    assert_eq!(admit(&mut model, &member, &start[0]), Admission::Declined);
    assert!(model.chains.is_empty());
    model.take_records(1, &[&all[1][..]]).1.unwrap();
    assert_eq!(admit(&mut model, &member, &start[0]), Admission::Applied);
    assert_eq!(model.admitted()[&waiting], hashes(&start));
}

// --- P16, case C1: listed prefixes ---

proptest! {
    #![proptest_config(config(24, 0x5ec0_0016))]

    /// P16: a listed prefix is the first record's, for good. A reader new
    /// to it takes it only after its heads link back from the listed hash;
    /// another branch at the listed numbers, signed by the same author (the
    /// same up to `k`), is never taken, is no fork, and freezes nothing;
    /// no cut reaches into it, whoever its author (the owner, an agent
    /// never added, a member later lowered or removed). At the end every
    /// replica holds the whole pinned prefix and tells the same tip.
    #[test]
    fn a_listed_prefix_is_taken_only_on_its_pinned_branch(
        (n, k) in (2..60u64).prop_flat_map(|n| (Just(n), 0..n)),
        author in 0..3usize,
        actions in proptest::collection::vec(action(), 0..40),
    ) {
        // The owner, a member (peer 1), or an agent never added.
        let signer = Signer::from_seed(&seed([0, 1, 9][author]));
        let origin = ChainOrigin { author: signer.public(), project: ProjectId([0xee; 16]), salt: [3; 16] };
        let pinned = prior(&signer, origin, n, 0);
        let shared = usize::try_from(k).unwrap();
        let branch = model::branch(&signer, origin, &pinned[..shared], n, 9);
        let pin = pinned.last().unwrap().0.hash();
        let mut net = Net::with(PEERS, PEERS - 1, vec![(origin.chain().0, n, pin.0)]);
        net.keep = false;
        // The owner holds the prefix from before the share; peer 3 holds
        // the other branch (a copy edited after the share), and is added.
        net.peers[0].model.chains.insert(origin.chain(), model::Chain::prior(origin, pinned.clone()));
        net.peers[3].model.chains.insert(origin.chain(), model::Chain::prior(origin, branch));
        let key = net.peers[3].key();
        net.record(Op::Add { key: key.0, editor: true });
        let foreign = foreign_proof();
        let good: BTreeSet<ChangeHash> = pinned.iter().map(|(h, _)| h.hash()).collect();
        for action in &actions {
            // Peer 3, which holds the other branch, stays a member.
            if matches!(action, Action::Remove { peer: 3 } | Action::Role { peer: 3, .. }) {
                continue;
            }
            step(&mut net, action, &foreign)?;
            for p in 0..3 {
                let held = net.peers[p].model.admitted().get(&origin.chain()).cloned().unwrap_or_default();
                prop_assert!(held.iter().all(|h| good.contains(h)), "peer {} took the other branch", p);
            }
        }
        // The other branch's holder is closed by the readers it serves:
        // the step properties are not asked of it.
        finish(&mut net, None)?;
        let whole: Vec<ChangeHash> = pinned.iter().map(|(h, _)| h.hash()).collect();
        for p in 0..3 {
            // Those still members (removed ones are told nothing).
            if !net.peers[0].model.is_member(net.peers[p].key()) {
                continue;
            }
            let tip = net.peers[p].model.tip(origin.chain());
            prop_assert_eq!(tip.map(|t| (t.seq, t.hash, t.fork)), Some((n, pin, 0)), "peer {}", p);
            prop_assert_eq!(&net.peers[p].model.admitted()[&origin.chain()], &whole, "peer {}", p);
        }
    }
}

// --- P17, case D: two starts of one chain ---

proptest! {
    #![proptest_config(config(48, 0x5ec0_0017))]

    /// P17: two different valid starts of one chain in one share, one on
    /// each of two replicas: once linked, every replica that knows the
    /// chain tells the empty tip with fork place 1, holds the proof, and
    /// compares nothing further; a fresh replica learns it from either.
    #[test]
    fn two_starts_end_in_one_empty_tip_everywhere(
        holders in pair(),
        actions in proptest::collection::vec(action(), 0..40),
    ) {
        let mut net = Net::with(PEERS, PEERS, Vec::new());
        net.keep = false;
        // The chain is of a fifth key, a member that never links.
        let author = Signer::from_seed(&seed(9));
        net.record(Op::Add { key: author.public().0, editor: true });
        let grant = net.peers[0].model.membership().0;
        for p in 1..PEERS {
            net.peers[p].model.records = net.peers[0].model.records.clone();
        }
        let origin = ChainOrigin { author: author.public(), project: ProjectId([0x55; 16]), salt: [5; 16] };
        let share = Under { genesis: net.peers[0].model.share(), grant };
        for (peer, blind) in [(holders.0, 1), (holders.1, 2)] {
            let body = ModelBody::Start { share: Some(share), binary: BINARY, blind };
            let head = sign(&author, origin, 1, ChangeHash::ZERO, &body);
            let envelope = seal(head, &body);
            let parsed = Envelope::parse(&envelope).unwrap();
            net.peers[peer].model.admit(author.public(), &parsed);
            net.peers[peer].model.events.clear();
        }
        let foreign = foreign_proof();
        for action in &actions {
            let action = match action {
                Action::Remove { .. } | Action::Role { .. } => continue,
                other => other,
            };
            step(&mut net, action, &foreign)?;
            check_step(&net, &foreign)?;
        }
        finish(&mut net, Some(&foreign))?;
        let chain = origin.chain();
        for p in 0..PEERS {
            let tip = net.peers[p].model.tip(chain).unwrap();
            prop_assert_eq!((tip.seq, tip.hash, tip.fork), (0, ChangeHash::ZERO, 1), "peer {}", p);
            prop_assert_eq!(net.peers[p].model.evidence(chain).unwrap().place(), 1);
        }
    }
}
