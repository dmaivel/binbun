//! Named cases over model peers, each with fixed inputs: the gating cases
//! of the design review (C1, D), the round-3 findings that concern sync,
//! and the special cases the properties name (§10.5).

#![allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::wildcard_enum_match_arm,
    reason = "tests fail loudly"
)]

mod model;

use std::time::Duration;

use binbun_bounded::Bounded;
use binbun_session::journal::{
    ChainId, ChainOrigin, ChangeHash, ChangeId, ForkProof, ProjectId, SignedHead, Signer, Tip,
    Under,
};
use binbun_sync::budget::PER_DECLINED;
use binbun_sync::machine::{Closed, Effect, Local, TIPS_WALK};
use binbun_sync::wire::{EnvelopeBytes, ProofBytes, RecordBytes, SignedHeadBytes};
use binbun_sync::{Storage, Sync};
use model::{BINARY, ModelBody, Net, Op, Record, prior, record_hash, seal, seal_in, seed, sign};

/// Whether `peer` closed a link for `why`.
fn closed(net: &Net, peer: usize, why: Closed) -> bool {
    net.effects[peer]
        .iter()
        .any(|effect| matches!(effect, Effect::Close { why: w, .. } if *w == why))
}

/// Whether `message` was ever delivered from `from` to `to`.
fn delivered(net: &Net, from: usize, to: usize, test: impl Fn(&Sync) -> bool) -> bool {
    net.delivered
        .iter()
        .any(|(f, t, message)| *f == from && *t == to && test(message))
}

/// A tip of `chain` with `seq` and `hash`, unforked.
fn tip(chain: ChainId, project: ProjectId, seq: u64, hash: ChangeHash) -> Tip {
    Tip {
        chain,
        project,
        seq,
        hash,
        fork: 0,
    }
}

/// The tip of a chain with two starts: empty, forked at 1.
fn empty(chain: ChainId, project: ProjectId) -> Tip {
    Tip {
        chain,
        project,
        seq: 0,
        hash: ChangeHash::ZERO,
        fork: 1,
    }
}

/// Whether `message` tells, or serves a change of, `chain`.
fn names(message: &Sync, chain: ChainId) -> bool {
    match message {
        Sync::Tips { tips } => tips.iter().any(|t| t.chain == chain),
        Sync::TipsPage { tips, .. } => tips.iter().any(|t| t.chain == chain),
        Sync::Changes {
            chain: c, changes, ..
        } => *c == chain && !changes.is_empty(),
        Sync::Fresh { changes } => changes
            .iter()
            .any(|e| binbun_sync::Envelope::parse(e).is_some_and(|e| e.chain() == chain)),
        _ => false,
    }
}

/// Two peers linked to Reader with each one's start known to both.
fn readers() -> Net {
    let mut net = Net::new(2);
    net.start(0);
    net.start(1);
    net.link_all();
    net.settle(3);
    assert!(net.reader(0, 1) && net.reader(1, 0));
    net
}

// --- Phases (P14) ---

#[test]
fn two_readers_reach_reader_and_converge() {
    let mut net = readers();
    net.change(0, Vec::new());
    net.change(1, Vec::new());
    net.change(1, Vec::new());
    net.settle(5);
    assert_eq!(net.peers[0].model.admitted(), net.peers[1].model.admitted());
    assert_eq!(net.peers[1].model.tip(net.peers[1].chain()).unwrap().seq, 3);
    assert_eq!(net.peers[0].model.tip(net.peers[1].chain()).unwrap().seq, 3);
}

#[test]
fn nothing_but_bootstraps_messages_passes_before_both_are_ready() {
    let mut net = Net::new(2);
    net.start(0);
    net.start(1);
    net.link_all();
    net.settle(3);
    // Every message delivered before the receiver was Reader was one of
    // Bootstrap's: the readers' first messages are the membership heads.
    let first: Vec<&str> = net
        .delivered
        .iter()
        .take(2)
        .map(|(_, _, message)| message.name())
        .collect();
    assert_eq!(first, ["MembershipHead", "MembershipHead"]);
    let tips_first = net
        .delivered
        .iter()
        .position(|(_, _, message)| !message.in_bootstrap())
        .unwrap();
    let readies = net
        .delivered
        .iter()
        .take(tips_first)
        .filter(|(_, _, message)| matches!(message, Sync::Ready { .. }))
        .count();
    assert_eq!(readies, 2);
}

#[test]
fn a_tip_told_before_readiness_closes_the_link() {
    let mut net = Net::new(2);
    net.start(1);
    net.link(0, 1);
    let chain = net.peers[1].chain();
    let told = net.peers[1].model.tip(chain).unwrap();
    net.deliver_message(
        1,
        0,
        &Sync::Tips {
            tips: Bounded::truncated(vec![told]),
        },
    );
    assert!(closed(&net, 0, Closed::Phase("Tips")));
    assert!(net.peers[0].model.chains.is_empty());
}

#[test]
fn a_summary_before_readiness_closes_the_link() {
    let mut net = Net::new(2);
    net.link(0, 1);
    net.deliver_message(
        1,
        0,
        &Sync::Summary {
            membership: net.peers[1].model.membership(),
            tips: (0, [0; 32]),
        },
    );
    assert!(closed(&net, 0, Closed::Phase("Summary")));
}

#[test]
fn a_joiner_on_another_file_never_reaches_reader_and_is_told_nothing() {
    let mut net = Net::new(3);
    net.start(0);
    net.peers[2].model.binary = [0xff; 32];
    net.link_all();
    net.settle(40);
    assert!(net.reader(0, 1));
    assert!(!net.reader(0, 2) && !net.reader(2, 0));
    assert!(!delivered(&net, 0, 2, |m| !m.in_bootstrap()));
    assert!(!delivered(&net, 2, 0, |m| matches!(m, Sync::Ready { .. })));
    // The file arrives (the session opens on the right binary): Reader.
    net.peers[2].model.binary = BINARY;
    net.local(2, Local::Readiness);
    net.settle(5);
    assert!(net.reader(0, 2) && net.reader(2, 0));
    assert!(
        net.peers[2]
            .model
            .chains
            .contains_key(&net.peers[0].chain())
    );
}

#[test]
fn a_joiner_takes_the_membership_chain_before_it_is_ready() {
    // Peer 2 starts with the first record only: it is not named a member
    // in its own chain, so it serves nothing and sends no Ready until it
    // has taken the owner's records.
    let mut net = Net::new(3);
    net.peers[2].model.records.truncate(1);
    net.start(0);
    net.link(0, 2);
    net.settle(5);
    assert!(net.reader(0, 2));
    assert_eq!(
        net.peers[2].model.membership(),
        net.peers[0].model.membership()
    );
    assert!(
        net.peers[2]
            .model
            .chains
            .contains_key(&net.peers[0].chain())
    );
}

#[test]
fn a_removed_key_is_revoked_served_no_record_and_given_nothing_made_before() {
    let mut net = readers();
    net.change(0, Vec::new());
    // A Fresh and Tips for peer 1 are made, not yet written.
    let pending: Vec<_> = net
        .flight
        .get(&(0, 1))
        .map(|queue| queue.iter().cloned().collect())
        .unwrap_or_default();
    let jobs: Vec<_> = net.peers[0].jobs.iter().copied().collect();
    assert!(!pending.is_empty() || !jobs.is_empty());
    let key = net.peers[1].key();
    let cuts = net.cuts(key);
    net.record(Op::Remove { key: key.0, cuts });
    // The link was revoked: nothing made for its old generation passes.
    assert!(closed(&net, 0, Closed::Revoked));
    for send in &pending {
        assert!(!net.peers[0].machine.is_current(send.link, send.generation));
    }
    for job in &jobs {
        let p = &mut net.peers[0];
        assert!(p.machine.serve(&mut p.model, &mut p.budget, job).is_none());
    }
    // Linked again, it is asked for nothing and served no record.
    net.link(0, 1);
    let link = net.link_id(0, 1);
    let mine = net.peers[1].model.membership();
    net.deliver_message(
        1,
        0,
        &Sync::RecordsAsk {
            id: 0,
            after: mine.0 - 1,
            at: net.peers[1].model.record_hash(mine.0 - 1).unwrap(),
        },
    );
    assert!(closed(&net, 0, Closed::NotServed));
    assert!(link.is_some());
    assert!(net.peers[0].jobs.iter().all(|job| Some(job.link) != link));
}

/// The owner's records after `records` doing `ops`, in order, as signed.
fn following(records: &[Vec<u8>], ops: Vec<Op>) -> Vec<Vec<u8>> {
    let mut all = records.to_vec();
    for op in ops {
        let record = Record {
            seq: all.len() as u64 + 1,
            prev: record_hash(all.last().unwrap()),
            op,
        };
        all.push(record.bytes());
    }
    all.split_off(records.len())
}

#[test]
fn a_page_whose_third_record_fails_keeps_the_first_two_and_revokes_whom_they_removed() {
    let mut net = Net::new(3);
    net.link_all();
    net.settle(3);
    assert!(net.reader(1, 2));
    let held = net.peers[1].model.records.len();
    let removed = net.peers[2].key().0;
    let mut page = following(
        &net.peers[0].model.records,
        vec![
            Op::Remove {
                key: removed,
                cuts: Vec::new(),
            },
            Op::Add {
                key: [9; 32],
                editor: true,
            },
        ],
    );
    // A third that does not follow them.
    page.push(
        Record {
            seq: held as u64 + 4,
            prev: [0; 32],
            op: Op::Add {
                key: [8; 32],
                editor: true,
            },
        }
        .bytes(),
    );
    let page = page
        .into_iter()
        .map(|record| RecordBytes::try_from(record).unwrap())
        .collect();
    net.deliver_message(
        0,
        1,
        &Sync::Records {
            id: None,
            records: Bounded::truncated(page),
            more: false,
        },
    );
    // The two taken stay taken, and the link to the key removed is
    // revoked: the failure after them undoes neither.
    assert_eq!(net.peers[1].model.records.len(), held + 2);
    assert!(!net.peers[1].model.is_member(net.peers[2].key()));
    assert!(net.closes.contains(&(1, Closed::Revoked)));
    assert!(net.link_id(1, 2).is_none());
}

#[test]
fn readiness_revokes_a_readers_link_whose_other_side_a_record_taken_elsewhere_removed() {
    let mut net = readers();
    // A removal taken by peer 0 outside its machine (a recovery's, say);
    // only readiness is told.
    let key = net.peers[1].key().0;
    let model = &mut net.peers[0].model;
    let after = model.records.len() as u64;
    let removal = following(
        &model.records,
        vec![Op::Remove {
            key,
            cuts: Vec::new(),
        }],
    );
    model.take_records(after, &[&removal[0][..]]).1.unwrap();
    assert!(net.reader(0, 1));
    net.local(0, Local::Readiness);
    assert!(closed(&net, 0, Closed::Revoked));
    assert!(net.link_id(0, 1).is_none());
}

#[test]
fn a_page_of_changes_built_after_its_askers_removal_is_none() {
    let mut net = readers();
    net.change(0, Vec::new());
    net.settle(2);
    let chain = net.peers[0].chain();
    net.deliver_message(
        1,
        0,
        &Sync::Want {
            id: 900,
            chain,
            after: 0,
            at: ChangeHash::ZERO,
            most: 8,
        },
    );
    let job = net.peers[0].jobs.pop_back().unwrap();
    // Removed before the page is built, the link not yet told.
    let key = net.peers[1].key().0;
    let model = &mut net.peers[0].model;
    let after = model.records.len() as u64;
    let removal = following(
        &model.records,
        vec![Op::Remove {
            key,
            cuts: Vec::new(),
        }],
    );
    model.take_records(after, &[&removal[0][..]]).1.unwrap();
    let p = &mut net.peers[0];
    assert!(p.machine.serve(&mut p.model, &mut p.budget, &job).is_none());
}

#[test]
fn a_records_divergence_answering_another_request_shows_nothing_and_closes_the_link() {
    let mut net = Net::new(2);
    net.start(0);
    net.start(1);
    net.link_all();
    // Peer 0's first request once Reader: its tips.
    let id = loop {
        let asked = net.flight.get(&(0, 1)).and_then(|queue| {
            queue.iter().find_map(|send| match send.message {
                Sync::TipsAsk { id, .. } => Some(id),
                _ => None,
            })
        });
        if let Some(id) = asked {
            break id;
        }
        assert!(net.deliver(0, 1) || net.deliver(1, 0) || net.serve(0) || net.serve(1));
    };
    let record = RecordBytes::try_from(net.peers[1].model.records[0].clone()).unwrap();
    net.deliver_message(1, 0, &Sync::RecordsDiverged { id, record });
    assert!(
        net.effects[0]
            .iter()
            .all(|effect| !matches!(effect, Effect::Diverged { .. }))
    );
    assert!(
        net.closes
            .iter()
            .any(|(peer, why)| { *peer == 0 && matches!(why, Closed::Reply(_)) })
    );
}

// --- Acknowledgement (P12) ---

#[test]
fn membership_is_acknowledged_by_the_other_sides_statement_of_its_head_and_nothing_else() {
    let mut net = Net::new(3);
    net.link(0, 1);
    // Within 5 s of link-up (before any Summary), a flush sees the
    // membership acknowledged: by the other side's head and Ready.
    for _ in 0..5 {
        net.drain(64);
        net.tick(Duration::from_secs(1));
    }
    assert!(net.reader(0, 1));
    assert!(!delivered(&net, 1, 0, |m| matches!(
        m,
        Sync::Summary { .. }
    )));
    let link = net.link_id(0, 1).unwrap();
    let head = net.peers[0].model.membership().0;
    let report = net.peers[0].machine.report(link).unwrap();
    assert!(report.has_membership(&net.peers[0].model, head));
    // A record taken later: not acknowledged by sending it, nor by the
    // other side being asked for it; only by its head that follows.
    let key = net.peers[2].key();
    let cuts = net.cuts(key);
    net.record(Op::Role {
        key: key.0,
        editor: false,
        cuts,
    });
    let head = net.peers[0].model.membership().0;
    while net.deliver(0, 1) {}
    let report = net.peers[0].machine.report(link).unwrap();
    assert!(!report.has_membership(&net.peers[0].model, head));
    net.drain(64);
    assert_eq!(net.peers[1].model.membership().0, head);
    let report = net.peers[0].machine.report(link).unwrap();
    assert!(report.has_membership(&net.peers[0].model, head));
}

#[test]
fn a_ready_naming_a_record_the_receiver_lacks_closes_the_link() {
    // Ready is sent only once the other side has told this side's head,
    // so it always names a record its receiver holds.
    let mut net = Net::new(2);
    net.link(0, 1);
    let genesis = net.peers[0].model.genesis();
    net.deliver_message(
        1,
        0,
        &Sync::Ready {
            genesis,
            membership: (9, [9; 32]),
        },
    );
    assert!(closed(&net, 0, Closed::Membership));
}

#[test]
fn a_change_pushed_but_not_applied_is_never_acknowledged() {
    let mut net = readers();
    // Peer 1 has not the key of epoch 0: it stops the change.
    net.peers[1].model.keys.clear();
    let id = net.change(0, Vec::new()).unwrap();
    for second in 0..90 {
        net.drain(64);
        let report = net.peers[0]
            .machine
            .report(net.link_id(0, 1).unwrap())
            .unwrap();
        assert!(
            !report.has(&net.peers[0].model, id.chain, id.seq),
            "at {second} s"
        );
        assert!(
            report.has(&net.peers[0].model, id.chain, id.seq - 1),
            "at {second} s"
        );
        net.tick(Duration::from_secs(1));
    }
    assert!(delivered(&net, 0, 1, |m| matches!(m, Sync::Fresh { .. })));
    // The key arrives: the stop wakes, the change is taken and told.
    net.peers[1].model.keys.insert(0);
    net.local(1, Local::Key(0));
    net.settle(10);
    let report = net.peers[0]
        .machine
        .report(net.link_id(0, 1).unwrap())
        .unwrap();
    assert!(report.has(&net.peers[0].model, id.chain, id.seq));
}

#[test]
fn a_membership_on_another_branch_is_never_acknowledged() {
    let mut net = Net::new(2);
    // Peer 1 holds another record 2.
    let mut other = Record {
        seq: 2,
        prev: record_hash(&net.peers[1].model.records[0]),
        op: Op::Add {
            key: net.peers[1].key().0,
            editor: false,
        },
    };
    net.peers[1].model.records[1] = other.bytes();
    other.seq = 2;
    net.link_all();
    net.settle(5);
    assert!(closed(&net, 0, Closed::Membership) || closed(&net, 1, Closed::Membership));
    let report = net.effects[0].iter().find_map(|effect| match effect {
        Effect::Unlinked { report, .. } => Some(report.clone()),
        _ => None,
    });
    let report = report.unwrap_or_default();
    assert!(!report.has_membership(&net.peers[0].model, 2));
}

// --- Scope (P13) ---

#[test]
fn a_valid_proof_of_a_chain_not_known_here_leaves_no_state() {
    let mut net = Net::new(3);
    net.start(0);
    net.start(2);
    // Peer 2's chain forks; peers 0 and 1 have never seen it.
    let signer = Signer::from_seed(&seed(2));
    let origin = net.peers[2].origin;
    let a = prior(&signer, origin, 1, 1).remove(0).0;
    let b = prior(&signer, origin, 1, 2).remove(0).0;
    let proof = ForkProof::new(origin, a, b).unwrap();
    net.link(0, 1);
    net.settle(3);
    let before = net.peers[0].model.admitted();
    net.deliver_message(
        1,
        0,
        &Sync::Fork {
            id: None,
            chain: origin.chain(),
            proof: Some(ProofBytes::try_from(&*proof.bytes()).unwrap()),
        },
    );
    assert!(net.reader(0, 1));
    assert_eq!(net.peers[0].model.admitted(), before);
    assert!(net.peers[0].model.evidence(origin.chain()).is_none());
}

#[test]
fn a_proof_of_another_chain_than_its_message_closes_the_link() {
    let mut net = readers();
    let signer = Signer::from_seed(&seed(1));
    let origin = net.peers[1].origin;
    let a = prior(&signer, origin, 1, 1).remove(0).0;
    let b = prior(&signer, origin, 1, 2).remove(0).0;
    let proof = ForkProof::new(origin, a, b).unwrap();
    net.deliver_message(
        1,
        0,
        &Sync::Fork {
            id: None,
            chain: net.peers[0].chain(),
            proof: Some(ProofBytes::try_from(&*proof.bytes()).unwrap()),
        },
    );
    assert!(closed(&net, 0, Closed::Reply("a proof of another chain")));
    assert!(net.peers[0].model.evidence(origin.chain()).is_none());
}

#[test]
fn a_chain_bound_to_another_share_or_binary_is_never_applied_told_or_served() {
    for case in 0..3 {
        let mut net = Net::new(3);
        let grant = net.peers[1].grant.unwrap();
        let share = Under {
            genesis: net.peers[0].model.share(),
            grant,
        };
        // Another share; no share and not listed; another binary.
        let (share, binary) = match case {
            0 => (
                Some(Under {
                    genesis: [0x11; 32],
                    grant,
                }),
                BINARY,
            ),
            1 => (None, BINARY),
            _ => (Some(share), [0x22; 32]),
        };
        let body = ModelBody::Start {
            share,
            binary,
            blind: 0,
        };
        // Peer 1 holds a start bound elsewhere in its own log (as a
        // private log would); nothing of it reaches peer 0 or 2.
        let p = &net.peers[1];
        let head = sign(&p.signer, p.origin, 1, ChangeHash::ZERO, &body);
        let chain = p.chain();
        let origin = p.origin;
        net.peers[1].model.chains.insert(
            chain,
            model::Chain::prior(origin, vec![(head, seal(head, &body))]),
        );
        net.link_all();
        net.settle(40);
        assert!(net.peers[0].model.tip(chain).is_none(), "{body:?}");
        assert!(net.peers[2].model.tip(chain).is_none(), "{body:?}");
        assert!(!delivered(&net, 0, 2, |m| names(m, chain)));
    }
}

#[test]
fn a_tips_origin_its_start_proves_false_closes_the_link() {
    let mut net = readers();
    let chain = net.peers[1].chain();
    let held = net.peers[0].model.tip(chain).unwrap();
    let lie = Tip {
        project: ProjectId([0x99; 16]),
        ..held
    };
    net.deliver_message(
        1,
        0,
        &Sync::Tips {
            tips: Bounded::truncated(vec![lie]),
        },
    );
    assert!(closed(&net, 0, Closed::Claim));
}

// --- Forks (P3, P7) ---

/// `n` peers: 0 and 1 each hold another change 2 of peer 2's chain.
fn forked(n: usize) -> (Net, ChainId) {
    let mut net = Net::new(n);
    net.start(2);
    net.link(0, 2);
    net.link(1, 2);
    net.settle(3);
    net.unlink(0, 2);
    net.unlink(1, 2);
    net.fork_into(2, 0).unwrap();
    net.change(2, Vec::new()).unwrap();
    net.link(1, 2);
    net.settle(3);
    net.unlink(1, 2);
    let chain = net.peers[2].chain();
    assert_eq!(net.peers[0].model.tip(chain).unwrap().seq, 2);
    assert_eq!(net.peers[1].model.tip(chain).unwrap().seq, 2);
    assert_ne!(
        net.peers[0].model.tip(chain).unwrap().hash,
        net.peers[1].model.tip(chain).unwrap().hash
    );
    (net, chain)
}

#[test]
fn two_peers_holding_another_last_change_of_one_chain_both_freeze_it_once_linked() {
    let (mut net, chain) = forked(3);
    net.link(0, 1);
    net.settle(5);
    for peer in [0, 1] {
        let tip = net.peers[peer].model.tip(chain).unwrap();
        assert_eq!((tip.seq, tip.fork), (1, 2), "peer {peer}");
        assert_eq!(net.peers[peer].model.evidence(chain).unwrap().place(), 2);
    }
    // The author, linked again, learns the proof too.
    net.link(0, 2);
    net.settle(5);
    assert_eq!(net.peers[2].model.tip(chain).unwrap().fork, 2);
}

#[test]
fn a_proof_survives_a_restart_and_is_learnt_from_the_restarted_peer() {
    let (mut net, chain) = forked(4);
    net.link(0, 1);
    net.settle(5);
    net.unlink(0, 1);
    net.restart(0);
    assert_eq!(net.peers[0].model.evidence(chain).unwrap().place(), 2);
    // A fresh replica linked only to the restarted peer learns the chain
    // and its place.
    net.link(0, 3);
    net.settle(5);
    let tip = net.peers[3].model.tip(chain).unwrap();
    assert_eq!((tip.seq, tip.fork), (1, 2));
    assert_eq!(net.peers[3].model.evidence(chain).unwrap().place(), 2);
}

#[test]
fn a_fork_at_the_tip_found_by_one_bisection_round_is_the_final_singleton() {
    // Peer 0 and peer 1 hold chains of 40 changes that differ from 37.
    let mut net = Net::new(3);
    net.start(2);
    for _ in 0..35 {
        net.change(2, Vec::new());
    }
    net.link(0, 2);
    net.link(1, 2);
    net.settle(5);
    net.unlink(0, 2);
    net.unlink(1, 2);
    net.fork_into(2, 0).unwrap();
    for _ in 0..3 {
        net.change(2, Vec::new());
    }
    net.link(1, 2);
    net.settle(5);
    net.unlink(1, 2);
    let chain = net.peers[2].chain();
    // Peer 0 is at 37 on one branch; peer 1 at 39 on the other.
    net.link(0, 1);
    net.settle(10);
    for peer in [0, 1] {
        let tip = net.peers[peer].model.tip(chain).unwrap();
        assert_eq!((tip.seq, tip.fork), (36, 37), "peer {peer}");
    }
}

// --- Two starts of one chain (P17, case D) ---

/// Peer 2's chain with two different starts, one held by peer 0, the
/// other by peer 1; and the start each holds.
fn two_starts() -> (Net, ChainId) {
    let mut net = Net::new(3);
    let signer = Signer::from_seed(&seed(2));
    let origin = net.peers[2].origin;
    let share = Under {
        genesis: net.peers[0].model.share(),
        grant: net.peers[2].grant.unwrap(),
    };
    for (peer, blind) in [(0, 1), (1, 2)] {
        let body = ModelBody::Start {
            share: Some(share),
            binary: BINARY,
            blind,
        };
        let head = sign(&signer, origin, 1, ChangeHash::ZERO, &body);
        let envelope = seal(head, &body);
        let parsed = binbun_sync::Envelope::parse(&envelope).unwrap();
        let key = net.peers[2].key();
        net.peers[peer].model.admit(key, &parsed);
        net.peers[peer].model.events.clear();
    }
    (net, origin.chain())
}

#[test]
fn two_starts_give_the_empty_tip_with_fork_one_everywhere() {
    let (mut net, chain) = two_starts();
    net.link(0, 1);
    net.settle(5);
    let empty = empty(chain, net.peers[2].origin.project);
    assert_eq!(net.peers[0].model.tip(chain), Some(empty));
    assert_eq!(net.peers[1].model.tip(chain), Some(empty));
    // Each still serves the start it holds, and they tell the same tip.
    assert_ne!(
        net.peers[0].model.head_at(chain, 1).unwrap().hash(),
        net.peers[1].model.head_at(chain, 1).unwrap().hash()
    );
    assert_eq!(net.told(0, 1, chain).unwrap().tip, empty);
    assert_eq!(net.told(1, 0, chain).unwrap().tip, empty);
}

#[test]
fn a_fresh_replica_learns_a_chain_known_only_by_its_start_and_its_place() {
    for holder in [0, 1] {
        let (mut net, chain) = two_starts();
        net.link(0, 1);
        net.settle(5);
        net.unlink(0, 1);
        // Peer 2 (the author, fresh: it holds nothing) links to one holder.
        net.link(2, holder);
        net.settle(5);
        let empty = empty(chain, net.peers[2].origin.project);
        assert_eq!(
            net.peers[2].model.tip(chain),
            Some(empty),
            "holder {holder}"
        );
        assert_eq!(net.peers[2].model.evidence(chain).unwrap().place(), 1);
    }
}

// --- Listed prefixes from before the share (P16, case C1) ---

/// A share whose first record lists peer 0's chain of `n` changes from
/// before the share, held by `holders`; the chain and its pin.
fn listed(n: u64, holders: &[usize]) -> (Net, ChainOrigin, Vec<ChangeHash>) {
    let signer = Signer::from_seed(&seed(0));
    let origin = ChainOrigin {
        author: signer.public(),
        project: ProjectId([0xee; 16]),
        salt: [3; 16],
    };
    let changes = prior(&signer, origin, n, 0);
    let pin = changes.last().unwrap().0.hash();
    let mut net = Net::with(3, 3, vec![(origin.chain().0, n, pin.0)]);
    net.prior_chain(0, n, 3, holders);
    let hashes = changes.iter().map(|(head, _)| head.hash()).collect();
    (net, origin, hashes)
}

#[test]
fn a_new_reader_takes_a_listed_prefix_of_several_runs_after_its_heads_link_back() {
    let n = 5000;
    let (mut net, origin, hashes) = listed(n, &[0]);
    let chain = origin.chain();
    net.link(0, 1);
    net.settle(30);
    let tip = net.peers[1].model.tip(chain).unwrap();
    assert_eq!(
        (tip.seq, tip.hash),
        (n, hashes[usize::try_from(n - 1).unwrap()])
    );
    // Two runs were asked (4,096 then 904), before any change.
    let runs = net
        .delivered
        .iter()
        .filter(|(f, t, m)| *f == 0 && *t == 1 && matches!(m, Sync::HeadsRun { .. }))
        .count();
    assert_eq!(runs, 2);
    let first_want = net
        .delivered
        .iter()
        .position(|(_, _, m)| matches!(m, Sync::Want { chain: c, .. } if *c == chain))
        .unwrap();
    let last_run = net
        .delivered
        .iter()
        .rposition(|(_, _, m)| matches!(m, Sync::HeadsRun { .. }))
        .unwrap();
    assert!(last_run < first_want);
    // The walk's file is gone once the pull reached the pin.
    assert!(net.peers[1].model.walk(chain).is_none());
}

#[test]
fn another_branch_at_the_listed_numbers_is_never_taken_and_its_server_is_closed() {
    let n = 30;
    let (mut net, origin, _) = listed(n, &[0]);
    let chain = origin.chain();
    // Peer 2 holds another branch of the same chain, signed by the same
    // author, at the same numbers (a private copy edited after the share).
    let signer = Signer::from_seed(&seed(0));
    let other = prior(&signer, origin, n, 9);
    net.peers[2]
        .model
        .chains
        .insert(chain, model::Chain::prior(origin, other));
    net.link(1, 2);
    net.settle(40);
    assert!(closed(&net, 1, Closed::Reply("a run that does not link")));
    assert!(net.peers[1].model.tip(chain).is_none());
    assert!(!net.peers[1].model.admitted().contains_key(&chain));
}

#[test]
fn a_listed_prefix_whose_end_is_withheld_is_left_untouched() {
    let n = 30;
    let (mut net, origin, _) = listed(n, &[]);
    let chain = origin.chain();
    // Peer 2 holds the prefix only up to one short of the pin.
    let signer = Signer::from_seed(&seed(0));
    let mut short = prior(&signer, origin, n, 0);
    short.pop();
    net.peers[2]
        .model
        .chains
        .insert(chain, model::Chain::prior(origin, short));
    net.link(1, 2);
    net.settle(60);
    assert!(net.reader(1, 2));
    assert!(net.peers[1].model.tip(chain).is_none());
    assert!(net.peers[1].model.walk(chain).is_none());
}

#[test]
fn a_walk_the_storage_refuses_ends_without_walking_again_or_taking_anything() {
    let n = 5000;
    let (mut net, origin, _) = listed(n, &[0]);
    let chain = origin.chain();
    // Peer 1's storage holds one run of a walk at most: the second is
    // refused, the walk dropped.
    net.peers[1].model.walk_ceiling = Some(4096);
    net.link(0, 1);
    net.settle(60);
    assert!(net.reader(0, 1));
    // Neither walked again at once nor pulled.
    let asks = net
        .delivered
        .iter()
        .filter(|(f, t, m)| *f == 1 && *t == 0 && matches!(m, Sync::HeadsAsk { .. }))
        .count();
    assert_eq!(asks, 2);
    assert!(net.peers[1].model.walk(chain).is_none());
    assert!(net.peers[1].model.tip(chain).is_none());
    assert!(!delivered(&net, 1, 0, |m| matches!(m, Sync::Want { .. })));
}

#[test]
fn a_reader_mid_walk_neither_tells_nor_serves_the_prefix() {
    let n = 5000;
    let (mut net, origin, _) = listed(n, &[0]);
    let chain = origin.chain();
    net.link(0, 1);
    // Deliver until peer 1 has walked one run, not yet two.
    for _ in 0..200 {
        net.drain(1);
        net.tick(Duration::from_millis(100));
        if net.peers[1].model.walk(chain).is_some() {
            break;
        }
    }
    let walk = net.peers[1].model.walk(chain).unwrap();
    assert!(walk.lowest > 1);
    assert!(net.peers[1].model.tip(chain).is_none());
    // Peer 0 goes; peer 2 links to peer 1, which tells and serves it
    // nothing of the chain, asked or not.
    net.unlink(0, 1);
    net.link(1, 2);
    net.settle(5);
    for id in [900, 901] {
        let after = u64::from(id - 900);
        net.deliver_message(
            2,
            1,
            &Sync::Want {
                id,
                chain,
                after,
                at: ChangeHash::ZERO,
                most: 1,
            },
        );
    }
    net.settle(1);
    assert!(!delivered(&net, 1, 2, |m| names(m, chain)));
    assert!(net.reader(1, 2));
}

// --- Stops, held changes and cuts (P2, P5, P19) ---

#[test]
fn a_listed_prefix_is_never_forked_and_its_proof_is_dropped() {
    let n = 6;
    let (mut net, origin, hashes) = listed(n, &[0, 1]);
    let chain = origin.chain();
    net.link(0, 1);
    net.settle(3);
    // Another head at a listed number, signed by its author: not of the
    // share, no fork, nothing frozen.
    let signer = Signer::from_seed(&seed(0));
    let pinned = prior(&signer, origin, n, 0);
    let other = model::branch(&signer, origin, &pinned[..3], n, 9);
    let envelope = &other[3].1;
    let fresh = Sync::Fresh {
        changes: Bounded::truncated(vec![EnvelopeBytes::try_from(envelope.clone()).unwrap()]),
    };
    net.deliver_message(0, 1, &fresh);
    // A valid proof of the two heads at 4.
    let proof = ForkProof::new(origin, pinned[3].0, other[3].0).unwrap();
    net.deliver_message(
        0,
        1,
        &Sync::Fork {
            id: None,
            chain,
            proof: Some(ProofBytes::try_from(&*proof.bytes()).unwrap()),
        },
    );
    net.settle(3);
    assert!(net.reader(0, 1));
    for peer in [0, 1] {
        let tip = net.peers[peer].model.tip(chain).unwrap();
        assert_eq!(
            (tip.seq, tip.hash, tip.fork),
            (n, hashes[5], 0),
            "peer {peer}"
        );
        assert!(net.peers[peer].model.evidence(chain).is_none());
    }
}

#[test]
fn after_its_walk_a_listed_prefix_takes_only_changes_on_the_walked_branch() {
    let n = 30;
    let (mut net, origin, hashes) = listed(n, &[]);
    let chain = origin.chain();
    // Peer 1 walked the pinned branch earlier (from a link now gone).
    net.peers[1].model.walks.insert(
        chain,
        (
            1,
            ChangeHash::ZERO,
            (1..=n).zip(hashes.iter().copied()).collect(),
        ),
    );
    // Peer 2 holds another branch: the same up to 10, then its own.
    let signer = Signer::from_seed(&seed(0));
    let pinned = prior(&signer, origin, n, 0);
    let other = model::branch(&signer, origin, &pinned[..10], n, 9);
    net.peers[2]
        .model
        .chains
        .insert(chain, model::Chain::prior(origin, other));
    net.link(1, 2);
    net.settle(10);
    let tip = net.peers[1].model.tip(chain).unwrap();
    assert_eq!((tip.seq, tip.hash), (10, hashes[9]));
    let held = &net.peers[1].model.admitted()[&chain];
    assert!(held.iter().all(|hash| hashes.contains(hash)));
}

/// Three peers linked in a line 0 – 1 – 2, each chain started; peers 1
/// and 2 hold the key of epoch 1, peer 0 does not. Peer 2 makes a change
/// in epoch 1 (`named`); peer 1 a change naming it (`waiting`). Peer 0
/// cannot open the first: it declines it on its link, and nothing stops;
/// it holds the second for the first, stopped.
fn waiting_behind_a_sealing() -> (Net, ChangeId, ChangeId) {
    let mut net = Net::new(3);
    for p in 0..3 {
        net.start(p);
    }
    net.peers[1].model.keys.insert(1);
    net.peers[2].model.keys.insert(1);
    net.link(0, 1);
    net.link(1, 2);
    net.settle(3);
    let named = net.change_in(2, Vec::new(), 1).unwrap();
    net.settle(3);
    let waiting = net.change(1, vec![named]).unwrap();
    net.settle(3);
    assert!(net.peers[1].model.holds(waiting));
    assert!(!net.peers[0].model.holds(named));
    assert!(!net.peers[0].model.holds(waiting));
    assert_eq!(net.peers[0].machine.stop(named.chain), None);
    assert_eq!(
        net.peers[0].machine.stop(waiting.chain),
        Some((waiting.seq, stop_hash(&net, 1, waiting)))
    );
    (net, named, waiting)
}

/// The hash of `change` as `peer` holds it.
fn stop_hash(net: &Net, peer: usize, change: ChangeId) -> ChangeHash {
    net.peers[peer]
        .model
        .head_at(change.chain, change.seq)
        .unwrap()
        .hash()
}

#[test]
fn a_held_change_released_after_a_cut_of_its_author_is_never_admitted() {
    // Round 3: a held change crossing a signed removal.
    let (mut net, named, held) = waiting_behind_a_sealing();
    assert!(net.peers[0].model.held.contains_key(&named));
    // The owner removes peer 1, cutting after its start.
    let key = net.peers[1].key();
    let cuts = net.cuts(key);
    net.record(Op::Remove { key: key.0, cuts });
    net.settle(3);
    // The key arrives: peer 2's change is asked for again and taken, the
    // held one released and refused.
    net.peers[0].model.keys.insert(1);
    net.local(0, Local::Key(1));
    net.link(0, 2);
    net.settle(10);
    assert!(net.peers[0].model.holds(named));
    assert!(!net.peers[0].model.holds(held));
    assert!(!net.peers[0].model.admitted_log.contains(&held));
}

#[test]
fn a_stop_wakes_by_its_index_when_what_it_waits_for_is_applied() {
    let (mut net, named, waiting) = waiting_behind_a_sealing();
    // Peer 0's held cache is dropped: the stop still names what is
    // awaited, and the change is pulled again when it is applied.
    net.peers[0].model.drop_held();
    net.peers[0].model.keys.insert(1);
    net.local(0, Local::Key(1));
    net.settle(10);
    assert!(net.peers[0].model.holds(named));
    assert!(net.peers[0].model.holds(waiting));
    assert!(net.peers[0].machine.stop(waiting.chain).is_none());
}

#[test]
fn neither_a_declined_change_nor_a_stop_is_asked_again_until_its_cause_passes() {
    let (mut net, named, waiting) = waiting_behind_a_sealing();
    net.peers[0].model.keys.insert(1);
    // The key is here, but nothing said so: the declined change is not
    // asked for again, and the stop waits for it.
    net.settle(60);
    assert!(!net.peers[0].model.holds(named));
    assert!(!net.peers[0].model.holds(waiting));
}

#[test]
fn a_change_declined_on_a_link_is_asked_again_when_its_build_changes() {
    let (mut net, named, waiting) = waiting_behind_a_sealing();
    net.peers[0].model.keys.insert(1);
    let remote = net.peers[1].key();
    net.local(0, Local::Build(remote));
    net.settle(10);
    assert!(net.peers[0].model.holds(named));
    assert!(net.peers[0].model.holds(waiting));
}

#[test]
fn a_change_declined_on_a_link_is_asked_again_when_a_chain_freezes() {
    let (mut net, named, _) = waiting_behind_a_sealing();
    net.peers[0].model.keys.insert(1);
    // A malformed change of peer 0's own chain freezes it there.
    let body = ModelBody::Edit {
        deps: Vec::new(),
        never: true,
        blind: 0,
    };
    assert!(matches!(
        net.give(0, 0, &body),
        binbun_sync::Admission::Never { .. }
    ));
    net.settle(10);
    assert!(net.peers[0].model.holds(named));
}

#[test]
fn two_different_stops_in_succession_on_one_chain_are_each_compared() {
    let mut net = Net::new(3);
    for p in 0..3 {
        net.start(p);
    }
    net.peers[1].model.keys.insert(1);
    net.peers[2].model.keys.insert(1);
    net.link_all();
    net.settle(3);
    // Peer 0 cannot open peer 1's change of epoch 1: peer 2's change 2,
    // which names it, stops there.
    let dep = net.change_in(1, Vec::new(), 1).unwrap();
    net.settle(3);
    net.change(2, vec![dep]).unwrap();
    net.settle(3);
    let chain = net.peers[2].chain();
    let first = net.peers[0].machine.stop(chain).unwrap();
    let probes = |net: &Net, seq: u64| {
        net.delivered
            .iter()
            .filter(|(f, t, m)| {
                *f == 0
                    && *t == 1
                    && matches!(m, Sync::Probe { chain: c, seqs, .. } if *c == chain && seqs.first() == Some(&seq))
            })
            .count()
    };
    assert_eq!(probes(&net, first.0), 1);
    // The key arrives, both changes are taken; peer 2's next change stops
    // too, at another head.
    net.peers[0].model.keys.insert(1);
    net.local(0, Local::Key(1));
    net.settle(3);
    assert!(net.peers[0].machine.stop(chain).is_none());
    net.peers[0].model.keys.remove(&1);
    let dep = net.change_in(1, Vec::new(), 1).unwrap();
    net.settle(3);
    net.change(2, vec![dep]).unwrap();
    net.settle(3);
    let second = net.peers[0].machine.stop(chain).unwrap();
    assert_ne!(first, second);
    assert_eq!(probes(&net, second.0), 1);
}

#[test]
fn a_change_that_stops_mid_page_ends_the_page_and_nothing_else() {
    let mut net = Net::new(3);
    for p in 0..3 {
        net.start(p);
    }
    net.peers[1].model.keys.insert(1);
    net.peers[2].model.keys.insert(1);
    net.link(1, 2);
    net.settle(3);
    // Peer 1 makes 4 changes; the third names a change of peer 2 that
    // peer 0 cannot open.
    let named = net.change_in(2, Vec::new(), 1).unwrap();
    net.settle(2);
    net.change(1, Vec::new());
    net.change(1, Vec::new());
    net.change(1, vec![named]);
    net.change(1, Vec::new());
    net.unlink(1, 2);
    net.link(0, 1);
    net.settle(5);
    let chain = net.peers[1].chain();
    assert_eq!(net.peers[0].model.tip(chain).unwrap().seq, 3);
    assert_eq!(net.peers[0].machine.stop(chain).unwrap().0, 4);
    // Peer 2's own chain went on regardless.
    assert!(net.reader(0, 1));
}

// --- Sealing and stops (P23) ---

/// The envelope `peer` holds of `change`.
fn envelope_of(net: &Net, peer: usize, change: ChangeId) -> Vec<u8> {
    let index = usize::try_from(change.seq - 1).unwrap();
    net.peers[peer].model.chains[&change.chain].changes[index]
        .1
        .clone()
}

/// A `Fresh` of `envelope`.
fn fresh(envelope: Vec<u8>) -> Sync {
    Sync::Fresh {
        changes: Bounded::truncated(vec![EnvelopeBytes::try_from(envelope).unwrap()]),
    }
}

#[test]
fn a_genuine_head_sealed_under_an_epoch_that_does_not_exist_stops_nothing() {
    let mut net = Net::new(3);
    for p in 0..3 {
        net.start(p);
    }
    net.link_all();
    net.settle(3);
    net.unlink(0, 2);
    net.unlink(1, 2);
    // Peer 2's next change, which only peer 2 holds; peer 1 seals its
    // genuine head again under epoch 99, which does not exist.
    let id = net.change(2, Vec::new()).unwrap();
    let head = net.peers[2].model.head_at(id.chain, id.seq).unwrap();
    let body = ModelBody::Edit {
        deps: Vec::new(),
        never: false,
        blind: 0,
    };
    net.deliver_message(1, 0, &fresh(seal_in(head, &body, 99)));
    // Declined on that link: no stop, nothing taken.
    assert_eq!(net.peers[0].machine.stop(id.chain), None);
    assert!(!net.peers[0].model.holds(id));
    // The same head from another link is pulled and taken, with nothing
    // woken in between.
    net.link(0, 2);
    net.settle(5);
    assert!(net.peers[0].model.holds(id));
    assert!(net.reader(0, 1));
}

#[test]
fn a_chain_declined_on_a_link_is_charged_to_it_until_asked_again() {
    let mut net = Net::new(3);
    for p in 0..3 {
        net.start(p);
    }
    net.link_all();
    net.settle(3);
    net.unlink(0, 2);
    let id = net.change(2, Vec::new()).unwrap();
    let head = net.peers[2].model.head_at(id.chain, id.seq).unwrap();
    let body = ModelBody::Edit {
        deps: Vec::new(),
        never: false,
        blind: 0,
    };
    let link = net.link_id(0, 1).unwrap();
    let before = net.peers[0].machine.charged(link);
    net.deliver_message(1, 0, &fresh(seal_in(head, &body, 99)));
    assert_eq!(net.peers[0].machine.charged(link), before + PER_DECLINED);
    // Declined again on the same link: one entry, charged once.
    net.deliver_message(1, 0, &fresh(seal_in(head, &body, 99)));
    assert_eq!(net.peers[0].machine.charged(link), before + PER_DECLINED);
    // A key taken here: what was declined is asked for again, and its
    // charge given back.
    net.local(0, Local::Key(99));
    assert_eq!(net.peers[0].machine.charged(link), before);
}

/// Peers 0, 1, 2 linked, each chain started; peer 1 makes a change in
/// epoch 1, which peer 0 cannot open (`dep`); peer 2 signs two heads at
/// its next number, both naming `dep` (a fork): the two envelopes.
fn two_heads_waiting() -> (Net, ChangeId, Vec<u8>, Vec<u8>) {
    let mut net = Net::new(3);
    for p in 0..3 {
        net.start(p);
    }
    net.peers[1].model.keys.insert(1);
    net.peers[2].model.keys.insert(1);
    net.link_all();
    net.settle(3);
    let dep = net.change_in(1, Vec::new(), 1).unwrap();
    net.settle(3);
    assert!(!net.peers[0].model.holds(dep));
    let p = &net.peers[2];
    let tip = p.model.tip(p.chain()).unwrap();
    let envelopes: Vec<Vec<u8>> = [0, 1]
        .into_iter()
        .map(|blind| {
            let body = ModelBody::Edit {
                deps: vec![(dep.chain.0, dep.seq)],
                never: false,
                blind,
            };
            seal(
                sign(&p.signer, p.origin, tip.seq + 1, tip.hash, &body),
                &body,
            )
        })
        .collect();
    let at = ChangeId {
        chain: p.chain(),
        seq: tip.seq + 1,
    };
    let [a, b] = <[Vec<u8>; 2]>::try_from(envelopes).unwrap();
    (net, at, a, b)
}

/// The hash of `envelope`'s head.
fn head_hash(envelope: &[u8]) -> ChangeHash {
    let parsed = binbun_sync::Envelope::parse(envelope).unwrap();
    SignedHead::parse(parsed.signed_head()).unwrap().hash()
}

#[test]
fn a_second_head_at_a_stops_number_is_a_fork_though_neither_was_admitted() {
    let (mut net, at, a, b) = two_heads_waiting();
    // Peer 0 stops at the first head, waiting for `dep`.
    net.deliver_message(2, 0, &fresh(a.clone()));
    assert_eq!(
        net.peers[0].machine.stop(at.chain),
        Some((at.seq, head_hash(&a)))
    );
    // The second, from another link: proved against the stop's head.
    net.deliver_message(1, 0, &fresh(b));
    let proof = net.peers[0].model.evidence(at.chain).unwrap();
    assert_eq!(proof.place(), at.seq);
    assert!(!net.peers[0].model.holds(at));
    assert_eq!(net.peers[0].model.tip(at.chain).unwrap().seq, at.seq - 1);
}

#[test]
fn a_compare_probe_proves_a_stops_head_against_the_head_it_brings() {
    let (mut net, at, a, b) = two_heads_waiting();
    net.deliver_message(2, 0, &fresh(a));
    assert!(net.peers[0].machine.stop(at.chain).is_some());
    // Peer 1 takes the second head while unlinked (so it pushes it to no
    // one), then links to peer 0 again: its told tip covers the stop,
    // which is compared.
    net.unlink(0, 1);
    net.unlink(1, 2);
    let key = net.peers[2].key();
    let parsed = binbun_sync::Envelope::parse(&b).unwrap();
    assert_eq!(
        net.peers[1].model.admit(key, &parsed),
        binbun_sync::Admission::Applied
    );
    net.journal(1);
    net.link(0, 1);
    net.settle(5);
    assert!(delivered(&net, 0, 1, |m| matches!(
        m,
        Sync::Probe { chain, .. } if *chain == at.chain
    )));
    let proof = net.peers[0].model.evidence(at.chain).unwrap();
    assert_eq!(proof.place(), at.seq);
    assert!(!net.peers[0].model.holds(at));
}

// --- Grants (P21) ---

#[test]
fn a_start_naming_a_record_not_yet_held_is_declined_then_taken_when_it_arrives() {
    let mut net = Net::with(4, 3, Vec::new());
    for p in 0..3 {
        net.start(p);
    }
    net.link(1, 2);
    net.settle(3);
    // The owner adds peer 3; peer 2's storage takes the record, its
    // machine not yet told; peer 1 does not have it.
    let key = net.peers[3].key();
    net.record(Op::Add {
        key: key.0,
        editor: true,
    });
    let records = net.peers[0].model.records.clone();
    let record = records.last().unwrap().clone();
    let after = net.peers[2].model.membership().0;
    let (taken, refused) = net.peers[2].model.take_records(after, &[&record[..]]);
    refused.unwrap();
    // Peer 3 begins a chain under that record; peer 2 takes it.
    net.peers[3].model.records = records;
    net.peers[3].regrant();
    net.start(3);
    let chain = net.peers[3].chain();
    let start = envelope_of(&net, 3, ChangeId { chain, seq: 1 });
    let parsed = binbun_sync::Envelope::parse(&start).unwrap();
    assert_eq!(
        net.peers[2].model.admit(key, &parsed),
        binbun_sync::Admission::Applied
    );
    net.journal(2);
    net.settle(2);
    // Peer 1 pulled it and declined it on the link: its grant is not here.
    assert!(delivered(&net, 2, 1, |m| matches!(
        m,
        Sync::Changes { chain: c, .. } if *c == chain
    )));
    assert!(net.peers[1].model.tip(chain).is_none());
    assert!(net.told(1, 2, chain).unwrap().tried);
    // Peer 2's machine is told of the record: peer 1 takes it and asks
    // for the start again.
    net.local(2, Local::Membership(taken));
    net.settle(3);
    assert_eq!(
        net.peers[1].model.membership(),
        net.peers[0].model.membership()
    );
    assert_eq!(net.peers[1].model.tip(chain).unwrap().seq, 1);
}

// --- Work against well-formed adversaries (P4) ---

#[test]
fn a_lying_tip_costs_one_want_and_is_not_pulled_again() {
    let mut net = readers();
    let chain = net.peers[1].chain();
    let project = net.peers[1].origin.project;
    let lie = tip(chain, project, 50, ChangeHash([7; 32]));
    let before = net.delivered.len();
    for _ in 0..3 {
        net.deliver_message(
            1,
            0,
            &Sync::Tips {
                tips: Bounded::truncated(vec![lie]),
            },
        );
        net.settle(2);
    }
    let wants = net
        .delivered
        .iter()
        .skip(before)
        .filter(|(f, t, m)| {
            *f == 0 && *t == 1 && matches!(m, Sync::Want { chain: c, .. } if *c == chain)
        })
        .count();
    assert_eq!(wants, 1);
    assert!(net.told(0, 1, chain).unwrap().tried);
}

#[test]
fn an_empty_page_with_more_closes_the_link() {
    let mut net = readers();
    let chain = net.peers[1].chain();
    let project = net.peers[1].origin.project;
    let ahead = net.peers[1].model.tip(chain).unwrap();
    // Tell a tip ahead, then answer the Want with an empty page saying
    // more.
    net.deliver_message(
        1,
        0,
        &Sync::Tips {
            tips: Bounded::truncated(vec![tip(
                chain,
                project,
                ahead.seq + 1,
                ChangeHash([1; 32]),
            )]),
        },
    );
    net.tick(Duration::from_secs(1));
    let want = net.flight[&(0, 1)]
        .iter()
        .find_map(|send| match send.message {
            Sync::Want { id, .. } => Some(id),
            _ => None,
        })
        .unwrap();
    net.deliver_message(
        1,
        0,
        &Sync::Changes {
            id: want,
            chain,
            changes: Bounded::new(),
            more: true,
        },
    );
    assert!(closed(
        &net,
        0,
        Closed::Reply("a page of changes past its request")
    ));
}

#[test]
fn a_tips_page_may_end_short_of_its_cursor_but_one_whose_cursor_does_not_advance_closes_the_link() {
    let mut net = Net::new(2);
    net.start(0);
    net.start(1);
    net.link(0, 1);
    // Run the bootstrap; hold peer 1's answer to peer 0's TipsAsk.
    for _ in 0..20 {
        net.serve(0);
        net.serve(1);
        net.deliver(0, 1);
        if net
            .flight
            .get(&(1, 0))
            .is_some_and(|q| q.iter().any(|s| matches!(s.message, Sync::TipsPage { .. })))
        {
            break;
        }
        net.deliver(1, 0);
    }
    let id = net.flight[&(1, 0)]
        .iter()
        .find_map(|send| match send.message {
            Sync::TipsPage { id, .. } => Some(id),
            _ => None,
        })
        .unwrap();
    // An empty page whose scan ran out at chain 5: the next is asked from
    // there (sync §15, H6).
    let cursor = ChainId([5; 16]);
    net.deliver_message(
        1,
        0,
        &Sync::TipsPage {
            id,
            tips: Bounded::new(),
            next: Some(cursor),
        },
    );
    assert!(!closed(
        &net,
        0,
        Closed::Reply("a page of tips out of order")
    ));
    let id = net.flight[&(0, 1)]
        .iter()
        .find_map(|send| match send.message {
            Sync::TipsAsk { id, after, .. } if after == Some(cursor) => Some(id),
            _ => None,
        })
        .unwrap();
    // The answer to it names the same cursor again: no progress.
    net.deliver_message(
        1,
        0,
        &Sync::TipsPage {
            id,
            tips: Bounded::new(),
            next: Some(cursor),
        },
    );
    assert!(closed(
        &net,
        0,
        Closed::Reply("a page of tips out of order")
    ));
}

#[test]
fn a_walk_of_tips_past_its_most_pages_closes_the_link() {
    let mut net = Net::new(2);
    net.start(0);
    net.start(1);
    net.link(0, 1);
    for _ in 0..20 {
        net.serve(0);
        net.serve(1);
        net.deliver(0, 1);
        if net
            .flight
            .get(&(1, 0))
            .is_some_and(|q| q.iter().any(|s| matches!(s.message, Sync::TipsPage { .. })))
        {
            break;
        }
        net.deliver(1, 0);
    }
    let mut id = net.flight[&(1, 0)]
        .iter()
        .find_map(|send| match send.message {
            Sync::TipsPage { id, .. } => Some(id),
            _ => None,
        })
        .unwrap();
    // Empty pages, each moving the cursor on by one chain: valid one by
    // one, but no honest walk takes more than `TIPS_WALK` pages.
    for page in 1..=TIPS_WALK + 1 {
        let cursor = ChainId(u128::from(page).to_be_bytes());
        net.deliver_message(
            1,
            0,
            &Sync::TipsPage {
                id,
                tips: Bounded::new(),
                next: Some(cursor),
            },
        );
        let past = closed(&net, 0, Closed::Reply("a walk of tips past its most pages"));
        assert_eq!(past, page > TIPS_WALK, "page {page}");
        if past {
            break;
        }
        id = net.flight[&(0, 1)]
            .iter()
            .rev()
            .find_map(|send| match send.message {
                Sync::TipsAsk { id, after, .. } if after == Some(cursor) => Some(id),
                _ => None,
            })
            .unwrap();
    }
}

#[test]
fn heads_of_a_number_not_asked_or_of_another_chain_close_the_link() {
    for wrong_chain in [false, true] {
        let mut net = readers();
        let chain = net.peers[1].chain();
        let project = net.peers[1].origin.project;
        // Tell a tip whose hash differs at number 1: peer 0 probes [1].
        net.deliver_message(
            1,
            0,
            &Sync::Tips {
                tips: Bounded::truncated(vec![tip(chain, project, 1, ChangeHash([3; 32]))]),
            },
        );
        net.tick(Duration::from_secs(1));
        let id = net.flight[&(0, 1)]
            .iter()
            .find_map(|send| match send.message {
                Sync::Probe { id, .. } => Some(id),
                _ => None,
            })
            .unwrap();
        let (of, seq) = if wrong_chain { (0, 1) } else { (1, 2) };
        net.change(1, Vec::new());
        let head = net.peers[of]
            .model
            .head_at(net.peers[of].chain(), seq)
            .unwrap();
        net.deliver_message(
            1,
            0,
            &Sync::Heads {
                id,
                chain,
                heads: Bounded::truncated(vec![SignedHeadBytes::try_from(&*head.bytes()).unwrap()]),
            },
        );
        assert!(
            closed(&net, 0, Closed::Reply("a head not asked for")),
            "{wrong_chain}"
        );
    }
}

#[test]
fn numbers_at_the_end_of_u64_are_answered_without_overflow() {
    let mut net = readers();
    let chain = net.peers[1].chain();
    let project = net.peers[1].origin.project;
    for message in [
        Sync::Want {
            id: 1,
            chain,
            after: u64::MAX,
            at: ChangeHash::ZERO,
            most: 256,
        },
        Sync::Probe {
            id: 2,
            chain,
            seqs: Bounded::truncated(vec![u64::MAX - 1, u64::MAX]),
        },
        Sync::HeadsAsk {
            id: 3,
            chain,
            upto: u64::MAX,
            most: 4096,
        },
        Sync::Tips {
            tips: Bounded::truncated(vec![tip(chain, project, u64::MAX, ChangeHash([1; 32]))]),
        },
    ] {
        net.deliver_message(1, 0, &message);
        net.settle(1);
    }
    assert!(net.reader(0, 1));
}

#[test]
fn pulls_both_ways_at_once_converge() {
    let mut net = Net::new(2);
    net.start(0);
    net.start(1);
    for _ in 0..600 {
        net.change(0, Vec::new());
        net.change(1, Vec::new());
    }
    net.link_all();
    net.settle(30);
    assert_eq!(net.peers[0].model.admitted(), net.peers[1].model.admitted());
    assert_eq!(
        net.peers[0].model.tip(net.peers[1].chain()).unwrap().seq,
        601
    );
}

#[test]
fn a_record_arriving_mid_page_cuts_what_follows_it() {
    let mut net = Net::new(3);
    for p in 0..3 {
        net.start(p);
    }
    net.link(1, 2);
    net.settle(3);
    for _ in 0..10 {
        net.change(1, Vec::new());
    }
    net.link(0, 2);
    // Peer 0 removes peer 1 while pulling its chain from peer 2.
    for _ in 0..6 {
        net.drain(1);
        net.tick(Duration::from_millis(10));
    }
    let key = net.peers[1].key();
    let cuts = net.cuts(key);
    net.record(Op::Remove {
        key: key.0,
        cuts: cuts.clone(),
    });
    net.settle(5);
    let chain = net.peers[1].chain();
    // The record names the last change the owner had; it keeps that much.
    let cut = cuts
        .iter()
        .find(|(c, _)| ChainId(*c) == chain)
        .map_or(2, |(_, last)| last + 1);
    assert!(net.peers[0].model.tip(chain).is_none_or(|t| t.seq < cut));
}

#[test]
fn a_request_past_the_slots_closes_the_link() {
    let mut net = readers();
    let chain = net.peers[1].chain();
    for id in 0..5 {
        net.deliver_message(
            1,
            0,
            &Sync::Want {
                id,
                chain,
                after: 0,
                at: ChangeHash::ZERO,
                most: 1,
            },
        );
    }
    assert!(closed(&net, 0, Closed::Requests));
}

#[test]
fn a_request_unanswered_past_its_deadline_closes_the_link() {
    let mut net = readers();
    let chain = net.peers[1].chain();
    let project = net.peers[1].origin.project;
    net.deliver_message(
        1,
        0,
        &Sync::Tips {
            tips: Bounded::truncated(vec![tip(chain, project, 9, ChangeHash([1; 32]))]),
        },
    );
    // Peer 1 never answers.
    net.flight.clear();
    for _ in 0..31 {
        net.tick(Duration::from_secs(1));
        net.flight.clear();
        net.peers[1].jobs.clear();
    }
    assert!(closed(&net, 0, Closed::Stalled));
}

#[test]
fn replies_with_no_outstanding_id_are_dropped_until_sixteen_close_the_link() {
    let mut net = readers();
    let chain = net.peers[1].chain();
    for id in 100..115 {
        net.deliver_message(1, 0, &Sync::Diverged { id, chain });
    }
    assert!(net.reader(0, 1));
    net.deliver_message(1, 0, &Sync::Diverged { id: 115, chain });
    assert!(closed(&net, 0, Closed::Strays));
}

#[test]
fn asking_again_and_again_from_the_start_is_served_each_time_and_kept_nowhere() {
    // Round 3: a regressing frontier redid a whole history pass. Each
    // `Want` after 0 reads one page by index; nothing is remembered.
    let mut net = readers();
    for _ in 0..300 {
        net.change(1, Vec::new());
    }
    net.settle(10);
    let chain = net.peers[1].chain();
    let charged = net.peers[1].machine.charged(net.link_id(1, 0).unwrap());
    for id in 0..3 {
        net.deliver_message(
            0,
            1,
            &Sync::Want {
                id: 1000 + id,
                chain,
                after: 0,
                at: ChangeHash::ZERO,
                most: 256,
            },
        );
        let job = *net.peers[1].jobs.back().unwrap();
        net.peers[1].budget.take();
        let p = &mut net.peers[1];
        let send = p.machine.serve(&mut p.model, &mut p.budget, &job).unwrap();
        net.peers[1].jobs.pop_back();
        let Sync::Changes { changes, more, .. } = send.message else {
            panic!("{send:?}");
        };
        assert_eq!((changes.len(), more), (256, true));
        assert!(net.peers[1].budget.take().read <= 257);
    }
    assert_eq!(
        net.peers[1].machine.charged(net.link_id(1, 0).unwrap()),
        charged
    );
}

// --- Pages, recovery (P19) ---

#[test]
fn pages_of_tips_join_with_no_entry_skipped_or_repeated() {
    let mut net = Net::new(2);
    // Peer 0 holds 1,100 chains of its own (three pages).
    let signer = Signer::from_seed(&seed(0));
    let share = Under {
        genesis: net.peers[0].model.share(),
        grant: 1,
    };
    for salt in 0..1100u32 {
        let mut s = [0; 16];
        s[..4].copy_from_slice(&salt.to_be_bytes());
        let origin = ChainOrigin {
            author: signer.public(),
            project: ProjectId([0; 16]),
            salt: s,
        };
        let body = ModelBody::Start {
            share: Some(share),
            binary: BINARY,
            blind: 0,
        };
        let head = sign(&signer, origin, 1, ChangeHash::ZERO, &body);
        let envelope = seal(head, &body);
        let parsed = binbun_sync::Envelope::parse(&envelope).unwrap();
        net.peers[0].model.admit(signer.public(), &parsed);
    }
    net.peers[0].model.events.clear();
    net.link_all();
    net.settle(60);
    let link = net.link_id(1, 0).unwrap();
    let report = net.peers[1].machine.report(link).unwrap();
    let told: Vec<ChainId> = report.tips.keys().copied().collect();
    let held: Vec<ChainId> = net.peers[0].model.chains.keys().copied().collect();
    assert_eq!(told, held);
    let pages: Vec<usize> = net
        .delivered
        .iter()
        .filter_map(|(f, t, m)| match m {
            Sync::TipsPage { tips, .. } if *f == 0 && *t == 1 => Some(tips.len()),
            _ => None,
        })
        .collect();
    assert_eq!(pages, [512, 512, 76]);
    assert_eq!(net.peers[1].model.chains.len(), 1100);
}

#[test]
fn a_share_in_recovery_serves_and_takes_nothing() {
    let mut net = readers();
    net.peers[0].model.recovering = true;
    net.change(1, Vec::new());
    net.settle(5);
    assert!(closed(&net, 0, Closed::Recovering));
    assert_eq!(net.peers[0].model.tip(net.peers[1].chain()).unwrap().seq, 1);
    net.link(0, 1);
    assert!(!net.reader(0, 1));
}

// --- Decoding bounds (round 3: decode before count) ---

#[test]
fn a_page_of_more_changes_than_its_bound_or_of_tiny_ones_does_not_decode() {
    let one = EnvelopeBytes::try_from(vec![0; 308]).unwrap();
    let full = Sync::Changes {
        id: 0,
        chain: ChainId([0; 16]),
        changes: Bounded::truncated(vec![one; 256]),
        more: false,
    };
    let mut bytes = full.encode().unwrap();
    assert!(Sync::decode(&bytes).is_ok());
    // Declare 257 (after the variant, the id and the chain).
    let at = 1 + 1 + 16;
    assert_eq!(bytes[at..at + 2], [0x80, 0x02]);
    bytes[at..at + 2].copy_from_slice(&[0x81, 0x02]);
    assert!(Sync::decode(&bytes).is_err());
    // Items of fewer than 308 bytes.
    let tiny =
        postcard::to_allocvec(&(10u8, 0u32, [0u8; 16], vec![vec![0u8; 1]; 3], false)).unwrap();
    assert!(Sync::decode(&tiny).is_err());
    let fits =
        postcard::to_allocvec(&(10u8, 0u32, [0u8; 16], vec![vec![0u8; 308]; 3], false)).unwrap();
    assert!(Sync::decode(&fits).is_ok());
}
