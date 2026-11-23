//! P19: the memory a link's state really takes per chain it names,
//! measured with an allocator that counts live heap bytes, against what
//! the machine charges to `sync.link` for it ([`PER_CHAIN`]).

#![allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    reason = "tests fail loudly"
)]

mod model;

use std::alloc::System;
use std::time::Duration;

use binbun_bounded::Bounded;
use binbun_session::journal::{ChainId, ChangeHash, ProjectId, Tip};
use binbun_sync::Sync;
use binbun_sync::budget::PER_CHAIN;
use cap::Cap;
use model::Net;

#[global_allocator]
static ALLOCATOR: Cap<System> = Cap::new(System, usize::MAX);

#[test]
fn a_told_tip_takes_no_more_than_its_charge() {
    let mut net = Net::new(2);
    net.keep = false;
    net.link_all();
    net.settle(3);
    assert!(net.reader(0, 1));
    let link = net.link_id(0, 1).unwrap();
    let charged = net.peers[0].machine.charged(link);
    // 8 pages of 64 tips of chains peer 0 does not know: each is told,
    // and a pull is scheduled for it.
    let chains = 512usize;
    let messages: Vec<Vec<u8>> = (0..chains / 64)
        .map(|page| {
            let tips = (0..64)
                .map(|i| {
                    let n = u32::try_from(page * 64 + i).unwrap();
                    let mut chain = [0; 16];
                    chain[..4].copy_from_slice(&n.to_be_bytes());
                    Tip {
                        chain: ChainId(chain),
                        project: ProjectId([1; 16]),
                        seq: 9,
                        hash: ChangeHash([2; 32]),
                        fork: 0,
                    }
                })
                .collect();
            Sync::Tips {
                tips: Bounded::truncated(tips),
            }
            .encode()
            .unwrap()
        })
        .collect();
    let peer = &mut net.peers[0];
    let before = ALLOCATOR.allocated();
    for bytes in &messages {
        let output = peer.machine.on_message(
            &mut peer.model,
            &mut peer.budget,
            Duration::from_secs(10),
            link,
            bytes,
        );
        drop(output);
    }
    let held = ALLOCATOR.allocated().saturating_sub(before);
    let per_chain = held / chains;
    assert_eq!(
        peer.machine.charged(link) - charged,
        chains * PER_CHAIN,
        "charged per chain named"
    );
    assert!(
        per_chain <= PER_CHAIN,
        "{per_chain} bytes held per told tip, {PER_CHAIN} charged"
    );
    assert_eq!(
        peer.machine.told(link, ChainId([0; 16])).unwrap().tip.seq,
        9
    );
}
