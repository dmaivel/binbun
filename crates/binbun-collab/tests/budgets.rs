#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers fail loudly"
)]
//! What remote parties may make a process spend, through
//! [`Budgets`]: each hard ceiling exceeded and refused, then allowed once
//! a guard is dropped or time passes; a reconnect refills neither a
//! stranger's count nor a member's rates; an old link's cleanup leaves
//! its successor; a stranger's deadline covers a write that stalls.
//! Rates run on a fake clock, deadlines on tokio's paused one.

use std::time::Duration;

use binbun_collab::budgets::{
    ASK_FOR, ASKERS, ASKING, ASKS, Budgets, CHAT, CHAT_BACKLOG, Clock, DATAGRAMS, FRAMES,
    FakeRelativeClock, HANDSHAKE, LINK_STREAMS, LINKS, LIVE_BYTES, LIVE_FRAMES, PRESENCE, Refused,
    STRANGERS, STREAM_ASK, STREAMS, SYNC_BYTES, SYNC_LINK, SYNC_LINK_BASE, SYNC_LINK_PER_LINK,
    SYNC_PAGES, SYNC_PAGES_PER_LINK, ShareBudget, TASKS,
};
use binbun_session::journal::PublicKey;
use tokio::io::AsyncWriteExt;
use tokio::time::Instant;

/// The `n`th made-up key.
fn key(n: u32) -> PublicKey {
    let mut bytes = [0; 32];
    bytes[..4].copy_from_slice(&n.to_le_bytes());
    PublicKey(bytes)
}

/// Budgets on a fake clock, and the clock.
fn faked() -> (Budgets, FakeRelativeClock) {
    let clock = FakeRelativeClock::default();
    (Budgets::new(Clock::fake(clock.clone())), clock)
}

/// How many of `n` tries `take` allows.
fn allowed(n: usize, mut take: impl FnMut() -> bool) -> usize {
    (0..n).filter(|_| take()).count()
}

#[tokio::test]
async fn the_stranger_pool_turns_one_away_past_its_ceiling_until_a_place_is_freed() {
    let (budgets, _) = faked();
    let mut held: Vec<_> = (0..STRANGERS)
        .map(|_| budgets.stranger().unwrap())
        .collect();
    assert!(budgets.stranger().is_none());
    held.pop();
    assert!(budgets.stranger().is_some());
}

#[tokio::test(start_paused = true)]
async fn a_strangers_deadline_covers_a_write_that_stalls_and_its_place_is_freed() {
    let (budgets, _) = faked();
    let mut held: Vec<_> = (1..STRANGERS)
        .map(|_| budgets.stranger().unwrap())
        .collect();
    let mut stranger = budgets.stranger().unwrap();
    let start = Instant::now();
    assert_eq!(stranger.deadline().at(), start + HANDSHAKE);

    // A stranger that reads nothing: the write stalls once the stream's
    // buffer is full, and is given up at the deadline.
    let (mut to_them, _unread) = tokio::io::duplex(64);
    let stalled = stranger
        .deadline()
        .within(to_them.write_all(&[0; 4096]))
        .await;
    assert!(stalled.is_err());
    assert_eq!(start.elapsed(), HANDSHAKE);

    // Asking starts a stage of its own, the approver's time ending before
    // the last word's.
    let asking = budgets.ask(&mut stranger, key(1)).unwrap();
    let asked = Instant::now();
    assert_eq!(stranger.deadline().at(), asked + ASK_FOR);
    assert!(asking.answer_by() < stranger.deadline());
    let stalled = stranger
        .deadline()
        .within(to_them.write_all(&[0; 4096]))
        .await;
    assert!(stalled.is_err());
    assert_eq!(asked.elapsed(), ASK_FOR);

    // Dropped, its place is free.
    assert!(budgets.stranger().is_none());
    drop((asking, stranger));
    held.push(budgets.stranger().unwrap());
}

#[tokio::test]
async fn requests_wait_one_per_key_and_a_bounded_number_at_once() {
    let (budgets, _) = faked();
    let mut stranger = budgets.stranger().unwrap();
    let first = budgets.ask(&mut stranger, key(0)).unwrap();
    assert_eq!(
        budgets.ask(&mut stranger, key(0)).unwrap_err(),
        Refused::Waiting
    );
    let mut waiting: Vec<_> = (1..u32::try_from(ASKING).unwrap())
        .map(|n| budgets.ask(&mut stranger, key(n)).unwrap())
        .collect();
    assert_eq!(
        budgets.ask(&mut stranger, key(1000)).unwrap_err(),
        Refused::Full
    );
    // One withdrawn: another key is asked about.
    waiting.pop();
    let _next = budgets.ask(&mut stranger, key(1000)).unwrap();
    assert_eq!(
        budgets.ask(&mut stranger, key(1001)).unwrap_err(),
        Refused::Full
    );
    // The first key's withdrawn: it may ask again.
    drop(first);
    assert!(budgets.ask(&mut stranger, key(0)).is_ok());
}

#[tokio::test]
async fn a_key_asks_a_few_times_a_while_and_dialling_again_does_not_refill_it() {
    let (budgets, clock) = faked();
    for _ in 0..ASKS.burst {
        // Each on a link of its own, withdrawn as it closes.
        let mut stranger = budgets.stranger().unwrap();
        drop(budgets.ask(&mut stranger, key(7)).unwrap());
    }
    let mut stranger = budgets.stranger().unwrap();
    assert_eq!(
        budgets.ask(&mut stranger, key(7)).unwrap_err(),
        Refused::Often
    );
    // Another key is asked about all the same.
    drop(budgets.ask(&mut stranger, key(8)).unwrap());
    // A while later, this one again.
    clock.advance(ASKS.over);
    let mut again = budgets.stranger().unwrap();
    assert!(budgets.ask(&mut again, key(7)).is_ok());
}

#[tokio::test]
async fn past_the_askers_counted_apart_new_keys_share_one_count() {
    let (budgets, _) = faked();
    let mut stranger = budgets.stranger().unwrap();
    let askers = u32::try_from(ASKERS).unwrap();
    for n in 0..askers {
        drop(budgets.ask(&mut stranger, key(n)).unwrap());
    }
    // New keys share one count: a burst's worth among all of them.
    let fresh = (askers..askers + 10)
        .filter(|n| budgets.ask(&mut stranger, key(*n)).is_ok())
        .count();
    assert_eq!(fresh, usize::try_from(ASKS.burst).unwrap());
    // A key counted apart keeps its own.
    assert!(budgets.ask(&mut stranger, key(0)).is_ok());
}

#[tokio::test]
async fn links_are_bounded_and_an_old_links_cleanup_leaves_its_successor() {
    let (budgets, _) = faked();
    let old = budgets.link(key(1)).unwrap();
    let new = budgets.link(key(1)).unwrap();
    assert!(new.generation() > old.generation());
    assert!(!old.is_current() && new.is_current());
    drop(old);
    assert!(new.is_current());
    assert_eq!(budgets.current(key(1)), Some(new.generation()));
    drop(new);
    assert_eq!(budgets.current(key(1)), None);

    // The process's ceiling.
    let mut links: Vec<_> = (0..u32::try_from(LINKS).unwrap())
        .map(|n| budgets.link(key(n)).unwrap())
        .collect();
    assert!(budgets.link(key(5000)).is_none());
    links.pop();
    assert!(budgets.link(key(5000)).is_some());
}

#[tokio::test]
async fn sync_state_is_bounded_per_link_and_per_process() {
    let (budgets, _) = faked();
    let link = budgets.link(key(1)).unwrap();
    let most = link.charge(SYNC_LINK_PER_LINK - SYNC_LINK_BASE).unwrap();
    assert!(link.charge(1).is_none());
    drop(most);
    assert!(link.charge(1).is_some());
    drop(link);

    // Links each full: past the process's ceiling, not even a new link's
    // base fits.
    let mut full = Vec::new();
    for n in 0..u32::try_from(SYNC_LINK / SYNC_LINK_PER_LINK).unwrap() {
        let link = budgets.link(key(n)).unwrap();
        let charge = link.charge(SYNC_LINK_PER_LINK - SYNC_LINK_BASE).unwrap();
        full.push((charge, link));
    }
    assert!(budgets.link(key(9999)).is_none());
    full.pop();
    assert!(budgets.link(key(9999)).is_some());
}

#[tokio::test(start_paused = true)]
async fn streams_are_bounded_per_link_and_per_process_their_ask_due_in_time() {
    let (budgets, _) = faked();
    let link = budgets.link(key(0)).unwrap();
    let start = Instant::now();
    let mut streams: Vec<_> = (0..LINK_STREAMS).map(|_| link.stream().unwrap()).collect();
    assert_eq!(streams[0].ask_by().at(), start + STREAM_ASK);
    assert!(link.stream().is_none());
    streams.pop();
    streams.push(link.stream().unwrap());

    // Other links fill the process's.
    let others: Vec<_> = (1..u32::try_from(STREAMS / LINK_STREAMS).unwrap())
        .map(|n| budgets.link(key(n)).unwrap())
        .collect();
    let mut theirs: Vec<_> = others
        .iter()
        .flat_map(|link| (0..LINK_STREAMS).map(|_| link.stream().unwrap()))
        .collect();
    let last = budgets.link(key(5000)).unwrap();
    assert!(last.stream().is_none());
    theirs.pop();
    assert!(last.stream().is_some());
}

#[tokio::test(start_paused = true)]
async fn frames_wait_for_their_bytes_and_go_on_once_others_are_handled() {
    let (budgets, _) = faked();
    assert!(budgets.frame(FRAMES + 1).await.is_none());
    let all = budgets.frame(FRAMES).await.unwrap();
    let waiting = tokio::time::timeout(Duration::from_secs(60), budgets.frame(1)).await;
    assert!(waiting.is_err());
    let next = tokio::spawn({
        let budgets = budgets.clone();
        async move { budgets.frame(1 << 20).await.is_some() }
    });
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert!(!next.is_finished());
    drop(all);
    assert!(next.await.unwrap());
}

#[tokio::test]
async fn tasks_are_bounded_per_process() {
    let (budgets, _) = faked();
    let mut tasks: Vec<_> = (0..TASKS).map(|_| budgets.task().unwrap()).collect();
    assert!(budgets.task().is_none());
    tasks.pop();
    assert!(budgets.task().is_some());
}

#[tokio::test(start_paused = true)]
async fn sync_pages_are_bounded_per_link_and_per_process_with_one_kept_for_each_shares_records() {
    let (budgets, _) = faked();
    let wait = Duration::from_secs(30);
    let link = budgets.link(key(0)).unwrap();
    let mut pages = Vec::new();
    for _ in 0..SYNC_PAGES_PER_LINK {
        pages.push(link.page().await.unwrap());
    }
    assert!(tokio::time::timeout(wait, link.page()).await.is_err());
    pages.pop();
    pages.push(link.page().await.unwrap());

    // Other links take the rest of the process's.
    let others: Vec<_> = (1..=u32::try_from(SYNC_PAGES).unwrap())
        .map(|n| budgets.link(key(n)).unwrap())
        .collect();
    let mut theirs = Vec::new();
    for other in &others {
        if pages.len() + theirs.len() == SYNC_PAGES {
            break;
        }
        theirs.push(other.page().await.unwrap());
    }
    assert_eq!(budgets.pages_free(), 0);
    let last = budgets.link(key(5000)).unwrap();
    assert!(tokio::time::timeout(wait, last.page()).await.is_err());
    // Each share keeps one for its records, past the process's: one held
    // (its write stalled, say) holds up its own share's next, not another
    // share's.
    let (share, other) = (ShareBudget::default(), ShareBudget::default());
    let records = share.records_page().await.unwrap();
    assert!(
        tokio::time::timeout(wait, share.records_page())
            .await
            .is_err()
    );
    let start = Instant::now();
    let theirs_too = tokio::time::timeout(wait, other.records_page())
        .await
        .expect("another share's records page at once")
        .unwrap();
    assert_eq!(start.elapsed(), Duration::ZERO);
    drop(records);
    assert!(share.records_page().await.is_some());
    drop(theirs_too);
    theirs.pop();
    assert!(tokio::time::timeout(wait, last.page()).await.is_ok());
}

#[tokio::test]
async fn a_members_live_rates_hold_past_a_reconnect_and_fill_again_over_time() {
    let (budgets, clock) = faked();
    let (member, author) = (key(1), key(2));

    let frames = usize::try_from(LIVE_FRAMES.burst).unwrap();
    let link = budgets.link(member).unwrap();
    assert_eq!(
        allowed(frames + 100, || budgets.live_frame(member, 10)),
        frames
    );
    // Linking again fills nothing.
    drop(link);
    let _link = budgets.link(member).unwrap();
    assert!(!budgets.live_frame(member, 10));
    clock.advance(LIVE_FRAMES.over / LIVE_FRAMES.burst);
    assert!(budgets.live_frame(member, 10));
    // Bytes: a burst's worth, then none until they come again.
    let other = key(3);
    let burst = usize::try_from(LIVE_BYTES.burst).unwrap();
    assert!(budgets.live_frame(other, burst));
    assert!(!budgets.live_frame(other, 1 << 10));
    clock.advance(LIVE_BYTES.over);
    assert!(budgets.live_frame(other, 1 << 10));

    // Chat through a link: its backlog, then the author's own rate; an
    // author's rate through one link is not another's.
    let backlog = usize::try_from(CHAT_BACKLOG.burst).unwrap();
    let chat = usize::try_from(CHAT.burst).unwrap();
    assert_eq!(
        allowed(backlog + chat + 10, || budgets.chat(member, author)),
        backlog + chat
    );
    assert!(budgets.chat(member, key(4)));
    clock.advance(CHAT.over / CHAT.burst);
    assert!(budgets.chat(member, author));
    assert!(!budgets.chat(member, author));

    // Datagrams per link, presence per participant.
    let datagrams = usize::try_from(DATAGRAMS.burst).unwrap();
    assert_eq!(
        allowed(datagrams * 2, || budgets.datagram(member)),
        datagrams
    );
    let presence = usize::try_from(PRESENCE.burst).unwrap();
    assert_eq!(allowed(presence * 2, || budgets.presence(author)), presence);
    clock.advance(Duration::from_secs(1));
    assert!(budgets.datagram(member) && budgets.presence(author));

    // This peer's own chat.
    assert_eq!(allowed(chat * 2, || budgets.say_chat()), chat);
    clock.advance(CHAT.over / CHAT.burst);
    assert!(budgets.say_chat());
}

#[tokio::test]
async fn sync_bytes_past_a_members_burst_become_backpressure() {
    let (budgets, clock) = faked();
    let member = key(1);
    let burst = usize::try_from(SYNC_BYTES.burst).unwrap();
    assert_eq!(budgets.sync_in(member, burst), Duration::ZERO);
    let page = 2 << 20;
    let wait = budgets.sync_in(member, page);
    assert!(wait > Duration::ZERO);
    // Asked again before then, still waiting; after, taken.
    assert!(budgets.sync_in(member, page) > Duration::ZERO);
    clock.advance(wait);
    assert_eq!(budgets.sync_in(member, page), Duration::ZERO);
    // Each way apart.
    assert_eq!(budgets.sync_out(member, burst), Duration::ZERO);
    assert!(budgets.sync_out(member, page) > Duration::ZERO);
}
