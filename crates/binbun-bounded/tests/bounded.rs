#![allow(clippy::unwrap_used, reason = "test helpers fail loudly")]
//! The bounded types, decoding, encoding, pages and the walk, through
//! the crate's public API.

use std::cell::Cell;
use std::collections::BTreeMap;

use binbun_bounded::{
    Bounded, Bounds, Bytes, Error, Exact, Map, Page, PageBuilder, Text, decode, encode, size, take,
    walk,
};
use serde::{Deserialize, Deserializer, Serialize};

thread_local! {
    /// The [`Counted`] items decoded on this thread.
    static DECODED: Cell<usize> = const { Cell::new(0) };
}

/// A byte that counts its decodings.
#[derive(Debug, Serialize)]
struct Counted(u8);

impl<'de> Deserialize<'de> for Counted {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        DECODED.with(|decoded| decoded.set(decoded.get() + 1));
        u8::deserialize(deserializer).map(Counted)
    }
}

/// `length`'s varint, then `body`.
fn declared(length: usize, body: &[u8]) -> Vec<u8> {
    let mut bytes = postcard::to_allocvec(&length).unwrap();
    bytes.extend_from_slice(body);
    bytes
}

#[test]
fn a_list_is_refused_at_item_n_plus_one_before_it_is_decoded() {
    // Declared past the bound, every item there: refused before any.
    DECODED.with(|decoded| decoded.set(0));
    let bytes = declared(4, &[1, 2, 3, 4]);
    assert!(decode::<Bounded<Counted, 3>>(&bytes).is_err());
    assert_eq!(DECODED.with(Cell::get), 0);
    // Declared past what follows (so postcard gives no length up front)
    // and past the bound: the fourth item is there but never decoded.
    let bytes = declared(9, &[1, 2, 3, 4]);
    assert!(decode::<Bounded<Counted, 3>>(&bytes).is_err());
    assert_eq!(DECODED.with(Cell::get), 3);
    // At the bound, it reads.
    DECODED.with(|decoded| decoded.set(0));
    let read = decode::<Bounded<Counted, 3>>(&declared(3, &[1, 2, 3])).unwrap();
    assert_eq!(read.iter().map(|c| c.0).collect::<Vec<_>>(), [1, 2, 3]);
}

#[test]
fn byte_strings_and_text_outside_their_bounds_are_refused() {
    assert!(decode::<Bytes<4>>(&declared(5, &[0; 5])).is_err());
    // Declared far past the bound, with nothing after: refused, not read.
    assert!(decode::<Bytes<4>>(&declared(1 << 30, &[])).is_err());
    assert_eq!(
        decode::<Bytes<4>>(&declared(4, &[9; 4])).unwrap().as_ref(),
        [9; 4]
    );
    // The least too.
    assert!(decode::<Bytes<4, 2>>(&declared(1, &[0])).is_err());
    assert!(Bytes::<4, 2>::try_from(vec![0]).is_err());
    assert!(decode::<Exact<3>>(&declared(2, &[0; 2])).is_err());
    assert!(decode::<Exact<3>>(&declared(4, &[0; 4])).is_err());
    assert_eq!(
        decode::<Exact<3>>(&declared(3, &[7; 3]))
            .unwrap()
            .as_array(),
        &[7; 3]
    );
    assert!(decode::<Text<3>>(&postcard::to_allocvec("four").unwrap()).is_err());
    assert_eq!(
        &*decode::<Text<4>>(&postcard::to_allocvec("four").unwrap()).unwrap(),
        "four"
    );
    // Cut between characters, never inside one.
    assert_eq!(&*Text::<4>::truncated("abcé"), "abc");
}

#[test]
fn a_map_refuses_entries_past_its_bound_and_a_key_twice() {
    let three: BTreeMap<u8, u8> = [(1, 1), (2, 2), (3, 3)].into();
    let bytes = postcard::to_allocvec(&three).unwrap();
    assert!(decode::<Map<u8, u8, 2>>(&bytes).is_err());
    assert_eq!(*decode::<Map<u8, u8, 3>>(&bytes).unwrap(), three);
    // Key 1 twice.
    let twice = declared(2, &[1, 1, 1, 2]);
    assert!(decode::<Map<u8, u8, 4>>(&twice).is_err());
}

#[test]
fn the_bounded_types_encode_as_what_they_wrap() {
    let list = vec![1u32, 300, 70_000];
    let text = "é".repeat(5);
    let map: BTreeMap<u16, u64> = [(1, 2), (500, u64::MAX)].into();
    let bytes = vec![0u8, 255, 7];
    assert_eq!(
        postcard::to_allocvec(&Bounded::<u32, 3>::try_from(list.clone()).unwrap()).unwrap(),
        postcard::to_allocvec(&list).unwrap()
    );
    assert_eq!(
        postcard::to_allocvec(&Text::<10>::try_from(text.as_str()).unwrap()).unwrap(),
        postcard::to_allocvec(&text).unwrap()
    );
    assert_eq!(
        postcard::to_allocvec(&Map::<u16, u64, 2>::try_from(map.clone()).unwrap()).unwrap(),
        postcard::to_allocvec(&map).unwrap()
    );
    assert_eq!(
        postcard::to_allocvec(&Bytes::<3>::try_from(bytes.clone()).unwrap()).unwrap(),
        postcard::to_allocvec(&bytes).unwrap()
    );
    assert_eq!(
        postcard::to_allocvec(&Exact::from([0u8, 255, 7])).unwrap(),
        postcard::to_allocvec(&bytes).unwrap()
    );
}

#[test]
fn decoding_refuses_bytes_left_over_and_taking_gives_them_back() {
    let mut bytes = postcard::to_allocvec(&7u32).unwrap();
    bytes.push(0);
    assert_eq!(decode::<u32>(&bytes), Err(Error::Trailing(1)));
    assert_eq!(take::<u32>(&bytes), Ok((7, &[0][..])));
}

#[test]
fn encoding_past_its_limit_fails_and_within_it_is_postcards() {
    let value = Bytes::<1024>::try_from(vec![3; 1000]).unwrap();
    let whole = postcard::to_allocvec(&value).unwrap();
    assert_eq!(encode(&value, whole.len()).unwrap(), whole);
    assert_eq!(size(&value, whole.len()), Ok(whole.len()));
    assert_eq!(
        encode(&value, whole.len() - 1),
        Err(Error::TooLarge(whole.len() - 1))
    );
    assert_eq!(
        size(&value, whole.len() - 1),
        Err(Error::TooLarge(whole.len() - 1))
    );
}

/// An item of a page: its key and some bytes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Item {
    key: u32,
    body: Bytes<512>,
}

/// The page of `items` after `after` (all if `None`), within `room`.
fn page(items: &[Item], after: Option<u32>, room: usize) -> Page<Item, 64> {
    let mut builder = PageBuilder::new(room);
    for item in items
        .iter()
        .filter(|item| after.is_none_or(|after| item.key > after))
    {
        if builder.push(item.clone()).is_err() {
            break;
        }
    }
    builder.finish()
}

#[test]
fn pages_stay_within_their_room_and_their_cursor_reaches_every_item() {
    // Items of every size from 0 to 511 bytes, keyed apart.
    let items: Vec<Item> = (0..1000u32)
        .map(|n| Item {
            key: n * 3,
            body: Bytes::try_from(vec![0; (n as usize * 37) % 512]).unwrap(),
        })
        .collect();
    for room in [600, 4096, 100_000] {
        let mut after = None;
        let mut read = Vec::new();
        loop {
            let page = page(&items, after, room);
            let encoded = postcard::to_allocvec(&page).unwrap();
            assert!(encoded.len() <= room, "{} > {room}", encoded.len());
            assert_eq!(decode::<Page<Item, 64>>(&encoded).unwrap(), page);
            // Each page goes on from the cursor the asker stated.
            assert!(!page.items.is_empty());
            let last = page.items.last().unwrap().key;
            assert!(after.is_none_or(|after| page.items[0].key > after));
            read.extend(page.items.into_iter().map(|item| item.key));
            if !page.more {
                break;
            }
            after = Some(last);
        }
        assert_eq!(read, items.iter().map(|item| item.key).collect::<Vec<_>>());
    }
    // An item larger than the room leaves the page empty, saying more
    // come.
    let big = page(&items[511..512], None, 64);
    assert!(big.items.is_empty() && big.more);
}

#[derive(Deserialize)]
#[expect(dead_code, reason = "only its shape is walked")]
enum Inner {
    Fine(u64),
    Wide { list: Vec<u8> },
}

#[derive(Deserialize)]
#[expect(dead_code, reason = "only its shape is walked")]
enum Outer {
    Plain,
    Nested(Box<Inner>),
}

#[derive(Deserialize)]
#[expect(dead_code, reason = "only its shape is walked")]
struct Good {
    id: [u8; 16],
    name: Text<64>,
    keys: Bounded<(u32, Exact<80>), 8>,
    cut: Map<u64, u64, 16>,
    sealed: Option<Bytes<256, 1>>,
    page: Page<Bytes<9, 2>, 3>,
}

#[derive(Deserialize)]
#[expect(dead_code, reason = "only its shape is walked")]
struct Named {
    name: String,
}

#[derive(Deserialize)]
#[expect(dead_code, reason = "only its shape is walked")]
struct Listed {
    list: Bounded<BTreeMap<u8, u8>, 4>,
}

#[derive(Deserialize)]
#[expect(dead_code, reason = "only its shape is walked")]
struct Looped {
    next: Option<Box<Looped>>,
}

impl Bounds for Good {}

#[test]
fn the_walk_finds_every_unbounded_part_however_deep() {
    assert_eq!(walk::<Good>(), Ok(()));
    // A list in a variant reached only through another enum's variant.
    let error = walk::<Outer>().unwrap_err().to_string();
    assert!(error.contains("Inner::Wide.list"), "{error}");
    assert!(walk::<Named>().is_err());
    // Inside a bounded list, an unbounded map.
    assert!(walk::<Listed>().is_err());
    assert!(walk::<Vec<u8>>().is_err());
    assert!(walk::<Looped>().is_err());
}
