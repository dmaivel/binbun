//! binbun's collaboration sync protocol (sync §3) as a state machine
//! without I/O.
//!
//! - [`wire`]: the sync lane's messages ([`Sync`]), every field bounded,
//!   decoded only through `binbun-bounded`.
//! - [`envelope`]: the envelope of a change as it travels, its public head
//!   beside its sealed body: the one parser and writer of the layout.
//! - [`storage`]: what the machine reads and writes outside itself, the
//!   journal and the membership chain ([`Storage`]), which the caller
//!   implements.
//! - [`budget`]: what the machine draws from the caller's budgets, and
//!   the instruments of its work ([`Budget`], [`Counting`]).
//! - [`machine`]: the protocol over all links of one journal
//!   ([`Machine`]): messages and local events in, messages to send and
//!   effects out.
//!
//! A change's identity, heads, proofs and tips are the journal's
//! (`binbun_session::journal`); membership records are opaque bytes here,
//! with their numbers and hashes.

pub mod budget;
pub mod envelope;
pub mod machine;
pub mod storage;
pub mod wire;

pub use budget::{Budget, Counting, Spent, Work};
pub use envelope::Envelope;
pub use machine::{Closed, Effect, Job, LinkId, Local, Machine, Output, Page, Phase, Report, Send};
pub use storage::{
    Admission, Event, ForkTaken, Records, RecordsRefused, Storage, TIPS_SCAN, Taken, Walk,
};
pub use wire::Sync;
