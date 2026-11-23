//! Peers in one process, for tests ([`MemNet`], [`MemTransport`]): links
//! are in-memory pipes, identities taken as given.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError, Weak};

use binbun_bounded::Bounded;
use binbun_session::journal::PublicKey;
use tokio::io::DuplexStream;
use tokio::sync::{mpsc, watch};

use crate::Error;
use crate::budgets::Budgets;
use crate::ticket::PeerAddr;
use crate::transport::{BoxFuture, Lane, Link, RecvStream, SendStream, Transport};

/// Bytes each in-memory stream buffers each way.
const BUFFER: usize = 1 << 16;

/// Datagrams each in-memory link buffers each way; more are lost, as on a
/// congested path.
const DATAGRAMS: usize = 256;

/// The largest datagram, about what one QUIC packet carries.
pub const MAX_DATAGRAM: usize = 1200;

/// Where each peer's incoming links go, by identity.
type Inboxes = HashMap<PublicKey, mpsc::UnboundedSender<Arc<dyn Link>>>;

/// A stream's two pipes, as one side holds them: the one it writes, the
/// one it reads. Dropping (or shutting) the one it writes ends what the
/// other side reads, as a QUIC stream's finish.
type Pipes = (DuplexStream, DuplexStream);

/// The peers of one test, by identity.
#[derive(Clone, Debug, Default)]
pub struct MemNet {
    peers: Arc<Mutex<Inboxes>>,
}

impl MemNet {
    /// No peers yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// A peer on it with identity `id` (in place of one with that id).
    pub fn endpoint(&self, id: PublicKey) -> MemTransport {
        self.endpoint_within(id, Budgets::default())
    }

    /// A peer on it with identity `id`, spending from `budgets` (as a
    /// process of its own would).
    pub fn endpoint_within(&self, id: PublicKey, budgets: Budgets) -> MemTransport {
        let (send, incoming) = mpsc::unbounded_channel();
        self.peers
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(id, send);
        MemTransport {
            net: self.clone(),
            id,
            incoming: tokio::sync::Mutex::new(incoming),
            links: Mutex::new(Vec::new()),
            budgets,
        }
    }
}

/// One peer on a [`MemNet`].
#[derive(Debug)]
pub struct MemTransport {
    net: MemNet,
    id: PublicKey,
    incoming: tokio::sync::Mutex<mpsc::UnboundedReceiver<Arc<dyn Link>>>,
    links: Mutex<Vec<Weak<MemLink>>>,
    budgets: Budgets,
}

impl MemTransport {
    /// Keeps `link` to close with the transport.
    fn keep(&self, link: &Arc<MemLink>) {
        let mut links = self.links.lock().unwrap_or_else(PoisonError::into_inner);
        links.retain(|link| link.strong_count() > 0);
        links.push(Arc::downgrade(link));
    }
}

impl Transport for MemTransport {
    fn id(&self) -> PublicKey {
        self.id
    }

    fn addr(&self) -> PeerAddr {
        PeerAddr {
            id: self.id,
            relay: None,
            direct: Bounded::new(),
        }
    }

    fn connect<'a>(&'a self, to: &'a PeerAddr) -> BoxFuture<'a, Result<Arc<dyn Link>, Error>> {
        Box::pin(async move {
            let peer = self
                .net
                .peers
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .get(&to.id)
                .cloned()
                .ok_or_else(|| Error::new(format!("no peer {} on this net", to.id)))?;
            let (ours, theirs) = MemLink::pair(self.id, to.id);
            peer.send(theirs as Arc<dyn Link>)
                .map_err(|_| Error::new(format!("peer {} is closed", to.id)))?;
            self.keep(&ours);
            Ok(ours as Arc<dyn Link>)
        })
    }

    fn accept(&self) -> BoxFuture<'_, Option<Arc<dyn Link>>> {
        Box::pin(async move { self.incoming.lock().await.recv().await })
    }

    fn close(&self) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            {
                let mut peers = self
                    .net
                    .peers
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner);
                peers.remove(&self.id);
            }
            self.incoming.lock().await.close();
            let links: Vec<Weak<MemLink>> =
                std::mem::take(&mut *self.links.lock().unwrap_or_else(PoisonError::into_inner));
            for link in links.iter().filter_map(Weak::upgrade) {
                link.close("closed");
            }
        })
    }

    fn budgets(&self) -> &Budgets {
        &self.budgets
    }
}

/// One side of an in-memory link.
#[derive(Debug)]
struct MemLink {
    remote: PublicKey,
    /// Streams to the other side.
    out: mpsc::UnboundedSender<(Lane, Pipes)>,
    /// Streams from it.
    streams: tokio::sync::Mutex<mpsc::UnboundedReceiver<(Lane, Pipes)>>,
    /// Datagrams to the other side.
    datagrams_out: mpsc::Sender<Vec<u8>>,
    /// Datagrams from it.
    datagrams: tokio::sync::Mutex<mpsc::Receiver<Vec<u8>>>,
    /// Whether the link is closed, shared by both sides.
    closed: Arc<watch::Sender<bool>>,
}

impl MemLink {
    /// Both sides of a link between `a` and `b`: `a`'s, then `b`'s.
    fn pair(a: PublicKey, b: PublicKey) -> (Arc<Self>, Arc<Self>) {
        let (to_b, from_a) = mpsc::unbounded_channel();
        let (to_a, from_b) = mpsc::unbounded_channel();
        let (datagrams_to_b, datagrams_from_a) = mpsc::channel(DATAGRAMS);
        let (datagrams_to_a, datagrams_from_b) = mpsc::channel(DATAGRAMS);
        let closed = Arc::new(watch::Sender::new(false));
        let side = |remote, out, streams, datagrams_out, datagrams| {
            Arc::new(Self {
                remote,
                out,
                streams: tokio::sync::Mutex::new(streams),
                datagrams_out,
                datagrams: tokio::sync::Mutex::new(datagrams),
                closed: Arc::clone(&closed),
            })
        };
        (
            side(b, to_b, from_b, datagrams_to_b, datagrams_from_b),
            side(a, to_a, from_a, datagrams_to_a, datagrams_from_a),
        )
    }

    /// A stream's halves from its pipes.
    fn halves((write, read): Pipes) -> (SendStream, RecvStream) {
        (Box::new(write), Box::new(read))
    }
}

impl Link for MemLink {
    fn remote(&self) -> PublicKey {
        self.remote
    }

    fn open(&self, lane: Lane) -> BoxFuture<'_, Result<(SendStream, RecvStream), Error>> {
        Box::pin(async move {
            if *self.closed.borrow() {
                return Err(Error::new("the link is closed"));
            }
            let (our_write, their_read) = tokio::io::duplex(BUFFER);
            let (their_write, our_read) = tokio::io::duplex(BUFFER);
            self.out
                .send((lane, (their_write, their_read)))
                .map_err(|_| Error::new("the link is closed"))?;
            Ok(Self::halves((our_write, our_read)))
        })
    }

    fn accept(&self) -> BoxFuture<'_, Result<(Lane, SendStream, RecvStream), Error>> {
        Box::pin(async move {
            let mut closed = self.closed.subscribe();
            let mut streams = self.streams.lock().await;
            tokio::select! {
                stream = streams.recv() => {
                    let (lane, stream) = stream.ok_or_else(|| Error::new("the link is closed"))?;
                    let (send, recv) = Self::halves(stream);
                    Ok((lane, send, recv))
                }
                _ = closed.wait_for(|closed| *closed) => Err(Error::new("the link is closed")),
            }
        })
    }

    fn path(&self) -> String {
        "in memory".to_owned()
    }

    fn close(&self, _reason: &str) {
        self.closed.send_replace(true);
    }

    fn closed(&self) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            let mut closed = self.closed.subscribe();
            let _ = closed.wait_for(|closed| *closed).await;
        })
    }

    fn send_datagram(&self, bytes: Vec<u8>) -> Result<(), Error> {
        if *self.closed.borrow() {
            return Err(Error::new("the link is closed"));
        }
        if bytes.len() > MAX_DATAGRAM {
            return Err(Error::new("a datagram too large"));
        }
        // Full: lost, as datagrams are.
        let _ = self.datagrams_out.try_send(bytes);
        Ok(())
    }

    fn recv_datagram(&self) -> BoxFuture<'_, Result<Vec<u8>, Error>> {
        Box::pin(async move {
            let mut closed = self.closed.subscribe();
            let mut datagrams = self.datagrams.lock().await;
            tokio::select! {
                bytes = datagrams.recv() => bytes.ok_or_else(|| Error::new("the link is closed")),
                _ = closed.wait_for(|closed| *closed) => Err(Error::new("the link is closed")),
            }
        })
    }
}
