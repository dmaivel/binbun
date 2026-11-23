//! How peers reach each other: the
//! [`Transport`] trait, behind which iroh stays ([`crate::net`]), with an
//! in-process one for tests ([`crate::mem`]). A transport proves each
//! link's remote identity (iroh: TLS with the identity's ed25519 key);
//! everything above it (who may join, what is sealed, what is taken) is
//! binbun's.
//!
//! A link carries one bidirectional stream per [`Lane`], opened by the
//! dialler, its first byte naming the lane; on each, frames: a LEB128
//! length, then the message's postcard ([`write_frame`], [`read_frame`]),
//! the length checked against the message kind's limit
//! ([`crate::wire::Frame`]) before any of the body is read.
//! Presence travels beside them in unreliable datagrams
//! ([`Link::send_datagram`]).

use std::pin::Pin;
use std::sync::Arc;

use binbun_bounded::Bounds;
use binbun_session::journal::PublicKey;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::Error;
use crate::budgets::{Budgets, Stranger};
use crate::ticket::PeerAddr;
use crate::wire::{self, Frame};

/// A boxed future, as the traits return.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// A stream's sending half.
pub type SendStream = Box<dyn AsyncWrite + Send + Unpin>;

/// A stream's receiving half.
pub type RecvStream = Box<dyn AsyncRead + Send + Unpin>;

/// A link's streams, one per purpose.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Lane {
    /// Joining and leaving ([`crate::wire::Control`]).
    Control,
    /// The log's sync ([`binbun_sync::Sync`]).
    Sync,
    /// The live session: who is there, chat ([`crate::live::Said`]); one
    /// stream each way, opened by each side once synced.
    Live,
    /// Files by hash ([`crate::blobs`]): one stream per ask, opened by
    /// the asker once synced.
    Blob,
}

impl Lane {
    /// The byte that opens its stream.
    pub fn byte(self) -> u8 {
        match self {
            Self::Control => 0,
            Self::Sync => 1,
            Self::Live => 2,
            Self::Blob => 3,
        }
    }

    /// The lane `byte` opens.
    pub fn of(byte: u8) -> Option<Self> {
        match byte {
            0 => Some(Self::Control),
            1 => Some(Self::Sync),
            2 => Some(Self::Live),
            3 => Some(Self::Blob),
            _ => None,
        }
    }
}

/// A way to reach peers.
pub trait Transport: Send + Sync + 'static {
    /// This peer's identity key.
    fn id(&self) -> PublicKey;

    /// Where this peer is reached, for tickets.
    fn addr(&self) -> PeerAddr;

    /// A link to the peer at `to`, its identity proven.
    fn connect<'a>(&'a self, to: &'a PeerAddr) -> BoxFuture<'a, Result<Arc<dyn Link>, Error>>;

    /// The next link a peer made to this one, its identity proven; `None`
    /// once closed.
    fn accept(&self) -> BoxFuture<'_, Option<Arc<dyn Link>>>;

    /// Stops: links closed, no more accepted.
    fn close(&self) -> BoxFuture<'_, ()>;

    /// What remote parties may make this peer's process spend: shared
    /// with everything on the process's transports.
    fn budgets(&self) -> &Budgets;
}

/// A link to one peer.
pub trait Link: Send + Sync {
    /// The peer's identity key, as the transport proved it.
    fn remote(&self) -> PublicKey;

    /// Opens a stream for `lane`.
    fn open(&self, lane: Lane) -> BoxFuture<'_, Result<(SendStream, RecvStream), Error>>;

    /// The next stream the peer opened, and its lane.
    fn accept(&self) -> BoxFuture<'_, Result<(Lane, SendStream, RecvStream), Error>>;

    /// How the link reaches the peer now (`direct 192.168.1.5:4433`, a
    /// direct path tagged `(tailnet)` or, to this machine's own address,
    /// `(loopback)`; `relay https://…`), for people.
    fn path(&self) -> String;

    /// Closes it, telling the peer `reason`.
    fn close(&self, reason: &str);

    /// Waits until it is closed, by either side or the network.
    fn closed(&self) -> BoxFuture<'_, ()>;

    /// Sends `bytes` as one unreliable datagram (presence): lost, never
    /// queued, when the path is congested or the peer reads none.
    ///
    /// # Errors
    ///
    /// The link is closed, does not carry datagrams, or `bytes` is too
    /// large for one.
    fn send_datagram(&self, bytes: Vec<u8>) -> Result<(), Error>;

    /// The next datagram the peer sent.
    ///
    /// # Errors
    ///
    /// The link is closed.
    fn recv_datagram(&self) -> BoxFuture<'_, Result<Vec<u8>, Error>>;

    /// The place in the stranger pool the transport took for this link
    /// as it accepted the connection, handed over once, so one place is
    /// held from the accepting through the admission decision
    /// ([`crate::budgets`]); `None` for a link dialled, one handed over
    /// already, or a transport that takes none before its links.
    fn stranger(&self) -> Option<Stranger> {
        None
    }
}

/// Writes `message` to `to` as one frame ([`wire::encode`]).
///
/// # Errors
///
/// It does not fit its kind's frame, or the stream fails.
pub async fn write_frame<T: Frame + Sync>(
    to: &mut (dyn AsyncWrite + Send + Unpin),
    message: &T,
) -> Result<(), Error> {
    write_bytes(to, &wire::encode(message)?).await
}

/// Writes `bytes`, a message already encoded within its kind's limit, to
/// `to` as one frame.
///
/// # Errors
///
/// The stream fails.
pub async fn write_bytes(
    to: &mut (dyn AsyncWrite + Send + Unpin),
    bytes: &[u8],
) -> Result<(), Error> {
    let mut frame = Vec::with_capacity(bytes.len() + 5);
    let mut length = bytes.len();
    loop {
        let low = u8::try_from(length & 0x7f).unwrap_or_default();
        length >>= 7;
        if length == 0 {
            frame.push(low);
            break;
        }
        frame.push(low | 0x80);
    }
    frame.extend_from_slice(bytes);
    to.write_all(&frame).await?;
    Ok(to.flush().await?)
}

/// The next frame's message from `from`, within its kind's limit;
/// `None` at the stream's end ([`read_frame_length`], then
/// [`read_frame_body`]).
///
/// # Errors
///
/// The stream fails or ends inside a frame, the frame is too large, or
/// it does not decode.
pub async fn read_frame<T: Frame + Bounds>(
    from: &mut (dyn AsyncRead + Send + Unpin),
) -> Result<Option<T>, Error> {
    match read_frame_length(from, T::LIMIT).await? {
        Some(length) => read_frame_body(from, length).await.map(Some),
        None => Ok(None),
    }
}

/// The length of the next frame from `from`, of `max` bytes at most;
/// `None` at the stream's end.
///
/// # Errors
///
/// The stream fails or ends inside the length, or the frame is larger
/// than `max`.
pub async fn read_frame_length(
    from: &mut (dyn AsyncRead + Send + Unpin),
    max: usize,
) -> Result<Option<usize>, Error> {
    let mut length = 0usize;
    for shift in (0..).step_by(7) {
        let byte = match from.read_u8().await {
            Ok(byte) => byte,
            Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof && shift == 0 => {
                return Ok(None);
            }
            Err(error) => return Err(error.into()),
        };
        if shift > 28 {
            return Err(Error::new("a frame too large"));
        }
        length |= usize::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            break;
        }
    }
    if length > max {
        return Err(Error::new("a frame too large"));
    }
    Ok(Some(length))
}

/// The message of the frame whose `length` [`read_frame_length`] read,
/// from `from` ([`wire::decode`]).
///
/// # Errors
///
/// The stream fails or ends inside the frame, or it does not decode.
pub async fn read_frame_body<T: Frame + Bounds>(
    from: &mut (dyn AsyncRead + Send + Unpin),
    length: usize,
) -> Result<T, Error> {
    wire::decode(&read_bytes(from, length).await?)
}

/// The `length` bytes of a frame's body, from `from`: the buffer grows as
/// they come, not to the length the frame claims.
///
/// # Errors
///
/// The stream fails or ends first.
pub async fn read_bytes(
    from: &mut (dyn AsyncRead + Send + Unpin),
    length: usize,
) -> Result<Vec<u8>, Error> {
    let mut bytes = Vec::new();
    (&mut *from)
        .take(length as u64)
        .read_to_end(&mut bytes)
        .await?;
    if bytes.len() < length {
        return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof).into());
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use binbun_bounded::{Bytes, Text};

    use super::{read_frame, write_frame};
    use crate::wire::{self, CONTROL_FRAME, Control, LIVE_FRAME, LiveFrame, MAX_LIVE_SEALED};

    /// `n`'s LEB128.
    fn length(mut n: usize) -> Vec<u8> {
        let mut length = Vec::new();
        while n >= 0x80 {
            length.push(u8::try_from(n & 0x7f).unwrap() | 0x80);
            n >>= 7;
        }
        length.push(u8::try_from(n).unwrap());
        length
    }

    #[tokio::test]
    async fn a_frame_past_its_kinds_limit_is_refused_before_its_bytes_are_read() {
        // A stranger's first control frame claims one byte past its 16 KiB
        // and sends none of it: the host refuses it at once instead of
        // waiting for (and holding) it.
        let (mut a, mut b) = tokio::io::duplex(64);
        tokio::io::AsyncWriteExt::write_all(&mut a, &length(CONTROL_FRAME + 1))
            .await
            .unwrap();
        let read = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            read_frame::<Control>(&mut b),
        )
        .await
        .expect("refused before reading the frame's bytes");
        assert!(read.is_err());
        // A live frame, whose limit is its own, at the limit reads.
        let (mut a, mut b) = tokio::io::duplex(1 << 16);
        let full = LiveFrame(Bytes::try_from(vec![7; MAX_LIVE_SEALED]).unwrap());
        assert!(wire::encode(&full).unwrap().len() <= LIVE_FRAME);
        write_frame(&mut a, &full).await.unwrap();
        assert_eq!(read_frame::<LiveFrame>(&mut b).await.unwrap(), Some(full));
    }

    #[tokio::test]
    async fn frames_round_trip_and_refuse_what_is_cut_or_left_over() {
        let (mut a, mut b) = tokio::io::duplex(1 << 20);
        let messages =
            [0, 127, 128, 16_000].map(|n| LiveFrame(Bytes::try_from(vec![1; n]).unwrap()));
        let writer = tokio::spawn(async move {
            for message in &messages {
                write_frame(&mut a, message).await.unwrap();
            }
            messages
        });
        let mut read = Vec::new();
        while read.len() < 4 {
            read.push(read_frame::<LiveFrame>(&mut b).await.unwrap().unwrap());
        }
        let messages = writer.await.unwrap();
        assert_eq!(read, messages);
        // The end between frames is the end; inside one, an error.
        assert_eq!(read_frame::<LiveFrame>(&mut b).await.unwrap(), None);
        let (mut a, mut b) = tokio::io::duplex(64);
        tokio::io::AsyncWriteExt::write_all(&mut a, &[5, b'a'])
            .await
            .unwrap();
        drop(a);
        assert!(read_frame::<LiveFrame>(&mut b).await.is_err());
        // A frame holding a message and a byte more is refused.
        let denied = Control::Denied {
            reason: Text::truncated("no"),
        };
        let mut body = wire::encode(&denied).unwrap();
        body.push(0);
        let mut frame = length(body.len());
        frame.extend(body);
        let (mut a, mut b) = tokio::io::duplex(64);
        tokio::io::AsyncWriteExt::write_all(&mut a, &frame)
            .await
            .unwrap();
        assert!(read_frame::<Control>(&mut b).await.is_err());
    }
}
