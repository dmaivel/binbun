//! Windows' socket: a named pipe (`\\.\pipe\binbun-gui-<pid>[-<n>]-<random>`,
//! [`discovery::pipe`](crate::discovery::pipe)), through interprocess's
//! safe wrappers over the Win32 calls.
//!
//! Who may connect is the pipe's DACL ([`DACL`]): one entry, all access
//! for the pipe's owner (`OW`, the Owner Rights SID), so as a Unix socket
//! of mode 0600 is its owner's alone, the pipe is: the owner is the user
//! whose process made it (an administrator's elevated process makes its
//! objects the Administrators group's, as Windows does), and any other
//! user is refused when opening it (`ERROR_ACCESS_DENIED`, a
//! [`PermissionDenied`](io::ErrorKind::PermissionDenied) error). No one
//! else may make another instance of it either: that needs the same
//! access. Its first instance is made with `FILE_FLAG_FIRST_PIPE_INSTANCE`
//! (a name taken by another process before it is refused, never shared),
//! and every instance with `PIPE_REJECT_REMOTE_CLIENTS`: a client from
//! another machine (over SMB) is refused, the owner's own included.
//!
//! A stream's reads and writes go through Tokio's named pipes on one
//! thread of their own (`binbun-pipes`), so that a read waiting for the
//! peer can be given up: shutting a stream down, from any of its clones,
//! ends what its clones wait for and closes the pipe, as `shutdown` does
//! a Unix socket's.

use std::fmt;
use std::io::{self, Read, Write};
use std::net::Shutdown;
use std::os::windows::io::OwnedHandle;
use std::path::Path;
use std::sync::{Arc, LazyLock, Mutex, PoisonError};

use interprocess::os::windows::named_pipe::tokio::DuplexPipeStream as AsyncPipe;
use interprocess::os::windows::named_pipe::{
    DuplexPipeStream, PipeListener, PipeListenerOptions, pipe_mode,
};
use interprocess::os::windows::security_descriptor::SecurityDescriptor;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::runtime::{Builder, Runtime};
use tokio::sync::watch;
use widestring::U16CString;

/// The pipe's DACL in SDDL: protected from inheritance (`P`), one entry
/// allowing (`A`) all file access (`FA`) to the Owner Rights SID (`OW`).
const DACL: &str = "D:P(A;;FA;;;OW)";

/// The pipe's buffers each way: a frame of a few kilobytes goes whole.
const BUFFER: u32 = 64 * 1024;

/// The runtime that drives every pipe's reads and writes (its I/O
/// driver on one thread), made when the first stream is.
static RUNTIME: LazyLock<Result<Runtime, String>> = LazyLock::new(|| {
    Builder::new_multi_thread()
        .worker_threads(1)
        .thread_name("binbun-pipes")
        .enable_io()
        .build()
        .map_err(|error| error.to_string())
});

/// [`RUNTIME`], or why it could not be made.
fn runtime() -> io::Result<&'static Runtime> {
    RUNTIME
        .as_ref()
        .map_err(|error| io::Error::other(error.as_str()))
}

/// A pipe listened on.
#[derive(Debug)]
pub(crate) struct Listener(PipeListener<pipe_mode::Bytes, pipe_mode::Bytes>);

impl Listener {
    /// Makes the pipe named `pipe` (`\\.\pipe\…`), its first instance
    /// waiting for a client.
    pub(crate) fn bind(pipe: &Path) -> io::Result<Self> {
        let dacl = U16CString::from_str(DACL).map_err(io::Error::other)?;
        PipeListenerOptions::new()
            .path(pipe)
            .accept_remote(false)
            .security_descriptor(Some(SecurityDescriptor::deserialize(&dacl)?))
            .input_buffer_size_hint(BUFFER)
            .output_buffer_size_hint(BUFFER)
            .create_duplex::<pipe_mode::Bytes>()
            .map(Self)
    }

    /// Each client as it connects (each on an instance of its own; one
    /// more instance is made to wait for the next).
    pub(crate) fn incoming(&self) -> impl Iterator<Item = io::Result<Stream>> + '_ {
        self.0
            .incoming()
            .map(|accepted| accepted.and_then(Stream::new))
    }
}

/// A connection, either end; its clones share it.
#[derive(Clone, Debug)]
pub(crate) struct Stream(Arc<Shared>);

/// What a connection's clones share.
struct Shared {
    /// The pipe, until shut down. Each read or write holds it while it
    /// waits, so that it closes once the last one gives up.
    pipe: Mutex<Option<Arc<AsyncPipe<pipe_mode::Bytes>>>>,
    /// Set when shut down: what waits gives up.
    closed: watch::Sender<bool>,
}

impl fmt::Debug for Shared {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Shared")
            .field("closed", &*self.closed.borrow())
            .finish_non_exhaustive()
    }
}

impl Stream {
    /// `pipe`, connected, handed to the runtime.
    fn new(pipe: DuplexPipeStream<pipe_mode::Bytes>) -> io::Result<Self> {
        let handle = OwnedHandle::try_from(pipe)
            .map_err(|_| io::Error::other("a pipe's handle is shared"))?;
        let _entered = runtime()?.enter();
        let pipe = AsyncPipe::try_from(handle)?;
        Ok(Self(Arc::new(Shared {
            pipe: Mutex::new(Some(Arc::new(pipe))),
            closed: watch::Sender::new(false),
        })))
    }

    /// Connects to the pipe named `pipe`, waiting while all its instances
    /// are busy.
    pub(crate) fn connect(pipe: &Path) -> io::Result<Self> {
        Self::new(DuplexPipeStream::connect_by_path(pipe)?)
    }

    /// Another handle on the same connection.
    #[expect(
        clippy::unnecessary_wraps,
        reason = "as a Unix socket's, which can fail"
    )]
    pub(crate) fn try_clone(&self) -> io::Result<Self> {
        Ok(self.clone())
    }

    /// Ends the connection both ways (a pipe has no half closed): every
    /// clone's read waiting ends as at the end of the stream, its writes
    /// fail, and the pipe closes, so that the peer reads its end.
    #[expect(
        clippy::unnecessary_wraps,
        reason = "as a Unix socket's, which can fail"
    )]
    pub(crate) fn shutdown(&self, _how: Shutdown) -> io::Result<()> {
        self.0.closed.send_replace(true);
        drop(
            self.0
                .pipe
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .take(),
        );
        Ok(())
    }

    /// The pipe, unless shut down.
    fn pipe(&self) -> Option<Arc<AsyncPipe<pipe_mode::Bytes>>> {
        self.0
            .pipe
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

impl Read for Stream {
    /// As a Unix socket's: `0` at the end, the peer gone or the stream
    /// shut down.
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let Some(pipe) = self.pipe() else {
            return Ok(0);
        };
        let mut closed = self.0.closed.subscribe();
        runtime()?.block_on(async {
            let mut pipe = &*pipe;
            tokio::select! {
                read = pipe.read(buf) => read,
                _ = closed.wait_for(|&closed| closed) => Ok(0),
            }
        })
    }
}

impl Write for Stream {
    /// As a Unix socket's: written to the pipe, or
    /// [`BrokenPipe`](io::ErrorKind::BrokenPipe) once shut down.
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let pipe = self.pipe().ok_or(io::ErrorKind::BrokenPipe)?;
        let mut closed = self.0.closed.subscribe();
        runtime()?.block_on(async {
            let mut pipe = &*pipe;
            tokio::select! {
                written = pipe.write(buf) => written,
                _ = closed.wait_for(|&closed| closed) => Err(io::ErrorKind::BrokenPipe.into()),
            }
        })
    }

    /// Nothing: what is written is the pipe's already, as a Unix
    /// socket's. (The pipe's own flush would wait until the peer has read
    /// it all.)
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
