//! The socket under [`server`](crate::server) and
//! [`client`](crate::client): a Unix socket on Linux and macOS; on
//! Windows a named pipe whose DACL admits the pipe's owner only, and no
//! client from another machine (`pipe`). Both are a listener whose
//! connections are streams, cloned for a reader and a writer and shut
//! down from either side.

#[cfg(unix)]
pub(crate) use std::os::unix::net::{UnixListener as Listener, UnixStream as Stream};

#[cfg(windows)]
mod pipe;

#[cfg(windows)]
pub(crate) use pipe::{Listener, Stream};
