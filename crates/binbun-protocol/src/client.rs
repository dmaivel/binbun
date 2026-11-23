//! The client: a connection to a server's socket, the handshake made
//! ([`Client::connect`]); requests
//! sent from any thread and answered in any order ([`Client::send`],
//! [`Pending`]); notifications queued ([`Client::notification`]). A
//! reader thread takes the server's messages; the connection lost, every
//! request waiting fails with [`FaultKind::Connection`].

use std::collections::HashMap;
use std::io::{self, BufReader, BufWriter, ErrorKind};
use std::net::Shutdown;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread;
use std::time::Duration;

use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::fault::{Fault, FaultKind};
use crate::framing::{read_frame, write_frame};
use crate::handshake::{Initialize, Initialized};
use crate::messages::method;
use crate::rpc::Message;
use crate::socket::Stream;

/// What a request comes to.
type Outcome = Result<Value, Fault>;

/// The requests waiting for their responses, by number.
type Waiting = Arc<Mutex<HashMap<u64, Sender<Outcome>>>>;

/// A notification from the server.
#[derive(Clone, Debug, PartialEq)]
pub struct Notification {
    /// Its method (`event.history`...).
    pub method: String,
    /// Its parameters.
    pub params: Value,
}

/// A connection to a server.
#[derive(Debug)]
pub struct Client {
    stream: Stream,
    writer: Mutex<BufWriter<Stream>>,
    waiting: Waiting,
    next: AtomicU64,
    lost: Arc<AtomicBool>,
    notifications: Mutex<Receiver<Notification>>,
    initialized: Initialized,
}

/// A request sent, its response awaited.
#[derive(Debug)]
pub struct Pending {
    response: Receiver<Outcome>,
}

impl Pending {
    /// The response, if it comes within `timeout` (`None`: not yet).
    pub fn wait(&self, timeout: Duration) -> Option<Outcome> {
        match self.response.recv_timeout(timeout) {
            Ok(outcome) => Some(outcome),
            Err(RecvTimeoutError::Timeout) => None,
            Err(RecvTimeoutError::Disconnected) => Some(Err(gone())),
        }
    }

    /// The response, however long it takes.
    ///
    /// # Errors
    ///
    /// The server's fault; the connection lost.
    pub fn get(self) -> Outcome {
        self.response.recv().unwrap_or_else(|_| Err(gone()))
    }
}

/// The connection lost.
fn gone() -> Fault {
    Fault::new(
        FaultKind::Connection,
        "the connection to the server was lost",
    )
}

/// `error` reaching `socket` as a fault: refused access is
/// [`FaultKind::Permission`].
fn unreachable(socket: &Path, error: &io::Error) -> Fault {
    let kind = if error.kind() == ErrorKind::PermissionDenied {
        FaultKind::Permission
    } else {
        FaultKind::Connection
    };
    Fault::new(kind, format!("{}: {error}", socket.display()))
}

impl Client {
    /// Connects to the server at `socket` and makes the handshake.
    ///
    /// # Errors
    ///
    /// The socket is another user's ([`FaultKind::Permission`]) or cannot
    /// be reached ([`FaultKind::Connection`]); the server refuses the
    /// handshake (no common version: [`FaultKind::Version`]; no such
    /// database: [`FaultKind::Ambiguous`]).
    pub fn connect(socket: &Path, initialize: &Initialize) -> Result<Self, Fault> {
        let stream = Stream::connect(socket).map_err(|error| unreachable(socket, &error))?;
        let (incoming, outgoing) = match (stream.try_clone(), stream.try_clone()) {
            (Ok(incoming), Ok(outgoing)) => (incoming, outgoing),
            (Err(error), _) | (_, Err(error)) => return Err(unreachable(socket, &error)),
        };
        let waiting: Waiting = Arc::default();
        let lost = Arc::new(AtomicBool::new(false));
        let (notify, notifications) = mpsc::channel();
        {
            let waiting = Arc::clone(&waiting);
            let lost = Arc::clone(&lost);
            thread::Builder::new()
                .name("binbun-client".to_owned())
                .spawn(move || read(incoming, &waiting, &lost, &notify))
                .map_err(|error| Fault::new(FaultKind::Binbun, error.to_string()))?;
        }
        let mut client = Self {
            stream,
            writer: Mutex::new(BufWriter::new(outgoing)),
            waiting,
            next: AtomicU64::new(1),
            lost,
            notifications: Mutex::new(notifications),
            initialized: Initialized::default(),
        };
        client.initialized = client.call(method::INITIALIZE, initialize)?;
        Ok(client)
    }

    /// What the handshake said.
    pub const fn initialized(&self) -> &Initialized {
        &self.initialized
    }

    /// Whether the server has `capability`.
    pub fn has(&self, capability: &str) -> bool {
        self.initialized
            .capabilities
            .iter()
            .any(|have| have == capability)
    }

    /// Whether the connection is lost.
    pub fn is_lost(&self) -> bool {
        self.lost.load(Ordering::Relaxed)
    }

    fn writer(&self) -> MutexGuard<'_, BufWriter<Stream>> {
        self.writer.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Sends request `method` with `params`; its response to wait for.
    ///
    /// # Errors
    ///
    /// The connection is lost.
    pub fn send(&self, method: &str, params: impl Serialize) -> Result<Pending, Fault> {
        let params = serde_json::to_value(params)
            .map_err(|error| Fault::new(FaultKind::Protocol, error.to_string()))?;
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        let (sender, response) = mpsc::channel();
        self.waiting
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(id, sender);
        if self.is_lost() {
            return Err(gone());
        }
        let bytes = Message::request(id, method, params).to_bytes()?;
        if write_frame(&mut *self.writer(), &bytes).is_err() {
            self.waiting
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .remove(&id);
            return Err(gone());
        }
        Ok(Pending { response })
    }

    /// Request `method` with `params`, its result read as `R`, however
    /// long it takes.
    ///
    /// # Errors
    ///
    /// The server's fault; the connection lost; a result that is no `R`
    /// ([`FaultKind::Protocol`]).
    pub fn call<R: DeserializeOwned>(
        &self,
        method: &str,
        params: impl Serialize,
    ) -> Result<R, Fault> {
        read_as(self.send(method, params)?.get()?)
    }

    /// The next notification, if one comes within `timeout`.
    pub fn notification(&self, timeout: Duration) -> Option<Notification> {
        self.notifications
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .recv_timeout(timeout)
            .ok()
    }

    /// Ends the connection (the server rolls back a transaction left
    /// open).
    pub fn close(&self) {
        let _ = self.stream.shutdown(Shutdown::Both);
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        self.close();
    }
}

/// `value` read as `R`.
///
/// # Errors
///
/// It is no `R` ([`FaultKind::Protocol`]).
pub fn read_as<R: DeserializeOwned>(value: Value) -> Result<R, Fault> {
    serde_json::from_value(value).map_err(|error| {
        Fault::new(
            FaultKind::Protocol,
            format!("an unexpected result: {error}"),
        )
    })
}

/// Takes the server's messages until the connection ends: responses to
/// their requests, notifications to the queue; then fails every request
/// still waiting.
fn read(stream: Stream, waiting: &Waiting, lost: &AtomicBool, notify: &Sender<Notification>) {
    let mut reader = BufReader::new(stream);
    while let Ok(Some(bytes)) = read_frame(&mut reader) {
        let Ok(message) = Message::from_bytes(&bytes) else {
            continue;
        };
        if let Some(method) = message.method {
            let _ = notify.send(Notification {
                method,
                params: message.params.unwrap_or(Value::Null),
            });
            continue;
        }
        let Some(id) = message.id else { continue };
        let outcome = match message.error {
            Some(error) => Err(error.into_fault()),
            None => Ok(message.result.unwrap_or(Value::Null)),
        };
        let sender = waiting
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&id);
        if let Some(sender) = sender {
            let _ = sender.send(outcome);
        }
    }
    lost.store(true, Ordering::Relaxed);
    for (_, sender) in waiting
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .drain()
    {
        let _ = sender.send(Err(gone()));
    }
}
