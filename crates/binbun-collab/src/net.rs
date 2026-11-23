//! The [`Transport`] on iroh:
//! QUIC with TLS keyed by the identity's ed25519 key (the endpoint's id is
//! the identity key), dialled by key over direct addresses, hole punching
//! and relays, on ALPN `binbun/collab/1`.
//!
//! Relays ([`Relay`]): binbun's ([`BINBUN_RELAY`], the default), n0's
//! public ones (development only: rate-limited, no guarantees) with n0's
//! address lookup (pkarr over DNS), a custom list, or none (tickets carry
//! direct addresses). Local discovery
//! (mDNS) is opt-in; port mapping (`UPnP`, PCP, NAT-PMP) is on unless
//! turned off, as on a LAN only, where it would take the path off the LAN
//! to the router's public address.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use binbun_bounded::{Bounded, Text};
use binbun_session::journal::PublicKey;
use iroh::endpoint::{Connection, PortmapperConfig, VarInt, presets};
use iroh::{
    Endpoint, EndpointAddr, EndpointId, RelayMode, RelayUrl, SecretKey, TransportAddr, Watcher,
};
use iroh_mdns_address_lookup::MdnsAddressLookupBuilder;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::task::AbortHandle;

use crate::Error;
use crate::budgets::{Budgets, STRANGERS, Stranger};
use crate::ticket::PeerAddr;
use crate::transport::{BoxFuture, Lane, Link, RecvStream, SendStream, Transport};
use crate::wire::ALPN;

/// binbun's relay's URL.
pub const BINBUN_RELAY: &str = "https://us-east.relay.binbun.org";

/// Which relays an endpoint uses.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Relay {
    /// binbun's relay, [`BINBUN_RELAY`].
    Binbun,
    /// n0's public relays and address lookup.
    N0,
    /// These relays (URLs).
    Custom(Vec<String>),
    /// None: direct addresses only.
    Disabled,
}

impl Relay {
    /// `binbun`, `n0`, `none`, or a relay's URL.
    ///
    /// # Errors
    ///
    /// Not one of those.
    pub fn parse(text: &str) -> Result<Self, Error> {
        match text {
            "binbun" => Ok(Self::Binbun),
            "n0" => Ok(Self::N0),
            "none" => Ok(Self::Disabled),
            url => {
                url.parse::<RelayUrl>()
                    .map_err(|error| Error::new(format!("not a relay URL {url:?}: {error}")))?;
                Ok(Self::Custom(vec![url.to_owned()]))
            }
        }
    }
}

/// How an endpoint is made.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetOptions {
    /// Its relays.
    pub relay: Relay,
    /// Whether it finds and is found by peers on the LAN (mDNS).
    pub mdns: bool,
    /// Whether it asks the router to map a public port to it (`UPnP`, PCP,
    /// NAT-PMP).
    pub portmap: bool,
    /// The one address to bind (its port 0: any), else every interface.
    pub bind: Option<SocketAddr>,
}

impl Default for NetOptions {
    fn default() -> Self {
        Self {
            relay: Relay::Binbun,
            mdns: false,
            portmap: true,
            bind: None,
        }
    }
}

/// How long binding waits to be reachable (a relay, or an address).
const ONLINE: Duration = Duration::from_secs(10);

/// An iroh endpoint as a [`Transport`].
#[derive(Debug)]
pub struct IrohTransport {
    endpoint: Endpoint,
    /// Connections whose handshake finished: each is completed on a task
    /// of its own, so a slow one holds up no other; each still holds the
    /// place in the stranger pool its handshake took.
    accepted: tokio::sync::Mutex<mpsc::Receiver<(Connection, Stranger)>>,
    /// The task taking incoming connections.
    acceptor: AbortHandle,
    /// The process's ([`Budgets::process`]).
    budgets: Budgets,
}

impl Drop for IrohTransport {
    fn drop(&mut self) {
        self.acceptor.abort();
    }
}

impl IrohTransport {
    /// The transport of `endpoint`, its incoming connections taken: each
    /// handshake holds a place in the stranger pool (none free, the
    /// connection is turned away) and is given up at its deadline; the
    /// place goes with the connection to its link ([`Link::stranger`]),
    /// held while it waits to be taken.
    fn new(endpoint: Endpoint) -> Self {
        let budgets = Budgets::process();
        let (done, accepted) = mpsc::channel(STRANGERS);
        let incoming = endpoint.clone();
        let strangers = budgets.clone();
        let acceptor = tokio::spawn(async move {
            while let Some(connecting) = incoming.accept().await {
                let Some(stranger) = strangers.stranger() else {
                    connecting.refuse();
                    continue;
                };
                // A stray packet: the next.
                let Ok(accepting) = connecting.accept() else {
                    continue;
                };
                let done = done.clone();
                tokio::spawn(async move {
                    let by = stranger.deadline();
                    let handshake = async {
                        if let Ok(connection) = accepting.await {
                            let _ = done.send((connection, stranger)).await;
                        }
                    };
                    let _ = by.within(handshake).await;
                });
            }
        })
        .abort_handle();
        Self {
            endpoint,
            accepted: tokio::sync::Mutex::new(accepted),
            acceptor,
            budgets,
        }
    }

    /// An endpoint keyed by `secret` (the identity's signing key) per
    /// `options`, once reachable: a relay connected, or (without relays) a
    /// direct address known; or after 10 s.
    ///
    /// # Errors
    ///
    /// A relay URL or bind address that does not work; no socket.
    pub async fn bind(secret: &[u8; 32], options: &NetOptions) -> Result<Self, Error> {
        let mut builder = match &options.relay {
            Relay::Binbun => {
                let url = BINBUN_RELAY
                    .parse::<RelayUrl>()
                    .map_err(|error| Error::new(error.to_string()))?;
                Endpoint::builder(presets::Minimal).relay_mode(RelayMode::custom([url]))
            }
            Relay::N0 => Endpoint::builder(presets::N0),
            Relay::Custom(urls) => {
                let urls = urls
                    .iter()
                    .map(|url| url.parse::<RelayUrl>())
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|error| Error::new(error.to_string()))?;
                Endpoint::builder(presets::Minimal).relay_mode(RelayMode::custom(urls))
            }
            Relay::Disabled => Endpoint::builder(presets::Minimal).relay_mode(RelayMode::Disabled),
        }
        .secret_key(SecretKey::from_bytes(secret))
        .alpns(vec![ALPN.to_vec()]);
        if let Some(addr) = options.bind {
            builder = builder
                .clear_ip_transports()
                .bind_addr(addr)
                .map_err(|error| Error::new(format!("cannot bind {addr}: {error}")))?;
        }
        if options.mdns {
            builder = builder.address_lookup(MdnsAddressLookupBuilder::default());
        }
        if !options.portmap {
            builder = builder.portmapper_config(PortmapperConfig::Disabled);
        }
        let endpoint = builder
            .bind()
            .await
            .map_err(|error| Error::new(format!("cannot make the endpoint: {error}")))?;
        let reachable = async {
            if options.relay == Relay::Disabled {
                let mut addr = endpoint.watch_addr();
                while addr.get().ip_addrs().next().is_none() {
                    if addr.updated().await.is_err() {
                        return;
                    }
                }
            } else {
                endpoint.online().await;
            }
        };
        let _ = tokio::time::timeout(ONLINE, reachable).await;
        Ok(Self::new(endpoint))
    }

    /// An endpoint made elsewhere (its own relays, transports, trust),
    /// as a transport: its ALPNs must include [`ALPN`], and its key is
    /// the identity's.
    pub fn from_endpoint(endpoint: Endpoint) -> Self {
        Self::new(endpoint)
    }
}

/// `key` as binbun's.
fn ours(key: EndpointId) -> PublicKey {
    PublicKey(*key.as_bytes())
}

impl Transport for IrohTransport {
    fn id(&self) -> PublicKey {
        ours(self.endpoint.id())
    }

    fn addr(&self) -> PeerAddr {
        let addr = self.endpoint.addr();
        PeerAddr {
            id: ours(addr.id),
            // A relay URL past the bound is left out, never cut.
            relay: addr
                .relay_urls()
                .next()
                .and_then(|url| Text::try_from(url.to_string()).ok()),
            direct: Bounded::truncated(addr.ip_addrs().copied().collect()),
        }
    }

    fn connect<'a>(&'a self, to: &'a PeerAddr) -> BoxFuture<'a, Result<Arc<dyn Link>, Error>> {
        Box::pin(async move {
            let id = EndpointId::from_bytes(&to.id.0)
                .map_err(|error| Error::new(format!("not a peer key: {error}")))?;
            let relay = to
                .relay
                .as_deref()
                .and_then(|url| url.parse::<RelayUrl>().ok())
                .map(TransportAddr::Relay);
            let addrs = to
                .direct
                .iter()
                .copied()
                .map(TransportAddr::Ip)
                .chain(relay);
            let connection = self
                .endpoint
                .connect(EndpointAddr::from_parts(id, addrs), ALPN)
                .await
                .map_err(|error| Error::new(format!("cannot reach {}: {error}", to.id)))?;
            Ok(Arc::new(IrohLink {
                connection,
                endpoint: self.endpoint.clone(),
                stranger: std::sync::Mutex::new(None),
            }) as Arc<dyn Link>)
        })
    }

    fn accept(&self) -> BoxFuture<'_, Option<Arc<dyn Link>>> {
        Box::pin(async move {
            let (connection, stranger) = self.accepted.lock().await.recv().await?;
            Some(Arc::new(IrohLink {
                connection,
                endpoint: self.endpoint.clone(),
                stranger: std::sync::Mutex::new(Some(stranger)),
            }) as Arc<dyn Link>)
        })
    }

    fn close(&self) -> BoxFuture<'_, ()> {
        Box::pin(self.endpoint.close())
    }

    fn budgets(&self) -> &Budgets {
        &self.budgets
    }
}

/// A QUIC connection as a [`Link`].
#[derive(Debug)]
struct IrohLink {
    connection: Connection,
    /// The endpoint it is of: its own addresses tell a path within this
    /// machine.
    endpoint: Endpoint,
    /// The place in the stranger pool its handshake took, until handed
    /// over ([`Link::stranger`]): accepted links only.
    stranger: std::sync::Mutex<Option<Stranger>>,
}

impl Link for IrohLink {
    fn remote(&self) -> PublicKey {
        ours(self.connection.remote_id())
    }

    fn open(&self, lane: Lane) -> BoxFuture<'_, Result<(SendStream, RecvStream), Error>> {
        Box::pin(async move {
            let (mut send, recv) = self
                .connection
                .open_bi()
                .await
                .map_err(|error| Error::new(error.to_string()))?;
            send.write_u8(lane.byte()).await?;
            Ok((Box::new(send) as SendStream, Box::new(recv) as RecvStream))
        })
    }

    fn accept(&self) -> BoxFuture<'_, Result<(Lane, SendStream, RecvStream), Error>> {
        Box::pin(async move {
            let (send, mut recv) = self
                .connection
                .accept_bi()
                .await
                .map_err(|error| Error::new(error.to_string()))?;
            let byte = recv.read_u8().await?;
            let lane = Lane::of(byte).ok_or_else(|| Error::new(format!("no lane {byte}")))?;
            Ok((
                lane,
                Box::new(send) as SendStream,
                Box::new(recv) as RecvStream,
            ))
        })
    }

    fn path(&self) -> String {
        let paths = self.connection.paths();
        let own = self.endpoint.addr();
        let described: Vec<String> = paths
            .iter()
            .map(|path| {
                let addr = match path.remote_addr() {
                    TransportAddr::Relay(url) => format!("relay {url}"),
                    // Before the tailnet's: this machine's own tailnet
                    // address is reached without the tailnet.
                    TransportAddr::Ip(addr) if this_machine(addr.ip(), &own) => {
                        format!("direct {addr} (loopback)")
                    }
                    TransportAddr::Ip(addr) if tailnet(addr.ip()) => {
                        format!("direct {addr} (tailnet)")
                    }
                    TransportAddr::Ip(addr) => format!("direct {addr}"),
                    other @ (TransportAddr::Custom(_) | _) => format!("{other:?}"),
                };
                let rtt = path.rtt().as_secs_f64() * 1000.0;
                let mark = if path.is_selected() { "*" } else { "" };
                format!("{mark}{addr} ({rtt:.1} ms)")
            })
            .collect();
        if described.is_empty() {
            "no path".to_owned()
        } else {
            described.join(", ")
        }
    }

    fn close(&self, reason: &str) {
        self.connection
            .close(VarInt::from_u32(0), reason.as_bytes());
    }

    fn closed(&self) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            self.connection.closed().await;
        })
    }

    fn send_datagram(&self, bytes: Vec<u8>) -> Result<(), Error> {
        self.connection
            .send_datagram(bytes.into())
            .map_err(|error| Error::new(error.to_string()))
    }

    fn recv_datagram(&self) -> BoxFuture<'_, Result<Vec<u8>, Error>> {
        Box::pin(async move {
            self.connection
                .read_datagram()
                .await
                .map(Vec::from)
                .map_err(|error| Error::new(error.to_string()))
        })
    }

    fn stranger(&self) -> Option<Stranger> {
        self.stranger
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
    }
}

/// Whether `ip` is this machine's: a loopback address or one of `own`'s
/// (the endpoint's) direct addresses. A working path to it never leaves
/// the machine, whatever network the address is of (a second window on
/// one machine reaching the first at its own tailnet address).
fn this_machine(ip: IpAddr, own: &EndpointAddr) -> bool {
    let ip = ip.to_canonical();
    ip.is_loopback() || own.ip_addrs().any(|a| a.ip().to_canonical() == ip)
}

/// Whether `ip` is on a tailnet (`100.64.0.0/10`, `fd7a:115c:a1e0::/48`).
fn tailnet(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, ..] = v4.octets();
            a == 100 && (64..128).contains(&b)
        }
        IpAddr::V6(v6) => {
            let [a, b, c, ..] = v6.segments();
            a == 0xfd7a && b == 0x115c && c == 0xa1e0
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use iroh::{EndpointAddr, SecretKey, TransportAddr};

    use super::{IrohTransport, NetOptions, Relay, tailnet, this_machine};
    use crate::Transport;
    use crate::budgets::{Budgets, STRANGERS};

    /// An endpoint on loopback keyed by `seed`, no relay.
    async fn local(seed: u8) -> IrohTransport {
        let options = NetOptions {
            relay: Relay::Disabled,
            mdns: false,
            portmap: false,
            bind: Some(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))),
        };
        IrohTransport::bind(&[seed; 32], &options).await.unwrap()
    }

    /// The place in the stranger pool an accepted connection's handshake
    /// took is held while it waits to be taken and goes with its link,
    /// handed over once: no gap between the handshake and the hello for
    /// another to take it. A link dialled has none. (The only test of
    /// this binary on the process's budgets.)
    #[tokio::test]
    async fn an_accepted_link_keeps_its_handshake_s_place_in_the_stranger_pool() {
        let free = || Budgets::process().strangers_free();
        let (host, guest) = (local(1).await, local(2).await);
        let dialled = guest.connect(&host.addr()).await.unwrap();
        let accepted = host.accept().await.unwrap();
        assert_eq!(free(), STRANGERS - 1);
        let place = accepted.stranger().unwrap();
        assert!(accepted.stranger().is_none());
        assert_eq!(free(), STRANGERS - 1);
        drop(place);
        assert_eq!(free(), STRANGERS);
        assert!(dialled.stranger().is_none());
        guest.close().await;
        host.close().await;
    }

    /// `binbun`, `n0` and `none` name their relays, a URL is a custom
    /// relay, anything else is refused; the default is binbun's.
    #[test]
    fn relays_parse_by_name_or_url() {
        assert_eq!(Relay::parse("binbun").unwrap(), Relay::Binbun);
        assert_eq!(Relay::parse("n0").unwrap(), Relay::N0);
        assert_eq!(Relay::parse("none").unwrap(), Relay::Disabled);
        assert_eq!(
            Relay::parse("https://relay.example.org").unwrap(),
            Relay::Custom(vec!["https://relay.example.org".to_owned()])
        );
        assert!(Relay::parse("not a relay").is_err());
        assert_eq!(NetOptions::default().relay, Relay::Binbun);
    }

    /// A path to one of this machine's own addresses is within it, its
    /// tailnet address too (two windows on one machine); another
    /// machine's tailnet address is the tailnet.
    #[test]
    fn a_path_to_an_own_address_is_this_machine_not_the_tailnet() {
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        let at = |s: &str| TransportAddr::Ip(s.parse::<SocketAddr>().unwrap());
        let own = EndpointAddr::from_parts(
            SecretKey::from_bytes(&[7; 32]).public(),
            [at("192.168.1.101:40001"), at("100.67.192.16:40002")],
        );
        assert!(this_machine(ip("100.67.192.16"), &own));
        assert!(this_machine(ip("::ffff:192.168.1.101"), &own));
        assert!(this_machine(ip("127.0.0.1"), &own));
        assert!(!this_machine(ip("100.67.1.2"), &own));
        assert!(tailnet(ip("100.67.1.2")));
        assert!(!this_machine(ip("192.168.1.5"), &own));
        assert!(!tailnet(ip("100.128.0.1")));
        assert!(tailnet(ip("fd7a:115c:a1e0::1")));
    }
}
