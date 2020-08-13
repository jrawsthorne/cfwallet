use bitcoin::{
    consensus::{deserialize_partial, encode, Encodable},
    network::{
        constants::ServiceFlags,
        message::{NetworkMessage, RawNetworkMessage},
        message_blockdata::GetHeadersMessage,
        message_filter::GetCFHeaders,
        message_network::VersionMessage,
        Address,
    },
    BlockHash, Network,
};
use bytes::Buf;
use bytes::BytesMut;
use io::ErrorKind;
use log::{debug, error, info, trace};
use std::{
    io,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::prelude::*;
use tokio::{
    net::TcpStream,
    sync::{mpsc, oneshot},
    task::JoinHandle,
};

pub type OutgoingSender = mpsc::UnboundedSender<(NetworkMessage, Option<oneshot::Sender<()>>)>;
pub type OutgoingReceiver = mpsc::UnboundedReceiver<(NetworkMessage, Option<oneshot::Sender<()>>)>;

pub type IncomingSender = mpsc::Sender<NetworkMessage>;

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum ConnectionType {
    Inbound,
    Outbound,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum HandshakeState {
    WaitingForVersion,
    WaitingForVerack,
    Complete,
}

impl Default for HandshakeState {
    fn default() -> Self {
        HandshakeState::WaitingForVersion
    }
}

pub struct Peer {
    outgoing_tx: OutgoingSender,
    pub addr: SocketAddr,
    connection_type: ConnectionType,
    network: Network,
    state: Mutex<State>,
}

#[derive(Default)]
pub struct State {
    handshake_state: HandshakeState,
}

impl Peer {
    pub fn new(
        incoming_tx: IncomingSender,
        stream: TcpStream,
        network: Network,
        connection_type: ConnectionType,
    ) -> (Arc<Self>, JoinHandle<()>) {
        stream.set_nodelay(true).unwrap();
        let (outgoing_tx, outgoing_rx) = mpsc::unbounded_channel();
        let peer = Arc::new(Self {
            addr: stream.peer_addr().unwrap(),
            outgoing_tx,
            connection_type,
            network,
            state: Mutex::new(State::default()),
        });
        let peer2 = Arc::clone(&peer);
        let jh = tokio::spawn(peer2.run(stream, outgoing_rx, incoming_tx));
        (peer, jh)
    }

    pub fn send(&self, message: NetworkMessage) {
        self.outgoing_tx.send((message, None)).unwrap();
    }

    pub async fn send_and_wait(&self, message: NetworkMessage) {
        let (tx, rx) = oneshot::channel();
        self.outgoing_tx.send((message, Some(tx))).unwrap();
        rx.await.unwrap();
    }

    pub fn send_version(&self) {
        use std::net::{IpAddr, Ipv4Addr};

        let version = VersionMessage {
            version: 70015,
            services: ServiceFlags::WITNESS,
            timestamp: 0,
            receiver: Address::new(&self.addr, ServiceFlags::NONE),
            sender: Address::new(
                &SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0),
                ServiceFlags::NONE,
            ),
            nonce: 0,
            user_agent: "/rust_bitcoin_node:0.1.0/".to_string(),
            start_height: 0,
            relay: false,
        };

        self.send(NetworkMessage::Version(version));
    }

    pub fn send_get_headers(&self, locator_hashes: Vec<BlockHash>, stop_hash: Option<BlockHash>) {
        self.send(NetworkMessage::GetHeaders(GetHeadersMessage::new(
            locator_hashes,
            stop_hash.unwrap_or_default(),
        )));
    }

    pub fn send_get_cf_headers(&self, start_height: u32, stop_hash: BlockHash) {
        self.send(NetworkMessage::GetCFHeaders(GetCFHeaders {
            filter_type: 0,
            start_height,
            stop_hash,
        }));
    }

    pub async fn handle_message(
        self: &Arc<Self>,
        message: NetworkMessage,
        incoming_tx: &mut IncomingSender,
    ) {
        if self.state.lock().unwrap().handshake_state != HandshakeState::Complete {
            // only handle verack and version before handshake complete
            match &message {
                NetworkMessage::Version(_) => {}
                NetworkMessage::Verack => {}
                _ => {
                    panic!("msg before handshake");
                    // TODO: disconnect
                }
            }
        }
        match &message {
            NetworkMessage::Version(version) => {
                let required_services =
                    ServiceFlags::WITNESS | ServiceFlags::NETWORK | ServiceFlags::COMPACT_FILTERS;

                assert!(
                    version.services.has(required_services),
                    "peer doesn't support required services"
                );

                let mut state = self.state.lock().unwrap();
                if state.handshake_state != HandshakeState::WaitingForVersion {
                    // TODO: disconnect
                    panic!("bad handshake: unexpected version ({})", self.addr);
                }
                state.handshake_state = HandshakeState::WaitingForVerack;
                info!(
                    "received version={} services={} start_height={} user_agent={} relay={} ({})",
                    version.version,
                    version.services,
                    version.start_height,
                    version.user_agent,
                    version.relay,
                    self.addr
                );

                if self.connection_type == ConnectionType::Inbound {
                    self.send_version();
                }

                self.send(NetworkMessage::Verack);
            }

            NetworkMessage::Verack => {
                let mut state = self.state.lock().unwrap();
                if state.handshake_state != HandshakeState::WaitingForVerack {
                    // TODO: disconnect
                    todo!("bad handshake: unexpected verack ({})", self.addr);
                }
                state.handshake_state = HandshakeState::Complete;
                debug!("handshake complete ({})", self.addr);
            }

            NetworkMessage::Ping(nonce) => {
                self.send(NetworkMessage::Pong(*nonce));
            }

            _ => {}
        }
        incoming_tx.send(message).await.unwrap();
    }

    pub async fn run(
        self: Arc<Self>,
        mut stream: TcpStream,
        mut outgoing_rx: OutgoingReceiver,
        mut incoming_tx: IncomingSender,
    ) {
        let (mut r, mut w) = stream.split();

        let mut read_buf = BytesMut::new();
        let mut write_buf = Vec::new();
        let magic = self.network.magic();

        if let ConnectionType::Outbound = self.connection_type {
            self.send_version();
        }

        {
            let peer = Arc::clone(&self);
            tokio::spawn(async move {
                tokio::time::delay_for(Duration::from_secs(10)).await;
                if peer.state.lock().unwrap().handshake_state != HandshakeState::Complete {
                    todo!("handshake timeout");
                    // TODO: Disconnect
                }
            });
        }

        let incoming = async {
            loop {
                match deserialize_partial::<RawNetworkMessage>(&read_buf[..]) {
                    Ok((message, n)) => {
                        read_buf.advance(n);
                        assert_eq!(message.magic, magic);
                        trace!("received {} ({} bytes) ({})", message.cmd(), n, self.addr);
                        self.handle_message(message.payload, &mut incoming_tx).await;
                    }
                    Err(err) => match err {
                        encode::Error::UnrecognizedNetworkCommand(_) => {
                            // ignore
                        }
                        encode::Error::Io(err) if err.kind() == ErrorKind::UnexpectedEof => {
                            // read more
                            r.read_buf(&mut read_buf).await.unwrap();
                        }
                        _ => {
                            error!("message handling error");
                            break;
                        }
                    },
                }
            }
            trace!("incoming finished");
        };

        let outgoing = async {
            while let Some((payload, done)) = outgoing_rx.recv().await {
                let message = RawNetworkMessage { magic, payload };

                message.consensus_encode(&mut write_buf).unwrap();
                w.write_all(&write_buf).await.unwrap();
                let len = write_buf.len();
                write_buf.clear();
                w.flush().await.unwrap();

                trace!("sent {} ({} bytes) ({})", message.cmd(), len, self.addr);

                if let Some(done) = done {
                    let _ = done.send(());
                }
            }
            trace!("outgoing finished");
        };

        tokio::join!(incoming, outgoing);

        trace!("peer finished");
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn test_handshake() {
        env_logger::builder()
            .format_timestamp_millis()
            .is_test(true)
            .init();

        let (tx1, mut rx1) = mpsc::channel(1);
        let (tx2, mut rx2) = mpsc::channel(1);

        let mut listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listener_addr = listener.local_addr().unwrap();

        let jh = tokio::spawn(async move { listener.accept().await.unwrap() });

        let stream2 = TcpStream::connect(listener_addr).await.unwrap();

        let (stream1, _) = jh.await.unwrap();

        let (peer1, _) = Peer::new(tx1, stream1, Network::Regtest, ConnectionType::Inbound);
        let (peer2, _) = Peer::new(tx2, stream2, Network::Regtest, ConnectionType::Outbound);

        assert_eq!(rx1.recv().await.unwrap().cmd(), "version");
        assert_eq!(rx2.recv().await.unwrap().cmd(), "version");
        assert_eq!(rx1.recv().await.unwrap().cmd(), "verack");
        assert_eq!(rx2.recv().await.unwrap().cmd(), "verack");

        assert_eq!(
            peer1.state.lock().unwrap().handshake_state,
            HandshakeState::Complete
        );

        assert_eq!(
            peer2.state.lock().unwrap().handshake_state,
            HandshakeState::Complete
        );
    }
}
