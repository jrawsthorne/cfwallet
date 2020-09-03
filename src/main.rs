use bitcoin::{network::constants::ServiceFlags, Network};
use cfwallet::{net::*, wallet::create_master_account};
use std::{net::SocketAddr, str::FromStr, sync::Arc};
use tokio::{
    net::TcpStream,
    sync::{mpsc, Mutex},
};

#[tokio::main]
async fn main() {
    env_logger::builder().format_timestamp_millis().init();

    let args: Vec<_> = std::env::args().skip(1).collect();
    let network = Network::Testnet;
    let addrs: Vec<SocketAddr> = args
        .get(0)
        .expect("enter an IP address")
        .split(",")
        .map(str::parse)
        .collect::<Result<Vec<_>, _>>()
        .expect("invalid IP address");

    let extended_pubkeys = args
        .get(1)
        .expect("enter comma separated (x/y/z)pubs")
        .split(",")
        .map(FromStr::from_str)
        .collect::<Result<Vec<_>, _>>()
        .expect("invalid (x/y/z)pub");

    let master_account = create_master_account(extended_pubkeys, network);

    let p2p = Arc::new(Mutex::new(P2P::new(network, master_account)));

    let mut handles = vec![];

    {
        let mut locked_p2p = p2p.lock().await;
        for addr in addrs {
            let stream = TcpStream::connect(addr).await.unwrap();
            let (tx, mut rx) = mpsc::channel(1);
            let (peer, jh) = Peer::new(
                tx,
                stream,
                network,
                ConnectionType::Outbound,
                ServiceFlags::WITNESS | ServiceFlags::COMPACT_FILTERS | ServiceFlags::NETWORK,
            );
            handles.push(jh);
            {
                let peer = Arc::clone(&peer);
                let p2p = Arc::clone(&p2p);
                tokio::spawn(async move {
                    while let Some(message) = rx.recv().await {
                        p2p.lock().await.handle_message(&peer, message).await;
                    }
                });
            }

            locked_p2p.filter_peers.insert(peer.addr, Arc::clone(&peer));
            locked_p2p.block_peers.insert(peer.addr, Arc::clone(&peer));
            locked_p2p.peers.insert(peer.addr, peer);
        }
    }

    for handle in handles {
        handle.await.unwrap();
    }
}
