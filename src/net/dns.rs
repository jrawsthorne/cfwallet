use bitcoin::Network;
use log::{info, trace};
use std::net::SocketAddr;
use tokio::net::lookup_host;

const MAIN_SEEDER: [&str; 5] = [
    "seed.bitcoin.sipa.be",
    "dnsseed.bluematt.me",
    "dnsseed.bitcoin.dashjr.org",
    "seed.bitcoinstats.com",
    "seed.btc.petertodd.org",
];

const TEST_SEEDER: [&str; 4] = [
    "testnet-seed.bitcoin.jonasschnelli.ch",
    "seed.tbtc.petertodd.org",
    "seed.testnet.bitcoin.sprovoost.nl",
    "testnet-seed.bluematt.me",
];

pub async fn dns_seeds(network: Network) -> Vec<SocketAddr> {
    let mut addrs = vec![];

    if network == Network::Bitcoin {
        info!("reaching out for DNS seed...");
        for seedhost in MAIN_SEEDER.iter() {
            if let Ok(lookup) = lookup_host((*seedhost, 8333)).await {
                for host in lookup {
                    addrs.push(host);
                }
            } else {
                trace!("{} did not answer", seedhost);
            }
        }
        info!("received {} DNS seeds", addrs.len());
    }
    if network == Network::Testnet {
        info!("reaching out for DNS seed...");
        for seedhost in TEST_SEEDER.iter() {
            if let Ok(lookup) = lookup_host((*seedhost, 18333)).await {
                for host in lookup {
                    addrs.push(host);
                }
            } else {
                trace!("{} did not answer", seedhost);
            }
        }
        info!("received {} DNS seeds", addrs.len());
    }

    addrs
}
