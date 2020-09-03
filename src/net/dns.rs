use bitcoin::{network::constants::ServiceFlags, Network};
use log::{info, trace};
use std::net::SocketAddr;
use tokio::net::lookup_host;

const MAIN_SEEDER: [&str; 9] = [
    "seed.bitcoin.sipa.be",
    "dnsseed.bluematt.me",
    "dnsseed.bitcoin.dashjr.org",
    "seed.bitcoinstats.com",
    "seed.bitcoin.jonasschnelli.ch",
    "seed.btc.petertodd.org",
    "seed.bitcoin.sprovoost.nl",
    "dnsseed.emzy.de",
    "seed.bitcoin.wiz.biz",
];

const TEST_SEEDER: [&str; 4] = [
    "testnet-seed.bitcoin.jonasschnelli.ch",
    "seed.tbtc.petertodd.org",
    "seed.testnet.bitcoin.sprovoost.nl",
    "testnet-seed.bluematt.me",
];

pub async fn dns_seeds(network: Network, services: Option<ServiceFlags>) -> Vec<SocketAddr> {
    let (seeders, port) = match network {
        Network::Bitcoin => (&MAIN_SEEDER[..], 8333),
        Network::Testnet => (&TEST_SEEDER[..], 18333),
        Network::Regtest => return vec![],
    };

    let mut addrs = vec![];

    info!("reaching out for DNS seed...");

    for seedhost in seeders {
        let host = match services {
            Some(services) => format!("x{}.{}:{}", services.as_u64(), seedhost, port),
            None => format!("{}:{}", seedhost, port),
        };

        if let Ok(lookup) = lookup_host(host).await {
            addrs.extend(lookup);
        } else {
            trace!("{} did not answer", seedhost);
        }
    }

    addrs
}
