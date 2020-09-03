use super::{dns_seeds, AddressManager, Peer};
use crate::{
    db::{FilterHeaderStore, FilterStore, HeaderStore},
    primitives::FilterHeader,
    wallet::matches_filter,
};
use bitcoin::{
    network::{
        constants::ServiceFlags,
        message::NetworkMessage,
        message_blockdata::Inventory,
        message_filter::{CFHeaders, CFilter, GetCFilters},
    },
    secp256k1::rand::{prelude::*, thread_rng},
    util::bip158::BlockFilter,
    Amount, Block, BlockHash, Network,
};
use bitcoin_wallet::{account::MasterAccount, coins::Coins};
use log::info;
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    net::SocketAddr,
    sync::Arc,
};
use tokio::sync::Mutex as AsyncMutex;

#[derive(Default, Debug, Clone)]
pub struct FilterHeaderRequester {
    current: Option<CurrentFilterHeaderRequest>,
    fetching: HashSet<SocketAddr>,
    fetched: HashMap<SocketAddr, CFHeaders>,
}

impl FilterHeaderRequester {
    pub fn clear(&mut self) {
        self.current = None;
        self.fetching.clear();
        self.fetched.clear();
    }
}

#[derive(Debug, Clone)]
pub struct CurrentFilterHeaderRequest {
    start_height: u32,
    stop_hash: BlockHash,
    len: usize,
    previous_filter_header: FilterHeader,
    bad: Vec<usize>,
}

pub type PeerRef = Arc<Peer>;

pub struct P2P {
    pub network: Network,
    pub header_store: HeaderStore,
    pub filter_header_store: FilterHeaderStore,
    pub header_sync_peer: Option<PeerRef>,
    pub filter_header_requester: FilterHeaderRequester,
    pub peers: HashMap<SocketAddr, PeerRef>,
    pub block_peers: HashMap<SocketAddr, PeerRef>,
    pub filter_peers: HashMap<SocketAddr, PeerRef>,
    pub address_manager: AddressManager,
    fetching_filters: HashMap<SocketAddr, usize>,
    pub filter_store: FilterStore,
    // TODO: Separate from p2p
    coins: Coins,
    account: MasterAccount,
    blocks_to_process: BTreeMap<u32, Option<Block>>,
}

pub async fn maintain_peers(p2p: Arc<AsyncMutex<P2P>>) {
    let network = p2p.lock().await.network;
    let seeds = dns_seeds(network, None).await;
    let mut p2p = p2p.lock().await;
    for addr in seeds {
        p2p.address_manager.add(addr, ServiceFlags::NONE);
    }
}

impl P2P {
    pub fn new(network: Network, account: MasterAccount) -> Self {
        Self {
            network,
            header_store: HeaderStore::new(network),
            filter_header_store: FilterHeaderStore::new(network),
            header_sync_peer: None,
            filter_header_requester: FilterHeaderRequester::default(),
            peers: HashMap::new(),
            block_peers: HashMap::new(),
            filter_peers: HashMap::new(),
            address_manager: AddressManager::new(),
            fetching_filters: HashMap::new(),
            filter_store: FilterStore::new(network),
            coins: Coins::new(),
            account,
            blocks_to_process: BTreeMap::new(),
        }
    }

    /// get a block from a random blocks only peer
    pub async fn get_block(&mut self, hash: BlockHash) {
        if self.block_peers.is_empty() {
            todo!("no useful peers");
        }

        let peer_pos: usize = thread_rng().gen_range(0, self.block_peers.len());
        let peer = self.block_peers.values().skip(peer_pos).next().unwrap();

        let height = self.header_store.by_hash(&hash).unwrap().height;
        self.blocks_to_process.insert(height, None);

        peer.get_block(hash);
    }

    pub fn get_filter_headers(&mut self) {
        assert!(self.filter_header_requester.current.is_none());

        let header_tip = &self.header_store.tip;
        let filter_tip = self
            .header_store
            .by_hash(&self.filter_header_store.tip.header_hash)
            .unwrap();

        // headers and filter headers in sync
        if header_tip == filter_tip {
            return;
        }

        // find common point of headers and filter headers
        let common = self
            .header_store
            .common_ancestor(header_tip, filter_tip)
            .expect("header and filter stores should at least have genesis in common");

        // if common and filter tip don't match then there must have been a reorg
        // so disconnect any filter headers now not on the main chain
        if common != filter_tip {
            while self.filter_header_store.tip.header_hash != common.hash {
                self.filter_header_store.disconnect();
            }
        }

        let start_height = common.height + 1;
        let stop_height = std::cmp::min(header_tip.height, common.height + 2000);
        let stop_hash = self.header_store.by_height(stop_height).unwrap().hash;

        let previous_filter_header = *self.filter_header_store.by_height(common.height).unwrap();

        self.filter_header_requester.current = Some(CurrentFilterHeaderRequest {
            start_height,
            stop_hash,
            len: (stop_height - common.height) as usize,
            previous_filter_header,
            bad: vec![],
        });

        for peer in self.filter_peers.values() {
            peer.send_get_cf_headers(start_height, stop_hash);
            self.filter_header_requester.fetching.insert(peer.addr);
        }
    }

    pub fn get_filters(&mut self) {
        // don't fetch unless all outstanding requests have ben fulfilled
        if self.fetching_filters.values().any(|v| *v != 0) {
            return;
        }

        let filter_tip = self
            .header_store
            .by_hash(&self.filter_header_store.tip.header_hash)
            .unwrap();

        if self.filter_store.height < filter_tip.height {
            let mut start_height = self.filter_store.height + 1;
            let mut stop_height = std::cmp::min(filter_tip.height, start_height + 999);

            for peer in self.filter_peers.values() {
                // don't fetch if already fetching
                if *self.fetching_filters.entry(peer.addr).or_default() > 0 {
                    continue;
                }

                assert!(stop_height >= start_height);

                let stop_hash = self.header_store.by_height(stop_height).unwrap().hash;

                peer.get_filters(start_height, stop_hash);

                *self.fetching_filters.entry(peer.addr).or_default() +=
                    (stop_height - start_height) as usize + 1;

                start_height = std::cmp::min(filter_tip.height, start_height + 1000);
                stop_height = std::cmp::min(filter_tip.height, start_height + 999);

                // all caught up
                if stop_height == start_height {
                    break;
                }
            }
        }
    }

    pub fn send_initial_get_headers(&self, peer: &PeerRef) {
        // From core: ask for header before tip to ensure we always get a response
        // and can set their best header
        let tip = self.header_store.tip;
        let start = self.header_store.by_hash(tip.prev()).map(|h| h.hash);
        let locator = self.header_store.locator(start);
        peer.get_headers(locator, None);
    }

    pub async fn handle_message(&mut self, peer: &PeerRef, message: NetworkMessage) {
        match message {
            NetworkMessage::Version(_) => {}

            NetworkMessage::Verack => {
                peer.send(NetworkMessage::SendHeaders);
                peer.send(NetworkMessage::GetAddr);

                if self.header_store.synced() || self.header_sync_peer.is_none() {
                    self.send_initial_get_headers(peer);
                }

                if self.header_sync_peer.is_none() {
                    self.header_sync_peer = Some(Arc::clone(peer));
                }
            }

            NetworkMessage::Headers(headers) => {
                let mut new_headers = false;

                for header in &headers {
                    let (header, _, _) = self.header_store.add_header(*header);
                    if header.is_some() {
                        new_headers = true;
                    }
                }

                if headers.len() == 2000 {
                    let last_hash = headers[headers.len() - 1].block_hash();
                    peer.get_headers(vec![last_hash], None);
                }

                // fetch new filter headers from peers

                if new_headers
                    && self.filter_header_requester.current.is_none()
                    && self.header_store.synced()
                {
                    self.get_filter_headers();
                }
            }

            NetworkMessage::CFHeaders(headers) => {
                // check that we asked them for filter headers
                assert!(self.filter_header_requester.fetching.remove(&peer.addr));

                if let Some(current) = &mut self.filter_header_requester.current {
                    assert_eq!(headers.filter_type, 0);
                    assert_eq!(headers.filter_hashes.len(), current.len);
                    assert_eq!(headers.stop_hash, current.stop_hash);

                    self.filter_header_requester
                        .fetched
                        .insert(peer.addr, headers.clone());

                    // all peers have returned filter headers
                    if self.filter_header_requester.fetching.is_empty() {
                        let all_filter_headers = self
                            .filter_header_requester
                            .fetched
                            .values()
                            .cloned()
                            .collect();

                        for i in 0..current.len {
                            if filter_header_mismatch(&all_filter_headers, i) {
                                todo!("handle mismatched filter headers");
                            }
                        }

                        // add to store and fetch more

                        let stop_header = self.header_store.by_hash(&current.stop_hash).unwrap();

                        let mut previous_filter_header = current.previous_filter_header;

                        for filter_hash in headers.filter_hashes {
                            let height = previous_filter_header.height + 1;
                            // in case there was a reorg, get by hash
                            let header = self.header_store.ancestor(stop_header, height);

                            self.filter_header_store.add(
                                filter_hash,
                                header,
                                &previous_filter_header,
                            );

                            previous_filter_header = self.filter_header_store.tip;
                        }

                        self.filter_header_requester.clear();

                        self.get_filter_headers();

                        // TODO: handle reorgs for filters

                        // in sync
                        if self.header_store.tip.hash == self.filter_header_store.tip.header_hash {
                            // get filters
                            self.get_filters();
                        }
                    }
                } else {
                    todo!("unexpected cf headers");
                }
            }

            NetworkMessage::Block(block) => {
                let header = self.header_store.by_hash(&block.block_hash()).unwrap();

                *self.blocks_to_process.get_mut(&header.height).unwrap() = Some(block);

                // TODO: clean this logic up

                // must process blocks in order, could be received out of order from different peers
                for height in self.blocks_to_process.keys().copied().collect::<Vec<_>>() {
                    if self.blocks_to_process[&height].is_some() {
                        let block = self.blocks_to_process.remove(&height).unwrap().unwrap();

                        let modified = self.coins.process(&mut self.account, &block);
                        if modified {
                            let block_height = |hash: &BlockHash| {
                                self.header_store.by_hash(hash).map(|h| h.height)
                            };
                            let available_balance =
                                self.coins.available_balance(height, block_height);
                            info!(
                                "Balance: {} at height={} hash={}",
                                Amount::from_sat(available_balance),
                                height,
                                block.block_hash()
                            );
                        }
                    } else {
                        break;
                    }
                }
            }

            NetworkMessage::Addr(_) => {}

            NetworkMessage::GetAddr => {}

            NetworkMessage::CFilter(filter) => {
                let CFilter {
                    block_hash,
                    filter_type,
                    filter,
                } = filter;
                let filter = BlockFilter { content: filter };

                assert_eq!(filter_type, 0);

                *self.fetching_filters.get_mut(&peer.addr).unwrap() -= 1;

                let header = *self.header_store.by_hash(&block_hash).unwrap();

                let prev = self.header_store.by_hash(header.prev()).unwrap();
                let prev_filter_header = self.filter_header_store.by_hash(&prev.hash).unwrap();

                let filter_header = self.filter_header_store.by_hash(&header.hash).unwrap();

                assert_eq!(header.hash, block_hash);
                assert_eq!(
                    filter.filter_id(&prev_filter_header.filter_header),
                    filter_header.filter_header
                );

                let connected = self.filter_store.add(filter, header);

                // TODO: matched filters can potentially be checked before previous blocks have been processed
                // As process block instantiates more keys in the wallet, future addresses might be misses in `matches_filter`

                for (height, hash) in connected {
                    let filter = self.filter_store.by_hash(&hash).unwrap();
                    if matches_filter(&self.account, &hash, filter) {
                        info!(
                            "filter match, requesting block: height={} hash={}",
                            height, hash
                        );

                        self.get_block(hash).await;
                    }
                }

                if self.fetching_filters.values().all(|v| *v == 0) {
                    self.get_filters();
                }
            }

            NetworkMessage::CFCheckpt(_) => {}

            NetworkMessage::GetHeaders(_) => {
                // TODO: Do this properly
                peer.send(NetworkMessage::Headers(vec![self.header_store.tip.header]))
            }

            NetworkMessage::Inv(_) => {}
            NetworkMessage::GetData(_) => {}
            NetworkMessage::NotFound(_) => {}
            NetworkMessage::GetBlocks(_) => {}
            NetworkMessage::MemPool => {}
            NetworkMessage::Tx(_) => {}
            NetworkMessage::SendHeaders => {}
            NetworkMessage::Ping(_) => {}
            NetworkMessage::Pong(_) => {}
            NetworkMessage::MerkleBlock(_) => {}
            NetworkMessage::FeeFilter(_) => {}
            NetworkMessage::FilterLoad(_) => {}
            NetworkMessage::FilterAdd(_) => {}
            NetworkMessage::FilterClear => {}
            NetworkMessage::GetCFilters(_) => {}
            NetworkMessage::GetCFHeaders(_) => {}
            NetworkMessage::GetCFCheckpt(_) => {}
            NetworkMessage::SendCmpct(_) => {}
            NetworkMessage::CmpctBlock(_) => {}
            NetworkMessage::GetBlockTxn(_) => {}
            NetworkMessage::BlockTxn(_) => {}
            NetworkMessage::Alert(_) => {}
            NetworkMessage::Reject(_) => {}
        }
    }
}

fn filter_header_mismatch(headers: &Vec<CFHeaders>, index: usize) -> bool {
    let mut hash = None;
    for msg in headers {
        if msg.filter_hashes.len() <= index {
            continue;
        }

        if let Some(hash) = hash {
            if hash != msg.filter_hashes[index] {
                return true;
            }
        } else {
            hash = Some(msg.filter_hashes[index]);
        }
    }

    false
}

#[cfg(test)]
mod test {
    use super::*;
    use bitcoin::{hashes::Hash, secp256k1::rand::thread_rng, FilterHash};

    fn random_filter_hash() -> FilterHash {
        let mut bytes: Vec<u8> = (0..32).collect();
        bytes.shuffle(&mut thread_rng());
        FilterHash::hash(&bytes)
    }

    #[test]
    fn test_filter_header_mismatch() {
        let a = random_filter_hash();
        let b = random_filter_hash();
        let c = random_filter_hash();
        let d = random_filter_hash();

        fn header(filter_hashes: Vec<FilterHash>) -> CFHeaders {
            CFHeaders {
                filter_hashes,
                filter_type: 0,
                stop_hash: Default::default(),
                previous_filter: Default::default(),
            }
        }

        let first = header(vec![a, b, c]);
        let second = header(vec![a, b, d]);

        let headers = vec![first, second];

        assert!(!filter_header_mismatch(&headers, 0));
        assert!(!filter_header_mismatch(&headers, 1));
        assert!(filter_header_mismatch(&headers, 2));
    }
}
