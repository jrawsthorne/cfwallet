use bitcoin::{
    blockdata::constants::genesis_block,
    network::{
        constants::ServiceFlags,
        message::{NetworkMessage, RawNetworkMessage},
        message_blockdata::{GetHeadersMessage, Inventory},
        message_filter::{CFHeaders, CFilter, GetCFHeaders, GetCFilters},
        message_network::VersionMessage,
        stream_reader::StreamReader,
        Address,
    },
    secp256k1::Secp256k1,
    util::{
        bip158::{BlockFilter, BlockFilterWriter},
        bip32::{ChildNumber, ExtendedPubKey, ScriptType},
        uint::Uint256,
    },
    Amount, Block, BlockHash, BlockHeader, FilterHash, Network,
};
use bitcoin_wallet::{
    account::{Account, AccountAddressType, MasterAccount},
    coins::Coins,
};
use log::{info, LevelFilter};
use std::{
    collections::{HashMap, VecDeque},
    net::{SocketAddr, TcpStream},
    str::FromStr,
    time::SystemTime,
};

fn create_master_account(extended_pubkeys: Vec<ExtendedPubKey>, network: Network) -> MasterAccount {
    let mut master_account =
        MasterAccount::watch_only(extended_pubkeys[0] /*doesn't effect watch only*/, 0);
    for (i, extended_pubkey) in extended_pubkeys.into_iter().enumerate() {
        let account_number = (i as u32) + 1; // start at 1 is convention
        let address_type = match extended_pubkey.script_type {
            ScriptType::P2pkh => AccountAddressType::P2PKH,
            ScriptType::P2wpkh => AccountAddressType::P2WPKH,
            ScriptType::P2shP2wpkh => AccountAddressType::P2SHWPKH,
        };
        let mut receive = Account::new_from_storage(
            address_type,
            account_number,
            0, // typical for receive addresses
            extended_pubkey
                .ckd_pub(&Secp256k1::new(), ChildNumber::from(0))
                .unwrap(),
            vec![],
            0,
            20,
            network,
        );
        receive.do_look_ahead(None).unwrap();
        let mut change = Account::new_from_storage(
            address_type,
            account_number,
            1, // typical for change addresses
            extended_pubkey
                .ckd_pub(&Secp256k1::new(), ChildNumber::from(1))
                .unwrap(),
            vec![],
            0,
            10,
            network,
        );
        change.do_look_ahead(None).unwrap();
        master_account.add_account(receive);
        master_account.add_account(change);
    }
    master_account
}

fn matches_filter(master_account: &MasterAccount, filter: &CFilter) -> bool {
    let scripts = master_account
        .get_scripts()
        .map(|(s, _)| s)
        .collect::<Vec<_>>();

    let matches = BlockFilter::new(&filter.filter)
        .match_any(
            &filter.block_hash,
            scripts.iter().map(|script| script.as_bytes()),
        )
        .unwrap();

    matches
}

fn main() {
    env_logger::builder()
        .format_timestamp_millis()
        .filter_level(LevelFilter::Debug)
        .init();
    let args: Vec<_> = std::env::args().skip(1).collect();
    let network = Network::Testnet;
    let addr: SocketAddr = args
        .get(0)
        .expect("enter an IP address")
        .parse()
        .expect("invalid IP address");
    let stream = TcpStream::connect(addr).expect("couldn't connect to peer");
    let mut peer = Peer::new(stream, network);
    let mut headers_store = HeaderStore::new(network);
    let mut filter_headers_store = FilterHeaderStore::new(network);
    let extended_pubkeys = args
        .get(1)
        .expect("enter comma separated (x/y/z)pubs")
        .split(",")
        .map(FromStr::from_str)
        .collect::<Result<Vec<_>, _>>()
        .expect("invalid (x/y/z)pub");
    let mut master_account = create_master_account(extended_pubkeys, network);
    let mut coins = Coins::new();
    let mut filters_height = 0;

    // initiate the connection
    peer.send_version();

    loop {
        match peer.read() {
            NetworkMessage::Version(_) => {
                // once https://github.com/bitcoin/bitcoin/pull/19070 merged
                // assert!(version.services.has(ServiceFlags::COMPACT_FILTERS));
                peer.send(NetworkMessage::Verack);
            }

            NetworkMessage::Verack => {
                peer.send(NetworkMessage::SendHeaders);

                let tip = headers_store.tip;
                let start = headers_store.by_hash(tip.prev()).map(|h| h.hash);
                let locator = headers_store.locator(start);
                peer.send(NetworkMessage::GetHeaders(GetHeadersMessage::new(
                    locator,
                    BlockHash::default(),
                )))
            }

            NetworkMessage::Block(block) => {
                coins.process(&mut master_account, &block);
                let header = &headers_store.hash[&block.block_hash()];
                let block_height = |hash: &BlockHash| headers_store.by_hash(hash).map(|h| h.height);
                let available_balance = coins.available_balance(header.height, block_height);
                info!("Balance: {}", Amount::from_sat(available_balance));
            }

            NetworkMessage::Headers(headers) => {
                for header in &headers {
                    let (_, _, disconnected) = headers_store.add_header(*header);
                    if !disconnected.is_empty() {
                        for header in disconnected {
                            if filter_headers_store.tip.header_hash == header.hash {
                                filter_headers_store.disconnect();
                            }
                        }
                    }
                }
                if headers.len() == 2000 && !headers_store.synced() {
                    let last_hash = headers[headers.len() - 1].block_hash();
                    let locator = headers_store.locator(Some(last_hash));
                    peer.send(NetworkMessage::GetHeaders(GetHeadersMessage::new(
                        locator,
                        BlockHash::default(),
                    )))
                }
                if headers_store.synced() {
                    let header_tip = headers_store.tip;
                    let filter_tip = filter_headers_store.tip;

                    // headers and filters not in sync, request filter headers
                    if header_tip.hash != filter_tip.header_hash {
                        assert!(header_tip.height > filter_tip.height);

                        info!("Attempting to fetch set of un-checkpointed filters at height={} hash={}",header_tip.height,header_tip.hash);
                        let start_height = filter_tip.height + 1;
                        let stop_height =
                            std::cmp::min(header_tip.height, filter_tip.height + 2000);
                        peer.send(NetworkMessage::GetCFHeaders(GetCFHeaders {
                            filter_type: 0,
                            start_height,
                            stop_hash: headers_store.by_height(stop_height).unwrap().hash,
                        }));
                    }
                }
            }

            NetworkMessage::Ping(nonce) => {
                peer.send(NetworkMessage::Pong(nonce));
            }

            NetworkMessage::CFilter(filter) => {
                let header = headers_store.by_hash(&filter.block_hash);
                if let Some(header) = header {
                    filters_height += 1;
                    assert_eq!(header.hash, filter.block_hash);

                    if filters_height % 2000 == 0 {
                        info!(
                            "filter processed: height={} hash={}",
                            header.height, header.hash,
                        );
                    }

                    if matches_filter(&master_account, &filter) {
                        info!("{} {} matches", header.height, header.hash);
                        peer.send(NetworkMessage::GetData(vec![Inventory::WitnessBlock(
                            header.hash,
                        )]));
                    }
                    peer.filters_in_flights -= 1;

                    if peer.filters_in_flights == 0 {
                        let header_tip = headers_store.tip;
                        let filter_tip = filter_headers_store.tip;
                        if filters_height < header_tip.height {
                            let stop_height =
                                std::cmp::min(filter_tip.height, filters_height + 1000);
                            let stop_hash = headers_store.height[&stop_height];
                            peer.send(NetworkMessage::GetCFilters(GetCFilters {
                                filter_type: 0,
                                start_height: filters_height + 1,
                                stop_hash,
                            }));
                            peer.filters_in_flights = stop_height - filters_height;
                        }
                    }
                }
            }

            NetworkMessage::CFHeaders(CFHeaders {
                filter_hashes,
                filter_type,
                stop_hash,
                previous_filter,
            }) => {
                let filter_tip = &filter_headers_store.tip;

                // These connect at the start
                assert_eq!(previous_filter, filter_tip.filter_hash);
                // connect to the end
                assert_eq!(
                    &stop_hash,
                    headers_store
                        .height
                        .get(&(filter_tip.height + filter_hashes.len() as u32))
                        .unwrap()
                );

                assert!(!filter_hashes.is_empty());
                assert_eq!(filter_type, 0);

                // TODO: Need support for multiple peers to detect mismatch

                let mut height = filter_tip.height + 1;

                for filter_hash in filter_hashes {
                    let header = headers_store.by_height(height).unwrap();
                    let filter_header = FilterHeader {
                        filter_hash,
                        header_hash: header.hash,
                        height: header.height,
                    };
                    filter_headers_store.hash.insert(header.hash, filter_header);
                    let duplicate = filter_headers_store
                        .height
                        .insert(height, header.hash)
                        .is_some();
                    assert!(!duplicate);
                    filter_headers_store.tip = filter_header;
                    height += 1;
                    // info!("{:?}", filter_headers_store.tip);
                }

                let stop = headers_store.by_hash(&stop_hash).unwrap();

                if height % 2000 == 0 || headers_store.synced() {
                    info!(
                        "added filter header: height={}, hash={}",
                        stop.height, stop.hash
                    );
                }

                let header_tip = headers_store.tip;
                let filter_tip = filter_headers_store.tip;
                if header_tip.height > filter_tip.height {
                    let start_height = filter_tip.height + 1;
                    let stop_height = std::cmp::min(header_tip.height, filter_tip.height + 2000);

                    peer.send(NetworkMessage::GetCFHeaders(GetCFHeaders {
                        filter_type: 0,
                        start_height,
                        stop_hash: headers_store.by_height(stop_height).unwrap().hash,
                    }));
                } else if header_tip.hash == filter_tip.header_hash {
                    if filters_height < header_tip.height {
                        let stop_height = std::cmp::min(filter_tip.height, filters_height + 1000);
                        let stop_hash = headers_store.height[&stop_height];
                        peer.send(NetworkMessage::GetCFilters(GetCFilters {
                            filter_type: 0,
                            start_height: filters_height + 1,
                            stop_hash,
                        }));
                        peer.filters_in_flights += stop_height - filters_height;
                    }
                } else {
                }
            }

            _ => {}
        }
    }
}

pub struct Peer {
    stream: TcpStream,
    network: Network,
    reader: StreamReader<TcpStream>,
    addr: SocketAddr,
    filters_in_flights: u32,
}

impl Peer {
    pub fn new(stream: TcpStream, network: Network) -> Self {
        Self {
            addr: stream.peer_addr().unwrap(),
            stream: stream.try_clone().unwrap(),
            network,
            reader: StreamReader::new(stream, None),
            filters_in_flights: 0,
        }
    }

    pub fn send(&mut self, payload: NetworkMessage) {
        use bitcoin::consensus::Encodable;

        let msg = RawNetworkMessage {
            payload,
            magic: self.network.magic(),
        };

        msg.consensus_encode(&mut self.stream).unwrap();
    }

    pub fn read(&mut self) -> NetworkMessage {
        self.reader
            .read_next::<RawNetworkMessage>()
            .unwrap()
            .payload
    }

    pub fn send_version(&mut self) {
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
}

pub struct FilterHeaderStore {
    hash: HashMap<BlockHash, FilterHeader>,
    height: HashMap<u32, BlockHash>,
    pub tip: FilterHeader,
}

fn genesis_filter(genesis: &Block) -> BlockFilter {
    let mut content = vec![];
    let mut writer = BlockFilterWriter::new(&mut content, genesis);
    writer.add_output_scripts();
    writer.finish().unwrap();
    BlockFilter { content }
}

impl FilterHeaderStore {
    pub const MAX_TIP_AGE: u32 = 24 * 60 * 60;

    pub fn new(network: Network) -> Self {
        let genesis = genesis_block(network);
        let header = FilterHeader {
            header_hash: genesis.block_hash(),
            height: 0,
            filter_hash: genesis_filter(&genesis).filter_id(&FilterHash::default()),
        };
        let mut hash = HashMap::new();
        hash.insert(header.header_hash, header);
        let mut height = HashMap::new();
        height.insert(header.height, header.header_hash);
        Self {
            height,
            hash,
            tip: header,
        }
    }

    pub fn by_hash(&self, hash: &BlockHash) -> Option<&FilterHeader> {
        self.hash.get(hash)
    }

    pub fn by_height(&self, height: u32) -> Option<&FilterHeader> {
        self.height.get(&height).map(|hash| &self.hash[hash])
    }

    pub fn disconnect(&mut self) {
        let old_tip_hash = self.height.remove(&self.tip.height).unwrap();
        let old_tip = self.hash[&old_tip_hash];
        let new_tip = self.hash[&self.height[&(old_tip.height - 1)]];
        self.tip = new_tip;
        info!(
            "filter header disconnected: height={} hash={}",
            self.tip.height + 1,
            old_tip_hash,
        );
    }
}

pub struct HeaderStore {
    hash: HashMap<BlockHash, Header>,
    height: HashMap<u32, BlockHash>,
    tip: Header,
}

impl HeaderStore {
    pub const MAX_TIP_AGE: u32 = 24 * 60 * 60;

    pub fn new(network: Network) -> Self {
        let genesis = genesis_block(network);
        let header = Header {
            hash: genesis.block_hash(),
            height: 0,
            header: genesis.header,
            chainwork: genesis.header.work(),
        };
        let mut hash = HashMap::new();
        hash.insert(header.hash, header);
        let mut height = HashMap::new();
        height.insert(header.height, header.hash);
        Self {
            height,
            hash,
            tip: header,
        }
    }

    pub fn by_height(&self, height: u32) -> Option<&Header> {
        self.height.get(&height).map(|hash| &self.hash[hash])
    }

    pub fn by_hash(&self, hash: &BlockHash) -> Option<&Header> {
        self.hash.get(hash)
    }

    pub fn synced(&self) -> bool {
        self.tip.time() > now().saturating_sub(Self::MAX_TIP_AGE)
    }

    pub fn add_header(
        &mut self,
        header: BlockHeader,
    ) -> (Option<Header>, Vec<Header>, Vec<Header>) {
        if self.by_hash(&header.block_hash()).is_some() {
            // laready have it so not added
            return (None, vec![], vec![]);
        }
        if let Some(&prev) = self.by_hash(&header.prev_blockhash) {
            let header = Header {
                hash: header.block_hash(),
                header,
                height: prev.height + 1,
                chainwork: prev.chainwork + header.work(),
            };
            self.hash.insert(header.hash, header);
            if header.height % 2000 == 0 || self.synced() {
                info!(
                    "header stored: height={} hash={}",
                    header.height, header.hash
                );
            }
            if self.tip == prev {
                self.connect(header);
                (Some(header), vec![header], vec![])
            } else {
                if header.chainwork > self.tip.chainwork {
                    let mut connect = VecDeque::new();
                    {
                        let mut header = header;
                        while !self.in_best_chain(&header) {
                            connect.push_front(header);
                            header = self.hash[header.prev()];
                        }
                    }
                    let mut disconnect = vec![];
                    while self.tip.hash != *connect[0].prev() {
                        disconnect.push(self.disconnect());
                    }
                    for header in &connect {
                        self.connect(*header);
                    }
                    (Some(header), connect.into(), disconnect)
                } else {
                    (Some(header), vec![], vec![])
                }
            }
        } else {
            todo!("bad header chain, ban peer");
        }
    }

    fn disconnect(&mut self) -> Header {
        let old_tip_hash = self.height.remove(&self.tip.height).unwrap();
        let old_tip = self.hash[&old_tip_hash];
        let new_tip = self.hash[old_tip.prev()];
        self.tip = new_tip;
        info!(
            "header disconnected: height={} hash={}",
            self.tip.height + 1,
            old_tip_hash,
        );
        old_tip
    }

    fn connect(&mut self, header: Header) {
        let prev = self.hash[header.prev()];
        assert_eq!(prev.hash, self.tip.hash);
        self.height.insert(prev.height + 1, header.hash);
        self.tip = header;
        if header.height % 2000 == 0 || self.synced() {
            info!(
                "header connected: height={} hash={}",
                header.height, header.hash
            );
        }
    }

    pub fn locator(&self, start: Option<BlockHash>) -> Vec<BlockHash> {
        let start = start.unwrap_or(self.tip.hash);
        let mut hashes = vec![];

        let start = match self.by_hash(&start) {
            Some(header) => *header,
            None => {
                hashes.push(start);
                self.tip
            }
        };

        let mut in_best_chain = self.in_best_chain(&start);
        let mut hash = start.hash;
        let mut height = start.height;
        let mut step = 1;

        hashes.push(hash);

        while height > 0 {
            height = height.saturating_sub(step);

            if hashes.len() > 10 {
                step *= 2;
            }

            if in_best_chain {
                hash = self.height[&height];
            } else {
                let ancestor = self.ancestor(&start, height);
                in_best_chain = self.in_best_chain(ancestor);
                hash = ancestor.hash;
            }

            hashes.push(hash);
        }

        hashes
    }

    fn ancestor<'a>(&'a self, mut header: &'a Header, height: u32) -> &Header {
        if self.in_best_chain(header) {
            return self.by_height(height).expect("in best chain so must exist");
        }

        while header.height != height {
            header = &self.hash[header.prev()];
        }

        header
    }

    fn in_best_chain(&self, header: &Header) -> bool {
        match self.height.get(&header.height) {
            Some(best) => *best == header.hash,
            None => false,
        }
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct Header {
    pub hash: BlockHash,
    pub height: u32,
    pub chainwork: Uint256,
    header: BlockHeader,
}

impl Header {
    pub fn prev(&self) -> &BlockHash {
        &self.header.prev_blockhash
    }

    pub fn time(&self) -> u32 {
        self.header.time
    }

    pub fn bits(&self) -> u32 {
        self.header.bits
    }

    pub fn nonce(&self) -> u32 {
        self.header.nonce
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct FilterHeader {
    pub header_hash: BlockHash,
    pub filter_hash: FilterHash,
    pub height: u32,
}

pub fn now() -> u32 {
    use std::time::UNIX_EPOCH;
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32
}
