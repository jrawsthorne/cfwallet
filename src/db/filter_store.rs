use super::HeaderStore;
use crate::{
    primitives::Header,
    util::{genesis_filter, now},
};
use bitcoin::{blockdata::constants::genesis_block, util::bip158::BlockFilter, BlockHash, Network};
use log::{info, trace};
use std::collections::{BTreeMap, HashMap};

pub struct FilterStore {
    by_height: BTreeMap<u32, Header>,
    by_hash: HashMap<BlockHash, BlockFilter>,
    tip: BlockHash,
    pub height: u32,
}

impl FilterStore {
    pub fn new(network: Network) -> Self {
        let genesis = genesis_block(network);
        let hash = genesis.block_hash();

        let filter = genesis_filter(&genesis);
        let mut by_hash = HashMap::new();
        by_hash.insert(hash, filter);
        let mut by_height = BTreeMap::new();
        by_height.insert(
            0,
            Header {
                hash,
                height: 0,
                chainwork: genesis.header.work(),
                header: genesis.header,
            },
        );
        Self {
            by_height,
            by_hash,
            tip: hash,
            height: 0,
        }
    }

    // TODO: Handle reorgs
    pub fn add(&mut self, filter: BlockFilter, header: Header) -> Vec<(u32, BlockHash)> {
        trace!(
            "stored filter hash={}  height={}",
            header.hash,
            header.height
        );
        self.by_hash.insert(header.hash, filter);
        self.by_height.insert(header.height, header);

        let mut connected = vec![];

        // filters are received out of order, see if we've received the next filter in the chain
        for (&height, header) in self.by_height.range(self.height + 1..) {
            if self.height + 1 == height {
                let synced = header.time() > now().saturating_sub(HeaderStore::MAX_TIP_AGE);

                if height % 2000 == 0 || synced {
                    info!(
                        "filter connected: height={} hash={}",
                        header.height, header.hash
                    );
                }
                self.tip = header.hash;
                self.height = height;

                connected.push((height, header.hash));
            } else {
                break;
            }
        }

        connected
    }

    pub fn by_hash(&self, hash: &BlockHash) -> Option<&BlockFilter> {
        self.by_hash.get(hash)
    }

    pub fn by_height(&self, height: u32) -> Option<&BlockFilter> {
        self.by_height
            .get(&height)
            .map(|header| &self.by_hash[&header.hash])
    }

    pub fn tip(&self) -> &BlockFilter {
        &self.by_hash[&self.tip]
    }
}
