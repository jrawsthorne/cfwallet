use super::HeaderStore;
use crate::{
    primitives::{FilterHeader, Header},
    util::{genesis_filter, now},
};
use bitcoin::{blockdata::constants::genesis_block, BlockHash, FilterHash, Network};
use log::info;
use std::collections::HashMap;

pub struct FilterHeaderStore {
    hash: HashMap<BlockHash, FilterHeader>,

    height: HashMap<u32, BlockHash>,
    pub tip: FilterHeader,
}

impl FilterHeaderStore {
    pub const MAX_TIP_AGE: u32 = 24 * 60 * 60;

    pub fn new(network: Network) -> Self {
        let genesis = genesis_block(network);
        let header = FilterHeader {
            header_hash: genesis.block_hash(),
            height: 0,
            filter_header: genesis_filter(&genesis).filter_id(&FilterHash::default()),
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

    pub fn add(
        &mut self,
        filter_hash: FilterHash,
        header: &Header,
        previous_filter_header: &FilterHeader,
    ) {
        assert!(!self.height.contains_key(&header.height));

        let filter_header = FilterHeader::new(&previous_filter_header, filter_hash, header.hash);

        self.hash.insert(header.hash, filter_header);
        self.height.insert(header.height, header.hash);
        self.tip = filter_header;

        let synced = header.time() > now().saturating_sub(HeaderStore::MAX_TIP_AGE);

        if header.height % 2000 == 0 || synced {
            info!(
                "filter header connected: height={}, hash={}",
                header.height, header.hash
            );
        }
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
