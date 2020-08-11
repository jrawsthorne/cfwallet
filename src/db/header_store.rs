use crate::{primitives::Header, util::now};
use bitcoin::{blockdata::constants::genesis_block, BlockHash, BlockHeader, Network};
use log::{debug, info, trace};
use std::collections::{HashMap, VecDeque};

pub struct HeaderStore {
    hash: HashMap<BlockHash, Header>,
    height: HashMap<u32, BlockHash>,
    pub tip: Header,
    network: Network,
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
            network,
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

    // TODO: Verify headers against consensus rules
    pub fn add_header(
        &mut self,
        header: BlockHeader,
    ) -> (Option<Header>, Vec<Header>, Vec<Header>) {
        if self.by_hash(&header.block_hash()).is_some() {
            // laready have it so not added
            trace!("already have header {}", header.block_hash());
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
                debug!(
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

    pub fn common_ancestor<'a>(&'a self, mut a: &'a Header, mut b: &'a Header) -> Option<&Header> {
        if a.height > b.height {
            a = self.ancestor(a, b.height);
        } else if b.height > a.height {
            b = self.ancestor(b, a.height);
        }

        let mut a = Some(a);
        let mut b = Some(b);

        loop {
            match (a, b) {
                (Some(aa), Some(bb)) if aa.hash != bb.hash => {
                    a = self.by_hash(&aa.prev());
                    b = self.by_hash(&bb.prev());
                }
                (Some(_), Some(_)) => break a,
                _ => break None,
            }
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

    pub fn find_locator(&self, locator: &[BlockHash]) -> BlockHash {
        for hash in locator {
            if self.hash_in_best_chain(hash) {
                return *hash;
            }
        }

        genesis_block(self.network).block_hash()
    }

    pub fn ancestor<'a>(&'a self, mut header: &'a Header, height: u32) -> &Header {
        if self.in_best_chain(header) {
            return self.by_height(height).expect("in best chain so must exist");
        }

        while header.height != height {
            header = &self.hash[header.prev()];
        }

        header
    }

    fn hash_in_best_chain(&self, hash: &BlockHash) -> bool {
        match self.by_hash(hash) {
            None => false,
            Some(header) => self.in_best_chain(header),
        }
    }

    fn in_best_chain(&self, header: &Header) -> bool {
        match self.height.get(&header.height) {
            Some(best) => *best == header.hash,
            None => false,
        }
    }
}
