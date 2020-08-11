use bitcoin::{util::uint::Uint256, BlockHash, BlockHeader};

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct Header {
    pub hash: BlockHash,
    pub height: u32,
    pub chainwork: Uint256,
    pub(crate) header: BlockHeader,
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
