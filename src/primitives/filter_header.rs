use bitcoin::{BlockHash, FilterHash};

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct FilterHeader {
    pub header_hash: BlockHash,
    pub filter_header: FilterHash,
    pub height: u32,
}

impl FilterHeader {
    pub fn new(prev: &FilterHeader, filter_hash: FilterHash, header_hash: BlockHash) -> Self {
        use bitcoin::hashes::Hash;

        let mut header_data = [0u8; 64];
        header_data[0..32].copy_from_slice(&filter_hash[..]);
        header_data[32..64].copy_from_slice(&prev.filter_header[..]);
        let filter_header = FilterHash::hash(&header_data);

        Self {
            filter_header,
            header_hash,
            height: prev.height + 1,
        }
    }
}
