use bitcoin::{
    util::bip158::{BlockFilter, BlockFilterWriter},
    Block,
};
use std::time::{SystemTime, UNIX_EPOCH};

pub fn now() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32
}

pub fn genesis_filter(genesis: &Block) -> BlockFilter {
    let mut content = vec![];
    let mut writer = BlockFilterWriter::new(&mut content, genesis);
    writer.add_output_scripts();
    writer.finish().unwrap();
    BlockFilter { content }
}
