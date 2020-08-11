use bitcoin::{
    secp256k1::Secp256k1,
    util::{
        bip158::BlockFilter,
        bip32::{ChildNumber, ExtendedPubKey, ScriptType},
    },
    BlockHash, Network, Script,
};
use bitcoin_wallet::account::{Account, AccountAddressType, MasterAccount};

pub fn create_master_account(
    extended_pubkeys: Vec<ExtendedPubKey>,
    network: Network,
) -> MasterAccount {
    let look_ahead = 20;

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
            look_ahead,
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
            look_ahead,
            network,
        );
        change.do_look_ahead(None).unwrap();
        master_account.add_account(receive);
        master_account.add_account(change);
    }
    master_account
}

pub fn matches_filter(
    master_account: &MasterAccount,
    block_hash: &BlockHash,
    filter: &BlockFilter,
) -> bool {
    let scripts = master_account
        .get_scripts()
        .map(|(s, _)| s)
        .collect::<Vec<_>>();

    let matches = filter
        .match_any(block_hash, scripts.iter().map(Script::as_bytes))
        .unwrap();

    matches
}
