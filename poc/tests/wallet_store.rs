use incrementalmerkletree::{frontier::NonEmptyFrontier, Level};
use orchard::{
    keys::{FullViewingKey, Scope, SpendingKey},
    note::{ExtractedNoteCommitment, RandomSeed, Rho},
    note_encryption::{IronwoodDomain, IronwoodNoteEncryption},
    value::NoteValue,
    Note, NoteVersion,
};
use zcash_client_backend::{
    data_api::{chain::ChainState, AccountBirthday},
    proto::compact_formats::{ChainMetadata, CompactBlock, CompactOrchardAction, CompactTx},
};
use zcash_note_encryption::Domain;
use zcash_primitives::block::BlockHash;
use zcash_protocol::consensus::{BlockHeight, Network};

#[test]
fn a_vault_viewing_account_survives_restart_without_duplication() {
    let path = std::env::temp_dir().join(format!(
        "loki-wallet-{}-{}.db",
        std::process::id(),
        rand_zp::random::<u64>()
    ));
    let sk = SpendingKey::from_bytes([42; 32]).unwrap();
    let ordinary = FullViewingKey::from(&sk);
    let ak = ordinary.to_bytes()[..32].try_into().unwrap();
    let fvk = loki_poc::zip2005::frost_viewing_key(&ak, &[42; 32]).unwrap();
    let birthday = AccountBirthday::from_parts(
        ChainState::empty(BlockHeight::from_u32(0), BlockHash([0; 32])),
        None,
    );

    let first = loki_poc::wallet_store::VaultWallet::open(
        &path,
        Network::TestNetwork,
        &fvk,
        &birthday,
        "correct horse",
    )
    .expect("import vault viewing key");
    assert_eq!(first.viewing_key().unwrap().to_bytes(), fvk.to_bytes());
    drop(first);
    assert!(!std::fs::read(&path)
        .unwrap()
        .starts_with(b"SQLite format 3"));

    assert!(loki_poc::wallet_store::VaultWallet::open(
        &path,
        Network::TestNetwork,
        &fvk,
        &birthday,
        "wrong passphrase",
    )
    .is_err());
    assert!(loki_poc::wallet_store::VaultWallet::open(
        &path,
        Network::MainNetwork,
        &fvk,
        &birthday,
        "correct horse",
    )
    .is_err());
    let later_birthday = AccountBirthday::from_parts(
        ChainState::empty(BlockHeight::from_u32(1), BlockHash([1; 32])),
        None,
    );
    assert!(loki_poc::wallet_store::VaultWallet::open(
        &path,
        Network::TestNetwork,
        &fvk,
        &later_birthday,
        "correct horse",
    )
    .is_err());
    let second = loki_poc::wallet_store::VaultWallet::open(
        &path,
        Network::TestNetwork,
        &fvk,
        &birthday,
        "correct horse",
    )
    .expect("reopen vault viewing key");
    assert_eq!(second.viewing_key().unwrap().to_bytes(), fvk.to_bytes());
    assert_eq!(second.account_count().unwrap(), 1);
    drop(second);

    std::fs::remove_file(path).unwrap();
}

#[test]
fn scanned_ironwood_height_survives_restart() {
    let path = std::env::temp_dir().join(format!(
        "loki-wallet-scan-{}-{}.db",
        std::process::id(),
        rand_zp::random::<u64>()
    ));
    let sk = SpendingKey::from_bytes([42; 32]).unwrap();
    let ordinary = FullViewingKey::from(&sk);
    let ak = ordinary.to_bytes()[..32].try_into().unwrap();
    let fvk = loki_poc::zip2005::frost_viewing_key(&ak, &[42; 32]).unwrap();
    let height = loki_poc::network::TESTNET_NU7_BIRTH + 1;
    let previous = ChainState::empty(BlockHeight::from_u32(height - 1), BlockHash([7; 32]));
    let birthday = AccountBirthday::from_parts(previous.clone(), None);
    let block = CompactBlock {
        height: u64::from(height),
        hash: vec![8; 32],
        prev_hash: vec![7; 32],
        chain_metadata: Some(ChainMetadata {
            sapling_commitment_tree_size: 0,
            orchard_commitment_tree_size: 0,
            ironwood_commitment_tree_size: 0,
        }),
        ..Default::default()
    };
    let mut wallet = loki_poc::wallet_store::VaultWallet::open(
        &path,
        Network::TestNetwork,
        &fvk,
        &birthday,
        "correct horse",
    )
    .unwrap();
    wallet.sync_blocks(&previous, &[block]).unwrap();
    assert_eq!(wallet.scanned_height().unwrap(), Some(height));
    drop(wallet);
    let wallet = loki_poc::wallet_store::VaultWallet::open(
        &path,
        Network::TestNetwork,
        &fvk,
        &birthday,
        "correct horse",
    )
    .unwrap();
    assert_eq!(wallet.scanned_height().unwrap(), Some(height));
    drop(wallet);
    std::fs::remove_file(path).unwrap();
}

#[test]
fn received_ironwood_note_updates_persistent_vault_balance() {
    let path = std::env::temp_dir().join(format!(
        "loki-wallet-note-{}-{}.db",
        std::process::id(),
        rand_zp::random::<u64>()
    ));
    let sk = SpendingKey::from_bytes([42; 32]).unwrap();
    let ordinary = FullViewingKey::from(&sk);
    let ak = ordinary.to_bytes()[..32].try_into().unwrap();
    let fvk = loki_poc::zip2005::frost_viewing_key(&ak, &[42; 32]).unwrap();
    let height = loki_poc::network::TESTNET_NU7_BIRTH + 1;
    let previous = ChainState::empty(BlockHeight::from_u32(height - 1), BlockHash([7; 32]));
    let birthday = AccountBirthday::from_parts(previous.clone(), None);
    let rho = Rho::from_bytes(&[12; 32]).unwrap();
    let rseed = RandomSeed::from_bytes([13; 32], &rho).unwrap();
    let note = Note::from_parts(
        fvk.address_at(0u64, Scope::External),
        NoteValue::from_raw(400_000),
        rho,
        rseed,
        NoteVersion::V3,
    )
    .unwrap();
    let enc = IronwoodNoteEncryption::new(None, note, [0; 512]);
    let block = CompactBlock {
        height: u64::from(height),
        hash: vec![8; 32],
        prev_hash: vec![7; 32],
        chain_metadata: Some(ChainMetadata {
            sapling_commitment_tree_size: 0,
            orchard_commitment_tree_size: 0,
            ironwood_commitment_tree_size: 1,
        }),
        vtx: vec![CompactTx {
            index: 1,
            txid: vec![9; 32],
            ironwood_actions: vec![CompactOrchardAction {
                nullifier: vec![12; 32],
                cmx: ExtractedNoteCommitment::from(note.commitment())
                    .to_bytes()
                    .to_vec(),
                ephemeral_key: IronwoodDomain::epk_bytes(enc.epk()).0.to_vec(),
                ciphertext: enc.encrypt_note_plaintext()[..52].to_vec(),
            }],
            ..Default::default()
        }],
        ..Default::default()
    };
    let mut wallet = loki_poc::wallet_store::VaultWallet::open(
        &path,
        Network::TestNetwork,
        &fvk,
        &birthday,
        "correct horse",
    )
    .unwrap();
    wallet.sync_blocks(&previous, &[block]).unwrap();
    assert_eq!(wallet.ironwood_balance_zat().unwrap(), 400_000);
    drop(wallet);
    let wallet = loki_poc::wallet_store::VaultWallet::open(
        &path,
        Network::TestNetwork,
        &fvk,
        &birthday,
        "correct horse",
    )
    .unwrap();
    assert_eq!(wallet.ironwood_balance_zat().unwrap(), 400_000);
    let cmx = ExtractedNoteCommitment::from(note.commitment());
    let frontier = NonEmptyFrontier::new(orchard::tree::MerkleHashOrchard::from_cmx(&cmx));
    let inputs = wallet
        .ironwood_inputs_at(BlockHeight::from_u32(height), frontier.clone())
        .unwrap();
    assert_eq!(inputs.len(), 1);
    assert_eq!(inputs[0].0.note().value().inner(), 400_000);
    assert_eq!(inputs[0].1.position(), 0);
    assert_eq!(
        inputs[0].1.root(cmx).to_bytes(),
        orchard::tree::Anchor::from(frontier.root(Some(Level::from(32u8)))).to_bytes()
    );
    drop(wallet);
    std::fs::remove_file(path).unwrap();
}
