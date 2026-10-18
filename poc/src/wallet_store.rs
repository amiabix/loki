use std::{collections::BTreeMap, convert::Infallible, fs, io, path::Path, sync::Mutex};

use argon2::Argon2;
use async_trait::async_trait;
use incrementalmerkletree::frontier::NonEmptyFrontier;
use orchard::keys::FullViewingKey;
use orchard::{
    note::Note,
    tree::{MerkleHashOrchard, MerklePath},
};
use rand_zp::{rand_core::UnwrapErr, rngs::SysRng};
use rusqlite::{Connection, OptionalExtension};
use zcash_client_backend::{
    data_api::{
        AccountBirthday, AccountPurpose, OutputLockStore, WalletRead, WalletWrite,
        chain::{
            BlockCache, BlockSource, ChainState, error::Error as ScanError, scan_cached_blocks,
        },
        scanning::ScanRange,
    },
    proto::compact_formats::CompactBlock,
    wallet::{LockOwner, OutputRef, ReceivedNote},
};
use zcash_client_sqlite::{
    ReceivedNoteId, WalletDb, util::SystemClock, wallet::init::init_wallet_db,
};
use zcash_keys::keys::UnifiedFullViewingKey;
use zcash_primitives::transaction::TxId;
use zcash_protocol::consensus::{BlockHeight, Network};
use zcash_protocol::PoolType;
use zeroize::Zeroizing;

type Database = WalletDb<Connection, Network, SystemClock, UnwrapErr<SysRng>>;

pub struct VaultWallet {
    db: Database,
    network: Network,
}

struct Blocks<'a>(&'a [CompactBlock]);

#[derive(Default)]
struct DownloadedBlocks(Mutex<BTreeMap<u32, CompactBlock>>);

impl BlockSource for DownloadedBlocks {
    type Error = io::Error;

    fn with_blocks<F, E>(
        &self,
        from_height: Option<BlockHeight>,
        limit: Option<usize>,
        mut with_block: F,
    ) -> Result<(), ScanError<E, Self::Error>>
    where
        F: FnMut(CompactBlock) -> Result<(), ScanError<E, Self::Error>>,
    {
        let blocks = self.0.lock().map_err(|_| {
            ScanError::BlockSource(io::Error::other("compact block cache poisoned"))
        })?;
        for (_, block) in blocks
            .range(from_height.map(u32::from).unwrap_or(0)..)
            .take(limit.unwrap_or(usize::MAX))
        {
            with_block(block.clone())?;
        }
        Ok(())
    }
}

#[async_trait]
impl BlockCache for DownloadedBlocks {
    fn get_tip_height(
        &self,
        range: Option<&ScanRange>,
    ) -> Result<Option<BlockHeight>, Self::Error> {
        let blocks = self
            .0
            .lock()
            .map_err(|_| io::Error::other("compact block cache poisoned"))?;
        Ok(blocks
            .keys()
            .rev()
            .find(|height| {
                range.is_none_or(|range| {
                    range
                        .block_range()
                        .contains(&BlockHeight::from_u32(**height))
                })
            })
            .copied()
            .map(BlockHeight::from_u32))
    }

    async fn read(&self, range: &ScanRange) -> Result<Vec<CompactBlock>, Self::Error> {
        let blocks = self
            .0
            .lock()
            .map_err(|_| io::Error::other("compact block cache poisoned"))?;
        (u32::from(range.block_range().start)..u32::from(range.block_range().end))
            .map(|height| {
                blocks
                    .get(&height)
                    .cloned()
                    .ok_or_else(|| io::Error::other(format!("missing compact block {height}")))
            })
            .collect()
    }

    async fn insert(&self, compact_blocks: Vec<CompactBlock>) -> Result<(), Self::Error> {
        let mut blocks = self
            .0
            .lock()
            .map_err(|_| io::Error::other("compact block cache poisoned"))?;
        for block in compact_blocks {
            let height = u32::try_from(block.height)
                .map_err(|_| io::Error::other("compact block height overflow"))?;
            blocks.insert(height, block);
        }
        Ok(())
    }

    async fn delete(&self, range: ScanRange) -> Result<(), Self::Error> {
        let mut blocks = self
            .0
            .lock()
            .map_err(|_| io::Error::other("compact block cache poisoned"))?;
        blocks.retain(|height, _| {
            !range
                .block_range()
                .contains(&BlockHeight::from_u32(*height))
        });
        Ok(())
    }
}

impl BlockSource for Blocks<'_> {
    type Error = Infallible;

    fn with_blocks<F, E>(
        &self,
        from_height: Option<BlockHeight>,
        limit: Option<usize>,
        mut with_block: F,
    ) -> Result<(), ScanError<E, Self::Error>>
    where
        F: FnMut(CompactBlock) -> Result<(), ScanError<E, Self::Error>>,
    {
        let blocks = self
            .0
            .iter()
            .filter(|block| from_height.is_none_or(|height| block.height >= u64::from(height)));
        for block in blocks.take(limit.unwrap_or(usize::MAX)) {
            with_block(block.clone())?;
        }
        Ok(())
    }
}

impl VaultWallet {
    pub async fn sync_testnet(
        &mut self,
        client: &mut zcash_client_backend::proto::service::compact_tx_streamer_client::CompactTxStreamerClient<tonic::transport::Channel>,
    ) -> Result<(), String> {
        if self.network != Network::TestNetwork {
            return Err("wallet sync currently supports Testnet only".into());
        }
        zcash_client_backend::sync::run(
            client,
            &self.network,
            &DownloadedBlocks::default(),
            &mut self.db,
            100,
        )
        .await
        .map_err(|e| format!("sync Testnet wallet: {e}"))?;
        self.release_confirmed_reservations()
    }

    pub fn open(
        path: &Path,
        network: Network,
        fvk: &FullViewingKey,
        birthday: &AccountBirthday,
        passphrase: &str,
    ) -> Result<Self, String> {
        Self::open_inner(path, network, fvk, Some(birthday), passphrase)
    }

    pub fn open_existing(
        path: &Path,
        network: Network,
        fvk: &FullViewingKey,
        birth_height: u32,
        passphrase: &str,
    ) -> Result<Self, String> {
        if !path.is_file() {
            return Err("wallet database is missing; run loki_wallet_sync first".into());
        }
        let wallet = Self::open_inner(path, network, fvk, None, passphrase)?;
        let account = wallet
            .db
            .get_account_ids()
            .map_err(|e| e.to_string())?
            .into_iter()
            .next()
            .ok_or("wallet database has no vault account")?;
        if wallet
            .db
            .get_account_birthday(account)
            .map_err(|e| e.to_string())?
            != BlockHeight::from_u32(birth_height)
        {
            return Err("wallet database has a different vault birth height".into());
        }
        Ok(wallet)
    }

    fn open_inner(
        path: &Path,
        network: Network,
        fvk: &FullViewingKey,
        birthday: Option<&AccountBirthday>,
        passphrase: &str,
    ) -> Result<Self, String> {
        if !path.exists() {
            let mut options = fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            options
                .open(path)
                .map_err(|e| format!("create wallet database: {e}"))?;
        }
        let conn = Connection::open(path).map_err(|e| format!("open wallet database: {e}"))?;
        let salt = blake3::derive_key("Loki wallet database salt v1", &fvk.to_bytes());
        let mut key = Zeroizing::new([0u8; 32]);
        Argon2::default()
            .hash_password_into(passphrase.as_bytes(), &salt[..16], key.as_mut())
            .map_err(|e| format!("derive wallet database key: {e}"))?;
        let pragma = Zeroizing::new(format!("PRAGMA key = \"x'{}'\";", hex::encode(*key)));
        conn.execute_batch(&pragma)
            .map_err(|e| format!("unlock wallet database: {e}"))?;
        let _: String = conn
            .query_row("PRAGMA cipher_version", [], |row| row.get(0))
            .map_err(|e| format!("SQLCipher unavailable: {e}"))?;
        conn.query_row("SELECT name FROM sqlite_master LIMIT 1", [], |row| {
            row.get::<_, String>(0)
        })
        .optional()
        .map_err(|e| format!("wrong wallet passphrase or damaged database: {e}"))?;
        rusqlite::vtab::array::load_module(&conn)
            .map_err(|e| format!("initialize wallet array queries: {e}"))?;

        let mut db = WalletDb::from_connection(conn, network, SystemClock, UnwrapErr(SysRng));
        init_wallet_db(&mut db, None).map_err(|e| format!("initialize wallet database: {e}"))?;
        let keys = db
            .get_unified_full_viewing_keys()
            .map_err(|e| format!("read wallet accounts: {e}"))?;
        if keys.is_empty() {
            let birthday = birthday.ok_or("wallet database has no vault account")?;
            let ufvk = UnifiedFullViewingKey::from_orchard_fvk(fvk.clone())
                .map_err(|e| format!("vault viewing key: {e:?}"))?;
            db.import_account_ufvk(
                "Loki vault",
                &ufvk,
                birthday,
                AccountPurpose::Spending { derivation: None },
                None,
            )
            .map_err(|e| format!("import vault viewing key: {e}"))?;
        } else if keys.len() != 1
            || keys
                .values()
                .next()
                .and_then(UnifiedFullViewingKey::orchard)
                .map(|saved| saved.to_bytes())
                != Some(fvk.to_bytes())
        {
            return Err("wallet database belongs to another vault".into());
        }
        let account = db
            .get_account_ids()
            .map_err(|e| format!("read wallet accounts: {e}"))?
            .into_iter()
            .next()
            .ok_or("wallet database has no vault account")?;
        if let Some(birthday) = birthday {
            if db
                .get_account_birthday(account)
                .map_err(|e| format!("read wallet birthday: {e}"))?
                != birthday.height()
            {
                return Err("wallet database has a different vault birth height".into());
            }
        }
        Ok(Self { db, network })
    }

    pub fn viewing_key(&self) -> Result<FullViewingKey, String> {
        let keys = self
            .db
            .get_unified_full_viewing_keys()
            .map_err(|e| format!("read vault viewing key: {e}"))?;
        let fvk = keys
            .values()
            .next()
            .and_then(UnifiedFullViewingKey::orchard)
            .ok_or("wallet database has no vault viewing key")?;
        Ok(fvk.clone())
    }

    pub fn account_count(&self) -> Result<usize, String> {
        self.db
            .get_account_ids()
            .map(|ids| ids.len())
            .map_err(|e| format!("read wallet accounts: {e}"))
    }

    pub fn sync_blocks(
        &mut self,
        previous: &ChainState,
        blocks: &[CompactBlock],
    ) -> Result<(), String> {
        if blocks.is_empty() {
            return Ok(());
        }
        let first = blocks.first().expect("nonempty blocks");
        if first.height != u64::from(previous.block_height()) + 1
            || first.prev_hash != previous.block_hash().0
            || blocks.windows(2).any(|pair| {
                pair[1].height != pair[0].height + 1 || pair[1].prev_hash != pair[0].hash
            })
        {
            return Err("compact blocks do not extend the supplied chain state".into());
        }
        scan_cached_blocks(
            &self.network,
            &Blocks(blocks),
            &mut self.db,
            BlockHeight::try_from(first.height).map_err(|_| "block height overflow")?,
            previous,
            blocks.len(),
        )
        .map_err(|e| format!("scan Ironwood blocks: {e}"))?;
        let last = blocks.last().expect("nonempty blocks");
        self.db
            .update_chain_tip(
                BlockHeight::try_from(last.height).map_err(|_| "block height overflow")?,
            )
            .map_err(|e| format!("save chain tip: {e}"))?;
        self.release_confirmed_reservations()
    }

    pub fn scanned_height(&self) -> Result<Option<u32>, String> {
        self.db
            .block_fully_scanned()
            .map(|block| block.map(|metadata| u32::from(metadata.block_height())))
            .map_err(|e| format!("read scan height: {e}"))
    }

    pub fn scanned_hash(&self, height: BlockHeight) -> Result<String, String> {
        self.db
            .get_block_hash(height)
            .map_err(|e| format!("read scanned block hash: {e}"))?
            .map(|hash| hash.to_string())
            .ok_or_else(|| "wallet has no hash for its scanned height".into())
    }

    pub fn mined_height(&self, txid: TxId) -> Result<Option<BlockHeight>, String> {
        self.db.get_tx_height(txid)
            .map_err(|e| format!("read indexed transaction height: {e}"))
    }

    pub fn ironwood_balance_zat(&self) -> Result<u64, String> {
        let height = BlockHeight::from_u32(
            self.scanned_height()?
                .ok_or("wallet has no scanned balance yet")?,
        );
        let account = self
            .db
            .get_account_ids()
            .map_err(|e| e.to_string())?
            .into_iter()
            .next()
            .ok_or("wallet has no vault account")?;
        self.db
            .get_unspent_ironwood_notes_at_historical_height(account, height)
            .map_err(|e| format!("read Ironwood notes: {e}"))?
            .iter()
            .try_fold(0u64, |sum, note| {
                sum.checked_add(note.note().value().inner())
                    .ok_or_else(|| "vault balance exceeds u64".to_string())
            })
    }

    pub fn ironwood_note_count(&self, height: BlockHeight) -> Result<usize, String> {
        let account = self
            .db
            .get_account_ids()
            .map_err(|e| e.to_string())?
            .into_iter()
            .next()
            .ok_or("wallet has no vault account")?;
        self.db
            .get_unspent_ironwood_notes_at_historical_height(account, height)
            .map(|notes| notes.len())
            .map_err(|e| format!("read Ironwood notes: {e}"))
    }

    pub fn ironwood_inputs_at(
        &self,
        height: BlockHeight,
        frontier: NonEmptyFrontier<MerkleHashOrchard>,
    ) -> Result<Vec<(ReceivedNote<ReceivedNoteId, Note>, MerklePath)>, String> {
        let account = self
            .db
            .get_account_ids()
            .map_err(|e| format!("read vault account: {e}"))?
            .into_iter()
            .next()
            .ok_or("wallet has no vault account")?;
        let notes = self
            .db
            .get_unspent_ironwood_notes_at_historical_height(account, height)
            .map_err(|e| format!("read Ironwood notes: {e}"))?;
        if notes.is_empty() {
            return Ok(Vec::new());
        }
        let positions = notes
            .iter()
            .map(ReceivedNote::note_commitment_tree_position)
            .collect::<Vec<_>>();
        let witnesses = self
            .db
            .generate_ironwood_witnesses_at_historical_height(&positions, frontier, height)
            .map_err(|e| format!("generate Ironwood witnesses: {e}"))?;
        if notes.len() != witnesses.len() {
            return Err("wallet returned a different number of witnesses than notes".into());
        }
        Ok(notes
            .into_iter()
            .zip(witnesses.into_iter().map(MerklePath::from))
            .collect())
    }

    pub fn spendable_ironwood_inputs_at(
        &self,
        height: BlockHeight,
        frontier: NonEmptyFrontier<MerkleHashOrchard>,
    ) -> Result<Vec<(ReceivedNote<ReceivedNoteId, Note>, MerklePath)>, String> {
        let account = self
            .db
            .get_account_ids()
            .map_err(|e| e.to_string())?
            .into_iter()
            .next()
            .ok_or("wallet has no vault account")?;
        let locked = self
            .db
            .get_locked_outputs(account)
            .map_err(|e| format!("read reserved inputs: {e}"))?;
        Ok(self
            .ironwood_inputs_at(height, frontier)?
            .into_iter()
            .filter(|(note, _)| {
                !locked.contains(&OutputRef::new(
                    *note.txid(),
                    PoolType::IRONWOOD,
                    note.output_index().into(),
                ))
            })
            .collect())
    }

    pub fn reserve_broadcast_inputs(
        &mut self,
        txid: TxId,
        nullifiers: &[[u8; 32]],
        expiry_height: u32,
    ) -> Result<(), String> {
        let height = self
            .scanned_height()?
            .ok_or("wallet has not scanned any blocks")?;
        if nullifiers.is_empty() || expiry_height <= height {
            return Err("payment has no inputs or has expired".into());
        }
        let account = self
            .db
            .get_account_ids()
            .map_err(|e| e.to_string())?
            .into_iter()
            .next()
            .ok_or("wallet has no vault account")?;
        let fvk = self.viewing_key()?;
        let notes = self
            .db
            .get_unspent_ironwood_notes_at_historical_height(account, BlockHeight::from_u32(height))
            .map_err(|e| format!("read Ironwood notes: {e}"))?;
        let outputs = nullifiers
            .iter()
            .map(|nf| {
                notes
                    .iter()
                    .find(|note| note.note().nullifier(&fvk).to_bytes() == *nf)
                    .map(|note| {
                        OutputRef::new(*note.txid(), PoolType::IRONWOOD, note.output_index().into())
                    })
                    .ok_or_else(|| format!("payment input {} is not unspent", hex::encode(nf)))
            })
            .collect::<Result<Vec<_>, _>>()?;
        self.db
            .lock_outputs(&outputs, txid.into(), BlockHeight::from_u32(expiry_height))
            .map_err(|e| format!("reserve payment inputs: {e}"))?;
        Ok(())
    }

    fn release_confirmed_reservations(&mut self) -> Result<(), String> {
        let account = self
            .db
            .get_account_ids()
            .map_err(|e| e.to_string())?
            .into_iter()
            .next()
            .ok_or("wallet has no vault account")?;
        let locked = self
            .db
            .get_locked_outputs(account)
            .map_err(|e| format!("read reserved inputs: {e}"))?;
        if locked.is_empty() {
            return Ok(());
        }
        self.db
            .transactionally_with_extension(|db, ext| {
                for output in locked
                    .iter()
                    .filter(|output| output.pool() == PoolType::IRONWOOD)
                {
                    let owner: Option<Vec<u8>> = ext
                        .query_row(
                            "SELECT rn.lock_owner FROM ironwood_received_notes rn \
                     JOIN transactions t ON t.id_tx = rn.transaction_id \
                     WHERE t.txid = ?1 AND rn.action_index = ?2",
                            rusqlite::params![output.txid().as_ref(), output.output_index()],
                            |row| row.get(0),
                        )
                        .optional()?
                        .flatten();
                    if let Some(owner) = owner {
                        let owner: [u8; 32] = owner
                            .try_into()
                            .map_err(|_| io::Error::other("invalid payment reservation owner"))?;
                        if db.get_tx_height(TxId::from_bytes(owner))?.is_some() {
                            db.unlock_output(output, LockOwner::new(owner))?;
                        }
                    }
                }
                Ok::<(), Box<dyn std::error::Error>>(())
            })
            .map_err(|e| format!("release confirmed payment inputs: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use incrementalmerkletree::frontier::Frontier;
    use orchard::{
        keys::{Scope, SpendingKey},
        note::{ExtractedNoteCommitment, Note, NoteVersion, RandomSeed, Rho},
        note_encryption::{IronwoodDomain, IronwoodNoteEncryption},
        value::NoteValue,
    };
    use zcash_client_backend::data_api::scanning::ScanPriority;
    use zcash_client_backend::proto::compact_formats::{
        ChainMetadata, CompactOrchardAction, CompactTx,
    };
    use zcash_note_encryption::Domain;
    use zcash_primitives::block::BlockHash;

    #[test]
    fn downloaded_blocks_must_be_contiguous_and_can_be_replaced() {
        let cache = DownloadedBlocks::default();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let range = ScanRange::from_parts(
            BlockHeight::from_u32(7)..BlockHeight::from_u32(10),
            ScanPriority::Historic,
        );
        runtime.block_on(async {
            cache
                .insert(vec![
                    CompactBlock {
                        height: 7,
                        ..Default::default()
                    },
                    CompactBlock {
                        height: 9,
                        ..Default::default()
                    },
                ])
                .await
                .unwrap();
            assert!(cache.read(&range).await.is_err());
            cache
                .insert(vec![CompactBlock {
                    height: 8,
                    ..Default::default()
                }])
                .await
                .unwrap();
            assert_eq!(cache.read(&range).await.unwrap().len(), 3);
            cache
                .insert(vec![CompactBlock {
                    height: 8,
                    hash: vec![42; 32],
                    ..Default::default()
                }])
                .await
                .unwrap();
            assert_eq!(cache.read(&range).await.unwrap()[1].hash, vec![42; 32]);
            cache.truncate(BlockHeight::from_u32(8)).await.unwrap();
            assert_eq!(
                cache.get_tip_height(None).unwrap(),
                Some(BlockHeight::from_u32(8))
            );
        });
    }

    #[test]
    fn broadcast_reservation_expires_and_reorg_releases_confirmed_spend() {
        let fvk = FullViewingKey::from(&SpendingKey::from_bytes([3; 32]).unwrap());
        let height = crate::network::TESTNET_NU7_BIRTH;
        let prior = ChainState::empty(BlockHeight::from_u32(height - 1), BlockHash([7; 32]));
        let birthday = AccountBirthday::from_parts(prior.clone(), None);
        let path = std::env::temp_dir().join(format!(
            "loki-wallet-reorg-{}-{}.sqlite",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let rho = Rho::from_bytes(&[4; 32]).unwrap();
        let rseed = RandomSeed::from_bytes([5; 32], &rho).unwrap();
        let note = Note::from_parts(
            fvk.address_at(0u64, Scope::External),
            NoteValue::from_raw(50_000),
            rho,
            rseed,
            NoteVersion::V3,
        )
        .unwrap();
        let enc = IronwoodNoteEncryption::new(None, note, [0; 512]);
        let cmx = ExtractedNoteCommitment::from(note.commitment());
        let funded = CompactBlock {
            height: u64::from(height),
            hash: vec![8; 32],
            prev_hash: vec![7; 32],
            vtx: vec![CompactTx {
                txid: vec![6; 32],
                index: 1,
                ironwood_actions: vec![CompactOrchardAction {
                    nullifier: vec![4; 32],
                    cmx: cmx.to_bytes().to_vec(),
                    ephemeral_key: IronwoodDomain::epk_bytes(enc.epk()).0.to_vec(),
                    ciphertext: enc.encrypt_note_plaintext()[..52].to_vec(),
                }],
                ..Default::default()
            }],
            chain_metadata: Some(ChainMetadata {
                ironwood_commitment_tree_size: 1,
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut wallet =
            VaultWallet::open(&path, Network::TestNetwork, &fvk, &birthday, "pass").unwrap();
        wallet.sync_blocks(&prior, &[funded]).unwrap();
        drop(wallet);
        let mut wallet =
            VaultWallet::open_existing(&path, Network::TestNetwork, &fvk, height, "pass").unwrap();
        assert_eq!(
            wallet.scanned_hash(BlockHeight::from_u32(height)).unwrap(),
            BlockHash([8; 32]).to_string()
        );
        assert_eq!(
            wallet.mined_height(TxId::from_bytes([6; 32])).unwrap(),
            Some(BlockHeight::from_u32(height))
        );
        assert_eq!(wallet.ironwood_balance_zat().unwrap(), 50_000);
        assert_eq!(
            wallet
                .ironwood_note_count(BlockHeight::from_u32(height))
                .unwrap(),
            1
        );
        let mut frontier = Frontier::<MerkleHashOrchard, 32>::empty();
        assert!(frontier.append(MerkleHashOrchard::from_cmx(&cmx)));
        let inputs = wallet
            .ironwood_inputs_at(
                BlockHeight::from_u32(height),
                frontier.value().unwrap().clone(),
            )
            .unwrap();
        assert_eq!(inputs.len(), 1);
        assert_eq!(inputs[0].1.root(cmx).to_bytes(), frontier.root().to_bytes());
        let nullifier = note.nullifier(&fvk).to_bytes();
        let payment_txid = TxId::from_bytes([10; 32]);
        wallet
            .reserve_broadcast_inputs(payment_txid, &[nullifier], height + 1)
            .unwrap();
        assert!(wallet
            .reserve_broadcast_inputs(TxId::from_bytes([11; 32]), &[nullifier], height + 1)
            .is_err());
        drop(wallet);
        let mut wallet =
            VaultWallet::open_existing(&path, Network::TestNetwork, &fvk, height, "pass").unwrap();
        assert!(wallet
            .spendable_ironwood_inputs_at(
                BlockHeight::from_u32(height),
                frontier.value().unwrap().clone()
            )
            .unwrap()
            .is_empty());

        let funded_state = ChainState::new(
            BlockHeight::from_u32(height),
            BlockHash([8; 32]),
            Frontier::empty(),
            Frontier::empty(),
            frontier.clone(),
        );
        let empty = CompactBlock {
            height: u64::from(height + 1),
            hash: vec![9; 32],
            prev_hash: vec![8; 32],
            chain_metadata: Some(ChainMetadata {
                ironwood_commitment_tree_size: 1,
                ..Default::default()
            }),
            ..Default::default()
        };
        wallet.sync_blocks(&funded_state, &[empty]).unwrap();
        assert_eq!(
            wallet
                .spendable_ironwood_inputs_at(
                    BlockHeight::from_u32(height + 1),
                    frontier.value().unwrap().clone()
                )
                .unwrap()
                .len(),
            1
        );

        wallet
            .reserve_broadcast_inputs(payment_txid, &[nullifier], height + 10)
            .unwrap();
        assert!(wallet
            .spendable_ironwood_inputs_at(
                BlockHeight::from_u32(height + 1),
                frontier.value().unwrap().clone()
            )
            .unwrap()
            .is_empty());
        let before_spend = ChainState::new(
            BlockHeight::from_u32(height + 1),
            BlockHash([9; 32]),
            Frontier::empty(),
            Frontier::empty(),
            frontier.clone(),
        );
        let spent = CompactBlock {
            height: u64::from(height + 2),
            hash: vec![10; 32],
            prev_hash: vec![9; 32],
            vtx: vec![CompactTx {
                txid: payment_txid.as_ref().to_vec(),
                index: 1,
                ironwood_actions: vec![CompactOrchardAction {
                    nullifier: nullifier.to_vec(),
                    cmx: vec![0; 32],
                    ephemeral_key: vec![0; 32],
                    ciphertext: vec![0; 52],
                }],
                ..Default::default()
            }],
            chain_metadata: Some(ChainMetadata {
                ironwood_commitment_tree_size: 2,
                ..Default::default()
            }),
            ..Default::default()
        };
        wallet.sync_blocks(&before_spend, &[spent]).unwrap();
        assert_eq!(
            wallet.mined_height(payment_txid).unwrap(),
            Some(BlockHeight::from_u32(height + 2))
        );
        assert_eq!(
            wallet
                .ironwood_note_count(BlockHeight::from_u32(height + 2))
                .unwrap(),
            0
        );
        assert!(wallet
            .spendable_ironwood_inputs_at(
                BlockHeight::from_u32(height + 2),
                frontier.value().unwrap().clone()
            )
            .unwrap()
            .is_empty());
        wallet
            .db
            .truncate_to_chain_state(before_spend.clone())
            .unwrap();
        let replacement_spend = CompactBlock {
            height: u64::from(height + 2),
            hash: vec![11; 32],
            prev_hash: vec![9; 32],
            chain_metadata: Some(ChainMetadata {
                ironwood_commitment_tree_size: 1,
                ..Default::default()
            }),
            ..Default::default()
        };
        wallet
            .sync_blocks(&before_spend, &[replacement_spend])
            .unwrap();
        assert_eq!(wallet.mined_height(payment_txid).unwrap(), None);
        assert_eq!(
            wallet
                .spendable_ironwood_inputs_at(
                    BlockHeight::from_u32(height + 2),
                    frontier.value().unwrap().clone()
                )
                .unwrap()
                .len(),
            1
        );

        wallet.db.truncate_to_chain_state(prior.clone()).unwrap();
        let replacement = CompactBlock {
            height: u64::from(height),
            hash: vec![9; 32],
            prev_hash: vec![7; 32],
            chain_metadata: Some(ChainMetadata::default()),
            ..Default::default()
        };
        wallet.sync_blocks(&prior, &[replacement]).unwrap();
        assert_eq!(
            wallet.scanned_hash(BlockHeight::from_u32(height)).unwrap(),
            BlockHash([9; 32]).to_string()
        );
        assert_eq!(
            wallet.mined_height(TxId::from_bytes([6; 32])).unwrap(),
            None
        );
        assert_eq!(
            wallet
                .ironwood_note_count(BlockHeight::from_u32(height))
                .unwrap(),
            0
        );
        assert_eq!(wallet.ironwood_balance_zat().unwrap(), 0);
        drop(wallet);
        std::fs::remove_file(path).unwrap();
    }
}
