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
        chain::{
            error::Error as ScanError, scan_cached_blocks, BlockCache, BlockSource, ChainState,
        },
        scanning::ScanRange,
        wallet::ConfirmationsPolicy,
        AccountBirthday, AccountPurpose, WalletRead, WalletWrite,
    },
    proto::compact_formats::CompactBlock,
    wallet::ReceivedNote,
};
use zcash_client_sqlite::{
    util::SystemClock, wallet::init::init_wallet_db, ReceivedNoteId, WalletDb,
};
use zcash_keys::keys::UnifiedFullViewingKey;
use zcash_protocol::consensus::{BlockHeight, Network};
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
        .map_err(|e| format!("sync Testnet wallet: {e}"))
    }

    pub fn open(
        path: &Path,
        network: Network,
        fvk: &FullViewingKey,
        birthday: &AccountBirthday,
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
        if db
            .get_account_birthday(account)
            .map_err(|e| format!("read wallet birthday: {e}"))?
            != birthday.height()
        {
            return Err("wallet database has a different vault birth height".into());
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
        Ok(())
    }

    pub fn scanned_height(&self) -> Result<Option<u32>, String> {
        self.db
            .block_fully_scanned()
            .map(|block| block.map(|metadata| u32::from(metadata.block_height())))
            .map_err(|e| format!("read scan height: {e}"))
    }

    pub fn ironwood_balance_zat(&self) -> Result<u64, String> {
        let summary = self
            .db
            .get_wallet_summary(ConfirmationsPolicy::MIN)
            .map_err(|e| format!("read wallet balance: {e}"))?
            .ok_or("wallet has no scanned balance yet")?;
        let account = summary
            .account_balances()
            .values()
            .next()
            .ok_or("wallet has no vault account")?;
        Ok(account.ironwood_balance().total().into_u64())
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use zcash_client_backend::data_api::scanning::ScanPriority;

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
}
