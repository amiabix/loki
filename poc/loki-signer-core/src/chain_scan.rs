//! The vault's Ironwood balance and history from lightwalletd compact blocks, for a signer with
//! no wallet database (the in-browser signer). Trial decryption is zcash_client_backend's
//! `scan_block`, the scanner the native wallet runs through `scan_cached_blocks`. Spends are
//! found by matching every compact action's nullifier against the vault's own notes, so the
//! scan state is just those notes plus the last block scanned.

use std::collections::BTreeMap;

use orchard::keys::FullViewingKey;
use prost::Message;
use serde::Serialize;
use zcash_client_backend::{
    data_api::BlockMetadata,
    proto::compact_formats::CompactBlock,
    scanning::{scan_block, Nullifiers, ScanningKeys},
};
use zcash_keys::keys::UnifiedFullViewingKey;

use crate::network::VaultNetwork;

/// One note the vault received.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Received {
    pub height: u32,
    pub txid: String,
    pub value_zat: u64,
    /// Change back to the vault (internal scope), not an incoming payment.
    pub change: bool,
    /// The transaction that spent it and its height, once seen on chain.
    pub spent_in: Option<(String, u32)>,
}

/// What one transaction did to the vault, from the chain alone.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct TxEffect {
    pub txid: String,
    pub height: u32,
    /// Received at the vault's external address.
    pub received_zat: u64,
    /// Returned to the vault as change.
    pub change_zat: u64,
    /// Value of the vault notes this transaction spent.
    pub spent_zat: u64,
}

pub struct ChainScan {
    network: VaultNetwork,
    keys: ScanningKeys<u32, (u32, zip32::Scope)>,
    /// Keyed by each note's spend nullifier.
    notes: BTreeMap<[u8; 32], Received>,
    prior: Option<BlockMetadata>,
    /// Where a fresh scan starts: the vault's birth height.
    birth: u32,
}

impl ChainScan {
    pub fn new(network: VaultNetwork, fvk: &FullViewingKey, birth: u32) -> Result<Self, String> {
        let ufvk = UnifiedFullViewingKey::from_orchard_fvk(fvk.clone()).map_err(|e| format!("vault viewing key: {e:?}"))?;
        Ok(Self { network, keys: ScanningKeys::from_account_ufvks([(0u32, ufvk)]), notes: BTreeMap::new(), prior: None, birth })
    }

    /// The last block scanned, if any.
    pub fn height(&self) -> Option<u32> {
        self.prior.as_ref().map(|m| m.block_height().into())
    }

    /// The height of the next block to scan.
    pub fn next_height(&self) -> u32 {
        self.height().map_or(self.birth, |h| h + 1)
    }

    /// Scan the next compact block (protobuf bytes, as lightwalletd streams it). Blocks must
    /// come in order; one that does not extend the last block scanned is refused.
    pub fn scan(&mut self, block: &[u8]) -> Result<(), String> {
        let block = CompactBlock::decode(block).map_err(|e| format!("compact block: {e}"))?;
        let at = u32::try_from(block.height).map_err(|_| "block height out of range")?;
        if at != self.next_height() {
            return Err(format!("expected block {}, got {at}", self.next_height()));
        }
        let spent: Vec<([u8; 32], String)> = block.vtx.iter().flat_map(|tx| {
            let txid = tx_id(&tx.txid);
            tx.ironwood_actions.iter().filter_map(move |a| Some((a.nullifier.as_slice().try_into().ok()?, txid.clone())))
        }).collect();
        let scanned = scan_block(&self.network, block, &self.keys, &Nullifiers::empty(), self.prior.as_ref())
            .map_err(|e| format!("scan block: {e}"))?;
        let height: u32 = scanned.height().into();
        for tx in scanned.transactions() {
            for out in tx.ironwood_outputs() {
                let nf = out.nf().ok_or("received note without a nullifier")?.to_bytes();
                self.notes.insert(nf, Received {
                    height,
                    txid: tx.txid().to_string(),
                    value_zat: out.note().0.value().inner(),
                    // By scope: the library's own change flag needs the spends it was not given.
                    change: out.recipient_key_scope() == Some(zip32::Scope::Internal),
                    spent_in: None,
                });
            }
        }
        for (nf, txid) in spent {
            if let Some(note) = self.notes.get_mut(&nf) {
                note.spent_in.get_or_insert((txid, at));
            }
        }
        self.prior = Some(scanned.to_block_metadata());
        Ok(())
    }

    /// Unspent Ironwood value, as `VaultWallet::ironwood_balance_zat` counts it.
    pub fn balance_zat(&self) -> u64 {
        self.notes.values().filter(|n| n.spent_in.is_none()).map(|n| n.value_zat).sum()
    }

    pub fn notes(&self) -> impl Iterator<Item = &Received> {
        self.notes.values()
    }

    /// Every transaction that touched the vault, newest first.
    pub fn history(&self) -> Vec<TxEffect> {
        let mut by_tx: BTreeMap<String, TxEffect> = BTreeMap::new();
        fn entry<'a>(by_tx: &'a mut BTreeMap<String, TxEffect>, txid: &str, height: u32) -> &'a mut TxEffect {
            by_tx.entry(txid.to_owned()).or_insert_with(|| TxEffect { txid: txid.to_owned(), height, received_zat: 0, change_zat: 0, spent_zat: 0 })
        }
        for n in self.notes.values() {
            let e = entry(&mut by_tx, &n.txid, n.height);
            if n.change { e.change_zat += n.value_zat } else { e.received_zat += n.value_zat }
        }
        for n in self.notes.values() {
            if let Some((txid, height)) = &n.spent_in {
                entry(&mut by_tx, txid, *height).spent_zat += n.value_zat;
            }
        }
        let mut out: Vec<TxEffect> = by_tx.into_values().collect();
        out.sort_by(|a, b| b.height.cmp(&a.height).then_with(|| a.txid.cmp(&b.txid)));
        out
    }
}

/// A compact transaction id as explorers show it (byte-reversed hex).
fn tx_id(bytes: &[u8]) -> String {
    bytes.iter().rev().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use orchard::{
        keys::{Scope, SpendingKey},
        note::{ExtractedNoteCommitment, Note, NoteVersion, Nullifier, Rho},
        note_encryption::{IronwoodDomain, IronwoodNoteEncryption},
        value::NoteValue,
    };
    use zcash_client_backend::proto::compact_formats::{ChainMetadata, CompactOrchardAction, CompactTx};
    use zcash_note_encryption::Domain;

    const H: u64 = 4_638_988;

    fn fvk(seed: u8) -> FullViewingKey {
        FullViewingKey::from(&SpendingKey::from_bytes([seed; 32]).unwrap())
    }

    /// An Ironwood output to `to`, as a compact action that spends `nf_old`.
    fn action(to: &FullViewingKey, scope: Scope, value: u64, nf_old: Nullifier) -> (Note, CompactOrchardAction) {
        let note = Note::new(to.address_at(0u32, scope), NoteValue::from_raw(value), Rho::from_nf_old(nf_old), NoteVersion::V3, rand_zp::rng());
        let enc = IronwoodNoteEncryption::new(None, note, [0u8; 512]);
        (note, CompactOrchardAction {
            nullifier: nf_old.to_bytes().to_vec(),
            cmx: ExtractedNoteCommitment::from(note.commitment()).to_bytes().to_vec(),
            ephemeral_key: IronwoodDomain::epk_bytes(enc.epk()).0.to_vec(),
            ciphertext: AsRef::<[u8]>::as_ref(&enc.encrypt_note_plaintext())[..52].to_vec(),
        })
    }

    fn block(height: u64, hash: u8, prev: u8, txs: Vec<(u8, Vec<CompactOrchardAction>)>, ironwood_size: u32) -> Vec<u8> {
        CompactBlock {
            height,
            hash: vec![hash; 32],
            prev_hash: vec![prev; 32],
            vtx: txs.into_iter().enumerate().map(|(i, (id, ironwood_actions))| CompactTx { index: i as u64, txid: vec![id; 32], ironwood_actions, ..Default::default() }).collect(),
            chain_metadata: Some(ChainMetadata { ironwood_commitment_tree_size: ironwood_size, ..Default::default() }),
            ..Default::default()
        }
        .encode_to_vec()
    }

    #[test]
    fn finds_received_notes_and_their_spends() {
        let vault = fvk(1);
        let other = fvk(2);
        let zero = Nullifier::from_bytes(&[0u8; 32]).unwrap();
        let (paid, to_vault) = action(&vault, Scope::External, 50_000, zero);
        let (_, to_other) = action(&other, Scope::External, 10_000, paid.nullifier(&other));
        let mut scan = ChainScan::new(VaultNetwork::Testnet, &vault, H as u32).unwrap();
        scan.scan(&block(H, 0xa0, 0x9f, vec![(0xaa, vec![to_vault]), (0xab, vec![to_other])], 2)).unwrap();
        assert_eq!(scan.height(), Some(H as u32));
        assert_eq!(scan.balance_zat(), 50_000);
        assert_eq!(scan.history(), vec![TxEffect { txid: "aa".repeat(32), height: H as u32, received_zat: 50_000, change_zat: 0, spent_zat: 0 }]);

        // The vault spends that note and gets change back on its internal address.
        let (_, change) = action(&vault, Scope::Internal, 39_000, paid.nullifier(&vault));
        scan.scan(&block(H + 1, 0xa1, 0xa0, vec![(0xbb, vec![change])], 3)).unwrap();
        assert_eq!(scan.balance_zat(), 39_000);
        assert_eq!(scan.history(), vec![
            TxEffect { txid: "bb".repeat(32), height: H as u32 + 1, received_zat: 0, change_zat: 39_000, spent_zat: 50_000 },
            TxEffect { txid: "aa".repeat(32), height: H as u32, received_zat: 50_000, change_zat: 0, spent_zat: 0 },
        ]);
    }

    #[test]
    fn refuses_a_block_that_does_not_extend_the_last() {
        let mut scan = ChainScan::new(VaultNetwork::Testnet, &fvk(1), H as u32).unwrap();
        scan.scan(&block(H, 0xa0, 0x9f, vec![], 0)).unwrap();
        assert!(scan.scan(&block(H + 1, 0xa1, 0x55, vec![], 0)).is_err());
        assert!(scan.scan(&block(H + 2, 0xa2, 0xa0, vec![], 0)).is_err(), "a gap is refused");
        assert_eq!(scan.next_height(), H as u32 + 1);
    }
}
