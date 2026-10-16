//! Build an authentication path for a vault note from the chain's commitment stream.
//!
//! The node does not hand out witnesses. Regtest rebuilds from every commitment;
//! Testnet starts from a birth checkpoint and extends incremental witnesses for
//! notes the vault owns.
//!
//! The result is checked against the node's own anchor before it is used, so a mistake
//! here fails loudly rather than producing a transaction consensus will reject.

use incrementalmerkletree::{
    frontier::CommitmentTree as FrontierTree, witness::IncrementalWitness, Hashable, Level,
};
use orchard::{
    note::ExtractedNoteCommitment,
    tree::{MerkleHashOrchard, MerklePath},
};
use std::{collections::BTreeMap, io::Cursor};
use zcash_primitives::merkle_tree::read_commitment_tree;

/// Witnesses for notes created after a node-provided birth-height tree checkpoint.
pub struct BirthWitnesses {
    tree: FrontierTree<MerkleHashOrchard, 32>,
    witnesses: BTreeMap<u64, IncrementalWitness<MerkleHashOrchard, 32>>,
}

impl BirthWitnesses {
    pub fn from_state(bytes: &[u8]) -> Result<Self, String> {
        let mut cursor = Cursor::new(bytes);
        let tree = read_commitment_tree(&mut cursor).map_err(|e| format!("Ironwood tree: {e}"))?;
        if cursor.position() != bytes.len() as u64 {
            return Err("Ironwood tree has trailing bytes".into());
        }
        Ok(Self {
            tree,
            witnesses: BTreeMap::new(),
        })
    }

    pub fn append(&mut self, cmx: [u8; 32]) -> Result<u64, String> {
        let cmx = ExtractedNoteCommitment::from_bytes(&cmx)
            .into_option()
            .ok_or("invalid Ironwood commitment")?;
        let position = self.tree.size() as u64;
        let leaf = MerkleHashOrchard::from_cmx(&cmx);
        self.tree
            .append(leaf)
            .map_err(|_| "Ironwood tree is full")?;
        for witness in self.witnesses.values_mut() {
            witness
                .append(leaf)
                .map_err(|_| "Ironwood witness is full")?;
        }
        Ok(position)
    }

    pub fn track_latest(&mut self) -> Result<u64, String> {
        let position = self
            .tree
            .size()
            .checked_sub(1)
            .ok_or("Ironwood tree is empty")? as u64;
        let witness =
            IncrementalWitness::from_tree(self.tree.clone()).ok_or("Ironwood tree is empty")?;
        self.witnesses.insert(position, witness);
        Ok(position)
    }

    pub fn path(&self, position: u64) -> Result<MerklePath, String> {
        self.witnesses
            .get(&position)
            .and_then(IncrementalWitness::path)
            .map(Into::into)
            .ok_or_else(|| format!("no witness for Ironwood position {position}"))
    }

    pub fn root(&self) -> [u8; 32] {
        self.tree.root().to_bytes()
    }
}

#[cfg(test)]
mod checkpoint_tests {
    use super::*;
    use incrementalmerkletree::frontier::CommitmentTree as FrontierTree;
    use zcash_primitives::merkle_tree::write_commitment_tree;

    fn cmx(n: u8) -> [u8; 32] {
        let mut bytes = [0; 32];
        bytes[0] = n;
        bytes
    }

    #[test]
    fn tracks_a_note_added_after_a_nonempty_checkpoint() {
        let mut checkpoint = FrontierTree::<MerkleHashOrchard, 32>::empty();
        let old = ExtractedNoteCommitment::from_bytes(&cmx(1))
            .into_option()
            .unwrap();
        checkpoint
            .append(MerkleHashOrchard::from_cmx(&old))
            .unwrap();
        let mut encoded = Vec::new();
        write_commitment_tree(&checkpoint, &mut encoded).unwrap();

        let mut tree = BirthWitnesses::from_state(&encoded).unwrap();
        assert_eq!(tree.append(cmx(2)).unwrap(), 1);
        tree.track_latest().unwrap();
        tree.append(cmx(3)).unwrap();

        let path = tree.path(1).unwrap();
        let note = ExtractedNoteCommitment::from_bytes(&cmx(2))
            .into_option()
            .unwrap();
        assert_eq!(path.root(note).to_bytes(), tree.root());
    }
}

/// Orchard and Ironwood share a tree depth of 32.
const DEPTH: usize = 32;

/// The whole commitment tree, as levels of nodes.
///
/// `levels[0]` is the leaves; `levels[l+1]` is `levels[l]` paired and combined. Missing
/// right-hand children are the empty root for that level, which is how an incomplete
/// tree is padded.
pub struct CommitmentTree {
    levels: Vec<Vec<MerkleHashOrchard>>,
}

impl CommitmentTree {
    /// Build from every commitment in the order the chain appended them.
    pub fn build(cmxs: &[[u8; 32]]) -> Result<Self, String> {
        let leaves: Vec<MerkleHashOrchard> = cmxs
            .iter()
            .map(|b| {
                let cmx = ExtractedNoteCommitment::from_bytes(b)
                    .into_option()
                    .ok_or_else(|| format!("not a valid cmx: {}", hex::encode(b)))?;
                Ok(MerkleHashOrchard::from_cmx(&cmx))
            })
            .collect::<Result<_, String>>()?;

        let mut levels = vec![leaves];
        for l in 0..DEPTH {
            let below = &levels[l];
            let level = Level::from(l as u8);
            let empty = MerkleHashOrchard::empty_root(level);

            let mut up = Vec::with_capacity(below.len().div_ceil(2));
            for pair in below.chunks(2) {
                let left = pair[0];
                let right = *pair.get(1).unwrap_or(&empty);
                up.push(MerkleHashOrchard::combine(level, &left, &right));
            }
            levels.push(up);
        }

        Ok(CommitmentTree { levels })
    }

    /// The tree root, which must equal the node's anchor.
    pub fn root(&self) -> MerkleHashOrchard {
        self.levels[DEPTH]
            .first()
            .copied()
            .unwrap_or_else(|| MerkleHashOrchard::empty_root(Level::from(DEPTH as u8)))
    }

    /// The authentication path for the leaf at `position`.
    pub fn path(&self, position: u64) -> Result<MerklePath, String> {
        if position >= self.levels[0].len() as u64 {
            return Err(format!(
                "position {position} is beyond the {} commitments in the tree",
                self.levels[0].len()
            ));
        }

        let mut auth = [MerkleHashOrchard::empty_leaf(); DEPTH];
        for (l, slot) in auth.iter_mut().enumerate() {
            let level = Level::from(l as u8);
            let sibling = ((position >> l) ^ 1) as usize;
            *slot = self.levels[l]
                .get(sibling)
                .copied()
                .unwrap_or_else(|| MerkleHashOrchard::empty_root(level));
        }

        Ok(MerklePath::from_parts(position as u32, auth))
    }
}

/// Build a path and prove it reaches `expected_anchor`.
///
/// This is the check that makes the rebuilt tree trustworthy: if our ordering or padding
/// were wrong, the root would differ from what the node computed.
pub fn witness_for(
    cmxs: &[[u8; 32]],
    position: u64,
    expected_anchor: &[u8; 32],
) -> Result<MerklePath, String> {
    let tree = CommitmentTree::build(cmxs)?;

    let got = tree.root().to_bytes();
    if &got != expected_anchor {
        return Err(format!(
            "rebuilt tree root {} does not match the node's anchor {}",
            hex::encode(got),
            hex::encode(expected_anchor)
        ));
    }

    let path = tree.path(position)?;

    // And the path itself must reach the same root from this leaf.
    let cmx = ExtractedNoteCommitment::from_bytes(&cmxs[position as usize])
        .into_option()
        .ok_or("the note's own cmx is invalid")?;
    let via_path = path.root(cmx).to_bytes();
    if &via_path != expected_anchor {
        return Err(format!(
            "auth path for position {position} reaches {} not {}",
            hex::encode(via_path),
            hex::encode(expected_anchor)
        ));
    }

    Ok(path)
}
