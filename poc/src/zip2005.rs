//! FROST viewing-key derivation from ZIP 2005 (2026.8.0).
//!
//! This path is limited to regtest until an independent implementation checks its
//! vectors and the key and backup flow is reviewed. The ZIP is still Proposed.

use blake2b_simd::Params;
use ff_zp::{FromUniformBytes, PrimeField};
use orchard::keys::FullViewingKey;
use pasta_curves::pallas;
use zeroize::Zeroize;

const EXPAND_PERSONALIZATION: &[u8; 16] = b"Zcash_ExpandSeed";
const QK_CONTEXT: &str = "Zcash ZIP 2005 qk-derivation v1";
const NK_DOMAIN: u8 = 0x07;
const QSK_DOMAIN: u8 = 0x0c;
const RIVK_EXT_DOMAIN: u8 = 0x0d;

/// The exact ZIP 2005 derivation this vault state commits to.
pub const VERSION: &str = "zip2005-use-qsk-2026.8.0";

#[derive(Debug, PartialEq, Eq)]
pub enum KeyDerivationError {
    InvalidFullViewingKey,
}

fn expand(key: &[u8; 32], domain: u8, data: &[u8]) -> [u8; 64] {
    let mut state = Params::new()
        .hash_length(64)
        .personal(EXPAND_PERSONALIZATION)
        .to_state();
    state.update(key);
    state.update(&[domain]);
    state.update(data);
    *state.finalize().as_array()
}

/// Derive an Orchard-protocol FVK from a FROST DKG group key and the group's
/// privately agreed `sk`, using ZIP 2005's `use_qsk = true` branch.
pub fn frost_viewing_key(
    group_ak: &[u8; 32],
    group_sk: &[u8; 32],
) -> Result<FullViewingKey, KeyDerivationError> {
    let mut expanded_nk = expand(group_sk, NK_DOMAIN, &[]);
    let nk = pallas::Base::from_uniform_bytes(&expanded_nk).to_repr();
    expanded_nk.zeroize();

    let mut expanded_qsk = expand(group_sk, QSK_DOMAIN, &[]);
    let mut qsk: [u8; 32] = expanded_qsk[..32].try_into().expect("32-byte prefix");
    expanded_qsk.zeroize();
    let mut qk = blake3::derive_key(QK_CONTEXT, &qsk);
    qsk.zeroize();

    let mut data = [0u8; 64];
    data[..32].copy_from_slice(group_ak);
    data[32..].copy_from_slice(&nk);
    let mut expanded_rivk = expand(&qk, RIVK_EXT_DOMAIN, &data);
    qk.zeroize();
    let rivk = pallas::Scalar::from_uniform_bytes(&expanded_rivk).to_repr();
    expanded_rivk.zeroize();

    let mut raw = [0u8; 96];
    raw[..32].copy_from_slice(group_ak);
    raw[32..64].copy_from_slice(&nk);
    raw[64..].copy_from_slice(&rivk);
    FullViewingKey::from_bytes(&raw).ok_or(KeyDerivationError::InvalidFullViewingKey)
}
