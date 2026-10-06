//! The G1-TX vault: a real 2-of-3 FROST group key, wrapped in a **test-only** viewing key.
//!
//! # This is not a Loki vault
//!
//! ZIP 2005 derives an Ironwood viewing key for a FROST group as
//!
//! ```text
//!     qsk --H^qk--> qk
//!     rivk_ext = H^rivk_ext_qk(ak, nk)        keyed by qk, selected by use_qsk
//! ```
//!
//! That derivation is implemented nowhere (see `DEPENDENCIES.md` finding B1), so this
//! module takes the documented G1-TX deviation instead: `ak` is real, from the 2-of-3
//! DKG, and `nk`/`rivk` come from fixed test inputs that all three member processes
//! share. The result exercises the v6 sign-before-proof transaction path and says
//! nothing about key derivation.
//!
//! Every item here is named `test_only_*` so no call site can be mistaken for the real
//! thing. **The address this produces is not a production Loki vault address, and it
//! carries no quantum-recovery property.**

use orchard::keys::{FullViewingKey, Scope, SpendingKey};

/// The fixed test input that `nk` and `rivk` are taken from.
///
/// ASCII "LOKI-G1-TX-TEST-ONLY-NOT-ZIP2005" — chosen so it is obvious in a hex dump
/// that these bytes are a test fixture and not key material from any derivation.
pub const TEST_ONLY_SEED: [u8; 32] = *b"LOKI-G1-TX-TEST-ONLY-NOT-ZIP2005";

/// Why a candidate group key was refused.
///
/// The two `reddsa` versions in this graph can only exchange 32-byte encodings
/// (`DEPENDENCIES.md` finding F3), so every crossing is checked rather than assumed.
#[derive(Debug, PartialEq, Eq)]
pub enum VaultKeyError {
    /// All-zero encoding: the identity point is not a valid `ak`.
    Identity,
    /// Top bit set. Orchard requires `ak` to have a positive (even) y coordinate;
    /// `SpendValidatingKey::from_bytes` refuses anything else.
    OddY,
    /// Not a canonical encoding of a Pallas point, or the resulting viewing key is
    /// structurally invalid (for example a zero `ivk`).
    NotCanonical,
    /// The parsed key did not re-serialize to the bytes it was built from.
    RoundTripMismatch,
}

/// The fixed `nk || rivk` tail that every member process uses.
///
/// Returned as bytes rather than typed values because `CommitIvkRandomness` is private
/// in orchard; the only public surface is `FullViewingKey::{to_bytes, from_bytes}`.
fn test_only_tail() -> [u8; 64] {
    let carrier = FullViewingKey::from(
        &SpendingKey::from_bytes(TEST_ONLY_SEED).expect("the fixed test seed is valid"),
    );
    let mut tail = [0u8; 64];
    tail.copy_from_slice(&carrier.to_bytes()[32..96]);
    tail
}

/// Build the G1-TX viewing key from a DKG-derived group `ak`.
///
/// `group_ak` is the serialized FROST group verifying key, which crosses the crate
/// version boundary as raw bytes. It is checked for canonicality here, on this side of
/// that boundary, before anything is built from it.
///
/// **Test-only.** See the module docs.
pub fn test_only_fvk(group_ak: &[u8; 32]) -> Result<FullViewingKey, VaultKeyError> {
    if group_ak == &[0u8; 32] {
        return Err(VaultKeyError::Identity);
    }
    if group_ak[31] & 0x80 != 0 {
        return Err(VaultKeyError::OddY);
    }

    let mut bytes = [0u8; 96];
    bytes[0..32].copy_from_slice(group_ak);
    bytes[32..96].copy_from_slice(&test_only_tail());

    let fvk = FullViewingKey::from_bytes(&bytes).ok_or(VaultKeyError::NotCanonical)?;

    // Round-trip: the parsed key must re-serialize to exactly what it was built from.
    if fvk.to_bytes() != bytes {
        return Err(VaultKeyError::RoundTripMismatch);
    }

    Ok(fvk)
}

/// The vault's external receive address, at diversifier index 0.
///
/// **Test-only.** Not a production Loki vault address.
pub fn test_only_address(fvk: &FullViewingKey) -> orchard::Address {
    fvk.address_at(0u64, Scope::External)
}

/// Encode the vault's Orchard receiver as a Regtest unified address.
///
/// There is no Ironwood receiver typecode: `zcash_address` 0.14 knows only Orchard,
/// Sapling, P2PKH and P2SH. Ironwood reuses the Orchard receiver and the pool is chosen
/// by the sending bundle, so one address can receive either.
///
/// **Test-only.** Not a production Loki vault address.
pub fn regtest_unified_address(fvk: &FullViewingKey) -> String {
    use zcash_address::{
        unified::{Address as Ua, Encoding, Receiver, Revision, Uitem},
        ToAddress, ZcashAddress,
    };

    let raw = test_only_address(fvk).to_raw_address_bytes();
    let ua = Ua::try_from_items(Revision::R0, vec![Uitem::Data(Receiver::Orchard(raw))])
        .expect("one Orchard receiver is a valid unified address");

    ZcashAddress::from_unified(zcash_protocol::consensus::NetworkType::Regtest, ua)
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use reddsa_frost::frost::redpallas as frost;

    /// A real 2-of-3 DKG group key, as the three member processes would produce it.
    fn dkg_group_ak() -> [u8; 32] {
        let rng = rand_core::OsRng;
        let (_shares, pubkeys) = frost::keys::generate_with_dealer(
            3,
            2,
            frost::keys::IdentifierList::Default,
            rng,
        )
        .unwrap();
        pubkeys
            .verifying_key()
            .serialize()
            .unwrap()
            .try_into()
            .expect("a RedPallas verifying key is 32 bytes")
    }

    /// Checkpoint 2, evidence item 1: canonical parsing of the test-only FVK.
    #[test]
    fn c2_test_only_fvk_parses_and_round_trips() {
        let ak = dkg_group_ak();
        let fvk = test_only_fvk(&ak).expect("a DKG group key is a valid ak");

        assert_eq!(&fvk.to_bytes()[0..32], &ak, "ak survives the round trip");
        assert_eq!(
            &fvk.to_bytes()[32..96],
            &test_only_tail(),
            "the fixed test tail survives the round trip"
        );
    }

    /// Checkpoint 2, evidence item 1: two independently initialized member processes
    /// agree on the address. Here that is modelled as two independent derivations from
    /// the same DKG output and the same documented fixture.
    #[test]
    fn c2_members_agree_on_the_address() {
        let ak = dkg_group_ak();

        let alice = test_only_address(&test_only_fvk(&ak).unwrap());
        let carol = test_only_address(&test_only_fvk(&ak).unwrap());

        assert_eq!(alice.to_raw_address_bytes(), carol.to_raw_address_bytes());
    }

    /// Different groups must not collide on an address, or the fixture would be doing
    /// the work instead of the DKG.
    #[test]
    fn c2_a_different_group_gets_a_different_address() {
        let a = test_only_address(&test_only_fvk(&dkg_group_ak()).unwrap());
        let b = test_only_address(&test_only_fvk(&dkg_group_ak()).unwrap());
        assert_ne!(a.to_raw_address_bytes(), b.to_raw_address_bytes());
    }

    /// Noncanonical encodings are refused on this side of the version boundary.
    #[test]
    fn c2_noncanonical_group_keys_are_rejected() {
        assert_eq!(test_only_fvk(&[0u8; 32]), Err(VaultKeyError::Identity));

        let mut odd = dkg_group_ak();
        odd[31] |= 0x80;
        assert_eq!(test_only_fvk(&odd), Err(VaultKeyError::OddY));

        // 0xFF.. is not a canonical Pallas point encoding, and has its top bit set.
        assert_eq!(test_only_fvk(&[0xFFu8; 32]), Err(VaultKeyError::OddY));

        // Top bit clear but still not on the curve.
        let mut off_curve = [0xFFu8; 32];
        off_curve[31] = 0x7F;
        assert_eq!(test_only_fvk(&off_curve), Err(VaultKeyError::NotCanonical));
    }
}


/// Decode a unified address into the Orchard receiver this prototype can pay.
///
/// The counterpart to [`regtest_unified_address`]. Only the Orchard receiver is used:
/// the prototype refuses transparent and Sapling outputs everywhere else, so accepting an
/// address it could only pay through a forbidden pool would be a lie to the caller.
pub fn orchard_receiver_from_ua(
    s: &str,
    expect: zcash_protocol::consensus::NetworkType,
) -> Result<orchard::Address, String> {
    use zcash_address::unified::{Address as Ua, Container, Encoding, Receiver};

    let (net, _revision, ua) =
        Ua::decode(s.trim()).map_err(|e| format!("not a unified address: {e:?}"))?;
    if net != expect {
        return Err(format!("that address is for {net:?}, this network is {expect:?}"));
    }

    for item in ua.items() {
        if let Receiver::Orchard(raw) = item {
            return orchard::Address::from_raw_address_bytes(&raw)
                .into_option()
                .ok_or_else(|| "the Orchard receiver is not a valid address".to_string());
        }
    }
    Err("that address has no Orchard receiver; this prototype can only pay Orchard".into())
}

#[cfg(test)]
mod address_tests {
    use super::*;

    /// A real group verifying key. `ak` must be a canonical Pallas point with even y, so
    /// an arbitrary 32 bytes will not do: the first version of this test used `[2u8; 32]`
    /// and failed with `NotCanonical`.
    fn real_ak() -> [u8; 32] {
        use reddsa_frost::frost::redpallas as frost;
        let (_, public) = frost::keys::generate_with_dealer(
            3, 2, frost::keys::IdentifierList::Default, rand_core::OsRng,
        )
        .expect("keygen");
        public.verifying_key().serialize().expect("vk serializes")
            .as_slice().try_into().expect("32 bytes")
    }

    /// The decoder must be the exact inverse of the encoder, or the prototype would
    /// accept an address it cannot actually pay.
    #[test]
    fn a_vault_address_round_trips() {
        let fvk = test_only_fvk(&real_ak()).expect("a test fvk");
        let ua = regtest_unified_address(&fvk);
        let back = orchard_receiver_from_ua(&ua, zcash_protocol::consensus::NetworkType::Regtest)
            .expect("the address we just printed must decode");
        assert_eq!(back, test_only_address(&fvk), "round trip must give the same receiver");
    }

    #[test]
    fn a_mainnet_address_is_refused_on_regtest() {
        let fvk = test_only_fvk(&real_ak()).expect("a test fvk");
        let ua = regtest_unified_address(&fvk);
        let err = orchard_receiver_from_ua(&ua, zcash_protocol::consensus::NetworkType::Main)
            .expect_err("a regtest address must not be accepted as mainnet");
        assert!(err.contains("network"), "the error should name the mismatch, got: {err}");
    }

    #[test]
    fn rubbish_is_refused() {
        for bad in ["", "not an address", "uregtest1zzzz"] {
            assert!(orchard_receiver_from_ua(bad, zcash_protocol::consensus::NetworkType::Regtest).is_err());
        }
    }
}
