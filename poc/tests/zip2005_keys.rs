use orchard::keys::{FullViewingKey, SpendingKey};

#[test]
fn frost_viewing_key_keeps_the_zip2005_nullifier_key_but_changes_rivk() {
    let secret = [42u8; 32];
    let sk = SpendingKey::from_bytes(secret).unwrap();
    let ordinary = FullViewingKey::from(&sk);
    let ak: [u8; 32] = ordinary.to_bytes()[..32].try_into().unwrap();

    let frost = loki_poc::zip2005::frost_viewing_key(&ak, &secret).unwrap();
    // Independently computed with Python hashlib/blake3 and integer reduction
    // using the Pasta field moduli, from ZIP 2005's specified domains.
    assert_eq!(
        hex::encode(frost.to_bytes()),
        concat!(
            "c605c0eb00d6bb40b6d058a7308f85883a9b589feb7c4d07265951d415fb1e34",
            "18c5cd0dcf61488eec0ce2981deaa3343f36606137da78739171664d4dde5e37",
            "cff6fe36aff82c5c4b70b1d325d3c78992551f611495a7b2fc7ba30cb42a3006"
        )
    );
    assert_eq!(&frost.to_bytes()[..32], &ak);
    assert_eq!(&frost.to_bytes()[32..64], &ordinary.to_bytes()[32..64]);
    assert_ne!(&frost.to_bytes()[64..96], &ordinary.to_bytes()[64..96]);
    assert_ne!(
        frost.address_at(0u64, orchard::keys::Scope::External),
        ordinary.address_at(0u64, orchard::keys::Scope::External)
    );
}
