use hpke::{
    aead::ChaCha20Poly1305, kdf::HkdfSha256, kem::X25519HkdfSha256, setup_receiver,
    setup_sender_with_rng, Deserializable, Kem, OpModeR, OpModeS, Serializable,
};
use rand_core::{Infallible, TryCryptoRng, TryRng};
use serde_json::Value;

type SelectedKem = X25519HkdfSha256;

struct VectorIkmRng {
    ikm: [u8; 32],
    fills: usize,
}

impl TryRng for VectorIkmRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        panic!("HPKE X25519 must consume IKM with one fill_bytes call")
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        panic!("HPKE X25519 must consume IKM with one fill_bytes call")
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        assert_eq!(self.fills, 0, "HPKE requested additional RNG input");
        assert_eq!(dst.len(), 32, "X25519 IKM input must be 32 bytes");
        dst.copy_from_slice(&self.ikm);
        self.fills += 1;
        Ok(())
    }
}

impl TryCryptoRng for VectorIkmRng {}

fn bytes(value: &Value, field: &str) -> Vec<u8> {
    hex::decode(value[field].as_str().expect("public vector hex field")).expect("valid vector hex")
}

fn selected_row(rows: &[Value]) -> Option<&Value> {
    let mut selected = rows.iter().filter(|row| {
        row["mode"] == 0 && row["kem_id"] == 32 && row["kdf_id"] == 1 && row["aead_id"] == 3
    });
    let row = selected.next()?;
    if selected.next().is_some() {
        return None;
    }
    Some(row)
}

#[test]
fn selected_suite_vectors() {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/hpke-base-x25519-sha256-chacha.json"))
            .expect("public HPKE fixture JSON");
    let rows = fixture["vectors"].as_array().expect("vector rows");
    let row = selected_row(rows).expect("exactly one base/X25519/SHA256/ChaCha suite row required");
    assert!(
        selected_row(&[]).is_none(),
        "missing suite must be rejected"
    );
    assert!(
        selected_row(&[row.clone(), row.clone()]).is_none(),
        "ambiguous suite must be rejected"
    );
    for (field, wrong) in [("mode", 1), ("kem_id", 16), ("kdf_id", 2), ("aead_id", 1)] {
        let mut other_suite = row.clone();
        other_suite[field] = wrong.into();
        assert!(
            selected_row(&[other_suite]).is_none(),
            "wrong {field} must be rejected"
        );
    }
    let (sk_r, pk_r) = SelectedKem::derive_keypair(&bytes(row, "ikmR"));
    assert_eq!(
        sk_r.to_bytes().as_slice(),
        bytes(row, "skRm"),
        "derived recipient secret"
    );
    assert_eq!(
        pk_r.to_bytes().as_slice(),
        bytes(row, "pkRm"),
        "derived recipient public key"
    );
    let (sk_e, pk_e) = SelectedKem::derive_keypair(&bytes(row, "ikmE"));
    assert_eq!(
        sk_e.to_bytes().as_slice(),
        bytes(row, "skEm"),
        "derived ephemeral secret"
    );
    assert_eq!(
        pk_e.to_bytes().as_slice(),
        bytes(row, "pkEm"),
        "derived ephemeral public key"
    );

    let mut rng = VectorIkmRng {
        ikm: bytes(row, "ikmE")
            .try_into()
            .expect("32-byte ephemeral IKM"),
        fills: 0,
    };
    let info = bytes(row, "info");
    let (enc, mut sender) = setup_sender_with_rng::<ChaCha20Poly1305, HkdfSha256, SelectedKem>(
        &OpModeS::Base,
        &pk_r,
        &info,
        &mut rng,
    )
    .expect("selected-suite sender setup");
    assert_eq!(rng.fills, 1, "exactly one 32-byte IKM fill");
    assert_eq!(
        enc.to_bytes().as_slice(),
        bytes(row, "enc"),
        "published encapsulated key"
    );

    let published_enc = <SelectedKem as Kem>::EncappedKey::from_bytes(&bytes(row, "enc"))
        .expect("published encapsulated key");
    let mut receiver = setup_receiver::<ChaCha20Poly1305, HkdfSha256, SelectedKem>(
        &OpModeR::Base,
        &sk_r,
        &published_enc,
        &info,
    )
    .expect("selected-suite receiver setup");
    let encryptions = row["encryptions"]
        .as_array()
        .expect("published encryptions");
    assert_eq!(
        encryptions.len(),
        257,
        "all published sequence cases retained"
    );
    for (sequence, encryption) in encryptions.iter().enumerate() {
        let pt = bytes(encryption, "pt");
        let aad = bytes(encryption, "aad");
        let ct = bytes(encryption, "ct");
        assert_eq!(
            sender.seal(&pt, &aad).expect("vector seal"),
            ct,
            "published ciphertext at sequence {sequence}"
        );
        assert_eq!(
            receiver.open(&ct, &aad).expect("published vector open"),
            pt,
            "published plaintext at sequence {sequence}"
        );
    }
}
