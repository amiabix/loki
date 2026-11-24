use reddsa_frost::frost::redpallas as frost;
use std::collections::BTreeMap;

type Commitments = BTreeMap<frost::Identifier, frost::round1::SigningCommitments>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SeedRecord {
    pub version: u32,
    pub proposal_id: [u8; 32],
    pub pair: String,
    pub spend_index: usize,
    pub nullifier: [u8; 32],
    pub commitments: Vec<(String, String)>,
    pub seed: [u8; 32],
}

fn serialized_commitments(commitments: &Commitments) -> Result<Vec<(String, String)>, String> {
    commitments
        .iter()
        .map(|(id, commitment)| {
            Ok((
                hex::encode(id.serialize()),
                hex::encode(
                    commitment.serialize().map_err(|e| {
                        format!("cannot serialize randomizer seed commitments: {e}")
                    })?,
                ),
            ))
        })
        .collect()
}

impl SeedRecord {
    pub fn new(
        proposal_id: [u8; 32],
        pair: impl Into<String>,
        spend_index: usize,
        nullifier: [u8; 32],
        commitments: &Commitments,
        seed: &[u8],
    ) -> Result<Self, String> {
        Ok(Self {
            version: 1,
            proposal_id,
            pair: pair.into(),
            spend_index,
            nullifier,
            commitments: serialized_commitments(commitments)?,
            seed: seed
                .try_into()
                .map_err(|_| "randomizer seed must be exactly 32 bytes")?,
        })
    }

    pub fn encode(&self) -> Result<String, String> {
        serde_json::to_string(&serde_json::json!({
            "version": self.version,
            "proposal_id": hex::encode(self.proposal_id),
            "pair": self.pair,
            "spend_index": self.spend_index,
            "nullifier": hex::encode(self.nullifier),
            "commitments": self.commitments,
            "seed": hex::encode(self.seed),
        }))
        .map_err(|e| format!("cannot encode randomizer seed record: {e}"))
    }

    pub fn decode(text: &str) -> Result<Self, String> {
        const INVALID: &str = "invalid randomizer seed record JSON";
        let value: serde_json::Value = serde_json::from_str(text).map_err(|_| INVALID)?;
        let object = value.as_object().ok_or(INVALID)?;
        let version = object
            .get("version")
            .and_then(|v| v.as_u64())
            .ok_or(INVALID)?;
        if version != 1 {
            return Err("unsupported randomizer seed record version".into());
        }
        let field = |name: &str| -> Result<&str, String> {
            object
                .get(name)
                .and_then(|v| v.as_str())
                .ok_or_else(|| INVALID.into())
        };
        let bytes32 = |name: &str, label: &str| -> Result<[u8; 32], String> {
            hex::decode(field(name)?)
                .map_err(|_| format!("invalid randomizer seed {label}hex"))?
                .try_into()
                .map_err(|_| format!("randomizer seed {label}must be exactly 32 bytes"))
        };
        let proposal_id = bytes32("proposal_id", "proposal ID ")?;
        let nullifier = bytes32("nullifier", "nullifier ")?;
        let seed = bytes32("seed", "")?;
        let pair = field("pair")?.to_owned();
        let spend_index = object
            .get("spend_index")
            .and_then(|v| v.as_u64())
            .and_then(|v| usize::try_from(v).ok())
            .ok_or(INVALID)?;
        let commitments: Vec<(String, String)> =
            serde_json::from_value(object.get("commitments").ok_or(INVALID)?.clone())
                .map_err(|_| INVALID)?;
        for (id, commitment) in &commitments {
            let id =
                hex::decode(id).map_err(|_| "invalid randomizer seed commitment identifier hex")?;
            frost::Identifier::deserialize(&id)
                .map_err(|_| "invalid randomizer seed commitment identifier")?;
            let commitment =
                hex::decode(commitment).map_err(|_| "invalid randomizer seed commitment hex")?;
            frost::round1::SigningCommitments::deserialize(&commitment)
                .map_err(|_| "invalid randomizer seed commitment")?;
        }
        Ok(Self {
            version: 1,
            proposal_id,
            pair,
            spend_index,
            nullifier,
            commitments,
            seed,
        })
    }

    pub fn validate(
        &self,
        proposal_id: &[u8; 32],
        pair: &str,
        spend_index: usize,
        nullifier: &[u8; 32],
        commitments: &Commitments,
    ) -> Result<[u8; 32], String> {
        if self.version != 1 {
            return Err("unsupported randomizer seed record version".into());
        }
        for (matches, label) in [
            (self.proposal_id == *proposal_id, "proposal"),
            (self.pair == pair, "pair"),
            (self.spend_index == spend_index, "spend index"),
            (self.nullifier == *nullifier, "nullifier"),
            (
                self.commitments == serialized_commitments(commitments)?,
                "commitments",
            ),
        ] {
            if !matches {
                return Err(format!("randomizer seed {label} mismatch"));
            }
        }
        Ok(self.seed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use frost_rerandomized::RandomizedParams;

    fn fixture() -> (frost::keys::PublicKeyPackage, Commitments) {
        let (shares, public) = frost::keys::generate_with_dealer(
            3,
            2,
            frost::keys::IdentifierList::Default,
            rand_core::OsRng,
        )
        .unwrap();
        let commitments = shares
            .into_iter()
            .take(2)
            .map(|(id, share)| {
                let key = frost::keys::KeyPackage::try_from(share).unwrap();
                let (_, commitment) =
                    frost::round1::commit(key.signing_share(), &mut rand_core::OsRng);
                (id, commitment)
            })
            .collect();
        (public, commitments)
    }

    #[test]
    fn randomizer_library_seed_reconstructs_alpha_and_key_and_is_fresh() {
        let (public, commitments) = fixture();
        let (params, seed) = RandomizedParams::new_from_commitments(
            public.verifying_key(),
            &commitments,
            rand_core::OsRng,
        )
        .unwrap();
        let restored = RandomizedParams::regenerate_from_seed_and_commitments(
            public.verifying_key(),
            &seed,
            &commitments,
        )
        .unwrap();
        assert_eq!(seed.len(), 32);
        assert_eq!(
            params.randomizer().serialize(),
            restored.randomizer().serialize()
        );
        assert_eq!(
            params.randomized_verifying_key().serialize().unwrap(),
            restored.randomized_verifying_key().serialize().unwrap()
        );
        let (_, fresh_seed) = RandomizedParams::new_from_commitments(
            public.verifying_key(),
            &commitments,
            rand_core::OsRng,
        )
        .unwrap();
        assert_ne!(seed, fresh_seed);
        let (_, changed_commitments) = fixture();
        let changed = RandomizedParams::regenerate_from_seed_and_commitments(
            public.verifying_key(),
            &seed,
            &changed_commitments,
        )
        .unwrap();
        assert_ne!(
            params.randomizer().serialize(),
            changed.randomizer().serialize()
        );
    }

    #[test]
    fn randomizer_record_round_trip_and_exact_association() {
        let (_, commitments) = fixture();
        let record = SeedRecord::new([1; 32], "AB", 1, [2; 32], &commitments, &[3; 32]).unwrap();
        let decoded = SeedRecord::decode(&record.encode().unwrap()).unwrap();
        assert_eq!(decoded, record);
        assert_eq!(
            decoded
                .validate(&[1; 32], "AB", 1, &[2; 32], &commitments)
                .unwrap(),
            [3; 32]
        );
        for (proposal, pair, index, nullifier, expected) in [
            ([9; 32], "AB", 1, [2; 32], "proposal"),
            ([1; 32], "AC", 1, [2; 32], "pair"),
            ([1; 32], "AB", 0, [2; 32], "spend index"),
            ([1; 32], "AB", 1, [9; 32], "nullifier"),
        ] {
            assert_eq!(
                decoded
                    .validate(&proposal, pair, index, &nullifier, &commitments)
                    .unwrap_err(),
                format!("randomizer seed {expected} mismatch")
            );
        }
        let (_, changed) = fixture();
        assert_eq!(
            decoded
                .validate(&[1; 32], "AB", 1, &[2; 32], &changed)
                .unwrap_err(),
            "randomizer seed commitments mismatch"
        );
        let mut reversed = decoded.clone();
        reversed.commitments.reverse();
        assert_eq!(
            reversed
                .validate(&[1; 32], "AB", 1, &[2; 32], &commitments)
                .unwrap_err(),
            "randomizer seed commitments mismatch"
        );
    }

    #[test]
    fn randomizer_record_refuses_invalid_encoding_length_and_version() {
        let (_, commitments) = fixture();
        assert_eq!(
            SeedRecord::new([1; 32], "AB", 0, [2; 32], &commitments, &[3; 31]).unwrap_err(),
            "randomizer seed must be exactly 32 bytes"
        );
        let record = SeedRecord::new([1; 32], "AB", 0, [2; 32], &commitments, &[3; 32]).unwrap();
        let encoded = record.encode().unwrap();
        for (field, replacement, expected) in [
            (
                "seed",
                serde_json::json!("zz"),
                "invalid randomizer seed hex",
            ),
            (
                "seed",
                serde_json::json!(hex::encode([3; 31])),
                "randomizer seed must be exactly 32 bytes",
            ),
            (
                "seed",
                serde_json::json!(hex::encode([3; 33])),
                "randomizer seed must be exactly 32 bytes",
            ),
            (
                "version",
                serde_json::json!(2),
                "unsupported randomizer seed record version",
            ),
            (
                "proposal_id",
                serde_json::json!("zz"),
                "invalid randomizer seed proposal ID hex",
            ),
            (
                "nullifier",
                serde_json::json!("00"),
                "randomizer seed nullifier must be exactly 32 bytes",
            ),
        ] {
            let mut value: serde_json::Value = serde_json::from_str(&encoded).unwrap();
            value[field] = replacement;
            assert_eq!(
                SeedRecord::decode(&value.to_string()).unwrap_err(),
                expected
            );
        }
        assert_eq!(
            SeedRecord::decode("030303").unwrap_err(),
            "invalid randomizer seed record JSON"
        );
        let mut value: serde_json::Value = serde_json::from_str(&encoded).unwrap();
        value.as_object_mut().unwrap().remove("seed");
        assert_eq!(
            SeedRecord::decode(&value.to_string()).unwrap_err(),
            "invalid randomizer seed record JSON"
        );
    }
}
