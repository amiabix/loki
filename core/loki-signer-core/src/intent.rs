use blake2b_simd::Params;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChangePolicy {
    VaultInternal,
}

impl ChangePolicy {
    fn as_u64(self) -> u64 {
        match self {
            ChangePolicy::VaultInternal => 0,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Intent {
    pub proposer: Vec<u8>,
    pub created_height: u32,
    pub input_nullifiers: Vec<[u8; 32]>,
    pub recipient: Vec<u8>,
    pub amount_zat: u64,
    pub memo: Vec<u8>,
    pub change_policy: ChangePolicy,
    pub fee_zat: u64,
    pub change_zat: u64,
    pub expiry_height: u32,
}

impl Intent {
    pub fn canonical_cbor(&self) -> Vec<u8> {
        use ciborium::value::Value;

        let v = Value::Array(vec![
            Value::Bytes(self.proposer.clone()),
            Value::Integer(self.created_height.into()),
            Value::Array(
                self.input_nullifiers
                    .iter()
                    .map(|n| Value::Bytes(n.to_vec()))
                    .collect(),
            ),
            Value::Bytes(self.recipient.clone()),
            Value::Integer(self.amount_zat.into()),
            Value::Bytes(self.memo.clone()),
            Value::Integer(self.change_policy.as_u64().into()),
            Value::Integer(self.fee_zat.into()),
            Value::Integer(self.change_zat.into()),
            Value::Integer(self.expiry_height.into()),
        ]);

        let mut out = Vec::new();
        ciborium::into_writer(&v, &mut out).expect("writing to a Vec cannot fail");
        out
    }

    pub fn proposal_id(&self) -> [u8; 32] {
        Params::new()
            .hash_length(32)
            .personal(b"Loki_intent_v1")
            .hash(&self.canonical_cbor())
            .as_bytes()
            .try_into()
            .expect("hash_length(32)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn intent() -> Intent {
        Intent {
            proposer: vec![1u8; 32],
            created_height: 100,
            input_nullifiers: vec![[7u8; 32]],
            recipient: vec![9u8; 43],
            amount_zat: 40_000_000,
            memo: b"loki g1-tx".to_vec(),
            change_policy: ChangePolicy::VaultInternal,
            fee_zat: 15_000,
            change_zat: 59_985_000,
            expiry_height: 1_152,
        }
    }

    #[test]
    fn c3_proposal_id_is_deterministic() {
        assert_eq!(intent().proposal_id(), intent().proposal_id());
    }

    #[test]
    fn c3_proposal_id_changes_with_every_checked_field() {
        let base = intent().proposal_id();

        let m = |f: &dyn Fn(&mut Intent)| {
            let mut i = intent();
            f(&mut i);
            assert_ne!(i.proposal_id(), base);
        };

        m(&|i| i.amount_zat += 1);
        m(&|i| i.fee_zat += 1);
        m(&|i| i.change_zat += 1);
        m(&|i| i.expiry_height += 1);
        m(&|i| i.created_height += 1);
        m(&|i| i.memo.push(b'!'));
        m(&|i| i.recipient[0] ^= 1);
        m(&|i| i.input_nullifiers[0][0] ^= 1);
        m(&|i| i.proposer[0] ^= 1);
    }
}
