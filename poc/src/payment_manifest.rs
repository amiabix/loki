//! The exact payment intent shared by the payment signer and relay inbox.

use crate::{
    intent::{ChangePolicy, Intent},
    network::VaultNetwork,
    signing_session::{AttemptId, SessionContext},
};
use reddsa_frost::frost::redpallas as frost;
use serde_json::{json, Value};

pub const MAX_MANIFEST: usize = 8192;
pub const PROPOSAL_DOMAIN: &[u8] = b"Loki_Proposal_v1\0";

fn hex<const N: usize>(value: &Value, field: &str) -> Result<[u8; N], String> {
    hex::decode(
        value[field]
            .as_str()
            .ok_or_else(|| format!("missing {field}"))?,
    )
    .map_err(|e| format!("{field}: {e}"))?
    .try_into()
    .map_err(|_| format!("{field} must be {N} bytes"))
}

fn bytes(value: &Value, field: &str) -> Result<Vec<u8>, String> {
    hex::decode(
        value[field]
            .as_str()
            .ok_or_else(|| format!("missing {field}"))?,
    )
    .map_err(|e| format!("{field}: {e}"))
}

fn number(value: &Value, field: &str) -> Result<u64, String> {
    value[field]
        .as_u64()
        .ok_or_else(|| format!("missing or invalid {field}"))
}

pub fn manifest_pair(value: &Value) -> Result<[u16; 2], String> {
    let Some(pair) = value.get("pair") else {
        return Ok([1, 2]); // Existing regtest manifests predate pair selection.
    };
    let ids = pair
        .as_array()
        .ok_or("payment pair must contain two member IDs")?;
    if ids.len() != 2 {
        return Err("payment pair must contain two member IDs".into());
    }
    let first = ids[0].as_u64().ok_or("invalid payment pair")?;
    let second = ids[1].as_u64().ok_or("invalid payment pair")?;
    let pair = [
        u16::try_from(first).map_err(|_| "invalid payment pair")?,
        u16::try_from(second).map_err(|_| "invalid payment pair")?,
    ];
    if pair[0] < 1 || pair[1] > 4 || pair[0] >= pair[1] {
        return Err("payment pair must be a supported sorted pair".into());
    }
    Ok(pair)
}

pub fn proposer_id(bytes: &[u8]) -> Result<u16, String> {
    (1u16..=4)
        .find(|id| frost::Identifier::try_from(*id).is_ok_and(|member| member.serialize() == bytes))
        .ok_or_else(|| "payment proposer is not a vault member".into())
}

pub fn parse(raw: &[u8]) -> Result<(SessionContext, Intent), String> {
    parse_for_network(raw, VaultNetwork::Regtest)
}

pub fn parse_for_network(
    raw: &[u8],
    network: VaultNetwork,
) -> Result<(SessionContext, Intent), String> {
    if raw.len() > MAX_MANIFEST {
        return Err("payment manifest exceeds 8192 bytes".into());
    }
    let value: Value = serde_json::from_slice(raw).map_err(|e| format!("manifest: {e}"))?;
    if value["version"] != 1 || value["network"] != network.label() {
        return Err("unsupported payment manifest".into());
    }
    let notes = value["input_nullifiers"]
        .as_array()
        .ok_or("missing input nullifiers")?
        .iter()
        .map(|entry| hex::<32>(&json!({"nf": entry}), "nf"))
        .collect::<Result<Vec<_>, _>>()?;
    if notes.is_empty() || notes.len() > 8 {
        return Err("payment needs 1 to 8 input notes".into());
    }
    let intent = Intent {
        proposer: bytes(&value, "proposer")?,
        created_height: number(&value, "created_height")?
            .try_into()
            .map_err(|_| "created height overflow")?,
        input_nullifiers: notes,
        recipient: bytes(&value, "recipient")?,
        amount_zat: number(&value, "amount_zat")?,
        memo: bytes(&value, "memo")?,
        change_policy: ChangePolicy::VaultInternal,
        fee_zat: number(&value, "fee_zat")?,
        change_zat: number(&value, "change_zat")?,
        expiry_height: number(&value, "expiry_height")?
            .try_into()
            .map_err(|_| "expiry height overflow")?,
    };
    if value["change_policy"] != "vault_internal"
        || intent.recipient.len() != 43
        || intent.amount_zat == 0
        || intent.memo.is_empty()
        || intent.memo.len() > 512
        || intent.expiry_height <= intent.created_height
    {
        return Err("unsupported payment intent".into());
    }
    let context = SessionContext {
        vault: hex(&value, "vault")?,
        payment: hex(&value, "payment")?,
        attempt: AttemptId(hex(&value, "attempt")?),
        pair: manifest_pair(&value)?,
    };
    context.validate()?;
    if context.payment != intent.proposal_id() {
        return Err("manifest payment ID differs from intent".into());
    }
    proposer_id(&intent.proposer)?;
    Ok((context, intent))
}

pub fn validate_roster(
    vault: [u8; 32],
    member_ids: impl IntoIterator<Item = u16>,
    context: &SessionContext,
    intent: &Intent,
) -> Result<(), String> {
    let ids: Vec<_> = member_ids.into_iter().collect();
    if context.vault != vault {
        return Err("manifest names another vault".into());
    }
    if context.pair.iter().any(|id| !ids.contains(id)) {
        return Err("payment pair includes a member outside this vault".into());
    }
    if !ids.contains(&proposer_id(&intent.proposer)?) {
        return Err("payment proposer is not a vault member".into());
    }
    Ok(())
}

pub fn encode_proposal(raw: &[u8]) -> Result<Vec<u8>, String> {
    require_explicit_pair(raw)?;
    parse(raw)?;
    let mut out = Vec::with_capacity(PROPOSAL_DOMAIN.len() + raw.len());
    out.extend_from_slice(PROPOSAL_DOMAIN);
    out.extend_from_slice(raw);
    Ok(out)
}

pub fn decode_proposal(raw: &[u8]) -> Result<Option<&[u8]>, String> {
    let Some(manifest) = raw.strip_prefix(PROPOSAL_DOMAIN) else {
        return Ok(None);
    };
    require_explicit_pair(manifest)?;
    parse(manifest)?;
    Ok(Some(manifest))
}

fn require_explicit_pair(raw: &[u8]) -> Result<(), String> {
    if raw.len() > MAX_MANIFEST {
        return Err("payment manifest exceeds 8192 bytes".into());
    }
    let value: Value = serde_json::from_slice(raw).map_err(|e| format!("manifest: {e}"))?;
    if value.get("pair").is_none() {
        return Err("relay proposal requires an explicit signing pair".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> Vec<u8> {
        let proposer = frost::Identifier::try_from(1u16).unwrap().serialize();
        let intent = Intent {
            proposer: proposer.clone(),
            created_height: 20,
            input_nullifiers: vec![[3; 32]],
            recipient: vec![4; 43],
            amount_zat: 100_000,
            memo: b"memo".to_vec(),
            change_policy: ChangePolicy::VaultInternal,
            fee_zat: 10_000,
            change_zat: 200_000,
            expiry_height: 1152,
        };
        serde_json::to_vec(&json!({
            "version": 1, "network": "regtest", "vault": hex::encode([9; 32]),
            "payment": hex::encode(intent.proposal_id()), "attempt": hex::encode([8; 32]),
            "pair": [1, 3], "proposer": hex::encode(proposer), "created_height": 20,
            "input_nullifiers": [hex::encode([3; 32])], "recipient": hex::encode([4; 43]),
            "amount_zat": 100_000, "memo": hex::encode(b"memo"),
            "change_policy": "vault_internal", "fee_zat": 10_000,
            "change_zat": 200_000, "expiry_height": 1152,
        }))
        .unwrap()
    }

    #[test]
    fn proposal_tag_and_intent_are_required() {
        let raw = fixture();
        let envelope = encode_proposal(&raw).unwrap();
        assert_eq!(decode_proposal(&envelope).unwrap(), Some(raw.as_slice()));
        assert_eq!(decode_proposal(&raw).unwrap(), None);
        let mut wrong = envelope.clone();
        wrong[0] ^= 1;
        assert_eq!(decode_proposal(&wrong).unwrap(), None);
        let mut changed: Value = serde_json::from_slice(&raw).unwrap();
        changed["amount_zat"] = json!(100_001);
        assert!(encode_proposal(&serde_json::to_vec(&changed).unwrap()).is_err());
        assert!(decode_proposal(
            &[PROPOSAL_DOMAIN, &serde_json::to_vec(&changed).unwrap()].concat()
        )
        .is_err());
        let mut legacy: Value = serde_json::from_slice(&raw).unwrap();
        legacy.as_object_mut().unwrap().remove("pair");
        let legacy = serde_json::to_vec(&legacy).unwrap();
        assert!(parse(&legacy).is_ok());
        assert!(encode_proposal(&legacy).is_err());
        assert!(decode_proposal(&[PROPOSAL_DOMAIN, &legacy].concat()).is_err());
    }

    #[test]
    fn proposal_must_match_certified_vault_and_roster() {
        let (context, intent) = parse(&fixture()).unwrap();
        assert!(validate_roster([9; 32], [1, 2, 3], &context, &intent).is_ok());
        assert!(validate_roster([1; 32], [1, 2, 3], &context, &intent).is_err());
        assert!(validate_roster([9; 32], [1, 2], &context, &intent).is_err());
        assert_eq!(proposer_id(&intent.proposer).unwrap(), 1);
    }

    #[test]
    fn payment_network_must_match_the_member_vault() {
        let raw = fixture();
        assert!(parse_for_network(&raw, VaultNetwork::Testnet).is_err());
        let mut value: Value = serde_json::from_slice(&raw).unwrap();
        value["network"] = json!("testnet");
        let testnet = serde_json::to_vec(&value).unwrap();
        assert!(parse_for_network(&testnet, VaultNetwork::Testnet).is_ok());
        assert!(parse(&testnet).is_err());
    }
}
