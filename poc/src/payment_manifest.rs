//! The exact payment intent shared by the payment signer and relay inbox.

use crate::{
    intent::{ChangePolicy, Intent},
    member_state::MAX_MEMBERS,
    network::VaultNetwork,
    signing_session::{AttemptId, SessionContext},
};
use reddsa_frost::frost::redpallas as frost;
use serde_json::{json, Value};

pub const MAX_MANIFEST: usize = 8192;
/// Notes one payment may spend: each is one Ironwood action and one FROST signature.
pub const MAX_INPUTS: usize = 64;
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
    if pair[0] < 1 || pair[1] > MAX_MEMBERS || pair[0] >= pair[1] {
        return Err("payment pair must be a supported sorted pair".into());
    }
    Ok(pair)
}

fn manifest_signers(value: &Value) -> Result<Vec<u16>, String> {
    match value["version"].as_u64() {
        Some(1) if value.get("signers").is_none() => Ok(manifest_pair(value)?.to_vec()),
        Some(2) if value.get("pair").is_none() => {
            // One signer per threshold share. Two signers use the version 1 pair, so a
            // signer list has 3 to 15 IDs (a vault has at most 16 members).
            let ids = value["signers"].as_array().ok_or("payment needs its signer IDs")?;
            if !(3..usize::from(MAX_MEMBERS)).contains(&ids.len()) {
                return Err("payment needs 3 to 15 signer IDs".into());
            }
            let ids: Vec<u16> = ids
                .iter()
                .map(|id| u16::try_from(id.as_u64().ok_or("invalid signer ID")?).map_err(|_| "invalid signer ID".to_string()))
                .collect::<Result<_, _>>()?;
            if ids.iter().any(|id| !(1..=MAX_MEMBERS).contains(id)) {
                return Err("invalid signer ID".into());
            }
            Ok(ids)
        }
        _ => Err("unsupported payment signer format".into()),
    }
}

pub fn proposer_id(bytes: &[u8]) -> Result<u16, String> {
    (1u16..=MAX_MEMBERS)
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
    if !matches!(value["version"].as_u64(), Some(1 | 2)) || value["network"] != network.label() {
        return Err("unsupported payment manifest".into());
    }
    let notes = value["input_nullifiers"]
        .as_array()
        .ok_or("missing input nullifiers")?
        .iter()
        .map(|entry| hex::<32>(&json!({"nf": entry}), "nf"))
        .collect::<Result<Vec<_>, _>>()?;
    if notes.is_empty() || notes.len() > MAX_INPUTS {
        return Err(format!("payment needs 1 to {MAX_INPUTS} input notes"));
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
        signers: manifest_signers(&value)?,
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
    threshold: u16,
    member_ids: impl IntoIterator<Item = u16>,
    context: &SessionContext,
    intent: &Intent,
) -> Result<(), String> {
    let ids: Vec<_> = member_ids.into_iter().collect();
    if context.vault != vault {
        return Err("manifest names another vault".into());
    }
    if context.signers.len() != usize::from(threshold)
        || context.signers.iter().any(|id| !ids.contains(id))
    {
        return Err("payment signer set differs from certified vault policy".into());
    }
    if !ids.contains(&proposer_id(&intent.proposer)?) {
        return Err("payment proposer is not a vault member".into());
    }
    Ok(())
}

pub fn encode_proposal(raw: &[u8]) -> Result<Vec<u8>, String> {
    encode_proposal_for_network(raw, VaultNetwork::Regtest)
}

pub fn encode_proposal_for_network(raw: &[u8], network: VaultNetwork) -> Result<Vec<u8>, String> {
    require_explicit_signers(raw)?;
    parse_for_network(raw, network)?;
    let mut out = Vec::with_capacity(PROPOSAL_DOMAIN.len() + raw.len());
    out.extend_from_slice(PROPOSAL_DOMAIN);
    out.extend_from_slice(raw);
    Ok(out)
}

pub fn decode_proposal(raw: &[u8]) -> Result<Option<&[u8]>, String> {
    decode_proposal_for_network(raw, VaultNetwork::Regtest)
}

pub fn decode_proposal_for_network(raw: &[u8], network: VaultNetwork) -> Result<Option<&[u8]>, String> {
    let Some(manifest) = raw.strip_prefix(PROPOSAL_DOMAIN) else {
        return Ok(None);
    };
    require_explicit_signers(manifest)?;
    parse_for_network(manifest, network)?;
    Ok(Some(manifest))
}

fn require_explicit_signers(raw: &[u8]) -> Result<(), String> {
    if raw.len() > MAX_MANIFEST {
        return Err("payment manifest exceeds 8192 bytes".into());
    }
    let value: Value = serde_json::from_slice(raw).map_err(|e| format!("manifest: {e}"))?;
    if (value["version"] == 1 && value.get("pair").is_none())
        || (value["version"] == 2 && value.get("signers").is_none())
    {
        return Err("relay proposal requires an explicit signer set".into());
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
    fn testnet_proposal_requires_the_certified_network() {
        let mut value: Value = serde_json::from_slice(&fixture()).unwrap();
        value["network"] = json!("testnet");
        let raw = serde_json::to_vec(&value).unwrap();
        assert!(encode_proposal(&raw).is_err());
        let envelope = encode_proposal_for_network(&raw, VaultNetwork::Testnet).unwrap();
        assert_eq!(decode_proposal_for_network(&envelope, VaultNetwork::Testnet).unwrap(), Some(raw.as_slice()));
        assert!(decode_proposal_for_network(&envelope, VaultNetwork::Regtest).is_err());
    }

    #[test]
    fn proposal_must_match_certified_vault_and_roster() {
        let (context, intent) = parse(&fixture()).unwrap();
        assert!(validate_roster([9; 32], 2, [1, 2, 3], &context, &intent).is_ok());
        assert!(validate_roster([1; 32], 2, [1, 2, 3], &context, &intent).is_err());
        assert!(validate_roster([9; 32], 2, [1, 2], &context, &intent).is_err());
        assert!(validate_roster([9; 32], 3, [1, 2, 3, 4], &context, &intent).is_err());
        assert_eq!(proposer_id(&intent.proposer).unwrap(), 1);
    }

    #[test]
    fn three_signer_manifest_requires_exact_certified_threshold() {
        let mut value: Value = serde_json::from_slice(&fixture()).unwrap();
        value["version"] = json!(2);
        value.as_object_mut().unwrap().remove("pair");
        value["signers"] = json!([1, 2, 4]);
        let raw = serde_json::to_vec(&value).unwrap();
        let (context, intent) = parse(&raw).unwrap();
        assert_eq!(context.signers, vec![1, 2, 4]);
        assert!(validate_roster([9; 32], 3, [1, 2, 3, 4], &context, &intent).is_ok());
        assert!(validate_roster([9; 32], 2, [1, 2, 3, 4], &context, &intent).is_err());
        value["signers"] = json!([1, 2]);
        assert!(parse(&serde_json::to_vec(&value).unwrap()).is_err());
        value["signers"] = json!([1, 4, 2]);
        assert!(parse(&serde_json::to_vec(&value).unwrap()).is_err());
        // 15-of-16: fifteen signers parse and match the certified policy; sixteen do not.
        value["signers"] = json!((1..=15).collect::<Vec<u16>>());
        let (context, intent) = parse(&serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(validate_roster([9; 32], 15, 1..=16, &context, &intent).is_ok());
        value["signers"] = json!((1..=16).collect::<Vec<u16>>());
        assert!(parse(&serde_json::to_vec(&value).unwrap()).is_err());
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
