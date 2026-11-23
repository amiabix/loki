use crate::{
    canonical::{self, Value},
    types::{Id32, RelayPin},
    WireError, WireResult,
};

pub const SIGNATURE_DOMAIN: &[u8] = b"Loki_Relay_Identity_v1\0";
pub const MAX_RESPONSE: usize = 2304;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChallengeResponse {
    pub pin: RelayPin,
    pub endpoint: String,
    pub challenge: Id32,
}

pub fn encode_body(response: &ChallengeResponse) -> WireResult<Vec<u8>> {
    if response.endpoint.is_empty() || response.endpoint.len() > 2048 {
        return Err(WireError::Bounds);
    }
    canonical::encode(&Value::Array(vec![
        Value::Integer(1.into()),
        Value::Bytes(response.pin.key.to_vec()),
        Value::Bytes(response.pin.run.to_vec()),
        Value::Bytes(response.endpoint.as_bytes().to_vec()),
        Value::Bytes(response.challenge.to_vec()),
    ]))
}

pub fn decode_body(raw: &[u8]) -> WireResult<ChallengeResponse> {
    let Value::Array(fields) = canonical::decode(raw, MAX_RESPONSE)? else {
        return Err(WireError::Schema);
    };
    if fields.len() != 5 || fields[0] != Value::Integer(1.into()) {
        return Err(WireError::Schema);
    }
    let bytes = |index: usize| -> WireResult<&[u8]> {
        match &fields[index] {
            Value::Bytes(value) => Ok(value),
            _ => Err(WireError::Schema),
        }
    };
    let id =
        |index| -> WireResult<Id32> { bytes(index)?.try_into().map_err(|_| WireError::Schema) };
    let endpoint = std::str::from_utf8(bytes(3)?)
        .map_err(|_| WireError::Schema)?
        .to_owned();
    let response = ChallengeResponse {
        pin: RelayPin {
            key: id(1)?,
            run: id(2)?,
        },
        endpoint,
        challenge: id(4)?,
    };
    if encode_body(&response)? != raw {
        return Err(WireError::Canonical);
    }
    Ok(response)
}

pub fn signature_input(body: &[u8]) -> WireResult<Vec<u8>> {
    let length = u32::try_from(body.len()).map_err(|_| WireError::Bounds)?;
    let mut input = Vec::with_capacity(SIGNATURE_DOMAIN.len() + 4 + body.len());
    input.extend_from_slice(SIGNATURE_DOMAIN);
    input.extend_from_slice(&length.to_be_bytes());
    input.extend_from_slice(body);
    Ok(input)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_challenge_body_binds_all_fields() {
        let expected = ChallengeResponse {
            pin: RelayPin {
                key: [1; 32],
                run: [2; 32],
            },
            endpoint: "http://127.0.0.1:8000".into(),
            challenge: [3; 32],
        };
        let encoded = encode_body(&expected).unwrap();
        assert_eq!(decode_body(&encoded).unwrap(), expected);
        assert!(signature_input(&encoded)
            .unwrap()
            .starts_with(SIGNATURE_DOMAIN));
        assert!(decode_body(&encoded[..encoded.len() - 1]).is_err());
    }
}
