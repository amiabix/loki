use super::{AcceptedCeremonyRoster, CheckpointAuthority, CheckpointState, SavedCheckpoint};
use crate::setup_transport::Identity;
use loki_relay_client::{
    sign_admission_request, AdmissionHttp, AdmissionOutcome, CommIdentity, OperatorSet,
    RelayRuntime, VerifiedAdmissionReply,
};
use loki_relay_protocol::{
    admission::{AdmissionCommand, AdmissionRequest},
    canonical::Value,
};
use rand_core::{OsRng, RngCore};
use std::{collections::BTreeMap, time::Duration};
use zeroize::Zeroizing;
const ERROR: &str = "setup_checkpoint";
enum Action {
    Confirmed(CheckpointState),
    Submit,
}
fn fields(value: &Value, n: usize) -> Result<&[Value], String> {
    match value {
        Value::Array(fields) if fields.len() == n => Ok(fields),
        _ => Err(ERROR.into()),
    }
}
fn number(value: &Value) -> Result<u64, String> {
    match value {
        Value::Integer(n) => u64::try_from(*n).map_err(|_| ERROR.into()),
        _ => Err(ERROR.into()),
    }
}
fn id(value: &Value) -> Result<[u8; 32], String> {
    match value {
        Value::Bytes(raw) => raw.as_slice().try_into().map_err(|_| ERROR.into()),
        _ => Err(ERROR.into()),
    }
}
fn stopped(expected: &SavedCheckpoint) -> CheckpointState {
    CheckpointState {
        generation: expected.generation,
        digest: expected.digest,
        terminal: true,
    }
}
#[cfg(test)]
fn checkpoint_action(expected: &SavedCheckpoint, state: &Value) -> Result<Action, String> {
    checkpoint_action_with_activation(expected, state, false)
}
fn checkpoint_action_with_activation(
    expected: &SavedCheckpoint,
    state: &Value,
    active: bool,
) -> Result<Action, String> {
    let state = fields(state, 7)?;
    let terminal = number(&state[3])?;
    if terminal > 4 {
        return Err(ERROR.into());
    }
    if terminal != 0 {
        if active && terminal == 2 && state[6] != Value::Null {
            let saved = fields(&state[6], 3)?;
            if number(&saved[0])? == expected.generation
                && id(&saved[1])? == expected.predecessor
                && id(&saved[2])? == expected.digest
            {
                return Ok(Action::Confirmed(CheckpointState {
                    generation: expected.generation,
                    digest: expected.digest,
                    terminal: false,
                }));
            }
        }
        return Ok(Action::Confirmed(stopped(expected)));
    }
    if state[6] == Value::Null {
        return Ok(
            if expected.generation == 1 && expected.predecessor == [0; 32] {
                Action::Submit
            } else {
                Action::Confirmed(stopped(expected))
            },
        );
    }
    let saved = fields(&state[6], 3)?;
    let generation = number(&saved[0])?;
    let predecessor = id(&saved[1])?;
    let digest = id(&saved[2])?;
    if generation == 0 || digest == [0; 32] {
        return Err(ERROR.into());
    }
    if generation == expected.generation
        && predecessor == expected.predecessor
        && digest == expected.digest
    {
        Ok(Action::Confirmed(CheckpointState {
            generation,
            digest,
            terminal: false,
        }))
    } else if generation.checked_add(1) == Some(expected.generation)
        && digest == expected.predecessor
    {
        Ok(Action::Submit)
    } else {
        Ok(Action::Confirmed(stopped(expected)))
    }
}
pub struct AdmissionCheckpointAuthority {
    http: AdmissionHttp,
    runtime: RelayRuntime,
    identity: CommIdentity,
    ceremony: [u8; 32],
    members: BTreeMap<u16, ([u8; 32], [u8; 32])>,
    deadline: Duration,
    retry: Option<std::sync::Arc<crate::setup_retry::AdmissionRetry>>,
}
impl AdmissionCheckpointAuthority {
    pub fn new(
        identity: &Identity,
        operators: &OperatorSet,
        accepted: &AcceptedCeremonyRoster,
        development: bool,
    ) -> Result<Self, String> {
        if accepted.operator_digest() != operators.digest()
            || accepted.roster().members.get(&identity.public().id) != Some(&identity.public())
        {
            return Err(ERROR.into());
        }
        let raw = Zeroizing::new(identity.to_secret_bytes());
        Ok(Self {
            http: if development {
                AdmissionHttp::development(operators)
            } else {
                AdmissionHttp::new(operators)
            }
            .map_err(|_| ERROR)?,
            runtime: RelayRuntime::new().map_err(|_| ERROR)?,
            identity: CommIdentity::from_serialized(&raw).map_err(|_| ERROR)?,
            ceremony: accepted.roster().vault,
            members: accepted
                .roster()
                .members
                .iter()
                .map(|(id, m)| (*id, (m.signing, m.encryption)))
                .collect(),
            deadline: Duration::from_secs(operators.limits().request_seconds),
            retry: None,
        })
    }
    pub(crate) fn with_retry(
        mut self,
        retry: std::sync::Arc<crate::setup_retry::AdmissionRetry>,
    ) -> Self {
        self.retry = Some(retry);
        self
    }
    async fn execute(
        &self,
        package: &[u8],
    ) -> loki_relay_client::ClientResult<VerifiedAdmissionReply> {
        if let Some(retry) = &self.retry {
            retry
                .execute(package, self.http.execute(package, None))
                .await
        } else {
            self.http.execute(package, None).await
        }
    }
    fn request(&self, operation: [u8; 32], command: AdmissionCommand) -> Result<Vec<u8>, String> {
        sign_admission_request(
            &self.identity,
            &AdmissionRequest {
                operation,
                device: self.identity.public(),
                command,
            },
        )
        .map_err(|_| ERROR.into())
    }
    fn state_request(&self) -> Result<Vec<u8>, String> {
        let mut operation = [0; 32];
        OsRng.fill_bytes(&mut operation);
        self.request(
            operation,
            AdmissionCommand::State {
                ceremony: self.ceremony,
                slot: self.identity.public().id,
            },
        )
    }
    fn action(
        &self,
        expected: &SavedCheckpoint,
        reply: &VerifiedAdmissionReply,
        active: bool,
    ) -> Result<Action, String> {
        match reply.outcome() {
            AdmissionOutcome::Accepted(value) => {
                let state = fields(value, 7)?;
                if number(&state[0])? != self.members.len() as u64 {
                    return Ok(Action::Confirmed(stopped(expected)));
                }
                let Value::Array(claims) = &state[4] else {
                    return Err(ERROR.into());
                };
                if claims.len() != self.members.len() {
                    return Ok(Action::Confirmed(stopped(expected)));
                }
                let mut seen = BTreeMap::new();
                for claim in claims {
                    let claim = fields(claim, 3)?;
                    let slot = u16::try_from(number(&claim[0])?).map_err(|_| ERROR)?;
                    if seen
                        .insert(slot, (id(&claim[1])?, id(&claim[2])?))
                        .is_some()
                    {
                        return Err(ERROR.into());
                    }
                }
                if seen != self.members {
                    return Ok(Action::Confirmed(stopped(expected)));
                }
                checkpoint_action_with_activation(expected, value, active)
            }
            AdmissionOutcome::Rejected("storage" | "unavailable") => Err(ERROR.into()),
            AdmissionOutcome::Rejected(_) => Ok(Action::Confirmed(stopped(expected))),
        }
    }
}
impl AdmissionCheckpointAuthority {
    fn reconcile_mode(
        &mut self,
        expected: &SavedCheckpoint,
        active: bool,
    ) -> Result<CheckpointState, String> {
        let state = self.state_request()?;
        self.runtime
            .block_on(async {
                loki_relay_client::relay_timeout(self.deadline, async {
                    let reply = self.execute(&state).await.map_err(|_| ERROR)?;
                    match self.action(expected, &reply, active)? {
                        Action::Confirmed(state) => Ok(state),
                        Action::Submit => {
                            let package = self.request(
                                expected.operation,
                                AdmissionCommand::Checkpoint {
                                    ceremony: self.ceremony,
                                    slot: self.identity.public().id,
                                    generation: expected.generation,
                                    predecessor: expected.predecessor,
                                    checkpoint: expected.digest,
                                },
                            )?;
                            let reply = self.execute(&package).await.map_err(|_| ERROR)?;
                            match reply.outcome() {
                                AdmissionOutcome::Accepted(value) => {
                                    let value = fields(value, 2)?;
                                    if number(&value[0])? != expected.generation
                                        || id(&value[1])? != expected.digest
                                    {
                                        return Ok(stopped(expected));
                                    }
                                }
                                AdmissionOutcome::Rejected("storage" | "unavailable") => {
                                    return Err(ERROR.into())
                                }
                                AdmissionOutcome::Rejected(_) => return Ok(stopped(expected)),
                            }
                            let state = self.state_request()?;
                            let reply = self.execute(&state).await.map_err(|_| ERROR)?;
                            match self.action(expected, &reply, active)? {
                                Action::Confirmed(state) => Ok(state),
                                Action::Submit => Ok(stopped(expected)),
                            }
                        }
                    }
                })
                .await
            })
            .map_err(|_| ERROR)?
    }
}

impl CheckpointAuthority for AdmissionCheckpointAuthority {
    fn reconcile(&mut self, expected: &SavedCheckpoint) -> Result<CheckpointState, String> {
        self.reconcile_mode(expected, false)
    }
    fn reconcile_active(&mut self, expected: &SavedCheckpoint) -> Result<CheckpointState, String> {
        self.reconcile_mode(expected, true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use loki_relay_protocol::canonical::Value;
    fn state(generation: u64, predecessor: [u8; 32], digest: [u8; 32], terminal: u64) -> Value {
        Value::Array(vec![
            Value::Integer(3.into()),
            Value::Integer(10.into()),
            Value::Integer(20.into()),
            Value::Integer(terminal.into()),
            Value::Array(vec![]),
            Value::Array(vec![]),
            Value::Array(vec![
                Value::Integer(generation.into()),
                Value::Bytes(predecessor.to_vec()),
                Value::Bytes(digest.to_vec()),
            ]),
        ])
    }
    fn checkpoint() -> SavedCheckpoint {
        SavedCheckpoint {
            generation: 3,
            predecessor: [2; 32],
            digest: [3; 32],
            operation: [4; 32],
        }
    }
    #[test]
    fn activation_reopen_requires_exact_checkpoint_and_signed_active_terminal() {
        let expected = checkpoint();
        for terminal in [0, 1, 2, 3, 4] {
            let reply = state(3, [2; 32], [3; 32], terminal);
            let Action::Confirmed(actual) =
                checkpoint_action_with_activation(&expected, &reply, true).unwrap()
            else {
                panic!("saved checkpoint must reconcile");
            };
            assert_eq!(actual.terminal, !matches!(terminal, 0 | 2));
        }
        for reply in [
            state(2, [1; 32], [2; 32], 2),
            state(3, [9; 32], [3; 32], 2),
            state(3, [2; 32], [9; 32], 2),
        ] {
            assert!(matches!(
                checkpoint_action_with_activation(&expected, &reply, true).unwrap(),
                Action::Confirmed(CheckpointState { terminal: true, .. })
            ));
        }
        assert!(matches!(
            checkpoint_action(&expected, &state(3, [2; 32], [3; 32], 2)).unwrap(),
            Action::Confirmed(CheckpointState { terminal: true, .. })
        ));
    }
    #[test]
    fn exact_saved_checkpoint_reconciles_and_only_immediate_predecessor_can_advance() {
        let expected = checkpoint();
        assert!(matches!(
            checkpoint_action(&expected, &state(3, [2; 32], [3; 32], 0)).unwrap(),
            Action::Confirmed(_)
        ));
        assert!(matches!(
            checkpoint_action(&expected, &state(2, [1; 32], [2; 32], 0)).unwrap(),
            Action::Submit
        ));
        for value in [
            state(3, [2; 32], [9; 32], 0),
            state(3, [9; 32], [3; 32], 0),
            state(1, [0; 32], [1; 32], 0),
            state(4, [3; 32], [4; 32], 0),
            state(2, [1; 32], [2; 32], 1),
            state(3, [2; 32], [3; 32], 4),
        ] {
            assert!(matches!(
                checkpoint_action(&expected, &value).unwrap(),
                Action::Confirmed(CheckpointState { terminal: true, .. })
            ));
        }
    }
    #[test]
    fn signed_http_reconciles_lost_checkpoint_responses_and_observes_terminal_state() {
        use ed25519_dalek::{Signer, SigningKey};
        use loki_relay_protocol::{admission, canonical};
        use sha2::{Digest, Sha256};
        use std::{
            io::{Read, Write},
            net::TcpListener,
            sync::{
                atomic::{AtomicBool, Ordering},
                Arc,
            },
        };
        for count in [3u16, 4] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let origin = format!("http://{}", listener.local_addr().unwrap());
            let admission_key = SigningKey::from_bytes(&[8; 32]);
            let config_key = SigningKey::from_bytes(&[9; 32]);
            fn signed(key: &SigningKey, domain: &[u8], body: Vec<u8>) -> Vec<u8> {
                let mut input = domain.to_vec();
                input.extend_from_slice(&(body.len() as u32).to_be_bytes());
                input.extend_from_slice(&body);
                canonical::encode(&Value::Array(vec![
                    Value::Bytes(body),
                    Value::Bytes(key.sign(&input).to_bytes().to_vec()),
                ]))
                .unwrap()
            }
            let mut relays: Vec<_> = (1u8..=3)
                .map(|i| {
                    Value::Array(vec![
                        Value::Bytes(
                            SigningKey::from_bytes(&[i; 32])
                                .verifying_key()
                                .to_bytes()
                                .to_vec(),
                        ),
                        Value::Bytes(vec![i + 10; 32]),
                        Value::Bytes(format!("https://relay{i}.example").into_bytes()),
                    ])
                })
                .collect();
            relays.sort_by_key(|r| canonical::encode(r).unwrap());
            let config = canonical::encode(&Value::Array(vec![
                Value::Integer(1.into()),
                Value::Array(relays),
                Value::Array(vec![
                    Value::Bytes(origin.as_bytes().to_vec()),
                    Value::Bytes(admission_key.verifying_key().to_bytes().to_vec()),
                ]),
                Value::Array(vec![Value::Integer(2.into())]),
                Value::Array(
                    [86400u64, 2592000, 1048576, 67108864, 2, 1, 60]
                        .into_iter()
                        .map(|n| Value::Integer(n.into()))
                        .collect(),
                ),
            ]))
            .unwrap();
            let config = signed(&config_key, b"Loki_Operator_Config_v1\0", config);
            let operators =
                OperatorSet::verify_development(&config, &config_key.verifying_key().to_bytes())
                    .unwrap();
            let identities: Vec<_> = (1..=count).map(Identity::new).collect();
            let document=serde_json::to_vec(&serde_json::json!({"vault":hex::encode([78;32]),"threshold":2,"members":identities.iter().map(|i|{let p=i.public();serde_json::json!({"id":p.id,"signing":hex::encode(p.signing),"encryption":hex::encode(p.encryption)})}).collect::<Vec<_>>()})).unwrap();
            let roster = crate::member_state::Roster::from_bytes(&document).unwrap();
            let payload =
                AcceptedCeremonyRoster::agreement_payload(&roster, "regtest", operators.digest())
                    .unwrap();
            let votes = identities
                .iter()
                .map(|i| {
                    (
                        i.public().id,
                        i.sign_setup_agreement(&[78; 32], &payload).unwrap(),
                    )
                })
                .collect();
            let accepted = AcceptedCeremonyRoster::verify(
                roster,
                "regtest",
                *operators.digest(),
                &identities[0],
                &votes,
            )
            .unwrap();
            let claims = Value::Array(
                identities
                    .iter()
                    .map(|i| {
                        let p = i.public();
                        Value::Array(vec![
                            Value::Integer(p.id.into()),
                            Value::Bytes(p.signing.to_vec()),
                            Value::Bytes(p.encryption.to_vec()),
                        ])
                    })
                    .collect(),
            );
            let terminal = Arc::new(AtomicBool::new(false));
            let server_terminal = terminal.clone();
            let server = std::thread::spawn(move || {
                let mut committed = None;
                let mut checkpoint_packages = Vec::new();
                for _ in 0..6 {
                    let (mut stream, _) = listener.accept().unwrap();
                    stream
                        .set_read_timeout(Some(Duration::from_secs(5)))
                        .unwrap();
                    let mut raw = Vec::new();
                    let header_end = loop {
                        let mut byte = [0; 1];
                        stream.read_exact(&mut byte).unwrap();
                        raw.push(byte[0]);
                        if raw.ends_with(b"\r\n\r\n") {
                            break raw.len();
                        }
                        assert!(raw.len() < 8192);
                    };
                    let headers = String::from_utf8(raw.clone()).unwrap();
                    let size: usize = headers
                        .lines()
                        .find_map(|line| {
                            line.split_once(':')
                                .filter(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                                .map(|(_, size)| size.trim().parse().unwrap())
                        })
                        .unwrap();
                    assert!(size < 32768);
                    raw.resize(header_end + size, 0);
                    stream.read_exact(&mut raw[header_end..]).unwrap();
                    let package = &raw[header_end..];
                    let wrapper = canonical::decode(package, 32768).unwrap();
                    let wrapper = fields(&wrapper, 2).unwrap();
                    let Value::Bytes(body) = &wrapper[0] else {
                        panic!("request body")
                    };
                    let request = admission::decode_request(body).unwrap();
                    let Value::Bytes(signature) = &wrapper[1] else {
                        panic!("request signature")
                    };
                    let mut input = admission::REQUEST_DOMAIN.to_vec();
                    input.extend_from_slice(&(body.len() as u32).to_be_bytes());
                    input.extend_from_slice(body);
                    ed25519_dalek::VerifyingKey::from_bytes(&request.device.signing)
                        .unwrap()
                        .verify_strict(
                            &input,
                            &ed25519_dalek::Signature::from_slice(signature).unwrap(),
                        )
                        .unwrap();
                    let result = match request.command {
                        AdmissionCommand::State { .. } => Value::Array(vec![
                            Value::Integer(count.into()),
                            Value::Integer(86400.into()),
                            Value::Integer(2592000.into()),
                            Value::Integer((server_terminal.load(Ordering::SeqCst) as u64).into()),
                            claims.clone(),
                            Value::Array(vec![]),
                            committed.clone().unwrap_or(Value::Null),
                        ]),
                        AdmissionCommand::Checkpoint {
                            generation,
                            predecessor,
                            checkpoint,
                            ..
                        } => {
                            checkpoint_packages.push(package.to_vec());
                            if checkpoint_packages.len() == 2 {
                                committed = Some(Value::Array(vec![
                                    Value::Integer(generation.into()),
                                    Value::Bytes(predecessor.to_vec()),
                                    Value::Bytes(checkpoint.to_vec()),
                                ]));
                            }
                            continue;
                        }
                        _ => panic!("unexpected request"),
                    };
                    let body = canonical::encode(&Value::Array(vec![
                        Value::Integer(1.into()),
                        Value::Bytes(request.operation.to_vec()),
                        Value::Bytes(Sha256::digest(package).to_vec()),
                        Value::Array(vec![Value::Integer(1.into()), result]),
                    ]))
                    .unwrap();
                    let reply = signed(&admission_key, admission::RESPONSE_DOMAIN, body);
                    stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/cbor\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",reply.len()).as_bytes()).unwrap();
                    stream.write_all(&reply).unwrap();
                }
                assert_eq!(checkpoint_packages.len(), 2);
                assert_eq!(checkpoint_packages[0], checkpoint_packages[1]);
            });
            assert!(AdmissionCheckpointAuthority::new(
                &identities[0],
                &operators,
                &accepted,
                false
            )
            .is_err());
            let mut authority =
                AdmissionCheckpointAuthority::new(&identities[0], &operators, &accepted, true)
                    .unwrap();
            let expected = SavedCheckpoint {
                generation: 1,
                predecessor: [0; 32],
                digest: [3; 32],
                operation: [4; 32],
            };
            assert!(authority.reconcile(&expected).is_err());
            assert!(authority.reconcile(&expected).is_err());
            let confirmed = authority.reconcile(&expected).unwrap();
            assert!(!confirmed.terminal);
            assert_eq!(confirmed.digest, expected.digest);
            terminal.store(true, Ordering::SeqCst);
            assert!(authority.reconcile(&expected).unwrap().terminal);
            server.join().unwrap();
        }
    }
}
