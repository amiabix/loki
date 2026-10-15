use crate::{
    setup_ceremony::journal::{self, MemberLock},
    state::MemberDir,
};
use loki_relay_protocol::canonical::{self, Value};
use rand_core::{OsRng, RngCore};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;
const ERROR: &str = "setup_retry";
const FILE: &str = "setup-admission-retry.sealed";
const LIMIT: u64 = 4096;
struct Entry {
    attempts: u64,
    last: u64,
    next: u64,
}
pub(crate) struct AdmissionRetry {
    root: PathBuf,
    passphrase: Zeroizing<String>,
    context: [u8; 32],
    floor: u64,
    cap: u64,
    lock: MemberLock,
}
impl AdmissionRetry {
    pub(crate) fn key(package: &[u8]) -> Result<[u8; 32], String> {
        use sha2::{Digest, Sha256};
        let Value::Array(envelope) =
            canonical::decode(package, loki_relay_protocol::admission::MAX_REQUEST)
                .map_err(|_| ERROR)?
        else {
            return Err(ERROR.into());
        };
        if envelope.len() != 2 {
            return Err(ERROR.into());
        }
        let Value::Bytes(body) = &envelope[0] else {
            return Err(ERROR.into());
        };
        loki_relay_protocol::admission::decode_request(body).map_err(|_| ERROR)?;
        let Value::Array(fields) =
            canonical::decode(body, loki_relay_protocol::admission::MAX_REQUEST)
                .map_err(|_| ERROR)?
        else {
            return Err(ERROR.into());
        };
        Ok(Sha256::digest(canonical::encode(&fields[3]).map_err(|_| ERROR)?).into())
    }
    pub(crate) async fn execute<F>(
        &self,
        package: &[u8],
        action: F,
    ) -> loki_relay_client::ClientResult<loki_relay_client::VerifiedAdmissionReply>
    where
        F: std::future::Future<
            Output = loki_relay_client::ClientResult<loki_relay_client::VerifiedAdmissionReply>,
        >,
    {
        use loki_relay_client::{AdmissionOutcome, ClientError};
        let key = Self::key(package).map_err(|_| ClientError::Config)?;
        let now = || -> Result<u64, ClientError> {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| ClientError::Storage)?
                .as_millis()
                .try_into()
                .map_err(|_| ClientError::Storage)
        };
        if !self
            .can_attempt(key, now()?)
            .map_err(|_| ClientError::Storage)?
        {
            return Err(ClientError::Transport);
        }
        let reply = action.await;
        if matches!(&reply, Err(ClientError::Transport))
            || matches!(&reply, Ok(reply) if matches!(reply.outcome(),AdmissionOutcome::Rejected("storage"|"unavailable")))
        {
            self.failure(key, now()?)
                .map_err(|_| ClientError::Storage)?;
            return Err(ClientError::Transport);
        }
        if reply.is_ok() {
            self.success(key).map_err(|_| ClientError::Storage)?;
        }
        reply
    }

    pub(crate) fn new(
        root: &Path,
        passphrase: &str,
        context: [u8; 32],
        minimum: u64,
        maximum: u64,
        lock: &MemberLock,
    ) -> Result<Self, String> {
        if context == [0; 32] || minimum == 0 || minimum > maximum || maximum > 60 {
            return Err(ERROR.into());
        }
        journal::check_private_root(root)?;
        journal::check_private_root(&root.join("secrets"))?;
        Ok(Self {
            root: root.to_owned(),
            passphrase: Zeroizing::new(passphrase.to_owned()),
            context,
            floor: minimum * 1000,
            cap: maximum * 1000,
            lock: lock.share_for(&root.join("secrets/.setup.lock"))?,
        })
    }
    fn load(&self) -> Result<BTreeMap<[u8; 32], Entry>, String> {
        let _held = self
            .lock
            .share_for(&self.root.join("secrets/.setup.lock"))?;
        let secrets = MemberDir::open(&self.root, "secrets");
        journal::check_private_root(secrets.path())?;
        let path = secrets.path().join(FILE);
        if !path.try_exists().map_err(|_| ERROR)? {
            return Ok(BTreeMap::new());
        }
        if journal::checked_file(&path)?
            .metadata()
            .map_err(|_| ERROR)?
            .len()
            > LIMIT + 65
        {
            return Err(ERROR.into());
        }
        let raw = Zeroizing::new(
            secrets
                .read_sealed(FILE, &self.passphrase)
                .map_err(|_| ERROR)?,
        );
        let Value::Array(fields) = canonical::decode(&raw, LIMIT as usize).map_err(|_| ERROR)?
        else {
            return Err(ERROR.into());
        };
        if fields.len() != 3
            || fields[0] != Value::Integer(1.into())
            || fields[1] != Value::Bytes(self.context.to_vec())
        {
            return Err(ERROR.into());
        }
        let Value::Array(rows) = &fields[2] else {
            return Err(ERROR.into());
        };
        if rows.is_empty() || rows.len() > 32 {
            return Err(ERROR.into());
        }
        let mut result = BTreeMap::new();
        let mut previous = None;
        for row in rows {
            let Value::Array(row) = row else {
                return Err(ERROR.into());
            };
            if row.len() != 4 {
                return Err(ERROR.into());
            }
            let Value::Bytes(key) = &row[0] else {
                return Err(ERROR.into());
            };
            let key: [u8; 32] = key.as_slice().try_into().map_err(|_| ERROR)?;
            if previous.is_some_and(|p| p >= key) {
                return Err(ERROR.into());
            }
            fn number(value: &Value) -> Result<u64, String> {
                let Value::Integer(v) = value else {
                    return Err(ERROR.into());
                };
                u64::try_from(*v).map_err(|_| ERROR.into())
            }
            let entry = Entry {
                attempts: number(&row[1])?,
                last: number(&row[2])?,
                next: number(&row[3])?,
            };
            let delay = entry.next.checked_sub(entry.last).ok_or(ERROR)?;
            if !(1..=1000000).contains(&entry.attempts) || delay < self.floor || delay > self.cap {
                return Err(ERROR.into());
            }
            previous = Some(key);
            result.insert(key, entry);
        }
        Ok(result)
    }
    fn save(&self, entries: &BTreeMap<[u8; 32], Entry>) -> Result<(), String> {
        let _held = self
            .lock
            .share_for(&self.root.join("secrets/.setup.lock"))?;
        let secrets = MemberDir::open(&self.root, "secrets");
        journal::check_private_root(secrets.path())?;
        let target = secrets.path().join(FILE);
        if target.try_exists().map_err(|_| ERROR)? {
            journal::checked_file(&target)?;
        }
        if entries.is_empty() {
            if target.try_exists().map_err(|_| ERROR)? {
                fs::remove_file(&target).map_err(|_| ERROR)?;
            }
            fs::File::open(secrets.path())
                .map_err(|_| ERROR)?
                .sync_all()
                .map_err(|_| ERROR)?;
            return Ok(());
        }
        if entries.len() > 32 {
            return Err(ERROR.into());
        }
        let rows = entries
            .iter()
            .map(|(key, v)| {
                Value::Array(vec![
                    Value::Bytes(key.to_vec()),
                    Value::Integer(v.attempts.into()),
                    Value::Integer(v.last.into()),
                    Value::Integer(v.next.into()),
                ])
            })
            .collect();
        let raw = Zeroizing::new(
            canonical::encode(&Value::Array(vec![
                Value::Integer(1.into()),
                Value::Bytes(self.context.to_vec()),
                Value::Array(rows),
            ]))
            .map_err(|_| ERROR)?,
        );
        if raw.len() as u64 > LIMIT {
            return Err(ERROR.into());
        }
        let name = format!(".setup-admission-retry-{:016x}.sealed", OsRng.next_u64());
        secrets
            .write_sealed(&name, &raw, &self.passphrase)
            .map_err(|_| ERROR)?;
        let temporary = secrets.path().join(name);
        let result = (|| {
            journal::checked_file(&temporary)?;
            fs::rename(&temporary, &target).map_err(|_| ERROR)?;
            fs::File::open(secrets.path())
                .map_err(|_| ERROR)?
                .sync_all()
                .map_err(|_| ERROR)?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }
    pub(crate) fn can_attempt(&self, key: [u8; 32], now: u64) -> Result<bool, String> {
        let entries = self.load()?;
        let Some(entry) = entries.get(&key) else {
            return Ok(true);
        };
        if now < entry.last {
            return Err(ERROR.into());
        }
        Ok(now >= entry.next)
    }
    pub(crate) fn failure(&self, key: [u8; 32], now: u64) -> Result<(), String> {
        let mut entries = self.load()?;
        if entries.get(&key).is_some_and(|entry| now < entry.last) {
            return Err(ERROR.into());
        }
        let attempts = entries
            .get(&key)
            .map_or(1, |entry| entry.attempts.saturating_add(1).min(1000000));
        let cap = self
            .floor
            .saturating_mul(1u64 << attempts.saturating_sub(1).min(16))
            .min(self.cap);
        let width = cap - self.floor + 1;
        let cutoff = u64::MAX - (u64::MAX % width);
        let mut delay = None;
        for _ in 0..16 {
            let value = OsRng.next_u64();
            if value < cutoff {
                delay = Some(self.floor + value % width);
                break;
            }
        }
        let next = now.checked_add(delay.ok_or(ERROR)?).ok_or(ERROR)?;
        entries.insert(
            key,
            Entry {
                attempts,
                last: now,
                next,
            },
        );
        self.save(&entries)
    }
    pub(crate) fn success(&self, key: [u8; 32]) -> Result<(), String> {
        let mut entries = self.load()?;
        if entries.remove(&key).is_some() {
            self.save(&entries)?;
        }
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{setup_ceremony::journal, state::MemberDir};
    #[test]
    fn admission_retry_survives_reopen_and_keeps_context_and_operation_independent() {
        let root = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("loki-admission-retry-{}", std::process::id()));
        let member = MemberDir::create(&root, "member").unwrap();
        MemberDir::create(member.path(), "secrets").unwrap();
        let lock = journal::lock_file(&member.path().join("secrets/.setup.lock")).unwrap();
        let retry = AdmissionRetry::new(member.path(), "pass", [8; 32], 1, 60, &lock).unwrap();
        let identity = crate::setup_transport::Identity::new(1);
        let signer =
            loki_relay_client::CommIdentity::from_serialized(&identity.to_secret_bytes()).unwrap();
        let mut request = loki_relay_protocol::admission::AdmissionRequest {
            operation: [1; 32],
            device: signer.public(),
            command: loki_relay_protocol::admission::AdmissionCommand::State {
                ceremony: [12; 32],
                slot: 1,
            },
        };
        let first = loki_relay_client::sign_admission_request(&signer, &request).unwrap();
        request.operation = [2; 32];
        let replay = loki_relay_client::sign_admission_request(&signer, &request).unwrap();
        assert_eq!(
            AdmissionRetry::key(&first).unwrap(),
            AdmissionRetry::key(&replay).unwrap()
        );
        request.command = loki_relay_protocol::admission::AdmissionCommand::Terminal {
            ceremony: [12; 32],
            kind: 1,
        };
        let other = loki_relay_client::sign_admission_request(&signer, &request).unwrap();
        assert_ne!(
            AdmissionRetry::key(&first).unwrap(),
            AdmissionRetry::key(&other).unwrap()
        );
        let key = [9; 32];
        assert!(retry.can_attempt(key, 1000).unwrap());
        retry.failure(key, 1000).unwrap();
        assert!(!retry.can_attempt(key, 1999).unwrap());
        assert!(retry.can_attempt([10; 32], 1001).unwrap());
        retry.success([10; 32]).unwrap();
        assert!(!retry.can_attempt(key, 1999).unwrap());
        let reopened = AdmissionRetry::new(member.path(), "pass", [8; 32], 1, 60, &lock).unwrap();
        assert!(!reopened.can_attempt(key, 1999).unwrap());
        assert!(reopened.can_attempt(key, 2000).unwrap());
        reopened.failure(key, 2000).unwrap();
        let entries = reopened.load().unwrap();
        let entry = entries.get(&key).unwrap();
        assert_eq!(entry.attempts, 2);
        assert!((1000..=2000).contains(&(entry.next - entry.last)));
        assert!(!reopened.can_attempt(key, 2001).unwrap());
        let raw =
            std::fs::read(member.path().join("secrets/setup-admission-retry.sealed")).unwrap();
        assert!(!raw.windows(32).any(|v| v == [8; 32] || v == key));
        let foreign = AdmissionRetry::new(member.path(), "pass", [11; 32], 1, 60, &lock).unwrap();
        assert!(foreign.can_attempt(key, 2001).is_err());
        assert!(reopened.can_attempt(key, 999).is_err());
        reopened.success(key).unwrap();
        assert!(reopened.can_attempt(key, 2001).unwrap());
        assert!(!member
            .path()
            .join("secrets/setup-admission-retry.sealed")
            .exists());
        drop(foreign);
        drop(reopened);
        drop(retry);
        drop(lock);
        std::fs::remove_dir_all(root).unwrap();
    }
}
