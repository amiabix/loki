use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use reddsa_frost::frost::redpallas as frost;
use uuid::Uuid;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

pub use crate::setup_transport::{DkgWire, DkgWireKind};
use crate::{
    setup_transport::{Identity, PublicIdentity},
    signing_session::{MessageKind, SessionContext},
};

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Peer(pub [u8; 32]);

pub struct FrostdLoginKey(StaticSecret);

impl FrostdLoginKey {
    pub fn generate() -> Self {
        Self(StaticSecret::random_from_rng(rand_core::OsRng))
    }

    pub fn from_secret_bytes(secret: [u8; 32]) -> Self {
        Self(StaticSecret::from(secret))
    }

    pub fn to_secret_bytes(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.0.to_bytes())
    }

    pub fn peer(&self) -> Peer {
        Peer(PublicKey::from(&self.0).to_bytes())
    }
}

pub enum Outbound {
    Dkg(DkgWire),
    Commitments(frost::round1::SigningCommitments),
    Candidate(SealedCandidate),
    Package(frost::SigningPackage),
    RandomizerSeed([u8; 32]),
    Share(frost::round2::SignatureShare),
    Signing(SealedSigning),
    Peer(SealedPeer),
}

impl Outbound {
    pub fn to_bytes(&self) -> Result<Vec<u8>, TransportError> {
        let encoding = |e: frost::Error| TransportError::Decode(e.to_string());
        match self {
            Self::Dkg(wire) => Ok(wire.as_bytes().to_vec()),
            Self::Commitments(commitments) => commitments.serialize().map_err(encoding),
            Self::Candidate(sealed) => Ok(sealed.0.clone()),
            Self::Package(package) => package.serialize().map_err(encoding),
            Self::RandomizerSeed(seed) => Ok(seed.to_vec()),
            Self::Share(share) => Ok(share.serialize()),
            Self::Signing(sealed) => Ok(sealed.0.clone()),
            Self::Peer(sealed) => Ok(sealed.0.clone()),
        }
    }
}

pub struct SealedSigning(Vec<u8>);

impl SealedSigning {
    pub fn seal(
        own: &Identity,
        recipient: &PublicIdentity,
        context: &SessionContext,
        kind: MessageKind,
        body: &[u8],
    ) -> Result<Self, String> {
        if !kind.valid_hosted_body(context, body) {
            return Err("invalid hosted signing message".into());
        }
        own.seal_session(recipient, context, kind, body).map(Self)
    }
}

pub struct SealedPeer(Vec<u8>);

impl SealedPeer {
    pub fn seal(
        own: &Identity,
        recipient: &PublicIdentity,
        context: &SessionContext,
        kind: MessageKind,
        body: &[u8],
    ) -> Result<Self, String> {
        if !matches!(kind, MessageKind::PeerRequest | MessageKind::PeerReply) {
            return Err("sealed peer message must be a peer request or reply".into());
        }
        own.seal_session(recipient, context, kind, body).map(Self)
    }

    pub fn seal_join(
        own: &Identity,
        creator: &PublicIdentity,
        context: &SessionContext,
        body: &[u8],
    ) -> Result<Self, String> {
        let me = own.public();
        let mut wire = me.id.to_be_bytes().to_vec();
        wire.extend_from_slice(&me.signing);
        wire.extend(own.seal_session(creator, context, MessageKind::PeerRequest, body)?);
        Ok(Self(wire))
    }

    pub fn join_sender<'a>(from: &[u8; 32], wire: &'a [u8]) -> Result<(PublicIdentity, &'a [u8]), String> {
        if wire.len() < 34 {
            return Err("short join request".into());
        }
        let signing: [u8; 32] = wire[2..34].try_into().unwrap();
        ed25519_dalek::VerifyingKey::from_bytes(&signing).map_err(|_| "invalid joiner signing key")?;
        let id = u16::from_be_bytes([wire[0], wire[1]]);
        Ok((PublicIdentity { id, signing, encryption: *from }, &wire[34..]))
    }
}

pub struct SealedCandidate(Vec<u8>);

impl SealedCandidate {
    pub fn seal(
        own: &Identity,
        recipient: &PublicIdentity,
        context: &SessionContext,
        candidate: &crate::signer::CandidatePczt,
    ) -> Result<Self, String> {
        own.seal_session(recipient, context, MessageKind::Candidate, candidate.as_bytes())
            .map(Self)
    }

    pub fn open(
        own: &Identity,
        sender: &PublicIdentity,
        context: &SessionContext,
        wire: &[u8],
    ) -> Result<Vec<u8>, String> {
        let opened = own.open_session(sender, context, wire)?;
        if opened.kind != MessageKind::Candidate {
            return Err("sealed signing message is not a candidate".into());
        }
        Ok(opened.body)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Incoming {
    pub from: Peer,
    pub message: Vec<u8>,
}

pub trait Transport {
    type Error;
    type Channel;

    fn open(&mut self, peers: &[Peer], message_count: u8) -> Result<Self::Channel, Self::Error>;

    fn join(&mut self, session: Uuid) -> Result<Self::Channel, Self::Error>;

    fn send(&self, channel: &Self::Channel, to: &[Peer], message: &Outbound)
        -> Result<(), Self::Error>;

    fn recv(&self, channel: &Self::Channel, as_coordinator: bool)
        -> Result<Vec<Incoming>, Self::Error>;

    fn close(&self, channel: Self::Channel) -> Result<(), Self::Error>;
}

#[derive(Debug)]
pub enum TransportError {
    Http(String),
    Server(String),
    Auth(String),
    Decode(String),
}

impl std::fmt::Display for TransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransportError::Http(e) => write!(f, "frostd http error: {e}"),
            TransportError::Server(e) => write!(f, "frostd server error: {e}"),
            TransportError::Auth(e) => write!(f, "frostd auth error: {e}"),
            TransportError::Decode(e) => write!(f, "frostd decode error: {e}"),
        }
    }
}
impl std::error::Error for TransportError {}

const RELAY_LOG: &str = "dkg-relay.log";
const RELAY_LOG_MAGIC: &[u8; 8] = b"LOKIRLG1";
const RELAY_LOG_ENTRIES: usize = 4096;
const RELAY_LOG_WIRE: usize = 128 * 1024;

pub struct RelayLog {
    dir: PathBuf,
    members: u16,
    entries: Vec<(u16, Vec<u8>)>,
}

fn log_error(e: impl std::fmt::Display) -> TransportError {
    TransportError::Decode(format!("relay log: {e}"))
}

impl RelayLog {
    pub fn open(dir: &Path, members: u16) -> Result<Self, TransportError> {
        if !(2..=crate::member_state::MAX_MEMBERS).contains(&members) {
            return Err(log_error("member count"));
        }
        std::fs::create_dir_all(dir).map_err(log_error)?;
        let mut log = Self {
            dir: dir.to_path_buf(),
            members,
            entries: Vec::new(),
        };
        let raw = match std::fs::read(dir.join(RELAY_LOG)) {
            Ok(raw) => raw,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(log),
            Err(e) => return Err(log_error(e)),
        };
        let mut rest = raw
            .strip_prefix(RELAY_LOG_MAGIC.as_slice())
            .ok_or_else(|| log_error("format"))?;
        while !rest.is_empty() {
            if rest.len() < 6 {
                return Err(log_error("truncated"));
            }
            let from = u16::from_be_bytes([rest[0], rest[1]]);
            let size = u32::from_be_bytes(rest[2..6].try_into().unwrap()) as usize;
            if size > RELAY_LOG_WIRE || rest.len() < 6 + size {
                return Err(log_error("truncated"));
            }
            let bytes = rest[6..6 + size].to_vec();
            log.recipients(from, &DkgWire::parse(bytes.clone()).map_err(log_error)?)?;
            log.entries.push((from, bytes));
            rest = &rest[6 + size..];
        }
        if log.entries.len() > RELAY_LOG_ENTRIES {
            return Err(log_error("too many entries"));
        }
        Ok(log)
    }

    fn recipients(&self, from: u16, wire: &DkgWire) -> Result<Vec<u16>, TransportError> {
        let valid = |id: u16| (1..=self.members).contains(&id);
        if !valid(from) || wire.sender() != from {
            return Err(log_error("the wire's sender is not the relay sender"));
        }
        match wire.recipient() {
            Some(to) if valid(to) && to != from => Ok(vec![to]),
            Some(_) => Err(log_error("recipient")),
            None => Ok((1..=self.members).filter(|id| *id != from).collect()),
        }
    }

    pub fn relay(
        &mut self,
        from: u16,
        bytes: Vec<u8>,
    ) -> Result<Option<(DkgWire, Vec<u16>)>, TransportError> {
        let wire = DkgWire::parse(bytes).map_err(log_error)?;
        let recipients = self.recipients(from, &wire)?;
        if self
            .entries
            .iter()
            .any(|(sender, saved)| *sender == from && saved.as_slice() == wire.as_bytes())
        {
            return Ok(None);
        }
        if self.entries.len() >= RELAY_LOG_ENTRIES || wire.as_bytes().len() > RELAY_LOG_WIRE {
            return Err(log_error("full"));
        }
        self.entries.push((from, wire.as_bytes().to_vec()));
        if let Err(e) = self.save() {
            self.entries.pop();
            return Err(e);
        }
        Ok(Some((wire, recipients)))
    }

    fn save(&self) -> Result<(), TransportError> {
        let mut out = RELAY_LOG_MAGIC.to_vec();
        for (from, bytes) in &self.entries {
            out.extend_from_slice(&from.to_be_bytes());
            out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
            out.extend_from_slice(bytes);
        }
        crate::signer::durable::replace_durable(&self.dir, RELAY_LOG, &out).map_err(log_error)
    }

    pub fn for_member(&self, member: u16) -> Vec<DkgWire> {
        self.entries
            .iter()
            .filter_map(|(from, bytes)| {
                let wire = DkgWire::parse(bytes.clone()).ok()?;
                self.recipients(*from, &wire)
                    .ok()?
                    .contains(&member)
                    .then_some(wire)
            })
            .collect()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn active(&self) -> bool {
        let mut receipts = BTreeMap::new();
        for (from, bytes) in &self.entries {
            if crate::setup_transport::wire_kind(bytes) == Some(DkgWireKind::BackupReceipt) {
                receipts.insert(*from, ());
            }
        }
        receipts.len() == usize::from(self.members)
    }

    pub fn delete(self) -> Result<(), TransportError> {
        if !self.active() {
            return Err(log_error("the vault is not active yet"));
        }
        crate::signer::durable::remove_durable(&self.dir, RELAY_LOG).map_err(log_error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::setup_transport::Identity;

    #[test]
    fn relay_log_checks_senders_survives_restart_and_deletes_only_when_active() {
        let dir = std::env::temp_dir().join(format!(
            "loki-relay-log-{}-{}",
            std::process::id(),
            rand_core::RngCore::next_u64(&mut rand_core::OsRng)
        ));
        let vault = [3u8; 32];
        let identities: Vec<Identity> = (1..=3).map(Identity::new).collect();
        let round1 = identities[0].sign_round1(&vault, b"round one").unwrap();
        let mut log = RelayLog::open(&dir, 3).unwrap();
        assert!(log.relay(2, round1.clone()).is_err());
        assert!(log.relay(1, b"not a wire".to_vec()).is_err());
        let (_, to) = log.relay(1, round1.clone()).unwrap().unwrap();
        assert_eq!(to, vec![2, 3]);
        assert!(log.relay(1, round1.clone()).unwrap().is_none());
        assert!(!log.active());

        let log = RelayLog::open(&dir, 3).unwrap();
        assert_eq!(log.len(), 1);
        assert_eq!(log.for_member(2)[0].as_bytes(), round1.as_slice());
        assert!(log.for_member(1).is_empty());
        assert!(log.delete().is_err(), "deleted before the vault is active");

        let mut log = RelayLog::open(&dir, 3).unwrap();
        for (i, identity) in identities.iter().enumerate() {
            let receipt = identity.sign_backup(&vault, b"receipt").unwrap();
            log.relay(i as u16 + 1, receipt).unwrap().unwrap();
        }
        assert!(log.active());
        log.delete().unwrap();
        assert!(!dir.join(RELAY_LOG).exists());

        std::fs::write(dir.join(RELAY_LOG), b"LOKIRLG1\x00\x01\x00\x00\x00\x09garbage").unwrap();
        assert!(RelayLog::open(&dir, 3).is_err());
    }
}
