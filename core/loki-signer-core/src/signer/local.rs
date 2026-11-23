//! [`LocalSigner`]: the in-app implementation of the single [`Signer`] seam.
//!
//! It holds exactly one member's FROST share for one vault, sealed at rest by the
//! [`SecureElement`] (software backend for now; Secure Enclave / StrongBox implement the
//! same trait later). The share is unsealed into memory only for the two FROST rounds and
//! the plaintext is held in a `Zeroizing` buffer.
//!
//! A signer created with [`LocalSigner::create`] owns a data directory
//! ([`crate::signer::store`]) and runs the vault setup itself: [`Signer::dkg_begin`] shows
//! the roster code on the device, and [`Signer::dkg_step`] drives the shared v2 DKG core
//! ([`crate::dkg_core`]), saving every step before it releases any message. Round-two
//! shares only ever leave as v2 envelopes between one-setup fresh keys, so nobody who
//! carries the messages (coordinator, frostd, logs) can rebuild the vault key.
//!
//! The safety-critical signing method is [`LocalSigner::sign_approve`], which binds the
//! WYSIWYS render to the exact bytes being signed (invariant #3 / threat §5.4):
//!   1. independently parse the PCZT and render it ([`wysiwys::describe_pczt`]),
//!   2. require an explicit approval decision over that render,
//!   3. recompute the sighash from the SAME bytes ([`wysiwys::sighash_of_pczt`]) and
//!      REFUSE unless `pkg.message()` equals it — BEFORE the nonce/share is touched,
//!   4. only then produce the rerandomized round-2 share under the single-use nonce rules.

use crate::dkg_core::{DkgCore, DkgPhase, DkgState};
use crate::member_state::{Roster, ValidatedRoster};
use crate::setup_transport::{DkgWire, DkgWireKind, Identity, PublicIdentity};
use crate::signing_session::{MessageKind, NonceWitness, SessionContext};
use crate::signer::backup::{self, BackupArtifact, BackupMaterial};
use crate::signer::nonce::NonceStore;
use crate::signer::secure_element::{SealedShare, SecureElement};
use crate::signer::store::{FileKind, SignerStore};
use crate::signer::wysiwys::{self, PaymentView};
use crate::signer::{
    CandidatePczt, CandidateRef, Connection, DkgInput, MemberIdentity, Network, ReleasedAddress,
    Session, Signer, VaultRef,
};
use crate::zip2005;
use orchard::keys::FullViewingKey;
use reddsa_frost::frost::redpallas as frost;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;
#[cfg(not(target_arch = "wasm32"))]
use std::time::Instant;
#[cfg(target_arch = "wasm32")]
use web_time::Instant;
use zeroize::Zeroizing;

pub type ApprovalPolicy = Box<dyn FnMut(&ApprovalRequest<'_>) -> bool + Send>;

pub struct ApprovalRequest<'a> {
    pub candidate: &'a CandidateRef,
    pub sighash: [u8; 32],
    pub view: &'a PaymentView,
}

pub type ConnectApproval = Box<dyn FnMut(&str, Network) -> bool + Send>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RosterDecision {
    Match,
    NoMatch,
    Cancelled,
}

pub type RosterConfirmation = Box<dyn FnMut(&str) -> RosterDecision + Send>;

pub trait BackupDevice: Send {
    fn passphrase(&mut self) -> Option<Zeroizing<String>>;
    fn save(&mut self, artifact: &BackupArtifact) -> Result<(), String>;
    fn load(&mut self) -> Result<BackupArtifact, String>;
}

pub struct DevicePrompts {
    pub connect: ConnectApproval,
    pub roster: RosterConfirmation,
    pub roster_deadline: Duration,
    pub backup: Box<dyn BackupDevice>,
    pub approval: ApprovalPolicy,
}

#[derive(Debug)]
pub enum SignerError {
    MemberRefused,
    FeeUnverified(String),
    SighashMismatch,
    NoSession,
    NoShare,
    ConnectRefused,
    RosterRejected(String),
    Cancelled,
    TimedOut,
    SetupAborted(String),
    MessageRefused(String),
    NotReady,
    Other(String),
}

impl std::fmt::Display for SignerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SignerError::MemberRefused => write!(f, "member refused the rendered payment"),
            SignerError::FeeUnverified(e) => write!(f, "{e}"),
            SignerError::SighashMismatch => write!(
                f,
                "REFUSED: SigningPackage.message() != sighash(rendered pczt) — \
                 what-you-see-is-what-you-sign binding failed"
            ),
            SignerError::NoSession => write!(f, "no active session"),
            SignerError::NoShare => write!(f, "no sealed share (DKG incomplete)"),
            SignerError::ConnectRefused => write!(f, "member refused the connection"),
            SignerError::RosterRejected(e) => write!(f, "setup roster rejected: {e}"),
            SignerError::Cancelled => write!(f, "member cancelled on the device"),
            SignerError::TimedOut => write!(f, "member did not decide before the deadline"),
            SignerError::SetupAborted(e) => write!(f, "setup aborted: {e}"),
            SignerError::MessageRefused(e) => {
                write!(f, "setup message refused (setup and share kept): {e}")
            }
            SignerError::NotReady => write!(f, "vault not ready: certificates or backups missing"),
            SignerError::Other(e) => write!(f, "{e}"),
        }
    }
}
impl From<String> for SignerError {
    fn from(e: String) -> Self {
        SignerError::Other(e)
    }
}

pub const SETUP_VERSION: u64 = 2;

pub fn roster_code(fingerprint: &[u8; 32]) -> String {
    let hash = blake2b_simd::Params::new()
        .hash_length(16)
        .personal(b"Loki_roster_code")
        .hash(fingerprint);
    let value = u128::from_be_bytes(hash.as_bytes().try_into().expect("16 bytes"));
    let digits = format!("{:024}", value % 10u128.pow(24));
    digits
        .as_bytes()
        .chunks(4)
        .map(|group| std::str::from_utf8(group).expect("ASCII digits"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn kind_code(kind: DkgWireKind) -> u8 {
    match kind {
        DkgWireKind::Round1 => 1,
        DkgWireKind::Round2 => 2,
        DkgWireKind::Certificate => 3,
        DkgWireKind::BackupReceipt => 4,
    }
}

fn expected_kind(phase: DkgPhase) -> Option<DkgWireKind> {
    match phase {
        DkgPhase::Empty => None,
        DkgPhase::Round1 => Some(DkgWireKind::Round1),
        DkgPhase::Round2 => Some(DkgWireKind::Round2),
        DkgPhase::Certificate => Some(DkgWireKind::Certificate),
        DkgPhase::Certified => Some(DkgWireKind::BackupReceipt),
    }
}

const SETUP_MAGIC: &[u8; 8] = b"LOKISGS1";
const MAX_SETUP_WIRE: usize = 66 * 1024;

struct SetupCheckpoint {
    core: DkgState,
    outgoing: Vec<Vec<u8>>,
    pending: BTreeMap<(u8, u16), Vec<u8>>,
    backups: BTreeMap<u16, Vec<u8>>,
    aborted: bool,
}

impl SetupCheckpoint {
    fn new() -> Self {
        Self {
            core: DkgState::empty(),
            outgoing: Vec::new(),
            pending: BTreeMap::new(),
            backups: BTreeMap::new(),
            aborted: false,
        }
    }

    fn duplicate(&self) -> Self {
        Self {
            core: self.core.duplicate(),
            outgoing: self.outgoing.clone(),
            pending: self.pending.clone(),
            backups: self.backups.clone(),
            aborted: self.aborted,
        }
    }

    fn wipe(&mut self) {
        self.core.wipe();
        self.outgoing.clear();
        self.pending.clear();
        self.aborted = true;
    }

    fn encode(&self) -> Result<Zeroizing<Vec<u8>>, String> {
        fn field(out: &mut Vec<u8>, value: &[u8]) {
            out.extend_from_slice(&(value.len() as u32).to_be_bytes());
            out.extend_from_slice(value);
        }
        let mut out = Zeroizing::new(SETUP_MAGIC.to_vec());
        out.push(u8::from(self.aborted));
        field(&mut out, &self.core.encode()?);
        out.extend_from_slice(&(self.outgoing.len() as u16).to_be_bytes());
        for wire in &self.outgoing {
            field(&mut out, wire);
        }
        out.extend_from_slice(&(self.pending.len() as u16).to_be_bytes());
        for ((kind, sender), wire) in &self.pending {
            out.push(*kind);
            out.extend_from_slice(&sender.to_be_bytes());
            field(&mut out, wire);
        }
        crate::dkg_core::encode_map(&mut out, &self.backups)?;
        Ok(out)
    }

    fn decode(raw: &[u8]) -> Result<Self, String> {
        let mut reader = crate::dkg_core::Reader::new(raw);
        if reader.take(8)? != SETUP_MAGIC {
            return Err("invalid signer setup checkpoint".into());
        }
        let aborted = match reader.take(1)?[0] {
            0 => false,
            1 => true,
            _ => return Err("invalid signer setup checkpoint".into()),
        };
        let core = DkgState::decode(&Zeroizing::new(reader.field(1 << 20)?.to_vec()))?;
        let count = u16::from_be_bytes(reader.take(2)?.try_into().unwrap());
        let mut outgoing = Vec::new();
        for _ in 0..count {
            outgoing.push(reader.field(MAX_SETUP_WIRE)?.to_vec());
        }
        let count = u16::from_be_bytes(reader.take(2)?.try_into().unwrap());
        let mut pending = BTreeMap::new();
        for _ in 0..count {
            let kind = reader.take(1)?[0];
            let sender = u16::from_be_bytes(reader.take(2)?.try_into().unwrap());
            pending.insert((kind, sender), reader.field(MAX_SETUP_WIRE)?.to_vec());
        }
        let backups = reader.map()?;
        reader.finish()?;
        Ok(Self {
            core,
            outgoing,
            pending,
            backups,
            aborted,
        })
    }
}

pub fn encode_share(key_package: &[u8], public_package: &[u8], vs: &[u8; 32]) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::new());
    out.extend_from_slice(&(key_package.len() as u32).to_be_bytes());
    out.extend_from_slice(key_package);
    out.extend_from_slice(&(public_package.len() as u32).to_be_bytes());
    out.extend_from_slice(public_package);
    out.extend_from_slice(vs);
    out
}

#[allow(clippy::type_complexity)]
pub fn decode_share(raw: &[u8]) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>, [u8; 32]), String> {
    let mut reader = crate::dkg_core::Reader::new(raw);
    let key = Zeroizing::new(reader.field(64 * 1024)?.to_vec());
    let public = reader.field(64 * 1024)?.to_vec();
    let vs: [u8; 32] = reader.take(32)?.try_into().map_err(|_| "invalid share file")?;
    reader.finish()?;
    Ok((key, public, vs))
}

fn vault_network(network: crate::network::VaultNetwork) -> Network {
    match network {
        crate::network::VaultNetwork::Regtest => Network::Regtest,
        crate::network::VaultNetwork::Testnet => Network::Testnet,
    }
}

/// One member's signer for one vault: the sealed share, the public key package, the vault
/// viewing key (kept inside the signer to render and build payments), a secure element, a
/// crash-safe nonce store and the on-device prompts.
pub struct LocalSigner<SE: SecureElement> {
    member_id: u16,
    threshold: u16,
    members: u16,
    vault_id: [u8; 32],
    label: String,
    network: Network,
    se: SE,
    store: Option<SignerStore>,
    identity: Option<Identity>,
    roster: Option<(ValidatedRoster, Vec<u8>)>,
    setup: Option<SetupCheckpoint>,
    sealed_share: Option<SealedShare>,
    public_package: Option<Vec<u8>>,
    vault_fvk: Option<FullViewingKey>,
    nonces: NonceStore,
    approval: ApprovalPolicy,
    connect_approval: Option<ConnectApproval>,
    nonce_witness: Option<Box<dyn NonceWitness + Send>>,
    roster_confirmation: Option<RosterConfirmation>,
    roster_deadline: Duration,
    backup_device: Option<Box<dyn BackupDevice>>,
    session: Option<Session>,
    session_origin: Option<String>,
    rendered: BTreeMap<[u8; 32], PaymentView>,
    approved: Option<([u8; 32], [u8; 32])>,
    candidate_notes: Vec<orchard::Note>,
}

impl<SE: SecureElement> LocalSigner<SE> {
    #[allow(clippy::too_many_arguments)]
    fn bare(
        member_id: u16,
        threshold: u16,
        members: u16,
        vault_id: [u8; 32],
        label: String,
        network: Network,
        se: SE,
        nonces: NonceStore,
        approval: ApprovalPolicy,
    ) -> Self {
        Self {
            member_id,
            threshold,
            members,
            vault_id,
            label,
            network,
            se,
            store: None,
            identity: None,
            roster: None,
            setup: None,
            sealed_share: None,
            public_package: None,
            vault_fvk: None,
            nonces,
            approval,
            connect_approval: None,
            nonce_witness: None,
            roster_confirmation: None,
            roster_deadline: Duration::ZERO,
            backup_device: None,
            session: None,
            session_origin: None,
            rendered: BTreeMap::new(),
            approved: None,
            candidate_notes: Vec::new(),
        }
    }

    /// Construct a signer that already holds a sealed share (e.g. restored from backup, or
    /// — in tests — dealt by the dealer DKG). `nonce_dir` is this member's crash-safe
    /// nonce store directory.
    #[allow(clippy::too_many_arguments)]
    pub fn with_sealed_share(
        member_id: u16,
        threshold: u16,
        members: u16,
        vault_id: [u8; 32],
        label: String,
        network: Network,
        se: SE,
        key_package_bytes: &[u8],
        public_package_bytes: Vec<u8>,
        vault_fvk: FullViewingKey,
        nonce_dir: PathBuf,
        approval: ApprovalPolicy,
    ) -> Result<Self, SignerError> {
        let nonces = NonceStore::open(&nonce_dir, vault_id, member_id)
            .map_err(|e| SignerError::Other(e.to_string()))?;
        let sealed = SealedShare::seal(&se, 0, key_package_bytes).map_err(SignerError::Other)?;
        let mut signer = Self::bare(
            member_id, threshold, members, vault_id, label, network, se, nonces, approval,
        );
        signer.sealed_share = Some(sealed);
        signer.public_package = Some(public_package_bytes);
        signer.vault_fvk = Some(vault_fvk);
        Ok(signer)
    }

    pub fn from_vault_member(
        state: &crate::member_state::MemberState,
        se: SE,
        nonce_dir: PathBuf,
        approval: ApprovalPolicy,
    ) -> Result<Self, SignerError> {
        let mut signer = Self::with_sealed_share(
            state.identity.public().id,
            state.roster.threshold,
            state.roster.members.len() as u16,
            state.vault,
            format!("vault {}", hex::encode(&state.vault[..4])),
            vault_network(state.network),
            se,
            &Zeroizing::new(state.key.serialize().map_err(|e| SignerError::Other(e.to_string()))?),
            state.public.serialize().map_err(|e| SignerError::Other(e.to_string()))?,
            state.fvk.clone(),
            nonce_dir,
            approval,
        )?;
        let secret = Zeroizing::new(state.identity.to_secret_bytes());
        signer.identity = Some(Identity::from_secret_bytes(&secret[..]).map_err(SignerError::Other)?);
        Ok(signer)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn from_restored(
        member_id: u16,
        threshold: u16,
        members: u16,
        vault_id: [u8; 32],
        label: String,
        network: Network,
        se: SE,
        key_package_bytes: &[u8],
        public_package_bytes: Vec<u8>,
        vault_fvk: FullViewingKey,
        epoch: u64,
        nonces: NonceStore,
        approval: ApprovalPolicy,
        identity: Option<Identity>,
    ) -> Result<Self, SignerError> {
        let sealed = SealedShare::seal(&se, epoch, key_package_bytes).map_err(SignerError::Other)?;
        let mut signer = Self::bare(
            member_id, threshold, members, vault_id, label, network, se, nonces, approval,
        );
        signer.sealed_share = Some(sealed);
        signer.public_package = Some(public_package_bytes);
        signer.vault_fvk = Some(vault_fvk);
        signer.identity = identity;
        Ok(signer)
    }

    pub fn create(
        dir: &Path,
        se: SE,
        network: Network,
        vault_id: [u8; 32],
        member_id: u16,
        label: String,
        prompts: DevicePrompts,
    ) -> Result<Self, SignerError> {
        Self::create_with_identity(dir, se, network, vault_id, member_id, label, prompts, Identity::new(member_id))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn create_with_identity(
        dir: &Path,
        se: SE,
        network: Network,
        vault_id: [u8; 32],
        member_id: u16,
        label: String,
        prompts: DevicePrompts,
        identity: Identity,
    ) -> Result<Self, SignerError> {
        if vault_id == [0; 32] || !(1..=crate::member_state::MAX_MEMBERS).contains(&member_id) {
            return Err(SignerError::Other("invalid vault id or member number".into()));
        }
        if identity.public().id != member_id {
            return Err(SignerError::Other("signer identity is for another member".into()));
        }
        let store = SignerStore::create(dir, network, vault_id, member_id)?;
        store.write(
            &se,
            FileKind::Identity,
            0,
            &Zeroizing::new(identity.to_secret_bytes())[..],
        )?;
        let nonces = NonceStore::open(&store.nonce_dir(), vault_id, member_id)
            .map_err(|e| SignerError::Other(e.to_string()))?;
        let mut signer = Self::bare(
            member_id, 0, 0, vault_id, label, network, se, nonces, prompts.approval,
        );
        signer.identity = Some(identity);
        signer.store = Some(store);
        signer.connect_approval = Some(prompts.connect);
        signer.roster_confirmation = Some(prompts.roster);
        signer.roster_deadline = prompts.roster_deadline;
        signer.backup_device = Some(prompts.backup);
        Ok(signer)
    }

    pub fn open(dir: &Path, se: SE, label: String, prompts: DevicePrompts) -> Result<Self, SignerError> {
        let store = SignerStore::open(dir)?;
        let (_, raw) = store
            .read(&se, FileKind::Identity)?
            .ok_or_else(|| SignerError::Other("signer has no identity".into()))?;
        let identity = Identity::from_secret_bytes(&raw).map_err(SignerError::Other)?;
        if identity.public().id != store.member() {
            return Err(SignerError::Other("signer identity is for another member".into()));
        }
        let nonces = NonceStore::open(&store.nonce_dir(), store.vault(), store.member())
            .map_err(|e| SignerError::Other(e.to_string()))?;
        let mut signer = Self::bare(
            store.member(),
            0,
            0,
            store.vault(),
            label,
            store.network(),
            se,
            nonces,
            prompts.approval,
        );
        signer.identity = Some(identity);
        signer.connect_approval = Some(prompts.connect);
        signer.roster_confirmation = Some(prompts.roster);
        signer.roster_deadline = prompts.roster_deadline;
        signer.backup_device = Some(prompts.backup);
        if let Some((_, document)) = store.read(&signer.se, FileKind::Roster)? {
            let roster = signer.check_roster(&document)?;
            signer.threshold = roster.threshold;
            signer.members = roster.member_count();
            signer.roster = Some((roster, document.to_vec()));
        }
        let setup = match store.read(&signer.se, FileKind::Setup)? {
            Some((_, raw)) => Some(SetupCheckpoint::decode(&raw)?),
            None => None,
        };
        let share = store.read(&signer.se, FileKind::Share)?;
        signer.store = Some(store);
        let mut installed = None;
        let setup = match (&signer.roster, setup) {
            (Some(_), None) if share.is_none() => {
                let setup = SetupCheckpoint::new();
                signer.save_setup(&setup)?;
                Some(setup)
            }
            (_, setup) => setup,
        };
        match (&signer.roster, &setup) {
            (None, None) if share.is_none() => {}
            (Some((roster, _)), Some(setup)) => {
                let identity = signer.identity.as_ref().expect("set above");
                let core = DkgCore::new(roster, identity).map_err(SignerError::Other)?;
                if !setup.aborted {
                    core.validate(&setup.core).map_err(SignerError::Other)?;
                }
                let certified = (setup.core.phase() as u8) >= DkgPhase::Certificate as u8;
                match (&share, certified && !setup.aborted) {
                    (Some((epoch, raw)), true) => {
                        let (key, public, vs) = decode_share(raw)?;
                        installed =
                            Some(signer.checked_share(&core, &setup.core, &key, public, &vs, *epoch)?);
                    }
                    (None, false) => {}
                    (None, true) => {
                        installed = Some(
                            signer
                                .restore_share(&core, &setup.core)
                                .map_err(SignerError::Other)?,
                        );
                    }
                    _ => {
                        return Err(SignerError::Other(
                            "signer files are inconsistent (rolled back?)".into(),
                        ))
                    }
                }
            }
            _ => {
                return Err(SignerError::Other(
                    "signer files are inconsistent (rolled back?)".into(),
                ))
            }
        }
        if let Some(share) = installed {
            signer.install(share);
        }
        signer.setup = setup;
        Ok(signer)
    }

    pub fn public_package_bytes(&self) -> Option<&[u8]> {
        self.public_package.as_deref()
    }

    pub fn hosted_metadata(&self) -> Result<(frost::keys::PublicKeyPackage, FullViewingKey), SignerError> {
        self.require_ready()?;
        let public = frost::keys::PublicKeyPackage::deserialize(
            self.public_package.as_deref().ok_or(SignerError::NoShare)?,
        )
        .map_err(|e| SignerError::Other(e.to_string()))?;
        Ok((public, self.fvk()?.clone()))
    }

    pub fn open_hosted_signing(
        &self,
        sender: &PublicIdentity,
        context: &SessionContext,
        wire: &[u8],
    ) -> Result<crate::signing_session::OpenedMessage, SignerError> {
        let identity = self.identity.as_ref().ok_or(SignerError::NotReady)?;
        if context.vault != self.vault_id || (sender.id != 0 && self.confirmed_roster()
            .and_then(|r| r.members.get(&sender.id)) != Some(sender)) {
            return Err(SignerError::Other("signing sender or vault differs from the roster".into()));
        }
        identity.open_session(sender, context, wire).map_err(SignerError::Other)
    }

    pub fn seal_hosted_signing(
        &self,
        coordinator: &PublicIdentity,
        context: &SessionContext,
        kind: MessageKind,
        body: &[u8],
    ) -> Result<Vec<u8>, SignerError> {
        let identity = self.identity.as_ref().ok_or(SignerError::NotReady)?;
        if coordinator.id != 0 || context.vault != self.vault_id
            || !matches!(kind, MessageKind::HostedCommitment | MessageKind::HostedShare)
            || !kind.valid_hosted_body(context, body)
        {
            return Err(SignerError::Other("invalid signing message for coordinator".into()));
        }
        identity.seal_session(coordinator, context, kind, body).map_err(SignerError::Other)
    }

    pub fn confirmed_roster(&self) -> Option<&Roster> {
        self.roster.as_ref().map(|(roster, _)| roster.roster())
    }

    pub fn adopt_restored_roster(&mut self, document: &[u8], connect: ConnectApproval) -> Result<(), SignerError> {
        if self.store.is_some() || self.roster.is_some() || self.setup.is_some() {
            return Err(SignerError::Other("only a restored signer adopts its backup roster".into()));
        }
        let roster = self.check_roster(document)?;
        if roster.threshold != self.threshold || roster.member_count() != self.members {
            return Err(SignerError::RosterRejected("roster differs from the restored vault".into()));
        }
        self.roster = Some((roster, document.to_vec()));
        self.connect_approval = Some(connect);
        Ok(())
    }

    pub fn network(&self) -> Network {
        self.network
    }

    pub fn open_control(
        &self,
        session: uuid::Uuid,
        sender_relay: &[u8; 32],
        wire: &[u8],
    ) -> Result<(u16, Vec<u8>), SignerError> {
        let identity = self.identity.as_ref().ok_or(SignerError::NotReady)?;
        let me = identity.public().id;
        let sender = self
            .confirmed_roster()
            .ok_or(SignerError::NotReady)?
            .members
            .values()
            .find(|m| &m.encryption == sender_relay && m.id != me)
            .ok_or_else(|| SignerError::Other("control message from a non-member".into()))?;
        let context = SessionContext::control(self.vault_id, session, me, sender.id);
        let opened = identity
            .open_session(sender, &context, wire)
            .map_err(SignerError::Other)?;
        if opened.kind() != MessageKind::PeerReply {
            return Err(SignerError::Other("not a control message".into()));
        }
        Ok((sender.id, opened.body().to_vec()))
    }

    pub fn seal_control(
        &self,
        session: uuid::Uuid,
        recipient: u16,
        body: &[u8],
    ) -> Result<Vec<u8>, SignerError> {
        let identity = self.identity.as_ref().ok_or(SignerError::NotReady)?;
        let peer = self
            .confirmed_roster()
            .ok_or(SignerError::NotReady)?
            .members
            .get(&recipient)
            .ok_or_else(|| SignerError::Other("recipient is not a vault member".into()))?;
        let context = SessionContext::control(self.vault_id, session, identity.public().id, recipient);
        identity
            .seal_session(peer, &context, MessageKind::PeerReply, body)
            .map_err(SignerError::Other)
    }

    pub fn abandon_setup(&mut self) -> Result<(), SignerError> {
        let mut setup = self
            .setup
            .take()
            .ok_or_else(|| SignerError::Other("no setup in progress".into()))?;
        if (setup.core.phase() as u8) >= DkgPhase::Certificate as u8 && !setup.aborted {
            self.setup = Some(setup);
            return Err(SignerError::Other("the vault share already exists".into()));
        }
        setup.wipe();
        let saved = self.save_setup(&setup);
        self.setup = Some(setup);
        saved
    }

    pub fn set_nonce_witness(&mut self, witness: Box<dyn NonceWitness + Send>) {
        self.nonce_witness = Some(witness);
    }

    pub fn nonce_claim_pins(
        &self,
        cand: &CandidateRef,
        commitment: &frost::round1::SigningCommitments,
    ) -> Result<crate::signing_session::WitnessPins, SignerError> {
        let pins = self.nonce_witness.as_ref().ok_or_else(||
            SignerError::Other("two nonce witnesses required".into()))?.pins();
        let pending = self.nonces.pending_commitment(&self.nonce_id(cand), &self.se, pins)
            .map_err(|e| SignerError::Other(e.to_string()))?;
        if pending != *commitment {
            return Err(SignerError::Other("own commitment differs from the pending nonce".into()));
        }
        Ok(pins)
    }

    pub fn nonce_claim_proof(
        &self,
        (key, run, mailbox): ([u8; 32], [u8; 32], [u8; 32]),
        cid: [u8; 32],
        challenge: [u8; 32],
        record: &[u8],
    ) -> Result<loki_relay_protocol::nonce::ClaimProof, SignerError> {
        let identity = self.identity.as_ref().ok_or(SignerError::NotReady)?;
        let pin = loki_relay_protocol::types::RelayPin { key, run };
        Ok(identity.nonce_claim_proof(self.vault_id, &pin, mailbox, cid, challenge, record))
    }

    pub fn set_approval_policy(&mut self, approval: ApprovalPolicy) {
        self.approval = approval;
        self.approved = None;
    }

    pub fn set_candidate_notes(&mut self, notes: Vec<orchard::Note>) {
        self.candidate_notes = notes;
    }

    fn build_pczt<P: zcash_protocol::consensus::Parameters + Clone>(
        &self,
        params_net: &P,
        params: &crate::signer::PublicPaymentParams,
        alphas: &[[u8; 32]],
    ) -> Result<Vec<u8>, SignerError> {
        if self.candidate_notes.is_empty() {
            return Err(SignerError::Other("signer holds no spendable note".into()));
        }
        if self.candidate_notes.len() != alphas.len() {
            return Err(SignerError::Other("the coordinator sent a randomiser count that differs from the payment's notes".into()));
        }
        crate::builder::build_unsigned(self.fvk()?, params_net, params, &self.candidate_notes, alphas)
            .map_err(SignerError::Other)
    }

    fn fvk(&self) -> Result<&FullViewingKey, SignerError> {
        self.vault_fvk.as_ref().ok_or(SignerError::NoShare)
    }

    /// Unseal the member's `KeyPackage` into memory (with the Apple element, one Secure
    /// Enclave unwrap). The unwrapped bytes are a `Zeroizing` buffer wiped when this returns;
    /// the returned `KeyPackage` wipes its signing share on drop (`ZeroizeOnDrop`), so
    /// callers drop it as soon as its one use is done. It is never stored on the signer.
    fn open_key(&self) -> Result<frost::keys::KeyPackage, SignerError> {
        let sealed = self.sealed_share.as_ref().ok_or(SignerError::NoShare)?;
        let plain = sealed.open(&self.se).map_err(SignerError::Other)?;
        let key = frost::keys::KeyPackage::deserialize(&plain)
            .map_err(|e| SignerError::Other(format!("key package: {e}")));
        drop(plain);
        key
    }

    fn nonce_id(&self, cand: &CandidateRef) -> String {
        // One nonce per (payment, attempt). Hex so it is a safe filename.
        let mut s = String::with_capacity(64);
        for b in cand.payment_id.iter().chain(cand.attempt_id.iter()) {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }

    fn check_session(&self, session: &Session) -> Result<(), SignerError> {
        if self.session.as_ref() != Some(session) {
            return Err(SignerError::NoSession);
        }
        Ok(())
    }

    fn is_ready(&self) -> bool {
        match (&self.setup, &self.roster) {
            (None, _) => self.sealed_share.is_some(),
            (Some(setup), Some((roster, _))) => {
                !setup.aborted
                    && setup.core.phase() == DkgPhase::Certified
                    && setup.backups.len() == roster.members.len()
            }
            (Some(_), None) => false,
        }
    }

    fn require_ready(&self) -> Result<(), SignerError> {
        if self.is_ready() {
            Ok(())
        } else {
            Err(SignerError::NotReady)
        }
    }

    fn check_roster(&self, document: &[u8]) -> Result<ValidatedRoster, SignerError> {
        let reject = |e: &str| SignerError::RosterRejected(e.to_string());
        let value: serde_json::Value =
            serde_json::from_slice(document).map_err(|_| reject("roster is not JSON"))?;
        if value.get("setup_version").and_then(serde_json::Value::as_u64) != Some(SETUP_VERSION) {
            return Err(reject("roster setup_version must be 2"));
        }
        let roster = Roster::from_bytes(document).map_err(|e| reject(&e))?;
        let roster = ValidatedRoster::new(roster).map_err(|e| reject(&e.to_string()))?;
        let identity = self
            .identity
            .as_ref()
            .ok_or_else(|| reject("signer has no setup identity"))?;
        if vault_network(roster.network) != self.network {
            return Err(reject("roster is for another network"));
        }
        if roster.vault != self.vault_id {
            return Err(reject("roster is for another vault"));
        }
        if roster.members.get(&self.member_id) != Some(&identity.public()) {
            return Err(reject("roster does not hold this signer's identity"));
        }
        Ok(roster)
    }

    fn save_setup(&self, setup: &SetupCheckpoint) -> Result<(), SignerError> {
        let store = self
            .store
            .as_ref()
            .ok_or_else(|| SignerError::Other("signer has no data directory".into()))?;
        store
            .write(&self.se, FileKind::Setup, 0, &setup.encode()?)
            .map_err(SignerError::Other)
    }

    fn install(&mut self, share: InstalledShare) {
        self.sealed_share = Some(share.sealed);
        self.public_package = Some(share.public_package);
        self.vault_fvk = Some(share.fvk);
    }

    #[allow(clippy::too_many_arguments)]
    fn checked_share(
        &self,
        core: &DkgCore<'_>,
        state: &DkgState,
        key_package: &[u8],
        public_package: Vec<u8>,
        vs: &[u8; 32],
        epoch: u64,
    ) -> Result<InstalledShare, SignerError> {
        let key = frost::keys::KeyPackage::deserialize(key_package)
            .map_err(|e| SignerError::Other(format!("key package: {e}")))?;
        let public = frost::keys::PublicKeyPackage::deserialize(&public_package)
            .map_err(|e| SignerError::Other(format!("public package: {e}")))?;
        let body = core.certificate_body(state).map_err(SignerError::Other)?;
        let completed_public = state_public_package(state)?;
        if public_package != completed_public
            || key.verifying_key() != public.verifying_key()
            || vs != state.vault_secret()
            || body.is_empty()
        {
            return Err(SignerError::Other("signer share does not match its setup".into()));
        }
        let ak: [u8; 32] = public
            .verifying_key()
            .serialize()
            .map_err(|e| SignerError::Other(e.to_string()))?
            .try_into()
            .map_err(|_| SignerError::Other("group key is not 32 bytes".into()))?;
        Ok(InstalledShare {
            fvk: zip2005::frost_viewing_key(&ak, vs)
                .map_err(|e| SignerError::Other(format!("ZIP 2005 derivation: {e:?}")))?,
            sealed: SealedShare::seal(&self.se, epoch, key_package).map_err(SignerError::Other)?,
            public_package,
        })
    }

    fn advance_setup(
        &mut self,
        setup: &mut SetupCheckpoint,
        inputs: &[DkgInput],
    ) -> Result<(), StepError> {
        let mut share = None;
        let outcome = self.progress_setup(setup, inputs, &mut share);
        if let Some(share) = share {
            self.install(share);
        }
        outcome
    }

    fn progress_setup(
        &self,
        setup: &mut SetupCheckpoint,
        inputs: &[DkgInput],
        share: &mut Option<InstalledShare>,
    ) -> Result<(), StepError> {
        let fail = |state: &SetupCheckpoint, error: String| {
            if holds_share(state) {
                StepError::Kept(error)
            } else {
                StepError::Abort(error)
            }
        };
        let (roster, _) = self
            .roster
            .as_ref()
            .ok_or_else(|| fail(setup, "no confirmed roster".into()))?;
        let identity = self
            .identity
            .as_ref()
            .ok_or_else(|| fail(setup, "no setup identity".into()))?;
        let core = DkgCore::new(roster, identity).map_err(|e| fail(setup, e))?;
        let own = self.member_id;
        if holds_share(setup) && self.sealed_share.is_none() {
            *share = Some(self.restore_share(&core, &setup.core).map_err(|e| fail(setup, e))?);
        }
        if setup.core.phase() == DkgPhase::Empty {
            let (state, outgoing) = core.start().map_err(|e| fail(setup, e))?;
            let mut next = setup.duplicate();
            next.core = state;
            next.outgoing = released(&outgoing, own);
            self.save_setup(&next).map_err(|e| fail(setup, e.to_string()))?;
            *setup = next;
        }
        let mut next = setup.duplicate();
        let mut refused = Vec::new();
        for input in inputs {
            if let Err(error) = accept_input(roster, identity, own, &mut next, input) {
                if !holds_share(&next) {
                    return Err(StepError::Abort(error));
                }
                refused.push(error);
            }
        }
        let peers: Vec<u16> = roster.members.keys().copied().filter(|id| *id != own).collect();
        loop {
            let Some(kind) = expected_kind(next.core.phase()) else {
                break;
            };
            if kind == DkgWireKind::BackupReceipt {
                let expected = core.backup_body(&next.core).map_err(|e| fail(&next, e))?;
                let receipts: Vec<(u16, Vec<u8>)> = next
                    .pending
                    .iter()
                    .filter(|((k, _), _)| *k == kind_code(kind))
                    .map(|((_, sender), wire)| (*sender, wire.clone()))
                    .collect();
                for (sender, wire) in receipts {
                    next.pending.remove(&(kind_code(kind), sender));
                    match identity.verify_backup(&roster.members[&sender], &roster.vault, &wire) {
                        Ok(body) if body.as_slice() == expected => {
                            next.backups.insert(sender, wire);
                        }
                        _ => refused.push(format!(
                            "member {sender}'s backup receipt is for a different vault"
                        )),
                    }
                }
                break;
            }
            let records: BTreeMap<u16, Vec<u8>> = peers
                .iter()
                .filter_map(|id| {
                    next.pending
                        .get(&(kind_code(kind), *id))
                        .map(|wire| (*id, wire.clone()))
                })
                .collect();
            if records.len() != peers.len() {
                break;
            }
            let (state, outgoing) = match core.advance(&next.core, &records) {
                Ok(advanced) => advanced,
                Err(error) if holds_share(&next) => {
                    refused.push(error);
                    break;
                }
                Err(error) => return Err(StepError::Abort(error)),
            };
            for id in &peers {
                next.pending.remove(&(kind_code(kind), *id));
            }
            next.core = state;
            for wire in released(&outgoing, own) {
                if !next.outgoing.contains(&wire) {
                    next.outgoing.push(wire);
                }
            }
            self.save_setup(&next).map_err(|e| fail(setup, e.to_string()))?;
            *setup = next.duplicate();
            if next.core.phase() == DkgPhase::Certificate {
                *share = Some(self.restore_share(&core, &next.core).map_err(|e| fail(&next, e))?);
            }
        }
        self.save_setup(&next).map_err(|e| fail(setup, e.to_string()))?;
        *setup = next;
        if refused.is_empty() {
            Ok(())
        } else {
            Err(StepError::Kept(refused.join("; ")))
        }
    }

    fn restore_share(&self, core: &DkgCore<'_>, state: &DkgState) -> Result<InstalledShare, String> {
        let completed =
            crate::distributed_setup::Completed::restore_checkpoint(&state.completed_checkpoint()?)?;
        let key_package = Zeroizing::new(completed.key_package_bytes().to_vec());
        let public = completed.public_package().to_vec();
        let store = self.store.as_ref().ok_or("no data directory")?;
        store.write(
            &self.se,
            FileKind::Share,
            0,
            &encode_share(&key_package, &public, state.vault_secret()),
        )?;
        self.checked_share(core, state, &key_package, public, state.vault_secret(), 0)
            .map_err(|e| e.to_string())
    }
}

enum StepError {
    Abort(String),
    Kept(String),
}

fn holds_share(setup: &SetupCheckpoint) -> bool {
    !setup.aborted && (setup.core.phase() as u8) >= DkgPhase::Certificate as u8
}

fn accept_input(
    roster: &ValidatedRoster,
    identity: &Identity,
    own: u16,
    next: &mut SetupCheckpoint,
    input: &DkgInput,
) -> Result<(), String> {
    let vault = roster.vault;
    let wire = DkgWire::parse(input.bytes.clone())?;
    if wire.sender() != input.sender || !roster.members.contains_key(&wire.sender()) {
        return Err("setup message sender does not match its tag".into());
    }
    if wire.sender() == own {
        if !next.outgoing.contains(&input.bytes) {
            return Err("a setup message claims to be ours but is not".into());
        }
        return Ok(());
    }
    if wire.kind() == DkgWireKind::Round2 && wire.recipient() != Some(own) {
        return Err("round-two envelope addressed to another member".into());
    }
    let peer = &roster.members[&wire.sender()];
    let past = match wire.kind() {
        DkgWireKind::Round1 => next.core.round1().get(&wire.sender()),
        DkgWireKind::Round2 => next.core.round2().get(&wire.sender()),
        DkgWireKind::Certificate => next.core.certificates().get(&wire.sender()),
        DkgWireKind::BackupReceipt => next.backups.get(&wire.sender()),
    };
    if let Some(saved) = past {
        if saved != &input.bytes {
            return Err("a member sent two different messages for one phase".into());
        }
        return Ok(());
    }
    match wire.kind() {
        DkgWireKind::Round1 => {
            identity.verify_round1(peer, &vault, &input.bytes)?;
        }
        DkgWireKind::Certificate => {
            identity.verify_certificate(peer, &vault, &input.bytes)?;
        }
        DkgWireKind::BackupReceipt => {
            identity.verify_backup(peer, &vault, &input.bytes)?;
        }
        DkgWireKind::Round2 => {}
    }
    let key = (kind_code(wire.kind()), wire.sender());
    match next.pending.get(&key) {
        Some(saved) if saved != &input.bytes => {
            Err("a member sent two different messages for one phase".into())
        }
        _ => {
            next.pending.insert(key, input.bytes.clone());
            Ok(())
        }
    }
}

struct InstalledShare {
    sealed: SealedShare,
    public_package: Vec<u8>,
    fvk: FullViewingKey,
}

fn released(outgoing: &crate::dkg_core::Outgoing, own: u16) -> Vec<Vec<u8>> {
    let mut wires: Vec<Vec<u8>> = Vec::new();
    for (recipient, wire) in outgoing {
        if *recipient != own && !wires.contains(wire) {
            wires.push(wire.clone());
        }
    }
    wires
}

fn state_public_package(state: &DkgState) -> Result<Vec<u8>, SignerError> {
    let completed = crate::distributed_setup::Completed::restore_checkpoint(
        &state.completed_checkpoint().map_err(SignerError::Other)?,
    )
    .map_err(SignerError::Other)?;
    Ok(completed.public_package().to_vec())
}

impl<SE: SecureElement> Signer for LocalSigner<SE> {
    type Error = SignerError;

    fn connect(
        &mut self,
        origin: &str,
        network: Network,
        challenge: &[u8],
    ) -> Result<Connection, Self::Error> {
        if network != self.network {
            return Err(SignerError::Other(format!(
                "connect network {:?} does not match signer network {:?}",
                network, self.network
            )));
        }
        let approved = match self.connect_approval.as_mut() {
            Some(approve) => {
                if !approve(origin, network) {
                    return Err(SignerError::ConnectRefused);
                }
                true
            }
            None => false,
        };
        let mut sid = [0u8; 32];
        let h = blake3::hash(challenge);
        sid.copy_from_slice(h.as_bytes());
        let session = Session(sid);
        self.session = Some(session.clone());
        self.session_origin = approved.then(|| origin.to_owned());
        let (signing, encryption) = match &self.identity {
            Some(identity) => {
                let public = identity.public();
                (public.signing, public.encryption)
            }
            None => ([0u8; 32], [0u8; 32]),
        };
        Ok(Connection {
            session,
            member: MemberIdentity {
                id: self.member_id,
                signing,
                encryption,
            },
        })
    }

    fn list_vaults(&self, session: &Session) -> Result<Vec<VaultRef>, Self::Error> {
        self.check_session(session)?;
        if self.store.is_some() && self.roster.is_none() {
            return Ok(vec![]);
        }
        Ok(vec![VaultRef {
            vault_id: self.vault_id,
            label: self.label.clone(),
            threshold: self.threshold,
            members: self.members,
            ready: self.is_ready(),
        }])
    }

    fn dkg_begin(&mut self, session: &Session, roster: &[u8]) -> Result<VaultRef, Self::Error> {
        self.check_session(session)?;
        if self.store.is_none() || self.identity.is_none() {
            return Err(SignerError::Other("signer has no setup identity".into()));
        }
        if self.roster.is_some() || self.setup.is_some() {
            return Err(SignerError::Other("this signer's setup has already begun".into()));
        }
        let validated = self.check_roster(roster)?;
        let code = roster_code(&validated.fingerprint());
        let confirm = self
            .roster_confirmation
            .as_mut()
            .ok_or_else(|| SignerError::Other("signer has no roster prompt".into()))?;
        let started = Instant::now();
        let decision = confirm(&code);
        if started.elapsed() > self.roster_deadline {
            return Err(SignerError::TimedOut);
        }
        match decision {
            RosterDecision::Match => {}
            RosterDecision::NoMatch => {
                return Err(SignerError::RosterRejected(
                    "the member's code did not match".into(),
                ))
            }
            RosterDecision::Cancelled => return Err(SignerError::Cancelled),
        }
        let store = self.store.as_ref().expect("checked above");
        store
            .write(&self.se, FileKind::Roster, 0, roster)
            .map_err(SignerError::Other)?;
        let setup = SetupCheckpoint::new();
        self.threshold = validated.threshold;
        self.members = validated.member_count();
        self.roster = Some((validated, roster.to_vec()));
        self.save_setup(&setup)?;
        self.setup = Some(setup);
        Ok(VaultRef {
            vault_id: self.vault_id,
            label: self.label.clone(),
            threshold: self.threshold,
            members: self.members,
            ready: false,
        })
    }

    fn dkg_step(
        &mut self,
        session: &Session,
        vault: &VaultRef,
        in_msgs: &[DkgInput],
    ) -> Result<Vec<DkgWire>, Self::Error> {
        self.check_session(session)?;
        if vault.vault_id != self.vault_id
            || vault.threshold != self.threshold
            || vault.members != self.members
        {
            return Err(SignerError::Other("DKG vault differs from this signer".into()));
        }
        let mut setup = self
            .setup
            .take()
            .ok_or_else(|| SignerError::Other("no confirmed setup roster (dkg_begin)".into()))?;
        if setup.aborted {
            self.setup = Some(setup);
            return Err(SignerError::SetupAborted("an earlier mismatch ended this setup".into()));
        }
        match self.advance_setup(&mut setup, in_msgs) {
            Ok(()) => {}
            Err(StepError::Abort(error)) => {
                setup.wipe();
                let _ = self.save_setup(&setup);
                self.setup = Some(setup);
                return Err(SignerError::SetupAborted(error));
            }
            Err(StepError::Kept(error)) => {
                self.setup = Some(setup);
                return Err(SignerError::MessageRefused(error));
            }
        }
        let wires = setup
            .outgoing
            .iter()
            .map(|bytes| DkgWire::parse(bytes.clone()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(SignerError::Other);
        self.setup = Some(setup);
        wires
    }

    fn backup(&mut self, session: &Session) -> Result<Vec<DkgWire>, Self::Error> {
        self.check_session(session)?;
        let (roster, document) = self.roster.as_ref().ok_or(SignerError::NotReady)?;
        let setup = self.setup.as_ref().ok_or(SignerError::NotReady)?;
        if setup.aborted || setup.core.phase() != DkgPhase::Certified {
            return Err(SignerError::NotReady);
        }
        if let Some(receipt) = setup.backups.get(&self.member_id) {
            return Ok(vec![DkgWire::parse(receipt.clone()).map_err(SignerError::Other)?]);
        }
        let identity = self.identity.as_ref().ok_or(SignerError::NotReady)?;
        let core = DkgCore::new(roster, identity).map_err(SignerError::Other)?;
        let key_package = Zeroizing::new(
            self.open_key()?
                .serialize()
                .map_err(|e| SignerError::Other(e.to_string()))?,
        );
        let material = BackupMaterial {
            member_id: self.member_id,
            threshold: self.threshold,
            members: self.members,
            network: self.network,
            vault_id: self.vault_id,
            label: self.label.clone(),
            group_sk: *setup.core.vault_secret(),
            key_package: key_package.clone(),
            public_package: self.public_package.clone().ok_or(SignerError::NoShare)?,
            backup_epoch: 0,
            identity: Zeroizing::new(identity.to_secret_bytes().to_vec()),
            roster: document.clone(),
            roster_fingerprint: roster.fingerprint(),
            birth_height: roster.birth_height,
        };
        let device = self
            .backup_device
            .as_mut()
            .ok_or_else(|| SignerError::Other("signer has no backup device".into()))?;
        let passphrase = device.passphrase().ok_or(SignerError::Cancelled)?;
        let artifact = backup::create(&material, &passphrase).map_err(SignerError::Other)?;
        device.save(&artifact).map_err(SignerError::Other)?;
        let reloaded = device.load().map_err(SignerError::Other)?;
        let again = device.passphrase().ok_or(SignerError::Cancelled)?;
        let back = backup::verify(&reloaded, &again, &self.vault_id).map_err(SignerError::Other)?;
        if *back.key_package != *key_package
            || back.group_sk != material.group_sk
            || *back.identity != *material.identity
            || back.roster_fingerprint != material.roster_fingerprint
            || back.member_id != self.member_id
        {
            return Err(SignerError::Other("the stored backup does not reload this vault".into()));
        }
        let body = core.backup_body(&setup.core).map_err(SignerError::Other)?;
        let receipt = identity
            .sign_backup(&self.vault_id, &body)
            .map_err(SignerError::Other)?;
        let mut next = setup.duplicate();
        next.backups.insert(self.member_id, receipt.clone());
        next.outgoing.push(receipt.clone());
        self.save_setup(&next)?;
        self.setup = Some(next);
        Ok(vec![DkgWire::parse(receipt).map_err(SignerError::Other)?])
    }

    fn release_address(&mut self, session: &Session) -> Result<ReleasedAddress, Self::Error> {
        self.check_session(session)?;
        if self.session_origin.is_none() {
            return Err(SignerError::ConnectRefused);
        }
        self.require_ready()?;
        let (roster, _) = self.roster.as_ref().ok_or(SignerError::NotReady)?;
        let identity = self.identity.as_ref().ok_or(SignerError::NotReady)?;
        let address = match self.setup.as_ref() {
            Some(setup) => DkgCore::new(roster, identity)
                .and_then(|core| core.address(&setup.core))
                .map_err(SignerError::Other)?,
            None => crate::vault::unified_address(
                self.vault_fvk.as_ref().ok_or(SignerError::NotReady)?,
                zcash_protocol::consensus::Parameters::network_type(&roster.roster().network),
            ),
        };
        Ok(ReleasedAddress {
            vault_id: self.vault_id,
            address,
        })
    }

    fn build_candidate(
        &self,
        session: &Session,
        _cand: &CandidateRef,
        params: &crate::signer::PublicPaymentParams,
        alphas: &[[u8; 32]],
    ) -> Result<CandidatePczt, Self::Error> {
        self.check_session(session)?;
        self.require_ready()?;
        match self.network {
            Network::Regtest => self.build_pczt(&crate::candidate::Regtest, params, alphas),
            Network::Testnet => {
                self.build_pczt(&zcash_protocol::consensus::TEST_NETWORK, params, alphas)
            }
        }
        .map(CandidatePczt)
    }

    fn sign_commit(
        &mut self,
        session: &Session,
        cand: &CandidateRef,
    ) -> Result<frost::round1::SigningCommitments, Self::Error> {
        if self.session.as_ref() != Some(session) {
            return Err(SignerError::NoSession);
        }
        self.require_ready()?;
        let id = self.nonce_id(cand);
        let kp = self.open_key()?;
        let pins = self.nonce_witness.as_ref().map(|witness| witness.pins());
        let commitment = self.nonces.commit(&id, &self.se, kp.signing_share(), pins);
        drop(kp);
        commitment.map_err(|e| SignerError::Other(e.to_string()))
    }

    fn sign_approve(
        &mut self,
        session: &Session,
        cand: &CandidateRef,
        params: &crate::signer::PublicPaymentParams,
        pczt: &[u8],
        pkg: &frost::SigningPackage,
        randomizer: &[u8],
    ) -> Result<frost::round2::SignatureShare, Self::Error> {
        if self.session.as_ref() != Some(session) {
            return Err(SignerError::NoSession);
        }

        self.require_ready()?;
        let view = wysiwys::describe_pczt(pczt, self.fvk()?).map_err(SignerError::Other)?;
        let height = zcash_protocol::consensus::BlockHeight::from_u32(params.target_height);
        let branch = match self.network {
            Network::Regtest => {
                zcash_protocol::consensus::BranchId::for_height(&crate::candidate::Regtest, height)
            }
            Network::Testnet => zcash_protocol::consensus::BranchId::for_height(
                &zcash_protocol::consensus::TEST_NETWORK,
                height,
            ),
        };
        if view.to != params.recipient.to_raw_address_bytes()
            || view.amount_zat != u64::from(params.amount)
            || view.memo.as_slice() != params.memo.as_array().as_slice()
            || view.expiry_height != params.expiry_height
            || view.network_branch_id != u32::from(branch)
        {
            return Err(SignerError::Other(
                "candidate payment differs from requested payment".into(),
            ));
        }
        if !view.fee_verified {
            return Err(SignerError::FeeUnverified("candidate fee is unverified".into()));
        }
        let parsed = pczt::Pczt::parse(pczt)
            .map_err(|e| SignerError::Other(format!("pczt parse: {e:?}")))?;
        let actions = parsed.ironwood().actions().len();
        use zcash_primitives::transaction::fees::zip317::{GRACE_ACTIONS, MARGINAL_FEE};
        let zip317_fee = u64::try_from(actions.max(GRACE_ACTIONS))
            .ok()
            .and_then(|count| u64::from(MARGINAL_FEE).checked_mul(count))
            .ok_or_else(|| SignerError::Other("candidate action count is too large".into()))?;
        if view.fee_zat != zip317_fee {
            return Err(SignerError::Other(
                "candidate fee differs from ZIP-317 fee".into(),
            ));
        }
        self.rendered.insert(cand.attempt_id, view.clone());

        let local_sighash = wysiwys::checked_sighash_of_pczt(pczt, self.fvk()?)?;

        let decided = self.approved == Some((cand.payment_id, local_sighash));
        if !decided && !(self.approval)(&ApprovalRequest { candidate: cand, sighash: local_sighash, view: &view }) {
            return Err(SignerError::MemberRefused);
        }
        self.approved = Some((cand.payment_id, local_sighash));

        if pkg.message().as_slice() != local_sighash {
            return Err(SignerError::SighashMismatch);
        }

        // 4. Only now: unseal the share and produce the rerandomized partial under the
        //    single-use, crash-safe nonce rules. `randomizer` is the 32-byte seed.
        let seed: [u8; 32] = randomizer
            .try_into()
            .map_err(|_| SignerError::Other("randomizer seed is not 32 bytes".into()))?;
        let id = self.nonce_id(cand);
        let kp = self.open_key()?;
        let share = self.nonces.sign_and_burn(
            &id, &self.se, pkg, &kp, &seed, self.nonce_witness.as_deref_mut(), &|| false,
        );
        drop(kp);
        share.map_err(|e| SignerError::Other(e.to_string()))
    }

    fn rendered_payment(
        &self,
        session: &Session,
        cand: &CandidateRef,
    ) -> Result<PaymentView, Self::Error> {
        if self.session.as_ref() != Some(session) {
            return Err(SignerError::NoSession);
        }
        self.rendered
            .get(&cand.attempt_id)
            .cloned()
            .ok_or_else(|| SignerError::Other("no rendered payment for candidate".into()))
    }

    fn disconnect(&mut self, session: Session) -> Result<(), Self::Error> {
        if self.session.as_ref() == Some(&session) {
            self.session = None;
        }
        Ok(())
    }
}


#[cfg(test)]
#[path = "local_setup_tests.rs"]
mod setup_tests;

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::candidate::{
        alpha_from_canonical_bytes, build_candidate, quote_fee, CandidateInputs, Regtest,
    };
    use crate::signer::secure_element::SoftwareSecureElement;
    use crate::zip2005;
    use orchard::keys::Scope;
    use orchard::note::{Note, RandomSeed, Rho};
    use orchard::value::NoteValue;
    use orchard::NoteVersion;
    use zcash_protocol::{memo::MemoBytes, value::Zatoshis};

    const SPEND_VALUE: u64 = 625_000_000;
    const AMOUNT: u64 = 40_000_000;

    fn tempdir(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "loki-local-{tag}-{}-{}",
            std::process::id(),
            rand_core::RngCore::next_u64(&mut rand_core::OsRng)
        ));
        let _ = std::fs::remove_dir_all(&p);
        p
    }

    #[allow(clippy::type_complexity)]
    pub(crate) fn candidate_and_package(
        fvk: &FullViewingKey,
        key: &frost::keys::KeyPackage,
        public: &frost::keys::PublicKeyPackage,
        peer_id: frost::Identifier,
        peer_commit: frost::round1::SigningCommitments,
        own_commit: frost::round1::SigningCommitments,
        finalize: bool,
    ) -> (Vec<u8>, frost::SigningPackage, [u8; 32]) {
        candidate_with_fee(fvk, key, public, peer_id, peer_commit, own_commit, finalize, 0)
    }

    struct FixedFee(Zatoshis);

    impl zcash_primitives::transaction::fees::FeeRule for FixedFee {
        type Error = std::convert::Infallible;

        fn fee_required<P: zcash_protocol::consensus::Parameters>(
            &self,
            _params: &P,
            _target_height: zcash_protocol::consensus::BlockHeight,
            _transparent_inputs: impl IntoIterator<Item = zcash_primitives::transaction::fees::transparent::InputSize>,
            _transparent_outputs: impl IntoIterator<Item = usize>,
            _sapling_inputs: usize,
            _sapling_outputs: usize,
            _orchard_actions: usize,
            _ironwood_actions: usize,
        ) -> Result<Zatoshis, Self::Error> {
            Ok(self.0)
        }
    }

    #[allow(clippy::type_complexity, clippy::too_many_arguments)]
    fn candidate_with_fee(
        fvk: &FullViewingKey,
        key: &frost::keys::KeyPackage,
        public: &frost::keys::PublicKeyPackage,
        peer_id: frost::Identifier,
        peer_commit: frost::round1::SigningCommitments,
        own_commit: frost::round1::SigningCommitments,
        finalize: bool,
        extra_fee_zat: u64,
    ) -> (Vec<u8>, frost::SigningPackage, [u8; 32]) {
        let mut set = BTreeMap::new();
        set.insert(*key.identifier(), own_commit);
        set.insert(peer_id, peer_commit);
        let (params, seed) = frost_rerandomized::RandomizedParams::new_from_commitments(
            public.verifying_key(),
            &set,
            rand_core::OsRng,
        )
        .unwrap();
        let alpha = alpha_from_canonical_bytes(
            &params.randomizer().serialize().as_slice().try_into().unwrap(),
        )
        .unwrap();

        let rho = Rho::from_bytes(&[1u8; 32]).unwrap();
        let rseed = RandomSeed::from_bytes([2u8; 32], &rho).unwrap();
        let note = Note::from_parts(
            fvk.address_at(0u64, Scope::External),
            NoteValue::from_raw(SPEND_VALUE),
            rho,
            rseed,
            NoteVersion::V3,
        )
        .unwrap();
        let params = payment_params(fvk);
        let mut inputs = CandidateInputs {
            vault_fvk: fvk,
            notes: vec![note],
            recipient: params.recipient,
            amount: params.amount,
            memo: params.memo,
            change: Zatoshis::ZERO,
            target_height: params.target_height,
            expiry_height: params.expiry_height,
        };
        let fee = u64::from(quote_fee(&Regtest, &inputs).unwrap());
        inputs.change = Zatoshis::const_from_u64(SPEND_VALUE - AMOUNT - fee - extra_fee_zat);
        let built = if extra_fee_zat == 0 {
            build_candidate(
                &Regtest,
                &inputs,
                &[alpha],
                rand_zp::rand_core::UnwrapErr(rand_zp::rngs::SysRng),
            )
            .unwrap()
        } else {
            use zcash_primitives::transaction::builder::{BundlePadding, DeferredPcztBuilder};
            use zcash_protocol::consensus::BlockHeight;

            let mut builder = DeferredPcztBuilder::new::<std::convert::Infallible>(
                Regtest,
                BlockHeight::from_u32(inputs.target_height),
                BundlePadding::DEFAULT,
                BundlePadding::DEFAULT,
            )
            .unwrap()
            .with_expiry_height(BlockHeight::from_u32(inputs.expiry_height));
            builder
                .add_ironwood_spend_with_alpha::<std::convert::Infallible>(fvk.clone(), note, alpha)
                .unwrap();
            builder
                .add_ironwood_output::<std::convert::Infallible>(
                    None,
                    inputs.recipient,
                    inputs.amount,
                    inputs.memo,
                )
                .unwrap();
            builder
                .add_ironwood_output::<std::convert::Infallible>(
                    None,
                    fvk.address_at(0u64, Scope::Internal),
                    inputs.change,
                    MemoBytes::empty(),
                )
                .unwrap();
            builder
                .build_for_pczt(
                    rand_zp::rand_core::UnwrapErr(rand_zp::rngs::SysRng),
                    &FixedFee(Zatoshis::const_from_u64(fee + extra_fee_zat)),
                )
                .unwrap()
        };
        let pczt = pczt::roles::creator::Creator::build_from_parts(built.pczt_parts).unwrap();
        let pczt = if finalize {
            pczt::roles::io_finalizer::IoFinalizer::new(pczt)
                .finalize_io()
                .unwrap()
        } else {
            pczt
        };
        let bytes = pczt.serialize().unwrap();
        let sighash = wysiwys::sighash_of_pczt(&bytes, fvk).unwrap();
        let pkg = frost::SigningPackage::new(set, &sighash);
        let seed_bytes: [u8; 32] = seed.as_slice().try_into().unwrap();
        (bytes, pkg, seed_bytes)
    }

    fn dealer_vault() -> (
        BTreeMap<frost::Identifier, frost::keys::SecretShare>,
        frost::keys::PublicKeyPackage,
        FullViewingKey,
    ) {
        let (shares, public) = frost::keys::generate_with_dealer(
            3,
            2,
            frost::keys::IdentifierList::Default,
            &mut rand_core::OsRng,
        )
        .unwrap();
        let ak: [u8; 32] = public
            .verifying_key()
            .serialize()
            .unwrap()
            .try_into()
            .unwrap();
        let fvk = zip2005::frost_viewing_key(&ak, &[42u8; 32]).unwrap();
        (shares, public, fvk)
    }

    fn connect_signer<SE: SecureElement>(signer: &mut LocalSigner<SE>) -> Session {
        signer
            .connect("http://coordinator.test", Network::Regtest, b"challenge-1")
            .unwrap()
            .session
    }

    pub(crate) fn payment_params(fvk: &FullViewingKey) -> crate::signer::PublicPaymentParams {
        crate::signer::PublicPaymentParams {
            recipient: fvk.address_at(7u64, Scope::External),
            amount: Zatoshis::const_from_u64(AMOUNT),
            memo: MemoBytes::from_bytes(b"loki bind").unwrap(),
            target_height: 700,
            expiry_height: 1_152,
        }
    }

    #[allow(clippy::type_complexity)]
    fn committed_signer(
        attempt: u8,
    ) -> (
        LocalSigner<SoftwareSecureElement>,
        Session,
        CandidateRef,
        frost::keys::KeyPackage,
        frost::keys::KeyPackage,
        frost::round1::SigningCommitments,
        frost::round1::SigningCommitments,
        frost::keys::PublicKeyPackage,
        FullViewingKey,
    ) {
        let (shares, public, fvk) = dealer_vault();
        let (mut signer, key1) = signer_with_dealer_share(1, &shares, &public, &fvk);
        let session = connect_signer(&mut signer);
        let cand = CandidateRef {
            vault_id: [1u8; 32],
            payment_id: [7u8; 32],
            attempt_id: [attempt; 32],
        };
        let own = signer.sign_commit(&session, &cand).unwrap();
        let key2 = frost::keys::KeyPackage::try_from(
            shares
                .get(&frost::Identifier::try_from(2u16).unwrap())
                .unwrap()
                .clone(),
        )
        .unwrap();
        let (_peer_nonce, peer) = frost::round1::commit(key2.signing_share(), &mut rand_core::OsRng);
        (signer, session, cand, key1, key2, own, peer, public, fvk)
    }

    #[test]
    fn sign_approve_refuses_payment_request_mismatch_without_burning_nonce() {
        let (mut signer, session, cand, key1, key2, own, peer, public, fvk) = committed_signer(8);
        let (pczt, pkg, seed) =
            candidate_and_package(&fvk, &key1, &public, *key2.identifier(), peer, own, true);
        let expected = payment_params(&fvk);
        let mismatches = [
            crate::signer::PublicPaymentParams {
                recipient: fvk.address_at(8u64, Scope::External),
                ..expected.clone()
            },
            crate::signer::PublicPaymentParams {
                amount: Zatoshis::const_from_u64(AMOUNT + 1),
                ..expected.clone()
            },
            crate::signer::PublicPaymentParams {
                memo: MemoBytes::from_bytes(b"different memo").unwrap(),
                ..expected.clone()
            },
            crate::signer::PublicPaymentParams {
                expiry_height: expected.expiry_height + 1,
                ..expected.clone()
            },
            crate::signer::PublicPaymentParams {
                target_height: 0,
                ..expected.clone()
            },
        ];
        for params in &mismatches {
            let refused = signer.sign_approve(&session, &cand, params, &pczt, &pkg, &seed);
            assert!(
                matches!(&refused, Err(SignerError::Other(message)) if message == "candidate payment differs from requested payment"),
                "got {refused:?}"
            );
            assert_eq!(
                signer.nonces.state(&signer.nonce_id(&cand)),
                crate::signer::nonce::NonceState::Committed
            );
        }
        signer
            .sign_approve(&session, &cand, &expected, &pczt, &pkg, &seed)
            .expect("matching request may sign");
    }

    #[test]
    fn sign_approve_refuses_valid_high_fee_before_approval_or_nonce_use() {
        let (mut signer, session, cand, key1, key2, own, peer, public, fvk) = committed_signer(18);
        let (pczt, pkg, seed) = candidate_with_fee(
            &fvk,
            &key1,
            &public,
            *key2.identifier(),
            peer,
            own,
            true,
            100_000_000,
        );
        let view = wysiwys::describe_pczt(&pczt, &fvk).unwrap();
        assert!(view.fee_verified);
        assert_eq!(view.fee_zat, 100_010_000);
        signer.approval = Box::new(|_| panic!("high fee reached approval"));

        let result = signer.sign_approve(&session, &cand, &payment_params(&fvk), &pczt, &pkg, &seed);
        assert!(
            matches!(&result, Err(SignerError::Other(message)) if message == "candidate fee differs from ZIP-317 fee"),
            "got {result:?}"
        );
        assert_eq!(
            signer.nonces.state(&signer.nonce_id(&cand)),
            crate::signer::nonce::NonceState::Committed
        );
    }

    #[test]
    fn sign_approve_refuses_unverified_fee_before_approval_or_nonce_use() {
        let (mut signer, session, cand, key1, key2, own, peer, public, fvk) = committed_signer(19);
        let (pczt, pkg, seed) =
            candidate_and_package(&fvk, &key1, &public, *key2.identifier(), peer, own, true);
        let pczt = pczt::roles::redactor::Redactor::new(pczt::Pczt::parse(&pczt).unwrap())
            .redact_ironwood_with(|mut bundle| bundle.redact_actions(|mut action| action.clear_rcv()))
            .finish()
            .serialize()
            .unwrap();
        let view = wysiwys::describe_pczt(&pczt, &fvk).unwrap();
        assert!(!view.fee_verified);
        signer.approval = Box::new(|_| panic!("unverified fee reached approval"));

        let result = signer.sign_approve(&session, &cand, &payment_params(&fvk), &pczt, &pkg, &seed);
        assert!(
            matches!(&result, Err(SignerError::FeeUnverified(_))),
            "got {result:?}"
        );
        assert_eq!(result.unwrap_err().to_string(), "candidate fee is unverified");
        assert_eq!(
            signer.nonces.state(&signer.nonce_id(&cand)),
            crate::signer::nonce::NonceState::Committed
        );
    }

    fn signer_with_dealer_share(
        id: u16,
        shares: &BTreeMap<frost::Identifier, frost::keys::SecretShare>,
        public: &frost::keys::PublicKeyPackage,
        fvk: &FullViewingKey,
    ) -> (LocalSigner<SoftwareSecureElement>, frost::keys::KeyPackage) {
        let ident = frost::Identifier::try_from(id).unwrap();
        let kp = frost::keys::KeyPackage::try_from(shares.get(&ident).unwrap().clone()).unwrap();
        let signer = LocalSigner::with_sealed_share(
            id,
            2,
            3,
            [id as u8; 32],
            "test vault".into(),
            Network::Regtest,
            SoftwareSecureElement::generate(),
            &kp.serialize().unwrap(),
            public.serialize().unwrap(),
            fvk.clone(),
            tempdir(&format!("m{id}")),
            Box::new(|_view| true),
        )
        .unwrap();
        (signer, kp)
    }

    #[test]
    fn sign_approve_binds_package_message_to_rendered_sighash() {
        let (shares, public, fvk) = dealer_vault();
        let (mut signer, key1) = signer_with_dealer_share(1, &shares, &public, &fvk);
        let session = connect_signer(&mut signer);
        let cand = CandidateRef {
            vault_id: [1u8; 32],
            payment_id: [7u8; 32],
            attempt_id: [9u8; 32],
        };

        let own_commit = signer.sign_commit(&session, &cand).unwrap();
        let key2 = frost::keys::KeyPackage::try_from(
            shares
                .get(&frost::Identifier::try_from(2u16).unwrap())
                .unwrap()
                .clone(),
        )
        .unwrap();
        let (_n2, peer_commit) =
            frost::round1::commit(key2.signing_share(), &mut rand_core::OsRng);

        let (pczt, good_pkg, seed) = candidate_and_package(
            &fvk,
            &key1,
            &public,
            *key2.identifier(),
            peer_commit,
            own_commit,
            true,
        );

        let bad_pkg = frost::SigningPackage::new(
            good_pkg.signing_commitments().clone(),
            &[0xabu8; 32],
        );
        let refused = signer.sign_approve(&session, &cand, &payment_params(&fvk), &pczt, &bad_pkg, &seed);
        assert!(
            matches!(refused, Err(SignerError::SighashMismatch)),
            "a package naming a different sighash must be REFUSED, got {refused:?}"
        );
        assert_eq!(
            signer.nonces.state(&signer.nonce_id(&cand)),
            crate::signer::nonce::NonceState::Committed,
            "refused binding must not touch the nonce"
        );

        let share = signer
            .sign_approve(&session, &cand, &payment_params(&fvk), &pczt, &good_pkg, &seed)
            .expect("matching sighash must sign");
        assert_eq!(share.serialize().len(), 32);
    }

    #[derive(Clone, Default)]
    struct Witnesses(std::sync::Arc<std::sync::Mutex<Vec<[u8; 32]>>>, bool);

    impl NonceWitness for Witnesses {
        fn pins(&self) -> crate::signing_session::WitnessPins {
            [([1; 32], [2; 32], [3; 32]), ([4; 32], [5; 32], [6; 32])]
        }
        fn claim(&mut self, cid: [u8; 32], record: &[u8]) -> Result<(), String> {
            let mut claimed = self.0.lock().unwrap();
            if self.1 || claimed.contains(&cid) || record[..32] != cid {
                return Err("nonce already claimed; start a new signing attempt".into());
            }
            claimed.push(cid);
            Ok(())
        }
    }

    #[test]
    fn nonce_witness_claim_gates_the_share_and_blocks_rolled_back_nonces() {
        let (shares, public, fvk) = dealer_vault();
        let key1 = frost::keys::KeyPackage::try_from(shares[&frost::Identifier::try_from(1u16).unwrap()].clone()).unwrap();
        let key2 = frost::keys::KeyPackage::try_from(shares[&frost::Identifier::try_from(2u16).unwrap()].clone()).unwrap();
        let nonce_dir = tempdir("witness-m1");
        let mut signer = LocalSigner::with_sealed_share(
            1, 2, 3, [1; 32], "test vault".into(), Network::Regtest, SoftwareSecureElement::generate(),
            &key1.serialize().unwrap(), public.serialize().unwrap(), fvk.clone(), nonce_dir.clone(),
            Box::new(|_| true),
        )
        .unwrap();
        let witnesses = Witnesses::default();
        signer.set_nonce_witness(Box::new(Witnesses(witnesses.0.clone(), true)));
        let session = connect_signer(&mut signer);
        let cand = CandidateRef { vault_id: [1; 32], payment_id: [7; 32], attempt_id: [9; 32] };
        let own = signer.sign_commit(&session, &cand).unwrap();
        let (_n2, peer) = frost::round1::commit(key2.signing_share(), &mut rand_core::OsRng);
        let (pczt, pkg, seed) = candidate_and_package(&fvk, &key1, &public, *key2.identifier(), peer, own, true);
        let id = signer.nonce_id(&cand);

        let refused = signer.sign_approve(&session, &cand, &payment_params(&fvk), &pczt, &pkg, &seed);
        assert!(matches!(&refused, Err(SignerError::Other(e)) if e.contains("nonce witness refused")), "{refused:?}");
        assert_eq!(signer.nonces.state(&id), crate::signer::nonce::NonceState::Committed);

        signer.set_nonce_witness(Box::new(witnesses.clone()));
        let snapshot: Vec<_> = std::fs::read_dir(&nonce_dir).unwrap().flatten()
            .map(|e| (e.path(), std::fs::read(e.path()).unwrap())).collect();
        let share = signer.sign_approve(&session, &cand, &payment_params(&fvk), &pczt, &pkg, &seed).expect("claimed nonce signs");
        assert_eq!(witnesses.0.lock().unwrap().len(), 1);
        assert_eq!(signer.sign_approve(&session, &cand, &payment_params(&fvk), &pczt, &pkg, &seed).unwrap(), share);
        assert_eq!(witnesses.0.lock().unwrap().len(), 1);

        for entry in std::fs::read_dir(&nonce_dir).unwrap().flatten() {
            std::fs::remove_file(entry.path()).unwrap();
        }
        for (path, bytes) in &snapshot {
            std::fs::write(path, bytes).unwrap();
        }
        assert_eq!(signer.nonces.state(&id), crate::signer::nonce::NonceState::Committed);
        let replayed = signer.sign_approve(&session, &cand, &payment_params(&fvk), &pczt, &pkg, &seed);
        assert!(matches!(&replayed, Err(SignerError::Other(e)) if e.contains("already claimed")), "{replayed:?}");
    }

    #[test]
    fn payment_review_recomputes_candidate_sighash_and_tamper_is_refused() {
        let (shares, public, fvk) = dealer_vault();
        let (mut signer, key1) = signer_with_dealer_share(1, &shares, &public, &fvk);
        let session = connect_signer(&mut signer);
        let cand = CandidateRef {
            vault_id: [1u8; 32],
            payment_id: [9u8; 32],
            attempt_id: [9u8; 32],
        };
        let own_commit = signer.sign_commit(&session, &cand).unwrap();
        let key2 = frost::keys::KeyPackage::try_from(
            shares.get(&frost::Identifier::try_from(2u16).unwrap()).unwrap().clone(),
        )
        .unwrap();
        let (_n2, peer_commit) = frost::round1::commit(key2.signing_share(), &mut rand_core::OsRng);
        let (pczt, pkg, _seed) = candidate_and_package(
            &fvk, &key1, &public, *key2.identifier(), peer_commit, own_commit, true,
        );

        let view = wysiwys::describe_pczt(&pczt, &fvk).unwrap();
        let sighash = wysiwys::sighash_of_pczt(&pczt, &fvk).unwrap();
        assert_eq!(view.amount_zat, AMOUNT);
        assert!(view.fee_verified);
        assert_eq!(pkg.message().as_slice(), sighash);

        let mut bad = pczt.clone();
        *bad.last_mut().unwrap() ^= 0xff;
        match wysiwys::sighash_of_pczt(&bad, &fvk) {
            Ok(h) => assert_ne!(h, sighash, "tampered candidate must not reproduce the sighash"),
            Err(_) => {}
        }
    }

    #[test]
    fn member_refusal_is_first_class_and_leaves_nonce() {
        let (shares, public, fvk) = dealer_vault();
        let ident = frost::Identifier::try_from(1u16).unwrap();
        let key1 = frost::keys::KeyPackage::try_from(shares.get(&ident).unwrap().clone()).unwrap();
        let mut signer = LocalSigner::with_sealed_share(
            1,
            2,
            3,
            [1u8; 32],
            "test vault".into(),
            Network::Regtest,
            SoftwareSecureElement::generate(),
            &key1.serialize().unwrap(),
            public.serialize().unwrap(),
            fvk.clone(),
            tempdir("refuse"),
            Box::new(|_view| false),
        )
        .unwrap();
        let session = connect_signer(&mut signer);
        let cand = CandidateRef {
            vault_id: [1u8; 32],
            payment_id: [7u8; 32],
            attempt_id: [9u8; 32],
        };
        let own_commit = signer.sign_commit(&session, &cand).unwrap();
        let key2 = frost::keys::KeyPackage::try_from(
            shares
                .get(&frost::Identifier::try_from(2u16).unwrap())
                .unwrap()
                .clone(),
        )
        .unwrap();
        let (_n2, peer_commit) =
            frost::round1::commit(key2.signing_share(), &mut rand_core::OsRng);
        let (pczt, pkg, seed) = candidate_and_package(
            &fvk,
            &key1,
            &public,
            *key2.identifier(),
            peer_commit,
            own_commit,
            true,
        );
        let out = signer.sign_approve(&session, &cand, &payment_params(&fvk), &pczt, &pkg, &seed);
        assert!(matches!(out, Err(SignerError::MemberRefused)));
        assert_eq!(
            signer.nonces.state(&signer.nonce_id(&cand)),
            crate::signer::nonce::NonceState::Committed,
        );
    }

    #[test]
    fn fee_is_verified_when_values_bind_to_commitments() {
        let (shares, public, fvk) = dealer_vault();
        let (mut signer, key1) = signer_with_dealer_share(1, &shares, &public, &fvk);
        let session = connect_signer(&mut signer);
        let key2 = frost::keys::KeyPackage::try_from(
            shares
                .get(&frost::Identifier::try_from(2u16).unwrap())
                .unwrap()
                .clone(),
        )
        .unwrap();
        let cand = CandidateRef {
            vault_id: [1u8; 32],
            payment_id: [1u8; 32],
            attempt_id: [1u8; 32],
        };
        let own = signer.sign_commit(&session, &cand).unwrap();
        let (_a, peer) = frost::round1::commit(key2.signing_share(), &mut rand_core::OsRng);
        let (pczt, _pkg, _seed) =
            candidate_and_package(&fvk, &key1, &public, *key2.identifier(), peer, own, true);

        let view = wysiwys::describe_pczt(&pczt, &fvk).unwrap();
        assert!(
            view.fee_verified,
            "a candidate whose values bind to cv_net must report a VERIFIED fee"
        );
        assert_eq!(view.fee_zat, SPEND_VALUE - AMOUNT - view.change_zat);
        assert!(view.fee_zat > 0);

        let parsed = pczt::Pczt::parse(&pczt).unwrap();
        let mut all_bound = true;
        pczt::roles::verifier::Verifier::new(parsed)
            .with_ironwood::<String, _>(|bundle| {
                for action in bundle.actions() {
                    if action.verify_cv_net().is_err() {
                        all_bound = false;
                    }
                }
                Ok(())
            })
            .unwrap();
        assert_eq!(all_bound, view.fee_verified);
    }

    #[test]
    fn signer_from_vault_member_can_sign_a_candidate() {
        use crate::member_state::{MemberState, Roster};
        use crate::network::VaultNetwork;

        let (shares, public, fvk) = dealer_vault();
        let id1 = frost::Identifier::try_from(1u16).unwrap();
        let id2 = frost::Identifier::try_from(2u16).unwrap();
        let key1 = frost::keys::KeyPackage::try_from(shares.get(&id1).unwrap().clone()).unwrap();
        let key2 = frost::keys::KeyPackage::try_from(shares.get(&id2).unwrap().clone()).unwrap();

        let identities: Vec<Identity> = (1..=3).map(Identity::new).collect();
        let vault = [7u8; 32];
        let members: Vec<_> = identities
            .iter()
            .map(|identity| {
                let peer = identity.public();
                serde_json::json!({
                    "id": peer.id,
                    "signing": hex::encode(peer.signing),
                    "encryption": hex::encode(peer.encryption),
                })
            })
            .collect();
        let roster = Roster::from_bytes(
            &serde_json::to_vec(&serde_json::json!({
                "vault": hex::encode(vault),
                "threshold": 2,
                "members": members,
            }))
            .unwrap(),
        )
        .unwrap();
        let state = MemberState {
            vault,
            network: VaultNetwork::Regtest,
            birth_height: None,
            roster,
            identity: identities.into_iter().next().unwrap(),
            key: key1.clone(),
            public: public.clone(),
            fvk: fvk.clone(),
        };

        let mut signer = LocalSigner::from_vault_member(
            &state,
            SoftwareSecureElement::generate(),
            tempdir("from-vault-member"),
            Box::new(|_view| true),
        )
        .unwrap();
        let session = connect_signer(&mut signer);

        let vaults = signer.list_vaults(&session).unwrap();
        assert_eq!(vaults.len(), 1);
        assert_eq!(vaults[0].vault_id, vault);

        let cand = CandidateRef {
            vault_id: vault,
            payment_id: [7u8; 32],
            attempt_id: [9u8; 32],
        };
        let own_commit = signer.sign_commit(&session, &cand).unwrap();
        let (_n2, peer_commit) =
            frost::round1::commit(key2.signing_share(), &mut rand_core::OsRng);
        let (pczt, pkg, seed) = candidate_and_package(
            &fvk,
            &key1,
            &public,
            *key2.identifier(),
            peer_commit,
            own_commit,
            true,
        );
        let share = signer
            .sign_approve(&session, &cand, &payment_params(&fvk), &pczt, &pkg, &seed)
            .expect("vault-member signer must produce a partial signature");
        assert_eq!(share.serialize().len(), 32);
    }
}
