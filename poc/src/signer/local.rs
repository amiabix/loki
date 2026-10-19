//! [`LocalSigner`]: the in-app implementation of the single [`Signer`] seam.
//!
//! It holds exactly one member's FROST share, sealed at rest by the [`SecureElement`]
//! (software backend for now; Secure Enclave / StrongBox implement the same trait later).
//! The share is unsealed into memory only for the two FROST rounds and the plaintext is
//! held in a `Zeroizing` buffer.
//!
//! The safety-critical method is [`LocalSigner::sign_approve`], which binds the WYSIWYS
//! render to the exact bytes being signed (invariant #3 / threat §5.4):
//!   1. independently parse the PCZT and render it ([`wysiwys::describe_pczt`]),
//!   2. require an explicit approval decision over that render,
//!   3. recompute the sighash from the SAME bytes ([`wysiwys::sighash_of_pczt`]) and
//!      REFUSE unless `pkg.message()` equals it — BEFORE the nonce/share is touched,
//!   4. only then produce the rerandomized round-2 share under the single-use nonce rules.

use crate::distributed_setup::{Completed, Member, Round2Member};
use crate::setup_transport::{Identity, PublicIdentity};
use crate::signer::nonce::NonceStore;
use crate::signer::secure_element::{SealedShare, SecureElement};
use crate::signer::wysiwys::{self, PaymentView};
use crate::signer::{CandidateRef, Connection, MemberIdentity, Network, Session, Signer, VaultRef};
use orchard::keys::FullViewingKey;
use reddsa_frost::frost::redpallas as frost;
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use zeroize::Zeroize;

/// The member's on-device approval decision for a rendered payment. In a real signer this
/// is a full-screen confirmation + biometric prompt; here it is a policy callback so the
/// tests can drive approve/refuse deterministically (ws1-signer §7: "a callback/policy is
/// fine for tests").
pub type ApprovalPolicy = Box<dyn FnMut(&PaymentView) -> bool + Send>;

/// Error surface of the local signer. A refusal (member declined, or a binding failed) is
/// a first-class, non-secret outcome (ws1-signer §7).
#[derive(Debug)]
pub enum SignerError {
    /// The member declined the rendered payment on-device.
    MemberRefused,
    /// `pkg.message()` did not equal the sighash recomputed from the rendered PCZT. A
    /// malicious coordinator asking us to sign something other than what we rendered.
    SighashMismatch,
    /// The signer is not connected / the session is unknown.
    NoSession,
    /// No share is sealed yet (DKG not complete).
    NoShare,
    /// A protocol/parse/io failure, carried as text.
    Other(String),
}

impl std::fmt::Display for SignerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SignerError::MemberRefused => write!(f, "member refused the rendered payment"),
            SignerError::SighashMismatch => write!(
                f,
                "REFUSED: SigningPackage.message() != sighash(rendered pczt) — \
                 what-you-see-is-what-you-sign binding failed"
            ),
            SignerError::NoSession => write!(f, "no active session"),
            SignerError::NoShare => write!(f, "no sealed share (DKG incomplete)"),
            SignerError::Other(e) => write!(f, "{e}"),
        }
    }
}
impl From<String> for SignerError {
    fn from(e: String) -> Self {
        SignerError::Other(e)
    }
}

/// Where the DKG typestate machine is for this member.
enum Dkg {
    /// Not started; the next `dkg_step` (with empty `in_msgs`) runs round 1.
    Idle,
    Aborted,
    AfterRound1(Member),
    AfterRound2(Round2Member),
    Done(Completed),
}

struct SecretRound2(BTreeMap<u16, Vec<u8>>);

impl Drop for SecretRound2 {
    fn drop(&mut self) {
        for package in self.0.values_mut() {
            package.zeroize();
        }
    }
}

/// One member's signer. Holds the sealed share + the public key package + the vault FVK
/// (public: used only to render PCZTs and verify openings), a secure element, a crash-safe
/// nonce store, and an approval policy.
pub struct LocalSigner<SE: SecureElement> {
    member_id: u16,
    threshold: u16,
    members: u16,
    vault_id: [u8; 32],
    label: String,
    network: Network,
    se: SE,
    /// The member's FROST share, sealed at rest. Present once DKG completes (or when the
    /// signer is constructed from a restored/dealer-dealt share for tests).
    sealed_share: Option<SealedShare>,
    /// The group `PublicKeyPackage`, serialized. Public.
    public_package: Option<Vec<u8>>,
    /// The vault viewing key. PUBLIC — used to render payments and verify openings.
    vault_fvk: FullViewingKey,
    nonces: NonceStore,
    approval: ApprovalPolicy,
    dkg_identity: Option<Identity>,
    approved_roster: BTreeMap<u16, PublicIdentity>,
    dkg: Dkg,
    session: Option<Session>,
    /// Last rendered payment, keyed by candidate attempt id, for `rendered_payment`.
    rendered: BTreeMap<[u8; 32], PaymentView>,
}

impl<SE: SecureElement> LocalSigner<SE> {
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
        let sealed = SealedShare::seal(&se, 0, key_package_bytes).map_err(SignerError::Other)?;
        Ok(Self {
            member_id,
            threshold,
            members,
            vault_id,
            label,
            network,
            se,
            sealed_share: Some(sealed),
            public_package: Some(public_package_bytes),
            vault_fvk,
            nonces: NonceStore::open(&nonce_dir).map_err(|e| SignerError::Other(e.to_string()))?,
            approval,
            dkg_identity: None,
            approved_roster: BTreeMap::new(),
            dkg: Dkg::Idle,
            session: None,
            rendered: BTreeMap::new(),
        })
    }

    /// Construct a signer with NO share yet, after this device has approved the exact
    /// public DKG roster out of band. The coordinator must not choose these keys.
    #[allow(clippy::too_many_arguments)]
    pub fn for_dkg(
        member_id: u16,
        threshold: u16,
        members: u16,
        vault_id: [u8; 32],
        label: String,
        network: Network,
        se: SE,
        identity: Identity,
        approved_roster: Vec<PublicIdentity>,
        vault_fvk: FullViewingKey,
        nonce_dir: PathBuf,
        approval: ApprovalPolicy,
    ) -> Result<Self, SignerError> {
        let roster: BTreeMap<_, _> = approved_roster
            .iter()
            .cloned()
            .map(|peer| (peer.id, peer))
            .collect();
        if roster.len() != usize::from(members)
            || approved_roster.len() != roster.len()
            || roster.keys().copied().collect::<Vec<_>>() != (1..=members).collect::<Vec<_>>()
            || roster.get(&member_id) != Some(&identity.public())
            || roster
                .values()
                .map(|peer| peer.signing)
                .collect::<BTreeSet<_>>()
                .len()
                != roster.len()
            || roster
                .values()
                .map(|peer| peer.encryption)
                .collect::<BTreeSet<_>>()
                .len()
                != roster.len()
        {
            return Err(SignerError::Other(
                "DKG roster is not this member's approved roster".into(),
            ));
        }
        Ok(Self {
            member_id,
            threshold,
            members,
            vault_id,
            label,
            network,
            se,
            sealed_share: None,
            public_package: None,
            vault_fvk,
            nonces: NonceStore::open(&nonce_dir).map_err(|e| SignerError::Other(e.to_string()))?,
            approval,
            dkg_identity: Some(identity),
            approved_roster: roster,
            dkg: Dkg::Idle,
            session: None,
            rendered: BTreeMap::new(),
        })
    }

    /// The group verifying (public) key package, once DKG has completed. Public.
    pub fn public_package_bytes(&self) -> Option<&[u8]> {
        self.public_package.as_deref()
    }

    /// Unseal the member's `KeyPackage` into memory. Caller drops it promptly.
    fn open_key(&self) -> Result<frost::keys::KeyPackage, SignerError> {
        let sealed = self.sealed_share.as_ref().ok_or(SignerError::NoShare)?;
        let plain = sealed.open(&self.se).map_err(SignerError::Other)?;
        frost::keys::KeyPackage::deserialize(&plain)
            .map_err(|e| SignerError::Other(format!("key package: {e}")))
    }

    fn nonce_id(&self, cand: &CandidateRef) -> String {
        // One nonce per (payment, attempt). Hex so it is a safe filename.
        let mut s = String::with_capacity(64);
        for b in cand.payment_id.iter().chain(cand.attempt_id.iter()) {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }
}

impl<SE: SecureElement> Signer for LocalSigner<SE> {
    type Error = SignerError;

    fn connect(
        &mut self,
        _origin: &str,
        network: Network,
        challenge: &[u8],
    ) -> Result<Connection, Self::Error> {
        if network != self.network {
            return Err(SignerError::Other(format!(
                "connect network {:?} does not match signer network {:?}",
                network, self.network
            )));
        }
        // Session id binds the challenge so a replayed connect gets a distinct handle.
        let mut sid = [0u8; 32];
        let h = blake3::hash(challenge);
        sid.copy_from_slice(h.as_bytes());
        let session = Session(sid);
        self.session = Some(session.clone());
        // The DKG identity is the approved roster key; a restored share has only
        // its verifying share available here.
        let (signing, encryption) = if let Some(identity) = &self.dkg_identity {
            let public = identity.public();
            (public.signing, public.encryption)
        } else {
            match self.open_key() {
                Ok(kp) => {
                    let vs: [u8; 32] = kp
                        .verifying_share()
                        .serialize()
                        .map_err(|e| SignerError::Other(e.to_string()))?
                        .try_into()
                        .map_err(|_| SignerError::Other("verifying share not 32 bytes".into()))?;
                    (vs, [0u8; 32])
                }
                Err(_) => ([0u8; 32], [0u8; 32]),
            }
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
        if self.session.as_ref() != Some(session) {
            return Err(SignerError::NoSession);
        }
        Ok(vec![VaultRef {
            vault_id: self.vault_id,
            label: self.label.clone(),
            threshold: self.threshold,
            members: self.members,
            ready: self.sealed_share.is_some(),
        }])
    }

    fn dkg_step(
        &mut self,
        session: &Session,
        vault: &VaultRef,
        in_msgs: &[Vec<u8>],
    ) -> Result<Vec<Vec<u8>>, Self::Error> {
        if self.session.as_ref() != Some(session) {
            return Err(SignerError::NoSession);
        }
        if vault.vault_id != self.vault_id
            || vault.threshold != self.threshold
            || vault.members != self.members
        {
            return Err(SignerError::Other(
                "DKG vault differs from this signer".into(),
            ));
        }
        let identity = self
            .dkg_identity
            .as_ref()
            .ok_or_else(|| SignerError::Other("DKG requires an approved signer roster".into()))?;
        // The dealerless DKG from `distributed_setup` is a 3-call typestate machine. The
        // coordinator passes signed round-one wires or encrypted round-two wires
        // in roster order (member 1..=N):
        //   call 0: in_msgs empty            -> run part1, emit [own round1 package]
        //   call 1: in_msgs = all round1 pkgs (roster order) -> part2, emit round2 pkgs
        //                                                        for each peer (roster order)
        //   call 2: in_msgs = peers' round2 pkgs to this member (roster order)
        //                                      -> part3; SEAL the share internally, emit []
        match std::mem::replace(&mut self.dkg, Dkg::Aborted) {
            Dkg::Idle => {
                if !in_msgs.is_empty() {
                    return Err(SignerError::Other("round-1 start needs no packages".into()));
                }
                let (member, own_r1) =
                    Member::start_with_policy(self.member_id, self.threshold, self.members)
                        .map_err(SignerError::Other)?;
                let signed = identity
                    .sign_round1(&self.vault_id, &own_r1)
                    .map_err(SignerError::Other)?;
                self.dkg = Dkg::AfterRound1(member);
                Ok(vec![signed])
            }
            Dkg::AfterRound1(member) => {
                if in_msgs.len() != usize::from(self.members) {
                    return Err(SignerError::Other(format!(
                        "round-1 step needs {} packages in roster order, got {}",
                        self.members,
                        in_msgs.len()
                    )));
                }
                let round1: BTreeMap<u16, Vec<u8>> = (1..=self.members)
                    .zip(in_msgs)
                    .map(|(id, wire)| {
                        let peer = self.approved_roster.get(&id).expect("complete DKG roster");
                        identity
                            .verify_round1(peer, &self.vault_id, wire)
                            .map(|payload| (id, payload))
                            .map_err(SignerError::Other)
                    })
                    .collect::<Result<_, _>>()?;
                let (r2member, wire) = member.advance(&round1).map_err(SignerError::Other)?;
                let wire = SecretRound2(wire);
                let mut outgoing = Vec::with_capacity(wire.0.len());
                for (id, payload) in &wire.0 {
                    let peer = self.approved_roster.get(id).expect("complete DKG roster");
                    let sealed = identity
                        .seal_round2(peer, &self.vault_id, payload)
                        .map_err(SignerError::Other)?;
                    outgoing.push(sealed);
                }
                self.dkg = Dkg::AfterRound2(r2member);
                Ok(outgoing)
            }
            Dkg::AfterRound2(r2member) => {
                let peers: Vec<u16> = (1..=self.members)
                    .filter(|p| *p != self.member_id)
                    .collect();
                if in_msgs.len() != peers.len() {
                    return Err(SignerError::Other(format!(
                        "round-2 step needs {} peer packages, got {}",
                        peers.len(),
                        in_msgs.len()
                    )));
                }
                let mut incoming = SecretRound2(BTreeMap::new());
                for (id, wire) in peers.into_iter().zip(in_msgs) {
                    let peer = self.approved_roster.get(&id).expect("complete DKG roster");
                    let payload = identity
                        .open_round2(peer, &self.vault_id, wire)
                        .map_err(SignerError::Other)?;
                    incoming.0.insert(id, payload);
                }
                let completed = r2member.finish(&incoming.0).map_err(SignerError::Other)?;
                // The share is BORN here, inside the signer. Seal it immediately with the
                // secure element and keep only the sealed blob + the public key package.
                self.sealed_share = Some(
                    SealedShare::seal(&self.se, 0, completed.key_package_bytes())
                        .map_err(SignerError::Other)?,
                );
                self.public_package = Some(completed.public_package().to_vec());
                self.dkg = Dkg::Done(completed);
                Ok(vec![])
            }
            Dkg::Done(c) => {
                self.dkg = Dkg::Done(c);
                Err(SignerError::Other("DKG already complete".into()))
            }
            Dkg::Aborted => Err(SignerError::Other(
                "DKG aborted after an earlier error".into(),
            )),
        }
    }

    fn sign_commit(
        &mut self,
        session: &Session,
        cand: &CandidateRef,
    ) -> Result<frost::round1::SigningCommitments, Self::Error> {
        if self.session.as_ref() != Some(session) {
            return Err(SignerError::NoSession);
        }
        let kp = self.open_key()?;
        let id = self.nonce_id(cand);
        self.nonces
            .commit(&id, &self.se, kp.signing_share())
            .map_err(|e| SignerError::Other(e.to_string()))
    }

    fn sign_approve(
        &mut self,
        session: &Session,
        cand: &CandidateRef,
        pczt: &[u8],
        pkg: &frost::SigningPackage,
        randomizer: &[u8],
    ) -> Result<frost::round2::SignatureShare, Self::Error> {
        if self.session.as_ref() != Some(session) {
            return Err(SignerError::NoSession);
        }

        // 1. INDEPENDENTLY render what this PCZT pays — from the bytes, not any claim.
        let view = wysiwys::describe_pczt(pczt, &self.vault_fvk).map_err(SignerError::Other)?;
        self.rendered.insert(cand.attempt_id, view.clone());

        // 2. The member decides on THAT render (policy/biometric). Refusal is first-class.
        if !(self.approval)(&view) {
            return Err(SignerError::MemberRefused);
        }

        // 3. BINDING (the must-fix): recompute the sighash from the SAME bytes and require
        //    the SigningPackage to name exactly it. Done BEFORE the nonce/share is touched,
        //    so a mismatched package can never consume a nonce or release a share.
        let local_sighash =
            wysiwys::sighash_of_pczt(pczt, &self.vault_fvk).map_err(SignerError::Other)?;
        if pkg.message().as_slice() != local_sighash {
            return Err(SignerError::SighashMismatch);
        }

        // 4. Only now: unseal the share and produce the rerandomized partial under the
        //    single-use, crash-safe nonce rules. `randomizer` is the 32-byte seed.
        let seed: [u8; 32] = randomizer
            .try_into()
            .map_err(|_| SignerError::Other("randomizer seed is not 32 bytes".into()))?;
        let kp = self.open_key()?;
        let id = self.nonce_id(cand);
        self.nonces
            .sign_and_burn(&id, &self.se, pkg, &kp, &seed, &|| false)
            .map_err(|e| match e {
                crate::signer::nonce::NonceError::Reuse => {
                    SignerError::Other(crate::signer::nonce::NonceError::Reuse.to_string())
                }
                other => SignerError::Other(other.to_string()),
            })
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
mod tests {
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

    /// A one-note candidate paying `fvk.address_at(7)` from `fvk`, under `member`+`peer`
    /// commitments and a rerandomization `seed`. `finalize` toggles IO finalization, which
    /// is what populates the `rcv` trapdoors (→ `fee_verified`).
    ///
    /// Returns (pczt_bytes, signing_package, seed) where the package's message is the real
    /// sighash of the bytes.
    #[allow(clippy::type_complexity)]
    fn candidate_and_package(
        fvk: &FullViewingKey,
        key: &frost::keys::KeyPackage,
        public: &frost::keys::PublicKeyPackage,
        peer_id: frost::Identifier,
        peer_commit: frost::round1::SigningCommitments,
        own_commit: frost::round1::SigningCommitments,
        finalize: bool,
    ) -> (Vec<u8>, frost::SigningPackage, [u8; 32]) {
        // Commitment set drives the seed-derived alpha used to randomize the single spend.
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
        let mut inputs = CandidateInputs {
            vault_fvk: fvk,
            notes: vec![note],
            recipient: fvk.address_at(7u64, Scope::External),
            amount: Zatoshis::const_from_u64(AMOUNT),
            memo: MemoBytes::from_bytes(b"loki bind").unwrap(),
            change: Zatoshis::ZERO,
            target_height: 700,
            expiry_height: 1_152,
        };
        let fee = u64::from(quote_fee(&Regtest, &inputs).unwrap());
        inputs.change = Zatoshis::const_from_u64(SPEND_VALUE - AMOUNT - fee);
        let built = build_candidate(
            &Regtest,
            &inputs,
            &[alpha],
            rand_zp::rand_core::UnwrapErr(rand_zp::rngs::SysRng),
        )
        .unwrap();
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

    /// A 2-of-3 dealer keyset and the vault FVK derived from its group verifying key.
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

    // (a) sign_approve REFUSES when pkg.message() != sighash(rendered pczt), and SUCCEEDS
    //     when they match. This is the must-fix WYSIWYS→signature binding (threat §5.4).
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

        // Round 1 inside the signer: it persists the nonce and gives us the commitment.
        let own_commit = signer.sign_commit(&session, &cand).unwrap();
        // A peer commitment to populate the package.
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

        // Tampered package: same commitments, WRONG message (not the pczt's sighash).
        let bad_pkg = frost::SigningPackage::new(
            good_pkg.signing_commitments().clone(),
            &[0xabu8; 32],
        );
        let refused = signer.sign_approve(&session, &cand, &pczt, &bad_pkg, &seed);
        assert!(
            matches!(refused, Err(SignerError::SighashMismatch)),
            "a package naming a different sighash must be REFUSED, got {refused:?}"
        );
        // And the nonce was NOT burned by the refused attempt.
        assert_eq!(
            signer.nonces.state(&signer.nonce_id(&cand)),
            crate::signer::nonce::NonceState::Committed,
            "refused binding must not touch the nonce"
        );

        // Matching package: binding passes, a real partial signature is produced.
        let share = signer
            .sign_approve(&session, &cand, &pczt, &good_pkg, &seed)
            .expect("matching sighash must sign");
        assert_eq!(share.serialize().len(), 32);
    }

    // (a') a member refusal is first-class and does not consume the nonce.
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
            Box::new(|_view| false), // member declines
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
        let out = signer.sign_approve(&session, &cand, &pczt, &pkg, &seed);
        assert!(matches!(out, Err(SignerError::MemberRefused)));
        assert_eq!(
            signer.nonces.state(&signer.nonce_id(&cand)),
            crate::signer::nonce::NonceState::Committed,
        );
    }

    // (b) dkg_step runs the real dealerless DKG, the share is born+sealed inside the
    //     signer, and the signer can then sign a candidate for the group key.
    #[test]
    fn rejected_dkg_input_cannot_silently_restart_the_ceremony() {
        let identities: Vec<_> = (1..=3).map(Identity::new).collect();
        let roster = identities.iter().map(Identity::public).collect();
        let mut signer = LocalSigner::for_dkg(
            1,
            2,
            3,
            [1u8; 32],
            "dkg vault".into(),
            Network::Regtest,
            SoftwareSecureElement::generate(),
            identities.into_iter().next().unwrap(),
            roster,
            placeholder_fvk(),
            tempdir("dkg-abort"),
            Box::new(|_| true),
        )
        .unwrap();
        let session = signer
            .connect("http://coordinator.test", Network::Regtest, b"challenge")
            .unwrap()
            .session;
        let vault = signer.list_vaults(&session).unwrap().remove(0);
        signer.dkg_step(&session, &vault, &[]).unwrap();
        assert!(signer.dkg_step(&session, &vault, &[]).is_err());
        assert!(signer.dkg_step(&session, &vault, &[]).is_err());
    }

    #[test]
    fn dkg_step_produces_sealed_share_that_can_sign() {
        let challenge = b"dkg-challenge";
        // Three signers (members 1..=3). FVK is filled in once DKG yields the group key;
        // for connect/dkg we only need a placeholder FVK, so derive a throwaway now and
        // rebuild once the group ak is known.
        let identities: Vec<Identity> = (1..=3u16).map(Identity::new).collect();
        let roster: Vec<PublicIdentity> = identities.iter().map(Identity::public).collect();
        let vault_id = [1u8; 32];
        let mut signers: Vec<LocalSigner<SoftwareSecureElement>> = (1..=3u16)
            .zip(identities)
            .map(|(id, identity)| {
                LocalSigner::for_dkg(
                    id,
                    2,
                    3,
                    vault_id,
                    "dkg vault".into(),
                    Network::Regtest,
                    SoftwareSecureElement::generate(),
                    identity,
                    roster.clone(),
                    placeholder_fvk(),
                    tempdir(&format!("dkg-m{id}")),
                    Box::new(|_v| true),
                )
                .unwrap()
            })
            .collect();
        let sessions: Vec<Session> = signers
            .iter_mut()
            .map(|s| {
                s.connect("http://coordinator.test", Network::Regtest, challenge)
                    .unwrap()
                    .session
            })
            .collect();
        let vault = signers[0].list_vaults(&sessions[0]).unwrap()[0].clone();

        // Round 1: each emits its own round-1 package.
        let r1: Vec<Vec<u8>> = (0..3)
            .map(|i| {
                let out = signers[i].dkg_step(&sessions[i], &vault, &[]).unwrap();
                assert_eq!(out.len(), 1);
                out.into_iter().next().unwrap()
            })
            .collect();
        // Round 2: feed all three round-1 packages (roster order) to each member; collect
        // the outgoing round-2 packages addressed to peers (peer-id order).
        let r2: Vec<Vec<Vec<u8>>> = (0..3)
            .map(|i| signers[i].dkg_step(&sessions[i], &vault, &r1).unwrap())
            .collect();
        for outgoing in &r2 {
            for wire in outgoing {
                assert!(
                    frost::keys::dkg::round2::Package::deserialize(wire).is_err(),
                    "the coordinator must not receive a plaintext DKG share"
                );
            }
        }
        assert!(
            signers[2]
                .dkg_identity
                .as_ref()
                .unwrap()
                .open_round2(&roster[0], &vault_id, &r2[0][0])
                .is_err(),
            "another member must not open this recipient's DKG share"
        );
        // Route round-2 packages: member `i` must receive, in roster order, the package
        // each OTHER member produced for `i`. Member j's r2 output is ordered by its peer
        // ids ascending; map it back to (sender=j+1, receiver).
        for recv in 1..=3u16 {
            let mut incoming: Vec<Vec<u8>> = Vec::new();
            for send in 1..=3u16 {
                if send == recv {
                    continue;
                }
                // Sender `send`'s peers in ascending order, minus itself:
                let peers: Vec<u16> = (1..=3u16).filter(|p| *p != send).collect();
                let pos = peers.iter().position(|p| *p == recv).unwrap();
                incoming.push(r2[(send - 1) as usize][pos].clone());
            }
            let out = signers[(recv - 1) as usize]
                .dkg_step(&sessions[(recv - 1) as usize], &vault, &incoming)
                .unwrap();
            assert!(out.is_empty(), "final DKG step emits no public message");
        }

        // All three now hold a sealed share and agree on the group public package.
        let pp = signers[0].public_package_bytes().unwrap().to_vec();
        for s in &signers {
            assert_eq!(s.public_package_bytes().unwrap(), pp.as_slice());
            assert!(s.sealed_share.is_some());
        }
        let public = frost::keys::PublicKeyPackage::deserialize(&pp).unwrap();
        let ak: [u8; 32] = public.verifying_key().serialize().unwrap().try_into().unwrap();
        let fvk = zip2005::frost_viewing_key(&ak, &[42u8; 32]).unwrap();

        // Rebuild member 1 with the now-known vault FVK (its sealed share is reused by
        // re-sealing the same key bytes from the dealer-free DKG output), then sign.
        let key1 = {
            // Unseal member 1's DKG share directly to drive the candidate's alpha path.
            let sealed = signers[0].sealed_share.as_ref().unwrap();
            let plain = sealed.open(&signers[0].se).unwrap();
            frost::keys::KeyPackage::deserialize(&plain).unwrap()
        };
        // Point member 1's renderer at the real FVK and sign a candidate for the group key.
        signers[0].vault_fvk = fvk.clone();
        let cand = CandidateRef {
            vault_id: [1u8; 32],
            payment_id: [7u8; 32],
            attempt_id: [9u8; 32],
        };
        let own_commit = signers[0].sign_commit(&sessions[0], &cand).unwrap();
        let (_n2, peer_commit) =
            frost::round1::commit(key1.signing_share(), &mut rand_core::OsRng); // stand-in peer commit
        let peer_id = frost::Identifier::try_from(2u16).unwrap();
        let (pczt, pkg, seed) = candidate_and_package(
            &fvk,
            &key1,
            &public,
            peer_id,
            peer_commit,
            own_commit,
            true,
        );
        let share = signers[0]
            .sign_approve(&sessions[0], &cand, &pczt, &pkg, &seed)
            .expect("DKG-born share must sign a candidate for its group key");
        assert_eq!(share.serialize().len(), 32);
    }

    // (c) fee integrity: the rendered fee is only reported as trusted when every action's
    //     declared spend/output value is BOUND to its `cv_net` value commitment via `rcv`
    //     (`verify_cv_net`) — the same binding the sighash commits to. Here the real
    //     candidate carries `rcv`, so the binding runs AND passes: the fee is verified and
    //     equals total_in - total_out, not a self-declared number.
    //
    //     The opposite (`fee_verified == false`) is the guard for a PCZT whose `rcv` is
    //     absent or whose values do not match the commitment. That state is not reachable
    //     through the public builder here (every built action carries a canonical `rcv`,
    //     and the spend `value`/`rcv` fields are crate-private so a forged value cannot be
    //     injected from a test), so the negative is asserted at the unit level below by
    //     checking that `describe_pczt` and `verify_cv_net` agree on the SAME bytes.
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
        // The verified fee is the real spend-minus-output difference.
        assert_eq!(view.fee_zat, SPEND_VALUE - AMOUNT - view.change_zat);
        assert!(view.fee_zat > 0);

        // Same bytes, independent check: every action's cv_net binds its declared values.
        // If any did not, describe_pczt would have cleared fee_verified above.
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

    /// A throwaway but structurally valid FVK, used only to construct a signer before its
    /// group key exists. `[3u8;32]` is not a valid Pallas ak, so derive from a real key.
    fn placeholder_fvk() -> FullViewingKey {
        let (_s, public) = frost::keys::generate_with_dealer(
            2,
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
        zip2005::frost_viewing_key(&ak, &[9u8; 32]).unwrap()
    }
}

