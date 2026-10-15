//! Two-member signing attempt and its encrypted courier mailbox.
//! A caller must review the full exact PCZT and its locally derived sighash before `sign`.

use crate::{
    intent::Intent,
    setup_transport::{Identity, PublicIdentity},
    state::MemberDir,
};
use rand_core::{OsRng, RngCore};
use reddsa_frost::frost::redpallas as frost;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
};

/// Random per retry. The payment ID remains the canonical intent ID.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AttemptId(pub [u8; 32]);

impl AttemptId {
    pub fn random() -> Self {
        let mut id = [0; 32];
        OsRng.fill_bytes(&mut id);
        Self(id)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionContext {
    pub vault: [u8; 32],
    pub payment: [u8; 32],
    pub attempt: AttemptId,
    /// Exactly one pair, sorted by roster member ID.
    pub pair: [u16; 2],
}

impl SessionContext {
    pub fn validate(&self) -> Result<(), String> {
        if self.pair[0] < 1 || self.pair[1] > 4 || self.pair[0] >= self.pair[1] {
            return Err("signing attempt needs one distinct supported pair".into());
        }
        if self.attempt.0 == [0; 32] {
            return Err("zero signing attempt ID".into());
        }
        Ok(())
    }
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MessageKind {
    Invite = 1,
    Commitment = 2,
    Package = 3,
    Share = 4,
    Receipt = 5,
    Abort = 6,
    Consuming = 7,
}

impl TryFrom<u8> for MessageKind {
    type Error = String;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Invite),
            2 => Ok(Self::Commitment),
            3 => Ok(Self::Package),
            4 => Ok(Self::Share),
            5 => Ok(Self::Receipt),
            6 => Ok(Self::Abort),
            7 => Ok(Self::Consuming),
            _ => Err("unknown signing message type".into()),
        }
    }
}

impl MessageKind {
    pub fn max_body(self) -> usize {
        match self {
            Self::Package => 4 * 1024 * 1024,
            Self::Invite | Self::Commitment | Self::Share | Self::Consuming => 64 * 1024,
            Self::Receipt | Self::Abort => 1024,
        }
    }
}

#[derive(Clone, Debug)]
pub struct OpenedMessage {
    pub(crate) context: SessionContext,
    pub(crate) sender: u16,
    pub(crate) recipient: u16,
    pub(crate) kind: MessageKind,
    pub(crate) body: Vec<u8>,
    /// Hash of the exact authenticated envelope. A retry resends those same bytes.
    pub(crate) wire_hash: [u8; 32],
    /// Hash of vault/payment/attempt/pair/sender/recipient/type and exact plaintext.
    pub(crate) transcript_hash: [u8; 32],
}

impl OpenedMessage {
    pub fn context(&self) -> &SessionContext {
        &self.context
    }
    pub fn sender(&self) -> u16 {
        self.sender
    }
    pub fn recipient(&self) -> u16 {
        self.recipient
    }
    pub fn kind(&self) -> MessageKind {
        self.kind
    }
    pub fn body(&self) -> &[u8] {
        &self.body
    }
    pub fn wire_hash(&self) -> [u8; 32] {
        self.wire_hash
    }
    pub fn transcript_hash(&self) -> [u8; 32] {
        self.transcript_hash
    }
}

/// Append-only opaque courier. Filenames are hashes of encrypted envelopes.
pub struct Mailbox(PathBuf);

impl Mailbox {
    pub fn new(path: &Path) -> io::Result<Self> {
        fs::create_dir_all(path)?;
        Ok(Self(path.to_path_buf()))
    }

    pub fn append(&self, wire: &[u8]) -> io::Result<[u8; 32]> {
        if wire.len() > 8 * 1024 * 1024 + 53 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "oversized signing envelope",
            ));
        }
        let hash: [u8; 32] = blake3::hash(wire).into();
        let path = self.0.join(hex::encode(hash));
        let mut random = [0; 16];
        OsRng.fill_bytes(&mut random);
        let temp = self.0.join(format!(".{}.tmp", hex::encode(random)));
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut file = opts.open(&temp)?;
        file.write_all(wire)?;
        file.sync_all()?;
        let result = match fs::hard_link(&temp, &path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists && fs::read(&path)? == wire => {
                Ok(())
            }
            Err(e) => Err(e),
        };
        fs::remove_file(temp)?;
        result?;
        fs::File::open(&self.0)?.sync_all()?;
        Ok(hash)
    }

    pub fn read_for(
        &self,
        own: &Identity,
        roster: &BTreeMap<u16, PublicIdentity>,
        context: &SessionContext,
    ) -> Result<Vec<OpenedMessage>, String> {
        context.validate()?;
        let mut messages = Vec::new();
        let mut seen = BTreeSet::new();
        for entry in fs::read_dir(&self.0).map_err(|e| e.to_string())? {
            let entry = entry.map_err(|e| e.to_string())?;
            if !entry.file_type().map_err(|e| e.to_string())?.is_file()
                || entry.file_name().to_string_lossy().starts_with('.')
            {
                continue;
            }
            if entry.metadata().map_err(|e| e.to_string())?.len() > 8 * 1024 * 1024 + 53 {
                continue;
            }
            let wire = fs::read(entry.path()).map_err(|e| e.to_string())?;
            if crate::setup_transport::session_envelope(&wire).is_err() {
                continue;
            }
            if roster.get(&own.public().id) != Some(&own.public()) {
                return Err("local identity differs from authenticated roster".into());
            }
            for peer in roster
                .values()
                .filter(|p| p.id != own.public().id && context.pair.contains(&p.id))
            {
                if let Ok(opened) = own.open_session(peer, context, &wire) {
                    if seen.insert(opened.wire_hash) {
                        messages.push(opened);
                    }
                    break;
                }
            }
        }
        messages.sort_by_key(|m| m.wire_hash);
        Ok(messages)
    }
}

/// Nonces exist only in this object. Dropping it abandons an unsigned attempt.
struct LiveAttempt {
    context: SessionContext,
    own_id: frost::Identifier,
    nonces: Option<Vec<frost::round1::SigningNonces>>,
    commitments: Vec<frost::round1::SigningCommitments>,
}

/// Produced only after checking the exact candidate and every spend locally.
pub struct ReviewedBatch {
    context: SessionContext,
    group_ak: [u8; 32],
    candidate_hash: [u8; 32],
    sighash: [u8; 32],
    packages: Vec<frost::SigningPackage>,
    seeds: Vec<[u8; 32]>,
}

impl ReviewedBatch {
    pub fn candidate_hash(&self) -> [u8; 32] {
        self.candidate_hash
    }
    pub fn sighash(&self) -> [u8; 32] {
        self.sighash
    }
}

/// Recompute approval from a member's own intent, vault key, and exact PCZT bytes.
/// No sender-provided sighash or alpha is trusted. All spends pass before a token exists.
pub fn review_batch(
    context: &SessionContext,
    intent: &Intent,
    known_vault: &[u8; 32],
    key: &frost::keys::KeyPackage,
    public: &frost::keys::PublicKeyPackage,
    fvk: &orchard::keys::FullViewingKey,
    candidate_bytes: &[u8],
    commitments: &[BTreeMap<frost::Identifier, frost::round1::SigningCommitments>],
    seeds: &[[u8; 32]],
) -> Result<ReviewedBatch, String> {
    if key.verifying_key().serialize().map_err(|e| e.to_string())?
        != public
            .verifying_key()
            .serialize()
            .map_err(|e| e.to_string())?
    {
        return Err("member key differs from vault group key".into());
    }
    let own: u16 = (1..=4)
        .find(|n| frost::Identifier::try_from(*n).ok() == Some(*key.identifier()))
        .ok_or("unknown signer identifier")?;
    if !context.pair.contains(&own) {
        return Err("signer outside chosen pair".into());
    }
    review_public_candidate(
        context,
        intent,
        known_vault,
        public,
        fvk,
        candidate_bytes,
        commitments,
        seeds,
    )
}

fn review_public_candidate(
    context: &SessionContext,
    intent: &Intent,
    known_vault: &[u8; 32],
    public: &frost::keys::PublicKeyPackage,
    fvk: &orchard::keys::FullViewingKey,
    candidate_bytes: &[u8],
    commitments: &[BTreeMap<frost::Identifier, frost::round1::SigningCommitments>],
    seeds: &[[u8; 32]],
) -> Result<ReviewedBatch, String> {
    use crate::verify::{Expectations, Refusal};
    use pczt::roles::{
        low_level_signer::Signer as LowLevelSigner,
        signer::Signer,
        verifier::{OrchardError, Verifier},
    };
    context.validate()?;
    if context.vault != *known_vault || context.payment != intent.proposal_id() {
        return Err("vault or payment differs from member-approved intent".into());
    }
    if intent.input_nullifiers.is_empty()
        || intent.input_nullifiers.len() > 64
        || intent
            .input_nullifiers
            .iter()
            .copied()
            .collect::<BTreeSet<_>>()
            .len()
            != intent.input_nullifiers.len()
        || commitments.len() != intent.input_nullifiers.len()
        || seeds.len() != commitments.len()
        || intent.recipient.len() != 43
        || intent.memo.is_empty()
    {
        return Err("invalid intent or signing batch length".into());
    }
    let recipient: [u8; 43] = intent.recipient.as_slice().try_into().unwrap();
    let group_ak: [u8; 32] = public
        .verifying_key()
        .serialize()
        .map_err(|e| e.to_string())?
        .as_slice()
        .try_into()
        .map_err(|_| "group ak is not 32 bytes")?;
    if group_ak != fvk.to_bytes()[..32] {
        return Err("public package and vault viewing key differ".into());
    }
    let pair: BTreeSet<_> = context
        .pair
        .iter()
        .map(|n| frost::Identifier::try_from(*n).unwrap())
        .collect();
    for (i, set) in commitments.iter().enumerate() {
        if set.keys().copied().collect::<BTreeSet<_>>() != pair {
            return Err(format!("spend {i}: wrong signing pair"));
        }
    }
    if candidate_bytes.len() > MessageKind::Package.max_body() {
        return Err("oversized candidate".into());
    }
    let candidate =
        pczt::Pczt::parse(candidate_bytes).map_err(|e| format!("candidate parse: {e:?}"))?;
    if candidate.ironwood().anchor().is_some() || candidate.ironwood().zkproof().is_some() {
        return Err("candidate already carries anchor or proof".into());
    }
    let want = Expectations {
        input_nullifiers: intent.input_nullifiers.clone(),
        recipient,
        amount_zat: intent.amount_zat,
        memo: intent.memo.clone(),
        change_zat: intent.change_zat,
        fee_zat: intent.fee_zat,
        expiry_height: intent.expiry_height,
    };
    let checked = Verifier::new(candidate)
        .with_ironwood::<Refusal, _>(|bundle| {
            if bundle.actions().iter().any(|a| {
                intent
                    .input_nullifiers
                    .contains(&a.spend().nullifier().to_bytes())
                    && a.spend().witness().is_some()
            }) {
                return Err(OrchardError::Custom(Refusal::ExtraOutputOrPool(
                    "candidate already carries real spend witness".into(),
                )));
            }
            for (i, action) in bundle.actions().iter().enumerate() {
                action.verify_cv_net().map_err(|e| {
                    OrchardError::Custom(Refusal::OpeningsDoNotMatchCommitment(format!(
                        "action {i} value commitment: {e:?}"
                    )))
                })?;
                action.spend().verify_nullifier(Some(fvk)).map_err(|e| {
                    OrchardError::Custom(Refusal::OpeningsDoNotMatchCommitment(format!(
                        "action {i} owned spend nullifier: {e:?}"
                    )))
                })?;
                action.spend().verify_rk(Some(fvk)).map_err(|e| {
                    OrchardError::Custom(Refusal::OpeningsDoNotMatchCommitment(format!(
                        "action {i} rk: {e:?}"
                    )))
                })?;
            }
            crate::verify::check_candidate(bundle, fvk, &want).map_err(OrchardError::Custom)
        })
        .map_err(|e| format!("candidate refused: {e:?}"))?
        .finish();
    if !checked.orchard().actions().is_empty()
        || !checked.transparent().inputs().is_empty()
        || !checked.transparent().outputs().is_empty()
        || !checked.sapling().spends().is_empty()
        || !checked.sapling().outputs().is_empty()
        || *checked.global().tx_version() != 6
        || *checked.global().expiry_height() != intent.expiry_height
    {
        return Err("candidate has another pool, version, or expiry".into());
    }
    let sighash = Signer::new(checked.clone())
        .map_err(|e| format!("sighash: {e:?}"))?
        .shielded_sighash();
    let mut found = BTreeMap::new();
    LowLevelSigner::new(checked)
        .sign_ironwood_with::<pczt::roles::low_level_signer::OrchardParseError, _>(
            |_pczt, bundle, _| {
                for action in bundle.actions() {
                    found.insert(
                        action.spend().nullifier().to_bytes(),
                        (
                            *action.spend().alpha(),
                            <[u8; 32]>::from(action.spend().rk()),
                        ),
                    );
                }
                Ok(())
            },
        )
        .map_err(|e| format!("candidate spend parse: {e:?}"))?;
    let mut packages = Vec::with_capacity(commitments.len());
    for (i, (nf, set)) in intent
        .input_nullifiers
        .iter()
        .zip(commitments.iter())
        .enumerate()
    {
        let params = frost_rerandomized::RandomizedParams::regenerate_from_seed_and_commitments(
            public.verifying_key(),
            &seeds[i],
            set,
        )
        .map_err(|e| format!("spend {i}: randomizer: {e}"))?;
        let alpha_bytes: [u8; 32] = params
            .randomizer()
            .serialize()
            .as_slice()
            .try_into()
            .map_err(|_| "alpha is not 32 bytes")?;
        let alpha = crate::candidate::alpha_from_canonical_bytes(&alpha_bytes)
            .ok_or("noncanonical alpha")?;
        let expected_rk: orchard::primitives::redpallas::VerificationKey<
            orchard::primitives::redpallas::SpendAuth,
        > = orchard::keys::SpendValidatingKey::from(fvk.clone()).randomize(&alpha);
        let (actual_alpha, actual_rk) = found
            .get(nf)
            .ok_or_else(|| format!("spend {i}: candidate missing intended nullifier"))?;
        if *actual_alpha != Some(alpha)
            || *actual_rk != <[u8; 32]>::from(&expected_rk)
            || params
                .randomized_verifying_key()
                .serialize()
                .map_err(|e| e.to_string())?
                != *actual_rk
        {
            return Err(format!(
                "spend {i}: seed-derived alpha/rk differs from candidate"
            ));
        }
        packages.push(frost::SigningPackage::new(set.clone(), &sighash));
    }
    Ok(ReviewedBatch {
        context: context.clone(),
        group_ak,
        candidate_hash: blake3::hash(candidate_bytes).into(),
        sighash,
        packages,
        seeds: seeds.to_vec(),
    })
}

impl LiveAttempt {
    fn new(
        context: SessionContext,
        key: &frost::keys::KeyPackage,
        spends: usize,
    ) -> Result<Self, String> {
        context.validate()?;
        if spends == 0 || spends > 64 {
            return Err("signing attempt must have 1..=64 spends".into());
        }
        let id: u16 = (1..=4)
            .find(|n| frost::Identifier::try_from(*n).ok() == Some(*key.identifier()))
            .ok_or("key package has unknown member ID")?;
        if !context.pair.contains(&id) {
            return Err("member is not in selected pair".into());
        }
        let mut nonces = Vec::with_capacity(spends);
        let mut commitments = Vec::with_capacity(spends);
        for _ in 0..spends {
            let (nonce, commitment) = frost::round1::commit(key.signing_share(), &mut OsRng);
            nonces.push(nonce);
            commitments.push(commitment);
        }
        Ok(Self {
            context,
            own_id: *key.identifier(),
            nonces: Some(nonces),
            commitments,
        })
    }

    fn commitments(&self) -> &[frost::round1::SigningCommitments] {
        &self.commitments
    }

    /// Call only after independent full-candidate, seed/rk, and local sighash review.
    /// Consumes every nonce before any fallible signature operation; a refusal burns the attempt.
    fn sign(
        &mut self,
        key: &frost::keys::KeyPackage,
        reviewed: ReviewedBatch,
    ) -> Result<Vec<frost::round2::SignatureShare>, String> {
        let nonces = self
            .nonces
            .take()
            .ok_or("attempt nonces already consumed")?;
        if reviewed.context != self.context
            || *key.identifier() != self.own_id
            || reviewed.packages.len() != nonces.len()
            || reviewed.seeds.len() != nonces.len()
            || key.verifying_key().serialize().map_err(|e| e.to_string())? != reviewed.group_ak
        {
            return Err("signing batch does not match committed spends".into());
        }
        let pair: BTreeSet<_> = self
            .context
            .pair
            .iter()
            .map(|n| frost::Identifier::try_from(*n).unwrap())
            .collect();
        for (index, package) in reviewed.packages.iter().enumerate() {
            if package
                .signing_commitments()
                .keys()
                .copied()
                .collect::<BTreeSet<_>>()
                != pair
                || package.signing_commitments().get(&self.own_id) != Some(&self.commitments[index])
                || package.message().as_slice() != reviewed.sighash
            {
                return Err(format!(
                    "spend {index} has a wrong pair, own commitment, or sighash"
                ));
            }
        }
        reviewed
            .packages
            .iter()
            .zip(nonces.iter())
            .zip(reviewed.seeds.iter())
            .enumerate()
            .map(|(i, ((package, nonce), seed))| {
                frost_rerandomized::sign_with_randomizer_seed(package, nonce, key, seed)
                    .map_err(|e| format!("spend {i}: {e}"))
            })
            .collect()
    }
}

/// Exact candidate, both members' commitments, and library-generated seeds.
/// The wire body is encrypted as one Package message.
pub struct PackagePayload {
    pub candidate: Vec<u8>,
    pub commitments: Vec<BTreeMap<frost::Identifier, frost::round1::SigningCommitments>>,
    pub seeds: Vec<[u8; 32]>,
}

/// Values the member app must present before it calls `publish_approved`.
pub struct ReviewSummary {
    pub vault: [u8; 32],
    pub payment: [u8; 32],
    pub attempt: AttemptId,
    pub pair: [u16; 2],
    pub recipient: [u8; 43],
    pub amount_zat: u64,
    pub memo: Vec<u8>,
    pub fee_zat: u64,
    pub change_zat: u64,
    pub expiry_height: u32,
    pub input_nullifiers: Vec<[u8; 32]>,
    pub candidate_hash: [u8; 32],
    pub sighash: [u8; 32],
}

pub struct ReviewedPackage {
    summary: ReviewSummary,
    batch: ReviewedBatch,
    package_hash: [u8; 32],
    peer: u16,
}

impl ReviewedPackage {
    pub fn summary(&self) -> &ReviewSummary {
        &self.summary
    }

    /// Binds a displayed review to this exact member package; it is not member consent.
    pub fn review_token(&self) -> [u8; 32] {
        let mut hash = blake3::Hasher::new();
        hash.update(b"Loki_review_token_v1\0");
        hash.update(&self.summary.vault);
        hash.update(&self.summary.payment);
        hash.update(&self.summary.attempt.0);
        for member in self.summary.pair {
            hash.update(&member.to_be_bytes());
        }
        hash.update(&self.peer.to_be_bytes());
        hash.update(&self.summary.candidate_hash);
        hash.update(&self.summary.sighash);
        hash.update(&self.package_hash);
        hash.finalize().into()
    }

    pub fn require_review_token(&self, token: [u8; 32]) -> Result<(), String> {
        if self.review_token() != token {
            return Err("reviewed signing package changed; review again".into());
        }
        Ok(())
    }
}

impl PackagePayload {
    pub fn encode(&self, context: &SessionContext) -> Result<Vec<u8>, String> {
        context.validate()?;
        if self.candidate.is_empty()
            || self.commitments.is_empty()
            || self.commitments.len() > 64
            || self.commitments.len() != self.seeds.len()
        {
            return Err("invalid signing package batch".into());
        }
        let mut out = Vec::new();
        out.push(1);
        out.extend_from_slice(&(self.candidate.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.candidate);
        out.extend_from_slice(&(self.commitments.len() as u16).to_be_bytes());
        for (set, seed) in self.commitments.iter().zip(&self.seeds) {
            if set.len() != 2 {
                return Err("package must name exactly two commitments".into());
            }
            out.extend_from_slice(seed);
            for member in context.pair {
                let id = frost::Identifier::try_from(member).map_err(|e| e.to_string())?;
                let raw = set
                    .get(&id)
                    .ok_or("package commitment pair differs")?
                    .serialize()
                    .map_err(|e| e.to_string())?;
                if raw.len() > u16::MAX as usize {
                    return Err("oversized commitment".into());
                }
                out.extend_from_slice(&(raw.len() as u16).to_be_bytes());
                out.extend_from_slice(&raw);
            }
        }
        if out.len() > MessageKind::Package.max_body() {
            return Err("oversized package message".into());
        }
        Ok(out)
    }

    pub fn decode(context: &SessionContext, body: &[u8]) -> Result<Self, String> {
        context.validate()?;
        if body.len() < 7 || body.len() > MessageKind::Package.max_body() || body[0] != 1 {
            return Err("invalid signing package version or length".into());
        }
        let mut at = 1;
        let candidate_len = u32::from_be_bytes(body[at..at + 4].try_into().unwrap()) as usize;
        at += 4;
        if candidate_len == 0 || at + candidate_len + 2 > body.len() {
            return Err("truncated signing candidate".into());
        }
        let candidate = body[at..at + candidate_len].to_vec();
        at += candidate_len;
        let count = u16::from_be_bytes(body[at..at + 2].try_into().unwrap()) as usize;
        at += 2;
        if count == 0 || count > 64 {
            return Err("invalid spend count".into());
        }
        let mut commitments = Vec::with_capacity(count);
        let mut seeds = Vec::with_capacity(count);
        for _ in 0..count {
            if at + 32 > body.len() {
                return Err("truncated randomizer seed".into());
            }
            seeds.push(body[at..at + 32].try_into().unwrap());
            at += 32;
            let mut set = BTreeMap::new();
            for member in context.pair {
                if at + 2 > body.len() {
                    return Err("truncated commitment length".into());
                }
                let len = u16::from_be_bytes(body[at..at + 2].try_into().unwrap()) as usize;
                at += 2;
                if len == 0 || at + len > body.len() {
                    return Err("truncated commitment".into());
                }
                let parsed = frost::round1::SigningCommitments::deserialize(&body[at..at + len])
                    .map_err(|e| format!("invalid commitment: {e}"))?;
                set.insert(
                    frost::Identifier::try_from(member).map_err(|e| e.to_string())?,
                    parsed,
                );
                at += len;
            }
            commitments.push(set);
        }
        if at != body.len() {
            return Err("trailing signing package bytes".into());
        }
        Ok(Self {
            candidate,
            commitments,
            seeds,
        })
    }
}

/// Parse one authenticated Commitment packet from the selected peer.
pub fn commitments_from_message(
    context: &SessionContext,
    message: &OpenedMessage,
    spends: usize,
) -> Result<Vec<frost::round1::SigningCommitments>, String> {
    if message.context != *context
        || message.kind != MessageKind::Commitment
        || !context.pair.contains(&message.sender)
        || !context.pair.contains(&message.recipient)
        || message.sender == message.recipient
        || message.body.len() < 3
        || message.body[0] != 1
        || u16::from_be_bytes(message.body[1..3].try_into().unwrap()) as usize != spends
    {
        return Err("commitment packet differs from selected attempt or spend count".into());
    }
    let mut at = 3;
    let mut commitments = Vec::with_capacity(spends);
    for _ in 0..spends {
        if at + 2 > message.body.len() {
            return Err("truncated commitment length".into());
        }
        let len = u16::from_be_bytes(message.body[at..at + 2].try_into().unwrap()) as usize;
        at += 2;
        if len == 0 || at + len > message.body.len() {
            return Err("truncated commitment".into());
        }
        commitments.push(
            frost::round1::SigningCommitments::deserialize(&message.body[at..at + len])
                .map_err(|e| format!("invalid commitment: {e}"))?,
        );
        at += len;
    }
    if at != message.body.len() {
        return Err("trailing commitment bytes".into());
    }
    Ok(commitments)
}

/// Regtest member signing path: review, consume volatile nonces, seal exact shares, publish.
/// A crash before the sealed outbox exists abandons the attempt; after that, `recover_share`
/// can resend only the exact encrypted wire and cannot recreate nonces.
pub struct SigningSession {
    context: SessionContext,
    approved_intent: Intent,
    known_vault: [u8; 32],
    own: Identity,
    key: frost::keys::KeyPackage,
    public: frost::keys::PublicKeyPackage,
    fvk: orchard::keys::FullViewingKey,
    store: AttemptStore,
    live: LiveAttempt,
    _lock: Option<fs::File>,
    witness_pins: Option<WitnessPins>,
}

/// (relay public key, relay run ID, mailbox), fixed before commitments are published.
pub type WitnessPins = [([u8; 32], [u8; 32], [u8; 32]); 2];

fn valid_witness_pins(pins: WitnessPins) -> bool {
    pins[0].0 != pins[1].0
        && pins[0].1 != pins[1].1
        && pins[0].2 != pins[1].2
        && pins
            .iter()
            .all(|(key, run, mailbox)| *key != [0; 32] && *run != [0; 32] && *mailbox != [0; 32])
}

/// Implementations must verify fresh signed receipts from two fixed, distinct relay
/// identities. Operators must be checked separately. A duplicate claim is a refusal.
pub trait NonceWitness {
    fn pins(&self) -> WitnessPins;
    fn claim(&mut self, cid: [u8; 32], encrypted_record: &[u8]) -> Result<(), String>;
}

impl SigningSession {
    pub fn begin(
        root: &Path,
        context: SessionContext,
        known_vault: &[u8; 32],
        approved_intent: Intent,
        own: Identity,
        key: frost::keys::KeyPackage,
        public: frost::keys::PublicKeyPackage,
        fvk: orchard::keys::FullViewingKey,
        spends: usize,
    ) -> Result<Self, String> {
        if context.vault != *known_vault || context.payment != approved_intent.proposal_id() {
            return Err("attempt differs from locally approved vault or intent".into());
        }
        let id = own.public().id;
        if frost::Identifier::try_from(id).map_err(|e| e.to_string())? != *key.identifier() {
            return Err("identity and FROST key belong to different members".into());
        }
        let live = LiveAttempt::new(context.clone(), &key, spends)?;
        let store = AttemptStore::new(root, &context, id)?;
        Ok(Self {
            context,
            approved_intent,
            known_vault: *known_vault,
            own,
            key,
            public,
            fvk,
            store,
            live,
            _lock: None,
            witness_pins: None,
        })
    }

    pub fn begin_sealed(
        root: &Path,
        context: SessionContext,
        known_vault: &[u8; 32],
        approved_intent: Intent,
        own: Identity,
        key: frost::keys::KeyPackage,
        public: frost::keys::PublicKeyPackage,
        fvk: orchard::keys::FullViewingKey,
        spends: usize,
        passphrase: &str,
        pins: WitnessPins,
    ) -> Result<Self, String> {
        if !valid_witness_pins(pins) {
            return Err("two distinct nonzero relay identities required".into());
        }
        let mut session = Self::begin(
            root,
            context,
            known_vault,
            approved_intent,
            own,
            key,
            public,
            fvk,
            spends,
        )?;
        session._lock = Some(session.store.signer_lock()?);
        session.store.save_nonces(&session.live, passphrase, pins)?;
        session.witness_pins = Some(pins);
        Ok(session)
    }

    pub fn reopen_sealed(
        root: &Path,
        context: SessionContext,
        known_vault: &[u8; 32],
        approved_intent: Intent,
        own: Identity,
        key: frost::keys::KeyPackage,
        public: frost::keys::PublicKeyPackage,
        fvk: orchard::keys::FullViewingKey,
        passphrase: &str,
    ) -> Result<Self, String> {
        if context.vault != *known_vault
            || context.payment != approved_intent.proposal_id()
            || frost::Identifier::try_from(own.public().id).map_err(|e| e.to_string())?
                != *key.identifier()
        {
            return Err("attempt differs from member key or approved intent".into());
        }
        let store = AttemptStore::reopen(root, &context, own.public().id)?;
        let lock = store.signer_lock()?;
        if store.dir.exists("decision") {
            return Err(
                "attempt already consumed; resend saved shares or start a new attempt".into(),
            );
        }
        let (live, pins) = store.read_nonces(&context, &key, passphrase)?;
        Ok(Self {
            context,
            approved_intent,
            known_vault: *known_vault,
            own,
            key,
            public,
            fvk,
            store,
            live,
            _lock: Some(lock),
            witness_pins: Some(pins),
        })
    }

    pub fn commitments(&self) -> &[frost::round1::SigningCommitments] {
        self.live.commitments()
    }

    /// Save one exact ciphertext for each other roster member before delivery.
    pub fn publish_package_to_roster(
        &self,
        roster: &BTreeMap<u16, PublicIdentity>,
        package: &PackagePayload,
        mailbox: &Mailbox,
        passphrase: &str,
    ) -> Result<Vec<[u8; 32]>, String> {
        let own = self.own.public();
        if !matches!(roster.len(), 3 | 4)
            || roster.keys().copied().collect::<Vec<_>>()
                != (1..=roster.len() as u16).collect::<Vec<_>>()
            || self.context.pair.iter().any(|id| !roster.contains_key(id))
            || roster.get(&own.id) != Some(&own)
        {
            return Err("package publisher differs from certified roster".into());
        }
        let body = package.encode(&self.context)?;
        let digest: [u8; 32] = blake3::hash(&body).into();
        if self.store.dir.exists("package.sealed") {
            return self.store.publish_package(mailbox, passphrase, &digest);
        }
        let reviewed = review_batch(
            &self.context,
            &self.approved_intent,
            &self.known_vault,
            &self.key,
            &self.public,
            &self.fvk,
            &package.candidate,
            &package.commitments,
            &package.seeds,
        )?;
        for (i, signing_package) in reviewed.packages.iter().enumerate() {
            if signing_package
                .signing_commitments()
                .get(self.key.identifier())
                != Some(&self.live.commitments[i])
            {
                return Err(format!(
                    "spend {i}: driver package differs from own commitment"
                ));
            }
        }
        let peer_id = self
            .context
            .pair
            .iter()
            .copied()
            .find(|id| *id != own.id)
            .unwrap();
        let peers = std::iter::once(roster.get(&peer_id).unwrap()).chain(
            roster
                .values()
                .filter(|p| !self.context.pair.contains(&p.id)),
        );
        let wires = peers
            .map(|peer| {
                self.own
                    .seal_session(peer, &self.context, MessageKind::Package, &body)
            })
            .collect::<Result<Vec<_>, _>>()?;
        self.store.save_package(&wires, &digest, passphrase)?;
        self.store.publish_package(mailbox, passphrase, &digest)
    }

    pub fn publish_commitments(
        &self,
        peer: &PublicIdentity,
        mailbox: &Mailbox,
    ) -> Result<[u8; 32], String> {
        if !self.context.pair.contains(&peer.id) || peer.id == self.own.public().id {
            return Err("commitment recipient is not selected peer".into());
        }
        let mut body = Vec::new();
        body.push(1);
        body.extend_from_slice(&(self.live.commitments.len() as u16).to_be_bytes());
        for commitment in &self.live.commitments {
            let raw = commitment.serialize().map_err(|e| e.to_string())?;
            body.extend_from_slice(&(raw.len() as u16).to_be_bytes());
            body.extend_from_slice(&raw);
        }
        let wire = self
            .own
            .seal_session(peer, &self.context, MessageKind::Commitment, &body)?;
        mailbox.append(&wire).map_err(|e| e.to_string())
    }

    pub fn review_package(
        &self,
        package_message: &OpenedMessage,
        peer: &PublicIdentity,
    ) -> Result<ReviewedPackage, String> {
        let own = self.own.public().id;
        let from_peer = package_message.sender == peer.id && package_message.recipient == own;
        let own_outbound = package_message.sender == own && package_message.recipient == peer.id;
        if package_message.context != self.context
            || package_message.kind != MessageKind::Package
            || !(from_peer || own_outbound)
            || peer.id == self.own.public().id
            || !self.context.pair.contains(&peer.id)
        {
            return Err("package is not from selected peer for this attempt".into());
        }
        let package = PackagePayload::decode(&self.context, &package_message.body)?;
        let reviewed = review_batch(
            &self.context,
            &self.approved_intent,
            &self.known_vault,
            &self.key,
            &self.public,
            &self.fvk,
            &package.candidate,
            &package.commitments,
            &package.seeds,
        )?;
        let recipient = self
            .approved_intent
            .recipient
            .as_slice()
            .try_into()
            .unwrap();
        let summary = ReviewSummary {
            vault: self.context.vault,
            payment: self.context.payment,
            attempt: self.context.attempt,
            pair: self.context.pair,
            recipient,
            amount_zat: self.approved_intent.amount_zat,
            memo: self.approved_intent.memo.clone(),
            fee_zat: self.approved_intent.fee_zat,
            change_zat: self.approved_intent.change_zat,
            expiry_height: self.approved_intent.expiry_height,
            input_nullifiers: self.approved_intent.input_nullifiers.clone(),
            candidate_hash: reviewed.candidate_hash,
            sighash: reviewed.sighash,
        };
        Ok(ReviewedPackage {
            summary,
            batch: reviewed,
            package_hash: package_message.transcript_hash,
            peer: peer.id,
        })
    }

    /// Called only after the local member explicitly confirms `reviewed.summary()`.
    /// A saved share can be republished byte-for-byte; a conflicting package is refused.
    pub fn publish_approved(
        &mut self,
        reviewed: ReviewedPackage,
        peer: &PublicIdentity,
        finishers: &[PublicIdentity],
        mailbox: &Mailbox,
        passphrase: &str,
    ) -> Result<[u8; 32], String> {
        if self._lock.is_some() {
            return Err("persisted nonces require two relay witness receipts".into());
        }
        if reviewed.batch.context != self.context
            || reviewed.peer != peer.id
            || peer.id == self.own.public().id
            || !self.context.pair.contains(&peer.id)
            || !matches!(finishers.len(), 1 | 2)
            || finishers.iter().any(|finisher| {
                !(1..=4).contains(&finisher.id) || self.context.pair.contains(&finisher.id)
            })
            || finishers
                .iter()
                .map(|f| f.id)
                .collect::<BTreeSet<_>>()
                .len()
                != finishers.len()
        {
            return Err("reviewed package or finisher belongs to another attempt".into());
        }
        if self.store.dir.exists("share.sealed") {
            let (candidate_hash, package_hash, _) = self.store.resend_share(passphrase)?;
            if candidate_hash != reviewed.batch.candidate_hash
                || package_hash != reviewed.package_hash
            {
                return Err("conflicting package after share release".into());
            }
            return self.store.publish(mailbox, passphrase);
        }
        let ReviewedPackage {
            batch,
            package_hash,
            ..
        } = reviewed;
        let reviewed = batch;
        let candidate_hash = reviewed.candidate_hash;
        let sighash = reviewed.sighash;
        let shares = self.live.sign(&self.key, reviewed)?;
        let mut body = Vec::new();
        body.push(1);
        body.extend_from_slice(&candidate_hash);
        body.extend_from_slice(&package_hash);
        body.extend_from_slice(&sighash);
        body.extend_from_slice(&(shares.len() as u16).to_be_bytes());
        for share in shares {
            let raw = share.serialize();
            body.extend_from_slice(&(raw.len() as u16).to_be_bytes());
            body.extend_from_slice(&raw);
        }
        let wires = std::iter::once(peer)
            .chain(finishers.iter())
            .map(|recipient| {
                self.own
                    .seal_session(recipient, &self.context, MessageKind::Share, &body)
            })
            .collect::<Result<Vec<_>, _>>()?;
        self.store
            .save_share(&wires, &candidate_hash, &package_hash, passphrase)?;
        self.store.publish(mailbox, passphrase)
    }

    /// Relay-backed approval for a persisted attempt. Both claims must be fresh
    /// before the local decision is fsynced and any signature share is computed.
    pub fn publish_approved_secured(
        &mut self,
        reviewed: ReviewedPackage,
        peer: &PublicIdentity,
        finisher: &PublicIdentity,
        mailbox: &Mailbox,
        passphrase: &str,
        witness: &mut impl NonceWitness,
    ) -> Result<[u8; 32], String> {
        if self.public.verifying_shares().len() != 3 {
            return Err("four-member approval requires the complete certified roster".into());
        }
        self.publish_approved_secured_to_finishers(
            reviewed, peer, std::slice::from_ref(finisher), mailbox, passphrase, witness,
        )
    }

    /// The caller supplies its certified roster. Validate its complete audience before
    /// claiming nonces, then compute each share once and persist every recipient copy.
    pub fn publish_approved_secured_to_roster(
        &mut self,
        reviewed: ReviewedPackage,
        peer: &PublicIdentity,
        roster: &BTreeMap<u16, PublicIdentity>,
        mailbox: &Mailbox,
        passphrase: &str,
        witness: &mut impl NonceWitness,
    ) -> Result<[u8; 32], String> {
        let own = self.own.public();
        if !matches!(roster.len(), 3 | 4)
            || roster.keys().copied().collect::<Vec<_>>()
                != (1..=roster.len() as u16).collect::<Vec<_>>()
            || roster.get(&own.id) != Some(&own)
            || roster.get(&peer.id) != Some(peer)
            || self.context.pair.iter().any(|id| !roster.contains_key(id))
            || roster.iter().any(|(id, identity)| {
                *id != identity.id || identity.signing == [0; 32] || identity.encryption == [0; 32]
            })
            || roster.values().any(|identity| {
                roster.values().any(|other| identity.id != other.id &&
                    (identity.signing == other.signing || identity.encryption == other.encryption))
            })
            || self.public.verifying_shares().len() != roster.len()
            || roster.keys().any(|id| {
                frost::Identifier::try_from(*id).map_or(true, |identifier| {
                    !self.public.verifying_shares().contains_key(&identifier)
                })
            })
        {
            return Err("approval audience differs from certified roster".into());
        }
        let finishers = roster.values()
            .filter(|identity| !self.context.pair.contains(&identity.id))
            .cloned().collect::<Vec<_>>();
        self.publish_approved_secured_to_finishers(
            reviewed, peer, &finishers, mailbox, passphrase, witness,
        )
    }

    fn publish_approved_secured_to_finishers(
        &mut self,
        reviewed: ReviewedPackage,
        peer: &PublicIdentity,
        finishers: &[PublicIdentity],
        mailbox: &Mailbox,
        passphrase: &str,
        witness: &mut impl NonceWitness,
    ) -> Result<[u8; 32], String> {
        if self._lock.is_none()
            || self.witness_pins != Some(witness.pins())
            || reviewed.batch.context != self.context
            || reviewed.peer != peer.id
            || peer.id == self.own.public().id
            || !self.context.pair.contains(&peer.id)
            || !matches!(finishers.len(), 1 | 2)
            || finishers.iter().any(|finisher| {
                !(1..=4).contains(&finisher.id) || self.context.pair.contains(&finisher.id)
            })
        {
            return Err("invalid persisted signing attempt or peer".into());
        }
        if self.store.dir.exists("decision") || self.store.dir.exists("share.sealed") {
            return Err("attempt already consumed; resend saved shares".into());
        }
        let candidate_hash = reviewed.batch.candidate_hash;
        let package_hash = reviewed.package_hash;
        let sighash = reviewed.batch.sighash;
        for (i, package) in reviewed.batch.packages.iter().enumerate() {
            let own_commitment = package
                .signing_commitments()
                .get(self.key.identifier())
                .ok_or("own commitment absent")?;
            if own_commitment != &self.live.commitments[i] {
                return Err(format!(
                    "spend {i}: own nonce differs from reviewed package"
                ));
            }
            let raw = own_commitment.serialize().map_err(|e| e.to_string())?;
            let mut hash = blake3::Hasher::new();
            hash.update(b"Loki_nonce_cid_v1\0");
            hash.update(&self.context.vault);
            hash.update(&self.live.own_id.serialize());
            hash.update(&raw);
            let cid: [u8; 32] = hash.finalize().into();
            let mut record = Vec::new();
            record.extend_from_slice(&cid);
            record.extend_from_slice(&candidate_hash);
            record.extend_from_slice(&package_hash);
            record.extend_from_slice(&sighash);
            record.extend_from_slice(&(i as u16).to_be_bytes());
            record.extend_from_slice(&reviewed.batch.seeds[i]);
            for commitments in package.signing_commitments().values() {
                let raw = commitments.serialize().map_err(|e| e.to_string())?;
                record.extend_from_slice(&(raw.len() as u16).to_be_bytes());
                record.extend_from_slice(&raw);
            }
            let wire =
                self.own
                    .seal_session(peer, &self.context, MessageKind::Consuming, &record)?;
            witness.claim(cid, &wire)?;
        }
        self.store.decide(b'R')?;
        self.store.remove_nonces()?;
        let shares = self.live.sign(&self.key, reviewed.batch)?;
        let mut body = Vec::new();
        body.push(1);
        body.extend_from_slice(&candidate_hash);
        body.extend_from_slice(&package_hash);
        body.extend_from_slice(&sighash);
        body.extend_from_slice(&(shares.len() as u16).to_be_bytes());
        for share in shares {
            let raw = share.serialize();
            body.extend_from_slice(&(raw.len() as u16).to_be_bytes());
            body.extend_from_slice(&raw);
        }
        let wires = std::iter::once(peer)
            .chain(finishers.iter())
            .map(|recipient| {
                self.own.seal_session(recipient, &self.context, MessageKind::Share, &body)
            })
            .collect::<Result<Vec<_>, _>>()?;
        self.store
            .save_share_after_decision(&wires, &candidate_hash, &package_hash, passphrase)?;
        self.store.publish(mailbox, passphrase)
    }

    pub fn abort(self) -> Result<(), String> {
        self.store.abort()
    }

    pub fn recover_share(
        root: &Path,
        context: &SessionContext,
        own: u16,
        passphrase: &str,
        mailbox: &Mailbox,
    ) -> Result<[u8; 32], String> {
        AttemptStore::reopen(root, context, own)?.publish(mailbox, passphrase)
    }

    /// Read only the two original ciphertext copies; no nonce or signing call is possible.
    pub fn saved_share_wires(
        root: &Path,
        context: &SessionContext,
        own: u16,
        passphrase: &str,
    ) -> Result<Vec<Vec<u8>>, String> {
        let (_, _, wires) = AttemptStore::reopen(root, context, own)?.resend_share(passphrase)?;
        Ok(wires)
    }

    pub fn saved_package_wires(
        root: &Path,
        context: &SessionContext,
        own: u16,
        passphrase: &str,
    ) -> Result<Vec<Vec<u8>>, String> {
        let (_, wires) = AttemptStore::reopen(root, context, own)?.resend_package(passphrase)?;
        Ok(wires)
    }
}

fn decode_share_body(
    member: u16,
    body: &[u8],
    candidate_hash: &[u8; 32],
    sighash: &[u8; 32],
    spends: usize,
) -> Result<Vec<frost::round2::SignatureShare>, String> {
    if body.len() < 99 || body[0] != 1 || body[1..33] != *candidate_hash || body[65..97] != *sighash
    {
        return Err("share packet differs from exact candidate or sighash".into());
    }
    let count = u16::from_be_bytes(body[97..99].try_into().unwrap()) as usize;
    if count != spends {
        return Err("share packet has wrong spend count".into());
    }
    let mut at = 99;
    let mut shares = Vec::with_capacity(count);
    for _ in 0..count {
        if at + 2 > body.len() {
            return Err("truncated share length".into());
        }
        let len = u16::from_be_bytes(body[at..at + 2].try_into().unwrap()) as usize;
        at += 2;
        if len == 0 || at + len > body.len() {
            return Err("truncated signature share".into());
        }
        shares.push(
            frost::round2::SignatureShare::deserialize(&body[at..at + len])
                .map_err(|e| format!("member {member}: invalid signature share: {e}"))?,
        );
        at += len;
    }
    if at != body.len() {
        return Err("trailing share bytes".into());
    }
    Ok(shares)
}

/// Secret-free finisher step. Verifies the full candidate and both share batches,
/// then applies valid signatures. The caller builds its own chain witness/anchor later.
pub fn aggregate_and_apply(
    context: &SessionContext,
    intent: &Intent,
    known_vault: &[u8; 32],
    public: &frost::keys::PublicKeyPackage,
    fvk: &orchard::keys::FullViewingKey,
    package: &PackagePayload,
    share_messages: &[OpenedMessage; 2],
) -> Result<(pczt::Pczt, [u8; 32], Vec<usize>), String> {
    use pczt::roles::signer::Signer;
    let reviewed = review_public_candidate(
        context,
        intent,
        known_vault,
        public,
        fvk,
        &package.candidate,
        &package.commitments,
        &package.seeds,
    )?;
    let mut by_member = BTreeMap::new();
    for message in share_messages {
        if message.context != *context
            || message.kind != MessageKind::Share
            || !context.pair.contains(&message.sender)
        {
            return Err("share comes from another attempt or signer".into());
        }
        let shares = decode_share_body(
            message.sender,
            &message.body,
            &reviewed.candidate_hash,
            &reviewed.sighash,
            reviewed.packages.len(),
        )?;
        if by_member.insert(message.sender, shares).is_some() {
            return Err("duplicate share sender".into());
        }
    }
    if by_member.keys().copied().collect::<Vec<_>>() != context.pair {
        return Err("incomplete selected signer pair".into());
    }
    let candidate =
        pczt::Pczt::parse(&package.candidate).map_err(|e| format!("candidate parse: {e:?}"))?;
    let mut signer =
        Signer::new(candidate.clone()).map_err(|e| format!("candidate sighash: {e:?}"))?;
    let mut indices = Vec::with_capacity(reviewed.packages.len());
    for (i, (signing_package, commitments)) in reviewed
        .packages
        .iter()
        .zip(package.commitments.iter())
        .enumerate()
    {
        let mut shares = BTreeMap::new();
        for member in context.pair {
            let id = frost::Identifier::try_from(member).map_err(|e| e.to_string())?;
            shares.insert(id, by_member[&member][i].clone());
        }
        let params = frost_rerandomized::RandomizedParams::regenerate_from_seed_and_commitments(
            public.verifying_key(),
            &package.seeds[i],
            commitments,
        )
        .map_err(|e| format!("spend {i}: randomizer: {e}"))?;
        let sig = frost_rerandomized::aggregate(signing_package, &shares, public, &params)
            .map_err(|e| {
                let culprits = e
                    .culprits()
                    .iter()
                    .filter_map(|id| {
                        context
                            .pair
                            .iter()
                            .find(|n| frost::Identifier::try_from(**n).ok() == Some(*id))
                    })
                    .map(u16::to_string)
                    .collect::<Vec<_>>()
                    .join(",");
                format!("spend {i}: invalid share from member {culprits}: {e}")
            })?;
        params
            .randomized_verifying_key()
            .verify(&reviewed.sighash, &sig)
            .map_err(|e| format!("spend {i}: invalid aggregate: {e}"))?;
        let bytes: [u8; 64] = sig
            .serialize()
            .map_err(|e| e.to_string())?
            .as_slice()
            .try_into()
            .map_err(|_| "signature is not 64 bytes")?;
        let orchard_sig = orchard::primitives::redpallas::Signature::<
            orchard::primitives::redpallas::SpendAuth,
        >::from(bytes);
        let index = candidate
            .ironwood()
            .actions()
            .iter()
            .position(|a| a.spend().nullifier() == &intent.input_nullifiers[i])
            .ok_or_else(|| format!("spend {i}: intended input missing"))?;
        if indices.contains(&index) {
            return Err("duplicate signed input".into());
        }
        signer
            .apply_ironwood_signature(index, orchard_sig)
            .map_err(|e| format!("spend {i}: apply signature: {e:?}"))?;
        indices.push(index);
    }
    Ok((signer.finish(), reviewed.sighash, indices))
}

/// Member-local monotone record. A reopened `Started` record has no nonce and is abandoned.
struct AttemptStore {
    dir: MemberDir,
}

fn read_saved_wire(raw: &[u8], at: &mut usize) -> Result<Vec<u8>, String> {
    if *at + 4 > raw.len() {
        return Err("truncated sealed outbox length".into());
    }
    let len = u32::from_be_bytes(raw[*at..*at + 4].try_into().unwrap()) as usize;
    *at += 4;
    if *at + len > raw.len() {
        return Err("truncated sealed outbox wire".into());
    }
    let wire = raw[*at..*at + len].to_vec();
    *at += len;
    crate::setup_transport::session_envelope(&wire)?;
    Ok(wire)
}

impl AttemptStore {
    fn signer_lock(&self) -> Result<fs::File, String> {
        let lock = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(self.dir.path().join("signer.lock"))
            .map_err(|e| e.to_string())?;
        lock.try_lock()
            .map_err(|_| "signer already open in another process".to_string())?;
        Ok(lock)
    }

    fn save_nonces(
        &self,
        live: &LiveAttempt,
        passphrase: &str,
        pins: WitnessPins,
    ) -> Result<(), String> {
        let mut raw = zeroize::Zeroizing::new(Vec::new());
        raw.push(2);
        for (key, run, mailbox) in pins {
            raw.extend_from_slice(&key);
            raw.extend_from_slice(&run);
            raw.extend_from_slice(&mailbox);
        }
        raw.extend_from_slice(&(live.commitments.len() as u16).to_be_bytes());
        for nonce in live.nonces.as_ref().ok_or("nonces already consumed")? {
            let serialized = zeroize::Zeroizing::new(nonce.serialize().map_err(|e| e.to_string())?);
            let length = u16::try_from(serialized.len()).map_err(|_| "oversized nonce")?;
            raw.extend_from_slice(&length.to_be_bytes());
            raw.extend_from_slice(&serialized);
        }
        self.dir
            .write_sealed("nonces.sealed", &raw, passphrase)
            .map_err(|e| e.to_string())
    }

    fn read_nonces(
        &self,
        context: &SessionContext,
        key: &frost::keys::KeyPackage,
        passphrase: &str,
    ) -> Result<(LiveAttempt, WitnessPins), String> {
        let raw = zeroize::Zeroizing::new(
            self.dir
                .read_sealed("nonces.sealed", passphrase)
                .map_err(|e| e.to_string())?,
        );
        // v1 omitted mailbox IDs; reopening those nonce records could reuse a CID on
        // a newly provisioned mailbox. Discard the attempt and start with fresh nonces.
        if raw.len() < 195 || raw[0] != 2 {
            return Err("invalid sealed nonce record".into());
        }
        let pins = [
            (
                raw[1..33].try_into().unwrap(),
                raw[33..65].try_into().unwrap(),
                raw[65..97].try_into().unwrap(),
            ),
            (
                raw[97..129].try_into().unwrap(),
                raw[129..161].try_into().unwrap(),
                raw[161..193].try_into().unwrap(),
            ),
        ];
        if !valid_witness_pins(pins) {
            return Err("invalid sealed relay identities".into());
        }
        let count = u16::from_be_bytes(raw[193..195].try_into().unwrap()) as usize;
        if !(1..=64).contains(&count) {
            return Err("invalid sealed nonce count".into());
        }
        let mut at = 195;
        let mut nonces = Vec::with_capacity(count);
        let mut commitments = Vec::with_capacity(count);
        for _ in 0..count {
            if at + 2 > raw.len() {
                return Err("truncated sealed nonce".into());
            }
            let length = u16::from_be_bytes(raw[at..at + 2].try_into().unwrap()) as usize;
            at += 2;
            if length == 0 || at + length > raw.len() {
                return Err("truncated sealed nonce".into());
            }
            let nonce = frost::round1::SigningNonces::deserialize(&raw[at..at + length])
                .map_err(|e| format!("invalid sealed nonce: {e}"))?;
            commitments.push(frost::round1::SigningCommitments::from(&nonce));
            nonces.push(nonce);
            at += length;
        }
        if at != raw.len() {
            return Err("trailing sealed nonce bytes".into());
        }
        let own_id = *key.identifier();
        if !context
            .pair
            .iter()
            .any(|id| frost::Identifier::try_from(*id).ok() == Some(own_id))
        {
            return Err("nonce owner differs from pair".into());
        }
        Ok((
            LiveAttempt {
                context: context.clone(),
                own_id,
                nonces: Some(nonces),
                commitments,
            },
            pins,
        ))
    }

    fn remove_nonces(&self) -> Result<(), String> {
        fs::remove_file(self.dir.path().join("nonces.sealed")).map_err(|e| e.to_string())?;
        fs::File::open(self.dir.path())
            .and_then(|file| file.sync_all())
            .map_err(|e| e.to_string())
    }
    fn new(root: &Path, context: &SessionContext, own: u16) -> Result<Self, String> {
        context.validate()?;
        if !context.pair.contains(&own) {
            return Err("member is not in selected pair".into());
        }
        let parent = root.join(hex::encode(context.payment));
        fs::create_dir_all(&parent).map_err(|e| e.to_string())?;
        let name = hex::encode(context.attempt.0);
        let dir = MemberDir::create(&parent, &name).map_err(|e| e.to_string())?;
        let state = dir.path().join("started");
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(state)
            .map_err(|e| format!("attempt already exists: {e}"))?;
        file.write_all(&context.vault).map_err(|e| e.to_string())?;
        file.write_all(&context.pair[0].to_be_bytes())
            .map_err(|e| e.to_string())?;
        file.write_all(&context.pair[1].to_be_bytes())
            .map_err(|e| e.to_string())?;
        file.write_all(&own.to_be_bytes())
            .map_err(|e| e.to_string())?;
        file.sync_all().map_err(|e| e.to_string())?;
        Ok(Self { dir })
    }

    fn reopen(root: &Path, context: &SessionContext, own: u16) -> Result<Self, String> {
        context.validate()?;
        if !context.pair.contains(&own) {
            return Err("member is not in selected pair".into());
        }
        let dir = MemberDir::open(
            &root.join(hex::encode(context.payment)),
            &hex::encode(context.attempt.0),
        );
        let mut expected = Vec::with_capacity(38);
        expected.extend_from_slice(&context.vault);
        for id in context.pair {
            expected.extend_from_slice(&id.to_be_bytes());
        }
        expected.extend_from_slice(&own.to_be_bytes());
        if fs::read(dir.path().join("started")).map_err(|e| e.to_string())? != expected {
            return Err("saved attempt differs from local vault, pair, or member".into());
        }
        Ok(Self { dir })
    }

    fn save_package(
        &self,
        wires: &[Vec<u8>],
        digest: &[u8; 32],
        passphrase: &str,
    ) -> Result<(), String> {
        if !matches!(wires.len(), 2 | 3) {
            return Err("package needs one copy for each other member".into());
        }
        let mut out = Vec::with_capacity(40 + wires.iter().map(Vec::len).sum::<usize>());
        out.extend_from_slice(digest);
        for wire in wires {
            crate::setup_transport::session_envelope(wire)?;
            out.extend_from_slice(&(wire.len() as u32).to_be_bytes());
            out.extend_from_slice(wire);
        }
        self.dir
            .write_sealed("package.sealed", &out, passphrase)
            .map_err(|e| e.to_string())
    }

    fn resend_package(&self, passphrase: &str) -> Result<([u8; 32], Vec<Vec<u8>>), String> {
        let raw = self
            .dir
            .read_sealed("package.sealed", passphrase)
            .map_err(|e| e.to_string())?;
        if raw.len() < 40 {
            return Err("corrupt sealed package outbox".into());
        }
        let mut at = 32;
        let mut wires = Vec::new();
        while at < raw.len() && wires.len() < 4 {
            wires.push(read_saved_wire(&raw, &mut at)?);
        }
        if at != raw.len() || !matches!(wires.len(), 2 | 3) {
            return Err("invalid sealed package copy count".into());
        }
        Ok((raw[..32].try_into().unwrap(), wires))
    }

    fn publish_package(
        &self,
        mailbox: &Mailbox,
        passphrase: &str,
        digest: &[u8; 32],
    ) -> Result<Vec<[u8; 32]>, String> {
        let (saved_digest, wires) = self.resend_package(passphrase)?;
        if saved_digest != *digest {
            return Err("conflicting package for this attempt".into());
        }
        wires
            .iter()
            .map(|wire| mailbox.append(wire).map_err(|e| e.to_string()))
            .collect()
    }

    /// Save exact encrypted share envelope bytes before their first delivery.
    fn save_share(
        &self,
        wires: &[Vec<u8>],
        candidate_hash: &[u8; 32],
        package_hash: &[u8; 32],
        passphrase: &str,
    ) -> Result<(), String> {
        self.decide(b'R')?;
        self.save_share_after_decision(wires, candidate_hash, package_hash, passphrase)
    }

    fn save_share_after_decision(
        &self,
        wires: &[Vec<u8>],
        candidate_hash: &[u8; 32],
        package_hash: &[u8; 32],
        passphrase: &str,
    ) -> Result<(), String> {
        if !matches!(wires.len(), 2 | 3) {
            return Err("share needs one copy for the peer and each finisher".into());
        }
        let mut out = Vec::with_capacity(72 + wires.iter().map(Vec::len).sum::<usize>());
        out.extend_from_slice(candidate_hash);
        out.extend_from_slice(package_hash);
        for wire in wires {
            crate::setup_transport::session_envelope(wire)?;
            out.extend_from_slice(&(wire.len() as u32).to_be_bytes());
            out.extend_from_slice(wire);
        }
        self.dir
            .write_sealed("share.sealed", &out, passphrase)
            .map_err(|e| e.to_string())
    }

    fn resend_share(&self, passphrase: &str) -> Result<([u8; 32], [u8; 32], Vec<Vec<u8>>), String> {
        let raw = self
            .dir
            .read_sealed("share.sealed", passphrase)
            .map_err(|e| e.to_string())?;
        if raw.len() < 72 {
            return Err("corrupt sealed share outbox".into());
        }
        let mut at = 64;
        let mut wires = Vec::new();
        while at < raw.len() && wires.len() < 4 {
            wires.push(read_saved_wire(&raw, &mut at)?);
        }
        if at != raw.len() || !matches!(wires.len(), 2 | 3) {
            return Err("invalid sealed share copy count".into());
        }
        Ok((
            raw[..32].try_into().unwrap(),
            raw[32..64].try_into().unwrap(),
            wires,
        ))
    }

    fn abort(&self) -> Result<(), String> {
        self.decide(b'A')
    }

    fn publish(&self, mailbox: &Mailbox, passphrase: &str) -> Result<[u8; 32], String> {
        if fs::read(self.dir.path().join("decision")).map_err(|e| e.to_string())? != b"R" {
            return Err("attempt was aborted or release interrupted".into());
        }
        let (_, _, wires) = self.resend_share(passphrase)?;
        let hashes = wires
            .iter()
            .map(|wire| mailbox.append(wire).map_err(|e| e.to_string()))
            .collect::<Result<Vec<_>, _>>()?;
        let marker: Vec<u8> = hashes
            .iter()
            .flat_map(|hash| hash.iter().copied())
            .collect();
        let path = self.dir.path().join("published");
        let mut random = [0; 16];
        OsRng.fill_bytes(&mut random);
        let temp = self
            .dir
            .path()
            .join(format!(".{}.tmp", hex::encode(random)));
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)
            .map_err(|e| e.to_string())?;
        file.write_all(&marker).map_err(|e| e.to_string())?;
        file.sync_all().map_err(|e| e.to_string())?;
        let result = match fs::hard_link(&temp, &path) {
            Ok(()) => Ok(()),
            Err(e)
                if e.kind() == io::ErrorKind::AlreadyExists
                    && fs::read(&path).map_err(|e| e.to_string())? == marker =>
            {
                Ok(())
            }
            Err(e) => Err(e.to_string()),
        };
        fs::remove_file(temp).map_err(|e| e.to_string())?;
        result?;
        fs::File::open(self.dir.path())
            .and_then(|f| f.sync_all())
            .map_err(|e| e.to_string())?;
        Ok(hashes[0])
    }

    fn decide(&self, value: u8) -> Result<(), String> {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(self.dir.path().join("decision"))
            .map_err(|e| format!("attempt already decided: {e}"))?;
        file.write_all(&[value]).map_err(|e| e.to_string())?;
        file.sync_all().map_err(|e| e.to_string())?;
        fs::File::open(self.dir.path())
            .and_then(|f| f.sync_all())
            .map_err(|e| e.to_string())?;
        Ok(())
    }
}
