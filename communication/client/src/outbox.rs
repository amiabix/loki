use crate::{
    AuthenticatedDescriptor, ClientConfig, ClientError, ClientResult, ClientStore, CommIdentity,
    ConfigReference, DescriptorRelay, OwnerInbox, PreparedOutbox, RecoveryLogical, RecoveryUpload,
    RelayHttp, Secret32, TransferAssembler,
};
use loki_relay_protocol::{
    envelope,
    types::{self, Id32, LogicalKey, MemberId, MessageBody, Object, Payload, RelayRoute, Roster},
    WireError,
};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use zeroize::{Zeroize, Zeroizing};

pub fn outbox_intent_digest(body: &MessageBody) -> ClientResult<Id32> {
    let mut normalized = body.clone();
    normalized.key.message = [0; 32];
    let encoded = types::encode_message(&normalized);
    if let Payload::Test(payload) = &mut normalized.payload {
        payload.zeroize();
    }
    let encoded = Zeroizing::new(encoded?);
    let mut hash = Sha256::new();
    hash.update(b"Loki_Relay_Outbox_Intent_v1\0");
    hash.update(&*encoded);
    Ok(hash.finalize().into())
}

pub(crate) struct ValidatedOutbox {
    pub intent: Id32,
    pub kind: u8,
    pub session: Option<Id32>,
    pub source_root: Id32,
}

pub(crate) fn validate_set(
    objects: &[Object],
    transfer: Option<&Id32>,
    root: &Id32,
) -> ClientResult<()> {
    if (transfer.is_none() && objects.len() != 1)
        || (transfer.is_some() && !(2..=275).contains(&objects.len()))
        || objects.last().map(|object| &object.hash) != Some(root)
    {
        return Err(WireError::Schema.into());
    }
    let mut hashes = BTreeSet::new();
    for object in objects {
        envelope::validate_wire(&object.wire)?;
        if &object.wire[..8] != envelope::MESSAGE_MAGIC
            || <Id32>::from(Sha256::digest(&object.wire)) != object.hash
            || !hashes.insert(object.hash)
        {
            return Err(WireError::Schema.into());
        }
    }
    Ok(())
}

pub(crate) fn authenticate_author(
    roster: &Roster,
    identity: &CommIdentity,
    objects: &[Object],
) -> ClientResult<crate::AuthenticatedMessage> {
    let root = objects.last().ok_or(WireError::Schema)?;
    let map: BTreeMap<_, _> = objects
        .iter()
        .map(|object| (object.hash, object.clone()))
        .collect();
    let authenticated = TransferAssembler::open(roster, identity, root, &map)?;
    let actual: BTreeSet<_> = objects.iter().map(|object| object.hash).collect();
    let required: BTreeSet<_> = authenticated
        .source()
        .required_hashes()
        .iter()
        .copied()
        .collect();
    if actual != required || actual.len() != objects.len() {
        return Err(WireError::Schema.into());
    }
    Ok(authenticated.into_parts().0)
}

pub(crate) fn validate(
    roster: &Roster,
    identity: &CommIdentity,
    prepared: &PreparedOutbox,
) -> ClientResult<ValidatedOutbox> {
    let digest = types::roster_digest(roster)?;
    let public = identity.public();
    if !roster.members.contains(&public)
        || prepared.key().vault != roster.vault
        || prepared.key().roster != digest
        || prepared.key().sender != public.id
    {
        return Err(ClientError::Identity);
    }
    if !prepared
        .recipients()
        .iter()
        .map(|r| r.recipient())
        .eq(roster.members.iter().map(|m| m.id))
    {
        return Err(WireError::Schema.into());
    }
    let author = prepared
        .recipients()
        .iter()
        .find(|r| r.recipient() == public.id)
        .ok_or(WireError::Schema)?;
    let mut all_hashes = BTreeSet::new();
    for recipient in prepared.recipients() {
        validate_set(
            recipient.objects(),
            recipient.transfer(),
            recipient.root_hash(),
        )?;
        if recipient.transfer().is_some() != author.transfer().is_some()
            || recipient.objects().len() != author.objects().len()
            || !recipient
                .objects()
                .iter()
                .map(|o| o.wire.len())
                .eq(author.objects().iter().map(|o| o.wire.len()))
            || recipient
                .objects()
                .iter()
                .any(|object| !all_hashes.insert(object.hash))
        {
            return Err(WireError::Schema.into());
        }
    }
    let message = authenticate_author(roster, identity, author.objects())?;
    if message.body().key != *prepared.key() || message.digest() != prepared.digest() {
        return Err(ClientError::Identity);
    }
    Ok(ValidatedOutbox {
        intent: outbox_intent_digest(message.body())?,
        kind: match message.body().payload {
            Payload::Test(_) => 1,
            Payload::Received(_) => 2,
        },
        session: message.body().session,
        source_root: *author.root_hash(),
    })
}

pub enum ThirdPass {
    StopAfterStored,
    ContinueThird,
}

pub struct UploadPass {
    pub needs_route: Vec<MemberId>,
    pub stopped_third: bool,
}

pub struct DeliveryReport {
    key: LogicalKey,
    source_root: Id32,
    members: Vec<Vec<(Id32, Id32)>>,
    whole: Vec<(Id32, Id32)>,
}

impl DeliveryReport {
    pub(crate) fn new(
        key: LogicalKey,
        source_root: Id32,
        members: Vec<Vec<(Id32, Id32)>>,
        whole: Vec<(Id32, Id32)>,
    ) -> Self {
        Self {
            key,
            source_root,
            members,
            whole,
        }
    }

    pub fn key(&self) -> &LogicalKey {
        &self.key
    }

    pub fn source_root(&self) -> &Id32 {
        &self.source_root
    }

    pub fn member_stored(&self, recipient: MemberId) -> bool {
        two_keys(self.member_pins(recipient))
    }

    pub fn whole_vault(&self) -> bool {
        two_keys(&self.whole)
    }

    pub fn member_pins(&self, recipient: MemberId) -> &[(Id32, Id32)] {
        recipient
            .checked_sub(1)
            .and_then(|index| self.members.get(index as usize))
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    pub fn whole_pins(&self) -> &[(Id32, Id32)] {
        &self.whole
    }
}

fn two_keys(pins: &[(Id32, Id32)]) -> bool {
    pins.iter().map(|pin| pin.0).collect::<BTreeSet<_>>().len() >= 2
}

struct CertifiedRoute {
    route: RelayRoute,
    append: Secret32,
    descriptor_revision: u64,
    append_revision: u64,
    third: bool,
}

pub(crate) fn inboxes_match(own: &[OwnerInbox], relays: &[DescriptorRelay]) -> bool {
    own.len() == 3
        && relays.len() == 3
        && relays.iter().all(|relay| {
            own.iter().any(|inbox| {
                inbox.route == relay.route && inbox.append.as_bytes() == relay.append.as_bytes()
            })
        })
}

fn certified_route(
    identity: &CommIdentity,
    config: &ClientConfig,
    self_route: &AuthenticatedDescriptor,
    recipient: MemberId,
    relay_key: &Id32,
    run: &Id32,
    mailbox: &Id32,
    vault: &Id32,
    roster: &Id32,
) -> Option<CertifiedRoute> {
    let descriptor = if recipient == identity.public().id {
        self_route
    } else {
        config.peers.iter().find(|peer| {
            let body = peer.body();
            body.owner == recipient && body.vault == *vault && body.roster == *roster
        })?
    };
    let body = descriptor.body();
    if body.relays.len() != 3 {
        return None;
    }
    if recipient == identity.public().id && !inboxes_match(&config.own, &body.relays) {
        return None;
    }
    let relay = body.relays.iter().find(|relay| {
        relay.route.pin.key == *relay_key
            && relay.route.pin.run == *run
            && relay.route.mailbox == *mailbox
    })?;
    Some(CertifiedRoute {
        route: relay.route.clone(),
        append: Secret32::from_bytes(*relay.append.as_bytes()),
        descriptor_revision: body.revision,
        append_revision: relay.route.append_revision,
        third: *relay_key == body.relays[2].route.pin.key,
    })
}

pub async fn upload_pending(
    store: &mut ClientStore,
    http: &RelayHttp,
    logical: &RecoveryLogical,
    roster: &Roster,
    identity: &CommIdentity,
    config: &ClientConfig,
    self_route: &AuthenticatedDescriptor,
    now_ms: u64,
    third: ThirdPass,
) -> ClientResult<UploadPass> {
    let Some(reference) = store.config_reference()? else {
        return Err(ClientError::Config);
    };
    if now_ms > i64::MAX as u64 {
        return Err(ClientError::Capacity);
    }
    store.bind_upload_routes(roster, identity, logical, config, self_route)?;
    let needs_route = store
        .recover_recipients(&logical.key)?
        .into_iter()
        .filter(|recipient| recipient.needs_route)
        .map(|recipient| recipient.recipient)
        .collect();
    let mut stopped_third = false;
    let mut primary = Vec::new();
    let mut optional_third = Vec::new();
    for stored in store.message_uploads(&logical.key)? {
        let upload = stored.upload;
        if upload.acknowledged {
            continue;
        }
        let Some(certified) = certified_route(
            identity,
            config,
            self_route,
            upload.recipient,
            &upload.relay_key,
            &upload.run,
            &upload.mailbox,
            &upload.key.vault,
            &upload.key.roster,
        ) else {
            continue;
        };
        if certified.third && matches!(third, ThirdPass::StopAfterStored) {
            optional_third.push((upload, certified));
        } else {
            primary.push((upload, certified));
        }
    }
    for (upload, certified) in primary {
        transmit(store, http, &reference, &certified, &upload, now_ms).await?;
    }
    for (upload, certified) in optional_third {
        if store
            .delivery_report(roster, identity, logical, config, self_route)?
            .whole_vault()
        {
            stopped_third = true;
            break;
        }
        transmit(store, http, &reference, &certified, &upload, now_ms).await?;
    }
    store.release_stored_capacity(roster, identity, logical, config, self_route)?;
    Ok(UploadPass {
        needs_route,
        stopped_third,
    })
}

async fn transmit(
    store: &mut ClientStore,
    http: &RelayHttp,
    reference: &ConfigReference,
    certified: &CertifiedRoute,
    upload: &RecoveryUpload,
    now_ms: u64,
) -> ClientResult<()> {
    let Some(fresh) = store.upload_eligibility(upload)? else {
        return Ok(());
    };
    if fresh.upload.acknowledged {
        return Ok(());
    }
    if let Some(rejection) = fresh.rejection {
        let woke = reference.revision() > rejection.config_revision
            && certified.descriptor_revision >= rejection.descriptor_revision
            && certified.append_revision > rejection.append_revision;
        if !woke {
            return Ok(());
        }
        store.clear_rejection(upload)?;
    }
    if fresh.upload.retry_at > now_ms {
        return Ok(());
    }
    let saved = store
        .saved_object(&upload.hash)?
        .ok_or(ClientError::Storage)?;
    match http.put(&certified.route, &certified.append, &saved).await {
        Ok(receipt) => match store.commit_upload_receipt(upload, &receipt) {
            Err(ClientError::Conflict | ClientError::Receipt) => Ok(()),
            result => result,
        },
        Err(ClientError::Identity) => store.record_route_rejection(
            &upload.key,
            upload.recipient,
            &upload.relay_key,
            &upload.run,
            &upload.mailbox,
            certified.descriptor_revision,
            certified.append_revision,
            reference,
        ),
        Err(ClientError::Transport | ClientError::Storage | ClientError::Capacity) => {
            store.schedule_upload_retry(upload, now_ms)
        }
        Err(
            ClientError::Conflict
            | ClientError::Receipt
            | ClientError::Cursor
            | ClientError::Config,
        ) => Ok(()),
        Err(error) => Err(error),
    }
}
