use crate::setup_store::{add_object, key_bytes};
use crate::{
    AuthenticatedSetupRecord, ClientError, ClientResult, OwnerInbox, RelayHttp, Secret32,
    SetupInboxDescriptor, SetupStore, SetupTransport,
};
use loki_relay_protocol::{
    canonical::{self, Value},
    setup::{SetupKey, SetupPhase},
    types::{Id32, Object, RelayRoute},
};
use rusqlite::{params, OptionalExtension, TransactionBehavior};
use std::collections::{BTreeMap, BTreeSet};
use zeroize::Zeroizing;
const ACK_DOMAIN: &[u8] = b"Loki_Setup_Received_v1\0";
pub struct SetupRoutes {
    pub own: Vec<OwnerInbox>,
    pub peers: Vec<SetupInboxDescriptor>,
}
#[derive(Default, Debug, Eq, PartialEq)]
pub struct SetupProgress {
    pub stored_groups: usize,
    pub received_groups: usize,
    pub incoming_records: usize,
    pub retryable_routes: usize,
}
fn fields(v: &Value, n: usize) -> ClientResult<&[Value]> {
    match v {
        Value::Array(a) if a.len() == n => Ok(a),
        _ => Err(ClientError::Config),
    }
}
fn bytes(v: &Value) -> ClientResult<&[u8]> {
    match v {
        Value::Bytes(b) => Ok(b),
        _ => Err(ClientError::Config),
    }
}
fn number(v: &Value) -> ClientResult<u64> {
    match v {
        Value::Integer(n) => u64::try_from(*n).map_err(|_| ClientError::Config),
        _ => Err(ClientError::Config),
    }
}
fn decode_key(ceremony: Id32, raw: &[u8]) -> ClientResult<SetupKey> {
    let v = canonical::decode(raw, 128)?;
    let f = fields(&v, 4)?;
    Ok(SetupKey {
        ceremony,
        phase: SetupPhase::try_from(number(&f[0])?)?,
        author: u16::try_from(number(&f[1])?).map_err(|_| ClientError::Identity)?,
        recipient: u16::try_from(number(&f[2])?).map_err(|_| ClientError::Identity)?,
        revision: number(&f[3])?,
    })
}
pub(crate) struct VerifiedAck {
    pub key: Vec<u8>,
    pub digest: Id32,
    pub package: Vec<u8>,
}
impl SetupTransport<'_> {
    pub(crate) fn prepare_ack(
        &self,
        record: &AuthenticatedSetupRecord,
    ) -> ClientResult<Option<(u16, Object)>> {
        let key = &record.body().key;
        if key.author == self.identity.public().id {
            return Ok(None);
        }
        let value = Value::Array(vec![
            Value::Integer(1.into()),
            Value::Bytes(crate::setup::policy_bytes(self.context().policy())?),
            Value::Bytes(key_bytes(key)?),
            Value::Bytes(record.digest().to_vec()),
            Value::Integer(self.identity.public().id.into()),
        ]);
        let package = crate::setup::signed(self.identity, ACK_DOMAIN, canonical::encode(&value)?)?;
        let frame = canonical::encode(&Value::Array(vec![
            Value::Integer(4.into()),
            Value::Bytes(package),
        ]))?;
        Ok(Some((
            key.author,
            crate::seal_record(&self.seal_context(key.author)?, &frame)?,
        )))
    }
    pub(crate) fn open_ack(&self, object: &Object) -> ClientResult<Option<VerifiedAck>> {
        let raw = Zeroizing::new(crate::open_record(
            &self.seal_context(self.identity.public().id)?,
            self.identity,
            &object.wire,
        )?);
        let value = crate::setup::PrivateValue(canonical::decode(&raw, 65536)?);
        let Value::Array(a) = &value.0 else {
            return Err(ClientError::Config);
        };
        if a.first().map(number).transpose()? != Some(4) {
            return Ok(None);
        }
        let f = fields(&value.0, 2)?;
        Ok(Some(self.verify_ack_package(bytes(&f[1])?)?))
    }
    fn verify_ack_package(&self, package: &[u8]) -> ClientResult<VerifiedAck> {
        let outer = canonical::decode(package, 4096)?;
        let p = fields(&outer, 2)?;
        let body = canonical::decode(bytes(&p[0])?, 4096)?;
        let b = fields(&body, 5)?;
        let author = u16::try_from(number(&b[4])?).map_err(|_| ClientError::Identity)?;
        let verified = crate::setup::verify_package(package, 4096, ACK_DOMAIN, self.peer(author)?)?;
        if verified != bytes(&p[0])?
            || number(&b[0])? != 1
            || bytes(&b[1])? != crate::setup::policy_bytes(self.context().policy())?
        {
            return Err(ClientError::Identity);
        }
        let key = decode_key(self.context().policy().ceremony, bytes(&b[2])?)?;
        if key.author != self.identity.public().id
            || key.recipient != author
            || author == key.author
        {
            return Err(ClientError::Identity);
        }
        let digest = bytes(&b[3])?
            .try_into()
            .map_err(|_| ClientError::Identity)?;
        Ok(VerifiedAck {
            key: key_bytes(&key)?,
            digest,
            package: package.to_vec(),
        })
    }
    fn check_routes(&self, routes: &SetupRoutes) -> ClientResult<()> {
        if routes.own.len() != 3 {
            return Err(ClientError::Config);
        }
        let mut seen = BTreeSet::new();
        for (own, pin) in routes.own.iter().zip(self.operators.relay_routes()) {
            if own.route.pin != pin.pin
                || own.route.endpoint != pin.endpoint
                || own.route.mailbox == [0; 32]
                || own.route.append_revision != 1
                || *own.read.as_bytes() == [0; 32]
                || *own.append.as_bytes() == [0; 32]
                || *own.admin.as_bytes() == [0; 32]
                || !seen.insert(own.route.mailbox)
            {
                return Err(ClientError::Config);
            }
        }
        seen.clear();
        for peer in &routes.peers {
            if peer.policy() != self.context().policy()
                || self.peer(peer.owner())? != peer.owner_identity()
                || peer.owner() == self.identity.public().id
                || !seen.insert(peer.owner_identity().signing)
            {
                return Err(ClientError::Identity);
            }
        }
        Ok(())
    }
    fn append_route<'a>(
        &self,
        routes: &'a SetupRoutes,
        recipient: u16,
        index: usize,
    ) -> Option<(&'a RelayRoute, &'a Secret32)> {
        if recipient == self.identity.public().id {
            routes.own.get(index).map(|r| (&r.route, &r.append))
        } else {
            routes
                .peers
                .iter()
                .find(|p| p.owner() == recipient)
                .and_then(|p| p.relays().get(index))
                .map(|r| (&r.route, &r.append))
        }
    }
    pub async fn drive_once(
        &self,
        store: &mut SetupStore,
        routes: &SetupRoutes,
    ) -> ClientResult<SetupProgress> {
        store.check_transport(self)?;
        store.active()?;
        self.check_routes(routes)?;
        let http = RelayHttp::for_setup(self.operators, self.development)?;
        let mut retries = 0;
        let drive = self.drive_bounded(store, routes, &http, &mut retries);
        match tokio::time::timeout(
            std::time::Duration::from_secs(self.operators.limits().request_seconds),
            drive,
        )
        .await
        {
            Ok(result) => result?,
            Err(_) => {
                for r in self.operators.relay_routes() {
                    store.defer_route(self, &r.pin.key)?;
                }
                retries = 3;
            }
        }
        let mut progress = store.progress(self, routes)?;
        progress.retryable_routes = retries;
        Ok(progress)
    }
    async fn drive_bounded(
        &self,
        store: &mut SetupStore,
        routes: &SetupRoutes,
        http: &RelayHttp,
        retries: &mut usize,
    ) -> ClientResult<()> {
        store.reconcile_deferred(self)?;
        let mut verified_pins = BTreeSet::new();
        for index in 0..3 {
            let pin = self.operators.relay_routes()[index].pin.key;
            if !store.route_due(&pin)? {
                *retries += 1;
                continue;
            }
            let uploads = store.uploads(&pin, 64)?;
            let mut authenticated = false;
            for (key, recipient, object, ack) in uploads {
                let Some((route, cap)) = self.append_route(routes, recipient, index) else {
                    continue;
                };
                if !authenticated {
                    if http
                        .authenticate_endpoint(&route.pin, &route.endpoint)
                        .await
                        .is_err()
                    {
                        *retries += 1;
                        store.defer_route(self, &pin)?;
                        break;
                    }
                    authenticated = true;
                    verified_pins.insert(pin);
                }
                match http.put(route, cap, &object).await {
                    Ok(receipt) => {
                        store.save_receipt(&key, &pin, &object.hash, receipt.bytes(), ack)?
                    }
                    Err(_) => {
                        *retries += 1;
                        store.defer_route(self, &pin)?;
                        break;
                    }
                }
            }
        }
        for own in &routes.own {
            if !store.route_due(&own.route.pin.key)? {
                continue;
            }
            if !verified_pins.contains(&own.route.pin.key) {
                if http
                    .authenticate_endpoint(&own.route.pin, &own.route.endpoint)
                    .await
                    .is_err()
                {
                    *retries += 1;
                    store.defer_route(self, &own.route.pin.key)?;
                    continue;
                }
                verified_pins.insert(own.route.pin.key);
            }
            let after = store.cursor(&own.route)?;
            let page = match http.entries(&own.route, &own.read, after, Some(32)).await {
                Ok(p) => p,
                Err(_) => {
                    *retries += 1;
                    store.defer_route(self, &own.route.pin.key)?;
                    continue;
                }
            };
            let mut cached = BTreeMap::new();
            let mut acknowledgements = Vec::new();
            let mut rejected = Vec::new();
            let mut incomplete = false;
            for entry in page.entries() {
                let object = match http.get(&own.route, &own.read, entry.hash()).await {
                    Ok(o) if o.wire.len() as u64 == entry.wire_length() => o,
                    _ => {
                        *retries += 1;
                        incomplete = true;
                        break;
                    }
                };
                cached.insert(object.hash, object.clone());
                match self.open_ack(&object) {
                    Ok(Some(ack)) => {
                        acknowledgements.push(ack);
                        continue;
                    }
                    Ok(None) => {}
                    Err(_) => {
                        rejected.push(object.hash);
                        continue;
                    }
                }
                let requirements = match self.inspect(&object) {
                    Ok(r) => r,
                    Err(ClientError::MissingObjects(m)) if m.is_empty() => continue,
                    Err(_) => {
                        rejected.push(object.hash);
                        continue;
                    }
                };
                for (hash, _) in requirements {
                    if cached.contains_key(&hash) {
                        continue;
                    }
                    match http.get(&own.route, &own.read, &hash).await {
                        Ok(o) => {
                            cached.insert(hash, o);
                        }
                        Err(_) => {
                            *retries += 1;
                            incomplete = true;
                            break;
                        }
                    }
                }
                if incomplete {
                    break;
                }
                match store.commit_incoming(self, &object, &cached) {
                    Ok(_) | Err(ClientError::SetupAgreementPending) => {}
                    Err(ClientError::Conflict) => return Err(ClientError::Conflict),
                    Err(error @ (ClientError::Storage | ClientError::Capacity)) => {
                        return Err(error)
                    }
                    Err(_) => rejected.push(object.hash),
                }
            }
            if incomplete {
                store.defer_route(self, &own.route.pin.key)?;
            }
            if !incomplete {
                store.capture_page(
                    &own.route,
                    after,
                    page.next(),
                    &cached,
                    &acknowledgements,
                    &rejected,
                )?;
                store.connection.execute(
                    "DELETE FROM retries WHERE pin=?1",
                    [own.route.pin.key.as_slice()],
                )?;
            }
        }
        Ok(())
    }
}
fn now_ms() -> ClientResult<u64> {
    let ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| ClientError::Storage)?
        .as_millis();
    u64::try_from(ms).map_err(|_| ClientError::Capacity)
}
impl SetupStore {
    fn route_due(&self, pin: &Id32) -> ClientResult<bool> {
        let next: Option<u64> = self
            .connection
            .query_row(
                "SELECT next_ms FROM retries WHERE pin=?1",
                [pin.as_slice()],
                |r| r.get(0),
            )
            .optional()?;
        let now = now_ms()?;
        Ok(next.is_none_or(|n| n <= now))
    }
    fn defer_route(&mut self, t: &SetupTransport<'_>, pin: &Id32) -> ClientResult<()> {
        let prior: Option<u64> = self
            .connection
            .query_row(
                "SELECT attempts FROM retries WHERE pin=?1",
                [pin.as_slice()],
                |r| r.get(0),
            )
            .optional()?;
        let attempts = prior.unwrap_or(0).saturating_add(1).min(1000000);
        let policy = t.operators.limits();
        let floor = policy.retry_min_seconds * 1000;
        let cap = (floor.saturating_mul(1u64 << attempts.saturating_sub(1).min(16)))
            .min(policy.retry_max_seconds * 1000);
        let width = cap - floor + 1;
        let cutoff = u64::MAX - (u64::MAX % width);
        let mut delay = None;
        for _ in 0..16 {
            let mut raw = [0u8; 8];
            getrandom::fill(&mut raw).map_err(|_| ClientError::Crypto)?;
            let draw = u64::from_le_bytes(raw);
            if draw < cutoff {
                delay = Some(floor + draw % width);
                break;
            }
        }
        let next = now_ms()?
            .checked_add(delay.ok_or(ClientError::Crypto)?)
            .filter(|n| *n <= i64::MAX as u64)
            .ok_or(ClientError::Capacity)?;
        self.connection.execute("INSERT INTO retries VALUES(?1,?2,?3) ON CONFLICT(pin) DO UPDATE SET attempts=excluded.attempts,next_ms=excluded.next_ms",params![pin.as_slice(),attempts,next])?;
        Ok(())
    }
    fn uploads(&self, pin: &Id32, limit: usize) -> ClientResult<Vec<(Vec<u8>, u16, Object, bool)>> {
        let mut stmt=self.connection.prepare("SELECT o.key,o.recipient,x.hash,x.wire,0 FROM outgoing o JOIN required r ON r.key=o.key JOIN objects x ON x.hash=r.hash WHERE NOT EXISTS(SELECT 1 FROM stored s WHERE s.key=o.key AND s.pin=?1 AND s.hash=x.hash) ORDER BY o.key,r.ordinal LIMIT ?2")?;
        let rows = stmt.query_map(params![pin.as_slice(), limit as i64], |r| {
            Ok((
                r.get::<_, Vec<u8>>(0)?,
                r.get::<_, u16>(1)?,
                r.get::<_, Vec<u8>>(2)?,
                r.get::<_, Vec<u8>>(3)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (key, recipient, hash, wire) = row?;
            out.push((
                key,
                recipient,
                Object {
                    hash: hash.try_into().map_err(|_| ClientError::Storage)?,
                    wire,
                },
                false,
            ));
        }
        let mut stmt=self.connection.prepare("SELECT a.key,a.recipient,x.hash,x.wire FROM acknowledgements a JOIN objects x ON x.hash=a.hash WHERE NOT EXISTS(SELECT 1 FROM ack_stored s WHERE s.hash=a.hash AND s.pin=?1) ORDER BY a.key LIMIT ?2")?;
        let rows = stmt.query_map(
            params![pin.as_slice(), limit.saturating_sub(out.len()) as i64],
            |r| {
                Ok((
                    r.get::<_, Vec<u8>>(0)?,
                    r.get::<_, u16>(1)?,
                    r.get::<_, Vec<u8>>(2)?,
                    r.get::<_, Vec<u8>>(3)?,
                ))
            },
        )?;
        for row in rows {
            let (key, recipient, hash, wire) = row?;
            out.push((
                key,
                recipient,
                Object {
                    hash: hash.try_into().map_err(|_| ClientError::Storage)?,
                    wire,
                },
                true,
            ));
        }
        Ok(out)
    }
    fn save_receipt(
        &mut self,
        key: &[u8],
        pin: &Id32,
        hash: &Id32,
        receipt: &[u8],
        ack: bool,
    ) -> ClientResult<()> {
        if ack {
            self.connection.execute(
                "INSERT OR IGNORE INTO ack_stored VALUES(?1,?2,?3)",
                params![hash.as_slice(), pin.as_slice(), receipt],
            )?;
        } else {
            self.connection.execute(
                "INSERT OR IGNORE INTO stored VALUES(?1,?2,?3,?4)",
                params![key, pin.as_slice(), hash.as_slice(), receipt],
            )?;
        }
        Ok(())
    }
    fn cursor(&self, route: &RelayRoute) -> ClientResult<u64> {
        let row: Option<(Vec<u8>, u64)> = self
            .connection
            .query_row(
                "SELECT mailbox,sequence FROM cursors WHERE pin=?1",
                [route.pin.key.as_slice()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        match row {
            None => Ok(0),
            Some((mailbox, seq)) if mailbox == route.mailbox => Ok(seq),
            _ => Err(ClientError::Identity),
        }
    }
    fn capture_page(
        &mut self,
        route: &RelayRoute,
        after: u64,
        next: u64,
        objects: &BTreeMap<Id32, Object>,
        acks: &[VerifiedAck],
        rejected: &[Id32],
    ) -> ClientResult<()> {
        self.active()?;
        if self.cursor(route)? != after || next < after || next > i64::MAX as u64 {
            return Err(ClientError::Cursor);
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        for o in objects.values() {
            add_object(&tx, o)?;
        }
        for ack in acks {
            let digest: Option<Vec<u8>> = tx
                .query_row(
                    "SELECT digest FROM outgoing WHERE key=?1",
                    [&ack.key],
                    |r| r.get(0),
                )
                .optional()?;
            if digest.as_deref() == Some(ack.digest.as_slice()) {
                tx.execute(
                    "INSERT OR IGNORE INTO received VALUES(?1,?2,?3)",
                    params![&ack.key, ack.digest.as_slice(), &ack.package],
                )?;
            }
        }
        for hash in rejected {
            tx.execute(
                "INSERT OR IGNORE INTO rejected VALUES(?1)",
                [hash.as_slice()],
            )?;
        }
        tx.execute("INSERT INTO cursors VALUES(?1,?2,?3) ON CONFLICT(pin) DO UPDATE SET sequence=excluded.sequence",params![route.pin.key.as_slice(),route.mailbox.as_slice(),next])?;
        tx.commit()?;
        Ok(())
    }
    pub fn progress(
        &self,
        t: &SetupTransport<'_>,
        routes: &SetupRoutes,
    ) -> ClientResult<SetupProgress> {
        self.progress_selected(t, routes, None)
    }
    pub fn progress_for(
        &self,
        t: &SetupTransport<'_>,
        routes: &SetupRoutes,
        key: &SetupKey,
    ) -> ClientResult<SetupProgress> {
        if key.ceremony != t.context().policy().ceremony
            || key.author != t.identity.public().id
            || key.recipient != key.author
            || key.revision == 0
        {
            return Err(ClientError::Identity);
        }
        self.progress_selected(t, routes, Some(key))
    }
    fn progress_selected(
        &self,
        t: &SetupTransport<'_>,
        routes: &SetupRoutes,
        selected: Option<&SetupKey>,
    ) -> ClientResult<SetupProgress> {
        self.check_transport(t)?;
        self.active()?;
        t.check_routes(routes)?;
        let mut groups = BTreeMap::<(u8, u16, u64), Vec<(Vec<u8>, Vec<u8>, u16)>>::new();
        let mut stmt = self
            .connection
            .prepare("SELECT key,digest,recipient FROM outgoing ORDER BY key")?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, Vec<u8>>(0)?,
                r.get::<_, Vec<u8>>(1)?,
                r.get::<_, u16>(2)?,
            ))
        })?;
        for row in rows {
            let (key, digest, recipient) = row?;
            let k = decode_key(t.context().policy().ceremony, &key)?;
            groups
                .entry((k.phase as u8, k.author, k.revision))
                .or_default()
                .push((key, digest, recipient));
        }
        if let Some(key) = selected {
            groups.retain(|(phase, author, revision), _| {
                *phase == key.phase as u8 && *author == key.author && *revision == key.revision
            });
        }
        let mut progress = SetupProgress::default();
        for ((phase, author, revision), copies) in &groups {
            let required: BTreeSet<u16> = if *phase == SetupPhase::Join as u8 {
                [1, *author].into_iter().collect()
            } else {
                (1..=t.context().policy().member_count).collect()
            };
            if *author != t.identity.public().id
                || copies.iter().map(|(_, _, r)| *r).collect::<BTreeSet<_>>() != required
                || copies.len() != required.len()
            {
                return Err(ClientError::Storage);
            }
            let mut pins: BTreeSet<_> = t
                .operators
                .relay_routes()
                .iter()
                .map(|r| r.pin.key)
                .collect();
            let mut received = true;
            for (key, digest, recipient) in copies {
                let mut present = BTreeSet::new();
                for (index, operator) in t.operators.relay_routes().iter().enumerate() {
                    if !pins.contains(&operator.pin.key) {
                        continue;
                    }
                    let Some((route, _)) = t.append_route(routes, *recipient, index) else {
                        continue;
                    };
                    let mut objects=self.connection.prepare("SELECT r.hash,x.wire,s.receipt FROM required r JOIN objects x ON x.hash=r.hash LEFT JOIN stored s ON s.key=r.key AND s.hash=r.hash AND s.pin=?2 WHERE r.key=?1 ORDER BY r.ordinal")?;
                    let rows =
                        objects.query_map(params![key, operator.pin.key.as_slice()], |r| {
                            Ok((
                                r.get::<_, Vec<u8>>(0)?,
                                r.get::<_, Vec<u8>>(1)?,
                                r.get::<_, Option<Vec<u8>>>(2)?,
                            ))
                        })?;
                    let mut complete = true;
                    let mut count = 0;
                    for row in rows {
                        let (hash, wire, receipt) = row?;
                        count += 1;
                        let hash: Id32 = hash.try_into().map_err(|_| ClientError::Storage)?;
                        use sha2::Digest;
                        if <Id32>::from(sha2::Sha256::digest(&wire)) != hash {
                            return Err(ClientError::Storage);
                        }
                        if let Some(receipt) = receipt {
                            crate::http::verify_saved_receipt(
                                route,
                                &receipt,
                                hash,
                                wire.len() as u64,
                            )?;
                        } else {
                            complete = false;
                        }
                    }
                    if count == 0 {
                        return Err(ClientError::Storage);
                    }
                    if complete {
                        present.insert(operator.pin.key);
                    }
                }
                pins = present;
                let confirmed = if *recipient == t.identity.public().id {
                    let k = decode_key(t.context().policy().ceremony, key)?;
                    self.receive(t, &k)?.is_some_and(|record| {
                        record.digest().as_slice() == digest
                            && record.body().key.phase as u8 == *phase
                            && record.body().key.revision == *revision
                    })
                } else {
                    let package: Option<Vec<u8>> = self
                        .connection
                        .query_row(
                            "SELECT package FROM received WHERE key=?1 AND digest=?2",
                            params![key, digest],
                            |r| r.get(0),
                        )
                        .optional()?;
                    if let Some(package) = package {
                        let ack = t.verify_ack_package(&package)?;
                        if ack.key != *key || ack.digest.as_slice() != digest {
                            return Err(ClientError::Receipt);
                        }
                        true
                    } else {
                        false
                    }
                };
                received &= confirmed;
            }
            if pins.len() >= 2 {
                progress.stored_groups += 1;
            }
            if received {
                progress.received_groups += 1;
            }
        }
        progress.incoming_records =
            self.connection
                .query_row("SELECT count(*) FROM incoming", [], |r| r.get(0))?;
        Ok(progress)
    }
}
