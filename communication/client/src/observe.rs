//! Bounded transport observations. A full or disconnected sink cannot change a result.

use loki_relay_protocol::types::{Id32, MemberId};
use std::{
    future::Future,
    sync::{
        atomic::{AtomicU64, Ordering},
        mpsc::{sync_channel, Receiver, SyncSender, TrySendError},
        Arc,
    },
    time::Duration,
};

tokio::task_local! {
    static ACTIVE_SINK: ObservationSink;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObservationKind {
    RequestStart,
    RequestEnd,
    ReceiptValidated,
    ReceiptPersisted,
    ReceiptRejected,
    OriginalAuthenticated,
    OriginalCommitted,
    ReceivedLinked,
    RetryDue,
    RouteFailure,
    Quarantine,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Observation {
    pub kind: ObservationKind,
    pub actor: Option<MemberId>,
    pub sender: Option<MemberId>,
    pub recipient: Option<MemberId>,
    pub pin: Option<Id32>,
    pub run: Option<Id32>,
    pub mailbox: Option<Id32>,
    pub logical_message: Option<Id32>,
    pub digest: Option<Id32>,
    pub object_hash: Option<Id32>,
    pub ordinal: Option<u16>,
    pub bytes: Option<u64>,
    pub request: u64,
    pub status: Option<u16>,
    pub duration: Option<Duration>,
    pub result: Option<&'static str>,
}

impl Observation {
    pub fn new(kind: ObservationKind, request: u64) -> Self {
        Self {
            kind,
            actor: None,
            sender: None,
            recipient: None,
            pin: None,
            run: None,
            mailbox: None,
            logical_message: None,
            digest: None,
            object_hash: None,
            ordinal: None,
            bytes: None,
            request,
            status: None,
            duration: None,
            result: None,
        }
    }
}

#[derive(Clone)]
pub struct ObservationSink {
    sender: Option<SyncSender<Observation>>,
    dropped: Arc<AtomicU64>,
    next_request: Arc<AtomicU64>,
}

impl ObservationSink {
    pub fn disabled() -> Self {
        Self {
            sender: None,
            dropped: Arc::new(AtomicU64::new(0)),
            next_request: Arc::new(AtomicU64::new(1)),
        }
    }

    pub fn bounded(capacity: usize) -> (Self, Receiver<Observation>) {
        let (sender, receiver) = sync_channel(capacity.max(1));
        let dropped = Arc::new(AtomicU64::new(0));
        (
            Self {
                sender: Some(sender),
                dropped,
                next_request: Arc::new(AtomicU64::new(1)),
            },
            receiver,
        )
    }

    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    pub fn begin(&self, kind: ObservationKind) -> Observation {
        let request = self.next_request.fetch_add(1, Ordering::Relaxed);
        Observation::new(kind, request)
    }

    pub fn emit(&self, event: Observation) {
        let Some(sender) = &self.sender else {
            return;
        };
        if let Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) = sender.try_send(event) {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Run `future` while journal milestones use this sink. A disabled or missing sink emits nothing.
    pub async fn drive<T>(&self, future: impl Future<Output = T>) -> T {
        ACTIVE_SINK.scope(self.clone(), future).await
    }
}

pub(crate) fn emit_active(kind: ObservationKind, fill: impl FnOnce(&mut Observation)) {
    let mut event = ACTIVE_SINK
        .try_with(|sink| sink.begin(kind))
        .unwrap_or_else(|_| Observation::new(kind, 0));
    fill(&mut event);
    let _ = ACTIVE_SINK.try_with(|sink| sink.emit(event));
}

pub(crate) fn note_original(kind: ObservationKind, sender: MemberId, message: Id32, digest: Id32) {
    emit_active(kind, |event| {
        event.sender = Some(sender);
        event.logical_message = Some(message);
        event.digest = Some(digest);
    });
}

pub(crate) fn note_received_link(sender: MemberId, recipient: MemberId, message: Id32, digest: Id32) {
    emit_active(ObservationKind::ReceivedLinked, |event| {
        event.sender = Some(sender);
        event.recipient = Some(recipient);
        event.logical_message = Some(message);
        event.digest = Some(digest);
    });
}

pub(crate) fn note_persisted_receipt(
    sender: MemberId,
    recipient: MemberId,
    message: Id32,
    hash: Id32,
    pin: Id32,
    run: Id32,
    mailbox: Id32,
) {
    emit_active(ObservationKind::ReceiptPersisted, |event| {
        event.sender = Some(sender);
        event.recipient = Some(recipient);
        event.logical_message = Some(message);
        event.object_hash = Some(hash);
        event.pin = Some(pin);
        event.run = Some(run);
        event.mailbox = Some(mailbox);
        event.result = Some("ok");
    });
}

pub(crate) fn note_retry(
    sender: MemberId,
    recipient: MemberId,
    message: Id32,
    hash: Id32,
    pin: Id32,
    run: Id32,
    mailbox: Id32,
) {
    emit_active(ObservationKind::RetryDue, |event| {
        event.sender = Some(sender);
        event.recipient = Some(recipient);
        event.logical_message = Some(message);
        event.object_hash = Some(hash);
        event.pin = Some(pin);
        event.run = Some(run);
        event.mailbox = Some(mailbox);
        event.result = Some("retry");
    });
}

pub(crate) fn note_download_retry(hash: Id32, pin: Id32, run: Id32, mailbox: Id32) {
    emit_active(ObservationKind::RetryDue, |event| {
        event.object_hash = Some(hash);
        event.pin = Some(pin);
        event.run = Some(run);
        event.mailbox = Some(mailbox);
        event.result = Some("retry");
    });
}

pub(crate) fn note_route_failure(pin: Id32, run: Id32, mailbox: Id32, result: &'static str) {
    emit_active(ObservationKind::RouteFailure, |event| {
        event.pin = Some(pin);
        event.run = Some(run);
        event.mailbox = Some(mailbox);
        event.result = Some(result);
    });
}

pub(crate) fn note_quarantine(pin: Id32, run: Id32, mailbox: Id32, hash: Id32, result: &'static str) {
    emit_active(ObservationKind::Quarantine, |event| {
        event.pin = Some(pin);
        event.run = Some(run);
        event.mailbox = Some(mailbox);
        event.object_hash = Some(hash);
        event.result = Some(result);
    });
}
