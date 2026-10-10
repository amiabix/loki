//! Bounded transport observations. A full or disconnected sink cannot change a result.

use loki_relay_protocol::types::{Id32, MemberId};
use std::{
    sync::{
        atomic::{AtomicU64, Ordering},
        mpsc::{sync_channel, Receiver, SyncSender, TrySendError},
        Arc,
    },
    time::Duration,
};

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
}
