use loki_relay_client::{Observation, ObservationKind, ObservationSink};

#[test]
fn disabled_sink_drops_nothing_and_changes_no_result() {
    let sink = ObservationSink::disabled();
    sink.emit(Observation::new(ObservationKind::RequestStart, 1));
    assert_eq!(sink.dropped(), 0);
}

#[test]
fn full_or_disconnected_queue_counts_a_gap_and_keeps_going() {
    let (sink, receiver) = ObservationSink::bounded(1);
    sink.emit(sink.begin(ObservationKind::RequestStart));
    sink.emit(sink.begin(ObservationKind::RequestEnd));
    assert_eq!(sink.dropped(), 1);
    let first = receiver.recv().unwrap();
    assert_eq!(first.kind, ObservationKind::RequestStart);
    assert!(first.request >= 1);
    drop(receiver);
    sink.emit(Observation::new(ObservationKind::Quarantine, 9));
    assert_eq!(sink.dropped(), 2);
    let rendered = format!("{first:?}");
    assert!(!rendered.contains("secret"));
    assert!(rendered.contains("RequestStart"));
}
