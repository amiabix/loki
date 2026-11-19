use loki_harness::scenario::ceremony::ceremony;

fn run(members: u16, threshold: u16) {
    let measured = ceremony(members, threshold).expect("full v2 DKG and signed PCZT");
    eprintln!(
        "measured {threshold}-of-{members}: DKG round1={:?}, round2={:?}, finalize={:?}, signing={:?}",
        measured.round1, measured.round2, measured.finalize, measured.signing,
    );
}

#[test]
fn ceremony_and_sign_2_of_3() {
    run(3, 2);
}

#[test]
fn ceremony_and_sign_2_of_10() {
    run(10, 2);
}
