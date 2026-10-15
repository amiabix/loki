use loki_relay_protocol::envelope::{padded_wire_length, validate_wire};
use loki_relay_protocol::WireError;

fn frame(magic: &[u8; 8], length: usize) -> Vec<u8> {
    let mut wire = vec![0; length];
    wire[..8].copy_from_slice(magic);
    wire[8] = 1;
    wire
}

#[test]
fn wire_boundary_record_963() {
    assert_eq!(padded_wire_length(963), Ok(1024));
}

#[test]
fn wire_boundary_record_964() {
    assert_eq!(padded_wire_length(964), Ok(2048));
}

#[test]
fn wire_boundary_record_65475() {
    assert_eq!(padded_wire_length(65475), Ok(65536));
}

#[test]
fn wire_boundary_record_65476() {
    assert_eq!(padded_wire_length(65476), Err(WireError::Bounds));
}

#[test]
fn wire_boundary_record_overflow() {
    for length in [usize::MAX, usize::MAX - 61, usize::MAX - 1023] {
        assert_eq!(padded_wire_length(length), Err(WireError::Bounds));
    }
    assert_eq!(padded_wire_length(0), Ok(1024));
}

#[test]
fn wire_boundary_message_and_config() {
    for magic in [b"LOKIRLY1", b"LOKICFG1", b"LOKISET1"] {
        for length in [1024, 2048, 65536] {
            assert_eq!(validate_wire(&frame(magic, length)), Ok(()));
        }
    }
}

#[test]
fn wire_boundary_wrong_magic() {
    assert_eq!(
        validate_wire(&frame(b"UNKNOWN1", 1024)),
        Err(WireError::Schema)
    );
}

#[test]
fn wire_boundary_wrong_version() {
    for magic in [b"LOKIRLY1", b"LOKICFG1", b"LOKISET1"] {
        for version in [0, 2, 255] {
            let mut wire = frame(magic, 1024);
            wire[8] = version;
            assert_eq!(validate_wire(&wire), Err(WireError::Version));
        }
    }
}

#[test]
fn wire_boundary_non_multiple() {
    for length in [1025, 2047, 65535] {
        assert_eq!(
            validate_wire(&frame(b"LOKIRLY1", length)),
            Err(WireError::Bounds)
        );
    }
}

#[test]
fn wire_boundary_frame_bounds() {
    for length in [0, 8, 9, 40, 41, 57, 1023] {
        assert_eq!(validate_wire(&vec![0; length]), Err(WireError::Bounds));
    }
    assert_eq!(
        validate_wire(&frame(b"LOKIRLY1", 66560)),
        Err(WireError::Bounds)
    );
}
