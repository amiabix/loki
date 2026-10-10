CREATE TABLE metadata (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    schema_version INTEGER NOT NULL CHECK (schema_version = 1),
    protocol_version INTEGER NOT NULL CHECK (protocol_version = 1),
    run_id BLOB NOT NULL CHECK (typeof(run_id) = 'blob' AND length(run_id) = 32),
    receipt_public_key BLOB NOT NULL CHECK (typeof(receipt_public_key) = 'blob' AND length(receipt_public_key) = 32),
    provisioning_verifier BLOB NOT NULL CHECK (typeof(provisioning_verifier) = 'blob' AND length(provisioning_verifier) = 32),
    total_bytes INTEGER NOT NULL CHECK (typeof(total_bytes) = 'integer' AND total_bytes >= 0),
    mailbox_bytes INTEGER NOT NULL CHECK (typeof(mailbox_bytes) = 'integer' AND mailbox_bytes >= 0),
    mailbox_count INTEGER NOT NULL CHECK (typeof(mailbox_count) = 'integer' AND mailbox_count >= 0),
    used_bytes INTEGER NOT NULL CHECK (typeof(used_bytes) = 'integer' AND used_bytes >= 0 AND used_bytes <= total_bytes)
) STRICT;

-- Mailbox schema is installed transactionally on first provisioning, including existing roots.
CREATE TABLE IF NOT EXISTS mailboxes (
    id BLOB PRIMARY KEY NOT NULL CHECK (typeof(id) = 'blob' AND length(id) = 32),
    read_verifier BLOB NOT NULL CHECK (typeof(read_verifier) = 'blob' AND length(read_verifier) = 32),
    append_verifier BLOB NOT NULL CHECK (typeof(append_verifier) = 'blob' AND length(append_verifier) = 32),
    admin_verifier BLOB NOT NULL CHECK (typeof(admin_verifier) = 'blob' AND length(admin_verifier) = 32),
    creation_request BLOB NOT NULL,
    append_revision INTEGER NOT NULL CHECK (append_revision > 0),
    append_update BLOB,
    byte_quota INTEGER NOT NULL CHECK (byte_quota >= 0),
    used_bytes INTEGER NOT NULL CHECK (used_bytes >= 0 AND used_bytes <= byte_quota),
    next_sequence INTEGER NOT NULL CHECK (next_sequence > 0)
) STRICT;

-- Object schema is installed after mailbox authentication, including existing roots.
CREATE TABLE IF NOT EXISTS objects (
    mailbox BLOB NOT NULL CHECK (length(mailbox) = 32),
    hash BLOB NOT NULL CHECK (length(hash) = 32),
    wire BLOB NOT NULL,
    wire_length INTEGER NOT NULL CHECK (wire_length >= 1024 AND wire_length <= 65536 AND wire_length % 1024 = 0 AND length(wire) = wire_length),
    sequence INTEGER NOT NULL CHECK (sequence > 0),
    receipt BLOB NOT NULL,
    PRIMARY KEY (mailbox, hash),
    UNIQUE (mailbox, sequence),
    FOREIGN KEY (mailbox) REFERENCES mailboxes(id)
) STRICT;
