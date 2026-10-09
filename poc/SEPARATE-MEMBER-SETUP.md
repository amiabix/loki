# Separate-member setup experiment

`loki_setup_member` is the first slice of distributed setup. Three processes, each with its own member directory, complete a 2-of-3 FROST DKG. The group key is real. The receive address is **regtest-only** because its viewing key still uses the documented test-only `ak || nk || rivk` construction. No backup card, ZIP 2005 key derivation, or integration with the payment CLI exists yet.

## Reproduce

```sh
cd poc
cargo test --test setup_processes
cargo test --test distributed_setup
cargo test --test setup_transport
```

The process test creates three owner-only stores, a public exchange directory, and a roster. It starts three `loki_setup_member run` processes concurrently and requires one identical address and one sealed key package per member. The DKG core test checks that the shares differ. A wrong roster fingerprint is refused before any DKG message is published.

## Manual ceremony

1. On each member's machine, choose a member directory outside the source checkout and create a passphrase file readable only by that member (`chmod 600`). Run `loki_setup_member identity <member-dir> <id:1|2|3> <passphrase-file>` and share only its JSON output. The private identity is stored as `secrets/identity.sealed`.
2. Build one JSON roster with a fresh random 32-byte hex `vault` (for example, `python3 -c 'import secrets; print(secrets.token_hex(32))'`) and a `members` array containing all three public identity JSON objects. Give the identical roster file to each member. Run `loki_setup_member fingerprint <roster.json>` on all three machines and compare the result by a trusted call or group chat.
3. Each member starts `loki_setup_member run <member-dir> <passphrase-file> <roster.json> <exchange-dir> <agreed-fingerprint>`. Keep all three processes running until completion. Deliver files from each process's exchange directory to the others without editing them. A shared folder works for a local drill; on separate machines the courier must copy complete files atomically. If a process exits or any check fails, discard that vault id and begin again with a new roster and exchange directory. If the final address was printed but lost, `loki_setup_member address <member-dir> <passphrase-file>` reads it from the completed sealed state.

Round-one messages and final certificates are signed. Round-two DKG shares are signed and encrypted to one recipient. The group certificate binds the DKG transcript, group key, public package, shared vault-secret derivation and roster fingerprint. Each member writes only its own signing share in one atomic `secrets/vault.sealed` file, sealed under its passphrase. Setup on the same member directory is locked so two processes cannot replace each other's state. The CLI's fingerprint check is effective only if members actually compare it out of band.

The existing `loki setup` path remains the mined transaction regression fixture; `run-regtest.sh` now uses an isolated scratch directory so it cannot erase another run's state. `loki_setup_member` does **not** make a spendable user wallet yet; the next implementation slice connects a member's sealed key package to independent proposal review and signing.
