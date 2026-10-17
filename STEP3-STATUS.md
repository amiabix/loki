# Step 3: remote Testnet setup and approvals

## What the local checks cover

The hosted path uses a signed operator bundle, scoped enrollment grants, a separate admission service, and three separately stored relay processes. Each member keeps its own private root. Setup publishes encrypted records to relay inboxes and saves the exact outgoing ciphertext and native ceremony checkpoint before retrying delivery. The creator's app may close after publishing its invitations; other members can join and approve while it is closed. Once all invitations have been claimed, the signed configuration permits the ceremony to continue for 30 days. The first claim of each invitation still has a 24-hour deadline from vault creation.

`communication/admission/tests/admission.rs::three_members_resume_checkpoints_days_apart_after_claiming` advances the admission clock to days 1, 3, and 5, reopening the database for each member, and checks expiry at day 30. `poc/tests/setup_relay.rs::staggered_testnet_members_resume_with_one_relay_offline` exercises Testnet setup and recovery with three private member roots, separate setup CLI processes, three independent relay databases, and relay 1 offline. It checks that the creator's saved state stays unchanged while the other members approve, that two relays hold signed storage receipts, and that the stopped relay remains in the retry journal. These tests compress the human wait; they do not sleep for days or use separate physical machines.

The existing `communication/client/tests/setup_delivery.rs::peers_arrive_independently_after_creator_offline_and_ack_survives_reopen` checks encrypted setup delivery and acknowledgements after reopen. `poc/wallet/test_local_relays.py::LocalRelayTest::test_three_members_provision_exchange_and_retry_without_changing_keys` checks encrypted payment transport and acknowledgements through three local relays. The existing `poc/wallet/test_remote_join.py` checks a verified HTTPS browser join with distinct app roots on one host. The owned hosted-service fixture uses signed literal-loopback HTTP in its explicit development mode. Production clients require HTTPS.

Verified in this worktree on 2026-10-17:

- `communication` `cargo test`: 1,128 passed, 0 failed, 8 ignored.
- `poc` `cargo test`: 144 passed, 0 failed.
- Simulated days-apart admission test: 1 passed, 0 failed.
- Staggered hosted Testnet outage test: 1 passed, 0 failed (871.30s).
- Local encrypted relay delivery: 1 passed, 0 failed (109.659s).
- Verified HTTPS browser join: 1 passed, 0 failed (31.009s).

Run the local gates from the repository root:

```sh
cargo test --manifest-path communication/Cargo.toml
cargo test --manifest-path poc/Cargo.toml
cargo test --manifest-path poc/Cargo.toml --features relay-communication --test setup_relay staggered_testnet_members_resume_with_one_relay_offline -- --exact
cargo test --manifest-path communication/Cargo.toml -p loki-setup-admission --test admission three_members_resume_checkpoints_days_apart_after_claiming -- --exact
(cd poc/wallet && python3 -m unittest test_local_relays.LocalRelayTest.test_three_members_provision_exchange_and_retry_without_changing_keys)
(cd poc/wallet && python3 -m unittest test_remote_join.RemoteJoinTest.test_full_setup_over_https_the_joiners_verify)
```

## What deployment still requires

Deploy the three relay servers under independent operator control, each with its own durable private root, provisioning secret, signing identity, and publicly trusted HTTPS origin. Put the admission server behind a publicly trusted HTTPS origin and provision it with only the three relay provisioning credentials, its signing seed, the signed operator bundle, and the enrollment issuer's public key. Keep its private listener on loopback. Configure an enrollment issuer that authenticates invite-only beta users and issues device-bound grants; give each member app the signed bundle and its trusted configuration key. The operator must retain relay and admission data through the 30-day setup window and back up their durable stores. Each Testnet member also needs its own local node or authenticated loopback RPC tunnel for wallet sync and payments.

After deployment, run the full hosted setup, backup, and encrypted payment journey from three physical machines against those HTTPS origins, including a relay outage and a process restart. Verify that all devices show the same certified roster, address, and activation, and confirm a disposable Testnet payment. The local suite does not establish public reachability, independent operators, physical-device isolation, or a mined hosted Testnet payment.
