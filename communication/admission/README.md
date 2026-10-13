# Setup admission

`loki-setup-admission` is a separate service. The ordinary relay dependency graph does not depend on admission, the client, HPKE, or FROST. Admission keeps public policy, invitation hashes, identity claims, verifier-only mailbox intents, checkpoint commitments and signed operation outcomes. Owners keep read/admin capabilities; the operator keeps relay provisioning credentials.

The service verifies the signed operator bundle and requires its signing seed to match the advertised admission key. Configure an enrollment issuer's **public** key. With no issuer, fresh creation is denied; authenticated saved outcomes remain retrievable. Issuer private keys belong to the enrollment provider. Tests explicitly create an owned issuer and scoped grants.

Enrollment grant package: `[body:bytes, signature:bytes64]`. Body: `[1, grant_id:bytes32, device_signing_key:bytes32, expiry:u64, max_creations:u64, mailbox_budget:u64, configuration_digest:bytes32]`. Signature input is `Loki_Setup_Enrollment_v1\0` + u32 big-endian body length + body. Maxima are 100 creations and 2400 mailboxes. The grant is consumed transactionally and cannot change under the same grant ID.

Every command contains a saved 32-byte operation ID and device identity, signed under `Loki_Setup_Admission_Request_v1\0`. Grant/invitation bearer bytes go in Authorization, with their digest bound into the command. Requests and responses use bounded canonical CBOR. Responses sign operation ID, exact signed-request digest and outcome under `Loki_Setup_Admission_Response_v1\0`. Both domains include u32 big-endian body length before the body. Save exact request bytes before sending; an unknown result is retried under the same operation ID. A known rejection requires a new operation if the requested transition changes.

Routes are defined in `protocol/src/admission.rs`: create, identity claim, verifier-only mailbox provisioning, per-slot checkpoint CAS, authenticated state, and terminal intent. State exposes all public claims and the caller's mailbox/checkpoint state. Activation requires two common provisioned payment relay identities and every slot's signed vote. Native certificate and backup checks still gate the wallet handoff.

Setup mailboxes use the separate operator-authenticated relay `/v1/mailboxes/<id>/setup` control. Its immutable namespace intent survives ambiguous creation; ordinary payment mailboxes cannot be converted into setup. Expiry stops setup read/append/admin access before cleanup. Setup namespaces cannot hold nonce claims. Retirement deletes setup objects and mailbox rows, restores byte capacity, and retains a namespace tombstone. Payment objects and nonce records retain their existing lifetime. Admission prioritizes retirement on abort, expiry or activation; unavailable relays are retried with saved bytes and signed-policy jitter. Activated payment backfill remains eligible after the setup deadline. The relay executable also runs setup-only cleanup every minute.

Serve behind a TLS reverse proxy, retaining the immutable HTTPS origin from the bundle. Its private listener must be literal loopback:

```sh
loki-setup-admission serve \
  --root /absolute/owned/admission \
  --bundle-file /absolute/operator.cbor \
  --config-key-file /absolute/configuration-public.key \
  --signing-key-file /absolute/admission.seed \
  --issuer-key-file /absolute/enrollment-public.key \
  --relay-1-provision-file /absolute/relay-1.secret \
  --relay-2-provision-file /absolute/relay-2.secret \
  --relay-3-provision-file /absolute/relay-3.secret \
  --listen 127.0.0.1:9000
```

Public keys and private seeds are raw 32-byte files. The root is owner-only mode 0700. Private files must be regular, have one hard link, belong to the root owner, and use mode 0600. Relay numbers follow the bundle's increasing signing-key order. Private values never go in CLI arguments or output.

Owned loopback tests explicitly select `--development`, `OperatorSet::verify_development`, development invitation verification, and development HTTP constructors. This admits signed literal-loopback HTTP origins only. Default constructors and bundle verification require HTTPS. Development CLI admission origin must match its selected listener. HTTP timeouts honor the signed request limit (at most 30 seconds); relay operations also retain their existing ten-second ceiling.

Current evidence covers owned loopback HTTP, actual admission process kill/restart, real relay commits with suppressed responses, quorum provisioning/backfill, TTL/retirement and negative trust/signature checks. Resumable native DKG, application integration, separate-host HTTPS acceptance and production custody approval remain subsequent plan gates.
