# Hosted operator configuration

`RelayHttp::hosted()` requires HTTPS. `RelayHttp::new()` retains literal loopback HTTP for existing development callers. Every request checks the selected policy; both constructors disable redirects, implicit proxies and decompression and retain a ten-second request deadline and existing response bounds.

`OperatorSet::verify` takes a bounded canonical CBOR signed package and an application-trusted Ed25519 configuration key. No network request occurs during verification. Configuration bundles contain public values only, never mailbox capabilities or operator provisioning credentials.

Version 1 package: `[body:bytes, signature:bytes64]`. Signature input is `Loki_Operator_Config_v1\0`, followed by the body length as a four-byte big-endian integer, followed by the exact canonical body. The configuration digest is SHA-256 of the complete canonical signed package.

Body: `[1, relays, admission, setup_versions, limits]`.

- `relays`: exactly three `[signing_key:bytes32, run:bytes32, https_origin:bytes]` entries in increasing signing-key order.
- `admission`: `[https_origin:bytes, signing_key:bytes32]`.
- `setup_versions`: `[2]`; unsupported versions are refused. Version 2 is the fresh-key round-two DKG format.
- `limits`: `[first_claim_seconds, ceremony_seconds, payload_bytes, storage_bytes_per_relay, request_seconds, retry_min_seconds, retry_max_seconds]`. All values are positive and bounded by `[86400, 2592000, 1048576, 67108864, 30, 60, 60]`; retry minimum cannot exceed maximum.

Origins may contain only an HTTPS scheme, host, optional nonzero port and optional single trailing slash. Credentials, queries, fragments, additional paths, control characters and parser-normalized path spellings are rejected. The route placeholders exposed by the bundle use mailbox zero and revision one; admission supplies each owner's actual mailbox, so bundle routes alone confer no mailbox authority.

Relay initialization accepts an optional immutable `--public-origin https://relay.example:443`. The relay still binds a literal loopback private listener for its TLS reverse proxy. The saved manifest and signed identity challenge advertise the configured origin, independently of request Host or forwarded headers. Serve cannot change that origin. Existing local manifests retain their listen-address equality check.

The separate admission service now implements scoped enrollment, durable claims, verifier-only provisioning and setup retention; see `../admission/README.md`. Explicit `verify_development` and development constructors support signed literal-loopback HTTP for owned tests. Default verification still requires HTTPS. Resumable DKG, payment handoff and production deployment remain later plan gates. Only owned test issuer/infrastructure use is currently selected.
