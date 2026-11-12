# WS3 — Transport

Parent: `00-architecture.md`. Upholds invariant 4 (only public data crosses).

---

## 1. Goal

Move the public protocol messages (the signer's DKG wires, signing commitments, the
candidate PCZT, signing packages, randomizer seeds, signature shares) between the
coordinator and the signers, with authentication, confidentiality, and delivery
receipts — **without** any component learning a share. DKG round two crosses only as
v2 envelopes sealed under one-setup fresh keys (ws1 §6), so recorded traffic stays
closed even if a member's long-lived identity keys leak later.
Retire Loki's bespoke relay/admission/courier stack in favor of the **audited
`frostd`** relay, keeping an optional **serverless Zcash-memo** transport as a
censorship-resistant alternative.

## 2. Primary: `frostd` (ZF, audited)

- `frostd` is the ZF FROST coordination server: a **JSON-over-HTTPS** relay that passes
  opaque messages between a coordinator and the signing participants. It is **audited**
  (Least Authority) and **self-hostable**.
- It sees only ciphertext/public protocol messages; it holds **no** shares and is not a
  coordinator (it cannot create vaults or approve).
- Deployment: self-hosted by the vault operator or by a member; multiple instances
  possible. TLS with webpki roots + `aws-lc-rs` rustls provider (the pattern already
  used in `loki_wallet_sync`).

### What it replaces in Loki
Loki's current stack — HPKE courier, 2-of-3 relay-ack relays (`relay_member`,
`setup_relay`), the admission service, and the enrollment issuer (ports 39101-4 /
39201-4) — collapses onto `frostd` for message passing, plus a thin Loki enrollment/
roster layer for vault membership that `frostd` does not itself provide (see §4).

## 3. Optional: serverless Zcash-memo transport

zkool coordinates FROST over **Zcash memos** (on-chain encrypted messages), with no
central relay at all — maximally censorship-resistant. Offer this as an alternative
transport behind the same message interface for members who want no server dependency,
at the cost of on-chain latency/fees for coordination. Not a v1 requirement; the
transport interface (§5) is defined so it can be added without touching WS1/WS2 logic.

## 4. What `frostd` does NOT give us (the thin Loki layer that remains)

`frostd` relays messages; it does not define *who is in a vault* or run admission.
A minimal Loki layer still owns:
- **Enrollment / invitation**: inviting members to a vault, slot assignment, bearer
  invite links (existing invite model in `WALLET_BUILD.md` §Join).
- **Roster certification**: the `VaultCertificate` (roster, threshold, group key,
  per-vault member identities) and backup-confirmation gating before activation.
- **Network/birth-height tagging** of the vault (the fix the live testnet run
  surfaced: roster must carry `network` + `birth_height`).

This layer carries **no secrets** and can be a small service or peer-to-peer over
`frostd` messages.

## 5. Transport interface (stable across frostd / memo)

```
open(peers, messageCount) -> channel           # coordinator; logged in with a dedicated frostd login key
join(session) -> channel                       # participant
send(channel, to, Outbound)                    # typed: Dkg(DkgWire) | Commitments | Candidate | Package | RandomizerSeed | Share
recv(channel, asCoordinator) -> [(from, bytes)]
close(channel)
```

`send` takes only an `Outbound` (`poc/src/transport.rs`), so raw bytes — a plaintext
round-two package, a share, a nonce — do not compile as a payload; `DkgWire` and
`CandidatePczt` are made only by the signer. Each app logs in to frostd with its own
`FrostdLoginKey`, not with the member's setup encryption key. The DKG wires are
authenticated end to end (signed round one, certificates and receipts; round-two
envelopes signed and sealed to the recipient), so the relay is untrusted for
confidentiality and integrity, trusted only for best-effort delivery. During setup the
members send to the coordinator, which records each wire in its `RelayLog` before
forwarding it, redelivers from the log after a restart, and deletes the log once every
member's backup receipt has been relayed (the vault is active).

## 6. Security requirements

- Relay is **honest-but-curious**: assume it can read, drop, reorder, replay. E2E
  auth+encryption between members defends confidentiality/integrity; sequence numbers +
  receipts defend against replay/reorder for the signing protocol.
- No share, nonce, viewing key, or spend authorization is ever a message payload
  (enforced by WS1's API shape and the typed `Outbound` — those are never produced for
  transport, and raw bytes cannot be sent).
- The relay still sees who sends to whom, when, and each message's type, and payment
  transactions travel in clear between coordinator and signers; transport privacy is a
  follow-up.
- TLS everywhere for `frostd`; pin/verify server identity for self-hosted instances.

## 7. Acceptance criteria

1. A 2-of-3 testnet DKG + signing completes end-to-end over a self-hosted `frostd`,
   replacing the bespoke relay stack; print the resulting vault address + a confirmed
   payment txid.
2. Relay-adversary test: a relay that drops/reorders/replays messages cannot cause a
   wrong signature or a stranded nonce (ties to ws1 §8); the protocol detects and
   recovers or safely aborts.
3. Capture `frostd` traffic and confirm no secret material appears (only public
   protocol messages / ciphertext), and that recorded setup traffic cannot rebuild the
   group key even with every member's long-lived identity keys (done:
   `tests/frostd_transport.rs` and
   `recorded_relay_traffic_cannot_rebuild_the_group_key`; ADOPTION §5.3).
4. (Stretch) the same signing flow completes over the memo transport on testnet.

## 8. Dependencies

WS4 (frostd packaging/integration; `frost-client` speaks the frostd protocol), WS1/WS2
(message producers/consumers). Retires: `communication/relay_member`,
`communication/setup_relay`, admission + issuer bins, `deploy/bringup.sh` relay stack.
</content>
