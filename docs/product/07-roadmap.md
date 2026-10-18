# Roadmap & Sequencing

Parent: `00-architecture.md`. How the workstreams land in order, with a verifiable
gate at each milestone. No milestone is "done" without its paste-the-output check.

---

## Dependency graph

```
WS4 (ZF stack) ──┬──> WS1 (signer) ──┐
                 ├──> WS2 (coordinator) ──┤
                 └──> WS3 (transport) ────┼──> M3 end-to-end split payment
WS5 (FVK) ───────────────────────────────┘
WS6 (standards/audit) cross-cuts; gates mainnet.
```

WS4 is the spine and starts first. WS5 is a short, verifiable investigation that can run
in parallel. WS1 is the long pole (safety-critical). WS6 runs continuously and owns the
mainnet gate.

---

## M0 — Decisions locked (DONE)
- Architecture locked (`00-architecture.md`): keyless coordinator + isolated native
  signer, Enclave-wrapped share, ZF stack, confirm-on-signer.
- Remaining micro-decisions, each with a lean default, resolved during the WS they gate:
  signer form (one native app, logical split — ws1 §12), FVK (prefer audited
  `zcash-sign` if recoverable — ws5 §5).

## M1 — ZF stack parity on testnet (WS4 + WS5)
Gate: a 2-of-3 testnet vault created via `frost-client`/`frostd` DKG (not bespoke) and
a confirmed testnet payment aggregated with `frost-core`/`zcash-sign`. Print vault
address + txid. WS5 determination written (recoverable or not) with `generate.rs`
evidence.

## M2 — Isolated signer with real key protection (WS1)
Gate: three isolated signers, shares Enclave/StrongBox-wrapped + biometric-gated;
WYSIWYS catches a tampered-coordinator PCZT; nonce crash-injection leaves nothing
stranded. Paste test output. (No coordinator UI polish yet.)

## M3 — Split architecture end-to-end (WS1 + WS2 + WS3)
Gate: keyless coordinator drives a confirmed 2-of-3 testnet payment against two
isolated signers over `frostd`; all three eligible pairs pass; one-approver-offline
passes; network capture shows no secret crossing the wire. Print txids.

## M4 — Web coordinator (WS2 deployment form 2)
Gate: the coordinator served as a web app over HTTPS completes a confirmed testnet
payment with the share only ever on the native signer. This is the "web app you log
into and still be safe with" milestone.

## M5 — Audit-ready & standards-aligned (WS6)
Gate: audit-scope map published; reproducible signer build reproduced to the same hash
on two machines; #490 alignment note; #1094 disposition. External review booked.

## M6 — Mainnet custody (post-audit)
Gate: external security review passed; independent recovery spend demonstrated;
reorg/crash drills passed; independent delivery across approving pairs in place. Only
now does a build accept mainnet funds. Until then every build shows its test network
and refuses mainnet (release boundary).

---

## Parallelization for an agent fleet

| Track | Can start | Owns |
|---|---|---|
| A | now | WS4 adoption (Mode A/B gate), retire bespoke relay/FROST |
| B | now | WS5 investigation (`generate.rs` vs `zip2005` vectors) — small, fast |
| C | after M1 | WS1 signer: at-rest hierarchy + biometric + WYSIWYS + nonce safety |
| D | after M1 | WS2 coordinator: re-home scan/build/broadcast onto ZF, keyless boundary |
| E | after M1 | WS3 frostd deployment + thin roster layer, retire courier/admission |
| F | continuous | WS6 audit-scope map, reproducible builds, standards notes |

Tracks C/D/E converge at M3. Keep each track's branch isolated; verify with the WS's
own acceptance tests before merge (no claim without passing output).
</content>
