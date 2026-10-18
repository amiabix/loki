# WS6 — Standards, Trust & Audit

Parent: `00-architecture.md`. Upholds invariants 5, 6 and the `WALLET_BUILD.md`
release boundary.

---

## 1. Goal

Align Loki with the emerging Zcash FROST standards so it interoperates and so its
audit surface is as small and as reviewable as possible, and define the trust/delivery
hardening (reproducible builds, independent delivery) that makes the keyless-
coordinator + isolated-signer model honest rather than aspirational.

## 2. Standards to track and align with

| Item | What it is | Loki action |
|---|---|---|
| **ZF `frost` #1094** | FROST FVK derivation is unreviewed upstream | Resolve via WS5: prefer audited `zcash-sign generate`; if keeping `zip2005.rs`, push the vector-matched derivation into #1094. |
| **Grant #490** | Open spec for coordinator↔co-signer **QR** handoff + a backup format | Align the WS1 signer API / WS3 message framing + the backup artifact to #490 so an isolated/air-gapped/hardware signer interops. Pull the current spec draft before freezing WS1's approve/backup formats. |
| **Zconnect** | Web-wallet interface (the `window.ethereum` analogue for Zcash), PCZT-based | Target as the standard way the **web coordinator** connects to an **external signer/extension** — the clean long-term answer to "web app + external signer." |
| **TSSK / Cyze** | Other FROST-multisig efforts / toolkits | Interop/learning; avoid reinventing where a shared format exists. |
| **PCZT** | Partially-Created Zcash Transaction | Already the interchange format between WS2 (builder) and WS1 (signer); the path to hardware signing (vizor ships PCZT hardware signing for single-sig shielded). |

## 3. Audit scope (keep it small on purpose)

By adopting the ZF stack (WS4), the **audited** crates carry the threshold crypto and
relay. What remains **Loki-specific and must be reviewed**:

1. **The signer shell (WS1):** at-rest key hierarchy, secure-element wrapping, biometric
   gating, nonce crash-safety, and the WYSIWYS PCZT parse/render + approval. This is the
   highest-value review target — it is what stands between an attacker and a share.
2. **The keyless-coordinator boundary (WS2 §4):** proof that no share/nonce/spend path
   exists in the coordinator/browser.
3. **FVK derivation (WS5)** if Option A is kept (#1094).
4. **The thin enrollment/roster layer (WS3 §4).**

Everything else (scan, balance, broadcast) is non-custodial public-data code and is a
lower review priority.

## 4. App-delivery trust (the hardening the current docs demand)

`WALLET_BUILD.md` is explicit: "App delivery is part of custody… A custody design needs
an independently delivered app in every possible approving pair and must count every
device each member uses." The split architecture **narrows** this to the **signer**
(the coordinator holds no key, so its delivery is not custody), which is a large win,
but the signer's delivery is now the thing that matters:

- **Reproducible builds** of the signer; published hashes.
- **Signed releases** + (stretch) signature transparency, so a targeted malicious
  signer build is detectable.
- **Independent delivery across approving pairs**: members in a quorum should not all
  receive their signer from a single mutable origin; prefer app stores / reproducible
  artifacts so a single compromised publisher cannot silently backdoor a threshold.
- **Device counting**: a member using N devices means N signer installs to account for.

## 5. The release boundary (unchanged, restated)

Real custody still requires, per `WALLET_BUILD.md`: resolved FVK/randomizer review
(WS5/#1094), the native key-storage decision (**now made** — WS1), physical crash and
rollback tests (WS1 §8 nonce safety + reorg handling), independent recovery spend,
chain-sync/reorg validation, and an external security review (WS6 §3). Every pre-custody
build shows its network plainly and refuses mainnet funds.

## 6. Acceptance criteria

1. A one-page **audit-scope map** naming exactly which files/modules an external auditor
   must review (the short WS1/WS2-boundary/WS5/roster list above), with everything else
   explicitly marked out-of-custody-scope.
2. Reproducible-build recipe for the signer that two machines reproduce to the same
   hash.
3. A written **#490 alignment note**: which of our signer-API/backup formats match the
   spec and which diverge, with a plan to converge.
4. A **#1094 disposition**: either "using audited `zcash-sign` derivation, N/A" or an
   upstream review thread link.

## 7. Dependencies

Cross-cuts all workstreams; gated by WS4 (what's audited) and WS5 (#1094 outcome).
</content>
