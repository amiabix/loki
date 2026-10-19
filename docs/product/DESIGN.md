# Loki Wallet — Redesign (review prototype)

Status: **review prototype**, not an implementation. A self-contained, static,
clickable walkthrough of the full member journey lives at
`poc/wallet/design/index.html` (open it directly in a browser — no build, no
deps, no backend). It does **not** touch or replace the shipping app in
`poc/wallet/`.

The prototype realises the Safe-shaped split from `docs/product/00-architecture.md`:
a **keyless coordinator** (this UI — only public data) and an **isolated signer**
(holds the share, approves on-device). The signer-approval screen is the hero and
is the UI expression of invariant 3 and §5.4, "what you see is what you sign."

## Design direction

Clean and modern, Safe/Linear-inspired, privacy-forward, **dark-mode-first** with a
light option (and a System setting). Generous spacing, strong typographic
hierarchy, subtle motion (fade-in per screen, a pulsing network dot), and a
**loud, always-visible test-network badge** so the build can never be mistaken for
mainnet: a striped strip across the top of the viewport, a badge in the sidebar,
and a badge in the top bar and on the signer hero.

Fonts reuse the existing wallet assets so the prototype needs no new downloads and
keeps the house voice:
- **Geist** — chrome and UI.
- **Geist Mono** — anything a person compares character-by-character (addresses,
  fingerprints, short codes, tx fields, challenges).
- **Young Serif** — the few things a person reads once and must trust (screen
  titles, the "this is exactly what you are signing" line, memos).

## Design tokens

All tokens live in `poc/wallet/design/tokens.css`. Components reference semantic
names only — never a raw hex — so a theme change is a change in one place. Two full
palettes (dark default, light) are mapped onto semantic variables; `[data-theme]`
makes the explicit choice win, a `prefers-color-scheme` block covers System.

### Colour (semantic)

| Token | Dark | Light | Role |
|---|---|---|---|
| `--bg` / `--bg-2` | `#0a0e14` / `#0d131b` | `#eef1ee` / `#e6ebe7` | app ground / rail |
| `--surface` → `--surface-3` | `#121a24` … `#1b2835` | `#fff` … `#eaeeeb` | cards, insets, hover |
| `--line` / `--line-soft` | `#22303d` / `#1a2530` | `#d3dcd6` / `#e2e8e4` | borders |
| `--text` / `--dim` / `--faint` | `#eef2f6` / `#93a1b0` / `#5f6f7e` | `#0f1b17` / `#4a5a52` / `#7a8a81` | text ramp |
| `--accent` (+ hi/lo) | `#19e3a0` | `#00704e` | the **one** safe action colour (mint) |
| `--warn` | `#f6b73c` | `#8a5603` | steps where a mistake is **permanent** |
| `--danger` | `#ff5566` | `#b01f2d` | refuse / remove / destructive |
| `--info` | `#5aa9ff` | `#1c5fb0` | neutral explanation |
| `--mono` | `#8fe7cc` | `#00704e` | compare-text accent |

One accent only: mint means "the safe forward action." Amber is reserved for
irreversibility (backup, roster lock, remove-member). Red is refusal and
destruction. This keeps the signer hero legible under stress.

### Type scale

`--fs-micro 11` · `xs 12` · `sm 13` · `base 15` · `md 17` · `lg 22` · `xl 30` ·
`2xl 40` · `hero 52` (px equivalents; defined in `rem`). Titles use Young Serif;
the amount on the signer hero uses Geist Mono at `--fs-hero`.

### Spacing / radius / motion

Spacing step scale `--sp-1 … --sp-8` (4px → 64px). Radii `--r-sm 8` · `md 12` ·
`lg 16` · `xl 22` · `pill`. Motion: `--dur 180ms`, one easing curve `--ease`; all
motion is disabled under `prefers-reduced-motion`.

## Files

| File | What |
|---|---|
| `poc/wallet/design/index.html` | all 10 screens as toggled sections; sidebar journey nav; top bar; signer hero |
| `poc/wallet/design/tokens.css` | design tokens + theme application |
| `poc/wallet/design/app.css` | components (cards, buttons, pills, steps, kv rows, hero, forms) |
| `poc/wallet/design/proto.js` | nav between screens, theme toggle, small state demos (DKG progress, send states, approve/refuse, address reveal) |

Fonts are loaded from the existing `poc/wallet/fonts/` via `../fonts/`. No assets
are copied or modified.

## Screen-by-screen

Vocabulary matches `WALLET_BUILD.md` (profile, vault, roster, DKG, candidate,
intent, approval) and the states in its *Boundaries and state* section. The
existing `poc/wallet/index.html` element semantics are preserved — the redesign
re-skins the same flow, it does not invent new steps.

1. **Connect signer** — Safe's "connect a signer wallet" contract. Shows origin,
   network, requested access, and a short-lived challenge; approval happens on the
   signer. Copy states plainly that this page holds no key and that approving only
   grants read of public vault data. (ws1 §9 Connect.)

2. **Vaults (dashboard)** — only this member's vaults, each with a status pill
   (Active / Creating keys / Waiting for members), balance at a named height, and a
   restore entry point. Mirrors the "list only this signer's vaults" rule.

3. **Create vault — general t-of-n** — threshold `t` and member count `n` are both
   pickable (prototype defaults to 3-of-5 to prove it is not hardcoded). Generates
   one invite per other member; creator is slot 1; the vault is a draft with no
   address. Copy notes the roster/threshold become immutable at setup.

4. **Join vault** — paste invite, see vault/threshold/inviter/slot, and compare the
   roster fingerprint short-code with other members through a trusted channel.
   Warns that agreement shows readiness but the comparison is what reveals a wrong
   claimant.

5. **Setup & backup** — a resumable step rail (members → roster → DKG → backup →
   active). DKG progress bar survives restarts (copy + demo advance). Short-code
   compare blocks. Backup card + 24 words with a mandatory "prove you can restore"
   gate; the address stays hidden and the vault activates only when all confirm.

6. **Vault overview** — balance at a named chain height from this device's own
   scan, receive UA (revealed on demand, since it only exists once active),
   member/roster list with backup status, pending payments and history with state
   pills.

7. **Propose payment** — recipient, amount, memo; an Effects panel showing
   fee / change / expiry / approvals-required. **No pair selector** — copy explains
   a candidate is built for every eligible quorum. The first visit is labelled
   *Preparing*, not Approved.

8. **Signer approval (HERO)** — full-screen, signer-chrome takeover (rail and top
   bar hide). A "Parsed from the transaction bytes" tag and a Young-Serif "This is
   exactly what you are signing" headline. The amount is the largest thing on
   screen; a key-value card renders **To / Amount / Fee / Change / Memo / Network**
   from the PCZT. A warning makes clear a malicious coordinator can only cause a
   *refusal*. Two actions: a large, easy **Refuse** (danger) and **Approve with Face
   ID** (biometric). Refusal copy states it is a member decision, not a veto. This
   is the UI of invariant 3 / threat §5.4 and ws1 §9.

9. **Send & confirm** — the state machine from `WALLET_BUILD.md`: Preparing →
   Collecting commitments → Ready to send → Broadcast → Confirmed, with a demo
   "simulate reorg rollback" that returns to Broadcast. Approvals list shows
   progress; copy states any synced member can finish and that Confirmed is
   per-device from its own scan.

10. **Recover / leave** — restore from 24 words + card on a new device (notes the
    fresh nonce epoch and that the old device is not removed); and leave/remove a
    member, with the hard truth that it creates a new vault and sweeps funds.

## Non-goals of the prototype

No real crypto, network, scanning, or signing. The JS only toggles screens and a
few illustrative states. Addresses, fingerprints, codes and amounts are fixed
placeholders chosen to read as testnet (`utest1…`, `TAZ`). This is a review
artifact to agree the look and flow before implementation (WS1/WS2).
