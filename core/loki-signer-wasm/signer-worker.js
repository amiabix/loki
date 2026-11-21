// Module Web Worker hosting the stateful in-browser signer (Phase A: profile lifecycle).
//
// The signing/DKG core is synchronous and persists to OPFS through synchronous access
// handles, which exist ONLY inside a Worker and must be acquired asynchronously FIRST. So
// this worker owns the pre-open protocol: before each synchronous `Signer` call it awaits
// `opfsPreopen{Write,Read}` on exactly the deterministic paths that op touches, then calls
// the sync wasm method. The path set is `devicePaths()` from the wasm module — one source
// of truth, no drift.
//
//   createSigner  preopenWrite: identity.sealed, profile.json, (passphrase) kek.salt
//   hasSigner     preopenRead:  identity.sealed
//   unlock        preopenRead:  identity.sealed, profile.json, (passphrase) kek.salt
//   lock          no I/O
//
// One worker per page lifetime: OPFS sync handles are exclusive, so a single long-lived
// Signer instance holds them; a page reload terminates it and releases them.

import init, { Signer, devicePaths, vaultPaths } from "./pkg/loki_signer_wasm.js";
import {
  opfsPreopenWrite as preopenWriteOnce,
  opfsPreopenRead as preopenReadOnce,
  opfsCloseAll,
} from "./pkg/snippets/loki-signer-core-8724841f4db15c9f/js/opfs_fs.js";
import { blockRange, latestHeight } from "./lightwalletd.js";
import { controlInbox, endsRequest, idbStore } from "./control-inbox.js";
import { vaultSummary, saveVaultName, readVaultName } from "./vault-list.js";

// Ops run concurrently (a status read during a join), and two pre-opens of one path racing
// would each try to take its exclusive sync handle; the second throws. Share one in-flight
// pre-open per path instead.
const inflight = new Map();
function shared(open) {
  return (path) => {
    const key = `${open === preopenWriteOnce ? "w" : "r"}:${path}`;
    if (!inflight.has(key)) inflight.set(key, open(path).finally(() => inflight.delete(key)));
    return inflight.get(key);
  };
}
const opfsPreopenWrite = shared(preopenWriteOnce);
const opfsPreopenRead = shared(preopenReadOnce);

const ready = init().then(() => {
  const P = JSON.parse(devicePaths()); // { identity, profile, salt, recovery }
  return { signer: new Signer(), P };
});

// The frostd transport is a SEPARATE wasm module (core/wasm-transport) so its reqwest dep tree
// stays isolated from the signer core. It is loaded lazily, and only from its pinned path on
// this (the signer) origin — never from a caller-supplied URL — so lifecycle-only pages never
// fetch it and no page can swap the code that runs beside the signer.
const TRANSPORT_URL = new URL("./wasm-transport/pkg/loki_wasm_transport.js", import.meta.url).href;
let transport = null;
async function loadTransport() {
  if (!transport) {
    const mod = await import(TRANSPORT_URL);
    await mod.default();
    transport = mod;
  }
  return transport;
}
async function loadFrostd() {
  return (await loadTransport()).FrostdClient;
}

// Claim this signature's nonce at BOTH external witnesses (fresh, pinned-key receipts verified
// in wasm-transport), then tell the signer; the core's witness check in signApprove accepts
// only that claim. A duplicate at either relay (a nonce already used) refuses the signature.
async function claimAtWitnesses(signer, witnesses, packageHex, seedHex, sighashHex) {
  const { cid, record } = JSON.parse(signer.nonceClaim(packageHex, seedHex, sighashHex));
  const { claimNonce } = await loadTransport();
  for (const w of witnesses) {
    if (!await claimNonce(w.endpoint, w.key, w.run, w.mailbox, w.read, cid, record)) {
      throw new Error("This nonce was already claimed at a nonce witness; start a new signing attempt");
    }
  }
  signer.nonceClaimed(cid, record);
}

// Testnet NU5 (Orchard) activation height (zakura-protocol consensus.rs, TestNetwork). No
// Orchard vault can be born below it.
const TESTNET_NU5_HEIGHT = 1_842_420;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const toHex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");

function b64urlToBytes(s) {
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/");
  const pad = b64.length % 4 ? "=".repeat(4 - (b64.length % 4)) : "";
  const bin = atob(b64 + pad);
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

async function postJson(url, body) {
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error ?? `request to ${url} failed (${res.status})`);
  return data;
}

// Retry `fn` until it resolves (the creator's roster/session endpoints 404 "pending" until
// every member has enrolled/agreed), bounded so a stalled ceremony fails instead of hanging.
async function poll(fn, p) {
  const pollMs = Number(p.joinPollMs) || 500;
  const max = Number(p.joinMaxTicks) || 240;
  let lastErr;
  for (let i = 0; i < max; i++) {
    try {
      return await fn();
    } catch (e) {
      lastErr = e;
      await sleep(pollMs);
    }
  }
  throw lastErr ?? new Error("ceremony step timed out");
}

// Decode a creator invite and run the native joiner dance against the creator's member app
// (core/src/host/ceremony.rs: enroll → poll roster → agree → poll session), then hand the
// assembled DKG params to driveDkg. The four endpoints are token-authenticated member-to-member
// calls the creator CORS-opens for browser joiners (routes.rs `browser_origin`). The setup
// document the creator feeds its own dkg_begin is rebuilt here from the polled roster — the
// roster fingerprint is over PARSED content (member_state::Roster::fingerprint), so field/byte
// order is irrelevant and only the values must match.
async function joinCeremony(signer, p) {
  const invite = JSON.parse(new TextDecoder().decode(b64urlToBytes(p.invite)));
  const base = invite.creator_base_url.replace(/\/+$/, "");
  const { vault, slot, token, threshold, name } = invite;
  const network = p.network ?? "testnet";

  // Our enrolled identity at the target slot: the device signing/relay keys (slot-independent;
  // restamp only overwrites the id bytes) stamped with the slot id. Needs the signer unlocked.
  const material = JSON.parse(signer.enrollMaterial());
  const identity = { id: slot, signing: material.signing_pubkey, encryption: material.relay_pubkey };
  await postJson(`${base}/api/enroll`, { vault, slot, token, identity });

  // Poll until the full roster is published (fingerprint present).
  const auth = { vault, slot, token };
  const rosterResp = await poll(() => postJson(`${base}/api/roster`, auth), p);
  const roster = rosterResp.roster;

  // The creator must not have swapped our slot's identity.
  const mine = roster[String(slot)];
  if (!mine || mine.signing !== identity.signing || mine.encryption !== identity.encryption) {
    throw new Error("creator roster changed this member's identity");
  }

  // Rebuild the creator's setup document (setup_version 2), members sorted by slot. The
  // testnet birth_height is NOT reconstructed from a guessed tip (it would mismatch the
  // creator's and the DKG setup certificate would be refused) — it is adopted from the
  // creator's published session below, so the document matches byte-for-byte.
  const members = Object.keys(roster)
    .map(Number)
    .sort((a, b) => a - b)
    .map((s) => ({ id: s, signing: roster[String(s)].signing, encryption: roster[String(s)].encryption }));

  // The member sees EVERY member before telling the creator it agrees, not just its own slot.
  if (!Number.isSafeInteger(threshold) || threshold < 1 || threshold > members.length) {
    throw new Error("the invite's threshold does not fit the roster");
  }
  if (!await ask("roster-members", { name, vault, threshold, network, slot, members })) {
    throw new Error("You rejected this vault's members");
  }

  // Agree, then poll for the creator's frostd session + coordinator relay peer (+ birth_height).
  await postJson(`${base}/api/agreed`, auth);
  const session = await poll(
    () =>
      postJson(`${base}/api/session`, auth).then((s) =>
        s.session_id && s.coordinator_peer && (network !== "testnet" || s.birth_height != null)
          ? s
          : Promise.reject(new Error("session pending"))),
    p,
  );

  // The creator's birth height: it is inside the roster fingerprint, so every member's roster
  // code differs if the creator gave members different heights. Here it must at least be a
  // real Orchard-era Testnet height. ponytail: no upper bound — the browser has no chain
  // source to compare against; add one when the signer can reach a lightwalletd.
  const doc = { vault, threshold, setup_version: 2, network, members };
  if (network === "testnet") {
    const height = Number(session.birth_height);
    if (!Number.isSafeInteger(height) || height < TESTNET_NU5_HEIGHT) {
      throw new Error("the creator's vault birth height is not a Testnet Orchard height");
    }
    doc.birth_height = height;
  }
  const rosterHex = toHex(new TextEncoder().encode(JSON.stringify(doc)));

  return driveDkg(signer, {
    vaultHex: vault,
    slot,
    label: p.label ?? name,
    network,
    rosterHex,
    birthHeight: doc.birth_height,
    frostdUrl: p.frostdUrl,
    sessionId: session.session_id,
    coordinatorPeer: session.coordinator_peer,
    pollMs: p.pollMs,
    maxTicks: p.maxTicks,
  });
}

// Drive this member through create-or-reopen → confirm roster → DKG rounds ↔ frostd → backup
// → active, then release the vault address. The signer core is synchronous (vaultJoin/vaultStep/
// vaultBackup/vaultReady/vaultAddress); this loop owns the async frostd pump. The coordinator
// (a roster member running the frostd relay) forwards each member's wires to its peers; this
// member only ever sends to the coordinator and keeps the coordinator's relayed wires.
async function driveDkg(signer, p) {
  const { vaultHex, slot, label, network, rosterHex, frostdUrl, coordinatorPeer, sessionId } = p;
  for (const path of JSON.parse(vaultPaths(vaultHex))) await opfsPreopenWrite(path);
  // The backup also seals to the recovery public key; without one vaultJoin refuses.
  await opfsPreopenRead(JSON.parse(devicePaths()).recovery);

  // The 24-digit roster code, computed by the signer from the exact roster it will confirm,
  // shown on the signer page for the member to compare with every other member. vaultJoin's
  // roster prompt answers Match only for the code the member confirmed here.
  const roster = Uint8Array.from(rosterHex.match(/../g).map((b) => parseInt(b, 16)));
  const code = signer.rosterCode(roster);
  if (!await ask("roster-code", { code, birth_height: p.birthHeight ?? null })) {
    throw new Error("You reported that the roster codes differ; this vault setup is stopped");
  }
  const vref = JSON.parse(signer.vaultJoin(vaultHex, slot, label ?? "vault", network, roster, code));
  if (label) await saveVaultName(await (await (await (await navigator.storage.getDirectory()).getDirectoryHandle("loki")).getDirectoryHandle("vaults")).getDirectoryHandle(vaultHex), label);

  const fc = await frostdClient(signer, { frostdUrl });
  fc.useSession(sessionId);

  const pollMs = Number(p.pollMs) || 200;
  const maxTicks = Number(p.maxTicks) || 1200;
  let ready = false;
  for (let tick = 0; tick < maxTicks && !ready; tick++) {
    const inbox = JSON.parse(await fc.recv());
    const inWires = inbox.filter((m) => m.from === coordinatorPeer).map((m) => m.message);
    for (const w of signer.vaultStep(inWires)) await fc.sendToCoordinator(w);
    for (const r of signer.vaultBackup()) await fc.sendToCoordinator(r);
    ready = signer.vaultReady();
    if (!ready) await sleep(pollMs);
  }
  if (!ready) throw new Error("DKG did not reach active before the deadline");
  return { vault: vref.vault_id, address: signer.vaultAddress() };
}

// Reopen this browser's signer for an active vault from its own stored state. Every member
// key the payment flow uses comes from the roster this member confirmed at setup.
async function openVault(signer, vaultHex) {
  const vault = await openVaultAny(signer, vaultHex);
  if (!vault.ready) throw new Error("this vault is not active yet");
  return vault;
}
async function openVaultAny(signer, vaultHex) {
  if (!/^[0-9a-f]{64}$/.test(vaultHex ?? "")) throw new Error("invalid vault id");
  for (const path of JSON.parse(vaultPaths(vaultHex))) await opfsPreopenWrite(path);
  return JSON.parse(signer.vaultOpen(vaultHex));
}

// The vault's balance and history from the chain itself: lightwalletd compact blocks from the
// vault's birth (or the last block this Worker scanned) to the tip, trial-decrypted in wasm
// (loki-signer-core chain_scan.rs). Nothing here comes from other members.
async function chainScan(signer, p) {
  if (!p.lightwalletdGrpcWeb) throw new Error("This signer has no lightwalletd gRPC-web endpoint configured, so it cannot read the chain");
  await openVault(signer, p.vaultHex);
  const tip = await latestHeight(p.lightwalletdGrpcWeb);
  // Resumes from the sealed state the last scan saved (scanSave after each batch). A block that
  // does not extend the saved tip means the chain reorganized: rescan once from the vault birth.
  // ponytail: full rescan on any reorg; roll back a few blocks if vaults get old.
  for (let rescanned = false; ;) {
    try {
      for (let next = signer.scanNext(); next <= tip; next = signer.scanNext()) {
        for (const block of await blockRange(p.lightwalletdGrpcWeb, next, Math.min(tip, next + 499))) signer.scanBlock(block);
        signer.scanSave();
      }
      break;
    } catch (e) {
      if (rescanned || !/extend|expected block/.test(String(e?.message ?? e))) throw e;
      rescanned = true;
      signer.scanReset();
    }
  }
  return { tip, ...JSON.parse(signer.scanResult()) };
}

// A payment's status for the wallet: its terms and signing group from the proposer's notices,
// and whether the chain scan saw its one input note spent (and in which transaction).
async function paymentStatus(signer, p) {
  const vault = await openVault(signer, p.vaultHex);
  const control = await frostdClient(signer, p);
  const { notices } = await findPayment(signer, control, vault, p.attemptHex, p);
  const terms = notices[notices.length - 1].intent;
  checkTerms(terms);
  const ended = notices.find((n) => n.kind === "cancelled" || n.kind === "failed")?.kind ?? null;
  const signers = notices.find((n) => n.kind === "start" && n.intent.signers?.length)?.intent.signers ?? [];
  await chainScan(signer, p);
  const spent = JSON.parse(signer.scanSpentBy(terms.note_selection[0]));
  return { terms, signers, ended, spent };
}

// The terms a proposer announced for this payment, read-only: nothing is approved or sent.
// The wallet shows them before the member opens the approval on the signer page.
async function paymentTerms(signer, p) {
  const vault = await openVault(signer, p.vaultHex);
  const control = await frostdClient(signer, p);
  const { notices } = await findPayment(signer, control, vault, p.attemptHex, p);
  const t = notices[notices.length - 1].intent;
  checkTerms(t);
  return { review_token: p.attemptHex, recipient: t.recipient, amount_zat: String(t.amount_zat), fee_zat: String(t.fee_zat), memo: t.memo };
}

// Log in to frostd without the relay secret ever reaching JS: the transport fetches the
// challenge, the wasm signer XEdDSA-signs it, and only the signature crosses back.
async function frostdClient(signer, p) {
  const Client = await loadFrostd();
  const fc = new Client(p.frostdUrl, signer.frostdPubkey());
  const challenge = await fc.challenge();
  await fc.loginSigned(challenge, signer.frostdSignChallenge(challenge));
  return fc;
}

// Drain this member's inbox on a payment control session and open each sealed message under
// the confirmed roster. Anything that does not open (a non-member, another session) is dropped.
// Returns every message opened on that session so far (control-inbox.js), not just new ones.
const controlHistory = controlInbox(idbStore());
async function readControl(signer, control, sessionId) {
  const raw = await controlHistory(sessionId, async () => {
    control.useSession(sessionId);
    return JSON.parse(await control.recv());
  });
  const out = [];
  for (const m of raw) {
    try {
      const { from, body } = JSON.parse(signer.openControl(sessionId, m.from, m.message));
      out.push({ from, ...JSON.parse(body) });
    } catch { /* not a control message sealed to this member */ }
  }
  return out;
}

// A proposer notice about this payment: the sender is the proposer and the session ids match.
function aboutPayment(msg, vault, attemptHex, controlSessionId) {
  const i = msg.intent;
  return i && msg.from === i.proposer && i.attempt === attemptHex && i.vault === vault.vault_id
    && i.control_session_id === controlSessionId && i.session_id && i.session_id !== controlSessionId;
}

// Find the payment's control session the way native members do (payment.rs `sync_control`):
// a session a vault member opened with every member as a participant, where that member sealed
// a notice about this attempt. A signing session is opened by a one-shot coordinator key, so it
// never matches. Notices already drained there are kept (readControl), and other payments'
// sessions are read once and skipped.
async function findPayment(signer, control, vault, attemptHex, p) {
  const ids = new Map(vault.members.map((m) => [m.encryption, m.id]));
  const skip = new Set();
  const pollMs = Number(p.findPollMs) || 2000;
  const maxTicks = Number(p.findMaxTicks) || 30;
  for (let tick = 0; tick < maxTicks; tick++) {
    for (const sessionId of await control.list_sessions()) {
      if (skip.has(sessionId)) continue;
      control.useSession(sessionId);
      const info = JSON.parse(await control.sessionInfo());
      const owner = ids.get(info.coordinator);
      if (owner === undefined || owner === vault.slot
        || info.participants.length !== ids.size || !info.participants.every((k) => ids.has(k))) {
        skip.add(sessionId);
        continue;
      }
      const msgs = await readControl(signer, control, sessionId);
      const notices = msgs.filter((m) => m.from === owner && aboutPayment(m, vault, attemptHex, sessionId));
      if (notices.length > 0) return { controlSessionId: sessionId, notices };
      if (msgs.length > 0) skip.add(sessionId);
    }
    await sleep(pollMs);
  }
  throw new Error("this payment was not found on the relay; it may be finished, cancelled or for another vault");
}

// Payments other members proposed in this vault that still want this member: one pass over the
// relay's control sessions, read like findPayment. The proposer sends its notice once at publish
// and again only after it approves, so a request stays listed from the notices readControl kept.
async function listPending(signer, vaultHex, p) {
  const vault = await openVault(signer, vaultHex);
  const control = await frostdClient(signer, p);
  const ids = new Map(vault.members.map((m) => [m.encryption, m.id]));
  const pending = new Map();
  for (const sessionId of await control.list_sessions()) {
    control.useSession(sessionId);
    const info = JSON.parse(await control.sessionInfo());
    const owner = ids.get(info.coordinator);
    if (owner === undefined || owner === vault.slot
      || info.participants.length !== ids.size || !info.participants.every((k) => ids.has(k))) continue;
    for (const m of await readControl(signer, control, sessionId)) {
      const i = m.intent;
      if (m.from !== owner || !i || !/^[0-9a-f]{64}$/.test(i.attempt ?? "") || !aboutPayment(m, vault, i.attempt, sessionId)) continue;
      if (endsRequest(m, vault.slot)) { pending.set(i.attempt, null); continue; }
      if (pending.get(i.attempt) === null) continue;
      pending.set(i.attempt, { attempt: i.attempt, amount_zat: String(i.amount_zat), recipient: i.recipient, proposer: i.proposer });
    }
  }
  return [...pending.values()].filter(Boolean);
}

// Every vault this browser holds a signer for, from its own OPFS (loki/vaults/<id>/signer).
async function listVaults(signer) {
  let dir;
  try {
    dir = await (await (await navigator.storage.getDirectory()).getDirectoryHandle("loki")).getDirectoryHandle("vaults");
  } catch { return []; } // no vault yet
  const out = [];
  for await (const [name, h] of dir.entries()) {
    if (h.kind !== "directory" || !/^[0-9a-f]{64}$/.test(name)) continue;
    let v;
    try { v = await openVaultAny(signer, name); } catch { continue; } // setup never started
    out.push(vaultSummary(v, await readVaultName(h)));
  }
  return out;
}

// The proposer's latest word on the signing group: `start` names it and fixes the signing
// expiry (outside the intent hash, like the group), `cancelled` and `failed` end the request.
// Plain `intent` re-announcements change nothing.
function groupFrom(notices) {
  for (const n of notices) {
    if (n.kind === "cancelled") throw new Error("the proposer cancelled this payment");
    if (n.kind === "failed") throw new Error("the proposer could not complete this payment");
    if (n.kind === "start" && n.intent.signers?.length) {
      return { signers: n.intent.signers, signingExpiry: n.intent.signing_expiry ?? null };
    }
  }
  return null;
}

// Drive this NON-proposer member through one payment signing attempt over frostd, mirroring
// the native `signer_loop`: find the payment on the relay → approve → wait for the signing
// group → commit → receive the proposer's sealed candidate + the coordinator's signing package
// and rerandomizer seed → WYSIWYS-review the candidate → release the signature share.
// Everything comes from the relay and this member's own stored roster; no member serves HTTP.
//
// The request is open to every member: the proposer fixes the signing group from the first
// approvals to arrive. So this member approves, waits for the group, and commits a nonce only
// if the group includes it; a commitment from outside the group would fail the round.
async function drivePayment(signer, p) {
  const { vaultHex, attemptHex } = p;
  // Like a native member without --nonce-witnesses: no witnesses, no signing — refused before
  // anything is approved or committed.
  if (!Array.isArray(p.nonceWitnesses) || p.nonceWitnesses.length !== 2) {
    throw new Error("This signer has no nonce witnesses configured, so it cannot sign");
  }
  signer.setNonceWitnesses(JSON.stringify(p.nonceWitnesses.map(({ key, run, mailbox }) => ({ key, run, mailbox }))));
  const vault = await openVault(signer, vaultHex);
  const control = await frostdClient(signer, p);
  const { controlSessionId, notices } = await findPayment(signer, control, vault, attemptHex, p);
  const announced = notices[notices.length - 1];
  const proposer = vault.members.find((m) => m.id === announced.from);

  const terms = announced.intent;
  checkTerms(terms);

  // Approve on the control session: a sealed {kind:"approval"} for the terms the proposer
  // announced, which the proposer records (payment.rs `sync_control`). Durable at frostd. The
  // member sees those terms on the signer page first; declining sends nothing.
  let group = groupFrom(notices);
  if (group && !group.signers.includes(vault.slot)) throw new Error("enough members already approved this payment");
  if (!group) {
    if (!await ask("payment-terms", terms)) throw new Error("You declined this payment request");
    const approval = JSON.stringify({ kind: "approval", hash: announced.hash, intent: terms, txid: null });
    await control.sendToPeer(proposer.encryption, signer.sealControl(controlSessionId, proposer.id, approval));
    group = await waitForSigningGroup(signer, control, vault, attemptHex, controlSessionId, proposer.id, p);
  }
  const { signers, signingExpiry } = group;
  if (!signers.includes(vault.slot)) return { approved: true, signed: false };
  // The transaction's real expiry is fixed by `start` (about seven days above the proposer's
  // tip) and must lie above the anchor and no later than the approved bound (payment.rs
  // `check_intent`). Without one, the approved bound is the expiry.
  const expiry = signingExpiry ?? terms.expiry_height;
  if (!Number.isSafeInteger(expiry) || expiry <= terms.target_height || expiry > terms.expiry_height) {
    throw new Error("the proposer's signing expiry is outside the approved terms");
  }

  // The signing session's coordinator is the one-shot key that opened it.
  const fc = await frostdClient(signer, p);
  const signingSessionId = announced.intent.session_id;
  fc.useSession(signingSessionId);
  const coordinatorPeer = JSON.parse(await fc.sessionInfo()).coordinator;
  if (!coordinatorPeer || vault.members.some((m) => m.encryption === coordinatorPeer)) {
    throw new Error("the payment's signing session has no coordinator");
  }

  // Pre-open this attempt's crash-safe nonce files (name = payment_id ++ attempt_id hex; the
  // native host sets both to the attempt), so the synchronous commit/sign can persist.
  const nonceId = attemptHex + attemptHex;
  const dir = `loki/vaults/${vaultHex}/signer`;
  await opfsPreopenWrite(`${dir}/nonces/${nonceId}.nonce`);
  await opfsPreopenWrite(`${dir}/nonces/${nonceId}.burn`);

  // Round 1: emit this member's public commitment to the coordinator.
  await fc.sendToCoordinator(signer.signCommit(attemptHex));

  // Collect the three inbound messages: the sealed candidate (from the proposer) and the
  // signing package + 32-byte seed (from the coordinator). The 32-byte message is the seed;
  // the longer coordinator message is the package.
  const signersCsv = signers.join(",");
  let candidateHex = null, packageHex = null, seedHex = null;
  const pollMs = Number(p.pollMs) || 200;
  const maxTicks = Number(p.maxTicks) || 1200;
  for (let tick = 0; tick < maxTicks; tick++) {
    for (const m of JSON.parse(await fc.recv())) {
      if (m.from === proposer.encryption && candidateHex === null) {
        candidateHex = signer.openCandidate(proposer.signing, proposer.encryption, proposer.id, signersCsv, attemptHex, m.message);
      } else if (m.from === coordinatorPeer) {
        if (m.message.length === 64) seedHex = m.message; // 32 bytes hex
        else packageHex = m.message;
      }
    }
    if (candidateHex !== null && packageHex !== null && seedHex !== null) break;
    await sleep(pollMs);
  }
  if (candidateHex === null || packageHex === null || seedHex === null) {
    throw new Error("payment signing messages did not arrive before the deadline");
  }

  // The signer's own parse of the candidate must be exactly the approved terms (network,
  // expiry, the one input note, recipient, amount, memo, change, fee) — refused otherwise,
  // before the member is even asked. Then the member confirms that parse on the signer page
  // with a fresh passkey assertion (or the passphrase again), and signApprove releases the
  // share only for the sighash the member confirmed.
  const review = JSON.parse(signer.paymentCheck(candidateHex, JSON.stringify({ ...terms, tx_expiry: expiry })));
  const consent = await ask("payment-sign", review);
  if (!consent) throw new Error("You declined to sign this payment");
  signer.reauth(consent.method, consent.passphrase, consent.prfSecret);
  await claimAtWitnesses(signer, p.nonceWitnesses, packageHex, seedHex, review.sighash);
  const share = signer.signApprove(attemptHex, candidateHex, packageHex, seedHex, review.sighash, JSON.stringify({ ...terms, tx_expiry: expiry }));
  await fc.sendToCoordinator(share);
  return { approved: true, signed: true, review };
}

// The announced terms, shape-checked before they are shown (payment.rs `check_intent`). The
// wasm `paymentCheck` re-checks every value against the candidate itself.
function checkTerms(t) {
  const ok = t && typeof t.recipient === "string" && typeof t.memo === "string"
    && [t.amount_zat, t.fee_zat, t.change_zat, t.target_height, t.expiry_height].every(Number.isSafeInteger)
    && t.amount_zat > 0 && t.expiry_height > t.target_height
    && Array.isArray(t.note_selection) && t.note_selection.length === 1;
  if (!ok) throw new Error("the proposer announced invalid payment terms");
}

// Wait on the control session until the proposer names the signing group. Nothing secret is
// committed while waiting, so giving up here is safe: approving again resumes the wait.
async function waitForSigningGroup(signer, control, vault, attemptHex, controlSessionId, proposerId, p) {
  const pollMs = Number(p.groupPollMs) || 2000;
  const maxTicks = Number(p.groupMaxTicks) || 900; // 30 minutes at the default poll
  for (let tick = 0; tick < maxTicks; tick++) {
    await sleep(pollMs);
    const notices = (await readControl(signer, control, controlSessionId))
      .filter((m) => m.from === proposerId && aboutPayment(m, vault, attemptHex, controlSessionId));
    const group = groupFrom(notices);
    if (group) return group;
  }
  throw new Error("Your approval is recorded, but not enough members approved yet. Open this payment again later to sign.");
}

async function preopenCreate(P, method) {
  await opfsPreopenWrite(P.identity);
  await opfsPreopenWrite(P.profile);
  if (method === "passphrase") await opfsPreopenWrite(P.salt);
}

async function preopenUnlock(P, method) {
  await opfsPreopenRead(P.identity);
  await opfsPreopenRead(P.profile);
  if (method === "passphrase") await opfsPreopenRead(P.salt);
}

// On-device decisions: the worker asks the signer page (signer-page.js), which shows the
// prompt on the signer origin and answers. The wallet page never sees or answers these.
const asks = new Map();
let askSeq = 0;
let busy = null; // "join" | "payment-approve" while one holds the open vault
let turn = Promise.resolve(); // vault ops take turns
function ask(kind, data) {
  const id = ++askSeq;
  return new Promise((resolve, reject) => {
    asks.set(id, { resolve, reject });
    self.postMessage({ ask: id, kind, data });
  });
}

self.onmessage = async (e) => {
  if (e.data.answer !== undefined) {
    const a = asks.get(e.data.answer);
    asks.delete(e.data.answer);
    if (a) e.data.ok ? a.resolve(e.data.value) : a.reject(new Error(e.data.error));
    return;
  }
  const { id, op, method, name, passphrase, prfSecret, join, payment, devicePubHex, vaultHex, words, blob } = e.data;
  // The Signer holds ONE open vault, and these ops each reopen one. A join, payment, restore
  // or removal holds it, so the quick reads are refused while one runs (the wallet polls
  // again) and otherwise take turns, so no op swaps the vault under another mid-flight.
  const holds = op === "join" || op === "payment-approve" || op === "restore" || op === "remove";
  const reads = op === "payment-review" || op === "pending" || op === "vaults" || op === "address" || op === "recovery-backup" || op === "chain" || op === "payment-status";
  let release = () => {};
  try {
    if (reads && busy) throw new Error(`the signer is busy with a ${{ join: "vault setup", "payment-approve": "payment", restore: "restore", remove: "removal" }[busy]}; try again when it finishes`);
    if (holds) busy = op;
    if (reads || holds) {
      const prev = turn;
      turn = new Promise((r) => { release = r; });
      await prev;
    }
    const { signer, P } = await ready;
    let result;
    switch (op) {
      case "has":
        await opfsPreopenRead(P.identity);
        result = signer.hasSigner();
        break;
      case "enroll-material":
        // Public roster enrollment identity; the unlocked device identity is already in memory.
        result = JSON.parse(signer.enrollMaterial());
        break;
      case "authorize-device":
        result = signer.authorizeDevice(devicePubHex);
        break;
      case "join":
        result = await joinCeremony(signer, join);
        break;
      case "payment-review":
        // The announced terms only; the candidate is checked against them inside approval.
        result = await paymentTerms(signer, payment);
        break;
      case "pending":
        result = await listPending(signer, payment.vaultHex, payment);
        break;
      case "vaults":
        result = await listVaults(signer);
        break;
      case "chain":
        result = await chainScan(signer, payment);
        break;
      case "payment-status":
        result = await paymentStatus(signer, payment);
        break;
      case "address":
        await openVault(signer, payment.vaultHex);
        result = signer.vaultAddress();
        break;
      case "payment-approve":
        result = await drivePayment(signer, payment);
        break;
      case "create":
        await preopenCreate(P, method);
        result = JSON.parse(
          signer.createSigner(method, name ?? "", passphrase, prfSecret)
        );
        break;
      case "unlock":
        await preopenUnlock(P, method);
        result = JSON.parse(signer.unlock(method, passphrase, prfSecret));
        break;
      case "lock":
        signer.lock();
        result = null;
        break;
      case "has-recovery":
        await opfsPreopenRead(P.recovery);
        result = signer.hasRecovery();
        break;
      case "recovery-begin":
        // The words go only to the signer page, which shows them once.
        await opfsPreopenRead(P.recovery);
        result = signer.recoveryBegin();
        break;
      case "recovery-confirm":
        await opfsPreopenWrite(P.recovery);
        signer.recoveryConfirm();
        result = null;
        break;
      case "recovery-backup":
        for (const path of JSON.parse(vaultPaths(vaultHex))) await opfsPreopenWrite(path);
        result = signer.recoveryBackup(vaultHex);
        break;
      case "restore":
        await preopenCreate(P, method);
        await opfsPreopenWrite(P.recovery);
        for (const path of JSON.parse(vaultPaths(vaultHex))) await opfsPreopenWrite(path);
        result = JSON.parse(signer.restoreSigner(method, name ?? "", passphrase, prfSecret, vaultHex, words, blob));
        break;
      case "remove": {
        // Delete every signer file in this browser: release the sync handles, then the tree.
        signer.lock();
        opfsCloseAll();
        const root = await navigator.storage.getDirectory();
        await root.removeEntry("loki", { recursive: true }).catch((e) => { if (e.name !== "NotFoundError") throw e; });
        result = null;
        break;
      }
      default:
        throw new Error(`unknown op: ${op}`);
    }
    self.postMessage({ id, ok: true, result });
  } catch (err) {
    self.postMessage({ id, ok: false, error: String((err && err.message) || err) });
  } finally {
    if (holds) busy = null;
    release();
  }
};

self.addEventListener("unhandledrejection", () => self.postMessage({ cmd: "failed" }));
try {
  await ready;
  self.postMessage({ cmd: "loaded" });
} catch { self.postMessage({ cmd: "failed" }); }
