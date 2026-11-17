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
  opfsPreopenWrite,
  opfsPreopenRead,
} from "./pkg/snippets/loki-signer-core-8724841f4db15c9f/js/opfs_fs.js";

const ready = init().then(() => {
  const P = JSON.parse(devicePaths()); // { identity, profile, salt }
  return { signer: new Signer(), P };
});

// The frostd transport is a SEPARATE wasm module (poc/wasm-transport) so its reqwest/xeddsa
// dep tree stays isolated from the signer core. It is loaded lazily from the URL the UI passes
// in the DKG params (`transportUrl`), so lifecycle-only pages never fetch it.
let FrostdClient = null;
async function loadFrostd(transportUrl) {
  if (!FrostdClient) {
    const mod = await import(transportUrl);
    await mod.default();
    FrostdClient = mod.FrostdClient;
  }
  return FrostdClient;
}

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
// (poc/src/host/ceremony.rs: enroll → poll roster → agree → poll session), then hand the
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

  const doc = { vault, threshold, setup_version: 2, network, members };
  if (network === "testnet") doc.birth_height = Number(session.birth_height);
  const rosterHex = toHex(new TextEncoder().encode(JSON.stringify(doc)));

  return driveDkg(signer, {
    vaultHex: vault,
    slot,
    label: p.label ?? name,
    network,
    rosterHex,
    frostdUrl: p.frostdUrl,
    transportUrl: p.transportUrl,
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
  const { vaultHex, slot, label, network, rosterHex, frostdUrl, coordinatorPeer, sessionId, transportUrl } = p;
  for (const path of JSON.parse(vaultPaths(vaultHex))) await opfsPreopenWrite(path);

  const roster = Uint8Array.from(rosterHex.match(/../g).map((b) => parseInt(b, 16)));
  const vref = JSON.parse(signer.vaultJoin(vaultHex, slot, label ?? "vault", network, roster));

  const login = JSON.parse(signer.frostdLogin());
  const Client = await loadFrostd(transportUrl);
  const fc = new Client(frostdUrl, login.secret, login.pubkey);
  await fc.login();
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
  for (const path of JSON.parse(vaultPaths(vaultHex))) await opfsPreopenWrite(path);
  const vault = JSON.parse(signer.vaultOpen(vaultHex));
  if (!vault.ready) throw new Error("this vault is not active yet");
  return vault;
}

async function frostdClient(signer, p) {
  const login = JSON.parse(signer.frostdLogin());
  const Client = await loadFrostd(p.transportUrl);
  const fc = new Client(p.frostdUrl, login.secret, login.pubkey);
  await fc.login();
  return fc;
}

// Drain this member's inbox on a payment control session and open each sealed message under
// the confirmed roster. Anything that does not open (a non-member, another session) is dropped.
async function readControl(signer, control, sessionId) {
  control.useSession(sessionId);
  const out = [];
  for (const m of JSON.parse(await control.recv())) {
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
// never matches. Reading drains this member's inbox there; the proposer re-sends its notice every
// few seconds until signing starts, and other payments' sessions are read once and skipped.
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

// The proposer's latest word on the signing group: `start` names it, `cancelled` and `failed`
// end the request. Plain `intent` re-announcements change nothing.
function groupFrom(notices) {
  for (const n of notices) {
    if (n.kind === "cancelled") throw new Error("the proposer cancelled this payment");
    if (n.kind === "failed") throw new Error("the proposer could not complete this payment");
    if (n.kind === "start" && n.intent.signers?.length) return n.intent.signers;
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
  const vault = await openVault(signer, vaultHex);
  const control = await frostdClient(signer, p);
  const { controlSessionId, notices } = await findPayment(signer, control, vault, attemptHex, p);
  const announced = notices[notices.length - 1];
  const proposer = vault.members.find((m) => m.id === announced.from);

  // Approve on the control session: a sealed {kind:"approval"} for the terms the proposer
  // announced, which the proposer records (payment.rs `sync_control`). Durable at frostd.
  let signers = groupFrom(notices);
  if (signers && !signers.includes(vault.slot)) throw new Error("enough members already approved this payment");
  if (!signers) {
    const approval = JSON.stringify({ kind: "approval", hash: announced.hash, intent: announced.intent, txid: null });
    await control.sendToPeer(proposer.encryption, signer.sealControl(controlSessionId, proposer.id, approval));
    signers = await waitForSigningGroup(signer, control, vault, attemptHex, controlSessionId, proposer.id, p);
  }
  if (!signers.includes(vault.slot)) return { approved: true, signed: false };

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

  // WYSIWYS render (for the UI/audit) then release the share — signApprove re-derives and
  // binds the sighash itself and refuses any mismatch before touching the nonce/share.
  const review = JSON.parse(signer.paymentReview(candidateHex));
  const share = signer.signApprove(attemptHex, candidateHex, packageHex, seedHex);
  await fc.sendToCoordinator(share);
  return { approved: true, signed: true, review };
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
    const signers = groupFrom(notices);
    if (signers) return signers;
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

self.onmessage = async (e) => {
  const { id, op, method, name, passphrase, prfSecret, dkg, join, payment, devicePubHex } = e.data;
  try {
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
      case "dkg":
        result = await driveDkg(signer, dkg);
        break;
      case "join":
        result = await joinCeremony(signer, join);
        break;
      case "payment-review":
        // Reopen the vault for its viewing key, then WYSIWYS-render the supplied candidate.
        await openVault(signer, payment.vaultHex);
        result = JSON.parse(signer.paymentReview(payment.candidateHex));
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
      default:
        throw new Error(`unknown op: ${op}`);
    }
    self.postMessage({ id, ok: true, result });
  } catch (err) {
    self.postMessage({ id, ok: false, error: String((err && err.message) || err) });
  }
};

self.postMessage({ cmd: "loaded" });
