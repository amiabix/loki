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
  const { id, op, method, name, passphrase, prfSecret, dkg } = e.data;
  try {
    const { signer, P } = await ready;
    let result;
    switch (op) {
      case "has":
        await opfsPreopenRead(P.identity);
        result = signer.hasSigner();
        break;
      case "dkg":
        result = await driveDkg(signer, dkg);
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
