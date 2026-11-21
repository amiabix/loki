// The signer-origin page. It runs on its own origin (serve.mjs), embedded by the wallet in an
// iframe, and is the ONLY place the custody secrets are entered: the passkey PRF ceremony, the
// passphrase, the roster-code comparison and every payment approval happen here, in this
// origin's JS, never in wallet-page JS. It owns the signer Worker (signer-worker.js).
//
// The wallet talks to it only over postMessage, carrying public data: {id, op, params} in,
// {id, ok, result | error, status} out, plus {cmd: "ready" | "show" | "hide"} so the wallet
// can reveal the iframe while a prompt needs the member. Messages from any origin other than
// the configured wallet origin, or from any window other than the embedding parent, are dropped.

import { requirePersistentStorage, requireShare } from "./storage-guard.js";

const cfg = await fetch("./config.json", { cache: "no-store" }).then((r) => r.json());
const wallet = cfg.walletOrigin;
const rpId = cfg.rpId || location.hostname;
const $ = (id) => document.getElementById(id);
$("self-origin").textContent = location.origin;
$("relay").textContent = `${cfg.frostdUrl || "none configured"} · nonce witnesses: ${cfg.nonceWitnesses?.map((w) => w.endpoint).join(", ") || "none (signing is refused)"}`;

class SignerError extends Error {
  constructor(message, status = 500) { super(message); this.status = status; }
}

// ─── one signer per browser profile ──────────────────────────────────────────
// The Worker holds exclusive OPFS handles and the crash-safe nonce store, so exactly one tab
// may run it. This page holds a Web Lock for its lifetime; a second tab refuses every op
// instead of racing the first over the same share and nonces.
const owner = await new Promise((resolve) => {
  if (!navigator.locks) { resolve(false); return; }
  navigator.locks.request("loki-signer", { ifAvailable: true }, (lock) => {
    resolve(!!lock);
    return lock ? new Promise(() => {}) : undefined; // held until this page unloads
  });
});

// ─── the Worker ──────────────────────────────────────────────────────────────
const worker = owner ? new Worker("./signer-worker.js", { type: "module" }) : null;
const pending = new Map();
let seq = 0;
const loaded = new Promise((resolve) => {
  if (!worker) { resolve(); return; }
  worker.addEventListener("message", function onload(e) {
    if (e.data?.cmd === "loaded") { worker.removeEventListener("message", onload); resolve(); }
  });
});
worker?.addEventListener("message", (e) => {
  const d = e.data ?? {};
  if (d.ask !== undefined) { answerAsk(d); return; }
  const p = pending.get(d.id);
  if (!p) return;
  pending.delete(d.id);
  d.ok ? p.resolve(d.result) : p.reject(new SignerError(d.error ?? "signer error"));
});
async function call(msg) {
  if (!worker) throw new SignerError("Your signer is open in another tab. Close it there and reload.", 409);
  await loaded;
  const id = ++seq;
  return new Promise((resolve, reject) => {
    pending.set(id, { resolve, reject });
    worker.postMessage({ id, ...msg });
  });
}

// ─── prompts ─────────────────────────────────────────────────────────────────
function el(tag, props = {}, ...children) {
  const n = Object.assign(document.createElement(tag), props);
  for (const c of children) n.append(c);
  return n;
}
function facts(rows) {
  const dl = el("dl");
  for (const [k, v, mono] of rows) dl.append(el("dt", { textContent: k }), el("dd", { textContent: String(v), className: mono ? "mono" : "" }));
  return dl;
}

// Show one prompt and resolve with the value of the button the member pressed. A button's
// `run` (async, called inside the click so WebAuthn keeps its user activation) may throw to
// keep the prompt open with the error shown, or return the value to resolve with.
function prompt(title, body, buttons) {
  const main = $("prompt");
  $("title").textContent = title;
  $("body").replaceChildren(...body);
  $("error").textContent = "";
  main.hidden = false;
  parent.postMessage({ cmd: "show" }, wallet);
  return new Promise((resolve, reject) => {
    const done = (fn) => { main.hidden = true; parent.postMessage({ cmd: "hide" }, wallet); fn(); };
    $("actions").replaceChildren(...buttons.map((b) => {
      const btn = el("button", { textContent: b.label, className: b.ghost ? "ghost" : "" });
      btn.onclick = async () => {
        for (const x of $("actions").children) x.disabled = true;
        try {
          const v = b.run ? await b.run() : b.value;
          if (b.cancel) done(() => reject(new SignerError("Cancelled on the signer", 400)));
          else done(() => resolve(v));
        } catch (e) {
          $("error").textContent = e.message || String(e);
          for (const x of $("actions").children) x.disabled = false;
        }
      };
      return btn;
    }));
  });
}
const cancelButton = { label: "Cancel", ghost: true, cancel: true };

// ─── WebAuthn PRF (the custody secret is released here, on the signer origin) ─────────────
const PRF_SALT = new TextEncoder().encode("loki/signer/share-kek/v1");
const CRED = "loki_passkey_cred";
const toHex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
const fromHex = (h) => Uint8Array.from(h.match(/../g) ?? [], (x) => parseInt(x, 16));
const random = (n) => crypto.getRandomValues(new Uint8Array(n));

async function createPasskey(name, attachment) {
  const cred = await navigator.credentials.create({
    publicKey: {
      challenge: random(32),
      rp: { id: rpId, name: "Loki" },
      user: { id: random(16), name, displayName: name },
      pubKeyCredParams: [{ type: "public-key", alg: -7 }, { type: "public-key", alg: -257 }],
      authenticatorSelection: { authenticatorAttachment: attachment, residentKey: "required", userVerification: "required" },
      extensions: { prf: { eval: { first: PRF_SALT } } },
    },
  });
  if (!cred.getClientExtensionResults().prf?.enabled) {
    throw new SignerError("This authenticator has no PRF support. Use a passphrase instead.", 400);
  }
  const id = new Uint8Array(cred.rawId);
  try { localStorage.setItem(CRED, toHex(id)); } catch {}
  return id;
}

// A fresh user-verified assertion releasing the PRF secret. The remembered credential id is
// only a hint: without it (cleared storage) the authenticator offers its discoverable Loki
// passkeys for this rpId.
async function prfSecret(credentialId) {
  let id = credentialId;
  if (!id) { try { const h = localStorage.getItem(CRED); if (h) id = fromHex(h); } catch {} }
  const assertion = await navigator.credentials.get({
    publicKey: {
      challenge: random(32),
      rpId,
      ...(id ? { allowCredentials: [{ type: "public-key", id }] } : {}),
      userVerification: "required",
      extensions: { prf: { eval: { first: PRF_SALT } } },
    },
  });
  const first = assertion.getClientExtensionResults().prf?.results?.first;
  if (!first || first.byteLength < 32) throw new SignerError("This passkey released no PRF secret. Use a passphrase instead.", 400);
  try { localStorage.setItem(CRED, toHex(new Uint8Array(assertion.rawId))); } catch {}
  return new Uint8Array(first).slice(0, 32);
}

// Passphrase floor for the passphrase tier: long enough that the offline Argon2id guess
// cost dominates. ponytail: length-only rule; add a strength estimator if users pick weak long phrases.
const MIN_PASSPHRASE = 12;
function passField(label, autocomplete) {
  return el("input", { type: "password", autocomplete, spellcheck: false, placeholder: label });
}

// ─── custody: create / unlock / reauthorize ──────────────────────────────────
let current = null; // { profile, se }
let persisted = null;

// A share is sealed only while the browser keeps this origin's storage persistent
// (storage-guard.js); each unlock re-reads it so a lost grant shows in status.
async function persistent() {
  await requirePersistentStorage(navigator.storage);
  persisted = true;
}

// Ask for a new custody secret (a passphrase typed twice, or a new passkey) and pass it to
// `submit`, which seals the signer under it.
function newCustody(name, method, submit) {
  if (method === "passphrase") {
    const a = passField("Passphrase", "new-password"), b = passField("Repeat passphrase", "new-password");
    return prompt("Protect your signer with a passphrase", [
      el("p", { textContent: `At least ${MIN_PASSPHRASE} characters. It seals your share in this browser; it is not sent anywhere.` }),
      el("label", { textContent: "Passphrase" }, a), el("label", { textContent: "Repeat" }, b),
    ], [cancelButton, { label: "Create signer", run: async () => {
      if (a.value.length < MIN_PASSPHRASE) throw new SignerError(`Use at least ${MIN_PASSPHRASE} characters.`, 400);
      if (a.value !== b.value) throw new SignerError("The two passphrases differ.", 400);
      return submit({ passphrase: a.value });
    } }]);
  }
  return prompt("Create a passkey for your signer", [
    el("p", { textContent: `Your share is sealed under a passkey for ${rpId}. Touch/Face ID, a security key or your phone unlocks it.` }),
  ], [cancelButton, { label: "Create passkey", run: async () => {
    const id = await createPasskey(name, method === "platform" ? "platform" : "cross-platform");
    return submit({ prfSecret: await prfSecret(id) });
  } }]);
}

async function create({ name, method }) {
  name = String(name || "You");
  await persistent();
  const result = await newCustody(name, method, (secret) => call({ op: "create", method, name, ...secret }));
  current = { profile: result, se: method === "passphrase" ? "software" : "passkey" };
  return { profile: result, persisted };
}

async function unlock({ method }) {
  await requireShare(() => call({ op: "has" }));
  let result;
  if (method === "passphrase") {
    const a = passField("Passphrase", "current-password");
    result = await prompt("Unlock your signer", [el("label", { textContent: "Passphrase" }, a)],
      [cancelButton, { label: "Unlock", run: () => call({ op: "unlock", method, passphrase: a.value }) }]);
  } else {
    result = await prompt("Unlock your signer", [el("p", { textContent: `Use your passkey for ${rpId}.` })],
      [cancelButton, { label: "Use passkey", run: async () => call({ op: "unlock", method, prfSecret: await prfSecret() }) }]);
  }
  current = { profile: result, se: method === "passphrase" ? "software" : "passkey" };
  persisted = await navigator.storage?.persisted?.().catch(() => false) ?? false;
  return { profile: result, persisted };
}

// A fresh proof the member is present, for one approval: a new passkey assertion, or the
// passphrase typed again. The Worker checks it re-derives the unlocked KEK before signing.
function reauthField() {
  return current?.se === "passkey" ? null : passField("Passphrase", "current-password");
}
async function reauthValue(field) {
  return field ? { method: "passphrase", passphrase: field.value } : { method: "platform", prfSecret: await prfSecret() };
}

// ─── recovery: 24 words shown once, backups sealed to them ──────────────────
// The words exist only on this page, once; the signer keeps only their public keys. Each
// vault's recovery backup is ciphertext only the words open, so it is safe to download.
async function recoverySetup() {
  if (!current) throw new SignerError("Unlock your signer", 401);
  const words = (await call({ op: "recovery-begin" })).split(" ");
  await prompt("Write down your 24 recovery words", [
    el("p", { textContent: "They are shown only now. With them and a vault's recovery backup file, you can restore your signer in a new browser. Anyone who has both can sign as you." }),
    el("ol", { className: "mono" }, ...words.map((w) => el("li", { textContent: w }))),
  ], [cancelButton, { label: "I wrote them down", value: true }]);
  const chosen = new Set();
  while (chosen.size < 3) chosen.add(random(1)[0] % 24);
  const picks = [...chosen].sort((a, b) => a - b);
  const fields = picks.map(() => el("input", { autocomplete: "off", spellcheck: false }));
  await prompt("Confirm your recovery words", [
    ...picks.map((i, k) => el("label", { textContent: `Word ${i + 1}` }, fields[k])),
  ], [cancelButton, { label: "Confirm", run: async () => {
    if (picks.some((i, k) => fields[k].value.trim().toLowerCase() !== words[i])) {
      throw new SignerError("Those words do not match. Check what you wrote down.", 400);
    }
    return call({ op: "recovery-confirm" });
  } }]);
  return { recovery: true };
}

// Download a vault's recovery backup on this origin. The wallet gets the same opaque bytes.
async function recoveryExport({ vault }) {
  const blob = await call({ op: "recovery-backup", vaultHex: vault });
  await prompt("Save this vault's recovery backup", [
    el("p", { textContent: "Keep the file anywhere you like. It opens only with your 24 recovery words." }),
  ], [cancelButton, { label: "Download backup", run: () => {
    const a = el("a", { href: URL.createObjectURL(new Blob([blob])), download: `loki-recovery-${vault}.bin` });
    a.click();
    URL.revokeObjectURL(a.href);
  } }]);
  return { backup: toHex(blob) };
}

// Restore a vault member into this (fresh) browser from its words and backup file.
// The backup is opaque ciphertext, so the wallet may hand it over (`backup`, hex, with its
// `vault`), e.g. one the member kept with the coordinator; otherwise the member picks the file.
async function restore({ vault, name, method, backup }) {
  await persistent();
  const words = el("textarea", { autocomplete: "off", spellcheck: false, rows: 4 });
  const file = el("input", { type: "file" });
  const given = typeof backup === "string" && /^([0-9a-f]{2})+$/.test(backup) && /^[0-9a-f]{64}$/.test(vault ?? "");
  const input = await prompt("Restore your signer", [
    el("label", { textContent: "Your 24 recovery words" }, words),
    given ? el("p", { className: "mono", textContent: `Backup for vault ${vault.slice(0, 16)}… provided by the wallet` })
      : el("label", { textContent: "The vault's recovery backup file" }, file),
  ], [cancelButton, { label: "Continue", run: async () => {
    const typed = words.value.trim().toLowerCase().split(/\s+/).join(" ");
    if (given) return { vaultHex: vault, words: typed, blob: fromHex(backup) };
    const f = file.files[0];
    const vaultHex = vault || f?.name.match(/[0-9a-f]{64}/)?.[0];
    if (!f || !vaultHex) throw new SignerError("Choose the loki-recovery-<vault>.bin file you saved.", 400);
    return { vaultHex, words: typed, blob: new Uint8Array(await f.arrayBuffer()) };
  } }]);
  name = String(name || "You");
  const result = await newCustody(name, method, (secret) => call({ op: "restore", method, name, ...input, ...secret }));
  current = { profile: result.profile, se: method === "passphrase" ? "software" : "passkey" };
  return { ...result, persisted };
}

// Delete this browser's signer, only after the member confirms every vault's recovery
// backup is exported and the words are kept: without them the shares here are gone.
async function remove() {
  const kept = el("input", { type: "checkbox" });
  await prompt("Remove the signer from this browser?", [
    el("p", { textContent: "This deletes your sealed identity and every vault share in this browser. You can sign again only by restoring from your 24 recovery words and each vault's recovery backup file." }),
    el("label", {}, kept, " I exported every vault's recovery backup and I have my 24 words"),
  ], [cancelButton, { label: "Remove signer", run: async () => {
    if (!kept.checked) throw new SignerError("Export your recovery backups first.", 400);
    return call({ op: "remove" });
  } }]);
  current = null;
  enrollment = null;
  return null;
}

// ─── Worker asks: on-device decisions ────────────────────────────────────────
const zec = (zat) => `${(Number(zat) / 1e8).toFixed(8)} TAZ`;
const asks = {
  // The full member list, before this member tells the creator it agrees.
  "roster-members": (d) => prompt(`Join "${d.name}"?`, [
    el("p", { textContent: `${d.threshold} of ${d.members.length} members must approve each payment. Network: ${d.network}. You are member ${d.slot}.` }),
    el("ul", {}, ...d.members.map((m) => el("li", { className: "mono", textContent: `#${m.id}${m.id === d.slot ? " (you)" : ""} signing ${m.signing.slice(0, 16)}… relay ${m.encryption.slice(0, 16)}…` }))),
  ], [{ label: "Reject", ghost: true, value: false }, { label: "These are the members", value: true }]),

  // The 24-digit roster code, compared out of band with every other member.
  "roster-code": (d) => prompt("Compare this code with every other member", [
    el("p", { className: "code", textContent: d.code }),
    el("p", { textContent: "Every member's signer must show exactly these digits. If any differ, someone changed the vault setup." }),
    ...(d.birth_height != null ? [facts([["Vault birth height", d.birth_height]])] : []),
  ], [{ label: "Codes differ", ghost: true, value: false }, { label: "All codes match", value: true }]),

  "nonce-witnesses": (endpoints) => {
    const code = el("input", { type: "text", autocomplete: "off", spellcheck: false, maxLength: 64 });
    const field = reauthField();
    return prompt("Verify the nonce witnesses", [
      facts(endpoints.map((endpoint, i) => [`Witness ${i + 1}`, endpoint, true])),
      el("p", { textContent: "Get the 64-character pair fingerprint from the witness operators through a channel you trust, not from this wallet. An old signing attempt cannot use replacement witnesses." }),
      el("label", { textContent: "Witness fingerprint" }, code),
      ...(field ? [el("label", { textContent: "Passphrase" }, field)] : []),
    ], [cancelButton, { label: "Approve witnesses", run: async () => {
      const fingerprint = code.value.trim();
      if (!/^[0-9a-f]{64}$/i.test(fingerprint)) throw new SignerError("Enter the complete 64-character hexadecimal fingerprint.", 400);
      return { ...await reauthValue(field), fingerprint };
    } }]);
  },

  // The terms the proposer announced, before this member sends its approval vote.
  "payment-terms": (d) => prompt("Approve this payment request?", [
    facts([["To", d.recipient, true], ["Amount", zec(d.amount_zat)], ["Fee", zec(d.fee_zat)], ["Memo", d.memo || "(none)"],
      ["Proposed by", `member ${d.proposer}`], ["Expires by height", d.expiry_height]]),
    el("p", { textContent: "Nothing is signed yet: the transaction itself is checked against these terms before you sign." }),
  ], [{ label: "Decline", ghost: true, value: false }, { label: "Approve request", value: true }]),

  // The signer's OWN parse of the candidate transaction, after it matched the approved terms.
  // Signing needs a fresh passkey assertion (or the passphrase again).
  "payment-sign": (d) => {
    const field = reauthField();
    return prompt("Sign this transaction?", [
      facts([["To", d.recipient_ua || d.recipient, true], ["Amount", zec(d.amount_zat)], ["Fee", `${zec(d.fee_zat)}${d.fee_verified ? "" : " (unverified)"}`],
        ["Change", zec(d.change_zat)], ["Memo", d.memo_text || "(none)"], ["Expires at height", d.expiry_height], ["Sighash", d.sighash, true]]),
      ...(field ? [el("label", { textContent: "Passphrase" }, field)] : []),
    ], [{ label: "Decline", ghost: true, value: null }, { label: "Sign", run: () => reauthValue(field) }]);
  },
};
async function answerAsk(d) {
  let reply;
  try { reply = { answer: d.ask, ok: true, value: await asks[d.kind](d.data) }; }
  catch (e) { reply = { answer: d.ask, ok: false, error: e.message || String(e) }; }
  worker.postMessage(reply);
}

// ─── enrollment: the device-login key lives on the signer origin ────────────────────────
// A non-extractable P-256 key in this origin's IndexedDB, authorized by the member identity in
// wasm. The wallet sees only public enrollment material and the transcript signature.
function idb() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open("loki_signer", 1);
    req.onupgradeneeded = () => req.result.createObjectStore("device");
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}
function idbReq(db, mode, fn) {
  return new Promise((resolve, reject) => {
    const r = fn(db.transaction("device", mode).objectStore("device"));
    r.onsuccess = () => resolve(r.result);
    r.onerror = () => reject(r.error);
  });
}
async function deviceKeypair() {
  const db = await idb();
  const existing = await idbReq(db, "readonly", (s) => s.get("enrollment-device-key"));
  if (existing) return existing;
  const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"]);
  await idbReq(db, "readwrite", (s) => s.put(pair, "enrollment-device-key"));
  return pair;
}
let enrollment = null;
async function enrollBegin() {
  if (!current) throw new SignerError("Unlock your signer", 401);
  const material = await call({ op: "enroll-material" });
  const pair = await deviceKeypair();
  const device_pubkey = toHex(new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey)));
  const authorization = await call({ op: "authorize-device", devicePubHex: device_pubkey });
  enrollment = { signing_pubkey: material.signing_pubkey, relay_pubkey: material.relay_pubkey, device_pubkey, authorization };
  return enrollment;
}
// Sign the coordinator's registration transcript. The coordinator is the wallet origin; the
// transcript binds it, the enrollment above and the coordinator's challenge — nothing else.
async function enrollSign({ challenge }) {
  if (!enrollment) throw new SignerError("Start enrollment first", 400);
  if (typeof challenge !== "string" || !/^[0-9a-f]{64}$/.test(challenge)) throw new SignerError("invalid challenge", 400);
  const e = enrollment;
  const transcript = ["loki-member-registration-v1", wallet, 0, e.signing_pubkey, e.relay_pubkey, "", e.device_pubkey, challenge].join("\n");
  const pair = await deviceKeypair();
  const sig = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, pair.privateKey, new TextEncoder().encode(transcript));
  return { signature: toHex(new Uint8Array(sig)) };
}

// ─── the wallet bridge ───────────────────────────────────────────────────────
const relay = (p) => ({ ...p, frostdUrl: cfg.frostdUrl, nonceWitnesses: cfg.nonceWitnesses });
const ops = {
  has: () => call({ op: "has" }),
  status: () => {
    if (!current) throw new SignerError("Unlock your signer", 401);
    return { ...current, persisted, relay: cfg.frostdUrl, origin: location.origin };
  },
  create,
  unlock,
  lock: async () => { if (worker) await call({ op: "lock" }); current = null; enrollment = null; return null; },
  "enroll-begin": enrollBegin,
  "enroll-sign": enrollSign,
  // A vault backup must also seal to recovery words, so set them up before the first join.
  join: async (p) => {
    if (!await call({ op: "has-recovery" })) await recoverySetup();
    return call({ op: "join", join: relay(p) });
  },
  "payment-review": (p) => call({ op: "payment-review", payment: relay(p) }),
  "payment-approve": (p) => call({ op: "payment-approve", payment: relay(p) }),
  pending: (p) => call({ op: "pending", payment: relay(p) }),
  vaults: () => call({ op: "vaults" }),
  address: (p) => call({ op: "address", payment: p }),
  chain: (p) => call({ op: "chain", payment: { ...p, lightwalletdGrpcWeb: cfg.lightwalletdGrpcWebUrl } }),
  "payment-status": (p) => call({ op: "payment-status", payment: { ...relay(p), lightwalletdGrpcWeb: cfg.lightwalletdGrpcWebUrl } }),
  "recovery-setup": recoverySetup,
  "recovery-status": async () => ({ recovery_identity: await call({ op: "has-recovery" }) }),
  "recovery-export": recoveryExport,
  restore,
  remove,
};
const UNLOCKED = new Set(["join", "payment-review", "payment-approve", "pending", "vaults", "address", "chain", "payment-status", "recovery-setup", "recovery-export", "recovery-status"]);
// Ops that may show a prompt run one at a time; the read-only ones answer alongside them
// (the Worker refuses them with "busy" while a join or payment holds the vault).
const PROMPTING = new Set(["create", "unlock", "join", "payment-approve", "recovery-setup", "recovery-export", "restore", "remove"]);

let queue = Promise.resolve(); // one op (and so one prompt) at a time
addEventListener("message", (e) => {
  if (e.origin !== wallet || e.source !== parent || parent === window) return;
  const { id, op, params } = e.data ?? {};
  if (typeof id !== "number" || !Object.hasOwn(ops, op)) return;
  const run = async () => {
    try {
      if (UNLOCKED.has(op) && !current) throw new SignerError("Unlock your signer", 401);
      parent.postMessage({ id, ok: true, result: await ops[op](params ?? {}) }, wallet);
    } catch (err) {
      parent.postMessage({ id, ok: false, error: err.message || String(err), status: err.status ?? 500 }, wallet);
    }
  };
  if (PROMPTING.has(op)) queue = queue.then(run);
  else run();
});
if (parent !== window) parent.postMessage({ cmd: "ready" }, wallet);
