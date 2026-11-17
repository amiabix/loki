"use client";

import { createWebAuthnCredential, getPrfSecret } from "./webauthn";

// ─────────────────────────────────────────────────────────────────────────────
// MOCK WASM signer — the seam for Agent W1's wasm-bindgen output.
//
// The milestone removes the local member process and the 127.0.0.1 pairing link:
// the signer runs IN this browser (the Rust FROST core compiled to wasm32 by W1,
// the share sealed under a passkey/passphrase by W2). The UI talks to it through
// the `SignerModule` interface below instead of HTTP to a local member.
//
// Until W1 ships the real module, this file is an in-memory MOCK so the
// onboarding UX is testable now and swaps cleanly: replace `signer` at the
// bottom with the wasm-bindgen module (it must satisfy `SignerModule`). This
// mock holds NO keys — it services only the onboarding lifecycle; every vault /
// DKG / payment path throws `SignerPending` until the real wasm core lands.
// ─────────────────────────────────────────────────────────────────────────────

export class ApiError extends Error {
  status: number;
  constructor(message: string, status: number) { super(message); this.status = status; }
}

/** Thrown by the mock for member paths the real wasm core (W1) will service. */
export class SignerPending extends ApiError {
  constructor(path: string) { super(`signer core not loaded: "${path}" needs the wasm signer (W1)`, 501); }
}

/** Custody tiers, all backed by the same `SecureElement` trait (definition §2.B). */
export type CustodyMethod = "platform" | "roaming" | "passphrase";
export interface CreateSignerOpts { name: string; method: CustodyMethod; passphrase?: string }
export interface UnlockOpts { method: CustodyMethod; passphrase?: string }
export interface SignerSession { slot?: number; profile: { id: string; name: string } }
/** A public-roster member, as the coordinator's `/api/members` returns it. */
export interface EnrolledMember { slot: number; signing_pubkey: string; relay_pubkey: string; advertise_url: string }

/** Discover + sign a payment the proposer published (this signer is a NON-proposer approver). */
export interface ApprovePaymentOpts { creatorBaseUrl: string; vault: string; attempt: string }
/** `/api/payment-session` on the proposer's host (poc/src/host/payment.rs::session). */
interface PaymentSession {
  session_id: string;
  control_session_id: string;
  control_hash: string;
  intent: unknown;
  intent_hash: string;
  attempt: string;
  signers: number[];
  proposer: number;
  proposer_frostd_pubkey: string;
  coordinator_frostd_pubkey: string;
  members: { id: number; signing: string; encryption: string }[];
  threshold: number;
  network: string;
  birth_height: number | null;
}

/**
 * The contract W1's wasm module must satisfy. `request` is the in-process
 * equivalent of the old member HTTP API: W1 dispatches each (path, body) into
 * the Rust core. The named vault operations W1's doc lists map onto paths:
 *   create     → request("create", {name,members,threshold})
 *   join       → request("join", {invite})
 *   DKG rounds → request("verify" | "agree" | "backup" | "finalize-backup" | "verify-final-backup", …)
 *   reviewPayment → request("payment-review", {attempt})  → WYSIWYS check
 *   approve       → request("payment-approve", {vault,review_token})
 *   status / balance / address / payments / pending / recovery-* likewise.
 */
export interface SignerModule {
  /** True once a share is sealed in this browser (IndexedDB) → Unlock, not Create. */
  hasSigner(): Promise<boolean>;
  /** Generate + seal a new share under the chosen custody backend. */
  createSigner(opts: CreateSignerOpts): Promise<SignerSession>;
  /** Open the sealed share (Touch/Face ID, security key, phone, or passphrase). */
  unlock(opts: UnlockOpts): Promise<SignerSession>;
  /** Drop the in-memory share; the session ends. */
  lock(): Promise<void>;
  /** Register this signer into the coordinator's public roster (frostd-only, no advertise_url)
   *  and return the allocated member — its `slot` is the DKG slot. Default origin: same-origin. */
  enroll(coordinatorOrigin?: string): Promise<EnrolledMember>;
  /** In-process member call — the old per-member HTTP, now dispatched into wasm. */
  request<T = unknown>(path: string, body?: unknown): Promise<T>;
  /** Approve a published payment on the proposer's host. `signed` is true when this member was
   *  among the first approvers and released its share; otherwise others signed it. */
  approvePayment(opts: ApprovePaymentOpts): Promise<{ approved: boolean; signed: boolean; review?: unknown }>;
}

// ─── real wasm signer (browser Worker) ───────────────────────────────────────
//
// W1F's wasm module runs the FROST core in a Web Worker and seals the device identity to
// OPFS (loki-signer-wasm/signer-worker.js). This client bridges the lifecycle half of
// `SignerModule` to it over postMessage, and routes DKG/join/payment through it. The app
// serves the built worker + pkg under `/signer/` (scripts/copy-signer.mjs), so `browserSigner`
// is the default in the browser; SSR, Node tests and an un-provisioned build (no assets copied)
// fall back to the in-memory mock below — OPFS cannot run there anyway.

export interface SignerConfig { workerUrl: string; transportUrl: string; frostdUrl: string }

/** Served-asset + live-frostd config, overridable at build (NEXT_PUBLIC_*) or runtime (window).
 *  null when there is no Worker (SSR / Node tests) — the caller then uses the mock. */
function signerConfig(): SignerConfig | null {
  if (typeof window === "undefined" || typeof Worker === "undefined") return null;
  const w = window as unknown as { __LOKI_SIGNER_WORKER_URL?: string; __LOKI_FROSTD_URL?: string };
  return {
    workerUrl: w.__LOKI_SIGNER_WORKER_URL || process.env.NEXT_PUBLIC_SIGNER_WORKER_URL || "/signer/signer-worker.js",
    transportUrl: process.env.NEXT_PUBLIC_SIGNER_TRANSPORT_URL || "/signer/wasm-transport/pkg/loki_wasm_transport.js",
    frostdUrl: w.__LOKI_FROSTD_URL || process.env.NEXT_PUBLIC_FROSTD_URL || "",
  };
}

// ─── browser enrollment: device key + signed registration ────────────────────
//
// Enrollment mirrors the native self-registration (poc/src/host/registration.rs): the member
// identity (held unlocked in the Worker) authorizes a device-login key, which then signs the
// coordinator's registration transcript. In the browser the device key is a non-extractable
// WebCrypto P-256 keypair persisted in IndexedDB — the private key never leaves the device,
// and re-enrolling the same identity reuses the same device key (the coordinator pins one
// device to one identity). The member advertises no origin: it is reachable only over frostd.

const DEVICE_DB = "loki_signer";
const DEVICE_STORE = "device";
const DEVICE_KEY = "enrollment-device-key";

function idb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DEVICE_DB, 1);
    req.onupgradeneeded = () => req.result.createObjectStore(DEVICE_STORE);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}
function idbReq<T>(store: IDBObjectStore, op: "get" | "put", ...args: unknown[]): Promise<T> {
  return new Promise((resolve, reject) => {
    const r = (store[op] as (...a: unknown[]) => IDBRequest).apply(store, args);
    r.onsuccess = () => resolve(r.result as T);
    r.onerror = () => reject(r.error);
  });
}
/** The persistent device-login keypair for this browser; generated once, never extractable. */
async function deviceKeypair(): Promise<CryptoKeyPair> {
  const db = await idb();
  const existing = await idbReq<CryptoKeyPair | undefined>(
    db.transaction(DEVICE_STORE, "readonly").objectStore(DEVICE_STORE), "get", DEVICE_KEY);
  if (existing) return existing;
  const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"]);
  await idbReq(db.transaction(DEVICE_STORE, "readwrite").objectStore(DEVICE_STORE), "put", pair, DEVICE_KEY);
  return pair;
}
function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}
function fromHex(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}
const PASSKEY_CRED = "loki_passkey_cred"; // localStorage: the passkey credential id (hex) for unlock
async function postJson<T>(url: string, body: unknown): Promise<T> {
  const res = await fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new ApiError(data.error ?? "coordinator request failed", res.status);
  return data as T;
}

function browserSigner(cfg: SignerConfig): SignerModule {
  const worker = new Worker(cfg.workerUrl, { type: "module" });
  const pending = new Map<number, { resolve: (v: unknown) => void; reject: (e: Error) => void }>();
  let seq = 0;
  const loaded = new Promise<void>((resolve) => {
    const onload = (e: MessageEvent) => {
      if (e.data?.cmd === "loaded") { worker.removeEventListener("message", onload); resolve(); }
    };
    worker.addEventListener("message", onload);
  });
  worker.addEventListener("message", (e: MessageEvent) => {
    const { id, ok, result, error } = e.data ?? {};
    const p = pending.get(id);
    if (!p) return;
    pending.delete(id);
    ok ? p.resolve(result) : p.reject(new ApiError(error ?? "signer error", 500));
  });
  async function call<T>(msg: Record<string, unknown>): Promise<T> {
    await loaded;
    const id = ++seq;
    return new Promise<T>((resolve, reject) => {
      pending.set(id, { resolve: resolve as (v: unknown) => void, reject });
      worker.postMessage({ id, ...msg });
    });
  }
  // The onboarding UX needs `status` to reach Home; the worker holds the identity, so mirror
  // the current profile/method here to answer status without a round-trip.
  let current: { profile: { id: string; name: string }; se: string } | null = null;
  return {
    hasSigner: () => call<boolean>({ op: "has" }),
    async createSigner({ name, method, passphrase }) {
      if (method === "passphrase" && !passphrase) throw new ApiError("Choose a passphrase to protect your share", 400);
      let prfSecret: Uint8Array | undefined;
      if (method !== "passphrase") {
        const { credentialId, prfSupported } = await createWebAuthnCredential(name || "You", method === "platform" ? "platform" : "cross-platform");
        if (!prfSupported) throw new ApiError("This device's authenticator has no PRF support — use a passphrase instead", 400);
        prfSecret = await getPrfSecret(credentialId);
        try { localStorage.setItem(PASSKEY_CRED, toHex(credentialId)); } catch {}
      }
      const profile = await call<{ id: string; name: string }>({ op: "create", method, name, passphrase, prfSecret });
      current = { profile, se: method === "passphrase" ? "software" : "passkey" };
      try { localStorage.setItem(SEALED, "1"); } catch {} // sync hint so Login paints Unlock without a flicker
      return { profile };
    },
    async unlock({ method, passphrase }) {
      if (method === "passphrase" && !passphrase) throw new ApiError("Enter your passphrase", 400);
      let prfSecret: Uint8Array | undefined;
      if (method !== "passphrase") {
        let credHex: string | null = null;
        try { credHex = localStorage.getItem(PASSKEY_CRED); } catch {}
        if (!credHex) throw new ApiError("No passkey registered on this device — create your signer first", 400);
        prfSecret = await getPrfSecret(fromHex(credHex));
      }
      const profile = await call<{ id: string; name: string }>({ op: "unlock", method, passphrase, prfSecret });
      current = { profile, se: method === "passphrase" ? "software" : "passkey" };
      return { profile };
    },
    async lock() { await call({ op: "lock" }); current = null; },
    async enroll(coordinatorOrigin?: string): Promise<EnrolledMember> {
      if (!current) throw new ApiError("Unlock your signer", 401);
      const origin = coordinatorOrigin ?? window.location.origin;
      const material = await call<{ signing_pubkey: string; relay_pubkey: string }>({ op: "enroll-material" });
      const pair = await deviceKeypair();
      const device_pubkey = toHex(new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey)));
      const authorization = await call<string>({ op: "authorize-device", devicePubHex: device_pubkey });
      const enrollment = { signing_pubkey: material.signing_pubkey, relay_pubkey: material.relay_pubkey, device_pubkey, authorization };
      // No advertise_url (frostd-only) and no slot (coordinator allocates); the transcript binds "".
      const { challenge } = await postJson<{ challenge: string }>(`${origin}/api/members/challenge`, enrollment);
      const transcript = ["loki-member-registration-v1", origin, 0, enrollment.signing_pubkey, enrollment.relay_pubkey, "", device_pubkey, challenge].join("\n");
      const signature = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, pair.privateKey, new TextEncoder().encode(transcript)));
      const { member } = await postJson<{ member: EnrolledMember }>(`${origin}/api/members`, { ...enrollment, challenge, signature: toHex(signature) });
      return member;
    },
    async request<T>(path: string, body?: unknown): Promise<T> {
      if (path === "status") {
        if (!current) throw new ApiError("Unlock your signer", 401);
        return { phase: "home", network: "testnet", secure_element: current.se, profile: current.profile, vaults: [] } as T;
      }
      if (path === "lock") { await this.lock(); return {} as T; }
      if (!current) throw new ApiError("Unlock your signer", 401);
      // The ceremony/payment ops reach frostd: fold in the served transport module + the
      // deployment's TLS frostd URL (config, not discovered); a caller-supplied value still wins.
      const relay = (b: unknown) => ({ frostdUrl: cfg.frostdUrl, transportUrl: cfg.transportUrl, ...(b as object) });
      // Phase B: join-a-vault + DKG. The UI supplies the ceremony params (roster bytes, the
      // coordinator's frostd session + relay peer); the Worker drives the synchronous DKG core
      // over the frostd transport to an active vault + released address.
      if (path === "dkg") return call<T>({ op: "dkg", dkg: relay(body) });
      // Phase B join: decode a creator invite and run the joiner dance (enroll → poll roster →
      // agree → poll session) against the creator's member app, then drive the DKG. The UI
      // supplies the invite (and, on testnet, the creator's birthHeight) so the rebuilt setup
      // document matches the creator's.
      if (path === "join") return call<T>({ op: "join", join: relay(body) });
      // Phase C: review + approve a payment (NON-proposer signer). The UI supplies the vault
      // reopen params (vaultHex/slot/label/network/rosterHex), the frostd session + relay
      // peers, the proposer identity, and the attempt; the Worker drives the synchronous
      // signer core over the frostd transport. WYSIWYS is enforced inside the core (signApprove
      // refuses unless the signing package binds the recomputed sighash).
      if (path === "payment-review") return call<T>({ op: "payment-review", payment: relay(body) });
      if (path === "payment-approve") return call<T>({ op: "payment-approve", payment: relay(body) });
      throw new SignerPending(path); // other member paths stay unbuilt
    },
    async approvePayment({ creatorBaseUrl, vault, attempt }) {
      if (!current) throw new ApiError("Unlock your signer", 401);
      const base = creatorBaseUrl.replace(/\/+$/, "");
      const sessionUrl = `${base}/api/payment-session`;
      const s = await postJson<PaymentSession>(sessionUrl, { vault, attempt });
      // Find THIS member's slot by matching its roster encryption (relay) key — the frostd
      // login pubkey differs, so match the roster field, not the login identity.
      const material = await call<{ relay_pubkey: string }>({ op: "enroll-material" });
      const me = s.members.find((m) => m.encryption === material.relay_pubkey);
      if (!me) throw new ApiError("this signer is not a member of the payment's vault", 403);
      // Open request: empty `signers` until the first approvals fix the group.
      if (s.signers.length > 0 && !s.signers.includes(me.id)) {
        throw new ApiError("enough members already approved this payment", 409);
      }
      const proposer = s.members.find((m) => m.id === s.proposer);
      if (!proposer) throw new ApiError("payment session is missing the proposer", 502);
      // Rebuild the DKG setup document BYTE-IDENTICAL (joinCeremony: sorted by slot, same keys).
      const members = s.members
        .slice()
        .sort((a, b) => a.id - b.id)
        .map((m) => ({ id: m.id, signing: m.signing, encryption: m.encryption }));
      const doc: Record<string, unknown> = { vault, threshold: s.threshold, setup_version: 2, network: s.network, members };
      if (s.network === "testnet") doc.birth_height = Number(s.birth_height);
      const rosterHex = toHex(new TextEncoder().encode(JSON.stringify(doc)));
      const body = {
        vaultHex: vault,
        slot: me.id,
        label: "vault",
        network: s.network,
        rosterHex,
        sessionId: s.session_id,
        sessionUrl,
        attemptHex: s.attempt,
        signers: s.signers,
        proposerSigning: proposer.signing,
        proposerEnc: s.proposer_frostd_pubkey,
        proposerId: s.proposer,
        coordinatorPeer: s.coordinator_frostd_pubkey,
        controlSessionId: s.control_session_id,
        controlHash: s.control_hash,
        intent: s.intent,
        intentHash: s.intent_hash,
        frostdUrl: cfg.frostdUrl,
        transportUrl: cfg.transportUrl,
      };
      return call({ op: "payment-approve", payment: body });
    },
  };
}

// ─── mock implementation (SSR / Node tests / un-provisioned app) ──────────────

const SESSION = "loki_signer_session"; // sessionStorage: the unlocked session
const SEALED = "loki_signer_sealed";   // localStorage: a share exists in this browser

/** Synchronous best-guess "a share is sealed here" for the first paint; hasSigner() confirms. */
export function hasSignerHint(): boolean { try { return localStorage.getItem(SEALED) !== null; } catch { return false; } }

function session(): (SignerSession & { se: string }) | null {
  if (typeof window === "undefined") return null;
  try { const raw = sessionStorage.getItem(SESSION); return raw ? JSON.parse(raw) : null; }
  catch { return null; }
}
function open(name: string, method: CustodyMethod): SignerSession {
  const se = method === "passphrase" ? "software" : "passkey";
  const s = { profile: { id: crypto.randomUUID(), name }, se };
  try { sessionStorage.setItem(SESSION, JSON.stringify(s)); } catch {}
  return { profile: s.profile };
}

const mockSigner: SignerModule = {
  async hasSigner() {
    try { return typeof window !== "undefined" && localStorage.getItem(SEALED) !== null; }
    catch { return false; }
  },
  async createSigner({ name, method, passphrase }) {
    if (method === "passphrase" && !passphrase) throw new ApiError("Choose a passphrase to protect your share", 400);
    try { localStorage.setItem(SEALED, JSON.stringify({ name, method })); } catch {}
    return open(name || "You", method);
  },
  async unlock({ method, passphrase }) {
    if (method === "passphrase" && !passphrase) throw new ApiError("Enter your passphrase", 400);
    let sealed: { name?: string } = {};
    try { sealed = JSON.parse(localStorage.getItem(SEALED) ?? "null") ?? {}; } catch {}
    return open(sealed.name ?? "You", method);
  },
  async lock() {
    try { sessionStorage.removeItem(SESSION); } catch {}
  },
  // Enrollment needs the unlocked identity + a device key the wasm core authorizes (W1).
  async enroll(): Promise<EnrolledMember> { throw new SignerPending("enroll"); },
  async approvePayment(): Promise<{ approved: boolean; signed: boolean; review?: unknown }> { throw new SignerPending("payment-approve"); },
  async request<T>(path: string): Promise<T> {
    const s = session();
    // Status is the only member call the onboarding lifecycle needs; serve it so a
    // fresh signer reaches Home. Everything else is the wasm core's job (W1).
    if (path === "status") {
      if (!s) throw new ApiError("Unlock your signer", 401);
      return { phase: "home", network: "testnet", secure_element: s.se, profile: s.profile, vaults: [] } as T;
    }
    if (path === "lock") { await this.lock(); return {} as T; }
    if (!s) throw new ApiError("Unlock your signer", 401);
    throw new SignerPending(path);
  },
};

// ─── dispatcher ──────────────────────────────────────────────────────────────
// The real Worker-backed signer when the app serves the signer assets, the mock otherwise
// (SSR / Node tests, or a build where scripts/copy-signer.mjs found nothing to copy). Resolved
// once: a HEAD probe of the served worker confirms the assets are present before binding the
// Worker, so a missing build degrades cleanly to the mock instead of hanging on a 404.

let implPromise: Promise<SignerModule> | null = null;
function impl(): Promise<SignerModule> {
  if (implPromise) return implPromise;
  implPromise = (async () => {
    const cfg = signerConfig();
    if (!cfg) return mockSigner;
    // A missing build 404s fast → mock. But the probe must never hang the app: on a slow
    // network the memoized promise would stall forever, so time it out and, since a timeout
    // means "served but slow" (not "absent"), bind the real signer anyway. Only a fast,
    // definitive non-ok degrades to the mock.
    const ctrl = new AbortController();
    let timedOut = false;
    const timer = setTimeout(() => { timedOut = true; ctrl.abort(); }, 2500);
    try {
      const res = await fetch(cfg.workerUrl, { method: "HEAD", signal: ctrl.signal });
      if (res.ok) return browserSigner(cfg);
    } catch {
      if (timedOut) return browserSigner(cfg);
    } finally { clearTimeout(timer); }
    return mockSigner;
  })();
  return implPromise;
}

export const signer: SignerModule = {
  hasSigner: async () => (await impl()).hasSigner(),
  createSigner: async (opts) => (await impl()).createSigner(opts),
  unlock: async (opts) => (await impl()).unlock(opts),
  lock: async () => (await impl()).lock(),
  enroll: async (coordinatorOrigin) => (await impl()).enroll(coordinatorOrigin),
  async request<T = unknown>(path: string, body?: unknown): Promise<T> { return (await impl()).request<T>(path, body); },
  approvePayment: async (opts) => (await impl()).approvePayment(opts),
};

// Callable without the (unwired) vault UI: `await window.lokiApprovePayment({ creatorBaseUrl, vault, attempt })`.
if (typeof window !== "undefined") {
  (window as unknown as { lokiApprovePayment?: typeof signer.approvePayment }).lokiApprovePayment = signer.approvePayment;
}
