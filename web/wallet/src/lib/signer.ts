"use client";

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
}

// ─── real wasm signer (browser Worker) ───────────────────────────────────────
//
// W1F's wasm module runs the FROST core in a Web Worker and seals the device identity to
// OPFS (loki-signer-wasm/signer-worker.js). This client bridges the lifecycle half of
// `SignerModule` to it over postMessage; `request()` stays `SignerPending` (DKG/payment are
// Phase B/C). It activates only when the integrator serves the built pkg + worker and points
// `window.__LOKI_SIGNER_WORKER_URL` at it — so SSR, Node tests and the un-provisioned app all
// keep the in-memory mock below (OPFS cannot run there anyway) with no behaviour change.

function workerUrl(): string | null {
  if (typeof window === "undefined" || typeof Worker === "undefined") return null;
  const u = (window as unknown as { __LOKI_SIGNER_WORKER_URL?: string }).__LOKI_SIGNER_WORKER_URL;
  return typeof u === "string" && u.length > 0 ? u : null;
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
async function postJson<T>(url: string, body: unknown): Promise<T> {
  const res = await fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new ApiError(data.error ?? "coordinator request failed", res.status);
  return data as T;
}

function browserSigner(url: string): SignerModule {
  const worker = new Worker(url, { type: "module" });
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
      const profile = await call<{ id: string; name: string }>({ op: "create", method, name, passphrase });
      current = { profile, se: method === "passphrase" ? "software" : "passkey" };
      return { profile };
    },
    async unlock({ method, passphrase }) {
      if (method === "passphrase" && !passphrase) throw new ApiError("Enter your passphrase", 400);
      const profile = await call<{ id: string; name: string }>({ op: "unlock", method, passphrase });
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
      // Phase B: join-a-vault + DKG. The UI supplies the ceremony params (roster bytes, the
      // coordinator's frostd session + relay peer, the TLS frostd URL); the Worker drives the
      // synchronous DKG core over the frostd transport to an active vault + released address.
      if (path === "dkg") return call<T>({ op: "dkg", dkg: body });
      throw new SignerPending(path); // payment ops stay Phase C
    },
  };
}

// ─── mock implementation (SSR / Node tests / un-provisioned app) ──────────────

const SESSION = "loki_signer_session"; // sessionStorage: the unlocked session
const SEALED = "loki_signer_sealed";   // localStorage: a share exists in this browser

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
// The real Worker-backed signer when provisioned (browser + worker URL), the mock
// otherwise. Chosen per call so SSR→client hydration and test env never bind the wrong one.

let browser: SignerModule | null = null;
function impl(): SignerModule {
  const url = workerUrl();
  if (!url) return mockSigner;
  if (!browser) browser = browserSigner(url);
  return browser;
}

export const signer: SignerModule = {
  hasSigner: () => impl().hasSigner(),
  createSigner: (opts) => impl().createSigner(opts),
  unlock: (opts) => impl().unlock(opts),
  lock: () => impl().lock(),
  enroll: (coordinatorOrigin) => impl().enroll(coordinatorOrigin),
  request<T = unknown>(path: string, body?: unknown): Promise<T> { return impl().request<T>(path, body); },
};
