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
  /** In-process member call — the old per-member HTTP, now dispatched into wasm. */
  request<T = unknown>(path: string, body?: unknown): Promise<T>;
}

// ─── mock implementation ─────────────────────────────────────────────────────

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

export const signer: SignerModule = {
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
