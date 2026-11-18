"use client";

// ─────────────────────────────────────────────────────────────────────────────
// The wallet's seam to the in-browser signer.
//
// The signer (the Rust FROST core compiled to wasm, in a Web Worker, its share sealed in
// OPFS) runs on its OWN origin — poc/loki-signer-wasm/serve.mjs — embedded here in an iframe.
// This page never holds the share, never runs the passkey PRF ceremony and never sees the
// passphrase: those happen on the signer-origin page, which also shows the roster code and
// every payment for the member to confirm. This file only exchanges public data with it over
// postMessage. The in-memory mock below exists for SSR and Node tests only; a browser build
// never falls back to it.
// ─────────────────────────────────────────────────────────────────────────────

export class ApiError extends Error {
  status: number;
  constructor(message: string, status: number) { super(message); this.status = status; }
}

/** Thrown for member paths the in-browser signer does not serve. */
export class SignerPending extends ApiError {
  constructor(path: string) { super(`the in-browser signer does not serve "${path}"`, 501); }
}

/** Custody tiers, all backed by the same `SecureElement` trait (definition §2.B). */
export type CustodyMethod = "platform" | "roaming" | "passphrase";
/** The custody secret itself (passphrase or passkey) is entered on the signer origin. */
export interface CreateSignerOpts { name: string; method: CustodyMethod }
export interface UnlockOpts { method: CustodyMethod }
export interface SignerSession { slot?: number; profile: { id: string; name: string }; persisted?: boolean | null }
/** A public-roster member, as the coordinator's `/api/members` returns it. */
export interface EnrolledMember { slot: number; signing_pubkey: string; relay_pubkey: string; advertise_url: string }

/**
 * The signer contract. `request` is the in-process equivalent of the old member HTTP API,
 * dispatched to the signer origin for the paths it serves (status, lock, join, pending, address,
 * payment-review, payment-approve); other paths throw `SignerPending`.
 */
export interface SignerModule {
  /** True once a share is sealed in this browser → Unlock, not Create. */
  hasSigner(): Promise<boolean>;
  /** Generate + seal a new share under the chosen custody backend (entered on the signer origin). */
  createSigner(opts: CreateSignerOpts): Promise<SignerSession>;
  /** Open the sealed share (Touch/Face ID, security key, phone, or passphrase, on the signer origin). */
  unlock(opts: UnlockOpts): Promise<SignerSession>;
  /** Drop the in-memory share; the session ends. */
  lock(): Promise<void>;
  /** Register this signer into this coordinator's public roster (frostd-only, no advertise_url)
   *  and return the allocated member — its `slot` is the DKG slot. */
  enroll(coordinatorOrigin?: string): Promise<EnrolledMember>;
  /** In-process member call — the old per-member HTTP, now dispatched to the signer. */
  request<T = unknown>(path: string, body?: unknown): Promise<T>;
}

// ─── the signer origin (iframe + postMessage) ────────────────────────────────

/** The signer origin, fixed at build (NEXT_PUBLIC_SIGNER_ORIGIN); never overridable from the page.
 *  `next dev` defaults to the local signer server on :3002. A production build without one
 *  fails closed: every signer call rejects. */
function signerOrigin(): string {
  const configured = process.env.NEXT_PUBLIC_SIGNER_ORIGIN;
  if (configured) return new URL(configured).origin;
  if (process.env.NODE_ENV !== "production") return "http://localhost:3002";
  throw new ApiError("This build has no signer origin (NEXT_PUBLIC_SIGNER_ORIGIN), so the signer is unavailable", 503);
}

const SEALED = "loki_signer_sealed"; // localStorage: a share exists in this browser (first-paint hint only)

async function postJson<T>(url: string, body: unknown): Promise<T> {
  const res = await fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new ApiError(data.error ?? "coordinator request failed", res.status);
  return data as T;
}

function browserSigner(origin: string): SignerModule {
  // The signer page shows its own prompts; this frame is revealed (full-window overlay) only
  // while it asks for the member, on its {cmd:"show"} / {cmd:"hide"}.
  const frame = document.createElement("iframe");
  frame.src = `${origin}/`;
  frame.title = "Loki signer";
  frame.allow = `publickey-credentials-create ${origin}; publickey-credentials-get ${origin}`;
  Object.assign(frame.style, { position: "fixed", inset: "0", width: "100%", height: "100%", border: "0", zIndex: "1000", display: "none", colorScheme: "normal" });
  document.body.append(frame);

  const pending = new Map<number, { resolve: (v: unknown) => void; reject: (e: Error) => void }>();
  let seq = 0;
  let ready: () => void;
  const loaded = new Promise<void>((resolve, reject) => {
    ready = resolve;
    setTimeout(() => reject(new ApiError(`The signer at ${origin} did not load`, 503)), 15000);
  });
  loaded.catch(() => {});
  window.addEventListener("message", (e: MessageEvent) => {
    if (e.origin !== origin || e.source !== frame.contentWindow) return;
    const d = e.data ?? {};
    if (d.cmd === "ready") { ready(); return; }
    if (d.cmd === "show") { frame.style.display = "block"; return; }
    if (d.cmd === "hide") { frame.style.display = "none"; return; }
    const p = pending.get(d.id);
    if (!p) return;
    pending.delete(d.id);
    d.ok ? p.resolve(d.result) : p.reject(new ApiError(d.error ?? "signer error", d.status ?? 500));
  });
  async function call<T>(op: string, params?: unknown): Promise<T> {
    await loaded;
    const id = ++seq;
    return new Promise<T>((resolve, reject) => {
      pending.set(id, { resolve: resolve as (v: unknown) => void, reject });
      frame.contentWindow!.postMessage({ id, op, params }, origin);
    });
  }
  const opened = (s: SignerSession) => { try { localStorage.setItem(SEALED, "1"); } catch {} return s; };

  return {
    hasSigner: () => call<boolean>("has"),
    createSigner: async ({ name, method }) => opened(await call<SignerSession>("create", { name, method })),
    unlock: async ({ method }) => opened(await call<SignerSession>("unlock", { method })),
    async lock() { await call("lock"); },
    async enroll(coordinatorOrigin?: string): Promise<EnrolledMember> {
      // The signer binds its registration transcript to this wallet origin, the coordinator.
      if (coordinatorOrigin && coordinatorOrigin !== window.location.origin) {
        throw new ApiError("The signer registers only with this wallet's coordinator", 400);
      }
      const origin = window.location.origin;
      const enrollment = await call<Record<string, string>>("enroll-begin");
      // No advertise_url (frostd-only) and no slot (coordinator allocates).
      const { challenge } = await postJson<{ challenge: string }>(`${origin}/api/members/challenge`, enrollment);
      const { signature } = await call<{ signature: string }>("enroll-sign", { challenge });
      const { member } = await postJson<{ member: EnrolledMember }>(`${origin}/api/members`, { ...enrollment, challenge, signature });
      return member;
    },
    async request<T>(pathAndQuery: string, body?: unknown): Promise<T> {
      const [path, query] = pathAndQuery.split("?");
      const args = { ...Object.fromEntries(new URLSearchParams(query ?? "")), ...(body as object) } as { vault?: string; attempt?: string };
      if (path === "status") {
        const s = await call<{ profile: { id: string; name: string }; se: string; persisted: boolean | null; relay: string }>("status");
        // The signer's own vaults (OPFS). Refused while a join/payment holds the signer; the
        // next status poll fills them in.
        const vaults = await call<unknown[]>("vaults").catch(() => undefined);
        return { phase: "home", network: "testnet", secure_element: s.se, profile: s.profile, persisted: s.persisted, relay: s.relay, vaults } as T;
      }
      if (path === "lock") { await this.lock(); return {} as T; }
      // Join a vault (enroll → roster → agree → session → DKG). The member confirms every member
      // and the roster code on the signer page; the relay is the signer origin's own config.
      if (path === "join") return call<T>("join", body);
      // Payments other members proposed: list them, read one's announced terms, and approve it.
      // Approving opens the signer page, which checks the transaction against those terms and
      // asks the member to confirm with a fresh passkey assertion (or the passphrase).
      const payment = { vaultHex: args.vault, attemptHex: args.attempt };
      if (path === "pending") return { pending: await call("pending", payment) } as T;
      if (path === "payment-review" || path === "payment-approve") return call<T>(path, payment);
      if (path === "address") return { address: await call<string>("address", payment) } as T;
      // Recovery words are shown, typed and checked on the signer page; only the opaque
      // backup ciphertext ({backup} from recovery-export) and public results come back.
      if (path === "recovery-setup" || path === "recovery-export") return call<T>(path, body);
      if (path === "restore") { const r = await call<T>(path, body); try { localStorage.setItem(SEALED, "1"); } catch {} return r; }
      if (path === "remove") { const r = await call<T>(path, body); try { localStorage.removeItem(SEALED); } catch {} return r; }
      throw new SignerPending(path);
    },
  };
}

// ─── mock implementation (SSR / Node tests only) ─────────────────────────────

const SESSION = "loki_signer_session"; // sessionStorage: the unlocked session

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
  async createSigner({ name, method }) {
    try { localStorage.setItem(SEALED, JSON.stringify({ name, method })); } catch {}
    return open(name || "You", method);
  },
  async unlock({ method }) {
    let sealed: { name?: string } = {};
    try { sealed = JSON.parse(localStorage.getItem(SEALED) ?? "null") ?? {}; } catch {}
    return open(sealed.name ?? "You", method);
  },
  async lock() {
    try { sessionStorage.removeItem(SESSION); } catch {}
  },
  async enroll(): Promise<EnrolledMember> { throw new SignerPending("enroll"); },
  async request<T>(path: string): Promise<T> {
    const s = session();
    // Status is the only member call the onboarding lifecycle needs; serve it so a
    // fresh signer reaches Home.
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
// A real browser (a DOM) always gets the signer origin; only SSR and Node tests, which have no
// DOM and no browser storage, get the mock. No probe, no silent fallback: if the signer origin
// is missing or unreachable, signer calls fail.

let implPromise: Promise<SignerModule> | null = null;
function impl(): Promise<SignerModule> {
  implPromise ??= (async () => (typeof document === "undefined" ? mockSigner : browserSigner(signerOrigin())))();
  return implPromise;
}

export const signer: SignerModule = {
  hasSigner: async () => (await impl()).hasSigner(),
  createSigner: async (opts) => (await impl()).createSigner(opts),
  unlock: async (opts) => (await impl()).unlock(opts),
  lock: async () => (await impl()).lock(),
  enroll: async (coordinatorOrigin) => (await impl()).enroll(coordinatorOrigin),
  async request<T = unknown>(path: string, body?: unknown): Promise<T> { return (await impl()).request<T>(path, body); },
};

