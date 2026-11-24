"use client";

import type { Payment, PaymentSession } from "./types";

export class ApiError extends Error {
  status: number;
  constructor(message: string, status: number) { super(message); this.status = status; }
}

export class SignerPending extends ApiError {
  constructor(path: string) { super(`the in-browser signer does not serve "${path}"`, 501); }
}

export type CustodyMethod = "platform" | "roaming" | "passphrase";
export interface CreateSignerOpts { name: string; method: CustodyMethod }
export interface UnlockOpts { method: CustodyMethod }
export interface SignerSession { slot?: number; profile: { id: string; name: string }; persisted?: boolean | null }
export interface EnrolledMember { slot: number; signing_pubkey: string; relay_pubkey: string; advertise_url: string }

export interface SignerModule {
  hasSigner(): Promise<boolean>;
  createSigner(opts: CreateSignerOpts): Promise<SignerSession>;
  /** Open the sealed share (Touch/Face ID, security key, phone, or passphrase, on the signer origin). */
  unlock(opts: UnlockOpts): Promise<SignerSession>;
  lock(): Promise<void>;
  enroll(coordinatorOrigin?: string): Promise<EnrolledMember>;
  request<T = unknown>(path: string, body?: unknown): Promise<T>;
}

export function browserVaultStatus(vaults: { vault: string; active: boolean }[] | undefined, vault: string): { phase: "active" | "creating_keys" } {
  return { phase: vaults?.some((v) => v.vault === vault && v.active) ? "active" : "creating_keys" };
}

export type ChainTx = { txid: string; height: number; received_zat: number; change_zat: number; spent_zat: number };

export function chainPayments(history: ChainTx[]): Payment[] {
  return history.map((t) => {
    const sent = t.spent_zat > 0;
    const amount = sent ? t.spent_zat - t.change_zat - t.received_zat : t.received_zat + t.change_zat;
    return { attempt: t.txid, phase: "confirmed", recipient: "", amount_zat: String(amount), txid: t.txid,
      direction: sent ? "sent" : "received", amount_is_net: sent, mined_height: t.height };
  });
}

export function chainPaymentSession(r: {
  terms: { proposer: number; recipient: string; amount_zat: number; fee_zat: number };
  signers: number[];
  ended?: "cancelled" | "failed" | null;
  closed?: boolean;
  spent: { txid: string; height: number } | null;
  txid?: string | null;
  approved?: boolean;
  slot?: number;
}): PaymentSession {
  const confirmed = r.spent !== null && r.spent.txid === r.txid;
  return {
    phase: confirmed ? "confirmed" : r.spent ? (r.txid ? "replaced" : "spent_unverified") :
      r.ended ?? (r.closed ? "awaiting_verification" : "signing"),
    signatures_received: confirmed,
    txid: confirmed ? r.spent?.txid : null,
    spent_by: confirmed ? null : r.spent?.txid ?? null,
    approvals: r.approved === true && r.slot !== undefined ? [r.slot] : [],
    approval_requested: r.approved === true,
    intent: { proposer: r.terms.proposer, signers: r.signers, recipient: r.terms.recipient, amount_zat: r.terms.amount_zat, fee_zat: r.terms.fee_zat, open_approval: true },
  };
}

function signerOrigin(): string {
  const rendered = document.head.querySelector('meta[name="loki-signer-origin"]')?.getAttribute("content");
  const configured = rendered || process.env.NEXT_PUBLIC_SIGNER_ORIGIN;
  if (configured) return new URL(configured).origin;
  if (process.env.NODE_ENV !== "production") return "http://localhost:3002";
  throw new ApiError("This deploy has no signer origin (LOKI_SIGNER_ORIGIN), so the signer is unavailable", 503);
}

const SEALED = "loki_signer_sealed";
const LONG_CALLS = new Set(["create", "unlock", "join", "verify-address", "payment-approve", "recovery-setup", "recovery-export", "restore", "remove", "chain", "payment-status"]);

async function postJson<T>(url: string, body: unknown): Promise<T> {
  const signal = AbortSignal.timeout(30_000);
  const res = await fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body), signal });
  const data = await res.json().catch(() => ({}));
  signal.throwIfAborted();
  if (!res.ok) throw new ApiError(data.error ?? "coordinator request failed", res.status);
  return data as T;
}

function browserSigner(origin: string): SignerModule {
  const frame = document.createElement("iframe");
  frame.src = `${origin}/`;
  frame.title = "Loki signer";
  frame.allow = `publickey-credentials-create ${origin}; publickey-credentials-get ${origin}`;
  Object.assign(frame.style, { position: "fixed", inset: "0", width: "100%", height: "100%", border: "0", zIndex: "1000", display: "none", colorScheme: "normal" });

  const pending = new Map<number, { resolve: (v: unknown) => void; reject: (e: Error) => void; timer: ReturnType<typeof setTimeout> }>();
  let seq = 0;
  let failure: ApiError | undefined;
  const { promise: loaded, resolve: ready, reject: notReady } = Promise.withResolvers<void>();
  const startup = setTimeout(() => fail(new ApiError(`The signer at ${origin} did not load. Try again.`, 503)), 15_000);
  loaded.catch(() => {});
  function fail(error: ApiError) {
    if (failure) return;
    failure = error;
    clearTimeout(startup);
    notReady(error);
    for (const p of pending.values()) { clearTimeout(p.timer); p.reject(error); }
    pending.clear();
    window.removeEventListener("message", receive);
    frame.remove();
    browser = undefined;
  }
  function receive(e: MessageEvent) {
    if (e.origin !== origin || e.source !== frame.contentWindow) return;
    const d = e.data ?? {};
    if (d.cmd === "ready") { clearTimeout(startup); ready(); return; }
    if (d.cmd === "failed") { fail(new ApiError(d.error ?? "The browser signer stopped. Try again.", 503)); return; }
    if (d.cmd === "show") { frame.style.display = "block"; return; }
    if (d.cmd === "hide") { frame.style.display = "none"; return; }
    const p = pending.get(d.id);
    if (!p) return;
    pending.delete(d.id);
    clearTimeout(p.timer);
    d.ok ? p.resolve(d.result) : p.reject(new ApiError(d.error ?? "signer error", d.status ?? 500));
  }
  window.addEventListener("message", receive);
  document.body.append(frame);
  async function call<T>(op: string, params?: unknown): Promise<T> {
    await loaded;
    if (failure) throw failure;
    const id = ++seq;
    return new Promise<T>((resolve, reject) => {
      const timer = setTimeout(() => fail(new ApiError(`The browser signer did not finish ${op}. Unlock it and try again.`, 504)),
        LONG_CALLS.has(op) ? 15 * 60_000 : 60_000);
      pending.set(id, { resolve: resolve as (v: unknown) => void, reject, timer });
      try { frame.contentWindow!.postMessage({ id, op, params }, origin); }
      catch { fail(new ApiError("Could not reach the browser signer. Try again.", 503)); }
    });
  }
  const opened = (s: SignerSession) => { try { localStorage.setItem(SEALED, "1"); } catch {} return s; };

  return {
    hasSigner: async () => checkShare(await call<boolean>("has")),
    createSigner: async ({ name, method }) => opened(await call<SignerSession>("create", { name, method })),
    unlock: async ({ method }) => opened(await call<SignerSession>("unlock", { method })),
    async lock() { await call("lock"); },
    async enroll(coordinatorOrigin?: string): Promise<EnrolledMember> {
      if (coordinatorOrigin && coordinatorOrigin !== window.location.origin) {
        throw new ApiError("The signer registers only with this wallet's coordinator", 400);
      }
      const origin = window.location.origin;
      const enrollment = await call<Record<string, string>>("enroll-begin");
      const reply = await postJson<{ challenge: string; replacement_generation?: number; relay_challenge_pubkey: string }>(`${origin}/api/members/challenge`, enrollment);
      const proof = await call<{ signature: string; replacement_authorization?: string; relay_proof: string }>("enroll-sign", reply);
      const { member } = await postJson<{ member: EnrolledMember }>(`${origin}/api/members`, { ...enrollment, challenge: reply.challenge, ...proof });
      return member;
    },
    async request<T>(pathAndQuery: string, body?: unknown): Promise<T> {
      const [path, query] = pathAndQuery.split("?");
      const args = { ...Object.fromEntries(new URLSearchParams(query ?? "")), ...(body as object) } as { vault?: string; attempt?: string; proposer?: string | number };
      if (path === "status") {
        const s = await call<{ profile: { id: string; name: string }; se: string; persisted: boolean | null; relay: string; network: "testnet" | "regtest" }>("status");
        const vaults = await call<{ vault: string; active: boolean }[]>("vaults").catch(() => undefined);
        if (failure) throw failure;
        if (args.vault) return browserVaultStatus(vaults, args.vault) as T;
        return { phase: "home", network: s.network, secure_element: s.se, profile: s.profile, persisted: s.persisted, relay: s.relay, vaults } as T;
      }
      if (path === "lock") { await this.lock(); return {} as T; }
      if (path === "join") return call<T>("join", body);
      const { proposer } = args;
      const payment = { vaultHex: args.vault, attemptHex: args.attempt,
        proposer: typeof proposer === "string" && /^[1-9]\d*$/.test(proposer) ? Number(proposer) : proposer };
      if (path === "pending") return { pending: await call("pending", payment) } as T;
      if (path === "payment-review" || path === "payment-approve") return call<T>(path, payment);
      if (path === "address") return { address: await call<string>("address", payment) } as T;
      if (path === "verify-address") return call<T>(path, payment);
      if (path === "balance" || path === "payments") {
        const scan = await call<{ balance_zat: string; history: ChainTx[]; chain_trust: "provider_reported" }>("chain", payment);
        return (path === "balance"
          ? { balance_zat: Number(scan.balance_zat), chain_trust: scan.chain_trust }
          : { payments: chainPayments(scan.history), chain_trust: scan.chain_trust }) as T;
      }
      if (path === "payment-status") {
        const status = await call<Parameters<typeof chainPaymentSession>[0] & { chain_trust: "provider_reported" }>("payment-status", payment);
        return { ...chainPaymentSession(status), chain_trust: status.chain_trust } as T;
      }
      if (path === "recovery-setup" || path === "recovery-export" || path === "recovery-status") return call<T>(path, body);
      if (path === "restore") { const r = await call<T>(path, body); try { localStorage.setItem(SEALED, "1"); } catch {} return r; }
      if (path === "manage-custody") {
        const removed = await call<boolean>(path);
        if (removed) { try { localStorage.removeItem(SEALED); } catch {} }
        return removed as T;
      }
      throw new SignerPending(path);
    },
  };
}

const SESSION = "loki_signer_session";

export function hasSignerHint(): boolean { try { return localStorage.getItem(SEALED) !== null; } catch { return false; } }

export function checkShare(has: boolean): boolean {
  if (!has && hasSignerHint()) {
    throw new ApiError("Your signer's share is missing from this browser: its storage was cleared. Restore it from your 24 recovery words and a vault's recovery backup file.", 404);
  }
  return has;
}

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
    if (path === "status") {
      if (!s) throw new ApiError("Unlock your signer", 401);
      return { phase: "home", network: "testnet", secure_element: s.se, profile: s.profile, vaults: [] } as T;
    }
    if (path === "lock") { await this.lock(); return {} as T; }
    if (!s) throw new ApiError("Unlock your signer", 401);
    throw new SignerPending(path);
  },
};

let browser: SignerModule | undefined;
function impl(): SignerModule {
  return typeof document === "undefined" ? mockSigner : (browser ??= browserSigner(signerOrigin()));
}

export const signer: SignerModule = {
  hasSigner: async () => impl().hasSigner(),
  createSigner: async (opts) => impl().createSigner(opts),
  unlock: async (opts) => impl().unlock(opts),
  lock: async () => impl().lock(),
  enroll: async (coordinatorOrigin) => impl().enroll(coordinatorOrigin),
  async request<T = unknown>(path: string, body?: unknown): Promise<T> { return impl().request<T>(path, body); },
};
