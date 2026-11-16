"use client";

// Member calls now run in the in-browser wasm signer (src/lib/signer.ts), not
// over HTTP to a local member. Only coordinator calls (/api/members, /api/fund)
// still hit the network.
// Explicit .ts extension so Node's test loader resolves the chained import.
import { signer, ApiError, type CreateSignerOpts, type EnrolledMember, type SignerSession, type UnlockOpts } from "./signer.ts";
export { ApiError };
export type { CustodyMethod, CreateSignerOpts, EnrolledMember, UnlockOpts } from "./signer";
export type Slot = { slot: number; signing_pubkey: string; relay_pubkey: string; advertise_url: string };

/** Register this in-browser signer into the public roster; returns its allocated member/slot. */
export function enroll(coordinatorOrigin?: string): Promise<EnrolledMember> { return signer.enroll(coordinatorOrigin); }

/** A member request, dispatched into the in-browser signer instead of fetched. */
export async function api<T = unknown>(path: string, body?: unknown): Promise<T> {
  if (!/^[a-z][a-z0-9-]*(\?[^#]*)?$/.test(path)) throw new Error("invalid signer API path");
  try {
    return await signer.request<T>(path, body);
  } catch (e) {
    if (e instanceof ApiError && e.status === 401 && typeof window !== "undefined") window.dispatchEvent(new Event("loki:auth-lost"));
    throw e;
  }
}

export async function listSlots(): Promise<Slot[]> {
  const res = await fetch("/api/members", { cache: "no-store" });
  if (!res.ok) throw new Error("could not read public roster");
  return (await res.json()).slots as Slot[];
}

/** True once a share is sealed in this browser → Unlock rather than Create. */
export function hasSigner(): Promise<boolean> { return signer.hasSigner(); }

function rememberMe(s: SignerSession): void {
  try { sessionStorage.setItem("loki_me", JSON.stringify({ slot: s.slot })); } catch {}
}
export async function createSigner(opts: CreateSignerOpts): Promise<SignerSession> {
  const s = await signer.createSigner(opts);
  rememberMe(s);
  return s;
}
export async function unlock(opts: UnlockOpts): Promise<SignerSession> {
  const s = await signer.unlock(opts);
  rememberMe(s);
  return s;
}
export function forgetSession(): void {
  try { sessionStorage.removeItem("loki_me"); } catch {}
}
export async function logout(): Promise<boolean> {
  try { await signer.lock(); return true; }
  catch { return false; }
  finally { forgetSession(); }
}

/** Development faucet accepts only a public regtest address. */
export async function fund(address: string): Promise<void> {
  const res = await fetch("/api/fund", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ address }) });
  if (!res.ok) throw new Error((await res.json()).error ?? "could not request funds");
}
export type RecoveryStatus = { recovery_identity: boolean; recovery_backup: boolean };
export function recoveryStatus(vault: string): Promise<RecoveryStatus> { return api(`recovery-status?vault=${vault}`); }
export function recoverySetup(): Promise<{ words: string }> { return api("recovery-setup", {}); }
export function recoveryRestore(vault: string, words: string): Promise<{ restored: boolean }> { return api("recovery-restore", { vault, words }); }
export type PendingApproval = { attempt: string; amount_zat: string; recipient: string; proposer: number };
export function pendingApprovals(vault: string): Promise<{ pending: PendingApproval[] }> { return api(`pending?vault=${vault}`); }
