"use client";

// Member calls go to one of two signer kinds, chosen per tab:
//   - a paired NATIVE member app (loki_member_app): HTTP to its loopback origin with its
//     process capability (X-Loki-Token), exactly the device API it serves; or
//   - the in-browser wasm signer (src/lib/signer.ts) on its own origin.
// A tab paired with a native member routes every member call there; otherwise to the browser
// signer. Only coordinator calls (/api/members, /api/fund) go to this origin.
// Explicit .ts extension so Node's test loader resolves the chained import.
import { signer, ApiError, type CreateSignerOpts, type EnrolledMember, type SignerSession, type UnlockOpts } from "./signer.ts";
export { ApiError };
export type { CustodyMethod, CreateSignerOpts, EnrolledMember, UnlockOpts } from "./signer";
export type Slot = { slot: number; signing_pubkey: string; relay_pubkey: string; advertise_url: string };

/** Register this in-browser signer into the public roster; returns its allocated member/slot. */
export function enroll(coordinatorOrigin?: string): Promise<EnrolledMember> { return signer.enroll(coordinatorOrigin); }

// ─── native member (paired tab) ──────────────────────────────────────────────
type Pairing = { endpoint: string; capability: string };
const PAIRING = "loki_device_session"; // sessionStorage: this tab's native member + capability
function paired(): Pairing | null {
  if (typeof window === "undefined") return null;
  try { const raw = sessionStorage.getItem(PAIRING); return raw ? JSON.parse(raw) as Pairing : null; }
  catch { return null; }
}
/** Which signer this tab drives. */
export function signerKind(): "native" | "browser" { return paired() ? "native" : "browser"; }

async function nativeApi<T>(session: Pairing, path: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = { "X-Loki-Token": session.capability };
  if (body !== undefined) headers["Content-Type"] = "application/json";
  const res = await fetch(`${session.endpoint}/api/${path}`, {
    method: body === undefined ? "GET" : "POST", headers,
    body: body === undefined ? undefined : JSON.stringify(body),
    credentials: "omit", redirect: "error", cache: "no-store",
  });
  const text = await res.text();
  const data = text ? JSON.parse(text) : {};
  if (!res.ok) throw new ApiError(data.error ?? `${path} failed (${res.status})`, res.status);
  return data as T;
}

/** Pair this tab with a native member from the link it printed (`http://127.0.0.1:<port>/#<capability>`).
 *  The member's identity must be the one the public roster lists for its slot. */
export async function pairDevice(link: string): Promise<Slot> {
  const url = new URL(link.trim());
  if (url.protocol !== "http:" || !["127.0.0.1", "[::1]"].includes(url.hostname)
    || !url.port || Number(url.port) < 1024 || url.pathname !== "/" || url.search || url.username || url.password
    || !/^#[A-Za-z0-9_-]{43}$/.test(url.hash)) throw new Error("Paste the local pairing link printed by your member process");
  const session = { endpoint: url.origin, capability: url.hash.slice(1) };
  const member = await nativeApi<Slot>(session, "registration");
  const roster = await listSlots();
  if (!roster.some((m) => m.slot === member.slot && m.signing_pubkey === member.signing_pubkey && m.relay_pubkey === member.relay_pubkey && m.advertise_url === member.advertise_url)) {
    throw new Error("Device identity does not match the public roster; register the device first");
  }
  const status = await nativeApi<{ phase: string }>(session, "status");
  if (status.phase !== "home") throw new Error("Unlock the profile locally on your device, then pair again");
  sessionStorage.setItem(PAIRING, JSON.stringify(session));
  sessionStorage.setItem("loki_me", JSON.stringify({ slot: member.slot }));
  return member;
}

/** A member request: to this tab's paired native member, else into the in-browser signer. */
export async function api<T = unknown>(path: string, body?: unknown): Promise<T> {
  if (!/^[a-z][a-z0-9-]*(\?[^#]*)?$/.test(path)) throw new Error("invalid signer API path");
  const native = paired();
  try {
    return native ? await nativeApi<T>(native, path, body) : await signer.request<T>(path, body);
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
export { hasSignerHint } from "./signer.ts"; // sync first-paint guess; hasSigner() confirms

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
  try { sessionStorage.removeItem("loki_me"); sessionStorage.removeItem(PAIRING); } catch {}
}
export async function logout(): Promise<boolean> {
  // A native member locks its own profile (it restarts locally with a new pairing link).
  try { if (paired()) await api("lock", {}); else await signer.lock(); return true; }
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
export type PendingApproval = { attempt: string; amount_zat: string; recipient: string; proposer: number; replaces?: { attempt: string; cancel: boolean } | null };
export function pendingApprovals(vault: string): Promise<{ pending: PendingApproval[] }> { return api(`pending?vault=${vault}`); }
