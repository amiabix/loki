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

/** A pairing link LokiSigner opens; the coordinator reserves its slot until `expires`, in this
 *  browser's clock (ms). */
export type PairingLink = { slot: number; url: string; expires: number };
/** The asked-for slot is registered or reserved, possibly by another member: the next link must
 *  let the coordinator pick a new slot. */
export class PairingSlotTaken extends Error {}
// The coordinator builds `loki://pair?` + URLSearchParams; anything else is never a link target.
const PAIRING_LINK = /^loki:\/\/pair\?[A-Za-z0-9%*._+=&-]+$/;
const PAIRING_TTL_MS = 120_000;
const PAIRING_REFUSALS: [string, (slot?: number) => string][] = [
  ["too many pending registrations", () => "The coordinator has too many pairing links waiting. Try again in two minutes."],
  ["registration is busy", () => "The coordinator is busy registering another member. Try again in a moment."],
  ["expected an HTTPS origin", () => "This coordinator issues pairing links only over HTTPS. Open the wallet at its HTTPS address and try again."],
];

/** Ask the coordinator for a native pairing link: the next free slot, or `slot` again after
 *  its link expired. Each request reserves a slot, so callers never reissue on their own. */
export async function requestPairingLink(slot?: number): Promise<PairingLink> {
  const res = await fetch("/api/members/pairing", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify(slot === undefined ? {} : { slot }), cache: "no-store",
  });
  const now = Date.now();
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    // Only our own sentences reach the page, never the coordinator's text.
    const error = typeof data.error === "string" ? data.error : "";
    if (error.startsWith("slot already registered or reserved")) {
      throw new PairingSlotTaken(`${slot === undefined ? "That slot" : `Slot ${slot}`} was taken, possibly by another member. If LokiSigner shows “Signer paired and running”, paste its private link in step 2. Otherwise get a new link; it will use another slot.`);
    }
    const known = PAIRING_REFUSALS.find(([prefix]) => error.startsWith(prefix));
    throw new Error(known ? known[1](slot) : `The coordinator refused a pairing link (HTTP ${res.status}). Try again, or ask whoever runs it.`);
  }
  if (!Number.isSafeInteger(data.slot) || data.slot < 1 || !Number.isSafeInteger(data.expires)
    || typeof data.url !== "string" || !PAIRING_LINK.test(data.url)) {
    throw new Error("The coordinator returned a pairing link LokiSigner would not accept. Try again, or ask whoever runs it.");
  }
  // LokiSigner shows the origin and slot from the link itself; they must be what this page shows.
  const query = new URLSearchParams(data.url.slice("loki://pair?".length));
  const keys = [...query.keys()].sort();
  if ((slot !== undefined && data.slot !== slot) || keys.join() !== "challenge,origin,slot"
    || query.get("origin") !== window.location.origin || query.get("slot") !== String(data.slot)
    || !/^[0-9a-f]{64}$/.test(query.get("challenge")!)) {
    throw new Error("The coordinator's pairing link does not match this page, so it is not shown. Ask whoever runs the coordinator.");
  }
  // `expires` is on the coordinator's clock: keep only the time left, measured from its Date header.
  const served = Date.parse(res.headers.get("date") ?? "");
  const left = Number.isNaN(served) ? PAIRING_TTL_MS : data.expires - served;
  return { slot: data.slot, url: data.url, expires: now + Math.min(left, PAIRING_TTL_MS) };
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

// The in-browser signer's recovery. The words are shown, re-typed and entered only on the
// signer page; the wallet sees public results and the opaque backup ciphertext.
function browserOnly(): void {
  if (paired()) throw new ApiError("This tab uses a native member; recover it in the member app", 400);
}
/** Show the 24 words once on the signer page and confirm three of them. */
export async function setupBrowserRecovery(): Promise<{ recovery: boolean }> { browserOnly(); return signer.request("recovery-setup", {}); }
/** Download this vault's recovery backup on the signer page (ciphertext only the words open). */
export async function exportRecoveryBackup(vault: string): Promise<{ backup: string }> { browserOnly(); return signer.request("recovery-export", { vault }); }
/** Fresh browser: restore a vault member from its words (typed on the signer page) and its backup:
 *  the file the member picks there, or `backup` (hex ciphertext) + `vault` the wallet already holds. */
export async function restoreSigner(opts: CreateSignerOpts & { vault?: string; backup?: string }): Promise<SignerSession> { browserOnly(); return signer.request("restore", opts); }
/** Delete this browser's signer after the member confirms the backups are exported. */
export async function removeBrowserSigner(): Promise<void> {
  browserOnly();
  await signer.request("remove", {});
  forgetSession();
}
export type PendingApproval = { attempt: string; amount_zat: string; recipient: string; proposer: number; replaces?: { attempt: string; cancel: boolean } | null };
export function pendingApprovals(vault: string): Promise<{ pending: PendingApproval[] }> { return api(`pending?vault=${vault}`); }
