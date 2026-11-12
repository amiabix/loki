"use client";

/** A paired tab calls its member device directly. No member capability goes to Next. */
export class ApiError extends Error {
  status: number;
  constructor(message: string, status: number) { super(message); this.status = status; }
}
export type Slot = { slot: number; signing_pubkey: string; relay_pubkey: string; advertise_url: string };
type Pairing = { endpoint: string; capability: string };
const PAIRING = "loki_device_session";
function paired(): Pairing | null {
  if (typeof window === "undefined") return null;
  const raw = sessionStorage.getItem(PAIRING);
  return raw ? JSON.parse(raw) as Pairing : null;
}

export async function api<T = unknown>(path: string, body?: unknown): Promise<T> {
  const session = paired();
  if (!session) throw new ApiError("Pair your local member device", 401);
  if (!/^[a-z][a-z0-9-]*(\?[^#]*)?$/.test(path)) throw new Error("invalid device API path");
  const headers: Record<string, string> = { "X-Loki-Token": session.capability };
  if (body !== undefined) headers["Content-Type"] = "application/json";
  const res = await fetch(`${session.endpoint}/api/${path}`, {
    method: body === undefined ? "GET" : "POST", headers,
    body: body === undefined ? undefined : JSON.stringify(body),
    credentials: "omit", redirect: "error", cache: "no-store",
  });
  const text = await res.text();
  const data = text ? JSON.parse(text) : {};
  if (!res.ok) {
    if (res.status === 401) window.dispatchEvent(new Event("loki:auth-lost"));
    throw new ApiError(data.error ?? `${path} failed (${res.status})`, res.status);
  }
  return data as T;
}

export async function listSlots(): Promise<Slot[]> {
  const res = await fetch("/api/members", { cache: "no-store" });
  if (!res.ok) throw new Error("could not read public roster");
  return (await res.json()).slots as Slot[];
}

/** shortcut: explicit loopback pairing for S4a; replace with native pairing in S4b. */
export async function pairDevice(link: string): Promise<Slot> {
  const url = new URL(link.trim());
  if (url.protocol !== "http:" || !["127.0.0.1", "[::1]"].includes(url.hostname)
    || !url.port || Number(url.port) < 1024 || url.pathname !== "/" || url.search || url.username || url.password
    || !/^#[A-Za-z0-9_-]{43}$/.test(url.hash)) throw new Error("Paste the local pairing link printed by your member process");
  const previous = sessionStorage.getItem(PAIRING);
  sessionStorage.setItem(PAIRING, JSON.stringify({ endpoint: url.origin, capability: url.hash.slice(1) }));
  try {
    const member = await api<Slot>("registration");
    const roster = await listSlots();
    // The manually selected loopback session and the public peer endpoint serve different callers.
    if (!roster.some((m) => m.slot === member.slot && m.signing_pubkey === member.signing_pubkey && m.relay_pubkey === member.relay_pubkey && m.advertise_url === member.advertise_url)) throw new Error("Device identity does not match the public roster; register the device first");
    const status = await api<{ phase: string }>("status");
    if (status.phase !== "home") throw new Error("Unlock the profile locally on your device, then pair again");
    return member;
  } catch (error) {
    if (previous) sessionStorage.setItem(PAIRING, previous); else sessionStorage.removeItem(PAIRING);
    throw error;
  }
}
export function forgetPairing(): void {
  sessionStorage.removeItem(PAIRING);
  sessionStorage.removeItem("loki_me");
}
export async function logout(): Promise<boolean> {
  try { if (paired()) await api("lock", {}); return true; }
  catch { return false; }
  finally { forgetPairing(); }
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
