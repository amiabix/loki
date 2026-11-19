import { createPublicKey, randomBytes, verify } from "node:crypto";
import { mkdirSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { isLokiSignerUrl } from "./lokisigner-url.ts";

export type Member = { slot: number; signing_pubkey: string; relay_pubkey: string; advertise_url: string; lokisigner_url?: string };
type Enrollment = Omit<Member, "slot"> & { slot?: number; device_pubkey: string; authorization: string };
type Challenge = { challenge: string; origin: string; enrollment?: Enrollment; pairing_slot?: number; expires: number };
type Device = { slot: number; signing_pubkey: string; device_pubkey: string };
const publicFields = ["slot", "signing_pubkey", "relay_pubkey", "advertise_url", "lokisigner_url"];
const enrollmentFields = [...publicFields, "device_pubkey", "authorization"];

function registryPath(): string {
  return process.env.LOKI_REGISTRY ?? join(process.cwd(), ".access.json");
}

function read(file: string, fallback: unknown): unknown {
  try { return JSON.parse(readFileSync(file, "utf8")); }
  catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return fallback;
    throw error;
  }
}

function object(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("expected an object");
  return value as Record<string, unknown>;
}
function fields(value: Record<string, unknown>, allowed: string[]) {
  if (Object.keys(value).some((key) => !allowed.includes(key))) throw new Error("unexpected registration field");
}
function hex(value: unknown, length: number): string {
  if (typeof value !== "string" || !new RegExp(`^[0-9a-f]{${length * 2}}$`).test(value)) throw new Error("invalid public key or proof");
  return value;
}
function slot(value: unknown): number {
  if (!Number.isSafeInteger(value) || Number(value) < 1 || Number(value) > 0xffffffff) throw new Error("invalid slot");
  return Number(value);
}
function publicOrigin(value: unknown): string {
  if (typeof value !== "string") throw new Error("missing public origin");
  const url = new URL(value);
  const loopback = ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
  if (url.origin !== value || url.username || url.password || (url.protocol !== "https:" && !(url.protocol === "http:" && loopback))) {
    throw new Error("expected an HTTPS origin (HTTP is local development only)");
  }
  return value;
}
// A frostd-only member (an in-browser signer) advertises no peer origin: peer-over-frostd
// removed inbound peer HTTP, so "" means "reachable only via the frostd relay". A native
// member still advertises its loopback origin, which must be a valid origin.
function optionalOrigin(value: unknown): string {
  return value === undefined || value === "" ? "" : publicOrigin(value);
}
function lokiSignerField(value: unknown): { lokisigner_url?: string } {
  if (value === undefined) return {};
  if (!isLokiSignerUrl(value)) throw new Error("invalid LokiSigner loopback endpoint");
  return { lokisigner_url: value };
}
function publicMember(raw: unknown): Member {
  const m = object(raw);
  fields(m, publicFields);
  return { slot: slot(m.slot), signing_pubkey: hex(m.signing_pubkey, 32), relay_pubkey: hex(m.relay_pubkey, 32), advertise_url: optionalOrigin(m.advertise_url), ...lokiSignerField(m.lokisigner_url) };
}

/** Strictly public data. Legacy hosted registries must be retired locally, never loaded. */
export function slots(): Member[] {
  const data = object(read(registryPath(), { access: [] }));
  fields(data, ["access"]);
  if (!Array.isArray(data.access)) throw new Error("invalid public roster");
  return data.access.map(publicMember).sort((a, b) => a.slot - b.slot);
}
export function memberById(id: number): Member | null {
  return slots().find((m) => m.slot === id) ?? null;
}

/** Serialize challenge consumption and roster allocation across Next workers. */
async function registrationLock(file: string): Promise<() => void> {
  mkdirSync(dirname(file), { recursive: true, mode: 0o700 });
  const lock = `${file}.lock`;
  const deadline = Date.now() + 5000;
  while (true) {
    try {
      writeFileSync(lock, "", { flag: "wx", mode: 0o600 });
      return () => rmSync(lock);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
      // shortcut: a crashed worker leaves this lock; remove it only after stopping all web workers.
      if (Date.now() >= deadline) throw new Error("registration is busy");
      await delay(25);
    }
  }
}
function write(file: string, value: unknown) {
  const temp = `${file}.${randomBytes(8).toString("hex")}.tmp`;
  try {
    writeFileSync(temp, JSON.stringify(value), { mode: 0o600, flag: "wx" });
    renameSync(temp, file);
  } finally { rmSync(temp, { force: true }); }
}
function pending(file: string): Challenge[] {
  const data = read(`${file}.challenges`, []);
  if (!Array.isArray(data)) throw new Error("invalid challenge store");
  return (data as Challenge[]).filter((c) => c.expires > Date.now());
}

// Same Ed25519 authorization of SEC1 P-256 bytes as signer/device_auth.rs::enroll.
function enrollment(raw: unknown): Enrollment {
  const e = object(raw);
  fields(e, enrollmentFields);
  const signing_pubkey = hex(e.signing_pubkey, 32);
  const relay_pubkey = hex(e.relay_pubkey, 32);
  if (relay_pubkey === "00".repeat(32)) throw new Error("invalid relay key");
  const device_pubkey = hex(e.device_pubkey, 65);
  deviceKey(device_pubkey); // Reject invalid points before issuing a challenge.
  const authorization = hex(e.authorization, 64);
  const identity = createPublicKey({ key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), Buffer.from(signing_pubkey, "hex")]), format: "der", type: "spki" });
  if (!verify(null, Buffer.from(device_pubkey, "hex"), identity, Buffer.from(authorization, "hex"))) throw new Error("device authorization does not verify");
  return { ...(e.slot === undefined ? {} : { slot: slot(e.slot) }), signing_pubkey, relay_pubkey, advertise_url: optionalOrigin(e.advertise_url), ...lokiSignerField(e.lokisigner_url), device_pubkey, authorization };
}
function deviceKey(key: string) {
  if (!key.startsWith("04")) throw new Error("expected uncompressed P-256 key");
  return createPublicKey({ key: Buffer.concat([Buffer.from("3059301306072a8648ce3d020106082a8648ce3d030107034200", "hex"), Buffer.from(key, "hex")]), format: "der", type: "spki" });
}
function devices(file: string): Device[] {
  const data = read(`${file}.devices`, []);
  if (!Array.isArray(data)) throw new Error("invalid device registry");
  return data as Device[];
}
// A device key stays bound to one identity. An identity may replace its device key (a member
// restored on a new machine): its signature authorizes the new key, which signs a fresh
// challenge, and whoever holds the identity key already holds the share. Its slot and relay key
// stay pinned (relay key: `allocatedSlot`).
function checkDevice(e: Enrollment, file: string) {
  for (const d of devices(file)) {
    if (d.device_pubkey === e.device_pubkey && d.signing_pubkey !== e.signing_pubkey) throw new Error("registered device cannot change identity");
    if (d.signing_pubkey === e.signing_pubkey && e.slot !== undefined && d.slot !== e.slot) throw new Error("registered identity cannot change slot");
  }
}
function allocatedSlot(e: Enrollment, list: Member[], challenges: Challenge[]): number {
  const bindings = devices(registryPath());
  const desired = e.slot ?? bindings.find((d) => d.signing_pubkey === e.signing_pubkey)?.slot;
  const existing = list.find((m) => m.signing_pubkey === e.signing_pubkey);
  if (existing) {
    if ((e.slot !== undefined && e.slot !== existing.slot) || existing.relay_pubkey !== e.relay_pubkey) throw new Error("registered identity cannot change slot or relay key");
    return existing.slot;
  }
  if (desired !== undefined && (list.some((m) => m.slot === desired) || bindings.some((d) => d.slot === desired && d.signing_pubkey !== e.signing_pubkey))) throw new Error("slot already belongs to another identity");
  const reserved = challenges.flatMap((c) => c.pairing_slot === undefined ? [] : [c.pairing_slot]);
  if (desired !== undefined && reserved.includes(desired)) throw new Error("slot reserved for pairing");
  if (list.some((m) => m.relay_pubkey === e.relay_pubkey)) throw new Error("relay key already registered");
  return slot(desired ?? Math.max(0, ...list.map((m) => m.slot), ...bindings.map((d) => d.slot), ...reserved) + 1);
}
function message(e: Enrollment, origin: string, challenge: string): Buffer {
  const local = e.lokisigner_url === undefined ? [] : [e.lokisigner_url];
  return Buffer.from([local.length ? "loki-member-registration-v2" : "loki-member-registration-v1", origin, e.slot ?? 0, e.signing_pubkey, e.relay_pubkey, e.advertise_url, ...local, e.device_pubkey, challenge].join("\n"));
}

export async function issuePairingChallenge(raw: unknown, origin: string) {
  const body = object(raw);
  fields(body, ["slot"]);
  publicOrigin(origin);
  const file = registryPath();
  const unlock = await registrationLock(file);
  try {
    const challenges = pending(file);
    if (challenges.length >= 256) throw new Error("too many pending registrations");
    const used = [...slots().map((m) => m.slot), ...devices(file).map((d) => d.slot), ...challenges.flatMap((c) => c.pairing_slot ?? c.enrollment?.slot ?? [])];
    const id = slot(body.slot ?? Math.max(0, ...used) + 1);
    if (used.includes(id)) throw new Error("slot already registered or reserved");
    const challenge = randomBytes(32).toString("hex");
    const expires = Date.now() + 120_000;
    challenges.push({ challenge, origin, pairing_slot: id, expires });
    write(`${file}.challenges`, challenges);
    const query = new URLSearchParams({ origin, slot: String(id), challenge });
    return { slot: id, challenge, expires, url: `loki://pair?${query}` };
  } finally { unlock(); }
}

export async function issueRegistrationChallenge(raw: unknown, origin: string): Promise<{ challenge: string }> {
  const { pairing_challenge, ...identity } = object(raw);
  const e = enrollment(identity);
  publicOrigin(origin);
  const file = registryPath();
  const unlock = await registrationLock(file);
  try {
    let challenges = pending(file);
    let claimed: Challenge | undefined;
    if (pairing_challenge !== undefined) {
      const nonce = hex(pairing_challenge, 32);
      claimed = challenges.find((c) => c.challenge === nonce && !c.enrollment);
      challenges = challenges.filter((c) => c.challenge !== nonce);
      write(`${file}.challenges`, challenges);
      if (!claimed || claimed.origin !== origin || claimed.pairing_slot !== e.slot) throw new Error("unknown, expired or changed pairing challenge");
    }
    checkDevice(e, file);
    allocatedSlot(e, slots(), challenges);
    if (challenges.length >= 256) throw new Error("too many pending registrations");
    const challenge = randomBytes(32).toString("hex");
    challenges.push({ challenge, origin, enrollment: e, ...(claimed ? { pairing_slot: claimed.pairing_slot } : {}), expires: claimed?.expires ?? Date.now() + 120_000 });
    write(`${file}.challenges`, challenges);
    return { challenge };
  } finally { unlock(); }
}

export async function registerMember(raw: unknown, origin: string): Promise<Member> {
  const body = object(raw);
  fields(body, [...enrollmentFields, "challenge", "signature"]);
  const { challenge: rawChallenge, signature: rawSignature, ...identity } = body;
  const e = enrollment(identity);
  const challenge = hex(rawChallenge, 32);
  const signature = typeof rawSignature === "string" && /^[0-9a-f]{128,144}$/.test(rawSignature) ? Buffer.from(rawSignature, "hex") : null;
  if (!signature) throw new Error("invalid device signature");
  const file = registryPath();
  const unlock = await registrationLock(file);
  try {
    const challenges = pending(file);
    const issued = challenges.find((c) => c.challenge === challenge);
    // Consume before checking the proof, including failures; restarts cannot revive it.
    write(`${file}.challenges`, challenges.filter((c) => c.challenge !== challenge));
    if (!issued || issued.origin !== origin || JSON.stringify(issued.enrollment) !== JSON.stringify(e)) throw new Error("unknown, expired or changed registration challenge");
    const key = deviceKey(e.device_pubkey);
    const bytes = message(e, origin, challenge);
    if (!verify("sha256", bytes, key, signature) && !(signature.length === 64 && verify("sha256", bytes, { key, dsaEncoding: "ieee-p1363" }, signature))) throw new Error("device signature does not verify");
    checkDevice(e, file);
    const list = slots();
    const member: Member = { slot: allocatedSlot(e, list, challenges.filter((c) => c.challenge !== challenge)), signing_pubkey: e.signing_pubkey, relay_pubkey: e.relay_pubkey, advertise_url: e.advertise_url, ...lokiSignerField(e.lokisigner_url) };
    // Persist the public binding first: a crash cannot let a second identity reuse the device.
    write(`${file}.devices`, [...devices(file).filter((d) => d.signing_pubkey !== e.signing_pubkey), { slot: member.slot, signing_pubkey: e.signing_pubkey, device_pubkey: e.device_pubkey }]);
    write(file, { access: [...list.filter((m) => m.slot !== member.slot), member] });
    return member;
  } finally { unlock(); }
}

/** Limit the stream, including chunked requests, before JSON parsing. */
export async function readRegistrationBody(req: Request): Promise<unknown> {
  const reader = req.body?.getReader();
  if (!reader) throw new Error("missing registration body");
  const chunks: Uint8Array[] = [];
  let length = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      length += value.length;
      if (length > 4096) { await reader.cancel(); throw new Error("registration too large"); }
      chunks.push(value);
    }
  } finally { reader.releaseLock(); }
  return JSON.parse(Buffer.concat(chunks).toString("utf8"));
}
