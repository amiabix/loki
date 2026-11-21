import { createPublicKey, randomBytes, verify } from "node:crypto";
import { closeSync, fsyncSync, mkdirSync, openSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { isLokiSignerUrl } from "./lokisigner-url.ts";

export type Member = { slot: number; signing_pubkey: string; relay_pubkey: string; advertise_url: string; lokisigner_url?: string };
type Enrollment = Omit<Member, "slot"> & { slot?: number; device_pubkey: string; authorization: string };
type Challenge = { challenge: string; origin: string; enrollment?: Enrollment; pairing_slot?: number; expires: number; generation?: number };
type Device = { slot: number; signing_pubkey: string; device_pubkey: string; generation: number; retired: string[] };
type Registry = { version: 1; access: Member[]; devices: Device[]; challenges: Challenge[] };
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

function publicRoster(data: Record<string, unknown>): Member[] {
  if (!Array.isArray(data.access)) throw new Error("invalid public roster");
  return data.access.map(publicMember).sort((a, b) => a.slot - b.slot);
}

/** Never include private registry metadata in the public roster. */
export function slots(): Member[] {
  const data = object(read(registryPath(), { access: [] }));
  checkRegistryFields(data);
  return publicRoster(data);
}

function checkRegistryFields(data: Record<string, unknown>) {
  fields(data, data.version === 1 ? ["version", "access", "devices", "challenges"] : ["access"]);
}

function loadRegistry(file: string): Registry {
  const data = object(read(file, { access: [] }));
  checkRegistryFields(data);
  const access = publicRoster(data);
  const legacy = data.version === undefined;
  const bindings = legacy ? read(`${file}.devices`, []) : data.devices;
  // Legacy nonces are not bound to a generation. Let users obtain fresh pairing links.
  const challenges = legacy ? [] : data.challenges;
  if (!Array.isArray(bindings) || !Array.isArray(challenges)) throw new Error("invalid registration store");
  const devices = bindings.map((raw): Device => {
    const d = object(raw);
    fields(d, legacy ? ["slot", "signing_pubkey", "device_pubkey"] : ["slot", "signing_pubkey", "device_pubkey", "generation", "retired"]);
    const generation = legacy ? 1 : d.generation;
    const retired = legacy ? [] : d.retired;
    if (typeof generation !== "number" || !Number.isSafeInteger(generation) || generation < 1 || !Array.isArray(retired)) {
      throw new Error("invalid device binding generation");
    }
    return { slot: slot(d.slot), signing_pubkey: hex(d.signing_pubkey, 32), device_pubkey: hex(d.device_pubkey, 65), generation, retired: retired.map((key) => hex(key, 65)) };
  });
  return { version: 1, access, devices, challenges };
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
    writeFileSync(temp, JSON.stringify(value), { mode: 0o600, flag: "wx", flush: true });
    renameSync(temp, file);
    const dir = openSync(dirname(file), "r");
    try { fsyncSync(dir); } finally { closeSync(dir); }
  } finally { rmSync(temp, { force: true }); }
}

/** One durable snapshot for nonce consumption, device bindings and roster writes. */
async function changeRegistry<T>(change: (state: Registry, now: number) => T | Error): Promise<T> {
  const file = registryPath();
  const unlock = await registrationLock(file);
  try {
    const state = loadRegistry(file);
    const now = Date.now();
    state.challenges = state.challenges.filter((c) => c.expires > now);
    const result = change(state, now);
    // An explicit Error result commits consumption of a rejected proof, then reports it.
    write(file, state);
    if (result instanceof Error) throw result;
    return result;
  } finally { unlock(); }
}

function identityKey(signing_pubkey: string) {
  return createPublicKey({ key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), Buffer.from(signing_pubkey, "hex")]), format: "der", type: "spki" });
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
  const identity = identityKey(signing_pubkey);
  if (!verify(null, Buffer.from(device_pubkey, "hex"), identity, Buffer.from(authorization, "hex"))) throw new Error("device authorization does not verify");
  return { ...(e.slot === undefined ? {} : { slot: slot(e.slot) }), signing_pubkey, relay_pubkey, advertise_url: optionalOrigin(e.advertise_url), ...lokiSignerField(e.lokisigner_url), device_pubkey, authorization };
}
function deviceKey(key: string) {
  if (!key.startsWith("04")) throw new Error("expected uncompressed P-256 key");
  return createPublicKey({ key: Buffer.concat([Buffer.from("3059301306072a8648ce3d020106082a8648ce3d030107034200", "hex"), Buffer.from(key, "hex")]), format: "der", type: "spki" });
}
// Removed keys keep their original identity binding even after a replacement.
function checkDevice(e: Enrollment, bindings: Device[]): Device | undefined {
  for (const d of bindings) {
    if ((d.device_pubkey === e.device_pubkey || d.retired.includes(e.device_pubkey)) && d.signing_pubkey !== e.signing_pubkey) throw new Error("registered device cannot change identity");
    if (d.signing_pubkey === e.signing_pubkey && e.slot !== undefined && d.slot !== e.slot) throw new Error("registered identity cannot change slot");
  }
  return bindings.find((d) => d.signing_pubkey === e.signing_pubkey);
}

function allocatedSlot(e: Enrollment, { access: list, devices: bindings }: Registry, challenges: Challenge[]): number {
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
export function registrationMessage(e: Enrollment, origin: string, challenge: string): Buffer {
  const local = e.lokisigner_url === undefined ? [] : [e.lokisigner_url];
  return Buffer.from([local.length ? "loki-member-registration-v2" : "loki-member-registration-v1", origin, e.slot ?? 0, e.signing_pubkey, e.relay_pubkey, e.advertise_url, ...local, e.device_pubkey, challenge].join("\n"));
}

function replacementGeneration(e: Enrollment, state: Registry, previous: Device | undefined): number | undefined {
  if (previous?.device_pubkey === e.device_pubkey) return undefined;
  if (!previous && !state.access.some((m) => m.signing_pubkey === e.signing_pubkey)) return undefined;
  const next = (previous?.generation ?? 0) + 1;
  if (!Number.isSafeInteger(next)) throw new Error("registration generation exhausted");
  return next;
}

function replacementMessage(e: Enrollment, origin: string, challenge: string, generation: number): Buffer {
  return Buffer.from(["loki-member-device-replacement-v1", origin, e.signing_pubkey, e.device_pubkey, generation, challenge].join("\n"));
}

export async function issuePairingChallenge(raw: unknown, origin: string) {
  const body = object(raw);
  fields(body, ["slot"]);
  publicOrigin(origin);
  return changeRegistry(({ access, devices, challenges }, now) => {
    if (challenges.length >= 256) throw new Error("too many pending registrations");
    const used = [...access.map((m) => m.slot), ...devices.map((d) => d.slot), ...challenges.flatMap((c) => c.pairing_slot ?? c.enrollment?.slot ?? [])];
    const id = slot(body.slot ?? Math.max(0, ...used) + 1);
    if (used.includes(id)) throw new Error("slot already registered or reserved");
    const challenge = randomBytes(32).toString("hex");
    const expires = now + 120_000;
    challenges.push({ challenge, origin, pairing_slot: id, expires });
    const query = new URLSearchParams({ origin, slot: String(id), challenge });
    return { slot: id, challenge, expires, url: `loki://pair?${query}` };
  });
}

export async function issueRegistrationChallenge(raw: unknown, origin: string): Promise<{ challenge: string; replacement_generation?: number }> {
  const { pairing_challenge, ...identity } = object(raw);
  const e = enrollment(identity);
  publicOrigin(origin);
  return changeRegistry((state, now) => {
    let claimed: Challenge | undefined;
    if (pairing_challenge !== undefined) {
      const nonce = hex(pairing_challenge, 32);
      claimed = state.challenges.find((c) => c.challenge === nonce && !c.enrollment);
      if (!claimed) throw new Error("unknown, expired or changed pairing challenge");
      state.challenges = state.challenges.filter((c) => c !== claimed);
      if (claimed.origin !== origin || claimed.pairing_slot !== e.slot) return new Error("unknown, expired or changed pairing challenge");
    }
    try {
      const previous = checkDevice(e, state.devices);
      const generation = replacementGeneration(e, state, previous);
      const boundGeneration = previous?.generation ?? 0;
      const challenges = state.challenges;
      // A native retry may change ports, but cannot change the device, identity, or generation.
      const resumed = pairing_challenge === undefined && e.lokisigner_url !== undefined
        ? challenges.find((c) => c.origin === origin && c.pairing_slot === e.slot && c.enrollment?.lokisigner_url !== undefined
          && c.enrollment.signing_pubkey === e.signing_pubkey && c.enrollment.relay_pubkey === e.relay_pubkey
          && c.enrollment.device_pubkey === e.device_pubkey && c.generation === boundGeneration)
        : undefined;
      allocatedSlot(e, state, challenges.filter((c) => c !== resumed));
      const replacement = generation === undefined ? {} : { replacement_generation: generation };
      if (resumed) {
        resumed.enrollment = e;
        return { challenge: resumed.challenge, ...replacement };
      }
      if (challenges.length >= 256) throw new Error("too many pending registrations");
      const challenge = randomBytes(32).toString("hex");
      challenges.push({ challenge, origin, enrollment: e, generation: boundGeneration, ...(claimed ? { pairing_slot: claimed.pairing_slot } : {}), expires: claimed?.expires ?? now + 120_000 });
      return { challenge, ...replacement };
    } catch (error) {
      if (claimed && error instanceof Error) return error;
      throw error;
    }
  });
}

export async function registerMember(raw: unknown, origin: string): Promise<Member> {
  const body = object(raw);
  fields(body, [...enrollmentFields, "challenge", "signature", "replacement_authorization"]);
  const { challenge: rawChallenge, signature: rawSignature, replacement_authorization, ...identity } = body;
  const e = enrollment(identity);
  const challenge = hex(rawChallenge, 32);
  const signature = typeof rawSignature === "string" && /^[0-9a-f]{128,144}$/.test(rawSignature) ? Buffer.from(rawSignature, "hex") : null;
  if (!signature) throw new Error("invalid device signature");
  return changeRegistry((state) => {
    const issued = state.challenges.find((c) => c.challenge === challenge && c.enrollment);
    if (!issued) throw new Error("unknown, expired or changed registration challenge");
    state.challenges = state.challenges.filter((c) => c !== issued);
    try {
      if (issued.origin !== origin || JSON.stringify(issued.enrollment) !== JSON.stringify(e)) throw new Error("unknown, expired or changed registration challenge");
      const previous = checkDevice(e, state.devices);
      if (issued.generation !== (previous?.generation ?? 0)) throw new Error("registration generation changed; request a new challenge");
      const next = replacementGeneration(e, state, previous);
      if (next !== undefined) {
        if (replacement_authorization === undefined) throw new Error("replacement authorization is required");
        const proof = Buffer.from(hex(replacement_authorization, 64), "hex");
        if (!verify(null, replacementMessage(e, origin, challenge, next), identityKey(e.signing_pubkey), proof)) throw new Error("replacement authorization does not verify");
      }
      const key = deviceKey(e.device_pubkey);
      const bytes = registrationMessage(e, origin, challenge);
      if (!verify("sha256", bytes, key, signature) && !(signature.length === 64 && verify("sha256", bytes, { key, dsaEncoding: "ieee-p1363" }, signature))) throw new Error("device signature does not verify");
      const member: Member = { slot: allocatedSlot(e, state, state.challenges), signing_pubkey: e.signing_pubkey, relay_pubkey: e.relay_pubkey, advertise_url: e.advertise_url, ...lokiSignerField(e.lokisigner_url) };
      if (!previous || next !== undefined) {
        const retired = previous ? [...previous.retired.filter((k) => k !== e.device_pubkey), previous.device_pubkey] : [];
        state.devices = [...state.devices.filter((d) => d !== previous), { slot: member.slot, signing_pubkey: e.signing_pubkey, device_pubkey: e.device_pubkey, generation: next ?? 1, retired }];
      }
      state.access = [...state.access.filter((m) => m.slot !== member.slot), member];
      return member;
    } catch (error) {
      if (!(error instanceof Error)) throw error;
      return error;
    }
  });
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
