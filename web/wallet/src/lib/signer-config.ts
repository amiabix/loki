export type WitnessConfig = { endpoint: string; key: number[]; run: number[]; mailbox: number[] };
export type SignerConfig = {
  network: "testnet" | "regtest";
  frostdUrl: string;
  lightwalletdUrl: string | null;
  nonceWitnesses: [WitnessConfig, WitnessConfig];
};

export function configuredSignerOrigin(): string | undefined {
  return process.env.LOKI_SIGNER_ORIGIN || process.env.NEXT_PUBLIC_SIGNER_ORIGIN;
}

export function signerOrigin(configured: string | undefined = configuredSignerOrigin(), mode: string | undefined = process.env.NODE_ENV): string {
  if (configured) return new URL(configured).origin;
  if (mode !== "production") return "http://localhost:3002";
  throw new Error("this coordinator has no signer origin (LOKI_SIGNER_ORIGIN or NEXT_PUBLIC_SIGNER_ORIGIN), so it serves no signer configuration");
}

export async function signerConfig(origin: string, timeoutMs = 10_000): Promise<SignerConfig> {
  let reply: Response;
  try {
    reply = await fetch(`${origin}/config.json`, { redirect: "manual", cache: "no-store", signal: AbortSignal.timeout(timeoutMs) });
  } catch {
    throw new Error(`the signer origin ${origin} is unreachable`);
  }
  if (reply.status !== 200) throw new Error(`the signer origin ${origin} answered ${reply.status} instead of its configuration`);
  const invalid = (what: string) => new Error(`the signer origin ${origin} serves an invalid ${what}`);
  const raw = await reply.json().catch(() => { throw invalid("configuration"); });
  if (!raw || typeof raw !== "object") throw invalid("configuration");
  const url = (value: unknown, what: string): string => {
    if (typeof value !== "string" || !URL.canParse(value) || !["https:", "http:"].includes(new URL(value).protocol)) throw invalid(what);
    return value;
  };
  const bytes = (value: unknown, what: string): number[] => {
    if (typeof value !== "string" || !/^[0-9a-f]{64}$/.test(value)) throw invalid(`nonce witness ${what}`);
    return [...Buffer.from(value, "hex")];
  };
  if (raw.network !== "testnet" && raw.network !== "regtest") throw invalid("network");
  if (!Array.isArray(raw.nonceWitnesses) || raw.nonceWitnesses.length !== 2) throw invalid("nonce witness list");
  const witness = (w: Record<string, unknown>): WitnessConfig => ({
    endpoint: url(w?.endpoint, "nonce witness endpoint"),
    key: bytes(w.key, "key"), run: bytes(w.run, "run"), mailbox: bytes(w.mailbox, "mailbox"),
  });
  return {
    network: raw.network,
    frostdUrl: url(raw.frostdUrl, "frostd URL"),
    lightwalletdUrl: raw.lightwalletdUrl === "" || raw.lightwalletdUrl === undefined ? null : url(raw.lightwalletdUrl, "lightwalletd URL"),
    nonceWitnesses: [witness(raw.nonceWitnesses[0]), witness(raw.nonceWitnesses[1])],
  };
}

export async function signerConfigResponse(configured: string | undefined = configuredSignerOrigin(), mode: string | undefined = process.env.NODE_ENV): Promise<Response> {
  const headers = { "Cache-Control": "no-store" };
  try {
    return Response.json(await signerConfig(signerOrigin(configured, mode)), { headers });
  } catch (error) {
    return Response.json({ error: (error as Error).message }, { status: 502, headers });
  }
}
