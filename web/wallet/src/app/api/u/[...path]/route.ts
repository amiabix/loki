import { memberBySlug } from "@/lib/members";

/**
 * Proxy `/api/u/<path>` → the member_app process on 127.0.0.1:<port>, resolving the caller's
 * member from the `X-Loki-Access` capability slug (server-side) and injecting that member's
 * `X-Loki-Token`. The slug is the only thing the tester holds, so they can act as exactly one
 * signer — the client cannot name a member, closing the member-switcher bypass.
 */
async function proxy(req: Request, path: string[]) {
  const slug = req.headers.get("x-loki-access") ?? "";
  let m;
  try {
    m = memberBySlug(slug);
  } catch (e) {
    return Response.json({ error: (e as Error).message }, { status: 401 });
  }
  const search = new URL(req.url).search;
  const url = `http://127.0.0.1:${m.port}/api/${path.join("/")}${search}`;
  const init: RequestInit = {
    method: req.method,
    headers: { "X-Loki-Token": m.token, "Content-Type": "application/json" },
  };
  if (req.method === "POST") init.body = await req.text();
  try {
    const res = await fetch(url, init);
    const body = await res.text();
    return new Response(body, {
      status: res.status,
      headers: { "Content-Type": "application/json" },
    });
  } catch (e) {
    return Response.json({ error: `member unreachable: ${(e as Error).message}` }, { status: 502 });
  }
}

type Ctx = { params: Promise<{ path: string[] }> };

export async function GET(req: Request, { params }: Ctx) {
  const { path } = await params;
  return proxy(req, path);
}

export async function POST(req: Request, { params }: Ctx) {
  const { path } = await params;
  return proxy(req, path);
}
