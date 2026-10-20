import { member } from "@/lib/members";

/**
 * Proxy `/api/m/<id>/<path>` → the member_app process on 127.0.0.1:<port>, injecting its
 * `X-Loki-Token` server-side. The browser never sees the token, and member_app needs no CORS.
 */
async function proxy(req: Request, id: string, path: string[]) {
  let m;
  try {
    m = member(Number(id));
  } catch (e) {
    return Response.json({ error: (e as Error).message }, { status: 502 });
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
    return Response.json({ error: `member ${id} unreachable: ${(e as Error).message}` }, { status: 502 });
  }
}

type Ctx = { params: Promise<{ id: string; path: string[] }> };

export async function GET(req: Request, { params }: Ctx) {
  const { id, path } = await params;
  return proxy(req, id, path);
}

export async function POST(req: Request, { params }: Ctx) {
  const { id, path } = await params;
  return proxy(req, id, path);
}
