/**
 * Call a member_app endpoint through the server-side proxy.
 *
 * `access` is the tester's capability slug (from the URL fragment). It is sent as the
 * `X-Loki-Access` header; the proxy resolves it to exactly one member server-side and injects
 * that member's `X-Loki-Token`. The browser never learns the member's token or any other
 * member's slug, so a tester can only ever act as their own signer.
 */
export async function api<T = unknown>(
  access: string,
  path: string,
  body?: unknown,
): Promise<T> {
  const headers: Record<string, string> = { "X-Loki-Access": access };
  if (body !== undefined) headers["Content-Type"] = "application/json";
  const res = await fetch(`/api/u/${path}`, {
    method: body === undefined ? "GET" : "POST",
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await res.text();
  const data = text ? JSON.parse(text) : {};
  if (!res.ok) throw new Error(data.error ?? `${path} failed (${res.status})`);
  return data as T;
}
