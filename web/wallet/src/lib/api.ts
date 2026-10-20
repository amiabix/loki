/** Call a member_app endpoint through the server-side proxy (which injects the token). */
export async function api<T = unknown>(
  member: number,
  path: string,
  body?: unknown,
): Promise<T> {
  const res = await fetch(`/api/m/${member}/${path}`, {
    method: body === undefined ? "GET" : "POST",
    headers: body === undefined ? undefined : { "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await res.text();
  const data = text ? JSON.parse(text) : {};
  if (!res.ok) throw new Error(data.error ?? `${path} failed (${res.status})`);
  return data as T;
}
