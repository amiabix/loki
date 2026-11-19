/** The literal HTTP origins LokiSigner advertises. Do not let URL normalize aliases,
 * paths, whitespace or an absent port before checking the roster value. */
export function isLokiSignerUrl(value: unknown): value is string {
  if (typeof value !== "string") return false;
  const match = /^http:\/\/(?:127\.0\.0\.1|\[::1\]):([1-9][0-9]{0,4})$/.exec(value);
  return match !== null && match[0] === value && Number(match[1]) <= 65535;
}
