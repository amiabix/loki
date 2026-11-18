// The signer origin: a static server for the in-browser signer, on its OWN origin, apart from
// the wallet UI. It serves only this directory's signer page + Worker + wasm and the transport
// pkg, so wallet-page JS never runs where the share, the passkey ceremony or the passphrase
// live. The wallet embeds `${origin}/` in an iframe and talks to it over postMessage.
//
//   node serve.mjs                      # dev: http://localhost:3002, wallet http://localhost:3001
//
// Environment (a deploy MUST set the first three; see README "Signer origin"):
//   LOKI_SIGNER_PORT     listen port (default 3002)
//   LOKI_WALLET_ORIGIN   the one wallet origin allowed to embed and message the signer
//                        (default http://localhost:3001)
//   LOKI_FROSTD_URL      the frostd relay the signer logs in to (shown to the member)
//   LOKI_RP_ID           WebAuthn rpId; must stay STABLE across deploys or passkeys stop
//                        unlocking (default: the signer page's hostname)
import { createServer } from "node:http";
import { readFileSync, statSync } from "node:fs";
import { dirname, extname, join, normalize, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const port = Number(process.env.LOKI_SIGNER_PORT || 3002);
const walletOrigin = new URL(process.env.LOKI_WALLET_ORIGIN || "http://localhost:3001").origin;
const frostdUrl = process.env.LOKI_FROSTD_URL || "";
const rpId = process.env.LOKI_RP_ID || "";

// Published path prefix -> directory on disk. Nothing outside these is served.
const roots = [
  ["/wasm-transport/pkg/", resolve(here, "../wasm-transport/pkg")],
  ["/pkg/", resolve(here, "pkg")],
  ["/", here],
];
const files = new Set(["/", "/signer.html", "/signer-page.js", "/signer-page.css", "/signer-worker.js"]);
const types = { ".html": "text/html", ".js": "text/javascript", ".css": "text/css", ".wasm": "application/wasm", ".json": "application/json" };

const config = JSON.stringify({ walletOrigin, frostdUrl, rpId });

function headers(type) {
  return {
    "Content-Type": type.startsWith("text/") ? `${type}; charset=utf-8` : type,
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    // Only the wallet may embed the signer; nothing may frame it elsewhere.
    "Content-Security-Policy": `frame-ancestors ${walletOrigin}`,
  };
}

function resolvePath(url) {
  const path = decodeURIComponent(new URL(url, "http://x").pathname);
  if (path.includes("\0")) return null;
  for (const [prefix, dir] of roots) {
    if (!path.startsWith(prefix)) continue;
    if (prefix === "/" && !files.has(path)) return null;
    const rel = prefix === "/" && path === "/" ? "signer.html" : path.slice(prefix.length);
    const file = normalize(join(dir, rel));
    return file.startsWith(dir) ? file : null;
  }
  return null;
}

createServer((req, res) => {
  if (req.method !== "GET" && req.method !== "HEAD") { res.writeHead(405).end(); return; }
  if (new URL(req.url, "http://x").pathname === "/config.json") {
    res.writeHead(200, headers("application/json")).end(req.method === "HEAD" ? undefined : config);
    return;
  }
  const file = resolvePath(req.url);
  let body;
  try { if (file && statSync(file).isFile()) body = readFileSync(file); } catch {}
  if (!body) { res.writeHead(404, headers("text/plain")).end("not found"); return; }
  res.writeHead(200, headers(types[extname(file)] || "application/octet-stream"));
  res.end(req.method === "HEAD" ? undefined : body);
}).listen(port, () => console.log(`loki signer origin on http://localhost:${port} (wallet ${walletOrigin})`));
