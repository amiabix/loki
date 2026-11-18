// The signer origin: a static server for the in-browser signer, on its OWN origin, apart from
// the wallet UI. It serves only this directory's signer page + Worker + wasm and the transport
// pkg, so wallet-page JS never runs where the share, the passkey ceremony or the passphrase
// live. The wallet embeds `${origin}/` in an iframe and talks to it over postMessage.
//
//   node serve.mjs            # dev: http://localhost:3002, wallet http://localhost:3001
//   node serve.mjs --hash     # print the published build hash and exit
//
// Environment (a deploy MUST set the first four; see web/wallet/README.md):
//   LOKI_WALLET_ORIGIN    the one wallet origin allowed to embed and message the signer
//                         (default http://localhost:3001)
//   LOKI_FROSTD_URL       the frostd relay the signer logs in to (shown to the member)
//   LOKI_RP_ID            WebAuthn rpId; must stay STABLE across deploys or passkeys stop
//                         unlocking (default: the signer page's hostname)
//   LOKI_CEREMONY_ORIGINS creator member-app origins a joiner may call during setup
//                         (space-separated CSP sources; default: loopback member apps)
//   LOKI_SIGNER_PORT      listen port (default 3002)
import { createServer } from "node:http";
import { createHash } from "node:crypto";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, extname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const port = Number(process.env.LOKI_SIGNER_PORT || 3002);
const walletOrigin = new URL(process.env.LOKI_WALLET_ORIGIN || "http://localhost:3001").origin;
const frostdUrl = process.env.LOKI_FROSTD_URL || "";
const rpId = process.env.LOKI_RP_ID || "";
const ceremonyOrigins = process.env.LOKI_CEREMONY_ORIGINS || "http://127.0.0.1:* http://localhost:*";

// The whole servable bundle, read ONCE at startup: the page files plus the two wasm-pack
// pkgs. Requests are answered from this snapshot by exact path, so nothing else on disk is
// reachable and the bytes served are exactly the bytes hashed below.
const types = { ".html": "text/html", ".js": "text/javascript", ".css": "text/css", ".wasm": "application/wasm", ".json": "application/json" };
const bundle = new Map();
for (const name of ["signer.html", "signer-page.js", "signer-page.css", "signer-worker.js"]) {
  bundle.set(`/${name}`, readFileSync(join(here, name)));
}
for (const [prefix, dir] of [["/pkg/", resolve(here, "pkg")], ["/wasm-transport/pkg/", resolve(here, "../wasm-transport/pkg")]]) {
  for (const name of readdirSync(dir, { recursive: true })) {
    if (statSync(join(dir, name)).isFile() && !name.endsWith(".gitignore")) bundle.set(`${prefix}${name}`, readFileSync(join(dir, name)));
  }
}

// The published build hash: SHA-256 of every served file, and one bundle hash over that sorted
// list. The running server serves it at /build-hash.json, so a member or auditor can compare
// the deployed signer against the published one. Browsers have no SRI for module Workers,
// dynamic imports or wasm, so this whole-bundle hash is what pins the signer's code.
const fileHashes = [...bundle].map(([p, b]) => [p, createHash("sha256").update(b).digest("hex")]).sort(([a], [b]) => (a < b ? -1 : 1));
const build = {
  bundle: createHash("sha256").update(fileHashes.map(([p, h]) => `${h}  ${p}\n`).join("")).digest("hex"),
  files: Object.fromEntries(fileHashes),
};
if (process.argv.includes("--hash")) {
  console.log(JSON.stringify(build, null, 2));
  process.exit(0);
}
bundle.set("/config.json", Buffer.from(JSON.stringify({ walletOrigin, frostdUrl, rpId })));
bundle.set("/build-hash.json", Buffer.from(JSON.stringify(build)));

// Strict CSP on every response (the page, the Worker script and its imports all get it).
// Only this origin's scripts run: no inline script, no eval, no third-party code;
// 'wasm-unsafe-eval' is the one exception, needed to instantiate wasm. connect-src: this
// origin (the .wasm fetch), the relay, and the creator member apps a joiner calls in setup.
const csp = [
  "default-src 'none'",
  "script-src 'self' 'wasm-unsafe-eval'",
  "worker-src 'self'",
  "style-src 'self'",
  `connect-src 'self' ${frostdUrl ? new URL(frostdUrl).origin : ""} ${ceremonyOrigins}`.replace(/\s+/g, " ").trim(),
  "img-src 'self'",
  "base-uri 'none'",
  "form-action 'none'",
  `frame-ancestors ${walletOrigin}`, // only the wallet may embed the signer
].join("; ");

createServer((req, res) => {
  if (req.method !== "GET" && req.method !== "HEAD") { res.writeHead(405).end(); return; }
  const path = new URL(req.url, "http://x").pathname;
  const key = path === "/" ? "/signer.html" : path;
  const body = bundle.get(key);
  const type = body ? types[extname(key)] || "application/octet-stream" : "text/plain";
  res.writeHead(body ? 200 : 404, {
    "Content-Type": type.startsWith("text/") ? `${type}; charset=utf-8` : type,
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Content-Security-Policy": csp,
  });
  res.end(req.method === "HEAD" ? undefined : body ?? "not found");
}).listen(port, () => console.log(`loki signer origin on http://localhost:${port} (wallet ${walletOrigin}) build ${build.bundle}`));
