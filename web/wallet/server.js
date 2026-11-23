const { createServer } = require("http");
const next = require("next");

const port = parseInt(process.env.PORT || "3001", 10);
const bind = "127.0.0.1";
const origin = process.env.PUBLIC_ORIGIN ?? new URL(`http://localhost:${port}`).origin;
const publicUrl = new URL(origin);
const loopback = ["localhost", bind].includes(publicUrl.hostname);
const https = publicUrl.protocol === "https:";
if (publicUrl.origin !== origin || !(https || (loopback && publicUrl.protocol === "http:"))) {
  throw new Error("PUBLIC_ORIGIN must be a canonical HTTPS or loopback HTTP origin");
}
const publicPort = Number(publicUrl.port || (https ? 443 : 80));
const app = next({ dev: false, hostname: publicUrl.hostname, port: publicPort });
const handle = app.getRequestHandler();

function cacheFor(url) {
  try {
    if (new URL(url, "http://x").pathname.startsWith("/_next/static/")) {
      return "public, max-age=0, must-revalidate";
    }
  } catch { }
  return "no-store, must-revalidate";
}

app.prepare().then(() => {
  createServer((req, res) => {
    req.headers["x-forwarded-proto"] = https ? "https" : "http";
    req.headers["x-forwarded-host"] = publicUrl.host;
    req.headers["x-forwarded-port"] = String(publicPort);
    const cc = cacheFor(req.url);
    const setHeader = res.setHeader.bind(res);
    res.setHeader = (name, value) =>
      String(name).toLowerCase() === "cache-control" ? setHeader(name, cc) : setHeader(name, value);
    const writeHead = res.writeHead.bind(res);
    res.writeHead = (...args) => {
      const headers = args.find((a) => a && typeof a === "object" && !Array.isArray(a));
      if (headers) {
        for (const k of Object.keys(headers)) {
          if (k.toLowerCase() === "cache-control") delete headers[k];
        }
      }
      setHeader("Cache-Control", cc);
      return writeHead(...args);
    };
    handle(req, res);
  }).on("upgrade", (_req, socket) => socket.destroy())
    .listen(port, bind, () => console.log(`loki web on ${bind}:${port} for ${origin}`));
});
