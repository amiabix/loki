// lightwalletd over gRPC-web (communication/deploy/lightwalletd-grpcweb.sh), for the signer's
// chain scan. Only the two calls the scan needs; each message is hand-encoded protobuf.

const varint = (n) => { const out = []; for (; n >= 0x80; n = Math.floor(n / 0x80)) out.push((n % 0x80) | 0x80); out.push(n); return out; };
const blockId = (height) => [0x08, ...varint(height)]; // BlockID { height = 1 }
const field = (tag, bytes) => [tag, ...varint(bytes.length), ...bytes];

async function call(base, method, message) {
  const body = new Uint8Array(5 + message.length);
  new DataView(body.buffer).setUint32(1, message.length);
  body.set(message, 5);
  const res = await fetch(`${base.replace(/\/+$/, "")}/cash.z.wallet.sdk.rpc.CompactTxStreamer/${method}`, {
    method: "POST", headers: { "content-type": "application/grpc-web+proto", "x-grpc-web": "1" }, body,
  });
  if (!res.ok) throw new Error(`lightwalletd ${method}: HTTP ${res.status}`);
  return frames(new Uint8Array(await res.arrayBuffer()), method, res.headers);
}

// Split a gRPC-web body into its data messages; a non-zero grpc-status (in the trailer frame or
// the headers) is an error.
export function frames(buf, method = "call", headers = new Headers()) {
  const out = [];
  let status = headers.get("grpc-status"), message = headers.get("grpc-message");
  for (let i = 0; i < buf.length;) {
    if (i + 5 > buf.length) throw new Error(`lightwalletd ${method}: truncated frame`);
    const flag = buf[i], len = new DataView(buf.buffer, buf.byteOffset + i + 1, 4).getUint32(0);
    const data = buf.subarray(i + 5, i + 5 + len);
    if (data.length !== len) throw new Error(`lightwalletd ${method}: truncated frame`);
    if (flag & 0x80) {
      for (const line of new TextDecoder().decode(data).split("\r\n")) {
        const [k, ...v] = line.split(":");
        if (k === "grpc-status") status = v.join(":").trim();
        if (k === "grpc-message") message = v.join(":").trim();
      }
    } else out.push(data);
    i += 5 + len;
  }
  if (status !== null && status !== "0") throw new Error(`lightwalletd ${method}: grpc-status ${status} ${message ?? ""}`.trim());
  return out;
}

// The chain tip height (GetLatestBlock -> BlockID, height = field 1).
export async function latestHeight(base) {
  const [msg] = await call(base, "GetLatestBlock", []);
  if (!msg || msg[0] !== 0x08) throw new Error("lightwalletd GetLatestBlock: no height");
  let height = 0;
  for (let i = 1, mul = 1; i < msg.length; i++, mul *= 0x80) {
    height += (msg[i] & 0x7f) * mul;
    if (!(msg[i] & 0x80)) return height;
  }
  throw new Error("lightwalletd GetLatestBlock: bad height");
}

// Compact blocks start..end inclusive, each as its protobuf bytes.
export function blockRange(base, start, end) {
  return call(base, "GetBlockRange", [...field(0x0a, blockId(start)), ...field(0x12, blockId(end))]);
}
