//! A minimal JSON-RPC client for local regtest and a loopback Testnet node.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;
use zeroize::Zeroizing;

pub struct Rpc {
    addr: String,
    auth: Option<Zeroizing<String>>,
}

impl Rpc {
    pub fn new(addr: &str) -> Self {
        Rpc {
            addr: addr.to_string(),
            auth: None,
        }
    }

    /// A locally reachable public Testnet node. Refuse other chains before payment work.
    pub fn testnet() -> Result<Self, String> {
        use base64::Engine as _;
        let addr =
            std::env::var("LOKI_TESTNET_RPC").unwrap_or_else(|_| "127.0.0.1:18232".to_string());
        let socket: SocketAddr = addr.parse().map_err(|_| "invalid Testnet RPC address")?;
        if !socket.ip().is_loopback() {
            return Err("Testnet RPC must use a loopback address or local tunnel".into());
        }
        let cookie_path = std::env::var("LOKI_TESTNET_COOKIE_FILE")
            .map_err(|_| "set LOKI_TESTNET_COOKIE_FILE to the local node's RPC cookie")?;
        let metadata =
            std::fs::symlink_metadata(&cookie_path).map_err(|e| format!("RPC cookie: {e}"))?;
        if !metadata.file_type().is_file() {
            return Err("RPC cookie must be a regular file".into());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o077 != 0 {
                return Err("RPC cookie must be owner-only (mode 0600)".into());
            }
        }
        let cookie =
            Zeroizing::new(std::fs::read(cookie_path).map_err(|e| format!("RPC cookie: {e}"))?);
        let cookie = cookie.strip_suffix(b"\n").unwrap_or(&cookie);
        let mut halves = cookie.split(|b| *b == b':');
        if cookie.len() > 256
            || halves.next().is_none_or(|part| part.is_empty())
            || halves.next().is_none_or(|part| part.is_empty())
            || halves.next().is_some()
            || cookie.iter().any(|b| !b.is_ascii_graphic())
        {
            return Err("invalid RPC cookie".into());
        }
        let auth = Zeroizing::new(format!(
            "Authorization: Basic {}\r\n",
            base64::engine::general_purpose::STANDARD.encode(cookie)
        ));
        let rpc = Rpc {
            addr,
            auth: Some(auth),
        };
        if rpc.json("getblockhash", "[0]")?.as_str()
            != Some("05a60a92d99d85997cce3b87616c089f6124d7342af37106edc76126334a2c38")
        {
            return Err("RPC is not the public Zcash Testnet chain".into());
        }
        let info = rpc.json("getblockchaininfo", "[]")?;
        let height = info["blocks"].as_u64().unwrap_or(0);
        let headers = info["headers"].as_u64().unwrap_or(0);
        if info["chain"] != "test"
            || height < 4_465_026
            || headers < height
            || headers - height > 3
            || info["initial_block_download_complete"] == false
            || !info["consensus"]["nextblock"]
                .as_str()
                .is_some_and(|branch| {
                    branch
                        .trim_start_matches("0x")
                        .eq_ignore_ascii_case("77190ad9")
                })
        {
            return Err("Testnet node has not reached the NU7 branch".into());
        }
        let tree = rpc.json("z_gettreestate", &format!("[\"{height}\"]"))?;
        if tree["ironwood"]["commitments"]["finalState"]
            .as_str()
            .is_none()
        {
            return Err("Testnet node did not provide the Ironwood tree state".into());
        }
        Ok(rpc)
    }

    /// The regtest node this process should talk to.
    ///
    /// `LOKI_RPC` overrides the default so a sandboxed chain can run on its own port and
    /// cannot be confused with, or collide with, one started by the shell scripts. The
    /// default is unchanged, so every existing script behaves exactly as before.
    pub fn regtest() -> Self {
        Rpc::new(&std::env::var("LOKI_RPC").unwrap_or_else(|_| "127.0.0.1:18232".to_string()))
    }

    /// Issue a JSON-RPC call and return the `result` value.
    pub fn call(&self, method: &str, params: &str) -> Result<ciborium::value::Value, String> {
        let body = format!(r#"{{"jsonrpc":"2.0","id":1,"method":"{method}","params":{params}}}"#);
        let req = Zeroizing::new(format!(
            "POST / HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\n{}\
             Content-Length: {}\r\nConnection: close\r\n\r\n{}",
            self.addr,
            self.auth.as_deref().map(String::as_str).unwrap_or(""),
            body.len(),
            body
        ));

        let mut stream = TcpStream::connect(&self.addr).map_err(|e| format!("connect: {e}"))?;
        stream
            .set_read_timeout(Some(Duration::from_secs(15)))
            .map_err(|e| e.to_string())?;
        stream
            .set_write_timeout(Some(Duration::from_secs(15)))
            .map_err(|e| e.to_string())?;
        stream
            .write_all(req.as_bytes())
            .map_err(|e| format!("write: {e}"))?;
        let mut raw = String::new();
        stream
            .take(16 * 1024 * 1024 + 1)
            .read_to_string(&mut raw)
            .map_err(|e| format!("read: {e}"))?;
        if raw.len() > 16 * 1024 * 1024 {
            return Err(format!("{method}: RPC response exceeds 16 MiB"));
        }

        let (status, json) = raw.split_once("\r\n\r\n").ok_or("no response body")?;
        if !status.starts_with("HTTP/1.1 200 ") {
            return Err(format!("{method}: RPC returned an HTTP error"));
        }

        let v: serde_json::Value = serde_json::from_str(json).map_err(|e| format!("parse: {e}"))?;
        if let Some(e) = v.get("error") {
            if !e.is_null() {
                return Err(format!("{method}: {e}"));
            }
        }
        // Re-encode through serde_json; callers use the helper accessors below.
        Ok(ciborium::value::Value::Text(v["result"].to_string()))
    }

    /// `method` returning raw `serde_json::Value`, which is what the callers want.
    pub fn json(&self, method: &str, params: &str) -> Result<serde_json::Value, String> {
        match self.call(method, params)? {
            ciborium::value::Value::Text(t) => {
                serde_json::from_str(&t).map_err(|e| format!("reparse: {e}"))
            }
            _ => Err("unexpected".into()),
        }
    }
}
