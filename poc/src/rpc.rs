//! A minimal JSON-RPC client for the regtest node. Test-only, no auth, loopback.

use std::io::{Read, Write};
use std::net::TcpStream;

pub struct Rpc {
    addr: String,
}

impl Rpc {
    pub fn new(addr: &str) -> Self {
        Rpc {
            addr: addr.to_string(),
        }
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
        let req = format!(
            "POST / HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n{}",
            self.addr,
            body.len(),
            body
        );

        let mut stream = TcpStream::connect(&self.addr).map_err(|e| format!("connect: {e}"))?;
        stream
            .write_all(req.as_bytes())
            .map_err(|e| format!("write: {e}"))?;
        let mut raw = String::new();
        stream
            .read_to_string(&mut raw)
            .map_err(|e| format!("read: {e}"))?;

        let json = raw
            .split_once("\r\n\r\n")
            .map(|(_, b)| b)
            .ok_or("no response body")?;

        let v: serde_json::Value =
            serde_json::from_str(json).map_err(|e| format!("parse: {e}: {json}"))?;
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
