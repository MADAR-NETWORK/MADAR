//! JSON-RPC transport over HTTP (`std::net` only) with a connect timeout, an overall timeout and a response size cap, behind a replaceable `Transport`.

use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

pub trait Transport {
    fn call(&self, method: &str, params: Value) -> Result<Value, String>;
}

#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub connect: Duration,
    pub total: Duration,
    pub max_response_bytes: usize,
}

pub const DEFAULT_LIMITS: Limits = Limits {
    connect: Duration::from_secs(5),
    total: Duration::from_secs(30),
    max_response_bytes: 8 * 1024 * 1024,
};

pub struct HttpRpc {
    addr: String,
    limits: Limits,
}

impl HttpRpc {
    /// `addr` in the form `host:port` (plain HTTP; no TLS — hence Loopback or a trusted tunnel is recommended).
    pub fn new(addr: &str) -> Self {
        HttpRpc {
            addr: addr
                .trim_start_matches("http://")
                .trim_end_matches('/')
                .to_string(),
            limits: DEFAULT_LIMITS,
        }
    }

    pub fn is_loopback(&self) -> bool {
        self.addr
            .to_socket_addrs()
            .ok()
            .and_then(|mut it| it.next())
            .map_or(false, |a| a.ip().is_loopback())
    }

    #[cfg(test)]
    pub fn with_limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }
}

impl Transport for HttpRpc {
    fn call(&self, method: &str, params: Value) -> Result<Value, String> {
        let started = Instant::now();
        let body =
            json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).to_string();
        let request = format!(
            "POST / HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            self.addr,
            body.len()
        );
        let sock = self
            .addr
            .to_socket_addrs()
            .map_err(|e| format!("Invalid RPC address ({}): {e}", self.addr))?
            .next()
            .ok_or_else(|| format!("RPC address resolved to nothing: {}", self.addr))?;
        let mut stream = TcpStream::connect_timeout(&sock, self.limits.connect).map_err(|e| {
            format!(
                "Could not connect to the node's RPC at {} ({e}) — is the node running?",
                self.addr
            )
        })?;
        stream
            .set_write_timeout(Some(self.limits.total))
            .map_err(|e| e.to_string())?;
        stream
            .write_all(request.as_bytes())
            .map_err(|e| e.to_string())?;

        let mut raw = Vec::new();
        let mut chunk = [0u8; 8192];
        loop {
            let left = self
                .limits
                .total
                .checked_sub(started.elapsed())
                .filter(|d| !d.is_zero())
                .ok_or("Timed out waiting for the node's response")?;
            stream
                .set_read_timeout(Some(left))
                .map_err(|e| e.to_string())?;
            match stream.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => {
                    raw.extend_from_slice(&chunk[..n]);
                    if raw.len() > self.limits.max_response_bytes {
                        return Err("The node's response is larger than the allowed limit".into());
                    }
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    return Err("Timed out waiting for the node's response".into())
                }
                Err(e) => return Err(e.to_string()),
            }
        }
        let text = String::from_utf8_lossy(&raw);
        let (_, payload) = text
            .split_once("\r\n\r\n")
            .ok_or("Invalid HTTP response from the node")?;
        let v: Value = serde_json::from_str(payload.trim())
            .map_err(|_| "Invalid JSON-RPC response from the node".to_string())?;
        if let Some(err) = v.get("error") {
            let msg = err
                .get("message")
                .and_then(|m| m.as_str())
                .unwrap_or("RPC error");
            let data = err.get("data").and_then(|d| d.as_str()).unwrap_or("");
            return Err(if data.is_empty() {
                msg.to_string()
            } else {
                format!("{msg}: {data}")
            });
        }
        v.get("result")
            .cloned()
            .ok_or_else(|| "Response has no result".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    fn serve(reply: impl FnOnce(&mut TcpStream) + Send + 'static) -> String {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap().to_string();
        std::thread::spawn(move || {
            if let Ok((mut s, _)) = l.accept() {
                let mut b = [0u8; 4096];
                let _ = s.read(&mut b);
                reply(&mut s);
            }
        });
        addr
    }
    fn tight() -> Limits {
        Limits {
            connect: Duration::from_millis(500),
            total: Duration::from_millis(700),
            max_response_bytes: 2048,
        }
    }

    #[test]
    fn result_error_timeout_and_oversize_are_all_handled() {
        let ok = serve(|s| {
            let b = r#"{"jsonrpc":"2.0","id":1,"result":"0x1"}"#;
            let _ = write!(
                s,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{b}",
                b.len()
            );
        });
        assert_eq!(
            HttpRpc::new(&ok)
                .with_limits(tight())
                .call("m", json!([]))
                .unwrap(),
            json!("0x1")
        );

        let err = serve(|s| {
            let b = r#"{"jsonrpc":"2.0","id":1,"error":{"code":1010,"message":"Invalid Transaction","data":"Custom error: 5"}}"#;
            let _ = write!(
                s,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{b}",
                b.len()
            );
        });
        let e = HttpRpc::new(&err)
            .with_limits(tight())
            .call("m", json!([]))
            .unwrap_err();
        assert!(
            e.contains("Invalid Transaction") && e.contains("Custom error"),
            "{e}"
        );

        let silent = serve(|_| std::thread::sleep(Duration::from_secs(2)));
        let began = Instant::now();
        assert!(HttpRpc::new(&silent)
            .with_limits(tight())
            .call("m", json!([]))
            .is_err());
        assert!(began.elapsed() < Duration::from_secs(2));

        let big = serve(|s| {
            let _ = s.write_all(b"HTTP/1.1 200 OK\r\n\r\n");
            let _ = s.write_all(&vec![b'x'; 64 * 1024]);
        });
        assert!(HttpRpc::new(&big)
            .with_limits(tight())
            .call("m", json!([]))
            .unwrap_err()
            .contains("larger"));
        assert!(
            HttpRpc::new("127.0.0.1:1").is_loopback()
                && !HttpRpc::new("8.8.8.8:9944").is_loopback()
        );
    }
}
