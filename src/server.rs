use crate::acme::CertEntry;
use crate::auth;
use crate::config::Config;
use crate::util::{err, log, now_unix};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Maximum accepted request size; legitimate requests are a few hundred
/// bytes.
const MAX_REQUEST_BYTES: usize = 16 * 1024;
/// Certificate state shared with the acme.json watcher.
pub type SharedCerts = Arc<Mutex<Vec<CertEntry>>>;

pub fn run(config: Config, certs: SharedCerts) {
    let addr = ("0.0.0.0", config.server_port);
    let listener = match TcpListener::bind(addr) {
        Ok(l) => l,
        Err(e) => {
            err(&format!(
                "cannot listen on port {}: {}",
                config.server_port, e
            ));
            std::process::exit(1);
        }
    };
    log(&format!(
        "Server mode: serving certificates on port {}",
        config.server_port
    ));

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let config = config.clone();
                let certs = Arc::clone(&certs);
                std::thread::spawn(move || handle_connection(stream, &config, &certs));
            }
            Err(e) => err(&format!("accept failed: {}", e)),
        }
    }
}

fn handle_connection(mut stream: TcpStream, config: &Config, certs: &SharedCerts) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
    let request = match read_request(&mut stream) {
        Ok(Some(r)) => r,
        Ok(None) => return,
        Err(e) => {
            let _ = write_response(&mut stream, 400, "text/plain", e.as_bytes());
            return;
        }
    };

    let (method, path, authorization) = request;

    match (method.as_str(), path.as_str()) {
        ("GET", "/healthz") | ("HEAD", "/healthz") => {
            let _ = write_response(&mut stream, 200, "text/plain", b"ok\n");
        }
        ("GET", "/v1/certs") => {
            let authorized = authorization
                .as_deref()
                .map(|h| auth::verify_header(&config.server_key, h, now_unix() as i64))
                .unwrap_or(false);
            if !authorized {
                log("Rejected unauthenticated request for /v1/certs");
                let _ = write_response(&mut stream, 401, "text/plain", b"unauthorized\n");
                return;
            }
            let payload = {
                let snapshot = certs.lock().unwrap_or_else(|p| p.into_inner());
                #[derive(serde::Serialize)]
                struct Payload<'a> {
                    certificates: &'a [CertEntry],
                }
                serde_json::to_vec(&Payload {
                    certificates: &snapshot,
                })
                .unwrap_or_default()
            };
            let _ = write_response(&mut stream, 200, "application/json", &payload);
        }
        _ => {
            let _ = write_response(&mut stream, 404, "text/plain", b"not found\n");
        }
    }
}

/// A parsed request head: (method, path, Authorization header value).
type Request = (String, String, Option<String>);

fn read_request(stream: &mut TcpStream) -> Result<Option<Request>, String> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    loop {
        if let Some(head_end) = find_head_end(&buf) {
            return parse_head(&buf[..head_end]).map(Some);
        }
        if buf.len() > MAX_REQUEST_BYTES {
            return Err("request too large".to_string());
        }
        let n = stream
            .read(&mut chunk)
            .map_err(|e| format!("read failed: {}", e))?;
        if n == 0 {
            return if buf.is_empty() {
                Ok(None)
            } else {
                Err("connection closed mid-request".to_string())
            };
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

fn find_head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
}

fn parse_head(head: &[u8]) -> Result<Request, String> {
    let text = std::str::from_utf8(head).map_err(|_| "request is not UTF-8".to_string())?;
    let mut lines = text.split("\r\n");
    let request_line = lines.next().ok_or("empty request")?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next().ok_or("missing method")?.to_string();
    let target = parts.next().ok_or("missing path")?.to_string();
    let path = target.split('?').next().unwrap_or("").to_string();

    let mut authorization = None;
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            if name.trim().eq_ignore_ascii_case("authorization") {
                authorization = Some(value.trim().to_string());
            }
        }
    }
    Ok((method, path, authorization))
}

fn write_response(
    stream: &mut TcpStream,
    status: u16,
    content_type: &str,
    body: &[u8],
) -> std::io::Result<()> {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        _ => "Internal Server Error",
    };
    let head = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        status,
        reason,
        content_type,
        body.len()
    );
    stream.write_all(head.as_bytes())?;
    stream.write_all(body)?;
    stream.flush()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth;

    const KEY: &str = "unit-test-key";

    fn get(port: u16, path: &str, key: Option<&str>) -> (u16, String) {
        use std::io::Write as _;
        let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
        let auth_header = key
            .map(|k| format!("Authorization: {}\r\n", auth::header_value(k)))
            .unwrap_or_default();
        write!(
            stream,
            "GET {} HTTP/1.1\r\nHost: localhost\r\n{}Connection: close\r\n\r\n",
            path, auth_header
        )
        .unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();
        let status: u16 = response
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let body = response.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
        (status, body)
    }

    #[test]
    fn healthz_is_public() {
        let port = spawn_test_server(vec![], KEY);
        let (status, body) = get(port, "/healthz", None);
        assert_eq!(status, 200);
        assert_eq!(body.trim(), "ok");
    }

    #[test]
    fn certs_require_valid_auth() {
        let certs = vec![CertEntry {
            domain: "example.com".to_string(),
            certificate: "CERT".to_string(),
            key: "KEY".to_string(),
        }];
        let port = spawn_test_server(certs, KEY);

        let (status, _) = get(port, "/v1/certs", None);
        assert_eq!(status, 401);

        let (status, _) = get(port, "/v1/certs", Some("wrong-key"));
        assert_eq!(status, 401);

        let (status, body) = get(port, "/v1/certs", Some(KEY));
        assert_eq!(status, 200);
        assert!(body.contains("\"domain\":\"example.com\""));
        assert!(body.contains("\"certificate\":\"CERT\""));
    }

    #[test]
    fn unknown_paths_are_404() {
        let port = spawn_test_server(vec![], KEY);
        let (status, _) = get(port, "/nope", None);
        assert_eq!(status, 404);
    }
}

/// Spawns a one-connection-per-thread test server on an ephemeral port.
#[cfg(test)]
pub fn spawn_test_server(certs: Vec<CertEntry>, key: &str) -> u16 {
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let key = key.to_string();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let config = Config {
                server_key: key.clone(),
                ..crate::config::test_config()
            };
            let shared: SharedCerts = Arc::new(Mutex::new(certs.clone()));
            handle_connection(stream, &config, &shared);
        }
    });
    port
}
