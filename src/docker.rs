use crate::http::read_response;
use serde_json::{json, Value};
use std::io::Write;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Minimal Docker Engine API client speaking HTTP/1.1 over the daemon's
/// unix socket — replaces the `docker` CLI so the image needs no Docker
/// installation for container/service restarts.
pub struct DockerClient {
    socket: PathBuf,
}

/// How long `docker restart` waits for a graceful stop before killing the
/// container — parity with the CLI default.
const RESTART_TIMEOUT_SECS: u8 = 10;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(120);

/// Docker API errors that mean "no such object" for our call sites.
fn is_not_found(status: u16) -> bool {
    status == 404
}

impl DockerClient {
    pub fn new(socket: impl Into<PathBuf>) -> Self {
        Self {
            socket: socket.into(),
        }
    }

    pub fn socket_path(&self) -> &Path {
        &self.socket
    }

    /// Whether the daemon is reachable at all.
    pub fn is_available(&self) -> bool {
        self.request("GET", "/_ping", None)
            .map(|(status, _)| status == 200)
            .unwrap_or(false)
    }

    /// Restarts a container by name or ID; returns the full container ID.
    pub fn restart_container(&self, name: &str) -> Result<String, String> {
        let id = self
            .inspect_container_id(name)
            .map_err(|e| format!("container '{}': {}", name, e))?;

        let path = format!(
            "/containers/{}/restart?t={}",
            percent_encode(&id),
            RESTART_TIMEOUT_SECS
        );
        let (status, body) = self.request("POST", &path, None)?;
        if status == 204 {
            return Ok(id);
        }
        Err(self.api_error("restart container", status, &body))
    }

    fn inspect_container_id(&self, name: &str) -> Result<String, String> {
        let path = format!("/containers/{}/json", percent_encode(name));
        let (status, body) = self.request("GET", &path, None)?;
        match status {
            200 => serde_json::from_slice::<Value>(&body)
                .ok()
                .and_then(|v| v.get("Id").and_then(Value::as_str).map(str::to_string))
                .ok_or_else(|| "inspect response has no Id".to_string()),
            s if is_not_found(s) => Err("no such container".to_string()),
            s => Err(self.api_error("inspect container", s, &body)),
        }
    }

    /// Force-updates a Swarm service the way `docker service update --force`
    /// does: bumps the spec's ForceUpdate counter and posts it back at the
    /// current version. Returns the full service ID.
    pub fn force_update_service(&self, name: &str) -> Result<String, String> {
        let (id, version, spec) = self
            .inspect_service(name)
            .map_err(|e| format!("service '{}': {}", name, e))?;

        let mut spec = spec;
        bump_force_update(&mut spec);

        let path = format!(
            "/services/{}/update?version={}&registryAuthFrom=spec",
            percent_encode(&id),
            version
        );
        let body =
            serde_json::to_string(&spec).map_err(|e| format!("cannot serialize spec: {}", e))?;
        let (status, resp_body) = self.request("POST", &path, Some(&body))?;
        if status == 200 {
            return Ok(id);
        }
        Err(self.api_error("update service", status, &resp_body))
    }

    fn inspect_service(&self, name: &str) -> Result<(String, u64, Value), String> {
        let path = format!("/services/{}", percent_encode(name));
        let (status, body) = self.request("GET", &path, None)?;
        match status {
            200 => {
                let value: Value = serde_json::from_slice(&body)
                    .map_err(|e| format!("invalid inspect response: {}", e))?;
                let id = value
                    .get("ID")
                    .and_then(Value::as_str)
                    .ok_or("inspect response has no ID")?
                    .to_string();
                let version = value
                    .pointer("/Version/Index")
                    .and_then(Value::as_u64)
                    .ok_or("inspect response has no Version.Index")?;
                let spec = value
                    .get("Spec")
                    .cloned()
                    .ok_or("inspect response has no Spec")?;
                Ok((id, version, spec))
            }
            s if is_not_found(s) => Err("no such service".to_string()),
            s => Err(self.api_error("inspect service", s, &body)),
        }
    }

    /// Performs one request on a fresh connection (`Connection: close`).
    fn request(
        &self,
        method: &str,
        path: &str,
        body: Option<&str>,
    ) -> Result<(u16, Vec<u8>), String> {
        let mut stream = UnixStream::connect(&self.socket).map_err(|e| {
            format!(
                "cannot connect to docker socket {}: {}",
                self.socket.display(),
                e
            )
        })?;
        stream
            .set_read_timeout(Some(REQUEST_TIMEOUT))
            .map_err(|e| format!("cannot set read timeout: {}", e))?;
        stream
            .set_write_timeout(Some(REQUEST_TIMEOUT))
            .map_err(|e| format!("cannot set write timeout: {}", e))?;

        let body_bytes = body.map(str::as_bytes).unwrap_or(&[]);
        let head = format!(
            "{} {} HTTP/1.1\r\nHost: docker\r\nAccept: */*\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            method,
            path,
            body_bytes.len()
        );
        stream
            .write_all(head.as_bytes())
            .and_then(|_| stream.write_all(body_bytes))
            .and_then(|_| stream.flush())
            .map_err(|e| format!("cannot send request: {}", e))?;

        let response = read_response(&mut stream, 64 * 1024 * 1024)?;
        Ok((response.status, response.body))
    }

    fn api_error(&self, what: &str, status: u16, body: &[u8]) -> String {
        let message = serde_json::from_slice::<Value>(body)
            .ok()
            .and_then(|v| v.get("message").and_then(Value::as_str).map(str::to_string))
            .unwrap_or_else(|| String::from_utf8_lossy(body).trim().to_string());
        format!("cannot {} (HTTP {}): {}", what, status, message)
    }
}

/// Increments `Spec.TaskTemplate.ForceUpdate`, creating the path as needed.
fn bump_force_update(spec: &mut Value) {
    if !spec.is_object() {
        return;
    }
    let task_template = spec
        .as_object_mut()
        .expect("checked above")
        .entry("TaskTemplate")
        .or_insert_with(|| json!({}));
    if !task_template.is_object() {
        *task_template = json!({});
    }
    let next = task_template
        .get("ForceUpdate")
        .and_then(Value::as_u64)
        .unwrap_or(0)
        + 1;
    task_template["ForceUpdate"] = json!(next);
}

/// Percent-encodes everything outside the URL-unreserved set; container and
/// service names mostly consist of `[a-zA-Z0-9_.-]` but may contain `/` or
/// other characters in legacy setups.
fn percent_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char)
            }
            _ => out.push_str(&format!("%{:02X}", byte)),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Read};
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::sync::{Arc, Mutex};

    /// One recorded request: (method, path with query, body).
    type Recorded = Arc<Mutex<Vec<(String, String, String)>>>;

    /// Serves one request per connection with canned responses keyed by
    /// method+path prefix. Panics the test on unexpected requests. Returns
    /// the client and the log of requests it sent.
    fn spawn_fake_docker(script: Vec<(&str, &str, u16, String)>) -> (DockerClient, Recorded) {
        static DIR_SEQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let seq = DIR_SEQ.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let dir =
            std::env::temp_dir().join(format!("tcs-docker-test-{}-{}", std::process::id(), seq));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let socket_path = dir.join("docker.sock");
        let listener = UnixListener::bind(&socket_path).unwrap();

        let expected: Vec<(String, String, u16, String)> = script
            .into_iter()
            .map(|(m, p, s, b)| (m.to_string(), p.to_string(), s, b))
            .collect();
        let seen: Recorded = Arc::new(Mutex::new(Vec::new()));
        {
            let expected = Arc::new(expected);
            let seen = Arc::clone(&seen);
            std::thread::spawn(move || {
                for stream in listener.incoming().flatten() {
                    handle_conn(stream, &expected, &seen);
                }
            });
        }
        (DockerClient::new(&socket_path), seen)
    }

    fn handle_conn(
        mut stream: UnixStream,
        expected: &[(String, String, u16, String)],
        seen: &Mutex<Vec<(String, String, String)>>,
    ) {
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut request_line = String::new();
        reader.read_line(&mut request_line).unwrap();
        let mut parts = request_line.split_whitespace();
        let method = parts.next().unwrap_or("").to_string();
        let path = parts.next().unwrap_or("").to_string();
        let mut content_length = 0usize;
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            if line == "\r\n" || line.is_empty() {
                break;
            }
            if let Some((name, value)) = line.split_once(':') {
                if name.trim().eq_ignore_ascii_case("content-length") {
                    content_length = value.trim().parse().unwrap_or(0);
                }
            }
        }
        let mut body = vec![0u8; content_length];
        if content_length > 0 {
            reader.read_exact(&mut body).unwrap();
        }
        seen.lock().unwrap().push((
            method.clone(),
            path.clone(),
            String::from_utf8_lossy(&body).to_string(),
        ));

        let (_, _, status, response_body) = expected
            .iter()
            .find(|(m, p, _, _)| *m == method && path.starts_with(p.as_str()))
            .unwrap_or_else(|| panic!("unexpected request {} {}", method, path));
        let head = format!(
            "HTTP/1.1 {} {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            status,
            if *status == 204 { "No Content" } else { "OK" },
            response_body.len()
        );
        stream.write_all(head.as_bytes()).unwrap();
        stream.write_all(response_body.as_bytes()).unwrap();
    }

    fn wait_for_requests(seen: &Recorded, count: usize) -> Vec<(String, String, String)> {
        // The client calls are synchronous: by the time they return, the
        // server has already recorded the request (before responding), so a
        // few short retries are purely belt-and-braces.
        for _ in 0..50 {
            if let Ok(guard) = seen.lock() {
                if guard.len() >= count {
                    return guard.clone();
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        panic!("fake docker server did not receive {} requests", count);
    }

    #[test]
    fn pings_daemon() {
        let (client, _seen) = spawn_fake_docker(vec![("GET", "/_ping", 200, "OK".into())]);
        assert!(client.is_available());
    }

    #[test]
    fn availability_is_false_on_connection_error() {
        assert!(!DockerClient::new("/nonexistent/docker.sock").is_available());
    }

    #[test]
    fn restarts_container_by_name() {
        let (client, seen) = spawn_fake_docker(vec![
            (
                "GET",
                "/containers/web/json",
                200,
                r#"{"Id":"abc123fullid","Name":"/web"}"#.into(),
            ),
            (
                "POST",
                "/containers/abc123fullid/restart",
                204,
                String::new(),
            ),
        ]);
        let id = client.restart_container("web").unwrap();
        assert_eq!(id, "abc123fullid");

        let requests = wait_for_requests(&seen, 2);
        assert_eq!(requests[0].0, "GET");
        assert_eq!(requests[0].1, "/containers/web/json");
        assert_eq!(requests[1].1, "/containers/abc123fullid/restart?t=10");
    }

    #[test]
    fn restart_reports_missing_container() {
        let (client, _seen) = spawn_fake_docker(vec![(
            "GET",
            "/containers/nope/json",
            404,
            r#"{"message":"No such container: nope"}"#.into(),
        )]);
        let err = client.restart_container("nope").unwrap_err();
        assert!(err.contains("no such container"), "got: {}", err);
    }

    #[test]
    fn force_updates_service_with_bumped_counter() {
        let spec = json!({
            "Name": "svc",
            "TaskTemplate": {"ContainerSpec": {"Image": "nginx"}, "ForceUpdate": 3}
        });
        let (client, seen) = spawn_fake_docker(vec![
            (
                "GET",
                "/services/svc",
                200,
                format!(
                    r#"{{"ID":"svc-id-1","Version":{{"Index":42}},"Spec":{}}}"#,
                    spec.to_string()
                ),
            ),
            (
                "POST",
                "/services/svc-id-1/update",
                200,
                r#"{"Warnings":null}"#.into(),
            ),
        ]);
        let id = client.force_update_service("svc").unwrap();
        assert_eq!(id, "svc-id-1");

        let requests = wait_for_requests(&seen, 2);
        assert_eq!(requests[1].0, "POST");
        assert_eq!(
            requests[1].1,
            "/services/svc-id-1/update?version=42&registryAuthFrom=spec"
        );
        let sent_spec: Value = serde_json::from_str(&requests[1].2).unwrap();
        assert_eq!(
            sent_spec.pointer("/TaskTemplate/ForceUpdate"),
            Some(&json!(4))
        );
        assert_eq!(sent_spec.pointer("/Name"), Some(&json!("svc")));
    }

    #[test]
    fn force_update_creates_missing_counter() {
        let spec = json!({"Name": "svc2", "TaskTemplate": {"ContainerSpec": {"Image": "nginx"}}});
        let (client, seen) = spawn_fake_docker(vec![
            (
                "GET",
                "/services/svc2",
                200,
                format!(
                    r#"{{"ID":"svc2-id","Version":{{"Index":7}},"Spec":{}}}"#,
                    spec.to_string()
                ),
            ),
            ("POST", "/services/svc2-id/update", 200, "{}".into()),
        ]);
        client.force_update_service("svc2").unwrap();
        let requests = wait_for_requests(&seen, 2);
        let sent_spec: Value = serde_json::from_str(&requests[1].2).unwrap();
        assert_eq!(
            sent_spec.pointer("/TaskTemplate/ForceUpdate"),
            Some(&json!(1))
        );
    }

    #[test]
    fn percent_encoding() {
        assert_eq!(percent_encode("web-1_0.9~"), "web-1_0.9~");
        assert_eq!(percent_encode("a/b c"), "a%2Fb%20c");
    }
}
