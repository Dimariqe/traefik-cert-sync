use crate::acme::CertEntry;
use crate::auth;
use crate::config::Config;
use crate::http::read_response;
use crate::util::{err, log};
use std::io::Write;
use std::net::TcpStream;
use std::time::Duration;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const READ_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_RESPONSE_BYTES: usize = 64 * 1024 * 1024;

#[derive(serde::Deserialize)]
struct Payload {
    #[serde(default)]
    certificates: Vec<CertEntry>,
}

/// Fetches the certificate list from the server once.
pub fn fetch(config: &Config) -> Result<Vec<CertEntry>, String> {
    let mut stream = TcpStream::connect(config.agent_server_address.trim())
        .map_err(|e| format!("cannot connect to {}: {}", config.agent_server_address, e))?;
    stream
        .set_read_timeout(Some(READ_TIMEOUT))
        .map_err(|e| format!("cannot set read timeout: {}", e))?;
    stream
        .set_write_timeout(Some(CONNECT_TIMEOUT))
        .map_err(|e| format!("cannot set write timeout: {}", e))?;

    let request = format!(
        "GET /v1/certs HTTP/1.1\r\nHost: {}\r\nAuthorization: {}\r\nConnection: close\r\n\r\n",
        config.agent_server_address,
        auth::header_value(&config.agent_key)
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|e| format!("cannot send request: {}", e))?;

    let response = read_response(&mut stream, MAX_RESPONSE_BYTES)?;
    match response.status {
        200 => {
            let payload: Payload = serde_json::from_slice(&response.body)
                .map_err(|e| format!("invalid payload: {}", e))?;
            Ok(payload.certificates)
        }
        401 => Err("server rejected the AGENT_KEY (unauthorized)".to_string()),
        404 => Err("server does not serve /v1/certs (version mismatch?)".to_string()),
        other => Err(format!("unexpected response status {}", other)),
    }
}

/// Agent main loop: poll, sync, report health, sleep.
pub fn run(config: Config, output_dir: &std::path::Path) -> ! {
    loop {
        match fetch(&config) {
            Ok(certificates) => {
                log(&format!(
                    "Fetched {} certificate(s) from {}",
                    certificates.len(),
                    config.agent_server_address
                ));
                crate::dump::sync(&certificates, &config, output_dir);
                crate::status::write_ok_to(&config.status_file, "agent");
            }
            Err(e) => err(&format!(
                "polling {} failed: {}",
                config.agent_server_address, e
            )),
        }
        std::thread::sleep(Duration::from_secs(config.agent_poll_interval.max(1)));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config_for(addr: &str) -> Config {
        Config {
            agent_server_address: addr.to_string(),
            agent_key: "unit-test-key".to_string(),
            ..crate::config::test_config()
        }
    }

    #[test]
    fn fetches_from_live_server() {
        let certs = vec![CertEntry {
            domain: "example.com".to_string(),
            certificate: "CERT".to_string(),
            key: "KEY".to_string(),
        }];
        let port = crate::server::spawn_test_server(certs, "unit-test-key");
        let config = config_for(&format!("127.0.0.1:{}", port));
        let fetched = fetch(&config).unwrap();
        assert_eq!(fetched.len(), 1);
        assert_eq!(fetched[0].domain, "example.com");
    }

    #[test]
    fn reports_wrong_key_as_unauthorized() {
        let port = crate::server::spawn_test_server(vec![], "server-key");
        let config = config_for(&format!("127.0.0.1:{}", port));
        let error = fetch(&config).unwrap_err();
        assert!(error.contains("unauthorized"), "got: {}", error);
    }
}
