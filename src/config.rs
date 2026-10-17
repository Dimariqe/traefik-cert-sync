use std::env;
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mode {
    /// Watch the local acme.json and dump certificates (default).
    Local,
    /// Local behaviour plus serving certificates to agents over HTTP.
    Server,
    /// Poll a remote server for certificates instead of reading acme.json.
    Agent,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub mode: Mode,

    // Source
    pub acme_file_path: PathBuf,

    // Destination (default /output, as mounted by the Docker images)
    pub output_dir: PathBuf,

    // Where the daemon writes its health status for --healthcheck
    pub status_file: PathBuf,

    // Output file naming
    pub certificate_file_name: String,
    pub certificate_file_ext: String,
    pub privatekey_file_name: String,
    pub privatekey_file_ext: String,
    pub rsakey_file_name: String,
    pub rsakey_file_ext: String,

    // Domain selection
    pub domains: Vec<String>,

    // Post-processing
    pub combined_pem: Option<String>,
    pub combine_pkcs12: bool,
    pub pkcs12_password: Option<String>,
    pub convert_keys_to_rsa: bool,
    pub override_uid: Option<u32>,
    pub override_gid: Option<u32>,
    pub posthook_file_path: PathBuf,

    // Container/service restarts
    pub containers: Vec<String>,
    pub services: Vec<String>,

    // Server mode
    pub server_port: u16,
    pub server_key: String,

    // Agent mode
    pub agent_server_address: String,
    pub agent_key: String,
    pub agent_poll_interval: u64,

    // Docker daemon (for container/service restarts)
    pub docker_socket: PathBuf,
}

fn env_str(key: &str, default: &str) -> String {
    match env::var(key) {
        Ok(v) if !v.trim().is_empty() => v,
        _ => default.to_string(),
    }
}

fn env_opt(key: &str) -> Option<String> {
    match env::var(key) {
        Ok(v) if !v.trim().is_empty() => Some(v),
        _ => None,
    }
}

fn env_bool(key: &str) -> bool {
    matches!(
        env::var(key)
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase()
            .as_str(),
        "true" | "yes" | "1" | "on"
    )
}

/// Normalizes `host` or `host:port` into `host:port`, defaulting the port to
/// SERVER_PORT's default. Bracketed IPv6 addresses are kept intact.
pub fn normalize_address(addr: &str, default_port: u16) -> String {
    if addr.starts_with('[') {
        if let Some(end) = addr.find(']') {
            if addr.len() > end + 1 && addr.as_bytes()[end + 1] == b':' {
                return addr.to_string();
            }
            return format!("{}:{}", addr, default_port);
        }
        return format!("{}:{}", addr, default_port);
    }
    if addr.matches(':').count() > 1 {
        // Bare IPv6 address without port.
        return format!("[{}]:{}", addr, default_port);
    }
    if addr.contains(':') {
        addr.to_string()
    } else {
        format!("{}:{}", addr, default_port)
    }
}

impl Config {
    pub fn from_env() -> Result<Self, String> {
        let server_mode = env_bool("SERVER_MODE");
        let agent_mode = env_bool("AGENT_MODE");

        let mode = match (server_mode, agent_mode) {
            (true, true) => {
                return Err("SERVER_MODE and AGENT_MODE are mutually exclusive".to_string())
            }
            (true, false) => Mode::Server,
            (false, true) => Mode::Agent,
            (false, false) => Mode::Local,
        };

        let acme_file_path = PathBuf::from(env_str("ACME_FILE_PATH", "/traefik/acme.json"));
        let output_dir = PathBuf::from(env_str("OUTPUT_DIR", "/output"));
        let status_file = PathBuf::from(env_str(
            "TCS_STATUS_FILE",
            "/tmp/traefik-cert-sync-status.json",
        ));

        let certificate_file_name = env_str("CERTIFICATE_FILE_NAME", "cert");
        let certificate_file_ext = env_str("CERTIFICATE_FILE_EXT", ".pem");
        let privatekey_file_name = env_str("PRIVATE_KEY_FILE_NAME", "key");
        let privatekey_file_ext = env_str("PRIVATE_KEY_FILE_EXT", ".pem");
        let rsakey_file_name = env_str("RSA_KEY_FILE_NAME", "rsakey");
        let rsakey_file_ext = env_str("RSA_KEY_FILE_EXT", ".pem");

        let domains = env_opt("DOMAIN")
            .map(|d| {
                d.split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_string)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        let combined_pem = env_opt("COMBINED_PEM").filter(|v| {
            if v.ends_with(".pem") {
                true
            } else {
                eprintln!(
                    "[warn] COMBINED_PEM={} does not end with .pem, omitting PEM combining step",
                    v
                );
                false
            }
        });

        let combine_pkcs12 = env_bool("COMBINE_PKCS12");
        let pkcs12_password = match env_opt("PKCS12_PASSWORD") {
            Some(p) => Some(p),
            None => env_opt("PKCS12_PASSWORD_FILE").and_then(|path| {
                std::fs::read_to_string(path.trim())
                    .map(|s| s.trim().to_string())
                    .map_err(|e| {
                        eprintln!("[warn] cannot read PKCS12_PASSWORD_FILE={}: {}", path, e)
                    })
                    .ok()
            }),
        };
        let convert_keys_to_rsa = env_bool("CONVERT_KEYS_TO_RSA");

        let override_uid = env_opt("OVERRIDE_UID");
        let override_gid = env_opt("OVERRIDE_GID");
        let (override_uid, override_gid) = match (override_uid, override_gid) {
            (Some(u), Some(g)) => match (u.parse::<u32>(), g.parse::<u32>()) {
                (Ok(u), Ok(g)) => (Some(u), Some(g)),
                _ => {
                    eprintln!(
                        "[warn] OVERRIDE_UID={}/OVERRIDE_GID={} is not a valid integer pair, skipping ownership change",
                        u, g
                    );
                    (None, None)
                }
            },
            _ => (None, None),
        };

        let posthook_file_path = PathBuf::from(env_str("POST_HOOK_FILE_PATH", "/hook/hook.sh"));

        let server_port = match env::var("SERVER_PORT") {
            Ok(v) if !v.trim().is_empty() => v
                .trim()
                .parse::<u16>()
                .map_err(|_| format!("SERVER_PORT={} is not a valid port number", v))?,
            _ => 3556,
        };
        let server_key = env_str("SERVER_KEY", "");

        let agent_server_address = match env_opt("AGENT_SERVER_ADDRESS") {
            Some(a) => normalize_address(&a, server_port),
            None => String::new(),
        };
        let agent_key = env_str("AGENT_KEY", "");
        let docker_socket = PathBuf::from(env_str("DOCKER_SOCKET", "/var/run/docker.sock"));
        let agent_poll_interval = match env::var("AGENT_POLL_INTERVAL") {
            Ok(v) if !v.trim().is_empty() => v.trim().parse::<u64>().map_err(|_| {
                format!("AGENT_POLL_INTERVAL={} is not a valid number of seconds", v)
            })?,
            _ => 30,
        };

        match mode {
            Mode::Server => {
                if server_key.is_empty() {
                    return Err("SERVER_MODE is enabled but SERVER_KEY is empty".to_string());
                }
            }
            Mode::Agent => {
                if agent_server_address.is_empty() {
                    return Err(
                        "AGENT_MODE is enabled but AGENT_SERVER_ADDRESS is empty".to_string()
                    );
                }
                if agent_key.is_empty() {
                    return Err("AGENT_MODE is enabled but AGENT_KEY is empty".to_string());
                }
            }
            Mode::Local => {}
        }

        Ok(Self {
            mode,
            acme_file_path,
            output_dir,
            status_file,
            certificate_file_name,
            certificate_file_ext,
            privatekey_file_name,
            privatekey_file_ext,
            rsakey_file_name,
            rsakey_file_ext,
            domains,
            combined_pem,
            combine_pkcs12,
            pkcs12_password,
            convert_keys_to_rsa,
            override_uid,
            override_gid,
            posthook_file_path,
            containers: Vec::new(),
            services: Vec::new(),
            server_port,
            server_key,
            agent_server_address,
            agent_key,
            agent_poll_interval,
            docker_socket,
        })
    }

    pub fn certificate_file(&self) -> String {
        format!(
            "{}{}",
            self.certificate_file_name, self.certificate_file_ext
        )
    }

    pub fn privatekey_file(&self) -> String {
        format!("{}{}", self.privatekey_file_name, self.privatekey_file_ext)
    }

    pub fn rsakey_file(&self) -> String {
        format!("{}{}", self.rsakey_file_name, self.rsakey_file_ext)
    }
}

/// A config suitable for unit tests: defaults, no reliance on the ambient
/// environment.
#[cfg(test)]
pub fn test_config() -> Config {
    Config {
        mode: Mode::Local,
        acme_file_path: PathBuf::from("/traefik/acme.json"),
        output_dir: PathBuf::from("/output"),
        status_file: PathBuf::from("/tmp/traefik-cert-sync-status.json"),
        certificate_file_name: "cert".to_string(),
        certificate_file_ext: ".pem".to_string(),
        privatekey_file_name: "key".to_string(),
        privatekey_file_ext: ".pem".to_string(),
        rsakey_file_name: "rsakey".to_string(),
        rsakey_file_ext: ".pem".to_string(),
        domains: vec![],
        combined_pem: None,
        combine_pkcs12: false,
        pkcs12_password: None,
        convert_keys_to_rsa: false,
        override_uid: None,
        override_gid: None,
        posthook_file_path: PathBuf::from("/hook/hook.sh"),
        containers: vec![],
        services: vec![],
        server_port: 3556,
        server_key: String::new(),
        agent_server_address: String::new(),
        agent_key: String::new(),
        agent_poll_interval: 30,
        docker_socket: PathBuf::from("/var/run/docker.sock"),
    }
}
