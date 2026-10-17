use crate::acme::CertEntry;
use crate::config::Config;
use crate::util::{err, log};
use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Where a certificate's files land inside the output directory.
enum Target {
    /// <output>/<domain>/<cert|key>
    Subdir(PathBuf),
    /// <output>/<cert|key>
    Flat,
}

/// Writes certificates that differ from what is already in the output
/// directory and, when anything changed, runs the post-processing chain
/// (PKCS12/PEM combining, RSA conversion, ownership, post-hook, restarts).
/// Returns whether anything changed.
pub fn sync(certs: &[CertEntry], config: &Config, output_dir: &Path) -> bool {
    let selected = select(certs, config);

    let mut changed = false;
    for entry in selected {
        let (cert_path, key_path) = match target_for(&entry.domain, config, output_dir) {
            Target::Subdir(dir) => (
                dir.join(config.certificate_file()),
                dir.join(config.privatekey_file()),
            ),
            Target::Flat => (
                output_dir.join(config.certificate_file()),
                output_dir.join(config.privatekey_file()),
            ),
        };

        if let Some(dir) = cert_path.parent() {
            if let Err(e) = fs::create_dir_all(dir) {
                err(&format!(
                    "cannot create output directory {}: {}",
                    dir.display(),
                    e
                ));
                continue;
            }
        }

        let cert_changed = write_if_differs(&cert_path, entry.certificate.as_bytes(), 0o644);
        let key_changed = write_if_differs(&key_path, entry.key.as_bytes(), 0o600);
        if cert_changed || key_changed {
            log(&format!(
                "Certificate or key for '{}' differ, updating",
                entry.domain
            ));
            changed = true;
        } else {
            log(&format!(
                "Certificate and key for '{}' still up to date, doing nothing",
                entry.domain
            ));
        }
    }

    if changed {
        combine_pkcs12(config, output_dir);
        combine_pem(config, output_dir);
        convert_keys_to_rsa(config, output_dir);
        change_ownership(config, output_dir);
        post_hook(config);
        restart_containers(config);
        restart_services(config);
    }

    changed
}

/// Applies DOMAIN selection with dump.sh semantics: no DOMAIN means
/// everything, one domain means flat output for it, several domains mean
/// per-domain subdirectories.
fn select<'a>(certs: &'a [CertEntry], config: &'a Config) -> Vec<&'a CertEntry> {
    if config.domains.is_empty() {
        return certs.iter().collect();
    }
    for wanted in &config.domains {
        if !certs.iter().any(|c| &c.domain == wanted) {
            err(&format!(
                "Certificates for domain '{}' don't exist. Omitting...",
                wanted
            ));
        }
    }
    certs
        .iter()
        .filter(|c| config.domains.contains(&c.domain))
        .collect()
}

fn target_for(domain: &str, config: &Config, output_dir: &Path) -> Target {
    if config.is_flat() {
        Target::Flat
    } else {
        Target::Subdir(output_dir.join(domain))
    }
}

impl Config {
    /// dump.sh writes a single selected domain straight into the output root;
    /// no DOMAIN or several domains mean per-domain subdirectories.
    pub fn is_flat(&self) -> bool {
        self.domains.len() == 1
    }
}

/// Atomically writes `data` to `path` unless the file already holds exactly
/// that content. Returns whether the file was (re)written.
fn write_if_differs(path: &Path, data: &[u8], mode: u32) -> bool {
    if let Ok(existing) = fs::read(path) {
        if existing == data {
            return false;
        }
    }

    let tmp = path.with_file_name(format!(
        ".{}.tmp",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("file")
    ));
    let write_out = |p: &Path| -> std::io::Result<()> {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(p)?;
        f.write_all(data)?;
        f.sync_all()?;
        let mut perms = fs::metadata(p)?.permissions();
        perms.set_mode(mode);
        fs::set_permissions(p, perms)?;
        Ok(())
    };

    if let Err(e) = write_out(&tmp).and_then(|_| fs::rename(&tmp, path)) {
        err(&format!("cannot write {}: {}", path.display(), e));
        let _ = fs::remove_file(&tmp);
    }
    true
}

/// Subdirectories of the output dir that contain dumped certificates (i.e.
/// every directory, in line with the bash implementation's glob).
fn output_subdirs(output_dir: &Path) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if let Ok(entries) = fs::read_dir(output_dir) {
        for entry in entries.flatten() {
            if let Ok(file_type) = entry.file_type() {
                if file_type.is_dir() {
                    dirs.push(entry.path());
                }
            }
        }
    }
    dirs
}

fn combine_pem(config: &Config, output_dir: &Path) {
    let Some(combined) = &config.combined_pem else {
        return;
    };

    if config.is_flat() {
        let cert = output_dir.join(config.certificate_file());
        let key = output_dir.join(config.privatekey_file());
        if cert.is_file() && key.is_file() {
            log("Combining key and cert to single PEM");
            concat_to(&cert, &key, &output_dir.join(combined));
        }
        return;
    }

    for dir in output_subdirs(output_dir) {
        let cert = dir.join(config.certificate_file());
        let key = dir.join(config.privatekey_file());
        if cert.is_file() && key.is_file() {
            log(&format!(
                "Combining key and certificate to single PEM with name {}",
                dir.join(combined).display()
            ));
            concat_to(&cert, &key, &dir.join(combined));
        }
    }
}

fn concat_to(first: &Path, second: &Path, dest: &Path) {
    match fs::read(first).and_then(|a| Ok((a, fs::read(second)?))) {
        Ok((a, b)) => {
            let mut data = a;
            data.extend_from_slice(&b);
            if let Err(e) = fs::write(dest, data) {
                err(&format!("cannot write {}: {}", dest.display(), e));
            }
        }
        Err(e) => err(&format!(
            "cannot read {} / {}: {}",
            first.display(),
            second.display(),
            e
        )),
    }
}

fn combine_pkcs12(config: &Config, output_dir: &Path) {
    if !config.combine_pkcs12 {
        return;
    }

    let run = |cert: &Path, key: &Path, out: &Path| {
        log(&format!(
            "Combining key and cert to PKCS12 file {}",
            out.display()
        ));
        let mut cmd = Command::new("openssl");
        cmd.args(["pkcs12", "-export"])
            .arg("-in")
            .arg(cert)
            .arg("-inkey")
            .arg(key)
            .arg("-out")
            .arg(out);
        match &config.pkcs12_password {
            Some(pw) => {
                cmd.arg("-password").arg(format!("pass:{}", pw));
            }
            None => {
                cmd.arg("-passout").arg("pass:");
            }
        }
        match cmd.output() {
            Ok(o) if o.status.success() => {}
            Ok(o) => err(&format!(
                "openssl pkcs12 failed for {}: {}",
                out.display(),
                String::from_utf8_lossy(&o.stderr).trim()
            )),
            Err(e) => err(&format!("cannot run openssl: {}", e)),
        }
    };

    if config.is_flat() {
        let cert = output_dir.join(config.certificate_file());
        let key = output_dir.join(config.privatekey_file());
        if cert.is_file() && key.is_file() {
            run(&cert, &key, &output_dir.join("cert.p12"));
        }
        return;
    }

    for dir in output_subdirs(output_dir) {
        let cert = dir.join(config.certificate_file());
        let key = dir.join(config.privatekey_file());
        if cert.is_file() && key.is_file() {
            run(&cert, &key, &dir.join("cert.p12"));
        }
    }
}

fn convert_keys_to_rsa(config: &Config, output_dir: &Path) {
    if !config.convert_keys_to_rsa {
        return;
    }

    let run = |key: &Path, out: &Path| {
        log(&format!("Converting key to RSA key file {}", out.display()));
        match Command::new("openssl")
            .args(["rsa", "-in"])
            .arg(key)
            .arg("-out")
            .arg(out)
            .output()
        {
            Ok(o) if o.status.success() => {}
            Ok(o) => err(&format!(
                "openssl rsa failed for {}: {}",
                out.display(),
                String::from_utf8_lossy(&o.stderr).trim()
            )),
            Err(e) => err(&format!("cannot run openssl: {}", e)),
        }
    };

    if config.is_flat() {
        let key = output_dir.join(config.privatekey_file());
        if key.is_file() {
            run(&key, &output_dir.join(config.rsakey_file()));
        }
        return;
    }

    for dir in output_subdirs(output_dir) {
        let key = dir.join(config.privatekey_file());
        if key.is_file() {
            run(&key, &dir.join(config.rsakey_file()));
        }
    }
}

fn change_ownership(config: &Config, output_dir: &Path) {
    let (Some(uid), Some(gid)) = (config.override_uid, config.override_gid) else {
        return;
    };

    log("Changing ownership of certificates and keys");
    let suffixes = [
        config.certificate_file_ext.clone(),
        config.privatekey_file_ext.clone(),
        ".p12".to_string(),
        config.rsakey_file_ext.clone(),
    ];
    walk_files(output_dir, &mut |path| {
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if !suffixes.iter().any(|s| name.ends_with(s.as_str())) {
            return;
        }
        let _ = std::os::unix::fs::chown(path, Some(uid), Some(gid));
        if let Ok(meta) = fs::metadata(path) {
            let mut perms = meta.permissions();
            let mode = perms.mode() | 0o40; // g+r
            perms.set_mode(mode);
            let _ = fs::set_permissions(path, perms);
        }
    });
}

fn walk_files(dir: &Path, visit: &mut dyn FnMut(&Path)) {
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            match entry.file_type() {
                Ok(t) if t.is_dir() => walk_files(&entry.path(), visit),
                Ok(_) => visit(&entry.path()),
                Err(_) => {}
            }
        }
    }
}

fn post_hook(config: &Config) {
    let path = &config.posthook_file_path;
    let executable = fs::metadata(path)
        .ok()
        .map(|m| m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false);
    if !executable {
        return;
    }

    log(&format!(
        "Post-hook script file found: {}. Executing",
        path.display()
    ));
    match Command::new("sh").arg(path).status() {
        Ok(status) if status.success() => {
            log(&format!("Post-hook script file {} exited successfully.", path.display()));
        }
        _ => err(&format!(
            "Post-hook script file {} exited with error. Please check logs or your post-hook script for errors.",
            path.display()
        )),
    }
}

fn restart_containers(config: &Config) {
    if config.containers.is_empty() {
        return;
    }
    let client = match docker_client(config) {
        Some(client) => client,
        None => return,
    };

    log("Trying to restart containers");
    for name in &config.containers {
        log(&format!("Looking up container with name {}", name));
        match client.restart_container(name) {
            Ok(id) => {
                log(&format!("Found '{}'. Restarting now...", id));
                log(&format!("Restarting container '{}' was successful", id));
            }
            Err(e) => err(&format!(
                "Something went wrong while restarting container '{}' ({}). Please check health of containers and consider restarting them manually.",
                name, e
            )),
        }
    }
    log("Container restarting process done.");
}

fn restart_services(config: &Config) {
    if config.services.is_empty() {
        return;
    }
    let client = match docker_client(config) {
        Some(client) => client,
        None => return,
    };

    log("Trying to restart services");
    for name in &config.services {
        log(&format!("Looking up service with name {}", name));
        match client.force_update_service(name) {
            Ok(id) => {
                log(&format!("Found '{}'. Running force update now...", id));
                log(&format!("Restarting service '{}' was successful", id));
            }
            Err(e) => err(&format!(
                "Something went wrong while updating service '{}' ({}). Please check health of services and their tasks and consider restarting them manually.",
                name, e
            )),
        }
    }
    log("Service restarting process done.");
}

/// Builds a Docker API client, or `None` (with a log line) when the daemon
/// is unreachable — restarts are then skipped, exactly like the bash
/// implementation did when the `docker` binary was missing.
fn docker_client(config: &Config) -> Option<crate::docker::DockerClient> {
    let client = crate::docker::DockerClient::new(&config.docker_socket);
    if client.is_available() {
        return Some(client);
    }
    err(&format!(
        "Docker daemon is not reachable via {} . Restart functionality will be skipped! Mount the Docker socket to use it.",
        client.socket_path().display()
    ));
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config(domains: Vec<&str>) -> Config {
        Config {
            mode: crate::config::Mode::Local,
            acme_file_path: "/traefik/acme.json".into(),
            output_dir: "/output".into(),
            status_file: "/tmp/traefik-cert-sync-status.json".into(),
            certificate_file_name: "cert".into(),
            certificate_file_ext: ".pem".into(),
            privatekey_file_name: "key".into(),
            privatekey_file_ext: ".pem".into(),
            rsakey_file_name: "rsakey".into(),
            rsakey_file_ext: ".pem".into(),
            domains: domains.into_iter().map(str::to_string).collect(),
            combined_pem: None,
            combine_pkcs12: false,
            pkcs12_password: None,
            convert_keys_to_rsa: false,
            override_uid: None,
            override_gid: None,
            posthook_file_path: "/hook/hook.sh".into(),
            containers: vec![],
            services: vec![],
            server_port: 3556,
            server_key: String::new(),
            agent_server_address: String::new(),
            agent_key: String::new(),
            agent_poll_interval: 30,
            docker_socket: "/var/run/docker.sock".into(),
        }
    }

    fn entry(domain: &str) -> CertEntry {
        CertEntry {
            domain: domain.to_string(),
            certificate: format!(
                "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
                domain
            ),
            key: format!(
                "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
                domain
            ),
        }
    }

    #[test]
    fn single_domain_goes_flat() {
        let dir = std::env::temp_dir().join(format!("tcd-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let config = test_config(vec!["example.com"]);
        let certs = vec![entry("example.com"), entry("other.com")];

        assert!(sync(&certs, &config, &dir));
        assert!(dir.join("cert.pem").is_file());
        assert!(dir.join("key.pem").is_file());
        assert!(!dir.join("example.com").exists());

        // Second run: no changes.
        assert!(!sync(&certs, &config, &dir));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn multiple_domains_use_subdirs() {
        let dir = std::env::temp_dir().join(format!("tcd-test-multi-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let config = test_config(vec!["example.com", "test.example.com"]);
        let certs = vec![
            entry("example.com"),
            entry("test.example.com"),
            entry("ignored.com"),
        ];

        assert!(sync(&certs, &config, &dir));
        assert!(dir.join("example.com/cert.pem").is_file());
        assert!(dir.join("test.example.com/key.pem").is_file());
        assert!(!dir.join("ignored.com").exists());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn all_domains_dumped_when_domain_unset() {
        let dir = std::env::temp_dir().join(format!("tcd-test-all-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let config = test_config(vec![]);
        let certs = vec![entry("a.com"), entry("b.com")];

        assert!(sync(&certs, &config, &dir));
        assert!(dir.join("a.com/cert.pem").is_file());
        assert!(dir.join("b.com/cert.pem").is_file());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn changed_content_triggers_rewrite() {
        let dir = std::env::temp_dir().join(format!("tcd-test-chg-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let config = test_config(vec!["a.com"]);
        sync(&[entry("a.com")], &config, &dir);
        assert!(sync(&[entry_with_version("a.com", 2)], &config, &dir));

        let _ = fs::remove_dir_all(&dir);
    }

    fn entry_with_version(domain: &str, v: u32) -> CertEntry {
        CertEntry {
            domain: domain.to_string(),
            certificate: format!("cert-v{}\n", v),
            key: format!("key-v{}\n", v),
        }
    }
}
