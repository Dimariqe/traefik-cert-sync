use crate::config::{Config, Mode};
use crate::util::now_unix;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Where the daemon records liveness/success for `--healthcheck`.
#[derive(Serialize, Deserialize)]
struct Status {
    mode: String,
    last_success: u64,
}

/// Records a successful dump/poll. Called after every successful cycle,
/// changed or not. Best-effort: a failing status file must never take the
/// certificate dumping itself down.
pub fn write_ok_to(path: &Path, mode: &str) {
    let status = Status {
        mode: mode.to_string(),
        last_success: now_unix(),
    };
    let Ok(json) = serde_json::to_vec(&status) else {
        return;
    };
    let tmp = path.with_extension("tmp");
    if std::fs::write(&tmp, &json)
        .and_then(|_| std::fs::rename(&tmp, path))
        .is_err()
    {
        crate::util::err(&format!("cannot write status file {}", path.display()));
    }
}

/// Whether the daemon looks healthy.
///
/// Local and server modes only require that a first dump ever succeeded —
/// an acme.json that never changes is a perfectly quiet, healthy state. An
/// agent that has not reached its server recently is unhealthy.
pub fn check(config: &Config) -> bool {
    check_path(&config.status_file, config)
}

pub fn check_path(path: &Path, config: &Config) -> bool {
    let Ok(json) = std::fs::read_to_string(path) else {
        return false;
    };
    let Ok(status) = serde_json::from_str::<Status>(&json) else {
        return false;
    };

    if config.mode == Mode::Agent {
        let tolerance = 3 * config.agent_poll_interval + 300;
        return now_unix().saturating_sub(status.last_success) <= tolerance;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config_with_mode(mode: Mode, interval: u64) -> Config {
        let mut config = crate::config::test_config();
        config.mode = mode;
        config.agent_poll_interval = interval;
        config
    }

    #[test]
    fn missing_file_is_unhealthy() {
        let config = config_with_mode(Mode::Local, 30);
        assert!(!check_path(
            Path::new("/nonexistent/tcd-status.json"),
            &config
        ));
    }

    #[test]
    fn local_mode_never_goes_stale() {
        let dir = std::env::temp_dir().join(format!("tcd-status-local-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("status.json");
        write_ok_to(&path, "local");

        // Forge an ancient timestamp; local modes stay healthy regardless.
        let ancient = r#"{"mode":"local","last_success":100}"#;
        std::fs::write(&path, ancient).unwrap();

        let config = config_with_mode(Mode::Local, 30);
        assert!(check_path(&path, &config));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn agent_mode_goes_stale_after_tolerance() {
        let dir = std::env::temp_dir().join(format!("tcd-status-agent-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("status.json");

        let config = config_with_mode(Mode::Agent, 30); // tolerance = 390s
        std::fs::write(&path, r#"{"mode":"agent","last_success":1000}"#).unwrap();
        // last_success 1000 is ancient compared to the real clock -> stale.
        assert!(!check_path(&path, &config));

        // A fresh write is healthy again.
        write_ok_to(&path, "agent");
        assert!(check_path(&path, &config));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
