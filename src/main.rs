mod acme;
mod agent;
mod auth;
mod config;
mod docker;
mod dump;
mod http;
mod server;
mod status;
mod util;

use config::{Config, Mode};
use notify::event::ModifyKind;
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::path::Path;
use std::sync::mpsc;
use std::time::Duration;
use util::{err, log};

/// Time to collect further watcher events after the first one, so a burst
/// of writes from Traefik results in a single re-read. A re-read that slips
/// through anyway is harmless: unchanged content is detected per domain.
const DEBOUNCE: Duration = Duration::from_millis(500);
/// How long to wait for acme.json to appear before re-checking.
const FILE_RETRY: Duration = Duration::from_secs(10);

fn print_help() {
    println!(
        "Usage: {} [OPTIONS...]",
        std::env::args()
            .next()
            .unwrap_or_else(|| "traefik-cert-sync".into())
    );
    println!(
        "\tPlease consult the repository README for available options and environment variables!"
    );
}

fn die(msg: &str, code: i32) -> ! {
    eprintln!("{}", msg);
    std::process::exit(code);
}

/// Ported from the bash implementation: `-r VALUE`, `-rVALUE`,
/// `--restart-containers VALUE`, `--restart-containers=VALUE`, same for
/// `--restart-services`, plus `-h/--help` and `--healthcheck`.
fn parse_commandline(config: &mut Config) {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    while let Some(key) = args.first().cloned() {
        // (destination flag, value carried by the flag if any)
        let parsed: (&str, Option<String>) = match key.as_str() {
            "-r" | "--restart-containers" => {
                if args.len() < 2 {
                    die(&format!("Missing value for the optional argument '{}'.", key), 1);
                }
                let value = args[1].clone();
                args.remove(1);
                ("containers", Some(value))
            }
            k if k.starts_with("--restart-containers=") => {
                ("containers", Some(k["--restart-containers=".len()..].to_string()))
            }
            k if k.starts_with("-r") && k.len() > 2 => {
                ("containers", Some(k[2..].to_string()))
            }
            k if k.starts_with("--restart-services=") => {
                ("services", Some(k["--restart-services=".len()..].to_string()))
            }
            k if k.starts_with("-h") => {
                print_help();
                std::process::exit(0);
            }
            "--healthcheck" => {
                let healthy = status::check(config);
                if !healthy {
                    err("Healthcheck failed: no successful dump/poll on record (or agent data is stale)");
                }
                std::process::exit(if healthy { 0 } else { 1 });
            }
            _ => die(
                &format!("FATAL ERROR: Got an unexpected argument '{}'\nUsage: traefik-cert-sync [OPTIONS...]", key),
                1,
            ),
        };
        args.remove(0);

        if let Some(v) = parsed.1 {
            let list: Vec<String> = if v.is_empty() {
                Vec::new()
            } else {
                v.split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect()
            };
            match parsed.0 {
                "containers" => {
                    log(&format!(
                        "Got value of --restart-containers: {}. Splitting values.",
                        v
                    ));
                    if list.is_empty() {
                        log("--restart-containers is empty. Won't attempt to restart containers.");
                    }
                    config.containers = list;
                }
                _ => {
                    log(&format!(
                        "Got value of --restart-services: {}. Splitting values.",
                        v
                    ));
                    if list.is_empty() {
                        log("--restart-services is empty. Won't attempt to restart services.");
                    }
                    config.services = list;
                }
            }
        }
    }
}

fn main() {
    let mut config =
        Config::from_env().unwrap_or_else(|e| die(&format!("Invalid configuration: {}", e), 1));
    parse_commandline(&mut config);

    let output_dir = config.output_dir.clone();
    if let Err(e) = std::fs::create_dir_all(&output_dir) {
        die(
            &format!(
                "cannot create output directory {}: {}",
                output_dir.display(),
                e
            ),
            1,
        );
    }

    match config.mode {
        Mode::Agent => {
            log(&format!(
                "Agent mode: polling {} every {}s",
                config.agent_server_address, config.agent_poll_interval
            ));
            agent::run(config, &output_dir);
        }
        Mode::Server => {
            let shared: server::SharedCerts =
                std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
            let server_shared = std::sync::Arc::clone(&shared);
            let server_config = config.clone();
            std::thread::spawn(move || server::run(server_config, server_shared));
            watch_loop(&config, &output_dir, Some(shared));
        }
        Mode::Local => watch_loop(&config, &output_dir, None),
    }
}

/// Waits for the acme file, dumps once, then re-dumps on every change.
fn watch_loop(config: &Config, output_dir: &Path, shared: Option<server::SharedCerts>) -> ! {
    log(&format!(
        "ACME file path: {}",
        config.acme_file_path.display()
    ));

    loop {
        if config.acme_file_path.is_file() {
            break;
        }
        log(&format!(
            "{} is not a file. Retrying...",
            config.acme_file_path.display()
        ));
        std::thread::sleep(FILE_RETRY);
    }

    load_and_sync(config, output_dir, shared.as_ref());

    let (tx, rx) = mpsc::channel::<notify::Result<Event>>();
    let mut watcher: RecommendedWatcher = match Watcher::new(tx, notify::Config::default()) {
        Ok(w) => w,
        Err(e) => die(&format!("cannot start file watcher: {}", e), 1),
    };
    // Watch the parent directory: Traefik may replace acme.json via rename,
    // which produces events on the directory, not the old inode.
    let watch_dir = config
        .acme_file_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    if let Err(e) = watcher.watch(watch_dir, RecursiveMode::NonRecursive) {
        die(&format!("cannot watch {}: {}", watch_dir.display(), e), 1);
    }
    log(&format!("Watching {} for changes", watch_dir.display()));

    loop {
        match rx.recv() {
            Ok(Ok(event)) => {
                if is_relevant(&event, &config.acme_file_path) {
                    // Drain the event burst: one save from Traefik produces
                    // several modify events; treat them as a single change.
                    let deadline = std::time::Instant::now() + DEBOUNCE;
                    while let Ok(_) = rx
                        .recv_timeout(deadline.saturating_duration_since(std::time::Instant::now()))
                    {
                    }
                    // The file may have been replaced atomically: wait for it
                    // to be there again, then re-read.
                    wait_for_file(&config.acme_file_path);
                    load_and_sync(config, output_dir, shared.as_ref());
                }
            }
            Ok(Err(e)) => err(&format!("watch error: {}", e)),
            Err(e) => die(&format!("watcher channel closed: {}", e), 1),
        }
    }
}

/// Only content-changing events matter. Reacting to reads (IN_ACCESS) would
/// self-feed: our own read of acme.json produces such events on the watched
/// directory.
fn is_relevant(event: &Event, acme_file_path: &Path) -> bool {
    let about_acme = event.paths.iter().any(|p| p == acme_file_path);
    if !about_acme && !event.kind.is_remove() {
        return false;
    }
    matches!(
        event.kind,
        EventKind::Create(_)
            | EventKind::Remove(_)
            | EventKind::Modify(ModifyKind::Data(_))
            | EventKind::Modify(ModifyKind::Name(_))
            | EventKind::Modify(ModifyKind::Any)
    )
}

fn wait_for_file(path: &Path) {
    while !path.is_file() {
        std::thread::sleep(FILE_RETRY);
    }
}

/// Reads and parses acme.json, updates the shared server state, and syncs
/// the output directory. Parse failures keep the previously good state.
fn load_and_sync(config: &Config, output_dir: &Path, shared: Option<&server::SharedCerts>) {
    let json = match std::fs::read_to_string(&config.acme_file_path) {
        Ok(j) => j,
        Err(e) => {
            err(&format!(
                "cannot read {}: {}",
                config.acme_file_path.display(),
                e
            ));
            return;
        }
    };

    match acme::parse_acme(&json) {
        Ok(certs) => {
            if let Some(shared) = shared {
                let mut guard = shared.lock().unwrap_or_else(|p| p.into_inner());
                *guard = certs.clone();
            }
            dump::sync(&certs, config, output_dir);
            let mode = match config.mode {
                Mode::Server => "server",
                _ => "local",
            };
            status::write_ok_to(&config.status_file, mode);
        }
        Err(e) => err(&format!("dumping certificates failed: {}", e)),
    }
}
