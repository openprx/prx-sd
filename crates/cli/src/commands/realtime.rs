use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use colored::Colorize;
use tokio::signal;

use prx_sd_core::{ScanConfig, ScanEngine, ThreatLevel};
use prx_sd_realtime::event::FileEvent;
use prx_sd_realtime::protected_dirs::{
    ProtectedDirsConfig, ProtectedDirsEnforcer, ProtectionVerdict,
};
use prx_sd_realtime::ransomware::{RansomwareConfig, RansomwareDetector, RansomwareVerdict};

/// Convert a `notify::Event` into zero or more [`FileEvent`]s.
///
/// The `notify` crate does not expose PIDs, so PID-dependent variants
/// (`Open`, `Execute`, `Rename`) are not produced here.  The ransomware
/// detector and protected-dirs enforcer handle the absence of a PID
/// gracefully (returning `Clean` / `Allowed`).
fn notify_to_file_events(event: &notify::Event) -> Vec<FileEvent> {
    let mut out = Vec::with_capacity(event.paths.len());
    for p in &event.paths {
        let fe = match event.kind {
            notify::EventKind::Create(_) => FileEvent::Create { path: p.clone() },
            notify::EventKind::Modify(notify::event::ModifyKind::Name(_)) => {
                // notify rename events carry two paths (from, to).  When
                // both are present we emit a Rename; otherwise treat as a
                // plain Modify so the ransomware detector still sees it.
                if event.paths.len() == 2 {
                    // Only emit one Rename for the pair, not one per path.
                    if p == &event.paths[0] {
                        return vec![FileEvent::Rename {
                            from: event.paths[0].clone(),
                            to: event.paths[1].clone(),
                            pid: 0,
                        }];
                    }
                    // Second path of the rename pair – already handled.
                    return out;
                }
                FileEvent::Modify { path: p.clone() }
            }
            notify::EventKind::Modify(_) => FileEvent::Modify { path: p.clone() },
            notify::EventKind::Access(notify::event::AccessKind::Close(
                notify::event::AccessMode::Write,
            )) => FileEvent::CloseWrite { path: p.clone() },
            notify::EventKind::Remove(_) => FileEvent::Delete { path: p.clone() },
            _ => continue,
        };
        out.push(fe);
    }
    out
}

/// Create a `ScanConfig` for the real-time monitor.
fn build_config(data_dir: &Path) -> ScanConfig {
    ScanConfig::default()
        .with_signatures_dir(data_dir.join("signatures"))
        .with_yara_rules_dir(data_dir.join("yara"))
        .with_quarantine_dir(data_dir.join("quarantine"))
}

pub async fn run(
    paths: Vec<PathBuf>,
    block_mode: bool,
    daemon: bool,
    data_dir: &Path,
) -> Result<()> {
    let config = build_config(data_dir);
    let engine = ScanEngine::new(config).context("failed to initialise scan engine")?;

    println!(
        "{} Starting real-time monitor on {} path(s)",
        ">>>".cyan().bold(),
        paths.len()
    );
    for p in &paths {
        println!("  {} {}", "Watching:".green(), p.display());
    }

    if block_mode {
        println!(
            "  {} blocking mode enabled (requires root + fanotify on Linux)",
            "Mode:".yellow().bold()
        );
    }

    if daemon {
        println!(
            "  {} running in foreground (daemon fork not implemented)",
            "Note:".yellow()
        );
    }

    // Use the notify-based cross-platform watcher.
    // The prx-sd-realtime crate is a placeholder, so we use `notify` directly.
    let (tx, mut rx) = tokio::sync::mpsc::channel::<notify::Event>(4096);

    let mut watcher = notify::recommended_watcher(
        move |res: std::result::Result<notify::Event, notify::Error>| match res {
            Ok(event) => {
                let _ = tx.blocking_send(event);
            }
            Err(e) => {
                tracing::error!("watcher error: {e}");
            }
        },
    )
    .context("failed to create file system watcher")?;

    use notify::{RecursiveMode, Watcher};
    for p in &paths {
        watcher
            .watch(p, RecursiveMode::Recursive)
            .with_context(|| format!("failed to watch: {}", p.display()))?;
    }

    // Ransomware behaviour detector (stateful, tracks per-PID sliding windows).
    let mut ransomware_detector = RansomwareDetector::new(RansomwareConfig::default());
    // Protected directory enforcer (blocks unauthorised writes to sensitive paths).
    let protected_dirs = ProtectedDirsEnforcer::new(ProtectedDirsConfig::default());

    println!(
        "\n{} Monitoring active. Press {} to stop.\n",
        ">>>".green().bold(),
        "Ctrl+C".bold()
    );

    // Event processing loop.
    loop {
        tokio::select! {
            Some(event) = rx.recv() => {
                // Only scan on file creation, modification, or close-write.
                let dominated = matches!(
                    event.kind,
                    notify::EventKind::Create(_)
                    | notify::EventKind::Modify(_)
                    | notify::EventKind::Access(notify::event::AccessKind::Close(
                        notify::event::AccessMode::Write,
                    ))
                );

                if !dominated {
                    continue;
                }

                // ── Ransomware + protected-dirs checks ──────────────
                let file_events = notify_to_file_events(&event);
                for fe in &file_events {
                    // 1. Ransomware behaviour analysis.
                    match ransomware_detector.on_file_event(fe) {
                        RansomwareVerdict::RansomwareDetected { pid, ref process_name, ref reason } => {
                            println!(
                                "  {} {} (PID {}) - {}",
                                "RANSOMWARE DETECTED:".red().bold(),
                                process_name,
                                pid,
                                reason,
                            );
                            tracing::error!(
                                pid,
                                process = %process_name,
                                reason = %reason,
                                "ransomware behaviour detected"
                            );
                        }
                        RansomwareVerdict::Suspicious { pid, ref process_name, ref reason, score } => {
                            println!(
                                "  {} {} (PID {}) score={} - {}",
                                "SUSPICIOUS ACTIVITY:".yellow().bold(),
                                process_name,
                                pid,
                                score,
                                reason,
                            );
                            tracing::warn!(
                                pid,
                                process = %process_name,
                                score,
                                reason = %reason,
                                "suspicious ransomware-like activity"
                            );
                        }
                        RansomwareVerdict::Clean => {}
                    }

                    // 2. Protected directory enforcement.
                    if let Some(pid) = fe.pid() {
                        if let ProtectionVerdict::Blocked { ref path, pid: blocked_pid, ref process_name, ref reason } = protected_dirs.check_access(fe.path(), pid) {
                            println!(
                                "  {} {} (PID {}) tried to modify {}",
                                "PROTECTED DIR VIOLATION:".red().bold(),
                                process_name,
                                blocked_pid,
                                path.display(),
                            );
                            tracing::warn!(
                                pid = blocked_pid,
                                process = %process_name,
                                path = %path.display(),
                                reason = %reason,
                                "protected directory violation"
                            );
                        }
                    }
                }

                for file_path in &event.paths {
                    if !file_path.is_file() {
                        continue;
                    }

                    let kind_label = match event.kind {
                        notify::EventKind::Create(_) => "CREATE",
                        notify::EventKind::Modify(_) => "MODIFY",
                        _ => "WRITE",
                    };

                    match engine.scan_file(file_path).await {
                        Ok(result) => {
                            let level_str = match result.threat_level {
                                ThreatLevel::Clean => format!("{}", "CLEAN".green()),
                                ThreatLevel::Suspicious => format!("{}", "SUSPICIOUS".yellow().bold()),
                                ThreatLevel::Malicious => format!("{}", "MALICIOUS".red().bold()),
                            };

                            let threat_info = result
                                .threat_name
                                .as_deref()
                                .map(|n| format!(" ({})", n))
                                .unwrap_or_default();

                            println!(
                                "[{}] {} {} → {}{}",
                                kind_label.dimmed(),
                                chrono::Local::now().format("%H:%M:%S"),
                                file_path.display(),
                                level_str,
                                threat_info,
                            );

                            // In block mode, attempt to remove malicious files immediately.
                            if block_mode && result.threat_level == ThreatLevel::Malicious {
                                println!(
                                    "  {} blocking access to {}",
                                    "BLOCKED:".red().bold(),
                                    file_path.display()
                                );
                                // Best-effort removal -- true blocking requires fanotify.
                                if let Err(e) = std::fs::remove_file(file_path) {
                                    tracing::warn!(
                                        path = %file_path.display(),
                                        error = %e,
                                        "could not remove malicious file"
                                    );
                                }
                            }
                        }
                        Err(e) => {
                            tracing::debug!(
                                path = %file_path.display(),
                                error = %e,
                                "failed to scan file event"
                            );
                        }
                    }
                }
            }
            _ = signal::ctrl_c() => {
                println!("\n{} Shutting down monitor...", ">>>".yellow().bold());
                break;
            }
        }
    }

    drop(watcher);
    println!("{} Monitor stopped.", ">>>".green().bold());
    Ok(())
}
