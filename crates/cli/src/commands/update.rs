use std::fmt::Write;
use std::path::Path;

use anyhow::{Context, Result};
use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};
use serde::{Deserialize, Serialize};

/// Default update server URL.
const DEFAULT_SERVER_URL: &str = "https://update.prx-sd.dev/v1";

/// Manifest returned by the update server's `/manifest.json` endpoint.
#[derive(Debug, Serialize, Deserialize)]
struct UpdateManifest {
    /// Latest available signature database version.
    version: u64,
    /// ISO-8601 timestamp of the release.
    released_at: String,
    /// SHA-256 hex digest of the update payload.
    sha256: String,
    /// Byte size of the compressed payload.
    size: u64,
    /// Relative URL path to the payload archive.
    payload_url: String,
}

/// Read the current local signature DB version from the data directory.
fn read_local_version(data_dir: &Path) -> u64 {
    let version_file = data_dir.join("signatures").join("version");
    std::fs::read_to_string(&version_file)
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .unwrap_or(0)
}

/// Write the local signature DB version after a successful update.
fn write_local_version(data_dir: &Path, version: u64) -> Result<()> {
    let sig_dir = data_dir.join("signatures");
    std::fs::create_dir_all(&sig_dir)?;
    std::fs::write(sig_dir.join("version"), version.to_string())?;
    Ok(())
}

/// Load config to get a potentially user-overridden server URL.
fn load_server_url(data_dir: &Path) -> String {
    let config_path = data_dir.join("config.json");
    if let Ok(data) = std::fs::read_to_string(&config_path) {
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(&data) {
            if let Some(url) = val.get("update_server_url").and_then(|v| v.as_str()) {
                return url.to_string();
            }
        }
    }
    DEFAULT_SERVER_URL.to_string()
}

pub async fn run(check_only: bool, force: bool, server_url: Option<String>, data_dir: &Path) -> Result<()> {
    let base_url = server_url.unwrap_or_else(|| load_server_url(data_dir));
    let local_version = read_local_version(data_dir);

    println!("{} Checking for signature updates...", ">>>".cyan().bold());
    println!("  Server:        {base_url}");
    println!("  Local version: {local_version}");

    // Fetch manifest from the update server.
    let manifest_url = format!("{}/manifest.json", base_url.trim_end_matches('/'));
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()?;

    let manifest: UpdateManifest = client
        .get(&manifest_url)
        .send()
        .await
        .context("failed to reach update server")?
        .error_for_status()
        .context("update server returned an error")?
        .json()
        .await
        .context("failed to parse update manifest")?;

    println!("  Remote version: {}", manifest.version);
    println!("  Released:       {}", manifest.released_at);

    let up_to_date = manifest.version <= local_version;

    if up_to_date && !force {
        println!(
            "\n{} Signatures are up to date (v{}).",
            "OK".green().bold(),
            local_version
        );
        return Ok(());
    }

    if check_only {
        if up_to_date {
            println!("\n{} Already up to date.", "OK".green().bold());
        } else {
            println!(
                "\n{} Update available: v{} -> v{} ({})",
                "UPDATE".yellow().bold(),
                local_version,
                manifest.version,
                crate::output::format_bytes(manifest.size),
            );
        }
        return Ok(());
    }

    // Download the update payload.
    let payload_url = if manifest.payload_url.starts_with("http") {
        manifest.payload_url.clone()
    } else {
        format!(
            "{}/{}",
            base_url.trim_end_matches('/'),
            manifest.payload_url.trim_start_matches('/')
        )
    };

    println!(
        "\n{} Downloading update ({})...",
        ">>>".cyan().bold(),
        crate::output::format_bytes(manifest.size),
    );

    let pb = ProgressBar::new(manifest.size);
    pb.set_style(
        ProgressStyle::with_template(
            "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec})",
        )
        .map_or_else(|_| ProgressStyle::default_bar(), |style| style.progress_chars("#>-")),
    );

    let response = client
        .get(&payload_url)
        .send()
        .await
        .context("failed to download update payload")?
        .error_for_status()
        .context("update download failed")?;

    let bytes = response.bytes().await.context("failed to read update payload body")?;

    pb.set_position(bytes.len() as u64);
    pb.finish_and_clear();

    // Verify SHA-256 digest.
    {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        let hash_bytes = hasher.finalize();
        let digest = hash_bytes.iter().fold(String::new(), |mut acc, b| {
            let _ = write!(acc, "{b:02x}");
            acc
        });
        if digest != manifest.sha256 {
            anyhow::bail!("SHA-256 mismatch: expected {}, got {}", manifest.sha256, digest);
        }
        println!("  {} SHA-256 verified", "OK".green());
    }

    // Write the payload to the signatures directory.
    let sig_dir = data_dir.join("signatures");
    std::fs::create_dir_all(&sig_dir)?;

    let payload_path = sig_dir.join("update.bin");
    std::fs::write(&payload_path, &bytes)?;

    // Update version marker.
    write_local_version(data_dir, manifest.version)?;

    println!("\n{} Signatures updated to v{}.", "OK".green().bold(), manifest.version);

    Ok(())
}
