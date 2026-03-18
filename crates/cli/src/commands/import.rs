//! Import hash signatures from blocklist files into the signature database.

use std::path::Path;

use anyhow::{anyhow, Context, Result};
use colored::Colorize;

fn decode_hex(s: &str) -> Result<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return Err(anyhow!("odd length hex string"));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| anyhow!("{}", e)))
        .collect()
}

pub async fn run(blocklist_path: &Path, data_dir: &Path) -> Result<()> {
    let sig_dir = data_dir.join("signatures");
    let db = prx_sd_signatures::SignatureDatabase::open(&sig_dir)
        .context("failed to open signature database")?;

    let content = std::fs::read_to_string(blocklist_path)
        .with_context(|| format!("failed to read {}", blocklist_path.display()))?;

    let mut entries: Vec<(Vec<u8>, String)> = Vec::new();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // Format: hex_hash malware_name
        let parts: Vec<&str> = line.splitn(2, ' ').collect();
        if parts.len() != 2 {
            eprintln!("{} skipping malformed line: {}", "warning:".yellow(), line);
            continue;
        }

        let hex_hash = parts[0].trim();
        let name = parts[1].trim().to_string();

        match decode_hex(hex_hash) {
            Ok(hash_bytes) => entries.push((hash_bytes, name)),
            Err(e) => {
                eprintln!("{} invalid hex '{}': {}", "warning:".yellow(), hex_hash, e);
            }
        }
    }

    if entries.is_empty() {
        println!("No valid entries found in {}", blocklist_path.display());
        return Ok(());
    }

    let count = db.import_hashes(&entries)?;
    println!(
        "{} Imported {} hash entries from {}",
        "success:".green().bold(),
        count,
        blocklist_path.display()
    );

    let stats = db.get_stats()?;
    println!("  Database now has {} SHA-256 entries", stats.hash_count);

    Ok(())
}
