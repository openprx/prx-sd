//! Ed25519 key management and payload signing utilities for the update server.

use std::path::Path;

use anyhow::{Context, Result};
use ed25519_dalek::{SigningKey, VerifyingKey};
use tracing::info;

use prx_sd_updater::sign_payload;

/// Load an Ed25519 keypair from a file, or generate and save a new one.
///
/// The key file stores the 32-byte Ed25519 seed (private key material).
/// If the file does not exist, a fresh keypair is generated, the seed is
/// written to disk, and the pair is returned. If it exists, the seed is
/// read and the keypair is reconstructed.
pub fn load_or_create_keypair(path: &Path) -> Result<(SigningKey, VerifyingKey)> {
    if path.exists() {
        let seed_bytes = std::fs::read(path)
            .with_context(|| format!("failed to read signing key from {}", path.display()))?;

        if seed_bytes.len() != 32 {
            anyhow::bail!(
                "signing key file has invalid length: expected 32 bytes, got {}",
                seed_bytes.len()
            );
        }

        let seed: [u8; 32] = seed_bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("signing key seed conversion failed despite length check"))?;

        let signing_key = SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key();

        info!(
            path = %path.display(),
            public_key = hex::encode(verifying_key.as_bytes()),
            "loaded existing signing keypair"
        );

        Ok((signing_key, verifying_key))
    } else {
        // Generate a new keypair.
        let signing_key = SigningKey::generate(&mut rand::rngs::OsRng);
        let verifying_key = signing_key.verifying_key();

        // Ensure parent directory exists.
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).with_context(|| {
                format!("failed to create directory for signing key: {}", parent.display())
            })?;
        }

        std::fs::write(path, signing_key.to_bytes()).with_context(|| {
            format!("failed to write signing key to {}", path.display())
        })?;

        info!(
            path = %path.display(),
            public_key = hex::encode(verifying_key.as_bytes()),
            "generated and saved new signing keypair"
        );

        Ok((signing_key, verifying_key))
    }
}

/// Sign data with the given key and compress with zstd.
///
/// Used when generating full database snapshots.
///
/// The output format is `[64-byte Ed25519 signature][zstd-compressed data]`.
/// This is the wire format used for delta and full-database downloads.
#[allow(dead_code)]
pub fn sign_and_compress(data: &[u8], key: &SigningKey) -> Result<Vec<u8>> {
    let compressed =
        zstd::encode_all(data, 3).context("failed to compress payload with zstd")?;

    Ok(sign_payload(key, &compressed))
}

/// Hex-encode bytes into a lowercase string.
///
/// Used for logging public keys; kept private to this module.
mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        for &b in bytes {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }
}
