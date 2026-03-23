// This crate uses unsafe for LMDB environment initialization (heed).
// All unsafe blocks have SAFETY comments.
#![allow(unsafe_code)]

//! Signature management crate for prx-sd.
//!
//! Provides hash computation, an LMDB-backed signature database, YARA rule
//! scanning (stub), parsers for `ClamAV` signature formats (CVD, NDB, LDB,
//! HDB, HSB), and a `ClamAV` CVD importer.

pub mod clamav;
pub mod database;
pub mod formats;
pub mod hash;
pub mod yara;

pub use clamav::{import_cvd, import_cvd_bytes, import_hash_file, ClamavImportStats};
pub use database::{DbStats, SignatureDatabase};
pub use yara::{YaraEngine, YaraMatch};
