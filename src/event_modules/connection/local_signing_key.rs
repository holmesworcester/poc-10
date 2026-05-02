//! Process-local cache for the daemon's static Ed25519 signing key.
//!
//! `connection.unwrap` and `apply_connection_post` both need the
//! daemon's PRIVATE key to do real X25519 ECDH. The kernel chain
//! threads only the public `local_endpoint_id` (one parameter — the
//! "minimal kernel touch" rule from plan.md), so we have to recover
//! the matching `SigningKey` from somewhere.
//!
//! Strategy: the binary entry point (`bin/topo/main.rs`) calls
//! `api::ensure_signing_key(db_path)` at startup, which loads the
//! 32-byte seed from a sidecar file `.<dbname>.signkey` next to the
//! database. We do the same here, lazily, and memoize the result in a
//! process-wide map keyed by db path. The first inbound frame on a
//! new daemon pays one filesystem read; everything afterward is a
//! `RwLock` read.
//!
//! Tests with `:memory:` databases install their key directly via
//! [`install_for_path`] (typically through the `for_db_or_test_default`
//! helper used by the connection module's tests). When no key has been
//! installed for a db path, we fall back to a deterministic test key
//! derived from the db path itself, so the in-memory test harness
//! stays self-contained.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{OnceLock, RwLock};

use ed25519_dalek::SigningKey;
use rusqlite::Connection as SqlConnection;

/// Process-wide cache. Keyed by db filename (the value rusqlite's
/// `Connection::path()` returns). The cache is populated on demand
/// from the sidecar file beside `db_path`.
static CACHE: OnceLock<RwLock<HashMap<String, SigningKey>>> = OnceLock::new();

fn cache() -> &'static RwLock<HashMap<String, SigningKey>> {
    CACHE.get_or_init(|| RwLock::new(HashMap::new()))
}

/// Sidecar filename: `.<dbname>.signkey`. Mirrors the layout used by
/// `runtime::control::api::signing_key_path` so a daemon started by
/// the binary entry point and a daemon spun up via the runtime see
/// the same file.
fn sidecar_path(db_path: &Path) -> PathBuf {
    let mut p = db_path.to_path_buf();
    let stem = p
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "topo.db".to_string());
    p.set_file_name(format!(".{}.signkey", stem));
    p
}

/// Install (or override) the signing key for `db_path`. Used by tests
/// that don't go through the on-disk sidecar.
pub fn install_for_path(db_path: &str, key: SigningKey) {
    let mut g = cache().write().unwrap();
    g.insert(db_path.to_string(), key);
}

/// Pull the daemon's signing key for the connection's underlying db.
///
/// Resolution order:
///
/// 1. In-memory cache hit on the db path.
/// 2. On-disk sidecar `.<dbname>.signkey` (32-byte seed).
/// 3. Deterministic test fallback derived from the db path string —
///    keeps in-memory tests reproducible without a real on-disk file.
///
/// The chosen key is inserted into the cache for subsequent calls.
pub fn for_db(db: &SqlConnection) -> SigningKey {
    let raw = db.path().unwrap_or("");
    {
        let g = cache().read().unwrap();
        if let Some(k) = g.get(raw) {
            return k.clone();
        }
    }
    let key = load_or_synthesize(raw);
    let mut g = cache().write().unwrap();
    g.entry(raw.to_string()).or_insert_with(|| key.clone());
    key
}

fn load_or_synthesize(db_path_str: &str) -> SigningKey {
    if !db_path_str.is_empty() {
        let sidecar = sidecar_path(Path::new(db_path_str));
        if let Ok(bytes) = std::fs::read(&sidecar) {
            if bytes.len() == 32 {
                let mut seed = [0u8; 32];
                seed.copy_from_slice(&bytes);
                return SigningKey::from_bytes(&seed);
            }
        }
    }
    // Test fallback: deterministic per-db-path so the same in-memory
    // test sees a stable identity. Real daemons always have a sidecar.
    let mut seed = [0u8; 32];
    let h = blake3::hash(format!("poc9-test-fallback-signkey-v1::{}", db_path_str).as_bytes());
    seed.copy_from_slice(h.as_bytes());
    SigningKey::from_bytes(&seed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn install_then_for_db_returns_installed_key() {
        let db = SqlConnection::open_in_memory().unwrap();
        // In-memory dbs report `Some("")` from rusqlite.
        let path = db.path().unwrap_or("").to_string();
        let key = SigningKey::from_bytes(&[0xAB; 32]);
        install_for_path(&path, key.clone());
        let got = for_db(&db);
        assert_eq!(got.to_bytes(), key.to_bytes());
    }
}
