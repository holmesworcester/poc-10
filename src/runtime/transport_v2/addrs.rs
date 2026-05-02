//! Pluggable address resolver.
//!
//! Phase 1: in-memory `HashMap<EndpointId, SocketAddr>` plus an optional
//! SQLite-backed `endpoint_addresses` table fallback. The table lets two
//! processes (CLI `topo connect` writing on one side, daemon dispatcher
//! reading on the other) agree on `endpoint_id -> addr` without needing
//! shared in-memory state.
//!
//! The DB-fallback path is best-effort: any DB error is swallowed and we
//! fall back to "no address known", which is the resolver's existing
//! contract on a miss.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::{Arc, OnceLock, RwLock};

use rusqlite::{params, Connection};

use super::super::control_loop::work_item::EndpointId;

/// Anything that can map a remote `endpoint_id` to a `SocketAddr`.
pub trait AddressResolver: Send + Sync {
    fn resolve(&self, endpoint_id: &EndpointId) -> Option<SocketAddr>;

    /// Record a freshly-learned address (e.g. from incoming connection,
    /// `observed_address` event, invite metadata). Default no-op for
    /// resolvers that are read-only.
    fn record(&self, _endpoint_id: EndpointId, _addr: SocketAddr) {}
}

/// In-memory cache plus optional SQLite-backed `endpoint_addresses`
/// fallback. The cache is the fast path; the DB is consulted on a miss
/// so two processes sharing a DB can agree on an `endpoint_id -> addr`
/// mapping without an explicit handshake.
#[derive(Default, Clone)]
pub struct AddressBook {
    inner: Arc<RwLock<HashMap<EndpointId, SocketAddr>>>,
    /// Optional DB path. When set, missed resolves and fresh inserts
    /// also touch the `endpoint_addresses` table. `OnceLock` so the
    /// runtime can attach the path lazily after construction (the
    /// runtime's address-book is built before the DB path is in scope).
    db_path: Arc<OnceLock<PathBuf>>,
}

impl AddressBook {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_initial(map: HashMap<EndpointId, SocketAddr>) -> Self {
        Self {
            inner: Arc::new(RwLock::new(map)),
            db_path: Arc::new(OnceLock::new()),
        }
    }

    /// Construct a book that also persists insertions to and consults
    /// `endpoint_addresses` in the SQLite database at `db_path`. The
    /// schema is created lazily on first write.
    pub fn with_db_path(db_path: PathBuf) -> Self {
        let cell = OnceLock::new();
        let _ = cell.set(db_path);
        Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
            db_path: Arc::new(cell),
        }
    }

    /// Attach a DB path. No-op if already set.
    pub fn attach_db_path(&self, db_path: PathBuf) {
        let _ = self.db_path.set(db_path);
    }

    /// Best-effort load of all persisted rows into the in-memory cache.
    /// Useful at daemon startup so resolution is fast for already-known
    /// endpoints.
    pub fn warm_from_db(&self) {
        let Some(p) = self.db_path.get() else { return };
        let Ok(c) = Connection::open(p.as_path()) else { return };
        let _ = ensure_schema(&c);
        let mut stmt = match c.prepare("SELECT endpoint_id, addr FROM endpoint_addresses") {
            Ok(s) => s,
            Err(_) => return,
        };
        let rows = match stmt.query_map([], |r| {
            let blob: Vec<u8> = r.get(0)?;
            let addr_str: String = r.get(1)?;
            Ok((blob, addr_str))
        }) {
            Ok(rs) => rs,
            Err(_) => return,
        };
        for row in rows.flatten() {
            let (blob, addr_str) = row;
            if blob.len() != 32 {
                continue;
            }
            let mut id = [0u8; 32];
            id.copy_from_slice(&blob);
            if let Ok(addr) = SocketAddr::from_str(&addr_str) {
                if let Ok(mut g) = self.inner.write() {
                    g.insert(id, addr);
                }
            }
        }
    }

    pub fn insert(&self, endpoint_id: EndpointId, addr: SocketAddr) {
        if let Ok(mut g) = self.inner.write() {
            g.insert(endpoint_id, addr);
        }
        if let Some(p) = self.db_path.get() {
            // Best-effort persist; ignore errors.
            if let Ok(c) = Connection::open(p.as_path()) {
                let _ = ensure_schema(&c);
                let _ = c.execute(
                    "INSERT OR REPLACE INTO endpoint_addresses (endpoint_id, addr) VALUES (?1, ?2)",
                    params![endpoint_id.to_vec(), addr.to_string()],
                );
            }
        }
    }

    pub fn get(&self, endpoint_id: &EndpointId) -> Option<SocketAddr> {
        if let Some(addr) = self
            .inner
            .read()
            .ok()
            .and_then(|g| g.get(endpoint_id).copied())
        {
            return Some(addr);
        }
        // Cache miss: try the DB-backed table.
        if let Some(p) = self.db_path.get() {
            if let Ok(c) = Connection::open(p.as_path()) {
                let _ = ensure_schema(&c);
                let row: rusqlite::Result<String> = c.query_row(
                    "SELECT addr FROM endpoint_addresses WHERE endpoint_id = ?1",
                    params![endpoint_id.to_vec()],
                    |r| r.get(0),
                );
                if let Ok(s) = row {
                    if let Ok(addr) = SocketAddr::from_str(&s) {
                        if let Ok(mut g) = self.inner.write() {
                            g.insert(*endpoint_id, addr);
                        }
                        return Some(addr);
                    }
                }
            }
        }
        None
    }
}

impl AddressResolver for AddressBook {
    fn resolve(&self, endpoint_id: &EndpointId) -> Option<SocketAddr> {
        self.get(endpoint_id)
    }

    fn record(&self, endpoint_id: EndpointId, addr: SocketAddr) {
        self.insert(endpoint_id, addr);
    }
}

/// Idempotent: create the `endpoint_addresses` table.
pub fn ensure_schema(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS endpoint_addresses (
            endpoint_id BLOB PRIMARY KEY,
            addr        TEXT NOT NULL
        );",
    )
}

/// Helper that writes a row through the supplied connection. Designed
/// for the CLI process to seed the DB before the daemon's
/// `AddressBook::get` consults it.
pub fn upsert_endpoint_address(
    conn: &Connection,
    endpoint_id: &EndpointId,
    addr: &SocketAddr,
) -> rusqlite::Result<()> {
    ensure_schema(conn)?;
    conn.execute(
        "INSERT OR REPLACE INTO endpoint_addresses (endpoint_id, addr) VALUES (?1, ?2)",
        params![endpoint_id.to_vec(), addr.to_string()],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn address_book_round_trip() {
        let book = AddressBook::new();
        let id: EndpointId = [7u8; 32];
        let addr = SocketAddr::from_str("127.0.0.1:1234").unwrap();
        book.insert(id, addr);
        assert_eq!(book.resolve(&id), Some(addr));
        assert_eq!(book.resolve(&[0u8; 32]), None);
    }

    #[test]
    fn address_book_db_fallback() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("addr.db");
        // First book persists.
        let book_a = AddressBook::with_db_path(db_path.clone());
        let id: EndpointId = [9u8; 32];
        let addr = SocketAddr::from_str("127.0.0.1:9999").unwrap();
        book_a.insert(id, addr);
        // Second book (different in-memory cache) reads from DB.
        let book_b = AddressBook::with_db_path(db_path.clone());
        assert_eq!(book_b.resolve(&id), Some(addr));
    }
}
