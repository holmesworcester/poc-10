use rusqlite::{params, types::Type, Connection, OptionalExtension};
use std::io;
use std::path::Path;

pub type EventId = [u8; 32];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TableRow {
    pub table: &'static str,
    pub key: Vec<u8>,
    pub value: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventRecord {
    pub timestamp: u64,
    pub body_len: usize,
    pub canonical_bytes: Vec<u8>,
    pub dependencies: Vec<EventId>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StateChanges {
    pub rows: Vec<TableRow>,
    pub events: Vec<EventRecord>,
}

impl StateChanges {
    pub fn rows(rows: Vec<TableRow>) -> Self {
        Self {
            rows,
            events: Vec::new(),
        }
    }

    pub fn events(events: Vec<EventRecord>) -> Self {
        Self {
            rows: Vec::new(),
            events,
        }
    }

    pub fn append(&mut self, mut other: Self) {
        self.rows.append(&mut other.rows);
        self.events.append(&mut other.events);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandOutput<T> {
    pub value: T,
    pub changes: StateChanges,
}

impl<T> CommandOutput<T> {
    pub fn new(value: T) -> Self {
        Self {
            value,
            changes: StateChanges::default(),
        }
    }

    pub fn with_changes(value: T, changes: StateChanges) -> Self {
        Self { value, changes }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventIndexEntry {
    pub event_id: EventId,
    pub partition: u8,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EventStatusCounts {
    pub ready: usize,
    pub blocked: usize,
    pub applied: usize,
    pub rejected: usize,
    pub blocked_edges: usize,
}

pub struct Store {
    conn: Connection,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventStatus {
    Ready,
    Blocked,
    Applied,
    Rejected,
}

impl EventStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::Blocked => "blocked",
            Self::Applied => "applied",
            Self::Rejected => "rejected",
        }
    }
}

impl Store {
    pub fn open(path: impl AsRef<Path>) -> rusqlite::Result<Self> {
        let conn = Connection::open(path)?;
        let store = Self { conn };
        store.ensure_schema()?;
        Ok(store)
    }

    pub fn insert_table_rows(&self, rows: Vec<TableRow>) -> rusqlite::Result<usize> {
        self.write_transaction(|store| store.insert_table_rows_in_tx(rows))
    }

    pub fn insert_table_rows_in_tx(&self, rows: Vec<TableRow>) -> rusqlite::Result<usize> {
        let mut inserted = 0;
        for row in rows {
            inserted += self.conn.execute(
                "INSERT OR IGNORE INTO table_rows
                    (table_name, row_key, row_value)
                 VALUES (?1, ?2, ?3)",
                params![row.table, row.key, row.value],
            )?;
        }
        Ok(inserted)
    }

    pub fn table_row(&self, table: &'static str, key: &[u8]) -> rusqlite::Result<Option<Vec<u8>>> {
        self.conn
            .query_row(
                "SELECT row_value FROM table_rows
                 WHERE table_name = ?1 AND row_key = ?2",
                params![table, key],
                |row| row.get(0),
            )
            .optional()
    }

    pub fn table_row_count(&self, table: &'static str) -> rusqlite::Result<usize> {
        self.conn
            .query_row(
                "SELECT COUNT(*) FROM table_rows WHERE table_name = ?1",
                params![table],
                |row| row.get::<_, i64>(0),
            )
            .map(|count| count as usize)
    }

    pub fn table_rows(&self, table: &'static str) -> rusqlite::Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let mut stmt = self.conn.prepare(
            "SELECT row_key, row_value FROM table_rows
             WHERE table_name = ?1
             ORDER BY row_key",
        )?;
        let rows = stmt.query_map(params![table], |row| Ok((row.get(0)?, row.get(1)?)))?;
        rows.collect()
    }

    pub fn write_transaction<T>(
        &self,
        apply: impl FnOnce(&Store) -> rusqlite::Result<T>,
    ) -> rusqlite::Result<T> {
        self.conn.execute_batch("BEGIN IMMEDIATE")?;
        let result = apply(self);
        match result {
            Ok(value) => {
                self.conn.execute_batch("COMMIT")?;
                Ok(value)
            }
            Err(err) => {
                let _ = self.conn.execute_batch("ROLLBACK");
                Err(err)
            }
        }
    }

    pub fn insert_event(&self, event: &EventRecord, status: EventStatus) -> rusqlite::Result<bool> {
        let event_id = event_id(&event.canonical_bytes);
        let inserted = self.conn.execute(
            "INSERT OR IGNORE INTO events
                (event_id, timestamp, body_len, event_partition, status, canonical_bytes)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                event_id.to_vec(),
                event.timestamp as i64,
                event.body_len as i64,
                i64::from(event_id[0]),
                status.as_str(),
                &event.canonical_bytes,
            ],
        )?;
        Ok(inserted > 0)
    }

    pub fn event_is_applied(&self, event_id: &EventId) -> rusqlite::Result<bool> {
        self.conn
            .query_row(
                "SELECT 1 FROM events
                 WHERE event_id = ?1 AND status = ?2",
                params![event_id.to_vec(), EventStatus::Applied.as_str()],
                |_| Ok(()),
            )
            .optional()
            .map(|row| row.is_some())
    }

    pub fn insert_dependency_wait(
        &self,
        blocked_by_event_id: &EventId,
        event_id: &EventId,
    ) -> rusqlite::Result<bool> {
        self.conn
            .execute(
                "INSERT OR IGNORE INTO blocked_by_event
                    (blocked_by_event_id, event_id)
                 VALUES (?1, ?2)",
                params![blocked_by_event_id.to_vec(), event_id.to_vec()],
            )
            .map(|changed| changed > 0)
    }

    pub fn next_ready_event(&self) -> rusqlite::Result<Option<EventId>> {
        self.conn
            .query_row(
                "SELECT event_id FROM events
                 WHERE status = ?1
                 ORDER BY timestamp, event_id
                 LIMIT 1",
                params![EventStatus::Ready.as_str()],
                |row| {
                    let id: Vec<u8> = row.get(0)?;
                    vec_to_id(id)
                },
            )
            .optional()
    }

    pub fn set_event_status(
        &self,
        event_id: &EventId,
        from: EventStatus,
        to: EventStatus,
    ) -> rusqlite::Result<bool> {
        self.conn
            .execute(
                "UPDATE events
                 SET status = ?2
                 WHERE event_id = ?1 AND status = ?3",
                params![event_id.to_vec(), to.as_str(), from.as_str()],
            )
            .map(|changed| changed > 0)
    }

    pub fn delete_dependency_waits_for(
        &self,
        blocked_by_event_id: &EventId,
    ) -> rusqlite::Result<usize> {
        self.conn.execute(
            "DELETE FROM blocked_by_event
             WHERE blocked_by_event_id = ?1",
            params![blocked_by_event_id.to_vec()],
        )
    }

    pub fn events_waiting_on(
        &self,
        blocked_by_event_id: &EventId,
    ) -> rusqlite::Result<Vec<EventId>> {
        let mut stmt = self.conn.prepare(
            "SELECT event_id FROM blocked_by_event
             WHERE blocked_by_event_id = ?1
             ORDER BY event_id",
        )?;
        let rows = stmt.query_map(params![blocked_by_event_id.to_vec()], |row| {
            let id: Vec<u8> = row.get(0)?;
            vec_to_id(id)
        })?;
        rows.collect()
    }

    pub fn event_has_dependency_waits(&self, event_id: &EventId) -> rusqlite::Result<bool> {
        self.conn
            .query_row(
                "SELECT 1 FROM blocked_by_event
                 WHERE event_id = ?1
                 LIMIT 1",
                params![event_id.to_vec()],
                |_| Ok(()),
            )
            .optional()
            .map(|row| row.is_some())
    }

    pub fn max_timestamp(&self) -> rusqlite::Result<u64> {
        let value = self
            .conn
            .query_row("SELECT MAX(timestamp) FROM events", [], |row| {
                row.get::<_, Option<i64>>(0)
            })?
            .unwrap_or(0);
        Ok(value.max(0) as u64)
    }

    pub fn event_count(&self) -> rusqlite::Result<usize> {
        self.conn
            .query_row("SELECT COUNT(*) FROM events", [], |row| {
                row.get::<_, i64>(0)
            })
            .map(|count| count as usize)
    }

    pub fn status_counts(&self) -> rusqlite::Result<EventStatusCounts> {
        let ready = self.status_count(EventStatus::Ready)?;
        let blocked = self.status_count(EventStatus::Blocked)?;
        let applied = self.status_count(EventStatus::Applied)?;
        let rejected = self.status_count(EventStatus::Rejected)?;
        let blocked_edges =
            self.conn
                .query_row("SELECT COUNT(*) FROM blocked_by_event", [], |row| {
                    row.get::<_, i64>(0)
                })? as usize;
        Ok(EventStatusCounts {
            ready,
            blocked,
            applied,
            rejected,
            blocked_edges,
        })
    }

    fn status_count(&self, status: EventStatus) -> rusqlite::Result<usize> {
        self.conn
            .query_row(
                "SELECT COUNT(*) FROM events WHERE status = ?1",
                params![status.as_str()],
                |row| row.get::<_, i64>(0),
            )
            .map(|count| count as usize)
    }

    pub fn body_bytes(&self) -> rusqlite::Result<usize> {
        self.conn
            .query_row("SELECT COALESCE(SUM(body_len), 0) FROM events", [], |row| {
                row.get::<_, i64>(0)
            })
            .map(|count| count as usize)
    }

    pub fn event_index_entries(&self) -> rusqlite::Result<Vec<EventIndexEntry>> {
        let mut stmt = self
            .conn
            .prepare("SELECT event_id, event_partition FROM events ORDER BY event_id")?;
        let rows = stmt.query_map([], |row| {
            let id: Vec<u8> = row.get(0)?;
            Ok(EventIndexEntry {
                event_id: vec_to_id(id)?,
                partition: row.get::<_, i64>(1)? as u8,
            })
        })?;
        rows.collect()
    }

    pub fn event_ids_in_partition(&self, partition: u8) -> rusqlite::Result<Vec<EventId>> {
        let mut stmt = self
            .conn
            .prepare("SELECT event_id FROM events WHERE event_partition = ?1 ORDER BY event_id")?;
        let rows = stmt.query_map(params![i64::from(partition)], |row| {
            let id: Vec<u8> = row.get(0)?;
            vec_to_id(id)
        })?;
        rows.collect()
    }

    pub fn has_event(&self, event_id: &EventId) -> rusqlite::Result<bool> {
        self.conn
            .query_row(
                "SELECT 1 FROM events WHERE event_id = ?1",
                params![event_id.to_vec()],
                |_| Ok(()),
            )
            .optional()
            .map(|row| row.is_some())
    }

    pub fn event_bytes(&self, event_id: &EventId) -> rusqlite::Result<Option<Vec<u8>>> {
        self.conn
            .query_row(
                "SELECT canonical_bytes FROM events WHERE event_id = ?1",
                params![event_id.to_vec()],
                |row| row.get(0),
            )
            .optional()
    }

    fn ensure_schema(&self) -> rusqlite::Result<()> {
        self.conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS events (
                event_id BLOB PRIMARY KEY NOT NULL,
                timestamp INTEGER NOT NULL,
                body_len INTEGER NOT NULL,
                event_partition INTEGER NOT NULL,
                status TEXT NOT NULL,
                canonical_bytes BLOB NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_events_partition
                ON events(event_partition, event_id);
            CREATE INDEX IF NOT EXISTS idx_events_status
                ON events(status, timestamp, event_id);
            CREATE TABLE IF NOT EXISTS blocked_by_event (
                blocked_by_event_id BLOB NOT NULL,
                event_id BLOB NOT NULL,
                PRIMARY KEY (blocked_by_event_id, event_id)
            );
            CREATE INDEX IF NOT EXISTS idx_blocked_by_event_event
                ON blocked_by_event(event_id, blocked_by_event_id);

            CREATE TABLE IF NOT EXISTS table_rows (
                table_name TEXT NOT NULL,
                row_key BLOB NOT NULL,
                row_value BLOB NOT NULL,
                PRIMARY KEY (table_name, row_key)
            );
            ",
        )
    }
}

pub fn event_id(bytes: &[u8]) -> EventId {
    *blake3::hash(bytes).as_bytes()
}

fn vec_to_id(bytes: Vec<u8>) -> rusqlite::Result<EventId> {
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        rusqlite::Error::FromSqlConversionFailure(
            0,
            Type::Blob,
            Box::new(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("expected 32-byte event id, got {}", bytes.len()),
            )),
        )
    })
}
