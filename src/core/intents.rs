//! Intent queues and handler contract types.
//!
//! An intent is idempotent queued work. Core persists durable intents in
//! `intents`, stores ephemeral intents in `local_intents`, and dispatches
//! both through the same handler contract. The intent kind selects a handler;
//! the key deduplicates equivalent work of that kind; the payload is opaque
//! bytes owned by the protocol module that registered the handler.
//!
//! Intents are the runtime's "do this later" language. Projection emits an
//! intent when it discovers work that should not run inside a projector, such
//! as sending network bytes, materializing a follow-up fact, or purging derived
//! state. Commands can also emit intents when user input should enqueue
//! asynchronous work. Dispatch later loads the handler, builds its narrow
//! context, and commits the handler's `RuntimeEffects` atomically with queue
//! consumption.
//!
//! Durable and ephemeral intents share identity and payload rules. Durable
//! intents survive process restarts and participate in replay. Ephemeral
//! intents are connection-local work, useful for inbound frames and other
//! process-scoped signals that should disappear on restart. If the same durable
//! identity is handled, dispatch removes the matching ephemeral duplicate so
//! local work does not repeat accepted durable work.
//!
//! Handlers are reactive runtime code, not user-facing commands. They may ask
//! core to load specific facts and may use query helpers through `Db`, then
//! return `RuntimeEffects` for runtime workers to commit atomically. Missing
//! declared inputs or semantic violations are handler errors: dispatch does not
//! commit output or consume the queue row. Runtime effect validation rejects any
//! emitted intent whose kind is not registered by the active runtime.

use crate::core::db::Db;
use crate::core::effects::RuntimeEffects;
use crate::core::facts::{Fact, FactId, FactScope};
use std::collections::BTreeMap;
use std::fmt;

pub use crate::core::db::{RowMutation, TableDeleteWhere, TableInsert, TypedTableSchema, Value};

/// Stable queue routing key for an intent handler.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IntentKind(String);

impl IntentKind {
    /// Build a stable handler routing key.
    ///
    /// Intent kinds are persisted and compared across runs, so they use the
    /// same lowercase ASCII vocabulary rule as context roles and scope kinds.
    pub fn new(value: impl Into<String>) -> Result<Self, String> {
        let value = value.into();
        if value.is_empty() {
            return Err("intent kind cannot be empty".to_string());
        }
        if !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        {
            return Err(format!("invalid intent kind {value:?}"));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One idempotent unit of handler work.
///
/// `(kind, key)` is the queue identity. Re-emitting the same payload is a
/// no-op; re-emitting a different payload for the same identity is rejected by
/// runtime effect validation because it would make repeated dispatch ambiguous.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Intent {
    /// Handler routing key.
    pub kind: IntentKind,
    /// Idempotence key within `kind`.
    pub key: Vec<u8>,
    /// Opaque handler-owned payload bytes.
    pub payload: Vec<u8>,
}

/// One raw row in the durable or local intent work table.
///
/// `core::intents` owns converting between this mechanical queue row and an
/// `Intent`; `handle_intent` owns the SQL lifecycle for rows with this shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct IntentWorkRow {
    pub(crate) kind: String,
    pub(crate) idempotence_key: Vec<u8>,
    pub(crate) payload: Vec<u8>,
}

impl IntentWorkRow {
    pub(crate) fn new(
        kind: impl Into<String>,
        idempotence_key: impl Into<Vec<u8>>,
        payload: impl Into<Vec<u8>>,
    ) -> Self {
        Self {
            kind: kind.into(),
            idempotence_key: idempotence_key.into(),
            payload: payload.into(),
        }
    }
}

impl Intent {
    pub fn new(kind: IntentKind, key: impl Into<Vec<u8>>, payload: impl Into<Vec<u8>>) -> Self {
        Self {
            kind,
            key: key.into(),
            payload: payload.into(),
        }
    }

    pub(crate) fn work_row(&self) -> IntentWorkRow {
        IntentWorkRow::new(
            self.kind.as_str().to_string(),
            self.key.clone(),
            self.payload.clone(),
        )
    }

    pub(crate) fn from_work_row(row: IntentWorkRow) -> Result<Self, String> {
        let kind = IntentKind::new(row.kind)
            .map_err(|err| format!("invalid queued intent kind: {err}"))?;
        Ok(Self::new(kind, row.idempotence_key, row.payload))
    }
}

// === Intent handler contract ===

/// Fact ids requested by a handler before it runs.
pub type HandlerFactId = FactId;

/// Handler failure before dispatch commits effects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandlerError(String);

impl HandlerError {
    pub fn fatal(reason: impl Into<String>) -> Self {
        Self(reason.into())
    }

    pub fn contains(&self, needle: &str) -> bool {
        self.0.contains(needle)
    }
}

impl fmt::Display for HandlerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for HandlerError {}

impl From<String> for HandlerError {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl From<&str> for HandlerError {
    fn from(value: &str) -> Self {
        Self(value.to_string())
    }
}

/// Result returned by an intent handler before core commits its effects.
pub type HandlerResult = Result<RuntimeEffects, HandlerError>;

/// Runtime mode visible to intent handlers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandlerMode {
    /// Normal live dispatch after commands, projection, daemon ticks, or IO.
    Live,
    /// Replay dispatch while derived runtime state is being rebuilt.
    Replay,
}

impl Default for HandlerMode {
    fn default() -> Self {
        Self::Live
    }
}

impl HandlerMode {
    /// Whether this dispatch is part of replay.
    pub fn is_replay(self) -> bool {
        matches!(self, Self::Replay)
    }
}

/// Read-only inputs handed to an intent handler.
///
/// Durable and local queue dispatch both build this immediately before
/// `handle`.
/// The handler gets only the facts it requested plus the database for explicit
/// query helpers; it cannot reach runtime workers directly.
#[derive(Clone, Default)]
pub struct HandlerContext<'a> {
    facts: BTreeMap<FactId, Fact>,
    db: Option<&'a Db>,
    mode: HandlerMode,
}

impl fmt::Debug for HandlerContext<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HandlerContext")
            .field("facts", &self.facts)
            .field("has_db", &self.db.is_some())
            .field("mode", &self.mode)
            .finish()
    }
}

impl<'a> HandlerContext<'a> {
    /// Build an empty handler context, mostly for tests.
    pub fn new() -> Self {
        Self::default()
    }

    /// Build context from preloaded facts.
    pub fn with_facts(facts: impl IntoIterator<Item = Fact>) -> Self {
        Self {
            facts: facts.into_iter().map(|fact| (fact.id, fact)).collect(),
            db: None,
            mode: HandlerMode::Live,
        }
    }

    /// Attach the database handle used by query helpers.
    pub fn with_db(mut self, db: &'a Db) -> Self {
        self.db = Some(db);
        self
    }

    /// Mark whether this handler invocation is running in live or replay mode.
    pub fn with_mode(mut self, mode: HandlerMode) -> Self {
        self.mode = mode;
        self
    }

    /// Return the runtime mode for this handler invocation.
    pub fn mode(&self) -> HandlerMode {
        self.mode
    }

    /// Whether this handler invocation is part of replay.
    pub fn is_replay(&self) -> bool {
        self.mode.is_replay()
    }

    /// Borrow the database or return a fatal handler error if none was attached.
    pub fn db(&self) -> Result<&Db, HandlerError> {
        self.db
            .ok_or_else(|| HandlerError::fatal("handler context missing db"))
    }

    /// Return a preloaded fact by id.
    pub fn fact(&self, id: &FactId) -> Option<&Fact> {
        self.facts.get(id)
    }

    /// Iterate over all preloaded facts.
    pub fn facts(&self) -> impl Iterator<Item = &Fact> {
        self.facts.values()
    }

    /// Require a preloaded fact.
    pub fn require_fact(&self, id: &FactId) -> Result<&Fact, HandlerError> {
        self.fact(id)
            .ok_or_else(|| HandlerError::fatal(format!("handler context missing fact {id:?}")))
    }

    /// Require non-local fact bytes for outbound or sync-visible work.
    ///
    /// Local facts are deliberately rejected here so handlers do not accidentally
    /// send database-private material through generic protocol paths.
    pub fn require_non_local_fact_bytes(&self, id: &FactId) -> Result<&[u8], HandlerError> {
        let fact = self.require_fact(id)?;
        if fact.scope == FactScope::Local {
            return Err(HandlerError::fatal(format!(
                "handler context refused local fact {id:?}"
            )));
        }
        Ok(&fact.bytes)
    }
}

/// A protocol handler for one or more intent kinds.
pub trait IntentHandler {
    /// Fact ids core should load before calling `handle`.
    ///
    /// Missing facts do not fail dispatch here; a handler that requires a
    /// missing declared fact returns a handler error and dispatch leaves the row
    /// queued without committing output.
    fn input_fact_ids(&self, _intent: &Intent) -> Result<Vec<HandlerFactId>, String> {
        Ok(Vec::new())
    }

    /// Run one intent against its read-only context and return uncommitted effects.
    fn handle(&self, intent: &Intent, context: &HandlerContext<'_>) -> HandlerResult;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::db::TableName;
    use rusqlite::types::Value as SqliteValue;

    const TEST_TABLE: TableName = TableName::new("test.rows");

    #[test]
    fn intent_kind_uses_registry_safe_vocabulary() {
        assert!(IntentKind::new("put_row").is_ok());
        assert!(IntentKind::new("PutRow").is_err());
    }

    #[test]
    fn intent_carries_idempotence_key() {
        let intent = Intent::new(
            IntentKind::new("materialize").unwrap(),
            b"same-work",
            b"payload",
        );
        assert_eq!(intent.key, b"same-work");
    }

    #[test]
    fn runtime_effects_track_row_mutations_separately_from_intents() {
        let insert = TableInsert {
            table: TEST_TABLE,
            columns: &["owner", "value"],
            values: vec![
                Value::Bytes(b"row-key".to_vec()),
                Value::Bytes(b"a".to_vec()),
            ],
        };
        let delete = TableDeleteWhere {
            table: TEST_TABLE,
            columns: &["owner"],
            values: vec![Value::Bytes(b"row-key".to_vec())],
        };

        let output = RuntimeEffects::new()
            .row_mutation(RowMutation::InsertValues(insert.clone()))
            .row_mutation(RowMutation::DeleteWhere(delete.clone()))
            .intent(Intent::new(
                IntentKind::new("followup").unwrap(),
                b"key",
                b"payload",
            ));

        assert_eq!(
            output.row_mutations,
            vec![
                RowMutation::InsertValues(insert),
                RowMutation::DeleteWhere(delete)
            ]
        );
        assert_eq!(output.intents.len(), 1);
        assert!(output.local_intents.is_empty());
    }

    #[test]
    fn typed_table_values_convert_to_sqlite_bind_values() {
        assert_eq!(
            Value::Bytes(b"bytes".to_vec()).as_sqlite_value().unwrap(),
            SqliteValue::Blob(b"bytes".to_vec())
        );
        assert_eq!(
            Value::U64(42).as_sqlite_value().unwrap(),
            SqliteValue::Integer(42)
        );
        assert_eq!(
            Value::Bool(true).as_sqlite_value().unwrap(),
            SqliteValue::Integer(1)
        );
    }

    #[test]
    fn typed_table_u64_values_must_fit_sqlite_integer_range() {
        let err = Value::U64(i64::MAX as u64 + 1)
            .as_sqlite_value()
            .expect_err("oversized u64 should not bind");

        assert!(
            err.to_string()
                .contains("SQL value exceeds SQLite integer range"),
            "{err}"
        );
    }
}
