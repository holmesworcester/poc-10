//! Intent queues and handler contract types.
//!
//! An intent is one queued unit of handler work. Core persists durable intents
//! in `intents`, stores ephemeral intents in `local_intents`, and dispatches
//! both through the same handler contract. The intent kind selects a handler;
//! the key is handler-owned semantic metadata; the payload is opaque bytes
//! owned by the protocol module that registered the handler. Context fact ids
//! are core-visible queue metadata attached beside the payload so dispatch can
//! load exact committed facts without parsing handler bytes.
//!
//! Intents are the runtime's "do this later" language. Projection emits an
//! intent when it discovers work that should not run inside a projector, such
//! as sending network bytes, materializing a follow-up fact, or purging derived
//! state. Commands can also emit intents when user input should enqueue
//! asynchronous work. Dispatch later loads the handler, builds its narrow
//! context, and commits the handler's `RuntimeEffects` atomically with queue
//! consumption.
//!
//! Durable intents survive process restarts and participate in replay.
//! Ephemeral intents are connection-local work, useful for inbound frames and
//! other process-scoped signals that should disappear on restart. Each queued
//! row is a distinct work item; duplicate suppression belongs in facts,
//! protocol rows, network queues, or handler-local state when a handler needs
//! backpressure.
//!
//! Handlers are reactive runtime code, not user-facing commands. They receive
//! facts declared by the queued intent, use the transaction-local `Db` for
//! handler-owned SQL, and return `RuntimeEffects` for runtime workers to commit
//! atomically. Handler errors roll back handler-owned SQL to dispatch's
//! savepoint and commit only queue consumption. Runtime effect validation rejects
//! any emitted intent whose kind is not registered by the active runtime; those
//! validation errors abort the outer transaction, leaving the queue row in place.

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

/// One unit of handler work.
///
/// Core uses `kind` for routing and treats every enqueued row as distinct work.
/// The `handler_key` remains available to handlers as a stable semantic key for
/// their own protocol checks, payload validation, and row writes. Context fact
/// ids are exact inputs that core loads into `HandlerContext` before calling
/// the handler; handlers still decode the payload to interpret what those facts
/// mean.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Intent {
    /// Handler routing key.
    pub kind: IntentKind,
    /// Handler-owned semantic key within `kind`.
    pub handler_key: Vec<u8>,
    /// Opaque handler-owned payload bytes.
    pub payload: Vec<u8>,
    /// Exact fact inputs dispatch should preload for the handler.
    pub context_fact_ids: Vec<FactId>,
}

impl Intent {
    pub fn new(
        kind: IntentKind,
        handler_key: impl Into<Vec<u8>>,
        payload: impl Into<Vec<u8>>,
    ) -> Self {
        Self {
            kind,
            handler_key: handler_key.into(),
            payload: payload.into(),
            context_fact_ids: Vec::new(),
        }
    }

    pub fn with_context_fact_ids(mut self, fact_ids: impl IntoIterator<Item = FactId>) -> Self {
        self.context_fact_ids = fact_ids.into_iter().collect();
        self
    }
}

// === Intent handler contract ===

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

/// Inputs handed to an intent handler.
///
/// Durable and local queue dispatch both build this immediately before
/// `handle`.
/// The handler gets only the facts declared by the queued intent plus the
/// transaction-local database handle for explicit handler-owned SQL; it cannot
/// reach runtime workers directly.
#[derive(Clone)]
pub struct HandlerContext<'a> {
    facts: BTreeMap<FactId, Fact>,
    db: &'a Db,
    mode: HandlerMode,
}

impl fmt::Debug for HandlerContext<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HandlerContext")
            .field("facts", &self.facts)
            .field("mode", &self.mode)
            .finish()
    }
}

impl<'a> HandlerContext<'a> {
    /// Build a handler context with no attached facts.
    pub fn new(db: &'a Db) -> Self {
        Self::with_facts(db, [])
    }

    /// Build context from preloaded facts.
    pub fn with_facts(db: &'a Db, facts: impl IntoIterator<Item = Fact>) -> Self {
        Self {
            facts: facts.into_iter().map(|fact| (fact.id, fact)).collect(),
            db,
            mode: HandlerMode::Live,
        }
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

    /// Borrow the transaction-local database.
    pub fn db(&self) -> &Db {
        self.db
    }

    /// Return a preloaded fact by id.
    pub fn fact(&self, id: &FactId) -> Option<&Fact> {
        self.facts.get(id)
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
    /// Run one intent against its context and return uncommitted effects.
    fn handle(&self, intent: &Intent, context: &HandlerContext<'_>) -> HandlerResult;
}

// === Tests ===
// Ordered most-central-first: effect/intent separation before value-encoding guards.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::db::TableName;
    use rusqlite::types::Value as SqliteValue;

    const TEST_TABLE: TableName = TableName::new("test.rows");

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
    fn intent_carries_handler_key() {
        let intent = Intent::new(
            IntentKind::new("materialize").unwrap(),
            b"same-work",
            b"payload",
        );
        assert_eq!(intent.handler_key, b"same-work");
    }

    #[test]
    fn intent_kind_uses_registry_safe_vocabulary() {
        assert!(IntentKind::new("put_row").is_ok());
        assert!(IntentKind::new("PutRow").is_err());
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
