//! Intent queues and handler contract types.
//!
//! An intent is idempotent queued work. Core persists durable intents in
//! `intents`, stores ephemeral intents in `local_intents`, and dispatches
//! both through the same handler contract. The intent kind selects a handler;
//! the key deduplicates equivalent work of that kind; the payload is opaque
//! bytes owned by the protocol module that registered the handler.
//!
//! Handlers are reactive runtime code, not user-facing commands. They may ask
//! core to load specific facts and may use query helpers through `Store`, then
//! return `PipelineEffects` for the pipeline to commit atomically. If a handler
//! needs to wait for missing input, return `retry_intent`; if it observes a
//! semantic violation that should not be retried, return a fatal error.

use crate::core::effects::PipelineEffects;
use crate::core::facts::{Fact, FactId, FactScope};
use crate::core::select::Value as SqlValue;
use crate::core::store::{Store, TableName, TableRow};
use std::collections::BTreeMap;
use std::fmt;

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
/// the pipeline because it would make retries ambiguous.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Intent {
    /// Handler routing key.
    pub kind: IntentKind,
    /// Idempotence key within `kind`.
    pub key: Vec<u8>,
    /// Opaque handler-owned payload bytes.
    pub payload: Vec<u8>,
}

impl Intent {
    pub fn new(kind: IntentKind, key: impl Into<Vec<u8>>, payload: impl Into<Vec<u8>>) -> Self {
        Self {
            kind,
            key: key.into(),
            payload: payload.into(),
        }
    }
}

/// Delete one opaque row by key from a row table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TableDelete {
    /// Table to delete from.
    pub table: TableName,
    /// Opaque row key to delete.
    pub key: Vec<u8>,
}

/// Insert a typed-table row by column values.
///
/// This is for schema-declared tables whose key is not the generic
/// `row_key/row_value` shape. The insert is idempotent only when an existing
/// row has exactly the same column values. To change typed projection state,
/// emit a matching `DeleteWhere` before the replacement insert.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TableInsert {
    /// Typed table to insert into.
    pub table: TableName,
    /// Columns supplied by this insert.
    pub columns: &'static [&'static str],
    /// Values corresponding to `columns`.
    pub values: Vec<SqlValue>,
}

/// Delete typed-table rows matching all supplied columns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TableDeleteWhere {
    /// Typed table to delete from.
    pub table: TableName,
    /// Predicate columns.
    pub columns: &'static [&'static str],
    /// Predicate values corresponding to `columns`.
    pub values: Vec<SqlValue>,
}

/// Row-level mutations a command, projector, or handler can request.
///
/// Core validates the target table against the runtime description before any
/// mutation commits. The module that constructs the mutation owns the row
/// layout and semantic meaning.
///
/// `PutRow` is an idempotent insert into an opaque key/value row table, not an
/// upsert. Re-emitting the same key with different bytes is a conflict. Use
/// typed-table mutations when projection needs explicit delete-then-insert
/// state changes for the same logical row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RowMutation {
    PutRow(TableRow),
    DeleteRow(TableDelete),
    InsertValues(TableInsert),
    DeleteWhere(TableDeleteWhere),
}

// === Intent handler contract ===

/// Fact ids requested by a handler before it runs.
pub type HandlerFactId = FactId;

/// Handler failure mode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandlerError {
    /// Transient failure. Dispatch leaves the intent queued for another pass.
    Retry(String),
    /// Permanent failure. Dispatch reports the error and does not commit output.
    Fatal(String),
}

impl HandlerError {
    pub fn fatal(reason: impl Into<String>) -> Self {
        Self::Fatal(reason.into())
    }

    pub fn retry(reason: impl Into<String>) -> Self {
        Self::Retry(reason.into())
    }

    pub fn contains(&self, needle: &str) -> bool {
        self.to_string().contains(needle)
    }
}

impl fmt::Display for HandlerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HandlerError::Retry(reason) | HandlerError::Fatal(reason) => {
                formatter.write_str(reason)
            }
        }
    }
}

impl std::error::Error for HandlerError {}

impl From<String> for HandlerError {
    fn from(value: String) -> Self {
        Self::Fatal(value)
    }
}

impl From<&str> for HandlerError {
    fn from(value: &str) -> Self {
        Self::Fatal(value.to_string())
    }
}

/// Result returned by an intent handler before core commits its effects.
pub type HandlerResult = Result<PipelineEffects, HandlerError>;

/// Mark a handler failure as transient so dispatch leaves the intent queued.
pub fn retry_intent(reason: impl Into<String>) -> HandlerError {
    HandlerError::retry(reason)
}

/// Extract the retry reason when a handler asked dispatch to keep the row queued.
pub fn retry_intent_reason(err: &HandlerError) -> Option<&str> {
    match err {
        HandlerError::Retry(reason) => Some(reason),
        HandlerError::Fatal(_) => None,
    }
}

/// Read-only inputs handed to an intent handler.
///
/// Durable and local queue dispatch both build this immediately before
/// `handle`.
/// The handler gets only the facts it requested plus the store for explicit
/// query helpers; it cannot reach the runtime pipelines directly.
#[derive(Clone, Default)]
pub struct HandlerContext<'a> {
    facts: BTreeMap<FactId, Fact>,
    store: Option<&'a Store>,
}

impl fmt::Debug for HandlerContext<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HandlerContext")
            .field("facts", &self.facts)
            .field("has_store", &self.store.is_some())
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
            store: None,
        }
    }

    /// Attach the store handle used by query helpers.
    pub fn with_store(mut self, store: &'a Store) -> Self {
        self.store = Some(store);
        self
    }

    /// Borrow the store or return a fatal handler error if none was attached.
    pub fn store(&self) -> Result<&Store, HandlerError> {
        self.store
            .ok_or_else(|| HandlerError::fatal("handler context missing store"))
    }

    /// Return a preloaded fact by id.
    pub fn fact(&self, id: &FactId) -> Option<&Fact> {
        self.facts.get(id)
    }

    /// Iterate over all preloaded facts.
    pub fn facts(&self) -> impl Iterator<Item = &Fact> {
        self.facts.values()
    }

    /// Require a preloaded fact, marking absence as retryable.
    pub fn require_fact(&self, id: &FactId) -> Result<&Fact, HandlerError> {
        self.fact(id)
            .ok_or_else(|| HandlerError::retry(format!("handler context missing fact {id:?}")))
    }

    /// Require non-local fact bytes for outbound or sync-visible work.
    ///
    /// Local facts are deliberately rejected here so handlers do not accidentally
    /// send store-private material through generic protocol paths.
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
    /// Missing facts do not fail dispatch here; the handler can call
    /// `require_fact` and return `Retry` if the missing input is expected to
    /// arrive later.
    fn input_fact_ids(&self, _intent: &Intent) -> Result<Vec<HandlerFactId>, String> {
        Ok(Vec::new())
    }

    /// Run one intent against its read-only context and return uncommitted effects.
    fn handle(&self, intent: &Intent, context: &HandlerContext<'_>) -> HandlerResult;
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn pipeline_effects_track_row_mutations_separately_from_intents() {
        let row_a = TableRow {
            table: TEST_TABLE,
            key: b"row-key".to_vec(),
            value: b"value-a".to_vec(),
        };
        let delete = TableDelete {
            table: TEST_TABLE,
            key: b"row-key".to_vec(),
        };

        let output = PipelineEffects::new()
            .row_mutation(RowMutation::PutRow(row_a.clone()))
            .row_mutation(RowMutation::DeleteRow(delete.clone()))
            .intent(Intent::new(
                IntentKind::new("followup").unwrap(),
                b"key",
                b"payload",
            ));

        assert_eq!(
            output.row_mutations,
            vec![RowMutation::PutRow(row_a), RowMutation::DeleteRow(delete)]
        );
        assert_eq!(output.intents.len(), 1);
        assert!(output.local_intents.is_empty());
    }
}
