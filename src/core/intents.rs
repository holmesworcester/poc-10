//! Intent and handler-output types.

use crate::core::facts::{Fact, FactId, FactScope};
use crate::core::store::{Store, TableName, TableRow};
use std::collections::BTreeMap;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IntentKind(String);

impl IntentKind {
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Intent {
    pub kind: IntentKind,
    pub key: Vec<u8>,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TableDelete {
    pub table: TableName,
    pub key: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RowMutation {
    PutRow(TableRow),
    DeleteRow(TableDelete),
}

// === Intent handler contract ===

/// Fact ids requested by a handler before it runs.
pub type HandlerFactId = FactId;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandlerError {
    Retry(String),
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

pub type HandlerResult = Result<HandlerOutput, HandlerError>;

/// Mark a handler failure as transient so dispatch leaves the intent queued.
pub fn retry_intent(reason: impl Into<String>) -> HandlerError {
    HandlerError::retry(reason)
}

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
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_facts(facts: impl IntoIterator<Item = Fact>) -> Self {
        Self {
            facts: facts.into_iter().map(|fact| (fact.id, fact)).collect(),
            store: None,
        }
    }

    pub fn with_store(mut self, store: &'a Store) -> Self {
        self.store = Some(store);
        self
    }

    pub fn store(&self) -> Result<&Store, HandlerError> {
        self.store
            .ok_or_else(|| HandlerError::fatal("handler context missing store"))
    }

    pub fn fact(&self, id: &FactId) -> Option<&Fact> {
        self.facts.get(id)
    }

    pub fn facts(&self) -> impl Iterator<Item = &Fact> {
        self.facts.values()
    }

    pub fn require_fact(&self, id: &FactId) -> Result<&Fact, HandlerError> {
        self.fact(id)
            .ok_or_else(|| HandlerError::retry(format!("handler context missing fact {id:?}")))
    }

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

/// Handler output feeds facts, purges, and follow-up intents back into the
/// same dispatch transaction.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HandlerOutput {
    pub facts: Vec<Fact>,
    pub purged_facts: Vec<FactId>,
    pub row_mutations: Vec<RowMutation>,
    pub intents: Vec<Intent>,
    pub local_intents: Vec<Intent>,
}

impl HandlerOutput {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn fact(mut self, fact: Fact) -> Self {
        self.facts.push(fact);
        self
    }

    pub fn purge_fact(mut self, id: FactId) -> Self {
        self.purged_facts.push(id);
        self
    }

    pub fn row_mutation(mut self, mutation: RowMutation) -> Self {
        self.row_mutations.push(mutation);
        self
    }

    pub fn intent(mut self, intent: Intent) -> Self {
        self.intents.push(intent);
        self
    }

    pub fn local_intent(mut self, intent: Intent) -> Self {
        self.local_intents.push(intent);
        self
    }
}

/// A protocol handler for one or more intent kinds.
pub trait IntentHandler {
    fn input_fact_ids(&self, _intent: &Intent) -> Result<Vec<HandlerFactId>, String> {
        Ok(Vec::new())
    }

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
    fn handler_output_tracks_row_mutations_separately_from_intents() {
        let row_a = TableRow {
            table: TEST_TABLE,
            key: b"row-key".to_vec(),
            value: b"value-a".to_vec(),
        };
        let delete = TableDelete {
            table: TEST_TABLE,
            key: b"row-key".to_vec(),
        };

        let output = HandlerOutput::new()
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
