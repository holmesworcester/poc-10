//! Intent handler contract.

use crate::core::facts::{Fact, FactId, FactScope};
use crate::core::intents::{AtomicIntent, Intent};
use crate::core::store::{Store, TableName};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Default)]
pub struct HandlerContext {
    facts: BTreeMap<FactId, Fact>,
}

impl HandlerContext {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_facts(facts: impl IntoIterator<Item = Fact>) -> Self {
        Self {
            facts: facts
                .into_iter()
                .map(|fact| (fact.id, fact))
                .collect::<BTreeMap<_, _>>(),
        }
    }

    pub fn fact(&self, id: &FactId) -> Option<&Fact> {
        self.facts.get(id)
    }

    pub fn require_fact(&self, id: &FactId) -> Result<&Fact, String> {
        self.fact(id)
            .ok_or_else(|| format!("handler context missing fact {id:?}"))
    }

    pub fn require_non_local_fact_bytes(&self, id: &FactId) -> Result<&[u8], String> {
        let fact = self.require_fact(id)?;
        if fact.scope == FactScope::Local {
            return Err(format!("handler context refused local fact {id:?}"));
        }
        Ok(&fact.bytes)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HandlerOutput {
    pub facts: Vec<Fact>,
    pub intents: Vec<Intent>,
}

impl HandlerOutput {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn fact(mut self, fact: Fact) -> Self {
        self.facts.push(fact);
        self
    }

    pub fn intent(mut self, intent: Intent) -> Self {
        self.intents.push(intent);
        self
    }
}

pub trait IntentHandler {
    fn accepts(&self, _intent: &Intent) -> bool {
        true
    }

    fn handle(&self, intent: &Intent, context: &HandlerContext) -> Result<HandlerOutput, String>;
}

pub struct RowIntentHandler<'a> {
    store: &'a Store,
    allowed_tables: &'a [TableName],
}

impl<'a> RowIntentHandler<'a> {
    pub fn new(store: &'a Store, allowed_tables: &'a [TableName]) -> Self {
        Self {
            store,
            allowed_tables,
        }
    }
}

impl IntentHandler for RowIntentHandler<'_> {
    fn accepts(&self, intent: &Intent) -> bool {
        matches!(intent.kind.as_str(), "put_row" | "delete_row")
    }

    fn handle(&self, intent: &Intent, _context: &HandlerContext) -> Result<HandlerOutput, String> {
        match AtomicIntent::from_intent(intent, self.allowed_tables)? {
            AtomicIntent::PutRow(row) => {
                self.store
                    .insert_table_rows(vec![row])
                    .map_err(|err| format!("apply put_row intent: {err}"))?;
            }
            AtomicIntent::DeleteRow(delete) => {
                self.store
                    .delete_table_rows(delete.table, vec![delete.key])
                    .map_err(|err| format!("apply delete_row intent: {err}"))?;
            }
        }
        Ok(HandlerOutput::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::event_bus::EventBus;
    use crate::core::facts::FactScope;
    use crate::core::intents::{IntentExecution, IntentKind, TableDelete};
    use crate::core::store::{Schema, TableRow};

    const TEST_TABLE: TableName = TableName::new("handler.rows");

    #[test]
    fn handler_output_feeds_facts_and_intents_back_to_core() {
        let fact = Fact::new(FactScope::Local, 7, b"bytes".to_vec());
        let intent = Intent::new(
            IntentKind::new("followup").unwrap(),
            IntentExecution::Deferred,
            b"k",
            b"p",
        );
        let output = HandlerOutput::new().fact(fact).intent(intent);

        assert_eq!(output.facts.len(), 1);
        assert_eq!(output.intents.len(), 1);
    }

    #[test]
    fn handler_context_exposes_only_exact_scoped_fact_lookup() {
        let fact = Fact::new(FactScope::Local, 7, b"bytes".to_vec());
        let missing = [9; 32];

        assert!(HandlerContext::new().fact(&fact.id).is_none());
        let context = HandlerContext::with_facts([fact.clone()]);
        assert_eq!(context.require_fact(&fact.id).expect("fact"), &fact);
        assert!(context.fact(&missing).is_none());
    }

    #[test]
    fn row_intent_handler_applies_put_and_delete_through_registered_tables() {
        let store = Store::open_memory_with_schemas(&[Schema::durable_row_table(
            "handler.rows.v1",
            TEST_TABLE,
        )])
        .expect("open store");
        let handler = RowIntentHandler::new(&store, &[TEST_TABLE]);
        let mut bus = EventBus::new();

        bus.submit_intent(
            AtomicIntent::PutRow(TableRow {
                table: TEST_TABLE,
                key: b"row".to_vec(),
                value: b"value".to_vec(),
            })
            .into_intent(),
        )
        .expect("submit put");
        let put = bus
            .dispatch_intents(&handler, &HandlerContext::new(), 10)
            .expect("dispatch put");
        assert_eq!(put.handled, 1);
        assert_eq!(
            store.table_rows(TEST_TABLE).expect("rows"),
            vec![(b"row".to_vec(), b"value".to_vec())]
        );

        bus.submit_intent(
            TableDelete {
                table: TEST_TABLE,
                key: b"row".to_vec(),
            }
            .into_intent(),
        )
        .expect("submit delete");
        let delete = bus
            .dispatch_intents(&handler, &HandlerContext::new(), 10)
            .expect("dispatch delete");
        assert_eq!(delete.handled, 1);
        assert!(store.table_rows(TEST_TABLE).expect("rows").is_empty());
    }

    #[test]
    fn row_intent_handler_error_leaves_intent_queued() {
        let store = Store::open_memory_with_schemas(&[Schema::durable_row_table(
            "handler.rows.v1",
            TEST_TABLE,
        )])
        .expect("open store");
        store
            .insert_table_rows(vec![TableRow {
                table: TEST_TABLE,
                key: b"row".to_vec(),
                value: b"old".to_vec(),
            }])
            .expect("seed row");
        let handler = RowIntentHandler::new(&store, &[TEST_TABLE]);
        let mut bus = EventBus::new();

        bus.submit_intent(
            AtomicIntent::PutRow(TableRow {
                table: TEST_TABLE,
                key: b"row".to_vec(),
                value: b"new".to_vec(),
            })
            .into_intent(),
        )
        .expect("submit conflicting put");
        let err = bus
            .dispatch_intents(&handler, &HandlerContext::new(), 10)
            .expect_err("conflicting put fails");

        assert!(err.contains("apply put_row intent"), "{err}");
        assert_eq!(bus.intents().len(), 1);
        assert_eq!(
            store.table_rows(TEST_TABLE).expect("rows"),
            vec![(b"row".to_vec(), b"old".to_vec())]
        );
    }
}
