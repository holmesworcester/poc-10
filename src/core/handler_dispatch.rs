//! Intent handler contract.

use crate::core::facts::{Fact, FactId, FactScope};
use crate::core::intents::Intent;
use crate::core::store::Store;
use std::collections::BTreeMap;
use std::fmt;

pub type HandlerFactId = FactId;
pub const RETRY_INTENT_PREFIX: &str = "retry intent: ";

pub fn retry_intent(reason: impl AsRef<str>) -> String {
    format!("{RETRY_INTENT_PREFIX}{}", reason.as_ref())
}

pub fn retry_intent_reason(err: &str) -> Option<&str> {
    err.strip_prefix(RETRY_INTENT_PREFIX)
}

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
            facts: facts
                .into_iter()
                .map(|fact| (fact.id, fact))
                .collect::<BTreeMap<_, _>>(),
            store: None,
        }
    }

    pub fn with_store(mut self, store: &'a Store) -> Self {
        self.store = Some(store);
        self
    }

    pub fn store(&self) -> Result<&Store, String> {
        self.store
            .ok_or_else(|| "handler context missing store".to_string())
    }

    pub fn fact(&self, id: &FactId) -> Option<&Fact> {
        self.facts.get(id)
    }

    pub fn facts(&self) -> impl Iterator<Item = &Fact> {
        self.facts.values()
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
    pub purged_facts: Vec<FactId>,
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

    pub fn purge_fact(mut self, id: FactId) -> Self {
        self.purged_facts.push(id);
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

    fn input_fact_ids(&self, _intent: &Intent) -> Result<Vec<HandlerFactId>, String> {
        Ok(Vec::new())
    }

    fn handle(
        &self,
        intent: &Intent,
        context: &HandlerContext<'_>,
    ) -> Result<HandlerOutput, String>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::facts::FactScope;
    use crate::core::intents::{IntentExecution, IntentKind};

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
        assert!(output.purged_facts.is_empty());
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
}
