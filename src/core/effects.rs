//! Shared side effects committed by runtime work.
//!
//! Commands, projection, and intent handlers all reduce to this language before
//! the SQL pipeline commits their output.

use crate::core::facts::{Fact, FactId};
use crate::core::intents::{Intent, RowMutation};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PipelineEffects {
    pub facts: Vec<Fact>,
    pub purged_facts: Vec<FactId>,
    pub row_mutations: Vec<RowMutation>,
    pub intents: Vec<Intent>,
    pub local_intents: Vec<Intent>,
}

impl PipelineEffects {
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
