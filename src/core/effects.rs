//! Shared side-effect language committed by runtime work.
//!
//! Projection and intent handlers reduce to this structure before the SQL
//! runtime workers commit their output. The structure is intentionally mechanical: it
//! names facts to admit, facts to purge, row mutations, durable intents,
//! ephemeral intents, and candidate facts. It does not contain
//! callbacks, open sockets, command receipts, or protocol-specific execution
//! state.
//!
//! If a new kind of runtime effect needs atomic commit with projection or
//! intent dispatch, add it here and teach `pipeline::commit_effects` how to
//! validate and write it. If it is only display data for a command, keep it in
//! that command's receipt instead.

use crate::core::facts::{Fact, FactId};
use crate::core::intents::{Intent, RowMutation};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PipelineEffects {
    /// New facts to admit and mark pending for projection.
    pub facts: Vec<Fact>,
    /// Runtime-local projectable inputs that should not enter durable facts.
    pub candidate_facts: Vec<Fact>,
    /// Existing facts to remove with their derived core-owned rows.
    pub purged_facts: Vec<FactId>,
    /// Protocol or core table mutations validated against the runtime allowlist.
    pub row_mutations: Vec<RowMutation>,
    /// Durable idempotent work for handlers.
    pub intents: Vec<Intent>,
    /// Connection-local idempotent work, dropped on restart.
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

    pub fn candidate_fact(mut self, fact: Fact) -> Self {
        self.candidate_facts.push(fact);
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
