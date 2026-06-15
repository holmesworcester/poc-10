//! Shared side-effect language committed by runtime work.
//!
//! Projection and intent handlers reduce to this structure before the SQL
//! runtime workers commit their output. The structure is intentionally mechanical: it
//! names facts to admit, facts to purge, row mutations, durable intents,
//! ephemeral intents, and outside-origin incoming facts. It does not contain
//! callbacks, open sockets, command receipts, or protocol-specific execution
//! state.
//!
//! If a new kind of runtime effect needs atomic commit with projection or
//! intent dispatch, add it here and teach `project_fact::commit_effects` how
//! to validate and write it. If it is only display data for a command, keep it
//! in that command's receipt instead.

use crate::core::facts::{Fact, FactId};
use crate::core::intents::{Intent, RowMutation};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RuntimeEffects {
    /// New facts to admit and mark pending for projection.
    pub facts: Vec<Fact>,
    /// Outside-origin projectable inputs that are not durable until projection retains them.
    pub incoming_facts: Vec<Fact>,
    /// Existing facts to remove with their derived core-owned rows.
    pub purged_facts: Vec<FactId>,
    /// Protocol or core table mutations validated against the runtime allowlist.
    pub row_mutations: Vec<RowMutation>,
    /// Durable idempotent work for handlers.
    pub intents: Vec<Intent>,
    /// Connection-local idempotent work, dropped on restart.
    pub local_intents: Vec<Intent>,
}

impl RuntimeEffects {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_empty(&self) -> bool {
        self.facts.is_empty()
            && self.incoming_facts.is_empty()
            && self.purged_facts.is_empty()
            && self.row_mutations.is_empty()
            && self.intents.is_empty()
            && self.local_intents.is_empty()
    }

    pub fn fact(mut self, fact: Fact) -> Self {
        self.facts.push(fact);
        self
    }

    pub fn incoming_fact(mut self, fact: Fact) -> Self {
        self.incoming_facts.push(fact);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::facts::{Fact, FactScope};

    #[test]
    fn runtime_effects_reports_whether_any_runtime_work_exists() {
        assert!(RuntimeEffects::new().is_empty());

        let fact = Fact::new(FactScope::Global, 1, b"child".to_vec());
        assert!(!RuntimeEffects::new().fact(fact).is_empty());
    }
}
