//! Shared side-effect language committed by runtime work.
//!
//! Projection and intent handlers reduce to this structure before the SQL
//! runtime workers commit their output. The structure is intentionally
//! mechanical: it names ordinary facts, priority facts, incoming facts, purges,
//! row mutations, durable intents, ephemeral intents, and database-wide rebuild
//! requests. It does not contain callbacks, open sockets, command receipts, or
//! protocol-specific execution state.
//!
//! If a new kind of runtime effect needs atomic commit with projection or
//! intent dispatch, add it here and teach `project_fact::commit_effects` how
//! to validate and write it. If it is only display data for a command, keep it
//! in that command's receipt instead.

use crate::core::facts::{Fact, FactId};
use crate::core::intents::{Intent, RowMutation};
use std::collections::BTreeMap;

/// Storage version contract carried by one effect batch.
///
/// Normal protocol projectors and handlers declare the storage shape they were
/// written to touch. Maintenance work, such as the update fact that repairs an
/// old database, must explicitly bypass this guard so it can run while storage
/// is stale.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageRequirement {
    /// The runtime storage marker must match this version before commit.
    Current(u32),
    /// Maintenance work that is allowed to commit while storage is stale.
    MaintenanceBypass,
}

impl Default for StorageRequirement {
    fn default() -> Self {
        Self::MaintenanceBypass
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncomingMetadata {
    pub origin_addr: Vec<u8>,
    pub received_at_local_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeEffects {
    /// Storage precondition checked before this batch commits.
    pub storage_requirement: StorageRequirement,
    /// New facts to admit and mark pending for projection.
    pub facts: Vec<Fact>,
    /// Control-plane facts that must project before ordinary pending facts.
    pub priority_facts: Vec<Fact>,
    /// Outside-origin projectable inputs that are not durable until projection retains them.
    pub incoming_facts: Vec<Fact>,
    /// Optional transport metadata for incoming facts emitted by projectors.
    pub incoming_fact_metadata: BTreeMap<FactId, IncomingMetadata>,
    /// Existing facts to remove with their derived core-owned rows.
    pub purged_facts: Vec<FactId>,
    /// Protocol or core table mutations validated against the runtime allowlist.
    pub row_mutations: Vec<RowMutation>,
    /// Durable queued work for handlers.
    pub intents: Vec<Intent>,
    /// Connection-local queued work, dropped on restart.
    pub local_intents: Vec<Intent>,
    /// Clear derived/runtime state and requeue all retained facts in replay mode.
    pub rebuild_derived_state: bool,
}

impl Default for RuntimeEffects {
    fn default() -> Self {
        Self {
            storage_requirement: StorageRequirement::default(),
            facts: Vec::new(),
            priority_facts: Vec::new(),
            incoming_facts: Vec::new(),
            incoming_fact_metadata: BTreeMap::new(),
            purged_facts: Vec::new(),
            row_mutations: Vec::new(),
            intents: Vec::new(),
            local_intents: Vec::new(),
            rebuild_derived_state: false,
        }
    }
}

impl RuntimeEffects {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_empty(&self) -> bool {
        self.facts.is_empty()
            && self.priority_facts.is_empty()
            && self.incoming_facts.is_empty()
            && self.incoming_fact_metadata.is_empty()
            && self.purged_facts.is_empty()
            && self.row_mutations.is_empty()
            && self.intents.is_empty()
            && self.local_intents.is_empty()
            && !self.rebuild_derived_state
    }

    pub fn with_storage_requirement(mut self, requirement: StorageRequirement) -> Self {
        self.storage_requirement = requirement;
        self
    }

    pub fn fact(mut self, fact: Fact) -> Self {
        self.facts.push(fact);
        self
    }

    pub fn priority_fact(mut self, fact: Fact) -> Self {
        self.priority_facts.push(fact);
        self
    }

    pub fn incoming_fact(mut self, fact: Fact) -> Self {
        self.incoming_facts.push(fact);
        self
    }

    pub fn incoming_fact_with_metadata(mut self, fact: Fact, metadata: IncomingMetadata) -> Self {
        self.incoming_fact_metadata.insert(fact.id, metadata);
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

    pub fn rebuild_derived_state(mut self) -> Self {
        self.rebuild_derived_state = true;
        self
    }
}

// Tests.
// Ordered most-central-first: this module has one emptiness invariant test.
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
