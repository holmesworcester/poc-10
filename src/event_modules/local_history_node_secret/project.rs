//! Poc-10 local history node secret projector.
//!
//! Decodes the local-only fact body, asserts `FactScope::Local`, and emits a
//! single `PutRow` atomic intent. The legacy projector also walked source-
//! secret and removal-frontier dependencies, validated time-tree and trie
//! parent/child relationships, and exact-deleted tombstoned siblings. Those
//! checks are deferred until the surrounding key-secret modules are also
//! ported into the target tree (Wave 6 reconciliation).

use crate::core::facts::{Fact, FactScope};
use crate::core::intents::AtomicIntent;
use crate::core::projection::{ProjectionContext, ProjectionOutput, Projector};

use super::layout;
use super::rows::local_history_node_secret_row;

#[derive(Debug, Clone, Default)]
pub struct LocalHistoryNodeSecretProjector;

impl LocalHistoryNodeSecretProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for LocalHistoryNodeSecretProjector {
    fn project(
        &self,
        fact: &Fact,
        _context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        if fact.scope != FactScope::Local {
            return Err("local history node secret fact must have FactScope::Local".to_string());
        }
        let node = layout::decode_fact(&fact.bytes)?;
        Ok(ProjectionOutput::new()
            .intent(AtomicIntent::PutRow(local_history_node_secret_row(fact.id, &node)?).into_intent()))
    }
}
