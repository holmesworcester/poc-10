//! Author the local active-workspace selection fact.
//!
//! A command supplies the chosen workspace id; this builds the single local-only
//! fact and a receipt. It performs no authority checks: the selection is local
//! UI state, validated for existence at the command boundary.

use crate::core::command::{AuthoredFacts, CommandClock};
use crate::core::facts::{Fact, FactId, FactScope};

use super::encode::encode_fact;
use super::fact::ActiveWorkspaceFact;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActiveWorkspaceReceipt {
    pub setting_fact_id: FactId,
    pub effective_at_ms: u64,
    pub workspace_id: FactId,
}

pub fn author_active_workspace(
    clock: &dyn CommandClock,
    workspace_id: FactId,
) -> Result<AuthoredFacts<ActiveWorkspaceReceipt>, String> {
    let effective_at_ms = clock.next_timestamp();
    let fact = active_workspace_fact(effective_at_ms, workspace_id)?;
    Ok(AuthoredFacts::new(ActiveWorkspaceReceipt {
        setting_fact_id: fact.id,
        effective_at_ms,
        workspace_id,
    })
    .with_facts(vec![fact]))
}

pub fn active_workspace_fact(effective_at_ms: u64, workspace_id: FactId) -> Result<Fact, String> {
    let setting = ActiveWorkspaceFact {
        effective_at_ms,
        workspace_id,
    };
    Ok(Fact::new(
        FactScope::Local,
        effective_at_ms,
        encode_fact(&setting)?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::command::FnClock;

    #[test]
    fn author_active_workspace_emits_one_local_fact() {
        let output = author_active_workspace(&FnClock(|| 55), [9u8; 32]).expect("author");
        assert_eq!(output.facts.len(), 1);
        assert_eq!(output.facts[0].scope, FactScope::Local);
        assert_eq!(output.receipt.workspace_id, [9u8; 32]);
    }
}
