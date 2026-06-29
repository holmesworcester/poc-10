//! Projection for active-workspace facts.

use crate::core::facts::{Fact, FactScope};
use crate::core::intents::RowMutation;
use crate::core::project_fact::{
    FactProjectorInfo, ProjectionContext, ProjectionOutput, Projector,
};

use super::fact::ActiveWorkspaceFact;

pub mod decode {
    use super::ActiveWorkspaceFact;
    use crate::protocol::auth::active_workspace::encode::{FACT_BYTES, TYPE_ACTIVE_WORKSPACE};

    pub fn decode_fact(bytes: &[u8]) -> Result<ActiveWorkspaceFact, String> {
        if bytes.len() != FACT_BYTES {
            return Err("active workspace fact has invalid length".to_string());
        }
        if bytes[0] != TYPE_ACTIVE_WORKSPACE {
            return Err("expected active workspace fact".to_string());
        }
        let effective_at_ms = u64::from_be_bytes(bytes[1..9].try_into().unwrap());
        let workspace_id = bytes[9..41].try_into().unwrap();
        Ok(ActiveWorkspaceFact {
            effective_at_ms,
            workspace_id,
        })
    }
}

pub mod authenticate {
    use super::{ActiveWorkspaceFact, Fact, FactScope, ProjectionContext};
    use crate::core::project_fact::verify_fact_id;

    pub fn authenticate(
        fact: &Fact,
        setting: ActiveWorkspaceFact,
        _context: &ProjectionContext,
    ) -> Result<ActiveWorkspaceFact, String> {
        verify_fact_id(fact)?;
        if fact.scope != FactScope::Local {
            return Err("active workspace fact must have local scope".to_string());
        }
        Ok(setting)
    }
}

pub mod adapt {
    //! Active-workspace semantic adapter.
    //!
    //! The current wire shape is already the active semantic shape. This identity
    //! adapter keeps the protocol-local conversion point available for future
    //! versioned facts.

    use super::ActiveWorkspaceFact;

    pub(crate) fn adapt(source: ActiveWorkspaceFact) -> Result<ActiveWorkspaceFact, String> {
        Ok(source)
    }
}

// Active-workspace projector.
//
// POLICY. An active-workspace selection is admitted iff it is a local-scope fact
// (it is purely this store's UI toggle, never shared or networked). Projection
// records one row per selection fact; the latest-effective row wins at read time.

pub const PROJECTOR_INFO: FactProjectorInfo =
    FactProjectorInfo::projector("auth::active_workspace::project::ActiveWorkspaceProjector");

pub const STORAGE_VERSION: u32 = crate::protocol::versioning::CURRENT_PROTOCOL_VERSION;
pub const STORAGE_REQUIREMENT: crate::core::effects::StorageRequirement =
    crate::core::effects::StorageRequirement::Current(STORAGE_VERSION);

#[derive(Debug, Clone, Default)]
pub struct ActiveWorkspaceProjector;

impl ActiveWorkspaceProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for ActiveWorkspaceProjector {
    fn project(
        &self,
        fact: &Fact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        // 1. Decode, authenticate (local scope), and adapt the wire fact.
        let decoded = decode::decode_fact(fact.body())?;
        let authenticated = authenticate::authenticate(fact, decoded, context)?;
        let setting = adapt::adapt(authenticated)?;
        // 3. Materialize one selection row; no context offers or intents.
        Ok(ProjectionOutput::new().row_mutation(RowMutation::InsertValues(
            super::active_workspace_insert(fact.id, &setting),
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::super::{author, queries};
    use super::*;
    use crate::core::db::Db;
    use crate::core::schema::CORE_SCHEMA_SOURCE;
    use crate::protocol::registry::FACTS_SCHEMA_SOURCE;

    fn project_into(store: &Db, fact: &Fact) {
        ActiveWorkspaceProjector::new()
            .project(fact, &ProjectionContext::default())
            .expect("project")
            .effects
            .row_mutations
            .into_iter()
            .for_each(|mutation| {
                if let RowMutation::InsertValues(row) = mutation {
                    store
                        .write_transaction(|tx| tx.insert_values_in_tx(&row).map(|_| ()))
                        .expect("insert row");
                }
            });
    }

    #[test]
    fn round_trips_fixed_width() {
        let fact = author::active_workspace_fact(123, [7u8; 32]).expect("fact");
        assert_eq!(fact.scope, FactScope::Local);
        assert_eq!(
            decode::decode_fact(&fact.bytes).expect("decode"),
            ActiveWorkspaceFact {
                effective_at_ms: 123,
                workspace_id: [7u8; 32],
            }
        );
    }

    #[test]
    fn current_active_workspace_uses_most_recent_row() {
        let store = Db::open_memory_with_schema_sources(&[CORE_SCHEMA_SOURCE, FACTS_SCHEMA_SOURCE])
            .expect("store");
        project_into(
            &store,
            &author::active_workspace_fact(100, [1u8; 32]).expect("older"),
        );
        project_into(
            &store,
            &author::active_workspace_fact(200, [2u8; 32]).expect("newer"),
        );
        assert_eq!(
            queries::current_active_workspace(&store).expect("current"),
            Some([2u8; 32])
        );
    }
}
