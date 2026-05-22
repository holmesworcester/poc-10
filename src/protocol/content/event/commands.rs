//! Command-facing content-event workflows.
//!
//! `generate` constructs shared content facts only. Projection remains owned by
//! `project.rs`; row reads for reports stay in `queries.rs`.

use crate::core::clock;
use crate::core::command_context::{CommandContext, CommandOutput};
use crate::core::facts::{Fact, FactId};
use crate::protocol::content::event::{fact::ContentEventFact, layout, queries};
use crate::protocol::identity;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenerateReceipt {
    pub workspace_id: FactId,
    pub generated_facts: usize,
    pub event_size_bytes: usize,
    pub first_timestamp: u64,
    pub last_timestamp: u64,
    pub fact_ids: Vec<FactId>,
}

pub fn generate(
    ctx: &CommandContext<'_>,
    workspace_id: FactId,
    count: usize,
    event_size_bytes: usize,
) -> Result<CommandOutput<GenerateReceipt>, String> {
    if count == 0 {
        return Err("generate count must be positive".to_string());
    }
    if event_size_bytes == 0 {
        return Err("generate event size must be positive".to_string());
    }
    identity::workspace::queries::workspace_by_id(ctx.store(), workspace_id)?;

    let observed_max = queries::max_timestamp(ctx.store())?;
    let first_timestamp = clock::next_timestamp(ctx.store(), observed_max)?;
    let last_timestamp = first_timestamp
        .checked_add((count - 1) as u64)
        .ok_or_else(|| "generate timestamp range overflows u64".to_string())?;

    let mut facts = Vec::with_capacity(count);
    let mut fact_ids = Vec::with_capacity(count);
    for index in 0..count {
        let timestamp = first_timestamp
            .checked_add(index as u64)
            .ok_or_else(|| "generate timestamp overflows u64".to_string())?;
        let payload = deterministic_payload(&workspace_id, timestamp, index, event_size_bytes);
        let event = ContentEventFact {
            workspace_id,
            timestamp,
            payload,
        };
        let fact = Fact::new(
            crate::protocol::identity::workspace::scope(workspace_id),
            timestamp,
            layout::encode_fact(&event)?,
        );
        fact_ids.push(fact.id);
        facts.push(fact);
    }

    Ok(CommandOutput::new(GenerateReceipt {
        workspace_id,
        generated_facts: count,
        event_size_bytes,
        first_timestamp,
        last_timestamp,
        fact_ids,
    })
    .with_facts(facts))
}

fn deterministic_payload(
    workspace_id: &FactId,
    timestamp: u64,
    index: usize,
    size: usize,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(size);
    let mut block = 0u64;
    while out.len() < size {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"topo:poc10:content-event-payload:v1");
        hasher.update(workspace_id);
        hasher.update(&timestamp.to_be_bytes());
        hasher.update(&(index as u64).to_be_bytes());
        hasher.update(&block.to_be_bytes());
        out.extend_from_slice(hasher.finalize().as_bytes());
        block = block.saturating_add(1);
    }
    out.truncate(size);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::command_context::{FnClock, IdentityVault};
    use crate::core::store::Store;
    use crate::protocol::identity;

    struct EmptyVault;

    impl IdentityVault for EmptyVault {
        fn local_signing_capability(
            &self,
            _workspace_id: FactId,
        ) -> Result<crate::core::command_context::LocalSigningCapability, String> {
            Err("no signing capability".to_string())
        }

        fn local_encryption_capability(
            &self,
            _workspace_id: FactId,
        ) -> Result<crate::core::command_context::LocalEncryptionCapability, String> {
            Err("no encryption capability".to_string())
        }
    }

    #[test]
    fn generate_constructs_deterministic_content_facts() {
        let store = Store::open_memory_with_schema_sources(&[
            crate::core::schema::CORE_SCHEMA_SOURCE,
            crate::protocol::registry::FACTS_SCHEMA_SOURCE,
        ])
        .expect("store");
        let clock = FnClock(|| 1);
        let vault = EmptyVault;
        let ctx = CommandContext::new(&store, &clock, &vault);
        let workspace = identity::workspace::commands::create_workspace(&ctx, [7; 32], "workspace")
            .expect("workspace command");
        let workspace_fact = workspace.effects.facts.first().expect("workspace fact");
        let workspace_body =
            identity::workspace::layout::decode_fact(&workspace_fact.bytes).expect("decode");
        store
            .insert_table_rows(vec![identity::workspace::rows::workspace_row(
                workspace_fact.id,
                &workspace_body,
            )
            .expect("workspace row")])
            .expect("write workspace row");

        let output =
            generate(&ctx, workspace.receipt.workspace_fact_id, 2, 17).expect("generate command");
        assert_eq!(output.receipt.first_timestamp, 1);
        assert_eq!(output.receipt.last_timestamp, 2);
        assert_eq!(output.effects.facts.len(), 2);
        assert_eq!(output.effects.facts[0], output.effects.facts[0].clone());
    }
}
