use crate::core::command_context::CommandOutput;
use crate::core::facts::{Fact, FactId};
use crate::core::intents::{HandlerOutput, Intent, RowMutation};
use crate::core::pipeline::LOCAL_INTENTS;
use crate::core::pipeline_storage::{
    insert_fact_and_pending_in_tx, purge_fact_in_tx, row_mutation_rows, sqlite_string_error,
    validate_row_mutations,
};
use crate::core::store::{Store, TableName};
use std::collections::BTreeMap;

use super::intent_queue::{intent_row_key, record_intent_in_table_in_tx, record_intent_in_tx};

/// Durable effects produced by one pipeline step.
///
/// Projection, intent handlers, and command submission all eventually reduce to
/// this shape: admit facts, purge facts, mutate protocol-owned row tables, and
/// enqueue durable or restart-local intents.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PipelineEffects {
    pub facts: Vec<Fact>,
    pub purged_facts: Vec<FactId>,
    pub row_mutations: Vec<RowMutation>,
    pub durable_intents: Vec<Intent>,
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
        self.durable_intents.push(intent);
        self
    }

    pub fn local_intent(mut self, intent: Intent) -> Self {
        self.local_intents.push(intent);
        self
    }

    pub(crate) fn from_command_output<T>(output: CommandOutput<T>) -> (T, Self) {
        (
            output.receipt,
            Self {
                facts: output.facts,
                durable_intents: output.intents,
                local_intents: output.local_intents,
                ..Self::default()
            },
        )
    }

    pub(crate) fn validate(&self, allowed_tables: &[TableName]) -> Result<(), String> {
        validate_intents(&self.durable_intents)?;
        validate_intents(&self.local_intents)?;
        validate_row_mutations(&self.row_mutations, allowed_tables)?;
        Ok(())
    }

    pub(crate) fn validate_ignoring_intent_key(
        &self,
        ignored_key: Option<&[u8]>,
        allowed_tables: &[TableName],
    ) -> Result<(), String> {
        validate_intents_ignoring_key(&self.durable_intents, ignored_key)?;
        validate_intents_ignoring_key(&self.local_intents, ignored_key)?;
        validate_row_mutations(&self.row_mutations, allowed_tables)?;
        Ok(())
    }
}

impl From<HandlerOutput> for PipelineEffects {
    fn from(output: HandlerOutput) -> Self {
        Self {
            facts: output.facts,
            purged_facts: output.purged_facts,
            row_mutations: output.row_mutations,
            durable_intents: output.intents,
            local_intents: output.local_intents,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct PipelineEffectCounts {
    pub facts: usize,
    pub durable_intents: usize,
    pub local_intents: usize,
}

impl PipelineEffectCounts {
    pub(crate) fn intents(self) -> usize {
        self.durable_intents + self.local_intents
    }
}

/// Validate that a batch can be written to a single intent queue.
///
/// Intent durability is owned by the destination table. This check only rejects
/// conflicting duplicates within one destination queue.
fn validate_intents(intents: &[Intent]) -> Result<(), String> {
    validate_intents_ignoring_key(intents, None)
}

/// As [`validate_intents`], with the handled row key reserved for the intent
/// currently being consumed.
fn validate_intents_ignoring_key(
    intents: &[Intent],
    _ignored_key: Option<&[u8]>,
) -> Result<(), String> {
    let mut proposed = BTreeMap::<Vec<u8>, &Intent>::new();
    for intent in intents {
        let key = intent_row_key(intent);
        if let Some(existing) = proposed.insert(key, intent) {
            if existing != intent {
                return Err(format!(
                    "pipeline emitted conflicting intents for {}",
                    intent.kind.as_str()
                ));
            }
        }
    }
    Ok(())
}

pub(crate) fn commit_pipeline_effects_to_store(
    store: &Store,
    effects: &PipelineEffects,
    allowed_tables: &[TableName],
    label: &str,
) -> Result<PipelineEffectCounts, String> {
    effects.validate(allowed_tables)?;
    store
        .write_transaction(|tx| commit_pipeline_effects_in_tx(tx, effects, allowed_tables))
        .map_err(|err| format!("{label}: {err}"))
}

pub(crate) fn commit_pipeline_effects_in_tx(
    tx: &Store,
    effects: &PipelineEffects,
    allowed_tables: &[TableName],
) -> rusqlite::Result<PipelineEffectCounts> {
    for purged in &effects.purged_facts {
        purge_fact_in_tx(tx, *purged)?;
    }

    let mut facts = 0usize;
    for fact in &effects.facts {
        if insert_fact_and_pending_in_tx(tx, fact)? {
            facts += 1;
        }
    }

    let (rows, deletes) =
        row_mutation_rows(&effects.row_mutations, allowed_tables).map_err(sqlite_string_error)?;
    tx.insert_table_rows_in_tx(rows)?;
    for delete in deletes {
        tx.delete_table_rows_in_tx(delete.table, vec![delete.key])?;
    }

    let mut durable_intents = 0usize;
    for intent in &effects.durable_intents {
        if record_intent_in_tx(tx, intent)? {
            durable_intents += 1;
        }
    }

    let mut local_intents = 0usize;
    for intent in &effects.local_intents {
        if record_intent_in_table_in_tx(tx, LOCAL_INTENTS, intent)? {
            local_intents += 1;
        }
    }

    Ok(PipelineEffectCounts {
        facts,
        durable_intents,
        local_intents,
    })
}
