use crate::core::command_context::CommandOutput;
use crate::core::fact_store::{insert_fact_and_pending_in_tx, purge_fact_in_tx};
use crate::core::facts::{Fact, FactId};
use crate::core::intents::{HandlerOutput, Intent, RowMutation, TableDelete};
use crate::core::schema::LOCAL_INTENTS;
use crate::core::store::{Store, TableName, TableRow};
use std::collections::BTreeMap;

use super::intent_queue::{record_intent_in_table_in_tx, record_intent_in_tx};

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
    let mut proposed = BTreeMap::<Vec<u8>, &Intent>::new();
    for intent in intents {
        let key = intent_validation_key(intent);
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

fn intent_validation_key(intent: &Intent) -> Vec<u8> {
    let mut key = intent.kind.as_str().as_bytes().to_vec();
    key.push(0);
    key.extend_from_slice(&intent.key);
    key
}

/// Reject any row mutation targeting a table this runtime has not registered.
fn validate_row_mutations(
    mutations: &[RowMutation],
    allowed_tables: &[TableName],
) -> Result<(), String> {
    for mutation in mutations {
        validate_row_mutation_table(mutation, allowed_tables)?;
    }
    Ok(())
}

/// Split row mutations into inserts and deletes so a commit can apply them.
fn row_mutation_rows(
    mutations: &[RowMutation],
    allowed_tables: &[TableName],
) -> Result<(Vec<TableRow>, Vec<TableDelete>), String> {
    let mut rows = Vec::new();
    let mut deletes = Vec::<TableDelete>::new();
    for mutation in mutations {
        validate_row_mutation_table(mutation, allowed_tables)?;
        match mutation {
            RowMutation::PutRow(row) => rows.push(row.clone()),
            RowMutation::DeleteRow(delete) => deletes.push(delete.clone()),
        }
    }
    Ok((rows, deletes))
}

fn validate_row_mutation_table(
    mutation: &RowMutation,
    allowed_tables: &[TableName],
) -> Result<(), String> {
    let table = match mutation {
        RowMutation::PutRow(row) => row.table,
        RowMutation::DeleteRow(delete) => delete.table,
    };
    if allowed_tables.contains(&table) {
        Ok(())
    } else {
        Err(format!(
            "row mutation table {} is not registered",
            table.as_str()
        ))
    }
}

/// Adapt a `String` error into the [`rusqlite::Error`] a transaction closure
/// must return, so a non-SQL failure can still abort a commit.
pub(super) fn sqlite_string_error(err: String) -> rusqlite::Error {
    rusqlite::Error::InvalidParameterName(err)
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
