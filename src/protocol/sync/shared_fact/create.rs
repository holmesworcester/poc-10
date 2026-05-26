//! Sync contribution planning.
//!
//! Shared-fact projection records a fact's sync visibility by queuing
//! `share_fact_with_sync`. The handler must not mutate these rows directly:
//! it plans row mutations here and lets the runtime commit them atomically
//! with the handled intent row.

use crate::core::effects::PipelineEffects;
use crate::core::facts::{Fact, FactId, FactScope};
use crate::core::intents::{RowMutation, TableDeleteWhere, TableInsert, Value};
use crate::core::store::{Store, TableName, TableRow};
use crate::protocol::sync::{
    compare::fact::RangeSummary,
    share_fact_with_sync::{ShareFactWithSync, SyncShareState},
};

use super::rows::{
    contribution_fingerprint, decode_negentropy_node_row, negentropy_context_have_for_leaf,
    negentropy_context_have_key, negentropy_context_have_row,
    negentropy_context_have_rows_for_leaf, negentropy_leaf_key, negentropy_leaf_row,
    negentropy_leaf_row_for_owner, negentropy_node_key, negentropy_node_row, node_path,
    shareable_fact_key, shareable_fact_row, xor_fingerprint, NegentropyContextHaveRow,
    NegentropyLeafRow, NegentropyNodeRow, ShareableFactRow, NEGENTROPY_CONTEXT_HAVE_ROWS,
    NEGENTROPY_LEAF_ROWS, NEGENTROPY_NODE_ROWS, SHAREABLE_FACT_ROWS,
};

const ROW_COLUMNS: &[&str] = &["row_key", "row_value"];
const ROW_KEY_COLUMNS: &[&str] = &["row_key"];
const SYNC_CONTRIBUTION_TABLES: &[TableName] = &[
    SHAREABLE_FACT_ROWS,
    NEGENTROPY_LEAF_ROWS,
    NEGENTROPY_CONTEXT_HAVE_ROWS,
    NEGENTROPY_NODE_ROWS,
];

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SyncContributionPlan {
    pub changed: bool,
    pub context_have: Vec<FactId>,
    pub row_mutations: Vec<RowMutation>,
}

pub fn record_sync_contribution(
    store: &Store,
    input: &ShareFactWithSync,
    owner: Option<&Fact>,
) -> Result<bool, String> {
    let plan = plan_sync_contribution(store, input, owner)?;
    if plan.changed {
        let mut effects = PipelineEffects::new();
        effects.row_mutations = plan.row_mutations;
        crate::core::pipeline::commit_pipeline_effects_to_store(
            store,
            &effects,
            SYNC_CONTRIBUTION_TABLES,
            "record sync contribution rows",
        )?;
    }
    Ok(plan.changed)
}

pub fn plan_sync_contribution(
    store: &Store,
    input: &ShareFactWithSync,
    owner: Option<&Fact>,
) -> Result<SyncContributionPlan, String> {
    match input.state {
        SyncShareState::Upsert => {
            let owner = owner
                .ok_or_else(|| "share_fact_with_sync upsert requires owner fact".to_string())?;
            validate_sync_owner(
                input.workspace_id,
                input.owner_fact_id,
                input.timestamp_ms,
                owner,
            )?;
            plan_upsert_sync_contribution(store, input, owner)
        }
        SyncShareState::Retract => plan_retract_sync_contribution(store, input),
    }
}

fn validate_sync_owner(
    workspace_id: FactId,
    owner_fact_id: FactId,
    timestamp_ms: u64,
    owner: &Fact,
) -> Result<(), String> {
    if owner.id != owner_fact_id {
        return Err("share_fact_with_sync owner fact id mismatch".to_string());
    }
    if owner.timestamp != timestamp_ms {
        return Err("share_fact_with_sync timestamp does not match owner fact".to_string());
    }
    match &owner.scope {
        FactScope::Scoped { kind, id } if kind.as_str() == "workspace" => {
            if id != &workspace_id {
                return Err("share_fact_with_sync owner scope does not match workspace".to_string());
            }
        }
        FactScope::Global => {}
        _ => {
            return Err(
                "share_fact_with_sync requires a workspace-scoped or global owner fact".to_string(),
            );
        }
    }
    Ok(())
}

fn plan_upsert_sync_contribution(
    store: &Store,
    input: &ShareFactWithSync,
    owner: &Fact,
) -> Result<SyncContributionPlan, String> {
    let old_leaf = negentropy_leaf_row_for_owner(store, input.workspace_id, input.owner_fact_id)?;
    if let Some(old_leaf) = &old_leaf {
        if old_leaf.timestamp_ms != input.timestamp_ms {
            return Err("share_fact_with_sync timestamp changed for existing owner".to_string());
        }
    }

    let mut context_have =
        negentropy_context_have_for_leaf(store, input.workspace_id, input.owner_fact_id)?;
    context_have.extend(input.context_have.iter().copied());
    context_have.sort();
    context_have.dedup();
    let new_fingerprint = contribution_fingerprint(
        input.workspace_id,
        input.owner_fact_id,
        input.timestamp_ms,
        &context_have,
    );
    if old_leaf
        .as_ref()
        .map(|leaf| leaf.contribution_fingerprint == new_fingerprint)
        .unwrap_or(false)
    {
        return Ok(SyncContributionPlan {
            changed: false,
            context_have,
            row_mutations: Vec::new(),
        });
    }

    let old_summary = old_leaf.as_ref().map(|leaf| RangeSummary {
        count: 1,
        fingerprint: leaf.contribution_fingerprint,
    });
    let new_summary = RangeSummary {
        count: 1,
        fingerprint: new_fingerprint,
    };
    let leaf_row = negentropy_leaf_row(NegentropyLeafRow {
        workspace_id: input.workspace_id,
        owner_fact_id: input.owner_fact_id,
        timestamp_ms: input.timestamp_ms,
        contribution_fingerprint: new_fingerprint,
    });
    let shareable_row = shareable_fact_row(ShareableFactRow {
        workspace_id: input.workspace_id,
        fact_id: owner.id,
        timestamp_ms: owner.timestamp,
    });
    let context_rows = context_have
        .iter()
        .map(|context_fact_id| {
            negentropy_context_have_row(NegentropyContextHaveRow {
                workspace_id: input.workspace_id,
                owner_fact_id: input.owner_fact_id,
                context_fact_id: *context_fact_id,
            })
        })
        .collect::<Vec<_>>();
    let old_context_keys =
        negentropy_context_have_rows_for_leaf(store, input.workspace_id, input.owner_fact_id)?
            .into_iter()
            .map(|row| {
                negentropy_context_have_key(
                    row.workspace_id,
                    row.owner_fact_id,
                    row.context_fact_id,
                )
            })
            .collect::<Vec<_>>();

    let mut row_mutations = Vec::new();
    row_mutations.push(delete_row_key_mutation(
        NEGENTROPY_LEAF_ROWS,
        negentropy_leaf_key(input.workspace_id, input.owner_fact_id),
    ));
    row_mutations.extend(
        old_context_keys
            .into_iter()
            .map(|key| delete_row_key_mutation(NEGENTROPY_CONTEXT_HAVE_ROWS, key)),
    );
    plan_update_node_path(
        store,
        input.workspace_id,
        input.timestamp_ms,
        old_summary,
        Some(new_summary),
        &mut row_mutations,
    )?;
    row_mutations.push(insert_row_mutation(shareable_row));
    row_mutations.push(insert_row_mutation(leaf_row));
    row_mutations.extend(context_rows.into_iter().map(insert_row_mutation));
    Ok(SyncContributionPlan {
        changed: true,
        context_have,
        row_mutations,
    })
}

fn plan_retract_sync_contribution(
    store: &Store,
    input: &ShareFactWithSync,
) -> Result<SyncContributionPlan, String> {
    let Some(old_leaf) =
        negentropy_leaf_row_for_owner(store, input.workspace_id, input.owner_fact_id)?
    else {
        return Ok(SyncContributionPlan::default());
    };
    let old_summary = RangeSummary {
        count: 1,
        fingerprint: old_leaf.contribution_fingerprint,
    };
    let old_context_keys =
        negentropy_context_have_rows_for_leaf(store, input.workspace_id, input.owner_fact_id)?
            .into_iter()
            .map(|row| {
                negentropy_context_have_key(
                    row.workspace_id,
                    row.owner_fact_id,
                    row.context_fact_id,
                )
            })
            .collect::<Vec<_>>();

    let mut row_mutations = Vec::new();
    row_mutations.push(delete_row_key_mutation(
        SHAREABLE_FACT_ROWS,
        shareable_fact_key(input.workspace_id, input.owner_fact_id),
    ));
    row_mutations.push(delete_row_key_mutation(
        NEGENTROPY_LEAF_ROWS,
        negentropy_leaf_key(input.workspace_id, input.owner_fact_id),
    ));
    row_mutations.extend(
        old_context_keys
            .into_iter()
            .map(|key| delete_row_key_mutation(NEGENTROPY_CONTEXT_HAVE_ROWS, key)),
    );
    plan_update_node_path(
        store,
        input.workspace_id,
        old_leaf.timestamp_ms,
        Some(old_summary),
        None,
        &mut row_mutations,
    )?;
    Ok(SyncContributionPlan {
        changed: true,
        context_have: Vec::new(),
        row_mutations,
    })
}

fn plan_update_node_path(
    store: &Store,
    workspace_id: FactId,
    timestamp_ms: u64,
    old_summary: Option<RangeSummary>,
    new_summary: Option<RangeSummary>,
    row_mutations: &mut Vec<RowMutation>,
) -> Result<(), String> {
    for (level, start_timestamp_ms) in node_path(timestamp_ms) {
        let key = negentropy_node_key(workspace_id, level, start_timestamp_ms);
        let current = store
            .table_row(NEGENTROPY_NODE_ROWS, &key)
            .map_err(|err| format!("load negentropy node row: {err}"))?
            .map(|value| decode_negentropy_node_row(&key, &value))
            .transpose()
            .map_err(|err| format!("decode negentropy node row: {err}"))?;
        let mut summary = current
            .map(|row| row.summary)
            .unwrap_or_else(RangeSummary::default);
        if let Some(old) = old_summary {
            summary.count = summary.count.saturating_sub(old.count);
            xor_fingerprint(&mut summary.fingerprint, old.fingerprint);
        }
        if let Some(new) = new_summary {
            summary.count = summary.count.saturating_add(new.count);
            xor_fingerprint(&mut summary.fingerprint, new.fingerprint);
        }
        row_mutations.push(delete_row_key_mutation(NEGENTROPY_NODE_ROWS, key));
        if summary.count != 0 || summary.fingerprint != [0; 32] {
            row_mutations.push(insert_row_mutation(negentropy_node_row(
                NegentropyNodeRow {
                    workspace_id,
                    level,
                    start_timestamp_ms,
                    summary,
                },
            )));
        }
    }
    Ok(())
}

fn insert_row_mutation(row: TableRow) -> RowMutation {
    RowMutation::InsertValues(TableInsert {
        table: row.table,
        columns: ROW_COLUMNS,
        values: vec![Value::Bytes(row.key), Value::Bytes(row.value)],
    })
}

fn delete_row_key_mutation(table: TableName, key: Vec<u8>) -> RowMutation {
    RowMutation::DeleteWhere(TableDeleteWhere {
        table,
        columns: ROW_KEY_COLUMNS,
        values: vec![Value::Bytes(key)],
    })
}
