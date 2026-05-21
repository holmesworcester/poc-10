//! Atomic SQL writes for one completed projection.

use super::context_rows::{insert_context_need_in_tx, insert_context_offer_in_tx};
use super::context_wake_sql::{
    exact_role_delta, wake_custom_context_matches_in_tx, wake_exact_context_matches_in_tx,
};
use super::effects::sqlite_string_error;
use crate::core::context::{ContextSet, ContextSetDelta};
use crate::core::facts::FactId;
use crate::core::matchers::ContextMatcher;
use crate::core::pipeline::{
    commit_pipeline_effects_in_tx, PipelineEffectCounts, PipelineEffects, CONTEXT_EDGES,
    PENDING_PROJECTION, PENDING_TIME_RANGES, TIME_WAKES,
};
use crate::core::projectors::TimeWake;
use crate::core::store::{ColumnValue, Store, TableName};
use std::collections::BTreeSet;

/// The uncommitted output of projecting one pending fact.
pub(super) struct ProjectionEffects {
    fact_id: FactId,
    next_context: ContextSet,
    next_time_wakes: Vec<TimeWake>,
    context_delta: ContextSetDelta,
    pipeline: PipelineEffects,
}

impl ProjectionEffects {
    pub(super) fn new(
        fact_id: FactId,
        next_context: ContextSet,
        next_time_wakes: Vec<TimeWake>,
        context_delta: ContextSetDelta,
        pipeline: PipelineEffects,
    ) -> Self {
        Self {
            fact_id,
            next_context,
            next_time_wakes,
            context_delta,
            pipeline,
        }
    }
}

/// The committed SQL result needed to update memory and reporting.
pub(super) struct ProjectionCommit {
    pub(super) effects: PipelineEffectCounts,
    pub(super) woken_facts: usize,
}

/// Commit all durable projection effects in one SQLite transaction.
///
/// Transaction contents:
///
/// - Clear this fact's pending row.
/// - Replace this fact's standing context.
/// - Replace this fact's time wakes.
/// - Wake exact context matches directly.
/// - Wake custom context matches directly.
/// - Apply row mutations.
/// - Record durable intents.
/// - Record restart-local intents in the temp local queue.
pub(super) fn commit_projection_effects(
    store: &Store,
    effects: &ProjectionEffects,
    matchers: &[&dyn ContextMatcher],
    allowed_tables: &[TableName],
) -> Result<ProjectionCommit, String> {
    let matcher_roles = ContextMatcherRoles::from_matchers(matchers);
    store
        .write_transaction(|tx| {
            tx.delete_table_rows_in_tx(PENDING_PROJECTION, vec![effects.fact_id.to_vec()])?;
            delete_pending_time_ranges_for_owner_in_tx(tx, effects.fact_id)?;
            replace_stored_context_owner_rows(tx, effects.fact_id, &effects.next_context)?;
            replace_stored_time_wake_owner_rows(tx, effects.fact_id, &effects.next_time_wakes)?;

            let exact_delta = exact_role_delta(&effects.context_delta, &matcher_roles.exact);
            let mut woken_facts = wake_exact_context_matches_in_tx(tx, &exact_delta)?;
            woken_facts += wake_custom_context_matches_in_tx(tx, &effects.context_delta, matchers)
                .map_err(sqlite_string_error)?;

            let counts = commit_pipeline_effects_in_tx(tx, &effects.pipeline, allowed_tables)?;

            Ok(ProjectionCommit {
                effects: counts,
                woken_facts,
            })
        })
        .map_err(|err| format!("commit projection effects: {err}"))
}

struct ContextMatcherRoles {
    exact: BTreeSet<crate::core::context::Role>,
}

impl ContextMatcherRoles {
    fn from_matchers(matchers: &[&dyn ContextMatcher]) -> Self {
        let mut exact = BTreeSet::new();
        for matcher in matchers {
            if let Some(role) = matcher.exact_selector_role() {
                exact.insert(role.clone());
            }
        }
        Self { exact }
    }
}

fn delete_pending_time_ranges_for_owner_in_tx(
    store: &Store,
    owner: FactId,
) -> rusqlite::Result<usize> {
    store.delete_typed_rows_where_in_tx(
        PENDING_TIME_RANGES,
        &[("owner", ColumnValue::Bytes(&owner))],
    )
}

/// Replace this fact's standing needs/offers by owner.
///
/// Projection owns the complete context set for its fact. The owner column is
/// the fact id, so deleting by owner replaces exactly this fact's rows.
fn replace_stored_context_owner_rows(
    store: &Store,
    owner: FactId,
    context: &ContextSet,
) -> rusqlite::Result<()> {
    store.delete_typed_rows_where_in_tx(CONTEXT_EDGES, &[("owner", ColumnValue::Bytes(&owner))])?;
    for need in &context.needs {
        insert_context_need_in_tx(store, need)?;
    }
    for offer in &context.offers {
        insert_context_offer_in_tx(store, offer)?;
    }
    Ok(())
}

/// Replace all time wakes owned by this fact.
///
/// Time wakes are not appended: projection output is the complete current
/// schedule for the owner, so old rows must disappear when the projection no
/// longer emits them.
fn replace_stored_time_wake_owner_rows(
    store: &Store,
    owner: FactId,
    wakes: &[TimeWake],
) -> rusqlite::Result<()> {
    store.delete_typed_rows_where_in_tx(TIME_WAKES, &[("owner", ColumnValue::Bytes(&owner))])?;
    for wake in wakes {
        store.insert_typed_row_in_tx(
            TIME_WAKES,
            &[
                ("timeline", ColumnValue::Text(wake.timeline.as_str())),
                ("at", ColumnValue::U64(wake.at)),
                ("owner", ColumnValue::Bytes(&wake.owner)),
            ],
        )?;
    }
    Ok(())
}
