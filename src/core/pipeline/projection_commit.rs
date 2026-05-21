//! Atomic SQL writes for one completed projection.

use super::context_rows::{insert_context_need_in_tx, insert_context_offer_in_tx};
use super::context_wakes::wake_context_matches_in_tx;
use super::effects::{commit_pipeline_effects_in_tx, sqlite_string_error, PipelineEffectCounts};
use crate::core::context::{ContextSet, ContextSetDelta};
use crate::core::effects::PipelineEffects;
use crate::core::facts::FactId;
use crate::core::matchers::ContextMatcher;
use crate::core::projectors::TimeWake;
use crate::core::store::{Store, TableName};
use rusqlite::params;

/// The uncommitted output of projecting one pending fact.
pub(super) struct ProjectionEffects {
    pub(super) fact_id: FactId,
    pub(super) next_context: ContextSet,
    pub(super) next_time_wakes: Vec<TimeWake>,
    pub(super) context_delta: ContextSetDelta,
    pub(super) pipeline: PipelineEffects,
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
/// - Wake context matches directly.
/// - Apply row mutations.
/// - Record durable intents.
/// - Record restart-local intents in the temp local queue.
pub(super) fn commit_projection_effects(
    store: &Store,
    effects: &ProjectionEffects,
    matchers: &[&dyn ContextMatcher],
    allowed_tables: &[TableName],
) -> Result<ProjectionCommit, String> {
    store
        .write_transaction(|tx| {
            tx.conn().execute(
                "DELETE FROM pending_projection WHERE owner = ?1",
                params![effects.fact_id.as_slice()],
            )?;
            delete_pending_time_ranges_for_owner_in_tx(tx, effects.fact_id)?;
            replace_stored_context_owner_rows(tx, effects.fact_id, &effects.next_context)?;
            replace_stored_time_wake_owner_rows(tx, effects.fact_id, &effects.next_time_wakes)?;

            let woken_facts = wake_context_matches_in_tx(tx, &effects.context_delta, matchers)
                .map_err(sqlite_string_error)?;

            let counts = commit_pipeline_effects_in_tx(tx, &effects.pipeline, allowed_tables)?;

            Ok(ProjectionCommit {
                effects: counts,
                woken_facts,
            })
        })
        .map_err(|err| format!("commit projection effects: {err}"))
}

fn delete_pending_time_ranges_for_owner_in_tx(
    store: &Store,
    owner: FactId,
) -> rusqlite::Result<usize> {
    store.conn().execute(
        "DELETE FROM pending_time_ranges WHERE owner = ?1",
        params![owner.as_slice()],
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
    store.conn().execute(
        "DELETE FROM context_edges WHERE owner = ?1",
        params![owner.as_slice()],
    )?;
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
    store.conn().execute(
        "DELETE FROM time_wakes WHERE owner = ?1",
        params![owner.as_slice()],
    )?;
    for wake in wakes {
        store.conn().execute(
            "INSERT OR IGNORE INTO time_wakes (timeline, at, owner)
             VALUES (?1, ?2, ?3)",
            params![
                wake.timeline.as_str(),
                sqlite_u64(wake.at, "time wake")?,
                wake.owner.as_slice()
            ],
        )?;
    }
    Ok(())
}

fn sqlite_u64(value: u64, name: &str) -> rusqlite::Result<i64> {
    i64::try_from(value).map_err(|_| {
        rusqlite::Error::InvalidParameterName(format!("{name} exceeds SQLite integer range"))
    })
}
