//! Pending fact projection orchestration.

use super::effects::validate_pipeline_effects;
use super::projection_commit::{commit_projection_effects, ProjectionCommit, ProjectionEffects};
use super::projection_queue::{load_pending_fact, pending_owner_batch, PendingFact};
use super::projection_run::run_projection_with_context;
use crate::core::fact_store::purge_fact_in_tx;
use crate::core::matchers::ContextMatcher;
use crate::core::pipeline::report::PipelineReport;
use crate::core::projectors::Projector;
use crate::core::store::{Store, TableName};

/// Process pending facts from SQLite one at a time until there is no work or
/// `limit` facts have completed projection.
///
/// This is the readable entry point for the SQL-backed projection path:
///
/// 1. `pending_owner_batch` chooses pending fact ids from SQLite.
/// 2. `load_pending_fact` loads each fact's projection inputs.
/// 3. `process_pending_fact` completes all processing for that one fact.
/// 4. `prepare_projection_effects` runs protocol projection and groups the outputs.
/// 5. `commit_projection_effects` commits every durable and restart-local effect in one
///    SQLite transaction.
/// 6. `finish_pending_fact` refreshes compatibility memory and the report after
///    the transaction has succeeded.
pub(crate) fn process_pending_projection_batch(
    projector: &(impl Projector + ?Sized),
    matchers: &[&dyn ContextMatcher],
    store: &Store,
    allowed_tables: &[TableName],
    limit: usize,
) -> Result<PipelineReport, String> {
    let mut report = PipelineReport::default();

    for fact_id in pending_owner_batch(store, limit)? {
        if report.projections >= limit {
            break;
        }
        let Some(pending_fact) = load_pending_fact(store, fact_id, matchers)? else {
            store
                .write_transaction(|tx| purge_fact_in_tx(tx, fact_id))
                .map_err(|err| format!("purge stale pending fact: {err}"))?;
            continue;
        };
        process_pending_fact(
            pending_fact,
            projector,
            matchers,
            store,
            allowed_tables,
            &mut report,
        )?;
    }

    Ok(report)
}

/// Complete all projection work for one pending fact.
///
/// The middle call, `commit_projection_effects`, is the only SQLite
/// transaction in this per-fact pipeline. Everything before it is uncommitted
/// calculation. Everything after it refreshes compatibility memory and reporting.
fn process_pending_fact(
    pending_fact: PendingFact,
    projector: &(impl Projector + ?Sized),
    matchers: &[&dyn ContextMatcher],
    store: &Store,
    allowed_tables: &[TableName],
    report: &mut PipelineReport,
) -> Result<(), String> {
    let effects = prepare_projection_effects(projector, pending_fact, allowed_tables)?;
    let commit = commit_projection_effects(store, &effects, matchers, allowed_tables)?;
    finish_pending_fact(commit, report);
    Ok(())
}

/// Run the protocol projector for one fact and split its output.
///
/// No rows are written here. The result is an uncommitted `ProjectionEffects`
/// value that says what should happen if the projection commits.
fn prepare_projection_effects(
    projector: &(impl Projector + ?Sized),
    pending_fact: PendingFact,
    allowed_tables: &[TableName],
) -> Result<ProjectionEffects, String> {
    let PendingFact {
        fact_id,
        fact,
        previous_context,
        projection_context,
    } = pending_fact;
    let run = run_projection_with_context(projector, &fact, &previous_context, projection_context)?;
    validate_pipeline_effects(&run.pipeline, allowed_tables)?;
    Ok(ProjectionEffects {
        fact_id,
        next_context: run.context,
        next_time_wakes: run.time_wakes,
        context_delta: run.context_delta,
        pipeline: run.pipeline,
    })
}

/// Update compatibility memory and the report after a projection commit.
///
/// This function runs after SQLite has accepted the durable work and any
/// restart-local temp rows.
fn finish_pending_fact(commit: ProjectionCommit, report: &mut PipelineReport) {
    report.projections += 1;
    report.intents += commit.effects.intents();
    report.woken_facts += commit.woken_facts;
}
