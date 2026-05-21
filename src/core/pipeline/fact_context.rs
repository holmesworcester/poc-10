use crate::core::matchers::ContextMatcher;
use crate::core::pipeline::context_wake::process_context_changes;
use crate::core::pipeline::projection::process_pending_facts;
use crate::core::pipeline::report::{add_pipeline_report, PipelineReport};
use crate::core::pipeline::TIME_WAKES;
use crate::core::pipeline_storage::{
    decode_time_wake_row, insert_pending_owner_in_tx, pending_time_range_row,
};
use crate::core::projectors::{Projector, TimeRange, Timeline};
use crate::core::store::{Store, TableName};

/// Turn due time wakes into pending facts plus projection time context.
///
/// Time is modeled as another source of context: the fact is marked pending
/// and receives the triggering `TimeRange` when it projects.
pub(crate) fn process_due_time_range(
    store: &Store,
    timeline: Timeline,
    start_exclusive: Option<u64>,
    end_inclusive: u64,
    limit: usize,
) -> Result<usize, String> {
    if limit == 0 {
        return Ok(0);
    }
    let range = TimeRange {
        timeline,
        start_exclusive,
        end_inclusive,
    };
    let mut due = store
        .table_rows(TIME_WAKES)
        .map_err(|err| format!("load time wakes: {err}"))?
        .into_iter()
        .map(|(key, value)| decode_time_wake_row(&key, &value))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .filter(|wake| wake.timeline == range.timeline && range.contains(wake.at))
        .collect::<Vec<_>>();
    due.sort_by(|left, right| {
        left.at
            .cmp(&right.at)
            .then_with(|| left.owner.cmp(&right.owner))
            .then_with(|| left.timeline.cmp(&right.timeline))
    });
    due.dedup();
    due.truncate(limit);

    let inserted = store
        .write_transaction(|tx| {
            let mut inserted = 0usize;
            let mut time_range_rows = Vec::new();
            for wake in &due {
                inserted += insert_pending_owner_in_tx(tx, wake.owner)?;
                time_range_rows.push(pending_time_range_row(wake.owner, &range));
            }
            tx.insert_table_rows_in_tx(time_range_rows)?;
            Ok(inserted)
        })
        .map_err(|err| format!("process due time range: {err}"))?;
    Ok(inserted)
}

/// Drive context matching and fact projection until no more work is found.
///
/// The two pipelines intentionally alternate: context changes wake facts;
/// fact projection writes more context changes. The loop stops when neither
/// stage made progress or the projection limit has been reached.
pub(crate) fn process_pending_facts_and_context_changes(
    projector: &(impl Projector + ?Sized),
    matchers: &[&dyn ContextMatcher],
    store: &Store,
    allowed_tables: &[TableName],
    limit: usize,
) -> Result<PipelineReport, String> {
    let mut total = PipelineReport::default();

    loop {
        let context_report = process_context_changes(store, matchers, limit)?;
        let context_woke_facts = context_report.woken_facts > 0;
        add_pipeline_report(&mut total, context_report);

        if total.projections >= limit {
            break;
        }

        let projection_report = process_pending_facts(
            projector,
            matchers,
            store,
            allowed_tables,
            limit - total.projections,
        )?;
        let projected_facts = projection_report.projections > 0;
        add_pipeline_report(&mut total, projection_report);

        if !context_woke_facts && !projected_facts {
            break;
        }
    }

    Ok(total)
}
