use crate::core::pipeline::TIME_WAKES;
use crate::core::pipeline_storage::{
    decode_time_wake_row, insert_pending_owner_in_tx, pending_time_range_row,
};
use crate::core::projectors::{TimeRange, Timeline};
use crate::core::store::Store;

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
