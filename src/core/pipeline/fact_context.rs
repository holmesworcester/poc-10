use crate::core::matchers::ContextMatcher;
use crate::core::pipeline::projection::process_pending_facts;
use crate::core::pipeline::report::{add_pipeline_report, PipelineReport};
use crate::core::pipeline::{PENDING_PROJECTION, PENDING_TIME_RANGES, TIME_WAKES};
use crate::core::projectors::{Projector, TimeRange, Timeline};
use crate::core::store::{Store, TableName};
use crate::core::wake::{execute_wake_plan_in_tx, WakeParam, WakePlan};

const TIME_WAKE_TABLES: &[TableName] = &[TIME_WAKES];

const DUE_TIME_WAKE_OWNER_SQL: &str = r#"
SELECT owner
FROM time_wakes
WHERE timeline = :timeline
  AND (:has_start = 0 OR at > :start_exclusive)
  AND at <= :end_inclusive
ORDER BY at, owner
LIMIT :limit
"#;

const DUE_TIME_RANGE_SQL: &str = r#"
SELECT owner,
       :timeline AS timeline,
       :has_start AS has_start,
       :start_exclusive AS start_exclusive,
       :end_inclusive AS end_inclusive
FROM time_wakes
WHERE timeline = :timeline
  AND (:has_start = 0 OR at > :start_exclusive)
  AND at <= :end_inclusive
ORDER BY at, owner
LIMIT :limit
"#;

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

    store
        .write_transaction(|tx| enqueue_due_time_wakes_in_tx(tx, &range, limit))
        .map_err(|err| format!("process due time range: {err}"))
}

fn enqueue_due_time_wakes_in_tx(
    store: &Store,
    range: &TimeRange,
    limit: usize,
) -> rusqlite::Result<usize> {
    let has_start = range.start_exclusive.is_some();
    let start_exclusive = range.start_exclusive.unwrap_or(0);
    let params = vec![
        WakeParam::text(":timeline", range.timeline.as_str()),
        WakeParam::bool(":has_start", has_start),
        WakeParam::u64(":start_exclusive", start_exclusive),
        WakeParam::u64(":end_inclusive", range.end_inclusive),
        WakeParam::u64(":limit", limit as u64),
    ];

    let inserted = execute_wake_plan_in_tx(
        store,
        PENDING_PROJECTION,
        &["owner"],
        &WakePlan::new(DUE_TIME_WAKE_OWNER_SQL, TIME_WAKE_TABLES, params.clone()),
    )?;

    execute_wake_plan_in_tx(
        store,
        PENDING_TIME_RANGES,
        &[
            "owner",
            "timeline",
            "has_start",
            "start_exclusive",
            "end_inclusive",
        ],
        &WakePlan::new(DUE_TIME_RANGE_SQL, TIME_WAKE_TABLES, params),
    )?;

    Ok(inserted)
}

/// Drive fact projection until no more work is found.
///
/// Projection commits context edges and immediately wakes exact and custom
/// context matches. The loop stops when no fact projected or the projection
/// limit has been reached.
pub(crate) fn process_pending_facts_and_context_changes(
    projector: &(impl Projector + ?Sized),
    matchers: &[&dyn ContextMatcher],
    store: &Store,
    allowed_tables: &[TableName],
    limit: usize,
) -> Result<PipelineReport, String> {
    let mut total = PipelineReport::default();

    loop {
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

        if !projected_facts {
            break;
        }
    }

    Ok(total)
}
