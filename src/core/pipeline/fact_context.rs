use crate::core::matchers::ContextMatcher;
use crate::core::pipeline::context_wake::process_context_changes;
use crate::core::pipeline::projection::process_pending_facts;
use crate::core::pipeline::report::{add_pipeline_report, PipelineReport};
use crate::core::pipeline::{PENDING_PROJECTION, PENDING_TIME_RANGES, TIME_WAKES};
use crate::core::projectors::{Projector, TimeRange, Timeline};
use crate::core::schema_dsl::ColumnType;
use crate::core::store::{ColumnValue, SelectColumn, SelectedRow, SelectedValue, Store, TableName};

struct DueTimeWake {
    owner: [u8; 32],
}

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
    let due = due_time_wakes(store, &range, limit)?;

    let inserted = store
        .write_transaction(|tx| {
            let mut inserted = 0usize;
            for wake in &due {
                if tx.insert_typed_row_in_tx(
                    PENDING_PROJECTION,
                    &[("owner", ColumnValue::Bytes(&wake.owner))],
                )? {
                    inserted += 1;
                }
                tx.insert_typed_row_in_tx(
                    PENDING_TIME_RANGES,
                    &[
                        ("owner", ColumnValue::Bytes(&wake.owner)),
                        ("timeline", ColumnValue::Text(range.timeline.as_str())),
                        (
                            "has_start",
                            ColumnValue::Bool(range.start_exclusive.is_some()),
                        ),
                        (
                            "start_exclusive",
                            ColumnValue::U64(range.start_exclusive.unwrap_or(0)),
                        ),
                        ("end_inclusive", ColumnValue::U64(range.end_inclusive)),
                    ],
                )?;
            }
            Ok(inserted)
        })
        .map_err(|err| format!("process due time range: {err}"))?;
    Ok(inserted)
}

fn due_time_wakes(
    store: &Store,
    range: &TimeRange,
    limit: usize,
) -> Result<Vec<DueTimeWake>, String> {
    let rows = store
        .select_only(
            r#"
            SELECT owner
            FROM time_wakes
            WHERE timeline = :timeline
              AND (:has_start = 0 OR at > :start_exclusive)
              AND at <= :end_inclusive
            ORDER BY at, owner
            LIMIT :limit
            "#,
            &[TIME_WAKES],
            &[
                (":timeline", ColumnValue::Text(range.timeline.as_str())),
                (
                    ":has_start",
                    ColumnValue::Bool(range.start_exclusive.is_some()),
                ),
                (
                    ":start_exclusive",
                    ColumnValue::U64(range.start_exclusive.unwrap_or(0)),
                ),
                (":end_inclusive", ColumnValue::U64(range.end_inclusive)),
                (":limit", ColumnValue::U64(limit as u64)),
            ],
            &[SelectColumn {
                name: "owner",
                ty: ColumnType::Bytes { len: Some(32) },
            }],
        )
        .map_err(|err| format!("load due time wakes: {err}"))?;
    rows.into_iter().map(decode_due_time_wake).collect()
}

fn decode_due_time_wake(row: SelectedRow) -> Result<DueTimeWake, String> {
    let owner = match row.get("owner") {
        Some(SelectedValue::Bytes(bytes)) => bytes
            .as_slice()
            .try_into()
            .map_err(|_| "due time wake owner should be 32 bytes".to_string())?,
        _ => return Err("due time wake row missing owner".to_string()),
    };
    Ok(DueTimeWake { owner })
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
