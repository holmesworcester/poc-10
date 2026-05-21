//! Pending projection queue reads and per-fact projection input loading.

use super::context_matching::stored_matching_context;
use super::context_rows::stored_context_for_owner;
use crate::core::context::ContextSet;
use crate::core::fact_store::persisted_fact;
use crate::core::facts::{Fact, FactId};
use crate::core::matchers::ContextMatcher;
use crate::core::projectors::{ProjectionContext, TimeRange, Timeline};
use crate::core::schema::{FACTS, PENDING_PROJECTION, PENDING_TIME_RANGES};
use crate::core::schema_dsl::ColumnType;
use crate::core::store::{ColumnValue, SelectColumn, SelectedRow, SelectedValue, Store};

/// A fact that has been claimed from the pending queue and is ready to project.
pub(super) struct PendingFact {
    pub(super) fact_id: FactId,
    pub(super) fact: Fact,
    pub(super) previous_context: ContextSet,
    pub(super) projection_context: ProjectionContext,
}

/// Read the next pending fact ids without mutating the queue.
///
/// The commit step removes the row only after projection succeeds. Missing
/// facts are handled by the caller as stale pending rows and purged there.
pub(super) fn pending_owner_batch(store: &Store, limit: usize) -> Result<Vec<FactId>, String> {
    store
        .select_only(
            r#"
            SELECT p.owner
            FROM pending_projection p
            LEFT JOIN facts f ON f.id = p.owner
            ORDER BY COALESCE(f.timestamp, 9223372036854775807), p.owner
            LIMIT :limit
            "#,
            &[PENDING_PROJECTION, FACTS],
            &[(":limit", ColumnValue::U64(limit as u64))],
            &[SelectColumn {
                name: "owner",
                ty: ColumnType::Bytes { len: Some(32) },
            }],
        )
        .map_err(|err| format!("load pending projection: {err}"))?
        .into_iter()
        .map(decode_pending_owner)
        .collect()
}

/// Load everything projection needs for one fact.
///
/// `previous_context` is the fact's standing context before this run.
/// `projection_context` is the matched input context exposed to the projector
/// for this run, including any due time ranges.
pub(super) fn load_pending_fact(
    store: &Store,
    fact_id: FactId,
    matchers: &[&dyn ContextMatcher],
) -> Result<Option<PendingFact>, String> {
    let Some(fact) = persisted_fact(store, &fact_id)? else {
        return Ok(None);
    };
    let previous_context = stored_context_for_owner(store, &fact_id)?;
    let time_ranges = pending_time_ranges_for_owner(store, &fact_id)?;
    let projection_context =
        stored_matching_context(store, &previous_context, matchers)?.with_time_ranges(time_ranges);
    Ok(Some(PendingFact {
        fact_id,
        fact,
        previous_context,
        projection_context,
    }))
}

fn decode_pending_owner(row: SelectedRow) -> Result<FactId, String> {
    match row.get("owner") {
        Some(SelectedValue::Bytes(bytes)) => bytes
            .as_slice()
            .try_into()
            .map_err(|_| "pending projection owner should be 32 bytes".to_string()),
        _ => Err("pending projection row missing owner".to_string()),
    }
}

fn pending_time_ranges_for_owner(store: &Store, owner: &FactId) -> Result<Vec<TimeRange>, String> {
    store
        .select_only(
            r#"
            SELECT timeline, has_start, start_exclusive, end_inclusive
            FROM pending_time_ranges
            WHERE owner = :owner
            ORDER BY timeline, has_start, start_exclusive, end_inclusive
            "#,
            &[PENDING_TIME_RANGES],
            &[(":owner", ColumnValue::Bytes(owner))],
            &[
                SelectColumn {
                    name: "timeline",
                    ty: ColumnType::Text,
                },
                SelectColumn {
                    name: "has_start",
                    ty: ColumnType::Bool,
                },
                SelectColumn {
                    name: "start_exclusive",
                    ty: ColumnType::U64,
                },
                SelectColumn {
                    name: "end_inclusive",
                    ty: ColumnType::U64,
                },
            ],
        )
        .map_err(|err| format!("load pending time ranges: {err}"))?
        .into_iter()
        .map(decode_pending_time_range)
        .collect()
}

fn decode_pending_time_range(row: SelectedRow) -> Result<TimeRange, String> {
    let timeline = match row.get("timeline") {
        Some(SelectedValue::Text(value)) => Timeline::new(value.clone())?,
        _ => return Err("pending time range row missing timeline".to_string()),
    };
    let has_start = match row.get("has_start") {
        Some(SelectedValue::Bool(value)) => *value,
        _ => return Err("pending time range row missing has_start".to_string()),
    };
    let start = match row.get("start_exclusive") {
        Some(SelectedValue::U64(value)) => *value,
        _ => return Err("pending time range row missing start_exclusive".to_string()),
    };
    let end_inclusive = match row.get("end_inclusive") {
        Some(SelectedValue::U64(value)) => *value,
        _ => return Err("pending time range row missing end_inclusive".to_string()),
    };
    Ok(TimeRange {
        timeline,
        start_exclusive: has_start.then_some(start),
        end_inclusive,
    })
}
