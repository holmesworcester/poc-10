//! Pending projection queue reads and per-fact projection input loading.

use super::context_matching::stored_matching_context;
use super::context_rows::stored_context_for_owner;
use crate::core::context::ContextSet;
use crate::core::fact_store::persisted_fact;
use crate::core::facts::{Fact, FactId};
use crate::core::matchers::ContextMatcher;
use crate::core::projectors::{ProjectionContext, TimeRange, Timeline};
use crate::core::store::Store;
use rusqlite::params;

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
    let limit =
        i64::try_from(limit).map_err(|_| "pending projection limit exceeds i64".to_string())?;
    let mut stmt = store
        .conn()
        .prepare(
            r#"
            SELECT p.owner
            FROM pending_projection p
            LEFT JOIN local_fact_admissions m ON m.fact_id = p.owner
            ORDER BY COALESCE(m.received_at, 9223372036854775807), p.owner
            LIMIT ?1
            "#,
        )
        .map_err(|err| format!("load pending projection: {err}"))?;
    let rows = stmt
        .query_map(params![limit], |row| {
            fact_id_column(row.get::<_, Vec<u8>>(0)?, "owner")
        })
        .map_err(|err| format!("load pending projection: {err}"))?;
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|err| format!("load pending projection: {err}"))
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

fn pending_time_ranges_for_owner(store: &Store, owner: &FactId) -> Result<Vec<TimeRange>, String> {
    let mut stmt = store
        .conn()
        .prepare(
            r#"
            SELECT timeline, has_start, start_exclusive, end_inclusive
            FROM pending_time_ranges
            WHERE owner = ?1
            ORDER BY timeline, has_start, start_exclusive, end_inclusive
            "#,
        )
        .map_err(|err| format!("load pending time ranges: {err}"))?;
    let rows = stmt
        .query_map(params![owner.as_slice()], decode_pending_time_range)
        .map_err(|err| format!("load pending time ranges: {err}"))?;
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|err| format!("load pending time ranges: {err}"))
}

fn decode_pending_time_range(row: &rusqlite::Row<'_>) -> rusqlite::Result<TimeRange> {
    let timeline =
        Timeline::new(row.get::<_, String>(0)?).map_err(rusqlite::Error::InvalidParameterName)?;
    let has_start = match row.get::<_, i64>(1)? {
        0 => false,
        1 => true,
        other => {
            return Err(rusqlite::Error::InvalidParameterName(format!(
                "pending time range has invalid bool {other}"
            )));
        }
    };
    let start = u64_column(row.get::<_, i64>(2)?, "start_exclusive")?;
    let end_inclusive = u64_column(row.get::<_, i64>(3)?, "end_inclusive")?;
    Ok(TimeRange {
        timeline,
        start_exclusive: has_start.then_some(start),
        end_inclusive,
    })
}

fn fact_id_column(bytes: Vec<u8>, name: &str) -> rusqlite::Result<FactId> {
    bytes.try_into().map_err(|_| {
        rusqlite::Error::InvalidParameterName(format!("{name} is not a 32-byte fact id"))
    })
}

fn u64_column(value: i64, name: &str) -> rusqlite::Result<u64> {
    u64::try_from(value)
        .map_err(|_| rusqlite::Error::InvalidParameterName(format!("{name} is negative")))
}
