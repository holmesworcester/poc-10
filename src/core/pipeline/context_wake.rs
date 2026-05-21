use crate::core::context::ContextSetDelta;
use crate::core::matchers::{ContextMatch, ContextMatcher};
use crate::core::pipeline::report::PipelineReport;
use crate::core::pipeline::{
    persisted_fact, CONTEXT_NEEDS, CONTEXT_OFFERS, PENDING_CONTEXT_CHANGES,
};
use crate::core::pipeline_storage::{
    context_need_row, context_offer_row, decode_pending_context_change_row,
    insert_pending_owner_in_tx, sqlite_string_error, stored_context_matches,
};
use crate::core::store::Store;

/// Drain pending need/offer changes and wake newly matched facts.
pub(super) fn process_context_changes(
    store: &Store,
    matchers: &[&dyn ContextMatcher],
    limit: usize,
) -> Result<PipelineReport, String> {
    let mut report = PipelineReport::default();
    if limit == 0 {
        return Ok(report);
    }

    let rows = store
        .table_rows(PENDING_CONTEXT_CHANGES)
        .map_err(|err| format!("load pending context changes: {err}"))?;
    let mut keys = Vec::new();
    let mut delta = ContextSetDelta::default();
    for (key, value) in rows.into_iter().take(limit) {
        let decoded = decode_pending_context_change_row(&key, &value)?;
        keys.push(key);
        delta.added_needs.extend(decoded.added_needs);
        delta.added_offers.extend(decoded.added_offers);
    }
    if keys.is_empty() {
        return Ok(report);
    }
    let commit = commit_context_change_matching(store, keys, &delta, matchers)?;
    report.context_matches += commit.context_matches.len();
    report.woken_facts += commit.woken_facts;
    Ok(report)
}

struct ContextChangeCommit {
    context_matches: Vec<ContextMatch>,
    woken_facts: usize,
}

/// Commit one batch of pending context changes.
///
/// Deleting the pending-change rows and inserting dependent pending facts are
/// one transaction, so a crash cannot replay already-consumed changes without
/// also preserving the wakeups they produced.
fn commit_context_change_matching(
    store: &Store,
    pending_keys: Vec<Vec<u8>>,
    delta: &ContextSetDelta,
    matchers: &[&dyn ContextMatcher],
) -> Result<ContextChangeCommit, String> {
    store
        .write_transaction(|tx| {
            tx.delete_table_rows_in_tx(PENDING_CONTEXT_CHANGES, pending_keys)?;
            let current_delta = current_stored_context_delta(tx, delta)?;
            let context_matches = stored_context_matches(tx, &current_delta, matchers)
                .map_err(sqlite_string_error)?;
            let mut woken_facts = 0usize;
            for matched in &context_matches {
                if persisted_fact(tx, &matched.need_owner)
                    .map_err(sqlite_string_error)?
                    .is_some()
                {
                    woken_facts += insert_pending_owner_in_tx(tx, matched.need_owner)?;
                }
            }
            Ok(ContextChangeCommit {
                context_matches,
                woken_facts,
            })
        })
        .map_err(|err| format!("process pending context change: {err}"))
}

/// Keep only added needs/offers that still exist at commit time.
///
/// A fact may have been purged or reprojected after the pending context-change
/// row was written. Matching against current rows prevents stale wakeups.
fn current_stored_context_delta(
    store: &Store,
    delta: &ContextSetDelta,
) -> rusqlite::Result<ContextSetDelta> {
    let mut current = ContextSetDelta::default();
    for need in &delta.added_needs {
        let row = context_need_row(need);
        if store.table_row(CONTEXT_NEEDS, &row.key)?.is_some() {
            current.added_needs.push(need.clone());
        }
    }
    for offer in &delta.added_offers {
        let row = context_offer_row(offer);
        if store.table_row(CONTEXT_OFFERS, &row.key)?.is_some() {
            current.added_offers.push(offer.clone());
        }
    }
    Ok(current)
}
