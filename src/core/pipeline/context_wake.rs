use crate::core::context::ContextSetDelta;
use crate::core::matchers::{ContextMatch, ContextMatcher};
use crate::core::pipeline::report::PipelineReport;
use crate::core::pipeline::{persisted_fact, PENDING_PROJECTION};
use crate::core::store::{ColumnValue, Store};
use std::collections::BTreeSet;

use super::context_queue::{
    delete_pending_context_change_in_tx, pending_context_change_batch, PendingContextChange,
};
use super::context_store::stored_context_matches;
use super::context_wake_sql::{current_stored_context_delta, exact_context_matches};
use super::effects::sqlite_string_error;

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

    let changes = pending_context_change_batch(store, limit)?;
    let mut delta = ContextSetDelta::default();
    for change in &changes {
        change.add_to_delta(&mut delta);
    }
    if changes.is_empty() {
        return Ok(report);
    }
    let commit = commit_context_change_matching(store, changes, &delta, matchers)?;
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
    pending_changes: Vec<PendingContextChange>,
    delta: &ContextSetDelta,
    matchers: &[&dyn ContextMatcher],
) -> Result<ContextChangeCommit, String> {
    store
        .write_transaction(|tx| {
            for change in &pending_changes {
                delete_pending_context_change_in_tx(tx, change)?;
            }
            let current_delta = current_stored_context_delta(tx, delta)?;
            let mut context_matches = exact_context_matches(tx, &current_delta, matchers)?;
            let custom_matchers = matchers
                .iter()
                .copied()
                .filter(|matcher| matcher.exact_selector_role().is_none())
                .collect::<Vec<_>>();
            context_matches.extend(
                stored_context_matches(tx, &current_delta, &custom_matchers)
                    .map_err(sqlite_string_error)?,
            );
            let context_matches = context_matches.into_iter().collect::<BTreeSet<_>>();
            let woken_facts = wake_matched_facts(tx, &context_matches)?;
            Ok(ContextChangeCommit {
                context_matches: context_matches.into_iter().collect(),
                woken_facts,
            })
        })
        .map_err(|err| format!("process pending context change: {err}"))
}

fn wake_matched_facts(
    store: &Store,
    context_matches: &BTreeSet<ContextMatch>,
) -> rusqlite::Result<usize> {
    let mut woken_facts = 0usize;
    for matched in context_matches {
        if persisted_fact(store, &matched.need_owner)
            .map_err(sqlite_string_error)?
            .is_some()
            && store.insert_typed_row_in_tx(
                PENDING_PROJECTION,
                &[("owner", ColumnValue::Bytes(&matched.need_owner))],
            )?
        {
            woken_facts += 1;
        }
    }
    Ok(woken_facts)
}
