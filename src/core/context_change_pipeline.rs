//! Protocol-neutral projection work.
//!
//! SQLite is the durable runtime source of truth. This module does one job:
//! consume committed need/offer changes and mark newly unblocked facts pending.
//!
//! The SQL-backed pending-fact projection pipeline lives in
//! `pending_fact_pipeline.rs`. Runtime calls that module to process pending
//! facts, passing this pipeline as the context-change state that gets updated.
//!
//! Main flows:
//!
//! ```text
//! submit_fact_to_store
//!   -> insert fact row and pending row in one transaction
//!
//! pending_fact_pipeline::process_pending_facts
//!   -> claim pending facts from SQLite
//!   -> project each fact and commit needs/offers/time wakes/intents
//!   -> record pending context changes for newly added needs/offers
//!
//! process_context_changes
//!   -> claim pending context changes from SQLite
//!   -> run context delta matching against stored context
//!   -> mark dependent facts pending in the same transaction
//!
//! process_due_time_range
//!   -> find due time triggers
//!   -> insert pending rows for those facts
//!   -> remember the triggering time range for projection context
//!
//! intent_pipeline::dispatch_*_from_store
//!   -> claim durable intents from SQLite
//!   -> run handlers
//!   -> commit handler facts, purges, atomic rows, and intent output
//!
//! purge_fact_from_store
//!   -> delete the fact and all derived durable state
//! ```

use crate::core::context::{ContextOffer, ContextSetDelta};
use crate::core::facts::{Fact, FactId};
use crate::core::intent_pipeline::IntentPipeline;
use crate::core::matchers::{ContextMatch, ContextMatcher};
use crate::core::pending_fact_pipeline;
use crate::core::projection::{Projector, TimeRange, Timeline};
use crate::core::store::{Store, TableName};

use crate::core::context_change_helpers::{
    context_need_row, context_offer_row, decode_pending_context_change_row, decode_time_wake_row,
    insert_fact_and_pending_in_tx, insert_pending_owner_in_tx, pending_time_range_row,
    purge_fact_in_tx, sqlite_string_error, stored_context_matches,
};

pub(crate) use crate::core::context_change_helpers::{
    persisted_context, persisted_fact, persisted_facts,
};

pub(crate) const FACTS: TableName = TableName::new("facts");
pub(crate) const CONTEXT_NEEDS: TableName = TableName::new("context_needs");
pub(crate) const CONTEXT_OFFERS: TableName = TableName::new("context_offers");
pub(crate) const TIME_WAKES: TableName = TableName::new("time_wakes");
pub(crate) const PENDING_PROJECTION: TableName = TableName::new("pending_projection");
pub(crate) const PENDING_TIME_RANGES: TableName = TableName::new("pending_time_ranges");
pub(crate) const PENDING_CONTEXT_CHANGES: TableName = TableName::new("pending_context_changes");
pub(crate) const INTENTS: TableName = TableName::new("intents");

pub(crate) fn commit_projected_context_offers(
    store: &Store,
    offers: &[ContextOffer],
    completed_fact_ids: &[FactId],
) -> Result<(), String> {
    store
        .write_transaction(|tx| {
            tx.insert_table_rows_in_tx(offers.iter().map(context_offer_row).collect())?;
            tx.delete_table_rows_in_tx(
                PENDING_PROJECTION,
                completed_fact_ids.iter().map(|id| id.to_vec()).collect(),
            )?;
            Ok(())
        })
        .map_err(|err| format!("commit projected context offers: {err}"))
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PipelineReport {
    pub projections: usize,
    pub context_matches: usize,
    pub woken_facts: usize,
    pub intents: usize,
}

/// Durable facts, pending work, context, and time triggers live in SQLite.
/// This struct exists to name and scope protocol-neutral context matching:
/// converting committed need/offer deltas into newly pending facts.
#[derive(Debug, Default)]
pub struct ContextChangePipeline;

impl ContextChangePipeline {
    // Construction.

    pub(crate) fn new() -> Self {
        Self::default()
    }

    // Store-backed intake and purge.

    pub(crate) fn submit_fact_to_store(
        &mut self,
        store: &Store,
        fact: Fact,
    ) -> Result<bool, String> {
        let inserted = store
            .write_transaction(|tx| insert_fact_and_pending_in_tx(tx, &fact))
            .map_err(|err| format!("submit fact: {err}"))?;
        Ok(inserted)
    }

    pub(crate) fn submit_facts_to_store(
        &mut self,
        store: &Store,
        facts: impl IntoIterator<Item = Fact>,
    ) -> Result<usize, String> {
        let facts = facts.into_iter().collect::<Vec<_>>();
        let inserted = store
            .write_transaction(|tx| {
                let mut inserted = Vec::new();
                for fact in &facts {
                    if insert_fact_and_pending_in_tx(tx, fact)? {
                        inserted.push(fact.id);
                    }
                }
                Ok(inserted)
            })
            .map_err(|err| format!("submit facts: {err}"))?;
        Ok(inserted.len())
    }

    pub(crate) fn purge_fact_from_store(
        &mut self,
        store: &Store,
        owner: FactId,
    ) -> Result<bool, String> {
        let changed = store
            .write_transaction(|tx| purge_fact_in_tx(tx, owner))
            .map_err(|err| format!("purge fact: {err}"))?;
        Ok(changed)
    }

    pub(crate) fn process_due_time_range(
        &mut self,
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

    // Context-change matching.

    fn process_context_changes(
        &mut self,
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

    pub(crate) fn process_pending_facts_and_context_changes(
        &mut self,
        intent_pipeline: &mut IntentPipeline,
        projector: &impl Projector,
        matchers: &[&dyn ContextMatcher],
        store: &Store,
        allowed_tables: &[TableName],
        limit: usize,
    ) -> Result<PipelineReport, String> {
        let mut total = PipelineReport::default();

        loop {
            let context_report = self.process_context_changes(store, matchers, limit)?;
            let context_woke_facts = context_report.woken_facts > 0;
            add_pipeline_report(&mut total, context_report);

            if total.projections >= limit {
                break;
            }

            let projection_report = pending_fact_pipeline::process_pending_facts(
                intent_pipeline,
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
}

fn add_pipeline_report(total: &mut PipelineReport, report: PipelineReport) {
    total.projections += report.projections;
    total.context_matches += report.context_matches;
    total.woken_facts += report.woken_facts;
    total.intents += report.intents;
}

struct ContextChangeCommit {
    context_matches: Vec<ContextMatch>,
    woken_facts: usize,
}

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
