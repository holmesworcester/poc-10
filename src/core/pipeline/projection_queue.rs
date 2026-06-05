//! Queue drain for pending projection items.
//!
//! This module owns "many items": selecting pending durable and ephemeral facts
//! and repeatedly applying the one-item projection step in `projection`.

use super::commit_effects::IntentAdmissionPolicy;
use super::projection::{
    commit_projection_effects, drop_rejected_ephemeral_input, drop_stale_ephemeral_input,
    isolate_rejected_durable_fact_in_tx, load_pending_fact, pending_durable_fact_ids,
    pending_ephemeral_fact_ids, prepare_projection_effects, purge_stale_durable_pending_in_tx,
    ProjectionSource,
};
use super::route::FactAdmissionFn;
use super::{ProjectionProgress, Projector};
use crate::core::facts::FactId;
use crate::core::store::{Store, TableName};

pub(super) fn drain_projection_queue(
    store: &Store,
    projector: &dyn Projector,
    allowed_tables: &[TableName],
    fact_admission: Option<FactAdmissionFn>,
    limit: usize,
    intent_policy: IntentAdmissionPolicy<'_>,
) -> Result<ProjectionProgress, String> {
    let worker = ProjectionQueue {
        store,
        projector,
        allowed_tables,
        fact_admission,
    };
    worker.drain(limit, intent_policy)
}

struct ProjectionQueue<'a> {
    store: &'a Store,
    projector: &'a dyn Projector,
    allowed_tables: &'a [TableName],
    fact_admission: Option<FactAdmissionFn>,
}

impl ProjectionQueue<'_> {
    fn drain(
        &self,
        limit: usize,
        intent_policy: IntentAdmissionPolicy<'_>,
    ) -> Result<ProjectionProgress, String> {
        let mut total = ProjectionProgress::default();
        while total.projected < limit {
            let progress = self.drain_once(limit - total.projected, intent_policy)?;
            let projected = progress.projected > 0;
            total.merge(progress);
            if !projected {
                break;
            }
        }
        Ok(total)
    }

    fn drain_once(
        &self,
        limit: usize,
        intent_policy: IntentAdmissionPolicy<'_>,
    ) -> Result<ProjectionProgress, String> {
        let mut progress = ProjectionProgress::default();

        let durable_fact_ids =
            crate::core::perf_profile::measure_result("projection_pending_load", || {
                pending_durable_fact_ids(self.store, limit)
            })?;
        for fact_id in durable_fact_ids {
            if progress.projected >= limit {
                break;
            }
            let Some(pending_fact) =
                crate::core::perf_profile::measure_result("projection_load_pending_fact", || {
                    load_pending_fact(self.store, ProjectionSource::Durable, fact_id)
                })?
            else {
                self.purge_stale_durable_pending(fact_id)?;
                continue;
            };
            self.process_projection_item(
                pending_fact,
                QueuedProjectionKind::Durable,
                &mut progress,
                intent_policy,
            )?;
        }

        if progress.projected < limit {
            let ephemeral_fact_ids =
                crate::core::perf_profile::measure_result("projection_ephemeral_load", || {
                    pending_ephemeral_fact_ids(self.store, limit - progress.projected)
                })?;
            for fact_id in ephemeral_fact_ids {
                if progress.projected >= limit {
                    break;
                }
                let Some(pending_fact) = crate::core::perf_profile::measure_result(
                    "projection_load_pending_fact",
                    || load_pending_fact(self.store, ProjectionSource::Ephemeral, fact_id),
                )?
                else {
                    drop_stale_ephemeral_input(self.store, fact_id)?;
                    continue;
                };
                self.process_projection_item(
                    pending_fact,
                    QueuedProjectionKind::Ephemeral,
                    &mut progress,
                    intent_policy,
                )?;
            }
        }

        Ok(progress)
    }

    fn process_projection_item(
        &self,
        pending_fact: super::projection::PendingFact,
        kind: QueuedProjectionKind,
        progress: &mut ProjectionProgress,
        intent_policy: IntentAdmissionPolicy<'_>,
    ) -> Result<(), String> {
        let fact_id = pending_fact.fact_id();
        let effects =
            match crate::core::perf_profile::measure_result("projection_prepare_effects", || {
                prepare_projection_effects(
                    self.store,
                    self.projector,
                    pending_fact,
                    self.allowed_tables,
                    self.fact_admission,
                    intent_policy,
                )
            }) {
                Ok(effects) => effects,
                Err(_rejection) => {
                    self.handle_rejected_projection(kind, fact_id)?;
                    return Ok(());
                }
            };
        let suppressed_intents =
            crate::core::perf_profile::measure_result("projection_commit_effects", || {
                commit_projection_effects(
                    self.store,
                    &effects,
                    self.allowed_tables,
                    self.fact_admission,
                )
            })?;
        progress.suppressed_intents += suppressed_intents;
        progress.projected += 1;
        progress.status.progressed = true;
        Ok(())
    }

    fn handle_rejected_projection(
        &self,
        kind: QueuedProjectionKind,
        fact_id: FactId,
    ) -> Result<(), String> {
        match kind {
            QueuedProjectionKind::Durable => self.isolate_rejected_durable_fact(fact_id),
            QueuedProjectionKind::Ephemeral => drop_rejected_ephemeral_input(self.store, fact_id),
        }
    }

    fn purge_stale_durable_pending(&self, fact_id: FactId) -> Result<(), String> {
        self.store
            .write_transaction(|tx| purge_stale_durable_pending_in_tx(tx, fact_id))
            .map(|_| ())
            .map_err(|err| format!("purge stale durable pending fact: {err}"))
    }

    fn isolate_rejected_durable_fact(&self, fact_id: FactId) -> Result<(), String> {
        self.store
            .write_transaction(|tx| {
                isolate_rejected_durable_fact_in_tx(tx, fact_id, self.projector)
            })
            .map_err(|err| format!("isolate rejected durable fact: {err}"))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum QueuedProjectionKind {
    Durable,
    Ephemeral,
}
