//! Core fact lifecycle and SQL-backed runtime pipeline.
//!
//! This module is the public facade and work driver for the reusable fact
//! pipeline. It names the first-class read stages:
//!
//! ```text
//! route -> decode -> authenticate -> adapt -> project -> effects -> commit
//! ```
//!
//! and the write-side shape protocol commands and authors should mirror:
//!
//! ```text
//! command -> author -> encode -> authenticate self-check -> admit -> read pipeline
//! ```
//!
//! Core owns when these stages run, how context is matched, and where commit
//! boundaries sit. Protocol fact families own the stage implementations: byte
//! layouts, authentication proofs, version adapters, semantic projection, row
//! construction, and user-facing commands. Keeping the contracts here makes the
//! core pipeline isomorphic with fact-family files without teaching core what a
//! workspace, message, invite, key wrap, sync range, or connection fact means.
//!
//! The SQL-backed worker modules below implement individual steps. The
//! `PipelineEngine` in this facade owns the generic state machine: admitted facts
//! and intents are queued, projection replaces per-fact context/time-wake state
//! atomically with effects, handler dispatch commits atomically with queue
//! deletion, handler intent output is committed through the same shared effect
//! language, and command, daemon, and replay modes differ only by handler and
//! intent-admission policy.

pub mod adapt;
pub mod authenticate;
mod commit_effects;
pub mod context;
pub(crate) mod context_store;
pub mod decode;
mod dispatch;
pub mod effects;
mod insert_select;
pub mod project;
mod project_pending_facts;
pub mod route;

pub use adapt::Adapter;
pub use authenticate::{
    authenticate_authored, verify_fact_id, AuthenticatedFact, Authentication, DecodedAuthenticator,
};
pub use context::{MatchedContext, ProjectionContext};
pub use decode::FactCodec;
pub use effects::{
    fact_purged_need, fact_purged_offer, fact_purged_range_need, fact_purged_range_offer,
    fact_purged_role, ProjectionOutput, TimeRange, TimeWake, Timeline,
};
pub use project::{project_staged, SemanticProjector};
pub use route::{
    EffectiveTagFn, EnvelopeRoute, FactAdmissionFn, FactPipeline, FactRoute, Projector,
    ProjectorFn, RouterProjector,
};

use crate::core::command_context::CommandOutput;
use crate::core::context::ContextOffer;
use crate::core::facts::{Fact, FactId};
use crate::core::intents::{Intent, IntentHandler};
use crate::core::schema::{EPHEMERAL_PROJECTION_INPUTS, LOCAL_INTENTS, PENDING_PROJECTION};
use crate::core::store::{Store, TableName};
use std::collections::BTreeSet;

use commit_effects::{sqlite_string_error, IntentAdmissionPolicy};
use project_pending_facts::{
    commit_projected_context_offers, commit_projection_effects, commit_projection_effects_in_tx,
    drop_rejected_ephemeral_input, drop_stale_ephemeral_input, isolate_rejected_durable_fact_in_tx,
    load_pending_fact, pending_ephemeral_batch, pending_owner_batch, prepare_projection_effects,
    process_due_time_range, purge_fact_from_store, purge_stale_durable_pending_in_tx,
    submit_facts_to_store, ProjectionSource, DURABLE_PROJECTION_TRANSACTION_CHUNK_LIMIT,
};

/// Factory for one protocol intent handler.
pub type HandlerFactory = fn() -> Box<dyn IntentHandler>;

/// Build the current intent for a recurring operational loop.
///
/// The daemon calls this while the process is online to mint one tick of live
/// work. Returning `Ok(None)` means there is nothing to do this tick. The
/// builder reads the store the same way a handler reads its inputs; it must not
/// depend on persisted scheduler rows, because recurring schedules are
/// in-memory only and never replayed.
pub type RecurringIntentBuilder = fn(&Store) -> Result<Option<Intent>, String>;

/// In-memory schedule for a live-only recurring operational intent.
///
/// Recurring intents are not durable state. The daemon installs these schedules
/// at startup, after replay has finished, and fires them on a fixed cadence
/// while the process runs. There is nothing to wipe on upgrade and nothing to
/// replay: operational repetition belongs here, not in durable time wakes or
/// projectors.
#[derive(Debug, Clone, Copy)]
pub struct RecurringIntentSpec {
    /// Cadence between successive fires once the loop is running.
    pub interval_ms: u64,
    /// Delay from daemon startup before the first fire.
    pub initial_delay_ms: u64,
    /// Build this tick's intent from current store state, or `None` to skip.
    pub build_intent: RecurringIntentBuilder,
}

/// One handler route in the protocol registry.
///
/// `name` is a human-facing route name used for exclusion lists. `intent_kind`
/// is the queue routing key that selects this handler for both durable and
/// ephemeral intents.
///
/// `runs_during_replay` answers one question: if this intent is emitted while
/// replay is rebuilding facts and rows, may core record and dispatch it before
/// the replay barrier finishes? Replay-enabled handlers must be deterministic
/// rebuild work over retained facts: no network IO, no fresh randomness, no
/// process-global mutable state, and no operational wall-clock decisions. Every
/// route declares this flag explicitly so adding a route forces a conscious
/// replay decision.
///
/// `recurrence` marks live-only operational repetition. A route with a
/// recurrence is installed as an in-memory daemon schedule and must not run
/// during replay.
#[derive(Debug, Clone, Copy)]
pub struct HandlerRoute {
    /// Human-facing route name used for exclusion lists.
    pub name: &'static str,
    /// Intent kind handled by this route.
    pub intent_kind: &'static str,
    /// Handler factory.
    pub factory: HandlerFactory,
    /// Whether core may dispatch this intent before the replay barrier finishes.
    pub runs_during_replay: bool,
    /// Live-only recurring schedule installed by the daemon, if any.
    pub recurrence: Option<RecurringIntentSpec>,
}

/// Public outcome returned by runtime pipeline calls.
///
/// Runtime callers only need to know whether a bounded pass moved work forward
/// and whether any handler asked to retry.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WorkStatus {
    /// Whether a bounded pass committed or staged any work.
    pub progressed: bool,
    /// Whether a handler asked to leave work queued for a later pass.
    pub retried: bool,
}

impl WorkStatus {
    /// No progress and no retry.
    pub fn idle() -> Self {
        Self::default()
    }

    /// Build status from a simple progressed flag.
    pub fn progressed(progressed: bool) -> Self {
        Self {
            progressed,
            retried: false,
        }
    }

    /// Accumulate status across pipeline stages.
    pub fn merge(&mut self, other: Self) {
        self.progressed |= other.progressed;
        self.retried |= other.retried;
    }

    /// Return whether the pass did nothing and hit no retry.
    pub fn is_idle(self) -> bool {
        !self.progressed && !self.retried
    }
}

/// Instantiated handlers for one runtime pass.
///
/// The set owns concrete handler values so dispatch can borrow trait objects
/// without rebuilding them for every queued row. Command processing builds a
/// filtered set to avoid daemon/network side effects; replay builds a filtered
/// set that contains only replay-allowed routes.
pub(crate) struct HandlerSet {
    entries: Vec<HandlerEntry>,
}

struct HandlerEntry {
    intent_kind: &'static str,
    handler: Box<dyn IntentHandler>,
}

impl HandlerSet {
    /// Instantiate all declared routes.
    pub(crate) fn new(routes: &'static [HandlerRoute]) -> Self {
        Self {
            entries: routes
                .iter()
                .map(|route| HandlerEntry {
                    intent_kind: route.intent_kind,
                    handler: (route.factory)(),
                })
                .collect(),
        }
    }

    /// Instantiate every route except the protocol-declared command exclusions.
    pub(crate) fn new_excluding(routes: &'static [HandlerRoute], excluded_names: &[&str]) -> Self {
        Self {
            entries: routes
                .iter()
                .filter(|route| !excluded_names.contains(&route.name))
                .map(|route| HandlerEntry {
                    intent_kind: route.intent_kind,
                    handler: (route.factory)(),
                })
                .collect(),
        }
    }

    /// Instantiate only routes allowed to run before the replay barrier.
    pub(crate) fn new_replay(routes: &'static [HandlerRoute]) -> Self {
        Self {
            entries: routes
                .iter()
                .filter(|route| route.runs_during_replay)
                .map(|route| HandlerEntry {
                    intent_kind: route.intent_kind,
                    handler: (route.factory)(),
                })
                .collect(),
        }
    }

    pub(crate) fn intent_kinds(&self) -> Vec<&'static str> {
        self.entries.iter().map(|entry| entry.intent_kind).collect()
    }

    fn handler_for_kind(&self, kind: &str) -> Option<&dyn IntentHandler> {
        self.entries
            .iter()
            .find(|entry| entry.intent_kind == kind)
            .map(|entry| entry.handler.as_ref())
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct IntentDispatchProgress {
    pub(crate) status: WorkStatus,
    pub(crate) dispatched: usize,
    pub(crate) suppressed_intents: usize,
}

/// Projection progress from one bounded drain pass.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct ProjectionProgress {
    /// Number of facts that completed projection.
    pub(crate) projected: usize,
    /// Follow-up intents emitted by projection but suppressed by the current mode.
    pub(crate) suppressed_intents: usize,
    /// Whether the pass made progress or hit a retry.
    pub(crate) status: WorkStatus,
}

impl ProjectionProgress {
    /// Accumulate another projection progress report.
    fn merge(&mut self, other: Self) {
        self.projected += other.projected;
        self.suppressed_intents += other.suppressed_intents;
        self.status.merge(other.status);
    }
}

/// Runtime-independent owner of the core pipeline work order.
///
/// `Runtime` holds the protocol description and process-facing API. This engine
/// owns the generic sequencing: projection drains, intent dispatch, due time-wake
/// admission, and the fixed ordering used by command, daemon, and replay modes.
pub(crate) struct PipelineEngine<'a> {
    store: &'a Store,
    projector: &'a dyn Projector,
    allowed_tables: &'a [TableName],
    fact_admission: Option<FactAdmissionFn>,
}

impl<'a> PipelineEngine<'a> {
    pub(crate) fn new(
        store: &'a Store,
        projector: &'a dyn Projector,
        allowed_tables: &'a [TableName],
        fact_admission: Option<FactAdmissionFn>,
    ) -> Self {
        Self {
            store,
            projector,
            allowed_tables,
            fact_admission,
        }
    }

    pub(crate) fn store(&self) -> &'a Store {
        self.store
    }

    /// Count durable plus ephemeral facts currently queued for projection.
    pub(crate) fn pending_fact_count(&self) -> usize {
        self.store
            .table_row_count(PENDING_PROJECTION)
            .expect("pipeline pending fact count should load from store")
            + self
                .store
                .table_row_count(EPHEMERAL_PROJECTION_INPUTS)
                .expect("pipeline ephemeral projection count should load from store")
    }

    /// Admit one fact and mark it pending for projection.
    pub(crate) fn submit_fact(&self, fact: Fact) -> Result<bool, String> {
        if let Some(admit) = self.fact_admission {
            admit(&fact)?;
        }
        submit_fact_to_store(self.store, fact)
    }

    /// Admit many facts in one transaction.
    pub(crate) fn submit_facts(
        &self,
        facts: impl IntoIterator<Item = Fact>,
    ) -> Result<usize, String> {
        let facts = facts.into_iter().collect::<Vec<_>>();
        if let Some(admit) = self.fact_admission {
            for fact in &facts {
                admit(fact)?;
            }
        }
        submit_facts_to_store(self.store, facts)
    }

    /// Remove one fact and its core-owned derived rows.
    pub(crate) fn purge_fact(&self, fact_id: FactId) -> Result<bool, String> {
        purge_fact_from_store(self.store, fact_id)
    }

    pub(crate) fn commit_projected_context_offers(
        &self,
        offers: &[ContextOffer],
        completed_fact_ids: &[FactId],
    ) -> Result<usize, String> {
        commit_projected_context_offers(self.store, offers, completed_fact_ids)
    }

    /// Queue durable idempotent handler work.
    pub(crate) fn submit_intent(&self, intent: Intent) -> Result<bool, String> {
        submit_intent_to_store(self.store, intent)
    }

    /// Queue process-local handler work.
    pub(crate) fn submit_local_intent(&self, intent: Intent) -> Result<bool, String> {
        submit_local_intent_to_store(self.store, intent)
    }

    /// Commit command effects and return the command receipt.
    pub(crate) fn submit_command_output<T>(
        &self,
        output: CommandOutput<T>,
        label: &str,
    ) -> Result<T, String> {
        let (receipt, effects) = output.into_parts();
        commit_pipeline_effects_to_store(
            self.store,
            &effects,
            self.allowed_tables,
            self.fact_admission,
            label,
        )?;
        Ok(receipt)
    }

    /// Drive one bounded projection drain pass.
    pub(crate) fn drain_projection(&self, limit: usize) -> Result<ProjectionProgress, String> {
        self.drain_projection_with_policy(limit, IntentAdmissionPolicy::All)
    }

    /// Drive one bounded replay-mode projection drain pass.
    pub(crate) fn drain_projection_filtering_intents(
        &self,
        limit: usize,
        allowed_intent_kinds: &[&'static str],
    ) -> Result<ProjectionProgress, String> {
        self.drain_projection_with_policy(
            limit,
            IntentAdmissionPolicy::AllowKinds(allowed_intent_kinds),
        )
    }

    /// Drive fact projection until no more work is found.
    ///
    /// Projection commits context edges and immediately wakes matching facts.
    /// The loop stops when no fact projected or the projection limit has been
    /// reached.
    fn drain_projection_with_policy(
        &self,
        limit: usize,
        intent_policy: IntentAdmissionPolicy<'_>,
    ) -> Result<ProjectionProgress, String> {
        let mut total = ProjectionProgress::default();

        loop {
            if total.projected >= limit {
                break;
            }

            let projection_report =
                self.process_projection_batch(limit - total.projected, intent_policy)?;
            let projected_facts = projection_report.projected > 0;
            total.merge(projection_report);

            if !projected_facts {
                break;
            }
        }

        Ok(total)
    }

    /// Process pending durable facts and ephemeral inputs from SQLite until
    /// there is no work or `limit` inputs have completed projection.
    fn process_projection_batch(
        &self,
        limit: usize,
        intent_policy: IntentAdmissionPolicy<'_>,
    ) -> Result<ProjectionProgress, String> {
        let mut progress = ProjectionProgress::default();

        let durable_fact_ids =
            crate::core::perf_profile::measure_result("projection_pending_batch_load", || {
                pending_owner_batch(self.store, limit)
            })?;
        if !durable_fact_ids.is_empty() {
            let chunk_len = durable_fact_ids
                .len()
                .min(limit)
                .min(DURABLE_PROJECTION_TRANSACTION_CHUNK_LIMIT);
            let durable_progress = self
                .process_durable_projection_chunk(&durable_fact_ids[..chunk_len], intent_policy)?;
            progress.merge(durable_progress);
        }

        if progress.projected < limit {
            let ephemeral_fact_ids = crate::core::perf_profile::measure_result(
                "projection_ephemeral_batch_load",
                || pending_ephemeral_batch(self.store, limit - progress.projected),
            )?;
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
                self.process_ephemeral_projection(pending_fact, &mut progress, intent_policy)?;
            }
        }

        Ok(progress)
    }

    /// Process a selected durable pending chunk in one SQLite transaction.
    ///
    /// The ordering is still load -> prepare -> commit per fact. The
    /// transaction only removes per-fact fsync overhead and lets later
    /// same-batch facts see rows committed by earlier same-batch facts.
    fn process_durable_projection_chunk(
        &self,
        fact_ids: &[FactId],
        intent_policy: IntentAdmissionPolicy<'_>,
    ) -> Result<ProjectionProgress, String> {
        crate::core::perf_profile::measure_result("projection_batch_transaction", || {
            self.store
                .write_transaction(|tx| {
                    crate::core::perf_profile::measure_result("projection_commit_tx_body", || {
                        let mut progress = ProjectionProgress::default();
                        for fact_id in fact_ids {
                            let Some(pending_fact) = crate::core::perf_profile::measure_result(
                                "projection_load_pending_fact",
                                || load_pending_fact(tx, ProjectionSource::Durable, *fact_id),
                            )
                            .map_err(sqlite_string_error)?
                            else {
                                purge_stale_durable_pending_in_tx(tx, *fact_id)?;
                                continue;
                            };
                            self.process_durable_projection_in_tx(
                                tx,
                                pending_fact,
                                &mut progress,
                                intent_policy,
                            )?;
                        }
                        Ok(progress)
                    })
                })
                .map_err(|err| format!("commit durable projection batch: {err}"))
        })
    }

    /// Complete all projection work for one ephemeral pending input.
    ///
    /// Ephemeral inputs are not durable facts, so projector/authentication
    /// rejection drops the transient input instead of parking evidence.
    fn process_ephemeral_projection(
        &self,
        pending_fact: project_pending_facts::PendingFact,
        progress: &mut ProjectionProgress,
        intent_policy: IntentAdmissionPolicy<'_>,
    ) -> Result<(), String> {
        let fact_id = pending_fact.fact_id();
        let effects =
            match crate::core::perf_profile::measure_result("projection_prepare_effects", || {
                prepare_projection_effects(
                    self.projector,
                    pending_fact,
                    self.store,
                    self.allowed_tables,
                    self.fact_admission,
                    intent_policy,
                )
            }) {
                Ok(effects) => effects,
                Err(_rejection) => {
                    drop_rejected_ephemeral_input(self.store, fact_id)?;
                    return Ok(());
                }
            };
        let suppressed_intents =
            crate::core::perf_profile::measure_result("projection_commit_effects", || {
                commit_projection_effects(
                    self.store,
                    &effects,
                    self.projector,
                    self.allowed_tables,
                    self.fact_admission,
                    intent_policy,
                )
            })?;
        progress.suppressed_intents += suppressed_intents;
        progress.projected += 1;
        progress.status.progressed = true;
        Ok(())
    }

    /// Complete all projection work for one durable pending fact in the caller's
    /// transaction.
    ///
    /// Rejected durable facts are isolated inside the same transaction so one
    /// bad fact cannot roll back the rest of the selected chunk.
    fn process_durable_projection_in_tx(
        &self,
        tx: &Store,
        pending_fact: project_pending_facts::PendingFact,
        progress: &mut ProjectionProgress,
        intent_policy: IntentAdmissionPolicy<'_>,
    ) -> rusqlite::Result<()> {
        let fact_id = pending_fact.fact_id();
        let effects =
            match crate::core::perf_profile::measure_result("projection_prepare_effects", || {
                prepare_projection_effects(
                    self.projector,
                    pending_fact,
                    tx,
                    self.allowed_tables,
                    self.fact_admission,
                    intent_policy,
                )
            }) {
                Ok(effects) => effects,
                Err(_rejection) => {
                    isolate_rejected_durable_fact_in_tx(tx, fact_id, self.projector)?;
                    return Ok(());
                }
            };
        let suppressed_intents =
            crate::core::perf_profile::measure_result("projection_commit_effects", || {
                commit_projection_effects_in_tx(
                    tx,
                    &effects,
                    self.projector,
                    self.allowed_tables,
                    self.fact_admission,
                    intent_policy,
                    0,
                )
            })?;
        progress.suppressed_intents += suppressed_intents;
        progress.projected += 1;
        progress.status.progressed = true;
        Ok(())
    }

    /// Drain pending projection until no projection work remains or rounds expire.
    pub(crate) fn process_projection_until_idle(
        &self,
        max_rounds: usize,
        limit_per_round: usize,
    ) -> Result<WorkStatus, String> {
        let mut total = WorkStatus::idle();
        for _ in 0..max_rounds {
            let progress = self.drain_projection(limit_per_round)?;
            total.merge(progress.status);
            if progress.projected == 0 && self.pending_fact_count() == 0 {
                return Ok(total);
            }
        }
        Err("projection work did not become idle within the round limit".to_string())
    }

    /// Dispatch queued intents with the provided handler set.
    pub(crate) fn dispatch_intents(
        &self,
        handlers: &HandlerSet,
        limit: usize,
    ) -> Result<WorkStatus, String> {
        Ok(self
            .dispatch_intents_with_policy(handlers, limit, None)?
            .status)
    }

    /// Dispatch queued intents while suppressing inadmissible follow-up work.
    pub(crate) fn dispatch_intents_filtering(
        &self,
        handlers: &HandlerSet,
        limit: usize,
        allowed_followup_kinds: &[&'static str],
    ) -> Result<IntentDispatchProgress, String> {
        self.dispatch_intents_with_policy(handlers, limit, Some(allowed_followup_kinds))
    }

    fn dispatch_intents_with_policy(
        &self,
        handlers: &HandlerSet,
        limit: usize,
        allowed_followup_kinds: Option<&[&'static str]>,
    ) -> Result<IntentDispatchProgress, String> {
        let mut progress = IntentDispatchProgress::default();
        let kinds = handlers.intent_kinds();
        let mut retried_local = BTreeSet::<(String, Vec<u8>)>::new();
        for _ in 0..limit {
            let Some(queued) = next_queued_intent(self.store, &kinds)? else {
                break;
            };
            let kind = queued.intent.kind.as_str();
            let local_retry_key = if queued.table == LOCAL_INTENTS {
                Some((kind.to_owned(), queued.intent.key.clone()))
            } else {
                None
            };
            if local_retry_key
                .as_ref()
                .is_some_and(|key| retried_local.contains(key))
            {
                break;
            }
            let handler = handlers
                .handler_for_kind(kind)
                .ok_or_else(|| format!("no handler registered for intent kind {kind}"))?;
            let report = if let Some(allowed) = allowed_followup_kinds {
                dispatch_queued_intent_filtering_intents(
                    handler,
                    self.store,
                    self.allowed_tables,
                    self.fact_admission,
                    queued,
                    allowed,
                )?
            } else {
                dispatch::IntentDispatchReport {
                    status: dispatch_queued_intent(
                        handler,
                        self.store,
                        self.allowed_tables,
                        self.fact_admission,
                        queued,
                    )?,
                    suppressed_intents: 0,
                }
            };
            progress.status.merge(report.status);
            progress.suppressed_intents += report.suppressed_intents;
            if report.status.progressed {
                progress.dispatched += 1;
            }
            if report.status.retried {
                if let Some(key) = local_retry_key {
                    retried_local.insert(key);
                    continue;
                }
                break;
            }
        }
        Ok(progress)
    }

    /// Run one daemon tick's queue order after IO and time wakes have been handled.
    ///
    /// Projection runs before and after intent dispatch because handlers often
    /// emit facts that should become visible before the next quiet sleep.
    pub(crate) fn drain_daemon_queues_once(
        &self,
        handlers: &HandlerSet,
        limit: usize,
    ) -> Result<WorkStatus, String> {
        let mut total = WorkStatus::idle();
        total.merge(self.process_projection_until_idle(4, limit)?);
        total.merge(self.dispatch_intents(handlers, limit)?);
        total.merge(self.process_projection_until_idle(4, limit)?);
        Ok(total)
    }

    /// Settle projection and intent work to the command/live fixed point.
    pub(crate) fn process_work_until_idle(
        &self,
        handlers: &HandlerSet,
        max_rounds: usize,
        limit_per_round: usize,
    ) -> Result<WorkStatus, String> {
        let mut total = WorkStatus::idle();
        for _ in 0..max_rounds {
            total.merge(crate::core::perf_profile::measure_result(
                "projection",
                || self.process_projection_until_idle(8, limit_per_round),
            )?);
            let dispatched = crate::core::perf_profile::measure_result("intent_dispatch", || {
                self.dispatch_intents(handlers, limit_per_round)
            })?;
            total.merge(dispatched);
            if dispatched.is_idle() {
                total.merge(crate::core::perf_profile::measure_result(
                    "projection",
                    || self.process_projection_until_idle(8, limit_per_round),
                )?);
                return Ok(total);
            }
        }
        Ok(total)
    }

    /// Turn due time wakes into pending projection work.
    pub(crate) fn process_due_time_range(
        &self,
        timeline: Timeline,
        start_exclusive: Option<u64>,
        end_inclusive: u64,
        limit: usize,
    ) -> Result<usize, String> {
        process_due_time_range(self.store, timeline, start_exclusive, end_inclusive, limit)
    }
}

pub(crate) use commit_effects::commit_pipeline_effects_to_store;
pub(crate) use dispatch::{
    dispatch_queued_intent, dispatch_queued_intent_filtering_intents, next_queued_intent,
    submit_intent_to_store, submit_local_intent_to_store,
};
pub(crate) use project_pending_facts::submit_fact_to_store;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::context::{ContextKey, ContextNeed, ContextOffer, Role};
    use crate::core::facts::{Fact, FactId, FactScope};
    use crate::core::intents::{HandlerContext, HandlerResult, Intent, IntentHandler};

    #[test]
    fn projection_output_keeps_context_and_work_separate() {
        let id = [1; 32];
        let role = Role::new("exact").unwrap();
        let key = ContextKey::from_bytes([2; 32]);
        let output = ProjectionOutput::new()
            .need(ContextNeed {
                owner: id,
                role: role.clone(),
                scope: FactScope::Global,
                start_key: key.clone(),
                end_key: key.clone(),
            })
            .offer(ContextOffer {
                owner: id,
                role,
                scope: FactScope::Global,
                start_key: key.clone(),
                end_key: key,
            });

        assert_eq!(output.needs.len(), 1);
        assert_eq!(output.offers.len(), 1);
        assert!(output.effects.intents.is_empty());
    }

    #[test]
    fn projection_output_exposes_normalized_replacement_context() {
        let id = [1; 32];
        let role = Role::new("exact").unwrap();
        let need = ContextNeed {
            owner: id,
            role,
            scope: FactScope::Global,
            start_key: ContextKey::from_bytes([2; 32]),
            end_key: ContextKey::from_bytes([2; 32]),
        };
        let output = ProjectionOutput::new()
            .need(need.clone())
            .need(need.clone());

        assert_eq!(output.context_set().needs, vec![need]);
    }

    #[test]
    fn projection_context_returns_matched_payloads_by_need() {
        let role = Role::new("exact").unwrap();
        let need_a = ContextNeed {
            owner: [1; 32],
            role: role.clone(),
            scope: FactScope::Global,
            start_key: ContextKey::from_bytes([10; 32]),
            end_key: ContextKey::from_bytes([10; 32]),
        };
        let need_b = ContextNeed {
            owner: [2; 32],
            role: role.clone(),
            scope: FactScope::Global,
            start_key: ContextKey::from_bytes([20; 32]),
            end_key: ContextKey::from_bytes([20; 32]),
        };
        let context = ProjectionContext::from_matches(vec![
            matched_context(need_a.clone(), [11; 32]),
            matched_context(need_b.clone(), [22; 32]),
            matched_context(need_a.clone(), [33; 32]),
        ]);

        let payload_ids = context
            .matched_payloads_for(&need_a)
            .map(|(_offer, payload)| payload.id)
            .collect::<Vec<_>>();
        assert_eq!(payload_ids, vec![[11; 32], [33; 32]]);
        assert_eq!(
            context.payload_for(&need_b).map(|payload| payload.id),
            Some([22; 32])
        );
    }

    #[test]
    fn projection_context_decodes_payload_with_fact_codec() {
        let role = Role::new("exact").unwrap();
        let need = ContextNeed {
            owner: [1; 32],
            role,
            scope: FactScope::Global,
            start_key: ContextKey::from_bytes([10; 32]),
            end_key: ContextKey::from_bytes([10; 32]),
        };
        let context = ProjectionContext::from_matches(vec![matched_context(need.clone(), [7; 32])]);

        assert_eq!(context.payload_as::<FirstByteCodec>(&need), Ok(Some(7)));
        assert_eq!(
            context.payload_as::<FirstByteCodec>(&ContextNeed {
                owner: [2; 32],
                role: Role::new("exact").unwrap(),
                scope: FactScope::Global,
                start_key: ContextKey::from_bytes([20; 32]),
                end_key: ContextKey::from_bytes([20; 32]),
            }),
            Ok(None)
        );
    }

    #[test]
    fn projection_context_decodes_checked_matched_payloads() {
        let role = Role::new("exact").unwrap();
        let need = ContextNeed {
            owner: [1; 32],
            role,
            scope: FactScope::Global,
            start_key: ContextKey::from_bytes([10; 32]),
            end_key: ContextKey::from_bytes([10; 32]),
        };
        let context = ProjectionContext::from_matches(vec![
            matched_context(need.clone(), [7; 32]),
            matched_context(need.clone(), [8; 32]),
        ]);

        let payloads = context
            .matched_payloads_as_checked::<FirstByteCodec>(&need, "typed")
            .map(|matched| {
                let (offer, payload, decoded) = matched?;
                Ok((offer.owner, payload.id, decoded))
            })
            .collect::<Result<Vec<_>, String>>()
            .expect("typed matched payloads");

        assert_eq!(payloads, vec![([7; 32], [7; 32], 7), ([8; 32], [8; 32], 8)]);
    }

    #[test]
    fn checked_typed_payloads_report_offer_payload_mismatch_before_decode() {
        let role = Role::new("exact").unwrap();
        let need = ContextNeed {
            owner: [1; 32],
            role,
            scope: FactScope::Global,
            start_key: ContextKey::from_bytes([10; 32]),
            end_key: ContextKey::from_bytes([10; 32]),
        };
        let mut matched = matched_context(need.clone(), [7; 32]);
        matched.offer.owner = [8; 32];
        matched.payload.bytes.clear();
        let context = ProjectionContext::from_matches(vec![matched]);

        let err = context
            .matched_payloads_as_checked::<FirstByteCodec>(&need, "typed")
            .next()
            .expect("matched payload")
            .expect_err("offer owner mismatch should fail before decode");

        assert_eq!(err, "typed context offer payload mismatch");
    }

    #[test]
    fn staged_pipeline_decodes_authenticates_adapts_then_projects() {
        let fact = Fact::new(FactScope::Global, 1, vec![200, 5]);
        let output =
            project_staged::<ModelCodec, ModelAuthenticator, ModelAdapter, ModelProjector>(
                &ModelProjector,
                &fact,
                &ProjectionContext::default(),
            )
            .expect("staged projection");

        assert_eq!(output.offers.len(), 1);
        assert_eq!(output.offers[0].owner, fact.id);
        assert_eq!(output.offers[0].start_key.as_bytes(), &[15]);
    }

    #[test]
    fn staged_pipeline_parks_authentication_before_adapt_or_project() {
        let fact = Fact::new(FactScope::Global, 1, vec![200, 2]);
        let output =
            project_staged::<ModelCodec, ModelAuthenticator, ModelAdapter, ModelProjector>(
                &ModelProjector,
                &fact,
                &ProjectionContext::default(),
            )
            .expect("authentication need parks");

        assert_eq!(output.needs.len(), 1);
        assert_eq!(output.needs[0].role.as_str(), "model_auth");
        assert!(output.offers.is_empty());
    }

    #[test]
    fn staged_pipeline_preserves_multiple_authentication_needs() {
        let fact = Fact::new(FactScope::Global, 1, vec![200, 3]);
        let output =
            project_staged::<ModelCodec, ModelAuthenticator, ModelAdapter, ModelProjector>(
                &ModelProjector,
                &fact,
                &ProjectionContext::default(),
            )
            .expect("authentication needs park");

        assert_eq!(output.needs.len(), 2);
        assert_eq!(output.needs[0].role.as_str(), "model_auth");
        assert_eq!(output.needs[0].start_key.as_bytes(), &[3]);
        assert_eq!(output.needs[1].role.as_str(), "model_auth_fallback");
        assert_eq!(output.needs[1].start_key.as_bytes(), &[4]);
        assert!(output.offers.is_empty());
    }

    #[test]
    fn fact_route_records_staged_pipeline_metadata() {
        fn model_projector(
            fact: &Fact,
            context: &ProjectionContext,
        ) -> Result<ProjectionOutput, String> {
            project_staged::<ModelCodec, ModelAuthenticator, ModelAdapter, ModelProjector>(
                &ModelProjector,
                fact,
                context,
            )
        }

        let route = FactRoute {
            tag: 200,
            projector: model_projector,
            pipeline: FactPipeline::Staged {
                decode: "ModelCodec",
                authenticate: "ModelAuthenticator",
                adapt: "ModelAdapter",
                project: "ModelProjector",
            },
            replayed: true,
        };

        assert!(route.pipeline.is_staged());
        let output = (route.projector)(
            &Fact::new(FactScope::Global, 1, vec![200, 5]),
            &ProjectionContext::default(),
        )
        .expect("route projection");
        assert_eq!(output.offers.len(), 1);
    }

    #[test]
    fn handler_sets_filter_command_and_replay_routes() {
        const ROUTES: &[HandlerRoute] = &[
            HandlerRoute {
                name: "semantic",
                intent_kind: "semantic",
                factory: noop_handler,
                runs_during_replay: true,
                recurrence: None,
            },
            HandlerRoute {
                name: "network",
                intent_kind: "network",
                factory: noop_handler,
                runs_during_replay: false,
                recurrence: None,
            },
        ];

        assert_eq!(
            HandlerSet::new(ROUTES).intent_kinds(),
            vec!["semantic", "network"]
        );
        assert_eq!(
            HandlerSet::new_excluding(ROUTES, &["network"]).intent_kinds(),
            vec!["semantic"]
        );
        assert_eq!(
            HandlerSet::new_replay(ROUTES).intent_kinds(),
            vec!["semantic"]
        );
    }

    struct ModelCodec;

    impl FactCodec for ModelCodec {
        type Payload = u8;

        fn decode_fact(fact: &Fact) -> Result<Self::Payload, String> {
            if fact.bytes.first().copied() != Some(200) {
                return Err("wrong model tag".to_string());
            }
            fact.bytes
                .get(1)
                .copied()
                .ok_or_else(|| "missing model payload".to_string())
        }
    }

    struct ModelAuthenticator;

    impl DecodedAuthenticator<ModelCodec> for ModelAuthenticator {
        type Authenticated = u8;

        fn authenticate_decoded<'a>(
            fact: &'a Fact,
            decoded: u8,
            _context: &ProjectionContext,
        ) -> Authentication<'a, Self::Authenticated> {
            match decoded {
                0 => Authentication::Invalid("zero is not authentic".to_string()),
                2 => Authentication::need(ContextNeed::range(
                    fact.id,
                    "model_auth",
                    FactScope::Global,
                    vec![2],
                    vec![2],
                )),
                3 => Authentication::needs([
                    ContextNeed::range(fact.id, "model_auth", FactScope::Global, vec![3], vec![3]),
                    ContextNeed::range(
                        fact.id,
                        "model_auth_fallback",
                        FactScope::Global,
                        vec![4],
                        vec![4],
                    ),
                ]),
                value => Authentication::Authenticated(AuthenticatedFact::new(fact, value)),
            }
        }
    }

    struct ModelAdapter;

    impl Adapter for ModelAdapter {
        type Source = u8;
        type Semantic = u16;

        fn adapt(source: Self::Source) -> Result<Self::Semantic, String> {
            Ok(u16::from(source) + 10)
        }
    }

    struct ModelProjector;

    impl SemanticProjector<u16> for ModelProjector {
        fn project_semantic(
            &self,
            fact: &Fact,
            semantic: u16,
            _context: &ProjectionContext,
        ) -> Result<ProjectionOutput, String> {
            Ok(ProjectionOutput::new().offer(ContextOffer::range(
                fact.id,
                "model_semantic",
                FactScope::Global,
                vec![semantic as u8],
                vec![semantic as u8],
            )))
        }
    }

    struct NoopIntentHandler;

    impl IntentHandler for NoopIntentHandler {
        fn handle(&self, _intent: &Intent, _context: &HandlerContext<'_>) -> HandlerResult {
            Ok(crate::core::effects::PipelineEffects::new())
        }
    }

    fn noop_handler() -> Box<dyn IntentHandler> {
        Box::new(NoopIntentHandler)
    }

    struct FirstByteCodec;

    impl FactCodec for FirstByteCodec {
        type Payload = u8;

        fn decode_fact(fact: &Fact) -> Result<Self::Payload, String> {
            fact.bytes
                .first()
                .copied()
                .ok_or_else(|| "empty typed payload".to_string())
        }
    }

    fn matched_context(need: ContextNeed, payload_id: FactId) -> MatchedContext {
        let payload = Fact {
            id: payload_id,
            scope: need.scope.clone(),
            timestamp: 1,
            bytes: payload_id.to_vec(),
        };
        MatchedContext {
            offer: ContextOffer {
                owner: payload_id,
                role: need.role.clone(),
                scope: need.scope.clone(),
                start_key: need.start_key.clone(),
                end_key: need.end_key.clone(),
            },
            need,
            payload,
        }
    }
}
