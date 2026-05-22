//! Generic target runtime.
//!
//! Core owns the mechanics: open the store, submit facts and intents, run
//! pending fact projection, and dispatch handler work through SQLite-backed
//! intent queues.
//! Protocol code supplies the projector router, context matchers, handler
//! registry, schema sources, and row mutation tables.
//!
//! This is the facade a protocol host should use when it wants the whole core
//! engine. If code wants to change projection scheduling, intent queue
//! dispatch, command-safe handler filtering, or due-time processing, this file
//! is the place that composes those pieces. The pieces themselves stay in
//! `pipeline`, `fact_store`, and protocol modules.

use crate::core::command_context::{CommandClock, CommandContext, CommandOutput, IdentityVault};
use crate::core::context::ContextOffer;
use crate::core::fact_store::persisted_facts;
use crate::core::facts::{Fact, FactId};
use crate::core::intents::{Intent, IntentHandler};
use crate::core::matchers::ContextMatchers;
use crate::core::pipeline;
use crate::core::projectors::{Projector, Timeline};
use crate::core::schema::{CORE_SCHEMA_SOURCE, INTENTS, LOCAL_INTENTS, PENDING_PROJECTION};
use crate::core::store::{SchemaSource, Store, TableName};
use std::path::Path;

pub use crate::core::pipeline::WorkStatus;

/// Factory for the protocol's projector implementation.
pub type ProjectorFactory = fn() -> Box<dyn Projector>;
/// Factory for the protocol's context matcher registry.
pub type MatchersFactory = fn() -> ContextMatchers;

/// Protocol-owned declarations needed by core's runtime engine.
///
/// The description is static so a runtime instance cannot drift after opening
/// its store. `schema_sources` declare protocol tables, `row_mutation_tables`
/// is the allowlist for effects, `projector` and `matchers` define projection,
/// and `handlers` define the queued work core may dispatch.
#[derive(Clone, Copy)]
pub struct RuntimeDescription {
    /// Protocol table declarations appended after the core schema.
    pub schema_sources: &'static [SchemaSource],
    /// Tables protocol effects are allowed to mutate.
    pub row_mutation_tables: &'static [TableName],
    /// Factory for the projector router.
    pub projector: ProjectorFactory,
    /// Factory for exact and custom context matchers.
    pub matchers: MatchersFactory,
    /// Intent handlers this runtime may dispatch.
    pub handlers: &'static [HandlerRoute],
    /// Handler route names a synchronous command should not run.
    pub command_excluded_handlers: &'static [&'static str],
}

/// Factory for one protocol intent handler.
pub type HandlerFactory = fn() -> Box<dyn IntentHandler>;

/// One handler route in the protocol registry.
///
/// `name` is a human-facing route name used for exclusion lists. `intent_kind`
/// is the queue routing key that selects this handler for both durable and
/// ephemeral intents.
#[derive(Debug, Clone, Copy)]
pub struct HandlerRoute {
    /// Human-facing route name used for exclusion lists.
    pub name: &'static str,
    /// Intent kind handled by this route.
    pub intent_kind: &'static str,
    /// Handler factory.
    pub factory: HandlerFactory,
}

/// Instantiated handlers for one runtime pass.
///
/// The set owns concrete handler values so dispatch can borrow trait objects
/// without rebuilding them for every queued row. Command processing builds a
/// filtered set to avoid daemon/network side effects.
struct HandlerSet {
    entries: Vec<HandlerEntry>,
}

struct HandlerEntry {
    intent_kind: &'static str,
    handler: Box<dyn IntentHandler>,
}

impl HandlerSet {
    /// Instantiate all declared routes.
    pub fn new(routes: &'static [HandlerRoute]) -> Self {
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
    pub fn new_excluding(routes: &'static [HandlerRoute], excluded_names: &[&str]) -> Self {
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

    fn intent_kinds(&self) -> Vec<&'static str> {
        self.entries.iter().map(|entry| entry.intent_kind).collect()
    }

    fn handler_for_kind(&self, kind: &str) -> Option<&dyn IntentHandler> {
        self.entries
            .iter()
            .find(|entry| entry.intent_kind == kind)
            .map(|entry| entry.handler.as_ref())
    }

    pub(crate) fn dispatch(
        &self,
        store: &Store,
        allowed_tables: &[TableName],
        limit: usize,
    ) -> Result<WorkStatus, String> {
        let mut total = WorkStatus::idle();
        let kinds = self.intent_kinds();
        for _ in 0..limit {
            let Some(queued) = pipeline::next_queued_intent(store, &kinds)? else {
                break;
            };
            let kind = queued.intent.kind.as_str();
            let handler = self
                .handler_for_kind(kind)
                .ok_or_else(|| format!("no handler registered for intent kind {kind}"))?;
            let status = pipeline::dispatch_queued_intent(handler, store, allowed_tables, queued)?;
            total.merge(status);
            if status.retried {
                break;
            }
        }
        Ok(total)
    }
}

/// Runtime for one concrete protocol description.
///
/// `Runtime` owns a single SQLite connection. All durable and memory tables,
/// projection, and dispatch operations happen through that handle so transaction
/// boundaries stay visible and ephemeral tables are actually local to this
/// runtime instance.
pub struct Runtime {
    description: &'static RuntimeDescription,
    store: Store,
    projector: Box<dyn Projector>,
    matchers: ContextMatchers,
    handlers: HandlerSet,
}

impl Runtime {
    /// Open an in-memory runtime with core and protocol schema sources applied.
    pub fn open_memory(description: &'static RuntimeDescription) -> Result<Self, String> {
        let schema_sources = runtime_schema_sources(description);
        let store = Store::open_memory_with_schema_sources(&schema_sources)
            .map_err(|err| format!("open target memory store: {err}"))?;
        Self::from_store(description, store)
    }

    /// Open a disk-backed runtime with core and protocol schema sources applied.
    pub fn open_disk(
        description: &'static RuntimeDescription,
        path: impl AsRef<Path>,
    ) -> Result<Self, String> {
        let schema_sources = runtime_schema_sources(description);
        let store = Store::open_disk_with_schema_sources(path, &schema_sources)
            .map_err(|err| format!("open target disk store: {err}"))?;
        Self::from_store(description, store)
    }

    fn from_store(description: &'static RuntimeDescription, store: Store) -> Result<Self, String> {
        Ok(Self {
            description,
            store,
            projector: (description.projector)(),
            matchers: (description.matchers)(),
            handlers: HandlerSet::new(description.handlers),
        })
    }

    /// Borrow the runtime's store handle.
    ///
    /// This exposes the concrete SQLite-backed store for query helpers and
    /// daemon IO code that must share the same connection-local memory tables as
    /// the runtime. New runtime flows should prefer the typed methods below so
    /// projection and intent ordering stay centralized here.
    pub fn store(&self) -> &Store {
        &self.store
    }

    /// Return all persisted facts known to this runtime.
    pub fn facts(&self) -> impl Iterator<Item = Fact> {
        persisted_facts(&self.store)
            .expect("runtime facts should load from store")
            .into_iter()
    }

    /// Count facts currently queued for projection.
    pub fn pending_fact_count(&self) -> usize {
        self.store
            .table_row_count(PENDING_PROJECTION)
            .expect("runtime pending fact count should load from store")
    }

    /// Count durable plus ephemeral queued intents.
    pub fn pending_intent_count(&self) -> usize {
        let stored = self
            .store
            .table_row_count(INTENTS)
            .expect("runtime intent count should load from store");
        let local = self
            .store
            .table_row_count(LOCAL_INTENTS)
            .expect("runtime local intent count should load from store");
        stored + local
    }

    /// Build the narrow command context for a user-facing command.
    pub fn command_context<'a>(
        &'a self,
        clock: &'a dyn CommandClock,
        vault: &'a dyn IdentityVault,
    ) -> CommandContext<'a> {
        CommandContext::new(&self.store, clock, vault)
    }

    /// Admit one fact and mark it pending for projection.
    pub fn submit_fact(&mut self, fact: Fact) -> bool {
        pipeline::submit_fact_to_store(&self.store, fact)
            .expect("runtime fact submission should persist")
    }

    /// Admit many facts in one transaction.
    pub fn submit_facts(&mut self, facts: impl IntoIterator<Item = Fact>) -> Result<usize, String> {
        pipeline::submit_facts_to_store(&self.store, facts)
    }

    /// Remove one fact and its core-owned derived rows.
    pub fn purge_fact(&mut self, fact_id: crate::core::facts::FactId) -> bool {
        pipeline::purge_fact_from_store(&self.store, fact_id)
            .expect("runtime fact purge should persist")
    }

    pub(crate) fn commit_projected_context_offers(
        &self,
        offers: &[ContextOffer],
        completed_fact_ids: &[FactId],
    ) -> Result<usize, String> {
        pipeline::commit_projected_context_offers(
            &self.store,
            &self.matchers,
            offers,
            completed_fact_ids,
        )
    }

    /// Queue durable idempotent work for the protocol handler registry.
    ///
    /// The handler selected by `intent.kind` may run in a later daemon or
    /// command-safe drain pass. Use `submit_local_intent` for work that is only
    /// valid on this process and should disappear on restart.
    pub fn submit_intent(&mut self, intent: Intent) -> Result<bool, String> {
        pipeline::submit_intent_to_store(&self.store, intent)
    }

    /// Queue ephemeral work for this runtime connection.
    pub fn submit_local_intent(&mut self, intent: Intent) -> Result<bool, String> {
        pipeline::submit_local_intent_to_store(&self.store, intent)
    }

    /// Commit the effects returned by a user-facing command and return its receipt.
    ///
    /// Command receipts are not pipeline state. They return directly to the CLI
    /// caller after the command's facts, rows, and intents have been committed.
    pub fn submit_command_output<T>(&mut self, output: CommandOutput<T>) -> Result<T, String> {
        let (receipt, effects) = output.into_parts();
        pipeline::commit_pipeline_effects_to_store(
            &self.store,
            &effects,
            self.description.row_mutation_tables,
            "submit command output",
        )?;
        Ok(receipt)
    }

    fn process_projection_work(
        &mut self,
        limit: usize,
    ) -> Result<pipeline::ProjectionProgress, String> {
        pipeline::drain_pending_projection(
            self.projector.as_ref(),
            &self.matchers,
            &self.store,
            self.description.row_mutation_tables,
            limit,
        )
    }

    /// Drain pending projection until no projection work remains or rounds expire.
    ///
    /// Each round processes at most `limit_per_round` facts, and newly emitted
    /// context may enqueue more pending facts. Callers use this when they need
    /// projection-visible state to settle without dispatching intent handlers.
    pub fn process_projection_until_idle(
        &mut self,
        max_rounds: usize,
        limit_per_round: usize,
    ) -> Result<WorkStatus, String> {
        let mut total = WorkStatus::idle();
        for _ in 0..max_rounds {
            let progress = self.process_projection_work(limit_per_round)?;
            total.merge(progress.status);
            if progress.projected == 0 && self.pending_fact_count() == 0 {
                return Ok(total);
            }
        }
        Err("projection work did not become idle within the round limit".to_string())
    }

    /// Dispatch queued intents using the full protocol handler set.
    pub fn dispatch_intents(&mut self, limit: usize) -> Result<WorkStatus, String> {
        self.dispatch_with_handlers(&self.handlers, limit)
    }

    /// Run one daemon tick's queue order after IO and time wakes have been handled.
    ///
    /// Projection runs before and after intent dispatch because handlers often
    /// emit facts that should become visible before the next quiet sleep.
    pub fn drain_daemon_queues_once(&mut self, limit: usize) -> Result<WorkStatus, String> {
        let mut total = WorkStatus::idle();
        total.merge(self.process_projection_until_idle(4, limit)?);
        total.merge(self.dispatch_intents(limit)?);
        total.merge(self.process_projection_until_idle(4, limit)?);
        Ok(total)
    }

    /// Settle all projection and intent work using the protocol's full handler
    /// set. This is for internal runtime workflows; synchronous CLI commands
    /// should usually call `process_command_work_until_idle` so daemon/network
    /// effects remain daemon-owned.
    pub fn process_all_work_until_idle(
        &mut self,
        max_rounds: usize,
        limit_per_round: usize,
    ) -> Result<WorkStatus, String> {
        self.process_work_until_idle(max_rounds, limit_per_round, None)
    }

    fn dispatch_with_handlers(
        &self,
        handlers: &HandlerSet,
        limit: usize,
    ) -> Result<WorkStatus, String> {
        handlers.dispatch(&self.store, self.description.row_mutation_tables, limit)
    }

    fn process_work_until_idle(
        &mut self,
        max_rounds: usize,
        limit_per_round: usize,
        handlers: Option<&HandlerSet>,
    ) -> Result<WorkStatus, String> {
        let mut total = WorkStatus::idle();
        for _ in 0..max_rounds {
            total.merge(self.process_projection_until_idle(8, limit_per_round)?);
            let dispatched =
                self.dispatch_with_handlers(handlers.unwrap_or(&self.handlers), limit_per_round)?;
            total.merge(dispatched);
            if dispatched.is_idle() {
                total.merge(self.process_projection_until_idle(8, limit_per_round)?);
                return Ok(total);
            }
        }
        Ok(total)
    }

    /// Settle work that a synchronous CLI command should be allowed to observe.
    ///
    /// Protocols declare effectful daemon/network handlers as command-excluded
    /// routes. The command host can then ask runtime to finish local projection
    /// and non-effect intent work without knowing the pending-fact, context
    /// change, or intent pipeline schedule.
    pub fn process_command_work_until_idle(
        &mut self,
        max_rounds: usize,
        limit_per_round: usize,
    ) -> Result<WorkStatus, String> {
        let handlers = HandlerSet::new_excluding(
            self.description.handlers,
            self.description.command_excluded_handlers,
        );
        self.process_work_until_idle(max_rounds, limit_per_round, Some(&handlers))
    }

    pub fn process_due_time_range(
        &mut self,
        timeline: Timeline,
        start_exclusive: Option<u64>,
        end_inclusive: u64,
        limit: usize,
    ) -> usize {
        pipeline::process_due_time_range(
            &self.store,
            timeline,
            start_exclusive,
            end_inclusive,
            limit,
        )
        .expect("runtime time wake should persist pending projection")
    }
}

fn runtime_schema_sources(description: &RuntimeDescription) -> Vec<SchemaSource> {
    let mut sources = Vec::with_capacity(1 + description.schema_sources.len());
    sources.push(CORE_SCHEMA_SOURCE);
    sources.extend_from_slice(description.schema_sources);
    sources
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::facts::{Fact, FactScope};
    use crate::core::projectors::{ProjectionContext, ProjectionOutput};

    struct NoopProjector;

    impl Projector for NoopProjector {
        fn project(
            &self,
            _fact: &Fact,
            _context: &ProjectionContext,
        ) -> Result<ProjectionOutput, String> {
            Ok(ProjectionOutput::new())
        }
    }

    fn noop_projector() -> Box<dyn Projector> {
        Box::new(NoopProjector)
    }

    fn no_matchers() -> ContextMatchers {
        ContextMatchers::empty()
    }

    const TEST_RUNTIME: RuntimeDescription = RuntimeDescription {
        schema_sources: &[],
        row_mutation_tables: &[],
        projector: noop_projector,
        matchers: no_matchers,
        handlers: &[],
        command_excluded_handlers: &[],
    };

    #[test]
    fn runtime_reads_store_backed_facts_from_sqlite() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("runtime.db");
        let runtime = Runtime::open_disk(&TEST_RUNTIME, &path).expect("runtime");

        let external_fact = Fact::new(FactScope::Global, 7, b"external".to_vec());
        let mut writer = Runtime::open_disk(&TEST_RUNTIME, &path).expect("writer runtime");
        assert!(writer.submit_fact(external_fact.clone()));

        assert!(
            runtime.facts().any(|fact| fact.id == external_fact.id),
            "fact iteration should read externally committed facts from SQLite"
        );
    }
}
