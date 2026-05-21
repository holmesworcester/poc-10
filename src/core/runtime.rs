//! Generic target runtime.
//!
//! Core owns the mechanics: open the store, submit facts and intents, run
//! pending fact projection, and dispatch handler work through SQLite-backed
//! intent queues.
//! Protocol code supplies the projector router, context matchers, handler
//! registry, schema sources, and row mutation tables.

use crate::core::command_context::{CommandClock, CommandContext, CommandOutput, IdentityVault};
use crate::core::context::ContextOffer;
use crate::core::fact_store::persisted_facts;
use crate::core::facts::{Fact, FactId};
use crate::core::intents::{Intent, IntentHandler};
use crate::core::matchers::ContextMatcher;
use crate::core::pipeline;
use crate::core::projectors::{Projector, Timeline};
use crate::core::schema::{CORE_SCHEMA_SOURCE, INTENTS, LOCAL_INTENTS, PENDING_PROJECTION};
use crate::core::store::{Store, TableName};
use std::path::Path;

pub use crate::core::pipeline::WorkStatus;

pub type ProjectorFactory = fn() -> Box<dyn Projector>;
pub type MatchersFactory = fn() -> Vec<Box<dyn ContextMatcher>>;

/// Protocol-owned declarations needed by core's runtime engine.
#[derive(Clone, Copy)]
pub struct RuntimeDescription {
    pub schema_sources: &'static [&'static str],
    pub row_mutation_tables: &'static [TableName],
    pub projector: ProjectorFactory,
    pub matchers: MatchersFactory,
    pub handlers: &'static [HandlerRoute],
    pub command_excluded_handlers: &'static [&'static str],
}

pub type HandlerFactory = fn() -> Box<dyn IntentHandler>;

#[derive(Debug, Clone, Copy)]
pub struct HandlerRoute {
    pub name: &'static str,
    pub intent_kind: &'static str,
    pub factory: HandlerFactory,
}

struct HandlerSet {
    entries: Vec<HandlerEntry>,
}

struct HandlerEntry {
    route: &'static HandlerRoute,
    handler: Box<dyn IntentHandler>,
}

impl HandlerSet {
    pub fn new(routes: &'static [HandlerRoute]) -> Self {
        Self {
            entries: routes
                .iter()
                .map(|route| HandlerEntry {
                    route,
                    handler: (route.factory)(),
                })
                .collect(),
        }
    }

    pub fn new_excluding(routes: &'static [HandlerRoute], excluded_names: &[&str]) -> Self {
        Self {
            entries: routes
                .iter()
                .filter(|route| !excluded_names.contains(&route.name))
                .map(|route| HandlerEntry {
                    route,
                    handler: (route.factory)(),
                })
                .collect(),
        }
    }
    pub(crate) fn dispatch(
        &self,
        store: &Store,
        allowed_tables: &[TableName],
        limit_per_handler: usize,
    ) -> Result<WorkStatus, String> {
        let mut total = WorkStatus::idle();
        for entry in &self.entries {
            let status = pipeline::dispatch_durable_intents(
                entry.handler.as_ref(),
                entry.route.intent_kind,
                store,
                allowed_tables,
                limit_per_handler,
            )?;
            total.merge(status);
            if status.progressed || status.retried {
                continue;
            }

            total.merge(pipeline::dispatch_local_intents(
                entry.handler.as_ref(),
                entry.route.intent_kind,
                store,
                allowed_tables,
                limit_per_handler,
            )?);
        }
        Ok(total)
    }
}

/// Runtime for one concrete protocol description.
pub struct Runtime {
    description: &'static RuntimeDescription,
    store: Store,
    projector: Box<dyn Projector>,
    matchers: Vec<Box<dyn ContextMatcher>>,
    handlers: HandlerSet,
}

impl Runtime {
    pub fn open_memory(description: &'static RuntimeDescription) -> Result<Self, String> {
        let schema_sources = runtime_schema_sources(description);
        let store = Store::open_memory_with_schema_sources(&schema_sources)
            .map_err(|err| format!("open target memory store: {err}"))?;
        Self::from_store(description, store)
    }

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

    pub fn store(&self) -> &Store {
        &self.store
    }

    pub fn facts(&self) -> impl Iterator<Item = Fact> {
        persisted_facts(&self.store)
            .expect("runtime facts should load from store")
            .into_iter()
    }

    pub fn pending_fact_count(&self) -> usize {
        self.store
            .table_row_count(PENDING_PROJECTION)
            .expect("runtime pending fact count should load from store")
    }

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

    pub fn command_context<'a>(
        &'a self,
        clock: &'a dyn CommandClock,
        vault: &'a dyn IdentityVault,
    ) -> CommandContext<'a> {
        CommandContext::new(&self.store, clock, vault)
    }

    pub fn submit_fact(&mut self, fact: Fact) -> bool {
        pipeline::submit_fact_to_store(&self.store, fact)
            .expect("runtime fact submission should persist")
    }

    pub fn submit_facts(&mut self, facts: impl IntoIterator<Item = Fact>) -> Result<usize, String> {
        pipeline::submit_facts_to_store(&self.store, facts)
    }

    pub fn purge_fact(&mut self, fact_id: crate::core::facts::FactId) -> bool {
        pipeline::purge_fact_from_store(&self.store, fact_id)
            .expect("runtime fact purge should persist")
    }

    pub(crate) fn commit_projected_context_offers(
        &self,
        offers: &[ContextOffer],
        completed_fact_ids: &[FactId],
    ) -> Result<usize, String> {
        let matcher_refs = self
            .matchers
            .iter()
            .map(|matcher| matcher.as_ref() as &dyn ContextMatcher)
            .collect::<Vec<_>>();
        pipeline::commit_projected_context_offers(
            &self.store,
            &matcher_refs,
            offers,
            completed_fact_ids,
        )
    }

    pub fn submit_intent(&mut self, intent: Intent) -> Result<bool, String> {
        pipeline::submit_intent_to_store(&self.store, intent)
    }

    pub fn submit_local_intent(&mut self, intent: Intent) -> Result<bool, String> {
        pipeline::submit_local_intent_to_store(&self.store, intent)
    }

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
        let matcher_refs = self
            .matchers
            .iter()
            .map(|matcher| matcher.as_ref() as &dyn ContextMatcher)
            .collect::<Vec<_>>();
        pipeline::drain_pending_projection(
            self.projector.as_ref(),
            &matcher_refs,
            &self.store,
            self.description.row_mutation_tables,
            limit,
        )
    }

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

    pub fn dispatch_intents(&mut self, limit_per_handler: usize) -> Result<WorkStatus, String> {
        self.dispatch_with_handlers(&self.handlers, limit_per_handler)
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
        limit_per_handler: usize,
    ) -> Result<WorkStatus, String> {
        handlers.dispatch(
            &self.store,
            self.description.row_mutation_tables,
            limit_per_handler,
        )
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

fn runtime_schema_sources(description: &RuntimeDescription) -> Vec<&'static str> {
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

    fn no_matchers() -> Vec<Box<dyn ContextMatcher>> {
        Vec::new()
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
