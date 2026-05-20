//! Generic target runtime.
//!
//! Core owns the mechanics: open the store, submit facts and intents, run
//! pending-fact/context-change pipelines, and dispatch handler work through the
//! intent pipeline.
//! Protocol code supplies the projector router, context matchers, handler
//! registry, schema sources, and atomic row tables.

use crate::core::command_context::{CommandClock, CommandContext, CommandOutput, IdentityVault};
use crate::core::facts::Fact;
use crate::core::intents::{Intent, IntentHandler};
use crate::core::matchers::ContextMatcher;
use crate::core::pipeline::{
    self, persisted_facts, DispatchReport, IntentPipeline, PipelineReport, INTENTS,
    PENDING_CONTEXT_CHANGES, PENDING_PROJECTION,
};
use crate::core::projectors::{Projector, Timeline};
use crate::core::store::{Schema, Store, TableName};
use std::path::Path;

pub type ProjectorFactory = fn() -> Box<dyn Projector>;
pub type MatchersFactory = fn() -> Vec<Box<dyn ContextMatcher>>;

/// Protocol-owned declarations needed by core's runtime engine.
#[derive(Clone, Copy)]
pub struct RuntimeDescription {
    pub schema_sources: &'static [&'static str],
    pub schemas: &'static [Schema],
    pub atomic_row_tables: &'static [TableName],
    pub projector: ProjectorFactory,
    pub matchers: MatchersFactory,
    pub handlers: &'static [HandlerRoute],
    pub command_excluded_handlers: &'static [&'static str],
}

/// Public outcome returned by runtime pipeline calls.
///
/// Detailed counts stay inside the individual pipelines where they are useful
/// for tests and local implementation. Runtime callers only need to know
/// whether a bounded pass moved work forward and whether any handler asked to
/// retry before irreversible cleanup, such as deleting claimed network input.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WorkStatus {
    pub progressed: bool,
    pub retried: bool,
}

impl WorkStatus {
    pub fn idle() -> Self {
        Self::default()
    }

    fn from_projection_report(report: &PipelineReport) -> Self {
        Self {
            progressed: report.projections > 0
                || report.context_matches > 0
                || report.woken_facts > 0
                || report.intents > 0,
            retried: false,
        }
    }

    fn from_dispatch_report(report: &DispatchReport) -> Self {
        Self {
            progressed: report.handled > 0 || report.facts > 0 || report.intents > 0,
            retried: report.retries > 0,
        }
    }

    pub fn merge(&mut self, other: Self) {
        self.progressed |= other.progressed;
        self.retried |= other.retried;
    }

    pub fn is_idle(self) -> bool {
        !self.progressed && !self.retried
    }
}

pub type HandlerFactory = fn() -> Box<dyn IntentHandler>;

#[derive(Debug, Clone, Copy)]
pub struct HandlerRoute {
    pub name: &'static str,
    pub factory: HandlerFactory,
}

struct HandlerSet {
    handlers: Vec<Box<dyn IntentHandler>>,
}

impl HandlerSet {
    pub fn new(routes: &'static [HandlerRoute]) -> Self {
        Self {
            handlers: routes.iter().map(|route| (route.factory)()).collect(),
        }
    }

    pub fn new_excluding(routes: &'static [HandlerRoute], excluded_names: &[&str]) -> Self {
        Self {
            handlers: routes
                .iter()
                .filter(|route| !excluded_names.contains(&route.name))
                .map(|route| (route.factory)())
                .collect(),
        }
    }
    pub(crate) fn dispatch(
        &self,
        intent_pipeline: &mut IntentPipeline,
        store: &Store,
        allowed_tables: &[TableName],
        limit_per_handler: usize,
    ) -> Result<DispatchReport, String> {
        let mut total = DispatchReport::default();
        for handler in &self.handlers {
            let report = pipeline::dispatch_deferred_intents_from_store_with_fact_context(
                intent_pipeline,
                handler.as_ref(),
                store,
                allowed_tables,
                limit_per_handler,
            )?;
            total.handled += report.handled;
            total.facts += report.facts;
            total.intents += report.intents;
            total.retries += report.retries;
            if report.handled > 0 || report.retries > 0 {
                continue;
            }

            let report = pipeline::dispatch_atomic_intents_from_store(
                intent_pipeline,
                handler.as_ref(),
                store,
                allowed_tables,
                limit_per_handler,
            )?;
            total.handled += report.handled;
            total.facts += report.facts;
            total.intents += report.intents;
            total.retries += report.retries;
            if report.handled > 0 || report.retries > 0 {
                continue;
            }

            let report = pipeline::dispatch_ephemeral_intents_with_fact_context_and_store(
                intent_pipeline,
                handler.as_ref(),
                store,
                allowed_tables,
                limit_per_handler,
            )?;
            total.handled += report.handled;
            total.facts += report.facts;
            total.intents += report.intents;
            total.retries += report.retries;
        }
        Ok(total)
    }
}

/// Runtime for one concrete protocol description.
pub struct Runtime {
    description: &'static RuntimeDescription,
    store: Store,
    intent_pipeline: IntentPipeline,
    projector: Box<dyn Projector>,
    matchers: Vec<Box<dyn ContextMatcher>>,
    handlers: HandlerSet,
}

impl Runtime {
    pub fn open_memory(description: &'static RuntimeDescription) -> Result<Self, String> {
        let store = Store::open_memory_with_schema_sources_and_schemas(
            description.schema_sources,
            description.schemas,
        )
        .map_err(|err| format!("open target memory store: {err}"))?;
        Self::from_store(description, store)
    }

    pub fn open_disk(
        description: &'static RuntimeDescription,
        path: impl AsRef<Path>,
    ) -> Result<Self, String> {
        let store = Store::open_disk_with_schema_sources_and_schemas(
            path,
            description.schema_sources,
            description.schemas,
        )
        .map_err(|err| format!("open target disk store: {err}"))?;
        Self::from_store(description, store)
    }

    fn from_store(description: &'static RuntimeDescription, store: Store) -> Result<Self, String> {
        Ok(Self {
            description,
            store,
            intent_pipeline: IntentPipeline::new(),
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

    pub fn pending_work_count(&self) -> usize {
        let pending_context_changes = self
            .store
            .table_row_count(PENDING_CONTEXT_CHANGES)
            .expect("runtime pending context change count should load from store");
        self.pending_fact_count() + pending_context_changes
    }

    pub fn pending_intent_count(&self) -> usize {
        let stored = self
            .store
            .table_row_count(INTENTS)
            .expect("runtime intent count should load from store");
        stored + self.intent_pipeline.ephemeral_intents().len()
    }

    pub fn ephemeral_intents(&self) -> &[Intent] {
        self.intent_pipeline.ephemeral_intents()
    }

    pub fn command_context<'a>(
        &'a self,
        clock: &'a dyn CommandClock,
        vault: &'a dyn IdentityVault,
    ) -> CommandContext<'a> {
        CommandContext::new(&self.store, clock, vault)
    }

    pub fn submit_fact(&mut self, fact: Fact) -> bool {
        let inserted = pipeline::submit_fact_to_store(&self.store, fact.clone())
            .expect("runtime fact submission should persist");
        if inserted {
            self.intent_pipeline.remember_fact(fact);
        }
        inserted
    }

    pub fn submit_facts(&mut self, facts: impl IntoIterator<Item = Fact>) -> Result<usize, String> {
        let facts = facts.into_iter().collect::<Vec<_>>();
        let inserted = pipeline::submit_facts_to_store(&self.store, facts.clone())?;
        for fact in facts {
            self.intent_pipeline.remember_fact(fact);
        }
        Ok(inserted)
    }

    pub fn purge_fact(&mut self, fact_id: crate::core::facts::FactId) -> bool {
        let changed = pipeline::purge_fact_from_store(&self.store, fact_id)
            .expect("runtime fact purge should persist");
        if changed {
            self.intent_pipeline.forget_purged_fact(fact_id);
        }
        changed
    }

    pub fn submit_intent(&mut self, intent: Intent) -> Result<bool, String> {
        self.intent_pipeline
            .submit_intent_to_store(&self.store, intent)
    }

    pub fn submit_command_output<T>(&mut self, output: CommandOutput<T>) -> Result<T, String> {
        for fact in output.facts {
            self.submit_fact(fact);
        }
        for intent in output.intents {
            self.submit_intent(intent)?;
        }
        Ok(output.receipt)
    }

    fn process_projection_work(&mut self, limit: usize) -> Result<PipelineReport, String> {
        let matcher_refs = self
            .matchers
            .iter()
            .map(|matcher| matcher.as_ref() as &dyn ContextMatcher)
            .collect::<Vec<_>>();
        pipeline::process_pending_facts_and_context_changes(
            &mut self.intent_pipeline,
            self.projector.as_ref(),
            &matcher_refs,
            &self.store,
            self.description.atomic_row_tables,
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
            let report = self.process_projection_work(limit_per_round)?;
            total.merge(WorkStatus::from_projection_report(&report));
            if report.projections == 0
                && report.woken_facts == 0
                && report.intents == 0
                && self.pending_work_count() == 0
            {
                return Ok(total);
            }
        }
        Err("projection work did not become idle within the round limit".to_string())
    }

    pub fn dispatch_intents(&mut self, limit_per_handler: usize) -> Result<WorkStatus, String> {
        let report = self.handlers.dispatch(
            &mut self.intent_pipeline,
            &self.store,
            self.description.atomic_row_tables,
            limit_per_handler,
        )?;
        Ok(WorkStatus::from_dispatch_report(&report))
    }

    pub fn dispatch_intents_excluding(
        &mut self,
        excluded_handler_names: &[&str],
        limit_per_handler: usize,
    ) -> Result<WorkStatus, String> {
        let handlers = HandlerSet::new_excluding(self.description.handlers, excluded_handler_names);
        self.dispatch_with_handlers(&handlers, limit_per_handler)
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
        let mut total = WorkStatus::idle();
        for _ in 0..max_rounds {
            total.merge(self.process_projection_until_idle(8, limit_per_round)?);
            let dispatched = self.dispatch_intents(limit_per_round)?;
            total.merge(dispatched);
            if dispatched.is_idle() {
                total.merge(self.process_projection_until_idle(8, limit_per_round)?);
                return Ok(total);
            }
        }
        Ok(total)
    }

    fn dispatch_with_handlers(
        &mut self,
        handlers: &HandlerSet,
        limit_per_handler: usize,
    ) -> Result<WorkStatus, String> {
        let report = handlers.dispatch(
            &mut self.intent_pipeline,
            &self.store,
            self.description.atomic_row_tables,
            limit_per_handler,
        )?;
        Ok(WorkStatus::from_dispatch_report(&report))
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
        let mut total = WorkStatus::idle();
        for _ in 0..max_rounds {
            total.merge(self.process_projection_until_idle(8, limit_per_round)?);
            let dispatched = self.dispatch_intents_excluding(
                self.description.command_excluded_handlers,
                limit_per_round,
            )?;
            total.merge(dispatched);
            if dispatched.is_idle() {
                total.merge(self.process_projection_until_idle(8, limit_per_round)?);
                return Ok(total);
            }
        }
        Ok(total)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::facts::{Fact, FactScope};
    use crate::core::projectors::{ProjectionContext, ProjectionOutput};
    use crate::core::schema_dsl::CORE_SCHEMA_SOURCE;

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
        schema_sources: &[CORE_SCHEMA_SOURCE],
        schemas: &[],
        atomic_row_tables: &[],
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
