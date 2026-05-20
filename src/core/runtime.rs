//! Generic target runtime.
//!
//! Core owns the mechanics: open the store, submit facts and intents, run
//! pending-fact/context-change pipelines, and dispatch handler work through the
//! intent pipeline.
//! Protocol code supplies the projector router, context matchers, handler
//! registry, schema sources, and atomic row tables.

use crate::core::command_context::{CommandClock, CommandContext, CommandOutput, IdentityVault};
use crate::core::context_change_pipeline::{
    persisted_facts, ContextChangePipeline, PipelineReport, INTENTS, PENDING_CONTEXT_CHANGES,
    PENDING_PROJECTION,
};
use crate::core::facts::Fact;
use crate::core::handler_dispatch::IntentHandler;
use crate::core::intent_pipeline::{self, DispatchReport, IntentPipeline};
use crate::core::intents::Intent;
use crate::core::matchers::ContextMatcher;
use crate::core::projection::{Projector, Timeline};
use crate::core::store::{Schema, Store, TableName};
use std::marker::PhantomData;
use std::path::Path;

pub trait RuntimeProtocol {
    type Projector: Projector;
    type Matchers: RuntimeMatchers;
    type Handlers: RuntimeHandlers;

    fn schema_sources() -> &'static [&'static str];
    fn schemas() -> &'static [Schema] {
        &[]
    }
    fn atomic_row_tables() -> &'static [TableName];
    fn projector() -> Self::Projector;
    fn matchers() -> Self::Matchers;
    fn handlers() -> Self::Handlers;
}

pub trait RuntimeMatchers {
    fn refs(&self) -> Vec<&dyn ContextMatcher>;
}

pub trait RuntimeHandlers {
    fn dispatch(
        &self,
        intent_pipeline: &mut IntentPipeline,
        store: &Store,
        allowed_tables: &[TableName],
        limit_per_handler: usize,
    ) -> Result<DispatchReport, String>;
}

pub type HandlerFactory = fn() -> Box<dyn IntentHandler>;

#[derive(Debug, Clone, Copy)]
pub struct HandlerRoute {
    pub name: &'static str,
    pub factory: HandlerFactory,
}

pub struct HandlerSet {
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
}

impl RuntimeHandlers for HandlerSet {
    fn dispatch(
        &self,
        intent_pipeline: &mut IntentPipeline,
        store: &Store,
        allowed_tables: &[TableName],
        limit_per_handler: usize,
    ) -> Result<DispatchReport, String> {
        let mut total = DispatchReport::default();
        for handler in &self.handlers {
            let report = intent_pipeline::dispatch_deferred_intents_from_store_with_fact_context(
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

            let report = intent_pipeline::dispatch_atomic_intents_from_store(
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

            let report = intent_pipeline::dispatch_ephemeral_intents_with_fact_context_and_store(
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

/// Runtime for one concrete protocol.
pub struct Runtime<P: RuntimeProtocol> {
    store: Store,
    context_change_pipeline: ContextChangePipeline,
    intent_pipeline: IntentPipeline,
    projector: P::Projector,
    matchers: P::Matchers,
    handlers: P::Handlers,
    _protocol: PhantomData<P>,
}

impl<P: RuntimeProtocol> Runtime<P> {
    pub fn open_memory() -> Result<Self, String> {
        let store =
            Store::open_memory_with_schema_sources_and_schemas(P::schema_sources(), P::schemas())
                .map_err(|err| format!("open target memory store: {err}"))?;
        Self::from_store(store)
    }

    pub fn open_disk(path: impl AsRef<Path>) -> Result<Self, String> {
        let store = Store::open_disk_with_schema_sources_and_schemas(
            path,
            P::schema_sources(),
            P::schemas(),
        )
        .map_err(|err| format!("open target disk store: {err}"))?;
        Self::from_store(store)
    }

    fn from_store(store: Store) -> Result<Self, String> {
        Ok(Self {
            store,
            context_change_pipeline: ContextChangePipeline::new(),
            intent_pipeline: IntentPipeline::new(),
            projector: P::projector(),
            matchers: P::matchers(),
            handlers: P::handlers(),
            _protocol: PhantomData,
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
        let inserted = self
            .context_change_pipeline
            .submit_fact_to_store(&self.store, fact.clone())
            .expect("runtime fact submission should persist");
        if inserted {
            self.intent_pipeline.remember_fact(fact);
        }
        inserted
    }

    pub fn submit_facts(&mut self, facts: impl IntoIterator<Item = Fact>) -> Result<usize, String> {
        let facts = facts.into_iter().collect::<Vec<_>>();
        let inserted = self
            .context_change_pipeline
            .submit_facts_to_store(&self.store, facts.clone())?;
        for fact in facts {
            self.intent_pipeline.remember_fact(fact);
        }
        Ok(inserted)
    }

    pub fn purge_fact(&mut self, fact_id: crate::core::facts::FactId) -> bool {
        let changed = self
            .context_change_pipeline
            .purge_fact_from_store(&self.store, fact_id)
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

    pub fn process_projection_work(&mut self, limit: usize) -> Result<PipelineReport, String> {
        let matcher_refs = self.matchers.refs();
        self.context_change_pipeline
            .process_pending_facts_and_context_changes(
                &mut self.intent_pipeline,
                &self.projector,
                &matcher_refs,
                &self.store,
                P::atomic_row_tables(),
                limit,
            )
    }

    pub fn process_projection_until_idle(
        &mut self,
        max_rounds: usize,
        limit_per_round: usize,
    ) -> Result<PipelineReport, String> {
        let mut total = PipelineReport::default();
        for _ in 0..max_rounds {
            let report = self.process_projection_work(limit_per_round)?;
            total.projections += report.projections;
            total.context_matches += report.context_matches;
            total.woken_facts += report.woken_facts;
            total.intents += report.intents;
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

    pub fn dispatch_intents(&mut self, limit_per_handler: usize) -> Result<DispatchReport, String> {
        let report = self.handlers.dispatch(
            &mut self.intent_pipeline,
            &self.store,
            P::atomic_row_tables(),
            limit_per_handler,
        )?;
        Ok(report)
    }

    pub fn dispatch_with_handlers(
        &mut self,
        handlers: &impl RuntimeHandlers,
        limit_per_handler: usize,
    ) -> Result<DispatchReport, String> {
        let report = handlers.dispatch(
            &mut self.intent_pipeline,
            &self.store,
            P::atomic_row_tables(),
            limit_per_handler,
        )?;
        Ok(report)
    }

    pub fn process_due_time_range(
        &mut self,
        timeline: Timeline,
        start_exclusive: Option<u64>,
        end_inclusive: u64,
        limit: usize,
    ) -> usize {
        self.context_change_pipeline
            .process_due_time_range(&self.store, timeline, start_exclusive, end_inclusive, limit)
            .expect("runtime time wake should persist pending projection")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::facts::{Fact, FactScope};
    use crate::core::projection::{ProjectionContext, ProjectionOutput};
    use crate::core::schema_dsl::CORE_SCHEMA_SOURCE;

    struct TestProtocol;

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

    struct NoMatchers;

    impl RuntimeMatchers for NoMatchers {
        fn refs(&self) -> Vec<&dyn ContextMatcher> {
            Vec::new()
        }
    }

    struct NoHandlers;

    impl RuntimeHandlers for NoHandlers {
        fn dispatch(
            &self,
            _intent_pipeline: &mut IntentPipeline,
            _store: &Store,
            _allowed_tables: &[TableName],
            _limit_per_handler: usize,
        ) -> Result<DispatchReport, String> {
            Ok(DispatchReport::default())
        }
    }

    impl RuntimeProtocol for TestProtocol {
        type Projector = NoopProjector;
        type Matchers = NoMatchers;
        type Handlers = NoHandlers;

        fn schema_sources() -> &'static [&'static str] {
            &[CORE_SCHEMA_SOURCE]
        }

        fn atomic_row_tables() -> &'static [TableName] {
            &[]
        }

        fn projector() -> Self::Projector {
            NoopProjector
        }

        fn matchers() -> Self::Matchers {
            NoMatchers
        }

        fn handlers() -> Self::Handlers {
            NoHandlers
        }
    }

    #[test]
    fn runtime_reads_store_backed_facts_from_sqlite() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("runtime.db");
        let runtime = Runtime::<TestProtocol>::open_disk(&path).expect("runtime");

        let external_fact = Fact::new(FactScope::Global, 7, b"external".to_vec());
        let mut writer = Runtime::<TestProtocol>::open_disk(&path).expect("writer runtime");
        assert!(writer.submit_fact(external_fact.clone()));

        assert!(
            runtime.facts().any(|fact| fact.id == external_fact.id),
            "fact iteration should read externally committed facts from SQLite"
        );
    }
}
