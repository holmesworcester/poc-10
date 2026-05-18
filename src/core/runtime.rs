//! Generic target runtime.
//!
//! Core owns the mechanics: open the store, load and save `WakeLoop`, submit
//! facts and intents, drain projection, and dispatch deferred handlers.
//! Protocol code supplies the projector router, context matchers, handler
//! registry, schema sources, and atomic row tables.

use crate::core::command_context::{CommandClock, CommandContext, CommandOutput, IdentityVault};
use crate::core::facts::Fact;
use crate::core::intents::Intent;
use crate::core::matchers::ContextMatcher;
use crate::core::projection::Projector;
use crate::core::store::{Store, TableName};
use crate::core::wake_loop::{DispatchReport, DrainReport, WakeLoop};
use std::marker::PhantomData;
use std::path::Path;

pub trait RuntimeProtocol {
    type Projector: Projector;
    type Matchers: RuntimeMatchers;
    type Handlers: RuntimeHandlers;

    fn schema_sources() -> &'static [&'static str];
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
        wake_loop: &mut WakeLoop,
        store: &Store,
        limit_per_handler: usize,
    ) -> Result<DispatchReport, String>;
}

/// Runtime for one concrete protocol.
pub struct Runtime<P: RuntimeProtocol> {
    store: Store,
    wake_loop: WakeLoop,
    wake_loop_store_version: i64,
    projector: P::Projector,
    matchers: P::Matchers,
    handlers: P::Handlers,
    _protocol: PhantomData<P>,
}

impl<P: RuntimeProtocol> Runtime<P> {
    pub fn open_memory() -> Result<Self, String> {
        let store = Store::open_memory_with_schema_sources(P::schema_sources())
            .map_err(|err| format!("open target memory store: {err}"))?;
        Self::from_store(store)
    }

    pub fn open_disk(path: impl AsRef<Path>) -> Result<Self, String> {
        let store = Store::open_disk_with_schema_sources(path, P::schema_sources())
            .map_err(|err| format!("open target disk store: {err}"))?;
        Self::from_store(store)
    }

    fn from_store(store: Store) -> Result<Self, String> {
        let wake_loop = WakeLoop::load(&store)?;
        let wake_loop_store_version = store
            .data_version()
            .map_err(|err| format!("read store data version: {err}"))?;
        Ok(Self {
            store,
            wake_loop,
            wake_loop_store_version,
            projector: P::projector(),
            matchers: P::matchers(),
            handlers: P::handlers(),
            _protocol: PhantomData,
        })
    }

    pub fn store(&self) -> &Store {
        &self.store
    }

    pub fn wake_loop(&self) -> &WakeLoop {
        &self.wake_loop
    }

    pub fn reload_wake_loop(&mut self) -> Result<(), String> {
        self.wake_loop = WakeLoop::load(&self.store)?;
        self.wake_loop_store_version = self
            .store
            .data_version()
            .map_err(|err| format!("read store data version: {err}"))?;
        Ok(())
    }

    pub fn reload_wake_loop_if_store_changed(&mut self) -> Result<bool, String> {
        let current = self
            .store
            .data_version()
            .map_err(|err| format!("read store data version: {err}"))?;
        if current == self.wake_loop_store_version {
            return Ok(false);
        }
        self.reload_wake_loop()?;
        Ok(true)
    }

    pub fn facts(&self) -> impl Iterator<Item = &Fact> {
        self.wake_loop.facts()
    }

    pub fn command_context<'a>(
        &'a self,
        clock: &'a dyn CommandClock,
        vault: &'a dyn IdentityVault,
    ) -> CommandContext<'a> {
        CommandContext::new(&self.store, clock, vault)
    }

    pub fn submit_fact(&mut self, fact: Fact) -> bool {
        self.wake_loop.submit_fact(fact)
    }

    pub fn purge_fact(&mut self, fact_id: crate::core::facts::FactId) -> bool {
        self.wake_loop.purge_fact(fact_id)
    }

    pub fn submit_intent(&mut self, intent: Intent) -> Result<bool, String> {
        self.wake_loop.submit_intent(intent)
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

    pub fn drain_projection(&mut self, limit: usize) -> Result<DrainReport, String> {
        let matcher_refs = self.matchers.refs();
        self.wake_loop.drain_applying_atomic_rows(
            &self.projector,
            &matcher_refs,
            &self.store,
            P::atomic_row_tables(),
            limit,
        )
    }

    pub fn drain_projection_until_idle(
        &mut self,
        max_rounds: usize,
        limit_per_round: usize,
    ) -> Result<DrainReport, String> {
        let mut total = DrainReport::default();
        for _ in 0..max_rounds {
            let report = self.drain_projection(limit_per_round)?;
            total.projections += report.projections;
            total.context_matches += report.context_matches;
            total.wakes += report.wakes;
            total.intents += report.intents;
            if report.projections == 0 {
                return Ok(total);
            }
        }
        Err("projection drain did not become idle within the round limit".to_string())
    }

    pub fn dispatch_intents(&mut self, limit_per_handler: usize) -> Result<DispatchReport, String> {
        self.handlers
            .dispatch(&mut self.wake_loop, &self.store, limit_per_handler)
    }

    pub fn save(&mut self) -> Result<(), String> {
        self.wake_loop.save(&self.store)
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
            _wake_loop: &mut WakeLoop,
            _store: &Store,
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
    fn reload_wake_loop_if_store_changed_skips_until_external_commit() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("runtime.db");
        let mut runtime = Runtime::<TestProtocol>::open_disk(&path).expect("runtime");

        assert!(
            !runtime
                .reload_wake_loop_if_store_changed()
                .expect("unchanged reload check"),
            "fresh runtime should not reload without an external commit"
        );

        let external_fact = Fact::new(FactScope::Global, 7, b"external".to_vec());
        let mut writer = Runtime::<TestProtocol>::open_disk(&path).expect("writer runtime");
        assert!(writer.submit_fact(external_fact.clone()));
        writer.save().expect("writer save");

        assert!(
            runtime.facts().all(|fact| fact.id != external_fact.id),
            "runtime should not see sibling writes before the conditional reload"
        );
        assert!(
            runtime
                .reload_wake_loop_if_store_changed()
                .expect("changed reload check"),
            "external commit should trigger a reload"
        );
        assert!(
            runtime.facts().any(|fact| fact.id == external_fact.id),
            "conditional reload should load externally committed facts"
        );
        assert!(
            !runtime
                .reload_wake_loop_if_store_changed()
                .expect("post-reload check"),
            "second check should stay cheap until the next external commit"
        );
    }
}
