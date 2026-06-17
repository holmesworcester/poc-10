//! Replay-mode intent dispatch tests.
//!
//! These use a tiny runtime description instead of the full protocol so the
//! assertion is about core behavior: projectors own replay-mode emissions, core
//! passes replay mode to handlers, and handlers own replay-time no-ops.

use topo::core::effects::RuntimeEffects;
use topo::core::facts::{Fact, FactScope};
use topo::core::intents::{HandlerContext, HandlerResult, Intent, IntentHandler, IntentKind};
use topo::core::project_fact::{ProjectionContext, ProjectionOutput, Projector};
use topo::core::runtime::{HandlerRoute, Runtime, RuntimeDescription};
use topo::core::store::SchemaSource;

const REPLAY_OK: &str = "replay_ok";
const LIVE_ONLY: &str = "live_only";
const LIVE_LOCAL: &str = "live_local";
const LIVE_FROM_HANDLER: &str = "live_from_handler";

fn intent(kind: &'static str, key: &[u8]) -> Intent {
    Intent::new(
        IntentKind::new(kind).expect("valid test intent kind"),
        key.to_vec(),
        vec![1],
    )
}

#[derive(Debug)]
struct TestProjector;

impl Projector for TestProjector {
    fn project(
        &self,
        fact: &Fact,
        _context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        Ok(ProjectionOutput::new()
            .intent(intent(REPLAY_OK, &fact.id))
            .intent(intent(LIVE_ONLY, &fact.id))
            .local_intent(intent(LIVE_LOCAL, &fact.id)))
    }
}

#[derive(Debug)]
struct ReplayContextProjector;

impl Projector for ReplayContextProjector {
    fn project(
        &self,
        fact: &Fact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        Ok(if context.is_replay() {
            ProjectionOutput::new().intent(intent(REPLAY_OK, &fact.id))
        } else {
            ProjectionOutput::new()
        })
    }
}

#[derive(Debug)]
struct ReplayNoopProjector;

impl Projector for ReplayNoopProjector {
    fn project(
        &self,
        fact: &Fact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        if context.is_replay() {
            Ok(ProjectionOutput::new())
        } else {
            Ok(ProjectionOutput::new().intent(intent(REPLAY_OK, &fact.id)))
        }
    }
}

#[derive(Debug, Default)]
struct ReplayHandler;

impl ReplayHandler {
    fn new() -> Self {
        Self
    }
}

impl IntentHandler for ReplayHandler {
    fn handle(&self, intent: &Intent, context: &HandlerContext<'_>) -> HandlerResult {
        Ok(if context.is_replay() {
            RuntimeEffects::new().intent(Intent::new(
                IntentKind::new(LIVE_FROM_HANDLER).expect("valid test intent kind"),
                intent.key.clone(),
                vec![1],
            ))
        } else {
            RuntimeEffects::new()
        })
    }
}

#[derive(Debug, Default)]
struct LiveOnlyHandler;

impl LiveOnlyHandler {
    fn new() -> Self {
        Self
    }
}

impl IntentHandler for LiveOnlyHandler {
    fn handle(&self, intent: &Intent, context: &HandlerContext<'_>) -> HandlerResult {
        if context.is_replay() || intent.kind.as_str() == LIVE_FROM_HANDLER {
            return Ok(RuntimeEffects::new());
        }
        Ok(RuntimeEffects::new().intent(Intent::new(
            IntentKind::new(LIVE_FROM_HANDLER).expect("valid test intent kind"),
            intent.key.clone(),
            vec![1],
        )))
    }
}

fn test_projector() -> Box<dyn Projector> {
    Box::new(TestProjector)
}

fn replay_context_projector() -> Box<dyn Projector> {
    Box::new(ReplayContextProjector)
}

fn replay_noop_projector() -> Box<dyn Projector> {
    Box::new(ReplayNoopProjector)
}

fn replay_handler() -> Box<dyn IntentHandler> {
    Box::new(ReplayHandler::new())
}

fn live_handler() -> Box<dyn IntentHandler> {
    Box::new(LiveOnlyHandler::new())
}

const HANDLERS: &[HandlerRoute] = &[
    HandlerRoute {
        intent_kind: REPLAY_OK,
        factory: replay_handler,
        recurrence: None,
    },
    HandlerRoute {
        intent_kind: LIVE_ONLY,
        factory: live_handler,
        recurrence: None,
    },
    HandlerRoute {
        intent_kind: LIVE_LOCAL,
        factory: live_handler,
        recurrence: None,
    },
    HandlerRoute {
        intent_kind: LIVE_FROM_HANDLER,
        factory: live_handler,
        recurrence: None,
    },
];

const SCHEMA_SOURCES: &[SchemaSource] = &[topo::core::network::SCHEMA_SOURCE];

const FACT_TAG: u8 = 99;

const RUNTIME: RuntimeDescription = RuntimeDescription {
    schema_sources: SCHEMA_SOURCES,
    row_mutation_tables: &[],
    projector: test_projector,
    fact_routes: &[],
    fact_admission: None,
    handlers: HANDLERS,
};

const RUNTIME_REPLAY_AWARE: RuntimeDescription = RuntimeDescription {
    schema_sources: SCHEMA_SOURCES,
    row_mutation_tables: &[],
    projector: replay_context_projector,
    fact_routes: &[],
    fact_admission: None,
    handlers: HANDLERS,
};

const RUNTIME_REPLAY_NOOP: RuntimeDescription = RuntimeDescription {
    schema_sources: SCHEMA_SOURCES,
    row_mutation_tables: &[],
    projector: replay_noop_projector,
    fact_routes: &[],
    fact_admission: None,
    handlers: HANDLERS,
};

fn fact() -> Fact {
    Fact::new(FactScope::Global, 1, vec![FACT_TAG])
}

fn drain_projection_for_test(runtime: &mut Runtime, max_rounds: usize, limit: usize) {
    for _ in 0..max_rounds {
        runtime
            .drain_projection_once(limit)
            .expect("drain projection batch");
        if runtime.pending_fact_count() == 0 {
            return;
        }
    }
    panic!("projection work did not become idle within {max_rounds} rounds");
}

#[test]
fn live_projection_records_all_projector_intents() {
    let mut runtime = Runtime::open_memory(&RUNTIME).expect("runtime");

    runtime.submit_fact(fact());
    drain_projection_for_test(&mut runtime, 4, 32);

    assert_eq!(
        runtime.pending_intent_count(),
        3,
        "normal projection records replayable and live-only projector intents"
    );
}

#[test]
fn replay_commits_and_dispatches_handler_followup_intents() {
    let mut runtime = Runtime::open_memory(&RUNTIME_REPLAY_AWARE).expect("runtime");
    runtime.submit_fact(fact());
    drain_projection_for_test(&mut runtime, 4, 32);

    let report = runtime
        .replay(topo::core::replay::ReplayOrder::Canonical)
        .expect("replay");

    assert_eq!(
        report.replayed_intents, 2,
        "the replay handler sees replay mode, emits a follow-up, and replay dispatches that follow-up too"
    );
    assert_eq!(
        runtime.pending_intent_count(),
        0,
        "replay should consume the handler-emitted follow-up before the barrier"
    );
}

#[test]
fn replay_dispatches_projector_live_work_to_handlers_in_replay_mode() {
    let mut runtime = Runtime::open_memory(&RUNTIME).expect("runtime");
    runtime.submit_fact(fact());
    drain_projection_for_test(&mut runtime, 4, 32);

    let report = runtime
        .replay(topo::core::replay::ReplayOrder::Canonical)
        .expect("replay");

    assert_eq!(
        report.replayed_intents, 4,
        "replay dispatches projector-emitted durable and local intents, and live handlers no-op because they see replay mode"
    );
    assert_eq!(
        runtime.pending_intent_count(),
        0,
        "handler-owned replay no-ops must drain live-only queued work"
    );
}

#[test]
fn replay_projects_retained_facts_with_replay_context() {
    let mut runtime = Runtime::open_memory(&RUNTIME_REPLAY_NOOP).expect("runtime");
    runtime.submit_fact(fact());
    drain_projection_for_test(&mut runtime, 4, 32);
    assert_eq!(
        runtime.pending_intent_count(),
        1,
        "normal projection proves the test projector emits work outside replay"
    );

    let report = runtime
        .replay(topo::core::replay::ReplayOrder::Canonical)
        .expect("replay");

    assert_eq!(
        report.retained_facts, 1,
        "all retained facts are queued for replay"
    );
    assert_eq!(
        report.projected_facts, 1,
        "replay still runs the projector with replay context"
    );
    assert_eq!(report.replayed_intents, 0);
    assert_eq!(
        runtime.pending_intent_count(),
        0,
        "projector-owned replay no-op should not leave queued work after replay"
    );
}
