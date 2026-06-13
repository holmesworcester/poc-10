//! Replay-mode intent suppression tests.
//!
//! These use a tiny runtime description instead of the full protocol so the
//! assertion is about core behavior: projectors own replay-mode emissions, and
//! replay dispatch still filters live-only follow-up work from handlers.

use topo::core::effects::PipelineEffects;
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
struct ReplayAllowedProjector;

impl Projector for ReplayAllowedProjector {
    fn project(
        &self,
        fact: &Fact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        if context.is_replay() {
            Ok(ProjectionOutput::new().intent(intent(REPLAY_OK, &fact.id)))
        } else {
            Ok(ProjectionOutput::new().intent(intent(REPLAY_OK, &fact.id)))
        }
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
    fn handle(&self, intent: &Intent, _context: &HandlerContext<'_>) -> HandlerResult {
        Ok(PipelineEffects::new().intent(Intent::new(
            IntentKind::new(LIVE_FROM_HANDLER).expect("valid test intent kind"),
            intent.key.clone(),
            vec![1],
        )))
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
    fn handle(&self, _intent: &Intent, _context: &HandlerContext<'_>) -> HandlerResult {
        Ok(PipelineEffects::new())
    }
}

fn test_projector() -> Box<dyn Projector> {
    Box::new(TestProjector)
}

fn replay_allowed_projector() -> Box<dyn Projector> {
    Box::new(ReplayAllowedProjector)
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
        name: "replay_ok",
        intent_kind: REPLAY_OK,
        factory: replay_handler,
        runs_during_replay: true,
        recurrence: None,
    },
    HandlerRoute {
        name: "live_only",
        intent_kind: LIVE_ONLY,
        factory: live_handler,
        runs_during_replay: false,
        recurrence: None,
    },
    HandlerRoute {
        name: "live_local",
        intent_kind: LIVE_LOCAL,
        factory: live_handler,
        runs_during_replay: false,
        recurrence: None,
    },
    HandlerRoute {
        name: "live_from_handler",
        intent_kind: LIVE_FROM_HANDLER,
        factory: live_handler,
        runs_during_replay: false,
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
    command_excluded_handlers: &[],
};

const RUNTIME_REPLAY_AWARE: RuntimeDescription = RuntimeDescription {
    schema_sources: SCHEMA_SOURCES,
    row_mutation_tables: &[],
    projector: replay_allowed_projector,
    fact_routes: &[],
    fact_admission: None,
    handlers: HANDLERS,
    command_excluded_handlers: &[],
};

const RUNTIME_REPLAY_NOOP: RuntimeDescription = RuntimeDescription {
    schema_sources: SCHEMA_SOURCES,
    row_mutation_tables: &[],
    projector: replay_noop_projector,
    fact_routes: &[],
    fact_admission: None,
    handlers: HANDLERS,
    command_excluded_handlers: &[],
};

fn fact() -> Fact {
    Fact::new(FactScope::Global, 1, vec![FACT_TAG])
}

#[test]
fn live_projection_records_all_projector_intents() {
    let mut runtime = Runtime::open_memory(&RUNTIME).expect("runtime");

    runtime.submit_fact(fact());
    runtime
        .process_projection_until_idle(4, 32)
        .expect("live projection");

    assert_eq!(
        runtime.pending_intent_count(),
        3,
        "normal projection records replayable and live-only projector intents"
    );
}

#[test]
fn replay_suppresses_non_replayable_handler_followup_intents() {
    let mut runtime = Runtime::open_memory(&RUNTIME_REPLAY_AWARE).expect("runtime");
    runtime.submit_fact(fact());

    let report = runtime
        .replay(&[], topo::core::replay::ReplayOrder::Canonical)
        .expect("replay");

    assert_eq!(report.replay_allowed_intents, 1);
    assert_eq!(
        report.suppressed_live_only_work, 1,
        "replay suppresses the live-only handler follow-up"
    );
    assert_eq!(
        runtime.pending_intent_count(),
        0,
        "suppressed replay work must not remain queued after the barrier"
    );
}

#[test]
fn replay_projects_retained_facts_with_replay_context() {
    let mut runtime = Runtime::open_memory(&RUNTIME_REPLAY_NOOP).expect("runtime");
    runtime.submit_fact(fact());
    runtime
        .process_projection_until_idle(4, 32)
        .expect("live projection");
    assert_eq!(
        runtime.pending_intent_count(),
        1,
        "normal projection proves the test projector emits work outside replay"
    );

    let report = runtime
        .replay(&[], topo::core::replay::ReplayOrder::Canonical)
        .expect("replay");

    assert_eq!(
        report.retained_facts, 1,
        "all retained facts are queued for replay"
    );
    assert_eq!(
        report.projected_facts, 1,
        "replay still runs the projector with replay context"
    );
    assert_eq!(report.replay_allowed_intents, 0);
    assert_eq!(
        runtime.pending_intent_count(),
        0,
        "projector-owned replay no-op should not leave queued work after replay"
    );
}
