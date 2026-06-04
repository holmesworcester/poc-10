//! Replay-mode intent suppression tests.
//!
//! These use a tiny runtime description instead of the full protocol so the
//! assertion is about core behavior: replay may record only replay-allowed
//! follow-up intents, even when projectors or replay handlers emit live-only
//! work.

use topo::core::effects::PipelineEffects;
use topo::core::facts::{Fact, FactScope};
use topo::core::intents::{HandlerContext, HandlerResult, Intent, IntentHandler, IntentKind};
use topo::core::projectors::{
    FactPipeline, FactRoute, ProjectionContext, ProjectionOutput, Projector,
};
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

// The test fact has type tag 99; the router projector ignores the tag, so
// fact_routes only carries the replay decision the replay engine reads.
const FACT_TAG: u8 = 99;

fn route_projector(fact: &Fact, context: &ProjectionContext) -> Result<ProjectionOutput, String> {
    TestProjector.project(fact, context)
}

const RUNTIME: RuntimeDescription = RuntimeDescription {
    schema_sources: SCHEMA_SOURCES,
    row_mutation_tables: &[],
    projector: test_projector,
    // No not-replayed types: every fact replays, preserving the suppression
    // tests' behavior.
    fact_routes: &[],
    handlers: HANDLERS,
    command_excluded_handlers: &[],
};

const RUNTIME_NOT_REPLAYED: RuntimeDescription = RuntimeDescription {
    schema_sources: SCHEMA_SOURCES,
    row_mutation_tables: &[],
    projector: test_projector,
    // Tag 99 is a durable, not-replayed fact: kept on disk, skipped by replay.
    fact_routes: &[FactRoute {
        tag: FACT_TAG,
        projector: route_projector,
        pipeline: FactPipeline::ProjectorComposed,
        replayed: false,
    }],
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
fn replay_suppresses_non_replayable_projector_and_handler_intents() {
    let mut runtime = Runtime::open_memory(&RUNTIME).expect("runtime");
    runtime.submit_fact(fact());

    let report = runtime
        .replay(&[], topo::core::replay::ReplayOrder::Canonical)
        .expect("replay");

    assert_eq!(report.replay_allowed_intents, 1);
    assert_eq!(
        report.suppressed_live_only_work, 3,
        "replay suppresses two projector live-only intents and one handler follow-up"
    );
    assert_eq!(
        runtime.pending_intent_count(),
        0,
        "suppressed replay work must not remain queued after the barrier"
    );
}

#[test]
fn replay_retains_but_does_not_reproject_not_replayed_facts() {
    let mut runtime = Runtime::open_memory(&RUNTIME_NOT_REPLAYED).expect("runtime");
    runtime.submit_fact(fact());

    let report = runtime
        .replay(&[], topo::core::replay::ReplayOrder::Canonical)
        .expect("replay");

    // The fact stays on disk (durable) but its projection — live session state —
    // is skipped, so it emits nothing and rebuilds no derived rows.
    assert_eq!(
        report.retained_facts, 1,
        "a not-replayed fact is still retained durably"
    );
    assert_eq!(
        report.projected_facts, 0,
        "a not-replayed fact must not be re-projected on replay"
    );
    assert_eq!(report.replay_allowed_intents, 0);
    assert_eq!(runtime.pending_intent_count(), 0);
}
