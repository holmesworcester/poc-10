use topo::core::facts::{Fact, FactScope};
use topo::core::projectors::{ProjectionContext, ProjectionOutput, Projector};
use topo::core::runtime::{ProjectionStatus, Runtime, RuntimeDescription};

const EMPTY_HANDLERS: &[topo::core::runtime::HandlerRoute] = &[];

const SUCCESS_RUNTIME: RuntimeDescription = RuntimeDescription {
    schema_sources: &[],
    row_mutation_tables: &[],
    projector: success_projector,
    handlers: EMPTY_HANDLERS,
    command_excluded_handlers: &[],
};

const FAIL_RUNTIME: RuntimeDescription = RuntimeDescription {
    schema_sources: &[],
    row_mutation_tables: &[],
    projector: fail_projector,
    handlers: EMPTY_HANDLERS,
    command_excluded_handlers: &[],
};

#[derive(Debug)]
struct SuccessProjector;

impl Projector for SuccessProjector {
    fn project(
        &self,
        _fact: &Fact,
        _projection_context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        Ok(ProjectionOutput::new())
    }
}

fn success_projector() -> Box<dyn Projector> {
    Box::new(SuccessProjector)
}

#[derive(Debug)]
struct FailProjector;

impl Projector for FailProjector {
    fn project(
        &self,
        _fact: &Fact,
        _projection_context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        Err("intentional projection failure".to_string())
    }
}

fn fail_projector() -> Box<dyn Projector> {
    Box::new(FailProjector)
}

#[test]
fn projection_status_moves_from_pending_to_projected() {
    let mut runtime = Runtime::open_memory(&SUCCESS_RUNTIME).expect("runtime");
    let fact = Fact::new(FactScope::Global, 10, b"project me".to_vec());
    let fact_id = fact.id;

    assert!(runtime.submit_fact(fact));
    assert_eq!(
        runtime.projection_status(fact_id).expect("status"),
        ProjectionStatus::Pending
    );

    runtime
        .process_projection_until_idle(2, 8)
        .expect("drain projection");

    assert_eq!(
        runtime.projection_status(fact_id).expect("status"),
        ProjectionStatus::Projected
    );
    assert_eq!(runtime.pending_fact_count(), 0);
}

#[test]
fn projection_failure_records_error_and_leaves_queue_idle() {
    let mut runtime = Runtime::open_memory(&FAIL_RUNTIME).expect("runtime");
    let fact = Fact::new(FactScope::Global, 10, b"fail me".to_vec());
    let fact_id = fact.id;

    assert!(runtime.submit_fact(fact));
    runtime
        .process_projection_until_idle(2, 8)
        .expect("drain projection");

    assert_eq!(
        runtime.projection_status(fact_id).expect("status"),
        ProjectionStatus::Failed("intentional projection failure".to_string())
    );
    assert_eq!(runtime.pending_fact_count(), 0);

    let status = runtime
        .process_projection_until_idle(2, 8)
        .expect("second drain");
    assert!(status.is_idle());
}
