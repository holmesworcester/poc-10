//! Pure projector execution for one fact.

use super::effects::PipelineEffects;
use crate::core::context::{diff_context_sets, ContextSet, ContextSetDelta};
use crate::core::facts::Fact;
use crate::core::projectors::{ProjectionContext, ProjectionOutput, Projector, TimeWake};

/// The pure result of running one projector before any SQL writes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ProjectionRun {
    pub(super) context: ContextSet,
    pub(super) context_delta: ContextSetDelta,
    pub(super) time_wakes: Vec<TimeWake>,
    pub(super) pipeline: PipelineEffects,
}

/// Call the protocol projector and normalize the output for the SQL pipeline.
///
/// Projection output is the complete replacement context for this fact. This
/// helper enforces that projectors only own their own context/time rows, then
/// computes the context delta that will wake dependent facts after commit.
pub(super) fn run_projection_with_context(
    projector: &(impl Projector + ?Sized),
    fact: &Fact,
    previous_context: &ContextSet,
    context: ProjectionContext,
) -> Result<ProjectionRun, String> {
    let output = projector.project(fact, &context)?;
    enforce_owner_is_self(fact, &output)?;
    let context = output.context_set();
    let context_delta = diff_context_sets(previous_context, &context);
    Ok(ProjectionRun {
        context,
        context_delta,
        time_wakes: output.time_wakes,
        pipeline: PipelineEffects {
            row_mutations: output.row_mutations,
            durable_intents: output.intents,
            local_intents: output.local_intents,
            ..PipelineEffects::default()
        },
    })
}

/// Reject any projected need, offer, or time wake whose `owner` is not the fact
/// being projected.
fn enforce_owner_is_self(fact: &Fact, output: &ProjectionOutput) -> Result<(), String> {
    for need in &output.needs {
        if need.owner != fact.id {
            return Err(format!(
                "projector emitted need with owner {:x?} that is not the projected fact {:x?}",
                need.owner, fact.id
            ));
        }
    }
    for offer in &output.offers {
        if offer.owner != fact.id {
            return Err(format!(
                "projector emitted offer with owner {:x?} that is not the projected fact {:x?}",
                offer.owner, fact.id
            ));
        }
    }
    for wake in &output.time_wakes {
        if wake.owner != fact.id {
            return Err(format!(
                "projector emitted time wake with owner {:x?} that is not the projected fact {:x?}",
                wake.owner, fact.id
            ));
        }
    }
    Ok(())
}
