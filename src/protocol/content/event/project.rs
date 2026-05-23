//! Poc-10 content-event projector.
//!
//! POLICY. A content_event is admitted iff:
//!   1. STRUCTURAL. The fact is workspace-scoped and contains either a raw
//!      content_event payload or a signed envelope for that payload type.
//!   2. AUTHORITY. Signed events must be signed by a validated endpoint/user
//!      context in the same workspace; raw events have no signer context.
//!   3. MATERIALIZE. Once valid, write the content_event row and share the
//!      fact with the workspace.
use crate::core::facts::Fact;
use crate::core::intents::RowMutation;
use crate::core::projectors::{
    project_typed, ProjectionContext, ProjectionOutput, Projector, TypedProjector,
};

use crate::protocol::content::message::project;
use crate::protocol::sync::share_fact_with_workspace::share_fact_with_workspace_intent_for_fact;

use super::rows::content_event_row;

#[derive(Debug, Clone, Default)]
pub struct ContentEventProjector;

impl ContentEventProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for ContentEventProjector {
    fn project(
        &self,
        fact: &Fact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        project_typed::<super::Codec, _>(self, fact, context)
    }
}

impl TypedProjector<super::Codec> for ContentEventProjector {
    fn project_typed(
        &self,
        fact: &Fact,
        decoded: project::DecodedFact<super::fact::ContentEventFact>,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        // 1. Structural.
        let project::DecodedFact {
            payload: event,
            signer,
            envelope,
        } = decoded;
        let scope = crate::protocol::auth::workspace::scope(event.workspace_id);
        require_fact_scope(fact, &scope)?;

        // 2. Authority.
        let signer_need = project::signer_need(fact.id, signer);
        if let (Some(signer), Some(need)) = (signer, signer_need.as_ref()) {
            if !project::validate_signer_context(
                context,
                need,
                signer,
                event.workspace_id,
                None,
                "content event",
            )? {
                return Ok(output_with_signer_need(signer_need));
            }
        }
        project::verify_envelope(envelope.as_ref(), "content event")?;

        // 3. Materialize.
        Ok(output_with_signer_need(signer_need)
            .row_mutation(RowMutation::InsertValues(content_event_row(
                fact.id, &event,
            )))
            .intent(share_fact_with_workspace_intent_for_fact(
                event.workspace_id,
                fact,
            )))
    }
}

fn output_with_signer_need(
    signer_need: Option<crate::core::context::ContextNeed>,
) -> ProjectionOutput {
    let mut output = ProjectionOutput::new();
    if let Some(need) = signer_need {
        output = output.need(need);
    }
    output
}

fn require_fact_scope(fact: &Fact, expected: &crate::core::facts::FactScope) -> Result<(), String> {
    if &fact.scope == expected {
        Ok(())
    } else {
        Err("content event fact scope does not match body workspace".to_string())
    }
}
