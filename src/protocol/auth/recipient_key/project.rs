//! Recipient key projector.
//!
//! POLICY. A recipient key is admitted iff its scope matches the workspace and
//! supersession of any previous recipient key validates. Projection shares the
//! fact, publishes recipient context, and emits proactive key-wrap work when
//! eligible local wrap sources and signer secrets are available.

use crate::core::context::{ContextNeed, ContextOffer};
use crate::core::facts::Fact;
use crate::core::projectors::{
    project_authenticated, AuthenticatedFact, AuthenticatedProjector, ProjectionContext,
    ProjectionOutput, Projector,
};
use crate::protocol::auth::create_key_wrap::create_key_wrap_intent;
use crate::protocol::auth::endpoint_shared;
use crate::protocol::auth::key_wrap::project::{
    add_signer_needs_for_matching_sources, matched_payload_fact, matching_wrap_sources_with_signer,
    proactive_wrap_source_need, require_fact_scope,
};
use crate::protocol::sync::shared_fact::project::{context_have_from_needs, share_fact_with_sync};

use super::fact::{RecipientKeyFact, NO_PREVIOUS_RECIPIENT_KEY};

#[derive(Debug, Clone, Default)]
pub struct RecipientKeyProjector;

impl RecipientKeyProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for RecipientKeyProjector {
    fn project(
        &self,
        fact: &Fact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        project_authenticated::<super::authenticate::RecipientKeyAuthenticator, _>(
            self, fact, context,
        )
    }
}

impl AuthenticatedProjector<super::authenticate::RecipientKeyAuthenticator> for RecipientKeyProjector {
    fn project_authenticated(
        &self,
        authenticated: AuthenticatedFact<'_, RecipientKeyFact>,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        let (fact, recipient) = authenticated.into_parts();
        recipient_key(fact, context, recipient)
    }
}

fn recipient_key(
    fact: &Fact,
    projection_context: &ProjectionContext,
    recipient: RecipientKeyFact,
) -> Result<ProjectionOutput, String> {
    // 1. Structural.
    let scope = crate::protocol::auth::workspace::scope(recipient.workspace_id);
    require_fact_scope(fact, &scope)?;

    // 2. Context: signer, supersession, and previous-key validation.
    let signer_need = ContextNeed::range(
        fact.id,
        "content_signer",
        scope.clone(),
        recipient.endpoint_id,
        recipient.endpoint_id,
    );
    let superseded_need = ContextNeed::range(
        fact.id,
        "recipient_superseded",
        scope.clone(),
        fact.id,
        fact.id,
    );
    let mut context_have = context_have_from_needs(projection_context, [&superseded_need]);
    let is_superseded = !context_have.is_empty();
    let mut output = ProjectionOutput::new()
        .need(signer_need.clone())
        .need(superseded_need);

    if recipient.previous_recipient_key_id != NO_PREVIOUS_RECIPIENT_KEY {
        let previous_need = ContextNeed::range(
            fact.id,
            "recipient_key",
            scope.clone(),
            recipient.previous_recipient_key_id,
            recipient.previous_recipient_key_id,
        );
        output = output.need(previous_need.clone());
        let Some(previous_fact) = matched_payload_fact(projection_context, &previous_need) else {
            return Ok(output);
        };
        validate_previous_recipient_key(previous_fact, &recipient)?;
        context_have.push(previous_fact.id);
        output = output.offer(ContextOffer::range(
            fact.id,
            "recipient_superseded",
            scope.clone(),
            recipient.previous_recipient_key_id,
            recipient.previous_recipient_key_id,
        ));
    }
    let Some(signer_fact) = projection_context.payload_for(&signer_need) else {
        return Ok(output);
    };
    validate_recipient_signer(signer_fact, &recipient)?;
    context_have.extend(context_have_from_needs(projection_context, [&signer_need]));

    // 3. Materialize: publish recipient context and proactive key-wrap work.
    output = share_fact_with_sync(
        output.offer(ContextOffer::range(
            fact.id,
            "recipient_key",
            scope.clone(),
            fact.id,
            fact.id,
        )),
        recipient.workspace_id,
        fact,
        context_have,
    );

    if is_superseded {
        return Ok(output);
    }

    let min_frontier_created_at_ms =
        if recipient.previous_recipient_key_id == NO_PREVIOUS_RECIPIENT_KEY {
            0
        } else {
            recipient.created_at_ms
        };
    let wrap_need = proactive_wrap_source_need(
        fact.id,
        scope.clone(),
        recipient.workspace_id,
        min_frontier_created_at_ms,
    );
    output = output.need(wrap_need.clone());

    output = add_signer_needs_for_matching_sources(output, projection_context, &wrap_need)?;
    for (source_fact_id, signer_secret_fact_id, source) in
        matching_wrap_sources_with_signer(projection_context, &wrap_need)?
    {
        output = output.intent(create_key_wrap_intent(
            fact.id,
            source_fact_id,
            signer_secret_fact_id,
            source,
        ));
    }
    Ok(output)
}

fn validate_previous_recipient_key(
    previous_fact: &Fact,
    recipient: &RecipientKeyFact,
) -> Result<(), String> {
    if previous_fact.id != recipient.previous_recipient_key_id {
        return Err("recipient key supersession previous context payload id mismatch".to_string());
    }
    let previous = super::decode_fact_payload(&previous_fact.bytes).map_err(|_| {
        "recipient key supersession previous dependency is not a recipient key".to_string()
    })?;
    if previous.workspace_id != recipient.workspace_id {
        return Err(
            "recipient key supersession previous_recipient_key workspace does not match"
                .to_string(),
        );
    }
    if previous.endpoint_id != recipient.endpoint_id {
        return Err(
            "recipient key supersession previous_recipient_key endpoint does not match \
             (cross-endpoint supersession is rejected)"
                .to_string(),
        );
    }
    Ok(())
}

fn validate_recipient_signer(
    signer_fact: &Fact,
    recipient: &RecipientKeyFact,
) -> Result<(), String> {
    let signer = endpoint_shared::decode_fact_payload(signer_fact.body())
        .map_err(|_| "recipient key signer context must be endpoint_shared".to_string())?;
    if signer.workspace_id != recipient.workspace_id {
        return Err("recipient key signer workspace mismatch".to_string());
    }
    if signer.endpoint_id != recipient.endpoint_id {
        return Err("recipient key signer endpoint mismatch".to_string());
    }
    if signer.signing_public_key != recipient.signer_public_key {
        return Err("recipient key signer public key mismatch".to_string());
    }
    Ok(())
}
