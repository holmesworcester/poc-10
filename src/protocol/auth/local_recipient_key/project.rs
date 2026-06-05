//! Local recipient key projector.
//!
//! POLICY. A local recipient key is admitted iff it is local-scoped and matches
//! its shared recipient fact. Projection offers local-recipient context while the
//! key is live, and self-purges when a superseding recipient key retires it.

use crate::core::context::{ContextNeed, ContextOffer};
use crate::core::facts::Fact;
use crate::core::pipeline::{
    project_staged, FactPipeline, ProjectionContext, ProjectionOutput, Projector, SemanticProjector,
};
use crate::protocol::auth::key_wrap::project::{matched_payload_fact, require_local_scope};
use crate::protocol::auth::recipient_key;

use super::fact::LocalRecipientKeyFact;

/// Staged read pipeline for the local_recipient_key fact.
pub const PIPELINE: FactPipeline = FactPipeline::Staged {
    decode: "auth::local_recipient_key::Codec",
    authenticate: "auth::local_recipient_key::authenticate::LocalRecipientKeyAuthenticator",
    adapt: "auth::local_recipient_key::adapt::LocalRecipientKeyAdapter",
    project: "auth::local_recipient_key::project::LocalRecipientKeyProjector",
};

#[derive(Debug, Clone, Default)]
pub struct LocalRecipientKeyProjector;

impl LocalRecipientKeyProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for LocalRecipientKeyProjector {
    fn project(
        &self,
        fact: &Fact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        project_staged::<
            super::Codec,
            super::authenticate::LocalRecipientKeyAuthenticator,
            super::adapt::LocalRecipientKeyAdapter,
            _,
        >(self, fact, context)
    }
}

impl SemanticProjector<LocalRecipientKeyFact> for LocalRecipientKeyProjector {
    fn project_semantic(
        &self,
        fact: &Fact,
        local: LocalRecipientKeyFact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        local_recipient_key(fact, context, local)
    }
}

fn local_recipient_key(
    fact: &Fact,
    projection_context: &ProjectionContext,
    local: LocalRecipientKeyFact,
) -> Result<ProjectionOutput, String> {
    // 1. Structural.
    let scope = crate::protocol::auth::workspace::scope(local.workspace_id);
    require_local_scope(fact)?;

    // 2. Context: recipient match and supersession.
    let recipient_need = ContextNeed::range(
        fact.id,
        "recipient_key",
        scope.clone(),
        local.recipient_key_id,
        local.recipient_key_id,
    );
    let Some(recipient_fact) = matched_payload_fact(projection_context, &recipient_need) else {
        return Ok(ProjectionOutput::new().need(recipient_need));
    };
    let recipient = recipient_key::decode_fact_payload(&recipient_fact.bytes)?;
    if recipient.workspace_id != local.workspace_id {
        return Err("local recipient key workspace does not match recipient".to_string());
    }
    if recipient.recipient_key != local.recipient_key {
        return Err("local recipient key public key does not match recipient".to_string());
    }

    let superseded_need = ContextNeed::range(
        fact.id,
        "recipient_superseded",
        scope.clone(),
        local.recipient_key_id,
        local.recipient_key_id,
    );
    let is_superseded = projection_context.payload_for(&superseded_need).is_some();
    let output = ProjectionOutput::new()
        .need(recipient_need)
        .need(superseded_need);
    // 3. Materialize: offer local-recipient context or self-purge.
    if is_superseded {
        return Ok(output.purge_self(fact.id));
    }

    Ok(output.offer(ContextOffer::range(
        fact.id,
        "local_recipient_key",
        scope,
        local.recipient_key_id,
        local.recipient_key_id,
    )))
}
