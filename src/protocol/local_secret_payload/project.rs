use crate::core::context::{ContextKeyPart, ContextNeed, ContextOffer};
use crate::core::facts::{Fact, FactId, FactScope};
use crate::core::pipeline::{
    project_staged, FactPipeline, ProjectionContext, ProjectionOutput, Projector, SemanticProjector,
};

use super::fact::LocalSecretPayloadFact;

pub const LOCAL_SECRET_PAYLOAD_ROLE: &str = "local_secret_payload";

pub const PIPELINE: FactPipeline = FactPipeline::Staged {
    decode: "local_secret_payload::decode::Codec",
    authenticate: "local_secret_payload::authenticate::LocalSecretPayloadAuthenticator",
    adapt: "local_secret_payload::adapt::LocalSecretPayloadAdapter",
    project: "local_secret_payload::project::LocalSecretPayloadProjector",
};

#[derive(Debug, Clone, Default)]
pub struct LocalSecretPayloadProjector;

impl LocalSecretPayloadProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for LocalSecretPayloadProjector {
    fn project(
        &self,
        fact: &Fact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        project_staged::<
            super::Codec,
            super::authenticate::LocalSecretPayloadAuthenticator,
            super::adapt::LocalSecretPayloadAdapter,
            _,
        >(self, fact, context)
    }
}

impl SemanticProjector<LocalSecretPayloadFact> for LocalSecretPayloadProjector {
    fn project_semantic(
        &self,
        fact: &Fact,
        secret: LocalSecretPayloadFact,
        _context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        if fact.scope != FactScope::Local {
            return Err("local secret payload must be local-scoped".to_string());
        }
        Ok(ProjectionOutput::new().offer(local_secret_payload_offer(
            fact.id,
            fact.id,
            secret.family,
            secret.version,
        )?))
    }
}

pub fn local_secret_payload_need(
    owner: FactId,
    secret_id: FactId,
    family: u32,
    version: u32,
) -> Result<ContextNeed, String> {
    ContextNeed::for_key_parts(
        owner,
        LOCAL_SECRET_PAYLOAD_ROLE,
        FactScope::Local,
        [
            ContextKeyPart::bytes(&secret_id),
            ContextKeyPart::u64(u64::from(family)),
            ContextKeyPart::u64(u64::from(version)),
        ],
    )
}

pub fn local_secret_payload_offer(
    owner: FactId,
    secret_id: FactId,
    family: u32,
    version: u32,
) -> Result<ContextOffer, String> {
    ContextOffer::for_key_parts(
        owner,
        LOCAL_SECRET_PAYLOAD_ROLE,
        FactScope::Local,
        [
            ContextKeyPart::bytes(&secret_id),
            ContextKeyPart::u64(u64::from(family)),
            ContextKeyPart::u64(u64::from(version)),
        ],
    )
}

#[cfg(test)]
mod tests {
    use crate::core::facts::{Fact, FactScope};
    use crate::core::pipeline::{ProjectionContext, Projector};
    use crate::protocol::local_secret_payload::fact::LocalSecretBytes;

    use super::*;

    fn secret_fact(scope: FactScope) -> Fact {
        let secret = LocalSecretPayloadFact {
            family: 9,
            version: 1,
            bytes: LocalSecretBytes::new(b"secret").unwrap(),
        };
        Fact::new(
            scope,
            0,
            crate::protocol::local_secret_payload::encode::encode_fact(&secret).unwrap(),
        )
    }

    #[test]
    fn local_secret_projects_only_under_local_scope() {
        let output = LocalSecretPayloadProjector::new()
            .project(
                &secret_fact(FactScope::Local),
                &ProjectionContext::default(),
            )
            .expect("project local secret");

        assert!(output.needs.is_empty());
        assert_eq!(output.offers.len(), 1);
        assert_eq!(output.offers[0].role, LOCAL_SECRET_PAYLOAD_ROLE);
        assert!(output.effects.intents.is_empty());
    }

    #[test]
    fn local_secret_rejects_global_scope() {
        assert!(LocalSecretPayloadProjector::new()
            .project(
                &secret_fact(FactScope::Global),
                &ProjectionContext::default()
            )
            .is_err());
    }
}
