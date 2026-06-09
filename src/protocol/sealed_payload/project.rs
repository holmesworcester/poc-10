use crate::core::context::{ContextKeyPart, ContextNeed, ContextOffer};
use crate::core::facts::{Fact, FactId, FactScope};
use crate::core::pipeline::{
    project_staged, FactPipeline, ProjectionContext, ProjectionOutput, Projector, SemanticProjector,
};

use super::fact::SealedPayloadFact;

pub const SEALED_PAYLOAD_ROLE: &str = "sealed_payload";
pub const PAYLOAD_OPEN_REQUEST_ROLE: &str = "payload_open_request";
pub const OPENED_PAYLOAD_ROLE: &str = "opened_payload";

pub const PIPELINE: FactPipeline = FactPipeline::Staged {
    decode: "sealed_payload::decode::Codec",
    authenticate: "sealed_payload::authenticate::SealedPayloadAuthenticator",
    adapt: "sealed_payload::adapt::SealedPayloadAdapter",
    project: "sealed_payload::project::SealedPayloadProjector",
};

#[derive(Debug, Clone, Default)]
pub struct SealedPayloadProjector;

impl SealedPayloadProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for SealedPayloadProjector {
    fn project(
        &self,
        fact: &Fact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        project_staged::<
            super::Codec,
            super::authenticate::SealedPayloadAuthenticator,
            super::adapt::SealedPayloadAdapter,
            _,
        >(self, fact, context)
    }
}

impl SemanticProjector<SealedPayloadFact> for SealedPayloadProjector {
    fn project_semantic(
        &self,
        fact: &Fact,
        payload: SealedPayloadFact,
        _context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        Ok(ProjectionOutput::new().offer(sealed_payload_offer(
            fact.id,
            fact.scope.clone(),
            fact.id,
            payload.format,
        )?))
    }
}

pub fn sealed_payload_need(
    owner: FactId,
    scope: FactScope,
    payload_id: FactId,
    format: u32,
) -> Result<ContextNeed, String> {
    ContextNeed::for_key_parts(
        owner,
        SEALED_PAYLOAD_ROLE,
        scope,
        [
            ContextKeyPart::bytes(&payload_id),
            ContextKeyPart::u64(u64::from(format)),
        ],
    )
}

pub fn sealed_payload_offer(
    owner: FactId,
    scope: FactScope,
    payload_id: FactId,
    format: u32,
) -> Result<ContextOffer, String> {
    ContextOffer::for_key_parts(
        owner,
        SEALED_PAYLOAD_ROLE,
        scope,
        [
            ContextKeyPart::bytes(&payload_id),
            ContextKeyPart::u64(u64::from(format)),
        ],
    )
}

pub fn payload_open_request_need(
    owner: FactId,
    scope: FactScope,
    root_id: FactId,
    role: u32,
    index: u32,
    payload_id: FactId,
    format: u32,
) -> Result<ContextNeed, String> {
    ContextNeed::for_key_parts(
        owner,
        PAYLOAD_OPEN_REQUEST_ROLE,
        scope,
        [
            ContextKeyPart::bytes(&root_id),
            ContextKeyPart::u64(u64::from(role)),
            ContextKeyPart::u64(u64::from(index)),
            ContextKeyPart::bytes(&payload_id),
            ContextKeyPart::u64(u64::from(format)),
        ],
    )
}

pub fn payload_open_request_offer(
    owner: FactId,
    scope: FactScope,
    root_id: FactId,
    role: u32,
    index: u32,
    payload_id: FactId,
    format: u32,
) -> Result<ContextOffer, String> {
    ContextOffer::for_key_parts(
        owner,
        PAYLOAD_OPEN_REQUEST_ROLE,
        scope,
        [
            ContextKeyPart::bytes(&root_id),
            ContextKeyPart::u64(u64::from(role)),
            ContextKeyPart::u64(u64::from(index)),
            ContextKeyPart::bytes(&payload_id),
            ContextKeyPart::u64(u64::from(format)),
        ],
    )
}

pub fn opened_payload_need(
    owner: FactId,
    scope: FactScope,
    root_id: FactId,
    role: u32,
    index: u32,
    payload_id: FactId,
    format: u32,
) -> Result<ContextNeed, String> {
    ContextNeed::for_key_parts(
        owner,
        OPENED_PAYLOAD_ROLE,
        scope,
        [
            ContextKeyPart::bytes(&root_id),
            ContextKeyPart::u64(u64::from(role)),
            ContextKeyPart::u64(u64::from(index)),
            ContextKeyPart::bytes(&payload_id),
            ContextKeyPart::u64(u64::from(format)),
        ],
    )
}

pub fn opened_payload_offer(
    owner: FactId,
    scope: FactScope,
    root_id: FactId,
    role: u32,
    index: u32,
    payload_id: FactId,
    format: u32,
) -> Result<ContextOffer, String> {
    ContextOffer::for_key_parts(
        owner,
        OPENED_PAYLOAD_ROLE,
        scope,
        [
            ContextKeyPart::bytes(&root_id),
            ContextKeyPart::u64(u64::from(role)),
            ContextKeyPart::u64(u64::from(index)),
            ContextKeyPart::bytes(&payload_id),
            ContextKeyPart::u64(u64::from(format)),
        ],
    )
}

#[cfg(test)]
mod tests {
    use crate::core::facts::{Fact, FactScope};
    use crate::core::pipeline::{ProjectionContext, Projector};
    use crate::protocol::sealed_payload::fact::{PayloadCiphertext, PayloadHeader};

    use super::*;

    #[test]
    fn sealed_payload_projects_only_payload_offer() {
        let payload = SealedPayloadFact {
            format: 7,
            algorithm: 1,
            header: PayloadHeader::new(b"nonce").unwrap(),
            ciphertext: PayloadCiphertext::new(b"ciphertext").unwrap(),
        };
        let fact = Fact::new(
            FactScope::Global,
            0,
            crate::protocol::sealed_payload::encode::encode_fact(&payload).unwrap(),
        );

        let output = SealedPayloadProjector::new()
            .project(&fact, &ProjectionContext::default())
            .expect("project payload");

        assert!(output.needs.is_empty());
        assert_eq!(output.offers.len(), 1);
        assert_eq!(output.offers[0].role, SEALED_PAYLOAD_ROLE);
        assert!(output.effects.row_mutations.is_empty());
        assert!(output.effects.intents.is_empty());
    }

    #[test]
    fn open_request_and_opened_payload_use_same_root_edge_key() {
        let scope = FactScope::Global;
        let request = payload_open_request_need(
            [1; 32],
            scope.clone(),
            [2; 32],
            crate::protocol::root::roles::CONTENT,
            0,
            [3; 32],
            7,
        )
        .expect("open request need");
        let request_offer = payload_open_request_offer(
            [4; 32],
            scope.clone(),
            [2; 32],
            crate::protocol::root::roles::CONTENT,
            0,
            [3; 32],
            7,
        )
        .expect("open request offer");
        assert_eq!(request.role, request_offer.role);
        assert_eq!(request.start_key, request_offer.start_key);

        let opened = opened_payload_need(
            [5; 32],
            scope.clone(),
            [2; 32],
            crate::protocol::root::roles::CONTENT,
            0,
            [3; 32],
            7,
        )
        .expect("opened need");
        let opened_offer = opened_payload_offer(
            [6; 32],
            scope,
            [2; 32],
            crate::protocol::root::roles::CONTENT,
            0,
            [3; 32],
            7,
        )
        .expect("opened offer");
        assert_eq!(opened.role, opened_offer.role);
        assert_eq!(opened.start_key, opened_offer.start_key);
        assert_ne!(request.role, opened.role);
    }
}
