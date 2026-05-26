//! Connection-bootstrap projector.
//!
//! Bootstrap projection is the receive-side bridge from sealed pre-connection
//! network bytes to durable semantic handshake facts. It does not decide
//! request or response validity; it opens the carrier with the daemon endpoint
//! secret context and emits the canonical `connection_request` or
//! `connection_response` fact plus its receipt. Those child projectors own the
//! invite, endpoint, receipt, and handshake validation.
//!
//! POLICY. A `connection_bootstrap` fact is admitted iff:
//!   1. STRUCTURAL. The fact is local ephemeral input and its layout contains a
//!      valid sealed request or response frame with receive metadata.
//!   2. CONTEXT. The projector needs the singleton local daemon endpoint
//!      context. If it is not already available in the fixed-point pass, the
//!      ephemeral input is discarded with no durable output.
//!   3. MATERIALIZE. Opened request bytes become a durable global
//!      `connection_request` plus request receipt. Opened response bytes become
//!      a durable local `connection_response` plus response receipt.

use crate::core::crypto;
use crate::core::facts::{Fact, FactScope};
use crate::core::projectors::{
    project_typed, ProjectionContext, ProjectionOutput, Projector, TypedProjector,
};
use crate::protocol::auth::endpoint;
use crate::protocol::connection::frame::create::{
    received_connection_request_fact_effect, received_connection_response_fact_effect,
};

use super::fact::ConnectionBootstrapFact;

#[derive(Debug, Clone, Default)]
pub struct ConnectionBootstrapProjector;

impl ConnectionBootstrapProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for ConnectionBootstrapProjector {
    fn project(
        &self,
        fact: &Fact,
        projection_context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        project_typed::<super::Codec, _>(self, fact, projection_context)
    }
}

impl TypedProjector<super::Codec> for ConnectionBootstrapProjector {
    fn project_typed(
        &self,
        fact: &Fact,
        bootstrap: ConnectionBootstrapFact,
        projection_context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        // 1. Structural.
        if fact.scope != FactScope::Local {
            return Err("connection bootstrap fact must have local scope".to_string());
        }

        // 2. Context.
        let endpoint_need = endpoint::daemon_endpoint_need(fact.id);
        let Some(endpoint_fact) = projection_context.payload_for(&endpoint_need) else {
            return Ok(ProjectionOutput::new().need(endpoint_need));
        };
        if endpoint_fact.scope != FactScope::Local {
            return Err("connection bootstrap endpoint context must be local".to_string());
        }
        let local_endpoint = endpoint::decode_fact_payload(endpoint_fact.body()).map_err(|_| {
            "connection bootstrap endpoint context is not a local endpoint".to_string()
        })?;

        // 3. Materialize.
        let frame = bootstrap.frame.bytes();
        let frame_hash = crypto::hash(frame);
        let effects = match frame.first().copied() {
            Some(super::layout::TYPE_SEALED_CONNECTION_REQUEST) => {
                let Ok(request_bytes) =
                    super::layout::open_connection_request(frame, &local_endpoint)
                else {
                    return Ok(ProjectionOutput::new());
                };
                received_connection_request_fact_effect(
                    &request_bytes,
                    bootstrap.origin_addr.bytes(),
                    bootstrap.received_at_local_ms,
                    frame_hash,
                )?
            }
            Some(super::layout::TYPE_SEALED_CONNECTION_RESPONSE) => {
                let Ok(response_bytes) =
                    super::layout::open_connection_response(frame, &local_endpoint)
                else {
                    return Ok(ProjectionOutput::new());
                };
                received_connection_response_fact_effect(
                    &response_bytes,
                    bootstrap.origin_addr.bytes(),
                    bootstrap.received_at_local_ms,
                    frame_hash,
                )?
            }
            _ => return Ok(ProjectionOutput::new()),
        };
        let mut output = ProjectionOutput::new();
        for fact in effects.facts {
            output = output.fact(fact);
        }
        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::crypto::{self, ED25519_SIGNATURE_BYTES};
    use crate::core::facts::Fact;
    use crate::core::projectors::{MatchedContext, ProjectionContext};
    use crate::protocol::auth::endpoint::fact::EndpointFact;
    use crate::protocol::auth::invite::fact::InviteSecretFact;
    use crate::protocol::connection::fact_receipt::fact::RECEIVE_PATH_CONNECTION_REQUEST;
    use crate::protocol::connection::request::fact::ConnectionRequestFact;
    use crate::protocol::connection::request::{
        create as request_create, layout as request_layout,
    };

    fn endpoint_fact(secret: [u8; 32]) -> (EndpointFact, Fact) {
        let endpoint = EndpointFact {
            endpoint: crypto::x25519_public_key(&secret),
            secret,
            signing_public_key: crypto::ed25519_public_key(&[91; 32]),
            signing_secret: [91; 32],
        };
        let fact = endpoint::create::endpoint_fact(1, endpoint).expect("endpoint fact");
        (endpoint, fact)
    }

    fn endpoint_match(owner: [u8; 32], endpoint: Fact) -> MatchedContext {
        let need = endpoint::daemon_endpoint_need(owner);
        MatchedContext {
            need,
            offer: endpoint::daemon_endpoint_offer(endpoint.id),
            payload: endpoint,
        }
    }

    #[test]
    fn sealed_request_projects_to_request_and_receipt_facts() {
        let invite = InviteSecretFact::new([33; 32]);
        let (endpoint, endpoint_fact) = endpoint_fact([44; 32]);
        let initiator_ephemeral_secret = [59; 32];
        let mut request = ConnectionRequestFact {
            from_endpoint: crypto::x25519_public_key(&[55; 32]),
            to_endpoint: endpoint.endpoint,
            nonce: [56; 32],
            invite_fact_id: [57; 32],
            bootstrap_hash: invite.bootstrap_hash,
            invite_signature: [0; ED25519_SIGNATURE_BYTES],
            invite_secret_fact_id: [50; 32],
            initiator_ephemeral_secret_fact_id: [58; 32],
            initiator_ephemeral_public_key: crypto::x25519_public_key(&initiator_ephemeral_secret),
            from_listen_addr: Some("127.0.0.1:41001".parse().expect("return addr")),
            to_listen_addr: None,
        };
        request.invite_signature = crypto::ed25519_sign(
            &invite.bootstrap_secret,
            &request_create::invite_signing_transcript(&request).expect("request transcript"),
        );
        let request_bytes = request_layout::encode_fact(&request).expect("request");
        let sealed = super::super::layout::seal_connection_request(
            &request_bytes,
            &initiator_ephemeral_secret,
        )
        .expect("sealed request");
        let bootstrap = ConnectionBootstrapFact {
            origin_addr: crate::protocol::connection::fact_receipt::fact::OriginAddr::new(
                b"127.0.0.1:41002",
            )
            .expect("origin"),
            received_at_local_ms: 100,
            frame: crate::core::wire::FixedSlot::new(&sealed).expect("frame"),
        };
        let bootstrap_fact = Fact::new(
            FactScope::Local,
            100,
            super::super::layout::encode_fact(&bootstrap).expect("bootstrap"),
        );

        let output = ConnectionBootstrapProjector::new()
            .project(
                &bootstrap_fact,
                &ProjectionContext::from_matches(vec![endpoint_match(
                    bootstrap_fact.id,
                    endpoint_fact,
                )]),
            )
            .expect("project bootstrap");

        assert_eq!(output.effects.facts.len(), 2);
        assert!(output
            .effects
            .facts
            .iter()
            .any(|fact| fact.bytes == request_bytes));
        assert!(output.effects.facts.iter().any(|fact| {
            fact.body().first().copied()
                == Some(
                    crate::protocol::connection::fact_receipt::layout::TYPE_CONNECTION_FACT_RECEIPT,
                )
        }));
        let receipt = output
            .effects
            .facts
            .iter()
            .find(|fact| {
                fact.body().first().copied()
                    == Some(
                        crate::protocol::connection::fact_receipt::layout::TYPE_CONNECTION_FACT_RECEIPT,
                    )
            })
            .expect("receipt");
        let receipt =
            crate::protocol::connection::fact_receipt::layout::decode_fact(receipt.body())
                .expect("decode receipt");
        assert_eq!(receipt.receive_path, RECEIVE_PATH_CONNECTION_REQUEST);
    }
}
