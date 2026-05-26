//! Bootstrap-response projector.
//!
//! Bootstrap-response projection is the receive-side bridge from one sealed
//! pre-connection response frame to the durable semantic handshake response. It
//! opens the flat receive fact with the daemon endpoint secret context and
//! emits the canonical `connection_response` fact plus its receipt. The
//! response projector owns request, invite, endpoint, receipt, and handshake
//! validation.
//!
//! POLICY. A `connection_bootstrap_response` fact is admitted iff:
//!   1. STRUCTURAL. The fact is local ephemeral input and its layout contains
//!      exactly one sealed response frame with receive metadata.
//!   2. CONTEXT. The projector needs the singleton local daemon endpoint
//!      context. If it is not already available in the fixed-point pass, the
//!      ephemeral input is discarded with no durable output.
//!   3. MATERIALIZE. Opened response bytes become a durable local
//!      `connection_response` plus response receipt.

use crate::core::crypto;
use crate::core::facts::{Fact, FactScope};
use crate::core::projectors::{
    project_typed, ProjectionContext, ProjectionOutput, Projector, TypedProjector,
};
use crate::protocol::auth::endpoint;
use crate::protocol::connection::frame::create::received_connection_response_fact_effect;

use super::fact::ConnectionBootstrapResponseFact;

#[derive(Debug, Clone, Default)]
pub struct ConnectionBootstrapResponseProjector;

impl ConnectionBootstrapResponseProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for ConnectionBootstrapResponseProjector {
    fn project(
        &self,
        fact: &Fact,
        projection_context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        project_typed::<super::Codec, _>(self, fact, projection_context)
    }
}

impl TypedProjector<super::Codec> for ConnectionBootstrapResponseProjector {
    fn project_typed(
        &self,
        fact: &Fact,
        bootstrap: ConnectionBootstrapResponseFact,
        projection_context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        // 1. Structural.
        if fact.scope != FactScope::Local {
            return Err("connection bootstrap response fact must have local scope".to_string());
        }

        // 2. Context.
        let endpoint_need = endpoint::daemon_endpoint_need(fact.id);
        let Some(endpoint_fact) = projection_context.payload_for(&endpoint_need) else {
            return Ok(ProjectionOutput::new().need(endpoint_need));
        };
        if endpoint_fact.scope != FactScope::Local {
            return Err("connection bootstrap response endpoint context must be local".to_string());
        }
        let local_endpoint = endpoint::decode_fact_payload(endpoint_fact.body()).map_err(|_| {
            "connection bootstrap response endpoint context is not a local endpoint".to_string()
        })?;

        // 3. Materialize.
        let frame = &bootstrap.sealed_response_frame;
        let frame_hash = crypto::hash(frame);
        let Ok(response_bytes) = super::layout::open_connection_response(frame, &local_endpoint)
        else {
            return Ok(ProjectionOutput::new());
        };
        let effects = received_connection_response_fact_effect(
            &response_bytes,
            bootstrap.origin_addr.bytes(),
            bootstrap.received_at_local_ms,
            frame_hash,
        )?;
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
    use crate::core::crypto;
    use crate::core::facts::Fact;
    use crate::core::projectors::{MatchedContext, ProjectionContext};
    use crate::protocol::auth::endpoint::fact::EndpointFact;
    use crate::protocol::connection::fact_receipt::fact::RECEIVE_PATH_CONNECTION_RESPONSE;
    use crate::protocol::connection::response::fact::ConnectionResponseFact;
    use crate::protocol::connection::response::layout as response_layout;

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
    fn sealed_response_projects_to_response_and_receipt_facts() {
        let (endpoint, endpoint_fact) = endpoint_fact([44; 32]);
        let responder_ephemeral_secret = [59; 32];
        let response = ConnectionResponseFact {
            from_endpoint: crypto::x25519_public_key(&[55; 32]),
            to_endpoint: endpoint.endpoint,
            request_id: [56; 32],
            invite_secret_fact_id: [57; 32],
            initiator_ephemeral_secret_fact_id: [58; 32],
            responder_ephemeral_secret_fact_id: [60; 32],
            responder_ephemeral_public_key: crypto::x25519_public_key(&responder_ephemeral_secret),
            handshake_hash: [61; 32],
            connection_secret: [62; 32],
        };
        let response_bytes = response_layout::encode_fact(&response).expect("response");
        let sealed = super::super::layout::seal_connection_response(
            &response_bytes,
            &responder_ephemeral_secret,
        )
        .expect("sealed response");
        let bootstrap = ConnectionBootstrapResponseFact {
            origin_addr: crate::protocol::connection::fact_receipt::fact::OriginAddr::new(
                b"127.0.0.1:41002",
            )
            .expect("origin"),
            received_at_local_ms: 100,
            sealed_response_frame: super::super::layout::copy_sealed_connection_response_frame(
                &sealed,
            )
            .expect("copy frame"),
        };
        let bootstrap_fact = Fact::new(
            FactScope::Local,
            100,
            super::super::layout::encode_fact(&bootstrap).expect("bootstrap"),
        );

        let output = ConnectionBootstrapResponseProjector::new()
            .project(
                &bootstrap_fact,
                &ProjectionContext::from_matches(vec![endpoint_match(
                    bootstrap_fact.id,
                    endpoint_fact,
                )]),
            )
            .expect("project bootstrap response");

        assert_eq!(output.effects.facts.len(), 2);
        assert!(output
            .effects
            .facts
            .iter()
            .any(|fact| fact.bytes == response_bytes));
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
        assert_eq!(receipt.receive_path, RECEIVE_PATH_CONNECTION_RESPONSE);
    }
}
