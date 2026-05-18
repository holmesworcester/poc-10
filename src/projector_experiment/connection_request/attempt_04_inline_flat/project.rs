//! Inline-flat connection_request projector.
//!
//! Everything happens top-to-bottom inside `project()`. No helper functions
//! split the logic across scopes: the reader follows a single linear story
//! from decode, through field checks, invite-secret context, signature
//! verification, and finally a `match` on the request scope. Each scope arm
//! validates its dependency context inline, parks on miss with a `let Some
//! (..) else { return Ok(parked) }`, then falls through to a single shared
//! "materialize" block. The signing transcript is rebuilt at the point of
//! verification so the reader never has to chase a helper.

use crate::core::crypto;
use crate::core::facts::{Fact, FactScope};
use crate::core::intents::AtomicIntent;
use crate::core::projection::{ProjectionContext, ProjectionOutput, Projector};

use crate::event_modules::connection_ephemeral_secret::{
    layout as ephemeral_layout, matchers as ephemeral_matchers,
};
use crate::event_modules::connection_request::addr::encode_optional_addr;
use crate::event_modules::connection_request::layout;
use crate::event_modules::connection_request::matchers;
use crate::event_modules::connection_request::rows::connection_request_row;
use crate::event_modules::identity_invite::layout as invite_layout;
use crate::event_modules::transit_received::{
    fact::TRANSIT_KIND_BOOTSTRAP, layout as receive_layout, matchers as receive_matchers,
};

#[derive(Debug, Clone, Default)]
pub struct ConnectionRequestProjector;

impl ConnectionRequestProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for ConnectionRequestProjector {
    fn project(
        &self,
        fact: &Fact,
        ctx: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        // 1. Decode and field-check the canonical body. (The match on
        //    `fact.scope` further down also rejects any unsupported scope.)
        let request = layout::decode_fact(&fact.bytes)?;
        if request.from_endpoint == [0; 32] {
            return Err("connection request from_endpoint cannot be empty".to_string());
        }
        if request.to_endpoint == [0; 32] {
            return Err("connection request to_endpoint cannot be empty".to_string());
        }
        if request.invite_event_id == [0; 32] {
            return Err("connection request invite_event_id cannot be empty".to_string());
        }
        if request.bootstrap_hash == [0; 32] {
            return Err("connection request bootstrap_hash cannot be empty".to_string());
        }
        if request.invite_secret_event_id == [0; 32] {
            return Err("connection request invite_secret_event_id cannot be empty".to_string());
        }
        if request.initiator_ephemeral_secret_event_id == [0; 32] {
            return Err("connection request initiator_ephemeral_secret_event_id cannot be empty".to_string());
        }
        if request.initiator_ephemeral_public_key == [0; 32] {
            return Err("connection request initiator_ephemeral_public_key cannot be empty".to_string());
        }
        if request.from_endpoint == request.to_endpoint {
            return Err("connection request endpoints must differ".to_string());
        }

        // 2. Always need the invite secret. Park if it has not arrived yet.
        let invite_need = matchers::invite_secret_need(fact.id, request.invite_secret_event_id);
        let Some(invite) = ctx.payload_for(&invite_need) else {
            return Ok(ProjectionOutput::new().need(invite_need));
        };
        let invite_secret = invite_layout::decode_fact(&invite.bytes)
            .map_err(|_| "connection request invite context is not an invite secret".to_string())?;
        if invite.id != request.invite_secret_event_id {
            return Err("connection request invite context id does not match request".to_string());
        }
        if invite.scope != FactScope::Local {
            return Err("connection request invite context must be local".to_string());
        }
        if invite_secret.bootstrap_hash != request.bootstrap_hash {
            return Err("connection request bootstrap hash is not authorized".to_string());
        }
        if let Some(invite_event_id) = invite_secret.invite_event_id {
            if invite_event_id != request.invite_event_id {
                return Err("connection request invite id is not authorized".to_string());
            }
        }

        // 3. Verify the invite signature against the canonical transcript.
        let mut transcript = Vec::new();
        transcript.extend_from_slice(b"topo-connection-request-invite-signing-transcript-v1");
        transcript.extend_from_slice(&request.from_endpoint);
        transcript.extend_from_slice(&request.to_endpoint);
        transcript.extend_from_slice(&request.nonce);
        transcript.extend_from_slice(&request.invite_event_id);
        transcript.extend_from_slice(&request.bootstrap_hash);
        transcript.extend_from_slice(&request.invite_secret_event_id);
        transcript.extend_from_slice(&request.initiator_ephemeral_secret_event_id);
        transcript.extend_from_slice(&request.initiator_ephemeral_public_key);
        transcript.extend_from_slice(&encode_optional_addr(request.from_listen_addr)?);
        transcript.extend_from_slice(&encode_optional_addr(request.to_listen_addr)?);
        let invite_public_key = crypto::ed25519_public_key(&invite_secret.bootstrap_secret);
        if !crypto::ed25519_verify(&invite_public_key, &transcript, &request.invite_signature) {
            return Err("connection request invite signature is not authorized".to_string());
        }

        // 4. Branch on scope. Local requests we issued need our initiator
        //    ephemeral secret; global requests we received need transit
        //    receive provenance. Any other scope is a category error.
        match fact.scope {
            FactScope::Local => {
                let ephemeral_need = ephemeral_matchers::connection_ephemeral_secret_need(
                    fact.id,
                    request.initiator_ephemeral_secret_event_id,
                );
                let Some(ephemeral) = ctx.payload_for(&ephemeral_need) else {
                    return Ok(ProjectionOutput::new().need(invite_need).need(ephemeral_need));
                };
                let ephemeral_secret = ephemeral_layout::decode_fact(&ephemeral.bytes)
                    .map_err(|_| "connection request dependency is not an ephemeral secret".to_string())?;
                if ephemeral.id != request.initiator_ephemeral_secret_event_id {
                    return Err("connection request ephemeral context id does not match request".to_string());
                }
                if ephemeral.scope != FactScope::Local {
                    return Err("connection request ephemeral context must be local".to_string());
                }
                if ephemeral_secret.owner_endpoint != request.from_endpoint {
                    return Err("connection request ephemeral owner does not match sender".to_string());
                }
                if ephemeral_secret.ephemeral_public_key != request.initiator_ephemeral_public_key {
                    return Err("connection request ephemeral public key does not match dependency".to_string());
                }
            }
            FactScope::Global => {
                let receive_need = receive_matchers::transit_received_need(fact.id, fact.id);
                let Some(receive) = ctx.payload_for(&receive_need) else {
                    return Ok(ProjectionOutput::new().need(invite_need).need(receive_need));
                };
                if receive.scope != FactScope::Local {
                    return Err("connection request receive context must be local".to_string());
                }
                let received = receive_layout::decode_fact(&receive.bytes)
                    .map_err(|_| "connection request receive context is not transit provenance".to_string())?;
                if received.received_fact_id != fact.id {
                    return Err("connection request receive context targets another fact".to_string());
                }
                if received.transit_kind != TRANSIT_KIND_BOOTSTRAP {
                    return Err("connection request requires bootstrap receive provenance".to_string());
                }
                if received.local_endpoint_id != request.to_endpoint {
                    return Err("connection request addressed to a different endpoint".to_string());
                }
                if received.sender_endpoint_id != request.from_endpoint {
                    return Err("connection request sender does not match receive sender".to_string());
                }
                if let Some(request_id) = received.request_id {
                    if request_id != fact.id {
                        return Err("connection request receive provenance names another request".to_string());
                    }
                }
            }
            _ => return Err("connection request fact must be local or global".to_string()),
        }

        // 5. All dependencies validated: publish the request offer and emit
        //    the put_row intent that records the materialized request.
        let row = connection_request_row(fact.id, &request)?;
        Ok(ProjectionOutput::new()
            .offer(matchers::connection_request_offer(fact.id, fact.id))
            .intent(AtomicIntent::PutRow(row).into_intent()))
    }
}
