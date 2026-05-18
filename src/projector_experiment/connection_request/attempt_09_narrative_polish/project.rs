//! Connection-request projector, written as a narrated security policy.
//!
//! POLICY. A connection_request is admitted iff:
//!   1. STRUCTURAL.   Bytes decode; every selector field is non-zero;
//!                    from_endpoint != to_endpoint.
//!   2. INVITE.       The named invite_secret is present (else park), its
//!                    fact id and local scope match the request's claim, its
//!                    bootstrap_hash matches, and if the invite is bound to
//!                    a particular invite_event_id, that matches too.
//!   3. SIGNATURE.    invite_signature verifies under the invite's bootstrap
//!                    key over the canonical transcript.
//!   4. DEPENDENCY.   LOCAL  -- we hold the named initiator ephemeral secret
//!                               (local, owner = from_endpoint, public key
//!                               matches the request).
//!                    GLOBAL -- local transit-receive provenance names this
//!                               exact fact (kind = bootstrap, addressed to
//!                               to_endpoint, sent by from_endpoint, and if
//!                               it names a request, names this one).
//!                    Missing context parks; mismatched context rejects.
//!   5. MATERIALIZE.  Publish the offer and emit the put_row intent.
//!
//! Read the policy, then confirm `project()` has one section per rule. Rule
//! text lives only here; the body uses bare markers `// 1.` .. `// 5.` that
//! index back. `?` carries rejection; parking is `Ok(NeedSet::park())`.

use crate::core::crypto;
use crate::core::facts::{Fact, FactScope};
use crate::core::intents::AtomicIntent;
use crate::core::projection::{ProjectionContext, ProjectionOutput, Projector};

use crate::event_modules::connection_ephemeral_secret::{
    layout as ephemeral_layout, matchers as ephemeral_matchers,
};
use crate::event_modules::connection_request::{
    addr::encode_optional_addr, layout, matchers, rows::connection_request_row,
};
use crate::event_modules::identity_invite::layout as invite_layout;
use crate::event_modules::transit_received::{
    fact::TRANSIT_KIND_BOOTSTRAP, layout as receive_layout, matchers as receive_matchers,
};

use crate::projector_experiment::checks::{is_zero32, require, NeedSet};

#[derive(Debug, Clone, Default)]
pub struct ConnectionRequestProjector;

impl ConnectionRequestProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for ConnectionRequestProjector {
    fn project(&self, fact: &Fact, ctx: &ProjectionContext) -> Result<ProjectionOutput, String> {
        // 1. Structural.
        let request = layout::decode_fact(&fact.bytes)?;
        require(!is_zero32(&request.from_endpoint),
            "connection request from_endpoint cannot be empty")?;
        require(!is_zero32(&request.to_endpoint),
            "connection request to_endpoint cannot be empty")?;
        require(!is_zero32(&request.invite_event_id),
            "connection request invite_event_id cannot be empty")?;
        require(!is_zero32(&request.bootstrap_hash),
            "connection request bootstrap_hash cannot be empty")?;
        require(!is_zero32(&request.invite_secret_event_id),
            "connection request invite_secret_event_id cannot be empty")?;
        require(!is_zero32(&request.initiator_ephemeral_secret_event_id),
            "connection request initiator_ephemeral_secret_event_id cannot be empty")?;
        require(!is_zero32(&request.initiator_ephemeral_public_key),
            "connection request initiator_ephemeral_public_key cannot be empty")?;
        require(request.from_endpoint != request.to_endpoint,
            "connection request endpoints must differ")?;

        // 2. Invite.
        let mut needs = NeedSet::new();
        let invite_need = matchers::invite_secret_need(fact.id, request.invite_secret_event_id);
        needs.add(invite_need.clone());
        let Some(invite) = ctx.payload_for(&invite_need) else {
            return Ok(needs.park());
        };
        let invite_secret = invite_layout::decode_fact(&invite.bytes)
            .map_err(|_| "connection request invite context is not an invite secret".to_string())?;
        require(invite.id == request.invite_secret_event_id,
            "connection request invite context id does not match request")?;
        require(invite.scope == FactScope::Local,
            "connection request invite context must be local")?;
        require(invite_secret.bootstrap_hash == request.bootstrap_hash,
            "connection request bootstrap hash is not authorized")?;
        require(invite_secret.invite_event_id.map_or(true, |id| id == request.invite_event_id),
            "connection request invite id is not authorized")?;

        // 3. Signature.
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
        require(crypto::ed25519_verify(&invite_public_key, &transcript, &request.invite_signature),
            "connection request invite signature is not authorized")?;

        // 4. Dependency.
        match fact.scope {
            FactScope::Local => {
                let ephemeral_need = ephemeral_matchers::connection_ephemeral_secret_need(
                    fact.id, request.initiator_ephemeral_secret_event_id);
                needs.add(ephemeral_need.clone());
                let Some(ephemeral) = ctx.payload_for(&ephemeral_need) else {
                    return Ok(needs.park());
                };
                let secret = ephemeral_layout::decode_fact(&ephemeral.bytes).map_err(|_|
                    "connection request dependency is not an ephemeral secret".to_string())?;
                require(ephemeral.id == request.initiator_ephemeral_secret_event_id,
                    "connection request ephemeral context id does not match request")?;
                require(ephemeral.scope == FactScope::Local,
                    "connection request ephemeral context must be local")?;
                require(secret.owner_endpoint == request.from_endpoint,
                    "connection request ephemeral owner does not match sender")?;
                require(secret.ephemeral_public_key == request.initiator_ephemeral_public_key,
                    "connection request ephemeral public key does not match dependency")?;
            }
            FactScope::Global => {
                let receive_need = receive_matchers::transit_received_need(fact.id, fact.id);
                needs.add(receive_need.clone());
                let Some(receive) = ctx.payload_for(&receive_need) else {
                    return Ok(needs.park());
                };
                require(receive.scope == FactScope::Local,
                    "connection request receive context must be local")?;
                let received = receive_layout::decode_fact(&receive.bytes).map_err(|_|
                    "connection request receive context is not transit provenance".to_string())?;
                require(received.received_fact_id == fact.id,
                    "connection request receive context targets another fact")?;
                require(received.transit_kind == TRANSIT_KIND_BOOTSTRAP,
                    "connection request requires bootstrap receive provenance")?;
                require(received.local_endpoint_id == request.to_endpoint,
                    "connection request addressed to a different endpoint")?;
                require(received.sender_endpoint_id == request.from_endpoint,
                    "connection request sender does not match receive sender")?;
                require(received.request_id.map_or(true, |id| id == fact.id),
                    "connection request receive provenance names another request")?;
            }
            _ => return Err("connection request fact must be local or global".to_string()),
        }

        // 5. Materialize.
        Ok(ProjectionOutput::new()
            .offer(matchers::connection_request_offer(fact.id, fact.id))
            .intent(AtomicIntent::PutRow(connection_request_row(fact.id, &request)?).into_intent()))
    }
}
