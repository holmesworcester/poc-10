//! Hybrid connection-request projector: inline-flat shape, declarative compressions.
//!
//! Read `project()` as a numbered top-to-bottom recipe. The shape is borrowed
//! from `attempt_04_inline_flat` (single function, `match fact.scope` for
//! dispatch, transcript built at the verification site), and the structural
//! non-zero surface is compressed into a `REQUIRED_FIELDS` table plus a
//! `require(cond, msg)?` micro-helper, both borrowed from
//! `attempt_03_declarative`. The result: every invariant is one line of prose
//! near the line that uses its result, no helper hides what is being signed.

use crate::core::crypto;
use crate::core::facts::{Fact, FactScope};
use crate::core::intents::AtomicIntent;
use crate::core::projection::{ProjectionContext, ProjectionOutput, Projector};

use crate::event_modules::connection_ephemeral_secret::{
    layout as ephemeral_layout, matchers as ephemeral_matchers,
};
use crate::event_modules::connection_request::{
    addr::encode_optional_addr, fact::ConnectionRequestFact, layout, matchers,
    rows::connection_request_row,
};
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

/// Each request body field that must not be all-zero. The name is interpolated
/// into "connection request <name> cannot be empty".
const REQUIRED_FIELDS: &[(&str, fn(&ConnectionRequestFact) -> &[u8; 32])] = &[
    ("from_endpoint",                       |r| &r.from_endpoint),
    ("to_endpoint",                         |r| &r.to_endpoint),
    ("invite_event_id",                     |r| &r.invite_event_id),
    ("bootstrap_hash",                      |r| &r.bootstrap_hash),
    ("invite_secret_event_id",              |r| &r.invite_secret_event_id),
    ("initiator_ephemeral_secret_event_id", |r| &r.initiator_ephemeral_secret_event_id),
    ("initiator_ephemeral_public_key",      |r| &r.initiator_ephemeral_public_key),
];

impl Projector for ConnectionRequestProjector {
    fn project(&self, fact: &Fact, ctx: &ProjectionContext) -> Result<ProjectionOutput, String> {
        // 1. Decode the canonical body and enforce structural invariants.
        let request = layout::decode_fact(&fact.bytes)?;
        for (name, field) in REQUIRED_FIELDS {
            require(field(&request) != &[0; 32], &format!("connection request {name} cannot be empty"))?;
        }
        require(request.from_endpoint != request.to_endpoint,
            "connection request endpoints must differ")?;

        // 2. Park until the invite secret has been matched, then validate it.
        let invite_need = matchers::invite_secret_need(fact.id, request.invite_secret_event_id);
        let Some(invite) = ctx.payload_for(&invite_need) else {
            return Ok(ProjectionOutput::new().need(invite_need));
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

        // 3. Verify the invite signature. Transcript is built inline so the
        //    reader sees exactly which bytes get signed.
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

        // 4. Branch on scope: local requests bind to our initiator ephemeral
        //    secret; global requests bind to local transit-receive provenance.
        match fact.scope {
            FactScope::Local => {
                let ephemeral_need = ephemeral_matchers::connection_ephemeral_secret_need(
                    fact.id, request.initiator_ephemeral_secret_event_id);
                let Some(ephemeral) = ctx.payload_for(&ephemeral_need) else {
                    return Ok(ProjectionOutput::new().need(invite_need).need(ephemeral_need));
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
                let Some(receive) = ctx.payload_for(&receive_need) else {
                    return Ok(ProjectionOutput::new().need(invite_need).need(receive_need));
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

        // 5. All dependencies are satisfied: publish the offer and emit the row.
        Ok(ProjectionOutput::new()
            .offer(matchers::connection_request_offer(fact.id, fact.id))
            .intent(AtomicIntent::PutRow(connection_request_row(fact.id, &request)?).into_intent()))
    }
}

/// Turn one boolean invariant into a `?`-friendly call. Reads like a spec line.
fn require(condition: bool, error: &str) -> Result<(), String> {
    if condition { Ok(()) } else { Err(error.to_string()) }
}
