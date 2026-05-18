//! Declarative connection-request projector.
//!
//! Read `project()` top-to-bottom as a checklist. The structural non-zero
//! field surface is the small data table `REQUIRED_FIELDS`; everything else
//! is a single line of prose per invariant. Each `?` boundary is one rule.
//! No runtime interpreter: the projector *is* the spec.

use crate::core::context::ContextNeed;
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

/// Each entry: a name (used in the error message) and the 32-byte field that
/// must not be all zero. Errors read "connection request <name> cannot be empty".
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
        // 1. Decode the request body, then enforce structural invariants.
        if !matches!(fact.scope, FactScope::Local | FactScope::Global) {
            return Err("connection request fact must be local or global".to_string());
        }
        let request = layout::decode_fact(&fact.bytes)?;
        for (name, field) in REQUIRED_FIELDS {
            require_nonzero(name, field(&request))?;
        }
        require(
            request.from_endpoint != request.to_endpoint,
            "connection request endpoints must differ",
        )?;

        // 2. The invite secret is the always-required context payload. If it
        //    has not been matched yet we park on its need.
        let invite_need = matchers::invite_secret_need(fact.id, request.invite_secret_event_id);
        let Some(invite) = ctx.payload_for(&invite_need) else {
            return Ok(park(vec![invite_need]));
        };
        let invite_secret = invite_layout::decode_fact(&invite.bytes)
            .map_err(|_| "connection request invite context is not an invite secret".to_string())?;
        require(invite.id == request.invite_secret_event_id,
            "connection request invite context id does not match request")?;
        require(invite.scope == FactScope::Local,
            "connection request invite context must be local")?;
        require(invite_secret.bootstrap_hash == request.bootstrap_hash,
            "connection request bootstrap hash is not authorized")?;
        require(
            invite_secret.invite_event_id.map_or(true, |id| id == request.invite_event_id),
            "connection request invite id is not authorized",
        )?;
        let public_key = crypto::ed25519_public_key(&invite_secret.bootstrap_secret);
        require(
            crypto::ed25519_verify(
                &public_key,
                &invite_signing_transcript(&request)?,
                &request.invite_signature,
            ),
            "connection request invite signature is not authorized",
        )?;

        // 3. Second dependency depends on scope:
        //    - Local request   : the initiator's ephemeral secret (also local).
        //    - Global request  : local transit-received provenance for this fact.
        if fact.scope == FactScope::Local {
            let need = ephemeral_matchers::connection_ephemeral_secret_need(
                fact.id, request.initiator_ephemeral_secret_event_id);
            let Some(ephemeral) = ctx.payload_for(&need) else {
                return Ok(park(vec![invite_need, need]));
            };
            let secret = ephemeral_layout::decode_fact(&ephemeral.bytes)
                .map_err(|_| "connection request dependency is not an ephemeral secret".to_string())?;
            require(ephemeral.id == request.initiator_ephemeral_secret_event_id,
                "connection request ephemeral context id does not match request")?;
            require(ephemeral.scope == FactScope::Local,
                "connection request ephemeral context must be local")?;
            require(secret.owner_endpoint == request.from_endpoint,
                "connection request ephemeral owner does not match sender")?;
            require(secret.ephemeral_public_key == request.initiator_ephemeral_public_key,
                "connection request ephemeral public key does not match dependency")?;
        } else {
            let need = receive_matchers::transit_received_need(fact.id, fact.id);
            let Some(receive) = ctx.payload_for(&need) else {
                return Ok(park(vec![invite_need, need]));
            };
            require(receive.scope == FactScope::Local,
                "connection request receive context must be local")?;
            let received = receive_layout::decode_fact(&receive.bytes)
                .map_err(|_| "connection request receive context is not transit provenance".to_string())?;
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

        // 4. All invariants satisfied: emit the projection row and the offer.
        Ok(ProjectionOutput::new()
            .offer(matchers::connection_request_offer(fact.id, fact.id))
            .intent(AtomicIntent::PutRow(connection_request_row(fact.id, &request)?).into_intent()))
    }
}

// ----- micro-helpers: turn an invariant into a `?`-friendly call ----------

fn require(condition: bool, error: &str) -> Result<(), String> {
    if condition { Ok(()) } else { Err(error.to_string()) }
}

fn require_nonzero(name: &str, field: &[u8; 32]) -> Result<(), String> {
    if field == &[0; 32] {
        return Err(format!("connection request {name} cannot be empty"));
    }
    Ok(())
}

fn park(needs: Vec<ContextNeed>) -> ProjectionOutput {
    let mut out = ProjectionOutput::new();
    for need in needs {
        out = out.need(need);
    }
    out
}

fn invite_signing_transcript(request: &ConnectionRequestFact) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    out.extend_from_slice(b"topo-connection-request-invite-signing-transcript-v1");
    out.extend_from_slice(&request.from_endpoint);
    out.extend_from_slice(&request.to_endpoint);
    out.extend_from_slice(&request.nonce);
    out.extend_from_slice(&request.invite_event_id);
    out.extend_from_slice(&request.bootstrap_hash);
    out.extend_from_slice(&request.invite_secret_event_id);
    out.extend_from_slice(&request.initiator_ephemeral_secret_event_id);
    out.extend_from_slice(&request.initiator_ephemeral_public_key);
    out.extend_from_slice(&encode_optional_addr(request.from_listen_addr)?);
    out.extend_from_slice(&encode_optional_addr(request.to_listen_addr)?);
    Ok(out)
}
