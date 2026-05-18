//! Connection-request projector, variant-typed.
//!
//! The single in-band signal `fact.scope == Local` decides whether this
//! projector is handling a request the local node just authored or one that
//! arrived over the wire. That fork drives two completely different sets of
//! context needs and provenance checks, so we promote it from a field test to
//! a typed value: `RequestOrigin`.
//!
//! `project()` reads top-to-bottom: decode, field shape, signature, then a
//! single `match` whose arms each lay out the rest of the policy for one
//! origin. Nothing flips behavior behind the scenes; every check that fires
//! for a given request is visible in the arm that owns it.

use crate::core::crypto;
use crate::core::facts::{Fact, FactScope};
use crate::core::intents::AtomicIntent;
use crate::core::projection::{ProjectionContext, ProjectionOutput, Projector};

use crate::event_modules::connection_ephemeral_secret::{
    layout as ephemeral_layout, matchers as ephemeral_matchers,
};
use crate::event_modules::identity_invite::layout as invite_layout;
use crate::event_modules::transit_received::{
    fact::TRANSIT_KIND_BOOTSTRAP, layout as receive_layout, matchers as receive_matchers,
};

use crate::event_modules::connection_request::addr::encode_optional_addr;
use crate::event_modules::connection_request::fact::{ConnectionRequestFact, EventId};
use crate::event_modules::connection_request::layout;
use crate::event_modules::connection_request::matchers;
use crate::event_modules::connection_request::rows::connection_request_row;

/// Which kind of bootstrap request this fact is, lifted out of `fact.scope`.
///
/// Every additional check beyond field shape and signature is owned by exactly
/// one variant, so `match` exhaustiveness is the only thing keeping the two
/// policies separate.
enum RequestOrigin {
    /// Local node authored this request. Must name its own ephemeral secret.
    LocalInitiator,
    /// Received from the network. Must come with transit receive provenance
    /// addressed to this node and tagged as bootstrap.
    ReceivedFromNetwork,
}

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
        let origin = match fact.scope {
            FactScope::Local => RequestOrigin::LocalInitiator,
            FactScope::Global => RequestOrigin::ReceivedFromNetwork,
            _ => return Err("connection request fact must be local or global".to_string()),
        };
        let request = layout::decode_fact(&fact.bytes)?;

        // Shape checks — same for both origins.
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
            return Err(
                "connection request initiator_ephemeral_secret_event_id cannot be empty".to_string(),
            );
        }
        if request.initiator_ephemeral_public_key == [0; 32] {
            return Err(
                "connection request initiator_ephemeral_public_key cannot be empty".to_string(),
            );
        }
        if request.from_endpoint == request.to_endpoint {
            return Err("connection request endpoints must differ".to_string());
        }

        // Invite-secret context — same for both origins.
        let invite_need = matchers::invite_secret_need(fact.id, request.invite_secret_event_id);
        let Some(invite_payload) = ctx.payload_for(&invite_need) else {
            return Ok(park(&[invite_need]));
        };
        let invite_secret = invite_layout::decode_fact(&invite_payload.bytes)
            .map_err(|_| "connection request invite context is not an invite secret".to_string())?;
        if invite_payload.id != request.invite_secret_event_id {
            return Err("connection request invite context id does not match request".to_string());
        }
        if invite_payload.scope != FactScope::Local {
            return Err("connection request invite context must be local".to_string());
        }
        if invite_secret.bootstrap_hash != request.bootstrap_hash {
            return Err("connection request bootstrap hash is not authorized".to_string());
        }
        if let Some(scoped) = invite_secret.invite_event_id {
            if scoped != request.invite_event_id {
                return Err("connection request invite id is not authorized".to_string());
            }
        }
        if !crypto::ed25519_verify(
            &crypto::ed25519_public_key(&invite_secret.bootstrap_secret),
            &invite_signing_transcript(&request)?,
            &request.invite_signature,
        ) {
            return Err("connection request invite signature is not authorized".to_string());
        }

        // Origin-specific dependency: each arm owns its remaining policy.
        match origin {
            RequestOrigin::LocalInitiator => {
                let ephemeral_need = ephemeral_matchers::connection_ephemeral_secret_need(
                    fact.id,
                    request.initiator_ephemeral_secret_event_id,
                );
                let Some(ephemeral_payload) = ctx.payload_for(&ephemeral_need) else {
                    return Ok(park(&[invite_need, ephemeral_need]));
                };
                let ephemeral = ephemeral_layout::decode_fact(&ephemeral_payload.bytes)
                    .map_err(|_| {
                        "connection request dependency is not an ephemeral secret".to_string()
                    })?;
                if ephemeral_payload.id != request.initiator_ephemeral_secret_event_id {
                    return Err(
                        "connection request ephemeral context id does not match request".to_string(),
                    );
                }
                if ephemeral_payload.scope != FactScope::Local {
                    return Err("connection request ephemeral context must be local".to_string());
                }
                if ephemeral.owner_endpoint != request.from_endpoint {
                    return Err(
                        "connection request ephemeral owner does not match sender".to_string(),
                    );
                }
                if ephemeral.ephemeral_public_key != request.initiator_ephemeral_public_key {
                    return Err(
                        "connection request ephemeral public key does not match dependency".to_string(),
                    );
                }
                materialize(fact.id, &request)
            }
            RequestOrigin::ReceivedFromNetwork => {
                let receive_need = receive_matchers::transit_received_need(fact.id, fact.id);
                let Some(receive_payload) = ctx.payload_for(&receive_need) else {
                    return Ok(park(&[invite_need, receive_need]));
                };
                if receive_payload.scope != FactScope::Local {
                    return Err("connection request receive context must be local".to_string());
                }
                let received = receive_layout::decode_fact(&receive_payload.bytes)
                    .map_err(|_| {
                        "connection request receive context is not transit provenance".to_string()
                    })?;
                if received.received_fact_id != fact.id {
                    return Err(
                        "connection request receive context targets another fact".to_string(),
                    );
                }
                if received.transit_kind != TRANSIT_KIND_BOOTSTRAP {
                    return Err(
                        "connection request requires bootstrap receive provenance".to_string(),
                    );
                }
                if received.local_endpoint_id != request.to_endpoint {
                    return Err(
                        "connection request addressed to a different endpoint".to_string(),
                    );
                }
                if received.sender_endpoint_id != request.from_endpoint {
                    return Err(
                        "connection request sender does not match receive sender".to_string(),
                    );
                }
                if let Some(named) = received.request_id {
                    if named != fact.id {
                        return Err(
                            "connection request receive provenance names another request".to_string(),
                        );
                    }
                }
                materialize(fact.id, &request)
            }
        }
    }
}

fn park(needs: &[crate::core::context::ContextNeed]) -> ProjectionOutput {
    let mut out = ProjectionOutput::new();
    for need in needs {
        out = out.need(need.clone());
    }
    out
}

fn materialize(
    request_id: EventId,
    request: &ConnectionRequestFact,
) -> Result<ProjectionOutput, String> {
    Ok(ProjectionOutput::new()
        .offer(matchers::connection_request_offer(request_id, request_id))
        .intent(
            AtomicIntent::PutRow(connection_request_row(request_id, request)?).into_intent(),
        ))
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

