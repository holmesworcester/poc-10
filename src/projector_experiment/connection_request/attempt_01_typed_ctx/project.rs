//! Typed-context idiom for the connection_request projector.
//!
//! `project()` reads as English security policy: decode the body, ask `Ctx` for
//! each dependency by name, then call one assertion method per invariant. Every
//! cross-field check is visible at the call site; helper bodies are one-liners.
//!
//! The `Ctx` wrapper hides three things a reader does not need on first read:
//! the canonical `ContextNeed` constructors, the `payload_for` lookup, and the
//! decode-bytes-to-typed-struct step. It also remembers each need it consulted
//! so `ctx.park()` can publish them when a dependency is absent. This park-on-
//! miss shape (rather than collecting all possible needs up front) is required:
//! the invariant battery expects only the invite-secret need when nothing has
//! matched yet, and adds the second need only after the invite is found.

use crate::core::context::ContextNeed;
use crate::core::crypto;
use crate::core::facts::{Fact, FactScope};
use crate::core::intents::AtomicIntent;
use crate::core::projection::{ProjectionContext, ProjectionOutput, Projector};

use crate::event_modules::connection_ephemeral_secret::{
    fact::ConnectionEphemeralSecretFact, layout as ephemeral_layout,
    matchers as ephemeral_matchers,
};
use crate::event_modules::identity_invite::{fact::InviteSecretFact, layout as invite_layout};
use crate::event_modules::transit_received::{
    fact::{TransitReceivedFact, TRANSIT_KIND_BOOTSTRAP},
    layout as receive_layout, matchers as receive_matchers,
};

use crate::event_modules::connection_request::addr::encode_optional_addr;
use crate::event_modules::connection_request::fact::ConnectionRequestFact;
use crate::event_modules::connection_request::layout;
use crate::event_modules::connection_request::matchers;
use crate::event_modules::connection_request::rows::connection_request_row;

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
        projection_context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        if !matches!(fact.scope, FactScope::Local | FactScope::Global) {
            return Err("connection request fact must be local or global".to_string());
        }
        let request = layout::decode_fact(&fact.bytes)?;
        check_request_body(&request)?;

        let mut ctx = Ctx::new(fact, projection_context);

        // 1. Invite-secret authorization (both local and global paths).
        let Some(invite) = ctx.invite_secret(request.invite_secret_event_id)? else {
            return Ok(ctx.park());
        };
        invite.scope_is_local()?;
        invite.bootstrap_hash_matches(&request)?;
        invite.invite_event_id_matches(&request)?;
        invite.signature_verifies(&request)?;

        // 2. Branch on scope: local needs the initiator's ephemeral secret;
        //    global needs the bootstrap receive provenance. The opening
        //    scope check above already rejected anything else.
        if fact.scope == FactScope::Local {
            let Some(ephemeral) =
                ctx.ephemeral_secret(request.initiator_ephemeral_secret_event_id)?
            else {
                return Ok(ctx.park());
            };
            ephemeral.scope_is_local()?;
            ephemeral.owner_matches(&request)?;
            ephemeral.public_key_matches(&request)?;
        } else {
            let Some(receive) = ctx.transit_received()? else {
                return Ok(ctx.park());
            };
            receive.scope_is_local()?;
            receive.targets_this_fact()?;
            receive.kind_is_bootstrap()?;
            receive.delivered_to(request.to_endpoint)?;
            receive.sent_by(request.from_endpoint)?;
            receive.request_id_matches_or_absent()?;
        }

        materialize(fact.id, &request)
    }
}

// ---- request body checks -----------------------------------------------------

fn check_request_body(request: &ConnectionRequestFact) -> Result<(), String> {
    let zero = [0u8; 32];
    if request.from_endpoint == zero {
        return Err("connection request from_endpoint cannot be empty".to_string());
    }
    if request.to_endpoint == zero {
        return Err("connection request to_endpoint cannot be empty".to_string());
    }
    if request.invite_event_id == zero {
        return Err("connection request invite_event_id cannot be empty".to_string());
    }
    if request.bootstrap_hash == zero {
        return Err("connection request bootstrap_hash cannot be empty".to_string());
    }
    if request.invite_secret_event_id == zero {
        return Err("connection request invite_secret_event_id cannot be empty".to_string());
    }
    if request.initiator_ephemeral_secret_event_id == zero {
        return Err(
            "connection request initiator_ephemeral_secret_event_id cannot be empty".to_string(),
        );
    }
    if request.initiator_ephemeral_public_key == zero {
        return Err(
            "connection request initiator_ephemeral_public_key cannot be empty".to_string(),
        );
    }
    if request.from_endpoint == request.to_endpoint {
        return Err("connection request endpoints must differ".to_string());
    }
    Ok(())
}

// ---- typed context wrapper ---------------------------------------------------
//
// `Ctx` is purely a discovery helper: each accessor builds the canonical
// `ContextNeed`, remembers it, and either returns a decoded payload or `None`.
// If a dependency is absent the projector parks by handing every consulted
// need to `ctx.park()`. The returned `Found<T>` exposes one assertion method
// per invariant so each policy line at the call site reads on its own.

struct Ctx<'a> {
    fact: &'a Fact,
    pcx: &'a ProjectionContext,
    consulted: Vec<ContextNeed>,
}

impl<'a> Ctx<'a> {
    fn new(fact: &'a Fact, pcx: &'a ProjectionContext) -> Self {
        Self {
            fact,
            pcx,
            consulted: Vec::new(),
        }
    }

    fn invite_secret(
        &mut self,
        invite_secret_event_id: [u8; 32],
    ) -> Result<Option<FoundInvite<'a>>, String> {
        let need = matchers::invite_secret_need(self.fact.id, invite_secret_event_id);
        self.consulted.push(need.clone());
        let Some(payload) = self.pcx.payload_for(&need) else {
            return Ok(None);
        };
        let secret = invite_layout::decode_fact(&payload.bytes)
            .map_err(|_| "connection request invite context is not an invite secret".to_string())?;
        if payload.id != invite_secret_event_id {
            return Err("connection request invite context id does not match request".to_string());
        }
        Ok(Some(FoundInvite { payload, secret }))
    }

    fn ephemeral_secret(
        &mut self,
        ephemeral_secret_event_id: [u8; 32],
    ) -> Result<Option<FoundEphemeral<'a>>, String> {
        let need = ephemeral_matchers::connection_ephemeral_secret_need(
            self.fact.id,
            ephemeral_secret_event_id,
        );
        self.consulted.push(need.clone());
        let Some(payload) = self.pcx.payload_for(&need) else {
            return Ok(None);
        };
        let secret = ephemeral_layout::decode_fact(&payload.bytes)
            .map_err(|_| "connection request dependency is not an ephemeral secret".to_string())?;
        if payload.id != ephemeral_secret_event_id {
            return Err(
                "connection request ephemeral context id does not match request".to_string(),
            );
        }
        Ok(Some(FoundEphemeral { payload, secret }))
    }

    fn transit_received(&mut self) -> Result<Option<FoundReceive<'a>>, String> {
        let need = receive_matchers::transit_received_need(self.fact.id, self.fact.id);
        self.consulted.push(need.clone());
        let Some(payload) = self.pcx.payload_for(&need) else {
            return Ok(None);
        };
        let receive = receive_layout::decode_fact(&payload.bytes).map_err(|_| {
            "connection request receive context is not transit provenance".to_string()
        })?;
        Ok(Some(FoundReceive {
            payload,
            receive,
            request_fact_id: self.fact.id,
        }))
    }

    fn park(self) -> ProjectionOutput {
        let mut output = ProjectionOutput::new();
        for need in self.consulted {
            output = output.need(need);
        }
        output
    }
}

// ---- found-payload typed accessors ------------------------------------------

struct FoundInvite<'a> {
    payload: &'a Fact,
    secret: InviteSecretFact,
}

impl FoundInvite<'_> {
    fn scope_is_local(&self) -> Result<(), String> {
        if self.payload.scope != FactScope::Local {
            return Err("connection request invite context must be local".to_string());
        }
        Ok(())
    }

    fn bootstrap_hash_matches(&self, request: &ConnectionRequestFact) -> Result<(), String> {
        if self.secret.bootstrap_hash != request.bootstrap_hash {
            return Err("connection request bootstrap hash is not authorized".to_string());
        }
        Ok(())
    }

    fn invite_event_id_matches(&self, request: &ConnectionRequestFact) -> Result<(), String> {
        if let Some(scoped_invite_id) = self.secret.invite_event_id {
            if scoped_invite_id != request.invite_event_id {
                return Err("connection request invite id is not authorized".to_string());
            }
        }
        Ok(())
    }

    fn signature_verifies(&self, request: &ConnectionRequestFact) -> Result<(), String> {
        let public_key = crypto::ed25519_public_key(&self.secret.bootstrap_secret);
        if !crypto::ed25519_verify(
            &public_key,
            &invite_signing_transcript(request)?,
            &request.invite_signature,
        ) {
            return Err("connection request invite signature is not authorized".to_string());
        }
        Ok(())
    }
}

struct FoundEphemeral<'a> {
    payload: &'a Fact,
    secret: ConnectionEphemeralSecretFact,
}

impl FoundEphemeral<'_> {
    fn scope_is_local(&self) -> Result<(), String> {
        if self.payload.scope != FactScope::Local {
            return Err("connection request ephemeral context must be local".to_string());
        }
        Ok(())
    }

    fn owner_matches(&self, request: &ConnectionRequestFact) -> Result<(), String> {
        if self.secret.owner_endpoint != request.from_endpoint {
            return Err("connection request ephemeral owner does not match sender".to_string());
        }
        Ok(())
    }

    fn public_key_matches(&self, request: &ConnectionRequestFact) -> Result<(), String> {
        if self.secret.ephemeral_public_key != request.initiator_ephemeral_public_key {
            return Err(
                "connection request ephemeral public key does not match dependency".to_string(),
            );
        }
        Ok(())
    }
}

struct FoundReceive<'a> {
    payload: &'a Fact,
    receive: TransitReceivedFact,
    request_fact_id: [u8; 32],
}

impl FoundReceive<'_> {
    fn scope_is_local(&self) -> Result<(), String> {
        if self.payload.scope != FactScope::Local {
            return Err("connection request receive context must be local".to_string());
        }
        Ok(())
    }

    fn targets_this_fact(&self) -> Result<(), String> {
        if self.receive.received_fact_id != self.request_fact_id {
            return Err("connection request receive context targets another fact".to_string());
        }
        Ok(())
    }

    fn kind_is_bootstrap(&self) -> Result<(), String> {
        if self.receive.transit_kind != TRANSIT_KIND_BOOTSTRAP {
            return Err("connection request requires bootstrap receive provenance".to_string());
        }
        Ok(())
    }

    fn delivered_to(&self, expected_endpoint: [u8; 32]) -> Result<(), String> {
        if self.receive.local_endpoint_id != expected_endpoint {
            return Err("connection request addressed to a different endpoint".to_string());
        }
        Ok(())
    }

    fn sent_by(&self, expected_endpoint: [u8; 32]) -> Result<(), String> {
        if self.receive.sender_endpoint_id != expected_endpoint {
            return Err("connection request sender does not match receive sender".to_string());
        }
        Ok(())
    }

    fn request_id_matches_or_absent(&self) -> Result<(), String> {
        if let Some(named) = self.receive.request_id {
            if named != self.request_fact_id {
                return Err(
                    "connection request receive provenance names another request".to_string(),
                );
            }
        }
        Ok(())
    }
}

// ---- output shaping ----------------------------------------------------------

fn materialize(
    request_id: [u8; 32],
    request: &ConnectionRequestFact,
) -> Result<ProjectionOutput, String> {
    Ok(ProjectionOutput::new()
        .offer(matchers::connection_request_offer(request_id, request_id))
        .intent(AtomicIntent::PutRow(connection_request_row(request_id, request)?).into_intent()))
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
