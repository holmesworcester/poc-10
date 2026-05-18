//! Connection-request projector as a top-down checklist of named operations.
//!
//! `project()` reads as a numbered sequence of English-named steps. A reader
//! who scans only the function body should be able to recover the whole
//! projection policy from the call sites alone. Each step is one helper
//! whose body is ≤ 10 lines and lives directly below — the name is the
//! summary; the body is verifiable at a glance.
//!
//! How needs are collected: a single `NeedSet` accumulates every dependency
//! the projector discovers, in lockstep with the lookups. The reader sees
//!
//!     needs.add(some_need.clone());                                 // declare
//!     let Some(payload) = ctx.payload_for(&some_need) else {        // look up
//!         return Ok(needs.park());                                  // park on miss
//!     };
//!
//! at every fetch site, so the parking story is visible in the projector
//! body itself — no scattered `.need().need()` chains, no ad-hoc vectors
//! built at park sites.
//!
//! Contrast with `attempt_03_declarative` (each rule was an inline
//! `require(cond, msg)?`): here we cluster the related `require`s into
//! policy-verb helpers so the projector body is even shorter while each
//! verb remains inspectable at a glance below.
//!
//! Granularity tried:
//!   * coarser variant (`fetch_invite_secret`, `check_local_branch`,
//!     `check_global_branch` each owning park-or-validate inside) buried
//!     the `needs.add` calls below `project()`, hiding the very thing the
//!     reader most wants to see — discarded.
//!   * finer variant (one helper per `require` line) inflated the named-
//!     function set without helping the call site — discarded.
//!   * the kept variant: clusters at the level of one English clause per
//!     helper (`require_invite_payload_matches_request`,
//!     `require_ephemeral_authorizes_initiator`, ...), and keeps the park
//!     dance in the body where the reader looks for it.

use crate::core::crypto;
use crate::core::facts::{Fact, FactScope};
use crate::core::intents::AtomicIntent;
use crate::core::projection::{ProjectionContext, ProjectionOutput, Projector};
use crate::projector_experiment::checks::{is_zero32, require, NeedSet};

use crate::event_modules::connection_ephemeral_secret::{
    fact::ConnectionEphemeralSecretFact, layout as ephemeral_layout,
    matchers as ephemeral_matchers,
};
use crate::event_modules::connection_request::{
    addr::encode_optional_addr, fact::ConnectionRequestFact, layout, matchers,
    rows::connection_request_row,
};
use crate::event_modules::identity_invite::{fact::InviteSecretFact, layout as invite_layout};
use crate::event_modules::transit_received::{
    fact::{TransitReceivedFact, TRANSIT_KIND_BOOTSTRAP},
    layout as receive_layout, matchers as receive_matchers,
};

#[derive(Debug, Clone, Default)]
pub struct ConnectionRequestProjector;

impl ConnectionRequestProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for ConnectionRequestProjector {
    fn project(&self, fact: &Fact, ctx: &ProjectionContext) -> Result<ProjectionOutput, String> {
        // ===== 1. Structural: decode body and check fields in isolation. =====
        require_scope_is_local_or_global(fact)?;
        let request = layout::decode_fact(&fact.bytes)?;
        require_request_fields_are_all_present(&request)?;
        require_endpoints_differ(&request)?;

        // ===== 2. Invite-secret context: declare the need, park or validate. =====
        let mut needs = NeedSet::new();
        let invite_need = matchers::invite_secret_need(fact.id, request.invite_secret_event_id);
        needs.add(invite_need.clone());
        let Some(invite) = ctx.payload_for(&invite_need) else { return Ok(needs.park()); };
        let invite_secret = decode_invite_payload(invite)?;
        require_invite_payload_matches_request(invite, &invite_secret, &request)?;
        require_invite_signature_verifies(&invite_secret, &request)?;

        // ===== 3. Scope-specific dependency: local needs ephemeral, global needs receipt. =====
        match fact.scope {
            FactScope::Local => {
                let need = ephemeral_matchers::connection_ephemeral_secret_need(
                    fact.id, request.initiator_ephemeral_secret_event_id);
                needs.add(need.clone());
                let Some(payload) = ctx.payload_for(&need) else { return Ok(needs.park()); };
                let ephemeral = decode_ephemeral_payload(payload)?;
                require_ephemeral_authorizes_initiator(payload, &ephemeral, &request)?;
            }
            FactScope::Global => {
                let need = receive_matchers::transit_received_need(fact.id, fact.id);
                needs.add(need.clone());
                let Some(payload) = ctx.payload_for(&need) else { return Ok(needs.park()); };
                require(payload.scope == FactScope::Local,
                    "connection request receive context must be local")?;
                let received = decode_receive_payload(payload)?;
                require_receive_provenance_targets_this_request(&received, &request, fact.id)?;
            }
            FactScope::Scoped { .. } => unreachable!("rejected in step 1"),
        }

        // ===== 4. All dependencies satisfied: emit the offer and the row. =====
        materialized_output(fact.id, &request)
    }
}

// =============================================================================
// Below: one helper per English clause in the checklist above. Each body is
// ≤ 10 lines; the name on the call site is the spec. Helpers are grouped by
// step so a reader can jump directly from a call site to its inspection.
// =============================================================================

// ---- step 1: structural ------------------------------------------------------

fn require_scope_is_local_or_global(fact: &Fact) -> Result<(), String> {
    require(
        matches!(fact.scope, FactScope::Local | FactScope::Global),
        "connection request fact must be local or global",
    )
}

/// Every selector / public-key field of the request must be set (non-zero).
fn require_request_fields_are_all_present(r: &ConnectionRequestFact) -> Result<(), String> {
    require(!is_zero32(&r.from_endpoint), "connection request from_endpoint cannot be empty")?;
    require(!is_zero32(&r.to_endpoint), "connection request to_endpoint cannot be empty")?;
    require(!is_zero32(&r.invite_event_id), "connection request invite_event_id cannot be empty")?;
    require(!is_zero32(&r.bootstrap_hash), "connection request bootstrap_hash cannot be empty")?;
    require(!is_zero32(&r.invite_secret_event_id), "connection request invite_secret_event_id cannot be empty")?;
    require(!is_zero32(&r.initiator_ephemeral_secret_event_id), "connection request initiator_ephemeral_secret_event_id cannot be empty")?;
    require(!is_zero32(&r.initiator_ephemeral_public_key), "connection request initiator_ephemeral_public_key cannot be empty")?;
    Ok(())
}

fn require_endpoints_differ(request: &ConnectionRequestFact) -> Result<(), String> {
    require(
        request.from_endpoint != request.to_endpoint,
        "connection request endpoints must differ",
    )
}

// ---- step 2: invite-secret context -------------------------------------------

fn decode_invite_payload(invite: &Fact) -> Result<InviteSecretFact, String> {
    invite_layout::decode_fact(&invite.bytes)
        .map_err(|_| "connection request invite context is not an invite secret".to_string())
}

/// The invite payload supplied by context must be the one the request named.
/// Covers wrapper checks (id, scope) and body checks (hash, optional scope-binding).
fn require_invite_payload_matches_request(
    invite: &Fact,
    secret: &InviteSecretFact,
    request: &ConnectionRequestFact,
) -> Result<(), String> {
    require(invite.id == request.invite_secret_event_id,
        "connection request invite context id does not match request")?;
    require(invite.scope == FactScope::Local,
        "connection request invite context must be local")?;
    require(secret.bootstrap_hash == request.bootstrap_hash,
        "connection request bootstrap hash is not authorized")?;
    require(secret.invite_event_id.map_or(true, |id| id == request.invite_event_id),
        "connection request invite id is not authorized")
}

/// Verify the requester signed the canonical transcript with the invite key.
fn require_invite_signature_verifies(
    secret: &InviteSecretFact,
    request: &ConnectionRequestFact,
) -> Result<(), String> {
    let transcript = invite_signing_transcript(request)?;
    let public_key = crypto::ed25519_public_key(&secret.bootstrap_secret);
    require(
        crypto::ed25519_verify(&public_key, &transcript, &request.invite_signature),
        "connection request invite signature is not authorized",
    )
}

// ---- step 3a: local branch (initiator-ephemeral) -----------------------------

fn decode_ephemeral_payload(payload: &Fact) -> Result<ConnectionEphemeralSecretFact, String> {
    ephemeral_layout::decode_fact(&payload.bytes)
        .map_err(|_| "connection request dependency is not an ephemeral secret".to_string())
}

/// The named ephemeral secret must really be ours and match the public key the
/// request advertised. Covers wrapper checks (id, scope) and body checks
/// (owner, public key).
fn require_ephemeral_authorizes_initiator(
    payload: &Fact,
    secret: &ConnectionEphemeralSecretFact,
    request: &ConnectionRequestFact,
) -> Result<(), String> {
    require(payload.id == request.initiator_ephemeral_secret_event_id,
        "connection request ephemeral context id does not match request")?;
    require(payload.scope == FactScope::Local,
        "connection request ephemeral context must be local")?;
    require(secret.owner_endpoint == request.from_endpoint,
        "connection request ephemeral owner does not match sender")?;
    require(secret.ephemeral_public_key == request.initiator_ephemeral_public_key,
        "connection request ephemeral public key does not match dependency")
}

// ---- step 3b: global branch (receive provenance) -----------------------------

fn decode_receive_payload(payload: &Fact) -> Result<TransitReceivedFact, String> {
    receive_layout::decode_fact(&payload.bytes)
        .map_err(|_| "connection request receive context is not transit provenance".to_string())
}

/// Transit provenance must name this fact, be a bootstrap receive, and be
/// addressed from-sender to-endpoint. An optional embedded request id, if
/// present, must also point at this fact.
fn require_receive_provenance_targets_this_request(
    received: &TransitReceivedFact,
    request: &ConnectionRequestFact,
    request_fact_id: [u8; 32],
) -> Result<(), String> {
    require(received.received_fact_id == request_fact_id,
        "connection request receive context targets another fact")?;
    require(received.transit_kind == TRANSIT_KIND_BOOTSTRAP,
        "connection request requires bootstrap receive provenance")?;
    require(received.local_endpoint_id == request.to_endpoint,
        "connection request addressed to a different endpoint")?;
    require(received.sender_endpoint_id == request.from_endpoint,
        "connection request sender does not match receive sender")?;
    require(received.request_id.map_or(true, |id| id == request_fact_id),
        "connection request receive provenance names another request")
}

// ---- step 4: success output --------------------------------------------------

fn materialized_output(
    request_id: [u8; 32],
    request: &ConnectionRequestFact,
) -> Result<ProjectionOutput, String> {
    Ok(ProjectionOutput::new()
        .offer(matchers::connection_request_offer(request_id, request_id))
        .intent(AtomicIntent::PutRow(connection_request_row(request_id, request)?).into_intent()))
}

// ---- canonical transcript ----------------------------------------------------
//
// The transcript layout is part of the wire protocol; changing it is a hard
// fork. It is built here rather than memoized because the projector is
// stateless and the cost is negligible against the signature check itself.

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
