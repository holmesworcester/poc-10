//! Connection-request projector, written as a narrated security checklist.
//!
//! The idiom: `policy()` is the whole security specification. Each line is one
//! rule, named in English, chained with `?`. A rule returns `Ok` to continue
//! or a `Verdict` that short-circuits:
//!
//!   - `Verdict::Reject(message)` -> caller surfaces `Err(message)`
//!   - `Verdict::Park(needs)`     -> caller publishes those needs and waits
//!
//! Both short-circuits ride the same `?`, so the happy path stays a straight
//! line. Every helper body is a small list of `require(condition, message)`
//! assertions. Where it helps: a newcomer can read `policy()` once and recover
//! the whole policy. Where it falls short: the reader must first learn one
//! custom type (`Verdict`) and one helper (`require`); the bet is that this
//! tiny vocabulary is repaid by the flat reading order in `policy()`.

use crate::core::context::ContextNeed;
use crate::core::crypto;
use crate::core::facts::{Fact, FactScope};
use crate::core::intents::AtomicIntent;
use crate::core::projection::{ProjectionContext, ProjectionOutput, Projector};

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

// =============================================================================
// The policy, in plain English
// =============================================================================
//
// A connection request is admitted into the projection iff:
//
//   1. Its scope is `Local` (we issued it) or `Global` (we received it from a
//      peer). Anything else is meaningless.
//   2. Its bytes decode into a well-formed `ConnectionRequestFact`.
//   3. Every required field is non-zero, and `from_endpoint != to_endpoint`.
//   4. The named invite secret is present in local context. If not, we park
//      on a single `invite_secret` need.
//   5. The invite payload really is an invite secret, its id matches the
//      request, its scope is local, its bootstrap hash matches the request,
//      and (if the invite is scope-bound) its invite event id matches too.
//   6. The request's signature verifies against the invite's bootstrap key
//      over the canonical transcript.
//   7. The scope-specific dependency is satisfied (and present):
//        LOCAL  -> we hold the named initiator ephemeral secret, it belongs
//                  to `from_endpoint`, and its public key matches the request.
//        GLOBAL -> local transit-receive provenance names this exact fact,
//                  kind=bootstrap, addressed to `to_endpoint`, sent by
//                  `from_endpoint`, and (if it names a request) names this
//                  one.
//      Missing dependency parks alongside `invite_secret`.
//
// `project()` walks this list with `?`. Each `require_*` returns either a
// value (success) or a `Verdict` that short-circuits the whole projector via
// `?`. The two short-circuit kinds (Reject, Park) merge into one error
// channel so the happy path stays a straight line.
// =============================================================================

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
        // The inner function uses `?` to short-circuit on either reject or park.
        // At the boundary, we translate each Verdict into the framework's
        // `Result<ProjectionOutput, String>` shape.
        match policy(fact, ctx) {
            Ok(output) => Ok(output),
            Err(Verdict::Reject(message)) => Err(message),
            Err(Verdict::Park(needs)) => Ok(park_on(&needs)),
        }
    }
}

// -----------------------------------------------------------------------------
// The policy itself. Read top-to-bottom; each `?` either passes its value
// onward or short-circuits the whole projector.
// -----------------------------------------------------------------------------

fn policy(fact: &Fact, ctx: &ProjectionContext) -> Result<ProjectionOutput, Verdict> {
    // Steps 1-3: validate the request body in isolation.
    require_scope_local_or_global(fact)?;
    let request = require_bytes_decode_as_request(fact)?;
    require_every_required_field_is_non_zero(&request)?;
    require_endpoints_differ(&request)?;

    // Step 4-6: the invite secret must endorse this request.
    let invite_need = matchers::invite_secret_need(fact.id, request.invite_secret_event_id);
    let (invite_fact, invite_secret) = require_invite_present(ctx, &invite_need)?;
    require_invite_matches_request_claim(invite_fact, &invite_secret, &request)?;
    require_invite_signature_verifies(&invite_secret, &request)?;

    // Step 7: the scope-specific dependency. Local issuers must own the
    //         initiator ephemeral secret; global receivers need transit
    //         provenance for *this* request.
    match fact.scope {
        FactScope::Local => require_local_ephemeral_authorizes_sender(
            ctx, fact, &request, &invite_need,
        )?,
        FactScope::Global => require_receive_provenance_targets_this_request(
            ctx, fact, &request, &invite_need,
        )?,
        // Step 1 already rejected anything else.
        FactScope::Scoped { .. } => unreachable!("rejected by require_scope_local_or_global"),
    }

    // All rules passed: publish the offer and record the row.
    materialized_output(fact.id, &request).map_err(Verdict::Reject)
}

// -----------------------------------------------------------------------------
// Rules: one function per English sentence in the policy. Each function name
// IS its specification. The bodies are intentionally small.
// -----------------------------------------------------------------------------

fn require_scope_local_or_global(fact: &Fact) -> Result<(), Verdict> {
    require(
        matches!(fact.scope, FactScope::Local | FactScope::Global),
        "connection request fact must be local or global",
    )
}

fn require_bytes_decode_as_request(fact: &Fact) -> Result<ConnectionRequestFact, Verdict> {
    layout::decode_fact(&fact.bytes).map_err(Verdict::Reject)
}

fn require_every_required_field_is_non_zero(
    request: &ConnectionRequestFact,
) -> Result<(), Verdict> {
    let zero = [0u8; 32];
    require(
        request.from_endpoint != zero,
        "connection request from_endpoint cannot be empty",
    )?;
    require(
        request.to_endpoint != zero,
        "connection request to_endpoint cannot be empty",
    )?;
    require(
        request.invite_event_id != zero,
        "connection request invite_event_id cannot be empty",
    )?;
    require(
        request.bootstrap_hash != zero,
        "connection request bootstrap_hash cannot be empty",
    )?;
    require(
        request.invite_secret_event_id != zero,
        "connection request invite_secret_event_id cannot be empty",
    )?;
    require(
        request.initiator_ephemeral_secret_event_id != zero,
        "connection request initiator_ephemeral_secret_event_id cannot be empty",
    )?;
    require(
        request.initiator_ephemeral_public_key != zero,
        "connection request initiator_ephemeral_public_key cannot be empty",
    )?;
    Ok(())
}

fn require_endpoints_differ(request: &ConnectionRequestFact) -> Result<(), Verdict> {
    require(
        request.from_endpoint != request.to_endpoint,
        "connection request endpoints must differ",
    )
}

/// The invite secret must be present in local context. Missing -> park.
/// Malformed bytes -> reject. Returns both the fact and decoded secret so
/// later rules can inspect the wrapper (id, scope) and the body (hash, id).
fn require_invite_present<'a>(
    ctx: &'a ProjectionContext,
    invite_need: &ContextNeed,
) -> Result<(&'a Fact, InviteSecretFact), Verdict> {
    let invite = ctx
        .payload_for(invite_need)
        .ok_or_else(|| Verdict::Park(vec![invite_need.clone()]))?;
    let secret = invite_layout::decode_fact(&invite.bytes).map_err(|_| {
        Verdict::reject("connection request invite context is not an invite secret")
    })?;
    Ok((invite, secret))
}

/// The invite-secret fact really must be the one the request named. This
/// covers id, scope, bootstrap hash, and the optional scope-binding to a
/// particular invite event.
fn require_invite_matches_request_claim(
    invite: &Fact,
    secret: &InviteSecretFact,
    request: &ConnectionRequestFact,
) -> Result<(), Verdict> {
    require(
        invite.id == request.invite_secret_event_id,
        "connection request invite context id does not match request",
    )?;
    require(
        invite.scope == FactScope::Local,
        "connection request invite context must be local",
    )?;
    require(
        secret.bootstrap_hash == request.bootstrap_hash,
        "connection request bootstrap hash is not authorized",
    )?;
    if let Some(bound_invite_event_id) = secret.invite_event_id {
        require(
            bound_invite_event_id == request.invite_event_id,
            "connection request invite id is not authorized",
        )?;
    }
    Ok(())
}

fn require_invite_signature_verifies(
    secret: &InviteSecretFact,
    request: &ConnectionRequestFact,
) -> Result<(), Verdict> {
    let transcript = invite_signing_transcript(request).map_err(Verdict::Reject)?;
    let public_key = crypto::ed25519_public_key(&secret.bootstrap_secret);
    require(
        crypto::ed25519_verify(&public_key, &transcript, &request.invite_signature),
        "connection request invite signature is not authorized",
    )
}

/// LOCAL branch. We issued this request, so we must hold the matching
/// initiator ephemeral secret. The dependency must also be ours: its
/// `owner_endpoint` is the sender and its public key matches what the
/// request advertised. Missing the secret entirely -> park with both
/// the invite need (kept so we don't lose subscription) and the
/// ephemeral need.
fn require_local_ephemeral_authorizes_sender(
    ctx: &ProjectionContext,
    fact: &Fact,
    request: &ConnectionRequestFact,
    invite_need: &ContextNeed,
) -> Result<(), Verdict> {
    let ephemeral_need = ephemeral_matchers::connection_ephemeral_secret_need(
        fact.id,
        request.initiator_ephemeral_secret_event_id,
    );
    let ephemeral = ctx
        .payload_for(&ephemeral_need)
        .ok_or_else(|| Verdict::Park(vec![invite_need.clone(), ephemeral_need.clone()]))?;
    let secret: ConnectionEphemeralSecretFact = ephemeral_layout::decode_fact(&ephemeral.bytes)
        .map_err(|_| Verdict::reject("connection request dependency is not an ephemeral secret"))?;
    require(
        ephemeral.id == request.initiator_ephemeral_secret_event_id,
        "connection request ephemeral context id does not match request",
    )?;
    require(
        ephemeral.scope == FactScope::Local,
        "connection request ephemeral context must be local",
    )?;
    require(
        secret.owner_endpoint == request.from_endpoint,
        "connection request ephemeral owner does not match sender",
    )?;
    require(
        secret.ephemeral_public_key == request.initiator_ephemeral_public_key,
        "connection request ephemeral public key does not match dependency",
    )?;
    Ok(())
}

/// GLOBAL branch. The request came from a peer; transit must have observed
/// it for *this* endpoint, from *this* sender, via a bootstrap channel, and
/// it must name this very fact (and, if the provenance also names a request
/// id, that name must match too). Missing provenance -> park.
fn require_receive_provenance_targets_this_request(
    ctx: &ProjectionContext,
    fact: &Fact,
    request: &ConnectionRequestFact,
    invite_need: &ContextNeed,
) -> Result<(), Verdict> {
    let receive_need = receive_matchers::transit_received_need(fact.id, fact.id);
    let receive = ctx
        .payload_for(&receive_need)
        .ok_or_else(|| Verdict::Park(vec![invite_need.clone(), receive_need.clone()]))?;
    require(
        receive.scope == FactScope::Local,
        "connection request receive context must be local",
    )?;
    let received: TransitReceivedFact = receive_layout::decode_fact(&receive.bytes).map_err(|_| {
        Verdict::reject("connection request receive context is not transit provenance")
    })?;
    require(
        received.received_fact_id == fact.id,
        "connection request receive context targets another fact",
    )?;
    require(
        received.transit_kind == TRANSIT_KIND_BOOTSTRAP,
        "connection request requires bootstrap receive provenance",
    )?;
    require(
        received.local_endpoint_id == request.to_endpoint,
        "connection request addressed to a different endpoint",
    )?;
    require(
        received.sender_endpoint_id == request.from_endpoint,
        "connection request sender does not match receive sender",
    )?;
    if let Some(provenance_request_id) = received.request_id {
        require(
            provenance_request_id == fact.id,
            "connection request receive provenance names another request",
        )?;
    }
    Ok(())
}

/// Helper used by every rule: "if `condition` doesn't hold, reject with this
/// English explanation". One-liner so each rule reads as a list of expectations.
fn require(condition: bool, message_if_violated: &str) -> Result<(), Verdict> {
    if condition {
        Ok(())
    } else {
        Err(Verdict::reject(message_if_violated))
    }
}

// -----------------------------------------------------------------------------
// Outputs.
// -----------------------------------------------------------------------------

fn park_on(needs: &[ContextNeed]) -> ProjectionOutput {
    let mut out = ProjectionOutput::new();
    for need in needs {
        out = out.need(need.clone());
    }
    out
}

fn materialized_output(
    request_id: [u8; 32],
    request: &ConnectionRequestFact,
) -> Result<ProjectionOutput, String> {
    Ok(ProjectionOutput::new()
        .offer(matchers::connection_request_offer(request_id, request_id))
        .intent(AtomicIntent::PutRow(connection_request_row(request_id, request)?).into_intent()))
}

// -----------------------------------------------------------------------------
// Canonical transcript: signed bytes the requester committed to.
//
// The transcript order is part of the protocol; changing it is a hard fork.
// It is rebuilt here on every verification rather than cached because the
// projector is stateless and the cost is negligible compared to the signature
// check itself.
// -----------------------------------------------------------------------------

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

// -----------------------------------------------------------------------------
// Verdict: how a rule short-circuits the policy.
// -----------------------------------------------------------------------------

/// The two ways a rule can stop the chain. `Reject` becomes the projector's
/// `Err`; `Park` becomes a parked `Ok` with the listed needs. Both pass
/// through `?` so the policy body reads top-to-bottom.
#[derive(Debug)]
enum Verdict {
    Reject(String),
    Park(Vec<ContextNeed>),
}

impl Verdict {
    fn reject(message: &str) -> Self {
        Verdict::Reject(message.to_string())
    }
}
