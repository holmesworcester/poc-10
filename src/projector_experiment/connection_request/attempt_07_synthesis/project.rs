//! Wave-2 synthesis: a *two-function* connection-request projector.
//!
//! The angle: every projector returns one of exactly three things — reject,
//! park, or materialize. Wave-1's strongest entry (`attempt_04_inline_flat`)
//! kept all three in a single function and read top-to-bottom. This attempt
//! asks a different question: *what if the three-way outcome is a value, named
//! once, and the function that produces it is separate from the function that
//! shapes the output?*
//!
//! Concretely:
//!
//!   - [`Projector::project`] is a five-line shim. It calls [`plan`] and then
//!     forwards the resulting [`Plan`] to the appropriate output combinator.
//!   - [`plan`] is the entire policy. It reads top-to-bottom exactly like
//!     `attempt_04_inline_flat`, with the same `let Some(..) else { return … }`
//!     parking pattern. The only difference: where inline-flat returns a
//!     `ProjectionOutput::new().need(..)` directly, `plan` returns the more
//!     semantic `Plan::Park(vec![..])`; where inline-flat builds the offer +
//!     intent at the bottom, `plan` returns `Plan::Materialize { … }`.
//!   - [`Plan`] makes the three-way outcome of every projector visible at the
//!     boundary between policy and output shaping: a reader of `project` sees
//!     "this projector either rejects, parks, or materializes" without
//!     scanning a 100-line function.
//!
//! What this experiment is honestly testing: does promoting the projector's
//! three outcomes to a typed value at a function boundary help a newcomer, or
//! is the cost of one extra enum and one extra function call greater than the
//! payoff? The reviewer's verdict on wave-1's `Verdict` (attempt_05) was that
//! using `?` for *both* reject and park muddles the control-flow channel —
//! this attempt deliberately keeps `?` exclusively for reject (the `String`
//! error channel) and routes park through a normal `Ok` value, so the channels
//! stay legible.

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

/// The three-way outcome of running the policy. Rejection is `Err(String)` and
/// rides `?`; this enum covers the two `Ok` cases that the projector boundary
/// must distinguish.
enum Plan {
    /// Policy is waiting on these context dependencies. Each park returns the
    /// exact set of needs the framework should re-subscribe to.
    Park(Vec<ContextNeed>),
    /// Policy is satisfied; the projector should publish the request offer and
    /// emit the put-row intent for this fact.
    Materialize {
        request_id: [u8; 32],
        request: ConnectionRequestFact,
    },
}

impl Projector for ConnectionRequestProjector {
    fn project(&self, fact: &Fact, ctx: &ProjectionContext) -> Result<ProjectionOutput, String> {
        match plan(fact, ctx)? {
            Plan::Park(needs) => Ok(parked(needs)),
            Plan::Materialize { request_id, request } => materialized(request_id, &request),
        }
    }
}

/// Run the full connection-request policy and report what the projector should
/// do next. Reads top-to-bottom: structural checks, then invite-secret
/// authorization, then the scope-specific dependency. Each `let Some(..) else
/// { return Ok(Plan::Park(..)) }` is a parking point; each `if .. { return
/// Err(..) }` is a rejection point.
fn plan(fact: &Fact, ctx: &ProjectionContext) -> Result<Plan, String> {
    // 1. Decode the canonical body and enforce structural invariants. The
    //    match on fact.scope further down also rejects any unsupported scope.
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

    // 2. The invite secret is always required. Park if it hasn't arrived;
    //    otherwise verify id/scope/hash/binding match the request's claim.
    let invite_need = matchers::invite_secret_need(fact.id, request.invite_secret_event_id);
    let Some(invite) = ctx.payload_for(&invite_need) else {
        return Ok(Plan::Park(vec![invite_need]));
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
    if let Some(bound_invite_event_id) = invite_secret.invite_event_id {
        if bound_invite_event_id != request.invite_event_id {
            return Err("connection request invite id is not authorized".to_string());
        }
    }

    // 3. The invite signature must verify against the canonical transcript.
    //    The transcript is rebuilt inline so the reader can see exactly which
    //    fields are signed without chasing a helper.
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

    // 4. Scope-specific dependency: Local issuers must hold the named
    //    initiator ephemeral secret; Global receivers need bootstrap
    //    transit-receive provenance for this exact fact.
    match fact.scope {
        FactScope::Local => {
            let ephemeral_need = ephemeral_matchers::connection_ephemeral_secret_need(
                fact.id,
                request.initiator_ephemeral_secret_event_id,
            );
            let Some(ephemeral) = ctx.payload_for(&ephemeral_need) else {
                return Ok(Plan::Park(vec![invite_need, ephemeral_need]));
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
                return Ok(Plan::Park(vec![invite_need, receive_need]));
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
            if let Some(provenance_request_id) = received.request_id {
                if provenance_request_id != fact.id {
                    return Err("connection request receive provenance names another request".to_string());
                }
            }
        }
        _ => return Err("connection request fact must be local or global".to_string()),
    }

    Ok(Plan::Materialize { request_id: fact.id, request })
}

// ----- output combinators ----------------------------------------------------
//
// These two helpers exist solely to turn a `Plan` variant into the
// framework's `ProjectionOutput`. They are deliberately tiny so the reader
// has nothing to chase.

fn parked(needs: Vec<ContextNeed>) -> ProjectionOutput {
    let mut out = ProjectionOutput::new();
    for need in needs {
        out = out.need(need);
    }
    out
}

fn materialized(
    request_id: [u8; 32],
    request: &ConnectionRequestFact,
) -> Result<ProjectionOutput, String> {
    Ok(ProjectionOutput::new()
        .offer(matchers::connection_request_offer(request_id, request_id))
        .intent(AtomicIntent::PutRow(connection_request_row(request_id, request)?).into_intent()))
}
