//! Exhaustive invariants for the connection_request projector.
//!
//! Every invariant is a free function generic over `P: Projector`. Each variant
//! of the projector (baseline + attempts) instantiates the full battery via
//! `run_all_invariants(&projector)`. Adding a new invariant here forces every
//! variant to handle it.
//!
//! These tests are intentionally style-agnostic: they assert on observable
//! behavior (output needs, offers, intents, error strings) rather than on
//! internal helpers.

#![cfg(test)]

use crate::core::crypto::{self, ED25519_SIGNATURE_BYTES};
use crate::core::facts::{Fact, FactScope};
use crate::core::intents::AtomicIntent;
use crate::core::projection::{MatchedContext, ProjectionContext, Projector};
use crate::event_modules::connection_ephemeral_secret::{
    fact::ConnectionEphemeralSecretFact, layout as ephemeral_layout, matchers as ephemeral_matchers,
};
use crate::event_modules::connection_request::{
    addr::encode_optional_addr, fact::ConnectionRequestFact, layout, matchers as request_matchers,
    rows,
};
use crate::event_modules::identity_invite::{fact::InviteSecretFact, layout as invite_layout};
use crate::event_modules::transit_received::{
    fact::{TransitReceivedFact, TRANSIT_KIND_BOOTSTRAP},
    layout as received_layout, matchers as received_matchers,
};

const FROM_ENDPOINT: [u8; 32] = [1; 32];
const TO_ENDPOINT: [u8; 32] = [2; 32];
const NONCE: [u8; 32] = [3; 32];
const INVITE_EVENT_ID: [u8; 32] = [4; 32];
const BOOTSTRAP_SECRET: [u8; 32] = [55; 32];
const EPHEMERAL_PRIVATE_KEY: [u8; 32] = [7; 32];

pub struct Scenario {
    pub request: ConnectionRequestFact,
    pub request_fact: Fact,
    pub invite_secret: InviteSecretFact,
    pub invite_fact: Fact,
    pub ephemeral_secret: ConnectionEphemeralSecretFact,
    pub ephemeral_fact: Fact,
}

pub fn build_scenario(scope: FactScope) -> Scenario {
    let invite_secret = InviteSecretFact::new(BOOTSTRAP_SECRET);
    let invite_fact = Fact::new(
        FactScope::Local,
        10,
        invite_layout::encode_fact(&invite_secret).expect("encode invite"),
    );
    let ephemeral_secret = ConnectionEphemeralSecretFact {
        owner_endpoint: FROM_ENDPOINT,
        ephemeral_private_key: EPHEMERAL_PRIVATE_KEY,
        ephemeral_public_key: crypto::x25519_public_key(&EPHEMERAL_PRIVATE_KEY),
        created_at_ms: 11,
    };
    let ephemeral_fact = Fact::new(
        FactScope::Local,
        11,
        ephemeral_layout::encode_fact(&ephemeral_secret).expect("encode ephemeral"),
    );
    let mut request = ConnectionRequestFact {
        from_endpoint: FROM_ENDPOINT,
        to_endpoint: TO_ENDPOINT,
        nonce: NONCE,
        invite_event_id: INVITE_EVENT_ID,
        bootstrap_hash: invite_secret.bootstrap_hash,
        invite_signature: [0; ED25519_SIGNATURE_BYTES],
        invite_secret_event_id: invite_fact.id,
        initiator_ephemeral_secret_event_id: ephemeral_fact.id,
        initiator_ephemeral_public_key: ephemeral_secret.ephemeral_public_key,
        from_listen_addr: None,
        to_listen_addr: None,
    };
    request.invite_signature = crypto::ed25519_sign(
        &invite_secret.bootstrap_secret,
        &transcript(&request).expect("transcript"),
    );
    let request_fact = Fact::new(
        scope,
        12,
        layout::encode_fact(&request).expect("encode request"),
    );
    Scenario {
        request,
        request_fact,
        invite_secret,
        invite_fact,
        ephemeral_secret,
        ephemeral_fact,
    }
}

fn transcript(request: &ConnectionRequestFact) -> Result<Vec<u8>, String> {
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

fn re_sign(request: &mut ConnectionRequestFact, secret: &[u8; 32]) {
    request.invite_signature = crypto::ed25519_sign(secret, &transcript(request).expect("transcript"));
}

fn encode_request_fact(scope: FactScope, request: &ConnectionRequestFact) -> Fact {
    Fact::new(
        scope,
        12,
        layout::encode_fact(request).expect("encode request"),
    )
}

fn invite_match(owner: [u8; 32], invite: Fact) -> MatchedContext {
    let need = request_matchers::invite_secret_need(owner, invite.id);
    MatchedContext {
        need: need.clone(),
        offer: request_matchers::invite_secret_offer(invite.id, invite.id),
        payload: invite,
    }
}

fn ephemeral_match(owner: [u8; 32], ephemeral: Fact) -> MatchedContext {
    let need = ephemeral_matchers::connection_ephemeral_secret_need(owner, ephemeral.id);
    MatchedContext {
        need,
        offer: ephemeral_matchers::connection_ephemeral_secret_offer(ephemeral.id, ephemeral.id),
        payload: ephemeral,
    }
}

fn receive_match_with(
    owner: [u8; 32],
    request_id: [u8; 32],
    overrides: impl FnOnce(&mut TransitReceivedFact),
) -> MatchedContext {
    let mut received = TransitReceivedFact {
        received_fact_id: request_id,
        origin_addr: b"127.0.0.1:41001".to_vec(),
        local_endpoint_id: TO_ENDPOINT,
        sender_endpoint_id: FROM_ENDPOINT,
        transit_kind: TRANSIT_KIND_BOOTSTRAP,
        connection_id: None,
        request_id: Some(request_id),
        frame_hash: [9; 32],
        received_at_local_ms: 1_700_000_000,
    };
    overrides(&mut received);
    let fact = Fact::new(
        FactScope::Local,
        13,
        received_layout::encode_fact(&received).expect("encode provenance"),
    );
    let need = received_matchers::transit_received_need(owner, request_id);
    MatchedContext {
        need,
        offer: received_matchers::transit_received_offer(fact.id, request_id),
        payload: fact,
    }
}

fn receive_match(owner: [u8; 32], request_id: [u8; 32]) -> MatchedContext {
    receive_match_with(owner, request_id, |_| {})
}

fn local_invite_only_context(s: &Scenario) -> ProjectionContext {
    ProjectionContext::from_matches(vec![invite_match(s.request_fact.id, s.invite_fact.clone())])
}

fn local_full_context(s: &Scenario) -> ProjectionContext {
    ProjectionContext::from_matches(vec![
        invite_match(s.request_fact.id, s.invite_fact.clone()),
        ephemeral_match(s.request_fact.id, s.ephemeral_fact.clone()),
    ])
}

fn global_full_context(s: &Scenario) -> ProjectionContext {
    ProjectionContext::from_matches(vec![
        invite_match(s.request_fact.id, s.invite_fact.clone()),
        receive_match(s.request_fact.id, s.request_fact.id),
    ])
}

fn expect_err<P: Projector>(p: &P, fact: &Fact, ctx: &ProjectionContext, fragment: &str) {
    let err = p
        .project(fact, ctx)
        .expect_err(&format!("projector must reject; expected '{fragment}'"));
    assert!(
        err.contains(fragment),
        "expected error containing '{fragment}', got '{err}'",
    );
}

// --- structural invariants ----------------------------------------------------

pub fn rejects_malformed_bytes<P: Projector>(p: &P) {
    let fact = Fact::new(FactScope::Local, 0, vec![0; 4]);
    let err = p
        .project(&fact, &ProjectionContext::new(Vec::new()))
        .expect_err("malformed bytes must be rejected");
    assert!(
        err.contains("connection request") || err.contains("Length") || err.contains("decode"),
        "malformed bytes error must mention decode/length/connection request; got '{err}'",
    );
}

pub fn rejects_zero_from_endpoint<P: Projector>(p: &P) {
    let s = build_scenario(FactScope::Local);
    let mut request = s.request.clone();
    request.from_endpoint = [0; 32];
    re_sign(&mut request, &s.invite_secret.bootstrap_secret);
    let fact = encode_request_fact(FactScope::Local, &request);
    expect_err(p, &fact, &ProjectionContext::new(Vec::new()), "from_endpoint");
}

pub fn rejects_zero_to_endpoint<P: Projector>(p: &P) {
    let s = build_scenario(FactScope::Local);
    let mut request = s.request.clone();
    request.to_endpoint = [0; 32];
    re_sign(&mut request, &s.invite_secret.bootstrap_secret);
    let fact = encode_request_fact(FactScope::Local, &request);
    expect_err(p, &fact, &ProjectionContext::new(Vec::new()), "to_endpoint");
}

pub fn rejects_zero_invite_event_id<P: Projector>(p: &P) {
    let s = build_scenario(FactScope::Local);
    let mut request = s.request.clone();
    request.invite_event_id = [0; 32];
    re_sign(&mut request, &s.invite_secret.bootstrap_secret);
    let fact = encode_request_fact(FactScope::Local, &request);
    expect_err(p, &fact, &ProjectionContext::new(Vec::new()), "invite_event_id");
}

pub fn rejects_zero_bootstrap_hash<P: Projector>(p: &P) {
    let s = build_scenario(FactScope::Local);
    let mut request = s.request.clone();
    request.bootstrap_hash = [0; 32];
    re_sign(&mut request, &s.invite_secret.bootstrap_secret);
    let fact = encode_request_fact(FactScope::Local, &request);
    expect_err(p, &fact, &ProjectionContext::new(Vec::new()), "bootstrap_hash");
}

pub fn rejects_zero_invite_secret_event_id<P: Projector>(p: &P) {
    let s = build_scenario(FactScope::Local);
    let mut request = s.request.clone();
    request.invite_secret_event_id = [0; 32];
    re_sign(&mut request, &s.invite_secret.bootstrap_secret);
    let fact = encode_request_fact(FactScope::Local, &request);
    expect_err(p, &fact, &ProjectionContext::new(Vec::new()), "invite_secret_event_id");
}

pub fn rejects_zero_initiator_ephemeral_secret_event_id<P: Projector>(p: &P) {
    let s = build_scenario(FactScope::Local);
    let mut request = s.request.clone();
    request.initiator_ephemeral_secret_event_id = [0; 32];
    re_sign(&mut request, &s.invite_secret.bootstrap_secret);
    let fact = encode_request_fact(FactScope::Local, &request);
    expect_err(
        p,
        &fact,
        &ProjectionContext::new(Vec::new()),
        "initiator_ephemeral_secret_event_id",
    );
}

pub fn rejects_zero_initiator_ephemeral_public_key<P: Projector>(p: &P) {
    let s = build_scenario(FactScope::Local);
    let mut request = s.request.clone();
    request.initiator_ephemeral_public_key = [0; 32];
    re_sign(&mut request, &s.invite_secret.bootstrap_secret);
    let fact = encode_request_fact(FactScope::Local, &request);
    expect_err(
        p,
        &fact,
        &ProjectionContext::new(Vec::new()),
        "initiator_ephemeral_public_key",
    );
}

pub fn rejects_self_loop<P: Projector>(p: &P) {
    let s = build_scenario(FactScope::Local);
    let mut request = s.request.clone();
    request.to_endpoint = request.from_endpoint;
    re_sign(&mut request, &s.invite_secret.bootstrap_secret);
    let fact = encode_request_fact(FactScope::Local, &request);
    expect_err(p, &fact, &ProjectionContext::new(Vec::new()), "endpoints");
}

// --- parking behavior ---------------------------------------------------------

pub fn local_request_with_no_context_parks_on_invite_only<P: Projector>(p: &P) {
    let s = build_scenario(FactScope::Local);
    let out = p
        .project(&s.request_fact, &ProjectionContext::new(Vec::new()))
        .expect("structurally valid local request parks");
    assert!(out.intents.is_empty(), "must not emit intents while parked");
    assert!(out.offers.is_empty(), "must not emit offers while parked");
    assert_eq!(out.needs.len(), 1, "expected one need (invite_secret) when nothing matched yet");
    assert!(
        out.needs
            .iter()
            .any(|need| need.role.as_str() == request_matchers::CONNECTION_INVITE_SECRET_ROLE),
        "must publish the invite_secret need first",
    );
}

pub fn global_request_with_no_context_parks_on_invite_only<P: Projector>(p: &P) {
    let s = build_scenario(FactScope::Global);
    let out = p
        .project(&s.request_fact, &ProjectionContext::new(Vec::new()))
        .expect("structurally valid global request parks");
    assert!(out.intents.is_empty());
    assert!(out.offers.is_empty());
    assert_eq!(out.needs.len(), 1);
    assert!(
        out.needs
            .iter()
            .any(|need| need.role.as_str() == request_matchers::CONNECTION_INVITE_SECRET_ROLE),
    );
}

pub fn local_request_missing_ephemeral_waits_with_two_needs<P: Projector>(p: &P) {
    let s = build_scenario(FactScope::Local);
    let out = p
        .project(&s.request_fact, &local_invite_only_context(&s))
        .expect("local request parks waiting for ephemeral");
    assert!(out.intents.is_empty());
    assert!(out.offers.is_empty());
    assert_eq!(out.needs.len(), 2);
    assert!(
        out.needs
            .iter()
            .any(|need| need.role.as_str() == ephemeral_matchers::CONNECTION_EPHEMERAL_SECRET_ROLE),
        "missing ephemeral_secret need",
    );
    assert!(
        out.needs
            .iter()
            .any(|need| need.role.as_str() == request_matchers::CONNECTION_INVITE_SECRET_ROLE),
        "missing invite_secret need",
    );
}

pub fn global_request_missing_provenance_waits_with_two_needs<P: Projector>(p: &P) {
    let s = build_scenario(FactScope::Global);
    let out = p
        .project(&s.request_fact, &local_invite_only_context(&s))
        .expect("global request parks waiting for provenance");
    assert!(out.intents.is_empty());
    assert!(out.offers.is_empty());
    assert_eq!(out.needs.len(), 2);
    assert!(out
        .needs
        .iter()
        .any(|need| need.role == received_matchers::transit_received_role()));
    assert!(
        out.needs
            .iter()
            .any(|need| need.role.as_str() == request_matchers::CONNECTION_INVITE_SECRET_ROLE),
    );
}

// --- success cases ------------------------------------------------------------

pub fn local_request_materializes_on_full_context<P: Projector>(p: &P) {
    let s = build_scenario(FactScope::Local);
    let out = p
        .project(&s.request_fact, &local_full_context(&s))
        .expect("local request materializes");
    assert_eq!(out.intents.len(), 1, "expected exactly one intent");
    assert_eq!(out.offers.len(), 1, "expected exactly one offer");
    assert_eq!(
        out.offers[0].role.as_str(),
        request_matchers::CONNECTION_REQUEST_ROLE,
        "offer must use connection_request role",
    );
}

pub fn global_request_materializes_on_full_context<P: Projector>(p: &P) {
    let s = build_scenario(FactScope::Global);
    let out = p
        .project(&s.request_fact, &global_full_context(&s))
        .expect("global request materializes");
    assert_eq!(out.intents.len(), 1);
    assert_eq!(out.offers.len(), 1);
    assert_eq!(
        out.offers[0].role.as_str(),
        request_matchers::CONNECTION_REQUEST_ROLE,
    );
}

pub fn materialized_row_round_trips_fields<P: Projector>(p: &P) {
    let s = build_scenario(FactScope::Local);
    let out = p
        .project(&s.request_fact, &local_full_context(&s))
        .expect("local request materializes");
    let intent = out.intents.first().expect("expected put_row intent");
    let row_intent = AtomicIntent::from_intent(intent, &[rows::CONNECTION_REQUEST_ROWS])
        .expect("intent must convert to atomic put_row");
    let AtomicIntent::PutRow(stored) = row_intent else {
        panic!("expected PutRow atomic intent");
    };
    let row = rows::decode_connection_request_row(&stored.key, &stored.value)
        .expect("row must decode");
    assert_eq!(row.request_id, s.request_fact.id);
    assert_eq!(row.from_endpoint, s.request.from_endpoint);
    assert_eq!(row.to_endpoint, s.request.to_endpoint);
    assert_eq!(row.invite_event_id, s.request.invite_event_id);
    assert_eq!(row.invite_secret_event_id, s.request.invite_secret_event_id);
    assert_eq!(
        row.initiator_ephemeral_secret_event_id,
        s.request.initiator_ephemeral_secret_event_id,
    );
}

// --- invite-secret context validation -----------------------------------------

pub fn rejects_invite_payload_that_is_not_invite_secret<P: Projector>(p: &P) {
    let s = build_scenario(FactScope::Local);
    let bogus_fact = Fact::new(FactScope::Local, 1, vec![0xff; 8]);
    let need = request_matchers::invite_secret_need(s.request_fact.id, s.invite_fact.id);
    let context = ProjectionContext::from_matches(vec![MatchedContext {
        need: need.clone(),
        offer: request_matchers::invite_secret_offer(s.invite_fact.id, s.invite_fact.id),
        payload: Fact {
            id: s.invite_fact.id,
            scope: FactScope::Local,
            timestamp: 0,
            bytes: bogus_fact.bytes,
        },
    }]);
    expect_err(p, &s.request_fact, &context, "invite");
}

pub fn rejects_invite_id_mismatch<P: Projector>(p: &P) {
    let s = build_scenario(FactScope::Local);
    // Invite has the matching bytes but a different `id` than the request claims.
    let need = request_matchers::invite_secret_need(s.request_fact.id, s.invite_fact.id);
    let mut payload = s.invite_fact.clone();
    payload.id = [0xab; 32];
    let context = ProjectionContext::from_matches(vec![MatchedContext {
        need,
        offer: request_matchers::invite_secret_offer(s.invite_fact.id, s.invite_fact.id),
        payload,
    }]);
    expect_err(p, &s.request_fact, &context, "invite context id");
}

pub fn rejects_invite_scope_not_local<P: Projector>(p: &P) {
    let s = build_scenario(FactScope::Local);
    let need = request_matchers::invite_secret_need(s.request_fact.id, s.invite_fact.id);
    let mut payload = s.invite_fact.clone();
    payload.scope = FactScope::Global;
    let context = ProjectionContext::from_matches(vec![MatchedContext {
        need,
        offer: request_matchers::invite_secret_offer(s.invite_fact.id, s.invite_fact.id),
        payload,
    }]);
    expect_err(p, &s.request_fact, &context, "invite context must be local");
}

pub fn rejects_invite_bootstrap_hash_mismatch<P: Projector>(p: &P) {
    let s = build_scenario(FactScope::Local);
    // Build a separate invite secret with a different secret => different hash.
    let other_secret = InviteSecretFact::new([66; 32]);
    let other_invite_fact = Fact::new(
        FactScope::Local,
        10,
        invite_layout::encode_fact(&other_secret).expect("encode other invite"),
    );
    // Keep the request claiming the original secret's id, but supply the other payload.
    let need = request_matchers::invite_secret_need(s.request_fact.id, s.invite_fact.id);
    let mut payload = other_invite_fact.clone();
    payload.id = s.invite_fact.id; // collides on id, but bytes encode different bootstrap_hash
    let context = ProjectionContext::from_matches(vec![MatchedContext {
        need,
        offer: request_matchers::invite_secret_offer(s.invite_fact.id, s.invite_fact.id),
        payload,
    }]);
    expect_err(p, &s.request_fact, &context, "bootstrap hash");
}

pub fn rejects_invite_event_id_scope_mismatch<P: Projector>(p: &P) {
    let s = build_scenario(FactScope::Local);
    // Bind the invite secret to a different invite event id than the request names.
    let scoped_invite = InviteSecretFact::scoped(
        s.invite_secret.bootstrap_secret,
        [77; 32],
        [88; 32], // request.invite_event_id is [4;32]
    );
    let scoped_invite_fact = Fact::new(
        FactScope::Local,
        10,
        invite_layout::encode_fact(&scoped_invite).expect("encode scoped invite"),
    );
    let need = request_matchers::invite_secret_need(s.request_fact.id, s.invite_fact.id);
    let mut payload = scoped_invite_fact;
    payload.id = s.invite_fact.id;
    let context = ProjectionContext::from_matches(vec![MatchedContext {
        need,
        offer: request_matchers::invite_secret_offer(s.invite_fact.id, s.invite_fact.id),
        payload,
    }]);
    expect_err(p, &s.request_fact, &context, "invite id");
}

pub fn rejects_invalid_invite_signature<P: Projector>(p: &P) {
    let s = build_scenario(FactScope::Local);
    let mut request = s.request.clone();
    // Sign with a wrong secret so verification fails.
    re_sign(&mut request, &[99; 32]);
    let fact = encode_request_fact(FactScope::Local, &request);
    let context = ProjectionContext::from_matches(vec![invite_match(fact.id, s.invite_fact.clone())]);
    expect_err(p, &fact, &context, "signature");
}

// --- ephemeral context validation (local path) --------------------------------

pub fn rejects_ephemeral_id_mismatch<P: Projector>(p: &P) {
    let s = build_scenario(FactScope::Local);
    let mut payload = s.ephemeral_fact.clone();
    payload.id = [0xcd; 32];
    let need = ephemeral_matchers::connection_ephemeral_secret_need(
        s.request_fact.id,
        s.ephemeral_fact.id,
    );
    let context = ProjectionContext::from_matches(vec![
        invite_match(s.request_fact.id, s.invite_fact.clone()),
        MatchedContext {
            need,
            offer: ephemeral_matchers::connection_ephemeral_secret_offer(
                s.ephemeral_fact.id,
                s.ephemeral_fact.id,
            ),
            payload,
        },
    ]);
    expect_err(p, &s.request_fact, &context, "ephemeral context id");
}

pub fn rejects_ephemeral_scope_not_local<P: Projector>(p: &P) {
    let s = build_scenario(FactScope::Local);
    let mut payload = s.ephemeral_fact.clone();
    payload.scope = FactScope::Global;
    let need = ephemeral_matchers::connection_ephemeral_secret_need(
        s.request_fact.id,
        s.ephemeral_fact.id,
    );
    let context = ProjectionContext::from_matches(vec![
        invite_match(s.request_fact.id, s.invite_fact.clone()),
        MatchedContext {
            need,
            offer: ephemeral_matchers::connection_ephemeral_secret_offer(
                s.ephemeral_fact.id,
                s.ephemeral_fact.id,
            ),
            payload,
        },
    ]);
    expect_err(p, &s.request_fact, &context, "ephemeral context must be local");
}

pub fn rejects_ephemeral_owner_mismatch<P: Projector>(p: &P) {
    let s = build_scenario(FactScope::Local);
    let mut secret = s.ephemeral_secret;
    secret.owner_endpoint = [0xee; 32];
    let payload = Fact::new(
        FactScope::Local,
        11,
        ephemeral_layout::encode_fact(&secret).expect("encode tampered ephemeral"),
    );
    let mut payload = payload;
    payload.id = s.ephemeral_fact.id;
    let need = ephemeral_matchers::connection_ephemeral_secret_need(
        s.request_fact.id,
        s.ephemeral_fact.id,
    );
    let context = ProjectionContext::from_matches(vec![
        invite_match(s.request_fact.id, s.invite_fact.clone()),
        MatchedContext {
            need,
            offer: ephemeral_matchers::connection_ephemeral_secret_offer(
                s.ephemeral_fact.id,
                s.ephemeral_fact.id,
            ),
            payload,
        },
    ]);
    expect_err(p, &s.request_fact, &context, "owner");
}

pub fn rejects_ephemeral_public_key_mismatch<P: Projector>(p: &P) {
    let s = build_scenario(FactScope::Local);
    let mut secret = s.ephemeral_secret;
    secret.ephemeral_public_key = [0xee; 32];
    let payload = Fact::new(
        FactScope::Local,
        11,
        ephemeral_layout::encode_fact(&secret).expect("encode tampered ephemeral"),
    );
    let mut payload = payload;
    payload.id = s.ephemeral_fact.id;
    let need = ephemeral_matchers::connection_ephemeral_secret_need(
        s.request_fact.id,
        s.ephemeral_fact.id,
    );
    let context = ProjectionContext::from_matches(vec![
        invite_match(s.request_fact.id, s.invite_fact.clone()),
        MatchedContext {
            need,
            offer: ephemeral_matchers::connection_ephemeral_secret_offer(
                s.ephemeral_fact.id,
                s.ephemeral_fact.id,
            ),
            payload,
        },
    ]);
    expect_err(p, &s.request_fact, &context, "ephemeral public key");
}

// --- provenance context validation (global path) ------------------------------

pub fn rejects_provenance_scope_not_local<P: Projector>(p: &P) {
    let s = build_scenario(FactScope::Global);
    let mut receive = receive_match(s.request_fact.id, s.request_fact.id);
    receive.payload.scope = FactScope::Global;
    let context = ProjectionContext::from_matches(vec![
        invite_match(s.request_fact.id, s.invite_fact.clone()),
        receive,
    ]);
    expect_err(p, &s.request_fact, &context, "receive context must be local");
}

pub fn rejects_provenance_target_mismatch<P: Projector>(p: &P) {
    let s = build_scenario(FactScope::Global);
    let receive = receive_match_with(s.request_fact.id, s.request_fact.id, |r| {
        r.received_fact_id = [0xbb; 32];
    });
    let context = ProjectionContext::from_matches(vec![
        invite_match(s.request_fact.id, s.invite_fact.clone()),
        receive,
    ]);
    expect_err(p, &s.request_fact, &context, "another fact");
}

pub fn rejects_provenance_non_bootstrap_kind<P: Projector>(p: &P) {
    use crate::event_modules::transit_received::fact::TRANSIT_KIND_CONNECTION;
    let s = build_scenario(FactScope::Global);
    let receive = receive_match_with(s.request_fact.id, s.request_fact.id, |r| {
        r.transit_kind = TRANSIT_KIND_CONNECTION;
    });
    let context = ProjectionContext::from_matches(vec![
        invite_match(s.request_fact.id, s.invite_fact.clone()),
        receive,
    ]);
    expect_err(p, &s.request_fact, &context, "bootstrap");
}

pub fn rejects_provenance_wrong_local_endpoint<P: Projector>(p: &P) {
    let s = build_scenario(FactScope::Global);
    let receive = receive_match_with(s.request_fact.id, s.request_fact.id, |r| {
        r.local_endpoint_id = [0xcc; 32];
    });
    let context = ProjectionContext::from_matches(vec![
        invite_match(s.request_fact.id, s.invite_fact.clone()),
        receive,
    ]);
    expect_err(p, &s.request_fact, &context, "different endpoint");
}

pub fn rejects_provenance_wrong_sender<P: Projector>(p: &P) {
    let s = build_scenario(FactScope::Global);
    let receive = receive_match_with(s.request_fact.id, s.request_fact.id, |r| {
        r.sender_endpoint_id = [0xdd; 32];
    });
    let context = ProjectionContext::from_matches(vec![
        invite_match(s.request_fact.id, s.invite_fact.clone()),
        receive,
    ]);
    expect_err(p, &s.request_fact, &context, "sender");
}

pub fn rejects_provenance_request_id_mismatch<P: Projector>(p: &P) {
    let s = build_scenario(FactScope::Global);
    let receive = receive_match_with(s.request_fact.id, s.request_fact.id, |r| {
        r.request_id = Some([0xee; 32]);
    });
    let context = ProjectionContext::from_matches(vec![
        invite_match(s.request_fact.id, s.invite_fact.clone()),
        receive,
    ]);
    expect_err(p, &s.request_fact, &context, "another request");
}

pub fn accepts_provenance_without_request_id<P: Projector>(p: &P) {
    let s = build_scenario(FactScope::Global);
    let receive = receive_match_with(s.request_fact.id, s.request_fact.id, |r| {
        r.request_id = None;
    });
    let context = ProjectionContext::from_matches(vec![
        invite_match(s.request_fact.id, s.invite_fact.clone()),
        receive,
    ]);
    let out = p
        .project(&s.request_fact, &context)
        .expect("optional request_id None should still authorize");
    assert_eq!(out.intents.len(), 1);
    assert_eq!(out.offers.len(), 1);
}

// --- master battery -----------------------------------------------------------

pub fn run_all_invariants<P: Projector>(p: &P) {
    rejects_malformed_bytes(p);
    rejects_zero_from_endpoint(p);
    rejects_zero_to_endpoint(p);
    rejects_zero_invite_event_id(p);
    rejects_zero_bootstrap_hash(p);
    rejects_zero_invite_secret_event_id(p);
    rejects_zero_initiator_ephemeral_secret_event_id(p);
    rejects_zero_initiator_ephemeral_public_key(p);
    rejects_self_loop(p);
    local_request_with_no_context_parks_on_invite_only(p);
    global_request_with_no_context_parks_on_invite_only(p);
    local_request_missing_ephemeral_waits_with_two_needs(p);
    global_request_missing_provenance_waits_with_two_needs(p);
    local_request_materializes_on_full_context(p);
    global_request_materializes_on_full_context(p);
    materialized_row_round_trips_fields(p);
    rejects_invite_payload_that_is_not_invite_secret(p);
    rejects_invite_id_mismatch(p);
    rejects_invite_scope_not_local(p);
    rejects_invite_bootstrap_hash_mismatch(p);
    rejects_invite_event_id_scope_mismatch(p);
    rejects_invalid_invite_signature(p);
    rejects_ephemeral_id_mismatch(p);
    rejects_ephemeral_scope_not_local(p);
    rejects_ephemeral_owner_mismatch(p);
    rejects_ephemeral_public_key_mismatch(p);
    rejects_provenance_scope_not_local(p);
    rejects_provenance_target_mismatch(p);
    rejects_provenance_non_bootstrap_kind(p);
    rejects_provenance_wrong_local_endpoint(p);
    rejects_provenance_wrong_sender(p);
    rejects_provenance_request_id_mismatch(p);
    accepts_provenance_without_request_id(p);
}
