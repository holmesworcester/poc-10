use topo::core::crypto::{self, ED25519_SIGNATURE_BYTES};
use topo::core::facts::{Fact, FactScope};
use topo::core::intents::AtomicIntent;
use topo::core::projection::{MatchedContext, ProjectionContext, Projector};
use topo::event_modules::connection_ephemeral_secret::{
    fact::ConnectionEphemeralSecretFact, layout as ephemeral_layout, matchers as ephemeral_matchers,
};
use topo::event_modules::connection_request::{
    addr::encode_optional_addr, fact::ConnectionRequestFact, layout, matchers as request_matchers,
    project, rows,
};
use topo::event_modules::identity_invite::{fact::InviteSecretFact, layout as invite_layout};
use topo::event_modules::transit_received::{
    fact::{TransitReceivedFact, TRANSIT_KIND_BOOTSTRAP},
    layout as received_layout, matchers as received_matchers,
};

fn invite_fact() -> (InviteSecretFact, Fact) {
    let invite = InviteSecretFact::new([55; 32]);
    let fact = Fact::new(
        FactScope::Local,
        10,
        invite_layout::encode_fact(&invite).expect("encode invite"),
    );
    (invite, fact)
}

fn ephemeral_fact(owner_endpoint: [u8; 32]) -> (ConnectionEphemeralSecretFact, Fact) {
    let private_key = [7u8; 32];
    let secret = ConnectionEphemeralSecretFact {
        owner_endpoint,
        ephemeral_private_key: private_key,
        ephemeral_public_key: crypto::x25519_public_key(&private_key),
        created_at_ms: 11,
    };
    let fact = Fact::new(
        FactScope::Local,
        11,
        ephemeral_layout::encode_fact(&secret).expect("encode ephemeral"),
    );
    (secret, fact)
}

fn signed_request_fact(scope: FactScope) -> (ConnectionRequestFact, Fact, Fact, Fact) {
    let (invite, invite_fact) = invite_fact();
    let (ephemeral, ephemeral_fact) = ephemeral_fact([1; 32]);
    let mut request = ConnectionRequestFact {
        from_endpoint: [1; 32],
        to_endpoint: [2; 32],
        nonce: [3; 32],
        invite_event_id: [4; 32],
        bootstrap_hash: invite.bootstrap_hash,
        invite_signature: [0; ED25519_SIGNATURE_BYTES],
        invite_secret_event_id: invite_fact.id,
        initiator_ephemeral_secret_event_id: ephemeral_fact.id,
        initiator_ephemeral_public_key: ephemeral.ephemeral_public_key,
        from_listen_addr: None,
    };
    request.invite_signature = crypto::ed25519_sign(
        &invite.bootstrap_secret,
        &invite_signing_transcript(&request).expect("transcript"),
    );
    let request_fact = Fact::new(
        scope,
        12,
        layout::encode_fact(&request).expect("encode request"),
    );
    (request, request_fact, invite_fact, ephemeral_fact)
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

fn receive_match(
    owner: [u8; 32],
    request: &ConnectionRequestFact,
    request_id: [u8; 32],
) -> MatchedContext {
    let received = TransitReceivedFact {
        received_fact_id: request_id,
        origin_addr: b"127.0.0.1:41001".to_vec(),
        local_endpoint_id: request.to_endpoint,
        sender_endpoint_id: request.from_endpoint,
        transit_kind: TRANSIT_KIND_BOOTSTRAP,
        connection_id: None,
        request_id: Some(request_id),
        frame_hash: [9; 32],
        received_at_local_ms: 1_700_000_000,
    };
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

#[test]
fn local_request_missing_ephemeral_waits_without_row() {
    let (_, request_fact, invite_fact, _) = signed_request_fact(FactScope::Local);
    let context = ProjectionContext::from_matches(vec![invite_match(request_fact.id, invite_fact)]);

    let output = project::ConnectionRequestProjector::new()
        .project(&request_fact, &context)
        .expect("project waits");

    assert!(output.intents.is_empty());
    assert_eq!(output.needs.len(), 2);
    assert!(output
        .needs
        .iter()
        .any(|need| need.role.as_str() == ephemeral_matchers::CONNECTION_EPHEMERAL_SECRET_ROLE));
}

#[test]
fn received_request_missing_provenance_waits_without_row() {
    let (_, request_fact, invite_fact, _) = signed_request_fact(FactScope::Global);
    let context = ProjectionContext::from_matches(vec![invite_match(request_fact.id, invite_fact)]);

    let output = project::ConnectionRequestProjector::new()
        .project(&request_fact, &context)
        .expect("project waits");

    assert!(output.intents.is_empty());
    assert_eq!(output.needs.len(), 2);
    assert!(output
        .needs
        .iter()
        .any(|need| need.role == received_matchers::transit_received_role()));
}

#[test]
fn local_request_materializes_after_invite_and_ephemeral_context_match() {
    let (request, request_fact, invite_fact, ephemeral_fact) =
        signed_request_fact(FactScope::Local);
    let context = ProjectionContext::from_matches(vec![
        invite_match(request_fact.id, invite_fact),
        ephemeral_match(request_fact.id, ephemeral_fact),
    ]);

    let output = project::ConnectionRequestProjector::new()
        .project(&request_fact, &context)
        .expect("project request");

    assert_eq!(output.intents.len(), 1);
    assert_eq!(output.offers.len(), 1);
    assert_eq!(
        output.offers[0].role.as_str(),
        request_matchers::CONNECTION_REQUEST_ROLE
    );
    let AtomicIntent::PutRow(row) =
        AtomicIntent::from_intent(&output.intents[0], &[rows::CONNECTION_REQUEST_ROWS])
            .expect("row intent")
    else {
        panic!("expected put_row intent");
    };
    let row = rows::decode_connection_request_row(&row.key, &row.value)
        .expect("decode connection request row");
    assert_eq!(row.request_id, request_fact.id);
    assert_eq!(row.from_endpoint, request.from_endpoint);
    assert_eq!(row.to_endpoint, request.to_endpoint);
    assert_eq!(row.invite_event_id, request.invite_event_id);
    assert_eq!(row.invite_secret_event_id, request.invite_secret_event_id);
    assert_eq!(
        row.initiator_ephemeral_secret_event_id,
        request.initiator_ephemeral_secret_event_id
    );
}

#[test]
fn received_request_materializes_after_invite_and_provenance_context_match() {
    let (request, request_fact, invite_fact, _) = signed_request_fact(FactScope::Global);
    let context = ProjectionContext::from_matches(vec![
        invite_match(request_fact.id, invite_fact),
        receive_match(request_fact.id, &request, request_fact.id),
    ]);

    let output = project::ConnectionRequestProjector::new()
        .project(&request_fact, &context)
        .expect("project received request");

    assert_eq!(output.intents.len(), 1);
    assert_eq!(
        output.offers[0].role.as_str(),
        request_matchers::CONNECTION_REQUEST_ROLE
    );
}

#[test]
fn connection_request_projector_rejects_self_loop() {
    let (mut request, _, _, _) = signed_request_fact(FactScope::Local);
    request.to_endpoint = request.from_endpoint;
    let fact = Fact::new(
        FactScope::Local,
        0,
        layout::encode_fact(&request).expect("encode request"),
    );
    let err = project::ConnectionRequestProjector::new()
        .project(&fact, &ProjectionContext::new(Vec::new()))
        .expect_err("self-loop request must fail projection");
    assert!(err.contains("endpoints"), "{err}");
}

#[test]
fn connection_request_projector_rejects_malformed_bytes() {
    let fact = Fact::new(FactScope::Local, 0, vec![0; 4]);
    let err = project::ConnectionRequestProjector::new()
        .project(&fact, &ProjectionContext::new(Vec::new()))
        .expect_err("malformed bytes must fail projection");
    assert!(
        err.contains("connection request") || err.contains("Length"),
        "{err}"
    );
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
    Ok(out)
}
