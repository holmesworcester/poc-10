use topo::core::crypto::{self, ED25519_SIGNATURE_BYTES};
use topo::core::facts::{Fact, FactScope};
use topo::core::intents::AtomicIntent;
use topo::core::projection::{MatchedContext, ProjectionContext, Projector};
use topo::event_modules::connection_ephemeral_secret::{
    fact::ConnectionEphemeralSecretFact, layout as ephemeral_layout, matchers as ephemeral_context,
};
use topo::event_modules::connection_request::{
    addr::encode_optional_addr, fact::ConnectionRequestFact, layout as request_layout,
    matchers as request_context,
};
use topo::event_modules::connection_response::{create, layout, project, rows};
use topo::event_modules::identity_endpoint::fact::EndpointFact;
use topo::event_modules::identity_invite::{fact::InviteSecretFact, layout as invite_layout};
use topo::event_modules::transit_received::{
    fact::{TransitReceivedFact, TRANSIT_KIND_CONNECTION_HANDSHAKE},
    layout as received_layout, matchers as received_context,
};

struct Scenario {
    request_fact: Fact,
    invite_fact: Fact,
    initiator_ephemeral_fact: Fact,
    responder_ephemeral_fact: Fact,
    response_fact: Fact,
}

fn scenario() -> Scenario {
    let invite = InviteSecretFact::new([55; 32]);
    let invite_fact = Fact::new(
        FactScope::Local,
        10,
        invite_layout::encode_fact(&invite).expect("encode invite"),
    );
    let initiator_endpoint = crypto::x25519_public_key(&[11; 32]);
    let responder_static = [22; 32];
    let responder_endpoint = crypto::x25519_public_key(&responder_static);
    let (initiator_ephemeral, initiator_ephemeral_fact) =
        ephemeral_fact(initiator_endpoint, [33; 32], 11);
    let (responder_ephemeral, responder_ephemeral_fact) =
        ephemeral_fact(responder_endpoint, [44; 32], 12);
    let mut request = ConnectionRequestFact {
        from_endpoint: initiator_endpoint,
        to_endpoint: responder_endpoint,
        nonce: [77; 32],
        invite_event_id: [88; 32],
        bootstrap_hash: invite.bootstrap_hash,
        invite_signature: [0; ED25519_SIGNATURE_BYTES],
        invite_secret_event_id: invite_fact.id,
        initiator_ephemeral_secret_event_id: initiator_ephemeral_fact.id,
        initiator_ephemeral_public_key: initiator_ephemeral.ephemeral_public_key,
        from_listen_addr: None,
    };
    request.invite_signature = crypto::ed25519_sign(
        &invite.bootstrap_secret,
        &invite_signing_transcript(&request).expect("transcript"),
    );
    let request_fact = Fact::new(
        FactScope::Global,
        13,
        request_layout::encode_fact(&request).expect("encode request"),
    );
    let endpoint = EndpointFact {
        endpoint: responder_endpoint,
        secret: responder_static,
        signing_public_key: crypto::ed25519_public_key(&[99; 32]),
        signing_secret: [99; 32],
    };
    let built = create::build_responder_response(create::BuildResponderResponse {
        request_id: request_fact.id,
        request: &request,
        invite: &invite,
        endpoint: &endpoint,
        responder_ephemeral_private_key: responder_ephemeral.ephemeral_private_key,
        responder_ephemeral_secret_event_id: responder_ephemeral_fact.id,
        created_at_ms: 14,
    })
    .expect("build response");
    Scenario {
        request_fact,
        invite_fact,
        initiator_ephemeral_fact,
        responder_ephemeral_fact,
        response_fact: built.fact,
    }
}

fn ephemeral_fact(
    owner_endpoint: [u8; 32],
    private_key: [u8; 32],
    timestamp: u64,
) -> (ConnectionEphemeralSecretFact, Fact) {
    let secret = ConnectionEphemeralSecretFact {
        owner_endpoint,
        ephemeral_private_key: private_key,
        ephemeral_public_key: crypto::x25519_public_key(&private_key),
        created_at_ms: timestamp,
    };
    let fact = Fact::new(
        FactScope::Local,
        timestamp,
        ephemeral_layout::encode_fact(&secret).expect("encode ephemeral"),
    );
    (secret, fact)
}

fn request_match(owner: [u8; 32], request: Fact) -> MatchedContext {
    MatchedContext {
        need: request_context::connection_request_need(owner, request.id),
        offer: request_context::connection_request_offer(request.id, request.id),
        payload: request,
    }
}

fn invite_match(owner: [u8; 32], invite: Fact) -> MatchedContext {
    MatchedContext {
        need: request_context::invite_secret_need(owner, invite.id),
        offer: request_context::invite_secret_offer(invite.id, invite.id),
        payload: invite,
    }
}

fn ephemeral_match(owner: [u8; 32], ephemeral: Fact) -> MatchedContext {
    MatchedContext {
        need: ephemeral_context::connection_ephemeral_secret_need(owner, ephemeral.id),
        offer: ephemeral_context::connection_ephemeral_secret_offer(ephemeral.id, ephemeral.id),
        payload: ephemeral,
    }
}

fn receive_match(
    owner: [u8; 32],
    response_id: [u8; 32],
    request_id: [u8; 32],
    response: &topo::event_modules::connection_response::fact::ConnectionResponseFact,
) -> MatchedContext {
    let received = TransitReceivedFact {
        received_fact_id: response_id,
        origin_addr: b"127.0.0.1:41002".to_vec(),
        local_endpoint_id: response.to_endpoint,
        sender_endpoint_id: response.from_endpoint,
        transit_kind: TRANSIT_KIND_CONNECTION_HANDSHAKE,
        connection_id: Some(response_id),
        request_id: Some(request_id),
        frame_hash: [8; 32],
        received_at_local_ms: 1_700_000_001,
    };
    let fact = Fact::new(
        FactScope::Local,
        15,
        received_layout::encode_fact(&received).expect("encode provenance"),
    );
    MatchedContext {
        need: received_context::transit_received_need(owner, response_id),
        offer: received_context::transit_received_offer(fact.id, response_id),
        payload: fact,
    }
}

#[test]
fn response_missing_request_waits_without_row() {
    let scenario = scenario();
    let context = ProjectionContext::from_matches(vec![
        invite_match(scenario.response_fact.id, scenario.invite_fact),
        ephemeral_match(scenario.response_fact.id, scenario.responder_ephemeral_fact),
    ]);

    let output = project::ConnectionResponseProjector::new()
        .project(&scenario.response_fact, &context)
        .expect("project waits");

    assert!(output.intents.is_empty());
    assert!(output
        .needs
        .iter()
        .any(|need| need.role == request_context::connection_request_role()));
}

#[test]
fn local_response_materializes_after_request_invite_and_responder_ephemeral_context() {
    let scenario = scenario();
    let context = ProjectionContext::from_matches(vec![
        request_match(scenario.response_fact.id, scenario.request_fact.clone()),
        invite_match(scenario.response_fact.id, scenario.invite_fact.clone()),
        ephemeral_match(
            scenario.response_fact.id,
            scenario.responder_ephemeral_fact.clone(),
        ),
    ]);

    let output = project::ConnectionResponseProjector::new()
        .project(&scenario.response_fact, &context)
        .expect("project response");

    assert_eq!(output.intents.len(), 1);
    let AtomicIntent::PutRow(row) =
        AtomicIntent::from_intent(&output.intents[0], &[rows::CONNECTION_RESPONSE_ROWS])
            .expect("row intent")
    else {
        panic!("expected put_row intent");
    };
    let response = layout::decode_fact(&scenario.response_fact.bytes).expect("decode response");
    let row = rows::decode_connection_response_row(&row.key, &row.value)
        .expect("decode connection response row");
    assert_eq!(row.connection_id, scenario.response_fact.id);
    assert_eq!(row.from_endpoint, response.from_endpoint);
    assert_eq!(row.to_endpoint, response.to_endpoint);
    assert_eq!(row.request_id, response.request_id);
    assert_eq!(
        row.responder_ephemeral_public_key,
        response.responder_ephemeral_public_key
    );
    assert_eq!(row.handshake_hash, response.handshake_hash);
    assert_eq!(row.connection_secret, response.connection_secret);
}

#[test]
fn received_response_materializes_after_provenance_and_initiator_ephemeral_context() {
    let scenario = scenario();
    let response = layout::decode_fact(&scenario.response_fact.bytes).expect("decode response");
    let context = ProjectionContext::from_matches(vec![
        request_match(scenario.response_fact.id, scenario.request_fact.clone()),
        invite_match(scenario.response_fact.id, scenario.invite_fact.clone()),
        ephemeral_match(
            scenario.response_fact.id,
            scenario.initiator_ephemeral_fact.clone(),
        ),
        receive_match(
            scenario.response_fact.id,
            scenario.response_fact.id,
            scenario.request_fact.id,
            &response,
        ),
    ]);

    let output = project::ConnectionResponseProjector::new()
        .project(&scenario.response_fact, &context)
        .expect("project received response");

    assert_eq!(output.intents.len(), 1);
    let AtomicIntent::PutRow(row) =
        AtomicIntent::from_intent(&output.intents[0], &[rows::CONNECTION_RESPONSE_ROWS])
            .expect("row intent")
    else {
        panic!("expected put_row intent");
    };
    let row = rows::decode_connection_response_row(&row.key, &row.value)
        .expect("decode connection response row");
    assert_eq!(row.connection_id, scenario.response_fact.id);
    assert_eq!(row.to_endpoint, response.to_endpoint);
}

#[test]
fn connection_response_projector_rejects_self_loop_endpoints() {
    let mut response = layout::decode_fact(&scenario().response_fact.bytes).expect("response");
    response.to_endpoint = response.from_endpoint;
    let fact = Fact::new(
        FactScope::Local,
        0,
        layout::encode_fact(&response).expect("encode response"),
    );
    let err = project::ConnectionResponseProjector::new()
        .project(&fact, &ProjectionContext::new(Vec::new()))
        .expect_err("self-loop endpoints must fail projection");
    assert!(err.contains("endpoints"), "{err}");
}

#[test]
fn connection_response_projector_rejects_malformed_bytes() {
    let fact = Fact::new(FactScope::Local, 0, vec![0; 4]);
    let err = project::ConnectionResponseProjector::new()
        .project(&fact, &ProjectionContext::new(Vec::new()))
        .expect_err("malformed bytes must fail projection");
    assert!(
        err.contains("connection response") || err.contains("Length"),
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
