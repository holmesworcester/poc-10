//! Behavioural tests for the target `connection_response` handler.
//!
//! Synthesizes a connection_request + invite_secret + local endpoint fact
//! context, drives the handler, and verifies the emitted response fact
//! decodes into a `ConnectionResponseFact` with a non-degenerate connection
//! secret and the request's dependency edges copied through. A second case
//! exercises endpoint mismatch ("wrong workspace" on this lane: the request
//! is addressed to a different endpoint than the local responder fact).

use topo::core::crypto::{self, ED25519_SIGNATURE_BYTES};
use topo::core::facts::{Fact, FactScope};
use topo::core::handler_dispatch::{HandlerContext, IntentHandler};
use topo::event_modules::connection_request::fact::ConnectionRequestFact;
use topo::event_modules::connection_request::layout as request_layout;
use topo::event_modules::connection_response::layout as response_layout;
use topo::event_modules::identity_endpoint::fact::EndpointFact;
use topo::event_modules::identity_endpoint::layout as endpoint_layout;
use topo::event_modules::identity_invite::fact::InviteSecretFact;
use topo::event_modules::identity_invite::layout as invite_layout;
use topo::handlers::connection_response::{
    connection_response_intent, ConnectionResponseHandler, ConnectionResponseIntent,
};

#[test]
fn handler_emits_decodable_response_fact_for_addressed_request() {
    let scenario = synthesize_scenario(SynthOpts::default());
    let handler = ConnectionResponseHandler::new();
    let context = HandlerContext::with_facts([
        scenario.request_fact.clone(),
        scenario.invite_fact.clone(),
        scenario.endpoint_fact.clone(),
    ]);

    let output = handler
        .handle(&scenario.intent, &context)
        .expect("handler produces response fact");

    assert_eq!(output.facts.len(), 1, "exactly one response fact");
    let response = response_layout::decode_fact(&output.facts[0].bytes).expect("decode response");
    assert_eq!(response.request_id, scenario.request_fact.id);
    assert_eq!(response.from_endpoint, scenario.responder_endpoint);
    assert_eq!(response.to_endpoint, scenario.initiator_endpoint);
    assert_eq!(
        response.invite_secret_event_id,
        scenario.invite_secret_event_id
    );
    assert_eq!(
        response.initiator_ephemeral_secret_event_id,
        scenario.initiator_ephemeral_secret_event_id
    );
    assert_eq!(
        response.responder_ephemeral_public_key,
        crypto::x25519_public_key(&scenario.responder_ephemeral_private_key)
    );
    assert_ne!(response.handshake_hash, [0u8; 32]);
    assert_ne!(response.connection_secret, [0u8; 32]);
}

#[test]
fn handler_rejects_request_addressed_to_a_different_endpoint() {
    // The request is addressed `to_endpoint = other_endpoint`, but the local
    // endpoint fact carries a different identity. On this lane this is the
    // "mismatched workspace" rejection: the responder is not the addressed
    // party so cannot complete the handshake.
    let scenario = synthesize_scenario(SynthOpts {
        request_to_endpoint: Some(crypto::x25519_public_key(&[77u8; 32])),
    });
    let handler = ConnectionResponseHandler::new();
    let context = HandlerContext::with_facts([
        scenario.request_fact.clone(),
        scenario.invite_fact.clone(),
        scenario.endpoint_fact.clone(),
    ]);

    let err = handler
        .handle(&scenario.intent, &context)
        .expect_err("handler rejects mismatched request");
    assert!(
        err.contains("endpoint does not match request"),
        "unexpected error: {err}"
    );
}

struct Scenario {
    request_fact: Fact,
    invite_fact: Fact,
    endpoint_fact: Fact,
    intent: topo::core::intents::Intent,
    initiator_endpoint: [u8; 32],
    responder_endpoint: [u8; 32],
    invite_secret_event_id: [u8; 32],
    initiator_ephemeral_secret_event_id: [u8; 32],
    responder_ephemeral_private_key: [u8; 32],
}

#[derive(Default)]
struct SynthOpts {
    /// Override the request's `to_endpoint`. When unset, defaults to the
    /// local responder endpoint, producing the happy path.
    request_to_endpoint: Option<[u8; 32]>,
}

fn synthesize_scenario(opts: SynthOpts) -> Scenario {
    let initiator_static = [11u8; 32];
    let initiator_endpoint = crypto::x25519_public_key(&initiator_static);
    let responder_static = [22u8; 32];
    let responder_endpoint = crypto::x25519_public_key(&responder_static);
    let initiator_ephemeral_private = [33u8; 32];
    let initiator_ephemeral_public = crypto::x25519_public_key(&initiator_ephemeral_private);
    let responder_ephemeral_private = [44u8; 32];

    let bootstrap_secret = [55u8; 32];
    let invite =
        InviteSecretFact::new(bootstrap_secret).validate().expect("invite is well-formed");
    let invite_fact = Fact::new(
        FactScope::Local,
        100,
        invite_layout::encode_fact(&invite).expect("encode invite"),
    );

    let signing_secret = [66u8; 32];
    let endpoint = EndpointFact {
        endpoint: responder_endpoint,
        secret: responder_static,
        signing_public_key: crypto::ed25519_public_key(&signing_secret),
        signing_secret,
    };
    let endpoint_fact = Fact::new(
        FactScope::Local,
        100,
        endpoint_layout::encode_fact(&endpoint).expect("encode endpoint"),
    );

    let request = ConnectionRequestFact {
        from_endpoint: initiator_endpoint,
        to_endpoint: opts.request_to_endpoint.unwrap_or(responder_endpoint),
        nonce: [77u8; 32],
        invite_event_id: [88u8; 32],
        bootstrap_hash: invite.bootstrap_hash,
        invite_signature: [0u8; ED25519_SIGNATURE_BYTES],
        invite_secret_event_id: invite_fact.id,
        initiator_ephemeral_secret_event_id: [99u8; 32],
        initiator_ephemeral_public_key: initiator_ephemeral_public,
        from_listen_addr: None,
    };
    let request_fact = Fact::new(
        FactScope::Global,
        100,
        request_layout::encode_fact(&request).expect("encode request"),
    );

    // Responder ephemeral has no target fact form yet; use the public key
    // hash as a stable placeholder event id.
    let responder_ephemeral_secret_event_id =
        *blake3::hash(&crypto::x25519_public_key(&responder_ephemeral_private)).as_bytes();

    let intent = connection_response_intent(ConnectionResponseIntent {
        request_id: request_fact.id,
        invite_secret_id: invite_fact.id,
        local_endpoint_id: endpoint_fact.id,
        responder_ephemeral_secret_event_id,
        responder_ephemeral_private_key: responder_ephemeral_private,
    });

    Scenario {
        request_fact,
        invite_fact,
        endpoint_fact,
        intent,
        initiator_endpoint,
        responder_endpoint,
        invite_secret_event_id: request.invite_secret_event_id,
        initiator_ephemeral_secret_event_id: request.initiator_ephemeral_secret_event_id,
        responder_ephemeral_private_key: responder_ephemeral_private,
    }
}
