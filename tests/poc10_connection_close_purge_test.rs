//! Black-box connection close cleanup tests.

use std::cell::Cell;

use topo::core::command::CommandClock;
use topo::core::crypto;
use topo::core::facts::{Fact, FactScope};
use topo::core::runtime::Runtime;
use topo::protocol::app::MATCH_RUNTIME;
use topo::protocol::auth::endpoint::{encode as endpoint_layout, fact::EndpointFact};
use topo::protocol::auth::invite_secret::project::decode as invite_layout;
use topo::protocol::connection::close::commands::close;
use topo::protocol::connection::connection::{
    author::{build_responder_connection, BuildResponderConnection},
    CONNECTION_ROWS,
};
use topo::protocol::connection::ephemeral_secret::encode as ephemeral_layout_encode;
use topo::protocol::connection::ephemeral_secret::project::decode as ephemeral_layout_decode;
use topo::protocol::connection::ephemeral_secret::{
    fact::ConnectionEphemeralSecretFact, CONNECTION_EPHEMERAL_SECRET_ROWS,
};
use topo::protocol::connection::frame_observation;
use topo::protocol::connection::request::commands::{
    create_bootstrap, CreateBootstrapConnectionRequest,
};
use topo::protocol::connection::request::project::decode as request_layout;

struct FixedClock(Cell<u64>);

impl CommandClock for FixedClock {
    fn next_timestamp(&self) -> u64 {
        let next = self.0.get();
        self.0.set(next + 1);
        next
    }
}

#[test]
fn closing_connection_purges_connection_fact_and_row() {
    let mut runtime = Runtime::open_memory(&MATCH_RUNTIME).expect("runtime");
    let alice = endpoint([11; 32], [12; 32]);
    let bob = endpoint([21; 32], [22; 32]);
    let alice_endpoint_fact = Fact::new(
        FactScope::Local,
        999,
        endpoint_layout::encode_fact(&alice).expect("encode alice endpoint"),
    );

    let request_output = create_bootstrap(CreateBootstrapConnectionRequest {
        created_at_ms: 1_000,
        local_endpoint: alice,
        remote_endpoint: bob.endpoint,
        bootstrap_secret: [31; 32],
        workspace_id: None,
        invite_fact_id: [32; 32],
        dialed_addr: "127.0.0.1:41002".parse().expect("peer addr"),
        initiator_addr: None,
    })
    .expect("create request");
    let initiator_ephemeral_id = request_output.receipt.initiator_ephemeral_secret_id;
    let request_id = request_output.receipt.request_id;
    let invite_fact = request_output.facts[0].clone();
    let initiator_ephemeral_fact = request_output.facts[1].clone();
    let request_fact = request_output.facts[2].clone();
    let invite = invite_layout::decode_fact(&invite_fact.bytes).expect("decode invite");
    let initiator_ephemeral = ephemeral_layout_decode::decode_fact(&initiator_ephemeral_fact.bytes)
        .expect("decode initiator ephemeral");
    let request = request_layout::open_fact_as_sender(&request_fact.bytes, &initiator_ephemeral)
        .expect("open request as sender");

    runtime
        .submit_facts([alice_endpoint_fact])
        .expect("submit local endpoint");
    runtime
        .submit_command_output(request_output)
        .expect("submit request");
    runtime
        .process_projection_until_idle(8, 64)
        .expect("project request");

    let responder_ephemeral_private_key = [41; 32];
    let responder_ephemeral = ConnectionEphemeralSecretFact {
        owner_endpoint: bob.endpoint,
        ephemeral_private_key: responder_ephemeral_private_key,
        ephemeral_public_key: crypto::x25519_public_key(&responder_ephemeral_private_key),
        created_at_ms: 1_001,
    };
    let responder_ephemeral_fact = Fact::new(
        FactScope::Local,
        1_001,
        ephemeral_layout_encode::encode_fact(&responder_ephemeral)
            .expect("encode responder ephemeral"),
    );
    let responder_ephemeral_id = responder_ephemeral_fact.id;
    let connection = build_responder_connection(BuildResponderConnection {
        request_id,
        request: &request,
        invite: Some(&invite),
        endpoint: &bob,
        responder_ephemeral_private_key,
        responder_ephemeral_secret_fact_id: responder_ephemeral_id,
        responder_addr: Some("127.0.0.1:41002".parse().expect("responder addr")),
        initiator_addr: None,
        created_at_ms: 1_002,
    })
    .expect("build connection");
    let connection_fact = connection.fact;
    let connection_observation_fact = frame_observation::author::fact_from_observation(
        connection_fact.id,
        b"127.0.0.1:41002",
        1_003,
    )
    .expect("connection observation");
    let connection_id = connection_fact.id;

    runtime
        .submit_facts([connection_fact.clone(), connection_observation_fact])
        .expect("submit connection");
    runtime
        .process_projection_until_idle(8, 64)
        .expect("project connection");

    assert!(runtime
        .facts()
        .any(|fact| fact.id == initiator_ephemeral_id));
    assert!(!runtime
        .facts()
        .any(|fact| fact.id == responder_ephemeral_id));
    assert!(runtime.facts().any(|fact| fact.id == connection_id));
    assert_eq!(
        runtime
            .store()
            .table_row_count(CONNECTION_EPHEMERAL_SECRET_ROWS)
            .expect("secret rows"),
        1
    );
    assert_eq!(
        runtime
            .store()
            .table_row_count(CONNECTION_ROWS)
            .expect("connection rows"),
        1
    );

    let clock = FixedClock(Cell::new(2_000));
    let close_output = close(&clock, connection_id).expect("close connection");
    runtime
        .submit_command_output(close_output)
        .expect("submit close");
    runtime
        .process_all_work_until_idle(16, 64)
        .expect("close cleanup");

    assert!(runtime
        .facts()
        .any(|fact| fact.id == initiator_ephemeral_id));
    assert!(!runtime
        .facts()
        .any(|fact| fact.id == responder_ephemeral_id));
    assert!(!runtime.facts().any(|fact| fact.id == connection_id));
    assert_eq!(
        runtime
            .store()
            .table_row_count(CONNECTION_EPHEMERAL_SECRET_ROWS)
            .expect("secret rows after close"),
        1
    );
    assert_eq!(
        runtime
            .store()
            .table_row_count(CONNECTION_ROWS)
            .expect("connection rows after close"),
        0
    );
    assert_eq!(runtime.pending_fact_count(), 0);
    assert_eq!(runtime.pending_intent_count(), 0);

    assert!(
        runtime.facts().any(|fact| fact.id == request_fact.id),
        "closing the connection must not purge the request history"
    );
    assert_eq!(initiator_ephemeral_fact.id, initiator_ephemeral_id);
}

fn endpoint(secret: [u8; 32], signing_secret: [u8; 32]) -> EndpointFact {
    EndpointFact {
        endpoint: crypto::x25519_public_key(&secret),
        secret,
        signing_public_key: crypto::ed25519_public_key(&signing_secret),
        signing_secret,
    }
}
