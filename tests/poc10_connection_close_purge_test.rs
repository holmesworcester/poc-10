//! Black-box connection close cleanup tests.

use std::cell::Cell;

use topo::core::command_context::{
    CommandClock, IdentityVault, LocalEncryptionCapability, LocalSigningCapability, WorkspaceId,
};
use topo::core::crypto;
use topo::core::facts::{Fact, FactScope};
use topo::core::runtime::Runtime;
use topo::protocol::app::MATCH_RUNTIME;
use topo::protocol::auth::endpoint::fact::EndpointFact;
use topo::protocol::auth::invite::layout as invite_layout;
use topo::protocol::connection::close::commands::close;
use topo::protocol::connection::ephemeral_secret::{
    fact::ConnectionEphemeralSecretFact, layout as ephemeral_layout,
    rows::CONNECTION_EPHEMERAL_SECRET_ROWS,
};
use topo::protocol::connection::fact_receipt::{
    fact::{ConnectionFactReceipt, RECEIVE_PATH_CONNECTION_RESPONSE},
    layout as receipt_layout,
};
use topo::protocol::connection::request::{
    commands::{create as create_request, CreateConnectionRequest},
    layout as request_layout,
};
use topo::protocol::connection::response::{
    create::{build_responder_response, BuildResponderResponse},
    rows::CONNECTION_RESPONSE_ROWS,
};

struct FixedClock(Cell<u64>);

impl CommandClock for FixedClock {
    fn next_timestamp(&self) -> u64 {
        let next = self.0.get();
        self.0.set(next + 1);
        next
    }
}

struct EmptyVault;

impl IdentityVault for EmptyVault {
    fn local_signing_capability(
        &self,
        _workspace_id: WorkspaceId,
    ) -> Result<LocalSigningCapability, String> {
        Err("no signing capability".to_string())
    }

    fn local_encryption_capability(
        &self,
        _workspace_id: WorkspaceId,
    ) -> Result<LocalEncryptionCapability, String> {
        Err("no encryption capability".to_string())
    }
}

#[test]
fn closing_connection_purges_ephemeral_secret_facts_and_rows() {
    let mut runtime = Runtime::open_memory(&MATCH_RUNTIME).expect("runtime");
    let alice = endpoint([11; 32], [12; 32]);
    let bob = endpoint([21; 32], [22; 32]);

    let request_output = create_request(CreateConnectionRequest {
        created_at_ms: 1_000,
        local_endpoint: alice,
        remote_endpoint: bob.endpoint,
        bootstrap_secret: [31; 32],
        workspace_id: None,
        invite_fact_id: [32; 32],
        from_listen_addr: None,
        to_listen_addr: None,
    })
    .expect("create request");
    let initiator_ephemeral_id = request_output.receipt.initiator_ephemeral_secret_id;
    let request_id = request_output.receipt.request_id;
    let invite_fact = request_output.effects.facts[0].clone();
    let initiator_ephemeral_fact = request_output.effects.facts[1].clone();
    let request_fact = request_output.effects.facts[2].clone();
    let invite = invite_layout::decode_fact(&invite_fact.bytes).expect("decode invite");
    let request = request_layout::decode_fact(&request_fact.bytes).expect("decode request");

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
        ephemeral_layout::encode_fact(&responder_ephemeral).expect("encode responder ephemeral"),
    );
    let responder_ephemeral_id = responder_ephemeral_fact.id;
    let response = build_responder_response(BuildResponderResponse {
        request_id,
        request: &request,
        invite: &invite,
        endpoint: &bob,
        responder_ephemeral_private_key,
        responder_ephemeral_secret_fact_id: responder_ephemeral_id,
        created_at_ms: 1_002,
    })
    .expect("build response");
    let response_fact = response.fact;
    let response_body = response.response;
    let receipt = ConnectionFactReceipt {
        received_fact_id: response_fact.id,
        origin_addr: b"127.0.0.1:41001".to_vec(),
        local_endpoint_id: response_body.to_endpoint,
        sender_endpoint_id: response_body.from_endpoint,
        receive_path: RECEIVE_PATH_CONNECTION_RESPONSE,
        connection_id: Some(response_fact.id),
        request_id: Some(request_id),
        frame_hash: crypto::hash(&response_fact.bytes),
        received_at_local_ms: 1_003,
    };
    let receipt_fact = Fact::new(
        FactScope::Local,
        1_003,
        receipt_layout::encode_fact(&receipt).expect("encode receipt"),
    );
    let connection_id = response_fact.id;

    runtime
        .submit_facts([
            responder_ephemeral_fact.clone(),
            response_fact.clone(),
            receipt_fact,
        ])
        .expect("submit response");
    runtime
        .process_projection_until_idle(8, 64)
        .expect("project response");

    assert!(runtime
        .facts()
        .any(|fact| fact.id == initiator_ephemeral_id));
    assert!(runtime
        .facts()
        .any(|fact| fact.id == responder_ephemeral_id));
    assert!(runtime.facts().any(|fact| fact.id == connection_id));
    assert_eq!(
        runtime
            .store()
            .table_row_count(CONNECTION_EPHEMERAL_SECRET_ROWS)
            .expect("secret rows"),
        2
    );
    assert_eq!(
        runtime
            .store()
            .table_row_count(CONNECTION_RESPONSE_ROWS)
            .expect("connection rows"),
        1
    );

    let clock = FixedClock(Cell::new(2_000));
    let vault = EmptyVault;
    let close_output = {
        let ctx = runtime.command_context(&clock, &vault);
        close(&ctx, connection_id).expect("close connection")
    };
    runtime
        .submit_command_output(close_output)
        .expect("submit close");
    runtime
        .process_all_work_until_idle(16, 64)
        .expect("close cleanup");

    assert!(!runtime
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
        0
    );
    assert_eq!(
        runtime
            .store()
            .table_row_count(CONNECTION_RESPONSE_ROWS)
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
