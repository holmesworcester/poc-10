//! End-to-end integration test for the transport→bridge→chain seam.
//!
//! Validates: TCP accept → bytes → InboundFrame → bridge writes
//! `inbound_bytes(pending)` → wakes dispatcher → dispatcher drains via
//! `handle_inbound_bytes_for_claimed_in_tx` → unwrap → admit → parse →
//! context → project → apply. Uses two `transport_v2` endpoints on
//! localhost, one wraps a single signed `TenantEvent` via
//! `connection.wrap_bootstrap` (which does not need pre-existing
//! connection_secrets state), sends it over the wire, and asserts it
//! surfaces in `events_canonical` with `status = applied` plus a row in
//! the tenant projector's `tenants` table.
//!
//! Plan-rework D: this test used to install the bridge against a bare
//! `Mutex<Connection>` (the old bridge ran the chain inline). Now the
//! bridge is just a writer-of-`inbound_bytes` and the dispatcher does
//! the chain, so we wire the test through `ControlLoopRuntime::start`
//! to get the dispatcher loop spun up.

use std::net::SocketAddr;
use std::str::FromStr;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use topo::event_modules::connection::wrap::{wrap_bootstrap, InnerCanonicalEvent};
use topo::event_modules::{encode_event, ParsedEvent, TenantEvent};
use topo::runtime::control_loop::work_item::BlakeId;
use topo::runtime::control_loop::ControlLoopRuntime;
use topo::runtime::transport_v2::{send as transport_send, AddressBook, SocketCache};
use topo::state::events_canonical::{get as get_event, EventStatus};

fn tenant_blob() -> Vec<u8> {
    let e = TenantEvent {
        created_at_ms: 4_242,
        public_key: [0xCAu8; 32],
    };
    encode_event(&ParsedEvent::Tenant(e)).unwrap()
}

fn blake3_id(bytes: &[u8]) -> BlakeId {
    let mut id = [0u8; 32];
    id.copy_from_slice(blake3::hash(bytes).as_bytes());
    id
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn transport_to_inbound_chain_end_to_end() {
    // Real Ed25519 keypairs for both sides — required because the
    // bootstrap unwrap path now does X25519 ECDH against the recipient's
    // private key.
    let sender_sk = SigningKey::from_bytes(&[0x11u8; 32]);
    let recipient_sk = SigningKey::from_bytes(&[0x22u8; 32]);
    let sender_eid = sender_sk.verifying_key().to_bytes();
    let recipient_eid = recipient_sk.verifying_key().to_bytes();

    // Receiver side ("daemon B"): start a full ControlLoopRuntime so
    // the dispatcher loop drains inbound_bytes the bridge writes.
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("transport_chain.db");
    // Persist the recipient's signing key in the same sidecar file the
    // production binary writes — the inbound chain reads it on demand.
    let signkey_path = {
        let mut p = db_path.clone();
        let stem = p
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| "topo.db".to_string());
        p.set_file_name(format!(".{}.signkey", stem));
        p
    };
    std::fs::write(&signkey_path, recipient_sk.to_bytes()).expect("write signkey");

    let bind: SocketAddr = SocketAddr::from_str("127.0.0.1:0").unwrap();
    let handles = ControlLoopRuntime::start(bind, recipient_eid, &db_path)
        .await
        .expect("runtime start");
    let recipient_addr = handles.runtime.listen_addr;
    let db = handles.runtime.db.clone();

    // Sender side ("daemon A"): build a real OutboundFrame via
    // wrap_bootstrap carrying a single TenantEvent.
    let blob = tenant_blob();
    let inner_event_id = blake3_id(&blob);
    let inner = vec![InnerCanonicalEvent {
        workspace_id: [0u8; 32],
        bytes: blob,
    }];
    let frame = wrap_bootstrap(&sender_sk, recipient_eid, &inner)
        .expect("wrap_bootstrap");

    let book = AddressBook::new();
    book.insert(recipient_eid, recipient_addr);
    let cache = SocketCache::new();
    transport_send(
        &cache,
        &book,
        sender_eid,
        recipient_eid,
        frame,
    )
    .await
    .expect("transport_send");

    // Poll the receiver DB until the inner event surfaces.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let mut applied = false;
    while std::time::Instant::now() < deadline {
        {
            let g = db.lock().await;
            if let Some(row) = get_event(&g, &inner_event_id).unwrap() {
                if row.status == EventStatus::Applied {
                    applied = true;
                    break;
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    if !applied {
        let g = db.lock().await;
        let n_inbound: i64 = g
            .query_row("SELECT COUNT(*) FROM inbound_bytes", [], |r| r.get(0))
            .unwrap();
        let n_events: i64 = g
            .query_row("SELECT COUNT(*) FROM events_canonical", [], |r| r.get(0))
            .unwrap();
        drop(g);
        let _ = ControlLoopRuntime::shutdown(handles).await;
        panic!(
            "timed out waiting for inner event to apply: inbound_bytes={}, events_canonical={}",
            n_inbound, n_events,
        );
    }

    // Assert the side effects on the tenant projector.
    {
        let g = db.lock().await;
        let tenants: i64 = g
            .query_row("SELECT COUNT(*) FROM tenants", [], |r| r.get(0))
            .unwrap();
        assert_eq!(
            tenants, 1,
            "tenant projector should have written a row from the wire frame"
        );

        let row = get_event(&g, &inner_event_id).unwrap().expect("event row");
        assert_eq!(row.status, EventStatus::Applied);
    }

    ControlLoopRuntime::shutdown(handles)
        .await
        .expect("shutdown ok");
}
