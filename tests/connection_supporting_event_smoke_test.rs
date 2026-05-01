//! Smoke tests for Phase 2 connection-related event types.
//!
//! Per task spec: encode -> parse round-trip and project-then-assert-row
//! for each new event type. Unit-style — these are not full pipeline
//! integration tests; they exercise the wire codec and the projector
//! contract in isolation.
//!
//! Modules covered (plan.md lines 204-218):
//! - connection_prekey
//! - connection_prekey_shared
//! - intro
//! - observed_address
//! - self_address
//! - negentropy (wire only — no durable state)
//! - sync_window (wire only — no durable state)

use ed25519_dalek::{Signer, SigningKey};
use rusqlite::Connection;
use topo::event_modules::connection;

fn open_db() -> Connection {
    Connection::open_in_memory().unwrap()
}

/// Deterministic signing key for tests. NOT SECURE — fixed seed.
fn signing_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

#[test]
fn connection_prekey_round_trip_and_project() {
    use connection::connection_prekey::{encode, parse, project, ConnectionPrekeyEvent};

    let sk = signing_key(0xA1);
    let endpoint_id = sk.verifying_key().to_bytes();

    let mut ev = ConnectionPrekeyEvent {
        prekey_id: [0xAB; 32],
        endpoint_id,
        private_key: [0x10; 32],
        public_key: [0x11; 32],
        created_at_ms: 1234,
        ttl_ms: 60_000,
        signature: [0; 64],
    };
    let sig = sk.sign(&ev.signing_bytes());
    ev.signature = sig.to_bytes();

    // Round trip.
    let blob = encode(&ev);
    let parsed = parse(&blob).expect("parse ok");
    assert_eq!(parsed, ev);

    // Project + assert row.
    let db = open_db();
    project(&db, &ev).expect("project ok");
    let count: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM connection_prekeys WHERE prekey_id = ?1",
            [&ev.prekey_id[..]],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(count, 1);
}

#[test]
fn connection_prekey_shared_round_trip_and_project() {
    use connection::connection_prekey_shared::{
        encode, parse, project, ConnectionPrekeySharedEvent,
    };

    let sk = signing_key(0xA2);
    let endpoint_id = sk.verifying_key().to_bytes();

    let mut ev = ConnectionPrekeySharedEvent {
        prekey_id: [0xCD; 32],
        endpoint_id,
        public_key: [0x22; 32],
        created_at_ms: 5678,
        ttl_ms: 60_000,
        signature: [0; 64],
    };
    ev.signature = sk.sign(&ev.signing_bytes()).to_bytes();

    let blob = encode(&ev);
    let parsed = parse(&blob).expect("parse ok");
    assert_eq!(parsed, ev);

    let db = open_db();
    project(&db, &ev).expect("project ok");
    let count: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM connection_prekeys_shared WHERE prekey_id = ?1",
            [&ev.prekey_id[..]],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(count, 1);
}

#[test]
fn intro_round_trip_and_project() {
    use connection::intro::{encode, parse, project, IntroAddress, IntroEvent};

    let sk = signing_key(0xA3);
    let signed_by = sk.verifying_key().to_bytes();

    let mut ev = IntroEvent {
        subject_a_endpoint_id: [11; 32],
        subject_b_endpoint_id: [22; 32],
        addresses_a: vec![IntroAddress {
            ip: [10; 16],
            port: 4433,
        }],
        addresses_b: vec![IntroAddress {
            ip: [20; 16],
            port: 7777,
        }],
        created_at_ms: 100,
        signed_by,
        signature: [0; 64],
    };
    ev.signature = sk.sign(&ev.signing_bytes()).to_bytes();

    let blob = encode(&ev);
    let parsed = parse(&blob).expect("parse ok");
    assert_eq!(parsed, ev);

    let db = open_db();
    project(&db, &ev).expect("project ok");
    let count: i64 = db
        .query_row("SELECT COUNT(*) FROM intros", [], |r| r.get(0))
        .unwrap();
    // Expect two rows: one per (subject, address) tuple.
    assert_eq!(count, 2);
}

#[test]
fn observed_address_round_trip_and_project() {
    use connection::observed_address::{encode, parse, project, ObservedAddressEvent};

    let sk = signing_key(0xA4);
    let observer = sk.verifying_key().to_bytes();

    let mut ev = ObservedAddressEvent {
        observer_endpoint_id: observer,
        subject_endpoint_id: [99; 32],
        ip: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
        port: 4433,
        observed_at_ms: 1000,
        ttl_ms: 60_000,
        signed_by: observer,
        signature: [0; 64],
    };
    ev.signature = sk.sign(&ev.signing_bytes()).to_bytes();

    let blob = encode(&ev);
    let parsed = parse(&blob).expect("parse ok");
    assert_eq!(parsed, ev);

    let db = open_db();
    project(&db, &ev).expect("project ok");
    let count: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM observed_addresses WHERE subject_endpoint_id = ?1",
            [&ev.subject_endpoint_id[..]],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(count, 1);
}

#[test]
fn self_address_round_trip_and_project() {
    use connection::self_address::{encode, parse, project, SelfAddressEvent};

    let sk = signing_key(0xA5);
    let endpoint_id = sk.verifying_key().to_bytes();

    let mut ev = SelfAddressEvent {
        endpoint_id,
        ip: [10; 16],
        port: 4433,
        created_at_ms: 1000,
        ttl_ms: 60_000,
        signed_by: endpoint_id,
        signature: [0; 64],
    };
    ev.signature = sk.sign(&ev.signing_bytes()).to_bytes();

    let blob = encode(&ev);
    let parsed = parse(&blob).expect("parse ok");
    assert_eq!(parsed, ev);

    let db = open_db();
    project(&db, &ev).expect("project ok");
    let count: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM self_addresses WHERE endpoint_id = ?1",
            [&ev.endpoint_id[..]],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(count, 1);
}

#[test]
fn negentropy_round_trip_and_project_noop() {
    use connection::negentropy::{encode, parse, project, NegentropyEvent};

    let ev = NegentropyEvent {
        connection_id: [3; 32],
        workspace_id: [4; 32],
        node_id: vec![0x01, 0x02, 0x03],
        fingerprint: [0xAB; 32],
        created_at_ms: 5000,
    };

    let blob = encode(&ev);
    let parsed = parse(&blob).expect("parse ok");
    assert_eq!(parsed, ev);

    // Wire-only: project is a no-op and returns Ok(()). Just confirm it
    // does not error and does not require any pre-existing schema.
    let db = open_db();
    project(&db, &ev).expect("noop project ok");
}

#[test]
fn sync_window_round_trip_and_project_noop() {
    use connection::sync_window::{encode, parse, project, SyncWindowEvent, SyncWindowKind};

    let ev = SyncWindowEvent {
        connection_id: [5; 32],
        workspace_id: [6; 32],
        kind: SyncWindowKind::Recent,
        begin_ms: 100,
        end_ms: 200,
        created_at_ms: 300,
    };

    let blob = encode(&ev);
    let parsed = parse(&blob).expect("parse ok");
    assert_eq!(parsed, ev);

    let db = open_db();
    project(&db, &ev).expect("noop project ok");
}
