//! Coverage for `state::generic_context::load_generic_context`
//! (plan.md lines 234-240). Verifies that the loader returns the bounded
//! `{event, deps, labels}` view that the new chain hands to projectors —
//! and nothing else.
//!
//! Cases:
//! 1. event with no declared deps and no labels → empty deps + labels.
//! 2. event B declares dep on applied event A → deps map contains A's
//!    canonical bytes keyed by base64(A).
//! 3. dep A carries label "deleted" → labels map contains
//!    `base64(A) -> ["deleted"]`.
//! 4. event E itself is labeled "removed_by:U" → labels contains
//!    `base64(E) -> ["removed_by:U"]`.
//! 5. event B declares dep on missing event A → deps map omits A; the
//!    loader returns successfully (chain blocks on A separately).

use rusqlite::{params, Connection};
use topo::crypto::event_id_to_base64;
use topo::event_modules::{encode_event, ParsedEvent, TenantEvent, MessageDeletionEvent};
use topo::state::db::control_loop_tables::ensure_schema as ensure_substrate_schema;
use topo::state::events_canonical::{
    finalize_admitted, upsert_event, EventRow, EventScope, EventStatus,
};
use topo::state::generic_context::load_generic_context;
use topo::state::labels::write_label;

fn open_db() -> Connection {
    let c = Connection::open_in_memory().unwrap();
    ensure_substrate_schema(&c).unwrap();
    c
}

fn blake3_id(bytes: &[u8]) -> [u8; 32] {
    let mut id = [0u8; 32];
    id.copy_from_slice(blake3::hash(bytes).as_bytes());
    id
}

/// Canonical bytes for a Tenant event with no declared deps. Useful as a
/// "zero-dep" probe for the loader.
fn make_tenant_event(marker: u8) -> (ParsedEvent, Vec<u8>, [u8; 32]) {
    let e = TenantEvent {
        created_at_ms: 1_000 + marker as u64,
        public_key: [marker; 32],
    };
    let pe = ParsedEvent::Tenant(e);
    let bytes = encode_event(&pe).unwrap();
    let id = blake3_id(&bytes);
    (pe, bytes, id)
}

/// Build a MessageDeletion event whose `signed_by` is `signed_by`. The
/// MessageDeletion projector declares one dep field (`signed_by`) per
/// codec.rs, which makes it the simplest one-dep event we can synthesize
/// without juggling cryptographic invariants.
fn make_msg_deletion(target: [u8; 32], signed_by: [u8; 32]) -> (ParsedEvent, Vec<u8>, [u8; 32]) {
    let m = MessageDeletionEvent {
        created_at_ms: 12_345,
        workspace_id: [0u8; 32],
        target_event_id: target,
        author_id: [0x77u8; 32],
        signed_by,
        signer_type: 0,
        signature: [0u8; 64],
    };
    let pe = ParsedEvent::MessageDeletion(m);
    let bytes = encode_event(&pe).unwrap();
    let id = blake3_id(&bytes);
    (pe, bytes, id)
}

fn workspace_id_bytes() -> [u8; 32] {
    [0xA5u8; 32]
}

#[test]
fn load_generic_context_with_no_deps_no_labels() {
    let c = open_db();
    let ws = workspace_id_bytes();

    // Tenant event has dep_field_values() == [] per registry.
    let (pe, bytes, id) = make_tenant_event(0x11);

    // Admit + finalize so events_canonical knows about it.
    upsert_event(
        &c,
        &EventRow {
            event_id: id,
            canonical_event_bytes: bytes,
            workspace_id: Some(ws),
            scope: EventScope::Durable,
            status: EventStatus::Applied,
            created_at_ms: 0,
            expires_at_ms: None,
        },
    )
    .unwrap();

    let ctx = load_generic_context(&pe, &c).expect("load_generic_context");
    assert!(ctx.deps.is_empty(), "expected no deps; got {:?}", ctx.deps);
    assert!(
        ctx.labels.is_empty(),
        "expected no labels; got {:?}",
        ctx.labels
    );
}

#[test]
fn load_generic_context_with_one_dep_returns_dep_event() {
    let c = open_db();
    let ws = workspace_id_bytes();

    // A: applied tenant event used as dep.
    let (_pa, a_bytes, a_id) = make_tenant_event(0xA1);
    upsert_event(
        &c,
        &EventRow {
            event_id: a_id,
            canonical_event_bytes: a_bytes.clone(),
            workspace_id: Some(ws),
            scope: EventScope::Durable,
            status: EventStatus::Applied,
            created_at_ms: 0,
            expires_at_ms: None,
        },
    )
    .unwrap();

    // B: MessageDeletion whose `signed_by` is A. Admitted but not yet
    // applied — caller has just parsed it and is about to project.
    let (pb, b_bytes, b_id) = make_msg_deletion([0u8; 32], a_id);
    upsert_event(
        &c,
        &EventRow {
            event_id: b_id,
            canonical_event_bytes: b_bytes,
            workspace_id: Some(ws),
            scope: EventScope::Durable,
            // Status doesn't matter for the loader — it only reads bytes
            // + workspace.
            status: EventStatus::Processing,
            created_at_ms: 0,
            expires_at_ms: None,
        },
    )
    .unwrap();

    let ctx = load_generic_context(&pb, &c).expect("load_generic_context");
    let a_b64 = event_id_to_base64(&a_id);
    assert_eq!(ctx.deps.len(), 1, "expected exactly one dep entry");
    assert_eq!(
        ctx.deps.get(&a_b64).cloned(),
        Some(a_bytes),
        "dep entry must carry A's canonical bytes"
    );
    // No labels written for either A or B → labels empty.
    assert!(ctx.labels.is_empty());
}

#[test]
fn load_generic_context_with_label_on_dep_propagates() {
    let c = open_db();
    let ws = workspace_id_bytes();
    let ws_b64 = event_id_to_base64(&ws);

    // A: applied. Carries a "deleted" label written via the labels API.
    let (_pa, a_bytes, a_id) = make_tenant_event(0xA2);
    upsert_event(
        &c,
        &EventRow {
            event_id: a_id,
            canonical_event_bytes: a_bytes,
            workspace_id: Some(ws),
            scope: EventScope::Durable,
            status: EventStatus::Applied,
            created_at_ms: 0,
            expires_at_ms: None,
        },
    )
    .unwrap();
    let a_b64 = event_id_to_base64(&a_id);
    write_label(&c, &ws_b64, &a_b64, "deleted").unwrap();

    // B: declares A as dep (signed_by).
    let (pb, b_bytes, b_id) = make_msg_deletion([0u8; 32], a_id);
    upsert_event(
        &c,
        &EventRow {
            event_id: b_id,
            canonical_event_bytes: b_bytes,
            workspace_id: Some(ws),
            scope: EventScope::Durable,
            status: EventStatus::Processing,
            created_at_ms: 0,
            expires_at_ms: None,
        },
    )
    .unwrap();

    let ctx = load_generic_context(&pb, &c).expect("load_generic_context");
    let labels_for_a = ctx
        .labels
        .get(&a_b64)
        .cloned()
        .unwrap_or_default();
    assert_eq!(
        labels_for_a,
        vec!["deleted".to_string()],
        "labels for A must contain 'deleted'; full map: {:?}",
        ctx.labels
    );
}

#[test]
fn load_generic_context_with_label_on_self() {
    let c = open_db();
    let ws = workspace_id_bytes();
    let ws_b64 = event_id_to_base64(&ws);

    // E: tenant event labeled "removed_by:U".
    let (pe, bytes, id) = make_tenant_event(0xE3);
    upsert_event(
        &c,
        &EventRow {
            event_id: id,
            canonical_event_bytes: bytes,
            workspace_id: Some(ws),
            scope: EventScope::Durable,
            status: EventStatus::Applied,
            created_at_ms: 0,
            expires_at_ms: None,
        },
    )
    .unwrap();
    let id_b64 = event_id_to_base64(&id);
    write_label(&c, &ws_b64, &id_b64, "removed_by:U").unwrap();

    let ctx = load_generic_context(&pe, &c).expect("load_generic_context");
    let labels_for_self = ctx.labels.get(&id_b64).cloned().unwrap_or_default();
    assert_eq!(
        labels_for_self,
        vec!["removed_by:U".to_string()],
        "self-label must show up in labels map; got {:?}",
        ctx.labels
    );
    assert!(ctx.deps.is_empty(), "tenant has no deps");
}

#[test]
fn missing_dep_returns_partial_context() {
    let c = open_db();
    let ws = workspace_id_bytes();

    // A is NOT inserted into events_canonical.
    let a_id: [u8; 32] = [0xCC; 32];

    // B declares A as signed_by.
    let (pb, b_bytes, b_id) = make_msg_deletion([0u8; 32], a_id);
    upsert_event(
        &c,
        &EventRow {
            event_id: b_id,
            canonical_event_bytes: b_bytes,
            workspace_id: Some(ws),
            scope: EventScope::Durable,
            status: EventStatus::Processing,
            created_at_ms: 0,
            expires_at_ms: None,
        },
    )
    .unwrap();

    let ctx = load_generic_context(&pb, &c).expect("load_generic_context");
    // Loader does not surface missing deps — it returns a partial context
    // with A absent. The chain's Block path handles missing deps via
    // `add_blockers`/`blocked_by_event`.
    assert!(
        ctx.deps.is_empty(),
        "missing dep must be omitted; got {:?}",
        ctx.deps
    );
    assert!(ctx.labels.is_empty());
}

/// Sanity helper: confirm finalize_admitted is wired (mirrors
/// inbound_chain_test conventions). Not a generic_context test per se,
/// just a regression guard so the test file's preamble assumptions hold.
#[test]
fn helper_finalize_admitted_compiles() {
    let c = open_db();
    let (_pe, bytes, id) = make_tenant_event(0x44);
    // upsert_event takes the place of admit_event_id + finalize_admitted
    // for these unit tests; we only invoke finalize_admitted to make sure
    // the import is exercised.
    let row = EventRow {
        event_id: id,
        canonical_event_bytes: vec![],
        workspace_id: None,
        scope: EventScope::Durable,
        status: EventStatus::Processing,
        created_at_ms: 0,
        expires_at_ms: None,
    };
    upsert_event(&c, &row).unwrap();
    finalize_admitted(
        &c,
        &id,
        &bytes,
        Some(workspace_id_bytes()),
        EventScope::Durable,
        EventStatus::Applied,
    )
    .unwrap();
    let stored: i64 = c
        .query_row(
            "SELECT length(canonical_event_bytes) FROM events_canonical WHERE event_id = ?1",
            params![id.to_vec()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(stored as usize, bytes.len());
}
