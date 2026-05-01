use super::super::ParsedEvent;
use crate::crypto::event_id_to_base64;
use crate::projection::contract::{ContextSnapshot, ProjectorResult, SqlVal, WriteOp};

/// Pure projector: PeerShared -> peers_shared table.
///
/// Plan.md "no scaffolding" rule (Forking plan): the projector sees only
/// `{event, deps, labels}` — no per-event-type SQL on the loader side.
///
/// Validation rules:
/// - Apply the standard label-gate: any `removed_by:*` / `superseded` /
///   `deleted` label on this event id rejects the projection
///   (plan.md §164-170).
/// - The peer's claimed `user_event_id` must match the user identity
///   authorized by the signing device-invite chain. The signer's invite
///   event is reachable via `signed_by` (declared dep); we parse its
///   bytes from `ctx.deps[signed_by]` and check its `authority_event_id`
///   resolves to the same `user_event_id` the PeerShared claims.
/// - Write to `peers_shared` keyed by `(workspace_id, event_id)`.
///
/// We intentionally do NOT delete `invite_bootstrap_trust` here.  The
/// bootstrap trust row doubles as an autodial address record: keeping it alive
/// ensures the leaf can re-dial the hub via the Bootstrap source after its
/// runtime restarts on identity transition, regardless of which side wins the
/// hex-ordered preferred-connection-direction check for ObservedPeer sources.
/// The row expires naturally after its 24-hour TTL; by that time the first
/// successful permanent-cert reconnect will have established a durable
/// observed-endpoint record that takes over for future reconnects.
pub fn project_pure(
    event_id_b64: &str,
    parsed: &ParsedEvent,
    ctx: &ContextSnapshot,
) -> ProjectorResult {
    let ps = match parsed {
        ParsedEvent::PeerShared(p) => p,
        _ => return ProjectorResult::reject("not a peer_shared event".to_string()),
    };

    // Generic label-gate (plan.md §164-170).
    if let Some(types) = ctx.labels.get(event_id_b64) {
        for t in types {
            if t == "deleted" || t.starts_with("removed_by:") || t == "superseded" {
                return ProjectorResult::reject(format!(
                    "peer_shared gated by label `{}`",
                    t
                ));
            }
        }
    }

    // Plan.md "no scaffolding": derive the user-identity-chain check from
    // the declared `signed_by` dep instead of a bespoke ctx field. The
    // signer is a DeviceInvite whose `authority_event_id` resolves to the
    // user identity. The PeerShared claim must agree.
    let signed_by_b64 = event_id_to_base64(&ps.signed_by);
    if let Some(dep_bytes) = ctx.deps.get(&signed_by_b64) {
        if let Ok(dep_parsed) = crate::event_modules::parse_event(dep_bytes) {
            if let ParsedEvent::DeviceInvite(di) = &dep_parsed {
                if di.authority_event_id != ps.user_event_id {
                    return ProjectorResult::reject(
                        "peer_shared signer authorizes user a but event claims b".to_string(),
                    );
                }
            }
        }
    }

    let workspace_id_b64 = event_id_to_base64(&ps.workspace_id);
    let user_event_id_b64 = event_id_to_base64(&ps.user_event_id);
    let transport_fingerprint = crate::crypto::spki_fingerprint_from_ed25519_pubkey(&ps.public_key);
    let ops = vec![WriteOp::InsertOrIgnore {
        table: "peers_shared",
        columns: vec![
            "event_id",
            "workspace_id",
            "public_key",
            "transport_fingerprint",
            "user_event_id",
            "device_name",
        ],
        values: vec![
            SqlVal::Text(event_id_b64.to_string()),
            SqlVal::Text(workspace_id_b64),
            SqlVal::Blob(ps.public_key.to_vec()),
            SqlVal::Blob(transport_fingerprint.to_vec()),
            SqlVal::Text(user_event_id_b64),
            SqlVal::Text(ps.device_name.clone()),
        ],
    }];

    ProjectorResult::valid(ops)
}

#[cfg(test)]
mod projector_tests {
    use super::*;
    use crate::event_modules::{
        encode_event, DeviceInviteEvent, ParsedEvent, PeerSharedEvent, WorkspaceEvent,
    };

    fn peer_shared_event(user_eid: [u8; 32], signed_by: [u8; 32]) -> ParsedEvent {
        ParsedEvent::PeerShared(PeerSharedEvent {
            created_at_ms: 1,
            workspace_id: [4u8; 32],
            public_key: [5u8; 32],
            user_event_id: user_eid,
            device_name: "phone".to_string(),
            signed_by,
            signer_type: 3,
            signature: [0u8; 64],
        })
    }

    fn device_invite_for_user(user_eid: [u8; 32]) -> ParsedEvent {
        ParsedEvent::DeviceInvite(DeviceInviteEvent {
            created_at_ms: 1,
            public_key: [9u8; 32],
            workspace_id: [1u8; 32],
            authority_event_id: user_eid,
            signed_by: [0u8; 32],
            signer_type: 5,
            signature: [0u8; 64],
        })
    }

    #[test]
    fn test_peer_shared_valid() {
        let result = project_pure(
            "peer-shared-event",
            &peer_shared_event([6u8; 32], [7u8; 32]),
            &ContextSnapshot::default(),
        );
        assert!(matches!(
            result.decision,
            crate::projection::decision::ProjectionDecision::Valid
        ));
        assert_eq!(result.write_ops.len(), 1);
    }

    #[test]
    fn test_peer_shared_rejects_authorized_user_mismatch() {
        let signer_eid = [7u8; 32];
        // The signer authorizes user A, but the PeerShared claims user B.
        let dep = device_invite_for_user([0xAAu8; 32]);
        let dep_bytes = encode_event(&dep).unwrap();
        let mut deps = std::collections::BTreeMap::new();
        deps.insert(event_id_to_base64(&signer_eid), dep_bytes);
        let result = project_pure(
            "peer-shared-event",
            &peer_shared_event([0xBBu8; 32], signer_eid),
            &ContextSnapshot {
                deps,
                ..ContextSnapshot::default()
            },
        );
        assert!(matches!(
            result.decision,
            crate::projection::decision::ProjectionDecision::Reject { .. }
        ));
    }

    #[test]
    fn test_peer_shared_rejects_non_peer_shared_event() {
        let other = ParsedEvent::Workspace(WorkspaceEvent {
            created_at_ms: 1,
            workspace_id: [0u8; 32],
            public_key: [0u8; 32],
            name: "ws".to_string(),
        });
        let result = project_pure(
            "workspace-event",
            &other,
            &ContextSnapshot::default(),
        );
        assert!(matches!(
            result.decision,
            crate::projection::decision::ProjectionDecision::Reject { .. }
        ));
    }
}
