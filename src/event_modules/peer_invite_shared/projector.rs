use super::super::ParsedEvent;
use crate::crypto::event_id_to_base64;
use crate::projection::contract::{ContextSnapshot, ProjectorResult, SqlVal, WriteOp};

/// Pure projector: DeviceInvite -> device_invites table.
///
/// Plan.md "no scaffolding" rule (Forking plan): the projector reads only
/// `{event, deps, labels}`. Validation rules:
///
/// - Apply the standard label-gate pattern: any `removed_by:*` /
///   `superseded` / `deleted` label on this event id rejects the
///   projection (plan.md §164-170).
/// - Bootstrap signer (`signer_type == 4`): `authority_event_id` must
///   equal `signed_by` (self-binding to the user event).
/// - Peer signer (`signer_type == 5`): the signer's PeerShared event is
///   a declared dep (`signed_by`). We parse it from `ctx.deps[signed_by]`
///   and confirm its `user_event_id` matches the DeviceInvite's
///   `authority_event_id` (the peer is acting on behalf of their user).
///
/// The bootstrap-trust write side (legacy `pending_invite_bootstrap_trust`
/// from `bootstrap_context` + `is_local_create`) is gone — the daemon only
/// PROJECTS events here; local-trust intent runs through the authoring-side
/// codepath instead.
pub fn project_pure(
    event_id_b64: &str,
    parsed: &ParsedEvent,
    ctx: &ContextSnapshot,
) -> ProjectorResult {
    // Generic label-gate (plan.md §164-170): any retiring label on this
    // event id rejects the projection.
    if let Some(types) = ctx.labels.get(event_id_b64) {
        for t in types {
            if t == "deleted" || t.starts_with("removed_by:") || t == "superseded" {
                return ProjectorResult::reject(format!(
                    "device_invite gated by label `{}`",
                    t
                ));
            }
        }
    }

    let (public_key, signer_type, signed_by, authority_event_id, workspace_id) = match parsed {
        ParsedEvent::DeviceInvite(di) => (
            &di.public_key,
            di.signer_type,
            di.signed_by,
            di.authority_event_id,
            di.workspace_id,
        ),
        _ => return ProjectorResult::reject("not a device_invite event".to_string()),
    };

    if signer_type == 4 {
        if authority_event_id != signed_by {
            return ProjectorResult::reject(
                "bootstrap device_invite authority must match signer user event".to_string(),
            );
        }
    } else if signer_type == 5 {
        // Peer-signed: derive authority/signer match from the declared dep.
        let signer_b64 = event_id_to_base64(&signed_by);
        let dep_authorizes_authority = match ctx.deps.get(&signer_b64) {
            Some(bytes) => match crate::event_modules::parse_event(bytes) {
                Ok(ParsedEvent::PeerShared(ps)) => ps.user_event_id == authority_event_id,
                _ => false,
            },
            None => false,
        };
        if !dep_authorizes_authority {
            return ProjectorResult::reject(
                "peer-signed device_invite authority does not match signer user identity"
                    .to_string(),
            );
        }
    } else {
        return ProjectorResult::reject("unsupported device_invite signer_type".to_string());
    }

    let workspace_id_b64 = event_id_to_base64(&workspace_id);

    let ops = vec![WriteOp::InsertOrIgnore {
        table: "device_invites",
        columns: vec!["event_id", "workspace_id", "public_key"],
        values: vec![
            SqlVal::Text(event_id_b64.to_string()),
            SqlVal::Text(workspace_id_b64),
            SqlVal::Blob(public_key.to_vec()),
        ],
    }];

    ProjectorResult::valid(ops)
}

#[cfg(test)]
mod device_invite_projector_tests {
    use super::*;
    use crate::event_modules::{
        encode_event, DeviceInviteEvent, ParsedEvent, PeerSharedEvent, WorkspaceEvent,
    };
    use crate::projection::contract::ContextSnapshot;
    use crate::projection::decision::ProjectionDecision;

    fn bootstrap_device_invite() -> ParsedEvent {
        ParsedEvent::DeviceInvite(DeviceInviteEvent {
            created_at_ms: 1,
            public_key: [9u8; 32],
            workspace_id: [1u8; 32],
            authority_event_id: [2u8; 32],
            signed_by: [2u8; 32],
            signer_type: 4,
            signature: [0u8; 64],
        })
    }

    fn peer_signed_device_invite(signer: [u8; 32], authority: [u8; 32]) -> ParsedEvent {
        ParsedEvent::DeviceInvite(DeviceInviteEvent {
            created_at_ms: 1,
            public_key: [9u8; 32],
            workspace_id: [1u8; 32],
            authority_event_id: authority,
            signed_by: signer,
            signer_type: 5,
            signature: [0u8; 64],
        })
    }

    fn assert_valid(result: &ProjectorResult, expected_writes: usize) {
        assert!(matches!(result.decision, ProjectionDecision::Valid));
        assert_eq!(result.write_ops.len(), expected_writes);
    }

    #[test]
    fn test_device_invite_basic_valid() {
        let result = project_pure(
            "invite-event",
            &bootstrap_device_invite(),
            &ContextSnapshot::default(),
        );
        assert_valid(&result, 1);
    }

    #[test]
    fn test_device_invite_rejects_bootstrap_authority_mismatch() {
        let event = ParsedEvent::DeviceInvite(DeviceInviteEvent {
            created_at_ms: 1,
            public_key: [9u8; 32],
            workspace_id: [1u8; 32],
            authority_event_id: [6u8; 32],
            signed_by: [2u8; 32],
            signer_type: 4,
            signature: [0u8; 64],
        });
        let result = project_pure("invite-event", &event, &ContextSnapshot::default());
        assert!(matches!(
            result.decision,
            ProjectionDecision::Reject { ref reason }
                if reason.contains("bootstrap device_invite authority must match signer user event")
        ));
    }

    #[test]
    fn test_device_invite_rejects_peer_signed_when_authority_mismatches() {
        // The peer's PeerShared dep authorizes user A, but the DeviceInvite
        // claims authority over user B.
        let signer = [3u8; 32];
        let authority_b = [4u8; 32];
        let dep = ParsedEvent::PeerShared(PeerSharedEvent {
            created_at_ms: 1,
            workspace_id: [1u8; 32],
            public_key: [5u8; 32],
            user_event_id: [9u8; 32], // user A
            device_name: "device".to_string(),
            signed_by: [0u8; 32],
            signer_type: 3,
            signature: [0u8; 64],
        });
        let dep_bytes = encode_event(&dep).unwrap();
        let mut deps = std::collections::BTreeMap::new();
        deps.insert(event_id_to_base64(&signer), dep_bytes);
        let result = project_pure(
            "invite-event",
            &peer_signed_device_invite(signer, authority_b),
            &ContextSnapshot {
                deps,
                ..ContextSnapshot::default()
            },
        );
        assert!(matches!(
            result.decision,
            ProjectionDecision::Reject { ref reason }
                if reason.contains("peer-signed device_invite authority does not match signer user identity")
        ));
    }

    #[test]
    fn test_device_invite_rejects_non_device_invite_event() {
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
        assert!(matches!(result.decision, ProjectionDecision::Reject { .. }));
    }
}
