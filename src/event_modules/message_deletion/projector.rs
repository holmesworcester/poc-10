use super::super::ParsedEvent;
use crate::crypto::event_id_to_base64;
use crate::projection::contract::{ContextSnapshot, EmitCommand, ProjectorResult, SqlVal, WriteOp};

/// Build the `(event_id, label_type, workspace_id)` write op for a `deleted`
/// label keyed by the target message id.
fn deleted_label_write_op(target_event_id: &[u8; 32], workspace_id: &[u8; 32]) -> WriteOp {
    WriteOp::InsertOrIgnore {
        table: "labels",
        columns: vec!["event_id", "label_type", "workspace_id"],
        values: vec![
            SqlVal::Blob(target_event_id.to_vec()),
            SqlVal::Text("deleted".to_string()),
            SqlVal::Blob(workspace_id.to_vec()),
        ],
    }
}

/// Pure projector: MessageDeletion -> tombstone + label gate.
///
/// Plan.md "no scaffolding" rule (Forking plan): the projector reads only
/// `{event, deps, labels}`. Validation rules:
///
/// - Label gate: a `removed_by:*` label on the signer rejects projection.
/// - Author check: the deletion author must match the target message
///   author. The target is a declared dep (`target_event_id`), parsed
///   from `ctx.deps[target_event_id]` to read its `author_id`. If the
///   target dep isn't yet present (delete-before-create), we skip the
///   author check and emit the canonical write set unconditionally
///   (idempotent — the matching message projector will refuse to
///   materialize when it sees the `deleted` label we write here).
/// - Always emits: `deleted` label on the target id, `deleted_messages`
///   tombstone, cascade Delete from `messages`/`reactions`, and a
///   `HardPurgeMessageGraph` command.
pub fn project_pure(
    event_id_b64: &str,
    parsed: &ParsedEvent,
    ctx: &ContextSnapshot,
) -> ProjectorResult {
    let del = match parsed {
        ParsedEvent::MessageDeletion(d) => d,
        _ => return ProjectorResult::reject("not a message_deletion event".to_string()),
    };

    let workspace_id_b64 = event_id_to_base64(&del.workspace_id);
    let target_b64 = event_id_to_base64(&del.target_event_id);
    let del_author_b64 = event_id_to_base64(&del.author_id);
    let signed_by_b64 = event_id_to_base64(&del.signed_by);

    // Label-based gate (plan.md §164-170): refuse to project if the signer
    // identity carries any `removed_by:<issuer>` label.
    let signer_removed = ctx
        .labels
        .get(&signed_by_b64)
        .map(|labels| labels.iter().any(|l| l.starts_with("removed_by:")))
        .unwrap_or(false);
    if signer_removed {
        return ProjectorResult::reject(
            "message_deletion signer identity has been removed (removed_by label)".to_string(),
        );
    }

    // Author check: parse the target dep (if present) and confirm the
    // deletion author matches the target's author. If the target dep is a
    // non-Message variant, reject. If absent, fall through to the
    // delete-before-create path.
    if let Some(dep_bytes) = ctx.deps.get(&target_b64) {
        match crate::event_modules::parse_event(dep_bytes) {
            Ok(ParsedEvent::Message(target_msg)) => {
                let target_author_b64 = event_id_to_base64(&target_msg.author_id);
                if target_author_b64 != del_author_b64 {
                    return ProjectorResult::reject(
                        "deletion author does not match message author".to_string(),
                    );
                }
            }
            Ok(_) => {
                return ProjectorResult::reject(
                    "deletion target is a non-message event".to_string(),
                );
            }
            Err(_) => {
                // dep bytes don't parse — treat as delete-before-create.
            }
        }
    }

    // Emit the canonical write set unconditionally — all writes are
    // idempotent. The Message projector consults the `deleted` label
    // produced here and refuses to materialize on arrival.
    let ops = vec![
        WriteOp::InsertOrIgnore {
            table: "deleted_messages",
            columns: vec![
                "workspace_id",
                "message_id",
                "deletion_event_id",
                "author_id",
                "deleted_at",
            ],
            values: vec![
                SqlVal::Text(workspace_id_b64.clone()),
                SqlVal::Text(target_b64.clone()),
                SqlVal::Text(event_id_b64.to_string()),
                SqlVal::Text(del_author_b64),
                SqlVal::Int(del.created_at_ms as i64),
            ],
        },
        deleted_label_write_op(&del.target_event_id, &del.workspace_id),
        WriteOp::Delete {
            table: "messages",
            where_clause: vec![
                ("workspace_id", SqlVal::Text(workspace_id_b64.clone())),
                ("message_id", SqlVal::Text(target_b64.clone())),
            ],
        },
        WriteOp::Delete {
            table: "reactions",
            where_clause: vec![
                ("workspace_id", SqlVal::Text(workspace_id_b64.clone())),
                ("target_event_id", SqlVal::Text(target_b64.clone())),
            ],
        },
    ];

    ProjectorResult::valid_with_commands(
        ops,
        vec![EmitCommand::HardPurgeMessageGraph {
            message_event_id: target_b64,
        }],
    )
}
