use super::super::ParsedEvent;
use crate::crypto::event_id_to_base64;
use crate::projection::contract::{ContextSnapshot, EmitCommand, ProjectorResult, SqlVal, WriteOp};

/// Pure projector: Message -> messages table insert.
///
/// Plan.md "no scaffolding" rule (Forking plan): the projector reads only
/// `{event, deps, labels}`. Validation rules:
///
/// - The event carries its own `workspace_id`; the projector reads it
///   directly and writes `messages.workspace_id` from the parsed event.
/// - Label gates (plan.md §164-170): a `removed_by:*` label on the
///   signer or author identity rejects projection; a `deleted` label
///   on this message's own event id collapses to a no-op + purge
///   (delete-before-create convergence).
/// - The legacy "deletion intent author-match" path is gone: the
///   `deleted` label is the canonical signal that a deletion has been
///   admitted ahead of the message and the message must purge on
///   arrival.
pub fn project_pure(
    event_id_b64: &str,
    parsed: &ParsedEvent,
    ctx: &ContextSnapshot,
) -> ProjectorResult {
    let msg = match parsed {
        ParsedEvent::Message(m) => m,
        _ => return ProjectorResult::reject("not a message event".to_string()),
    };

    if msg.content.trim().is_empty() {
        return ProjectorResult::reject("message content must not be empty".to_string());
    }

    let workspace_id_b64 = event_id_to_base64(&msg.workspace_id);
    let author_id_b64 = event_id_to_base64(&msg.author_id);
    let signed_by_b64 = event_id_to_base64(&msg.signed_by);

    // Label-based gate (plan.md §164-170): refuse to project if the signer or
    // the author identity carries any `removed_by:<issuer>` label.
    let signer_removed = ctx
        .labels
        .get(&signed_by_b64)
        .map(|labels| labels.iter().any(|l| l.starts_with("removed_by:")))
        .unwrap_or(false)
        || ctx
            .labels
            .get(&author_id_b64)
            .map(|labels| labels.iter().any(|l| l.starts_with("removed_by:")))
            .unwrap_or(false);
    if signer_removed {
        return ProjectorResult::reject(
            "message author/signer identity has been removed (removed_by label)".to_string(),
        );
    }

    // Label-based gate (plan.md §164-170): if a `deleted` label was already
    // attached to this message id (i.e. a delete-before-create message
    // deletion arrived earlier), purge immediately on first materialization.
    let already_deleted_label = ctx
        .labels
        .get(event_id_b64)
        .map(|labels| labels.iter().any(|l| l == "deleted"))
        .unwrap_or(false);

    if already_deleted_label {
        return ProjectorResult::valid_with_commands(
            vec![],
            vec![EmitCommand::HardPurgeMessageGraph {
                message_event_id: event_id_b64.to_string(),
            }],
        );
    }

    let ops = vec![WriteOp::InsertOrIgnore {
        table: "messages",
        columns: vec![
            "message_id",
            "workspace_id",
            "author_id",
            "content",
            "created_at",
        ],
        values: vec![
            SqlVal::Text(event_id_b64.to_string()),
            SqlVal::Text(workspace_id_b64),
            SqlVal::Text(author_id_b64),
            SqlVal::Text(msg.content.clone()),
            SqlVal::Int(msg.created_at_ms as i64),
        ],
    }];
    ProjectorResult::valid(ops)
}
