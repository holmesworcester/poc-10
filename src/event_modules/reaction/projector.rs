use super::super::ParsedEvent;
use crate::crypto::event_id_to_base64;
use crate::projection::contract::{ContextSnapshot, EmitCommand, ProjectorResult, SqlVal, WriteOp};

/// Pure projector: Reaction → reactions table insert.
///
/// Plan.md "no scaffolding" rule (Forking plan): the projector reads only
/// `{event, deps, labels}`. Validation rules:
///
/// - The event carries its own `workspace_id`; the projector reads it
///   directly and writes `reactions.workspace_id` from the parsed event.
/// - Label gates (plan.md §164-170): a `removed_by:*` label on the
///   signer or author identity rejects projection; a `deleted` label on
///   the reaction's target collapses to a no-op + purge.
pub fn project_pure(
    event_id_b64: &str,
    parsed: &ParsedEvent,
    ctx: &ContextSnapshot,
) -> ProjectorResult {
    let rxn = match parsed {
        ParsedEvent::Reaction(r) => r,
        _ => return ProjectorResult::reject("not a reaction event".to_string()),
    };

    if rxn.emoji.trim().is_empty() {
        return ProjectorResult::reject("reaction content must not be empty".to_string());
    }

    let workspace_id_b64 = event_id_to_base64(&rxn.workspace_id);

    // Label-based gate (plan.md §164-170): refuse to project if the signer or
    // author identity carries any `removed_by:<issuer>` label.
    let author_id_b64 = event_id_to_base64(&rxn.author_id);
    let signed_by_b64 = event_id_to_base64(&rxn.signed_by);
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
            "reaction author/signer identity has been removed (removed_by label)".to_string(),
        );
    }

    let target_id_b64 = event_id_to_base64(&rxn.target_event_id);

    // Label-based gate (plan.md §164-170): if the target carries a `deleted`
    // label, the reaction is structurally valid but no row is written.
    let target_deleted_via_label = ctx
        .labels
        .get(&target_id_b64)
        .map(|labels| labels.iter().any(|l| l == "deleted"))
        .unwrap_or(false);

    if target_deleted_via_label {
        return ProjectorResult::valid_with_commands(
            vec![],
            vec![EmitCommand::HardPurgeMessageGraph {
                message_event_id: target_id_b64,
            }],
        );
    }

    let ops = vec![WriteOp::InsertOrIgnore {
        table: "reactions",
        columns: vec![
            "event_id",
            "workspace_id",
            "target_event_id",
            "author_id",
            "emoji",
            "created_at",
        ],
        values: vec![
            SqlVal::Text(event_id_b64.to_string()),
            SqlVal::Text(workspace_id_b64),
            SqlVal::Text(target_id_b64),
            SqlVal::Text(author_id_b64),
            SqlVal::Text(rxn.emoji.clone()),
            SqlVal::Int(rxn.created_at_ms as i64),
        ],
    }];
    ProjectorResult::valid(ops)
}
