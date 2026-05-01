//! Pure projector conformance tests for MessageDeletion (type 7).
//!
//! Plan.md (Forking plan, "no scaffolding"): the projector reads only
//! `{event, deps, labels}`. Tests construct that shape directly.
//!
//! Coverage:
//!   CHK_DEL_AUTHOR — author check via `ctx.deps[target_event_id]`
//!   CHK_DEL_NON_MESSAGE — non-message dep rejects
//!   CHK_DEL_REMOVED_BY — `removed_by:*` label on signer rejects
//!   CHK_DEL_BEFORE_CREATE — target dep absent → unconditional canonical
//!     write set (idempotent; the message projector consults the
//!     `deleted` label written here)

#[cfg(test)]
mod tests {
    use crate::harness::fixtures::*;
    use topo::event_modules::message::MessageEvent;
    use topo::event_modules::message_deletion::project_pure;
    use topo::event_modules::message_deletion::MessageDeletionEvent;
    use topo::event_modules::{encode_event, ParsedEvent, TenantEvent};
    use topo::projection::contract::EmitCommand;

    const EVENT_ID: &str = "del_event_1";
    const TARGET_ID: [u8; 32] = [1u8; 32];

    fn make_deletion(target: [u8; 32], author: [u8; 32]) -> ParsedEvent {
        ParsedEvent::MessageDeletion(MessageDeletionEvent {
            created_at_ms: 5000,
            workspace_id: [9u8; 32],
            target_event_id: target,
            author_id: author,
            signed_by: [3u8; 32],
            signer_type: 5,
            signature: [0u8; 64],
        })
    }

    fn target_message_with_author(author: [u8; 32]) -> Vec<u8> {
        let m = ParsedEvent::Message(MessageEvent {
            created_at_ms: 1000,
            workspace_id: [9u8; 32],
            author_id: author,
            content: "to be deleted".to_string(),
            signed_by: [3u8; 32],
            signer_type: 5,
            signature: [0u8; 64],
        });
        encode_event(&m).unwrap()
    }

    #[test]
    fn test_deletion_valid_when_author_matches_target() {
        let author = [2u8; 32];
        let parsed = make_deletion(TARGET_ID, author);
        let ctx = ctx_with_dep(&b64(&TARGET_ID), target_message_with_author(author));

        let result = project_pure(EVENT_ID, &parsed, &ctx);
        assert_valid(&result);
        assert_writes_to_table(&result, "deleted_messages");
        assert_writes_to_table(&result, "labels"); // `deleted` label
        assert_emits_command(&result, "HardPurgeMessageGraph", |cmd| {
            matches!(
                cmd,
                EmitCommand::HardPurgeMessageGraph { message_event_id } if message_event_id == &b64(&TARGET_ID)
            )
        });
    }

    #[test]
    fn test_deletion_rejects_wrong_author() {
        let author = [2u8; 32];
        let other_author = [99u8; 32];
        let parsed = make_deletion(TARGET_ID, author);
        // Target dep authored by someone else.
        let ctx = ctx_with_dep(&b64(&TARGET_ID), target_message_with_author(other_author));

        let result = project_pure(EVENT_ID, &parsed, &ctx);
        assert_reject_contains(&result, "does not match message author");
    }

    #[test]
    fn test_deletion_rejects_non_message_target() {
        let parsed = make_deletion(TARGET_ID, [2u8; 32]);
        // Target dep is a Tenant event, not a Message.
        let non_msg = ParsedEvent::Tenant(TenantEvent {
            created_at_ms: 1,
            public_key: [7u8; 32],
        });
        let ctx = ctx_with_dep(&b64(&TARGET_ID), encode_event(&non_msg).unwrap());

        let result = project_pure(EVENT_ID, &parsed, &ctx);
        assert_reject_contains(&result, "non-message event");
    }

    #[test]
    fn test_deletion_emits_canonical_writes_when_target_absent() {
        // Delete-before-create: target dep not yet admitted. The
        // projector emits the canonical write set unconditionally
        // (idempotent — message projector consults the `deleted` label).
        let parsed = make_deletion(TARGET_ID, [2u8; 32]);
        let ctx = empty_ctx();

        let result = project_pure(EVENT_ID, &parsed, &ctx);
        assert_valid(&result);
        assert_writes_to_table(&result, "deleted_messages");
        assert_writes_to_table(&result, "labels");
    }

    #[test]
    fn test_deletion_rejects_when_signer_removed_by_label() {
        let parsed = make_deletion(TARGET_ID, [2u8; 32]);
        let signer_b64 = b64(&[3u8; 32]);
        let ctx = ctx_with_label(&signer_b64, "removed_by:admin");

        let result = project_pure(EVENT_ID, &parsed, &ctx);
        assert_reject_contains(&result, "removed_by");
    }
}
