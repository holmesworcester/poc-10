//! Pure projector conformance tests for Message (type 1).
//!
//! Plan.md (Forking plan, "no scaffolding"): the projector reads only
//! `{event, deps, labels}`. Tests construct that shape directly.
//!
//! Coverage:
//!   CHK_MSG_REMOVED_BY  — `removed_by:*` label on signer/author rejects
//!   CHK_MSG_DELETED_LABEL — `deleted` label on this message id collapses
//!     to no-op + purge (delete-before-create convergence)

#[cfg(test)]
mod tests {
    use crate::harness::fixtures::*;
    use topo::event_modules::message::project_pure;
    use topo::event_modules::message::MessageEvent;
    use topo::event_modules::ParsedEvent;
    use topo::projection::contract::EmitCommand;

    const EVENT_ID: &str = "msg_event_1";

    fn make_message(author_id: [u8; 32]) -> ParsedEvent {
        ParsedEvent::Message(MessageEvent {
            created_at_ms: 3000,
            workspace_id: [1u8; 32],
            author_id,
            content: "hello".to_string(),
            signed_by: [3u8; 32],
            signer_type: 5,
            signature: [0u8; 64],
        })
    }

    #[test]
    fn test_message_valid() {
        let parsed = make_message([2u8; 32]);
        let ctx = empty_ctx();

        let result = project_pure(EVENT_ID, &parsed, &ctx);
        assert_valid(&result);
        assert_writes_to_table(&result, "messages");
        assert_no_commands(&result);
    }

    #[test]
    fn test_message_rejects_when_signer_removed_by_label() {
        let parsed = make_message([2u8; 32]);
        // `removed_by:*` keyed on the signer id rejects projection.
        let signer_b64 = b64(&[3u8; 32]);
        let ctx = ctx_with_label(&signer_b64, "removed_by:admin");

        let result = project_pure(EVENT_ID, &parsed, &ctx);
        assert_reject_contains(&result, "removed_by");
    }

    #[test]
    fn test_message_purges_when_deleted_label_already_present() {
        // Delete-before-create: the deletion event arrived first and
        // wrote a `deleted` label keyed by this message id. The message
        // must purge on arrival.
        let parsed = make_message([2u8; 32]);
        let ctx = ctx_with_label(EVENT_ID, "deleted");

        let result = project_pure(EVENT_ID, &parsed, &ctx);
        assert_valid(&result);
        assert!(
            result.write_ops.is_empty(),
            "should produce no write ops when target deleted"
        );
        assert_emits_command(&result, "HardPurgeMessageGraph", |cmd| {
            matches!(
                cmd,
                EmitCommand::HardPurgeMessageGraph { message_event_id } if message_event_id == EVENT_ID
            )
        });
    }
}
