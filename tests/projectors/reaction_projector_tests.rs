//! Pure projector conformance tests for Reaction (type 2).
//!
//! Plan.md (Forking plan, "no scaffolding"): the projector reads only
//! `{event, deps, labels}`. Tests construct that shape directly.
//!
//! Coverage:
//!   CHK_RXN_REMOVED_BY — `removed_by:*` label on signer/author rejects
//!   CHK_RXN_DELETED_LABEL — `deleted` label on target → no write + purge

#[cfg(test)]
mod tests {
    use crate::harness::fixtures::*;
    use topo::event_modules::reaction::project_pure;
    use topo::event_modules::reaction::ReactionEvent;
    use topo::event_modules::ParsedEvent;
    use topo::projection::contract::EmitCommand;

    const EVENT_ID: &str = "rxn_event_1";

    fn make_reaction() -> ParsedEvent {
        ParsedEvent::Reaction(ReactionEvent {
            created_at_ms: 4000,
            workspace_id: [9u8; 32],
            target_event_id: [1u8; 32],
            author_id: [2u8; 32],
            emoji: "\u{1f44d}".to_string(),
            signed_by: [3u8; 32],
            signer_type: 5,
            signature: [0u8; 64],
        })
    }

    #[test]
    fn test_reaction_valid() {
        let parsed = make_reaction();
        let ctx = empty_ctx();

        let result = project_pure(EVENT_ID, &parsed, &ctx);
        assert_valid(&result);
        assert_writes_to_table(&result, "reactions");
        assert_no_commands(&result);
    }

    #[test]
    fn test_reaction_rejects_when_signer_removed_by_label() {
        let parsed = make_reaction();
        let signer_b64 = b64(&[3u8; 32]);
        let ctx = ctx_with_label(&signer_b64, "removed_by:admin");

        let result = project_pure(EVENT_ID, &parsed, &ctx);
        assert_reject_contains(&result, "removed_by");
    }

    #[test]
    fn test_reaction_skips_when_target_has_deleted_label() {
        let parsed = make_reaction();
        let target_b64 = b64(&[1u8; 32]);
        let ctx = ctx_with_label(&target_b64, "deleted");

        let result = project_pure(EVENT_ID, &parsed, &ctx);
        assert_valid(&result);
        assert!(
            result.write_ops.is_empty(),
            "should produce no write ops when target deleted"
        );
        assert_emits_command(&result, "HardPurgeMessageGraph", |cmd| {
            matches!(
                cmd,
                EmitCommand::HardPurgeMessageGraph { message_event_id } if message_event_id == &b64(&[1u8; 32])
            )
        });
    }
}
