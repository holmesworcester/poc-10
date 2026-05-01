//! Pure projector conformance tests for mostly simple projectors.
//!
//! Wave 1: covers User and KeySecret. Admin/File/BenchDep dropped.

#[cfg(test)]
mod tests {
    use crate::harness::fixtures::*;
    use topo::event_modules::ParsedEvent;

    const PEER: &str = "peer_alice";
    const EVENT_ID: &str = "simple_event_1";

    fn unrelated_event() -> ParsedEvent {
        ParsedEvent::KeySecret(topo::event_modules::key_secret::KeySecretEvent {
            created_at_ms: 42,
            workspace_id: [0u8; 32],
            key_bytes: [0u8; 32],
        })
    }

    // ── User ──

    #[test]
    fn test_user_valid() {
        use topo::event_modules::user::{project_pure, UserEvent};
        let parsed = ParsedEvent::User(UserEvent {
            created_at_ms: 1000,
            workspace_id: [9u8; 32],
            public_key: [1u8; 32],
            username: "alice".to_string(),
            signed_by: [2u8; 32],
            signer_type: 2,
            signature: [0u8; 64],
        });
        let result = project_pure(EVENT_ID, &parsed, &empty_ctx());
        assert_valid(&result);
        assert_writes_to_table(&result, "users");
        assert_no_commands(&result);
    }

    #[test]
    fn test_user_valid_second_sample() {
        use topo::event_modules::user::{project_pure, UserEvent};
        let parsed = ParsedEvent::User(UserEvent {
            created_at_ms: 1001,
            workspace_id: [9u8; 32],
            public_key: [1u8; 32],
            username: "alice".to_string(),
            signed_by: [2u8; 32],
            signer_type: 2,
            signature: [0u8; 64],
        });
        let result = project_pure(EVENT_ID, &parsed, &empty_ctx());
        assert_valid(&result);
        assert_writes_to_table(&result, "users");
    }

    #[test]
    fn test_user_rejects_non_user_event() {
        use topo::event_modules::user::project_pure;
        let result = project_pure(EVENT_ID, &unrelated_event(), &empty_ctx());
        assert_reject(&result);
    }

    // ── KeySecret ──

    #[test]
    fn test_key_secret_valid() {
        use topo::event_modules::key_secret::{project_pure, KeySecretEvent};
        let parsed = ParsedEvent::KeySecret(KeySecretEvent {
            created_at_ms: 5000,
            workspace_id: [0x77u8; 32],
            key_bytes: [0xAB; 32],
        });
        let result = project_pure(EVENT_ID, &parsed, &empty_ctx());
        assert_valid(&result);
        assert_writes_to_table(&result, "key_secrets");
        assert_no_commands(&result);
    }

    #[test]
    fn test_key_secret_rejects_non_key_secret_event() {
        use topo::event_modules::key_secret::project_pure;
        let unrelated = ParsedEvent::User(topo::event_modules::user::UserEvent {
            created_at_ms: 1,
            workspace_id: [0u8; 32],
            public_key: [0u8; 32],
            username: "alice".to_string(),
            signed_by: [0u8; 32],
            signer_type: 2,
            signature: [0u8; 64],
        });
        let result = project_pure(EVENT_ID, &unrelated, &empty_ctx());
        assert_reject(&result);
    }
}
