//! Commands for signed recipient key tombstones.
//!
//! The command creates one shared retirement fact signed by the endpoint that
//! owns the key being retired. It does not delete private material, derive new
//! keys, or remove already-projected wraps; those are local worker/retention
//! questions after the shared tombstone applies.

use crate::core::crypto::Ed25519PrivateKey;
use crate::protocol::event_modules::types::{event_id, EventId};
use crate::protocol::event_modules::worker::CommandOutput;

use super::{codec, types::RecipientKeyTombstoneEvent};

/// Sanity guard: every named id is non-zero and the old and new recipient
/// keys are distinct. The codec is intentionally lenient on decode; this
/// helper is shared between the authoring path and the receive projector so
/// a malformed peer event is rejected at projection time too.
pub(super) fn validate_event_ids(event: &RecipientKeyTombstoneEvent) -> Result<(), String> {
    if is_zero(&event.workspace_id) {
        return Err("recipient key tombstone workspace cannot be empty".to_string());
    }
    if is_zero(&event.endpoint_shared_id) {
        return Err("recipient key tombstone endpoint_shared_id cannot be empty".to_string());
    }
    if is_zero(&event.old_recipient_key_id) {
        return Err("recipient key tombstone old key cannot be empty".to_string());
    }
    if is_zero(&event.new_recipient_key_id) {
        return Err("recipient key tombstone new key cannot be empty".to_string());
    }
    if event.old_recipient_key_id == event.new_recipient_key_id {
        return Err("recipient key tombstone must name different keys".to_string());
    }
    Ok(())
}

fn is_zero(bytes: &[u8; 32]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TombstoneRecipientKey {
    pub workspace_id: EventId,
    pub created_at_ms: u64,
    pub endpoint_shared_id: EventId,
    pub signer_private_key: Ed25519PrivateKey,
    pub old_recipient_key_id: EventId,
    pub new_recipient_key_id: EventId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecipientKeyTombstoneOutput {
    pub recipient_key_tombstone_id: EventId,
    pub old_recipient_key_id: EventId,
    pub new_recipient_key_id: EventId,
}

pub fn tombstone(
    input: TombstoneRecipientKey,
) -> Result<CommandOutput<RecipientKeyTombstoneOutput>, String> {
    let event = RecipientKeyTombstoneEvent {
        workspace_id: input.workspace_id,
        created_at_ms: input.created_at_ms,
        endpoint_shared_id: input.endpoint_shared_id,
        old_recipient_key_id: input.old_recipient_key_id,
        new_recipient_key_id: input.new_recipient_key_id,
    };
    validate_event_ids(&event)?;
    let payload = codec::encode(&event);
    let envelope = codec::sign(input.endpoint_shared_id, &input.signer_private_key, payload);
    let bytes = codec::encode_signed(&envelope);
    let record = codec::signed_record_from_bytes(bytes)?;
    let value = RecipientKeyTombstoneOutput {
        recipient_key_tombstone_id: event_id(&record.canonical_bytes),
        old_recipient_key_id: event.old_recipient_key_id,
        new_recipient_key_id: event.new_recipient_key_id,
    };
    Ok(CommandOutput::with_events(value, vec![record]))
}

#[cfg(test)]
mod tests {
    use crate::protocol::event_modules::types::EventScope;

    use super::*;

    #[test]
    fn tombstone_proposes_signed_shared_event_depending_on_old_and_new_keys() {
        let output = tombstone(TombstoneRecipientKey {
            workspace_id: [1; 32],
            created_at_ms: 10,
            endpoint_shared_id: [2; 32],
            signer_private_key: [7; 32],
            old_recipient_key_id: [3; 32],
            new_recipient_key_id: [4; 32],
        })
        .expect("tombstone");

        let record = output.events[0].record();
        assert_eq!(record.scope, EventScope::Shared);
        assert_eq!(record.workspace_id, Some([1; 32]));
        assert_eq!(
            record.dependencies,
            vec![[2; 32], [1; 32], [3; 32], [4; 32]]
        );
        assert_eq!(
            output.value.recipient_key_tombstone_id,
            output.events[0].event_id()
        );
    }

    #[test]
    fn tombstone_rejects_empty_or_same_key_ids() {
        let mut input = TombstoneRecipientKey {
            workspace_id: [1; 32],
            created_at_ms: 10,
            endpoint_shared_id: [2; 32],
            signer_private_key: [7; 32],
            old_recipient_key_id: [3; 32],
            new_recipient_key_id: [3; 32],
        };
        assert_eq!(
            tombstone(input.clone()).expect_err("same key must fail"),
            "recipient key tombstone must name different keys"
        );
        input.new_recipient_key_id = [0; 32];
        assert_eq!(
            tombstone(input).expect_err("empty key must fail"),
            "recipient key tombstone new key cannot be empty"
        );
    }
}
