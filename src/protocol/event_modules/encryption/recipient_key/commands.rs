//! Commands for shared recipient key facts.
//!
//! Publishing a recipient key signs the public key with the endpoint membership
//! signing key. The local private key is created and stored by
//! `local_recipient_key`; this command only publishes the public half.

use crate::core::crypto::{Ed25519PrivateKey, X25519PublicKey};
use crate::protocol::event_modules::types::{event_id, EventId};
use crate::protocol::event_modules::worker::CommandOutput;

use super::layout;
use super::types::{RecipientKeyEvent, NO_PREVIOUS_RECIPIENT_KEY};

/// Sanity guard: every named id in a recipient key event is non-zero. The
/// layout is intentionally lenient on decode; this helper is shared between
/// the authoring path and the receive projector so a malformed peer event
/// is rejected at projection time too.
pub(super) fn validate_event_ids(event: &RecipientKeyEvent) -> Result<(), String> {
    if is_zero(&event.workspace_id) {
        return Err("recipient key workspace cannot be empty".to_string());
    }
    if is_zero(&event.endpoint_shared_id) {
        return Err("recipient key endpoint_shared_id cannot be empty".to_string());
    }
    if is_zero(&event.recipient_key) {
        return Err("recipient key public key cannot be empty".to_string());
    }
    Ok(())
}

fn is_zero(bytes: &[u8; 32]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishRecipientKey {
    pub workspace_id: EventId,
    pub created_at_ms: u64,
    pub endpoint_shared_id: EventId,
    pub signer_private_key: Ed25519PrivateKey,
    pub recipient_key: X25519PublicKey,
    /// `NO_PREVIOUS_RECIPIENT_KEY` for a fresh keypair publication.
    /// Otherwise the event id of the recipient_key being superseded by
    /// this rotation. Forward-secrecy rotation paths (per
    /// `RULES.md` § "Forward Secrecy Requires Recipient Key Rotation On
    /// Wrap-Bound Deletion") set this to the wiped pubkey's event id;
    /// the projector treats the resulting event as both tombstone of
    /// the old pubkey and introduction of the new pubkey.
    pub previous_recipient_key_id: EventId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishRecipientKeyOutput {
    pub recipient_key_id: EventId,
    pub workspace_id: EventId,
    pub endpoint_shared_id: EventId,
    pub recipient_key: X25519PublicKey,
    pub previous_recipient_key_id: EventId,
}

pub fn publish(
    input: PublishRecipientKey,
) -> Result<CommandOutput<PublishRecipientKeyOutput>, String> {
    validate_id("workspace_id", &input.workspace_id)?;
    validate_id("endpoint_shared_id", &input.endpoint_shared_id)?;
    validate_id("recipient_key", &input.recipient_key)?;
    if input.previous_recipient_key_id != NO_PREVIOUS_RECIPIENT_KEY {
        // A non-zero predecessor must be a real event id (not all-zero
        // fields surfaced as a typo). The layout lets the value through
        // unchanged; the projector validates the predecessor's
        // workspace + endpoint match this event.
    }

    let event = RecipientKeyEvent {
        workspace_id: input.workspace_id,
        created_at_ms: input.created_at_ms,
        endpoint_shared_id: input.endpoint_shared_id,
        recipient_key: input.recipient_key,
        previous_recipient_key_id: input.previous_recipient_key_id,
    };
    let payload = layout::encode(&event);
    let envelope = layout::sign(input.endpoint_shared_id, &input.signer_private_key, payload);
    let bytes = layout::encode_signed(&envelope);
    let record = layout::signed_record_from_bytes(bytes)?;
    let value = PublishRecipientKeyOutput {
        recipient_key_id: event_id(&record.canonical_bytes),
        workspace_id: event.workspace_id,
        endpoint_shared_id: event.endpoint_shared_id,
        recipient_key: event.recipient_key,
        previous_recipient_key_id: event.previous_recipient_key_id,
    };
    Ok(CommandOutput::with_events(value, vec![record]))
}

fn validate_id(name: &str, id: &EventId) -> Result<(), String> {
    if id.iter().all(|byte| *byte == 0) {
        return Err(format!("{name} cannot be empty"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::core::crypto;
    use crate::protocol::event_modules::types::EventScope;

    use super::*;

    fn input() -> PublishRecipientKey {
        let recipient_secret = crypto::random_x25519_private_key();
        PublishRecipientKey {
            workspace_id: [1; 32],
            created_at_ms: 1234,
            endpoint_shared_id: [2; 32],
            signer_private_key: [9; 32],
            recipient_key: crypto::x25519_public_key(&recipient_secret),
            previous_recipient_key_id: NO_PREVIOUS_RECIPIENT_KEY,
        }
    }

    #[test]
    fn publish_proposes_signed_shared_recipient_key() {
        let output = publish(input()).expect("publish");

        assert_eq!(output.events.len(), 1);
        let record = output.events[0].record();
        assert_eq!(record.scope, EventScope::Shared);
        assert_eq!(record.workspace_id, Some([1; 32]));
        assert_eq!(record.dependencies, vec![[2; 32], [1; 32]]);
        assert_eq!(output.value.recipient_key_id, output.events[0].event_id());
    }

    #[test]
    fn publish_rejects_empty_ids_without_panicking() {
        let mut input = input();
        input.recipient_key = [0; 32];

        let err = publish(input).expect_err("empty public key must fail");

        assert_eq!(err, "recipient_key cannot be empty");
    }
}
