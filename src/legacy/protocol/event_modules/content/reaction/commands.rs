//! Commands for posting reactions.
//!
//! Commands encrypt the emoji into the canonical reaction payload and return a
//! proposed signed event. They rely on the caller to provide the already
//! authorized signer and content key; they do not check target-message
//! existence or write projection rows.

use crate::core::crypto::{self, Ed25519PrivateKey, XChaCha20Poly1305Key};
use crate::core::store::Store;
use crate::legacy::protocol::event_modules::types::EventId;
use crate::legacy::protocol::event_modules::worker::CommandOutput;

use super::layout;
use super::types::ReactionEvent;

/// Sanity guard: every named id in a reaction event is non-zero. The layout
/// is intentionally lenient on decode; this helper is shared between the
/// authoring path and the receive projector so a malformed peer event is
/// rejected at projection time too.
pub(super) fn validate_event_ids(event: &ReactionEvent) -> Result<(), String> {
    validate_id("reaction workspace", &event.workspace_id)?;
    validate_id("reaction target_message_id", &event.target_message_id)?;
    validate_id("reaction author_user_id", &event.author_user_id)?;
    validate_id("reaction removal_frontier_id", &event.removal_frontier_id)?;
    validate_id(
        "reaction local_history_node_secret_id",
        &event.local_history_node_secret_id,
    )?;
    Ok(())
}

fn validate_id(name: &str, id: &EventId) -> Result<(), String> {
    if id.iter().all(|byte| *byte == 0) {
        return Err(format!("{name} cannot be empty"));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostReaction {
    pub workspace_id: EventId,
    pub created_at_ms: u64,
    pub target_message_id: EventId,
    pub author_user_id: EventId,
    pub signer_endpoint_shared_id: EventId,
    pub signer_private_key: Ed25519PrivateKey,
    pub removal_frontier_id: EventId,
    pub local_history_node_secret_id: EventId,
    pub leaf_node_secret: XChaCha20Poly1305Key,
    pub emoji: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostReactionOutput {
    pub reaction_id: EventId,
    pub target_message_id: EventId,
    pub emoji: String,
}

/// Open a sealed reaction row, returning the cleartext `ReactionRow`.
/// `Ok(None)` indicates the local leaf material is not yet on disk and
/// the row is not yet displayable. Errors surface decryption failures
/// or a mismatched leaf id.
pub fn open_sealed_reaction_row(
    store: &Store,
    row: super::rows::SealedReactionRow,
) -> Result<Option<super::types::ReactionRow>, String> {
    use crate::legacy::protocol::event_modules::encryption::local_history_node_secret;
    let unix_minute =
        crate::legacy::protocol::event_modules::content::message::types::unix_minute_for(
            row.created_at_ms,
        );
    let event_id_in_minute = super::types::reaction_event_id_in_minute(
        &row.workspace_id,
        &row.author_user_id,
        &row.target_message_id,
        &row.removal_frontier_id,
        row.created_at_ms,
    );
    let Some(leaf) = local_history_node_secret::queries::get_leaf(
        store,
        row.workspace_id,
        row.removal_frontier_id,
        unix_minute,
        event_id_in_minute,
    )?
    else {
        return Ok(None);
    };
    if leaf.local_history_node_secret_id != row.local_history_node_secret_id {
        return Err(
            "sealed reaction local_history_node_secret_id does not match local leaf".to_string(),
        );
    }
    let event = super::types::ReactionEvent {
        workspace_id: row.workspace_id,
        created_at_ms: row.created_at_ms,
        target_message_id: row.target_message_id,
        author_user_id: row.author_user_id,
        removal_frontier_id: row.removal_frontier_id,
        local_history_node_secret_id: row.local_history_node_secret_id,
        nonce: row.nonce,
        ciphertext: row.ciphertext,
    };
    let plaintext = crypto::xchacha20poly1305_decrypt(
        &leaf.node_secret,
        &layout::associated_data(&event, row.signer_endpoint_shared_id),
        &event.nonce,
        &event.ciphertext,
    )
    .map_err(|err| format!("decrypt sealed reaction: {err}"))?;
    let emoji = layout::decode_emoji_slot(&plaintext)?;
    Ok(Some(super::types::ReactionRow {
        workspace_id: row.workspace_id,
        reaction_id: row.reaction_id,
        target_message_id: row.target_message_id,
        author_user_id: row.author_user_id,
        signer_endpoint_shared_id: row.signer_endpoint_shared_id,
        created_at_ms: row.created_at_ms,
        emoji,
    }))
}

pub fn post(input: PostReaction) -> Result<CommandOutput<PostReactionOutput>, String> {
    if input.emoji.trim().is_empty() {
        return Err("reaction emoji must not be empty".to_string());
    }
    let plaintext = layout::encode_emoji_slot(&input.emoji)?;
    let mut event = ReactionEvent {
        workspace_id: input.workspace_id,
        created_at_ms: input.created_at_ms,
        target_message_id: input.target_message_id,
        author_user_id: input.author_user_id,
        removal_frontier_id: input.removal_frontier_id,
        local_history_node_secret_id: input.local_history_node_secret_id,
        nonce: crypto::random_xchacha20poly1305_nonce(),
        ciphertext: [0; super::types::REACTION_CIPHERTEXT_BYTES],
    };
    validate_event_ids(&event)?;
    let ciphertext = crypto::xchacha20poly1305_encrypt(
        &input.leaf_node_secret,
        &layout::associated_data(&event, input.signer_endpoint_shared_id),
        &event.nonce,
        &plaintext,
    )?;
    event.ciphertext = ciphertext
        .try_into()
        .map_err(|_| "reaction ciphertext length mismatch".to_string())?;

    let payload = layout::encode(&event);
    let envelope = layout::sign(
        input.signer_endpoint_shared_id,
        &input.signer_private_key,
        payload,
    );
    let bytes = layout::encode_signed(&envelope);
    let record = layout::signed_record_from_bytes(bytes)?;
    let reaction_id =
        crate::legacy::protocol::event_modules::types::event_id(&record.canonical_bytes);
    Ok(CommandOutput::with_events(
        PostReactionOutput {
            reaction_id,
            target_message_id: event.target_message_id,
            emoji: input.emoji,
        },
        vec![record],
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn post_proposes_signed_ciphertext_without_emoji_bytes() {
        let output = post(PostReaction {
            workspace_id: [1; 32],
            created_at_ms: 10,
            target_message_id: [2; 32],
            author_user_id: [3; 32],
            signer_endpoint_shared_id: [4; 32],
            signer_private_key: [9; 32],
            removal_frontier_id: [5; 32],
            local_history_node_secret_id: [6; 32],
            leaf_node_secret: [7; 32],
            emoji: "secret-react".to_string(),
        })
        .expect("post");
        let record = output.events[0].record();

        assert!(!record
            .canonical_bytes
            .windows("secret-react".len())
            .any(|window| window == b"secret-react"));
        assert_eq!(
            record.dependencies,
            vec![[4; 32], [1; 32], [3; 32], [2; 32], [5; 32], [6; 32]]
        );

        let envelope = layout::decode_signed(&record.canonical_bytes).expect("signed");
        let event = layout::decode(&envelope.payload).expect("event");
        let plaintext = crypto::xchacha20poly1305_decrypt(
            &[7; 32],
            &layout::associated_data(&event, [4; 32]),
            &event.nonce,
            &event.ciphertext,
        )
        .expect("decrypt");
        assert_eq!(
            layout::decode_emoji_slot(&plaintext).expect("decode emoji"),
            "secret-react"
        );
    }
}
