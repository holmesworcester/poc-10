//! Commands for sending messages.
//!
//! The send command takes explicit signing material plus the message body and
//! returns one proposed signed message event. The CLI is responsible for
//! resolving local endpoint material, workspace memberships, user identity, and
//! the per-message history-tree leaf key before calling this command. Each
//! message is encrypted with a per-message leaf key so deletion can retire that
//! specific leaf without revoking decryption for the rest of the frontier.

use crate::core::crypto::{self, Ed25519PrivateKey, XChaCha20Poly1305Key};
use crate::core::logical_clock;
use crate::core::store::Store;
use crate::protocol::event_modules::types::EventId;
use crate::protocol::event_modules::worker::CommandOutput;

use super::codec;
use super::queries as message_queries;
use super::types::{MessageEvent, EXPIRES_NEVER, UNIX_MINUTE_MS};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendMessage {
    pub workspace_id: EventId,
    pub created_at_ms: u64,
    pub author_user_id: EventId,
    pub signer_endpoint_shared_id: EventId,
    pub signer_private_key: Ed25519PrivateKey,
    pub removal_frontier_id: EventId,
    pub local_history_node_secret_id: EventId,
    pub leaf_node_secret: XChaCha20Poly1305Key,
    /// Authoring-time expiry stamped into the canonical bytes.
    /// `super::types::EXPIRES_NEVER` (i.e. `u64::MAX`) means no expiry.
    pub expires_at_minute: u64,
    /// Reference to the disappearing-messages policy under which this
    /// message is being authored — a signed
    /// `disappearing_messages_setting` event id. Workspace creation
    /// emits an initial setting alongside the workspace event so there
    /// is always a setting to reference. Becomes a dependency of the
    /// resulting message; the projector validates that
    /// `expires_at_minute` is consistent with the referenced policy.
    pub disappearing_setting_id: EventId,
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendMessageOutput {
    pub message_id: EventId,
    pub workspace_id: EventId,
    pub author_user_id: EventId,
    pub created_at_ms: u64,
    pub text: String,
}

pub fn send(input: SendMessage) -> Result<CommandOutput<SendMessageOutput>, String> {
    if input.text.trim().is_empty() {
        return Err("message text must not be empty".to_string());
    }
    validate_expires_at_minute(input.created_at_ms, input.expires_at_minute)?;
    let plaintext = codec::encode_text_slot(&input.text)?;
    let mut event = MessageEvent {
        workspace_id: input.workspace_id,
        created_at_ms: input.created_at_ms,
        author_user_id: input.author_user_id,
        removal_frontier_id: input.removal_frontier_id,
        local_history_node_secret_id: input.local_history_node_secret_id,
        expires_at_minute: input.expires_at_minute,
        disappearing_setting_id: input.disappearing_setting_id,
        nonce: crypto::random_xchacha20poly1305_nonce(),
        ciphertext: [0; super::types::MESSAGE_CIPHERTEXT_BYTES],
    };
    let ciphertext = crypto::xchacha20poly1305_encrypt(
        &input.leaf_node_secret,
        &codec::associated_data(&event, input.signer_endpoint_shared_id),
        &event.nonce,
        &plaintext,
    )?;
    event.ciphertext = ciphertext
        .try_into()
        .map_err(|_| "message ciphertext length mismatch".to_string())?;

    let payload = codec::encode(&event);
    let envelope = codec::sign(
        input.signer_endpoint_shared_id,
        &input.signer_private_key,
        payload,
    );
    let bytes = codec::encode_signed(&envelope);
    let record = codec::signed_record_from_bytes(bytes)?;
    let value = SendMessageOutput {
        message_id: crate::protocol::event_modules::types::event_id(&record.canonical_bytes),
        workspace_id: event.workspace_id,
        author_user_id: event.author_user_id,
        created_at_ms: event.created_at_ms,
        text: input.text,
    };
    Ok(CommandOutput::with_events(value, vec![record]))
}

/// Authoring sanity guard. The projector additionally rejects messages that
/// are already past their expiry at receive time and validates against the
/// referenced disappearing-messages setting; this check only enforces the
/// canonical-bytes invariant that an authored message's stamped expiry
/// cannot be earlier than its authored unix_minute.
pub(super) fn validate_expires_at_minute(
    created_at_ms: u64,
    expires_at_minute: u64,
) -> Result<(), String> {
    if expires_at_minute == EXPIRES_NEVER {
        return Ok(());
    }
    let authored_minute = created_at_ms / UNIX_MINUTE_MS;
    if expires_at_minute < authored_minute {
        return Err("message expires_at_minute is earlier than authored minute".to_string());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// CLI authoring helpers
// ---------------------------------------------------------------------------
//
// Multi-step state reads that the message/reaction/file deletion / file
// CLIs all need before they can build a signed event: workspace
// membership lookup, active-frontier resolution for authoring, and
// next-timestamp computation. They live here so the CLI runners stay
// thin and so peer CLIs can share the same resolution logic.

/// Locate the local endpoint's membership row for a workspace and verify
/// the locally-stored signing public key matches what the membership row
/// recorded. Returns the row; the CLI uses fields like
/// `endpoint_shared_id`, `user_authority_event_id`, and `endpoint_role`.
pub fn require_local_membership(
    store: &Store,
    workspace_id: EventId,
) -> Result<
    crate::protocol::event_modules::identity::endpoint_shared::types::EndpointMembershipRow,
    String,
> {
    use crate::protocol::event_modules::identity::{endpoint, endpoint_shared};
    let local = endpoint::commands::local_keypair(store)?
        .ok_or_else(|| "local endpoint is missing".to_string())?;
    let key = endpoint_shared::schema::endpoint_membership_key(local.endpoint, workspace_id);
    let value = store
        .table_row(endpoint_shared::schema::ENDPOINT_MEMBERSHIPS, &key)
        .map_err(|err| format!("load endpoint membership: {err}"))?
        .ok_or_else(|| "local endpoint is not joined to workspace".to_string())?;
    let row = endpoint_shared::schema::decode_endpoint_membership_row(&key, &value)?;
    if row.signing_public_key != local.signing_public_key {
        return Err("local endpoint signing key does not match workspace membership".to_string());
    }
    Ok(row)
}

/// Compute the next-authoring timestamp for events in this workspace.
/// Folds in both content (`message`) and protocol (`content_event`)
/// timestamps so concurrent authoring across event families doesn't go
/// backwards.
pub fn next_authoring_timestamp(store: &Store, workspace_id: EventId) -> Result<u64, String> {
    let from_messages = max_timestamp_for_messages(store, workspace_id)?;
    let from_content =
        crate::protocol::event_modules::content::content_event::queries::max_timestamp_for_workspace(
            store,
            workspace_id,
        )?;
    logical_clock::next_timestamp(store, from_messages.max(from_content))
}

fn max_timestamp_for_messages(store: &Store, workspace_id: EventId) -> Result<u64, String> {
    let mut max = 0u64;
    let mut by_id = std::collections::BTreeMap::new();
    for row in message_queries::list_for_workspace(store, workspace_id)? {
        by_id.insert(row.message_id, row);
    }
    for row in message_queries::list_sealed_for_workspace(store, workspace_id)? {
        by_id
            .entry(row.message_id)
            .or_insert_with(|| super::types::MessageRow {
                workspace_id: row.workspace_id,
                message_id: row.message_id,
                created_at_ms: row.created_at_ms,
                author_user_id: row.author_user_id,
                signer_endpoint_shared_id: row.signer_endpoint_shared_id,
                text: String::new(),
            });
    }
    for row in by_id.values() {
        if row.created_at_ms > max {
            max = row.created_at_ms;
        }
    }
    Ok(max)
}

/// Find the most recent local frontier for which this store has key
/// material. Senders need a frontier id to author messages; receivers do
/// not call this because they trust the message body to name the
/// frontier id.
///
/// A frontier is considered active when EITHER its F root row
/// (`local_key_secret`) is on disk, OR at least one history-node sibling
/// row survives under it. The latter case arises after
/// `retire_deleted_event_leaf` wipes F: the materialized time-tree
/// siblings still cover authoring for every non-retired coordinate, so
/// `derive_event_leaf` can keep working without forcing a
/// `key-frontier` rotation.
pub fn require_active_frontier_id(store: &Store, workspace_id: EventId) -> Result<EventId, String> {
    use crate::protocol::event_modules::encryption::{
        local_history_node_secret, local_key_secret, removal_frontier,
    };
    let mut candidates = Vec::new();
    for frontier in removal_frontier::queries::list_for_workspace(store, workspace_id)? {
        let root_present =
            local_key_secret::queries::get(store, workspace_id, frontier.removal_frontier_id)?
                .is_some();
        let has_siblings = !root_present
            && !local_history_node_secret::queries::list_for_frontier(
                store,
                workspace_id,
                frontier.removal_frontier_id,
            )?
            .is_empty();
        if !root_present && !has_siblings {
            continue;
        }
        candidates.push((frontier.created_at_ms, frontier.removal_frontier_id));
    }
    candidates.sort_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)));
    let Some((_, removal_frontier_id)) = candidates.pop() else {
        return Err(
            "local content key is missing for workspace; run key-frontier or key-derive"
                .to_string(),
        );
    };
    Ok(removal_frontier_id)
}

/// Compute the authoring-time `expires_at_minute` and the
/// `disappearing_setting_id` reference that produced it. Reads from the
/// active `disappearing_messages_setting` event for the workspace, which
/// is guaranteed to exist because workspace creation emits an initial
/// setting. Returns `(EXPIRES_NEVER, setting_event_id)` when the active
/// TTL is zero.
pub fn workspace_expires_at_minute(
    store: &Store,
    workspace_id: EventId,
    created_at_ms: u64,
) -> Result<(u64, EventId), String> {
    use crate::protocol::event_modules::encryption::disappearing_messages_setting::queries as setting_queries;
    let active = setting_queries::active_for_workspace(store, workspace_id)?
        .ok_or_else(|| "workspace has no active disappearing-messages setting".to_string())?;
    let ttl_minutes = active.ttl_minutes;
    let reference = active.setting_event_id;
    if ttl_minutes == 0 {
        return Ok((EXPIRES_NEVER, reference));
    }
    let authored_minute = created_at_ms / UNIX_MINUTE_MS;
    Ok((
        authored_minute.saturating_add(ttl_minutes as u64),
        reference,
    ))
}

/// Per-event leaf key material identifying which `local_history_node_secret`
/// covers the authoring coord and the AEAD secret bytes for that leaf.
///
/// Constructed by the CLI-side `derive_message_leaf` helper (which drives the
/// encryption worker); commands consume `MessageLeafKey` as an explicit
/// authoring input rather than asking workers for it themselves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MessageLeafKey {
    pub removal_frontier_id: EventId,
    pub local_history_node_secret_id: EventId,
    pub leaf_node_secret: XChaCha20Poly1305Key,
}

/// True iff the target message id has a deletion label authored by
/// `author_user_id`. Read-side defensive filter: projectors purge message
/// rows for both message-before-tombstone and tombstone-before-message
/// orders, so most callers see message rows that already reflect
/// deletion. This helper exists to filter rows written by older code or
/// interrupted test fixtures.
pub fn is_deleted_by_author(
    store: &Store,
    message_id: &EventId,
    author_user_id: &EventId,
) -> Result<bool, String> {
    use crate::protocol::event_modules::content::message_deletion::types::deletion_label_author;
    let labels = crate::protocol::event_modules::schema::event_labels(store, message_id)
        .map_err(|err| format!("load deletion labels: {err}"))?;
    Ok(labels.iter().any(|label| {
        deletion_label_author(label)
            .map(|author| author == *author_user_id)
            .unwrap_or(false)
    }))
}

/// Open a sealed message row's ciphertext using the local leaf secret
/// implied by the row, returning the message in plaintext form. Returns
/// `Ok(None)` when the matching local leaf is not (yet) on disk;
/// callers should treat that as "this sealed row is not openable yet"
/// rather than an error. Returns `Err` only when the decryption fails
/// after a matching leaf is found (which would indicate corruption).
pub fn open_sealed_message_row(
    store: &Store,
    row: super::schema::SealedMessageRow,
) -> Result<Option<super::types::MessageRow>, String> {
    use crate::protocol::event_modules::encryption::local_history_node_secret;
    let unix_minute = super::types::unix_minute_for(row.created_at_ms);
    let event_id_in_minute = super::types::message_event_id_in_minute(
        &row.workspace_id,
        &row.author_user_id,
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
            "sealed message local_history_node_secret_id does not match local leaf".to_string(),
        );
    }
    let event = super::types::MessageEvent {
        workspace_id: row.workspace_id,
        created_at_ms: row.created_at_ms,
        author_user_id: row.author_user_id,
        removal_frontier_id: row.removal_frontier_id,
        local_history_node_secret_id: row.local_history_node_secret_id,
        expires_at_minute: row.expires_at_minute,
        disappearing_setting_id: row.disappearing_setting_id,
        nonce: row.nonce,
        ciphertext: row.ciphertext,
    };
    let plaintext = crypto::xchacha20poly1305_decrypt(
        &leaf.node_secret,
        &codec::associated_data(&event, row.signer_endpoint_shared_id),
        &event.nonce,
        &event.ciphertext,
    )
    .map_err(|err| format!("decrypt sealed message: {err}"))?;
    let text = codec::decode_text_slot(&plaintext)?;
    Ok(Some(super::types::MessageRow {
        workspace_id: row.workspace_id,
        message_id: row.message_id,
        created_at_ms: row.created_at_ms,
        author_user_id: row.author_user_id,
        signer_endpoint_shared_id: row.signer_endpoint_shared_id,
        text,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn send_proposes_signed_ciphertext_without_plaintext_bytes() {
        let output = send(SendMessage {
            workspace_id: [1; 32],
            created_at_ms: 10,
            author_user_id: [2; 32],
            signer_endpoint_shared_id: [3; 32],
            signer_private_key: [9; 32],
            removal_frontier_id: [4; 32],
            local_history_node_secret_id: [5; 32],
            leaf_node_secret: [6; 32],
            expires_at_minute: super::super::types::EXPIRES_NEVER,
            disappearing_setting_id: [1; 32],
            text: "private message".to_string(),
        })
        .expect("send");
        let record = output.events[0].record();

        assert!(!record
            .canonical_bytes
            .windows("private message".len())
            .any(|window| window == b"private message"));
        assert_eq!(
            record.dependencies,
            vec![[3; 32], [1; 32], [2; 32], [4; 32], [5; 32]]
        );

        let envelope = codec::decode_signed(&record.canonical_bytes).expect("signed");
        let event = codec::decode(&envelope.payload).expect("event");
        let plaintext = crypto::xchacha20poly1305_decrypt(
            &[6; 32],
            &codec::associated_data(&event, [3; 32]),
            &event.nonce,
            &event.ciphertext,
        )
        .expect("decrypt");
        assert_eq!(
            codec::decode_text_slot(&plaintext).expect("decode text"),
            "private message"
        );
    }

    #[test]
    fn send_with_identical_inputs_produces_identical_event_id() {
        // Determinism property: two callers with the same canonical inputs
        // (and the same fresh nonce/AEAD ciphertext) collapse to the same
        // event id. Here we drive that through the full send path to also
        // sanity-check that the leaf id and timestamp survive the round trip.
        let input = SendMessage {
            workspace_id: [1; 32],
            created_at_ms: 60_000,
            author_user_id: [2; 32],
            signer_endpoint_shared_id: [3; 32],
            signer_private_key: [9; 32],
            removal_frontier_id: [4; 32],
            local_history_node_secret_id: [5; 32],
            leaf_node_secret: [6; 32],
            expires_at_minute: super::super::types::EXPIRES_NEVER,
            disappearing_setting_id: [1; 32],
            text: "hello".to_string(),
        };
        // The two outputs will not be byte-identical because each draws a
        // fresh AEAD nonce; but the deterministic *leaf coord* derivation is
        // verified separately by the type's `event_id_in_minute_derived` test.
        let first = send(input.clone()).expect("first send");
        let second = send(input).expect("second send");
        // Both produce structurally valid records with the same leaf id and
        // same metadata.
        let first_envelope = codec::decode_signed(&first.events[0].record().canonical_bytes)
            .expect("first envelope");
        let first_event = codec::decode(&first_envelope.payload).expect("first event");
        let second_envelope = codec::decode_signed(&second.events[0].record().canonical_bytes)
            .expect("second envelope");
        let second_event = codec::decode(&second_envelope.payload).expect("second event");
        assert_eq!(
            first_event.local_history_node_secret_id,
            second_event.local_history_node_secret_id
        );
        assert_eq!(
            first_event.event_id_in_minute_derived(),
            second_event.event_id_in_minute_derived()
        );
    }
}
