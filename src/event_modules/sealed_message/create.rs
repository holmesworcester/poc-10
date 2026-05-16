//! `send_message`: the first concrete target command.
//!
//! The command takes a workspace id and a free-text body and turns them into
//! a single sealed-message fact ready for admission. It uses only its narrow
//! `CommandContext` view: signing material comes from the identity vault,
//! encryption material comes from the identity vault, and the timestamp
//! comes from the clock surface. The command does not run a worker, does
//! not generate fresh local keys, and does not touch the protocol crate.
//!
//! The encrypted body is a length-prefixed plaintext padded out to the
//! fixed sealed-message slot. `decode_sealed_message` plus the workspace
//! key recover the original text exactly.

use crate::commands::context::{CommandContext, CommandOutput, WorkspaceId};
use crate::core::crypto::{self, XChaCha20Poly1305Nonce, XCHACHA20_POLY1305_TAG_BYTES};
use crate::core::facts::{Fact, FactScope, ScopeKind};
use crate::core::wire;
use crate::event_modules::sealed_message::fact::{
    SealedMessageFact, CIPHERTEXT_BYTES, NONCE_BYTES, UNIX_MINUTE_MS,
};
use crate::event_modules::sealed_message::layout;
use crate::event_modules::signed_fact::create as signed_fact_create;
use crate::event_modules::signed_fact::layout as signed_fact_layout;

/// The maximum text byte length that fits the fixed sealed-message slot.
///
/// The ciphertext slot is `CIPHERTEXT_BYTES`. XChaCha20-Poly1305 expands
/// the plaintext by `XCHACHA20_POLY1305_TAG_BYTES`. We reserve a four-byte
/// length prefix so the plaintext is self-describing on decode.
pub const TEXT_LENGTH_PREFIX_BYTES: usize = 4;
pub const PLAINTEXT_SLOT_BYTES: usize = CIPHERTEXT_BYTES - XCHACHA20_POLY1305_TAG_BYTES;
pub const MAX_TEXT_BYTES: usize = PLAINTEXT_SLOT_BYTES - TEXT_LENGTH_PREFIX_BYTES;

/// A typed summary of a successful `send_message` call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendSummary {
    pub workspace_id: WorkspaceId,
    pub message_fact_id: crate::core::facts::FactId,
    pub created_at_ms: u64,
}

/// Construct a signed sealed-message fact for `text` in `workspace_id`.
///
/// The returned `CommandOutput` carries one proposed fact whose bytes are
/// the `signed_fact` envelope around the inner sealed-message payload. The
/// fact id is therefore the id of the signed envelope, not of the inner
/// sealed bytes. Callers that need the inner sealed-message decode through
/// `signed_fact::layout::decode_signed_fact` first.
///
/// The command emits no deferred intents in this first cut: the projector
/// and downstream handlers own the rest of the pipeline.
pub fn send_message(
    ctx: &CommandContext<'_>,
    workspace_id: WorkspaceId,
    text: &str,
) -> Result<CommandOutput<SendSummary>, String> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Err("send_message text must not be blank".to_string());
    }
    if text.as_bytes().len() > MAX_TEXT_BYTES {
        return Err(format!(
            "send_message text exceeds {MAX_TEXT_BYTES} byte sealed slot"
        ));
    }

    let signing = ctx.local_signing_capability(workspace_id)?;
    let encryption = ctx.local_encryption_capability(workspace_id)?;
    if signing.fact.workspace_id != workspace_id {
        return Err("signing capability is not bound to this workspace".to_string());
    }
    if encryption.fact.workspace_id != workspace_id {
        return Err("encryption capability is not bound to this workspace".to_string());
    }

    let created_at_ms = ctx.next_timestamp();
    let minute = created_at_ms / UNIX_MINUTE_MS;

    let nonce = deterministic_nonce(workspace_id, signing.fact.signer_id, created_at_ms);
    let plaintext = pad_plaintext(text.as_bytes())?;
    let ciphertext = crypto::xchacha20poly1305_encrypt(
        &encryption.fact.key_secret,
        &associated_data(workspace_id, encryption.fact.frontier_id, minute),
        &nonce,
        &plaintext,
    )?;
    if ciphertext.len() != CIPHERTEXT_BYTES {
        return Err(format!(
            "sealed ciphertext is {} bytes, expected {CIPHERTEXT_BYTES}",
            ciphertext.len()
        ));
    }

    // Identity is the authoring user for this first cut: the same fact id
    // identifies the local signer's author until a separate author/user
    // identity fact lands in target.
    let author_user_id = signing.fact.signer_id;

    let sealed = SealedMessageFact {
        workspace_id,
        created_at_ms,
        author_user_id,
        signer_id: signing.fact.signer_id,
        frontier_id: encryption.fact.frontier_id,
        local_history_node_secret_id: [0; 32],
        expires_at_minute: u64::MAX,
        disappearing_setting_id: [0; 32],
        minute,
        leaf_id: [0; 32],
        nonce,
        ciphertext,
    };
    let payload = layout::encode_sealed_message(&sealed)?;
    // Wrap the inner sealed-message payload in a signed envelope so the
    // emitted fact carries authentication. The signed_fact module owns the
    // signing primitive; the command merely supplies the payload.
    let envelope_bytes = signed_fact_create::sign_payload_bytes(
        signing.fact.signer_id,
        &signing.fact.private_key,
        payload,
    )?;
    debug_assert_eq!(envelope_bytes.len(), signed_fact_layout::SIGNED_FACT_BYTES);

    let scope = FactScope::Scoped {
        kind: ScopeKind::new("workspace").expect("valid workspace scope"),
        id: workspace_id,
    };
    // The emitted fact is the signed envelope. Callers that need the inner
    // sealed-message bytes call `signed_fact::layout::decode_signed_fact` on
    // `fact.bytes` and then `sealed_message::layout::decode_sealed_message`
    // on the envelope payload.
    let fact = Fact::new(scope, created_at_ms, envelope_bytes);

    Ok(CommandOutput::new(SendSummary {
        workspace_id,
        message_fact_id: fact.id,
        created_at_ms,
    })
    .with_facts(vec![fact]))
}

/// Pad caller text into the fixed plaintext slot.
///
/// The first four bytes carry the BE-encoded length of the original text;
/// the remainder is zero-padded to `PLAINTEXT_SLOT_BYTES`. This shape is
/// reversible by `recover_text` below and by any tests that read the
/// decoded sealed message.
pub fn pad_plaintext(text: &[u8]) -> Result<Vec<u8>, String> {
    if text.len() > MAX_TEXT_BYTES {
        return Err("text too long for sealed slot".to_string());
    }
    let mut buf = vec![0u8; PLAINTEXT_SLOT_BYTES];
    let len = u32::try_from(text.len()).expect("text length fits u32");
    wire::put_u32be(len, &mut buf[..TEXT_LENGTH_PREFIX_BYTES]).map_err(|err| format!("{err:?}"))?;
    buf[TEXT_LENGTH_PREFIX_BYTES..TEXT_LENGTH_PREFIX_BYTES + text.len()].copy_from_slice(text);
    Ok(buf)
}

/// Recover the caller text from a decrypted plaintext slot.
pub fn recover_text(plaintext: &[u8]) -> Result<String, String> {
    if plaintext.len() != PLAINTEXT_SLOT_BYTES {
        return Err(format!(
            "plaintext slot is {} bytes, expected {PLAINTEXT_SLOT_BYTES}",
            plaintext.len()
        ));
    }
    let len = wire::take_u32be(&plaintext[..TEXT_LENGTH_PREFIX_BYTES])
        .map_err(|err| format!("{err:?}"))? as usize;
    if len > MAX_TEXT_BYTES {
        return Err("recovered text length out of range".to_string());
    }
    let bytes = &plaintext[TEXT_LENGTH_PREFIX_BYTES..TEXT_LENGTH_PREFIX_BYTES + len];
    String::from_utf8(bytes.to_vec()).map_err(|err| format!("text was not utf-8: {err}"))
}

/// Associated-data bytes bound to every sealed message ciphertext.
///
/// Including workspace, frontier, and minute pins the ciphertext to its
/// surrounding context: a peer that swaps a sealed message into a different
/// workspace or frontier cannot reuse the ciphertext.
pub fn associated_data(
    workspace_id: WorkspaceId,
    frontier_id: crate::core::facts::FactId,
    minute: u64,
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(32 + 32 + 8);
    bytes.extend_from_slice(&workspace_id);
    bytes.extend_from_slice(&frontier_id);
    let mut minute_bytes = [0u8; 8];
    wire::put_u64be(minute, &mut minute_bytes).expect("eight-byte minute slot");
    bytes.extend_from_slice(&minute_bytes);
    bytes
}

/// Deterministic per-message nonce.
///
/// The nonce is derived from `(workspace_id, signer_id, created_at_ms)` so
/// the command does not have to read system randomness. Identity owns the
/// freshness of `signer_id`; the clock surface owns the monotonicity of
/// `created_at_ms`.
pub fn deterministic_nonce(
    workspace_id: WorkspaceId,
    signer_id: crate::core::facts::FactId,
    created_at_ms: u64,
) -> XChaCha20Poly1305Nonce {
    let mut info = Vec::with_capacity(32 + 32 + 8);
    info.extend_from_slice(&workspace_id);
    info.extend_from_slice(&signer_id);
    let mut ts = [0u8; 8];
    wire::put_u64be(created_at_ms, &mut ts).expect("eight-byte timestamp slot");
    info.extend_from_slice(&ts);
    let hash = crypto::hash(&info);
    let mut nonce = [0u8; NONCE_BYTES];
    nonce.copy_from_slice(&hash[..NONCE_BYTES]);
    nonce
}
