//! Driver for outbound transit frame packaging.
//!
//! Decodes a `send_on_connection` intent, gathers the sendable inner fact
//! bytes through the handler context, packs them into a flat inner payload,
//! picks the small or large transit size class, derives a deterministic nonce
//! from the connection id, and encrypts the inner payload into the fixed
//! ciphertext slot of the chosen frame.
//!
//! The AEAD step needs the connection secret (and the sender / receiver
//! endpoint ids that double as AEAD context). Those are not yet threaded
//! through `HandlerContext` in poc-10, so the live `handle` path packs the
//! inner payload, picks the size class, and stops with a clear retryable
//! error so the intent stays queued for a later turn instead of being
//! dropped. The real packaging path is exposed as
//! [`package_transit_frame`] and is exercised end-to-end by the poc-10
//! handler tests using a synthetic connection secret.

use crate::core::crypto::{xchacha20poly1305_encrypt, XChaCha20Poly1305Key};
use crate::core::handler_dispatch::{HandlerContext, HandlerFactId, HandlerOutput, IntentHandler};
use crate::core::intents::{Intent, IntentExecution, IntentKind};
use crate::event_modules::transit::layout::{
    TRANSIT_FRAME_SIZE_CLASS_LARGE, TRANSIT_FRAME_SIZE_CLASS_SMALL, TRANSIT_FRAME_TAG,
    TRANSIT_FRAME_VERSION, TRANSIT_LARGE_CIPHERTEXT_BYTES, TRANSIT_LARGE_PLAINTEXT_BYTES,
    TRANSIT_LARGE_WIRE_BYTES, TRANSIT_SMALL_CIPHERTEXT_BYTES, TRANSIT_SMALL_PLAINTEXT_BYTES,
    TRANSIT_SMALL_WIRE_BYTES,
};
use crate::event_modules::{encryption, signed_fact};

use super::intent::{
    decode_send_on_connection, HandlerId, TransitSendOnConnection, TRANSIT_SEND_ON_CONNECTION,
};

/// Connection secret + endpoint context is required to AEAD-encrypt the inner
/// payload of a transit frame. Until that context is wired through the
/// handler dispatcher the live driver finishes inner-payload packing and the
/// size-class decision, then returns this error so the intent stays queued.
pub const SECRET_CONTEXT_NOT_WIRED: &str = "connection secret context not yet wired";

/// Intent kind emitted after packaging succeeds, carrying the produced frame
/// bytes to the connection-transport layer. The kind is owned by this handler
/// so we do not pull in connection-side modules here.
pub const TRANSIT_NETWORK_SEND: &str = "transit_network_send";

/// Inner payload framing version. The receiver uses this byte to know how the
/// concatenated fact bytes are laid out after AEAD opens the slot.
pub const INNER_PAYLOAD_VERSION: u8 = 1;

/// AAD domain string mixed into transit AEAD so frames from this codec cannot
/// be confused with any other XChaCha20-Poly1305 usage in the codebase.
pub const TRANSIT_AEAD_DOMAIN: &[u8] = b"topo:transit:v1";

/// Domain separation tag for the deterministic nonce derivation.
pub const TRANSIT_NONCE_DOMAIN: &[u8] = b"topo:transit-nonce:v1";

#[derive(Debug, Clone, Default)]
pub struct TransitSendOnConnectionHandler;

impl TransitSendOnConnectionHandler {
    pub fn new() -> Self {
        Self
    }
}

impl IntentHandler for TransitSendOnConnectionHandler {
    fn accepts(&self, intent: &Intent) -> bool {
        intent.kind.as_str() == TRANSIT_SEND_ON_CONNECTION
    }

    fn input_fact_ids(&self, intent: &Intent) -> Result<Vec<HandlerFactId>, String> {
        Ok(decode_send_on_connection(intent)?.fact_ids)
    }

    fn handle(&self, intent: &Intent, context: &HandlerContext) -> Result<HandlerOutput, String> {
        let input = decode_send_on_connection(intent)?;
        let inner_facts = sendable_fact_bytes(&input, context)?;
        let inner_payload = pack_inner_payload(&inner_facts);

        // Validate that the inner payload at least fits the largest frame
        // class before stopping at the secret-context stub. This way over-
        // sized payloads fail fast instead of being silently re-queued.
        let _ = pick_size_class(inner_payload.len())?;

        Err(SECRET_CONTEXT_NOT_WIRED.to_string())
    }
}

/// Frame size class selected for an inner payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransitFrameSizeClass {
    Small,
    Large,
}

/// Choose the smallest transit frame class whose plaintext budget fits the
/// inner payload. Returns an error for over-sized payloads.
pub fn pick_size_class(inner_len: usize) -> Result<TransitFrameSizeClass, String> {
    if inner_len <= TRANSIT_SMALL_PLAINTEXT_BYTES {
        Ok(TransitFrameSizeClass::Small)
    } else if inner_len <= TRANSIT_LARGE_PLAINTEXT_BYTES {
        Ok(TransitFrameSizeClass::Large)
    } else {
        Err(format!(
            "transit send refused inner payload of {inner_len} bytes (max {TRANSIT_LARGE_PLAINTEXT_BYTES})"
        ))
    }
}

/// Pack the ordered inner fact bytes into a single length-prefixed payload.
pub fn pack_inner_payload(facts: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 4 + facts.iter().map(|f| 4 + f.len()).sum::<usize>());
    out.push(INNER_PAYLOAD_VERSION);
    out.extend_from_slice(&(facts.len() as u32).to_be_bytes());
    for fact in facts {
        out.extend_from_slice(&(fact.len() as u32).to_be_bytes());
        out.extend_from_slice(fact);
    }
    out
}

/// Derive a deterministic 24-byte nonce from the connection id and a hash of
/// the inner payload. Using the inner payload digest as the second mixing
/// input guarantees nonce uniqueness across distinct sends on the same
/// connection without requiring a stateful send counter at this layer.
pub fn derive_transit_nonce(connection_id: &HandlerId, inner_payload: &[u8]) -> [u8; 24] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(TRANSIT_NONCE_DOMAIN);
    hasher.update(connection_id);
    hasher.update(inner_payload);
    let mut out = [0u8; 24];
    out.copy_from_slice(&hasher.finalize().as_bytes()[..24]);
    out
}

/// AAD used to bind a transit frame's public header to its ciphertext.
fn transit_aad(
    sender: &HandlerId,
    receiver: &HandlerId,
    connection: &HandlerId,
    nonce: &[u8; 24],
    size_class: TransitFrameSizeClass,
) -> Vec<u8> {
    let class_byte = match size_class {
        TransitFrameSizeClass::Small => 0u8,
        TransitFrameSizeClass::Large => 1u8,
    };
    let mut aad = Vec::with_capacity(TRANSIT_AEAD_DOMAIN.len() + 1 + 32 * 3 + 24);
    aad.extend_from_slice(TRANSIT_AEAD_DOMAIN);
    aad.push(class_byte);
    aad.extend_from_slice(sender);
    aad.extend_from_slice(receiver);
    aad.extend_from_slice(connection);
    aad.extend_from_slice(nonce);
    aad
}

/// Encrypt `inner_payload` into a fixed-width transit frame and return the
/// outer wire bytes plus the selected size class. The caller supplies the
/// connection secret (used as the AEAD key) and the sender / receiver
/// endpoint ids that the AEAD header binds.
pub fn package_transit_frame(
    connection_secret: &XChaCha20Poly1305Key,
    sender_endpoint_id: &HandlerId,
    receiver_endpoint_id: &HandlerId,
    connection_id: &HandlerId,
    inner_payload: &[u8],
) -> Result<(TransitFrameSizeClass, Vec<u8>), String> {
    let size_class = pick_size_class(inner_payload.len())?;
    let nonce = derive_transit_nonce(connection_id, inner_payload);
    let aad = transit_aad(
        sender_endpoint_id,
        receiver_endpoint_id,
        connection_id,
        &nonce,
        size_class,
    );
    let ciphertext = xchacha20poly1305_encrypt(connection_secret, &aad, &nonce, inner_payload)
        .map_err(|err| format!("transit AEAD encrypt failed: {err}"))?;

    // Build the output buffer directly so neither the ~1 MiB
    // `TransitLargeV1` struct nor a transient `FixedSlot` ciphertext is ever
    // placed on the stack. The byte layout below matches
    // `event_modules::transit::layout::TransitSmallV1::encode` /
    // `TransitLargeV1::encode` exactly and is asserted by the unit tests via
    // `peek_frame_header` + manual ciphertext slot unpacking.
    let (outer_len, class_byte, slot_capacity) = match size_class {
        TransitFrameSizeClass::Small => (
            TRANSIT_SMALL_WIRE_BYTES,
            TRANSIT_FRAME_SIZE_CLASS_SMALL,
            TRANSIT_SMALL_CIPHERTEXT_BYTES,
        ),
        TransitFrameSizeClass::Large => (
            TRANSIT_LARGE_WIRE_BYTES,
            TRANSIT_FRAME_SIZE_CLASS_LARGE,
            TRANSIT_LARGE_CIPHERTEXT_BYTES,
        ),
    };
    if ciphertext.len() > slot_capacity {
        return Err(format!(
            "transit ciphertext does not fit selected size class: have {} max {}",
            ciphertext.len(),
            slot_capacity
        ));
    }

    let mut out = vec![0u8; outer_len];
    // Header: 4 byte tag + 1 version + 1 size class + 3 * 32 ids + 24 nonce.
    out[..4].copy_from_slice(TRANSIT_FRAME_TAG.0.as_slice());
    out[4] = TRANSIT_FRAME_VERSION;
    out[5] = class_byte;
    out[6..38].copy_from_slice(sender_endpoint_id);
    out[38..70].copy_from_slice(receiver_endpoint_id);
    out[70..102].copy_from_slice(connection_id);
    out[102..126].copy_from_slice(&nonce);

    // FixedSlot: u32 BE length + zero-padded slot bytes.
    let slot_start = 126;
    let ct_len = u32::try_from(ciphertext.len())
        .map_err(|_| "transit ciphertext length exceeds u32".to_string())?;
    out[slot_start..slot_start + 4].copy_from_slice(&ct_len.to_be_bytes());
    out[slot_start + 4..slot_start + 4 + ciphertext.len()].copy_from_slice(&ciphertext);

    Ok((size_class, out))
}

/// Build the follow-up `transit_network_send` intent that carries the
/// produced frame bytes to the connection transport layer.
pub fn transit_network_send_intent(
    connection_id: HandlerId,
    frame_bytes: Vec<u8>,
) -> Result<Intent, String> {
    let mut payload = Vec::with_capacity(1 + 32 + 4 + frame_bytes.len());
    payload.push(1);
    payload.extend_from_slice(&connection_id);
    payload.extend_from_slice(&(frame_bytes.len() as u32).to_be_bytes());
    payload.extend_from_slice(&frame_bytes);

    let mut hasher = blake3::Hasher::new();
    hasher.update(b"topo:transit-network-send:v1:");
    hasher.update(&connection_id);
    hasher.update(&frame_bytes);
    let key = hasher.finalize().as_bytes().to_vec();

    Ok(Intent::new(
        IntentKind::new(TRANSIT_NETWORK_SEND)
            .map_err(|err| format!("transit network send intent kind rejected: {err}"))?,
        IntentExecution::Deferred,
        key,
        payload,
    ))
}

pub fn sendable_fact_bytes(
    input: &TransitSendOnConnection,
    context: &HandlerContext,
) -> Result<Vec<Vec<u8>>, String> {
    input
        .fact_ids
        .iter()
        .map(|fact_id| {
            let bytes = context.require_non_local_fact_bytes(fact_id)?;
            require_sendable_fact_bytes(fact_id, bytes)?;
            Ok(bytes.to_vec())
        })
        .collect()
}

pub fn require_sendable_fact_bytes(fact_id: &[u8; 32], bytes: &[u8]) -> Result<(), String> {
    if let Some(tag) = bytes.first().copied() {
        if is_known_private_or_local_fact_tag(tag) {
            return Err(format!(
                "transit send refused private/local fact tag {tag} for {:?}",
                fact_id
            ));
        }
    }
    Ok(())
}

fn is_known_private_or_local_fact_tag(tag: u8) -> bool {
    matches!(
        tag,
        signed_fact::layout::TYPE_LOCAL_SIGNER_SECRET
            | encryption::layout::TYPE_LOCAL_KEY_SECRET
            | encryption::layout::TYPE_LOCAL_HISTORY_NODE_SECRET
            | encryption::layout::TYPE_LOCAL_RECIPIENT_KEY
    )
}
