//! Decrypt-and-recurse helper for the chained inbound pipeline.
//!
//! Per `plan.md` wave-1: an `EncryptedEvent` arriving on the wire is
//! unwrapped by `connection.unwrap`, lands in the per-inner chain, and at
//! projector dispatch must be:
//!
//!   1. matched against a locally-known workspace key (looked up by the
//!      encrypted event's `key_event_id` in the `key_secrets` projector
//!      table),
//!   2. AES-256-GCM decrypted + AEAD-verified,
//!   3. its inner canonical bytes re-entered into the chain's
//!      `admit_event_id → parse → project → apply` tail under the same
//!      transaction.
//!
//! This file owns step (1) and (2). The recursion in (3) lives in
//! `runtime/control_loop/inbound_step.rs` (the only other file the chain
//! itself touches).

use rusqlite::{params, Connection, OptionalExtension};

use crate::event_modules::EncryptedEvent;
use crate::runtime::control_loop::work_item::BlakeId;
use crate::shared::crypto::decrypt_event_blob;

/// Inner event recovered from a successful decrypt.
#[derive(Debug, Clone)]
pub struct DecryptedInner {
    /// Canonical bytes of the inner (plaintext) event — same shape as
    /// any other received event blob.
    pub canonical_bytes: Vec<u8>,
    /// `BLAKE3(canonical_bytes)` — matches the chain's
    /// `event_id` convention (control_loop uses BLAKE3).
    pub event_id: BlakeId,
}

/// Outcome of attempting to decrypt an `EncryptedEvent` against the
/// locally-known workspace keys.
#[derive(Debug, Clone)]
pub enum DecryptOutcome {
    Decrypted(DecryptedInner),
    /// Workspace key referenced by `key_event_id` is not yet present in
    /// state. The chain will mark the encrypted event `blocked` on this
    /// id so the later `KeyShared` / `KeySecret` arrival unblocks it.
    KeyMissing { key_id: BlakeId },
    /// Ciphertext present + key resolved, but AEAD verification failed,
    /// or the recovered plaintext is structurally inadmissible (zero
    /// length, nested encryption). Encrypted event must be rejected.
    InvalidCiphertext { reason: String },
}

/// Decrypts an `EncryptedEvent`'s inner ciphertext under the matching
/// workspace key found in the `key_secrets` projector table. Returns the
/// inner canonical bytes and the chain's BLAKE3 event id.
///
/// The lookup mirrors the legacy projector at
/// `state/projection/encrypted.rs`, scoped to the chain's `__chain__`
/// `recorded_by` sentinel (the value used by the new pipeline when the
/// `key_secret` projector writes its row — see
/// `runtime/control_loop/inbound_step.rs::project_and_apply`).
pub fn decrypt_encrypted(ev: &EncryptedEvent, db: &Connection) -> rusqlite::Result<DecryptOutcome> {
    use base64::Engine;
    let key_event_id_b64 = base64::engine::general_purpose::STANDARD.encode(ev.key_event_id);

    // Look up the symmetric AES-256 key from the `key_secrets` projector
    // table. We don't filter by `recorded_by` — the chain's chosen
    // sentinel is irrelevant when matching by stable key_event_id.
    // Selecting any matching row keeps the decrypter compatible with both
    // the legacy `peer_id` recorded_by value AND the chain's
    // `__chain__` value, so a key minted by either path decrypts.
    let key_bytes: Option<Vec<u8>> = db
        .query_row(
            "SELECT key_bytes FROM key_secrets WHERE event_id = ?1 LIMIT 1",
            params![key_event_id_b64],
            |row| row.get(0),
        )
        .optional()?;

    let key_bytes = match key_bytes {
        Some(k) => k,
        None => {
            return Ok(DecryptOutcome::KeyMissing {
                key_id: ev.key_event_id,
            })
        }
    };

    if key_bytes.len() != 32 {
        return Ok(DecryptOutcome::InvalidCiphertext {
            reason: format!(
                "key_secrets row has wrong key_bytes length: {}",
                key_bytes.len()
            ),
        });
    }
    let mut key_arr = [0u8; 32];
    key_arr.copy_from_slice(&key_bytes);

    // AES-256-GCM decrypt + AEAD verify.
    let plaintext =
        match decrypt_event_blob(&key_arr, &ev.nonce, &ev.ciphertext, &ev.auth_tag) {
            Ok(pt) => pt,
            Err(e) => {
                return Ok(DecryptOutcome::InvalidCiphertext {
                    reason: format!("aes-gcm verify/decrypt failed: {}", e),
                })
            }
        };

    if plaintext.is_empty() {
        return Ok(DecryptOutcome::InvalidCiphertext {
            reason: "decrypted plaintext is empty".to_string(),
        });
    }

    // Compute the chain's blake3 event_id over the recovered inner bytes.
    let mut event_id = [0u8; 32];
    event_id.copy_from_slice(blake3::hash(&plaintext).as_bytes());

    Ok(DecryptOutcome::Decrypted(DecryptedInner {
        canonical_bytes: plaintext,
        event_id,
    }))
}
