//! `connection.wrap_bootstrap` / `connection.wrap` / `connection.unwrap`.
//!
//! Plain functions, not an event type — see `plan.md` lines 121-133. The
//! encrypted bytes are opaque transit form: no event id, no deps, no labels.
//!
//! ### Wire envelope
//!
//! Bootstrap frame:
//! ```text
//! [u8 mode = 0x01]
//! [u8; 32] sender_endpoint_pubkey
//! [u8 addr_len][addr_bytes]   // utf-8 "ip:port", empty addr_len=0 ok
//! [u8; 12] aes-gcm nonce
//! [u32 BE] ciphertext_len
//! [bytes]  ciphertext (aes-256-gcm of inner_payload)
//! ```
//!
//! Connection-secret frame:
//! ```text
//! [u8 mode = 0x02]
//! [u8; 32] connection_secret_id
//! [u8; 12] aes-gcm nonce
//! [u32 BE] ciphertext_len
//! [bytes]  ciphertext (aes-256-gcm, padded to size bucket)
//! ```
//!
//! Inner payload (under both modes):
//! ```text
//! [u32 BE] num_events
//! repeat:
//!   [u8; 32] workspace_id
//!   [u32 BE] event_len
//!   [bytes]  canonical event bytes
//! ```
//!
//! ### Bootstrap key agreement
//!
//! Bootstrap frames perform real X25519 ECDH between the sender's static
//! ed25519 identity and the recipient's static ed25519 identity. We
//! convert the ed25519 keys to their Montgomery (X25519) form via the
//! standard birational map (`to_scalar` for the private, `to_montgomery`
//! for the public). The shared secret point feeds a blake3-keyed KDF
//! that emits a separate `outbound_key` and `inbound_key`. Role labels
//! ("outbound" vs "inbound") are derived from the sorted endpoint ids
//! so each side's outbound equals the other side's inbound.
//!
//! ### Workspace check
//!
//! `wrap` looks up `shared_workspaces(connection_id)` and `assert!`s every
//! inner event's `workspace_id` is in the set. This is an internal
//! correctness invariant — violation panics. `unwrap` does the symmetric
//! check on the receive side, but instead of panicking it *drops* the
//! offending events and returns them as `dropped_events` for diagnostics.

use std::collections::BTreeSet;

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::RngCore;
use rusqlite::{params, Connection as SqlConnection};

use crate::runtime::control_loop::work_item::{ConnectionId, EndpointId, WorkspaceId};
use crate::runtime::transport_v2::OutboundFrame;

const MODE_BOOTSTRAP: u8 = 0x01;
const MODE_CONNECTION_SECRET: u8 = 0x02;

/// HKDF/blake3 info strings. Both sides feed the SAME shared point into
/// blake3 with these labels; the role assignment is determined by sorted
/// endpoint ids (see `bootstrap_keys_for_pair`), so the "outbound" key on
/// one side equals the "inbound" key on the other.
const KDF_INFO_OUTBOUND: &[u8] = b"poc9-bootstrap-outbound-v1";
const KDF_INFO_INBOUND: &[u8] = b"poc9-bootstrap-inbound-v1";

/// One inner event as carried inside a wrapped frame.
///
/// We don't take a hard dependency on `event_modules::ParsedEvent` here to
/// keep the connection module's surface small. Callers pass canonical bytes
/// + the workspace id they were minted for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InnerCanonicalEvent {
    pub workspace_id: WorkspaceId,
    pub bytes: Vec<u8>,
}

#[derive(Debug)]
pub enum WrapError {
    NoOutboundSecret,
    Crypto(String),
    Db(rusqlite::Error),
    /// Recipient endpoint_id couldn't be parsed as a valid Ed25519
    /// public key (X25519 ECDH requires this).
    InvalidRecipientPubkey,
    /// At least one inner event has no `workspace_id` accessible. Should not
    /// happen for real `ParsedEvent`s — they all carry a workspace_id — but
    /// keeping a typed error path so callers don't silently drop.
    MissingWorkspaceId,
}

impl std::fmt::Display for WrapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WrapError::NoOutboundSecret => write!(f, "no outbound secret for connection"),
            WrapError::Crypto(s) => write!(f, "crypto: {}", s),
            WrapError::Db(e) => write!(f, "db: {}", e),
            WrapError::InvalidRecipientPubkey => {
                write!(f, "recipient endpoint_id is not a valid ed25519 pubkey")
            }
            WrapError::MissingWorkspaceId => write!(f, "inner event missing workspace_id"),
        }
    }
}

impl std::error::Error for WrapError {}

impl From<rusqlite::Error> for WrapError {
    fn from(e: rusqlite::Error) -> Self {
        WrapError::Db(e)
    }
}

#[derive(Debug)]
pub enum UnwrapError {
    Truncated,
    UnknownMode(u8),
    NoMatchingSecret,
    Crypto(String),
    Db(rusqlite::Error),
    MalformedInner(&'static str),
    /// Sender pubkey embedded in a bootstrap frame did not parse as a
    /// valid Ed25519 verifying key — required for ECDH on the recipient
    /// side.
    InvalidSenderPubkey,
}

impl std::fmt::Display for UnwrapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UnwrapError::Truncated => write!(f, "frame truncated"),
            UnwrapError::UnknownMode(m) => write!(f, "unknown wrap mode {:#x}", m),
            UnwrapError::NoMatchingSecret => write!(f, "no matching connection secret"),
            UnwrapError::Crypto(s) => write!(f, "crypto: {}", s),
            UnwrapError::Db(e) => write!(f, "db: {}", e),
            UnwrapError::MalformedInner(s) => write!(f, "malformed inner payload: {}", s),
            UnwrapError::InvalidSenderPubkey => {
                write!(f, "bootstrap sender pubkey is not a valid ed25519 pubkey")
            }
        }
    }
}

impl std::error::Error for UnwrapError {}

impl From<rusqlite::Error> for UnwrapError {
    fn from(e: rusqlite::Error) -> Self {
        UnwrapError::Db(e)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnwrapKind {
    Bootstrap,
    ConnectionSecret,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnwrapResult {
    pub kind: UnwrapKind,
    pub connection_id: Option<ConnectionId>,
    pub inner_events: Vec<InnerCanonicalEvent>,
    /// Inner events whose `workspace_id` was not in
    /// `shared_workspaces(connection_id)`. For `ConnectionSecret` frames
    /// these get dropped instead of forwarded; for `Bootstrap` frames this
    /// is always empty.
    pub dropped_events: Vec<InnerCanonicalEvent>,
    /// For `Bootstrap` frames, the sender's endpoint pubkey (which is also
    /// their `endpoint_id`). `None` for connection-secret frames — those
    /// recover the connection but not the specific sender on their own.
    pub sender_endpoint_id: Option<EndpointId>,
    /// For `Bootstrap` frames, the in-the-clear utf-8 listen address the
    /// sender embedded so the responder can dial back. Empty (or the
    /// `Some("")` for older callers) means "no addr supplied".
    pub sender_listen_addr: Option<String>,
}

/// Bootstrap wrap: encrypts to the remote endpoint's Ed25519 pubkey via
/// real X25519 ECDH. Both sides derive the SAME inbound/outbound key
/// pair from the sorted endpoint ids; the sender encrypts under its
/// outbound key and the recipient decrypts under its inbound key (which
/// is bit-equal to the sender's outbound key).
///
/// Layout:
/// ```text
/// [u8 mode = 0x01]
/// [u8;32 sender_endpoint_pubkey]
/// [u8 addr_len][addr_bytes]   // utf-8 "ip:port", empty addr_len=0 ok
/// [u8;12 aes-gcm nonce]
/// [u32 BE ciphertext_len]
/// [ciphertext]
/// ```
pub fn wrap_bootstrap(
    local_signing_key: &SigningKey,
    remote_endpoint_id: EndpointId,
    inner_events: &[InnerCanonicalEvent],
) -> Result<OutboundFrame, WrapError> {
    wrap_bootstrap_with_addr(local_signing_key, remote_endpoint_id, "", inner_events)
}

/// Like [`wrap_bootstrap`] but the responder learns `sender_addr` (a
/// utf-8 "ip:port" string) so it can register the sender's address in
/// its `endpoint_addresses` table without needing the value to flow
/// through a separate channel. Pass an empty `&str` for backward
/// compatibility (unwrap will skip the address-recording step).
pub fn wrap_bootstrap_with_addr(
    local_signing_key: &SigningKey,
    remote_endpoint_id: EndpointId,
    sender_addr: &str,
    inner_events: &[InnerCanonicalEvent],
) -> Result<OutboundFrame, WrapError> {
    let sender_endpoint_id: EndpointId = local_signing_key.verifying_key().to_bytes();
    let (outbound_key, _inbound_key) =
        bootstrap_keys_for_pair(local_signing_key, &remote_endpoint_id)?;
    let plaintext = encode_inner_payload(inner_events);
    let (nonce, ciphertext) = aes_gcm_encrypt(&outbound_key, &plaintext)?;

    let addr_bytes = sender_addr.as_bytes();
    if addr_bytes.len() > 255 {
        return Err(WrapError::Crypto(format!(
            "sender_addr too long: {} bytes",
            addr_bytes.len()
        )));
    }
    let mut out =
        Vec::with_capacity(1 + 32 + 1 + addr_bytes.len() + 12 + 4 + ciphertext.len());
    out.push(MODE_BOOTSTRAP);
    out.extend_from_slice(&sender_endpoint_id);
    out.push(addr_bytes.len() as u8);
    out.extend_from_slice(addr_bytes);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&(ciphertext.len() as u32).to_be_bytes());
    out.extend_from_slice(&ciphertext);
    Ok(OutboundFrame::from_bytes(out))
}

/// Connection-secret wrap. Looks up the outbound secret for `connection_id`,
/// asserts every inner event's `workspace_id ∈ shared_workspaces`, pads to a
/// size bucket, and encrypts under the secret with AES-256-GCM.
///
/// Per plan.md the workspace check is an `assert!()` because violation is a
/// programmer-bug invariant breach, not a runtime error.
pub fn wrap(
    connection_id: ConnectionId,
    inner_events: &[InnerCanonicalEvent],
    db: &SqlConnection,
) -> Result<OutboundFrame, WrapError> {
    let now_ms = now_ms();
    let secret = super::secrets::lookup_outbound(db, &connection_id, now_ms)?
        .ok_or(WrapError::NoOutboundSecret)?;
    let shared = shared_workspaces(db, &connection_id)?;

    for ev in inner_events {
        assert!(
            shared.contains(&ev.workspace_id),
            "connection.wrap: inner event workspace_id {:?} not in shared_workspaces of connection {:?} — caller violated invariant",
            ev.workspace_id,
            connection_id
        );
    }

    let plaintext = encode_inner_payload(inner_events);
    let padded = pad_to_bucket(&plaintext);
    let (nonce, ciphertext) = aes_gcm_encrypt(&secret.key, &padded)?;

    let mut out = Vec::with_capacity(1 + 32 + 12 + 4 + ciphertext.len());
    out.push(MODE_CONNECTION_SECRET);
    out.extend_from_slice(&secret.connection_secret_id);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&(ciphertext.len() as u32).to_be_bytes());
    out.extend_from_slice(&ciphertext);
    Ok(OutboundFrame::from_bytes(out))
}

/// Unwrap an inbound frame. Recovers either a bootstrap-mode envelope
/// (sender's endpoint pubkey is in the clear; the AES key is derived
/// from real X25519 ECDH between the sender's static pubkey and the
/// local signing key) or a connection-secret envelope (look up by
/// secret id, recover `connection_id`, drop events outside
/// `shared_workspaces(connection_id)`).
pub fn unwrap(
    bytes: &[u8],
    local_signing_key: &SigningKey,
    db: &SqlConnection,
) -> Result<UnwrapResult, UnwrapError> {
    if bytes.is_empty() {
        return Err(UnwrapError::Truncated);
    }
    let mode = bytes[0];
    match mode {
        MODE_BOOTSTRAP => unwrap_bootstrap(bytes, local_signing_key),
        MODE_CONNECTION_SECRET => unwrap_connection_secret(bytes, db),
        other => Err(UnwrapError::UnknownMode(other)),
    }
}

fn unwrap_bootstrap(
    bytes: &[u8],
    local_signing_key: &SigningKey,
) -> Result<UnwrapResult, UnwrapError> {
    // [u8 mode][u8;32 sender_pub][u8 addr_len][addr_bytes][u8;12 nonce]
    // [u32 len][ciphertext]
    if bytes.len() < 1 + 32 + 1 + 12 + 4 {
        return Err(UnwrapError::Truncated);
    }
    let mut pos = 1;
    let mut sender = [0u8; 32];
    sender.copy_from_slice(&bytes[pos..pos + 32]);
    pos += 32;
    let addr_len = bytes[pos] as usize;
    pos += 1;
    if bytes.len() < pos + addr_len {
        return Err(UnwrapError::Truncated);
    }
    let addr_str = if addr_len == 0 {
        String::new()
    } else {
        match std::str::from_utf8(&bytes[pos..pos + addr_len]) {
            Ok(s) => s.to_string(),
            Err(_) => return Err(UnwrapError::MalformedInner("sender_addr utf8")),
        }
    };
    pos += addr_len;
    if bytes.len() < pos + 12 + 4 {
        return Err(UnwrapError::Truncated);
    }
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&bytes[pos..pos + 12]);
    pos += 12;
    let len = u32::from_be_bytes(bytes[pos..pos + 4].try_into().unwrap()) as usize;
    pos += 4;
    if bytes.len() < pos + len {
        return Err(UnwrapError::Truncated);
    }
    let ciphertext = &bytes[pos..pos + len];

    // Real ECDH: derive the same outbound/inbound key pair the sender
    // used. We DECRYPT under our INBOUND key, which equals the sender's
    // OUTBOUND key (role labels come from sorted endpoint ids).
    let (_outbound_key, inbound_key) = bootstrap_keys_for_pair(local_signing_key, &sender)
        .map_err(|e| match e {
            WrapError::InvalidRecipientPubkey => UnwrapError::InvalidSenderPubkey,
            other => UnwrapError::Crypto(other.to_string()),
        })?;

    let plaintext = aes_gcm_decrypt(&inbound_key, &nonce, ciphertext)
        .map_err(|e| UnwrapError::Crypto(e))?;
    let inner = decode_inner_payload(&plaintext)?;

    Ok(UnwrapResult {
        kind: UnwrapKind::Bootstrap,
        connection_id: None,
        inner_events: inner,
        dropped_events: Vec::new(),
        sender_endpoint_id: Some(sender),
        sender_listen_addr: if addr_str.is_empty() {
            None
        } else {
            Some(addr_str)
        },
    })
}

fn unwrap_connection_secret(
    bytes: &[u8],
    db: &SqlConnection,
) -> Result<UnwrapResult, UnwrapError> {
    // [u8 mode][u8;32 secret_id][u8;12 nonce][u32 len][ciphertext]
    if bytes.len() < 1 + 32 + 12 + 4 {
        return Err(UnwrapError::Truncated);
    }
    let mut pos = 1;
    let mut secret_id = [0u8; 32];
    secret_id.copy_from_slice(&bytes[pos..pos + 32]);
    pos += 32;
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&bytes[pos..pos + 12]);
    pos += 12;
    let len = u32::from_be_bytes(bytes[pos..pos + 4].try_into().unwrap()) as usize;
    pos += 4;
    if bytes.len() < pos + len {
        return Err(UnwrapError::Truncated);
    }
    let ciphertext = &bytes[pos..pos + len];

    let now = now_ms();
    let secret = super::secrets::lookup_inbound(db, &secret_id, now)?
        .ok_or(UnwrapError::NoMatchingSecret)?;
    let plaintext = aes_gcm_decrypt(&secret.key, &nonce, ciphertext)
        .map_err(|e| UnwrapError::Crypto(e))?;
    let plaintext = strip_padding(&plaintext);
    let inner = decode_inner_payload(plaintext)?;

    let shared = shared_workspaces(db, &secret.connection_id).map_err(UnwrapError::Db)?;
    let mut kept = Vec::with_capacity(inner.len());
    let mut dropped = Vec::new();
    for ev in inner {
        if shared.contains(&ev.workspace_id) {
            kept.push(ev);
        } else {
            dropped.push(ev);
        }
    }

    Ok(UnwrapResult {
        kind: UnwrapKind::ConnectionSecret,
        connection_id: Some(secret.connection_id),
        inner_events: kept,
        dropped_events: dropped,
        sender_endpoint_id: None,
        sender_listen_addr: None,
    })
}

// ---------------------------------------------------------------------------
// ECDH key agreement
// ---------------------------------------------------------------------------

/// Real X25519 ECDH between the local ed25519 signing key and the
/// remote ed25519 verifying key (passed as raw `EndpointId` bytes).
///
/// Returns `(outbound_key, inbound_key)` from the local side's
/// perspective. The role assignment is derived from the sorted endpoint
/// ids: the lower id is "role A" and the higher is "role B". Each role
/// gets its own KDF info string, so:
///
/// - On the role-A side, `outbound = KDF(shared, A_INFO)` and
///   `inbound = KDF(shared, B_INFO)`.
/// - On the role-B side, the assignment flips, so its `outbound =
///   KDF(shared, B_INFO)` matches role-A's `inbound`.
///
/// Result: side A's outbound bit-equals side B's inbound, and vice
/// versa — the standard property of an ECDH-derived bidirectional
/// channel.
pub(crate) fn bootstrap_keys_for_pair(
    local_signing_key: &SigningKey,
    remote_endpoint_id: &EndpointId,
) -> Result<([u8; 32], [u8; 32]), WrapError> {
    let local_id: EndpointId = local_signing_key.verifying_key().to_bytes();
    let remote_vk =
        VerifyingKey::from_bytes(remote_endpoint_id).map_err(|_| WrapError::InvalidRecipientPubkey)?;

    // X25519 ECDH: `local_scalar * remote_montgomery_point`. Both sides
    // produce the same shared point because of the symmetry of DH.
    let local_scalar = local_signing_key.to_scalar();
    let remote_point = remote_vk.to_montgomery();
    let shared_point = &remote_point * &local_scalar;
    let shared_secret = shared_point.as_bytes();

    // Role labels from sorted endpoint ids. We hash the FULL pair (both
    // endpoint ids in canonical order) into the KDF context so a key
    // collision across different connections is impossible.
    let (low, high) = if local_id <= *remote_endpoint_id {
        (&local_id, remote_endpoint_id)
    } else {
        (remote_endpoint_id, &local_id)
    };
    let local_is_low = local_id <= *remote_endpoint_id;

    // Each side derives BOTH keys with the same labels; "outbound"
    // means "the key I encrypt with", and which info string is which
    // depends on whether we're the low or high endpoint.
    let key_a = kdf(shared_secret, KDF_INFO_OUTBOUND, low, high);
    let key_b = kdf(shared_secret, KDF_INFO_INBOUND, low, high);

    if local_is_low {
        // The "low" side encrypts under the "outbound-v1" key; its
        // peer (the high side) encrypts under "inbound-v1".
        Ok((key_a, key_b))
    } else {
        // The "high" side mirrors: its outbound is the "inbound-v1"
        // key (which is the low side's inbound key), and its inbound
        // is the "outbound-v1" key (the low side's outbound).
        Ok((key_b, key_a))
    }
}

/// Blake3-keyed KDF. We don't pull in the `hkdf` crate — blake3's keyed
/// hash gives us a 32-byte uniformly-random output with full domain
/// separation by `info`.
fn kdf(shared_secret: &[u8; 32], info: &[u8], low: &[u8; 32], high: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new_keyed(shared_secret);
    h.update(info);
    h.update(low);
    h.update(high);
    let mut out = [0u8; 32];
    out.copy_from_slice(h.finalize().as_bytes());
    out
}

/// Public helper: derive the deterministic per-connection
/// `connection_secret_id` (32 bytes) for a given endpoint pair, given
/// the sorted endpoint ids and a salt (typically the canonical
/// `connection_id`). Used by `post_apply.rs` to keep the
/// outbound/inbound secret-id math symmetric on both sides.
pub(crate) fn connection_secret_id(
    shared_secret: &[u8; 32],
    low: &[u8; 32],
    high: &[u8; 32],
    salt: &[u8; 32],
) -> [u8; 32] {
    let mut h = blake3::Hasher::new_keyed(shared_secret);
    h.update(b"poc9-connection-secret-id-v1");
    h.update(low);
    h.update(high);
    h.update(salt);
    let mut out = [0u8; 32];
    out.copy_from_slice(h.finalize().as_bytes());
    out
}

/// Public helper: derive the per-connection AEAD key for the durable
/// `connection_secrets` rows. Used by `post_apply.rs`. We feed the
/// `connection_id` as a salt so two separate Connection events between
/// the same endpoint pair produce distinct keys.
pub(crate) fn connection_secret_key(
    shared_secret: &[u8; 32],
    low: &[u8; 32],
    high: &[u8; 32],
    salt: &[u8; 32],
) -> [u8; 32] {
    let mut h = blake3::Hasher::new_keyed(shared_secret);
    h.update(b"poc9-connection-secret-key-v1");
    h.update(low);
    h.update(high);
    h.update(salt);
    let mut out = [0u8; 32];
    out.copy_from_slice(h.finalize().as_bytes());
    out
}

/// Compute the raw X25519 shared secret between the local signing key
/// and a remote endpoint id. Exposed within the crate so `post_apply.rs`
/// can run the SAME ECDH against the canonical Connection event's
/// endpoints + the local signing key, without re-implementing the
/// scalar arithmetic.
pub(crate) fn ecdh_shared_secret(
    local_signing_key: &SigningKey,
    remote_endpoint_id: &EndpointId,
) -> Result<[u8; 32], WrapError> {
    let remote_vk =
        VerifyingKey::from_bytes(remote_endpoint_id).map_err(|_| WrapError::InvalidRecipientPubkey)?;
    let local_scalar = local_signing_key.to_scalar();
    let remote_point = remote_vk.to_montgomery();
    let shared_point = &remote_point * &local_scalar;
    Ok(*shared_point.as_bytes())
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

fn aes_gcm_encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<([u8; 12], Vec<u8>), WrapError> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| WrapError::Crypto(format!("aes-gcm key init: {}", e)))?;
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| WrapError::Crypto(format!("aes-gcm encrypt: {}", e)))?;
    Ok((nonce_bytes, ciphertext))
}

fn aes_gcm_decrypt(
    key: &[u8; 32],
    nonce_bytes: &[u8; 12],
    ciphertext: &[u8],
) -> Result<Vec<u8>, String> {
    let cipher =
        Aes256Gcm::new_from_slice(key).map_err(|e| format!("aes-gcm key init: {}", e))?;
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| format!("aes-gcm decrypt: {}", e))
}

const PAD_BUCKETS: &[usize] = &[256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536];

fn pad_to_bucket(data: &[u8]) -> Vec<u8> {
    // Reserve 4 bytes for an inner-length prefix so we can strip padding
    // deterministically: [u32 BE inner_len][inner_bytes][zero pad].
    let inner_len = data.len();
    let needed = 4 + inner_len;
    let bucket = PAD_BUCKETS
        .iter()
        .copied()
        .find(|&b| b >= needed)
        .unwrap_or(needed);
    let mut out = vec![0u8; bucket];
    out[..4].copy_from_slice(&(inner_len as u32).to_be_bytes());
    out[4..4 + inner_len].copy_from_slice(data);
    out
}

fn strip_padding(padded: &[u8]) -> &[u8] {
    if padded.len() < 4 {
        return padded;
    }
    let inner_len = u32::from_be_bytes(padded[..4].try_into().unwrap()) as usize;
    if 4 + inner_len > padded.len() {
        // Malformed; let the inner decoder fail gracefully.
        return &padded[4..];
    }
    &padded[4..4 + inner_len]
}

fn encode_inner_payload(events: &[InnerCanonicalEvent]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(events.len() as u32).to_be_bytes());
    for ev in events {
        out.extend_from_slice(&ev.workspace_id);
        out.extend_from_slice(&(ev.bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(&ev.bytes);
    }
    out
}

fn decode_inner_payload(bytes: &[u8]) -> Result<Vec<InnerCanonicalEvent>, UnwrapError> {
    if bytes.len() < 4 {
        return Err(UnwrapError::MalformedInner("missing num_events"));
    }
    let mut pos = 0;
    let n = u32::from_be_bytes(bytes[pos..pos + 4].try_into().unwrap()) as usize;
    pos += 4;
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        if bytes.len() < pos + 32 + 4 {
            return Err(UnwrapError::MalformedInner("event header truncated"));
        }
        let mut workspace_id = [0u8; 32];
        workspace_id.copy_from_slice(&bytes[pos..pos + 32]);
        pos += 32;
        let len = u32::from_be_bytes(bytes[pos..pos + 4].try_into().unwrap()) as usize;
        pos += 4;
        if bytes.len() < pos + len {
            return Err(UnwrapError::MalformedInner("event bytes truncated"));
        }
        let ev_bytes = bytes[pos..pos + len].to_vec();
        pos += len;
        out.push(InnerCanonicalEvent {
            workspace_id,
            bytes: ev_bytes,
        });
    }
    Ok(out)
}

/// Read `shared_workspaces(connection_id)` from projected state.
///
/// TODO(plan.md): wire to the actual `connection` projector's state table
/// once `projector.rs` is implemented. Phase 1 reads from a placeholder
/// table `connection_shared_workspaces (connection_id BLOB, workspace_id
/// BLOB)`. The projector will populate this from the canonical Connection
/// event's `shared_workspaces` field.
fn shared_workspaces(
    db: &SqlConnection,
    connection_id: &ConnectionId,
) -> rusqlite::Result<BTreeSet<WorkspaceId>> {
    // Make sure the table exists. Projector will end up using IF NOT EXISTS
    // too, so this is a no-op once that lands.
    db.execute_batch(
        "CREATE TABLE IF NOT EXISTS connection_shared_workspaces (
            connection_id BLOB NOT NULL,
            workspace_id  BLOB NOT NULL,
            PRIMARY KEY (connection_id, workspace_id)
        );",
    )?;

    let mut stmt = db.prepare(
        "SELECT workspace_id FROM connection_shared_workspaces WHERE connection_id = ?1",
    )?;
    let mut rows = stmt.query(params![connection_id.to_vec()])?;
    let mut out = BTreeSet::new();
    while let Some(row) = rows.next()? {
        let blob: Vec<u8> = row.get(0)?;
        if blob.len() == 32 {
            let mut ws = [0u8; 32];
            ws.copy_from_slice(&blob);
            out.insert(ws);
        }
    }
    Ok(out)
}

fn now_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event_modules::connection::secrets::{upsert, SecretDirection, SecretRow};

    fn open() -> SqlConnection {
        let c = SqlConnection::open_in_memory().unwrap();
        super::super::secrets::ensure_schema(&c).unwrap();
        c
    }

    fn add_shared(c: &SqlConnection, conn_id: &ConnectionId, ws: &WorkspaceId) {
        c.execute_batch(
            "CREATE TABLE IF NOT EXISTS connection_shared_workspaces (
                connection_id BLOB NOT NULL,
                workspace_id  BLOB NOT NULL,
                PRIMARY KEY (connection_id, workspace_id)
            );",
        )
        .unwrap();
        c.execute(
            "INSERT OR IGNORE INTO connection_shared_workspaces VALUES (?1, ?2)",
            params![conn_id.to_vec(), ws.to_vec()],
        )
        .unwrap();
    }

    fn sk(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    #[test]
    fn bootstrap_round_trip_with_real_ecdh() {
        let c = open();
        let sender_sk = sk(0x11);
        let recipient_sk = sk(0x22);
        let recipient_eid = recipient_sk.verifying_key().to_bytes();
        let ws: WorkspaceId = [33u8; 32];
        let inner = vec![InnerCanonicalEvent {
            workspace_id: ws,
            bytes: b"hello".to_vec(),
        }];
        let frame = wrap_bootstrap(&sender_sk, recipient_eid, &inner).unwrap();
        let res = unwrap(frame.as_bytes(), &recipient_sk, &c).unwrap();
        assert_eq!(res.kind, UnwrapKind::Bootstrap);
        assert_eq!(
            res.sender_endpoint_id,
            Some(sender_sk.verifying_key().to_bytes())
        );
        assert_eq!(res.inner_events, inner);
    }

    #[test]
    fn bootstrap_keys_are_symmetric_across_sides() {
        // Side A and Side B independently derive (outbound, inbound).
        // A.outbound must equal B.inbound and vice versa — the standard
        // bidirectional ECDH-channel property.
        let a_sk = sk(0xAA);
        let b_sk = sk(0xBB);
        let a_eid = a_sk.verifying_key().to_bytes();
        let b_eid = b_sk.verifying_key().to_bytes();

        let (a_out, a_in) = bootstrap_keys_for_pair(&a_sk, &b_eid).unwrap();
        let (b_out, b_in) = bootstrap_keys_for_pair(&b_sk, &a_eid).unwrap();

        assert_eq!(a_out, b_in, "A.outbound must equal B.inbound");
        assert_eq!(a_in, b_out, "A.inbound must equal B.outbound");
        assert_ne!(a_out, a_in, "A's two keys must differ");
    }

    #[test]
    fn bootstrap_unwrap_rejects_wrong_recipient() {
        let c = open();
        let sender_sk = sk(0x11);
        let recipient_sk = sk(0x22);
        let bystander_sk = sk(0x33);
        let recipient_eid = recipient_sk.verifying_key().to_bytes();
        let inner = vec![InnerCanonicalEvent {
            workspace_id: [33u8; 32],
            bytes: b"hello".to_vec(),
        }];
        let frame = wrap_bootstrap(&sender_sk, recipient_eid, &inner).unwrap();
        // A bystander can't derive the same key — AES-GCM auth fails.
        let res = unwrap(frame.as_bytes(), &bystander_sk, &c);
        assert!(matches!(res, Err(UnwrapError::Crypto(_))));
    }

    #[test]
    fn connection_secret_round_trip_filters_unshared_workspaces() {
        let c = open();
        let conn_id: ConnectionId = [44u8; 32];
        let ws_a: WorkspaceId = [1u8; 32];
        let ws_b: WorkspaceId = [2u8; 32];
        add_shared(&c, &conn_id, &ws_a);

        let key = [9u8; 32];
        let secret_id = [7u8; 32];
        upsert(
            &c,
            &SecretRow {
                connection_secret_id: secret_id,
                key,
                direction: SecretDirection::Outbound,
                connection_id: conn_id,
                ttl_ms: i64::MAX / 2,
                created_at_ms: 0,
            },
        )
        .unwrap();
        upsert(
            &c,
            &SecretRow {
                connection_secret_id: secret_id,
                key,
                direction: SecretDirection::Inbound,
                connection_id: conn_id,
                ttl_ms: i64::MAX / 2,
                created_at_ms: 0,
            },
        )
        .unwrap();

        let inner = vec![
            InnerCanonicalEvent {
                workspace_id: ws_a,
                bytes: b"good".to_vec(),
            },
        ];
        let frame = wrap(conn_id, &inner, &c).unwrap();

        // Now decode and confirm we get the workspace through. Use any
        // dummy signing key — connection-secret unwrap doesn't use it.
        let res = unwrap(frame.as_bytes(), &sk(0x00), &c).unwrap();
        assert_eq!(res.kind, UnwrapKind::ConnectionSecret);
        assert_eq!(res.connection_id, Some(conn_id));
        assert_eq!(res.inner_events, inner);
        assert!(res.dropped_events.is_empty());

        // Manually craft a frame containing an out-of-workspace event, by
        // re-encrypting under the same secret. This simulates a misbehaving
        // sender — `unwrap` must drop the bad event.
        let bad_inner_payload =
            encode_inner_payload(&[InnerCanonicalEvent {
                workspace_id: ws_b,
                bytes: b"bad".to_vec(),
            }]);
        let padded = pad_to_bucket(&bad_inner_payload);
        let (nonce, ct) = aes_gcm_encrypt(&key, &padded).unwrap();
        let mut bad = Vec::new();
        bad.push(MODE_CONNECTION_SECRET);
        bad.extend_from_slice(&secret_id);
        bad.extend_from_slice(&nonce);
        bad.extend_from_slice(&(ct.len() as u32).to_be_bytes());
        bad.extend_from_slice(&ct);

        let res = unwrap(&bad, &sk(0x00), &c).unwrap();
        assert!(res.inner_events.is_empty());
        assert_eq!(res.dropped_events.len(), 1);
    }

    #[test]
    #[should_panic(expected = "not in shared_workspaces")]
    fn wrap_panics_on_unshared_workspace() {
        let c = open();
        let conn_id: ConnectionId = [44u8; 32];
        let ws_a: WorkspaceId = [1u8; 32];
        let ws_b: WorkspaceId = [2u8; 32];
        add_shared(&c, &conn_id, &ws_a);

        upsert(
            &c,
            &SecretRow {
                connection_secret_id: [7u8; 32],
                key: [9u8; 32],
                direction: SecretDirection::Outbound,
                connection_id: conn_id,
                ttl_ms: i64::MAX / 2,
                created_at_ms: 0,
            },
        )
        .unwrap();

        let inner = vec![InnerCanonicalEvent {
            workspace_id: ws_b,
            bytes: b"bad".to_vec(),
        }];
        let _ = wrap(conn_id, &inner, &c);
    }
}
