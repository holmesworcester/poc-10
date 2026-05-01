//! `connection.wrap_bootstrap` / `connection.wrap` / `connection.unwrap`.
//!
//! Plain functions, not an event type — see `plan.md` lines 121-133. The
//! encrypted bytes are opaque transit form: no event id, no deps, no labels.
//!
//! ### Wire envelope (Phase 1)
//!
//! Bootstrap frame:
//! ```text
//! [u8 mode = 0x01]
//! [u8; 32] sender_endpoint_pubkey
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
//!   [u32 BE] event_len
//!   [bytes]  canonical event bytes
//! ```
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
use rand::RngCore;
use rusqlite::{params, Connection as SqlConnection};

use crate::runtime::control_loop::work_item::{ConnectionId, EndpointId, WorkspaceId};
use crate::runtime::transport_v2::OutboundFrame;

const MODE_BOOTSTRAP: u8 = 0x01;
const MODE_CONNECTION_SECRET: u8 = 0x02;

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
}

/// Bootstrap wrap: encrypts to the remote endpoint's Ed25519 pubkey.
///
/// Phase 1: derive a 32-byte AES key by hashing
/// `b"poc9-bootstrap-v1" || sender_pubkey || remote_pubkey`. This is *not*
/// authenticated DH (we don't have a static private/public split for the
/// "sender_pubkey" passed in below — bootstrap is meant to be DH against
/// the remote endpoint's pubkey using *our* signing key).
///
/// TODO(plan.md): switch to ECDH using our SigningKey + remote VerifyingKey,
/// matching the scheme in `shared::crypto::derive_wrap_key`. Phase 1 ships a
/// real AES-GCM round-trip with a deterministic key so unit tests can
/// validate the envelope; the ECDH wiring is an interface-level change
/// later.
pub fn wrap_bootstrap(
    sender_endpoint_id: EndpointId,
    remote_endpoint_id: EndpointId,
    inner_events: &[InnerCanonicalEvent],
) -> Result<OutboundFrame, WrapError> {
    let key = derive_bootstrap_key(&sender_endpoint_id, &remote_endpoint_id);
    let plaintext = encode_inner_payload(inner_events);
    let (nonce, ciphertext) = aes_gcm_encrypt(&key, &plaintext)?;

    let mut out = Vec::with_capacity(1 + 32 + 12 + 4 + ciphertext.len());
    out.push(MODE_BOOTSTRAP);
    out.extend_from_slice(&sender_endpoint_id);
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

/// Unwrap an inbound frame. Recovers either a bootstrap-mode envelope (the
/// sender's endpoint pubkey is in the clear and the AES key is derived
/// from it + our endpoint id) or a connection-secret envelope (look up by
/// secret id, recover `connection_id`, drop events outside
/// `shared_workspaces(connection_id)`).
pub fn unwrap(
    bytes: &[u8],
    local_endpoint_id: EndpointId,
    db: &SqlConnection,
) -> Result<UnwrapResult, UnwrapError> {
    if bytes.is_empty() {
        return Err(UnwrapError::Truncated);
    }
    let mode = bytes[0];
    match mode {
        MODE_BOOTSTRAP => unwrap_bootstrap(bytes, local_endpoint_id),
        MODE_CONNECTION_SECRET => unwrap_connection_secret(bytes, db),
        other => Err(UnwrapError::UnknownMode(other)),
    }
}

fn unwrap_bootstrap(
    bytes: &[u8],
    local_endpoint_id: EndpointId,
) -> Result<UnwrapResult, UnwrapError> {
    // [u8 mode][u8;32 sender_pub][u8;12 nonce][u32 len][ciphertext]
    if bytes.len() < 1 + 32 + 12 + 4 {
        return Err(UnwrapError::Truncated);
    }
    let mut pos = 1;
    let mut sender = [0u8; 32];
    sender.copy_from_slice(&bytes[pos..pos + 32]);
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

    let key = derive_bootstrap_key(&sender, &local_endpoint_id);
    let plaintext =
        aes_gcm_decrypt(&key, &nonce, ciphertext).map_err(|e| UnwrapError::Crypto(e))?;
    let inner = decode_inner_payload(&plaintext)?;

    Ok(UnwrapResult {
        kind: UnwrapKind::Bootstrap,
        connection_id: None,
        inner_events: inner,
        dropped_events: Vec::new(),
        sender_endpoint_id: Some(sender),
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
    })
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

fn derive_bootstrap_key(sender: &EndpointId, recipient: &EndpointId) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"poc9-connection-bootstrap-v1");
    h.update(sender);
    h.update(recipient);
    let out = h.finalize();
    let mut k = [0u8; 32];
    k.copy_from_slice(out.as_bytes());
    k
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

    #[test]
    fn bootstrap_round_trip() {
        let c = open();
        let sender: EndpointId = [11u8; 32];
        let recipient: EndpointId = [22u8; 32];
        let ws: WorkspaceId = [33u8; 32];
        let inner = vec![InnerCanonicalEvent {
            workspace_id: ws,
            bytes: b"hello".to_vec(),
        }];
        let frame = wrap_bootstrap(sender, recipient, &inner).unwrap();
        let res = unwrap(frame.as_bytes(), recipient, &c).unwrap();
        assert_eq!(res.kind, UnwrapKind::Bootstrap);
        assert_eq!(res.sender_endpoint_id, Some(sender));
        assert_eq!(res.inner_events, inner);
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

        // Now decode and confirm we get the workspace through.
        let res = unwrap(frame.as_bytes(), [0u8; 32], &c).unwrap();
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

        let res = unwrap(&bad, [0u8; 32], &c).unwrap();
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
