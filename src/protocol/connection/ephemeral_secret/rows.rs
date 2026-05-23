//! Durable rows for local connection ephemeral secrets.
//!
//! Rows are keyed by the secret fact id. The value stores the owner endpoint,
//! public key, private key, and creation time so response construction can load
//! the local handshake material without re-decoding fact bytes.
//!
//! These rows contain private material and are meaningful only inside the local
//! store. Change this file for row key/value compatibility; projector admission
//! and context offers belong in `project.rs`.

use crate::core::crypto::{
    X25519PrivateKey, X25519PublicKey, X25519_PRIVATE_KEY_BYTES, X25519_PUBLIC_KEY_BYTES,
};
use crate::core::facts::FactId;
use crate::core::store::{TableName, TableRow};
use crate::core::wire;

use super::fact::{ConnectionEphemeralSecretFact, EndpointId};

pub const CONNECTION_EPHEMERAL_SECRET_ROWS: TableName =
    TableName::new("connection_ephemeral_secret_rows");

pub const ROW_VALUE_BYTES: usize = 32 + X25519_PRIVATE_KEY_BYTES + X25519_PUBLIC_KEY_BYTES + 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectionEphemeralSecretRow {
    pub secret_id: FactId,
    pub owner_endpoint: EndpointId,
    pub ephemeral_private_key: X25519PrivateKey,
    pub ephemeral_public_key: X25519PublicKey,
    pub created_at_ms: u64,
}

pub fn connection_ephemeral_secret_key(secret_id: &FactId) -> Vec<u8> {
    secret_id.to_vec()
}

pub fn connection_ephemeral_secret_row(
    secret_id: FactId,
    fact: &ConnectionEphemeralSecretFact,
) -> Result<TableRow, String> {
    let mut value = vec![0; ROW_VALUE_BYTES];
    value[0..32].copy_from_slice(&fact.owner_endpoint);
    value[32..32 + X25519_PRIVATE_KEY_BYTES].copy_from_slice(&fact.ephemeral_private_key);
    let mut cursor = 32 + X25519_PRIVATE_KEY_BYTES;
    value[cursor..cursor + X25519_PUBLIC_KEY_BYTES].copy_from_slice(&fact.ephemeral_public_key);
    cursor += X25519_PUBLIC_KEY_BYTES;
    wire::put_u64be(fact.created_at_ms, &mut value[cursor..cursor + 8])
        .map_err(|err| format!("{err:?}"))?;
    Ok(TableRow {
        table: CONNECTION_EPHEMERAL_SECRET_ROWS,
        key: connection_ephemeral_secret_key(&secret_id),
        value,
    })
}

pub fn decode_connection_ephemeral_secret_row(
    key: &[u8],
    value: &[u8],
) -> Result<ConnectionEphemeralSecretRow, String> {
    if key.len() != 32 {
        return Err("connection ephemeral secret row key must be the secret fact id".to_string());
    }
    if value.len() != ROW_VALUE_BYTES {
        return Err("connection ephemeral secret row value is malformed".to_string());
    }
    let mut secret_id = [0; 32];
    secret_id.copy_from_slice(key);
    let mut owner_endpoint = [0; 32];
    owner_endpoint.copy_from_slice(&value[0..32]);
    let mut ephemeral_private_key = [0; X25519_PRIVATE_KEY_BYTES];
    ephemeral_private_key.copy_from_slice(&value[32..32 + X25519_PRIVATE_KEY_BYTES]);
    let mut cursor = 32 + X25519_PRIVATE_KEY_BYTES;
    let mut ephemeral_public_key = [0; X25519_PUBLIC_KEY_BYTES];
    ephemeral_public_key.copy_from_slice(&value[cursor..cursor + X25519_PUBLIC_KEY_BYTES]);
    cursor += X25519_PUBLIC_KEY_BYTES;
    let created_at_ms =
        wire::take_u64be(&value[cursor..cursor + 8]).map_err(|err| format!("{err:?}"))?;
    Ok(ConnectionEphemeralSecretRow {
        secret_id,
        owner_endpoint,
        ephemeral_private_key,
        ephemeral_public_key,
        created_at_ms,
    })
}
