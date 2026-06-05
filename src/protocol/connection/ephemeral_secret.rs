//! Local connection handshake secret family.
//!
//! An ephemeral secret is private X25519 material created for one handshake
//! leg. It exists as a local fact so request and response projectors can prove
//! that the public key they reference is backed by local private material, while
//! the secret bytes never become shared protocol state.
//!
//! Projection validates the keypair, writes a local row keyed by the secret
//! fact id, and publishes exact local context for the matching request or
//! response. Change this family when handshake secret bytes, row storage, or
//! context offers change; request and connection facts own how the secret
//! is consumed.

pub mod adapt;
pub mod authenticate;
pub mod author;
pub mod decode;
pub mod encode;
pub mod fact;
pub mod project;

use crate::core::crypto::{X25519PrivateKey, X25519PublicKey};
use crate::core::facts::FactId;
use crate::core::row_schema::{RowField, RowTableSchema, RowValue};
use crate::core::store::{TableName, TableRow};

use fact::EndpointId;

pub(crate) use decode::Codec;

/// Durable rows for local connection ephemeral secrets, keyed by the secret
/// fact id. The value stores the owner endpoint, public key, private key, and
/// creation time so response construction can load the local handshake material
/// without re-decoding fact bytes.
pub const CONNECTION_EPHEMERAL_SECRET_ROWS: TableName =
    TableName::new("connection_ephemeral_secret_rows");

const CONNECTION_EPHEMERAL_SECRET_ROW_KEY_FIELDS: &[RowField] = &[RowField::bytes32("secret_id")];
const CONNECTION_EPHEMERAL_SECRET_ROW_VALUE_FIELDS: &[RowField] = &[
    RowField::bytes32("owner_endpoint"),
    RowField::bytes32("ephemeral_private_key"),
    RowField::bytes32("ephemeral_public_key"),
    RowField::u64be("created_at_ms"),
];

pub const CONNECTION_EPHEMERAL_SECRET_ROW_SCHEMA: RowTableSchema = RowTableSchema::new(
    CONNECTION_EPHEMERAL_SECRET_ROWS,
    CONNECTION_EPHEMERAL_SECRET_ROW_KEY_FIELDS,
    CONNECTION_EPHEMERAL_SECRET_ROW_VALUE_FIELDS,
);

pub fn connection_ephemeral_secret_key(secret_id: &FactId) -> Vec<u8> {
    secret_id.to_vec()
}

pub fn connection_ephemeral_secret_row(
    secret_id: FactId,
    fact: &fact::ConnectionEphemeralSecretFact,
) -> Result<TableRow, String> {
    CONNECTION_EPHEMERAL_SECRET_ROW_SCHEMA.row(
        &[RowValue::Bytes(secret_id.to_vec())],
        &[
            RowValue::Bytes(fact.owner_endpoint.to_vec()),
            RowValue::Bytes(fact.ephemeral_private_key.to_vec()),
            RowValue::Bytes(fact.ephemeral_public_key.to_vec()),
            RowValue::U64(fact.created_at_ms),
        ],
    )
}

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::ConnectionEphemeralSecretFact, String> {
    decode::decode_fact(bytes)
}

/// Decoded local ephemeral-secret row.
///
/// Rows contain private material and are meaningful only inside the local store,
/// so this read stays in the family module (capability-bearing), not in the
/// public `queries.rs` read-model surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectionEphemeralSecretRow {
    pub secret_id: FactId,
    pub owner_endpoint: EndpointId,
    pub ephemeral_private_key: X25519PrivateKey,
    pub ephemeral_public_key: X25519PublicKey,
    pub created_at_ms: u64,
}

pub fn decode_connection_ephemeral_secret_row(
    key: &[u8],
    value: &[u8],
) -> Result<ConnectionEphemeralSecretRow, String> {
    let key_fields = CONNECTION_EPHEMERAL_SECRET_ROW_SCHEMA.decode_key(key)?;
    let value_fields = CONNECTION_EPHEMERAL_SECRET_ROW_SCHEMA.decode_value(value)?;
    Ok(ConnectionEphemeralSecretRow {
        secret_id: key_fields[0].as_bytes32("secret_id")?,
        owner_endpoint: value_fields[0].as_bytes32("owner_endpoint")?,
        ephemeral_private_key: value_fields[1].as_bytes32("ephemeral_private_key")?,
        ephemeral_public_key: value_fields[2].as_bytes32("ephemeral_public_key")?,
        created_at_ms: value_fields[3].as_u64("created_at_ms")?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_ephemeral_secret_row_roundtrips_through_schema() {
        let fact = fact::ConnectionEphemeralSecretFact {
            owner_endpoint: [2; 32],
            ephemeral_private_key: [3; 32],
            ephemeral_public_key: [4; 32],
            created_at_ms: 55,
        };
        let row = connection_ephemeral_secret_row([1; 32], &fact).expect("secret row");
        let decoded = decode_connection_ephemeral_secret_row(&row.key, &row.value)
            .expect("decode secret row");
        assert_eq!(decoded.secret_id, [1; 32]);
        assert_eq!(decoded.owner_endpoint, [2; 32]);
        assert_eq!(decoded.ephemeral_private_key, [3; 32]);
        assert_eq!(decoded.ephemeral_public_key, [4; 32]);
        assert_eq!(decoded.created_at_ms, 55);
    }
}
