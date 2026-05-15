//! Projection row layout for shared endpoint identity state.
//!
//! Rows are keyed by `workspace_id || endpoint_shared_id`. The endpoint shared
//! id is the fact id of the projected endpoint-shared fact.

use crate::core::crypto::Ed25519PublicKey;
use crate::core::store::{TableName, TableRow};

use super::fact::{
    EndpointId, EndpointRole, EndpointSharedFact, EndpointSharedId, UserAuthorityId, WorkspaceId,
};
use super::layout;

pub const ENDPOINT_SHARED_ROWS: TableName = TableName::new("identity_endpoint_shared_rows");

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointSharedRow {
    pub workspace_id: WorkspaceId,
    pub endpoint_shared_id: EndpointSharedId,
    pub created_at_ms: u64,
    pub endpoint_id: EndpointId,
    pub signing_public_key: Ed25519PublicKey,
    pub endpoint_role: EndpointRole,
    pub user_authority_event_id: UserAuthorityId,
    pub device_name: String,
}

pub fn endpoint_shared_key(
    workspace_id: &WorkspaceId,
    endpoint_shared_id: &EndpointSharedId,
) -> Vec<u8> {
    let mut key = Vec::with_capacity(64);
    key.extend_from_slice(workspace_id);
    key.extend_from_slice(endpoint_shared_id);
    key
}

pub fn endpoint_shared_row(
    endpoint_shared_id: EndpointSharedId,
    fact: &EndpointSharedFact,
) -> Result<TableRow, String> {
    Ok(TableRow {
        table: ENDPOINT_SHARED_ROWS,
        key: endpoint_shared_key(&fact.workspace_id, &endpoint_shared_id),
        value: layout::encode_row_value(fact)?,
    })
}

pub fn decode_endpoint_shared_row(key: &[u8], value: &[u8]) -> Result<EndpointSharedRow, String> {
    if key.len() != 64 {
        return Err("endpoint shared row key must be workspace_id || endpoint_shared_id".to_string());
    }
    let mut workspace_id = [0; 32];
    let mut endpoint_shared_id = [0; 32];
    workspace_id.copy_from_slice(&key[..32]);
    endpoint_shared_id.copy_from_slice(&key[32..]);
    let decoded = layout::decode_row_value(value)?;
    Ok(EndpointSharedRow {
        workspace_id,
        endpoint_shared_id,
        created_at_ms: decoded.created_at_ms,
        endpoint_id: decoded.endpoint_id,
        signing_public_key: decoded.signing_public_key,
        endpoint_role: decoded.endpoint_role,
        user_authority_event_id: decoded.user_authority_event_id,
        device_name: decoded.device_name,
    })
}
