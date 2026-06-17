//! Read-only queries over shared endpoint membership.
//!
//! `endpoint_shared` rows are the identity facts other protocol families use
//! to decide whether a signer or peer belongs to a workspace. This module
//! exposes the projected peer list in deterministic display order. It should
//! stay side-effect free; endpoint authority is established by projection, not
//! by these lookups.

use crate::core::crypto::Ed25519PublicKey;
use crate::core::facts::FactId;
use crate::core::store::{Store, DEFAULT_QUERY_LIMIT};
use crate::core::wire::FixedText;
use rusqlite::{params, Row};

use super::fact::{
    EndpointId, EndpointRole, EndpointSharedId, UserAuthorityId, WorkspaceId,
    ENDPOINT_DEVICE_NAME_BYTES,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointSharedRow {
    pub workspace_id: WorkspaceId,
    pub endpoint_shared_id: EndpointSharedId,
    pub created_at_ms: u64,
    pub endpoint_id: EndpointId,
    pub signing_public_key: Ed25519PublicKey,
    pub endpoint_role: EndpointRole,
    pub user_authority_fact_id: UserAuthorityId,
    pub device_name: String,
}

pub fn decode_endpoint_shared_row(row: &Row<'_>) -> rusqlite::Result<EndpointSharedRow> {
    let device_name_bytes: Vec<u8> = row.get(7)?;
    let device_name_bytes: [u8; ENDPOINT_DEVICE_NAME_BYTES] =
        device_name_bytes.as_slice().try_into().map_err(|_| {
            rusqlite::Error::InvalidParameterName("device_name slot has wrong length".to_string())
        })?;
    let device_name = FixedText::<ENDPOINT_DEVICE_NAME_BYTES>::from_padded(device_name_bytes)
        .map_err(|err| rusqlite::Error::InvalidParameterName(format!("{err:?}")))?;
    Ok(EndpointSharedRow {
        workspace_id: row.get(0)?,
        endpoint_shared_id: row.get(1)?,
        created_at_ms: row.get::<_, i64>(2)? as u64,
        endpoint_id: row.get(3)?,
        signing_public_key: row.get(4)?,
        endpoint_role: EndpointRole::from_u8(row.get::<_, i64>(5)? as u8)
            .map_err(|err| rusqlite::Error::InvalidParameterName(err))?,
        user_authority_fact_id: row.get(6)?,
        device_name: device_name.to_string(),
    })
}

/// One endpoint's membership binding — the minimal typed interface other scopes
/// need to reason about cross-workspace membership without touching
/// `endpoint_shared` row internals.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct EndpointMembership {
    pub workspace_id: FactId,
    pub endpoint_id: FactId,
    pub endpoint_shared_id: FactId,
}

/// Every projected endpoint membership across all workspaces, in deterministic
/// order. Other scopes use this to decide mutual membership without importing
/// `endpoint_shared` rows.
pub(crate) fn all_memberships(store: &Store) -> Result<Vec<EndpointMembership>, String> {
    let mut stmt = store
        .conn()
        .prepare(
            "SELECT workspace_id,
                    endpoint_shared_id,
                    created_at_ms,
                    endpoint_id,
                    signing_public_key,
                    endpoint_role,
                    user_authority_fact_id,
                    device_name
             FROM auth_endpoint_shared_rows
             ORDER BY workspace_id, endpoint_id
             LIMIT ?1",
        )
        .map_err(|err| format!("load endpoint memberships: {err}"))?;
    let rows = stmt
        .query_map(params![DEFAULT_QUERY_LIMIT as i64], |row| {
            decode_endpoint_shared_row(row).map(|row| EndpointMembership {
                workspace_id: row.workspace_id,
                endpoint_id: row.endpoint_id,
                endpoint_shared_id: row.endpoint_shared_id,
            })
        })
        .map_err(|err| format!("load endpoint memberships: {err}"))?;
    let mut memberships = rows
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|err| format!("decode endpoint memberships: {err}"))?;
    memberships.sort_by(|left, right| {
        left.workspace_id
            .cmp(&right.workspace_id)
            .then_with(|| left.endpoint_id.cmp(&right.endpoint_id))
    });
    Ok(memberships)
}

pub fn peers_in_workspace(
    store: &Store,
    workspace_id: FactId,
) -> Result<Vec<EndpointSharedRow>, String> {
    let mut stmt = store
        .conn()
        .prepare(
            "SELECT workspace_id,
                    endpoint_shared_id,
                    created_at_ms,
                    endpoint_id,
                    signing_public_key,
                    endpoint_role,
                    user_authority_fact_id,
                    device_name
             FROM auth_endpoint_shared_rows
             WHERE workspace_id = ?1
             ORDER BY device_name, endpoint_id
             LIMIT ?2",
        )
        .map_err(|err| format!("load endpoint peers: {err}"))?;
    let rows = stmt
        .query_map(
            params![workspace_id, DEFAULT_QUERY_LIMIT as i64],
            decode_endpoint_shared_row,
        )
        .map_err(|err| format!("load endpoint peers: {err}"))?;
    let mut rows = rows
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|err| format!("decode endpoint peers: {err}"))?;
    rows.sort_by(|left, right| {
        left.device_name
            .cmp(&right.device_name)
            .then_with(|| left.endpoint_id.cmp(&right.endpoint_id))
    });
    Ok(rows)
}
