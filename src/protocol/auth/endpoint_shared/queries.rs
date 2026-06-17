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

use super::fact::{
    EndpointId, EndpointRole, EndpointSharedId, UserAuthorityId, WorkspaceId,
    ENDPOINT_DEVICE_NAME_BYTES,
};
use super::ENDPOINT_SHARED_ROWS;
use super::ENDPOINT_SHARED_ROW_SCHEMA;

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

pub fn decode_endpoint_shared_row(key: &[u8], value: &[u8]) -> Result<EndpointSharedRow, String> {
    let key_fields = ENDPOINT_SHARED_ROW_SCHEMA.decode_key(key)?;
    let value_fields = ENDPOINT_SHARED_ROW_SCHEMA.decode_value(value)?;
    let device_name_bytes: [u8; ENDPOINT_DEVICE_NAME_BYTES] = value_fields[5]
        .as_bytes("device_name")?
        .try_into()
        .map_err(|_| "device_name slot has wrong length".to_string())?;
    let device_name = FixedText::<ENDPOINT_DEVICE_NAME_BYTES>::from_padded(device_name_bytes)
        .map_err(|err| format!("{err:?}"))?;
    Ok(EndpointSharedRow {
        workspace_id: key_fields[0].as_bytes32("workspace_id")?,
        endpoint_shared_id: key_fields[1].as_bytes32("endpoint_shared_id")?,
        created_at_ms: value_fields[0].as_u64("created_at_ms")?,
        endpoint_id: value_fields[1].as_bytes32("endpoint_id")?,
        signing_public_key: value_fields[2].as_bytes32("signing_public_key")?,
        endpoint_role: EndpointRole::from_u8(value_fields[3].as_u8("endpoint_role")?)?,
        user_authority_fact_id: value_fields[4].as_bytes32("user_authority_fact_id")?,
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
    let mut memberships = store
        .table_rows_page(ENDPOINT_SHARED_ROWS, DEFAULT_QUERY_LIMIT)
        .map_err(|err| format!("load endpoint memberships: {err}"))?
        .into_iter()
        .map(|(key, value)| {
            decode_endpoint_shared_row(&key, &value).map(|row| EndpointMembership {
                workspace_id: row.workspace_id,
                endpoint_id: row.endpoint_id,
                endpoint_shared_id: row.endpoint_shared_id,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
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
    let mut rows = store
        .table_rows_with_key_prefix(ENDPOINT_SHARED_ROWS, &workspace_id, DEFAULT_QUERY_LIMIT)
        .map_err(|err| format!("load endpoint peers: {err}"))?
        .into_iter()
        .map(|(key, value)| decode_endpoint_shared_row(&key, &value))
        .collect::<Result<Vec<_>, _>>()?;
    rows.sort_by(|left, right| {
        left.device_name
            .cmp(&right.device_name)
            .then_with(|| left.endpoint_id.cmp(&right.endpoint_id))
    });
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::auth::endpoint_shared::endpoint_shared_row;
    use crate::protocol::auth::endpoint_shared::fact::{EndpointDeviceName, EndpointSharedFact};

    #[test]
    fn endpoint_shared_row_roundtrips_through_schema() {
        let fact = EndpointSharedFact {
            created_at_ms: 77,
            workspace_id: [1; 32],
            user_authority_fact_id: [2; 32],
            endpoint_id: [3; 32],
            signing_public_key: [4; 32],
            endpoint_role: EndpointRole::InviteServer,
            device_name: EndpointDeviceName::new("laptop").expect("device name"),
            signer_id: [6; 32],
            signer_public_key: [7; 32],
        };
        let row = endpoint_shared_row([9; 32], &fact).expect("endpoint shared row");
        let decoded =
            decode_endpoint_shared_row(&row.key, &row.value).expect("decode endpoint shared row");
        assert_eq!(decoded.workspace_id, [1; 32]);
        assert_eq!(decoded.endpoint_shared_id, [9; 32]);
        assert_eq!(decoded.created_at_ms, 77);
        assert_eq!(decoded.endpoint_id, [3; 32]);
        assert_eq!(decoded.signing_public_key, [4; 32]);
        assert_eq!(decoded.endpoint_role, EndpointRole::InviteServer);
        assert_eq!(decoded.user_authority_fact_id, [2; 32]);
        assert_eq!(decoded.device_name, "laptop");
    }
}
