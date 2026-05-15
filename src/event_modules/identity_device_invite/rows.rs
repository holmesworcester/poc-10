//! Projection row layouts for device-invite state.
//!
//! Rows are keyed by `workspace_id || device_invite_id`. The device-invite id
//! is the fact id of the device-invite fact being projected.

use crate::core::crypto::Ed25519PublicKey;
use crate::core::facts::FactId;
use crate::core::store::{TableName, TableRow};

use super::fact::{DeviceInviteFact, WorkspaceId};
use super::layout;

pub const DEVICE_INVITE_ROWS: TableName = TableName::new("device_invite_rows");

pub type DeviceInviteId = FactId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceInviteRow {
    pub workspace_id: WorkspaceId,
    pub device_invite_id: DeviceInviteId,
    pub created_at_ms: u64,
    pub user_authority_event_id: FactId,
    pub user_invite_event_id: Option<FactId>,
    pub public_key: Ed25519PublicKey,
}

pub fn device_invite_key(
    workspace_id: &WorkspaceId,
    device_invite_id: &DeviceInviteId,
) -> Vec<u8> {
    let mut key = Vec::with_capacity(64);
    key.extend_from_slice(workspace_id);
    key.extend_from_slice(device_invite_id);
    key
}

pub fn device_invite_row(
    device_invite_id: DeviceInviteId,
    fact: &DeviceInviteFact,
) -> Result<TableRow, String> {
    Ok(TableRow {
        table: DEVICE_INVITE_ROWS,
        key: device_invite_key(&fact.workspace_id, &device_invite_id),
        value: layout::encode_row_value(fact)?,
    })
}

pub fn decode_device_invite_row(key: &[u8], value: &[u8]) -> Result<DeviceInviteRow, String> {
    if key.len() != 64 {
        return Err("device_invite row key must be workspace_id || device_invite_id".to_string());
    }
    let mut workspace_id = [0; 32];
    let mut device_invite_id = [0; 32];
    workspace_id.copy_from_slice(&key[..32]);
    device_invite_id.copy_from_slice(&key[32..]);
    let decoded = layout::decode_row_value(value)?;
    Ok(DeviceInviteRow {
        workspace_id,
        device_invite_id,
        created_at_ms: decoded.created_at_ms,
        user_authority_event_id: decoded.user_authority_event_id,
        user_invite_event_id: decoded.user_invite_event_id,
        public_key: decoded.public_key,
    })
}
