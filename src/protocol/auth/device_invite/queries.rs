//! Read-only decoding for device-invite projection rows.
//!
//! Query helpers are the only device-invite module functions that inspect
//! projected row state directly. They never write, construct facts, project, or
//! dispatch intents.

use crate::core::crypto::Ed25519PublicKey;
use crate::core::facts::FactId;

use super::fact::WorkspaceId;
use super::DEVICE_INVITE_ROW_SCHEMA;

pub type DeviceInviteId = FactId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceInviteRow {
    pub workspace_id: WorkspaceId,
    pub device_invite_id: DeviceInviteId,
    pub created_at_ms: u64,
    pub user_authority_fact_id: FactId,
    pub user_invite_fact_id: Option<FactId>,
    pub public_key: Ed25519PublicKey,
}

pub fn decode_device_invite_row(key: &[u8], value: &[u8]) -> Result<DeviceInviteRow, String> {
    let key_fields = DEVICE_INVITE_ROW_SCHEMA.decode_key(key)?;
    let value_fields = DEVICE_INVITE_ROW_SCHEMA.decode_value(value)?;
    let user_invite_raw = value_fields[2].as_bytes32("user_invite_fact_id")?;
    let user_invite_fact_id = if user_invite_raw == [0; 32] {
        None
    } else {
        Some(user_invite_raw)
    };
    Ok(DeviceInviteRow {
        workspace_id: key_fields[0].as_bytes32("workspace_id")?,
        device_invite_id: key_fields[1].as_bytes32("device_invite_id")?,
        created_at_ms: value_fields[0].as_u64("created_at_ms")?,
        user_authority_fact_id: value_fields[1].as_bytes32("user_authority_fact_id")?,
        user_invite_fact_id,
        public_key: value_fields[3].as_bytes32("public_key")?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::crypto::ED25519_SIGNATURE_BYTES;
    use crate::protocol::auth::device_invite::fact::DeviceInviteFact;

    #[test]
    fn device_invite_row_roundtrips_through_schema() {
        let fact = DeviceInviteFact {
            created_at_ms: 11,
            workspace_id: [1; 32],
            user_authority_fact_id: [2; 32],
            user_invite_fact_id: Some([4; 32]),
            public_key: [3; 32],
            signer_id: [5; 32],
            signer_public_key: [6; 32],
            signature: [7; ED25519_SIGNATURE_BYTES],
        };
        let row = super::super::device_invite_row([9; 32], &fact).expect("device invite row");
        let decoded =
            decode_device_invite_row(&row.key, &row.value).expect("decode device invite row");
        assert_eq!(decoded.workspace_id, [1; 32]);
        assert_eq!(decoded.device_invite_id, [9; 32]);
        assert_eq!(decoded.created_at_ms, 11);
        assert_eq!(decoded.user_authority_fact_id, [2; 32]);
        assert_eq!(decoded.user_invite_fact_id, Some([4; 32]));
        assert_eq!(decoded.public_key, [3; 32]);
    }

    #[test]
    fn zero_user_invite_decodes_as_none() {
        let fact = DeviceInviteFact {
            created_at_ms: 11,
            workspace_id: [1; 32],
            user_authority_fact_id: [2; 32],
            user_invite_fact_id: None,
            public_key: [3; 32],
            signer_id: [5; 32],
            signer_public_key: [6; 32],
            signature: [7; ED25519_SIGNATURE_BYTES],
        };
        let row = super::super::device_invite_row([9; 32], &fact).expect("device invite row");
        let decoded =
            decode_device_invite_row(&row.key, &row.value).expect("decode device invite row");
        assert_eq!(decoded.user_invite_fact_id, None);
    }
}
