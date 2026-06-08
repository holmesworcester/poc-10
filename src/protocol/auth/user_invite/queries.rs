//! Read-only decoding for user-invite projection rows.
//!
//! Query helpers are the only user-invite module functions that inspect
//! projected row state directly. They never write, construct facts, project, or
//! dispatch intents.

use crate::core::crypto::Ed25519PublicKey;
use crate::core::facts::FactId;

use super::fact::WorkspaceId;
use super::USER_INVITE_ROW_SCHEMA;

pub type UserInviteId = FactId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UserInviteRow {
    pub workspace_id: WorkspaceId,
    pub user_invite_id: UserInviteId,
    pub created_at_ms: u64,
    pub public_key: Ed25519PublicKey,
    pub authority_fact_id: FactId,
}

pub fn decode_user_invite_row(key: &[u8], value: &[u8]) -> Result<UserInviteRow, String> {
    let key_fields = USER_INVITE_ROW_SCHEMA.decode_key(key)?;
    let value_fields = USER_INVITE_ROW_SCHEMA.decode_value(value)?;
    Ok(UserInviteRow {
        workspace_id: key_fields[0].as_bytes32("workspace_id")?,
        user_invite_id: key_fields[1].as_bytes32("user_invite_id")?,
        created_at_ms: value_fields[0].as_u64("created_at_ms")?,
        public_key: value_fields[1].as_bytes32("public_key")?,
        authority_fact_id: value_fields[2].as_bytes32("authority_fact_id")?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::auth::user_invite::fact::UserInviteFact;

    #[test]
    fn user_invite_row_roundtrips_through_schema() {
        let fact = UserInviteFact {
            created_at_ms: 5,
            public_key: [1; 32],
            workspace_id: [2; 32],
            authority_fact_id: [3; 32],
            signer_id: [4; 32],
            signer_public_key: [5; 32],
        };
        let row = super::super::user_invite_row([9; 32], &fact).expect("user invite row");
        let decoded = decode_user_invite_row(&row.key, &row.value).expect("decode user invite row");
        assert_eq!(decoded.workspace_id, [2; 32]);
        assert_eq!(decoded.user_invite_id, [9; 32]);
        assert_eq!(decoded.created_at_ms, 5);
        assert_eq!(decoded.public_key, [1; 32]);
        assert_eq!(decoded.authority_fact_id, [3; 32]);
    }
}
