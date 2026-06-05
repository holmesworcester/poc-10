//! Read-only decoding for admin grant projection rows.
//!
//! Query helpers are the only admin module functions that inspect projected row
//! state directly. They never write, construct facts, project, or dispatch
//! intents.

use super::fact::{AdminId, AdminPublicKey, UserId, WorkspaceId};
use super::ADMIN_ROW_SCHEMA;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminRow {
    pub workspace_id: WorkspaceId,
    pub admin_id: AdminId,
    pub created_at_ms: u64,
    pub public_key: AdminPublicKey,
    pub authority_fact_id: [u8; 32],
    pub user_fact_id: UserId,
}

pub fn decode_admin_row(key: &[u8], value: &[u8]) -> Result<AdminRow, String> {
    let key_fields = ADMIN_ROW_SCHEMA.decode_key(key)?;
    let value_fields = ADMIN_ROW_SCHEMA.decode_value(value)?;
    Ok(AdminRow {
        workspace_id: key_fields[0].as_bytes32("workspace_id")?,
        admin_id: key_fields[1].as_bytes32("admin_id")?,
        created_at_ms: value_fields[0].as_u64("created_at_ms")?,
        public_key: value_fields[1].as_bytes32("public_key")?,
        authority_fact_id: value_fields[2].as_bytes32("authority_fact_id")?,
        user_fact_id: value_fields[3].as_bytes32("user_fact_id")?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::crypto::ED25519_SIGNATURE_BYTES;
    use crate::protocol::auth::admin::fact::AdminFact;

    #[test]
    fn admin_row_roundtrips_through_schema() {
        let fact = AdminFact {
            created_at_ms: 55,
            workspace_id: [1; 32],
            public_key: [2; 32],
            authority_fact_id: [3; 32],
            user_fact_id: [4; 32],
            signer_id: [3; 32],
            signer_public_key: [5; 32],
            signature: [6; ED25519_SIGNATURE_BYTES],
        };
        let row = super::super::admin_row([9; 32], &fact).expect("admin row");
        let decoded = decode_admin_row(&row.key, &row.value).expect("decode admin row");
        assert_eq!(decoded.workspace_id, [1; 32]);
        assert_eq!(decoded.admin_id, [9; 32]);
        assert_eq!(decoded.created_at_ms, 55);
        assert_eq!(decoded.public_key, [2; 32]);
        assert_eq!(decoded.authority_fact_id, [3; 32]);
        assert_eq!(decoded.user_fact_id, [4; 32]);
    }
}
