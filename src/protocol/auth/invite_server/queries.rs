//! Read-only decoding for invite-server projection rows.
//!
//! Query helpers are the only invite-server module functions that inspect
//! projected row state directly. They never write, construct facts, project, or
//! dispatch intents.

use crate::core::crypto::Ed25519PublicKey;
use crate::core::facts::FactId;

use super::fact::WorkspaceId;
use super::{InviteServerId, INVITE_SERVER_ROW_SCHEMA};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InviteServerRow {
    pub workspace_id: WorkspaceId,
    pub invite_server_id: InviteServerId,
    pub created_at_ms: u64,
    pub public_key: Ed25519PublicKey,
    pub authority_fact_id: FactId,
}

pub fn decode_invite_server_row(key: &[u8], value: &[u8]) -> Result<InviteServerRow, String> {
    let key_fields = INVITE_SERVER_ROW_SCHEMA.decode_key(key)?;
    let value_fields = INVITE_SERVER_ROW_SCHEMA.decode_value(value)?;
    Ok(InviteServerRow {
        workspace_id: key_fields[0].as_bytes32("workspace_id")?,
        invite_server_id: key_fields[1].as_bytes32("invite_server_id")?,
        created_at_ms: value_fields[0].as_u64("created_at_ms")?,
        public_key: value_fields[1].as_bytes32("public_key")?,
        authority_fact_id: value_fields[2].as_bytes32("authority_fact_id")?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::auth::invite_server::fact::InviteServerFact;

    #[test]
    fn invite_server_row_roundtrips_through_schema() {
        let fact = InviteServerFact {
            created_at_ms: 9,
            public_key: [1; 32],
            workspace_id: [2; 32],
            authority_fact_id: [3; 32],
            signer_id: [4; 32],
            signer_public_key: [5; 32],
        };
        let row = super::super::invite_server_row([7; 32], &fact).expect("invite server row");
        let decoded =
            decode_invite_server_row(&row.key, &row.value).expect("decode invite server row");
        assert_eq!(decoded.workspace_id, [2; 32]);
        assert_eq!(decoded.invite_server_id, [7; 32]);
        assert_eq!(decoded.created_at_ms, 9);
        assert_eq!(decoded.public_key, [1; 32]);
        assert_eq!(decoded.authority_fact_id, [3; 32]);
    }
}
