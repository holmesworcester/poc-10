//! Read-only decoding for invite-accepted projection rows.
//!
//! Query helpers are the only invite-accepted module functions that inspect
//! projected row state directly. They never write, construct facts, project, or
//! dispatch intents.

use super::fact::{EndpointId, WorkspaceId};
use super::INVITE_ACCEPTED_ROW_SCHEMA;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InviteAcceptedRow {
    pub accepted_endpoint_id: EndpointId,
    pub workspace_id: WorkspaceId,
    pub invite_fact_id: [u8; 32],
    pub invite_accepted_fact_id: [u8; 32],
    pub invite_secret_fact_id: [u8; 32],
    pub bootstrap_hash: [u8; 32],
}

pub fn decode_invite_accepted_row(key: &[u8], value: &[u8]) -> Result<InviteAcceptedRow, String> {
    let key_fields = INVITE_ACCEPTED_ROW_SCHEMA.decode_key(key)?;
    let value_fields = INVITE_ACCEPTED_ROW_SCHEMA.decode_value(value)?;
    Ok(InviteAcceptedRow {
        accepted_endpoint_id: key_fields[0].as_bytes32("accepted_endpoint_id")?,
        workspace_id: key_fields[1].as_bytes32("workspace_id")?,
        invite_fact_id: key_fields[2].as_bytes32("invite_fact_id")?,
        invite_accepted_fact_id: value_fields[0].as_bytes32("invite_accepted_fact_id")?,
        invite_secret_fact_id: value_fields[1].as_bytes32("invite_secret_fact_id")?,
        bootstrap_hash: value_fields[2].as_bytes32("bootstrap_hash")?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::auth::invite_accepted::fact::InviteAcceptedFact;

    #[test]
    fn invite_accepted_row_roundtrips_through_schema() {
        let fact = InviteAcceptedFact {
            workspace_id: [1; 32],
            invite_fact_id: [2; 32],
            invite_secret_fact_id: [3; 32],
            bootstrap_hash: [4; 32],
            accepted_endpoint_id: [5; 32],
        };
        let row = super::super::invite_accepted_row([6; 32], &fact).expect("invite accepted row");
        let decoded =
            decode_invite_accepted_row(&row.key, &row.value).expect("decode invite accepted row");
        assert_eq!(decoded.accepted_endpoint_id, [5; 32]);
        assert_eq!(decoded.workspace_id, [1; 32]);
        assert_eq!(decoded.invite_fact_id, [2; 32]);
        assert_eq!(decoded.invite_accepted_fact_id, [6; 32]);
        assert_eq!(decoded.invite_secret_fact_id, [3; 32]);
        assert_eq!(decoded.bootstrap_hash, [4; 32]);
    }
}
