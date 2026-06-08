//! Read-only decoding for invite-accepted projection rows.
//!
//! Query helpers are the only invite-accepted module functions that inspect
//! projected row state directly. They never write, construct facts, project, or
//! dispatch intents.

use std::net::SocketAddr;

use crate::core::store::Store;
use crate::protocol::auth::endpoint_shared::fact::EndpointRole;
use crate::protocol::connection::request::{
    decode::decode_optional_addr, encode::ADDR_BLOCK_BYTES,
};

use super::fact::{EndpointId, WorkspaceId};
use super::{INVITE_ACCEPTED_ROWS, INVITE_ACCEPTED_ROW_SCHEMA};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InviteAcceptedRow {
    pub accepted_endpoint_id: EndpointId,
    pub workspace_id: WorkspaceId,
    pub invite_fact_id: [u8; 32],
    pub invite_accepted_fact_id: [u8; 32],
    pub bootstrap_hash: [u8; 32],
    pub bootstrap_secret: [u8; 32],
    pub bootstrap_endpoint_id: EndpointId,
    pub bootstrap_addr: SocketAddr,
    pub user_authority_fact_id: Option<[u8; 32]>,
    pub endpoint_role: EndpointRole,
    pub identity_scope: bool,
}

pub fn decode_invite_accepted_row(key: &[u8], value: &[u8]) -> Result<InviteAcceptedRow, String> {
    let key_fields = INVITE_ACCEPTED_ROW_SCHEMA.decode_key(key)?;
    let value_fields = INVITE_ACCEPTED_ROW_SCHEMA.decode_value(value)?;
    let peer_addr_block: [u8; ADDR_BLOCK_BYTES] = value_fields[4]
        .as_bytes("bootstrap_addr")?
        .try_into()
        .map_err(|_| "invite_accepted row bootstrap_addr block is malformed".to_string())?;
    let bootstrap_addr = decode_optional_addr(&peer_addr_block)?
        .ok_or_else(|| "invite_accepted row bootstrap_addr cannot be empty".to_string())?;
    let user_authority = value_fields[5].as_bytes32("user_authority_fact_id_or_zero")?;
    let identity_scope = match value_fields[7].as_u8("identity_scope")? {
        0 => false,
        1 => true,
        other => {
            return Err(format!(
                "invite_accepted row identity_scope has invalid value {other}"
            ))
        }
    };
    Ok(InviteAcceptedRow {
        accepted_endpoint_id: key_fields[0].as_bytes32("accepted_endpoint_id")?,
        workspace_id: key_fields[1].as_bytes32("workspace_id")?,
        invite_fact_id: key_fields[2].as_bytes32("invite_fact_id")?,
        invite_accepted_fact_id: value_fields[0].as_bytes32("invite_accepted_fact_id")?,
        bootstrap_hash: value_fields[1].as_bytes32("bootstrap_hash")?,
        bootstrap_secret: value_fields[2].as_bytes32("bootstrap_secret")?,
        bootstrap_endpoint_id: value_fields[3].as_bytes32("bootstrap_endpoint_id")?,
        bootstrap_addr,
        user_authority_fact_id: (user_authority != [0; 32]).then_some(user_authority),
        endpoint_role: EndpointRole::from_u8(value_fields[6].as_u8("endpoint_role")?)?,
        identity_scope,
    })
}

pub fn accepted_bootstrap_peers(store: &Store) -> Result<Vec<InviteAcceptedRow>, String> {
    store
        .table_rows(INVITE_ACCEPTED_ROWS)
        .map_err(|err| format!("read invite accepted rows: {err}"))?
        .into_iter()
        .map(|(key, value)| decode_invite_accepted_row(&key, &value))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::auth::endpoint_shared::fact::EndpointRole;
    use crate::protocol::auth::invite::fact::bootstrap_secret_hash;
    use crate::protocol::auth::invite_accepted::fact::InviteAcceptedFact;

    #[test]
    fn invite_accepted_row_roundtrips_through_schema() {
        let fact = InviteAcceptedFact {
            workspace_id: [1; 32],
            invite_fact_id: [2; 32],
            bootstrap_hash: bootstrap_secret_hash(&[7; 32]),
            bootstrap_secret: [7; 32],
            accepted_endpoint_id: [5; 32],
            bootstrap_endpoint_id: [6; 32],
            bootstrap_addr: "127.0.0.1:41000".parse().unwrap(),
            user_authority_fact_id: Some([8; 32]),
            endpoint_role: EndpointRole::Device,
            identity_scope: true,
        };
        let row = super::super::invite_accepted_row([9; 32], &fact).expect("invite accepted row");
        let decoded =
            decode_invite_accepted_row(&row.key, &row.value).expect("decode invite accepted row");
        assert_eq!(decoded.accepted_endpoint_id, [5; 32]);
        assert_eq!(decoded.workspace_id, [1; 32]);
        assert_eq!(decoded.invite_fact_id, [2; 32]);
        assert_eq!(decoded.invite_accepted_fact_id, [9; 32]);
        assert_eq!(decoded.bootstrap_hash, fact.bootstrap_hash);
        assert_eq!(decoded.bootstrap_secret, [7; 32]);
        assert_eq!(decoded.bootstrap_endpoint_id, [6; 32]);
        assert_eq!(decoded.bootstrap_addr, "127.0.0.1:41000".parse().unwrap());
        assert_eq!(decoded.user_authority_fact_id, Some([8; 32]));
        assert_eq!(decoded.endpoint_role, EndpointRole::Device);
        assert!(decoded.identity_scope);
    }
}
