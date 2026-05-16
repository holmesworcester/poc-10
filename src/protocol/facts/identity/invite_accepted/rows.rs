//! Projection row layouts for invite-accepted state.
//!
//! Rows are keyed by `accepted_endpoint_id || workspace_id || invite_fact_id`.

use crate::core::store::{TableName, TableRow};

use super::fact::{EndpointId, InviteAcceptedFact, WorkspaceId};
use super::layout;

pub const INVITE_ACCEPTED_ROWS: TableName = TableName::new("invite_accepted_rows");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InviteAcceptedRow {
    pub accepted_endpoint_id: EndpointId,
    pub workspace_id: WorkspaceId,
    pub invite_fact_id: [u8; 32],
    pub invite_accepted_fact_id: [u8; 32],
    pub invite_secret_fact_id: [u8; 32],
    pub bootstrap_hash: [u8; 32],
}

pub fn invite_accepted_key(
    accepted_endpoint_id: &EndpointId,
    workspace_id: &WorkspaceId,
    invite_fact_id: &[u8; 32],
) -> Vec<u8> {
    let mut key = Vec::with_capacity(96);
    key.extend_from_slice(accepted_endpoint_id);
    key.extend_from_slice(workspace_id);
    key.extend_from_slice(invite_fact_id);
    key
}

pub fn invite_accepted_row(
    invite_accepted_fact_id: [u8; 32],
    fact: &InviteAcceptedFact,
) -> Result<TableRow, String> {
    Ok(TableRow {
        table: INVITE_ACCEPTED_ROWS,
        key: invite_accepted_key(
            &fact.accepted_endpoint_id,
            &fact.workspace_id,
            &fact.invite_fact_id,
        ),
        value: layout::encode_row_value(&invite_accepted_fact_id, fact)?,
    })
}

pub fn decode_invite_accepted_row(key: &[u8], value: &[u8]) -> Result<InviteAcceptedRow, String> {
    if key.len() != 96 {
        return Err("invite_accepted row key is malformed".to_string());
    }
    let mut accepted_endpoint_id = [0; 32];
    let mut workspace_id = [0; 32];
    let mut invite_fact_id = [0; 32];
    accepted_endpoint_id.copy_from_slice(&key[..32]);
    workspace_id.copy_from_slice(&key[32..64]);
    invite_fact_id.copy_from_slice(&key[64..96]);
    let decoded = layout::decode_row_value(value)?;
    Ok(InviteAcceptedRow {
        accepted_endpoint_id,
        workspace_id,
        invite_fact_id,
        invite_accepted_fact_id: decoded.invite_accepted_fact_id,
        invite_secret_fact_id: decoded.invite_secret_fact_id,
        bootstrap_hash: decoded.bootstrap_hash,
    })
}
