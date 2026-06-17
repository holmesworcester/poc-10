//! Read-only decoding for invite-accepted projection rows.
//!
//! Query helpers are the only invite-accepted module functions that inspect
//! projected row state directly. They never write, construct facts, project, or
//! dispatch intents.

use std::net::SocketAddr;

use crate::core::db::{Db, DEFAULT_QUERY_LIMIT};
use crate::protocol::auth::endpoint_shared::fact::EndpointRole;
use crate::protocol::connection::request::{
    encode::ADDR_BLOCK_BYTES, project::decode::decode_optional_addr,
};
use rusqlite::{params, OptionalExtension, Row};

use super::fact::{EndpointId, WorkspaceId};

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

pub fn decode_invite_accepted_row(row: &Row<'_>) -> rusqlite::Result<InviteAcceptedRow> {
    let peer_addr_block: Vec<u8> = row.get(7)?;
    let peer_addr_block: [u8; ADDR_BLOCK_BYTES] =
        peer_addr_block.as_slice().try_into().map_err(|_| {
            rusqlite::Error::InvalidParameterName(
                "invite_accepted row bootstrap_addr block is malformed".to_string(),
            )
        })?;
    let bootstrap_addr = decode_optional_addr(&peer_addr_block)
        .map_err(rusqlite::Error::InvalidParameterName)?
        .ok_or_else(|| {
            rusqlite::Error::InvalidParameterName(
                "invite_accepted row bootstrap_addr cannot be empty".to_string(),
            )
        })?;
    let user_authority: [u8; 32] = row.get(8)?;
    let identity_scope = match row.get::<_, i64>(10)? {
        0 => false,
        1 => true,
        other => {
            return Err(rusqlite::Error::InvalidParameterName(format!(
                "invite_accepted row identity_scope has invalid value {other}",
            )))
        }
    };
    Ok(InviteAcceptedRow {
        accepted_endpoint_id: row.get(0)?,
        workspace_id: row.get(1)?,
        invite_fact_id: row.get(2)?,
        invite_accepted_fact_id: row.get(3)?,
        bootstrap_hash: row.get(4)?,
        bootstrap_secret: row.get(5)?,
        bootstrap_endpoint_id: row.get(6)?,
        bootstrap_addr,
        user_authority_fact_id: (user_authority != [0; 32]).then_some(user_authority),
        endpoint_role: EndpointRole::from_u8(row.get::<_, i64>(9)? as u8)
            .map_err(|err| rusqlite::Error::InvalidParameterName(err))?,
        identity_scope,
    })
}

pub fn accepted_bootstrap_peers(store: &Db) -> Result<Vec<InviteAcceptedRow>, String> {
    let mut stmt = store
        .conn()
        .prepare(
            "SELECT accepted_endpoint_id,
                    workspace_id,
                    invite_fact_id,
                    invite_accepted_fact_id,
                    bootstrap_hash,
                    bootstrap_secret,
                    bootstrap_endpoint_id,
                    bootstrap_addr,
                    user_authority_fact_id_or_zero,
                    endpoint_role,
                    identity_scope
             FROM invite_accepted_rows
             ORDER BY accepted_endpoint_id, workspace_id, invite_fact_id
             LIMIT ?1",
        )
        .map_err(|err| format!("read invite accepted rows: {err}"))?;
    let rows = stmt
        .query_map(
            params![DEFAULT_QUERY_LIMIT as i64],
            decode_invite_accepted_row,
        )
        .map_err(|err| format!("read invite accepted rows: {err}"))?;
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|err| format!("decode invite accepted rows: {err}"))
}

pub fn accepted_endpoint_in_workspace(
    store: &Db,
    endpoint_id: EndpointId,
    workspace_id: WorkspaceId,
) -> Result<bool, String> {
    store
        .conn()
        .query_row(
            "SELECT 1
             FROM invite_accepted_rows
             WHERE accepted_endpoint_id = ?1 AND workspace_id = ?2
             LIMIT 1",
            params![endpoint_id, workspace_id],
            |_| Ok(()),
        )
        .optional()
        .map(|row| row.is_some())
        .map_err(|err| format!("load accepted invites: {err}"))
}
